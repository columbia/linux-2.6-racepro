/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/scribe.h>

struct scribe_context *scribe_alloc_context(void)
{
	struct scribe_context *ctx;

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	atomic_set(&ctx->ref_cnt, 1);
	ctx->id = current->pid;
	ctx->flags = SCRIBE_IDLE;

	spin_lock_init(&ctx->tasks_lock);
	INIT_LIST_HEAD(&ctx->tasks);
	init_waitqueue_head(&ctx->tasks_wait);

	spin_lock_init(&ctx->queues_lock);
	INIT_LIST_HEAD(&ctx->queues);
	init_waitqueue_head(&ctx->queues_wait);

	scribe_init_queue_bare(&ctx->notification_queue);

	ctx->idle_event = NULL;
	ctx->diverge_event = NULL;

	spin_lock_init(&ctx->backtrace_lock);
	ctx->backtrace = NULL;

	return ctx;
}

void scribe_exit_context(struct scribe_context *ctx)
{
	struct scribe_queue *queue, *tmp;

	scribe_emergency_stop(ctx, NULL);

	/* No locks are needed: from now on, tasks cannot be added */
	wait_event(ctx->tasks_wait, list_empty(&ctx->tasks));

	spin_lock(&ctx->queues_lock);
	list_for_each_entry_safe(queue, tmp, &ctx->queues, node)
		scribe_unset_persistent(queue);
	spin_unlock(&ctx->queues_lock);

	BUG_ON(!list_empty(&ctx->queues));

	scribe_free_all_events(&ctx->notification_queue);

	BUG_ON(ctx->idle_event);
	BUG_ON(ctx->backtrace);

	scribe_put_context(ctx);
}

static int context_start(struct scribe_context *ctx, int state,
			 struct scribe_event_context_idle *idle_event,
			 struct scribe_event_diverge *diverge_event,
			 struct scribe_backtrace *backtrace)
{
	assert_spin_locked(&ctx->tasks_lock);

	if (ctx->flags != SCRIBE_IDLE)
		return -EPERM;

	/*
	 * The task list might not be empty (just got an emergency_stop),
	 * we're getting there.
	 */
	if (!list_empty(&ctx->tasks))
		return -EPERM;

	ctx->queues_wont_grow = 0;

	BUG_ON(ctx->idle_event);
	ctx->idle_event = idle_event;

	BUG_ON(ctx->diverge_event);
	ctx->diverge_event = diverge_event;

	BUG_ON(ctx->backtrace);
	ctx->backtrace = backtrace;

	ctx->flags = state;

	return 0;
}

static void context_idle(struct scribe_context *ctx,
			 struct scribe_event *reason)
{
	struct scribe_backtrace *backtrace;

	assert_spin_locked(&ctx->tasks_lock);

	ctx->flags = SCRIBE_IDLE;

	spin_lock(&ctx->backtrace_lock);
	backtrace = ctx->backtrace;
	ctx->backtrace = NULL;
	spin_unlock(&ctx->backtrace_lock);

	if (backtrace) {
		if (reason) {
			scribe_backtrace_dump(backtrace,
					      &ctx->notification_queue);
		}
		scribe_free_backtrace(backtrace);
	}

	if (IS_ERR(reason) || !reason) {
		ctx->idle_event->error = PTR_ERR(reason);
		WARN(reason, "scribe: Context going idle with error=%ld\n",
		     PTR_ERR(reason));
	} else {
		ctx->idle_event->error = -EDIVERGE;
		scribe_queue_event_bare(&ctx->notification_queue, reason);
	}

	scribe_queue_event_bare(&ctx->notification_queue, ctx->idle_event);
	ctx->idle_event = NULL;

	if (ctx->diverge_event) {
		scribe_free_event(ctx->diverge_event);
		ctx->diverge_event = NULL;
	}
}

static int event_diverge_max_size_type(void)
{
	int i;
	size_t max_size = 0;
	int max_size_type = 0;
	for (i = 0; i < (__u8)-1; i++) {
		if (!is_diverge_type(i))
			continue;
		if (sizeof_event_from_type(i) > max_size) {
			max_size = sizeof_event_from_type(i);
			max_size_type = i;
		}
	}

	return max_size_type;
}

static int do_start(struct scribe_context *ctx, int state, int backtrace_len)
{
	int ret = -ENOMEM;
	struct scribe_event_context_idle *idle_event;
	struct scribe_event_diverge *diverge_event;
	struct scribe_backtrace *backtrace = NULL;

	idle_event = scribe_alloc_event(SCRIBE_EVENT_CONTEXT_IDLE);
	if (!idle_event)
		goto err;

	diverge_event = scribe_alloc_event(event_diverge_max_size_type());
	if (!diverge_event)
		goto err_idle_event;

	if (backtrace_len) {
		backtrace = scribe_alloc_backtrace(backtrace_len);
		if (!backtrace)
			goto err_diverge_event;
	}

	spin_lock(&ctx->tasks_lock);
	ret = context_start(ctx, state, idle_event, diverge_event, backtrace);
	spin_unlock(&ctx->tasks_lock);
	if (ret)
		goto err_backtrace;
	return ret;

err_backtrace:
	if (backtrace)
		scribe_free_backtrace(backtrace);
err_diverge_event:
	scribe_free_event(diverge_event);
err_idle_event:
	scribe_free_event(idle_event);
err:
	return ret;
}

int scribe_start_record(struct scribe_context *ctx)
{
	return do_start(ctx, SCRIBE_RECORD, 0);
}

int scribe_start_replay(struct scribe_context *ctx, int backtrace_len)
{
	return do_start(ctx, SCRIBE_REPLAY, backtrace_len);
}

void scribe_emergency_stop(struct scribe_context *ctx,
			   struct scribe_event *reason)
{
	struct scribe_ps *scribe;

	spin_lock(&ctx->tasks_lock);

	if (ctx->flags == SCRIBE_IDLE)
		goto out;

	/*
	 * The SCRIBE_IDLE flag has to be set here to guard against race with
	 * scribe_attach() called from copy_process() or execve().
	 * See in scribe_attach() for more details.
	 */
	context_idle(ctx, reason);

	/*
	 * The tasks list is most likely to be empty by now.
	 * If it's not empty, it means that the userspace monitor process has
	 * gone missing. We'll kill all the scribed tasks because we cannot
	 * guarantee that they can continue properly.
	 */
	list_for_each_entry(scribe, &ctx->tasks, node)
		force_sig(SIGKILL, scribe->p);

out:
	spin_unlock(&ctx->tasks_lock);

	/*
	 * If the current process called emergency_stop(), we must detach
	 * ourselves, and die in peace. We have a SIGKILL waiting for us...
	 */
	scribe = current->scribe;
	if (is_replaying(scribe) && scribe->ctx == ctx)
		scribe_free_all_events(&scribe->queue->bare);
}

/*
 * XXX This is not an emergency_stop. This is just a notification that will
 * initiate a graceful ending.
 */
int scribe_stop(struct scribe_context *ctx)
{
	int ret = 0;

	spin_lock(&ctx->tasks_lock);
	if (ctx->flags == SCRIBE_IDLE)
		ret = -EPERM;
	else if (list_empty(&ctx->tasks)) {
		/* This would happen only when no task attached */
		context_idle(ctx, NULL);
	} else
		ctx->flags |= SCRIBE_STOP;
	spin_unlock(&ctx->tasks_lock);

	/* FIXME send a signal wakeup to tasks */

	return ret;
}

int scribe_set_attach_on_exec(struct scribe_context *ctx, int enable)
{
	struct task_struct *p = current;
	int ret;

	if (is_ps_scribed(p))
		return -EPERM;

	if (ctx->flags == SCRIBE_IDLE)
		return -EPERM;

	exit_scribe(p);

	if (!enable)
		return 0;

	ret = init_scribe(p, ctx);
	if (ret)
		return ret;

	p->scribe->flags = SCRIBE_PS_ATTACH_ON_EXEC;

	return 0;
}

/*
 * scribe_attach() and scribe_detach() must only be called only by when
 * current == scribe->p, OR scribe->p is sleeping (and thus not accessing
 * scribe->flags).
 */
void scribe_attach(struct scribe_ps *scribe)
{
	struct scribe_context *ctx = scribe->ctx;

	/*
	 * First get the queue, and only then, add to the task list:
	 * It guarantee that if a task is in the task list, its
	 * queue is in the queue list.
	 */
	BUG_ON(scribe->queue);
	BUG_ON(!scribe->pre_alloc_queue);
	scribe->queue = scribe_get_queue_by_pid(ctx, &scribe->pre_alloc_queue,
						task_pid_vnr(scribe->p));
	if (scribe->pre_alloc_queue) {
		kfree(scribe->pre_alloc_queue);
		scribe->pre_alloc_queue = NULL;
	}

	spin_lock(&ctx->tasks_lock);
	BUG_ON(is_scribed(scribe));

	if (unlikely(ctx->flags == SCRIBE_IDLE)) {
		spin_unlock(&ctx->tasks_lock);

		/*
		 * Two reasons we are here:
		 * 1) We got caught in the attach_on_exec race:
		 *    - the process calls scribe_set_attach_on_exec(ctx)
		 *    - the context goes idle (event pump, or device closed)
		 *    - the process calls execve(), and lands here
		 *
		 * 2) copy_process() was about to attach a child, when
		 * suddenly scribe_emergency_stop() got called and distributed
		 * some SIGKILLs, but only to the parent.
		 *
		 * We can SIGKILL ourselves because if we attached right
		 * before the context went IDLE, would have got the SIGKILL
		 * from emergency_stop() anyways. It's a race condition.
		 */
		spin_lock(&ctx->queues_lock);
		scribe_unset_persistent(scribe->queue);
		spin_unlock(&ctx->queues_lock);

		force_sig(SIGKILL, scribe->p);
		exit_scribe(scribe->p);
		return;
	}

	list_add_tail(&scribe->node, &ctx->tasks);
	spin_unlock(&ctx->tasks_lock);

	scribe->flags |= (ctx->flags & SCRIBE_RECORD) ? SCRIBE_PS_RECORD : 0;
	scribe->flags |= (ctx->flags & SCRIBE_REPLAY) ? SCRIBE_PS_REPLAY : 0;
	scribe->flags |= SCRIBE_PS_ENABLE_ALL;

	if (is_recording(scribe)) {
		/*
		 * The monitor will be waiting on ctx->queue_wait, and all
		 * processes sends their event queue notifications to it.
		 */
		scribe->queue->bare.wait = &ctx->queues_wait;
	} else { /* is_replaying(scribe) == 1 */

		/*
		 * Releasing the persistent reference that was holding the
		 * queue waiting the process to attach.
		 *
		 * Note: In case a new event comes in for our pid, a new queue
		 * will be instantiated by the device, and will never be
		 * picked up by any process. But that's fine because it means
		 * something went wrong, and the scribe context is about to
		 * die, the queue will get freed in scribe_exit_context().
		 */
		spin_lock(&ctx->queues_lock);
		scribe_unset_persistent(scribe->queue);
		spin_unlock(&ctx->queues_lock);

		BUG_ON(scribe->queue->bare.wait !=
		       &scribe->queue->bare.default_wait);
	}

	wake_up(&ctx->tasks_wait);

	scribe->in_syscall = 0;
	scribe->data_flags = 0;
	scribe->prepared_data_event = NULL;
	scribe->can_uaccess = 0;
}

void scribe_detach(struct scribe_ps *scribe)
{
	struct scribe_context *ctx = scribe->ctx;
	BUG_ON(!is_scribed(scribe));

	if (scribe->prepared_data_event) {
		WARN(1, "prepared_data_event present\n");
		scribe_free_event(scribe->prepared_data_event);
	}

	spin_lock(&ctx->tasks_lock);
	list_del(&scribe->node);

	/* We were the last task in the context, it's time to set it idle */
	if (list_empty(&ctx->tasks) && ctx->flags != SCRIBE_IDLE)
		context_idle(ctx, NULL);
	spin_unlock(&ctx->tasks_lock);
	wake_up(&ctx->tasks_wait);

	if (is_recording(scribe))
		scribe_set_queue_wont_grow(&scribe->queue->bare);

	scribe_put_queue(scribe->queue);
	scribe->queue = NULL;

	scribe->flags &= ~(SCRIBE_PS_RECORD | SCRIBE_PS_REPLAY);
}
