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
		goto err;

	atomic_set(&ctx->ref_cnt, 1);
	ctx->id = current->pid;
	ctx->flags = SCRIBE_IDLE;

	spin_lock_init(&ctx->tasks_lock);
	INIT_LIST_HEAD(&ctx->tasks);
	init_waitqueue_head(&ctx->tasks_wait);

	spin_lock_init(&ctx->queues_lock);
	INIT_LIST_HEAD(&ctx->queues);
	init_waitqueue_head(&ctx->queues_wait);

	ctx->notification_queue = scribe_alloc_event_queue();
	if (!ctx->notification_queue)
		goto err_ctx;
	ctx->idle_event = NULL;

	spin_lock_init(&ctx->backtrace_lock);
	ctx->backtrace = NULL;

	return ctx;

err_ctx:
	kfree(ctx);
err:
	return NULL;
}

static void context_idle(struct scribe_context *ctx, int error);

void scribe_emergency_stop(struct scribe_context *ctx, int error)
{
	struct scribe_ps *scribe;

	spin_lock(&ctx->tasks_lock);

	if (ctx->flags == SCRIBE_IDLE) {
		spin_unlock(&ctx->tasks_lock);
		return;
	}

	/*
	 * The SCRIBE_IDLE flag has to be set here to guard against race with
	 * scribe_attach() called from copy_process() or execve().
	 * See in scribe_attach() for more details.
	 */
	context_idle(ctx, error);

	/*
	 * The tasks list is most likely to be empty by now.
	 * If it's not empty, it means that the userspace monitor process has
	 * gone missing. We'll kill all the scribed tasks because we cannot
	 * guarantee that they can continue properly.
	 */
	if (unlikely(!list_empty(&ctx->tasks))) {
		WARN(1, "scribe: emergency stop (error=%d)\n", error);

		list_for_each_entry(scribe, &ctx->tasks, node)
			force_sig(SIGKILL, scribe->p);
	}
	spin_unlock(&ctx->tasks_lock);

	/*
	 * If the current process called emergency_stop(), we must detach
	 * ourselves, and die in peace. We cannot call do_exit() here because
	 * we don't know the context, we may be holding locks for example.
	 * We have a SIGKILL waiting for us anyways.
	 */
	scribe = current->scribe;
	if (is_scribed(scribe) && scribe->ctx == ctx)
		scribe_detach(scribe);
}

void scribe_exit_context(struct scribe_context *ctx)
{
	struct scribe_event_queue *queue, *tmp;

	scribe_emergency_stop(ctx, 0);

	/* No locks are needed: from now on, tasks cannot be added */
	wait_event(ctx->tasks_wait, list_empty(&ctx->tasks));

	spin_lock(&ctx->queues_lock);
	list_for_each_entry_safe(queue, tmp, &ctx->queues, node)
		scribe_make_persistent(queue, 0);
	spin_unlock(&ctx->queues_lock);

	scribe_put_queue(ctx->notification_queue);

	BUG_ON(ctx->idle_event);
	BUG_ON(ctx->backtrace);

	scribe_put_context(ctx);
}

static int context_start(struct scribe_context *ctx, int state,
			 struct scribe_event_context_idle *idle_event,
			 struct scribe_backtrace *backtrace)
{
	assert_spin_locked(&ctx->tasks_lock);

	if (ctx->flags != SCRIBE_IDLE)
		return -EPERM;

	BUG_ON(!list_empty(&ctx->tasks));

	ctx->queues_wont_grow = 0;

	BUG_ON(ctx->idle_event);
	ctx->idle_event = idle_event;

	BUG_ON(ctx->backtrace);
	ctx->backtrace = backtrace;

	ctx->flags = state;

	return 0;
}

static void context_idle(struct scribe_context *ctx, int error)
{
	struct scribe_backtrace *backtrace;
	assert_spin_locked(&ctx->tasks_lock);

	BUG_ON(ctx->flags == SCRIBE_IDLE);

	ctx->flags = SCRIBE_IDLE;

	spin_lock(&ctx->backtrace_lock);
	backtrace = ctx->backtrace;
	if (backtrace)
		ctx->backtrace = NULL;
	spin_unlock(&ctx->backtrace_lock);

	if (backtrace) {
		scribe_backtrace_dump(backtrace, ctx->notification_queue);
		scribe_free_backtrace(backtrace);
	}

	ctx->idle_event->error = error;
	scribe_queue_event(ctx->notification_queue, ctx->idle_event);
	ctx->idle_event = NULL;
}

int scribe_start_record(struct scribe_context *ctx)
{
	int ret;
	struct scribe_event_context_idle *event;

	event = scribe_alloc_event(SCRIBE_EVENT_CONTEXT_IDLE);
	if (!event)
		return -ENOMEM;

	spin_lock(&ctx->tasks_lock);
	ret = context_start(ctx, SCRIBE_RECORD, event, NULL);
	spin_unlock(&ctx->tasks_lock);

	if (ret)
		scribe_free_event(event);
	return ret;
}

int scribe_start_replay(struct scribe_context *ctx, int backtrace_len)
{
	int ret = -ENOMEM;
	struct scribe_event_context_idle *event;
	struct scribe_backtrace *backtrace = NULL;

	event = scribe_alloc_event(SCRIBE_EVENT_CONTEXT_IDLE);
	if (!event)
		goto err;

	if (backtrace_len) {
		backtrace = scribe_alloc_backtrace(backtrace_len);
		if (!backtrace)
			goto err_event;
	}

	spin_lock(&ctx->tasks_lock);
	ret = context_start(ctx, SCRIBE_REPLAY, event, backtrace);
	spin_unlock(&ctx->tasks_lock);
	if (ret)
		goto err_backtrace;
	return ret;

err_backtrace:
	if (backtrace)
		scribe_free_backtrace(backtrace);
err_event:
	scribe_free_event(event);
err:
	return ret;
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
		context_idle(ctx, 0);
	}
	else
		ctx->flags &= SCRIBE_STOP;
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
 * scribe_attach() and scribe_detach() must be called only by
 * the current process or if scribe->p is sleeping (and thus not accessing
 * scribe->flags)
 */
void scribe_attach(struct scribe_ps *scribe)
{
	struct scribe_context *ctx = scribe->ctx;

	/*
	 * First get the queue, and only then, add to the task list:
	 * It guarantee that if a task is in the task list, its
	 * queue is in the queue list
	 */
	BUG_ON(!scribe->queue);
	scribe->queue = scribe_get_queue_by_pid(ctx, &scribe->pre_alloc_queue,
						task_pid_vnr(scribe->p));
	if (scribe->pre_alloc_queue) {
		scribe_put_queue(scribe->pre_alloc_queue);
		scribe->pre_alloc_queue = NULL;
	}

	spin_lock(&ctx->tasks_lock);
	BUG_ON(!(ctx->flags & (SCRIBE_RECORD | SCRIBE_REPLAY)));
	BUG_ON(is_scribed(scribe));

	if (unlikely(ctx->flags == SCRIBE_IDLE)) {
		spin_unlock(&ctx->tasks_lock);

		/*
		 * Two reasons we are here:
		 * 1) We got caught in the attach_on_exec race:
		 *    - the process calls scribe_set_attach_on_exec(ctx)
		 *    - the device gets closed and the context dies
		 *    - the process calls execve(), and lands here
		 * Note: the execve will still succeed.
		 *
		 * 2) copy_process() was about to attach a child, when
		 * suddenly scribe_emergency_stop() got called and distributed
		 * some SIGKILLs, but only to the parent, which is why we
		 * need to do our own cleanup.
		 */
		spin_lock(&ctx->queues_lock);
		scribe_make_persistent(scribe->queue, 0);
		spin_unlock(&ctx->queues_lock);
		exit_scribe(scribe->p);

		/* FIXME send ourselves a SIGKILL if our parent got one */
		return;
	}

	list_add_tail(&scribe->node, &ctx->tasks);
	spin_unlock(&ctx->tasks_lock);

	scribe->flags |= (ctx->flags & SCRIBE_RECORD) ? SCRIBE_PS_RECORD : 0;
	scribe->flags |= (ctx->flags & SCRIBE_REPLAY) ? SCRIBE_PS_REPLAY : 0;

	if (is_recording(scribe)) {
		/*
		 * The monitor will be waiting on ctx->queue_wait, and all
		 * processes sends their event queue notifications to it.
		 */
		scribe->queue->wait = &ctx->queues_wait;
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
		scribe_make_persistent(scribe->queue, 0);
		spin_unlock(&ctx->queues_lock);

		scribe->queue->wait = &scribe->queue->default_wait;
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
		WARN(1, "prepared_data_event present");
		scribe_free_event(scribe->prepared_data_event);
	}

	spin_lock(&ctx->tasks_lock);
	list_del(&scribe->node);

	/* We were the last task in the context, it's time to set it idle */
	if (list_empty(&ctx->tasks) && ctx->flags != SCRIBE_IDLE)
		context_idle(ctx, 0);
	spin_unlock(&ctx->tasks_lock);
	wake_up(&ctx->tasks_wait);

	if (is_recording(scribe))
		scribe_set_queue_wont_grow(scribe->queue);

	scribe_put_queue(scribe->queue);
	scribe->queue = NULL;

	scribe->flags &= ~(SCRIBE_PS_RECORD | SCRIBE_PS_REPLAY);
}
