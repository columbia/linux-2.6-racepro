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
#include <linux/futex.h>

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

	scribe_init_stream(&ctx->notifications);

	ctx->idle_event = NULL;
	ctx->diverge_event = NULL;
	ctx->last_error = 0;

	spin_lock_init(&ctx->backtrace_lock);
	ctx->backtrace = NULL;

	ctx->res_ctx = scribe_alloc_resource_context();
	if (!ctx->res_ctx)
		goto err_ctx;

	if (scribe_open_futexes(ctx->res_ctx))
		goto err_res_ctx;

	scribe_init_resource(&ctx->tasks_res, SCRIBE_RES_TYPE_TASK);

	ctx->bmark = scribe_bookmark_alloc(ctx);
	if (!ctx->bmark)
		goto err_futex;

	spin_lock_init(&ctx->mem_hash_lock);
	ctx->mem_hash = scribe_alloc_mem_hash();
	if (!ctx->mem_hash)
		goto err_bmark;
	spin_lock_init(&ctx->mem_list_lock);
	INIT_LIST_HEAD(&ctx->mem_list);

	return ctx;

err_bmark:
	scribe_bookmark_free(ctx->bmark);
err_futex:
	scribe_close_futexes(ctx->res_ctx);
err_res_ctx:
	scribe_free_resource_context(ctx->res_ctx);
err_ctx:
	kfree(ctx);
	return NULL;
}

static void wait_for_ctx_empty(struct scribe_context *ctx)
{
	struct scribe_queue *queue, *tmp;

	/* No locks are needed: from now on, tasks cannot be added */
	wait_event(ctx->tasks_wait, list_empty(&ctx->tasks));

	spin_lock(&ctx->queues_lock);
	list_for_each_entry_safe(queue, tmp, &ctx->queues, node)
		scribe_unset_persistent(queue);
	spin_unlock(&ctx->queues_lock);

	wait_event(ctx->queues_wait, list_empty(&ctx->queues));
}

void scribe_exit_context(struct scribe_context *ctx)
{
	scribe_emergency_stop(ctx, NULL);
	wait_for_ctx_empty(ctx);

	scribe_free_all_events(&ctx->notifications);
	scribe_free_mem_hash(ctx->mem_hash);
	scribe_close_futexes(ctx->res_ctx);
	scribe_free_resource_context(ctx->res_ctx);
	scribe_bookmark_free(ctx->bmark);

	scribe_put_context(ctx);
}

static int context_start(struct scribe_context *ctx, unsigned long flags,
			 struct scribe_event_context_idle *idle_event,
			 struct scribe_event_diverge *diverge_event,
			 struct scribe_backtrace *backtrace)
{
	assert_spin_locked(&ctx->tasks_lock);

	if (ctx->flags != SCRIBE_IDLE)
		return -EPERM;

	/*
	 * The task list might not be empty (just got an emergency_stop).
	 */
	wait_for_ctx_empty(ctx);

	ctx->queues_sealed = 0;

	ctx->idle_event = idle_event;
	ctx->diverge_event = diverge_event;
	ctx->backtrace = backtrace;

	ctx->flags = flags;

	/*
	 * TODO reset only when context_start() isn't called for the first
	 * time.
	 */
	scribe_reset_resource_context(ctx->res_ctx);
	scribe_reset_resource(&ctx->tasks_res);

	atomic_set(&ctx->signal_cookie, 0);

	return 0;
}

/*
 * This is the place to put the context to an idle state.
 * It is assume that the context is not idle.
 * @reason can be:
 * - NULL: everything went well.
 * - an error (IS_ERR(reason) == 1): something bad happened, such as -ENODATA.
 * - a diverge event: a specific diverge error happened.
 */
static void context_idle(struct scribe_context *ctx,
			 struct scribe_event *reason)
{
	struct scribe_backtrace *backtrace;
	struct scribe_queue *queue;

	assert_spin_locked(&ctx->tasks_lock);

	if (ctx->flags & SCRIBE_REPLAY) {
		spin_lock(&ctx->queues_lock);
		list_for_each_entry(queue, &ctx->queues, node)
			scribe_kill_queue(queue);
		ctx->queues_sealed = 1;
		spin_unlock(&ctx->queues_lock);
	}

	ctx->flags = SCRIBE_IDLE;

	spin_lock(&ctx->backtrace_lock);
	backtrace = ctx->backtrace;
	ctx->backtrace = NULL;
	spin_unlock(&ctx->backtrace_lock);

	if (backtrace) {
		/* We don't dump the backtrace if everything went well */
		if (reason)
			scribe_backtrace_dump(backtrace, &ctx->notifications);
		scribe_free_backtrace(backtrace);
	}

	if (IS_ERR(reason) || !reason) {
		ctx->last_error = ctx->idle_event->error = PTR_ERR(reason);
		WARN(reason, "scribe: Context going idle with error=%ld\n",
		     PTR_ERR(reason));
	} else {
		WARN(1, "scribe: Replay diverged\n");
		ctx->last_error = ctx->idle_event->error = -EDIVERGE;
		scribe_queue_event_stream(&ctx->notifications, reason);
	}

	scribe_queue_event_stream(&ctx->notifications, ctx->idle_event);
	ctx->idle_event = NULL;

	if (ctx->diverge_event) {
		scribe_free_event(ctx->diverge_event);
		ctx->diverge_event = NULL;
	}
}

static int event_diverge_max_size_type(void)
{
	struct scribe_event *event;
	size_t max_size = 0;
	int max_size_type = 0;
	int i;

	for (i = 0; i < (__typeof__(event->type))-1; i++) {
		if (!is_diverge_type(i))
			continue;
		if (sizeof_event_from_type(i) > max_size) {
			max_size = sizeof_event_from_type(i);
			max_size_type = i;
		}
	}

	return max_size_type;
}

int scribe_start(struct scribe_context *ctx, unsigned long flags,
		 int backtrace_len)
{
	int ret = -ENOMEM;
	struct scribe_event_context_idle *idle_event;
	struct scribe_event_diverge *diverge_event;
	struct scribe_backtrace *backtrace = NULL;

	idle_event = scribe_alloc_event(SCRIBE_EVENT_CONTEXT_IDLE);
	if (!idle_event)
		goto err;

	/*
	 * We cannot allocate the diverge event when the diverge happens,
	 * because the context may not allow to.
	 * Allocating the maximum size will suffice.
	 */
	diverge_event = scribe_alloc_event(event_diverge_max_size_type());
	if (!diverge_event)
		goto err_idle_event;

	if (backtrace_len) {
		backtrace = scribe_alloc_backtrace(backtrace_len);
		if (!backtrace)
			goto err_diverge_event;
	}

	spin_lock(&ctx->tasks_lock);
	ret = context_start(ctx, flags, idle_event, diverge_event, backtrace);
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

void scribe_emergency_stop(struct scribe_context *ctx,
			   struct scribe_event *reason)
{
	struct scribe_ps *scribe;

	spin_lock(&ctx->tasks_lock);

	if (ctx->flags == SCRIBE_IDLE) {
		if (!IS_ERR(reason))
			scribe_free_event(reason);
		goto out;
	}

	/*
	 * The SCRIBE_IDLE flag has to be set here (as opposed to after the
	 * killing) to guard against races with scribe_attach() called from
	 * copy_process() or execve(). See in scribe_attach() for more
	 * details.
	 */
	context_idle(ctx, reason);

	/*
	 * The tasks list is most likely to be empty by now.
	 * If it's not empty, it means that the userspace monitor process has
	 * gone missing. We'll kill all the scribed tasks because we cannot
	 * guarantee that they can continue properly.
	 */
	rcu_read_lock();
	list_for_each_entry(scribe, &ctx->tasks, node) {
		do_send_sig_info(SIGKILL, SEND_SIG_PRIV, scribe->p, 1);
		/*
		 * do_send_sig_info() may fail because the signal handler is
		 * gone, and the task is waiting on a resource in do_exit()
		 * during the replay. wake_up_process() is necessary in that
		 * case.
		 */
		wake_up_process(scribe->p);
	}
	rcu_read_unlock();

out:
	spin_unlock(&ctx->tasks_lock);
}

/*
 * XXX This is not an emergency_stop. This is just a notification that will
 * initiate a graceful ending.
 * Processes are checking for the SCRIBE_STOP flag when entering a syscall.
 */
int scribe_stop(struct scribe_context *ctx)
{
	int ret = 0;

	spin_lock(&ctx->tasks_lock);
	if (ctx->flags == SCRIBE_IDLE)
		ret = -EPERM;
	else if (list_empty(&ctx->tasks))
		context_idle(ctx, NULL);
	else {
		ctx->flags |= SCRIBE_STOP;
		if (ctx->flags & SCRIBE_RECORD)
			scribe_wake_all_fake_sig(ctx);
	}
	spin_unlock(&ctx->tasks_lock);

	/*
	 * FIXME send a signal wakeup to tasks, set TIF_SIGPENDING or
	 * something.
	 */

	return ret;
}

/* scribe_wake_all_fake_sig() interrupts syscalls */
void scribe_wake_all_fake_sig(struct scribe_context *ctx)
{
	unsigned long flags;
	struct scribe_ps *scribe;

	list_for_each_entry(scribe, &ctx->tasks, node) {
		spin_lock_irqsave(&scribe->p->sighand->siglock, flags);
		signal_wake_up(scribe->p, 0);
		spin_unlock_irqrestore(&scribe->p->sighand->siglock, flags);
	}
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
 * scribe_attach() and scribe_detach() must only be called when
 * current == scribe->p, or when scribe->p is sleeping (and thus not accessing
 * scribe->flags).
 */
void scribe_attach(struct scribe_ps *scribe)
{
	struct scribe_context *ctx = scribe->ctx;

	/*
	 * First get the queue, and only then, add to the task list:
	 * It guarantees that if a task is in the task list, its
	 * queue would also be in the queue list.
	 */
	BUG_ON(scribe->queue);
	BUG_ON(!scribe->pre_alloc_queue);
	scribe->queue = scribe_get_queue_by_pid(ctx, &scribe->pre_alloc_queue,
						task_pid_vnr(scribe->p));
	kfree(scribe->pre_alloc_queue);
	scribe->pre_alloc_queue = NULL;

	spin_lock(&ctx->tasks_lock);
	BUG_ON(is_scribed(scribe));

	if (unlikely(ctx->flags == SCRIBE_IDLE)) {
		spin_unlock(&ctx->tasks_lock);

		/*
		 * Two reasons we landed here:
		 * 1) We got caught in the attach_on_exec race:
		 *    - the process calls scribe_set_attach_on_exec(ctx)
		 *    - the context goes idle (event pump, or device closed)
		 *    - the process calls execve(), and lands here
		 *
		 * 2) copy_process() was about to attach a child, when
		 * suddenly scribe_emergency_stop() got called and distributed
		 * some SIGKILLs, but only to the parent.
		 *
		 * We can SIGKILL the current process because if we attached
		 * right before the context went SCRIBE_IDLE, we would have
		 * received the SIGKILL from emergency_stop() anyways. It's a
		 * race.
		 *
		 * Note: During replay, in case a new event comes in for our
		 * pid, a new queue will be instantiated by the device, and
		 * will never be picked up by any process. But that's fine
		 * because it means something went wrong, and the scribe
		 * context is about to die, the queue will get freed anyways.
		 */

		spin_lock(&ctx->queues_lock);
		scribe_unset_persistent(scribe->queue);
		spin_unlock(&ctx->queues_lock);

		do_send_sig_info(SIGKILL, SEND_SIG_PRIV, scribe->p, 1);
		exit_scribe(scribe->p);
		return;
	}

	list_add_tail(&scribe->node, &ctx->tasks);
	spin_unlock(&ctx->tasks_lock);

	wake_up(&ctx->tasks_wait);

	scribe->flags |= (ctx->flags & SCRIBE_RECORD) ? SCRIBE_PS_RECORD : 0;
	scribe->flags |= (ctx->flags & SCRIBE_REPLAY) ? SCRIBE_PS_REPLAY : 0;
	scribe->flags |= SCRIBE_PS_ENABLE_ALL;

	if (is_recording(scribe)) {
		/*
		 * The monitor will be waiting on ctx->queue_wait, and all
		 * processes sends their event queue notifications to it.
		 */
		scribe->queue->stream.wait = &ctx->queues_wait;
	} else { /* is_replaying(scribe) == 1 */

		/*
		 * We can now release the persistent reference that was holding
		 * the queue waiting the process to attach since we got our
		 * reference in scribe_get_queue_by_pid()
		 */
		spin_lock(&ctx->queues_lock);
		scribe_unset_persistent(scribe->queue);
		spin_unlock(&ctx->queues_lock);

		BUG_ON(scribe->queue->stream.wait !=
		       &scribe->queue->stream.default_wait);
	}

	scribe->in_syscall = 0;
	scribe->data_flags = 0;
	scribe->prepared_data_event.generic = NULL;
	scribe->can_uaccess = 0;

	scribe_attach_arch(scribe);

	scribe_open_files(scribe->p->files);
	BUG_ON(scribe_mem_init_st(scribe));
}

void __scribe_detach(struct scribe_ps *scribe)
{
	struct scribe_context *ctx = scribe->ctx;
	unsigned int scribe_flags;
	bool sighand_locked;
	unsigned long flags;

	BUG_ON(!is_scribed(scribe));

	WARN_ON(scribe->can_uaccess && ctx->flags != SCRIBE_IDLE);
	WARN_ON(is_recording(scribe) && scribe->signal.should_defer);

	scribe_detach_arch(scribe);

	if (scribe->prepared_data_event.generic) {
		WARN(1, "prepared_data_event present\n");
		scribe_free_event(scribe->prepared_data_event.generic);
	}

	spin_lock(&ctx->tasks_lock);
	list_del(&scribe->node);

	/*
	 * The last task in the context is detaching, it's time to set it to
	 * idle. Userspace will get notified.
	 */
	if (list_empty(&ctx->tasks) && ctx->flags != SCRIBE_IDLE)
		context_idle(ctx, NULL);
	spin_unlock(&ctx->tasks_lock);
	wake_up(&ctx->tasks_wait);

	/*
	 * The sighand lock guards against some races within the signal code.
	 */
	scribe_flags = scribe->flags;

	sighand_locked = !!lock_task_sighand(scribe->p, &flags);
	scribe->flags &= ~(SCRIBE_PS_RECORD | SCRIBE_PS_REPLAY);
	if (sighand_locked)
		unlock_task_sighand(scribe->p, &flags);

	/*
	 * We want to set the sealed flag and put the queue in an atomic
	 * way so that the event pump sends a QUEUE_EOF event once and only
	 * once.
	 */
	spin_lock(&ctx->queues_lock);
	if (scribe_flags & SCRIBE_PS_RECORD)
		scribe_seal_queue(scribe->queue);
	scribe_put_queue_locked(scribe->queue);
	spin_unlock(&ctx->queues_lock);

	scribe->queue = NULL;
}

void scribe_detach(struct scribe_ps *scribe)
{
	scribe->flags |= SCRIBE_PS_DETACHING;
	if (is_replaying(scribe))
		scribe_kill_queue(scribe->queue);

	scribe_mem_exit_st(scribe);
	scribe_close_files(scribe->p->files);
	__scribe_detach(scribe);
}

static bool should_detach(struct scribe_ps *scribe)
{
	if (scribe->ctx->flags & SCRIBE_STOP)
		return true;

	if (scribe_is_queue_dead(scribe->queue))
		return true;

	return false;
}

bool scribe_maybe_detach(struct scribe_ps *scribe)
{
	struct scribe_context *ctx = scribe->ctx;

	if (!should_detach(scribe))
		return false;

	scribe_get_context(ctx);
	scribe_detach(scribe);
	exit_scribe(scribe->p);

	wait_event(ctx->tasks_wait, list_empty(&ctx->tasks) || ctx->last_error);
	/*
	 * FIXME possible race: when list_empty(ctx->task), the context might
	 * have started again, and other tasks might have joined the context.
	 */
	if (ctx->last_error)
		do_send_sig_info(SIGKILL, SEND_SIG_PRIV, scribe->p, 1);
	scribe_put_context(ctx);

	return true;
}
