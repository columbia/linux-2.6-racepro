/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/scribe.h>

#ifdef CONFIG_PROC_FS

static int status_seq_show(struct seq_file *seq, void *offset)
{
	struct scribe_ps *scribe;
	struct scribe_context *ctx = seq->private;
	const char *status1 = "";
	const char *status2 = "";

	if (!ctx)
		return 0;

	if (ctx->flags == SCRIBE_IDLE)
		status1 = "idle";
	else if (ctx->flags & SCRIBE_RECORD)
		status1 = "record";
	else if (ctx->flags & SCRIBE_REPLAY)
		status1 = "replay";
	if (ctx->flags & SCRIBE_STOP)
		status2 = ", stop";

	seq_printf(seq, "status: %s%s\n", status1, status2);
	seq_printf(seq, "tasks:\n");

	spin_lock(&ctx->tasks_lock);
	list_for_each_entry(scribe, &ctx->tasks, node)
		seq_printf(seq, "  [%d]\n", task_pid_vnr(scribe->p));
	spin_unlock(&ctx->tasks_lock);

	return 0;
}

static int status_open_fs(struct inode *inode, struct file *file)
{
	return single_open(file, status_seq_show, PDE(inode)->data);
}

static const struct file_operations status_fops = {
	.open = status_open_fs,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static char *get_ctx_proc_name(struct scribe_context *ctx, char *str)
{
	sprintf(str, "context%d", ctx->id);
	return str;
}
static int register_proc(struct scribe_context *ctx)
{
	struct proc_dir_entry *ctx_entry;
	struct proc_dir_entry *entry;
	char str[32];

	ctx_entry = create_proc_entry(get_ctx_proc_name(ctx, str),
				      S_IFDIR | S_IRUGO | S_IXUGO,
				      scribe_proc_root);
	if (!ctx_entry)
		return -ENOMEM;

	entry = proc_create_data("status", S_IRUGO, ctx_entry,
				 &status_fops, ctx);
	if (!entry)
		goto err;

	ctx->proc_entry = ctx_entry;
	return 0;

err:
	remove_proc_entry(get_ctx_proc_name(ctx, str), scribe_proc_root);
	return -ENOMEM;
}
static void unregister_proc(struct scribe_context *ctx)
{
	char str[32];
	remove_proc_entry("status", ctx->proc_entry);
	remove_proc_entry(get_ctx_proc_name(ctx, str), scribe_proc_root);
}

#else
static inline int register_proc(struct scribe_context *ctx) { return 0; }
static inline void unregister_proc(struct scribe_context *ctx) { }
#endif /* CONFIG_PROC_FS */

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
	scribe_make_persistent(ctx->notification_queue, 0);

	if (register_proc(ctx))
		goto err_queue;

	return ctx;

err_queue:
	scribe_put_queue(ctx->notification_queue);
err_ctx:
	kfree(ctx);
err:
	return NULL;
}

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
	ctx->flags = SCRIBE_IDLE;
	ctx->idle_error = error;

	/*
	 * The tasks list is most likely to be empty by now.
	 * If it's not empty, it means that the userspace monitor process has
	 * gone missing. We'll kill all the scribed tasks because we cannot
	 * guarantee that they can continue (no more events).
	 */
	if (unlikely(!list_empty(&ctx->tasks))) {
		printk(KERN_WARNING "scribe: emergency stop (context=%d)\n",
		       ctx->id);

		list_for_each_entry(scribe, &ctx->tasks, node)
			force_sig(SIGKILL, scribe->p);

		spin_unlock(&ctx->tasks_lock);
		wait_event(ctx->tasks_wait, list_empty(&ctx->tasks));
		spin_lock(&ctx->tasks_lock);
	}
	spin_unlock(&ctx->tasks_lock);
}

void scribe_exit_context(struct scribe_context *ctx)
{
	struct scribe_event_queue *queue, *tmp;

	scribe_emergency_stop(ctx, 0);

	spin_lock(&ctx->queues_lock);
	list_for_each_entry_safe(queue, tmp, &ctx->queues, node)
		scribe_make_persistent(queue, 0);
	spin_unlock(&ctx->queues_lock);

	scribe_put_queue(ctx->notification_queue);
	unregister_proc(ctx);
	scribe_put_context(ctx);
}

static int context_start(struct scribe_context *ctx, int action)
{
	spin_lock(&ctx->tasks_lock);
	if (ctx->flags != SCRIBE_IDLE) {
		spin_unlock(&ctx->tasks_lock);
		return -EPERM;
	}

	BUG_ON(!list_empty(&ctx->tasks));

	ctx->idle_error = 0;
	ctx->flags = action;
	spin_unlock(&ctx->tasks_lock);

	return 0;
}

static int context_stop(struct scribe_context *ctx)
{
	int ret = 0;

	spin_lock(&ctx->tasks_lock);
	if (ctx->flags == SCRIBE_IDLE)
		ret = -EPERM;
	else if (list_empty(&ctx->tasks))
		ctx->flags = SCRIBE_IDLE;
	else
		ctx->flags &= SCRIBE_STOP;
	spin_unlock(&ctx->tasks_lock);

	return ret;
}

int scribe_set_state(struct scribe_context *ctx, int state)
{
	if ((state & SCRIBE_STOP) == state)
		return context_stop(ctx);
	if ((state & SCRIBE_RECORD) == state)
		return context_start(ctx, state);
	if ((state & SCRIBE_REPLAY) == state)
		return context_start(ctx, state);

	return -EINVAL;
}

int scribe_set_attach_on_exec(struct scribe_context *ctx, int enable)
{
	struct task_struct *p = current;
	int ret;

	if (is_ps_scribbed(p))
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
	BUG_ON(is_scribbed(scribe));

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
		 * suddenly scribe_exit_context() got called and distributed
		 * some SIG_KILLs, but only to the parent, which is why we
		 * need to do our own cleanup.
		 */
		spin_lock(&ctx->queues_lock);
		scribe_make_persistent(scribe->queue, 0);
		spin_unlock(&ctx->queues_lock);
		exit_scribe(scribe->p);
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
}

void scribe_detach(struct scribe_ps *scribe)
{
	struct scribe_context *ctx = scribe->ctx;
	BUG_ON(!is_scribbed(scribe));

	spin_lock(&ctx->tasks_lock);
	list_del(&scribe->node);

	/* We were the last task in the context, it's time to set it idle */
	if (list_empty(&ctx->tasks))
		ctx->flags = SCRIBE_IDLE;
	spin_unlock(&ctx->tasks_lock);
	wake_up(&ctx->tasks_wait);

	if (is_recording(scribe))
		scribe_set_queue_wont_grow(scribe->queue);

	scribe_put_queue(scribe->queue);
	scribe->queue = NULL;

	scribe->flags &= ~(SCRIBE_PS_RECORD | SCRIBE_PS_REPLAY);
}
