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
		return NULL;

	atomic_set(&ctx->ref_cnt, 0);
	ctx->id = current->pid;
	ctx->flags = SCRIBE_IDLE;

	spin_lock_init(&ctx->tasks_lock);
	INIT_LIST_HEAD(&ctx->tasks);
	init_waitqueue_head(&ctx->tasks_wait);

	spin_lock_init(&ctx->queues_lock);
	INIT_LIST_HEAD(&ctx->queues);
	init_waitqueue_head(&ctx->queues_wait);

	if (register_proc(ctx)) {
		kfree(ctx);
		return NULL;
	}

	scribe_get_context(ctx);

	return ctx;
}

void scribe_exit_context(struct scribe_context *ctx)
{
	struct scribe_event_queue *queue, *tmp;
	struct scribe_ps *scribe;

	spin_lock(&ctx->tasks_lock);
	/* The tasks list should be empty by now.
	 * If it's not, it means that the userspace monitor process
	 * has gone missing. We'll kill all the scribed tasks because
	 * we cannot guarantee that they can continue (no more events)
	 */

	if (!list_empty(&ctx->tasks)) {
		printk(KERN_WARNING "scribe: emergency stop (context=%d)\n",
		       ctx->id);
		BUG_ON(ctx->flags == SCRIBE_IDLE);
		list_for_each_entry(scribe, &ctx->tasks, node)
			force_sig(SIGKILL, scribe->p);

		spin_unlock(&ctx->tasks_lock);
		wait_event(ctx->tasks_wait, ctx->flags == SCRIBE_IDLE);
		spin_lock(&ctx->tasks_lock);
	}

	/* Setting the SCRIBE_DEAD flag has to be set with the lock,
	 * to guards against race with attach_on_exec.
	 */
	ctx->flags = SCRIBE_DEAD;
	spin_unlock(&ctx->tasks_lock);


	spin_lock(&ctx->queues_lock);
	list_for_each_entry_safe(queue, tmp, &ctx->queues, node) {
		if (!(queue->flags & SCRIBE_CTX_DETACHED)) {
			queue->flags |= SCRIBE_CTX_DETACHED;
			scribe_put_queue_locked(queue);
		}
	}
	spin_unlock(&ctx->queues_lock);

	unregister_proc(ctx);

	scribe_put_context(ctx);
}

static int context_start(struct scribe_context *ctx, int action)
{
	if (ctx->flags != SCRIBE_IDLE)
		return -EPERM;

	ctx->flags = action;
	return 0;
}

static int context_stop(struct scribe_context *ctx)
{
	if (ctx->flags == SCRIBE_IDLE)
		return -EPERM;
	if (ctx->flags & SCRIBE_STOP)
		return 0;
	ctx->flags = SCRIBE_IDLE;
	return 0;
}

int scribe_set_state(struct scribe_context *ctx, int state)
{
	if (state & ~(SCRIBE_RECORD | SCRIBE_REPLAY | SCRIBE_STOP))
		return -EINVAL;

	if (state & SCRIBE_STOP)
		return context_stop(ctx);

	if (state)
		return context_start(ctx, state);

	return -EINVAL;
}

int scribe_set_attach_on_exec(struct scribe_context *ctx, int enable)
{
	struct task_struct *p = current;
	int ret;

	if (is_ps_scribbed(p))
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

/* scribe_attach() and scribe_detach() must be called only by
 * the current process or if scribe->p is sleeping (and thus not accessing
 * scribe->flags)
 */
int scribe_attach(struct scribe_ps *scribe)
{
	struct scribe_context *ctx = scribe->ctx;
	struct scribe_event_queue *queue;
	int ret;

	/* First get the queue, and only then, add to the task list:
	 * It guarantee that if a task is in the task list, its
	 * queue is in the queue list
	 */

	queue = scribe_get_queue_by_pid(ctx, task_pid_vnr(scribe->p));
	if (!queue)
		return -ENOMEM;
	scribe->queue = queue;

	spin_lock(&ctx->tasks_lock);
	BUG_ON(!(ctx->flags & (SCRIBE_RECORD | SCRIBE_REPLAY)));
	BUG_ON(is_scribbed(scribe));

	if (unlikely(ctx->flags & SCRIBE_DEAD)) {
		spin_unlock(&ctx->tasks_lock);
		ret = -ENODEV;
		goto err_queue;
	}

	list_add_tail(&scribe->node, &ctx->tasks);
	spin_unlock(&ctx->tasks_lock);

	scribe->flags |= (ctx->flags & SCRIBE_RECORD) ? SCRIBE_PS_RECORD : 0;
	scribe->flags |= (ctx->flags & SCRIBE_REPLAY) ? SCRIBE_PS_REPLAY : 0;

	if (is_recording(scribe)) {
		/* The monitor will be waiting on ctx->queue_wait, and all
		 * processes sends their notification to it.
		 */
		queue->wait = &ctx->queues_wait;
	}
	else { /* is_replaying(scribe) == 1 */
		/* Releasing the reference that the context has on it.
		 * That way when the process detaches, the queue will
		 * be removed right away.
		 * In case new events comes in for new events, a new queue
		 * will be instanciated, and will never be picked up by any
		 * process. But that's fine because it means something went
		 * wrong, and the scribe context is about to die. Clean up
		 * will occure anyways
		 */
		queue->flags |= SCRIBE_CTX_DETACHED;
		scribe_put_queue(queue);
	}

	wake_up(&ctx->tasks_wait);
	return 0;

err_queue:
	if (is_recording(scribe)) {
		/* The context has a reference to the queue. */
		scribe_set_queue_wont_grow(queue);
		scribe_put_queue(queue);
	}
	scribe_put_queue(queue);
	scribe->flags &= ~(SCRIBE_PS_RECORD | SCRIBE_PS_REPLAY);

	return ret;
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
	scribe->flags &= ~(SCRIBE_PS_RECORD | SCRIBE_PS_REPLAY);
}


static struct scribe_event_queue *
find_queue(struct scribe_context *ctx, pid_t pid)
{
	struct scribe_event_queue *queue;

	list_for_each_entry(queue, &ctx->queues, node)
		if (queue->pid == pid)
			return queue;

	return NULL;
}

struct scribe_event_queue *
scribe_get_queue_by_pid(struct scribe_context *ctx, pid_t pid)
{
	struct scribe_event_queue *queue, *new_queue;

	spin_lock(&ctx->queues_lock);

	queue = find_queue(ctx, pid);
	if (!queue) {
		spin_unlock(&ctx->queues_lock);

		new_queue = scribe_alloc_event_queue();
		if (!new_queue)
			return NULL;

		spin_lock(&ctx->queues_lock);

		queue = find_queue(ctx, pid);
		if (queue) {
			/* raced */
			scribe_free_event_queue(new_queue);
		}
		else {
			queue = new_queue;

			/* A newly created queue will have a ref_cnt = 2:
			 * - The queue is registered by the context
			 * - The function returns a queue pointer
			 */
			atomic_inc(&queue->ref_cnt);
			list_add(&queue->node, &ctx->queues);
			queue->ctx = ctx;
			queue->pid = pid;
		}
	}

	atomic_inc(&queue->ref_cnt);
	spin_unlock(&ctx->queues_lock);

	return queue;
}

void scribe_get_queue(struct scribe_event_queue *queue)
{
	atomic_inc(&queue->ref_cnt);
}

void scribe_put_queue(struct scribe_event_queue *queue)
{
	struct scribe_context *ctx = queue->ctx;

	if (atomic_dec_and_lock(&queue->ref_cnt, &ctx->queues_lock)) {
		list_del(&queue->node);
		spin_unlock(&ctx->queues_lock);
		scribe_free_event_queue(queue);
	}
}

void scribe_put_queue_locked(struct scribe_event_queue *queue)
{
	if (atomic_dec_and_test(&queue->ref_cnt)) {
		list_del(&queue->node);
		scribe_free_event_queue(queue);
	}
}
