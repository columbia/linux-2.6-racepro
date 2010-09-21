/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/sched.h>
#include <linux/idr.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "context.h"

DEFINE_IDR(idr);

#ifdef CONFIG_PROC_FS

static int status_seq_show(struct seq_file *seq, void *offset)
{
	scribe_context_t *ctx = seq->private;
	const char *status1 = "";
	const char *status2 = "";

	if (!ctx)
		return 0;

	if (ctx->status == SCRIBE_IDLE)
		status1 = "idle";
	else if (ctx->status & SCRIBE_RECORD)
		status1 = "record";
	else if (ctx->status & SCRIBE_REPLAY)
		status1 = "replay";
	if (ctx->status & SCRIBE_STOP)
		status2 = ", stop";

	seq_printf(seq, "status: %s%s\n", status1, status2);
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

extern struct proc_dir_entry *scribe_proc_root;
static char *get_ctx_proc_name(scribe_context_t *ctx, char *str)
{
	sprintf(str, "context%d", ctx->id);
	return str;
}
static void unregister_proc(scribe_context_t *ctx);
static int register_proc(scribe_context_t *ctx)
{
	struct proc_dir_entry *p;
	char str[32];

	p = create_proc_entry(get_ctx_proc_name(ctx, str),
			      S_IFDIR | S_IRUGO | S_IXUGO,
			      scribe_proc_root);
	if (!p)
		return -ENOMEM;

	p = proc_create_data("status", S_IRUGO, p, &status_fops, ctx);
	if (!p)
		goto err;

	ctx->proc_entry = p;
	return 0;

err:
	unregister_proc(ctx);
	return -ENOMEM;
}
static void unregister_proc(scribe_context_t *ctx)
{
	char str[32];
	remove_proc_entry(get_ctx_proc_name(ctx, str), scribe_proc_root);
}
#else
static inline int register_proc(scribe_context_t *ctx) { return 0; }
static inline void unregister_proc(scribe_context_t *ctx) { }
#endif /* CONFIG_PROC_FS */

int scribe_init_context(scribe_context_t *ctx)
{
	int ret, id;

retry:
	if (!idr_pre_get(&idr, GFP_KERNEL))
		return -ENOMEM;
	ret = idr_get_new(&idr, ctx, &id);
	if (ret == -EAGAIN)
		goto retry;
	if (ret)
		return -ENFILE;

	ctx->id = id;
	ctx->status = SCRIBE_IDLE;
	INIT_LIST_HEAD(&ctx->tasks);

	ret = register_proc(ctx);
	if (ret) {
		idr_remove(&idr, id);
		return ret;
	}

	return 0;
}

void scribe_exit_context(scribe_context_t *ctx)
{
	idr_remove(&idr, ctx->id);
}

static int __scribe_start_action(scribe_context_t *ctx, int action,
				 struct task_struct *p)
{
	if (ctx->status != SCRIBE_IDLE)
		return -EPERM;

	if (action == SCRIBE_RECORD) {
		ctx->status = SCRIBE_RECORD;
	}
	else if (action == SCRIBE_REPLAY) {
		ctx->status = SCRIBE_REPLAY;
	}
	else
		return -EINVAL;

	put_task_struct(p); /* to be removed */
	return 0;
}

int scribe_start_action(scribe_context_t *ctx, int action, pid_t pid)
{
	struct task_struct *p;
	int ret;

	rcu_read_lock();
	p = find_task_by_vpid(pid);
	if (p)
		get_task_struct(p);
	rcu_read_unlock();

	if (!p)
		return -ESRCH;

	ret = __scribe_start_action(ctx, action, p);
	if (ret)
		put_task_struct(p);
	return ret;
}

int scribe_request_stop(scribe_context_t *ctx)
{
	if (ctx->status == SCRIBE_IDLE)
		return -EPERM;
	if (ctx->status & SCRIBE_STOP)
		return 0;
	ctx->status = SCRIBE_IDLE;
	return 0;
}

