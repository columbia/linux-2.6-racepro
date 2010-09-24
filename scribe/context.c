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

int scribe_init_context(struct scribe_context *ctx)
{
	int ret;

	atomic_set(&ctx->ref_cnt, 0);
	ctx->id = current->pid;
	ctx->flags = SCRIBE_IDLE;
	INIT_LIST_HEAD(&ctx->tasks);

	ret = register_proc(ctx);
	if (ret)
		return ret;

	return 0;
}

void scribe_exit_context(struct scribe_context *ctx)
{
	unregister_proc(ctx);
}

int scribe_start_on_exec(struct scribe_context *ctx, int action)
{
	struct task_struct *p = current;
	int ret;

	if (action & ~(SCRIBE_RECORD | SCRIBE_REPLAY))
		return -EINVAL;

	if (is_scribbed(p))
		return -EPERM;

	/* XXX if a previous call to start_on_exec() has
	 * already made, we undo the effect, even
	 * if the current call fails
	 */
	exit_scribe(p);

	ret = scribe_info_init(p, ctx);
	if (ret)
		return ret;
	p->scribe->flags = SCRIBE_START_ON_EXEC | action;

	return 0;
}

int scribe_request_stop(struct scribe_context *ctx)
{
	if (ctx->flags == SCRIBE_IDLE)
		return -EPERM;
	if (ctx->flags & SCRIBE_STOP)
		return 0;
	ctx->flags = SCRIBE_IDLE;
	return 0;
}

