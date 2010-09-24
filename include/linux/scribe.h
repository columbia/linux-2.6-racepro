/*
 *  Scribe, the record/replay mechanism
 *
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#ifndef _LINUX_SCRIBE_H_
#define _LINUX_SCRIBE_H_

#ifdef CONFIG_SCRIBE

#include <linux/types.h>
#include <linux/list.h>
#include <linux/ioctl.h>
#include <asm/atomic.h>

struct proc_dir_entry;
struct task_struct;

#define SCRIBE_IDLE		0x00000000
#define SCRIBE_RECORD		0x00000001
#define SCRIBE_REPLAY		0x00000002
#define SCRIBE_START_ON_EXEC	0x00000004
#define SCRIBE_STOP		0x00000008

#ifdef CONFIG_PROC_FS
extern struct proc_dir_entry *scribe_proc_root;
#endif

struct scribe_context {
	atomic_t ref_cnt;
	int id;
	int flags;
	struct list_head tasks;

#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *proc_entry;
#endif
};

static inline void get_scribe_context(struct scribe_context *ctx)
{
	atomic_inc(&ctx->ref_cnt);
}
static inline void put_scribe_context(struct scribe_context *ctx)
{
	if (atomic_dec_and_test(&ctx->ref_cnt))
		kfree(ctx);
}

int scribe_init_context(struct scribe_context *ctx);
void scribe_exit_context(struct scribe_context *ctx);
int scribe_start_on_exec(struct scribe_context *ctx, int action);
int scribe_request_stop(struct scribe_context *ctx);

#define SCRIBE_DEVICE_NAME	"scribe"
#define SCRIBE_IO_MAGIC		0xFF
#define SCRIBE_IO_START_ON_EXEC	_IOR(SCRIBE_IO_MAGIC,	1, int)
#define SCRIBE_IO_REQUEST_STOP	_IO(SCRIBE_IO_MAGIC,	2)

struct scribe_info {
	/* The two next fields should only be written to by
	 * the current process
	 */
	int flags;
	struct scribe_context *ctx;
};

/* Preferring defines vs inline function so that we don't need to include
 * sched.h for the overhead
 */
#define is_scribbed(t)  (t->scribe != NULL && t->scribe->flags)
#define is_recording(t) (t->scribe != NULL && t->scribe->flags & SCRIBE_RECORD)
#define is_replaying(t) (t->scribe != NULL && t->scribe->flags & SCRIBE_REPLAY)

#else /* CONFIG_SCRIBE */

#define is_scribbed(t)  0
#define is_recording(t) 0
#define is_replaying(t) 0

#endif /* CONFIG_SCRIBE */

#endif /* _LINUX_SCRIBE_H_ */
