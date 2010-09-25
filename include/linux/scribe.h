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
#include <linux/wait.h>
#include <asm/atomic.h>

struct proc_dir_entry;
struct task_struct;

#define SCRIBE_IDLE		0x00000000
#define SCRIBE_RECORD		0x00000001
#define SCRIBE_REPLAY		0x00000002
#define SCRIBE_STOP		0x00000004
#define SCRIBE_DEAD		0x80000000

#ifdef CONFIG_PROC_FS
extern struct proc_dir_entry *scribe_proc_root;
#endif

struct scribe_context {
	atomic_t ref_cnt;
	int id;
	int flags;

	spinlock_t tasks_lock;
	struct list_head tasks;
	wait_queue_head_t tasks_wait;

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
int scribe_set_state(struct scribe_context *ctx, int state);
int scribe_set_attach_on_exec(struct scribe_context *ctx, int enable);

#define SCRIBE_DEVICE_NAME		"scribe"
#define SCRIBE_IO_MAGIC			0xFF
#define SCRIBE_IO_SET_STATE		_IOR(SCRIBE_IO_MAGIC,	1, int)
#define SCRIBE_IO_ATTACH_ON_EXEC	_IOR(SCRIBE_IO_MAGIC,	2, int)


#define SCRIBE_PS_ATTACH_ON_EXEC 0x00000001

struct scribe_ps {
	/* The two next fields should only be written to by
	 * the current process.
	 */
	int flags;
	struct scribe_context *ctx;
	struct task_struct *p;

	struct list_head task_node;
};

static inline int __is_scribbed(struct scribe_ps *scribe)
{ return scribe != NULL && scribe->ctx->flags & (SCRIBE_RECORD | SCRIBE_REPLAY); }
static inline int __is_recording(struct scribe_ps *scribe)
{ return scribe != NULL && scribe->ctx->flags & SCRIBE_RECORD; }
static inline int __is_replaying(struct scribe_ps *scribe)
{ return scribe != NULL && scribe->ctx->flags & SCRIBE_REPLAY; }

/* Using defines instead of inline functions so that we don't need
 * to include sched.h
 */
#define is_scribbed(t)  __is_scribbed(t->scribe)
#define is_recording(t) __is_recording(t->scribe)
#define is_replaying(t) __is_replaying(t->scribe)

void scribe_attach(struct scribe_ps *scribe);
void scribe_detach(struct scribe_ps *scribe);

int init_scribe(struct task_struct *p, struct scribe_context *ctx);
void exit_scribe(struct task_struct *p);

#else /* CONFIG_SCRIBE */

#define is_scribbed(t)  0
#define is_recording(t) 0
#define is_replaying(t) 0

static inline int init_scribe(struct task_struct *p, struct scribe_context *ctx) { return 0; }
static inline void exit_scribe(struct task_struct *tsk) {}

#endif /* CONFIG_SCRIBE */

#endif /* _LINUX_SCRIBE_H_ */
