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
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <asm/atomic.h>
#include <linux/scribe_api.h>
#include <linux/slab.h>

struct proc_dir_entry;
struct task_struct;

/* Context stuff */

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

/* Events */

struct scribe_event_queue;
struct scribe_insert_point {
	struct list_head node;
	struct scribe_event_queue *queue;
	struct list_head events;
};

struct scribe_event_queue {
	atomic_t ref_cnt;
	struct list_head node;

	/* Insert points allows to insert event at an arbitrary location
	 * which is quite handy when we need to put events "in the past",
	 * like saving the return value of a syscall.
	 */
	spinlock_t lock;
	struct scribe_insert_point master;
	/* For simplicity, there is not head of the insert point list */

	/* points to context->wait_event in record mode
	 * points to default_wait in replay mode
	 */
	wait_queue_head_t default_wait;
	wait_queue_head_t *wait;

	/* When wont_grow == 1 and list_empty(events), the queue can be
	 * considered as dead
	 */
	int wont_grow;
};


struct scribe_event_queue *scribe_alloc_event_queue(void);
void scribe_free_event_queue(struct scribe_event_queue *queue);
void scribe_free_all_events(struct scribe_event_queue *queue);

void scribe_create_insert_point(struct scribe_event_queue *queue,
				struct scribe_insert_point *ip);
void scribe_commit_insert_point(struct scribe_insert_point *ip);

void scribe_queue_event_at(struct scribe_insert_point *where, void *event);
void scribe_queue_event(struct scribe_event_queue *queue, void *event);
struct scribe_event *scribe_try_dequeue_event(struct scribe_event_queue *queue);

struct scribe_event_data *scribe_alloc_event_data(size_t size);
void scribe_free_event_data(struct scribe_event_data *event);

static __always_inline void *__scribe_alloc_event_const(__u8 type)
{
	struct scribe_event *event;

	event = kmalloc(sizeof_event_from_type(type), GFP_KERNEL);
	if (event)
		event->type = type;

	return event;
}
void *__scribe_alloc_event(__u8 type);
static __always_inline void *scribe_alloc_event(__u8 type)
{
	if (__builtin_constant_p(type))
		return __scribe_alloc_event_const(type);
	return __scribe_alloc_event(type);
}
static inline void scribe_free_event(void *event)
{
	struct scribe_event_data *event_data = event;
	if (event_data->h.type == SCRIBE_EVENT_DATA)
		scribe_free_event_data(event_data);
	else
		kfree(event);
}

#else /* CONFIG_SCRIBE */

#define is_scribbed(t)  0
#define is_recording(t) 0
#define is_replaying(t) 0

static inline int init_scribe(struct task_struct *p, struct scribe_context *ctx) { return 0; }
static inline void exit_scribe(struct task_struct *tsk) {}

#endif /* CONFIG_SCRIBE */

#endif /* _LINUX_SCRIBE_H_ */
