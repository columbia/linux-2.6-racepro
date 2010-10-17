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

#include <linux/scribe_api.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <asm/atomic.h>
#include <linux/slab.h>

struct proc_dir_entry;
struct task_struct;

/* Context stuff */

struct scribe_context {
	atomic_t ref_cnt;
	int id;
	int flags;

	spinlock_t tasks_lock;
	struct list_head tasks;
	wait_queue_head_t tasks_wait;

	int queues_wont_grow;
	spinlock_t queues_lock;
	struct list_head queues;
	wait_queue_head_t queues_wait;

	struct scribe_event_queue *notification_queue;
	struct scribe_event_context_idle *idle_event;
};

static inline void scribe_get_context(struct scribe_context *ctx)
{
	atomic_inc(&ctx->ref_cnt);
}
static inline void scribe_put_context(struct scribe_context *ctx)
{
	if (atomic_dec_and_test(&ctx->ref_cnt))
		kfree(ctx);
}

extern struct scribe_context *scribe_alloc_context(void);
extern void scribe_emergency_stop(struct scribe_context *ctx, int reason);
extern void scribe_exit_context(struct scribe_context *ctx);
extern int scribe_set_state(struct scribe_context *ctx, int state);


/* Events */

struct scribe_insert_point {
	struct list_head node;
	struct scribe_event_queue *queue;
	struct list_head events;
};

#define SCRIBE_WONT_GROW 1
#define SCRIBE_PERSISTENT 2

struct scribe_event_queue {
	atomic_t ref_cnt;

	/*
	 * ctx, node and pid are only relevent when the queue has been
	 * attached to the context list of queues, with
	 * scribe_get_queue_by_pid()
	 */
	struct scribe_context *ctx;
	struct list_head node;
	pid_t pid;

	/*
	 * When wont_grow == 1 and list_empty(events), the queue can be
	 * considered as dead
	 */
	int flags;

	/*
	 * Insert points allows to insert event at an arbitrary location
	 * which is quite handy when we need to put events "in the past",
	 * like saving the return value of a syscall.
	 */
	spinlock_t lock;
	/* For simplicity, there is not list head of the insert point list */
	struct scribe_insert_point master;

	/*
	 * 'wait' points to:
	 * - context->wait_event in record mode
	 * - default_wait in replay mode
	 */
	wait_queue_head_t default_wait;
	wait_queue_head_t *wait;
};

extern struct scribe_event_queue *scribe_alloc_event_queue(void);
extern struct scribe_event_queue *scribe_get_queue_by_pid(
				struct scribe_context *ctx,
				struct scribe_event_queue **pre_alloc_queue,
				pid_t pid);
extern void scribe_get_queue(struct scribe_event_queue *queue);
extern void scribe_put_queue(struct scribe_event_queue *queue);
extern void scribe_put_queue_nolock(struct scribe_event_queue *queue);
extern void scribe_make_persistent(struct scribe_event_queue *queue,
				   int enable);
extern void scribe_free_all_events(struct scribe_event_queue *queue);

extern void scribe_create_insert_point(struct scribe_event_queue *queue,
				       struct scribe_insert_point *ip);
extern void scribe_commit_insert_point(struct scribe_insert_point *ip);

extern void scribe_queue_event_at(struct scribe_insert_point *where,
				  void *event);
extern void scribe_queue_event(struct scribe_event_queue *queue, void *event);

/*
 * This macro allows us to write such code:
 *	scribe_queue_new_event(scribe->queue,
 *			       SCRIBE_EVENT_SYSCALL,
 *			       .nr = 1, .ret = 2);
 */
#define scribe_queue_new_event(queue, _type, ...)			\
({									\
	struct_##_type *__new_event;					\
	int __ret = 0;							\
									\
	__new_event = scribe_alloc_event(_type);			\
	if (!__new_event)						\
		__ret = -ENOMEM;					\
	else {								\
		*__new_event = (struct_##_type)				\
			{.h = {.type = _type},  __VA_ARGS__};		\
		scribe_queue_event(queue, __new_event);			\
	}								\
	__ret;								\
})

#define SCRIBE_NO_WAIT 0
#define SCRIBE_WAIT 1
#define SCRIBE_WAIT_INTERRUPTIBLE 2
extern struct scribe_event *scribe_dequeue_event(
				struct scribe_event_queue *queue, int wait);
extern struct scribe_event *scribe_peek_event(
				struct scribe_event_queue *queue, int wait);
#define scribe_dequeue_event_specific(_type, queue, wait)		\
({									\
	struct scribe_event *__event;					\
									\
	__event = scribe_dequeue_event(queue, wait);			\
	if (IS_ERR(__event))						\
		scribe_emergency_stop(queue->ctx, PTR_ERR(__event));	\
	else if (__event->type != _type) {				\
		scribe_free_event(__event);				\
		scribe_emergency_stop(queue->ctx, -EDIVERGE);		\
		__event = ERR_PTR(-EDIVERGE);				\
	}								\
	(struct_##_type *)__event;					\
})

extern int scribe_is_queue_empty(struct scribe_event_queue *queue);
extern void scribe_set_queue_wont_grow(struct scribe_event_queue *queue);

extern struct scribe_event_data *scribe_alloc_event_data(size_t size);

/*
 * We need the __always_inline (like kmalloc()) to make sure that the constant
 * propagation with its optimization will be made by the compiler.
 */
static __always_inline void *__scribe_alloc_event_const(__u8 type)
{
	struct scribe_event *event;

	event = kmalloc(sizeof_event_from_type(type), GFP_KERNEL);
	if (event)
		event->type = type;

	return event;
}
extern void *__scribe_alloc_event(__u8 type);
void __please_use_scribe_alloc_event_data(void);
static __always_inline void *scribe_alloc_event(__u8 type)
{
	if (__builtin_constant_p(type)) {
		if (type == SCRIBE_EVENT_DATA)
			__please_use_scribe_alloc_event_data();
		return __scribe_alloc_event_const(type);
	}
	return __scribe_alloc_event(type);
}
static inline void scribe_free_event(void *event)
{
	kfree(event);
}


/* Per-process state */

#define SCRIBE_PS_RECORD	0x00000001
#define SCRIBE_PS_REPLAY	0x00000002
#define SCRIBE_PS_ATTACH_ON_EXEC 0x00000004

struct scribe_event_queue;
struct scribe_ps {
	struct list_head node;

	/*
	 * The two next fields should only be accessed by
	 * the current process.
	 */
	int flags;
	struct scribe_context *ctx;

	struct task_struct *p;
	struct scribe_event_queue *pre_alloc_queue;
	struct scribe_event_queue *queue;

	struct scribe_insert_point syscall_ip;
	int in_syscall;

	struct scribe_event_data *prepared_data_event;
	int data_flags;
	int can_uaccess;
};

static inline int is_scribed(struct scribe_ps *scribe)
{
	return scribe != NULL &&
	       (scribe->flags & (SCRIBE_PS_RECORD | SCRIBE_PS_REPLAY));
}
static inline int is_recording(struct scribe_ps *scribe)
{
	return scribe != NULL && (scribe->flags & SCRIBE_PS_RECORD);
}
static inline int is_replaying(struct scribe_ps *scribe)
{
	return scribe != NULL && (scribe->flags & SCRIBE_PS_REPLAY);
}
static inline int is_stopping(struct scribe_ps *scribe)
{
	return scribe != NULL && scribe->ctx &&
		(scribe->ctx->flags & SCRIBE_STOP);
}

/* Using defines instead of inline functions so that we don't need
 * to include sched.h
 */
#define is_ps_scribed(t)  is_scribed(t->scribe)
#define is_ps_recording(t) is_recording(t->scribe)
#define is_ps_replaying(t) is_replaying(t->scribe)

extern int init_scribe(struct task_struct *p, struct scribe_context *ctx);
extern void exit_scribe(struct task_struct *p);

extern int scribe_set_attach_on_exec(struct scribe_context *ctx, int enable);
extern void scribe_attach(struct scribe_ps *scribe);
extern void scribe_detach(struct scribe_ps *scribe);

extern void __scribe_allow_uaccess(struct scribe_ps *scribe);
extern void __scribe_forbid_uaccess(struct scribe_ps *scribe);
extern void scribe_allow_uaccess(void);
extern void scribe_forbid_uaccess(void);
extern void scribe_prepare_data_event(size_t pre_alloc_size);

#define SCRIBE_DATA_INPUT		0x01
#define SCRIBE_DATA_STRING		0x02
#define SCRIBE_DATA_NON_DETERMINISTIC	0x04
#define SCRIBE_DATA_INTERNAL		0x08
#define SCRIBE_DATA_DONT_RECORD		0x10
#define SCRIBE_DATA_IGNORE		0x20
static inline void scribe_set_data_flags(struct scribe_ps *scribe, int flags)
{
	scribe->data_flags = flags;
}
static inline int scribe_get_data_flags(struct scribe_ps *scribe)
{
	return scribe->data_flags;
}
extern void scribe_pre_schedule(void);
extern void scribe_post_schedule(void);

#define scribe_interpose_value(dst, src)				\
({									\
	int __ret = 0;							\
	struct scribe_ps *__scribe = current->scribe;			\
	struct scribe_event_data *__event;				\
									\
	if (is_recording(__scribe)) {					\
		__event = scribe_alloc_event_data(sizeof(src));		\
		if (!__event)						\
			__ret = -ENOMEM;				\
		else {							\
			__event->data_type = SCRIBE_DATA_INTERNAL;	\
			__event->user_ptr = 0;				\
			(dst) = *((__typeof__(src) *)__event->data)	\
			      = (src);					\
			scribe_queue_event(__scribe->queue, __event);	\
		}							\
	} else if (is_replaying(__scribe)) {				\
		__event = scribe_dequeue_event_specific(		\
				SCRIBE_EVENT_DATA,			\
				__scribe->queue, SCRIBE_WAIT);		\
		if (IS_ERR(__event)) {					\
			__ret = PTR_ERR(__event);			\
			/* the next line fixes a compiler warning */	\
			__ret = __ret ? : -EDIVERGE;			\
		}							\
		else if (__event->data_type != SCRIBE_DATA_INTERNAL ||	\
			 __event->size != sizeof(src)) {		\
			scribe_free_event(__event);			\
			scribe_emergency_stop(__scribe->ctx,		\
					      -EDIVERGE);		\
			__ret = -EDIVERGE;				\
		} else {						\
			(dst) = __event->ldata[0];			\
			scribe_free_event(__event);			\
		}							\
	} else								\
		(dst) = (src);						\
									\
	__ret;								\
})

#else /* CONFIG_SCRIBE */

#define is_ps_scribed(t)  0
#define is_ps_recording(t) 0
#define is_ps_replaying(t) 0

static inline int init_scribe(struct task_struct *p,
			      struct scribe_context *ctx) { return 0; }
static inline void exit_scribe(struct task_struct *tsk) {}

static inline void scribe_allow_uaccess(void) {}
static inline void scribe_forbid_uaccess(void) {}
static inline void scribe_prepare_data_event(size_t pre_alloc_size) {}
static inline void scribe_pre_schedule(void) {}
static inline void scribe_post_schedule(void) {}

#define scribe_interpose_value(dst, src) ({ (dst) = (src); 0; })

#endif /* CONFIG_SCRIBE */

#endif /* _LINUX_SCRIBE_H_ */
