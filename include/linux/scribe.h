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
#include <linux/scribe_resource.h>
#include <linux/scribe_uaccess.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <asm/scribe.h>
#include <asm/atomic.h>

/* Events */

struct scribe_insert_point {
	struct list_head node;
	struct scribe_queue_bare *bare;
	struct list_head events;
};

struct scribe_queue_bare {
	spinlock_t lock;
	/*
	 * For simplicity, there is not list head of the insert point list:
	 * It's a circular list, and there is no need to interate through
	 * the list.
	 */
	struct scribe_insert_point master;

	/*
	 * When wont_grow == 1 and list_empty(events), the queue can be
	 * considered as dead.
	 */
	int wont_grow;

	/*
	 * 'wait' points to:
	 * - &ctx->wait_event in record mode (many producers, one consumer)
	 * - &default_wait in replay mode (one producer, many consumer)
	 */
	wait_queue_head_t default_wait;
	wait_queue_head_t *wait;
};

/*
 * scribe_queue are used for the per process queue whereas the
 * scribe_queue_bare are used freely, unrelated to a specific process (e.g.
 * the notification queue).
 */
struct scribe_queue {
	struct scribe_queue_bare bare;

	atomic_t ref_cnt;

	/* when persistent == 1, it means that we take an additional internal
	 * reference (This is useful to pass the queue around without having
	 * it to die in the middle).
	 */
	int persistent;

	struct scribe_context *ctx;
	struct list_head node;
	pid_t pid;
};

extern void scribe_init_queue_bare(struct scribe_queue_bare *bare);

extern struct scribe_queue *scribe_get_queue_by_pid(
				struct scribe_context *ctx,
				struct scribe_queue **pre_alloc_queue,
				pid_t pid);
extern void scribe_get_queue(struct scribe_queue *queue);
extern void scribe_put_queue(struct scribe_queue *queue);
extern void scribe_put_queue_locked(struct scribe_queue *queue);
extern void scribe_set_persistent(struct scribe_queue *queue);
extern void scribe_unset_persistent(struct scribe_queue *queue);
extern void scribe_free_all_events(struct scribe_queue_bare *bare);

/*
 * Insert points allows to insert event at an arbitrary location which is
 * quite handy when we need to put events "in the past", like saving the
 * return value of a syscall.
 */
extern void scribe_create_insert_point(struct scribe_queue_bare *bare,
				       struct scribe_insert_point *ip);
extern void scribe_commit_insert_point(struct scribe_insert_point *ip);

extern void scribe_queue_event_at(struct scribe_insert_point *where,
				  void *event);
extern void scribe_queue_event(struct scribe_queue *queue, void *event);
extern void scribe_queue_event_bare(struct scribe_queue_bare *bare,
				    void *event);
extern void scribe_queue_events_bare(struct scribe_queue_bare *bare,
				     struct list_head *events);

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
extern struct scribe_event *scribe_dequeue_event_bare(
				struct scribe_queue_bare *bare, int wait);
extern struct scribe_event *scribe_dequeue_event(
				struct scribe_queue *queue, int wait);
extern struct scribe_event *scribe_peek_event(
				struct scribe_queue *queue, int wait);
#define scribe_dequeue_event_specific(sp, _type)			\
({									\
	struct scribe_event *__event;					\
									\
	__event = scribe_dequeue_event((sp)->queue, SCRIBE_WAIT);	\
	if (IS_ERR(__event))						\
		scribe_emergency_stop((sp)->ctx, __event);		\
	else if (__event->type != _type) {				\
		scribe_free_event(__event);				\
		scribe_diverge(sp, SCRIBE_EVENT_DIVERGE_EVENT_TYPE,	\
			       .type = _type);				\
		__event = ERR_PTR(-EDIVERGE);				\
	}								\
	(struct_##_type *)__event;					\
})

#define scribe_dequeue_event_sized(sp, _type, _size)			\
({									\
	struct scribe_event_sized *__event_sized;			\
									\
	__event_sized = (struct scribe_event_sized *)			\
		scribe_dequeue_event_specific(sp, _type);		\
	if (!IS_ERR(__event_sized) && __event_sized->size != (_size)) {	\
		scribe_free_event(__event_sized);			\
		scribe_diverge(sp, SCRIBE_EVENT_DIVERGE_EVENT_SIZE,	\
			       .size = _size);				\
		__event_sized = ERR_PTR(-EDIVERGE);			\
	}								\
	(struct_##_type *)__event_sized;				\
})

extern int scribe_is_queue_empty(struct scribe_queue_bare *bare);
extern void scribe_set_queue_wont_grow(struct scribe_queue_bare *bare);

/*
 * We need the __always_inline (like kmalloc()) to make sure that the constant
 * propagation with its optimization will be made by the compiler.
 */
static __always_inline void *__scribe_alloc_event_const(int type)
{
	struct scribe_event *event;

	event = kmalloc(sizeof_event_from_type(type), GFP_KERNEL);
	if (event)
		event->type = type;

	return event;
}
extern void *__scribe_alloc_event(int type);
void __please_use_scribe_alloc_event_sized(void);
static __always_inline void *scribe_alloc_event(int type)
{
	if (__builtin_constant_p(type)) {
		if (is_sized_type(type))
			__please_use_scribe_alloc_event_sized();
		return __scribe_alloc_event_const(type);
	}
	return __scribe_alloc_event(type);
}
static __always_inline void *scribe_alloc_event_sized(int type, size_t size)
{
	struct scribe_event_sized *event;
	size_t event_size;

	event_size = size + sizeof_event_from_type(type);

	WARN(event_size > PAGE_SIZE*4,
	     "This event (%d) is quite big (%d)...\n", type, size);

	event = kmalloc(event_size, GFP_KERNEL);

	if (event) {
		event->h.type = type;
		event->size = size;
	}

	return event;
}
static inline void scribe_free_event(void *event)
{
	kfree(event);
}

/* Context */

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

	struct scribe_queue_bare notification_queue;

	/* Those are pre-allocated events to be used in atomic contexts */
	struct scribe_event_context_idle *idle_event;
	struct scribe_event_diverge *diverge_event;

	spinlock_t backtrace_lock;
	struct scribe_backtrace *backtrace;

	struct scribe_resource_context *res_ctx;
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
extern void scribe_emergency_stop(struct scribe_context *ctx,
				  struct scribe_event *reason);
extern void scribe_exit_context(struct scribe_context *ctx);

extern int scribe_start_record(struct scribe_context *ctx);
extern int scribe_start_replay(struct scribe_context *ctx, int backtrace_len);
extern int scribe_stop(struct scribe_context *ctx);

#define scribe_get_diverge_event(sp, _type)				\
({									\
	struct scribe_event_diverge *__event;				\
	__event = xchg(&(sp)->ctx->diverge_event, NULL);		\
	if (__event) {							\
		__event->h.type = _type;				\
		__event->pid = (sp)->queue->pid;			\
		WARN(1, "Replay diverged\n");				\
	} else								\
		__event = ERR_PTR(-EDIVERGE);				\
	(struct_##_type *)__event;					\
})

#define scribe_diverge(sp, _type, ...)					\
({									\
	struct_##_type *__event = scribe_get_diverge_event(sp, _type);	\
	if (!IS_ERR(__event)) {						\
		*__event = (struct_##_type) {				\
			.h.h.type = _type,				\
			.h.pid = sp->queue->pid,			\
			__VA_ARGS__					\
		};							\
	}								\
	scribe_emergency_stop((sp)->ctx, (struct scribe_event *)__event); \
})

/* Resources */

struct scribe_resource_cache {
	/*
	 * We need two pre-allocated hres because an inode can have two of
	 * them (one for each end point of a pipe for instance).
	 */
	struct scribe_resource_handle *hres[2];
	/*
	 * We need at most 3 lock_regions pre allocated upfront:
	 * - in fd_install(): Two for the open/close region on the inode
	 *   registration, and one for the files_struct.
	 */
	struct scribe_lock_region *lock_regions[3];
};

extern struct scribe_resource_context *scribe_alloc_resource_context(void);
extern void scribe_free_resource_context(struct scribe_resource_context *);

extern void scribe_resource_init_cache(struct scribe_resource_cache *cache);
extern void scribe_resource_exit_cache(struct scribe_resource_cache *cache);
extern int scribe_resource_prepare(void);

#define SCRIBE_NOSYNC	0
#define SCRIBE_SYNC	1
extern void scribe_resource_open_file(struct file *file, int do_sync);
extern void scribe_resource_close_file(struct file *file);
extern void scribe_resource_lock_file_no_inode(struct file *file);
extern void scribe_resource_lock_file_read(struct file *file);
extern void scribe_resource_lock_file_write(struct file *file);

extern int scribe_resource_lock_next_file_no_inode(void);
extern int scribe_resource_lock_next_file_read(void);
extern int scribe_resource_lock_next_file_write(void);
extern void scribe_pre_fget(struct files_struct *files, int *lock_flags);
extern void scribe_post_fget(struct files_struct *files, struct file *file,
			     int lock_flags);
extern void scribe_pre_fput(struct file *file);

extern void scribe_resource_open_files(struct files_struct *files);
extern void scribe_resource_close_files(struct files_struct *files);
extern void scribe_resource_lock_files_read(struct files_struct *files);
extern void scribe_resource_lock_files_write(struct files_struct *files);

extern void scribe_resource_unlock(void *object);
extern void scribe_resource_unlock_discard(void *object);
extern void scribe_resource_unlock_discard_err(void *object, int err);
extern void scribe_resource_assert_locked(void *object);


/* Process */

struct scribe_ps {
	struct list_head node;

	/*
	 * The two next fields should only be accessed by
	 * the current process.
	 */
	int flags;
	struct scribe_context *ctx;

	struct task_struct *p;
	struct scribe_queue *pre_alloc_queue;
	struct scribe_queue *queue;

	struct scribe_insert_point syscall_ip;
	int in_syscall;
	long orig_ret;

	struct scribe_event_data *prepared_data_event;
	int data_flags;
	int old_data_flags;
	int can_uaccess;

	int waiting_for_serial;
	struct scribe_resource_cache res_cache;
	int lock_next_file;
	struct file *locked_file;

	struct scribe_ps_arch arch;
};

static inline int may_be_scribed(struct scribe_ps *scribe)
{
	return scribe != NULL;
}
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

static inline int should_scribe_syscalls(struct scribe_ps *scribe)
{
	return scribe->flags & SCRIBE_PS_ENABLE_SYSCALL;
}
static inline int should_scribe_data(struct scribe_ps *scribe)
{
	return scribe->flags & SCRIBE_PS_ENABLE_DATA;
}
static inline int should_scribe_resources(struct scribe_ps *scribe)
{
	return scribe->flags & SCRIBE_PS_ENABLE_RESOURCE;
}
static inline int should_scribe_tsc(struct scribe_ps *scribe)
{
	return scribe->flags & SCRIBE_PS_ENABLE_TSC;
}

/* Using defines instead of inline functions so that we don't need
 * to include sched.h
 */
#define is_ps_scribed(t)	is_scribed(t->scribe)
#define is_ps_recording(t)	is_recording(t->scribe)
#define is_ps_replaying(t)	is_replaying(t->scribe)

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
extern void scribe_pre_schedule(void);
extern void scribe_post_schedule(void);
extern void scribe_data_push_flags(int flags);
extern void scribe_data_non_det(void);
extern void scribe_data_dont_record(void);
extern void scribe_data_ignore(void);
extern void scribe_data_pop_flags(void);

#define scribe_interpose_value(dst, src)				\
({									\
	int __ret = 0;							\
	struct scribe_ps *__scribe = current->scribe;			\
	struct scribe_event_data *__event;				\
									\
	if (is_recording(__scribe) && should_scribe_data(__scribe)) {	\
		__event = scribe_alloc_event_sized(SCRIBE_EVENT_DATA,	\
						   sizeof(src));	\
		if (!__event)						\
			__ret = -ENOMEM;				\
		else {							\
			__event->data_type = SCRIBE_DATA_INTERNAL;	\
			__event->user_ptr = 0;				\
			(dst) = *((__typeof__(src) *)__event->data)	\
			      = (src);					\
			scribe_queue_event(__scribe->queue, __event);	\
		}							\
	} else if (is_replaying(__scribe) && should_scribe_data(__scribe)) { \
		__event = scribe_dequeue_event_sized(__scribe,		\
				SCRIBE_EVENT_DATA, sizeof(src));	\
		if (IS_ERR(__event)) {					\
			__ret = PTR_ERR(__event);			\
			/* the next line fixes a compiler warning */	\
			__ret = __ret ? : -EDIVERGE;			\
		}							\
		else if (__event->data_type != SCRIBE_DATA_INTERNAL) {	\
			scribe_free_event(__event);			\
			scribe_diverge(__scribe,			\
				       SCRIBE_EVENT_DIVERGE_DATA_TYPE,	\
				       .type = SCRIBE_DATA_INTERNAL);	\
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

extern struct scribe_backtrace *scribe_alloc_backtrace(int backtrace_len);
extern void scribe_free_backtrace(struct scribe_backtrace *bt);
extern void scribe_backtrace_add(struct scribe_backtrace *bt,
				 struct scribe_event *event);
extern void scribe_backtrace_dump(struct scribe_backtrace *bt,
				  struct scribe_queue_bare *bare);

extern void scribe_enter_syscall(struct pt_regs *regs);
extern void scribe_exit_syscall(struct pt_regs *regs);
extern int is_kernel_copy(void);

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

#define scribe_set_current_data_flags(flags) ({ 0; })
#define scribe_interpose_value(dst, src) ({ (dst) = (src); 0; })

#endif /* CONFIG_SCRIBE */

#endif /* _LINUX_SCRIBE_H_ */
