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
#include <linux/signal.h>
#include <linux/rcupdate.h>
#include <asm/scribe.h>
#include <asm/atomic.h>

/* Events */

struct scribe_substream {
	/*
	 * For the master substream, @node serves as the list head.
	 * For insert points, @node serves as a list node.
	 */
	struct list_head node;
	struct scribe_stream *stream;
	struct list_head events;

	unsigned long clear_region_on_commit_set;
	unsigned long region_set;
};

/*
 * An insert point is semantically different from a substream, but is
 * modelised by a substream.
 */
typedef struct scribe_substream scribe_insert_point_t;

struct scribe_stream {
	spinlock_t lock;

	struct scribe_substream master;

	unsigned long *last_event_jiffies;

	/*
	 * When sealed == 1 and list_empty(events), the queue can be
	 * considered as dead.
	 */
	int sealed;

	/*
	 * 'wait' points to:
	 * - &ctx->wait_event in record mode (one waiter for all queues)
	 * - &default_wait in replay mode (one waiter per queue)
	 */
	wait_queue_head_t default_wait;
	wait_queue_head_t *wait;
};

#define SCRIBE_REGION_SIGNAL		0
#define SCRIBE_REGION_SIG_COOKIE	1
#define SCRIBE_REGION_MEM		2
#define SCRIBE_REGION_NUM		4

/*
 * scribe_queues are used for the per process queue whereas scribe_streams are
 * used freely, unrelated to a specific process (e.g. the notification queue).
 */
struct scribe_queue {
	struct scribe_stream stream;

	atomic_t ref_cnt;

	/*
	 * When persistent == 1, it means that we take an additional internal
	 * reference (This is useful to pass the queue around without having
	 * it to die in the middle).
	 */
	int persistent;

	struct scribe_context *ctx;
	struct list_head node;
	pid_t pid;

	/*
	 * No synchronization is done on the fence_* fields,
	 * only the queue owner accesses them.
	 */
	unsigned long regions_set;
	struct scribe_event_fence *fence_events[SCRIBE_REGION_NUM];
	unsigned int fence_serial;

	loff_t last_event_offset;
};

extern void scribe_init_stream(struct scribe_stream *stream);

extern struct scribe_queue *scribe_get_queue_by_pid(
				struct scribe_context *ctx,
				struct scribe_queue **pre_alloc_queue,
				pid_t pid);
extern void scribe_get_queue(struct scribe_queue *queue);
extern void scribe_put_queue(struct scribe_queue *queue);
extern void scribe_put_queue_locked(struct scribe_queue *queue);
extern void scribe_set_persistent(struct scribe_queue *queue);
extern void scribe_unset_persistent(struct scribe_queue *queue);
extern void scribe_free_all_events(struct scribe_stream *stream);

/*
 * Insert points allows to insert event at an arbitrary location which is
 * quite handy when we need to "put events in the past", like saving the
 * return value of a syscall.
 */
extern void scribe_create_insert_point(scribe_insert_point_t *ip,
				       struct scribe_stream *stream);
extern void scribe_commit_insert_point(scribe_insert_point_t *ip);

extern void scribe_queue_event_at(scribe_insert_point_t *ip, void *event);
extern void scribe_queue_event_stream(struct scribe_stream *stream,
				      void *event);
extern void scribe_queue_event(struct scribe_queue *queue, void *event);
extern void scribe_queue_events_stream(struct scribe_stream *stream,
				       struct list_head *events);

/*
 * This macro allows us to write such code:
 *	scribe_queue_new_event(scribe->queue,
 *			       SCRIBE_EVENT_SYSCALL,
 *			       .nr = 1, .ret = 2);
 */
#define scribe_queue_new_event(queue, _type, ...)			\
({									\
	struct##_type *__new_event;					\
	int __ret = 0;							\
									\
	__new_event = scribe_alloc_event(_type);			\
	if (!__new_event)						\
		__ret = -ENOMEM;					\
	else {								\
		*__new_event = (struct##_type)				\
			{.h = {.type = _type},  __VA_ARGS__};		\
		scribe_queue_event(queue, __new_event);			\
	}								\
	__ret;								\
})

#define SCRIBE_NO_WAIT			0
#define SCRIBE_WAIT			1
#define SCRIBE_WAIT_INTERRUPTIBLE	2
extern struct scribe_event *scribe_dequeue_event_stream(
				struct scribe_stream *stream, int wait);
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
		scribe_kill((sp)->ctx, PTR_ERR(__event));		\
	else if (__event->type != _type) {				\
		scribe_free_event(__event);				\
		scribe_diverge(sp, SCRIBE_EVENT_DIVERGE_EVENT_TYPE,	\
			       .type = _type);				\
		__event = ERR_PTR(-EDIVERGE);				\
	}								\
	(struct##_type *)__event;					\
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
	(struct##_type *)__event_sized;				\
})

extern bool scribe_is_stream_empty(struct scribe_stream *stream);
static inline bool scribe_is_queue_empty(struct scribe_queue *queue)
{
	return scribe_is_stream_empty(&queue->stream);
}

extern void scribe_seal_stream(struct scribe_stream *stream);
static inline void scribe_seal_queue(struct scribe_queue *queue)
{
	scribe_seal_stream(&queue->stream);
}

extern bool scribe_is_stream_dead(struct scribe_stream *stream, int wait);
static inline bool scribe_is_queue_dead(struct scribe_queue *queue, int wait)
{
	return scribe_is_stream_dead(&queue->stream, wait);
}

extern void scribe_kill_stream(struct scribe_stream *stream);
static inline void scribe_kill_queue(struct scribe_queue *queue)
{
	scribe_kill_stream(&queue->stream);
}

/*
 * We need the __always_inline (like kmalloc()) to make sure that the constant
 * propagation with its optimization will be made by the compiler.
 */
static __always_inline void *__scribe_alloc_event_const(int type, gfp_t flags)
{
	struct scribe_event *event;

	event = kmalloc(sizeof_event_from_type(type), flags);
	if (event)
		event->type = type;

	return event;
}

extern void *__scribe_alloc_event(int type, gfp_t flags);
void __please_use_scribe_alloc_event_sized(void);
static __always_inline void *scribe_alloc_event_flags(int type, gfp_t flags)
{
	if (__builtin_constant_p(type)) {
		if (is_sized_type(type))
			__please_use_scribe_alloc_event_sized();
		return __scribe_alloc_event_const(type, flags);
	}
	return __scribe_alloc_event(type, flags);
}
static __always_inline void *scribe_alloc_event(int type)
{
	return scribe_alloc_event_flags(type, GFP_KERNEL);
}
static __always_inline void *scribe_alloc_event_sized_flags(
					int type, size_t size, gfp_t flags)
{
	struct scribe_event_sized *event;
	size_t event_size;

	event_size = size + sizeof_event_from_type(type);

	WARN(event_size > PAGE_SIZE*4,
	     "This event (%d) is quite big (%zd)...\n", type, size);

	event = kmalloc(event_size, flags);

	if (event) {
		event->h.type = type;
		event->size = size;
	}

	return event;
}
static __always_inline void *scribe_alloc_event_sized(int type, size_t size)
{
	return scribe_alloc_event_sized_flags(type, size, GFP_KERNEL);
}
static inline void scribe_free_event(void *event)
{
	kfree(event);
}

extern int scribe_enter_fenced_region(int region);
extern void scribe_leave_fenced_region(int region);

/* Pump */
struct scribe_pump;
extern struct scribe_pump *scribe_pump_alloc(struct scribe_context *ctx);
extern void scribe_pump_free(struct scribe_pump *pump);
extern int scribe_pump_prepare_start(struct scribe_pump *pump);
extern void scribe_pump_abort_start(struct scribe_pump *pump);
extern void scribe_pump_start(struct scribe_pump *pump, int state,
			     struct file *logfile);
extern void scribe_pump_stop(struct scribe_pump *pump);
extern int scribe_pump_wait_completion_interruptible(struct scribe_pump *pump);

/* Context */

struct scribe_context {
	atomic_t ref_cnt;
	int id;
	int flags;

	spinlock_t tasks_lock;
	struct list_head tasks;
	wait_queue_head_t tasks_wait;
	int max_num_tasks;
	int num_tasks;

	int queues_sealed;
	spinlock_t queues_lock;
	struct list_head queues;
	wait_queue_head_t queues_wait;
	unsigned long last_event_jiffies;

	struct scribe_stream notifications;

	/* Those are pre-allocated events to be used in atomic contexts */
	struct scribe_event_context_idle *idle_event;
	struct scribe_event_diverge *diverge_event;
	int last_error;

	spinlock_t backtrace_lock;
	struct scribe_backtrace *backtrace;

	struct scribe_resources *resources;

	atomic_t signal_cookie;

	struct scribe_bookmark *bmark;

	struct scribe_mm_context *mm_ctx;
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
extern void __scribe_kill(struct scribe_context *ctx,
			  struct scribe_event *reason);
static inline void scribe_kill(struct scribe_context *ctx, long error)
{
	__scribe_kill(ctx, ERR_PTR(error));
}

extern void scribe_exit_context(struct scribe_context *ctx);

extern int scribe_start(struct scribe_context *ctx, unsigned long flags,
			int backtrace_len);
extern int scribe_stop(struct scribe_context *ctx);

static inline bool is_scribe_context_dead(struct scribe_context *ctx)
{
	return !(ctx->flags & SCRIBE_STATE_MASK);
}

extern int scribe_check_deadlock(struct scribe_context *ctx);
extern void scribe_wake_all_fake_sig(struct scribe_context *ctx);

#define scribe_get_diverge_event(sp, _type)				\
({									\
	struct scribe_event_diverge *__event;				\
	__event = xchg(&(sp)->ctx->diverge_event, NULL);		\
	if (__event) {							\
		__event->h.type = _type;				\
		__event->pid = (sp)->queue->pid;			\
	} else								\
		__event = ERR_PTR(-EDIVERGE);				\
	(struct##_type *)__event;					\
})

#define scribe_diverge(sp, _type, ...)					\
({									\
	struct##_type *__event = scribe_get_diverge_event(sp, _type);	\
	if (!IS_ERR(__event)) {						\
		*__event = (struct##_type) {				\
			.h.h.type = _type,				\
			.h.pid = sp->queue->pid,			\
			.h.last_event_offset = (sp)->queue->last_event_offset, \
			__VA_ARGS__					\
		};							\
	}								\
	__scribe_kill((sp)->ctx, (struct scribe_event *)__event);	\
})

/* Bookmarks */

extern struct scribe_bookmark *scribe_bookmark_alloc(
						struct scribe_context *ctx);
extern void scribe_bookmark_free(struct scribe_bookmark *bmark);
extern void scribe_bookmark_reset(struct scribe_bookmark *bmark);
extern int scribe_bookmark_request(struct scribe_bookmark *bmark);
extern void scribe_bookmark_point(unsigned int type);
extern int scribe_bookmark_resume(struct scribe_bookmark *bmark);

/* Resources */

struct scribe_res_user {
	struct hlist_head pre_alloc_idres;
	int num_pre_alloc_idres;

	struct list_head pre_alloc_hres;
	int num_pre_alloc_hres;

	struct list_head pre_alloc_regions;
	int num_pre_alloc_regions;

	struct list_head locked_regions;
};

extern struct scribe_resources *scribe_alloc_resources(void);
extern void scribe_reset_resources(struct scribe_resources *ctx);
extern void scribe_free_resources(struct scribe_resources *);

extern void scribe_resource_init_user(struct scribe_res_user *user);
extern void scribe_resource_exit_user(struct scribe_res_user *user);
extern int scribe_resource_pre_alloc(struct scribe_res_user *user,
				     int doing_recording, int res_extra);
extern void scribe_assert_no_locked_region(struct scribe_res_user *user);
extern int scribe_resource_prepare(void);

#define SCRIBE_INTERRUPTIBLE	0x01
#define SCRIBE_READ		0x02
#define SCRIBE_WRITE		0x04
#define SCRIBE_INODE_READ	0x08
#define SCRIBE_INODE_WRITE	0x10
#define SCRIBE_INODE_EXPLICIT	0x20
#define SCRIBE_NESTED		0x40
extern void scribe_lock_object(void *object, struct scribe_resource *res,
			       int flags);
extern void scribe_lock_object_handle(void *object,
		struct scribe_container *container, int type, int flags);

extern void scribe_lock_file_no_inode(struct file *file);
extern void scribe_lock_file_read(struct file *file);
extern void scribe_lock_file_write(struct file *file);
extern int scribe_lock_file_read_interruptible(struct file *file);
extern int scribe_lock_file_write_interruptible(struct file *file);

extern void scribe_lock_inode_read(struct inode *inode);
extern void scribe_lock_inode_write(struct inode *inode);
extern void scribe_lock_inode_write_nested(struct inode *inode);

extern int scribe_track_next_file_no_inode(void);
extern int scribe_track_next_file_read(void);
extern int scribe_track_next_file_write(void);
extern int scribe_track_next_file_explicit_inode_read(void);
extern int scribe_track_next_file_explicit_inode_write(void);
extern int scribe_track_next_file_read_interruptible(void);
extern int scribe_track_next_file_write_interruptible(void);
extern bool scribe_was_file_locking_interrupted(void);
extern void scribe_pre_fget(struct files_struct *files, int *lock_flags);
extern int scribe_post_fget(struct files_struct *files, struct file *file,
			    int lock_flags);
extern void scribe_pre_fput(struct file *file);

extern void scribe_lock_files_read(struct files_struct *files);
extern void scribe_lock_files_write(struct files_struct *files);

extern void scribe_lock_pid_read(pid_t pid);
extern void scribe_lock_pid_write(pid_t pid);
extern void scribe_unlock_pid(pid_t pid);
extern void scribe_unlock_pid_discard(pid_t pid);

struct ipc_namespace;
extern void scribe_lock_ipc(struct ipc_namespace *ns);

extern void scribe_lock_mmap_read(struct mm_struct *mm);
extern void scribe_lock_mmap_write(struct mm_struct *mm);

extern void scribe_lock_ppid_ptr_read(struct task_struct *p);
extern void scribe_lock_ppid_ptr_write(struct task_struct *p);

extern void scribe_unlock(void *object);
extern void scribe_unlock_discard(void *object);
extern void scribe_unlock_err(void *object, int err);
extern void scribe_downgrade(void *object);
extern void scribe_assert_locked(void *object);

/* Signals */

#define NO_COOKIE ((unsigned int)-1)
struct scribe_signal {
	/*
	 * The should_defer and deferred fields are protected with
	 * sighand->siglock.
	 */
	bool should_defer;
	bool self_signaling;
	struct sigpending deferred;
	scribe_insert_point_t signal_ip;

	struct scribe_event_sig_send_cookie *send_cookie_event;
};

extern void scribe_signal_enter_sync_point(int *num_deferred);
extern void scribe_signal_leave_sync_point(void);
extern void scribe_init_signal(struct scribe_signal *scribe_sig);

static inline int is_interruption(int ret)
{
	return ret == -ERESTARTSYS ||
		ret == -ERESTARTNOINTR ||
		ret == -ERESTARTNOHAND ||
		ret == -ERESTART_RESTARTBLOCK ||
		ret == -EINTR;
}

union scribe_event_data_union {
	struct scribe_event *generic;
	struct scribe_event_sized *generic_sized;
	struct scribe_event_data *regular;
	struct scribe_event_data_info *info;
	struct scribe_event_data_extra *extra;
};

/* Process */

/*
 * A few rules:
 * - Only the current process have a write access to the fields in the
 *   scribe_ps struct.
 * - To dereference task->scribe:
 *   - The current process doesn't need extra precaution
 *   - Other processes need to use rcu_read_lock() (or the safe version of the
 *   macro defined below).
 */
struct scribe_ps {
	struct list_head node;
	struct rcu_head rcu;

	int flags;
	struct scribe_context *ctx;

	struct task_struct *p;
	struct scribe_queue *pre_alloc_queue;
	struct scribe_queue *queue;

	scribe_insert_point_t syscall_ip;
	int in_syscall;
	int nr_syscall;
	bool need_syscall_ret;
	long orig_ret;

	union scribe_event_data_union prepared_data_event;
	size_t to_be_copied_size;
	int data_flags;
	int old_data_flags;
	int can_uaccess;
	bool in_read_write;

	int waiting_for_serial;
	struct scribe_res_user resources;
	int lock_next_file;
	struct file *locked_file;
	bool was_file_locking_interrupted;
	bool do_dpath_scribing;

	struct scribe_ps_arch arch;

	struct scribe_signal signal;

	int bmark_waiting;

	struct scribe_mm *mm;
};

#ifndef may_be_scribed
#define may_be_scribed may_be_scribed
static inline int may_be_scribed(struct scribe_ps *scribe)
{
	return scribe != NULL;
}
#endif /* may_be_scribed */

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
static inline int is_detaching(struct scribe_ps *scribe)
{
	return scribe != NULL && (scribe->flags & SCRIBE_PS_DETACHING);
}

/* Use the safe version when current != t */
#define is_ps_scribed(t)	is_scribed(t->scribe)
#define is_ps_recording(t)	is_recording(t->scribe)
#define is_ps_replaying(t)	is_replaying(t->scribe)

#define __call_scribe_safe(t, func)				\
({								\
	int __safe_ret;						\
	rcu_read_lock();					\
	__safe_ret = func(rcu_dereference((t)->scribe));	\
	rcu_read_unlock();					\
	__safe_ret;						\
})

#define is_ps_scribed_safe(t)	__call_scribe_safe(t, is_scribed)
#define is_ps_recording_safe(t)	__call_scribe_safe(t, is_recording)
#define is_ps_replaying_safe(t)	__call_scribe_safe(t, is_replaying)

static inline int scribe_is_in_read_write(struct scribe_ps *scribe)
{
	if (!may_be_scribed(scribe))
		return false;
	return scribe->in_read_write;
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
static inline int should_scribe_signals(struct scribe_ps *scribe)
{
	return scribe->flags & SCRIBE_PS_ENABLE_SIGNAL;
}
static inline int should_scribe_tsc(struct scribe_ps *scribe)
{
	return scribe->flags & SCRIBE_PS_ENABLE_TSC;
}
static inline int should_scribe_mm(struct scribe_ps *scribe)
{
	return scribe->flags & SCRIBE_PS_ENABLE_MM;
}
static inline int should_ret_check(struct scribe_ps *scribe)
{
	return scribe->flags & SCRIBE_PS_ENABLE_RET_CHECK;
}

static inline int should_scribe_syscall_ret(struct scribe_ps *scribe)
{
	return scribe->ctx->flags & (SCRIBE_SYSCALL_RET | SCRIBE_SYSCALL_EXTRA);
}
static inline int should_scribe_syscall_extra(struct scribe_ps *scribe)
{
	return scribe->ctx->flags & SCRIBE_SYSCALL_EXTRA;
}
static inline int should_scribe_sig_extra(struct scribe_ps *scribe)
{
	return scribe->ctx->flags & SCRIBE_SIG_EXTRA;
}
static inline int should_scribe_sig_cookie(struct scribe_ps *scribe)
{
	return scribe->ctx->flags & SCRIBE_SIG_COOKIE;
}
static inline int should_scribe_res_extra(struct scribe_ps *scribe)
{
	return scribe->ctx->flags & SCRIBE_RES_EXTRA;
}
static inline int should_scribe_mem_extra(struct scribe_ps *scribe)
{
	return scribe->ctx->flags & SCRIBE_MEM_EXTRA;
}
static inline int should_scribe_data_extra(struct scribe_ps *scribe)
{
	return scribe->ctx->flags & SCRIBE_DATA_EXTRA;
}
static inline int should_scribe_data_string_always(struct scribe_ps *scribe)
{
	return scribe->ctx->flags & (SCRIBE_DATA_STRING_ALWAYS |
				     SCRIBE_DATA_ALWAYS);
}
static inline int should_scribe_data_always(struct scribe_ps *scribe)
{
	return scribe->ctx->flags & SCRIBE_DATA_ALWAYS;
}
static inline int should_scribe_res_always(struct scribe_ps *scribe)
{
	return scribe->ctx->flags & SCRIBE_RES_ALWAYS;
}
static inline int should_scribe_fence_always(struct scribe_ps *scribe)
{
	return scribe->ctx->flags & SCRIBE_FENCE_ALWAYS;
}
static inline int should_scribe_regs(struct scribe_ps *scribe)
{
	return scribe->ctx->flags & SCRIBE_REGS;
}
static inline int scribe_mm_disabled(struct scribe_ps *scribe)
{
	return scribe->ctx->flags & SCRIBE_DISABLE_MM;
}

extern int init_scribe(struct task_struct *p, struct scribe_context *ctx);
extern void exit_scribe(struct task_struct *p);

extern int scribe_set_attach_on_exec(struct scribe_context *ctx, int enable);
extern void scribe_attach(struct scribe_ps *scribe);
extern void __scribe_detach(struct scribe_ps *scribe);
extern void scribe_detach(struct scribe_ps *scribe);
extern bool scribe_maybe_detach(struct scribe_ps *scribe);

extern size_t scribe_emul_copy_to_user(struct scribe_ps *scribe,
				       char __user *buf, ssize_t len);
extern size_t scribe_emul_copy_from_user(struct scribe_ps *scribe,
					 char __user *buf, ssize_t len);

extern void __scribe_allow_uaccess(struct scribe_ps *scribe);
extern void __scribe_forbid_uaccess(struct scribe_ps *scribe);
extern void scribe_allow_uaccess(void);
extern void scribe_forbid_uaccess(void);
extern void scribe_prepare_data_event(size_t pre_alloc_size);
extern void scribe_pre_schedule(void);
extern void scribe_post_schedule(void);
extern void scribe_data_push_flags(int flags);
extern void scribe_data_det(void);
extern void scribe_data_non_det(void);
extern void scribe_data_need_info(void);
extern void scribe_data_non_det_need_info(void);
extern void scribe_data_ignore(void);
extern void scribe_data_pop_flags(void);

extern int __scribe_buffer_record(struct scribe_ps *scribe,
				  scribe_insert_point_t *ip,
				  const void *data, size_t size);
extern int __scribe_buffer_replay(struct scribe_ps *scribe,
				  void *data, size_t size);
extern int scribe_buffer_at(void *buffer, size_t size,
			    scribe_insert_point_t *ip);
static inline int scribe_buffer(void *buffer, size_t size)
{
	return scribe_buffer_at(buffer, size, NULL);
}

#define scribe_result_cond(dst, src, cond)				\
({									\
	int __ret;							\
	scribe_insert_point_t __ip;					\
	struct scribe_ps *__scribe = current->scribe;			\
									\
	if (!is_scribed(__scribe) || !should_scribe_data(__scribe)) {	\
		(dst) = (src);						\
		__ret = 0;						\
	} else if (is_recording(__scribe)) {				\
		scribe_create_insert_point(&__ip, &__scribe->queue->stream); \
		(dst) = (src);						\
		if (cond)						\
			__ret = __scribe_buffer_record(__scribe,	\
					&__ip, &(dst), sizeof(dst));	\
		else							\
			__ret = 0;					\
		scribe_commit_insert_point(&__ip);			\
	} else {							\
		__ret = __scribe_buffer_replay(				\
				__scribe, &(dst), sizeof(dst));		\
	}								\
	__ret;								\
})

#define scribe_result(dst, src) scribe_result_cond(dst, src, 1)

#define scribe_value(pval) scribe_buffer(pval, sizeof(*pval))
#define scribe_value_at(pval, ip) scribe_buffer_at(pval, sizeof(*pval), ip)


extern struct scribe_backtrace *scribe_alloc_backtrace(int backtrace_len);
extern void scribe_free_backtrace(struct scribe_backtrace *bt);
extern void scribe_backtrace_add(struct scribe_backtrace *bt,
				 struct scribe_event *event);
extern void scribe_backtrace_dump(struct scribe_backtrace *bt,
				  struct scribe_stream *stream);

extern int scribe_need_syscall_ret(struct scribe_ps *scribe);
extern void scribe_enter_syscall(struct pt_regs *regs);
extern void scribe_commit_syscall(struct scribe_ps *scribe,
				  struct pt_regs *regs, long ret_value);
extern void scribe_exit_syscall(struct pt_regs *regs);
extern int is_kernel_copy(void);

/* Memory */
#define MEM_SYNC_IN		1
#define MEM_SYNC_OUT		2
#define MEM_SYNC_SLEEP		4

extern struct scribe_mm_context *scribe_alloc_mm_context(void);
extern void scribe_free_mm_context(struct scribe_mm_context *mm_ctx);

extern int scribe_mem_init_st(struct scribe_ps *scribe);

extern void scribe_mem_exit_st(struct scribe_ps *scribe);
extern void scribe_mem_sync_point(struct scribe_ps *scribe, int mode);
extern void scribe_disable_sync_sleep(void);
extern void scribe_enable_sync_sleep(void);
extern void scribe_mem_reload(struct scribe_ps *scribe);

extern int do_scribe_page(struct scribe_ps *scribe, struct mm_struct *mm,
			  struct vm_area_struct *vma, unsigned long address,
			  pte_t *pte, pmd_t *pmd, unsigned int flags);
extern void scribe_add_vma(struct vm_area_struct *vma);
extern void scribe_remove_vma(struct vm_area_struct *vma);
extern void scribe_clear_shadow_pte_locked(struct mm_struct *mm,
					   struct vm_area_struct *vma,
					   pte_t *real_pte, unsigned long addr);

struct mmu_gather;
extern void scribe_free_all_shadow_pgd_range(struct mmu_gather *tlb,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling);

extern void scribe_mem_schedule_in(struct scribe_ps *scribe);
extern void scribe_mem_schedule_out(struct scribe_ps *scribe);


/* Sockets */
struct socket;
extern int scribe_interpose_socket(struct socket *sock);

#else /* CONFIG_SCRIBE */

/* FIXME Make the kernel compile with !CONFIG_SCRIBE ... */

#define is_ps_scribed(t)	0
#define is_ps_recording(t)	0
#define is_ps_replaying(t)	0
#define is_ps_scribed_safe(t)	0
#define is_ps_recording_safe(t)	0
#define is_ps_replaying_safe(t)	0

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
