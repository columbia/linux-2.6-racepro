/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/scribe.h>
#include <linux/scribe_resource.h>
#include <linux/hash.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/pid_namespace.h>
#include <linux/ipc_namespace.h>
#include <linux/sunrpc/svcauth.h> /* For hash_str() */

/*
 * A few notes:
 * - scribe_resource_prepare() must be called prior to any resource lock/open
 *   operations with the exception that get_unused_fd() will successfully
 *   return only with the user refilled (so that fd_install() can proceed).
 *
 * - The files_struct lock must be taken as well to access any close_on_exec
 *   flags.
 *
 * - The filp lock must be taken to access any of the file related data.
 *
 * - The filp+inode lock must be taken to access any of the file related data
 *   and/or inode related data, with the exception of pipes
 *   (inode_need_explicit_locking() returns false in that case).
 *
 * - For pipes, it's quite convenient to have two different resources for each
 *   endpoint:
 *   - Reduced overhead (decoupling the readers/writers)
 *   - It Solve the deadlocking issue when the writer wants to send data to the
 *     pipe while the pipe buffer is full (the reader will not be able to
 *     consume the data since the writer has the resource lock).
 *   Instead of having two resources per inode, we are just using the filp
 *   resource to synchronize each end point (and don't need to take the inode
 *   resource since no other file pointer can exist on the pipe inode).
 *   (In rare cases we may take the inode resource lock -- see in fs/fcntl.c)
 *
 * - TODO use a rw_semaphore instead of a mutex to synchronize accesses (the
 *   resource API already use read/write version, but it does the same thing).
 */

#define INODE_HASH_BITS 8
#define INODE_HASH_SIZE (1 << INODE_HASH_BITS)

#define FS_HASH_BITS 10
#define FS_HASH_SIZE (1 << FS_HASH_BITS)

static inline int should_handle_resources(struct scribe_ps *scribe)
{
	if (!is_scribed(scribe))
		return 0;

	return should_scribe_resources(scribe);
}

struct scribe_resource_context {
	/*
	 * For inodes, instead of using one registration resource, we are
	 * using 256 registration resources to decrease contention on SMP.
	 */
	struct scribe_resource registration_res_inode[INODE_HASH_SIZE];
	struct scribe_resource fs_res[FS_HASH_SIZE];
};

struct scribe_resource_context *scribe_alloc_resource_context(void)
{
	struct scribe_resource_context *ctx;
	int i;

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	for (i = 0; i < INODE_HASH_SIZE; i++) {
		scribe_init_resource(&ctx->registration_res_inode[i],
				     SCRIBE_RES_TYPE_REGISTRATION |
				     SCRIBE_RES_TYPE_INODE |
				     SCRIBE_RES_TYPE_SPINLOCK);
	}

	for (i = 0; i < FS_HASH_SIZE; i++)
		scribe_init_resource(&ctx->fs_res[i], SCRIBE_RES_TYPE_FS);

	return ctx;
}

void scribe_reset_resource_context(struct scribe_resource_context *ctx)
{
	int i;
	for (i = 0; i < INODE_HASH_SIZE; i++)
		scribe_reset_resource(&ctx->registration_res_inode[i]);
	for (i = 0; i < FS_HASH_SIZE; i++)
		scribe_reset_resource(&ctx->fs_res[i]);
}

void scribe_free_resource_context(struct scribe_resource_context *ctx)
{
	kfree(ctx);
}

void scribe_init_resource_container(struct scribe_resource_container *container)
{
	spin_lock_init(&container->lock);
	INIT_LIST_HEAD(&container->handles);
}

static struct scribe_resource *find_registration_res_inode(
		struct scribe_resource_context *ctx, struct inode *inode)
{
	/*
	 * We don't really care about the reference counter on the
	 * registration resources.
	 */
	int index = hash_long(inode->i_ino, INODE_HASH_BITS);
	index = 0;
	return &ctx->registration_res_inode[index];
}

static struct scribe_resource *find_fs_res(
		struct scribe_resource_context *ctx, const char *name)
{
	int index = hash_str((char *)name, FS_HASH_BITS);
	return &ctx->fs_res[index];
}

struct scribe_resource_handle {
	atomic_t ref_cnt;
	struct list_head container_node;
	struct scribe_resource_context *ctx;
	struct rcu_head rcu;

	struct scribe_resource res;
	/*
	 * We cannot fail resource_close(), because it might get called in
	 * do_exit(). We need to keep all the necessary memory to close the
	 * resource. This is where it goes.
	 */
	spinlock_t lock;
	struct list_head close_lock_regions;
};

void scribe_init_resource(struct scribe_resource *res, int type)
{
	res->type = type;
	mutex_init(&res->lock);
	spin_lock_init(&res->slock);
	init_waitqueue_head(&res->wait);
	scribe_reset_resource(res);
}

void scribe_reset_resource(struct scribe_resource *res)
{
	res->serial = 0;
}

static void init_resource_handle(struct scribe_resource_context *ctx,
				 struct scribe_resource_handle *hres, int type)
{
	atomic_set(&hres->ref_cnt, 1);
	hres->ctx = ctx;
	scribe_init_resource(&hres->res, type);
	spin_lock_init(&hres->lock);
	INIT_LIST_HEAD(&hres->close_lock_regions);
}

struct scribe_lock_region {
	struct list_head node;
	scribe_insert_point_t ip;
	union {
		struct scribe_event *generic;
		struct scribe_event_resource_lock *regular;
		struct scribe_event_resource_lock_intr *intr;
		struct scribe_event_resource_lock_extra *extra;
	} lock_event;
	struct scribe_event_resource_unlock *unlock_event;
	struct scribe_resource *res;
	void *object;
	int flags;
};

static void free_lock_region(struct scribe_lock_region *lock_region);

static struct scribe_lock_region *alloc_lock_region(int doing_recording,
						    int res_extra)
{
	struct scribe_lock_region *lock_region;

	lock_region = kmalloc(sizeof(*lock_region), GFP_KERNEL);
	if (!lock_region)
		return NULL;

	lock_region->lock_event.generic = NULL;
	lock_region->unlock_event = NULL;

	if (!doing_recording) {
		/*
		 * During replaying, we don't really need those events, since
		 * they will be coming from the event pump.
		 */
		return lock_region;
	}

	if (res_extra)
		lock_region->lock_event.extra = scribe_alloc_event(
				SCRIBE_EVENT_RESOURCE_LOCK_EXTRA);
	else
		lock_region->lock_event.regular = scribe_alloc_event(
				SCRIBE_EVENT_RESOURCE_LOCK);

	if (!lock_region->lock_event.generic)
		goto err;

	if (res_extra) {
		lock_region->unlock_event = scribe_alloc_event(
						SCRIBE_EVENT_RESOURCE_UNLOCK);
		if (!lock_region->unlock_event)
			goto err;
	}

	return lock_region;

err:
	free_lock_region(lock_region);
	return NULL;
}

/* Use this when you didn't had the chance to lock()/unlock() the resource */
static void free_lock_region(struct scribe_lock_region *lock_region)
{
	scribe_free_event(lock_region->lock_event.generic);
	scribe_free_event(lock_region->unlock_event);
	kfree(lock_region);
}

void scribe_resource_init_user(struct scribe_res_user *user)
{
	user->pre_alloc_hres = NULL;
	INIT_LIST_HEAD(&user->pre_alloc_regions);
	user->num_pre_alloc_regions = 0;
	INIT_LIST_HEAD(&user->locked_regions);
}

/*
 * We need at most 3 lock_regions pre allocated upfront, e.g in fd_install():
 * Two for the open/close region on the inode registration, and one for the
 * files_struct.
 */
#define MAX_PRE_ALLOC_REGIONS 4

int scribe_resource_pre_alloc(struct scribe_res_user *user,
			      int doing_recording, int res_extra)
{
	struct scribe_lock_region *lock_region;

	if (!user->pre_alloc_hres) {
		user->pre_alloc_hres = kmalloc(sizeof(*user->pre_alloc_hres),
					       GFP_KERNEL);
		if (!user->pre_alloc_hres)
			return -ENOMEM;
	}

	while (user->num_pre_alloc_regions <= MAX_PRE_ALLOC_REGIONS) {
		lock_region = alloc_lock_region(doing_recording, res_extra);
		if (!lock_region)
			return -ENOMEM;

		list_add(&lock_region->node, &user->pre_alloc_regions);
		user->num_pre_alloc_regions++;
	}

	return 0;
}

static int __resource_prepare(struct scribe_ps *scribe)
{
	might_sleep();

	if (scribe_resource_pre_alloc(&scribe->resources, is_recording(scribe),
				      should_scribe_res_extra(scribe)))
		return -ENOMEM;

	return 0;
}

int scribe_resource_prepare(void)
{
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return 0;

	return __resource_prepare(scribe);
}

void scribe_resource_exit_user(struct scribe_res_user *user)
{
	struct scribe_lock_region *lock_region, *tmp;

	kfree(user->pre_alloc_hres);

	list_for_each_entry_safe(lock_region, tmp,
				 &user->pre_alloc_regions, node) {
		list_del(&lock_region->node);
		free_lock_region(lock_region);
	}

	WARN(!list_empty(&user->locked_regions),
	     "Some regions are left unlocked\n");
}

/*
 * Global objects like inodes needs to be synchronized. Since we can have
 * multiple scribe contextes, we need a list of resources per object.
 * This list is in the scribe_resource_container struct.
 */
static struct scribe_resource_handle *__get_resource_handle(
				struct scribe_resource_context *ctx,
				struct scribe_resource_container *container)
{
	struct scribe_resource_handle *hres;

	list_for_each_entry_rcu(hres, &container->handles, container_node) {
		if (hres->ctx != ctx)
			continue;

		if (likely(atomic_inc_not_zero(&hres->ref_cnt)))
			return hres;
	}

	return NULL;
}

static struct scribe_resource_handle *get_resource_handle(
				struct scribe_resource_context *ctx,
				struct scribe_resource_container *container,
				int type, int *created,
				struct scribe_resource_handle **pre_alloc_hres)
{
	struct scribe_resource_handle *hres;

	*created = 0;

	rcu_read_lock();
	hres = __get_resource_handle(ctx, container);
	rcu_read_unlock();
	if (hres)
		return hres;

	spin_lock(&container->lock);
	hres = __get_resource_handle(ctx, container);
	if (unlikely(hres)) {
		spin_unlock(&container->lock);
		return hres;
	}

	hres = *pre_alloc_hres;
	*pre_alloc_hres = NULL;
	BUG_ON(!hres);

	init_resource_handle(ctx, hres, type);

	list_add_rcu(&hres->container_node, &container->handles);

	spin_unlock(&container->lock);

	*created = 1;
	return hres;
}

static void free_rcu_hres(struct rcu_head *rcu)
{
	kfree(container_of(rcu, struct scribe_resource_handle, rcu));
}

/* put_resource_handle() is somewhat hidden in scribe_close_resource() */
static inline void __put_resource_handle(
				struct scribe_resource_container *container,
				struct scribe_resource_handle *hres)
{
	spin_lock(&container->lock);
	list_del_rcu(&hres->container_node);
	spin_unlock(&container->lock);
	call_rcu(&hres->rcu, free_rcu_hres);
}

static struct scribe_resource_handle *find_resource_handle(
				struct scribe_resource_context *ctx,
				struct scribe_resource_container *container)
{
	struct scribe_resource_handle *hres;

	rcu_read_lock();
	list_for_each_entry_rcu(hres, &container->handles, container_node) {
		if (hres->ctx == ctx) {
			rcu_read_unlock();
			return hres;
		}
	}
	rcu_read_unlock();

	return NULL;
}

static bool is_locking_necessary(struct scribe_ps *scribe,
				 struct scribe_resource *res)
{
	if (should_scribe_res_always(scribe))
		return true;

	/*
	 * It is assumed that the init process won't do anything racy with the
	 * first child, this way when the number of processes is equal to 2,
	 * we can disable resource tracking.
	 * When the number of processes is equal to 3, we need resource
	 * tracking, but we cannot go back to the disabled resource tracking
	 * easily. We would need a MEM_ALONE event or something to
	 * deterministically switch back to this state.
	 * In our case, we are lazy and stay in that mode.
	 * TODO send a RES_ALONE event when necessary.
	 */
	if (scribe->ctx->max_num_tasks > 2)
		return true;

	/*
	 * The only resource we need for the init process is the task one.
	 * Forcing the synchronization on it is an easy way to avoid races
	 */
	if (res->type == SCRIBE_RES_TYPE_TASK)
		return true;

	return false;
}

static int serial_match(struct scribe_ps *scribe,
			struct scribe_resource *res, int serial)
{
	if (serial == res->serial)
		return 1;

	if (serial < res->serial) {
		WARN(1, "Waiting for serial = %d, but the current one is %d\n",
		     serial, res->serial);
		scribe_emergency_stop(scribe->ctx, ERR_PTR(-EDIVERGE));
		return 1;
	}

	if (scribe->ctx->flags == SCRIBE_IDLE) {
		/* emergency_stop() has been triggered, we need to leave */
		return 1;
	}
	return 0;
}

#ifdef CONFIG_DEBUG_LOCK_ALLOC
static int get_lockdep_subclass(int type)
{
	/* MAX_LOCKDEP_SUBCLASSES is small, trying not to overflow it */
	if (type & SCRIBE_RES_TYPE_REGISTRATION)
		return SCRIBE_RES_TYPE_RESERVED;
	return type & 0x07;
}
#else
static inline int get_lockdep_subclass(int type)
{
	return 0;
}
#endif

static inline int use_spinlock(struct scribe_resource *res)
{
	return res->type & SCRIBE_RES_TYPE_SPINLOCK;
}

static void do_lock_record(struct scribe_ps *scribe,
			   struct scribe_lock_region *lock_region,
			   struct scribe_resource *res)
{
	scribe_create_insert_point(&lock_region->ip, &scribe->queue->stream);
}

static void do_lock_record_intr(struct scribe_ps *scribe,
				struct scribe_lock_region *lock_region)
{
	struct scribe_event_resource_lock_intr *event;

	event = lock_region->lock_event.intr;
	lock_region->lock_event.intr = NULL;

	/*
	 * The lock_intr event is smaller than the allocated one, so casting
	 * the event works.
	 */
	event->h.type = SCRIBE_EVENT_RESOURCE_LOCK_INTR;
	scribe_queue_event_at(&lock_region->ip, event);
	scribe_commit_insert_point(&lock_region->ip);
}

static int do_lock_replay(struct scribe_ps *scribe,
			  struct scribe_lock_region *lock_region,
			  struct scribe_resource *res)
{
	struct scribe_event *intr_event;
	int type;
	int serial;

	intr_event = scribe_peek_event(scribe->queue, SCRIBE_WAIT);
	if (IS_ERR(intr_event))
		return PTR_ERR(intr_event);

	if (intr_event->type == SCRIBE_EVENT_RESOURCE_LOCK_INTR) {
		intr_event = scribe_dequeue_event(scribe->queue, SCRIBE_WAIT);
		scribe_free_event(intr_event);
		return -EINTR;
	}

	if (should_scribe_res_extra(scribe)) {
		struct scribe_event_resource_lock_extra *event;

		event = scribe_dequeue_event_specific(scribe,
					      SCRIBE_EVENT_RESOURCE_LOCK_EXTRA);
		if (IS_ERR(event))
			return PTR_ERR(event);

		type = event->type;
		serial = event->serial;
		scribe_free_event(event);

		if (type != res->type) {
			scribe_diverge(scribe,
				       SCRIBE_EVENT_DIVERGE_RESOURCE_TYPE,
				       .type = res->type);
			return -EDIVERGE;
		}
	} else {
		struct scribe_event_resource_lock *event;

		event = scribe_dequeue_event_specific(scribe,
						SCRIBE_EVENT_RESOURCE_LOCK);
		if (IS_ERR(event))
			return PTR_ERR(event);

		serial = event->serial;
		scribe_free_event(event);
	}

	/* That's for avoiding a thundering herd */
	scribe->waiting_for_serial = serial;
	wmb();

	wait_event(res->wait, serial_match(scribe, res, serial));
	return 0;
}

static int __do_lock(struct scribe_ps *scribe,
		  struct scribe_lock_region *lock_region,
		  struct scribe_resource *res)
{
	int class;
	int intr;

	class = get_lockdep_subclass(res->type);

	if (use_spinlock(res)) {
		spin_lock_nested(&res->slock, class);
		return 0;
	}

	if (!(lock_region->flags & SCRIBE_INTERRUPTIBLE)) {
		mutex_lock_nested(&res->lock, class);
		return 0;
	}

	intr = mutex_lock_interruptible_nested(&res->lock, class) ? -EINTR : 0;
	scribe->locking_was_interrupted = !!intr;
	return intr;

}

static int do_lock(struct scribe_ps *scribe,
		   struct scribe_lock_region *lock_region)
{
	struct scribe_resource *res = lock_region->res;
	might_sleep();

	if (!is_locking_necessary(scribe, res))
		return 0;

	if (unlikely(is_detaching(scribe))) {
		if (lock_region->flags & SCRIBE_INTERRUPTIBLE)
			return -EINTR;
		return __do_lock(scribe, lock_region, res);
	}

	if (is_recording(scribe))
		do_lock_record(scribe, lock_region, res);
	else {
		/*
		 * Even in case of replay errors while trying to pump events,
		 * we want to take the lock if we cannot fail with EINT, so
		 * that we stay consistent with the paired unlock().
		 */
		if (do_lock_replay(scribe, lock_region, res)) {
			if (lock_region->flags & SCRIBE_INTERRUPTIBLE) {
				scribe->locking_was_interrupted = true;
				return -EINTR;
			}
		}
		scribe->locking_was_interrupted = false;

		/* During the replay we never wait in a interruptible state */
		lock_region->flags &= ~SCRIBE_INTERRUPTIBLE;
	}

	if (__do_lock(scribe, lock_region, res)) {
		/* Reached only when recording */
		do_lock_record_intr(scribe, lock_region);
		return -EINTR;
	}
	return 0;
}

static void wake_up_for_serial(struct scribe_resource *res)
{
	wait_queue_head_t *q = &res->wait;
	wait_queue_t *wq;

	spin_lock(&q->lock);
	list_for_each_entry(wq, &q->task_list, task_list) {
		struct task_struct *p = wq->private;
		if (p->scribe->waiting_for_serial == res->serial) {
			wq->func(wq, TASK_NORMAL, 0, NULL);
			break;
		}
	}
	spin_unlock(&q->lock);
}

static void do_unlock_record(struct scribe_ps *scribe,
			     struct scribe_lock_region *lock_region,
			     struct scribe_resource *res, int serial)
{
	if (should_scribe_res_extra(scribe)) {
		struct scribe_event_resource_lock_extra *lock_event;
		struct scribe_event_resource_unlock *unlock_event;
		lock_event = lock_region->lock_event.extra;
		unlock_event = lock_region->unlock_event;
		lock_region->lock_event.extra = NULL;
		lock_region->unlock_event = NULL;

		lock_event->type = res->type;
		lock_event->object = (unsigned long)lock_region->object;
		lock_event->serial = serial;
		scribe_queue_event_at(&lock_region->ip, lock_event);
		scribe_commit_insert_point(&lock_region->ip);

		unlock_event->object = (unsigned int)lock_region->object;
		scribe_queue_event(scribe->queue, unlock_event);
	} else {
		struct scribe_event_resource_lock *lock_event;
		lock_event = lock_region->lock_event.regular;
		lock_region->lock_event.extra = NULL;

		lock_event->serial = serial;
		scribe_queue_event_at(&lock_region->ip, lock_event);
		scribe_commit_insert_point(&lock_region->ip);
	}
}

static void do_unlock_replay(struct scribe_ps *scribe,
			     struct scribe_lock_region *lock_region,
			     struct scribe_resource *res, int serial)
{
	struct scribe_event_resource_unlock *event;

	wake_up_for_serial(res);

	if (!should_scribe_res_extra(scribe))
		return;

	event = scribe_dequeue_event_specific(scribe,
					      SCRIBE_EVENT_RESOURCE_UNLOCK);
	if (!IS_ERR(event))
		scribe_free_event(event);
}

static void do_unlock(struct scribe_ps *scribe,
		      struct scribe_lock_region *lock_region)
{
	struct scribe_resource *res = lock_region->res;
	int serial = 0;
	int detaching;

	if (!is_locking_necessary(scribe, res))
		return;

	detaching = is_detaching(scribe);

	if (likely(!detaching))
		serial = res->serial++;

	if (use_spinlock(res))
		spin_unlock(&res->slock);
	else
		mutex_unlock(&res->lock);

	might_sleep();

	if (unlikely(detaching))
		return;

	if (is_recording(scribe))
		do_unlock_record(scribe, lock_region, res, serial);
	else
		do_unlock_replay(scribe, lock_region, res, serial);
}

static void do_unlock_discard(struct scribe_ps *scribe,
			      struct scribe_lock_region *lock_region)
{
	struct scribe_resource *res = lock_region->res;

	if (!is_locking_necessary(scribe, res))
		return;

	if (use_spinlock(res))
		spin_unlock(&res->slock);
	else
		mutex_unlock(&res->lock);

	if (unlikely(is_detaching(scribe)))
		return;

	if (is_recording(scribe))
		scribe_commit_insert_point(&lock_region->ip);
	else {
		WARN(scribe->ctx->flags != SCRIBE_IDLE,
		     "Discarding resource lock on replay\n");
	}
}

static inline struct scribe_lock_region *get_pre_alloc_lock_region(
						struct scribe_res_user *user)
{
	struct scribe_lock_region *lock_region;

	BUG_ON(list_empty(&user->pre_alloc_regions));
	lock_region = list_first_entry(&user->pre_alloc_regions,
				       struct scribe_lock_region, node);
	list_del(&lock_region->node);
	user->num_pre_alloc_regions--;
	return lock_region;
}

/* Will always succeed if (@flags & SCRIBE_INTERRUPTIBLE) is not set */
static int __lock_object(struct scribe_ps *scribe,
			 void *object, struct scribe_resource *res, int flags)
{
	struct scribe_res_user *user;
	struct scribe_lock_region *lock_region;
	int ret;

	user = &scribe->resources;

	lock_region = get_pre_alloc_lock_region(user);
	lock_region->res = res;
	lock_region->object = object;
	lock_region->flags = flags;

	ret = do_lock(scribe, lock_region);
	if (ret)
		free_lock_region(lock_region);
	else
		list_add(&lock_region->node, &user->locked_regions);
	return ret;
}

void scribe_lock_object(void *object, struct scribe_resource *res, int flags)
{
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return;

	__lock_object(scribe, object, res, flags);
}

static int __lock_object_handle(struct scribe_ps *scribe, void *object,
				struct scribe_resource_container *container,
				int flags)
{
	struct scribe_resource_handle *hres;

	hres = find_resource_handle(scribe->ctx->res_ctx, container);
	if (likely(hres))
		return __lock_object(scribe, object, &hres->res, flags);

	scribe_emergency_stop(scribe->ctx, ERR_PTR(-ENOENT));
	return -ENOENT;
}

void scribe_lock_object_handle(void *object,
		struct scribe_resource_container *container, int flags)
{
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return;

	__lock_object_handle(scribe, object, container, flags);
}

static inline struct inode *file_inode(struct file *file)
{
	return file->f_path.dentry->d_inode;
}

static inline bool can_skip_files_struct_sync(struct scribe_ps *scribe,
					      struct files_struct *files)
{
	/* TODO */
	return false;
}

static inline bool can_skip_file_sync(struct scribe_ps *scribe,
				      struct file *file)
{
	/* TODO */
	return false;
}

static struct scribe_lock_region *find_locked_region(
						struct scribe_res_user *user,
						void *object)
{
	struct scribe_lock_region *lock_region;

	list_for_each_entry(lock_region, &user->locked_regions, node) {
		if (lock_region->object == object)
			return lock_region;
	}
	return NULL;
}

void scribe_unlock_err(void *object, int err)
{
	struct scribe_ps *scribe = current->scribe;
	struct scribe_res_user *user;
	struct scribe_lock_region *lock_region;
	struct file *file;

	if (!should_handle_resources(scribe))
		return;

	user = &scribe->resources;
	lock_region = find_locked_region(user, object);
	if (!lock_region) {
		/*
		 * This happens when the locking was not necessary, e.g. when
		 * can_skip_files_struct_sync() returns true
		 */
		return;
	}

	list_del(&lock_region->node);

	if (lock_region->flags & (SCRIBE_INODE_READ | SCRIBE_INODE_WRITE)) {
		file = object;
		scribe_unlock_err(file_inode(file), err);
	}

	if (likely(!IS_ERR_VALUE(err))) {
		do_unlock(scribe, lock_region);
		free_lock_region(lock_region);
	} else {
		do_unlock_discard(scribe, lock_region);
		list_add(&lock_region->node, &user->pre_alloc_regions);
	}

}

void scribe_unlock(void *object)
{
	scribe_unlock_err(object, 0);
}

void scribe_unlock_discard(void *object)
{
	scribe_unlock_err(object, -EAGAIN);
}

void scribe_assert_locked(void *object)
{
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return;

	WARN_ON(!find_locked_region(&scribe->resources, object));
}

void scribe_open_resource_no_sync(struct scribe_resource_context *ctx,
				  struct scribe_resource_container *container,
				  int type, struct scribe_res_user *user)
{
	int created;
	get_resource_handle(ctx, container, type, &created,
			    &user->pre_alloc_hres);
}

/*
 * We need to open/close any resources that can be used within different
 * scribe contexts because we need a serial number per resource, and per
 * scribe context.
 *
 * This resource (un)registration has to be done in the same order during the
 * replay (compared to the recording) to avoid an open/close race.
 *
 * An open/close race happens when we don't ensure 1) or 2) from happening
 * deterministically during the replay:
 * 1) Task A closes the resource and its reference counter reaches 0. Thus
 *    releasing the resource memory. Then task B opens the resource and its
 *    serial number is initialized to 0.
 * 2) Task B opens the resource, bumps its reference counter. Then task A
 *    closes the resource. The serial number is not re-initialized to 0.
 */
static void scribe_open_resource(struct scribe_ps *scribe,
				 struct scribe_resource_container *container,
				 int type, struct scribe_resource *sync_res,
				 int do_sync_open, int do_sync_close,
				 int *created)
{
	struct scribe_res_user *user = &scribe->resources;
	struct scribe_resource_context *ctx = scribe->ctx->res_ctx;
	struct scribe_lock_region *open_lock_region = NULL;
	struct scribe_lock_region *close_lock_region;
	struct scribe_resource_handle *hres;
	int _created;

	if (!created)
		created = &_created;

	if (do_sync_open) {
		open_lock_region = get_pre_alloc_lock_region(user);
		open_lock_region->res = sync_res;
		open_lock_region->object = sync_res;
		open_lock_region->flags = SCRIBE_WRITE;

		do_lock(scribe, open_lock_region);
	}

	hres = get_resource_handle(ctx, container, type, created,
				   &user->pre_alloc_hres);

	if (do_sync_open) {
		do_unlock(scribe, open_lock_region);
		free_lock_region(open_lock_region);
	}

	if (do_sync_close) {
		close_lock_region = get_pre_alloc_lock_region(user);

		/*
		 * Close synchronization can be performed on the resource
		 * itself. sync_res == NULL would indicate that.
		 */
		if (!sync_res)
			sync_res = &hres->res;

		close_lock_region->res = sync_res;
		close_lock_region->object = sync_res;
		close_lock_region->flags = SCRIBE_WRITE;

		spin_lock(&hres->lock);
		list_add(&close_lock_region->node, &hres->close_lock_regions);
		spin_unlock(&hres->lock);
	}
}

void scribe_close_resource_no_sync(struct scribe_resource_context *ctx,
				   struct scribe_resource_container *container)
{
	struct scribe_resource_handle *hres;

	hres = find_resource_handle(ctx, container);
	if (unlikely(!hres)) {
		WARN(1, "No resource\n");
		return;
	}

	if (atomic_dec_and_test(&hres->ref_cnt))
		__put_resource_handle(container, hres);
}

void scribe_close_resource(struct scribe_ps *scribe,
			   struct scribe_resource_container *container,
			   int do_close_sync, int *destroyed)
{
	struct scribe_resource_context *ctx = scribe->ctx->res_ctx;
	struct scribe_lock_region *close_lock_region = NULL;
	struct scribe_resource_handle *hres;
	int _destroyed;

	if (!destroyed)
		destroyed = &_destroyed;

	hres = find_resource_handle(ctx, container);
	if (unlikely(!hres)) {
		scribe_emergency_stop(scribe->ctx, ERR_PTR(-ENOENT));
		return;
	}

	if (do_close_sync) {
		spin_lock(&hres->lock);
		BUG_ON(list_empty(&hres->close_lock_regions));
		close_lock_region = list_first_entry(&hres->close_lock_regions,
					__typeof__(*close_lock_region), node);
		list_del(&close_lock_region->node);
		spin_unlock(&hres->lock);

		do_lock(scribe, close_lock_region);
	}

	*destroyed = atomic_dec_and_test(&hres->ref_cnt);
	/*
	 * We have to defer the resource removal because the unlock() can be
	 * performed on the resource itself.
	 */

	if (do_close_sync) {
		do_unlock(scribe, close_lock_region);
		free_lock_region(close_lock_region);
	}

	if (*destroyed)
		__put_resource_handle(container, hres);
}

static inline int inode_need_reg_sync(struct inode *inode)
{
	umode_t mode = inode->i_mode;
	/*
	 * For fifos and sockets, we don't need to synchronize open/close
	 * because once closed permanantly (ref_cnt reaches 0), they cannot be
	 * reopened: the open/close race cannot happen.
	 */
	return !(S_ISFIFO(mode) || S_ISSOCK(mode));
}

static inline int inode_need_explicit_locking(struct inode *inode)
{
	umode_t mode = inode->i_mode;
	/*
	 * For fifos and sockets, each endpoint has to be locked independently
	 * (otherwise deadlocks could happen when the buffer is full...).
	 * It's also better in terms of performance.
	 */
	return S_ISFIFO(mode) || S_ISSOCK(mode);
}

void scribe_open_file(struct file *file, int do_sync)
{
	struct scribe_ps *scribe = current->scribe;
	struct inode *inode;
	struct scribe_resource_context *file_ctx, *ctx;
	struct scribe_resource *sync_res;
	int do_sync_open, do_sync_close;

	if (!should_handle_resources(scribe))
		return;

	ctx = scribe->ctx->res_ctx;

	/* Files struct must belong to only one scribe resource context */
	file_ctx = xchg(&file->scribe_context, ctx);
	if (!file_ctx) {
		scribe_init_resource(&file->scribe_resource,
				     SCRIBE_RES_TYPE_FILE);
		file_ctx = ctx;
	}
	BUG_ON(file_ctx != ctx);
	atomic_inc(&file->scribe_ref_cnt);

	inode = file_inode(file);
	sync_res = find_registration_res_inode(ctx, inode);
	do_sync_open = do_sync && inode_need_reg_sync(inode);
	do_sync_close = inode_need_reg_sync(inode);
	scribe_open_resource(scribe, &inode->i_scribe_resource,
			     SCRIBE_RES_TYPE_INODE, sync_res,
			     do_sync_open, do_sync_close, NULL);
}

void scribe_close_file(struct file *file)
{
	int do_sync;
	struct inode *inode;
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return;

	inode = file_inode(file);
	do_sync = inode_need_reg_sync(inode);
	scribe_close_resource(scribe, &inode->i_scribe_resource, do_sync, NULL);

	if (atomic_dec_and_test(&file->scribe_ref_cnt))
		file->scribe_context = NULL;
}

static int __lock_file(struct file *file, int flags)
{
	struct scribe_ps *scribe = current->scribe;
	struct scribe_res_user *user;
	struct scribe_lock_region *lock_region;
	struct inode *inode;
	bool file_locked;
	int intr;

	if (!should_handle_resources(scribe))
		return 0;

	inode = file_inode(file);
	if (inode_need_explicit_locking(inode))
		flags &= ~(SCRIBE_INODE_READ | SCRIBE_INODE_WRITE);

	file_locked = false;
	if (!can_skip_file_sync(scribe, file)) {
		if (__lock_object(scribe, file, &file->scribe_resource, flags))
			return -EINTR;
		file_locked = true;
	}

	if (flags & SCRIBE_INODE_READ)
		flags = SCRIBE_READ;
	else if (flags & SCRIBE_INODE_WRITE)
		flags = SCRIBE_WRITE;
	else
		return 0;

	/*
	 * We may associate the inode_lock_obj with the file, because this is
	 * what gets passed to the scribe_unlock() function.
	 * This is how the inode will get unlocked.
	 */
	intr = __lock_object_handle(scribe,
				    file_locked ? (void *)inode : (void *)file,
				    &inode->i_scribe_resource, flags);

	if (intr && file_locked) {
		user = &scribe->resources;
		lock_region = find_locked_region(user, file);
		/* Was in locked_regions */
		list_del(&lock_region->node);
		do_unlock_discard(scribe, lock_region);
		/* Put back int the pre alloc regions, lock was discarded */
		list_add(&lock_region->node, &user->pre_alloc_regions);
	}

	return intr;
}

void scribe_lock_file_no_inode(struct file *file)
{
	__lock_file(file, SCRIBE_WRITE);
}

void scribe_lock_file_read(struct file *file)
{
	__lock_file(file, SCRIBE_WRITE | SCRIBE_INODE_READ);
}

void scribe_lock_file_write(struct file *file)
{
	__lock_file(file, SCRIBE_WRITE | SCRIBE_INODE_WRITE);
}

int scribe_lock_file_read_interruptible(struct file *file)
{
	return __lock_file(file, SCRIBE_INTERRUPTIBLE |
				 SCRIBE_WRITE | SCRIBE_INODE_READ);
}

int scribe_lock_file_write_interruptible(struct file *file)
{
	return __lock_file(file, SCRIBE_INTERRUPTIBLE |
				 SCRIBE_WRITE | SCRIBE_INODE_WRITE);
}

static void __lock_inode(struct inode *inode, int flags)
{
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return;

	__lock_object_handle(scribe, inode, &inode->i_scribe_resource, flags);
}

void scribe_lock_inode_read(struct inode *inode)
{
	__lock_inode(inode, SCRIBE_READ);
}

void scribe_lock_inode_write(struct inode *inode)
{
	__lock_inode(inode, SCRIBE_WRITE);
}

static int __track_next_file(int flags)
{
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return 0;

	if (__resource_prepare(scribe))
		return -ENOMEM;

	scribe->lock_next_file = flags;
	return 0;
}

int scribe_track_next_file_no_inode(void)
{
	return __track_next_file(SCRIBE_WRITE);
}

int scribe_track_next_file_read(void)
{
	return __track_next_file(SCRIBE_WRITE | SCRIBE_INODE_READ);
}

int scribe_track_next_file_write(void)
{
	return __track_next_file(SCRIBE_WRITE | SCRIBE_INODE_WRITE);
}

int scribe_track_next_file_read_interruptible(void)
{
	return __track_next_file(SCRIBE_INTERRUPTIBLE |
				 SCRIBE_WRITE | SCRIBE_INODE_READ);
}

int scribe_track_next_file_write_interruptible(void)
{
	return __track_next_file(SCRIBE_INTERRUPTIBLE |
				 SCRIBE_WRITE | SCRIBE_INODE_WRITE);
}

void scribe_pre_fget(struct files_struct *files, int *lock_flags)
{
	struct scribe_ps *scribe = current->scribe;

	*lock_flags = 0;

	if (!is_scribed(scribe))
		return;

	if (scribe->lock_next_file) {
		*lock_flags = scribe->lock_next_file;
		scribe->lock_next_file = 0;

		/*
		 * We need to lock the files_struct while doing fcheck_files()
		 * to guards against races with fd_install()
		 */
		scribe_lock_files_read(files);
	}
}

int scribe_post_fget(struct files_struct *files, struct file *file,
		      int lock_flags)
{
	if (!lock_flags)
		return 0;

	scribe_unlock(files);

	if (!file) {
		current->scribe->locking_was_interrupted = false;
		return 0;
	}

	if (__lock_file(file, lock_flags))
		return -EINTR;

	current->scribe->locked_file = file;
	return 0;
}

void scribe_pre_fput(struct file *file)
{
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return;

	if (scribe->locked_file) {
		scribe_unlock(scribe->locked_file);
		scribe->locked_file = NULL;
	}
}

#define rcu_dereference_check_fd(files, fdt, _fd) \
	(rcu_dereference_check((fdt)->fd[(_fd)], \
			       rcu_read_lock_held() || \
			       lockdep_is_held(&(files)->file_lock) || \
			       atomic_read(&(files)->count) == 1 || \
			       rcu_my_thread_group_empty()))

void scribe_open_files(struct files_struct *files)
{
	struct scribe_ps *scribe = current->scribe;
	struct file *file;
	struct fdtable *fdt;
	int created;
	int fd;

	BUG_ON(!is_scribed(scribe));

	if (scribe_resource_prepare()) {
		/*
		 * FIXME Make this unfailable (do the memory allocation in
		 * init_scribe()).
		 */
		scribe_emergency_stop(scribe->ctx, ERR_PTR(-ENOMEM));
		return;
	}

	/*
	 * We must make other threads wait here until all resources are
	 * created, otherwise one might start using a file resource that
	 * haven't been opened yet.
	 */
	mutex_lock(&files->scribe_open_lock);

	scribe_open_resource(scribe, &files->scribe_resource,
			     SCRIBE_RES_TYPE_FILES_STRUCT |
			     SCRIBE_RES_TYPE_SPINLOCK, NULL,
			     SCRIBE_NO_SYNC, SCRIBE_SYNC, &created);

	if (!created) {
		mutex_unlock(&files->scribe_open_lock);
		return;
	}

	/*
	 * We don't need to take any of the standard fdtable locks here
	 * because other processes trying to access the files_struct will be
	 * waiting on the mutex.
	 */
	fdt = files_fdtable(files);
	for (fd = 0; fd < fdt->max_fds; fd++) {
		file = rcu_dereference_check_fd(files, fdt, fd);
		if (!file)
			continue;

		if (scribe_resource_prepare()) {
			/*
			 * TODO once the pre-allocation is done, change the
			 * mutex to a spinlock.
			 */
			scribe_emergency_stop(scribe->ctx, ERR_PTR(-ENOMEM));
			break;
		}

		/*
		 * We don't need to synchronize the registration because:
		 * - We are starting a scribe session
		 * - Or those inodes are already registered, so there is no
		 *   race condition risk.
		 */
		scribe_open_file(file, SCRIBE_NO_SYNC);
	}

	mutex_unlock(&files->scribe_open_lock);
}

void scribe_close_files(struct files_struct *files)
{
	struct scribe_ps *scribe = current->scribe;
	struct file *file;
	struct fdtable *fdt;
	int destroyed;
	int fd;

	if (!is_scribed(scribe))
		return;

	/*
	 * We need to guarantee that the task closing the files during record
	 * will be the same as the one during the replay. Hence the locking.
	 */
	scribe_close_resource(scribe, &files->scribe_resource, SCRIBE_SYNC,
			      &destroyed);
	if (!destroyed)
		return;

	/*
	 * We don't need to take any of the standard fdtable locks here
	 * because we are the last process referencing it (and thus no other
	 * process can access it).
	 */
	fdt = files_fdtable(files);
	for (fd = 0; fd < fdt->max_fds; fd++) {
		file = rcu_dereference_check_fd(files, fdt, fd);
		if (!file)
			continue;

		scribe_close_file(file);
	}
}

void scribe_lock_files_read(struct files_struct *files)
{
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return;

	if (can_skip_files_struct_sync(scribe, files))
		return;

	__lock_object_handle(scribe, files,
			     &files->scribe_resource, SCRIBE_READ);
}

void scribe_lock_files_write(struct files_struct *files)
{
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return;

	if (can_skip_files_struct_sync(scribe, files))
		return;

	__lock_object_handle(scribe, files,
			     &files->scribe_resource, SCRIBE_WRITE);
}

static void lock_task(struct task_struct *task, int flags)
{
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return;

	/* For now all the tasks are synchronized on the same resource */
	__lock_object(scribe, task, &scribe->ctx->tasks_res, flags);
}

void scribe_lock_task_read(struct task_struct *task)
{
	lock_task(task, SCRIBE_READ);
}

void scribe_lock_task_write(struct task_struct *task)
{
	lock_task(task, SCRIBE_WRITE);
}

void scribe_lock_ipc(struct ipc_namespace *ns)
{
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return;

	/* For now all IPC things are synchronized on the same resource */
	__lock_object(scribe, ns, &ns->scribe_resource, SCRIBE_WRITE);
}

void scribe_lock_fs(const char *name)
{
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return;

	__lock_object(scribe, (void *)name,
		      find_fs_res(scribe->ctx->res_ctx, name), SCRIBE_WRITE);
}

bool scribe_was_locking_interrupted(void)
{
	struct scribe_ps *scribe = current->scribe;

	if (!may_be_scribed(scribe))
		return false;

	return scribe->locking_was_interrupted;
}
