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

/*
 * A few notes:
 * - scribe_resource_prepare() must be called prior to any resource lock/open
 *   operations with the exception that get_unused_fd() will successfully
 *   return only with the cache refilled (so that fd_install() can proceed).
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

	return ctx;
}

void scribe_reset_resource_context(struct scribe_resource_context *ctx)
{
	int i;
	for (i = 0; i < INODE_HASH_SIZE; i++)
		scribe_reset_resource(&ctx->registration_res_inode[i]);
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
	return &ctx->registration_res_inode[index];
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
		struct scribe_event_resource_lock_extra *extra;
	} lock_event;
	struct scribe_event_resource_unlock *unlock_event;
	struct scribe_resource *res;
	void *object;
	int flags;
};

static int reinit_lock_region(struct scribe_lock_region *lock_region,
			      int doing_recording, int res_extra)
{
	/*
	 * During replaying, we don't really need those events, since they
	 * will be coming from the event pump.
	 */
	if (!doing_recording)
		return 0;

	if (!lock_region->lock_event.generic) {
		if (res_extra)
			lock_region->lock_event.extra = scribe_alloc_event(
					SCRIBE_EVENT_RESOURCE_LOCK_EXTRA);
		else
			lock_region->lock_event.regular = scribe_alloc_event(
					SCRIBE_EVENT_RESOURCE_LOCK);
		if (!lock_region->lock_event.generic)
			return -ENOMEM;
	}

	if (res_extra && !lock_region->unlock_event) {
		lock_region->unlock_event = scribe_alloc_event(
						SCRIBE_EVENT_RESOURCE_UNLOCK);
		if (!lock_region->unlock_event) {
			scribe_free_event(lock_region->lock_event.generic);
			lock_region->lock_event.generic = NULL;
			return -ENOMEM;
		}
	}

	return 0;
}

static int init_lock_region(struct scribe_lock_region *lock_region,
			    int doing_recording, int res_extra)
{
	lock_region->lock_event.generic = NULL;
	lock_region->unlock_event = NULL;
	lock_region->res = NULL;
	lock_region->object = NULL;

	return reinit_lock_region(lock_region, doing_recording, res_extra);
}

/* Use this when you didn't had the chance to lock()/unlock() the resource */
static void exit_lock_region(struct scribe_lock_region *lock_region)
{
	scribe_free_event(lock_region->lock_event.generic);
	scribe_free_event(lock_region->unlock_event);
}

void scribe_resource_init_cache(struct scribe_resource_cache *cache)
{
	memset(cache, 0, sizeof(*cache));
}

int scribe_resource_pre_alloc(struct scribe_resource_cache *cache,
			      int doing_recording, int res_extra)
{
	struct scribe_lock_region *lock_region;
	int i;

	if (!cache->hres) {
		cache->hres = kmalloc(sizeof(*cache->hres), GFP_KERNEL);
		if (!cache->hres)
			return -ENOMEM;
	}

	for (i = 0; i < ARRAY_SIZE(cache->lock_regions); i++) {
		lock_region = cache->lock_regions[i];

		if (lock_region) {
			if (!lock_region->object)
				if (reinit_lock_region(lock_region,
						       doing_recording,
						       res_extra))
					return -ENOMEM;
			continue;
		}

		lock_region = kmalloc(sizeof(*lock_region), GFP_KERNEL);
		if (!lock_region)
			return -ENOMEM;
		if (init_lock_region(lock_region, doing_recording, res_extra)) {
			kfree(lock_region);
			return -ENOMEM;
		}
		cache->lock_regions[i] = lock_region;
	}

	return 0;
}

static int __resource_prepare(struct scribe_ps *scribe)
{
	might_sleep();

	if (scribe_resource_pre_alloc(&scribe->res_cache,
				      is_recording(scribe),
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

void scribe_resource_exit_cache(struct scribe_resource_cache *cache)
{
	struct scribe_lock_region *lock_region;
	int i;

	kfree(cache->hres);

	for (i = 0; i < ARRAY_SIZE(cache->lock_regions); i++) {
		lock_region = cache->lock_regions[i];
		if (lock_region) {
			exit_lock_region(lock_region);
			kfree(lock_region);
		}
	}
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

/* put_resource_handle() is somewhat hidden in scribe_close_resource() */

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
#endif

static inline int use_spinlock(struct scribe_resource *res)
{
	return res->type & SCRIBE_RES_TYPE_SPINLOCK;
}

static void lock_record(struct scribe_ps *scribe,
			struct scribe_lock_region *lock_region,
			struct scribe_resource *res)
{
	scribe_create_insert_point(&lock_region->ip, &scribe->queue->stream);
}

static int lock_replay(struct scribe_ps *scribe,
		       struct scribe_lock_region *lock_region,
		       struct scribe_resource *res)
{
	int type;
	int serial;

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

static void lock(struct scribe_lock_region *lock_region)
{
	struct scribe_resource *res;
	struct scribe_ps *scribe = current->scribe;

	might_sleep();

	res = lock_region->res;

	if (unlikely(is_detaching(scribe)))
		goto out;

	if (is_recording(scribe))
		lock_record(scribe, lock_region, res);
	else {
		/*
		 * Even in case of replay errors, we want to take the lock, so
		 * that we stay consistent.
		 */
		lock_replay(scribe, lock_region, res);
	}

out:
	if (use_spinlock(res))
		spin_lock_nested(&res->slock, get_lockdep_subclass(res->type));
	else
		mutex_lock_nested(&res->lock, get_lockdep_subclass(res->type));
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

static bool put_back_lock_region(struct scribe_resource_cache *cache,
				 struct scribe_lock_region *lock_region);

static void unlock_record(struct scribe_ps *scribe,
			  struct scribe_lock_region *lock_region,
			  struct scribe_resource *res, int serial)
{
	if (should_scribe_res_extra(scribe)) {
		struct scribe_event_resource_lock_extra *lock_event;
		struct scribe_event_resource_unlock *unlock_event;

		lock_event = lock_region->lock_event.extra;
		unlock_event = lock_region->unlock_event;

		lock_event->type = res->type;
		lock_event->object = (unsigned long)lock_region->object;
		lock_event->serial = serial;

		unlock_event->object = (unsigned int)lock_region->object;

		scribe_queue_event_at(&lock_region->ip, lock_event);
		scribe_commit_insert_point(&lock_region->ip);

		scribe_queue_event(scribe->queue, lock_region->unlock_event);

		lock_region->lock_event.extra = NULL;
		lock_region->unlock_event = NULL;
	} else {
		lock_region->lock_event.regular->serial = serial;
		scribe_queue_event_at(&lock_region->ip,
				      lock_region->lock_event.regular);
		scribe_commit_insert_point(&lock_region->ip);
		lock_region->lock_event.regular = NULL;
	}
}

static void unlock_replay(struct scribe_ps *scribe,
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

static void unlock(struct scribe_resource_cache *cache,
		   struct scribe_lock_region *lock_region)
{
	struct scribe_resource *res;
	struct scribe_ps *scribe = current->scribe;
	int serial;

	res = lock_region->res;
	serial = res->serial++;

	if (use_spinlock(res))
		spin_unlock(&res->slock);
	else
		mutex_unlock(&res->lock);

	might_sleep();

	if (unlikely(is_detaching(scribe)))
		goto out;

	if (is_recording(scribe)) {
		unlock_record(scribe, lock_region, res, serial);
		/*
		 * We don't put back the lock region in the cache since the
		 * events have been consumed.
		 */
	} else {
		unlock_replay(scribe, lock_region, res, serial);
		if (put_back_lock_region(cache, lock_region))
			return;
	}

out:
	exit_lock_region(lock_region);
	kfree(lock_region);
}

static void unlock_discard(struct scribe_resource_cache *cache,
			   struct scribe_lock_region *lock_region)
{
	struct scribe_ps *scribe = current->scribe;
	struct scribe_resource *res;

	res = lock_region->res;
	if (use_spinlock(res))
		spin_unlock(&res->slock);
	else
		mutex_unlock(&res->lock);

	if (unlikely(is_detaching(scribe)))
		goto out;

	if (is_recording(scribe))
		scribe_commit_insert_point(&lock_region->ip);

	if (put_back_lock_region(cache, lock_region))
		return;

out:
	exit_lock_region(lock_region);
	kfree(lock_region);
}

static inline struct scribe_lock_region **find_lock_region_ptr(
		struct scribe_resource_cache *cache, void *object)
{
	struct scribe_lock_region *lock_region;
	int i;

	for (i = 0; i < ARRAY_SIZE(cache->lock_regions); i++) {
		lock_region = cache->lock_regions[i];
		if (lock_region && lock_region->object == object)
			return &cache->lock_regions[i];
	}

	return NULL;
}

static inline struct scribe_lock_region *find_lock_region(
		struct scribe_resource_cache *cache, void *object)
{
	struct scribe_lock_region **lock_region_ptr;

	lock_region_ptr = find_lock_region_ptr(cache, object);
	if (!lock_region_ptr)
		return NULL;

	return *lock_region_ptr;
}

static inline struct scribe_lock_region *get_lock_region(
		struct scribe_resource_cache *cache, void *object)
{
	struct scribe_lock_region **lock_region_ptr;
	struct scribe_lock_region *lock_region;

	lock_region_ptr = find_lock_region_ptr(cache, object);
	if (!lock_region_ptr)
		return NULL;

	lock_region = *lock_region_ptr;
	*lock_region_ptr = NULL;
	return lock_region;
}

/*
 * returns true if able to put the region back in the cache, false otherwise
 */
static bool put_back_lock_region(struct scribe_resource_cache *cache,
				 struct scribe_lock_region *lock_region)
{
	struct scribe_lock_region **cached_region_slot;

	if (unlikely(!cache))
		return false;

	cached_region_slot = find_lock_region_ptr(cache, NULL);
	if (!cached_region_slot)
		return false;

	lock_region->res = NULL;
	lock_region->object = NULL;
	*cached_region_slot = lock_region;
	return true;
}

static void __lock_object(struct scribe_ps *scribe, void *object,
			  struct scribe_resource *res, int flags)
{
	struct scribe_lock_region *lock_region;

	lock_region = find_lock_region(&scribe->res_cache, NULL);
	BUG_ON(!lock_region);

	lock_region->res = res;
	lock_region->object = object;
	lock_region->flags = flags;

	lock(lock_region);
}

void scribe_lock_object(void *object, struct scribe_resource *res, int flags)
{
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return;

	__lock_object(scribe, object, res, flags);
}

static void __lock_object_handle(struct scribe_ps *scribe, void *object,
				 struct scribe_resource_container *container,
				 int flags)
{
	struct scribe_resource_handle *hres;

	hres = find_resource_handle(scribe->ctx->res_ctx, container);
	if (likely(hres))
		__lock_object(scribe, object, &hres->res, flags);
	else
		scribe_emergency_stop(scribe->ctx, ERR_PTR(-ENOENT));
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

static inline bool can_skip_files_struct_sync(struct files_struct *files)
{
	/*
	 * We can skip the synchronization on the files_struct and also on the
	 * file pointer only when we have a single owner on the files_struct.
	 * It wouldn't be as trivial to do it for inodes since the number of
	 * users on an inode can change anywhere.
	 */
	return atomic_read(&files->count) <= 1;
}

static inline bool can_skip_file_sync(struct file *file)
{
	return atomic_read(&file->scribe_ref_cnt) <= 1;
}

void scribe_unlock_err(void *object, int err)
{
	struct scribe_ps *scribe = current->scribe;
	struct scribe_lock_region *lock_region;
	struct file *file;

	if (!should_handle_resources(scribe))
		return;

	lock_region = get_lock_region(&scribe->res_cache, object);
	if (!lock_region)
		return;

	if (lock_region->flags & (SCRIBE_INODE_READ | SCRIBE_INODE_WRITE)) {
		file = object;
		scribe_unlock_err(file_inode(file), err);
	}

	if (likely(!IS_ERR_VALUE(err)))
		unlock(&scribe->res_cache, lock_region);
	else
		unlock_discard(&scribe->res_cache, lock_region);
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

	WARN_ON(!find_lock_region(&scribe->res_cache, object));
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
void scribe_open_resource(struct scribe_resource_context *ctx,
			  struct scribe_resource_container *container,
			  int type, struct scribe_resource *sync_res,
			  int do_sync_open, int do_sync_close,
			  int *created, struct scribe_resource_cache *cache)
{
	struct scribe_resource_handle *hres;
	struct scribe_lock_region *open_lock_region = NULL;
	struct scribe_lock_region *close_lock_region;
	int _created;

	if (!created)
		created = &_created;

	if (do_sync_open) {
		open_lock_region = get_lock_region(cache, NULL);
		BUG_ON(!open_lock_region);

		open_lock_region->res = sync_res;
		open_lock_region->object = sync_res;

		lock(open_lock_region);
	}

	hres = get_resource_handle(ctx, container, type, created, &cache->hres);

	if (do_sync_open)
		unlock(cache, open_lock_region);

	if (do_sync_close) {
		close_lock_region = get_lock_region(cache, NULL);
		BUG_ON(!close_lock_region);

		/*
		 * Close synchronization can be performed on the resource
		 * itself. sync_res == NULL would indicate that.
		 */
		if (!sync_res)
			sync_res = &hres->res;

		close_lock_region->res = sync_res;
		close_lock_region->object = sync_res;

		spin_lock(&hres->lock);
		list_add(&close_lock_region->node, &hres->close_lock_regions);
		spin_unlock(&hres->lock);
	}
}

static void free_rcu_hres(struct rcu_head *rcu)
{
	kfree(container_of(rcu, struct scribe_resource_handle, rcu));
}

void scribe_close_resource(struct scribe_resource_context *ctx,
			   struct scribe_resource_container *container,
			   int do_close_sync, int *destroyed,
			   struct scribe_resource_cache *cache)
{
	struct scribe_lock_region *close_lock_region = NULL;
	struct scribe_resource_handle *hres;
	int _destroyed;

	if (!destroyed)
		destroyed = &_destroyed;

	hres = find_resource_handle(ctx, container);
	if (unlikely(!hres)) {
		scribe_emergency_stop(current->scribe->ctx, ERR_PTR(-ENOENT));
		return;
	}

	if (do_close_sync) {
		spin_lock(&hres->lock);
		BUG_ON(list_empty(&hres->close_lock_regions));
		close_lock_region = list_first_entry(&hres->close_lock_regions,
					__typeof__(*close_lock_region), node);
		list_del(&close_lock_region->node);
		spin_unlock(&hres->lock);

		lock(close_lock_region);
	}

	*destroyed = atomic_dec_and_test(&hres->ref_cnt);
	/*
	 * We have to defer the resource removal because the unlock() can be
	 * performed on the resource itself.
	 */

	if (do_close_sync)
		unlock(cache, close_lock_region);

	if (*destroyed) {
		spin_lock(&container->lock);
		list_del_rcu(&hres->container_node);
		spin_unlock(&container->lock);
		call_rcu(&hres->rcu, free_rcu_hres);
	}
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
	scribe_open_resource(ctx, &inode->i_scribe_resource,
			     SCRIBE_RES_TYPE_INODE, sync_res,
			     do_sync_open, do_sync_close, NULL,
			     &scribe->res_cache);
}

void scribe_close_file(struct file *file)
{
	int do_sync;
	struct inode *inode;
	struct scribe_resource_context *ctx;
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return;

	ctx = scribe->ctx->res_ctx;
	inode = file_inode(file);
	do_sync = inode_need_reg_sync(inode);
	scribe_close_resource(ctx, &inode->i_scribe_resource, do_sync, NULL,
			      &scribe->res_cache);

	if (atomic_dec_and_test(&file->scribe_ref_cnt))
		file->scribe_context = NULL;
}

static void __lock_file(struct file *file, int flags)
{
	struct scribe_ps *scribe = current->scribe;
	struct inode *inode;
	void *inode_lock_obj;

	if (!should_handle_resources(scribe))
		return;

	inode = file_inode(file);
	if (inode_need_explicit_locking(inode))
		flags &= ~(SCRIBE_INODE_READ | SCRIBE_INODE_WRITE);

	if (!can_skip_file_sync(file)) {
		__lock_object(scribe, file, &file->scribe_resource, flags);
		inode_lock_obj = inode;
	} else
		inode_lock_obj = file;


	if (flags & SCRIBE_INODE_READ)
		flags = SCRIBE_READ;
	else if (flags & SCRIBE_INODE_WRITE)
		flags = SCRIBE_WRITE;
	else
		return;

	/*
	 * We may associate the inode_lock_obj with the file, because this is
	 * what gets passed to the scribe_unlock() function.
	 * This is how the inode will get unlocked.
	 */
	__lock_object_handle(scribe, inode_lock_obj,
			     &inode->i_scribe_resource, flags);
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

void scribe_post_fget(struct files_struct *files, struct file *file,
		      int lock_flags)
{
	if (!lock_flags)
		return;

	scribe_unlock(files);
	if (file) {
		current->scribe->locked_file = file;
		__lock_file(file, lock_flags);
	}
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

	scribe_open_resource(scribe->ctx->res_ctx,
			     &files->scribe_resource,
			     SCRIBE_RES_TYPE_FILES_STRUCT |
			     SCRIBE_RES_TYPE_SPINLOCK, NULL,
			     SCRIBE_NO_SYNC, SCRIBE_SYNC, &created,
			     &scribe->res_cache);

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
	scribe_close_resource(scribe->ctx->res_ctx,
			      &files->scribe_resource, SCRIBE_SYNC, &destroyed,
			      &scribe->res_cache);
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
	if (can_skip_files_struct_sync(files))
		return;
	scribe_lock_object_handle(files, &files->scribe_resource, SCRIBE_READ);
}

void scribe_lock_files_write(struct files_struct *files)
{
	if (can_skip_files_struct_sync(files))
		return;
	scribe_lock_object_handle(files, &files->scribe_resource, SCRIBE_WRITE);
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
