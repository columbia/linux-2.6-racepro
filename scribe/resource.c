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
 *   operations. get_unused_fd() will successfully return only with the cache
 *   refilled (so that fd_install() can proceed).
 *
 * - The files_struct lock will be taken in call get_unused_fd(), and
 *   put_unused_fd(). This ensure consistency on file descriptors value when
 *   concurrent open/close happens. You have to call scribe_resource_prepare()
 *   before calling those functions.
 *
 * - FIXME fget() needs to take the files_struct lock to guard with
 *   fd_install() and "fd_uninstall()".
 *
 * - The files_struct lock must be taken as well to access any close_on_exec
 *   flags.
 *
 * - The filp lock must be taken to access any of the file related data.
 *
 * - The filp+inode lock must be taken to access any of the file related data
 *   and/or inode related data.
 */

#define INODE_HASH_BITS 8
#define INODE_HASH_SIZE (1 << INODE_HASH_BITS)

#define SCRIBE_READ		0x01
#define SCRIBE_WRITE		0x02
#define SCRIBE_INODE_READ	0x04
#define SCRIBE_INODE_WRITE	0x08

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
				     SCRIBE_RES_TYPE_REGISTRATION(
					      SCRIBE_RES_TYPE_INODE));
	}

	return ctx;
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
	struct scribe_resource_context *ctx;
	struct list_head container_node;
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
	atomic_set(&res->ref_cnt, 0);
	res->type = type;
	res->serial = 0;
	mutex_init(&res->lock);
	init_waitqueue_head(&res->wait);
}

static void init_resource_handle(struct scribe_resource_context *ctx,
				 struct scribe_resource_handle *hres, int type)
{
	hres->ctx = ctx;
	scribe_init_resource(&hres->res, type);
	spin_lock_init(&hres->lock);
	INIT_LIST_HEAD(&hres->close_lock_regions);
}

struct scribe_lock_region {
	struct list_head node;
	struct scribe_insert_point ip;
	struct scribe_event_resource_lock *lock_event;
	struct scribe_event_resource_unlock *unlock_event;
	struct scribe_resource *res;
	void *object;
	int flags;
};

static int reinit_lock_region(struct scribe_lock_region *lock_region,
			      int doing_recording)
{
	/*
	 * During replaying, we don't really need those events, since they
	 * will be coming from the event pump.
	 */
	if (!doing_recording)
		return 0;

	if (!lock_region->lock_event) {
		lock_region->lock_event = scribe_alloc_event(
						SCRIBE_EVENT_RESOURCE_LOCK);
		if (!lock_region->lock_event)
			return -ENOMEM;
	}

	if (!lock_region->unlock_event) {
		lock_region->unlock_event = scribe_alloc_event(
						SCRIBE_EVENT_RESOURCE_UNLOCK);
		if (!lock_region->unlock_event) {
			scribe_free_event(lock_region->lock_event);
			lock_region->lock_event = NULL;
			return -ENOMEM;
		}
	}

	return 0;
}

static int init_lock_region(struct scribe_lock_region *lock_region,
			    int record_mode)
{
	lock_region->lock_event = NULL;
	lock_region->unlock_event = NULL;
	lock_region->res = NULL;
	lock_region->object = NULL;

	return reinit_lock_region(lock_region, record_mode);
}

/* Use this when you didn't had the chance to lock()/unlock() the resource */
static void exit_lock_region(struct scribe_lock_region *lock_region)
{
	scribe_free_event(lock_region->lock_event);
	scribe_free_event(lock_region->unlock_event);
}

void scribe_resource_init_cache(struct scribe_resource_cache *cache)
{
	memset(cache, 0, sizeof(*cache));
}

static int resource_pre_alloc(struct scribe_resource_cache *cache,
			      int doing_recording)
{
	struct scribe_lock_region *lock_region;
	int i;

	cache->hres = kmalloc(sizeof(*cache->hres), GFP_KERNEL);
	if (!cache->hres)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(cache->lock_regions); i++) {
		lock_region = cache->lock_regions[i];

		if (lock_region && !lock_region->object) {
			if (reinit_lock_region(lock_region, doing_recording))
				return -ENOMEM;
			continue;
		}

		lock_region = kmalloc(sizeof(*lock_region), GFP_KERNEL);
		if (!lock_region)
			return -ENOMEM;
		if (init_lock_region(lock_region, doing_recording)) {
			kfree(lock_region);
			return -ENOMEM;
		}
		cache->lock_regions[i] = lock_region;
	}

	return 0;
}

static int __scribe_resource_prepare(struct scribe_ps *scribe)
{
	might_sleep();

	if (resource_pre_alloc(&scribe->res_cache, is_recording(scribe)))
		return -ENOMEM;

	return 0;
}

int scribe_resource_prepare(void)
{
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return 0;

	return __scribe_resource_prepare(scribe);
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

		if (likely(atomic_inc_not_zero(&hres->res.ref_cnt)))
			return hres;
	}

	return NULL;
}

static struct scribe_resource_handle *get_resource_handle(
				struct scribe_resource_context *ctx,
				struct scribe_resource_container *container,
				int type,
				struct scribe_resource_handle **pre_alloc_hres)
{
	struct scribe_resource_handle *hres;

	BUG_ON(!*pre_alloc_hres);

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

	init_resource_handle(ctx, hres, type);
	atomic_set(&hres->res.ref_cnt, 1);

	list_add_rcu(&hres->container_node, &container->handles);

	spin_unlock(&container->lock);

	return hres;
}

static void free_rcu_hres(struct rcu_head *rcu)
{
	kfree(container_of(rcu, struct scribe_resource_handle, rcu));
}

static void put_resource_handle(struct scribe_resource_context *ctx,
				struct scribe_resource_container *container,
				struct scribe_resource_handle *hres)
{
	if (atomic_dec_and_test(&hres->res.ref_cnt)) {
		spin_lock(&container->lock);
		list_del_rcu(&hres->container_node);
		spin_unlock(&container->lock);
		call_rcu(&hres->rcu, free_rcu_hres);
	}
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

static int serial_match(struct scribe_resource *res, int serial)
{
	if (serial < res->serial) {
		printk(KERN_ERR "Waiting for serial = %d, "
		       "but the current one is %d\n", serial, res->serial);
		BUG();
	}
	return serial == res->serial;
}

static int get_lockdep_subclass(int type)
{
	/* MAX_LOCKDEP_SUBCLASSES is small, trying not to overflow it */
	if (type & SCRIBE_RES_TYPE_REGISTRATION_FLAG)
		return SCRIBE_RES_TYPE_RESERVED;
	return type;
}

static void resource_lock(struct scribe_lock_region *lock_region)
{
	struct scribe_resource *res;
	struct scribe_event_resource_lock *event;
	struct scribe_ps *scribe = current->scribe;
	int type;
	int serial;

	res = lock_region->res;

	if (is_recording(scribe)) {
		scribe_create_insert_point(&scribe->queue->bare,
					   &lock_region->ip);
	} else {
		event = scribe_dequeue_event_specific(scribe,
						SCRIBE_EVENT_RESOURCE_LOCK);
		if (IS_ERR(event))
			goto out;

		type = event->type;
		serial = event->serial;
		scribe_free_event(event);

		if (type != res->type) {
			scribe_diverge(scribe,
				       SCRIBE_EVENT_DIVERGE_RESOURCE_TYPE,
				       .type = res->type);
			scribe_free_event(event);
			goto out;
		}

		/* That's for avoiding a thundering herd */
		scribe->waiting_for_serial = serial;
		wmb();

		if (wait_event_killable(res->wait, serial_match(res, serial))) {
			scribe_emergency_stop(current->scribe->ctx,
					      ERR_PTR(-EINTR));
		}
	}

	/*
	 * Even in case of replay errors, we want to take the lock, so that we
	 * stay consistent.
	 */
out:
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

static void resource_unlock(struct scribe_lock_region *lock_region)
{
	struct scribe_resource *res;
	struct scribe_event_resource_unlock *res_event;
	struct scribe_ps *scribe = current->scribe;
	int serial;

	might_sleep();

	res = lock_region->res;
	serial = res->serial++;
	mutex_unlock(&res->lock);

	if (is_recording(scribe)) {
		lock_region->lock_event->type = res->type;
		lock_region->lock_event->serial = serial;

		scribe_queue_event_at(&lock_region->ip,
				      lock_region->lock_event);
		scribe_commit_insert_point(&lock_region->ip);
		scribe_queue_event(scribe->queue, lock_region->unlock_event);

		lock_region->lock_event = NULL;
		lock_region->unlock_event = NULL;

		/*
		 * We don't need to call exit_lock_region(),
		 * The events are gone.
		 */
	} else {
		wake_up_for_serial(res);
		res_event = scribe_dequeue_event_specific(scribe,
						  SCRIBE_EVENT_RESOURCE_UNLOCK);
		if (!IS_ERR(res_event))
			scribe_free_event(res_event);
	}

	kfree(lock_region);
}

static void resource_unlock_discard(struct scribe_lock_region *lock_region)
{
	struct scribe_ps *scribe = current->scribe;
	struct scribe_resource *res;

	res = lock_region->res;
	mutex_unlock(&res->lock);

	if (is_recording(scribe)) {
		scribe_commit_insert_point(&lock_region->ip);
		exit_lock_region(lock_region);
	}

	lock_region->res = NULL;
	lock_region->object = NULL;
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

static void __resource_lock_object(struct scribe_ps *scribe, void *object,
				   struct scribe_resource *res, int flags)
{
	struct scribe_lock_region *lock_region;

	lock_region = find_lock_region(&scribe->res_cache, NULL);
	BUG_ON(!lock_region);

	lock_region->res = res;
	lock_region->object = object;
	lock_region->flags = flags;

	resource_lock(lock_region);
}

static void resource_lock_object(void *object, struct scribe_resource *res,
				 int flags)
{
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return;

	__resource_lock_object(scribe, object, res, flags);
}

static void __resource_lock_object_handle(struct scribe_ps *scribe,
		void *object, struct scribe_resource_container *container,
		int flags)
{
	struct scribe_resource_handle *hres;

	hres = find_resource_handle(scribe->ctx->res_ctx, container);
	BUG_ON(!hres);

	__resource_lock_object(scribe, object, &hres->res, flags);
}

static inline struct inode *file_inode(struct file *file)
{
	return file->f_path.dentry->d_inode;
}

void scribe_resource_unlock_err(void *object, int err)
{
	struct scribe_ps *scribe = current->scribe;
	struct scribe_lock_region *lock_region;
	struct file *file;

	if (!should_handle_resources(scribe))
		return;

	lock_region = get_lock_region(&scribe->res_cache, object);
	BUG_ON(!lock_region);

	if (lock_region->flags & (SCRIBE_INODE_READ | SCRIBE_INODE_WRITE)) {
		file = object;
		scribe_resource_unlock_err(file_inode(file), err);
	}

	if (likely(err >= 0))
		resource_unlock(lock_region);
	else
		resource_unlock_discard(lock_region);
}

void scribe_resource_unlock(void *object)
{
	scribe_resource_unlock_err(object, 0);
}

void scribe_resource_unlock_discard(void *object)
{
	scribe_resource_unlock_err(object, -1);
}

void scribe_resource_assert_locked(void *object)
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
static void resource_open(struct scribe_resource_context *ctx,
			  struct scribe_resource_container *container,
			  int type, struct scribe_resource *sync_res,
			  int do_sync_open, int do_sync_close,
			  struct scribe_resource_cache *cache)
{
	struct scribe_resource_handle *hres;
	struct scribe_lock_region *open_lock_region = NULL;
	struct scribe_lock_region *close_lock_region;

	if (do_sync_open) {
		open_lock_region = get_lock_region(cache, NULL);
		BUG_ON(!open_lock_region);

		open_lock_region->res = sync_res;
		open_lock_region->object = sync_res;

		resource_lock(open_lock_region);
	}

	hres = get_resource_handle(ctx, container, type, &cache->hres);

	if (do_sync_open)
		resource_unlock(open_lock_region);

	if (do_sync_close) {
		close_lock_region = get_lock_region(cache, NULL);
		BUG_ON(!close_lock_region);

		close_lock_region->res = sync_res;
		close_lock_region->object = sync_res;

		spin_lock(&hres->lock);
		list_add(&close_lock_region->node, &hres->close_lock_regions);
		spin_unlock(&hres->lock);
	}
}

static void resource_close(struct scribe_resource_context *ctx,
			   struct scribe_resource_container *container,
			   int do_close_sync)
{
	struct scribe_lock_region *close_lock_region;
	struct scribe_resource_handle *hres;

	hres = find_resource_handle(ctx, container);
	BUG_ON(!hres);

	if (do_close_sync) {
		spin_lock(&hres->lock);
		BUG_ON(list_empty(&hres->close_lock_regions));
		close_lock_region = list_first_entry(&hres->close_lock_regions,
						     typeof(*close_lock_region),
						     node);
		list_del(&close_lock_region->node);
		spin_unlock(&hres->lock);

		resource_lock(close_lock_region);
	}

	put_resource_handle(ctx, container, hres);

	if (do_close_sync)
		resource_unlock(close_lock_region);
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

void scribe_resource_open_file(struct file *file, int do_sync)
{
	struct scribe_ps *scribe = current->scribe;
	struct inode *inode;
	struct scribe_resource_context *file_ctx, *current_ctx;
	struct scribe_resource *sync_res;
	int do_sync_open, do_sync_close;

	if (!should_handle_resources(scribe))
		return;

	current_ctx = scribe->ctx->res_ctx;

	/* Files struct must belong to only one scribe resource context */
	file_ctx = xchg(&file->scribe_context, current_ctx);
	if (!file_ctx) {
		scribe_init_resource(&file->scribe_resource,
				     SCRIBE_RES_TYPE_FILE);
		file_ctx = current_ctx;
	}
	BUG_ON(file_ctx != current_ctx);
	atomic_inc(&file->scribe_resource.ref_cnt);

	inode = file_inode(file);
	sync_res = find_registration_res_inode(current_ctx, inode);
	do_sync_open = do_sync && inode_need_reg_sync(inode);
	do_sync_close = inode_need_reg_sync(inode);
	resource_open(current_ctx, &inode->i_scribe_resource,
		      SCRIBE_RES_TYPE_INODE, sync_res,
		      do_sync_open, do_sync_close, &scribe->res_cache);
}

void scribe_resource_close_file(struct file *file)
{
	int do_sync;
	struct inode *inode;
	struct scribe_resource_context *current_ctx;
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return;

	current_ctx = scribe->ctx->res_ctx;
	inode = file_inode(file);
	do_sync = inode_need_reg_sync(inode);
	resource_close(current_ctx, &inode->i_scribe_resource, do_sync);

	if (atomic_dec_and_test(&file->scribe_resource.ref_cnt))
		file->scribe_context = NULL;
}

static void __scribe_resource_lock_file(struct file *file, int flags)
{
	struct scribe_ps *scribe = current->scribe;
	struct inode *inode;

	if (!should_handle_resources(scribe))
		return;

	inode = file_inode(file);
	if (inode_need_explicit_locking(inode))
		flags &= ~(SCRIBE_INODE_READ | SCRIBE_INODE_WRITE);

	__resource_lock_object(scribe, file, &file->scribe_resource, flags);

	if (flags & SCRIBE_INODE_READ)
		flags = SCRIBE_READ;
	else if (flags & SCRIBE_INODE_WRITE)
		flags = SCRIBE_WRITE;
	else
		return;

	__resource_lock_object_handle(scribe, inode,
				      &inode->i_scribe_resource, flags);
}

void scribe_resource_lock_file_no_inode(struct file *file)
{
	__scribe_resource_lock_file(file, SCRIBE_WRITE);
}

void scribe_resource_lock_file_read(struct file *file)
{
	__scribe_resource_lock_file(file, SCRIBE_WRITE | SCRIBE_INODE_READ);
}

void scribe_resource_lock_file_write(struct file *file)
{
	__scribe_resource_lock_file(file, SCRIBE_WRITE | SCRIBE_INODE_WRITE);
}

static void __scribe_resource_lock_inode(struct inode *inode, int flags)
{
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return;

	__resource_lock_object_handle(scribe, inode,
				      &inode->i_scribe_resource, flags);
}

void scribe_resource_lock_inode_read(struct inode *inode)
{
	__scribe_resource_lock_inode(inode, SCRIBE_READ);
}

void scribe_resource_lock_inode_write(struct inode *inode)
{
	__scribe_resource_lock_inode(inode, SCRIBE_WRITE);
}

static int __scribe_resource_lock_next_file(int flags)
{
	struct scribe_ps *scribe = current->scribe;

	if (!should_handle_resources(scribe))
		return 0;

	if (__scribe_resource_prepare(scribe))
		return -ENOMEM;

	scribe->lock_next_file = flags;
	return 0;
}

int scribe_resource_lock_next_file_no_inode(void)
{
	return __scribe_resource_lock_next_file(SCRIBE_WRITE);
}

int scribe_resource_lock_next_file_read(void)
{
	return __scribe_resource_lock_next_file(SCRIBE_WRITE |
						SCRIBE_INODE_READ);
}

int scribe_resource_lock_next_file_write(void)
{
	return __scribe_resource_lock_next_file(SCRIBE_WRITE |
						SCRIBE_INODE_WRITE);
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
		scribe_resource_lock_files_read(files);
	}
}

void scribe_post_fget(struct files_struct *files, struct file *file,
		      int lock_flags)
{
	if (!lock_flags)
		return;

	if (file) {
		scribe_resource_unlock(files);

		current->scribe->locked_file = file;
		__scribe_resource_lock_file(file, lock_flags);
	} else
		scribe_resource_unlock_discard(files);
}

void scribe_pre_fput(struct file *file)
{
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return;

	if (scribe->locked_file) {
		scribe_resource_unlock(scribe->locked_file);
		scribe->locked_file = NULL;
	}
}

#define rcu_dereference_check_fd(files, fdt, _fd) \
	(rcu_dereference_check((fdt)->fd[(_fd)], \
			       rcu_read_lock_held() || \
			       lockdep_is_held(&(files)->file_lock) || \
			       atomic_read(&(files)->count) == 1 || \
			       rcu_my_thread_group_empty()))

void scribe_resource_open_files(struct files_struct *files)
{
	struct scribe_resource *files_res = &files->scribe_resource;
	struct file *file;
	struct fdtable *fdt;
	int fd;

	mutex_lock_nested(&files_res->lock,
			  get_lockdep_subclass(files_res->type));

	/*
	 * It is much more efficient to open files only at the beginning,
	 * otherwise we will end with a lot of open/close allocated regions
	 * when dealing with a lot of threads, so we will reference count the
	 * open/close of the files_struct.
	 * It is better to use our own ref_cnt rather than the one in
	 * files_struct because we might want to attach to live processes later
	 * on, where their ref_cnt is already set.
	 */
	if (atomic_inc_return(&files_res->ref_cnt) != 1) {
		mutex_unlock(&files_res->lock);
		return;
	}

	/*
	 * We don't need to take any of the standard fdtable locks here
	 * because any process other process trying to access the files_struct
	 * will be waiting scribe_resource_register_files() to complete.
	 */
	fdt = files_fdtable(files);
	for (fd = 0; fd < fdt->max_fds; fd++) {
		file = rcu_dereference_check_fd(files, fdt, fd);
		if (!file)
			continue;

		if (scribe_resource_prepare()) {
			/*
			 * FIXME Make this unfailable (do the memory
			 * allocation in init_scribe()).
			 */
			scribe_emergency_stop(current->scribe->ctx,
					      ERR_PTR(-ENOMEM));
			break;
		}

		/*
		 * We don't need to synchronize the registration because:
		 * - We are starting a scribe session
		 * - Or those inodes are already registered, so there is no
		 *   race condition risk.
		 */
		scribe_resource_open_file(file, SCRIBE_NOSYNC);
	}

	mutex_unlock(&files_res->lock);
}

void scribe_resource_close_files(struct files_struct *files)
{
	struct scribe_resource *files_res = &files->scribe_resource;
	struct file *file;
	struct fdtable *fdt;
	int fd;

	if (!atomic_dec_and_test(&files_res->ref_cnt))
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

		scribe_resource_close_file(file);
	}
}

void scribe_resource_lock_files_read(struct files_struct *files)
{
	resource_lock_object(files, &files->scribe_resource, SCRIBE_READ);
}

void scribe_resource_lock_files_write(struct files_struct *files)
{
	resource_lock_object(files, &files->scribe_resource, SCRIBE_WRITE);
}
