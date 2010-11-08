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

#define INODE_HASH_BITS 8
#define INODE_HASH_SIZE (1 << INODE_HASH_BITS)

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

static int scribe_resource_pre_alloc(struct scribe_resource_cache *cache,
				     int doing_recording)
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

int scribe_resource_prepare(void)
{
	struct scribe_ps *scribe = current->scribe;

	might_sleep();

	if (!is_scribed(scribe))
		return 0;

	return scribe_resource_pre_alloc(&scribe->res_cache,
					 is_recording(scribe));
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
	WARN(serial < res->serial,
	     "Waiting for serial = %d, but the current one is %d",
	     serial, res->serial);
	return serial == res->serial;
}

static int get_lockdep_subclass(int type)
{
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

static void __resource_lock_object(struct scribe_ps *scribe,
				   void *object, struct scribe_resource *res)
{
	struct scribe_lock_region *lock_region;

	lock_region = find_lock_region(&scribe->res_cache, NULL);
	BUG_ON(!lock_region);

	lock_region->object = object;
	lock_region->res = res;

	resource_lock(lock_region);
}

static void resource_lock_object(void *object, struct scribe_resource *res)
{
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return;

	__resource_lock_object(scribe, object, res);
}

static void resource_lock_object_handle(
		void *object, struct scribe_resource_container *container)
{
	struct scribe_resource_handle *hres;
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return;

	hres = find_resource_handle(scribe->ctx->res_ctx, container);
	BUG_ON(!hres);

	__resource_lock_object(scribe, object, &hres->res);
}

void scribe_resource_unlock(void *object)
{
	struct scribe_ps *scribe = current->scribe;
	struct scribe_lock_region *lock_region;

	if (!is_scribed(scribe))
		return;

	lock_region = get_lock_region(&scribe->res_cache, object);
	BUG_ON(!lock_region);

	resource_unlock(lock_region);
}

void scribe_resource_unlock_discard(void *object)
{
	struct scribe_ps *scribe = current->scribe;
	struct scribe_lock_region *lock_region;

	if (!is_scribed(scribe))
		return;

	lock_region = find_lock_region(&scribe->res_cache, object);
	BUG_ON(!lock_region);

	resource_unlock_discard(lock_region);
}

void scribe_resource_unlock_may_discard(void *object, int err)
{
	if (err >= 0)
		scribe_resource_unlock(object);
	else
		scribe_resource_unlock_discard(object);
}

void scribe_resource_assert_locked(void *object)
{
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return;

	WARN_ON(!find_lock_region(&scribe->res_cache, object));
}

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

		open_lock_region->res = sync_res;
		open_lock_region->object = sync_res;

		resource_lock(open_lock_region);
	}

	hres = get_resource_handle(ctx, container, type, &cache->hres);

	if (do_sync_open)
		resource_unlock(open_lock_region);

	if (do_sync_close) {
		close_lock_region = get_lock_region(cache, NULL);

		close_lock_region->res = sync_res;
		close_lock_region->object = sync_res;

		spin_lock(&hres->lock);
		list_add(&close_lock_region->node, &hres->close_lock_regions);
		spin_unlock(&hres->lock);
	}
}

static void resource_close(struct scribe_resource_context *ctx,
			   struct scribe_resource_container *container,
			   int has_close_region)
{
	struct scribe_lock_region *close_lock_region;
	struct scribe_resource_handle *hres;

	hres = find_resource_handle(ctx, container);
	BUG_ON(!hres);

	if (has_close_region) {
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

	if (has_close_region)
		resource_unlock(close_lock_region);
}

static inline int inode_need_reg_sync(struct inode *inode)
{
	umode_t mode = inode->i_mode;

	/* never sync registration on fifo/socks/chr */
	return !(S_ISFIFO(mode) || S_ISSOCK(mode) || S_ISCHR(mode));
}

static void open_inode(struct scribe_ps *scribe, struct inode *inode,
		      int do_sync_open)
{
	int do_sync_close;
	struct scribe_resource *sync_res = NULL;
	struct scribe_resource_context *ctx;

	ctx = scribe->ctx->res_ctx;

	do_sync_close = inode_need_reg_sync(inode);
	do_sync_open &= inode_need_reg_sync(inode);

	if (do_sync_close)
		sync_res = find_registration_res_inode(ctx, inode);

	resource_open(ctx, &inode->i_scribe_resource, SCRIBE_RES_TYPE_INODE,
		      sync_res, do_sync_open, do_sync_close,
		      &scribe->res_cache);
}

static inline struct inode *file_inode(struct file *file)
{
	return file->f_path.dentry->d_inode;
}

/*
 * For performance reasons, we allow the user not to synchronize the resource
 * opening. It's fine to do so when the file is already registered and will
 * stay so deterministically.
 */
void scribe_resource_open_file(struct file *file)
{
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return;

	open_inode(scribe, file_inode(file), 0);
}

void scribe_resource_open_file_sync(struct file *file)
{
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return;

	open_inode(scribe, file_inode(file), 1);
}

void scribe_resource_close_file(struct file *file)
{
	int do_sync;
	struct inode *inode;
	struct scribe_resource_context *ctx;
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return;

	ctx = scribe->ctx->res_ctx;
	inode = file_inode(file);
	do_sync = inode_need_reg_sync(inode);
	resource_close(ctx, &inode->i_scribe_resource, do_sync);
}

/*
 * Performance wise, it's not worth it to distinguish the file resource, and
 * the inode resource. So we'll be always taking the inode lock.
 */
void scribe_resource_lock_file_only(struct file *file)
{
	resource_lock_object_handle(file, &file_inode(file)->i_scribe_resource);
}
void scribe_resource_lock_file(struct file *file)
{
	scribe_resource_lock_file_only(file);
}

void scribe_resource_open_files(struct files_struct *files)
{
	struct scribe_resource *files_res = &files->scribe_resource;
	struct file *file;
	struct fdtable *fdt;
	int fd;

	mutex_lock_nested(&files_res->lock,
			  get_lockdep_subclass(files_res->type));

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
		file = rcu_dereference_check(fdt->fd[fd], 1);
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
		scribe_resource_open_file(file);
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
		file = rcu_dereference_check(fdt->fd[fd], 1);
		if (!file)
			continue;

		scribe_resource_close_file(file);
	}
}

void scribe_resource_lock_files(struct files_struct *files)
{
	resource_lock_object(files, &files->scribe_resource);
}
