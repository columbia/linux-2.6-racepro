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

struct scribe_resource_handle {
	struct scribe_resource_context *ctx;
	struct list_head container_node;
	struct rcu_head rcu;

	struct scribe_resource res;
	/*
	 * We do not want to fail the resource close. So we need to allocate
	 * all the necessary memory during open. This is where it goes.
	 */
	spinlock_t lock;
	struct list_head close_lock_regions;
};

static int refill_hres_cache(struct scribe_ps *scribe)
{
	struct scribe_resource_handle *hres;
	if (scribe->pre_alloc_hres)
		return 0;

	hres = kmalloc(sizeof(*hres), GFP_KERNEL);
	if (!hres)
		return -ENOMEM;

	scribe->pre_alloc_hres = hres;
	return 0;
}

void scribe_free_resource_handle(struct scribe_resource_handle *hres)
{
	kfree(hres);
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

int scribe_init_lock_region(struct scribe_lock_region *lock_region,
			    struct scribe_resource *res)
{
	struct scribe_ps *scribe = current->scribe;

	lock_region->lock_event = NULL;
	lock_region->unlock_event = NULL;

	might_sleep();

	if (is_recording(scribe)) {
		lock_region->lock_event = scribe_alloc_event(
				SCRIBE_EVENT_RESOURCE_LOCK);
		if (!lock_region->lock_event)
			return -ENOMEM;

		lock_region->unlock_event = scribe_alloc_event(
				SCRIBE_EVENT_RESOURCE_UNLOCK);
		if (!lock_region->unlock_event) {
			scribe_free_event(lock_region->lock_event);
			return -ENOMEM;
		}
	}

	lock_region->res = res;

	return 0;
}

void scribe_exit_lock_region(struct scribe_lock_region *lock_region)
{
	if (unlikely(lock_region->lock_event))
		scribe_free_event(lock_region->lock_event);
	if (unlikely(lock_region->unlock_event))
		scribe_free_event(lock_region->unlock_event);
}

static struct scribe_lock_region *alloc_lock_region(struct scribe_resource *res)
{
	struct scribe_lock_region *lock_region;
	lock_region = kmalloc(sizeof(*lock_region), GFP_KERNEL);
	if (lock_region)
		scribe_init_lock_region(lock_region, res);
	return lock_region;
}

static void free_lock_region(struct scribe_lock_region *lock_region)
{
	scribe_exit_lock_region(lock_region);
	kfree(lock_region);
}

static int serial_match(struct scribe_resource *res, int serial)
{
	WARN_ON(res->serial > serial);
	return res->serial == serial;
}

static int get_lockdep_subclass(int type)
{
	if (type & SCRIBE_RES_TYPE_REGISTRATION_FLAG)
		return SCRIBE_RES_TYPE_RESERVED;
	return type;
}

void scribe_resource_lock(struct scribe_lock_region *lock_region)
{
	struct scribe_resource *res;
	struct scribe_event_resource_lock *event;
	struct scribe_ps *scribe = current->scribe;
	int type;
	int serial;

	might_sleep();

	if (!is_scribed(scribe))
		return;

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

		wait_event_killable(res->wait, serial_match(res, serial));
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

void scribe_resource_unlock(struct scribe_lock_region *lock_region)
{
	struct scribe_resource *res;
	struct scribe_event_resource_unlock *res_event;
	struct scribe_ps *scribe = current->scribe;
	int serial;

	might_sleep();

	if (!is_scribed(scribe))
		return;

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
	} else {
		wake_up_for_serial(res);
		res_event = scribe_dequeue_event_specific(scribe,
						  SCRIBE_EVENT_RESOURCE_UNLOCK);
		if (!IS_ERR(res_event))
			scribe_free_event(res_event);
	}
}

void scribe_resource_unlock_discard(struct scribe_lock_region *lock_region)
{
	struct scribe_ps *scribe = current->scribe;
	struct scribe_resource *res;

	if (!is_scribed(scribe))
		return;

	res = lock_region->res;
	mutex_unlock(&res->lock);

	if (is_recording(scribe))
		scribe_commit_insert_point(&lock_region->ip);
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
	struct scribe_resource_handle *hres;

	hres = container_of(rcu, typeof(*hres), rcu);
	scribe_free_resource_handle(hres);
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

static void resource_open(struct scribe_resource_context *ctx,
			  struct scribe_resource_container *container,
			  int type,
			  struct scribe_lock_region *open_lock_region,
			  struct scribe_lock_region *close_lock_region,
			  struct scribe_resource_handle **pre_alloc_hres)
{
	struct scribe_resource_handle *hres;

	if (open_lock_region)
		scribe_resource_lock(open_lock_region);

	hres = get_resource_handle(ctx, container, type, pre_alloc_hres);

	if (open_lock_region) {
		scribe_resource_unlock(open_lock_region);
		free_lock_region(open_lock_region);
	}

	if (close_lock_region) {
		spin_lock(&hres->lock);
		list_add(&close_lock_region->node,
			 &hres->close_lock_regions);
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

		scribe_resource_lock(close_lock_region);
	}

	put_resource_handle(ctx, container, hres);

	if (has_close_region) {
		scribe_resource_unlock(close_lock_region);
		free_lock_region(close_lock_region);
	}
}

static int open_inode(struct scribe_ps *scribe, struct inode *inode,
		      int do_sync_open, int do_sync_close)
{
	struct scribe_resource *sync_res;
	struct scribe_resource_context *ctx;
	struct scribe_lock_region *open_lock_region;
	struct scribe_lock_region *close_lock_region;

	if (refill_hres_cache(scribe))
		return -ENOMEM;

	ctx = scribe->ctx->res_ctx;

	if (do_sync_open || do_sync_close)
		sync_res = find_registration_res_inode(ctx, inode);

	open_lock_region = NULL;
	close_lock_region = NULL;

	if (do_sync_open) {
		open_lock_region = alloc_lock_region(sync_res);
		if (!open_lock_region)
			return -ENOMEM;
	}

	if (do_sync_close) {
		close_lock_region = alloc_lock_region(sync_res);
		if (!close_lock_region) {
			if (open_lock_region)
				free_lock_region(open_lock_region);
			return -ENOMEM;
		}
	}

	resource_open(ctx, &inode->i_scribe_resource, SCRIBE_RES_TYPE_INODE,
		      open_lock_region, close_lock_region,
		      &scribe->pre_alloc_hres);

	return 0;
}

static inline int inode_need_reg_sync(struct inode *inode)
{
	umode_t mode = inode->i_mode;

	/* never sync registration on fifo/socks/chr */
	return !(S_ISFIFO(mode) || S_ISSOCK(mode) || S_ISCHR(mode));
}

/*
 * For performance reasons, we allow the user not to synchronize the resource
 * opening. It's fine to do so when the inode is already registered and will
 * stay so deterministically.
 */
int scribe_resource_open_inode_nosync(struct inode *inode)
{
	int do_sync;
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return 0;

	do_sync = inode_need_reg_sync(inode);
	return open_inode(scribe, inode, 0, do_sync);
}

int scribe_resource_open_inode(struct inode *inode)
{
	int do_sync;
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return 0;

	do_sync = inode_need_reg_sync(inode);
	return open_inode(scribe, inode, do_sync, do_sync);
}

void scribe_resource_close_inode(struct inode *inode)
{
	int do_sync;
	struct scribe_resource_context *ctx;
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return;

	ctx = scribe->ctx->res_ctx;
	do_sync = inode_need_reg_sync(inode);

	resource_close(ctx, &inode->i_scribe_resource, do_sync);
}

int scribe_init_lock_region_inode(struct scribe_lock_region *lock_region,
				  struct inode *inode)
{
	struct scribe_ps *scribe = current->scribe;
	struct scribe_resource_handle *hres;

	if (!is_scribed(scribe))
		return 0;

	hres = find_resource_handle(scribe->ctx->res_ctx,
				    &inode->i_scribe_resource);
	BUG_ON(!hres);
	return scribe_init_lock_region(lock_region, &hres->res);
}

int scribe_resource_open_files(struct files_struct *files)
{
	struct scribe_resource *files_res = &files->scribe_resource;
	struct file *file;
	struct fdtable *fdt;
	struct inode *inode;
	int fd;
	int ret = 0;

	mutex_lock_nested(&files_res->lock,
			  get_lockdep_subclass(files_res->type));

	if (atomic_inc_return(&files_res->ref_cnt) != 1) {
		mutex_unlock(&files_res->lock);
		return 0;
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

		/*
		 * We don't need to synchronize the registration because:
		 * - We are starting a scribe session
		 * - Or those inodes are already registered, so there is no
		 *   race condition risk.
		 */
		inode = file->f_path.dentry->d_inode;
		ret = scribe_resource_open_inode(inode);
		if (ret) {
			/*
			 * FIXME Do some cleanup and return an error instead
			 * of dying.
			 */
			if (current->scribe)
				scribe_emergency_stop(current->scribe->ctx,
						      ERR_PTR(ret));
			break;
		}
	}

	mutex_unlock(&files_res->lock);
	return ret;
}

void scribe_resource_close_files(struct files_struct *files)
{
	struct scribe_resource *files_res = &files->scribe_resource;
	struct inode *inode;
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

		inode = file->f_path.dentry->d_inode;
		scribe_resource_close_inode(inode);
	}
}
