/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */
#include "internal.h"
#include <linux/writeback.h>
#include <net/af_unix.h>

#ifdef CONFIG_LOCKDEP

#define set_lock_class(lock, type) do {					\
	struct resource_ops_struct *ops = &scribe_resource_ops[type];	\
	lockdep_set_class_and_name(lock, &ops->key, ops->name);		\
} while (0)

bool is_scribe_resource_key(struct lock_class_key *key)
{
	char *ptr = (char *)key;
	char *base = (char *)&scribe_resource_ops;
	return base <= ptr && ptr < (base + sizeof(scribe_resource_ops));
}

#else
#define set_lock_class(lock, type) do { } while (0)
#endif

void scribe_init_resource(struct scribe_resource *res, int type)
{
	res->ctx = NULL;
	res->id = -1; /* The id will be set once the resource is tracked */
	res->type = type;

	res->first_read_serial = -1;
	atomic_set(&res->serial, 0);

	if (use_spinlock(res)) {
		spin_lock_init(&res->lock.spinlock);
		set_lock_class(&res->lock.spinlock, type);
	} else {
		init_rwsem(&res->lock.semaphore);
		set_lock_class(&res->lock.semaphore, type);
	}

	init_waitqueue_head(&res->wait);
	atomic_set(&res->priority_users, 0);

	spin_lock_init(&res->lock_regions_lock);
	INIT_LIST_HEAD(&res->lock_regions);
}


static void acquire_res(struct scribe_context *ctx, struct scribe_resource *res,
			bool *lock_dropped)
{
	BUG_ON(res->ctx);
	BUG_ON(res->first_read_serial != -1);
	BUG_ON(atomic_read(&res->serial));

	res->ctx = ctx;
	res->id = ctx->res_ctx->next_id++;
	list_add(&res->node, &ctx->res_ctx->tracked);

	spin_unlock_bh(&ctx->res_ctx->lock);
	*lock_dropped = true;
}

static void release_res(struct scribe_resource *res, bool *lock_dropped)
{
	res->ctx = NULL;
	list_del(&res->node);
	res->first_read_serial = -1;
	atomic_set(&res->serial, 0);
}

static void release_mres(struct scribe_resource *res, bool *lock_dropped)
{
	struct scribe_mapped_res *mres;
	mres = container_of(res, struct scribe_mapped_res, mr_res);
	release_res(res, lock_dropped);
	scribe_remove_mapped_res(mres);
}

static struct inode *__get_inode_from_res(struct scribe_resource *res)
{
	struct scribe_mapped_res *mres;

	mres = container_of(res, struct scribe_mapped_res, mr_res);
	return container_of(mres->mr_map, struct inode, i_scribe_resource);
}

static void acquire_res_inode(struct scribe_context *ctx,
			      struct scribe_resource *res, bool *lock_dropped)
{
	struct inode *inode = __get_inode_from_res(res);
	acquire_res(ctx, res, lock_dropped);
	/* We don't need to hold the resources->lock anymore */
	BUG_ON(!*lock_dropped);
	spin_lock(&inode_lock);
	__iget(inode);
	spin_unlock(&inode_lock);
}

static void release_res_inode(struct scribe_resource *res, bool *lock_dropped)
{
	struct scribe_context *ctx = res->ctx;
	struct inode *inode = __get_inode_from_res(res);

	release_mres(res, NULL);
	spin_unlock_bh(&ctx->res_ctx->lock);
	*lock_dropped = true;
	/* iput sleeps */
	iput(inode);
}

static size_t get_path_desc(struct scribe_ps *scribe,
			    struct file *file, char *buffer, size_t size)
{
	char *tmp, *pathname;
	size_t ret;

	tmp = (char *)__get_free_page(GFP_TEMPORARY);
	if (!tmp) {
		return snprintf(buffer, size,
				"memory allocation failed");
	}

	scribe->do_dpath_scribing = false;
	pathname = d_path(&file->f_path, tmp, PAGE_SIZE);
	scribe->do_dpath_scribing = true;
	if (IS_ERR(pathname)) {
		ret = snprintf(buffer, size, "d_path failed with %ld",
			       PTR_ERR(pathname));
	} else
		ret = snprintf(buffer, size, "%s", pathname);

	free_page((unsigned long)tmp);

	return ret;
}

#define unix_peer(sk) (unix_sk(sk)->peer)
static size_t get_file_lock_description(struct scribe_ps *scribe,
					char *buffer, size_t _size,
					struct scribe_lock_region *lock_region)
{
	struct file *file = lock_region->object;
	ssize_t ret, size = _size;

	ret = get_path_desc(scribe, file, buffer, size);
	buffer += ret;
	size -= ret;

	if (S_ISSOCK(file->f_dentry->d_inode->i_mode)) {
		struct socket *sock = file->private_data;

		if (size <= 5)
			return ret;

		if (!sock->real_ops)
			return ret;

		if (sock->real_ops->family != PF_UNIX)
			return ret;

		if (!unix_peer(sock->sk))
			return ret;

		if (unix_peer(sock->sk)->sk_scribe_ctx != scribe->ctx)
			return ret;

		/* FIXME we should take some locks around here */

		if (!unix_peer(sock->sk)->sk_socket)
			return ret;

		strcat(buffer, " ");
		buffer += 1;
		size -= 1;
		ret += 1;

		file = unix_peer(sock->sk)->sk_socket->file;
		ret += get_path_desc(scribe, file, buffer, size);
	}

	return ret;
}

static size_t get_ppid_lock_description(struct scribe_ps *scribe,
					char *buffer, size_t size,
					struct scribe_lock_region *lock_region)
{
	struct task_struct *p = lock_region->object;
	return snprintf(buffer, size, "%d", task_pid_vnr(p));
}

#ifdef CONFIG_LOCKDEP
#define LK(name_, ...) [name_] = { .name = #name_,  __VA_ARGS__ },
#else
#define LK(name_, ...) [name_] = { __VA_ARGS__ },
#endif

struct resource_ops_struct scribe_resource_ops[SCRIBE_RES_NUM_TYPES] =
{
	LK(SCRIBE_RES_TYPE_INODE,	 .acquire = acquire_res_inode,
					 .release = release_res_inode)
	LK(SCRIBE_RES_TYPE_FILE,	 .track_users = true,
					 .release = release_mres,
					 .get_lock_description =
					            get_file_lock_description)
	LK(SCRIBE_RES_TYPE_FILES_STRUCT, .use_spinlock = true)
	LK(SCRIBE_RES_TYPE_PID,		 .release = release_mres)
	LK(SCRIBE_RES_TYPE_FUTEX,	 .use_spinlock = true,
					 .release = release_mres)
	LK(SCRIBE_RES_TYPE_IPC)
	LK(SCRIBE_RES_TYPE_MMAP)
	LK(SCRIBE_RES_TYPE_PPID,	 .use_spinlock = true,
					 .get_lock_description =
					            get_ppid_lock_description)
	LK(SCRIBE_RES_TYPE_SUNADDR,	 .use_spinlock = true,
					 .release = release_mres)
};

struct scribe_res_context *scribe_alloc_res_context(void)
{
	struct scribe_res_context *res_ctx;

	res_ctx = kmalloc(sizeof(*res_ctx), GFP_KERNEL);
	if (!res_ctx)
		return NULL;

	spin_lock_init(&res_ctx->lock);
	res_ctx->next_id = 0;
	INIT_LIST_HEAD(&res_ctx->tracked);

	res_ctx->pid_map = scribe_alloc_res_map(&scribe_pid_map_ops,
						PID_RES_HASH_BITS);
	if (!res_ctx->pid_map)
		goto err_resources;

	res_ctx->sunaddr_map = scribe_alloc_res_map(&scribe_sunaddr_map_ops,
						    SUNADDR_RES_HASH_BITS);
	if (!res_ctx->sunaddr_map)
		goto err_pid_map;

	return res_ctx;

err_pid_map:
	scribe_free_res_map(res_ctx->pid_map);
err_resources:
	kfree(res_ctx);
	return NULL;
}

void scribe_free_res_context(struct scribe_res_context *res_ctx)
{
	scribe_reset_resources(res_ctx);
	/*
	 * XXX There is no possible race with scribe_reset_resource() since
	 * all potential processes that could call scribe_reset_resource() and
	 * scribe_reset_resource_container() are gone.
	 */

	scribe_free_res_map(res_ctx->pid_map);
	scribe_free_res_map(res_ctx->sunaddr_map);
	kfree(res_ctx);
}

void scribe_track_resource(struct scribe_context *ctx,
			   struct scribe_resource *res)
{
	struct scribe_res_context *res_ctx;
	int type = res->type;
	bool lock_dropped = false;

	if (res->ctx) {
		BUG_ON(res->ctx != ctx);
		return;
	}

	res_ctx = ctx->res_ctx;
	spin_lock_bh(&res_ctx->lock);
	if (likely(!res->ctx)) {
		if (scribe_resource_ops[type].acquire)
			scribe_resource_ops[type].acquire(ctx, res, &lock_dropped);
		else
			acquire_res(ctx, res, &lock_dropped);

	}
	if (unlikely(!lock_dropped))
		spin_unlock_bh(&res_ctx->lock);
}

static void __scribe_reset_resource(struct scribe_resource *res,
				    bool *lock_dropped)
{
	int type = res->type;
	if (scribe_resource_ops[type].release)
		scribe_resource_ops[type].release(res, lock_dropped);
	else
		release_res(res, lock_dropped);
}

void scribe_reset_resource(struct scribe_resource *res)
{
	struct scribe_res_context *res_ctx;
	bool lock_dropped = false;

	if (!res->ctx)
		return;
	res_ctx = res->ctx->res_ctx;

	BUG_ON(!list_empty(&res->lock_regions));

	spin_lock_bh(&res_ctx->lock);
	__scribe_reset_resource(res, &lock_dropped);
	if (!lock_dropped)
		spin_unlock_bh(&res_ctx->lock);
}

void scribe_reset_resources(struct scribe_res_context *res_ctx)
{
	struct scribe_resource *res, *tmp;
	bool lock_dropped;

retry:
	lock_dropped = false;
	spin_lock_bh(&res_ctx->lock);
	list_for_each_entry_safe(res, tmp, &res_ctx->tracked, node) {
		__scribe_reset_resource(res, &lock_dropped);
		if (lock_dropped)
			goto retry;
	}
	spin_unlock_bh(&res_ctx->lock);
}

void scribe_reset_res_map(struct scribe_res_map *map)
{
	struct scribe_res_context *res_ctx;
	struct scribe_mapped_res *mres;
	struct scribe_context *ctx;
	bool lock_dropped;
	struct hlist_head *head;

	/*
	 * We only support single list resource maps, where the key
	 * is the scribe context.
	 */
	BUG_ON (map->ops->hash_fn);
	head = &map->head[0];

retry:
	rcu_read_lock_bh();
	if (hlist_empty(head)) {
		rcu_read_unlock_bh();
		return;
	}

	mres = hlist_entry(rcu_dereference_bh(head->first),
			   typeof(*mres), mr_node);
	ctx = mres->mr_key;

	/*
	 * ctx should always be valid: we are in a place where processes
	 * cannot add any handles to the list (umount).
	 */
	BUG_ON(!ctx);
	res_ctx = ctx->res_ctx;

	lock_dropped = false;
	spin_lock_bh(&res_ctx->lock);
	rcu_read_unlock_bh();

	__scribe_reset_resource(&mres->mr_res, &lock_dropped);
	if (lock_dropped)
		goto retry;
	spin_unlock_bh(&res_ctx->lock);
	goto retry;
}
