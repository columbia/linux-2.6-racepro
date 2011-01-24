/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/scribe_container.h>
#include <linux/rculist.h>

static struct scribe_handle *__get_handle(struct scribe_container *container,
					  struct scribe_context *ctx)
{
	struct scribe_handle *handle;

	list_for_each_entry_rcu(handle, &container->handles, node) {
		if (handle->ctx != ctx)
			continue;

		if (likely(atomic_inc_not_zero(&handle->ref_cnt)))
			return handle;
	}

	return NULL;
}

struct scribe_handle *get_scribe_handle(struct scribe_container *container,
					struct scribe_context *ctx,
					struct scribe_handle_ctor *ctor)
{
	struct scribe_handle *handle;

	rcu_read_lock();
	handle = __get_handle(container, ctx);
	rcu_read_unlock();
	if (handle)
		return handle;

	spin_lock(&container->lock);
	handle = __get_handle(container, ctx);
	if (unlikely(handle)) {
		spin_unlock(&container->lock);
		return handle;
	}

	handle = ctor->pre_alloc_handle;
	BUG_ON(!handle);
	atomic_set(&handle->ref_cnt, 1);
	handle->ctx = ctx;
	handle->free = ctor->free;
	ctor->init(handle, ctor->arg);

	list_add_rcu(&handle->node, &container->handles);

	spin_unlock(&container->lock);

	return handle;
}

static void free_rcu_handle(struct rcu_head *rcu)
{
	struct scribe_handle *handle;
	handle = container_of(rcu, struct scribe_handle, rcu);
	handle->free(handle);
}

void put_scribe_handle(struct scribe_container *container,
		       struct scribe_handle *handle,
		       struct scribe_handle_put *put)
{
	int ref_left = atomic_dec_return(&handle->ref_cnt);

	if (put) {
		put->ref_left = ref_left;
		put->put(handle, put->arg);
	}

	if (!ref_left) {
		spin_lock(&container->lock);
		list_del_rcu(&handle->node);
		spin_unlock(&container->lock);
		call_rcu(&handle->rcu, free_rcu_handle);
	}
}

struct scribe_handle *find_scribe_handle(struct scribe_container *container,
					 struct scribe_context *ctx)
{
	struct scribe_handle *handle;

	rcu_read_lock();
	list_for_each_entry_rcu(handle, &container->handles, node) {
		if (handle->ctx == ctx) {
			rcu_read_unlock();
			return handle;
		}
	}
	rcu_read_unlock();

	return NULL;
}

