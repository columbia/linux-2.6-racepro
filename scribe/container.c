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
		if (handle->ctx == ctx)
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

	spin_lock_bh(&container->lock);
	handle = __get_handle(container, ctx);
	if (unlikely(handle)) {
		spin_unlock_bh(&container->lock);
		return handle;
	}

	handle = ctor->get_new(ctor->arg);
	handle->container = container;
	handle->ctx = ctx;
	handle->free = ctor->free;

	list_add_rcu(&handle->node, &container->handles);

	spin_unlock_bh(&container->lock);

	return handle;
}

static void free_rcu_handle(struct rcu_head *rcu)
{
	struct scribe_handle *handle;
	handle = container_of(rcu, struct scribe_handle, rcu);
	handle->free(handle);
}

void remove_scribe_handle(struct scribe_handle *handle)
{
	struct scribe_container *container = handle->container;

	spin_lock_bh(&container->lock);
	list_del_rcu(&handle->node);
	spin_unlock_bh(&container->lock);
	call_rcu(&handle->rcu, free_rcu_handle);
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
