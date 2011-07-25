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

	list_for_each_entry_rcu(handle, &container->handles, nf.node) {
		if (handle->ctx == ctx)
			return handle;
	}

	return NULL;
}

struct scribe_handle *find_scribe_handle(struct scribe_container *container,
					 struct scribe_context *ctx)
{
	struct scribe_handle *handle;

	rcu_read_lock();
	handle = __get_handle(container, ctx);
	rcu_read_unlock();

	return handle;
}

extern struct scribe_handle *get_scribe_handle(
				struct scribe_container *container,
				struct scribe_context *ctx,
				struct scribe_handle* (*get_new) (void *),
				void *arg)
{
	struct scribe_handle *handle;

	handle = find_scribe_handle(container, ctx);
	if (handle)
		return handle;

	spin_lock_bh(&container->lock);
	handle = __get_handle(container, ctx);
	if (unlikely(handle)) {
		spin_unlock_bh(&container->lock);
		return handle;
	}

	handle = get_new(arg);
	handle->cr.container = container;
	handle->ctx = ctx;

	list_add_rcu(&handle->nf.node, &container->handles);

	spin_unlock_bh(&container->lock);

	return handle;
}

static void free_rcu_handle(struct rcu_head *rcu)
{
	struct scribe_handle *handle;
	handle = container_of(rcu, struct scribe_handle, cr.rcu);
	handle->nf.free(handle);
}

void remove_scribe_handle(struct scribe_handle *handle,
			  void (*free) (struct scribe_handle *))
{
	struct scribe_container *container = handle->cr.container;

	spin_lock_bh(&container->lock);
	list_del_rcu(&handle->nf.node);
	spin_unlock_bh(&container->lock);

	handle->nf.free = free;
	call_rcu(&handle->cr.rcu, free_rcu_handle);
}
