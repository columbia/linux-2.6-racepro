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

#ifndef _LINUX_SCRIBE_CONTAINER_H_
#define _LINUX_SCRIBE_CONTAINER_H_

#ifdef CONFIG_SCRIBE

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <asm/atomic.h>

/*
 * This is not in scribe.h because of the compilation overhead: linux/fs.h
 * depends on this file.
 */

/*
 * We want to store objects (resources and page information) per scribe
 * context. This is the mechanism that allow to do so.
 */

struct scribe_container {
	spinlock_t lock;
	struct list_head handles;
};

struct scribe_handle_ctor {
	struct scribe_handle *pre_alloc_handle;
	void (*init) (struct scribe_handle *, void *);
	void *arg;
	void (*free) (struct scribe_handle *);
};

struct scribe_handle_put {
	void (*put) (struct scribe_handle *, void *);
	void *arg;
	int ref_left;
};

struct scribe_handle {
	struct list_head node;
	struct scribe_context *ctx;
	atomic_t ref_cnt;
	struct rcu_head rcu;
	void (*free) (struct scribe_handle *);
};

static inline void scribe_init_container(struct scribe_container *container)
{
	spin_lock_init(&container->lock);
	INIT_LIST_HEAD(&container->handles);
}

extern struct scribe_handle *get_scribe_handle(
		struct scribe_container *container,
		struct scribe_context *ctx, struct scribe_handle_ctor *ctor);

extern void put_scribe_handle(struct scribe_container *container,
			      struct scribe_handle *handle,
			      struct scribe_handle_put *put);

extern struct scribe_handle *find_scribe_handle(
					struct scribe_container *container,
					struct scribe_context *ctx);

#endif /* CONFIG_SCRIBE */

#endif /* _LINUX_SCRIBE_CONTAINER_H_ */
