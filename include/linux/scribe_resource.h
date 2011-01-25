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

#ifndef _LINUX_SCRIBE_RESOURCE_H_
#define _LINUX_SCRIBE_RESOURCE_H_

#ifdef CONFIG_SCRIBE

#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/wait.h>

/*
 * This is not in scribe.h because of the compilation overhead: linux/fs.h
 * depends on this file.
 */

struct scribe_resource {
	/* Attached context, conveniant to know if a resource is tracked */
	struct scribe_context *ctx;

	/* This node correspond to the scribe_resources->tracked list */
	struct list_head node;

	/* Return -EAGAIN when the lock has been dropped */
	int (*on_reset) (struct scribe_context *, struct scribe_resource *);

	int type;
	u32 serial;
	struct mutex lock;
	spinlock_t slock;
	wait_queue_head_t wait;
};

/* Types are also in scribe_api.h */
#define SCRIBE_RES_TYPE_INODE		0
#define SCRIBE_RES_TYPE_FILE		1
#define SCRIBE_RES_TYPE_FILES_STRUCT	2
#define SCRIBE_RES_TYPE_TASK		3
#define SCRIBE_RES_TYPE_FUTEX		4
#define SCRIBE_RES_TYPE_IPC		5
#define SCRIBE_RES_TYPE_MASK		0x0f
#define SCRIBE_RES_SPINLOCK		0x80

void scribe_init_resource(struct scribe_resource *res, int type);
void scribe_reset_resource(struct scribe_resource *res);
struct scribe_container;
void scribe_reset_resource_container(struct scribe_container *container);

#endif /* CONFIG_SCRIBE */

#endif /* _LINUX_SCRIBE_RESOURCE_H_ */
