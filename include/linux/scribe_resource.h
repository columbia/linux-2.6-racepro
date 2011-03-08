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

#ifdef __KERNEL__

#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/wait.h>
#include <asm/atomic.h>

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

	int id;
	int type;

	/*
	 * @first_read_serial is used during the recording to save the first
	 * serial number of read accesses.
	 */
	unsigned long first_read_serial;

	/*
	 * An atomic type is needed here because the replay doesn't take any
	 * locks.
	 */
	atomic_t serial;

	union {
		struct rw_semaphore semaphore;
		spinlock_t spinlock;
	} lock;

	wait_queue_head_t wait;
};

void scribe_init_resource(struct scribe_resource *res, int type);
void scribe_reset_resource(struct scribe_resource *res);
struct scribe_container;
void scribe_reset_resource_container(struct scribe_container *container);

#endif /* __KERNEL__ */

/*
 * XXX When adding a new resource type, don't forget to call reset_resource()
 * when the resource object is about to vanish...
 */

enum scribe_resource_type {
	SCRIBE_RES_TYPE_INODE,
	SCRIBE_RES_TYPE_FILE,
	SCRIBE_RES_TYPE_FILES_STRUCT,
	SCRIBE_RES_TYPE_PID,
	SCRIBE_RES_TYPE_FUTEX,
	SCRIBE_RES_TYPE_IPC,
	SCRIBE_RES_TYPE_MMAP,
};
#define SCRIBE_RES_TYPE_MASK		0x0f
#define SCRIBE_RES_SPINLOCK		0x80

#endif /* CONFIG_SCRIBE */

#endif /* _LINUX_SCRIBE_RESOURCE_H_ */
