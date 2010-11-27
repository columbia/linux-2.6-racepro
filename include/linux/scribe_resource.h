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

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/wait.h>

/*
 * This is not in scribe.h because of the compilation overhead: linux/fs.h
 * depends on this file.
 */

/*
 * We want to store each resource in the struct of the object they
 * synchronize. For example we want to put a resource in the inode struct.
 * But an inode may be utilized by more than one scribe context, thus the
 * resource_container.
 * On the other hand, a files_struct object can only be synchronized in one
 * scribe context. A simple scribe_resource will be used.
 */

struct scribe_resource_container {
	spinlock_t lock;
	struct list_head handles;
};

struct scribe_resource {
	atomic_t ref_cnt;
	int type;
	u32 serial;
	struct mutex lock;
	wait_queue_head_t wait;
};

extern void scribe_init_resource_container(
				struct scribe_resource_container *container);


/* Types are also in scribe_api.h */
#define SCRIBE_RES_TYPE_RESERVED	0
#define SCRIBE_RES_TYPE_INODE		1
#define SCRIBE_RES_TYPE_FILE		2
#define SCRIBE_RES_TYPE_FILES_STRUCT	3
#define SCRIBE_RES_TYPE_TASK		4
#define SCRIBE_RES_TYPE_FUTEX		5
#define SCRIBE_RES_TYPE_REGISTRATION_FLAG 0x80
#define SCRIBE_RES_TYPE_REGISTRATION(type) \
	((type) | SCRIBE_RES_TYPE_REGISTRATION_FLAG)

void scribe_init_resource(struct scribe_resource *res, int type);
void scribe_reset_resource(struct scribe_resource *res);

#endif /* CONFIG_SCRIBE */

#endif /* _LINUX_SCRIBE_RESOURCE_H_ */
