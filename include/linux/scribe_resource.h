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
	int type;
	u32 serial;
	struct mutex lock;
	spinlock_t slock;
	wait_queue_head_t wait;
};


/* Types are also in scribe_api.h */
#define SCRIBE_RES_TYPE_RESERVED	0
#define SCRIBE_RES_TYPE_INODE		1
#define SCRIBE_RES_TYPE_FILE		2
#define SCRIBE_RES_TYPE_FILES_STRUCT	3
#define SCRIBE_RES_TYPE_TASK		4
#define SCRIBE_RES_TYPE_FUTEX		5
#define SCRIBE_RES_TYPE_IPC		6
#define SCRIBE_RES_TYPE_FS		7
#define SCRIBE_RES_TYPE_SPINLOCK	0x40
#define SCRIBE_RES_TYPE_REGISTRATION	0x80

void scribe_init_resource(struct scribe_resource *res, int type);
void scribe_reset_resource(struct scribe_resource *res);

#endif /* CONFIG_SCRIBE */

#endif /* _LINUX_SCRIBE_RESOURCE_H_ */
