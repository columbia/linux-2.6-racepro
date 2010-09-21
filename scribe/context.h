/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */


#ifndef _SCRIBE_CONTEXT_H
#define _SCRIBE_CONTEXT_H

#include <linux/list.h>
#include <linux/types.h>

struct proc_dir_entry;

typedef struct scribe_context {
	int id;
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *proc_entry;
#endif /* CONFIG_PROC_FS */
	int status;
	struct list_head tasks;
} scribe_context_t;

#define SCRIBE_IDLE	0
#define SCRIBE_RECORD	1
#define SCRIBE_REPLAY	2
#define SCRIBE_STOP	4

struct task_struct;

int scribe_init_context(scribe_context_t *ctx);
void scribe_exit_context(scribe_context_t *ctx);
int scribe_start_action(scribe_context_t *ctx, int action, pid_t pid);
int scribe_request_stop(scribe_context_t *ctx);


#endif /* _SCRIBE_CONTEXT_H */
