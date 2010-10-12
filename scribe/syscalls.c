/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/scribe.h>

void scribe_enter_syscall(struct pt_regs *regs)
{
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return;

	if (is_stopping(scribe)) {
		scribe_detach(scribe);
		return;
	}

	if (is_recording(scribe)) {
		scribe_create_insert_point(scribe->queue, &scribe->syscall_ip);
	}
	scribe->in_syscall = 1;
}

void scribe_exit_syscall(struct pt_regs *regs)
{
	struct scribe_ps *scribe = current->scribe;
	struct scribe_event_syscall *event;

	if (!is_scribed(scribe))
		return;

	if (!scribe->in_syscall) {
		/*
		 * The current process was freshly attached. This syscall
		 * doesn't count, we don't want a half recorded syscall.
		 */
		return;
	}

	if (is_recording(scribe)) {
		event = scribe_alloc_event(SCRIBE_EVENT_SYSCALL);
		if (!event)
			scribe_emergency_stop(scribe->ctx, -ENOMEM);
		event->nr = regs->orig_ax;
		event->ret = regs->ax;
		scribe_queue_event_at(&scribe->syscall_ip, event);
		scribe_commit_insert_point(&scribe->syscall_ip);
	}

	scribe->in_syscall = 0;
}
