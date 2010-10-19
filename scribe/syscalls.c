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
#include <asm/syscall.h>

void scribe_enter_syscall(struct pt_regs *regs)
{
	struct scribe_event_syscall *event;
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return;

	__scribe_forbid_uaccess(scribe);

	if (is_stopping(scribe)) {
		scribe_detach(scribe);
		return;
	}

	if (is_recording(scribe))
		scribe_create_insert_point(scribe->queue, &scribe->syscall_ip);
	else {
		event = scribe_dequeue_event_specific(SCRIBE_EVENT_SYSCALL,
						      scribe->queue,
						      SCRIBE_WAIT);
		if (IS_ERR(event))
			return;

		if (event->nr != syscall_get_nr(current, regs))
			scribe_emergency_stop(scribe->ctx, ERR_PTR(-EDIVERGE));

		scribe->orig_ret = event->ret;
		scribe_free_event(event);
	}
	scribe->in_syscall = 1;
	scribe_set_data_flags(scribe, 0);
}

void scribe_exit_syscall(struct pt_regs *regs)
{
	struct scribe_ps *scribe = current->scribe;
	struct scribe_event_syscall *event;

	if (!is_scribed(scribe))
		return;

	__scribe_allow_uaccess(scribe);

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
			goto bad;
		event->nr = syscall_get_nr(current, regs);
		event->ret = syscall_get_return_value(current, regs);
		scribe_queue_event_at(&scribe->syscall_ip, event);
		scribe_commit_insert_point(&scribe->syscall_ip);

		if (scribe_queue_new_event(scribe->queue,
					   SCRIBE_EVENT_SYSCALL_END))
			goto bad;
	} else {
		scribe_dequeue_event_specific(SCRIBE_EVENT_SYSCALL_END,
					      scribe->queue, SCRIBE_WAIT);
		if (scribe->orig_ret != syscall_get_return_value(current, regs))
			scribe_emergency_stop(scribe->ctx, ERR_PTR(-EDIVERGE));
	}

	scribe->in_syscall = 0;
	return;

bad:
	scribe_emergency_stop(scribe->ctx, ERR_PTR(-ENOMEM));
}
