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
#include <linux/syscalls.h>
#include <asm/syscall.h>

static int is_scribe_syscall(int nr)
{
	return nr == __NR_get_scribe_flags ||
	       nr == __NR_set_scribe_flags;
}

void scribe_enter_syscall(struct pt_regs *regs)
{
	struct scribe_event_syscall *event;
	struct scribe_ps *scribe = current->scribe;
	int nr_syscall = syscall_get_nr(current, regs);

	if (!is_scribed(scribe))
		return;

	if (is_scribe_syscall(nr_syscall))
		return;

	__scribe_forbid_uaccess(scribe);

	if (is_stopping(scribe)) {
		scribe_detach(scribe);
		return;
	}

	if (!should_scribe_syscalls(scribe))
		return;

	if (is_recording(scribe))
		scribe_create_insert_point(&scribe->queue->bare,
					   &scribe->syscall_ip);
	else {
		event = scribe_dequeue_event_specific(scribe,
						      SCRIBE_EVENT_SYSCALL);
		if (IS_ERR(event))
			return;

		if (event->nr != nr_syscall)
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
	int nr_syscall = syscall_get_nr(current, regs);

	if (!is_scribed(scribe))
		return;

	if (is_scribe_syscall(nr_syscall))
		return;

	__scribe_allow_uaccess(scribe);

	if (!scribe->in_syscall) {
		/*
		 * Two cases:
		 * - The current process was freshly attached. This syscall
		 * doesn't count, we don't want a half recorded syscall.
		 * - should_scribe_syscalls() == 0
		 */
		return;
	}

	if (is_recording(scribe)) {
		event = scribe_alloc_event(SCRIBE_EVENT_SYSCALL);
		if (!event)
			goto bad;
		event->nr = nr_syscall;
		event->ret = syscall_get_return_value(current, regs);
		scribe_queue_event_at(&scribe->syscall_ip, event);
		scribe_commit_insert_point(&scribe->syscall_ip);

		if (scribe_queue_new_event(scribe->queue,
					   SCRIBE_EVENT_SYSCALL_END))
			goto bad;
	} else {
		scribe_dequeue_event_specific(scribe, SCRIBE_EVENT_SYSCALL_END);
		if (scribe->orig_ret != syscall_get_return_value(current, regs))
			scribe_emergency_stop(scribe->ctx, ERR_PTR(-EDIVERGE));
	}

	scribe->in_syscall = 0;
	return;

bad:
	scribe_emergency_stop(scribe->ctx, ERR_PTR(-ENOMEM));
}


asmlinkage long sys_get_scribe_flags(void)
{
	struct scribe_ps *scribe = current->scribe;
	if (!is_scribed(scribe))
		return -EPERM;

	return scribe->flags;
}

asmlinkage long sys_set_scribe_flags(int flags)
{
	struct scribe_ps *scribe = current->scribe;
	int old_flags;

	if (!is_scribed(scribe))
		return -EPERM;

	old_flags = scribe->flags;

	/* We allow only enable flags to be set */
	scribe->flags &= ~SCRIBE_PS_ENABLE_ALL;
	scribe->flags |= flags & SCRIBE_PS_ENABLE_ALL;

	return old_flags;
}
