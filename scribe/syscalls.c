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

	if (!is_scribed(scribe))
		return;

	scribe->nr_syscall = syscall_get_nr(current, regs);
	if (is_scribe_syscall(scribe->nr_syscall))
		return;

	scribe_signal_sync_point(regs);

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

		if (event->nr != scribe->nr_syscall)
			scribe_emergency_stop(scribe->ctx, ERR_PTR(-EDIVERGE));

		scribe->orig_ret = event->ret;
		scribe_free_event(event);

		if (scribe->orig_ret == -EINTR ||
		    scribe->orig_ret == -ERESTARTNOHAND ||
		    scribe->orig_ret == -ERESTARTSYS ||
		    scribe->orig_ret == -ERESTARTNOINTR ||
		    scribe->orig_ret == -ERESTART_RESTARTBLOCK)
			set_thread_flag(TIF_SIGPENDING);

		/*
		 * FIXME Do something about non deterministic errors such as
		 * -ENOMEM. We need to process any events that the syscall
		 *  may have produced.
		 */
	}
	scribe->in_syscall = 1;
	scribe_data_push_flags(0);
}

void scribe_exit_syscall(struct pt_regs *regs)
{
	struct scribe_ps *scribe = current->scribe;
	struct scribe_event_syscall *event;
	struct scribe_event_syscall_end *event_end;
	long ret;

	if (!is_scribed(scribe))
		return;

	if (is_scribe_syscall(scribe->nr_syscall))
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
		event->nr = scribe->nr_syscall;
		event->ret = syscall_get_return_value(current, regs);

		scribe_queue_event_at(&scribe->syscall_ip, event);
		scribe_commit_insert_point(&scribe->syscall_ip);

		if (scribe_queue_new_event(scribe->queue,
					   SCRIBE_EVENT_SYSCALL_END))
			goto bad;
	} else {
		event_end = scribe_dequeue_event_specific(scribe,
						  SCRIBE_EVENT_SYSCALL_END);
		if (!IS_ERR(event_end))
			scribe_free_event(event_end);

		ret = syscall_get_return_value(current, regs);
		if (scribe->orig_ret != ret) {
			scribe_diverge(scribe, SCRIBE_EVENT_DIVERGE_SYSCALL_RET,
				       .ret = ret);
		}
	}

	scribe->in_syscall = 0;

	/*
	 * scribe_exit_syscall() can be called from do_exit, but in that case
	 * we must not trigger do_signal().
	 */
	if (likely(!(current->flags & PF_EXITING)))
		scribe_signal_sync_point(regs);
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

/*
 * Scribe enable flags are not inherited on fork().
 * The flags are also reset in scribe_detach().
 */
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
