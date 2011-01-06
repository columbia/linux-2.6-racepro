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

union scribe_syscall_event_union {
	struct scribe_event *generic;
	struct scribe_event_syscall *regular;
	struct scribe_event_syscall_extra *extra;
};

static int scribe_regs(struct scribe_ps *scribe, struct pt_regs *regs)
{
	struct scribe_event_regs *event_regs;
	int ret;

	if (is_recording(scribe)) {
		if (scribe_queue_new_event(scribe->queue,
				       SCRIBE_EVENT_REGS,
				       .regs = *regs)) {
			scribe_emergency_stop(scribe->ctx, ERR_PTR(-ENOMEM));
			return -ENOMEM;
		}
	} else {
		event_regs = scribe_dequeue_event_specific(scribe,
						SCRIBE_EVENT_REGS);
		if (IS_ERR(event_regs))
			return PTR_ERR(event_regs);

		ret = memcmp(regs, &event_regs->regs, sizeof(*regs));
		scribe_free_event(event_regs);

		if (ret) {
			scribe_diverge(scribe, SCRIBE_EVENT_DIVERGE_REGS,
				       .regs = *regs);
			return -EDIVERGE;
		}
	}

	return 0;
}

static inline int is_scribe_syscall(int nr)
{
	return nr == __NR_get_scribe_flags ||
	       nr == __NR_set_scribe_flags;
}

static void scribe_enter_syscall_record(struct scribe_ps *scribe)
{
	/*
	 * We'll postpone the insertion of the syscall event for the
	 * return value.
	 *
	 * XXX This is potentially dangerous in the sense that the
	 * userspace can make the kernel allocate many events during
	 * the syscall, which won't get flushed to the logfile until
	 * the syscall returns.
	 */
	scribe_create_insert_point(&scribe->syscall_ip, &scribe->queue->stream);
}

static void scribe_enter_syscall_replay(struct scribe_ps *scribe)
{
	union scribe_syscall_event_union event;
	int syscall_extra = should_scribe_syscall_extra(scribe);

	if (syscall_extra)
		event.extra = scribe_dequeue_event_specific(scribe,
				      SCRIBE_EVENT_SYSCALL_EXTRA);
	else 
		event.regular = scribe_dequeue_event_specific(scribe,
				      SCRIBE_EVENT_SYSCALL);

	if (IS_ERR(event.generic))
		return;

	if (syscall_extra) {
		if (event.extra->nr != scribe->nr_syscall) {
			scribe_diverge(scribe,
				       SCRIBE_EVENT_DIVERGE_SYSCALL,
				       .nr = scribe->nr_syscall);
		}
		scribe->orig_ret = event.extra->ret;
	} else
		scribe->orig_ret = event.regular->ret;

	scribe_free_event(event.generic);

	if (is_interruption(scribe->orig_ret))
		set_thread_flag(TIF_SIGPENDING);

	/*
	 * FIXME Do something about non deterministic errors such as
	 * -ENOMEM.
	 */
}

void scribe_enter_syscall(struct pt_regs *regs)
{
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return;

	scribe->nr_syscall = syscall_get_nr(current, regs);
	if (is_scribe_syscall(scribe->nr_syscall))
		return;

	if (should_scribe_syscalls(scribe) &&
	    should_scribe_regs(scribe) &&
	    scribe_regs(scribe, regs))
		return;

	scribe_data_det();

	while (scribe_signal_enter_sync_point()) {
		recalc_sigpending();
		if (signal_pending(current))
			do_signal(regs);
	}

	__scribe_forbid_uaccess(scribe);

	scribe_bookmark_point();

	if (scribe_maybe_detach(scribe))
		return;

	if (!should_scribe_syscalls(scribe))
		return;

	if (is_recording(scribe)) {
		scribe_enter_syscall_record(scribe);
	} else
		scribe_enter_syscall_replay(scribe);

	scribe->in_syscall = 1;
}

static void scribe_commit_syscall_record(struct scribe_ps *scribe,
					 struct pt_regs *regs, long ret_value)
{
	union scribe_syscall_event_union event;
	int syscall_extra = should_scribe_syscall_extra(scribe);

	if (syscall_extra)
		event.extra = scribe_alloc_event(SCRIBE_EVENT_SYSCALL_EXTRA);
	else
		event.regular = scribe_alloc_event(SCRIBE_EVENT_SYSCALL);

	if (!event.generic)
		goto err;

	if (syscall_extra) {
		event.extra->nr = scribe->nr_syscall;
		event.extra->ret = ret_value;
	} else
		event.regular->ret = ret_value;

	scribe_queue_event_at(&scribe->syscall_ip, event.generic);
	scribe_commit_insert_point(&scribe->syscall_ip);

	if (syscall_extra) {
		if (scribe_queue_new_event(scribe->queue,
				   SCRIBE_EVENT_SYSCALL_END))
			goto err;
	}

	return;
err:
	scribe_emergency_stop(scribe->ctx, ERR_PTR(-ENOMEM));
}

static void scribe_commit_syscall_replay(struct scribe_ps *scribe,
					 struct pt_regs *regs, long ret_value)
{
	struct scribe_event_syscall_end *event_end;
	int syscall_extra = should_scribe_syscall_extra(scribe);

	if (syscall_extra) {
		event_end = scribe_dequeue_event_specific(scribe,
						SCRIBE_EVENT_SYSCALL_END);
		if (!IS_ERR(event_end))
			scribe_free_event(event_end);
	}

	if (is_interruption(scribe->orig_ret)) {
		syscall_set_return_value(scribe->p, regs,
					 scribe->orig_ret, 0);
	} else if (scribe->orig_ret != ret_value) {
		scribe_diverge(scribe, SCRIBE_EVENT_DIVERGE_SYSCALL_RET,
			       .ret = ret_value);
	}
}

void scribe_commit_syscall(struct scribe_ps *scribe, struct pt_regs *regs,
			   long ret_value)
{
	if (is_recording(scribe))
		scribe_commit_syscall_record(scribe, regs, ret_value);
	else
		scribe_commit_syscall_replay(scribe, regs, ret_value);
	scribe->in_syscall = 0;
}

void scribe_exit_syscall(struct pt_regs *regs)
{
	long ret_value = 0;
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return;

	if (is_scribe_syscall(scribe->nr_syscall))
		return;

	if (scribe->in_syscall) {
		ret_value = syscall_get_return_value(current, regs);
		scribe_commit_syscall(scribe, regs, ret_value);
	}

	__scribe_allow_uaccess(scribe);
	scribe_signal_leave_sync_point();

	/*
	 * In case we have a fake signal to handle, we want do_signal() to be
	 * called.
	 */
	if (is_interruption(ret_value))
		set_thread_flag(TIF_SIGPENDING);
}

SYSCALL_DEFINE0(get_scribe_flags)
{
	struct scribe_ps *scribe = current->scribe;
	if (!is_scribed(scribe))
		return -EPERM;

	return scribe->flags;
}

SYSCALL_DEFINE1(set_scribe_flags, int, flags)
{
	struct scribe_ps *scribe = current->scribe;
	int old_flags;

	if (!is_scribed(scribe))
		return -EPERM;

	old_flags = scribe->flags;

	/* We allow only enable flags to be set */
	scribe->flags &= ~SCRIBE_PS_ENABLE_ALL;
	scribe->flags |= flags & SCRIBE_PS_ENABLE_ALL;

	/* FIXME switch the pgd to the real page table if needed */

	return old_flags;
}
