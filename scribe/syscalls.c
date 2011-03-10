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
#include <linux/net.h>
#include <linux/futex.h>
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
		if (scribe_queue_new_event(scribe->queue, SCRIBE_EVENT_REGS,
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

static void do_inject_msleep(struct scribe_event_inject_action *event)
{
	long arg = (long) event->arg1;

	printk("[%d] msleep for %ld\n", task_pid_vnr(current), arg);
	msleep_interruptible(event->arg1);
}

static int do_inject_psflags(struct scribe_event_inject_action *event)
{
	long add = (long) event->arg1;
	long del = (long) event->arg2;
	long flags;

	printk("[%d] psflags add %#lx del %#lx\n",
	       task_pid_vnr(current), add, del);

	flags = sys_get_scribe_flags();
	flags = (flags & ~del) | add;
	return sys_set_scribe_flags(flags);
}
static int do_inject_action(struct scribe_event_inject_action *event)
{
	int ret = 0;

	switch (event->action) {
	case SCRIBE_INJECT_ACTION_SLEEP:
		do_inject_msleep(event);
		break;
	case SCRIBE_INJECT_ACTION_PSFLAGS:
		ret = do_inject_psflags(event);
		break;
	default:
		printk("[%d] unknown action %d\n",
		       task_pid_vnr(current), event->action);
	}
	return ret;
}

static int scribe_inject_action(struct scribe_ps *scribe)
{
	struct scribe_event *event;
	struct scribe_event_inject_action *event_inject;
	int ret;

	if (!is_replaying(scribe))
		return 0;

	if (!should_scribe_syscalls(scribe))
		return 0;

	/* execute pending inject_action events, if any */

	while (1) {
		event = scribe_peek_event(scribe->queue, SCRIBE_WAIT);
		if (IS_ERR(event) || event->type != SCRIBE_EVENT_INJECT_ACTION)
			break;
		event_inject = scribe_dequeue_event_specific(
				     scribe, SCRIBE_EVENT_INJECT_ACTION);
		if (IS_ERR(event_inject))
			return PTR_ERR(event);

		ret = do_inject_action(event_inject);

		scribe_free_event(event_inject);

		if (ret < 0) {
			/*
			 * There is no reason to abort the replay if the
			 * injected syscall failed.
			 */
			WARN(1, "Injected action failed with %d\n", ret);
		}
	}

	return 0;
}

static inline int is_scribe_syscall(int nr)
{
	return nr == __NR_get_scribe_flags ||
	       nr == __NR_set_scribe_flags;
}

static int scribe_need_syscall_ret_record(struct scribe_ps *scribe)
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
	return 0;
}

static int scribe_need_syscall_ret_replay(struct scribe_ps *scribe)
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
		return PTR_ERR(event.generic);

	if (syscall_extra) {
		if (event.extra->nr != scribe->nr_syscall) {
			scribe_diverge(scribe, SCRIBE_EVENT_DIVERGE_SYSCALL,
				       .nr = scribe->nr_syscall);
		}
		scribe->orig_ret = event.extra->ret;
	} else
		scribe->orig_ret = event.regular->ret;

	scribe_free_event(event.generic);

	/*
	 * FIXME Do something about non deterministic errors such as
	 * -ENOMEM.
	 */
	return 0;
}

static int __scribe_need_syscall_ret(struct scribe_ps *scribe)
{
	scribe->need_syscall_ret = true;

	if (is_recording(scribe))
		return scribe_need_syscall_ret_record(scribe);
	else
		return scribe_need_syscall_ret_replay(scribe);
}

int scribe_need_syscall_ret(struct scribe_ps *scribe)
{
	if (!is_scribed(scribe))
		return 0;

	if (!should_scribe_syscalls(scribe))
		return 0;

	if (scribe->need_syscall_ret)
		return 0;

	return __scribe_need_syscall_ret(scribe);
}

static bool is_interruptible_syscall(int nr_syscall)
{
	/*
	 * FIXME Only do that for interruptible system calls (with
	 * nr_syscall).
	 */
	return true;
}

static int get_nr_syscall(struct pt_regs *regs)
{
	unsigned long call;
	int nr;

	nr = syscall_get_nr(current, regs);
	if (nr == __NR_socketcall) {
		syscall_get_arguments(current, regs, 0, 1, &call);
		if (call < 1 || call > SYS_RECVMMSG)
			return nr;

		return SCRIBE_SOCKETCALL_BASE + call;
	}
	if (nr == __NR_futex) {
		syscall_get_arguments(current, regs, 1, 1, &call);
		call &= FUTEX_CMD_MASK;
		if (call > FUTEX_CMP_REQUEUE_PI)
			return nr;

		return SCRIBE_FUTEX_BASE + call;
	}

	return nr;
}

void scribe_enter_syscall(struct pt_regs *regs)
{
	struct scribe_ps *scribe = current->scribe;
	int num_sig_deferred;

	if (!is_scribed(scribe))
		return;

	scribe->nr_syscall = get_nr_syscall(regs);
	if (is_scribe_syscall(scribe->nr_syscall))
		return;

	if (should_scribe_syscalls(scribe) &&
	    should_scribe_regs(scribe) &&
	    scribe_regs(scribe, regs))
		return;

	/* It should already be set to false, but let's be sure */
	scribe->need_syscall_ret = false;

	scribe_data_det();

	scribe_signal_enter_sync_point(&num_sig_deferred);
	if (num_sig_deferred > 0) {
		/* TODO We could go back to userspace to reduce latency */
	}

	__scribe_forbid_uaccess(scribe);

	scribe_bookmark_point();

	/* execute pending injects */
	if (scribe_inject_action(scribe) < 0)
		return;

	if (scribe_maybe_detach(scribe))
		return;

	/* FIXME signals needs the return value */
	if (!should_scribe_syscalls(scribe))
		return;

	if (should_scribe_syscall_ret(scribe) ||
	    is_interruptible_syscall(scribe->nr_syscall))
		__scribe_need_syscall_ret(scribe);

	recalc_sigpending();
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

	if (scribe->orig_ret != ret_value) {
		scribe_diverge(scribe, SCRIBE_EVENT_DIVERGE_SYSCALL_RET,
			       .ret = ret_value);
	}
}

void scribe_commit_syscall(struct scribe_ps *scribe, struct pt_regs *regs,
			   long ret_value)
{
	if (!scribe->need_syscall_ret)
		return;

	scribe->need_syscall_ret = false;

	if (is_recording(scribe))
		scribe_commit_syscall_record(scribe, regs, ret_value);
	else
		scribe_commit_syscall_replay(scribe, regs, ret_value);
}

void scribe_exit_syscall(struct pt_regs *regs)
{
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return;

	if (is_scribe_syscall(scribe->nr_syscall))
		return;

	scribe_commit_syscall(scribe, regs,
			      syscall_get_return_value(current, regs));

	scribe_bookmark_point();

	if (scribe_maybe_detach(scribe))
		return;

	__scribe_allow_uaccess(scribe);
	scribe_signal_leave_sync_point();

	/*
	 * During the replay, the sigpending flag was cleared to not disturb
	 * the syscall. Now we want do_signal() to be called if needed.
	 * Note: If the syscall was interrupted with a fake signal,
	 * we are not clearing the sigpending flag either.
	 */
	recalc_sigpending_and_wake(current);

	if (unlikely(!scribe->can_uaccess))
		scribe_emergency_stop(scribe->ctx, ERR_PTR(-EINVAL));
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

	scribe_mem_reload(scribe);

	return old_flags;
}
