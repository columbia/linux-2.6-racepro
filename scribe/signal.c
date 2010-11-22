/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/scribe.h>
#include <linux/signal.h>
#include <linux/sched.h>

static void scribe_do_signal(struct scribe_ps *scribe, struct pt_regs *regs)
{
	scribe_data_det();
	scribe->in_signal_sync_point = 1;
	while (test_thread_flag(TIF_SIGPENDING))
		do_signal(regs);
	scribe->in_signal_sync_point = 0;
}

/* XXX scribe_signal_sync_point() may call do_exit() */
void scribe_signal_sync_point(struct pt_regs *regs)
{
	struct scribe_event *event;
	struct scribe_event_signal *sig_event;
	struct scribe_ps *scribe = current->scribe;
	int ret;
	int got_signal = 0;

	if (!is_scribed(scribe) || !should_scribe_signals(scribe))
		return;

	if (is_recording(scribe)) {
		/*
		 * recalc_sigpending() because we reset the TIF_SIGPENDING
		 * flag in scribe_can_deliver_signal().
		 */
		recalc_sigpending();
		scribe_do_signal(scribe, regs);
		return;
	}

	/* Replay */
	for (;;) {
		event = scribe_peek_event(scribe->queue, SCRIBE_WAIT);
		if (IS_ERR(event) || event->type != SCRIBE_EVENT_SIGNAL)
			break;

		sig_event = scribe_dequeue_event_sized(
				scribe, SCRIBE_EVENT_SIGNAL, sizeof(siginfo_t));
		if (IS_ERR(sig_event))
			break;

		ret = force_sig_info(sig_event->nr,
				     (siginfo_t *)sig_event->info, current);
		scribe_free_event(sig_event);
		if (ret) {
			scribe_emergency_stop(scribe->ctx, ERR_PTR(ret));
			return;
		}
		got_signal = 1;
	}

	if (got_signal)
		scribe_do_signal(scribe, regs);
}

/* copy/pasted from kernel/signal.c */
#define SYNCHRONOUS_MASK \
	(sigmask(SIGSEGV) | sigmask(SIGBUS) | sigmask(SIGILL) | \
	 sigmask(SIGTRAP) | sigmask(SIGFPE))

static int no_sync_point_needed(struct scribe_ps *scribe)
{
	int ret;
	sigset_t mask;

	/*
	 * If the context state is set to SCRIBE_IDLE, it means that
	 * emergency_stop() got called, and we have a SIGKILL to process ASAP,
	 * synchronizing doesn't really matter here because something has
	 * already went wrong.
	 */
	if (unlikely(scribe->ctx->flags == SCRIBE_IDLE))
		return 1;

	/*
	 * Synchronous signals don't need a sync point by definition, and they
	 * are picked first before any other signals (so we are fine if other
	 * signals arrive between now and do_signal()).
	 */

	siginitset(&mask, ~SYNCHRONOUS_MASK);
	spin_lock_irq(&current->sighand->siglock);
	ret = next_signal(&current->pending, &mask);
	ret |= next_signal(&current->signal->shared_pending, &mask);
	spin_unlock_irq(&current->sighand->siglock);

	return ret;
}

int scribe_can_deliver_signal(void)
{
	struct scribe_ps *scribe = current->scribe;

	if (!is_recording(scribe) || !should_scribe_signals(scribe))
		return 1;

	/*
	 * Two options:
	 * - We are at a sync point, so we will be able to replay the signal
	 *   at the exact same location.
	 * - We don't care about being in a sync point because the signal to
	 *   get delivered will not need a sync point.
	 */
	if (scribe->in_signal_sync_point || no_sync_point_needed(scribe))
		return 1;

	/*
	 * We clear the TIF_SIGPENDING flag so that do_signal() gets called
	 * only on the next sync point.
	 */
	clear_thread_flag(TIF_SIGPENDING);
	return 0;
}

void scribe_delivering_signal(int signr, struct siginfo *info)
{
	struct scribe_ps *scribe = current->scribe;
	struct scribe_event_signal *event;

	if (!is_recording(scribe) || !should_scribe_signals(scribe))
		return;

	/*
	 * We cannot really fail gracefully here: sys_kill() cannot fail with
	 * a -ENOMEM, so even preallocation won't do it.
	 */

	event = scribe_alloc_event_sized(SCRIBE_EVENT_SIGNAL, sizeof(*info));
	if (!event) {
		scribe_emergency_stop(scribe->ctx, ERR_PTR(-ENOMEM));
		return;
	}

	/*
	 * FIXME Do like in copy_siginfo_to_user(), where only
	 * the relevent fields are copied because right now we are copying the
	 * padding and all, it contains non-initialized data...
	 */
	event->nr = signr;
	memcpy(event->info, info, sizeof(*info));
	scribe_queue_event(scribe->queue, event);
}
