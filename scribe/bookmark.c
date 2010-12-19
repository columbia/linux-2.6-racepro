/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/scribe.h>
#include <linux/time.h>
#include <linux/wait.h>
#include <linux/sched.h>

#define NPR_PENDING -1

struct scribe_bookmark {
	struct scribe_context	*ctx;
	struct timeval		time_start;
	spinlock_t		lock;
	int			id;
	int			npr;
	int			npr_total;
	wait_queue_head_t	wait;
	wait_queue_head_t	ctx_wait;
	int			golive_id;
	int			golive_latch;
};

struct scribe_bookmark *scribe_bookmark_alloc(struct scribe_context *ctx)
{
	struct scribe_bookmark *bmark;

	bmark = kmalloc(sizeof(*bmark), GFP_KERNEL);
	if (!bmark)
		return NULL;

	bmark->ctx = ctx;
	init_waitqueue_head(&bmark->wait);
	init_waitqueue_head(&bmark->ctx_wait);
	spin_lock_init(&bmark->lock);
	bmark->npr = 0;
	bmark->npr_total = 0;
	bmark->golive_id = -1;
	bmark->golive_latch = 0;

	scribe_bookmark_reset(bmark);
	return bmark;
}

void scribe_bookmark_free(struct scribe_bookmark *bmark)
{
	kfree(bmark);
}

void scribe_bookmark_reset(struct scribe_bookmark *bmark)
{
	bmark->id = 0;
	do_gettimeofday(&bmark->time_start);
}

/*
 * returns -EAGAIN if some scribed task are still waiting
 * otherwise return the number of processes waiting on the bookmark sync
 */
static int scribe_wait_all_sync(struct scribe_context *ctx)
{
	struct scribe_ps *scribe;
	int npr_waiting = 0;
	int npr = 0;

	spin_lock(&ctx->tasks_lock);
	list_for_each_entry(scribe, &ctx->tasks, node) {
		if (!(scribe->p->flags & PF_EXITING)) {
			npr_waiting += scribe->bmark_waiting;
			npr++;
		}
	}
	scribe_wake_all_fake_sig(ctx);
	spin_unlock(&ctx->tasks_lock);

	return npr != npr_waiting ? -EAGAIN : npr;
}

int scribe_bookmark_request(struct scribe_bookmark *bmark)
{
	struct scribe_context *ctx = bmark->ctx;
	int npr;

	if (!(ctx->flags & SCRIBE_RECORD))
		return -EPERM;

	/* first we have to wait if there is a pending bookmark sync ... */
	if (wait_event_interruptible(bmark->wait, !bmark->npr_total))
		return -ERESTARTSYS;

	spin_lock(&bmark->lock);
	bmark->npr_total = NPR_PENDING;
	spin_unlock(&bmark->lock);

	wait_event(bmark->ctx_wait,
		   (npr = scribe_wait_all_sync(ctx)) != -EAGAIN);

	spin_lock(&bmark->lock);
	bmark->npr_total = npr;
	spin_unlock(&bmark->lock);

	wake_up(&bmark->wait); /* will wakeup anyone waiting on NPR_PENDING */

	return 0;

}

static inline int bookmark_is_wait_over(struct scribe_bookmark *bmark, int id)
{
	if (bmark->golive_latch)
		return 0;

	if (bmark->ctx->flags == SCRIBE_IDLE)
		return 1;

	return bmark->npr == 0 || bmark->id != id;
}

static void sync_on_bookmark(struct scribe_ps *scribe,
			     struct scribe_bookmark *bmark, int *id, int *npr)
{
	int no_wait = 0;

	/*
	 * current task arrives on a bookmark point:
	 * - if we are not the last task to arrive on the bookmark, we have to
	 *   wait for all the tasks.
	 * - if we are the last task, we should wait everybody up, the wait is
	 * over.
	 */

	if (is_recording(scribe)) {
		scribe->bmark_waiting = 1;
		wake_up(&bmark->ctx_wait);
		wait_event(bmark->wait, bmark->npr_total > 0);
		scribe->bmark_waiting = 0;
	} else {
		/* First we have to wait for the right bookmark... */
		BUG_ON(bmark->id > *id);
		wait_event(bmark->wait, bmark->id == *id ||
					bmark->ctx->flags == SCRIBE_IDLE);
		if (bmark->ctx->flags == SCRIBE_IDLE)
			return;
	}

	spin_lock(&bmark->lock);

	*id = bmark->id;

	if (!bmark->npr_total) {
		BUG_ON(*npr == -1);
		bmark->npr_total = *npr;
	} else
		*npr = bmark->npr_total;

	if (!bmark->npr)
		bmark->npr = bmark->npr_total;
	if (!--bmark->npr) {
		if (bmark->id == bmark->golive_id) {
			bmark->golive_latch = 1;
			smp_wmb();
		}
		bmark->id++;
		bmark->npr_total = 0;
		no_wait = 1;
	}
	BUG_ON(bmark->npr < 0);

	spin_unlock(&bmark->lock);

	if (no_wait) {
		if (bmark->golive_latch) {
			scribe_stop(scribe->ctx);
			bmark->golive_latch = 0;
		}

		wake_up(&bmark->wait);
	} else
		wait_event(bmark->wait, bookmark_is_wait_over(bmark, *id));
}

void scribe_bookmark_point(void)
{
	struct scribe_ps *scribe = current->scribe;
	struct scribe_event *generic_event;
	struct scribe_event_bookmark *event;
	struct scribe_bookmark *bmark;
	int npr, id;
	int ret;

	if (!is_scribed(scribe))
		return;

	bmark = scribe->ctx->bmark;

	if (is_recording(scribe)) {
		if (!bmark->npr_total)
			return;

		sync_on_bookmark(scribe, bmark, &id, &npr);

		ret = scribe_queue_new_event(scribe->queue,
					     SCRIBE_EVENT_BOOKMARK,
					     .id = id, .npr = npr);
		if (ret)
			scribe_emergency_stop(scribe->ctx, ERR_PTR(ret));

	} else {
		generic_event = scribe_peek_event(scribe->queue, SCRIBE_WAIT);
		if (IS_ERR(generic_event))
			return;

		if (generic_event->type != SCRIBE_EVENT_BOOKMARK)
			return;

		event = scribe_dequeue_event_specific(scribe,
						      SCRIBE_EVENT_BOOKMARK);

		id = event->id;
		npr = event->npr;
		scribe_free_event(event);
		sync_on_bookmark(scribe, bmark, &id, &npr);
	}

}

static int scribe_golive_on_bookmark(struct scribe_bookmark *bmark,
				     int id, int next)
{
	struct scribe_context *ctx = bmark->ctx;

	if (!(ctx->flags & SCRIBE_REPLAY))
		return -EPERM;

	spin_lock(&bmark->lock);
	if (next)
		bmark->golive_id = bmark->id;
	else
		bmark->golive_id = id;
	spin_unlock(&bmark->lock);

	return 0;
}

int scribe_golive_on_bookmark_id(struct scribe_bookmark *bmark, int id)
{
	if (bmark->id > id)
		return -EINVAL;
	return scribe_golive_on_bookmark(bmark, id, 0);
}

int scribe_golive_on_next_bookmark(struct scribe_bookmark *bmark)
{
	return scribe_golive_on_bookmark(bmark, 0, 1);
}
