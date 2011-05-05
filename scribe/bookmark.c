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
	spinlock_t		lock;
	int			id;
	int			npr;
	int			npr_total;
	bool			resume;
	wait_queue_head_t	wait;
	struct scribe_event_bookmark_reached *reached_event;
};

struct scribe_bookmark *scribe_bookmark_alloc(struct scribe_context *ctx)
{
	struct scribe_bookmark *bmark;

	bmark = kmalloc(sizeof(*bmark), GFP_KERNEL);
	if (!bmark)
		return NULL;

	bmark->ctx = ctx;
	spin_lock_init(&bmark->lock);
	bmark->id = 0;
	bmark->npr = 0;
	bmark->npr_total = 0;
	init_waitqueue_head(&bmark->wait);
	bmark->reached_event = NULL;

	return bmark;
}

void scribe_bookmark_free(struct scribe_bookmark *bmark)
{
	scribe_free_event(bmark->reached_event);
	kfree(bmark);
}

/*
 * returns -EAGAIN if some scribed task are not blocking in sync_on_bookmark
 * yet, otherwise return the number of processes waiting on the bookmark sync
 */
static int scribe_wait_all_sync(struct scribe_context *ctx)
{
	struct scribe_ps *scribe;
	int npr_waiting = 0;
	int npr = 0;
	int ret;

	spin_lock(&ctx->tasks_lock);
	list_for_each_entry(scribe, &ctx->tasks, node) {
		npr_waiting += scribe->bmark_waiting;
		npr++;
	}
	if (npr != npr_waiting) {
		scribe_wake_all_fake_sig(ctx);
		ret = -EAGAIN;
	} else
		ret = npr;
	spin_unlock(&ctx->tasks_lock);

	return ret;
}

static int prealloc_reached_event(struct scribe_bookmark *bmark)
{
	struct scribe_event_bookmark_reached *reached_event;

	if (bmark->reached_event)
		return 0;

	reached_event = scribe_alloc_event(SCRIBE_EVENT_BOOKMARK_REACHED);
	if (!reached_event)
		return -ENOMEM;

	spin_lock(&bmark->lock);
	if (bmark->reached_event)
		scribe_free_event(reached_event);
	else
		bmark->reached_event = reached_event;
	spin_unlock(&bmark->lock);

	return 0;
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

	if (prealloc_reached_event(bmark) < 0)
		return -ENOMEM;

	/*
	 * Tasks will start blocking in scribe_bookmark_point_record() because
	 * of NPR_PENDING.
	 */
	bmark->npr_total = NPR_PENDING;

	/*
	 * We need to wait on tasks_wait because tasks can die in do_exit()
	 * and we want to be woken up in that case.
	 */
	wait_event(ctx->tasks_wait,
		   (npr = scribe_wait_all_sync(ctx)) != -EAGAIN);

	/*
	 * All tasks are now blocking in scribe_bookmark_point_record() and
	 * npr is the number of task. The tasks will write npr in their
	 * bookmark event.
	 */
	bmark->npr_total = npr;
	wake_up(&bmark->wait);

	return 0;
}

static void sync_on_bookmark(struct scribe_bookmark *bmark)
{
	struct scribe_event_bookmark_reached *reached_event = NULL;

	spin_lock(&bmark->lock);
	if (!bmark->npr) {
		bmark->npr = bmark->npr_total;
		bmark->resume = false;
	}
	if (!--bmark->npr) {
		/*
		 * Only the last thread gets to send the notification so that
		 * we guarentee that all tasks are paused when userspace gets
		 * the notification
		 */
		reached_event = bmark->reached_event;
		bmark->reached_event = NULL;
	}
	spin_unlock(&bmark->lock);

	if (reached_event) {
		reached_event->id = bmark->id;
		reached_event->npr = bmark->npr_total;
		scribe_queue_event_stream(&bmark->ctx->notifications,
					  reached_event);
	}

	wait_event(bmark->wait, bmark->resume ||
				is_scribe_context_dead(bmark->ctx));

	/*
	 * We want to keep npr_total non-zero until all tasks passed the
	 * bookmark to make sure scribe_bookmark_request sleep.
	 * It also ensure that scribe_bookmark_resume() operate on the right
	 * bookmark.
	 */

	spin_lock(&bmark->lock);
	if (!--bmark->npr_total) {
		bmark->id++;
		wake_up(&bmark->wait);
	}
	spin_unlock(&bmark->lock);
}

void scribe_bookmark_point_record(struct scribe_ps *scribe,
				  struct scribe_bookmark *bmark,
				  unsigned int type)
{
	int ret;

	if (bmark->npr_total != NPR_PENDING)
		return;

	scribe->bmark_waiting = 1;
	wake_up(&bmark->ctx->tasks_wait);
	wait_event(bmark->wait, bmark->npr_total > 0);
	scribe->bmark_waiting = 0;

	ret = scribe_queue_new_event(scribe->queue,
				     SCRIBE_EVENT_BOOKMARK,
				     .type = type,
				     .id = bmark->id, .npr = bmark->npr_total);
	if (ret < 0)
		scribe_kill(scribe->ctx, ret);

	sync_on_bookmark(bmark);
}

void scribe_bookmark_point_replay(struct scribe_ps *scribe,
				  struct scribe_bookmark *bmark,
				  unsigned int type)
{
	struct scribe_event *generic_event;
	struct scribe_event_bookmark *event;
	int npr, id;

	while (1) {
		generic_event = scribe_peek_event(scribe->queue, SCRIBE_WAIT);
		if (IS_ERR(generic_event))
			return;

		if (generic_event->type != SCRIBE_EVENT_BOOKMARK)
			return;

		event = (void*)generic_event;
		if (event->type != type)
			return;

		event = scribe_dequeue_event_specific(scribe,
						      SCRIBE_EVENT_BOOKMARK);

		id = event->id;
		npr = event->npr;
		scribe_free_event(event);

		wait_event(bmark->wait, bmark->id == id ||
					is_scribe_context_dead(bmark->ctx));
		if (is_scribe_context_dead(bmark->ctx))
			return;

		if (prealloc_reached_event(bmark) < 0) {
			scribe_kill(scribe->ctx, -ENOMEM);
			return;
		}

		bmark->npr_total = npr;
		sync_on_bookmark(bmark);
	}
}

void scribe_bookmark_point(unsigned int type)
{
	struct scribe_ps *scribe = current->scribe;
	struct scribe_bookmark *bmark;

	if (!is_scribed(scribe))
		return;

	bmark = scribe->ctx->bmark;

	if (is_recording(scribe))
		scribe_bookmark_point_record(scribe, bmark, type);
	else
		scribe_bookmark_point_replay(scribe, bmark, type);
}

int scribe_bookmark_resume(struct scribe_bookmark *bmark)
{
	if (bmark->npr || !bmark->npr_total)
		return -EPERM;

	bmark->resume = true;
	wake_up(&bmark->wait);
	return 0;
}
