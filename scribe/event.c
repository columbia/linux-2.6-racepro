/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/scribe.h>
#include <linux/sched.h>

static void init_substream(struct scribe_stream *stream,
			   struct scribe_substream *substream)
{
	substream->stream = stream;
	INIT_LIST_HEAD(&substream->events);
	INIT_LIST_HEAD(&substream->node);
}

void scribe_init_stream(struct scribe_stream *stream)
{
	spin_lock_init(&stream->lock);
	init_substream(stream, &stream->master);
	stream->wont_grow = 0;
	init_waitqueue_head(&stream->default_wait);
	stream->wait = &stream->default_wait;
}

static void init_queue(struct scribe_queue *queue,
		       struct scribe_context *ctx, pid_t pid)
{
	/*
	 * XXX the context reference is not taken: the caller should maintain
	 * that reference until that queue dies.
	 */
	scribe_init_stream(&queue->stream);
	atomic_set(&queue->ref_cnt, 1);
	queue->persistent = 0;
	queue->ctx = ctx;
	INIT_LIST_HEAD(&queue->node);
	queue->pid = pid;
	queue->fence_serial = 0;
}

static struct scribe_queue *find_queue(struct scribe_context *ctx, pid_t pid)
{
	struct scribe_queue *queue;

	list_for_each_entry(queue, &ctx->queues, node)
		if (queue->pid == pid)
			return queue;

	return NULL;
}

/*
 * scribe_get_queue_by_pid() never fails. The pre allocated queue is useful
 * for attach_process() to perform without failing.
 * When the pre allocated queue is used, its address is set NULL.
 */
struct scribe_queue *scribe_get_queue_by_pid(
				struct scribe_context *ctx,
				struct scribe_queue **pre_alloc_queue,
				pid_t pid)
{
	struct scribe_queue *queue;

	spin_lock(&ctx->queues_lock);
	queue = find_queue(ctx, pid);
	if (queue) {
		scribe_get_queue(queue);
		goto out;
	}

	queue = *pre_alloc_queue;
	*pre_alloc_queue = NULL;

	init_queue(queue, ctx, pid);
	if (ctx->queues_wont_grow)
		queue->stream.wont_grow = 1;

	/*
	 * Making the new queue persistent: We are keeping an internal
	 * reference to prevent the queue from being freed when the producer
	 * is done with the queue and the consumer is not available yet.
	 */
	scribe_set_persistent(queue);
	list_add_tail(&queue->node, &ctx->queues);
out:
	spin_unlock(&ctx->queues_lock);
	return queue;
}

void scribe_get_queue(struct scribe_queue *queue)
{
	atomic_inc(&queue->ref_cnt);
}

void scribe_put_queue(struct scribe_queue *queue)
{
	struct scribe_context *ctx = queue->ctx;

	if (atomic_dec_and_lock(&queue->ref_cnt, &ctx->queues_lock)) {
		list_del(&queue->node);
		spin_unlock(&ctx->queues_lock);
		scribe_free_all_events(&queue->stream);
		kfree(queue);
	}
}

void scribe_put_queue_locked(struct scribe_queue *queue)
{
	if (atomic_dec_and_test(&queue->ref_cnt)) {
		list_del(&queue->node);
		scribe_free_all_events(&queue->stream);
		kfree(queue);
	}
}

void scribe_set_persistent(struct scribe_queue *queue)
{
	assert_spin_locked(&queue->ctx->queues_lock);

	if (queue->persistent)
		return;

	queue->persistent = 1;
	scribe_get_queue(queue);
}
void scribe_unset_persistent(struct scribe_queue *queue)
{
	assert_spin_locked(&queue->ctx->queues_lock);

	if (!queue->persistent)
		return;

	queue->persistent = 0;
	scribe_put_queue_locked(queue);
}

void scribe_free_all_events(struct scribe_stream *stream)
{
	struct scribe_event *event, *tmp;

	spin_lock(&stream->lock);

	/* Some insert points are in progress... */
	BUG_ON(!list_empty(&stream->master.node));

	list_for_each_entry_safe(event, tmp, &stream->master.events, node) {
		list_del(&event->node);
		scribe_free_event(event);
	}

	spin_unlock(&stream->lock);
}

static void init_insert_point(scribe_insert_point_t *ip,
			      struct scribe_stream *stream,
			      struct scribe_substream *where)
{
	ip->stream = stream;
	INIT_LIST_HEAD(&ip->events);
	spin_lock(&stream->lock);
	list_add(&ip->node, &where->node);
	spin_unlock(&stream->lock);
}

void scribe_create_insert_point(scribe_insert_point_t *ip,
				struct scribe_stream *stream)
{
	init_insert_point(ip, stream, &stream->master);
}

/*
 * This is where the difference between an insert point and a substream lies.
 */
static struct scribe_substream *get_tail_substream(scribe_insert_point_t *ip)
{
	return list_entry(ip->node.next, typeof(*ip), node);
}
static struct scribe_substream *get_head_substream(scribe_insert_point_t *ip)
{
	return ip;
}

void scribe_commit_insert_point(scribe_insert_point_t *ip)
{
	struct scribe_stream *stream = ip->stream;
	struct scribe_substream *substream;

	spin_lock(&stream->lock);
	substream = get_tail_substream(ip);
	list_splice_tail(&ip->events, &substream->events);
	list_del(&ip->node);
	spin_unlock(&stream->lock);

	if (substream == &stream->master)
		wake_up(stream->wait);
}

static void commit_pending_insert_points(struct scribe_stream *stream)
{
	scribe_insert_point_t *ip, *tmp;

	list_for_each_entry_safe(ip, tmp, &stream->master.node, node)
		scribe_commit_insert_point(ip);
}

static inline void __scribe_queue_events_at(struct scribe_stream *stream,
					    scribe_insert_point_t *ip,
					    struct scribe_event *event,
					    struct list_head *events)
{
	struct scribe_substream *substream;

	spin_lock(&stream->lock);
	substream = get_tail_substream(ip);

	/*
	 * When queuing events, we want to put them in the next
	 * insert point event list because the current insert point is
	 * blocked by the insert point.
	 * when the next insert point is committed, those events will be
	 * merge into the current insert point with
	 * scribe_commit_insert_point().
	 */
	if (likely(event))
		list_add_tail(&event->node, &substream->events);
	if (events)
		list_splice_tail_init(events, &substream->events);
	spin_unlock(&stream->lock);

	if (substream == &stream->master)
		wake_up(stream->wait);
}

void scribe_queue_event_at(scribe_insert_point_t *ip, void *event)
{
	__scribe_queue_events_at(ip->stream, ip, event, NULL);
}

void scribe_queue_event_stream(struct scribe_stream *stream, void *event)
{
	__scribe_queue_events_at(stream, &stream->master, event, NULL);
}

void scribe_queue_event(struct scribe_queue *queue, void *event)
{
	scribe_queue_event_stream(&queue->stream, event);
}

void scribe_queue_events_stream(struct scribe_stream *stream,
				struct list_head *events)
{
	__scribe_queue_events_at(stream, &stream->master, NULL, events);
}

static struct scribe_event *__scribe_peek_event(struct scribe_stream *stream,
						int wait, int remove)
{
	scribe_insert_point_t *ip = &stream->master;
	struct scribe_substream *substream;
	struct scribe_event *event;

retry:
	if (wait == SCRIBE_WAIT_INTERRUPTIBLE &&
	    wait_event_interruptible(*stream->wait,
				     !scribe_is_stream_empty(stream) ||
				     stream->wont_grow))
		return ERR_PTR(-ERESTARTSYS);

	if (wait == SCRIBE_WAIT)
		wait_event(*stream->wait,
		       !scribe_is_stream_empty(stream) ||
		       stream->wont_grow);

	spin_lock(&stream->lock);
	substream = get_head_substream(ip);
	if (list_empty(&substream->events)) {
		spin_unlock(&stream->lock);
		/*
		 * If the queue will never grow, the queue is officially dead.
		 * There is no point waiting.
		 */
		if (stream->wont_grow)
			return ERR_PTR(-ENODATA);
		if (wait)
			goto retry;
		return ERR_PTR(-EAGAIN);
	}
	event = list_first_entry(&substream->events, typeof(*event), node);
	if (likely(remove))
		list_del(&event->node);
	spin_unlock(&stream->lock);

	return event;
}

struct scribe_event *scribe_dequeue_event(struct scribe_queue *queue, int wait)
{
	struct scribe_event *event;
	struct scribe_context *ctx = queue->ctx;

	event = __scribe_peek_event(&queue->stream, wait, 1);
	if (IS_ERR(event))
		return event;

	if (ctx->backtrace) {
		spin_lock(&ctx->backtrace_lock);
		if (ctx->backtrace)
			scribe_backtrace_add(ctx->backtrace, event);
		spin_unlock(&ctx->backtrace_lock);
	}

	return event;
}

struct scribe_event *scribe_dequeue_event_stream(struct scribe_stream *stream,
						 int wait)
{
	return __scribe_peek_event(stream, wait, 1);
}

/*
 * scribe_peek_event() returns the first event (like dequeue), but doesn't
 * remove it from the queue. If you want to consume the event, dequeue it.
 * XXX BE CAREFUL: do not free the event, do not access the event list node,
 * forbit another process dequeing the event while your are accessing that
 * event.
 */
struct scribe_event *scribe_peek_event(struct scribe_queue *queue, int wait)
{
	return __scribe_peek_event(&queue->stream, wait, 0);
}

int scribe_is_stream_empty(struct scribe_stream *stream)
{
	int ret;
	/* FIXME is the spinlock really necessary ? */
	spin_lock(&stream->lock);
	ret = list_empty(&stream->master.events);
	spin_unlock(&stream->lock);
	return ret;
}

void scribe_set_stream_wont_grow(struct scribe_stream *stream)
{
	commit_pending_insert_points(stream);
	stream->wont_grow = 1;
	wake_up(stream->wait);
}

void *__scribe_alloc_event(int type)
{
	return __scribe_alloc_event_const(type);
}

int scribe_enter_fenced_region(int region)
{
	struct scribe_ps *scribe = current->scribe;
	struct scribe_event_fence *event;
	int serial;
	int ret;

	if (!is_scribed(scribe))
		return 0;

	/*
	 * TODO This is a trivial and very inefficient implementation of fences.
	 * We record a serial number just for extra safety while we're at it.
	 */

	serial = scribe->queue->fence_serial++;

	if (is_recording(scribe)) {
		return scribe_queue_new_event(scribe->queue, SCRIBE_EVENT_FENCE,
					      .serial = serial);
	}
	/* is_replaying == true */
	event = scribe_dequeue_event_specific(scribe, SCRIBE_EVENT_FENCE);
	if (IS_ERR(event))
		return PTR_ERR(event);

	ret = 0;
	if (serial != event->serial) {
		scribe_diverge(scribe, SCRIBE_EVENT_DIVERGE_FENCE_SERIAL,
			       .serial = serial);
		ret = -EDIVERGE;
	}

	scribe_free_event(event);
	return ret;
}

void scribe_leave_fenced_region(int region)
{
}
