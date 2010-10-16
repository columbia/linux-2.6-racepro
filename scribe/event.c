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

static void init_insert_point(struct scribe_event_queue *queue,
			      struct scribe_insert_point *ip)
{
	ip->queue = queue;
	INIT_LIST_HEAD(&ip->events);
}

struct scribe_event_queue *scribe_alloc_event_queue(void)
{
	struct scribe_event_queue *queue;

	queue = kmalloc(sizeof(*queue), GFP_KERNEL);
	if (!queue)
		return NULL;

	atomic_set(&queue->ref_cnt, 1);
	queue->ctx = NULL;
	INIT_LIST_HEAD(&queue->node);
	queue->pid = 0;
	queue->flags = 0;

	spin_lock_init(&queue->lock);
	init_insert_point(queue, &queue->master);
	INIT_LIST_HEAD(&queue->master.node);

	init_waitqueue_head(&queue->default_wait);
	queue->wait = &queue->default_wait;

	return queue;
}

static void scribe_free_event_queue(struct scribe_event_queue *queue)
{
	scribe_free_all_events(queue);
	kfree(queue);
}

static struct scribe_event_queue *find_queue(struct scribe_context *ctx,
					     pid_t pid)
{
	struct scribe_event_queue *queue;

	list_for_each_entry(queue, &ctx->queues, node)
		if (queue->pid == pid)
			return queue;

	return NULL;
}

/*
 * scribe_get_queue_by_pid() never fails. The pre allocated queue is useful
 * for attach_process() to perform without failing.
 * When the pre allocated queue is used, it's address is set NULL.
 */
struct scribe_event_queue *scribe_get_queue_by_pid(
				struct scribe_context *ctx,
				struct scribe_event_queue **pre_alloc_queue,
				pid_t pid)
{
	struct scribe_event_queue *queue;

	spin_lock(&ctx->queues_lock);
	queue = find_queue(ctx, pid);
	if (queue) {
		scribe_get_queue(queue);
		goto out;
	}

	queue = *pre_alloc_queue;
	*pre_alloc_queue = NULL;

	queue->ctx = ctx;
	queue->pid = pid;

	/*
	 * Making the new queue persistent: the queue reader hasn't
	 * taken a reference on the queue yet. This is his reference.
	 */
	scribe_make_persistent(queue, 1);

	list_add(&queue->node, &ctx->queues);

out:
	spin_unlock(&ctx->queues_lock);
	return queue;
}

void scribe_get_queue(struct scribe_event_queue *queue)
{
	atomic_inc(&queue->ref_cnt);
}

void scribe_put_queue(struct scribe_event_queue *queue)
{
	struct scribe_context *ctx = queue->ctx;

	if (unlikely(!ctx)) {
		/* The queue is not attached in the context queues list */
		scribe_put_queue_nolock(queue);
		return;
	}

	if (atomic_dec_and_lock(&queue->ref_cnt, &ctx->queues_lock)) {
		list_del(&queue->node);
		spin_unlock(&ctx->queues_lock);
		scribe_free_event_queue(queue);
	}
}

void scribe_put_queue_nolock(struct scribe_event_queue *queue)
{
	if (atomic_dec_and_test(&queue->ref_cnt)) {
		list_del(&queue->node);
		scribe_free_event_queue(queue);
	}
}

void scribe_make_persistent(struct scribe_event_queue *queue, int enable)
{
	assert_spin_locked(&queue->ctx->queues_lock);

	if (enable && !(queue->flags & SCRIBE_PERSISTENT)) {
		queue->flags |= SCRIBE_PERSISTENT;
		scribe_get_queue(queue);
	}
	if (!enable && (queue->flags & SCRIBE_PERSISTENT)) {
		queue->flags &= ~SCRIBE_PERSISTENT;
		scribe_put_queue_nolock(queue);
	}
}

void scribe_free_all_events(struct scribe_event_queue *queue)
{
	struct scribe_event *event, *tmp;

	spin_lock(&queue->lock);

	/* Some insert points are in progress... */
	BUG_ON(!list_empty(&queue->master.node));

	list_for_each_entry_safe(event, tmp, &queue->master.events, node) {
		list_del(&event->node);
		scribe_free_event(event);
	}

	spin_unlock(&queue->lock);
}

static inline
struct scribe_insert_point *get_next_ip(struct scribe_insert_point *ip)
{
	return list_entry(ip->node.next, typeof(*ip), node);
}

void scribe_create_insert_point(struct scribe_event_queue *queue,
				struct scribe_insert_point *ip)

{
	struct scribe_insert_point *where = &queue->master;

	init_insert_point(queue, ip);

	spin_lock(&queue->lock);
	list_add(&ip->node, &where->node);
	spin_unlock(&queue->lock);
}

void scribe_commit_insert_point(struct scribe_insert_point *ip)
{
	struct scribe_event_queue *queue = ip->queue;
	struct scribe_insert_point *next_ip = get_next_ip(ip);

	spin_lock(&queue->lock);
	list_splice_tail(&ip->events, &next_ip->events);
	list_del_init(&ip->node);
	spin_unlock(&queue->lock);

	if (next_ip == &queue->master)
		wake_up(queue->wait);
}

static void commit_pending_insert_points(struct scribe_event_queue *queue)
{
	struct scribe_insert_point *ip, *tmp;

	list_for_each_entry_safe(ip, tmp, &queue->master.node, node)
		scribe_commit_insert_point(ip);
}

static inline void __scribe_queue_event_at(struct scribe_event_queue *queue,
					   struct scribe_insert_point *where,
					   void *_event)
{
	struct scribe_event *event = (struct scribe_event *)_event;
	struct scribe_insert_point *next_ip = get_next_ip(where);

	spin_lock(&queue->lock);
	/*
	 * When queuing events, we want to put them in the next
	 * insert point event list because the current insert point is
	 * blocked by the insert point.
	 * When the next insert point is committed, those events will be
	 * merge into the current insert point with
	 * scribe_commit_insert_point().
	 */
	list_add_tail(&event->node, &next_ip->events);
	spin_unlock(&queue->lock);

	if (next_ip == &queue->master)
		wake_up(queue->wait);
}

void scribe_queue_event_at(struct scribe_insert_point *where, void *event)
{
	__scribe_queue_event_at(where->queue, where, event);
}

void scribe_queue_event(struct scribe_event_queue *queue, void *event)
{
	__scribe_queue_event_at(queue, &queue->master, event);
}

static struct scribe_event *__scribe_peek_event(
		struct scribe_event_queue *queue, int wait, int remove)
{
	struct scribe_event *event;
	struct list_head *events;

	/*
	 * When deqeuing events, we grab them from the current insert point,
	 * not the next one.
	 */
	events = &queue->master.events;

retry:
	if (wait == SCRIBE_WAIT_INTERRUPTIBLE &&
	    wait_event_interruptible(*queue->wait,
				     !scribe_is_queue_empty(queue) ||
				     (queue->flags & SCRIBE_WONT_GROW)))
		return ERR_PTR(-ERESTARTSYS);

	if (wait == SCRIBE_WAIT)
		wait_event(*queue->wait,
		       !scribe_is_queue_empty(queue) ||
		       (queue->flags & SCRIBE_WONT_GROW));

	spin_lock(&queue->lock);
	if (list_empty(events)) {
		spin_unlock(&queue->lock);
		/*
		 * If the queue will never grow, the queue is officially dead.
		 * There is no point waiting.
		 */
		if (queue->flags & SCRIBE_WONT_GROW)
			return ERR_PTR(-ENODATA);
		if (wait)
			goto retry;
		return ERR_PTR(-EAGAIN);
	}
	event = list_first_entry(events, typeof(*event), node);
	if (likely(remove))
		list_del(&event->node);
	spin_unlock(&queue->lock);

	return event;
}

struct scribe_event *scribe_dequeue_event(struct scribe_event_queue *queue,
					  int wait)
{
	return __scribe_peek_event(queue, wait, 1);
}

/*
 * scribe_peek_event() returns the first event (like dequeue), but doesn't
 * remove it from the queue.
 * XXX BE CAREFUL: do not free the event, do not access the event list node.
 * If you want to consume the event, dequeue it.
 */
struct scribe_event *scribe_peek_event(struct scribe_event_queue *queue,
				       int wait)
{
	return __scribe_peek_event(queue, wait, 0);
}

int scribe_is_queue_empty(struct scribe_event_queue *queue)
{
	int ret;
	spin_lock(&queue->lock);
	ret = list_empty(&queue->master.events);
	spin_unlock(&queue->lock);
	return ret;
}

void scribe_set_queue_wont_grow(struct scribe_event_queue *queue)
{
	commit_pending_insert_points(queue);
	queue->flags |= SCRIBE_WONT_GROW;
	wake_up(queue->wait);
}

void *__scribe_alloc_event(__u8 type)
{
	return __scribe_alloc_event_const(type);
}

struct scribe_event_data *scribe_alloc_event_data(size_t size)
{
	struct scribe_event_data *event;
	size_t event_size;

	event_size = size + sizeof_event_from_type(SCRIBE_EVENT_DATA);

	event = kmalloc(event_size, GFP_KERNEL);

	if (event) {
		event->h.type = SCRIBE_EVENT_DATA;
		event->size = size;
	}

	return event;
}
