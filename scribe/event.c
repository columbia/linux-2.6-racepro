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

static void init_insert_point(struct scribe_queue_bare *bare,
			      struct scribe_insert_point *ip)
{
	ip->bare = bare;
	INIT_LIST_HEAD(&ip->events);
}

static void init_queue_bare(struct scribe_queue_bare *bare)
{
	spin_lock_init(&bare->lock);
	init_insert_point(bare, &bare->master);
	INIT_LIST_HEAD(&bare->master.node);
	bare->wont_grow = 0;
	init_waitqueue_head(&bare->default_wait);
	bare->wait = &bare->default_wait;
}

static void init_queue(struct scribe_queue *queue,
		       struct scribe_context *ctx, pid_t pid)
{
	/*
	 * XXX the context reference is not taken: the caller should maintain
	 * that reference until that queue dies.
	 */
	init_queue_bare(&queue->bare);
	atomic_set(&queue->ref_cnt, 1);
	queue->persistent = 0;
	queue->ctx = ctx;
	INIT_LIST_HEAD(&queue->node);
	queue->pid = pid;
}

struct scribe_queue_bare *scribe_alloc_queue_bare(void)
{
	struct scribe_queue_bare *bare;

	bare = kmalloc(sizeof(*bare), GFP_KERNEL);
	if (!bare)
		return NULL;
	init_queue_bare(bare);
	return bare;
}

/*
 * The queue initialization is done in scribe_get_queue_by_pid().
 */
struct scribe_queue *scribe_alloc_queue(void)
{
	struct scribe_queue *queue;

	queue = kmalloc(sizeof(*queue), GFP_KERNEL);
	return queue;
}

void scribe_free_queue_bare(struct scribe_queue_bare *bare)
{
	scribe_free_all_events(bare);
	kfree(bare);
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
 * When the pre allocated queue is used, it's address is set NULL.
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
		queue->bare.wont_grow = 1;

	/*
	 * Making the new queue persistent: We are keeping an internal
	 * reference to prevent the queue from being freed when the producer
	 * is done with the queue and the consumer is not available yet.
	 */
	scribe_set_persistent(queue);

	list_add(&queue->node, &ctx->queues);

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
		scribe_free_all_events(&queue->bare);
		kfree(queue);
	}
}

void scribe_put_queue_locked(struct scribe_queue *queue)
{
	if (atomic_dec_and_test(&queue->ref_cnt)) {
		list_del(&queue->node);
		scribe_free_all_events(&queue->bare);
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

void scribe_free_all_events(struct scribe_queue_bare *bare)
{
	struct scribe_event *event, *tmp;

	spin_lock(&bare->lock);

	/* Some insert points are in progress... */
	BUG_ON(!list_empty(&bare->master.node));

	list_for_each_entry_safe(event, tmp, &bare->master.events, node) {
		list_del(&event->node);
		scribe_free_event(event);
	}

	spin_unlock(&bare->lock);
}

static inline struct scribe_insert_point *get_next_ip(
						struct scribe_insert_point *ip)
{
	return list_entry(ip->node.next, typeof(*ip), node);
}

void scribe_create_insert_point(struct scribe_queue_bare *bare,
				struct scribe_insert_point *ip)

{
	struct scribe_insert_point *where = &bare->master;

	init_insert_point(bare, ip);

	spin_lock(&bare->lock);
	list_add(&ip->node, &where->node);
	spin_unlock(&bare->lock);
}

void scribe_commit_insert_point(struct scribe_insert_point *ip)
{
	struct scribe_queue_bare *bare = ip->bare;
	struct scribe_insert_point *next_ip = get_next_ip(ip);

	spin_lock(&bare->lock);
	list_splice_tail(&ip->events, &next_ip->events);
	list_del_init(&ip->node);
	spin_unlock(&bare->lock);

	if (next_ip == &bare->master)
		wake_up(bare->wait);
}

static void commit_pending_insert_points(struct scribe_queue_bare *bare)
{
	struct scribe_insert_point *ip, *tmp;

	list_for_each_entry_safe(ip, tmp, &bare->master.node, node)
		scribe_commit_insert_point(ip);
}

static inline void __scribe_queue_event_at(struct scribe_queue_bare *bare,
					   struct scribe_insert_point *where,
					   void *_event)
{
	struct scribe_event *event = (struct scribe_event *)_event;
	struct scribe_insert_point *next_ip = get_next_ip(where);

	spin_lock(&bare->lock);
	/*
	 * When queuing events, we want to put them in the next
	 * insert point event list because the current insert point is
	 * blocked by the insert point.
	 * When the next insert point is committed, those events will be
	 * merge into the current insert point with
	 * scribe_commit_insert_point().
	 */
	list_add_tail(&event->node, &next_ip->events);
	spin_unlock(&bare->lock);

	if (next_ip == &bare->master)
		wake_up(bare->wait);
}

void scribe_queue_event_at(struct scribe_insert_point *where, void *event)
{
	__scribe_queue_event_at(where->bare, where, event);
}

void scribe_queue_event(struct scribe_queue *queue, void *event)
{
	__scribe_queue_event_at(&queue->bare, &queue->bare.master, event);
}

void scribe_queue_event_bare(struct scribe_queue_bare *bare, void *event)
{
	__scribe_queue_event_at(bare, &bare->master, event);
}

static inline void __scribe_queue_events_at(struct scribe_queue_bare *bare,
					    struct scribe_insert_point *where,
					    struct list_head *events)
{
	struct scribe_insert_point *next_ip = get_next_ip(where);

	spin_lock(&bare->lock);
	list_splice_tail_init(events, &next_ip->events);
	spin_unlock(&bare->lock);

	if (next_ip == &bare->master)
		wake_up(bare->wait);
}

void scribe_queue_events_bare(struct scribe_queue_bare *bare,
			      struct list_head *events)
{
	__scribe_queue_events_at(bare, &bare->master, events);
}

static struct scribe_event *__scribe_peek_event(
		struct scribe_queue_bare *bare, int wait, int remove)
{
	struct scribe_event *event;
	struct list_head *events;

	/*
	 * When deqeuing events, we grab them from the current insert point,
	 * not the next one.
	 */
	events = &bare->master.events;

retry:
	if (wait == SCRIBE_WAIT_INTERRUPTIBLE &&
	    wait_event_interruptible(*bare->wait,
				     !scribe_is_queue_empty(bare) ||
				     bare->wont_grow))
		return ERR_PTR(-ERESTARTSYS);

	if (wait == SCRIBE_WAIT)
		wait_event(*bare->wait,
		       !scribe_is_queue_empty(bare) ||
		       bare->wont_grow);

	spin_lock(&bare->lock);
	if (list_empty(events)) {
		spin_unlock(&bare->lock);
		/*
		 * If the queue will never grow, the queue is officially dead.
		 * There is no point waiting.
		 */
		if (bare->wont_grow)
			return ERR_PTR(-ENODATA);
		if (wait)
			goto retry;
		return ERR_PTR(-EAGAIN);
	}
	event = list_first_entry(events, typeof(*event), node);
	if (likely(remove))
		list_del(&event->node);
	spin_unlock(&bare->lock);

	return event;
}

struct scribe_event *scribe_dequeue_event(struct scribe_queue *queue,
					  int wait)
{
	struct scribe_event *event;
	struct scribe_context *ctx = queue->ctx;

	event = __scribe_peek_event(&queue->bare, wait, 1);
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

struct scribe_event *scribe_dequeue_event_bare(struct scribe_queue_bare *bare,
					       int wait)
{
	return __scribe_peek_event(bare, wait, 1);
}

/*
 * scribe_peek_event() returns the first event (like dequeue), but doesn't
 * remove it from the queue.
 * XXX BE CAREFUL: do not free the event, do not access the event list node.
 * If you want to consume the event, dequeue it.
 */
struct scribe_event *scribe_peek_event(struct scribe_queue *queue, int wait)
{
	return __scribe_peek_event(&queue->bare, wait, 0);
}

int scribe_is_queue_empty(struct scribe_queue_bare *bare)
{
	int ret;
	/* FIXME is the spinlock really necessary ? */
	spin_lock(&bare->lock);
	ret = list_empty(&bare->master.events);
	spin_unlock(&bare->lock);
	return ret;
}

void scribe_set_queue_wont_grow(struct scribe_queue_bare *bare)
{
	commit_pending_insert_points(bare);
	bare->wont_grow = 1;
	wake_up(bare->wait);
}

void *__scribe_alloc_event(int type)
{
	return __scribe_alloc_event_const(type);
}
