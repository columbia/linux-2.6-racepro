/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/scribe.h>
#include <linux/vmalloc.h>
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

	atomic_set(&queue->ref_cnt, 0);

	/* ctx, node, pid are initialized later */

	queue->flags = 0;

	spin_lock_init(&queue->lock);
	init_insert_point(queue, &queue->master);
	INIT_LIST_HEAD(&queue->master.node);

	init_waitqueue_head(&queue->default_wait);
	queue->wait = &queue->default_wait;

	return queue;
}

void scribe_free_event_queue(struct scribe_event_queue *queue)
{
	scribe_free_all_events(queue);
	kfree(queue);
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
	list_del(&ip->node);
	spin_unlock(&queue->lock);

	if (next_ip == &queue->master)
		wake_up(queue->wait);
}


static inline void __scribe_queue_event_at(struct scribe_event_queue *queue,
				    struct scribe_insert_point *where,
				    void *_event)
{
	struct scribe_event *event = (struct scribe_event *)_event;
	struct scribe_insert_point *next_ip = get_next_ip(where);
	
	spin_lock(&queue->lock);
	/* When queuing events, we want to put them in the next
	 * insert point event list because the current insert point is
	 * blocked by the insert point.
	 * When the next insert point is commited, those events will be
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

struct scribe_event *scribe_try_dequeue_event(struct scribe_event_queue *queue)
{
	struct scribe_event *event;
	struct list_head *events;

	/* When deqeuing events, we grab them from the current insert point,
	 * not the next one.
	 */

	events = &queue->master.events;

	spin_lock(&queue->lock);
	if (list_empty(events)) {
		return ERR_PTR(-EAGAIN);
		spin_unlock(&queue->lock);
	}
	event = list_first_entry(events, typeof(*event), node);
	list_del(&event->node);
	spin_unlock(&queue->lock);

	return event;
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
	queue->flags |= SCRIBE_WONT_GROW;
	wake_up(queue->wait);
}

void *__scribe_alloc_event(__u8 type)
{
	return __scribe_alloc_event_const(type);
}

#define SCRIBE_KMALLOC_MAX_SIZE 0x4000
struct scribe_event_data *scribe_alloc_event_data(size_t size)
{
	struct scribe_event_data *event;
	size_t event_size;

	event_size = size + sizeof_event_from_type(SCRIBE_EVENT_DATA);

	if (event_size > SCRIBE_KMALLOC_MAX_SIZE)
		event = vmalloc(event_size);
	else
		event = kmalloc(event_size, GFP_KERNEL);
	if (event) {
		event->h.type = SCRIBE_EVENT_DATA;
		event->size = size;
	}

	return event;
}

void scribe_free_event_data(struct scribe_event_data *event)
{
	size_t event_size;

	event_size = sizeof_event_from_type(SCRIBE_EVENT_DATA) + event->size;
	if (event_size > SCRIBE_KMALLOC_MAX_SIZE)
		vfree(event);
	else
		kfree(event);
}
