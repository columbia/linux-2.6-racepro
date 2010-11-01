/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/scribe.h>

struct scribe_backtrace {
	struct list_head events;
	struct scribe_event_backtrace *last;
};

struct scribe_backtrace *scribe_alloc_backtrace(int backtrace_len)
{
	struct scribe_event_backtrace *event = NULL;
	struct scribe_backtrace *bt;
	int i;

	bt = kmalloc(sizeof(*bt), GFP_KERNEL);
	if (!bt)
		return NULL;

	INIT_LIST_HEAD(&bt->events);

	for (i = 0; i < backtrace_len; i++) {
		event = scribe_alloc_event(SCRIBE_EVENT_BACKTRACE);
		if (!event) {
			scribe_free_backtrace(bt);
			return NULL;
		}

		list_add_tail(&event->h.node, &bt->events);
		event->event_offset = -1;
	}
	bt->last = event;

	return bt;
}

void scribe_free_backtrace(struct scribe_backtrace *bt)
{
	struct scribe_event_backtrace *event, *tmp;

	list_for_each_entry_safe(event, tmp, &bt->events, h.node) {
		list_del(&event->h.node);
		scribe_free_event(event);
	}

	kfree(bt);
}

/* It's the owner responsability to serialize operations */
void scribe_backtrace_add(struct scribe_backtrace *bt,
			  struct scribe_event *event)
{
	struct scribe_event_backtrace *bt_event;

	bt_event = list_first_entry(&bt->events, typeof(*bt_event), h.node);
	bt_event->event_offset = event->log_offset;
	list_move_tail(&bt_event->h.node, &bt->events);
}

void scribe_backtrace_dump(struct scribe_backtrace *bt,
			   struct scribe_queue_bare *queue)
{
	struct list_head invalid_entries;
	struct scribe_event_backtrace *last = bt->last;

	if (last->event_offset == -1) {
		/* the backtrace is not full, moving invalid entries  */
		list_cut_position(&invalid_entries, &bt->events, &last->h.node);
	}

	scribe_queue_events_bare(queue, &bt->events);

	if (last->event_offset == -1) {
		/* Putting back the invalid entries in the bt list */
		list_splice_tail(&invalid_entries, &bt->events);
	}
}
