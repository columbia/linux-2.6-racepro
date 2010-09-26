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

#define KMALLOC_MAX_SIZE 0x4000

struct scribe_event_data *scribe_alloc_event_data(size_t size)
{
	struct scribe_event_data *event;
	size_t event_size;

	event_size += sizeof_event_from_type(SCRIBE_EVENT_DATA);

	if (size > KMALLOC_MAX_SIZE)
		event = vmalloc(event_size);
	else
		event = kmalloc(event_size, GFP_KERNEL);
	if (event) {
		event->h.type = type;
		event->size = size;
	}

	return event;
}

void scribe_free_event_data(struct scribe_event_data *event)
{
	size_t event_size;

	event_size = sizeof_event_from_type(SCRIBE_EVENT_DATA) + event->size;
	if (event_size > KMALLOC_MAX_SIZE)
		event = vfree(event);
	else
		event = kfree(event);
}
