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

void scribe_pre_uaccess(void)
{
}

void scribe_post_uaccess(const void *data, size_t size, int flags)
{
	struct scribe_event_data *event;
	struct scribe_ps *scribe = current->scribe;

	/*
	 * @size is the number of bytes that have been copied from/to
	 * userspace. We do not care about bytes that would cause an -EFAULT.
	 */
	if (!size)
		return;

	if (!is_scribed(scribe))
		return;

	if (is_recording(scribe)) {
		event = scribe_alloc_event_data(size);
		if (!event)
			scribe_emergency_stop(scribe->ctx, -ENOMEM);

		event->data_type = scribe->data_flags | flags;

		memcpy(event->data, data, size);
		scribe_queue_event(scribe->queue, event);
	}
}

void scribe_set_data_flags(struct scribe_ps *scribe, int flags)
{
	scribe->data_flags = flags;
}
