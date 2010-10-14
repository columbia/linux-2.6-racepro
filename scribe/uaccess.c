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
#include <linux/hardirq.h>
#include <linux/pagemap.h>

void __scribe_allow_uaccess(struct scribe_ps *scribe)
{
	scribe->can_uaccess++;
}

void __scribe_forbid_uaccess(struct scribe_ps *scribe)
{
	WARN(!scribe->can_uaccess,
	     "scribe->can_uaccess == %d\n", scribe->can_uaccess);

	if (--scribe->can_uaccess)
		return;

	WARN_ON(in_atomic());
}

static struct scribe_event_data *get_data_event(struct scribe_ps *scribe,
						size_t size)
{
	struct scribe_event_data *event;

	event = scribe->pre_alloc_data_event;
	if (event) {
		scribe->pre_alloc_data_event = NULL;
		if (event->size >= size) {
			event->size = size;
			return event;
		}
		scribe_free_event(event);
	}

	event = scribe_alloc_event_data(size);
	if (!event)
		scribe_emergency_stop(scribe->ctx, -ENOMEM);

	return event;
}

void scribe_pre_alloc_data_event(size_t pre_alloc_size)
{
	struct scribe_ps *scribe = current->scribe;
	if (!is_scribed(scribe))
		return;

	scribe->pre_alloc_data_event = get_data_event(scribe, pre_alloc_size);
}

void scribe_pre_uaccess(const void *data, const void __user *user_ptr,
			size_t size, int flags)
{
	struct scribe_ps *scribe = current->scribe;
	if (!is_scribed(scribe))
		return;

	__scribe_allow_uaccess(scribe);
}

void scribe_post_uaccess(const void *data, const void __user *user_ptr,
			 size_t size, int flags)
{
	struct scribe_event_data *event;
	struct scribe_ps *scribe = current->scribe;
	int data_flags;

	if (!is_scribed(scribe))
		return;

	/*
	 * @size is the number of bytes that have been copied from/to
	 * userspace. We do not care about bytes that have not been copied.
	 */
	if (!size)
		goto out_forbid;

	data_flags = scribe->data_flags | flags;

	if (data_flags & SCRIBE_DATA_DONT_RECORD)
		goto out_forbid;

	if (is_recording(scribe)) {
		event = get_data_event(scribe, size);
		if (!event)
			return;

		event->data_type = data_flags;
		event->user_ptr = (__u32)user_ptr;

		memcpy(event->data, data, size);
		scribe_queue_event(scribe->queue, event);
	}

out_forbid:
	__scribe_forbid_uaccess(scribe);

	/* TODO this is a failsafe, it can be removed later */
	event = scribe->pre_alloc_data_event;
	if (event) {
		scribe->pre_alloc_data_event = NULL;
		scribe_free_event(scribe->pre_alloc_data_event);
	}
}

void scribe_allow_uaccess(void)
{
	struct scribe_ps *scribe = current->scribe;
	if (!is_scribed(scribe))
		return;

	__scribe_allow_uaccess(scribe);
}

void scribe_forbid_uaccess(void)
{
	struct scribe_ps *scribe = current->scribe;
	if (!is_scribed(scribe))
		return;

	__scribe_forbid_uaccess(scribe);
}

void scribe_pre_schedule(void)
{
	struct scribe_ps *scribe = current->scribe;
	if (!is_scribed(scribe))
		return;

	WARN_ON(scribe->can_uaccess && current->state == TASK_INTERRUPTIBLE);
}

void scribe_post_schedule(void)
{
	struct scribe_ps *scribe = current->scribe;
	if (!is_scribed(scribe))
		return;
}

int fault_in_pages_writeable(char __user *uaddr, int size)
{
	struct scribe_ps *scribe = current->scribe;
	int data_flags = 0;
	int ret;

	if (scribe) {
		data_flags = scribe_get_data_flags(scribe);
		scribe_set_data_flags(scribe, SCRIBE_DATA_DONT_RECORD);
	}
	ret = __fault_in_pages_writeable(uaddr, size);
	if (scribe)
		scribe_set_data_flags(scribe, data_flags);

	return ret;
}

int fault_in_pages_readable(char __user *uaddr, int size)
{
	struct scribe_ps *scribe = current->scribe;
	int data_flags = 0;
	int ret;

	if (scribe) {
		data_flags = scribe_get_data_flags(scribe);
		scribe_set_data_flags(scribe, SCRIBE_DATA_DONT_RECORD);
	}
	ret = __fault_in_pages_readable(uaddr, size);
	if (scribe)
		scribe_set_data_flags(scribe, data_flags);

	return ret;
}
