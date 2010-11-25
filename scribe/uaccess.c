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
	/* If we are already at 3 level deep... Something must be wrong */
	WARN(scribe->can_uaccess > 3,
	     "scribe->can_uaccess == %d\n", scribe->can_uaccess);

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

	if (is_recording(scribe)) {
		event = scribe->prepared_data_event;
		if (event) {
			scribe->prepared_data_event = NULL;
			BUG_ON(event->h.size < size);
			event->h.size = size;
			return event;
		}

		event = scribe_alloc_event_sized(SCRIBE_EVENT_DATA, size);
		if (!event) {
			scribe_emergency_stop(scribe->ctx, ERR_PTR(-ENOMEM));
			event = ERR_PTR(-ENOMEM);
		}
	} else {
		event = scribe->prepared_data_event;
		if (event) {
			scribe->prepared_data_event = NULL;
			return event;
		}
		/*
		 * Not using scribe_dequeue_event_sized() because we don't
		 * really know the size (maybe we are in
		 * scribe_prepare_data_event() and @size would only be the
		 * maximum size).
		 */
		event = scribe_dequeue_event_specific(scribe,
						      SCRIBE_EVENT_DATA);
	}

	return event;
}

int is_kernel_copy(void)
{
	return !memcmp(&get_fs(), &get_ds(), sizeof(mm_segment_t));
}

static int should_handle_data(struct scribe_ps *scribe)
{
	return !(scribe->data_flags & SCRIBE_DATA_IGNORE) &&
	       !is_kernel_copy() &&
	       should_scribe_data(scribe);
}

void scribe_prepare_data_event(size_t pre_alloc_size)
{
	struct scribe_event_data *event;
	struct scribe_ps *scribe = current->scribe;
	if (!is_scribed(scribe))
		return;

	if (!should_handle_data(scribe))
		return;

	event = get_data_event(scribe, pre_alloc_size);
	if (!IS_ERR(event))
		scribe->prepared_data_event = event;
}

void scribe_pre_uaccess(const void *data, const void __user *user_ptr,
			size_t size, int flags)
{
	struct scribe_ps *scribe = current->scribe;
	if (!is_scribed(scribe))
		return;

	__scribe_allow_uaccess(scribe);
}

/*
 * This version of memcmp() returns the offset of the mismatch,
 * or -1 when the buffers are matching
 */
static int __memcmp(const void *cs, const void *ct, size_t count)
{
	const unsigned char *su1, *su2;
	size_t orig_count = count;

	for (su1 = cs, su2 = ct; count > 0; ++su1, ++su2, count--)
		if (*su1 != *su2)
			return orig_count - count;;
	return -1;
}

static void ensure_data_correctness(struct scribe_ps *scribe,
				    const void *recorded_data, const void *data,
				    size_t count)
{
	struct scribe_event_diverge_data_content *de;
	int offset;

	offset = __memcmp(recorded_data, data, count);

	if (offset == -1)
		return;

	de = scribe_get_diverge_event(scribe,
				      SCRIBE_EVENT_DIVERGE_DATA_CONTENT);
	if (!IS_ERR(de)) {
		de->offset = offset;
		de->size = min(count - offset, sizeof(de->data));
		memcpy(de->data, data + offset, de->size);
		memset(de->data + de->size, 0, sizeof(de->data) - de->size);
	}
	scribe_emergency_stop(scribe->ctx, (struct scribe_event *)de);
}

static void scribe_post_uaccess_record(struct scribe_ps *scribe,
		struct scribe_event_data *event, const void *data,
		void __user *user_ptr, size_t size, int data_flags)
{
	event->data_type = data_flags;
	event->user_ptr = (__u32)user_ptr;

	if (data_flags & SCRIBE_DATA_ZERO)
		memset(event->data, 0, size);
	else
		memcpy(event->data, data, size);
	scribe_queue_event(scribe->queue, event);
}

static void scribe_post_uaccess_replay(struct scribe_ps *scribe,
		struct scribe_event_data *event, const void *data,
		void __user *user_ptr, size_t size, int data_flags)
{
	if (event->data_type != data_flags) {
		scribe_diverge(scribe, SCRIBE_EVENT_DIVERGE_DATA_TYPE,
			       .type = data_flags);
		return;
	}

	if (event->h.size != size) {
		scribe_diverge(scribe, SCRIBE_EVENT_DIVERGE_EVENT_SIZE,
			       .size = size);
		return;
	}

	if ((void *)event->user_ptr != user_ptr) {
		scribe_diverge(scribe, SCRIBE_EVENT_DIVERGE_DATA_PTR,
			       .user_ptr = (u32)user_ptr);
		return;
	}

	if (data_flags & SCRIBE_DATA_ZERO) {
		/*
		 * Avoiding the use of scribe_data_ignore so that we
		 * don't pollute the data flags 'stack'.
		 */
		data_flags = scribe->data_flags;
		scribe->data_flags = SCRIBE_DATA_IGNORE;
		if (__clear_user(user_ptr, size)) {
			scribe_emergency_stop(scribe->ctx,
					      ERR_PTR(-EDIVERGE));
		}
		scribe->data_flags = data_flags;
		return;
	}

	if (!(data_flags & SCRIBE_DATA_NON_DETERMINISTIC)) {
		ensure_data_correctness(scribe, event->data, data, size);
		return;
	}

	/*
	 * FIXME Do the copying in pre_uaccess and skip the extra copy_to_user
	 * that happened before.
	 */
	data_flags = scribe->data_flags;
	scribe->data_flags = SCRIBE_DATA_IGNORE;
	/*
	 * We're using the inatomic version so that we don't get the
	 * might_sleep(), but if we're not in an atomic context, it's
	 * equivalent to __copy_to_user().
	 */
	if (__copy_to_user_inatomic(user_ptr, event->data, size)) {
		/*
		 * FIXME If we are in an atomic region, the copy may or may
		 * not have happended. We need to make sure that the copy
		 * happens anyway.
		 */
		WARN(in_atomic(), "Need to implement proper "
				  "atomic copies in replay\n");
		scribe_emergency_stop(scribe->ctx, ERR_PTR(-EDIVERGE));
	}

	scribe->data_flags = data_flags;
}


void scribe_post_uaccess(const void *data, const void __user *user_ptr,
			 size_t size, int flags)
{
	int data_flags;
	struct scribe_event_data *event;
	struct scribe_ps *scribe = current->scribe;
	if (!is_scribed(scribe))
		return;

	if (!should_handle_data(scribe))
		goto skip;

	/*
	 * @size is the number of bytes that have been copied from/to
	 * userspace.
	 * For convenience during the replay, we will record a 0 sized
	 * data event.
	 */

	data_flags = scribe->data_flags | flags;

	WARN_ON((long)user_ptr > TASK_SIZE);

	if (data_flags & SCRIBE_DATA_DONT_RECORD)
		goto skip;

	event = get_data_event(scribe, size);
	if (IS_ERR(event))
		goto skip;

	if (is_recording(scribe)) {
		scribe_post_uaccess_record(scribe, event, data,
					   (void __user *)user_ptr, size,
					   data_flags);
	} else { /* replay */
		scribe_post_uaccess_replay(scribe, event, data,
					   (void __user *)user_ptr, size,
					   data_flags);
		scribe_free_event(event);
	}

skip:
	__scribe_forbid_uaccess(scribe);
	WARN(scribe->prepared_data_event,
	     "pre-allocated data event not used\n");
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

	if (may_be_scribed(scribe)) {
		data_flags = scribe->data_flags;
		scribe->data_flags = SCRIBE_DATA_DONT_RECORD;
	}
	ret = __fault_in_pages_writeable(uaddr, size);
	if (may_be_scribed(scribe))
		scribe->data_flags = data_flags;

	return ret;
}

int fault_in_pages_readable(char __user *uaddr, int size)
{
	struct scribe_ps *scribe = current->scribe;
	int data_flags = 0;
	int ret;

	if (may_be_scribed(scribe)) {
		data_flags = scribe->data_flags;
		scribe->data_flags = SCRIBE_DATA_DONT_RECORD;
	}
	ret = __fault_in_pages_readable(uaddr, size);
	if (may_be_scribed(scribe))
		scribe->data_flags = data_flags;

	return ret;
}

/* XXX You have only one level of data_flags "levels" */
void scribe_data_push_flags(int flags)
{
	struct scribe_ps *scribe = current->scribe;
	if (!is_scribed(scribe))
		return;

	scribe->old_data_flags = scribe->data_flags;
	scribe->data_flags = flags;
}

void scribe_data_det(void)
{
	scribe_data_push_flags(0);
}

void scribe_data_non_det(void)
{
	scribe_data_push_flags(SCRIBE_DATA_NON_DETERMINISTIC);
}

void scribe_data_dont_record(void)
{
	scribe_data_push_flags(SCRIBE_DATA_DONT_RECORD);
}

void scribe_data_ignore(void)
{
	scribe_data_push_flags(SCRIBE_DATA_IGNORE);
}

void scribe_data_pop_flags(void)
{
	struct scribe_ps *scribe = current->scribe;
	if (!is_scribed(scribe))
		return;

	scribe->data_flags = scribe->old_data_flags;
}
