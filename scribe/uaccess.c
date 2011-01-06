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
#include <linux/module.h>

void __scribe_allow_uaccess(struct scribe_ps *scribe)
{
	/* If we are already at 3 level deep... Something must be wrong */
	WARN(scribe->can_uaccess > 3,
	     "scribe->can_uaccess == %d\n", scribe->can_uaccess);

	if (scribe->can_uaccess++)
		return;

	scribe_mem_sync_point(scribe, MEM_SYNC_OUT);
}

void __scribe_forbid_uaccess(struct scribe_ps *scribe)
{
	WARN(!scribe->can_uaccess,
	     "scribe->can_uaccess == %d\n", scribe->can_uaccess);

	if (--scribe->can_uaccess)
		return;

	scribe_mem_sync_point(scribe, MEM_SYNC_IN);
}

static union scribe_event_data_union get_data_event(struct scribe_ps *scribe,
						    int data_extra, size_t size)
{
	union scribe_event_data_union event;

	if (is_recording(scribe)) {
		event = scribe->prepared_data_event;
		if (event.generic) {
			scribe->prepared_data_event.generic = NULL;

			if (data_extra) {
				BUG_ON(event.extra->h.size < size);
				event.extra->h.size = size;
			} else {
				BUG_ON(event.regular->h.size < size);
				event.regular->h.size = size;
			}
			return event;
		}

		if (data_extra)
			event.extra = scribe_alloc_event_sized(
						SCRIBE_EVENT_DATA_EXTRA, size);
		else
			event.regular = scribe_alloc_event_sized(
						SCRIBE_EVENT_DATA, size);
		if (!event.generic) {
			scribe_emergency_stop(scribe->ctx, ERR_PTR(-ENOMEM));
			event.generic = ERR_PTR(-ENOMEM);
		}
	} else {
		event = scribe->prepared_data_event;
		if (event.generic) {
			scribe->prepared_data_event.generic = NULL;
			return event;
		}
		/*
		 * Not using scribe_dequeue_event_sized() because we don't
		 * really know the size (maybe we are in
		 * scribe_prepare_data_event() and @size would only be the
		 * maximum size).
		 */
		if (data_extra)
			event.extra = scribe_dequeue_event_specific(scribe,
						      SCRIBE_EVENT_DATA_EXTRA);
		else
			event.regular = scribe_dequeue_event_specific(scribe,
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
	union scribe_event_data_union event;
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return;

	if (!should_handle_data(scribe))
		return;

	if (!(scribe->data_flags & SCRIBE_DATA_NON_DETERMINISTIC) &&
	    !should_scribe_data_det(scribe))
		return;

	event = get_data_event(scribe, should_scribe_data_extra(scribe),
			       pre_alloc_size);
	if (!IS_ERR(event.generic))
		scribe->prepared_data_event = event;
}

void scribe_pre_uaccess(const void *data, const void __user *user_ptr,
			size_t size, int flags)
{
	struct scribe_ps *scribe = current->scribe;
	if (!is_scribed(scribe))
		return;

	if (!is_kernel_copy())
		__scribe_allow_uaccess(scribe);
}
EXPORT_SYMBOL(scribe_pre_uaccess);

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

static void scribe_post_uaccess_record(struct scribe_ps *scribe, int data_extra,
				       union scribe_event_data_union event,
				       const void *data, void __user *user_ptr,
				       size_t size, int data_flags)
{
	void *event_data;

	if (data_extra) {
		event.extra->data_type = data_flags;
		event.extra->user_ptr = (__u32)user_ptr;
		event_data = event.extra->data;
	} else
		event_data = event.regular->data;

	if (data_flags & SCRIBE_DATA_ZERO)
		memset(event_data, 0, size);
	else
		memcpy(event_data, data, size);
	scribe_queue_event(scribe->queue, event.generic);
}

static void scribe_post_uaccess_replay(struct scribe_ps *scribe, int data_extra,
				       union scribe_event_data_union event,
				       const void *data, void __user *user_ptr,
				       size_t size, int data_flags)
{
	const void *event_data;

	if (!data_extra)
		goto skip_extra_checks;

	if ((event.extra->data_type & ~SCRIBE_DATA_ZERO) !=
	    (data_flags & ~SCRIBE_DATA_ZERO)) {
		scribe_diverge(scribe, SCRIBE_EVENT_DIVERGE_DATA_TYPE,
			       .type = data_flags);
		return;
	}

	if ((void *)event.extra->user_ptr != user_ptr) {
		scribe_diverge(scribe, SCRIBE_EVENT_DIVERGE_DATA_PTR,
			       .user_ptr = (u32)user_ptr);
		return;
	}

skip_extra_checks:
	if (event.generic->size != size) {
		scribe_diverge(scribe, SCRIBE_EVENT_DIVERGE_EVENT_SIZE,
			       .size = size);
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

	event_data = data_extra ? event.extra->data : event.regular->data;

	if (!(data_flags & SCRIBE_DATA_NON_DETERMINISTIC)) {
		if (likely(data))
			ensure_data_correctness(scribe, event_data,
						data, size);
		else
			scribe_diverge(scribe, SCRIBE_EVENT_DIVERGE_DATA_TYPE,
				       .type = SCRIBE_DATA_NON_DETERMINISTIC);

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
	if (__copy_to_user_inatomic(user_ptr, event_data, size)) {
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


static void __scribe_post_uaccess(const void *data, const void __user *user_ptr,
				  size_t size, int flags,
				  union scribe_event_data_union *eventp)
{
	int data_flags;
	union scribe_event_data_union event;
	struct scribe_ps *scribe = current->scribe;
	int data_extra;

	if (!is_scribed(scribe))
		return;

	if (eventp)
		eventp->generic = NULL;

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

	if ((!(data_flags & SCRIBE_DATA_NON_DETERMINISTIC) ||
	     data_flags & SCRIBE_DATA_ZERO) &&
	    !should_scribe_data_det(scribe))
		goto skip;

	data_extra = should_scribe_data_extra(scribe);
	event = get_data_event(scribe, data_extra, size);
	if (IS_ERR(event.generic))
		goto skip;

	if (is_recording(scribe)) {
		scribe_post_uaccess_record(scribe, data_extra, event, data,
					   (void __user *)user_ptr, size,
					   data_flags);
	} else { /* replay */
		scribe_post_uaccess_replay(scribe, data_extra, event, data,
					   (void __user *)user_ptr, size,
					   data_flags);
		if (eventp)
			*eventp = event;
		else
			scribe_free_event(event.generic);
	}

skip:
	if (!is_kernel_copy())
		__scribe_forbid_uaccess(scribe);
	WARN(scribe->prepared_data_event.generic,
	     "pre-allocated data event not used\n");
}

void scribe_post_uaccess(const void *data, const void __user *user_ptr,
			 size_t size, int flags)
{
	__scribe_post_uaccess(data, user_ptr, size, flags, NULL);
}
EXPORT_SYMBOL(scribe_post_uaccess);

void scribe_copy_to_user_recorded(void __user *to, long n,
				  union scribe_event_data_union *event)
{
	struct scribe_ps *scribe = current->scribe;
	BUG_ON(!is_replaying(scribe));

	scribe_pre_uaccess(NULL, to, n, scribe->data_flags);
	__scribe_post_uaccess(NULL, to, n, scribe->data_flags, event);
}

int scribe_interpose_value_record(struct scribe_ps *scribe,
				  const void *data, size_t size)
{
	int data_extra = should_scribe_data_extra(scribe);
	union scribe_event_data_union event;

	if (data_extra)
		event.extra = scribe_alloc_event_sized(
						SCRIBE_EVENT_DATA_EXTRA, size);
	else
		event.regular = scribe_alloc_event_sized(
						SCRIBE_EVENT_DATA, size);

	if (!event.generic)
		return -ENOMEM;

	if (data_extra) {
		event.extra->data_type = SCRIBE_DATA_INTERNAL;
		event.extra->user_ptr = 0;
		memcpy(event.extra->data, data, size);
	} else {
		memcpy(event.regular->data, data, size);
	}
	scribe_queue_event(scribe->queue, event.regular);
	return 0;
}

int scribe_interpose_value_replay(struct scribe_ps *scribe,
				  void *data, size_t size)
{

	int data_extra = should_scribe_data_extra(scribe);
	union scribe_event_data_union event;

	if (data_extra)
		event.extra = scribe_dequeue_event_sized(scribe,
						 SCRIBE_EVENT_DATA_EXTRA, size);
	else
		event.regular = scribe_dequeue_event_sized(scribe,
						 SCRIBE_EVENT_DATA, size);

	if (IS_ERR(event.generic))
		return PTR_ERR(event.generic);

	if (data_extra) {
		if (event.extra->data_type != SCRIBE_DATA_INTERNAL) {
			scribe_free_event(event.generic);
			scribe_diverge(scribe, SCRIBE_EVENT_DIVERGE_DATA_TYPE,
				       .type = SCRIBE_DATA_INTERNAL);
			return -EDIVERGE;
		}

		memcpy(data, event.extra->data, size);
	} else {
		memcpy(data, event.regular->data, size);
	}

	scribe_free_event(event.generic);
	return 0;
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

	scribe_mem_schedule_in(scribe);
}

void scribe_post_schedule(void)
{
	struct scribe_ps *scribe = current->scribe;
	if (!is_scribed(scribe))
		return;

	scribe_mem_schedule_out(scribe);
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

/* XXX There is only one level of data_flags stack levels */
void scribe_data_push_flags(int flags)
{
	struct scribe_ps *scribe = current->scribe;
	if (!may_be_scribed(scribe))
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
