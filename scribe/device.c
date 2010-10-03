/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/major.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/scribe.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

struct scribe_dev {
	struct scribe_context *ctx;
	struct scribe_event_queue *last_queue, *pre_alloc_queue;
	struct scribe_event *pending_event;
	unsigned long offset;
	pid_t last_pid;
};

static inline size_t sizeof_event_payload(struct scribe_event *event)
{
	return sizeof_event(event) - offsetof(typeof(*event), payload_offset);
}

static inline char *get_event_payload(struct scribe_event *event)
{
	return (char *)(event->payload_offset);
}

static int handle_event_pid(struct scribe_dev *dev, struct scribe_event *event)
{
	pid_t pid = ((struct scribe_event_pid *)event)->pid;

	if (!dev->pre_alloc_queue) {
		dev->pre_alloc_queue = scribe_alloc_event_queue();
		if (!dev->pre_alloc_queue)
			return -ENOMEM;
	}

	dev->last_queue =
		scribe_get_queue_by_pid(dev->ctx, &dev->pre_alloc_queue, pid);

	return 0;
}

static ssize_t dev_write(struct file *file,
			 const char __user *buf, size_t count, loff_t *ppos)
{
	struct scribe_dev *dev = file->private_data;
	struct scribe_event *event = NULL;
	struct scribe_event_data *event_data = NULL;
	typeof(event->type) type;
	typeof(event_data->size) data_size = 0;
	int data_size_offset;
	size_t event_payload_size, to_copy;
	ssize_t ret = 0;
	int err = 0;

	if (dev->ctx->flags & SCRIBE_RECORD)
		return -EPERM;

	/*
	 * TODO When an event cannot be read in its whole, the function
	 * returns. We'd like to prevent that by accepting whatever is given,
	 * and buffer the data until the event is complete.
	 */

	for (;;) {
		/* Step 1: The event allocation */
		err = -EINVAL;
		if (count < sizeof(type))
			goto out;
		err = -EFAULT;
		if (get_user(type, buf))
			goto out;

		if (type == SCRIBE_EVENT_DATA) {
			/*
			 * This event has a variable size, and we need to know
			 * its payload length to properly allocate the event.
			 */
			data_size_offset =
				       offsetof(typeof(*event_data), size)
				     - offsetof(typeof(*event), payload_offset);

			err = -EINVAL;
			if (count < data_size_offset + sizeof(data_size))
				goto out;
			err = -EFAULT;
			if (get_user(data_size, buf + data_size_offset))
				goto out;

			event_data = scribe_alloc_event_data(data_size);
			event = (struct scribe_event *)event_data;
		} else {
			event = scribe_alloc_event(type);
		}

		err = -ENOMEM;
		if (!event)
			goto out;

		/* Step 2: The copy_from_user() */
		event_payload_size = sizeof_event_payload(event);
		to_copy = event_payload_size - sizeof(type);

		err = -EINVAL;
		if (count < to_copy)
			goto out;
		if (to_copy) {
			err = -EFAULT;
			if (copy_from_user(
					get_event_payload(event) + sizeof(type),
					buf + sizeof(type),
					to_copy))
				goto out;
		}

		/* Step 3: Special event handling */
		if (type == SCRIBE_EVENT_DATA) {
			/*
			 * This is a guards against a race that could happen
			 * if a thread changes the event_data->size field
			 * after we first read it.
			 */
			event_data->size = data_size;
		} else if (type == SCRIBE_EVENT_PID) {
			err = handle_event_pid(dev, event);
			scribe_free_event(event);
			event = NULL;
			if (err)
				goto out;
		} else { /* generic event handling */
			scribe_queue_event(dev->last_queue, event);
		}

		event = NULL;
		ret += event_payload_size;
		buf += event_payload_size;
		count -= event_payload_size;
	}

out:
	if (event)
		scribe_free_event(event);
	if (err)
		return err;
	return ret;
}

/*
 * __get_non_empty_queue() try to find the the first non empty queue. It
 * returns the queue on success, -ENODEV if the queue list is empty and will
 * stay empty, -EAGAIN if at least one queue is present and all queues are
 * empty.
 *
 * Note: scribe_get_non_empty_queue() also remove dead queues.
 */
static struct scribe_event_queue *__get_non_empty_queue(
		struct scribe_context *ctx)
{
	struct scribe_event_queue *queue, *tmp;
	int ret;

	spin_lock(&ctx->queues_lock);
	list_for_each_entry_safe(queue, tmp, &ctx->queues, node) {
		if (!scribe_is_queue_empty(queue)) {
			scribe_get_queue(queue);
			spin_unlock(&ctx->queues_lock);
			return queue;
		}

		/*
		 * When the queue is empty and set to not growing, we can
		 * consider it as dead. Releasing our persistent token on it
		 * will make the queue go away if the associated process
		 * detaches.
		 */
		if (queue->flags & SCRIBE_WONT_GROW)
			scribe_make_persistent(queue, 0);
	}

	ret = -EAGAIN;
	if (list_empty(&ctx->queues)) {
		/*
		 * There are no more queues in the context, which means that
		 * there are no tasks attached as well. Thus the context
		 * status is either set to:
		 * - SCRIBE_IDLE: the recording is over, and so we want
		 *   dev_read() to return 0
		 * - SCRIBE_RECORD: the recording has not started yet, we want
		 *   to wait.
		 */
		if (ctx->flags == SCRIBE_IDLE)
			ret = -ENODEV;
	}

	spin_unlock(&ctx->queues_lock);
	return ERR_PTR(ret);
}

#define SCRIBE_NO_WAIT 0
#define SCRIBE_WAIT 1

static struct scribe_event_queue *get_non_empty_queue(
		struct scribe_dev *dev, int wait)
{
	struct scribe_context *ctx = dev->ctx;
	struct scribe_event_queue *queue;
	int ret;

	queue = dev->last_queue;
	if (queue) {
		if (!scribe_is_queue_empty(queue))
			return queue;
		scribe_put_queue(queue);
		dev->last_queue = NULL;
	}

	if (wait == SCRIBE_WAIT) {
		ret = wait_event_interruptible(
			ctx->queues_wait,
			((queue = __get_non_empty_queue(ctx))
			 != ERR_PTR(-EAGAIN)));

		if (ret)
			return ERR_PTR(-ERESTARTSYS);
	} else {
		queue = __get_non_empty_queue(ctx);
	}

	if (!IS_ERR(queue))
		dev->last_queue = queue;

	return queue;
}

static struct scribe_event *get_next_event(struct scribe_dev *dev,
					   struct scribe_event_queue *queue)
{
	struct scribe_event_pid *event_pid;
	struct scribe_event *event;

	if (likely(dev->last_pid == queue->pid)) {
		event = scribe_dequeue_event(queue, SCRIBE_NO_WAIT);
		BUG_ON(IS_ERR(event));
		return event;
	}

	/* We've changed pid, inserting a pid event */
	event_pid = scribe_alloc_event(SCRIBE_EVENT_PID);
	if (!event_pid)
		return ERR_PTR(-ENOMEM);

	event_pid->pid = queue->pid;
	dev->last_pid = queue->pid;

	return (struct scribe_event *)event_pid;
}

static ssize_t dev_read(struct file *file,
			char __user *buf, size_t count, loff_t * ppos)
{
	struct scribe_dev *dev = file->private_data;
	struct scribe_event_queue *queue;
	struct scribe_event *event;
	long not_written;
	ssize_t ret = 0;
	size_t length;
	char *kbuf;

	/*
	 * FIXME put a mutex around this to protect it against multiple
	 * readers, although it would not make any sense to have multiple
	 * readers.
	 */

	if (dev->ctx->flags & SCRIBE_REPLAY)
		return -EPERM;

	/*
	 * Two cases:
	 * - We are dealing with a partially sent event, we need to pick up
	 *   where we left off.
	 * - In the other case, we'll just grab the next non empty queue.
	 */
	event = dev->pending_event;
	if (event) {
		dev->pending_event = NULL;
		queue = NULL;
	} else {
		queue = get_non_empty_queue(dev, SCRIBE_WAIT);
		if (IS_ERR(queue)) {
			ret = PTR_ERR(queue);
			if (ret == -ENODEV)
				ret = 0;
			goto out;
		}
	}

	for (;;) {
		if (!event) {
			event = get_next_event(dev, queue);
			if (IS_ERR(event)) {
				ret = ret ? ret : PTR_ERR(event);
				goto out;
			}
		}

		length = sizeof_event_payload(event) - dev->offset;
		kbuf = get_event_payload(event) + dev->offset;

		if (length > count) {
			length = count;
			dev->pending_event = event;
		}
		dev->offset += length;

		not_written = copy_to_user(buf, kbuf, length);
		if (not_written) {
			dev->offset -= not_written;
			ret += length - not_written;

			dev->pending_event = event;

			ret = ret ? : -EFAULT;
			goto out;
		}

		ret += length;
		if (dev->pending_event)
			goto out;

		scribe_free_event(event);
		event = NULL;
		dev->offset = 0;

		buf += length;
		count -= length;

		queue = get_non_empty_queue(dev, SCRIBE_NO_WAIT);
		if (IS_ERR(queue))
			goto out;
	}

out:
	return ret;
}

static int dev_open(struct inode *inode, struct file *file)
{
	struct scribe_dev *dev;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->ctx = scribe_alloc_context();
	if (!dev->ctx) {
		kfree(dev);
		return -ENOMEM;
	}

	file->private_data = dev;

	return 0;
}

static int dev_release(struct inode *inode, struct file *file)
{
	struct scribe_dev *dev = file->private_data;

	if (dev->pending_event)
		scribe_free_event(dev->pending_event);
	if (dev->pre_alloc_queue)
		scribe_put_queue(dev->last_queue);
	if (dev->last_queue)
		scribe_put_queue(dev->last_queue);

	scribe_exit_context(dev->ctx);
	kfree(dev);
	return 0;
}

static int dev_ioctl(struct inode *inode, struct file *file,
		     unsigned int num, unsigned long arg)
{
	struct scribe_dev *dev = file->private_data;
	struct scribe_context *ctx = dev->ctx;

	switch (num) {
	case SCRIBE_IO_SET_STATE:
		return scribe_set_state(ctx, arg);
	case SCRIBE_IO_ATTACH_ON_EXEC:
		return scribe_set_attach_on_exec(ctx, arg);
	}

	return -ENOIOCTLCMD;
}

static const struct file_operations scribe_fops = {
	.read    = dev_read,
	.write   = dev_write,
	.open    = dev_open,
	.release = dev_release,
	.ioctl   = dev_ioctl
};

int __init scribe_init_device(void)
{
	struct class *cls;
	struct device *dev;

	if (register_chrdev(SCRIBE_MAJOR, SCRIBE_DEVICE_NAME, &scribe_fops))
		return -EBUSY;

	cls = class_create(THIS_MODULE, SCRIBE_DEVICE_NAME);
	if (IS_ERR(cls)) {
		unregister_chrdev(SCRIBE_MAJOR, SCRIBE_DEVICE_NAME);
		return PTR_ERR(cls);
	}

	dev = device_create(cls, NULL, MKDEV(SCRIBE_MAJOR, 0),
			    NULL, SCRIBE_DEVICE_NAME);
	if (IS_ERR(dev)) {
		unregister_chrdev(SCRIBE_MAJOR, SCRIBE_DEVICE_NAME);
		class_destroy(cls);
		return PTR_ERR(dev);
	}

	return 0;
}
