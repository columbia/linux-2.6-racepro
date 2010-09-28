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
#include <asm/uaccess.h>

struct scribe_dev {
	struct scribe_context *ctx;
	struct scribe_event_queue *last_queue;
	struct scribe_event *pending_event;
	unsigned long offset;
	pid_t last_pid;
};

static inline size_t sizeof_raw_event(struct scribe_event *event)
{
	return sizeof_event(event) - offsetof(typeof(*event), raw_offset);
}

static inline char *get_raw_event(struct scribe_event *event)
{
	return (char*)event + offsetof(typeof(*event), raw_offset);
}

static ssize_t dev_write(struct file *file,
			 const char __user *buf, size_t count, loff_t *ppos)
{
	return 0;
}

/* Returns the first non empty queue, -ENODEV if the queue list is empty and
 * will stay empty, -EAGAIN if at least one queue is present and all queues
 * are empty
 *
 * Note: scribe_get_non_empty_queue() also remove dead queues.
 */
static struct scribe_event_queue *
get_non_empty_queue(struct scribe_context *ctx)
{
	struct scribe_event_queue *queue;
	int ret = -EAGAIN;

retry:
	spin_lock(&ctx->queues_lock);
	list_for_each_entry(queue, &ctx->queues, node) {
		if (!scribe_is_queue_empty(queue)) {
			scribe_get_queue(queue);
			spin_unlock(&ctx->queues_lock);
			return queue;
		}

		/* If the queue is set to wont_grow, we don't want to detach
		 * it twice. Hence the check for SCRIBE_CTX_DETACHED.
		 */
		if (queue->flags &= (SCRIBE_WONT_GROW | SCRIBE_CTX_DETACHED) ==
		    SCRIBE_WONT_GROW) {
			queue->flags |= SCRIBE_CTX_DETACHED;

			spin_unlock(&ctx->queues_lock);
			scribe_put_queue(queue);
			goto retry;
		}
		continue;
	}

	if (list_empty(&ctx->queues)) {
		/* There are no queues in the context, which means that there
		 * are no tasks attached as well. Thus the context flag is
		 * either set to:
		 * - SCRIBE_IDLE: the recording is over, and so we want
		 *   dev_read() to return 0
		 * - SCRIBE_RECORD: the recording has not started yet, we want
		 *   to wait.
		 */
		ret = (ctx->flags == SCRIBE_IDLE) ? -ENODEV : -EAGAIN;
	}

	spin_unlock(&ctx->queues_lock);
	return ERR_PTR(ret);
}

static struct scribe_event_queue *
get_non_empty_queue_wait(struct scribe_dev *dev)
{
	struct scribe_context *ctx = dev->ctx;
	struct scribe_event_queue *queue;
	int ret;

	queue = dev->last_queue;
	if (queue && !scribe_is_queue_empty(queue))
		return queue;

	if (queue) {
		scribe_put_queue(queue);
		dev->last_queue = NULL;
	}

	ret = wait_event_interruptible(
		ctx->queues_wait,
		((queue = get_non_empty_queue(ctx)) != ERR_PTR(-EAGAIN)));
	if (ret)
		return ERR_PTR(-ERESTARTSYS);

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
		event = scribe_try_dequeue_event(queue);
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
	struct scribe_context *ctx = dev->ctx;
	struct scribe_event_queue *queue;
	struct scribe_event *event;
	long not_written;
	ssize_t ret = 0;
	size_t length;
	char *kbuf;

	/* FIXME put a mutex around this to protect it against multiple
	 * readers, although it would not make sense.
	 */

	if (!(ctx->flags &= SCRIBE_RECORD))
		return -EPERM;

	/* Maybe we had an even half-sent. We'll pick up where we left off,
	 * or we'll get the next non empty queue
	 */
	event = dev->pending_event;
	if (event) {
		dev->pending_event = NULL;
		queue = NULL;
	}
	else {
		queue = get_non_empty_queue_wait(dev);
		if (IS_ERR(queue)) {
			ret = PTR_ERR(queue);
			if (ret != -ENODEV)
				ret = 0;
			goto out;
		}
	}

	for (;;) {
		if (!event) {
			event = get_next_event(dev, queue);
			if (IS_ERR(event) && !ret)
				ret = PTR_ERR(event);
			goto out;
		}

		length = sizeof_raw_event(event) - dev->offset;
		kbuf = get_raw_event(event) + dev->offset;

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

			if (!ret)
				ret = -EFAULT;
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

		if (!queue || scribe_is_queue_empty(queue)) {
			queue = get_non_empty_queue(ctx);
			if (IS_ERR(queue))
				goto out;

			scribe_put_queue(dev->last_queue);
			dev->last_queue = queue;
		}
	}

out:
	return ret;
}

static int dev_open(struct inode *inode, struct file *file)
{
	struct scribe_dev *dev;

	dev = kmalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->ctx = scribe_alloc_context();
	if (!dev->ctx) {
		kfree(dev);
		return -ENOMEM;
	}

	dev->last_queue = NULL;
	dev->pending_event = NULL;
	dev->offset = 0;
	dev->last_pid = -1;

	file->private_data = dev;

	return 0;
}

static int dev_release(struct inode *inode, struct file *file)
{
	struct scribe_dev *dev = file->private_data;

	if (dev->pending_event)
		scribe_free_event(dev->pending_event);
	if (dev->last_queue)
		scribe_put_queue(dev->last_queue);

	scribe_exit_context(dev->ctx);
	return 0;
}

static int dev_ioctl(struct inode *inode, struct file *file,
		     unsigned int num, unsigned long arg)
{
	struct scribe_context *ctx = file->private_data;

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
