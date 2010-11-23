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
#include <linux/file.h>
#include <linux/major.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/scribe.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/kthread.h>
#include <linux/splice.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/completion.h>

#define PUMP_BUFFER_ORDER 2
#define PUMP_BUFFER_SIZE (PAGE_SIZE << PUMP_BUFFER_ORDER)

struct scribe_dev {
	struct scribe_context *ctx;
	struct mutex lock_read;
	struct mutex lock_write;
	struct task_struct *kthread_event_pump;
	struct completion pump_done;
	char *pump_buffer;
	struct file *log_file;
	struct scribe_event *pending_notification_event;
};

static inline size_t sizeof_event_payload(struct scribe_event *event)
{
	return sizeof_event(event) - offsetof(typeof(*event), payload_offset);
}

static inline char *get_event_payload(struct scribe_event *event)
{
	return (char *)(event->payload_offset);
}

static inline int is_interrupted(int ret)
{
	return ret == -ERESTARTSYS ||
		ret == -ERESTARTNOINTR ||
		ret == -ERESTARTNOHAND ||
		ret == -ERESTART_RESTARTBLOCK ||
		ret == -EINTR;
}

/* Record */

static inline int is_queue_active(struct scribe_queue *queue)
{
	return !scribe_is_stream_empty(&queue->stream) ||
		queue->stream.wont_grow;
}

/*
 * __get_active_queue() tries to find the the next non empty queue, or ready
 * to be ripped off. Returns -ENODATA if the queue list is empty and will stay
 * empty, -EAGAIN if at least one queue is present and all queues are empty
 * (or that we are waiting for the recording to start).
 */
static int __get_active_queue(struct scribe_context *ctx,
			      struct scribe_queue **current_queue)
{
	struct scribe_queue *queue;
	int ret = 0;

	queue = *current_queue;
	if (queue && is_queue_active(queue))
		return 0;

	spin_lock(&ctx->queues_lock);
	queue = list_prepare_entry(queue, &ctx->queues, node);
	list_for_each_entry_continue(queue, &ctx->queues, node) {
		if (is_queue_active(queue)) {
			scribe_get_queue(queue);
			goto out;
		}
	}

	queue = NULL;
	ret = -EAGAIN;
	if (list_empty(&ctx->queues)) {
		/*
		 * There are no more queues in the context, which means that
		 * there are no tasks attached as well. Thus the context
		 * status is either set to:
		 * - SCRIBE_IDLE: the recording is over, and so we want
		 *   serialize_events() to return 0
		 * - SCRIBE_RECORD: the recording has not started yet, we want
		 *   to wait.
		 */
		if (ctx->flags == SCRIBE_IDLE)
			ret = -ENODATA;
	}
out:
	spin_unlock(&ctx->queues_lock);

	if (*current_queue)
		scribe_put_queue(*current_queue);
	*current_queue = queue;

	return ret;
}

static int get_active_queue(struct scribe_context *ctx,
			    struct scribe_queue **current_queue,
			    int wait)
{
	int ret;

	if (wait == SCRIBE_NO_WAIT)
		return __get_active_queue(ctx, current_queue);

	wait_event(ctx->queues_wait,
		   (ret = __get_active_queue(ctx, current_queue)) != -EAGAIN);

	return ret;
}

/*
 * get_next_event() returns in most cases the next event on the
 * @current_queue. When switching queues, it returns a PID event, and when the
 * queue is dead, it returned a QUEUE_EOF event.
 *
 * Note: This is where queues get to be freed when dead
 */
static int get_next_event(pid_t *last_pid, struct scribe_event **event,
			  struct scribe_queue **current_queue)
{
	struct scribe_queue *queue;
	struct scribe_event_pid *event_pid;
	struct scribe_event_queue_eof *event_eof;

	queue = *current_queue;

	if (unlikely(*last_pid != queue->pid)) {
		/* We've changed pid, inserting a pid event */
		event_pid = scribe_alloc_event(SCRIBE_EVENT_PID);
		if (!event_pid)
			return -ENOMEM;

		event_pid->pid = queue->pid;
		*last_pid = queue->pid;

		*event = (struct scribe_event *)event_pid;
	} else if (likely(!scribe_is_stream_empty(&queue->stream))) {
		*event = scribe_dequeue_event(queue, SCRIBE_NO_WAIT);
	} else {
		BUG_ON(!&queue->stream.wont_grow);

		event_eof = scribe_alloc_event(SCRIBE_EVENT_QUEUE_EOF);
		if (!event_eof)
			return -ENOMEM;

		*event = (struct scribe_event *)event_eof;

		/*
		 * When the queue is empty and set to not growing, we can
		 * consider it as dead. Releasing our persistent token on it
		 * will make the queue go away if the associated process
		 * detaches.
		 */
		spin_lock(&queue->ctx->queues_lock);
		scribe_unset_persistent(queue);
		spin_unlock(&queue->ctx->queues_lock);

		scribe_put_queue(queue);
		*current_queue = NULL;
	}

	return 0;
}

static ssize_t serialize_events(struct scribe_context *ctx,
				char *buf, size_t count,
				pid_t *last_pid,
				struct scribe_queue **current_queue,
				struct scribe_event **pending_event,
				size_t *pending_offset)
{
	struct scribe_event *event;
	size_t to_write;
	ssize_t ret = 0;
	int err = 0;

	/*
	 * Two cases:
	 * - We are dealing with a partially sent event, we need to pick up
	 *   where we left off.
	 * - In the other case, we'll just grab the next event on the next non
	 *   empty queue.
	 */
	event = *pending_event;
	*pending_event = NULL;
	if (!event) {
		err = get_active_queue(ctx, current_queue, SCRIBE_WAIT);
		if (err) {
			/*
			 * if err == -ENODATA, it means that the context is in
			 * idle state and that the queue list is empty.
			 * It's time for EOF
			 */
			if (err == -ENODATA)
				err = 0;
			goto out;
		}
	}

	for (;;) {
		if (!event) {
			err = get_next_event(last_pid, &event, current_queue);
			if (err)
				goto out;
		}

		to_write = sizeof_event_payload(event) - *pending_offset;
		if (to_write > count) {
			to_write = count;
			*pending_event = event;
		}
		memcpy(buf,
		       get_event_payload(event) + *pending_offset, to_write);
		ret += to_write;

		if (*pending_event) {
			*pending_offset += to_write;
			goto out;
		}

		scribe_free_event(event);
		event = NULL;
		*pending_offset = 0;

		buf += to_write;
		count -= to_write;

		err = get_active_queue(ctx, current_queue, SCRIBE_NO_WAIT);
		if (err)
			goto out;
	}

out:
	if (ret)
		return ret;
	return err;
}

static void event_pump_record(struct scribe_context *ctx,
			      char *buf, struct file *file)
{
	struct scribe_queue *current_queue = NULL;
	struct scribe_event *pending_event = NULL;
	size_t pending_offset = 0;
	pid_t last_pid = 0;

	int buffer_full = 0;
	ssize_t ret;
	size_t to_write;
	char *write_buf;

	while (!kthread_should_stop()) {
		/*
		 * Looping here on every event is inefficient.
		 * We are waiting one second on each full iteration.
		 * And instant return when the context goes idle
		 */
		if (!buffer_full) {
			wait_event_timeout(ctx->tasks_wait,
					   ctx->flags == SCRIBE_IDLE, HZ);
		}

		ret = serialize_events(ctx, buf, PUMP_BUFFER_SIZE,
				       &last_pid, &current_queue,
				       &pending_event, &pending_offset);
		if (ret < 0)
			goto err;
		if (!ret)
			break;

		buffer_full = ret == PUMP_BUFFER_SIZE;

		to_write = ret;
		write_buf = buf;
		while (to_write) {
			ret = kernel_write(file,
					   write_buf, to_write, file->f_pos);
			if (unlikely(is_interrupted(ret)))
				continue;

			if (ret < 0)
				goto err;

			to_write -= ret;
			write_buf += ret;
			file->f_pos += ret;
		}
	}
free:
	if (current_queue)
		scribe_put_queue(current_queue);
	if (pending_event)
		scribe_free_event(pending_event);
	return;
err:
	scribe_emergency_stop(ctx, ERR_PTR(ret));
	goto free;
}

/* Replay */

static int handle_event_pid(struct scribe_context *ctx,
			    struct scribe_event *event,
			    struct scribe_queue **current_queue,
			    struct scribe_queue **pre_alloc_queue)
{
	pid_t pid = ((struct scribe_event_pid *)event)->pid;

	if (!*pre_alloc_queue) {
		*pre_alloc_queue = kmalloc(sizeof(**pre_alloc_queue),
					   GFP_KERNEL);
		if (!*pre_alloc_queue)
			return -ENOMEM;
	}

	if (*current_queue)
		scribe_put_queue(*current_queue);
	*current_queue = scribe_get_queue_by_pid(ctx, pre_alloc_queue, pid);
	return 0;
}

static ssize_t get_sized_event_size(const char *buf, size_t count)
{
	struct scribe_event_sized *event;
	typeof(event->size) size = 0;
	int size_offset;

	size_offset = offsetof(struct scribe_event_sized, size)
		    - offsetof(struct scribe_event_sized, h.payload_offset);

	if (count < size_offset + sizeof(size))
		return -EINVAL;
	return *(typeof(size) *)(buf + size_offset);
}

static int alloc_next_event(const char *buf, size_t count,
			    struct scribe_event **event)
{
	typeof((*event)->type) type;
	ssize_t size;

	if (sizeof(type) > count)
		return -EAGAIN;
	type = *(typeof(type) *)buf;

	if (is_sized_type(type)) {
		size = get_sized_event_size(buf, count);
		if (size < 0)
			return size;
		*event = scribe_alloc_event_sized(type, size);
	} else {
		*event = scribe_alloc_event(type);
	}

	if (!*event)
		return -ENOMEM;

	return 0;
}

static ssize_t deserialize_events(struct scribe_context *ctx, const char *buf,
				  size_t count, loff_t file_pos,
				  struct scribe_queue **current_queue,
				  struct scribe_queue **pre_alloc_queue,
				  struct scribe_event **pending_event,
				  size_t *pending_offset)
{
	struct scribe_event *event = NULL;
	size_t to_copy;
	ssize_t ret = 0;
	int err = 0;

	event = *pending_event;
	*pending_event = NULL;

	for (;;) {
		if (!event) {
			err = alloc_next_event(buf, count, &event);
			if (err)
				goto out;
			event->log_offset = file_pos;
		}

		to_copy = sizeof_event_payload(event) - *pending_offset;

		if (to_copy > count) {
			to_copy = count;
			*pending_event = event;
		}
		memcpy(get_event_payload(event) + *pending_offset,
		       buf, to_copy);

		if (*pending_event) {
			ret += to_copy;
			*pending_offset += to_copy;
			goto out;
		}
		*pending_offset = 0;

		if (event->type == SCRIBE_EVENT_PID) {
			err = handle_event_pid(ctx, event,
					       current_queue, pre_alloc_queue);
			scribe_free_event(event);
			if (err)
				goto out;
		} else if (event->type == SCRIBE_EVENT_QUEUE_EOF) {
			scribe_set_stream_wont_grow(&(*current_queue)->stream);
			scribe_free_event(event);
		} else { /* generic event handling */
			scribe_queue_event(*current_queue, event);
		}

		event = NULL;
		ret += to_copy;
		buf += to_copy;
		count -= to_copy;
		file_pos += to_copy;
	}

out:
	if (ret)
		return ret;
	return err;
}

/*
 * event_pump_replay() reads from @file to @buf, and call deserialize_events()
 * to instantiate each event.
 */
static void event_pump_replay(struct scribe_context *ctx, char *buf,
			      struct file *file)

{
	struct scribe_queue *queue;
	struct scribe_queue *current_queue = NULL;
	struct scribe_queue *pre_alloc_queue = NULL;
	struct scribe_event *pending_event = NULL;
	size_t pending_offset = 0;
	size_t count = 0;
	loff_t old_f_pos;
	ssize_t ret = 0;

	while (!kthread_should_stop()) {
		ret = kernel_read(file, file->f_pos,
				  buf + count,
				  PUMP_BUFFER_SIZE - count);

		if (unlikely(is_interrupted(ret)))
			continue;
		if (!ret) {
			/*
			 * We might have a pending event in our buffer (count
			 * is not 0), which means something is went wrong.
			 * Otherwise, we've reached EOF.
			 */
			if (count)
				ret = -EPIPE;
			break;
		}
		if (ret < 0)
			break;

		old_f_pos = file->f_pos;

		file->f_pos += ret;
		count += ret;

		ret = deserialize_events(ctx, buf, count, old_f_pos,
					 &current_queue, &pre_alloc_queue,
					 &pending_event, &pending_offset);
		if (ret < 0)
			break;

		BUG_ON(!ret);
		count -= ret;
		if (count) {
			/*
			 * Only a portion of the buffer has been processed, it
			 * will get processed on the next round.
			 */
			memmove(buf, buf + ret, count);
		}
	}

	spin_lock(&ctx->queues_lock);
	list_for_each_entry(queue, &ctx->queues, node) {
		/*
		 * If some queue were left open, that means that we didn't
		 * have the entire event stream, we need to kill the context.
		 */
		if (!ret && !queue->stream.wont_grow)
			ret = -EPIPE;
		if (ret)
			scribe_set_stream_wont_grow(&queue->stream);
	}
	ctx->queues_wont_grow = 1;
	spin_unlock(&ctx->queues_lock);

	if (ret)
		scribe_emergency_stop(ctx, ERR_PTR(ret));

	if (current_queue)
		scribe_put_queue(current_queue);
	kfree(pre_alloc_queue);
	scribe_free_event(pending_event);
}

/*
 * We need a kthread for performance reasons: consider a single process
 * getting recorded. When that process queues some events in its queue, we
 * want it to immediately return to work, and the actual serialization will
 * happen on another CPU.
 */
static int kthread_event_pump(void *_dev)
{
	struct scribe_dev *dev = _dev;
	struct scribe_context *ctx = dev->ctx;

	if (ctx->flags & SCRIBE_RECORD)
		event_pump_record(ctx, dev->pump_buffer, dev->log_file);
	else if (ctx->flags & SCRIBE_REPLAY)
		event_pump_replay(ctx, dev->pump_buffer, dev->log_file);
	else
		BUG();

	fput(dev->log_file);

	complete(&dev->pump_done);

	do_exit(0);
}

static void stop_event_pump(struct scribe_dev *dev)
{
	if (!dev->kthread_event_pump)
		return;

	scribe_emergency_stop(dev->ctx, ERR_PTR(-EINTR));

	kthread_stop(dev->kthread_event_pump);
	put_task_struct(dev->kthread_event_pump);
	dev->kthread_event_pump = NULL;
}

static int do_start(struct scribe_dev *dev, int state, int log_fd,
		    unsigned int backtrace_len)
{
	int ret;

	if (backtrace_len < 0)
		return -EINVAL;

	stop_event_pump(dev);
	dev->kthread_event_pump = kthread_create(kthread_event_pump, dev,
						 "scribe%d", dev->ctx->id);
	if (IS_ERR(dev->kthread_event_pump)) {
		ret = PTR_ERR(dev->kthread_event_pump);
		dev->kthread_event_pump = NULL;
		goto err;
	}
	get_task_struct(dev->kthread_event_pump);

	ret = -EBADF;
	dev->log_file = fget(log_fd);
	if (!dev->log_file)
		goto err_kthread;

	if (state == SCRIBE_RECORD)
		ret = scribe_start_record(dev->ctx);
	else
		ret = scribe_start_replay(dev->ctx, backtrace_len);
	if (ret)
		goto err_file;

	INIT_COMPLETION(dev->pump_done);

	wake_up_process(dev->kthread_event_pump);
	return 0;

err_file:
	fput(dev->log_file);
err_kthread:
	stop_event_pump(dev);
err:
	return ret;
}

static int handle_command(struct scribe_dev *dev, struct scribe_event *event)
{
	struct scribe_event_record *event_record;
	struct scribe_event_replay *event_replay;

	switch (event->type) {
	case SCRIBE_EVENT_ATTACH_ON_EXECVE:
		return scribe_set_attach_on_exec(dev->ctx,
		      ((struct scribe_event_attach_on_execve *)event)->enable);
	case SCRIBE_EVENT_RECORD:
		event_record = ((struct scribe_event_record *)event);
		return do_start(dev, SCRIBE_RECORD,
				event_record->log_fd, 0);
	case SCRIBE_EVENT_REPLAY:
		event_replay = ((struct scribe_event_replay *)event);
		return do_start(dev, SCRIBE_REPLAY,
				event_replay->log_fd,
				event_replay->backtrace_len);
	case SCRIBE_EVENT_STOP:
		return scribe_stop(dev->ctx);
	default:
		return -EINVAL;
	}
}

static ssize_t dev_write(struct file *file,
			 const char __user *buf, size_t count, loff_t *ppos)
{
	struct scribe_dev *dev = file->private_data;
	struct scribe_event *event;
	typeof(event->type) type;
	size_t to_copy;
	ssize_t ret;

	if (count < sizeof(type))
		return -EINVAL;
	if (get_user(type, buf))
		return -EFAULT;

	if (is_sized_type(type))
		return -EINVAL;

	event = scribe_alloc_event(type);
	if (!event)
		return -ENOMEM;

	to_copy = sizeof_event_payload(event);
	if (count != to_copy) {
		scribe_free_event(event);
		return -EINVAL;
	}

	if (copy_from_user(get_event_payload(event), buf, to_copy)) {
		scribe_free_event(event);
		return -EFAULT;
	}
	event->type = type; /* guard against TOCTTOU */

	mutex_lock(&dev->lock_write);
	ret = handle_command(dev, event);
	mutex_unlock(&dev->lock_write);

	scribe_free_event(event);
	if (ret)
		return ret;
	return to_copy;
}

static ssize_t dev_read(struct file *file,
			char __user *buf, size_t count, loff_t * ppos)
{
	struct scribe_dev *dev = file->private_data;
	struct scribe_context *ctx = dev->ctx;
	struct scribe_event *event;
	ssize_t err;
	size_t to_copy = 0;

	mutex_lock(&dev->lock_read);
	event = dev->pending_notification_event;
	if (!event) {
		event = scribe_dequeue_event_stream(&ctx->notifications,
						    SCRIBE_WAIT_INTERRUPTIBLE);
		if (IS_ERR(event)) {
			err = PTR_ERR(event);
			event = NULL;
			goto out;
		}
	}

	if (event->type == SCRIBE_EVENT_CONTEXT_IDLE) {
		err = -ERESTARTSYS;
		if (wait_for_completion_interruptible(&dev->pump_done))
			goto out;
	}

	to_copy = sizeof_event_payload(event);
	err = -EINVAL;
	if (count < to_copy)
		goto out;
	err = -EFAULT;
	if (copy_to_user(buf, get_event_payload(event), to_copy))
		goto out;

	scribe_free_event(event);
	event = NULL;
	err = 0;

out:
	dev->pending_notification_event = event;
	mutex_unlock(&dev->lock_read);
	if (err)
		return err;
	return to_copy;
}

static int dev_open(struct inode *inode, struct file *file)
{
	struct scribe_dev *dev;
	int ret;

	ret = -ENOMEM;
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		goto out;

	mutex_init(&dev->lock_read);
	mutex_init(&dev->lock_write);

	dev->ctx = scribe_alloc_context();
	if (!dev->ctx)
		goto out_dev;

	dev->pump_buffer = (char *)__get_free_pages(GFP_KERNEL,
						    PUMP_BUFFER_ORDER);
	if (!dev->pump_buffer)
		goto out_ctx;

	init_completion(&dev->pump_done);

	file->private_data = dev;
	return 0;

out_ctx:
	scribe_exit_context(dev->ctx);
out_dev:
	mutex_destroy(&dev->lock_read);
	mutex_destroy(&dev->lock_write);
	kfree(dev);
out:
	return ret;
}

static int dev_release(struct inode *inode, struct file *file)
{
	struct scribe_dev *dev = file->private_data;

	stop_event_pump(dev);
	free_pages((unsigned long)dev->pump_buffer, PUMP_BUFFER_ORDER);
	if (dev->pending_notification_event)
		scribe_free_event(dev->pending_notification_event);
	scribe_exit_context(dev->ctx);
	mutex_destroy(&dev->lock_read);
	mutex_destroy(&dev->lock_write);
	kfree(dev);
	return 0;
}

static const struct file_operations scribe_fops = {
	.read    = dev_read,
	.write   = dev_write,
	.open    = dev_open,
	.release = dev_release,
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
