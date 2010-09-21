/*
 *  scribe/device.c - provide the scribe device
 *
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/fs.h>
#include <linux/major.h>
#include <linux/device.h>
#include "device.h"

static ssize_t dev_write(struct file *file,
			 const char __user *buf, size_t count, loff_t *ppos)
{
	return 0;
}

static ssize_t dev_read(struct file *file,
			char __user *buf, size_t count, loff_t * ppos)
{
	return 0;
}

static int dev_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int dev_release(struct inode *inode, struct file *file)
{
	return 0;
}

static int dev_ioctl(struct inode *inode, struct file *file,
		     unsigned int ioctl_num, unsigned long ioctl_param)
{
	return 0;
}

static struct file_operations scribe_fops = {
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
