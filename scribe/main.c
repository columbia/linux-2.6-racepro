/*
 *  scribe/main.c - Scribe initialization
 *
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/init.h>
#include <linux/module.h>
#include "device.h"

static int __init scribe_init(void)
{
	int err;

	if ((err = scribe_init_device()))
		return err;
	return 0;
}

device_initcall(scribe_init);
