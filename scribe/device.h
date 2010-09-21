/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#ifndef _SCRIBE_DEVICE_H_
#define _SCRIBE_DEVICE_H_

#include <linux/ioctl.h>
#include <linux/types.h>

#define SCRIBE_DEVICE_NAME "scribe"

#define SCRIBE_IO_MAGIC			0xFF
#define SCRIBE_IO_START_RECORDING	_IOR(SCRIBE_IO_MAGIC,	1, int)
#define SCRIBE_IO_START_REPLAYING	_IOR(SCRIBE_IO_MAGIC,	2, int)
#define SCRIBE_IO_REQUEST_STOP		_IO(SCRIBE_IO_MAGIC,	3)

int scribe_init_device(void);

#endif /*_SCRIBE_DEVICE_H_*/
