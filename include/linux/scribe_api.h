/*
 *  Scribe, the record/replay mechanism
 *
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#ifndef _LINUX_SCRIBE_API_H
#define _LINUX_SCRIBE_API_H


#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/list.h>

#else

#include <sys/types.h>
#ifndef __always_inline
#define __always_inline inline
#endif

#endif /* __KERNEL__ */


#define SCRIBE_IDLE		0x00000000
#define SCRIBE_RECORD		0x00000001
#define SCRIBE_REPLAY		0x00000002
#define SCRIBE_STOP		0x00000004
#define SCRIBE_DEAD		0x80000000

#define SCRIBE_DEVICE_NAME		"scribe"
#define SCRIBE_IO_MAGIC			0xFF
#define SCRIBE_IO_SET_STATE		_IOR(SCRIBE_IO_MAGIC,	1, int)
#define SCRIBE_IO_ATTACH_ON_EXEC	_IOR(SCRIBE_IO_MAGIC,	2, int)


enum scribe_event_type {
	SCRIBE_EVENT_PID = 1,
	SCRIBE_EVENT_DATA,
	SCRIBE_EVENT_SYSCALL,
};

struct scribe_event {
#ifdef __KERNEL__
	struct list_head node;
	char raw_offset[0];
#endif
	__u8 type;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_PID struct scribe_event_pid
struct scribe_event_pid {
	struct scribe_event h;
	__u32 pid;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_DATA struct scribe_event_data
struct scribe_event_data {
	struct scribe_event h;
	__u32 size;
	__u8 data[0];
	__u32 ldata[0];
} __attribute__((packed));

#define struct_SCRIBE_EVENT_SYSCALL struct scribe_event_syscall
struct scribe_event_syscall {
	struct scribe_event h;
	__u16 nr;
	__u32 ret; /* FIXME 64 bit support ? */
} __attribute__((packed));

void __you_are_using_an_unknown_scribe_type(void);
/* XXX Data events have a variable size. This additional payload
 * is NOT accounted here.
 */
static __always_inline size_t sizeof_event_from_type(__u8 type)
{
#define __TYPE(t) if (type == t) return sizeof(struct_##t);
	__TYPE(SCRIBE_EVENT_PID);
	__TYPE(SCRIBE_EVENT_DATA);
	__TYPE(SCRIBE_EVENT_SYSCALL);
#undef  __TYPE

	if (__builtin_constant_p(type))
		__you_are_using_an_unknown_scribe_type();

	return (size_t)-1;
}

static inline size_t sizeof_event(struct scribe_event *event)
{
	return sizeof_event_from_type(event->type);
}

#endif /* _LINUX_SCRIBE_API_H_ */

