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

#ifndef _LINUX_SCRIBE_UACCESS_H_
#define _LINUX_SCRIBE_UACCESS_H_

#define SCRIBE_DATA_INPUT		1
#define SCRIBE_DATA_STRING		2

/*
 * For x86, all user accesses can be probed by hooking on:
 *	get_user
 *	put_user
 *	__get_user_nocheck
 *	__put_user_nocheck
 *	__get_user_size_ex
 *	__put_user_size_ex
 *	__copy_to_user
 *	__copy_from_user
 *
 *	__copy_to_user_inatomic
 *	__copy_from_user_inatomic
 *	__copy_from_user_nocache
 *	__copy_from_user_inatomic_nocache
 *
 *	__do_strncpy_from_user
 *	__do_clear_user
 *	strnlen_user
 */


#ifdef CONFIG_SCRIBE

/* FIXME Those two functions should be inlined */
extern void scribe_pre_uaccess(const void *data, const void __user *user_ptr,
			       size_t size, int flags);
extern void scribe_post_uaccess(const void *data, const void __user *user_ptr,
				size_t size, int flags);

#else /* CONFIG_SCRIBE */

static inline void scribe_pre_uaccess(const void *data,
				      const void __user *user_ptr, size_t size,
				      int flags) {}
static inline void scribe_post_uaccess(const void *data,
				       const void __user *user_ptr,
				       size_t size, int flags) {}

#endif /* CONFIG_SCRIBE */

#endif /* _LINUX_SCRIBE_UACCESS_H_ */
