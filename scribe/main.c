/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/scribe.h>

extern int scribe_init_device(void);

struct proc_dir_entry *scribe_proc_root;

#ifdef CONFIG_PROC_FS
static int __init scribe_init_proc(void)
{
	struct proc_dir_entry *p;

	p = create_proc_entry("scribe", S_IFDIR | S_IRUGO | S_IXUGO, NULL);
	if (!p)
		return -ENOMEM;
	scribe_proc_root = p;
	return 0;
}
#else
static inline int __init scribe_init_proc(void) { return 0; }
#endif /* CONFIG_PROC_FS */

static int __init scribe_init(void)
{
	int err;

	/* TODO clean exit path */
	if ((err = scribe_init_proc()))
		return err;
	if ((err = scribe_init_device()))
		return err;
	return 0;
}

device_initcall(scribe_init);
