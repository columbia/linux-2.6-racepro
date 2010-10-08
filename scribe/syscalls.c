/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/scribe.h>

void scribe_enter_syscall(struct pt_regs *regs)
{
	struct scribe_ps *scribe = current->scribe;
	int nr;

	if (!is_scribbed(scribe))
		return;

	nr = regs->orig_ax;
	printk("scribe: Entering syscall %d\n", nr);
}

void scribe_exit_syscall(struct pt_regs *regs)
{
	struct scribe_ps *scribe = current->scribe;
	int nr;

	if (!is_scribbed(scribe))
		return;

	nr = regs->orig_ax;
	printk("scribe: Exiting syscall %d\n", nr);
}
