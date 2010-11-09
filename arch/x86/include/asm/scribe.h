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

#ifndef _ASM_X86_RESOURCE_H_
#define _ASM_X86_RESOURCE_H_

#ifdef CONFIG_SCRIBE

struct scribe_ps_arch {
	int tsc_disabled;
};

struct scribe_ps;
extern int init_scribe_arch(struct scribe_ps *scribe);
extern void exit_scribe_arch(struct scribe_ps *scribe);
extern void scribe_attach_arch(struct scribe_ps *scribe);
extern void scribe_detach_arch(struct scribe_ps *scribe);

extern int scribe_handle_rdtsc(struct scribe_ps *scribe, struct pt_regs *regs);

#endif /* CONFIG_SCRIBE */

#endif /* _ASM_X86_RESOURCE_H_ */
