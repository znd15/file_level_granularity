

/*
 * linux/arch/arm/mm/fault.c
 *
 * Copyright (C) 1995 Linus Torvalds
 * Modifications for ARM processor (c) 1995-2004 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/signal.h>
#include <linux/mm.h>
#include <linux/hardirq.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/page-flags.h>
#include <linux/sched.h>
#include <linux/highmem.h>
#include <linux/perf_event.h>

#include <asm/system.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include "fault.h"

/*
 * Fault status register encodings. We steal bit 31 for our own purposes.
 */
#define FSR_LNX_PF (1 << 31)
#define FSR_WRITE (1 << 11)
#define FSR_FS4 (1 << 10)
#define FSR_FS3_0 (15)

static inline int fsr_fs(unsigned int fsr)
{
	return (fsr & FSR_FS3_0) | (fsr & FSR_FS4) >> 6;
}

#ifdef CONFIG_MMU

#ifdef CONFIG_KPROBES
static inline int notify_page_fault(struct pt_regs *regs, unsigned int fsr)
{
	int ret = 0;

	if (!user_mode(regs)) {
		/* kprobe_running() needs smp_processor_id() */
		preempt_disable();
		if (kprobe_running() && kprobe_fault_handler(regs, fsr))
			ret = 1;
		preempt_enable();
	}

	return ret;
}
#else
static inline int notify_page_fault(struct pt_regs *regs, unsigned int fsr)
{
	return 0;
}
#endif

/*
 * This is useful to dump out the page tables associated with
 * 'addr' in mm 'mm'.
 */
void show_pte(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;

	if (!mm)
		mm = &init_mm;

	printk(KERN_ALERT "pgd = %p\n", mm->pgd);
	pgd = pgd_offset(mm, addr);
	printk(KERN_ALERT "[%08lx] *pgd=%08llx",
			addr, (long long)pgd_val(*pgd));

	do {
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;

		if (pgd_none(*pgd))
			break;

		if (pgd_bad(*pgd)) {
			printk("(bad)");
			break;
		}

		pud = pud_offset(pgd, addr);
		if (PTRS_PER_PUD != 1)
			printk(", *pud=%08lx", pud_val(*pud));

		if (pud_none(*pud))
			break;

		if (pud_bad(*pud)) {
			printk("(bad)");
			break;
		}

		pmd = pmd_offset(pud, addr);
		if (PTRS_PER_PMD != 1)
			printk(", *pmd=%08llx", (long long)pmd_val(*pmd));

		if (pmd_none(*pmd))
			break;

		if (pmd_bad(*pmd)) {
			printk("(bad)");
			break;
		}

		/* We must not map this if we have highmem enabled */
		if (PageHighMem(pfn_to_page(pmd_val(*pmd) >> PAGE_SHIFT)))
			break;

		pte = pte_offset_map(pmd, addr);
		printk(", *pte=%08llx", (long long)pte_val(*pte));
		printk(", *ppte=%08llx",
		       (long long)pte_val(pte[PTE_HWTABLE_PTRS]));
		pte_unmap(pte);
	} while(0);

	printk("\n");
}
#else					/* CONFIG_MMU */
void show_pte(struct mm_struct *mm, unsigned long addr)
{ }
#endif					/* CONFIG_MMU */

/*
 * Oops. The kernel tried to access some page that wasn't present.
 */
static void
__do_kernel_fault(struct mm_struct *mm, unsigned long addr, unsigned int fsr,
		  struct pt_regs *regs)
{
	/*
 * Are we prepared to handle this kernel fault?
 */
	if (fixup_exception(regs))
		return;

	/*
 * No handler, we'll have to terminate things with extreme prejudice.
 */
	bust_spinlocks(1);
	printk(KERN_ALERT
		"Unable to handle kernel %s at virtual address %08lx\n",
		(addr < PAGE_SIZE) ? "NULL pointer dereference" :
		"paging request", addr);

	show_pte(mm, addr);
	die("Oops", regs, fsr);
	bust_spinlocks(0);
	do_exit(SIGKILL);
}

/*
 * Something tried to access memory that isn't in our memory map..
 * User mode accesses just cause a SIGSEGV
 */
static void
__do_user_fault(struct task_struct *tsk, unsigned long addr,
		unsigned int fsr, unsigned int sig, int code,
		struct pt_regs *regs)
{
	struct siginfo si;

#ifdef CONFIG_DEBUG_USER
	if (user_debug & UDBG_SEGV) {
		printk(KERN_DEBUG "%s: unhandled page fault (%d) at 0x%08lx, code 0x%03x\n",
		       tsk->comm, sig, addr, fsr);
		show_pte(tsk->mm, addr);
		show_regs(regs);
	}
#endif

	tsk->thread.address = addr;
	tsk->thread.error_code = fsr;
	tsk->thread.trap_no = 14;
	si.si_signo = sig;
	si.si_errno = 0;
	si.si_code = code;
	si.si_addr = (void __user *)addr;
	force_sig_info(sig, &si, tsk);
}

void do_bad_area(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	struct task_struct *tsk = current;
	struct mm_struct *mm = tsk->active_mm;

	/*
 * If we are in kernel mode at this point, we
 * have no context to handle this fault with.
 */
	if (user_mode(regs))
		__do_user_fault(tsk, addr, fsr, SIGSEGV, SEGV_MAPERR, regs);
	else
		__do_kernel_fault(mm, addr, fsr, regs);
}

#ifdef CONFIG_MMU
#define VM_FAULT_BADMAP 0x010000
#define VM_FAULT_BADACCESS 0x020000

/*
 * Check that the permissions on the VMA allow for the fault which occurred.
 * If we encountered a write fault, we must have write permission, otherwise
 * we allow any permission.
 */
static inline bool access_error(unsigned int fsr, struct vm_area_struct *vma)
{
	unsigned int mask = VM_READ | VM_WRITE | VM_EXEC;

	if (fsr & FSR_WRITE)
		mask = VM_WRITE;
	if (fsr & FSR_LNX_PF)
		mask = VM_EXEC;

	return vma->vm_flags & mask ? false : true;
}

static int __kprobes
__do_page_fault(struct mm_struct *mm, unsigned long addr, unsigned int fsr,
		struct task_struct *tsk)
{
	struct vm_area_struct *vma;
	int fault;

	vma = find_vma(mm, addr);
	fault = VM_FAULT_BADMAP;
	if (unlikely(!vma))
		goto out;
	if (unlikely(vma->vm_start > addr))
		goto check_stack;

	/*
 * Ok, we have a good vm_area for this
 * memory access, so we can handle it.
 */
good_area:
	if (access_error(fsr, vma)) {
		fault = VM_FAULT_BADACCESS;
		goto out;
	}

	/*
 * If for any reason at all we couldn't handle the fault, make
 * sure we exit gracefully rather than endlessly redo the fault.
 */
	fault = handle_mm_fault(mm, vma, addr & PAGE_MASK, (fsr & FSR_WRITE) ? FAULT_FLAG_WRITE : 0);
	if (unlikely(fault & VM_FAULT_ERROR))
		return fault;
	if (fault & VM_FAULT_MAJOR)
		tsk->maj_flt++;
	else
		tsk->min_flt++;
	return fault;

check_stack:
	if (vma->vm_flags & VM_GROWSDOWN && !expand_stack(vma, addr))
		goto good_area;
out:
	return fault;
}

static int __kprobes
do_page_fault(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	int fault, sig, code;

	if (notify_page_fault(regs, fsr))
		return 0;

	tsk = current;
	mm  = tsk->mm;

	/*
 * If we're in an interrupt or have no user
 * context, we must not take the fault..
 */
	if (in_atomic() || !mm)
		goto no_context;

	/*
 * As per x86, we may deadlock here. However, since the kernel only
 * validly references user space from well defined areas of the code,
 * we can bug out early if this is from code which shouldn't.
 */
	if (!down_read_trylock(&mm->mmap_sem)) {
		if (!user_mode(regs) && !search_exception_tables(regs->ARM_pc))
			goto no_context;
		down_read(&mm->mmap_sem);
	} else {
		/*
 * The above down_read_trylock() might have succeeded in
 * which case, we'll have missed the might_sleep() from
 * down_read()
 */
		might_sleep();
#ifdef CONFIG_DEBUG_VM
		if (!user_mode(regs) &&
		    !search_exception_tables(regs->ARM_pc))
			goto no_context;
#endif
	}

	fault = __do_page_fault(mm, addr, fsr, tsk);
	up_read(&mm->mmap_sem);

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, 0, regs, addr);
	if (fault & VM_FAULT_MAJOR)
		perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ, 1, 0, regs, addr);
	else if (fault & VM_FAULT_MINOR)
		perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN, 1, 0, regs, addr);

	/*
 * Handle the "normal" case first - VM_FAULT_MAJOR / VM_FAULT_MINOR
 */
	if (likely(!(fault & (VM_FAULT_ERROR | VM_FAULT_BADMAP | VM_FAULT_BADACCESS))))
		return 0;

	if (fault & VM_FAULT_OOM) {
		/*
 * We ran out of memory, call the OOM killer, and return to
 * userspace (which will retry the fault, or kill us if we
 * got oom-killed)
 */
		pagefault_out_of_memory();
		return 0;
	}

	/*
 * If we are in kernel mode at this point, we
 * have no context to handle this fault with.
 */
	if (!user_mode(regs))
		goto no_context;

	if (fault & VM_FAULT_SIGBUS) {
		/*
 * We had some memory, but were unable to
 * successfully fix up this page fault.
 */
		sig = SIGBUS;
		code = BUS_ADRERR;
	} else {
		/*
 * Something tried to access memory that
 * isn't in our memory map..
 */
		sig = SIGSEGV;
		code = fault == VM_FAULT_BADACCESS ?
			SEGV_ACCERR : SEGV_MAPERR;
	}

	__do_user_fault(tsk, addr, fsr, sig, code, regs);
	return 0;

no_context:
	__do_kernel_fault(mm, addr, fsr, regs);
	return 0;
}
#else					/* CONFIG_MMU */
static int
do_page_fault(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	return 0;
}
#endif					/* CONFIG_MMU */

/*
 * First Level Translation Fault Handler
 *
 * We enter here because the first level page table doesn't contain
 * a valid entry for the address.
 *
 * If the address is in kernel space (>= TASK_SIZE), then we are
 * probably faulting in the vmalloc() area.
 *
 * If the init_task's first level page tables contains the relevant
 * entry, we copy the it to this task. If not, we send the process
 * a signal, fixup the exception, or oops the kernel.
 *
 * NOTE! We MUST NOT take any locks for this case. We may be in an
 * interrupt or a critical region, and should only copy the information
 * from the master page table, nothing more.
 */
#ifdef CONFIG_MMU
static int __kprobes
do_translation_fault(unsigned long addr, unsigned int fsr,
		     struct pt_regs *regs)
{
	unsigned int index;
	pgd_t *pgd, *pgd_k;
	pud_t *pud, *pud_k;
	pmd_t *pmd, *pmd_k;

	if (addr < TASK_SIZE)
		return do_page_fault(addr, fsr, regs);

	if (user_mode(regs))
		goto bad_area;

	index = pgd_index(addr);

	/*
 * FIXME: CP15 C1 is write only on ARMv3 architectures.
 */
	pgd = cpu_get_pgd() + index;
	pgd_k = init_mm.pgd + index;

	if (pgd_none(*pgd_k))
		goto bad_area;
	if (!pgd_present(*pgd))
		set_pgd(pgd, *pgd_k);

	pud = pud_offset(pgd, addr);
	pud_k = pud_offset(pgd_k, addr);

	if (pud_none(*pud_k))
		goto bad_area;
	if (!pud_present(*pud))
		set_pud(pud, *pud_k);

	pmd = pmd_offset(pud, addr);
	pmd_k = pmd_offset(pud_k, addr);

	/*
 * On ARM one Linux PGD entry contains two hardware entries (see page
 * tables layout in pgtable.h). We normally guarantee that we always
 * fill both L1 entries. But create_mapping() doesn't follow the rule.
 * It can create inidividual L1 entries, so here we have to call
 * pmd_none() check for the entry really corresponded to address, not
 * for the first of pair.
 */
	index = (addr >> SECTION_SHIFT) & 1;
	if (pmd_none(pmd_k[index]))
		goto bad_area;

	copy_pmd(pmd, pmd_k);
	return 0;

bad_area:
	do_bad_area(addr, fsr, regs);
	return 0;
}
#else					/* CONFIG_MMU */
static int
do_translation_fault(unsigned long addr, unsigned int fsr,
		     struct pt_regs *regs)
{
	return 0;
}
#endif					/* CONFIG_MMU */

/*
 * Some section permission faults need to be handled gracefully.
 * They can happen due to a __{get,put}_user during an oops.
 */
static int
do_sect_fault(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	do_bad_area(addr, fsr, regs);
	return 0;
}

/*
 * This abort handler always returns "fault".
 */
static int
do_bad(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	return 1;
}

static struct fsr_info {
	int	(*fn)(unsigned long addr, unsigned int fsr, struct pt_regs *regs);
	int	sig;
	int	code;
	const char *name;
} fsr_info[] = {
	/*
 * The following are the standard ARMv3 and ARMv4 aborts. ARMv5
 * defines these to be "precise" aborts.
 */
	{ do_bad,		SIGSEGV, 0,		"vector exception"		   },
	{ do_bad,		SIGBUS,	 BUS_ADRALN,	"alignment exception"		   },
	{ do_bad,		SIGKILL, 0,		"terminal exception"		   },
	{ do_bad,		SIGBUS,	 BUS_ADRALN,	"alignment exception"		   },
	{ do_bad,		SIGBUS,	 0,		"external abort on linefetch"	   },
	{ do_translation_fault,	SIGSEGV, SEGV_MAPERR,	"section translation fault"	   },
	{ do_bad,		SIGBUS,	 0,		"external abort on linefetch"	   },
	{ do_page_fault,	SIGSEGV, SEGV_MAPERR,	"page translation fault"	   },
	{ do_bad,		SIGBUS,	 0,		"external abort on non-linefetch"  },
	{ do_bad,		SIGSEGV, SEGV_ACCERR,	"section domain fault"		   },
	{ do_bad,		SIGBUS,	 0,		"external abort on non-linefetch"  },
	{ do_bad,		SIGSEGV, SEGV_ACCERR,	"page domain fault"		   },
	{ do_bad,		SIGBUS,	 0,		"external abort on translation"	   },
	{ do_sect_fault,	SIGSEGV, SEGV_ACCERR,	"section permission fault"	   },
	{ do_bad,		SIGBUS,	 0,		"external abort on translation"	   },
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"page permission fault"		   },
	/*
 * The following are "imprecise" aborts, which are signalled by bit
 * 10 of the FSR, and may not be recoverable. These are only
 * supported if the CPU abort handler supports bit 10.
 */
	{ do_bad,		SIGBUS,  0,		"unknown 16"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 17"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 18"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 19"			   },
	{ do_bad,		SIGBUS,  0,		"lock abort"			   }, /* xscale */
	{ do_bad,		SIGBUS,  0,		"unknown 21"			   },
	{ do_bad,		SIGBUS,  BUS_OBJERR,	"imprecise external abort"	   }, /* xscale */
	{ do_bad,		SIGBUS,  0,		"unknown 23"			   },
	{ do_bad,		SIGBUS,  0,		"dcache parity error"		   }, /* xscale */
	{ do_bad,		SIGBUS,  0,		"unknown 25"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 26"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 27"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 28"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 29"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 30"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 31"			   }
};

void __init
hook_fault_code(int nr, int (*fn)(unsigned long, unsigned int, struct pt_regs *),
		int sig, int code, const char *name)
{
	if (nr < 0 || nr >= ARRAY_SIZE(fsr_info))
		BUG();

	fsr_info[nr].fn   = fn;
	fsr_info[nr].sig  = sig;
	fsr_info[nr].code = code;
	fsr_info[nr].name = name;
}

/*
 * Dispatch a data abort to the relevant handler.
 */
asmlinkage void __exception
do_DataAbort(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	const struct fsr_info *inf = fsr_info + fsr_fs(fsr);
	struct siginfo info;

	if (!inf->fn(addr, fsr & ~FSR_LNX_PF, regs))
		return;

	printk(KERN_ALERT "Unhandled fault: %s (0x%03x) at 0x%08lx\n",
		inf->name, fsr, addr);

	info.si_signo = inf->sig;
	info.si_errno = 0;
	info.si_code  = inf->code;
	info.si_addr  = (void __user *)addr;
	arm_notify_die("", regs, &info, fsr, 0);
}


static struct fsr_info ifsr_info[] = {
	{ do_bad,		SIGBUS,  0,		"unknown 0"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 1"			   },
	{ do_bad,		SIGBUS,  0,		"debug event"			   },
	{ do_bad,		SIGSEGV, SEGV_ACCERR,	"section access flag fault"	   },
	{ do_bad,		SIGBUS,  0,		"unknown 4"			   },
	{ do_translation_fault,	SIGSEGV, SEGV_MAPERR,	"section translation fault"	   },
	{ do_bad,		SIGSEGV, SEGV_ACCERR,	"page access flag fault"	   },
	{ do_page_fault,	SIGSEGV, SEGV_MAPERR,	"page translation fault"	   },
	{ do_bad,		SIGBUS,	 0,		"external abort on non-linefetch"  },
	{ do_bad,		SIGSEGV, SEGV_ACCERR,	"section domain fault"		   },
	{ do_bad,		SIGBUS,  0,		"unknown 10"			   },
	{ do_bad,		SIGSEGV, SEGV_ACCERR,	"page domain fault"		   },
	{ do_bad,		SIGBUS,	 0,		"external abort on translation"	   },
	{ do_sect_fault,	SIGSEGV, SEGV_ACCERR,	"section permission fault"	   },
	{ do_bad,		SIGBUS,	 0,		"external abort on translation"	   },
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"page permission fault"		   },
	{ do_bad,		SIGBUS,  0,		"unknown 16"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 17"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 18"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 19"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 20"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 21"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 22"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 23"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 24"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 25"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 26"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 27"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 28"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 29"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 30"			   },
	{ do_bad,		SIGBUS,  0,		"unknown 31"			   },
};

void __init
hook_ifault_code(int nr, int (*fn)(unsigned long, unsigned int, struct pt_regs *),
		 int sig, int code, const char *name)
{
	if (nr < 0 || nr >= ARRAY_SIZE(ifsr_info))
		BUG();

	ifsr_info[nr].fn   = fn;
	ifsr_info[nr].sig  = sig;
	ifsr_info[nr].code = code;
	ifsr_info[nr].name = name;
}

asmlinkage void __exception
do_PrefetchAbort(unsigned long addr, unsigned int ifsr, struct pt_regs *regs)
{
	const struct fsr_info *inf = ifsr_info + fsr_fs(ifsr);
	struct siginfo info;

	if (!inf->fn(addr, ifsr | FSR_LNX_PF, regs))
		return;

	printk(KERN_ALERT "Unhandled prefetch abort: %s (0x%03x) at 0x%08lx\n",
		inf->name, ifsr, addr);

	info.si_signo = inf->sig;
	info.si_errno = 0;
	info.si_code  = inf->code;
	info.si_addr  = (void __user *)addr;
	arm_notify_die("", regs, &info, ifsr, 0);
}

static int __init exceptions_init(void)
{
	if (cpu_architecture() >= CPU_ARCH_ARMv6) {
		hook_fault_code(4, do_translation_fault, SIGSEGV, SEGV_MAPERR,
				"I-cache maintenance fault");
	}

	if (cpu_architecture() >= CPU_ARCH_ARMv7) {
		/*
 * TODO: Access flag faults introduced in ARMv6K.
 * Runtime check for 'K' extension is needed
 */
		hook_fault_code(3, do_bad, SIGSEGV, SEGV_MAPERR,
				"section access flag fault");
		hook_fault_code(6, do_bad, SIGSEGV, SEGV_MAPERR,
				"section access flag fault");
	}

	return 0;
}

arch_initcall(exceptions_init);

/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License. See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1995 - 2000 by Ralf Baechle
 */
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/perf_event.h>

#include <asm/branch.h>
#include <asm/mmu_context.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/ptrace.h>
#include <asm/highmem.h>		/* For VMALLOC_END */
#include <linux/kdebug.h>

/*
 * This routine handles page faults. It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 */
asmlinkage void __kprobes do_page_fault(struct pt_regs *regs, unsigned long write,
			      unsigned long address)
{
	struct vm_area_struct * vma = NULL;
	struct task_struct *tsk = current;
	struct mm_struct *mm = tsk->mm;
	const int field = sizeof(unsigned long) * 2;
	siginfo_t info;
	int fault;

#if 0
	printk("Cpu%d[%s:%d:%0*lx:%ld:%0*lx]\n", raw_smp_processor_id(),
	       current->comm, current->pid, field, address, write,
	       field, regs->cp0_epc);
#endif

#ifdef CONFIG_KPROBES
	/*
 * This is to notify the fault handler of the kprobes. The
 * exception code is redundant as it is also carried in REGS,
 * but we pass it anyhow.
 */
	if (notify_die(DIE_PAGE_FAULT, "page fault", regs, -1,
		       (regs->cp0_cause >> 2) & 0x1f, SIGSEGV) == NOTIFY_STOP)
		return;
#endif

	info.si_code = SEGV_MAPERR;

	/*
 * We fault-in kernel-space virtual memory on-demand. The
 * 'reference' page table is init_mm.pgd.
 *
 * NOTE! We MUST NOT take any locks for this case. We may
 * be in an interrupt or a critical region, and should
 * only copy the information from the master page table,
 * nothing more.
 */
#ifdef CONFIG_64BIT
# define VMALLOC_FAULT_TARGET no_context
#else
# define VMALLOC_FAULT_TARGET vmalloc_fault
#endif

	if (unlikely(address >= VMALLOC_START && address <= VMALLOC_END))
		goto VMALLOC_FAULT_TARGET;
#ifdef MODULE_START
	if (unlikely(address >= MODULE_START && address < MODULE_END))
		goto VMALLOC_FAULT_TARGET;
#endif

	/*
 * If we're in an interrupt or have no user
 * context, we must not take the fault..
 */
	if (in_atomic() || !mm)
		goto bad_area_nosemaphore;

	down_read(&mm->mmap_sem);
	vma = find_vma(mm, address);
	if (!vma)
		goto bad_area;
	if (vma->vm_start <= address)
		goto good_area;
	if (!(vma->vm_flags & VM_GROWSDOWN))
		goto bad_area;
	if (expand_stack(vma, address))
		goto bad_area;
/*
 * Ok, we have a good vm_area for this memory access, so
 * we can handle it..
 */
good_area:
	info.si_code = SEGV_ACCERR;

	if (write) {
		if (!(vma->vm_flags & VM_WRITE))
			goto bad_area;
	} else {
		if (kernel_uses_smartmips_rixi) {
			if (address == regs->cp0_epc && !(vma->vm_flags & VM_EXEC)) {
#if 0
				pr_notice("Cpu%d[%s:%d:%0*lx:%ld:%0*lx] XI violation\n",
					  raw_smp_processor_id(),
					  current->comm, current->pid,
					  field, address, write,
					  field, regs->cp0_epc);
#endif
				goto bad_area;
			}
			if (!(vma->vm_flags & VM_READ)) {
#if 0
				pr_notice("Cpu%d[%s:%d:%0*lx:%ld:%0*lx] RI violation\n",
					  raw_smp_processor_id(),
					  current->comm, current->pid,
					  field, address, write,
					  field, regs->cp0_epc);
#endif
				goto bad_area;
			}
		} else {
			if (!(vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC)))
				goto bad_area;
		}
	}

	/*
 * If for any reason at all we couldn't handle the fault,
 * make sure we exit gracefully rather than endlessly redo
 * the fault.
 */
	fault = handle_mm_fault(mm, vma, address, write ? FAULT_FLAG_WRITE : 0);
	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, 0, regs, address);
	if (unlikely(fault & VM_FAULT_ERROR)) {
		if (fault & VM_FAULT_OOM)
			goto out_of_memory;
		else if (fault & VM_FAULT_SIGBUS)
			goto do_sigbus;
		BUG();
	}
	if (fault & VM_FAULT_MAJOR) {
		perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ,
				1, 0, regs, address);
		tsk->maj_flt++;
	} else {
		perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN,
				1, 0, regs, address);
		tsk->min_flt++;
	}

	up_read(&mm->mmap_sem);
	return;

/*
 * Something tried to access memory that isn't in our memory map..
 * Fix it, but check if it's kernel or user first..
 */
bad_area:
	up_read(&mm->mmap_sem);

bad_area_nosemaphore:
	/* User mode accesses just cause a SIGSEGV */
	if (user_mode(regs)) {
		tsk->thread.cp0_badvaddr = address;
		tsk->thread.error_code = write;
#if 0
		printk("do_page_fault() #2: sending SIGSEGV to %s for "
		       "invalid %s\n%0*lx (epc == %0*lx, ra == %0*lx)\n",
		       tsk->comm,
		       write ? "write access to" : "read access from",
		       field, address,
		       field, (unsigned long) regs->cp0_epc,
		       field, (unsigned long) regs->regs[31]);
#endif
		info.si_signo = SIGSEGV;
		info.si_errno = 0;
		/* info.si_code has been set above */
		info.si_addr = (void __user *) address;
		force_sig_info(SIGSEGV, &info, tsk);
		return;
	}

no_context:
	/* Are we prepared to handle this kernel fault? */
	if (fixup_exception(regs)) {
		current->thread.cp0_baduaddr = address;
		return;
	}

	/*
 * Oops. The kernel tried to access some bad page. We'll have to
 * terminate things with extreme prejudice.
 */
	bust_spinlocks(1);

	printk(KERN_ALERT "CPU %d Unable to handle kernel paging request at "
	       "virtual address %0*lx, epc == %0*lx, ra == %0*lx\n",
	       raw_smp_processor_id(), field, address, field, regs->cp0_epc,
	       field,  regs->regs[31]);
	die("Oops", regs);

out_of_memory:
	/*
 * We ran out of memory, call the OOM killer, and return the userspace
 * (which will retry the fault, or kill us if we got oom-killed).
 */
	up_read(&mm->mmap_sem);
	pagefault_out_of_memory();
	return;

do_sigbus:
	up_read(&mm->mmap_sem);

	/* Kernel mode? Handle exceptions or die */
	if (!user_mode(regs))
		goto no_context;
	else
	/*
 * Send a sigbus, regardless of whether we were in kernel
 * or user mode.
 */
#if 0
		printk("do_page_fault() #3: sending SIGBUS to %s for "
		       "invalid %s\n%0*lx (epc == %0*lx, ra == %0*lx)\n",
		       tsk->comm,
		       write ? "write access to" : "read access from",
		       field, address,
		       field, (unsigned long) regs->cp0_epc,
		       field, (unsigned long) regs->regs[31]);
#endif
	tsk->thread.cp0_badvaddr = address;
	info.si_signo = SIGBUS;
	info.si_errno = 0;
	info.si_code = BUS_ADRERR;
	info.si_addr = (void __user *) address;
	force_sig_info(SIGBUS, &info, tsk);

	return;
#ifndef CONFIG_64BIT
vmalloc_fault:
	{
		/*
 * Synchronize this task's top level page-table
 * with the 'reference' page table.
 *
 * Do _not_ use "tsk" here. We might be inside
 * an interrupt in the middle of a task switch..
 */
		int offset = __pgd_offset(address);
		pgd_t *pgd, *pgd_k;
		pud_t *pud, *pud_k;
		pmd_t *pmd, *pmd_k;
		pte_t *pte_k;

		pgd = (pgd_t *) pgd_current[raw_smp_processor_id()] + offset;
		pgd_k = init_mm.pgd + offset;

		if (!pgd_present(*pgd_k))
			goto no_context;
		set_pgd(pgd, *pgd_k);

		pud = pud_offset(pgd, address);
		pud_k = pud_offset(pgd_k, address);
		if (!pud_present(*pud_k))
			goto no_context;

		pmd = pmd_offset(pud, address);
		pmd_k = pmd_offset(pud_k, address);
		if (!pmd_present(*pmd_k))
			goto no_context;
		set_pmd(pmd, *pmd_k);

		pte_k = pte_offset_kernel(pmd_k, address);
		if (!pte_present(*pte_k))
			goto no_context;
		return;
	}
#endif
}

/*
 * PowerPC version
 * Copyright (C) 1995-1996 Gary Thomas (gdt@linuxppc.org)
 *
 * Derived from "arch/i386/mm/fault.c"
 * Copyright (C) 1991, 1992, 1993, 1994 Linus Torvalds
 *
 * Modified by Cort Dougan and Paul Mackerras.
 *
 * Modified for PPC64 by Dave Engebretsen (engebret@ibm.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kdebug.h>
#include <linux/perf_event.h>
#include <linux/magic.h>

#include <asm/firmware.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/mmu.h>
#include <asm/mmu_context.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/tlbflush.h>
#include <asm/siginfo.h>
#include <mm/mmu_decl.h>

#ifdef CONFIG_KPROBES
static inline int notify_page_fault(struct pt_regs *regs)
{
	int ret = 0;

	/* kprobe_running() needs smp_processor_id() */
	if (!user_mode(regs)) {
		preempt_disable();
		if (kprobe_running() && kprobe_fault_handler(regs, 11))
			ret = 1;
		preempt_enable();
	}

	return ret;
}
#else
static inline int notify_page_fault(struct pt_regs *regs)
{
	return 0;
}
#endif

/*
 * Check whether the instruction at regs->nip is a store using
 * an update addressing form which will update r1.
 */
static int store_updates_sp(struct pt_regs *regs)
{
	unsigned int inst;

	if (get_user(inst, (unsigned int __user *)regs->nip))
		return 0;
	/* check for 1 in the rA field */
	if (((inst >> 16) & 0x1f) != 1)
		return 0;
	/* check major opcode */
	switch (inst >> 26) {
	case 37:	/* stwu */
	case 39:	/* stbu */
	case 45:	/* sthu */
	case 53:	/* stfsu */
	case 55:	/* stfdu */
		return 1;
	case 62:	/* std or stdu */
		return (inst & 3) == 1;
	case 31:
		/* check minor opcode */
		switch ((inst >> 1) & 0x3ff) {
		case 181:	/* stdux */
		case 183:	/* stwux */
		case 247:	/* stbux */
		case 439:	/* sthux */
		case 695:	/* stfsux */
		case 759:	/* stfdux */
			return 1;
		}
	}
	return 0;
}

/*
 * For 600- and 800-family processors, the error_code parameter is DSISR
 * for a data fault, SRR1 for an instruction fault. For 400-family processors
 * the error_code parameter is ESR for a data fault, 0 for an instruction
 * fault.
 * For 64-bit processors, the error_code parameter is
 * - DSISR for a non-SLB data access fault,
 * - SRR1 & 0x08000000 for a non-SLB instruction access fault
 * - 0 any SLB fault.
 *
 * The return value is 0 if the fault was handled, or the signal
 * number if this is a kernel fault that can't be handled here.
 */
int __kprobes do_page_fault(struct pt_regs *regs, unsigned long address,
			    unsigned long error_code)
{
	struct vm_area_struct * vma;
	struct mm_struct *mm = current->mm;
	siginfo_t info;
	int code = SEGV_MAPERR;
	int is_write = 0, ret;
	int trap = TRAP(regs);
 	int is_exec = trap == 0x400;

#if !(defined(CONFIG_4xx) || defined(CONFIG_BOOKE))
	/*
 * Fortunately the bit assignments in SRR1 for an instruction
 * fault and DSISR for a data fault are mostly the same for the
 * bits we are interested in. But there are some bits which
 * indicate errors in DSISR but can validly be set in SRR1.
 */
	if (trap == 0x400)
		error_code &= 0x48200000;
	else
		is_write = error_code & DSISR_ISSTORE;
#else
	is_write = error_code & ESR_DST;
#endif /* CONFIG_4xx || CONFIG_BOOKE */

	if (notify_page_fault(regs))
		return 0;

	if (unlikely(debugger_fault_handler(regs)))
		return 0;

	/* On a kernel SLB miss we can only check for a valid exception entry */
	if (!user_mode(regs) && (address >= TASK_SIZE))
		return SIGSEGV;

#if !(defined(CONFIG_4xx) || defined(CONFIG_BOOKE) || \
 defined(CONFIG_PPC_BOOK3S_64))
  	if (error_code & DSISR_DABRMATCH) {
		/* DABR match */
		do_dabr(regs, address, error_code);
		return 0;
	}
#endif

	if (in_atomic() || mm == NULL) {
		if (!user_mode(regs))
			return SIGSEGV;
		/* in_atomic() in user mode is really bad,
 as is current->mm == NULL. */
		printk(KERN_EMERG "Page fault in user mode with "
		       "in_atomic() = %d mm = %p\n", in_atomic(), mm);
		printk(KERN_EMERG "NIP = %lx MSR = %lx\n",
		       regs->nip, regs->msr);
		die("Weird page fault", regs, SIGSEGV);
	}

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, 0, regs, address);

	/* When running in the kernel we expect faults to occur only to
 * addresses in user space. All other faults represent errors in the
 * kernel and should generate an OOPS. Unfortunately, in the case of an
 * erroneous fault occurring in a code path which already holds mmap_sem
 * we will deadlock attempting to validate the fault against the
 * address space. Luckily the kernel only validly references user
 * space from well defined areas of code, which are listed in the
 * exceptions table.
 *
 * As the vast majority of faults will be valid we will only perform
 * the source reference check when there is a possibility of a deadlock.
 * Attempt to lock the address space, if we cannot we then validate the
 * source. If this is invalid we can skip the address space check,
 * thus avoiding the deadlock.
 */
	if (!down_read_trylock(&mm->mmap_sem)) {
		if (!user_mode(regs) && !search_exception_tables(regs->nip))
			goto bad_area_nosemaphore;

		down_read(&mm->mmap_sem);
	}

	vma = find_vma(mm, address);
	if (!vma)
		goto bad_area;
	if (vma->vm_start <= address)
		goto good_area;
	if (!(vma->vm_flags & VM_GROWSDOWN))
		goto bad_area;

	/*
 * N.B. The POWER/Open ABI allows programs to access up to
 * 288 bytes below the stack pointer.
 * The kernel signal delivery code writes up to about 1.5kB
 * below the stack pointer (r1) before decrementing it.
 * The exec code can write slightly over 640kB to the stack
 * before setting the user r1. Thus we allow the stack to
 * expand to 1MB without further checks.
 */
	if (address + 0x100000 < vma->vm_end) {
		/* get user regs even if this fault is in kernel mode */
		struct pt_regs *uregs = current->thread.regs;
		if (uregs == NULL)
			goto bad_area;

		/*
 * A user-mode access to an address a long way below
 * the stack pointer is only valid if the instruction
 * is one which would update the stack pointer to the
 * address accessed if the instruction completed,
 * i.e. either stwu rs,n(r1) or stwux rs,r1,rb
 * (or the byte, halfword, float or double forms).
 *
 * If we don't check this then any write to the area
 * between the last mapped region and the stack will
 * expand the stack rather than segfaulting.
 */
		if (address + 2048 < uregs->gpr[1]
		    && (!user_mode(regs) || !store_updates_sp(regs)))
			goto bad_area;
	}
	if (expand_stack(vma, address))
		goto bad_area;

good_area:
	code = SEGV_ACCERR;
#if defined(CONFIG_6xx)
	if (error_code & 0x95700000)
		/* an error such as lwarx to I/O controller space,
 address matching DABR, eciwx, etc. */
		goto bad_area;
#endif /* CONFIG_6xx */
#if defined(CONFIG_8xx)
	/* 8xx sometimes need to load a invalid/non-present TLBs.
 * These must be invalidated separately as linux mm don't.
 */
	if (error_code & 0x40000000) /* no translation? */
		_tlbil_va(address, 0, 0, 0);

        /* The MPC8xx seems to always set 0x80000000, which is
 * "undefined". Of those that can be set, this is the only
 * one which seems bad.
 */
	if (error_code & 0x10000000)
                /* Guarded storage error. */
		goto bad_area;
#endif /* CONFIG_8xx */

	if (is_exec) {
#ifdef CONFIG_PPC_STD_MMU
		/* Protection fault on exec go straight to failure on
 * Hash based MMUs as they either don't support per-page
 * execute permission, or if they do, it's handled already
 * at the hash level. This test would probably have to
 * be removed if we change the way this works to make hash
 * processors use the same I/D cache coherency mechanism
 * as embedded.
 */
		if (error_code & DSISR_PROTFAULT)
			goto bad_area;
#endif /* CONFIG_PPC_STD_MMU */

		/*
 * Allow execution from readable areas if the MMU does not
 * provide separate controls over reading and executing.
 *
 * Note: That code used to not be enabled for 4xx/BookE.
 * It is now as I/D cache coherency for these is done at
 * set_pte_at() time and I see no reason why the test
 * below wouldn't be valid on those processors. This -may-
 * break programs compiled with a really old ABI though.
 */
		if (!(vma->vm_flags & VM_EXEC) &&
		    (cpu_has_feature(CPU_FTR_NOEXECUTE) ||
		     !(vma->vm_flags & (VM_READ | VM_WRITE))))
			goto bad_area;
	/* a write */
	} else if (is_write) {
		if (!(vma->vm_flags & VM_WRITE))
			goto bad_area;
	/* a read */
	} else {
		/* protection fault */
		if (error_code & 0x08000000)
			goto bad_area;
		if (!(vma->vm_flags & (VM_READ | VM_EXEC | VM_WRITE)))
			goto bad_area;
	}

	/*
 * If for any reason at all we couldn't handle the fault,
 * make sure we exit gracefully rather than endlessly redo
 * the fault.
 */
	ret = handle_mm_fault(mm, vma, address, is_write ? FAULT_FLAG_WRITE : 0);
	if (unlikely(ret & VM_FAULT_ERROR)) {
		if (ret & VM_FAULT_OOM)
			goto out_of_memory;
		else if (ret & VM_FAULT_SIGBUS)
			goto do_sigbus;
		BUG();
	}
	if (ret & VM_FAULT_MAJOR) {
		current->maj_flt++;
		perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ, 1, 0,
				     regs, address);
#ifdef CONFIG_PPC_SMLPAR
		if (firmware_has_feature(FW_FEATURE_CMO)) {
			preempt_disable();
			get_lppaca()->page_ins += (1 << PAGE_FACTOR);
			preempt_enable();
		}
#endif
	} else {
		current->min_flt++;
		perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN, 1, 0,
				     regs, address);
	}
	up_read(&mm->mmap_sem);
	return 0;

bad_area:
	up_read(&mm->mmap_sem);

bad_area_nosemaphore:
	/* User mode accesses cause a SIGSEGV */
	if (user_mode(regs)) {
		_exception(SIGSEGV, regs, code, address);
		return 0;
	}

	if (is_exec && (error_code & DSISR_PROTFAULT)
	    && printk_ratelimit())
		printk(KERN_CRIT "kernel tried to execute NX-protected"
		       " page (%lx) - exploit attempt? (uid: %d)\n",
		       address, current_uid());

	return SIGSEGV;

/*
 * We ran out of memory, or some other thing happened to us that made
 * us unable to handle the page fault gracefully.
 */
out_of_memory:
	up_read(&mm->mmap_sem);
	if (!user_mode(regs))
		return SIGKILL;
	pagefault_out_of_memory();
	return 0;

do_sigbus:
	up_read(&mm->mmap_sem);
	if (user_mode(regs)) {
		info.si_signo = SIGBUS;
		info.si_errno = 0;
		info.si_code = BUS_ADRERR;
		info.si_addr = (void __user *)address;
		force_sig_info(SIGBUS, &info, current);
		return 0;
	}
	return SIGBUS;
}

/*
 * bad_page_fault is called when we have a bad access from the kernel.
 * It is called from the DSI and ISI handlers in head.S and from some
 * of the procedures in traps.c.
 */
void bad_page_fault(struct pt_regs *regs, unsigned long address, int sig)
{
	const struct exception_table_entry *entry;
	unsigned long *stackend;

	/* Are we prepared to handle this fault? */
	if ((entry = search_exception_tables(regs->nip)) != NULL) {
		regs->nip = entry->fixup;
		return;
	}

	/* kernel has accessed a bad area */

	switch (regs->trap) {
	case 0x300:
	case 0x380:
		printk(KERN_ALERT "Unable to handle kernel paging request for "
			"data at address 0x%08lx\n", regs->dar);
		break;
	case 0x400:
	case 0x480:
		printk(KERN_ALERT "Unable to handle kernel paging request for "
			"instruction fetch\n");
		break;
	default:
		printk(KERN_ALERT "Unable to handle kernel paging request for "
			"unknown fault\n");
		break;
	}
	printk(KERN_ALERT "Faulting instruction address: 0x%08lx\n",
		regs->nip);

	stackend = end_of_stack(current);
	if (current != &init_task && *stackend != STACK_END_MAGIC)
		printk(KERN_ALERT "Thread overran stack, or stack corrupted\n");

	die("Kernel access of bad area", regs, sig);
}

/*
 * arch/s390/mm/fault.c
 *
 * S390 version
 * Copyright (C) 1999 IBM Deutschland Entwicklung GmbH, IBM Corporation
 * Author(s): Hartmut Penner (hp@de.ibm.com)
 * Ulrich Weigand (uweigand@de.ibm.com)
 *
 * Derived from "arch/i386/mm/fault.c"
 * Copyright (C) 1995 Linus Torvalds
 */

#include <linux/kernel_stat.h>
#include <linux/perf_event.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/compat.h>
#include <linux/smp.h>
#include <linux/kdebug.h>
#include <linux/init.h>
#include <linux/console.h>
#include <linux/module.h>
#include <linux/hardirq.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/hugetlb.h>
#include <asm/asm-offsets.h>
#include <asm/system.h>
#include <asm/pgtable.h>
#include <asm/irq.h>
#include <asm/mmu_context.h>
#include <asm/compat.h>
#include "../kernel/entry.h"

#ifndef CONFIG_64BIT
#define __FAIL_ADDR_MASK 0x7ffff000
#define __SUBCODE_MASK 0x0200
#define __PF_RES_FIELD 0ULL
#else /* CONFIG_64BIT */
#define __FAIL_ADDR_MASK -4096L
#define __SUBCODE_MASK 0x0600
#define __PF_RES_FIELD 0x8000000000000000ULL
#endif /* CONFIG_64BIT */

#define VM_FAULT_BADCONTEXT 0x010000
#define VM_FAULT_BADMAP 0x020000
#define VM_FAULT_BADACCESS 0x040000

static unsigned long store_indication;

void fault_init(void)
{
	if (test_facility(2) && test_facility(75))
		store_indication = 0xc00;
}

static inline int notify_page_fault(struct pt_regs *regs)
{
	int ret = 0;

	/* kprobe_running() needs smp_processor_id() */
	if (kprobes_built_in() && !user_mode(regs)) {
		preempt_disable();
		if (kprobe_running() && kprobe_fault_handler(regs, 14))
			ret = 1;
		preempt_enable();
	}
	return ret;
}


/*
 * Unlock any spinlocks which will prevent us from getting the
 * message out.
 */
void bust_spinlocks(int yes)
{
	if (yes) {
		oops_in_progress = 1;
	} else {
		int loglevel_save = console_loglevel;
		console_unblank();
		oops_in_progress = 0;
		/*
 * OK, the message is on the console. Now we call printk()
 * without oops_in_progress set so that printk will give klogd
 * a poke. Hold onto your hats...
 */
		console_loglevel = 15;
		printk(" ");
		console_loglevel = loglevel_save;
	}
}

/*
 * Returns the address space associated with the fault.
 * Returns 0 for kernel space and 1 for user space.
 */
static inline int user_space_fault(unsigned long trans_exc_code)
{
	/*
 * The lowest two bits of the translation exception
 * identification indicate which paging table was used.
 */
	trans_exc_code &= 3;
	if (trans_exc_code == 2)
		/* Access via secondary space, set_fs setting decides */
		return current->thread.mm_segment.ar4;
	if (user_mode == HOME_SPACE_MODE)
		/* User space if the access has been done via home space. */
		return trans_exc_code == 3;
	/*
 * If the user space is not the home space the kernel runs in home
 * space. Access via secondary space has already been covered,
 * access via primary space or access register is from user space
 * and access via home space is from the kernel.
 */
	return trans_exc_code != 3;
}

static inline void report_user_fault(struct pt_regs *regs, long int_code,
				     int signr, unsigned long address)
{
	if ((task_pid_nr(current) > 1) && !show_unhandled_signals)
		return;
	if (!unhandled_signal(current, signr))
		return;
	if (!printk_ratelimit())
		return;
	printk("User process fault: interruption code 0x%lX ", int_code);
	print_vma_addr(KERN_CONT "in ", regs->psw.addr & PSW_ADDR_INSN);
	printk("\n");
	printk("failing address: %lX\n", address);
	show_regs(regs);
}

/*
 * Send SIGSEGV to task. This is an external routine
 * to keep the stack usage of do_page_fault small.
 */
static noinline void do_sigsegv(struct pt_regs *regs, long int_code,
				int si_code, unsigned long trans_exc_code)
{
	struct siginfo si;
	unsigned long address;

	address = trans_exc_code & __FAIL_ADDR_MASK;
	current->thread.prot_addr = address;
	current->thread.trap_no = int_code;
	report_user_fault(regs, int_code, SIGSEGV, address);
	si.si_signo = SIGSEGV;
	si.si_code = si_code;
	si.si_addr = (void __user *) address;
	force_sig_info(SIGSEGV, &si, current);
}

static noinline void do_no_context(struct pt_regs *regs, long int_code,
				   unsigned long trans_exc_code)
{
	const struct exception_table_entry *fixup;
	unsigned long address;

	/* Are we prepared to handle this kernel fault? */
	fixup = search_exception_tables(regs->psw.addr & PSW_ADDR_INSN);
	if (fixup) {
		regs->psw.addr = fixup->fixup | PSW_ADDR_AMODE;
		return;
	}

	/*
 * Oops. The kernel tried to access some bad page. We'll have to
 * terminate things with extreme prejudice.
 */
	address = trans_exc_code & __FAIL_ADDR_MASK;
	if (!user_space_fault(trans_exc_code))
		printk(KERN_ALERT "Unable to handle kernel pointer dereference"
		       " at virtual kernel address %p\n", (void *)address);
	else
		printk(KERN_ALERT "Unable to handle kernel paging request"
		       " at virtual user address %p\n", (void *)address);

	die("Oops", regs, int_code);
	do_exit(SIGKILL);
}

static noinline void do_low_address(struct pt_regs *regs, long int_code,
				    unsigned long trans_exc_code)
{
	/* Low-address protection hit in kernel mode means
 NULL pointer write access in kernel mode. */
	if (regs->psw.mask & PSW_MASK_PSTATE) {
		/* Low-address protection hit in user mode 'cannot happen'. */
		die ("Low-address protection", regs, int_code);
		do_exit(SIGKILL);
	}

	do_no_context(regs, int_code, trans_exc_code);
}

static noinline void do_sigbus(struct pt_regs *regs, long int_code,
			       unsigned long trans_exc_code)
{
	struct task_struct *tsk = current;
	unsigned long address;
	struct siginfo si;

	/*
 * Send a sigbus, regardless of whether we were in kernel
 * or user mode.
 */
	address = trans_exc_code & __FAIL_ADDR_MASK;
	tsk->thread.prot_addr = address;
	tsk->thread.trap_no = int_code;
	si.si_signo = SIGBUS;
	si.si_errno = 0;
	si.si_code = BUS_ADRERR;
	si.si_addr = (void __user *) address;
	force_sig_info(SIGBUS, &si, tsk);
}

static noinline void do_fault_error(struct pt_regs *regs, long int_code,
				    unsigned long trans_exc_code, int fault)
{
	int si_code;

	switch (fault) {
	case VM_FAULT_BADACCESS:
	case VM_FAULT_BADMAP:
		/* Bad memory access. Check if it is kernel or user space. */
		if (regs->psw.mask & PSW_MASK_PSTATE) {
			/* User mode accesses just cause a SIGSEGV */
			si_code = (fault == VM_FAULT_BADMAP) ?
				SEGV_MAPERR : SEGV_ACCERR;
			do_sigsegv(regs, int_code, si_code, trans_exc_code);
			return;
		}
	case VM_FAULT_BADCONTEXT:
		do_no_context(regs, int_code, trans_exc_code);
		break;
	default: /* fault & VM_FAULT_ERROR */
		if (fault & VM_FAULT_OOM) {
			if (!(regs->psw.mask & PSW_MASK_PSTATE))
				do_no_context(regs, int_code, trans_exc_code);
			else
				pagefault_out_of_memory();
		} else if (fault & VM_FAULT_SIGBUS) {
			/* Kernel mode? Handle exceptions or die */
			if (!(regs->psw.mask & PSW_MASK_PSTATE))
				do_no_context(regs, int_code, trans_exc_code);
			else
				do_sigbus(regs, int_code, trans_exc_code);
		} else
			BUG();
		break;
	}
}

/*
 * This routine handles page faults. It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 *
 * interruption code (int_code):
 * 04 Protection -> Write-Protection (suprression)
 * 10 Segment translation -> Not present (nullification)
 * 11 Page translation -> Not present (nullification)
 * 3b Region third trans. -> Not present (nullification)
 */
static inline int do_exception(struct pt_regs *regs, int access,
			       unsigned long trans_exc_code)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long address;
	unsigned int flags;
	int fault;

	if (notify_page_fault(regs))
		return 0;

	tsk = current;
	mm = tsk->mm;

	/*
 * Verify that the fault happened in user space, that
 * we are not in an interrupt and that there is a 
 * user context.
 */
	fault = VM_FAULT_BADCONTEXT;
	if (unlikely(!user_space_fault(trans_exc_code) || in_atomic() || !mm))
		goto out;

	address = trans_exc_code & __FAIL_ADDR_MASK;
	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, 0, regs, address);
	flags = FAULT_FLAG_ALLOW_RETRY;
	if (access == VM_WRITE || (trans_exc_code & store_indication) == 0x400)
		flags |= FAULT_FLAG_WRITE;
retry:
	down_read(&mm->mmap_sem);

	fault = VM_FAULT_BADMAP;
	vma = find_vma(mm, address);
	if (!vma)
		goto out_up;

	if (unlikely(vma->vm_start > address)) {
		if (!(vma->vm_flags & VM_GROWSDOWN))
			goto out_up;
		if (expand_stack(vma, address))
			goto out_up;
	}

	/*
 * Ok, we have a good vm_area for this memory access, so
 * we can handle it..
 */
	fault = VM_FAULT_BADACCESS;
	if (unlikely(!(vma->vm_flags & access)))
		goto out_up;

	if (is_vm_hugetlb_page(vma))
		address &= HPAGE_MASK;
	/*
 * If for any reason at all we couldn't handle the fault,
 * make sure we exit gracefully rather than endlessly redo
 * the fault.
 */
	fault = handle_mm_fault(mm, vma, address, flags);
	if (unlikely(fault & VM_FAULT_ERROR))
		goto out_up;

	/*
 * Major/minor page fault accounting is only done on the
 * initial attempt. If we go through a retry, it is extremely
 * likely that the page will be found in page cache at that point.
 */
	if (flags & FAULT_FLAG_ALLOW_RETRY) {
		if (fault & VM_FAULT_MAJOR) {
			tsk->maj_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ, 1, 0,
				      regs, address);
		} else {
			tsk->min_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN, 1, 0,
				      regs, address);
		}
		if (fault & VM_FAULT_RETRY) {
			/* Clear FAULT_FLAG_ALLOW_RETRY to avoid any risk
 * of starvation. */
			flags &= ~FAULT_FLAG_ALLOW_RETRY;
			goto retry;
		}
	}
	/*
 * The instruction that caused the program check will
 * be repeated. Don't signal single step via SIGTRAP.
 */
	clear_tsk_thread_flag(tsk, TIF_PER_TRAP);
	fault = 0;
out_up:
	up_read(&mm->mmap_sem);
out:
	return fault;
}

void __kprobes do_protection_exception(struct pt_regs *regs, long pgm_int_code,
				       unsigned long trans_exc_code)
{
	int fault;

	/* Protection exception is suppressing, decrement psw address. */
	regs->psw.addr -= (pgm_int_code >> 16);
	/*
 * Check for low-address protection. This needs to be treated
 * as a special case because the translation exception code
 * field is not guaranteed to contain valid data in this case.
 */
	if (unlikely(!(trans_exc_code & 4))) {
		do_low_address(regs, pgm_int_code, trans_exc_code);
		return;
	}
	fault = do_exception(regs, VM_WRITE, trans_exc_code);
	if (unlikely(fault))
		do_fault_error(regs, 4, trans_exc_code, fault);
}

void __kprobes do_dat_exception(struct pt_regs *regs, long pgm_int_code,
				unsigned long trans_exc_code)
{
	int access, fault;

	access = VM_READ | VM_EXEC | VM_WRITE;
	fault = do_exception(regs, access, trans_exc_code);
	if (unlikely(fault))
		do_fault_error(regs, pgm_int_code & 255, trans_exc_code, fault);
}

#ifdef CONFIG_64BIT
void __kprobes do_asce_exception(struct pt_regs *regs, long pgm_int_code,
				 unsigned long trans_exc_code)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;

	if (unlikely(!user_space_fault(trans_exc_code) || in_atomic() || !mm))
		goto no_context;

	down_read(&mm->mmap_sem);
	vma = find_vma(mm, trans_exc_code & __FAIL_ADDR_MASK);
	up_read(&mm->mmap_sem);

	if (vma) {
		update_mm(mm, current);
		return;
	}

	/* User mode accesses just cause a SIGSEGV */
	if (regs->psw.mask & PSW_MASK_PSTATE) {
		do_sigsegv(regs, pgm_int_code, SEGV_MAPERR, trans_exc_code);
		return;
	}

no_context:
	do_no_context(regs, pgm_int_code, trans_exc_code);
}
#endif

int __handle_fault(unsigned long uaddr, unsigned long pgm_int_code, int write)
{
	struct pt_regs regs;
	int access, fault;

	regs.psw.mask = psw_kernel_bits;
	if (!irqs_disabled())
		regs.psw.mask |= PSW_MASK_IO | PSW_MASK_EXT;
	regs.psw.addr = (unsigned long) __builtin_return_address(0);
	regs.psw.addr |= PSW_ADDR_AMODE;
	uaddr &= PAGE_MASK;
	access = write ? VM_WRITE : VM_READ;
	fault = do_exception(&regs, access, uaddr | 2);
	if (unlikely(fault)) {
		if (fault & VM_FAULT_OOM)
			return -EFAULT;
		else if (fault & VM_FAULT_SIGBUS)
			do_sigbus(&regs, pgm_int_code, uaddr);
	}
	return fault ? -EFAULT : 0;
}

#ifdef CONFIG_PFAULT 
/*
 * 'pfault' pseudo page faults routines.
 */
static int pfault_disable;

static int __init nopfault(char *str)
{
	pfault_disable = 1;
	return 1;
}

__setup("nopfault", nopfault);

struct pfault_refbk {
	u16 refdiagc;
	u16 reffcode;
	u16 refdwlen;
	u16 refversn;
	u64 refgaddr;
	u64 refselmk;
	u64 refcmpmk;
	u64 reserved;
} __attribute__ ((packed, aligned(8)));

int pfault_init(void)
{
	struct pfault_refbk refbk = {
		.refdiagc = 0x258,
		.reffcode = 0,
		.refdwlen = 5,
		.refversn = 2,
		.refgaddr = __LC_CURRENT_PID,
		.refselmk = 1ULL << 48,
		.refcmpmk = 1ULL << 48,
		.reserved = __PF_RES_FIELD };
        int rc;

	if (!MACHINE_IS_VM || pfault_disable)
		return -1;
	asm volatile(
		" diag %1,%0,0x258\n"
		"0: j 2f\n"
		"1: la %0,8\n"
		"2:\n"
		EX_TABLE(0b,1b)
		: "=d" (rc) : "a" (&refbk), "m" (refbk) : "cc");
        return rc;
}

void pfault_fini(void)
{
	struct pfault_refbk refbk = {
		.refdiagc = 0x258,
		.reffcode = 1,
		.refdwlen = 5,
		.refversn = 2,
	};

	if (!MACHINE_IS_VM || pfault_disable)
		return;
	asm volatile(
		" diag %0,0,0x258\n"
		"0:\n"
		EX_TABLE(0b,0b)
		: : "a" (&refbk), "m" (refbk) : "cc");
}

static DEFINE_SPINLOCK(pfault_lock);
static LIST_HEAD(pfault_list);

static void pfault_interrupt(unsigned int ext_int_code,
			     unsigned int param32, unsigned long param64)
{
	struct task_struct *tsk;
	__u16 subcode;
	pid_t pid;

	/*
 * Get the external interruption subcode & pfault
 * initial/completion signal bit. VM stores this 
 * in the 'cpu address' field associated with the
 * external interrupt. 
 */
	subcode = ext_int_code >> 16;
	if ((subcode & 0xff00) != __SUBCODE_MASK)
		return;
	kstat_cpu(smp_processor_id()).irqs[EXTINT_PFL]++;
	if (subcode & 0x0080) {
		/* Get the token (= pid of the affected task). */
		pid = sizeof(void *) == 4 ? param32 : param64;
		rcu_read_lock();
		tsk = find_task_by_pid_ns(pid, &init_pid_ns);
		if (tsk)
			get_task_struct(tsk);
		rcu_read_unlock();
		if (!tsk)
			return;
	} else {
		tsk = current;
	}
	spin_lock(&pfault_lock);
	if (subcode & 0x0080) {
		/* signal bit is set -> a page has been swapped in by VM */
		if (tsk->thread.pfault_wait == 1) {
			/* Initial interrupt was faster than the completion
 * interrupt. pfault_wait is valid. Set pfault_wait
 * back to zero and wake up the process. This can
 * safely be done because the task is still sleeping
 * and can't produce new pfaults. */
			tsk->thread.pfault_wait = 0;
			list_del(&tsk->thread.list);
			wake_up_process(tsk);
		} else {
			/* Completion interrupt was faster than initial
 * interrupt. Set pfault_wait to -1 so the initial
 * interrupt doesn't put the task to sleep. */
			tsk->thread.pfault_wait = -1;
		}
		put_task_struct(tsk);
	} else {
		/* signal bit not set -> a real page is missing. */
		if (tsk->thread.pfault_wait == -1) {
			/* Completion interrupt was faster than the initial
 * interrupt (pfault_wait == -1). Set pfault_wait
 * back to zero and exit. */
			tsk->thread.pfault_wait = 0;
		} else {
			/* Initial interrupt arrived before completion
 * interrupt. Let the task sleep. */
			tsk->thread.pfault_wait = 1;
			list_add(&tsk->thread.list, &pfault_list);
			set_task_state(tsk, TASK_UNINTERRUPTIBLE);
			set_tsk_need_resched(tsk);
		}
	}
	spin_unlock(&pfault_lock);
}

static int __cpuinit pfault_cpu_notify(struct notifier_block *self,
				       unsigned long action, void *hcpu)
{
	struct thread_struct *thread, *next;
	struct task_struct *tsk;

	switch (action) {
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		spin_lock_irq(&pfault_lock);
		list_for_each_entry_safe(thread, next, &pfault_list, list) {
			thread->pfault_wait = 0;
			list_del(&thread->list);
			tsk = container_of(thread, struct task_struct, thread);
			wake_up_process(tsk);
		}
		spin_unlock_irq(&pfault_lock);
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

static int __init pfault_irq_init(void)
{
	int rc;

	if (!MACHINE_IS_VM)
		return 0;
	rc = register_external_interrupt(0x2603, pfault_interrupt);
	if (rc)
		goto out_extint;
	rc = pfault_init() == 0 ? 0 : -EOPNOTSUPP;
	if (rc)
		goto out_pfault;
	service_subclass_irq_register();
	hotcpu_notifier(pfault_cpu_notify, 0);
	return 0;

out_pfault:
	unregister_external_interrupt(0x2603, pfault_interrupt);
out_extint:
	pfault_disable = 1;
	return rc;
}
early_initcall(pfault_irq_init);

#endif /* CONFIG_PFAULT */

/*
 * Copyright (C) 1995 Linus Torvalds
 * Copyright (C) 2001, 2002 Andi Kleen, SuSE Labs.
 * Copyright (C) 2008-2009, Red Hat Inc., Ingo Molnar
 */
#include <linux/magic.h>		/* STACK_END_MAGIC */
#include <linux/sched.h>		/* test_thread_flag(), ... */
#include <linux/kdebug.h>		/* oops_begin/end, ... */
#include <linux/module.h>		/* search_exception_table */
#include <linux/bootmem.h>		/* max_low_pfn */
#include <linux/kprobes.h>		/* __kprobes, ... */
#include <linux/mmiotrace.h>		/* kmmio_handler, ... */
#include <linux/perf_event.h>		/* perf_sw_event */
#include <linux/hugetlb.h>		/* hstate_index_to_shift */
#include <linux/prefetch.h>		/* prefetchw */

#include <asm/traps.h>			/* dotraplinkage, ... */
#include <asm/pgalloc.h>		/* pgd_*(), ... */
#include <asm/kmemcheck.h>		/* kmemcheck_*(), ... */

/*
 * Page fault error code bits:
 *
 * bit 0 == 0: no page found 1: protection fault
 * bit 1 == 0: read access 1: write access
 * bit 2 == 0: kernel-mode access 1: user-mode access
 * bit 3 == 1: use of reserved bit detected
 * bit 4 == 1: fault was an instruction fetch
 */
enum x86_pf_error_code {

	PF_PROT		=		1 << 0,
	PF_WRITE	=		1 << 1,
	PF_USER		=		1 << 2,
	PF_RSVD		=		1 << 3,
	PF_INSTR	=		1 << 4,
};

/*
 * Returns 0 if mmiotrace is disabled, or if the fault is not
 * handled by mmiotrace:
 */
static inline int __kprobes
kmmio_fault(struct pt_regs *regs, unsigned long addr)
{
	if (unlikely(is_kmmio_active()))
		if (kmmio_handler(regs, addr) == 1)
			return -1;
	return 0;
}

static inline int __kprobes notify_page_fault(struct pt_regs *regs)
{
	int ret = 0;

	/* kprobe_running() needs smp_processor_id() */
	if (kprobes_built_in() && !user_mode_vm(regs)) {
		preempt_disable();
		if (kprobe_running() && kprobe_fault_handler(regs, 14))
			ret = 1;
		preempt_enable();
	}

	return ret;
}

/*
 * Prefetch quirks:
 *
 * 32-bit mode:
 *
 * Sometimes AMD Athlon/Opteron CPUs report invalid exceptions on prefetch.
 * Check that here and ignore it.
 *
 * 64-bit mode:
 *
 * Sometimes the CPU reports invalid exceptions on prefetch.
 * Check that here and ignore it.
 *
 * Opcode checker based on code by Richard Brunner.
 */
static inline int
check_prefetch_opcode(struct pt_regs *regs, unsigned char *instr,
		      unsigned char opcode, int *prefetch)
{
	unsigned char instr_hi = opcode & 0xf0;
	unsigned char instr_lo = opcode & 0x0f;

	switch (instr_hi) {
	case 0x20:
	case 0x30:
		/*
 * Values 0x26,0x2E,0x36,0x3E are valid x86 prefixes.
 * In X86_64 long mode, the CPU will signal invalid
 * opcode if some of these prefixes are present so
 * X86_64 will never get here anyway
 */
		return ((instr_lo & 7) == 0x6);
#ifdef CONFIG_X86_64
	case 0x40:
		/*
 * In AMD64 long mode 0x40..0x4F are valid REX prefixes
 * Need to figure out under what instruction mode the
 * instruction was issued. Could check the LDT for lm,
 * but for now it's good enough to assume that long
 * mode only uses well known segments or kernel.
 */
		return (!user_mode(regs)) || (regs->cs == __USER_CS);
#endif
	case 0x60:
		/* 0x64 thru 0x67 are valid prefixes in all modes. */
		return (instr_lo & 0xC) == 0x4;
	case 0xF0:
		/* 0xF0, 0xF2, 0xF3 are valid prefixes in all modes. */
		return !instr_lo || (instr_lo>>1) == 1;
	case 0x00:
		/* Prefetch instruction is 0x0F0D or 0x0F18 */
		if (probe_kernel_address(instr, opcode))
			return 0;

		*prefetch = (instr_lo == 0xF) &&
			(opcode == 0x0D || opcode == 0x18);
		return 0;
	default:
		return 0;
	}
}

static int
is_prefetch(struct pt_regs *regs, unsigned long error_code, unsigned long addr)
{
	unsigned char *max_instr;
	unsigned char *instr;
	int prefetch = 0;

	/*
 * If it was a exec (instruction fetch) fault on NX page, then
 * do not ignore the fault:
 */
	if (error_code & PF_INSTR)
		return 0;

	instr = (void *)convert_ip_to_linear(current, regs);
	max_instr = instr + 15;

	if (user_mode(regs) && instr >= (unsigned char *)TASK_SIZE)
		return 0;

	while (instr < max_instr) {
		unsigned char opcode;

		if (probe_kernel_address(instr, opcode))
			break;

		instr++;

		if (!check_prefetch_opcode(regs, instr, opcode, &prefetch))
			break;
	}
	return prefetch;
}

static void
force_sig_info_fault(int si_signo, int si_code, unsigned long address,
		     struct task_struct *tsk, int fault)
{
	unsigned lsb = 0;
	siginfo_t info;

	info.si_signo	= si_signo;
	info.si_errno	= 0;
	info.si_code	= si_code;
	info.si_addr	= (void __user *)address;
	if (fault & VM_FAULT_HWPOISON_LARGE)
		lsb = hstate_index_to_shift(VM_FAULT_GET_HINDEX(fault)); 
	if (fault & VM_FAULT_HWPOISON)
		lsb = PAGE_SHIFT;
	info.si_addr_lsb = lsb;

	force_sig_info(si_signo, &info, tsk);
}

DEFINE_SPINLOCK(pgd_lock);
LIST_HEAD(pgd_list);

#ifdef CONFIG_X86_32
static inline pmd_t *vmalloc_sync_one(pgd_t *pgd, unsigned long address)
{
	unsigned index = pgd_index(address);
	pgd_t *pgd_k;
	pud_t *pud, *pud_k;
	pmd_t *pmd, *pmd_k;

	pgd += index;
	pgd_k = init_mm.pgd + index;

	if (!pgd_present(*pgd_k))
		return NULL;

	/*
 * set_pgd(pgd, *pgd_k); here would be useless on PAE
 * and redundant with the set_pmd() on non-PAE. As would
 * set_pud.
 */
	pud = pud_offset(pgd, address);
	pud_k = pud_offset(pgd_k, address);
	if (!pud_present(*pud_k))
		return NULL;

	pmd = pmd_offset(pud, address);
	pmd_k = pmd_offset(pud_k, address);
	if (!pmd_present(*pmd_k))
		return NULL;

	if (!pmd_present(*pmd))
		set_pmd(pmd, *pmd_k);
	else
		BUG_ON(pmd_page(*pmd) != pmd_page(*pmd_k));

	return pmd_k;
}

void vmalloc_sync_all(void)
{
	unsigned long address;

	if (SHARED_KERNEL_PMD)
		return;

	for (address = VMALLOC_START & PMD_MASK;
	     address >= TASK_SIZE && address < FIXADDR_TOP;
	     address += PMD_SIZE) {
		struct page *page;

		spin_lock(&pgd_lock);
		list_for_each_entry(page, &pgd_list, lru) {
			spinlock_t *pgt_lock;
			pmd_t *ret;

			/* the pgt_lock only for Xen */
			pgt_lock = &pgd_page_get_mm(page)->page_table_lock;

			spin_lock(pgt_lock);
			ret = vmalloc_sync_one(page_address(page), address);
			spin_unlock(pgt_lock);

			if (!ret)
				break;
		}
		spin_unlock(&pgd_lock);
	}
}

/*
 * 32-bit:
 *
 * Handle a fault on the vmalloc or module mapping area
 */
static noinline __kprobes int vmalloc_fault(unsigned long address)
{
	unsigned long pgd_paddr;
	pmd_t *pmd_k;
	pte_t *pte_k;

	/* Make sure we are in vmalloc area: */
	if (!(address >= VMALLOC_START && address < VMALLOC_END))
		return -1;

	WARN_ON_ONCE(in_nmi());

	/*
 * Synchronize this task's top level page-table
 * with the 'reference' page table.
 *
 * Do _not_ use "current" here. We might be inside
 * an interrupt in the middle of a task switch..
 */
	pgd_paddr = read_cr3();
	pmd_k = vmalloc_sync_one(__va(pgd_paddr), address);
	if (!pmd_k)
		return -1;

	pte_k = pte_offset_kernel(pmd_k, address);
	if (!pte_present(*pte_k))
		return -1;

	return 0;
}

/*
 * Did it hit the DOS screen memory VA from vm86 mode?
 */
static inline void
check_v8086_mode(struct pt_regs *regs, unsigned long address,
		 struct task_struct *tsk)
{
	unsigned long bit;

	if (!v8086_mode(regs))
		return;

	bit = (address - 0xA0000) >> PAGE_SHIFT;
	if (bit < 32)
		tsk->thread.screen_bitmap |= 1 << bit;
}

static bool low_pfn(unsigned long pfn)
{
	return pfn < max_low_pfn;
}

static void dump_pagetable(unsigned long address)
{
	pgd_t *base = __va(read_cr3());
	pgd_t *pgd = &base[pgd_index(address)];
	pmd_t *pmd;
	pte_t *pte;

#ifdef CONFIG_X86_PAE
	printk("*pdpt = %016Lx ", pgd_val(*pgd));
	if (!low_pfn(pgd_val(*pgd) >> PAGE_SHIFT) || !pgd_present(*pgd))
		goto out;
#endif
	pmd = pmd_offset(pud_offset(pgd, address), address);
	printk(KERN_CONT "*pde = %0*Lx ", sizeof(*pmd) * 2, (u64)pmd_val(*pmd));

	/*
 * We must not directly access the pte in the highpte
 * case if the page table is located in highmem.
 * And let's rather not kmap-atomic the pte, just in case
 * it's allocated already:
 */
	if (!low_pfn(pmd_pfn(*pmd)) || !pmd_present(*pmd) || pmd_large(*pmd))
		goto out;

	pte = pte_offset_kernel(pmd, address);
	printk("*pte = %0*Lx ", sizeof(*pte) * 2, (u64)pte_val(*pte));
out:
	printk("\n");
}

#else /* CONFIG_X86_64: */

void vmalloc_sync_all(void)
{
	sync_global_pgds(VMALLOC_START & PGDIR_MASK, VMALLOC_END);
}

/*
 * 64-bit:
 *
 * Handle a fault on the vmalloc area
 *
 * This assumes no large pages in there.
 */
static noinline __kprobes int vmalloc_fault(unsigned long address)
{
	pgd_t *pgd, *pgd_ref;
	pud_t *pud, *pud_ref;
	pmd_t *pmd, *pmd_ref;
	pte_t *pte, *pte_ref;

	/* Make sure we are in vmalloc area: */
	if (!(address >= VMALLOC_START && address < VMALLOC_END))
		return -1;

	WARN_ON_ONCE(in_nmi());

	/*
 * Copy kernel mappings over when needed. This can also
 * happen within a race in page table update. In the later
 * case just flush:
 */
	pgd = pgd_offset(current->active_mm, address);
	pgd_ref = pgd_offset_k(address);
	if (pgd_none(*pgd_ref))
		return -1;

	if (pgd_none(*pgd))
		set_pgd(pgd, *pgd_ref);
	else
		BUG_ON(pgd_page_vaddr(*pgd) != pgd_page_vaddr(*pgd_ref));

	/*
 * Below here mismatches are bugs because these lower tables
 * are shared:
 */

	pud = pud_offset(pgd, address);
	pud_ref = pud_offset(pgd_ref, address);
	if (pud_none(*pud_ref))
		return -1;

	if (pud_none(*pud) || pud_page_vaddr(*pud) != pud_page_vaddr(*pud_ref))
		BUG();

	pmd = pmd_offset(pud, address);
	pmd_ref = pmd_offset(pud_ref, address);
	if (pmd_none(*pmd_ref))
		return -1;

	if (pmd_none(*pmd) || pmd_page(*pmd) != pmd_page(*pmd_ref))
		BUG();

	pte_ref = pte_offset_kernel(pmd_ref, address);
	if (!pte_present(*pte_ref))
		return -1;

	pte = pte_offset_kernel(pmd, address);

	/*
 * Don't use pte_page here, because the mappings can point
 * outside mem_map, and the NUMA hash lookup cannot handle
 * that:
 */
	if (!pte_present(*pte) || pte_pfn(*pte) != pte_pfn(*pte_ref))
		BUG();

	return 0;
}

static const char errata93_warning[] =
KERN_ERR 
"******* Your BIOS seems to not contain a fix for K8 errata #93\n"
"******* Working around it, but it may cause SEGVs or burn power.\n"
"******* Please consider a BIOS update.\n"
"******* Disabling USB legacy in the BIOS may also help.\n";

/*
 * No vm86 mode in 64-bit mode:
 */
static inline void
check_v8086_mode(struct pt_regs *regs, unsigned long address,
		 struct task_struct *tsk)
{
}

static int bad_address(void *p)
{
	unsigned long dummy;

	return probe_kernel_address((unsigned long *)p, dummy);
}

static void dump_pagetable(unsigned long address)
{
	pgd_t *base = __va(read_cr3() & PHYSICAL_PAGE_MASK);
	pgd_t *pgd = base + pgd_index(address);
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (bad_address(pgd))
		goto bad;

	printk("PGD %lx ", pgd_val(*pgd));

	if (!pgd_present(*pgd))
		goto out;

	pud = pud_offset(pgd, address);
	if (bad_address(pud))
		goto bad;

	printk("PUD %lx ", pud_val(*pud));
	if (!pud_present(*pud) || pud_large(*pud))
		goto out;

	pmd = pmd_offset(pud, address);
	if (bad_address(pmd))
		goto bad;

	printk("PMD %lx ", pmd_val(*pmd));
	if (!pmd_present(*pmd) || pmd_large(*pmd))
		goto out;

	pte = pte_offset_kernel(pmd, address);
	if (bad_address(pte))
		goto bad;

	printk("PTE %lx", pte_val(*pte));
out:
	printk("\n");
	return;
bad:
	printk("BAD\n");
}

#endif /* CONFIG_X86_64 */

/*
 * Workaround for K8 erratum #93 & buggy BIOS.
 *
 * BIOS SMM functions are required to use a specific workaround
 * to avoid corruption of the 64bit RIP register on C stepping K8.
 *
 * A lot of BIOS that didn't get tested properly miss this.
 *
 * The OS sees this as a page fault with the upper 32bits of RIP cleared.
 * Try to work around it here.
 *
 * Note we only handle faults in kernel here.
 * Does nothing on 32-bit.
 */
static int is_errata93(struct pt_regs *regs, unsigned long address)
{
#ifdef CONFIG_X86_64
	if (address != regs->ip)
		return 0;

	if ((address >> 32) != 0)
		return 0;

	address |= 0xffffffffUL << 32;
	if ((address >= (u64)_stext && address <= (u64)_etext) ||
	    (address >= MODULES_VADDR && address <= MODULES_END)) {
		printk_once(errata93_warning);
		regs->ip = address;
		return 1;
	}
#endif
	return 0;
}

/*
 * Work around K8 erratum #100 K8 in compat mode occasionally jumps
 * to illegal addresses >4GB.
 *
 * We catch this in the page fault handler because these addresses
 * are not reachable. Just detect this case and return. Any code
 * segment in LDT is compatibility mode.
 */
static int is_errata100(struct pt_regs *regs, unsigned long address)
{
#ifdef CONFIG_X86_64
	if ((regs->cs == __USER32_CS || (regs->cs & (1<<2))) && (address >> 32))
		return 1;
#endif
	return 0;
}

static int is_f00f_bug(struct pt_regs *regs, unsigned long address)
{
#ifdef CONFIG_X86_F00F_BUG
	unsigned long nr;

	/*
 * Pentium F0 0F C7 C8 bug workaround:
 */
	if (boot_cpu_data.f00f_bug) {
		nr = (address - idt_descr.address) >> 3;

		if (nr == 6) {
			do_invalid_op(regs, 0);
			return 1;
		}
	}
#endif
	return 0;
}

static const char nx_warning[] = KERN_CRIT
"kernel tried to execute NX-protected page - exploit attempt? (uid: %d)\n";

static void
show_fault_oops(struct pt_regs *regs, unsigned long error_code,
		unsigned long address)
{
	if (!oops_may_print())
		return;

	if (error_code & PF_INSTR) {
		unsigned int level;

		pte_t *pte = lookup_address(address, &level);

		if (pte && pte_present(*pte) && !pte_exec(*pte))
			printk(nx_warning, current_uid());
	}

	printk(KERN_ALERT "BUG: unable to handle kernel ");
	if (address < PAGE_SIZE)
		printk(KERN_CONT "NULL pointer dereference");
	else
		printk(KERN_CONT "paging request");

	printk(KERN_CONT " at %p\n", (void *) address);
	printk(KERN_ALERT "IP:");
	printk_address(regs->ip, 1);

	dump_pagetable(address);
}

static noinline void
pgtable_bad(struct pt_regs *regs, unsigned long error_code,
	    unsigned long address)
{
	struct task_struct *tsk;
	unsigned long flags;
	int sig;

	flags = oops_begin();
	tsk = current;
	sig = SIGKILL;

	printk(KERN_ALERT "%s: Corrupted page table at address %lx\n",
	       tsk->comm, address);
	dump_pagetable(address);

	tsk->thread.cr2		= address;
	tsk->thread.trap_no	= 14;
	tsk->thread.error_code	= error_code;

	if (__die("Bad pagetable", regs, error_code))
		sig = 0;

	oops_end(flags, regs, sig);
}

static noinline void
no_context(struct pt_regs *regs, unsigned long error_code,
	   unsigned long address)
{
	struct task_struct *tsk = current;
	unsigned long *stackend;
	unsigned long flags;
	int sig;

	/* Are we prepared to handle this kernel fault? */
	if (fixup_exception(regs))
		return;

	/*
 * 32-bit:
 *
 * Valid to do another page fault here, because if this fault
 * had been triggered by is_prefetch fixup_exception would have
 * handled it.
 *
 * 64-bit:
 *
 * Hall of shame of CPU/BIOS bugs.
 */
	if (is_prefetch(regs, error_code, address))
		return;

	if (is_errata93(regs, address))
		return;

	/*
 * Oops. The kernel tried to access some bad page. We'll have to
 * terminate things with extreme prejudice:
 */
	flags = oops_begin();

	show_fault_oops(regs, error_code, address);

	stackend = end_of_stack(tsk);
	if (tsk != &init_task && *stackend != STACK_END_MAGIC)
		printk(KERN_ALERT "Thread overran stack, or stack corrupted\n");

	tsk->thread.cr2		= address;
	tsk->thread.trap_no	= 14;
	tsk->thread.error_code	= error_code;

	sig = SIGKILL;
	if (__die("Oops", regs, error_code))
		sig = 0;

	/* Executive summary in case the body of the oops scrolled away */
	printk(KERN_EMERG "CR2: %016lx\n", address);

	oops_end(flags, regs, sig);
}

/*
 * Print out info about fatal segfaults, if the show_unhandled_signals
 * sysctl is set:
 */
static inline void
show_signal_msg(struct pt_regs *regs, unsigned long error_code,
		unsigned long address, struct task_struct *tsk)
{
	if (!unhandled_signal(tsk, SIGSEGV))
		return;

	if (!printk_ratelimit())
		return;

	printk("%s%s[%d]: segfault at %lx ip %p sp %p error %lx",
		task_pid_nr(tsk) > 1 ? KERN_INFO : KERN_EMERG,
		tsk->comm, task_pid_nr(tsk), address,
		(void *)regs->ip, (void *)regs->sp, error_code);

	print_vma_addr(KERN_CONT " in ", regs->ip);

	printk(KERN_CONT "\n");
}

static void
__bad_area_nosemaphore(struct pt_regs *regs, unsigned long error_code,
		       unsigned long address, int si_code)
{
	struct task_struct *tsk = current;

	/* User mode accesses just cause a SIGSEGV */
	if (error_code & PF_USER) {
		/*
 * It's possible to have interrupts off here:
 */
		local_irq_enable();

		/*
 * Valid to do another page fault here because this one came
 * from user space:
 */
		if (is_prefetch(regs, error_code, address))
			return;

		if (is_errata100(regs, address))
			return;

		if (unlikely(show_unhandled_signals))
			show_signal_msg(regs, error_code, address, tsk);

		/* Kernel addresses are always protection faults: */
		tsk->thread.cr2		= address;
		tsk->thread.error_code	= error_code | (address >= TASK_SIZE);
		tsk->thread.trap_no	= 14;

		force_sig_info_fault(SIGSEGV, si_code, address, tsk, 0);

		return;
	}

	if (is_f00f_bug(regs, address))
		return;

	no_context(regs, error_code, address);
}

static noinline void
bad_area_nosemaphore(struct pt_regs *regs, unsigned long error_code,
		     unsigned long address)
{
	__bad_area_nosemaphore(regs, error_code, address, SEGV_MAPERR);
}

static void
__bad_area(struct pt_regs *regs, unsigned long error_code,
	   unsigned long address, int si_code)
{
	struct mm_struct *mm = current->mm;

	/*
 * Something tried to access memory that isn't in our memory map..
 * Fix it, but check if it's kernel or user first..
 */
	up_read(&mm->mmap_sem);

	__bad_area_nosemaphore(regs, error_code, address, si_code);
}

static noinline void
bad_area(struct pt_regs *regs, unsigned long error_code, unsigned long address)
{
	__bad_area(regs, error_code, address, SEGV_MAPERR);
}

static noinline void
bad_area_access_error(struct pt_regs *regs, unsigned long error_code,
		      unsigned long address)
{
	__bad_area(regs, error_code, address, SEGV_ACCERR);
}

/* TODO: fixup for "mm-invoke-oom-killer-from-page-fault.patch" */
static void
out_of_memory(struct pt_regs *regs, unsigned long error_code,
	      unsigned long address)
{
	/*
 * We ran out of memory, call the OOM killer, and return the userspace
 * (which will retry the fault, or kill us if we got oom-killed):
 */
	up_read(&current->mm->mmap_sem);

	pagefault_out_of_memory();
}

static void
do_sigbus(struct pt_regs *regs, unsigned long error_code, unsigned long address,
	  unsigned int fault)
{
	struct task_struct *tsk = current;
	struct mm_struct *mm = tsk->mm;
	int code = BUS_ADRERR;

	up_read(&mm->mmap_sem);

	/* Kernel mode? Handle exceptions or die: */
	if (!(error_code & PF_USER)) {
		no_context(regs, error_code, address);
		return;
	}

	/* User-space => ok to do another page fault: */
	if (is_prefetch(regs, error_code, address))
		return;

	tsk->thread.cr2		= address;
	tsk->thread.error_code	= error_code;
	tsk->thread.trap_no	= 14;

#ifdef CONFIG_MEMORY_FAILURE
	if (fault & (VM_FAULT_HWPOISON|VM_FAULT_HWPOISON_LARGE)) {
		printk(KERN_ERR
	"MCE: Killing %s:%d due to hardware memory corruption fault at %lx\n",
			tsk->comm, tsk->pid, address);
		code = BUS_MCEERR_AR;
	}
#endif
	force_sig_info_fault(SIGBUS, code, address, tsk, fault);
}

static noinline int
mm_fault_error(struct pt_regs *regs, unsigned long error_code,
	       unsigned long address, unsigned int fault)
{
	/*
 * Pagefault was interrupted by SIGKILL. We have no reason to
 * continue pagefault.
 */
	if (fatal_signal_pending(current)) {
		if (!(fault & VM_FAULT_RETRY))
			up_read(&current->mm->mmap_sem);
		if (!(error_code & PF_USER))
			no_context(regs, error_code, address);
		return 1;
	}
	if (!(fault & VM_FAULT_ERROR))
		return 0;

	if (fault & VM_FAULT_OOM) {
		/* Kernel mode? Handle exceptions or die: */
		if (!(error_code & PF_USER)) {
			up_read(&current->mm->mmap_sem);
			no_context(regs, error_code, address);
			return 1;
		}

		out_of_memory(regs, error_code, address);
	} else {
		if (fault & (VM_FAULT_SIGBUS|VM_FAULT_HWPOISON|
			     VM_FAULT_HWPOISON_LARGE))
			do_sigbus(regs, error_code, address, fault);
		else
			BUG();
	}
	return 1;
}

static int spurious_fault_check(unsigned long error_code, pte_t *pte)
{
	if ((error_code & PF_WRITE) && !pte_write(*pte))
		return 0;

	if ((error_code & PF_INSTR) && !pte_exec(*pte))
		return 0;

	return 1;
}

/*
 * Handle a spurious fault caused by a stale TLB entry.
 *
 * This allows us to lazily refresh the TLB when increasing the
 * permissions of a kernel page (RO -> RW or NX -> X). Doing it
 * eagerly is very expensive since that implies doing a full
 * cross-processor TLB flush, even if no stale TLB entries exist
 * on other processors.
 *
 * There are no security implications to leaving a stale TLB when
 * increasing the permissions on a page.
 */
static noinline __kprobes int
spurious_fault(unsigned long error_code, unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int ret;

	/* Reserved-bit violation or user access to kernel space? */
	if (error_code & (PF_USER | PF_RSVD))
		return 0;

	pgd = init_mm.pgd + pgd_index(address);
	if (!pgd_present(*pgd))
		return 0;

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		return 0;

	if (pud_large(*pud))
		return spurious_fault_check(error_code, (pte_t *) pud);

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return 0;

	if (pmd_large(*pmd))
		return spurious_fault_check(error_code, (pte_t *) pmd);

	/*
 * Note: don't use pte_present() here, since it returns true
 * if the _PAGE_PROTNONE bit is set. However, this aliases the
 * _PAGE_GLOBAL bit, which for kernel pages give false positives
 * when CONFIG_DEBUG_PAGEALLOC is used.
 */
	pte = pte_offset_kernel(pmd, address);
	if (!(pte_flags(*pte) & _PAGE_PRESENT))
		return 0;

	ret = spurious_fault_check(error_code, pte);
	if (!ret)
		return 0;

	/*
 * Make sure we have permissions in PMD.
 * If not, then there's a bug in the page tables:
 */
	ret = spurious_fault_check(error_code, (pte_t *) pmd);
	WARN_ONCE(!ret, "PMD has incorrect permission bits\n");

	return ret;
}

int show_unhandled_signals = 1;

static inline int
access_error(unsigned long error_code, struct vm_area_struct *vma)
{
	if (error_code & PF_WRITE) {
		/* write, present and write, not present: */
		if (unlikely(!(vma->vm_flags & VM_WRITE)))
			return 1;
		return 0;
	}

	/* read, present: */
	if (unlikely(error_code & PF_PROT))
		return 1;

	/* read, not present: */
	if (unlikely(!(vma->vm_flags & (VM_READ | VM_EXEC | VM_WRITE))))
		return 1;

	return 0;
}

static int fault_in_kernel_space(unsigned long address)
{
	return address >= TASK_SIZE_MAX;
}

/*
 * This routine handles page faults. It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 */
dotraplinkage void __kprobes
do_page_fault(struct pt_regs *regs, unsigned long error_code)
{
	struct vm_area_struct *vma;
	struct task_struct *tsk;
	unsigned long address;
	struct mm_struct *mm;
	int fault;
	int write = error_code & PF_WRITE;
	unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE |
					(write ? FAULT_FLAG_WRITE : 0);

	tsk = current;
	mm = tsk->mm;

	/* Get the faulting address: */
	address = read_cr2();

	/*
 * Detect and handle instructions that would cause a page fault for
 * both a tracked kernel page and a userspace page.
 */
	if (kmemcheck_active(regs))
		kmemcheck_hide(regs);
	prefetchw(&mm->mmap_sem);

	if (unlikely(kmmio_fault(regs, address)))
		return;

	/*
 * We fault-in kernel-space virtual memory on-demand. The
 * 'reference' page table is init_mm.pgd.
 *
 * NOTE! We MUST NOT take any locks for this case. We may
 * be in an interrupt or a critical region, and should
 * only copy the information from the master page table,
 * nothing more.
 *
 * This verifies that the fault happens in kernel space
 * (error_code & 4) == 0, and that the fault was not a
 * protection error (error_code & 9) == 0.
 */
	if (unlikely(fault_in_kernel_space(address))) {
		if (!(error_code & (PF_RSVD | PF_USER | PF_PROT))) {
			if (vmalloc_fault(address) >= 0)
				return;

			if (kmemcheck_fault(regs, address, error_code))
				return;
		}

		/* Can handle a stale RO->RW TLB: */
		if (spurious_fault(error_code, address))
			return;

		/* kprobes don't want to hook the spurious faults: */
		if (notify_page_fault(regs))
			return;
		/*
 * Don't take the mm semaphore here. If we fixup a prefetch
 * fault we could otherwise deadlock:
 */
		bad_area_nosemaphore(regs, error_code, address);

		return;
	}

	/* kprobes don't want to hook the spurious faults: */
	if (unlikely(notify_page_fault(regs)))
		return;
	/*
 * It's safe to allow irq's after cr2 has been saved and the
 * vmalloc fault has been handled.
 *
 * User-mode registers count as a user access even for any
 * potential system fault or CPU buglet:
 */
	if (user_mode_vm(regs)) {
		local_irq_enable();
		error_code |= PF_USER;
	} else {
		if (regs->flags & X86_EFLAGS_IF)
			local_irq_enable();
	}

	if (unlikely(error_code & PF_RSVD))
		pgtable_bad(regs, error_code, address);

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, 0, regs, address);

	/*
 * If we're in an interrupt, have no user context or are running
 * in an atomic region then we must not take the fault:
 */
	if (unlikely(in_atomic() || !mm)) {
		bad_area_nosemaphore(regs, error_code, address);
		return;
	}

	/*
 * When running in the kernel we expect faults to occur only to
 * addresses in user space. All other faults represent errors in
 * the kernel and should generate an OOPS. Unfortunately, in the
 * case of an erroneous fault occurring in a code path which already
 * holds mmap_sem we will deadlock attempting to validate the fault
 * against the address space. Luckily the kernel only validly
 * references user space from well defined areas of code, which are
 * listed in the exceptions table.
 *
 * As the vast majority of faults will be valid we will only perform
 * the source reference check when there is a possibility of a
 * deadlock. Attempt to lock the address space, if we cannot we then
 * validate the source. If this is invalid we can skip the address
 * space check, thus avoiding the deadlock:
 */
	if (unlikely(!down_read_trylock(&mm->mmap_sem))) {
		if ((error_code & PF_USER) == 0 &&
		    !search_exception_tables(regs->ip)) {
			bad_area_nosemaphore(regs, error_code, address);
			return;
		}
retry:
		down_read(&mm->mmap_sem);
	} else {
		/*
 * The above down_read_trylock() might have succeeded in
 * which case we'll have missed the might_sleep() from
 * down_read():
 */
		might_sleep();
	}

	vma = find_vma(mm, address);
	if (unlikely(!vma)) {
		bad_area(regs, error_code, address);
		return;
	}
	if (likely(vma->vm_start <= address))
		goto good_area;
	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN))) {
		bad_area(regs, error_code, address);
		return;
	}
	if (error_code & PF_USER) {
		/*
 * Accessing the stack below %sp is always a bug.
 * The large cushion allows instructions like enter
 * and pusha to work. ("enter $65535, $31" pushes
 * 32 pointers and then decrements %sp by 65535.)
 */
		if (unlikely(address + 65536 + 32 * sizeof(unsigned long) < regs->sp)) {
			bad_area(regs, error_code, address);
			return;
		}
	}
	if (unlikely(expand_stack(vma, address))) {
		bad_area(regs, error_code, address);
		return;
	}

	/*
 * Ok, we have a good vm_area for this memory access, so
 * we can handle it..
 */
good_area:
	if (unlikely(access_error(error_code, vma))) {
		bad_area_access_error(regs, error_code, address);
		return;
	}

	/*
 * If for any reason at all we couldn't handle the fault,
 * make sure we exit gracefully rather than endlessly redo
 * the fault:
 */
	fault = handle_mm_fault(mm, vma, address, flags);

	if (unlikely(fault & (VM_FAULT_RETRY|VM_FAULT_ERROR))) {
		if (mm_fault_error(regs, error_code, address, fault))
			return;
	}

	/*
 * Major/minor page fault accounting is only done on the
 * initial attempt. If we go through a retry, it is extremely
 * likely that the page will be found in page cache at that point.
 */
	if (flags & FAULT_FLAG_ALLOW_RETRY) {
		if (fault & VM_FAULT_MAJOR) {
			tsk->maj_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ, 1, 0,
				      regs, address);
		} else {
			tsk->min_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN, 1, 0,
				      regs, address);
		}
		if (fault & VM_FAULT_RETRY) {
			/* Clear FAULT_FLAG_ALLOW_RETRY to avoid any risk
 * of starvation. */
			flags &= ~FAULT_FLAG_ALLOW_RETRY;
			goto retry;
		}
	}

	check_v8086_mode(regs, address, tsk);

	up_read(&mm->mmap_sem);
}