

/*
 * linux/arch/arm/kernel/ptrace.c
 *
 * By Ross Biro 1/23/92
 * edited by Linus Torvalds
 * ARM modifications Copyright (C) 2000 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/ptrace.h>
#include <linux/user.h>
#include <linux/security.h>
#include <linux/init.h>
#include <linux/signal.h>
#include <linux/uaccess.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/regset.h>

#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/traps.h>

#define REG_PC 15
#define REG_PSR 16
/*
 * does not yet catch signals sent when the child dies.
 * in exit.c or in signal.c.
 */

#if 0
/*
 * Breakpoint SWI instruction: SWI &9F0001
 */
#define BREAKINST_ARM 0xef9f0001
#define BREAKINST_THUMB 0xdf00		/* fill this in later */
#else
/*
 * New breakpoints - use an undefined instruction. The ARM architecture
 * reference manual guarantees that the following instruction space
 * will produce an undefined instruction exception on all CPUs:
 *
 * ARM: xxxx 0111 1111 xxxx xxxx xxxx 1111 xxxx
 * Thumb: 1101 1110 xxxx xxxx
 */
#define BREAKINST_ARM 0xe7f001f0
#define BREAKINST_THUMB 0xde01
#endif

struct pt_regs_offset {
	const char *name;
	int offset;
};

#define REG_OFFSET_NAME(r) \
 {.name = #r, .offset = offsetof(struct pt_regs, ARM_##r)}
#define REG_OFFSET_END {.name = NULL, .offset = 0}

static const struct pt_regs_offset regoffset_table[] = {
	REG_OFFSET_NAME(r0),
	REG_OFFSET_NAME(r1),
	REG_OFFSET_NAME(r2),
	REG_OFFSET_NAME(r3),
	REG_OFFSET_NAME(r4),
	REG_OFFSET_NAME(r5),
	REG_OFFSET_NAME(r6),
	REG_OFFSET_NAME(r7),
	REG_OFFSET_NAME(r8),
	REG_OFFSET_NAME(r9),
	REG_OFFSET_NAME(r10),
	REG_OFFSET_NAME(fp),
	REG_OFFSET_NAME(ip),
	REG_OFFSET_NAME(sp),
	REG_OFFSET_NAME(lr),
	REG_OFFSET_NAME(pc),
	REG_OFFSET_NAME(cpsr),
	REG_OFFSET_NAME(ORIG_r0),
	REG_OFFSET_END,
};

/**
 * regs_query_register_offset() - query register offset from its name
 * @name: the name of a register
 *
 * regs_query_register_offset() returns the offset of a register in struct
 * pt_regs from its name. If the name is invalid, this returns -EINVAL;
 */
int regs_query_register_offset(const char *name)
{
	const struct pt_regs_offset *roff;
	for (roff = regoffset_table; roff->name != NULL; roff++)
		if (!strcmp(roff->name, name))
			return roff->offset;
	return -EINVAL;
}

/**
 * regs_query_register_name() - query register name from its offset
 * @offset: the offset of a register in struct pt_regs.
 *
 * regs_query_register_name() returns the name of a register from its
 * offset in struct pt_regs. If the @offset is invalid, this returns NULL;
 */
const char *regs_query_register_name(unsigned int offset)
{
	const struct pt_regs_offset *roff;
	for (roff = regoffset_table; roff->name != NULL; roff++)
		if (roff->offset == offset)
			return roff->name;
	return NULL;
}

/**
 * regs_within_kernel_stack() - check the address in the stack
 * @regs: pt_regs which contains kernel stack pointer.
 * @addr: address which is checked.
 *
 * regs_within_kernel_stack() checks @addr is within the kernel stack page(s).
 * If @addr is within the kernel stack, it returns true. If not, returns false.
 */
bool regs_within_kernel_stack(struct pt_regs *regs, unsigned long addr)
{
	return ((addr & ~(THREAD_SIZE - 1)) ==
		(kernel_stack_pointer(regs) & ~(THREAD_SIZE - 1)));
}

/**
 * regs_get_kernel_stack_nth() - get Nth entry of the stack
 * @regs: pt_regs which contains kernel stack pointer.
 * @n: stack entry number.
 *
 * regs_get_kernel_stack_nth() returns @n th entry of the kernel stack which
 * is specified by @regs. If the @n th entry is NOT in the kernel stack,
 * this returns 0.
 */
unsigned long regs_get_kernel_stack_nth(struct pt_regs *regs, unsigned int n)
{
	unsigned long *addr = (unsigned long *)kernel_stack_pointer(regs);
	addr += n;
	if (regs_within_kernel_stack(regs, (unsigned long)addr))
		return *addr;
	else
		return 0;
}

/*
 * this routine will get a word off of the processes privileged stack.
 * the offset is how far from the base addr as stored in the THREAD.
 * this routine assumes that all the privileged stacks are in our
 * data space.
 */
static inline long get_user_reg(struct task_struct *task, int offset)
{
	return task_pt_regs(task)->uregs[offset];
}

/*
 * this routine will put a word on the processes privileged stack.
 * the offset is how far from the base addr as stored in the THREAD.
 * this routine assumes that all the privileged stacks are in our
 * data space.
 */
static inline int
put_user_reg(struct task_struct *task, int offset, long data)
{
	struct pt_regs newregs, *regs = task_pt_regs(task);
	int ret = -EINVAL;

	newregs = *regs;
	newregs.uregs[offset] = data;

	if (valid_user_regs(&newregs)) {
		regs->uregs[offset] = data;
		ret = 0;
	}

	return ret;
}

/*
 * Called by kernel/ptrace.c when detaching..
 */
void ptrace_disable(struct task_struct *child)
{
	/* Nothing to do. */
}

/*
 * Handle hitting a breakpoint.
 */
void ptrace_break(struct task_struct *tsk, struct pt_regs *regs)
{
	siginfo_t info;

	info.si_signo = SIGTRAP;
	info.si_errno = 0;
	info.si_code  = TRAP_BRKPT;
	info.si_addr  = (void __user *)instruction_pointer(regs);

	force_sig_info(SIGTRAP, &info, tsk);
}

static int break_trap(struct pt_regs *regs, unsigned int instr)
{
	ptrace_break(current, regs);
	return 0;
}

static struct undef_hook arm_break_hook = {
	.instr_mask	= 0x0fffffff,
	.instr_val	= 0x07f001f0,
	.cpsr_mask	= PSR_T_BIT,
	.cpsr_val	= 0,
	.fn		= break_trap,
};

static struct undef_hook thumb_break_hook = {
	.instr_mask	= 0xffff,
	.instr_val	= 0xde01,
	.cpsr_mask	= PSR_T_BIT,
	.cpsr_val	= PSR_T_BIT,
	.fn		= break_trap,
};

static int thumb2_break_trap(struct pt_regs *regs, unsigned int instr)
{
	unsigned int instr2;
	void __user *pc;

	/* Check the second half of the instruction. */
	pc = (void __user *)(instruction_pointer(regs) + 2);

	if (processor_mode(regs) == SVC_MODE) {
		instr2 = *(u16 *) pc;
	} else {
		get_user(instr2, (u16 __user *)pc);
	}

	if (instr2 == 0xa000) {
		ptrace_break(current, regs);
		return 0;
	} else {
		return 1;
	}
}

static struct undef_hook thumb2_break_hook = {
	.instr_mask	= 0xffff,
	.instr_val	= 0xf7f0,
	.cpsr_mask	= PSR_T_BIT,
	.cpsr_val	= PSR_T_BIT,
	.fn		= thumb2_break_trap,
};

static int __init ptrace_break_init(void)
{
	register_undef_hook(&arm_break_hook);
	register_undef_hook(&thumb_break_hook);
	register_undef_hook(&thumb2_break_hook);
	return 0;
}

core_initcall(ptrace_break_init);

/*
 * Read the word at offset "off" into the "struct user". We
 * actually access the pt_regs stored on the kernel stack.
 */
static int ptrace_read_user(struct task_struct *tsk, unsigned long off,
			    unsigned long __user *ret)
{
	unsigned long tmp;

	if (off & 3 || off >= sizeof(struct user))
		return -EIO;

	tmp = 0;
	if (off == PT_TEXT_ADDR)
		tmp = tsk->mm->start_code;
	else if (off == PT_DATA_ADDR)
		tmp = tsk->mm->start_data;
	else if (off == PT_TEXT_END_ADDR)
		tmp = tsk->mm->end_code;
	else if (off < sizeof(struct pt_regs))
		tmp = get_user_reg(tsk, off >> 2);

	return put_user(tmp, ret);
}

/*
 * Write the word at offset "off" into "struct user". We
 * actually access the pt_regs stored on the kernel stack.
 */
static int ptrace_write_user(struct task_struct *tsk, unsigned long off,
			     unsigned long val)
{
	if (off & 3 || off >= sizeof(struct user))
		return -EIO;

	if (off >= sizeof(struct pt_regs))
		return 0;

	return put_user_reg(tsk, off >> 2, val);
}

#ifdef CONFIG_IWMMXT

/*
 * Get the child iWMMXt state.
 */
static int ptrace_getwmmxregs(struct task_struct *tsk, void __user *ufp)
{
	struct thread_info *thread = task_thread_info(tsk);

	if (!test_ti_thread_flag(thread, TIF_USING_IWMMXT))
		return -ENODATA;
	iwmmxt_task_disable(thread);  /* force it to ram */
	return copy_to_user(ufp, &thread->fpstate.iwmmxt, IWMMXT_SIZE)
		? -EFAULT : 0;
}

/*
 * Set the child iWMMXt state.
 */
static int ptrace_setwmmxregs(struct task_struct *tsk, void __user *ufp)
{
	struct thread_info *thread = task_thread_info(tsk);

	if (!test_ti_thread_flag(thread, TIF_USING_IWMMXT))
		return -EACCES;
	iwmmxt_task_release(thread);  /* force a reload */
	return copy_from_user(&thread->fpstate.iwmmxt, ufp, IWMMXT_SIZE)
		? -EFAULT : 0;
}

#endif

#ifdef CONFIG_CRUNCH
/*
 * Get the child Crunch state.
 */
static int ptrace_getcrunchregs(struct task_struct *tsk, void __user *ufp)
{
	struct thread_info *thread = task_thread_info(tsk);

	crunch_task_disable(thread);  /* force it to ram */
	return copy_to_user(ufp, &thread->crunchstate, CRUNCH_SIZE)
		? -EFAULT : 0;
}

/*
 * Set the child Crunch state.
 */
static int ptrace_setcrunchregs(struct task_struct *tsk, void __user *ufp)
{
	struct thread_info *thread = task_thread_info(tsk);

	crunch_task_release(thread);  /* force a reload */
	return copy_from_user(&thread->crunchstate, ufp, CRUNCH_SIZE)
		? -EFAULT : 0;
}
#endif

#ifdef CONFIG_HAVE_HW_BREAKPOINT
/*
 * Convert a virtual register number into an index for a thread_info
 * breakpoint array. Breakpoints are identified using positive numbers
 * whilst watchpoints are negative. The registers are laid out as pairs
 * of (address, control), each pair mapping to a unique hw_breakpoint struct.
 * Register 0 is reserved for describing resource information.
 */
static int ptrace_hbp_num_to_idx(long num)
{
	if (num < 0)
		num = (ARM_MAX_BRP << 1) - num;
	return (num - 1) >> 1;
}

/*
 * Returns the virtual register number for the address of the
 * breakpoint at index idx.
 */
static long ptrace_hbp_idx_to_num(int idx)
{
	long mid = ARM_MAX_BRP << 1;
	long num = (idx << 1) + 1;
	return num > mid ? mid - num : num;
}

/*
 * Handle hitting a HW-breakpoint.
 */
static void ptrace_hbptriggered(struct perf_event *bp, int unused,
				     struct perf_sample_data *data,
				     struct pt_regs *regs)
{
	struct arch_hw_breakpoint *bkpt = counter_arch_bp(bp);
	long num;
	int i;
	siginfo_t info;

	for (i = 0; i < ARM_MAX_HBP_SLOTS; ++i)
		if (current->thread.debug.hbp[i] == bp)
			break;

	num = (i == ARM_MAX_HBP_SLOTS) ? 0 : ptrace_hbp_idx_to_num(i);

	info.si_signo	= SIGTRAP;
	info.si_errno	= (int)num;
	info.si_code	= TRAP_HWBKPT;
	info.si_addr	= (void __user *)(bkpt->trigger);

	force_sig_info(SIGTRAP, &info, current);
}

/*
 * Set ptrace breakpoint pointers to zero for this task.
 * This is required in order to prevent child processes from unregistering
 * breakpoints held by their parent.
 */
void clear_ptrace_hw_breakpoint(struct task_struct *tsk)
{
	memset(tsk->thread.debug.hbp, 0, sizeof(tsk->thread.debug.hbp));
}

/*
 * Unregister breakpoints from this task and reset the pointers in
 * the thread_struct.
 */
void flush_ptrace_hw_breakpoint(struct task_struct *tsk)
{
	int i;
	struct thread_struct *t = &tsk->thread;

	for (i = 0; i < ARM_MAX_HBP_SLOTS; i++) {
		if (t->debug.hbp[i]) {
			unregister_hw_breakpoint(t->debug.hbp[i]);
			t->debug.hbp[i] = NULL;
		}
	}
}

static u32 ptrace_get_hbp_resource_info(void)
{
	u8 num_brps, num_wrps, debug_arch, wp_len;
	u32 reg = 0;

	num_brps	= hw_breakpoint_slots(TYPE_INST);
	num_wrps	= hw_breakpoint_slots(TYPE_DATA);
	debug_arch	= arch_get_debug_arch();
	wp_len		= arch_get_max_wp_len();

	reg		|= debug_arch;
	reg		<<= 8;
	reg		|= wp_len;
	reg		<<= 8;
	reg		|= num_wrps;
	reg		<<= 8;
	reg		|= num_brps;

	return reg;
}

static struct perf_event *ptrace_hbp_create(struct task_struct *tsk, int type)
{
	struct perf_event_attr attr;

	ptrace_breakpoint_init(&attr);

	/* Initialise fields to sane defaults. */
	attr.bp_addr	= 0;
	attr.bp_len	= HW_BREAKPOINT_LEN_4;
	attr.bp_type	= type;
	attr.disabled	= 1;

	return register_user_hw_breakpoint(&attr, ptrace_hbptriggered, tsk);
}

static int ptrace_gethbpregs(struct task_struct *tsk, long num,
			     unsigned long  __user *data)
{
	u32 reg;
	int idx, ret = 0;
	struct perf_event *bp;
	struct arch_hw_breakpoint_ctrl arch_ctrl;

	if (num == 0) {
		reg = ptrace_get_hbp_resource_info();
	} else {
		idx = ptrace_hbp_num_to_idx(num);
		if (idx < 0 || idx >= ARM_MAX_HBP_SLOTS) {
			ret = -EINVAL;
			goto out;
		}

		bp = tsk->thread.debug.hbp[idx];
		if (!bp) {
			reg = 0;
			goto put;
		}

		arch_ctrl = counter_arch_bp(bp)->ctrl;

		/*
 * Fix up the len because we may have adjusted it
 * to compensate for an unaligned address.
 */
		while (!(arch_ctrl.len & 0x1))
			arch_ctrl.len >>= 1;

		if (num & 0x1)
			reg = bp->attr.bp_addr;
		else
			reg = encode_ctrl_reg(arch_ctrl);
	}

put:
	if (put_user(reg, data))
		ret = -EFAULT;

out:
	return ret;
}

static int ptrace_sethbpregs(struct task_struct *tsk, long num,
			     unsigned long __user *data)
{
	int idx, gen_len, gen_type, implied_type, ret = 0;
	u32 user_val;
	struct perf_event *bp;
	struct arch_hw_breakpoint_ctrl ctrl;
	struct perf_event_attr attr;

	if (num == 0)
		goto out;
	else if (num < 0)
		implied_type = HW_BREAKPOINT_RW;
	else
		implied_type = HW_BREAKPOINT_X;

	idx = ptrace_hbp_num_to_idx(num);
	if (idx < 0 || idx >= ARM_MAX_HBP_SLOTS) {
		ret = -EINVAL;
		goto out;
	}

	if (get_user(user_val, data)) {
		ret = -EFAULT;
		goto out;
	}

	bp = tsk->thread.debug.hbp[idx];
	if (!bp) {
		bp = ptrace_hbp_create(tsk, implied_type);
		if (IS_ERR(bp)) {
			ret = PTR_ERR(bp);
			goto out;
		}
		tsk->thread.debug.hbp[idx] = bp;
	}

	attr = bp->attr;

	if (num & 0x1) {
		/* Address */
		attr.bp_addr	= user_val;
	} else {
		/* Control */
		decode_ctrl_reg(user_val, &ctrl);
		ret = arch_bp_generic_fields(ctrl, &gen_len, &gen_type);
		if (ret)
			goto out;

		if ((gen_type & implied_type) != gen_type) {
			ret = -EINVAL;
			goto out;
		}

		attr.bp_len	= gen_len;
		attr.bp_type	= gen_type;
		attr.disabled	= !ctrl.enabled;
	}

	ret = modify_user_hw_breakpoint(bp, &attr);
out:
	return ret;
}
#endif

/* regset get/set implementations */

static int gpr_get(struct task_struct *target,
		   const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   void *kbuf, void __user *ubuf)
{
	struct pt_regs *regs = task_pt_regs(target);

	return user_regset_copyout(&pos, &count, &kbuf, &ubuf,
				   regs,
				   0, sizeof(*regs));
}

static int gpr_set(struct task_struct *target,
		   const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   const void *kbuf, const void __user *ubuf)
{
	int ret;
	struct pt_regs newregs;

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf,
				 &newregs,
				 0, sizeof(newregs));
	if (ret)
		return ret;

	if (!valid_user_regs(&newregs))
		return -EINVAL;

	*task_pt_regs(target) = newregs;
	return 0;
}

static int fpa_get(struct task_struct *target,
		   const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   void *kbuf, void __user *ubuf)
{
	return user_regset_copyout(&pos, &count, &kbuf, &ubuf,
				   &task_thread_info(target)->fpstate,
				   0, sizeof(struct user_fp));
}

static int fpa_set(struct task_struct *target,
		   const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   const void *kbuf, const void __user *ubuf)
{
	struct thread_info *thread = task_thread_info(target);

	thread->used_cp[1] = thread->used_cp[2] = 1;

	return user_regset_copyin(&pos, &count, &kbuf, &ubuf,
		&thread->fpstate,
		0, sizeof(struct user_fp));
}

#ifdef CONFIG_VFP
/*
 * VFP register get/set implementations.
 *
 * With respect to the kernel, struct user_fp is divided into three chunks:
 * 16 or 32 real VFP registers (d0-d15 or d0-31)
 * These are transferred to/from the real registers in the task's
 * vfp_hard_struct. The number of registers depends on the kernel
 * configuration.
 *
 * 16 or 0 fake VFP registers (d16-d31 or empty)
 * i.e., the user_vfp structure has space for 32 registers even if
 * the kernel doesn't have them all.
 *
 * vfp_get() reads this chunk as zero where applicable
 * vfp_set() ignores this chunk
 *
 * 1 word for the FPSCR
 *
 * The bounds-checking logic built into user_regset_copyout and friends
 * means that we can make a simple sequence of calls to map the relevant data
 * to/from the specified slice of the user regset structure.
 */
static int vfp_get(struct task_struct *target,
		   const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   void *kbuf, void __user *ubuf)
{
	int ret;
	struct thread_info *thread = task_thread_info(target);
	struct vfp_hard_struct const *vfp = &thread->vfpstate.hard;
	const size_t user_fpregs_offset = offsetof(struct user_vfp, fpregs);
	const size_t user_fpscr_offset = offsetof(struct user_vfp, fpscr);

	vfp_sync_hwstate(thread);

	ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf,
				  &vfp->fpregs,
				  user_fpregs_offset,
				  user_fpregs_offset + sizeof(vfp->fpregs));
	if (ret)
		return ret;

	ret = user_regset_copyout_zero(&pos, &count, &kbuf, &ubuf,
				       user_fpregs_offset + sizeof(vfp->fpregs),
				       user_fpscr_offset);
	if (ret)
		return ret;

	return user_regset_copyout(&pos, &count, &kbuf, &ubuf,
				   &vfp->fpscr,
				   user_fpscr_offset,
				   user_fpscr_offset + sizeof(vfp->fpscr));
}

/*
 * For vfp_set() a read-modify-write is done on the VFP registers,
 * in order to avoid writing back a half-modified set of registers on
 * failure.
 */
static int vfp_set(struct task_struct *target,
			  const struct user_regset *regset,
			  unsigned int pos, unsigned int count,
			  const void *kbuf, const void __user *ubuf)
{
	int ret;
	struct thread_info *thread = task_thread_info(target);
	struct vfp_hard_struct new_vfp = thread->vfpstate.hard;
	const size_t user_fpregs_offset = offsetof(struct user_vfp, fpregs);
	const size_t user_fpscr_offset = offsetof(struct user_vfp, fpscr);

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf,
				  &new_vfp.fpregs,
				  user_fpregs_offset,
				  user_fpregs_offset + sizeof(new_vfp.fpregs));
	if (ret)
		return ret;

	ret = user_regset_copyin_ignore(&pos, &count, &kbuf, &ubuf,
				user_fpregs_offset + sizeof(new_vfp.fpregs),
				user_fpscr_offset);
	if (ret)
		return ret;

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf,
				 &new_vfp.fpscr,
				 user_fpscr_offset,
				 user_fpscr_offset + sizeof(new_vfp.fpscr));
	if (ret)
		return ret;

	vfp_sync_hwstate(thread);
	thread->vfpstate.hard = new_vfp;
	vfp_flush_hwstate(thread);

	return 0;
}
#endif /* CONFIG_VFP */

enum arm_regset {
	REGSET_GPR,
	REGSET_FPR,
#ifdef CONFIG_VFP
	REGSET_VFP,
#endif
};

static const struct user_regset arm_regsets[] = {
	[REGSET_GPR] = {
		.core_note_type = NT_PRSTATUS,
		.n = ELF_NGREG,
		.size = sizeof(u32),
		.align = sizeof(u32),
		.get = gpr_get,
		.set = gpr_set
	},
	[REGSET_FPR] = {
		/*
 * For the FPA regs in fpstate, the real fields are a mixture
 * of sizes, so pretend that the registers are word-sized:
 */
		.core_note_type = NT_PRFPREG,
		.n = sizeof(struct user_fp) / sizeof(u32),
		.size = sizeof(u32),
		.align = sizeof(u32),
		.get = fpa_get,
		.set = fpa_set
	},
#ifdef CONFIG_VFP
	[REGSET_VFP] = {
		/*
 * Pretend that the VFP regs are word-sized, since the FPSCR is
 * a single word dangling at the end of struct user_vfp:
 */
		.core_note_type = NT_ARM_VFP,
		.n = ARM_VFPREGS_SIZE / sizeof(u32),
		.size = sizeof(u32),
		.align = sizeof(u32),
		.get = vfp_get,
		.set = vfp_set
	},
#endif /* CONFIG_VFP */
};

static const struct user_regset_view user_arm_view = {
	.name = "arm", .e_machine = ELF_ARCH, .ei_osabi = ELF_OSABI,
	.regsets = arm_regsets, .n = ARRAY_SIZE(arm_regsets)
};

const struct user_regset_view *task_user_regset_view(struct task_struct *task)
{
	return &user_arm_view;
}

long arch_ptrace(struct task_struct *child, long request,
		 unsigned long addr, unsigned long data)
{
	int ret;
	unsigned long __user *datap = (unsigned long __user *) data;

	switch (request) {
		case PTRACE_PEEKUSR:
			ret = ptrace_read_user(child, addr, datap);
			break;

		case PTRACE_POKEUSR:
			ret = ptrace_write_user(child, addr, data);
			break;

		case PTRACE_GETREGS:
			ret = copy_regset_to_user(child,
						  &user_arm_view, REGSET_GPR,
						  0, sizeof(struct pt_regs),
						  datap);
			break;

		case PTRACE_SETREGS:
			ret = copy_regset_from_user(child,
						    &user_arm_view, REGSET_GPR,
						    0, sizeof(struct pt_regs),
						    datap);
			break;

		case PTRACE_GETFPREGS:
			ret = copy_regset_to_user(child,
						  &user_arm_view, REGSET_FPR,
						  0, sizeof(union fp_state),
						  datap);
			break;

		case PTRACE_SETFPREGS:
			ret = copy_regset_from_user(child,
						    &user_arm_view, REGSET_FPR,
						    0, sizeof(union fp_state),
						    datap);
			break;

#ifdef CONFIG_IWMMXT
		case PTRACE_GETWMMXREGS:
			ret = ptrace_getwmmxregs(child, datap);
			break;

		case PTRACE_SETWMMXREGS:
			ret = ptrace_setwmmxregs(child, datap);
			break;
#endif

		case PTRACE_GET_THREAD_AREA:
			ret = put_user(task_thread_info(child)->tp_value,
				       datap);
			break;

		case PTRACE_SET_SYSCALL:
			task_thread_info(child)->syscall = data;
			ret = 0;
			break;

#ifdef CONFIG_CRUNCH
		case PTRACE_GETCRUNCHREGS:
			ret = ptrace_getcrunchregs(child, datap);
			break;

		case PTRACE_SETCRUNCHREGS:
			ret = ptrace_setcrunchregs(child, datap);
			break;
#endif

#ifdef CONFIG_VFP
		case PTRACE_GETVFPREGS:
			ret = copy_regset_to_user(child,
						  &user_arm_view, REGSET_VFP,
						  0, ARM_VFPREGS_SIZE,
						  datap);
			break;

		case PTRACE_SETVFPREGS:
			ret = copy_regset_from_user(child,
						    &user_arm_view, REGSET_VFP,
						    0, ARM_VFPREGS_SIZE,
						    datap);
			break;
#endif

#ifdef CONFIG_HAVE_HW_BREAKPOINT
		case PTRACE_GETHBPREGS:
			if (ptrace_get_breakpoints(child) < 0)
				return -ESRCH;

			ret = ptrace_gethbpregs(child, addr,
						(unsigned long __user *)data);
			ptrace_put_breakpoints(child);
			break;
		case PTRACE_SETHBPREGS:
			if (ptrace_get_breakpoints(child) < 0)
				return -ESRCH;

			ret = ptrace_sethbpregs(child, addr,
						(unsigned long __user *)data);
			ptrace_put_breakpoints(child);
			break;
#endif

		default:
			ret = ptrace_request(child, request, addr, data);
			break;
	}

	return ret;
}

asmlinkage int syscall_trace(int why, struct pt_regs *regs, int scno)
{
	unsigned long ip;

	if (!test_thread_flag(TIF_SYSCALL_TRACE))
		return scno;
	if (!(current->ptrace & PT_PTRACED))
		return scno;

	/*
 * Save IP. IP is used to denote syscall entry/exit:
 * IP = 0 -> entry, = 1 -> exit
 */
	ip = regs->ARM_ip;
	regs->ARM_ip = why;

	current_thread_info()->syscall = scno;

	/* the 0x80 provides a way for the tracing parent to distinguish
 between a syscall stop and SIGTRAP delivery */
	ptrace_notify(SIGTRAP | ((current->ptrace & PT_TRACESYSGOOD)
				 ? 0x80 : 0));
	/*
 * this isn't the same as continuing with a signal, but it will do
 * for normal use. strace only continues with a signal if the
 * stopping signal is not SIGTRAP. -brl
 */
	if (current->exit_code) {
		send_sig(current->exit_code, current, 1);
		current->exit_code = 0;
	}
	regs->ARM_ip = ip;

	return current_thread_info()->syscall;
}

/*
 * PowerPC version
 * Copyright (C) 1995-1996 Gary Thomas (gdt@linuxppc.org)
 *
 * Derived from "arch/m68k/kernel/ptrace.c"
 * Copyright (C) 1994 by Hamish Macdonald
 * Taken from linux/kernel/ptrace.c and modified for M680x0.
 * linux/kernel/ptrace.c is by Ross Biro 1/23/92, edited by Linus Torvalds
 *
 * Modified by Cort Dougan (cort@hq.fsmlabs.com)
 * and Paul Mackerras (paulus@samba.org).
 *
 * This file is subject to the terms and conditions of the GNU General
 * Public License. See the file README.legal in the main directory of
 * this archive for more details.
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#include <linux/regset.h>
#include <linux/tracehook.h>
#include <linux/elf.h>
#include <linux/user.h>
#include <linux/security.h>
#include <linux/signal.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <trace/syscall.h>
#ifdef CONFIG_PPC32
#include <linux/module.h>
#endif
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>

#include <asm/uaccess.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/system.h>

#define CREATE_TRACE_POINTS
#include <trace/events/syscalls.h>

/*
 * The parameter save area on the stack is used to store arguments being passed
 * to callee function and is located at fixed offset from stack pointer.
 */
#ifdef CONFIG_PPC32
#define PARAMETER_SAVE_AREA_OFFSET 24  /* bytes */
#else /* CONFIG_PPC32 */
#define PARAMETER_SAVE_AREA_OFFSET 48  /* bytes */
#endif

struct pt_regs_offset {
	const char *name;
	int offset;
};

#define STR(s) #s			/* convert to string */
#define REG_OFFSET_NAME(r) {.name = #r, .offset = offsetof(struct pt_regs, r)}
#define GPR_OFFSET_NAME(num) \
 {.name = STR(gpr##num), .offset = offsetof(struct pt_regs, gpr[num])}
#define REG_OFFSET_END {.name = NULL, .offset = 0}

static const struct pt_regs_offset regoffset_table[] = {
	GPR_OFFSET_NAME(0),
	GPR_OFFSET_NAME(1),
	GPR_OFFSET_NAME(2),
	GPR_OFFSET_NAME(3),
	GPR_OFFSET_NAME(4),
	GPR_OFFSET_NAME(5),
	GPR_OFFSET_NAME(6),
	GPR_OFFSET_NAME(7),
	GPR_OFFSET_NAME(8),
	GPR_OFFSET_NAME(9),
	GPR_OFFSET_NAME(10),
	GPR_OFFSET_NAME(11),
	GPR_OFFSET_NAME(12),
	GPR_OFFSET_NAME(13),
	GPR_OFFSET_NAME(14),
	GPR_OFFSET_NAME(15),
	GPR_OFFSET_NAME(16),
	GPR_OFFSET_NAME(17),
	GPR_OFFSET_NAME(18),
	GPR_OFFSET_NAME(19),
	GPR_OFFSET_NAME(20),
	GPR_OFFSET_NAME(21),
	GPR_OFFSET_NAME(22),
	GPR_OFFSET_NAME(23),
	GPR_OFFSET_NAME(24),
	GPR_OFFSET_NAME(25),
	GPR_OFFSET_NAME(26),
	GPR_OFFSET_NAME(27),
	GPR_OFFSET_NAME(28),
	GPR_OFFSET_NAME(29),
	GPR_OFFSET_NAME(30),
	GPR_OFFSET_NAME(31),
	REG_OFFSET_NAME(nip),
	REG_OFFSET_NAME(msr),
	REG_OFFSET_NAME(ctr),
	REG_OFFSET_NAME(link),
	REG_OFFSET_NAME(xer),
	REG_OFFSET_NAME(ccr),
#ifdef CONFIG_PPC64
	REG_OFFSET_NAME(softe),
#else
	REG_OFFSET_NAME(mq),
#endif
	REG_OFFSET_NAME(trap),
	REG_OFFSET_NAME(dar),
	REG_OFFSET_NAME(dsisr),
	REG_OFFSET_END,
};

/**
 * regs_query_register_offset() - query register offset from its name
 * @name: the name of a register
 *
 * regs_query_register_offset() returns the offset of a register in struct
 * pt_regs from its name. If the name is invalid, this returns -EINVAL;
 */
int regs_query_register_offset(const char *name)
{
	const struct pt_regs_offset *roff;
	for (roff = regoffset_table; roff->name != NULL; roff++)
		if (!strcmp(roff->name, name))
			return roff->offset;
	return -EINVAL;
}

/**
 * regs_query_register_name() - query register name from its offset
 * @offset: the offset of a register in struct pt_regs.
 *
 * regs_query_register_name() returns the name of a register from its
 * offset in struct pt_regs. If the @offset is invalid, this returns NULL;
 */
const char *regs_query_register_name(unsigned int offset)
{
	const struct pt_regs_offset *roff;
	for (roff = regoffset_table; roff->name != NULL; roff++)
		if (roff->offset == offset)
			return roff->name;
	return NULL;
}

/*
 * does not yet catch signals sent when the child dies.
 * in exit.c or in signal.c.
 */

/*
 * Set of msr bits that gdb can change on behalf of a process.
 */
#ifdef CONFIG_PPC_ADV_DEBUG_REGS
#define MSR_DEBUGCHANGE 0
#else
#define MSR_DEBUGCHANGE (MSR_SE | MSR_BE)
#endif

/*
 * Max register writeable via put_reg
 */
#ifdef CONFIG_PPC32
#define PT_MAX_PUT_REG PT_MQ
#else
#define PT_MAX_PUT_REG PT_CCR
#endif

static unsigned long get_user_msr(struct task_struct *task)
{
	return task->thread.regs->msr | task->thread.fpexc_mode;
}

static int set_user_msr(struct task_struct *task, unsigned long msr)
{
	task->thread.regs->msr &= ~MSR_DEBUGCHANGE;
	task->thread.regs->msr |= msr & MSR_DEBUGCHANGE;
	return 0;
}

/*
 * We prevent mucking around with the reserved area of trap
 * which are used internally by the kernel.
 */
static int set_user_trap(struct task_struct *task, unsigned long trap)
{
	task->thread.regs->trap = trap & 0xfff0;
	return 0;
}

/*
 * Get contents of register REGNO in task TASK.
 */
unsigned long ptrace_get_reg(struct task_struct *task, int regno)
{
	if (task->thread.regs == NULL)
		return -EIO;

	if (regno == PT_MSR)
		return get_user_msr(task);

	if (regno < (sizeof(struct pt_regs) / sizeof(unsigned long)))
		return ((unsigned long *)task->thread.regs)[regno];

	return -EIO;
}

/*
 * Write contents of register REGNO in task TASK.
 */
int ptrace_put_reg(struct task_struct *task, int regno, unsigned long data)
{
	if (task->thread.regs == NULL)
		return -EIO;

	if (regno == PT_MSR)
		return set_user_msr(task, data);
	if (regno == PT_TRAP)
		return set_user_trap(task, data);

	if (regno <= PT_MAX_PUT_REG) {
		((unsigned long *)task->thread.regs)[regno] = data;
		return 0;
	}
	return -EIO;
}

static int gpr_get(struct task_struct *target, const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   void *kbuf, void __user *ubuf)
{
	int i, ret;

	if (target->thread.regs == NULL)
		return -EIO;

	if (!FULL_REGS(target->thread.regs)) {
		/* We have a partial register set. Fill 14-31 with bogus values */
		for (i = 14; i < 32; i++)
			target->thread.regs->gpr[i] = NV_REG_POISON;
	}

	ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf,
				  target->thread.regs,
				  0, offsetof(struct pt_regs, msr));
	if (!ret) {
		unsigned long msr = get_user_msr(target);
		ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf, &msr,
					  offsetof(struct pt_regs, msr),
					  offsetof(struct pt_regs, msr) +
					  sizeof(msr));
	}

	BUILD_BUG_ON(offsetof(struct pt_regs, orig_gpr3) !=
		     offsetof(struct pt_regs, msr) + sizeof(long));

	if (!ret)
		ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf,
					  &target->thread.regs->orig_gpr3,
					  offsetof(struct pt_regs, orig_gpr3),
					  sizeof(struct pt_regs));
	if (!ret)
		ret = user_regset_copyout_zero(&pos, &count, &kbuf, &ubuf,
					       sizeof(struct pt_regs), -1);

	return ret;
}

static int gpr_set(struct task_struct *target, const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   const void *kbuf, const void __user *ubuf)
{
	unsigned long reg;
	int ret;

	if (target->thread.regs == NULL)
		return -EIO;

	CHECK_FULL_REGS(target->thread.regs);

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf,
				 target->thread.regs,
				 0, PT_MSR * sizeof(reg));

	if (!ret && count > 0) {
		ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &reg,
					 PT_MSR * sizeof(reg),
					 (PT_MSR + 1) * sizeof(reg));
		if (!ret)
			ret = set_user_msr(target, reg);
	}

	BUILD_BUG_ON(offsetof(struct pt_regs, orig_gpr3) !=
		     offsetof(struct pt_regs, msr) + sizeof(long));

	if (!ret)
		ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf,
					 &target->thread.regs->orig_gpr3,
					 PT_ORIG_R3 * sizeof(reg),
					 (PT_MAX_PUT_REG + 1) * sizeof(reg));

	if (PT_MAX_PUT_REG + 1 < PT_TRAP && !ret)
		ret = user_regset_copyin_ignore(
			&pos, &count, &kbuf, &ubuf,
			(PT_MAX_PUT_REG + 1) * sizeof(reg),
			PT_TRAP * sizeof(reg));

	if (!ret && count > 0) {
		ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &reg,
					 PT_TRAP * sizeof(reg),
					 (PT_TRAP + 1) * sizeof(reg));
		if (!ret)
			ret = set_user_trap(target, reg);
	}

	if (!ret)
		ret = user_regset_copyin_ignore(
			&pos, &count, &kbuf, &ubuf,
			(PT_TRAP + 1) * sizeof(reg), -1);

	return ret;
}

static int fpr_get(struct task_struct *target, const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   void *kbuf, void __user *ubuf)
{
#ifdef CONFIG_VSX
	double buf[33];
	int i;
#endif
	flush_fp_to_thread(target);

#ifdef CONFIG_VSX
	/* copy to local buffer then write that out */
	for (i = 0; i < 32 ; i++)
		buf[i] = target->thread.TS_FPR(i);
	memcpy(&buf[32], &target->thread.fpscr, sizeof(double));
	return user_regset_copyout(&pos, &count, &kbuf, &ubuf, buf, 0, -1);

#else
	BUILD_BUG_ON(offsetof(struct thread_struct, fpscr) !=
		     offsetof(struct thread_struct, TS_FPR(32)));

	return user_regset_copyout(&pos, &count, &kbuf, &ubuf,
				   &target->thread.fpr, 0, -1);
#endif
}

static int fpr_set(struct task_struct *target, const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   const void *kbuf, const void __user *ubuf)
{
#ifdef CONFIG_VSX
	double buf[33];
	int i;
#endif
	flush_fp_to_thread(target);

#ifdef CONFIG_VSX
	/* copy to local buffer then write that out */
	i = user_regset_copyin(&pos, &count, &kbuf, &ubuf, buf, 0, -1);
	if (i)
		return i;
	for (i = 0; i < 32 ; i++)
		target->thread.TS_FPR(i) = buf[i];
	memcpy(&target->thread.fpscr, &buf[32], sizeof(double));
	return 0;
#else
	BUILD_BUG_ON(offsetof(struct thread_struct, fpscr) !=
		     offsetof(struct thread_struct, TS_FPR(32)));

	return user_regset_copyin(&pos, &count, &kbuf, &ubuf,
				  &target->thread.fpr, 0, -1);
#endif
}

#ifdef CONFIG_ALTIVEC
/*
 * Get/set all the altivec registers vr0..vr31, vscr, vrsave, in one go.
 * The transfer totals 34 quadword. Quadwords 0-31 contain the
 * corresponding vector registers. Quadword 32 contains the vscr as the
 * last word (offset 12) within that quadword. Quadword 33 contains the
 * vrsave as the first word (offset 0) within the quadword.
 *
 * This definition of the VMX state is compatible with the current PPC32
 * ptrace interface. This allows signal handling and ptrace to use the
 * same structures. This also simplifies the implementation of a bi-arch
 * (combined (32- and 64-bit) gdb.
 */

static int vr_active(struct task_struct *target,
		     const struct user_regset *regset)
{
	flush_altivec_to_thread(target);
	return target->thread.used_vr ? regset->n : 0;
}

static int vr_get(struct task_struct *target, const struct user_regset *regset,
		  unsigned int pos, unsigned int count,
		  void *kbuf, void __user *ubuf)
{
	int ret;

	flush_altivec_to_thread(target);

	BUILD_BUG_ON(offsetof(struct thread_struct, vscr) !=
		     offsetof(struct thread_struct, vr[32]));

	ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf,
				  &target->thread.vr, 0,
				  33 * sizeof(vector128));
	if (!ret) {
		/*
 * Copy out only the low-order word of vrsave.
 */
		union {
			elf_vrreg_t reg;
			u32 word;
		} vrsave;
		memset(&vrsave, 0, sizeof(vrsave));
		vrsave.word = target->thread.vrsave;
		ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf, &vrsave,
					  33 * sizeof(vector128), -1);
	}

	return ret;
}

static int vr_set(struct task_struct *target, const struct user_regset *regset,
		  unsigned int pos, unsigned int count,
		  const void *kbuf, const void __user *ubuf)
{
	int ret;

	flush_altivec_to_thread(target);

	BUILD_BUG_ON(offsetof(struct thread_struct, vscr) !=
		     offsetof(struct thread_struct, vr[32]));

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf,
				 &target->thread.vr, 0, 33 * sizeof(vector128));
	if (!ret && count > 0) {
		/*
 * We use only the first word of vrsave.
 */
		union {
			elf_vrreg_t reg;
			u32 word;
		} vrsave;
		memset(&vrsave, 0, sizeof(vrsave));
		vrsave.word = target->thread.vrsave;
		ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &vrsave,
					 33 * sizeof(vector128), -1);
		if (!ret)
			target->thread.vrsave = vrsave.word;
	}

	return ret;
}
#endif /* CONFIG_ALTIVEC */

#ifdef CONFIG_VSX
/*
 * Currently to set and and get all the vsx state, you need to call
 * the fp and VMX calls as well. This only get/sets the lower 32
 * 128bit VSX registers.
 */

static int vsr_active(struct task_struct *target,
		      const struct user_regset *regset)
{
	flush_vsx_to_thread(target);
	return target->thread.used_vsr ? regset->n : 0;
}

static int vsr_get(struct task_struct *target, const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   void *kbuf, void __user *ubuf)
{
	double buf[32];
	int ret, i;

	flush_vsx_to_thread(target);

	for (i = 0; i < 32 ; i++)
		buf[i] = target->thread.fpr[i][TS_VSRLOWOFFSET];
	ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf,
				  buf, 0, 32 * sizeof(double));

	return ret;
}

static int vsr_set(struct task_struct *target, const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   const void *kbuf, const void __user *ubuf)
{
	double buf[32];
	int ret,i;

	flush_vsx_to_thread(target);

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf,
				 buf, 0, 32 * sizeof(double));
	for (i = 0; i < 32 ; i++)
		target->thread.fpr[i][TS_VSRLOWOFFSET] = buf[i];


	return ret;
}
#endif /* CONFIG_VSX */

#ifdef CONFIG_SPE

/*
 * For get_evrregs/set_evrregs functions 'data' has the following layout:
 *
 * struct {
 * u32 evr[32];
 * u64 acc;
 * u32 spefscr;
 * }
 */

static int evr_active(struct task_struct *target,
		      const struct user_regset *regset)
{
	flush_spe_to_thread(target);
	return target->thread.used_spe ? regset->n : 0;
}

static int evr_get(struct task_struct *target, const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   void *kbuf, void __user *ubuf)
{
	int ret;

	flush_spe_to_thread(target);

	ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf,
				  &target->thread.evr,
				  0, sizeof(target->thread.evr));

	BUILD_BUG_ON(offsetof(struct thread_struct, acc) + sizeof(u64) !=
		     offsetof(struct thread_struct, spefscr));

	if (!ret)
		ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf,
					  &target->thread.acc,
					  sizeof(target->thread.evr), -1);

	return ret;
}

static int evr_set(struct task_struct *target, const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   const void *kbuf, const void __user *ubuf)
{
	int ret;

	flush_spe_to_thread(target);

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf,
				 &target->thread.evr,
				 0, sizeof(target->thread.evr));

	BUILD_BUG_ON(offsetof(struct thread_struct, acc) + sizeof(u64) !=
		     offsetof(struct thread_struct, spefscr));

	if (!ret)
		ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf,
					 &target->thread.acc,
					 sizeof(target->thread.evr), -1);

	return ret;
}
#endif /* CONFIG_SPE */


/*
 * These are our native regset flavors.
 */
enum powerpc_regset {
	REGSET_GPR,
	REGSET_FPR,
#ifdef CONFIG_ALTIVEC
	REGSET_VMX,
#endif
#ifdef CONFIG_VSX
	REGSET_VSX,
#endif
#ifdef CONFIG_SPE
	REGSET_SPE,
#endif
};

static const struct user_regset native_regsets[] = {
	[REGSET_GPR] = {
		.core_note_type = NT_PRSTATUS, .n = ELF_NGREG,
		.size = sizeof(long), .align = sizeof(long),
		.get = gpr_get, .set = gpr_set
	},
	[REGSET_FPR] = {
		.core_note_type = NT_PRFPREG, .n = ELF_NFPREG,
		.size = sizeof(double), .align = sizeof(double),
		.get = fpr_get, .set = fpr_set
	},
#ifdef CONFIG_ALTIVEC
	[REGSET_VMX] = {
		.core_note_type = NT_PPC_VMX, .n = 34,
		.size = sizeof(vector128), .align = sizeof(vector128),
		.active = vr_active, .get = vr_get, .set = vr_set
	},
#endif
#ifdef CONFIG_VSX
	[REGSET_VSX] = {
		.core_note_type = NT_PPC_VSX, .n = 32,
		.size = sizeof(double), .align = sizeof(double),
		.active = vsr_active, .get = vsr_get, .set = vsr_set
	},
#endif
#ifdef CONFIG_SPE
	[REGSET_SPE] = {
		.n = 35,
		.size = sizeof(u32), .align = sizeof(u32),
		.active = evr_active, .get = evr_get, .set = evr_set
	},
#endif
};

static const struct user_regset_view user_ppc_native_view = {
	.name = UTS_MACHINE, .e_machine = ELF_ARCH, .ei_osabi = ELF_OSABI,
	.regsets = native_regsets, .n = ARRAY_SIZE(native_regsets)
};

#ifdef CONFIG_PPC64
#include <linux/compat.h>

static int gpr32_get(struct task_struct *target,
		     const struct user_regset *regset,
		     unsigned int pos, unsigned int count,
		     void *kbuf, void __user *ubuf)
{
	const unsigned long *regs = &target->thread.regs->gpr[0];
	compat_ulong_t *k = kbuf;
	compat_ulong_t __user *u = ubuf;
	compat_ulong_t reg;
	int i;

	if (target->thread.regs == NULL)
		return -EIO;

	if (!FULL_REGS(target->thread.regs)) {
		/* We have a partial register set. Fill 14-31 with bogus values */
		for (i = 14; i < 32; i++)
			target->thread.regs->gpr[i] = NV_REG_POISON; 
	}

	pos /= sizeof(reg);
	count /= sizeof(reg);

	if (kbuf)
		for (; count > 0 && pos < PT_MSR; --count)
			*k++ = regs[pos++];
	else
		for (; count > 0 && pos < PT_MSR; --count)
			if (__put_user((compat_ulong_t) regs[pos++], u++))
				return -EFAULT;

	if (count > 0 && pos == PT_MSR) {
		reg = get_user_msr(target);
		if (kbuf)
			*k++ = reg;
		else if (__put_user(reg, u++))
			return -EFAULT;
		++pos;
		--count;
	}

	if (kbuf)
		for (; count > 0 && pos < PT_REGS_COUNT; --count)
			*k++ = regs[pos++];
	else
		for (; count > 0 && pos < PT_REGS_COUNT; --count)
			if (__put_user((compat_ulong_t) regs[pos++], u++))
				return -EFAULT;

	kbuf = k;
	ubuf = u;
	pos *= sizeof(reg);
	count *= sizeof(reg);
	return user_regset_copyout_zero(&pos, &count, &kbuf, &ubuf,
					PT_REGS_COUNT * sizeof(reg), -1);
}

static int gpr32_set(struct task_struct *target,
		     const struct user_regset *regset,
		     unsigned int pos, unsigned int count,
		     const void *kbuf, const void __user *ubuf)
{
	unsigned long *regs = &target->thread.regs->gpr[0];
	const compat_ulong_t *k = kbuf;
	const compat_ulong_t __user *u = ubuf;
	compat_ulong_t reg;

	if (target->thread.regs == NULL)
		return -EIO;

	CHECK_FULL_REGS(target->thread.regs);

	pos /= sizeof(reg);
	count /= sizeof(reg);

	if (kbuf)
		for (; count > 0 && pos < PT_MSR; --count)
			regs[pos++] = *k++;
	else
		for (; count > 0 && pos < PT_MSR; --count) {
			if (__get_user(reg, u++))
				return -EFAULT;
			regs[pos++] = reg;
		}


	if (count > 0 && pos == PT_MSR) {
		if (kbuf)
			reg = *k++;
		else if (__get_user(reg, u++))
			return -EFAULT;
		set_user_msr(target, reg);
		++pos;
		--count;
	}

	if (kbuf) {
		for (; count > 0 && pos <= PT_MAX_PUT_REG; --count)
			regs[pos++] = *k++;
		for (; count > 0 && pos < PT_TRAP; --count, ++pos)
			++k;
	} else {
		for (; count > 0 && pos <= PT_MAX_PUT_REG; --count) {
			if (__get_user(reg, u++))
				return -EFAULT;
			regs[pos++] = reg;
		}
		for (; count > 0 && pos < PT_TRAP; --count, ++pos)
			if (__get_user(reg, u++))
				return -EFAULT;
	}

	if (count > 0 && pos == PT_TRAP) {
		if (kbuf)
			reg = *k++;
		else if (__get_user(reg, u++))
			return -EFAULT;
		set_user_trap(target, reg);
		++pos;
		--count;
	}

	kbuf = k;
	ubuf = u;
	pos *= sizeof(reg);
	count *= sizeof(reg);
	return user_regset_copyin_ignore(&pos, &count, &kbuf, &ubuf,
					 (PT_TRAP + 1) * sizeof(reg), -1);
}

/*
 * These are the regset flavors matching the CONFIG_PPC32 native set.
 */
static const struct user_regset compat_regsets[] = {
	[REGSET_GPR] = {
		.core_note_type = NT_PRSTATUS, .n = ELF_NGREG,
		.size = sizeof(compat_long_t), .align = sizeof(compat_long_t),
		.get = gpr32_get, .set = gpr32_set
	},
	[REGSET_FPR] = {
		.core_note_type = NT_PRFPREG, .n = ELF_NFPREG,
		.size = sizeof(double), .align = sizeof(double),
		.get = fpr_get, .set = fpr_set
	},
#ifdef CONFIG_ALTIVEC
	[REGSET_VMX] = {
		.core_note_type = NT_PPC_VMX, .n = 34,
		.size = sizeof(vector128), .align = sizeof(vector128),
		.active = vr_active, .get = vr_get, .set = vr_set
	},
#endif
#ifdef CONFIG_SPE
	[REGSET_SPE] = {
		.core_note_type = NT_PPC_SPE, .n = 35,
		.size = sizeof(u32), .align = sizeof(u32),
		.active = evr_active, .get = evr_get, .set = evr_set
	},
#endif
};

static const struct user_regset_view user_ppc_compat_view = {
	.name = "ppc", .e_machine = EM_PPC, .ei_osabi = ELF_OSABI,
	.regsets = compat_regsets, .n = ARRAY_SIZE(compat_regsets)
};
#endif	/* CONFIG_PPC64 */

const struct user_regset_view *task_user_regset_view(struct task_struct *task)
{
#ifdef CONFIG_PPC64
	if (test_tsk_thread_flag(task, TIF_32BIT))
		return &user_ppc_compat_view;
#endif
	return &user_ppc_native_view;
}


void user_enable_single_step(struct task_struct *task)
{
	struct pt_regs *regs = task->thread.regs;

	if (regs != NULL) {
#ifdef CONFIG_PPC_ADV_DEBUG_REGS
		task->thread.dbcr0 &= ~DBCR0_BT;
		task->thread.dbcr0 |= DBCR0_IDM | DBCR0_IC;
		regs->msr |= MSR_DE;
#else
		regs->msr &= ~MSR_BE;
		regs->msr |= MSR_SE;
#endif
	}
	set_tsk_thread_flag(task, TIF_SINGLESTEP);
}

void user_enable_block_step(struct task_struct *task)
{
	struct pt_regs *regs = task->thread.regs;

	if (regs != NULL) {
#ifdef CONFIG_PPC_ADV_DEBUG_REGS
		task->thread.dbcr0 &= ~DBCR0_IC;
		task->thread.dbcr0 = DBCR0_IDM | DBCR0_BT;
		regs->msr |= MSR_DE;
#else
		regs->msr &= ~MSR_SE;
		regs->msr |= MSR_BE;
#endif
	}
	set_tsk_thread_flag(task, TIF_SINGLESTEP);
}

void user_disable_single_step(struct task_struct *task)
{
	struct pt_regs *regs = task->thread.regs;

	if (regs != NULL) {
#ifdef CONFIG_PPC_ADV_DEBUG_REGS
		/*
 * The logic to disable single stepping should be as
 * simple as turning off the Instruction Complete flag.
 * And, after doing so, if all debug flags are off, turn
 * off DBCR0(IDM) and MSR(DE) .... Torez
 */
		task->thread.dbcr0 &= ~DBCR0_IC;
		/*
 * Test to see if any of the DBCR_ACTIVE_EVENTS bits are set.
 */
		if (!DBCR_ACTIVE_EVENTS(task->thread.dbcr0,
					task->thread.dbcr1)) {
			/*
 * All debug events were off.....
 */
			task->thread.dbcr0 &= ~DBCR0_IDM;
			regs->msr &= ~MSR_DE;
		}
#else
		regs->msr &= ~(MSR_SE | MSR_BE);
#endif
	}
	clear_tsk_thread_flag(task, TIF_SINGLESTEP);
}

#ifdef CONFIG_HAVE_HW_BREAKPOINT
void ptrace_triggered(struct perf_event *bp, int nmi,
		      struct perf_sample_data *data, struct pt_regs *regs)
{
	struct perf_event_attr attr;

	/*
 * Disable the breakpoint request here since ptrace has defined a
 * one-shot behaviour for breakpoint exceptions in PPC64.
 * The SIGTRAP signal is generated automatically for us in do_dabr().
 * We don't have to do anything about that here
 */
	attr = bp->attr;
	attr.disabled = true;
	modify_user_hw_breakpoint(bp, &attr);
}
#endif /* CONFIG_HAVE_HW_BREAKPOINT */

int ptrace_set_debugreg(struct task_struct *task, unsigned long addr,
			       unsigned long data)
{
#ifdef CONFIG_HAVE_HW_BREAKPOINT
	int ret;
	struct thread_struct *thread = &(task->thread);
	struct perf_event *bp;
	struct perf_event_attr attr;
#endif /* CONFIG_HAVE_HW_BREAKPOINT */

	/* For ppc64 we support one DABR and no IABR's at the moment (ppc64).
 * For embedded processors we support one DAC and no IAC's at the
 * moment.
 */
	if (addr > 0)
		return -EINVAL;

	/* The bottom 3 bits in dabr are flags */
	if ((data & ~0x7UL) >= TASK_SIZE)
		return -EIO;

#ifndef CONFIG_PPC_ADV_DEBUG_REGS
	/* For processors using DABR (i.e. 970), the bottom 3 bits are flags.
 * It was assumed, on previous implementations, that 3 bits were
 * passed together with the data address, fitting the design of the
 * DABR register, as follows:
 *
 * bit 0: Read flag
 * bit 1: Write flag
 * bit 2: Breakpoint translation
 *
 * Thus, we use them here as so.
 */

	/* Ensure breakpoint translation bit is set */
	if (data && !(data & DABR_TRANSLATION))
		return -EIO;
#ifdef CONFIG_HAVE_HW_BREAKPOINT
	if (ptrace_get_breakpoints(task) < 0)
		return -ESRCH;

	bp = thread->ptrace_bps[0];
	if ((!data) || !(data & (DABR_DATA_WRITE | DABR_DATA_READ))) {
		if (bp) {
			unregister_hw_breakpoint(bp);
			thread->ptrace_bps[0] = NULL;
		}
		ptrace_put_breakpoints(task);
		return 0;
	}
	if (bp) {
		attr = bp->attr;
		attr.bp_addr = data & ~HW_BREAKPOINT_ALIGN;
		arch_bp_generic_fields(data &
					(DABR_DATA_WRITE | DABR_DATA_READ),
							&attr.bp_type);
		ret =  modify_user_hw_breakpoint(bp, &attr);
		if (ret) {
			ptrace_put_breakpoints(task);
			return ret;
		}
		thread->ptrace_bps[0] = bp;
		ptrace_put_breakpoints(task);
		thread->dabr = data;
		return 0;
	}

	/* Create a new breakpoint request if one doesn't exist already */
	hw_breakpoint_init(&attr);
	attr.bp_addr = data & ~HW_BREAKPOINT_ALIGN;
	arch_bp_generic_fields(data & (DABR_DATA_WRITE | DABR_DATA_READ),
								&attr.bp_type);

	thread->ptrace_bps[0] = bp = register_user_hw_breakpoint(&attr,
							ptrace_triggered, task);
	if (IS_ERR(bp)) {
		thread->ptrace_bps[0] = NULL;
		ptrace_put_breakpoints(task);
		return PTR_ERR(bp);
	}

	ptrace_put_breakpoints(task);

#endif /* CONFIG_HAVE_HW_BREAKPOINT */

	/* Move contents to the DABR register */
	task->thread.dabr = data;
#else /* CONFIG_PPC_ADV_DEBUG_REGS */
	/* As described above, it was assumed 3 bits were passed with the data
 * address, but we will assume only the mode bits will be passed
 * as to not cause alignment restrictions for DAC-based processors.
 */

	/* DAC's hold the whole address without any mode flags */
	task->thread.dac1 = data & ~0x3UL;

	if (task->thread.dac1 == 0) {
		dbcr_dac(task) &= ~(DBCR_DAC1R | DBCR_DAC1W);
		if (!DBCR_ACTIVE_EVENTS(task->thread.dbcr0,
					task->thread.dbcr1)) {
			task->thread.regs->msr &= ~MSR_DE;
			task->thread.dbcr0 &= ~DBCR0_IDM;
		}
		return 0;
	}

	/* Read or Write bits must be set */

	if (!(data & 0x3UL))
		return -EINVAL;

	/* Set the Internal Debugging flag (IDM bit 1) for the DBCR0
 register */
	task->thread.dbcr0 |= DBCR0_IDM;

	/* Check for write and read flags and set DBCR0
 accordingly */
	dbcr_dac(task) &= ~(DBCR_DAC1R|DBCR_DAC1W);
	if (data & 0x1UL)
		dbcr_dac(task) |= DBCR_DAC1R;
	if (data & 0x2UL)
		dbcr_dac(task) |= DBCR_DAC1W;
	task->thread.regs->msr |= MSR_DE;
#endif /* CONFIG_PPC_ADV_DEBUG_REGS */
	return 0;
}

/*
 * Called by kernel/ptrace.c when detaching..
 *
 * Make sure single step bits etc are not set.
 */
void ptrace_disable(struct task_struct *child)
{
	/* make sure the single step bit is not set. */
	user_disable_single_step(child);
}

#ifdef CONFIG_PPC_ADV_DEBUG_REGS
static long set_intruction_bp(struct task_struct *child,
			      struct ppc_hw_breakpoint *bp_info)
{
	int slot;
	int slot1_in_use = ((child->thread.dbcr0 & DBCR0_IAC1) != 0);
	int slot2_in_use = ((child->thread.dbcr0 & DBCR0_IAC2) != 0);
	int slot3_in_use = ((child->thread.dbcr0 & DBCR0_IAC3) != 0);
	int slot4_in_use = ((child->thread.dbcr0 & DBCR0_IAC4) != 0);

	if (dbcr_iac_range(child) & DBCR_IAC12MODE)
		slot2_in_use = 1;
	if (dbcr_iac_range(child) & DBCR_IAC34MODE)
		slot4_in_use = 1;

	if (bp_info->addr >= TASK_SIZE)
		return -EIO;

	if (bp_info->addr_mode != PPC_BREAKPOINT_MODE_EXACT) {

		/* Make sure range is valid. */
		if (bp_info->addr2 >= TASK_SIZE)
			return -EIO;

		/* We need a pair of IAC regsisters */
		if ((!slot1_in_use) && (!slot2_in_use)) {
			slot = 1;
			child->thread.iac1 = bp_info->addr;
			child->thread.iac2 = bp_info->addr2;
			child->thread.dbcr0 |= DBCR0_IAC1;
			if (bp_info->addr_mode ==
					PPC_BREAKPOINT_MODE_RANGE_EXCLUSIVE)
				dbcr_iac_range(child) |= DBCR_IAC12X;
			else
				dbcr_iac_range(child) |= DBCR_IAC12I;
#if CONFIG_PPC_ADV_DEBUG_IACS > 2
		} else if ((!slot3_in_use) && (!slot4_in_use)) {
			slot = 3;
			child->thread.iac3 = bp_info->addr;
			child->thread.iac4 = bp_info->addr2;
			child->thread.dbcr0 |= DBCR0_IAC3;
			if (bp_info->addr_mode ==
					PPC_BREAKPOINT_MODE_RANGE_EXCLUSIVE)
				dbcr_iac_range(child) |= DBCR_IAC34X;
			else
				dbcr_iac_range(child) |= DBCR_IAC34I;
#endif
		} else
			return -ENOSPC;
	} else {
		/* We only need one. If possible leave a pair free in
 * case a range is needed later
 */
		if (!slot1_in_use) {
			/*
 * Don't use iac1 if iac1-iac2 are free and either
 * iac3 or iac4 (but not both) are free
 */
			if (slot2_in_use || (slot3_in_use == slot4_in_use)) {
				slot = 1;
				child->thread.iac1 = bp_info->addr;
				child->thread.dbcr0 |= DBCR0_IAC1;
				goto out;
			}
		}
		if (!slot2_in_use) {
			slot = 2;
			child->thread.iac2 = bp_info->addr;
			child->thread.dbcr0 |= DBCR0_IAC2;
#if CONFIG_PPC_ADV_DEBUG_IACS > 2
		} else if (!slot3_in_use) {
			slot = 3;
			child->thread.iac3 = bp_info->addr;
			child->thread.dbcr0 |= DBCR0_IAC3;
		} else if (!slot4_in_use) {
			slot = 4;
			child->thread.iac4 = bp_info->addr;
			child->thread.dbcr0 |= DBCR0_IAC4;
#endif
		} else
			return -ENOSPC;
	}
out:
	child->thread.dbcr0 |= DBCR0_IDM;
	child->thread.regs->msr |= MSR_DE;

	return slot;
}

static int del_instruction_bp(struct task_struct *child, int slot)
{
	switch (slot) {
	case 1:
		if ((child->thread.dbcr0 & DBCR0_IAC1) == 0)
			return -ENOENT;

		if (dbcr_iac_range(child) & DBCR_IAC12MODE) {
			/* address range - clear slots 1 & 2 */
			child->thread.iac2 = 0;
			dbcr_iac_range(child) &= ~DBCR_IAC12MODE;
		}
		child->thread.iac1 = 0;
		child->thread.dbcr0 &= ~DBCR0_IAC1;
		break;
	case 2:
		if ((child->thread.dbcr0 & DBCR0_IAC2) == 0)
			return -ENOENT;

		if (dbcr_iac_range(child) & DBCR_IAC12MODE)
			/* used in a range */
			return -EINVAL;
		child->thread.iac2 = 0;
		child->thread.dbcr0 &= ~DBCR0_IAC2;
		break;
#if CONFIG_PPC_ADV_DEBUG_IACS > 2
	case 3:
		if ((child->thread.dbcr0 & DBCR0_IAC3) == 0)
			return -ENOENT;

		if (dbcr_iac_range(child) & DBCR_IAC34MODE) {
			/* address range - clear slots 3 & 4 */
			child->thread.iac4 = 0;
			dbcr_iac_range(child) &= ~DBCR_IAC34MODE;
		}
		child->thread.iac3 = 0;
		child->thread.dbcr0 &= ~DBCR0_IAC3;
		break;
	case 4:
		if ((child->thread.dbcr0 & DBCR0_IAC4) == 0)
			return -ENOENT;

		if (dbcr_iac_range(child) & DBCR_IAC34MODE)
			/* Used in a range */
			return -EINVAL;
		child->thread.iac4 = 0;
		child->thread.dbcr0 &= ~DBCR0_IAC4;
		break;
#endif
	default:
		return -EINVAL;
	}
	return 0;
}

static int set_dac(struct task_struct *child, struct ppc_hw_breakpoint *bp_info)
{
	int byte_enable =
		(bp_info->condition_mode >> PPC_BREAKPOINT_CONDITION_BE_SHIFT)
		& 0xf;
	int condition_mode =
		bp_info->condition_mode & PPC_BREAKPOINT_CONDITION_MODE;
	int slot;

	if (byte_enable && (condition_mode == 0))
		return -EINVAL;

	if (bp_info->addr >= TASK_SIZE)
		return -EIO;

	if ((dbcr_dac(child) & (DBCR_DAC1R | DBCR_DAC1W)) == 0) {
		slot = 1;
		if (bp_info->trigger_type & PPC_BREAKPOINT_TRIGGER_READ)
			dbcr_dac(child) |= DBCR_DAC1R;
		if (bp_info->trigger_type & PPC_BREAKPOINT_TRIGGER_WRITE)
			dbcr_dac(child) |= DBCR_DAC1W;
		child->thread.dac1 = (unsigned long)bp_info->addr;
#if CONFIG_PPC_ADV_DEBUG_DVCS > 0
		if (byte_enable) {
			child->thread.dvc1 =
				(unsigned long)bp_info->condition_value;
			child->thread.dbcr2 |=
				((byte_enable << DBCR2_DVC1BE_SHIFT) |
				 (condition_mode << DBCR2_DVC1M_SHIFT));
		}
#endif
#ifdef CONFIG_PPC_ADV_DEBUG_DAC_RANGE
	} else if (child->thread.dbcr2 & DBCR2_DAC12MODE) {
		/* Both dac1 and dac2 are part of a range */
		return -ENOSPC;
#endif
	} else if ((dbcr_dac(child) & (DBCR_DAC2R | DBCR_DAC2W)) == 0) {
		slot = 2;
		if (bp_info->trigger_type & PPC_BREAKPOINT_TRIGGER_READ)
			dbcr_dac(child) |= DBCR_DAC2R;
		if (bp_info->trigger_type & PPC_BREAKPOINT_TRIGGER_WRITE)
			dbcr_dac(child) |= DBCR_DAC2W;
		child->thread.dac2 = (unsigned long)bp_info->addr;
#if CONFIG_PPC_ADV_DEBUG_DVCS > 0
		if (byte_enable) {
			child->thread.dvc2 =
				(unsigned long)bp_info->condition_value;
			child->thread.dbcr2 |=
				((byte_enable << DBCR2_DVC2BE_SHIFT) |
				 (condition_mode << DBCR2_DVC2M_SHIFT));
		}
#endif
	} else
		return -ENOSPC;
	child->thread.dbcr0 |= DBCR0_IDM;
	child->thread.regs->msr |= MSR_DE;

	return slot + 4;
}

static int del_dac(struct task_struct *child, int slot)
{
	if (slot == 1) {
		if ((dbcr_dac(child) & (DBCR_DAC1R | DBCR_DAC1W)) == 0)
			return -ENOENT;

		child->thread.dac1 = 0;
		dbcr_dac(child) &= ~(DBCR_DAC1R | DBCR_DAC1W);
#ifdef CONFIG_PPC_ADV_DEBUG_DAC_RANGE
		if (child->thread.dbcr2 & DBCR2_DAC12MODE) {
			child->thread.dac2 = 0;
			child->thread.dbcr2 &= ~DBCR2_DAC12MODE;
		}
		child->thread.dbcr2 &= ~(DBCR2_DVC1M | DBCR2_DVC1BE);
#endif
#if CONFIG_PPC_ADV_DEBUG_DVCS > 0
		child->thread.dvc1 = 0;
#endif
	} else if (slot == 2) {
		if ((dbcr_dac(child) & (DBCR_DAC2R | DBCR_DAC2W)) == 0)
			return -ENOENT;

#ifdef CONFIG_PPC_ADV_DEBUG_DAC_RANGE
		if (child->thread.dbcr2 & DBCR2_DAC12MODE)
			/* Part of a range */
			return -EINVAL;
		child->thread.dbcr2 &= ~(DBCR2_DVC2M | DBCR2_DVC2BE);
#endif
#if CONFIG_PPC_ADV_DEBUG_DVCS > 0
		child->thread.dvc2 = 0;
#endif
		child->thread.dac2 = 0;
		dbcr_dac(child) &= ~(DBCR_DAC2R | DBCR_DAC2W);
	} else
		return -EINVAL;

	return 0;
}
#endif /* CONFIG_PPC_ADV_DEBUG_REGS */

#ifdef CONFIG_PPC_ADV_DEBUG_DAC_RANGE
static int set_dac_range(struct task_struct *child,
			 struct ppc_hw_breakpoint *bp_info)
{
	int mode = bp_info->addr_mode & PPC_BREAKPOINT_MODE_MASK;

	/* We don't allow range watchpoints to be used with DVC */
	if (bp_info->condition_mode)
		return -EINVAL;

	/*
 * Best effort to verify the address range. The user/supervisor bits
 * prevent trapping in kernel space, but let's fail on an obvious bad
 * range. The simple test on the mask is not fool-proof, and any
 * exclusive range will spill over into kernel space.
 */
	if (bp_info->addr >= TASK_SIZE)
		return -EIO;
	if (mode == PPC_BREAKPOINT_MODE_MASK) {
		/*
 * dac2 is a bitmask. Don't allow a mask that makes a
 * kernel space address from a valid dac1 value
 */
		if (~((unsigned long)bp_info->addr2) >= TASK_SIZE)
			return -EIO;
	} else {
		/*
 * For range breakpoints, addr2 must also be a valid address
 */
		if (bp_info->addr2 >= TASK_SIZE)
			return -EIO;
	}

	if (child->thread.dbcr0 &
	    (DBCR0_DAC1R | DBCR0_DAC1W | DBCR0_DAC2R | DBCR0_DAC2W))
		return -ENOSPC;

	if (bp_info->trigger_type & PPC_BREAKPOINT_TRIGGER_READ)
		child->thread.dbcr0 |= (DBCR0_DAC1R | DBCR0_IDM);
	if (bp_info->trigger_type & PPC_BREAKPOINT_TRIGGER_WRITE)
		child->thread.dbcr0 |= (DBCR0_DAC1W | DBCR0_IDM);
	child->thread.dac1 = bp_info->addr;
	child->thread.dac2 = bp_info->addr2;
	if (mode == PPC_BREAKPOINT_MODE_RANGE_INCLUSIVE)
		child->thread.dbcr2  |= DBCR2_DAC12M;
	else if (mode == PPC_BREAKPOINT_MODE_RANGE_EXCLUSIVE)
		child->thread.dbcr2  |= DBCR2_DAC12MX;
	else	/* PPC_BREAKPOINT_MODE_MASK */
		child->thread.dbcr2  |= DBCR2_DAC12MM;
	child->thread.regs->msr |= MSR_DE;

	return 5;
}
#endif /* CONFIG_PPC_ADV_DEBUG_DAC_RANGE */

static long ppc_set_hwdebug(struct task_struct *child,
		     struct ppc_hw_breakpoint *bp_info)
{
#ifndef CONFIG_PPC_ADV_DEBUG_REGS
	unsigned long dabr;
#endif

	if (bp_info->version != 1)
		return -ENOTSUPP;
#ifdef CONFIG_PPC_ADV_DEBUG_REGS
	/*
 * Check for invalid flags and combinations
 */
	if ((bp_info->trigger_type == 0) ||
	    (bp_info->trigger_type & ~(PPC_BREAKPOINT_TRIGGER_EXECUTE |
				       PPC_BREAKPOINT_TRIGGER_RW)) ||
	    (bp_info->addr_mode & ~PPC_BREAKPOINT_MODE_MASK) ||
	    (bp_info->condition_mode &
	     ~(PPC_BREAKPOINT_CONDITION_MODE |
	       PPC_BREAKPOINT_CONDITION_BE_ALL)))
		return -EINVAL;
#if CONFIG_PPC_ADV_DEBUG_DVCS == 0
	if (bp_info->condition_mode != PPC_BREAKPOINT_CONDITION_NONE)
		return -EINVAL;
#endif

	if (bp_info->trigger_type & PPC_BREAKPOINT_TRIGGER_EXECUTE) {
		if ((bp_info->trigger_type != PPC_BREAKPOINT_TRIGGER_EXECUTE) ||
		    (bp_info->condition_mode != PPC_BREAKPOINT_CONDITION_NONE))
			return -EINVAL;
		return set_intruction_bp(child, bp_info);
	}
	if (bp_info->addr_mode == PPC_BREAKPOINT_MODE_EXACT)
		return set_dac(child, bp_info);

#ifdef CONFIG_PPC_ADV_DEBUG_DAC_RANGE
	return set_dac_range(child, bp_info);
#else
	return -EINVAL;
#endif
#else /* !CONFIG_PPC_ADV_DEBUG_DVCS */
	/*
 * We only support one data breakpoint
 */
	if ((bp_info->trigger_type & PPC_BREAKPOINT_TRIGGER_RW) == 0 ||
	    (bp_info->trigger_type & ~PPC_BREAKPOINT_TRIGGER_RW) != 0 ||
	    bp_info->addr_mode != PPC_BREAKPOINT_MODE_EXACT ||
	    bp_info->condition_mode != PPC_BREAKPOINT_CONDITION_NONE)
		return -EINVAL;

	if (child->thread.dabr)
		return -ENOSPC;

	if ((unsigned long)bp_info->addr >= TASK_SIZE)
		return -EIO;

	dabr = (unsigned long)bp_info->addr & ~7UL;
	dabr |= DABR_TRANSLATION;
	if (bp_info->trigger_type & PPC_BREAKPOINT_TRIGGER_READ)
		dabr |= DABR_DATA_READ;
	if (bp_info->trigger_type & PPC_BREAKPOINT_TRIGGER_WRITE)
		dabr |= DABR_DATA_WRITE;

	child->thread.dabr = dabr;

	return 1;
#endif /* !CONFIG_PPC_ADV_DEBUG_DVCS */
}

static long ppc_del_hwdebug(struct task_struct *child, long addr, long data)
{
#ifdef CONFIG_PPC_ADV_DEBUG_REGS
	int rc;

	if (data <= 4)
		rc = del_instruction_bp(child, (int)data);
	else
		rc = del_dac(child, (int)data - 4);

	if (!rc) {
		if (!DBCR_ACTIVE_EVENTS(child->thread.dbcr0,
					child->thread.dbcr1)) {
			child->thread.dbcr0 &= ~DBCR0_IDM;
			child->thread.regs->msr &= ~MSR_DE;
		}
	}
	return rc;
#else
	if (data != 1)
		return -EINVAL;
	if (child->thread.dabr == 0)
		return -ENOENT;

	child->thread.dabr = 0;

	return 0;
#endif
}

/*
 * Here are the old "legacy" powerpc specific getregs/setregs ptrace calls,
 * we mark them as obsolete now, they will be removed in a future version
 */
static long arch_ptrace_old(struct task_struct *child, long request,
			    unsigned long addr, unsigned long data)
{
	void __user *datavp = (void __user *) data;

	switch (request) {
	case PPC_PTRACE_GETREGS:	/* Get GPRs 0 - 31. */
		return copy_regset_to_user(child, &user_ppc_native_view,
					   REGSET_GPR, 0, 32 * sizeof(long),
					   datavp);

	case PPC_PTRACE_SETREGS:	/* Set GPRs 0 - 31. */
		return copy_regset_from_user(child, &user_ppc_native_view,
					     REGSET_GPR, 0, 32 * sizeof(long),
					     datavp);

	case PPC_PTRACE_GETFPREGS:	/* Get FPRs 0 - 31. */
		return copy_regset_to_user(child, &user_ppc_native_view,
					   REGSET_FPR, 0, 32 * sizeof(double),
					   datavp);

	case PPC_PTRACE_SETFPREGS:	/* Set FPRs 0 - 31. */
		return copy_regset_from_user(child, &user_ppc_native_view,
					     REGSET_FPR, 0, 32 * sizeof(double),
					     datavp);
	}

	return -EPERM;
}

long arch_ptrace(struct task_struct *child, long request,
		 unsigned long addr, unsigned long data)
{
	int ret = -EPERM;
	void __user *datavp = (void __user *) data;
	unsigned long __user *datalp = datavp;

	switch (request) {
	/* read the word at location addr in the USER area. */
	case PTRACE_PEEKUSR: {
		unsigned long index, tmp;

		ret = -EIO;
		/* convert to index and check */
#ifdef CONFIG_PPC32
		index = addr >> 2;
		if ((addr & 3) || (index > PT_FPSCR)
		    || (child->thread.regs == NULL))
#else
		index = addr >> 3;
		if ((addr & 7) || (index > PT_FPSCR))
#endif
			break;

		CHECK_FULL_REGS(child->thread.regs);
		if (index < PT_FPR0) {
			tmp = ptrace_get_reg(child, (int) index);
		} else {
			flush_fp_to_thread(child);
			tmp = ((unsigned long *)child->thread.fpr)
				[TS_FPRWIDTH * (index - PT_FPR0)];
		}
		ret = put_user(tmp, datalp);
		break;
	}

	/* write the word at location addr in the USER area */
	case PTRACE_POKEUSR: {
		unsigned long index;

		ret = -EIO;
		/* convert to index and check */
#ifdef CONFIG_PPC32
		index = addr >> 2;
		if ((addr & 3) || (index > PT_FPSCR)
		    || (child->thread.regs == NULL))
#else
		index = addr >> 3;
		if ((addr & 7) || (index > PT_FPSCR))
#endif
			break;

		CHECK_FULL_REGS(child->thread.regs);
		if (index < PT_FPR0) {
			ret = ptrace_put_reg(child, index, data);
		} else {
			flush_fp_to_thread(child);
			((unsigned long *)child->thread.fpr)
				[TS_FPRWIDTH * (index - PT_FPR0)] = data;
			ret = 0;
		}
		break;
	}

	case PPC_PTRACE_GETHWDBGINFO: {
		struct ppc_debug_info dbginfo;

		dbginfo.version = 1;
#ifdef CONFIG_PPC_ADV_DEBUG_REGS
		dbginfo.num_instruction_bps = CONFIG_PPC_ADV_DEBUG_IACS;
		dbginfo.num_data_bps = CONFIG_PPC_ADV_DEBUG_DACS;
		dbginfo.num_condition_regs = CONFIG_PPC_ADV_DEBUG_DVCS;
		dbginfo.data_bp_alignment = 4;
		dbginfo.sizeof_condition = 4;
		dbginfo.features = PPC_DEBUG_FEATURE_INSN_BP_RANGE |
				   PPC_DEBUG_FEATURE_INSN_BP_MASK;
#ifdef CONFIG_PPC_ADV_DEBUG_DAC_RANGE
		dbginfo.features |=
				   PPC_DEBUG_FEATURE_DATA_BP_RANGE |
				   PPC_DEBUG_FEATURE_DATA_BP_MASK;
#endif
#else /* !CONFIG_PPC_ADV_DEBUG_REGS */
		dbginfo.num_instruction_bps = 0;
		dbginfo.num_data_bps = 1;
		dbginfo.num_condition_regs = 0;
#ifdef CONFIG_PPC64
		dbginfo.data_bp_alignment = 8;
#else
		dbginfo.data_bp_alignment = 4;
#endif
		dbginfo.sizeof_condition = 0;
		dbginfo.features = 0;
#endif /* CONFIG_PPC_ADV_DEBUG_REGS */

		if (!access_ok(VERIFY_WRITE, datavp,
			       sizeof(struct ppc_debug_info)))
			return -EFAULT;
		ret = __copy_to_user(datavp, &dbginfo,
				     sizeof(struct ppc_debug_info)) ?
		      -EFAULT : 0;
		break;
	}

	case PPC_PTRACE_SETHWDEBUG: {
		struct ppc_hw_breakpoint bp_info;

		if (!access_ok(VERIFY_READ, datavp,
			       sizeof(struct ppc_hw_breakpoint)))
			return -EFAULT;
		ret = __copy_from_user(&bp_info, datavp,
				       sizeof(struct ppc_hw_breakpoint)) ?
		      -EFAULT : 0;
		if (!ret)
			ret = ppc_set_hwdebug(child, &bp_info);
		break;
	}

	case PPC_PTRACE_DELHWDEBUG: {
		ret = ppc_del_hwdebug(child, addr, data);
		break;
	}

	case PTRACE_GET_DEBUGREG: {
		ret = -EINVAL;
		/* We only support one DABR and no IABRS at the moment */
		if (addr > 0)
			break;
#ifdef CONFIG_PPC_ADV_DEBUG_REGS
		ret = put_user(child->thread.dac1, datalp);
#else
		ret = put_user(child->thread.dabr, datalp);
#endif
		break;
	}

	case PTRACE_SET_DEBUGREG:
		ret = ptrace_set_debugreg(child, addr, data);
		break;

#ifdef CONFIG_PPC64
	case PTRACE_GETREGS64:
#endif
	case PTRACE_GETREGS:	/* Get all pt_regs from the child. */
		return copy_regset_to_user(child, &user_ppc_native_view,
					   REGSET_GPR,
					   0, sizeof(struct pt_regs),
					   datavp);

#ifdef CONFIG_PPC64
	case PTRACE_SETREGS64:
#endif
	case PTRACE_SETREGS:	/* Set all gp regs in the child. */
		return copy_regset_from_user(child, &user_ppc_native_view,
					     REGSET_GPR,
					     0, sizeof(struct pt_regs),
					     datavp);

	case PTRACE_GETFPREGS: /* Get the child FPU state (FPR0...31 + FPSCR) */
		return copy_regset_to_user(child, &user_ppc_native_view,
					   REGSET_FPR,
					   0, sizeof(elf_fpregset_t),
					   datavp);

	case PTRACE_SETFPREGS: /* Set the child FPU state (FPR0...31 + FPSCR) */
		return copy_regset_from_user(child, &user_ppc_native_view,
					     REGSET_FPR,
					     0, sizeof(elf_fpregset_t),
					     datavp);

#ifdef CONFIG_ALTIVEC
	case PTRACE_GETVRREGS:
		return copy_regset_to_user(child, &user_ppc_native_view,
					   REGSET_VMX,
					   0, (33 * sizeof(vector128) +
					       sizeof(u32)),
					   datavp);

	case PTRACE_SETVRREGS:
		return copy_regset_from_user(child, &user_ppc_native_view,
					     REGSET_VMX,
					     0, (33 * sizeof(vector128) +
						 sizeof(u32)),
					     datavp);
#endif
#ifdef CONFIG_VSX
	case PTRACE_GETVSRREGS:
		return copy_regset_to_user(child, &user_ppc_native_view,
					   REGSET_VSX,
					   0, 32 * sizeof(double),
					   datavp);

	case PTRACE_SETVSRREGS:
		return copy_regset_from_user(child, &user_ppc_native_view,
					     REGSET_VSX,
					     0, 32 * sizeof(double),
					     datavp);
#endif
#ifdef CONFIG_SPE
	case PTRACE_GETEVRREGS:
		/* Get the child spe register state. */
		return copy_regset_to_user(child, &user_ppc_native_view,
					   REGSET_SPE, 0, 35 * sizeof(u32),
					   datavp);

	case PTRACE_SETEVRREGS:
		/* Set the child spe register state. */
		return copy_regset_from_user(child, &user_ppc_native_view,
					     REGSET_SPE, 0, 35 * sizeof(u32),
					     datavp);
#endif

	/* Old reverse args ptrace callss */
	case PPC_PTRACE_GETREGS: /* Get GPRs 0 - 31. */
	case PPC_PTRACE_SETREGS: /* Set GPRs 0 - 31. */
	case PPC_PTRACE_GETFPREGS: /* Get FPRs 0 - 31. */
	case PPC_PTRACE_SETFPREGS: /* Get FPRs 0 - 31. */
		ret = arch_ptrace_old(child, request, addr, data);
		break;

	default:
		ret = ptrace_request(child, request, addr, data);
		break;
	}
	return ret;
}

/*
 * We must return the syscall number to actually look up in the table.
 * This can be -1L to skip running any syscall at all.
 */
long do_syscall_trace_enter(struct pt_regs *regs)
{
	long ret = 0;

	secure_computing(regs->gpr[0]);

	if (test_thread_flag(TIF_SYSCALL_TRACE) &&
	    tracehook_report_syscall_entry(regs))
		/*
 * Tracing decided this syscall should not happen.
 * We'll return a bogus call number to get an ENOSYS
 * error, but leave the original number in regs->gpr[0].
 */
		ret = -1L;

	if (unlikely(test_thread_flag(TIF_SYSCALL_TRACEPOINT)))
		trace_sys_enter(regs, regs->gpr[0]);

	if (unlikely(current->audit_context)) {
#ifdef CONFIG_PPC64
		if (!is_32bit_task())
			audit_syscall_entry(AUDIT_ARCH_PPC64,
					    regs->gpr[0],
					    regs->gpr[3], regs->gpr[4],
					    regs->gpr[5], regs->gpr[6]);
		else
#endif
			audit_syscall_entry(AUDIT_ARCH_PPC,
					    regs->gpr[0],
					    regs->gpr[3] & 0xffffffff,
					    regs->gpr[4] & 0xffffffff,
					    regs->gpr[5] & 0xffffffff,
					    regs->gpr[6] & 0xffffffff);
	}

	return ret ?: regs->gpr[0];
}

void do_syscall_trace_leave(struct pt_regs *regs)
{
	int step;

	if (unlikely(current->audit_context))
		audit_syscall_exit((regs->ccr&0x10000000)?AUDITSC_FAILURE:AUDITSC_SUCCESS,
				   regs->result);

	if (unlikely(test_thread_flag(TIF_SYSCALL_TRACEPOINT)))
		trace_sys_exit(regs, regs->result);

	step = test_thread_flag(TIF_SINGLESTEP);
	if (step || test_thread_flag(TIF_SYSCALL_TRACE))
		tracehook_report_syscall_exit(regs, step);
}

/* By Ross Biro 1/23/92 */
/*
 * Pentium III FXSR, SSE support
 * Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/ptrace.h>
#include <linux/regset.h>
#include <linux/tracehook.h>
#include <linux/user.h>
#include <linux/elf.h>
#include <linux/security.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <linux/signal.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/processor.h>
#include <asm/i387.h>
#include <asm/debugreg.h>
#include <asm/ldt.h>
#include <asm/desc.h>
#include <asm/prctl.h>
#include <asm/proto.h>
#include <asm/hw_breakpoint.h>

#include "tls.h"

#define CREATE_TRACE_POINTS
#include <trace/events/syscalls.h>

enum x86_regset {
	REGSET_GENERAL,
	REGSET_FP,
	REGSET_XFP,
	REGSET_IOPERM64 = REGSET_XFP,
	REGSET_XSTATE,
	REGSET_TLS,
	REGSET_IOPERM32,
};

struct pt_regs_offset {
	const char *name;
	int offset;
};

#define REG_OFFSET_NAME(r) {.name = #r, .offset = offsetof(struct pt_regs, r)}
#define REG_OFFSET_END {.name = NULL, .offset = 0}

static const struct pt_regs_offset regoffset_table[] = {
#ifdef CONFIG_X86_64
	REG_OFFSET_NAME(r15),
	REG_OFFSET_NAME(r14),
	REG_OFFSET_NAME(r13),
	REG_OFFSET_NAME(r12),
	REG_OFFSET_NAME(r11),
	REG_OFFSET_NAME(r10),
	REG_OFFSET_NAME(r9),
	REG_OFFSET_NAME(r8),
#endif
	REG_OFFSET_NAME(bx),
	REG_OFFSET_NAME(cx),
	REG_OFFSET_NAME(dx),
	REG_OFFSET_NAME(si),
	REG_OFFSET_NAME(di),
	REG_OFFSET_NAME(bp),
	REG_OFFSET_NAME(ax),
#ifdef CONFIG_X86_32
	REG_OFFSET_NAME(ds),
	REG_OFFSET_NAME(es),
	REG_OFFSET_NAME(fs),
	REG_OFFSET_NAME(gs),
#endif
	REG_OFFSET_NAME(orig_ax),
	REG_OFFSET_NAME(ip),
	REG_OFFSET_NAME(cs),
	REG_OFFSET_NAME(flags),
	REG_OFFSET_NAME(sp),
	REG_OFFSET_NAME(ss),
	REG_OFFSET_END,
};

/**
 * regs_query_register_offset() - query register offset from its name
 * @name: the name of a register
 *
 * regs_query_register_offset() returns the offset of a register in struct
 * pt_regs from its name. If the name is invalid, this returns -EINVAL;
 */
int regs_query_register_offset(const char *name)
{
	const struct pt_regs_offset *roff;
	for (roff = regoffset_table; roff->name != NULL; roff++)
		if (!strcmp(roff->name, name))
			return roff->offset;
	return -EINVAL;
}

/**
 * regs_query_register_name() - query register name from its offset
 * @offset: the offset of a register in struct pt_regs.
 *
 * regs_query_register_name() returns the name of a register from its
 * offset in struct pt_regs. If the @offset is invalid, this returns NULL;
 */
const char *regs_query_register_name(unsigned int offset)
{
	const struct pt_regs_offset *roff;
	for (roff = regoffset_table; roff->name != NULL; roff++)
		if (roff->offset == offset)
			return roff->name;
	return NULL;
}

static const int arg_offs_table[] = {
#ifdef CONFIG_X86_32
	[0] = offsetof(struct pt_regs, ax),
	[1] = offsetof(struct pt_regs, dx),
	[2] = offsetof(struct pt_regs, cx)
#else /* CONFIG_X86_64 */
	[0] = offsetof(struct pt_regs, di),
	[1] = offsetof(struct pt_regs, si),
	[2] = offsetof(struct pt_regs, dx),
	[3] = offsetof(struct pt_regs, cx),
	[4] = offsetof(struct pt_regs, r8),
	[5] = offsetof(struct pt_regs, r9)
#endif
};

/*
 * does not yet catch signals sent when the child dies.
 * in exit.c or in signal.c.
 */

/*
 * Determines which flags the user has access to [1 = access, 0 = no access].
 */
#define FLAG_MASK_32 ((unsigned long) \
 (X86_EFLAGS_CF | X86_EFLAGS_PF | \
 X86_EFLAGS_AF | X86_EFLAGS_ZF | \
 X86_EFLAGS_SF | X86_EFLAGS_TF | \
 X86_EFLAGS_DF | X86_EFLAGS_OF | \
 X86_EFLAGS_RF | X86_EFLAGS_AC))

/*
 * Determines whether a value may be installed in a segment register.
 */
static inline bool invalid_selector(u16 value)
{
	return unlikely(value != 0 && (value & SEGMENT_RPL_MASK) != USER_RPL);
}

#ifdef CONFIG_X86_32

#define FLAG_MASK FLAG_MASK_32

static unsigned long *pt_regs_access(struct pt_regs *regs, unsigned long regno)
{
	BUILD_BUG_ON(offsetof(struct pt_regs, bx) != 0);
	return &regs->bx + (regno >> 2);
}

static u16 get_segment_reg(struct task_struct *task, unsigned long offset)
{
	/*
 * Returning the value truncates it to 16 bits.
 */
	unsigned int retval;
	if (offset != offsetof(struct user_regs_struct, gs))
		retval = *pt_regs_access(task_pt_regs(task), offset);
	else {
		if (task == current)
			retval = get_user_gs(task_pt_regs(task));
		else
			retval = task_user_gs(task);
	}
	return retval;
}

static int set_segment_reg(struct task_struct *task,
			   unsigned long offset, u16 value)
{
	/*
 * The value argument was already truncated to 16 bits.
 */
	if (invalid_selector(value))
		return -EIO;

	/*
 * For %cs and %ss we cannot permit a null selector.
 * We can permit a bogus selector as long as it has USER_RPL.
 * Null selectors are fine for other segment registers, but
 * we will never get back to user mode with invalid %cs or %ss
 * and will take the trap in iret instead. Much code relies
 * on user_mode() to distinguish a user trap frame (which can
 * safely use invalid selectors) from a kernel trap frame.
 */
	switch (offset) {
	case offsetof(struct user_regs_struct, cs):
	case offsetof(struct user_regs_struct, ss):
		if (unlikely(value == 0))
			return -EIO;

	default:
		*pt_regs_access(task_pt_regs(task), offset) = value;
		break;

	case offsetof(struct user_regs_struct, gs):
		if (task == current)
			set_user_gs(task_pt_regs(task), value);
		else
			task_user_gs(task) = value;
	}

	return 0;
}

#else  /* CONFIG_X86_64 */

#define FLAG_MASK (FLAG_MASK_32 | X86_EFLAGS_NT)

static unsigned long *pt_regs_access(struct pt_regs *regs, unsigned long offset)
{
	BUILD_BUG_ON(offsetof(struct pt_regs, r15) != 0);
	return &regs->r15 + (offset / sizeof(regs->r15));
}

static u16 get_segment_reg(struct task_struct *task, unsigned long offset)
{
	/*
 * Returning the value truncates it to 16 bits.
 */
	unsigned int seg;

	switch (offset) {
	case offsetof(struct user_regs_struct, fs):
		if (task == current) {
			/* Older gas can't assemble movq %?s,%r?? */
			asm("movl %%fs,%0" : "=r" (seg));
			return seg;
		}
		return task->thread.fsindex;
	case offsetof(struct user_regs_struct, gs):
		if (task == current) {
			asm("movl %%gs,%0" : "=r" (seg));
			return seg;
		}
		return task->thread.gsindex;
	case offsetof(struct user_regs_struct, ds):
		if (task == current) {
			asm("movl %%ds,%0" : "=r" (seg));
			return seg;
		}
		return task->thread.ds;
	case offsetof(struct user_regs_struct, es):
		if (task == current) {
			asm("movl %%es,%0" : "=r" (seg));
			return seg;
		}
		return task->thread.es;

	case offsetof(struct user_regs_struct, cs):
	case offsetof(struct user_regs_struct, ss):
		break;
	}
	return *pt_regs_access(task_pt_regs(task), offset);
}

static int set_segment_reg(struct task_struct *task,
			   unsigned long offset, u16 value)
{
	/*
 * The value argument was already truncated to 16 bits.
 */
	if (invalid_selector(value))
		return -EIO;

	switch (offset) {
	case offsetof(struct user_regs_struct,fs):
		/*
 * If this is setting fs as for normal 64-bit use but
 * setting fs_base has implicitly changed it, leave it.
 */
		if ((value == FS_TLS_SEL && task->thread.fsindex == 0 &&
		     task->thread.fs != 0) ||
		    (value == 0 && task->thread.fsindex == FS_TLS_SEL &&
		     task->thread.fs == 0))
			break;
		task->thread.fsindex = value;
		if (task == current)
			loadsegment(fs, task->thread.fsindex);
		break;
	case offsetof(struct user_regs_struct,gs):
		/*
 * If this is setting gs as for normal 64-bit use but
 * setting gs_base has implicitly changed it, leave it.
 */
		if ((value == GS_TLS_SEL && task->thread.gsindex == 0 &&
		     task->thread.gs != 0) ||
		    (value == 0 && task->thread.gsindex == GS_TLS_SEL &&
		     task->thread.gs == 0))
			break;
		task->thread.gsindex = value;
		if (task == current)
			load_gs_index(task->thread.gsindex);
		break;
	case offsetof(struct user_regs_struct,ds):
		task->thread.ds = value;
		if (task == current)
			loadsegment(ds, task->thread.ds);
		break;
	case offsetof(struct user_regs_struct,es):
		task->thread.es = value;
		if (task == current)
			loadsegment(es, task->thread.es);
		break;

		/*
 * Can't actually change these in 64-bit mode.
 */
	case offsetof(struct user_regs_struct,cs):
		if (unlikely(value == 0))
			return -EIO;
#ifdef CONFIG_IA32_EMULATION
		if (test_tsk_thread_flag(task, TIF_IA32))
			task_pt_regs(task)->cs = value;
#endif
		break;
	case offsetof(struct user_regs_struct,ss):
		if (unlikely(value == 0))
			return -EIO;
#ifdef CONFIG_IA32_EMULATION
		if (test_tsk_thread_flag(task, TIF_IA32))
			task_pt_regs(task)->ss = value;
#endif
		break;
	}

	return 0;
}

#endif	/* CONFIG_X86_32 */

static unsigned long get_flags(struct task_struct *task)
{
	unsigned long retval = task_pt_regs(task)->flags;

	/*
 * If the debugger set TF, hide it from the readout.
 */
	if (test_tsk_thread_flag(task, TIF_FORCED_TF))
		retval &= ~X86_EFLAGS_TF;

	return retval;
}

static int set_flags(struct task_struct *task, unsigned long value)
{
	struct pt_regs *regs = task_pt_regs(task);

	/*
 * If the user value contains TF, mark that
 * it was not "us" (the debugger) that set it.
 * If not, make sure it stays set if we had.
 */
	if (value & X86_EFLAGS_TF)
		clear_tsk_thread_flag(task, TIF_FORCED_TF);
	else if (test_tsk_thread_flag(task, TIF_FORCED_TF))
		value |= X86_EFLAGS_TF;

	regs->flags = (regs->flags & ~FLAG_MASK) | (value & FLAG_MASK);

	return 0;
}

static int putreg(struct task_struct *child,
		  unsigned long offset, unsigned long value)
{
	switch (offset) {
	case offsetof(struct user_regs_struct, cs):
	case offsetof(struct user_regs_struct, ds):
	case offsetof(struct user_regs_struct, es):
	case offsetof(struct user_regs_struct, fs):
	case offsetof(struct user_regs_struct, gs):
	case offsetof(struct user_regs_struct, ss):
		return set_segment_reg(child, offset, value);

	case offsetof(struct user_regs_struct, flags):
		return set_flags(child, value);

#ifdef CONFIG_X86_64
	case offsetof(struct user_regs_struct,fs_base):
		if (value >= TASK_SIZE_OF(child))
			return -EIO;
		/*
 * When changing the segment base, use do_arch_prctl
 * to set either thread.fs or thread.fsindex and the
 * corresponding GDT slot.
 */
		if (child->thread.fs != value)
			return do_arch_prctl(child, ARCH_SET_FS, value);
		return 0;
	case offsetof(struct user_regs_struct,gs_base):
		/*
 * Exactly the same here as the %fs handling above.
 */
		if (value >= TASK_SIZE_OF(child))
			return -EIO;
		if (child->thread.gs != value)
			return do_arch_prctl(child, ARCH_SET_GS, value);
		return 0;
#endif
	}

	*pt_regs_access(task_pt_regs(child), offset) = value;
	return 0;
}

static unsigned long getreg(struct task_struct *task, unsigned long offset)
{
	switch (offset) {
	case offsetof(struct user_regs_struct, cs):
	case offsetof(struct user_regs_struct, ds):
	case offsetof(struct user_regs_struct, es):
	case offsetof(struct user_regs_struct, fs):
	case offsetof(struct user_regs_struct, gs):
	case offsetof(struct user_regs_struct, ss):
		return get_segment_reg(task, offset);

	case offsetof(struct user_regs_struct, flags):
		return get_flags(task);

#ifdef CONFIG_X86_64
	case offsetof(struct user_regs_struct, fs_base): {
		/*
 * do_arch_prctl may have used a GDT slot instead of
 * the MSR. To userland, it appears the same either
 * way, except the %fs segment selector might not be 0.
 */
		unsigned int seg = task->thread.fsindex;
		if (task->thread.fs != 0)
			return task->thread.fs;
		if (task == current)
			asm("movl %%fs,%0" : "=r" (seg));
		if (seg != FS_TLS_SEL)
			return 0;
		return get_desc_base(&task->thread.tls_array[FS_TLS]);
	}
	case offsetof(struct user_regs_struct, gs_base): {
		/*
 * Exactly the same here as the %fs handling above.
 */
		unsigned int seg = task->thread.gsindex;
		if (task->thread.gs != 0)
			return task->thread.gs;
		if (task == current)
			asm("movl %%gs,%0" : "=r" (seg));
		if (seg != GS_TLS_SEL)
			return 0;
		return get_desc_base(&task->thread.tls_array[GS_TLS]);
	}
#endif
	}

	return *pt_regs_access(task_pt_regs(task), offset);
}

static int genregs_get(struct task_struct *target,
		       const struct user_regset *regset,
		       unsigned int pos, unsigned int count,
		       void *kbuf, void __user *ubuf)
{
	if (kbuf) {
		unsigned long *k = kbuf;
		while (count >= sizeof(*k)) {
			*k++ = getreg(target, pos);
			count -= sizeof(*k);
			pos += sizeof(*k);
		}
	} else {
		unsigned long __user *u = ubuf;
		while (count >= sizeof(*u)) {
			if (__put_user(getreg(target, pos), u++))
				return -EFAULT;
			count -= sizeof(*u);
			pos += sizeof(*u);
		}
	}

	return 0;
}

static int genregs_set(struct task_struct *target,
		       const struct user_regset *regset,
		       unsigned int pos, unsigned int count,
		       const void *kbuf, const void __user *ubuf)
{
	int ret = 0;
	if (kbuf) {
		const unsigned long *k = kbuf;
		while (count >= sizeof(*k) && !ret) {
			ret = putreg(target, pos, *k++);
			count -= sizeof(*k);
			pos += sizeof(*k);
		}
	} else {
		const unsigned long  __user *u = ubuf;
		while (count >= sizeof(*u) && !ret) {
			unsigned long word;
			ret = __get_user(word, u++);
			if (ret)
				break;
			ret = putreg(target, pos, word);
			count -= sizeof(*u);
			pos += sizeof(*u);
		}
	}
	return ret;
}

static void ptrace_triggered(struct perf_event *bp, int nmi,
			     struct perf_sample_data *data,
			     struct pt_regs *regs)
{
	int i;
	struct thread_struct *thread = &(current->thread);

	/*
 * Store in the virtual DR6 register the fact that the breakpoint
 * was hit so the thread's debugger will see it.
 */
	for (i = 0; i < HBP_NUM; i++) {
		if (thread->ptrace_bps[i] == bp)
			break;
	}

	thread->debugreg6 |= (DR_TRAP0 << i);
}

/*
 * Walk through every ptrace breakpoints for this thread and
 * build the dr7 value on top of their attributes.
 *
 */
static unsigned long ptrace_get_dr7(struct perf_event *bp[])
{
	int i;
	int dr7 = 0;
	struct arch_hw_breakpoint *info;

	for (i = 0; i < HBP_NUM; i++) {
		if (bp[i] && !bp[i]->attr.disabled) {
			info = counter_arch_bp(bp[i]);
			dr7 |= encode_dr7(i, info->len, info->type);
		}
	}

	return dr7;
}

static int
ptrace_modify_breakpoint(struct perf_event *bp, int len, int type,
			 struct task_struct *tsk, int disabled)
{
	int err;
	int gen_len, gen_type;
	struct perf_event_attr attr;

	/*
 * We should have at least an inactive breakpoint at this
 * slot. It means the user is writing dr7 without having
 * written the address register first
 */
	if (!bp)
		return -EINVAL;

	err = arch_bp_generic_fields(len, type, &gen_len, &gen_type);
	if (err)
		return err;

	attr = bp->attr;
	attr.bp_len = gen_len;
	attr.bp_type = gen_type;
	attr.disabled = disabled;

	return modify_user_hw_breakpoint(bp, &attr);
}

/*
 * Handle ptrace writes to debug register 7.
 */
static int ptrace_write_dr7(struct task_struct *tsk, unsigned long data)
{
	struct thread_struct *thread = &(tsk->thread);
	unsigned long old_dr7;
	int i, orig_ret = 0, rc = 0;
	int enabled, second_pass = 0;
	unsigned len, type;
	struct perf_event *bp;

	if (ptrace_get_breakpoints(tsk) < 0)
		return -ESRCH;

	data &= ~DR_CONTROL_RESERVED;
	old_dr7 = ptrace_get_dr7(thread->ptrace_bps);
restore:
	/*
 * Loop through all the hardware breakpoints, making the
 * appropriate changes to each.
 */
	for (i = 0; i < HBP_NUM; i++) {
		enabled = decode_dr7(data, i, &len, &type);
		bp = thread->ptrace_bps[i];

		if (!enabled) {
			if (bp) {
				/*
 * Don't unregister the breakpoints right-away,
 * unless all register_user_hw_breakpoint()
 * requests have succeeded. This prevents
 * any window of opportunity for debug
 * register grabbing by other users.
 */
				if (!second_pass)
					continue;

				rc = ptrace_modify_breakpoint(bp, len, type,
							      tsk, 1);
				if (rc)
					break;
			}
			continue;
		}

		rc = ptrace_modify_breakpoint(bp, len, type, tsk, 0);
		if (rc)
			break;
	}
	/*
 * Make a second pass to free the remaining unused breakpoints
 * or to restore the original breakpoints if an error occurred.
 */
	if (!second_pass) {
		second_pass = 1;
		if (rc < 0) {
			orig_ret = rc;
			data = old_dr7;
		}
		goto restore;
	}

	ptrace_put_breakpoints(tsk);

	return ((orig_ret < 0) ? orig_ret : rc);
}

/*
 * Handle PTRACE_PEEKUSR calls for the debug register area.
 */
static unsigned long ptrace_get_debugreg(struct task_struct *tsk, int n)
{
	struct thread_struct *thread = &(tsk->thread);
	unsigned long val = 0;

	if (n < HBP_NUM) {
		struct perf_event *bp;

		if (ptrace_get_breakpoints(tsk) < 0)
			return -ESRCH;

		bp = thread->ptrace_bps[n];
		if (!bp)
			val = 0;
		else
			val = bp->hw.info.address;

		ptrace_put_breakpoints(tsk);
	} else if (n == 6) {
		val = thread->debugreg6;
	 } else if (n == 7) {
		val = thread->ptrace_dr7;
	}
	return val;
}

static int ptrace_set_breakpoint_addr(struct task_struct *tsk, int nr,
				      unsigned long addr)
{
	struct perf_event *bp;
	struct thread_struct *t = &tsk->thread;
	struct perf_event_attr attr;
	int err = 0;

	if (ptrace_get_breakpoints(tsk) < 0)
		return -ESRCH;

	if (!t->ptrace_bps[nr]) {
		ptrace_breakpoint_init(&attr);
		/*
 * Put stub len and type to register (reserve) an inactive but
 * correct bp
 */
		attr.bp_addr = addr;
		attr.bp_len = HW_BREAKPOINT_LEN_1;
		attr.bp_type = HW_BREAKPOINT_W;
		attr.disabled = 1;

		bp = register_user_hw_breakpoint(&attr, ptrace_triggered, tsk);

		/*
 * CHECKME: the previous code returned -EIO if the addr wasn't
 * a valid task virtual addr. The new one will return -EINVAL in
 * this case.
 * -EINVAL may be what we want for in-kernel breakpoints users,
 * but -EIO looks better for ptrace, since we refuse a register
 * writing for the user. And anyway this is the previous
 * behaviour.
 */
		if (IS_ERR(bp)) {
			err = PTR_ERR(bp);
			goto put;
		}

		t->ptrace_bps[nr] = bp;
	} else {
		bp = t->ptrace_bps[nr];

		attr = bp->attr;
		attr.bp_addr = addr;
		err = modify_user_hw_breakpoint(bp, &attr);
	}

put:
	ptrace_put_breakpoints(tsk);
	return err;
}

/*
 * Handle PTRACE_POKEUSR calls for the debug register area.
 */
int ptrace_set_debugreg(struct task_struct *tsk, int n, unsigned long val)
{
	struct thread_struct *thread = &(tsk->thread);
	int rc = 0;

	/* There are no DR4 or DR5 registers */
	if (n == 4 || n == 5)
		return -EIO;

	if (n == 6) {
		thread->debugreg6 = val;
		goto ret_path;
	}
	if (n < HBP_NUM) {
		rc = ptrace_set_breakpoint_addr(tsk, n, val);
		if (rc)
			return rc;
	}
	/* All that's left is DR7 */
	if (n == 7) {
		rc = ptrace_write_dr7(tsk, val);
		if (!rc)
			thread->ptrace_dr7 = val;
	}

ret_path:
	return rc;
}

/*
 * These access the current or another (stopped) task's io permission
 * bitmap for debugging or core dump.
 */
static int ioperm_active(struct task_struct *target,
			 const struct user_regset *regset)
{
	return target->thread.io_bitmap_max / regset->size;
}

static int ioperm_get(struct task_struct *target,
		      const struct user_regset *regset,
		      unsigned int pos, unsigned int count,
		      void *kbuf, void __user *ubuf)
{
	if (!target->thread.io_bitmap_ptr)
		return -ENXIO;

	return user_regset_copyout(&pos, &count, &kbuf, &ubuf,
				   target->thread.io_bitmap_ptr,
				   0, IO_BITMAP_BYTES);
}

/*
 * Called by kernel/ptrace.c when detaching..
 *
 * Make sure the single step bit is not set.
 */
void ptrace_disable(struct task_struct *child)
{
	user_disable_single_step(child);
#ifdef TIF_SYSCALL_EMU
	clear_tsk_thread_flag(child, TIF_SYSCALL_EMU);
#endif
}

#if defined CONFIG_X86_32 || defined CONFIG_IA32_EMULATION
static const struct user_regset_view user_x86_32_view; /* Initialized below. */
#endif

long arch_ptrace(struct task_struct *child, long request,
		 unsigned long addr, unsigned long data)
{
	int ret;
	unsigned long __user *datap = (unsigned long __user *)data;

	switch (request) {
	/* read the word at location addr in the USER area. */
	case PTRACE_PEEKUSR: {
		unsigned long tmp;

		ret = -EIO;
		if ((addr & (sizeof(data) - 1)) || addr >= sizeof(struct user))
			break;

		tmp = 0;  /* Default return condition */
		if (addr < sizeof(struct user_regs_struct))
			tmp = getreg(child, addr);
		else if (addr >= offsetof(struct user, u_debugreg[0]) &&
			 addr <= offsetof(struct user, u_debugreg[7])) {
			addr -= offsetof(struct user, u_debugreg[0]);
			tmp = ptrace_get_debugreg(child, addr / sizeof(data));
		}
		ret = put_user(tmp, datap);
		break;
	}

	case PTRACE_POKEUSR: /* write the word at location addr in the USER area */
		ret = -EIO;
		if ((addr & (sizeof(data) - 1)) || addr >= sizeof(struct user))
			break;

		if (addr < sizeof(struct user_regs_struct))
			ret = putreg(child, addr, data);
		else if (addr >= offsetof(struct user, u_debugreg[0]) &&
			 addr <= offsetof(struct user, u_debugreg[7])) {
			addr -= offsetof(struct user, u_debugreg[0]);
			ret = ptrace_set_debugreg(child,
						  addr / sizeof(data), data);
		}
		break;

	case PTRACE_GETREGS:	/* Get all gp regs from the child. */
		return copy_regset_to_user(child,
					   task_user_regset_view(current),
					   REGSET_GENERAL,
					   0, sizeof(struct user_regs_struct),
					   datap);

	case PTRACE_SETREGS:	/* Set all gp regs in the child. */
		return copy_regset_from_user(child,
					     task_user_regset_view(current),
					     REGSET_GENERAL,
					     0, sizeof(struct user_regs_struct),
					     datap);

	case PTRACE_GETFPREGS:	/* Get the child FPU state. */
		return copy_regset_to_user(child,
					   task_user_regset_view(current),
					   REGSET_FP,
					   0, sizeof(struct user_i387_struct),
					   datap);

	case PTRACE_SETFPREGS:	/* Set the child FPU state. */
		return copy_regset_from_user(child,
					     task_user_regset_view(current),
					     REGSET_FP,
					     0, sizeof(struct user_i387_struct),
					     datap);

#ifdef CONFIG_X86_32
	case PTRACE_GETFPXREGS:	/* Get the child extended FPU state. */
		return copy_regset_to_user(child, &user_x86_32_view,
					   REGSET_XFP,
					   0, sizeof(struct user_fxsr_struct),
					   datap) ? -EIO : 0;

	case PTRACE_SETFPXREGS:	/* Set the child extended FPU state. */
		return copy_regset_from_user(child, &user_x86_32_view,
					     REGSET_XFP,
					     0, sizeof(struct user_fxsr_struct),
					     datap) ? -EIO : 0;
#endif

#if defined CONFIG_X86_32 || defined CONFIG_IA32_EMULATION
	case PTRACE_GET_THREAD_AREA:
		if ((int) addr < 0)
			return -EIO;
		ret = do_get_thread_area(child, addr,
					(struct user_desc __user *)data);
		break;

	case PTRACE_SET_THREAD_AREA:
		if ((int) addr < 0)
			return -EIO;
		ret = do_set_thread_area(child, addr,
					(struct user_desc __user *)data, 0);
		break;
#endif

#ifdef CONFIG_X86_64
		/* normal 64bit interface to access TLS data.
 Works just like arch_prctl, except that the arguments
 are reversed. */
	case PTRACE_ARCH_PRCTL:
		ret = do_arch_prctl(child, data, addr);
		break;
#endif

	default:
		ret = ptrace_request(child, request, addr, data);
		break;
	}

	return ret;
}

#ifdef CONFIG_IA32_EMULATION

#include <linux/compat.h>
#include <linux/syscalls.h>
#include <asm/ia32.h>
#include <asm/user32.h>

#define R32(l,q) \
 case offsetof(struct user32, regs.l): \
 regs->q = value; break

#define SEG32(rs) \
 case offsetof(struct user32, regs.rs): \
 return set_segment_reg(child, \
 offsetof(struct user_regs_struct, rs), \
 value); \
 break

static int putreg32(struct task_struct *child, unsigned regno, u32 value)
{
	struct pt_regs *regs = task_pt_regs(child);

	switch (regno) {

	SEG32(cs);
	SEG32(ds);
	SEG32(es);
	SEG32(fs);
	SEG32(gs);
	SEG32(ss);

	R32(ebx, bx);
	R32(ecx, cx);
	R32(edx, dx);
	R32(edi, di);
	R32(esi, si);
	R32(ebp, bp);
	R32(eax, ax);
	R32(eip, ip);
	R32(esp, sp);

	case offsetof(struct user32, regs.orig_eax):
		/*
 * A 32-bit debugger setting orig_eax means to restore
 * the state of the task restarting a 32-bit syscall.
 * Make sure we interpret the -ERESTART* codes correctly
 * in case the task is not actually still sitting at the
 * exit from a 32-bit syscall with TS_COMPAT still set.
 */
		regs->orig_ax = value;
		if (syscall_get_nr(child, regs) >= 0)
			task_thread_info(child)->status |= TS_COMPAT;
		break;

	case offsetof(struct user32, regs.eflags):
		return set_flags(child, value);

	case offsetof(struct user32, u_debugreg[0]) ...
		offsetof(struct user32, u_debugreg[7]):
		regno -= offsetof(struct user32, u_debugreg[0]);
		return ptrace_set_debugreg(child, regno / 4, value);

	default:
		if (regno > sizeof(struct user32) || (regno & 3))
			return -EIO;

		/*
 * Other dummy fields in the virtual user structure
 * are ignored
 */
		break;
	}
	return 0;
}

#undef R32
#undef SEG32

#define R32(l,q) \
 case offsetof(struct user32, regs.l): \
 *val = regs->q; break

#define SEG32(rs) \
 case offsetof(struct user32, regs.rs): \
 *val = get_segment_reg(child, \
 offsetof(struct user_regs_struct, rs)); \
 break

static int getreg32(struct task_struct *child, unsigned regno, u32 *val)
{
	struct pt_regs *regs = task_pt_regs(child);

	switch (regno) {

	SEG32(ds);
	SEG32(es);
	SEG32(fs);
	SEG32(gs);

	R32(cs, cs);
	R32(ss, ss);
	R32(ebx, bx);
	R32(ecx, cx);
	R32(edx, dx);
	R32(edi, di);
	R32(esi, si);
	R32(ebp, bp);
	R32(eax, ax);
	R32(orig_eax, orig_ax);
	R32(eip, ip);
	R32(esp, sp);

	case offsetof(struct user32, regs.eflags):
		*val = get_flags(child);
		break;

	case offsetof(struct user32, u_debugreg[0]) ...
		offsetof(struct user32, u_debugreg[7]):
		regno -= offsetof(struct user32, u_debugreg[0]);
		*val = ptrace_get_debugreg(child, regno / 4);
		break;

	default:
		if (regno > sizeof(struct user32) || (regno & 3))
			return -EIO;

		/*
 * Other dummy fields in the virtual user structure
 * are ignored
 */
		*val = 0;
		break;
	}
	return 0;
}

#undef R32
#undef SEG32

static int genregs32_get(struct task_struct *target,
			 const struct user_regset *regset,
			 unsigned int pos, unsigned int count,
			 void *kbuf, void __user *ubuf)
{
	if (kbuf) {
		compat_ulong_t *k = kbuf;
		while (count >= sizeof(*k)) {
			getreg32(target, pos, k++);
			count -= sizeof(*k);
			pos += sizeof(*k);
		}
	} else {
		compat_ulong_t __user *u = ubuf;
		while (count >= sizeof(*u)) {
			compat_ulong_t word;
			getreg32(target, pos, &word);
			if (__put_user(word, u++))
				return -EFAULT;
			count -= sizeof(*u);
			pos += sizeof(*u);
		}
	}

	return 0;
}

static int genregs32_set(struct task_struct *target,
			 const struct user_regset *regset,
			 unsigned int pos, unsigned int count,
			 const void *kbuf, const void __user *ubuf)
{
	int ret = 0;
	if (kbuf) {
		const compat_ulong_t *k = kbuf;
		while (count >= sizeof(*k) && !ret) {
			ret = putreg32(target, pos, *k++);
			count -= sizeof(*k);
			pos += sizeof(*k);
		}
	} else {
		const compat_ulong_t __user *u = ubuf;
		while (count >= sizeof(*u) && !ret) {
			compat_ulong_t word;
			ret = __get_user(word, u++);
			if (ret)
				break;
			ret = putreg32(target, pos, word);
			count -= sizeof(*u);
			pos += sizeof(*u);
		}
	}
	return ret;
}

long compat_arch_ptrace(struct task_struct *child, compat_long_t request,
			compat_ulong_t caddr, compat_ulong_t cdata)
{
	unsigned long addr = caddr;
	unsigned long data = cdata;
	void __user *datap = compat_ptr(data);
	int ret;
	__u32 val;

	switch (request) {
	case PTRACE_PEEKUSR:
		ret = getreg32(child, addr, &val);
		if (ret == 0)
			ret = put_user(val, (__u32 __user *)datap);
		break;

	case PTRACE_POKEUSR:
		ret = putreg32(child, addr, data);
		break;

	case PTRACE_GETREGS:	/* Get all gp regs from the child. */
		return copy_regset_to_user(child, &user_x86_32_view,
					   REGSET_GENERAL,
					   0, sizeof(struct user_regs_struct32),
					   datap);

	case PTRACE_SETREGS:	/* Set all gp regs in the child. */
		return copy_regset_from_user(child, &user_x86_32_view,
					     REGSET_GENERAL, 0,
					     sizeof(struct user_regs_struct32),
					     datap);

	case PTRACE_GETFPREGS:	/* Get the child FPU state. */
		return copy_regset_to_user(child, &user_x86_32_view,
					   REGSET_FP, 0,
					   sizeof(struct user_i387_ia32_struct),
					   datap);

	case PTRACE_SETFPREGS:	/* Set the child FPU state. */
		return copy_regset_from_user(
			child, &user_x86_32_view, REGSET_FP,
			0, sizeof(struct user_i387_ia32_struct), datap);

	case PTRACE_GETFPXREGS:	/* Get the child extended FPU state. */
		return copy_regset_to_user(child, &user_x86_32_view,
					   REGSET_XFP, 0,
					   sizeof(struct user32_fxsr_struct),
					   datap);

	case PTRACE_SETFPXREGS:	/* Set the child extended FPU state. */
		return copy_regset_from_user(child, &user_x86_32_view,
					     REGSET_XFP, 0,
					     sizeof(struct user32_fxsr_struct),
					     datap);

	case PTRACE_GET_THREAD_AREA:
	case PTRACE_SET_THREAD_AREA:
		return arch_ptrace(child, request, addr, data);

	default:
		return compat_ptrace_request(child, request, addr, data);
	}

	return ret;
}

#endif	/* CONFIG_IA32_EMULATION */

#ifdef CONFIG_X86_64

static struct user_regset x86_64_regsets[] __read_mostly = {
	[REGSET_GENERAL] = {
		.core_note_type = NT_PRSTATUS,
		.n = sizeof(struct user_regs_struct) / sizeof(long),
		.size = sizeof(long), .align = sizeof(long),
		.get = genregs_get, .set = genregs_set
	},
	[REGSET_FP] = {
		.core_note_type = NT_PRFPREG,
		.n = sizeof(struct user_i387_struct) / sizeof(long),
		.size = sizeof(long), .align = sizeof(long),
		.active = xfpregs_active, .get = xfpregs_get, .set = xfpregs_set
	},
	[REGSET_XSTATE] = {
		.core_note_type = NT_X86_XSTATE,
		.size = sizeof(u64), .align = sizeof(u64),
		.active = xstateregs_active, .get = xstateregs_get,
		.set = xstateregs_set
	},
	[REGSET_IOPERM64] = {
		.core_note_type = NT_386_IOPERM,
		.n = IO_BITMAP_LONGS,
		.size = sizeof(long), .align = sizeof(long),
		.active = ioperm_active, .get = ioperm_get
	},
};

static const struct user_regset_view user_x86_64_view = {
	.name = "x86_64", .e_machine = EM_X86_64,
	.regsets = x86_64_regsets, .n = ARRAY_SIZE(x86_64_regsets)
};

#else  /* CONFIG_X86_32 */

#define user_regs_struct32 user_regs_struct
#define genregs32_get genregs_get
#define genregs32_set genregs_set

#define user_i387_ia32_struct user_i387_struct
#define user32_fxsr_struct user_fxsr_struct

#endif	/* CONFIG_X86_64 */

#if defined CONFIG_X86_32 || defined CONFIG_IA32_EMULATION
static struct user_regset x86_32_regsets[] __read_mostly = {
	[REGSET_GENERAL] = {
		.core_note_type = NT_PRSTATUS,
		.n = sizeof(struct user_regs_struct32) / sizeof(u32),
		.size = sizeof(u32), .align = sizeof(u32),
		.get = genregs32_get, .set = genregs32_set
	},
	[REGSET_FP] = {
		.core_note_type = NT_PRFPREG,
		.n = sizeof(struct user_i387_ia32_struct) / sizeof(u32),
		.size = sizeof(u32), .align = sizeof(u32),
		.active = fpregs_active, .get = fpregs_get, .set = fpregs_set
	},
	[REGSET_XFP] = {
		.core_note_type = NT_PRXFPREG,
		.n = sizeof(struct user32_fxsr_struct) / sizeof(u32),
		.size = sizeof(u32), .align = sizeof(u32),
		.active = xfpregs_active, .get = xfpregs_get, .set = xfpregs_set
	},
	[REGSET_XSTATE] = {
		.core_note_type = NT_X86_XSTATE,
		.size = sizeof(u64), .align = sizeof(u64),
		.active = xstateregs_active, .get = xstateregs_get,
		.set = xstateregs_set
	},
	[REGSET_TLS] = {
		.core_note_type = NT_386_TLS,
		.n = GDT_ENTRY_TLS_ENTRIES, .bias = GDT_ENTRY_TLS_MIN,
		.size = sizeof(struct user_desc),
		.align = sizeof(struct user_desc),
		.active = regset_tls_active,
		.get = regset_tls_get, .set = regset_tls_set
	},
	[REGSET_IOPERM32] = {
		.core_note_type = NT_386_IOPERM,
		.n = IO_BITMAP_BYTES / sizeof(u32),
		.size = sizeof(u32), .align = sizeof(u32),
		.active = ioperm_active, .get = ioperm_get
	},
};

static const struct user_regset_view user_x86_32_view = {
	.name = "i386", .e_machine = EM_386,
	.regsets = x86_32_regsets, .n = ARRAY_SIZE(x86_32_regsets)
};
#endif

/*
 * This represents bytes 464..511 in the memory layout exported through
 * the REGSET_XSTATE interface.
 */
u64 xstate_fx_sw_bytes[USER_XSTATE_FX_SW_WORDS];

void update_regset_xstate_info(unsigned int size, u64 xstate_mask)
{
#ifdef CONFIG_X86_64
	x86_64_regsets[REGSET_XSTATE].n = size / sizeof(u64);
#endif
#if defined CONFIG_X86_32 || defined CONFIG_IA32_EMULATION
	x86_32_regsets[REGSET_XSTATE].n = size / sizeof(u64);
#endif
	xstate_fx_sw_bytes[USER_XSTATE_XCR0_WORD] = xstate_mask;
}

const struct user_regset_view *task_user_regset_view(struct task_struct *task)
{
#ifdef CONFIG_IA32_EMULATION
	if (test_tsk_thread_flag(task, TIF_IA32))
#endif
#if defined CONFIG_X86_32 || defined CONFIG_IA32_EMULATION
		return &user_x86_32_view;
#endif
#ifdef CONFIG_X86_64
	return &user_x86_64_view;
#endif
}

static void fill_sigtrap_info(struct task_struct *tsk,
				struct pt_regs *regs,
				int error_code, int si_code,
				struct siginfo *info)
{
	tsk->thread.trap_no = 1;
	tsk->thread.error_code = error_code;

	memset(info, 0, sizeof(*info));
	info->si_signo = SIGTRAP;
	info->si_code = si_code;
	info->si_addr = user_mode_vm(regs) ? (void __user *)regs->ip : NULL;
}

void user_single_step_siginfo(struct task_struct *tsk,
				struct pt_regs *regs,
				struct siginfo *info)
{
	fill_sigtrap_info(tsk, regs, 0, TRAP_BRKPT, info);
}

void send_sigtrap(struct task_struct *tsk, struct pt_regs *regs,
					 int error_code, int si_code)
{
	struct siginfo info;

	fill_sigtrap_info(tsk, regs, error_code, si_code, &info);
	/* Send us the fake SIGTRAP */
	force_sig_info(SIGTRAP, &info, tsk);
}


#ifdef CONFIG_X86_32
# define IS_IA32 1
#elif defined CONFIG_IA32_EMULATION
# define IS_IA32 is_compat_task()
#else
# define IS_IA32 0
#endif

/*
 * We must return the syscall number to actually look up in the table.
 * This can be -1L to skip running any syscall at all.
 */
long syscall_trace_enter(struct pt_regs *regs)
{
	long ret = 0;

	/*
 * If we stepped into a sysenter/syscall insn, it trapped in
 * kernel mode; do_debug() cleared TF and set TIF_SINGLESTEP.
 * If user-mode had set TF itself, then it's still clear from
 * do_debug() and we need to set it again to restore the user
 * state. If we entered on the slow path, TF was already set.
 */
	if (test_thread_flag(TIF_SINGLESTEP))
		regs->flags |= X86_EFLAGS_TF;

	/* do the secure computing check first */
	secure_computing(regs->orig_ax);

	if (unlikely(test_thread_flag(TIF_SYSCALL_EMU)))
		ret = -1L;

	if ((ret || test_thread_flag(TIF_SYSCALL_TRACE)) &&
	    tracehook_report_syscall_entry(regs))
		ret = -1L;

	if (unlikely(test_thread_flag(TIF_SYSCALL_TRACEPOINT)))
		trace_sys_enter(regs, regs->orig_ax);

	if (unlikely(current->audit_context)) {
		if (IS_IA32)
			audit_syscall_entry(AUDIT_ARCH_I386,
					    regs->orig_ax,
					    regs->bx, regs->cx,
					    regs->dx, regs->si);
#ifdef CONFIG_X86_64
		else
			audit_syscall_entry(AUDIT_ARCH_X86_64,
					    regs->orig_ax,
					    regs->di, regs->si,
					    regs->dx, regs->r10);
#endif
	}

	return ret ?: regs->orig_ax;
}

void syscall_trace_leave(struct pt_regs *regs)
{
	bool step;

	if (unlikely(current->audit_context))
		audit_syscall_exit(AUDITSC_RESULT(regs->ax), regs->ax);

	if (unlikely(test_thread_flag(TIF_SYSCALL_TRACEPOINT)))
		trace_sys_exit(regs, regs->ax);

	/*
 * If TIF_SYSCALL_EMU is set, we only get here because of
 * TIF_SINGLESTEP (i.e. this is PTRACE_SYSEMU_SINGLESTEP).
 * We already reported this syscall instruction in
 * syscall_trace_enter().
 */
	step = unlikely(test_thread_flag(TIF_SINGLESTEP)) &&
			!test_thread_flag(TIF_SYSCALL_EMU);
	if (step || test_thread_flag(TIF_SYSCALL_TRACE))
		tracehook_report_syscall_exit(regs, step);
}