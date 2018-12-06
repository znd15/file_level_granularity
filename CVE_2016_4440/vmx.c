

/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 *
 * Authors:
 * Avi Kivity <avi@qumranet.com>
 * Yaniv Kamay <yaniv@qumranet.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2. See
 * the COPYING file in the top-level directory.
 *
 */

#include "irq.h"
#include "mmu.h"
#include "cpuid.h"
#include "lapic.h"

#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include <linux/mod_devicetable.h>
#include <linux/trace_events.h>
#include <linux/slab.h>
#include <linux/tboot.h>
#include <linux/hrtimer.h>
#include "kvm_cache_regs.h"
#include "x86.h"

#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/desc.h>
#include <asm/vmx.h>
#include <asm/virtext.h>
#include <asm/mce.h>
#include <asm/fpu/internal.h>
#include <asm/perf_event.h>
#include <asm/debugreg.h>
#include <asm/kexec.h>
#include <asm/apic.h>
#include <asm/irq_remapping.h>

#include "trace.h"
#include "pmu.h"

#define __ex(x) __kvm_handle_fault_on_reboot(x)
#define __ex_clear(x, reg) \
 ____kvm_handle_fault_on_reboot(x, "xor " reg " , " reg)

MODULE_AUTHOR("Qumranet");
MODULE_LICENSE("GPL");

static const struct x86_cpu_id vmx_cpu_id[] = {
	X86_FEATURE_MATCH(X86_FEATURE_VMX),
	{}
};
MODULE_DEVICE_TABLE(x86cpu, vmx_cpu_id);

static bool __read_mostly enable_vpid = 1;
module_param_named(vpid, enable_vpid, bool, 0444);

static bool __read_mostly flexpriority_enabled = 1;
module_param_named(flexpriority, flexpriority_enabled, bool, S_IRUGO);

static bool __read_mostly enable_ept = 1;
module_param_named(ept, enable_ept, bool, S_IRUGO);

static bool __read_mostly enable_unrestricted_guest = 1;
module_param_named(unrestricted_guest,
			enable_unrestricted_guest, bool, S_IRUGO);

static bool __read_mostly enable_ept_ad_bits = 1;
module_param_named(eptad, enable_ept_ad_bits, bool, S_IRUGO);

static bool __read_mostly emulate_invalid_guest_state = true;
module_param(emulate_invalid_guest_state, bool, S_IRUGO);

static bool __read_mostly vmm_exclusive = 1;
module_param(vmm_exclusive, bool, S_IRUGO);

static bool __read_mostly fasteoi = 1;
module_param(fasteoi, bool, S_IRUGO);

static bool __read_mostly enable_apicv = 1;
module_param(enable_apicv, bool, S_IRUGO);

static bool __read_mostly enable_shadow_vmcs = 1;
module_param_named(enable_shadow_vmcs, enable_shadow_vmcs, bool, S_IRUGO);
/*
 * If nested=1, nested virtualization is supported, i.e., guests may use
 * VMX and be a hypervisor for its own guests. If nested=0, guests may not
 * use VMX instructions.
 */
static bool __read_mostly nested = 0;
module_param(nested, bool, S_IRUGO);

static u64 __read_mostly host_xss;

static bool __read_mostly enable_pml = 1;
module_param_named(pml, enable_pml, bool, S_IRUGO);

#define KVM_VMX_TSC_MULTIPLIER_MAX 0xffffffffffffffffULL

#define KVM_GUEST_CR0_MASK (X86_CR0_NW | X86_CR0_CD)
#define KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST (X86_CR0_WP | X86_CR0_NE)
#define KVM_VM_CR0_ALWAYS_ON \
 (KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST | X86_CR0_PG | X86_CR0_PE)
#define KVM_CR4_GUEST_OWNED_BITS \
 (X86_CR4_PVI | X86_CR4_DE | X86_CR4_PCE | X86_CR4_OSFXSR \
 | X86_CR4_OSXMMEXCPT | X86_CR4_TSD)

#define KVM_PMODE_VM_CR4_ALWAYS_ON (X86_CR4_PAE | X86_CR4_VMXE)
#define KVM_RMODE_VM_CR4_ALWAYS_ON (X86_CR4_VME | X86_CR4_PAE | X86_CR4_VMXE)

#define RMODE_GUEST_OWNED_EFLAGS_BITS (~(X86_EFLAGS_IOPL | X86_EFLAGS_VM))

#define VMX_MISC_EMULATED_PREEMPTION_TIMER_RATE 5

/*
 * These 2 parameters are used to config the controls for Pause-Loop Exiting:
 * ple_gap: upper bound on the amount of time between two successive
 * executions of PAUSE in a loop. Also indicate if ple enabled.
 * According to test, this time is usually smaller than 128 cycles.
 * ple_window: upper bound on the amount of time a guest is allowed to execute
 * in a PAUSE loop. Tests indicate that most spinlocks are held for
 * less than 2^12 cycles
 * Time is measured based on a counter that runs at the same rate as the TSC,
 * refer SDM volume 3b section 21.6.13 & 22.1.3.
 */
#define KVM_VMX_DEFAULT_PLE_GAP 128
#define KVM_VMX_DEFAULT_PLE_WINDOW 4096
#define KVM_VMX_DEFAULT_PLE_WINDOW_GROW 2
#define KVM_VMX_DEFAULT_PLE_WINDOW_SHRINK 0
#define KVM_VMX_DEFAULT_PLE_WINDOW_MAX \
 INT_MAX / KVM_VMX_DEFAULT_PLE_WINDOW_GROW

static int ple_gap = KVM_VMX_DEFAULT_PLE_GAP;
module_param(ple_gap, int, S_IRUGO);

static int ple_window = KVM_VMX_DEFAULT_PLE_WINDOW;
module_param(ple_window, int, S_IRUGO);

/* Default doubles per-vcpu window every exit. */
static int ple_window_grow = KVM_VMX_DEFAULT_PLE_WINDOW_GROW;
module_param(ple_window_grow, int, S_IRUGO);

/* Default resets per-vcpu window every exit to ple_window. */
static int ple_window_shrink = KVM_VMX_DEFAULT_PLE_WINDOW_SHRINK;
module_param(ple_window_shrink, int, S_IRUGO);

/* Default is to compute the maximum so we can never overflow. */
static int ple_window_actual_max = KVM_VMX_DEFAULT_PLE_WINDOW_MAX;
static int ple_window_max        = KVM_VMX_DEFAULT_PLE_WINDOW_MAX;
module_param(ple_window_max, int, S_IRUGO);

extern const ulong vmx_return;

#define NR_AUTOLOAD_MSRS 8
#define VMCS02_POOL_SIZE 1

struct vmcs {
	u32 revision_id;
	u32 abort;
	char data[0];
};

/*
 * Track a VMCS that may be loaded on a certain CPU. If it is (cpu!=-1), also
 * remember whether it was VMLAUNCHed, and maintain a linked list of all VMCSs
 * loaded on this CPU (so we can clear them if the CPU goes down).
 */
struct loaded_vmcs {
	struct vmcs *vmcs;
	int cpu;
	int launched;
	struct list_head loaded_vmcss_on_cpu_link;
};

struct shared_msr_entry {
	unsigned index;
	u64 data;
	u64 mask;
};

/*
 * struct vmcs12 describes the state that our guest hypervisor (L1) keeps for a
 * single nested guest (L2), hence the name vmcs12. Any VMX implementation has
 * a VMCS structure, and vmcs12 is our emulated VMX's VMCS. This structure is
 * stored in guest memory specified by VMPTRLD, but is opaque to the guest,
 * which must access it using VMREAD/VMWRITE/VMCLEAR instructions.
 * More than one of these structures may exist, if L1 runs multiple L2 guests.
 * nested_vmx_run() will use the data here to build a vmcs02: a VMCS for the
 * underlying hardware which will be used to run L2.
 * This structure is packed to ensure that its layout is identical across
 * machines (necessary for live migration).
 * If there are changes in this struct, VMCS12_REVISION must be changed.
 */
typedef u64 natural_width;
struct __packed vmcs12 {
	/* According to the Intel spec, a VMCS region must start with the
 * following two fields. Then follow implementation-specific data.
 */
	u32 revision_id;
	u32 abort;

	u32 launch_state; /* set to 0 by VMCLEAR, to 1 by VMLAUNCH */
	u32 padding[7]; /* room for future expansion */

	u64 io_bitmap_a;
	u64 io_bitmap_b;
	u64 msr_bitmap;
	u64 vm_exit_msr_store_addr;
	u64 vm_exit_msr_load_addr;
	u64 vm_entry_msr_load_addr;
	u64 tsc_offset;
	u64 virtual_apic_page_addr;
	u64 apic_access_addr;
	u64 posted_intr_desc_addr;
	u64 ept_pointer;
	u64 eoi_exit_bitmap0;
	u64 eoi_exit_bitmap1;
	u64 eoi_exit_bitmap2;
	u64 eoi_exit_bitmap3;
	u64 xss_exit_bitmap;
	u64 guest_physical_address;
	u64 vmcs_link_pointer;
	u64 guest_ia32_debugctl;
	u64 guest_ia32_pat;
	u64 guest_ia32_efer;
	u64 guest_ia32_perf_global_ctrl;
	u64 guest_pdptr0;
	u64 guest_pdptr1;
	u64 guest_pdptr2;
	u64 guest_pdptr3;
	u64 guest_bndcfgs;
	u64 host_ia32_pat;
	u64 host_ia32_efer;
	u64 host_ia32_perf_global_ctrl;
	u64 padding64[8]; /* room for future expansion */
	/*
 * To allow migration of L1 (complete with its L2 guests) between
 * machines of different natural widths (32 or 64 bit), we cannot have
 * unsigned long fields with no explict size. We use u64 (aliased
 * natural_width) instead. Luckily, x86 is little-endian.
 */
	natural_width cr0_guest_host_mask;
	natural_width cr4_guest_host_mask;
	natural_width cr0_read_shadow;
	natural_width cr4_read_shadow;
	natural_width cr3_target_value0;
	natural_width cr3_target_value1;
	natural_width cr3_target_value2;
	natural_width cr3_target_value3;
	natural_width exit_qualification;
	natural_width guest_linear_address;
	natural_width guest_cr0;
	natural_width guest_cr3;
	natural_width guest_cr4;
	natural_width guest_es_base;
	natural_width guest_cs_base;
	natural_width guest_ss_base;
	natural_width guest_ds_base;
	natural_width guest_fs_base;
	natural_width guest_gs_base;
	natural_width guest_ldtr_base;
	natural_width guest_tr_base;
	natural_width guest_gdtr_base;
	natural_width guest_idtr_base;
	natural_width guest_dr7;
	natural_width guest_rsp;
	natural_width guest_rip;
	natural_width guest_rflags;
	natural_width guest_pending_dbg_exceptions;
	natural_width guest_sysenter_esp;
	natural_width guest_sysenter_eip;
	natural_width host_cr0;
	natural_width host_cr3;
	natural_width host_cr4;
	natural_width host_fs_base;
	natural_width host_gs_base;
	natural_width host_tr_base;
	natural_width host_gdtr_base;
	natural_width host_idtr_base;
	natural_width host_ia32_sysenter_esp;
	natural_width host_ia32_sysenter_eip;
	natural_width host_rsp;
	natural_width host_rip;
	natural_width paddingl[8]; /* room for future expansion */
	u32 pin_based_vm_exec_control;
	u32 cpu_based_vm_exec_control;
	u32 exception_bitmap;
	u32 page_fault_error_code_mask;
	u32 page_fault_error_code_match;
	u32 cr3_target_count;
	u32 vm_exit_controls;
	u32 vm_exit_msr_store_count;
	u32 vm_exit_msr_load_count;
	u32 vm_entry_controls;
	u32 vm_entry_msr_load_count;
	u32 vm_entry_intr_info_field;
	u32 vm_entry_exception_error_code;
	u32 vm_entry_instruction_len;
	u32 tpr_threshold;
	u32 secondary_vm_exec_control;
	u32 vm_instruction_error;
	u32 vm_exit_reason;
	u32 vm_exit_intr_info;
	u32 vm_exit_intr_error_code;
	u32 idt_vectoring_info_field;
	u32 idt_vectoring_error_code;
	u32 vm_exit_instruction_len;
	u32 vmx_instruction_info;
	u32 guest_es_limit;
	u32 guest_cs_limit;
	u32 guest_ss_limit;
	u32 guest_ds_limit;
	u32 guest_fs_limit;
	u32 guest_gs_limit;
	u32 guest_ldtr_limit;
	u32 guest_tr_limit;
	u32 guest_gdtr_limit;
	u32 guest_idtr_limit;
	u32 guest_es_ar_bytes;
	u32 guest_cs_ar_bytes;
	u32 guest_ss_ar_bytes;
	u32 guest_ds_ar_bytes;
	u32 guest_fs_ar_bytes;
	u32 guest_gs_ar_bytes;
	u32 guest_ldtr_ar_bytes;
	u32 guest_tr_ar_bytes;
	u32 guest_interruptibility_info;
	u32 guest_activity_state;
	u32 guest_sysenter_cs;
	u32 host_ia32_sysenter_cs;
	u32 vmx_preemption_timer_value;
	u32 padding32[7]; /* room for future expansion */
	u16 virtual_processor_id;
	u16 posted_intr_nv;
	u16 guest_es_selector;
	u16 guest_cs_selector;
	u16 guest_ss_selector;
	u16 guest_ds_selector;
	u16 guest_fs_selector;
	u16 guest_gs_selector;
	u16 guest_ldtr_selector;
	u16 guest_tr_selector;
	u16 guest_intr_status;
	u16 host_es_selector;
	u16 host_cs_selector;
	u16 host_ss_selector;
	u16 host_ds_selector;
	u16 host_fs_selector;
	u16 host_gs_selector;
	u16 host_tr_selector;
};

/*
 * VMCS12_REVISION is an arbitrary id that should be changed if the content or
 * layout of struct vmcs12 is changed. MSR_IA32_VMX_BASIC returns this id, and
 * VMPTRLD verifies that the VMCS region that L1 is loading contains this id.
 */
#define VMCS12_REVISION 0x11e57ed0

/*
 * VMCS12_SIZE is the number of bytes L1 should allocate for the VMXON region
 * and any VMCS region. Although only sizeof(struct vmcs12) are used by the
 * current implementation, 4K are reserved to avoid future complications.
 */
#define VMCS12_SIZE 0x1000

/* Used to remember the last vmcs02 used for some recently used vmcs12s */
struct vmcs02_list {
	struct list_head list;
	gpa_t vmptr;
	struct loaded_vmcs vmcs02;
};

/*
 * The nested_vmx structure is part of vcpu_vmx, and holds information we need
 * for correct emulation of VMX (i.e., nested VMX) on this vcpu.
 */
struct nested_vmx {
	/* Has the level1 guest done vmxon? */
	bool vmxon;
	gpa_t vmxon_ptr;

	/* The guest-physical address of the current VMCS L1 keeps for L2 */
	gpa_t current_vmptr;
	/* The host-usable pointer to the above */
	struct page *current_vmcs12_page;
	struct vmcs12 *current_vmcs12;
	struct vmcs *current_shadow_vmcs;
	/*
 * Indicates if the shadow vmcs must be updated with the
 * data hold by vmcs12
 */
	bool sync_shadow_vmcs;

	/* vmcs02_list cache of VMCSs recently used to run L2 guests */
	struct list_head vmcs02_pool;
	int vmcs02_num;
	u64 vmcs01_tsc_offset;
	/* L2 must run next, and mustn't decide to exit to L1. */
	bool nested_run_pending;
	/*
 * Guest pages referred to in vmcs02 with host-physical pointers, so
 * we must keep them pinned while L2 runs.
 */
	struct page *apic_access_page;
	struct page *virtual_apic_page;
	struct page *pi_desc_page;
	struct pi_desc *pi_desc;
	bool pi_pending;
	u16 posted_intr_nv;
	u64 msr_ia32_feature_control;

	struct hrtimer preemption_timer;
	bool preemption_timer_expired;

	/* to migrate it to L2 if VM_ENTRY_LOAD_DEBUG_CONTROLS is off */
	u64 vmcs01_debugctl;

	u16 vpid02;
	u16 last_vpid;

	u32 nested_vmx_procbased_ctls_low;
	u32 nested_vmx_procbased_ctls_high;
	u32 nested_vmx_true_procbased_ctls_low;
	u32 nested_vmx_secondary_ctls_low;
	u32 nested_vmx_secondary_ctls_high;
	u32 nested_vmx_pinbased_ctls_low;
	u32 nested_vmx_pinbased_ctls_high;
	u32 nested_vmx_exit_ctls_low;
	u32 nested_vmx_exit_ctls_high;
	u32 nested_vmx_true_exit_ctls_low;
	u32 nested_vmx_entry_ctls_low;
	u32 nested_vmx_entry_ctls_high;
	u32 nested_vmx_true_entry_ctls_low;
	u32 nested_vmx_misc_low;
	u32 nested_vmx_misc_high;
	u32 nested_vmx_ept_caps;
	u32 nested_vmx_vpid_caps;
};

#define POSTED_INTR_ON 0
#define POSTED_INTR_SN 1

/* Posted-Interrupt Descriptor */
struct pi_desc {
	u32 pir[8];     /* Posted interrupt requested */
	union {
		struct {
				/* bit 256 - Outstanding Notification */
			u16	on	: 1,
				/* bit 257 - Suppress Notification */
				sn	: 1,
				/* bit 271:258 - Reserved */
				rsvd_1	: 14;
				/* bit 279:272 - Notification Vector */
			u8	nv;
				/* bit 287:280 - Reserved */
			u8	rsvd_2;
				/* bit 319:288 - Notification Destination */
			u32	ndst;
		};
		u64 control;
	};
	u32 rsvd[6];
} __aligned(64);

static bool pi_test_and_set_on(struct pi_desc *pi_desc)
{
	return test_and_set_bit(POSTED_INTR_ON,
			(unsigned long *)&pi_desc->control);
}

static bool pi_test_and_clear_on(struct pi_desc *pi_desc)
{
	return test_and_clear_bit(POSTED_INTR_ON,
			(unsigned long *)&pi_desc->control);
}

static int pi_test_and_set_pir(int vector, struct pi_desc *pi_desc)
{
	return test_and_set_bit(vector, (unsigned long *)pi_desc->pir);
}

static inline void pi_clear_sn(struct pi_desc *pi_desc)
{
	return clear_bit(POSTED_INTR_SN,
			(unsigned long *)&pi_desc->control);
}

static inline void pi_set_sn(struct pi_desc *pi_desc)
{
	return set_bit(POSTED_INTR_SN,
			(unsigned long *)&pi_desc->control);
}

static inline int pi_test_on(struct pi_desc *pi_desc)
{
	return test_bit(POSTED_INTR_ON,
			(unsigned long *)&pi_desc->control);
}

static inline int pi_test_sn(struct pi_desc *pi_desc)
{
	return test_bit(POSTED_INTR_SN,
			(unsigned long *)&pi_desc->control);
}

struct vcpu_vmx {
	struct kvm_vcpu       vcpu;
	unsigned long         host_rsp;
	u8                    fail;
	bool                  nmi_known_unmasked;
	u32                   exit_intr_info;
	u32                   idt_vectoring_info;
	ulong                 rflags;
	struct shared_msr_entry *guest_msrs;
	int                   nmsrs;
	int                   save_nmsrs;
	unsigned long	      host_idt_base;
#ifdef CONFIG_X86_64
	u64 		      msr_host_kernel_gs_base;
	u64 		      msr_guest_kernel_gs_base;
#endif
	u32 vm_entry_controls_shadow;
	u32 vm_exit_controls_shadow;
	/*
 * loaded_vmcs points to the VMCS currently used in this vcpu. For a
 * non-nested (L1) guest, it always points to vmcs01. For a nested
 * guest (L2), it points to a different VMCS.
 */
	struct loaded_vmcs    vmcs01;
	struct loaded_vmcs   *loaded_vmcs;
	bool                  __launched; /* temporary, used in vmx_vcpu_run */
	struct msr_autoload {
		unsigned nr;
		struct vmx_msr_entry guest[NR_AUTOLOAD_MSRS];
		struct vmx_msr_entry host[NR_AUTOLOAD_MSRS];
	} msr_autoload;
	struct {
		int           loaded;
		u16           fs_sel, gs_sel, ldt_sel;
#ifdef CONFIG_X86_64
		u16           ds_sel, es_sel;
#endif
		int           gs_ldt_reload_needed;
		int           fs_reload_needed;
		u64           msr_host_bndcfgs;
		unsigned long vmcs_host_cr4;	/* May not match real cr4 */
	} host_state;
	struct {
		int vm86_active;
		ulong save_rflags;
		struct kvm_segment segs[8];
	} rmode;
	struct {
		u32 bitmask; /* 4 bits per segment (1 bit per field) */
		struct kvm_save_segment {
			u16 selector;
			unsigned long base;
			u32 limit;
			u32 ar;
		} seg[8];
	} segment_cache;
	int vpid;
	bool emulation_required;

	/* Support for vnmi-less CPUs */
	int soft_vnmi_blocked;
	ktime_t entry_time;
	s64 vnmi_blocked_time;
	u32 exit_reason;

	/* Posted interrupt descriptor */
	struct pi_desc pi_desc;

	/* Support for a guest hypervisor (nested VMX) */
	struct nested_vmx nested;

	/* Dynamic PLE window. */
	int ple_window;
	bool ple_window_dirty;

	/* Support for PML */
#define PML_ENTITY_NUM 512
	struct page *pml_pg;

	u64 current_tsc_ratio;

	bool guest_pkru_valid;
	u32 guest_pkru;
	u32 host_pkru;
};

enum segment_cache_field {
	SEG_FIELD_SEL = 0,
	SEG_FIELD_BASE = 1,
	SEG_FIELD_LIMIT = 2,
	SEG_FIELD_AR = 3,

	SEG_FIELD_NR = 4
};

static inline struct vcpu_vmx *to_vmx(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_vmx, vcpu);
}

static struct pi_desc *vcpu_to_pi_desc(struct kvm_vcpu *vcpu)
{
	return &(to_vmx(vcpu)->pi_desc);
}

#define VMCS12_OFFSET(x) offsetof(struct vmcs12, x)
#define FIELD(number, name) [number] = VMCS12_OFFSET(name)
#define FIELD64(number, name) [number] = VMCS12_OFFSET(name), \
 [number##_HIGH] = VMCS12_OFFSET(name)+4


static unsigned long shadow_read_only_fields[] = {
	/*
 * We do NOT shadow fields that are modified when L0
 * traps and emulates any vmx instruction (e.g. VMPTRLD,
 * VMXON...) executed by L1.
 * For example, VM_INSTRUCTION_ERROR is read
 * by L1 if a vmx instruction fails (part of the error path).
 * Note the code assumes this logic. If for some reason
 * we start shadowing these fields then we need to
 * force a shadow sync when L0 emulates vmx instructions
 * (e.g. force a sync if VM_INSTRUCTION_ERROR is modified
 * by nested_vmx_failValid)
 */
	VM_EXIT_REASON,
	VM_EXIT_INTR_INFO,
	VM_EXIT_INSTRUCTION_LEN,
	IDT_VECTORING_INFO_FIELD,
	IDT_VECTORING_ERROR_CODE,
	VM_EXIT_INTR_ERROR_CODE,
	EXIT_QUALIFICATION,
	GUEST_LINEAR_ADDRESS,
	GUEST_PHYSICAL_ADDRESS
};
static int max_shadow_read_only_fields =
	ARRAY_SIZE(shadow_read_only_fields);

static unsigned long shadow_read_write_fields[] = {
	TPR_THRESHOLD,
	GUEST_RIP,
	GUEST_RSP,
	GUEST_CR0,
	GUEST_CR3,
	GUEST_CR4,
	GUEST_INTERRUPTIBILITY_INFO,
	GUEST_RFLAGS,
	GUEST_CS_SELECTOR,
	GUEST_CS_AR_BYTES,
	GUEST_CS_LIMIT,
	GUEST_CS_BASE,
	GUEST_ES_BASE,
	GUEST_BNDCFGS,
	CR0_GUEST_HOST_MASK,
	CR0_READ_SHADOW,
	CR4_READ_SHADOW,
	TSC_OFFSET,
	EXCEPTION_BITMAP,
	CPU_BASED_VM_EXEC_CONTROL,
	VM_ENTRY_EXCEPTION_ERROR_CODE,
	VM_ENTRY_INTR_INFO_FIELD,
	VM_ENTRY_INSTRUCTION_LEN,
	VM_ENTRY_EXCEPTION_ERROR_CODE,
	HOST_FS_BASE,
	HOST_GS_BASE,
	HOST_FS_SELECTOR,
	HOST_GS_SELECTOR
};
static int max_shadow_read_write_fields =
	ARRAY_SIZE(shadow_read_write_fields);

static const unsigned short vmcs_field_to_offset_table[] = {
	FIELD(VIRTUAL_PROCESSOR_ID, virtual_processor_id),
	FIELD(POSTED_INTR_NV, posted_intr_nv),
	FIELD(GUEST_ES_SELECTOR, guest_es_selector),
	FIELD(GUEST_CS_SELECTOR, guest_cs_selector),
	FIELD(GUEST_SS_SELECTOR, guest_ss_selector),
	FIELD(GUEST_DS_SELECTOR, guest_ds_selector),
	FIELD(GUEST_FS_SELECTOR, guest_fs_selector),
	FIELD(GUEST_GS_SELECTOR, guest_gs_selector),
	FIELD(GUEST_LDTR_SELECTOR, guest_ldtr_selector),
	FIELD(GUEST_TR_SELECTOR, guest_tr_selector),
	FIELD(GUEST_INTR_STATUS, guest_intr_status),
	FIELD(HOST_ES_SELECTOR, host_es_selector),
	FIELD(HOST_CS_SELECTOR, host_cs_selector),
	FIELD(HOST_SS_SELECTOR, host_ss_selector),
	FIELD(HOST_DS_SELECTOR, host_ds_selector),
	FIELD(HOST_FS_SELECTOR, host_fs_selector),
	FIELD(HOST_GS_SELECTOR, host_gs_selector),
	FIELD(HOST_TR_SELECTOR, host_tr_selector),
	FIELD64(IO_BITMAP_A, io_bitmap_a),
	FIELD64(IO_BITMAP_B, io_bitmap_b),
	FIELD64(MSR_BITMAP, msr_bitmap),
	FIELD64(VM_EXIT_MSR_STORE_ADDR, vm_exit_msr_store_addr),
	FIELD64(VM_EXIT_MSR_LOAD_ADDR, vm_exit_msr_load_addr),
	FIELD64(VM_ENTRY_MSR_LOAD_ADDR, vm_entry_msr_load_addr),
	FIELD64(TSC_OFFSET, tsc_offset),
	FIELD64(VIRTUAL_APIC_PAGE_ADDR, virtual_apic_page_addr),
	FIELD64(APIC_ACCESS_ADDR, apic_access_addr),
	FIELD64(POSTED_INTR_DESC_ADDR, posted_intr_desc_addr),
	FIELD64(EPT_POINTER, ept_pointer),
	FIELD64(EOI_EXIT_BITMAP0, eoi_exit_bitmap0),
	FIELD64(EOI_EXIT_BITMAP1, eoi_exit_bitmap1),
	FIELD64(EOI_EXIT_BITMAP2, eoi_exit_bitmap2),
	FIELD64(EOI_EXIT_BITMAP3, eoi_exit_bitmap3),
	FIELD64(XSS_EXIT_BITMAP, xss_exit_bitmap),
	FIELD64(GUEST_PHYSICAL_ADDRESS, guest_physical_address),
	FIELD64(VMCS_LINK_POINTER, vmcs_link_pointer),
	FIELD64(GUEST_IA32_DEBUGCTL, guest_ia32_debugctl),
	FIELD64(GUEST_IA32_PAT, guest_ia32_pat),
	FIELD64(GUEST_IA32_EFER, guest_ia32_efer),
	FIELD64(GUEST_IA32_PERF_GLOBAL_CTRL, guest_ia32_perf_global_ctrl),
	FIELD64(GUEST_PDPTR0, guest_pdptr0),
	FIELD64(GUEST_PDPTR1, guest_pdptr1),
	FIELD64(GUEST_PDPTR2, guest_pdptr2),
	FIELD64(GUEST_PDPTR3, guest_pdptr3),
	FIELD64(GUEST_BNDCFGS, guest_bndcfgs),
	FIELD64(HOST_IA32_PAT, host_ia32_pat),
	FIELD64(HOST_IA32_EFER, host_ia32_efer),
	FIELD64(HOST_IA32_PERF_GLOBAL_CTRL, host_ia32_perf_global_ctrl),
	FIELD(PIN_BASED_VM_EXEC_CONTROL, pin_based_vm_exec_control),
	FIELD(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control),
	FIELD(EXCEPTION_BITMAP, exception_bitmap),
	FIELD(PAGE_FAULT_ERROR_CODE_MASK, page_fault_error_code_mask),
	FIELD(PAGE_FAULT_ERROR_CODE_MATCH, page_fault_error_code_match),
	FIELD(CR3_TARGET_COUNT, cr3_target_count),
	FIELD(VM_EXIT_CONTROLS, vm_exit_controls),
	FIELD(VM_EXIT_MSR_STORE_COUNT, vm_exit_msr_store_count),
	FIELD(VM_EXIT_MSR_LOAD_COUNT, vm_exit_msr_load_count),
	FIELD(VM_ENTRY_CONTROLS, vm_entry_controls),
	FIELD(VM_ENTRY_MSR_LOAD_COUNT, vm_entry_msr_load_count),
	FIELD(VM_ENTRY_INTR_INFO_FIELD, vm_entry_intr_info_field),
	FIELD(VM_ENTRY_EXCEPTION_ERROR_CODE, vm_entry_exception_error_code),
	FIELD(VM_ENTRY_INSTRUCTION_LEN, vm_entry_instruction_len),
	FIELD(TPR_THRESHOLD, tpr_threshold),
	FIELD(SECONDARY_VM_EXEC_CONTROL, secondary_vm_exec_control),
	FIELD(VM_INSTRUCTION_ERROR, vm_instruction_error),
	FIELD(VM_EXIT_REASON, vm_exit_reason),
	FIELD(VM_EXIT_INTR_INFO, vm_exit_intr_info),
	FIELD(VM_EXIT_INTR_ERROR_CODE, vm_exit_intr_error_code),
	FIELD(IDT_VECTORING_INFO_FIELD, idt_vectoring_info_field),
	FIELD(IDT_VECTORING_ERROR_CODE, idt_vectoring_error_code),
	FIELD(VM_EXIT_INSTRUCTION_LEN, vm_exit_instruction_len),
	FIELD(VMX_INSTRUCTION_INFO, vmx_instruction_info),
	FIELD(GUEST_ES_LIMIT, guest_es_limit),
	FIELD(GUEST_CS_LIMIT, guest_cs_limit),
	FIELD(GUEST_SS_LIMIT, guest_ss_limit),
	FIELD(GUEST_DS_LIMIT, guest_ds_limit),
	FIELD(GUEST_FS_LIMIT, guest_fs_limit),
	FIELD(GUEST_GS_LIMIT, guest_gs_limit),
	FIELD(GUEST_LDTR_LIMIT, guest_ldtr_limit),
	FIELD(GUEST_TR_LIMIT, guest_tr_limit),
	FIELD(GUEST_GDTR_LIMIT, guest_gdtr_limit),
	FIELD(GUEST_IDTR_LIMIT, guest_idtr_limit),
	FIELD(GUEST_ES_AR_BYTES, guest_es_ar_bytes),
	FIELD(GUEST_CS_AR_BYTES, guest_cs_ar_bytes),
	FIELD(GUEST_SS_AR_BYTES, guest_ss_ar_bytes),
	FIELD(GUEST_DS_AR_BYTES, guest_ds_ar_bytes),
	FIELD(GUEST_FS_AR_BYTES, guest_fs_ar_bytes),
	FIELD(GUEST_GS_AR_BYTES, guest_gs_ar_bytes),
	FIELD(GUEST_LDTR_AR_BYTES, guest_ldtr_ar_bytes),
	FIELD(GUEST_TR_AR_BYTES, guest_tr_ar_bytes),
	FIELD(GUEST_INTERRUPTIBILITY_INFO, guest_interruptibility_info),
	FIELD(GUEST_ACTIVITY_STATE, guest_activity_state),
	FIELD(GUEST_SYSENTER_CS, guest_sysenter_cs),
	FIELD(HOST_IA32_SYSENTER_CS, host_ia32_sysenter_cs),
	FIELD(VMX_PREEMPTION_TIMER_VALUE, vmx_preemption_timer_value),
	FIELD(CR0_GUEST_HOST_MASK, cr0_guest_host_mask),
	FIELD(CR4_GUEST_HOST_MASK, cr4_guest_host_mask),
	FIELD(CR0_READ_SHADOW, cr0_read_shadow),
	FIELD(CR4_READ_SHADOW, cr4_read_shadow),
	FIELD(CR3_TARGET_VALUE0, cr3_target_value0),
	FIELD(CR3_TARGET_VALUE1, cr3_target_value1),
	FIELD(CR3_TARGET_VALUE2, cr3_target_value2),
	FIELD(CR3_TARGET_VALUE3, cr3_target_value3),
	FIELD(EXIT_QUALIFICATION, exit_qualification),
	FIELD(GUEST_LINEAR_ADDRESS, guest_linear_address),
	FIELD(GUEST_CR0, guest_cr0),
	FIELD(GUEST_CR3, guest_cr3),
	FIELD(GUEST_CR4, guest_cr4),
	FIELD(GUEST_ES_BASE, guest_es_base),
	FIELD(GUEST_CS_BASE, guest_cs_base),
	FIELD(GUEST_SS_BASE, guest_ss_base),
	FIELD(GUEST_DS_BASE, guest_ds_base),
	FIELD(GUEST_FS_BASE, guest_fs_base),
	FIELD(GUEST_GS_BASE, guest_gs_base),
	FIELD(GUEST_LDTR_BASE, guest_ldtr_base),
	FIELD(GUEST_TR_BASE, guest_tr_base),
	FIELD(GUEST_GDTR_BASE, guest_gdtr_base),
	FIELD(GUEST_IDTR_BASE, guest_idtr_base),
	FIELD(GUEST_DR7, guest_dr7),
	FIELD(GUEST_RSP, guest_rsp),
	FIELD(GUEST_RIP, guest_rip),
	FIELD(GUEST_RFLAGS, guest_rflags),
	FIELD(GUEST_PENDING_DBG_EXCEPTIONS, guest_pending_dbg_exceptions),
	FIELD(GUEST_SYSENTER_ESP, guest_sysenter_esp),
	FIELD(GUEST_SYSENTER_EIP, guest_sysenter_eip),
	FIELD(HOST_CR0, host_cr0),
	FIELD(HOST_CR3, host_cr3),
	FIELD(HOST_CR4, host_cr4),
	FIELD(HOST_FS_BASE, host_fs_base),
	FIELD(HOST_GS_BASE, host_gs_base),
	FIELD(HOST_TR_BASE, host_tr_base),
	FIELD(HOST_GDTR_BASE, host_gdtr_base),
	FIELD(HOST_IDTR_BASE, host_idtr_base),
	FIELD(HOST_IA32_SYSENTER_ESP, host_ia32_sysenter_esp),
	FIELD(HOST_IA32_SYSENTER_EIP, host_ia32_sysenter_eip),
	FIELD(HOST_RSP, host_rsp),
	FIELD(HOST_RIP, host_rip),
};

static inline short vmcs_field_to_offset(unsigned long field)
{
	BUILD_BUG_ON(ARRAY_SIZE(vmcs_field_to_offset_table) > SHRT_MAX);

	if (field >= ARRAY_SIZE(vmcs_field_to_offset_table) ||
	    vmcs_field_to_offset_table[field] == 0)
		return -ENOENT;

	return vmcs_field_to_offset_table[field];
}

static inline struct vmcs12 *get_vmcs12(struct kvm_vcpu *vcpu)
{
	return to_vmx(vcpu)->nested.current_vmcs12;
}

static struct page *nested_get_page(struct kvm_vcpu *vcpu, gpa_t addr)
{
	struct page *page = kvm_vcpu_gfn_to_page(vcpu, addr >> PAGE_SHIFT);
	if (is_error_page(page))
		return NULL;

	return page;
}

static void nested_release_page(struct page *page)
{
	kvm_release_page_dirty(page);
}

static void nested_release_page_clean(struct page *page)
{
	kvm_release_page_clean(page);
}

static unsigned long nested_ept_get_cr3(struct kvm_vcpu *vcpu);
static u64 construct_eptp(unsigned long root_hpa);
static void kvm_cpu_vmxon(u64 addr);
static void kvm_cpu_vmxoff(void);
static bool vmx_xsaves_supported(void);
static int vmx_set_tss_addr(struct kvm *kvm, unsigned int addr);
static void vmx_set_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg);
static void vmx_get_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg);
static bool guest_state_valid(struct kvm_vcpu *vcpu);
static u32 vmx_segment_access_rights(struct kvm_segment *var);
static void copy_vmcs12_to_shadow(struct vcpu_vmx *vmx);
static void copy_shadow_to_vmcs12(struct vcpu_vmx *vmx);
static int alloc_identity_pagetable(struct kvm *kvm);

static DEFINE_PER_CPU(struct vmcs *, vmxarea);
static DEFINE_PER_CPU(struct vmcs *, current_vmcs);
/*
 * We maintain a per-CPU linked-list of VMCS loaded on that CPU. This is needed
 * when a CPU is brought down, and we need to VMCLEAR all VMCSs loaded on it.
 */
static DEFINE_PER_CPU(struct list_head, loaded_vmcss_on_cpu);
static DEFINE_PER_CPU(struct desc_ptr, host_gdt);

/*
 * We maintian a per-CPU linked-list of vCPU, so in wakeup_handler() we
 * can find which vCPU should be waken up.
 */
static DEFINE_PER_CPU(struct list_head, blocked_vcpu_on_cpu);
static DEFINE_PER_CPU(spinlock_t, blocked_vcpu_on_cpu_lock);

static unsigned long *vmx_io_bitmap_a;
static unsigned long *vmx_io_bitmap_b;
static unsigned long *vmx_msr_bitmap_legacy;
static unsigned long *vmx_msr_bitmap_longmode;
static unsigned long *vmx_msr_bitmap_legacy_x2apic;
static unsigned long *vmx_msr_bitmap_longmode_x2apic;
static unsigned long *vmx_msr_bitmap_nested;
static unsigned long *vmx_vmread_bitmap;
static unsigned long *vmx_vmwrite_bitmap;

static bool cpu_has_load_ia32_efer;
static bool cpu_has_load_perf_global_ctrl;

static DECLARE_BITMAP(vmx_vpid_bitmap, VMX_NR_VPIDS);
static DEFINE_SPINLOCK(vmx_vpid_lock);

static struct vmcs_config {
	int size;
	int order;
	u32 revision_id;
	u32 pin_based_exec_ctrl;
	u32 cpu_based_exec_ctrl;
	u32 cpu_based_2nd_exec_ctrl;
	u32 vmexit_ctrl;
	u32 vmentry_ctrl;
} vmcs_config;

static struct vmx_capability {
	u32 ept;
	u32 vpid;
} vmx_capability;

#define VMX_SEGMENT_FIELD(seg) \
 [VCPU_SREG_##seg] = { \
 .selector = GUEST_##seg##_SELECTOR, \
 .base = GUEST_##seg##_BASE, \
 .limit = GUEST_##seg##_LIMIT, \
 .ar_bytes = GUEST_##seg##_AR_BYTES, \
 }

static const struct kvm_vmx_segment_field {
	unsigned selector;
	unsigned base;
	unsigned limit;
	unsigned ar_bytes;
} kvm_vmx_segment_fields[] = {
	VMX_SEGMENT_FIELD(CS),
	VMX_SEGMENT_FIELD(DS),
	VMX_SEGMENT_FIELD(ES),
	VMX_SEGMENT_FIELD(FS),
	VMX_SEGMENT_FIELD(GS),
	VMX_SEGMENT_FIELD(SS),
	VMX_SEGMENT_FIELD(TR),
	VMX_SEGMENT_FIELD(LDTR),
};

static u64 host_efer;

static void ept_save_pdptrs(struct kvm_vcpu *vcpu);

/*
 * Keep MSR_STAR at the end, as setup_msrs() will try to optimize it
 * away by decrementing the array size.
 */
static const u32 vmx_msr_index[] = {
#ifdef CONFIG_X86_64
	MSR_SYSCALL_MASK, MSR_LSTAR, MSR_CSTAR,
#endif
	MSR_EFER, MSR_TSC_AUX, MSR_STAR,
};

static inline bool is_exception_n(u32 intr_info, u8 vector)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
			     INTR_INFO_VALID_MASK)) ==
		(INTR_TYPE_HARD_EXCEPTION | vector | INTR_INFO_VALID_MASK);
}

static inline bool is_debug(u32 intr_info)
{
	return is_exception_n(intr_info, DB_VECTOR);
}

static inline bool is_breakpoint(u32 intr_info)
{
	return is_exception_n(intr_info, BP_VECTOR);
}

static inline bool is_page_fault(u32 intr_info)
{
	return is_exception_n(intr_info, PF_VECTOR);
}

static inline bool is_no_device(u32 intr_info)
{
	return is_exception_n(intr_info, NM_VECTOR);
}

static inline bool is_invalid_opcode(u32 intr_info)
{
	return is_exception_n(intr_info, UD_VECTOR);
}

static inline bool is_external_interrupt(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VALID_MASK))
		== (INTR_TYPE_EXT_INTR | INTR_INFO_VALID_MASK);
}

static inline bool is_machine_check(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
			     INTR_INFO_VALID_MASK)) ==
		(INTR_TYPE_HARD_EXCEPTION | MC_VECTOR | INTR_INFO_VALID_MASK);
}

static inline bool cpu_has_vmx_msr_bitmap(void)
{
	return vmcs_config.cpu_based_exec_ctrl & CPU_BASED_USE_MSR_BITMAPS;
}

static inline bool cpu_has_vmx_tpr_shadow(void)
{
	return vmcs_config.cpu_based_exec_ctrl & CPU_BASED_TPR_SHADOW;
}

static inline bool cpu_need_tpr_shadow(struct kvm_vcpu *vcpu)
{
	return cpu_has_vmx_tpr_shadow() && lapic_in_kernel(vcpu);
}

static inline bool cpu_has_secondary_exec_ctrls(void)
{
	return vmcs_config.cpu_based_exec_ctrl &
		CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
}

static inline bool cpu_has_vmx_virtualize_apic_accesses(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
}

static inline bool cpu_has_vmx_virtualize_x2apic_mode(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE;
}

static inline bool cpu_has_vmx_apic_register_virt(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_APIC_REGISTER_VIRT;
}

static inline bool cpu_has_vmx_virtual_intr_delivery(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY;
}

static inline bool cpu_has_vmx_posted_intr(void)
{
	return IS_ENABLED(CONFIG_X86_LOCAL_APIC) &&
		vmcs_config.pin_based_exec_ctrl & PIN_BASED_POSTED_INTR;
}

static inline bool cpu_has_vmx_apicv(void)
{
	return cpu_has_vmx_apic_register_virt() &&
		cpu_has_vmx_virtual_intr_delivery() &&
		cpu_has_vmx_posted_intr();
}

static inline bool cpu_has_vmx_flexpriority(void)
{
	return cpu_has_vmx_tpr_shadow() &&
		cpu_has_vmx_virtualize_apic_accesses();
}

static inline bool cpu_has_vmx_ept_execute_only(void)
{
	return vmx_capability.ept & VMX_EPT_EXECUTE_ONLY_BIT;
}

static inline bool cpu_has_vmx_ept_2m_page(void)
{
	return vmx_capability.ept & VMX_EPT_2MB_PAGE_BIT;
}

static inline bool cpu_has_vmx_ept_1g_page(void)
{
	return vmx_capability.ept & VMX_EPT_1GB_PAGE_BIT;
}

static inline bool cpu_has_vmx_ept_4levels(void)
{
	return vmx_capability.ept & VMX_EPT_PAGE_WALK_4_BIT;
}

static inline bool cpu_has_vmx_ept_ad_bits(void)
{
	return vmx_capability.ept & VMX_EPT_AD_BIT;
}

static inline bool cpu_has_vmx_invept_context(void)
{
	return vmx_capability.ept & VMX_EPT_EXTENT_CONTEXT_BIT;
}

static inline bool cpu_has_vmx_invept_global(void)
{
	return vmx_capability.ept & VMX_EPT_EXTENT_GLOBAL_BIT;
}

static inline bool cpu_has_vmx_invvpid_single(void)
{
	return vmx_capability.vpid & VMX_VPID_EXTENT_SINGLE_CONTEXT_BIT;
}

static inline bool cpu_has_vmx_invvpid_global(void)
{
	return vmx_capability.vpid & VMX_VPID_EXTENT_GLOBAL_CONTEXT_BIT;
}

static inline bool cpu_has_vmx_ept(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_EPT;
}

static inline bool cpu_has_vmx_unrestricted_guest(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_UNRESTRICTED_GUEST;
}

static inline bool cpu_has_vmx_ple(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_PAUSE_LOOP_EXITING;
}

static inline bool cpu_need_virtualize_apic_accesses(struct kvm_vcpu *vcpu)
{
	return flexpriority_enabled && lapic_in_kernel(vcpu);
}

static inline bool cpu_has_vmx_vpid(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_VPID;
}

static inline bool cpu_has_vmx_rdtscp(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_RDTSCP;
}

static inline bool cpu_has_vmx_invpcid(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_INVPCID;
}

static inline bool cpu_has_virtual_nmis(void)
{
	return vmcs_config.pin_based_exec_ctrl & PIN_BASED_VIRTUAL_NMIS;
}

static inline bool cpu_has_vmx_wbinvd_exit(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_WBINVD_EXITING;
}

static inline bool cpu_has_vmx_shadow_vmcs(void)
{
	u64 vmx_msr;
	rdmsrl(MSR_IA32_VMX_MISC, vmx_msr);
	/* check if the cpu supports writing r/o exit information fields */
	if (!(vmx_msr & MSR_IA32_VMX_MISC_VMWRITE_SHADOW_RO_FIELDS))
		return false;

	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_SHADOW_VMCS;
}

static inline bool cpu_has_vmx_pml(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl & SECONDARY_EXEC_ENABLE_PML;
}

static inline bool cpu_has_vmx_tsc_scaling(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_TSC_SCALING;
}

static inline bool report_flexpriority(void)
{
	return flexpriority_enabled;
}

static inline bool nested_cpu_has(struct vmcs12 *vmcs12, u32 bit)
{
	return vmcs12->cpu_based_vm_exec_control & bit;
}

static inline bool nested_cpu_has2(struct vmcs12 *vmcs12, u32 bit)
{
	return (vmcs12->cpu_based_vm_exec_control &
			CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) &&
		(vmcs12->secondary_vm_exec_control & bit);
}

static inline bool nested_cpu_has_virtual_nmis(struct vmcs12 *vmcs12)
{
	return vmcs12->pin_based_vm_exec_control & PIN_BASED_VIRTUAL_NMIS;
}

static inline bool nested_cpu_has_preemption_timer(struct vmcs12 *vmcs12)
{
	return vmcs12->pin_based_vm_exec_control &
		PIN_BASED_VMX_PREEMPTION_TIMER;
}

static inline int nested_cpu_has_ept(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_ENABLE_EPT);
}

static inline bool nested_cpu_has_xsaves(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_XSAVES) &&
		vmx_xsaves_supported();
}

static inline bool nested_cpu_has_virt_x2apic_mode(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE);
}

static inline bool nested_cpu_has_vpid(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_ENABLE_VPID);
}

static inline bool nested_cpu_has_apic_reg_virt(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_APIC_REGISTER_VIRT);
}

static inline bool nested_cpu_has_vid(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY);
}

static inline bool nested_cpu_has_posted_intr(struct vmcs12 *vmcs12)
{
	return vmcs12->pin_based_vm_exec_control & PIN_BASED_POSTED_INTR;
}

static inline bool is_exception(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VALID_MASK))
		== (INTR_TYPE_HARD_EXCEPTION | INTR_INFO_VALID_MASK);
}

static void nested_vmx_vmexit(struct kvm_vcpu *vcpu, u32 exit_reason,
			      u32 exit_intr_info,
			      unsigned long exit_qualification);
static void nested_vmx_entry_failure(struct kvm_vcpu *vcpu,
			struct vmcs12 *vmcs12,
			u32 reason, unsigned long qualification);

static int __find_msr_index(struct vcpu_vmx *vmx, u32 msr)
{
	int i;

	for (i = 0; i < vmx->nmsrs; ++i)
		if (vmx_msr_index[vmx->guest_msrs[i].index] == msr)
			return i;
	return -1;
}

static inline void __invvpid(int ext, u16 vpid, gva_t gva)
{
    struct {
	u64 vpid : 16;
	u64 rsvd : 48;
	u64 gva;
    } operand = { vpid, 0, gva };

    asm volatile (__ex(ASM_VMX_INVVPID)
		  /* CF==1 or ZF==1 --> rc = -1 */
		  "; ja 1f ; ud2 ; 1:"
		  : : "a"(&operand), "c"(ext) : "cc", "memory");
}

static inline void __invept(int ext, u64 eptp, gpa_t gpa)
{
	struct {
		u64 eptp, gpa;
	} operand = {eptp, gpa};

	asm volatile (__ex(ASM_VMX_INVEPT)
			/* CF==1 or ZF==1 --> rc = -1 */
			"; ja 1f ; ud2 ; 1:\n"
			: : "a" (&operand), "c" (ext) : "cc", "memory");
}

static struct shared_msr_entry *find_msr_entry(struct vcpu_vmx *vmx, u32 msr)
{
	int i;

	i = __find_msr_index(vmx, msr);
	if (i >= 0)
		return &vmx->guest_msrs[i];
	return NULL;
}

static void vmcs_clear(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (__ex(ASM_VMX_VMCLEAR_RAX) "; setna %0"
		      : "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
		      : "cc", "memory");
	if (error)
		printk(KERN_ERR "kvm: vmclear fail: %p/%llx\n",
		       vmcs, phys_addr);
}

static inline void loaded_vmcs_init(struct loaded_vmcs *loaded_vmcs)
{
	vmcs_clear(loaded_vmcs->vmcs);
	loaded_vmcs->cpu = -1;
	loaded_vmcs->launched = 0;
}

static void vmcs_load(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (__ex(ASM_VMX_VMPTRLD_RAX) "; setna %0"
			: "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
			: "cc", "memory");
	if (error)
		printk(KERN_ERR "kvm: vmptrld %p/%llx failed\n",
		       vmcs, phys_addr);
}

#ifdef CONFIG_KEXEC_CORE
/*
 * This bitmap is used to indicate whether the vmclear
 * operation is enabled on all cpus. All disabled by
 * default.
 */
static cpumask_t crash_vmclear_enabled_bitmap = CPU_MASK_NONE;

static inline void crash_enable_local_vmclear(int cpu)
{
	cpumask_set_cpu(cpu, &crash_vmclear_enabled_bitmap);
}

static inline void crash_disable_local_vmclear(int cpu)
{
	cpumask_clear_cpu(cpu, &crash_vmclear_enabled_bitmap);
}

static inline int crash_local_vmclear_enabled(int cpu)
{
	return cpumask_test_cpu(cpu, &crash_vmclear_enabled_bitmap);
}

static void crash_vmclear_local_loaded_vmcss(void)
{
	int cpu = raw_smp_processor_id();
	struct loaded_vmcs *v;

	if (!crash_local_vmclear_enabled(cpu))
		return;

	list_for_each_entry(v, &per_cpu(loaded_vmcss_on_cpu, cpu),
			    loaded_vmcss_on_cpu_link)
		vmcs_clear(v->vmcs);
}
#else
static inline void crash_enable_local_vmclear(int cpu) { }
static inline void crash_disable_local_vmclear(int cpu) { }
#endif /* CONFIG_KEXEC_CORE */

static void __loaded_vmcs_clear(void *arg)
{
	struct loaded_vmcs *loaded_vmcs = arg;
	int cpu = raw_smp_processor_id();

	if (loaded_vmcs->cpu != cpu)
		return; /* vcpu migration can race with cpu offline */
	if (per_cpu(current_vmcs, cpu) == loaded_vmcs->vmcs)
		per_cpu(current_vmcs, cpu) = NULL;
	crash_disable_local_vmclear(cpu);
	list_del(&loaded_vmcs->loaded_vmcss_on_cpu_link);

	/*
 * we should ensure updating loaded_vmcs->loaded_vmcss_on_cpu_link
 * is before setting loaded_vmcs->vcpu to -1 which is done in
 * loaded_vmcs_init. Otherwise, other cpu can see vcpu = -1 fist
 * then adds the vmcs into percpu list before it is deleted.
 */
	smp_wmb();

	loaded_vmcs_init(loaded_vmcs);
	crash_enable_local_vmclear(cpu);
}

static void loaded_vmcs_clear(struct loaded_vmcs *loaded_vmcs)
{
	int cpu = loaded_vmcs->cpu;

	if (cpu != -1)
		smp_call_function_single(cpu,
			 __loaded_vmcs_clear, loaded_vmcs, 1);
}

static inline void vpid_sync_vcpu_single(int vpid)
{
	if (vpid == 0)
		return;

	if (cpu_has_vmx_invvpid_single())
		__invvpid(VMX_VPID_EXTENT_SINGLE_CONTEXT, vpid, 0);
}

static inline void vpid_sync_vcpu_global(void)
{
	if (cpu_has_vmx_invvpid_global())
		__invvpid(VMX_VPID_EXTENT_ALL_CONTEXT, 0, 0);
}

static inline void vpid_sync_context(int vpid)
{
	if (cpu_has_vmx_invvpid_single())
		vpid_sync_vcpu_single(vpid);
	else
		vpid_sync_vcpu_global();
}

static inline void ept_sync_global(void)
{
	if (cpu_has_vmx_invept_global())
		__invept(VMX_EPT_EXTENT_GLOBAL, 0, 0);
}

static inline void ept_sync_context(u64 eptp)
{
	if (enable_ept) {
		if (cpu_has_vmx_invept_context())
			__invept(VMX_EPT_EXTENT_CONTEXT, eptp, 0);
		else
			ept_sync_global();
	}
}

static __always_inline void vmcs_check16(unsigned long field)
{
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6001) == 0x2000,
			 "16-bit accessor invalid for 64-bit field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6001) == 0x2001,
			 "16-bit accessor invalid for 64-bit high field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x4000,
			 "16-bit accessor invalid for 32-bit high field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x6000,
			 "16-bit accessor invalid for natural width field");
}

static __always_inline void vmcs_check32(unsigned long field)
{
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0,
			 "32-bit accessor invalid for 16-bit field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x6000,
			 "32-bit accessor invalid for natural width field");
}

static __always_inline void vmcs_check64(unsigned long field)
{
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0,
			 "64-bit accessor invalid for 16-bit field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6001) == 0x2001,
			 "64-bit accessor invalid for 64-bit high field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x4000,
			 "64-bit accessor invalid for 32-bit field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x6000,
			 "64-bit accessor invalid for natural width field");
}

static __always_inline void vmcs_checkl(unsigned long field)
{
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0,
			 "Natural width accessor invalid for 16-bit field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6001) == 0x2000,
			 "Natural width accessor invalid for 64-bit field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6001) == 0x2001,
			 "Natural width accessor invalid for 64-bit high field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x4000,
			 "Natural width accessor invalid for 32-bit field");
}

static __always_inline unsigned long __vmcs_readl(unsigned long field)
{
	unsigned long value;

	asm volatile (__ex_clear(ASM_VMX_VMREAD_RDX_RAX, "%0")
		      : "=a"(value) : "d"(field) : "cc");
	return value;
}

static __always_inline u16 vmcs_read16(unsigned long field)
{
	vmcs_check16(field);
	return __vmcs_readl(field);
}

static __always_inline u32 vmcs_read32(unsigned long field)
{
	vmcs_check32(field);
	return __vmcs_readl(field);
}

static __always_inline u64 vmcs_read64(unsigned long field)
{
	vmcs_check64(field);
#ifdef CONFIG_X86_64
	return __vmcs_readl(field);
#else
	return __vmcs_readl(field) | ((u64)__vmcs_readl(field+1) << 32);
#endif
}

static __always_inline unsigned long vmcs_readl(unsigned long field)
{
	vmcs_checkl(field);
	return __vmcs_readl(field);
}

static noinline void vmwrite_error(unsigned long field, unsigned long value)
{
	printk(KERN_ERR "vmwrite error: reg %lx value %lx (err %d)\n",
	       field, value, vmcs_read32(VM_INSTRUCTION_ERROR));
	dump_stack();
}

static __always_inline void __vmcs_writel(unsigned long field, unsigned long value)
{
	u8 error;

	asm volatile (__ex(ASM_VMX_VMWRITE_RAX_RDX) "; setna %0"
		       : "=q"(error) : "a"(value), "d"(field) : "cc");
	if (unlikely(error))
		vmwrite_error(field, value);
}

static __always_inline void vmcs_write16(unsigned long field, u16 value)
{
	vmcs_check16(field);
	__vmcs_writel(field, value);
}

static __always_inline void vmcs_write32(unsigned long field, u32 value)
{
	vmcs_check32(field);
	__vmcs_writel(field, value);
}

static __always_inline void vmcs_write64(unsigned long field, u64 value)
{
	vmcs_check64(field);
	__vmcs_writel(field, value);
#ifndef CONFIG_X86_64
	asm volatile ("");
	__vmcs_writel(field+1, value >> 32);
#endif
}

static __always_inline void vmcs_writel(unsigned long field, unsigned long value)
{
	vmcs_checkl(field);
	__vmcs_writel(field, value);
}

static __always_inline void vmcs_clear_bits(unsigned long field, u32 mask)
{
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x2000,
			 "vmcs_clear_bits does not support 64-bit fields");
	__vmcs_writel(field, __vmcs_readl(field) & ~mask);
}

static __always_inline void vmcs_set_bits(unsigned long field, u32 mask)
{
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x2000,
			 "vmcs_set_bits does not support 64-bit fields");
	__vmcs_writel(field, __vmcs_readl(field) | mask);
}

static inline void vm_entry_controls_init(struct vcpu_vmx *vmx, u32 val)
{
	vmcs_write32(VM_ENTRY_CONTROLS, val);
	vmx->vm_entry_controls_shadow = val;
}

static inline void vm_entry_controls_set(struct vcpu_vmx *vmx, u32 val)
{
	if (vmx->vm_entry_controls_shadow != val)
		vm_entry_controls_init(vmx, val);
}

static inline u32 vm_entry_controls_get(struct vcpu_vmx *vmx)
{
	return vmx->vm_entry_controls_shadow;
}


static inline void vm_entry_controls_setbit(struct vcpu_vmx *vmx, u32 val)
{
	vm_entry_controls_set(vmx, vm_entry_controls_get(vmx) | val);
}

static inline void vm_entry_controls_clearbit(struct vcpu_vmx *vmx, u32 val)
{
	vm_entry_controls_set(vmx, vm_entry_controls_get(vmx) & ~val);
}

static inline void vm_exit_controls_init(struct vcpu_vmx *vmx, u32 val)
{
	vmcs_write32(VM_EXIT_CONTROLS, val);
	vmx->vm_exit_controls_shadow = val;
}

static inline void vm_exit_controls_set(struct vcpu_vmx *vmx, u32 val)
{
	if (vmx->vm_exit_controls_shadow != val)
		vm_exit_controls_init(vmx, val);
}

static inline u32 vm_exit_controls_get(struct vcpu_vmx *vmx)
{
	return vmx->vm_exit_controls_shadow;
}


static inline void vm_exit_controls_setbit(struct vcpu_vmx *vmx, u32 val)
{
	vm_exit_controls_set(vmx, vm_exit_controls_get(vmx) | val);
}

static inline void vm_exit_controls_clearbit(struct vcpu_vmx *vmx, u32 val)
{
	vm_exit_controls_set(vmx, vm_exit_controls_get(vmx) & ~val);
}

static void vmx_segment_cache_clear(struct vcpu_vmx *vmx)
{
	vmx->segment_cache.bitmask = 0;
}

static bool vmx_segment_cache_test_set(struct vcpu_vmx *vmx, unsigned seg,
				       unsigned field)
{
	bool ret;
	u32 mask = 1 << (seg * SEG_FIELD_NR + field);

	if (!(vmx->vcpu.arch.regs_avail & (1 << VCPU_EXREG_SEGMENTS))) {
		vmx->vcpu.arch.regs_avail |= (1 << VCPU_EXREG_SEGMENTS);
		vmx->segment_cache.bitmask = 0;
	}
	ret = vmx->segment_cache.bitmask & mask;
	vmx->segment_cache.bitmask |= mask;
	return ret;
}

static u16 vmx_read_guest_seg_selector(struct vcpu_vmx *vmx, unsigned seg)
{
	u16 *p = &vmx->segment_cache.seg[seg].selector;

	if (!vmx_segment_cache_test_set(vmx, seg, SEG_FIELD_SEL))
		*p = vmcs_read16(kvm_vmx_segment_fields[seg].selector);
	return *p;
}

static ulong vmx_read_guest_seg_base(struct vcpu_vmx *vmx, unsigned seg)
{
	ulong *p = &vmx->segment_cache.seg[seg].base;

	if (!vmx_segment_cache_test_set(vmx, seg, SEG_FIELD_BASE))
		*p = vmcs_readl(kvm_vmx_segment_fields[seg].base);
	return *p;
}

static u32 vmx_read_guest_seg_limit(struct vcpu_vmx *vmx, unsigned seg)
{
	u32 *p = &vmx->segment_cache.seg[seg].limit;

	if (!vmx_segment_cache_test_set(vmx, seg, SEG_FIELD_LIMIT))
		*p = vmcs_read32(kvm_vmx_segment_fields[seg].limit);
	return *p;
}

static u32 vmx_read_guest_seg_ar(struct vcpu_vmx *vmx, unsigned seg)
{
	u32 *p = &vmx->segment_cache.seg[seg].ar;

	if (!vmx_segment_cache_test_set(vmx, seg, SEG_FIELD_AR))
		*p = vmcs_read32(kvm_vmx_segment_fields[seg].ar_bytes);
	return *p;
}

static void update_exception_bitmap(struct kvm_vcpu *vcpu)
{
	u32 eb;

	eb = (1u << PF_VECTOR) | (1u << UD_VECTOR) | (1u << MC_VECTOR) |
	     (1u << NM_VECTOR) | (1u << DB_VECTOR) | (1u << AC_VECTOR);
	if ((vcpu->guest_debug &
	     (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP)) ==
	    (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP))
		eb |= 1u << BP_VECTOR;
	if (to_vmx(vcpu)->rmode.vm86_active)
		eb = ~0;
	if (enable_ept)
		eb &= ~(1u << PF_VECTOR); /* bypass_guest_pf = 0 */
	if (vcpu->fpu_active)
		eb &= ~(1u << NM_VECTOR);

	/* When we are running a nested L2 guest and L1 specified for it a
 * certain exception bitmap, we must trap the same exceptions and pass
 * them to L1. When running L2, we will only handle the exceptions
 * specified above if L1 did not want them.
 */
	if (is_guest_mode(vcpu))
		eb |= get_vmcs12(vcpu)->exception_bitmap;

	vmcs_write32(EXCEPTION_BITMAP, eb);
}

static void clear_atomic_switch_msr_special(struct vcpu_vmx *vmx,
		unsigned long entry, unsigned long exit)
{
	vm_entry_controls_clearbit(vmx, entry);
	vm_exit_controls_clearbit(vmx, exit);
}

static void clear_atomic_switch_msr(struct vcpu_vmx *vmx, unsigned msr)
{
	unsigned i;
	struct msr_autoload *m = &vmx->msr_autoload;

	switch (msr) {
	case MSR_EFER:
		if (cpu_has_load_ia32_efer) {
			clear_atomic_switch_msr_special(vmx,
					VM_ENTRY_LOAD_IA32_EFER,
					VM_EXIT_LOAD_IA32_EFER);
			return;
		}
		break;
	case MSR_CORE_PERF_GLOBAL_CTRL:
		if (cpu_has_load_perf_global_ctrl) {
			clear_atomic_switch_msr_special(vmx,
					VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL,
					VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL);
			return;
		}
		break;
	}

	for (i = 0; i < m->nr; ++i)
		if (m->guest[i].index == msr)
			break;

	if (i == m->nr)
		return;
	--m->nr;
	m->guest[i] = m->guest[m->nr];
	m->host[i] = m->host[m->nr];
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, m->nr);
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, m->nr);
}

static void add_atomic_switch_msr_special(struct vcpu_vmx *vmx,
		unsigned long entry, unsigned long exit,
		unsigned long guest_val_vmcs, unsigned long host_val_vmcs,
		u64 guest_val, u64 host_val)
{
	vmcs_write64(guest_val_vmcs, guest_val);
	vmcs_write64(host_val_vmcs, host_val);
	vm_entry_controls_setbit(vmx, entry);
	vm_exit_controls_setbit(vmx, exit);
}

static void add_atomic_switch_msr(struct vcpu_vmx *vmx, unsigned msr,
				  u64 guest_val, u64 host_val)
{
	unsigned i;
	struct msr_autoload *m = &vmx->msr_autoload;

	switch (msr) {
	case MSR_EFER:
		if (cpu_has_load_ia32_efer) {
			add_atomic_switch_msr_special(vmx,
					VM_ENTRY_LOAD_IA32_EFER,
					VM_EXIT_LOAD_IA32_EFER,
					GUEST_IA32_EFER,
					HOST_IA32_EFER,
					guest_val, host_val);
			return;
		}
		break;
	case MSR_CORE_PERF_GLOBAL_CTRL:
		if (cpu_has_load_perf_global_ctrl) {
			add_atomic_switch_msr_special(vmx,
					VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL,
					VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL,
					GUEST_IA32_PERF_GLOBAL_CTRL,
					HOST_IA32_PERF_GLOBAL_CTRL,
					guest_val, host_val);
			return;
		}
		break;
	case MSR_IA32_PEBS_ENABLE:
		/* PEBS needs a quiescent period after being disabled (to write
 * a record). Disabling PEBS through VMX MSR swapping doesn't
 * provide that period, so a CPU could write host's record into
 * guest's memory.
 */
		wrmsrl(MSR_IA32_PEBS_ENABLE, 0);
	}

	for (i = 0; i < m->nr; ++i)
		if (m->guest[i].index == msr)
			break;

	if (i == NR_AUTOLOAD_MSRS) {
		printk_once(KERN_WARNING "Not enough msr switch entries. "
				"Can't add msr %x\n", msr);
		return;
	} else if (i == m->nr) {
		++m->nr;
		vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, m->nr);
		vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, m->nr);
	}

	m->guest[i].index = msr;
	m->guest[i].value = guest_val;
	m->host[i].index = msr;
	m->host[i].value = host_val;
}

static void reload_tss(void)
{
	/*
 * VT restores TR but not its size. Useless.
 */
	struct desc_ptr *gdt = this_cpu_ptr(&host_gdt);
	struct desc_struct *descs;

	descs = (void *)gdt->address;
	descs[GDT_ENTRY_TSS].type = 9; /* available TSS */
	load_TR_desc();
}

static bool update_transition_efer(struct vcpu_vmx *vmx, int efer_offset)
{
	u64 guest_efer = vmx->vcpu.arch.efer;
	u64 ignore_bits = 0;

	if (!enable_ept) {
		/*
 * NX is needed to handle CR0.WP=1, CR4.SMEP=1. Testing
 * host CPUID is more efficient than testing guest CPUID
 * or CR4. Host SMEP is anyway a requirement for guest SMEP.
 */
		if (boot_cpu_has(X86_FEATURE_SMEP))
			guest_efer |= EFER_NX;
		else if (!(guest_efer & EFER_NX))
			ignore_bits |= EFER_NX;
	}

	/*
 * LMA and LME handled by hardware; SCE meaningless outside long mode.
 */
	ignore_bits |= EFER_SCE;
#ifdef CONFIG_X86_64
	ignore_bits |= EFER_LMA | EFER_LME;
	/* SCE is meaningful only in long mode on Intel */
	if (guest_efer & EFER_LMA)
		ignore_bits &= ~(u64)EFER_SCE;
#endif

	clear_atomic_switch_msr(vmx, MSR_EFER);

	/*
 * On EPT, we can't emulate NX, so we must switch EFER atomically.
 * On CPUs that support "load IA32_EFER", always switch EFER
 * atomically, since it's faster than switching it manually.
 */
	if (cpu_has_load_ia32_efer ||
	    (enable_ept && ((vmx->vcpu.arch.efer ^ host_efer) & EFER_NX))) {
		if (!(guest_efer & EFER_LMA))
			guest_efer &= ~EFER_LME;
		if (guest_efer != host_efer)
			add_atomic_switch_msr(vmx, MSR_EFER,
					      guest_efer, host_efer);
		return false;
	} else {
		guest_efer &= ~ignore_bits;
		guest_efer |= host_efer & ignore_bits;

		vmx->guest_msrs[efer_offset].data = guest_efer;
		vmx->guest_msrs[efer_offset].mask = ~ignore_bits;

		return true;
	}
}

static unsigned long segment_base(u16 selector)
{
	struct desc_ptr *gdt = this_cpu_ptr(&host_gdt);
	struct desc_struct *d;
	unsigned long table_base;
	unsigned long v;

	if (!(selector & ~3))
		return 0;

	table_base = gdt->address;

	if (selector & 4) {           /* from ldt */
		u16 ldt_selector = kvm_read_ldt();

		if (!(ldt_selector & ~3))
			return 0;

		table_base = segment_base(ldt_selector);
	}
	d = (struct desc_struct *)(table_base + (selector & ~7));
	v = get_desc_base(d);
#ifdef CONFIG_X86_64
       if (d->s == 0 && (d->type == 2 || d->type == 9 || d->type == 11))
               v |= ((unsigned long)((struct ldttss_desc64 *)d)->base3) << 32;
#endif
	return v;
}

static inline unsigned long kvm_read_tr_base(void)
{
	u16 tr;
	asm("str %0" : "=g"(tr));
	return segment_base(tr);
}

static void vmx_save_host_state(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int i;

	if (vmx->host_state.loaded)
		return;

	vmx->host_state.loaded = 1;
	/*
 * Set host fs and gs selectors. Unfortunately, 22.2.3 does not
 * allow segment selectors with cpl > 0 or ti == 1.
 */
	vmx->host_state.ldt_sel = kvm_read_ldt();
	vmx->host_state.gs_ldt_reload_needed = vmx->host_state.ldt_sel;
	savesegment(fs, vmx->host_state.fs_sel);
	if (!(vmx->host_state.fs_sel & 7)) {
		vmcs_write16(HOST_FS_SELECTOR, vmx->host_state.fs_sel);
		vmx->host_state.fs_reload_needed = 0;
	} else {
		vmcs_write16(HOST_FS_SELECTOR, 0);
		vmx->host_state.fs_reload_needed = 1;
	}
	savesegment(gs, vmx->host_state.gs_sel);
	if (!(vmx->host_state.gs_sel & 7))
		vmcs_write16(HOST_GS_SELECTOR, vmx->host_state.gs_sel);
	else {
		vmcs_write16(HOST_GS_SELECTOR, 0);
		vmx->host_state.gs_ldt_reload_needed = 1;
	}

#ifdef CONFIG_X86_64
	savesegment(ds, vmx->host_state.ds_sel);
	savesegment(es, vmx->host_state.es_sel);
#endif

#ifdef CONFIG_X86_64
	vmcs_writel(HOST_FS_BASE, read_msr(MSR_FS_BASE));
	vmcs_writel(HOST_GS_BASE, read_msr(MSR_GS_BASE));
#else
	vmcs_writel(HOST_FS_BASE, segment_base(vmx->host_state.fs_sel));
	vmcs_writel(HOST_GS_BASE, segment_base(vmx->host_state.gs_sel));
#endif

#ifdef CONFIG_X86_64
	rdmsrl(MSR_KERNEL_GS_BASE, vmx->msr_host_kernel_gs_base);
	if (is_long_mode(&vmx->vcpu))
		wrmsrl(MSR_KERNEL_GS_BASE, vmx->msr_guest_kernel_gs_base);
#endif
	if (boot_cpu_has(X86_FEATURE_MPX))
		rdmsrl(MSR_IA32_BNDCFGS, vmx->host_state.msr_host_bndcfgs);
	for (i = 0; i < vmx->save_nmsrs; ++i)
		kvm_set_shared_msr(vmx->guest_msrs[i].index,
				   vmx->guest_msrs[i].data,
				   vmx->guest_msrs[i].mask);
}

static void __vmx_load_host_state(struct vcpu_vmx *vmx)
{
	if (!vmx->host_state.loaded)
		return;

	++vmx->vcpu.stat.host_state_reload;
	vmx->host_state.loaded = 0;
#ifdef CONFIG_X86_64
	if (is_long_mode(&vmx->vcpu))
		rdmsrl(MSR_KERNEL_GS_BASE, vmx->msr_guest_kernel_gs_base);
#endif
	if (vmx->host_state.gs_ldt_reload_needed) {
		kvm_load_ldt(vmx->host_state.ldt_sel);
#ifdef CONFIG_X86_64
		load_gs_index(vmx->host_state.gs_sel);
#else
		loadsegment(gs, vmx->host_state.gs_sel);
#endif
	}
	if (vmx->host_state.fs_reload_needed)
		loadsegment(fs, vmx->host_state.fs_sel);
#ifdef CONFIG_X86_64
	if (unlikely(vmx->host_state.ds_sel | vmx->host_state.es_sel)) {
		loadsegment(ds, vmx->host_state.ds_sel);
		loadsegment(es, vmx->host_state.es_sel);
	}
#endif
	reload_tss();
#ifdef CONFIG_X86_64
	wrmsrl(MSR_KERNEL_GS_BASE, vmx->msr_host_kernel_gs_base);
#endif
	if (vmx->host_state.msr_host_bndcfgs)
		wrmsrl(MSR_IA32_BNDCFGS, vmx->host_state.msr_host_bndcfgs);
	/*
 * If the FPU is not active (through the host task or
 * the guest vcpu), then restore the cr0.TS bit.
 */
	if (!fpregs_active() && !vmx->vcpu.guest_fpu_loaded)
		stts();
	load_gdt(this_cpu_ptr(&host_gdt));
}

static void vmx_load_host_state(struct vcpu_vmx *vmx)
{
	preempt_disable();
	__vmx_load_host_state(vmx);
	preempt_enable();
}

static void vmx_vcpu_pi_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct pi_desc *pi_desc = vcpu_to_pi_desc(vcpu);
	struct pi_desc old, new;
	unsigned int dest;

	if (!kvm_arch_has_assigned_device(vcpu->kvm) ||
		!irq_remapping_cap(IRQ_POSTING_CAP))
		return;

	do {
		old.control = new.control = pi_desc->control;

		/*
 * If 'nv' field is POSTED_INTR_WAKEUP_VECTOR, there
 * are two possible cases:
 * 1. After running 'pre_block', context switch
 * happened. For this case, 'sn' was set in
 * vmx_vcpu_put(), so we need to clear it here.
 * 2. After running 'pre_block', we were blocked,
 * and woken up by some other guy. For this case,
 * we don't need to do anything, 'pi_post_block'
 * will do everything for us. However, we cannot
 * check whether it is case #1 or case #2 here
 * (maybe, not needed), so we also clear sn here,
 * I think it is not a big deal.
 */
		if (pi_desc->nv != POSTED_INTR_WAKEUP_VECTOR) {
			if (vcpu->cpu != cpu) {
				dest = cpu_physical_id(cpu);

				if (x2apic_enabled())
					new.ndst = dest;
				else
					new.ndst = (dest << 8) & 0xFF00;
			}

			/* set 'NV' to 'notification vector' */
			new.nv = POSTED_INTR_VECTOR;
		}

		/* Allow posting non-urgent interrupts */
		new.sn = 0;
	} while (cmpxchg(&pi_desc->control, old.control,
			new.control) != old.control);
}

/*
 * Switches to specified vcpu, until a matching vcpu_put(), but assumes
 * vcpu mutex is already taken.
 */
static void vmx_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u64 phys_addr = __pa(per_cpu(vmxarea, cpu));

	if (!vmm_exclusive)
		kvm_cpu_vmxon(phys_addr);
	else if (vmx->loaded_vmcs->cpu != cpu)
		loaded_vmcs_clear(vmx->loaded_vmcs);

	if (per_cpu(current_vmcs, cpu) != vmx->loaded_vmcs->vmcs) {
		per_cpu(current_vmcs, cpu) = vmx->loaded_vmcs->vmcs;
		vmcs_load(vmx->loaded_vmcs->vmcs);
	}

	if (vmx->loaded_vmcs->cpu != cpu) {
		struct desc_ptr *gdt = this_cpu_ptr(&host_gdt);
		unsigned long sysenter_esp;

		kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
		local_irq_disable();
		crash_disable_local_vmclear(cpu);

		/*
 * Read loaded_vmcs->cpu should be before fetching
 * loaded_vmcs->loaded_vmcss_on_cpu_link.
 * See the comments in __loaded_vmcs_clear().
 */
		smp_rmb();

		list_add(&vmx->loaded_vmcs->loaded_vmcss_on_cpu_link,
			 &per_cpu(loaded_vmcss_on_cpu, cpu));
		crash_enable_local_vmclear(cpu);
		local_irq_enable();

		/*
 * Linux uses per-cpu TSS and GDT, so set these when switching
 * processors.
 */
		vmcs_writel(HOST_TR_BASE, kvm_read_tr_base()); /* 22.2.4 */
		vmcs_writel(HOST_GDTR_BASE, gdt->address);   /* 22.2.4 */

		rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
		vmcs_writel(HOST_IA32_SYSENTER_ESP, sysenter_esp); /* 22.2.3 */

		vmx->loaded_vmcs->cpu = cpu;
	}

	/* Setup TSC multiplier */
	if (kvm_has_tsc_control &&
	    vmx->current_tsc_ratio != vcpu->arch.tsc_scaling_ratio) {
		vmx->current_tsc_ratio = vcpu->arch.tsc_scaling_ratio;
		vmcs_write64(TSC_MULTIPLIER, vmx->current_tsc_ratio);
	}

	vmx_vcpu_pi_load(vcpu, cpu);
	vmx->host_pkru = read_pkru();
}

static void vmx_vcpu_pi_put(struct kvm_vcpu *vcpu)
{
	struct pi_desc *pi_desc = vcpu_to_pi_desc(vcpu);

	if (!kvm_arch_has_assigned_device(vcpu->kvm) ||
		!irq_remapping_cap(IRQ_POSTING_CAP))
		return;

	/* Set SN when the vCPU is preempted */
	if (vcpu->preempted)
		pi_set_sn(pi_desc);
}

static void vmx_vcpu_put(struct kvm_vcpu *vcpu)
{
	vmx_vcpu_pi_put(vcpu);

	__vmx_load_host_state(to_vmx(vcpu));
	if (!vmm_exclusive) {
		__loaded_vmcs_clear(to_vmx(vcpu)->loaded_vmcs);
		vcpu->cpu = -1;
		kvm_cpu_vmxoff();
	}
}

static void vmx_fpu_activate(struct kvm_vcpu *vcpu)
{
	ulong cr0;

	if (vcpu->fpu_active)
		return;
	vcpu->fpu_active = 1;
	cr0 = vmcs_readl(GUEST_CR0);
	cr0 &= ~(X86_CR0_TS | X86_CR0_MP);
	cr0 |= kvm_read_cr0_bits(vcpu, X86_CR0_TS | X86_CR0_MP);
	vmcs_writel(GUEST_CR0, cr0);
	update_exception_bitmap(vcpu);
	vcpu->arch.cr0_guest_owned_bits = X86_CR0_TS;
	if (is_guest_mode(vcpu))
		vcpu->arch.cr0_guest_owned_bits &=
			~get_vmcs12(vcpu)->cr0_guest_host_mask;
	vmcs_writel(CR0_GUEST_HOST_MASK, ~vcpu->arch.cr0_guest_owned_bits);
}

static void vmx_decache_cr0_guest_bits(struct kvm_vcpu *vcpu);

/*
 * Return the cr0 value that a nested guest would read. This is a combination
 * of the real cr0 used to run the guest (guest_cr0), and the bits shadowed by
 * its hypervisor (cr0_read_shadow).
 */
static inline unsigned long nested_read_cr0(struct vmcs12 *fields)
{
	return (fields->guest_cr0 & ~fields->cr0_guest_host_mask) |
		(fields->cr0_read_shadow & fields->cr0_guest_host_mask);
}
static inline unsigned long nested_read_cr4(struct vmcs12 *fields)
{
	return (fields->guest_cr4 & ~fields->cr4_guest_host_mask) |
		(fields->cr4_read_shadow & fields->cr4_guest_host_mask);
}

static void vmx_fpu_deactivate(struct kvm_vcpu *vcpu)
{
	/* Note that there is no vcpu->fpu_active = 0 here. The caller must
 * set this *before* calling this function.
 */
	vmx_decache_cr0_guest_bits(vcpu);
	vmcs_set_bits(GUEST_CR0, X86_CR0_TS | X86_CR0_MP);
	update_exception_bitmap(vcpu);
	vcpu->arch.cr0_guest_owned_bits = 0;
	vmcs_writel(CR0_GUEST_HOST_MASK, ~vcpu->arch.cr0_guest_owned_bits);
	if (is_guest_mode(vcpu)) {
		/*
 * L1's specified read shadow might not contain the TS bit,
 * so now that we turned on shadowing of this bit, we need to
 * set this bit of the shadow. Like in nested_vmx_run we need
 * nested_read_cr0(vmcs12), but vmcs12->guest_cr0 is not yet
 * up-to-date here because we just decached cr0.TS (and we'll
 * only update vmcs12->guest_cr0 on nested exit).
 */
		struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
		vmcs12->guest_cr0 = (vmcs12->guest_cr0 & ~X86_CR0_TS) |
			(vcpu->arch.cr0 & X86_CR0_TS);
		vmcs_writel(CR0_READ_SHADOW, nested_read_cr0(vmcs12));
	} else
		vmcs_writel(CR0_READ_SHADOW, vcpu->arch.cr0);
}

static unsigned long vmx_get_rflags(struct kvm_vcpu *vcpu)
{
	unsigned long rflags, save_rflags;

	if (!test_bit(VCPU_EXREG_RFLAGS, (ulong *)&vcpu->arch.regs_avail)) {
		__set_bit(VCPU_EXREG_RFLAGS, (ulong *)&vcpu->arch.regs_avail);
		rflags = vmcs_readl(GUEST_RFLAGS);
		if (to_vmx(vcpu)->rmode.vm86_active) {
			rflags &= RMODE_GUEST_OWNED_EFLAGS_BITS;
			save_rflags = to_vmx(vcpu)->rmode.save_rflags;
			rflags |= save_rflags & ~RMODE_GUEST_OWNED_EFLAGS_BITS;
		}
		to_vmx(vcpu)->rflags = rflags;
	}
	return to_vmx(vcpu)->rflags;
}

static void vmx_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	__set_bit(VCPU_EXREG_RFLAGS, (ulong *)&vcpu->arch.regs_avail);
	to_vmx(vcpu)->rflags = rflags;
	if (to_vmx(vcpu)->rmode.vm86_active) {
		to_vmx(vcpu)->rmode.save_rflags = rflags;
		rflags |= X86_EFLAGS_IOPL | X86_EFLAGS_VM;
	}
	vmcs_writel(GUEST_RFLAGS, rflags);
}

static u32 vmx_get_pkru(struct kvm_vcpu *vcpu)
{
	return to_vmx(vcpu)->guest_pkru;
}

static u32 vmx_get_interrupt_shadow(struct kvm_vcpu *vcpu)
{
	u32 interruptibility = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	int ret = 0;

	if (interruptibility & GUEST_INTR_STATE_STI)
		ret |= KVM_X86_SHADOW_INT_STI;
	if (interruptibility & GUEST_INTR_STATE_MOV_SS)
		ret |= KVM_X86_SHADOW_INT_MOV_SS;

	return ret;
}

static void vmx_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	u32 interruptibility_old = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	u32 interruptibility = interruptibility_old;

	interruptibility &= ~(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS);

	if (mask & KVM_X86_SHADOW_INT_MOV_SS)
		interruptibility |= GUEST_INTR_STATE_MOV_SS;
	else if (mask & KVM_X86_SHADOW_INT_STI)
		interruptibility |= GUEST_INTR_STATE_STI;

	if ((interruptibility != interruptibility_old))
		vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, interruptibility);
}

static void skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	unsigned long rip;

	rip = kvm_rip_read(vcpu);
	rip += vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	kvm_rip_write(vcpu, rip);

	/* skipping an emulated instruction also counts */
	vmx_set_interrupt_shadow(vcpu, 0);
}

/*
 * KVM wants to inject page-faults which it got to the guest. This function
 * checks whether in a nested guest, we need to inject them to L1 or L2.
 */
static int nested_vmx_check_exception(struct kvm_vcpu *vcpu, unsigned nr)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);

	if (!(vmcs12->exception_bitmap & (1u << nr)))
		return 0;

	nested_vmx_vmexit(vcpu, to_vmx(vcpu)->exit_reason,
			  vmcs_read32(VM_EXIT_INTR_INFO),
			  vmcs_readl(EXIT_QUALIFICATION));
	return 1;
}

static void vmx_queue_exception(struct kvm_vcpu *vcpu, unsigned nr,
				bool has_error_code, u32 error_code,
				bool reinject)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 intr_info = nr | INTR_INFO_VALID_MASK;

	if (!reinject && is_guest_mode(vcpu) &&
	    nested_vmx_check_exception(vcpu, nr))
		return;

	if (has_error_code) {
		vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
		intr_info |= INTR_INFO_DELIVER_CODE_MASK;
	}

	if (vmx->rmode.vm86_active) {
		int inc_eip = 0;
		if (kvm_exception_is_soft(nr))
			inc_eip = vcpu->arch.event_exit_inst_len;
		if (kvm_inject_realmode_interrupt(vcpu, nr, inc_eip) != EMULATE_DONE)
			kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		return;
	}

	if (kvm_exception_is_soft(nr)) {
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
			     vmx->vcpu.arch.event_exit_inst_len);
		intr_info |= INTR_TYPE_SOFT_EXCEPTION;
	} else
		intr_info |= INTR_TYPE_HARD_EXCEPTION;

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr_info);
}

static bool vmx_rdtscp_supported(void)
{
	return cpu_has_vmx_rdtscp();
}

static bool vmx_invpcid_supported(void)
{
	return cpu_has_vmx_invpcid() && enable_ept;
}

/*
 * Swap MSR entry in host/guest MSR entry array.
 */
static void move_msr_up(struct vcpu_vmx *vmx, int from, int to)
{
	struct shared_msr_entry tmp;

	tmp = vmx->guest_msrs[to];
	vmx->guest_msrs[to] = vmx->guest_msrs[from];
	vmx->guest_msrs[from] = tmp;
}

static void vmx_set_msr_bitmap(struct kvm_vcpu *vcpu)
{
	unsigned long *msr_bitmap;

	if (is_guest_mode(vcpu))
		msr_bitmap = vmx_msr_bitmap_nested;
	else if (vcpu->arch.apic_base & X2APIC_ENABLE) {
		if (is_long_mode(vcpu))
			msr_bitmap = vmx_msr_bitmap_longmode_x2apic;
		else
			msr_bitmap = vmx_msr_bitmap_legacy_x2apic;
	} else {
		if (is_long_mode(vcpu))
			msr_bitmap = vmx_msr_bitmap_longmode;
		else
			msr_bitmap = vmx_msr_bitmap_legacy;
	}

	vmcs_write64(MSR_BITMAP, __pa(msr_bitmap));
}

/*
 * Set up the vmcs to automatically save and restore system
 * msrs. Don't touch the 64-bit msrs if the guest is in legacy
 * mode, as fiddling with msrs is very expensive.
 */
static void setup_msrs(struct vcpu_vmx *vmx)
{
	int save_nmsrs, index;

	save_nmsrs = 0;
#ifdef CONFIG_X86_64
	if (is_long_mode(&vmx->vcpu)) {
		index = __find_msr_index(vmx, MSR_SYSCALL_MASK);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		index = __find_msr_index(vmx, MSR_LSTAR);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		index = __find_msr_index(vmx, MSR_CSTAR);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		index = __find_msr_index(vmx, MSR_TSC_AUX);
		if (index >= 0 && guest_cpuid_has_rdtscp(&vmx->vcpu))
			move_msr_up(vmx, index, save_nmsrs++);
		/*
 * MSR_STAR is only needed on long mode guests, and only
 * if efer.sce is enabled.
 */
		index = __find_msr_index(vmx, MSR_STAR);
		if ((index >= 0) && (vmx->vcpu.arch.efer & EFER_SCE))
			move_msr_up(vmx, index, save_nmsrs++);
	}
#endif
	index = __find_msr_index(vmx, MSR_EFER);
	if (index >= 0 && update_transition_efer(vmx, index))
		move_msr_up(vmx, index, save_nmsrs++);

	vmx->save_nmsrs = save_nmsrs;

	if (cpu_has_vmx_msr_bitmap())
		vmx_set_msr_bitmap(&vmx->vcpu);
}

/*
 * reads and returns guest's timestamp counter "register"
 * guest_tsc = (host_tsc * tsc multiplier) >> 48 + tsc_offset
 * -- Intel TSC Scaling for Virtualization White Paper, sec 1.3
 */
static u64 guest_read_tsc(struct kvm_vcpu *vcpu)
{
	u64 host_tsc, tsc_offset;

	host_tsc = rdtsc();
	tsc_offset = vmcs_read64(TSC_OFFSET);
	return kvm_scale_tsc(vcpu, host_tsc) + tsc_offset;
}

/*
 * Like guest_read_tsc, but always returns L1's notion of the timestamp
 * counter, even if a nested guest (L2) is currently running.
 */
static u64 vmx_read_l1_tsc(struct kvm_vcpu *vcpu, u64 host_tsc)
{
	u64 tsc_offset;

	tsc_offset = is_guest_mode(vcpu) ?
		to_vmx(vcpu)->nested.vmcs01_tsc_offset :
		vmcs_read64(TSC_OFFSET);
	return host_tsc + tsc_offset;
}

static u64 vmx_read_tsc_offset(struct kvm_vcpu *vcpu)
{
	return vmcs_read64(TSC_OFFSET);
}

/*
 * writes 'offset' into guest's timestamp counter offset register
 */
static void vmx_write_tsc_offset(struct kvm_vcpu *vcpu, u64 offset)
{
	if (is_guest_mode(vcpu)) {
		/*
 * We're here if L1 chose not to trap WRMSR to TSC. According
 * to the spec, this should set L1's TSC; The offset that L1
 * set for L2 remains unchanged, and still needs to be added
 * to the newly set TSC to get L2's TSC.
 */
		struct vmcs12 *vmcs12;
		to_vmx(vcpu)->nested.vmcs01_tsc_offset = offset;
		/* recalculate vmcs02.TSC_OFFSET: */
		vmcs12 = get_vmcs12(vcpu);
		vmcs_write64(TSC_OFFSET, offset +
			(nested_cpu_has(vmcs12, CPU_BASED_USE_TSC_OFFSETING) ?
			 vmcs12->tsc_offset : 0));
	} else {
		trace_kvm_write_tsc_offset(vcpu->vcpu_id,
					   vmcs_read64(TSC_OFFSET), offset);
		vmcs_write64(TSC_OFFSET, offset);
	}
}

static void vmx_adjust_tsc_offset_guest(struct kvm_vcpu *vcpu, s64 adjustment)
{
	u64 offset = vmcs_read64(TSC_OFFSET);

	vmcs_write64(TSC_OFFSET, offset + adjustment);
	if (is_guest_mode(vcpu)) {
		/* Even when running L2, the adjustment needs to apply to L1 */
		to_vmx(vcpu)->nested.vmcs01_tsc_offset += adjustment;
	} else
		trace_kvm_write_tsc_offset(vcpu->vcpu_id, offset,
					   offset + adjustment);
}

static bool guest_cpuid_has_vmx(struct kvm_vcpu *vcpu)
{
	struct kvm_cpuid_entry2 *best = kvm_find_cpuid_entry(vcpu, 1, 0);
	return best && (best->ecx & (1 << (X86_FEATURE_VMX & 31)));
}

/*
 * nested_vmx_allowed() checks whether a guest should be allowed to use VMX
 * instructions and MSRs (i.e., nested VMX). Nested VMX is disabled for
 * all guests if the "nested" module option is off, and can also be disabled
 * for a single guest by disabling its VMX cpuid bit.
 */
static inline bool nested_vmx_allowed(struct kvm_vcpu *vcpu)
{
	return nested && guest_cpuid_has_vmx(vcpu);
}

/*
 * nested_vmx_setup_ctls_msrs() sets up variables containing the values to be
 * returned for the various VMX controls MSRs when nested VMX is enabled.
 * The same values should also be used to verify that vmcs12 control fields are
 * valid during nested entry from L1 to L2.
 * Each of these control msrs has a low and high 32-bit half: A low bit is on
 * if the corresponding bit in the (32-bit) control field *must* be on, and a
 * bit in the high half is on if the corresponding bit in the control field
 * may be on. See also vmx_control_verify().
 */
static void nested_vmx_setup_ctls_msrs(struct vcpu_vmx *vmx)
{
	/*
 * Note that as a general rule, the high half of the MSRs (bits in
 * the control fields which may be 1) should be initialized by the
 * intersection of the underlying hardware's MSR (i.e., features which
 * can be supported) and the list of features we want to expose -
 * because they are known to be properly supported in our code.
 * Also, usually, the low half of the MSRs (bits which must be 1) can
 * be set to 0, meaning that L1 may turn off any of these bits. The
 * reason is that if one of these bits is necessary, it will appear
 * in vmcs01 and prepare_vmcs02, when it bitwise-or's the control
 * fields of vmcs01 and vmcs02, will turn these bits off - and
 * nested_vmx_exit_handled() will not pass related exits to L1.
 * These rules have exceptions below.
 */

	/* pin-based controls */
	rdmsr(MSR_IA32_VMX_PINBASED_CTLS,
		vmx->nested.nested_vmx_pinbased_ctls_low,
		vmx->nested.nested_vmx_pinbased_ctls_high);
	vmx->nested.nested_vmx_pinbased_ctls_low |=
		PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR;
	vmx->nested.nested_vmx_pinbased_ctls_high &=
		PIN_BASED_EXT_INTR_MASK |
		PIN_BASED_NMI_EXITING |
		PIN_BASED_VIRTUAL_NMIS;
	vmx->nested.nested_vmx_pinbased_ctls_high |=
		PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR |
		PIN_BASED_VMX_PREEMPTION_TIMER;
	if (kvm_vcpu_apicv_active(&vmx->vcpu))
		vmx->nested.nested_vmx_pinbased_ctls_high |=
			PIN_BASED_POSTED_INTR;

	/* exit controls */
	rdmsr(MSR_IA32_VMX_EXIT_CTLS,
		vmx->nested.nested_vmx_exit_ctls_low,
		vmx->nested.nested_vmx_exit_ctls_high);
	vmx->nested.nested_vmx_exit_ctls_low =
		VM_EXIT_ALWAYSON_WITHOUT_TRUE_MSR;

	vmx->nested.nested_vmx_exit_ctls_high &=
#ifdef CONFIG_X86_64
		VM_EXIT_HOST_ADDR_SPACE_SIZE |
#endif
		VM_EXIT_LOAD_IA32_PAT | VM_EXIT_SAVE_IA32_PAT;
	vmx->nested.nested_vmx_exit_ctls_high |=
		VM_EXIT_ALWAYSON_WITHOUT_TRUE_MSR |
		VM_EXIT_LOAD_IA32_EFER | VM_EXIT_SAVE_IA32_EFER |
		VM_EXIT_SAVE_VMX_PREEMPTION_TIMER | VM_EXIT_ACK_INTR_ON_EXIT;

	if (kvm_mpx_supported())
		vmx->nested.nested_vmx_exit_ctls_high |= VM_EXIT_CLEAR_BNDCFGS;

	/* We support free control of debug control saving. */
	vmx->nested.nested_vmx_true_exit_ctls_low =
		vmx->nested.nested_vmx_exit_ctls_low &
		~VM_EXIT_SAVE_DEBUG_CONTROLS;

	/* entry controls */
	rdmsr(MSR_IA32_VMX_ENTRY_CTLS,
		vmx->nested.nested_vmx_entry_ctls_low,
		vmx->nested.nested_vmx_entry_ctls_high);
	vmx->nested.nested_vmx_entry_ctls_low =
		VM_ENTRY_ALWAYSON_WITHOUT_TRUE_MSR;
	vmx->nested.nested_vmx_entry_ctls_high &=
#ifdef CONFIG_X86_64
		VM_ENTRY_IA32E_MODE |
#endif
		VM_ENTRY_LOAD_IA32_PAT;
	vmx->nested.nested_vmx_entry_ctls_high |=
		(VM_ENTRY_ALWAYSON_WITHOUT_TRUE_MSR | VM_ENTRY_LOAD_IA32_EFER);
	if (kvm_mpx_supported())
		vmx->nested.nested_vmx_entry_ctls_high |= VM_ENTRY_LOAD_BNDCFGS;

	/* We support free control of debug control loading. */
	vmx->nested.nested_vmx_true_entry_ctls_low =
		vmx->nested.nested_vmx_entry_ctls_low &
		~VM_ENTRY_LOAD_DEBUG_CONTROLS;

	/* cpu-based controls */
	rdmsr(MSR_IA32_VMX_PROCBASED_CTLS,
		vmx->nested.nested_vmx_procbased_ctls_low,
		vmx->nested.nested_vmx_procbased_ctls_high);
	vmx->nested.nested_vmx_procbased_ctls_low =
		CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR;
	vmx->nested.nested_vmx_procbased_ctls_high &=
		CPU_BASED_VIRTUAL_INTR_PENDING |
		CPU_BASED_VIRTUAL_NMI_PENDING | CPU_BASED_USE_TSC_OFFSETING |
		CPU_BASED_HLT_EXITING | CPU_BASED_INVLPG_EXITING |
		CPU_BASED_MWAIT_EXITING | CPU_BASED_CR3_LOAD_EXITING |
		CPU_BASED_CR3_STORE_EXITING |
#ifdef CONFIG_X86_64
		CPU_BASED_CR8_LOAD_EXITING | CPU_BASED_CR8_STORE_EXITING |
#endif
		CPU_BASED_MOV_DR_EXITING | CPU_BASED_UNCOND_IO_EXITING |
		CPU_BASED_USE_IO_BITMAPS | CPU_BASED_MONITOR_TRAP_FLAG |
		CPU_BASED_MONITOR_EXITING | CPU_BASED_RDPMC_EXITING |
		CPU_BASED_RDTSC_EXITING | CPU_BASED_PAUSE_EXITING |
		CPU_BASED_TPR_SHADOW | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	/*
 * We can allow some features even when not supported by the
 * hardware. For example, L1 can specify an MSR bitmap - and we
 * can use it to avoid exits to L1 - even when L0 runs L2
 * without MSR bitmaps.
 */
	vmx->nested.nested_vmx_procbased_ctls_high |=
		CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR |
		CPU_BASED_USE_MSR_BITMAPS;

	/* We support free control of CR3 access interception. */
	vmx->nested.nested_vmx_true_procbased_ctls_low =
		vmx->nested.nested_vmx_procbased_ctls_low &
		~(CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING);

	/* secondary cpu-based controls */
	rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2,
		vmx->nested.nested_vmx_secondary_ctls_low,
		vmx->nested.nested_vmx_secondary_ctls_high);
	vmx->nested.nested_vmx_secondary_ctls_low = 0;
	vmx->nested.nested_vmx_secondary_ctls_high &=
		SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
		SECONDARY_EXEC_RDTSCP |
		SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE |
		SECONDARY_EXEC_ENABLE_VPID |
		SECONDARY_EXEC_APIC_REGISTER_VIRT |
		SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY |
		SECONDARY_EXEC_WBINVD_EXITING |
		SECONDARY_EXEC_XSAVES |
		SECONDARY_EXEC_PCOMMIT;

	if (enable_ept) {
		/* nested EPT: emulate EPT also to L1 */
		vmx->nested.nested_vmx_secondary_ctls_high |=
			SECONDARY_EXEC_ENABLE_EPT;
		vmx->nested.nested_vmx_ept_caps = VMX_EPT_PAGE_WALK_4_BIT |
			 VMX_EPTP_WB_BIT | VMX_EPT_2MB_PAGE_BIT |
			 VMX_EPT_INVEPT_BIT;
		vmx->nested.nested_vmx_ept_caps &= vmx_capability.ept;
		/*
 * For nested guests, we don't do anything specific
 * for single context invalidation. Hence, only advertise
 * support for global context invalidation.
 */
		vmx->nested.nested_vmx_ept_caps |= VMX_EPT_EXTENT_GLOBAL_BIT;
	} else
		vmx->nested.nested_vmx_ept_caps = 0;

	/*
 * Old versions of KVM use the single-context version without
 * checking for support, so declare that it is supported even
 * though it is treated as global context. The alternative is
 * not failing the single-context invvpid, and it is worse.
 */
	if (enable_vpid)
		vmx->nested.nested_vmx_vpid_caps = VMX_VPID_INVVPID_BIT |
				VMX_VPID_EXTENT_SINGLE_CONTEXT_BIT |
				VMX_VPID_EXTENT_GLOBAL_CONTEXT_BIT;
	else
		vmx->nested.nested_vmx_vpid_caps = 0;

	if (enable_unrestricted_guest)
		vmx->nested.nested_vmx_secondary_ctls_high |=
			SECONDARY_EXEC_UNRESTRICTED_GUEST;

	/* miscellaneous data */
	rdmsr(MSR_IA32_VMX_MISC,
		vmx->nested.nested_vmx_misc_low,
		vmx->nested.nested_vmx_misc_high);
	vmx->nested.nested_vmx_misc_low &= VMX_MISC_SAVE_EFER_LMA;
	vmx->nested.nested_vmx_misc_low |=
		VMX_MISC_EMULATED_PREEMPTION_TIMER_RATE |
		VMX_MISC_ACTIVITY_HLT;
	vmx->nested.nested_vmx_misc_high = 0;
}

static inline bool vmx_control_verify(u32 control, u32 low, u32 high)
{
	/*
 * Bits 0 in high must be 0, and bits 1 in low must be 1.
 */
	return ((control & high) | low) == control;
}

static inline u64 vmx_control_msr(u32 low, u32 high)
{
	return low | ((u64)high << 32);
}

/* Returns 0 on success, non-0 otherwise. */
static int vmx_get_vmx_msr(struct kvm_vcpu *vcpu, u32 msr_index, u64 *pdata)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	switch (msr_index) {
	case MSR_IA32_VMX_BASIC:
		/*
 * This MSR reports some information about VMX support. We
 * should return information about the VMX we emulate for the
 * guest, and the VMCS structure we give it - not about the
 * VMX support of the underlying hardware.
 */
		*pdata = VMCS12_REVISION | VMX_BASIC_TRUE_CTLS |
			   ((u64)VMCS12_SIZE << VMX_BASIC_VMCS_SIZE_SHIFT) |
			   (VMX_BASIC_MEM_TYPE_WB << VMX_BASIC_MEM_TYPE_SHIFT);
		break;
	case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
	case MSR_IA32_VMX_PINBASED_CTLS:
		*pdata = vmx_control_msr(
			vmx->nested.nested_vmx_pinbased_ctls_low,
			vmx->nested.nested_vmx_pinbased_ctls_high);
		break;
	case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
		*pdata = vmx_control_msr(
			vmx->nested.nested_vmx_true_procbased_ctls_low,
			vmx->nested.nested_vmx_procbased_ctls_high);
		break;
	case MSR_IA32_VMX_PROCBASED_CTLS:
		*pdata = vmx_control_msr(
			vmx->nested.nested_vmx_procbased_ctls_low,
			vmx->nested.nested_vmx_procbased_ctls_high);
		break;
	case MSR_IA32_VMX_TRUE_EXIT_CTLS:
		*pdata = vmx_control_msr(
			vmx->nested.nested_vmx_true_exit_ctls_low,
			vmx->nested.nested_vmx_exit_ctls_high);
		break;
	case MSR_IA32_VMX_EXIT_CTLS:
		*pdata = vmx_control_msr(
			vmx->nested.nested_vmx_exit_ctls_low,
			vmx->nested.nested_vmx_exit_ctls_high);
		break;
	case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
		*pdata = vmx_control_msr(
			vmx->nested.nested_vmx_true_entry_ctls_low,
			vmx->nested.nested_vmx_entry_ctls_high);
		break;
	case MSR_IA32_VMX_ENTRY_CTLS:
		*pdata = vmx_control_msr(
			vmx->nested.nested_vmx_entry_ctls_low,
			vmx->nested.nested_vmx_entry_ctls_high);
		break;
	case MSR_IA32_VMX_MISC:
		*pdata = vmx_control_msr(
			vmx->nested.nested_vmx_misc_low,
			vmx->nested.nested_vmx_misc_high);
		break;
	/*
 * These MSRs specify bits which the guest must keep fixed (on or off)
 * while L1 is in VMXON mode (in L1's root mode, or running an L2).
 * We picked the standard core2 setting.
 */
#define VMXON_CR0_ALWAYSON (X86_CR0_PE | X86_CR0_PG | X86_CR0_NE)
#define VMXON_CR4_ALWAYSON X86_CR4_VMXE
	case MSR_IA32_VMX_CR0_FIXED0:
		*pdata = VMXON_CR0_ALWAYSON;
		break;
	case MSR_IA32_VMX_CR0_FIXED1:
		*pdata = -1ULL;
		break;
	case MSR_IA32_VMX_CR4_FIXED0:
		*pdata = VMXON_CR4_ALWAYSON;
		break;
	case MSR_IA32_VMX_CR4_FIXED1:
		*pdata = -1ULL;
		break;
	case MSR_IA32_VMX_VMCS_ENUM:
		*pdata = 0x2e; /* highest index: VMX_PREEMPTION_TIMER_VALUE */
		break;
	case MSR_IA32_VMX_PROCBASED_CTLS2:
		*pdata = vmx_control_msr(
			vmx->nested.nested_vmx_secondary_ctls_low,
			vmx->nested.nested_vmx_secondary_ctls_high);
		break;
	case MSR_IA32_VMX_EPT_VPID_CAP:
		/* Currently, no nested vpid support */
		*pdata = vmx->nested.nested_vmx_ept_caps |
			((u64)vmx->nested.nested_vmx_vpid_caps << 32);
		break;
	default:
		return 1;
	}

	return 0;
}

/*
 * Reads an msr value (of 'msr_index') into 'pdata'.
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int vmx_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	struct shared_msr_entry *msr;

	switch (msr_info->index) {
#ifdef CONFIG_X86_64
	case MSR_FS_BASE:
		msr_info->data = vmcs_readl(GUEST_FS_BASE);
		break;
	case MSR_GS_BASE:
		msr_info->data = vmcs_readl(GUEST_GS_BASE);
		break;
	case MSR_KERNEL_GS_BASE:
		vmx_load_host_state(to_vmx(vcpu));
		msr_info->data = to_vmx(vcpu)->msr_guest_kernel_gs_base;
		break;
#endif
	case MSR_EFER:
		return kvm_get_msr_common(vcpu, msr_info);
	case MSR_IA32_TSC:
		msr_info->data = guest_read_tsc(vcpu);
		break;
	case MSR_IA32_SYSENTER_CS:
		msr_info->data = vmcs_read32(GUEST_SYSENTER_CS);
		break;
	case MSR_IA32_SYSENTER_EIP:
		msr_info->data = vmcs_readl(GUEST_SYSENTER_EIP);
		break;
	case MSR_IA32_SYSENTER_ESP:
		msr_info->data = vmcs_readl(GUEST_SYSENTER_ESP);
		break;
	case MSR_IA32_BNDCFGS:
		if (!kvm_mpx_supported())
			return 1;
		msr_info->data = vmcs_read64(GUEST_BNDCFGS);
		break;
	case MSR_IA32_FEATURE_CONTROL:
		if (!nested_vmx_allowed(vcpu))
			return 1;
		msr_info->data = to_vmx(vcpu)->nested.msr_ia32_feature_control;
		break;
	case MSR_IA32_VMX_BASIC ... MSR_IA32_VMX_VMFUNC:
		if (!nested_vmx_allowed(vcpu))
			return 1;
		return vmx_get_vmx_msr(vcpu, msr_info->index, &msr_info->data);
	case MSR_IA32_XSS:
		if (!vmx_xsaves_supported())
			return 1;
		msr_info->data = vcpu->arch.ia32_xss;
		break;
	case MSR_TSC_AUX:
		if (!guest_cpuid_has_rdtscp(vcpu) && !msr_info->host_initiated)
			return 1;
		/* Otherwise falls through */
	default:
		msr = find_msr_entry(to_vmx(vcpu), msr_info->index);
		if (msr) {
			msr_info->data = msr->data;
			break;
		}
		return kvm_get_msr_common(vcpu, msr_info);
	}

	return 0;
}

static void vmx_leave_nested(struct kvm_vcpu *vcpu);

/*
 * Writes msr value into into the appropriate "register".
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int vmx_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct shared_msr_entry *msr;
	int ret = 0;
	u32 msr_index = msr_info->index;
	u64 data = msr_info->data;

	switch (msr_index) {
	case MSR_EFER:
		ret = kvm_set_msr_common(vcpu, msr_info);
		break;
#ifdef CONFIG_X86_64
	case MSR_FS_BASE:
		vmx_segment_cache_clear(vmx);
		vmcs_writel(GUEST_FS_BASE, data);
		break;
	case MSR_GS_BASE:
		vmx_segment_cache_clear(vmx);
		vmcs_writel(GUEST_GS_BASE, data);
		break;
	case MSR_KERNEL_GS_BASE:
		vmx_load_host_state(vmx);
		vmx->msr_guest_kernel_gs_base = data;
		break;
#endif
	case MSR_IA32_SYSENTER_CS:
		vmcs_write32(GUEST_SYSENTER_CS, data);
		break;
	case MSR_IA32_SYSENTER_EIP:
		vmcs_writel(GUEST_SYSENTER_EIP, data);
		break;
	case MSR_IA32_SYSENTER_ESP:
		vmcs_writel(GUEST_SYSENTER_ESP, data);
		break;
	case MSR_IA32_BNDCFGS:
		if (!kvm_mpx_supported())
			return 1;
		vmcs_write64(GUEST_BNDCFGS, data);
		break;
	case MSR_IA32_TSC:
		kvm_write_tsc(vcpu, msr_info);
		break;
	case MSR_IA32_CR_PAT:
		if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT) {
			if (!kvm_mtrr_valid(vcpu, MSR_IA32_CR_PAT, data))
				return 1;
			vmcs_write64(GUEST_IA32_PAT, data);
			vcpu->arch.pat = data;
			break;
		}
		ret = kvm_set_msr_common(vcpu, msr_info);
		break;
	case MSR_IA32_TSC_ADJUST:
		ret = kvm_set_msr_common(vcpu, msr_info);
		break;
	case MSR_IA32_FEATURE_CONTROL:
		if (!nested_vmx_allowed(vcpu) ||
		    (to_vmx(vcpu)->nested.msr_ia32_feature_control &
		     FEATURE_CONTROL_LOCKED && !msr_info->host_initiated))
			return 1;
		vmx->nested.msr_ia32_feature_control = data;
		if (msr_info->host_initiated && data == 0)
			vmx_leave_nested(vcpu);
		break;
	case MSR_IA32_VMX_BASIC ... MSR_IA32_VMX_VMFUNC:
		return 1; /* they are read-only */
	case MSR_IA32_XSS:
		if (!vmx_xsaves_supported())
			return 1;
		/*
 * The only supported bit as of Skylake is bit 8, but
 * it is not supported on KVM.
 */
		if (data != 0)
			return 1;
		vcpu->arch.ia32_xss = data;
		if (vcpu->arch.ia32_xss != host_xss)
			add_atomic_switch_msr(vmx, MSR_IA32_XSS,
				vcpu->arch.ia32_xss, host_xss);
		else
			clear_atomic_switch_msr(vmx, MSR_IA32_XSS);
		break;
	case MSR_TSC_AUX:
		if (!guest_cpuid_has_rdtscp(vcpu) && !msr_info->host_initiated)
			return 1;
		/* Check reserved bit, higher 32 bits should be zero */
		if ((data >> 32) != 0)
			return 1;
		/* Otherwise falls through */
	default:
		msr = find_msr_entry(vmx, msr_index);
		if (msr) {
			u64 old_msr_data = msr->data;
			msr->data = data;
			if (msr - vmx->guest_msrs < vmx->save_nmsrs) {
				preempt_disable();
				ret = kvm_set_shared_msr(msr->index, msr->data,
							 msr->mask);
				preempt_enable();
				if (ret)
					msr->data = old_msr_data;
			}
			break;
		}
		ret = kvm_set_msr_common(vcpu, msr_info);
	}

	return ret;
}

static void vmx_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	__set_bit(reg, (unsigned long *)&vcpu->arch.regs_avail);
	switch (reg) {
	case VCPU_REGS_RSP:
		vcpu->arch.regs[VCPU_REGS_RSP] = vmcs_readl(GUEST_RSP);
		break;
	case VCPU_REGS_RIP:
		vcpu->arch.regs[VCPU_REGS_RIP] = vmcs_readl(GUEST_RIP);
		break;
	case VCPU_EXREG_PDPTR:
		if (enable_ept)
			ept_save_pdptrs(vcpu);
		break;
	default:
		break;
	}
}

static __init int cpu_has_kvm_support(void)
{
	return cpu_has_vmx();
}

static __init int vmx_disabled_by_bios(void)
{
	u64 msr;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, msr);
	if (msr & FEATURE_CONTROL_LOCKED) {
		/* launched w/ TXT and VMX disabled */
		if (!(msr & FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX)
			&& tboot_enabled())
			return 1;
		/* launched w/o TXT and VMX only enabled w/ TXT */
		if (!(msr & FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX)
			&& (msr & FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX)
			&& !tboot_enabled()) {
			printk(KERN_WARNING "kvm: disable TXT in the BIOS or "
				"activate TXT before enabling KVM\n");
			return 1;
		}
		/* launched w/o TXT and VMX disabled */
		if (!(msr & FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX)
			&& !tboot_enabled())
			return 1;
	}

	return 0;
}

static void kvm_cpu_vmxon(u64 addr)
{
	asm volatile (ASM_VMX_VMXON_RAX
			: : "a"(&addr), "m"(addr)
			: "memory", "cc");
}

static int hardware_enable(void)
{
	int cpu = raw_smp_processor_id();
	u64 phys_addr = __pa(per_cpu(vmxarea, cpu));
	u64 old, test_bits;

	if (cr4_read_shadow() & X86_CR4_VMXE)
		return -EBUSY;

	INIT_LIST_HEAD(&per_cpu(loaded_vmcss_on_cpu, cpu));
	INIT_LIST_HEAD(&per_cpu(blocked_vcpu_on_cpu, cpu));
	spin_lock_init(&per_cpu(blocked_vcpu_on_cpu_lock, cpu));

	/*
 * Now we can enable the vmclear operation in kdump
 * since the loaded_vmcss_on_cpu list on this cpu
 * has been initialized.
 *
 * Though the cpu is not in VMX operation now, there
 * is no problem to enable the vmclear operation
 * for the loaded_vmcss_on_cpu list is empty!
 */
	crash_enable_local_vmclear(cpu);

	rdmsrl(MSR_IA32_FEATURE_CONTROL, old);

	test_bits = FEATURE_CONTROL_LOCKED;
	test_bits |= FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;
	if (tboot_enabled())
		test_bits |= FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX;

	if ((old & test_bits) != test_bits) {
		/* enable and lock */
		wrmsrl(MSR_IA32_FEATURE_CONTROL, old | test_bits);
	}
	cr4_set_bits(X86_CR4_VMXE);

	if (vmm_exclusive) {
		kvm_cpu_vmxon(phys_addr);
		ept_sync_global();
	}

	native_store_gdt(this_cpu_ptr(&host_gdt));

	return 0;
}

static void vmclear_local_loaded_vmcss(void)
{
	int cpu = raw_smp_processor_id();
	struct loaded_vmcs *v, *n;

	list_for_each_entry_safe(v, n, &per_cpu(loaded_vmcss_on_cpu, cpu),
				 loaded_vmcss_on_cpu_link)
		__loaded_vmcs_clear(v);
}


/* Just like cpu_vmxoff(), but with the __kvm_handle_fault_on_reboot()
 * tricks.
 */
static void kvm_cpu_vmxoff(void)
{
	asm volatile (__ex(ASM_VMX_VMXOFF) : : : "cc");
}

static void hardware_disable(void)
{
	if (vmm_exclusive) {
		vmclear_local_loaded_vmcss();
		kvm_cpu_vmxoff();
	}
	cr4_clear_bits(X86_CR4_VMXE);
}

static __init int adjust_vmx_controls(u32 ctl_min, u32 ctl_opt,
				      u32 msr, u32 *result)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 ctl = ctl_min | ctl_opt;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);

	ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
	ctl |= vmx_msr_low;  /* bit == 1 in low word ==> must be one */

	/* Ensure minimum (required) set of control bits are supported. */
	if (ctl_min & ~ctl)
		return -EIO;

	*result = ctl;
	return 0;
}

static __init bool allow_1_setting(u32 msr, u32 ctl)
{
	u32 vmx_msr_low, vmx_msr_high;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);
	return vmx_msr_high & ctl;
}

static __init int setup_vmcs_config(struct vmcs_config *vmcs_conf)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 min, opt, min2, opt2;
	u32 _pin_based_exec_control = 0;
	u32 _cpu_based_exec_control = 0;
	u32 _cpu_based_2nd_exec_control = 0;
	u32 _vmexit_control = 0;
	u32 _vmentry_control = 0;

	min = CPU_BASED_HLT_EXITING |
#ifdef CONFIG_X86_64
	      CPU_BASED_CR8_LOAD_EXITING |
	      CPU_BASED_CR8_STORE_EXITING |
#endif
	      CPU_BASED_CR3_LOAD_EXITING |
	      CPU_BASED_CR3_STORE_EXITING |
	      CPU_BASED_USE_IO_BITMAPS |
	      CPU_BASED_MOV_DR_EXITING |
	      CPU_BASED_USE_TSC_OFFSETING |
	      CPU_BASED_MWAIT_EXITING |
	      CPU_BASED_MONITOR_EXITING |
	      CPU_BASED_INVLPG_EXITING |
	      CPU_BASED_RDPMC_EXITING;

	opt = CPU_BASED_TPR_SHADOW |
	      CPU_BASED_USE_MSR_BITMAPS |
	      CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PROCBASED_CTLS,
				&_cpu_based_exec_control) < 0)
		return -EIO;
#ifdef CONFIG_X86_64
	if ((_cpu_based_exec_control & CPU_BASED_TPR_SHADOW))
		_cpu_based_exec_control &= ~CPU_BASED_CR8_LOAD_EXITING &
					   ~CPU_BASED_CR8_STORE_EXITING;
#endif
	if (_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
		min2 = 0;
		opt2 = SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
			SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE |
			SECONDARY_EXEC_WBINVD_EXITING |
			SECONDARY_EXEC_ENABLE_VPID |
			SECONDARY_EXEC_ENABLE_EPT |
			SECONDARY_EXEC_UNRESTRICTED_GUEST |
			SECONDARY_EXEC_PAUSE_LOOP_EXITING |
			SECONDARY_EXEC_RDTSCP |
			SECONDARY_EXEC_ENABLE_INVPCID |
			SECONDARY_EXEC_APIC_REGISTER_VIRT |
			SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY |
			SECONDARY_EXEC_SHADOW_VMCS |
			SECONDARY_EXEC_XSAVES |
			SECONDARY_EXEC_ENABLE_PML |
			SECONDARY_EXEC_PCOMMIT |
			SECONDARY_EXEC_TSC_SCALING;
		if (adjust_vmx_controls(min2, opt2,
					MSR_IA32_VMX_PROCBASED_CTLS2,
					&_cpu_based_2nd_exec_control) < 0)
			return -EIO;
	}
#ifndef CONFIG_X86_64
	if (!(_cpu_based_2nd_exec_control &
				SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES))
		_cpu_based_exec_control &= ~CPU_BASED_TPR_SHADOW;
#endif

	if (!(_cpu_based_exec_control & CPU_BASED_TPR_SHADOW))
		_cpu_based_2nd_exec_control &= ~(
				SECONDARY_EXEC_APIC_REGISTER_VIRT |
				SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE |
				SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY);

	if (_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_EPT) {
		/* CR3 accesses and invlpg don't need to cause VM Exits when EPT
 enabled */
		_cpu_based_exec_control &= ~(CPU_BASED_CR3_LOAD_EXITING |
					     CPU_BASED_CR3_STORE_EXITING |
					     CPU_BASED_INVLPG_EXITING);
		rdmsr(MSR_IA32_VMX_EPT_VPID_CAP,
		      vmx_capability.ept, vmx_capability.vpid);
	}

	min = VM_EXIT_SAVE_DEBUG_CONTROLS;
#ifdef CONFIG_X86_64
	min |= VM_EXIT_HOST_ADDR_SPACE_SIZE;
#endif
	opt = VM_EXIT_SAVE_IA32_PAT | VM_EXIT_LOAD_IA32_PAT |
		VM_EXIT_ACK_INTR_ON_EXIT | VM_EXIT_CLEAR_BNDCFGS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_EXIT_CTLS,
				&_vmexit_control) < 0)
		return -EIO;

	min = PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING;
	opt = PIN_BASED_VIRTUAL_NMIS | PIN_BASED_POSTED_INTR;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PINBASED_CTLS,
				&_pin_based_exec_control) < 0)
		return -EIO;

	if (!(_cpu_based_2nd_exec_control &
		SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY) ||
		!(_vmexit_control & VM_EXIT_ACK_INTR_ON_EXIT))
		_pin_based_exec_control &= ~PIN_BASED_POSTED_INTR;

	min = VM_ENTRY_LOAD_DEBUG_CONTROLS;
	opt = VM_ENTRY_LOAD_IA32_PAT | VM_ENTRY_LOAD_BNDCFGS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
				&_vmentry_control) < 0)
		return -EIO;

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	/* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
	if ((vmx_msr_high & 0x1fff) > PAGE_SIZE)
		return -EIO;

#ifdef CONFIG_X86_64
	/* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
	if (vmx_msr_high & (1u<<16))
		return -EIO;
#endif

	/* Require Write-Back (WB) memory type for VMCS accesses. */
	if (((vmx_msr_high >> 18) & 15) != 6)
		return -EIO;

	vmcs_conf->size = vmx_msr_high & 0x1fff;
	vmcs_conf->order = get_order(vmcs_config.size);
	vmcs_conf->revision_id = vmx_msr_low;

	vmcs_conf->pin_based_exec_ctrl = _pin_based_exec_control;
	vmcs_conf->cpu_based_exec_ctrl = _cpu_based_exec_control;
	vmcs_conf->cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
	vmcs_conf->vmexit_ctrl         = _vmexit_control;
	vmcs_conf->vmentry_ctrl        = _vmentry_control;

	cpu_has_load_ia32_efer =
		allow_1_setting(MSR_IA32_VMX_ENTRY_CTLS,
				VM_ENTRY_LOAD_IA32_EFER)
		&& allow_1_setting(MSR_IA32_VMX_EXIT_CTLS,
				   VM_EXIT_LOAD_IA32_EFER);

	cpu_has_load_perf_global_ctrl =
		allow_1_setting(MSR_IA32_VMX_ENTRY_CTLS,
				VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL)
		&& allow_1_setting(MSR_IA32_VMX_EXIT_CTLS,
				   VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL);

	/*
 * Some cpus support VM_ENTRY_(LOAD|SAVE)_IA32_PERF_GLOBAL_CTRL
 * but due to arrata below it can't be used. Workaround is to use
 * msr load mechanism to switch IA32_PERF_GLOBAL_CTRL.
 *
 * VM Exit May Incorrectly Clear IA32_PERF_GLOBAL_CTRL [34:32]
 *
 * AAK155 (model 26)
 * AAP115 (model 30)
 * AAT100 (model 37)
 * BC86,AAY89,BD102 (model 44)
 * BA97 (model 46)
 *
 */
	if (cpu_has_load_perf_global_ctrl && boot_cpu_data.x86 == 0x6) {
		switch (boot_cpu_data.x86_model) {
		case 26:
		case 30:
		case 37:
		case 44:
		case 46:
			cpu_has_load_perf_global_ctrl = false;
			printk_once(KERN_WARNING"kvm: VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL "
					"does not work properly. Using workaround\n");
			break;
		default:
			break;
		}
	}

	if (cpu_has_xsaves)
		rdmsrl(MSR_IA32_XSS, host_xss);

	return 0;
}

static struct vmcs *alloc_vmcs_cpu(int cpu)
{
	int node = cpu_to_node(cpu);
	struct page *pages;
	struct vmcs *vmcs;

	pages = __alloc_pages_node(node, GFP_KERNEL, vmcs_config.order);
	if (!pages)
		return NULL;
	vmcs = page_address(pages);
	memset(vmcs, 0, vmcs_config.size);
	vmcs->revision_id = vmcs_config.revision_id; /* vmcs revision id */
	return vmcs;
}

static struct vmcs *alloc_vmcs(void)
{
	return alloc_vmcs_cpu(raw_smp_processor_id());
}

static void free_vmcs(struct vmcs *vmcs)
{
	free_pages((unsigned long)vmcs, vmcs_config.order);
}

/*
 * Free a VMCS, but before that VMCLEAR it on the CPU where it was last loaded
 */
static void free_loaded_vmcs(struct loaded_vmcs *loaded_vmcs)
{
	if (!loaded_vmcs->vmcs)
		return;
	loaded_vmcs_clear(loaded_vmcs);
	free_vmcs(loaded_vmcs->vmcs);
	loaded_vmcs->vmcs = NULL;
}

static void free_kvm_area(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		free_vmcs(per_cpu(vmxarea, cpu));
		per_cpu(vmxarea, cpu) = NULL;
	}
}

static void init_vmcs_shadow_fields(void)
{
	int i, j;

	/* No checks for read only fields yet */

	for (i = j = 0; i < max_shadow_read_write_fields; i++) {
		switch (shadow_read_write_fields[i]) {
		case GUEST_BNDCFGS:
			if (!kvm_mpx_supported())
				continue;
			break;
		default:
			break;
		}

		if (j < i)
			shadow_read_write_fields[j] =
				shadow_read_write_fields[i];
		j++;
	}
	max_shadow_read_write_fields = j;

	/* shadowed fields guest access without vmexit */
	for (i = 0; i < max_shadow_read_write_fields; i++) {
		clear_bit(shadow_read_write_fields[i],
			  vmx_vmwrite_bitmap);
		clear_bit(shadow_read_write_fields[i],
			  vmx_vmread_bitmap);
	}
	for (i = 0; i < max_shadow_read_only_fields; i++)
		clear_bit(shadow_read_only_fields[i],
			  vmx_vmread_bitmap);
}

static __init int alloc_kvm_area(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct vmcs *vmcs;

		vmcs = alloc_vmcs_cpu(cpu);
		if (!vmcs) {
			free_kvm_area();
			return -ENOMEM;
		}

		per_cpu(vmxarea, cpu) = vmcs;
	}
	return 0;
}

static bool emulation_required(struct kvm_vcpu *vcpu)
{
	return emulate_invalid_guest_state && !guest_state_valid(vcpu);
}

static void fix_pmode_seg(struct kvm_vcpu *vcpu, int seg,
		struct kvm_segment *save)
{
	if (!emulate_invalid_guest_state) {
		/*
 * CS and SS RPL should be equal during guest entry according
 * to VMX spec, but in reality it is not always so. Since vcpu
 * is in the middle of the transition from real mode to
 * protected mode it is safe to assume that RPL 0 is a good
 * default value.
 */
		if (seg == VCPU_SREG_CS || seg == VCPU_SREG_SS)
			save->selector &= ~SEGMENT_RPL_MASK;
		save->dpl = save->selector & SEGMENT_RPL_MASK;
		save->s = 1;
	}
	vmx_set_segment(vcpu, save, seg);
}

static void enter_pmode(struct kvm_vcpu *vcpu)
{
	unsigned long flags;
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	/*
 * Update real mode segment cache. It may be not up-to-date if sement
 * register was written while vcpu was in a guest mode.
 */
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_ES], VCPU_SREG_ES);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_DS], VCPU_SREG_DS);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_FS], VCPU_SREG_FS);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_GS], VCPU_SREG_GS);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_SS], VCPU_SREG_SS);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_CS], VCPU_SREG_CS);

	vmx->rmode.vm86_active = 0;

	vmx_segment_cache_clear(vmx);

	vmx_set_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_TR], VCPU_SREG_TR);

	flags = vmcs_readl(GUEST_RFLAGS);
	flags &= RMODE_GUEST_OWNED_EFLAGS_BITS;
	flags |= vmx->rmode.save_rflags & ~RMODE_GUEST_OWNED_EFLAGS_BITS;
	vmcs_writel(GUEST_RFLAGS, flags);

	vmcs_writel(GUEST_CR4, (vmcs_readl(GUEST_CR4) & ~X86_CR4_VME) |
			(vmcs_readl(CR4_READ_SHADOW) & X86_CR4_VME));

	update_exception_bitmap(vcpu);

	fix_pmode_seg(vcpu, VCPU_SREG_CS, &vmx->rmode.segs[VCPU_SREG_CS]);
	fix_pmode_seg(vcpu, VCPU_SREG_SS, &vmx->rmode.segs[VCPU_SREG_SS]);
	fix_pmode_seg(vcpu, VCPU_SREG_ES, &vmx->rmode.segs[VCPU_SREG_ES]);
	fix_pmode_seg(vcpu, VCPU_SREG_DS, &vmx->rmode.segs[VCPU_SREG_DS]);
	fix_pmode_seg(vcpu, VCPU_SREG_FS, &vmx->rmode.segs[VCPU_SREG_FS]);
	fix_pmode_seg(vcpu, VCPU_SREG_GS, &vmx->rmode.segs[VCPU_SREG_GS]);
}

static void fix_rmode_seg(int seg, struct kvm_segment *save)
{
	const struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	struct kvm_segment var = *save;

	var.dpl = 0x3;
	if (seg == VCPU_SREG_CS)
		var.type = 0x3;

	if (!emulate_invalid_guest_state) {
		var.selector = var.base >> 4;
		var.base = var.base & 0xffff0;
		var.limit = 0xffff;
		var.g = 0;
		var.db = 0;
		var.present = 1;
		var.s = 1;
		var.l = 0;
		var.unusable = 0;
		var.type = 0x3;
		var.avl = 0;
		if (save->base & 0xf)
			printk_once(KERN_WARNING "kvm: segment base is not "
					"paragraph aligned when entering "
					"protected mode (seg=%d)", seg);
	}

	vmcs_write16(sf->selector, var.selector);
	vmcs_write32(sf->base, var.base);
	vmcs_write32(sf->limit, var.limit);
	vmcs_write32(sf->ar_bytes, vmx_segment_access_rights(&var));
}

static void enter_rmode(struct kvm_vcpu *vcpu)
{
	unsigned long flags;
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_TR], VCPU_SREG_TR);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_ES], VCPU_SREG_ES);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_DS], VCPU_SREG_DS);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_FS], VCPU_SREG_FS);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_GS], VCPU_SREG_GS);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_SS], VCPU_SREG_SS);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_CS], VCPU_SREG_CS);

	vmx->rmode.vm86_active = 1;

	/*
 * Very old userspace does not call KVM_SET_TSS_ADDR before entering
 * vcpu. Warn the user that an update is overdue.
 */
	if (!vcpu->kvm->arch.tss_addr)
		printk_once(KERN_WARNING "kvm: KVM_SET_TSS_ADDR need to be "
			     "called before entering vcpu\n");

	vmx_segment_cache_clear(vmx);

	vmcs_writel(GUEST_TR_BASE, vcpu->kvm->arch.tss_addr);
	vmcs_write32(GUEST_TR_LIMIT, RMODE_TSS_SIZE - 1);
	vmcs_write32(GUEST_TR_AR_BYTES, 0x008b);

	flags = vmcs_readl(GUEST_RFLAGS);
	vmx->rmode.save_rflags = flags;

	flags |= X86_EFLAGS_IOPL | X86_EFLAGS_VM;

	vmcs_writel(GUEST_RFLAGS, flags);
	vmcs_writel(GUEST_CR4, vmcs_readl(GUEST_CR4) | X86_CR4_VME);
	update_exception_bitmap(vcpu);

	fix_rmode_seg(VCPU_SREG_SS, &vmx->rmode.segs[VCPU_SREG_SS]);
	fix_rmode_seg(VCPU_SREG_CS, &vmx->rmode.segs[VCPU_SREG_CS]);
	fix_rmode_seg(VCPU_SREG_ES, &vmx->rmode.segs[VCPU_SREG_ES]);
	fix_rmode_seg(VCPU_SREG_DS, &vmx->rmode.segs[VCPU_SREG_DS]);
	fix_rmode_seg(VCPU_SREG_GS, &vmx->rmode.segs[VCPU_SREG_GS]);
	fix_rmode_seg(VCPU_SREG_FS, &vmx->rmode.segs[VCPU_SREG_FS]);

	kvm_mmu_reset_context(vcpu);
}

static void vmx_set_efer(struct kvm_vcpu *vcpu, u64 efer)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct shared_msr_entry *msr = find_msr_entry(vmx, MSR_EFER);

	if (!msr)
		return;

	/*
 * Force kernel_gs_base reloading before EFER changes, as control
 * of this msr depends on is_long_mode().
 */
	vmx_load_host_state(to_vmx(vcpu));
	vcpu->arch.efer = efer;
	if (efer & EFER_LMA) {
		vm_entry_controls_setbit(to_vmx(vcpu), VM_ENTRY_IA32E_MODE);
		msr->data = efer;
	} else {
		vm_entry_controls_clearbit(to_vmx(vcpu), VM_ENTRY_IA32E_MODE);

		msr->data = efer & ~EFER_LME;
	}
	setup_msrs(vmx);
}

#ifdef CONFIG_X86_64

static void enter_lmode(struct kvm_vcpu *vcpu)
{
	u32 guest_tr_ar;

	vmx_segment_cache_clear(to_vmx(vcpu));

	guest_tr_ar = vmcs_read32(GUEST_TR_AR_BYTES);
	if ((guest_tr_ar & VMX_AR_TYPE_MASK) != VMX_AR_TYPE_BUSY_64_TSS) {
		pr_debug_ratelimited("%s: tss fixup for long mode. \n",
				     __func__);
		vmcs_write32(GUEST_TR_AR_BYTES,
			     (guest_tr_ar & ~VMX_AR_TYPE_MASK)
			     | VMX_AR_TYPE_BUSY_64_TSS);
	}
	vmx_set_efer(vcpu, vcpu->arch.efer | EFER_LMA);
}

static void exit_lmode(struct kvm_vcpu *vcpu)
{
	vm_entry_controls_clearbit(to_vmx(vcpu), VM_ENTRY_IA32E_MODE);
	vmx_set_efer(vcpu, vcpu->arch.efer & ~EFER_LMA);
}

#endif

static inline void __vmx_flush_tlb(struct kvm_vcpu *vcpu, int vpid)
{
	vpid_sync_context(vpid);
	if (enable_ept) {
		if (!VALID_PAGE(vcpu->arch.mmu.root_hpa))
			return;
		ept_sync_context(construct_eptp(vcpu->arch.mmu.root_hpa));
	}
}

static void vmx_flush_tlb(struct kvm_vcpu *vcpu)
{
	__vmx_flush_tlb(vcpu, to_vmx(vcpu)->vpid);
}

static void vmx_decache_cr0_guest_bits(struct kvm_vcpu *vcpu)
{
	ulong cr0_guest_owned_bits = vcpu->arch.cr0_guest_owned_bits;

	vcpu->arch.cr0 &= ~cr0_guest_owned_bits;
	vcpu->arch.cr0 |= vmcs_readl(GUEST_CR0) & cr0_guest_owned_bits;
}

static void vmx_decache_cr3(struct kvm_vcpu *vcpu)
{
	if (enable_ept && is_paging(vcpu))
		vcpu->arch.cr3 = vmcs_readl(GUEST_CR3);
	__set_bit(VCPU_EXREG_CR3, (ulong *)&vcpu->arch.regs_avail);
}

static void vmx_decache_cr4_guest_bits(struct kvm_vcpu *vcpu)
{
	ulong cr4_guest_owned_bits = vcpu->arch.cr4_guest_owned_bits;

	vcpu->arch.cr4 &= ~cr4_guest_owned_bits;
	vcpu->arch.cr4 |= vmcs_readl(GUEST_CR4) & cr4_guest_owned_bits;
}

static void ept_load_pdptrs(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *mmu = vcpu->arch.walk_mmu;

	if (!test_bit(VCPU_EXREG_PDPTR,
		      (unsigned long *)&vcpu->arch.regs_dirty))
		return;

	if (is_paging(vcpu) && is_pae(vcpu) && !is_long_mode(vcpu)) {
		vmcs_write64(GUEST_PDPTR0, mmu->pdptrs[0]);
		vmcs_write64(GUEST_PDPTR1, mmu->pdptrs[1]);
		vmcs_write64(GUEST_PDPTR2, mmu->pdptrs[2]);
		vmcs_write64(GUEST_PDPTR3, mmu->pdptrs[3]);
	}
}

static void ept_save_pdptrs(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *mmu = vcpu->arch.walk_mmu;

	if (is_paging(vcpu) && is_pae(vcpu) && !is_long_mode(vcpu)) {
		mmu->pdptrs[0] = vmcs_read64(GUEST_PDPTR0);
		mmu->pdptrs[1] = vmcs_read64(GUEST_PDPTR1);
		mmu->pdptrs[2] = vmcs_read64(GUEST_PDPTR2);
		mmu->pdptrs[3] = vmcs_read64(GUEST_PDPTR3);
	}

	__set_bit(VCPU_EXREG_PDPTR,
		  (unsigned long *)&vcpu->arch.regs_avail);
	__set_bit(VCPU_EXREG_PDPTR,
		  (unsigned long *)&vcpu->arch.regs_dirty);
}

static int vmx_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4);

static void ept_update_paging_mode_cr0(unsigned long *hw_cr0,
					unsigned long cr0,
					struct kvm_vcpu *vcpu)
{
	if (!test_bit(VCPU_EXREG_CR3, (ulong *)&vcpu->arch.regs_avail))
		vmx_decache_cr3(vcpu);
	if (!(cr0 & X86_CR0_PG)) {
		/* From paging/starting to nonpaging */
		vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
			     vmcs_read32(CPU_BASED_VM_EXEC_CONTROL) |
			     (CPU_BASED_CR3_LOAD_EXITING |
			      CPU_BASED_CR3_STORE_EXITING));
		vcpu->arch.cr0 = cr0;
		vmx_set_cr4(vcpu, kvm_read_cr4(vcpu));
	} else if (!is_paging(vcpu)) {
		/* From nonpaging to paging */
		vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
			     vmcs_read32(CPU_BASED_VM_EXEC_CONTROL) &
			     ~(CPU_BASED_CR3_LOAD_EXITING |
			       CPU_BASED_CR3_STORE_EXITING));
		vcpu->arch.cr0 = cr0;
		vmx_set_cr4(vcpu, kvm_read_cr4(vcpu));
	}

	if (!(cr0 & X86_CR0_WP))
		*hw_cr0 &= ~X86_CR0_WP;
}

static void vmx_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long hw_cr0;

	hw_cr0 = (cr0 & ~KVM_GUEST_CR0_MASK);
	if (enable_unrestricted_guest)
		hw_cr0 |= KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST;
	else {
		hw_cr0 |= KVM_VM_CR0_ALWAYS_ON;

		if (vmx->rmode.vm86_active && (cr0 & X86_CR0_PE))
			enter_pmode(vcpu);

		if (!vmx->rmode.vm86_active && !(cr0 & X86_CR0_PE))
			enter_rmode(vcpu);
	}

#ifdef CONFIG_X86_64
	if (vcpu->arch.efer & EFER_LME) {
		if (!is_paging(vcpu) && (cr0 & X86_CR0_PG))
			enter_lmode(vcpu);
		if (is_paging(vcpu) && !(cr0 & X86_CR0_PG))
			exit_lmode(vcpu);
	}
#endif

	if (enable_ept)
		ept_update_paging_mode_cr0(&hw_cr0, cr0, vcpu);

	if (!vcpu->fpu_active)
		hw_cr0 |= X86_CR0_TS | X86_CR0_MP;

	vmcs_writel(CR0_READ_SHADOW, cr0);
	vmcs_writel(GUEST_CR0, hw_cr0);
	vcpu->arch.cr0 = cr0;

	/* depends on vcpu->arch.cr0 to be set to a new value */
	vmx->emulation_required = emulation_required(vcpu);
}

static u64 construct_eptp(unsigned long root_hpa)
{
	u64 eptp;

	/* TODO write the value reading from MSR */
	eptp = VMX_EPT_DEFAULT_MT |
		VMX_EPT_DEFAULT_GAW << VMX_EPT_GAW_EPTP_SHIFT;
	if (enable_ept_ad_bits)
		eptp |= VMX_EPT_AD_ENABLE_BIT;
	eptp |= (root_hpa & PAGE_MASK);

	return eptp;
}

static void vmx_set_cr3(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	unsigned long guest_cr3;
	u64 eptp;

	guest_cr3 = cr3;
	if (enable_ept) {
		eptp = construct_eptp(cr3);
		vmcs_write64(EPT_POINTER, eptp);
		if (is_paging(vcpu) || is_guest_mode(vcpu))
			guest_cr3 = kvm_read_cr3(vcpu);
		else
			guest_cr3 = vcpu->kvm->arch.ept_identity_map_addr;
		ept_load_pdptrs(vcpu);
	}

	vmx_flush_tlb(vcpu);
	vmcs_writel(GUEST_CR3, guest_cr3);
}

static int vmx_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	/*
 * Pass through host's Machine Check Enable value to hw_cr4, which
 * is in force while we are in guest mode. Do not let guests control
 * this bit, even if host CR4.MCE == 0.
 */
	unsigned long hw_cr4 =
		(cr4_read_shadow() & X86_CR4_MCE) |
		(cr4 & ~X86_CR4_MCE) |
		(to_vmx(vcpu)->rmode.vm86_active ?
		 KVM_RMODE_VM_CR4_ALWAYS_ON : KVM_PMODE_VM_CR4_ALWAYS_ON);

	if (cr4 & X86_CR4_VMXE) {
		/*
 * To use VMXON (and later other VMX instructions), a guest
 * must first be able to turn on cr4.VMXE (see handle_vmon()).
 * So basically the check on whether to allow nested VMX
 * is here.
 */
		if (!nested_vmx_allowed(vcpu))
			return 1;
	}
	if (to_vmx(vcpu)->nested.vmxon &&
	    ((cr4 & VMXON_CR4_ALWAYSON) != VMXON_CR4_ALWAYSON))
		return 1;

	vcpu->arch.cr4 = cr4;
	if (enable_ept) {
		if (!is_paging(vcpu)) {
			hw_cr4 &= ~X86_CR4_PAE;
			hw_cr4 |= X86_CR4_PSE;
		} else if (!(cr4 & X86_CR4_PAE)) {
			hw_cr4 &= ~X86_CR4_PAE;
		}
	}

	if (!enable_unrestricted_guest && !is_paging(vcpu))
		/*
 * SMEP/SMAP/PKU is disabled if CPU is in non-paging mode in
 * hardware. To emulate this behavior, SMEP/SMAP/PKU needs
 * to be manually disabled when guest switches to non-paging
 * mode.
 *
 * If !enable_unrestricted_guest, the CPU is always running
 * with CR0.PG=1 and CR4 needs to be modified.
 * If enable_unrestricted_guest, the CPU automatically
 * disables SMEP/SMAP/PKU when the guest sets CR0.PG=0.
 */
		hw_cr4 &= ~(X86_CR4_SMEP | X86_CR4_SMAP | X86_CR4_PKE);

	vmcs_writel(CR4_READ_SHADOW, cr4);
	vmcs_writel(GUEST_CR4, hw_cr4);
	return 0;
}

static void vmx_get_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 ar;

	if (vmx->rmode.vm86_active && seg != VCPU_SREG_LDTR) {
		*var = vmx->rmode.segs[seg];
		if (seg == VCPU_SREG_TR
		    || var->selector == vmx_read_guest_seg_selector(vmx, seg))
			return;
		var->base = vmx_read_guest_seg_base(vmx, seg);
		var->selector = vmx_read_guest_seg_selector(vmx, seg);
		return;
	}
	var->base = vmx_read_guest_seg_base(vmx, seg);
	var->limit = vmx_read_guest_seg_limit(vmx, seg);
	var->selector = vmx_read_guest_seg_selector(vmx, seg);
	ar = vmx_read_guest_seg_ar(vmx, seg);
	var->unusable = (ar >> 16) & 1;
	var->type = ar & 15;
	var->s = (ar >> 4) & 1;
	var->dpl = (ar >> 5) & 3;
	/*
 * Some userspaces do not preserve unusable property. Since usable
 * segment has to be present according to VMX spec we can use present
 * property to amend userspace bug by making unusable segment always
 * nonpresent. vmx_segment_access_rights() already marks nonpresent
 * segment as unusable.
 */
	var->present = !var->unusable;
	var->avl = (ar >> 12) & 1;
	var->l = (ar >> 13) & 1;
	var->db = (ar >> 14) & 1;
	var->g = (ar >> 15) & 1;
}

static u64 vmx_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment s;

	if (to_vmx(vcpu)->rmode.vm86_active) {
		vmx_get_segment(vcpu, &s, seg);
		return s.base;
	}
	return vmx_read_guest_seg_base(to_vmx(vcpu), seg);
}

static int vmx_get_cpl(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (unlikely(vmx->rmode.vm86_active))
		return 0;
	else {
		int ar = vmx_read_guest_seg_ar(vmx, VCPU_SREG_SS);
		return VMX_AR_DPL(ar);
	}
}

static u32 vmx_segment_access_rights(struct kvm_segment *var)
{
	u32 ar;

	if (var->unusable || !var->present)
		ar = 1 << 16;
	else {
		ar = var->type & 15;
		ar |= (var->s & 1) << 4;
		ar |= (var->dpl & 3) << 5;
		ar |= (var->present & 1) << 7;
		ar |= (var->avl & 1) << 12;
		ar |= (var->l & 1) << 13;
		ar |= (var->db & 1) << 14;
		ar |= (var->g & 1) << 15;
	}

	return ar;
}

static void vmx_set_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	const struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];

	vmx_segment_cache_clear(vmx);

	if (vmx->rmode.vm86_active && seg != VCPU_SREG_LDTR) {
		vmx->rmode.segs[seg] = *var;
		if (seg == VCPU_SREG_TR)
			vmcs_write16(sf->selector, var->selector);
		else if (var->s)
			fix_rmode_seg(seg, &vmx->rmode.segs[seg]);
		goto out;
	}

	vmcs_writel(sf->base, var->base);
	vmcs_write32(sf->limit, var->limit);
	vmcs_write16(sf->selector, var->selector);

	/*
 * Fix the "Accessed" bit in AR field of segment registers for older
 * qemu binaries.
 * IA32 arch specifies that at the time of processor reset the
 * "Accessed" bit in the AR field of segment registers is 1. And qemu
 * is setting it to 0 in the userland code. This causes invalid guest
 * state vmexit when "unrestricted guest" mode is turned on.
 * Fix for this setup issue in cpu_reset is being pushed in the qemu
 * tree. Newer qemu binaries with that qemu fix would not need this
 * kvm hack.
 */
	if (enable_unrestricted_guest && (seg != VCPU_SREG_LDTR))
		var->type |= 0x1; /* Accessed */

	vmcs_write32(sf->ar_bytes, vmx_segment_access_rights(var));

out:
	vmx->emulation_required = emulation_required(vcpu);
}

static void vmx_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	u32 ar = vmx_read_guest_seg_ar(to_vmx(vcpu), VCPU_SREG_CS);

	*db = (ar >> 14) & 1;
	*l = (ar >> 13) & 1;
}

static void vmx_get_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	dt->size = vmcs_read32(GUEST_IDTR_LIMIT);
	dt->address = vmcs_readl(GUEST_IDTR_BASE);
}

static void vmx_set_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	vmcs_write32(GUEST_IDTR_LIMIT, dt->size);
	vmcs_writel(GUEST_IDTR_BASE, dt->address);
}

static void vmx_get_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	dt->size = vmcs_read32(GUEST_GDTR_LIMIT);
	dt->address = vmcs_readl(GUEST_GDTR_BASE);
}

static void vmx_set_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	vmcs_write32(GUEST_GDTR_LIMIT, dt->size);
	vmcs_writel(GUEST_GDTR_BASE, dt->address);
}

static bool rmode_segment_valid(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment var;
	u32 ar;

	vmx_get_segment(vcpu, &var, seg);
	var.dpl = 0x3;
	if (seg == VCPU_SREG_CS)
		var.type = 0x3;
	ar = vmx_segment_access_rights(&var);

	if (var.base != (var.selector << 4))
		return false;
	if (var.limit != 0xffff)
		return false;
	if (ar != 0xf3)
		return false;

	return true;
}

static bool code_segment_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment cs;
	unsigned int cs_rpl;

	vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);
	cs_rpl = cs.selector & SEGMENT_RPL_MASK;

	if (cs.unusable)
		return false;
	if (~cs.type & (VMX_AR_TYPE_CODE_MASK|VMX_AR_TYPE_ACCESSES_MASK))
		return false;
	if (!cs.s)
		return false;
	if (cs.type & VMX_AR_TYPE_WRITEABLE_MASK) {
		if (cs.dpl > cs_rpl)
			return false;
	} else {
		if (cs.dpl != cs_rpl)
			return false;
	}
	if (!cs.present)
		return false;

	/* TODO: Add Reserved field check, this'll require a new member in the kvm_segment_field structure */
	return true;
}

static bool stack_segment_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment ss;
	unsigned int ss_rpl;

	vmx_get_segment(vcpu, &ss, VCPU_SREG_SS);
	ss_rpl = ss.selector & SEGMENT_RPL_MASK;

	if (ss.unusable)
		return true;
	if (ss.type != 3 && ss.type != 7)
		return false;
	if (!ss.s)
		return false;
	if (ss.dpl != ss_rpl) /* DPL != RPL */
		return false;
	if (!ss.present)
		return false;

	return true;
}

static bool data_segment_valid(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment var;
	unsigned int rpl;

	vmx_get_segment(vcpu, &var, seg);
	rpl = var.selector & SEGMENT_RPL_MASK;

	if (var.unusable)
		return true;
	if (!var.s)
		return false;
	if (!var.present)
		return false;
	if (~var.type & (VMX_AR_TYPE_CODE_MASK|VMX_AR_TYPE_WRITEABLE_MASK)) {
		if (var.dpl < rpl) /* DPL < RPL */
			return false;
	}

	/* TODO: Add other members to kvm_segment_field to allow checking for other access
 * rights flags
 */
	return true;
}

static bool tr_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment tr;

	vmx_get_segment(vcpu, &tr, VCPU_SREG_TR);

	if (tr.unusable)
		return false;
	if (tr.selector & SEGMENT_TI_MASK)	/* TI = 1 */
		return false;
	if (tr.type != 3 && tr.type != 11) /* TODO: Check if guest is in IA32e mode */
		return false;
	if (!tr.present)
		return false;

	return true;
}

static bool ldtr_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment ldtr;

	vmx_get_segment(vcpu, &ldtr, VCPU_SREG_LDTR);

	if (ldtr.unusable)
		return true;
	if (ldtr.selector & SEGMENT_TI_MASK)	/* TI = 1 */
		return false;
	if (ldtr.type != 2)
		return false;
	if (!ldtr.present)
		return false;

	return true;
}

static bool cs_ss_rpl_check(struct kvm_vcpu *vcpu)
{
	struct kvm_segment cs, ss;

	vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);
	vmx_get_segment(vcpu, &ss, VCPU_SREG_SS);

	return ((cs.selector & SEGMENT_RPL_MASK) ==
		 (ss.selector & SEGMENT_RPL_MASK));
}

/*
 * Check if guest state is valid. Returns true if valid, false if
 * not.
 * We assume that registers are always usable
 */
static bool guest_state_valid(struct kvm_vcpu *vcpu)
{
	if (enable_unrestricted_guest)
		return true;

	/* real mode guest state checks */
	if (!is_protmode(vcpu) || (vmx_get_rflags(vcpu) & X86_EFLAGS_VM)) {
		if (!rmode_segment_valid(vcpu, VCPU_SREG_CS))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_SS))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_DS))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_ES))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_FS))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_GS))
			return false;
	} else {
	/* protected mode guest state checks */
		if (!cs_ss_rpl_check(vcpu))
			return false;
		if (!code_segment_valid(vcpu))
			return false;
		if (!stack_segment_valid(vcpu))
			return false;
		if (!data_segment_valid(vcpu, VCPU_SREG_DS))
			return false;
		if (!data_segment_valid(vcpu, VCPU_SREG_ES))
			return false;
		if (!data_segment_valid(vcpu, VCPU_SREG_FS))
			return false;
		if (!data_segment_valid(vcpu, VCPU_SREG_GS))
			return false;
		if (!tr_valid(vcpu))
			return false;
		if (!ldtr_valid(vcpu))
			return false;
	}
	/* TODO:
 * - Add checks on RIP
 * - Add checks on RFLAGS
 */

	return true;
}

static int init_rmode_tss(struct kvm *kvm)
{
	gfn_t fn;
	u16 data = 0;
	int idx, r;

	idx = srcu_read_lock(&kvm->srcu);
	fn = kvm->arch.tss_addr >> PAGE_SHIFT;
	r = kvm_clear_guest_page(kvm, fn, 0, PAGE_SIZE);
	if (r < 0)
		goto out;
	data = TSS_BASE_SIZE + TSS_REDIRECTION_SIZE;
	r = kvm_write_guest_page(kvm, fn++, &data,
			TSS_IOPB_BASE_OFFSET, sizeof(u16));
	if (r < 0)
		goto out;
	r = kvm_clear_guest_page(kvm, fn++, 0, PAGE_SIZE);
	if (r < 0)
		goto out;
	r = kvm_clear_guest_page(kvm, fn, 0, PAGE_SIZE);
	if (r < 0)
		goto out;
	data = ~0;
	r = kvm_write_guest_page(kvm, fn, &data,
				 RMODE_TSS_SIZE - 2 * PAGE_SIZE - 1,
				 sizeof(u8));
out:
	srcu_read_unlock(&kvm->srcu, idx);
	return r;
}

static int init_rmode_identity_map(struct kvm *kvm)
{
	int i, idx, r = 0;
	kvm_pfn_t identity_map_pfn;
	u32 tmp;

	if (!enable_ept)
		return 0;

	/* Protect kvm->arch.ept_identity_pagetable_done. */
	mutex_lock(&kvm->slots_lock);

	if (likely(kvm->arch.ept_identity_pagetable_done))
		goto out2;

	identity_map_pfn = kvm->arch.ept_identity_map_addr >> PAGE_SHIFT;

	r = alloc_identity_pagetable(kvm);
	if (r < 0)
		goto out2;

	idx = srcu_read_lock(&kvm->srcu);
	r = kvm_clear_guest_page(kvm, identity_map_pfn, 0, PAGE_SIZE);
	if (r < 0)
		goto out;
	/* Set up identity-mapping pagetable for EPT in real mode */
	for (i = 0; i < PT32_ENT_PER_PAGE; i++) {
		tmp = (i << 22) + (_PAGE_PRESENT | _PAGE_RW | _PAGE_USER |
			_PAGE_ACCESSED | _PAGE_DIRTY | _PAGE_PSE);
		r = kvm_write_guest_page(kvm, identity_map_pfn,
				&tmp, i * sizeof(tmp), sizeof(tmp));
		if (r < 0)
			goto out;
	}
	kvm->arch.ept_identity_pagetable_done = true;

out:
	srcu_read_unlock(&kvm->srcu, idx);

out2:
	mutex_unlock(&kvm->slots_lock);
	return r;
}

static void seg_setup(int seg)
{
	const struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	unsigned int ar;

	vmcs_write16(sf->selector, 0);
	vmcs_writel(sf->base, 0);
	vmcs_write32(sf->limit, 0xffff);
	ar = 0x93;
	if (seg == VCPU_SREG_CS)
		ar |= 0x08; /* code segment */

	vmcs_write32(sf->ar_bytes, ar);
}

static int alloc_apic_access_page(struct kvm *kvm)
{
	struct page *page;
	int r = 0;

	mutex_lock(&kvm->slots_lock);
	if (kvm->arch.apic_access_page_done)
		goto out;
	r = __x86_set_memory_region(kvm, APIC_ACCESS_PAGE_PRIVATE_MEMSLOT,
				    APIC_DEFAULT_PHYS_BASE, PAGE_SIZE);
	if (r)
		goto out;

	page = gfn_to_page(kvm, APIC_DEFAULT_PHYS_BASE >> PAGE_SHIFT);
	if (is_error_page(page)) {
		r = -EFAULT;
		goto out;
	}

	/*
 * Do not pin the page in memory, so that memory hot-unplug
 * is able to migrate it.
 */
	put_page(page);
	kvm->arch.apic_access_page_done = true;
out:
	mutex_unlock(&kvm->slots_lock);
	return r;
}

static int alloc_identity_pagetable(struct kvm *kvm)
{
	/* Called with kvm->slots_lock held. */

	int r = 0;

	BUG_ON(kvm->arch.ept_identity_pagetable_done);

	r = __x86_set_memory_region(kvm, IDENTITY_PAGETABLE_PRIVATE_MEMSLOT,
				    kvm->arch.ept_identity_map_addr, PAGE_SIZE);

	return r;
}

static int allocate_vpid(void)
{
	int vpid;

	if (!enable_vpid)
		return 0;
	spin_lock(&vmx_vpid_lock);
	vpid = find_first_zero_bit(vmx_vpid_bitmap, VMX_NR_VPIDS);
	if (vpid < VMX_NR_VPIDS)
		__set_bit(vpid, vmx_vpid_bitmap);
	else
		vpid = 0;
	spin_unlock(&vmx_vpid_lock);
	return vpid;
}

static void free_vpid(int vpid)
{
	if (!enable_vpid || vpid == 0)
		return;
	spin_lock(&vmx_vpid_lock);
	__clear_bit(vpid, vmx_vpid_bitmap);
	spin_unlock(&vmx_vpid_lock);
}

#define MSR_TYPE_R 1
#define MSR_TYPE_W 2
static void __vmx_disable_intercept_for_msr(unsigned long *msr_bitmap,
						u32 msr, int type)
{
	int f = sizeof(unsigned long);

	if (!cpu_has_vmx_msr_bitmap())
		return;

	/*
 * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
 * have the write-low and read-high bitmap offsets the wrong way round.
 * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
 */
	if (msr <= 0x1fff) {
		if (type & MSR_TYPE_R)
			/* read-low */
			__clear_bit(msr, msr_bitmap + 0x000 / f);

		if (type & MSR_TYPE_W)
			/* write-low */
			__clear_bit(msr, msr_bitmap + 0x800 / f);

	} else if ((msr >= 0xc0000000) && (msr <= 0xc0001fff)) {
		msr &= 0x1fff;
		if (type & MSR_TYPE_R)
			/* read-high */
			__clear_bit(msr, msr_bitmap + 0x400 / f);

		if (type & MSR_TYPE_W)
			/* write-high */
			__clear_bit(msr, msr_bitmap + 0xc00 / f);

	}
}

static void __vmx_enable_intercept_for_msr(unsigned long *msr_bitmap,
						u32 msr, int type)
{
	int f = sizeof(unsigned long);

	if (!cpu_has_vmx_msr_bitmap())
		return;

	/*
 * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
 * have the write-low and read-high bitmap offsets the wrong way round.
 * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
 */
	if (msr <= 0x1fff) {
		if (type & MSR_TYPE_R)
			/* read-low */
			__set_bit(msr, msr_bitmap + 0x000 / f);

		if (type & MSR_TYPE_W)
			/* write-low */
			__set_bit(msr, msr_bitmap + 0x800 / f);

	} else if ((msr >= 0xc0000000) && (msr <= 0xc0001fff)) {
		msr &= 0x1fff;
		if (type & MSR_TYPE_R)
			/* read-high */
			__set_bit(msr, msr_bitmap + 0x400 / f);

		if (type & MSR_TYPE_W)
			/* write-high */
			__set_bit(msr, msr_bitmap + 0xc00 / f);

	}
}

/*
 * If a msr is allowed by L0, we should check whether it is allowed by L1.
 * The corresponding bit will be cleared unless both of L0 and L1 allow it.
 */
static void nested_vmx_disable_intercept_for_msr(unsigned long *msr_bitmap_l1,
					       unsigned long *msr_bitmap_nested,
					       u32 msr, int type)
{
	int f = sizeof(unsigned long);

	if (!cpu_has_vmx_msr_bitmap()) {
		WARN_ON(1);
		return;
	}

	/*
 * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
 * have the write-low and read-high bitmap offsets the wrong way round.
 * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
 */
	if (msr <= 0x1fff) {
		if (type & MSR_TYPE_R &&
		   !test_bit(msr, msr_bitmap_l1 + 0x000 / f))
			/* read-low */
			__clear_bit(msr, msr_bitmap_nested + 0x000 / f);

		if (type & MSR_TYPE_W &&
		   !test_bit(msr, msr_bitmap_l1 + 0x800 / f))
			/* write-low */
			__clear_bit(msr, msr_bitmap_nested + 0x800 / f);

	} else if ((msr >= 0xc0000000) && (msr <= 0xc0001fff)) {
		msr &= 0x1fff;
		if (type & MSR_TYPE_R &&
		   !test_bit(msr, msr_bitmap_l1 + 0x400 / f))
			/* read-high */
			__clear_bit(msr, msr_bitmap_nested + 0x400 / f);

		if (type & MSR_TYPE_W &&
		   !test_bit(msr, msr_bitmap_l1 + 0xc00 / f))
			/* write-high */
			__clear_bit(msr, msr_bitmap_nested + 0xc00 / f);

	}
}

static void vmx_disable_intercept_for_msr(u32 msr, bool longmode_only)
{
	if (!longmode_only)
		__vmx_disable_intercept_for_msr(vmx_msr_bitmap_legacy,
						msr, MSR_TYPE_R | MSR_TYPE_W);
	__vmx_disable_intercept_for_msr(vmx_msr_bitmap_longmode,
						msr, MSR_TYPE_R | MSR_TYPE_W);
}

static void vmx_enable_intercept_msr_read_x2apic(u32 msr)
{
	__vmx_enable_intercept_for_msr(vmx_msr_bitmap_legacy_x2apic,
			msr, MSR_TYPE_R);
	__vmx_enable_intercept_for_msr(vmx_msr_bitmap_longmode_x2apic,
			msr, MSR_TYPE_R);
}

static void vmx_disable_intercept_msr_read_x2apic(u32 msr)
{
	__vmx_disable_intercept_for_msr(vmx_msr_bitmap_legacy_x2apic,
			msr, MSR_TYPE_R);
	__vmx_disable_intercept_for_msr(vmx_msr_bitmap_longmode_x2apic,
			msr, MSR_TYPE_R);
}

static void vmx_disable_intercept_msr_write_x2apic(u32 msr)
{
	__vmx_disable_intercept_for_msr(vmx_msr_bitmap_legacy_x2apic,
			msr, MSR_TYPE_W);
	__vmx_disable_intercept_for_msr(vmx_msr_bitmap_longmode_x2apic,
			msr, MSR_TYPE_W);
}

static bool vmx_get_enable_apicv(void)
{
	return enable_apicv;
}

static int vmx_complete_nested_posted_interrupt(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int max_irr;
	void *vapic_page;
	u16 status;

	if (vmx->nested.pi_desc &&
	    vmx->nested.pi_pending) {
		vmx->nested.pi_pending = false;
		if (!pi_test_and_clear_on(vmx->nested.pi_desc))
			return 0;

		max_irr = find_last_bit(
			(unsigned long *)vmx->nested.pi_desc->pir, 256);

		if (max_irr == 256)
			return 0;

		vapic_page = kmap(vmx->nested.virtual_apic_page);
		if (!vapic_page) {
			WARN_ON(1);
			return -ENOMEM;
		}
		__kvm_apic_update_irr(vmx->nested.pi_desc->pir, vapic_page);
		kunmap(vmx->nested.virtual_apic_page);

		status = vmcs_read16(GUEST_INTR_STATUS);
		if ((u8)max_irr > ((u8)status & 0xff)) {
			status &= ~0xff;
			status |= (u8)max_irr;
			vmcs_write16(GUEST_INTR_STATUS, status);
		}
	}
	return 0;
}

static inline bool kvm_vcpu_trigger_posted_interrupt(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_SMP
	if (vcpu->mode == IN_GUEST_MODE) {
		struct vcpu_vmx *vmx = to_vmx(vcpu);

		/*
 * Currently, we don't support urgent interrupt,
 * all interrupts are recognized as non-urgent
 * interrupt, so we cannot post interrupts when
 * 'SN' is set.
 *
 * If the vcpu is in guest mode, it means it is
 * running instead of being scheduled out and
 * waiting in the run queue, and that's the only
 * case when 'SN' is set currently, warning if
 * 'SN' is set.
 */
		WARN_ON_ONCE(pi_test_sn(&vmx->pi_desc));

		apic->send_IPI_mask(get_cpu_mask(vcpu->cpu),
				POSTED_INTR_VECTOR);
		return true;
	}
#endif
	return false;
}

static int vmx_deliver_nested_posted_interrupt(struct kvm_vcpu *vcpu,
						int vector)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (is_guest_mode(vcpu) &&
	    vector == vmx->nested.posted_intr_nv) {
		/* the PIR and ON have been set by L1. */
		kvm_vcpu_trigger_posted_interrupt(vcpu);
		/*
 * If a posted intr is not recognized by hardware,
 * we will accomplish it in the next vmentry.
 */
		vmx->nested.pi_pending = true;
		kvm_make_request(KVM_REQ_EVENT, vcpu);
		return 0;
	}
	return -1;
}
/*
 * Send interrupt to vcpu via posted interrupt way.
 * 1. If target vcpu is running(non-root mode), send posted interrupt
 * notification to vcpu and hardware will sync PIR to vIRR atomically.
 * 2. If target vcpu isn't running(root mode), kick it to pick up the
 * interrupt from PIR in next vmentry.
 */
static void vmx_deliver_posted_interrupt(struct kvm_vcpu *vcpu, int vector)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int r;

	r = vmx_deliver_nested_posted_interrupt(vcpu, vector);
	if (!r)
		return;

	if (pi_test_and_set_pir(vector, &vmx->pi_desc))
		return;

	r = pi_test_and_set_on(&vmx->pi_desc);
	kvm_make_request(KVM_REQ_EVENT, vcpu);
	if (r || !kvm_vcpu_trigger_posted_interrupt(vcpu))
		kvm_vcpu_kick(vcpu);
}

static void vmx_sync_pir_to_irr(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (!pi_test_and_clear_on(&vmx->pi_desc))
		return;

	kvm_apic_update_irr(vcpu, vmx->pi_desc.pir);
}

/*
 * Set up the vmcs's constant host-state fields, i.e., host-state fields that
 * will not change in the lifetime of the guest.
 * Note that host-state that does change is set elsewhere. E.g., host-state
 * that is set differently for each CPU is set in vmx_vcpu_load(), not here.
 */
static void vmx_set_constant_host_state(struct vcpu_vmx *vmx)
{
	u32 low32, high32;
	unsigned long tmpl;
	struct desc_ptr dt;
	unsigned long cr4;

	vmcs_writel(HOST_CR0, read_cr0() & ~X86_CR0_TS);  /* 22.2.3 */
	vmcs_writel(HOST_CR3, read_cr3());  /* 22.2.3 FIXME: shadow tables */

	/* Save the most likely value for this task's CR4 in the VMCS. */
	cr4 = cr4_read_shadow();
	vmcs_writel(HOST_CR4, cr4);			/* 22.2.3, 22.2.5 */
	vmx->host_state.vmcs_host_cr4 = cr4;

	vmcs_write16(HOST_CS_SELECTOR, __KERNEL_CS);  /* 22.2.4 */
#ifdef CONFIG_X86_64
	/*
 * Load null selectors, so we can avoid reloading them in
 * __vmx_load_host_state(), in case userspace uses the null selectors
 * too (the expected case).
 */
	vmcs_write16(HOST_DS_SELECTOR, 0);
	vmcs_write16(HOST_ES_SELECTOR, 0);
#else
	vmcs_write16(HOST_DS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_ES_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
#endif
	vmcs_write16(HOST_SS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_TR_SELECTOR, GDT_ENTRY_TSS*8);  /* 22.2.4 */

	native_store_idt(&dt);
	vmcs_writel(HOST_IDTR_BASE, dt.address);   /* 22.2.4 */
	vmx->host_idt_base = dt.address;

	vmcs_writel(HOST_RIP, vmx_return); /* 22.2.5 */

	rdmsr(MSR_IA32_SYSENTER_CS, low32, high32);
	vmcs_write32(HOST_IA32_SYSENTER_CS, low32);
	rdmsrl(MSR_IA32_SYSENTER_EIP, tmpl);
	vmcs_writel(HOST_IA32_SYSENTER_EIP, tmpl);   /* 22.2.3 */

	if (vmcs_config.vmexit_ctrl & VM_EXIT_LOAD_IA32_PAT) {
		rdmsr(MSR_IA32_CR_PAT, low32, high32);
		vmcs_write64(HOST_IA32_PAT, low32 | ((u64) high32 << 32));
	}
}

static void set_cr4_guest_host_mask(struct vcpu_vmx *vmx)
{
	vmx->vcpu.arch.cr4_guest_owned_bits = KVM_CR4_GUEST_OWNED_BITS;
	if (enable_ept)
		vmx->vcpu.arch.cr4_guest_owned_bits |= X86_CR4_PGE;
	if (is_guest_mode(&vmx->vcpu))
		vmx->vcpu.arch.cr4_guest_owned_bits &=
			~get_vmcs12(&vmx->vcpu)->cr4_guest_host_mask;
	vmcs_writel(CR4_GUEST_HOST_MASK, ~vmx->vcpu.arch.cr4_guest_owned_bits);
}

static u32 vmx_pin_based_exec_ctrl(struct vcpu_vmx *vmx)
{
	u32 pin_based_exec_ctrl = vmcs_config.pin_based_exec_ctrl;

	if (!kvm_vcpu_apicv_active(&vmx->vcpu))
		pin_based_exec_ctrl &= ~PIN_BASED_POSTED_INTR;
	return pin_based_exec_ctrl;
}

static void vmx_refresh_apicv_exec_ctrl(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, vmx_pin_based_exec_ctrl(vmx));
}

static u32 vmx_exec_control(struct vcpu_vmx *vmx)
{
	u32 exec_control = vmcs_config.cpu_based_exec_ctrl;

	if (vmx->vcpu.arch.switch_db_regs & KVM_DEBUGREG_WONT_EXIT)
		exec_control &= ~CPU_BASED_MOV_DR_EXITING;

	if (!cpu_need_tpr_shadow(&vmx->vcpu)) {
		exec_control &= ~CPU_BASED_TPR_SHADOW;
#ifdef CONFIG_X86_64
		exec_control |= CPU_BASED_CR8_STORE_EXITING |
				CPU_BASED_CR8_LOAD_EXITING;
#endif
	}
	if (!enable_ept)
		exec_control |= CPU_BASED_CR3_STORE_EXITING |
				CPU_BASED_CR3_LOAD_EXITING  |
				CPU_BASED_INVLPG_EXITING;
	return exec_control;
}

static u32 vmx_secondary_exec_control(struct vcpu_vmx *vmx)
{
	u32 exec_control = vmcs_config.cpu_based_2nd_exec_ctrl;
	if (!cpu_need_virtualize_apic_accesses(&vmx->vcpu))
		exec_control &= ~SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
	if (vmx->vpid == 0)
		exec_control &= ~SECONDARY_EXEC_ENABLE_VPID;
	if (!enable_ept) {
		exec_control &= ~SECONDARY_EXEC_ENABLE_EPT;
		enable_unrestricted_guest = 0;
		/* Enable INVPCID for non-ept guests may cause performance regression. */
		exec_control &= ~SECONDARY_EXEC_ENABLE_INVPCID;
	}
	if (!enable_unrestricted_guest)
		exec_control &= ~SECONDARY_EXEC_UNRESTRICTED_GUEST;
	if (!ple_gap)
		exec_control &= ~SECONDARY_EXEC_PAUSE_LOOP_EXITING;
	if (!kvm_vcpu_apicv_active(&vmx->vcpu))
		exec_control &= ~(SECONDARY_EXEC_APIC_REGISTER_VIRT |
				  SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY);
	exec_control &= ~SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE;
	/* SECONDARY_EXEC_SHADOW_VMCS is enabled when L1 executes VMPTRLD
 (handle_vmptrld).
 We can NOT enable shadow_vmcs here because we don't have yet
 a current VMCS12
 */
	exec_control &= ~SECONDARY_EXEC_SHADOW_VMCS;

	if (!enable_pml)
		exec_control &= ~SECONDARY_EXEC_ENABLE_PML;

	/* Currently, we allow L1 guest to directly run pcommit instruction. */
	exec_control &= ~SECONDARY_EXEC_PCOMMIT;

	return exec_control;
}

static void ept_set_mmio_spte_mask(void)
{
	/*
 * EPT Misconfigurations can be generated if the value of bits 2:0
 * of an EPT paging-structure entry is 110b (write/execute).
 * Also, magic bits (0x3ull << 62) is set to quickly identify mmio
 * spte.
 */
	kvm_mmu_set_mmio_spte_mask((0x3ull << 62) | 0x6ull);
}

#define VMX_XSS_EXIT_BITMAP 0
/*
 * Sets up the vmcs for emulated real mode.
 */
static int vmx_vcpu_setup(struct vcpu_vmx *vmx)
{
#ifdef CONFIG_X86_64
	unsigned long a;
#endif
	int i;

	/* I/O */
	vmcs_write64(IO_BITMAP_A, __pa(vmx_io_bitmap_a));
	vmcs_write64(IO_BITMAP_B, __pa(vmx_io_bitmap_b));

	if (enable_shadow_vmcs) {
		vmcs_write64(VMREAD_BITMAP, __pa(vmx_vmread_bitmap));
		vmcs_write64(VMWRITE_BITMAP, __pa(vmx_vmwrite_bitmap));
	}
	if (cpu_has_vmx_msr_bitmap())
		vmcs_write64(MSR_BITMAP, __pa(vmx_msr_bitmap_legacy));

	vmcs_write64(VMCS_LINK_POINTER, -1ull); /* 22.3.1.5 */

	/* Control */
	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, vmx_pin_based_exec_ctrl(vmx));

	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, vmx_exec_control(vmx));

	if (cpu_has_secondary_exec_ctrls())
		vmcs_write32(SECONDARY_VM_EXEC_CONTROL,
				vmx_secondary_exec_control(vmx));

	if (kvm_vcpu_apicv_active(&vmx->vcpu)) {
		vmcs_write64(EOI_EXIT_BITMAP0, 0);
		vmcs_write64(EOI_EXIT_BITMAP1, 0);
		vmcs_write64(EOI_EXIT_BITMAP2, 0);
		vmcs_write64(EOI_EXIT_BITMAP3, 0);

		vmcs_write16(GUEST_INTR_STATUS, 0);

		vmcs_write16(POSTED_INTR_NV, POSTED_INTR_VECTOR);
		vmcs_write64(POSTED_INTR_DESC_ADDR, __pa((&vmx->pi_desc)));
	}

	if (ple_gap) {
		vmcs_write32(PLE_GAP, ple_gap);
		vmx->ple_window = ple_window;
		vmx->ple_window_dirty = true;
	}

	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, 0);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	vmcs_write32(CR3_TARGET_COUNT, 0);           /* 22.2.1 */

	vmcs_write16(HOST_FS_SELECTOR, 0);            /* 22.2.4 */
	vmcs_write16(HOST_GS_SELECTOR, 0);            /* 22.2.4 */
	vmx_set_constant_host_state(vmx);
#ifdef CONFIG_X86_64
	rdmsrl(MSR_FS_BASE, a);
	vmcs_writel(HOST_FS_BASE, a); /* 22.2.4 */
	rdmsrl(MSR_GS_BASE, a);
	vmcs_writel(HOST_GS_BASE, a); /* 22.2.4 */
#else
	vmcs_writel(HOST_FS_BASE, 0); /* 22.2.4 */
	vmcs_writel(HOST_GS_BASE, 0); /* 22.2.4 */
#endif

	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, 0);
	vmcs_write64(VM_EXIT_MSR_LOAD_ADDR, __pa(vmx->msr_autoload.host));
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);
	vmcs_write64(VM_ENTRY_MSR_LOAD_ADDR, __pa(vmx->msr_autoload.guest));

	if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT)
		vmcs_write64(GUEST_IA32_PAT, vmx->vcpu.arch.pat);

	for (i = 0; i < ARRAY_SIZE(vmx_msr_index); ++i) {
		u32 index = vmx_msr_index[i];
		u32 data_low, data_high;
		int j = vmx->nmsrs;

		if (rdmsr_safe(index, &data_low, &data_high) < 0)
			continue;
		if (wrmsr_safe(index, data_low, data_high) < 0)
			continue;
		vmx->guest_msrs[j].index = i;
		vmx->guest_msrs[j].data = 0;
		vmx->guest_msrs[j].mask = -1ull;
		++vmx->nmsrs;
	}


	vm_exit_controls_init(vmx, vmcs_config.vmexit_ctrl);

	/* 22.2.1, 20.8.1 */
	vm_entry_controls_init(vmx, vmcs_config.vmentry_ctrl);

	vmcs_writel(CR0_GUEST_HOST_MASK, ~0UL);
	set_cr4_guest_host_mask(vmx);

	if (vmx_xsaves_supported())
		vmcs_write64(XSS_EXIT_BITMAP, VMX_XSS_EXIT_BITMAP);

	return 0;
}

static void vmx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct msr_data apic_base_msr;
	u64 cr0;

	vmx->rmode.vm86_active = 0;

	vmx->soft_vnmi_blocked = 0;

	vmx->vcpu.arch.regs[VCPU_REGS_RDX] = get_rdx_init_val();
	kvm_set_cr8(vcpu, 0);

	if (!init_event) {
		apic_base_msr.data = APIC_DEFAULT_PHYS_BASE |
				     MSR_IA32_APICBASE_ENABLE;
		if (kvm_vcpu_is_reset_bsp(vcpu))
			apic_base_msr.data |= MSR_IA32_APICBASE_BSP;
		apic_base_msr.host_initiated = true;
		kvm_set_apic_base(vcpu, &apic_base_msr);
	}

	vmx_segment_cache_clear(vmx);

	seg_setup(VCPU_SREG_CS);
	vmcs_write16(GUEST_CS_SELECTOR, 0xf000);
	vmcs_writel(GUEST_CS_BASE, 0xffff0000ul);

	seg_setup(VCPU_SREG_DS);
	seg_setup(VCPU_SREG_ES);
	seg_setup(VCPU_SREG_FS);
	seg_setup(VCPU_SREG_GS);
	seg_setup(VCPU_SREG_SS);

	vmcs_write16(GUEST_TR_SELECTOR, 0);
	vmcs_writel(GUEST_TR_BASE, 0);
	vmcs_write32(GUEST_TR_LIMIT, 0xffff);
	vmcs_write32(GUEST_TR_AR_BYTES, 0x008b);

	vmcs_write16(GUEST_LDTR_SELECTOR, 0);
	vmcs_writel(GUEST_LDTR_BASE, 0);
	vmcs_write32(GUEST_LDTR_LIMIT, 0xffff);
	vmcs_write32(GUEST_LDTR_AR_BYTES, 0x00082);

	if (!init_event) {
		vmcs_write32(GUEST_SYSENTER_CS, 0);
		vmcs_writel(GUEST_SYSENTER_ESP, 0);
		vmcs_writel(GUEST_SYSENTER_EIP, 0);
		vmcs_write64(GUEST_IA32_DEBUGCTL, 0);
	}

	vmcs_writel(GUEST_RFLAGS, 0x02);
	kvm_rip_write(vcpu, 0xfff0);

	vmcs_writel(GUEST_GDTR_BASE, 0);
	vmcs_write32(GUEST_GDTR_LIMIT, 0xffff);

	vmcs_writel(GUEST_IDTR_BASE, 0);
	vmcs_write32(GUEST_IDTR_LIMIT, 0xffff);

	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS, 0);

	setup_msrs(vmx);

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);  /* 22.2.1 */

	if (cpu_has_vmx_tpr_shadow() && !init_event) {
		vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, 0);
		if (cpu_need_tpr_shadow(vcpu))
			vmcs_write64(VIRTUAL_APIC_PAGE_ADDR,
				     __pa(vcpu->arch.apic->regs));
		vmcs_write32(TPR_THRESHOLD, 0);
	}

	kvm_make_request(KVM_REQ_APIC_PAGE_RELOAD, vcpu);

	if (kvm_vcpu_apicv_active(vcpu))
		memset(&vmx->pi_desc, 0, sizeof(struct pi_desc));

	if (vmx->vpid != 0)
		vmcs_write16(VIRTUAL_PROCESSOR_ID, vmx->vpid);

	cr0 = X86_CR0_NW | X86_CR0_CD | X86_CR0_ET;
	vmx->vcpu.arch.cr0 = cr0;
	vmx_set_cr0(vcpu, cr0); /* enter rmode */
	vmx_set_cr4(vcpu, 0);
	vmx_set_efer(vcpu, 0);
	vmx_fpu_activate(vcpu);
	update_exception_bitmap(vcpu);

	vpid_sync_context(vmx->vpid);
}

/*
 * In nested virtualization, check if L1 asked to exit on external interrupts.
 * For most existing hypervisors, this will always return true.
 */
static bool nested_exit_on_intr(struct kvm_vcpu *vcpu)
{
	return get_vmcs12(vcpu)->pin_based_vm_exec_control &
		PIN_BASED_EXT_INTR_MASK;
}

/*
 * In nested virtualization, check if L1 has set
 * VM_EXIT_ACK_INTR_ON_EXIT
 */
static bool nested_exit_intr_ack_set(struct kvm_vcpu *vcpu)
{
	return get_vmcs12(vcpu)->vm_exit_controls &
		VM_EXIT_ACK_INTR_ON_EXIT;
}

static bool nested_exit_on_nmi(struct kvm_vcpu *vcpu)
{
	return get_vmcs12(vcpu)->pin_based_vm_exec_control &
		PIN_BASED_NMI_EXITING;
}

static void enable_irq_window(struct kvm_vcpu *vcpu)
{
	u32 cpu_based_vm_exec_control;

	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control |= CPU_BASED_VIRTUAL_INTR_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);
}

static void enable_nmi_window(struct kvm_vcpu *vcpu)
{
	u32 cpu_based_vm_exec_control;

	if (!cpu_has_virtual_nmis() ||
	    vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) & GUEST_INTR_STATE_STI) {
		enable_irq_window(vcpu);
		return;
	}

	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control |= CPU_BASED_VIRTUAL_NMI_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);
}

static void vmx_inject_irq(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	uint32_t intr;
	int irq = vcpu->arch.interrupt.nr;

	trace_kvm_inj_virq(irq);

	++vcpu->stat.irq_injections;
	if (vmx->rmode.vm86_active) {
		int inc_eip = 0;
		if (vcpu->arch.interrupt.soft)
			inc_eip = vcpu->arch.event_exit_inst_len;
		if (kvm_inject_realmode_interrupt(vcpu, irq, inc_eip) != EMULATE_DONE)
			kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		return;
	}
	intr = irq | INTR_INFO_VALID_MASK;
	if (vcpu->arch.interrupt.soft) {
		intr |= INTR_TYPE_SOFT_INTR;
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
			     vmx->vcpu.arch.event_exit_inst_len);
	} else
		intr |= INTR_TYPE_EXT_INTR;
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr);
}

static void vmx_inject_nmi(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (is_guest_mode(vcpu))
		return;

	if (!cpu_has_virtual_nmis()) {
		/*
 * Tracking the NMI-blocked state in software is built upon
 * finding the next open IRQ window. This, in turn, depends on
 * well-behaving guests: They have to keep IRQs disabled at
 * least as long as the NMI handler runs. Otherwise we may
 * cause NMI nesting, maybe breaking the guest. But as this is
 * highly unlikely, we can live with the residual risk.
 */
		vmx->soft_vnmi_blocked = 1;
		vmx->vnmi_blocked_time = 0;
	}

	++vcpu->stat.nmi_injections;
	vmx->nmi_known_unmasked = false;
	if (vmx->rmode.vm86_active) {
		if (kvm_inject_realmode_interrupt(vcpu, NMI_VECTOR, 0) != EMULATE_DONE)
			kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		return;
	}
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
			INTR_TYPE_NMI_INTR | INTR_INFO_VALID_MASK | NMI_VECTOR);
}

static bool vmx_get_nmi_mask(struct kvm_vcpu *vcpu)
{
	if (!cpu_has_virtual_nmis())
		return to_vmx(vcpu)->soft_vnmi_blocked;
	if (to_vmx(vcpu)->nmi_known_unmasked)
		return false;
	return vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) & GUEST_INTR_STATE_NMI;
}

static void vmx_set_nmi_mask(struct kvm_vcpu *vcpu, bool masked)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (!cpu_has_virtual_nmis()) {
		if (vmx->soft_vnmi_blocked != masked) {
			vmx->soft_vnmi_blocked = masked;
			vmx->vnmi_blocked_time = 0;
		}
	} else {
		vmx->nmi_known_unmasked = !masked;
		if (masked)
			vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO,
				      GUEST_INTR_STATE_NMI);
		else
			vmcs_clear_bits(GUEST_INTERRUPTIBILITY_INFO,
					GUEST_INTR_STATE_NMI);
	}
}

static int vmx_nmi_allowed(struct kvm_vcpu *vcpu)
{
	if (to_vmx(vcpu)->nested.nested_run_pending)
		return 0;

	if (!cpu_has_virtual_nmis() && to_vmx(vcpu)->soft_vnmi_blocked)
		return 0;

	return	!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
		  (GUEST_INTR_STATE_MOV_SS | GUEST_INTR_STATE_STI
		   | GUEST_INTR_STATE_NMI));
}

static int vmx_interrupt_allowed(struct kvm_vcpu *vcpu)
{
	return (!to_vmx(vcpu)->nested.nested_run_pending &&
		vmcs_readl(GUEST_RFLAGS) & X86_EFLAGS_IF) &&
		!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
			(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS));
}

static int vmx_set_tss_addr(struct kvm *kvm, unsigned int addr)
{
	int ret;

	ret = x86_set_memory_region(kvm, TSS_PRIVATE_MEMSLOT, addr,
				    PAGE_SIZE * 3);
	if (ret)
		return ret;
	kvm->arch.tss_addr = addr;
	return init_rmode_tss(kvm);
}

static bool rmode_exception(struct kvm_vcpu *vcpu, int vec)
{
	switch (vec) {
	case BP_VECTOR:
		/*
 * Update instruction length as we may reinject the exception
 * from user space while in guest debugging mode.
 */
		to_vmx(vcpu)->vcpu.arch.event_exit_inst_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP)
			return false;
		/* fall through */
	case DB_VECTOR:
		if (vcpu->guest_debug &
			(KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP))
			return false;
		/* fall through */
	case DE_VECTOR:
	case OF_VECTOR:
	case BR_VECTOR:
	case UD_VECTOR:
	case DF_VECTOR:
	case SS_VECTOR:
	case GP_VECTOR:
	case MF_VECTOR:
		return true;
	break;
	}
	return false;
}

static int handle_rmode_exception(struct kvm_vcpu *vcpu,
				  int vec, u32 err_code)
{
	/*
 * Instruction with address size override prefix opcode 0x67
 * Cause the #SS fault with 0 error code in VM86 mode.
 */
	if (((vec == GP_VECTOR) || (vec == SS_VECTOR)) && err_code == 0) {
		if (emulate_instruction(vcpu, 0) == EMULATE_DONE) {
			if (vcpu->arch.halt_request) {
				vcpu->arch.halt_request = 0;
				return kvm_vcpu_halt(vcpu);
			}
			return 1;
		}
		return 0;
	}

	/*
 * Forward all other exceptions that are valid in real mode.
 * FIXME: Breaks guest debugging in real mode, needs to be fixed with
 * the required debugging infrastructure rework.
 */
	kvm_queue_exception(vcpu, vec);
	return 1;
}

/*
 * Trigger machine check on the host. We assume all the MSRs are already set up
 * by the CPU and that we still run on the same CPU as the MCE occurred on.
 * We pass a fake environment to the machine check handler because we want
 * the guest to be always treated like user space, no matter what context
 * it used internally.
 */
static void kvm_machine_check(void)
{
#if defined(CONFIG_X86_MCE) && defined(CONFIG_X86_64)
	struct pt_regs regs = {
		.cs = 3, /* Fake ring 3 no matter what the guest ran on */
		.flags = X86_EFLAGS_IF,
	};

	do_machine_check(&regs, 0);
#endif
}

static int handle_machine_check(struct kvm_vcpu *vcpu)
{
	/* already handled by vcpu_run */
	return 1;
}

static int handle_exception(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm_run *kvm_run = vcpu->run;
	u32 intr_info, ex_no, error_code;
	unsigned long cr2, rip, dr6;
	u32 vect_info;
	enum emulation_result er;

	vect_info = vmx->idt_vectoring_info;
	intr_info = vmx->exit_intr_info;

	if (is_machine_check(intr_info))
		return handle_machine_check(vcpu);

	if ((intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR)
		return 1;  /* already handled by vmx_vcpu_run() */

	if (is_no_device(intr_info)) {
		vmx_fpu_activate(vcpu);
		return 1;
	}

	if (is_invalid_opcode(intr_info)) {
		if (is_guest_mode(vcpu)) {
			kvm_queue_exception(vcpu, UD_VECTOR);
			return 1;
		}
		er = emulate_instruction(vcpu, EMULTYPE_TRAP_UD);
		if (er != EMULATE_DONE)
			kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	error_code = 0;
	if (intr_info & INTR_INFO_DELIVER_CODE_MASK)
		error_code = vmcs_read32(VM_EXIT_INTR_ERROR_CODE);

	/*
 * The #PF with PFEC.RSVD = 1 indicates the guest is accessing
 * MMIO, it is better to report an internal error.
 * See the comments in vmx_handle_exit.
 */
	if ((vect_info & VECTORING_INFO_VALID_MASK) &&
	    !(is_page_fault(intr_info) && !(error_code & PFERR_RSVD_MASK))) {
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_SIMUL_EX;
		vcpu->run->internal.ndata = 3;
		vcpu->run->internal.data[0] = vect_info;
		vcpu->run->internal.data[1] = intr_info;
		vcpu->run->internal.data[2] = error_code;
		return 0;
	}

	if (is_page_fault(intr_info)) {
		/* EPT won't cause page fault directly */
		BUG_ON(enable_ept);
		cr2 = vmcs_readl(EXIT_QUALIFICATION);
		trace_kvm_page_fault(cr2, error_code);

		if (kvm_event_needs_reinjection(vcpu))
			kvm_mmu_unprotect_page_virt(vcpu, cr2);
		return kvm_mmu_page_fault(vcpu, cr2, error_code, NULL, 0);
	}

	ex_no = intr_info & INTR_INFO_VECTOR_MASK;

	if (vmx->rmode.vm86_active && rmode_exception(vcpu, ex_no))
		return handle_rmode_exception(vcpu, ex_no, error_code);

	switch (ex_no) {
	case AC_VECTOR:
		kvm_queue_exception_e(vcpu, AC_VECTOR, error_code);
		return 1;
	case DB_VECTOR:
		dr6 = vmcs_readl(EXIT_QUALIFICATION);
		if (!(vcpu->guest_debug &
		      (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP))) {
			vcpu->arch.dr6 &= ~15;
			vcpu->arch.dr6 |= dr6 | DR6_RTM;
			if (!(dr6 & ~DR6_RESERVED)) /* icebp */
				skip_emulated_instruction(vcpu);

			kvm_queue_exception(vcpu, DB_VECTOR);
			return 1;
		}
		kvm_run->debug.arch.dr6 = dr6 | DR6_FIXED_1;
		kvm_run->debug.arch.dr7 = vmcs_readl(GUEST_DR7);
		/* fall through */
	case BP_VECTOR:
		/*
 * Update instruction length as we may reinject #BP from
 * user space while in guest debugging mode. Reading it for
 * #DB as well causes no harm, it is not used in that case.
 */
		vmx->vcpu.arch.event_exit_inst_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		kvm_run->exit_reason = KVM_EXIT_DEBUG;
		rip = kvm_rip_read(vcpu);
		kvm_run->debug.arch.pc = vmcs_readl(GUEST_CS_BASE) + rip;
		kvm_run->debug.arch.exception = ex_no;
		break;
	default:
		kvm_run->exit_reason = KVM_EXIT_EXCEPTION;
		kvm_run->ex.exception = ex_no;
		kvm_run->ex.error_code = error_code;
		break;
	}
	return 0;
}

static int handle_external_interrupt(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.irq_exits;
	return 1;
}

static int handle_triple_fault(struct kvm_vcpu *vcpu)
{
	vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
	return 0;
}

static int handle_io(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	int size, in, string;
	unsigned port;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	string = (exit_qualification & 16) != 0;
	in = (exit_qualification & 8) != 0;

	++vcpu->stat.io_exits;

	if (string || in)
		return emulate_instruction(vcpu, 0) == EMULATE_DONE;

	port = exit_qualification >> 16;
	size = (exit_qualification & 7) + 1;
	skip_emulated_instruction(vcpu);

	return kvm_fast_pio_out(vcpu, size, port);
}

static void
vmx_patch_hypercall(struct kvm_vcpu *vcpu, unsigned char *hypercall)
{
	/*
 * Patch in the VMCALL instruction:
 */
	hypercall[0] = 0x0f;
	hypercall[1] = 0x01;
	hypercall[2] = 0xc1;
}

static bool nested_cr0_valid(struct kvm_vcpu *vcpu, unsigned long val)
{
	unsigned long always_on = VMXON_CR0_ALWAYSON;
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);

	if (to_vmx(vcpu)->nested.nested_vmx_secondary_ctls_high &
		SECONDARY_EXEC_UNRESTRICTED_GUEST &&
	    nested_cpu_has2(vmcs12, SECONDARY_EXEC_UNRESTRICTED_GUEST))
		always_on &= ~(X86_CR0_PE | X86_CR0_PG);
	return (val & always_on) == always_on;
}

/* called to set cr0 as appropriate for a mov-to-cr0 exit. */
static int handle_set_cr0(struct kvm_vcpu *vcpu, unsigned long val)
{
	if (is_guest_mode(vcpu)) {
		struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
		unsigned long orig_val = val;

		/*
 * We get here when L2 changed cr0 in a way that did not change
 * any of L1's shadowed bits (see nested_vmx_exit_handled_cr),
 * but did change L0 shadowed bits. So we first calculate the
 * effective cr0 value that L1 would like to write into the
 * hardware. It consists of the L2-owned bits from the new
 * value combined with the L1-owned bits from L1's guest_cr0.
 */
		val = (val & ~vmcs12->cr0_guest_host_mask) |
			(vmcs12->guest_cr0 & vmcs12->cr0_guest_host_mask);

		if (!nested_cr0_valid(vcpu, val))
			return 1;

		if (kvm_set_cr0(vcpu, val))
			return 1;
		vmcs_writel(CR0_READ_SHADOW, orig_val);
		return 0;
	} else {
		if (to_vmx(vcpu)->nested.vmxon &&
		    ((val & VMXON_CR0_ALWAYSON) != VMXON_CR0_ALWAYSON))
			return 1;
		return kvm_set_cr0(vcpu, val);
	}
}

static int handle_set_cr4(struct kvm_vcpu *vcpu, unsigned long val)
{
	if (is_guest_mode(vcpu)) {
		struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
		unsigned long orig_val = val;

		/* analogously to handle_set_cr0 */
		val = (val & ~vmcs12->cr4_guest_host_mask) |
			(vmcs12->guest_cr4 & vmcs12->cr4_guest_host_mask);
		if (kvm_set_cr4(vcpu, val))
			return 1;
		vmcs_writel(CR4_READ_SHADOW, orig_val);
		return 0;
	} else
		return kvm_set_cr4(vcpu, val);
}

/* called to set cr0 as appropriate for clts instruction exit. */
static void handle_clts(struct kvm_vcpu *vcpu)
{
	if (is_guest_mode(vcpu)) {
		/*
 * We get here when L2 did CLTS, and L1 didn't shadow CR0.TS
 * but we did (!fpu_active). We need to keep GUEST_CR0.TS on,
 * just pretend it's off (also in arch.cr0 for fpu_activate).
 */
		vmcs_writel(CR0_READ_SHADOW,
			vmcs_readl(CR0_READ_SHADOW) & ~X86_CR0_TS);
		vcpu->arch.cr0 &= ~X86_CR0_TS;
	} else
		vmx_set_cr0(vcpu, kvm_read_cr0_bits(vcpu, ~X86_CR0_TS));
}

static int handle_cr(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification, val;
	int cr;
	int reg;
	int err;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	cr = exit_qualification & 15;
	reg = (exit_qualification >> 8) & 15;
	switch ((exit_qualification >> 4) & 3) {
	case 0: /* mov to cr */
		val = kvm_register_readl(vcpu, reg);
		trace_kvm_cr_write(cr, val);
		switch (cr) {
		case 0:
			err = handle_set_cr0(vcpu, val);
			kvm_complete_insn_gp(vcpu, err);
			return 1;
		case 3:
			err = kvm_set_cr3(vcpu, val);
			kvm_complete_insn_gp(vcpu, err);
			return 1;
		case 4:
			err = handle_set_cr4(vcpu, val);
			kvm_complete_insn_gp(vcpu, err);
			return 1;
		case 8: {
				u8 cr8_prev = kvm_get_cr8(vcpu);
				u8 cr8 = (u8)val;
				err = kvm_set_cr8(vcpu, cr8);
				kvm_complete_insn_gp(vcpu, err);
				if (lapic_in_kernel(vcpu))
					return 1;
				if (cr8_prev <= cr8)
					return 1;
				vcpu->run->exit_reason = KVM_EXIT_SET_TPR;
				return 0;
			}
		}
		break;
	case 2: /* clts */
		handle_clts(vcpu);
		trace_kvm_cr_write(0, kvm_read_cr0(vcpu));
		skip_emulated_instruction(vcpu);
		vmx_fpu_activate(vcpu);
		return 1;
	case 1: /*mov from cr*/
		switch (cr) {
		case 3:
			val = kvm_read_cr3(vcpu);
			kvm_register_write(vcpu, reg, val);
			trace_kvm_cr_read(cr, val);
			skip_emulated_instruction(vcpu);
			return 1;
		case 8:
			val = kvm_get_cr8(vcpu);
			kvm_register_write(vcpu, reg, val);
			trace_kvm_cr_read(cr, val);
			skip_emulated_instruction(vcpu);
			return 1;
		}
		break;
	case 3: /* lmsw */
		val = (exit_qualification >> LMSW_SOURCE_DATA_SHIFT) & 0x0f;
		trace_kvm_cr_write(0, (kvm_read_cr0(vcpu) & ~0xful) | val);
		kvm_lmsw(vcpu, val);

		skip_emulated_instruction(vcpu);
		return 1;
	default:
		break;
	}
	vcpu->run->exit_reason = 0;
	vcpu_unimpl(vcpu, "unhandled control register: op %d cr %d\n",
	       (int)(exit_qualification >> 4) & 3, cr);
	return 0;
}

static int handle_dr(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	int dr, dr7, reg;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	dr = exit_qualification & DEBUG_REG_ACCESS_NUM;

	/* First, if DR does not exist, trigger UD */
	if (!kvm_require_dr(vcpu, dr))
		return 1;

	/* Do not handle if the CPL > 0, will trigger GP on re-entry */
	if (!kvm_require_cpl(vcpu, 0))
		return 1;
	dr7 = vmcs_readl(GUEST_DR7);
	if (dr7 & DR7_GD) {
		/*
 * As the vm-exit takes precedence over the debug trap, we
 * need to emulate the latter, either for the host or the
 * guest debugging itself.
 */
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP) {
			vcpu->run->debug.arch.dr6 = vcpu->arch.dr6;
			vcpu->run->debug.arch.dr7 = dr7;
			vcpu->run->debug.arch.pc = kvm_get_linear_rip(vcpu);
			vcpu->run->debug.arch.exception = DB_VECTOR;
			vcpu->run->exit_reason = KVM_EXIT_DEBUG;
			return 0;
		} else {
			vcpu->arch.dr6 &= ~15;
			vcpu->arch.dr6 |= DR6_BD | DR6_RTM;
			kvm_queue_exception(vcpu, DB_VECTOR);
			return 1;
		}
	}

	if (vcpu->guest_debug == 0) {
		vmcs_clear_bits(CPU_BASED_VM_EXEC_CONTROL,
				CPU_BASED_MOV_DR_EXITING);

		/*
 * No more DR vmexits; force a reload of the debug registers
 * and reenter on this instruction. The next vmexit will
 * retrieve the full state of the debug registers.
 */
		vcpu->arch.switch_db_regs |= KVM_DEBUGREG_WONT_EXIT;
		return 1;
	}

	reg = DEBUG_REG_ACCESS_REG(exit_qualification);
	if (exit_qualification & TYPE_MOV_FROM_DR) {
		unsigned long val;

		if (kvm_get_dr(vcpu, dr, &val))
			return 1;
		kvm_register_write(vcpu, reg, val);
	} else
		if (kvm_set_dr(vcpu, dr, kvm_register_readl(vcpu, reg)))
			return 1;

	skip_emulated_instruction(vcpu);
	return 1;
}

static u64 vmx_get_dr6(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.dr6;
}

static void vmx_set_dr6(struct kvm_vcpu *vcpu, unsigned long val)
{
}

static void vmx_sync_dirty_debug_regs(struct kvm_vcpu *vcpu)
{
	get_debugreg(vcpu->arch.db[0], 0);
	get_debugreg(vcpu->arch.db[1], 1);
	get_debugreg(vcpu->arch.db[2], 2);
	get_debugreg(vcpu->arch.db[3], 3);
	get_debugreg(vcpu->arch.dr6, 6);
	vcpu->arch.dr7 = vmcs_readl(GUEST_DR7);

	vcpu->arch.switch_db_regs &= ~KVM_DEBUGREG_WONT_EXIT;
	vmcs_set_bits(CPU_BASED_VM_EXEC_CONTROL, CPU_BASED_MOV_DR_EXITING);
}

static void vmx_set_dr7(struct kvm_vcpu *vcpu, unsigned long val)
{
	vmcs_writel(GUEST_DR7, val);
}

static int handle_cpuid(struct kvm_vcpu *vcpu)
{
	kvm_emulate_cpuid(vcpu);
	return 1;
}

static int handle_rdmsr(struct kvm_vcpu *vcpu)
{
	u32 ecx = vcpu->arch.regs[VCPU_REGS_RCX];
	struct msr_data msr_info;

	msr_info.index = ecx;
	msr_info.host_initiated = false;
	if (vmx_get_msr(vcpu, &msr_info)) {
		trace_kvm_msr_read_ex(ecx);
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	trace_kvm_msr_read(ecx, msr_info.data);

	/* FIXME: handling of bits 32:63 of rax, rdx */
	vcpu->arch.regs[VCPU_REGS_RAX] = msr_info.data & -1u;
	vcpu->arch.regs[VCPU_REGS_RDX] = (msr_info.data >> 32) & -1u;
	skip_emulated_instruction(vcpu);
	return 1;
}

static int handle_wrmsr(struct kvm_vcpu *vcpu)
{
	struct msr_data msr;
	u32 ecx = vcpu->arch.regs[VCPU_REGS_RCX];
	u64 data = (vcpu->arch.regs[VCPU_REGS_RAX] & -1u)
		| ((u64)(vcpu->arch.regs[VCPU_REGS_RDX] & -1u) << 32);

	msr.data = data;
	msr.index = ecx;
	msr.host_initiated = false;
	if (kvm_set_msr(vcpu, &msr) != 0) {
		trace_kvm_msr_write_ex(ecx, data);
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	trace_kvm_msr_write(ecx, data);
	skip_emulated_instruction(vcpu);
	return 1;
}

static int handle_tpr_below_threshold(struct kvm_vcpu *vcpu)
{
	kvm_make_request(KVM_REQ_EVENT, vcpu);
	return 1;
}

static int handle_interrupt_window(struct kvm_vcpu *vcpu)
{
	u32 cpu_based_vm_exec_control;

	/* clear pending irq */
	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control &= ~CPU_BASED_VIRTUAL_INTR_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);

	kvm_make_request(KVM_REQ_EVENT, vcpu);

	++vcpu->stat.irq_window_exits;
	return 1;
}

static int handle_halt(struct kvm_vcpu *vcpu)
{
	return kvm_emulate_halt(vcpu);
}

static int handle_vmcall(struct kvm_vcpu *vcpu)
{
	return kvm_emulate_hypercall(vcpu);
}

static int handle_invd(struct kvm_vcpu *vcpu)
{
	return emulate_instruction(vcpu, 0) == EMULATE_DONE;
}

static int handle_invlpg(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	kvm_mmu_invlpg(vcpu, exit_qualification);
	skip_emulated_instruction(vcpu);
	return 1;
}

static int handle_rdpmc(struct kvm_vcpu *vcpu)
{
	int err;

	err = kvm_rdpmc(vcpu);
	kvm_complete_insn_gp(vcpu, err);

	return 1;
}

static int handle_wbinvd(struct kvm_vcpu *vcpu)
{
	kvm_emulate_wbinvd(vcpu);
	return 1;
}

static int handle_xsetbv(struct kvm_vcpu *vcpu)
{
	u64 new_bv = kvm_read_edx_eax(vcpu);
	u32 index = kvm_register_read(vcpu, VCPU_REGS_RCX);

	if (kvm_set_xcr(vcpu, index, new_bv) == 0)
		skip_emulated_instruction(vcpu);
	return 1;
}

static int handle_xsaves(struct kvm_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
	WARN(1, "this should never happen\n");
	return 1;
}

static int handle_xrstors(struct kvm_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
	WARN(1, "this should never happen\n");
	return 1;
}

static int handle_apic_access(struct kvm_vcpu *vcpu)
{
	if (likely(fasteoi)) {
		unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
		int access_type, offset;

		access_type = exit_qualification & APIC_ACCESS_TYPE;
		offset = exit_qualification & APIC_ACCESS_OFFSET;
		/*
 * Sane guest uses MOV to write EOI, with written value
 * not cared. So make a short-circuit here by avoiding
 * heavy instruction emulation.
 */
		if ((access_type == TYPE_LINEAR_APIC_INST_WRITE) &&
		    (offset == APIC_EOI)) {
			kvm_lapic_set_eoi(vcpu);
			skip_emulated_instruction(vcpu);
			return 1;
		}
	}
	return emulate_instruction(vcpu, 0) == EMULATE_DONE;
}

static int handle_apic_eoi_induced(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	int vector = exit_qualification & 0xff;

	/* EOI-induced VM exit is trap-like and thus no need to adjust IP */
	kvm_apic_set_eoi_accelerated(vcpu, vector);
	return 1;
}

static int handle_apic_write(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	u32 offset = exit_qualification & 0xfff;

	/* APIC-write VM exit is trap-like and thus no need to adjust IP */
	kvm_apic_write_nodecode(vcpu, offset);
	return 1;
}

static int handle_task_switch(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long exit_qualification;
	bool has_error_code = false;
	u32 error_code = 0;
	u16 tss_selector;
	int reason, type, idt_v, idt_index;

	idt_v = (vmx->idt_vectoring_info & VECTORING_INFO_VALID_MASK);
	idt_index = (vmx->idt_vectoring_info & VECTORING_INFO_VECTOR_MASK);
	type = (vmx->idt_vectoring_info & VECTORING_INFO_TYPE_MASK);

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	reason = (u32)exit_qualification >> 30;
	if (reason == TASK_SWITCH_GATE && idt_v) {
		switch (type) {
		case INTR_TYPE_NMI_INTR:
			vcpu->arch.nmi_injected = false;
			vmx_set_nmi_mask(vcpu, true);
			break;
		case INTR_TYPE_EXT_INTR:
		case INTR_TYPE_SOFT_INTR:
			kvm_clear_interrupt_queue(vcpu);
			break;
		case INTR_TYPE_HARD_EXCEPTION:
			if (vmx->idt_vectoring_info &
			    VECTORING_INFO_DELIVER_CODE_MASK) {
				has_error_code = true;
				error_code =
					vmcs_read32(IDT_VECTORING_ERROR_CODE);
			}
			/* fall through */
		case INTR_TYPE_SOFT_EXCEPTION:
			kvm_clear_exception_queue(vcpu);
			break;
		default:
			break;
		}
	}
	tss_selector = exit_qualification;

	if (!idt_v || (type != INTR_TYPE_HARD_EXCEPTION &&
		       type != INTR_TYPE_EXT_INTR &&
		       type != INTR_TYPE_NMI_INTR))
		skip_emulated_instruction(vcpu);

	if (kvm_task_switch(vcpu, tss_selector,
			    type == INTR_TYPE_SOFT_INTR ? idt_index : -1, reason,
			    has_error_code, error_code) == EMULATE_FAIL) {
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
		vcpu->run->internal.ndata = 0;
		return 0;
	}

	/*
 * TODO: What about debug traps on tss switch?
 * Are we supposed to inject them and update dr6?
 */

	return 1;
}

static int handle_ept_violation(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	gpa_t gpa;
	u32 error_code;
	int gla_validity;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	gla_validity = (exit_qualification >> 7) & 0x3;
	if (gla_validity != 0x3 && gla_validity != 0x1 && gla_validity != 0) {
		printk(KERN_ERR "EPT: Handling EPT violation failed!\n");
		printk(KERN_ERR "EPT: GPA: 0x%lx, GVA: 0x%lx\n",
			(long unsigned int)vmcs_read64(GUEST_PHYSICAL_ADDRESS),
			vmcs_readl(GUEST_LINEAR_ADDRESS));
		printk(KERN_ERR "EPT: Exit qualification is 0x%lx\n",
			(long unsigned int)exit_qualification);
		vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
		vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_VIOLATION;
		return 0;
	}

	/*
 * EPT violation happened while executing iret from NMI,
 * "blocked by NMI" bit has to be set before next VM entry.
 * There are errata that may cause this bit to not be set:
 * AAK134, BY25.
 */
	if (!(to_vmx(vcpu)->idt_vectoring_info & VECTORING_INFO_VALID_MASK) &&
			cpu_has_virtual_nmis() &&
			(exit_qualification & INTR_INFO_UNBLOCK_NMI))
		vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO, GUEST_INTR_STATE_NMI);

	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
	trace_kvm_page_fault(gpa, exit_qualification);

	/* It is a write fault? */
	error_code = exit_qualification & PFERR_WRITE_MASK;
	/* It is a fetch fault? */
	error_code |= (exit_qualification << 2) & PFERR_FETCH_MASK;
	/* ept page table is present? */
	error_code |= (exit_qualification >> 3) & PFERR_PRESENT_MASK;

	vcpu->arch.exit_qualification = exit_qualification;

	return kvm_mmu_page_fault(vcpu, gpa, error_code, NULL, 0);
}

static int handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	int ret;
	gpa_t gpa;

	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
	if (!kvm_io_bus_write(vcpu, KVM_FAST_MMIO_BUS, gpa, 0, NULL)) {
		skip_emulated_instruction(vcpu);
		trace_kvm_fast_mmio(gpa);
		return 1;
	}

	ret = handle_mmio_page_fault(vcpu, gpa, true);
	if (likely(ret == RET_MMIO_PF_EMULATE))
		return x86_emulate_instruction(vcpu, gpa, 0, NULL, 0) ==
					      EMULATE_DONE;

	if (unlikely(ret == RET_MMIO_PF_INVALID))
		return kvm_mmu_page_fault(vcpu, gpa, 0, NULL, 0);

	if (unlikely(ret == RET_MMIO_PF_RETRY))
		return 1;

	/* It is the real ept misconfig */
	WARN_ON(1);

	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_MISCONFIG;

	return 0;
}

static int handle_nmi_window(struct kvm_vcpu *vcpu)
{
	u32 cpu_based_vm_exec_control;

	/* clear pending NMI */
	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control &= ~CPU_BASED_VIRTUAL_NMI_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);
	++vcpu->stat.nmi_window_exits;
	kvm_make_request(KVM_REQ_EVENT, vcpu);

	return 1;
}

static int handle_invalid_guest_state(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	enum emulation_result err = EMULATE_DONE;
	int ret = 1;
	u32 cpu_exec_ctrl;
	bool intr_window_requested;
	unsigned count = 130;

	cpu_exec_ctrl = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	intr_window_requested = cpu_exec_ctrl & CPU_BASED_VIRTUAL_INTR_PENDING;

	while (vmx->emulation_required && count-- != 0) {
		if (intr_window_requested && vmx_interrupt_allowed(vcpu))
			return handle_interrupt_window(&vmx->vcpu);

		if (test_bit(KVM_REQ_EVENT, &vcpu->requests))
			return 1;

		err = emulate_instruction(vcpu, EMULTYPE_NO_REEXECUTE);

		if (err == EMULATE_USER_EXIT) {
			++vcpu->stat.mmio_exits;
			ret = 0;
			goto out;
		}

		if (err != EMULATE_DONE) {
			vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
			vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
			vcpu->run->internal.ndata = 0;
			return 0;
		}

		if (vcpu->arch.halt_request) {
			vcpu->arch.halt_request = 0;
			ret = kvm_vcpu_halt(vcpu);
			goto out;
		}

		if (signal_pending(current))
			goto out;
		if (need_resched())
			schedule();
	}

out:
	return ret;
}

static int __grow_ple_window(int val)
{
	if (ple_window_grow < 1)
		return ple_window;

	val = min(val, ple_window_actual_max);

	if (ple_window_grow < ple_window)
		val *= ple_window_grow;
	else
		val += ple_window_grow;

	return val;
}

static int __shrink_ple_window(int val, int modifier, int minimum)
{
	if (modifier < 1)
		return ple_window;

	if (modifier < ple_window)
		val /= modifier;
	else
		val -= modifier;

	return max(val, minimum);
}

static void grow_ple_window(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int old = vmx->ple_window;

	vmx->ple_window = __grow_ple_window(old);

	if (vmx->ple_window != old)
		vmx->ple_window_dirty = true;

	trace_kvm_ple_window_grow(vcpu->vcpu_id, vmx->ple_window, old);
}

static void shrink_ple_window(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int old = vmx->ple_window;

	vmx->ple_window = __shrink_ple_window(old,
	                                      ple_window_shrink, ple_window);

	if (vmx->ple_window != old)
		vmx->ple_window_dirty = true;

	trace_kvm_ple_window_shrink(vcpu->vcpu_id, vmx->ple_window, old);
}

/*
 * ple_window