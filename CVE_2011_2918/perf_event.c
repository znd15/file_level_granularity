

/*
 * Hardware performance events for the Alpha.
 *
 * We implement HW counts on the EV67 and subsequent CPUs only.
 *
 * (C) 2010 Michael J. Cree
 *
 * Somewhat based on the Sparc code, and to a lesser extent the PowerPC and
 * ARM code, which are copyright by their respective authors.
 */

#include <linux/perf_event.h>
#include <linux/kprobes.h>
#include <linux/kernel.h>
#include <linux/kdebug.h>
#include <linux/mutex.h>
#include <linux/init.h>

#include <asm/hwrpb.h>
#include <asm/atomic.h>
#include <asm/irq.h>
#include <asm/irq_regs.h>
#include <asm/pal.h>
#include <asm/wrperfmon.h>
#include <asm/hw_irq.h>


/* The maximum number of PMCs on any Alpha CPU whatsoever. */
#define MAX_HWEVENTS 3
#define PMC_NO_INDEX -1

/* For tracking PMCs and the hw events they monitor on each CPU. */
struct cpu_hw_events {
	int			enabled;
	/* Number of events scheduled; also number entries valid in arrays below. */
	int			n_events;
	/* Number events added since last hw_perf_disable(). */
	int			n_added;
	/* Events currently scheduled. */
	struct perf_event	*event[MAX_HWEVENTS];
	/* Event type of each scheduled event. */
	unsigned long		evtype[MAX_HWEVENTS];
	/* Current index of each scheduled event; if not yet determined
 * contains PMC_NO_INDEX.
 */
	int			current_idx[MAX_HWEVENTS];
	/* The active PMCs' config for easy use with wrperfmon(). */
	unsigned long		config;
	/* The active counters' indices for easy use with wrperfmon(). */
	unsigned long		idx_mask;
};
DEFINE_PER_CPU(struct cpu_hw_events, cpu_hw_events);



/*
 * A structure to hold the description of the PMCs available on a particular
 * type of Alpha CPU.
 */
struct alpha_pmu_t {
	/* Mapping of the perf system hw event types to indigenous event types */
	const int *event_map;
	/* The number of entries in the event_map */
	int  max_events;
	/* The number of PMCs on this Alpha */
	int  num_pmcs;
	/*
 * All PMC counters reside in the IBOX register PCTR. This is the
 * LSB of the counter.
 */
	int  pmc_count_shift[MAX_HWEVENTS];
	/*
 * The mask that isolates the PMC bits when the LSB of the counter
 * is shifted to bit 0.
 */
	unsigned long pmc_count_mask[MAX_HWEVENTS];
	/* The maximum period the PMC can count. */
	unsigned long pmc_max_period[MAX_HWEVENTS];
	/*
 * The maximum value that may be written to the counter due to
 * hardware restrictions is pmc_max_period - pmc_left.
 */
	long pmc_left[3];
	 /* Subroutine for allocation of PMCs. Enforces constraints. */
	int (*check_constraints)(struct perf_event **, unsigned long *, int);
};

/*
 * The Alpha CPU PMU description currently in operation. This is set during
 * the boot process to the specific CPU of the machine.
 */
static const struct alpha_pmu_t *alpha_pmu;


#define HW_OP_UNSUPPORTED -1

/*
 * The hardware description of the EV67, EV68, EV69, EV7 and EV79 PMUs
 * follow. Since they are identical we refer to them collectively as the
 * EV67 henceforth.
 */

/*
 * EV67 PMC event types
 *
 * There is no one-to-one mapping of the possible hw event types to the
 * actual codes that are used to program the PMCs hence we introduce our
 * own hw event type identifiers.
 */
enum ev67_pmc_event_type {
	EV67_CYCLES = 1,
	EV67_INSTRUCTIONS,
	EV67_BCACHEMISS,
	EV67_MBOXREPLAY,
	EV67_LAST_ET
};
#define EV67_NUM_EVENT_TYPES (EV67_LAST_ET-EV67_CYCLES)


/* Mapping of the hw event types to the perf tool interface */
static const int ev67_perfmon_event_map[] = {
	[PERF_COUNT_HW_CPU_CYCLES] = EV67_CYCLES,
	[PERF_COUNT_HW_INSTRUCTIONS] = EV67_INSTRUCTIONS,
	[PERF_COUNT_HW_CACHE_REFERENCES] = HW_OP_UNSUPPORTED,
	[PERF_COUNT_HW_CACHE_MISSES] = EV67_BCACHEMISS,
};

struct ev67_mapping_t {
	int config;
	int idx;
};

/*
 * The mapping used for one event only - these must be in same order as enum
 * ev67_pmc_event_type definition.
 */
static const struct ev67_mapping_t ev67_mapping[] = {
	{EV67_PCTR_INSTR_CYCLES, 1},	 /* EV67_CYCLES, */
	{EV67_PCTR_INSTR_CYCLES, 0},	 /* EV67_INSTRUCTIONS */
	{EV67_PCTR_INSTR_BCACHEMISS, 1}, /* EV67_BCACHEMISS */
	{EV67_PCTR_CYCLES_MBOX, 1}	 /* EV67_MBOXREPLAY */
};


/*
 * Check that a group of events can be simultaneously scheduled on to the
 * EV67 PMU. Also allocate counter indices and config.
 */
static int ev67_check_constraints(struct perf_event **event,
				unsigned long *evtype, int n_ev)
{
	int idx0;
	unsigned long config;

	idx0 = ev67_mapping[evtype[0]-1].idx;
	config = ev67_mapping[evtype[0]-1].config;
	if (n_ev == 1)
		goto success;

	BUG_ON(n_ev != 2);

	if (evtype[0] == EV67_MBOXREPLAY || evtype[1] == EV67_MBOXREPLAY) {
		/* MBOX replay traps must be on PMC 1 */
		idx0 = (evtype[0] == EV67_MBOXREPLAY) ? 1 : 0;
		/* Only cycles can accompany MBOX replay traps */
		if (evtype[idx0] == EV67_CYCLES) {
			config = EV67_PCTR_CYCLES_MBOX;
			goto success;
		}
	}

	if (evtype[0] == EV67_BCACHEMISS || evtype[1] == EV67_BCACHEMISS) {
		/* Bcache misses must be on PMC 1 */
		idx0 = (evtype[0] == EV67_BCACHEMISS) ? 1 : 0;
		/* Only instructions can accompany Bcache misses */
		if (evtype[idx0] == EV67_INSTRUCTIONS) {
			config = EV67_PCTR_INSTR_BCACHEMISS;
			goto success;
		}
	}

	if (evtype[0] == EV67_INSTRUCTIONS || evtype[1] == EV67_INSTRUCTIONS) {
		/* Instructions must be on PMC 0 */
		idx0 = (evtype[0] == EV67_INSTRUCTIONS) ? 0 : 1;
		/* By this point only cycles can accompany instructions */
		if (evtype[idx0^1] == EV67_CYCLES) {
			config = EV67_PCTR_INSTR_CYCLES;
			goto success;
		}
	}

	/* Otherwise, darn it, there is a conflict. */
	return -1;

success:
	event[0]->hw.idx = idx0;
	event[0]->hw.config_base = config;
	if (n_ev == 2) {
		event[1]->hw.idx = idx0 ^ 1;
		event[1]->hw.config_base = config;
	}
	return 0;
}


static const struct alpha_pmu_t ev67_pmu = {
	.event_map = ev67_perfmon_event_map,
	.max_events = ARRAY_SIZE(ev67_perfmon_event_map),
	.num_pmcs = 2,
	.pmc_count_shift = {EV67_PCTR_0_COUNT_SHIFT, EV67_PCTR_1_COUNT_SHIFT, 0},
	.pmc_count_mask = {EV67_PCTR_0_COUNT_MASK,  EV67_PCTR_1_COUNT_MASK,  0},
	.pmc_max_period = {(1UL<<20) - 1, (1UL<<20) - 1, 0},
	.pmc_left = {16, 4, 0},
	.check_constraints = ev67_check_constraints
};



/*
 * Helper routines to ensure that we read/write only the correct PMC bits
 * when calling the wrperfmon PALcall.
 */
static inline void alpha_write_pmc(int idx, unsigned long val)
{
	val &= alpha_pmu->pmc_count_mask[idx];
	val <<= alpha_pmu->pmc_count_shift[idx];
	val |= (1<<idx);
	wrperfmon(PERFMON_CMD_WRITE, val);
}

static inline unsigned long alpha_read_pmc(int idx)
{
	unsigned long val;

	val = wrperfmon(PERFMON_CMD_READ, 0);
	val >>= alpha_pmu->pmc_count_shift[idx];
	val &= alpha_pmu->pmc_count_mask[idx];
	return val;
}

/* Set a new period to sample over */
static int alpha_perf_event_set_period(struct perf_event *event,
				struct hw_perf_event *hwc, int idx)
{
	long left = local64_read(&hwc->period_left);
	long period = hwc->sample_period;
	int ret = 0;

	if (unlikely(left <= -period)) {
		left = period;
		local64_set(&hwc->period_left, left);
		hwc->last_period = period;
		ret = 1;
	}

	if (unlikely(left <= 0)) {
		left += period;
		local64_set(&hwc->period_left, left);
		hwc->last_period = period;
		ret = 1;
	}

	/*
 * Hardware restrictions require that the counters must not be
 * written with values that are too close to the maximum period.
 */
	if (unlikely(left < alpha_pmu->pmc_left[idx]))
		left = alpha_pmu->pmc_left[idx];

	if (left > (long)alpha_pmu->pmc_max_period[idx])
		left = alpha_pmu->pmc_max_period[idx];

	local64_set(&hwc->prev_count, (unsigned long)(-left));

	alpha_write_pmc(idx, (unsigned long)(-left));

	perf_event_update_userpage(event);

	return ret;
}


/*
 * Calculates the count (the 'delta') since the last time the PMC was read.
 *
 * As the PMCs' full period can easily be exceeded within the perf system
 * sampling period we cannot use any high order bits as a guard bit in the
 * PMCs to detect overflow as is done by other architectures. The code here
 * calculates the delta on the basis that there is no overflow when ovf is
 * zero. The value passed via ovf by the interrupt handler corrects for
 * overflow.
 *
 * This can be racey on rare occasions -- a call to this routine can occur
 * with an overflowed counter just before the PMI service routine is called.
 * The check for delta negative hopefully always rectifies this situation.
 */
static unsigned long alpha_perf_event_update(struct perf_event *event,
					struct hw_perf_event *hwc, int idx, long ovf)
{
	long prev_raw_count, new_raw_count;
	long delta;

again:
	prev_raw_count = local64_read(&hwc->prev_count);
	new_raw_count = alpha_read_pmc(idx);

	if (local64_cmpxchg(&hwc->prev_count, prev_raw_count,
			     new_raw_count) != prev_raw_count)
		goto again;

	delta = (new_raw_count - (prev_raw_count & alpha_pmu->pmc_count_mask[idx])) + ovf;

	/* It is possible on very rare occasions that the PMC has overflowed
 * but the interrupt is yet to come. Detect and fix this situation.
 */
	if (unlikely(delta < 0)) {
		delta += alpha_pmu->pmc_max_period[idx] + 1;
	}

	local64_add(delta, &event->count);
	local64_sub(delta, &hwc->period_left);

	return new_raw_count;
}


/*
 * Collect all HW events into the array event[].
 */
static int collect_events(struct perf_event *group, int max_count,
			  struct perf_event *event[], unsigned long *evtype,
			  int *current_idx)
{
	struct perf_event *pe;
	int n = 0;

	if (!is_software_event(group)) {
		if (n >= max_count)
			return -1;
		event[n] = group;
		evtype[n] = group->hw.event_base;
		current_idx[n++] = PMC_NO_INDEX;
	}
	list_for_each_entry(pe, &group->sibling_list, group_entry) {
		if (!is_software_event(pe) && pe->state != PERF_EVENT_STATE_OFF) {
			if (n >= max_count)
				return -1;
			event[n] = pe;
			evtype[n] = pe->hw.event_base;
			current_idx[n++] = PMC_NO_INDEX;
		}
	}
	return n;
}



/*
 * Check that a group of events can be simultaneously scheduled on to the PMU.
 */
static int alpha_check_constraints(struct perf_event **events,
				   unsigned long *evtypes, int n_ev)
{

	/* No HW events is possible from hw_perf_group_sched_in(). */
	if (n_ev == 0)
		return 0;

	if (n_ev > alpha_pmu->num_pmcs)
		return -1;

	return alpha_pmu->check_constraints(events, evtypes, n_ev);
}


/*
 * If new events have been scheduled then update cpuc with the new
 * configuration. This may involve shifting cycle counts from one PMC to
 * another.
 */
static void maybe_change_configuration(struct cpu_hw_events *cpuc)
{
	int j;

	if (cpuc->n_added == 0)
		return;

	/* Find counters that are moving to another PMC and update */
	for (j = 0; j < cpuc->n_events; j++) {
		struct perf_event *pe = cpuc->event[j];

		if (cpuc->current_idx[j] != PMC_NO_INDEX &&
			cpuc->current_idx[j] != pe->hw.idx) {
			alpha_perf_event_update(pe, &pe->hw, cpuc->current_idx[j], 0);
			cpuc->current_idx[j] = PMC_NO_INDEX;
		}
	}

	/* Assign to counters all unassigned events. */
	cpuc->idx_mask = 0;
	for (j = 0; j < cpuc->n_events; j++) {
		struct perf_event *pe = cpuc->event[j];
		struct hw_perf_event *hwc = &pe->hw;
		int idx = hwc->idx;

		if (cpuc->current_idx[j] == PMC_NO_INDEX) {
			alpha_perf_event_set_period(pe, hwc, idx);
			cpuc->current_idx[j] = idx;
		}

		if (!(hwc->state & PERF_HES_STOPPED))
			cpuc->idx_mask |= (1<<cpuc->current_idx[j]);
	}
	cpuc->config = cpuc->event[0]->hw.config_base;
}



/* Schedule perf HW event on to PMU.
 * - this function is called from outside this module via the pmu struct
 * returned from perf event initialisation.
 */
static int alpha_pmu_add(struct perf_event *event, int flags)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	struct hw_perf_event *hwc = &event->hw;
	int n0;
	int ret;
	unsigned long irq_flags;

	/*
 * The Sparc code has the IRQ disable first followed by the perf
 * disable, however this can lead to an overflowed counter with the
 * PMI disabled on rare occasions. The alpha_perf_event_update()
 * routine should detect this situation by noting a negative delta,
 * nevertheless we disable the PMCs first to enable a potential
 * final PMI to occur before we disable interrupts.
 */
	perf_pmu_disable(event->pmu);
	local_irq_save(irq_flags);

	/* Default to error to be returned */
	ret = -EAGAIN;

	/* Insert event on to PMU and if successful modify ret to valid return */
	n0 = cpuc->n_events;
	if (n0 < alpha_pmu->num_pmcs) {
		cpuc->event[n0] = event;
		cpuc->evtype[n0] = event->hw.event_base;
		cpuc->current_idx[n0] = PMC_NO_INDEX;

		if (!alpha_check_constraints(cpuc->event, cpuc->evtype, n0+1)) {
			cpuc->n_events++;
			cpuc->n_added++;
			ret = 0;
		}
	}

	hwc->state = PERF_HES_UPTODATE;
	if (!(flags & PERF_EF_START))
		hwc->state |= PERF_HES_STOPPED;

	local_irq_restore(irq_flags);
	perf_pmu_enable(event->pmu);

	return ret;
}



/* Disable performance monitoring unit
 * - this function is called from outside this module via the pmu struct
 * returned from perf event initialisation.
 */
static void alpha_pmu_del(struct perf_event *event, int flags)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	struct hw_perf_event *hwc = &event->hw;
	unsigned long irq_flags;
	int j;

	perf_pmu_disable(event->pmu);
	local_irq_save(irq_flags);

	for (j = 0; j < cpuc->n_events; j++) {
		if (event == cpuc->event[j]) {
			int idx = cpuc->current_idx[j];

			/* Shift remaining entries down into the existing
 * slot.
 */
			while (++j < cpuc->n_events) {
				cpuc->event[j - 1] = cpuc->event[j];
				cpuc->evtype[j - 1] = cpuc->evtype[j];
				cpuc->current_idx[j - 1] =
					cpuc->current_idx[j];
			}

			/* Absorb the final count and turn off the event. */
			alpha_perf_event_update(event, hwc, idx, 0);
			perf_event_update_userpage(event);

			cpuc->idx_mask &= ~(1UL<<idx);
			cpuc->n_events--;
			break;
		}
	}

	local_irq_restore(irq_flags);
	perf_pmu_enable(event->pmu);
}


static void alpha_pmu_read(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;

	alpha_perf_event_update(event, hwc, hwc->idx, 0);
}


static void alpha_pmu_stop(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);

	if (!(hwc->state & PERF_HES_STOPPED)) {
		cpuc->idx_mask &= ~(1UL<<hwc->idx);
		hwc->state |= PERF_HES_STOPPED;
	}

	if ((flags & PERF_EF_UPDATE) && !(hwc->state & PERF_HES_UPTODATE)) {
		alpha_perf_event_update(event, hwc, hwc->idx, 0);
		hwc->state |= PERF_HES_UPTODATE;
	}

	if (cpuc->enabled)
		wrperfmon(PERFMON_CMD_DISABLE, (1UL<<hwc->idx));
}


static void alpha_pmu_start(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);

	if (WARN_ON_ONCE(!(hwc->state & PERF_HES_STOPPED)))
		return;

	if (flags & PERF_EF_RELOAD) {
		WARN_ON_ONCE(!(hwc->state & PERF_HES_UPTODATE));
		alpha_perf_event_set_period(event, hwc, hwc->idx);
	}

	hwc->state = 0;

	cpuc->idx_mask |= 1UL<<hwc->idx;
	if (cpuc->enabled)
		wrperfmon(PERFMON_CMD_ENABLE, (1UL<<hwc->idx));
}


/*
 * Check that CPU performance counters are supported.
 * - currently support EV67 and later CPUs.
 * - actually some later revisions of the EV6 have the same PMC model as the
 * EV67 but we don't do suffiently deep CPU detection to detect them.
 * Bad luck to the very few people who might have one, I guess.
 */
static int supported_cpu(void)
{
	struct percpu_struct *cpu;
	unsigned long cputype;

	/* Get cpu type from HW */
	cpu = (struct percpu_struct *)((char *)hwrpb + hwrpb->processor_offset);
	cputype = cpu->type & 0xffffffff;
	/* Include all of EV67, EV68, EV7, EV79 and EV69 as supported. */
	return (cputype >= EV67_CPU) && (cputype <= EV69_CPU);
}



static void hw_perf_event_destroy(struct perf_event *event)
{
	/* Nothing to be done! */
	return;
}



static int __hw_perf_event_init(struct perf_event *event)
{
	struct perf_event_attr *attr = &event->attr;
	struct hw_perf_event *hwc = &event->hw;
	struct perf_event *evts[MAX_HWEVENTS];
	unsigned long evtypes[MAX_HWEVENTS];
	int idx_rubbish_bin[MAX_HWEVENTS];
	int ev;
	int n;

	/* We only support a limited range of HARDWARE event types with one
 * only programmable via a RAW event type.
 */
	if (attr->type == PERF_TYPE_HARDWARE) {
		if (attr->config >= alpha_pmu->max_events)
			return -EINVAL;
		ev = alpha_pmu->event_map[attr->config];
	} else if (attr->type == PERF_TYPE_HW_CACHE) {
		return -EOPNOTSUPP;
	} else if (attr->type == PERF_TYPE_RAW) {
		ev = attr->config & 0xff;
	} else {
		return -EOPNOTSUPP;
	}

	if (ev < 0) {
		return ev;
	}

	/* The EV67 does not support mode exclusion */
	if (attr->exclude_kernel || attr->exclude_user
			|| attr->exclude_hv || attr->exclude_idle) {
		return -EPERM;
	}

	/*
 * We place the event type in event_base here and leave calculation
 * of the codes to programme the PMU for alpha_pmu_enable() because
 * it is only then we will know what HW events are actually
 * scheduled on to the PMU. At that point the code to programme the
 * PMU is put into config_base and the PMC to use is placed into
 * idx. We initialise idx (below) to PMC_NO_INDEX to indicate that
 * it is yet to be determined.
 */
	hwc->event_base = ev;

	/* Collect events in a group together suitable for calling
 * alpha_check_constraints() to verify that the group as a whole can
 * be scheduled on to the PMU.
 */
	n = 0;
	if (event->group_leader != event) {
		n = collect_events(event->group_leader,
				alpha_pmu->num_pmcs - 1,
				evts, evtypes, idx_rubbish_bin);
		if (n < 0)
			return -EINVAL;
	}
	evtypes[n] = hwc->event_base;
	evts[n] = event;

	if (alpha_check_constraints(evts, evtypes, n + 1))
		return -EINVAL;

	/* Indicate that PMU config and idx are yet to be determined. */
	hwc->config_base = 0;
	hwc->idx = PMC_NO_INDEX;

	event->destroy = hw_perf_event_destroy;

	/*
 * Most architectures reserve the PMU for their use at this point.
 * As there is no existing mechanism to arbitrate usage and there
 * appears to be no other user of the Alpha PMU we just assume
 * that we can just use it, hence a NO-OP here.
 *
 * Maybe an alpha_reserve_pmu() routine should be implemented but is
 * anything else ever going to use it?
 */

	if (!hwc->sample_period) {
		hwc->sample_period = alpha_pmu->pmc_max_period[0];
		hwc->last_period = hwc->sample_period;
		local64_set(&hwc->period_left, hwc->sample_period);
	}

	return 0;
}

/*
 * Main entry point to initialise a HW performance event.
 */
static int alpha_pmu_event_init(struct perf_event *event)
{
	int err;

	switch (event->attr.type) {
	case PERF_TYPE_RAW:
	case PERF_TYPE_HARDWARE:
	case PERF_TYPE_HW_CACHE:
		break;

	default:
		return -ENOENT;
	}

	if (!alpha_pmu)
		return -ENODEV;

	/* Do the real initialisation work. */
	err = __hw_perf_event_init(event);

	return err;
}

/*
 * Main entry point - enable HW performance counters.
 */
static void alpha_pmu_enable(struct pmu *pmu)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);

	if (cpuc->enabled)
		return;

	cpuc->enabled = 1;
	barrier();

	if (cpuc->n_events > 0) {
		/* Update cpuc with information from any new scheduled events. */
		maybe_change_configuration(cpuc);

		/* Start counting the desired events. */
		wrperfmon(PERFMON_CMD_LOGGING_OPTIONS, EV67_PCTR_MODE_AGGREGATE);
		wrperfmon(PERFMON_CMD_DESIRED_EVENTS, cpuc->config);
		wrperfmon(PERFMON_CMD_ENABLE, cpuc->idx_mask);
	}
}


/*
 * Main entry point - disable HW performance counters.
 */

static void alpha_pmu_disable(struct pmu *pmu)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);

	if (!cpuc->enabled)
		return;

	cpuc->enabled = 0;
	cpuc->n_added = 0;

	wrperfmon(PERFMON_CMD_DISABLE, cpuc->idx_mask);
}

static struct pmu pmu = {
	.pmu_enable	= alpha_pmu_enable,
	.pmu_disable	= alpha_pmu_disable,
	.event_init	= alpha_pmu_event_init,
	.add		= alpha_pmu_add,
	.del		= alpha_pmu_del,
	.start		= alpha_pmu_start,
	.stop		= alpha_pmu_stop,
	.read		= alpha_pmu_read,
};


/*
 * Main entry point - don't know when this is called but it
 * obviously dumps debug info.
 */
void perf_event_print_debug(void)
{
	unsigned long flags;
	unsigned long pcr;
	int pcr0, pcr1;
	int cpu;

	if (!supported_cpu())
		return;

	local_irq_save(flags);

	cpu = smp_processor_id();

	pcr = wrperfmon(PERFMON_CMD_READ, 0);
	pcr0 = (pcr >> alpha_pmu->pmc_count_shift[0]) & alpha_pmu->pmc_count_mask[0];
	pcr1 = (pcr >> alpha_pmu->pmc_count_shift[1]) & alpha_pmu->pmc_count_mask[1];

	pr_info("CPU#%d: PCTR0[%06x] PCTR1[%06x]\n", cpu, pcr0, pcr1);

	local_irq_restore(flags);
}


/*
 * Performance Monitoring Interrupt Service Routine called when a PMC
 * overflows. The PMC that overflowed is passed in la_ptr.
 */
static void alpha_perf_event_irq_handler(unsigned long la_ptr,
					struct pt_regs *regs)
{
	struct cpu_hw_events *cpuc;
	struct perf_sample_data data;
	struct perf_event *event;
	struct hw_perf_event *hwc;
	int idx, j;

	__get_cpu_var(irq_pmi_count)++;
	cpuc = &__get_cpu_var(cpu_hw_events);

	/* Completely counting through the PMC's period to trigger a new PMC
 * overflow interrupt while in this interrupt routine is utterly
 * disastrous! The EV6 and EV67 counters are sufficiently large to
 * prevent this but to be really sure disable the PMCs.
 */
	wrperfmon(PERFMON_CMD_DISABLE, cpuc->idx_mask);

	/* la_ptr is the counter that overflowed. */
	if (unlikely(la_ptr >= alpha_pmu->num_pmcs)) {
		/* This should never occur! */
		irq_err_count++;
		pr_warning("PMI: silly index %ld\n", la_ptr);
		wrperfmon(PERFMON_CMD_ENABLE, cpuc->idx_mask);
		return;
	}

	idx = la_ptr;

	perf_sample_data_init(&data, 0);
	for (j = 0; j < cpuc->n_events; j++) {
		if (cpuc->current_idx[j] == idx)
			break;
	}

	if (unlikely(j == cpuc->n_events)) {
		/* This can occur if the event is disabled right on a PMC overflow. */
		wrperfmon(PERFMON_CMD_ENABLE, cpuc->idx_mask);
		return;
	}

	event = cpuc->event[j];

	if (unlikely(!event)) {
		/* This should never occur! */
		irq_err_count++;
		pr_warning("PMI: No event at index %d!\n", idx);
		wrperfmon(PERFMON_CMD_ENABLE, cpuc->idx_mask);
		return;
	}

	hwc = &event->hw;
	alpha_perf_event_update(event, hwc, idx, alpha_pmu->pmc_max_period[idx]+1);
	data.period = event->hw.last_period;

	if (alpha_perf_event_set_period(event, hwc, idx)) {
		if (perf_event_overflow(event, 1, &data, regs)) {
			/* Interrupts coming too quickly; "throttle" the
 * counter, i.e., disable it for a little while.
 */
			alpha_pmu_stop(event, 0);
		}
	}
	wrperfmon(PERFMON_CMD_ENABLE, cpuc->idx_mask);

	return;
}



/*
 * Init call to initialise performance events at kernel startup.
 */
int __init init_hw_perf_events(void)
{
	pr_info("Performance events: ");

	if (!supported_cpu()) {
		pr_cont("No support for your CPU.\n");
		return 0;
	}

	pr_cont("Supported CPU type!\n");

	/* Override performance counter IRQ vector */

	perf_irq = alpha_perf_event_irq_handler;

	/* And set up PMU specification */
	alpha_pmu = &ev67_pmu;

	perf_pmu_register(&pmu, "cpu", PERF_TYPE_RAW);

	return 0;
}
early_initcall(init_hw_perf_events);

/*
 * Linux performance counter support for MIPS.
 *
 * Copyright (C) 2010 MIPS Technologies, Inc.
 * Author: Deng-Cheng Zhu
 *
 * This code is based on the implementation for ARM, which is in turn
 * based on the sparc64 perf event code and the x86 code. Performance
 * counter access is based on the MIPS Oprofile code. And the callchain
 * support references the code of MIPS stacktrace.c.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/cpumask.h>
#include <linux/interrupt.h>
#include <linux/smp.h>
#include <linux/kernel.h>
#include <linux/perf_event.h>
#include <linux/uaccess.h>

#include <asm/irq.h>
#include <asm/irq_regs.h>
#include <asm/stacktrace.h>
#include <asm/time.h> /* For perf_irq */

/* These are for 32bit counters. For 64bit ones, define them accordingly. */
#define MAX_PERIOD ((1ULL << 32) - 1)
#define VALID_COUNT 0x7fffffff
#define TOTAL_BITS 32
#define HIGHEST_BIT 31

#define MIPS_MAX_HWEVENTS 4

struct cpu_hw_events {
	/* Array of events on this cpu. */
	struct perf_event	*events[MIPS_MAX_HWEVENTS];

	/*
 * Set the bit (indexed by the counter number) when the counter
 * is used for an event.
 */
	unsigned long		used_mask[BITS_TO_LONGS(MIPS_MAX_HWEVENTS)];

	/*
 * The borrowed MSB for the performance counter. A MIPS performance
 * counter uses its bit 31 (for 32bit counters) or bit 63 (for 64bit
 * counters) as a factor of determining whether a counter overflow
 * should be signaled. So here we use a separate MSB for each
 * counter to make things easy.
 */
	unsigned long		msbs[BITS_TO_LONGS(MIPS_MAX_HWEVENTS)];

	/*
 * Software copy of the control register for each performance counter.
 * MIPS CPUs vary in performance counters. They use this differently,
 * and even may not use it.
 */
	unsigned int		saved_ctrl[MIPS_MAX_HWEVENTS];
};
DEFINE_PER_CPU(struct cpu_hw_events, cpu_hw_events) = {
	.saved_ctrl = {0},
};

/* The description of MIPS performance events. */
struct mips_perf_event {
	unsigned int event_id;
	/*
 * MIPS performance counters are indexed starting from 0.
 * CNTR_EVEN indicates the indexes of the counters to be used are
 * even numbers.
 */
	unsigned int cntr_mask;
	#define CNTR_EVEN 0x55555555
	#define CNTR_ODD 0xaaaaaaaa
#ifdef CONFIG_MIPS_MT_SMP
	enum {
		T  = 0,
		V  = 1,
		P  = 2,
	} range;
#else
	#define T
	#define V
	#define P
#endif
};

static struct mips_perf_event raw_event;
static DEFINE_MUTEX(raw_event_mutex);

#define UNSUPPORTED_PERF_EVENT_ID 0xffffffff
#define C(x) PERF_COUNT_HW_CACHE_##x

struct mips_pmu {
	const char	*name;
	int		irq;
	irqreturn_t	(*handle_irq)(int irq, void *dev);
	int		(*handle_shared_irq)(void);
	void		(*start)(void);
	void		(*stop)(void);
	int		(*alloc_counter)(struct cpu_hw_events *cpuc,
					struct hw_perf_event *hwc);
	u64		(*read_counter)(unsigned int idx);
	void		(*write_counter)(unsigned int idx, u64 val);
	void		(*enable_event)(struct hw_perf_event *evt, int idx);
	void		(*disable_event)(int idx);
	const struct mips_perf_event *(*map_raw_event)(u64 config);
	const struct mips_perf_event (*general_event_map)[PERF_COUNT_HW_MAX];
	const struct mips_perf_event (*cache_event_map)
				[PERF_COUNT_HW_CACHE_MAX]
				[PERF_COUNT_HW_CACHE_OP_MAX]
				[PERF_COUNT_HW_CACHE_RESULT_MAX];
	unsigned int	num_counters;
};

static const struct mips_pmu *mipspmu;

static int
mipspmu_event_set_period(struct perf_event *event,
			struct hw_perf_event *hwc,
			int idx)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	s64 left = local64_read(&hwc->period_left);
	s64 period = hwc->sample_period;
	int ret = 0;
	u64 uleft;
	unsigned long flags;

	if (unlikely(left <= -period)) {
		left = period;
		local64_set(&hwc->period_left, left);
		hwc->last_period = period;
		ret = 1;
	}

	if (unlikely(left <= 0)) {
		left += period;
		local64_set(&hwc->period_left, left);
		hwc->last_period = period;
		ret = 1;
	}

	if (left > (s64)MAX_PERIOD)
		left = MAX_PERIOD;

	local64_set(&hwc->prev_count, (u64)-left);

	local_irq_save(flags);
	uleft = (u64)(-left) & MAX_PERIOD;
	uleft > VALID_COUNT ?
		set_bit(idx, cpuc->msbs) : clear_bit(idx, cpuc->msbs);
	mipspmu->write_counter(idx, (u64)(-left) & VALID_COUNT);
	local_irq_restore(flags);

	perf_event_update_userpage(event);

	return ret;
}

static void mipspmu_event_update(struct perf_event *event,
			struct hw_perf_event *hwc,
			int idx)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	unsigned long flags;
	int shift = 64 - TOTAL_BITS;
	s64 prev_raw_count, new_raw_count;
	u64 delta;

again:
	prev_raw_count = local64_read(&hwc->prev_count);
	local_irq_save(flags);
	/* Make the counter value be a "real" one. */
	new_raw_count = mipspmu->read_counter(idx);
	if (new_raw_count & (test_bit(idx, cpuc->msbs) << HIGHEST_BIT)) {
		new_raw_count &= VALID_COUNT;
		clear_bit(idx, cpuc->msbs);
	} else
		new_raw_count |= (test_bit(idx, cpuc->msbs) << HIGHEST_BIT);
	local_irq_restore(flags);

	if (local64_cmpxchg(&hwc->prev_count, prev_raw_count,
				new_raw_count) != prev_raw_count)
		goto again;

	delta = (new_raw_count << shift) - (prev_raw_count << shift);
	delta >>= shift;

	local64_add(delta, &event->count);
	local64_sub(delta, &hwc->period_left);

	return;
}

static void mipspmu_start(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;

	if (!mipspmu)
		return;

	if (flags & PERF_EF_RELOAD)
		WARN_ON_ONCE(!(hwc->state & PERF_HES_UPTODATE));

	hwc->state = 0;

	/* Set the period for the event. */
	mipspmu_event_set_period(event, hwc, hwc->idx);

	/* Enable the event. */
	mipspmu->enable_event(hwc, hwc->idx);
}

static void mipspmu_stop(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;

	if (!mipspmu)
		return;

	if (!(hwc->state & PERF_HES_STOPPED)) {
		/* We are working on a local event. */
		mipspmu->disable_event(hwc->idx);
		barrier();
		mipspmu_event_update(event, hwc, hwc->idx);
		hwc->state |= PERF_HES_STOPPED | PERF_HES_UPTODATE;
	}
}

static int mipspmu_add(struct perf_event *event, int flags)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	struct hw_perf_event *hwc = &event->hw;
	int idx;
	int err = 0;

	perf_pmu_disable(event->pmu);

	/* To look for a free counter for this event. */
	idx = mipspmu->alloc_counter(cpuc, hwc);
	if (idx < 0) {
		err = idx;
		goto out;
	}

	/*
 * If there is an event in the counter we are going to use then
 * make sure it is disabled.
 */
	event->hw.idx = idx;
	mipspmu->disable_event(idx);
	cpuc->events[idx] = event;

	hwc->state = PERF_HES_STOPPED | PERF_HES_UPTODATE;
	if (flags & PERF_EF_START)
		mipspmu_start(event, PERF_EF_RELOAD);

	/* Propagate our changes to the userspace mapping. */
	perf_event_update_userpage(event);

out:
	perf_pmu_enable(event->pmu);
	return err;
}

static void mipspmu_del(struct perf_event *event, int flags)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	struct hw_perf_event *hwc = &event->hw;
	int idx = hwc->idx;

	WARN_ON(idx < 0 || idx >= mipspmu->num_counters);

	mipspmu_stop(event, PERF_EF_UPDATE);
	cpuc->events[idx] = NULL;
	clear_bit(idx, cpuc->used_mask);

	perf_event_update_userpage(event);
}

static void mipspmu_read(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;

	/* Don't read disabled counters! */
	if (hwc->idx < 0)
		return;

	mipspmu_event_update(event, hwc, hwc->idx);
}

static void mipspmu_enable(struct pmu *pmu)
{
	if (mipspmu)
		mipspmu->start();
}

static void mipspmu_disable(struct pmu *pmu)
{
	if (mipspmu)
		mipspmu->stop();
}

static atomic_t active_events = ATOMIC_INIT(0);
static DEFINE_MUTEX(pmu_reserve_mutex);
static int (*save_perf_irq)(void);

static int mipspmu_get_irq(void)
{
	int err;

	if (mipspmu->irq >= 0) {
		/* Request my own irq handler. */
		err = request_irq(mipspmu->irq, mipspmu->handle_irq,
			IRQF_DISABLED | IRQF_NOBALANCING,
			"mips_perf_pmu", NULL);
		if (err) {
			pr_warning("Unable to request IRQ%d for MIPS "
			   "performance counters!\n", mipspmu->irq);
		}
	} else if (cp0_perfcount_irq < 0) {
		/*
 * We are sharing the irq number with the timer interrupt.
 */
		save_perf_irq = perf_irq;
		perf_irq = mipspmu->handle_shared_irq;
		err = 0;
	} else {
		pr_warning("The platform hasn't properly defined its "
			"interrupt controller.\n");
		err = -ENOENT;
	}

	return err;
}

static void mipspmu_free_irq(void)
{
	if (mipspmu->irq >= 0)
		free_irq(mipspmu->irq, NULL);
	else if (cp0_perfcount_irq < 0)
		perf_irq = save_perf_irq;
}

/*
 * mipsxx/rm9000/loongson2 have different performance counters, they have
 * specific low-level init routines.
 */
static void reset_counters(void *arg);
static int __hw_perf_event_init(struct perf_event *event);

static void hw_perf_event_destroy(struct perf_event *event)
{
	if (atomic_dec_and_mutex_lock(&active_events,
				&pmu_reserve_mutex)) {
		/*
 * We must not call the destroy function with interrupts
 * disabled.
 */
		on_each_cpu(reset_counters,
			(void *)(long)mipspmu->num_counters, 1);
		mipspmu_free_irq();
		mutex_unlock(&pmu_reserve_mutex);
	}
}

static int mipspmu_event_init(struct perf_event *event)
{
	int err = 0;

	switch (event->attr.type) {
	case PERF_TYPE_RAW:
	case PERF_TYPE_HARDWARE:
	case PERF_TYPE_HW_CACHE:
		break;

	default:
		return -ENOENT;
	}

	if (!mipspmu || event->cpu >= nr_cpumask_bits ||
		(event->cpu >= 0 && !cpu_online(event->cpu)))
		return -ENODEV;

	if (!atomic_inc_not_zero(&active_events)) {
		if (atomic_read(&active_events) > MIPS_MAX_HWEVENTS) {
			atomic_dec(&active_events);
			return -ENOSPC;
		}

		mutex_lock(&pmu_reserve_mutex);
		if (atomic_read(&active_events) == 0)
			err = mipspmu_get_irq();

		if (!err)
			atomic_inc(&active_events);
		mutex_unlock(&pmu_reserve_mutex);
	}

	if (err)
		return err;

	err = __hw_perf_event_init(event);
	if (err)
		hw_perf_event_destroy(event);

	return err;
}

static struct pmu pmu = {
	.pmu_enable	= mipspmu_enable,
	.pmu_disable	= mipspmu_disable,
	.event_init	= mipspmu_event_init,
	.add		= mipspmu_add,
	.del		= mipspmu_del,
	.start		= mipspmu_start,
	.stop		= mipspmu_stop,
	.read		= mipspmu_read,
};

static inline unsigned int
mipspmu_perf_event_encode(const struct mips_perf_event *pev)
{
/*
 * Top 8 bits for range, next 16 bits for cntr_mask, lowest 8 bits for
 * event_id.
 */
#ifdef CONFIG_MIPS_MT_SMP
	return ((unsigned int)pev->range << 24) |
		(pev->cntr_mask & 0xffff00) |
		(pev->event_id & 0xff);
#else
	return (pev->cntr_mask & 0xffff00) |
		(pev->event_id & 0xff);
#endif
}

static const struct mips_perf_event *
mipspmu_map_general_event(int idx)
{
	const struct mips_perf_event *pev;

	pev = ((*mipspmu->general_event_map)[idx].event_id ==
		UNSUPPORTED_PERF_EVENT_ID ? ERR_PTR(-EOPNOTSUPP) :
		&(*mipspmu->general_event_map)[idx]);

	return pev;
}

static const struct mips_perf_event *
mipspmu_map_cache_event(u64 config)
{
	unsigned int cache_type, cache_op, cache_result;
	const struct mips_perf_event *pev;

	cache_type = (config >> 0) & 0xff;
	if (cache_type >= PERF_COUNT_HW_CACHE_MAX)
		return ERR_PTR(-EINVAL);

	cache_op = (config >> 8) & 0xff;
	if (cache_op >= PERF_COUNT_HW_CACHE_OP_MAX)
		return ERR_PTR(-EINVAL);

	cache_result = (config >> 16) & 0xff;
	if (cache_result >= PERF_COUNT_HW_CACHE_RESULT_MAX)
		return ERR_PTR(-EINVAL);

	pev = &((*mipspmu->cache_event_map)
					[cache_type]
					[cache_op]
					[cache_result]);

	if (pev->event_id == UNSUPPORTED_PERF_EVENT_ID)
		return ERR_PTR(-EOPNOTSUPP);

	return pev;

}

static int validate_event(struct cpu_hw_events *cpuc,
	       struct perf_event *event)
{
	struct hw_perf_event fake_hwc = event->hw;

	/* Allow mixed event group. So return 1 to pass validation. */
	if (event->pmu != &pmu || event->state <= PERF_EVENT_STATE_OFF)
		return 1;

	return mipspmu->alloc_counter(cpuc, &fake_hwc) >= 0;
}

static int validate_group(struct perf_event *event)
{
	struct perf_event *sibling, *leader = event->group_leader;
	struct cpu_hw_events fake_cpuc;

	memset(&fake_cpuc, 0, sizeof(fake_cpuc));

	if (!validate_event(&fake_cpuc, leader))
		return -ENOSPC;

	list_for_each_entry(sibling, &leader->sibling_list, group_entry) {
		if (!validate_event(&fake_cpuc, sibling))
			return -ENOSPC;
	}

	if (!validate_event(&fake_cpuc, event))
		return -ENOSPC;

	return 0;
}

/* This is needed by specific irq handlers in perf_event_*.c */
static void
handle_associated_event(struct cpu_hw_events *cpuc,
	int idx, struct perf_sample_data *data, struct pt_regs *regs)
{
	struct perf_event *event = cpuc->events[idx];
	struct hw_perf_event *hwc = &event->hw;

	mipspmu_event_update(event, hwc, idx);
	data->period = event->hw.last_period;
	if (!mipspmu_event_set_period(event, hwc, idx))
		return;

	if (perf_event_overflow(event, 0, data, regs))
		mipspmu->disable_event(idx);
}

#include "perf_event_mipsxx.c"

/* Callchain handling code. */

/*
 * Leave userspace callchain empty for now. When we find a way to trace
 * the user stack callchains, we add here.
 */
void perf_callchain_user(struct perf_callchain_entry *entry,
		    struct pt_regs *regs)
{
}

static void save_raw_perf_callchain(struct perf_callchain_entry *entry,
	unsigned long reg29)
{
	unsigned long *sp = (unsigned long *)reg29;
	unsigned long addr;

	while (!kstack_end(sp)) {
		addr = *sp++;
		if (__kernel_text_address(addr)) {
			perf_callchain_store(entry, addr);
			if (entry->nr >= PERF_MAX_STACK_DEPTH)
				break;
		}
	}
}

void perf_callchain_kernel(struct perf_callchain_entry *entry,
		      struct pt_regs *regs)
{
	unsigned long sp = regs->regs[29];
#ifdef CONFIG_KALLSYMS
	unsigned long ra = regs->regs[31];
	unsigned long pc = regs->cp0_epc;

	if (raw_show_trace || !__kernel_text_address(pc)) {
		unsigned long stack_page =
			(unsigned long)task_stack_page(current);
		if (stack_page && sp >= stack_page &&
		    sp <= stack_page + THREAD_SIZE - 32)
			save_raw_perf_callchain(entry, sp);
		return;
	}
	do {
		perf_callchain_store(entry, pc);
		if (entry->nr >= PERF_MAX_STACK_DEPTH)
			break;
		pc = unwind_stack(current, &sp, pc, &ra);
	} while (pc);
#else
	save_raw_perf_callchain(entry, sp);
#endif
}

/*
 * Performance event support - powerpc architecture code
 *
 * Copyright 2008-2009 Paul Mackerras, IBM Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/perf_event.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>
#include <asm/reg.h>
#include <asm/pmc.h>
#include <asm/machdep.h>
#include <asm/firmware.h>
#include <asm/ptrace.h>

struct cpu_hw_events {
	int n_events;
	int n_percpu;
	int disabled;
	int n_added;
	int n_limited;
	u8  pmcs_enabled;
	struct perf_event *event[MAX_HWEVENTS];
	u64 events[MAX_HWEVENTS];
	unsigned int flags[MAX_HWEVENTS];
	unsigned long mmcr[3];
	struct perf_event *limited_counter[MAX_LIMITED_HWCOUNTERS];
	u8  limited_hwidx[MAX_LIMITED_HWCOUNTERS];
	u64 alternatives[MAX_HWEVENTS][MAX_EVENT_ALTERNATIVES];
	unsigned long amasks[MAX_HWEVENTS][MAX_EVENT_ALTERNATIVES];
	unsigned long avalues[MAX_HWEVENTS][MAX_EVENT_ALTERNATIVES];

	unsigned int group_flag;
	int n_txn_start;
};
DEFINE_PER_CPU(struct cpu_hw_events, cpu_hw_events);

struct power_pmu *ppmu;

/*
 * Normally, to ignore kernel events we set the FCS (freeze counters
 * in supervisor mode) bit in MMCR0, but if the kernel runs with the
 * hypervisor bit set in the MSR, or if we are running on a processor
 * where the hypervisor bit is forced to 1 (as on Apple G5 processors),
 * then we need to use the FCHV bit to ignore kernel events.
 */
static unsigned int freeze_events_kernel = MMCR0_FCS;

/*
 * 32-bit doesn't have MMCRA but does have an MMCR2,
 * and a few other names are different.
 */
#ifdef CONFIG_PPC32

#define MMCR0_FCHV 0
#define MMCR0_PMCjCE MMCR0_PMCnCE

#define SPRN_MMCRA SPRN_MMCR2
#define MMCRA_SAMPLE_ENABLE 0

static inline unsigned long perf_ip_adjust(struct pt_regs *regs)
{
	return 0;
}
static inline void perf_get_data_addr(struct pt_regs *regs, u64 *addrp) { }
static inline u32 perf_get_misc_flags(struct pt_regs *regs)
{
	return 0;
}
static inline void perf_read_regs(struct pt_regs *regs) { }
static inline int perf_intr_is_nmi(struct pt_regs *regs)
{
	return 0;
}

#endif /* CONFIG_PPC32 */

/*
 * Things that are specific to 64-bit implementations.
 */
#ifdef CONFIG_PPC64

static inline unsigned long perf_ip_adjust(struct pt_regs *regs)
{
	unsigned long mmcra = regs->dsisr;

	if ((mmcra & MMCRA_SAMPLE_ENABLE) && !(ppmu->flags & PPMU_ALT_SIPR)) {
		unsigned long slot = (mmcra & MMCRA_SLOT) >> MMCRA_SLOT_SHIFT;
		if (slot > 1)
			return 4 * (slot - 1);
	}
	return 0;
}

/*
 * The user wants a data address recorded.
 * If we're not doing instruction sampling, give them the SDAR
 * (sampled data address). If we are doing instruction sampling, then
 * only give them the SDAR if it corresponds to the instruction
 * pointed to by SIAR; this is indicated by the [POWER6_]MMCRA_SDSYNC
 * bit in MMCRA.
 */
static inline void perf_get_data_addr(struct pt_regs *regs, u64 *addrp)
{
	unsigned long mmcra = regs->dsisr;
	unsigned long sdsync = (ppmu->flags & PPMU_ALT_SIPR) ?
		POWER6_MMCRA_SDSYNC : MMCRA_SDSYNC;

	if (!(mmcra & MMCRA_SAMPLE_ENABLE) || (mmcra & sdsync))
		*addrp = mfspr(SPRN_SDAR);
}

static inline u32 perf_get_misc_flags(struct pt_regs *regs)
{
	unsigned long mmcra = regs->dsisr;
	unsigned long sihv = MMCRA_SIHV;
	unsigned long sipr = MMCRA_SIPR;

	if (TRAP(regs) != 0xf00)
		return 0;	/* not a PMU interrupt */

	if (ppmu->flags & PPMU_ALT_SIPR) {
		sihv = POWER6_MMCRA_SIHV;
		sipr = POWER6_MMCRA_SIPR;
	}

	/* PR has priority over HV, so order below is important */
	if (mmcra & sipr)
		return PERF_RECORD_MISC_USER;
	if ((mmcra & sihv) && (freeze_events_kernel != MMCR0_FCHV))
		return PERF_RECORD_MISC_HYPERVISOR;
	return PERF_RECORD_MISC_KERNEL;
}

/*
 * Overload regs->dsisr to store MMCRA so we only need to read it once
 * on each interrupt.
 */
static inline void perf_read_regs(struct pt_regs *regs)
{
	regs->dsisr = mfspr(SPRN_MMCRA);
}

/*
 * If interrupts were soft-disabled when a PMU interrupt occurs, treat
 * it as an NMI.
 */
static inline int perf_intr_is_nmi(struct pt_regs *regs)
{
	return !regs->softe;
}

#endif /* CONFIG_PPC64 */

static void perf_event_interrupt(struct pt_regs *regs);

void perf_event_print_debug(void)
{
}

/*
 * Read one performance monitor counter (PMC).
 */
static unsigned long read_pmc(int idx)
{
	unsigned long val;

	switch (idx) {
	case 1:
		val = mfspr(SPRN_PMC1);
		break;
	case 2:
		val = mfspr(SPRN_PMC2);
		break;
	case 3:
		val = mfspr(SPRN_PMC3);
		break;
	case 4:
		val = mfspr(SPRN_PMC4);
		break;
	case 5:
		val = mfspr(SPRN_PMC5);
		break;
	case 6:
		val = mfspr(SPRN_PMC6);
		break;
#ifdef CONFIG_PPC64
	case 7:
		val = mfspr(SPRN_PMC7);
		break;
	case 8:
		val = mfspr(SPRN_PMC8);
		break;
#endif /* CONFIG_PPC64 */
	default:
		printk(KERN_ERR "oops trying to read PMC%d\n", idx);
		val = 0;
	}
	return val;
}

/*
 * Write one PMC.
 */
static void write_pmc(int idx, unsigned long val)
{
	switch (idx) {
	case 1:
		mtspr(SPRN_PMC1, val);
		break;
	case 2:
		mtspr(SPRN_PMC2, val);
		break;
	case 3:
		mtspr(SPRN_PMC3, val);
		break;
	case 4:
		mtspr(SPRN_PMC4, val);
		break;
	case 5:
		mtspr(SPRN_PMC5, val);
		break;
	case 6:
		mtspr(SPRN_PMC6, val);
		break;
#ifdef CONFIG_PPC64
	case 7:
		mtspr(SPRN_PMC7, val);
		break;
	case 8:
		mtspr(SPRN_PMC8, val);
		break;
#endif /* CONFIG_PPC64 */
	default:
		printk(KERN_ERR "oops trying to write PMC%d\n", idx);
	}
}

/*
 * Check if a set of events can all go on the PMU at once.
 * If they can't, this will look at alternative codes for the events
 * and see if any combination of alternative codes is feasible.
 * The feasible set is returned in event_id[].
 */
static int power_check_constraints(struct cpu_hw_events *cpuhw,
				   u64 event_id[], unsigned int cflags[],
				   int n_ev)
{
	unsigned long mask, value, nv;
	unsigned long smasks[MAX_HWEVENTS], svalues[MAX_HWEVENTS];
	int n_alt[MAX_HWEVENTS], choice[MAX_HWEVENTS];
	int i, j;
	unsigned long addf = ppmu->add_fields;
	unsigned long tadd = ppmu->test_adder;

	if (n_ev > ppmu->n_counter)
		return -1;

	/* First see if the events will go on as-is */
	for (i = 0; i < n_ev; ++i) {
		if ((cflags[i] & PPMU_LIMITED_PMC_REQD)
		    && !ppmu->limited_pmc_event(event_id[i])) {
			ppmu->get_alternatives(event_id[i], cflags[i],
					       cpuhw->alternatives[i]);
			event_id[i] = cpuhw->alternatives[i][0];
		}
		if (ppmu->get_constraint(event_id[i], &cpuhw->amasks[i][0],
					 &cpuhw->avalues[i][0]))
			return -1;
	}
	value = mask = 0;
	for (i = 0; i < n_ev; ++i) {
		nv = (value | cpuhw->avalues[i][0]) +
			(value & cpuhw->avalues[i][0] & addf);
		if ((((nv + tadd) ^ value) & mask) != 0 ||
		    (((nv + tadd) ^ cpuhw->avalues[i][0]) &
		     cpuhw->amasks[i][0]) != 0)
			break;
		value = nv;
		mask |= cpuhw->amasks[i][0];
	}
	if (i == n_ev)
		return 0;	/* all OK */

	/* doesn't work, gather alternatives... */
	if (!ppmu->get_alternatives)
		return -1;
	for (i = 0; i < n_ev; ++i) {
		choice[i] = 0;
		n_alt[i] = ppmu->get_alternatives(event_id[i], cflags[i],
						  cpuhw->alternatives[i]);
		for (j = 1; j < n_alt[i]; ++j)
			ppmu->get_constraint(cpuhw->alternatives[i][j],
					     &cpuhw->amasks[i][j],
					     &cpuhw->avalues[i][j]);
	}

	/* enumerate all possibilities and see if any will work */
	i = 0;
	j = -1;
	value = mask = nv = 0;
	while (i < n_ev) {
		if (j >= 0) {
			/* we're backtracking, restore context */
			value = svalues[i];
			mask = smasks[i];
			j = choice[i];
		}
		/*
 * See if any alternative k for event_id i,
 * where k > j, will satisfy the constraints.
 */
		while (++j < n_alt[i]) {
			nv = (value | cpuhw->avalues[i][j]) +
				(value & cpuhw->avalues[i][j] & addf);
			if ((((nv + tadd) ^ value) & mask) == 0 &&
			    (((nv + tadd) ^ cpuhw->avalues[i][j])
			     & cpuhw->amasks[i][j]) == 0)
				break;
		}
		if (j >= n_alt[i]) {
			/*
 * No feasible alternative, backtrack
 * to event_id i-1 and continue enumerating its
 * alternatives from where we got up to.
 */
			if (--i < 0)
				return -1;
		} else {
			/*
 * Found a feasible alternative for event_id i,
 * remember where we got up to with this event_id,
 * go on to the next event_id, and start with
 * the first alternative for it.
 */
			choice[i] = j;
			svalues[i] = value;
			smasks[i] = mask;
			value = nv;
			mask |= cpuhw->amasks[i][j];
			++i;
			j = -1;
		}
	}

	/* OK, we have a feasible combination, tell the caller the solution */
	for (i = 0; i < n_ev; ++i)
		event_id[i] = cpuhw->alternatives[i][choice[i]];
	return 0;
}

/*
 * Check if newly-added events have consistent settings for
 * exclude_{user,kernel,hv} with each other and any previously
 * added events.
 */
static int check_excludes(struct perf_event **ctrs, unsigned int cflags[],
			  int n_prev, int n_new)
{
	int eu = 0, ek = 0, eh = 0;
	int i, n, first;
	struct perf_event *event;

	n = n_prev + n_new;
	if (n <= 1)
		return 0;

	first = 1;
	for (i = 0; i < n; ++i) {
		if (cflags[i] & PPMU_LIMITED_PMC_OK) {
			cflags[i] &= ~PPMU_LIMITED_PMC_REQD;
			continue;
		}
		event = ctrs[i];
		if (first) {
			eu = event->attr.exclude_user;
			ek = event->attr.exclude_kernel;
			eh = event->attr.exclude_hv;
			first = 0;
		} else if (event->attr.exclude_user != eu ||
			   event->attr.exclude_kernel != ek ||
			   event->attr.exclude_hv != eh) {
			return -EAGAIN;
		}
	}

	if (eu || ek || eh)
		for (i = 0; i < n; ++i)
			if (cflags[i] & PPMU_LIMITED_PMC_OK)
				cflags[i] |= PPMU_LIMITED_PMC_REQD;

	return 0;
}

static u64 check_and_compute_delta(u64 prev, u64 val)
{
	u64 delta = (val - prev) & 0xfffffffful;

	/*
 * POWER7 can roll back counter values, if the new value is smaller
 * than the previous value it will cause the delta and the counter to
 * have bogus values unless we rolled a counter over. If a coutner is
 * rolled back, it will be smaller, but within 256, which is the maximum
 * number of events to rollback at once. If we dectect a rollback
 * return 0. This can lead to a small lack of precision in the
 * counters.
 */
	if (prev > val && (prev - val) < 256)
		delta = 0;

	return delta;
}

static void power_pmu_read(struct perf_event *event)
{
	s64 val, delta, prev;

	if (event->hw.state & PERF_HES_STOPPED)
		return;

	if (!event->hw.idx)
		return;
	/*
 * Performance monitor interrupts come even when interrupts
 * are soft-disabled, as long as interrupts are hard-enabled.
 * Therefore we treat them like NMIs.
 */
	do {
		prev = local64_read(&event->hw.prev_count);
		barrier();
		val = read_pmc(event->hw.idx);
		delta = check_and_compute_delta(prev, val);
		if (!delta)
			return;
	} while (local64_cmpxchg(&event->hw.prev_count, prev, val) != prev);

	local64_add(delta, &event->count);
	local64_sub(delta, &event->hw.period_left);
}

/*
 * On some machines, PMC5 and PMC6 can't be written, don't respect
 * the freeze conditions, and don't generate interrupts. This tells
 * us if `event' is using such a PMC.
 */
static int is_limited_pmc(int pmcnum)
{
	return (ppmu->flags & PPMU_LIMITED_PMC5_6)
		&& (pmcnum == 5 || pmcnum == 6);
}

static void freeze_limited_counters(struct cpu_hw_events *cpuhw,
				    unsigned long pmc5, unsigned long pmc6)
{
	struct perf_event *event;
	u64 val, prev, delta;
	int i;

	for (i = 0; i < cpuhw->n_limited; ++i) {
		event = cpuhw->limited_counter[i];
		if (!event->hw.idx)
			continue;
		val = (event->hw.idx == 5) ? pmc5 : pmc6;
		prev = local64_read(&event->hw.prev_count);
		event->hw.idx = 0;
		delta = check_and_compute_delta(prev, val);
		if (delta)
			local64_add(delta, &event->count);
	}
}

static void thaw_limited_counters(struct cpu_hw_events *cpuhw,
				  unsigned long pmc5, unsigned long pmc6)
{
	struct perf_event *event;
	u64 val, prev;
	int i;

	for (i = 0; i < cpuhw->n_limited; ++i) {
		event = cpuhw->limited_counter[i];
		event->hw.idx = cpuhw->limited_hwidx[i];
		val = (event->hw.idx == 5) ? pmc5 : pmc6;
		prev = local64_read(&event->hw.prev_count);
		if (check_and_compute_delta(prev, val))
			local64_set(&event->hw.prev_count, val);
		perf_event_update_userpage(event);
	}
}

/*
 * Since limited events don't respect the freeze conditions, we
 * have to read them immediately after freezing or unfreezing the
 * other events. We try to keep the values from the limited
 * events as consistent as possible by keeping the delay (in
 * cycles and instructions) between freezing/unfreezing and reading
 * the limited events as small and consistent as possible.
 * Therefore, if any limited events are in use, we read them
 * both, and always in the same order, to minimize variability,
 * and do it inside the same asm that writes MMCR0.
 */
static void write_mmcr0(struct cpu_hw_events *cpuhw, unsigned long mmcr0)
{
	unsigned long pmc5, pmc6;

	if (!cpuhw->n_limited) {
		mtspr(SPRN_MMCR0, mmcr0);
		return;
	}

	/*
 * Write MMCR0, then read PMC5 and PMC6 immediately.
 * To ensure we don't get a performance monitor interrupt
 * between writing MMCR0 and freezing/thawing the limited
 * events, we first write MMCR0 with the event overflow
 * interrupt enable bits turned off.
 */
	asm volatile("mtspr %3,%2; mfspr %0,%4; mfspr %1,%5"
		     : "=&r" (pmc5), "=&r" (pmc6)
		     : "r" (mmcr0 & ~(MMCR0_PMC1CE | MMCR0_PMCjCE)),
		       "i" (SPRN_MMCR0),
		       "i" (SPRN_PMC5), "i" (SPRN_PMC6));

	if (mmcr0 & MMCR0_FC)
		freeze_limited_counters(cpuhw, pmc5, pmc6);
	else
		thaw_limited_counters(cpuhw, pmc5, pmc6);

	/*
 * Write the full MMCR0 including the event overflow interrupt
 * enable bits, if necessary.
 */
	if (mmcr0 & (MMCR0_PMC1CE | MMCR0_PMCjCE))
		mtspr(SPRN_MMCR0, mmcr0);
}

/*
 * Disable all events to prevent PMU interrupts and to allow
 * events to be added or removed.
 */
static void power_pmu_disable(struct pmu *pmu)
{
	struct cpu_hw_events *cpuhw;
	unsigned long flags;

	if (!ppmu)
		return;
	local_irq_save(flags);
	cpuhw = &__get_cpu_var(cpu_hw_events);

	if (!cpuhw->disabled) {
		cpuhw->disabled = 1;
		cpuhw->n_added = 0;

		/*
 * Check if we ever enabled the PMU on this cpu.
 */
		if (!cpuhw->pmcs_enabled) {
			ppc_enable_pmcs();
			cpuhw->pmcs_enabled = 1;
		}

		/*
 * Disable instruction sampling if it was enabled
 */
		if (cpuhw->mmcr[2] & MMCRA_SAMPLE_ENABLE) {
			mtspr(SPRN_MMCRA,
			      cpuhw->mmcr[2] & ~MMCRA_SAMPLE_ENABLE);
			mb();
		}

		/*
 * Set the 'freeze counters' bit.
 * The barrier is to make sure the mtspr has been
 * executed and the PMU has frozen the events
 * before we return.
 */
		write_mmcr0(cpuhw, mfspr(SPRN_MMCR0) | MMCR0_FC);
		mb();
	}
	local_irq_restore(flags);
}

/*
 * Re-enable all events if disable == 0.
 * If we were previously disabled and events were added, then
 * put the new config on the PMU.
 */
static void power_pmu_enable(struct pmu *pmu)
{
	struct perf_event *event;
	struct cpu_hw_events *cpuhw;
	unsigned long flags;
	long i;
	unsigned long val;
	s64 left;
	unsigned int hwc_index[MAX_HWEVENTS];
	int n_lim;
	int idx;

	if (!ppmu)
		return;
	local_irq_save(flags);
	cpuhw = &__get_cpu_var(cpu_hw_events);
	if (!cpuhw->disabled) {
		local_irq_restore(flags);
		return;
	}
	cpuhw->disabled = 0;

	/*
 * If we didn't change anything, or only removed events,
 * no need to recalculate MMCR* settings and reset the PMCs.
 * Just reenable the PMU with the current MMCR* settings
 * (possibly updated for removal of events).
 */
	if (!cpuhw->n_added) {
		mtspr(SPRN_MMCRA, cpuhw->mmcr[2] & ~MMCRA_SAMPLE_ENABLE);
		mtspr(SPRN_MMCR1, cpuhw->mmcr[1]);
		if (cpuhw->n_events == 0)
			ppc_set_pmu_inuse(0);
		goto out_enable;
	}

	/*
 * Compute MMCR* values for the new set of events
 */
	if (ppmu->compute_mmcr(cpuhw->events, cpuhw->n_events, hwc_index,
			       cpuhw->mmcr)) {
		/* shouldn't ever get here */
		printk(KERN_ERR "oops compute_mmcr failed\n");
		goto out;
	}

	/*
 * Add in MMCR0 freeze bits corresponding to the
 * attr.exclude_* bits for the first event.
 * We have already checked that all events have the
 * same values for these bits as the first event.
 */
	event = cpuhw->event[0];
	if (event->attr.exclude_user)
		cpuhw->mmcr[0] |= MMCR0_FCP;
	if (event->attr.exclude_kernel)
		cpuhw->mmcr[0] |= freeze_events_kernel;
	if (event->attr.exclude_hv)
		cpuhw->mmcr[0] |= MMCR0_FCHV;

	/*
 * Write the new configuration to MMCR* with the freeze
 * bit set and set the hardware events to their initial values.
 * Then unfreeze the events.
 */
	ppc_set_pmu_inuse(1);
	mtspr(SPRN_MMCRA, cpuhw->mmcr[2] & ~MMCRA_SAMPLE_ENABLE);
	mtspr(SPRN_MMCR1, cpuhw->mmcr[1]);
	mtspr(SPRN_MMCR0, (cpuhw->mmcr[0] & ~(MMCR0_PMC1CE | MMCR0_PMCjCE))
				| MMCR0_FC);

	/*
 * Read off any pre-existing events that need to move
 * to another PMC.
 */
	for (i = 0; i < cpuhw->n_events; ++i) {
		event = cpuhw->event[i];
		if (event->hw.idx && event->hw.idx != hwc_index[i] + 1) {
			power_pmu_read(event);
			write_pmc(event->hw.idx, 0);
			event->hw.idx = 0;
		}
	}

	/*
 * Initialize the PMCs for all the new and moved events.
 */
	cpuhw->n_limited = n_lim = 0;
	for (i = 0; i < cpuhw->n_events; ++i) {
		event = cpuhw->event[i];
		if (event->hw.idx)
			continue;
		idx = hwc_index[i] + 1;
		if (is_limited_pmc(idx)) {
			cpuhw->limited_counter[n_lim] = event;
			cpuhw->limited_hwidx[n_lim] = idx;
			++n_lim;
			continue;
		}
		val = 0;
		if (event->hw.sample_period) {
			left = local64_read(&event->hw.period_left);
			if (left < 0x80000000L)
				val = 0x80000000L - left;
		}
		local64_set(&event->hw.prev_count, val);
		event->hw.idx = idx;
		if (event->hw.state & PERF_HES_STOPPED)
			val = 0;
		write_pmc(idx, val);
		perf_event_update_userpage(event);
	}
	cpuhw->n_limited = n_lim;
	cpuhw->mmcr[0] |= MMCR0_PMXE | MMCR0_FCECE;

 out_enable:
	mb();
	write_mmcr0(cpuhw, cpuhw->mmcr[0]);

	/*
 * Enable instruction sampling if necessary
 */
	if (cpuhw->mmcr[2] & MMCRA_SAMPLE_ENABLE) {
		mb();
		mtspr(SPRN_MMCRA, cpuhw->mmcr[2]);
	}

 out:
	local_irq_restore(flags);
}

static int collect_events(struct perf_event *group, int max_count,
			  struct perf_event *ctrs[], u64 *events,
			  unsigned int *flags)
{
	int n = 0;
	struct perf_event *event;

	if (!is_software_event(group)) {
		if (n >= max_count)
			return -1;
		ctrs[n] = group;
		flags[n] = group->hw.event_base;
		events[n++] = group->hw.config;
	}
	list_for_each_entry(event, &group->sibling_list, group_entry) {
		if (!is_software_event(event) &&
		    event->state != PERF_EVENT_STATE_OFF) {
			if (n >= max_count)
				return -1;
			ctrs[n] = event;
			flags[n] = event->hw.event_base;
			events[n++] = event->hw.config;
		}
	}
	return n;
}

/*
 * Add a event to the PMU.
 * If all events are not already frozen, then we disable and
 * re-enable the PMU in order to get hw_perf_enable to do the
 * actual work of reconfiguring the PMU.
 */
static int power_pmu_add(struct perf_event *event, int ef_flags)
{
	struct cpu_hw_events *cpuhw;
	unsigned long flags;
	int n0;
	int ret = -EAGAIN;

	local_irq_save(flags);
	perf_pmu_disable(event->pmu);

	/*
 * Add the event to the list (if there is room)
 * and check whether the total set is still feasible.
 */
	cpuhw = &__get_cpu_var(cpu_hw_events);
	n0 = cpuhw->n_events;
	if (n0 >= ppmu->n_counter)
		goto out;
	cpuhw->event[n0] = event;
	cpuhw->events[n0] = event->hw.config;
	cpuhw->flags[n0] = event->hw.event_base;

	if (!(ef_flags & PERF_EF_START))
		event->hw.state = PERF_HES_STOPPED | PERF_HES_UPTODATE;

	/*
 * If group events scheduling transaction was started,
 * skip the schedulability test here, it will be performed
 * at commit time(->commit_txn) as a whole
 */
	if (cpuhw->group_flag & PERF_EVENT_TXN)
		goto nocheck;

	if (check_excludes(cpuhw->event, cpuhw->flags, n0, 1))
		goto out;
	if (power_check_constraints(cpuhw, cpuhw->events, cpuhw->flags, n0 + 1))
		goto out;
	event->hw.config = cpuhw->events[n0];

nocheck:
	++cpuhw->n_events;
	++cpuhw->n_added;

	ret = 0;
 out:
	perf_pmu_enable(event->pmu);
	local_irq_restore(flags);
	return ret;
}

/*
 * Remove a event from the PMU.
 */
static void power_pmu_del(struct perf_event *event, int ef_flags)
{
	struct cpu_hw_events *cpuhw;
	long i;
	unsigned long flags;

	local_irq_save(flags);
	perf_pmu_disable(event->pmu);

	power_pmu_read(event);

	cpuhw = &__get_cpu_var(cpu_hw_events);
	for (i = 0; i < cpuhw->n_events; ++i) {
		if (event == cpuhw->event[i]) {
			while (++i < cpuhw->n_events) {
				cpuhw->event[i-1] = cpuhw->event[i];
				cpuhw->events[i-1] = cpuhw->events[i];
				cpuhw->flags[i-1] = cpuhw->flags[i];
			}
			--cpuhw->n_events;
			ppmu->disable_pmc(event->hw.idx - 1, cpuhw->mmcr);
			if (event->hw.idx) {
				write_pmc(event->hw.idx, 0);
				event->hw.idx = 0;
			}
			perf_event_update_userpage(event);
			break;
		}
	}
	for (i = 0; i < cpuhw->n_limited; ++i)
		if (event == cpuhw->limited_counter[i])
			break;
	if (i < cpuhw->n_limited) {
		while (++i < cpuhw->n_limited) {
			cpuhw->limited_counter[i-1] = cpuhw->limited_counter[i];
			cpuhw->limited_hwidx[i-1] = cpuhw->limited_hwidx[i];
		}
		--cpuhw->n_limited;
	}
	if (cpuhw->n_events == 0) {
		/* disable exceptions if no events are running */
		cpuhw->mmcr[0] &= ~(MMCR0_PMXE | MMCR0_FCECE);
	}

	perf_pmu_enable(event->pmu);
	local_irq_restore(flags);
}

/*
 * POWER-PMU does not support disabling individual counters, hence
 * program their cycle counter to their max value and ignore the interrupts.
 */

static void power_pmu_start(struct perf_event *event, int ef_flags)
{
	unsigned long flags;
	s64 left;

	if (!event->hw.idx || !event->hw.sample_period)
		return;

	if (!(event->hw.state & PERF_HES_STOPPED))
		return;

	if (ef_flags & PERF_EF_RELOAD)
		WARN_ON_ONCE(!(event->hw.state & PERF_HES_UPTODATE));

	local_irq_save(flags);
	perf_pmu_disable(event->pmu);

	event->hw.state = 0;
	left = local64_read(&event->hw.period_left);
	write_pmc(event->hw.idx, left);

	perf_event_update_userpage(event);
	perf_pmu_enable(event->pmu);
	local_irq_restore(flags);
}

static void power_pmu_stop(struct perf_event *event, int ef_flags)
{
	unsigned long flags;

	if (!event->hw.idx || !event->hw.sample_period)
		return;

	if (event->hw.state & PERF_HES_STOPPED)
		return;

	local_irq_save(flags);
	perf_pmu_disable(event->pmu);

	power_pmu_read(event);
	event->hw.state |= PERF_HES_STOPPED | PERF_HES_UPTODATE;
	write_pmc(event->hw.idx, 0);

	perf_event_update_userpage(event);
	perf_pmu_enable(event->pmu);
	local_irq_restore(flags);
}

/*
 * Start group events scheduling transaction
 * Set the flag to make pmu::enable() not perform the
 * schedulability test, it will be performed at commit time
 */
void power_pmu_start_txn(struct pmu *pmu)
{
	struct cpu_hw_events *cpuhw = &__get_cpu_var(cpu_hw_events);

	perf_pmu_disable(pmu);
	cpuhw->group_flag |= PERF_EVENT_TXN;
	cpuhw->n_txn_start = cpuhw->n_events;
}

/*
 * Stop group events scheduling transaction
 * Clear the flag and pmu::enable() will perform the
 * schedulability test.
 */
void power_pmu_cancel_txn(struct pmu *pmu)
{
	struct cpu_hw_events *cpuhw = &__get_cpu_var(cpu_hw_events);

	cpuhw->group_flag &= ~PERF_EVENT_TXN;
	perf_pmu_enable(pmu);
}

/*
 * Commit group events scheduling transaction
 * Perform the group schedulability test as a whole
 * Return 0 if success
 */
int power_pmu_commit_txn(struct pmu *pmu)
{
	struct cpu_hw_events *cpuhw;
	long i, n;

	if (!ppmu)
		return -EAGAIN;
	cpuhw = &__get_cpu_var(cpu_hw_events);
	n = cpuhw->n_events;
	if (check_excludes(cpuhw->event, cpuhw->flags, 0, n))
		return -EAGAIN;
	i = power_check_constraints(cpuhw, cpuhw->events, cpuhw->flags, n);
	if (i < 0)
		return -EAGAIN;

	for (i = cpuhw->n_txn_start; i < n; ++i)
		cpuhw->event[i]->hw.config = cpuhw->events[i];

	cpuhw->group_flag &= ~PERF_EVENT_TXN;
	perf_pmu_enable(pmu);
	return 0;
}

/*
 * Return 1 if we might be able to put event on a limited PMC,
 * or 0 if not.
 * A event can only go on a limited PMC if it counts something
 * that a limited PMC can count, doesn't require interrupts, and
 * doesn't exclude any processor mode.
 */
static int can_go_on_limited_pmc(struct perf_event *event, u64 ev,
				 unsigned int flags)
{
	int n;
	u64 alt[MAX_EVENT_ALTERNATIVES];

	if (event->attr.exclude_user
	    || event->attr.exclude_kernel
	    || event->attr.exclude_hv
	    || event->attr.sample_period)
		return 0;

	if (ppmu->limited_pmc_event(ev))
		return 1;

	/*
 * The requested event_id isn't on a limited PMC already;
 * see if any alternative code goes on a limited PMC.
 */
	if (!ppmu->get_alternatives)
		return 0;

	flags |= PPMU_LIMITED_PMC_OK | PPMU_LIMITED_PMC_REQD;
	n = ppmu->get_alternatives(ev, flags, alt);

	return n > 0;
}

/*
 * Find an alternative event_id that goes on a normal PMC, if possible,
 * and return the event_id code, or 0 if there is no such alternative.
 * (Note: event_id code 0 is "don't count" on all machines.)
 */
static u64 normal_pmc_alternative(u64 ev, unsigned long flags)
{
	u64 alt[MAX_EVENT_ALTERNATIVES];
	int n;

	flags &= ~(PPMU_LIMITED_PMC_OK | PPMU_LIMITED_PMC_REQD);
	n = ppmu->get_alternatives(ev, flags, alt);
	if (!n)
		return 0;
	return alt[0];
}

/* Number of perf_events counting hardware events */
static atomic_t num_events;
/* Used to avoid races in calling reserve/release_pmc_hardware */
static DEFINE_MUTEX(pmc_reserve_mutex);

/*
 * Release the PMU if this is the last perf_event.
 */
static void hw_perf_event_destroy(struct perf_event *event)
{
	if (!atomic_add_unless(&num_events, -1, 1)) {
		mutex_lock(&pmc_reserve_mutex);
		if (atomic_dec_return(&num_events) == 0)
			release_pmc_hardware();
		mutex_unlock(&pmc_reserve_mutex);
	}
}

/*
 * Translate a generic cache event_id config to a raw event_id code.
 */
static int hw_perf_cache_event(u64 config, u64 *eventp)
{
	unsigned long type, op, result;
	int ev;

	if (!ppmu->cache_events)
		return -EINVAL;

	/* unpack config */
	type = config & 0xff;
	op = (config >> 8) & 0xff;
	result = (config >> 16) & 0xff;

	if (type >= PERF_COUNT_HW_CACHE_MAX ||
	    op >= PERF_COUNT_HW_CACHE_OP_MAX ||
	    result >= PERF_COUNT_HW_CACHE_RESULT_MAX)
		return -EINVAL;

	ev = (*ppmu->cache_events)[type][op][result];
	if (ev == 0)
		return -EOPNOTSUPP;
	if (ev == -1)
		return -EINVAL;
	*eventp = ev;
	return 0;
}

static int power_pmu_event_init(struct perf_event *event)
{
	u64 ev;
	unsigned long flags;
	struct perf_event *ctrs[MAX_HWEVENTS];
	u64 events[MAX_HWEVENTS];
	unsigned int cflags[MAX_HWEVENTS];
	int n;
	int err;
	struct cpu_hw_events *cpuhw;

	if (!ppmu)
		return -ENOENT;

	switch (event->attr.type) {
	case PERF_TYPE_HARDWARE:
		ev = event->attr.config;
		if (ev >= ppmu->n_generic || ppmu->generic_events[ev] == 0)
			return -EOPNOTSUPP;
		ev = ppmu->generic_events[ev];
		break;
	case PERF_TYPE_HW_CACHE:
		err = hw_perf_cache_event(event->attr.config, &ev);
		if (err)
			return err;
		break;
	case PERF_TYPE_RAW:
		ev = event->attr.config;
		break;
	default:
		return -ENOENT;
	}

	event->hw.config_base = ev;
	event->hw.idx = 0;

	/*
 * If we are not running on a hypervisor, force the
 * exclude_hv bit to 0 so that we don't care what
 * the user set it to.
 */
	if (!firmware_has_feature(FW_FEATURE_LPAR))
		event->attr.exclude_hv = 0;

	/*
 * If this is a per-task event, then we can use
 * PM_RUN_* events interchangeably with their non RUN_*
 * equivalents, e.g. PM_RUN_CYC instead of PM_CYC.
 * XXX we should check if the task is an idle task.
 */
	flags = 0;
	if (event->attach_state & PERF_ATTACH_TASK)
		flags |= PPMU_ONLY_COUNT_RUN;

	/*
 * If this machine has limited events, check whether this
 * event_id could go on a limited event.
 */
	if (ppmu->flags & PPMU_LIMITED_PMC5_6) {
		if (can_go_on_limited_pmc(event, ev, flags)) {
			flags |= PPMU_LIMITED_PMC_OK;
		} else if (ppmu->limited_pmc_event(ev)) {
			/*
 * The requested event_id is on a limited PMC,
 * but we can't use a limited PMC; see if any
 * alternative goes on a normal PMC.
 */
			ev = normal_pmc_alternative(ev, flags);
			if (!ev)
				return -EINVAL;
		}
	}

	/*
 * If this is in a group, check if it can go on with all the
 * other hardware events in the group. We assume the event
 * hasn't been linked into its leader's sibling list at this point.
 */
	n = 0;
	if (event->group_leader != event) {
		n = collect_events(event->group_leader, ppmu->n_counter - 1,
				   ctrs, events, cflags);
		if (n < 0)
			return -EINVAL;
	}
	events[n] = ev;
	ctrs[n] = event;
	cflags[n] = flags;
	if (check_excludes(ctrs, cflags, n, 1))
		return -EINVAL;

	cpuhw = &get_cpu_var(cpu_hw_events);
	err = power_check_constraints(cpuhw, events, cflags, n + 1);
	put_cpu_var(cpu_hw_events);
	if (err)
		return -EINVAL;

	event->hw.config = events[n];
	event->hw.event_base = cflags[n];
	event->hw.last_period = event->hw.sample_period;
	local64_set(&event->hw.period_left, event->hw.last_period);

	/*
 * See if we need to reserve the PMU.
 * If no events are currently in use, then we have to take a
 * mutex to ensure that we don't race with another task doing
 * reserve_pmc_hardware or release_pmc_hardware.
 */
	err = 0;
	if (!atomic_inc_not_zero(&num_events)) {
		mutex_lock(&pmc_reserve_mutex);
		if (atomic_read(&num_events) == 0 &&
		    reserve_pmc_hardware(perf_event_interrupt))
			err = -EBUSY;
		else
			atomic_inc(&num_events);
		mutex_unlock(&pmc_reserve_mutex);
	}
	event->destroy = hw_perf_event_destroy;

	return err;
}

struct pmu power_pmu = {
	.pmu_enable	= power_pmu_enable,
	.pmu_disable	= power_pmu_disable,
	.event_init	= power_pmu_event_init,
	.add		= power_pmu_add,
	.del		= power_pmu_del,
	.start		= power_pmu_start,
	.stop		= power_pmu_stop,
	.read		= power_pmu_read,
	.start_txn	= power_pmu_start_txn,
	.cancel_txn	= power_pmu_cancel_txn,
	.commit_txn	= power_pmu_commit_txn,
};

/*
 * A counter has overflowed; update its count and record
 * things if requested. Note that interrupts are hard-disabled
 * here so there is no possibility of being interrupted.
 */
static void record_and_restart(struct perf_event *event, unsigned long val,
			       struct pt_regs *regs, int nmi)
{
	u64 period = event->hw.sample_period;
	s64 prev, delta, left;
	int record = 0;

	if (event->hw.state & PERF_HES_STOPPED) {
		write_pmc(event->hw.idx, 0);
		return;
	}

	/* we don't have to worry about interrupts here */
	prev = local64_read(&event->hw.prev_count);
	delta = check_and_compute_delta(prev, val);
	local64_add(delta, &event->count);

	/*
 * See if the total period for this event has expired,
 * and update for the next period.
 */
	val = 0;
	left = local64_read(&event->hw.period_left) - delta;
	if (period) {
		if (left <= 0) {
			left += period;
			if (left <= 0)
				left = period;
			record = 1;
			event->hw.last_period = event->hw.sample_period;
		}
		if (left < 0x80000000LL)
			val = 0x80000000LL - left;
	}

	write_pmc(event->hw.idx, val);
	local64_set(&event->hw.prev_count, val);
	local64_set(&event->hw.period_left, left);
	perf_event_update_userpage(event);

	/*
 * Finally record data if requested.
 */
	if (record) {
		struct perf_sample_data data;

		perf_sample_data_init(&data, ~0ULL);
		data.period = event->hw.last_period;

		if (event->attr.sample_type & PERF_SAMPLE_ADDR)
			perf_get_data_addr(regs, &data.addr);

		if (perf_event_overflow(event, nmi, &data, regs))
			power_pmu_stop(event, 0);
	}
}

/*
 * Called from generic code to get the misc flags (i.e. processor mode)
 * for an event_id.
 */
unsigned long perf_misc_flags(struct pt_regs *regs)
{
	u32 flags = perf_get_misc_flags(regs);

	if (flags)
		return flags;
	return user_mode(regs) ? PERF_RECORD_MISC_USER :
		PERF_RECORD_MISC_KERNEL;
}

/*
 * Called from generic code to get the instruction pointer
 * for an event_id.
 */
unsigned long perf_instruction_pointer(struct pt_regs *regs)
{
	unsigned long ip;

	if (TRAP(regs) != 0xf00)
		return regs->nip;	/* not a PMU interrupt */

	ip = mfspr(SPRN_SIAR) + perf_ip_adjust(regs);
	return ip;
}

static bool pmc_overflow(unsigned long val)
{
	if ((int)val < 0)
		return true;

	/*
 * Events on POWER7 can roll back if a speculative event doesn't
 * eventually complete. Unfortunately in some rare cases they will
 * raise a performance monitor exception. We need to catch this to
 * ensure we reset the PMC. In all cases the PMC will be 256 or less
 * cycles from overflow.
 *
 * We only do this if the first pass fails to find any overflowing
 * PMCs because a user might set a period of less than 256 and we
 * don't want to mistakenly reset them.
 */
	if (__is_processor(PV_POWER7) && ((0x80000000 - val) <= 256))
		return true;

	return false;
}

/*
 * Performance monitor interrupt stuff
 */
static void perf_event_interrupt(struct pt_regs *regs)
{
	int i;
	struct cpu_hw_events *cpuhw = &__get_cpu_var(cpu_hw_events);
	struct perf_event *event;
	unsigned long val;
	int found = 0;
	int nmi;

	if (cpuhw->n_limited)
		freeze_limited_counters(cpuhw, mfspr(SPRN_PMC5),
					mfspr(SPRN_PMC6));

	perf_read_regs(regs);

	nmi = perf_intr_is_nmi(regs);
	if (nmi)
		nmi_enter();
	else
		irq_enter();

	for (i = 0; i < cpuhw->n_events; ++i) {
		event = cpuhw->event[i];
		if (!event->hw.idx || is_limited_pmc(event->hw.idx))
			continue;
		val = read_pmc(event->hw.idx);
		if ((int)val < 0) {
			/* event has overflowed */
			found = 1;
			record_and_restart(event, val, regs, nmi);
		}
	}

	/*
 * In case we didn't find and reset the event that caused
 * the interrupt, scan all events and reset any that are
 * negative, to avoid getting continual interrupts.
 * Any that we processed in the previous loop will not be negative.
 */
	if (!found) {
		for (i = 0; i < ppmu->n_counter; ++i) {
			if (is_limited_pmc(i + 1))
				continue;
			val = read_pmc(i + 1);
			if (pmc_overflow(val))
				write_pmc(i + 1, 0);
		}
	}

	/*
 * Reset MMCR0 to its normal value. This will set PMXE and
 * clear FC (freeze counters) and PMAO (perf mon alert occurred)
 * and thus allow interrupts to occur again.
 * XXX might want to use MSR.PM to keep the events frozen until
 * we get back out of this interrupt.
 */
	write_mmcr0(cpuhw, cpuhw->mmcr[0]);

	if (nmi)
		nmi_exit();
	else
		irq_exit();
}

static void power_pmu_setup(int cpu)
{
	struct cpu_hw_events *cpuhw = &per_cpu(cpu_hw_events, cpu);

	if (!ppmu)
		return;
	memset(cpuhw, 0, sizeof(*cpuhw));
	cpuhw->mmcr[0] = MMCR0_FC;
}

static int __cpuinit
power_pmu_notifier(struct notifier_block *self, unsigned long action, void *hcpu)
{
	unsigned int cpu = (long)hcpu;

	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_UP_PREPARE:
		power_pmu_setup(cpu);
		break;

	default:
		break;
	}

	return NOTIFY_OK;
}

int register_power_pmu(struct power_pmu *pmu)
{
	if (ppmu)
		return -EBUSY;		/* something's already registered */

	ppmu = pmu;
	pr_info("%s performance monitor hardware support registered\n",
		pmu->name);

#ifdef MSR_HV
	/*
 * Use FCHV to ignore kernel events if MSR.HV is set.
 */
	if (mfmsr() & MSR_HV)
		freeze_events_kernel = MMCR0_FCHV;
#endif /* CONFIG_PPC64 */

	perf_pmu_register(&power_pmu, "cpu", PERF_TYPE_RAW);
	perf_cpu_notifier(power_pmu_notifier);

	return 0;
}

/* Performance event support for sparc64.
 *
 * Copyright (C) 2009, 2010 David S. Miller <davem@davemloft.net>
 *
 * This code is based almost entirely upon the x86 perf event
 * code, which is:
 *
 * Copyright (C) 2008 Thomas Gleixner <tglx@linutronix.de>
 * Copyright (C) 2008-2009 Red Hat, Inc., Ingo Molnar
 * Copyright (C) 2009 Jaswinder Singh Rajput
 * Copyright (C) 2009 Advanced Micro Devices, Inc., Robert Richter
 * Copyright (C) 2008-2009 Red Hat, Inc., Peter Zijlstra <pzijlstr@redhat.com>
 */

#include <linux/perf_event.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/kernel.h>
#include <linux/kdebug.h>
#include <linux/mutex.h>

#include <asm/stacktrace.h>
#include <asm/cpudata.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>
#include <asm/nmi.h>
#include <asm/pcr.h>

#include "kernel.h"
#include "kstack.h"

/* Sparc64 chips have two performance counters, 32-bits each, with
 * overflow interrupts generated on transition from 0xffffffff to 0.
 * The counters are accessed in one go using a 64-bit register.
 *
 * Both counters are controlled using a single control register. The
 * only way to stop all sampling is to clear all of the context (user,
 * supervisor, hypervisor) sampling enable bits. But these bits apply
 * to both counters, thus the two counters can't be enabled/disabled
 * individually.
 *
 * The control register has two event fields, one for each of the two
 * counters. It's thus nearly impossible to have one counter going
 * while keeping the other one stopped. Therefore it is possible to
 * get overflow interrupts for counters not currently "in use" and
 * that condition must be checked in the overflow interrupt handler.
 *
 * So we use a hack, in that we program inactive counters with the
 * "sw_count0" and "sw_count1" events. These count how many times
 * the instruction "sethi %hi(0xfc000), %g0" is executed. It's an
 * unusual way to encode a NOP and therefore will not trigger in
 * normal code.
 */

#define MAX_HWEVENTS 2
#define MAX_PERIOD ((1UL << 32) - 1)

#define PIC_UPPER_INDEX 0
#define PIC_LOWER_INDEX 1
#define PIC_NO_INDEX -1

struct cpu_hw_events {
	/* Number of events currently scheduled onto this cpu.
 * This tells how many entries in the arrays below
 * are valid.
 */
	int			n_events;

	/* Number of new events added since the last hw_perf_disable().
 * This works because the perf event layer always adds new
 * events inside of a perf_{disable,enable}() sequence.
 */
	int			n_added;

	/* Array of events current scheduled on this cpu. */
	struct perf_event	*event[MAX_HWEVENTS];

	/* Array of encoded longs, specifying the %pcr register
 * encoding and the mask of PIC counters this even can
 * be scheduled on. See perf_event_encode() et al.
 */
	unsigned long		events[MAX_HWEVENTS];

	/* The current counter index assigned to an event. When the
 * event hasn't been programmed into the cpu yet, this will
 * hold PIC_NO_INDEX. The event->hw.idx value tells us where
 * we ought to schedule the event.
 */
	int			current_idx[MAX_HWEVENTS];

	/* Software copy of %pcr register on this cpu. */
	u64			pcr;

	/* Enabled/disable state. */
	int			enabled;

	unsigned int		group_flag;
};
DEFINE_PER_CPU(struct cpu_hw_events, cpu_hw_events) = { .enabled = 1, };

/* An event map describes the characteristics of a performance
 * counter event. In particular it gives the encoding as well as
 * a mask telling which counters the event can be measured on.
 */
struct perf_event_map {
	u16	encoding;
	u8	pic_mask;
#define PIC_NONE 0x00
#define PIC_UPPER 0x01
#define PIC_LOWER 0x02
};

/* Encode a perf_event_map entry into a long. */
static unsigned long perf_event_encode(const struct perf_event_map *pmap)
{
	return ((unsigned long) pmap->encoding << 16) | pmap->pic_mask;
}

static u8 perf_event_get_msk(unsigned long val)
{
	return val & 0xff;
}

static u64 perf_event_get_enc(unsigned long val)
{
	return val >> 16;
}

#define C(x) PERF_COUNT_HW_CACHE_##x

#define CACHE_OP_UNSUPPORTED 0xfffe
#define CACHE_OP_NONSENSE 0xffff

typedef struct perf_event_map cache_map_t
				[PERF_COUNT_HW_CACHE_MAX]
				[PERF_COUNT_HW_CACHE_OP_MAX]
				[PERF_COUNT_HW_CACHE_RESULT_MAX];

struct sparc_pmu {
	const struct perf_event_map	*(*event_map)(int);
	const cache_map_t		*cache_map;
	int				max_events;
	int				upper_shift;
	int				lower_shift;
	int				event_mask;
	int				hv_bit;
	int				irq_bit;
	int				upper_nop;
	int				lower_nop;
};

static const struct perf_event_map ultra3_perfmon_event_map[] = {
	[PERF_COUNT_HW_CPU_CYCLES] = { 0x0000, PIC_UPPER | PIC_LOWER },
	[PERF_COUNT_HW_INSTRUCTIONS] = { 0x0001, PIC_UPPER | PIC_LOWER },
	[PERF_COUNT_HW_CACHE_REFERENCES] = { 0x0009, PIC_LOWER },
	[PERF_COUNT_HW_CACHE_MISSES] = { 0x0009, PIC_UPPER },
};

static const struct perf_event_map *ultra3_event_map(int event_id)
{
	return &ultra3_perfmon_event_map[event_id];
}

static const cache_map_t ultra3_cache_map = {
[C(L1D)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { 0x09, PIC_LOWER, },
		[C(RESULT_MISS)] = { 0x09, PIC_UPPER, },
	},
	[C(OP_WRITE)] = {
		[C(RESULT_ACCESS)] = { 0x0a, PIC_LOWER },
		[C(RESULT_MISS)] = { 0x0a, PIC_UPPER },
	},
	[C(OP_PREFETCH)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(L1I)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { 0x09, PIC_LOWER, },
		[C(RESULT_MISS)] = { 0x09, PIC_UPPER, },
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_NONSENSE },
		[ C(RESULT_MISS) ] = { CACHE_OP_NONSENSE },
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(LL)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { 0x0c, PIC_LOWER, },
		[C(RESULT_MISS)] = { 0x0c, PIC_UPPER, },
	},
	[C(OP_WRITE)] = {
		[C(RESULT_ACCESS)] = { 0x0c, PIC_LOWER },
		[C(RESULT_MISS)] = { 0x0c, PIC_UPPER },
	},
	[C(OP_PREFETCH)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(DTLB)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { 0x12, PIC_UPPER, },
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(ITLB)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { 0x11, PIC_UPPER, },
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(BPU)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { CACHE_OP_UNSUPPORTED },
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
},
};

static const struct sparc_pmu ultra3_pmu = {
	.event_map	= ultra3_event_map,
	.cache_map	= &ultra3_cache_map,
	.max_events	= ARRAY_SIZE(ultra3_perfmon_event_map),
	.upper_shift	= 11,
	.lower_shift	= 4,
	.event_mask	= 0x3f,
	.upper_nop	= 0x1c,
	.lower_nop	= 0x14,
};

/* Niagara1 is very limited. The upper PIC is hard-locked to count
 * only instructions, so it is free running which creates all kinds of
 * problems. Some hardware designs make one wonder if the creator
 * even looked at how this stuff gets used by software.
 */
static const struct perf_event_map niagara1_perfmon_event_map[] = {
	[PERF_COUNT_HW_CPU_CYCLES] = { 0x00, PIC_UPPER },
	[PERF_COUNT_HW_INSTRUCTIONS] = { 0x00, PIC_UPPER },
	[PERF_COUNT_HW_CACHE_REFERENCES] = { 0, PIC_NONE },
	[PERF_COUNT_HW_CACHE_MISSES] = { 0x03, PIC_LOWER },
};

static const struct perf_event_map *niagara1_event_map(int event_id)
{
	return &niagara1_perfmon_event_map[event_id];
}

static const cache_map_t niagara1_cache_map = {
[C(L1D)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { 0x03, PIC_LOWER, },
	},
	[C(OP_WRITE)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { 0x03, PIC_LOWER, },
	},
	[C(OP_PREFETCH)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(L1I)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { 0x00, PIC_UPPER },
		[C(RESULT_MISS)] = { 0x02, PIC_LOWER, },
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_NONSENSE },
		[ C(RESULT_MISS) ] = { CACHE_OP_NONSENSE },
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(LL)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { 0x07, PIC_LOWER, },
	},
	[C(OP_WRITE)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { 0x07, PIC_LOWER, },
	},
	[C(OP_PREFETCH)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(DTLB)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { 0x05, PIC_LOWER, },
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(ITLB)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { 0x04, PIC_LOWER, },
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(BPU)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { CACHE_OP_UNSUPPORTED },
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
},
};

static const struct sparc_pmu niagara1_pmu = {
	.event_map	= niagara1_event_map,
	.cache_map	= &niagara1_cache_map,
	.max_events	= ARRAY_SIZE(niagara1_perfmon_event_map),
	.upper_shift	= 0,
	.lower_shift	= 4,
	.event_mask	= 0x7,
	.upper_nop	= 0x0,
	.lower_nop	= 0x0,
};

static const struct perf_event_map niagara2_perfmon_event_map[] = {
	[PERF_COUNT_HW_CPU_CYCLES] = { 0x02ff, PIC_UPPER | PIC_LOWER },
	[PERF_COUNT_HW_INSTRUCTIONS] = { 0x02ff, PIC_UPPER | PIC_LOWER },
	[PERF_COUNT_HW_CACHE_REFERENCES] = { 0x0208, PIC_UPPER | PIC_LOWER },
	[PERF_COUNT_HW_CACHE_MISSES] = { 0x0302, PIC_UPPER | PIC_LOWER },
	[PERF_COUNT_HW_BRANCH_INSTRUCTIONS] = { 0x0201, PIC_UPPER | PIC_LOWER },
	[PERF_COUNT_HW_BRANCH_MISSES] = { 0x0202, PIC_UPPER | PIC_LOWER },
};

static const struct perf_event_map *niagara2_event_map(int event_id)
{
	return &niagara2_perfmon_event_map[event_id];
}

static const cache_map_t niagara2_cache_map = {
[C(L1D)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { 0x0208, PIC_UPPER | PIC_LOWER, },
		[C(RESULT_MISS)] = { 0x0302, PIC_UPPER | PIC_LOWER, },
	},
	[C(OP_WRITE)] = {
		[C(RESULT_ACCESS)] = { 0x0210, PIC_UPPER | PIC_LOWER, },
		[C(RESULT_MISS)] = { 0x0302, PIC_UPPER | PIC_LOWER, },
	},
	[C(OP_PREFETCH)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(L1I)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { 0x02ff, PIC_UPPER | PIC_LOWER, },
		[C(RESULT_MISS)] = { 0x0301, PIC_UPPER | PIC_LOWER, },
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_NONSENSE },
		[ C(RESULT_MISS) ] = { CACHE_OP_NONSENSE },
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(LL)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { 0x0208, PIC_UPPER | PIC_LOWER, },
		[C(RESULT_MISS)] = { 0x0330, PIC_UPPER | PIC_LOWER, },
	},
	[C(OP_WRITE)] = {
		[C(RESULT_ACCESS)] = { 0x0210, PIC_UPPER | PIC_LOWER, },
		[C(RESULT_MISS)] = { 0x0320, PIC_UPPER | PIC_LOWER, },
	},
	[C(OP_PREFETCH)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(DTLB)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { 0x0b08, PIC_UPPER | PIC_LOWER, },
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(ITLB)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { 0xb04, PIC_UPPER | PIC_LOWER, },
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(BPU)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { CACHE_OP_UNSUPPORTED },
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS) ] = { CACHE_OP_UNSUPPORTED },
	},
},
};

static const struct sparc_pmu niagara2_pmu = {
	.event_map	= niagara2_event_map,
	.cache_map	= &niagara2_cache_map,
	.max_events	= ARRAY_SIZE(niagara2_perfmon_event_map),
	.upper_shift	= 19,
	.lower_shift	= 6,
	.event_mask	= 0xfff,
	.hv_bit		= 0x8,
	.irq_bit	= 0x30,
	.upper_nop	= 0x220,
	.lower_nop	= 0x220,
};

static const struct sparc_pmu *sparc_pmu __read_mostly;

static u64 event_encoding(u64 event_id, int idx)
{
	if (idx == PIC_UPPER_INDEX)
		event_id <<= sparc_pmu->upper_shift;
	else
		event_id <<= sparc_pmu->lower_shift;
	return event_id;
}

static u64 mask_for_index(int idx)
{
	return event_encoding(sparc_pmu->event_mask, idx);
}

static u64 nop_for_index(int idx)
{
	return event_encoding(idx == PIC_UPPER_INDEX ?
			      sparc_pmu->upper_nop :
			      sparc_pmu->lower_nop, idx);
}

static inline void sparc_pmu_enable_event(struct cpu_hw_events *cpuc, struct hw_perf_event *hwc, int idx)
{
	u64 val, mask = mask_for_index(idx);

	val = cpuc->pcr;
	val &= ~mask;
	val |= hwc->config;
	cpuc->pcr = val;

	pcr_ops->write(cpuc->pcr);
}

static inline void sparc_pmu_disable_event(struct cpu_hw_events *cpuc, struct hw_perf_event *hwc, int idx)
{
	u64 mask = mask_for_index(idx);
	u64 nop = nop_for_index(idx);
	u64 val;

	val = cpuc->pcr;
	val &= ~mask;
	val |= nop;
	cpuc->pcr = val;

	pcr_ops->write(cpuc->pcr);
}

static u32 read_pmc(int idx)
{
	u64 val;

	read_pic(val);
	if (idx == PIC_UPPER_INDEX)
		val >>= 32;

	return val & 0xffffffff;
}

static void write_pmc(int idx, u64 val)
{
	u64 shift, mask, pic;

	shift = 0;
	if (idx == PIC_UPPER_INDEX)
		shift = 32;

	mask = ((u64) 0xffffffff) << shift;
	val <<= shift;

	read_pic(pic);
	pic &= ~mask;
	pic |= val;
	write_pic(pic);
}

static u64 sparc_perf_event_update(struct perf_event *event,
				   struct hw_perf_event *hwc, int idx)
{
	int shift = 64 - 32;
	u64 prev_raw_count, new_raw_count;
	s64 delta;

again:
	prev_raw_count = local64_read(&hwc->prev_count);
	new_raw_count = read_pmc(idx);

	if (local64_cmpxchg(&hwc->prev_count, prev_raw_count,
			     new_raw_count) != prev_raw_count)
		goto again;

	delta = (new_raw_count << shift) - (prev_raw_count << shift);
	delta >>= shift;

	local64_add(delta, &event->count);
	local64_sub(delta, &hwc->period_left);

	return new_raw_count;
}

static int sparc_perf_event_set_period(struct perf_event *event,
				       struct hw_perf_event *hwc, int idx)
{
	s64 left = local64_read(&hwc->period_left);
	s64 period = hwc->sample_period;
	int ret = 0;

	if (unlikely(left <= -period)) {
		left = period;
		local64_set(&hwc->period_left, left);
		hwc->last_period = period;
		ret = 1;
	}

	if (unlikely(left <= 0)) {
		left += period;
		local64_set(&hwc->period_left, left);
		hwc->last_period = period;
		ret = 1;
	}
	if (left > MAX_PERIOD)
		left = MAX_PERIOD;

	local64_set(&hwc->prev_count, (u64)-left);

	write_pmc(idx, (u64)(-left) & 0xffffffff);

	perf_event_update_userpage(event);

	return ret;
}

/* If performance event entries have been added, move existing
 * events around (if necessary) and then assign new entries to
 * counters.
 */
static u64 maybe_change_configuration(struct cpu_hw_events *cpuc, u64 pcr)
{
	int i;

	if (!cpuc->n_added)
		goto out;

	/* Read in the counters which are moving. */
	for (i = 0; i < cpuc->n_events; i++) {
		struct perf_event *cp = cpuc->event[i];

		if (cpuc->current_idx[i] != PIC_NO_INDEX &&
		    cpuc->current_idx[i] != cp->hw.idx) {
			sparc_perf_event_update(cp, &cp->hw,
						cpuc->current_idx[i]);
			cpuc->current_idx[i] = PIC_NO_INDEX;
		}
	}

	/* Assign to counters all unassigned events. */
	for (i = 0; i < cpuc->n_events; i++) {
		struct perf_event *cp = cpuc->event[i];
		struct hw_perf_event *hwc = &cp->hw;
		int idx = hwc->idx;
		u64 enc;

		if (cpuc->current_idx[i] != PIC_NO_INDEX)
			continue;

		sparc_perf_event_set_period(cp, hwc, idx);
		cpuc->current_idx[i] = idx;

		enc = perf_event_get_enc(cpuc->events[i]);
		pcr &= ~mask_for_index(idx);
		if (hwc->state & PERF_HES_STOPPED)
			pcr |= nop_for_index(idx);
		else
			pcr |= event_encoding(enc, idx);
	}
out:
	return pcr;
}

static void sparc_pmu_enable(struct pmu *pmu)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	u64 pcr;

	if (cpuc->enabled)
		return;

	cpuc->enabled = 1;
	barrier();

	pcr = cpuc->pcr;
	if (!cpuc->n_events) {
		pcr = 0;
	} else {
		pcr = maybe_change_configuration(cpuc, pcr);

		/* We require that all of the events have the same
 * configuration, so just fetch the settings from the
 * first entry.
 */
		cpuc->pcr = pcr | cpuc->event[0]->hw.config_base;
	}

	pcr_ops->write(cpuc->pcr);
}

static void sparc_pmu_disable(struct pmu *pmu)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	u64 val;

	if (!cpuc->enabled)
		return;

	cpuc->enabled = 0;
	cpuc->n_added = 0;

	val = cpuc->pcr;
	val &= ~(PCR_UTRACE | PCR_STRACE |
		 sparc_pmu->hv_bit | sparc_pmu->irq_bit);
	cpuc->pcr = val;

	pcr_ops->write(cpuc->pcr);
}

static int active_event_index(struct cpu_hw_events *cpuc,
			      struct perf_event *event)
{
	int i;

	for (i = 0; i < cpuc->n_events; i++) {
		if (cpuc->event[i] == event)
			break;
	}
	BUG_ON(i == cpuc->n_events);
	return cpuc->current_idx[i];
}

static void sparc_pmu_start(struct perf_event *event, int flags)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	int idx = active_event_index(cpuc, event);

	if (flags & PERF_EF_RELOAD) {
		WARN_ON_ONCE(!(event->hw.state & PERF_HES_UPTODATE));
		sparc_perf_event_set_period(event, &event->hw, idx);
	}

	event->hw.state = 0;

	sparc_pmu_enable_event(cpuc, &event->hw, idx);
}

static void sparc_pmu_stop(struct perf_event *event, int flags)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	int idx = active_event_index(cpuc, event);

	if (!(event->hw.state & PERF_HES_STOPPED)) {
		sparc_pmu_disable_event(cpuc, &event->hw, idx);
		event->hw.state |= PERF_HES_STOPPED;
	}

	if (!(event->hw.state & PERF_HES_UPTODATE) && (flags & PERF_EF_UPDATE)) {
		sparc_perf_event_update(event, &event->hw, idx);
		event->hw.state |= PERF_HES_UPTODATE;
	}
}

static void sparc_pmu_del(struct perf_event *event, int _flags)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	unsigned long flags;
	int i;

	local_irq_save(flags);
	perf_pmu_disable(event->pmu);

	for (i = 0; i < cpuc->n_events; i++) {
		if (event == cpuc->event[i]) {
			/* Absorb the final count and turn off the
 * event.
 */
			sparc_pmu_stop(event, PERF_EF_UPDATE);

			/* Shift remaining entries down into
 * the existing slot.
 */
			while (++i < cpuc->n_events) {
				cpuc->event[i - 1] = cpuc->event[i];
				cpuc->events[i - 1] = cpuc->events[i];
				cpuc->current_idx[i - 1] =
					cpuc->current_idx[i];
			}

			perf_event_update_userpage(event);

			cpuc->n_events--;
			break;
		}
	}

	perf_pmu_enable(event->pmu);
	local_irq_restore(flags);
}

static void sparc_pmu_read(struct perf_event *event)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	int idx = active_event_index(cpuc, event);
	struct hw_perf_event *hwc = &event->hw;

	sparc_perf_event_update(event, hwc, idx);
}

static atomic_t active_events = ATOMIC_INIT(0);
static DEFINE_MUTEX(pmc_grab_mutex);

static void perf_stop_nmi_watchdog(void *unused)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);

	stop_nmi_watchdog(NULL);
	cpuc->pcr = pcr_ops->read();
}

void perf_event_grab_pmc(void)
{
	if (atomic_inc_not_zero(&active_events))
		return;

	mutex_lock(&pmc_grab_mutex);
	if (atomic_read(&active_events) == 0) {
		if (atomic_read(&nmi_active) > 0) {
			on_each_cpu(perf_stop_nmi_watchdog, NULL, 1);
			BUG_ON(atomic_read(&nmi_active) != 0);
		}
		atomic_inc(&active_events);
	}
	mutex_unlock(&pmc_grab_mutex);
}

void perf_event_release_pmc(void)
{
	if (atomic_dec_and_mutex_lock(&active_events, &pmc_grab_mutex)) {
		if (atomic_read(&nmi_active) == 0)
			on_each_cpu(start_nmi_watchdog, NULL, 1);
		mutex_unlock(&pmc_grab_mutex);
	}
}

static const struct perf_event_map *sparc_map_cache_event(u64 config)
{
	unsigned int cache_type, cache_op, cache_result;
	const struct perf_event_map *pmap;

	if (!sparc_pmu->cache_map)
		return ERR_PTR(-ENOENT);

	cache_type = (config >>  0) & 0xff;
	if (cache_type >= PERF_COUNT_HW_CACHE_MAX)
		return ERR_PTR(-EINVAL);

	cache_op = (config >>  8) & 0xff;
	if (cache_op >= PERF_COUNT_HW_CACHE_OP_MAX)
		return ERR_PTR(-EINVAL);

	cache_result = (config >> 16) & 0xff;
	if (cache_result >= PERF_COUNT_HW_CACHE_RESULT_MAX)
		return ERR_PTR(-EINVAL);

	pmap = &((*sparc_pmu->cache_map)[cache_type][cache_op][cache_result]);

	if (pmap->encoding == CACHE_OP_UNSUPPORTED)
		return ERR_PTR(-ENOENT);

	if (pmap->encoding == CACHE_OP_NONSENSE)
		return ERR_PTR(-EINVAL);

	return pmap;
}

static void hw_perf_event_destroy(struct perf_event *event)
{
	perf_event_release_pmc();
}

/* Make sure all events can be scheduled into the hardware at
 * the same time. This is simplified by the fact that we only
 * need to support 2 simultaneous HW events.
 *
 * As a side effect, the evts[]->hw.idx values will be assigned
 * on success. These are pending indexes. When the events are
 * actually programmed into the chip, these values will propagate
 * to the per-cpu cpuc->current_idx[] slots, see the code in
 * maybe_change_configuration() for details.
 */
static int sparc_check_constraints(struct perf_event **evts,
				   unsigned long *events, int n_ev)
{
	u8 msk0 = 0, msk1 = 0;
	int idx0 = 0;

	/* This case is possible when we are invoked from
 * hw_perf_group_sched_in().
 */
	if (!n_ev)
		return 0;

	if (n_ev > MAX_HWEVENTS)
		return -1;

	msk0 = perf_event_get_msk(events[0]);
	if (n_ev == 1) {
		if (msk0 & PIC_LOWER)
			idx0 = 1;
		goto success;
	}
	BUG_ON(n_ev != 2);
	msk1 = perf_event_get_msk(events[1]);

	/* If both events can go on any counter, OK. */
	if (msk0 == (PIC_UPPER | PIC_LOWER) &&
	    msk1 == (PIC_UPPER | PIC_LOWER))
		goto success;

	/* If one event is limited to a specific counter,
 * and the other can go on both, OK.
 */
	if ((msk0 == PIC_UPPER || msk0 == PIC_LOWER) &&
	    msk1 == (PIC_UPPER | PIC_LOWER)) {
		if (msk0 & PIC_LOWER)
			idx0 = 1;
		goto success;
	}

	if ((msk1 == PIC_UPPER || msk1 == PIC_LOWER) &&
	    msk0 == (PIC_UPPER | PIC_LOWER)) {
		if (msk1 & PIC_UPPER)
			idx0 = 1;
		goto success;
	}

	/* If the events are fixed to different counters, OK. */
	if ((msk0 == PIC_UPPER && msk1 == PIC_LOWER) ||
	    (msk0 == PIC_LOWER && msk1 == PIC_UPPER)) {
		if (msk0 & PIC_LOWER)
			idx0 = 1;
		goto success;
	}

	/* Otherwise, there is a conflict. */
	return -1;

success:
	evts[0]->hw.idx = idx0;
	if (n_ev == 2)
		evts[1]->hw.idx = idx0 ^ 1;
	return 0;
}

static int check_excludes(struct perf_event **evts, int n_prev, int n_new)
{
	int eu = 0, ek = 0, eh = 0;
	struct perf_event *event;
	int i, n, first;

	n = n_prev + n_new;
	if (n <= 1)
		return 0;

	first = 1;
	for (i = 0; i < n; i++) {
		event = evts[i];
		if (first) {
			eu = event->attr.exclude_user;
			ek = event->attr.exclude_kernel;
			eh = event->attr.exclude_hv;
			first = 0;
		} else if (event->attr.exclude_user != eu ||
			   event->attr.exclude_kernel != ek ||
			   event->attr.exclude_hv != eh) {
			return -EAGAIN;
		}
	}

	return 0;
}

static int collect_events(struct perf_event *group, int max_count,
			  struct perf_event *evts[], unsigned long *events,
			  int *current_idx)
{
	struct perf_event *event;
	int n = 0;

	if (!is_software_event(group)) {
		if (n >= max_count)
			return -1;
		evts[n] = group;
		events[n] = group->hw.event_base;
		current_idx[n++] = PIC_NO_INDEX;
	}
	list_for_each_entry(event, &group->sibling_list, group_entry) {
		if (!is_software_event(event) &&
		    event->state != PERF_EVENT_STATE_OFF) {
			if (n >= max_count)
				return -1;
			evts[n] = event;
			events[n] = event->hw.event_base;
			current_idx[n++] = PIC_NO_INDEX;
		}
	}
	return n;
}

static int sparc_pmu_add(struct perf_event *event, int ef_flags)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	int n0, ret = -EAGAIN;
	unsigned long flags;

	local_irq_save(flags);
	perf_pmu_disable(event->pmu);

	n0 = cpuc->n_events;
	if (n0 >= MAX_HWEVENTS)
		goto out;

	cpuc->event[n0] = event;
	cpuc->events[n0] = event->hw.event_base;
	cpuc->current_idx[n0] = PIC_NO_INDEX;

	event->hw.state = PERF_HES_UPTODATE;
	if (!(ef_flags & PERF_EF_START))
		event->hw.state |= PERF_HES_STOPPED;

	/*
 * If group events scheduling transaction was started,
 * skip the schedulability test here, it will be performed
 * at commit time(->commit_txn) as a whole
 */
	if (cpuc->group_flag & PERF_EVENT_TXN)
		goto nocheck;

	if (check_excludes(cpuc->event, n0, 1))
		goto out;
	if (sparc_check_constraints(cpuc->event, cpuc->events, n0 + 1))
		goto out;

nocheck:
	cpuc->n_events++;
	cpuc->n_added++;

	ret = 0;
out:
	perf_pmu_enable(event->pmu);
	local_irq_restore(flags);
	return ret;
}

static int sparc_pmu_event_init(struct perf_event *event)
{
	struct perf_event_attr *attr = &event->attr;
	struct perf_event *evts[MAX_HWEVENTS];
	struct hw_perf_event *hwc = &event->hw;
	unsigned long events[MAX_HWEVENTS];
	int current_idx_dmy[MAX_HWEVENTS];
	const struct perf_event_map *pmap;
	int n;

	if (atomic_read(&nmi_active) < 0)
		return -ENODEV;

	switch (attr->type) {
	case PERF_TYPE_HARDWARE:
		if (attr->config >= sparc_pmu->max_events)
			return -EINVAL;
		pmap = sparc_pmu->event_map(attr->config);
		break;

	case PERF_TYPE_HW_CACHE:
		pmap = sparc_map_cache_event(attr->config);
		if (IS_ERR(pmap))
			return PTR_ERR(pmap);
		break;

	case PERF_TYPE_RAW:
		pmap = NULL;
		break;

	default:
		return -ENOENT;

	}

	if (pmap) {
		hwc->event_base = perf_event_encode(pmap);
	} else {
		/*
 * User gives us "(encoding << 16) | pic_mask" for
 * PERF_TYPE_RAW events.
 */
		hwc->event_base = attr->config;
	}

	/* We save the enable bits in the config_base. */
	hwc->config_base = sparc_pmu->irq_bit;
	if (!attr->exclude_user)
		hwc->config_base |= PCR_UTRACE;
	if (!attr->exclude_kernel)
		hwc->config_base |= PCR_STRACE;
	if (!attr->exclude_hv)
		hwc->config_base |= sparc_pmu->hv_bit;

	n = 0;
	if (event->group_leader != event) {
		n = collect_events(event->group_leader,
				   MAX_HWEVENTS - 1,
				   evts, events, current_idx_dmy);
		if (n < 0)
			return -EINVAL;
	}
	events[n] = hwc->event_base;
	evts[n] = event;

	if (check_excludes(evts, n, 1))
		return -EINVAL;

	if (sparc_check_constraints(evts, events, n + 1))
		return -EINVAL;

	hwc->idx = PIC_NO_INDEX;

	/* Try to do all error checking before this point, as unwinding
 * state after grabbing the PMC is difficult.
 */
	perf_event_grab_pmc();
	event->destroy = hw_perf_event_destroy;

	if (!hwc->sample_period) {
		hwc->sample_period = MAX_PERIOD;
		hwc->last_period = hwc->sample_period;
		local64_set(&hwc->period_left, hwc->sample_period);
	}

	return 0;
}

/*
 * Start group events scheduling transaction
 * Set the flag to make pmu::enable() not perform the
 * schedulability test, it will be performed at commit time
 */
static void sparc_pmu_start_txn(struct pmu *pmu)
{
	struct cpu_hw_events *cpuhw = &__get_cpu_var(cpu_hw_events);

	perf_pmu_disable(pmu);
	cpuhw->group_flag |= PERF_EVENT_TXN;
}

/*
 * Stop group events scheduling transaction
 * Clear the flag and pmu::enable() will perform the
 * schedulability test.
 */
static void sparc_pmu_cancel_txn(struct pmu *pmu)
{
	struct cpu_hw_events *cpuhw = &__get_cpu_var(cpu_hw_events);

	cpuhw->group_flag &= ~PERF_EVENT_TXN;
	perf_pmu_enable(pmu);
}

/*
 * Commit group events scheduling transaction
 * Perform the group schedulability test as a whole
 * Return 0 if success
 */
static int sparc_pmu_commit_txn(struct pmu *pmu)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	int n;

	if (!sparc_pmu)
		return -EINVAL;

	cpuc = &__get_cpu_var(cpu_hw_events);
	n = cpuc->n_events;
	if (check_excludes(cpuc->event, 0, n))
		return -EINVAL;
	if (sparc_check_constraints(cpuc->event, cpuc->events, n))
		return -EAGAIN;

	cpuc->group_flag &= ~PERF_EVENT_TXN;
	perf_pmu_enable(pmu);
	return 0;
}

static struct pmu pmu = {
	.pmu_enable	= sparc_pmu_enable,
	.pmu_disable	= sparc_pmu_disable,
	.event_init	= sparc_pmu_event_init,
	.add		= sparc_pmu_add,
	.del		= sparc_pmu_del,
	.start		= sparc_pmu_start,
	.stop		= sparc_pmu_stop,
	.read		= sparc_pmu_read,
	.start_txn	= sparc_pmu_start_txn,
	.cancel_txn	= sparc_pmu_cancel_txn,
	.commit_txn	= sparc_pmu_commit_txn,
};

void perf_event_print_debug(void)
{
	unsigned long flags;
	u64 pcr, pic;
	int cpu;

	if (!sparc_pmu)
		return;

	local_irq_save(flags);

	cpu = smp_processor_id();

	pcr = pcr_ops->read();
	read_pic(pic);

	pr_info("\n");
	pr_info("CPU#%d: PCR[%016llx] PIC[%016llx]\n",
		cpu, pcr, pic);

	local_irq_restore(flags);
}

static int __kprobes perf_event_nmi_handler(struct notifier_block *self,
					    unsigned long cmd, void *__args)
{
	struct die_args *args = __args;
	struct perf_sample_data data;
	struct cpu_hw_events *cpuc;
	struct pt_regs *regs;
	int i;

	if (!atomic_read(&active_events))
		return NOTIFY_DONE;

	switch (cmd) {
	case DIE_NMI:
		break;

	default:
		return NOTIFY_DONE;
	}

	regs = args->regs;

	perf_sample_data_init(&data, 0);

	cpuc = &__get_cpu_var(cpu_hw_events);

	/* If the PMU has the TOE IRQ enable bits, we need to do a
 * dummy write to the %pcr to clear the overflow bits and thus
 * the interrupt.
 *
 * Do this before we peek at the counters to determine
 * overflow so we don't lose any events.
 */
	if (sparc_pmu->irq_bit)
		pcr_ops->write(cpuc->pcr);

	for (i = 0; i < cpuc->n_events; i++) {
		struct perf_event *event = cpuc->event[i];
		int idx = cpuc->current_idx[i];
		struct hw_perf_event *hwc;
		u64 val;

		hwc = &event->hw;
		val = sparc_perf_event_update(event, hwc, idx);
		if (val & (1ULL << 31))
			continue;

		data.period = event->hw.last_period;
		if (!sparc_perf_event_set_period(event, hwc, idx))
			continue;

		if (perf_event_overflow(event, 1, &data, regs))
			sparc_pmu_stop(event, 0);
	}

	return NOTIFY_STOP;
}

static __read_mostly struct notifier_block perf_event_nmi_notifier = {
	.notifier_call		= perf_event_nmi_handler,
};

static bool __init supported_pmu(void)
{
	if (!strcmp(sparc_pmu_type, "ultra3") ||
	    !strcmp(sparc_pmu_type, "ultra3+") ||
	    !strcmp(sparc_pmu_type, "ultra3i") ||
	    !strcmp(sparc_pmu_type, "ultra4+")) {
		sparc_pmu = &ultra3_pmu;
		return true;
	}
	if (!strcmp(sparc_pmu_type, "niagara")) {
		sparc_pmu = &niagara1_pmu;
		return true;
	}
	if (!strcmp(sparc_pmu_type, "niagara2")) {
		sparc_pmu = &niagara2_pmu;
		return true;
	}
	return false;
}

int __init init_hw_perf_events(void)
{
	pr_info("Performance events: ");

	if (!supported_pmu()) {
		pr_cont("No support for PMU type '%s'\n", sparc_pmu_type);
		return 0;
	}

	pr_cont("Supported PMU type is '%s'\n", sparc_pmu_type);

	perf_pmu_register(&pmu, "cpu", PERF_TYPE_RAW);
	register_die_notifier(&perf_event_nmi_notifier);

	return 0;
}
early_initcall(init_hw_perf_events);

void perf_callchain_kernel(struct perf_callchain_entry *entry,
			   struct pt_regs *regs)
{
	unsigned long ksp, fp;
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	int graph = 0;
#endif

	stack_trace_flush();

	perf_callchain_store(entry, regs->tpc);

	ksp = regs->u_regs[UREG_I6];
	fp = ksp + STACK_BIAS;
	do {
		struct sparc_stackf *sf;
		struct pt_regs *regs;
		unsigned long pc;

		if (!kstack_valid(current_thread_info(), fp))
			break;

		sf = (struct sparc_stackf *) fp;
		regs = (struct pt_regs *) (sf + 1);

		if (kstack_is_trap_frame(current_thread_info(), regs)) {
			if (user_mode(regs))
				break;
			pc = regs->tpc;
			fp = regs->u_regs[UREG_I6] + STACK_BIAS;
		} else {
			pc = sf->callers_pc;
			fp = (unsigned long)sf->fp + STACK_BIAS;
		}
		perf_callchain_store(entry, pc);
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
		if ((pc + 8UL) == (unsigned long) &return_to_handler) {
			int index = current->curr_ret_stack;
			if (current->ret_stack && index >= graph) {
				pc = current->ret_stack[index - graph].ret;
				perf_callchain_store(entry, pc);
				graph++;
			}
		}
#endif
	} while (entry->nr < PERF_MAX_STACK_DEPTH);
}

static void perf_callchain_user_64(struct perf_callchain_entry *entry,
				   struct pt_regs *regs)
{
	unsigned long ufp;

	perf_callchain_store(entry, regs->tpc);

	ufp = regs->u_regs[UREG_I6] + STACK_BIAS;
	do {
		struct sparc_stackf *usf, sf;
		unsigned long pc;

		usf = (struct sparc_stackf *) ufp;
		if (__copy_from_user_inatomic(&sf, usf, sizeof(sf)))
			break;

		pc = sf.callers_pc;
		ufp = (unsigned long)sf.fp + STACK_BIAS;
		perf_callchain_store(entry, pc);
	} while (entry->nr < PERF_MAX_STACK_DEPTH);
}

static void perf_callchain_user_32(struct perf_callchain_entry *entry,
				   struct pt_regs *regs)
{
	unsigned long ufp;

	perf_callchain_store(entry, regs->tpc);

	ufp = regs->u_regs[UREG_I6] & 0xffffffffUL;
	do {
		struct sparc_stackf32 *usf, sf;
		unsigned long pc;

		usf = (struct sparc_stackf32 *) ufp;
		if (__copy_from_user_inatomic(&sf, usf, sizeof(sf)))
			break;

		pc = sf.callers_pc;
		ufp = (unsigned long)sf.fp;
		perf_callchain_store(entry, pc);
	} while (entry->nr < PERF_MAX_STACK_DEPTH);
}

void
perf_callchain_user(struct perf_callchain_entry *entry, struct pt_regs *regs)
{
	flushw_user();
	if (test_thread_flag(TIF_32BIT))
		perf_callchain_user_32(entry, regs);
	else
		perf_callchain_user_64(entry, regs);
}

/*
 * Performance events x86 architecture code
 *
 * Copyright (C) 2008 Thomas Gleixner <tglx@linutronix.de>
 * Copyright (C) 2008-2009 Red Hat, Inc., Ingo Molnar
 * Copyright (C) 2009 Jaswinder Singh Rajput
 * Copyright (C) 2009 Advanced Micro Devices, Inc., Robert Richter
 * Copyright (C) 2008-2009 Red Hat, Inc., Peter Zijlstra <pzijlstr@redhat.com>
 * Copyright (C) 2009 Intel Corporation, <markus.t.metzger@intel.com>
 * Copyright (C) 2009 Google, Inc., Stephane Eranian
 *
 * For licencing details see kernel-base/COPYING
 */

#include <linux/perf_event.h>
#include <linux/capability.h>
#include <linux/notifier.h>
#include <linux/hardirq.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/kdebug.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/cpu.h>
#include <linux/bitops.h>

#include <asm/apic.h>
#include <asm/stacktrace.h>
#include <asm/nmi.h>
#include <asm/compat.h>
#include <asm/smp.h>
#include <asm/alternative.h>

#if 0
#undef wrmsrl
#define wrmsrl(msr, val) \
do { \
 trace_printk("wrmsrl(%lx, %lx)\n", (unsigned long)(msr),\
 (unsigned long)(val)); \
 native_write_msr((msr), (u32)((u64)(val)), \
 (u32)((u64)(val) >> 32)); \
} while (0)
#endif

/*
 * best effort, GUP based copy_from_user() that assumes IRQ or NMI context
 */
static unsigned long
copy_from_user_nmi(void *to, const void __user *from, unsigned long n)
{
	unsigned long offset, addr = (unsigned long)from;
	unsigned long size, len = 0;
	struct page *page;
	void *map;
	int ret;

	do {
		ret = __get_user_pages_fast(addr, 1, 0, &page);
		if (!ret)
			break;

		offset = addr & (PAGE_SIZE - 1);
		size = min(PAGE_SIZE - offset, n - len);

		map = kmap_atomic(page);
		memcpy(to, map+offset, size);
		kunmap_atomic(map);
		put_page(page);

		len  += size;
		to   += size;
		addr += size;

	} while (len < n);

	return len;
}

struct event_constraint {
	union {
		unsigned long	idxmsk[BITS_TO_LONGS(X86_PMC_IDX_MAX)];
		u64		idxmsk64;
	};
	u64	code;
	u64	cmask;
	int	weight;
};

struct amd_nb {
	int nb_id;  /* NorthBridge id */
	int refcnt; /* reference count */
	struct perf_event *owners[X86_PMC_IDX_MAX];
	struct event_constraint event_constraints[X86_PMC_IDX_MAX];
};

struct intel_percore;

#define MAX_LBR_ENTRIES 16

struct cpu_hw_events {
	/*
 * Generic x86 PMC bits
 */
	struct perf_event	*events[X86_PMC_IDX_MAX]; /* in counter order */
	unsigned long		active_mask[BITS_TO_LONGS(X86_PMC_IDX_MAX)];
	unsigned long		running[BITS_TO_LONGS(X86_PMC_IDX_MAX)];
	int			enabled;

	int			n_events;
	int			n_added;
	int			n_txn;
	int			assign[X86_PMC_IDX_MAX]; /* event to counter assignment */
	u64			tags[X86_PMC_IDX_MAX];
	struct perf_event	*event_list[X86_PMC_IDX_MAX]; /* in enabled order */

	unsigned int		group_flag;

	/*
 * Intel DebugStore bits
 */
	struct debug_store	*ds;
	u64			pebs_enabled;

	/*
 * Intel LBR bits
 */
	int				lbr_users;
	void				*lbr_context;
	struct perf_branch_stack	lbr_stack;
	struct perf_branch_entry	lbr_entries[MAX_LBR_ENTRIES];

	/*
 * Intel percore register state.
 * Coordinate shared resources between HT threads.
 */
	int				percore_used; /* Used by this CPU? */
	struct intel_percore		*per_core;

	/*
 * AMD specific bits
 */
	struct amd_nb		*amd_nb;
};

#define __EVENT_CONSTRAINT(c, n, m, w) {\
 { .idxmsk64 = (n) }, \
 .code = (c), \
 .cmask = (m), \
 .weight = (w), \
}

#define EVENT_CONSTRAINT(c, n, m) \
 __EVENT_CONSTRAINT(c, n, m, HWEIGHT(n))

/*
 * Constraint on the Event code.
 */
#define INTEL_EVENT_CONSTRAINT(c, n) \
 EVENT_CONSTRAINT(c, n, ARCH_PERFMON_EVENTSEL_EVENT)

/*
 * Constraint on the Event code + UMask + fixed-mask
 *
 * filter mask to validate fixed counter events.
 * the following filters disqualify for fixed counters:
 * - inv
 * - edge
 * - cnt-mask
 * The other filters are supported by fixed counters.
 * The any-thread option is supported starting with v3.
 */
#define FIXED_EVENT_CONSTRAINT(c, n) \
 EVENT_CONSTRAINT(c, (1ULL << (32+n)), X86_RAW_EVENT_MASK)

/*
 * Constraint on the Event code + UMask
 */
#define INTEL_UEVENT_CONSTRAINT(c, n) \
 EVENT_CONSTRAINT(c, n, INTEL_ARCH_EVENT_MASK)

#define EVENT_CONSTRAINT_END \
 EVENT_CONSTRAINT(0, 0, 0)

#define for_each_event_constraint(e, c) \
 for ((e) = (c); (e)->weight; (e)++)

/*
 * Extra registers for specific events.
 * Some events need large masks and require external MSRs.
 * Define a mapping to these extra registers.
 */
struct extra_reg {
	unsigned int		event;
	unsigned int		msr;
	u64			config_mask;
	u64			valid_mask;
};

#define EVENT_EXTRA_REG(e, ms, m, vm) { \
 .event = (e), \
 .msr = (ms), \
 .config_mask = (m), \
 .valid_mask = (vm), \
 }
#define INTEL_EVENT_EXTRA_REG(event, msr, vm) \
 EVENT_EXTRA_REG(event, msr, ARCH_PERFMON_EVENTSEL_EVENT, vm)
#define EVENT_EXTRA_END EVENT_EXTRA_REG(0, 0, 0, 0)

union perf_capabilities {
	struct {
		u64	lbr_format    : 6;
		u64	pebs_trap     : 1;
		u64	pebs_arch_reg : 1;
		u64	pebs_format   : 4;
		u64	smm_freeze    : 1;
	};
	u64	capabilities;
};

/*
 * struct x86_pmu - generic x86 pmu
 */
struct x86_pmu {
	/*
 * Generic x86 PMC bits
 */
	const char	*name;
	int		version;
	int		(*handle_irq)(struct pt_regs *);
	void		(*disable_all)(void);
	void		(*enable_all)(int added);
	void		(*enable)(struct perf_event *);
	void		(*disable)(struct perf_event *);
	void		(*hw_watchdog_set_attr)(struct perf_event_attr *attr);
	int		(*hw_config)(struct perf_event *event);
	int		(*schedule_events)(struct cpu_hw_events *cpuc, int n, int *assign);
	unsigned	eventsel;
	unsigned	perfctr;
	u64		(*event_map)(int);
	int		max_events;
	int		num_counters;
	int		num_counters_fixed;
	int		cntval_bits;
	u64		cntval_mask;
	int		apic;
	u64		max_period;
	struct event_constraint *
			(*get_event_constraints)(struct cpu_hw_events *cpuc,
						 struct perf_event *event);

	void		(*put_event_constraints)(struct cpu_hw_events *cpuc,
						 struct perf_event *event);
	struct event_constraint *event_constraints;
	struct event_constraint *percore_constraints;
	void		(*quirks)(void);
	int		perfctr_second_write;

	int		(*cpu_prepare)(int cpu);
	void		(*cpu_starting)(int cpu);
	void		(*cpu_dying)(int cpu);
	void		(*cpu_dead)(int cpu);

	/*
 * Intel Arch Perfmon v2+
 */
	u64			intel_ctrl;
	union perf_capabilities intel_cap;

	/*
 * Intel DebugStore bits
 */
	int		bts, pebs;
	int		bts_active, pebs_active;
	int		pebs_record_size;
	void		(*drain_pebs)(struct pt_regs *regs);
	struct event_constraint *pebs_constraints;

	/*
 * Intel LBR
 */
	unsigned long	lbr_tos, lbr_from, lbr_to; /* MSR base regs */
	int		lbr_nr;			   /* hardware stack size */

	/*
 * Extra registers for events
 */
	struct extra_reg *extra_regs;
};

static struct x86_pmu x86_pmu __read_mostly;

static DEFINE_PER_CPU(struct cpu_hw_events, cpu_hw_events) = {
	.enabled = 1,
};

static int x86_perf_event_set_period(struct perf_event *event);

/*
 * Generalized hw caching related hw_event table, filled
 * in on a per model basis. A value of 0 means
 * 'not supported', -1 means 'hw_event makes no sense on
 * this CPU', any other value means the raw hw_event
 * ID.
 */

#define C(x) PERF_COUNT_HW_CACHE_##x

static u64 __read_mostly hw_cache_event_ids
				[PERF_COUNT_HW_CACHE_MAX]
				[PERF_COUNT_HW_CACHE_OP_MAX]
				[PERF_COUNT_HW_CACHE_RESULT_MAX];
static u64 __read_mostly hw_cache_extra_regs
				[PERF_COUNT_HW_CACHE_MAX]
				[PERF_COUNT_HW_CACHE_OP_MAX]
				[PERF_COUNT_HW_CACHE_RESULT_MAX];

void hw_nmi_watchdog_set_attr(struct perf_event_attr *wd_attr)
{
	if (x86_pmu.hw_watchdog_set_attr)
		x86_pmu.hw_watchdog_set_attr(wd_attr);
}

/*
 * Propagate event elapsed time into the generic event.
 * Can only be executed on the CPU where the event is active.
 * Returns the delta events processed.
 */
static u64
x86_perf_event_update(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	int shift = 64 - x86_pmu.cntval_bits;
	u64 prev_raw_count, new_raw_count;
	int idx = hwc->idx;
	s64 delta;

	if (idx == X86_PMC_IDX_FIXED_BTS)
		return 0;

	/*
 * Careful: an NMI might modify the previous event value.
 *
 * Our tactic to handle this is to first atomically read and
 * exchange a new raw count - then add that new-prev delta
 * count to the generic event atomically:
 */
again:
	prev_raw_count = local64_read(&hwc->prev_count);
	rdmsrl(hwc->event_base, new_raw_count);

	if (local64_cmpxchg(&hwc->prev_count, prev_raw_count,
					new_raw_count) != prev_raw_count)
		goto again;

	/*
 * Now we have the new raw value and have updated the prev
 * timestamp already. We can now calculate the elapsed delta
 * (event-)time and add that to the generic event.
 *
 * Careful, not all hw sign-extends above the physical width
 * of the count.
 */
	delta = (new_raw_count << shift) - (prev_raw_count << shift);
	delta >>= shift;

	local64_add(delta, &event->count);
	local64_sub(delta, &hwc->period_left);

	return new_raw_count;
}

static inline int x86_pmu_addr_offset(int index)
{
	int offset;

	/* offset = X86_FEATURE_PERFCTR_CORE ? index << 1 : index */
	alternative_io(ASM_NOP2,
		       "shll $1, %%eax",
		       X86_FEATURE_PERFCTR_CORE,
		       "=a" (offset),
		       "a"  (index));

	return offset;
}

static inline unsigned int x86_pmu_config_addr(int index)
{
	return x86_pmu.eventsel + x86_pmu_addr_offset(index);
}

static inline unsigned int x86_pmu_event_addr(int index)
{
	return x86_pmu.perfctr + x86_pmu_addr_offset(index);
}

/*
 * Find and validate any extra registers to set up.
 */
static int x86_pmu_extra_regs(u64 config, struct perf_event *event)
{
	struct extra_reg *er;

	event->hw.extra_reg = 0;
	event->hw.extra_config = 0;

	if (!x86_pmu.extra_regs)
		return 0;

	for (er = x86_pmu.extra_regs; er->msr; er++) {
		if (er->event != (config & er->config_mask))
			continue;
		if (event->attr.config1 & ~er->valid_mask)
			return -EINVAL;
		event->hw.extra_reg = er->msr;
		event->hw.extra_config = event->attr.config1;
		break;
	}
	return 0;
}

static atomic_t active_events;
static DEFINE_MUTEX(pmc_reserve_mutex);

#ifdef CONFIG_X86_LOCAL_APIC

static bool reserve_pmc_hardware(void)
{
	int i;

	for (i = 0; i < x86_pmu.num_counters; i++) {
		if (!reserve_perfctr_nmi(x86_pmu_event_addr(i)))
			goto perfctr_fail;
	}

	for (i = 0; i < x86_pmu.num_counters; i++) {
		if (!reserve_evntsel_nmi(x86_pmu_config_addr(i)))
			goto eventsel_fail;
	}

	return true;

eventsel_fail:
	for (i--; i >= 0; i--)
		release_evntsel_nmi(x86_pmu_config_addr(i));

	i = x86_pmu.num_counters;

perfctr_fail:
	for (i--; i >= 0; i--)
		release_perfctr_nmi(x86_pmu_event_addr(i));

	return false;
}

static void release_pmc_hardware(void)
{
	int i;

	for (i = 0; i < x86_pmu.num_counters; i++) {
		release_perfctr_nmi(x86_pmu_event_addr(i));
		release_evntsel_nmi(x86_pmu_config_addr(i));
	}
}

#else

static bool reserve_pmc_hardware(void) { return true; }
static void release_pmc_hardware(void) {}

#endif

static bool check_hw_exists(void)
{
	u64 val, val_new = 0;
	int i, reg, ret = 0;

	/*
 * Check to see if the BIOS enabled any of the counters, if so
 * complain and bail.
 */
	for (i = 0; i < x86_pmu.num_counters; i++) {
		reg = x86_pmu_config_addr(i);
		ret = rdmsrl_safe(reg, &val);
		if (ret)
			goto msr_fail;
		if (val & ARCH_PERFMON_EVENTSEL_ENABLE)
			goto bios_fail;
	}

	if (x86_pmu.num_counters_fixed) {
		reg = MSR_ARCH_PERFMON_FIXED_CTR_CTRL;
		ret = rdmsrl_safe(reg, &val);
		if (ret)
			goto msr_fail;
		for (i = 0; i < x86_pmu.num_counters_fixed; i++) {
			if (val & (0x03 << i*4))
				goto bios_fail;
		}
	}

	/*
 * Now write a value and read it back to see if it matches,
 * this is needed to detect certain hardware emulators (qemu/kvm)
 * that don't trap on the MSR access and always return 0s.
 */
	val = 0xabcdUL;
	ret = checking_wrmsrl(x86_pmu_event_addr(0), val);
	ret |= rdmsrl_safe(x86_pmu_event_addr(0), &val_new);
	if (ret || val != val_new)
		goto msr_fail;

	return true;

bios_fail:
	/*
 * We still allow the PMU driver to operate:
 */
	printk(KERN_CONT "Broken BIOS detected, complain to your hardware vendor.\n");
	printk(KERN_ERR FW_BUG "the BIOS has corrupted hw-PMU resources (MSR %x is %Lx)\n", reg, val);

	return true;

msr_fail:
	printk(KERN_CONT "Broken PMU hardware detected, using software events only.\n");

	return false;
}

static void reserve_ds_buffers(void);
static void release_ds_buffers(void);

static void hw_perf_event_destroy(struct perf_event *event)
{
	if (atomic_dec_and_mutex_lock(&active_events, &pmc_reserve_mutex)) {
		release_pmc_hardware();
		release_ds_buffers();
		mutex_unlock(&pmc_reserve_mutex);
	}
}

static inline int x86_pmu_initialized(void)
{
	return x86_pmu.handle_irq != NULL;
}

static inline int
set_ext_hw_attr(struct hw_perf_event *hwc, struct perf_event *event)
{
	struct perf_event_attr *attr = &event->attr;
	unsigned int cache_type, cache_op, cache_result;
	u64 config, val;

	config = attr->config;

	cache_type = (config >>  0) & 0xff;
	if (cache_type >= PERF_COUNT_HW_CACHE_MAX)
		return -EINVAL;

	cache_op = (config >>  8) & 0xff;
	if (cache_op >= PERF_COUNT_HW_CACHE_OP_MAX)
		return -EINVAL;

	cache_result = (config >> 16) & 0xff;
	if (cache_result >= PERF_COUNT_HW_CACHE_RESULT_MAX)
		return -EINVAL;

	val = hw_cache_event_ids[cache_type][cache_op][cache_result];

	if (val == 0)
		return -ENOENT;

	if (val == -1)
		return -EINVAL;

	hwc->config |= val;
	attr->config1 = hw_cache_extra_regs[cache_type][cache_op][cache_result];
	return x86_pmu_extra_regs(val, event);
}

static int x86_setup_perfctr(struct perf_event *event)
{
	struct perf_event_attr *attr = &event->attr;
	struct hw_perf_event *hwc = &event->hw;
	u64 config;

	if (!is_sampling_event(event)) {
		hwc->sample_period = x86_pmu.max_period;
		hwc->last_period = hwc->sample_period;
		local64_set(&hwc->period_left, hwc->sample_period);
	} else {
		/*
 * If we have a PMU initialized but no APIC
 * interrupts, we cannot sample hardware
 * events (user-space has to fall back and
 * sample via a hrtimer based software event):
 */
		if (!x86_pmu.apic)
			return -EOPNOTSUPP;
	}

	/*
 * Do not allow config1 (extended registers) to propagate,
 * there's no sane user-space generalization yet:
 */
	if (attr->type == PERF_TYPE_RAW)
		return 0;

	if (attr->type == PERF_TYPE_HW_CACHE)
		return set_ext_hw_attr(hwc, event);

	if (attr->config >= x86_pmu.max_events)
		return -EINVAL;

	/*
 * The generic map:
 */
	config = x86_pmu.event_map(attr->config);

	if (config == 0)
		return -ENOENT;

	if (config == -1LL)
		return -EINVAL;

	/*
 * Branch tracing:
 */
	if (attr->config == PERF_COUNT_HW_BRANCH_INSTRUCTIONS &&
	    !attr->freq && hwc->sample_period == 1) {
		/* BTS is not supported by this architecture. */
		if (!x86_pmu.bts_active)
			return -EOPNOTSUPP;

		/* BTS is currently only allowed for user-mode. */
		if (!attr->exclude_kernel)
			return -EOPNOTSUPP;
	}

	hwc->config |= config;

	return 0;
}

static int x86_pmu_hw_config(struct perf_event *event)
{
	if (event->attr.precise_ip) {
		int precise = 0;

		/* Support for constant skid */
		if (x86_pmu.pebs_active) {
			precise++;

			/* Support for IP fixup */
			if (x86_pmu.lbr_nr)
				precise++;
		}

		if (event->attr.precise_ip > precise)
			return -EOPNOTSUPP;
	}

	/*
 * Generate PMC IRQs:
 * (keep 'enabled' bit clear for now)
 */
	event->hw.config = ARCH_PERFMON_EVENTSEL_INT;

	/*
 * Count user and OS events unless requested not to
 */
	if (!event->attr.exclude_user)
		event->hw.config |= ARCH_PERFMON_EVENTSEL_USR;
	if (!event->attr.exclude_kernel)
		event->hw.config |= ARCH_PERFMON_EVENTSEL_OS;

	if (event->attr.type == PERF_TYPE_RAW)
		event->hw.config |= event->attr.config & X86_RAW_EVENT_MASK;

	return x86_setup_perfctr(event);
}

/*
 * Setup the hardware configuration for a given attr_type
 */
static int __x86_pmu_event_init(struct perf_event *event)
{
	int err;

	if (!x86_pmu_initialized())
		return -ENODEV;

	err = 0;
	if (!atomic_inc_not_zero(&active_events)) {
		mutex_lock(&pmc_reserve_mutex);
		if (atomic_read(&active_events) == 0) {
			if (!reserve_pmc_hardware())
				err = -EBUSY;
			else
				reserve_ds_buffers();
		}
		if (!err)
			atomic_inc(&active_events);
		mutex_unlock(&pmc_reserve_mutex);
	}
	if (err)
		return err;

	event->destroy = hw_perf_event_destroy;

	event->hw.idx = -1;
	event->hw.last_cpu = -1;
	event->hw.last_tag = ~0ULL;

	return x86_pmu.hw_config(event);
}

static void x86_pmu_disable_all(void)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	int idx;

	for (idx = 0; idx < x86_pmu.num_counters; idx++) {
		u64 val;

		if (!test_bit(idx, cpuc->active_mask))
			continue;
		rdmsrl(x86_pmu_config_addr(idx), val);
		if (!(val & ARCH_PERFMON_EVENTSEL_ENABLE))
			continue;
		val &= ~ARCH_PERFMON_EVENTSEL_ENABLE;
		wrmsrl(x86_pmu_config_addr(idx), val);
	}
}

static void x86_pmu_disable(struct pmu *pmu)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);

	if (!x86_pmu_initialized())
		return;

	if (!cpuc->enabled)
		return;

	cpuc->n_added = 0;
	cpuc->enabled = 0;
	barrier();

	x86_pmu.disable_all();
}

static inline void __x86_pmu_enable_event(struct hw_perf_event *hwc,
					  u64 enable_mask)
{
	if (hwc->extra_reg)
		wrmsrl(hwc->extra_reg, hwc->extra_config);
	wrmsrl(hwc->config_base, hwc->config | enable_mask);
}

static void x86_pmu_enable_all(int added)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	int idx;

	for (idx = 0; idx < x86_pmu.num_counters; idx++) {
		struct hw_perf_event *hwc = &cpuc->events[idx]->hw;

		if (!test_bit(idx, cpuc->active_mask))
			continue;

		__x86_pmu_enable_event(hwc, ARCH_PERFMON_EVENTSEL_ENABLE);
	}
}

static struct pmu pmu;

static inline int is_x86_event(struct perf_event *event)
{
	return event->pmu == &pmu;
}

static int x86_schedule_events(struct cpu_hw_events *cpuc, int n, int *assign)
{
	struct event_constraint *c, *constraints[X86_PMC_IDX_MAX];
	unsigned long used_mask[BITS_TO_LONGS(X86_PMC_IDX_MAX)];
	int i, j, w, wmax, num = 0;
	struct hw_perf_event *hwc;

	bitmap_zero(used_mask, X86_PMC_IDX_MAX);

	for (i = 0; i < n; i++) {
		c = x86_pmu.get_event_constraints(cpuc, cpuc->event_list[i]);
		constraints[i] = c;
	}

	/*
 * fastpath, try to reuse previous register
 */
	for (i = 0; i < n; i++) {
		hwc = &cpuc->event_list[i]->hw;
		c = constraints[i];

		/* never assigned */
		if (hwc->idx == -1)
			break;

		/* constraint still honored */
		if (!test_bit(hwc->idx, c->idxmsk))
			break;

		/* not already used */
		if (test_bit(hwc->idx, used_mask))
			break;

		__set_bit(hwc->idx, used_mask);
		if (assign)
			assign[i] = hwc->idx;
	}
	if (i == n)
		goto done;

	/*
 * begin slow path
 */

	bitmap_zero(used_mask, X86_PMC_IDX_MAX);

	/*
 * weight = number of possible counters
 *
 * 1 = most constrained, only works on one counter
 * wmax = least constrained, works on any counter
 *
 * assign events to counters starting with most
 * constrained events.
 */
	wmax = x86_pmu.num_counters;

	/*
 * when fixed event counters are present,
 * wmax is incremented by 1 to account
 * for one more choice
 */
	if (x86_pmu.num_counters_fixed)
		wmax++;

	for (w = 1, num = n; num && w <= wmax; w++) {
		/* for each event */
		for (i = 0; num && i < n; i++) {
			c = constraints[i];
			hwc = &cpuc->event_list[i]->hw;

			if (c->weight != w)
				continue;

			for_each_set_bit(j, c->idxmsk, X86_PMC_IDX_MAX) {
				if (!test_bit(j, used_mask))
					break;
			}

			if (j == X86_PMC_IDX_MAX)
				break;

			__set_bit(j, used_mask);

			if (assign)
				assign[i] = j;
			num--;
		}
	}
done:
	/*
 * scheduling failed or is just a simulation,
 * free resources if necessary
 */
	if (!assign || num) {
		for (i = 0; i < n; i++) {
			if (x86_pmu.put_event_constraints)
				x86_pmu.put_event_constraints(cpuc, cpuc->event_list[i]);
		}
	}
	return num ? -ENOSPC : 0;
}

/*
 * dogrp: true if must collect siblings events (group)
 * returns total number of events and error code
 */
static int collect_events(struct cpu_hw_events *cpuc, struct perf_event *leader, bool dogrp)
{
	struct perf_event *event;
	int n, max_count;

	max_count = x86_pmu.num_counters + x86_pmu.num_counters_fixed;

	/* current number of events already accepted */
	n = cpuc->n_events;

	if (is_x86_event(leader)) {
		if (n >= max_count)
			return -ENOSPC;
		cpuc->event_list[n] = leader;
		n++;
	}
	if (!dogrp)
		return n;

	list_for_each_entry(event, &leader->sibling_list, group_entry) {
		if (!is_x86_event(event) ||
		    event->state <= PERF_EVENT_STATE_OFF)
			continue;

		if (n >= max_count)
			return -ENOSPC;

		cpuc->event_list[n] = event;
		n++;
	}
	return n;
}

static inline void x86_assign_hw_event(struct perf_event *event,
				struct cpu_hw_events *cpuc, int i)
{
	struct hw_perf_event *hwc = &event->hw;

	hwc->idx = cpuc->assign[i];
	hwc->last_cpu = smp_processor_id();
	hwc->last_tag = ++cpuc->tags[i];

	if (hwc->idx == X86_PMC_IDX_FIXED_BTS) {
		hwc->config_base = 0;
		hwc->event_base	= 0;
	} else if (hwc->idx >= X86_PMC_IDX_FIXED) {
		hwc->config_base = MSR_ARCH_PERFMON_FIXED_CTR_CTRL;
		hwc->event_base = MSR_ARCH_PERFMON_FIXED_CTR0 + (hwc->idx - X86_PMC_IDX_FIXED);
	} else {
		hwc->config_base = x86_pmu_config_addr(hwc->idx);
		hwc->event_base  = x86_pmu_event_addr(hwc->idx);
	}
}

static inline int match_prev_assignment(struct hw_perf_event *hwc,
					struct cpu_hw_events *cpuc,
					int i)
{
	return hwc->idx == cpuc->assign[i] &&
		hwc->last_cpu == smp_processor_id() &&
		hwc->last_tag == cpuc->tags[i];
}

static void x86_pmu_start(struct perf_event *event, int flags);
static void x86_pmu_stop(struct perf_event *event, int flags);

static void x86_pmu_enable(struct pmu *pmu)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	struct perf_event *event;
	struct hw_perf_event *hwc;
	int i, added = cpuc->n_added;

	if (!x86_pmu_initialized())
		return;

	if (cpuc->enabled)
		return;

	if (cpuc->n_added) {
		int n_running = cpuc->n_events - cpuc->n_added;
		/*
 * apply assignment obtained either from
 * hw_perf_group_sched_in() or x86_pmu_enable()
 *
 * step1: save events moving to new counters
 * step2: reprogram moved events into new counters
 */
		for (i = 0; i < n_running; i++) {
			event = cpuc->event_list[i];
			hwc = &event->hw;

			/*
 * we can avoid reprogramming counter if:
 * - assigned same counter as last time
 * - running on same CPU as last time
 * - no other event has used the counter since
 */
			if (hwc->idx == -1 ||
			    match_prev_assignment(hwc, cpuc, i))
				continue;

			/*
 * Ensure we don't accidentally enable a stopped
 * counter simply because we rescheduled.
 */
			if (hwc->state & PERF_HES_STOPPED)
				hwc->state |= PERF_HES_ARCH;

			x86_pmu_stop(event, PERF_EF_UPDATE);
		}

		for (i = 0; i < cpuc->n_events; i++) {
			event = cpuc->event_list[i];
			hwc = &event->hw;

			if (!match_prev_assignment(hwc, cpuc, i))
				x86_assign_hw_event(event, cpuc, i);
			else if (i < n_running)
				continue;

			if (hwc->state & PERF_HES_ARCH)
				continue;

			x86_pmu_start(event, PERF_EF_RELOAD);
		}
		cpuc->n_added = 0;
		perf_events_lapic_init();
	}

	cpuc->enabled = 1;
	barrier();

	x86_pmu.enable_all(added);
}

static inline void x86_pmu_disable_event(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;

	wrmsrl(hwc->config_base, hwc->config);
}

static DEFINE_PER_CPU(u64 [X86_PMC_IDX_MAX], pmc_prev_left);

/*
 * Set the next IRQ period, based on the hwc->period_left value.
 * To be called with the event disabled in hw:
 */
static int
x86_perf_event_set_period(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	s64 left = local64_read(&hwc->period_left);
	s64 period = hwc->sample_period;
	int ret = 0, idx = hwc->idx;

	if (idx == X86_PMC_IDX_FIXED_BTS)
		return 0;

	/*
 * If we are way outside a reasonable range then just skip forward:
 */
	if (unlikely(left <= -period)) {
		left = period;
		local64_set(&hwc->period_left, left);
		hwc->last_period = period;
		ret = 1;
	}

	if (unlikely(left <= 0)) {
		left += period;
		local64_set(&hwc->period_left, left);
		hwc->last_period = period;
		ret = 1;
	}
	/*
 * Quirk: certain CPUs dont like it if just 1 hw_event is left:
 */
	if (unlikely(left < 2))
		left = 2;

	if (left > x86_pmu.max_period)
		left = x86_pmu.max_period;

	per_cpu(pmc_prev_left[idx], smp_processor_id()) = left;

	/*
 * The hw event starts counting from this event offset,
 * mark it to be able to extra future deltas:
 */
	local64_set(&hwc->prev_count, (u64)-left);

	wrmsrl(hwc->event_base, (u64)(-left) & x86_pmu.cntval_mask);

	/*
 * Due to erratum on certan cpu we need
 * a second write to be sure the register
 * is updated properly
 */
	if (x86_pmu.perfctr_second_write) {
		wrmsrl(hwc->event_base,
			(u64)(-left) & x86_pmu.cntval_mask);
	}

	perf_event_update_userpage(event);

	return ret;
}

static void x86_pmu_enable_event(struct perf_event *event)
{
	if (__this_cpu_read(cpu_hw_events.enabled))
		__x86_pmu_enable_event(&event->hw,
				       ARCH_PERFMON_EVENTSEL_ENABLE);
}

/*
 * Add a single event to the PMU.
 *
 * The event is added to the group of enabled events
 * but only if it can be scehduled with existing events.
 */
static int x86_pmu_add(struct perf_event *event, int flags)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	struct hw_perf_event *hwc;
	int assign[X86_PMC_IDX_MAX];
	int n, n0, ret;

	hwc = &event->hw;

	perf_pmu_disable(event->pmu);
	n0 = cpuc->n_events;
	ret = n = collect_events(cpuc, event, false);
	if (ret < 0)
		goto out;

	hwc->state = PERF_HES_UPTODATE | PERF_HES_STOPPED;
	if (!(flags & PERF_EF_START))
		hwc->state |= PERF_HES_ARCH;

	/*
 * If group events scheduling transaction was started,
 * skip the schedulability test here, it will be performed
 * at commit time (->commit_txn) as a whole
 */
	if (cpuc->group_flag & PERF_EVENT_TXN)
		goto done_collect;

	ret = x86_pmu.schedule_events(cpuc, n, assign);
	if (ret)
		goto out;
	/*
 * copy new assignment, now we know it is possible
 * will be used by hw_perf_enable()
 */
	memcpy(cpuc->assign, assign, n*sizeof(int));

done_collect:
	cpuc->n_events = n;
	cpuc->n_added += n - n0;
	cpuc->n_txn += n - n0;

	ret = 0;
out:
	perf_pmu_enable(event->pmu);
	return ret;
}

static void x86_pmu_start(struct perf_event *event, int flags)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	int idx = event->hw.idx;

	if (WARN_ON_ONCE(!(event->hw.state & PERF_HES_STOPPED)))
		return;

	if (WARN_ON_ONCE(idx == -1))
		return;

	if (flags & PERF_EF_RELOAD) {
		WARN_ON_ONCE(!(event->hw.state & PERF_HES_UPTODATE));
		x86_perf_event_set_period(event);
	}

	event->hw.state = 0;

	cpuc->events[idx] = event;
	__set_bit(idx, cpuc->active_mask);
	__set_bit(idx, cpuc->running);
	x86_pmu.enable(event);
	perf_event_update_userpage(event);
}

void perf_event_print_debug(void)
{
	u64 ctrl, status, overflow, pmc_ctrl, pmc_count, prev_left, fixed;
	u64 pebs;
	struct cpu_hw_events *cpuc;
	unsigned long flags;
	int cpu, idx;

	if (!x86_pmu.num_counters)
		return;

	local_irq_save(flags);

	cpu = smp_processor_id();
	cpuc = &per_cpu(cpu_hw_events, cpu);

	if (x86_pmu.version >= 2) {
		rdmsrl(MSR_CORE_PERF_GLOBAL_CTRL, ctrl);
		rdmsrl(MSR_CORE_PERF_GLOBAL_STATUS, status);
		rdmsrl(MSR_CORE_PERF_GLOBAL_OVF_CTRL, overflow);
		rdmsrl(MSR_ARCH_PERFMON_FIXED_CTR_CTRL, fixed);
		rdmsrl(MSR_IA32_PEBS_ENABLE, pebs);

		pr_info("\n");
		pr_info("CPU#%d: ctrl: %016llx\n", cpu, ctrl);
		pr_info("CPU#%d: status: %016llx\n", cpu, status);
		pr_info("CPU#%d: overflow: %016llx\n", cpu, overflow);
		pr_info("CPU#%d: fixed: %016llx\n", cpu, fixed);
		pr_info("CPU#%d: pebs: %016llx\n", cpu, pebs);
	}
	pr_info("CPU#%d: active: %016llx\n", cpu, *(u64 *)cpuc->active_mask);

	for (idx = 0; idx < x86_pmu.num_counters; idx++) {
		rdmsrl(x86_pmu_config_addr(idx), pmc_ctrl);
		rdmsrl(x86_pmu_event_addr(idx), pmc_count);

		prev_left = per_cpu(pmc_prev_left[idx], cpu);

		pr_info("CPU#%d: gen-PMC%d ctrl: %016llx\n",
			cpu, idx, pmc_ctrl);
		pr_info("CPU#%d: gen-PMC%d count: %016llx\n",
			cpu, idx, pmc_count);
		pr_info("CPU#%d: gen-PMC%d left: %016llx\n",
			cpu, idx, prev_left);
	}
	for (idx = 0; idx < x86_pmu.num_counters_fixed; idx++) {
		rdmsrl(MSR_ARCH_PERFMON_FIXED_CTR0 + idx, pmc_count);

		pr_info("CPU#%d: fixed-PMC%d count: %016llx\n",
			cpu, idx, pmc_count);
	}
	local_irq_restore(flags);
}

static void x86_pmu_stop(struct perf_event *event, int flags)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	struct hw_perf_event *hwc = &event->hw;

	if (__test_and_clear_bit(hwc->idx, cpuc->active_mask)) {
		x86_pmu.disable(event);
		cpuc->events[hwc->idx] = NULL;
		WARN_ON_ONCE(hwc->state & PERF_HES_STOPPED);
		hwc->state |= PERF_HES_STOPPED;
	}

	if ((flags & PERF_EF_UPDATE) && !(hwc->state & PERF_HES_UPTODATE)) {
		/*
 * Drain the remaining delta count out of a event
 * that we are disabling:
 */
		x86_perf_event_update(event);
		hwc->state |= PERF_HES_UPTODATE;
	}
}

static void x86_pmu_del(struct perf_event *event, int flags)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	int i;

	/*
 * If we're called during a txn, we don't need to do anything.
 * The events never got scheduled and ->cancel_txn will truncate
 * the event_list.
 */
	if (cpuc->group_flag & PERF_EVENT_TXN)
		return;

	x86_pmu_stop(event, PERF_EF_UPDATE);

	for (i = 0; i < cpuc->n_events; i++) {
		if (event == cpuc->event_list[i]) {

			if (x86_pmu.put_event_constraints)
				x86_pmu.put_event_constraints(cpuc, event);

			while (++i < cpuc->n_events)
				cpuc->event_list[i-1] = cpuc->event_list[i];

			--cpuc->n_events;
			break;
		}
	}
	perf_event_update_userpage(event);
}

static int x86_pmu_handle_irq(struct pt_regs *regs)
{
	struct perf_sample_data data;
	struct cpu_hw_events *cpuc;
	struct perf_event *event;
	int idx, handled = 0;
	u64 val;

	perf_sample_data_init(&data, 0);

	cpuc = &__get_cpu_var(cpu_hw_events);

	/*
 * Some chipsets need to unmask the LVTPC in a particular spot
 * inside the nmi handler. As a result, the unmasking was pushed
 * into all the nmi handlers.
 *
 * This generic handler doesn't seem to have any issues where the
 * unmasking occurs so it was left at the top.
 */
	apic_write(APIC_LVTPC, APIC_DM_NMI);

	for (idx = 0; idx < x86_pmu.num_counters; idx++) {
		if (!test_bit(idx, cpuc->active_mask)) {
			/*
 * Though we deactivated the counter some cpus
 * might still deliver spurious interrupts still
 * in flight. Catch them:
 */
			if (__test_and_clear_bit(idx, cpuc->running))
				handled++;
			continue;
		}

		event = cpuc->events[idx];

		val = x86_perf_event_update(event);
		if (val & (1ULL << (x86_pmu.cntval_bits - 1)))
			continue;

		/*
 * event overflow
 */
		handled++;
		data.period	= event->hw.last_period;

		if (!x86_perf_event_set_period(event))
			continue;

		if (perf_event_overflow(event, 1, &data, regs))
			x86_pmu_stop(event, 0);
	}

	if (handled)
		inc_irq_stat(apic_perf_irqs);

	return handled;
}

void perf_events_lapic_init(void)
{
	if (!x86_pmu.apic || !x86_pmu_initialized())
		return;

	/*
 * Always use NMI for PMU
 */
	apic_write(APIC_LVTPC, APIC_DM_NMI);
}

struct pmu_nmi_state {
	unsigned int	marked;
	int		handled;
};

static DEFINE_PER_CPU(struct pmu_nmi_state, pmu_nmi);

static int __kprobes
perf_event_nmi_handler(struct notifier_block *self,
			 unsigned long cmd, void *__args)
{
	struct die_args *args = __args;
	unsigned int this_nmi;
	int handled;

	if (!atomic_read(&active_events))
		return NOTIFY_DONE;

	switch (cmd) {
	case DIE_NMI:
		break;
	case DIE_NMIUNKNOWN:
		this_nmi = percpu_read(irq_stat.__nmi_count);
		if (this_nmi != __this_cpu_read(pmu_nmi.marked))
			/* let the kernel handle the unknown nmi */
			return NOTIFY_DONE;
		/*
 * This one is a PMU back-to-back nmi. Two events
 * trigger 'simultaneously' raising two back-to-back
 * NMIs. If the first NMI handles both, the latter
 * will be empty and daze the CPU. So, we drop it to
 * avoid false-positive 'unknown nmi' messages.
 */
		return NOTIFY_STOP;
	default:
		return NOTIFY_DONE;
	}

	handled = x86_pmu.handle_irq(args->regs);
	if (!handled)
		return NOTIFY_DONE;

	this_nmi = percpu_read(irq_stat.__nmi_count);
	if ((handled > 1) ||
		/* the next nmi could be a back-to-back nmi */
	    ((__this_cpu_read(pmu_nmi.marked) == this_nmi) &&
	     (__this_cpu_read(pmu_nmi.handled) > 1))) {
		/*
 * We could have two subsequent back-to-back nmis: The
 * first handles more than one counter, the 2nd
 * handles only one counter and the 3rd handles no
 * counter.
 *
 * This is the 2nd nmi because the previous was
 * handling more than one counter. We will mark the
 * next (3rd) and then drop it if unhandled.
 */
		__this_cpu_write(pmu_nmi.marked, this_nmi + 1);
		__this_cpu_write(pmu_nmi.handled, handled);
	}

	return NOTIFY_STOP;
}

static __read_mostly struct notifier_block perf_event_nmi_notifier = {
	.notifier_call		= perf_event_nmi_handler,
	.next			= NULL,
	.priority		= NMI_LOCAL_LOW_PRIOR,
};

static struct event_constraint unconstrained;
static struct event_constraint emptyconstraint;

static struct event_constraint *
x86_get_event_constraints(struct cpu_hw_events *cpuc, struct perf_event *event)
{
	struct event_constraint *c;

	if (x86_pmu.event_constraints) {
		for_each_event_constraint(c, x86_pmu.event_constraints) {
			if ((event->hw.config & c->cmask) == c->code)
				return c;
		}
	}

	return &unconstrained;
}

#include "perf_event_amd.c"
#include "perf_event_p6.c"
#include "perf_event_p4.c"
#include "perf_event_intel_lbr.c"
#include "perf_event_intel_ds.c"
#include "perf_event_intel.c"

static int __cpuinit
x86_pmu_notifier(struct notifier_block *self, unsigned long action, void *hcpu)
{
	unsigned int cpu = (long)hcpu;
	int ret = NOTIFY_OK;

	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_UP_PREPARE:
		if (x86_pmu.cpu_prepare)
			ret = x86_pmu.cpu_prepare(cpu);
		break;

	case CPU_STARTING:
		if (x86_pmu.cpu_starting)
			x86_pmu.cpu_starting(cpu);
		break;

	case CPU_DYING:
		if (x86_pmu.cpu_dying)
			x86_pmu.cpu_dying(cpu);
		break;

	case CPU_UP_CANCELED:
	case CPU_DEAD:
		if (x86_pmu.cpu_dead)
			x86_pmu.cpu_dead(cpu);
		break;

	default:
		break;
	}

	return ret;
}

static void __init pmu_check_apic(void)
{
	if (cpu_has_apic)
		return;

	x86_pmu.apic = 0;
	pr_info("no APIC, boot with the \"lapic\" boot parameter to force-enable it.\n");
	pr_info("no hardware sampling interrupt available.\n");
}

static int __init init_hw_perf_events(void)
{
	struct event_constraint *c;
	int err;

	pr_info("Performance Events: ");

	switch (boot_cpu_data.x86_vendor) {
	case X86_VENDOR_INTEL:
		err = intel_pmu_init();
		break;
	case X86_VENDOR_AMD:
		err = amd_pmu_init();
		break;
	default:
		return 0;
	}
	if (err != 0) {
		pr_cont("no PMU driver, software events only.\n");
		return 0;
	}

	pmu_check_apic();

	/* sanity check that the hardware exists or is emulated */
	if (!check_hw_exists())
		return 0;

	pr_cont("%s PMU driver.\n", x86_pmu.name);

	if (x86_pmu.quirks)
		x86_pmu.quirks();

	if (x86_pmu.num_counters > X86_PMC_MAX_GENERIC) {
		WARN(1, KERN_ERR "hw perf events %d > max(%d), clipping!",
		     x86_pmu.num_counters, X86_PMC_MAX_GENERIC);
		x86_pmu.num_counters = X86_PMC_MAX_GENERIC;
	}
	x86_pmu.intel_ctrl = (1 << x86_pmu.num_counters) - 1;

	if (x86_pmu.num_counters_fixed > X86_PMC_MAX_FIXED) {
		WARN(1, KERN_ERR "hw perf events fixed %d > max(%d), clipping!",
		     x86_pmu.num_counters_fixed, X86_PMC_MAX_FIXED);
		x86_pmu.num_counters_fixed = X86_PMC_MAX_FIXED;
	}

	x86_pmu.intel_ctrl |=
		((1LL << x86_pmu.num_counters_fixed)-1) << X86_PMC_IDX_FIXED;

	perf_events_lapic_init();
	register_die_notifier(&perf_event_nmi_notifier);

	unconstrained = (struct event_constraint)
		__EVENT_CONSTRAINT(0, (1ULL << x86_pmu.num_counters) - 1,
				   0, x86_pmu.num_counters);

	if (x86_pmu.event_constraints) {
		for_each_event_constraint(c, x86_pmu.event_constraints) {
			if (c->cmask != X86_RAW_EVENT_MASK)
				continue;

			c->idxmsk64 |= (1ULL << x86_pmu.num_counters) - 1;
			c->weight += x86_pmu.num_counters;
		}
	}

	pr_info("... version: %d\n",     x86_pmu.version);
	pr_info("... bit width: %d\n",     x86_pmu.cntval_bits);
	pr_info("... generic registers: %d\n",     x86_pmu.num_counters);
	pr_info("... value mask: %016Lx\n", x86_pmu.cntval_mask);
	pr_info("... max period: %016Lx\n", x86_pmu.max_period);
	pr_info("... fixed-purpose events: %d\n",     x86_pmu.num_counters_fixed);
	pr_info("... event mask: %016Lx\n", x86_pmu.intel_ctrl);

	perf_pmu_register(&pmu, "cpu", PERF_TYPE_RAW);
	perf_cpu_notifier(x86_pmu_notifier);

	return 0;
}
early_initcall(init_hw_perf_events);

static inline void x86_pmu_read(struct perf_event *event)
{
	x86_perf_event_update(event);
}

/*
 * Start group events scheduling transaction
 * Set the flag to make pmu::enable() not perform the
 * schedulability test, it will be performed at commit time
 */
static void x86_pmu_start_txn(struct pmu *pmu)
{
	perf_pmu_disable(pmu);
	__this_cpu_or(cpu_hw_events.group_flag, PERF_EVENT_TXN);
	__this_cpu_write(cpu_hw_events.n_txn, 0);
}

/*
 * Stop group events scheduling transaction
 * Clear the flag and pmu::enable() will perform the
 * schedulability test.
 */
static void x86_pmu_cancel_txn(struct pmu *pmu)
{
	__this_cpu_and(cpu_hw_events.group_flag, ~PERF_EVENT_TXN);
	/*
 * Truncate the collected events.
 */
	__this_cpu_sub(cpu_hw_events.n_added, __this_cpu_read(cpu_hw_events.n_txn));
	__this_cpu_sub(cpu_hw_events.n_events, __this_cpu_read(cpu_hw_events.n_txn));
	perf_pmu_enable(pmu);
}

/*
 * Commit group events scheduling transaction
 * Perform the group schedulability test as a whole
 * Return 0 if success
 */
static int x86_pmu_commit_txn(struct pmu *pmu)
{
	struct cpu_hw_events *cpuc = &__get_cpu_var(cpu_hw_events);
	int assign[X86_PMC_IDX_MAX];
	int n, ret;

	n = cpuc->n_events;

	if (!x86_pmu_initialized())
		return -EAGAIN;

	ret = x86_pmu.schedule_events(cpuc, n, assign);
	if (ret)
		return ret;

	/*
 * copy new assignment, now we know it is possible
 * will be used by hw_perf_enable()
 */
	memcpy(cpuc->assign, assign, n*sizeof(int));

	cpuc->group_flag &= ~PERF_EVENT_TXN;
	perf_pmu_enable(pmu);
	return 0;
}

/*
 * validate that we can schedule this event
 */
static int validate_event(struct perf_event *event)
{
	struct cpu_hw_events *fake_cpuc;
	struct event_constraint *c;
	int ret = 0;

	fake_cpuc = kmalloc(sizeof(*fake_cpuc), GFP_KERNEL | __GFP_ZERO);
	if (!fake_cpuc)
		return -ENOMEM;

	c = x86_pmu.get_event_constraints(fake_cpuc, event);

	if (!c || !c->weight)
		ret = -ENOSPC;

	if (x86_pmu.put_event_constraints)
		x86_pmu.put_event_constraints(fake_cpuc, event);

	kfree(fake_cpuc);

	return ret;
}

/*
 * validate a single event group
 *
 * validation include:
 * - check events are compatible which each other
 * - events do not compete for the same counter
 * - number of events <= number of counters
 *
 * validation ensures the group can be loaded onto the
 * PMU if it was the only group available.
 */
static int validate_group(struct perf_event *event)
{
	struct perf_event *leader = event->group_leader;
	struct cpu_hw_events *fake_cpuc;
	int ret, n;

	ret = -ENOMEM;
	fake_cpuc = kmalloc(sizeof(*fake_cpuc), GFP_KERNEL | __GFP_ZERO);
	if (!fake_cpuc)
		goto out;

	/*
 * the event is not yet connected with its
 * siblings therefore we must first collect
 * existing siblings, then add the new event
 * before we can simulate the scheduling
 */
	ret = -ENOSPC;
	n = collect_events(fake_cpuc, leader, true);
	if (n < 0)
		goto out_free;

	fake_cpuc->n_events = n;
	n = collect_events(fake_cpuc, event, false);
	if (n < 0)
		goto out_free;

	fake_cpuc->n_events = n;

	ret = x86_pmu.schedule_events(fake_cpuc, n, NULL);

out_free:
	kfree(fake_cpuc);
out:
	return ret;
}

static int x86_pmu_event_init(struct perf_event *event)
{
	struct pmu *tmp;
	int err;

	switch (event->attr.type) {
	case PERF_TYPE_RAW:
	case PERF_TYPE_HARDWARE:
	case PERF_TYPE_HW_CACHE:
		break;

	default:
		return -ENOENT;
	}

	err = __x86_pmu_event_init(event);
	if (!err) {
		/*
 * we temporarily connect event to its pmu
 * such that validate_group() can classify
 * it as an x86 event using is_x86_event()
 */
		tmp = event->pmu;
		event->pmu = &pmu;

		if (event->group_leader != event)
			err = validate_group(event);
		else
			err = validate_event(event);

		event->pmu = tmp;
	}
	if (err) {
		if (event->destroy)
			event->destroy(event);
	}

	return err;
}

static struct pmu pmu = {
	.pmu_enable	= x86_pmu_enable,
	.pmu_disable	= x86_pmu_disable,

	.event_init	= x86_pmu_event_init,

	.add		= x86_pmu_add,
	.del		= x86_pmu_del,
	.start		= x86_pmu_start,
	.stop		= x86_pmu_stop,
	.read		= x86_pmu_read,

	.start_txn	= x86_pmu_start_txn,
	.cancel_txn	= x86_pmu_cancel_txn,
	.commit_txn	= x86_pmu_commit_txn,
};

/*
 * callchain support
 */

static int backtrace_stack(void *data, char *name)
{
	return 0;
}

static void backtrace_address(void *data, unsigned long addr, int reliable)
{
	struct perf_callchain_entry *entry = data;

	perf_callchain_store(entry, addr);
}

static const struct stacktrace_ops backtrace_ops = {
	.stack			= backtrace_stack,
	.address		= backtrace_address,
	.walk_stack		= print_context_stack_bp,
};

void
perf_callchain_kernel(struct perf_callchain_entry *entry, struct pt_regs *regs)
{
	if (perf_guest_cbs && perf_guest_cbs->is_in_guest()) {
		/* TODO: We don't support guest os callchain now */
		return;
	}

	perf_callchain_store(entry, regs->ip);

	dump_trace(NULL, regs, NULL, 0, &backtrace_ops, entry);
}

#ifdef CONFIG_COMPAT
static inline int
perf_callchain_user32(struct pt_regs *regs, struct perf_callchain_entry *entry)
{
	/* 32-bit process in 64-bit kernel. */
	struct stack_frame_ia32 frame;
	const void __user *fp;

	if (!test_thread_flag(TIF_IA32))
		return 0;

	fp = compat_ptr(regs->bp);
	while (entry->nr < PERF_MAX_STACK_DEPTH) {
		unsigned long bytes;
		frame.next_frame     = 0;
		frame.return_address = 0;

		bytes = copy_from_user_nmi(&frame, fp, sizeof(frame));
		if (bytes != sizeof(frame))
			break;

		if (fp < compat_ptr(regs->sp))
			break;

		perf_callchain_store(entry, frame.return_address);
		fp = compat_ptr(frame.next_frame);
	}
	return 1;
}
#else
static inline int
perf_callchain_user32(struct pt_regs *regs, struct perf_callchain_entry *entry)
{
    return 0;
}
#endif

void
perf_callchain_user(struct perf_callchain_entry *entry, struct pt_regs *regs)
{
	struct stack_frame frame;
	const void __user *fp;

	if (perf_guest_cbs && perf_guest_cbs->is_in_guest()) {
		/* TODO: We don't support guest os callchain now */
		return;
	}

	fp = (void __user *)regs->bp;

	perf_callchain_store(entry, regs->ip);

	if (perf_callchain_user32(regs, entry))
		return;

	while (entry->nr < PERF_MAX_STACK_DEPTH) {
		unsigned long bytes;
		frame.next_frame	     = NULL;
		frame.return_address = 0;

		bytes = copy_from_user_nmi(&frame, fp, sizeof(frame));
		if (bytes != sizeof(frame))
			break;

		if ((unsigned long)fp < regs->sp)
			break;

		perf_callchain_store(entry, frame.return_address);
		fp = frame.next_frame;
	}
}

unsigned long perf_instruction_pointer(struct pt_regs *regs)
{
	unsigned long ip;

	if (perf_guest_cbs && perf_guest_cbs->is_in_guest())
		ip = perf_guest_cbs->get_guest_ip();
	else
		ip = instruction_pointer(regs);

	return ip;
}

unsigned long perf_misc_flags(struct pt_regs *regs)
{
	int misc = 0;

	if (perf_guest_cbs && perf_guest_cbs->is_in_guest()) {
		if (perf_guest_cbs->is_user_mode())
			misc |= PERF_RECORD_MISC_GUEST_USER;
		else
			misc |= PERF_RECORD_MISC_GUEST_KERNEL;
	} else {
		if (user_mode(regs))
			misc |= PERF_RECORD_MISC_USER;
		else
			misc |= PERF_RECORD_MISC_KERNEL;
	}

	if (regs->flags & PERF_EFLAGS_EXACT)
		misc |= PERF_RECORD_MISC_EXACT_IP;

	return misc;
}