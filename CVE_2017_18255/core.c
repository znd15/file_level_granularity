

/*
 * Performance events core code:
 *
 * Copyright (C) 2008 Thomas Gleixner <tglx@linutronix.de>
 * Copyright (C) 2008-2011 Red Hat, Inc., Ingo Molnar
 * Copyright (C) 2008-2011 Red Hat, Inc., Peter Zijlstra
 * Copyright © 2009 Paul Mackerras, IBM Corp. <paulus@au1.ibm.com>
 *
 * For licensing details see kernel-base/COPYING
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/idr.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/tick.h>
#include <linux/sysfs.h>
#include <linux/dcache.h>
#include <linux/percpu.h>
#include <linux/ptrace.h>
#include <linux/reboot.h>
#include <linux/vmstat.h>
#include <linux/device.h>
#include <linux/export.h>
#include <linux/vmalloc.h>
#include <linux/hardirq.h>
#include <linux/rculist.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/anon_inodes.h>
#include <linux/kernel_stat.h>
#include <linux/cgroup.h>
#include <linux/perf_event.h>
#include <linux/trace_events.h>
#include <linux/hw_breakpoint.h>
#include <linux/mm_types.h>
#include <linux/module.h>
#include <linux/mman.h>
#include <linux/compat.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/namei.h>
#include <linux/parser.h>

#include "internal.h"

#include <asm/irq_regs.h>

typedef int (*remote_function_f)(void *);

struct remote_function_call {
	struct task_struct	*p;
	remote_function_f	func;
	void			*info;
	int			ret;
};

static void remote_function(void *data)
{
	struct remote_function_call *tfc = data;
	struct task_struct *p = tfc->p;

	if (p) {
		/* -EAGAIN */
		if (task_cpu(p) != smp_processor_id())
			return;

		/*
 * Now that we're on right CPU with IRQs disabled, we can test
 * if we hit the right task without races.
 */

		tfc->ret = -ESRCH; /* No such (running) process */
		if (p != current)
			return;
	}

	tfc->ret = tfc->func(tfc->info);
}

/**
 * task_function_call - call a function on the cpu on which a task runs
 * @p: the task to evaluate
 * @func: the function to be called
 * @info: the function call argument
 *
 * Calls the function @func when the task is currently running. This might
 * be on the current CPU, which just calls the function directly
 *
 * returns: @func return value, or
 * -ESRCH - when the process isn't running
 * -EAGAIN - when the process moved away
 */
static int
task_function_call(struct task_struct *p, remote_function_f func, void *info)
{
	struct remote_function_call data = {
		.p	= p,
		.func	= func,
		.info	= info,
		.ret	= -EAGAIN,
	};
	int ret;

	do {
		ret = smp_call_function_single(task_cpu(p), remote_function, &data, 1);
		if (!ret)
			ret = data.ret;
	} while (ret == -EAGAIN);

	return ret;
}

/**
 * cpu_function_call - call a function on the cpu
 * @func: the function to be called
 * @info: the function call argument
 *
 * Calls the function @func on the remote cpu.
 *
 * returns: @func return value or -ENXIO when the cpu is offline
 */
static int cpu_function_call(int cpu, remote_function_f func, void *info)
{
	struct remote_function_call data = {
		.p	= NULL,
		.func	= func,
		.info	= info,
		.ret	= -ENXIO, /* No such CPU */
	};

	smp_call_function_single(cpu, remote_function, &data, 1);

	return data.ret;
}

static inline struct perf_cpu_context *
__get_cpu_context(struct perf_event_context *ctx)
{
	return this_cpu_ptr(ctx->pmu->pmu_cpu_context);
}

static void perf_ctx_lock(struct perf_cpu_context *cpuctx,
			  struct perf_event_context *ctx)
{
	raw_spin_lock(&cpuctx->ctx.lock);
	if (ctx)
		raw_spin_lock(&ctx->lock);
}

static void perf_ctx_unlock(struct perf_cpu_context *cpuctx,
			    struct perf_event_context *ctx)
{
	if (ctx)
		raw_spin_unlock(&ctx->lock);
	raw_spin_unlock(&cpuctx->ctx.lock);
}

#define TASK_TOMBSTONE ((void *)-1L)

static bool is_kernel_event(struct perf_event *event)
{
	return READ_ONCE(event->owner) == TASK_TOMBSTONE;
}

/*
 * On task ctx scheduling...
 *
 * When !ctx->nr_events a task context will not be scheduled. This means
 * we can disable the scheduler hooks (for performance) without leaving
 * pending task ctx state.
 *
 * This however results in two special cases:
 *
 * - removing the last event from a task ctx; this is relatively straight
 * forward and is done in __perf_remove_from_context.
 *
 * - adding the first event to a task ctx; this is tricky because we cannot
 * rely on ctx->is_active and therefore cannot use event_function_call().
 * See perf_install_in_context().
 *
 * If ctx->nr_events, then ctx->is_active and cpuctx->task_ctx are set.
 */

typedef void (*event_f)(struct perf_event *, struct perf_cpu_context *,
			struct perf_event_context *, void *);

struct event_function_struct {
	struct perf_event *event;
	event_f func;
	void *data;
};

static int event_function(void *info)
{
	struct event_function_struct *efs = info;
	struct perf_event *event = efs->event;
	struct perf_event_context *ctx = event->ctx;
	struct perf_cpu_context *cpuctx = __get_cpu_context(ctx);
	struct perf_event_context *task_ctx = cpuctx->task_ctx;
	int ret = 0;

	WARN_ON_ONCE(!irqs_disabled());

	perf_ctx_lock(cpuctx, task_ctx);
	/*
 * Since we do the IPI call without holding ctx->lock things can have
 * changed, double check we hit the task we set out to hit.
 */
	if (ctx->task) {
		if (ctx->task != current) {
			ret = -ESRCH;
			goto unlock;
		}

		/*
 * We only use event_function_call() on established contexts,
 * and event_function() is only ever called when active (or
 * rather, we'll have bailed in task_function_call() or the
 * above ctx->task != current test), therefore we must have
 * ctx->is_active here.
 */
		WARN_ON_ONCE(!ctx->is_active);
		/*
 * And since we have ctx->is_active, cpuctx->task_ctx must
 * match.
 */
		WARN_ON_ONCE(task_ctx != ctx);
	} else {
		WARN_ON_ONCE(&cpuctx->ctx != ctx);
	}

	efs->func(event, cpuctx, ctx, efs->data);
unlock:
	perf_ctx_unlock(cpuctx, task_ctx);

	return ret;
}

static void event_function_call(struct perf_event *event, event_f func, void *data)
{
	struct perf_event_context *ctx = event->ctx;
	struct task_struct *task = READ_ONCE(ctx->task); /* verified in event_function */
	struct event_function_struct efs = {
		.event = event,
		.func = func,
		.data = data,
	};

	if (!event->parent) {
		/*
 * If this is a !child event, we must hold ctx::mutex to
 * stabilize the the event->ctx relation. See
 * perf_event_ctx_lock().
 */
		lockdep_assert_held(&ctx->mutex);
	}

	if (!task) {
		cpu_function_call(event->cpu, event_function, &efs);
		return;
	}

	if (task == TASK_TOMBSTONE)
		return;

again:
	if (!task_function_call(task, event_function, &efs))
		return;

	raw_spin_lock_irq(&ctx->lock);
	/*
 * Reload the task pointer, it might have been changed by
 * a concurrent perf_event_context_sched_out().
 */
	task = ctx->task;
	if (task == TASK_TOMBSTONE) {
		raw_spin_unlock_irq(&ctx->lock);
		return;
	}
	if (ctx->is_active) {
		raw_spin_unlock_irq(&ctx->lock);
		goto again;
	}
	func(event, NULL, ctx, data);
	raw_spin_unlock_irq(&ctx->lock);
}

/*
 * Similar to event_function_call() + event_function(), but hard assumes IRQs
 * are already disabled and we're on the right CPU.
 */
static void event_function_local(struct perf_event *event, event_f func, void *data)
{
	struct perf_event_context *ctx = event->ctx;
	struct perf_cpu_context *cpuctx = __get_cpu_context(ctx);
	struct task_struct *task = READ_ONCE(ctx->task);
	struct perf_event_context *task_ctx = NULL;

	WARN_ON_ONCE(!irqs_disabled());

	if (task) {
		if (task == TASK_TOMBSTONE)
			return;

		task_ctx = ctx;
	}

	perf_ctx_lock(cpuctx, task_ctx);

	task = ctx->task;
	if (task == TASK_TOMBSTONE)
		goto unlock;

	if (task) {
		/*
 * We must be either inactive or active and the right task,
 * otherwise we're screwed, since we cannot IPI to somewhere
 * else.
 */
		if (ctx->is_active) {
			if (WARN_ON_ONCE(task != current))
				goto unlock;

			if (WARN_ON_ONCE(cpuctx->task_ctx != ctx))
				goto unlock;
		}
	} else {
		WARN_ON_ONCE(&cpuctx->ctx != ctx);
	}

	func(event, cpuctx, ctx, data);
unlock:
	perf_ctx_unlock(cpuctx, task_ctx);
}

#define PERF_FLAG_ALL (PERF_FLAG_FD_NO_GROUP |\
 PERF_FLAG_FD_OUTPUT |\
 PERF_FLAG_PID_CGROUP |\
 PERF_FLAG_FD_CLOEXEC)

/*
 * branch priv levels that need permission checks
 */
#define PERF_SAMPLE_BRANCH_PERM_PLM \
 (PERF_SAMPLE_BRANCH_KERNEL |\
 PERF_SAMPLE_BRANCH_HV)

enum event_type_t {
	EVENT_FLEXIBLE = 0x1,
	EVENT_PINNED = 0x2,
	EVENT_TIME = 0x4,
	/* see ctx_resched() for details */
	EVENT_CPU = 0x8,
	EVENT_ALL = EVENT_FLEXIBLE | EVENT_PINNED,
};

/*
 * perf_sched_events : >0 events exist
 * perf_cgroup_events: >0 per-cpu cgroup events exist on this cpu
 */

static void perf_sched_delayed(struct work_struct *work);
DEFINE_STATIC_KEY_FALSE(perf_sched_events);
static DECLARE_DELAYED_WORK(perf_sched_work, perf_sched_delayed);
static DEFINE_MUTEX(perf_sched_mutex);
static atomic_t perf_sched_count;

static DEFINE_PER_CPU(atomic_t, perf_cgroup_events);
static DEFINE_PER_CPU(int, perf_sched_cb_usages);
static DEFINE_PER_CPU(struct pmu_event_list, pmu_sb_events);

static atomic_t nr_mmap_events __read_mostly;
static atomic_t nr_comm_events __read_mostly;
static atomic_t nr_task_events __read_mostly;
static atomic_t nr_freq_events __read_mostly;
static atomic_t nr_switch_events __read_mostly;

static LIST_HEAD(pmus);
static DEFINE_MUTEX(pmus_lock);
static struct srcu_struct pmus_srcu;

/*
 * perf event paranoia level:
 * -1 - not paranoid at all
 * 0 - disallow raw tracepoint access for unpriv
 * 1 - disallow cpu events for unpriv
 * 2 - disallow kernel profiling for unpriv
 */
int sysctl_perf_event_paranoid __read_mostly = 2;

/* Minimum for 512 kiB + 1 user control page */
int sysctl_perf_event_mlock __read_mostly = 512 + (PAGE_SIZE / 1024); /* 'free' kiB per user */

/*
 * max perf event sample rate
 */
#define DEFAULT_MAX_SAMPLE_RATE 100000
#define DEFAULT_SAMPLE_PERIOD_NS (NSEC_PER_SEC / DEFAULT_MAX_SAMPLE_RATE)
#define DEFAULT_CPU_TIME_MAX_PERCENT 25

int sysctl_perf_event_sample_rate __read_mostly	= DEFAULT_MAX_SAMPLE_RATE;

static int max_samples_per_tick __read_mostly	= DIV_ROUND_UP(DEFAULT_MAX_SAMPLE_RATE, HZ);
static int perf_sample_period_ns __read_mostly	= DEFAULT_SAMPLE_PERIOD_NS;

static int perf_sample_allowed_ns __read_mostly =
	DEFAULT_SAMPLE_PERIOD_NS * DEFAULT_CPU_TIME_MAX_PERCENT / 100;

static void update_perf_cpu_limits(void)
{
	u64 tmp = perf_sample_period_ns;

	tmp *= sysctl_perf_cpu_time_max_percent;
	tmp = div_u64(tmp, 100);
	if (!tmp)
		tmp = 1;

	WRITE_ONCE(perf_sample_allowed_ns, tmp);
}

static int perf_rotate_context(struct perf_cpu_context *cpuctx);

int perf_proc_update_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp,
		loff_t *ppos)
{
	int ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (ret || !write)
		return ret;

	/*
 * If throttling is disabled don't allow the write:
 */
	if (sysctl_perf_cpu_time_max_percent == 100 ||
	    sysctl_perf_cpu_time_max_percent == 0)
		return -EINVAL;

	max_samples_per_tick = DIV_ROUND_UP(sysctl_perf_event_sample_rate, HZ);
	perf_sample_period_ns = NSEC_PER_SEC / sysctl_perf_event_sample_rate;
	update_perf_cpu_limits();

	return 0;
}

int sysctl_perf_cpu_time_max_percent __read_mostly = DEFAULT_CPU_TIME_MAX_PERCENT;

int perf_cpu_time_max_percent_handler(struct ctl_table *table, int write,
				void __user *buffer, size_t *lenp,
				loff_t *ppos)
{
	int ret = proc_dointvec(table, write, buffer, lenp, ppos);

	if (ret || !write)
		return ret;

	if (sysctl_perf_cpu_time_max_percent == 100 ||
	    sysctl_perf_cpu_time_max_percent == 0) {
		printk(KERN_WARNING
		       "perf: Dynamic interrupt throttling disabled, can hang your system!\n");
		WRITE_ONCE(perf_sample_allowed_ns, 0);
	} else {
		update_perf_cpu_limits();
	}

	return 0;
}

/*
 * perf samples are done in some very critical code paths (NMIs).
 * If they take too much CPU time, the system can lock up and not
 * get any real work done. This will drop the sample rate when
 * we detect that events are taking too long.
 */
#define NR_ACCUMULATED_SAMPLES 128
static DEFINE_PER_CPU(u64, running_sample_length);

static u64 __report_avg;
static u64 __report_allowed;

static void perf_duration_warn(struct irq_work *w)
{
	printk_ratelimited(KERN_INFO
		"perf: interrupt took too long (%lld > %lld), lowering "
		"kernel.perf_event_max_sample_rate to %d\n",
		__report_avg, __report_allowed,
		sysctl_perf_event_sample_rate);
}

static DEFINE_IRQ_WORK(perf_duration_work, perf_duration_warn);

void perf_sample_event_took(u64 sample_len_ns)
{
	u64 max_len = READ_ONCE(perf_sample_allowed_ns);
	u64 running_len;
	u64 avg_len;
	u32 max;

	if (max_len == 0)
		return;

	/* Decay the counter by 1 average sample. */
	running_len = __this_cpu_read(running_sample_length);
	running_len -= running_len/NR_ACCUMULATED_SAMPLES;
	running_len += sample_len_ns;
	__this_cpu_write(running_sample_length, running_len);

	/*
 * Note: this will be biased artifically low until we have
 * seen NR_ACCUMULATED_SAMPLES. Doing it this way keeps us
 * from having to maintain a count.
 */
	avg_len = running_len/NR_ACCUMULATED_SAMPLES;
	if (avg_len <= max_len)
		return;

	__report_avg = avg_len;
	__report_allowed = max_len;

	/*
 * Compute a throttle threshold 25% below the current duration.
 */
	avg_len += avg_len / 4;
	max = (TICK_NSEC / 100) * sysctl_perf_cpu_time_max_percent;
	if (avg_len < max)
		max /= (u32)avg_len;
	else
		max = 1;

	WRITE_ONCE(perf_sample_allowed_ns, avg_len);
	WRITE_ONCE(max_samples_per_tick, max);

	sysctl_perf_event_sample_rate = max * HZ;
	perf_sample_period_ns = NSEC_PER_SEC / sysctl_perf_event_sample_rate;

	if (!irq_work_queue(&perf_duration_work)) {
		early_printk("perf: interrupt took too long (%lld > %lld), lowering "
			     "kernel.perf_event_max_sample_rate to %d\n",
			     __report_avg, __report_allowed,
			     sysctl_perf_event_sample_rate);
	}
}

static atomic64_t perf_event_id;

static void cpu_ctx_sched_out(struct perf_cpu_context *cpuctx,
			      enum event_type_t event_type);

static void cpu_ctx_sched_in(struct perf_cpu_context *cpuctx,
			     enum event_type_t event_type,
			     struct task_struct *task);

static void update_context_time(struct perf_event_context *ctx);
static u64 perf_event_time(struct perf_event *event);

void __weak perf_event_print_debug(void) { }

extern __weak const char *perf_pmu_name(void)
{
	return "pmu";
}

static inline u64 perf_clock(void)
{
	return local_clock();
}

static inline u64 perf_event_clock(struct perf_event *event)
{
	return event->clock();
}

#ifdef CONFIG_CGROUP_PERF

static inline bool
perf_cgroup_match(struct perf_event *event)
{
	struct perf_event_context *ctx = event->ctx;
	struct perf_cpu_context *cpuctx = __get_cpu_context(ctx);

	/* @event doesn't care about cgroup */
	if (!event->cgrp)
		return true;

	/* wants specific cgroup scope but @cpuctx isn't associated with any */
	if (!cpuctx->cgrp)
		return false;

	/*
 * Cgroup scoping is recursive. An event enabled for a cgroup is
 * also enabled for all its descendant cgroups. If @cpuctx's
 * cgroup is a descendant of @event's (the test covers identity
 * case), it's a match.
 */
	return cgroup_is_descendant(cpuctx->cgrp->css.cgroup,
				    event->cgrp->css.cgroup);
}

static inline void perf_detach_cgroup(struct perf_event *event)
{
	css_put(&event->cgrp->css);
	event->cgrp = NULL;
}

static inline int is_cgroup_event(struct perf_event *event)
{
	return event->cgrp != NULL;
}

static inline u64 perf_cgroup_event_time(struct perf_event *event)
{
	struct perf_cgroup_info *t;

	t = per_cpu_ptr(event->cgrp->info, event->cpu);
	return t->time;
}

static inline void __update_cgrp_time(struct perf_cgroup *cgrp)
{
	struct perf_cgroup_info *info;
	u64 now;

	now = perf_clock();

	info = this_cpu_ptr(cgrp->info);

	info->time += now - info->timestamp;
	info->timestamp = now;
}

static inline void update_cgrp_time_from_cpuctx(struct perf_cpu_context *cpuctx)
{
	struct perf_cgroup *cgrp_out = cpuctx->cgrp;
	if (cgrp_out)
		__update_cgrp_time(cgrp_out);
}

static inline void update_cgrp_time_from_event(struct perf_event *event)
{
	struct perf_cgroup *cgrp;

	/*
 * ensure we access cgroup data only when needed and
 * when we know the cgroup is pinned (css_get)
 */
	if (!is_cgroup_event(event))
		return;

	cgrp = perf_cgroup_from_task(current, event->ctx);
	/*
 * Do not update time when cgroup is not active
 */
	if (cgrp == event->cgrp)
		__update_cgrp_time(event->cgrp);
}

static inline void
perf_cgroup_set_timestamp(struct task_struct *task,
			  struct perf_event_context *ctx)
{
	struct perf_cgroup *cgrp;
	struct perf_cgroup_info *info;

	/*
 * ctx->lock held by caller
 * ensure we do not access cgroup data
 * unless we have the cgroup pinned (css_get)
 */
	if (!task || !ctx->nr_cgroups)
		return;

	cgrp = perf_cgroup_from_task(task, ctx);
	info = this_cpu_ptr(cgrp->info);
	info->timestamp = ctx->timestamp;
}

static DEFINE_PER_CPU(struct list_head, cgrp_cpuctx_list);

#define PERF_CGROUP_SWOUT 0x1 /* cgroup switch out every event */
#define PERF_CGROUP_SWIN 0x2 /* cgroup switch in events based on task */

/*
 * reschedule events based on the cgroup constraint of task.
 *
 * mode SWOUT : schedule out everything
 * mode SWIN : schedule in based on cgroup for next
 */
static void perf_cgroup_switch(struct task_struct *task, int mode)
{
	struct perf_cpu_context *cpuctx;
	struct list_head *list;
	unsigned long flags;

	/*
 * Disable interrupts and preemption to avoid this CPU's
 * cgrp_cpuctx_entry to change under us.
 */
	local_irq_save(flags);

	list = this_cpu_ptr(&cgrp_cpuctx_list);
	list_for_each_entry(cpuctx, list, cgrp_cpuctx_entry) {
		WARN_ON_ONCE(cpuctx->ctx.nr_cgroups == 0);

		perf_ctx_lock(cpuctx, cpuctx->task_ctx);
		perf_pmu_disable(cpuctx->ctx.pmu);

		if (mode & PERF_CGROUP_SWOUT) {
			cpu_ctx_sched_out(cpuctx, EVENT_ALL);
			/*
 * must not be done before ctxswout due
 * to event_filter_match() in event_sched_out()
 */
			cpuctx->cgrp = NULL;
		}

		if (mode & PERF_CGROUP_SWIN) {
			WARN_ON_ONCE(cpuctx->cgrp);
			/*
 * set cgrp before ctxsw in to allow
 * event_filter_match() to not have to pass
 * task around
 * we pass the cpuctx->ctx to perf_cgroup_from_task()
 * because cgorup events are only per-cpu
 */
			cpuctx->cgrp = perf_cgroup_from_task(task,
							     &cpuctx->ctx);
			cpu_ctx_sched_in(cpuctx, EVENT_ALL, task);
		}
		perf_pmu_enable(cpuctx->ctx.pmu);
		perf_ctx_unlock(cpuctx, cpuctx->task_ctx);
	}

	local_irq_restore(flags);
}

static inline void perf_cgroup_sched_out(struct task_struct *task,
					 struct task_struct *next)
{
	struct perf_cgroup *cgrp1;
	struct perf_cgroup *cgrp2 = NULL;

	rcu_read_lock();
	/*
 * we come here when we know perf_cgroup_events > 0
 * we do not need to pass the ctx here because we know
 * we are holding the rcu lock
 */
	cgrp1 = perf_cgroup_from_task(task, NULL);
	cgrp2 = perf_cgroup_from_task(next, NULL);

	/*
 * only schedule out current cgroup events if we know
 * that we are switching to a different cgroup. Otherwise,
 * do no touch the cgroup events.
 */
	if (cgrp1 != cgrp2)
		perf_cgroup_switch(task, PERF_CGROUP_SWOUT);

	rcu_read_unlock();
}

static inline void perf_cgroup_sched_in(struct task_struct *prev,
					struct task_struct *task)
{
	struct perf_cgroup *cgrp1;
	struct perf_cgroup *cgrp2 = NULL;

	rcu_read_lock();
	/*
 * we come here when we know perf_cgroup_events > 0
 * we do not need to pass the ctx here because we know
 * we are holding the rcu lock
 */
	cgrp1 = perf_cgroup_from_task(task, NULL);
	cgrp2 = perf_cgroup_from_task(prev, NULL);

	/*
 * only need to schedule in cgroup events if we are changing
 * cgroup during ctxsw. Cgroup events were not scheduled
 * out of ctxsw out if that was not the case.
 */
	if (cgrp1 != cgrp2)
		perf_cgroup_switch(task, PERF_CGROUP_SWIN);

	rcu_read_unlock();
}

static inline int perf_cgroup_connect(int fd, struct perf_event *event,
				      struct perf_event_attr *attr,
				      struct perf_event *group_leader)
{
	struct perf_cgroup *cgrp;
	struct cgroup_subsys_state *css;
	struct fd f = fdget(fd);
	int ret = 0;

	if (!f.file)
		return -EBADF;

	css = css_tryget_online_from_dir(f.file->f_path.dentry,
					 &perf_event_cgrp_subsys);
	if (IS_ERR(css)) {
		ret = PTR_ERR(css);
		goto out;
	}

	cgrp = container_of(css, struct perf_cgroup, css);
	event->cgrp = cgrp;

	/*
 * all events in a group must monitor
 * the same cgroup because a task belongs
 * to only one perf cgroup at a time
 */
	if (group_leader && group_leader->cgrp != cgrp) {
		perf_detach_cgroup(event);
		ret = -EINVAL;
	}
out:
	fdput(f);
	return ret;
}

static inline void
perf_cgroup_set_shadow_time(struct perf_event *event, u64 now)
{
	struct perf_cgroup_info *t;
	t = per_cpu_ptr(event->cgrp->info, event->cpu);
	event->shadow_ctx_time = now - t->timestamp;
}

static inline void
perf_cgroup_defer_enabled(struct perf_event *event)
{
	/*
 * when the current task's perf cgroup does not match
 * the event's, we need to remember to call the
 * perf_mark_enable() function the first time a task with
 * a matching perf cgroup is scheduled in.
 */
	if (is_cgroup_event(event) && !perf_cgroup_match(event))
		event->cgrp_defer_enabled = 1;
}

static inline void
perf_cgroup_mark_enabled(struct perf_event *event,
			 struct perf_event_context *ctx)
{
	struct perf_event *sub;
	u64 tstamp = perf_event_time(event);

	if (!event->cgrp_defer_enabled)
		return;

	event->cgrp_defer_enabled = 0;

	event->tstamp_enabled = tstamp - event->total_time_enabled;
	list_for_each_entry(sub, &event->sibling_list, group_entry) {
		if (sub->state >= PERF_EVENT_STATE_INACTIVE) {
			sub->tstamp_enabled = tstamp - sub->total_time_enabled;
			sub->cgrp_defer_enabled = 0;
		}
	}
}

/*
 * Update cpuctx->cgrp so that it is set when first cgroup event is added and
 * cleared when last cgroup event is removed.
 */
static inline void
list_update_cgroup_event(struct perf_event *event,
			 struct perf_event_context *ctx, bool add)
{
	struct perf_cpu_context *cpuctx;
	struct list_head *cpuctx_entry;

	if (!is_cgroup_event(event))
		return;

	if (add && ctx->nr_cgroups++)
		return;
	else if (!add && --ctx->nr_cgroups)
		return;
	/*
 * Because cgroup events are always per-cpu events,
 * this will always be called from the right CPU.
 */
	cpuctx = __get_cpu_context(ctx);
	cpuctx_entry = &cpuctx->cgrp_cpuctx_entry;
	/* cpuctx->cgrp is NULL unless a cgroup event is active in this CPU .*/
	if (add) {
		list_add(cpuctx_entry, this_cpu_ptr(&cgrp_cpuctx_list));
		if (perf_cgroup_from_task(current, ctx) == event->cgrp)
			cpuctx->cgrp = event->cgrp;
	} else {
		list_del(cpuctx_entry);
		cpuctx->cgrp = NULL;
	}
}

#else /* !CONFIG_CGROUP_PERF */

static inline bool
perf_cgroup_match(struct perf_event *event)
{
	return true;
}

static inline void perf_detach_cgroup(struct perf_event *event)
{}

static inline int is_cgroup_event(struct perf_event *event)
{
	return 0;
}

static inline u64 perf_cgroup_event_cgrp_time(struct perf_event *event)
{
	return 0;
}

static inline void update_cgrp_time_from_event(struct perf_event *event)
{
}

static inline void update_cgrp_time_from_cpuctx(struct perf_cpu_context *cpuctx)
{
}

static inline void perf_cgroup_sched_out(struct task_struct *task,
					 struct task_struct *next)
{
}

static inline void perf_cgroup_sched_in(struct task_struct *prev,
					struct task_struct *task)
{
}

static inline int perf_cgroup_connect(pid_t pid, struct perf_event *event,
				      struct perf_event_attr *attr,
				      struct perf_event *group_leader)
{
	return -EINVAL;
}

static inline void
perf_cgroup_set_timestamp(struct task_struct *task,
			  struct perf_event_context *ctx)
{
}

void
perf_cgroup_switch(struct task_struct *task, struct task_struct *next)
{
}

static inline void
perf_cgroup_set_shadow_time(struct perf_event *event, u64 now)
{
}

static inline u64 perf_cgroup_event_time(struct perf_event *event)
{
	return 0;
}

static inline void
perf_cgroup_defer_enabled(struct perf_event *event)
{
}

static inline void
perf_cgroup_mark_enabled(struct perf_event *event,
			 struct perf_event_context *ctx)
{
}

static inline void
list_update_cgroup_event(struct perf_event *event,
			 struct perf_event_context *ctx, bool add)
{
}

#endif

/*
 * set default to be dependent on timer tick just
 * like original code
 */
#define PERF_CPU_HRTIMER (1000 / HZ)
/*
 * function must be called with interrupts disbled
 */
static enum hrtimer_restart perf_mux_hrtimer_handler(struct hrtimer *hr)
{
	struct perf_cpu_context *cpuctx;
	int rotations = 0;

	WARN_ON(!irqs_disabled());

	cpuctx = container_of(hr, struct perf_cpu_context, hrtimer);
	rotations = perf_rotate_context(cpuctx);

	raw_spin_lock(&cpuctx->hrtimer_lock);
	if (rotations)
		hrtimer_forward_now(hr, cpuctx->hrtimer_interval);
	else
		cpuctx->hrtimer_active = 0;
	raw_spin_unlock(&cpuctx->hrtimer_lock);

	return rotations ? HRTIMER_RESTART : HRTIMER_NORESTART;
}

static void __perf_mux_hrtimer_init(struct perf_cpu_context *cpuctx, int cpu)
{
	struct hrtimer *timer = &cpuctx->hrtimer;
	struct pmu *pmu = cpuctx->ctx.pmu;
	u64 interval;

	/* no multiplexing needed for SW PMU */
	if (pmu->task_ctx_nr == perf_sw_context)
		return;

	/*
 * check default is sane, if not set then force to
 * default interval (1/tick)
 */
	interval = pmu->hrtimer_interval_ms;
	if (interval < 1)
		interval = pmu->hrtimer_interval_ms = PERF_CPU_HRTIMER;

	cpuctx->hrtimer_interval = ns_to_ktime(NSEC_PER_MSEC * interval);

	raw_spin_lock_init(&cpuctx->hrtimer_lock);
	hrtimer_init(timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED);
	timer->function = perf_mux_hrtimer_handler;
}

static int perf_mux_hrtimer_restart(struct perf_cpu_context *cpuctx)
{
	struct hrtimer *timer = &cpuctx->hrtimer;
	struct pmu *pmu = cpuctx->ctx.pmu;
	unsigned long flags;

	/* not for SW PMU */
	if (pmu->task_ctx_nr == perf_sw_context)
		return 0;

	raw_spin_lock_irqsave(&cpuctx->hrtimer_lock, flags);
	if (!cpuctx->hrtimer_active) {
		cpuctx->hrtimer_active = 1;
		hrtimer_forward_now(timer, cpuctx->hrtimer_interval);
		hrtimer_start_expires(timer, HRTIMER_MODE_ABS_PINNED);
	}
	raw_spin_unlock_irqrestore(&cpuctx->hrtimer_lock, flags);

	return 0;
}

void perf_pmu_disable(struct pmu *pmu)
{
	int *count = this_cpu_ptr(pmu->pmu_disable_count);
	if (!(*count)++)
		pmu->pmu_disable(pmu);
}

void perf_pmu_enable(struct pmu *pmu)
{
	int *count = this_cpu_ptr(pmu->pmu_disable_count);
	if (!--(*count))
		pmu->pmu_enable(pmu);
}

static DEFINE_PER_CPU(struct list_head, active_ctx_list);

/*
 * perf_event_ctx_activate(), perf_event_ctx_deactivate(), and
 * perf_event_task_tick() are fully serialized because they're strictly cpu
 * affine and perf_event_ctx{activate,deactivate} are called with IRQs
 * disabled, while perf_event_task_tick is called from IRQ context.
 */
static void perf_event_ctx_activate(struct perf_event_context *ctx)
{
	struct list_head *head = this_cpu_ptr(&active_ctx_list);

	WARN_ON(!irqs_disabled());

	WARN_ON(!list_empty(&ctx->active_ctx_list));

	list_add(&ctx->active_ctx_list, head);
}

static void perf_event_ctx_deactivate(struct perf_event_context *ctx)
{
	WARN_ON(!irqs_disabled());

	WARN_ON(list_empty(&ctx->active_ctx_list));

	list_del_init(&ctx->active_ctx_list);
}

static void get_ctx(struct perf_event_context *ctx)
{
	WARN_ON(!atomic_inc_not_zero(&ctx->refcount));
}

static void free_ctx(struct rcu_head *head)
{
	struct perf_event_context *ctx;

	ctx = container_of(head, struct perf_event_context, rcu_head);
	kfree(ctx->task_ctx_data);
	kfree(ctx);
}

static void put_ctx(struct perf_event_context *ctx)
{
	if (atomic_dec_and_test(&ctx->refcount)) {
		if (ctx->parent_ctx)
			put_ctx(ctx->parent_ctx);
		if (ctx->task && ctx->task != TASK_TOMBSTONE)
			put_task_struct(ctx->task);
		call_rcu(&ctx->rcu_head, free_ctx);
	}
}

/*
 * Because of perf_event::ctx migration in sys_perf_event_open::move_group and
 * perf_pmu_migrate_context() we need some magic.
 *
 * Those places that change perf_event::ctx will hold both
 * perf_event_ctx::mutex of the 'old' and 'new' ctx value.
 *
 * Lock ordering is by mutex address. There are two other sites where
 * perf_event_context::mutex nests and those are:
 *
 * - perf_event_exit_task_context() [ child , 0 ]
 * perf_event_exit_event()
 * put_event() [ parent, 1 ]
 *
 * - perf_event_init_context() [ parent, 0 ]
 * inherit_task_group()
 * inherit_group()
 * inherit_event()
 * perf_event_alloc()
 * perf_init_event()
 * perf_try_init_event() [ child , 1 ]
 *
 * While it appears there is an obvious deadlock here -- the parent and child
 * nesting levels are inverted between the two. This is in fact safe because
 * life-time rules separate them. That is an exiting task cannot fork, and a
 * spawning task cannot (yet) exit.
 *
 * But remember that that these are parent<->child context relations, and
 * migration does not affect children, therefore these two orderings should not
 * interact.
 *
 * The change in perf_event::ctx does not affect children (as claimed above)
 * because the sys_perf_event_open() case will install a new event and break
 * the ctx parent<->child relation, and perf_pmu_migrate_context() is only
 * concerned with cpuctx and that doesn't have children.
 *
 * The places that change perf_event::ctx will issue:
 *
 * perf_remove_from_context();
 * synchronize_rcu();
 * perf_install_in_context();
 *
 * to affect the change. The remove_from_context() + synchronize_rcu() should
 * quiesce the event, after which we can install it in the new location. This
 * means that only external vectors (perf_fops, prctl) can perturb the event
 * while in transit. Therefore all such accessors should also acquire
 * perf_event_context::mutex to serialize against this.
 *
 * However; because event->ctx can change while we're waiting to acquire
 * ctx->mutex we must be careful and use the below perf_event_ctx_lock()
 * function.
 *
 * Lock order:
 * cred_guard_mutex
 * task_struct::perf_event_mutex
 * perf_event_context::mutex
 * perf_event::child_mutex;
 * perf_event_context::lock
 * perf_event::mmap_mutex
 * mmap_sem
 */
static struct perf_event_context *
perf_event_ctx_lock_nested(struct perf_event *event, int nesting)
{
	struct perf_event_context *ctx;

again:
	rcu_read_lock();
	ctx = ACCESS_ONCE(event->ctx);
	if (!atomic_inc_not_zero(&ctx->refcount)) {
		rcu_read_unlock();
		goto again;
	}
	rcu_read_unlock();

	mutex_lock_nested(&ctx->mutex, nesting);
	if (event->ctx != ctx) {
		mutex_unlock(&ctx->mutex);
		put_ctx(ctx);
		goto again;
	}

	return ctx;
}

static inline struct perf_event_context *
perf_event_ctx_lock(struct perf_event *event)
{
	return perf_event_ctx_lock_nested(event, 0);
}

static void perf_event_ctx_unlock(struct perf_event *event,
				  struct perf_event_context *ctx)
{
	mutex_unlock(&ctx->mutex);
	put_ctx(ctx);
}

/*
 * This must be done under the ctx->lock, such as to serialize against
 * context_equiv(), therefore we cannot call put_ctx() since that might end up
 * calling scheduler related locks and ctx->lock nests inside those.
 */
static __must_check struct perf_event_context *
unclone_ctx(struct perf_event_context *ctx)
{
	struct perf_event_context *parent_ctx = ctx->parent_ctx;

	lockdep_assert_held(&ctx->lock);

	if (parent_ctx)
		ctx->parent_ctx = NULL;
	ctx->generation++;

	return parent_ctx;
}

static u32 perf_event_pid(struct perf_event *event, struct task_struct *p)
{
	/*
 * only top level events have the pid namespace they were created in
 */
	if (event->parent)
		event = event->parent;

	return task_tgid_nr_ns(p, event->ns);
}

static u32 perf_event_tid(struct perf_event *event, struct task_struct *p)
{
	/*
 * only top level events have the pid namespace they were created in
 */
	if (event->parent)
		event = event->parent;

	return task_pid_nr_ns(p, event->ns);
}

/*
 * If we inherit events we want to return the parent event id
 * to userspace.
 */
static u64 primary_event_id(struct perf_event *event)
{
	u64 id = event->id;

	if (event->parent)
		id = event->parent->id;

	return id;
}

/*
 * Get the perf_event_context for a task and lock it.
 *
 * This has to cope with with the fact that until it is locked,
 * the context could get moved to another task.
 */
static struct perf_event_context *
perf_lock_task_context(struct task_struct *task, int ctxn, unsigned long *flags)
{
	struct perf_event_context *ctx;

retry:
	/*
 * One of the few rules of preemptible RCU is that one cannot do
 * rcu_read_unlock() while holding a scheduler (or nested) lock when
 * part of the read side critical section was irqs-enabled -- see
 * rcu_read_unlock_special().
 *
 * Since ctx->lock nests under rq->lock we must ensure the entire read
 * side critical section has interrupts disabled.
 */
	local_irq_save(*flags);
	rcu_read_lock();
	ctx = rcu_dereference(task->perf_event_ctxp[ctxn]);
	if (ctx) {
		/*
 * If this context is a clone of another, it might
 * get swapped for another underneath us by
 * perf_event_task_sched_out, though the
 * rcu_read_lock() protects us from any context
 * getting freed. Lock the context and check if it
 * got swapped before we could get the lock, and retry
 * if so. If we locked the right context, then it
 * can't get swapped on us any more.
 */
		raw_spin_lock(&ctx->lock);
		if (ctx != rcu_dereference(task->perf_event_ctxp[ctxn])) {
			raw_spin_unlock(&ctx->lock);
			rcu_read_unlock();
			local_irq_restore(*flags);
			goto retry;
		}

		if (ctx->task == TASK_TOMBSTONE ||
		    !atomic_inc_not_zero(&ctx->refcount)) {
			raw_spin_unlock(&ctx->lock);
			ctx = NULL;
		} else {
			WARN_ON_ONCE(ctx->task != task);
		}
	}
	rcu_read_unlock();
	if (!ctx)
		local_irq_restore(*flags);
	return ctx;
}

/*
 * Get the context for a task and increment its pin_count so it
 * can't get swapped to another task. This also increments its
 * reference count so that the context can't get freed.
 */
static struct perf_event_context *
perf_pin_task_context(struct task_struct *task, int ctxn)
{
	struct perf_event_context *ctx;
	unsigned long flags;

	ctx = perf_lock_task_context(task, ctxn, &flags);
	if (ctx) {
		++ctx->pin_count;
		raw_spin_unlock_irqrestore(&ctx->lock, flags);
	}
	return ctx;
}

static void perf_unpin_context(struct perf_event_context *ctx)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&ctx->lock, flags);
	--ctx->pin_count;
	raw_spin_unlock_irqrestore(&ctx->lock, flags);
}

/*
 * Update the record of the current time in a context.
 */
static void update_context_time(struct perf_event_context *ctx)
{
	u64 now = perf_clock();

	ctx->time += now - ctx->timestamp;
	ctx->timestamp = now;
}

static u64 perf_event_time(struct perf_event *event)
{
	struct perf_event_context *ctx = event->ctx;

	if (is_cgroup_event(event))
		return perf_cgroup_event_time(event);

	return ctx ? ctx->time : 0;
}

/*
 * Update the total_time_enabled and total_time_running fields for a event.
 */
static void update_event_times(struct perf_event *event)
{
	struct perf_event_context *ctx = event->ctx;
	u64 run_end;

	lockdep_assert_held(&ctx->lock);

	if (event->state < PERF_EVENT_STATE_INACTIVE ||
	    event->group_leader->state < PERF_EVENT_STATE_INACTIVE)
		return;

	/*
 * in cgroup mode, time_enabled represents
 * the time the event was enabled AND active
 * tasks were in the monitored cgroup. This is
 * independent of the activity of the context as
 * there may be a mix of cgroup and non-cgroup events.
 *
 * That is why we treat cgroup events differently
 * here.
 */
	if (is_cgroup_event(event))
		run_end = perf_cgroup_event_time(event);
	else if (ctx->is_active)
		run_end = ctx->time;
	else
		run_end = event->tstamp_stopped;

	event->total_time_enabled = run_end - event->tstamp_enabled;

	if (event->state == PERF_EVENT_STATE_INACTIVE)
		run_end = event->tstamp_stopped;
	else
		run_end = perf_event_time(event);

	event->total_time_running = run_end - event->tstamp_running;

}

/*
 * Update total_time_enabled and total_time_running for all events in a group.
 */
static void update_group_times(struct perf_event *leader)
{
	struct perf_event *event;

	update_event_times(leader);
	list_for_each_entry(event, &leader->sibling_list, group_entry)
		update_event_times(event);
}

static enum event_type_t get_event_type(struct perf_event *event)
{
	struct perf_event_context *ctx = event->ctx;
	enum event_type_t event_type;

	lockdep_assert_held(&ctx->lock);

	event_type = event->attr.pinned ? EVENT_PINNED : EVENT_FLEXIBLE;
	if (!ctx->task)
		event_type |= EVENT_CPU;

	return event_type;
}

static struct list_head *
ctx_group_list(struct perf_event *event, struct perf_event_context *ctx)
{
	if (event->attr.pinned)
		return &ctx->pinned_groups;
	else
		return &ctx->flexible_groups;
}

/*
 * Add a event from the lists for its context.
 * Must be called with ctx->mutex and ctx->lock held.
 */
static void
list_add_event(struct perf_event *event, struct perf_event_context *ctx)
{
	lockdep_assert_held(&ctx->lock);

	WARN_ON_ONCE(event->attach_state & PERF_ATTACH_CONTEXT);
	event->attach_state |= PERF_ATTACH_CONTEXT;

	/*
 * If we're a stand alone event or group leader, we go to the context
 * list, group events are kept attached to the group so that
 * perf_group_detach can, at all times, locate all siblings.
 */
	if (event->group_leader == event) {
		struct list_head *list;

		event->group_caps = event->event_caps;

		list = ctx_group_list(event, ctx);
		list_add_tail(&event->group_entry, list);
	}

	list_update_cgroup_event(event, ctx, true);

	list_add_rcu(&event->event_entry, &ctx->event_list);
	ctx->nr_events++;
	if (event->attr.inherit_stat)
		ctx->nr_stat++;

	ctx->generation++;
}

/*
 * Initialize event state based on the perf_event_attr::disabled.
 */
static inline void perf_event__state_init(struct perf_event *event)
{
	event->state = event->attr.disabled ? PERF_EVENT_STATE_OFF :
					      PERF_EVENT_STATE_INACTIVE;
}

static void __perf_event_read_size(struct perf_event *event, int nr_siblings)
{
	int entry = sizeof(u64); /* value */
	int size = 0;
	int nr = 1;

	if (event->attr.read_format & PERF_FORMAT_TOTAL_TIME_ENABLED)
		size += sizeof(u64);

	if (event->attr.read_format & PERF_FORMAT_TOTAL_TIME_RUNNING)
		size += sizeof(u64);

	if (event->attr.read_format & PERF_FORMAT_ID)
		entry += sizeof(u64);

	if (event->attr.read_format & PERF_FORMAT_GROUP) {
		nr += nr_siblings;
		size += sizeof(u64);
	}

	size += entry * nr;
	event->read_size = size;
}

static void __perf_event_header_size(struct perf_event *event, u64 sample_type)
{
	struct perf_sample_data *data;
	u16 size = 0;

	if (sample_type & PERF_SAMPLE_IP)
		size += sizeof(data->ip);

	if (sample_type & PERF_SAMPLE_ADDR)
		size += sizeof(data->addr);

	if (sample_type & PERF_SAMPLE_PERIOD)
		size += sizeof(data->period);

	if (sample_type & PERF_SAMPLE_WEIGHT)
		size += sizeof(data->weight);

	if (sample_type & PERF_SAMPLE_READ)
		size += event->read_size;

	if (sample_type & PERF_SAMPLE_DATA_SRC)
		size += sizeof(data->data_src.val);

	if (sample_type & PERF_SAMPLE_TRANSACTION)
		size += sizeof(data->txn);

	event->header_size = size;
}

/*
 * Called at perf_event creation and when events are attached/detached from a
 * group.
 */
static void perf_event__header_size(struct perf_event *event)
{
	__perf_event_read_size(event,
			       event->group_leader->nr_siblings);
	__perf_event_header_size(event, event->attr.sample_type);
}

static void perf_event__id_header_size(struct perf_event *event)
{
	struct perf_sample_data *data;
	u64 sample_type = event->attr.sample_type;
	u16 size = 0;

	if (sample_type & PERF_SAMPLE_TID)
		size += sizeof(data->tid_entry);

	if (sample_type & PERF_SAMPLE_TIME)
		size += sizeof(data->time);

	if (sample_type & PERF_SAMPLE_IDENTIFIER)
		size += sizeof(data->id);

	if (sample_type & PERF_SAMPLE_ID)
		size += sizeof(data->id);

	if (sample_type & PERF_SAMPLE_STREAM_ID)
		size += sizeof(data->stream_id);

	if (sample_type & PERF_SAMPLE_CPU)
		size += sizeof(data->cpu_entry);

	event->id_header_size = size;
}

static bool perf_event_validate_size(struct perf_event *event)
{
	/*
 * The values computed here will be over-written when we actually
 * attach the event.
 */
	__perf_event_read_size(event, event->group_leader->nr_siblings + 1);
	__perf_event_header_size(event, event->attr.sample_type & ~PERF_SAMPLE_READ);
	perf_event__id_header_size(event);

	/*
 * Sum the lot; should not exceed the 64k limit we have on records.
 * Conservative limit to allow for callchains and other variable fields.
 */
	if (event->read_size + event->header_size +
	    event->id_header_size + sizeof(struct perf_event_header) >= 16*1024)
		return false;

	return true;
}

static void perf_group_attach(struct perf_event *event)
{
	struct perf_event *group_leader = event->group_leader, *pos;

	lockdep_assert_held(&event->ctx->lock);

	/*
 * We can have double attach due to group movement in perf_event_open.
 */
	if (event->attach_state & PERF_ATTACH_GROUP)
		return;

	event->attach_state |= PERF_ATTACH_GROUP;

	if (group_leader == event)
		return;

	WARN_ON_ONCE(group_leader->ctx != event->ctx);

	group_leader->group_caps &= event->event_caps;

	list_add_tail(&event->group_entry, &group_leader->sibling_list);
	group_leader->nr_siblings++;

	perf_event__header_size(group_leader);

	list_for_each_entry(pos, &group_leader->sibling_list, group_entry)
		perf_event__header_size(pos);
}

/*
 * Remove a event from the lists for its context.
 * Must be called with ctx->mutex and ctx->lock held.
 */
static void
list_del_event(struct perf_event *event, struct perf_event_context *ctx)
{
	WARN_ON_ONCE(event->ctx != ctx);
	lockdep_assert_held(&ctx->lock);

	/*
 * We can have double detach due to exit/hot-unplug + close.
 */
	if (!(event->attach_state & PERF_ATTACH_CONTEXT))
		return;

	event->attach_state &= ~PERF_ATTACH_CONTEXT;

	list_update_cgroup_event(event, ctx, false);

	ctx->nr_events--;
	if (event->attr.inherit_stat)
		ctx->nr_stat--;

	list_del_rcu(&event->event_entry);

	if (event->group_leader == event)
		list_del_init(&event->group_entry);

	update_group_times(event);

	/*
 * If event was in error state, then keep it
 * that way, otherwise bogus counts will be
 * returned on read(). The only way to get out
 * of error state is by explicit re-enabling
 * of the event
 */
	if (event->state > PERF_EVENT_STATE_OFF)
		event->state = PERF_EVENT_STATE_OFF;

	ctx->generation++;
}

static void perf_group_detach(struct perf_event *event)
{
	struct perf_event *sibling, *tmp;
	struct list_head *list = NULL;

	lockdep_assert_held(&event->ctx->lock);

	/*
 * We can have double detach due to exit/hot-unplug + close.
 */
	if (!(event->attach_state & PERF_ATTACH_GROUP))
		return;

	event->attach_state &= ~PERF_ATTACH_GROUP;

	/*
 * If this is a sibling, remove it from its group.
 */
	if (event->group_leader != event) {
		list_del_init(&event->group_entry);
		event->group_leader->nr_siblings--;
		goto out;
	}

	if (!list_empty(&event->group_entry))
		list = &event->group_entry;

	/*
 * If this was a group event with sibling events then
 * upgrade the siblings to singleton events by adding them
 * to whatever list we are on.
 */
	list_for_each_entry_safe(sibling, tmp, &event->sibling_list, group_entry) {
		if (list)
			list_move_tail(&sibling->group_entry, list);
		sibling->group_leader = sibling;

		/* Inherit group flags from the previous leader */
		sibling->group_caps = event->group_caps;

		WARN_ON_ONCE(sibling->ctx != event->ctx);
	}

out:
	perf_event__header_size(event->group_leader);

	list_for_each_entry(tmp, &event->group_leader->sibling_list, group_entry)
		perf_event__header_size(tmp);
}

static bool is_orphaned_event(struct perf_event *event)
{
	return event->state == PERF_EVENT_STATE_DEAD;
}

static inline int __pmu_filter_match(struct perf_event *event)
{
	struct pmu *pmu = event->pmu;
	return pmu->filter_match ? pmu->filter_match(event) : 1;
}

/*
 * Check whether we should attempt to schedule an event group based on
 * PMU-specific filtering. An event group can consist of HW and SW events,
 * potentially with a SW leader, so we must check all the filters, to
 * determine whether a group is schedulable:
 */
static inline int pmu_filter_match(struct perf_event *event)
{
	struct perf_event *child;

	if (!__pmu_filter_match(event))
		return 0;

	list_for_each_entry(child, &event->sibling_list, group_entry) {
		if (!__pmu_filter_match(child))
			return 0;
	}

	return 1;
}

static inline int
event_filter_match(struct perf_event *event)
{
	return (event->cpu == -1 || event->cpu == smp_processor_id()) &&
	       perf_cgroup_match(event) && pmu_filter_match(event);
}

static void
event_sched_out(struct perf_event *event,
		  struct perf_cpu_context *cpuctx,
		  struct perf_event_context *ctx)
{
	u64 tstamp = perf_event_time(event);
	u64 delta;

	WARN_ON_ONCE(event->ctx != ctx);
	lockdep_assert_held(&ctx->lock);

	/*
 * An event which could not be activated because of
 * filter mismatch still needs to have its timings
 * maintained, otherwise bogus information is return
 * via read() for time_enabled, time_running:
 */
	if (event->state == PERF_EVENT_STATE_INACTIVE &&
	    !event_filter_match(event)) {
		delta = tstamp - event->tstamp_stopped;
		event->tstamp_running += delta;
		event->tstamp_stopped = tstamp;
	}

	if (event->state != PERF_EVENT_STATE_ACTIVE)
		return;

	perf_pmu_disable(event->pmu);

	event->tstamp_stopped = tstamp;
	event->pmu->del(event, 0);
	event->oncpu = -1;
	event->state = PERF_EVENT_STATE_INACTIVE;
	if (event->pending_disable) {
		event->pending_disable = 0;
		event->state = PERF_EVENT_STATE_OFF;
	}

	if (!is_software_event(event))
		cpuctx->active_oncpu--;
	if (!--ctx->nr_active)
		perf_event_ctx_deactivate(ctx);
	if (event->attr.freq && event->attr.sample_freq)
		ctx->nr_freq--;
	if (event->attr.exclusive || !cpuctx->active_oncpu)
		cpuctx->exclusive = 0;

	perf_pmu_enable(event->pmu);
}

static void
group_sched_out(struct perf_event *group_event,
		struct perf_cpu_context *cpuctx,
		struct perf_event_context *ctx)
{
	struct perf_event *event;
	int state = group_event->state;

	perf_pmu_disable(ctx->pmu);

	event_sched_out(group_event, cpuctx, ctx);

	/*
 * Schedule out siblings (if any):
 */
	list_for_each_entry(event, &group_event->sibling_list, group_entry)
		event_sched_out(event, cpuctx, ctx);

	perf_pmu_enable(ctx->pmu);

	if (state == PERF_EVENT_STATE_ACTIVE && group_event->attr.exclusive)
		cpuctx->exclusive = 0;
}

#define DETACH_GROUP 0x01UL

/*
 * Cross CPU call to remove a performance event
 *
 * We disable the event on the hardware level first. After that we
 * remove it from the context list.
 */
static void
__perf_remove_from_context(struct perf_event *event,
			   struct perf_cpu_context *cpuctx,
			   struct perf_event_context *ctx,
			   void *info)
{
	unsigned long flags = (unsigned long)info;

	event_sched_out(event, cpuctx, ctx);
	if (flags & DETACH_GROUP)
		perf_group_detach(event);
	list_del_event(event, ctx);

	if (!ctx->nr_events && ctx->is_active) {
		ctx->is_active = 0;
		if (ctx->task) {
			WARN_ON_ONCE(cpuctx->task_ctx != ctx);
			cpuctx->task_ctx = NULL;
		}
	}
}

/*
 * Remove the event from a task's (or a CPU's) list of events.
 *
 * If event->ctx is a cloned context, callers must make sure that
 * every task struct that event->ctx->task could possibly point to
 * remains valid. This is OK when called from perf_release since
 * that only calls us on the top-level context, which can't be a clone.
 * When called from perf_event_exit_task, it's OK because the
 * context has been detached from its task.
 */
static void perf_remove_from_context(struct perf_event *event, unsigned long flags)
{
	struct perf_event_context *ctx = event->ctx;

	lockdep_assert_held(&ctx->mutex);

	event_function_call(event, __perf_remove_from_context, (void *)flags);

	/*
 * The above event_function_call() can NO-OP when it hits
 * TASK_TOMBSTONE. In that case we must already have been detached
 * from the context (by perf_event_exit_event()) but the grouping
 * might still be in-tact.
 */
	WARN_ON_ONCE(event->attach_state & PERF_ATTACH_CONTEXT);
	if ((flags & DETACH_GROUP) &&
	    (event->attach_state & PERF_ATTACH_GROUP)) {
		/*
 * Since in that case we cannot possibly be scheduled, simply
 * detach now.
 */
		raw_spin_lock_irq(&ctx->lock);
		perf_group_detach(event);
		raw_spin_unlock_irq(&ctx->lock);
	}
}

/*
 * Cross CPU call to disable a performance event
 */
static void __perf_event_disable(struct perf_event *event,
				 struct perf_cpu_context *cpuctx,
				 struct perf_event_context *ctx,
				 void *info)
{
	if (event->state < PERF_EVENT_STATE_INACTIVE)
		return;

	update_context_time(ctx);
	update_cgrp_time_from_event(event);
	update_group_times(event);
	if (event == event->group_leader)
		group_sched_out(event, cpuctx, ctx);
	else
		event_sched_out(event, cpuctx, ctx);
	event->state = PERF_EVENT_STATE_OFF;
}

/*
 * Disable a event.
 *
 * If event->ctx is a cloned context, callers must make sure that
 * every task struct that event->ctx->task could possibly point to
 * remains valid. This condition is satisifed when called through
 * perf_event_for_each_child or perf_event_for_each because they
 * hold the top-level event's child_mutex, so any descendant that
 * goes to exit will block in perf_event_exit_event().
 *
 * When called from perf_pending_event it's OK because event->ctx
 * is the current context on this CPU and preemption is disabled,
 * hence we can't get into perf_event_task_sched_out for this context.
 */
static void _perf_event_disable(struct perf_event *event)
{
	struct perf_event_context *ctx = event->ctx;

	raw_spin_lock_irq(&ctx->lock);
	if (event->state <= PERF_EVENT_STATE_OFF) {
		raw_spin_unlock_irq(&ctx->lock);
		return;
	}
	raw_spin_unlock_irq(&ctx->lock);

	event_function_call(event, __perf_event_disable, NULL);
}

void perf_event_disable_local(struct perf_event *event)
{
	event_function_local(event, __perf_event_disable, NULL);
}

/*
 * Strictly speaking kernel users cannot create groups and therefore this
 * interface does not need the perf_event_ctx_lock() magic.
 */
void perf_event_disable(struct perf_event *event)
{
	struct perf_event_context *ctx;

	ctx = perf_event_ctx_lock(event);
	_perf_event_disable(event);
	perf_event_ctx_unlock(event, ctx);
}
EXPORT_SYMBOL_GPL(perf_event_disable);

void perf_event_disable_inatomic(struct perf_event *event)
{
	event->pending_disable = 1;
	irq_work_queue(&event->pending);
}

static void perf_set_shadow_time(struct perf_event *event,
				 struct perf_event_context *ctx,
				 u64 tstamp)
{
	/*
 * use the correct time source for the time snapshot
 *
 * We could get by without this by leveraging the
 * fact that to get to this function, the caller
 * has most likely already called update_context_time()
 * and update_cgrp_time_xx() and thus both timestamp
 * are identical (or very close). Given that tstamp is,
 * already adjusted for cgroup, we could say that:
 * tstamp - ctx->timestamp
 * is equivalent to
 * tstamp - cgrp->timestamp.
 *
 * Then, in perf_output_read(), the calculation would
 * work with no changes because:
 * - event is guaranteed scheduled in
 * - no scheduled out in between
 * - thus the timestamp would be the same
 *
 * But this is a bit hairy.
 *
 * So instead, we have an explicit cgroup call to remain
 * within the time time source all along. We believe it
 * is cleaner and simpler to understand.
 */
	if (is_cgroup_event(event))
		perf_cgroup_set_shadow_time(event, tstamp);
	else
		event->shadow_ctx_time = tstamp - ctx->timestamp;
}

#define MAX_INTERRUPTS (~0ULL)

static void perf_log_throttle(struct perf_event *event, int enable);
static void perf_log_itrace_start(struct perf_event *event);

static int
event_sched_in(struct perf_event *event,
		 struct perf_cpu_context *cpuctx,
		 struct perf_event_context *ctx)
{
	u64 tstamp = perf_event_time(event);
	int ret = 0;

	lockdep_assert_held(&ctx->lock);

	if (event->state <= PERF_EVENT_STATE_OFF)
		return 0;

	WRITE_ONCE(event->oncpu, smp_processor_id());
	/*
 * Order event::oncpu write to happen before the ACTIVE state
 * is visible.
 */
	smp_wmb();
	WRITE_ONCE(event->state, PERF_EVENT_STATE_ACTIVE);

	/*
 * Unthrottle events, since we scheduled we might have missed several
 * ticks already, also for a heavily scheduling task there is little
 * guarantee it'll get a tick in a timely manner.
 */
	if (unlikely(event->hw.interrupts == MAX_INTERRUPTS)) {
		perf_log_throttle(event, 1);
		event->hw.interrupts = 0;
	}

	/*
 * The new state must be visible before we turn it on in the hardware:
 */
	smp_wmb();

	perf_pmu_disable(event->pmu);

	perf_set_shadow_time(event, ctx, tstamp);

	perf_log_itrace_start(event);

	if (event->pmu->add(event, PERF_EF_START)) {
		event->state = PERF_EVENT_STATE_INACTIVE;
		event->oncpu = -1;
		ret = -EAGAIN;
		goto out;
	}

	event->tstamp_running += tstamp - event->tstamp_stopped;

	if (!is_software_event(event))
		cpuctx->active_oncpu++;
	if (!ctx->nr_active++)
		perf_event_ctx_activate(ctx);
	if (event->attr.freq && event->attr.sample_freq)
		ctx->nr_freq++;

	if (event->attr.exclusive)
		cpuctx->exclusive = 1;

out:
	perf_pmu_enable(event->pmu);

	return ret;
}

static int
group_sched_in(struct perf_event *group_event,
	       struct perf_cpu_context *cpuctx,
	       struct perf_event_context *ctx)
{
	struct perf_event *event, *partial_group = NULL;
	struct pmu *pmu = ctx->pmu;
	u64 now = ctx->time;
	bool simulate = false;

	if (group_event->state == PERF_EVENT_STATE_OFF)
		return 0;

	pmu->start_txn(pmu, PERF_PMU_TXN_ADD);

	if (event_sched_in(group_event, cpuctx, ctx)) {
		pmu->cancel_txn(pmu);
		perf_mux_hrtimer_restart(cpuctx);
		return -EAGAIN;
	}

	/*
 * Schedule in siblings as one group (if any):
 */
	list_for_each_entry(event, &group_event->sibling_list, group_entry) {
		if (event_sched_in(event, cpuctx, ctx)) {
			partial_group = event;
			goto group_error;
		}
	}

	if (!pmu->commit_txn(pmu))
		return 0;

group_error:
	/*
 * Groups can be scheduled in as one unit only, so undo any
 * partial group before returning:
 * The events up to the failed event are scheduled out normally,
 * tstamp_stopped will be updated.
 *
 * The failed events and the remaining siblings need to have
 * their timings updated as if they had gone thru event_sched_in()
 * and event_sched_out(). This is required to get consistent timings
 * across the group. This also takes care of the case where the group
 * could never be scheduled by ensuring tstamp_stopped is set to mark
 * the time the event was actually stopped, such that time delta
 * calculation in update_event_times() is correct.
 */
	list_for_each_entry(event, &group_event->sibling_list, group_entry) {
		if (event == partial_group)
			simulate = true;

		if (simulate) {
			event->tstamp_running += now - event->tstamp_stopped;
			event->tstamp_stopped = now;
		} else {
			event_sched_out(event, cpuctx, ctx);
		}
	}
	event_sched_out(group_event, cpuctx, ctx);

	pmu->cancel_txn(pmu);

	perf_mux_hrtimer_restart(cpuctx);

	return -EAGAIN;
}

/*
 * Work out whether we can put this event group on the CPU now.
 */
static int group_can_go_on(struct perf_event *event,
			   struct perf_cpu_context *cpuctx,
			   int can_add_hw)
{
	/*
 * Groups consisting entirely of software events can always go on.
 */
	if (event->group_caps & PERF_EV_CAP_SOFTWARE)
		return 1;
	/*
 * If an exclusive group is already on, no other hardware
 * events can go on.
 */
	if (cpuctx->exclusive)
		return 0;
	/*
 * If this group is exclusive and there are already
 * events on the CPU, it can't go on.
 */
	if (event->attr.exclusive && cpuctx->active_oncpu)
		return 0;
	/*
 * Otherwise, try to add it if all previous groups were able
 * to go on.
 */
	return can_add_hw;
}

static void add_event_to_ctx(struct perf_event *event,
			       struct perf_event_context *ctx)
{
	u64 tstamp = perf_event_time(event);

	list_add_event(event, ctx);
	perf_group_attach(event);
	event->tstamp_enabled = tstamp;
	event->tstamp_running = tstamp;
	event->tstamp_stopped = tstamp;
}

static void ctx_sched_out(struct perf_event_context *ctx,
			  struct perf_cpu_context *cpuctx,
			  enum event_type_t event_type);
static void
ctx_sched_in(struct perf_event_context *ctx,
	     struct perf_cpu_context *cpuctx,
	     enum event_type_t event_type,
	     struct task_struct *task);

static void task_ctx_sched_out(struct perf_cpu_context *cpuctx,
			       struct perf_event_context *ctx,
			       enum event_type_t event_type)
{
	if (!cpuctx->task_ctx)
		return;

	if (WARN_ON_ONCE(ctx != cpuctx->task_ctx))
		return;

	ctx_sched_out(ctx, cpuctx, event_type);
}

static void perf_event_sched_in(struct perf_cpu_context *cpuctx,
				struct perf_event_context *ctx,
				struct task_struct *task)
{
	cpu_ctx_sched_in(cpuctx, EVENT_PINNED, task);
	if (ctx)
		ctx_sched_in(ctx, cpuctx, EVENT_PINNED, task);
	cpu_ctx_sched_in(cpuctx, EVENT_FLEXIBLE, task);
	if (ctx)
		ctx_sched_in(ctx, cpuctx, EVENT_FLEXIBLE, task);
}

/*
 * We want to maintain the following priority of scheduling:
 * - CPU pinned (EVENT_CPU | EVENT_PINNED)
 * - task pinned (EVENT_PINNED)
 * - CPU flexible (EVENT_CPU | EVENT_FLEXIBLE)
 * - task flexible (EVENT_FLEXIBLE).
 *
 * In order to avoid unscheduling and scheduling back in everything every
 * time an event is added, only do it for the groups of equal priority and
 * below.
 *
 * This can be called after a batch operation on task events, in which case
 * event_type is a bit mask of the types of events involved. For CPU events,
 * event_type is only either EVENT_PINNED or EVENT_FLEXIBLE.
 */
static void ctx_resched(struct perf_cpu_context *cpuctx,
			struct perf_event_context *task_ctx,
			enum event_type_t event_type)
{
	enum event_type_t ctx_event_type = event_type & EVENT_ALL;
	bool cpu_event = !!(event_type & EVENT_CPU);

	/*
 * If pinned groups are involved, flexible groups also need to be
 * scheduled out.
 */
	if (event_type & EVENT_PINNED)
		event_type |= EVENT_FLEXIBLE;

	perf_pmu_disable(cpuctx->ctx.pmu);
	if (task_ctx)
		task_ctx_sched_out(cpuctx, task_ctx, event_type);

	/*
 * Decide which cpu ctx groups to schedule out based on the types
 * of events that caused rescheduling:
 * - EVENT_CPU: schedule out corresponding groups;
 * - EVENT_PINNED task events: schedule out EVENT_FLEXIBLE groups;
 * - otherwise, do nothing more.
 */
	if (cpu_event)
		cpu_ctx_sched_out(cpuctx, ctx_event_type);
	else if (ctx_event_type & EVENT_PINNED)
		cpu_ctx_sched_out(cpuctx, EVENT_FLEXIBLE);

	perf_event_sched_in(cpuctx, task_ctx, current);
	perf_pmu_enable(cpuctx->ctx.pmu);
}

/*
 * Cross CPU call to install and enable a performance event
 *
 * Very similar to remote_function() + event_function() but cannot assume that
 * things like ctx->is_active and cpuctx->task_ctx are set.
 */
static int  __perf_install_in_context(void *info)
{
	struct perf_event *event = info;
	struct perf_event_context *ctx = event->ctx;
	struct perf_cpu_context *cpuctx = __get_cpu_context(ctx);
	struct perf_event_context *task_ctx = cpuctx->task_ctx;
	bool reprogram = true;
	int ret = 0;

	raw_spin_lock(&cpuctx->ctx.lock);
	if (ctx->task) {
		raw_spin_lock(&ctx->lock);
		task_ctx = ctx;

		reprogram = (ctx->task == current);

		/*
 * If the task is running, it must be running on this CPU,
 * otherwise we cannot reprogram things.
 *
 * If its not running, we don't care, ctx->lock will
 * serialize against it becoming runnable.
 */
		if (task_curr(ctx->task) && !reprogram) {
			ret = -ESRCH;
			goto unlock;
		}

		WARN_ON_ONCE(reprogram && cpuctx->task_ctx && cpuctx->task_ctx != ctx);
	} else if (task_ctx) {
		raw_spin_lock(&task_ctx->lock);
	}

	if (reprogram) {
		ctx_sched_out(ctx, cpuctx, EVENT_TIME);
		add_event_to_ctx(event, ctx);
		ctx_resched(cpuctx, task_ctx, get_event_type(event));
	} else {
		add_event_to_ctx(event, ctx);
	}

unlock:
	perf_ctx_unlock(cpuctx, task_ctx);

	return ret;
}

/*
 * Attach a performance event to a context.
 *
 * Very similar to event_function_call, see comment there.
 */
static void
perf_install_in_context(struct perf_event_context *ctx,
			struct perf_event *event,
			int cpu)
{
	struct task_struct *task = READ_ONCE(ctx->task);

	lockdep_assert_held(&ctx->mutex);

	if (event->cpu != -1)
		event->cpu = cpu;

	/*
 * Ensures that if we can observe event->ctx, both the event and ctx
 * will be 'complete'. See perf_iterate_sb_cpu().
 */
	smp_store_release(&event->ctx, ctx);

	if (!task) {
		cpu_function_call(cpu, __perf_install_in_context, event);
		return;
	}

	/*
 * Should not happen, we validate the ctx is still alive before calling.
 */
	if (WARN_ON_ONCE(task == TASK_TOMBSTONE))
		return;

	/*
 * Installing events is tricky because we cannot rely on ctx->is_active
 * to be set in case this is the nr_events 0 -> 1 transition.
 *
 * Instead we use task_curr(), which tells us if the task is running.
 * However, since we use task_curr() outside of rq::lock, we can race
 * against the actual state. This means the result can be wrong.
 *
 * If we get a false positive, we retry, this is harmless.
 *
 * If we get a false negative, things are complicated. If we are after
 * perf_event_context_sched_in() ctx::lock will serialize us, and the
 * value must be correct. If we're before, it doesn't matter since
 * perf_event_context_sched_in() will program the counter.
 *
 * However, this hinges on the remote context switch having observed
 * our task->perf_event_ctxp[] store, such that it will in fact take
 * ctx::lock in perf_event_context_sched_in().
 *
 * We do this by task_function_call(), if the IPI fails to hit the task
 * we know any future context switch of task must see the
 * perf_event_ctpx[] store.
 */

	/*
 * This smp_mb() orders the task->perf_event_ctxp[] store with the
 * task_cpu() load, such that if the IPI then does not find the task
 * running, a future context switch of that task must observe the
 * store.
 */
	smp_mb();
again:
	if (!task_function_call(task, __perf_install_in_context, event))
		return;

	raw_spin_lock_irq(&ctx->lock);
	task = ctx->task;
	if (WARN_ON_ONCE(task == TASK_TOMBSTONE)) {
		/*
 * Cannot happen because we already checked above (which also
 * cannot happen), and we hold ctx->mutex, which serializes us
 * against perf_event_exit_task_context().
 */
		raw_spin_unlock_irq(&ctx->lock);
		return;
	}
	/*
 * If the task is not running, ctx->lock will avoid it becoming so,
 * thus we can safely install the event.
 */
	if (task_curr(task)) {
		raw_spin_unlock_irq(&ctx->lock);
		goto again;
	}
	add_event_to_ctx(event, ctx);
	raw_spin_unlock_irq(&ctx->lock);
}

/*
 * Put a event into inactive state and update time fields.
 * Enabling the leader of a group effectively enables all
 * the group members that aren't explicitly disabled, so we
 * have to update their ->tstamp_enabled also.
 * Note: this works for group members as well as group leaders
 * since the non-leader members' sibling_lists will be empty.
 */
static void __perf_event_mark_enabled(struct perf_event *event)
{
	struct perf_event *sub;
	u64 tstamp = perf_event_time(event);

	event->state = PERF_EVENT_STATE_INACTIVE;
	event->tstamp_enabled = tstamp - event->total_time_enabled;
	list_for_each_entry(sub, &event->sibling_list, group_entry) {
		if (sub->state >= PERF_EVENT_STATE_INACTIVE)
			sub->tstamp_enabled = tstamp - sub->total_time_enabled;
	}
}

/*
 * Cross CPU call to enable a performance event
 */
static void __perf_event_enable(struct perf_event *event,
				struct perf_cpu_context *cpuctx,
				struct perf_event_context *ctx,
				void *info)
{
	struct perf_event *leader = event->group_leader;
	struct perf_event_context *task_ctx;

	if (event->state >= PERF_EVENT_STATE_INACTIVE ||
	    event->state <= PERF_EVENT_STATE_ERROR)
		return;

	if (ctx->is_active)
		ctx_sched_out(ctx, cpuctx, EVENT_TIME);

	__perf_event_mark_enabled(event);

	if (!ctx->is_active)
		return;

	if (!event_filter_match(event)) {
		if (is_cgroup_event(event))
			perf_cgroup_defer_enabled(event);
		ctx_sched_in(ctx, cpuctx, EVENT_TIME, current);
		return;
	}

	/*
 * If the event is in a group and isn't the group leader,
 * then don't put it on unless the group is on.
 */
	if (leader != event && leader->state != PERF_EVENT_STATE_ACTIVE) {
		ctx_sched_in(ctx, cpuctx, EVENT_TIME, current);
		return;
	}

	task_ctx = cpuctx->task_ctx;
	if (ctx->task)
		WARN_ON_ONCE(task_ctx != ctx);

	ctx_resched(cpuctx, task_ctx, get_event_type(event));
}

/*
 * Enable a event.
 *
 * If event->ctx is a cloned context, callers must make sure that
 * every task struct that event->ctx->task could possibly point to
 * remains valid. This condition is satisfied when called through
 * perf_event_for_each_child or perf_event_for_each as described
 * for perf_event_disable.
 */
static void _perf_event_enable(struct perf_event *event)
{
	struct perf_event_context *ctx = event->ctx;

	raw_spin_lock_irq(&ctx->lock);
	if (event->state >= PERF_EVENT_STATE_INACTIVE ||
	    event->state <  PERF_EVENT_STATE_ERROR) {
		raw_spin_unlock_irq(&ctx->lock);
		return;
	}

	/*
 * If the event is in error state, clear that first.
 *
 * That way, if we see the event in error state below, we know that it
 * has gone back into error state, as distinct from the task having
 * been scheduled away before the cross-call arrived.
 */
	if (event->state == PERF_EVENT_STATE_ERROR)
		event->state = PERF_EVENT_STATE_OFF;
	raw_spin_unlock_irq(&ctx->lock);

	event_function_call(event, __perf_event_enable, NULL);
}

/*
 * See perf_event_disable();
 */
void perf_event_enable(struct perf_event *event)
{
	struct perf_event_context *ctx;

	ctx = perf_event_ctx_lock(event);
	_perf_event_enable(event);
	perf_event_ctx_unlock(event, ctx);
}
EXPORT_SYMBOL_GPL(perf_event_enable);

struct stop_event_data {
	struct perf_event	*event;
	unsigned int		restart;
};

static int __perf_event_stop(void *info)
{
	struct stop_event_data *sd = info;
	struct perf_event *event = sd->event;

	/* if it's already INACTIVE, do nothing */
	if (READ_ONCE(event->state) != PERF_EVENT_STATE_ACTIVE)
		return 0;

	/* matches smp_wmb() in event_sched_in() */
	smp_rmb();

	/*
 * There is a window with interrupts enabled before we get here,
 * so we need to check again lest we try to stop another CPU's event.
 */
	if (READ_ONCE(event->oncpu) != smp_processor_id())
		return -EAGAIN;

	event->pmu->stop(event, PERF_EF_UPDATE);

	/*
 * May race with the actual stop (through perf_pmu_output_stop()),
 * but it is only used for events with AUX ring buffer, and such
 * events will refuse to restart because of rb::aux_mmap_count==0,
 * see comments in perf_aux_output_begin().
 *
 * Since this is happening on a event-local CPU, no trace is lost
 * while restarting.
 */
	if (sd->restart)
		event->pmu->start(event, 0);

	return 0;
}

static int perf_event_stop(struct perf_event *event, int restart)
{
	struct stop_event_data sd = {
		.event		= event,
		.restart	= restart,
	};
	int ret = 0;

	do {
		if (READ_ONCE(event->state) != PERF_EVENT_STATE_ACTIVE)
			return 0;

		/* matches smp_wmb() in event_sched_in() */
		smp_rmb();

		/*
 * We only want to restart ACTIVE events, so if the event goes
 * inactive here (event->oncpu==-1), there's nothing more to do;
 * fall through with ret==-ENXIO.
 */
		ret = cpu_function_call(READ_ONCE(event->oncpu),
					__perf_event_stop, &sd);
	} while (ret == -EAGAIN);

	return ret;
}

/*
 * In order to contain the amount of racy and tricky in the address filter
 * configuration management, it is a two part process:
 *
 * (p1) when userspace mappings change as a result of (1) or (2) or (3) below,
 * we update the addresses of corresponding vmas in
 * event::addr_filters_offs array and bump the event::addr_filters_gen;
 * (p2) when an event is scheduled in (pmu::add), it calls
 * perf_event_addr_filters_sync() which calls pmu::addr_filters_sync()
 * if the generation has changed since the previous call.
 *
 * If (p1) happens while the event is active, we restart it to force (p2).
 *
 * (1) perf_addr_filters_apply(): adjusting filters' offsets based on
 * pre-existing mappings, called once when new filters arrive via SET_FILTER
 * ioctl;
 * (2) perf_addr_filters_adjust(): adjusting filters' offsets based on newly
 * registered mapping, called for every new mmap(), with mm::mmap_sem down
 * for reading;
 * (3) perf_event_addr_filters_exec(): clearing filters' offsets in the process
 * of exec.
 */
void perf_event_addr_filters_sync(struct perf_event *event)
{
	struct perf_addr_filters_head *ifh = perf_event_addr_filters(event);

	if (!has_addr_filter(event))
		return;

	raw_spin_lock(&ifh->lock);
	if (event->addr_filters_gen != event->hw.addr_filters_gen) {
		event->pmu->addr_filters_sync(event);
		event->hw.addr_filters_gen = event->addr_filters_gen;
	}
	raw_spin_unlock(&ifh->lock);
}
EXPORT_SYMBOL_GPL(perf_event_addr_filters_sync);

static int _perf_event_refresh(struct perf_event *event, int refresh)
{
	/*
 * not supported on inherited events
 */
	if (event->attr.inherit || !is_sampling_event(event))
		return -EINVAL;

	atomic_add(refresh, &event->event_limit);
	_perf_event_enable(event);

	return 0;
}

/*
 * See perf_event_disable()
 */
int perf_event_refresh(struct perf_event *event, int refresh)
{
	struct perf_event_context *ctx;
	int ret;

	ctx = perf_event_ctx_lock(event);
	ret = _perf_event_refresh(event, refresh);
	perf_event_ctx_unlock(event, ctx);

	return ret;
}
EXPORT_SYMBOL_GPL(perf_event_refresh);

static void ctx_sched_out(struct perf_event_context *ctx,
			  struct perf_cpu_context *cpuctx,
			  enum event_type_t event_type)
{
	int is_active = ctx->is_active;
	struct perf_event *event;

	lockdep_assert_held(&ctx->lock);

	if (likely(!ctx->nr_events)) {
		/*
 * See __perf_remove_from_context().
 */
		WARN_ON_ONCE(ctx->is_active);
		if (ctx->task)
			WARN_ON_ONCE(cpuctx->task_ctx);
		return;
	}

	ctx->is_active &= ~event_type;
	if (!(ctx->is_active & EVENT_ALL))
		ctx->is_active = 0;

	if (ctx->task) {
		WARN_ON_ONCE(cpuctx->task_ctx != ctx);
		if (!ctx->is_active)
			cpuctx->task_ctx = NULL;
	}

	/*
 * Always update time if it was set; not only when it changes.
 * Otherwise we can 'forget' to update time for any but the last
 * context we sched out. For example:
 *
 * ctx_sched_out(.event_type = EVENT_FLEXIBLE)
 * ctx_sched_out(.event_type = EVENT_PINNED)
 *
 * would only update time for the pinned events.
 */
	if (is_active & EVENT_TIME) {
		/* update (and stop) ctx time */
		update_context_time(ctx);
		update_cgrp_time_from_cpuctx(cpuctx);
	}

	is_active ^= ctx->is_active; /* changed bits */

	if (!ctx->nr_active || !(is_active & EVENT_ALL))
		return;

	perf_pmu_disable(ctx->pmu);
	if (is_active & EVENT_PINNED) {
		list_for_each_entry(event, &ctx->pinned_groups, group_entry)
			group_sched_out(event, cpuctx, ctx);
	}

	if (is_active & EVENT_FLEXIBLE) {
		list_for_each_entry(event, &ctx->flexible_groups, group_entry)
			group_sched_out(event, cpuctx, ctx);
	}
	perf_pmu_enable(ctx->pmu);
}

/*
 * Test whether two contexts are equivalent, i.e. whether they have both been
 * cloned from the same version of the same context.
 *
 * Equivalence is measured using a generation number in the context that is
 * incremented on each modification to it; see unclone_ctx(), list_add_event()
 * and list_del_event().
 */
static int context_equiv(struct perf_event_context *ctx1,
			 struct perf_event_context *ctx2)
{
	lockdep_assert_held(&ctx1->lock);
	lockdep_assert_held(&ctx2->lock);

	/* Pinning disables the swap optimization */
	if (ctx1->pin_count || ctx2->pin_count)
		return 0;

	/* If ctx1 is the parent of ctx2 */
	if (ctx1 == ctx2->parent_ctx && ctx1->generation == ctx2->parent_gen)
		return 1;

	/* If ctx2 is the parent of ctx1 */
	if (ctx1->parent_ctx == ctx2 && ctx1->parent_gen == ctx2->generation)
		return 1;

	/*
 * If ctx1 and ctx2 have the same parent; we flatten the parent
 * hierarchy, see perf_event_init_context().
 */
	if (ctx1->parent_ctx && ctx1->parent_ctx == ctx2->parent_ctx &&
			ctx1->parent_gen == ctx2->parent_gen)
		return 1;

	/* Unmatched */
	return 0;
}

static void __perf_event_sync_stat(struct perf_event *event,
				     struct perf_event *next_event)
{
	u64 value;

	if (!event->attr.inherit_stat)
		return;

	/*
 * Update the event value, we cannot use perf_event_read()
 * because we're in the middle of a context switch and have IRQs
 * disabled, which upsets smp_call_function_single(), however
 * we know the event must be on the current CPU, therefore we
 * don't need to use it.
 */
	switch (event->state) {
	case PERF_EVENT_STATE_ACTIVE:
		event->pmu->read(event);
		/* fall-through */

	case PERF_EVENT_STATE_INACTIVE:
		update_event_times(event);
		break;

	default:
		break;
	}

	/*
 * In order to keep per-task stats reliable we need to flip the event
 * values when we flip the contexts.
 */
	value = local64_read(&next_event->count);
	value = local64_xchg(&event->count, value);
	local64_set(&next_event->count, value);

	swap(event->total_time_enabled, next_event->total_time_enabled);
	swap(event->total_time_running, next_event->total_time_running);

	/*
 * Since we swizzled the values, update the user visible data too.
 */
	perf_event_update_userpage(event);
	perf_event_update_userpage(next_event);
}

static void perf_event_sync_stat(struct perf_event_context *ctx,
				   struct perf_event_context *next_ctx)
{
	struct perf_event *event, *next_event;

	if (!ctx->nr_stat)
		return;

	update_context_time(ctx);

	event = list_first_entry(&ctx->event_list,
				   struct perf_event, event_entry);

	next_event = list_first_entry(&next_ctx->event_list,
					struct perf_event, event_entry);

	while (&event->event_entry != &ctx->event_list &&
	       &next_event->event_entry != &next_ctx->event_list) {

		__perf_event_sync_stat(event, next_event);

		event = list_next_entry(event, event_entry);
		next_event = list_next_entry(next_event, event_entry);
	}
}

static void perf_event_context_sched_out(struct task_struct *task, int ctxn,
					 struct task_struct *next)
{
	struct perf_event_context *ctx = task->perf_event_ctxp[ctxn];
	struct perf_event_context *next_ctx;
	struct perf_event_context *parent, *next_parent;
	struct perf_cpu_context *cpuctx;
	int do_switch = 1;

	if (likely(!ctx))
		return;

	cpuctx = __get_cpu_context(ctx);
	if (!cpuctx->task_ctx)
		return;

	rcu_read_lock();
	next_ctx = next->perf_event_ctxp[ctxn];
	if (!next_ctx)
		goto unlock;

	parent = rcu_dereference(ctx->parent_ctx);
	next_parent = rcu_dereference(next_ctx->parent_ctx);

	/* If neither context have a parent context; they cannot be clones. */
	if (!parent && !next_parent)
		goto unlock;

	if (next_parent == ctx || next_ctx == parent || next_parent == parent) {
		/*
 * Looks like the two contexts are clones, so we might be
 * able to optimize the context switch. We lock both
 * contexts and check that they are clones under the
 * lock (including re-checking that neither has been
 * uncloned in the meantime). It doesn't matter which
 * order we take the locks because no other cpu could
 * be trying to lock both of these tasks.
 */
		raw_spin_lock(&ctx->lock);
		raw_spin_lock_nested(&next_ctx->lock, SINGLE_DEPTH_NESTING);
		if (context_equiv(ctx, next_ctx)) {
			WRITE_ONCE(ctx->task, next);
			WRITE_ONCE(next_ctx->task, task);

			swap(ctx->task_ctx_data, next_ctx->task_ctx_data);

			/*
 * RCU_INIT_POINTER here is safe because we've not
 * modified the ctx and the above modification of
 * ctx->task and ctx->task_ctx_data are immaterial
 * since those values are always verified under
 * ctx->lock which we're now holding.
 */
			RCU_INIT_POINTER(task->perf_event_ctxp[ctxn], next_ctx);
			RCU_INIT_POINTER(next->perf_event_ctxp[ctxn], ctx);

			do_switch = 0;

			perf_event_sync_stat(ctx, next_ctx);
		}
		raw_spin_unlock(&next_ctx->lock);
		raw_spin_unlock(&ctx->lock);
	}
unlock:
	rcu_read_unlock();

	if (do_switch) {
		raw_spin_lock(&ctx->lock);
		task_ctx_sched_out(cpuctx, ctx, EVENT_ALL);
		raw_spin_unlock(&ctx->lock);
	}
}

static DEFINE_PER_CPU(struct list_head, sched_cb_list);

void perf_sched_cb_dec(struct pmu *pmu)
{
	struct perf_cpu_context *cpuctx = this_cpu_ptr(pmu->pmu_cpu_context);

	this_cpu_dec(perf_sched_cb_usages);

	if (!--cpuctx->sched_cb_usage)
		list_del(&cpuctx->sched_cb_entry);
}


void perf_sched_cb_inc(struct pmu *pmu)
{
	struct perf_cpu_context *cpuctx = this_cpu_ptr(pmu->pmu_cpu_context);

	if (!cpuctx->sched_cb_usage++)
		list_add(&cpuctx->sched_cb_entry, this_cpu_ptr(&sched_cb_list));

	this_cpu_inc(perf_sched_cb_usages);
}

/*
 * This function provides the context switch callback to the lower code
 * layer. It is invoked ONLY when the context switch callback is enabled.
 *
 * This callback is relevant even to per-cpu events; for example multi event
 * PEBS requires this to provide PID/TID information. This requires we flush
 * all queued PEBS records before we context switch to a new task.
 */
static void perf_pmu_sched_task(struct task_struct *prev,
				struct task_struct *next,
				bool sched_in)
{
	struct perf_cpu_context *cpuctx;
	struct pmu *pmu;

	if (prev == next)
		return;

	list_for_each_entry(cpuctx, this_cpu_ptr(&sched_cb_list), sched_cb_entry) {
		pmu = cpuctx->ctx.pmu; /* software PMUs will not have sched_task */

		if (WARN_ON_ONCE(!pmu->sched_task))
			continue;

		perf_ctx_lock(cpuctx, cpuctx->task_ctx);
		perf_pmu_disable(pmu);

		pmu->sched_task(cpuctx->task_ctx, sched_in);

		perf_pmu_enable(pmu);
		perf_ctx_unlock(cpuctx, cpuctx->task_ctx);
	}
}

static void perf_event_switch(struct task_struct *task,
			      struct task_struct *next_prev, bool sched_in);

#define for_each_task_context_nr(ctxn) \
 for ((ctxn) = 0; (ctxn) < perf_nr_task_contexts; (ctxn)++)

/*
 * Called from scheduler to remove the events of the current task,
 * with interrupts disabled.
 *
 * We stop each event and update the event value in event->count.
 *
 * This does not protect us against NMI, but disable()
 * sets the disabled bit in the control field of event _before_
 * accessing the event control register. If a NMI hits, then it will
 * not restart the event.
 */
void __perf_event_task_sched_out(struct task_struct *task,
				 struct task_struct *next)
{
	int ctxn;

	if (__this_cpu_read(perf_sched_cb_usages))
		perf_pmu_sched_task(task, next, false);

	if (atomic_read(&nr_switch_events))
		perf_event_switch(task, next, false);

	for_each_task_context_nr(ctxn)
		perf_event_context_sched_out(task, ctxn, next);

	/*
 * if cgroup events exist on this CPU, then we need
 * to check if we have to switch out PMU state.
 * cgroup event are system-wide mode only
 */
	if (atomic_read(this_cpu_ptr(&perf_cgroup_events)))
		perf_cgroup_sched_out(task, next);
}

/*
 * Called with IRQs disabled
 */
static void cpu_ctx_sched_out(struct perf_cpu_context *cpuctx,
			      enum event_type_t event_type)
{
	ctx_sched_out(&cpuctx->ctx, cpuctx, event_type);
}

static void
ctx_pinned_sched_in(struct perf_event_context *ctx,
		    struct perf_cpu_context *cpuctx)
{
	struct perf_event *event;

	list_for_each_entry(event, &ctx->pinned_groups, group_entry) {
		if (event->state <= PERF_EVENT_STATE_OFF)
			continue;
		if (!event_filter_match(event))
			continue;

		/* may need to reset tstamp_enabled */
		if (is_cgroup_event(event))
			perf_cgroup_mark_enabled(event, ctx);

		if (group_can_go_on(event, cpuctx, 1))
			group_sched_in(event, cpuctx, ctx);

		/*
 * If this pinned group hasn't been scheduled,
 * put it in error state.
 */
		if (event->state == PERF_EVENT_STATE_INACTIVE) {
			update_group_times(event);
			event->state = PERF_EVENT_STATE_ERROR;
		}
	}
}

static void
ctx_flexible_sched_in(struct perf_event_context *ctx,
		      struct perf_cpu_context *cpuctx)
{
	struct perf_event *event;
	int can_add_hw = 1;

	list_for_each_entry(event, &ctx->flexible_groups, group_entry) {
		/* Ignore events in OFF or ERROR state */
		if (event->state <= PERF_EVENT_STATE_OFF)
			continue;
		/*
 * Listen to the 'cpu' scheduling filter constraint
 * of events:
 */
		if (!event_filter_match(event))
			continue;

		/* may need to reset tstamp_enabled */
		if (is_cgroup_event(event))
			perf_cgroup_mark_enabled(event, ctx);

		if (group_can_go_on(event, cpuctx, can_add_hw)) {
			if (group_sched_in(event, cpuctx, ctx))
				can_add_hw = 0;
		}
	}
}

static void
ctx_sched_in(struct perf_event_context *ctx,
	     struct perf_cpu_context *cpuctx,
	     enum event_type_t event_type,
	     struct task_struct *task)
{
	int is_active = ctx->is_active;
	u64 now;

	lockdep_assert_held(&ctx->lock);

	if (likely(!ctx->nr_events))
		return;

	ctx->is_active |= (event_type | EVENT_TIME);
	if (ctx->task) {
		if (!is_active)
			cpuctx->task_ctx = ctx;
		else
			WARN_ON_ONCE(cpuctx->task_ctx != ctx);
	}

	is_active ^= ctx->is_active; /* changed bits */

	if (is_active & EVENT_TIME) {
		/* start ctx time */
		now = perf_clock();
		ctx->timestamp = now;
		perf_cgroup_set_timestamp(task, ctx);
	}

	/*
 * First go through the list and put on any pinned groups
 * in order to give them the best chance of going on.
 */
	if (is_active & EVENT_PINNED)
		ctx_pinned_sched_in(ctx, cpuctx);

	/* Then walk through the lower prio flexible groups */
	if (is_active & EVENT_FLEXIBLE)
		ctx_flexible_sched_in(ctx, cpuctx);
}

static void cpu_ctx_sched_in(struct perf_cpu_context *cpuctx,
			     enum event_type_t event_type,
			     struct task_struct *task)
{
	struct perf_event_context *ctx = &cpuctx->ctx;

	ctx_sched_in(ctx, cpuctx, event_type, task);
}

static void perf_event_context_sched_in(struct perf_event_context *ctx,
					struct task_struct *task)
{
	struct perf_cpu_context *cpuctx;

	cpuctx = __get_cpu_context(ctx);
	if (cpuctx->task_ctx == ctx)
		return;

	perf_ctx_lock(cpuctx, ctx);
	perf_pmu_disable(ctx->pmu);
	/*
 * We want to keep the following priority order:
 * cpu pinned (that don't need to move), task pinned,
 * cpu flexible, task flexible.
 *
 * However, if task's ctx is not carrying any pinned
 * events, no need to flip the cpuctx's events around.
 */
	if (!list_empty(&ctx->pinned_groups))
		cpu_ctx_sched_out(cpuctx, EVENT_FLEXIBLE);
	perf_event_sched_in(cpuctx, ctx, task);
	perf_pmu_enable(ctx->pmu);
	perf_ctx_unlock(cpuctx, ctx);
}

/*
 * Called from scheduler to add the events of the current task
 * with interrupts disabled.
 *
 * We restore the event value and then enable it.
 *
 * This does not protect us against NMI, but enable()
 * sets the enabled bit in the control field of event _before_
 * accessing the event control register. If a NMI hits, then it will
 * keep the event running.
 */
void __perf_event_task_sched_in(struct task_struct *prev,
				struct task_struct *task)
{
	struct perf_event_context *ctx;
	int ctxn;

	/*
 * If cgroup events exist on this CPU, then we need to check if we have
 * to switch in PMU state; cgroup event are system-wide mode only.
 *
 * Since cgroup events are CPU events, we must schedule these in before
 * we schedule in the task events.
 */
	if (atomic_read(this_cpu_ptr(&perf_cgroup_events)))
		perf_cgroup_sched_in(prev, task);

	for_each_task_context_nr(ctxn) {
		ctx = task->perf_event_ctxp[ctxn];
		if (likely(!ctx))
			continue;

		perf_event_context_sched_in(ctx, task);
	}

	if (atomic_read(&nr_switch_events))
		perf_event_switch(task, prev, true);

	if (__this_cpu_read(perf_sched_cb_usages))
		perf_pmu_sched_task(prev, task, true);
}

static u64 perf_calculate_period(struct perf_event *event, u64 nsec, u64 count)
{
	u64 frequency = event->attr.sample_freq;
	u64 sec = NSEC_PER_SEC;
	u64 divisor, dividend;

	int count_fls, nsec_fls, frequency_fls, sec_fls;

	count_fls = fls64(count);
	nsec_fls = fls64(nsec);
	frequency_fls = fls64(frequency);
	sec_fls = 30;

	/*
 * We got @count in @nsec, with a target of sample_freq HZ
 * the target period becomes:
 *
 * @count * 10^9
 * period = -------------------
 * @nsec * sample_freq
 *
 */

	/*
 * Reduce accuracy by one bit such that @a and @b converge
 * to a similar magnitude.
 */
#define REDUCE_FLS(a, b) \
do { \
 if (a##_fls > b##_fls) { \
 a >>= 1; \
 a##_fls--; \
 } else { \
 b >>= 1; \
 b##_fls--; \
 } \
} while (0)

	/*
 * Reduce accuracy until either term fits in a u64, then proceed with
 * the other, so that finally we can do a u64/u64 division.
 */
	while (count_fls + sec_fls > 64 && nsec_fls + frequency_fls > 64) {
		REDUCE_FLS(nsec, frequency);
		REDUCE_FLS(sec, count);
	}

	if (count_fls + sec_fls > 64) {
		divisor = nsec * frequency;

		while (count_fls + sec_fls > 64) {
			REDUCE_FLS(count, sec);
			divisor >>= 1;
		}

		dividend = count * sec;
	} else {
		dividend = count * sec;

		while (nsec_fls + frequency_fls > 64) {
			REDUCE_FLS(nsec, frequency);
			dividend >>= 1;
		}

		divisor = nsec * frequency;
	}

	if (!divisor)
		return dividend;

	return div64_u64(dividend, divisor);
}

static DEFINE_PER_CPU(int, perf_throttled_count);
static DEFINE_PER_CPU(u64, perf_throttled_seq);

static void perf_adjust_period(struct perf_event *event, u64 nsec, u64 count, bool disable)
{
	struct hw_perf_event *hwc = &event->hw;
	s64 period, sample_period;
	s64 delta;

	period = perf_calculate_period(event, nsec, count);

	delta = (s64)(period - hwc->sample_period);
	delta = (delta + 7) / 8; /* low pass filter */

	sample_period = hwc->sample_period + delta;

	if (!sample_period)
		sample_period = 1;

	hwc->sample_period = sample_period;

	if (local64_read(&hwc->period_left) > 8*sample_period) {
		if (disable)
			event->pmu->stop(event, PERF_EF_UPDATE);

		local64_set(&hwc->period_left, 0);

		if (disable)
			event->pmu->start(event, PERF_EF_RELOAD);
	}
}

/*
 * combine freq adjustment with unthrottling to avoid two passes over the
 * events. At the same time, make sure, having freq events does not change
 * the rate of unthrottling as that would introduce bias.
 */
static void perf_adjust_freq_unthr_context(struct perf_event_context *ctx,
					   int needs_unthr)
{
	struct perf_event *event;
	struct hw_perf_event *hwc;
	u64 now, period = TICK_NSEC;
	s64 delta;

	/*
 * only need to iterate over all events iff:
 * - context have events in frequency mode (needs freq adjust)
 * - there are events to unthrottle on this cpu
 */
	if (!(ctx->nr_freq || needs_unthr))
		return;

	raw_spin_lock(&ctx->lock);
	perf_pmu_disable(ctx->pmu);

	list_for_each_entry_rcu(event, &ctx->event_list, event_entry) {
		if (event->state != PERF_EVENT_STATE_ACTIVE)
			continue;

		if (!event_filter_match(event))
			continue;

		perf_pmu_disable(event->pmu);

		hwc = &event->hw;

		if (hwc->interrupts == MAX_INTERRUPTS) {
			hwc->interrupts = 0;
			perf_log_throttle(event, 1);
			event->pmu->start(event, 0);
		}

		if (!event->attr.freq || !event->attr.sample_freq)
			goto next;

		/*
 * stop the event and update event->count
 */
		event->pmu->stop(event, PERF_EF_UPDATE);

		now = local64_read(&event->count);
		delta = now - hwc->freq_count_stamp;
		hwc->freq_count_stamp = now;

		/*
 * restart the event
 * reload only if value has changed
 * we have stopped the event so tell that
 * to perf_adjust_period() to avoid stopping it
 * twice.
 */
		if (delta > 0)
			perf_adjust_period(event, period, delta, false);

		event->pmu->start(event, delta > 0 ? PERF_EF_RELOAD : 0);
	next:
		perf_pmu_enable(event->pmu);
	}

	perf_pmu_enable(ctx->pmu);
	raw_spin_unlock(&ctx->lock);
}

/*
 * Round-robin a context's events:
 */
static void rotate_ctx(struct perf_event_context *ctx)
{
	/*
 * Rotate the first entry last of non-pinned groups. Rotation might be
 * disabled by the inheritance code.
 */
	if (!ctx->rotate_disable)
		list_rotate_left(&ctx->flexible_groups);
}

static int perf_rotate_context(struct perf_cpu_context *cpuctx)
{
	struct perf_event_context *ctx = NULL;
	int rotate = 0;

	if (cpuctx->ctx.nr_events) {
		if (cpuctx->ctx.nr_events != cpuctx->ctx.nr_active)
			rotate = 1;
	}

	ctx = cpuctx->task_ctx;
	if (ctx && ctx->nr_events) {
		if (ctx->nr_events != ctx->nr_active)
			rotate = 1;
	}

	if (!rotate)
		goto done;

	perf_ctx_lock(cpuctx, cpuctx->task_ctx);
	perf_pmu_disable(cpuctx->ctx.pmu);

	cpu_ctx_sched_out(cpuctx, EVENT_FLEXIBLE);
	if (ctx)
		ctx_sched_out(ctx, cpuctx, EVENT_FLEXIBLE);

	rotate_ctx(&cpuctx->ctx);
	if (ctx)
		rotate_ctx(ctx);

	perf_event_sched_in(cpuctx, ctx, current);

	perf_pmu_enable(cpuctx->ctx.pmu);
	perf_ctx_unlock(cpuctx, cpuctx->task_ctx);
done:

	return rotate;
}

void perf_event_task_tick(void)
{
	struct list_head *head = this_cpu_ptr(&active_ctx_list);
	struct perf_event_context *ctx, *tmp;
	int throttled;

	WARN_ON(!irqs_disabled());

	__this_cpu_inc(perf_throttled_seq);
	throttled = __this_cpu_xchg(perf_throttled_count, 0);
	tick_dep_clear_cpu(smp_processor_id(), TICK_DEP_BIT_PERF_EVENTS);

	list_for_each_entry_safe(ctx, tmp, head, active_ctx_list)
		perf_adjust_freq_unthr_context(ctx, throttled);
}

static int event_enable_on_exec(struct perf_event *event,
				struct perf_event_context *ctx)
{
	if (!event->attr.enable_on_exec)
		return 0;

	event->attr.enable_on_exec = 0;
	if (event->state >= PERF_EVENT_STATE_INACTIVE)
		return 0;

	__perf_event_mark_enabled(event);

	return 1;
}

/*
 * Enable all of a task's events that have been marked enable-on-exec.
 * This expects task == current.
 */
static void perf_event_enable_on_exec(int ctxn)
{
	struct perf_event_context *ctx, *clone_ctx = NULL;
	enum event_type_t event_type = 0;
	struct perf_cpu_context *cpuctx;
	struct perf_event *event;
	unsigned long flags;
	int enabled = 0;

	local_irq_save(flags);
	ctx = current->perf_event_ctxp[ctxn];
	if (!ctx || !ctx->nr_events)
		goto out;

	cpuctx = __get_cpu_context(ctx);
	perf_ctx_lock(cpuctx, ctx);
	ctx_sched_out(ctx, cpuctx, EVENT_TIME);
	list_for_each_entry(event, &ctx->event_list, event_entry) {
		enabled |= event_enable_on_exec(event, ctx);
		event_type |= get_event_type(event);
	}

	/*
 * Unclone and reschedule this context if we enabled any event.
 */
	if (enabled) {
		clone_ctx = unclone_ctx(ctx);
		ctx_resched(cpuctx, ctx, event_type);
	} else {
		ctx_sched_in(ctx, cpuctx, EVENT_TIME, current);
	}
	perf_ctx_unlock(cpuctx, ctx);

out:
	local_irq_restore(flags);

	if (clone_ctx)
		put_ctx(clone_ctx);
}

struct perf_read_data {
	struct perf_event *event;
	bool group;
	int ret;
};

static int __perf_event_read_cpu(struct perf_event *event, int event_cpu)
{
	u16 local_pkg, event_pkg;

	if (event->group_caps & PERF_EV_CAP_READ_ACTIVE_PKG) {
		int local_cpu = smp_processor_id();

		event_pkg = topology_physical_package_id(event_cpu);
		local_pkg = topology_physical_package_id(local_cpu);

		if (event_pkg == local_pkg)
			return local_cpu;
	}

	return event_cpu;
}

/*
 * Cross CPU call to read the hardware event
 */
static void __perf_event_read(void *info)
{
	struct perf_read_data *data = info;
	struct perf_event *sub, *event = data->event;
	struct perf_event_context *ctx = event->ctx;
	struct perf_cpu_context *cpuctx = __get_cpu_context(ctx);
	struct pmu *pmu = event->pmu;

	/*
 * If this is a task context, we need to check whether it is
 * the current task context of this cpu. If not it has been
 * scheduled out before the smp call arrived. In that case
 * event->count would have been updated to a recent sample
 * when the event was scheduled out.
 */
	if (ctx->task && cpuctx->task_ctx != ctx)
		return;

	raw_spin_lock(&ctx->lock);
	if (ctx->is_active) {
		update_context_time(ctx);
		update_cgrp_time_from_event(event);
	}

	update_event_times(event);
	if (event->state != PERF_EVENT_STATE_ACTIVE)
		goto unlock;

	if (!data->group) {
		pmu->read(event);
		data->ret = 0;
		goto unlock;
	}

	pmu->start_txn(pmu, PERF_PMU_TXN_READ);

	pmu->read(event);

	list_for_each_entry(sub, &event->sibling_list, group_entry) {
		update_event_times(sub);
		if (sub->state == PERF_EVENT_STATE_ACTIVE) {
			/*
 * Use sibling's PMU rather than @event's since
 * sibling could be on different (eg: software) PMU.
 */
			sub->pmu->read(sub);
		}
	}

	data->ret = pmu->commit_txn(pmu);

unlock:
	raw_spin_unlock(&ctx->lock);
}

static inline u64 perf_event_count(struct perf_event *event)
{
	if (event->pmu->count)
		return event->pmu->count(event);

	return __perf_event_count(event);
}

/*
 * NMI-safe method to read a local event, that is an event that
 * is:
 * - either for the current task, or for this CPU
 * - does not have inherit set, for inherited task events
 * will not be local and we cannot read them atomically
 * - must not have a pmu::count method
 */
u64 perf_event_read_local(struct perf_event *event)
{
	unsigned long flags;
	u64 val;

	/*
 * Disabling interrupts avoids all counter scheduling (context
 * switches, timer based rotation and IPIs).
 */
	local_irq_save(flags);

	/* If this is a per-task event, it must be for current */
	WARN_ON_ONCE((event->attach_state & PERF_ATTACH_TASK) &&
		     event->hw.target != current);

	/* If this is a per-CPU event, it must be for this CPU */
	WARN_ON_ONCE(!(event->attach_state & PERF_ATTACH_TASK) &&
		     event->cpu != smp_processor_id());

	/*
 * It must not be an event with inherit set, we cannot read
 * all child counters from atomic context.
 */
	WARN_ON_ONCE(event->attr.inherit);

	/*
 * It must not have a pmu::count method, those are not
 * NMI safe.
 */
	WARN_ON_ONCE(event->pmu->count);

	/*
 * If the event is currently on this CPU, its either a per-task event,
 * or local to this CPU. Furthermore it means its ACTIVE (otherwise
 * oncpu == -1).
 */
	if (event->oncpu == smp_processor_id())
		event->pmu->read(event);

	val = local64_read(&event->count);
	local_irq_restore(flags);

	return val;
}

static int perf_event_read(struct perf_event *event, bool group)
{
	int event_cpu, ret = 0;

	/*
 * If event is enabled and currently active on a CPU, update the
 * value in the event structure:
 */
	if (event->state == PERF_EVENT_STATE_ACTIVE) {
		struct perf_read_data data = {
			.event = event,
			.group = group,
			.ret = 0,
		};

		event_cpu = READ_ONCE(event->oncpu);
		if ((unsigned)event_cpu >= nr_cpu_ids)
			return 0;

		preempt_disable();
		event_cpu = __perf_event_read_cpu(event, event_cpu);

		/*
 * Purposely ignore the smp_call_function_single() return
 * value.
 *
 * If event_cpu isn't a valid CPU it means the event got
 * scheduled out and that will have updated the event count.
 *
 * Therefore, either way, we'll have an up-to-date event count
 * after this.
 */
		(void)smp_call_function_single(event_cpu, __perf_event_read, &data, 1);
		preempt_enable();
		ret = data.ret;
	} else if (event->state == PERF_EVENT_STATE_INACTIVE) {
		struct perf_event_context *ctx = event->ctx;
		unsigned long flags;

		raw_spin_lock_irqsave(&ctx->lock, flags);
		/*
 * may read while context is not active
 * (e.g., thread is blocked), in that case
 * we cannot update context time
 */
		if (ctx->is_active) {
			update_context_time(ctx);
			update_cgrp_time_from_event(event);
		}
		if (group)
			update_group_times(event);
		else
			update_event_times(event);
		raw_spin_unlock_irqrestore(&ctx->lock, flags);
	}

	return ret;
}

/*
 * Initialize the perf_event context in a task_struct:
 */
static void __perf_event_init_context(struct perf_event_context *ctx)
{
	raw_spin_lock_init(&ctx->lock);
	mutex_init(&ctx->mutex);
	INIT_LIST_HEAD(&ctx->active_ctx_list);
	INIT_LIST_HEAD(&ctx->pinned_groups);
	INIT_LIST_HEAD(&ctx->flexible_groups);
	INIT_LIST_HEAD(&ctx->event_list);
	atomic_set(&ctx->refcount, 1);
}

static struct perf_event_context *
alloc_perf_context(struct pmu *pmu, struct task_struct *task)
{
	struct perf_event_context *ctx;

	ctx = kzalloc(sizeof(struct perf_event_context), GFP_KERNEL);
	if (!ctx)
		return NULL;

	__perf_event_init_context(ctx);
	if (task) {
		ctx->task = task;
		get_task_struct(task);
	}
	ctx->pmu = pmu;

	return ctx;
}

static struct task_struct *
find_lively_task_by_vpid(pid_t vpid)
{
	struct task_struct *task;

	rcu_read_lock();
	if (!vpid)
		task = current;
	else
		task = find_task_by_vpid(vpid);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	if (!task)
		return ERR_PTR(-ESRCH);

	return task;
}

/*
 * Returns a matching context with refcount and pincount.
 */
static struct perf_event_context *
find_get_context(struct pmu *pmu, struct task_struct *task,
		struct perf_event *event)
{
	struct perf_event_context *ctx, *clone_ctx = NULL;
	struct perf_cpu_context *cpuctx;
	void *task_ctx_data = NULL;
	unsigned long flags;
	int ctxn, err;
	int cpu = event->cpu;

	if (!task) {
		/* Must be root to operate on a CPU event: */
		if (perf_paranoid_cpu() && !capable(CAP_SYS_ADMIN))
			return ERR_PTR(-EACCES);

		/*
 * We could be clever and allow to attach a event to an
 * offline CPU and activate it when the CPU comes up, but
 * that's for later.
 */
		if (!cpu_online(cpu))
			return ERR_PTR(-ENODEV);

		cpuctx = per_cpu_ptr(pmu->pmu_cpu_context, cpu);
		ctx = &cpuctx->ctx;
		get_ctx(ctx);
		++ctx->pin_count;

		return ctx;
	}

	err = -EINVAL;
	ctxn = pmu->task_ctx_nr;
	if (ctxn < 0)
		goto errout;

	if (event->attach_state & PERF_ATTACH_TASK_DATA) {
		task_ctx_data = kzalloc(pmu->task_ctx_size, GFP_KERNEL);
		if (!task_ctx_data) {
			err = -ENOMEM;
			goto errout;
		}
	}

retry:
	ctx = perf_lock_task_context(task, ctxn, &flags);
	if (ctx) {
		clone_ctx = unclone_ctx(ctx);
		++ctx->pin_count;

		if (task_ctx_data && !ctx->task_ctx_data) {
			ctx->task_ctx_data = task_ctx_data;
			task_ctx_data = NULL;
		}
		raw_spin_unlock_irqrestore(&ctx->lock, flags);

		if (clone_ctx)
			put_ctx(clone_ctx);
	} else {
		ctx = alloc_perf_context(pmu, task);
		err = -ENOMEM;
		if (!ctx)
			goto errout;

		if (task_ctx_data) {
			ctx->task_ctx_data = task_ctx_data;
			task_ctx_data = NULL;
		}

		err = 0;
		mutex_lock(&task->perf_event_mutex);
		/*
 * If it has already passed perf_event_exit_task().
 * we must see PF_EXITING, it takes this mutex too.
 */
		if (task->flags & PF_EXITING)
			err = -ESRCH;
		else if (task->perf_event_ctxp[ctxn])
			err = -EAGAIN;
		else {
			get_ctx(ctx);
			++ctx->pin_count;
			rcu_assign_pointer(task->perf_event_ctxp[ctxn], ctx);
		}
		mutex_unlock(&task->perf_event_mutex);

		if (unlikely(err)) {
			put_ctx(ctx);

			if (err == -EAGAIN)
				goto retry;
			goto errout;
		}
	}

	kfree(task_ctx_data);
	return ctx;

errout:
	kfree(task_ctx_data);
	return ERR_PTR(err);
}

static void perf_event_free_filter(struct perf_event *event);
static void perf_event_free_bpf_prog(struct perf_event *event);

static void free_event_rcu(struct rcu_head *head)
{
	struct perf_event *event;

	event = container_of(head, struct perf_event, rcu_head);
	if (event->ns)
		put_pid_ns(event->ns);
	perf_event_free_filter(event);
	kfree(event);
}

static void ring_buffer_attach(struct perf_event *event,
			       struct ring_buffer *rb);

static void detach_sb_event(struct perf_event *event)
{
	struct pmu_event_list *pel = per_cpu_ptr(&pmu_sb_events, event->cpu);

	raw_spin_lock(&pel->lock);
	list_del_rcu(&event->sb_list);
	raw_spin_unlock(&pel->lock);
}

static bool is_sb_event(struct perf_event *event)
{
	struct perf_event_attr *attr = &event->attr;

	if (event->parent)
		return false;

	if (event->attach_state & PERF_ATTACH_TASK)
		return false;

	if (attr->mmap || attr->mmap_data || attr->mmap2 ||
	    attr->comm || attr->comm_exec ||
	    attr->task ||
	    attr->context_switch)
		return true;
	return false;
}

static void unaccount_pmu_sb_event(struct perf_event *event)
{
	if (is_sb_event(event))
		detach_sb_event(event);
}

static void unaccount_event_cpu(struct perf_event *event, int cpu)
{
	if (event->parent)
		return;

	if (is_cgroup_event(event))
		atomic_dec(&per_cpu(perf_cgroup_events, cpu));
}

#ifdef CONFIG_NO_HZ_FULL
static DEFINE_SPINLOCK(nr_freq_lock);
#endif

static void unaccount_freq_event_nohz(void)
{
#ifdef CONFIG_NO_HZ_FULL
	spin_lock(&nr_freq_lock);
	if (atomic_dec_and_test(&nr_freq_events))
		tick_nohz_dep_clear(TICK_DEP_BIT_PERF_EVENTS);
	spin_unlock(&nr_freq_lock);
#endif
}

static void unaccount_freq_event(void)
{
	if (tick_nohz_full_enabled())
		unaccount_freq_event_nohz();
	else
		atomic_dec(&nr_freq_events);
}

static void unaccount_event(struct perf_event *event)
{
	bool dec = false;

	if (event->parent)
		return;

	if (event->attach_state & PERF_ATTACH_TASK)
		dec = true;
	if (event->attr.mmap || event->attr.mmap_data)
		atomic_dec(&nr_mmap_events);
	if (event->attr.comm)
		atomic_dec(&nr_comm_events);
	if (event->attr.task)
		atomic_dec(&nr_task_events);
	if (event->attr.freq)
		unaccount_freq_event();
	if (event->attr.context_switch) {
		dec = true;
		atomic_dec(&nr_switch_events);
	}
	if (is_cgroup_event(event))
		dec = true;
	if (has_branch_stack(event))
		dec = true;

	if (dec) {
		if (!atomic_add_unless(&perf_sched_count, -1, 1))
			schedule_delayed_work(&perf_sched_work, HZ);
	}

	unaccount_event_cpu(event, event->cpu);

	unaccount_pmu_sb_event(event);
}

static void perf_sched_delayed(struct work_struct *work)
{
	mutex_lock(&perf_sched_mutex);
	if (atomic_dec_and_test(&perf_sched_count))
		static_branch_disable(&perf_sched_events);
	mutex_unlock(&perf_sched_mutex);
}

/*
 * The following implement mutual exclusion of events on "exclusive" pmus
 * (PERF_PMU_CAP_EXCLUSIVE). Such pmus can only have one event scheduled
 * at a time, so we disallow creating events that might conflict, namely:
 *
 * 1) cpu-wide events in the presence of per-task events,
 * 2) per-task events in the presence of cpu-wide events,
 * 3) two matching events on the same context.
 *
 * The former two cases are handled in the allocation path (perf_event_alloc(),
 * _free_event()), the latter -- before the first perf_install_in_context().
 */
static int exclusive_event_init(struct perf_event *event)
{
	struct pmu *pmu = event->pmu;

	if (!(pmu->capabilities & PERF_PMU_CAP_EXCLUSIVE))
		return 0;

	/*
 * Prevent co-existence of per-task and cpu-wide events on the
 * same exclusive pmu.
 *
 * Negative pmu::exclusive_cnt means there are cpu-wide
 * events on this "exclusive" pmu, positive means there are
 * per-task events.
 *
 * Since this is called in perf_event_alloc() path, event::ctx
 * doesn't exist yet; it is, however, safe to use PERF_ATTACH_TASK
 * to mean "per-task event", because unlike other attach states it
 * never gets cleared.
 */
	if (event->attach_state & PERF_ATTACH_TASK) {
		if (!atomic_inc_unless_negative(&pmu->exclusive_cnt))
			return -EBUSY;
	} else {
		if (!atomic_dec_unless_positive(&pmu->exclusive_cnt))
			return -EBUSY;
	}

	return 0;
}

static void exclusive_event_destroy(struct perf_event *event)
{
	struct pmu *pmu = event->pmu;

	if (!(pmu->capabilities & PERF_PMU_CAP_EXCLUSIVE))
		return;

	/* see comment in exclusive_event_init() */
	if (event->attach_state & PERF_ATTACH_TASK)
		atomic_dec(&pmu->exclusive_cnt);
	else
		atomic_inc(&pmu->exclusive_cnt);
}

static bool exclusive_event_match(struct perf_event *e1, struct perf_event *e2)
{
	if ((e1->pmu == e2->pmu) &&
	    (e1->cpu == e2->cpu ||
	     e1->cpu == -1 ||
	     e2->cpu == -1))
		return true;
	return false;
}

/* Called under the same ctx::mutex as perf_install_in_context() */
static bool exclusive_event_installable(struct perf_event *event,
					struct perf_event_context *ctx)
{
	struct perf_event *iter_event;
	struct pmu *pmu = event->pmu;

	if (!(pmu->capabilities & PERF_PMU_CAP_EXCLUSIVE))
		return true;

	list_for_each_entry(iter_event, &ctx->event_list, event_entry) {
		if (exclusive_event_match(iter_event, event))
			return false;
	}

	return true;
}

static void perf_addr_filters_splice(struct perf_event *event,
				       struct list_head *head);

static void _free_event(struct perf_event *event)
{
	irq_work_sync(&event->pending);

	unaccount_event(event);

	if (event->rb) {
		/*
 * Can happen when we close an event with re-directed output.
 *
 * Since we have a 0 refcount, perf_mmap_close() will skip
 * over us; possibly making our ring_buffer_put() the last.
 */
		mutex_lock(&event->mmap_mutex);
		ring_buffer_attach(event, NULL);
		mutex_unlock(&event->mmap_mutex);
	}

	if (is_cgroup_event(event))
		perf_detach_cgroup(event);

	if (!event->parent) {
		if (event->attr.sample_type & PERF_SAMPLE_CALLCHAIN)
			put_callchain_buffers();
	}

	perf_event_free_bpf_prog(event);
	perf_addr_filters_splice(event, NULL);
	kfree(event->addr_filters_offs);

	if (event->destroy)
		event->destroy(event);

	if (event->ctx)
		put_ctx(event->ctx);

	exclusive_event_destroy(event);
	module_put(event->pmu->module);

	call_rcu(&event->rcu_head, free_event_rcu);
}

/*
 * Used to free events which have a known refcount of 1, such as in error paths
 * where the event isn't exposed yet and inherited events.
 */
static void free_event(struct perf_event *event)
{
	if (WARN(atomic_long_cmpxchg(&event->refcount, 1, 0) != 1,
				"unexpected event refcount: %ld; ptr=%p\n",
				atomic_long_read(&event->refcount), event)) {
		/* leak to avoid use-after-free */
		return;
	}

	_free_event(event);
}

/*
 * Remove user event from the owner task.
 */
static void perf_remove_from_owner(struct perf_event *event)
{
	struct task_struct *owner;

	rcu_read_lock();
	/*
 * Matches the smp_store_release() in perf_event_exit_task(). If we
 * observe !owner it means the list deletion is complete and we can
 * indeed free this event, otherwise we need to serialize on
 * owner->perf_event_mutex.
 */
	owner = lockless_dereference(event->owner);
	if (owner) {
		/*
 * Since delayed_put_task_struct() also drops the last
 * task reference we can safely take a new reference
 * while holding the rcu_read_lock().
 */
		get_task_struct(owner);
	}
	rcu_read_unlock();

	if (owner) {
		/*
 * If we're here through perf_event_exit_task() we're already
 * holding ctx->mutex which would be an inversion wrt. the
 * normal lock order.
 *
 * However we can safely take this lock because its the child
 * ctx->mutex.
 */
		mutex_lock_nested(&owner->perf_event_mutex, SINGLE_DEPTH_NESTING);

		/*
 * We have to re-check the event->owner field, if it is cleared
 * we raced with perf_event_exit_task(), acquiring the mutex
 * ensured they're done, and we can proceed with freeing the
 * event.
 */
		if (event->owner) {
			list_del_init(&event->owner_entry);
			smp_store_release(&event->owner, NULL);
		}
		mutex_unlock(&owner->perf_event_mutex);
		put_task_struct(owner);
	}
}

static void put_event(struct perf_event *event)
{
	if (!atomic_long_dec_and_test(&event->refcount))
		return;

	_free_event(event);
}

/*
 * Kill an event dead; while event:refcount will preserve the event
 * object, it will not preserve its functionality. Once the last 'user'
 * gives up the object, we'll destroy the thing.
 */
int perf_event_release_kernel(struct perf_event *event)
{
	struct perf_event_context *ctx = event->ctx;
	struct perf_event *child, *tmp;

	/*
 * If we got here through err_file: fput(event_file); we will not have
 * attached to a context yet.
 */
	if (!ctx) {
		WARN_ON_ONCE(event->attach_state &
				(PERF_ATTACH_CONTEXT|PERF_ATTACH_GROUP));
		goto no_ctx;
	}

	if (!is_kernel_event(event))
		perf_remove_from_owner(event);

	ctx = perf_event_ctx_lock(event);
	WARN_ON_ONCE(ctx->parent_ctx);
	perf_remove_from_context(event, DETACH_GROUP);

	raw_spin_lock_irq(&ctx->lock);
	/*
 * Mark this even as STATE_DEAD, there is no external reference to it
 * anymore.
 *
 * Anybody acquiring event->child_mutex after the below loop _must_
 * also see this, most importantly inherit_event() which will avoid
 * placing more children on the list.
 *
 * Thus this guarantees that we will in fact observe and kill _ALL_
 * child events.
 */
	event->state = PERF_EVENT_STATE_DEAD;
	raw_spin_unlock_irq(&ctx->lock);

	perf_event_ctx_unlock(event, ctx);

again:
	mutex_lock(&event->child_mutex);
	list_for_each_entry(child, &event->child_list, child_list) {

		/*
 * Cannot change, child events are not migrated, see the
 * comment with perf_event_ctx_lock_nested().
 */
		ctx = lockless_dereference(child->ctx);
		/*
 * Since child_mutex nests inside ctx::mutex, we must jump
 * through hoops. We start by grabbing a reference on the ctx.
 *
 * Since the event cannot get freed while we hold the
 * child_mutex, the context must also exist and have a !0
 * reference count.
 */
		get_ctx(ctx);

		/*
 * Now that we have a ctx ref, we can drop child_mutex, and
 * acquire ctx::mutex without fear of it going away. Then we
 * can re-acquire child_mutex.
 */
		mutex_unlock(&event->child_mutex);
		mutex_lock(&ctx->mutex);
		mutex_lock(&event->child_mutex);

		/*
 * Now that we hold ctx::mutex and child_mutex, revalidate our
 * state, if child is still the first entry, it didn't get freed
 * and we can continue doing so.
 */
		tmp = list_first_entry_or_null(&event->child_list,
					       struct perf_event, child_list);
		if (tmp == child) {
			perf_remove_from_context(child, DETACH_GROUP);
			list_del(&child->child_list);
			free_event(child);
			/*
 * This matches the refcount bump in inherit_event();
 * this can't be the last reference.
 */
			put_event(event);
		}

		mutex_unlock(&event->child_mutex);
		mutex_unlock(&ctx->mutex);
		put_ctx(ctx);
		goto again;
	}
	mutex_unlock(&event->child_mutex);

no_ctx:
	put_event(event); /* Must be the 'last' reference */
	return 0;
}
EXPORT_SYMBOL_GPL(perf_event_release_kernel);

/*
 * Called when the last reference to the file is gone.
 */
static int perf_release(struct inode *inode, struct file *file)
{
	perf_event_release_kernel(file->private_data);
	return 0;
}

u64 perf_event_read_value(struct perf_event *event, u64 *enabled, u64 *running)
{
	struct perf_event *child;
	u64 total = 0;

	*enabled = 0;
	*running = 0;

	mutex_lock(&event->child_mutex);

	(void)perf_event_read(event, false);
	total += perf_event_count(event);

	*enabled += event->total_time_enabled +
			atomic64_read(&event->child_total_time_enabled);
	*running += event->total_time_running +
			atomic64_read(&event->child_total_time_running);

	list_for_each_entry(child, &event->child_list, child_list) {
		(void)perf_event_read(child, false);
		total += perf_event_count(child);
		*enabled += child->total_time_enabled;
		*running += child->total_time_running;
	}
	mutex_unlock(&event->child_mutex);

	return total;
}
EXPORT_SYMBOL_GPL(perf_event_read_value);

static int __perf_read_group_add(struct perf_event *leader,
					u64 read_format, u64 *values)
{
	struct perf_event *sub;
	int n = 1; /* skip @nr */
	int ret;

	ret = perf_event_read(leader, true);
	if (ret)
		return ret;

	/*
 * Since we co-schedule groups, {enabled,running} times of siblings
 * will be identical to those of the leader, so we only publish one
 * set.
 */
	if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED) {
		values[n++] += leader->total_time_enabled +
			atomic64_read(&leader->child_total_time_enabled);
	}

	if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING) {
		values[n++] += leader->total_time_running +
			atomic64_read(&leader->child_total_time_running);
	}

	/*
 * Write {count,id} tuples for every sibling.
 */
	values[n++] += perf_event_count(leader);
	if (read_format & PERF_FORMAT_ID)
		values[n++] = primary_event_id(leader);

	list_for_each_entry(sub, &leader->sibling_list, group_entry) {
		values[n++] += perf_event_count(sub);
		if (read_format & PERF_FORMAT_ID)
			values[n++] = primary_event_id(sub);
	}

	return 0;
}

static int perf_read_group(struct perf_event *event,
				   u64 read_format, char __user *buf)
{
	struct perf_event *leader = event->group_leader, *child;
	struct perf_event_context *ctx = leader->ctx;
	int ret;
	u64 *values;

	lockdep_assert_held(&ctx->mutex);

	values = kzalloc(event->read_size, GFP_KERNEL);
	if (!values)
		return -ENOMEM;

	values[0] = 1 + leader->nr_siblings;

	/*
 * By locking the child_mutex of the leader we effectively
 * lock the child list of all siblings.. XXX explain how.
 */
	mutex_lock(&leader->child_mutex);

	ret = __perf_read_group_add(leader, read_format, values);
	if (ret)
		goto unlock;

	list_for_each_entry(child, &leader->child_list, child_list) {
		ret = __perf_read_group_add(child, read_format, values);
		if (ret)
			goto unlock;
	}

	mutex_unlock(&leader->child_mutex);

	ret = event->read_size;
	if (copy_to_user(buf, values, event->read_size))
		ret = -EFAULT;
	goto out;

unlock:
	mutex_unlock(&leader->child_mutex);
out:
	kfree(values);
	return ret;
}

static int perf_read_one(struct perf_event *event,
				 u64 read_format, char __user *buf)
{
	u64 enabled, running;
	u64 values[4];
	int n = 0;

	values[n++] = perf_event_read_value(event, &enabled, &running);
	if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED)
		values[n++] = enabled;
	if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING)
		values[n++] = running;
	if (read_format & PERF_FORMAT_ID)
		values[n++] = primary_event_id(event);

	if (copy_to_user(buf, values, n * sizeof(u64)))
		return -EFAULT;

	return n * sizeof(u64);
}

static bool is_event_hup(struct perf_event *event)
{
	bool no_children;

	if (event->state > PERF_EVENT_STATE_EXIT)
		return false;

	mutex_lock(&event->child_mutex);
	no_children = list_empty(&event->child_list);
	mutex_unlock(&event->child_mutex);
	return no_children;
}

/*
 * Read the performance event - simple non blocking version for now
 */
static ssize_t
__perf_read(struct perf_event *event, char __user *buf, size_t count)
{
	u64 read_format = event->attr.read_format;
	int ret;

	/*
 * Return end-of-file for a read on a event that is in
 * error state (i.e. because it was pinned but it couldn't be
 * scheduled on to the CPU at some point).
 */
	if (event->state == PERF_EVENT_STATE_ERROR)
		return 0;

	if (count < event->read_size)
		return -ENOSPC;

	WARN_ON_ONCE(event->ctx->parent_ctx);
	if (read_format & PERF_FORMAT_GROUP)
		ret = perf_read_group(event, read_format, buf);
	else
		ret = perf_read_one(event, read_format, buf);

	return ret;
}

static ssize_t
perf_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct perf_event *event = file->private_data;
	struct perf_event_context *ctx;
	int ret;

	ctx = perf_event_ctx_lock(event);
	ret = __perf_read(event, buf, count);
	perf_event_ctx_unlock(event, ctx);

	return ret;
}

static unsigned int perf_poll(struct file *file, poll_table *wait)
{
	struct perf_event *event = file->private_data;
	struct ring_buffer *rb;
	unsigned int events = POLLHUP;

	poll_wait(file, &event->waitq, wait);

	if (is_event_hup(event))
		return events;

	/*
 * Pin the event->rb by taking event->mmap_mutex; otherwise
 * perf_event_set_output() can swizzle our rb and make us miss wakeups.
 */
	mutex_lock(&event->mmap_mutex);
	rb = event->rb;
	if (rb)
		events = atomic_xchg(&rb->poll, 0);
	mutex_unlock(&event->mmap_mutex);
	return events;
}

static void _perf_event_reset(struct perf_event *event)
{
	(void)perf_event_read(event, false);
	local64_set(&event->count, 0);
	perf_event_update_userpage(event);
}

/*
 * Holding the top-level event's child_mutex means that any
 * descendant process that has inherited this event will block
 * in perf_event_exit_event() if it goes to exit, thus satisfying the
 * task existence requirements of perf_event_enable/disable.
 */
static void perf_event_for_each_child(struct perf_event *event,
					void (*func)(struct perf_event *))
{
	struct perf_event *child;

	WARN_ON_ONCE(event->ctx->parent_ctx);

	mutex_lock(&event->child_mutex);
	func(event);
	list_for_each_entry(child, &event->child_list, child_list)
		func(child);
	mutex_unlock(&event->child_mutex);
}

static void perf_event_for_each(struct perf_event *event,
				  void (*func)(struct perf_event *))
{
	struct perf_event_context *ctx = event->ctx;
	struct perf_event *sibling;

	lockdep_assert_held(&ctx->mutex);

	event = event->group_leader;

	perf_event_for_each_child(event, func);
	list_for_each_entry(sibling, &event->sibling_list, group_entry)
		perf_event_for_each_child(sibling, func);
}

static void __perf_event_period(struct perf_event *event,
				struct perf_cpu_context *cpuctx,
				struct perf_event_context *ctx,
				void *info)
{
	u64 value = *((u64 *)info);
	bool active;

	if (event->attr.freq) {
		event->attr.sample_freq = value;
	} else {
		event->attr.sample_period = value;
		event->hw.sample_period = value;
	}

	active = (event->state == PERF_EVENT_STATE_ACTIVE);
	if (active) {
		perf_pmu_disable(ctx->pmu);
		/*
 * We could be throttled; unthrottle now to avoid the tick
 * trying to unthrottle while we already re-started the event.
 */
		if (event->hw.interrupts == MAX_INTERRUPTS) {
			event->hw.interrupts = 0;
			perf_log_throttle(event, 1);
		}
		event->pmu->stop(event, PERF_EF_UPDATE);
	}

	local64_set(&event->hw.period_left, 0);

	if (active) {
		event->pmu->start(event, PERF_EF_RELOAD);
		perf_pmu_enable(ctx->pmu);
	}
}

static int perf_event_period(struct perf_event *event, u64 __user *arg)
{
	u64 value;

	if (!is_sampling_event(event))
		return -EINVAL;

	if (copy_from_user(&value, arg, sizeof(value)))
		return -EFAULT;

	if (!value)
		return -EINVAL;

	if (event->attr.freq && value > sysctl_perf_event_sample_rate)
		return -EINVAL;

	event_function_call(event, __perf_event_period, &value);

	return 0;
}

static const struct file_operations perf_fops;

static inline int perf_fget_light(int fd, struct fd *p)
{
	struct fd f = fdget(fd);
	if (!f.file)
		return -EBADF;

	if (f.file->f_op != &perf_fops) {
		fdput(f);
		return -EBADF;
	}
	*p = f;
	return 0;
}

static int perf_event_set_output(struct perf_event *event,
				 struct perf_event *output_event);
static int perf_event_set_filter(struct perf_event *event, void __user *arg);
static int perf_event_set_bpf_prog(struct perf_event *event, u32 prog_fd);

static long _perf_ioctl(struct perf_event *event, unsigned int cmd, unsigned long arg)
{
	void (*func)(struct perf_event *);
	u32 flags = arg;

	switch (cmd) {
	case PERF_EVENT_IOC_ENABLE:
		func = _perf_event_enable;
		break;
	case PERF_EVENT_IOC_DISABLE:
		func = _perf_event_disable;
		break;
	case PERF_EVENT_IOC_RESET:
		func = _perf_event_reset;
		break;

	case PERF_EVENT_IOC_REFRESH:
		return _perf_event_refresh(event, arg);

	case PERF_EVENT_IOC_PERIOD:
		return perf_event_period(event, (u64 __user *)arg);

	case PERF_EVENT_IOC_ID:
	{
		u64 id = primary_event_id(event);

		if (copy_to_user((void __user *)arg, &id, sizeof(id)))
			return -EFAULT;
		return 0;
	}

	case PERF_EVENT_IOC_SET_OUTPUT:
	{
		int ret;
		if (arg != -1) {
			struct perf_event *output_event;
			struct fd output;
			ret = perf_fget_light(arg, &output);
			if (ret)
				return ret;
			output_event = output.file->private_data;
			ret = perf_event_set_output(event, output_event);
			fdput(output);
		} else {
			ret = perf_event_set_output(event, NULL);
		}
		return ret;
	}

	case PERF_EVENT_IOC_SET_FILTER:
		return perf_event_set_filter(event, (void __user *)arg);

	case PERF_EVENT_IOC_SET_BPF:
		return perf_event_set_bpf_prog(event, arg);

	case PERF_EVENT_IOC_PAUSE_OUTPUT: {
		struct ring_buffer *rb;

		rcu_read_lock();
		rb = rcu_dereference(event->rb);
		if (!rb || !rb->nr_pages) {
			rcu_read_unlock();
			return -EINVAL;
		}
		rb_toggle_paused(rb, !!arg);
		rcu_read_unlock();
		return 0;
	}
	default:
		return -ENOTTY;
	}

	if (flags & PERF_IOC_FLAG_GROUP)
		perf_event_for_each(event, func);
	else
		perf_event_for_each_child(event, func);

	return 0;
}

static long perf_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct perf_event *event = file->private_data;
	struct perf_event_context *ctx;
	long ret;

	ctx = perf_event_ctx_lock(event);
	ret = _perf_ioctl(event, cmd, arg);
	perf_event_ctx_unlock(event, ctx);

	return ret;
}

#ifdef CONFIG_COMPAT
static long perf_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	switch (_IOC_NR(cmd)) {
	case _IOC_NR(PERF_EVENT_IOC_SET_FILTER):
	case _IOC_NR(PERF_EVENT_IOC_ID):
		/* Fix up pointer size (usually 4 -> 8 in 32-on-64-bit case */
		if (_IOC_SIZE(cmd) == sizeof(compat_uptr_t)) {
			cmd &= ~IOCSIZE_MASK;
			cmd |= sizeof(void *) << IOCSIZE_SHIFT;
		}
		break;
	}
	return perf_ioctl(file, cmd, arg);
}
#else
# define perf_compat_ioctl NULL
#endif

int perf_event_task_enable(void)
{
	struct perf_event_context *ctx;
	struct perf_event *event;

	mutex_lock(&current->perf_event_mutex);
	list_for_each_entry(event, &current->perf_event_list, owner_entry) {
		ctx = perf_event_ctx_lock(event);
		perf_event_for_each_child(event, _perf_event_enable);
		perf_event_ctx_unlock(event, ctx);
	}
	mutex_unlock(&current->perf_event_mutex);

	return 0;
}

int perf_event_task_disable(void)
{
	struct perf_event_context *ctx;
	struct perf_event *event;

	mutex_lock(&current->perf_event_mutex);
	list_for_each_entry(event, &current->perf_event_list, owner_entry) {
		ctx = perf_event_ctx_lock(event);
		perf_event_for_each_child(event, _perf_event_disable);
		perf_event_ctx_unlock(event, ctx);
	}
	mutex_unlock(&current->perf_event_mutex);

	return 0;
}

static int perf_event_index(struct perf_event *event)
{
	if (event->hw.state & PERF_HES_STOPPED)
		return 0;

	if (event->state != PERF_EVENT_STATE_ACTIVE)
		return 0;

	return event->pmu->event_idx(event);
}

static void calc_timer_values(struct perf_event *event,
				u64 *now,
				u64 *enabled,
				u64 *running)
{
	u64 ctx_time;

	*now = perf_clock();
	ctx_time = event->shadow_ctx_time + *now;
	*enabled = ctx_time - event->tstamp_enabled;
	*running = ctx_time - event->tstamp_running;
}

static void perf_event_init_userpage(struct perf_event *event)
{
	struct perf_event_mmap_page *userpg;
	struct ring_buffer *rb;

	rcu_read_lock();
	rb = rcu_dereference(event->rb);
	if (!rb)
		goto unlock;

	userpg = rb->user_page;

	/* Allow new userspace to detect that bit 0 is deprecated */
	userpg->cap_bit0_is_deprecated = 1;
	userpg->size = offsetof(struct perf_event_mmap_page, __reserved);
	userpg->data_offset = PAGE_SIZE;
	userpg->data_size = perf_data_size(rb);

unlock:
	rcu_read_unlock();
}

void __weak arch_perf_update_userpage(
	struct perf_event *event, struct perf_event_mmap_page *userpg, u64 now)
{
}

/*
 * Callers need to ensure there can be no nesting of this function, otherwise
 * the seqlock logic goes bad. We can not serialize this because the arch
 * code calls this from NMI context.
 */
void perf_event_update_userpage(struct perf_event *event)
{
	struct perf_event_mmap_page *userpg;
	struct ring_buffer *rb;
	u64 enabled, running, now;

	rcu_read_lock();
	rb = rcu_dereference(event->rb);
	if (!rb)
		goto unlock;

	/*
 * compute total_time_enabled, total_time_running
 * based on snapshot values taken when the event
 * was last scheduled in.
 *
 * we cannot simply called update_context_time()
 * because of locking issue as we can be called in
 * NMI context
 */
	calc_timer_values(event, &now, &enabled, &running);

	userpg = rb->user_page;
	/*
 * Disable preemption so as to not let the corresponding user-space
 * spin too long if we get preempted.
 */
	preempt_disable();
	++userpg->lock;
	barrier();
	userpg->index = perf_event_index(event);
	userpg->offset = perf_event_count(event);
	if (userpg->index)
		userpg->offset -= local64_read(&event->hw.prev_count);

	userpg->time_enabled = enabled +
			atomic64_read(&event->child_total_time_enabled);

	userpg->time_running = running +
			atomic64_read(&event->child_total_time_running);

	arch_perf_update_userpage(event, userpg, now);

	barrier();
	++userpg->lock;
	preempt_enable();
unlock:
	rcu_read_unlock();
}

static int perf_mmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct perf_event *event = vma->vm_file->private_data;
	struct ring_buffer *rb;
	int ret = VM_FAULT_SIGBUS;

	if (vmf->flags & FAULT_FLAG_MKWRITE) {
		if (vmf->pgoff == 0)
			ret = 0;
		return ret;
	}

	rcu_read_lock();
	rb = rcu_dereference(event->rb);
	if (!rb)
		goto unlock;

	if (vmf->pgoff && (vmf->flags & FAULT_FLAG_WRITE))
		goto unlock;

	vmf->page = perf_mmap_to_page(rb, vmf->pgoff);
	if (!vmf->page)
		goto unlock;

	get_page(vmf->page);
	vmf->page->mapping = vma->vm_file->f_mapping;
	vmf->page->index   = vmf->pgoff;

	ret = 0;
unlock:
	rcu_read_unlock();

	return ret;
}

static void ring_buffer_attach(struct perf_event *event,
			       struct ring_buffer *rb)
{
	struct ring_buffer *old_rb = NULL;
	unsigned long flags;

	if (event->rb) {
		/*
 * Should be impossible, we set this when removing
 * event->rb_entry and wait/clear when adding event->rb_entry.
 */
		WARN_ON_ONCE(event->rcu_pending);

		old_rb = event->rb;
		spin_lock_irqsave(&old_rb->event_lock, flags);
		list_del_rcu(&event->rb_entry);
		spin_unlock_irqrestore(&old_rb->event_lock, flags);

		event->rcu_batches = get_state_synchronize_rcu();
		event->rcu_pending = 1;
	}

	if (rb) {
		if (event->rcu_pending) {
			cond_synchronize_rcu(event->rcu_batches);
			event->rcu_pending = 0;
		}

		spin_lock_irqsave(&rb->event_lock, flags);
		list_add_rcu(&event->rb_entry, &rb->event_list);
		spin_unlock_irqrestore(&rb->event_lock, flags);
	}

	/*
 * Avoid racing with perf_mmap_close(AUX): stop the event
 * before swizzling the event::rb pointer; if it's getting
 * unmapped, its aux_mmap_count will be 0 and it won't
 * restart. See the comment in __perf_pmu_output_stop().
 *
 * Data will inevitably be lost when set_output is done in
 * mid-air, but then again, whoever does it like this is
 * not in for the data anyway.
 */
	if (has_aux(event))
		perf_event_stop(event, 0);

	rcu_assign_pointer(event->rb, rb);

	if (old_rb) {
		ring_buffer_put(old_rb);
		/*
 * Since we detached before setting the new rb, so that we
 * could attach the new rb, we could have missed a wakeup.
 * Provide it now.
 */
		wake_up_all(&event->waitq);
	}
}

static void ring_buffer_wakeup(struct perf_event *event)
{
	struct ring_buffer *rb;

	rcu_read_lock();
	rb = rcu_dereference(event->rb);
	if (rb) {
		list_for_each_entry_rcu(event, &rb->event_list, rb_entry)
			wake_up_all(&event->waitq);
	}
	rcu_read_unlock();
}

struct ring_buffer *ring_buffer_get(struct perf_event *event)
{
	struct ring_buffer *rb;

	rcu_read_lock();
	rb = rcu_dereference(event->rb);
	if (rb) {
		if (!atomic_inc_not_zero(&rb->refcount))
			rb = NULL;
	}
	rcu_read_unlock();

	return rb;
}

void ring_buffer_put(struct ring_buffer *rb)
{
	if (!atomic_dec_and_test(&rb->refcount))
		return;

	WARN_ON_ONCE(!list_empty(&rb->event_list));

	call_rcu(&rb->rcu_head, rb_free_rcu);
}

static void perf_mmap_open(struct vm_area_struct *vma)
{
	struct perf_event *event = vma->vm_file->private_data;

	atomic_inc(&event->mmap_count);
	atomic_inc(&event->rb->mmap_count);

	if (vma->vm_pgoff)
		atomic_inc(&event->rb->aux_mmap_count);

	if (event->pmu->event_mapped)
		event->pmu->event_mapped(event);
}

static void perf_pmu_output_stop(struct perf_event *event);

/*
 * A buffer can be mmap()ed multiple times; either directly through the same
 * event, or through other events by use of perf_event_set_output().
 *
 * In order to undo the VM accounting done by perf_mmap() we need to destroy
 * the buffer here, where we still have a VM context. This means we need
 * to detach all events redirecting to us.
 */
static void perf_mmap_close(struct vm_area_struct *vma)
{
	struct perf_event *event = vma->vm_file->private_data;

	struct ring_buffer *rb = ring_buffer_get(event);
	struct user_struct *mmap_user = rb->mmap_user;
	int mmap_locked = rb->mmap_locked;
	unsigned long size = perf_data_size(rb);

	if (event->pmu->event_unmapped)
		event->pmu->event_unmapped(event);

	/*
 * rb->aux_mmap_count will always drop before rb->mmap_count and
 * event->mmap_count, so it is ok to use event->mmap_mutex to
 * serialize with perf_mmap here.
 */
	if (rb_has_aux(rb) && vma->vm_pgoff == rb->aux_pgoff &&
	    atomic_dec_and_mutex_lock(&rb->aux_mmap_count, &event->mmap_mutex)) {
		/*
 * Stop all AUX events that are writing to this buffer,
 * so that we can free its AUX pages and corresponding PMU
 * data. Note that after rb::aux_mmap_count dropped to zero,
 * they won't start any more (see perf_aux_output_begin()).
 */
		perf_pmu_output_stop(event);

		/* now it's safe to free the pages */
		atomic_long_sub(rb->aux_nr_pages, &mmap_user->locked_vm);
		vma->vm_mm->pinned_vm -= rb->aux_mmap_locked;

		/* this has to be the last one */
		rb_free_aux(rb);
		WARN_ON_ONCE(atomic_read(&rb->aux_refcount));

		mutex_unlock(&event->mmap_mutex);
	}

	atomic_dec(&rb->mmap_count);

	if (!atomic_dec_and_mutex_lock(&event->mmap_count, &event->mmap_mutex))
		goto out_put;

	ring_buffer_attach(event, NULL);
	mutex_unlock(&event->mmap_mutex);

	/* If there's still other mmap()s of this buffer, we're done. */
	if (atomic_read(&rb->mmap_count))
		goto out_put;

	/*
 * No other mmap()s, detach from all other events that might redirect
 * into the now unreachable buffer. Somewhat complicated by the
 * fact that rb::event_lock otherwise nests inside mmap_mutex.
 */
again:
	rcu_read_lock();
	list_for_each_entry_rcu(event, &rb->event_list, rb_entry) {
		if (!atomic_long_inc_not_zero(&event->refcount)) {
			/*
 * This event is en-route to free_event() which will
 * detach it and remove it from the list.
 */
			continue;
		}
		rcu_read_unlock();

		mutex_lock(&event->mmap_mutex);
		/*
 * Check we didn't race with perf_event_set_output() which can
 * swizzle the rb from under us while we were waiting to
 * acquire mmap_mutex.
 *
 * If we find a different rb; ignore this event, a next
 * iteration will no longer find it on the list. We have to
 * still restart the iteration to make sure we're not now
 * iterating the wrong list.
 */
		if (event->rb == rb)
			ring_buffer_attach(event, NULL);

		mutex_unlock(&event->mmap_mutex);
		put_event(event);

		/*
 * Restart the iteration; either we're on the wrong list or
 * destroyed its integrity by doing a deletion.
 */
		goto again;
	}
	rcu_read_unlock();

	/*
 * It could be there's still a few 0-ref events on the list; they'll
 * get cleaned up by free_event() -- they'll also still have their
 * ref on the rb and will free it whenever they are done with it.
 *
 * Aside from that, this buffer is 'fully' detached and unmapped,
 * undo the VM accounting.
 */

	atomic_long_sub((size >> PAGE_SHIFT) + 1, &mmap_user->locked_vm);
	vma->vm_mm->pinned_vm -= mmap_locked;
	free_uid(mmap_user);

out_put:
	ring_buffer_put(rb); /* could be last */
}

static const struct vm_operations_struct perf_mmap_vmops = {
	.open		= perf_mmap_open,
	.close		= perf_mmap_close, /* non mergable */
	.fault		= perf_mmap_fault,
	.page_mkwrite	= perf_mmap_fault,
};

static int perf_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct perf_event *event = file->private_data;
	unsigned long user_locked, user_lock_limit;
	struct user_struct *user = current_user();
	unsigned long locked, lock_limit;
	struct ring_buffer *rb = NULL;
	unsigned long vma_size;
	unsigned long nr_pages;
	long user_extra = 0, extra = 0;
	int ret = 0, flags = 0;

	/*
 * Don't allow mmap() of inherited per-task counters. This would
 * create a performance issue due to all children writing to the
 * same rb.
 */
	if (event->cpu == -1 && event->attr.inherit)
		return -EINVAL;

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	vma_size = vma->vm_end - vma->vm_start;

	if (vma->vm_pgoff == 0) {
		nr_pages = (vma_size / PAGE_SIZE) - 1;
	} else {
		/*
 * AUX area mapping: if rb->aux_nr_pages != 0, it's already
 * mapped, all subsequent mappings should have the same size
 * and offset. Must be above the normal perf buffer.
 */
		u64 aux_offset, aux_size;

		if (!event->rb)
			return -EINVAL;

		nr_pages = vma_size / PAGE_SIZE;

		mutex_lock(&event->mmap_mutex);
		ret = -EINVAL;

		rb = event->rb;
		if (!rb)
			goto aux_unlock;

		aux_offset = ACCESS_ONCE(rb->user_page->aux_offset);
		aux_size = ACCESS_ONCE(rb->user_page->aux_size);

		if (aux_offset < perf_data_size(rb) + PAGE_SIZE)
			goto aux_unlock;

		if (aux_offset != vma->vm_pgoff << PAGE_SHIFT)
			goto aux_unlock;

		/* already mapped with a different offset */
		if (rb_has_aux(rb) && rb->aux_pgoff != vma->vm_pgoff)
			goto aux_unlock;

		if (aux_size != vma_size || aux_size != nr_pages * PAGE_SIZE)
			goto aux_unlock;

		/* already mapped with a different size */
		if (rb_has_aux(rb) && rb->aux_nr_pages != nr_pages)
			goto aux_unlock;

		if (!is_power_of_2(nr_pages))
			goto aux_unlock;

		if (!atomic_inc_not_zero(&rb->mmap_count))
			goto aux_unlock;

		if (rb_has_aux(rb)) {
			atomic_inc(&rb->aux_mmap_count);
			ret = 0;
			goto unlock;
		}

		atomic_set(&rb->aux_mmap_count, 1);
		user_extra = nr_pages;

		goto accounting;
	}

	/*
 * If we have rb pages ensure they're a power-of-two number, so we
 * can do bitmasks instead of modulo.
 */
	if (nr_pages != 0 && !is_power_of_2(nr_pages))
		return -EINVAL;

	if (vma_size != PAGE_SIZE * (1 + nr_pages))
		return -EINVAL;

	WARN_ON_ONCE(event->ctx->parent_ctx);
again:
	mutex_lock(&event->mmap_mutex);
	if (event->rb) {
		if (event->rb->nr_pages != nr_pages) {
			ret = -EINVAL;
			goto unlock;
		}

		if (!atomic_inc_not_zero(&event->rb->mmap_count)) {
			/*
 * Raced against perf_mmap_close() through
 * perf_event_set_output(). Try again, hope for better
 * luck.
 */
			mutex_unlock(&event->mmap_mutex);
			goto again;
		}

		goto unlock;
	}

	user_extra = nr_pages + 1;

accounting:
	user_lock_limit = sysctl_perf_event_mlock >> (PAGE_SHIFT - 10);

	/*
 * Increase the limit linearly with more CPUs:
 */
	user_lock_limit *= num_online_cpus();

	user_locked = atomic_long_read(&user->locked_vm) + user_extra;

	if (user_locked > user_lock_limit)
		extra = user_locked - user_lock_limit;

	lock_limit = rlimit(RLIMIT_MEMLOCK);
	lock_limit >>= PAGE_SHIFT;
	locked = vma->vm_mm->pinned_vm + extra;

	if ((locked > lock_limit) && perf_paranoid_tracepoint_raw() &&
		!capable(CAP_IPC_LOCK)) {
		ret = -EPERM;
		goto unlock;
	}

	WARN_ON(!rb && event->rb);

	if (vma->vm_flags & VM_WRITE)
		flags |= RING_BUFFER_WRITABLE;

	if (!rb) {
		rb = rb_alloc(nr_pages,
			      event->attr.watermark ? event->attr.wakeup_watermark : 0,
			      event->cpu, flags);

		if (!rb) {
			ret = -ENOMEM;
			goto unlock;
		}

		atomic_set(&rb->mmap_count, 1);
		rb->mmap_user = get_current_user();
		rb->mmap_locked = extra;

		ring_buffer_attach(event, rb);

		perf_event_init_userpage(event);
		perf_event_update_userpage(event);
	} else {
		ret = rb_alloc_aux(rb, event, vma->vm_pgoff, nr_pages,
				   event->attr.aux_watermark, flags);
		if (!ret)
			rb->aux_mmap_locked = extra;
	}

unlock:
	if (!ret) {
		atomic_long_add(user_extra, &user->locked_vm);
		vma->vm_mm->pinned_vm += extra;

		atomic_inc(&event->mmap_count);
	} else if (rb) {
		atomic_dec(&rb->mmap_count);
	}
aux_unlock:
	mutex_unlock(&event->mmap_mutex);

	/*
 * Since pinned accounting is per vm we cannot allow fork() to copy our
 * vma.
 */
	vma->vm_flags |= VM_DONTCOPY | VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_ops = &perf_mmap_vmops;

	if (event->pmu->event_mapped)
		event->pmu->event_mapped(event);

	return ret;
}

static int perf_fasync(int fd, struct file *filp, int on)
{
	struct inode *inode = file_inode(filp);
	struct perf_event *event = filp->private_data;
	int retval;

	inode_lock(inode);
	retval = fasync_helper(fd, filp, on, &event->fasync);
	inode_unlock(inode);

	if (retval < 0)
		return retval;

	return 0;
}

static const struct file_operations perf_fops = {
	.llseek			= no_llseek,
	.release		= perf_release,
	.read			= perf_read,
	.poll			= perf_poll,
	.unlocked_ioctl		= perf_ioctl,
	.compat_ioctl		= perf_compat_ioctl,
	.mmap			= perf_mmap,
	.fasync			= perf_fasync,
};

/*
 * Perf event wakeup
 *
 * If there's data, ensure we set the poll() state and publish everything
 * to user-space before waking everybody up.
 */

static inline struct fasync_struct **perf_event_fasync(struct perf_event *event)
{
	/* only the parent has fasync state */
	if (event->parent)
		event = event->parent;
	return &event->fasync;
}

void perf_event_wakeup(struct perf_event *event)
{
	ring_buffer_wakeup(event);

	if (event->pending_kill) {
		kill_fasync(perf_event_fasync(event), SIGIO, event->pending_kill);
		event->pending_kill = 0;
	}
}

static void perf_pending_event(struct irq_work *entry)
{
	struct perf_event *event = container_of(entry,
			struct perf_event, pending);
	int rctx;

	rctx = perf_swevent_get_recursion_context();
	/*
 * If we 'fail' here, that's OK, it means recursion is already disabled
 * and we won't recurse 'further'.
 */

	if (event->pending_disable) {
		event->pending_disable = 0;
		perf_event_disable_local(event);
	}

	if (event->pending_wakeup) {
		event->pending_wakeup = 0;
		perf_event_wakeup(event);
	}

	if (rctx >= 0)
		perf_swevent_put_recursion_context(rctx);
}

/*
 * We assume there is only KVM supporting the callbacks.
 * Later on, we might change it to a list if there is
 * another virtualization implementation supporting the callbacks.
 */
struct perf_guest_info_callbacks *perf_guest_cbs;

int perf_register_guest_info_callbacks(struct perf_guest_info_callbacks *cbs)
{
	perf_guest_cbs = cbs;
	return 0;
}
EXPORT_SYMBOL_GPL(perf_register_guest_info_callbacks);

int perf_unregister_guest_info_callbacks(struct perf_guest_info_callbacks *cbs)
{
	perf_guest_cbs = NULL;
	return 0;
}
EXPORT_SYMBOL_GPL(perf_unregister_guest_info_callbacks);

static void
perf_output_sample_regs(struct perf_output_handle *handle,
			struct pt_regs *regs, u64 mask)
{
	int bit;
	DECLARE_BITMAP(_mask, 64);

	bitmap_from_u64(_mask, mask);
	for_each_set_bit(bit, _mask, sizeof(mask) * BITS_PER_BYTE) {
		u64 val;

		val = perf_reg_value(regs, bit);
		perf_output_put(handle, val);
	}
}

static void perf_sample_regs_user(struct perf_regs *regs_user,
				  struct pt_regs *regs,
				  struct pt_regs *regs_user_copy)
{
	if (user_mode(regs)) {
		regs_user->abi = perf_reg_abi(current);
		regs_user->regs = regs;
	} else if (current->mm) {
		perf_get_regs_user(regs_user, regs, regs_user_copy);
	} else {
		regs_user->abi = PERF_SAMPLE_REGS_ABI_NONE;
		regs_user->regs = NULL;
	}
}

static void perf_sample_regs_intr(struct perf_regs *regs_intr,
				  struct pt_regs *regs)
{
	regs_intr->regs = regs;
	regs_intr->abi  = perf_reg_abi(current);
}


/*
 * Get remaining task size from user stack pointer.
 *
 * It'd be better to take stack vma map and limit this more
 * precisly, but there's no way to get it safely under interrupt,
 * so using TASK_SIZE as limit.
 */
static u64 perf_ustack_task_size(struct pt_regs *regs)
{
	unsigned long addr = perf_user_stack_pointer(regs);

	if (!addr || addr >= TASK_SIZE)
		return 0;

	return TASK_SIZE - addr;
}

static u16
perf_sample_ustack_size(u16 stack_size, u16 header_size,
			struct pt_regs *regs)
{
	u64 task_size;

	/* No regs, no stack pointer, no dump. */
	if (!regs)
		return 0;

	/*
 * Check if we fit in with the requested stack size into the:
 * - TASK_SIZE
 * If we don't, we limit the size to the TASK_SIZE.
 *
 * - remaining sample size
 * If we don't, we customize the stack size to
 * fit in to the remaining sample size.
 */

	task_size  = min((u64) USHRT_MAX, perf_ustack_task_size(regs));
	stack_size = min(stack_size, (u16) task_size);

	/* Current header size plus static size and dynamic size. */
	header_size += 2 * sizeof(u64);

	/* Do we fit in with the current stack dump size? */
	if ((u16) (header_size + stack_size) < header_size) {
		/*
 * If we overflow the maximum size for the sample,
 * we customize the stack dump size to fit in.
 */
		stack_size = USHRT_MAX - header_size - sizeof(u64);
		stack_size = round_up(stack_size, sizeof(u64));
	}

	return stack_size;
}

static void
perf_output_sample_ustack(struct perf_output_handle *handle, u64 dump_size,
			  struct pt_regs *regs)
{
	/* Case of a kernel thread, nothing to dump */
	if (!regs) {
		u64 size = 0;
		perf_output_put(handle, size);
	} else {
		unsigned long sp;
		unsigned int rem;
		u64 dyn_size;

		/*
 * We dump:
 * static size
 * - the size requested by user or the best one we can fit
 * in to the sample max size
 * data
 * - user stack dump data
 * dynamic size
 * - the actual dumped size
 */

		/* Static size. */
		perf_output_put(handle, dump_size);

		/* Data. */
		sp = perf_user_stack_pointer(regs);
		rem = __output_copy_user(handle, (void *) sp, dump_size);
		dyn_size = dump_size - rem;

		perf_output_skip(handle, rem);

		/* Dynamic size. */
		perf_output_put(handle, dyn_size);
	}
}

static void __perf_event_header__init_id(struct perf_event_header *header,
					 struct perf_sample_data *data,
					 struct perf_event *event)
{
	u64 sample_type = event->attr.sample_type;

	data->type = sample_type;
	header->size += event->id_header_size;

	if (sample_type & PERF_SAMPLE_TID) {
		/* namespace issues */
		data->tid_entry.pid = perf_event_pid(event, current);
		data->tid_entry.tid = perf_event_tid(event, current);
	}

	if (sample_type & PERF_SAMPLE_TIME)
		data->time = perf_event_clock(event);

	if (sample_type & (PERF_SAMPLE_ID | PERF_SAMPLE_IDENTIFIER))
		data->id = primary_event_id(event);

	if (sample_type & PERF_SAMPLE_STREAM_ID)
		data->stream_id = event->id;

	if (sample_type & PERF_SAMPLE_CPU) {
		data->cpu_entry.cpu	 = raw_smp_processor_id();
		data->cpu_entry.reserved = 0;
	}
}

void perf_event_header__init_id(struct perf_event_header *header,
				struct perf_sample_data *data,
				struct perf_event *event)
{
	if (event->attr.sample_id_all)
		__perf_event_header__init_id(header, data, event);
}

static void __perf_event__output_id_sample(struct perf_output_handle *handle,
					   struct perf_sample_data *data)
{
	u64 sample_type = data->type;

	if (sample_type & PERF_SAMPLE_TID)
		perf_output_put(handle, data->tid_entry);

	if (sample_type & PERF_SAMPLE_TIME)
		perf_output_put(handle, data->time);

	if (sample_type & PERF_SAMPLE_ID)
		perf_output_put(handle, data->id);

	if (sample_type & PERF_SAMPLE_STREAM_ID)
		perf_output_put(handle, data->stream_id);

	if (sample_type & PERF_SAMPLE_CPU)
		perf_output_put(handle, data->cpu_entry);

	if (sample_type & PERF_SAMPLE_IDENTIFIER)
		perf_output_put(handle, data->id);
}

void perf_event__output_id_sample(struct perf_event *event,
				  struct perf_output_handle *handle,
				  struct perf_sample_data *sample)
{
	if (event->attr.sample_id_all)
		__perf_event__output_id_sample(handle, sample);
}

static void perf_output_read_one(struct perf_output_handle *handle,
				 struct perf_event *event,
				 u64 enabled, u64 running)
{
	u64 read_format = event->attr.read_format;
	u64 values[4];
	int n = 0;

	values[n++] = perf_event_count(event);
	if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED) {
		values[n++] = enabled +
			atomic64_read(&event->child_total_time_enabled);
	}
	if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING) {
		values[n++] = running +
			atomic64_read(&event->child_total_time_running);
	}
	if (read_format & PERF_FORMAT_ID)
		values[n++] = primary_event_id(event);

	__output_copy(handle, values, n * sizeof(u64));
}

/*
 * XXX PERF_FORMAT_GROUP vs inherited events seems difficult.
 */
static void perf_output_read_group(struct perf_output_handle *handle,
			    struct perf_event *event,
			    u64 enabled, u64 running)
{
	struct perf_event *leader = event->group_leader, *sub;
	u64 read_format = event->attr.read_format;
	u64 values[5];
	int n = 0;

	values[n++] = 1 + leader->nr_siblings;

	if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED)
		values[n++] = enabled;

	if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING)
		values[n++] = running;

	if (leader != event)
		leader->pmu->read(leader);

	values[n++] = perf_event_count(leader);
	if (read_format & PERF_FORMAT_ID)
		values[n++] = primary_event_id(leader);

	__output_copy(handle, values, n * sizeof(u64));

	list_for_each_entry(sub, &leader->sibling_list, group_entry) {
		n = 0;

		if ((sub != event) &&
		    (sub->state == PERF_EVENT_STATE_ACTIVE))
			sub->pmu->read(sub);

		values[n++] = perf_event_count(sub);
		if (read_format & PERF_FORMAT_ID)
			values[n++] = primary_event_id(sub);

		__output_copy(handle, values, n * sizeof(u64));
	}
}

#define PERF_FORMAT_TOTAL_TIMES (PERF_FORMAT_TOTAL_TIME_ENABLED|\
 PERF_FORMAT_TOTAL_TIME_RUNNING)

static void perf_output_read(struct perf_output_handle *handle,
			     struct perf_event *event)
{
	u64 enabled = 0, running = 0, now;
	u64 read_format = event->attr.read_format;

	/*
 * compute total_time_enabled, total_time_running
 * based on snapshot values taken when the event
 * was last scheduled in.
 *
 * we cannot simply called update_context_time()
 * because of locking issue as we are called in
 * NMI context
 */
	if (read_format & PERF_FORMAT_TOTAL_TIMES)
		calc_timer_values(event, &now, &enabled, &running);

	if (event->attr.read_format & PERF_FORMAT_GROUP)
		perf_output_read_group(handle, event, enabled, running);
	else
		perf_output_read_one(handle, event, enabled, running);
}

void perf_output_sample(struct perf_output_handle *handle,
			struct perf_event_header *header,
			struct perf_sample_data *data,
			struct perf_event *event)
{
	u64 sample_type = data->type;

	perf_output_put(handle, *header);

	if (sample_type & PERF_SAMPLE_IDENTIFIER)
		perf_output_put(handle, data->id);

	if (sample_type & PERF_SAMPLE_IP)
		perf_output_put(handle, data->ip);

	if (sample_type & PERF_SAMPLE_TID)
		perf_output_put(handle, data->tid_entry);

	if (sample_type & PERF_SAMPLE_TIME)
		perf_output_put(handle, data->time);

	if (sample_type & PERF_SAMPLE_ADDR)
		perf_output_put(handle, data->addr);

	if (sample_type & PERF_SAMPLE_ID)
		perf_output_put(handle, data->id);

	if (sample_type & PERF_SAMPLE_STREAM_ID)
		perf_output_put(handle, data->stream_id);

	if (sample_type & PERF_SAMPLE_CPU)
		perf_output_put(handle, data->cpu_entry);

	if (sample_type & PERF_SAMPLE_PERIOD)
		perf_output_put(handle, data->period);

	if (sample_type & PERF_SAMPLE_READ)
		perf_output_read(handle, event);

	if (sample_type & PERF_SAMPLE_CALLCHAIN) {
		if (data->callchain) {
			int size = 1;

			if (data->callchain)
				size += data->callchain->nr;

			size *= sizeof(u64);

			__output_copy(handle, data->callchain, size);
		} else {
			u64 nr = 0;
			perf_output_put(handle, nr);
		}
	}

	if (sample_type & PERF_SAMPLE_RAW) {
		struct perf_raw_record *raw = data->raw;

		if (raw) {
			struct perf_raw_frag *frag = &raw->frag;

			perf_output_put(handle, raw->size);
			do {
				if (frag->copy) {
					__output_custom(handle, frag->copy,
							frag->data, frag->size);
				} else {
					__output_copy(handle, frag->data,
						      frag->size);
				}
				if (perf_raw_frag_last(frag))
					break;
				frag = frag->next;
			} while (1);
			if (frag->pad)
				__output_skip(handle, NULL, frag->pad);
		} else {
			struct {
				u32	size;
				u32	data;
			} raw = {
				.size = sizeof(u32),
				.data = 0,
			};
			perf_output_put(handle, raw);
		}
	}

	if (sample_type & PERF_SAMPLE_BRANCH_STACK) {
		if (data->br_stack) {
			size_t size;

			size = data->br_stack->nr
			     * sizeof(struct perf_branch_entry);

			perf_output_put(handle, data->br_stack->nr);
			perf_output_copy(handle, data->br_stack->entries, size);
		} else {
			/*
 * we always store at least the value of nr
 */
			u64 nr = 0;
			perf_output_put(handle, nr);
		}
	}

	if (sample_type & PERF_SAMPLE_REGS_USER) {
		u64 abi = data->regs_user.abi;

		/*
 * If there are no regs to dump, notice it through
 * first u64 being zero (PERF_SAMPLE_REGS_ABI_NONE).
 */
		perf_output_put(handle, abi);

		if (abi) {
			u64 mask = event->attr.sample_regs_user;
			perf_output_sample_regs(handle,
						data->regs_user.regs,
						mask);
		}
	}

	if (sample_type & PERF_SAMPLE_STACK_USER) {
		perf_output_sample_ustack(handle,
					  data->stack_user_size,
					  data->regs_user.regs);
	}

	if (sample_type & PERF_SAMPLE_WEIGHT)
		perf_output_put(handle, data->weight);

	if (sample_type & PERF_SAMPLE_DATA_SRC)
		perf_output_put(handle, data->data_src.val);

	if (sample_type & PERF_SAMPLE_TRANSACTION)
		perf_output_put(handle, data->txn);

	if (sample_type & PERF_SAMPLE_REGS_INTR) {
		u64 abi = data->regs_intr.abi;
		/*
 * If there are no regs to dump, notice it through
 * first u64 being zero (PERF_SAMPLE_REGS_ABI_NONE).
 */
		perf_output_put(handle, abi);

		if (abi) {
			u64 mask = event->attr.sample_regs_intr;

			perf_output_sample_regs(handle,
						data->regs_intr.regs,
						mask);
		}
	}

	if (!event->attr.watermark) {
		int wakeup_events = event->attr.wakeup_events;

		if (wakeup_events) {
			struct ring_buffer *rb = handle->rb;
			int events = local_inc_return(&rb->events);

			if (events >= wakeup_events) {
				local_sub(wakeup_events, &rb->events);
				local_inc(&rb->wakeup);
			}
		}
	}
}

void perf_prepare_sample(struct perf_event_header *header,
			 struct perf_sample_data *data,
			 struct perf_event *event,
			 struct pt_regs *regs)
{
	u64 sample_type = event->attr.sample_type;

	header->type = PERF_RECORD_SAMPLE;
	header->size = sizeof(*header) + event->header_size;

	header->misc = 0;
	header->misc |= perf_misc_flags(regs);

	__perf_event_header__init_id(header, data, event);

	if (sample_type & PERF_SAMPLE_IP)
		data->ip = perf_instruction_pointer(regs);

	if (sample_type & PERF_SAMPLE_CALLCHAIN) {
		int size = 1;

		data->callchain = perf_callchain(event, regs);

		if (data->callchain)
			size += data->callchain->nr;

		header->size += size * sizeof(u64);
	}

	if (sample_type & PERF_SAMPLE_RAW) {
		struct perf_raw_record *raw = data->raw;
		int size;

		if (raw) {
			struct perf_raw_frag *frag = &raw->frag;
			u32 sum = 0;

			do {
				sum += frag->size;
				if (perf_raw_frag_last(frag))
					break;
				frag = frag->next;
			} while (1);

			size = round_up(sum + sizeof(u32), sizeof(u64));
			raw->size = size - sizeof(u32);
			frag->pad = raw->size - sum;
		} else {
			size = sizeof(u64);
		}

		header->size += size;
	}

	if (sample_type & PERF_SAMPLE_BRANCH_STACK) {
		int size = sizeof(u64); /* nr */
		if (data->br_stack) {
			size += data->br_stack->nr
			      * sizeof(struct perf_branch_entry);
		}
		header->size += size;
	}

	if (sample_type & (PERF_SAMPLE_REGS_USER | PERF_SAMPLE_STACK_USER))
		perf_sample_regs_user(&data->regs_user, regs,
				      &data->regs_user_copy);

	if (sample_type & PERF_SAMPLE_REGS_USER) {
		/* regs dump ABI info */
		int size = sizeof(u64);

		if (data->regs_user.regs) {
			u64 mask = event->attr.sample_regs_user;
			size += hweight64(mask) * sizeof(u64);
		}

		header->size += size;
	}

	if (sample_type & PERF_SAMPLE_STACK_USER) {
		/*
 * Either we need PERF_SAMPLE_STACK_USER bit to be allways
 * processed as the last one or have additional check added
 * in case new sample type is added, because we could eat
 * up the rest of the sample size.
 */
		u16 stack_size = event->attr.sample_stack_user;
		u16 size = sizeof(u64);

		stack_size = perf_sample_ustack_size(stack_size, header->size,
						     data->regs_user.regs);

		/*
 * If there is something to dump, add space for the dump
 * itself and for the field that tells the dynamic size,
 * which is how many have been actually dumped.
 */
		if (stack_size)
			size += sizeof(u64) + stack_size;

		data->stack_user_size = stack_size;
		header->size += size;
	}

	if (sample_type & PERF_SAMPLE_REGS_INTR) {
		/* regs dump ABI info */
		int size = sizeof(u64);

		perf_sample_regs_intr(&data->regs_intr, regs);

		if (data->regs_intr.regs) {
			u64 mask = event->attr.sample_regs_intr;

			size += hweight64(mask) * sizeof(u64);
		}

		header->size += size;
	}
}

static void __always_inline
__perf_event_output(struct perf_event *event,
		    struct perf_sample_data *data,
		    struct pt_regs *regs,
		    int (*output_begin)(struct perf_output_handle *,
					struct perf_event *,
					unsigned int))
{
	struct perf_output_handle handle;
	struct perf_event_header header;

	/* protect the callchain buffers */
	rcu_read_lock();

	perf_prepare_sample(&header, data, event, regs);

	if (output_begin(&handle, event, header.size))
		goto exit;

	perf_output_sample(&handle, &header, data, event);

	perf_output_end(&handle);

exit:
	rcu_read_unlock();
}

void
perf_event_output_forward(struct perf_event *event,
			 struct perf_sample_data *data,
			 struct pt_regs *regs)
{
	__perf_event_output(event, data, regs, perf_output_begin_forward);
}

void
perf_event_output_backward(struct perf_event *event,
			   struct perf_sample_data *data,
			   struct pt_regs *regs)
{
	__perf_event_output(event, data, regs, perf_output_begin_backward);
}

void
perf_event_output(struct perf_event *event,
		  struct perf_sample_data *data,
		  struct pt_regs *regs)
{
	__perf_event_output(event, data, regs, perf_output_begin);
}

/*
 * read event_id
 */

struct perf_read_event {
	struct perf_event_header	header;

	u32				pid;
	u32				tid;
};

static void
perf_event_read_event(struct perf_event *event,
			struct task_struct *task)
{
	struct perf_output_handle handle;
	struct perf_sample_data sample;
	struct perf_read_event read_event = {
		.header = {
			.type = PERF_RECORD_READ,
			.misc = 0,
			.size = sizeof(read_event) + event->read_size,
		},
		.pid = perf_event_pid(event, task),
		.tid = perf_event_tid(event, task),
	};
	int ret;

	perf_event_header__init_id(&read_event.header, &sample, event);
	ret = perf_output_begin(&handle, event, read_event.header.size);
	if (ret)
		return;

	perf_output_put(&handle, read_event);
	perf_output_read(&handle, event);
	perf_event__output_id_sample(event, &handle, &sample);

	perf_output_end(&handle);
}

typedef void (perf_iterate_f)(struct perf_event *event, void *data);

static void
perf_iterate_ctx(struct perf_event_context *ctx,
		   perf_iterate_f output,
		   void *data, bool all)
{
	struct perf_event *event;

	list_for_each_entry_rcu(event, &ctx->event_list, event_entry) {
		if (!all) {
			if (event->state < PERF_EVENT_STATE_INACTIVE)
				continue;
			if (!event_filter_match(event))
				continue;
		}

		output(event, data);
	}
}

static void perf_iterate_sb_cpu(perf_iterate_f output, void *data)
{
	struct pmu_event_list *pel = this_cpu_ptr(&pmu_sb_events);
	struct perf_event *event;

	list_for_each_entry_rcu(event, &pel->list, sb_list) {
		/*
 * Skip events that are not fully formed yet; ensure that
 * if we observe event->ctx, both event and ctx will be
 * complete enough. See perf_install_in_context().
 */
		if (!smp_load_acquire(&event->ctx))
			continue;

		if (event->state < PERF_EVENT_STATE_INACTIVE)
			continue;
		if (!event_filter_match(event))
			continue;
		output(event, data);
	}
}

/*
 * Iterate all events that need to receive side-band events.
 *
 * For new callers; ensure that account_pmu_sb_event() includes
 * your event, otherwise it might not get delivered.
 */
static void
perf_iterate_sb(perf_iterate_f output, void *data,
	       struct perf_event_context *task_ctx)
{
	struct perf_event_context *ctx;
	int ctxn;

	rcu_read_lock();
	preempt_disable();

	/*
 * If we have task_ctx != NULL we only notify the task context itself.
 * The task_ctx is set only for EXIT events before releasing task
 * context.
 */
	if (task_ctx) {
		perf_iterate_ctx(task_ctx, output, data, false);
		goto done;
	}

	perf_iterate_sb_cpu(output, data);

	for_each_task_context_nr(ctxn) {
		ctx = rcu_dereference(current->perf_event_ctxp[ctxn]);
		if (ctx)
			perf_iterate_ctx(ctx, output, data, false);
	}
done:
	preempt_enable();
	rcu_read_unlock();
}

/*
 * Clear all file-based filters at exec, they'll have to be
 * re-instated when/if these objects are mmapped again.
 */
static void perf_event_addr_filters_exec(struct perf_event *event, void *data)
{
	struct perf_addr_filters_head *ifh = perf_event_addr_filters(event);
	struct perf_addr_filter *filter;
	unsigned int restart = 0, count = 0;
	unsigned long flags;

	if (!has_addr_filter(event))
		return;

	raw_spin_lock_irqsave(&ifh->lock, flags);
	list_for_each_entry(filter, &ifh->list, entry) {
		if (filter->inode) {
			event->addr_filters_offs[count] = 0;
			restart++;
		}

		count++;
	}

	if (restart)
		event->addr_filters_gen++;
	raw_spin_unlock_irqrestore(&ifh->lock, flags);

	if (restart)
		perf_event_stop(event, 1);
}

void perf_event_exec(void)
{
	struct perf_event_context *ctx;
	int ctxn;

	rcu_read_lock();
	for_each_task_context_nr(ctxn) {
		ctx = current->perf_event_ctxp[ctxn];
		if (!ctx)
			continue;

		perf_event_enable_on_exec(ctxn);

		perf_iterate_ctx(ctx, perf_event_addr_filters_exec, NULL,
				   true);
	}
	rcu_read_unlock();
}

struct remote_output {
	struct ring_buffer	*rb;
	int			err;
};

static void __perf_event_output_stop(struct perf_event *event, void *data)
{
	struct perf_event *parent = event->parent;
	struct remote_output *ro = data;
	struct ring_buffer *rb = ro->rb;
	struct stop_event_data sd = {
		.event	= event,
	};

	if (!has_aux(event))
		return;

	if (!parent)
		parent = event;

	/*
 * In case of inheritance, it will be the parent that links to the
 * ring-buffer, but it will be the child that's actually using it.
 *
 * We are using event::rb to determine if the event should be stopped,
 * however this may race with ring_buffer_attach() (through set_output),
 * which will make us skip the event that actually needs to be stopped.
 * So ring_buffer_attach() has to stop an aux event before re-assigning
 * its rb pointer.
 */
	if (rcu_dereference(parent->rb) == rb)
		ro->err = __perf_event_stop(&sd);
}

static int __perf_pmu_output_stop(void *info)
{
	struct perf_event *event = info;
	struct pmu *pmu = event->pmu;
	struct perf_cpu_context *cpuctx = this_cpu_ptr(pmu->pmu_cpu_context);
	struct remote_output ro = {
		.rb	= event->rb,
	};

	rcu_read_lock();
	perf_iterate_ctx(&cpuctx->ctx, __perf_event_output_stop, &ro, false);
	if (cpuctx->task_ctx)
		perf_iterate_ctx(cpuctx->task_ctx, __perf_event_output_stop,
				   &ro, false);
	rcu_read_unlock();

	return ro.err;
}

static void perf_pmu_output_stop(struct perf_event *event)
{
	struct perf_event *iter;
	int err, cpu;

restart:
	rcu_read_lock();
	list_for_each_entry_rcu(iter, &event->rb->event_list, rb_entry) {
		/*
 * For per-CPU events, we need to make sure that neither they
 * nor their children are running; for cpu==-1 events it's
 * sufficient to stop the event itself if it's active, since
 * it can't have children.
 */
		cpu = iter->cpu;
		if (cpu == -1)
			cpu = READ_ONCE(iter->oncpu);

		if (cpu == -1)
			continue;

		err = cpu_function_call(cpu, __perf_pmu_output_stop, event);
		if (err == -EAGAIN) {
			rcu_read_unlock();
			goto restart;
		}
	}
	rcu_read_unlock();
}

/*
 * task tracking -- fork/exit
 *
 * enabled by: attr.comm | attr.mmap | attr.mmap2 | attr.mmap_data | attr.task
 */

struct perf_task_event {
	struct task_struct		*task;
	struct perf_event_context	*task_ctx;

	struct {
		struct perf_event_header	header;

		u32				pid;
		u32				ppid;
		u32				tid;
		u32				ptid;
		u64				time;
	} event_id;
};

static int perf_event_task_match(struct perf_event *event)
{
	return event->attr.comm  || event->attr.mmap ||
	       event->attr.mmap2 || event->attr.mmap_data ||
	       event->attr.task;
}

static void perf_event_task_output(struct perf_event *event,
				   void *data)
{
	struct perf_task_event *task_event = data;
	struct perf_output_handle handle;
	struct perf_sample_data	sample;
	struct task_struct *task = task_event->task;
	int ret, size = task_event->event_id.header.size;

	if (!perf_event_task_match(event))
		return;

	perf_event_header__init_id(&task_event->event_id.header, &sample, event);

	ret = perf_output_begin(&handle, event,
				task_event->event_id.header.size);
	if (ret)
		goto out;

	task_event->event_id.pid = perf_event_pid(event, task);
	task_event->event_id.ppid = perf_event_pid(event, current);

	task_event->event_id.tid = perf_event_tid(event, task);
	task_event->event_id.ptid = perf_event_tid(event, current);

	task_event->event_id.time = perf_event_clock(event);

	perf_output_put(&handle, task_event->event_id);

	perf_event__output_id_sample(event, &handle, &sample);

	perf_output_end(&handle);
out:
	task_event->event_id.header.size = size;
}

static void perf_event_task(struct task_struct *task,
			      struct perf_event_context *task_ctx,
			      int new)
{
	struct perf_task_event task_event;

	if (!atomic_read(&nr_comm_events) &&
	    !atomic_read(&nr_mmap_events) &&
	    !atomic_read(&nr_task_events))
		return;

	task_event = (struct perf_task_event){
		.task	  = task,
		.task_ctx = task_ctx,
		.event_id    = {
			.header = {
				.type = new ? PERF_RECORD_FORK : PERF_RECORD_EXIT,
				.misc = 0,
				.size = sizeof(task_event.event_id),
			},
			/* .pid */
			/* .ppid */
			/* .tid */
			/* .ptid */
			/* .time */
		},
	};

	perf_iterate_sb(perf_event_task_output,
		       &task_event,
		       task_ctx);
}

void perf_event_fork(struct task_struct *task)
{
	perf_event_task(task, NULL, 1);
}

/*
 * comm tracking
 */

struct perf_comm_event {
	struct task_struct	*task;
	char			*comm;
	int			comm_size;

	struct {
		struct perf_event_header	header;

		u32				pid;
		u32				tid;
	} event_id;
};

static int perf_event_comm_match(struct perf_event *event)
{
	return event->attr.comm;
}

static void perf_event_comm_output(struct perf_event *event,
				   void *data)
{
	struct perf_comm_event *comm_event = data;
	struct perf_output_handle handle;
	struct perf_sample_data sample;
	int size = comm_event->event_id.header.size;
	int ret;

	if (!perf_event_comm_match(event))
		return;

	perf_event_header__init_id(&comm_event->event_id.header, &sample, event);
	ret = perf_output_begin(&handle, event,
				comm_event->event_id.header.size);

	if (ret)
		goto out;

	comm_event->event_id.pid = perf_event_pid(event, comm_event->task);
	comm_event->event_id.tid = perf_event_tid(event, comm_event->task);

	perf_output_put(&handle, comm_event->event_id);
	__output_copy(&handle, comm_event->comm,
				   comm_event->comm_size);

	perf_event__output_id_sample(event, &handle, &sample);

	perf_output_end(&handle);
out:
	comm_event->event_id.header.size = size;
}

static void perf_event_comm_event(struct perf_comm_event *comm_event)
{
	char comm[TASK_COMM_LEN];
	unsigned int size;

	memset(comm, 0, sizeof(comm));
	strlcpy(comm, comm_event->task->comm, sizeof(comm));
	size = ALIGN(strlen(comm)+1, sizeof(u64));

	comm_event->comm = comm;
	comm_event->comm_size = size;

	comm_event->event_id.header.size = sizeof(comm_event->event_id) + size;

	perf_iterate_sb(perf_event_comm_output,
		       comm_event,
		       NULL);
}

void perf_event_comm(struct task_struct *task, bool exec)
{
	struct perf_comm_event comm_event;

	if (!atomic_read(&nr_comm_events))
		return;

	comm_event = (struct perf_comm_event){
		.task	= task,
		/* .comm */
		/* .comm_size */
		.event_id  = {
			.header = {
				.type = PERF_RECORD_COMM,
				.misc = exec ? PERF_RECORD_MISC_COMM_EXEC : 0,
				/* .size */
			},
			/* .pid */
			/* .tid */
		},
	};

	perf_event_comm_event(&comm_event);
}

/*
 * mmap tracking
 */

struct perf_mmap_event {
	struct vm_area_struct	*vma;

	const char		*file_name;
	int			file_size;
	int			maj, min;
	u64			ino;
	u64			ino_generation;
	u32			prot, flags;

	struct {
		struct perf_event_header	header;

		u32				pid;
		u32				tid;
		u64				start;
		u64				len;
		u64				pgoff;
	} event_id;
};

static int perf_event_mmap_match(struct perf_event *event,
				 void *data)
{
	struct perf_mmap_event *mmap_event = data;
	struct vm_area_struct *vma = mmap_event->vma;
	int executable = vma->vm_flags & VM_EXEC;

	return (!executable && event->attr.mmap_data) ||
	       (executable && (event->attr.mmap || event->attr.mmap2));
}

static void perf_event_mmap_output(struct perf_event *event,
				   void *data)
{
	struct perf_mmap_event *mmap_event = data;
	struct perf_output_handle handle;
	struct perf_sample_data sample;
	int size = mmap_event->event_id.header.size;
	int ret;

	if (!perf_event_mmap_match(event, data))
		return;

	if (event->attr.mmap2) {
		mmap_event->event_id.header.type = PERF_RECORD_MMAP2;
		mmap_event->event_id.header.size += sizeof(mmap_event->maj);
		mmap_event->event_id.header.size += sizeof(mmap_event->min);
		mmap_event->event_id.header.size += sizeof(mmap_event->ino);
		mmap_event->event_id.header.size += sizeof(mmap_event->ino_generation);
		mmap_event->event_id.header.size += sizeof(mmap_event->prot);
		mmap_event->event_id.header.size += sizeof(mmap_event->flags);
	}

	perf_event_header__init_id(&mmap_event->event_id.header, &sample, event);
	ret = perf_output_begin(&handle, event,
				mmap_event->event_id.header.size);
	if (ret)
		goto out;

	mmap_event->event_id.pid = perf_event_pid(event, current);
	mmap_event->event_id.tid = perf_event_tid(event, current);

	perf_output_put(&handle, mmap_event->event_id);

	if (event->attr.mmap2) {
		perf_output_put(&handle, mmap_event->maj);
		perf_output_put(&handle, mmap_event->min);
		perf_output_put(&handle, mmap_event->ino);
		perf_output_put(&handle, mmap_event->ino_generation);
		perf_output_put(&handle, mmap_event->prot);
		perf_output_put(&handle, mmap_event->flags);
	}

	__output_copy(&handle, mmap_event->file_name,
				   mmap_event->file_size);

	perf_event__output_id_sample(event, &handle, &sample);

	perf_output_end(&handle);
out:
	mmap_event->event_id.header.size = size;
}

static void perf_event_mmap_event(struct perf_mmap_event *mmap_event)
{
	struct vm_area_struct *vma = mmap_event->vma;
	struct file *file = vma->vm_file;
	int maj = 0, min = 0;
	u64 ino = 0, gen = 0;
	u32 prot = 0, flags = 0;
	unsigned int size;
	char tmp[16];
	char *buf = NULL;
	char *name;

	if (vma->vm_flags & VM_READ)
		prot |= PROT_READ;
	if (vma->vm_flags & VM_WRITE)
		prot |= PROT_WRITE;
	if (vma->vm_flags & VM_EXEC)
		prot |= PROT_EXEC;

	if (vma->vm_flags & VM_MAYSHARE)
		flags = MAP_SHARED;
	else
		flags = MAP_PRIVATE;

	if (vma->vm_flags & VM_DENYWRITE)
		flags |= MAP_DENYWRITE;
	if (vma->vm_flags & VM_MAYEXEC)
		flags |= MAP_EXECUTABLE;
	if (vma->vm_flags & VM_LOCKED)
		flags |= MAP_LOCKED;
	if (vma->vm_flags & VM_HUGETLB)
		flags |= MAP_HUGETLB;

	if (file) {
		struct inode *inode;
		dev_t dev;

		buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!buf) {
			name = "//enomem";
			goto cpy_name;
		}
		/*
 * d_path() works from the end of the rb backwards, so we
 * need to add enough zero bytes after the string to handle
 * the 64bit alignment we do later.
 */
		name = file_path(file, buf, PATH_MAX - sizeof(u64));
		if (IS_ERR(name)) {
			name = "//toolong";
			goto cpy_name;
		}
		inode = file_inode(vma->vm_file);
		dev = inode->i_sb->s_dev;
		ino = inode->i_ino;
		gen = inode->i_generation;
		maj = MAJOR(dev);
		min = MINOR(dev);

		goto got_name;
	} else {
		if (vma->vm_ops && vma->vm_ops->name) {
			name = (char *) vma->vm_ops->name(vma);
			if (name)
				goto cpy_name;
		}

		name = (char *)arch_vma_name(vma);
		if (name)
			goto cpy_name;

		if (vma->vm_start <= vma->vm_mm->start_brk &&
				vma->vm_end >= vma->vm_mm->brk) {
			name = "[heap]";
			goto cpy_name;
		}
		if (vma->vm_start <= vma->vm_mm->start_stack &&
				vma->vm_end >= vma->vm_mm->start_stack) {
			name = "[stack]";
			goto cpy_name;
		}

		name = "//anon";
		goto cpy_name;
	}

cpy_name:
	strlcpy(tmp, name, sizeof(tmp));
	name = tmp;
got_name:
	/*
 * Since our buffer works in 8 byte units we need to align our string
 * size to a multiple of 8. However, we must guarantee the tail end is
 * zero'd out to avoid leaking random bits to userspace.
 */
	size = strlen(name)+1;
	while (!IS_ALIGNED(size, sizeof(u64)))
		name[size++] = '\0';

	mmap_event->file_name = name;
	mmap_event->file_size = size;
	mmap_event->maj = maj;
	mmap_event->min = min;
	mmap_event->ino = ino;
	mmap_event->ino_generation = gen;
	mmap_event->prot = prot;
	mmap_event->flags = flags;

	if (!(vma->vm_flags & VM_EXEC))
		mmap_event->event_id.header.misc |= PERF_RECORD_MISC_MMAP_DATA;

	mmap_event->event_id.header.size = sizeof(mmap_event->event_id) + size;

	perf_iterate_sb(perf_event_mmap_output,
		       mmap_event,
		       NULL);

	kfree(buf);
}

/*
 * Check whether inode and address range match filter criteria.
 */
static bool perf_addr_filter_match(struct perf_addr_filter *filter,
				     struct file *file, unsigned long offset,
				     unsigned long size)
{
	if (filter->inode != file_inode(file))
		return false;

	if (filter->offset > offset + size)
		return false;

	if (filter->offset + filter->size < offset)
		return false;

	return true;
}

static void __perf_addr_filters_adjust(struct perf_event *event, void *data)
{
	struct perf_addr_filters_head *ifh = perf_event_addr_filters(event);
	struct vm_area_struct *vma = data;
	unsigned long off = vma->vm_pgoff << PAGE_SHIFT, flags;
	struct file *file = vma->vm_file;
	struct perf_addr_filter *filter;
	unsigned int restart = 0, count = 0;

	if (!has_addr_filter(event))
		return;

	if (!file)
		return;

	raw_spin_lock_irqsave(&ifh->lock, flags);
	list_for_each_entry(filter, &ifh->list, entry) {
		if (perf_addr_filter_match(filter, file, off,
					     vma->vm_end - vma->vm_start)) {
			event->addr_filters_offs[count] = vma->vm_start;
			restart++;
		}

		count++;
	}

	if (restart)
		event->addr_filters_gen++;
	raw_spin_unlock_irqrestore(&ifh->lock, flags);

	if (restart)
		perf_event_stop(event, 1);
}

/*
 * Adjust all task's events' filters to the new vma
 */
static void perf_addr_filters_adjust(struct vm_area_struct *vma)
{
	struct perf_event_context *ctx;
	int ctxn;

	/*
 * Data tracing isn't supported yet and as such there is no need
 * to keep track of anything that isn't related to executable code:
 */
	if (!(vma->vm_flags & VM_EXEC))
		return;

	rcu_read_lock();
	for_each_task_context_nr(ctxn) {
		ctx = rcu_dereference(current->perf_event_ctxp[ctxn]);
		if (!ctx)
			continue;

		perf_iterate_ctx(ctx, __perf_addr_filters_adjust, vma, true);
	}
	rcu_read_unlock();
}

void perf_event_mmap(struct vm_area_struct *vma)
{
	struct perf_mmap_event mmap_event;

	if (!atomic_read(&nr_mmap_events))
		return;

	mmap_event = (struct perf_mmap_event){
		.vma	= vma,
		/* .file_name */
		/* .file_size */
		.event_id  = {
			.header = {
				.type = PERF_RECORD_MMAP,
				.misc = PERF_RECORD_MISC_USER,
				/* .size */
			},
			/* .pid */
			/* .tid */
			.start  = vma->vm_start,
			.len    = vma->vm_end - vma->vm_start,
			.pgoff  = (u64)vma->vm_pgoff << PAGE_SHIFT,
		},
		/* .maj (attr_mmap2 only) */
		/* .min (attr_mmap2 only) */
		/* .ino (attr_mmap2 only) */
		/* .ino_generation (attr_mmap2 only) */
		/* .prot (attr_mmap2 only) */
		/* .flags (attr_mmap2 only) */
	};

	perf_addr_filters_adjust(vma);
	perf_event_mmap_event(&mmap_event);
}

void perf_event_aux_event(struct perf_event *event, unsigned long head,
			  unsigned long size, u64 flags)
{
	struct perf_output_handle handle;
	struct perf_sample_data sample;
	struct perf_aux_event {
		struct perf_event_header	header;
		u64				offset;
		u64				size;
		u64				flags;
	} rec = {
		.header = {
			.type = PERF_RECORD_AUX,
			.misc = 0,
			.size = sizeof(rec),
		},
		.offset		= head,
		.size		= size,
		.flags		= flags,
	};
	int ret;

	perf_event_header__init_id(&rec.header, &sample, event);
	ret = perf_output_begin(&handle, event, rec.header.size);

	if (ret)
		return;

	perf_output_put(&handle, rec);
	perf_event__output_id_sample(event, &handle, &sample);

	perf_output_end(&handle);
}

/*
 * Lost/dropped samples logging
 */
void perf_log_lost_samples(struct perf_event *event, u64 lost)
{
	struct perf_output_handle handle;
	struct perf_sample_data sample;
	int ret;

	struct {
		struct perf_event_header	header;
		u64				lost;
	} lost_samples_event = {
		.header = {
			.type = PERF_RECORD_LOST_SAMPLES,
			.misc = 0,
			.size = sizeof(lost_samples_event),
		},
		.lost		= lost,
	};

	perf_event_header__init_id(&lost_samples_event.header, &sample, event);

	ret = perf_output_begin(&handle, event,
				lost_samples_event.header.size);
	if (ret)
		return;

	perf_output_put(&handle, lost_samples_event);
	perf_event__output_id_sample(event, &handle, &sample);
	perf_output_end(&handle);
}