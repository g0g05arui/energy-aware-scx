#include "vmlinux.h"
#include <scx/common.bpf.h>
#include <bpf/bpf_helpers.h>
#include "rapl_stats.h"
#include "core_state.h"

char _license[] SEC("license") = "GPL";

#define ENERGY_AWARE_DSQ_BASE (1ULL << 32)

static __always_inline __u64 cpu_dsq_id(s32 cpu)
{
	return ENERGY_AWARE_DSQ_BASE + (__u64)cpu;
}

#ifndef ENERGY_AWARE_MAX_CPUS
#ifdef MAX_CPUS
#define ENERGY_AWARE_MAX_CPUS MAX_CPUS
#else
#define ENERGY_AWARE_MAX_CPUS 64
#endif
#endif

extern bool scx_bpf_cpu_can_run(struct task_struct *p, s32 cpu, bool allowed) __ksym __weak;

/* Kernel threads: treat as "default policy" */
static __always_inline bool is_kernelish(struct task_struct *p)
{
	return (p->flags & PF_KTHREAD) || !p->mm;
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rapl_stats);
} rapl_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CORE_TEMPS);
	__type(key, __u32);
	__type(value, __u32);
} core_temp_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} core_temp_count_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CORE_TEMPS);
	__type(key, __u32);
	__type(value, enum core_status);
} core_state_map SEC(".maps");

struct sched_log_state {
	struct bpf_spin_lock lock;
	__u64 last_ts;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sched_log_state);
} sched_log_state_map SEC(".maps");

struct task_ctx {
	s32 target_cpu;
	s32 last_cpu;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_map SEC(".maps");

static __u64 last_printed_ts;
#define SCHED_DECISION_LOG_INTERVAL_NS (100ULL * 1000 * 1000)
static __u32 dsq_nr_cpus;

struct dsq_loop_ctx {
	__u32 nr_cpus;
	s32 err;
};

static long dsq_create_cb(u64 idx, void *data)
{
	struct dsq_loop_ctx *ctx = data;

	if ((__u32)idx >= ctx->nr_cpus)
		return 1;

	ctx->err = scx_bpf_create_dsq(cpu_dsq_id((s32)idx), -1);
	if (ctx->err)
		return 1;

	return 0;
}

static long dsq_destroy_cb(u64 idx, void *data)
{
	struct dsq_loop_ctx *ctx = data;

	if ((__u32)idx >= ctx->nr_cpus)
		return 1;

	scx_bpf_destroy_dsq(cpu_dsq_id((s32)idx));
	return 0;
}

static __always_inline bool sched_log_should_emit(__u64 now)
{
	struct sched_log_state *state;
	__u32 key = 0;
	bool should_log = false;

	state = bpf_map_lookup_elem(&sched_log_state_map, &key);
	if (!state)
		return false;

	bpf_spin_lock(&state->lock);
	if (now - state->last_ts >= SCHED_DECISION_LOG_INTERVAL_NS) {
		state->last_ts = now;
		should_log = true;
	}
	bpf_spin_unlock(&state->lock);

	return should_log;
}

static __always_inline void log_sched_decision(struct task_struct *p, s32 prev_cpu,
					       s32 next_cpu)
{
	__u64 now;

	if (next_cpu < 0)
		return;

	now = bpf_ktime_get_ns();
	if (!sched_log_should_emit(now))
		return;

	if (prev_cpu != next_cpu)
		bpf_printk("SCX sched pid=%d comm=%s prev=%d next=%d",
			   p->pid, p->comm, prev_cpu, next_cpu);
}

/* Scheduler policy CPU cap (performance knob) */
static __u32 clamp_nr_cpus(void)
{
	__u32 nr = scx_bpf_nr_cpu_ids();

	if (nr > ENERGY_AWARE_MAX_CPUS)
		return ENERGY_AWARE_MAX_CPUS;
	return nr;
}

/* Real cpu count (for cpu_can_run masks, DSQ creation bounds, etc.) */
static __always_inline __u32 clamp_nr_cpus_real(void)
{
	__u32 nr = scx_bpf_nr_cpu_ids();
	if (nr > NR_CPUS)
		nr = NR_CPUS;
	return nr;
}

static enum core_status read_core_state(__u32 cpu)
{
	__u32 key = cpu;
	enum core_status *state;

	state = bpf_map_lookup_elem(&core_state_map, &key);
	if (state)
		return *state;

	return CORE_WARM;
}

static __always_inline bool task_allows_cpu(struct task_struct *p, s32 cpu, __u32 nr_cpus)
{
	if (cpu < 0)
		return false;
	if ((__u32)cpu >= nr_cpus)
		return false;

	return bpf_cpumask_test_cpu(cpu, p->cpus_ptr);
}

static __always_inline s32 reuse_prev_cpu(struct task_struct *p, s32 prev_cpu, __u32 nr_cpus)
{
	enum core_status state;

	if (!task_allows_cpu(p, prev_cpu, nr_cpus))
		return -1;

	state = read_core_state(prev_cpu);
	if (state == CORE_COLD || state == CORE_WARM)
		return prev_cpu;

	return -1;
}

struct pick_ctx {
	struct task_struct *p;
	__u32 nr_cpus;
	bool found_warm;
	s32 best_cpu;
	__u32 best_depth;
};

static long pick_cold_cb(u64 idx, void *data)
{
	struct pick_ctx *ctx = data;
	s32 cpu = (s32)idx;
	s32 dsq_depth;
	__u32 depth;
	enum core_status state;

	if ((__u32)cpu >= ctx->nr_cpus)
		return 1;

	if (!task_allows_cpu(ctx->p, cpu, ctx->nr_cpus))
		return 0;

	state = read_core_state(cpu);

	if (state == CORE_COLD) {
		dsq_depth = scx_bpf_dsq_nr_queued(cpu_dsq_id(cpu));
		depth = dsq_depth < 0 ? (__u32)-1 : (__u32)dsq_depth;

		if (depth < ctx->best_depth) {
			ctx->best_depth = depth;
			ctx->best_cpu = cpu;
		}
		return 0;
	}

	if (state != CORE_HOT)
		ctx->found_warm = true;

	return 0;
}

static __always_inline s32 pick_cold_cpu(struct task_struct *p, __u32 nr_cpus,
					 bool *found_warm)
{
	struct pick_ctx ctx = {
		.p = p,
		.nr_cpus = nr_cpus,
		.found_warm = false,
		.best_cpu = -1,
		.best_depth = (__u32)-1,
	};
	long ret;

	ret = bpf_loop(ENERGY_AWARE_MAX_CPUS, pick_cold_cb, &ctx, 0);
	if (ret < 0)
		return -1;

	*found_warm = ctx.found_warm;
	return ctx.best_cpu;
}

struct steer_ctx {
	struct task_struct *p;
	__u32 nr_cpus;
};

static long steer_cb(u64 idx, void *data)
{
	struct steer_ctx *ctx = data;
	s32 cpu = (s32)idx;
	enum core_status state;

	if ((__u32)cpu >= ctx->nr_cpus)
		return 1;

	if (!task_allows_cpu(ctx->p, cpu, ctx->nr_cpus))
		return 0;

	state = read_core_state(cpu);

	if (state == CORE_HOT)
		scx_bpf_cpu_can_run(ctx->p, cpu, false);
	else
		scx_bpf_cpu_can_run(ctx->p, cpu, true);

	return 0;
}

static __always_inline void steer_away_from_hot(struct task_struct *p, __u32 nr_cpus)
{
	struct steer_ctx ctx = {
		.p = p,
		.nr_cpus = nr_cpus,
	};

	if (!bpf_ksym_exists(scx_bpf_cpu_can_run))
		return;

	bpf_loop(ENERGY_AWARE_MAX_CPUS, steer_cb, &ctx, 0);
}

/* cpu_can_run masks must cover the real cpu range - but never touch kernel threads */
static __always_inline void allow_all_cpus(struct task_struct *p)
{
	if (is_kernelish(p))
		return;

	if (!bpf_ksym_exists(scx_bpf_cpu_can_run))
		return;

	__u32 nr = clamp_nr_cpus_real();

#pragma clang loop unroll(disable)
	for (s32 i = 0; i < (s32)nr; i++)
		scx_bpf_cpu_can_run(p, i, true);
}

static __always_inline void pin_to_cpu(struct task_struct *p, s32 cpu)
{
	if (is_kernelish(p))
		return;

	if (!bpf_ksym_exists(scx_bpf_cpu_can_run))
		return;

	__u32 nr = clamp_nr_cpus_real();

#pragma clang loop unroll(disable)
	for (s32 i = 0; i < (s32)nr; i++)
		scx_bpf_cpu_can_run(p, i, i == cpu);
}

static __always_inline s32 select_cpu_default(struct task_struct *p, s32 prev_cpu,
					      u64 wake_flags)
{
	bool is_idle = false;

	return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

s32 BPF_STRUCT_OPS(select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	__u32 nr_cpus = clamp_nr_cpus();
	bool found_warm = false;
	s32 cpu;

	struct task_ctx *tctx;
	s32 last_cpu = -1;

	(void)wake_flags;

	/* Kernel threads: default CPU selection, no pinning/steering */
	if (is_kernelish(p)) {
		cpu = select_cpu_default(p, prev_cpu, wake_flags);
		log_sched_decision(p, prev_cpu, cpu);
		return cpu;
	}

	tctx = bpf_task_storage_get(&task_ctx_map, p, 0, 0);
	if (tctx)
		last_cpu = tctx->last_cpu;

	if (!nr_cpus) {
		allow_all_cpus(p);
		cpu = select_cpu_default(p, prev_cpu, wake_flags);
		bpf_printk("Switched to EEVDF scheduler");
		goto log_return;
	}

	if (last_cpu >= 0) {
		cpu = reuse_prev_cpu(p, last_cpu, nr_cpus);
		if (cpu >= 0)
			goto log_return;
	}

	cpu = reuse_prev_cpu(p, prev_cpu, nr_cpus);
	if (cpu >= 0)
		goto log_return;

	cpu = pick_cold_cpu(p, nr_cpus, &found_warm);
	if (cpu >= 0)
		goto log_return;

	if (found_warm) {
		steer_away_from_hot(p, nr_cpus);
		cpu = select_cpu_default(p, prev_cpu, wake_flags);
		bpf_printk("Switched to EEVDF scheduler");
		goto log_return;
	}

	allow_all_cpus(p);
	cpu = select_cpu_default(p, prev_cpu, wake_flags);

log_return:
	{
		struct task_ctx *tctx2;

		tctx2 = bpf_task_storage_get(&task_ctx_map, p, 0,
					     BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (tctx2)
			tctx2->target_cpu = cpu;
	}

	if (cpu >= 0 && (read_core_state(cpu) == CORE_COLD || read_core_state(cpu) == CORE_WARM))
		pin_to_cpu(p, cpu);
	else
		allow_all_cpus(p);

	log_sched_decision(p, prev_cpu, cpu);
	return cpu;
}

void BPF_STRUCT_OPS(rr_enqueue, struct task_struct *p, u64 enq_flags)
{
	/* Kernel threads: enqueue into built-in local DSQ (always valid) */
	if (is_kernelish(p)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
		return;
	}

	struct task_ctx *tctx;
	s32 cpu = -1;
	__u64 dsq_id = cpu_dsq_id((s32)bpf_get_smp_processor_id());

	tctx = bpf_task_storage_get(&task_ctx_map, p, 0, 0);
	if (tctx)
		cpu = tctx->target_cpu;

	if (cpu >= 0 && (__u32)cpu < dsq_nr_cpus)
		dsq_id = cpu_dsq_id(cpu);
	else
		cpu = -1;

	scx_bpf_dsq_insert(p, dsq_id, SCX_SLICE_DFL, enq_flags);

	if (cpu >= 0)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

void BPF_STRUCT_OPS(rr_dispatch, s32 cpu, struct task_struct *prev)
{
	/* Always drain built-in local DSQ first (kernel threads / fallback) */
	scx_bpf_dsq_move_to_local(SCX_DSQ_LOCAL);

	/* Then drain this CPU's per-CPU DSQ (user tasks) */
	if ((__u32)cpu < dsq_nr_cpus)
		scx_bpf_dsq_move_to_local(cpu_dsq_id(cpu));
}

void BPF_STRUCT_OPS(rr_running, struct task_struct *p)
{
	/* Track last_cpu only for user tasks */
	if (is_kernelish(p))
		return;

	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_map, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (tctx)
		tctx->last_cpu = (s32)bpf_get_smp_processor_id();
}

void BPF_STRUCT_OPS(rr_stopping, struct task_struct *p, bool runnable) {}

s32 BPF_STRUCT_OPS_SLEEPABLE(rr_init)
{
	__u32 nr_cpus = scx_bpf_nr_cpu_ids();
	struct dsq_loop_ctx loop_ctx = {
		.nr_cpus = nr_cpus,
		.err = 0,
	};

	if (nr_cpus > NR_CPUS)
		nr_cpus = NR_CPUS;

	loop_ctx.nr_cpus = nr_cpus;
	bpf_loop(nr_cpus, dsq_create_cb, &loop_ctx, 0);
	if (loop_ctx.err)
		return loop_ctx.err;

	dsq_nr_cpus = nr_cpus;
	return 0;
}

void BPF_STRUCT_OPS(rr_exit, struct scx_exit_info *ei)
{
	struct dsq_loop_ctx loop_ctx = {
		.nr_cpus = dsq_nr_cpus,
		.err = 0,
	};

	if (!dsq_nr_cpus)
		return;

	bpf_loop(dsq_nr_cpus, dsq_destroy_cb, &loop_ctx, 0);
}

SEC(".struct_ops.link")
struct sched_ext_ops energy_aware_ops = {
	.select_cpu		= (void *)select_cpu,
	.enqueue		= (void *)rr_enqueue,
	.dispatch		= (void *)rr_dispatch,
	.running		= (void *)rr_running,
	.stopping		= (void *)rr_stopping,
	.init			= (void *)rr_init,
	.exit			= (void *)rr_exit,
	.flags			= SCX_OPS_ENQ_LAST,
	.name			= "rr_cold_aware",
};