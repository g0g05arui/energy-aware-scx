#include "vmlinux.h"
#include <scx/common.bpf.h>
#include <bpf/bpf_helpers.h>
#include "core_state.h"
#include "topology_defs.h"

/*
 * DSQ routing remains the primary steering mechanism.
 * cpu_can_run pinning is optional, short-lived, and kept minimal to avoid thrash.
 */

char _license[] SEC("license") = "GPL";

#define ENERGY_AWARE_DSQ_BASE (1ULL << 32)
/* Dedicated fallback DSQ for kernel threads/default path */
#define FALLBACK_DSQ_ID (ENERGY_AWARE_DSQ_BASE - 1)

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
	__uint(max_entries, MAX_CORE_TEMPS);
	__type(key, __u32);
	__type(value, enum core_status);
} core_state_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, TOPO_MAX_CPUS);
	__type(key, __u32);
	__type(value, __u32);
} cpu_to_core_gid_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CORE_TEMPS);
	__type(key, __u32);
	__type(value, __u32);
} core_primary_cpu_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CORE_TEMPS);
	__type(key, __u32);
	__type(value, struct core_siblings);
} core_siblings_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CORE_TEMPS);
	__type(key, __u32);
	__type(value, __u32);
} core_active_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, ENERGY_AWARE_MAX_CPUS);
	__type(key, __u32);
	__type(value, __u32);
} cpu_busy_map SEC(".maps");

#define DEFAULT_MAX_COLD_DSQ_DEPTH 4
#define DEFAULT_MAX_REUSE_DSQ_DEPTH 6
#define DEFAULT_ENABLE_PINNING 1
#define DEFAULT_ENABLE_LOGGING 1
#define DEFAULT_LOG_INTERVAL_NS (100ULL * 1000 * 1000)
#define DEFAULT_PINNING_LEASE_NS (2ULL * 1000 * 1000)
#define DEFAULT_PREFER_PRIMARY 1

struct sched_cfg {
	__u32 max_cold_dsq_depth;
	__u32 max_reuse_dsq_depth;
	__u32 enable_pinning;
	__u32 enable_logging;
	__u32 log_interval_ns;
	__u32 pinning_lease_ns;
	__u32 prefer_primary;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sched_cfg);
} sched_cfg_map SEC(".maps");

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
	s32 pinned_cpu;
	__u64 pin_until_ts;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_map SEC(".maps");

static __always_inline const struct sched_cfg *get_cfg(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&sched_cfg_map, &key);
}

static __always_inline __u32 cfg_max_cold_depth(const struct sched_cfg *cfg)
{
	if (cfg)
		return cfg->max_cold_dsq_depth;
	return DEFAULT_MAX_COLD_DSQ_DEPTH;
}

static __always_inline __u32 cfg_max_reuse_depth(const struct sched_cfg *cfg)
{
	if (cfg)
		return cfg->max_reuse_dsq_depth;
	return DEFAULT_MAX_REUSE_DSQ_DEPTH;
}

static __always_inline bool cfg_pinning_enabled(const struct sched_cfg *cfg)
{
	if (cfg)
		return cfg->enable_pinning;
	return DEFAULT_ENABLE_PINNING;
}

static __always_inline bool cfg_logging_enabled(const struct sched_cfg *cfg)
{
	if (cfg)
		return cfg->enable_logging;
	return DEFAULT_ENABLE_LOGGING;
}

static __always_inline bool cfg_prefer_primary(const struct sched_cfg *cfg)
{
	if (cfg)
		return cfg->prefer_primary;
	return DEFAULT_PREFER_PRIMARY;
}

static __always_inline __u64 cfg_log_interval_ns(const struct sched_cfg *cfg)
{
	if (cfg)
		return cfg->log_interval_ns;
	return DEFAULT_LOG_INTERVAL_NS;
}

static __always_inline __u64 cfg_pinning_lease_ns(const struct sched_cfg *cfg)
{
	if (cfg)
		return cfg->pinning_lease_ns;
	return DEFAULT_PINNING_LEASE_NS;
}

static __u32 dsq_nr_cpus;
static bool fallback_dsq_created;

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

static __always_inline bool sched_log_should_emit(__u64 now,
						  const struct sched_cfg *cfg)
{
	struct sched_log_state *state;
	__u32 key = 0;
	bool should_log = false;
	__u64 interval = cfg_log_interval_ns(cfg);

	if (!cfg_logging_enabled(cfg))
		return false;

	state = bpf_map_lookup_elem(&sched_log_state_map, &key);
	if (!state)
		return false;

	bpf_spin_lock(&state->lock);
	if (now - state->last_ts >= interval) {
		state->last_ts = now;
		should_log = true;
	}
	bpf_spin_unlock(&state->lock);

	return should_log;
}

static __always_inline void log_sched_decision(struct task_struct *p, s32 prev_cpu,
					       s32 next_cpu,
					       const struct sched_cfg *cfg)
{
	__u64 now;

	if (next_cpu < 0)
		return;

	if (!cfg_logging_enabled(cfg))
		return;

	now = bpf_ktime_get_ns();
	if (!sched_log_should_emit(now, cfg))
		return;

	if (prev_cpu != next_cpu)
		bpf_printk("SCX sched pid=%d comm=%s prev=%d next=%d",
			   p->pid, p->comm, prev_cpu, next_cpu);
}

static __u32 clamp_nr_cpus(void)
{
	__u32 nr = scx_bpf_nr_cpu_ids();
	if (nr > ENERGY_AWARE_MAX_CPUS)
		return ENERGY_AWARE_MAX_CPUS;
	return nr;
}

static __always_inline __u32 clamp_nr_cpus_real(void)
{
	__u32 nr = scx_bpf_nr_cpu_ids();
	if (nr > NR_CPUS)
		nr = NR_CPUS;
	return nr;
}

static __always_inline __u32 get_core_gid_from_cpu(__u32 cpu)
{
	__u32 key = cpu;
	__u32 *gid = bpf_map_lookup_elem(&cpu_to_core_gid_map, &key);

	if (!gid)
		return TOPO_GID_INVALID;
	return *gid;
}

static enum core_status read_core_state_gid(__u32 core_gid)
{
	__u32 key = core_gid;
	enum core_status *state;

	state = bpf_map_lookup_elem(&core_state_map, &key);
	if (state)
		return *state;

	return CORE_WARM;
}

static enum core_status read_core_state_cpu(__u32 cpu)
{
	__u32 core_gid = get_core_gid_from_cpu(cpu);

	if (core_gid == TOPO_GID_INVALID)
		return CORE_WARM;
	return read_core_state_gid(core_gid);
}

static __always_inline bool cpu_is_primary(__u32 cpu)
{
	__u32 core_gid = get_core_gid_from_cpu(cpu);
	__u32 *primary;

	if (core_gid == TOPO_GID_INVALID)
		return true;

	primary = bpf_map_lookup_elem(&core_primary_cpu_map, &core_gid);
	if (!primary)
		return true;

	return *primary == cpu;
}

static __always_inline __u32 core_capacity(__u32 core_gid)
{
	const struct core_siblings *sibs;

	if (core_gid == TOPO_GID_INVALID)
		return 1;

	sibs = bpf_map_lookup_elem(&core_siblings_map, &core_gid);
	if (!sibs || sibs->sib_cnt == 0)
		return 1;

	return sibs->sib_cnt;
}

static __always_inline __u32 core_active_count(__u32 core_gid)
{
	__u32 *cnt;

	if (core_gid == TOPO_GID_INVALID)
		return 0;

	cnt = bpf_map_lookup_elem(&core_active_map, &core_gid);
	if (!cnt)
		return 0;

	return *cnt;
}

static __always_inline void core_active_inc_gid(__u32 core_gid)
{
	__u32 *cnt;

	if (core_gid == TOPO_GID_INVALID)
		return;

	cnt = bpf_map_lookup_elem(&core_active_map, &core_gid);
	if (!cnt)
		return;

	*cnt += 1;
}

static __always_inline void core_active_dec_gid(__u32 core_gid)
{
	__u32 *cnt;

	if (core_gid == TOPO_GID_INVALID)
		return;

	cnt = bpf_map_lookup_elem(&core_active_map, &core_gid);
	if (!cnt)
		return;

	if (*cnt > 0)
		*cnt -= 1;
}

static __always_inline void core_active_inc_cpu(__u32 cpu)
{
	__u32 gid = get_core_gid_from_cpu(cpu);

	core_active_inc_gid(gid);
}

static __always_inline void core_active_dec_cpu(__u32 cpu)
{
	__u32 gid = get_core_gid_from_cpu(cpu);

	core_active_dec_gid(gid);
}

static __always_inline bool cpu_is_busy(__u32 cpu)
{
	__u32 *busy;

	if (cpu >= ENERGY_AWARE_MAX_CPUS)
		return true;

	busy = bpf_map_lookup_elem(&cpu_busy_map, &cpu);
	if (!busy)
		return true;

	return *busy != 0;
}

static __always_inline void cpu_mark_busy(__u32 cpu)
{
	__u32 *busy;

	if (cpu >= ENERGY_AWARE_MAX_CPUS)
		return;

	busy = bpf_map_lookup_elem(&cpu_busy_map, &cpu);
	if (!busy)
		return;

	*busy = 1;
}

static __always_inline void cpu_mark_idle(__u32 cpu)
{
	__u32 *busy;

	if (cpu >= ENERGY_AWARE_MAX_CPUS)
		return;

	busy = bpf_map_lookup_elem(&cpu_busy_map, &cpu);
	if (!busy)
		return;

	*busy = 0;
}

static __always_inline bool task_allows_cpu(struct task_struct *p, s32 cpu, __u32 nr_cpus)
{
	if (cpu < 0)
		return false;
	if ((__u32)cpu >= nr_cpus)
		return false;

	return bpf_cpumask_test_cpu(cpu, p->cpus_ptr);
}

static __always_inline s32 reuse_prev_cpu(struct task_struct *p, s32 prev_cpu,
					  __u32 nr_cpus, __u32 max_reuse_depth)
{
	enum core_status state;
	s32 depth;

	if (!task_allows_cpu(p, prev_cpu, nr_cpus))
		return -1;

	state = read_core_state_cpu(prev_cpu);
	if (state != CORE_COLD && state != CORE_WARM)
		return -1;

	depth = scx_bpf_dsq_nr_queued(cpu_dsq_id(prev_cpu));
	if (depth < 0)
		return -1;
	if ((__u32)depth > max_reuse_depth)
		return -1;

	return prev_cpu;
}

struct pick_ctx {
	struct task_struct *p;
	__u32 nr_cpus;
	bool allow_siblings;
	bool has_cold;
	bool has_warm;
	s32 best_cold_cpu;
	__u32 best_cold_depth;
	s32 best_warm_cpu;
	__u32 best_warm_depth;
};

static long pick_cold_cb(u64 idx, void *data)
{
	struct pick_ctx *ctx = data;
	s32 cpu = (s32)idx;
	s32 dsq_depth;
	__u32 depth;
	enum core_status state;
	__u32 core_gid;
	__u32 capacity;
	__u32 active;

	if ((__u32)cpu >= ctx->nr_cpus)
		return 1;

	if (cpu_is_busy(cpu))
		return 0;

	if (!task_allows_cpu(ctx->p, cpu, ctx->nr_cpus))
		return 0;

	if (!ctx->allow_siblings && !cpu_is_primary(cpu))
		return 0;

	core_gid = get_core_gid_from_cpu(cpu);
	if (core_gid == TOPO_GID_INVALID)
		return 0;

	capacity = core_capacity(core_gid);
	if (capacity == 0)
		capacity = 1;

	active = core_active_count(core_gid);

	if (!ctx->allow_siblings) {
		if (capacity > 1 && active > 0)
			return 0;
	} else {
		if (active >= capacity)
			return 0;
	}

	state = read_core_state_cpu(cpu);

	if (state == CORE_COLD) {
		ctx->has_cold = true;
		dsq_depth = scx_bpf_dsq_nr_queued(cpu_dsq_id(cpu));
		if (dsq_depth < 0)
			return 0;
		depth = (__u32)dsq_depth;

		if (depth < ctx->best_cold_depth) {
			ctx->best_cold_depth = depth;
			ctx->best_cold_cpu = cpu;
		}
		return 0;
	}

	if (state == CORE_WARM) {
		ctx->has_warm = true;
		dsq_depth = scx_bpf_dsq_nr_queued(cpu_dsq_id(cpu));
		if (dsq_depth < 0)
			return 0;
		depth = (__u32)dsq_depth;

		if (depth < ctx->best_warm_depth) {
			ctx->best_warm_depth = depth;
			ctx->best_warm_cpu = cpu;
		}
		return 0;
	}

	return 0;
}

static __always_inline s32 pick_cold_cpu(struct task_struct *p, __u32 nr_cpus,
					 const struct sched_cfg *cfg,
					 bool allow_siblings, bool *found_warm)
{
	struct pick_ctx ctx = {
		.p = p,
		.nr_cpus = nr_cpus,
		.allow_siblings = allow_siblings,
		.has_cold = false,
		.has_warm = false,
		.best_cold_cpu = -1,
		.best_cold_depth = (__u32)-1,
		.best_warm_cpu = -1,
		.best_warm_depth = (__u32)-1,
	};
	long ret;

	if (found_warm)
		*found_warm = false;

	if (!nr_cpus)
		return -1;

	ret = bpf_loop(ENERGY_AWARE_MAX_CPUS, pick_cold_cb, &ctx, 0);
	if (ret < 0)
		return -1;

	if (ctx.best_cold_cpu >= 0 &&
	    ctx.best_cold_depth < cfg_max_cold_depth(cfg))
		return ctx.best_cold_cpu;

	if (ctx.best_warm_cpu >= 0)
		return ctx.best_warm_cpu;

	if (found_warm)
		*found_warm = ctx.has_warm;

	return -1;
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

	state = read_core_state_cpu(cpu);

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

static __always_inline bool cpu_matches_core(const struct core_siblings *core,
					     __u32 cpu)
{
	if (!core)
		return false;

#pragma clang loop unroll(disable)
	for (__u32 idx = 0; idx < TOPO_MAX_SIBLINGS; idx++) {
		if (idx >= core->sib_cnt)
			break;
		if (core->sibs[idx] == cpu)
			return true;
	}

	return false;
}

static __always_inline void pin_to_core(struct task_struct *p, __u32 cpu)
{
	if (is_kernelish(p))
		return;

	if (!bpf_ksym_exists(scx_bpf_cpu_can_run))
		return;

	__u32 core_gid = get_core_gid_from_cpu(cpu);
	const struct core_siblings *core =
		bpf_map_lookup_elem(&core_siblings_map, &core_gid);
	__u32 nr = clamp_nr_cpus_real();

#pragma clang loop unroll(disable)
	for (s32 i = 0; i < (s32)nr; i++) {
		bool allow = false;

		if (core && core->sib_cnt > 0)
			allow = cpu_matches_core(core, (__u32)i);
		else
			allow = (i == (s32)cpu);

		scx_bpf_cpu_can_run(p, i, allow);
	}
}

static __always_inline void init_task_ctx(struct task_ctx *tctx)
{
	if (!tctx)
		return;

	if (tctx->pin_until_ts == 0 && tctx->pinned_cpu == 0)
		tctx->pinned_cpu = -1;
}

static __always_inline void ensure_allow_all(struct task_struct *p,
					     struct task_ctx *tctx)
{
	if (!tctx) {
		allow_all_cpus(p);
		return;
	}

	if (tctx->pinned_cpu == -1)
		return;

	if (!bpf_ksym_exists(scx_bpf_cpu_can_run)) {
		tctx->pinned_cpu = -1;
		tctx->pin_until_ts = 0;
		return;
	}

	allow_all_cpus(p);
	tctx->pinned_cpu = -1;
	tctx->pin_until_ts = 0;
}

static __always_inline void ensure_pinned_to(struct task_struct *p,
					     struct task_ctx *tctx,
					     s32 cpu, __u64 now,
					     const struct sched_cfg *cfg)
{
	__u64 lease;

	if (!tctx)
		return;

	if (!cfg_pinning_enabled(cfg)) {
		ensure_allow_all(p, tctx);
		return;
	}

	if (!bpf_ksym_exists(scx_bpf_cpu_can_run)) {
		tctx->pinned_cpu = -1;
		tctx->pin_until_ts = 0;
		return;
	}

	if (tctx->pinned_cpu == cpu && now < tctx->pin_until_ts)
		return;

	pin_to_core(p, cpu);
	lease = cfg_pinning_lease_ns(cfg);
	tctx->pinned_cpu = cpu;
	tctx->pin_until_ts = now + lease;
}

static __always_inline s32 select_cpu_default(struct task_struct *p, s32 prev_cpu,
					      u64 wake_flags)
{
	bool is_idle = false;
	return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

s32 BPF_STRUCT_OPS(select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	const struct sched_cfg *cfg = get_cfg();
	__u32 nr_cpus = clamp_nr_cpus();
	bool found_warm_primary = false;
	bool found_warm_any = false;
	s32 cpu = -1;
	struct task_ctx *tctx;
	s32 last_cpu = -1;
	bool prefer_primary = cfg_prefer_primary(cfg);
	bool have_deferred = false;
	s32 deferred_cpu = -1;

	(void)wake_flags;

	/* Kernel threads: default CPU selection, no pinning/steering */
	if (is_kernelish(p)) {
		cpu = select_cpu_default(p, prev_cpu, wake_flags);
		log_sched_decision(p, prev_cpu, cpu, cfg);
		return cpu;
	}

	tctx = bpf_task_storage_get(&task_ctx_map, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (tctx) {
		init_task_ctx(tctx);
		last_cpu = tctx->last_cpu;
	}

	if (!nr_cpus) {
		ensure_allow_all(p, tctx);
		cpu = select_cpu_default(p, prev_cpu, wake_flags);
		goto record_ctx;
	}

	if (last_cpu >= 0) {
		s32 reuse_cpu = reuse_prev_cpu(p, last_cpu, nr_cpus,
					       cfg_max_reuse_depth(cfg));
		if (reuse_cpu >= 0) {
			if (!prefer_primary || cpu_is_primary(reuse_cpu)) {
				cpu = reuse_cpu;
				goto record_ctx;
			}

			deferred_cpu = reuse_cpu;
			have_deferred = true;
		}
	}

	{
		s32 reuse_cpu = reuse_prev_cpu(p, prev_cpu, nr_cpus,
					       cfg_max_reuse_depth(cfg));
		if (reuse_cpu >= 0) {
			if (!prefer_primary || cpu_is_primary(reuse_cpu)) {
				cpu = reuse_cpu;
				goto record_ctx;
			}

			if (!have_deferred) {
				deferred_cpu = reuse_cpu;
				have_deferred = true;
			}
		}
	}

	if (prefer_primary) {
		cpu = pick_cold_cpu(p, nr_cpus, cfg, false, &found_warm_primary);
		if (cpu >= 0)
			goto record_ctx;

		if (have_deferred) {
			cpu = deferred_cpu;
			goto record_ctx;
		}
	}

	cpu = pick_cold_cpu(p, nr_cpus, cfg, true, &found_warm_any);
	if (cpu >= 0)
		goto record_ctx;

	if (!prefer_primary && have_deferred) {
		cpu = deferred_cpu;
		goto record_ctx;
	}

	if (found_warm_primary || found_warm_any) {
		steer_away_from_hot(p, nr_cpus);
		if (tctx) {
			tctx->pinned_cpu = -1;
			tctx->pin_until_ts = 0;
		}
		cpu = select_cpu_default(p, prev_cpu, wake_flags);
		goto record_ctx;
	}

	ensure_allow_all(p, tctx);
	cpu = select_cpu_default(p, prev_cpu, wake_flags);

record_ctx:
	if (tctx)
		tctx->target_cpu = cpu;

	if (tctx) {
		bool should_pin = false;

		if (cpu >= 0 && cfg_pinning_enabled(cfg)) {
			enum core_status state = read_core_state_cpu(cpu);

			if (state == CORE_COLD || state == CORE_WARM) {
				s32 dsq_depth = scx_bpf_dsq_nr_queued(cpu_dsq_id(cpu));

				if (dsq_depth >= 0) {
					if (state == CORE_COLD &&
					    (__u32)dsq_depth < cfg_max_cold_depth(cfg))
						should_pin = true;
					else if (state == CORE_WARM &&
						 (__u32)dsq_depth < cfg_max_reuse_depth(cfg))
						should_pin = true;
				}
			}
		}

		if (should_pin) {
			__u64 now = bpf_ktime_get_ns();

			ensure_pinned_to(p, tctx, cpu, now, cfg);
		} else {
			ensure_allow_all(p, tctx);
		}
	} else if (cpu >= 0) {
		allow_all_cpus(p);
	}

	log_sched_decision(p, prev_cpu, cpu, cfg);
	return cpu;
}

void BPF_STRUCT_OPS(rr_enqueue, struct task_struct *p, u64 enq_flags)
{
	/* Kernel threads: enqueue into built-in local DSQ (always valid) */
	if (is_kernelish(p)) {
		scx_bpf_dsq_insert(p, FALLBACK_DSQ_ID, SCX_SLICE_DFL, enq_flags);
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
	cpu_mark_idle((__u32)cpu);

	if (prev && !is_kernelish(prev))
		core_active_dec_cpu((__u32)cpu);

	/* Always drain built-in local DSQ first (kernel threads / fallback) */
	if (fallback_dsq_created)
		scx_bpf_dsq_move_to_local(FALLBACK_DSQ_ID);

	/* Then drain this CPU's per-CPU DSQ (user tasks) */
	if ((__u32)cpu < dsq_nr_cpus)
		scx_bpf_dsq_move_to_local(cpu_dsq_id(cpu));
}

void BPF_STRUCT_OPS(rr_running, struct task_struct *p)
{
	if (is_kernelish(p))
		return;

	struct task_ctx *tctx;
	__u32 cpu = (__u32)bpf_get_smp_processor_id();

	tctx = bpf_task_storage_get(&task_ctx_map, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (tctx) {
		init_task_ctx(tctx);
		tctx->last_cpu = (s32)cpu;
	}

	cpu_mark_busy(cpu);
	core_active_inc_cpu(cpu);
}

void BPF_STRUCT_OPS(rr_stopping, struct task_struct *p, bool runnable) {}

s32 BPF_STRUCT_OPS_SLEEPABLE(rr_init)
{
	__u32 nr_cpus = scx_bpf_nr_cpu_ids();
	s32 err;
	struct dsq_loop_ctx loop_ctx = {
		.nr_cpus = nr_cpus,
		.err = 0,
	};

	if (nr_cpus > NR_CPUS)
		nr_cpus = NR_CPUS;

	err = scx_bpf_create_dsq(FALLBACK_DSQ_ID, -1);
	if (err)
		return err;
	fallback_dsq_created = true;

	loop_ctx.nr_cpus = nr_cpus;
	bpf_loop(nr_cpus, dsq_create_cb, &loop_ctx, 0);
	if (loop_ctx.err)
		goto destroy_fallback;

	dsq_nr_cpus = nr_cpus;
	return 0;

destroy_fallback:
	if (fallback_dsq_created) {
		scx_bpf_destroy_dsq(FALLBACK_DSQ_ID);
		fallback_dsq_created = false;
	}
	return loop_ctx.err;
}

void BPF_STRUCT_OPS(rr_exit, struct scx_exit_info *ei)
{
	struct dsq_loop_ctx loop_ctx = {
		.nr_cpus = dsq_nr_cpus,
		.err = 0,
	};

	if (!dsq_nr_cpus)
		goto destroy_fallback;

	bpf_loop(dsq_nr_cpus, dsq_destroy_cb, &loop_ctx, 0);

destroy_fallback:
	if (fallback_dsq_created) {
		scx_bpf_destroy_dsq(FALLBACK_DSQ_ID);
		fallback_dsq_created = false;
	}
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
