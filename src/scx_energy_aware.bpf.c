#include "vmlinux.h"
#include <scx/common.bpf.h>
#include <bpf/bpf_helpers.h>
#include "rapl_stats.h"
#include "core_state.h"

char _license[] SEC("license") = "GPL";

#define RR_SLICE_NS SCX_SLICE_DFL

#ifndef ENERGY_AWARE_MAX_CPUS
#ifdef MAX_CPUS
#define ENERGY_AWARE_MAX_CPUS MAX_CPUS
#else
#define ENERGY_AWARE_MAX_CPUS 32
#endif
#endif 

extern bool scx_bpf_cpu_can_run(struct task_struct *p, s32 cpu, bool allowed) __ksym __weak;

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

#define SCHED_TEMP_LOG_BUF_SZ 768

struct sched_temp_log_buf {
	char buf[SCHED_TEMP_LOG_BUF_SZ];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sched_temp_log_buf);
} sched_temp_log_buf_map SEC(".maps");

static __u64 last_printed_ts;
#define SCHED_DECISION_LOG_INTERVAL_NS (100ULL * 1000 * 1000)

static __always_inline __u32 clamp_temp_count(__u32 count)
{
	if (!count || count > MAX_CORE_TEMPS)
		return MAX_CORE_TEMPS;
	return count;
}

static __always_inline __u32 temp_count_for_log(void)
{
	struct rapl_stats *stats;
	__u32 key = 0;
	__u32 stats_count = 0;
	__u32 *count;

	stats = bpf_map_lookup_elem(&rapl_stats_map, &key);
	if (stats)
		stats_count = stats->core_count;

	count = bpf_map_lookup_elem(&core_temp_count_map, &key);
	if (count && *count)
		return clamp_temp_count(*count);

	return clamp_temp_count(stats_count);
}

static __always_inline int sched_temp_buf_append(struct sched_temp_log_buf *buf, int pos,
						 const char *fmt, __u64 *data,
						 __u32 data_len)
{
	int ret;
	__u32 avail;

	if (!buf)
		return -1;

	if (pos < 0)
		return -1;

	if (pos >= SCHED_TEMP_LOG_BUF_SZ)
		return -1;

	avail = SCHED_TEMP_LOG_BUF_SZ - pos;
	if (!avail)
		return -1;

	ret = bpf_snprintf(buf->buf + pos, avail, fmt, data, data_len);
	if (ret < 0)
		return ret;

	return pos + ret;
}

static __always_inline void format_temp_map_string(struct sched_temp_log_buf *buf,
						   __u32 temp_count)
{
	int pos = 0;
	__u32 i;

	if (!buf)
		return;

	pos = sched_temp_buf_append(buf, pos, "{", NULL, 0);
	if (pos < 0)
		goto out;

#pragma clang loop unroll(disable)
	for (i = 0; i < MAX_CORE_TEMPS; i++) {
		__u32 key = i;
		__u32 temp = 0;
		bool valid = false;
		const char *sep;
		const char *suffix;
		__u64 args[4];

		if (i >= temp_count)
			break;

		__u32 *temp_val = bpf_map_lookup_elem(&core_temp_map, &key);
		if (temp_val) {
			temp = *temp_val;
			valid = true;
		}

		sep = i ? " " : "";
		suffix = valid ? "" : "?";
		args[0] = (__u64)(unsigned long)sep;
		args[1] = i;
		args[2] = temp;
		args[3] = (__u64)(unsigned long)suffix;

		pos = sched_temp_buf_append(buf, pos, "%s%u:%uC%s", args, 4);
		if (pos < 0)
			goto out;
	}

	pos = sched_temp_buf_append(buf, pos, "}", NULL, 0);

out:
	if (pos < 0)
		pos = 0;
	else if (pos >= SCHED_TEMP_LOG_BUF_SZ)
		pos = SCHED_TEMP_LOG_BUF_SZ - 1;

	buf->buf[pos] = '\0';
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
	const char *temp_summary = "<temp_map_unavail>";
	struct sched_temp_log_buf *temp_buf;
	__u32 buf_key = 0;

	if (next_cpu < 0)
		return;

	now = bpf_ktime_get_ns();
	if (!sched_log_should_emit(now))
		return;

	temp_buf = bpf_map_lookup_elem(&sched_temp_log_buf_map, &buf_key);
	if (temp_buf) {
		format_temp_map_string(temp_buf, temp_count_for_log());
		temp_summary = temp_buf->buf;
	}

	if (prev_cpu != next_cpu)
		bpf_printk("SCX sched pid=%d comm=%s prev=%d next=%d temps=%s",
			   p->pid, p->comm, prev_cpu, next_cpu, temp_summary);
}

static __u32 clamp_nr_cpus(void)
{
	__u32 nr = scx_bpf_nr_cpu_ids();

	if (nr > ENERGY_AWARE_MAX_CPUS)
		return ENERGY_AWARE_MAX_CPUS;
	return nr;
}

static  enum core_status read_core_state(__u32 cpu)
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
		dsq_depth = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu);
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

static __always_inline s32 select_cpu_default(struct task_struct *p, s32 prev_cpu,
					      u64 wake_flags)
{
	bool is_idle = false;

	return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

static  __u32 read_temp(__u32 idx, bool *valid)
{
	__u32 *temp = bpf_map_lookup_elem(&core_temp_map, &idx);
	if (temp) {
		if (valid)
			*valid = true;
		return *temp;
	}

	if (valid)
		*valid = false;
	return 0;
}

static  __u32 read_temp_count(__u32 stats_core_count)
{
	__u32 key = 0;
	__u32 *count = bpf_map_lookup_elem(&core_temp_count_map, &key);

	if (count && *count && *count <= MAX_CORE_TEMPS)
		return *count;

	if (stats_core_count == 0 || stats_core_count > MAX_CORE_TEMPS)
		return MAX_CORE_TEMPS;

	return stats_core_count;
}

static void log_stats_from_map(void)
{
	struct rapl_stats *stats;
	__u32 key = 0;
	__u32 temp_count;

	stats = bpf_map_lookup_elem(&rapl_stats_map, &key);
	if (!stats)
		return;

	if (stats->timestamp == last_printed_ts)
		return;

	last_printed_ts = stats->timestamp;

	bpf_printk("RAPL ts=%llu delta=%llu pkg=%lluW/%uC core=%lluW cnt=%u tdp=%lluW",
		   stats->timestamp,
		   stats->delta_time,
		   stats->package_power,
		   stats->package_temp,
		   stats->core_power,
		   stats->core_count,
		   stats->tdp);

	temp_count = read_temp_count(stats->core_count);

#pragma clang loop unroll(disable)
	for (__u32 i = 0; i < MAX_CORE_TEMPS; i++) {
		if (i >= temp_count)
			break;
		bool valid = false;
		__u32 temp = read_temp(i, &valid);
		bpf_printk("RAPL core[%d]=%uC%s", i, temp, valid ? "" : "?");
	}
}

s32 BPF_STRUCT_OPS(select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	__u32 nr_cpus = clamp_nr_cpus();
	bool found_warm = false;
	s32 cpu;

	(void)wake_flags;

	if (!nr_cpus) {
		cpu = select_cpu_default(p, prev_cpu, wake_flags);
		goto log_return;
	}

	/* 1) Prefer to keep the task on its previous CPU if it isn't hot. */
	cpu = reuse_prev_cpu(p, prev_cpu, nr_cpus);
	if (cpu >= 0)
		goto log_return;

	/* 2) Search for the coldest permitted CPU with the shallowest DSQ. */
	cpu = pick_cold_cpu(p, nr_cpus, &found_warm);
	if (cpu >= 0)
		goto log_return;

	/*
	 * 3) No cold CPUs remain. If we saw at least one warm candidate,
	 *    exclude hot CPUs and ask the default selector (EEVDF / CFS)
	 *    to choose among the remaining warm CPUs.
	 */
	if (found_warm) {
		steer_away_from_hot(p, nr_cpus);
		cpu = select_cpu_default(p, prev_cpu, wake_flags);
		goto log_return;
	}

	/*
	 * 4) Every allowed CPU is hot (or none were eligible). Fall back
	 *    without exclusions so the kernel can pick the least bad CPU.
	 */
	cpu = select_cpu_default(p, prev_cpu, wake_flags);

log_return:
	log_sched_decision(p, prev_cpu, cpu);
	return cpu;
}

void BPF_STRUCT_OPS(rr_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, RR_SLICE_NS, enq_flags);
}

void BPF_STRUCT_OPS(rr_dispatch, s32 cpu, struct task_struct *prev)
{
	log_stats_from_map();
	scx_bpf_dsq_move_to_local(SCX_DSQ_LOCAL);
}

void BPF_STRUCT_OPS(rr_running, struct task_struct *p){}

void BPF_STRUCT_OPS(rr_stopping, struct task_struct *p, bool runnable){}

s32 BPF_STRUCT_OPS_SLEEPABLE(rr_init)
{
	return scx_bpf_create_dsq(0, -1);
}

void BPF_STRUCT_OPS(rr_exit, struct scx_exit_info *ei){}

SEC(".struct_ops.link")
struct sched_ext_ops energy_aware_ops = {
	.select_cpu		= (void *)select_cpu,
	.enqueue		= (void *)rr_enqueue,
	.dispatch		= (void *)rr_dispatch,
	.running		= (void *)rr_running,
	.stopping		= (void *)rr_stopping,
	.init			= (void *)rr_init,
	.exit			= (void *)rr_exit,
	.name			= "rr_cold_aware",
};
