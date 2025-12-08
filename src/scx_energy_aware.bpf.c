/* "Cold-aware" Round-Robin sched_ext scheduler */

#include "vmlinux.h"
#include <scx/common.bpf.h>
#include <bpf/bpf_helpers.h>
#include "rapl_stats.h"

char _license[] SEC("license") = "GPL";

#define RR_SLICE_NS SCX_SLICE_DFL

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

static __u64 last_printed_ts;
static __u32 cold_rr_cursor;

static __always_inline __u32 read_temp(__u32 idx, bool *valid)
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

static __always_inline __u32 read_temp_count(__u32 stats_core_count)
{
	__u32 key = 0;
	__u32 *count = bpf_map_lookup_elem(&core_temp_count_map, &key);

	if (count && *count && *count <= MAX_CORE_TEMPS)
		return *count;

	if (stats_core_count == 0 || stats_core_count > MAX_CORE_TEMPS)
		return MAX_CORE_TEMPS;

	return stats_core_count;
}

static __always_inline void log_stats_from_map(void)
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
	for (int i = 0; i < MAX_CORE_TEMPS; i++) {
		if (i >= temp_count)
			break;
		bool valid = false;
		__u32 temp = read_temp(i, &valid);
		bpf_printk("RAPL core[%d]=%uC%s", i, temp, valid ? "" : "?");
	}
}

static __always_inline s32 cold_select_cpu_impl(struct task_struct *p, s32 prev_cpu,
						u64 wake_flags)
{
	struct rapl_stats *stats;
	__u32 key = 0;
	bool idle_hint = false;
	s32 fallback = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &idle_hint);
	s32 best_cpu = -1;
	__u32 best_temp = (__u32)-1;
	__u32 temp_count;

	stats = bpf_map_lookup_elem(&rapl_stats_map, &key);
	if (!stats || !stats->core_count)
		return fallback;

	temp_count = read_temp_count(stats->core_count);
	if (temp_count > MAX_CORE_TEMPS)
		temp_count = MAX_CORE_TEMPS;

#pragma clang loop unroll(disable)
	for (int iter = 0; iter < MAX_CORE_TEMPS; iter++) {
		if (iter >= temp_count)
			break;
		__u32 idx = (cold_rr_cursor + iter) % temp_count;
		if (!bpf_cpumask_test_cpu(idx, p->cpus_ptr))
			continue;

		bool valid = false;
		__u32 temp = read_temp(idx, &valid);
		if (!valid)
			continue;

		if (temp < best_temp) {
			best_temp = temp;
			best_cpu = idx;
		}
	}

	if (best_cpu < 0)
		return fallback;

	cold_rr_cursor = (best_cpu + 1) % temp_count;

	if (scx_bpf_test_and_clear_cpu_idle(best_cpu))
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, RR_SLICE_NS, 0);

	return best_cpu;
}

s32 BPF_STRUCT_OPS(cold_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	return cold_select_cpu_impl(p, prev_cpu, wake_flags);
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
	.select_cpu		= (void *)cold_select_cpu,
	.enqueue		= (void *)rr_enqueue,
	.dispatch		= (void *)rr_dispatch,
	.running		= (void *)rr_running,
	.stopping		= (void *)rr_stopping,
	.init			= (void *)rr_init,
	.exit			= (void *)rr_exit,
	.name			= "rr_cold_aware",
};
