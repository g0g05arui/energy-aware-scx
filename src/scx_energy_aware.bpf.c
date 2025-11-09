// SPDX-License-Identifier: GPL-2.0
/* Minimal Round-Robin sched_ext scheduler */

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

static __u64 last_printed_ts;

static __always_inline void log_stats_from_map(void)
{
	struct rapl_stats *stats;
	__u32 key = 0;

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

#pragma unroll
	for (int i = 0; i < MAX_CORE_SENSORS; i++) {
		if (i >= stats->core_count)
			break;
		bpf_printk("RAPL core[%d]=%uC", i, stats->core_temp[i]);
	}
}

/* Enqueue tasks to the per-CPU DSQ with a fixed timeslice. */
void BPF_STRUCT_OPS(rr_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, RR_SLICE_NS, enq_flags);
}

/* Dispatch next runnable task from the local DSQ. */
void BPF_STRUCT_OPS(rr_dispatch, s32 cpu, struct task_struct *prev)
{
	log_stats_from_map();
	scx_bpf_dsq_move_to_local(SCX_DSQ_LOCAL);
}

void BPF_STRUCT_OPS(rr_running, struct task_struct *p)
{
	/* No-op */
}

void BPF_STRUCT_OPS(rr_stopping, struct task_struct *p, bool runnable)
{
	/* No-op */
}

s32 BPF_STRUCT_OPS_SLEEPABLE(rr_init)
{
	return scx_bpf_create_dsq(0, -1);
}

void BPF_STRUCT_OPS(rr_exit, struct scx_exit_info *ei)
{
	/* No-op */
}

SEC(".struct_ops.link")
struct sched_ext_ops energy_aware_ops = {
	.enqueue		= (void *)rr_enqueue,
	.dispatch		= (void *)rr_dispatch,
	.running		= (void *)rr_running,
	.stopping		= (void *)rr_stopping,
	.init			= (void *)rr_init,
	.exit			= (void *)rr_exit,
	.name			= "rr_energy_stub",
};
