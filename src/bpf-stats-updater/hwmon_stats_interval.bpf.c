// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "../include/rapl_stats.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CORE_TEMPS);
	__type(key, __u32);
	__type(value, __u32);
} core_temp_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, __s32);
	__type(value, __u32);
} thermal_zone_index_map SEC(".maps");

struct trace_entry {
	__u16 type;
	__u8 flags;
	__u8 preempt_count;
	__s32 pid;
};

struct thermal_temperature_args {
	struct trace_entry ent;
	__u32 data_loc_thermal_zone;
	int id;
	int temp_prev;
	int temp;
};

static __always_inline int handle_thermal_temperature(struct thermal_temperature_args *ctx)
{
	__s32 tz_id = ctx->id;
	int temp = ctx->temp;
	__u32 *p_idx;
	__u32 idx;
	int ret;

	if (temp <= 0)
		return 0;

	p_idx = bpf_map_lookup_elem(&thermal_zone_index_map, &tz_id);
	if (!p_idx)
		return 0;

	idx = *p_idx;
	if (idx >= MAX_CORE_TEMPS)
		return 0;

	ret = bpf_map_update_elem(&core_temp_map, &idx, &temp, BPF_ANY);
	if (ret)
		bpf_printk("temp update failed tz=%d idx=%u err=%d", tz_id, idx, ret);
	else
		bpf_printk("temp update tz=%d idx=%u temp=%d", tz_id, idx, temp);
	return 0;
}

SEC("tracepoint/thermal/thermal_temperature")
int bpf_hwmon_stats_updater(struct thermal_temperature_args *ctx)
{
	return handle_thermal_temperature(ctx);
}
