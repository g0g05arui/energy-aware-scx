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

struct thermal_temperature_args {
	__u64 pad;
	int temp;
	int trip;
	int type;
	int thermal_zone_id;
};

static __always_inline int handle_thermal_temperature(struct thermal_temperature_args *ctx)
{
	__s32 tz_id = ctx->thermal_zone_id;
	__u32 temp_mC = (__u32)ctx->temp;
	__u32 *p_idx;

	p_idx = bpf_map_lookup_elem(&thermal_zone_index_map, &tz_id);
	if (!p_idx)
		return 0;

	if (*p_idx >= MAX_CORE_TEMPS)
		return 0;

	bpf_map_update_elem(&core_temp_map, p_idx, &temp_mC, BPF_ANY);
	return 0;
}

SEC("tracepoint/thermal/thermal_temperature")
int bpf_hwmon_stats_updater(struct thermal_temperature_args *ctx)
{
	return handle_thermal_temperature(ctx);
}
