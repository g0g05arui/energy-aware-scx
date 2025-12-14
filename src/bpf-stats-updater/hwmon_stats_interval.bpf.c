// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../include/rapl_stats.h"
#include "../include/core_state.h"

char LICENSE[] SEC("license") = "GPL";

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
