#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../include/rapl_stats.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rapl_stats);
} rapl_stats_map SEC(".maps");

static __u64 seed = 12345;

static __u64 rand_u64(void) {
    seed = seed * 1103515245 + 12345;
    return seed;
}

static __u32 rand_range(__u32 min, __u32 max) {
    return min + (rand_u64() % (max - min + 1));
}

SEC("tp/timer")
int update_rapl_stats(void *ctx) {
    __u32 key = 0;
    struct rapl_stats stats = {};
    
    stats.timestamp = bpf_ktime_get_ns();
    
    stats.delta_time = 100000000;
    
    stats.package_power = rand_range(15000, 95000) / 1000;
    
    stats.core_power = rand_range(10000, 65000) / 1000;
    
    stats.package_energy = (stats.package_power * 100) / 1000;
    stats.core_energy = (stats.core_power * 100) / 1000;
    
    stats.package_temp = rand_range(40, 85);
    
    stats.core_temp = rand_range(38, 82);
    
    stats.tdp = rand_range(35, 125);
    
    bpf_map_update_elem(&rapl_stats_map, &key, &stats, BPF_ANY);
    
    return 0;
}
