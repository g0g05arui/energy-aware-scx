#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/rapl_stats.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rapl_stats);
} rapl_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rapl_config);
} rapl_config_map SEC(".maps");

struct timer_wrapper {
    struct bpf_timer timer;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct timer_wrapper);
} timer_map SEC(".maps");

static __u64 seed = 12345;

static __u64 rand_u64(void) {
    seed = seed * 1103515245 + 12345;
    return seed;
}

static __u32 rand_range(__u32 min, __u32 max) {
    return min + (rand_u64() % (max - min + 1));
}

static int timer_callback(void *map, int *key, struct bpf_timer *timer)
{
    __u32 stats_key = 0;
    __u32 config_key = 0;
    struct rapl_stats *stats;
    struct rapl_config *cfg;
    __u32 core_count = MAX_CORE_TEMPS;

    stats = bpf_map_lookup_elem(&rapl_stats_map, &stats_key);
    if (!stats)
        return 0;

    cfg = bpf_map_lookup_elem(&rapl_config_map, &config_key);
    if (cfg && cfg->core_count > 0 && cfg->core_count <= MAX_CORE_TEMPS)
        core_count = cfg->core_count;
    
    stats->timestamp = bpf_ktime_get_ns();
    stats->delta_time = 100000000;
    
    stats->package_power = rand_range(15, 95);
    stats->core_power = rand_range(10, 65);
    
    stats->package_energy = (stats->package_power * 100) / 1000;
    stats->core_energy = (stats->core_power * 100) / 1000;
    
    stats->package_temp = rand_range(40, 85);
    stats->core_count = core_count;
    
    stats->tdp = rand_range(35, 125);
    
    bpf_timer_start(timer, 100000000, 0);
    
    return 0;
}

SEC("syscall")
int start_timer(void *ctx)
{
    __u32 key = 0;
    struct timer_wrapper *tw;
    int ret;
    
    tw = bpf_map_lookup_elem(&timer_map, &key);
    if (!tw)
        return -1;
    
    ret = bpf_timer_init(&tw->timer, &timer_map, 0); 
    if (ret)
        return ret;
    
    ret = bpf_timer_set_callback(&tw->timer, timer_callback);
    if (ret)
        return ret;
    
    ret = bpf_timer_start(&tw->timer, 100000000, 0);
    
    return ret;
}
