#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../include/rapl_stats.h"

char LICENSE[] SEC("license") = "GPL";

// Map to store RAPL stats
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

// Timer wrapper struct
struct timer_wrapper {
    struct bpf_timer timer;
};

// BPF timer map - must use a struct containing bpf_timer
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

// Timer callback function - runs every 100ms
static int timer_callback(void *map, int *key, struct bpf_timer *timer)
{
    __u32 stats_key = 0;
    __u32 config_key = 0;
    struct rapl_stats *stats;
    struct rapl_config *cfg;
    __u32 core_count = MAX_CORE_SENSORS;

    stats = bpf_map_lookup_elem(&rapl_stats_map, &stats_key);
    if (!stats)
        return 0;

    cfg = bpf_map_lookup_elem(&rapl_config_map, &config_key);
    if (cfg && cfg->core_count > 0 && cfg->core_count <= MAX_CORE_SENSORS)
        core_count = cfg->core_count;
    
    // Generate timestamp
    stats->timestamp = bpf_ktime_get_ns();
    stats->delta_time = 100000000; // 100ms in ns
    
    // Generate random power values (in watts)
    stats->package_power = rand_range(15, 95);
    stats->core_power = rand_range(10, 65);
    
    // Calculate energy (joules = watts * seconds)
    stats->package_energy = (stats->package_power * 100) / 1000;
    stats->core_energy = (stats->core_power * 100) / 1000;
    
    // Generate random temperature values (in degrees Celsius)
    stats->package_temp = rand_range(40, 85);
#pragma unroll
    for (int i = 0; i < MAX_CORE_SENSORS; i++)
        stats->core_temp[i] = rand_range(38, 82);
    stats->core_count = core_count;
    
    // TDP
    stats->tdp = rand_range(35, 125);
    
    // Re-arm the timer for another 100ms
    bpf_timer_start(timer, 100000000, 0); // 100ms = 100,000,000 ns
    
    return 0;
}

// Program to initialize and start the timer
SEC("syscall")
int start_timer(void *ctx)
{
    __u32 key = 0;
    struct timer_wrapper *tw;
    int ret;
    
    tw = bpf_map_lookup_elem(&timer_map, &key);
    if (!tw)
        return -1;
    
    // Initialize the timer
    ret = bpf_timer_init(&tw->timer, &timer_map, 0); // 0 = CLOCK_BOOTTIME
    if (ret)
        return ret;
    
    // Set the timer callback
    ret = bpf_timer_set_callback(&tw->timer, timer_callback);
    if (ret)
        return ret;
    
    // Start the timer (100ms = 100,000,000 ns)
    ret = bpf_timer_start(&tw->timer, 100000000, 0);
    
    return ret;
}
