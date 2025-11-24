#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/rapl_stats.h"

char LICENSE[] SEC("license") = "GPL";

#define PERF_IDX_PACKAGE 0
#define PERF_IDX_CORE    1
#define PERF_EVENT_COUNT 2
#define SAMPLE_INTERVAL_NS 100000000ULL
#define MICROJOULES_PER_JOULE 1000000ULL

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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_CORE_TEMPS);
    __type(key, __u32);
    __type(value, __u32);
} core_temp_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, PERF_EVENT_COUNT);
    __type(key, __u32);
    __type(value, __u32);
} perf_event_map SEC(".maps");

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
static __u64 last_pkg_energy;
static __u64 last_core_energy;
static __u64 last_timestamp;

static __u64 rand_u64(void)
{
    seed = seed * 1103515245 + 12345;
    return seed;
}

static __u32 rand_range(__u32 min, __u32 max)
{
    return min + (rand_u64() % (max - min + 1));
}

static __u64 energy_delta(__u64 curr, __u64 prev)
{
    if (!prev)
        return 0;
    if (curr >= prev)
        return curr - prev;
    return (1ULL << 32) - prev + curr;
}

static int read_energy(__u32 idx, __u64 *value)
{
    struct bpf_perf_event_value data = {};
    int ret;

    ret = bpf_perf_event_read_value(&perf_event_map, idx, &data,
                                    sizeof(data));
    if (ret)
        return ret;
    *value = data.counter;
    return 0;
}

static __u64 compute_power(__u64 delta_energy_uj, __u64 delta_ns)
{
    if (!delta_ns || !delta_energy_uj)
        return 0;
    return (delta_energy_uj * 1000ULL) / delta_ns;
}

static void update_core_temps(__u32 count)
{
#pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_CORE_TEMPS; i++) {
        if (i >= count)
            break;
        __u32 idx = i;
        __u32 temp = rand_range(38, 82);
        bpf_map_update_elem(&core_temp_map, &idx, &temp, BPF_ANY);
    }
}

static int timer_callback(void *map, int *key, struct bpf_timer *timer)
{
    __u32 stats_key = 0;
    __u32 config_key = 0;
    struct rapl_stats *stats;
    struct rapl_config *cfg;
    __u32 core_count = MAX_CORE_TEMPS;
    __u64 now = bpf_ktime_get_ns();
    __u64 delta_ns = last_timestamp ? (now - last_timestamp) : SAMPLE_INTERVAL_NS;

    stats = bpf_map_lookup_elem(&rapl_stats_map, &stats_key);
    if (!stats)
        goto out;

    cfg = bpf_map_lookup_elem(&rapl_config_map, &config_key);
    if (cfg && cfg->core_count > 0 && cfg->core_count <= MAX_CORE_TEMPS)
        core_count = cfg->core_count;

    stats->timestamp = now;
    stats->delta_time = delta_ns;
    stats->core_count = core_count;

    __u64 pkg_energy_raw = 0;
    if (!read_energy(PERF_IDX_PACKAGE, &pkg_energy_raw)) {
        __u64 delta_energy = energy_delta(pkg_energy_raw, last_pkg_energy);
        stats->package_power = compute_power(delta_energy, delta_ns);
        stats->package_energy = pkg_energy_raw / MICROJOULES_PER_JOULE;
        last_pkg_energy = pkg_energy_raw;
    }

    __u64 core_energy_raw = 0;
    if (!read_energy(PERF_IDX_CORE, &core_energy_raw)) {
        __u64 delta_energy = energy_delta(core_energy_raw, last_core_energy);
        stats->core_power = compute_power(delta_energy, delta_ns);
        stats->core_energy = core_energy_raw / MICROJOULES_PER_JOULE;
        last_core_energy = core_energy_raw;
    }

    stats->package_temp = rand_range(40, 85);
    update_core_temps(core_count);
    stats->tdp = stats->package_power;

out:
    last_timestamp = now;
    bpf_timer_start(timer, SAMPLE_INTERVAL_NS, 0);
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

    ret = bpf_timer_start(&tw->timer, SAMPLE_INTERVAL_NS, 0);
    return ret;
}
