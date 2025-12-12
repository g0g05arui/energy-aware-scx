// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/rapl_stats.h"

char LICENSE[] SEC("license") = "GPL";

#define STATS_INTERVAL_NS 100000000ull
#define TJMAX_INTERVAL_NS 100000000ull
#define TJMAX_DELTA_MASK 0x7f
#define TJMAX_DELTA_SHIFT 16

extern __u64 therm_read_ia32_therm_status(void) __ksym;

struct timer_wrapper {
	struct bpf_timer timer;
};

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
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct timer_wrapper);
} timer_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, __u32);
	__type(value, struct tjmax_delta_sample);
} tjmax_delta_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, __u32);
	__type(value, struct timer_wrapper);
} tjmax_timer_map SEC(".maps");

static __u64 seed = 12345;

static __u64 rand_u64(void)
{
	seed = seed * 1103515245 + 12345;
	return seed;
}

static __u32 rand_range(__u32 min, __u32 max)
{
	return min + (rand_u64() % (max - min + 1));
}

static inline __u32 get_core_count(void)
{
	__u32 config_key = 0;
	struct rapl_config *cfg;

	cfg = bpf_map_lookup_elem(&rapl_config_map, &config_key);
	if (!cfg || cfg->core_count == 0 || cfg->core_count > MAX_CORE_TEMPS)
		return MAX_CORE_TEMPS;
	return cfg->core_count;
}

static inline __u32 get_tjmax_cpu_count(void)
{
	__u32 config_key = 0;
	struct rapl_config *cfg;

	cfg = bpf_map_lookup_elem(&rapl_config_map, &config_key);
	if (!cfg || cfg->tjmax_cpu_count == 0 || cfg->tjmax_cpu_count > MAX_CPUS)
		return MAX_CPUS;
	return cfg->tjmax_cpu_count;
}

static int stats_timer_callback(void *map, __u32 *key, struct bpf_timer *timer)
{
	__u32 stats_key = 0;
	struct rapl_stats *stats;
	__u32 core_count = get_core_count();

	stats = bpf_map_lookup_elem(&rapl_stats_map, &stats_key);
	if (!stats)
		return 0;

	stats->timestamp = bpf_ktime_get_ns();
	stats->delta_time = STATS_INTERVAL_NS;

	stats->package_power = rand_range(15, 95);
	stats->core_power = rand_range(10, 65);

	stats->package_energy = (stats->package_power * 100) / 1000;
	stats->core_energy = (stats->core_power * 100) / 1000;

	stats->package_temp = rand_range(40, 85);
	stats->core_count = core_count;

	stats->tdp = rand_range(35, 125);

	bpf_timer_start(timer, STATS_INTERVAL_NS, 0);
	return 0;
}

static int tjmax_timer_callback(void *map, __u32 *key, struct bpf_timer *timer)
{
	struct tjmax_delta_sample sample = {};
	__u64 therm = therm_read_ia32_therm_status();

	sample.delta = (therm >> TJMAX_DELTA_SHIFT) & TJMAX_DELTA_MASK;
	sample.ts_ns = bpf_ktime_get_ns();

	if (key)
		bpf_map_update_elem(&tjmax_delta_map, key, &sample, BPF_ANY);

	bpf_timer_start(timer, TJMAX_INTERVAL_NS, BPF_F_TIMER_CPU_PIN);
	return 0;
}

static int init_stats_timer(void)
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
	ret = bpf_timer_set_callback(&tw->timer, stats_timer_callback);
	if (ret)
		return ret;

	return bpf_timer_start(&tw->timer, STATS_INTERVAL_NS, 0);
}

static int init_tjmax_timer(__u32 cpu)
{
	struct timer_wrapper *tw;
	__u32 key = cpu;
	int ret;

	tw = bpf_map_lookup_elem(&tjmax_timer_map, &key);
	if (!tw)
		return -1;

	ret = bpf_timer_init(&tw->timer, &tjmax_timer_map, 0);
	if (ret)
		return ret;
	ret = bpf_timer_set_callback(&tw->timer, tjmax_timer_callback);
	if (ret)
		return ret;

	return bpf_timer_start(&tw->timer, TJMAX_INTERVAL_NS, BPF_F_TIMER_CPU_PIN);
}

SEC("syscall")
int start_timer(void *ctx)
{
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 max_cpus = get_tjmax_cpu_count();
	int ret;

	if (cpu == 0) {
		ret = init_stats_timer();
		if (ret)
			return ret;
	}

	if (cpu >= max_cpus)
		return 0;

	return init_tjmax_timer(cpu);
}
