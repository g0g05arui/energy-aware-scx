// SPDX-License-Identifier: GPL-2.0
/* Energy-aware sched_ext scheduler using RAPL stats */

#include <scx/common.bpf.h>
#include "include/rapl_stats.h"

char _license[] SEC("license") = "GPL";

/* 
 * Energy-aware scheduler that adjusts scheduling decisions based on:
 * - Current power consumption
 * - Temperature
 * - Energy efficiency targets
 *
 * Policy:
 * - When power/temp is high, reduce time slices and prefer energy efficiency
 * - When power/temp is low, use standard time slices for better performance
 * - Dynamically adjust based on real-time RAPL measurements
 */

/* Power/temperature thresholds */
#define TEMP_THRESHOLD_HIGH 75    // °C - start being more aggressive about power saving
#define TEMP_THRESHOLD_CRITICAL 85 // °C - very aggressive power saving
#define POWER_THRESHOLD_PERCENT 80 // % of TDP - start power saving at 80% of TDP

/* Time slice adjustments based on power state */
#define SLICE_NORMAL SCX_SLICE_DFL              // Normal slice
#define SLICE_POWER_SAVE (SCX_SLICE_DFL / 2)    // Reduced slice for power saving
#define SLICE_AGGRESSIVE_SAVE (SCX_SLICE_DFL / 4) // Very aggressive power saving

/* BPF map to read RAPL stats - external map created by rapl_stats_updater */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rapl_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rapl_stats_map SEC(".maps");

/* Per-CPU DSQ for energy-aware scheduling */
#define ENERGY_DSQ 0

/* Statistics tracking */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} scheduler_stats SEC(".maps");

enum stat_idx {
    STAT_POWER_SAVE_DECISIONS = 0,
    STAT_NORMAL_DECISIONS = 1,
    STAT_AGGRESSIVE_SAVE_DECISIONS = 2,
};

/*
 * Determine the appropriate time slice based on current energy state
 */
static u64 get_energy_aware_slice(void)
{
    struct rapl_stats *rapl;
    __u32 key = 0;
    u64 slice = SLICE_NORMAL;
    
    rapl = bpf_map_lookup_elem(&rapl_stats_map, &key);
    if (!rapl) {
        // If we can't read stats, use normal scheduling
        return SLICE_NORMAL;
    }
    
    // Check temperature first (highest priority)
    if (rapl->package_temp >= TEMP_THRESHOLD_CRITICAL || 
        rapl->core_temp >= TEMP_THRESHOLD_CRITICAL) {
        // Critical temperature - very aggressive power saving
        slice = SLICE_AGGRESSIVE_SAVE;
        
        key = STAT_AGGRESSIVE_SAVE_DECISIONS;
        __u64 *count = bpf_map_lookup_elem(&scheduler_stats, &key);
        if (count)
            __sync_fetch_and_add(count, 1);
            
    } else if (rapl->package_temp >= TEMP_THRESHOLD_HIGH || 
               rapl->core_temp >= TEMP_THRESHOLD_HIGH) {
        // High temperature - moderate power saving
        slice = SLICE_POWER_SAVE;
        
        key = STAT_POWER_SAVE_DECISIONS;
        __u64 *count = bpf_map_lookup_elem(&scheduler_stats, &key);
        if (count)
            __sync_fetch_and_add(count, 1);
            
    } else if (rapl->tdp > 0) {
        // Check power consumption relative to TDP
        u64 power_percent = (rapl->package_power * 100) / rapl->tdp;
        
        if (power_percent >= POWER_THRESHOLD_PERCENT) {
            // High power consumption - enable power saving
            slice = SLICE_POWER_SAVE;
            
            key = STAT_POWER_SAVE_DECISIONS;
            __u64 *count = bpf_map_lookup_elem(&scheduler_stats, &key);
            if (count)
                __sync_fetch_and_add(count, 1);
        } else {
            // Normal operation
            key = STAT_NORMAL_DECISIONS;
            __u64 *count = bpf_map_lookup_elem(&scheduler_stats, &key);
            if (count)
                __sync_fetch_and_add(count, 1);
        }
    }
    
    return slice;
}

/*
 * Called when a task is waking up. Dispatch with energy-aware time slice.
 */
void BPF_STRUCT_OPS(energy_aware_enqueue, struct task_struct *p, u64 enq_flags)
{
    u64 slice = get_energy_aware_slice();
    
    /* Dispatch to global DSQ with energy-aware time slice */
    scx_bpf_dsq_insert(p, ENERGY_DSQ, slice, enq_flags);
}

/*
 * Called when the CPU is looking for the next task to run.
 */
void BPF_STRUCT_OPS(energy_aware_dispatch, s32 cpu, struct task_struct *prev)
{
    /* Consume tasks from our energy-aware DSQ */
    if (!scx_bpf_dsq_move_to_local(ENERGY_DSQ)) {
        /* If no tasks in our DSQ, check local DSQ */
        scx_bpf_dsq_move_to_local(SCX_DSQ_LOCAL);
    }
}

/*
 * Called when a task is being scheduled.
 */
void BPF_STRUCT_OPS(energy_aware_running, struct task_struct *p)
{
    /* Task is now running - could add per-task energy tracking here */
}

/*
 * Called when a task stops running.
 */
void BPF_STRUCT_OPS(energy_aware_stopping, struct task_struct *p, bool runnable)
{
    /* Task stopped - will be re-enqueued if still runnable */
    /* Energy-aware time slice will be recalculated on next enqueue */
}

/*
 * Called when a task's time slice expires
 */
void BPF_STRUCT_OPS(energy_aware_tick, struct task_struct *p)
{
    /* Time slice expired - task will be preempted and re-enqueued */
    /* This allows us to reassess the energy situation frequently */
}

/*
 * Initialize the scheduler.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(energy_aware_init)
{
    int err;
    __u32 key;
    __u64 zero = 0;
    
    /* Create our custom DSQ for energy-aware scheduling */
    err = scx_bpf_create_dsq(ENERGY_DSQ, -1);
    if (err) {
        scx_bpf_error("Failed to create energy-aware DSQ: %d", err);
        return err;
    }
    
    /* Initialize statistics - unroll loop for BPF verifier */
    key = 0;
    bpf_map_update_elem(&scheduler_stats, &key, &zero, BPF_ANY);
    key = 1;
    bpf_map_update_elem(&scheduler_stats, &key, &zero, BPF_ANY);
    key = 2;
    bpf_map_update_elem(&scheduler_stats, &key, &zero, BPF_ANY);
    
    return 0;
}

/*
 * Cleanup when scheduler is being unloaded.
 */
void BPF_STRUCT_OPS(energy_aware_exit, struct scx_exit_info *ei)
{
    /* Print final statistics */
    __u32 key;
    __u64 *count;
    
    bpf_printk("Energy-Aware Scheduler Statistics:");
    
    key = STAT_NORMAL_DECISIONS;
    count = bpf_map_lookup_elem(&scheduler_stats, &key);
    if (count)
        bpf_printk("  Normal decisions: %llu", *count);
    
    key = STAT_POWER_SAVE_DECISIONS;
    count = bpf_map_lookup_elem(&scheduler_stats, &key);
    if (count)
        bpf_printk("  Power save decisions: %llu", *count);
    
    key = STAT_AGGRESSIVE_SAVE_DECISIONS;
    count = bpf_map_lookup_elem(&scheduler_stats, &key);
    if (count)
        bpf_printk("  Aggressive save decisions: %llu", *count);
}

SEC(".struct_ops.link")
struct sched_ext_ops energy_aware_ops = {
    .enqueue        = (void *)energy_aware_enqueue,
    .dispatch       = (void *)energy_aware_dispatch,
    .running        = (void *)energy_aware_running,
    .stopping       = (void *)energy_aware_stopping,
    .tick           = (void *)energy_aware_tick,
    .init           = (void *)energy_aware_init,
    .exit           = (void *)energy_aware_exit,
    .name           = "energy_aware",
};
