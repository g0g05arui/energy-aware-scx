// SPDX-License-Identifier: GPL-2.0
/* Userspace loader for Energy-Aware sched_ext scheduler */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "include/rapl_stats.h"

static volatile int keep_running = 1;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

void sig_handler(int signo) {
    keep_running = 0;
}

/* Print current RAPL stats */
void print_rapl_stats(int map_fd) {
    struct rapl_stats stats;
    __u32 key = 0;
    int err;
    
    err = bpf_map_lookup_elem(map_fd, &key, &stats);
    if (err) {
        return; // Silently fail if stats not available yet
    }
    
    printf("\n=== Current Energy State ===\n");
    printf("Package Power: %llu W  (TDP: %llu W, %.1f%%)\n", 
           stats.package_power, stats.tdp,
           stats.tdp > 0 ? (double)stats.package_power * 100.0 / stats.tdp : 0.0);
    printf("Package Temp:  %u °C\n", stats.package_temp);
    printf("Core Power:    %llu W\n", stats.core_power);
    printf("Core Temp:     %u °C\n", stats.core_temp);
    
    // Determine current power state
    const char *state;
    if (stats.package_temp >= 85 || stats.core_temp >= 85) {
        state = "CRITICAL - Aggressive Power Saving";
    } else if (stats.package_temp >= 75 || stats.core_temp >= 75) {
        state = "HIGH - Power Saving Mode";
    } else if (stats.tdp > 0 && (stats.package_power * 100 / stats.tdp) >= 80) {
        state = "HIGH - Power Saving Mode";
    } else {
        state = "NORMAL - Performance Mode";
    }
    printf("Scheduler Mode: %s\n", state);
}

/* Print scheduler statistics */
void print_scheduler_stats(struct bpf_object *obj) {
    struct bpf_map *stats_map;
    int stats_fd;
    __u32 key;
    __u64 count;
    
    stats_map = bpf_object__find_map_by_name(obj, "scheduler_stats");
    if (!stats_map)
        return;
    
    stats_fd = bpf_map__fd(stats_map);
    if (stats_fd < 0)
        return;
    
    printf("\n=== Scheduler Statistics ===\n");
    
    key = 1; // STAT_NORMAL_DECISIONS
    if (bpf_map_lookup_elem(stats_fd, &key, &count) == 0) {
        printf("Normal decisions:     %llu\n", count);
    }
    
    key = 0; // STAT_POWER_SAVE_DECISIONS
    if (bpf_map_lookup_elem(stats_fd, &key, &count) == 0) {
        printf("Power save decisions: %llu\n", count);
    }
    
    key = 2; // STAT_AGGRESSIVE_SAVE_DECISIONS
    if (bpf_map_lookup_elem(stats_fd, &key, &count) == 0) {
        printf("Aggressive save:      %llu\n", count);
    }
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_link *link = NULL;
    int err;
    int rapl_map_fd = -1;
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    /* Check if RAPL stats updater is running */
    const char *rapl_pin_path = "/sys/fs/bpf/rapl_stats";
    rapl_map_fd = bpf_obj_get(rapl_pin_path);
    if (rapl_map_fd < 0) {
        fprintf(stderr, "WARNING: RAPL stats map not found at %s\n", rapl_pin_path);
        fprintf(stderr, "The energy-aware scheduler will use default behavior.\n");
        fprintf(stderr, "Start rapl_stats_updater for full functionality.\n\n");
    }
    
    /* Set up libbpf logging - disable by default, can enable with env var */
    if (getenv("VERBOSE")) {
        libbpf_set_print(libbpf_print_fn);
    } else {
        libbpf_set_print(NULL);
    }
    
    /* Load BPF object file */
    const char *bpf_obj_path = argc > 1 ? argv[1] : "scx_energy_aware.bpf.o";
    
    obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: failed to open BPF object at %s: %s\n", 
                bpf_obj_path, strerror(errno));
        return 1;
    }
    
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: failed to load BPF object: %d\n", err);
        goto cleanup;
    }
    
    /* Find and attach the scheduler struct_ops */
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        if (bpf_program__type(prog) == BPF_PROG_TYPE_STRUCT_OPS) {
            link = bpf_map__attach_struct_ops(
                bpf_object__find_map_by_name(obj, "energy_aware_ops")
            );
            if (libbpf_get_error(link)) {
                fprintf(stderr, "ERROR: failed to attach struct_ops: %s\n", 
                        strerror(errno));
                link = NULL;
                goto cleanup;
            }
            break;
        }
    }
    
    if (!link) {
        fprintf(stderr, "ERROR: no struct_ops program found\n");
        err = -1;
        goto cleanup;
    }
    
    printf("======================================\n");
    printf("Energy-Aware Scheduler Loaded!\n");
    printf("======================================\n");
    printf("\nThis scheduler adjusts task scheduling based on:\n");
    printf("  - Current power consumption\n");
    printf("  - Temperature\n");
    printf("  - TDP limits\n");
    printf("\nPower/Temperature Thresholds:\n");
    printf("  Normal:     Temp < 75°C, Power < 80%% TDP\n");
    printf("  Power Save: Temp >= 75°C OR Power >= 80%% TDP\n");
    printf("  Aggressive: Temp >= 85°C\n");
    printf("\nPress Ctrl+C to stop and unload the scheduler\n");
    
    if (rapl_map_fd >= 0) {
        print_rapl_stats(rapl_map_fd);
    }
    
    /* Monitor and print stats every 5 seconds */
    int counter = 0;
    while (keep_running) {
        sleep(1);
        counter++;
        
        if (counter >= 5) {
            if (rapl_map_fd >= 0) {
                print_rapl_stats(rapl_map_fd);
            }
            print_scheduler_stats(obj);
            printf("\n");
            counter = 0;
        }
    }
    
    printf("\n\n=== Final Statistics ===\n");
    print_scheduler_stats(obj);
    printf("\nUnloading scheduler...\n");
    
cleanup:
    if (rapl_map_fd >= 0)
        close(rapl_map_fd);
    if (link)
        bpf_link__destroy(link);
    if (obj)
        bpf_object__close(obj);
    
    printf("Scheduler unloaded\n");
    return err != 0;
}
