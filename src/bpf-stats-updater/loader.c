// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <time.h>
#include <dirent.h>
#include <string.h>

#include "../include/rapl_stats.h"
#include "thermal_zone_helpers.h"

static volatile int keep_running = 1;

void sig_handler(int signo) {
    keep_running = 0;
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    int stats_map_fd;
    int temps_map_fd;
    int config_map_fd;
    int tz_map_fd;
    int timer_prog_fd;
    int err;
    int mapped_zones = 0;
    bool stats_map_pinned = false;
    bool temps_map_pinned = false;
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    const char *bpf_obj_path = argc > 1 ? argv[1] : "repl_stats_interval.bpf.o";
    
    obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: failed to open BPF object at %s\n", bpf_obj_path);
        fprintf(stderr, "Make sure you run this from the build/ directory or provide the path\n");
        return 1;
    }
    
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    /* Optional: find and build thermal_zone_id -> core_temp_map index mapping */
    tz_map_fd = bpf_object__find_map_fd_by_name(obj, "thermal_zone_index_map");
    if (tz_map_fd >= 0)
        printf("Found thermal_zone_index_map, building zone->index mapping...\n");
    else
        printf("No thermal_zone_index_map in this object (ok if temps are updated elsewhere).\n");
    build_thermal_zone_mapping(tz_map_fd, -1, &mapped_zones);

    config_map_fd = bpf_object__find_map_fd_by_name(obj, "rapl_config_map");
    if (config_map_fd >= 0) {
        __u32 cfg_key = 0;
        struct rapl_config cfg = {};
        long cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN);
        if (cpu_cnt < 1)
            cpu_cnt = 1;

        /* If we have mapped zones, prefer that as an upper bound for core_count */
        if (mapped_zones > 0 && mapped_zones < cpu_cnt)
            cpu_cnt = mapped_zones;

        if (cpu_cnt > MAX_CORE_TEMPS)
            cpu_cnt = MAX_CORE_TEMPS;

        cfg.core_count = cpu_cnt;
        if (bpf_map_update_elem(config_map_fd, &cfg_key, &cfg, BPF_ANY))
            fprintf(stderr, "WARNING: failed to set core_count config: %s\n",
                    strerror(errno));
        else
            printf("Configured core_count=%ld (mapped_zones=%d)\n",
                   cpu_cnt, mapped_zones);
    } else {
        fprintf(stderr, "WARNING: rapl_config_map not found, using defaults\n");
    }
    
    stats_map_fd = bpf_object__find_map_fd_by_name(obj, "rapl_stats_map");
    if (stats_map_fd < 0) {
        fprintf(stderr, "ERROR: failed to find rapl_stats_map\n");
        goto cleanup;
    }

    const char *stats_pin_path = "/sys/fs/bpf/rapl_stats";
    const char *temps_pin_path = "/sys/fs/bpf/rapl_temps";
    err = bpf_obj_pin(stats_map_fd, stats_pin_path);
    if (err && errno != EEXIST) {
        fprintf(stderr, "WARNING: failed to pin map to %s: %s\n", stats_pin_path, strerror(errno));
    } else {
        printf("BPF map pinned to: %s\n", stats_pin_path);
        stats_map_pinned = true;
    }

    temps_map_fd = bpf_object__find_map_fd_by_name(obj, "core_temp_map");
    if (temps_map_fd >= 0) {
        err = bpf_obj_pin(temps_map_fd, temps_pin_path);
        if (err && errno != EEXIST) {
            fprintf(stderr, "WARNING: failed to pin map to %s: %s\n", temps_pin_path, strerror(errno));
        } else {
            printf("BPF map pinned to: %s\n", temps_pin_path);
            temps_map_pinned = true;
        }
    } else {
        printf("No core_temp_map in this object; run the dedicated HWMON loader to populate temps.\n");
    }
    
    prog = bpf_object__find_program_by_name(obj, "start_timer");
    if (!prog) {
        fprintf(stderr, "ERROR: failed to find start_timer program\n");
        goto cleanup;
    }
    
    timer_prog_fd = bpf_program__fd(prog);
    if (timer_prog_fd < 0) {
        fprintf(stderr, "ERROR: failed to get program fd\n");
        goto cleanup;
    }
    
    LIBBPF_OPTS(bpf_test_run_opts, opts);
    err = bpf_prog_test_run_opts(timer_prog_fd, &opts);
    if (err || opts.retval) {
        fprintf(stderr, "ERROR: failed to start BPF timer: %d (retval: %d)\n", err, opts.retval);
        goto cleanup;
    }
    
    printf("RAPL Stats Updater started with BPF timer (100ms interval)\n");
    printf("SCX can read stats from BPF map at: %s\n", stats_pin_path);
    if (temps_map_pinned)
        printf("Per-core temps available at: %s\n", temps_pin_path);
    else
        printf("Per-core temps available at: %s (run hwmon_stats_updater to populate)\n",
               temps_pin_path);
    printf("Press Ctrl+C to stop.\n\n");
    
    while (keep_running) {
        pause(); 
    }
    
    printf("\n\nStopping...\n");
    
    if (stats_map_pinned)
        unlink("/sys/fs/bpf/rapl_stats");
    if (temps_map_pinned)
        unlink("/sys/fs/bpf/rapl_temps");
    
cleanup:
    if (link)
        bpf_link__destroy(link);
    bpf_object__close(obj);
    return err != 0;
}
