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

static volatile int keep_running = 1;

void sig_handler(int signo) {
    keep_running = 0;
}

/*
 * Build a simple mapping:
 *   thermal_zoneN  -> index = 0,1,2,... < MAX_CORE_TEMPS
 *
 * We assume the tracepoint thermal_temperature's thermal_zone_id == N.
 * This fills the BPF HASH map 'thermal_zone_index_map' that lives in the BPF object.
 *
 * out_mapped will contain the number of zones mapped (can be used as core_count).
 */
static int build_thermal_zone_mapping(int tz_map_fd, int *out_mapped)
{
    DIR *dir;
    struct dirent *de;
    int idx = 0;

    dir = opendir("/sys/class/thermal");
    if (!dir) {
        fprintf(stderr, "WARNING: failed to open /sys/class/thermal: %s\n",
                strerror(errno));
        return -1;
    }

    while ((de = readdir(dir)) != NULL) {
        int tz_id;

        if (sscanf(de->d_name, "thermal_zone%d", &tz_id) != 1)
            continue;

        if (idx >= MAX_CORE_TEMPS) {
            fprintf(stderr,
                    "INFO: reached MAX_CORE_TEMPS=%d, ignoring extra zones\n",
                    MAX_CORE_TEMPS);
            break;
        }

        __s32 key = tz_id;
        __u32 val = idx;

        if (bpf_map_update_elem(tz_map_fd, &key, &val, BPF_ANY)) {
            fprintf(stderr,
                    "WARNING: failed to update thermal_zone_index_map for tz_id=%d idx=%d: %s\n",
                    tz_id, idx, strerror(errno));
            continue;
        }

        printf("Mapped thermal_zone%d -> core_temp_map[%d]\n", tz_id, idx);
        idx++;
    }

    closedir(dir);

    if (out_mapped)
        *out_mapped = idx;

    if (idx == 0) {
        fprintf(stderr,
                "WARNING: no thermal zones mapped; temps may remain unused\n");
    }

    return 0;
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
    if (tz_map_fd >= 0) {
        printf("Found thermal_zone_index_map, building zone->index mapping...\n");
        build_thermal_zone_mapping(tz_map_fd, &mapped_zones);
    } else {
        printf("No thermal_zone_index_map in this object (ok if not using hwmon_stats_updater).\n");
    }

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

    temps_map_fd = bpf_object__find_map_fd_by_name(obj, "core_temp_map");
    if (temps_map_fd < 0) {
        fprintf(stderr, "ERROR: failed to find core_temp_map\n");
        goto cleanup;
    }
    
    const char *stats_pin_path = "/sys/fs/bpf/rapl_stats";
    const char *temps_pin_path = "/sys/fs/bpf/rapl_temps";
    err = bpf_obj_pin(stats_map_fd, stats_pin_path);
    if (err && errno != EEXIST) {
        fprintf(stderr, "WARNING: failed to pin map to %s: %s\n", stats_pin_path, strerror(errno));
    } else {
        printf("BPF map pinned to: %s\n", stats_pin_path);
    }

    err = bpf_obj_pin(temps_map_fd, temps_pin_path);
    if (err && errno != EEXIST) {
        fprintf(stderr, "WARNING: failed to pin map to %s: %s\n", temps_pin_path, strerror(errno));
    } else {
        printf("BPF map pinned to: %s\n", temps_pin_path);
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
    printf("Per-core temps available at: %s\n", temps_pin_path);
    printf("Press Ctrl+C to stop.\n\n");
    
    while (keep_running) {
        pause(); 
    }
    
    printf("\n\nStopping...\n");
    
    unlink("/sys/fs/bpf/rapl_stats");
    unlink("/sys/fs/bpf/rapl_temps");
    
cleanup:
    if (link)
        bpf_link__destroy(link);
    bpf_object__close(obj);
    return err != 0;
}