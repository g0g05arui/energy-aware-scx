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
#include "../include/rapl_stats.h"

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
    int timer_prog_fd;
    int err;
    
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

    config_map_fd = bpf_object__find_map_fd_by_name(obj, "rapl_config_map");
    if (config_map_fd >= 0) {
        __u32 cfg_key = 0;
        struct rapl_config cfg = {};
        long cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN);
        if (cpu_cnt < 1)
            cpu_cnt = 1;
        if (cpu_cnt > MAX_CORE_TEMPS)
            cpu_cnt = MAX_CORE_TEMPS;
        cfg.core_count = cpu_cnt;
        if (bpf_map_update_elem(config_map_fd, &cfg_key, &cfg, BPF_ANY))
            fprintf(stderr, "WARNING: failed to set core_count config: %s\n",
                    strerror(errno));
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
