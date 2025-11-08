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
    int map_fd;
    int err;
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    obj = bpf_object__open_file("repl_stats_interval.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: failed to open BPF object\n");
        return 1;
    }
    
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: failed to load BPF object: %d\n", err);
        goto cleanup;
    }
    
    map_fd = bpf_object__find_map_fd_by_name(obj, "rapl_stats_map");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: failed to find rapl_stats_map\n");
        goto cleanup;
    }
    
    const char *pin_path = "/sys/fs/bpf/rapl_stats";
    err = bpf_obj_pin(map_fd, pin_path);
    if (err && errno != EEXIST) {
        fprintf(stderr, "WARNING: failed to pin map to %s: %s\n", pin_path, strerror(errno));
    } else {
        printf("BPF map pinned to: %s\n", pin_path);
    }
    
    printf("RAPL Stats Updater started. Updating every 100ms...\n");
    printf("SCX can read stats from BPF map at: %s\n", pin_path);
    printf("Press Ctrl+C to stop.\n\n");
    
    while (keep_running) {
        struct rapl_stats stats;
        __u32 key = 0;
        
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        stats.timestamp = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
        stats.delta_time = 100000000; // 100ms in ns
        
        stats.package_power = 15 + (rand() % 80);
        stats.core_power = 10 + (rand() % 55);
        stats.package_energy = (stats.package_power * 100) / 1000;
        stats.core_energy = (stats.core_power * 100) / 1000;
        stats.package_temp = 40 + (rand() % 45);
        stats.core_temp = 38 + (rand() % 44);
        stats.tdp = 35 + (rand() % 90);
        
        bpf_map_update_elem(map_fd, &key, &stats, BPF_ANY);
        
        if (bpf_map_lookup_elem(map_fd, &key, &stats) == 0) {
            printf("\r[Time: %llu ns] Package: %lluW/%lluJ %u°C | Core: %lluW/%lluJ %u°C | TDP: %lluW    ",
                   stats.timestamp,
                   stats.package_power, stats.package_energy, stats.package_temp,
                   stats.core_power, stats.core_energy, stats.core_temp,
                   stats.tdp);
            fflush(stdout);
        }
        
        usleep(100000);
    }
    
    printf("\n\nStopping...\n");
    
    unlink("/sys/fs/bpf/rapl_stats");
    
cleanup:
    if (link)
        bpf_link__destroy(link);
    bpf_object__close(obj);
    return err != 0;
}
