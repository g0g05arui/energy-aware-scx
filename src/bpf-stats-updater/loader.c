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
    int timer_prog_fd;
    int err;
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Use relative path from build directory or full path
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
    
    // Find the stats map
    map_fd = bpf_object__find_map_fd_by_name(obj, "rapl_stats_map");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: failed to find rapl_stats_map\n");
        goto cleanup;
    }
    
    // Pin the map so SCX can access it
    const char *pin_path = "/sys/fs/bpf/rapl_stats";
    err = bpf_obj_pin(map_fd, pin_path);
    if (err && errno != EEXIST) {
        fprintf(stderr, "WARNING: failed to pin map to %s: %s\n", pin_path, strerror(errno));
    } else {
        printf("BPF map pinned to: %s\n", pin_path);
    }
    
    // Find and run the timer initialization program
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
    
    // Execute the timer initialization program
    LIBBPF_OPTS(bpf_test_run_opts, opts);
    err = bpf_prog_test_run_opts(timer_prog_fd, &opts);
    if (err || opts.retval) {
        fprintf(stderr, "ERROR: failed to start BPF timer: %d (retval: %d)\n", err, opts.retval);
        goto cleanup;
    }
    
    printf("RAPL Stats Updater started with BPF timer (100ms interval)\n");
    printf("SCX can read stats from BPF map at: %s\n", pin_path);
    printf("Press Ctrl+C to stop.\n\n");
    
    // Block until signal - no CPU waste!
    while (keep_running) {
        pause();  /* Suspends process until signal arrives */
    }
    
    printf("\n\nStopping...\n");
    
    unlink("/sys/fs/bpf/rapl_stats");
    
cleanup:
    if (link)
        bpf_link__destroy(link);
    bpf_object__close(obj);
    return err != 0;
}
