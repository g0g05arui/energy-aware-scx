// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <asm/unistd.h>
#include <limits.h>
#include "../include/rapl_stats.h"

#define PERF_IDX_PACKAGE 0
#define PERF_IDX_CORE    1
#define PERF_EVENT_COUNT 2

static volatile int keep_running = 1;

static void sig_handler(int signo)
{
    keep_running = 0;
}

static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                           int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int read_file_u64(const char *path, unsigned long long *value)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -errno;

    if (fscanf(f, "%llu", value) != 1) {
        fclose(f);
        return -EIO;
    }

    fclose(f);
    return 0;
}

static int read_event_config(const char *path, unsigned long long *config)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -errno;

    char buf[64];
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return -EIO;
    }
    fclose(f);

    char *eq = strchr(buf, '=');
    const char *start = eq ? eq + 1 : buf;
    *config = strtoull(start, NULL, 0);
    return 0;
}

static int resolve_event_path(const char *event, char *path, size_t len)
{
    int written = snprintf(path, len,
                           "/sys/bus/event_source/devices/power/events/%s",
                           event);
    if (written < 0 || (size_t)written >= len)
        return -ENAMETOOLONG;
    return 0;
}

static int get_event_config(const char *const *candidates, unsigned long long *config)
{
    char path[PATH_MAX];
    for (const char *const *ev = candidates; *ev; ev++) {
        if (resolve_event_path(*ev, path, sizeof(path)) != 0)
            continue;
        if (read_event_config(path, config) == 0)
            return 0;
    }
    return -ENOENT;
}

static int open_rapl_event(int pmu_type, __u64 config)
{
    struct perf_event_attr attr = {
        .type = pmu_type,
        .size = sizeof(struct perf_event_attr),
        .config = config,
        .disabled = 0,
        .exclude_kernel = 0,
        .exclude_hv = 0,
        .read_format = PERF_FORMAT_TOTAL_TIME_ENABLED |
                        PERF_FORMAT_TOTAL_TIME_RUNNING,
    };

    int fd = perf_event_open(&attr, -1, 0, -1, 0);
    if (fd < 0)
        fprintf(stderr, "ERROR: perf_event_open for config %#llx failed: %s\n",
                (unsigned long long)config, strerror(errno));
    return fd;
}

static void close_perf_events(int *fds, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (fds[i] >= 0)
            close(fds[i]);
    }
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    int stats_map_fd;
    int temps_map_fd;
    int config_map_fd;
    int perf_map_fd;
    int err;
    int perf_fds[PERF_EVENT_COUNT] = { [0 ... (PERF_EVENT_COUNT - 1)] = -1 };

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (setrlimit(RLIMIT_MEMLOCK,
                  &(struct rlimit){ .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY })) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

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

    long cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu_cnt < 1)
        cpu_cnt = 1;
    if (cpu_cnt > MAX_CORE_TEMPS)
        cpu_cnt = MAX_CORE_TEMPS;

    config_map_fd = bpf_object__find_map_fd_by_name(obj, "rapl_config_map");
    if (config_map_fd >= 0) {
        __u32 cfg_key = 0;
        struct rapl_config cfg = {
            .core_count = cpu_cnt,
        };
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

    perf_map_fd = bpf_object__find_map_fd_by_name(obj, "perf_event_map");
    if (perf_map_fd < 0) {
        fprintf(stderr, "ERROR: failed to find perf_event_map\n");
        goto cleanup;
    }

    const char *stats_pin_path = "/sys/fs/bpf/rapl_stats";
    const char *temps_pin_path = "/sys/fs/bpf/rapl_temps";
    err = bpf_obj_pin(stats_map_fd, stats_pin_path);
    if (err && errno != EEXIST)
        fprintf(stderr, "WARNING: failed to pin map to %s: %s\n", stats_pin_path,
                strerror(errno));
    else
        printf("BPF map pinned to: %s\n", stats_pin_path);

    err = bpf_obj_pin(temps_map_fd, temps_pin_path);
    if (err && errno != EEXIST)
        fprintf(stderr, "WARNING: failed to pin map to %s: %s\n", temps_pin_path,
                strerror(errno));
    else
        printf("BPF map pinned to: %s\n", temps_pin_path);

    const char *const pkg_candidates[] = { "energy-pkg", "energy-package", NULL };
    const char *const core_candidates[] = { "energy-cores", "energy-core", "energy-pp0", NULL };
    unsigned long long pmu_type = 0;
    unsigned long long pkg_config = 0;
    unsigned long long core_config = 0;

    if (read_file_u64("/sys/bus/event_source/devices/power/type", &pmu_type) != 0) {
        fprintf(stderr, "WARNING: power PMU not available (is Intel RAPL supported?)\n");
        pmu_type = 0;
    }

    if (pmu_type) {
        if (get_event_config(pkg_candidates, &pkg_config) == 0)
            perf_fds[PERF_IDX_PACKAGE] = open_rapl_event(pmu_type, pkg_config);
        else
            fprintf(stderr, "WARNING: unable to resolve package energy event\n");

        if (get_event_config(core_candidates, &core_config) == 0)
            perf_fds[PERF_IDX_CORE] = open_rapl_event(pmu_type, core_config);
        else
            fprintf(stderr, "WARNING: unable to resolve core energy event\n");
    }

    for (__u32 i = 0; i < PERF_EVENT_COUNT; i++) {
        if (perf_fds[i] < 0)
            continue;
        if (bpf_map_update_elem(perf_map_fd, &i, &perf_fds[i], BPF_ANY))
            fprintf(stderr, "WARNING: failed to set perf event %u: %s\n", i,
                    strerror(errno));
    }

    prog = bpf_object__find_program_by_name(obj, "start_timer");
    if (!prog) {
        fprintf(stderr, "ERROR: failed to find start_timer program\n");
        goto cleanup;
    }

    int timer_prog_fd = bpf_program__fd(prog);
    if (timer_prog_fd < 0) {
        fprintf(stderr, "ERROR: failed to get program fd\n");
        goto cleanup;
    }

    LIBBPF_OPTS(bpf_test_run_opts, opts);
    err = bpf_prog_test_run_opts(timer_prog_fd, &opts);
    if (err || opts.retval) {
        fprintf(stderr, "ERROR: failed to start BPF timer: %d (retval: %d)\n",
                err, opts.retval);
        goto cleanup;
    }

    printf("RAPL Stats Updater streaming Intel RAPL data every 100ms (BPF timer)\n");
    printf("SCX can read stats from BPF map at: %s\n", stats_pin_path);
    printf("Per-core temps available at: %s (still randomized)\n", temps_pin_path);
    printf("Press Ctrl+C to stop.\n\n");

    while (keep_running)
        pause();

    printf("\nStopping...\n");

    unlink(stats_pin_path);
    unlink(temps_pin_path);

cleanup:
    close_perf_events(perf_fds, PERF_EVENT_COUNT);
    if (obj)
        bpf_object__close(obj);
    return err != 0;
}
