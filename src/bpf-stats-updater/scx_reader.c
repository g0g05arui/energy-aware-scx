
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <bpf/bpf.h>
#include "../include/rapl_stats.h"
#include "../include/core_state.h"

static const char *state_to_str(enum core_status state)
{
    switch (state) {
    case CORE_COLD:
        return "cold";
    case CORE_WARM:
        return "warm";
    case CORE_HOT:
        return "hot";
    default:
        return "?";
    }
}

int main(int argc, char **argv) {
    const char *pin_path = "/sys/fs/bpf/rapl_stats";
    const char *temps_pin_path = "/sys/fs/bpf/rapl_temps";
    const char *temp_count_pin_path = "/sys/fs/bpf/rapl_temp_count";
    const char *state_pin_path = "/sys/fs/bpf/rapl_core_states";
    double refresh_interval = 1.0; /* seconds */
    useconds_t refresh_usecs;
    if (argc > 1) {
        char *end = NULL;
        refresh_interval = strtod(argv[1], &end);
        if (!end || *end != '\0' || refresh_interval <= 0.0)
            refresh_interval = 1.0;
    }
    refresh_usecs = (useconds_t)(refresh_interval * 1000000.0);

    int map_fd;
    int temps_fd;
    int temp_count_fd;
    int state_fd;
    struct rapl_stats stats;
    __u32 key = 0;
    int err;
    
    map_fd = bpf_obj_get(pin_path);
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: failed to open pinned map at %s: %s\n", 
                pin_path, strerror(errno));
        fprintf(stderr, "Make sure rapl_stats_updater is running!\n");
        return 1;
    }

    state_fd = bpf_obj_get(state_pin_path);
    if (state_fd < 0) {
        fprintf(stderr, "WARNING: failed to open core state map at %s: %s\n",
                state_pin_path, strerror(errno));
    }
    
    temps_fd = bpf_obj_get(temps_pin_path);
    if (temps_fd < 0) {
        fprintf(stderr, "ERROR: failed to open pinned map at %s: %s\n",
                temps_pin_path, strerror(errno));
        close(map_fd);
        return 1;
    }

    temp_count_fd = bpf_obj_get(temp_count_pin_path);
    if (temp_count_fd < 0) {
        fprintf(stderr, "WARNING: failed to open temp count map at %s: %s\n",
                temp_count_pin_path, strerror(errno));
    }
    

    while (true) {
        __u32 temp_count = 0;

        err = bpf_map_lookup_elem(map_fd, &key, &stats);
        if (err) {
            fprintf(stderr, "ERROR: failed to read from map: %s\n", strerror(errno));
            break;
        }

        temp_count = stats.core_count;
        if (temp_count_fd >= 0) {
            __u32 cnt_key = 0;
            __u32 count_val = stats.core_count;
            if (bpf_map_lookup_elem(temp_count_fd, &cnt_key, &count_val) == 0)
                temp_count = count_val;
        }

        printf("\033[H\033[J"); /* clear screen */
        printf("RAPL Stats from BPF Map (refresh %.2fs, Ctrl+C to exit):\n",
               refresh_interval);
        printf("========================================\n");
        printf("Timestamp:      %llu ns\n", stats.timestamp);
        printf("Delta Time:     %llu ns\n", stats.delta_time);
        printf("\n");
        printf("Package Power:  %llu W\n", stats.package_power);
        printf("Package Energy: %llu J\n", stats.package_energy);
        printf("Package Temp:   %u °C\n", stats.package_temp);
        printf("\n");
        printf("Core Power:     %llu W\n", stats.core_power);
        printf("Core Energy:    %llu J\n", stats.core_energy);
        printf("Core Count:     %u\n", stats.core_count);
        printf("Core Temps:\n");
        for (unsigned int i = 0; i < temp_count; i++) {
            __u32 idx = i;
            __u32 temp = 0;
            enum core_status state = CORE_COLD;
            const char *state_str = "?";
            bool has_temp = bpf_map_lookup_elem(temps_fd, &idx, &temp) == 0;
            if (has_temp && state_fd >= 0 &&
                bpf_map_lookup_elem(state_fd, &idx, &state) == 0)
                state_str = state_to_str(state);
            else if (!has_temp)
                state_str = "n/a";

            if (has_temp)
                printf("  Core %3u : %3u °C (%s)\n", i, temp, state_str);
            else
                printf("  Core %3u :   ? °C (%s)\n", i, state_str);
        }
        printf("\n");
        printf("TDP:            %llu W\n", stats.tdp);
        fflush(stdout);

        if (usleep(refresh_usecs) != 0 && errno == EINTR)
            break;
    }
    
    close(map_fd);
    close(temps_fd);
    if (temp_count_fd >= 0)
        close(temp_count_fd);
    if (state_fd >= 0)
        close(state_fd);
    return 0;
}
