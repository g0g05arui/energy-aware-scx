
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/bpf.h>
#include "../include/rapl_stats.h"

int main(int argc, char **argv) {
    const char *pin_path = "/sys/fs/bpf/rapl_stats";
    int map_fd;
    struct rapl_stats stats;
    __u32 key = 0;
    int err;
    
    // Open the pinned BPF map
    map_fd = bpf_obj_get(pin_path);
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: failed to open pinned map at %s: %s\n", 
                pin_path, strerror(errno));
        fprintf(stderr, "Make sure rapl_stats_updater is running!\n");
        return 1;
    }
    
    // Read the stats from the map
    err = bpf_map_lookup_elem(map_fd, &key, &stats);
    if (err) {
        fprintf(stderr, "ERROR: failed to read from map: %s\n", strerror(errno));
        close(map_fd);
        return 1;
    }
    
    // Print the stats
    printf("RAPL Stats from BPF Map:\n");
    printf("========================\n");
    printf("Timestamp:      %llu ns\n", stats.timestamp);
    printf("Delta Time:     %llu ns\n", stats.delta_time);
    printf("\n");
    printf("Package Power:  %llu W\n", stats.package_power);
    printf("Package Energy: %llu J\n", stats.package_energy);
    printf("Package Temp:   %u °C\n", stats.package_temp);
    printf("\n");
    printf("Core Power:     %llu W\n", stats.core_power);
    printf("Core Energy:    %llu J\n", stats.core_energy);
    printf("Core Temp:      %u °C\n", stats.core_temp);
    printf("\n");
    printf("TDP:            %llu W\n", stats.tdp);
    
    close(map_fd);
    return 0;
}
