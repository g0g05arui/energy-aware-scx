/* Helpers for discovering and populating thermal zone mappings */
#ifndef THERMAL_ZONE_HELPERS_H
#define THERMAL_ZONE_HELPERS_H

#include <stdbool.h>
#include <stdio.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <bpf/bpf.h>

#include "../include/rapl_stats.h"

static inline int seed_temp_entry(int temps_map_fd, __u32 idx, int tz_id)
{
	char temp_path[PATH_MAX];
	FILE *fp;
	long val;

	snprintf(temp_path, sizeof(temp_path),
		 "/sys/class/thermal/thermal_zone%d/temp", tz_id);
	fp = fopen(temp_path, "r");
	if (!fp)
		return -errno;

	if (fscanf(fp, "%ld", &val) != 1) {
		fclose(fp);
		return -EIO;
	}
	fclose(fp);

	if (val < 0)
		val = 0;

	__u32 temp_u32 = (__u32)val;
	if (bpf_map_update_elem(temps_map_fd, &idx, &temp_u32, BPF_ANY)) {
		fprintf(stderr,
			"WARNING: failed to seed temp for thermal_zone%d idx=%u: %s\n",
			tz_id, idx, strerror(errno));
		return -errno;
	}

	return 0;
}

static inline int build_thermal_zone_mapping(int tz_map_fd, int temps_map_fd,
					     int *out_mapped)
{
	DIR *dir;
	struct dirent *de;
    int idx = 0;
    bool update_map = tz_map_fd >= 0;
    bool prime_temps = temps_map_fd >= 0;

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

        if (update_map) {
            __s32 key = tz_id;
            __u32 val = idx;

			if (bpf_map_update_elem(tz_map_fd, &key, &val, BPF_ANY)) {
				fprintf(stderr,
					"WARNING: failed to update thermal_zone_index_map for tz_id=%d idx=%d: %s\n",
					tz_id, idx, strerror(errno));
				continue;
        }

        if (prime_temps)
            seed_temp_entry(temps_map_fd, idx, tz_id);

			printf("Mapped thermal_zone%d -> core_temp_map[%d]\n",
			       tz_id, idx);
		}

		idx++;
	}

	closedir(dir);

	if (out_mapped)
		*out_mapped = idx;

	if (idx == 0) {
		fprintf(stderr,
			"WARNING: no thermal zones processed; temps may remain unused\n");
	}

    return 0;
}

#endif /* THERMAL_ZONE_HELPERS_H */
