/* Helpers for discovering and populating thermal zone mappings */
#ifndef THERMAL_ZONE_HELPERS_H
#define THERMAL_ZONE_HELPERS_H

#include <stdbool.h>
#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <bpf/bpf.h>

#include "../include/rapl_stats.h"

static inline int build_thermal_zone_mapping(int tz_map_fd, int *out_mapped)
{
	DIR *dir;
	struct dirent *de;
	int idx = 0;
	bool update_map = tz_map_fd >= 0;

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
