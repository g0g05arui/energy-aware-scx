// SPDX-License-Identifier: GPL-2.0
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../include/rapl_stats.h"
#include "../include/core_state.h"
#include "../include/temp_thresholds.h"
#include "../include/topology.h"

static volatile sig_atomic_t keep_running = 1;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define TEMP_UPDATE_INTERVAL_MS 500

static void sig_handler(int signo)
{
	(void)signo;
	keep_running = 0;
}

static void trim_newline(char *buf)
{
	size_t len = strlen(buf);

	while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
		buf[--len] = '\0';
	}
}

static bool parse_core_label(const char *label, __u32 *core_idx)
{
	unsigned int idx;

	if (sscanf(label, "Core %u", &idx) == 1 ||
	    sscanf(label, "Core%u", &idx) == 1) {
		*core_idx = idx;
		return true;
	}

	return false;
}

struct core_sensor {
	__u32 cpu_id;
	char input_path[PATH_MAX];
};

static int load_hwmon_name(const char *hwmon_dir, char *buf, size_t buflen)
{
	char name_path[PATH_MAX];
	FILE *fp;

	if (snprintf(name_path, sizeof(name_path), "%s/name", hwmon_dir) >=
	    (int)sizeof(name_path))
		return -ENAMETOOLONG;

	fp = fopen(name_path, "r");
	if (!fp)
		return -errno;
	if (!fgets(buf, buflen, fp)) {
		fclose(fp);
		return -EIO;
	}
	fclose(fp);
	trim_newline(buf);
	return 0;
}

static int discover_core_sensors(const struct topo *topo,
				 struct core_sensor *sensors, size_t max_sensors)
{
	DIR *root;
	struct dirent *hwde;
	size_t count = 0;
	const char *hwmon_root = "/sys/class/hwmon";
	bool seen[MAX_CORE_TEMPS] = {};
	size_t next_core_gid = 0;

	if (!topo)
		return -EINVAL;

	root = opendir(hwmon_root);
	if (!root) {
		fprintf(stderr, "ERROR: failed to open %s: %s\n", hwmon_root,
			strerror(errno));
		return -errno;
	}

	while ((hwde = readdir(root)) != NULL) {
		char hwmon_dir[PATH_MAX];
		DIR *sensor_dir;
		struct dirent *entry;

		if (strncmp(hwde->d_name, "hwmon", 5) != 0)
			continue;

		if (snprintf(hwmon_dir, sizeof(hwmon_dir), "%s/%s", hwmon_root,
			     hwde->d_name) >= (int)sizeof(hwmon_dir)) {
			fprintf(stderr,
				"WARNING: hwmon path too long, skipping %s\n",
				hwde->d_name);
			continue;
		}
		sensor_dir = opendir(hwmon_dir);
		if (!sensor_dir)
			continue;

		char hwmon_name[64] = {};
		bool is_coretemp = false;
		size_t pkg_base_gid = 0;
		size_t pkg_max_gid = 0;
		bool pkg_has_core = false;

		if (!load_hwmon_name(hwmon_dir, hwmon_name, sizeof(hwmon_name)) &&
		    strcmp(hwmon_name, "coretemp") == 0) {
			is_coretemp = true;
			pkg_base_gid = next_core_gid;
			pkg_max_gid = pkg_base_gid;
		}

		while ((entry = readdir(sensor_dir)) != NULL) {
			int temp_id;
			char label_path[PATH_MAX];
			char label[128];
			FILE *fp;
			__u32 core_idx;

			if (sscanf(entry->d_name, "temp%d_label", &temp_id) != 1)
				continue;

			if (snprintf(label_path, sizeof(label_path),
				     "%s/temp%d_label", hwmon_dir, temp_id) >=
			    (int)sizeof(label_path)) {
				fprintf(stderr,
					"WARNING: temp label path too long (%s temp%d)\n",
					hwde->d_name, temp_id);
				continue;
			}
			fp = fopen(label_path, "r");
			if (!fp)
				continue;
			if (!fgets(label, sizeof(label), fp)) {
				fclose(fp);
				continue;
			}
			fclose(fp);
			trim_newline(label);

			if (!parse_core_label(label, &core_idx))
				continue;

			__u32 target_cpu = core_idx;
			__u32 target_gid = TOPO_GID_INVALID;

			if (is_coretemp) {
				target_gid = pkg_base_gid + core_idx;
				if (target_gid >= topo->nr_cores ||
				    target_gid >= MAX_CORE_TEMPS)
					continue;

				const struct topo_core *core =
					topo_core_by_gid(topo, target_gid);
				if (!core)
					continue;

				target_cpu = core->primary_cpu;
				pkg_has_core = true;
				if (target_gid + 1 > pkg_max_gid)
					pkg_max_gid = target_gid + 1;
			} else {
				if (core_idx >= TOPO_MAX_CPUS)
					continue;
				if (!topo_cpu_allowed(topo, target_cpu))
					continue;
				target_gid = topo_core_gid_for_cpu(topo, target_cpu);
				if (target_gid == TOPO_GID_INVALID ||
				    target_gid >= MAX_CORE_TEMPS)
					continue;
			}

			if (seen[target_gid])
				continue;
			if (count >= max_sensors) {
				fprintf(stderr,
					"WARNING: too many core sensors, ignoring core gid %u\n",
					target_gid);
				continue;
			}

			sensors[count].cpu_id = target_cpu;
			if (snprintf(sensors[count].input_path,
				     sizeof(sensors[count].input_path),
				     "%s/temp%d_input", hwmon_dir, temp_id) >=
			    (int)sizeof(sensors[count].input_path)) {
				fprintf(stderr,
					"WARNING: temp input path too long (%s temp%d)\n",
					hwde->d_name, temp_id);
				continue;
			}
			printf("Mapped %s temp%d (%s) -> cpu %u (core gid %u)\n",
			       hwde->d_name, temp_id, label, sensors[count].cpu_id,
			       target_gid);
			seen[target_gid] = true;
			count++;
		}

		closedir(sensor_dir);

		if (is_coretemp && pkg_has_core && pkg_max_gid > next_core_gid)
			next_core_gid = pkg_max_gid;
	}

	closedir(root);

	if (count == 0) {
		fprintf(stderr,
			"ERROR: no hwmon entries labeled as per-core temps were found.\n");
		return -ENOENT;
	}

	return (int)count;
}

static void sleep_interval(void)
{
	usleep(TEMP_UPDATE_INTERVAL_MS * 1000);
}

static enum core_status determine_core_state(int state_map_fd, __u32 key, __u32 temp)
{
	enum core_status prev = CORE_COLD;

	if (state_map_fd >= 0) {
		enum core_status stored;

		if (bpf_map_lookup_elem(state_map_fd, &key, &stored) == 0)
			prev = stored;
	}

	if (temp < TEMP_THRESHOLD_WARM)
		return CORE_COLD;
	if (temp >= TEMP_THRESHOLD_HOT)
		return CORE_HOT;
	if (prev == CORE_HOT)
		return CORE_HOT;
	return CORE_WARM;
}

static void update_core_temp_map(int temps_map_fd, int state_map_fd,
				 const struct topo *topo,
				 const struct core_sensor *sensors, int sensor_count)
{
	__u32 temps[MAX_CORE_TEMPS] = {};
	bool has_value[MAX_CORE_TEMPS] = {};
	__u32 slot_count;

	if (!topo)
		return;

	slot_count = topo->nr_cores;
	if (slot_count > MAX_CORE_TEMPS)
		slot_count = MAX_CORE_TEMPS;

	for (int i = 0; i < sensor_count; i++) {
		const struct core_sensor *sensor = &sensors[i];
		FILE *fp = fopen(sensor->input_path, "r");
		long val;
		__u32 gid = topo_core_gid_for_cpu(topo, sensor->cpu_id);

		if (gid == TOPO_GID_INVALID || gid >= slot_count)
			continue;

		if (!fp) {
			fprintf(stderr,
				"WARNING: failed to open %s: %s (core %u)\n",
				sensor->input_path, strerror(errno),
				sensor->cpu_id);
			continue;
		}
		if (fscanf(fp, "%ld", &val) != 1) {
			fprintf(stderr,
				"WARNING: failed to read %s: %s (core %u)\n",
				sensor->input_path, strerror(errno),
				sensor->cpu_id);
			fclose(fp);
			continue;
		}
		fclose(fp);

		if (val <= 0)
			continue;

		/* hwmon temps are in millidegrees C, convert to whole degrees */
		val /= 1000;
		if (val > UINT_MAX)
			val = UINT_MAX;

		if (!has_value[gid] || (__u32)val > temps[gid])
			temps[gid] = (__u32)val;
		has_value[gid] = true;
	}

	for (__u32 idx = 0; idx < slot_count; idx++) {
		__u32 temp = has_value[idx] ? temps[idx] : 0;
		enum core_status state;

		state = determine_core_state(state_map_fd, idx, temp);

		if (bpf_map_update_elem(temps_map_fd, &idx, &temp, BPF_ANY))
			fprintf(stderr,
				"WARNING: failed to update core_temp_map[%u]: %s\n",
				idx, strerror(errno));
		if (state_map_fd >= 0 &&
		    bpf_map_update_elem(state_map_fd, &idx, &state, BPF_ANY))
			fprintf(stderr,
				"WARNING: failed to update core_state_map[%u]: %s\n",
				idx, strerror(errno));
	}
}

int main(int argc, char **argv)
{
	const char *bpf_obj_path = argc > 1 ? argv[1] : "hwmon_stats_interval.bpf.o";
	const char *temps_pin_path = "/sys/fs/bpf/rapl_temps";
	const char *temp_count_pin_path = "/sys/fs/bpf/rapl_temp_count";
	const char *state_pin_path = "/sys/fs/bpf/rapl_core_states";
	struct bpf_object *obj = NULL;
	int temps_map_fd;
	int temp_count_map_fd;
	int state_map_fd;
	int err = 0;
	int mapped_cores = 0;
	__u32 slot_count = 0;
	bool temps_pinned = false;
	bool temp_count_pinned = false;
	bool state_pinned = false;
	struct core_sensor sensors[MAX_CORE_TEMPS] = {};
	struct topo topo = {};

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	obj = bpf_object__open_file(bpf_obj_path, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: failed to open BPF object at %s: %s\n",
			bpf_obj_path, strerror(errno));
		return 1;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "ERROR: failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	temps_map_fd = bpf_object__find_map_fd_by_name(obj, "core_temp_map");
	if (temps_map_fd < 0) {
		fprintf(stderr, "ERROR: core_temp_map not found in object\n");
		err = -ENOENT;
		goto cleanup;
	}

	err = bpf_obj_pin(temps_map_fd, temps_pin_path);
	if (err && errno != EEXIST) {
		fprintf(stderr, "ERROR: failed to pin core_temp_map at %s: %s\n",
			temps_pin_path, strerror(errno));
		goto cleanup;
	}
	temps_pinned = true;

	temp_count_map_fd = bpf_object__find_map_fd_by_name(obj, "core_temp_count_map");
	if (temp_count_map_fd < 0) {
		fprintf(stderr, "ERROR: core_temp_count_map not found in object\n");
		err = -ENOENT;
		goto cleanup;
	}

	err = bpf_obj_pin(temp_count_map_fd, temp_count_pin_path);
	if (err && errno != EEXIST) {
		fprintf(stderr, "ERROR: failed to pin core_temp_count_map at %s: %s\n",
			temp_count_pin_path, strerror(errno));
		goto cleanup;
	}
	temp_count_pinned = true;

	state_map_fd = bpf_object__find_map_fd_by_name(obj, "core_state_map");
	if (state_map_fd < 0) {
		fprintf(stderr, "ERROR: core_state_map not found in object\n");
		err = -ENOENT;
		goto cleanup;
	}

	err = bpf_obj_pin(state_map_fd, state_pin_path);
	if (err && errno != EEXIST) {
		fprintf(stderr, "ERROR: failed to pin core_state_map at %s: %s\n",
			state_pin_path, strerror(errno));
		goto cleanup;
	}
	state_pinned = true;

	err = topo_discover(&topo);
	if (err) {
		fprintf(stderr, "ERROR: failed to discover topology: %s\n",
			strerror(-err));
		goto cleanup;
	}

	if (topo.nr_cores == 0) {
		fprintf(stderr, "ERROR: topology discovery returned zero cores\n");
		err = -ENOENT;
		goto cleanup;
	}
	if (topo.nr_cores > MAX_CORE_TEMPS) {
		fprintf(stderr,
			"ERROR: topology has %u cores but MAX_CORE_TEMPS=%u; rebuild with larger MAX_CORE_TEMPS\n",
			topo.nr_cores, MAX_CORE_TEMPS);
		err = -E2BIG;
		goto cleanup;
	}

	slot_count = topo.nr_cores;

	printf("Topology: %u CPUs across %u cores (max CPU id %u)\n",
	       topo.nr_cpus, topo.nr_cores,
	       topo.max_cpu_id ? topo.max_cpu_id - 1 : 0);

	mapped_cores = discover_core_sensors(&topo, sensors, ARRAY_SIZE(sensors));
	if (mapped_cores < 0) {
		err = mapped_cores;
		goto cleanup;
	}

	{
		__u32 key = 0;
		__u32 count = slot_count;
		if (count > MAX_CORE_TEMPS)
			count = MAX_CORE_TEMPS;
		if (bpf_map_update_elem(temp_count_map_fd, &key, &count, BPF_ANY))
			fprintf(stderr,
				"WARNING: failed to update core_temp_count_map: %s\n",
				strerror(errno));
	}

	printf("HWMON stats updater running (%d sensors, %u physical cores)\n",
	       mapped_cores, slot_count);
	printf("Per-core temps pinned at: %s\n", temps_pin_path);
	printf("Per-core states pinned at: %s\n", state_pin_path);
	printf("Core temp count pinned at: %s\n", temp_count_pin_path);
	printf("Polling hwmon sensors every %d ms. Press Ctrl+C to stop.\n\n",
	       TEMP_UPDATE_INTERVAL_MS);

	while (keep_running) {
		update_core_temp_map(temps_map_fd, state_map_fd, &topo, sensors,
				     mapped_cores);
		sleep_interval();
	}

	printf("\nStopping HWMON stats updater...\n");

cleanup:
	if (obj)
		bpf_object__close(obj);
	if (temps_pinned)
		unlink(temps_pin_path);
	if (temp_count_pinned)
		unlink(temp_count_pin_path);
	if (state_pinned)
		unlink(state_pin_path);

	return err != 0;
}
