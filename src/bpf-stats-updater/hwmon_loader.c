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
	__u32 core_idx;
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

static int discover_core_sensors(struct core_sensor *sensors, size_t max_sensors)
{
	DIR *root;
	struct dirent *hwde;
	size_t count = 0;
	bool seen[MAX_CORE_TEMPS] = {};
	size_t next_core_idx = 0;
	const char *hwmon_root = "/sys/class/hwmon";

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
		size_t base_idx = 0;
		size_t dir_max_core = 0;
		bool dir_has_core = false;

		if (!load_hwmon_name(hwmon_dir, hwmon_name, sizeof(hwmon_name)) &&
		    strcmp(hwmon_name, "coretemp") == 0) {
			is_coretemp = true;
			base_idx = next_core_idx;
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

			__u32 idx = core_idx;
			if (is_coretemp)
				idx = base_idx + core_idx;

			if (idx >= MAX_CORE_TEMPS)
				continue;
			if (seen[idx])
				continue;
			if (count >= max_sensors) {
				fprintf(stderr,
					"WARNING: too many core sensors, ignoring core %u\n",
					core_idx);
				continue;
			}

			sensors[count].core_idx = idx;
			if (snprintf(sensors[count].input_path,
				     sizeof(sensors[count].input_path),
				     "%s/temp%d_input", hwmon_dir, temp_id) >=
			    (int)sizeof(sensors[count].input_path)) {
				fprintf(stderr,
					"WARNING: temp input path too long (%s temp%d)\n",
					hwde->d_name, temp_id);
				continue;
			}
			seen[idx] = true;
			if (is_coretemp) {
				dir_has_core = true;
				if (core_idx > dir_max_core)
					dir_max_core = core_idx;
			}
			printf("Mapped %s temp%d (%s) -> core %u\n", hwde->d_name,
			       temp_id, label, idx);
			count++;
		}

		closedir(sensor_dir);

		if (is_coretemp && dir_has_core) {
			size_t pkg_cores = dir_max_core + 1;
			if (base_idx + pkg_cores > next_core_idx)
				next_core_idx = base_idx + pkg_cores;
		}
	}

	closedir(root);

	if (count == 0) {
		fprintf(stderr,
			"ERROR: no hwmon entries labeled as per-core temps were found.\n");
		return -ENOENT;
	}

	return count;
}

static void sleep_interval(void)
{
	usleep(TEMP_UPDATE_INTERVAL_MS * 1000);
}

static void update_core_temp_map(int temps_map_fd,
				 const struct core_sensor *sensors, int count)
{
	for (int i = 0; i < count; i++) {
		const struct core_sensor *sensor = &sensors[i];
		FILE *fp = fopen(sensor->input_path, "r");
		long val;

		if (!fp) {
			fprintf(stderr,
				"WARNING: failed to open %s: %s (core %u)\n",
				sensor->input_path, strerror(errno),
				sensor->core_idx);
			continue;
		}
		if (fscanf(fp, "%ld", &val) != 1) {
			fprintf(stderr,
				"WARNING: failed to read %s: %s (core %u)\n",
				sensor->input_path, strerror(errno),
				sensor->core_idx);
			fclose(fp);
			continue;
		}
		fclose(fp);

		if (val < 0)
			val = 0;

		/* hwmon temps are in millidegrees C, convert to whole degrees */
		val /= 1000;
		if (val > UINT_MAX)
			val = UINT_MAX;

		__u32 temp = (__u32)val;
		__u32 key = sensor->core_idx;

		if (bpf_map_update_elem(temps_map_fd, &key, &temp, BPF_ANY))
			fprintf(stderr,
				"WARNING: failed to update core_temp_map[%u]: %s\n",
				key, strerror(errno));
	}
}

int main(int argc, char **argv)
{
	const char *bpf_obj_path = argc > 1 ? argv[1] : "hwmon_stats_interval.bpf.o";
	const char *temps_pin_path = "/sys/fs/bpf/rapl_temps";
	const char *temp_count_pin_path = "/sys/fs/bpf/rapl_temp_count";
	struct bpf_object *obj = NULL;
	int temps_map_fd;
	int temp_count_map_fd;
	int err = 0;
	int mapped_cores = 0;
	bool temps_pinned = false;
	bool temp_count_pinned = false;
	struct core_sensor sensors[MAX_CORE_TEMPS] = {};

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

	mapped_cores = discover_core_sensors(sensors, ARRAY_SIZE(sensors));
	if (mapped_cores < 0) {
		err = mapped_cores;
		goto cleanup;
	}

	{
		__u32 key = 0;
		__u32 count = mapped_cores;
		if (count > MAX_CORE_TEMPS)
			count = MAX_CORE_TEMPS;
		if (bpf_map_update_elem(temp_count_map_fd, &key, &count, BPF_ANY))
			fprintf(stderr,
				"WARNING: failed to update core_temp_count_map: %s\n",
				strerror(errno));
	}

	printf("HWMON stats updater running (%d mapped cores)\n", mapped_cores);
	printf("Per-core temps pinned at: %s\n", temps_pin_path);
	printf("Core temp count pinned at: %s\n", temp_count_pin_path);
	printf("Polling hwmon sensors every %d ms. Press Ctrl+C to stop.\n\n",
	       TEMP_UPDATE_INTERVAL_MS);

	while (keep_running) {
		update_core_temp_map(temps_map_fd, sensors, mapped_cores);
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

	return err != 0;
}
