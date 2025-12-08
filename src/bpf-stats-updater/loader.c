// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../include/rapl_stats.h"

#define UPDATE_INTERVAL_MS 100
#define MAX_RAPL_DOMAINS   32

static volatile sig_atomic_t keep_running = 1;

struct rapl_domain {
	char energy_path[PATH_MAX];
	char range_path[PATH_MAX];
	unsigned long long last_energy;
	unsigned long long max_energy;
	bool has_last;
	bool has_max;
};

struct rapl_sources {
	struct rapl_domain packages[MAX_RAPL_DOMAINS];
	size_t package_cnt;

	struct rapl_domain cores[MAX_RAPL_DOMAINS];
	size_t core_cnt;

	unsigned long long tdp_uw;
};

static void sig_handler(int signo)
{
	(void)signo;
	keep_running = 0;
}

static unsigned long long monotonic_time_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;

	return (unsigned long long)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static void sleep_interval(void)
{
	struct timespec req = {
		.tv_sec = UPDATE_INTERVAL_MS / 1000,
		.tv_nsec = (UPDATE_INTERVAL_MS % 1000) * 1000000ull,
	};

	nanosleep(&req, NULL);
}

static int read_u64_file(const char *path, unsigned long long *val)
{
	FILE *fp = fopen(path, "r");

	if (!fp)
		return -errno;
	if (fscanf(fp, "%llu", val) != 1) {
		fclose(fp);
		return -EIO;
	}
	fclose(fp);
	return 0;
}

static int read_string_file(const char *path, char *buf, size_t buflen)
{
	FILE *fp = fopen(path, "r");

	if (!fp)
		return -errno;
	if (!fgets(buf, buflen, fp)) {
		fclose(fp);
		return -EIO;
	}
	fclose(fp);
	buf[strcspn(buf, "\r\n")] = '\0';
	return 0;
}

static void init_rapl_domain(struct rapl_domain *dom, const char *dir_path)
{
	snprintf(dom->energy_path, sizeof(dom->energy_path), "%s/energy_uj", dir_path);
	snprintf(dom->range_path, sizeof(dom->range_path), "%s/max_energy_range_uj",
		 dir_path);
	dom->has_last = false;
	dom->has_max = (read_u64_file(dom->range_path, &dom->max_energy) == 0);
	if (!dom->has_max)
		dom->max_energy = 0;
}

static unsigned long long read_domain_energy(struct rapl_domain *dom,
					     unsigned long long *delta_out)
{
	unsigned long long val = 0;
	unsigned long long delta = 0;

	if (read_u64_file(dom->energy_path, &val) != 0)
		return 0;

	if (dom->has_last) {
		if (val >= dom->last_energy) {
			delta = val - dom->last_energy;
		} else if (dom->has_max && dom->max_energy > dom->last_energy) {
			delta = (dom->max_energy - dom->last_energy) + val;
		}
	}

	dom->last_energy = val;
	dom->has_last = true;

	if (delta_out)
		*delta_out = delta;
	return val;
}

static unsigned long long read_pkg_tdp_uw(const char *pkg_path)
{
	const char *candidates[] = {
		"constraint_0_max_power_uw",
		"constraint_0_power_limit_uw",
		"constraint_1_power_limit_uw",
	};

	for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
		char path[PATH_MAX];
		unsigned long long val;

		if (snprintf(path, sizeof(path), "%s/%s", pkg_path, candidates[i]) >=
		    (int)sizeof(path))
			continue;
		if (read_u64_file(path, &val) == 0)
			return val;
	}
	return 0;
}

static bool is_rapl_dir(const char *name)
{
	return strncmp(name, "intel-rapl", 10) == 0;
}

static int discover_rapl_sources(struct rapl_sources *srcs)
{
	const char *root_path = "/sys/class/powercap";
	DIR *root = opendir(root_path);

	if (!root) {
		fprintf(stderr, "ERROR: failed to open %s: %s\n", root_path,
			strerror(errno));
		return -errno;
	}

	memset(srcs, 0, sizeof(*srcs));

	struct dirent *de;
	while ((de = readdir(root)) != NULL) {
		if (!is_rapl_dir(de->d_name))
			continue;

		char pkg_dir[PATH_MAX];
		char name_path[PATH_MAX];
		char name_buf[128];

		if (snprintf(pkg_dir, sizeof(pkg_dir), "%s/%s", root_path,
			     de->d_name) >= (int)sizeof(pkg_dir))
			continue;

		if (snprintf(name_path, sizeof(name_path), "%s/name", pkg_dir) >=
		    (int)sizeof(name_path))
			continue;

		if (read_string_file(name_path, name_buf, sizeof(name_buf)) != 0)
			continue;

		if (strncmp(name_buf, "package", 7) == 0) {
			if (srcs->package_cnt >= MAX_RAPL_DOMAINS) {
				fprintf(stderr,
					"WARNING: too many package domains, ignoring %s\n",
					pkg_dir);
				continue;
			}
			init_rapl_domain(&srcs->packages[srcs->package_cnt], pkg_dir);
			srcs->tdp_uw += read_pkg_tdp_uw(pkg_dir);
			srcs->package_cnt++;
		}

		DIR *pkg_contents = opendir(pkg_dir);
		if (!pkg_contents)
			continue;

		struct dirent *sub;
		while ((sub = readdir(pkg_contents)) != NULL) {
			if (!is_rapl_dir(sub->d_name))
				continue;

			char sub_dir[PATH_MAX];
			char sub_name_path[PATH_MAX];
			char sub_name[128];

			if (snprintf(sub_dir, sizeof(sub_dir), "%s/%s", pkg_dir,
				     sub->d_name) >= (int)sizeof(sub_dir))
				continue;
			if (snprintf(sub_name_path, sizeof(sub_name_path), "%s/name",
				     sub_dir) >= (int)sizeof(sub_name_path))
				continue;
			if (read_string_file(sub_name_path, sub_name,
					     sizeof(sub_name)) != 0)
				continue;
			if (strcmp(sub_name, "core") != 0)
				continue;
			if (srcs->core_cnt >= MAX_RAPL_DOMAINS) {
				fprintf(stderr,
					"WARNING: too many core domains, ignoring %s\n",
					sub_dir);
				continue;
			}
			init_rapl_domain(&srcs->cores[srcs->core_cnt], sub_dir);
			srcs->core_cnt++;
		}
		closedir(pkg_contents);
	}

	closedir(root);

	if (srcs->package_cnt == 0) {
		fprintf(stderr, "ERROR: no RAPL package domains detected under %s\n",
			root_path);
		return -ENOENT;
	}

	if (srcs->core_cnt == 0)
		fprintf(stderr,
			"WARNING: no RAPL core domains detected; core power stats will be zero.\n");

	return 0;
}

static unsigned long long aggregate_domains(struct rapl_domain *domains,
					    size_t count, unsigned long long *delta_out)
{
	unsigned long long total = 0;
	unsigned long long delta_sum = 0;

	for (size_t i = 0; i < count; i++) {
		unsigned long long delta = 0;
		unsigned long long val = read_domain_energy(&domains[i], &delta);

		total += val;
		delta_sum += delta;
	}

	if (delta_out)
		*delta_out = delta_sum;
	return total;
}

static unsigned int read_package_temp_from_map(int temps_fd, int temp_count_fd,
					       unsigned int fallback_count)
{
	if (temps_fd < 0)
		return 0;

	__u32 key = 0;
	__u32 total = fallback_count;

	if (temp_count_fd >= 0) {
		if (bpf_map_lookup_elem(temp_count_fd, &key, &total) != 0 ||
		    total == 0)
			total = fallback_count;
	}

	if (total == 0 || total > MAX_CORE_TEMPS)
		total = MAX_CORE_TEMPS;

	unsigned int max_temp = 0;

	for (__u32 i = 0; i < total; i++) {
		__u32 temp = 0;

		if (bpf_map_lookup_elem(temps_fd, &i, &temp) == 0) {
			if (temp > max_temp)
				max_temp = temp;
		}
	}

	return max_temp;
}

int main(int argc, char **argv)
{
	const char *bpf_obj_path = argc > 1 ? argv[1] : "repl_stats_interval.bpf.o";
	const char *stats_pin_path = "/sys/fs/bpf/rapl_stats";
	struct bpf_object *obj = NULL;
	int stats_map_fd = -1;
	int config_map_fd = -1;
	int temps_fd = -1;
	int temp_count_fd = -1;
	int err = 0;
	struct rapl_sources sources;
	unsigned int configured_core_count = 0;
	bool stats_map_pinned = false;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	obj = bpf_object__open_file(bpf_obj_path, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: failed to open BPF object at %s\n",
			bpf_obj_path);
		return 1;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "ERROR: failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	config_map_fd = bpf_object__find_map_fd_by_name(obj, "rapl_config_map");
	if (config_map_fd >= 0) {
		long cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN);
		struct rapl_config cfg = {};
		__u32 cfg_key = 0;

		if (cpu_cnt < 1)
			cpu_cnt = 1;
		if (cpu_cnt > MAX_CORE_TEMPS)
			cpu_cnt = MAX_CORE_TEMPS;

		cfg.core_count = cpu_cnt;
		if (bpf_map_update_elem(config_map_fd, &cfg_key, &cfg, BPF_ANY))
			fprintf(stderr, "WARNING: failed to set core_count config: %s\n",
				strerror(errno));
		configured_core_count = cfg.core_count;
	} else {
		fprintf(stderr,
			"WARNING: rapl_config_map not found; using default core count 0\n");
	}

	if (configured_core_count == 0) {
		long cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN);

		if (cpu_cnt < 1)
			cpu_cnt = 1;
		if (cpu_cnt > MAX_CORE_TEMPS)
			cpu_cnt = MAX_CORE_TEMPS;
		configured_core_count = cpu_cnt;
	}

	stats_map_fd = bpf_object__find_map_fd_by_name(obj, "rapl_stats_map");
	if (stats_map_fd < 0) {
		fprintf(stderr, "ERROR: failed to find rapl_stats_map\n");
		goto cleanup;
	}

	err = bpf_obj_pin(stats_map_fd, stats_pin_path);
	if (err && errno != EEXIST) {
		fprintf(stderr, "ERROR: failed to pin rapl_stats_map at %s: %s\n",
			stats_pin_path, strerror(errno));
		goto cleanup;
	}
	stats_map_pinned = true;

	if (discover_rapl_sources(&sources)) {
		err = 1;
		goto cleanup;
	}

	temps_fd = bpf_obj_get("/sys/fs/bpf/rapl_temps");
	if (temps_fd < 0)
		fprintf(stderr,
			"INFO: rapl_temps map not available; package temps will be 0.\n");

	temp_count_fd = bpf_obj_get("/sys/fs/bpf/rapl_temp_count");
	if (temp_count_fd < 0)
		fprintf(stderr,
			"INFO: rapl_temp_count map not available; using configured core_count for temp scanning.\n");

	printf("Using %zu package RAPL domains and %zu core domains\n",
	       sources.package_cnt, sources.core_cnt);
	printf("Stats map pinned at: %s\n", stats_pin_path);
	printf("Polling RAPL counters every %d ms. Press Ctrl+C to stop.\n\n",
	       UPDATE_INTERVAL_MS);

	unsigned long long last_sample_ns = 0;
	__u32 stats_key = 0;

	while (keep_running) {
		unsigned long long now_ns = monotonic_time_ns();
		unsigned long long pkg_delta = 0;
		unsigned long long core_delta = 0;
		struct rapl_stats stats = {};

		unsigned long long pkg_total_uj =
			aggregate_domains(sources.packages, sources.package_cnt,
					  &pkg_delta);
		unsigned long long core_total_uj =
			aggregate_domains(sources.cores, sources.core_cnt, &core_delta);

		stats.timestamp = now_ns;
		stats.delta_time = last_sample_ns ? now_ns - last_sample_ns : 0;
		last_sample_ns = now_ns;

		stats.package_energy = pkg_total_uj / 1000000ull;
		stats.core_energy = core_total_uj / 1000000ull;

		if (stats.delta_time > 0) {
			stats.package_power = (pkg_delta * 1000ull) / stats.delta_time;
			stats.core_power = (core_delta * 1000ull) / stats.delta_time;
		}

		stats.package_temp =
			read_package_temp_from_map(temps_fd, temp_count_fd,
						   configured_core_count);
		stats.core_count = configured_core_count;
		stats.tdp = sources.tdp_uw / 1000000ull;

		if (bpf_map_update_elem(stats_map_fd, &stats_key, &stats, BPF_ANY))
			fprintf(stderr, "WARNING: failed to update rapl_stats_map: %s\n",
				strerror(errno));

		sleep_interval();
	}

	printf("\nStopping RAPL stats updater...\n");

cleanup:
	if (stats_map_pinned)
		unlink(stats_pin_path);
	if (temp_count_fd >= 0)
		close(temp_count_fd);
	if (temps_fd >= 0)
		close(temps_fd);
	if (obj)
		bpf_object__close(obj);

	return err != 0;
}
