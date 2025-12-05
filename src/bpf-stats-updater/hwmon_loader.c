// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "thermal_zone_helpers.h"

static volatile sig_atomic_t keep_running = 1;

static void sig_handler(int signo)
{
	(void)signo;
	keep_running = 0;
}

int main(int argc, char **argv)
{
	const char *bpf_obj_path = argc > 1 ? argv[1] : "hwmon_stats_interval.bpf.o";
	const char *temps_pin_path = "/sys/fs/bpf/rapl_temps";
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct bpf_link *link = NULL;
	int temps_map_fd;
	int tz_map_fd;
	int err = 0;
	int mapped_zones = 0;
	bool temps_pinned = false;

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

	tz_map_fd = bpf_object__find_map_fd_by_name(obj, "thermal_zone_index_map");
	if (tz_map_fd < 0) {
		fprintf(stderr, "ERROR: thermal_zone_index_map not found\n");
		err = -ENOENT;
		goto cleanup;
	}

	printf("Building thermal zone -> core index mapping...\n");
	build_thermal_zone_mapping(tz_map_fd, temps_map_fd, &mapped_zones);

	prog = bpf_object__find_program_by_name(obj, "bpf_hwmon_stats_updater");
	if (!prog) {
		fprintf(stderr, "ERROR: failed to find bpf_hwmon_stats_updater program\n");
		err = -ENOENT;
		goto cleanup;
	}

	link = bpf_program__attach_tracepoint(prog, "thermal", "thermal_temperature");
	if ((err = libbpf_get_error(link))) {
		fprintf(stderr, "ERROR: failed to attach tracepoint: %d\n", err);
		link = NULL;
		goto cleanup;
	}

	printf("HWMON stats updater running (mapped_zones=%d)\n", mapped_zones);
	printf("Per-core temps pinned at: %s\n", temps_pin_path);
	printf("Press Ctrl+C to stop.\n\n");

	while (keep_running)
		pause();

	printf("\nStopping HWMON stats updater...\n");

cleanup:
	if (link)
		bpf_link__destroy(link);
	if (obj)
		bpf_object__close(obj);
	if (temps_pinned)
		unlink(temps_pin_path);

	return err != 0;
}
