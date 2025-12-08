/* Loader for the minimal Round-Robin sched_ext scheduler.
 * Attaches the BPF struct_ops program and wires it up with the pinned
 * rapl_stats map so stats can be printed directly from the kernel.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile sig_atomic_t keep_running = 1;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

static void sig_handler(int signo)
{
	(void)signo;
	keep_running = 0;
}

int main(int argc, char **argv)
{
	const char *bpf_obj_path = argc > 1 ? argv[1] : "scx_energy_aware.bpf.o";
	const char *stats_pin_path = "/sys/fs/bpf/rapl_stats";
	const char *temps_pin_path = "/sys/fs/bpf/rapl_temps";
	const char *temp_count_pin_path = "/sys/fs/bpf/rapl_temp_count";
	struct bpf_object *obj = NULL;
	struct bpf_link *link = NULL;
	struct bpf_map *ops_map;
	struct bpf_map *stats_map;
	struct bpf_map *temps_map;
	struct bpf_map *temp_count_map;
	int stats_fd = -1;
	int temps_fd = -1;
	int temp_count_fd = -1;
	int err = 0;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	libbpf_set_print(libbpf_print_fn);

	stats_fd = bpf_obj_get(stats_pin_path);
	if (stats_fd < 0) {
		fprintf(stderr, "ERROR: failed to open pinned map at %s: %s\n",
			stats_pin_path, strerror(errno));
		fprintf(stderr, "Make sure rapl_stats_updater is running.\n");
		err = -errno;
		goto cleanup;
	}

	temps_fd = bpf_obj_get(temps_pin_path);
	if (temps_fd < 0) {
		fprintf(stderr, "ERROR: failed to open pinned map at %s: %s\n",
			temps_pin_path, strerror(errno));
		fprintf(stderr, "Make sure rapl_stats_updater is running.\n");
		err = -errno;
		goto cleanup;
	}

	temp_count_fd = bpf_obj_get(temp_count_pin_path);
	if (temp_count_fd < 0) {
		fprintf(stderr, "ERROR: failed to open pinned map at %s: %s\n",
			temp_count_pin_path, strerror(errno));
		fprintf(stderr, "Make sure hwmon_stats_updater is running.\n");
		err = -errno;
		goto cleanup;
	}

	obj = bpf_object__open_file(bpf_obj_path, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: failed to open BPF object at %s: %s\n",
			bpf_obj_path, strerror(errno));
		err = -errno;
		obj = NULL;
		goto cleanup;
	}

	stats_map = bpf_object__find_map_by_name(obj, "rapl_stats_map");
	if (!stats_map) {
		fprintf(stderr, "ERROR: rapl_stats_map not found in object\n");
		err = -ENOENT;
		goto cleanup;
	}

	temps_map = bpf_object__find_map_by_name(obj, "core_temp_map");
	if (!temps_map) {
		fprintf(stderr, "ERROR: core_temp_map not found in object\n");
		err = -ENOENT;
		goto cleanup;
	}

	temp_count_map = bpf_object__find_map_by_name(obj, "core_temp_count_map");
	if (!temp_count_map) {
		fprintf(stderr, "ERROR: core_temp_count_map not found in object\n");
		err = -ENOENT;
		goto cleanup;
	}

	if (bpf_map__reuse_fd(stats_map, stats_fd)) {
		fprintf(stderr, "ERROR: failed to link rapl_stats map: %s\n",
			strerror(errno));
		err = -errno;
		goto cleanup;
	}

	if (bpf_map__reuse_fd(temps_map, temps_fd)) {
		fprintf(stderr, "ERROR: failed to link core_temp_map: %s\n",
			strerror(errno));
		err = -errno;
		goto cleanup;
	}

	if (bpf_map__reuse_fd(temp_count_map, temp_count_fd)) {
		fprintf(stderr, "ERROR: failed to link core_temp_count_map: %s\n",
			strerror(errno));
		err = -errno;
		goto cleanup;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "ERROR: failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	ops_map = bpf_object__find_map_by_name(obj, "energy_aware_ops");
	if (!ops_map) {
		fprintf(stderr, "ERROR: energy_aware_ops map not found\n");
		err = -ENOENT;
		goto cleanup;
	}

	link = bpf_map__attach_struct_ops(ops_map);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: failed to attach struct_ops: %s\n",
			strerror(errno));
		link = NULL;
		err = -errno;
		goto cleanup;
	}

	printf("Round-Robin scheduler loaded and attached successfully.\n");
	printf("Pinned RAPL stats map: %s\n", stats_pin_path);
	printf("Pinned RAPL temps map: %s\n", temps_pin_path);
	printf("Pinned RAPL temp count map: %s\n", temp_count_pin_path);
	printf("Stats are emitted from the kernel via bpf_printk.\n");
	printf("Run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' to monitor them.\n");
	printf("Press Ctrl+C to stop.\n\n");

	while (keep_running)
		pause();

	printf("\nStopping scheduler...\n");

cleanup:
	if (temp_count_fd >= 0)
		close(temp_count_fd);
	if (temps_fd >= 0)
		close(temps_fd);
	if (stats_fd >= 0)
		close(stats_fd);
	if (link)
		bpf_link__destroy(link);
	if (obj)
		bpf_object__close(obj);

	printf("Scheduler unloaded.\n");
	return err != 0;
}
