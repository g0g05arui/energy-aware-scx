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
#include <stdbool.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <scx/common.h>
#include "topology.h"

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

#define DSQ_FLAG_BUILTIN_FALLBACK (1ULL << 63)
#define DSQ_FLAG_LOCAL_ON_FALLBACK (1ULL << 62)
#define DSQ_LOCAL_FALLBACK (DSQ_FLAG_BUILTIN_FALLBACK | 0x12ULL)
#define DSQ_LOCAL_ON_BASE_FALLBACK \
	(DSQ_FLAG_BUILTIN_FALLBACK | DSQ_FLAG_LOCAL_ON_FALLBACK)
#define DSQ_LOCAL_CPU_MASK_FALLBACK (0xffffffffULL)
#define SCX_SLICE_DFL_FALLBACK (20ULL * 1000 * 1000)
#define DEFAULT_MAX_COLD_DSQ_DEPTH 4
#define DEFAULT_MAX_REUSE_DSQ_DEPTH 8
#define DEFAULT_ENABLE_PINNING 1
#define DEFAULT_ENABLE_LOGGING 1
#define DEFAULT_LOG_INTERVAL_NS (100ULL * 1000 * 1000)
#define DEFAULT_PINNING_LEASE_NS (2ULL * 1000 * 1000)
#define DEFAULT_PREFER_PRIMARY 1

struct scx_enum_spec {
	const char *var_name;
	const char *enum_type;
	const char *enum_name;
	__u64 fallback;
};

static int rewrite_rodata_u64(const struct btf *btf, void *rodata, size_t sz,
			      const char *var_name, __u64 value)
{
	const struct btf_var_secinfo *var_info;
	const struct btf_type *sec;
	int i, sec_id;

	sec_id = btf__find_by_name_kind(btf, ".rodata", BTF_KIND_DATASEC);
	if (sec_id < 0)
		return -ENOENT;

	sec = btf__type_by_id(btf, sec_id);
	var_info = btf_var_secinfos(sec);

	for (i = 0; i < BTF_INFO_VLEN(sec->info); i++) {
		const struct btf_type *var_type;
		const char *name;

		var_type = btf__type_by_id(btf, var_info[i].type);
		name = btf__name_by_offset(btf, var_type->name_off);
		if (!name)
			continue;
		if (strcmp(name, var_name) != 0)
			continue;
		if (var_info[i].offset + sizeof(__u64) > sz)
			return -E2BIG;
		*(__u64 *)((char *)rodata + var_info[i].offset) = value;
		return 0;
	}

	return -ENOENT;
}

static int populate_scx_rodata(struct bpf_object *obj)
{
	static const struct scx_enum_spec enum_specs[] = {
		{ "__SCX_DSQ_LOCAL", "scx_dsq_id_flags", "SCX_DSQ_LOCAL",
		  DSQ_LOCAL_FALLBACK },
		{ "__SCX_DSQ_LOCAL_ON", "scx_dsq_id_flags", "SCX_DSQ_LOCAL_ON",
		  DSQ_LOCAL_ON_BASE_FALLBACK },
		{ "__SCX_DSQ_LOCAL_CPU_MASK", "scx_dsq_id_flags",
		  "SCX_DSQ_LOCAL_CPU_MASK", DSQ_LOCAL_CPU_MASK_FALLBACK },
		{ "__SCX_SLICE_DFL", "scx_public_consts", "SCX_SLICE_DFL",
		  SCX_SLICE_DFL_FALLBACK },
	};
	const struct btf *btf = bpf_object__btf(obj);
	struct bpf_map *rodata_map;
	size_t sz;
	void *rodata;
	int err = 0;
	int i;

	if (!btf) {
		fprintf(stderr, "ERROR: BTF missing in BPF object\n");
		return -EINVAL;
	}

	rodata_map = bpf_object__find_map_by_name(obj, ".rodata");
	if (!rodata_map)
		return 0;

	rodata = bpf_map__initial_value(rodata_map, &sz);
	if (!rodata) {
		fprintf(stderr, "ERROR: failed to access .rodata contents\n");
		return -EINVAL;
	}

	for (i = 0; i < (int)(sizeof(enum_specs) / sizeof(enum_specs[0])); i++) {
		const struct scx_enum_spec *spec = &enum_specs[i];
		__u64 value;

		if (!__COMPAT_read_enum(spec->enum_type, spec->enum_name,
					&value)) {
			fprintf(stderr,
				"WARN: enum %s::%s not found, using fallback\n",
				spec->enum_type, spec->enum_name);
			value = spec->fallback;
		}

		err = rewrite_rodata_u64(btf, rodata, sz, spec->var_name,
					 value);
		if (err) {
			fprintf(stderr,
				"ERROR: failed to rewrite %s in .rodata (%d)\n",
				spec->var_name, err);
			return err;
		}
	}

	return 0;
}

struct sched_cfg_init {
	__u32 max_cold_dsq_depth;
	__u32 max_reuse_dsq_depth;
	__u32 enable_pinning;
	__u32 enable_logging;
	__u32 log_interval_ns;
	__u32 pinning_lease_ns;
	__u32 prefer_primary;
};

static int configure_sched_cfg(struct bpf_object *obj, bool prefer_primary)
{
	struct bpf_map *cfg_map;
	struct sched_cfg_init cfg = {
		.max_cold_dsq_depth = DEFAULT_MAX_COLD_DSQ_DEPTH,
		.max_reuse_dsq_depth = DEFAULT_MAX_REUSE_DSQ_DEPTH,
		.enable_pinning = DEFAULT_ENABLE_PINNING,
		.enable_logging = DEFAULT_ENABLE_LOGGING,
		.log_interval_ns = DEFAULT_LOG_INTERVAL_NS,
		.pinning_lease_ns = DEFAULT_PINNING_LEASE_NS,
		.prefer_primary = prefer_primary ? 1 : 0,
	};
	__u32 key = 0;
	int fd;

	cfg_map = bpf_object__find_map_by_name(obj, "sched_cfg_map");
	if (!cfg_map)
		return 0;

	fd = bpf_map__fd(cfg_map);
	if (fd < 0)
		return -ENOENT;

	if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY)) {
		fprintf(stderr, "ERROR: failed to configure sched_cfg_map: %s\n",
			strerror(errno));
		return -errno;
	}

	return 0;
}

static int populate_topology_maps(struct bpf_object *obj,
				  const struct topo *topo)
{
	struct bpf_map *cpu_map;
	struct bpf_map *primary_map;
	struct bpf_map *siblings_map;
	int cpu_fd, primary_fd, siblings_fd;

	if (!topo)
		return -EINVAL;

	cpu_map = bpf_object__find_map_by_name(obj, "cpu_to_core_gid_map");
	primary_map = bpf_object__find_map_by_name(obj, "core_primary_cpu_map");
	siblings_map = bpf_object__find_map_by_name(obj, "core_siblings_map");
	if (!cpu_map || !primary_map || !siblings_map) {
		fprintf(stderr,
			"ERROR: topology maps not found in scheduler object\n");
		return -ENOENT;
	}

	cpu_fd = bpf_map__fd(cpu_map);
	primary_fd = bpf_map__fd(primary_map);
	siblings_fd = bpf_map__fd(siblings_map);
	if (cpu_fd < 0 || primary_fd < 0 || siblings_fd < 0)
		return -errno;

	for (__u32 cpu = 0; cpu < TOPO_MAX_CPUS; cpu++) {
		__u32 gid = topo->cpu_to_core_gid[cpu];

		if (bpf_map_update_elem(cpu_fd, &cpu, &gid, BPF_ANY)) {
			fprintf(stderr,
				"ERROR: failed to update cpu_to_core_gid_map[%u]: %s\n",
				cpu, strerror(errno));
			return -errno;
		}
	}

	for (__u32 gid = 0; gid < MAX_CORE_TEMPS; gid++) {
		__u32 primary = TOPO_GID_INVALID;
		struct core_siblings sib = {};

		if (gid < topo->nr_cores) {
			const struct topo_core *core = topo_core_by_gid(topo, gid);

			if (core) {
				primary = core->primary_cpu;
				sib = core->siblings;
			}
		}

		if (bpf_map_update_elem(primary_fd, &gid, &primary, BPF_ANY)) {
			fprintf(stderr,
				"ERROR: failed to update core_primary_cpu_map[%u]: %s\n",
				gid, strerror(errno));
			return -errno;
		}

		if (bpf_map_update_elem(siblings_fd, &gid, &sib, BPF_ANY)) {
			fprintf(stderr,
				"ERROR: failed to update core_siblings_map[%u]: %s\n",
				gid, strerror(errno));
			return -errno;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	const char *bpf_obj_path = "scx_energy_aware.bpf.o";
	const char *stats_pin_path = "/sys/fs/bpf/rapl_stats";
	const char *temps_pin_path = "/sys/fs/bpf/rapl_temps";
	const char *temp_count_pin_path = "/sys/fs/bpf/rapl_temp_count";
	const char *state_pin_path = "/sys/fs/bpf/rapl_core_states";
	struct bpf_object *obj = NULL;
	struct bpf_link *link = NULL;
	struct bpf_map *ops_map;
	struct bpf_map *stats_map;
	struct bpf_map *temps_map;
	struct bpf_map *temp_count_map;
	struct bpf_map *state_map;
	int stats_fd = -1;
	int temps_fd = -1;
	int temp_count_fd = -1;
	int state_fd = -1;
	int err = 0;
	struct topo topo = {};
	bool dump_topology = false;
	bool prefer_primary_flag = DEFAULT_PREFER_PRIMARY;
	int argi = 1;

	while (argi < argc) {
		const char *arg = argv[argi];

		if (strcmp(arg, "--dump-topology") == 0) {
			dump_topology = true;
			argi++;
			continue;
		}
		if (strcmp(arg, "--bpf") == 0) {
			if (argi + 1 >= argc) {
				fprintf(stderr, "ERROR: --bpf requires a path\n");
				return 1;
			}
			bpf_obj_path = argv[++argi];
			argi++;
			continue;
		}
		if (strcmp(arg, "--prefer-primary") == 0) {
			prefer_primary_flag = true;
			argi++;
			continue;
		}
		if (strcmp(arg, "--no-prefer-primary") == 0) {
			prefer_primary_flag = false;
			argi++;
			continue;
		}
		if (strncmp(arg, "--prefer-primary=", 17) == 0) {
			const char *val = arg + 17;

			prefer_primary_flag = atoi(val) != 0;
			argi++;
			continue;
		}
		if (arg[0] == '-') {
			fprintf(stderr, "ERROR: unknown option %s\n", arg);
			return 1;
		}

		bpf_obj_path = arg;
		argi++;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	libbpf_set_print(libbpf_print_fn);

	err = topo_discover(&topo);
	if (err) {
		fprintf(stderr, "ERROR: failed to discover topology: %s\n",
			strerror(-err));
		return 1;
	}
	if (topo.nr_cores == 0) {
		fprintf(stderr, "ERROR: topology reported zero cores\n");
		return 1;
	}
	if (topo.nr_cores > MAX_CORE_TEMPS) {
		fprintf(stderr,
			"ERROR: topology has %u cores but MAX_CORE_TEMPS=%u; rebuild with higher MAX_CORE_TEMPS\n",
			topo.nr_cores, MAX_CORE_TEMPS);
		return 1;
	}
	if (topo.max_cpu_id > TOPO_MAX_CPUS) {
		fprintf(stderr,
			"ERROR: topology CPU id %u exceeds TOPO_MAX_CPUS=%u; rebuild with higher TOPO_MAX_CPUS\n",
			topo.max_cpu_id, TOPO_MAX_CPUS);
		return 1;
	}

	printf("Topology: %u CPUs across %u cores (max CPU id %u)\n",
	       topo.nr_cpus, topo.nr_cores,
	       topo.max_cpu_id ? topo.max_cpu_id - 1 : 0);

	if (dump_topology) {
		topo_dump(&topo);
		return 0;
	}

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

	state_fd = bpf_obj_get(state_pin_path);
	if (state_fd < 0) {
		fprintf(stderr, "ERROR: failed to open pinned map at %s: %s\n",
			state_pin_path, strerror(errno));
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

	state_map = bpf_object__find_map_by_name(obj, "core_state_map");
	if (!state_map) {
		fprintf(stderr, "ERROR: core_state_map not found in object\n");
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

	if (bpf_map__reuse_fd(state_map, state_fd)) {
		fprintf(stderr, "ERROR: failed to link core_state_map: %s\n",
			strerror(errno));
		err = -errno;
		goto cleanup;
	}

	err = populate_scx_rodata(obj);
	if (err)
		goto cleanup;

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "ERROR: failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = configure_sched_cfg(obj, prefer_primary_flag);
	if (err)
		goto cleanup;

	err = populate_topology_maps(obj, &topo);
	if (err)
		goto cleanup;

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
	printf("Pinned RAPL core state map: %s\n", state_pin_path);
	printf("Physical cores discovered: %u (prefer primary=%s)\n",
	       topo.nr_cores, prefer_primary_flag ? "yes" : "no");
	printf("Stats are emitted from the kernel via bpf_printk.\n");
	printf("Run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' to monitor them.\n");
	printf("Press Ctrl+C to stop.\n\n");

	while (keep_running)
		pause();

	printf("\nStopping scheduler...\n");

cleanup:
	if (state_fd >= 0)
		close(state_fd);
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
