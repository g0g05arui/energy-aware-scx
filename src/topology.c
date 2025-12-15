#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "topology.h"

#define CPUSET_EFFECTIVE "/sys/fs/cgroup/cpuset.cpus.effective"
#define CPU_ONLINE "/sys/devices/system/cpu/online"

struct cpu_list {
	__u32 cpus[TOPO_MAX_SIBLINGS];
	__u32 count;
};

static int read_file_trim(const char *path, char *buf, size_t buf_sz)
{
	FILE *fp = fopen(path, "r");

	if (!fp)
		return -errno;
	if (!fgets(buf, buf_sz, fp)) {
		fclose(fp);
		return -EIO;
	}
	fclose(fp);

	buf[strcspn(buf, "\r\n")] = '\0';
	return 0;
}

static int read_cpu_source(char *buf, size_t buf_sz)
{
	int err = read_file_trim(CPUSET_EFFECTIVE, buf, buf_sz);

	if (!err)
		return 0;
	if (err != -ENOENT)
		return err;

	return read_file_trim(CPU_ONLINE, buf, buf_sz);
}

static int parse_cpu_list_to_mask(const char *buf, bool *mask, size_t mask_sz,
				  __u32 *max_cpu_id, __u32 *count_out)
{
	const char *p = buf;
	bool found = false;
	__u32 highest = 0;
	__u32 count = 0;

	if (!buf || !mask || !max_cpu_id)
		return -EINVAL;

	while (*p) {
		while (isspace(*p) || *p == ',')
			p++;
		if (!*p)
			break;

		char *end;
		long start = strtol(p, &end, 10);
		long stop = start;

		if (end == p)
			return -EINVAL;
		if (*end == '-') {
			p = end + 1;
			stop = strtol(p, &end, 10);
			if (end == p)
				return -EINVAL;
		}

		if (start < 0 || stop < 0)
			return -EINVAL;
		if (stop < start) {
			long tmp = start;
			start = stop;
			stop = tmp;
		}

		for (long cpu = start; cpu <= stop; cpu++) {
			if ((size_t)cpu >= mask_sz)
				return -ERANGE;
			if (!mask[cpu]) {
				mask[cpu] = true;
				count++;
			}
			if ((__u32)cpu > highest)
				highest = cpu;
			found = true;
		}

		p = end;
		if (*p == ',')
			p++;
	}

	if (!found)
		return -ENOENT;

	if (count_out)
		*count_out = count;
	*max_cpu_id = highest;
	return 0;
}

static void sort_and_dedup(struct cpu_list *list)
{
	if (!list || list->count <= 1)
		return;

	for (__u32 i = 0; i < list->count; i++) {
		for (__u32 j = i + 1; j < list->count; j++) {
			if (list->cpus[j] < list->cpus[i]) {
				__u32 tmp = list->cpus[i];
				list->cpus[i] = list->cpus[j];
				list->cpus[j] = tmp;
			}
		}
	}

	__u32 w = 0;

	for (__u32 r = 0; r < list->count; r++) {
		if (w == 0 || list->cpus[r] != list->cpus[w - 1])
			list->cpus[w++] = list->cpus[r];
	}

	list->count = w;
}

static int parse_cpu_list_filtered(const char *buf, const bool *mask,
				   size_t mask_sz, struct cpu_list *out)
{
	const char *p = buf;

	if (!out || !buf)
		return -EINVAL;

	out->count = 0;

	while (*p) {
		while (isspace(*p) || *p == ',')
			p++;
		if (!*p)
			break;

		char *end;
		long start = strtol(p, &end, 10);
		long stop = start;

		if (end == p)
			return -EINVAL;
		if (*end == '-') {
			p = end + 1;
			stop = strtol(p, &end, 10);
			if (end == p)
				return -EINVAL;
		}

		if (start < 0 || stop < 0)
			return -EINVAL;
		if (stop < start) {
			long tmp = start;
			start = stop;
			stop = tmp;
		}

		for (long cpu = start; cpu <= stop; cpu++) {
			if ((size_t)cpu >= mask_sz)
				return -ERANGE;
			if (mask && !mask[cpu])
				continue;
			if (out->count >= TOPO_MAX_SIBLINGS)
				return -E2BIG;

			out->cpus[out->count++] = (__u32)cpu;
		}

		p = end;
		if (*p == ',')
			p++;
	}

	sort_and_dedup(out);
	return 0;
}

static int read_sibling_list(__u32 cpu, const bool *allowed_mask,
			     struct cpu_list *siblings, char *buf,
			     size_t buf_sz)
{
	char path[PATH_MAX];

	if (!siblings || !buf)
		return -EINVAL;

	if (snprintf(path, sizeof(path),
		     "/sys/devices/system/cpu/cpu%u/topology/thread_siblings_list",
		     cpu) >= (int)sizeof(path))
		return -ENAMETOOLONG;

	int err = read_file_trim(path, buf, buf_sz);

	if (err)
		return err;

	err = parse_cpu_list_filtered(buf, allowed_mask, TOPO_MAX_CPUS, siblings);
	if (err)
		return err;

	if (siblings->count == 0) {
		if (siblings->count >= TOPO_MAX_SIBLINGS)
			return -E2BIG;
		siblings->cpus[0] = cpu;
		siblings->count = 1;
	}

	return 0;
}

static bool siblings_match(const struct core_siblings *core,
			   const struct cpu_list *list)
{
	if (!core || !list)
		return false;
	if (core->sib_cnt != list->count)
		return false;

	for (__u32 i = 0; i < core->sib_cnt; i++) {
		if (core->sibs[i] != list->cpus[i])
			return false;
	}

	return true;
}

static int add_core(struct topo *t, const struct cpu_list *list, __u32 *gid_out)
{
	if (t->nr_cores >= TOPO_MAX_CORES)
		return -E2BIG;

	struct topo_core *core = &t->cores[t->nr_cores];

	core->gid = t->nr_cores;
	core->primary_cpu = list->count ? list->cpus[0] : TOPO_GID_INVALID;
	core->siblings.sib_cnt = list->count;
	for (__u32 i = 0; i < list->count; i++)
		core->siblings.sibs[i] = list->cpus[i];

	if (gid_out)
		*gid_out = core->gid;

	t->nr_cores++;
	return 0;
}

static int find_or_add_core(struct topo *t, const struct cpu_list *list,
			    __u32 *gid_out)
{
	for (__u32 i = 0; i < t->nr_cores; i++) {
		if (siblings_match(&t->cores[i].siblings, list)) {
			if (gid_out)
				*gid_out = t->cores[i].gid;
			return 0;
		}
	}

	return add_core(t, list, gid_out);
}

int topo_discover(struct topo *t)
{
	char buf[4096];
	bool allowed_mask[TOPO_MAX_CPUS] = {};
	__u32 highest_cpu = 0;
	__u32 allowed_cnt = 0;
	int err;

	if (!t)
		return -EINVAL;

	memset(t, 0, sizeof(*t));
	for (__u32 i = 0; i < TOPO_MAX_CPUS; i++)
		t->cpu_to_core_gid[i] = TOPO_GID_INVALID;

	err = read_cpu_source(buf, sizeof(buf));
	if (err) {
		fprintf(stderr, "ERROR: failed to read CPU set: %s\n",
			strerror(-err));
		return err;
	}

	err = parse_cpu_list_to_mask(buf, allowed_mask, TOPO_MAX_CPUS,
				     &highest_cpu, &allowed_cnt);
	if (err) {
		fprintf(stderr, "ERROR: failed to parse CPU list \"%s\": %s\n",
			buf, strerror(-err));
		return err;
	}

	t->nr_cpus = allowed_cnt;
	t->max_cpu_id = highest_cpu + 1;

	for (__u32 cpu = 0; cpu < TOPO_MAX_CPUS; cpu++) {
		struct cpu_list list = {};
		__u32 gid = TOPO_GID_INVALID;

		if (!allowed_mask[cpu])
			continue;

		err = read_sibling_list(cpu, allowed_mask, &list, buf,
					sizeof(buf));
		if (err) {
			fprintf(stderr,
				"ERROR: failed to read thread_siblings_list for cpu%u: %s\n",
				cpu, strerror(-err));
			return err;
		}

		err = find_or_add_core(t, &list, &gid);
		if (err) {
			fprintf(stderr,
				"ERROR: failed to register core for cpu%u: %s\n",
				cpu, strerror(-err));
			return err;
		}

		t->cpu_to_core_gid[cpu] = gid;
	}

	if (t->nr_cpus == 0 || t->nr_cores == 0) {
		fprintf(stderr, "ERROR: no CPUs discovered in topology\n");
		return -ENOENT;
	}

	return 0;
}

void topo_dump(const struct topo *t)
{
	if (!t) {
		fprintf(stderr, "ERROR: no topology to dump\n");
		return;
	}

	printf("%-8s %-20s %-12s\n", "core_gid", "siblings", "primary_cpu");

	for (__u32 gid = 0; gid < t->nr_cores; gid++) {
		const struct topo_core *core = &t->cores[gid];

		printf("%-8u ", core->gid);

		for (__u32 i = 0; i < core->siblings.sib_cnt; i++) {
			printf("%u", core->siblings.sibs[i]);
			if (i + 1 < core->siblings.sib_cnt)
				printf(",");
		}

		if (core->siblings.sib_cnt == 0)
			printf("-");

		printf(" %-12u\n", core->primary_cpu);
	}
}
