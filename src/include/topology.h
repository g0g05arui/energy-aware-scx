#ifndef TOPOLOGY_H
#define TOPOLOGY_H

#include <stdbool.h>
#include <stddef.h>

#include "topology_defs.h"

struct topo_core {
	__u32 gid;
	__u32 primary_cpu;
	struct core_siblings siblings;
};

struct topo {
	__u32 nr_cpus;
	__u32 nr_cores;
	__u32 max_cpu_id;
	__u32 cpu_to_core_gid[TOPO_MAX_CPUS];
	struct topo_core cores[TOPO_MAX_CORES];
};

int topo_discover(struct topo *t);
void topo_dump(const struct topo *t);

static inline __u32 topo_core_gid_for_cpu(const struct topo *t, __u32 cpu)
{
	if (!t)
		return TOPO_GID_INVALID;
	if (cpu >= TOPO_MAX_CPUS)
		return TOPO_GID_INVALID;
	return t->cpu_to_core_gid[cpu];
}

static inline bool topo_cpu_allowed(const struct topo *t, __u32 cpu)
{
	return topo_core_gid_for_cpu(t, cpu) != TOPO_GID_INVALID;
}

static inline const struct topo_core *
topo_core_by_gid(const struct topo *t, __u32 gid)
{
	if (!t)
		return NULL;
	if (gid >= t->nr_cores)
		return NULL;
	return &t->cores[gid];
}

#endif /* TOPOLOGY_H */
