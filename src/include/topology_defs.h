#ifndef TOPOLOGY_DEFS_H
#define TOPOLOGY_DEFS_H

#include <linux/types.h>

#include "rapl_stats.h"

#ifndef TOPO_MAX_CPUS
#define TOPO_MAX_CPUS 256
#endif

#define TOPO_MAX_SIBLINGS 8
#define TOPO_MAX_CORES MAX_CORE_TEMPS
#define TOPO_GID_INVALID ((__u32)-1)

struct core_siblings {
	__u32 sib_cnt;
	__u32 sibs[TOPO_MAX_SIBLINGS];
};

#endif /* TOPOLOGY_DEFS_H */
