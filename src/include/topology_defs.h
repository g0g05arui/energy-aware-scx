#ifndef TOPOLOGY_DEFS_H
#define TOPOLOGY_DEFS_H

#include "rapl_stats.h"

#ifdef __BPF__
#ifndef __u32
#define __u32 unsigned int
#endif
#else
#include <stdint.h>
#ifndef __u32
#define __u32 uint32_t
#endif
#endif

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
