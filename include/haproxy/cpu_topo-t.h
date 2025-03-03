#ifndef _HAPROXY_CPU_TOPO_T_H
#define _HAPROXY_CPU_TOPO_T_H

#include <haproxy/api-t.h>
#include <haproxy/cpuset-t.h>

/* CPU state flags used with CPU topology detection (ha_cpu_topo.st). We try
 * hard to rely on known info. For example we don't claim a CPU is bound or
 * online if we don't know, reason why instead we store offline or excluded.
 * Other flags like DONT_USE indicate a user's choice while IGNORED indicates
 * the result of an automated selection. Two marks are available for allocation
 * algorithms to temporarily compare/select/evict CPUs. These must be cleared
 * after use.
 */
#define HA_CPU_F_EXCLUDED     0x0001  // this CPU was excluded at boot
#define HA_CPU_F_OFFLINE      0x0002  // this CPU is known to be offline
#define HA_CPU_F_DONT_USE     0x0004  // this CPU must not be used
#define HA_CPU_F_IGNORED      0x0008  // this CPU will not be used
#define HA_CPU_F_EXCL_MASK    0x000F  // mask of bits that exclude a CPU
#define HA_CPU_F_MARK1        0x0010  // for temporary internal use only
#define HA_CPU_F_MARK2        0x0020  // for temporary internal use only
#define HA_CPU_F_MARK_MASK    0x0030  // mask to drop the two marks above

/* CPU topology descriptor. All the ID and IDX fields are initialized to -1
 * when not known. The identifiers there are mostly assigned on the fly using
 * increments and have no particular representation except the fact that CPUs
 * having the same ID there share the same designated resource. The flags are
 * preset to zero.
 */
struct ha_cpu_topo {
	ushort st;    // state flags (HA_CPU_F_*)
	short idx;    // CPU index as passed to the OS. Initially the entry index.
	short ca_id[5]; // cache ID for each level (L0 to L4)
	short ts_id;  // thread-set identifier (generally core number)
	short cl_gid; // cluster global identifier (group of more intimate cores)
	short cl_lid; // cluster local identifier (per {pkg,node})
	short no_id;  // NUMA node identifier
	short pk_id;  // package identifier
	short th_cnt; // number of siblings threads
	short th_id;  // thread ID among siblings of the same core
	short capa;   // estimated CPU relative capacity; more is better
};

/* Description of a CPU cluster. */
struct ha_cpu_cluster {
	uint idx;         /* used when sorting, normally the entry index */
	uint capa;        /* total capacity */
	uint nb_cores;    /* total distinct cores */
	uint nb_cpu;      /* total CPUs */
};

/* Description of a CPU selection policy. For now it only associates an option
 * name with a callback function that is supposed to adjust the global.nbthread
 * and global.nbtgroups based on the policy, the topology, and the constraints
 * on the number of threads which must be between tmin and tmax included, and
 * the number of thread groups which must be between gmin and gmax included.
 * The callback also takes the policy number (cpu_policy) and a pointer to a
 * string to write an error to in case of failure (in which case ret must be
 * < 0 and the caller will fre the location). More settings might come later.
 */
struct ha_cpu_policy {
	const char *name;                    /* option name in the configuration */
	const char *desc;                    /* short description for help messages */
	int (*fct)(int policy, int tmin, int tmax, int gmin, int gmax, char **err);
};

#endif /* _HAPROXY_CPU_TOPO_T_H */
