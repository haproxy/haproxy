#ifndef _HAPROXY_CPUSET_T_H
#define _HAPROXY_CPUSET_T_H

#define _GNU_SOURCE
#include <sched.h>

#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__NetBSD__)
#include <sys/param.h>
#ifdef __FreeBSD__
#include <sys/_cpuset.h>
#include <sys/cpuset.h>
#include <sys/sysctl.h>
#include <strings.h>
#endif
#endif

#include <haproxy/api-t.h>

#if defined(__linux__) || defined(__DragonFly__) || \
  (defined(__FreeBSD_kernel__) && defined(__GLIBC__))

# define CPUSET_REPR cpu_set_t
# define CPUSET_USE_CPUSET

#elif defined(__FreeBSD__) || defined(__NetBSD__)

# define CPUSET_REPR cpuset_t

# if defined(__FreeBSD__) && __FreeBSD_version >= 1301000
#  define CPUSET_USE_CPUSET
# else
#  define CPUSET_USE_FREEBSD_CPUSET
# endif

#elif defined(__APPLE__)

# define CPUSET_REPR unsigned long
# define CPUSET_USE_ULONG

#else

# error "No cpuset support implemented on this platform"

#endif

struct hap_cpuset {
	CPUSET_REPR cpuset;
};

struct cpu_map {
	struct hap_cpuset thread[MAX_THREADS_PER_GROUP];  /* list of CPU masks for the 32/64 threads of this group */
};

/* CPU state flags used with CPU topology detection (ha_cpu_topo.st). We try
 * hard to rely on known info. For example we don't claim a CPU is bound or
 * online if we don't know, reason why instead we store offline or excluded.
 */
#define HA_CPU_F_EXCLUDED     0x0001  // this CPU was excluded at boot
#define HA_CPU_F_OFFLINE      0x0002  // this CPU is known to be offline

/* CPU topology descriptor. All the ID and IDX fields are initialized to -1
 * when not known. The identifiers there are mostly assigned on the fly using
 * increments and have no particular representation except the fact that CPUs
 * having the same ID there share the same designated resource. The flags are
 * preset to zero.
 */
struct ha_cpu_topo {
	ushort st;    // state flags (HA_CPU_F_*)
	short idx;    // CPU index as passed to the OS. Initially the entry index.
	short l1_id;  // L1 cache identifier
	short l2_id;  // L2 cache identifier
	short l3_id;  // L3 cache slice identifier
	short ts_id;  // thread-set identifier (generally core number)
	short cl_id;  // cluster identifier (group of more shortimate cores)
	short no_id;  // NUMA node identifier
	short pk_id;  // package identifier
	short tg_id;  // thread group ID
	short th_cnt; // number of siblings threads
	short capa;   // estimated CPU relative capacity; more is better
};

#endif /* _HAPROXY_CPUSET_T_H */
