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

#if defined(__linux__) || defined(__DragonFly__)

# define CPUSET_REPR cpu_set_t
# define CPUSET_USE_CPUSET

#elif defined(__FreeBSD__) || defined(__NetBSD__)

# define CPUSET_REPR cpuset_t

# if defined(__FreeBSD__) && __FreeBSD_version >= 1400046
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
	struct hap_cpuset proc;                 /* list of CPU masks for the whole process */
	struct hap_cpuset proc_t1           ;   /* list of CPU masks for the 1st thread of the process */
	struct hap_cpuset thread[MAX_THREADS];  /* list of CPU masks for the 32/64 first threads of the 1st process */
};

#endif /* _HAPROXY_CPUSET_T_H */
