#define _GNU_SOURCE

#include <unistd.h>
#include <haproxy/api.h>
#include <haproxy/cpu_topo.h>

/* CPU topology information, ha_cpuset_size() entries, allocated at boot */
int cpu_topo_maxcpus  = -1;  // max number of CPUs supported by OS/haproxy
int cpu_topo_lastcpu  = -1;  // last supposed online CPU (no need to look beyond)
struct ha_cpu_topo *ha_cpu_topo = NULL;

/* returns an optimal maxcpus for the current system. It will take into
 * account what is reported by the OS, if any, otherwise will fall back
 * to the cpuset size, which serves as an upper limit in any case.
 */
static int cpu_topo_get_maxcpus(void)
{
	int abs_max = ha_cpuset_size();

#if defined(_SC_NPROCESSORS_CONF)
	int n = (int)sysconf(_SC_NPROCESSORS_CONF);

	if (n > 0 && n <= abs_max)
		return n;
#endif
	return abs_max;
}

/* Allocates everything needed to store CPU topology at boot.
 * Returns non-zero on success, zero on failure.
 */
static int cpu_topo_alloc(void)
{
	int cpu;

	cpu_topo_maxcpus = cpu_topo_get_maxcpus();
	cpu_topo_lastcpu = cpu_topo_maxcpus - 1;

	/* allocate the structures used to store CPU topology info */
	ha_cpu_topo = (struct ha_cpu_topo*)malloc(cpu_topo_maxcpus * sizeof(*ha_cpu_topo));
	if (!ha_cpu_topo)
		return 0;

	/* preset all fields to -1 except the index and the state flags which
	 * are assumed to all be bound and online unless detected otherwise.
	 */
	for (cpu = 0; cpu < cpu_topo_maxcpus; cpu++) {
		memset(&ha_cpu_topo[cpu], 0xff, sizeof(*ha_cpu_topo));
		ha_cpu_topo[cpu].st  = 0;
		ha_cpu_topo[cpu].idx = cpu;
	}

	return 1;
}

static void cpu_topo_deinit(void)
{
	ha_free(&ha_cpu_topo);
}

INITCALL0(STG_ALLOC, cpu_topo_alloc);
REGISTER_POST_DEINIT(cpu_topo_deinit);
