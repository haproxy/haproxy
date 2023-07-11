#define _GNU_SOURCE

#include <sched.h>
#include <string.h>

#include <haproxy/api.h>
#include <haproxy/cpuset.h>
#include <haproxy/cpu_topo.h>
#include <haproxy/global.h>
#include <haproxy/tools.h>

/* CPU topology information, ha_cpuset_size() entries, allocated at boot */
struct ha_cpu_topo *ha_cpu_topo = NULL;
struct cpu_map *cpu_map;


/* Detects CPUs that are online on the system. It may rely on FS access (e.g.
 * /sys on Linux). Returns the number of CPUs detected or 0 if the detection
 * failed.
 */
int ha_cpuset_detect_online(struct hap_cpuset *set)
{
#if defined(__linux__)

	ha_cpuset_zero(set);

	/* contains a list of CPUs in the format <low>[-<high>][,...] */
	if (read_line_to_trash("%s/cpu/online", NUMA_DETECT_SYSTEM_SYSFS_PATH) >= 0) {
		const char *parse_cpu_set_args[2] = { trash.area, "\0" };

		if (parse_cpu_set(parse_cpu_set_args, set, NULL) != 0)
			ha_cpuset_zero(set);
	}

#else // !__linux__

	ha_cpuset_zero(set);

#endif
	return ha_cpuset_count(set);
}

/* Detects the CPUs that will be used based on the ones the process is bound to
 * at boot. The principle is the following: all CPUs from the boot cpuset will
 * be used since we don't know upfront how individual threads will be mapped to
 * groups and CPUs.
 *
 * Returns non-zero on success, zero on failure. Note that it may not be
 * performed in the function above because some calls may rely on other items
 * being allocated (e.g. trash).
 */
int cpu_detect_usable(void)
{
	struct hap_cpuset boot_set = { };
	int maxcpus = ha_cpuset_size();
	int cpu;

	/* update the list with the CPUs currently bound to the current process */
	ha_cpuset_detect_bound(&boot_set);

	/* remove the known-excluded CPUs */
	for (cpu = 0; cpu < maxcpus; cpu++)
		if (!ha_cpuset_isset(&boot_set, cpu))
			ha_cpu_topo[cpu].st |= HA_CPU_F_EXCLUDED;

	return 0;
}

/* Detects CPUs that are bound to the current process. Returns the number of
 * CPUs detected or 0 if the detection failed.
 */
int ha_cpuset_detect_bound(struct hap_cpuset *set)
{
	ha_cpuset_zero(set);

	/* detect bound CPUs depending on the OS's API */
	if (0
#if defined(__linux__)
	    || sched_getaffinity(0, sizeof(set->cpuset), &set->cpuset) != 0
#elif defined(__FreeBSD__)
	    || cpuset_getaffinity(CPU_LEVEL_CPUSET, CPU_WHICH_PID, -1, sizeof(set->cpuset), &set->cpuset) != 0
#else
	    || 1 // unhandled platform
#endif
	    ) {
		/* detection failed */
		return 0;
	}

	return ha_cpuset_count(set);
}

/* Returns true if at least one cpu-map directive was configured, otherwise
 * false.
 */
int cpu_map_configured(void)
{
	int grp, thr;

	for (grp = 0; grp < MAX_TGROUPS; grp++) {
		for (thr = 0; thr < MAX_THREADS_PER_GROUP; thr++)
			if (ha_cpuset_count(&cpu_map[grp].thread[thr]))
				return 1;
	}
	return 0;
}

/* Dump the CPU topology <topo> for up to <maxcpus> for debugging purposes.
 * Offline CPUs are skipped.
 */
void cpu_dump_topology(const struct ha_cpu_topo *topo, int maxcpus)
{
	int lastcpu = 0;
	int has_smt = 0;
	int cpu, lvl;

	for (cpu = 0; cpu < maxcpus; cpu++) {
		if (!(ha_cpu_topo[cpu].st & HA_CPU_F_OFFLINE))
			lastcpu = cpu;
		if (ha_cpu_topo[cpu].th_cnt > 1)
			has_smt = 1;
	}

	for (cpu = 0; cpu <= lastcpu; cpu++) {
		printf("%3d: cpu=%3d excl=%d pk=%02d no=%02d cl=%03d(%03d)",
		       cpu, ha_cpu_topo[cpu].idx,
		       (ha_cpu_topo[cpu].st & HA_CPU_F_EXCL_MASK),
		       ha_cpu_topo[cpu].pk_id,
		       ha_cpu_topo[cpu].no_id,
		       ha_cpu_topo[cpu].cl_gid,
		       ha_cpu_topo[cpu].cl_lid);

		/* list only relevant cache levels */
		for (lvl = 4; lvl >= 0; lvl--) {
			if (ha_cpu_topo[cpu].ca_id[lvl] < 0)
				continue;
			printf(lvl < 3 ? " l%d=%02d" : " l%d=%03d", lvl, ha_cpu_topo[cpu].ca_id[lvl]);
		}

		printf(" ts=%03d capa=%d",
		       ha_cpu_topo[cpu].ts_id,
		       ha_cpu_topo[cpu].capa);

		if (has_smt) {
			if (ha_cpu_topo[cpu].th_cnt > 1)
				printf(" smt=%d/%d",
				       ha_cpu_topo[cpu].th_id,
				       ha_cpu_topo[cpu].th_cnt);
			else
				printf(" smt=%d",
				       ha_cpu_topo[cpu].th_cnt);
		}
		putchar('\n');
	}
}

/* Allocates everything needed to store CPU topology at boot.
 * Returns non-zero on success, zero on failure.
 */
static int cpu_topo_alloc(void)
{
	int maxcpus = ha_cpuset_size();
	int cpu;

	/* allocate the structures used to store CPU topology info */
	cpu_map = calloc(MAX_TGROUPS, sizeof(*cpu_map));
	if (!cpu_map)
		return 0;

	/* allocate the structures used to store CPU topology info */
	ha_cpu_topo = (struct ha_cpu_topo*)malloc(maxcpus * sizeof(*ha_cpu_topo));
	if (!ha_cpu_topo)
		return 0;

	/* preset all fields to -1 except the index and the state flags which
	 * are assumed to all be bound and online unless detected otherwise.
	 */
	for (cpu = 0; cpu < maxcpus; cpu++) {
		memset(&ha_cpu_topo[cpu], 0xff, sizeof(*ha_cpu_topo));
		ha_cpu_topo[cpu].st  = 0;
		ha_cpu_topo[cpu].idx = cpu;
	}

	return 1;
}

static void cpu_topo_deinit(void)
{
	ha_free(&ha_cpu_topo);
	ha_free(&cpu_map);
}

INITCALL0(STG_ALLOC, cpu_topo_alloc);
REGISTER_POST_DEINIT(cpu_topo_deinit);
