#define _GNU_SOURCE
#include <sched.h>
#include <ctype.h>

#include <haproxy/api.h>
#include <haproxy/cpuset.h>
#include <haproxy/global.h>
#include <haproxy/intops.h>
#include <haproxy/tools.h>

struct cpu_map *cpu_map;

/* CPU topology information, ha_cpuset_size() entries, allocated at boot */
struct ha_cpu_topo *ha_cpu_topo = NULL;

void ha_cpuset_zero(struct hap_cpuset *set)
{
#if defined(CPUSET_USE_CPUSET) || defined(CPUSET_USE_FREEBSD_CPUSET)
	CPU_ZERO(&set->cpuset);

#elif defined(CPUSET_USE_ULONG)
	set->cpuset = 0;
#endif
}

int ha_cpuset_set(struct hap_cpuset *set, int cpu)
{
	if (cpu >= ha_cpuset_size())
		return 1;

#if defined(CPUSET_USE_CPUSET) || defined(CPUSET_USE_FREEBSD_CPUSET)
	CPU_SET(cpu, &set->cpuset);
	return 0;

#elif defined(CPUSET_USE_ULONG)
	set->cpuset |= (0x1 << cpu);
	return 0;
#endif
}

int ha_cpuset_clr(struct hap_cpuset *set, int cpu)
{
	if (cpu >= ha_cpuset_size())
		return 1;

#if defined(CPUSET_USE_CPUSET) || defined(CPUSET_USE_FREEBSD_CPUSET)
	CPU_CLR(cpu, &set->cpuset);
	return 0;

#elif defined(CPUSET_USE_ULONG)
	set->cpuset &= ~(0x1 << cpu);
	return 0;
#endif
}

void ha_cpuset_and(struct hap_cpuset *dst, struct hap_cpuset *src)
{
#if defined(CPUSET_USE_CPUSET)
	CPU_AND(&dst->cpuset, &dst->cpuset, &src->cpuset);

#elif defined(CPUSET_USE_FREEBSD_CPUSET)
	CPU_AND(&dst->cpuset, &src->cpuset);

#elif defined(CPUSET_USE_ULONG)
	dst->cpuset &= src->cpuset;
#endif
}

void ha_cpuset_or(struct hap_cpuset *dst, struct hap_cpuset *src)
{
#if defined(CPUSET_USE_CPUSET)
	CPU_OR(&dst->cpuset, &dst->cpuset, &src->cpuset);

#elif defined(CPUSET_USE_FREEBSD_CPUSET)
	CPU_OR(&dst->cpuset, &src->cpuset);

#elif defined(CPUSET_USE_ULONG)
	dst->cpuset |= src->cpuset;
#endif
}

int ha_cpuset_isset(const struct hap_cpuset *set, int cpu)
{
	if (cpu >= ha_cpuset_size())
		return 0;

#if defined(CPUSET_USE_CPUSET) || defined(CPUSET_USE_FREEBSD_CPUSET)
	return CPU_ISSET(cpu, &set->cpuset);

#elif defined(CPUSET_USE_ULONG)
	return !!(set->cpuset & (0x1 << cpu));
#else
	return 0;
#endif
}

int ha_cpuset_count(const struct hap_cpuset *set)
{
#if defined(CPUSET_USE_CPUSET) || defined(CPUSET_USE_FREEBSD_CPUSET)
	return CPU_COUNT(&set->cpuset);

#elif defined(CPUSET_USE_ULONG)
	return my_popcountl(set->cpuset);
#endif
}

int ha_cpuset_ffs(const struct hap_cpuset *set)
{
#if defined(CPUSET_USE_CPUSET)
	int n;

	if (!CPU_COUNT(&set->cpuset))
		return 0;

	for (n = 0; !CPU_ISSET(n, &set->cpuset); ++n)
		;

	return n + 1;

#elif defined(CPUSET_USE_FREEBSD_CPUSET)
	return CPU_FFS(&set->cpuset);

#elif defined(CPUSET_USE_ULONG)
	if (!set->cpuset)
		return 0;

	return my_ffsl(set->cpuset);
#endif
}

void ha_cpuset_assign(struct hap_cpuset *dst, struct hap_cpuset *src)
{
#if defined(CPUSET_USE_CPUSET)
	CPU_ZERO(&dst->cpuset);
	CPU_OR(&dst->cpuset, &dst->cpuset, &src->cpuset);

#elif defined(CPUSET_USE_FREEBSD_CPUSET)
	CPU_COPY(&src->cpuset, &dst->cpuset);

#elif defined(CPUSET_USE_ULONG)
	dst->cpuset = src->cpuset;
#endif
}

int ha_cpuset_size()
{
#if defined(CPUSET_USE_CPUSET) || defined(CPUSET_USE_FREEBSD_CPUSET)
	return CPU_SETSIZE;

#elif defined(CPUSET_USE_ULONG)
	return LONGBITS;

#endif
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

#elif defined(__FreeBSD__)

	struct hap_cpuset node_cpu_set;
	int ndomains, domain;
	size_t len = sizeof(ndomains);

	ha_cpuset_zero(set);

	/* retrieve the union of NUMA nodes as online CPUs */
	if (sysctlbyname("vm.ndomains", &ndomains, &len, NULL, 0) == 0) {
		BUG_ON(ndomains > MAXMEMDOM);

		for (domain = 0; domain < ndomains; domain++) {
			ha_cpuset_zero(&node_cpu_set);

			if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_DOMAIN, domain,
					       sizeof(node_cpu_set.cpuset), &node_cpu_set.cpuset) == -1)
				continue;

			ha_cpuset_or(set, &node_cpu_set);
		}
	}

#else // !__linux__, !__FreeBSD__

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

	/* Update the list of currently offline CPUs. Normally it's a subset
	 * of the unbound ones, but we cannot infer anything if we don't have
	 * the info so we only update what we know.
	 */
	if (ha_cpuset_detect_online(&boot_set)) {
		for (cpu = 0; cpu < maxcpus; cpu++) {
			if (!ha_cpuset_isset(&boot_set, cpu))
				ha_cpu_topo[cpu].st |= HA_CPU_F_OFFLINE;
		}
	}

	return 0;
}

/* CPU topology detection below, OS-specific */

#if defined(__linux__)

/* detect the CPU topology based on info in /sys */
int cpu_detect_topology(void)
{
	struct hap_cpuset node_cpu_set;
	const char *parse_cpu_set_args[2];
	struct ha_cpu_topo cpu_id = { }; /* all zeroes */
	int maxcpus = 0;
	int lastcpu = 0;
	int cpu;

	maxcpus = ha_cpuset_size();

	for (cpu = 0; cpu < maxcpus; cpu++)
		if (!(ha_cpu_topo[cpu].st & HA_CPU_F_OFFLINE))
			lastcpu = cpu;

	/* now let's only focus on bound CPUs to learn more about their
	 * topology, their siblings, their cache affinity etc. We can stop
	 * at lastcpu which matches the ID of the last known bound CPU
	 * when it's set. We'll pre-assign and auto-increment indexes for
	 * thread_set_id, cluster_id, l1/l2/l3 id, etc. We don't revisit entries
	 * already filled from the list provided by another CPU.
	 */
	for (cpu = 0; cpu <= lastcpu; cpu++) {
		struct hap_cpuset cpus_list;
		int cpu2;

		if (ha_cpu_topo[cpu].st & HA_CPU_F_OFFLINE)
			continue;

		/* First, let's check the cache hierarchy. On systems exposing
		 * it, index0 generally is the L1D cache, index1 the L1I, index2
		 * the L2 and index3 the L3.
		 */

		/* other CPUs sharing the same L1 cache (SMT) */
		if (ha_cpu_topo[cpu].l1_id < 0 &&
		    read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/cache/index0/shared_cpu_list", cpu) >= 0) {
			parse_cpu_set_args[0] = trash.area;
			parse_cpu_set_args[1] = "\0";
			if (parse_cpu_set(parse_cpu_set_args, &cpus_list, NULL) == 0) {
				for (cpu2 = 0; cpu2 <= lastcpu; cpu2++) {
					if (ha_cpuset_isset(&cpus_list, cpu2))
						ha_cpu_topo[cpu2].l1_id = cpu_id.l1_id;
				}
				cpu_id.l1_id++;
			}
		}

		/* other CPUs sharing the same L2 cache (clusters of cores) */
		if (ha_cpu_topo[cpu].l2_id < 0 &&
		    read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/cache/index2/shared_cpu_list", cpu) >= 0) {
			parse_cpu_set_args[0] = trash.area;
			parse_cpu_set_args[1] = "\0";
			if (parse_cpu_set(parse_cpu_set_args, &cpus_list, NULL) == 0) {
				for (cpu2 = 0; cpu2 <= lastcpu; cpu2++) {
					if (ha_cpuset_isset(&cpus_list, cpu2))
						ha_cpu_topo[cpu2].l2_id = cpu_id.l2_id;
				}
				cpu_id.l2_id++;
			}
		}

		/* other CPUs sharing the same L3 cache slices (local cores) */
		if (ha_cpu_topo[cpu].l3_id < 0 &&
		    read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/cache/index3/shared_cpu_list", cpu) >= 0) {
			parse_cpu_set_args[0] = trash.area;
			parse_cpu_set_args[1] = "\0";
			if (parse_cpu_set(parse_cpu_set_args, &cpus_list, NULL) == 0) {
				for (cpu2 = 0; cpu2 <= lastcpu; cpu2++) {
					if (ha_cpuset_isset(&cpus_list, cpu2))
						ha_cpu_topo[cpu2].l3_id = cpu_id.l3_id;
				}
				cpu_id.l3_id++;
			}
		}

		/* Now let's try to get more info about how the cores are
		 * arranged in packages, clusters, cores, threads etc. It
		 * overlaps a bit with the cache above, but as not all systems
		 * provide all of these, they're quite complementary in fact.
		 */

		/* thread siblings list will allow to figure which CPU threads
		 * share the same cores, and also to tell apart cores that
		 * support SMT from those which do not. When mixed, generally
		 * the ones with SMT are big cores and the ones without are the
		 * small ones.
		 */
		if (ha_cpu_topo[cpu].ts_id < 0 &&
		    read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/topology/thread_siblings_list", cpu) >= 0) {
			parse_cpu_set_args[0] = trash.area;
			parse_cpu_set_args[1] = "\0";
			if (parse_cpu_set(parse_cpu_set_args, &cpus_list, NULL) == 0) {
				cpu_id.th_cnt = ha_cpuset_count(&cpus_list);
				for (cpu2 = 0; cpu2 <= lastcpu; cpu2++) {
					if (ha_cpuset_isset(&cpus_list, cpu2)) {
						ha_cpu_topo[cpu2].ts_id  = cpu_id.ts_id;
						ha_cpu_topo[cpu2].th_cnt = cpu_id.th_cnt;
					}
				}
				cpu_id.ts_id++;
			}
		}

		/* clusters of cores when they exist, can be smaller and more
		 * precise than core lists (e.g. big.little), otherwise use
		 * core lists.
		 */
		if (ha_cpu_topo[cpu].cl_id < 0 &&
		    read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/topology/cluster_cpus_list", cpu) >= 0) {
			parse_cpu_set_args[0] = trash.area;
			parse_cpu_set_args[1] = "\0";
			if (parse_cpu_set(parse_cpu_set_args, &cpus_list, NULL) == 0) {
				for (cpu2 = 0; cpu2 <= lastcpu; cpu2++) {
					if (ha_cpuset_isset(&cpus_list, cpu2))
						ha_cpu_topo[cpu2].cl_id = cpu_id.cl_id;
				}
				cpu_id.cl_id++;
			}
		} else if (ha_cpu_topo[cpu].cl_id < 0 &&
		    read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/topology/core_siblings_list", cpu) >= 0) {
			parse_cpu_set_args[0] = trash.area;
			parse_cpu_set_args[1] = "\0";
			if (parse_cpu_set(parse_cpu_set_args, &cpus_list, NULL) == 0) {
				for (cpu2 = 0; cpu2 <= lastcpu; cpu2++) {
					if (ha_cpuset_isset(&cpus_list, cpu2))
						ha_cpu_topo[cpu2].cl_id = cpu_id.cl_id;
				}
				cpu_id.cl_id++;
			}
		}

		/* package CPUs list, like nodes, are generally a hard limit
		 * for groups, which must not span over multiple of them. On
		 * some systems, the package_cpus_list is not always provided,
		 * so we may fall back to the physical package id from each
		 * CPU, whose number starts at 0. The first one is preferred
		 * because it provides a list in a single read().
		 */
		if (ha_cpu_topo[cpu].pk_id < 0 &&
		    read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/topology/package_cpus_list", cpu) >= 0) {
			parse_cpu_set_args[0] = trash.area;
			parse_cpu_set_args[1] = "\0";
			if (parse_cpu_set(parse_cpu_set_args, &cpus_list, NULL) == 0) {
				for (cpu2 = 0; cpu2 <= lastcpu; cpu2++) {
					if (ha_cpuset_isset(&cpus_list, cpu2))
						ha_cpu_topo[cpu2].pk_id = cpu_id.pk_id;
				}
				cpu_id.pk_id++;
			}
		}

		if (ha_cpu_topo[cpu].pk_id < 0 &&
		    read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/topology/physical_package_id", cpu) >= 0) {
			if (trash.data)
				ha_cpu_topo[cpu].pk_id = str2uic(trash.area);
		}

		/* CPU capacity is a relative notion to compare little and big
		 * cores. Usually the values encountered in field set the big
		 * CPU's nominal capacity to 1024 and the other ones below.
		 */
		if (ha_cpu_topo[cpu].capa < 0 &&
		    read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/cpu_capacity", cpu) >= 0) {
			if (trash.data)
				ha_cpu_topo[cpu].capa = str2uic(trash.area);
		}
	}
	return 1;
}

#else // __linux__

int cpu_detect_topology(void)
{
	return 1;
}

#endif // OS-specific cpu_detect_topology()

/* Parse cpu sets. Each CPU set is either a unique number between 0 and
 * ha_cpuset_size() - 1 or a range with two such numbers delimited by a dash
 * ('-'). Each CPU set can be a list of unique numbers or ranges separated by
 * a comma. It is also possible to specify multiple cpu numbers or ranges in
 * distinct argument in <args>. On success, it returns 0, otherwise it returns
 * 1, optionally with an error message in <err> if <err> is not NULL.
 */
int parse_cpu_set(const char **args, struct hap_cpuset *cpu_set, char **err)
{
	int cur_arg = 0;
	const char *arg;

	ha_cpuset_zero(cpu_set);

	arg = args[cur_arg];
	while (*arg) {
		const char *dash, *comma;
		unsigned int low, high;

		if (!isdigit((unsigned char)*args[cur_arg])) {
			memprintf(err, "'%s' is not a CPU range.", arg);
			return 1;
		}

		low = high = str2uic(arg);

		comma = strchr(arg, ',');
		dash = strchr(arg, '-');

		if (dash && (!comma || dash < comma))
			high = *(dash+1) ? str2uic(dash + 1) : ha_cpuset_size() - 1;

		if (high < low) {
			unsigned int swap = low;
			low = high;
			high = swap;
		}

		if (high >= ha_cpuset_size()) {
			memprintf(err, "supports CPU numbers from 0 to %d.",
			          ha_cpuset_size() - 1);
			return 1;
		}

		while (low <= high)
			ha_cpuset_set(cpu_set, low++);

		/* if a comma is present, parse the rest of the arg, else
		 * skip to the next arg */
		arg = comma ? comma + 1 : args[++cur_arg];
	}
	return 0;
}

/* Parse a linux cpu map string representing to a numeric cpu mask map
 * The cpu map string is a list of 4-byte hex strings separated by commas, with
 * most-significant byte first, one bit per cpu number.
 */
void parse_cpumap(char *cpumap_str, struct hap_cpuset *cpu_set)
{
	unsigned long cpumap;
	char *start, *endptr, *comma;
	int i, j;

	ha_cpuset_zero(cpu_set);

	i = 0;
	do {
		/* reverse-search for a comma, parse the string after the comma
		 * or at the beginning if no comma found
		 */
		comma = strrchr(cpumap_str, ',');
		start = comma ? comma + 1 : cpumap_str;

		cpumap = strtoul(start, &endptr, 16);
		for (j = 0; cpumap; cpumap >>= 1, ++j) {
			if (cpumap & 0x1)
				ha_cpuset_set(cpu_set, j + i * 32);
		}

		if (comma)
			*comma = '\0';
		++i;
	} while (comma);
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

/* Allocates everything needed to store CPU information at boot.
 * Returns non-zero on success, zero on failure.
 */
static int cpuset_alloc(void)
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

static void cpuset_deinit(void)
{
	ha_free(&ha_cpu_topo);
	ha_free(&cpu_map);
}

INITCALL0(STG_ALLOC, cpuset_alloc);
REGISTER_POST_DEINIT(cpuset_deinit);
