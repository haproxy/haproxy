#define _GNU_SOURCE

#include <dirent.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>

#include <haproxy/api.h>
#include <haproxy/cpuset.h>
#include <haproxy/cpu_topo.h>
#include <haproxy/global.h>
#include <haproxy/tools.h>

/* CPU topology information, ha_cpuset_size() entries, allocated at boot */
int cpu_topo_maxcpus  = -1;  // max number of CPUs supported by OS/haproxy
int cpu_topo_lastcpu  = -1;  // last supposed online CPU (no need to look beyond)
struct ha_cpu_topo *ha_cpu_topo = NULL;
struct cpu_map *cpu_map;

/* non-zero if we're certain that taskset or similar was used to force CPUs */
int cpu_mask_forced = 0;

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
	int cpu;

	/* update the list with the CPUs currently bound to the current process */
	ha_cpuset_detect_bound(&boot_set);

	/* remove the known-excluded CPUs */
	for (cpu = 0; cpu < cpu_topo_maxcpus; cpu++)
		if (!ha_cpuset_isset(&boot_set, cpu))
			ha_cpu_topo[cpu].st |= HA_CPU_F_EXCLUDED;

	/* Update the list of currently offline CPUs. Normally it's a subset
	 * of the unbound ones, but we cannot infer anything if we don't have
	 * the info so we only update what we know. We take this opportunity
	 * for detecting that some online CPUs are not bound, indicating that
	 * taskset or equivalent was used.
	 */
	if (ha_cpuset_detect_online(&boot_set)) {
		for (cpu = 0; cpu < cpu_topo_maxcpus; cpu++) {
			if (!ha_cpuset_isset(&boot_set, cpu)) {
				ha_cpu_topo[cpu].st |= HA_CPU_F_OFFLINE;
			} else {
				cpu_topo_lastcpu = cpu;
				if (ha_cpu_topo[cpu].st & HA_CPU_F_EXCLUDED)
					cpu_mask_forced = 1;
			}
		}
	}

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

/* Dump the CPU topology <topo> for up to cpu_topo_maxcpus CPUs for
 * debugging purposes. Offline CPUs are skipped.
 */
void cpu_dump_topology(const struct ha_cpu_topo *topo)
{
	int has_smt = 0;
	int cpu, lvl;

	for (cpu = 0; cpu <= cpu_topo_lastcpu; cpu++)
		if (ha_cpu_topo[cpu].th_cnt > 1)
			has_smt = 1;

	for (cpu = 0; cpu <= cpu_topo_lastcpu; cpu++) {
		if (ha_cpu_topo[cpu].st & HA_CPU_F_OFFLINE)
			continue;

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

/* CPU topology detection below, OS-specific */

#if defined(__linux__)

/* detect the CPU topology based on info in /sys */
int cpu_detect_topology(void)
{
	const char *parse_cpu_set_args[2];
	struct ha_cpu_topo cpu_id = { }; /* all zeroes */
	struct hap_cpuset node_cpu_set;
	struct dirent *de;
	DIR *dir;
	int cpu;

	/* now let's only focus on bound CPUs to learn more about their
	 * topology, their siblings, their cache affinity etc. We can stop
	 * at lastcpu which matches the ID of the last known bound CPU
	 * when it's set. We'll pre-assign and auto-increment indexes for
	 * thread_set_id, cluster_id, l1/l2/l3 id, etc. We don't revisit entries
	 * already filled from the list provided by another CPU.
	 */
	for (cpu = 0; cpu <= cpu_topo_lastcpu; cpu++) {
		struct hap_cpuset cpus_list;
		int next_level = 1; // assume L1 if unknown
		int idx, level;
		int cpu2;

		if (ha_cpu_topo[cpu].st & HA_CPU_F_OFFLINE)
			continue;

		/* First, let's check the cache hierarchy. On systems exposing
		 * it, index0 generally is the L1D cache, index1 the L1I, index2
		 * the L2 and index3 the L3. But sometimes L1I/D are reversed,
		 * and some CPUs also have L0 or L4. Maybe some heterogenous
		 * SoCs even have inconsistent levels between clusters... Thus
		 * we'll scan all entries that we can find for each CPU and
		 * assign levels based on what is reported. The types generally
		 * are "Data", "Instruction", "Unified". We just ignore inst if
		 * found.
		 */
		for (idx = 0; idx < 10; idx++) {
			if (!is_dir_present(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/cache/index%d", cpu, idx))
				break;

			if (read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH
			                       "/cpu/cpu%d/cache/index%d/type", cpu, idx) >= 0 &&
			    strcmp(trash.area, "Instruction") == 0)
				continue;

			level = next_level;
			if (read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH
			                       "/cpu/cpu%d/cache/index%d/level", cpu, idx) >= 0) {
				level = atoi(trash.area);
				next_level = level + 1;
			}

			if (level < 0 || level > 4)
				continue; // level out of bounds

			if (ha_cpu_topo[cpu].ca_id[level] >= 0)
				continue; // already filled

			if (read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH
			                       "/cpu/cpu%d/cache/index%d/shared_cpu_list", cpu, idx) >= 0) {
				parse_cpu_set_args[0] = trash.area;
				parse_cpu_set_args[1] = "\0";
				if (parse_cpu_set(parse_cpu_set_args, &cpus_list, NULL) == 0) {
					for (cpu2 = 0; cpu2 <= cpu_topo_lastcpu; cpu2++) {
						if (ha_cpuset_isset(&cpus_list, cpu2))
							ha_cpu_topo[cpu2].ca_id[level] = cpu_id.ca_id[level];
					}
					cpu_id.ca_id[level]++;
				}
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
				int sib_id = 0;

				cpu_id.th_cnt = ha_cpuset_count(&cpus_list);
				for (cpu2 = 0; cpu2 <= cpu_topo_lastcpu; cpu2++) {
					if (ha_cpuset_isset(&cpus_list, cpu2)) {
						ha_cpu_topo[cpu2].ts_id  = cpu_id.ts_id;
						ha_cpu_topo[cpu2].th_cnt = cpu_id.th_cnt;
						ha_cpu_topo[cpu2].th_id  = sib_id++;
					}
				}
				cpu_id.ts_id++;
			}
		}

		/* clusters of cores when they exist, can be smaller and more
		 * precise than core lists (e.g. big.little), otherwise use
		 * core lists as a fall back, which may also have been used
		 * above as a fallback for package but we don't care here. We
		 * only consider these values if there's more than one CPU per
		 * cluster (some kernels such as 6.1 report one cluster per CPU).
		 */
		if (ha_cpu_topo[cpu].cl_gid < 0 &&
		    (read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/topology/cluster_cpus_list", cpu) >= 0 ||
		     read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/topology/core_siblings_list", cpu) >= 0)) {
			parse_cpu_set_args[0] = trash.area;
			parse_cpu_set_args[1] = "\0";
			if (parse_cpu_set(parse_cpu_set_args, &cpus_list, NULL) == 0 && ha_cpuset_count(&cpus_list) > 1) {
				for (cpu2 = 0; cpu2 <= cpu_topo_lastcpu; cpu2++) {
					if (ha_cpuset_isset(&cpus_list, cpu2)) {
						ha_cpu_topo[cpu2].cl_lid = cpu_id.cl_lid;
						ha_cpu_topo[cpu2].cl_gid = cpu_id.cl_gid;
					}
				}
				cpu_id.cl_lid++;
				cpu_id.cl_gid++;
			}
		}

		/* package CPUs list, like nodes, are generally a hard limit
		 * for groups, which must not span over multiple of them. On
		 * some systems, the package_cpus_list is not always provided,
		 * so we may first fall back to core_siblings_list which also
		 * exists, then to the physical package id from each CPU, whose
		 * number starts at 0. The first one is preferred because it
		 * provides a list in a single read().
		 */
		if (ha_cpu_topo[cpu].pk_id < 0 &&
		    (read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/topology/package_cpus_list", cpu) >= 0 ||
		     read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/topology/core_siblings_list", cpu) >= 0)) {
			parse_cpu_set_args[0] = trash.area;
			parse_cpu_set_args[1] = "\0";
			if (parse_cpu_set(parse_cpu_set_args, &cpus_list, NULL) == 0) {
				for (cpu2 = 0; cpu2 <= cpu_topo_lastcpu; cpu2++) {
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

	/* Now locate NUMA node IDs if any */

	dir = opendir(NUMA_DETECT_SYSTEM_SYSFS_PATH "/node");
	if (dir) {
		while ((de = readdir(dir))) {
			long node_id;
			char *endptr;

			/* dir name must start with "node" prefix */
			if (strncmp(de->d_name, "node", 4) != 0)
				continue;

			/* dir name must be at least 5 characters long */
			if (!de->d_name[4])
				continue;

			/* dir name must end with a non-negative numeric id */
			node_id = strtol(&de->d_name[4], &endptr, 10);
			if (*endptr || node_id < 0)
				continue;

			/* all tests succeeded, it's in the form "node%d" */
			if (read_line_to_trash("%s/node/%s/cpulist", NUMA_DETECT_SYSTEM_SYSFS_PATH, de->d_name) >= 0) {
				parse_cpu_set_args[0] = trash.area;
				parse_cpu_set_args[1] = "\0";
				if (parse_cpu_set(parse_cpu_set_args, &node_cpu_set, NULL) == 0) {
					for (cpu = 0; cpu < cpu_topo_maxcpus; cpu++)
						if (ha_cpuset_isset(&node_cpu_set, cpu))
							ha_cpu_topo[cpu].no_id = node_id;
				}
			}
		}
		/* done */
		closedir(dir);
	}
	return 1;
}

#elif defined(__FreeBSD__)

int cpu_detect_topology(void)
{
	struct hap_cpuset node_cpu_set;
	int ndomains, domain, cpu;
	size_t len = sizeof(ndomains);

	/* Try to detect NUMA nodes */
	if (sysctlbyname("vm.ndomains", &ndomains, &len, NULL, 0) == 0) {
		BUG_ON(ndomains > MAXMEMDOM);

		/* For each domain we'll reference the domain ID in the belonging
		 * CPUs.
		 */
		for (domain = 0; domain < ndomains; domain++) {
			ha_cpuset_zero(&node_cpu_set);

			if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_DOMAIN, domain,
					       sizeof(node_cpu_set.cpuset), &node_cpu_set.cpuset) == -1)
				continue;

			for (cpu = 0; cpu < cpu_topo_maxcpus; cpu++)
				if (ha_cpuset_isset(&node_cpu_set, cpu))
					ha_cpu_topo[cpu].no_id = domain;
		}
	}
	return 1;
}

#else // !__linux__, !__FreeBSD__

int cpu_detect_topology(void)
{
	return 1;
}

#endif // OS-specific cpu_detect_topology()

/* Allocates everything needed to store CPU topology at boot.
 * Returns non-zero on success, zero on failure.
 */
static int cpu_topo_alloc(void)
{
	int cpu;

	cpu_topo_maxcpus = cpu_topo_get_maxcpus();
	cpu_topo_lastcpu = cpu_topo_maxcpus - 1;

	cpu_map = calloc(MAX_TGROUPS, sizeof(*cpu_map));
	if (!cpu_map)
		return 0;

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
	ha_free(&cpu_map);
}

INITCALL0(STG_ALLOC, cpu_topo_alloc);
REGISTER_POST_DEINIT(cpu_topo_deinit);
