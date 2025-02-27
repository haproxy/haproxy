#define _GNU_SOURCE

#include <dirent.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/cpuset.h>
#include <haproxy/cpu_topo.h>
#include <haproxy/global.h>
#include <haproxy/tools.h>

/* for cpu_set.flags below */
#define CPU_SET_FL_NONE       0x0000
#define CPU_SET_FL_DO_RESET   0x0001

/* CPU topology information, ha_cpuset_size() entries, allocated at boot */
int cpu_topo_maxcpus  = -1;  // max number of CPUs supported by OS/haproxy
int cpu_topo_lastcpu  = -1;  // last supposed online CPU (no need to look beyond)
struct ha_cpu_topo *ha_cpu_topo = NULL;
struct cpu_map *cpu_map;

/* non-zero if we're certain that taskset or similar was used to force CPUs */
int cpu_mask_forced = 0;

/* "cpu-set" global configuration */
struct cpu_set_cfg {
	uint flags; // CPU_SET_FL_XXX above
	/* CPU numbers to accept / reject */
	struct hap_cpuset only_cpus;
	struct hap_cpuset drop_cpus;
} cpu_set_cfg;

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

	if (!(cpu_set_cfg.flags & CPU_SET_FL_DO_RESET)) {
		/* update the list with the CPUs currently bound to the current process */
		ha_cpuset_detect_bound(&boot_set);

		/* remove the known-excluded CPUs */
		for (cpu = 0; cpu < cpu_topo_maxcpus; cpu++)
			if (!ha_cpuset_isset(&boot_set, cpu))
				ha_cpu_topo[cpu].st |= HA_CPU_F_EXCLUDED;
	}

	/* remove CPUs in the drop-cpu set or not in the only-cpu set */
	for (cpu = 0; cpu < cpu_topo_maxcpus; cpu++) {
		if ( ha_cpuset_isset(&cpu_set_cfg.drop_cpus, cpu) ||
		    !ha_cpuset_isset(&cpu_set_cfg.only_cpus, cpu))
			ha_cpu_topo[cpu].st |= HA_CPU_F_DONT_USE;
	}

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

		printf("[%s] cpu=%3d pk=%02d no=%02d cl=%03d(%03d)",
		       (ha_cpu_topo[cpu].st & HA_CPU_F_EXCL_MASK) ? "----" : "keep",
		       ha_cpu_topo[cpu].idx,
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

/* function used by qsort to re-arrange CPUs by index only, to restore original
 * ordering.
 */
int _cmp_cpu_index(const void *a, const void *b)
{
	const struct ha_cpu_topo *l = (const struct ha_cpu_topo *)a;
	const struct ha_cpu_topo *r = (const struct ha_cpu_topo *)b;

	/* next, IDX, so that SMT ordering is preserved */
	if (l->idx >= 0 && l->idx < r->idx)
		return -1;
	if (l->idx > r->idx && r->idx >= 0)
		return  1;

	/* exactly the same (e.g. absent, should not happend) */
	return 0;
}

/* function used by qsort to compare two hwcpus and arrange them by vicinity
 * only. -1 says a<b, 1 says a>b. The goal is to arrange the closest CPUs
 * together, preferring locality over performance in order to keep latency
 * as low as possible, so that when picking a fixed number of threads, the
 * closest ones are used in priority. It's also used to help arranging groups
 * at the end.
 */
int _cmp_cpu_locality(const void *a, const void *b)
{
	const struct ha_cpu_topo *l = (const struct ha_cpu_topo *)a;
	const struct ha_cpu_topo *r = (const struct ha_cpu_topo *)b;

	/* first, online vs offline */
	if (!(l->st & HA_CPU_F_EXCL_MASK) && (r->st & HA_CPU_F_EXCL_MASK))
		return -1;

	if (!(r->st & HA_CPU_F_EXCL_MASK) && (l->st & HA_CPU_F_EXCL_MASK))
		return 1;

	/* next, package ID */
	if (l->pk_id >= 0 && l->pk_id < r->pk_id)
		return -1;
	if (l->pk_id > r->pk_id && r->pk_id >= 0)
		return  1;

	/* next, node ID */
	if (l->no_id >= 0 && l->no_id < r->no_id)
		return -1;
	if (l->no_id > r->no_id && r->no_id >= 0)
		return  1;

	/* next, L4 */
	if (l->ca_id[4] >= 0 && l->ca_id[4] < r->ca_id[4])
		return -1;
	if (l->ca_id[4] > r->ca_id[4] && r->ca_id[4] >= 0)
		return  1;

	/* next, L3 */
	if (l->ca_id[3] >= 0 && l->ca_id[3] < r->ca_id[3])
		return -1;
	if (l->ca_id[3] > r->ca_id[3] && r->ca_id[3] >= 0)
		return  1;

	/* next, cluster */
	if (l->cl_gid >= 0 && l->cl_gid < r->cl_gid)
		return -1;
	if (l->cl_gid > r->cl_gid && r->cl_gid >= 0)
		return  1;

	/* next, L2 */
	if (l->ca_id[2] >= 0 && l->ca_id[2] < r->ca_id[2])
		return -1;
	if (l->ca_id[2] > r->ca_id[2] && r->ca_id[2] >= 0)
		return  1;

	/* next, thread set */
	if (l->ts_id >= 0 && l->ts_id < r->ts_id)
		return -1;
	if (l->ts_id > r->ts_id && r->ts_id >= 0)
		return  1;

	/* next, L1 */
	if (l->ca_id[1] >= 0 && l->ca_id[1] < r->ca_id[1])
		return -1;
	if (l->ca_id[1] > r->ca_id[1] && r->ca_id[1] >= 0)
		return  1;

	/* next, L0 */
	if (l->ca_id[0] >= 0 && l->ca_id[0] < r->ca_id[0])
		return -1;
	if (l->ca_id[0] > r->ca_id[0] && r->ca_id[0] >= 0)
		return  1;

	/* next, IDX, so that SMT ordering is preserved */
	if (l->idx >= 0 && l->idx < r->idx)
		return -1;
	if (l->idx > r->idx && r->idx >= 0)
		return  1;

	/* exactly the same (e.g. absent) */
	return 0;
}

/* function used by qsort to compare two hwcpus and arrange them by cluster to
 * make sure no cluster crosses L3 boundaries. -1 says a<b, 1 says a>b. It's
 * only used during topology detection.
 */
int _cmp_cpu_cluster(const void *a, const void *b)
{
	const struct ha_cpu_topo *l = (const struct ha_cpu_topo *)a;
	const struct ha_cpu_topo *r = (const struct ha_cpu_topo *)b;

	/* first, online vs offline */
	if (!(l->st & HA_CPU_F_EXCL_MASK) && (r->st & HA_CPU_F_EXCL_MASK))
		return -1;

	if (!(r->st & HA_CPU_F_EXCL_MASK) && (l->st & HA_CPU_F_EXCL_MASK))
		return 1;

	/* next, cluster */
	if (l->cl_gid >= 0 && l->cl_gid < r->cl_gid)
		return -1;
	if (l->cl_gid > r->cl_gid && r->cl_gid >= 0)
		return  1;

	/* next, package ID */
	if (l->pk_id >= 0 && l->pk_id < r->pk_id)
		return -1;
	if (l->pk_id > r->pk_id && r->pk_id >= 0)
		return  1;

	/* next, node ID */
	if (l->no_id >= 0 && l->no_id < r->no_id)
		return -1;
	if (l->no_id > r->no_id && r->no_id >= 0)
		return  1;

	/* next, L3 */
	if (l->ca_id[3] >= 0 && l->ca_id[3] < r->ca_id[3])
		return -1;
	if (l->ca_id[3] > r->ca_id[3] && r->ca_id[3] >= 0)
		return  1;

	/* if no L3, then L2 */
	if (l->ca_id[2] >= 0 && l->ca_id[2] < r->ca_id[2])
		return -1;
	if (l->ca_id[2] > r->ca_id[2] && r->ca_id[2] >= 0)
		return  1;

	/* next, IDX, so that SMT ordering is preserved */
	if (l->idx >= 0 && l->idx < r->idx)
		return -1;
	if (l->idx > r->idx && r->idx >= 0)
		return  1;

	/* exactly the same (e.g. absent) */
	return 0;
}

/* re-order a CPU topology array by CPU index only. This is mostly used before
 * listing CPUs regardless of their characteristics.
 */
void cpu_reorder_by_index(struct ha_cpu_topo *topo, int entries)
{
	qsort(topo, entries, sizeof(*topo), _cmp_cpu_index);
}

/* re-order a CPU topology array by locality to help form groups. */
void cpu_reorder_by_locality(struct ha_cpu_topo *topo, int entries)
{
	qsort(topo, entries, sizeof(*topo), _cmp_cpu_locality);
}

/* re-order a CPU topology array by cluster id. */
void cpu_reorder_by_cluster(struct ha_cpu_topo *topo, int entries)
{
	qsort(topo, entries, sizeof(*topo), _cmp_cpu_cluster);
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

/* This function is responsible for trying to fill in the missing info after
 * topology detection and making sure we don't leave any ID at -1, but rather
 * we assign unused ones.
 */
void cpu_fixup_topology(void)
{
	struct hap_cpuset cpuset;
	int cpu, cpu2;
	int curr_id, prev_id;
	int min_id, neg;

	/* fill the package id, node id and thread_id. First we'll build a bitmap
	 * of all unassigned ones so that we can spot the lowest unassigned one
	 * and assign it to those currently set to -1.
	 */

	/* package id */
	ha_cpuset_zero(&cpuset);
	for (cpu = 0; cpu <= cpu_topo_lastcpu; cpu++)
		ha_cpuset_set(&cpuset, cpu);

	for (cpu = neg = 0; cpu <= cpu_topo_lastcpu; cpu++) {
		if (ha_cpu_topo[cpu].pk_id < 0)
			neg++;
		else
			ha_cpuset_clr(&cpuset, ha_cpu_topo[cpu].pk_id);
	}

	/* get the first unused pkg id */
	min_id = ha_cpuset_ffs(&cpuset) - 1;
	for (cpu = 0; neg && cpu <= cpu_topo_lastcpu; cpu++) {
		if (ha_cpu_topo[cpu].pk_id < 0) {
			ha_cpu_topo[cpu].pk_id = min_id;
			neg--;
		}
	}

	/* node id */
	ha_cpuset_zero(&cpuset);
	for (cpu = 0; cpu <= cpu_topo_lastcpu; cpu++)
		ha_cpuset_set(&cpuset, cpu);

	for (cpu = neg = 0; cpu <= cpu_topo_lastcpu; cpu++) {
		if (ha_cpu_topo[cpu].no_id < 0)
			neg++;
		else
			ha_cpuset_clr(&cpuset, ha_cpu_topo[cpu].no_id);
	}

	/* get the first unused node id */
	min_id = ha_cpuset_ffs(&cpuset) - 1;
	for (cpu = 0; neg && cpu <= cpu_topo_lastcpu; cpu++) {
		if (ha_cpu_topo[cpu].no_id < 0) {
			ha_cpu_topo[cpu].no_id = min_id;
			neg--;
		}
	}

	/* thread id */
	ha_cpuset_zero(&cpuset);
	for (cpu = 0; cpu <= cpu_topo_lastcpu; cpu++)
		ha_cpuset_set(&cpuset, cpu);

	for (cpu = neg = 0; cpu <= cpu_topo_lastcpu; cpu++) {
		if (ha_cpu_topo[cpu].th_id < 0)
			neg++;
		else
			ha_cpuset_clr(&cpuset, ha_cpu_topo[cpu].th_id);
	}

	/* get the first unused thr id */
	min_id = ha_cpuset_ffs(&cpuset) - 1;
	for (cpu = 0; neg && cpu <= cpu_topo_lastcpu; cpu++) {
		if (ha_cpu_topo[cpu].th_id < 0) {
			ha_cpu_topo[cpu].th_id = min_id;
			ha_cpu_topo[cpu].th_cnt = min_id + 1;
			neg--;
		}
	}

	/* assign capacity if not filled, based on the number of threads on the
	 * core: in a same package, SMT-capable cores are generally those
	 * optimized for performers while non-SMT ones are generally those
	 * optimized for efficiency. We'll reflect that by assigning 100 and 50
	 * respectively to those.
	 */
	for (cpu = 0; cpu <= cpu_topo_lastcpu; cpu++) {
		if (ha_cpu_topo[cpu].capa < 0)
			ha_cpu_topo[cpu].capa = (ha_cpu_topo[cpu].th_cnt > 1) ? 100 : 50;
	}

	/* First, on some machines, L3 is not reported. But some also don't
	 * have L3.  However, no L3 when there are more than 2 L2 is quite
	 * unheard of, and while we don't really care about firing 2 groups for
	 * 2 L2, we'd rather avoid this if there are 8! In this case we'll add
	 * an L3 instance to fix the situation.
	 */
	cpu_reorder_by_locality(ha_cpu_topo, cpu_topo_maxcpus);

	prev_id = -2; // make sure it cannot match even unassigned ones
	curr_id = -1;
	for (cpu = cpu2 = 0; cpu <= cpu_topo_lastcpu; cpu++) {
		if (ha_cpu_topo[cpu].ca_id[3] >= 0)
			continue;

		/* L3 not assigned, count L2 instances */
		if (!cpu ||
		    (ha_cpu_topo[cpu].pk_id != ha_cpu_topo[cpu-1].pk_id) ||
		    (ha_cpu_topo[cpu].no_id != ha_cpu_topo[cpu-1].no_id) ||
		    (ha_cpu_topo[cpu].ca_id[4] != ha_cpu_topo[cpu-1].ca_id[4])) {
			curr_id = 0;
			prev_id = -2;
			cpu2 = cpu;
		}
		else if (ha_cpu_topo[cpu].ca_id[2] != prev_id) {
			curr_id++;
			if (curr_id >= 2) {
				/* let's assign L3 id to zero for all those.
				 * We can go till the end since we'll just skip
				 * them on next passes above.
				 */
				for (; cpu2 <= cpu_topo_lastcpu; cpu2++) {
					if (ha_cpu_topo[cpu2].ca_id[3] < 0 &&
					    ha_cpu_topo[cpu2].pk_id == ha_cpu_topo[cpu].pk_id &&
					    ha_cpu_topo[cpu2].no_id == ha_cpu_topo[cpu].no_id &&
					    ha_cpu_topo[cpu2].ca_id[4] == ha_cpu_topo[cpu].ca_id[4])
						ha_cpu_topo[cpu2].ca_id[3] = 0;
				}
			}
		}
	}

	cpu_reorder_by_index(ha_cpu_topo, cpu_topo_maxcpus);
}

/* This function is responsible for composing clusters based on existing info
 * on the CPU topology.
 */
void cpu_compose_clusters(void)
{
	int cpu;
	int curr_gid, prev_gid;
	int curr_lid, prev_lid;

	/* Now we'll sort CPUs by topology and assign cluster IDs to those that
	 * don't yet have one, based on the die/pkg/llc.
	 */
	cpu_reorder_by_locality(ha_cpu_topo, cpu_topo_maxcpus);

	prev_gid = prev_lid = -2; // make sure it cannot match even unassigned ones
	curr_gid = curr_lid = -1;
	for (cpu = 0; cpu <= cpu_topo_lastcpu; cpu++) {
		/* renumber clusters and assign unassigned ones at the same
		 * time. For this, we'll compare pkg/die/llc with the last
		 * CPU's and verify if we need to create a new cluster ID.
		 * Note that some platforms don't report cache. The locao value
		 * is local to the pkg+node combination so that we reset it
		 * when changing, contrary to the global one which grows.
		 */
		if (!cpu ||
		    (ha_cpu_topo[cpu].pk_id != ha_cpu_topo[cpu-1].pk_id) ||
		    (ha_cpu_topo[cpu].no_id != ha_cpu_topo[cpu-1].no_id)) {
			curr_gid++;
			curr_lid = 0;
		}
		else if (ha_cpu_topo[cpu].cl_gid != prev_gid ||
			 ha_cpu_topo[cpu].ca_id[4] != ha_cpu_topo[cpu-1].ca_id[4] ||
			 (ha_cpu_topo[cpu].ca_id[4] < 0 && // no l4 ? check L3
			  ((ha_cpu_topo[cpu].ca_id[3] != ha_cpu_topo[cpu-1].ca_id[3]) ||
			   (ha_cpu_topo[cpu].ca_id[3] < 0 && // no l3 ? check L2
			    (ha_cpu_topo[cpu].ca_id[2] != ha_cpu_topo[cpu-1].ca_id[2]))))) {
			curr_gid++;
			curr_lid++;
		}
		prev_gid = ha_cpu_topo[cpu].cl_gid;
		prev_lid = ha_cpu_topo[cpu].cl_lid;
		ha_cpu_topo[cpu].cl_gid = curr_gid;
		ha_cpu_topo[cpu].cl_lid = curr_lid;
	}

	cpu_reorder_by_index(ha_cpu_topo, cpu_topo_maxcpus);
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
	int no_cache, no_topo, no_capa, no_clust, no_pkg;
	int no_cppc, no_freq;
	DIR *dir;
	int cpu;

	/* now let's only focus on bound CPUs to learn more about their
	 * topology, their siblings, their cache affinity etc. We can stop
	 * at lastcpu which matches the ID of the last known bound CPU
	 * when it's set. We'll pre-assign and auto-increment indexes for
	 * thread_set_id, cluster_id, l1/l2/l3 id, etc. We don't revisit entries
	 * already filled from the list provided by another CPU.
	 */

	if (!is_dir_present(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu"))
		goto skip_cpu;

	/* detect the presence of some kernel-specific fields */
	no_cache = no_topo = no_capa = no_clust = no_pkg = no_freq = no_cppc = -1;
	for (cpu = 0; cpu <= cpu_topo_lastcpu; cpu++) {
		struct hap_cpuset siblings_list = { };
		struct hap_cpuset cpus_list;
		int next_level = 1; // assume L1 if unknown
		int idx, level;
		int cpu2;

		if (ha_cpu_topo[cpu].st & HA_CPU_F_OFFLINE)
			continue;

		if (!is_dir_present(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d", cpu))
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
		if (no_cache < 0)
			no_cache = !is_dir_present(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/cache", cpu);

		if (no_cache)
			goto skip_cache;

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

	skip_cache:
		if (no_topo < 0)
			no_topo = !is_dir_present(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/topology", cpu);

		if (no_topo)
			goto skip_topo;

		/* Now let's try to get more info about how the cores are
		 * arranged in packages, clusters, cores, threads etc. It
		 * overlaps a bit with the cache above, but as not all systems
		 * provide all of these, they're quite complementary in fact.
		 */

		/* thread siblings list will allow to figure which CPU threads
		 * share the same cores, and also to tell apart cores that
		 * support SMT from those which do not. When mixed, generally
		 * the ones with SMT are big cores and the ones without are the
		 * small ones. We also read the entry if the cluster_id is not
		 * known because we'll have to compare both values.
		 */
		if ((ha_cpu_topo[cpu].ts_id < 0 || ha_cpu_topo[cpu].cl_gid < 0) &&
		    read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/topology/thread_siblings_list", cpu) >= 0) {
			parse_cpu_set_args[0] = trash.area;
			parse_cpu_set_args[1] = "\0";
			if (parse_cpu_set(parse_cpu_set_args, &siblings_list, NULL) == 0) {
				int sib_id = 0;

				cpu_id.th_cnt = ha_cpuset_count(&siblings_list);
				for (cpu2 = 0; cpu2 <= cpu_topo_lastcpu; cpu2++) {
					if (ha_cpuset_isset(&siblings_list, cpu2)) {
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
		 * Note that we purposely ignore clusters that are reportedly
		 * equal to the siblings list, because some machines report one
		 * distinct cluster per *core* (e.g. some armv7 and intel 14900).
		 */
		if (no_clust < 0) {
			no_clust = !is_file_present(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/topology/cluster_cpus_list", cpu) &&
				   !is_file_present(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/topology/core_siblings_list", cpu);
		}

		if (!no_clust && ha_cpu_topo[cpu].cl_gid < 0 &&
		    (read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/topology/cluster_cpus_list", cpu) >= 0 ||
		     read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/topology/core_siblings_list", cpu) >= 0)) {
			parse_cpu_set_args[0] = trash.area;
			parse_cpu_set_args[1] = "\0";
			if (parse_cpu_set(parse_cpu_set_args, &cpus_list, NULL) == 0 && ha_cpuset_count(&cpus_list) > 1 &&
			    (memcmp(&cpus_list, &siblings_list, sizeof(cpus_list)) != 0)) {
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
		if (no_pkg < 0) {
			no_pkg = !is_file_present(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/topology/package_cpus_list", cpu) &&
				 !is_file_present(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/topology/core_siblings_list", cpu);
		}

		if (!no_pkg && ha_cpu_topo[cpu].pk_id < 0 &&
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

	skip_topo:
		if (no_capa < 0)
			no_capa = !is_file_present(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/cpu_capacity", cpu);

		/* CPU capacity is a relative notion to compare little and big
		 * cores. Usually the values encountered in field set the big
		 * CPU's nominal capacity to 1024 and the other ones below.
		 */
		if (!no_capa && ha_cpu_topo[cpu].capa < 0 &&
		    read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/cpu_capacity", cpu) >= 0) {
			if (trash.data)
				ha_cpu_topo[cpu].capa = str2uic(trash.area);
		}

		/* When cpu_capacity is not available, sometimes acpi_cppc is
		 * available on servers to provide an equivalent metric allowing
		 * to distinguish big from small cores. Values as low as 15 and
		 * as high as 260 were seen there. Note that only nominal_perf
		 * is trustable, as nominal_freq may return zero. It's also
		 * more reliable than the max cpufreq values because it doesn't
		 * seem to take into account the die quality. However, acpi_cppc
		 * can be super slow on some systems (5ms per access noticed on
		 * a 64-core EPYC), making haproxy literally take seconds to
		 * start just due to this. Thus we start with cpufreq and fall
		 * back to acpi_cppc. If it becomes an issue, we could imagine
		 * forcing the value to all members of the same core and even
		 * cluster. Since the frequency alone is not a good criterion
		 * to qualify the CPU quality (perf vs efficiency core), instead
		 * we rely on the thread count to gauge if it's a performant or
		 * an efficient core, and we major performant cores' capacity
		 * by 50% (shown to be roughly correct on modern CPUs).
		 */
		if (no_freq < 0)
			no_freq = !is_dir_present(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/cpufreq", cpu);

		if (!no_freq && ha_cpu_topo[cpu].capa < 0 &&
		    read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/cpufreq/scaling_max_freq", cpu) >= 0) {
			/* This is in kHz, turn it to MHz to stay below 32k */
			if (trash.data) {
				ha_cpu_topo[cpu].capa = (str2uic(trash.area) + 999U) / 1000U;
				if (ha_cpu_topo[cpu].th_cnt > 1)
					ha_cpu_topo[cpu].capa = ha_cpu_topo[cpu].capa * 3 / 2;
			}
		}

		if (no_cppc < 0)
			no_cppc = !is_dir_present(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/acpi_cppc", cpu);

		if (!no_cppc && ha_cpu_topo[cpu].capa < 0 &&
		    read_line_to_trash(NUMA_DETECT_SYSTEM_SYSFS_PATH "/cpu/cpu%d/acpi_cppc/nominal_perf", cpu) >= 0) {
			if (trash.data)
				ha_cpu_topo[cpu].capa = str2uic(trash.area);
		}
	}

 skip_cpu:
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

/* Parse the "cpu-set" global directive, which takes action names and
 * optional values, and fills the cpu_set structure above.
 */
static int cfg_parse_cpu_set(char **args, int section_type, struct proxy *curpx,
                                   const struct proxy *defpx, const char *file, int line,
                                   char **err)
{
	const char *cpu_set_str[2] = { "", "" };
	struct hap_cpuset tmp_cpuset = { };
	int arg;

	for (arg = 1; *args[arg]; arg++) {
		if (strcmp(args[arg], "reset") == 0) {
			/* reset the excluded CPUs first (undo "taskset") */
			cpu_set_cfg.flags |= CPU_SET_FL_DO_RESET;
			cpu_mask_forced = 0;
		}
		else if (strcmp(args[arg], "drop-cpu") == 0 || strcmp(args[arg], "only-cpu") == 0) {
			if (!*args[arg + 1]) {
				memprintf(err, "missing CPU set");
				goto parse_err;
			}

			cpu_set_str[0] = args[arg + 1];
			if (parse_cpu_set(cpu_set_str, &tmp_cpuset, err) != 0)
				goto parse_err;

			if (*args[arg] == 'd') // cpus to drop
				ha_cpuset_or(&cpu_set_cfg.drop_cpus, &tmp_cpuset);
			else // cpus to keep
				ha_cpuset_and(&cpu_set_cfg.only_cpus, &tmp_cpuset);
			arg++;
		}
		else {
			/* fall back with default error message */
			memprintf(err, "'%s' passed an unknown directive '%s'", args[0], args[arg]);
			goto leave_with_err;
		}
	}

	if (arg == 1) {
		memprintf(err, "'%s' requires a directive and an optional value", args[0]);
		goto leave_with_err;
	}

	/* all done */
	return 0;

 parse_err:
	/* displays args[0] and args[arg] followed by *err so as to remind the
	 * option name, the sub-directive and the reported error.
	 */
	memprintf(err, "'%s %s': %s\n.", args[0], args[arg], *err);
	goto leave;

 leave_with_err:
	/* complete with supported directives */
	memprintf(err, "%s (only 'reset', 'only-cpu', 'drop-cpu' supported).", *err);
 leave:
	return -1;
}

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

	/* pre-inizialize the configured CPU sets */
	ha_cpuset_zero(&cpu_set_cfg.drop_cpus);
	ha_cpuset_zero(&cpu_set_cfg.only_cpus);

	/* preset all CPUs in the "only-XXX" sets */
	for (cpu = 0; cpu < cpu_topo_maxcpus; cpu++) {
		ha_cpuset_set(&cpu_set_cfg.only_cpus, cpu);
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

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "cpu-set",  cfg_parse_cpu_set, 0 },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
