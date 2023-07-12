#define _GNU_SOURCE
#include <sched.h>
#include <ctype.h>

#include <haproxy/api.h>
#include <haproxy/cpuset.h>
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
	cpu_map = (struct cpu_map*)calloc(MAX_TGROUPS, sizeof(*cpu_map));
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
