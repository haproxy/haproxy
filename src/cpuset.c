#define _GNU_SOURCE

#include <haproxy/compat.h>
#include <haproxy/cpuset.h>
#include <haproxy/intops.h>
#include <haproxy/tools.h>

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
	if (cpu < 0 || cpu >= ha_cpuset_size())
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
	if (cpu < 0 || cpu >= ha_cpuset_size())
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
	if (cpu < 0 || cpu >= ha_cpuset_size())
		return 0;

#if defined(CPUSET_USE_CPUSET) || defined(CPUSET_USE_FREEBSD_CPUSET)
	/* Turn to boolean because musl directly returns the mask as a
	 * a long instead of an int, hence loses bits 32+.
	 */
	return !!CPU_ISSET(cpu, &set->cpuset);

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

/* returns true if the sets are equal */
int ha_cpuset_isequal(const struct hap_cpuset *dst, const struct hap_cpuset *src)
{
#if defined(CPUSET_USE_CPUSET)
	return CPU_EQUAL(&dst->cpuset, &src->cpuset);

#elif defined(CPUSET_USE_FREEBSD_CPUSET)
	return !CPU_CMP(&src->cpuset, &dst->cpuset);

#elif defined(CPUSET_USE_ULONG)
	return dst->cpuset == src->cpuset;
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

/* Print a cpu-set as compactly as possible and returns the output length.
 * Returns >size if it cannot emit anything due to length constraints, in which
 * case it will match what is at least needed to go further, and may return 0
 * for an empty set. It will emit series of comma-delimited ranges in the form
 * "beg[-end]".
 */
int print_cpu_set(char *output, size_t size, const struct hap_cpuset *cpu_set)
{
	struct hap_cpuset set = *cpu_set;
	int cpus = ha_cpuset_size();
	int first = -1;
	int len = 0;
	int cpu;

	for (cpu = 0; cpu < cpus; cpu++) {
		if (!ha_cpuset_isset(&set, cpu))
			continue;

		ha_cpuset_clr(&set, cpu);

		/* check if first of a series*/
		if (first < 0) {
			first = cpu;
			len += snprintf(output + len, size - len, "%d", cpu);
			if (len >= size)
				return len + 1;

			/* check if belongs to a range */
			if (cpu < cpus - 1 && ha_cpuset_isset(&set, cpu + 1)) {
				if (len + 1 >= size)
					return len + 2;
				output[len++] = '-';
				output[len] = 0;
			} else
				first = -1;
		}
		else if (cpu >= cpus - 1 || !ha_cpuset_isset(&set, cpu + 1)) {
			/* end of a series and not first */
			len += snprintf(output + len, size - len, "%d", cpu);
			if (len >= size)
				return len + 1;
			first = -1;
		}

		if (first < 0 && ha_cpuset_count(&set) > 0) {
			if (len + 1 >= size)
				return len + 2;
			output[len++] = ',';
			output[len] = 0;
		}
	}
	return len;
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
