#ifndef _HAPROXY_CPUSET_H
#define _HAPROXY_CPUSET_H

#include <haproxy/cpuset-t.h>

extern struct cpu_map *cpu_map;

/* Unset all indexes in <set>.
 */
void ha_cpuset_zero(struct hap_cpuset *set);

/* Set <cpu> index in <set> if not present.
 * Returns 0 on success otherwise non-zero.
 */
int ha_cpuset_set(struct hap_cpuset *set, int cpu);

/* Clear <cpu> index in <set> if present.
 * Returns 0 on success otherwise non-zero.
 */
int ha_cpuset_clr(struct hap_cpuset *set, int cpu);

/* Bitwise and equivalent operation between <src> and <dst> stored in <dst>.
 */
void ha_cpuset_and(struct hap_cpuset *dst, struct hap_cpuset *src);

/* Bitwise OR equivalent operation between <src> and <dst> stored in <dst>.
 */
void ha_cpuset_or(struct hap_cpuset *dst, struct hap_cpuset *src);

/* returns non-zero if CPU index <cpu> is set in <set>, otherwise 0. */
int ha_cpuset_isset(const struct hap_cpuset *set, int cpu);

/* Returns the count of set index in <set>.
 */
int ha_cpuset_count(const struct hap_cpuset *set);

/* Returns the first index set plus one in <set> starting from the lowest.
 * Returns 0 if no index set.
 * Do not forget to subtract the result by one if using it for set/clr.
 */
int ha_cpuset_ffs(const struct hap_cpuset *set);

/* Copy <src> set into <dst>.
 */
void ha_cpuset_assign(struct hap_cpuset *dst, struct hap_cpuset *src);

/* Returns the biggest index plus one usable on the platform.
 */
int ha_cpuset_size(void);

/* Detects CPUs that are bound to the current process. Returns the number of
 * CPUs detected or 0 if the detection failed.
 */
int ha_cpuset_detect_bound(struct hap_cpuset *set);

/* Parse cpu sets. Each CPU set is either a unique number between 0 and
 * ha_cpuset_size() - 1 or a range with two such numbers delimited by a dash
 * ('-'). Each CPU set can be a list of unique numbers or ranges separated by
 * a comma. It is also possible to specify multiple cpu numbers or ranges in
 * distinct argument in <args>. On success, it returns 0, otherwise it returns
 * 1 with an error message in <err>.
 */
int parse_cpu_set(const char **args, struct hap_cpuset *cpu_set, char **err);

/* Parse a linux cpu map string representing to a numeric cpu mask map
 * The cpu map string is a list of 4-byte hex strings separated by commas, with
 * most-significant byte first, one bit per cpu number.
 */
void parse_cpumap(char *cpumap_str, struct hap_cpuset *cpu_set);

/* Returns true if at least one cpu-map directive was configured, otherwise
 * false.
 */
int cpu_map_configured(void);

#endif /* _HAPROXY_CPUSET_H */
