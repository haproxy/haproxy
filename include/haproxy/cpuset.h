#ifndef _HAPROXY_CPUSET_H
#define _HAPROXY_CPUSET_H

#include <haproxy/cpuset-t.h>

extern struct cpu_map cpu_map;

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
void ha_cpuset_and(struct hap_cpuset *dst, const struct hap_cpuset *src);

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
void ha_cpuset_assign(struct hap_cpuset *dst, const struct hap_cpuset *src);

/* Returns the biggest index plus one usable on the platform.
 */
int ha_cpuset_size();

#endif /* _HAPROXY_CPUSET_H */
