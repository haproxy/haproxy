/*
 * include/haproxy/counters.h
 * objects counters management
 *
 * Copyright 2025 HAProxy Technologies
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_COUNTERS_H
# define _HAPROXY_COUNTERS_H

#include <stddef.h>

#include <haproxy/counters-t.h>
#include <haproxy/guid-t.h>

struct fe_counters_shared *counters_fe_shared_get(const struct guid_node *guid);
struct be_counters_shared *counters_be_shared_get(const struct guid_node *guid);

void counters_fe_shared_drop(struct fe_counters_shared *counters);
void counters_be_shared_drop(struct be_counters_shared *counters);

/* time oriented helper: get last time (relative to current time) on a given
 * <scounter> array, for <elem> member (one member per thread group) which is
 * assumed to be unsigned long type.
 *
 * wrapping is handled by taking the lowest diff between now and last counter.
 * But since wrapping is expected once every ~136 years (starting 01/01/1970),
 * perhaps it's not worth the extra CPU cost.. let's see.
 */
#define COUNTERS_SHARED_LAST_OFFSET(scounters, type, offset)                  \
({                                                                            \
	unsigned long last = HA_ATOMIC_LOAD((type *)((char *)scounters[0] + offset));\
	unsigned long now_seconds = ns_to_sec(now_ns);                        \
	int it;                                                               \
                                                                              \
	for (it = 1; it < global.nbtgroups; it++) {                           \
		unsigned long cur = HA_ATOMIC_LOAD((type *)((char *)scounters[it] + offset));\
		if ((now_seconds - cur) < (now_seconds - last))               \
			last = cur;                                           \
        }                                                                     \
	last;                                                                 \
})

#define COUNTERS_SHARED_LAST(scounters, elem)                                 \
({                                                                            \
        int offset = offsetof(typeof(**scounters), elem);                     \
        unsigned long last = COUNTERS_SHARED_LAST_OFFSET(scounters, typeof(scounters[0]->elem), offset);  \
	                                                                      \
	last;                                                                 \
})


/* generic unsigned integer addition for all <elem> members from
 * <scounters> array (one member per thread group)
 * <rfunc> is function taking pointer as parameter to read from the memory
 * location pointed to scounters[it].elem
 */
#define COUNTERS_SHARED_TOTAL_OFFSET(scounters, type, offset, rfunc)          \
({                                                                            \
	uint64_t __ret = 0;                                                   \
        int it;                                                               \
                                                                              \
	for (it = 0; it < global.nbtgroups; it++)                             \
		__ret += rfunc((type *)((char *)scounters[it] + offset));     \
	__ret;                                                                \
})

#define COUNTERS_SHARED_TOTAL(scounters, elem, rfunc)                         \
({                                                                            \
	int offset = offsetof(typeof(**scounters), elem);                     \
	uint64_t __ret = COUNTERS_SHARED_TOTAL_OFFSET(scounters, typeof(scounters[0]->elem), offset, rfunc);\
                                                                              \
	__ret;                                                                \
})
/* same as COUNTERS_SHARED_TOTAL but with <rfunc> taking 2 extras arguments:
 * <arg1> and <arg2>
 */
#define COUNTERS_SHARED_TOTAL_ARG2(scounters, elem, rfunc, arg1, arg2)        \
({                                                                            \
	uint64_t __ret = 0;                                                   \
	int it;                                                               \
                                                                              \
	for (it = 0; it < global.nbtgroups; it++)                             \
		__ret += rfunc(&scounters[it]->elem, arg1, arg2);             \
	__ret;                                                                \
})

#endif /* _HAPROXY_COUNTERS_H */
