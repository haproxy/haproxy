/*
 * objects counters management
 *
 * Copyright 2025 HAProxy Technologies
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdlib.h>
#include <haproxy/atomic.h>
#include <haproxy/clock.h>
#include <haproxy/counters.h>
#include <haproxy/global.h>
#include <haproxy/time.h>

static void _counters_shared_drop(void *counters)
{
	struct counters_shared *shared = counters;
	int it = 0;

	if (!shared)
		return;

	/* memory was allocated using calloc(), simply free it */
	while (it < global.nbtgroups) {
		free(shared->tg[it]);
		it += 1;
	}
	free(counters);
}

/* release a shared fe counters struct */
void counters_fe_shared_drop(struct fe_counters_shared *counters)
{
	_counters_shared_drop(counters);
}

/* release a shared be counters struct */
void counters_be_shared_drop(struct be_counters_shared *counters)
{
	_counters_shared_drop(counters);
}

/* retrieved shared counters pointer for a given <guid> object
 * <size> hint is expected to reflect the actual tg member size (fe/be)
 * if <guid> is not set, then sharing is disabled
 * Returns the pointer on success or NULL on failure
 */
static void*_counters_shared_get(const struct guid_node *guid, size_t size)
{
	struct counters_shared *shared;
	int it = 0;

	/* no shared memory for now, simply allocate a memory block
	 * for the counters (zero-initialized), ignore guid
	 */
	shared = calloc(1, sizeof(*shared));
	if (!shared)
		return NULL;
	if (!guid->node.key)
		shared->flags |= COUNTERS_SHARED_F_LOCAL;
	while (it < global.nbtgroups) {
		shared->tg[it] = calloc(1, size);
		if (!shared->tg[it]) {
			_counters_shared_drop(shared);
			return NULL;
		}
		it += 1;
	}

	/* initial values:
	 *   only set one group, only latest value is considered
	 */
	HA_ATOMIC_STORE(&shared->tg[0]->last_state_change, ns_to_sec(now_ns));
	return shared;
}

/* retrieve shared fe counters pointer for a given <guid> object */
struct fe_counters_shared *counters_fe_shared_get(const struct guid_node *guid)
{
	return _counters_shared_get(guid, sizeof(struct fe_counters_shared_tg));
}

/* retrieve shared be counters pointer for a given <guid> object */
struct be_counters_shared *counters_be_shared_get(const struct guid_node *guid)
{
	return _counters_shared_get(guid, sizeof(struct be_counters_shared_tg));
}
