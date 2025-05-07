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
#include <haproxy/time.h>

/* retrieved shared counters pointer for a given <guid> object
 * <size> hint is expected to reflect the actual type size (fe/be)
 * if <guid> is not set, then sharing is disabled
 * Returns the pointer on success or NULL on failure
 */
static void*_counters_shared_get(const struct guid_node *guid, size_t size)
{
	struct counters_shared *shared;
	uint last_change;

	/* no shared memory for now, simply allocate a memory block
	 * for the counters (zero-initialized), ignore guid
	 */
	shared = calloc(1, size);
	if (!shared)
		return NULL;
	if (!guid->node.key)
		shared->flags |= COUNTERS_SHARED_F_LOCAL;
	last_change = ns_to_sec(now_ns);
	HA_ATOMIC_STORE(&shared->last_change, last_change);
	return shared;
}

/* retrieve shared fe counters pointer for a given <guid> object */
struct fe_counters_shared *counters_fe_shared_get(const struct guid_node *guid)
{
	return _counters_shared_get(guid, sizeof(struct fe_counters_shared));
}

/* retrieve shared be counters pointer for a given <guid> object */
struct be_counters_shared *counters_be_shared_get(const struct guid_node *guid)
{
	return _counters_shared_get(guid, sizeof(struct be_counters_shared));
}

static void _counters_shared_drop(void *counters)
{
	/* memory was allocated using calloc(), simply free it */
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
