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
#include <stdio.h>
#include <haproxy/atomic.h>
#include <haproxy/clock.h>
#include <haproxy/counters.h>
#include <haproxy/global.h>
#include <haproxy/guid.h>
#include <haproxy/stats-file.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>

static void _counters_shared_drop(void *counters)
{
	struct counters_shared *shared = counters;
	int it = 0;

	if (!shared)
		return;

	while (it < global.nbtgroups && shared->tg[it]) {
		if (shared->flags & COUNTERS_SHARED_F_LOCAL) {
			/* memory was allocated using calloc(), simply free it */
			free(shared->tg[it]);
		}
		else {
			struct shm_stats_file_object *obj;

			/* inside shared memory, retrieve associated object and remove
			 * ourselves from its users
			 */
			obj = container_of(shared->tg[it], struct shm_stats_file_object, data);
			HA_ATOMIC_OR(&obj->users, (1 << shm_stats_file_slot));
		}
		it += 1;
	}
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

/* prepare shared counters pointers for a given <shared> parent
 * pointer and for <guid> object
 * <is_be> hint is expected to be set to 1 when the guid refers to be_shared
 * struct, else fe_shared stuct is assumed.
 *
 * if <guid> is not set, then sharing is disabled
 * Returns the pointer on success or NULL on failure, in which case
 * <errmsg> may contain additional hints about the error and must be freed accordingly
 */
static int _counters_shared_prepare(struct counters_shared *shared,
                                    const struct guid_node *guid, int is_be, char **errmsg)
{
	struct fe_counters_shared *fe_shared;
	struct be_counters_shared *be_shared;
	int it = 0;

	if (!guid->key || !shm_stats_file_hdr)
		shared->flags |= COUNTERS_SHARED_F_LOCAL;

	while (it < global.nbtgroups) {
		if (shared->flags & COUNTERS_SHARED_F_LOCAL) {
			size_t tg_size;

			tg_size = (is_be) ? sizeof(*be_shared->tg[0]) : sizeof(*fe_shared->tg[0]);
			shared->tg[it] = calloc(1, tg_size);
			if (!shared->tg[it])
				memprintf(errmsg, "memory error, calloc failed");
		}
		else if (!shared->tg[it]) {
			struct shm_stats_file_object *shm_obj;

			shm_obj = shm_stats_file_add_object(errmsg);
			if (shm_obj) {
				snprintf(shm_obj->guid, sizeof(shm_obj->guid)- 1, "%s", guid_get(guid));
				if (is_be) {
					shm_obj->type = SHM_STATS_FILE_OBJECT_TYPE_BE;
					be_shared = (struct be_counters_shared *)shared;
					be_shared->tg[it] = &shm_obj->data.be;
				}
				else {
					shm_obj->type = SHM_STATS_FILE_OBJECT_TYPE_FE;
					fe_shared = (struct fe_counters_shared *)shared;
					fe_shared->tg[it] = &shm_obj->data.fe;
				}
				/* we use atomic op to make the object visible by setting valid tgid value */
				HA_ATOMIC_STORE(&shm_obj->tgid, it + 1);
			}
		}
		if (!shared->tg[it]) {
			_counters_shared_drop(shared);
			return 0;
		}
		it += 1;
	}

	/* initial values:
	 *   only set one group, only latest value is considered
	 */
	HA_ATOMIC_STORE(&shared->tg[0]->last_state_change, ns_to_sec(now_ns));
	return 1;
}

/* prepare shared fe counters pointer for a given <guid> object */
int counters_fe_shared_prepare(struct fe_counters_shared *shared, const struct guid_node *guid, char **errmsg)
{
	return _counters_shared_prepare((struct counters_shared *)shared, guid, 0, errmsg);
}

/* prepare shared be counters pointer for a given <guid> object */
int counters_be_shared_prepare(struct be_counters_shared *shared, const struct guid_node *guid, char **errmsg)
{
	return _counters_shared_prepare((struct counters_shared *)shared, guid, 1, errmsg);
}
