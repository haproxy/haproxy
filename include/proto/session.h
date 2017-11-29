/*
 * include/proto/session.h
 * This file defines everything related to sessions.
 *
 * Copyright (C) 2000-2015 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_SESSION_H
#define _PROTO_SESSION_H

#include <common/config.h>
#include <common/buffer.h>
#include <common/debug.h>
#include <common/memory.h>

#include <types/global.h>
#include <types/session.h>

#include <proto/stick_table.h>

extern struct pool_head *pool_head_session;
struct session *session_new(struct proxy *fe, struct listener *li, enum obj_type *origin);
void session_free(struct session *sess);
int init_session();
int session_accept_fd(struct listener *l, int cfd, struct sockaddr_storage *addr);

/* Remove the refcount from the session to the tracked counters, and clear the
 * pointer to ensure this is only performed once. The caller is responsible for
 * ensuring that the pointer is valid first.
 */
static inline void session_store_counters(struct session *sess)
{
	void *ptr;
	int i;
	struct stksess *ts;

	for (i = 0; i < MAX_SESS_STKCTR; i++) {
		struct stkctr *stkctr = &sess->stkctr[i];

		ts = stkctr_entry(stkctr);
		if (!ts)
			continue;

		ptr = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_CONN_CUR);
		if (ptr) {
			HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

			stktable_data_cast(ptr, conn_cur)--;

			HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

			/* If data was modified, we need to touch to re-schedule sync */
			stktable_touch_local(stkctr->table, ts, 0);
		}

		stkctr_set_entry(stkctr, NULL);
		stksess_kill_if_expired(stkctr->table, ts, 1);
	}
}


#endif /* _PROTO_SESSION_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
