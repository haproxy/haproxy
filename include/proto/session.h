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

#include <proto/obj_type.h>
#include <proto/stick_table.h>
#include <proto/server.h>

extern struct pool_head *pool_head_session;
struct session *session_new(struct proxy *fe, struct listener *li, enum obj_type *origin);
void session_free(struct session *sess);
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

static inline void session_add_conn(struct session *sess, struct connection *conn, void *target)
{
	int avail = -1;
	int i;

	sess->resp_conns++;
	for (i = 0; i < MAX_SRV_LIST; i++) {
		if (sess->srv_list[i].target == target) {
			avail = i;
			break;
		}
		if (LIST_ISEMPTY(&sess->srv_list[i].list) && avail == -1)
			avail = i;
	}
	if (avail == -1) {
		struct connection *conn, *conn_back;
		int count = 0;
		/* We have no slot free, let's free the one with the fewer connections */
		for (i = 0; i < MAX_SRV_LIST; i++) {
			int count_list = 0;
			list_for_each_entry(conn, &sess->srv_list[i].list, session_list)
			    count_list++;
			if (count == 0 || count_list < count) {
				count = count_list;
				avail = i;
			}
		}
		/* Now unown all the connections */
		list_for_each_entry_safe(conn, conn_back, &sess->srv_list[avail].list, session_list) {
			sess->resp_conns--;
			conn->owner = NULL;
			LIST_DEL(&conn->session_list);
			LIST_INIT(&conn->session_list);
			if (conn->mux)
				conn->mux->destroy(conn);
		}

	}
	sess->srv_list[avail].target = target;
	LIST_ADDQ(&sess->srv_list[avail].list, &conn->session_list);
}

/* Returns 0 if the session can keep the idle conn, -1 if it was destroyed, or 1 if it was added to the server list */
static inline int session_check_idle_conn(struct session *sess, struct connection *conn)
{
	if (sess->resp_conns > sess->fe->max_out_conns) {
		/* We can't keep the connection, let's try to add it to the server idle list */
		LIST_DEL(&conn->session_list);
		LIST_INIT(&conn->session_list);
		conn->owner = NULL;
		sess->resp_conns--;
		if (!srv_add_to_idle_list(objt_server(conn->target), conn)) {
			/* The server doesn't want it, let's kill the connection right away */
			conn->mux->destroy(conn);
			return -1;
		}
		return 1;
	}
	return 0;
}

#endif /* _PROTO_SESSION_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
