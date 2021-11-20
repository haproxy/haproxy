/*
 * include/haproxy/session.h
 * This file contains functions used to manage sessions.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_SESSION_H
#define _HAPROXY_SESSION_H

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/global-t.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/pool.h>
#include <haproxy/server.h>
#include <haproxy/session-t.h>
#include <haproxy/stick_table.h>

extern struct pool_head *pool_head_session;
extern struct pool_head *pool_head_sess_srv_list;

struct session *session_new(struct proxy *fe, struct listener *li, enum obj_type *origin);
void session_free(struct session *sess);
int session_accept_fd(struct connection *cli_conn);
int conn_complete_session(struct connection *conn);
struct task *session_expire_embryonic(struct task *t, void *context, unsigned int state);

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

			if (stktable_data_cast(ptr, std_t_uint) > 0)
				stktable_data_cast(ptr, std_t_uint)--;

			HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

			/* If data was modified, we need to touch to re-schedule sync */
			stktable_touch_local(stkctr->table, ts, 0);
		}

		stkctr_set_entry(stkctr, NULL);
		stksess_kill_if_expired(stkctr->table, ts, 1);
	}
}

/* Increase the number of cumulated HTTP requests in the tracked counters */
static inline void session_inc_http_req_ctr(struct session *sess)
{
	int i;

	for (i = 0; i < MAX_SESS_STKCTR; i++)
		stkctr_inc_http_req_ctr(&sess->stkctr[i]);
}

/* Increase the number of cumulated failed HTTP requests in the tracked
 * counters. Only 4xx requests should be counted here so that we can
 * distinguish between errors caused by client behaviour and other ones.
 * Note that even 404 are interesting because they're generally caused by
 * vulnerability scans.
 */
static inline void session_inc_http_err_ctr(struct session *sess)
{
	int i;

	for (i = 0; i < MAX_SESS_STKCTR; i++)
		stkctr_inc_http_err_ctr(&sess->stkctr[i]);
}

/* Increase the number of cumulated failed HTTP responses in the tracked
 * counters. Only some 5xx responses should be counted here so that we can
 * distinguish between server failures and errors triggered by the client
 * (i.e. 501 and 505 may be triggered and must be ignored).
 */
static inline void session_inc_http_fail_ctr(struct session *sess)
{
	int i;

	for (i = 0; i < MAX_SESS_STKCTR; i++)
		stkctr_inc_http_fail_ctr(&sess->stkctr[i]);
}


/* Remove the connection from the session list, and destroy the srv_list if it's now empty */
static inline void session_unown_conn(struct session *sess, struct connection *conn)
{
	struct sess_srv_list *srv_list = NULL;

	BUG_ON(objt_listener(conn->target));

	/* WT: this currently is a workaround for an inconsistency between
	 * the link status of the connection in the session list and the
	 * connection's owner. This should be removed as soon as all this
	 * is addressed. Right now it's possible to enter here with a non-null
	 * conn->owner that points to a dead session, but in this case the
	 * element is not linked.
	 */
	if (!LIST_INLIST(&conn->session_list))
		return;

	if (conn->flags & CO_FL_SESS_IDLE)
		sess->idle_conns--;
	LIST_DEL_INIT(&conn->session_list);
	conn->owner = NULL;
	list_for_each_entry(srv_list, &sess->srv_list, srv_list) {
		if (srv_list->target == conn->target) {
			if (LIST_ISEMPTY(&srv_list->conn_list)) {
				LIST_DELETE(&srv_list->srv_list);
				pool_free(pool_head_sess_srv_list, srv_list);
			}
			break;
		}
	}
}

/* Add the connection <conn> to the server list of the session <sess>. This
 * function is called only if the connection is private. Nothing is performed if
 * the connection is already in the session sever list or if the session does
 * not own the connection.
 */
static inline int session_add_conn(struct session *sess, struct connection *conn, void *target)
{
	struct sess_srv_list *srv_list = NULL;
	int found = 0;

	BUG_ON(objt_listener(conn->target));

	/* Already attach to the session or not the connection owner */
	if (!LIST_ISEMPTY(&conn->session_list) || (conn->owner && conn->owner != sess))
		return 1;

	list_for_each_entry(srv_list, &sess->srv_list, srv_list) {
		if (srv_list->target == target) {
			found = 1;
			break;
		}
	}
	if (!found) {
		/* The session has no connection for the server, create a new entry */
		srv_list = pool_alloc(pool_head_sess_srv_list);
		if (!srv_list)
			return 0;
		srv_list->target = target;
		LIST_INIT(&srv_list->conn_list);
		LIST_APPEND(&sess->srv_list, &srv_list->srv_list);
	}
	LIST_APPEND(&srv_list->conn_list, &conn->session_list);
	return 1;
}

/* Returns 0 if the session can keep the idle conn, -1 if it was destroyed. The
 * connection must be private.
 */
static inline int session_check_idle_conn(struct session *sess, struct connection *conn)
{
	/* Another session owns this connection */
	if (conn->owner != sess)
		return 0;

	if (sess->idle_conns >= sess->fe->max_out_conns) {
		session_unown_conn(sess, conn);
		conn->owner = NULL;
		conn->flags &= ~CO_FL_SESS_IDLE;
		conn->mux->destroy(conn->ctx);
		return -1;
	} else {
		conn->flags |= CO_FL_SESS_IDLE;
		sess->idle_conns++;
	}
	return 0;
}

/* Look for an available connection matching the target <target> in the server
 * list of the session <sess>. It returns a connection if found. Otherwise it
 * returns NULL.
 */
static inline struct connection *session_get_conn(struct session *sess, void *target, int64_t hash)
{
	struct connection *srv_conn = NULL;
	struct sess_srv_list *srv_list;

	list_for_each_entry(srv_list, &sess->srv_list, srv_list) {
		if (srv_list->target == target) {
			list_for_each_entry(srv_conn, &srv_list->conn_list, session_list) {
				if ((srv_conn->hash_node && srv_conn->hash_node->hash == hash) &&
				    srv_conn->mux &&
				    (srv_conn->mux->avail_streams(srv_conn) > 0) &&
				    !(srv_conn->flags & CO_FL_WAIT_XPRT)) {
					if (srv_conn->flags & CO_FL_SESS_IDLE) {
						srv_conn->flags &= ~CO_FL_SESS_IDLE;
						sess->idle_conns--;
					}
					goto end;
				}
			}
			srv_conn = NULL; /* No available connection found */
			goto end;
		}
	}

  end:
	return srv_conn;
}

/* Returns the source address of the session and fallbacks on the client
 * connection if not set. It returns a const address on success or NULL on
 * failure.
 */
static inline const struct sockaddr_storage *sess_src(struct session *sess)
{
	struct connection *cli_conn = objt_conn(sess->origin);

	if (sess->flags & SESS_FL_ADDR_FROM_SET)
		return sess->src;
	if (cli_conn && conn_get_src(cli_conn))
		return conn_src(cli_conn);
	return NULL;
}

/* Returns the destination address of the session and fallbacks on the client
 * connection if not set. It returns a const address on success or NULL on
 * failure.
 */
static inline const struct sockaddr_storage *sess_dst(struct session *sess)
{
	struct connection *cli_conn = objt_conn(sess->origin);

	if (sess->flags & SESS_FL_ADDR_TO_SET)
		return sess->dst;
	if (cli_conn && conn_get_dst(cli_conn))
		return conn_dst(cli_conn);
	return NULL;
}


/* Retrieves the source address of the session <sess>. Returns non-zero on
 * success or zero on failure. The operation is only performed once and the
 * address is stored in the session for future use. On the first call, the
 * session source address is copied from the client connection one.
 */
static inline int sess_get_src(struct session *sess)
{
	struct connection *cli_conn = objt_conn(sess->origin);
	const struct sockaddr_storage *src = NULL;

	if (sess->flags & SESS_FL_ADDR_FROM_SET)
		return 1;

	if (cli_conn && conn_get_src(cli_conn))
		src = conn_src(cli_conn);
	if (!src)
		return 0;

	if (!sockaddr_alloc(&sess->src, src, sizeof(*src)))
		return 0;

	sess->flags |= SESS_FL_ADDR_FROM_SET;
	return 1;
}


/* Retrieves the destination address of the session <sess>. Returns non-zero on
 * success or zero on failure. The operation is only performed once and the
 * address is stored in the session for future use. On the first call, the
 * session destination address is copied from the client connection one.
 */
static inline int sess_get_dst(struct session *sess)
{
	struct connection *cli_conn = objt_conn(sess->origin);
	const struct sockaddr_storage *dst = NULL;

	if (sess->flags & SESS_FL_ADDR_TO_SET)
		return 1;

	if (cli_conn && conn_get_dst(cli_conn))
		dst = conn_dst(cli_conn);
	if (!dst)
		return 0;

	if (!sockaddr_alloc(&sess->dst, dst, sizeof(*dst)))
		return 0;

	sess->flags |= SESS_FL_ADDR_TO_SET;
	return 1;
}

#endif /* _HAPROXY_SESSION_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
