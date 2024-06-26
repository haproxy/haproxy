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
extern struct pool_head *pool_head_sess_priv_conns;

struct session *session_new(struct proxy *fe, struct listener *li, enum obj_type *origin);
void session_free(struct session *sess);
void conn_session_free(struct connection *conn);
int session_accept_fd(struct connection *cli_conn);
int conn_complete_session(struct connection *conn);
struct task *session_expire_embryonic(struct task *t, void *context, unsigned int state);
void __session_add_glitch_ctr(struct session *sess, uint inc);
void session_embryonic_build_legacy_err(struct session *sess, struct buffer *out);


/* Remove the refcount from the session to the tracked counters, and clear the
 * pointer to ensure this is only performed once. The caller is responsible for
 * ensuring that the pointer is valid first.
 */
static inline void session_store_counters(struct session *sess)
{
	void *ptr;
	int i;
	struct stksess *ts;

	if (unlikely(!sess->stkctr)) // pool not allocated yet
		return;

	for (i = 0; i < global.tune.nb_stk_ctr; i++) {
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
		stksess_kill_if_expired(stkctr->table, ts);
	}
}

/* Increase the number of cumulated HTTP requests in the tracked counters */
static inline void session_inc_http_req_ctr(struct session *sess)
{
	int i;

	if (unlikely(!sess->stkctr)) // pool not allocated yet
		return;

	for (i = 0; i < global.tune.nb_stk_ctr; i++)
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

	if (unlikely(!sess->stkctr)) // pool not allocated yet
		return;

	for (i = 0; i < global.tune.nb_stk_ctr; i++)
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

	if (unlikely(!sess->stkctr)) // pool not allocated yet
		return;

	for (i = 0; i < global.tune.nb_stk_ctr; i++)
		stkctr_inc_http_fail_ctr(&sess->stkctr[i]);
}

/* Add <inc> to the number of cumulated glitches in the tracked counters, and
 * implicitly update the rate if also tracked.
 */
static inline void session_add_glitch_ctr(struct session *sess, uint inc)
{
	if (sess->stkctr && inc)
		__session_add_glitch_ctr(sess, inc);
}

/* Remove the connection from the session list, and destroy sess_priv_conns
 * element if it's now empty.
 */
static inline void session_unown_conn(struct session *sess, struct connection *conn)
{
	struct sess_priv_conns *pconns = NULL;

	BUG_ON(objt_listener(conn->target));

	/* WT: this currently is a workaround for an inconsistency between
	 * the link status of the connection in the session list and the
	 * connection's owner. This should be removed as soon as all this
	 * is addressed. Right now it's possible to enter here with a non-null
	 * conn->owner that points to a dead session, but in this case the
	 * element is not linked.
	 */
	if (!LIST_INLIST(&conn->sess_el))
		return;

	if (conn->flags & CO_FL_SESS_IDLE)
		sess->idle_conns--;
	LIST_DEL_INIT(&conn->sess_el);
	conn->owner = NULL;
	list_for_each_entry(pconns, &sess->priv_conns, sess_el) {
		if (pconns->target == conn->target) {
			if (LIST_ISEMPTY(&pconns->conn_list)) {
				LIST_DELETE(&pconns->sess_el);
				MT_LIST_DELETE(&pconns->srv_el);
				pool_free(pool_head_sess_priv_conns, pconns);
			}
			break;
		}
	}
}

/* Add the connection <conn> to the private conns list of session <sess>. This
 * function is called only if the connection is private. Nothing is performed
 * if the connection is already in the session list or if the session does not
 * owned the connection.
 */
static inline int session_add_conn(struct session *sess, struct connection *conn, void *target)
{
	struct sess_priv_conns *pconns = NULL;
	struct server *srv = objt_server(conn->target);
	int found = 0;

	BUG_ON(objt_listener(conn->target));

	/* Already attach to the session or not the connection owner */
	if (!LIST_ISEMPTY(&conn->sess_el) || (conn->owner && conn->owner != sess))
		return 1;

	list_for_each_entry(pconns, &sess->priv_conns, sess_el) {
		if (pconns->target == target) {
			found = 1;
			break;
		}
	}
	if (!found) {
		/* The session has no connection for the server, create a new entry */
		pconns = pool_alloc(pool_head_sess_priv_conns);
		if (!pconns)
			return 0;
		pconns->target = target;
		LIST_INIT(&pconns->conn_list);
		LIST_APPEND(&sess->priv_conns, &pconns->sess_el);

		MT_LIST_INIT(&pconns->srv_el);
		if (srv)
			MT_LIST_APPEND(&srv->sess_conns, &pconns->srv_el);

		pconns->tid = tid;
	}
	LIST_APPEND(&pconns->conn_list, &conn->sess_el);

	/* Ensure owner is set for connection. It could have been reset
	 * prior on after a session_add_conn() failure.
	 */
	conn->owner = sess;

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
	struct sess_priv_conns *pconns;

	list_for_each_entry(pconns, &sess->priv_conns, sess_el) {
		if (pconns->target == target) {
			list_for_each_entry(srv_conn, &pconns->conn_list, sess_el) {
				if ((srv_conn->hash_node && srv_conn->hash_node->node.key == hash) &&
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

	if (sess->src)
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

	if (sess->dst)
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

	if (sess->src)
		return 1;

	if (cli_conn && conn_get_src(cli_conn))
		src = conn_src(cli_conn);
	if (!src)
		return 0;

	if (!sockaddr_alloc(&sess->src, src, sizeof(*src)))
		return 0;

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

	if (sess->dst)
		return 1;

	if (cli_conn && conn_get_dst(cli_conn))
		dst = conn_dst(cli_conn);
	if (!dst)
		return 0;

	if (!sockaddr_alloc(&sess->dst, dst, sizeof(*dst)))
		return 0;

	return 1;
}

#endif /* _HAPROXY_SESSION_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
