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

int session_add_conn(struct session *sess, struct connection *conn);
int session_reinsert_idle_conn(struct session *sess, struct connection *conn);
int session_check_idle_conn(struct session *sess, struct connection *conn);
struct connection *session_get_conn(struct session *sess, void *target, int64_t hash);
void session_unown_conn(struct session *sess, struct connection *conn);
int session_detach_idle_conn(struct session *sess, struct connection *conn);
int sess_conns_cleanup_all_idle(struct sess_priv_conns *sess_conns);

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
