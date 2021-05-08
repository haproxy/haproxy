/*
 * Session management functions.
 *
 * Copyright 2000-2015 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/global.h>
#include <haproxy/http.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/pool.h>
#include <haproxy/proxy.h>
#include <haproxy/session.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/tools.h>
#include <haproxy/vars.h>


DECLARE_POOL(pool_head_session, "session", sizeof(struct session));
DECLARE_POOL(pool_head_sess_srv_list, "session server list",
		sizeof(struct sess_srv_list));

int conn_complete_session(struct connection *conn);

/* Create a a new session and assign it to frontend <fe>, listener <li>,
 * origin <origin>, set the current date and clear the stick counters pointers.
 * Returns the session upon success or NULL. The session may be released using
 * session_free(). Note: <li> may be NULL.
 */
struct session *session_new(struct proxy *fe, struct listener *li, enum obj_type *origin)
{
	struct session *sess;

	sess = pool_alloc(pool_head_session);
	if (sess) {
		sess->listener = li;
		sess->fe = fe;
		sess->origin = origin;
		sess->accept_date = date; /* user-visible date for logging */
		sess->tv_accept   = now;  /* corrected date for internal use */
		memset(sess->stkctr, 0, sizeof(sess->stkctr));
		vars_init(&sess->vars, SCOPE_SESS);
		sess->task = NULL;
		sess->t_handshake = -1; /* handshake not done yet */
		sess->t_idle = -1;
		_HA_ATOMIC_INC(&totalconn);
		_HA_ATOMIC_INC(&jobs);
		LIST_INIT(&sess->srv_list);
		sess->idle_conns = 0;
		sess->flags = SESS_FL_NONE;
	}
	return sess;
}

void session_free(struct session *sess)
{
	struct connection *conn, *conn_back;
	struct sess_srv_list *srv_list, *srv_list_back;

	if (sess->listener)
		listener_release(sess->listener);
	session_store_counters(sess);
	vars_prune_per_sess(&sess->vars);
	conn = objt_conn(sess->origin);
	if (conn != NULL && conn->mux)
		conn->mux->destroy(conn->ctx);
	list_for_each_entry_safe(srv_list, srv_list_back, &sess->srv_list, srv_list) {
		list_for_each_entry_safe(conn, conn_back, &srv_list->conn_list, session_list) {
			LIST_DEL_INIT(&conn->session_list);
			if (conn->mux) {
				conn->owner = NULL;
				conn->flags &= ~CO_FL_SESS_IDLE;
				conn->mux->destroy(conn->ctx);
			} else {
				/* We have a connection, but not yet an associated mux.
				 * So destroy it now.
				 */
				conn_stop_tracking(conn);
				conn_full_close(conn);
				conn_free(conn);
			}
		}
		pool_free(pool_head_sess_srv_list, srv_list);
	}
	pool_free(pool_head_session, sess);
	_HA_ATOMIC_DEC(&jobs);
}

/* callback used from the connection/mux layer to notify that a connection is
 * going to be released.
 */
void conn_session_free(struct connection *conn)
{
	session_free(conn->owner);
	conn->owner = NULL;
}

/* count a new session to keep frontend, listener and track stats up to date */
static void session_count_new(struct session *sess)
{
	struct stkctr *stkctr;
	void *ptr;
	int i;

	proxy_inc_fe_sess_ctr(sess->listener, sess->fe);

	for (i = 0; i < MAX_SESS_STKCTR; i++) {
		stkctr = &sess->stkctr[i];
		if (!stkctr_entry(stkctr))
			continue;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_SESS_CNT);
		if (ptr)
			HA_ATOMIC_INC(&stktable_data_cast(ptr, sess_cnt));

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_SESS_RATE);
		if (ptr)
			update_freq_ctr_period(&stktable_data_cast(ptr, sess_rate),
					       stkctr->table->data_arg[STKTABLE_DT_SESS_RATE].u, 1);
	}
}

/* This function is called from the protocol layer accept() in order to
 * instantiate a new session on behalf of a given listener and frontend. It
 * returns a positive value upon success, 0 if the connection can be ignored,
 * or a negative value upon critical failure. The accepted connection is
 * closed if we return <= 0. If no handshake is needed, it immediately tries
 * to instantiate a new stream. The connection must already have been filled
 * with the incoming connection handle (a fd), a target (the listener) and a
 * source address.
 */
int session_accept_fd(struct connection *cli_conn)
{
	struct listener *l = __objt_listener(cli_conn->target);
	struct proxy *p = l->bind_conf->frontend;
	int cfd = cli_conn->handle.fd;
	struct session *sess;
	int ret;

	ret = -1; /* assume unrecoverable error by default */

	cli_conn->proxy_netns = l->rx.settings->netns;

	if (conn_prepare(cli_conn, l->rx.proto, l->bind_conf->xprt) < 0)
		goto out_free_conn;

	conn_ctrl_init(cli_conn);

	/* wait for a PROXY protocol header */
	if (l->options & LI_O_ACC_PROXY)
		cli_conn->flags |= CO_FL_ACCEPT_PROXY;

	/* wait for a NetScaler client IP insertion protocol header */
	if (l->options & LI_O_ACC_CIP)
		cli_conn->flags |= CO_FL_ACCEPT_CIP;

	/* Add the handshake pseudo-XPRT */
	if (cli_conn->flags & (CO_FL_ACCEPT_PROXY | CO_FL_ACCEPT_CIP)) {
		if (xprt_add_hs(cli_conn) != 0)
			goto out_free_conn;
	}
	sess = session_new(p, l, &cli_conn->obj_type);
	if (!sess)
		goto out_free_conn;

	conn_set_owner(cli_conn, sess, NULL);

	/* now evaluate the tcp-request layer4 rules. We only need a session
	 * and no stream for these rules.
	 */
	if ((l->options & LI_O_TCP_L4_RULES) && !tcp_exec_l4_rules(sess)) {
		/* let's do a no-linger now to close with a single RST. */
		setsockopt(cfd, SOL_SOCKET, SO_LINGER, (struct linger *) &nolinger, sizeof(struct linger));
		ret = 0; /* successful termination */
		goto out_free_sess;
	}
	/* TCP rules may flag the connection as needing proxy protocol, now that it's done we can start ourxprt */
	if (conn_xprt_start(cli_conn) < 0)
		goto out_free_conn;

	/* Adjust some socket options */
	if (l->rx.addr.ss_family == AF_INET || l->rx.addr.ss_family == AF_INET6) {
		setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (char *) &one, sizeof(one));

		if (p->options & PR_O_TCP_CLI_KA) {
			setsockopt(cfd, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(one));

#ifdef TCP_KEEPCNT
			if (p->clitcpka_cnt)
				setsockopt(cfd, IPPROTO_TCP, TCP_KEEPCNT, &p->clitcpka_cnt, sizeof(p->clitcpka_cnt));
#endif

#ifdef TCP_KEEPIDLE
			if (p->clitcpka_idle)
				setsockopt(cfd, IPPROTO_TCP, TCP_KEEPIDLE, &p->clitcpka_idle, sizeof(p->clitcpka_idle));
#endif

#ifdef TCP_KEEPINTVL
			if (p->clitcpka_intvl)
				setsockopt(cfd, IPPROTO_TCP, TCP_KEEPINTVL, &p->clitcpka_intvl, sizeof(p->clitcpka_intvl));
#endif
		}

		if (p->options & PR_O_TCP_NOLING)
			HA_ATOMIC_OR(&fdtab[cfd].state, FD_LINGER_RISK);

#if defined(TCP_MAXSEG)
		if (l->maxseg < 0) {
			/* we just want to reduce the current MSS by that value */
			int mss;
			socklen_t mss_len = sizeof(mss);
			if (getsockopt(cfd, IPPROTO_TCP, TCP_MAXSEG, &mss, &mss_len) == 0) {
				mss += l->maxseg; /* remember, it's < 0 */
				setsockopt(cfd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));
			}
		}
#endif
	}

	if (global.tune.client_sndbuf)
		setsockopt(cfd, SOL_SOCKET, SO_SNDBUF, &global.tune.client_sndbuf, sizeof(global.tune.client_sndbuf));

	if (global.tune.client_rcvbuf)
		setsockopt(cfd, SOL_SOCKET, SO_RCVBUF, &global.tune.client_rcvbuf, sizeof(global.tune.client_rcvbuf));

	/* OK, now either we have a pending handshake to execute with and then
	 * we must return to the I/O layer, or we can proceed with the end of
	 * the stream initialization. In case of handshake, we also set the I/O
	 * timeout to the frontend's client timeout and register a task in the
	 * session for this purpose. The connection's owner is left to the
	 * session during this period.
	 *
	 * At this point we set the relation between sess/task/conn this way :
	 *
	 *                   +----------------- task
	 *                   |                    |
	 *          orig -- sess <-- context      |
	 *           |       ^           |        |
	 *           v       |           |        |
	 *          conn -- owner ---> task <-----+
	 */
	if (cli_conn->flags & (CO_FL_WAIT_XPRT | CO_FL_EARLY_SSL_HS)) {
		if (unlikely((sess->task = task_new(tid_bit)) == NULL))
			goto out_free_sess;

		sess->task->context = sess;
		sess->task->nice    = l->nice;
		sess->task->process = session_expire_embryonic;
		sess->task->expire  = tick_add_ifset(now_ms, p->timeout.client);
		task_queue(sess->task);
		return 1;
	}

	/* OK let's complete stream initialization since there is no handshake */
	if (conn_complete_session(cli_conn) >= 0)
		return 1;

	/* if we reach here we have deliberately decided not to keep this
	 * session (e.g. tcp-request rule), so that's not an error we should
	 * try to protect against.
	 */
	ret = 0;

	/* error unrolling */
 out_free_sess:
	 /* prevent call to listener_release during session_free. It will be
	  * done below, for all errors. */
	sess->listener = NULL;
	session_free(sess);

 out_free_conn:
	if (ret < 0 && l->bind_conf->xprt == xprt_get(XPRT_RAW) &&
	    p->mode == PR_MODE_HTTP && l->bind_conf->mux_proto == NULL) {
		/* critical error, no more memory, try to emit a 500 response */
		send(cfd, http_err_msgs[HTTP_ERR_500], strlen(http_err_msgs[HTTP_ERR_500]),
		     MSG_DONTWAIT|MSG_NOSIGNAL);
	}

	conn_stop_tracking(cli_conn);
	conn_full_close(cli_conn);
	conn_free(cli_conn);
	listener_release(l);
	return ret;
}


/* prepare the trash with a log prefix for session <sess>. It only works with
 * embryonic sessions based on a real connection. This function requires that
 * at sess->origin points to the incoming connection.
 */
static void session_prepare_log_prefix(struct session *sess)
{
	struct tm tm;
	char pn[INET6_ADDRSTRLEN];
	int ret;
	char *end;
	struct connection *cli_conn = __objt_conn(sess->origin);

	ret = conn_get_src(cli_conn) ? addr_to_str(cli_conn->src, pn, sizeof(pn)) : 0;
	if (ret <= 0)
		chunk_printf(&trash, "unknown [");
	else if (ret == AF_UNIX)
		chunk_printf(&trash, "%s:%d [", pn, sess->listener->luid);
	else
		chunk_printf(&trash, "%s:%d [", pn, get_host_port(cli_conn->src));

	get_localtime(sess->accept_date.tv_sec, &tm);
	end = date2str_log(trash.area + trash.data, &tm, &(sess->accept_date),
		           trash.size - trash.data);
	trash.data = end - trash.area;
	if (sess->listener->name)
		chunk_appendf(&trash, "] %s/%s", sess->fe->id, sess->listener->name);
	else
		chunk_appendf(&trash, "] %s/%d", sess->fe->id, sess->listener->luid);
}

/* This function kills an existing embryonic session. It stops the connection's
 * transport layer, releases assigned resources, resumes the listener if it was
 * disabled and finally kills the file descriptor. This function requires that
 * sess->origin points to the incoming connection.
 */
static void session_kill_embryonic(struct session *sess, unsigned int state)
{
	int level = LOG_INFO;
	struct connection *conn = __objt_conn(sess->origin);
	struct task *task = sess->task;
	unsigned int log = sess->fe->to_log;
	const char *err_msg;

	if (sess->fe->options2 & PR_O2_LOGERRORS)
		level = LOG_ERR;

	if (log && (sess->fe->options & PR_O_NULLNOLOG)) {
		/* with "option dontlognull", we don't log connections with no transfer */
		if (!conn->err_code ||
		    conn->err_code == CO_ER_PRX_EMPTY || conn->err_code == CO_ER_PRX_ABORT ||
		    conn->err_code == CO_ER_CIP_EMPTY || conn->err_code == CO_ER_CIP_ABORT ||
		    conn->err_code == CO_ER_SSL_EMPTY || conn->err_code == CO_ER_SSL_ABORT)
			log = 0;
	}

	if (log) {
		if (!conn->err_code && (state & TASK_WOKEN_TIMER)) {
			if (conn->flags & CO_FL_ACCEPT_PROXY)
				conn->err_code = CO_ER_PRX_TIMEOUT;
			else if (conn->flags & CO_FL_ACCEPT_CIP)
				conn->err_code = CO_ER_CIP_TIMEOUT;
			else if (conn->flags & CO_FL_SSL_WAIT_HS)
				conn->err_code = CO_ER_SSL_TIMEOUT;
		}

		session_prepare_log_prefix(sess);
		err_msg = conn_err_code_str(conn);
		if (err_msg)
			send_log(sess->fe, level, "%s: %s\n", trash.area,
				 err_msg);
		else
			send_log(sess->fe, level, "%s: unknown connection error (code=%d flags=%08x)\n",
				 trash.area, conn->err_code, conn->flags);
	}

	/* kill the connection now */
	conn_stop_tracking(conn);
	conn_full_close(conn);
	conn_free(conn);
	sess->origin = NULL;

	task_destroy(task);
	session_free(sess);
}

/* Manages the embryonic session timeout. It is only called when the timeout
 * strikes and performs the required cleanup. It's only exported to make it
 * resolve in "show tasks".
 */
struct task *session_expire_embryonic(struct task *t, void *context, unsigned int state)
{
	struct session *sess = context;

	if (!(state & TASK_WOKEN_TIMER))
		return t;

	session_kill_embryonic(sess, state);
	return NULL;
}

/* Finish initializing a session from a connection, or kills it if the
 * connection shows and error. Returns <0 if the connection was killed. It may
 * be called either asynchronously when ssl handshake is done with an embryonic
 * session, or synchronously to finalize the session. The distinction is made
 * on sess->task which is only set in the embryonic session case.
 */
int conn_complete_session(struct connection *conn)
{
	struct session *sess = conn->owner;

	sess->t_handshake = tv_ms_elapsed(&sess->tv_accept, &now);

	if (conn->flags & CO_FL_ERROR)
		goto fail;

	/* if logs require transport layer information, note it on the connection */
	if (sess->fe->to_log & LW_XPRT)
		conn->flags |= CO_FL_XPRT_TRACKED;

	/* we may have some tcp-request-session rules */
	if ((sess->listener->options & LI_O_TCP_L5_RULES) && !tcp_exec_l5_rules(sess))
		goto fail;

	session_count_new(sess);
	if (conn_install_mux_fe(conn, NULL) < 0)
		goto fail;

	/* the embryonic session's task is not needed anymore */
	task_destroy(sess->task);
	sess->task = NULL;
	conn_set_owner(conn, sess, conn_session_free);

	return 0;

 fail:
	if (sess->task)
		session_kill_embryonic(sess, 0);
	return -1;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
