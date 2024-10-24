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

#include <haproxy/ssl_sock-t.h>

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/global.h>
#include <haproxy/http.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/pool.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/session.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/tools.h>
#include <haproxy/trace.h>
#include <haproxy/vars.h>


DECLARE_POOL(pool_head_session, "session", sizeof(struct session));
DECLARE_POOL(pool_head_sess_priv_conns, "session priv conns list",
             sizeof(struct sess_priv_conns));

int conn_complete_session(struct connection *conn);

static const struct trace_event sess_trace_events[] = {
#define           SESS_EV_NEW       (1ULL <<  0)
	{ .mask = SESS_EV_NEW,      .name = "sess_new",     .desc = "new session creation" },
#define           SESS_EV_END       (1ULL <<  1)
	{ .mask = SESS_EV_END,      .name = "sess_end",     .desc = "session termination" },
#define           SESS_EV_ERR       (1ULL <<  1)
	{ .mask = SESS_EV_ERR,      .name = "sess_err",     .desc = "session error" },
	{ }
};

static const struct name_desc sess_trace_lockon_args[4] = {
	/* arg1 */ { /* already used by the session */ },
	/* arg2 */ { },
	/* arg3 */ { },
	/* arg4 */ { }
};

static struct trace_source trace_sess __read_mostly = {
	.name = IST("session"),
	.desc = "client session management",
	.arg_def = TRC_ARG1_SESS,  // TRACE()'s first argument is always a session
	.known_events = sess_trace_events,
	.lockon_args = sess_trace_lockon_args,
	.report_events = ~0,  // report everything by default
};

#define TRACE_SOURCE &trace_sess
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

/* Create a a new session and assign it to frontend <fe>, listener <li>,
 * origin <origin>, set the current date and clear the stick counters pointers.
 * Returns the session upon success or NULL. The session may be released using
 * session_free(). Note: <li> may be NULL.
 */
struct session *session_new(struct proxy *fe, struct listener *li, enum obj_type *origin)
{
	struct session *sess;

	TRACE_ENTER(SESS_EV_NEW);

	sess = pool_alloc(pool_head_session);
	if (sess) {
		sess->listener = li;
		sess->fe = fe;
		sess->origin = origin;
		sess->accept_date = date; /* user-visible date for logging */
		sess->accept_ts = now_ns;  /* corrected date for internal use */
		sess->stkctr = NULL;
		if (pool_head_stk_ctr) {
			sess->stkctr = pool_alloc(pool_head_stk_ctr);
			if (!sess->stkctr)
				goto out_fail_alloc;
			memset(sess->stkctr, 0, sizeof(sess->stkctr[0]) * global.tune.nb_stk_ctr);
		}
		vars_init_head(&sess->vars, SCOPE_SESS);
		sess->task = NULL;
		sess->t_handshake = -1; /* handshake not done yet */
		sess->t_idle = -1;
		_HA_ATOMIC_INC(&totalconn);
		_HA_ATOMIC_INC(&jobs);
		LIST_INIT(&sess->priv_conns);
		sess->idle_conns = 0;
		sess->flags = SESS_FL_NONE;
		sess->src = NULL;
		sess->dst = NULL;
		TRACE_STATE("new session", SESS_EV_NEW, sess);
	}
	TRACE_LEAVE(SESS_EV_NEW);
	return sess;
 out_fail_alloc:
	pool_free(pool_head_session, sess);
	TRACE_DEVEL("leaving in error", SESS_EV_NEW|SESS_EV_END|SESS_EV_ERR);
	return NULL;
}

void session_free(struct session *sess)
{
	struct connection *conn, *conn_back;
	struct sess_priv_conns *pconns, *pconns_back;

	TRACE_ENTER(SESS_EV_END);
	TRACE_STATE("releasing session", SESS_EV_END, sess);

	if (sess->flags & SESS_FL_RELEASE_LI) {
		/* listener must be set for session used to account FE conns. */
		BUG_ON(!sess->listener);
		listener_release(sess->listener);
	}

	session_store_counters(sess);
	pool_free(pool_head_stk_ctr, sess->stkctr);
	vars_prune_per_sess(&sess->vars);
	conn = objt_conn(sess->origin);
	if (conn != NULL && conn->mux)
		conn->mux->destroy(conn->ctx);
	list_for_each_entry_safe(pconns, pconns_back, &sess->priv_conns, sess_el) {
		list_for_each_entry_safe(conn, conn_back, &pconns->conn_list, sess_el) {
			LIST_DEL_INIT(&conn->sess_el);
			conn->owner = NULL;
			conn->flags &= ~CO_FL_SESS_IDLE;
			conn_release(conn);
		}
		MT_LIST_DELETE(&pconns->srv_el);
		pool_free(pool_head_sess_priv_conns, pconns);
	}
	sockaddr_free(&sess->src);
	sockaddr_free(&sess->dst);
	pool_free(pool_head_session, sess);
	_HA_ATOMIC_DEC(&jobs);

	TRACE_LEAVE(SESS_EV_END);
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

	for (i = 0; i < global.tune.nb_stk_ctr; i++) {
		stkctr = &sess->stkctr[i];
		if (!stkctr_entry(stkctr))
			continue;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_SESS_CNT);
		if (ptr)
			HA_ATOMIC_INC(&stktable_data_cast(ptr, std_t_uint));

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_SESS_RATE);
		if (ptr)
			update_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
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

	/* Active reversed connection has already been initialized before being
	 * accepted. It must not be reset.
	 * TODO use a dedicated accept_fd callback for reverse protocol
	 */
	if (!cli_conn->xprt) {
		if (conn_prepare(cli_conn, l->rx.proto, l->bind_conf->xprt) < 0)
			goto out_free_conn;

		conn_ctrl_init(cli_conn);

		/* wait for a PROXY protocol header */
		if (l->bind_conf->options & BC_O_ACC_PROXY)
			cli_conn->flags |= CO_FL_ACCEPT_PROXY;

		/* wait for a NetScaler client IP insertion protocol header */
		if (l->bind_conf->options & BC_O_ACC_CIP)
			cli_conn->flags |= CO_FL_ACCEPT_CIP;

		/* Add the handshake pseudo-XPRT */
		if (cli_conn->flags & (CO_FL_ACCEPT_PROXY | CO_FL_ACCEPT_CIP)) {
			if (xprt_add_hs(cli_conn) != 0)
				goto out_free_conn;
		}
	}

	/* Reversed conns already have an assigned session, do not recreate it. */
	if (!(cli_conn->flags & CO_FL_REVERSED)) {
		sess = session_new(p, l, &cli_conn->obj_type);
		if (!sess)
			goto out_free_conn;

		conn_set_owner(cli_conn, sess, NULL);
	}
	else {
		sess = cli_conn->owner;
	}

	/* now evaluate the tcp-request layer4 rules. We only need a session
	 * and no stream for these rules.
	 */
	if (((sess->fe->defpx && !LIST_ISEMPTY(&sess->fe->defpx->tcp_req.l4_rules)) ||
	     !LIST_ISEMPTY(&p->tcp_req.l4_rules)) && !tcp_exec_l4_rules(sess)) {
		/* let's do a no-linger now to close with a single RST. */
		if (!(cli_conn->flags & CO_FL_FDLESS))
			setsockopt(cfd, SOL_SOCKET, SO_LINGER, (struct linger *) &nolinger, sizeof(struct linger));
		ret = 0; /* successful termination */
		goto out_free_sess;
	}
	/* TCP rules may flag the connection as needing proxy protocol, now that it's done we can start ourxprt */
	if (conn_xprt_start(cli_conn) < 0)
		goto out_free_sess;

	/* FIXME/WTA: we should implement the setsockopt() calls at the proto
	 * level instead and let non-inet protocols implement their own equivalent.
	 */
	if (cli_conn->flags & CO_FL_FDLESS)
		goto skip_fd_setup;

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
		if (l->bind_conf->maxseg < 0) {
			/* we just want to reduce the current MSS by that value */
			int mss;
			socklen_t mss_len = sizeof(mss);
			if (getsockopt(cfd, IPPROTO_TCP, TCP_MAXSEG, &mss, &mss_len) == 0) {
				mss += l->bind_conf->maxseg; /* remember, it's < 0 */
				setsockopt(cfd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));
			}
		}
#endif
	}

	if (global.tune.client_sndbuf)
		setsockopt(cfd, SOL_SOCKET, SO_SNDBUF, &global.tune.client_sndbuf, sizeof(global.tune.client_sndbuf));

	if (global.tune.client_rcvbuf)
		setsockopt(cfd, SOL_SOCKET, SO_RCVBUF, &global.tune.client_rcvbuf, sizeof(global.tune.client_rcvbuf));

 skip_fd_setup:
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
		int timeout;
		int clt_tmt = p->timeout.client;
		int hs_tmt = p->timeout.client_hs;

		if (unlikely((sess->task = task_new_here()) == NULL))
			goto out_free_sess;

		/* Handshake timeout as default timeout */
		timeout = hs_tmt ? hs_tmt : clt_tmt;
		sess->task->context = sess;
		sess->task->nice    = l->bind_conf->nice;
		sess->task->process = session_expire_embryonic;
		sess->task->expire  = tick_add_ifset(now_ms, timeout);
		task_queue(sess->task);

		/* Session is responsible to decrement listener conns counters. */
		sess->flags |= SESS_FL_RELEASE_LI;

		return 1;
	}

	/* OK let's complete stream initialization since there is no handshake */
	if (conn_complete_session(cli_conn) >= 0) {
		/* Session is responsible to decrement listener conns counters. */
		sess->flags |= SESS_FL_RELEASE_LI;
		return 1;
	}

	/* if we reach here we have deliberately decided not to keep this
	 * session (e.g. tcp-request rule), so that's not an error we should
	 * try to protect against.
	 */
	ret = 0;

	/* error unrolling */
 out_free_sess:
	/* SESS_FL_RELEASE_LI must not be set here as listener_release() is
	 * called manually for all errors.
	 */
	session_free(sess);

 out_free_conn:
	if (ret < 0 && l->bind_conf->xprt == xprt_get(XPRT_RAW) &&
	    p->mode == PR_MODE_HTTP && l->bind_conf->mux_proto == NULL &&
	    !(cli_conn->flags & CO_FL_FDLESS)) {
		/* critical error, no more memory, try to emit a 500 response */
		send(cfd, http_err_msgs[HTTP_ERR_500], strlen(http_err_msgs[HTTP_ERR_500]),
		     MSG_DONTWAIT|MSG_NOSIGNAL);
	}

	/* Mux is already initialized for active reversed connection. */
	conn_release(cli_conn);
	listener_release(l);
	return ret;
}


/* prepare <out> buffer with a log prefix for session <sess>. It only works with
 * embryonic sessions based on a real connection. This function requires that
 * at sess->origin points to the incoming connection.
 */
static void session_prepare_log_prefix(struct session *sess, struct buffer *out)
{
	const struct sockaddr_storage *src;
	struct tm tm;
	char pn[INET6_ADDRSTRLEN];
	int ret;
	char *end;

	src = sess_src(sess);
	ret = (src ? addr_to_str(src, pn, sizeof(pn)) : 0);
	if (ret <= 0)
		chunk_printf(out, "unknown [");
	else if (real_family(ret) == AF_UNIX)
		chunk_printf(out, "%s:%d [", pn, sess->listener->luid);
	else
		chunk_printf(out, "%s:%d [", pn, get_host_port(src));

	get_localtime(sess->accept_date.tv_sec, &tm);
	end = date2str_log(out->area + out->data, &tm, &(sess->accept_date),
		           out->size - out->data);
	out->data = end - out->area;
	if (sess->listener->name)
		chunk_appendf(out, "] %s/%s", sess->fe->id, sess->listener->name);
	else
		chunk_appendf(out, "] %s/%d", sess->fe->id, sess->listener->luid);
}


/* fill <out> buffer with the string to use for send_log during
 * session_kill_embryonic(). Add log prefix and error string.
 *
 * It expects that the session originates from a connection.
 *
 * The function is able to dump an SSL error string when CO_ER_SSL_HANDSHAKE
 * is met.
 */
void session_embryonic_build_legacy_err(struct session *sess, struct buffer *out)
{
	struct connection *conn = objt_conn(sess->origin);
	const char *err_msg;
	struct ssl_sock_ctx __maybe_unused *ssl_ctx;

	BUG_ON(!conn);

	err_msg	= conn_err_code_str(conn);
	session_prepare_log_prefix(sess, out);

#ifdef USE_OPENSSL
	ssl_ctx = conn_get_ssl_sock_ctx(conn);

	/* when the SSL error code is present and during a SSL Handshake failure,
	 * try to dump the error string from OpenSSL */
	if (conn->err_code == CO_ER_SSL_HANDSHAKE && ssl_ctx && ssl_ctx->error_code != 0) {
		chunk_appendf(out, ": SSL handshake failure (");
		ERR_error_string_n(ssl_ctx->error_code, b_orig(out)+b_data(out), b_room(out));
		out->data = strlen(b_orig(out));
		chunk_appendf(out, ")\n");
	}

	else
#endif /* ! USE_OPENSSL */

	if (err_msg)
		chunk_appendf(out, ": %s\n", err_msg);
	else
		chunk_appendf(out, ": unknown connection error (code=%d flags=%08x)\n",
		              conn->err_code, conn->flags);

	return;
}



/* This function kills an existing embryonic session. It stops the connection's
 * transport layer, releases assigned resources, resumes the listener if it was
 * disabled and finally kills the file descriptor. This function requires that
 * sess->origin points to the incoming connection.
 */
static void session_kill_embryonic(struct session *sess, unsigned int state)
{
	struct connection *conn = __objt_conn(sess->origin);
	struct task *task = sess->task;
	unsigned int log = sess->fe->to_log;

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

		sess_log_embryonic(sess);
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

	sess->t_handshake = ns_to_ms(now_ns - sess->accept_ts);

	if (conn->flags & CO_FL_ERROR)
		goto fail;

	/* if logs require transport layer information, note it on the connection */
	if (sess->fe->to_log & LW_XPRT)
		conn->flags |= CO_FL_XPRT_TRACKED;

	/* we may have some tcp-request-session rules */
	if (((sess->fe->defpx && !LIST_ISEMPTY(&sess->fe->defpx->tcp_req.l5_rules)) ||
	     !LIST_ISEMPTY(&sess->fe->tcp_req.l5_rules)) && !tcp_exec_l5_rules(sess))
		goto fail;

	session_count_new(sess);
	if (!conn->mux) {
		if (conn_install_mux_fe(conn, NULL) < 0)
			goto fail;
	}

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

/* Add <inc> to the number of cumulated glitches in the tracked counters for
 * session <sess> which is known for being tracked, and implicitly update the
 * rate if also tracked.
 */
void __session_add_glitch_ctr(struct session *sess, uint inc)
{
	int i;

	for (i = 0; i < global.tune.nb_stk_ctr; i++)
		stkctr_add_glitch_ctr(&sess->stkctr[i], inc);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
