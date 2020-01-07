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

#include <common/config.h>
#include <common/buffer.h>
#include <common/debug.h>
#include <common/http.h>
#include <common/memory.h>

#include <types/global.h>
#include <types/session.h>

#include <proto/connection.h>
#include <proto/listener.h>
#include <proto/log.h>
#include <proto/proxy.h>
#include <proto/session.h>
#include <proto/stream.h>
#include <proto/tcp_rules.h>
#include <proto/vars.h>

DECLARE_POOL(pool_head_session, "session", sizeof(struct session));
DECLARE_POOL(pool_head_sess_srv_list, "session server list",
		sizeof(struct sess_srv_list));

static int conn_complete_session(struct connection *conn);
static struct task *session_expire_embryonic(struct task *t, void *context, unsigned short state);

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
		_HA_ATOMIC_ADD(&totalconn, 1);
		_HA_ATOMIC_ADD(&jobs, 1);
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
				if (!srv_add_to_idle_list(objt_server(conn->target), conn))
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
	_HA_ATOMIC_SUB(&jobs, 1);
}

/* callback used from the connection/mux layer to notify that a connection is
 * going to be released.
 */
void conn_session_free(struct connection *conn)
{
	session_free(conn->owner);
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
			stktable_data_cast(ptr, sess_cnt)++;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_SESS_RATE);
		if (ptr)
			update_freq_ctr_period(&stktable_data_cast(ptr, sess_rate),
					       stkctr->table->data_arg[STKTABLE_DT_SESS_RATE].u, 1);
	}
}

/* This function is called from the protocol layer accept() in order to
 * instantiate a new session on behalf of a given listener and frontend. It
 * returns a positive value upon success, 0 if the connection can be ignored,
 * or a negative value upon critical failure. The accepted file descriptor is
 * closed if we return <= 0. If no handshake is needed, it immediately tries
 * to instantiate a new stream. The created connection's owner points to the
 * new session until the upper layers are created.
 */
int session_accept_fd(struct listener *l, int cfd, struct sockaddr_storage *addr)
{
	struct connection *cli_conn;
	struct proxy *p = l->bind_conf->frontend;
	struct session *sess;
	int ret;


	ret = -1; /* assume unrecoverable error by default */

	if (unlikely((cli_conn = conn_new()) == NULL))
		goto out_close;

	if (!sockaddr_alloc(&cli_conn->src))
		goto out_free_conn;

	cli_conn->handle.fd = cfd;
	*cli_conn->src = *addr;
	cli_conn->flags |= CO_FL_ADDR_FROM_SET;
	cli_conn->target = &l->obj_type;
	cli_conn->proxy_netns = l->netns;

	conn_prepare(cli_conn, l->proto, l->bind_conf->xprt);
	conn_ctrl_init(cli_conn);

	/* wait for a PROXY protocol header */
	if (l->options & LI_O_ACC_PROXY)
		cli_conn->flags |= CO_FL_ACCEPT_PROXY;

	/* wait for a NetScaler client IP insertion protocol header */
	if (l->options & LI_O_ACC_CIP)
		cli_conn->flags |= CO_FL_ACCEPT_CIP;

	if (conn_xprt_init(cli_conn) < 0)
		goto out_free_conn;

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

	/* monitor-net and health mode are processed immediately after TCP
	 * connection rules. This way it's possible to block them, but they
	 * never use the lower data layers, they send directly over the socket,
	 * as they were designed for. We first flush the socket receive buffer
	 * in order to avoid emission of an RST by the system. We ignore any
	 * error.
	 */
	if (unlikely((p->mode == PR_MODE_HEALTH) ||
		     ((l->options & LI_O_CHK_MONNET) &&
		      addr->ss_family == AF_INET &&
		      (((struct sockaddr_in *)addr)->sin_addr.s_addr & p->mon_mask.s_addr) == p->mon_net.s_addr))) {
		/* we have 4 possibilities here :
		 *  - HTTP mode, from monitoring address => send "HTTP/1.0 200 OK"
		 *  - HEALTH mode with HTTP check => send "HTTP/1.0 200 OK"
		 *  - HEALTH mode without HTTP check => just send "OK"
		 *  - TCP mode from monitoring address => just close
		 */
		if (l->proto->drain)
			l->proto->drain(cfd);
		if (p->mode == PR_MODE_HTTP ||
		    (p->mode == PR_MODE_HEALTH && (p->options2 & PR_O2_CHK_ANY) == PR_O2_HTTP_CHK))
			send(cfd, "HTTP/1.0 200 OK\r\n\r\n", 19, MSG_DONTWAIT|MSG_NOSIGNAL|MSG_MORE);
		else if (p->mode == PR_MODE_HEALTH)
			send(cfd, "OK\n", 3, MSG_DONTWAIT|MSG_NOSIGNAL|MSG_MORE);
		ret = 0;
		goto out_free_sess;
	}

	/* Adjust some socket options */
	if (l->addr.ss_family == AF_INET || l->addr.ss_family == AF_INET6) {
		setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (char *) &one, sizeof(one));

		if (p->options & PR_O_TCP_CLI_KA)
			setsockopt(cfd, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(one));

		if (p->options & PR_O_TCP_NOLING)
			fdtab[cfd].linger_risk = 1;

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
	if (cli_conn->flags & (CO_FL_HANDSHAKE | CO_FL_EARLY_SSL_HS)) {
		if (unlikely((sess->task = task_new(tid_bit)) == NULL))
			goto out_free_sess;

		conn_set_xprt_done_cb(cli_conn, conn_complete_session);

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
	conn_stop_tracking(cli_conn);
	conn_xprt_close(cli_conn);
	conn_free(cli_conn);
 out_close:
	listener_release(l);
	if (ret < 0 && l->bind_conf->xprt == xprt_get(XPRT_RAW) &&
	    p->mode == PR_MODE_HTTP && l->bind_conf->mux_proto == NULL) {
		/* critical error, no more memory, try to emit a 500 response */
		send(cfd, http_err_msgs[HTTP_ERR_500], strlen(http_err_msgs[HTTP_ERR_500]),
		     MSG_DONTWAIT|MSG_NOSIGNAL);
	}

	if (fdtab[cfd].owner)
		fd_delete(cfd);
	else
		close(cfd);
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
static void session_kill_embryonic(struct session *sess, unsigned short state)
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
 * strikes and performs the required cleanup.
 */
static struct task *session_expire_embryonic(struct task *t, void *context, unsigned short state)
{
	struct session *sess = context;

	if (!(state & TASK_WOKEN_TIMER))
		return t;

	session_kill_embryonic(sess, state);
	return NULL;
}

/* Finish initializing a session from a connection, or kills it if the
 * connection shows and error. Returns <0 if the connection was killed. It may
 * be called either asynchronously as an xprt_done callback with an embryonic
 * session, or synchronously to finalize the session. The distinction is made
 * on sess->task which is only set in the embryonic session case.
 */
static int conn_complete_session(struct connection *conn)
{
	struct session *sess = conn->owner;

	sess->t_handshake = tv_ms_elapsed(&sess->tv_accept, &now);

	conn_clear_xprt_done_cb(conn);

	/* Verify if the connection just established. */
	if (unlikely(!(conn->flags & (CO_FL_WAIT_L4_CONN | CO_FL_WAIT_L6_CONN | CO_FL_CONNECTED))))
		conn->flags |= CO_FL_CONNECTED;

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
