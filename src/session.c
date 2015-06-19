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
#include <common/memory.h>

#include <types/global.h>
#include <types/session.h>

#include <proto/connection.h>
#include <proto/listener.h>
#include <proto/log.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/proxy.h>
#include <proto/raw_sock.h>
#include <proto/session.h>
#include <proto/stream.h>
#include <proto/vars.h>

struct pool_head *pool2_session;

static int conn_complete_session(struct connection *conn);
static int conn_update_session(struct connection *conn);
static struct task *session_expire_embryonic(struct task *t);

/* data layer callbacks for an embryonic stream */
struct data_cb sess_conn_cb = {
	.recv = NULL,
	.send = NULL,
	.wake = conn_update_session,
	.init = conn_complete_session,
};

/* Create a a new session and assign it to frontend <fe>, listener <li>,
 * origin <origin>, set the current date and clear the stick counters pointers.
 * Returns the session upon success or NULL. The session may be released using
 * session_free().
 */
struct session *session_new(struct proxy *fe, struct listener *li, enum obj_type *origin)
{
	struct session *sess;

	sess = pool_alloc2(pool2_session);
	if (sess) {
		sess->listener = li;
		sess->fe = fe;
		sess->origin = origin;
		sess->accept_date = date; /* user-visible date for logging */
		sess->tv_accept   = now;  /* corrected date for internal use */
		memset(sess->stkctr, 0, sizeof(sess->stkctr));
		vars_init(&sess->vars, SCOPE_SESS);
	}
	return sess;
}

void session_free(struct session *sess)
{
	session_store_counters(sess);
	vars_prune_per_sess(&sess->vars);
	pool_free2(pool2_session, sess);
}

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_session()
{
	pool2_session = create_pool("session", sizeof(struct session), MEM_F_SHARED);
	return pool2_session != NULL;
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
 * instanciate a new session on behalf of a given listener and frontend. It
 * returns a positive value upon success, 0 if the connection can be ignored,
 * or a negative value upon critical failure. The accepted file descriptor is
 * closed if we return <= 0. If no handshake is needed, it immediately tries
 * to instanciate a new stream.
 */
int session_accept_fd(struct listener *l, int cfd, struct sockaddr_storage *addr)
{
	struct connection *cli_conn;
	struct proxy *p = l->frontend;
	struct session *sess;
	struct stream *strm;
	struct task *t;
	int ret;


	ret = -1; /* assume unrecoverable error by default */

	if (unlikely((cli_conn = conn_new()) == NULL))
		goto out_close;

	conn_prepare(cli_conn, l->proto, l->xprt);

	cli_conn->t.sock.fd = cfd;
	cli_conn->addr.from = *addr;
	cli_conn->flags |= CO_FL_ADDR_FROM_SET;
	cli_conn->target = &l->obj_type;
	cli_conn->proxy_netns = l->netns;

	conn_ctrl_init(cli_conn);

	/* wait for a PROXY protocol header */
	if (l->options & LI_O_ACC_PROXY) {
		cli_conn->flags |= CO_FL_ACCEPT_PROXY;
		conn_sock_want_recv(cli_conn);
	}

	conn_data_want_recv(cli_conn);
	if (conn_xprt_init(cli_conn) < 0)
		goto out_free_conn;

	sess = session_new(p, l, &cli_conn->obj_type);
	if (!sess)
		goto out_free_conn;

	p->feconn++;
	/* This session was accepted, count it now */
	if (p->feconn > p->fe_counters.conn_max)
		p->fe_counters.conn_max = p->feconn;

	proxy_inc_fe_conn_ctr(l, p);

	/* now evaluate the tcp-request layer4 rules. We only need a session
	 * and no stream for these rules.
	 */
	if ((l->options & LI_O_TCP_RULES) && !tcp_exec_req_rules(sess)) {
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

	if (unlikely((t = task_new()) == NULL))
		goto out_free_sess;

	t->context = sess;
	t->nice = l->nice;

	/* OK, now either we have a pending handshake to execute with and
	 * then we must return to the I/O layer, or we can proceed with the
	 * end of the stream initialization. In case of handshake, we also
	 * set the I/O timeout to the frontend's client timeout.
	 *
	 * At this point we set the relation between sess/task/conn this way :
	 *
	 *          orig -- sess <-- context
	 *           |                   |
	 *           v                   |
	 *          conn -- owner ---> task
	 */
	if (cli_conn->flags & CO_FL_HANDSHAKE) {
		conn_attach(cli_conn, t, &sess_conn_cb);
		t->process = session_expire_embryonic;
		t->expire = tick_add_ifset(now_ms, p->timeout.client);
		task_queue(t);
		cli_conn->flags |= CO_FL_INIT_DATA | CO_FL_WAKE_DATA;
		return 1;
	}

	/* OK let's complete stream initialization since there is no handshake */
	cli_conn->flags |= CO_FL_CONNECTED;

	/* we want the connection handler to notify the stream interface about updates. */
	cli_conn->flags |= CO_FL_WAKE_DATA;

	/* if logs require transport layer information, note it on the connection */
	if (sess->fe->to_log & LW_XPRT)
		cli_conn->flags |= CO_FL_XPRT_TRACKED;

	session_count_new(sess);
	strm = stream_new(sess, t, &cli_conn->obj_type);
	if (!strm)
		goto out_free_task;

	strm->target        = sess->listener->default_target;
	strm->req.analysers = sess->listener->analysers;
	return 1;

 out_free_task:
	task_free(t);
 out_free_sess:
	p->feconn--;
	session_free(sess);
 out_free_conn:
	cli_conn->flags &= ~CO_FL_XPRT_TRACKED;
	conn_xprt_close(cli_conn);
	conn_free(cli_conn);
 out_close:
	if (ret < 0 && l->xprt == &raw_sock && p->mode == PR_MODE_HTTP) {
		/* critical error, no more memory, try to emit a 500 response */
		struct chunk *err_msg = &p->errmsg[HTTP_ERR_500];
		if (!err_msg->str)
			err_msg = &http_err_chunks[HTTP_ERR_500];
		send(cfd, err_msg->str, err_msg->len, MSG_DONTWAIT|MSG_NOSIGNAL);
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

	ret = addr_to_str(&cli_conn->addr.from, pn, sizeof(pn));
	if (ret <= 0)
		chunk_printf(&trash, "unknown [");
	else if (ret == AF_UNIX)
		chunk_printf(&trash, "%s:%d [", pn, sess->listener->luid);
	else
		chunk_printf(&trash, "%s:%d [", pn, get_host_port(&cli_conn->addr.from));

	get_localtime(sess->accept_date.tv_sec, &tm);
	end = date2str_log(trash.str + trash.len, &tm, &(sess->accept_date), trash.size - trash.len);
	trash.len = end - trash.str;
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
static void session_kill_embryonic(struct session *sess)
{
	int level = LOG_INFO;
	struct connection *conn = __objt_conn(sess->origin);
	struct task *task = conn->owner;
	unsigned int log = sess->fe->to_log;
	const char *err_msg;

	if (sess->fe->options2 & PR_O2_LOGERRORS)
		level = LOG_ERR;

	if (log && (sess->fe->options & PR_O_NULLNOLOG)) {
		/* with "option dontlognull", we don't log connections with no transfer */
		if (!conn->err_code ||
		    conn->err_code == CO_ER_PRX_EMPTY || conn->err_code == CO_ER_PRX_ABORT ||
		    conn->err_code == CO_ER_SSL_EMPTY || conn->err_code == CO_ER_SSL_ABORT)
			log = 0;
	}

	if (log) {
		if (!conn->err_code && (task->state & TASK_WOKEN_TIMER)) {
			if (conn->flags & CO_FL_ACCEPT_PROXY)
				conn->err_code = CO_ER_PRX_TIMEOUT;
			else if (conn->flags & CO_FL_SSL_WAIT_HS)
				conn->err_code = CO_ER_SSL_TIMEOUT;
		}

		session_prepare_log_prefix(sess);
		err_msg = conn_err_code_str(conn);
		if (err_msg)
			send_log(sess->fe, level, "%s: %s\n", trash.str, err_msg);
		else
			send_log(sess->fe, level, "%s: unknown connection error (code=%d flags=%08x)\n",
				 trash.str, conn->err_code, conn->flags);
	}

	/* kill the connection now */
	conn_force_close(conn);
	conn_free(conn);

	sess->fe->feconn--;

	if (!(sess->listener->options & LI_O_UNLIMITED))
		actconn--;
	jobs--;
	sess->listener->nbconn--;
	if (sess->listener->state == LI_FULL)
		resume_listener(sess->listener);

	/* Dequeues all of the listeners waiting for a resource */
	if (!LIST_ISEMPTY(&global_listener_queue))
		dequeue_all_listeners(&global_listener_queue);

	if (!LIST_ISEMPTY(&sess->fe->listener_queue) &&
	    (!sess->fe->fe_sps_lim || freq_ctr_remain(&sess->fe->fe_sess_per_sec, sess->fe->fe_sps_lim, 0) > 0))
		dequeue_all_listeners(&sess->fe->listener_queue);

	task_delete(task);
	task_free(task);
	session_free(sess);
}

/* Manages the embryonic session timeout. It is only called when the timeout
 * strikes and performs the required cleanup.
 */
static struct task *session_expire_embryonic(struct task *t)
{
	struct session *sess = t->context;

	if (!(t->state & TASK_WOKEN_TIMER))
		return t;

	session_kill_embryonic(sess);
	return NULL;
}

/* Finish initializing a session from a connection, or kills it if the
 * connection shows and error. Returns <0 if the connection was killed.
 */
static int conn_complete_session(struct connection *conn)
{
	struct task *task = conn->owner;
	struct session *sess = task->context;
	struct stream *strm;

	if (conn->flags & CO_FL_ERROR)
		goto fail;

	/* we want the connection handler to notify the stream interface about updates. */
	conn->flags |= CO_FL_WAKE_DATA;

	/* if logs require transport layer information, note it on the connection */
	if (sess->fe->to_log & LW_XPRT)
		conn->flags |= CO_FL_XPRT_TRACKED;

	session_count_new(sess);
	task->process = sess->listener->handler;
	strm = stream_new(sess, task, &conn->obj_type);
	if (!strm)
		goto fail;

	strm->target        = sess->listener->default_target;
	strm->req.analysers = sess->listener->analysers;
	conn->flags &= ~CO_FL_INIT_DATA;

	return 0;

 fail:
	session_kill_embryonic(sess);
	return -1;
}

/* Update a session status. The connection is killed in case of
 * error, and <0 will be returned. Otherwise it does nothing.
 */
static int conn_update_session(struct connection *conn)
{
	struct task *task = conn->owner;
	struct session *sess = task->context;

	if (conn->flags & CO_FL_ERROR) {
		session_kill_embryonic(sess);
		return -1;
	}
	return 0;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
