/*
 * Session management functions.
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <common/config.h>
#include <common/buffer.h>
#include <common/debug.h>
#include <common/memory.h>

#include <types/capture.h>
#include <types/global.h>

#include <proto/acl.h>
#include <proto/arg.h>
#include <proto/backend.h>
#include <proto/channel.h>
#include <proto/checks.h>
#include <proto/connection.h>
#include <proto/dumpstats.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/frontend.h>
#include <proto/hdr_idx.h>
#include <proto/listener.h>
#include <proto/log.h>
#include <proto/raw_sock.h>
#include <proto/session.h>
#include <proto/pipe.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/proxy.h>
#include <proto/queue.h>
#include <proto/server.h>
#include <proto/sample.h>
#include <proto/stick_table.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

struct pool_head *pool2_session;
struct list sessions;

static int conn_session_complete(struct connection *conn);
static int conn_session_update(struct connection *conn);
static struct task *expire_mini_session(struct task *t);
int session_complete(struct session *s);

/* data layer callbacks for an embryonic session */
struct data_cb sess_conn_cb = {
	.recv = NULL,
	.send = NULL,
	.wake = conn_session_update,
	.init = conn_session_complete,
};

/* This function is called from the protocol layer accept() in order to
 * instanciate a new embryonic session on behalf of a given listener and
 * frontend. It returns a positive value upon success, 0 if the connection
 * can be ignored, or a negative value upon critical failure. The accepted
 * file descriptor is closed if we return <= 0.
 */
int session_accept(struct listener *l, int cfd, struct sockaddr_storage *addr)
{
	struct connection *cli_conn;
	struct proxy *p = l->frontend;
	struct session *s;
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

	if (unlikely((s = pool_alloc2(pool2_session)) == NULL))
		goto out_free_conn;

	/* minimum session initialization required for an embryonic session is
	 * fairly low. We need very little to execute L4 ACLs, then we need a
	 * task to make the client-side connection live on its own.
	 *  - flags
	 *  - stick-entry tracking
	 */
	s->flags = 0;
	s->logs.logwait = p->to_log;
	s->logs.level = 0;

	memset(s->stkctr, 0, sizeof(s->stkctr));

	s->listener = l;
	s->fe  = p;

	/* On a mini-session, the connection is directly attached to the
	 * session's target so that we don't need to initialize the stream
	 * interfaces. Another benefit is that it's easy to detect a mini-
	 * session in dumps using this : it's the only one which has a
	 * connection in s->target.
	 */
	s->target = &cli_conn->obj_type;

	s->logs.accept_date = date; /* user-visible date for logging */
	s->logs.tv_accept = now;  /* corrected date for internal use */
	s->uniq_id = global.req_count++;
	p->feconn++;
	/* This session was accepted, count it now */
	if (p->feconn > p->fe_counters.conn_max)
		p->fe_counters.conn_max = p->feconn;

	proxy_inc_fe_conn_ctr(l, p);

	/* Add the minimum callbacks to prepare the connection's control layer.
	 * We need this so that we can safely execute the ACLs used by the
	 * "tcp-request connection" ruleset. We also carefully attach the
	 * connection to the stream interface without initializing the rest,
	 * so that ACLs can use si[0]->end.
	 */
	si_attach_conn(&s->si[0], cli_conn);
	conn_attach(cli_conn, s, &sess_conn_cb);
	conn_ctrl_init(cli_conn);

	/* now evaluate the tcp-request layer4 rules. Since we expect to be able
	 * to abort right here as soon as possible, we check the rules before
	 * even initializing the stream interfaces.
	 */
	if ((l->options & LI_O_TCP_RULES) && !tcp_exec_req_rules(s)) {
		/* let's do a no-linger now to close with a single RST. */
		setsockopt(cfd, SOL_SOCKET, SO_LINGER, (struct linger *) &nolinger, sizeof(struct linger));
		ret = 0; /* successful termination */
		goto out_free_session;
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
		goto out_free_session;
	}

	/* wait for a PROXY protocol header */
	if (l->options & LI_O_ACC_PROXY) {
		cli_conn->flags |= CO_FL_ACCEPT_PROXY;
		conn_sock_want_recv(cli_conn);
	}

	if (unlikely((t = task_new()) == NULL))
		goto out_free_session;

	t->context = s;
	t->nice = l->nice;
	s->task = t;

	/* Finish setting the callbacks. Right now the transport layer is present
	 * but not initialized. Also note we need to be careful as the stream
	 * int is not initialized yet.
	 */
	conn_data_want_recv(cli_conn);
	if (conn_xprt_init(cli_conn) < 0)
		goto out_free_task;

	/* OK, now either we have a pending handshake to execute with and
	 * then we must return to the I/O layer, or we can proceed with the
	 * end of the session initialization. In case of handshake, we also
	 * set the I/O timeout to the frontend's client timeout.
	 */

	if (cli_conn->flags & CO_FL_HANDSHAKE) {
		t->process = expire_mini_session;
		t->expire = tick_add_ifset(now_ms, p->timeout.client);
		task_queue(t);
		cli_conn->flags |= CO_FL_INIT_DATA | CO_FL_WAKE_DATA;
		return 1;
	}

	/* OK let's complete session initialization since there is no handshake */
	cli_conn->flags |= CO_FL_CONNECTED;
	ret = session_complete(s);
	if (ret > 0)
		return ret;

	/* Error unrolling */
 out_free_task:
	task_free(t);
 out_free_session:
	p->feconn--;
	session_store_counters(s);
	pool_free2(pool2_session, s);
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


/* prepare the trash with a log prefix for session <s>. It only works with
 * embryonic sessions based on a real connection. This function requires that
 * at s->target still points to the incoming connection.
 */
static void prepare_mini_sess_log_prefix(struct session *s)
{
	struct tm tm;
	char pn[INET6_ADDRSTRLEN];
	int ret;
	char *end;
	struct connection *cli_conn = __objt_conn(s->target);

	ret = addr_to_str(&cli_conn->addr.from, pn, sizeof(pn));
	if (ret <= 0)
		chunk_printf(&trash, "unknown [");
	else if (ret == AF_UNIX)
		chunk_printf(&trash, "%s:%d [", pn, s->listener->luid);
	else
		chunk_printf(&trash, "%s:%d [", pn, get_host_port(&cli_conn->addr.from));

	get_localtime(s->logs.accept_date.tv_sec, &tm);
	end = date2str_log(trash.str + trash.len, &tm, &(s->logs.accept_date), trash.size - trash.len);
	trash.len = end - trash.str;
	if (s->listener->name)
		chunk_appendf(&trash, "] %s/%s", s->fe->id, s->listener->name);
	else
		chunk_appendf(&trash, "] %s/%d", s->fe->id, s->listener->luid);
}

/* This function kills an existing embryonic session. It stops the connection's
 * transport layer, releases assigned resources, resumes the listener if it was
 * disabled and finally kills the file descriptor. This function requires that
 * at s->target still points to the incoming connection.
 */
static void kill_mini_session(struct session *s)
{
	int level = LOG_INFO;
	struct connection *conn = __objt_conn(s->target);
	unsigned int log = s->logs.logwait;
	const char *err_msg;

	if (s->fe->options2 & PR_O2_LOGERRORS)
		level = LOG_ERR;

	if (log && (s->fe->options & PR_O_NULLNOLOG)) {
		/* with "option dontlognull", we don't log connections with no transfer */
		if (!conn->err_code ||
		    conn->err_code == CO_ER_PRX_EMPTY || conn->err_code == CO_ER_PRX_ABORT ||
		    conn->err_code == CO_ER_SSL_EMPTY || conn->err_code == CO_ER_SSL_ABORT)
			log = 0;
	}

	if (log) {
		if (!conn->err_code && (s->task->state & TASK_WOKEN_TIMER)) {
			if (conn->flags & CO_FL_ACCEPT_PROXY)
				conn->err_code = CO_ER_PRX_TIMEOUT;
			else if (conn->flags & CO_FL_SSL_WAIT_HS)
				conn->err_code = CO_ER_SSL_TIMEOUT;
		}

		prepare_mini_sess_log_prefix(s);
		err_msg = conn_err_code_str(conn);
		if (err_msg)
			send_log(s->fe, level, "%s: %s\n", trash.str, err_msg);
		else
			send_log(s->fe, level, "%s: unknown connection error (code=%d flags=%08x)\n",
				 trash.str, conn->err_code, conn->flags);
	}

	/* kill the connection now */
	conn_force_close(conn);
	conn_free(conn);

	s->fe->feconn--;
	session_store_counters(s);

	if (!(s->listener->options & LI_O_UNLIMITED))
		actconn--;
	jobs--;
	s->listener->nbconn--;
	if (s->listener->state == LI_FULL)
		resume_listener(s->listener);

	/* Dequeues all of the listeners waiting for a resource */
	if (!LIST_ISEMPTY(&global_listener_queue))
		dequeue_all_listeners(&global_listener_queue);

	if (!LIST_ISEMPTY(&s->fe->listener_queue) &&
	    (!s->fe->fe_sps_lim || freq_ctr_remain(&s->fe->fe_sess_per_sec, s->fe->fe_sps_lim, 0) > 0))
		dequeue_all_listeners(&s->fe->listener_queue);

	task_delete(s->task);
	task_free(s->task);
	pool_free2(pool2_session, s);
}

/* Finish initializing a session from a connection, or kills it if the
 * connection shows and error. Returns <0 if the connection was killed.
 */
static int conn_session_complete(struct connection *conn)
{
	struct session *s = conn->owner;

	if (!(conn->flags & CO_FL_ERROR) && (session_complete(s) > 0)) {
		conn->flags &= ~CO_FL_INIT_DATA;
		return 0;
	}

	/* kill the connection now */
	kill_mini_session(s);
	return -1;
}

/* Update an embryonic session status. The connection is killed in case of
 * error, and <0 will be returned. Otherwise it does nothing.
 */
static int conn_session_update(struct connection *conn)
{
	if (conn->flags & CO_FL_ERROR) {
		kill_mini_session(conn->owner);
		return -1;
	}
	return 0;
}

/* Manages embryonic sessions timeout. It is only called when the timeout
 * strikes and performs the required cleanup.
 */
static struct task *expire_mini_session(struct task *t)
{
	struct session *s = t->context;

	if (!(t->state & TASK_WOKEN_TIMER))
		return t;

	kill_mini_session(s);
	return NULL;
}

/* This function is called from the I/O handler which detects the end of
 * handshake, in order to complete initialization of a valid session. It must
 * be called with an embryonic session. It returns a positive value upon
 * success, 0 if the connection can be ignored, or a negative value upon
 * critical failure. The accepted file descriptor is closed if we return <= 0.
 * The client-side end point is assumed to be a connection, whose pointer is
 * taken from s->target which is assumed to be valid. If the function fails,
 * it restores s->target.
 */
int session_complete(struct session *s)
{
	struct listener *l = s->listener;
	struct proxy *p = s->fe;
	struct http_txn *txn;
	struct task *t = s->task;
	struct connection *conn = __objt_conn(s->target);
	int ret;
	int i;

	ret = -1; /* assume unrecoverable error by default */

	/* OK, we're keeping the session, so let's properly initialize the session */
	LIST_ADDQ(&sessions, &s->list);
	LIST_INIT(&s->back_refs);

	s->flags |= SN_INITIALIZED;
	s->unique_id = NULL;

	t->process = l->handler;
	t->context = s;
	t->expire = TICK_ETERNITY;

	/* Note: initially, the session's backend points to the frontend.
	 * This changes later when switching rules are executed or
	 * when the default backend is assigned.
	 */
	s->be  = s->fe;
	s->req = s->rep = NULL; /* will be allocated later */
	s->comp_algo = NULL;

	/* Let's count a session now */
	proxy_inc_fe_sess_ctr(l, p);

	for (i = 0; i < MAX_SESS_STKCTR; i++) {
		void *ptr;

		if (!stkctr_entry(&s->stkctr[i]))
			continue;

		ptr = stktable_data_ptr(s->stkctr[i].table, stkctr_entry(&s->stkctr[i]), STKTABLE_DT_SESS_CNT);
		if (ptr)
			stktable_data_cast(ptr, sess_cnt)++;

		ptr = stktable_data_ptr(s->stkctr[i].table, stkctr_entry(&s->stkctr[i]), STKTABLE_DT_SESS_RATE);
		if (ptr)
			update_freq_ctr_period(&stktable_data_cast(ptr, sess_rate),
					       s->stkctr[i].table->data_arg[STKTABLE_DT_SESS_RATE].u, 1);
	}

	/* this part should be common with other protocols */
	si_reset(&s->si[0], t);
	si_set_state(&s->si[0], SI_ST_EST);

	/* attach the incoming connection to the stream interface now.
	 * We must do that *before* clearing ->target because we need
	 * to keep a pointer to the connection in case we have to call
	 * kill_mini_session().
	 */
	si_attach_conn(&s->si[0], conn);

	if (likely(s->fe->options2 & PR_O2_INDEPSTR))
		s->si[0].flags |= SI_FL_INDEP_STR;

	/* pre-initialize the other side's stream interface to an INIT state. The
	 * callbacks will be initialized before attempting to connect.
	 */
	si_reset(&s->si[1], t);
	si_detach(&s->si[1]);

	if (likely(s->fe->options2 & PR_O2_INDEPSTR))
		s->si[1].flags |= SI_FL_INDEP_STR;

	session_init_srv_conn(s);
	s->target = NULL;
	s->pend_pos = NULL;

	/* init store persistence */
	s->store_count = 0;

	if (unlikely((s->req = pool_alloc2(pool2_channel)) == NULL))
		goto out_free_task; /* no memory */

	if (unlikely((s->req->buf = pool_alloc2(pool2_buffer)) == NULL))
		goto out_free_req; /* no memory */

	if (unlikely((s->rep = pool_alloc2(pool2_channel)) == NULL))
		goto out_free_req_buf; /* no memory */

	if (unlikely((s->rep->buf = pool_alloc2(pool2_buffer)) == NULL))
		goto out_free_rep; /* no memory */

	/* initialize the request buffer */
	s->req->buf->size = global.tune.bufsize;
	channel_init(s->req);
	s->req->prod = &s->si[0];
	s->req->cons = &s->si[1];
	s->si[0].ib = s->si[1].ob = s->req;
	s->req->flags |= CF_READ_ATTACHED; /* the producer is already connected */

	/* activate default analysers enabled for this listener */
	s->req->analysers = l->analysers;

	s->req->wto = TICK_ETERNITY;
	s->req->rto = TICK_ETERNITY;
	s->req->rex = TICK_ETERNITY;
	s->req->wex = TICK_ETERNITY;
	s->req->analyse_exp = TICK_ETERNITY;

	/* initialize response buffer */
	s->rep->buf->size = global.tune.bufsize;
	channel_init(s->rep);
	s->rep->prod = &s->si[1];
	s->rep->cons = &s->si[0];
	s->si[0].ob = s->si[1].ib = s->rep;
	s->rep->analysers = 0;

	if (s->fe->options2 & PR_O2_NODELAY) {
		s->req->flags |= CF_NEVER_WAIT;
		s->rep->flags |= CF_NEVER_WAIT;
	}

	s->rep->rto = TICK_ETERNITY;
	s->rep->wto = TICK_ETERNITY;
	s->rep->rex = TICK_ETERNITY;
	s->rep->wex = TICK_ETERNITY;
	s->rep->analyse_exp = TICK_ETERNITY;

	txn = &s->txn;
	/* Those variables will be checked and freed if non-NULL in
	 * session.c:session_free(). It is important that they are
	 * properly initialized.
	 */
	txn->sessid = NULL;
	txn->srv_cookie = NULL;
	txn->cli_cookie = NULL;
	txn->uri = NULL;
	txn->req.cap = NULL;
	txn->rsp.cap = NULL;
	txn->hdr_idx.v = NULL;
	txn->hdr_idx.size = txn->hdr_idx.used = 0;
	txn->flags = 0;
	txn->req.flags = 0;
	txn->rsp.flags = 0;
	/* the HTTP messages need to know what buffer they're associated with */
	txn->req.chn = s->req;
	txn->rsp.chn = s->rep;

	/* finish initialization of the accepted file descriptor */
	conn_data_want_recv(conn);

	if (p->accept && (ret = p->accept(s)) <= 0) {
		/* Either we had an unrecoverable error (<0) or work is
		 * finished (=0, eg: monitoring), in both situations,
		 * we can release everything and close.
		 */
		goto out_free_rep_buf;
	}

	/* if logs require transport layer information, note it on the connection */
	if (s->logs.logwait & LW_XPRT)
		conn->flags |= CO_FL_XPRT_TRACKED;

	/* we want the connection handler to notify the stream interface about updates. */
	conn->flags |= CO_FL_WAKE_DATA;

	/* it is important not to call the wakeup function directly but to
	 * pass through task_wakeup(), because this one knows how to apply
	 * priorities to tasks.
	 */
	task_wakeup(t, TASK_WOKEN_INIT);
	return 1;

	/* Error unrolling */
 out_free_rep_buf:
	pool_free2(pool2_buffer, s->rep->buf);
 out_free_rep:
	pool_free2(pool2_channel, s->rep);
 out_free_req_buf:
	pool_free2(pool2_buffer, s->req->buf);
 out_free_req:
	pool_free2(pool2_channel, s->req);
 out_free_task:
	/* and restore the connection pointer in case we destroyed it,
	 * because kill_mini_session() will need it.
	 */
	s->target = &conn->obj_type;
	return ret;
}

/*
 * frees  the context associated to a session. It must have been removed first.
 */
static void session_free(struct session *s)
{
	struct http_txn *txn = &s->txn;
	struct proxy *fe = s->fe;
	struct bref *bref, *back;
	struct connection *cli_conn = objt_conn(s->si[0].end);
	int i;

	if (s->pend_pos)
		pendconn_free(s->pend_pos);

	if (objt_server(s->target)) { /* there may be requests left pending in queue */
		if (s->flags & SN_CURR_SESS) {
			s->flags &= ~SN_CURR_SESS;
			objt_server(s->target)->cur_sess--;
		}
		if (may_dequeue_tasks(objt_server(s->target), s->be))
			process_srv_queue(objt_server(s->target));
	}

	if (unlikely(s->srv_conn)) {
		/* the session still has a reserved slot on a server, but
		 * it should normally be only the same as the one above,
		 * so this should not happen in fact.
		 */
		sess_change_server(s, NULL);
	}

	if (s->req->pipe)
		put_pipe(s->req->pipe);

	if (s->rep->pipe)
		put_pipe(s->rep->pipe);

	pool_free2(pool2_buffer, s->req->buf);
	pool_free2(pool2_buffer, s->rep->buf);

	pool_free2(pool2_channel, s->req);
	pool_free2(pool2_channel, s->rep);

	http_end_txn(s);

	/* ensure the client-side transport layer is destroyed */
	if (cli_conn)
		conn_force_close(cli_conn);

	for (i = 0; i < s->store_count; i++) {
		if (!s->store[i].ts)
			continue;
		stksess_free(s->store[i].table, s->store[i].ts);
		s->store[i].ts = NULL;
	}

	pool_free2(pool2_hdr_idx, txn->hdr_idx.v);
	if (fe) {
		pool_free2(fe->rsp_cap_pool, txn->rsp.cap);
		pool_free2(fe->req_cap_pool, txn->req.cap);
	}

	session_store_counters(s);

	list_for_each_entry_safe(bref, back, &s->back_refs, users) {
		/* we have to unlink all watchers. We must not relink them if
		 * this session was the last one in the list.
		 */
		LIST_DEL(&bref->users);
		LIST_INIT(&bref->users);
		if (s->list.n != &sessions)
			LIST_ADDQ(&LIST_ELEM(s->list.n, struct session *, list)->back_refs, &bref->users);
		bref->ref = s->list.n;
	}
	LIST_DEL(&s->list);
	si_release_endpoint(&s->si[1]);
	si_release_endpoint(&s->si[0]);
	pool_free2(pool2_session, s);

	/* We may want to free the maximum amount of pools if the proxy is stopping */
	if (fe && unlikely(fe->state == PR_STSTOPPED)) {
		pool_flush2(pool2_buffer);
		pool_flush2(pool2_channel);
		pool_flush2(pool2_hdr_idx);
		pool_flush2(pool2_requri);
		pool_flush2(pool2_capture);
		pool_flush2(pool2_session);
		pool_flush2(fe->req_cap_pool);
		pool_flush2(fe->rsp_cap_pool);
	}
}


/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_session()
{
	LIST_INIT(&sessions);
	pool2_session = create_pool("session", sizeof(struct session), MEM_F_SHARED);
	return pool2_session != NULL;
}

void session_process_counters(struct session *s)
{
	unsigned long long bytes;
	void *ptr;
	int i;

	if (s->req) {
		bytes = s->req->total - s->logs.bytes_in;
		s->logs.bytes_in = s->req->total;
		if (bytes) {
			s->fe->fe_counters.bytes_in += bytes;

			s->be->be_counters.bytes_in += bytes;

			if (objt_server(s->target))
				objt_server(s->target)->counters.bytes_in += bytes;

			if (s->listener && s->listener->counters)
				s->listener->counters->bytes_in += bytes;

			for (i = 0; i < MAX_SESS_STKCTR; i++) {
				if (!stkctr_entry(&s->stkctr[i]))
					continue;

				ptr = stktable_data_ptr(s->stkctr[i].table,
				                        stkctr_entry(&s->stkctr[i]),
				                        STKTABLE_DT_BYTES_IN_CNT);
				if (ptr)
					stktable_data_cast(ptr, bytes_in_cnt) += bytes;

				ptr = stktable_data_ptr(s->stkctr[i].table,
				                        stkctr_entry(&s->stkctr[i]),
				                        STKTABLE_DT_BYTES_IN_RATE);
				if (ptr)
					update_freq_ctr_period(&stktable_data_cast(ptr, bytes_in_rate),
					                       s->stkctr[i].table->data_arg[STKTABLE_DT_BYTES_IN_RATE].u, bytes);
			}
		}
	}

	if (s->rep) {
		bytes = s->rep->total - s->logs.bytes_out;
		s->logs.bytes_out = s->rep->total;
		if (bytes) {
			s->fe->fe_counters.bytes_out += bytes;

			s->be->be_counters.bytes_out += bytes;

			if (objt_server(s->target))
				objt_server(s->target)->counters.bytes_out += bytes;

			if (s->listener && s->listener->counters)
				s->listener->counters->bytes_out += bytes;

			for (i = 0; i < MAX_SESS_STKCTR; i++) {
				if (!stkctr_entry(&s->stkctr[i]))
					continue;

				ptr = stktable_data_ptr(s->stkctr[i].table,
				                        stkctr_entry(&s->stkctr[i]),
				                        STKTABLE_DT_BYTES_OUT_CNT);
				if (ptr)
					stktable_data_cast(ptr, bytes_out_cnt) += bytes;

				ptr = stktable_data_ptr(s->stkctr[i].table,
				                        stkctr_entry(&s->stkctr[i]),
				                        STKTABLE_DT_BYTES_OUT_RATE);
				if (ptr)
					update_freq_ctr_period(&stktable_data_cast(ptr, bytes_out_rate),
					                       s->stkctr[i].table->data_arg[STKTABLE_DT_BYTES_OUT_RATE].u, bytes);
			}
		}
	}
}

/* This function is called with (si->state == SI_ST_CON) meaning that a
 * connection was attempted and that the file descriptor is already allocated.
 * We must check for establishment, error and abort. Possible output states
 * are SI_ST_EST (established), SI_ST_CER (error), SI_ST_DIS (abort), and
 * SI_ST_CON (no change). The function returns 0 if it switches to SI_ST_CER,
 * otherwise 1. This only works with connection-based sessions.
 */
static int sess_update_st_con_tcp(struct session *s, struct stream_interface *si)
{
	struct channel *req = si->ob;
	struct channel *rep = si->ib;
	struct connection *srv_conn = __objt_conn(si->end);

	/* If we got an error, or if nothing happened and the connection timed
	 * out, we must give up. The CER state handler will take care of retry
	 * attempts and error reports.
	 */
	if (unlikely(si->flags & (SI_FL_EXP|SI_FL_ERR))) {
		if (unlikely(si->ob->flags & CF_WRITE_PARTIAL)) {
			/* Some data were sent past the connection establishment,
			 * so we need to pretend we're established to log correctly
			 * and let later states handle the failure.
			 */
			si->state    = SI_ST_EST;
			si->err_type = SI_ET_DATA_ERR;
			si->ib->flags |= CF_READ_ERROR | CF_WRITE_ERROR;
			return 1;
		}
		si->exp   = TICK_ETERNITY;
		si->state = SI_ST_CER;

		conn_force_close(srv_conn);

		if (si->err_type)
			return 0;

		if (si->flags & SI_FL_ERR)
			si->err_type = SI_ET_CONN_ERR;
		else
			si->err_type = SI_ET_CONN_TO;
		return 0;
	}

	/* OK, maybe we want to abort */
	if (!(req->flags & CF_WRITE_PARTIAL) &&
	    unlikely((rep->flags & CF_SHUTW) ||
		     ((req->flags & CF_SHUTW_NOW) && /* FIXME: this should not prevent a connection from establishing */
		      ((!(req->flags & CF_WRITE_ACTIVITY) && channel_is_empty(req)) ||
		       s->be->options & PR_O_ABRT_CLOSE)))) {
		/* give up */
		si_shutw(si);
		si->err_type |= SI_ET_CONN_ABRT;
		if (s->srv_error)
			s->srv_error(s, si);
		return 1;
	}

	/* we need to wait a bit more if there was no activity either */
	if (!(req->flags & CF_WRITE_ACTIVITY))
		return 1;

	/* OK, this means that a connection succeeded. The caller will be
	 * responsible for handling the transition from CON to EST.
	 */
	si->state    = SI_ST_EST;
	si->err_type = SI_ET_NONE;
	return 1;
}

/* This function is called with (si->state == SI_ST_CER) meaning that a
 * previous connection attempt has failed and that the file descriptor
 * has already been released. Possible causes include asynchronous error
 * notification and time out. Possible output states are SI_ST_CLO when
 * retries are exhausted, SI_ST_TAR when a delay is wanted before a new
 * connection attempt, SI_ST_ASS when it's wise to retry on the same server,
 * and SI_ST_REQ when an immediate redispatch is wanted. The buffers are
 * marked as in error state. It returns 0.
 */
static int sess_update_st_cer(struct session *s, struct stream_interface *si)
{
	/* we probably have to release last session from the server */
	if (objt_server(s->target)) {
		health_adjust(objt_server(s->target), HANA_STATUS_L4_ERR);

		if (s->flags & SN_CURR_SESS) {
			s->flags &= ~SN_CURR_SESS;
			objt_server(s->target)->cur_sess--;
		}
	}

	/* ensure that we have enough retries left */
	si->conn_retries--;
	if (si->conn_retries < 0) {
		if (!si->err_type) {
			si->err_type = SI_ET_CONN_ERR;
		}

		if (objt_server(s->target))
			objt_server(s->target)->counters.failed_conns++;
		s->be->be_counters.failed_conns++;
		sess_change_server(s, NULL);
		if (may_dequeue_tasks(objt_server(s->target), s->be))
			process_srv_queue(objt_server(s->target));

		/* shutw is enough so stop a connecting socket */
		si_shutw(si);
		si->ob->flags |= CF_WRITE_ERROR;
		si->ib->flags |= CF_READ_ERROR;

		si->state = SI_ST_CLO;
		if (s->srv_error)
			s->srv_error(s, si);
		return 0;
	}

	/* If the "redispatch" option is set on the backend, we are allowed to
	 * retry on another server for the last retry. In order to achieve this,
	 * we must mark the session unassigned, and eventually clear the DIRECT
	 * bit to ignore any persistence cookie. We won't count a retry nor a
	 * redispatch yet, because this will depend on what server is selected.
	 * If the connection is not persistent, the balancing algorithm is not
	 * determinist (round robin) and there is more than one active server,
	 * we accept to perform an immediate redispatch without waiting since
	 * we don't care about this particular server.
	 */
	if (objt_server(s->target) &&
	    (si->conn_retries == 0 ||
	     (!(s->flags & SN_DIRECT) && s->be->srv_act > 1 &&
	      ((s->be->lbprm.algo & BE_LB_KIND) == BE_LB_KIND_RR))) &&
	    s->be->options & PR_O_REDISP && !(s->flags & SN_FORCE_PRST)) {
		sess_change_server(s, NULL);
		if (may_dequeue_tasks(objt_server(s->target), s->be))
			process_srv_queue(objt_server(s->target));

		s->flags &= ~(SN_DIRECT | SN_ASSIGNED | SN_ADDR_SET);
		si->state = SI_ST_REQ;
	} else {
		if (objt_server(s->target))
			objt_server(s->target)->counters.retries++;
		s->be->be_counters.retries++;
		si->state = SI_ST_ASS;
	}

	if (si->flags & SI_FL_ERR) {
		/* The error was an asynchronous connection error, and we will
		 * likely have to retry connecting to the same server, most
		 * likely leading to the same result. To avoid this, we wait
		 * MIN(one second, connect timeout) before retrying.
		 */

		int delay = 1000;

		if (s->be->timeout.connect && s->be->timeout.connect < delay)
			delay = s->be->timeout.connect;

		if (!si->err_type)
			si->err_type = SI_ET_CONN_ERR;

		/* only wait when we're retrying on the same server */
		if (si->state == SI_ST_ASS ||
		    (s->be->lbprm.algo & BE_LB_KIND) != BE_LB_KIND_RR ||
		    (s->be->srv_act <= 1)) {
			si->state = SI_ST_TAR;
			si->exp = tick_add(now_ms, MS_TO_TICKS(delay));
		}
		return 0;
	}
	return 0;
}

/*
 * This function handles the transition between the SI_ST_CON state and the
 * SI_ST_EST state. It must only be called after switching from SI_ST_CON (or
 * SI_ST_INI) to SI_ST_EST, but only when a ->proto is defined.
 */
static void sess_establish(struct session *s, struct stream_interface *si)
{
	struct channel *req = si->ob;
	struct channel *rep = si->ib;

	/* First, centralize the timers information */
	s->logs.t_connect = tv_ms_elapsed(&s->logs.tv_accept, &now);
	si->exp      = TICK_ETERNITY;

	if (objt_server(s->target))
		health_adjust(objt_server(s->target), HANA_STATUS_L4_OK);

	if (s->be->mode == PR_MODE_TCP) { /* let's allow immediate data connection in this case */
		/* if the user wants to log as soon as possible, without counting
		 * bytes from the server, then this is the right moment. */
		if (!LIST_ISEMPTY(&s->fe->logformat) && !(s->logs.logwait & LW_BYTES)) {
			s->logs.t_close = s->logs.t_connect; /* to get a valid end date */
			s->do_log(s);
		}
	}
	else {
		s->txn.rsp.msg_state = HTTP_MSG_RPBEFORE;
		rep->flags |= CF_READ_DONTWAIT; /* a single read is enough to get response headers */
	}

	rep->analysers |= s->fe->fe_rsp_ana | s->be->be_rsp_ana;
	rep->flags |= CF_READ_ATTACHED; /* producer is now attached */
	if (req->flags & CF_WAKE_CONNECT) {
		req->flags |= CF_WAKE_ONCE;
		req->flags &= ~CF_WAKE_CONNECT;
	}
	if (objt_conn(si->end)) {
		/* real connections have timeouts */
		req->wto = s->be->timeout.server;
		rep->rto = s->be->timeout.server;
	}
	req->wex = TICK_ETERNITY;
}

/* Update stream interface status for input states SI_ST_ASS, SI_ST_QUE, SI_ST_TAR.
 * Other input states are simply ignored.
 * Possible output states are SI_ST_CLO, SI_ST_TAR, SI_ST_ASS, SI_ST_REQ, SI_ST_CON
 * and SI_ST_EST. Flags must have previously been updated for timeouts and other
 * conditions.
 */
static void sess_update_stream_int(struct session *s, struct stream_interface *si)
{
	struct server *srv = objt_server(s->target);

	DPRINTF(stderr,"[%u] %s: sess=%p rq=%p, rp=%p, exp(r,w)=%u,%u rqf=%08x rpf=%08x rqh=%d rqt=%d rph=%d rpt=%d cs=%d ss=%d\n",
		now_ms, __FUNCTION__,
		s,
		s->req, s->rep,
		s->req->rex, s->rep->wex,
		s->req->flags, s->rep->flags,
		s->req->buf->i, s->req->buf->o, s->rep->buf->i, s->rep->buf->o, s->rep->cons->state, s->req->cons->state);

	if (si->state == SI_ST_ASS) {
		/* Server assigned to connection request, we have to try to connect now */
		int conn_err;

		conn_err = connect_server(s);
		srv = objt_server(s->target);

		if (conn_err == SN_ERR_NONE) {
			/* state = SI_ST_CON or SI_ST_EST now */
			if (srv)
				srv_inc_sess_ctr(srv);
			if (srv)
				srv_set_sess_last(srv);
			return;
		}

		/* We have received a synchronous error. We might have to
		 * abort, retry immediately or redispatch.
		 */
		if (conn_err == SN_ERR_INTERNAL) {
			if (!si->err_type) {
				si->err_type = SI_ET_CONN_OTHER;
			}

			if (srv)
				srv_inc_sess_ctr(srv);
			if (srv)
				srv_set_sess_last(srv);
			if (srv)
				srv->counters.failed_conns++;
			s->be->be_counters.failed_conns++;

			/* release other sessions waiting for this server */
			sess_change_server(s, NULL);
			if (may_dequeue_tasks(srv, s->be))
				process_srv_queue(srv);

			/* Failed and not retryable. */
			si_shutr(si);
			si_shutw(si);
			si->ob->flags |= CF_WRITE_ERROR;

			s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);

			/* no session was ever accounted for this server */
			si->state = SI_ST_CLO;
			if (s->srv_error)
				s->srv_error(s, si);
			return;
		}

		/* We are facing a retryable error, but we don't want to run a
		 * turn-around now, as the problem is likely a source port
		 * allocation problem, so we want to retry now.
		 */
		si->state = SI_ST_CER;
		si->flags &= ~SI_FL_ERR;
		sess_update_st_cer(s, si);
		/* now si->state is one of SI_ST_CLO, SI_ST_TAR, SI_ST_ASS, SI_ST_REQ */
		return;
	}
	else if (si->state == SI_ST_QUE) {
		/* connection request was queued, check for any update */
		if (!s->pend_pos) {
			/* The connection is not in the queue anymore. Either
			 * we have a server connection slot available and we
			 * go directly to the assigned state, or we need to
			 * load-balance first and go to the INI state.
			 */
			si->exp = TICK_ETERNITY;
			if (unlikely(!(s->flags & SN_ASSIGNED)))
				si->state = SI_ST_REQ;
			else {
				s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);
				si->state = SI_ST_ASS;
			}
			return;
		}

		/* Connection request still in queue... */
		if (si->flags & SI_FL_EXP) {
			/* ... and timeout expired */
			si->exp = TICK_ETERNITY;
			s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);
			if (srv)
				srv->counters.failed_conns++;
			s->be->be_counters.failed_conns++;
			si_shutr(si);
			si_shutw(si);
			si->ob->flags |= CF_WRITE_TIMEOUT;
			if (!si->err_type)
				si->err_type = SI_ET_QUEUE_TO;
			si->state = SI_ST_CLO;
			if (s->srv_error)
				s->srv_error(s, si);
			return;
		}

		/* Connection remains in queue, check if we have to abort it */
		if ((si->ob->flags & (CF_READ_ERROR)) ||
		    ((si->ob->flags & CF_SHUTW_NOW) &&   /* empty and client aborted */
		     (channel_is_empty(si->ob) || s->be->options & PR_O_ABRT_CLOSE))) {
			/* give up */
			si->exp = TICK_ETERNITY;
			s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);
			si_shutr(si);
			si_shutw(si);
			si->err_type |= SI_ET_QUEUE_ABRT;
			si->state = SI_ST_CLO;
			if (s->srv_error)
				s->srv_error(s, si);
			return;
		}

		/* Nothing changed */
		return;
	}
	else if (si->state == SI_ST_TAR) {
		/* Connection request might be aborted */
		if ((si->ob->flags & (CF_READ_ERROR)) ||
		    ((si->ob->flags & CF_SHUTW_NOW) &&  /* empty and client aborted */
		     (channel_is_empty(si->ob) || s->be->options & PR_O_ABRT_CLOSE))) {
			/* give up */
			si->exp = TICK_ETERNITY;
			si_shutr(si);
			si_shutw(si);
			si->err_type |= SI_ET_CONN_ABRT;
			si->state = SI_ST_CLO;
			if (s->srv_error)
				s->srv_error(s, si);
			return;
		}

		if (!(si->flags & SI_FL_EXP))
			return;  /* still in turn-around */

		si->exp = TICK_ETERNITY;

		/* we keep trying on the same server as long as the session is
		 * marked "assigned".
		 * FIXME: Should we force a redispatch attempt when the server is down ?
		 */
		if (s->flags & SN_ASSIGNED)
			si->state = SI_ST_ASS;
		else
			si->state = SI_ST_REQ;
		return;
	}
}

/* Set correct session termination flags in case no analyser has done it. It
 * also counts a failed request if the server state has not reached the request
 * stage.
 */
static void sess_set_term_flags(struct session *s)
{
	if (!(s->flags & SN_FINST_MASK)) {
		if (s->si[1].state < SI_ST_REQ) {

			s->fe->fe_counters.failed_req++;
			if (s->listener->counters)
				s->listener->counters->failed_req++;

			s->flags |= SN_FINST_R;
		}
		else if (s->si[1].state == SI_ST_QUE)
			s->flags |= SN_FINST_Q;
		else if (s->si[1].state < SI_ST_EST)
			s->flags |= SN_FINST_C;
		else if (s->si[1].state == SI_ST_EST || s->si[1].prev_state == SI_ST_EST)
			s->flags |= SN_FINST_D;
		else
			s->flags |= SN_FINST_L;
	}
}

/* This function initiates a server connection request on a stream interface
 * already in SI_ST_REQ state. Upon success, the state goes to SI_ST_ASS for
 * a real connection to a server, indicating that a server has been assigned,
 * or SI_ST_EST for a successful connection to an applet. It may also return
 * SI_ST_QUE, or SI_ST_CLO upon error.
 */
static void sess_prepare_conn_req(struct session *s, struct stream_interface *si)
{
	DPRINTF(stderr,"[%u] %s: sess=%p rq=%p, rp=%p, exp(r,w)=%u,%u rqf=%08x rpf=%08x rqh=%d rqt=%d rph=%d rpt=%d cs=%d ss=%d\n",
		now_ms, __FUNCTION__,
		s,
		s->req, s->rep,
		s->req->rex, s->rep->wex,
		s->req->flags, s->rep->flags,
		s->req->buf->i, s->req->buf->o, s->rep->buf->i, s->rep->buf->o, s->rep->cons->state, s->req->cons->state);

	if (si->state != SI_ST_REQ)
		return;

	if (unlikely(obj_type(s->target) == OBJ_TYPE_APPLET)) {
		/* the applet directly goes to the EST state */
		struct appctx *appctx = objt_appctx(si->end);

		if (!appctx || appctx->applet != __objt_applet(s->target))
			appctx = stream_int_register_handler(si, objt_applet(s->target));

		if (!appctx) {
			/* No more memory, let's immediately abort. Force the
			 * error code to ignore the ERR_LOCAL which is not a
			 * real error.
			 */
			s->flags &= ~(SN_ERR_MASK | SN_FINST_MASK);

			si_shutr(si);
			si_shutw(si);
			si->ob->flags |= CF_WRITE_ERROR;
			si->err_type = SI_ET_CONN_RES;
			si->state = SI_ST_CLO;
			if (s->srv_error)
				s->srv_error(s, si);
			return;
		}

		s->logs.t_queue   = tv_ms_elapsed(&s->logs.tv_accept, &now);
		si->state         = SI_ST_EST;
		si->err_type      = SI_ET_NONE;
		be_set_sess_last(s->be);
		/* let sess_establish() finish the job */
		return;
	}

	/* Try to assign a server */
	if (srv_redispatch_connect(s) != 0) {
		/* We did not get a server. Either we queued the
		 * connection request, or we encountered an error.
		 */
		if (si->state == SI_ST_QUE)
			return;

		/* we did not get any server, let's check the cause */
		si_shutr(si);
		si_shutw(si);
		si->ob->flags |= CF_WRITE_ERROR;
		if (!si->err_type)
			si->err_type = SI_ET_CONN_OTHER;
		si->state = SI_ST_CLO;
		if (s->srv_error)
			s->srv_error(s, si);
		return;
	}

	/* The server is assigned */
	s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);
	si->state = SI_ST_ASS;
	be_set_sess_last(s->be);
}

/* This stream analyser checks the switching rules and changes the backend
 * if appropriate. The default_backend rule is also considered, then the
 * target backend's forced persistence rules are also evaluated last if any.
 * It returns 1 if the processing can continue on next analysers, or zero if it
 * either needs more data or wants to immediately abort the request.
 */
static int process_switching_rules(struct session *s, struct channel *req, int an_bit)
{
	struct persist_rule *prst_rule;

	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;

	DPRINTF(stderr,"[%u] %s: session=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->buf->i,
		req->analysers);

	/* now check whether we have some switching rules for this request */
	if (!(s->flags & SN_BE_ASSIGNED)) {
		struct switching_rule *rule;

		list_for_each_entry(rule, &s->fe->switching_rules, list) {
			int ret = 1;

			if (rule->cond) {
				ret = acl_exec_cond(rule->cond, s->fe, s, &s->txn, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
				ret = acl_pass(ret);
				if (rule->cond->pol == ACL_COND_UNLESS)
					ret = !ret;
			}

			if (ret) {
				/* If the backend name is dynamic, try to resolve the name.
				 * If we can't resolve the name, or if any error occurs, break
				 * the loop and fallback to the default backend.
				 */
				struct proxy *backend;

				if (rule->dynamic) {
					struct chunk *tmp = get_trash_chunk();
					if (!build_logline(s, tmp->str, tmp->size, &rule->be.expr))
						break;
					backend = findproxy(tmp->str, PR_CAP_BE);
					if (!backend)
						break;
				}
				else
					backend = rule->be.backend;

				if (!session_set_backend(s, backend))
					goto sw_failed;
				break;
			}
		}

		/* To ensure correct connection accounting on the backend, we
		 * have to assign one if it was not set (eg: a listen). This
		 * measure also takes care of correctly setting the default
		 * backend if any.
		 */
		if (!(s->flags & SN_BE_ASSIGNED))
			if (!session_set_backend(s, s->fe->defbe.be ? s->fe->defbe.be : s->be))
				goto sw_failed;
	}

	/* we don't want to run the TCP or HTTP filters again if the backend has not changed */
	if (s->fe == s->be) {
		s->req->analysers &= ~AN_REQ_INSPECT_BE;
		s->req->analysers &= ~AN_REQ_HTTP_PROCESS_BE;
	}

	/* as soon as we know the backend, we must check if we have a matching forced or ignored
	 * persistence rule, and report that in the session.
	 */
	list_for_each_entry(prst_rule, &s->be->persist_rules, list) {
		int ret = 1;

		if (prst_rule->cond) {
	                ret = acl_exec_cond(prst_rule->cond, s->be, s, &s->txn, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (prst_rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			/* no rule, or the rule matches */
			if (prst_rule->type == PERSIST_TYPE_FORCE) {
				s->flags |= SN_FORCE_PRST;
			} else {
				s->flags |= SN_IGNORE_PRST;
			}
			break;
		}
	}

	return 1;

 sw_failed:
	/* immediately abort this request in case of allocation failure */
	channel_abort(s->req);
	channel_abort(s->rep);

	if (!(s->flags & SN_ERR_MASK))
		s->flags |= SN_ERR_RESOURCE;
	if (!(s->flags & SN_FINST_MASK))
		s->flags |= SN_FINST_R;

	s->txn.status = 500;
	s->req->analysers = 0;
	s->req->analyse_exp = TICK_ETERNITY;
	return 0;
}

/* This stream analyser works on a request. It applies all use-server rules on
 * it then returns 1. The data must already be present in the buffer otherwise
 * they won't match. It always returns 1.
 */
static int process_server_rules(struct session *s, struct channel *req, int an_bit)
{
	struct proxy *px = s->be;
	struct server_rule *rule;

	DPRINTF(stderr,"[%u] %s: session=%p b=%p, exp(r,w)=%u,%u bf=%08x bl=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->buf->i + req->buf->o,
		req->analysers);

	if (!(s->flags & SN_ASSIGNED)) {
		list_for_each_entry(rule, &px->server_rules, list) {
			int ret;

			ret = acl_exec_cond(rule->cond, s->be, s, &s->txn, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;

			if (ret) {
				struct server *srv = rule->srv.ptr;

				if ((srv->state != SRV_ST_STOPPED) ||
				    (px->options & PR_O_PERSIST) ||
				    (s->flags & SN_FORCE_PRST)) {
					s->flags |= SN_DIRECT | SN_ASSIGNED;
					s->target = &srv->obj_type;
					break;
				}
				/* if the server is not UP, let's go on with next rules
				 * just in case another one is suited.
				 */
			}
		}
	}

	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;
	return 1;
}

/* This stream analyser works on a request. It applies all sticking rules on
 * it then returns 1. The data must already be present in the buffer otherwise
 * they won't match. It always returns 1.
 */
static int process_sticking_rules(struct session *s, struct channel *req, int an_bit)
{
	struct proxy    *px   = s->be;
	struct sticking_rule  *rule;

	DPRINTF(stderr,"[%u] %s: session=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->buf->i,
		req->analysers);

	list_for_each_entry(rule, &px->sticking_rules, list) {
		int ret = 1 ;
		int i;

		/* Only the first stick store-request of each table is applied
		 * and other ones are ignored. The purpose is to allow complex
		 * configurations which look for multiple entries by decreasing
		 * order of precision and to stop at the first which matches.
		 * An example could be a store of the IP address from an HTTP
		 * header first, then from the source if not found.
		 */
		for (i = 0; i < s->store_count; i++) {
			if (rule->table.t == s->store[i].table)
				break;
		}

		if (i !=  s->store_count)
			continue;

		if (rule->cond) {
	                ret = acl_exec_cond(rule->cond, px, s, &s->txn, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			struct stktable_key *key;

			key = stktable_fetch_key(rule->table.t, px, s, &s->txn, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->expr, NULL);
			if (!key)
				continue;

			if (rule->flags & STK_IS_MATCH) {
				struct stksess *ts;

				if ((ts = stktable_lookup_key(rule->table.t, key)) != NULL) {
					if (!(s->flags & SN_ASSIGNED)) {
						struct eb32_node *node;
						void *ptr;

						/* srv found in table */
						ptr = stktable_data_ptr(rule->table.t, ts, STKTABLE_DT_SERVER_ID);
						node = eb32_lookup(&px->conf.used_server_id, stktable_data_cast(ptr, server_id));
						if (node) {
							struct server *srv;

							srv = container_of(node, struct server, conf.id);
							if ((srv->state != SRV_ST_STOPPED) ||
							    (px->options & PR_O_PERSIST) ||
							    (s->flags & SN_FORCE_PRST)) {
								s->flags |= SN_DIRECT | SN_ASSIGNED;
								s->target = &srv->obj_type;
							}
						}
					}
					stktable_touch(rule->table.t, ts, 1);
				}
			}
			if (rule->flags & STK_IS_STORE) {
				if (s->store_count < (sizeof(s->store) / sizeof(s->store[0]))) {
					struct stksess *ts;

					ts = stksess_new(rule->table.t, key);
					if (ts) {
						s->store[s->store_count].table = rule->table.t;
						s->store[s->store_count++].ts = ts;
					}
				}
			}
		}
	}

	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;
	return 1;
}

/* This stream analyser works on a response. It applies all store rules on it
 * then returns 1. The data must already be present in the buffer otherwise
 * they won't match. It always returns 1.
 */
static int process_store_rules(struct session *s, struct channel *rep, int an_bit)
{
	struct proxy    *px   = s->be;
	struct sticking_rule  *rule;
	int i;
	int nbreq = s->store_count;

	DPRINTF(stderr,"[%u] %s: session=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		rep,
		rep->rex, rep->wex,
		rep->flags,
		rep->buf->i,
		rep->analysers);

	list_for_each_entry(rule, &px->storersp_rules, list) {
		int ret = 1 ;

		/* Only the first stick store-response of each table is applied
		 * and other ones are ignored. The purpose is to allow complex
		 * configurations which look for multiple entries by decreasing
		 * order of precision and to stop at the first which matches.
		 * An example could be a store of a set-cookie value, with a
		 * fallback to a parameter found in a 302 redirect.
		 *
		 * The store-response rules are not allowed to override the
		 * store-request rules for the same table, but they may coexist.
		 * Thus we can have up to one store-request entry and one store-
		 * response entry for the same table at any time.
		 */
		for (i = nbreq; i < s->store_count; i++) {
			if (rule->table.t == s->store[i].table)
				break;
		}

		/* skip existing entries for this table */
		if (i < s->store_count)
			continue;

		if (rule->cond) {
	                ret = acl_exec_cond(rule->cond, px, s, &s->txn, SMP_OPT_DIR_RES|SMP_OPT_FINAL);
	                ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			struct stktable_key *key;

			key = stktable_fetch_key(rule->table.t, px, s, &s->txn, SMP_OPT_DIR_RES|SMP_OPT_FINAL, rule->expr, NULL);
			if (!key)
				continue;

			if (s->store_count < (sizeof(s->store) / sizeof(s->store[0]))) {
				struct stksess *ts;

				ts = stksess_new(rule->table.t, key);
				if (ts) {
					s->store[s->store_count].table = rule->table.t;
					s->store[s->store_count++].ts = ts;
				}
			}
		}
	}

	/* process store request and store response */
	for (i = 0; i < s->store_count; i++) {
		struct stksess *ts;
		void *ptr;

		if (objt_server(s->target) && objt_server(s->target)->flags & SRV_F_NON_STICK) {
			stksess_free(s->store[i].table, s->store[i].ts);
			s->store[i].ts = NULL;
			continue;
		}

		ts = stktable_lookup(s->store[i].table, s->store[i].ts);
		if (ts) {
			/* the entry already existed, we can free ours */
			stktable_touch(s->store[i].table, ts, 1);
			stksess_free(s->store[i].table, s->store[i].ts);
		}
		else
			ts = stktable_store(s->store[i].table, s->store[i].ts, 1);

		s->store[i].ts = NULL;
		ptr = stktable_data_ptr(s->store[i].table, ts, STKTABLE_DT_SERVER_ID);
		stktable_data_cast(ptr, server_id) = objt_server(s->target)->puid;
	}
	s->store_count = 0; /* everything is stored */

	rep->analysers &= ~an_bit;
	rep->analyse_exp = TICK_ETERNITY;
	return 1;
}

/* This macro is very specific to the function below. See the comments in
 * process_session() below to understand the logic and the tests.
 */
#define UPDATE_ANALYSERS(real, list, back, flag) {			\
		list = (((list) & ~(flag)) | ~(back)) & (real);		\
		back = real;						\
		if (!(list))						\
			break;						\
		if (((list) ^ ((list) & ((list) - 1))) < (flag))	\
			continue;					\
}

/* Processes the client, server, request and response jobs of a session task,
 * then puts it back to the wait queue in a clean state, or cleans up its
 * resources if it must be deleted. Returns in <next> the date the task wants
 * to be woken up, or TICK_ETERNITY. In order not to call all functions for
 * nothing too many times, the request and response buffers flags are monitored
 * and each function is called only if at least another function has changed at
 * least one flag it is interested in.
 */
struct task *process_session(struct task *t)
{
	struct server *srv;
	struct session *s = t->context;
	unsigned int rqf_last, rpf_last;
	unsigned int rq_prod_last, rq_cons_last;
	unsigned int rp_cons_last, rp_prod_last;
	unsigned int req_ana_back;

	//DPRINTF(stderr, "%s:%d: cs=%d ss=%d(%d) rqf=0x%08x rpf=0x%08x\n", __FUNCTION__, __LINE__,
	//        s->si[0].state, s->si[1].state, s->si[1].err_type, s->req->flags, s->rep->flags);

	/* this data may be no longer valid, clear it */
	memset(&s->txn.auth, 0, sizeof(s->txn.auth));

	/* This flag must explicitly be set every time */
	s->req->flags &= ~(CF_READ_NOEXP|CF_WAKE_WRITE);
	s->rep->flags &= ~(CF_READ_NOEXP|CF_WAKE_WRITE);

	/* Keep a copy of req/rep flags so that we can detect shutdowns */
	rqf_last = s->req->flags & ~CF_MASK_ANALYSER;
	rpf_last = s->rep->flags & ~CF_MASK_ANALYSER;

	/* we don't want the stream interface functions to recursively wake us up */
	if (s->req->prod->owner == t)
		s->req->prod->flags |= SI_FL_DONT_WAKE;
	if (s->req->cons->owner == t)
		s->req->cons->flags |= SI_FL_DONT_WAKE;

	/* 1a: Check for low level timeouts if needed. We just set a flag on
	 * stream interfaces when their timeouts have expired.
	 */
	if (unlikely(t->state & TASK_WOKEN_TIMER)) {
		stream_int_check_timeouts(&s->si[0]);
		stream_int_check_timeouts(&s->si[1]);

		/* check channel timeouts, and close the corresponding stream interfaces
		 * for future reads or writes. Note: this will also concern upper layers
		 * but we do not touch any other flag. We must be careful and correctly
		 * detect state changes when calling them.
		 */

		channel_check_timeouts(s->req);

		if (unlikely((s->req->flags & (CF_SHUTW|CF_WRITE_TIMEOUT)) == CF_WRITE_TIMEOUT)) {
			s->req->cons->flags |= SI_FL_NOLINGER;
			si_shutw(s->req->cons);
		}

		if (unlikely((s->req->flags & (CF_SHUTR|CF_READ_TIMEOUT)) == CF_READ_TIMEOUT)) {
			if (s->req->prod->flags & SI_FL_NOHALF)
				s->req->prod->flags |= SI_FL_NOLINGER;
			si_shutr(s->req->prod);
		}

		channel_check_timeouts(s->rep);

		if (unlikely((s->rep->flags & (CF_SHUTW|CF_WRITE_TIMEOUT)) == CF_WRITE_TIMEOUT)) {
			s->rep->cons->flags |= SI_FL_NOLINGER;
			si_shutw(s->rep->cons);
		}

		if (unlikely((s->rep->flags & (CF_SHUTR|CF_READ_TIMEOUT)) == CF_READ_TIMEOUT)) {
			if (s->rep->prod->flags & SI_FL_NOHALF)
				s->rep->prod->flags |= SI_FL_NOLINGER;
			si_shutr(s->rep->prod);
		}

		/* Once in a while we're woken up because the task expires. But
		 * this does not necessarily mean that a timeout has been reached.
		 * So let's not run a whole session processing if only an expiration
		 * timeout needs to be refreshed.
		 */
		if (!((s->req->flags | s->rep->flags) &
		      (CF_SHUTR|CF_READ_ACTIVITY|CF_READ_TIMEOUT|CF_SHUTW|
		       CF_WRITE_ACTIVITY|CF_WRITE_TIMEOUT|CF_ANA_TIMEOUT)) &&
		    !((s->si[0].flags | s->si[1].flags) & (SI_FL_EXP|SI_FL_ERR)) &&
		    ((t->state & TASK_WOKEN_ANY) == TASK_WOKEN_TIMER))
			goto update_exp_and_leave;
	}

	/* 1b: check for low-level errors reported at the stream interface.
	 * First we check if it's a retryable error (in which case we don't
	 * want to tell the buffer). Otherwise we report the error one level
	 * upper by setting flags into the buffers. Note that the side towards
	 * the client cannot have connect (hence retryable) errors. Also, the
	 * connection setup code must be able to deal with any type of abort.
	 */
	srv = objt_server(s->target);
	if (unlikely(s->si[0].flags & SI_FL_ERR)) {
		if (s->si[0].state == SI_ST_EST || s->si[0].state == SI_ST_DIS) {
			si_shutr(&s->si[0]);
			si_shutw(&s->si[0]);
			stream_int_report_error(&s->si[0]);
			if (!(s->req->analysers) && !(s->rep->analysers)) {
				s->be->be_counters.cli_aborts++;
				s->fe->fe_counters.cli_aborts++;
				if (srv)
					srv->counters.cli_aborts++;
				if (!(s->flags & SN_ERR_MASK))
					s->flags |= SN_ERR_CLICL;
				if (!(s->flags & SN_FINST_MASK))
					s->flags |= SN_FINST_D;
			}
		}
	}

	if (unlikely(s->si[1].flags & SI_FL_ERR)) {
		if (s->si[1].state == SI_ST_EST || s->si[1].state == SI_ST_DIS) {
			si_shutr(&s->si[1]);
			si_shutw(&s->si[1]);
			stream_int_report_error(&s->si[1]);
			s->be->be_counters.failed_resp++;
			if (srv)
				srv->counters.failed_resp++;
			if (!(s->req->analysers) && !(s->rep->analysers)) {
				s->be->be_counters.srv_aborts++;
				s->fe->fe_counters.srv_aborts++;
				if (srv)
					srv->counters.srv_aborts++;
				if (!(s->flags & SN_ERR_MASK))
					s->flags |= SN_ERR_SRVCL;
				if (!(s->flags & SN_FINST_MASK))
					s->flags |= SN_FINST_D;
			}
		}
		/* note: maybe we should process connection errors here ? */
	}

	if (s->si[1].state == SI_ST_CON) {
		/* we were trying to establish a connection on the server side,
		 * maybe it succeeded, maybe it failed, maybe we timed out, ...
		 */
		if (unlikely(!sess_update_st_con_tcp(s, &s->si[1])))
			sess_update_st_cer(s, &s->si[1]);
		else if (s->si[1].state == SI_ST_EST)
			sess_establish(s, &s->si[1]);

		/* state is now one of SI_ST_CON (still in progress), SI_ST_EST
		 * (established), SI_ST_DIS (abort), SI_ST_CLO (last error),
		 * SI_ST_ASS/SI_ST_TAR/SI_ST_REQ for retryable errors.
		 */
	}

	rq_prod_last = s->si[0].state;
	rq_cons_last = s->si[1].state;
	rp_cons_last = s->si[0].state;
	rp_prod_last = s->si[1].state;

 resync_stream_interface:
	/* Check for connection closure */

	DPRINTF(stderr,
		"[%u] %s:%d: task=%p s=%p, sfl=0x%08x, rq=%p, rp=%p, exp(r,w)=%u,%u rqf=%08x rpf=%08x rqh=%d rqt=%d rph=%d rpt=%d cs=%d ss=%d, cet=0x%x set=0x%x retr=%d\n",
		now_ms, __FUNCTION__, __LINE__,
		t,
		s, s->flags,
		s->req, s->rep,
		s->req->rex, s->rep->wex,
		s->req->flags, s->rep->flags,
		s->req->buf->i, s->req->buf->o, s->rep->buf->i, s->rep->buf->o, s->rep->cons->state, s->req->cons->state,
		s->rep->cons->err_type, s->req->cons->err_type,
		s->req->cons->conn_retries);

	/* nothing special to be done on client side */
	if (unlikely(s->req->prod->state == SI_ST_DIS))
		s->req->prod->state = SI_ST_CLO;

	/* When a server-side connection is released, we have to count it and
	 * check for pending connections on this server.
	 */
	if (unlikely(s->req->cons->state == SI_ST_DIS)) {
		s->req->cons->state = SI_ST_CLO;
		srv = objt_server(s->target);
		if (srv) {
			if (s->flags & SN_CURR_SESS) {
				s->flags &= ~SN_CURR_SESS;
				srv->cur_sess--;
			}
			sess_change_server(s, NULL);
			if (may_dequeue_tasks(srv, s->be))
				process_srv_queue(srv);
		}
	}

	/*
	 * Note: of the transient states (REQ, CER, DIS), only REQ may remain
	 * at this point.
	 */

 resync_request:
	/* Analyse request */
	if (((s->req->flags & ~rqf_last) & CF_MASK_ANALYSER) ||
	    ((s->req->flags ^ rqf_last) & CF_MASK_STATIC) ||
	    s->si[0].state != rq_prod_last ||
	    s->si[1].state != rq_cons_last) {
		unsigned int flags = s->req->flags;

		if (s->req->prod->state >= SI_ST_EST) {
			int max_loops = global.tune.maxpollevents;
			unsigned int ana_list;
			unsigned int ana_back;

			/* it's up to the analysers to stop new connections,
			 * disable reading or closing. Note: if an analyser
			 * disables any of these bits, it is responsible for
			 * enabling them again when it disables itself, so
			 * that other analysers are called in similar conditions.
			 */
			channel_auto_read(s->req);
			channel_auto_connect(s->req);
			channel_auto_close(s->req);

			/* We will call all analysers for which a bit is set in
			 * s->req->analysers, following the bit order from LSB
			 * to MSB. The analysers must remove themselves from
			 * the list when not needed. Any analyser may return 0
			 * to break out of the loop, either because of missing
			 * data to take a decision, or because it decides to
			 * kill the session. We loop at least once through each
			 * analyser, and we may loop again if other analysers
			 * are added in the middle.
			 *
			 * We build a list of analysers to run. We evaluate all
			 * of these analysers in the order of the lower bit to
			 * the higher bit. This ordering is very important.
			 * An analyser will often add/remove other analysers,
			 * including itself. Any changes to itself have no effect
			 * on the loop. If it removes any other analysers, we
			 * want those analysers not to be called anymore during
			 * this loop. If it adds an analyser that is located
			 * after itself, we want it to be scheduled for being
			 * processed during the loop. If it adds an analyser
			 * which is located before it, we want it to switch to
			 * it immediately, even if it has already been called
			 * once but removed since.
			 *
			 * In order to achieve this, we compare the analyser
			 * list after the call with a copy of it before the
			 * call. The work list is fed with analyser bits that
			 * appeared during the call. Then we compare previous
			 * work list with the new one, and check the bits that
			 * appeared. If the lowest of these bits is lower than
			 * the current bit, it means we have enabled a previous
			 * analyser and must immediately loop again.
			 */

			ana_list = ana_back = s->req->analysers;
			while (ana_list && max_loops--) {
				/* Warning! ensure that analysers are always placed in ascending order! */

				if (ana_list & AN_REQ_INSPECT_FE) {
					if (!tcp_inspect_request(s, s->req, AN_REQ_INSPECT_FE))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_INSPECT_FE);
				}

				if (ana_list & AN_REQ_WAIT_HTTP) {
					if (!http_wait_for_request(s, s->req, AN_REQ_WAIT_HTTP))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_WAIT_HTTP);
				}

				if (ana_list & AN_REQ_HTTP_PROCESS_FE) {
					if (!http_process_req_common(s, s->req, AN_REQ_HTTP_PROCESS_FE, s->fe))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_HTTP_PROCESS_FE);
				}

				if (ana_list & AN_REQ_SWITCHING_RULES) {
					if (!process_switching_rules(s, s->req, AN_REQ_SWITCHING_RULES))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_SWITCHING_RULES);
				}

				if (ana_list & AN_REQ_INSPECT_BE) {
					if (!tcp_inspect_request(s, s->req, AN_REQ_INSPECT_BE))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_INSPECT_BE);
				}

				if (ana_list & AN_REQ_HTTP_PROCESS_BE) {
					if (!http_process_req_common(s, s->req, AN_REQ_HTTP_PROCESS_BE, s->be))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_HTTP_PROCESS_BE);
				}

				if (ana_list & AN_REQ_HTTP_TARPIT) {
					if (!http_process_tarpit(s, s->req, AN_REQ_HTTP_TARPIT))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_HTTP_TARPIT);
				}

				if (ana_list & AN_REQ_SRV_RULES) {
					if (!process_server_rules(s, s->req, AN_REQ_SRV_RULES))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_SRV_RULES);
				}

				if (ana_list & AN_REQ_HTTP_INNER) {
					if (!http_process_request(s, s->req, AN_REQ_HTTP_INNER))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_HTTP_INNER);
				}

				if (ana_list & AN_REQ_HTTP_BODY) {
					if (!http_wait_for_request_body(s, s->req, AN_REQ_HTTP_BODY))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_HTTP_BODY);
				}

				if (ana_list & AN_REQ_PRST_RDP_COOKIE) {
					if (!tcp_persist_rdp_cookie(s, s->req, AN_REQ_PRST_RDP_COOKIE))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_PRST_RDP_COOKIE);
				}

				if (ana_list & AN_REQ_STICKING_RULES) {
					if (!process_sticking_rules(s, s->req, AN_REQ_STICKING_RULES))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_STICKING_RULES);
				}

				if (ana_list & AN_REQ_HTTP_XFER_BODY) {
					if (!http_request_forward_body(s, s->req, AN_REQ_HTTP_XFER_BODY))
						break;
					UPDATE_ANALYSERS(s->req->analysers, ana_list, ana_back, AN_REQ_HTTP_XFER_BODY);
				}
				break;
			}
		}

		rq_prod_last = s->si[0].state;
		rq_cons_last = s->si[1].state;
		s->req->flags &= ~CF_WAKE_ONCE;
		rqf_last = s->req->flags;

		if ((s->req->flags ^ flags) & CF_MASK_STATIC)
			goto resync_request;
	}

	/* we'll monitor the request analysers while parsing the response,
	 * because some response analysers may indirectly enable new request
	 * analysers (eg: HTTP keep-alive).
	 */
	req_ana_back = s->req->analysers;

 resync_response:
	/* Analyse response */

	if (((s->rep->flags & ~rpf_last) & CF_MASK_ANALYSER) ||
		 (s->rep->flags ^ rpf_last) & CF_MASK_STATIC ||
		 s->si[0].state != rp_cons_last ||
		 s->si[1].state != rp_prod_last) {
		unsigned int flags = s->rep->flags;

		if ((s->rep->flags & CF_MASK_ANALYSER) &&
		    (s->rep->analysers & AN_REQ_WAIT_HTTP)) {
			/* Due to HTTP pipelining, the HTTP request analyser might be waiting
			 * for some free space in the response buffer, so we might need to call
			 * it when something changes in the response buffer, but still we pass
			 * it the request buffer. Note that the SI state might very well still
			 * be zero due to us returning a flow of redirects!
			 */
			s->rep->analysers &= ~AN_REQ_WAIT_HTTP;
			s->req->flags |= CF_WAKE_ONCE;
		}

		if (s->rep->prod->state >= SI_ST_EST) {
			int max_loops = global.tune.maxpollevents;
			unsigned int ana_list;
			unsigned int ana_back;

			/* it's up to the analysers to stop disable reading or
			 * closing. Note: if an analyser disables any of these
			 * bits, it is responsible for enabling them again when
			 * it disables itself, so that other analysers are called
			 * in similar conditions.
			 */
			channel_auto_read(s->rep);
			channel_auto_close(s->rep);

			/* We will call all analysers for which a bit is set in
			 * s->rep->analysers, following the bit order from LSB
			 * to MSB. The analysers must remove themselves from
			 * the list when not needed. Any analyser may return 0
			 * to break out of the loop, either because of missing
			 * data to take a decision, or because it decides to
			 * kill the session. We loop at least once through each
			 * analyser, and we may loop again if other analysers
			 * are added in the middle.
			 */

			ana_list = ana_back = s->rep->analysers;
			while (ana_list && max_loops--) {
				/* Warning! ensure that analysers are always placed in ascending order! */

				if (ana_list & AN_RES_INSPECT) {
					if (!tcp_inspect_response(s, s->rep, AN_RES_INSPECT))
						break;
					UPDATE_ANALYSERS(s->rep->analysers, ana_list, ana_back, AN_RES_INSPECT);
				}

				if (ana_list & AN_RES_WAIT_HTTP) {
					if (!http_wait_for_response(s, s->rep, AN_RES_WAIT_HTTP))
						break;
					UPDATE_ANALYSERS(s->rep->analysers, ana_list, ana_back, AN_RES_WAIT_HTTP);
				}

				if (ana_list & AN_RES_STORE_RULES) {
					if (!process_store_rules(s, s->rep, AN_RES_STORE_RULES))
						break;
					UPDATE_ANALYSERS(s->rep->analysers, ana_list, ana_back, AN_RES_STORE_RULES);
				}

				if (ana_list & AN_RES_HTTP_PROCESS_BE) {
					if (!http_process_res_common(s, s->rep, AN_RES_HTTP_PROCESS_BE, s->be))
						break;
					UPDATE_ANALYSERS(s->rep->analysers, ana_list, ana_back, AN_RES_HTTP_PROCESS_BE);
				}

				if (ana_list & AN_RES_HTTP_XFER_BODY) {
					if (!http_response_forward_body(s, s->rep, AN_RES_HTTP_XFER_BODY))
						break;
					UPDATE_ANALYSERS(s->rep->analysers, ana_list, ana_back, AN_RES_HTTP_XFER_BODY);
				}
				break;
			}
		}

		rp_cons_last = s->si[0].state;
		rp_prod_last = s->si[1].state;
		rpf_last = s->rep->flags;

		if ((s->rep->flags ^ flags) & CF_MASK_STATIC)
			goto resync_response;
	}

	/* maybe someone has added some request analysers, so we must check and loop */
	if (s->req->analysers & ~req_ana_back)
		goto resync_request;

	if ((s->req->flags & ~rqf_last) & CF_MASK_ANALYSER)
		goto resync_request;

	/* FIXME: here we should call protocol handlers which rely on
	 * both buffers.
	 */


	/*
	 * Now we propagate unhandled errors to the session. Normally
	 * we're just in a data phase here since it means we have not
	 * seen any analyser who could set an error status.
	 */
	srv = objt_server(s->target);
	if (unlikely(!(s->flags & SN_ERR_MASK))) {
		if (s->req->flags & (CF_READ_ERROR|CF_READ_TIMEOUT|CF_WRITE_ERROR|CF_WRITE_TIMEOUT)) {
			/* Report it if the client got an error or a read timeout expired */
			s->req->analysers = 0;
			if (s->req->flags & CF_READ_ERROR) {
				s->be->be_counters.cli_aborts++;
				s->fe->fe_counters.cli_aborts++;
				if (srv)
					srv->counters.cli_aborts++;
				s->flags |= SN_ERR_CLICL;
			}
			else if (s->req->flags & CF_READ_TIMEOUT) {
				s->be->be_counters.cli_aborts++;
				s->fe->fe_counters.cli_aborts++;
				if (srv)
					srv->counters.cli_aborts++;
				s->flags |= SN_ERR_CLITO;
			}
			else if (s->req->flags & CF_WRITE_ERROR) {
				s->be->be_counters.srv_aborts++;
				s->fe->fe_counters.srv_aborts++;
				if (srv)
					srv->counters.srv_aborts++;
				s->flags |= SN_ERR_SRVCL;
			}
			else {
				s->be->be_counters.srv_aborts++;
				s->fe->fe_counters.srv_aborts++;
				if (srv)
					srv->counters.srv_aborts++;
				s->flags |= SN_ERR_SRVTO;
			}
			sess_set_term_flags(s);
		}
		else if (s->rep->flags & (CF_READ_ERROR|CF_READ_TIMEOUT|CF_WRITE_ERROR|CF_WRITE_TIMEOUT)) {
			/* Report it if the server got an error or a read timeout expired */
			s->rep->analysers = 0;
			if (s->rep->flags & CF_READ_ERROR) {
				s->be->be_counters.srv_aborts++;
				s->fe->fe_counters.srv_aborts++;
				if (srv)
					srv->counters.srv_aborts++;
				s->flags |= SN_ERR_SRVCL;
			}
			else if (s->rep->flags & CF_READ_TIMEOUT) {
				s->be->be_counters.srv_aborts++;
				s->fe->fe_counters.srv_aborts++;
				if (srv)
					srv->counters.srv_aborts++;
				s->flags |= SN_ERR_SRVTO;
			}
			else if (s->rep->flags & CF_WRITE_ERROR) {
				s->be->be_counters.cli_aborts++;
				s->fe->fe_counters.cli_aborts++;
				if (srv)
					srv->counters.cli_aborts++;
				s->flags |= SN_ERR_CLICL;
			}
			else {
				s->be->be_counters.cli_aborts++;
				s->fe->fe_counters.cli_aborts++;
				if (srv)
					srv->counters.cli_aborts++;
				s->flags |= SN_ERR_CLITO;
			}
			sess_set_term_flags(s);
		}
	}

	/*
	 * Here we take care of forwarding unhandled data. This also includes
	 * connection establishments and shutdown requests.
	 */


	/* If noone is interested in analysing data, it's time to forward
	 * everything. We configure the buffer to forward indefinitely.
	 * Note that we're checking CF_SHUTR_NOW as an indication of a possible
	 * recent call to channel_abort().
	 */
	if (unlikely(!s->req->analysers &&
	    !(s->req->flags & (CF_SHUTW|CF_SHUTR_NOW)) &&
	    (s->req->prod->state >= SI_ST_EST) &&
	    (s->req->to_forward != CHN_INFINITE_FORWARD))) {
		/* This buffer is freewheeling, there's no analyser
		 * attached to it. If any data are left in, we'll permit them to
		 * move.
		 */
		channel_auto_read(s->req);
		channel_auto_connect(s->req);
		channel_auto_close(s->req);
		buffer_flush(s->req->buf);

		/* We'll let data flow between the producer (if still connected)
		 * to the consumer (which might possibly not be connected yet).
		 */
		if (!(s->req->flags & (CF_SHUTR|CF_SHUTW_NOW)))
			channel_forward(s->req, CHN_INFINITE_FORWARD);
	}

	/* check if it is wise to enable kernel splicing to forward request data */
	if (!(s->req->flags & (CF_KERN_SPLICING|CF_SHUTR)) &&
	    s->req->to_forward &&
	    (global.tune.options & GTUNE_USE_SPLICE) &&
	    (objt_conn(s->si[0].end) && __objt_conn(s->si[0].end)->xprt && __objt_conn(s->si[0].end)->xprt->rcv_pipe) &&
	    (objt_conn(s->si[1].end) && __objt_conn(s->si[1].end)->xprt && __objt_conn(s->si[1].end)->xprt->snd_pipe) &&
	    (pipes_used < global.maxpipes) &&
	    (((s->fe->options2|s->be->options2) & PR_O2_SPLIC_REQ) ||
	     (((s->fe->options2|s->be->options2) & PR_O2_SPLIC_AUT) &&
	      (s->req->flags & CF_STREAMER_FAST)))) {
		s->req->flags |= CF_KERN_SPLICING;
	}

	/* reflect what the L7 analysers have seen last */
	rqf_last = s->req->flags;

	/*
	 * Now forward all shutdown requests between both sides of the buffer
	 */

	/* first, let's check if the request buffer needs to shutdown(write), which may
	 * happen either because the input is closed or because we want to force a close
	 * once the server has begun to respond. If a half-closed timeout is set, we adjust
	 * the other side's timeout as well.
	 */
	if (unlikely((s->req->flags & (CF_SHUTW|CF_SHUTW_NOW|CF_AUTO_CLOSE|CF_SHUTR)) ==
		     (CF_AUTO_CLOSE|CF_SHUTR))) {
		channel_shutw_now(s->req);
		if (tick_isset(s->fe->timeout.clientfin)) {
			s->rep->wto = s->fe->timeout.clientfin;
			s->rep->wex = tick_add(now_ms, s->rep->wto);
		}
	}

	/* shutdown(write) pending */
	if (unlikely((s->req->flags & (CF_SHUTW|CF_SHUTW_NOW)) == CF_SHUTW_NOW &&
		     channel_is_empty(s->req))) {
		if (s->req->flags & CF_READ_ERROR)
			s->req->cons->flags |= SI_FL_NOLINGER;
		si_shutw(s->req->cons);
		if (tick_isset(s->be->timeout.serverfin)) {
			s->rep->rto = s->be->timeout.serverfin;
			s->rep->rex = tick_add(now_ms, s->rep->rto);
		}
	}

	/* shutdown(write) done on server side, we must stop the client too */
	if (unlikely((s->req->flags & (CF_SHUTW|CF_SHUTR|CF_SHUTR_NOW)) == CF_SHUTW &&
		     !s->req->analysers))
		channel_shutr_now(s->req);

	/* shutdown(read) pending */
	if (unlikely((s->req->flags & (CF_SHUTR|CF_SHUTR_NOW)) == CF_SHUTR_NOW)) {
		if (s->req->prod->flags & SI_FL_NOHALF)
			s->req->prod->flags |= SI_FL_NOLINGER;
		si_shutr(s->req->prod);
		if (tick_isset(s->fe->timeout.clientfin)) {
			s->rep->wto = s->fe->timeout.clientfin;
			s->rep->wex = tick_add(now_ms, s->rep->wto);
		}
	}

	/* it's possible that an upper layer has requested a connection setup or abort.
	 * There are 2 situations where we decide to establish a new connection :
	 *  - there are data scheduled for emission in the buffer
	 *  - the CF_AUTO_CONNECT flag is set (active connection)
	 */
	if (s->req->cons->state == SI_ST_INI) {
		if (!(s->req->flags & CF_SHUTW)) {
			if ((s->req->flags & CF_AUTO_CONNECT) || !channel_is_empty(s->req)) {
				/* If we have an appctx, there is no connect method, so we
				 * immediately switch to the connected state, otherwise we
				 * perform a connection request.
				 */
				s->req->cons->state = SI_ST_REQ; /* new connection requested */
				s->req->cons->conn_retries = s->be->conn_retries;
			}
		}
		else {
			s->req->cons->state = SI_ST_CLO; /* shutw+ini = abort */
			channel_shutw_now(s->req);        /* fix buffer flags upon abort */
			channel_shutr_now(s->rep);
		}
	}


	/* we may have a pending connection request, or a connection waiting
	 * for completion.
	 */
	if (s->si[1].state >= SI_ST_REQ && s->si[1].state < SI_ST_CON) {
		do {
			/* nb: step 1 might switch from QUE to ASS, but we first want
			 * to give a chance to step 2 to perform a redirect if needed.
			 */
			if (s->si[1].state != SI_ST_REQ)
				sess_update_stream_int(s, &s->si[1]);
			if (s->si[1].state == SI_ST_REQ)
				sess_prepare_conn_req(s, &s->si[1]);

			/* applets directly go to the ESTABLISHED state. Similarly,
			 * servers experience the same fate when their connection
			 * is reused.
			 */
			if (unlikely(s->si[1].state == SI_ST_EST))
				sess_establish(s, &s->si[1]);

			/* Now we can add the server name to a header (if requested) */
			/* check for HTTP mode and proxy server_name_hdr_name != NULL */
			if ((s->si[1].state >= SI_ST_CON) &&
			    (s->be->server_id_hdr_name != NULL) &&
			    (s->be->mode == PR_MODE_HTTP) &&
			    objt_server(s->target)) {
				http_send_name_header(&s->txn, s->be, objt_server(s->target)->id);
			}

			srv = objt_server(s->target);
			if (s->si[1].state == SI_ST_ASS && srv && srv->rdr_len && (s->flags & SN_REDIRECTABLE))
				http_perform_server_redirect(s, &s->si[1]);
		} while (s->si[1].state == SI_ST_ASS);
	}

	/* Benchmarks have shown that it's optimal to do a full resync now */
	if (s->req->prod->state == SI_ST_DIS || s->req->cons->state == SI_ST_DIS)
		goto resync_stream_interface;

	/* otherwise we want to check if we need to resync the req buffer or not */
	if ((s->req->flags ^ rqf_last) & CF_MASK_STATIC)
		goto resync_request;

	/* perform output updates to the response buffer */

	/* If noone is interested in analysing data, it's time to forward
	 * everything. We configure the buffer to forward indefinitely.
	 * Note that we're checking CF_SHUTR_NOW as an indication of a possible
	 * recent call to channel_abort().
	 */
	if (unlikely(!s->rep->analysers &&
	    !(s->rep->flags & (CF_SHUTW|CF_SHUTR_NOW)) &&
	    (s->rep->prod->state >= SI_ST_EST) &&
	    (s->rep->to_forward != CHN_INFINITE_FORWARD))) {
		/* This buffer is freewheeling, there's no analyser
		 * attached to it. If any data are left in, we'll permit them to
		 * move.
		 */
		channel_auto_read(s->rep);
		channel_auto_close(s->rep);
		buffer_flush(s->rep->buf);

		/* We'll let data flow between the producer (if still connected)
		 * to the consumer.
		 */
		if (!(s->rep->flags & (CF_SHUTR|CF_SHUTW_NOW)))
			channel_forward(s->rep, CHN_INFINITE_FORWARD);

		/* if we have no analyser anymore in any direction and have a
		 * tunnel timeout set, use it now. Note that we must respect
		 * the half-closed timeouts as well.
		 */
		if (!s->req->analysers && s->be->timeout.tunnel) {
			s->req->rto = s->req->wto = s->rep->rto = s->rep->wto =
				s->be->timeout.tunnel;

			if ((s->req->flags & CF_SHUTR) && tick_isset(s->fe->timeout.clientfin))
				s->rep->wto = s->fe->timeout.clientfin;
			if ((s->req->flags & CF_SHUTW) && tick_isset(s->be->timeout.serverfin))
				s->rep->rto = s->be->timeout.serverfin;
			if ((s->rep->flags & CF_SHUTR) && tick_isset(s->be->timeout.serverfin))
				s->req->wto = s->be->timeout.serverfin;
			if ((s->rep->flags & CF_SHUTW) && tick_isset(s->fe->timeout.clientfin))
				s->req->rto = s->fe->timeout.clientfin;

			s->req->rex = tick_add(now_ms, s->req->rto);
			s->req->wex = tick_add(now_ms, s->req->wto);
			s->rep->rex = tick_add(now_ms, s->rep->rto);
			s->rep->wex = tick_add(now_ms, s->rep->wto);
		}
	}

	/* check if it is wise to enable kernel splicing to forward response data */
	if (!(s->rep->flags & (CF_KERN_SPLICING|CF_SHUTR)) &&
	    s->rep->to_forward &&
	    (global.tune.options & GTUNE_USE_SPLICE) &&
	    (objt_conn(s->si[0].end) && __objt_conn(s->si[0].end)->xprt && __objt_conn(s->si[0].end)->xprt->snd_pipe) &&
	    (objt_conn(s->si[1].end) && __objt_conn(s->si[1].end)->xprt && __objt_conn(s->si[1].end)->xprt->rcv_pipe) &&
	    (pipes_used < global.maxpipes) &&
	    (((s->fe->options2|s->be->options2) & PR_O2_SPLIC_RTR) ||
	     (((s->fe->options2|s->be->options2) & PR_O2_SPLIC_AUT) &&
	      (s->rep->flags & CF_STREAMER_FAST)))) {
		s->rep->flags |= CF_KERN_SPLICING;
	}

	/* reflect what the L7 analysers have seen last */
	rpf_last = s->rep->flags;

	/*
	 * Now forward all shutdown requests between both sides of the buffer
	 */

	/*
	 * FIXME: this is probably where we should produce error responses.
	 */

	/* first, let's check if the response buffer needs to shutdown(write) */
	if (unlikely((s->rep->flags & (CF_SHUTW|CF_SHUTW_NOW|CF_AUTO_CLOSE|CF_SHUTR)) ==
		     (CF_AUTO_CLOSE|CF_SHUTR))) {
		channel_shutw_now(s->rep);
		if (tick_isset(s->be->timeout.serverfin)) {
			s->req->wto = s->be->timeout.serverfin;
			s->req->wex = tick_add(now_ms, s->req->wto);
		}
	}

	/* shutdown(write) pending */
	if (unlikely((s->rep->flags & (CF_SHUTW|CF_SHUTW_NOW)) == CF_SHUTW_NOW &&
		     channel_is_empty(s->rep))) {
		si_shutw(s->rep->cons);
		if (tick_isset(s->fe->timeout.clientfin)) {
			s->req->rto = s->fe->timeout.clientfin;
			s->req->rex = tick_add(now_ms, s->req->rto);
		}
	}

	/* shutdown(write) done on the client side, we must stop the server too */
	if (unlikely((s->rep->flags & (CF_SHUTW|CF_SHUTR|CF_SHUTR_NOW)) == CF_SHUTW) &&
	    !s->rep->analysers)
		channel_shutr_now(s->rep);

	/* shutdown(read) pending */
	if (unlikely((s->rep->flags & (CF_SHUTR|CF_SHUTR_NOW)) == CF_SHUTR_NOW)) {
		if (s->rep->prod->flags & SI_FL_NOHALF)
			s->rep->prod->flags |= SI_FL_NOLINGER;
		si_shutr(s->rep->prod);
		if (tick_isset(s->be->timeout.serverfin)) {
			s->req->wto = s->be->timeout.serverfin;
			s->req->wex = tick_add(now_ms, s->req->wto);
		}
	}

	if (s->req->prod->state == SI_ST_DIS || s->req->cons->state == SI_ST_DIS)
		goto resync_stream_interface;

	if (s->req->flags != rqf_last)
		goto resync_request;

	if ((s->rep->flags ^ rpf_last) & CF_MASK_STATIC)
		goto resync_response;

	/* we're interested in getting wakeups again */
	s->req->prod->flags &= ~SI_FL_DONT_WAKE;
	s->req->cons->flags &= ~SI_FL_DONT_WAKE;

	/* This is needed only when debugging is enabled, to indicate
	 * client-side or server-side close. Please note that in the unlikely
	 * event where both sides would close at once, the sequence is reported
	 * on the server side first.
	 */
	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) ||
		      (global.mode & MODE_VERBOSE)))) {
		if (s->si[1].state == SI_ST_CLO &&
		    s->si[1].prev_state == SI_ST_EST) {
			chunk_printf(&trash, "%08x:%s.srvcls[%04x:%04x]\n",
				      s->uniq_id, s->be->id,
			              objt_conn(s->si[0].end) ? (unsigned short)objt_conn(s->si[0].end)->t.sock.fd : -1,
			              objt_conn(s->si[1].end) ? (unsigned short)objt_conn(s->si[1].end)->t.sock.fd : -1);
			shut_your_big_mouth_gcc(write(1, trash.str, trash.len));
		}

		if (s->si[0].state == SI_ST_CLO &&
		    s->si[0].prev_state == SI_ST_EST) {
			chunk_printf(&trash, "%08x:%s.clicls[%04x:%04x]\n",
				      s->uniq_id, s->be->id,
			              objt_conn(s->si[0].end) ? (unsigned short)objt_conn(s->si[0].end)->t.sock.fd : -1,
			              objt_conn(s->si[1].end) ? (unsigned short)objt_conn(s->si[1].end)->t.sock.fd : -1);
			shut_your_big_mouth_gcc(write(1, trash.str, trash.len));
		}
	}

	if (likely((s->rep->cons->state != SI_ST_CLO) ||
		   (s->req->cons->state > SI_ST_INI && s->req->cons->state < SI_ST_CLO))) {

		if ((s->fe->options & PR_O_CONTSTATS) && (s->flags & SN_BE_ASSIGNED))
			session_process_counters(s);

		if (s->rep->cons->state == SI_ST_EST && obj_type(s->rep->cons->end) != OBJ_TYPE_APPCTX)
			si_update(s->rep->cons);

		if (s->req->cons->state == SI_ST_EST && obj_type(s->req->cons->end) != OBJ_TYPE_APPCTX)
			si_update(s->req->cons);

		s->req->flags &= ~(CF_READ_NULL|CF_READ_PARTIAL|CF_WRITE_NULL|CF_WRITE_PARTIAL|CF_READ_ATTACHED);
		s->rep->flags &= ~(CF_READ_NULL|CF_READ_PARTIAL|CF_WRITE_NULL|CF_WRITE_PARTIAL|CF_READ_ATTACHED);
		s->si[0].prev_state = s->si[0].state;
		s->si[1].prev_state = s->si[1].state;
		s->si[0].flags &= ~(SI_FL_ERR|SI_FL_EXP);
		s->si[1].flags &= ~(SI_FL_ERR|SI_FL_EXP);

		/* Trick: if a request is being waiting for the server to respond,
		 * and if we know the server can timeout, we don't want the timeout
		 * to expire on the client side first, but we're still interested
		 * in passing data from the client to the server (eg: POST). Thus,
		 * we can cancel the client's request timeout if the server's
		 * request timeout is set and the server has not yet sent a response.
		 */

		if ((s->rep->flags & (CF_AUTO_CLOSE|CF_SHUTR)) == 0 &&
		    (tick_isset(s->req->wex) || tick_isset(s->rep->rex))) {
			s->req->flags |= CF_READ_NOEXP;
			s->req->rex = TICK_ETERNITY;
		}

		/* When any of the stream interfaces is attached to an applet,
		 * we have to call it here. Note that this one may wake the
		 * task up again. If at least one applet was called, the current
		 * task might have been woken up, in which case we don't want it
		 * to be requeued to the wait queue but rather to the run queue
		 * to run ASAP. The bitwise "or" in the condition ensures that
		 * both functions are always called and that we wake up if at
		 * least one did something.
		 */
		if ((si_applet_call(s->req->cons) | si_applet_call(s->rep->cons)) != 0) {
			if (task_in_rq(t)) {
				t->expire = TICK_ETERNITY;
				return t;
			}
		}

	update_exp_and_leave:
		t->expire = tick_first(tick_first(s->req->rex, s->req->wex),
				       tick_first(s->rep->rex, s->rep->wex));
		if (s->req->analysers)
			t->expire = tick_first(t->expire, s->req->analyse_exp);

		if (s->si[0].exp)
			t->expire = tick_first(t->expire, s->si[0].exp);

		if (s->si[1].exp)
			t->expire = tick_first(t->expire, s->si[1].exp);

#ifdef DEBUG_FULL
		fprintf(stderr,
			"[%u] queuing with exp=%u req->rex=%u req->wex=%u req->ana_exp=%u"
			" rep->rex=%u rep->wex=%u, si[0].exp=%u, si[1].exp=%u, cs=%d, ss=%d\n",
			now_ms, t->expire, s->req->rex, s->req->wex, s->req->analyse_exp,
			s->rep->rex, s->rep->wex, s->si[0].exp, s->si[1].exp, s->si[0].state, s->si[1].state);
#endif

#ifdef DEBUG_DEV
		/* this may only happen when no timeout is set or in case of an FSM bug */
		if (!tick_isset(t->expire))
			ABORT_NOW();
#endif
		return t; /* nothing more to do */
	}

	s->fe->feconn--;
	if (s->flags & SN_BE_ASSIGNED)
		s->be->beconn--;
	jobs--;
	if (s->listener) {
		if (!(s->listener->options & LI_O_UNLIMITED))
			actconn--;
		s->listener->nbconn--;
		if (s->listener->state == LI_FULL)
			resume_listener(s->listener);

		/* Dequeues all of the listeners waiting for a resource */
		if (!LIST_ISEMPTY(&global_listener_queue))
			dequeue_all_listeners(&global_listener_queue);

		if (!LIST_ISEMPTY(&s->fe->listener_queue) &&
		    (!s->fe->fe_sps_lim || freq_ctr_remain(&s->fe->fe_sess_per_sec, s->fe->fe_sps_lim, 0) > 0))
			dequeue_all_listeners(&s->fe->listener_queue);
	}

	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)))) {
		chunk_printf(&trash, "%08x:%s.closed[%04x:%04x]\n",
			      s->uniq_id, s->be->id,
		              objt_conn(s->si[0].end) ? (unsigned short)objt_conn(s->si[0].end)->t.sock.fd : -1,
		              objt_conn(s->si[1].end) ? (unsigned short)objt_conn(s->si[1].end)->t.sock.fd : -1);
		shut_your_big_mouth_gcc(write(1, trash.str, trash.len));
	}

	s->logs.t_close = tv_ms_elapsed(&s->logs.tv_accept, &now);
	session_process_counters(s);

	if (s->txn.status) {
		int n;

		n = s->txn.status / 100;
		if (n < 1 || n > 5)
			n = 0;

		if (s->fe->mode == PR_MODE_HTTP) {
			s->fe->fe_counters.p.http.rsp[n]++;
			if (s->comp_algo && (s->flags & SN_COMP_READY))
				s->fe->fe_counters.p.http.comp_rsp++;
		}
		if ((s->flags & SN_BE_ASSIGNED) &&
		    (s->be->mode == PR_MODE_HTTP)) {
			s->be->be_counters.p.http.rsp[n]++;
			s->be->be_counters.p.http.cum_req++;
			if (s->comp_algo && (s->flags & SN_COMP_READY))
				s->be->be_counters.p.http.comp_rsp++;
		}
	}

	/* let's do a final log if we need it */
	if (!LIST_ISEMPTY(&s->fe->logformat) && s->logs.logwait &&
	    !(s->flags & SN_MONITOR) &&
	    (!(s->fe->options & PR_O_NULLNOLOG) || s->req->total)) {
		s->do_log(s);
	}

	/* update time stats for this session */
	session_update_time_stats(s);

	/* the task MUST not be in the run queue anymore */
	session_free(s);
	task_delete(t);
	task_free(t);
	return NULL;
}

/* Update the session's backend and server time stats */
void session_update_time_stats(struct session *s)
{
	int t_request;
	int t_queue;
	int t_connect;
	int t_data;
	int t_close;
	struct server *srv;

	t_request = 0;
	t_queue   = s->logs.t_queue;
	t_connect = s->logs.t_connect;
	t_close   = s->logs.t_close;
	t_data    = s->logs.t_data;

	if (s->be->mode != PR_MODE_HTTP)
		t_data = t_connect;

	if (t_connect < 0 || t_data < 0)
		return;

	if (tv_isge(&s->logs.tv_request, &s->logs.tv_accept))
		t_request = tv_ms_elapsed(&s->logs.tv_accept, &s->logs.tv_request);

	t_data    -= t_connect;
	t_connect -= t_queue;
	t_queue   -= t_request;

	srv = objt_server(s->target);
	if (srv) {
		swrate_add(&srv->counters.q_time, TIME_STATS_SAMPLES, t_queue);
		swrate_add(&srv->counters.c_time, TIME_STATS_SAMPLES, t_connect);
		swrate_add(&srv->counters.d_time, TIME_STATS_SAMPLES, t_data);
		swrate_add(&srv->counters.t_time, TIME_STATS_SAMPLES, t_close);
	}
	swrate_add(&s->be->be_counters.q_time, TIME_STATS_SAMPLES, t_queue);
	swrate_add(&s->be->be_counters.c_time, TIME_STATS_SAMPLES, t_connect);
	swrate_add(&s->be->be_counters.d_time, TIME_STATS_SAMPLES, t_data);
	swrate_add(&s->be->be_counters.t_time, TIME_STATS_SAMPLES, t_close);
}

/*
 * This function adjusts sess->srv_conn and maintains the previous and new
 * server's served session counts. Setting newsrv to NULL is enough to release
 * current connection slot. This function also notifies any LB algo which might
 * expect to be informed about any change in the number of active sessions on a
 * server.
 */
void sess_change_server(struct session *sess, struct server *newsrv)
{
	if (sess->srv_conn == newsrv)
		return;

	if (sess->srv_conn) {
		sess->srv_conn->served--;
		if (sess->srv_conn->proxy->lbprm.server_drop_conn)
			sess->srv_conn->proxy->lbprm.server_drop_conn(sess->srv_conn);
		session_del_srv_conn(sess);
	}

	if (newsrv) {
		newsrv->served++;
		if (newsrv->proxy->lbprm.server_take_conn)
			newsrv->proxy->lbprm.server_take_conn(newsrv);
		session_add_srv_conn(sess, newsrv);
	}
}

/* Handle server-side errors for default protocols. It is called whenever a a
 * connection setup is aborted or a request is aborted in queue. It sets the
 * session termination flags so that the caller does not have to worry about
 * them. It's installed as ->srv_error for the server-side stream_interface.
 */
void default_srv_error(struct session *s, struct stream_interface *si)
{
	int err_type = si->err_type;
	int err = 0, fin = 0;

	if (err_type & SI_ET_QUEUE_ABRT) {
		err = SN_ERR_CLICL;
		fin = SN_FINST_Q;
	}
	else if (err_type & SI_ET_CONN_ABRT) {
		err = SN_ERR_CLICL;
		fin = SN_FINST_C;
	}
	else if (err_type & SI_ET_QUEUE_TO) {
		err = SN_ERR_SRVTO;
		fin = SN_FINST_Q;
	}
	else if (err_type & SI_ET_QUEUE_ERR) {
		err = SN_ERR_SRVCL;
		fin = SN_FINST_Q;
	}
	else if (err_type & SI_ET_CONN_TO) {
		err = SN_ERR_SRVTO;
		fin = SN_FINST_C;
	}
	else if (err_type & SI_ET_CONN_ERR) {
		err = SN_ERR_SRVCL;
		fin = SN_FINST_C;
	}
	else if (err_type & SI_ET_CONN_RES) {
		err = SN_ERR_RESOURCE;
		fin = SN_FINST_C;
	}
	else /* SI_ET_CONN_OTHER and others */ {
		err = SN_ERR_INTERNAL;
		fin = SN_FINST_C;
	}

	if (!(s->flags & SN_ERR_MASK))
		s->flags |= err;
	if (!(s->flags & SN_FINST_MASK))
		s->flags |= fin;
}

/* kill a session and set the termination flags to <why> (one of SN_ERR_*) */
void session_shutdown(struct session *session, int why)
{
	if (session->req->flags & (CF_SHUTW|CF_SHUTW_NOW))
		return;

	channel_shutw_now(session->req);
	channel_shutr_now(session->rep);
	session->task->nice = 1024;
	if (!(session->flags & SN_ERR_MASK))
		session->flags |= why;
	task_wakeup(session->task, TASK_WOKEN_OTHER);
}

/************************************************************************/
/*           All supported ACL keywords must be declared here.          */
/************************************************************************/

/* Returns a pointer to a stkctr depending on the fetch keyword name.
 * It is designed to be called as sc[0-9]_* sc_* or src_* exclusively.
 * sc[0-9]_* will return a pointer to the respective field in the
 * session <l4>. sc_* requires an UINT argument specifying the stick
 * counter number. src_* will fill a locally allocated structure with
 * the table and entry corresponding to what is specified with src_*.
 * NULL may be returned if the designated stkctr is not tracked. For
 * the sc_* and sc[0-9]_* forms, an optional table argument may be
 * passed. When present, the currently tracked key is then looked up
 * in the specified table instead of the current table. The purpose is
 * to be able to convery multiple values per key (eg: have gpc0 from
 * multiple tables).
 */
static struct stkctr *
smp_fetch_sc_stkctr(struct session *l4, const struct arg *args, const char *kw)
{
	static struct stkctr stkctr;
	struct stksess *stksess;
	unsigned int num = kw[2] - '0';
	int arg = 0;

	if (num == '_' - '0') {
		/* sc_* variant, args[0] = ctr# (mandatory) */
		num = args[arg++].data.uint;
		if (num >= MAX_SESS_STKCTR)
			return NULL;
	}
	else if (num > 9) { /* src_* variant, args[0] = table */
		struct stktable_key *key;
		struct connection *conn = objt_conn(l4->si[0].end);

		if (!conn)
			return NULL;

		key = addr_to_stktable_key(&conn->addr.from, args->data.prx->table.type);
		if (!key)
			return NULL;

		stkctr.table = &args->data.prx->table;
		stkctr_set_entry(&stkctr, stktable_lookup_key(stkctr.table, key));
		return &stkctr;
	}

	/* Here, <num> contains the counter number from 0 to 9 for
	 * the sc[0-9]_ form, or even higher using sc_(num) if needed.
	 * args[arg] is the first optional argument.
	 */
	stksess = stkctr_entry(&l4->stkctr[num]);
	if (!stksess)
		return NULL;

	if (unlikely(args[arg].type == ARGT_TAB)) {
		/* an alternate table was specified, let's look up the same key there */
		stkctr.table = &args[arg].data.prx->table;
		stkctr_set_entry(&stkctr, stktable_lookup(stkctr.table, stksess));
		return &stkctr;
	}
	return &l4->stkctr[num];
}

/* set return a boolean indicating if the requested session counter is
 * currently being tracked or not.
 * Supports being called as "sc[0-9]_tracked" only.
 */
static int
smp_fetch_sc_tracked(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                      const struct arg *args, struct sample *smp, const char *kw)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_BOOL;
	smp->data.uint = !!smp_fetch_sc_stkctr(l4, args, kw);
	return 1;
}

/* set <smp> to the General Purpose Counter 0 value from the session's tracked
 * frontend counters or from the src.
 * Supports being called as "sc[0-9]_get_gpc0" or "src_get_gpc0" only. Value
 * zero is returned if the key is new.
 */
static int
smp_fetch_sc_get_gpc0(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                      const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;

	if (stkctr_entry(stkctr) != NULL) {
		void *ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC0);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, gpc0);
	}
	return 1;
}

/* set <smp> to the General Purpose Counter 0's event rate from the session's
 * tracked frontend counters or from the src.
 * Supports being called as "sc[0-9]_gpc0_rate" or "src_gpc0_rate" only.
 * Value zero is returned if the key is new.
 */
static int
smp_fetch_sc_gpc0_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC0_RATE);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = read_freq_ctr_period(&stktable_data_cast(ptr, gpc0_rate),
		                                      stkctr->table->data_arg[STKTABLE_DT_GPC0_RATE].u);
	}
	return 1;
}

/* Increment the General Purpose Counter 0 value from the session's tracked
 * frontend counters and return it into temp integer.
 * Supports being called as "sc[0-9]_inc_gpc0" or "src_inc_gpc0" only.
 */
static int
smp_fetch_sc_inc_gpc0(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                      const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		/* First, update gpc0_rate if it's tracked. Second, update its
		 * gpc0 if tracked. Returns gpc0's value otherwise the curr_ctr.
		 */
		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC0_RATE);
		if (ptr) {
			update_freq_ctr_period(&stktable_data_cast(ptr, gpc0_rate),
					       stkctr->table->data_arg[STKTABLE_DT_GPC0_RATE].u, 1);
			smp->data.uint = (&stktable_data_cast(ptr, gpc0_rate))->curr_ctr;
		}

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC0);
		if (ptr)
			smp->data.uint = ++stktable_data_cast(ptr, gpc0);

	}
	return 1;
}

/* Clear the General Purpose Counter 0 value from the session's tracked
 * frontend counters and return its previous value into temp integer.
 * Supports being called as "sc[0-9]_clr_gpc0" or "src_clr_gpc0" only.
 */
static int
smp_fetch_sc_clr_gpc0(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                      const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC0);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, gpc0);
		stktable_data_cast(ptr, gpc0) = 0;
	}
	return 1;
}

/* set <smp> to the cumulated number of connections from the session's tracked
 * frontend counters. Supports being called as "sc[0-9]_conn_cnt" or
 * "src_conn_cnt" only.
 */
static int
smp_fetch_sc_conn_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                      const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_CONN_CNT);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, conn_cnt);
	}
	return 1;
}

/* set <smp> to the connection rate from the session's tracked frontend
 * counters. Supports being called as "sc[0-9]_conn_rate" or "src_conn_rate"
 * only.
 */
static int
smp_fetch_sc_conn_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_CONN_RATE);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = read_freq_ctr_period(&stktable_data_cast(ptr, conn_rate),
					       stkctr->table->data_arg[STKTABLE_DT_CONN_RATE].u);
	}
	return 1;
}

/* set temp integer to the number of connections from the session's source address
 * in the table pointed to by expr, after updating it.
 * Accepts exactly 1 argument of type table.
 */
static int
smp_fetch_src_updt_conn_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                            const struct arg *args, struct sample *smp, const char *kw)
{
	struct connection *conn = objt_conn(l4->si[0].end);
	struct stksess *ts;
	struct stktable_key *key;
	void *ptr;

	if (!conn)
		return 0;

	key = addr_to_stktable_key(&conn->addr.from, px->table.type);
	if (!key)
		return 0;

	px = args->data.prx;

	if ((ts = stktable_update_key(&px->table, key)) == NULL)
		/* entry does not exist and could not be created */
		return 0;

	ptr = stktable_data_ptr(&px->table, ts, STKTABLE_DT_CONN_CNT);
	if (!ptr)
		return 0; /* parameter not stored in this table */

	smp->type = SMP_T_UINT;
	smp->data.uint = ++stktable_data_cast(ptr, conn_cnt);
	smp->flags = SMP_F_VOL_TEST;
	return 1;
}

/* set <smp> to the number of concurrent connections from the session's tracked
 * frontend counters. Supports being called as "sc[0-9]_conn_cur" or
 * "src_conn_cur" only.
 */
static int
smp_fetch_sc_conn_cur(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                      const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_CONN_CUR);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, conn_cur);
	}
	return 1;
}

/* set <smp> to the cumulated number of sessions from the session's tracked
 * frontend counters. Supports being called as "sc[0-9]_sess_cnt" or
 * "src_sess_cnt" only.
 */
static int
smp_fetch_sc_sess_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                      const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_SESS_CNT);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, sess_cnt);
	}
	return 1;
}

/* set <smp> to the session rate from the session's tracked frontend counters.
 * Supports being called as "sc[0-9]_sess_rate" or "src_sess_rate" only.
 */
static int
smp_fetch_sc_sess_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_SESS_RATE);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = read_freq_ctr_period(&stktable_data_cast(ptr, sess_rate),
					       stkctr->table->data_arg[STKTABLE_DT_SESS_RATE].u);
	}
	return 1;
}

/* set <smp> to the cumulated number of HTTP requests from the session's tracked
 * frontend counters. Supports being called as "sc[0-9]_http_req_cnt" or
 * "src_http_req_cnt" only.
 */
static int
smp_fetch_sc_http_req_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                          const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_REQ_CNT);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, http_req_cnt);
	}
	return 1;
}

/* set <smp> to the HTTP request rate from the session's tracked frontend
 * counters. Supports being called as "sc[0-9]_http_req_rate" or
 * "src_http_req_rate" only.
 */
static int
smp_fetch_sc_http_req_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                           const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_REQ_RATE);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = read_freq_ctr_period(&stktable_data_cast(ptr, http_req_rate),
					       stkctr->table->data_arg[STKTABLE_DT_HTTP_REQ_RATE].u);
	}
	return 1;
}

/* set <smp> to the cumulated number of HTTP requests errors from the session's
 * tracked frontend counters. Supports being called as "sc[0-9]_http_err_cnt" or
 * "src_http_err_cnt" only.
 */
static int
smp_fetch_sc_http_err_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                          const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_ERR_CNT);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, http_err_cnt);
	}
	return 1;
}

/* set <smp> to the HTTP request error rate from the session's tracked frontend
 * counters. Supports being called as "sc[0-9]_http_err_rate" or
 * "src_http_err_rate" only.
 */
static int
smp_fetch_sc_http_err_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                           const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_ERR_RATE);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = read_freq_ctr_period(&stktable_data_cast(ptr, http_err_rate),
					       stkctr->table->data_arg[STKTABLE_DT_HTTP_ERR_RATE].u);
	}
	return 1;
}

/* set <smp> to the number of kbytes received from clients, as found in the
 * session's tracked frontend counters. Supports being called as
 * "sc[0-9]_kbytes_in" or "src_kbytes_in" only.
 */
static int
smp_fetch_sc_kbytes_in(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_BYTES_IN_CNT);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, bytes_in_cnt) >> 10;
	}
	return 1;
}

/* set <smp> to the data rate received from clients in bytes/s, as found
 * in the session's tracked frontend counters. Supports being called as
 * "sc[0-9]_bytes_in_rate" or "src_bytes_in_rate" only.
 */
static int
smp_fetch_sc_bytes_in_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                           const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_BYTES_IN_RATE);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = read_freq_ctr_period(&stktable_data_cast(ptr, bytes_in_rate),
					       stkctr->table->data_arg[STKTABLE_DT_BYTES_IN_RATE].u);
	}
	return 1;
}

/* set <smp> to the number of kbytes sent to clients, as found in the
 * session's tracked frontend counters. Supports being called as
 * "sc[0-9]_kbytes_out" or "src_kbytes_out" only.
 */
static int
smp_fetch_sc_kbytes_out(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_BYTES_OUT_CNT);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = stktable_data_cast(ptr, bytes_out_cnt) >> 10;
	}
	return 1;
}

/* set <smp> to the data rate sent to clients in bytes/s, as found in the
 * session's tracked frontend counters. Supports being called as
 * "sc[0-9]_bytes_out_rate" or "src_bytes_out_rate" only.
 */
static int
smp_fetch_sc_bytes_out_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                            const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_BYTES_OUT_RATE);
		if (!ptr)
			return 0; /* parameter not stored */
		smp->data.uint = read_freq_ctr_period(&stktable_data_cast(ptr, bytes_out_rate),
					       stkctr->table->data_arg[STKTABLE_DT_BYTES_OUT_RATE].u);
	}
	return 1;
}

/* set <smp> to the number of active trackers on the SC entry in the session's
 * tracked frontend counters. Supports being called as "sc[0-9]_trackers" only.
 */
static int
smp_fetch_sc_trackers(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp, const char *kw)
{
	struct stkctr *stkctr = smp_fetch_sc_stkctr(l4, args, kw);

	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = stkctr_entry(stkctr)->ref_cnt;
	return 1;
}

/* set temp integer to the number of used entries in the table pointed to by expr.
 * Accepts exactly 1 argument of type table.
 */
static int
smp_fetch_table_cnt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                    const struct arg *args, struct sample *smp, const char *kw)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = args->data.prx->table.current;
	return 1;
}

/* set temp integer to the number of free entries in the table pointed to by expr.
 * Accepts exactly 1 argument of type table.
 */
static int
smp_fetch_table_avl(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                    const struct arg *args, struct sample *smp, const char *kw)
{
	px = args->data.prx;
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = px->table.size - px->table.current;
	return 1;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct acl_kw_list acl_kws = {ILH, {
	{ /* END */ },
}};

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct sample_fetch_kw_list smp_fetch_keywords = {ILH, {
	{ "sc_bytes_in_rate",   smp_fetch_sc_bytes_in_rate,  ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc_bytes_out_rate",  smp_fetch_sc_bytes_out_rate, ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc_clr_gpc0",        smp_fetch_sc_clr_gpc0,       ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc_conn_cnt",        smp_fetch_sc_conn_cnt,       ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc_conn_cur",        smp_fetch_sc_conn_cur,       ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc_conn_rate",       smp_fetch_sc_conn_rate,      ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc_get_gpc0",        smp_fetch_sc_get_gpc0,       ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc_gpc0_rate",       smp_fetch_sc_gpc0_rate,      ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc_http_err_cnt",    smp_fetch_sc_http_err_cnt,   ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc_http_err_rate",   smp_fetch_sc_http_err_rate,  ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc_http_req_cnt",    smp_fetch_sc_http_req_cnt,   ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc_http_req_rate",   smp_fetch_sc_http_req_rate,  ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc_inc_gpc0",        smp_fetch_sc_inc_gpc0,       ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc_kbytes_in",       smp_fetch_sc_kbytes_in,      ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "sc_kbytes_out",      smp_fetch_sc_kbytes_out,     ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "sc_sess_cnt",        smp_fetch_sc_sess_cnt,       ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc_sess_rate",       smp_fetch_sc_sess_rate,      ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc_tracked",         smp_fetch_sc_tracked,        ARG2(1,UINT,TAB), NULL, SMP_T_BOOL, SMP_USE_INTRN, },
	{ "sc_trackers",        smp_fetch_sc_trackers,       ARG2(1,UINT,TAB), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc0_bytes_in_rate",  smp_fetch_sc_bytes_in_rate,  ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc0_bytes_out_rate", smp_fetch_sc_bytes_out_rate, ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc0_clr_gpc0",       smp_fetch_sc_clr_gpc0,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc0_conn_cnt",       smp_fetch_sc_conn_cnt,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc0_conn_cur",       smp_fetch_sc_conn_cur,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc0_conn_rate",      smp_fetch_sc_conn_rate,      ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc0_get_gpc0",       smp_fetch_sc_get_gpc0,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc0_gpc0_rate",      smp_fetch_sc_gpc0_rate,      ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc0_http_err_cnt",   smp_fetch_sc_http_err_cnt,   ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc0_http_err_rate",  smp_fetch_sc_http_err_rate,  ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc0_http_req_cnt",   smp_fetch_sc_http_req_cnt,   ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc0_http_req_rate",  smp_fetch_sc_http_req_rate,  ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc0_inc_gpc0",       smp_fetch_sc_inc_gpc0,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc0_kbytes_in",      smp_fetch_sc_kbytes_in,      ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "sc0_kbytes_out",     smp_fetch_sc_kbytes_out,     ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "sc0_sess_cnt",       smp_fetch_sc_sess_cnt,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc0_sess_rate",      smp_fetch_sc_sess_rate,      ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc0_tracked",        smp_fetch_sc_tracked,        ARG1(0,TAB),      NULL, SMP_T_BOOL, SMP_USE_INTRN, },
	{ "sc0_trackers",       smp_fetch_sc_trackers,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc1_bytes_in_rate",  smp_fetch_sc_bytes_in_rate,  ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc1_bytes_out_rate", smp_fetch_sc_bytes_out_rate, ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc1_clr_gpc0",       smp_fetch_sc_clr_gpc0,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc1_conn_cnt",       smp_fetch_sc_conn_cnt,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc1_conn_cur",       smp_fetch_sc_conn_cur,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc1_conn_rate",      smp_fetch_sc_conn_rate,      ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc1_get_gpc0",       smp_fetch_sc_get_gpc0,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc1_gpc0_rate",      smp_fetch_sc_gpc0_rate,      ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc1_http_err_cnt",   smp_fetch_sc_http_err_cnt,   ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc1_http_err_rate",  smp_fetch_sc_http_err_rate,  ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc1_http_req_cnt",   smp_fetch_sc_http_req_cnt,   ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc1_http_req_rate",  smp_fetch_sc_http_req_rate,  ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc1_inc_gpc0",       smp_fetch_sc_inc_gpc0,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc1_kbytes_in",      smp_fetch_sc_kbytes_in,      ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "sc1_kbytes_out",     smp_fetch_sc_kbytes_out,     ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "sc1_sess_cnt",       smp_fetch_sc_sess_cnt,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc1_sess_rate",      smp_fetch_sc_sess_rate,      ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc1_tracked",        smp_fetch_sc_tracked,        ARG1(0,TAB),      NULL, SMP_T_BOOL, SMP_USE_INTRN, },
	{ "sc1_trackers",       smp_fetch_sc_trackers,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc2_bytes_in_rate",  smp_fetch_sc_bytes_in_rate,  ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc2_bytes_out_rate", smp_fetch_sc_bytes_out_rate, ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc2_clr_gpc0",       smp_fetch_sc_clr_gpc0,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc2_conn_cnt",       smp_fetch_sc_conn_cnt,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc2_conn_cur",       smp_fetch_sc_conn_cur,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc2_conn_rate",      smp_fetch_sc_conn_rate,      ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc2_get_gpc0",       smp_fetch_sc_get_gpc0,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc2_gpc0_rate",      smp_fetch_sc_gpc0_rate,      ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc2_http_err_cnt",   smp_fetch_sc_http_err_cnt,   ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc2_http_err_rate",  smp_fetch_sc_http_err_rate,  ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc2_http_req_cnt",   smp_fetch_sc_http_req_cnt,   ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc2_http_req_rate",  smp_fetch_sc_http_req_rate,  ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc2_inc_gpc0",       smp_fetch_sc_inc_gpc0,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc2_kbytes_in",      smp_fetch_sc_kbytes_in,      ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "sc2_kbytes_out",     smp_fetch_sc_kbytes_out,     ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "sc2_sess_cnt",       smp_fetch_sc_sess_cnt,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc2_sess_rate",      smp_fetch_sc_sess_rate,      ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "sc2_tracked",        smp_fetch_sc_tracked,        ARG1(0,TAB),      NULL, SMP_T_BOOL, SMP_USE_INTRN, },
	{ "sc2_trackers",       smp_fetch_sc_trackers,       ARG1(0,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "src_bytes_in_rate",  smp_fetch_sc_bytes_in_rate,  ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "src_bytes_out_rate", smp_fetch_sc_bytes_out_rate, ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "src_clr_gpc0",       smp_fetch_sc_clr_gpc0,       ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "src_conn_cnt",       smp_fetch_sc_conn_cnt,       ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "src_conn_cur",       smp_fetch_sc_conn_cur,       ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "src_conn_rate",      smp_fetch_sc_conn_rate,      ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "src_get_gpc0",       smp_fetch_sc_get_gpc0,       ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "src_gpc0_rate",      smp_fetch_sc_gpc0_rate,      ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "src_http_err_cnt",   smp_fetch_sc_http_err_cnt,   ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "src_http_err_rate",  smp_fetch_sc_http_err_rate,  ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "src_http_req_cnt",   smp_fetch_sc_http_req_cnt,   ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "src_http_req_rate",  smp_fetch_sc_http_req_rate,  ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "src_inc_gpc0",       smp_fetch_sc_inc_gpc0,       ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "src_kbytes_in",      smp_fetch_sc_kbytes_in,      ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "src_kbytes_out",     smp_fetch_sc_kbytes_out,     ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "src_sess_cnt",       smp_fetch_sc_sess_cnt,       ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "src_sess_rate",      smp_fetch_sc_sess_rate,      ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "src_updt_conn_cnt",  smp_fetch_src_updt_conn_cnt, ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_L4CLI, },
	{ "table_avl",          smp_fetch_table_avl,         ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "table_cnt",          smp_fetch_table_cnt,         ARG1(1,TAB),      NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ /* END */ },
}};

__attribute__((constructor))
static void __session_init(void)
{
	sample_register_fetches(&smp_fetch_keywords);
	acl_register_keywords(&acl_kws);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
