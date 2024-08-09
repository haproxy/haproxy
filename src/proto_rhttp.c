#include <stdio.h>
#include <string.h>

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/errors.h>
#include <haproxy/intops.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/proto_tcp.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/server.h>
#include <haproxy/session.h>
#include <haproxy/sock.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/task.h>

#include <haproxy/proto_rhttp.h>

struct proto_fam proto_fam_rhttp = {
	.name = "rhttp",
	.sock_domain = AF_INET,
	.sock_family = AF_CUST_RHTTP_SRV,
	.real_family = AF_CUST_RHTTP_SRV,
	.bind = rhttp_bind_receiver,
};

struct protocol proto_rhttp = {
	.name = "rev",

	/* connection layer (no outgoing connection) */
	.listen      = rhttp_bind_listener,
	.enable      = rhttp_enable_listener,
	.disable     = rhttp_disable_listener,
	.suspend     = rhttp_suspend_listener,
	.add         = default_add_listener,
	.unbind      = rhttp_unbind_receiver,
	.resume      = default_resume_listener,
	.accept_conn = rhttp_accept_conn,
	.bind_tid_prep = rhttp_bind_tid_prep,

	/* address family */
	.fam  = &proto_fam_rhttp,

	/* socket layer */
	.proto_type     = PROTO_TYPE_STREAM,
	.sock_type      = SOCK_STREAM,
	.sock_prot      = IPPROTO_TCP,
	.rx_listening   = rhttp_accepting_conn,
	.receivers      = LIST_HEAD_INIT(proto_rhttp.receivers),
};

static struct connection *new_reverse_conn(struct listener *l, struct server *srv)
{
	struct connection *conn = conn_new(srv);
	struct sockaddr_storage *bind_addr = NULL;
	struct session *sess = NULL;
	if (!conn)
		goto err;

	HA_ATOMIC_INC(&th_ctx->nb_rhttp_conns);

	/* session origin is only set after reversal. This ensures fetches
	 * will be functional only after reversal, in particular src/dst.
	 */
	sess = session_new(l->bind_conf->frontend, l, NULL);
	if (!sess)
		goto err;

	conn_set_owner(conn, sess, conn_session_free);
	conn_set_reverse(conn, &l->obj_type);

	if (alloc_bind_address(&bind_addr, srv, srv->proxy, NULL) != SRV_STATUS_OK)
		goto err;
	conn->src = bind_addr;

	sockaddr_alloc(&conn->dst, 0, 0);
	if (!conn->dst)
		goto err;
	*conn->dst = srv->addr;
	set_host_port(conn->dst, srv->svc_port);

	conn->send_proxy_ofs = 0;
	if (srv->pp_opts) {
		conn->flags |= CO_FL_SEND_PROXY;
		conn->send_proxy_ofs = 1; /* must compute size */
	}

	/* TODO support SOCKS4 */

	if (conn_prepare(conn, protocol_lookup(conn->dst->ss_family, PROTO_TYPE_STREAM, 0), srv->xprt))
		goto err;

	if (conn->ctrl->connect(conn, 0) != SF_ERR_NONE)
		goto err;

#ifdef USE_OPENSSL
	if (srv->ssl_ctx.sni) {
		struct sample *sni_smp = NULL;
		/* TODO remove NULL session which can cause crash depending on the SNI sample expr used. */
		sni_smp = sample_fetch_as_type(srv->proxy, sess, NULL,
		                               SMP_OPT_DIR_REQ | SMP_OPT_FINAL,
		                               srv->ssl_ctx.sni, SMP_T_STR);
		if (smp_make_safe(sni_smp))
			ssl_sock_set_servername(conn, sni_smp->data.u.str.area);
	}
#endif /* USE_OPENSSL */

	/* The CO_FL_SEND_PROXY flag may have been set by the connect method,
	 * if so, add our handshake pseudo-XPRT now.
	 */
	if (conn->flags & CO_FL_HANDSHAKE) {
		if (xprt_add_hs(conn) < 0)
			goto err;
	}

	if (conn_xprt_start(conn) < 0)
		goto err;

	if (!srv->use_ssl ||
	    (!srv->ssl_ctx.alpn_str && !srv->ssl_ctx.npn_str) ||
	    srv->mux_proto) {
		if (conn_install_mux_be(conn, NULL, sess, NULL) < 0)
			goto err;
	}

	return conn;

 err:
	if (l->rx.rhttp.state != LI_PRECONN_ST_ERR) {
		send_log(l->bind_conf->frontend, LOG_ERR,
		         "preconnect %s::%s: Error on conn allocation.\n",
		         l->bind_conf->frontend->id, l->bind_conf->rhttp_srvname);
		l->rx.rhttp.state = LI_PRECONN_ST_ERR;
	}

	/* No need to free session as conn.destroy_cb will take care of it. */
	if (conn) {
		conn_stop_tracking(conn);
		conn_xprt_shutw(conn);
		conn_xprt_close(conn);
		conn_sock_shutw(conn, 0);
		conn_ctrl_close(conn);

		if (conn->destroy_cb)
			conn->destroy_cb(conn);

		/* Mark connection as non-reversable. This prevents conn_free()
		 * to reschedule rhttp task on freeing a preconnect connection.
		 */
		conn->reverse.target = NULL;
		conn_free(conn);
	}

	return NULL;
}

/* Report that a connection used for preconnect on listener <l> is freed before
 * reversal is completed. This is used to cleanup any reference to the
 * connection and rearm a new preconnect attempt.
 */
void rhttp_notify_preconn_err(struct listener *l)
{
	/* Receiver must reference a reverse connection as pending. */
	BUG_ON(!l->rx.rhttp.pend_conn);

	/* Remove reference to the freed connection. */
	l->rx.rhttp.pend_conn = NULL;

	if (l->rx.rhttp.state != LI_PRECONN_ST_ERR) {
		send_log(l->bind_conf->frontend, LOG_ERR,
		        "preconnect %s::%s: Error encountered.\n",
		         l->bind_conf->frontend->id, l->bind_conf->rhttp_srvname);
		l->rx.rhttp.state = LI_PRECONN_ST_ERR;
	}

	/* Rearm a new preconnect attempt. */
	l->rx.rhttp.task->expire = MS_TO_TICKS(now_ms + 1000);
	task_queue(l->rx.rhttp.task);
}

/* Lookup over listener <l> threads for their current count of active reverse
 * HTTP connections. Returns the less loaded thread ID.
 */
static unsigned int select_thread(struct listener *l)
{
	unsigned long mask = l->rx.bind_thread & _HA_ATOMIC_LOAD(&tg->threads_enabled);
	unsigned int load_min = HA_ATOMIC_LOAD(&th_ctx->nb_rhttp_conns);
	unsigned int load_thr;
	unsigned int ret = tid;
	int i;

	/* Returns current tid if listener runs on one thread only. */
	if (!atleast2(mask))
		goto end;

	/* Loop over all threads and return the less loaded one. This needs to
	 * be just an approximation so it's not important if the selected
	 * thread load has varied since its selection.
	 */

	for (i = tg->base; mask; mask >>= 1, i++) {
		if (!(mask & 0x1))
			continue;

		load_thr = HA_ATOMIC_LOAD(&ha_thread_ctx[i].nb_rhttp_conns);
		if (load_min > load_thr) {
			ret = i;
			load_min = load_thr;
		}
	}

 end:
	return ret;
}

/* Detach <task> from its thread and assign it to <new_tid> thread. The task is
 * queued to be woken up on the new thread.
 */
static void task_migrate(struct task *task, uint new_tid)
{
	task_unlink_wq(task);
	task->expire = TICK_ETERNITY;
	task_set_thread(task, new_tid);
	task_wakeup(task, TASK_WOKEN_MSG);
}

struct task *rhttp_process(struct task *task, void *ctx, unsigned int state)
{
	struct listener *l = ctx;
	struct connection *conn = l->rx.rhttp.pend_conn;

	if (conn) {
		/* Either connection is on error ot the connect timeout fired. */
		if (conn->flags & CO_FL_ERROR || tick_is_expired(task->expire, now_ms)) {
			/* If mux already instantiated, let it release the
			 * connection along with its context. Else do cleanup
			 * directly.
			 */
			if (conn->mux && conn->mux->destroy) {
				conn->mux->destroy(conn->ctx);
			}
			else {
				conn_stop_tracking(conn);
				conn_xprt_shutw(conn);
				conn_xprt_close(conn);
				conn_sock_shutw(conn, 0);
				conn_ctrl_close(conn);

				if (conn->destroy_cb)
					conn->destroy_cb(conn);
				conn_free(conn);
			}

			/* conn_free() must report preconnect failure using rhttp_notify_preconn_err(). */
			BUG_ON(l->rx.rhttp.pend_conn);

			l->rx.rhttp.task->expire = TICKS_TO_MS(now_ms);
		}
		else {
			/* Spurious receiver task woken up despite pend_conn not ready/on error. */
			BUG_ON(!(conn->flags & CO_FL_ACT_REVERSING));

			/* A connection is ready to be accepted. */
			listener_accept(l);
			l->rx.rhttp.task->expire = TICK_ETERNITY;
		}
	}
	else {
		struct server *srv = l->rx.rhttp.srv;

		if ((state & TASK_WOKEN_ANY) != TASK_WOKEN_MSG) {
			unsigned int new_tid = select_thread(l);
			if (new_tid != tid) {
				task_migrate(l->rx.rhttp.task, new_tid);
				return task;
			}
		}

		/* No pending reverse connection, prepare a new one. Store it in the
		 * listener and return NULL. Connection will be returned later after
		 * reversal is completed.
		 */
		conn = new_reverse_conn(l, srv);
		l->rx.rhttp.pend_conn = conn;

		/* On success task will be woken up by H2 mux after reversal. */
		l->rx.rhttp.task->expire = conn ?
		  tick_add_ifset(now_ms, srv->proxy->timeout.connect) :
		  MS_TO_TICKS(now_ms + 1000);
	}

	return task;
}

int rhttp_bind_receiver(struct receiver *rx, char **errmsg)
{
	rx->flags |= RX_F_BOUND;
	return ERR_NONE;
}

int rhttp_bind_listener(struct listener *listener, char *errmsg, int errlen)
{
	struct task *task;
	struct proxy *be;
	struct server *srv;
	struct ist be_name, sv_name;
	char *name = NULL;

	unsigned long mask;
	uint task_tid;

	if (listener->state != LI_ASSIGNED)
		return ERR_NONE; /* already bound */

	/* Retrieve the first thread usable for this listener. */
	mask = listener->rx.bind_thread & _HA_ATOMIC_LOAD(&tg->threads_enabled);
	task_tid = my_ffsl(mask) - 1 + ha_tgroup_info[listener->rx.bind_tgroup].base;
	if (!(task = task_new_on(task_tid))) {
		snprintf(errmsg, errlen, "Out of memory.");
		goto err;
	}

	task->process = rhttp_process;
	task->context = listener;
	listener->rx.rhttp.task = task;
	listener->rx.rhttp.state = LI_PRECONN_ST_STOP;

	/* Set maxconn which is defined via the special kw nbconn for reverse
	 * connect. Use a default value of 1 if not set. This guarantees that
	 * listener will be automatically re-enable each time it fell back below
	 * it due to a connection error.
	 */
	listener->bind_conf->maxconn = listener->bind_conf->rhttp_nbconn;
	if (!listener->bind_conf->maxconn)
		listener->bind_conf->maxconn = 1;

	name = strdup(listener->bind_conf->rhttp_srvname);
	if (!name) {
		snprintf(errmsg, errlen, "Out of memory.");
		goto err;
	}

	sv_name = ist(name);
	be_name = istsplit(&sv_name, '/');
	if (!istlen(sv_name)) {
		snprintf(errmsg, errlen, "Invalid server name: '%s'.", name);
		goto err;
	}

	if (!(be = proxy_be_by_name(ist0(be_name)))) {
		snprintf(errmsg, errlen, "No such backend: '%s'.", name);
		goto err;
	}
	if (!(srv = server_find_by_name(be, ist0(sv_name)))) {
		snprintf(errmsg, errlen, "No such server: '%s/%s'.", ist0(be_name), ist0(sv_name));
		goto err;
	}

	if (srv->flags & SRV_F_RHTTP) {
		snprintf(errmsg, errlen, "Cannot use reverse HTTP server '%s/%s' as target to a reverse bind.", ist0(be_name), ist0(sv_name));
		goto err;
	}

	if (srv_is_transparent(srv)) {
		snprintf(errmsg, errlen, "Cannot use transparent server '%s/%s' as target to a reverse bind.", ist0(be_name), ist0(sv_name));
		goto err;
	}

	/* Check that server uses HTTP/2 either with proto or ALPN. */
	if ((!srv->mux_proto || !isteqi(srv->mux_proto->token, ist("h2"))) &&
	    (!srv->use_ssl || !isteqi(ist(srv->ssl_ctx.alpn_str), ist("\x02h2")))) {
		snprintf(errmsg, errlen, "Cannot reverse connect with server '%s/%s' unless HTTP/2 is activated on it with either proto or alpn keyword.", name, ist0(sv_name));
		goto err;
	}

	/* Prevent dynamic source address settings. */
	if (((srv->conn_src.opts & CO_SRC_TPROXY_MASK) &&
	     (srv->conn_src.opts & CO_SRC_TPROXY_MASK) != CO_SRC_TPROXY_ADDR) ||
	    ((srv->proxy->conn_src.opts & CO_SRC_TPROXY_MASK) &&
	     (srv->proxy->conn_src.opts & CO_SRC_TPROXY_MASK) != CO_SRC_TPROXY_ADDR)) {
		snprintf(errmsg, errlen, "Cannot reverse connect with server '%s/%s' which uses dynamic source address setting.", name, ist0(sv_name));
		goto err;
	}

	ha_free(&name);

	listener->rx.rhttp.srv = srv;
	listener_set_state(listener, LI_LISTEN);

	return ERR_NONE;

 err:
	ha_free(&name);
	return ERR_ALERT | ERR_FATAL;
}

/* Do not support "disable frontend" for rhttp protocol. */
int rhttp_suspend_listener(struct listener *l)
{
	send_log(l->bind_conf->frontend, LOG_ERR, "cannot disable a reverse-HTTP listener.\n");
	return -1;
}

void rhttp_enable_listener(struct listener *l)
{
	if (l->rx.rhttp.state < LI_PRECONN_ST_INIT) {
		send_log(l->bind_conf->frontend, LOG_INFO,
		         "preconnect %s::%s: Initiating.\n",
		         l->bind_conf->frontend->id, l->bind_conf->rhttp_srvname);
		l->rx.rhttp.state = LI_PRECONN_ST_INIT;
	}

	task_wakeup(l->rx.rhttp.task, TASK_WOKEN_INIT);
}

void rhttp_disable_listener(struct listener *l)
{
	if (l->rx.rhttp.state < LI_PRECONN_ST_FULL) {
		send_log(l->bind_conf->frontend, LOG_INFO,
		         "preconnect %s::%s: Running with nbconn %d reached.\n",
		         l->bind_conf->frontend->id, l->bind_conf->rhttp_srvname,
		         l->bind_conf->maxconn);
		l->rx.rhttp.state = LI_PRECONN_ST_FULL;
	}
}

struct connection *rhttp_accept_conn(struct listener *l, int *status)
{
	struct connection *conn = l->rx.rhttp.pend_conn;

	if (!conn) {
		/* Reverse connect listener must have an explicit maxconn set
		 * to ensure it is re-enabled on connection error.
		 */
		BUG_ON(!l->bind_conf->maxconn);

		/* Instantiate a new conn if maxconn not yet exceeded. */
		if (l->nbconn <= l->bind_conf->maxconn) {
			/* Try first if a new thread should be used for the new connection. */
			unsigned int new_tid = select_thread(l);
			if (new_tid != tid) {
				task_migrate(l->rx.rhttp.task, new_tid);
				*status = CO_AC_DONE;
				return NULL;
			}

			/* No need to use a new thread, use the opportunity to alloc the connection right now. */
			l->rx.rhttp.pend_conn = new_reverse_conn(l, l->rx.rhttp.srv);
			if (!l->rx.rhttp.pend_conn) {
				*status = CO_AC_PAUSE;
				return NULL;
			}
		}

		*status = CO_AC_DONE;
		return NULL;
	}

	/* listener_accept() must not be called if no pending connection is not yet reversed. */
	BUG_ON(!(conn->flags & CO_FL_ACT_REVERSING));
	conn->flags &= ~CO_FL_ACT_REVERSING;
	conn->flags |= CO_FL_REVERSED;
	conn->mux->ctl(conn, MUX_CTL_REVERSE_CONN, NULL);

	l->rx.rhttp.pend_conn = NULL;
	*status = CO_AC_NONE;

	return conn;
}

void rhttp_unbind_receiver(struct listener *l)
{
	l->rx.flags &= ~RX_F_BOUND;
}

int rhttp_bind_tid_prep(struct connection *conn, int new_tid)
{
	/* Explicitly disable connection thread migration on accept. Indeed,
	 * it's unsafe to move a connection with its FD to another thread. Note
	 * that active reverse task thread migration should be sufficient to
	 * ensure repartition of reversed connections across listener threads.
	 */
	return -1;
}

int rhttp_accepting_conn(const struct receiver *rx)
{
	return 1;
}

INITCALL1(STG_REGISTER, protocol_register, &proto_rhttp);

/* perform minimal initializations */
static void init_rhttp()
{
	int i;

	for (i = 0; i < MAX_THREADS; i++)
		ha_thread_ctx[i].nb_rhttp_conns = 0;
}

INITCALL0(STG_PREPARE, init_rhttp);
