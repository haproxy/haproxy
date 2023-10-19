#include <stdio.h>
#include <string.h>

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/errors.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/proto_tcp.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/server.h>
#include <haproxy/sock.h>
#include <haproxy/task.h>

#include <haproxy/proto_reverse_connect.h>

struct proto_fam proto_fam_reverse_connect = {
	.name = "reverse_connect",
	.sock_domain = AF_CUST_REV_SRV,
	.sock_family = AF_INET,
	.bind = rev_bind_receiver,
};

struct protocol proto_reverse_connect = {
	.name = "rev",

	/* connection layer */
	.listen      = rev_bind_listener,
	.enable      = rev_enable_listener,
	.disable     = rev_disable_listener,
	.add         = default_add_listener,
	.unbind      = rev_unbind_receiver,
	.resume      = default_resume_listener,
	.accept_conn = rev_accept_conn,
	.set_affinity = rev_set_affinity,

	/* address family */
	.fam  = &proto_fam_reverse_connect,

	/* socket layer */
	.proto_type     = PROTO_TYPE_STREAM,
	.sock_type      = SOCK_STREAM,
	.sock_prot      = IPPROTO_TCP,
	.rx_listening   = rev_accepting_conn,
	.receivers      = LIST_HEAD_INIT(proto_reverse_connect.receivers),
};

static struct connection *new_reverse_conn(struct listener *l, struct server *srv)
{
	struct connection *conn = conn_new(srv);
	struct sockaddr_storage *bind_addr = NULL;
	if (!conn)
		goto err;

	conn_set_reverse(conn, &l->obj_type);

	if (alloc_bind_address(&bind_addr, srv, srv->proxy, NULL) != SRV_STATUS_OK)
		goto err;
	conn->src = bind_addr;

	sockaddr_alloc(&conn->dst, 0, 0);
	if (!conn->dst)
		goto err;
	*conn->dst = srv->addr;
	set_host_port(conn->dst, srv->svc_port);

	if (conn_prepare(conn, protocol_lookup(conn->dst->ss_family, PROTO_TYPE_STREAM, 0), srv->xprt))
		goto err;

	if (conn->ctrl->connect(conn, 0) != SF_ERR_NONE)
		goto err;

	if (conn_xprt_start(conn) < 0)
		goto err;

	if (!srv->use_ssl ||
	    (!srv->ssl_ctx.alpn_str && !srv->ssl_ctx.npn_str) ||
	    srv->mux_proto) {
		if (conn_install_mux_be(conn, NULL, NULL, NULL) < 0)
			goto err;
	}

	/* Not expected here. */
	BUG_ON((conn->flags & CO_FL_HANDSHAKE));
	return conn;

 err:
	if (conn) {
		conn_stop_tracking(conn);
		conn_xprt_shutw(conn);
		conn_xprt_close(conn);
		conn_sock_shutw(conn, 0);
		conn_ctrl_close(conn);

		if (conn->destroy_cb)
			conn->destroy_cb(conn);

		/* Mark connection as non-reversable. This prevents conn_free()
		 * to reschedule reverse_connect task on freeing a preconnect
		 * connection.
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
void rev_notify_preconn_err(struct listener *l)
{
	/* For the moment reverse connection are bound only on first thread. */
	BUG_ON(tid != 0);

	/* Receiver must reference a reverse connection as pending. */
	BUG_ON(!l->rx.reverse_connect.pend_conn);

	/* Remove reference to the freed connection. */
	l->rx.reverse_connect.pend_conn = NULL;

	if (l->rx.reverse_connect.state != LI_PRECONN_ST_ERR) {
		send_log(l->bind_conf->frontend, LOG_ERR,
		        "preconnect %s::%s: Error encountered.\n",
		         l->bind_conf->frontend->id, l->bind_conf->reverse_srvname);
		l->rx.reverse_connect.state = LI_PRECONN_ST_ERR;
	}

	/* Rearm a new preconnect attempt. */
	l->rx.reverse_connect.task->expire = MS_TO_TICKS(now_ms + 1000);
	task_queue(l->rx.reverse_connect.task);
}

struct task *rev_process(struct task *task, void *ctx, unsigned int state)
{
	struct listener *l = ctx;
	struct connection *conn = l->rx.reverse_connect.pend_conn;

	if (conn) {
		if (conn->flags & CO_FL_ERROR) {
			conn_stop_tracking(conn);
			conn_xprt_shutw(conn);
			conn_xprt_close(conn);
			conn_sock_shutw(conn, 0);
			conn_ctrl_close(conn);

			if (conn->destroy_cb)
				conn->destroy_cb(conn);
			conn_free(conn);

			/* conn_free() must report preconnect failure using rev_notify_preconn_err(). */
			BUG_ON(l->rx.reverse_connect.pend_conn);
		}
		else {
			/* Spurrious receiver task wake up when pend_conn is not ready/on error. */
			BUG_ON(!(conn->flags & CO_FL_REVERSED));

			/* A connection is ready to be accepted. */
			listener_accept(l);
			l->rx.reverse_connect.task->expire = TICK_ETERNITY;
		}
	}
	else {
		/* No pending reverse connection, prepare a new one. Store it in the
		 * listener and return NULL. Connection will be returned later after
		 * reversal is completed.
		 */
		conn = new_reverse_conn(l, l->rx.reverse_connect.srv);
		l->rx.reverse_connect.pend_conn = conn;

		/* On success task will be woken up by H2 mux after reversal. */
		l->rx.reverse_connect.task->expire = conn ? TICK_ETERNITY :
		                                            MS_TO_TICKS(now_ms + 1000);
	}

	return task;
}

int rev_bind_receiver(struct receiver *rx, char **errmsg)
{
	rx->flags |= RX_F_BOUND;
	return ERR_NONE;
}

int rev_bind_listener(struct listener *listener, char *errmsg, int errlen)
{
	struct task *task;
	struct proxy *be;
	struct server *srv;
	struct ist be_name, sv_name;
	char *name = NULL;

	/* TODO for the moment reverse conn creation is pinned to the first thread only. */
	if (!(task = task_new_here())) {
		snprintf(errmsg, errlen, "Out of memory.");
		goto err;
	}
	task->process = rev_process;
	task->context = listener;
	listener->rx.reverse_connect.task = task;
	listener->rx.reverse_connect.state = LI_PRECONN_ST_STOP;

	/* Set maxconn which is defined via the special kw nbconn for reverse
	 * connect. Use a default value of 1 if not set. This guarantees that
	 * listener will be automatically reenable each time it fell back below
	 * it due to a connection error.
	 */
	listener->bind_conf->maxconn = listener->bind_conf->reverse_nbconn;
	if (!listener->bind_conf->maxconn)
		listener->bind_conf->maxconn = 1;

	name = strdup(listener->bind_conf->reverse_srvname);
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

	if (srv->flags & SRV_F_REVERSE) {
		snprintf(errmsg, errlen, "Cannot use reverse server '%s/%s' as target to a reverse bind.", ist0(be_name), ist0(sv_name));
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

	listener->rx.reverse_connect.srv = srv;
	listener_set_state(listener, LI_LISTEN);

	return ERR_NONE;

 err:
	ha_free(&name);
	return ERR_ALERT | ERR_FATAL;
}

void rev_enable_listener(struct listener *l)
{
	if (l->rx.reverse_connect.state < LI_PRECONN_ST_INIT) {
		send_log(l->bind_conf->frontend, LOG_INFO,
		         "preconnect %s::%s: Initiating.\n",
		         l->bind_conf->frontend->id, l->bind_conf->reverse_srvname);
		l->rx.reverse_connect.state = LI_PRECONN_ST_INIT;
	}

	task_wakeup(l->rx.reverse_connect.task, TASK_WOKEN_ANY);
}

void rev_disable_listener(struct listener *l)
{
	if (l->rx.reverse_connect.state < LI_PRECONN_ST_FULL) {
		send_log(l->bind_conf->frontend, LOG_INFO,
		         "preconnect %s::%s: Running with nbconn %d reached.\n",
		         l->bind_conf->frontend->id, l->bind_conf->reverse_srvname,
		         l->bind_conf->maxconn);
		l->rx.reverse_connect.state = LI_PRECONN_ST_FULL;
	}
}

struct connection *rev_accept_conn(struct listener *l, int *status)
{
	struct connection *conn = l->rx.reverse_connect.pend_conn;

	if (!conn) {
		/* Reverse connect listener must have an explicit maxconn set
		 * to ensure it is reenabled on connection error.
		 */
		BUG_ON(!l->bind_conf->maxconn);

		/* Instantiate a new conn if maxconn not yet exceeded. */
		if (l->nbconn <= l->bind_conf->maxconn) {
			l->rx.reverse_connect.pend_conn = new_reverse_conn(l, l->rx.reverse_connect.srv);
			if (!l->rx.reverse_connect.pend_conn) {
				*status = CO_AC_PAUSE;
				return NULL;
			}
		}

		*status = CO_AC_DONE;
		return NULL;
	}

	/* listener_accept() must not be called if no pending connection is not yet reversed. */
	BUG_ON(!(conn->flags & CO_FL_REVERSED));
	conn->flags &= ~CO_FL_REVERSED;
	conn->mux->ctl(conn, MUX_REVERSE_CONN, NULL);

	l->rx.reverse_connect.pend_conn = NULL;
	*status = CO_AC_NONE;

	return conn;
}

void rev_unbind_receiver(struct listener *l)
{
	l->rx.flags &= ~RX_F_BOUND;
}

int rev_set_affinity(struct connection *conn, int new_tid)
{
	/* TODO reversal conn rebinding after is disabled for the moment as we
	 * did not test possible race conditions.
	 */
	return -1;
}

int rev_accepting_conn(const struct receiver *rx)
{
	return 1;
}

INITCALL1(STG_REGISTER, protocol_register, &proto_reverse_connect);
