#include <stdio.h>
#include <string.h>

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/errors.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
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
	if (!conn)
		goto err;

	conn_set_reverse(conn, &l->obj_type);

	/* These options is incompatible with a reverse connection. */
	BUG_ON(srv->conn_src.opts & CO_SRC_BIND);
	BUG_ON(srv->proxy->conn_src.opts & CO_SRC_BIND);

	sockaddr_alloc(&conn->dst, 0, 0);
	if (!conn->dst)
		goto err;
	*conn->dst = srv->addr;

	if (conn_prepare(conn, protocol_lookup(conn->dst->ss_family, PROTO_TYPE_STREAM, 0), srv->xprt))
		goto err;

	/* TODO simplification of tcp_connect_server() */
	conn->handle.fd = sock_create_server_socket(conn);
	if (fd_set_nonblock(conn->handle.fd) == -1)
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
		/* Mark connection as non-reversable. This prevents conn_free()
		 * to reschedule reverse_connect task on freeing a preconnect
		 * connection.
		 */
		conn->reverse.target = NULL;
		conn_free(conn);
	}

	return NULL;
}

struct task *rev_process(struct task *task, void *ctx, unsigned int state)
{
	struct listener *l = ctx;
	struct connection *conn = l->rx.reverse_connect.pend_conn;

	if (conn) {
		if (conn->flags & CO_FL_ERROR) {
			conn_full_close(conn);
			conn_free(conn);
			l->rx.reverse_connect.pend_conn = NULL;

			/* Retry on 1s on error. */
			l->rx.reverse_connect.task->expire = MS_TO_TICKS(now_ms + 1000);
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

	/* TODO check que on utilise pas un serveur @reverse */
	if (srv->flags & SRV_F_REVERSE) {
		snprintf(errmsg, errlen, "Cannot use reverse server '%s/%s' as target to a reverse bind.", ist0(be_name), ist0(sv_name));
		goto err;
	}

	/* Check that server uses HTTP/2 either with proto or ALPN. */
	if ((!srv->mux_proto || !isteqi(srv->mux_proto->token, ist("h2"))) &&
	    (!srv->use_ssl || !isteqi(ist(srv->ssl_ctx.alpn_str), ist("\x02h2")))) {
		snprintf(errmsg, errlen, "Cannot reverse connect with server '%s/%s' unless HTTP/2 is activated on it with either proto or alpn keyword.", name, ist0(sv_name));
		goto err;
	}
	ha_free(&name);

	listener->rx.reverse_connect.srv = srv;
	listener_set_state(listener, LI_LISTEN);
	task_wakeup(listener->rx.reverse_connect.task, TASK_WOKEN_ANY);

	return ERR_NONE;

 err:
	ha_free(&name);
	return ERR_ALERT | ERR_FATAL;
}

void rev_enable_listener(struct listener *l)
{
	task_wakeup(l->rx.reverse_connect.task, TASK_WOKEN_ANY);
}

void rev_disable_listener(struct listener *l)
{
}

struct connection *rev_accept_conn(struct listener *l, int *status)
{
	struct connection *conn = l->rx.reverse_connect.pend_conn;

	if (!conn) {
		/* Instantiate a new conn if maxconn not yet exceeded. */
		if (l->bind_conf->maxconn && l->nbconn <= l->bind_conf->maxconn) {
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
