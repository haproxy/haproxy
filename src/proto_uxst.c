/*
 * UNIX SOCK_STREAM protocol layer (uxst)
 *
 * Copyright 2000-2010 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/protocol.h>
#include <haproxy/proto_uxst.h>
#include <haproxy/sock.h>
#include <haproxy/sock_unix.h>
#include <haproxy/tools.h>
#include <haproxy/version.h>


static int uxst_bind_listener(struct listener *listener, char *errmsg, int errlen);
static int uxst_connect_server(struct connection *conn, int flags);
static void uxst_enable_listener(struct listener *listener);
static void uxst_disable_listener(struct listener *listener);
static int uxst_suspend_receiver(struct receiver *rx);

/* Note: must not be declared <const> as its list will be overwritten */
struct protocol proto_uxst = {
	.name           = "unix_stream",

	/* connection layer */
	.xprt_type      = PROTO_TYPE_STREAM,
	.listen         = uxst_bind_listener,
	.enable         = uxst_enable_listener,
	.disable        = uxst_disable_listener,
	.add            = default_add_listener,
	.unbind         = default_unbind_listener,
	.suspend        = default_suspend_listener,
	.resume         = default_resume_listener,
	.accept_conn    = sock_accept_conn,
	.ctrl_init      = sock_conn_ctrl_init,
	.ctrl_close     = sock_conn_ctrl_close,
	.connect        = uxst_connect_server,
	.drain          = sock_drain,
	.check_events   = sock_check_events,
	.ignore_events  = sock_ignore_events,

	/* binding layer */
	.rx_suspend     = uxst_suspend_receiver,

	/* address family */
	.fam            = &proto_fam_unix,

	/* socket layer */
	.proto_type     = PROTO_TYPE_STREAM,
	.sock_type      = SOCK_STREAM,
	.sock_prot      = 0,
	.rx_enable      = sock_enable,
	.rx_disable     = sock_disable,
	.rx_unbind      = sock_unbind,
	.rx_listening   = sock_accepting_conn,
	.default_iocb   = sock_accept_iocb,
};

/* Note: must not be declared <const> as its list will be overwritten */
struct protocol proto_abns_stream = {
	.name           = "abns_stream",

	/* connection layer */
	.xprt_type      = PROTO_TYPE_STREAM,
	.listen         = uxst_bind_listener,
	.enable         = uxst_enable_listener,
	.disable        = uxst_disable_listener,
	.add            = default_add_listener,
	.unbind         = default_unbind_listener,
	.suspend        = default_suspend_listener,
	.resume         = default_resume_listener,
	.accept_conn    = sock_accept_conn,
	.ctrl_init      = sock_conn_ctrl_init,
	.ctrl_close     = sock_conn_ctrl_close,
	.connect        = uxst_connect_server,
	.drain          = sock_drain,
	.check_events   = sock_check_events,
	.ignore_events  = sock_ignore_events,

	/* binding layer */
	.rx_suspend     = uxst_suspend_receiver,

	/* address family */
	.fam            = &proto_fam_abns,

	/* socket layer */
	.proto_type     = PROTO_TYPE_STREAM,
	.sock_type      = SOCK_STREAM,
	.sock_prot      = 0,
	.rx_enable      = sock_enable,
	.rx_disable     = sock_disable,
	.rx_unbind      = sock_unbind,
	.rx_listening   = sock_accepting_conn,
	.default_iocb   = sock_accept_iocb,

	.nb_receivers   = 0,
};

/* Note: must not be declared <const> as its list will be overwritten */
struct protocol proto_abnsz_stream = {
	.name           = "abnsz_stream",

	/* connection layer */
	.xprt_type      = PROTO_TYPE_STREAM,
	.listen         = uxst_bind_listener,
	.enable         = uxst_enable_listener,
	.disable        = uxst_disable_listener,
	.add            = default_add_listener,
	.unbind         = default_unbind_listener,
	.suspend        = default_suspend_listener,
	.resume         = default_resume_listener,
	.accept_conn    = sock_accept_conn,
	.ctrl_init      = sock_conn_ctrl_init,
	.ctrl_close     = sock_conn_ctrl_close,
	.connect        = uxst_connect_server,
	.drain          = sock_drain,
	.check_events   = sock_check_events,
	.ignore_events  = sock_ignore_events,

	/* binding layer */
	.rx_suspend     = uxst_suspend_receiver,

	/* address family */
	.fam            = &proto_fam_abnsz,

	/* socket layer */
	.proto_type     = PROTO_TYPE_STREAM,
	.sock_type      = SOCK_STREAM,
	.sock_prot      = 0,
	.rx_enable      = sock_enable,
	.rx_disable     = sock_disable,
	.rx_unbind      = sock_unbind,
	.rx_listening   = sock_accepting_conn,
	.default_iocb   = sock_accept_iocb,

	.nb_receivers   = 0,
};

INITCALL1(STG_REGISTER, protocol_register, &proto_uxst);
INITCALL1(STG_REGISTER, protocol_register, &proto_abns_stream);
INITCALL1(STG_REGISTER, protocol_register, &proto_abnsz_stream);

/********************************
 * 1) low-level socket functions
 ********************************/


/********************************
 * 2) listener-oriented functions
 ********************************/

/* This function creates a UNIX socket associated to the listener. It changes
 * the state from ASSIGNED to LISTEN. The socket is NOT enabled for polling.
 * The return value is composed from ERR_NONE, ERR_RETRYABLE and ERR_FATAL. It
 * may return a warning or an error message in <errmsg> if the message is at
 * most <errlen> bytes long (including '\0'). Note that <errmsg> may be NULL if
 * <errlen> is also zero.
 */
static int uxst_bind_listener(struct listener *listener, char *errmsg, int errlen)
{
	int fd, err;
	int ready;
	struct buffer *msg = alloc_trash_chunk();

	err = ERR_NONE;

	if (!msg) {
		if (errlen)
			snprintf(errmsg, errlen, "out of memory");
		return ERR_ALERT | ERR_FATAL;
	}

	/* ensure we never return garbage */
	if (errlen)
		*errmsg = 0;

	if (listener->state != LI_ASSIGNED)
		return ERR_NONE; /* already bound */

	if (!(listener->rx.flags & RX_F_BOUND)) {
		chunk_appendf(msg, "receiving socket not bound");
		err |= ERR_FATAL | ERR_ALERT;
		goto uxst_return;
	}

	if (listener->rx.flags & RX_F_MUST_DUP)
		goto done;

	fd = listener->rx.fd;
	ready = sock_accepting_conn(&listener->rx) > 0;

	if (!ready && /* only listen if not already done by external process */
	    listen(fd, listener_backlog(listener)) < 0) {
		err |= ERR_FATAL | ERR_ALERT;
		chunk_appendf(msg, "cannot listen on UNIX socket (%s)", strerror(errno));
		goto uxst_close_return;
	}

 done:
	/* the socket is now listening */
	listener_set_state(listener, LI_LISTEN);
	goto uxst_return;

 uxst_close_return:
	fd_delete(fd);
 uxst_return:
	if (msg && errlen) {
		char *path_str;

		path_str = sa2str((struct sockaddr_storage *)&listener->rx.addr, 0, 0);
		snprintf(errmsg, errlen, "%s for [%s]", msg->area, ((path_str) ? path_str : ""));
		ha_free(&path_str);
	}
	free_trash_chunk(msg);
	msg = NULL;
	return err;
}

/* Enable receipt of incoming connections for listener <l>. The receiver must
 * still be valid.
 */
static void uxst_enable_listener(struct listener *l)
{
	fd_want_recv_safe(l->rx.fd);
}

/* Disable receipt of incoming connections for listener <l>. The receiver must
 * still be valid.
 */
static void uxst_disable_listener(struct listener *l)
{
	fd_stop_recv(l->rx.fd);
}

/* Suspend a receiver. Returns < 0 in case of failure, 0 if the receiver
 * was totally stopped, or > 0 if correctly suspended. For plain unix sockets
 * we only disable the listener to prevent data from being handled but nothing
 * more is done since currently it's the new process which handles the renaming.
 * Abstract sockets are completely unbound and closed so there's no need to stop
 * the poller.
 */
static int uxst_suspend_receiver(struct receiver *rx)
{
	struct listener *l = LIST_ELEM(rx, struct listener *, rx);

	if (((struct sockaddr_un *)&rx->addr)->sun_path[0]) {
		uxst_disable_listener(l);
		return 1;
	}

	/* Listener's lock already held. Call lockless version of
	 * unbind_listener. */
	do_unbind_listener(l);
	return 0;
}


/*
 * This function initiates a UNIX connection establishment to the target assigned
 * to connection <conn> using (si->{target,dst}). The source address is ignored
 * and will be selected by the system. conn->target may point either to a valid
 * server or to a backend, depending on conn->target. Only OBJ_TYPE_PROXY and
 * OBJ_TYPE_SERVER are supported. The <data> parameter is a boolean indicating
 * whether there are data waiting for being sent or not, in order to adjust data
 * write polling and on some platforms. The <delack> argument is ignored.
 *
 * Note that a pending send_proxy message accounts for data.
 *
 * It can return one of :
 *  - SF_ERR_NONE if everything's OK
 *  - SF_ERR_SRVTO if there are no more servers
 *  - SF_ERR_SRVCL if the connection was refused by the server
 *  - SF_ERR_PRXCOND if the connection has been limited by the proxy (maxconn)
 *  - SF_ERR_RESOURCE if a system resource is lacking (eg: fd limits, ports, ...)
 *  - SF_ERR_INTERNAL for any other purely internal errors
 * Additionally, in the case of SF_ERR_RESOURCE, an emergency log will be emitted.
 *
 * The connection's fd is inserted only when SF_ERR_NONE is returned, otherwise
 * it's invalid and the caller has nothing to do.
 */
static int uxst_connect_server(struct connection *conn, int flags)
{
	int fd, stream_err;
	struct server *srv;
	struct proxy *be;

	BUG_ON(!conn->dst);

	switch (obj_type(conn->target)) {
	case OBJ_TYPE_PROXY:
		be = __objt_proxy(conn->target);
		srv = NULL;
		break;
	case OBJ_TYPE_SERVER:
		srv = __objt_server(conn->target);
		be = srv->proxy;
		break;
	default:
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_INTERNAL;
	}

	/* perform common checks on obtained socket FD, return appropriate Stream Error Flag in case of failure */
	fd = conn->handle.fd = sock_create_server_socket(conn, be, &stream_err);
	if (fd == -1)
		return stream_err;

	/* FD is ok, continue with protocol specific settings */
	if (global.tune.server_sndbuf)
                setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &global.tune.server_sndbuf, sizeof(global.tune.server_sndbuf));

	if (global.tune.server_rcvbuf)
                setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &global.tune.server_rcvbuf, sizeof(global.tune.server_rcvbuf));

	if (connect(fd, (struct sockaddr *)conn->dst, get_addr_len(conn->dst)) == -1) {
		if (errno == EINPROGRESS || errno == EALREADY) {
			conn->flags |= CO_FL_WAIT_L4_CONN;
		}
		else if (errno == EISCONN) {
			conn->flags &= ~CO_FL_WAIT_L4_CONN;
		}
		else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EADDRINUSE || errno == EADDRNOTAVAIL) {
			char *msg;
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EADDRNOTAVAIL) {
				msg = "can't connect to destination unix socket, check backlog size on the server";
				conn->err_code = CO_ER_FREE_PORTS;
			}
			else {
				msg = "local address already in use";
				conn->err_code = CO_ER_ADDR_INUSE;
			}

			qfprintf(stderr,"Connect() failed for backend %s: %s (%s).\n", be->id, msg, strerror(errno));
			close(fd);
			send_log(be, LOG_ERR, "Connect() failed for backend %s: %s (%s).\n", be->id, msg, strerror(errno));
			conn->flags |= CO_FL_ERROR;
			return SF_ERR_RESOURCE;
		}
		else if (errno == ETIMEDOUT) {
			close(fd);
			conn->err_code = CO_ER_SOCK_ERR;
			conn->flags |= CO_FL_ERROR;
			return SF_ERR_SRVTO;
		}
		else {	// (errno == ECONNREFUSED || errno == ENETUNREACH || errno == EACCES || errno == EPERM)
			close(fd);
			conn->err_code = CO_ER_SOCK_ERR;
			conn->flags |= CO_FL_ERROR;
			return SF_ERR_SRVCL;
		}
	}
	else {
		/* connect() already succeeded, which is quite usual for unix
		 * sockets. Let's avoid a second connect() probe to complete it.
		 */
		conn->flags &= ~CO_FL_WAIT_L4_CONN;
	}

	/* Prepare to send a few handshakes related to the on-wire protocol. */
	if (conn->send_proxy_ofs)
		conn->flags |= CO_FL_SEND_PROXY;

	conn_ctrl_init(conn);       /* registers the FD */
	HA_ATOMIC_AND(&fdtab[fd].state, ~FD_LINGER_RISK);  /* no need to disable lingering */

	if (conn->flags & CO_FL_WAIT_L4_CONN) {
		fd_want_send(fd);
		fd_cant_send(fd);
		fd_cant_recv(fd);
	}

	return SF_ERR_NONE;  /* connection is OK */
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
