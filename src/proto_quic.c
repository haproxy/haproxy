/*
 * AF_INET/AF_INET6 QUIC protocol layer.
 *
 * Copyright 2020 Frederic Lecaille <flecaille@haproxy.com>
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
#include <time.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/udp.h>
#include <netinet/in.h>

#include <import/ebtree-t.h>

#include <haproxy/api.h>
#include <haproxy/arg.h>
#include <haproxy/cbuf.h>
#include <haproxy/connection.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/namespace.h>
#include <haproxy/port_range.h>
#include <haproxy/protocol.h>
#include <haproxy/proto_quic.h>
#include <haproxy/proto_udp.h>
#include <haproxy/proxy-t.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_sock.h>
#include <haproxy/sock.h>
#include <haproxy/sock_inet.h>
#include <haproxy/task.h>
#include <haproxy/tools.h>

/* per-thread quic datagram handlers */
struct quic_dghdlr *quic_dghdlrs;

/* Size of the internal buffer of QUIC RX buffer at the fd level */
#define QUIC_RX_BUFSZ  (1UL << 18)

DECLARE_STATIC_POOL(pool_head_quic_rxbuf, "quic_rxbuf", QUIC_RX_BUFSZ);

static int quic_bind_listener(struct listener *listener, char *errmsg, int errlen);
static int quic_connect_server(struct connection *conn, int flags);
static void quic_enable_listener(struct listener *listener);
static void quic_disable_listener(struct listener *listener);
static int quic_bind_tid_prep(struct connection *conn, int new_tid);
static void quic_bind_tid_commit(struct connection *conn);
static void quic_bind_tid_reset(struct connection *conn);
static int quic_get_info(struct connection *conn, long long int *info, int info_num);

/* Note: must not be declared <const> as its list will be overwritten */
struct protocol proto_quic4 = {
	.name           = "quic4",

	/* connection layer */
	.xprt_type      = PROTO_TYPE_STREAM,
	.listen         = quic_bind_listener,
	.enable         = quic_enable_listener,
	.disable        = quic_disable_listener,
	.add            = default_add_listener,
	.unbind         = default_unbind_listener,
	.suspend        = default_suspend_listener,
	.resume         = default_resume_listener,
	.accept_conn    = quic_sock_accept_conn,
	.get_src        = quic_sock_get_src,
	.get_dst        = quic_sock_get_dst,
	.connect        = quic_connect_server,
	.get_info       = quic_get_info,
	.bind_tid_prep   = quic_bind_tid_prep,
	.bind_tid_commit = quic_bind_tid_commit,
	.bind_tid_reset  = quic_bind_tid_reset,

	/* binding layer */
	.rx_suspend     = udp_suspend_receiver,
	.rx_resume      = udp_resume_receiver,

	/* address family */
	.fam            = &proto_fam_inet4,

	/* socket layer */
	.proto_type     = PROTO_TYPE_DGRAM,
	.sock_type      = SOCK_DGRAM,
	.sock_prot      = IPPROTO_UDP,
	.rx_enable      = sock_enable,
	.rx_disable     = sock_disable,
	.rx_unbind      = sock_unbind,
	.rx_listening   = quic_sock_accepting_conn,
	.default_iocb   = quic_lstnr_sock_fd_iocb,
#ifdef SO_REUSEPORT
	.flags          = PROTO_F_REUSEPORT_SUPPORTED,
#endif
};

INITCALL1(STG_REGISTER, protocol_register, &proto_quic4);

/* Note: must not be declared <const> as its list will be overwritten */
struct protocol proto_quic6 = {
	.name            = "quic6",

	/* connection layer */
	.xprt_type      = PROTO_TYPE_STREAM,
	.listen         = quic_bind_listener,
	.enable         = quic_enable_listener,
	.disable        = quic_disable_listener,
	.add            = default_add_listener,
	.unbind         = default_unbind_listener,
	.suspend        = default_suspend_listener,
	.resume         = default_resume_listener,
	.accept_conn    = quic_sock_accept_conn,
	.get_src        = quic_sock_get_src,
	.get_dst        = quic_sock_get_dst,
	.connect        = quic_connect_server,
	.get_info       = quic_get_info,
	.bind_tid_prep   = quic_bind_tid_prep,
	.bind_tid_commit = quic_bind_tid_commit,
	.bind_tid_reset  = quic_bind_tid_reset,

	/* binding layer */
	.rx_suspend     = udp_suspend_receiver,
	.rx_resume      = udp_resume_receiver,

	/* address family */
	.fam            = &proto_fam_inet6,

	/* socket layer */
	.proto_type     = PROTO_TYPE_DGRAM,
	.sock_type      = SOCK_DGRAM,
	.sock_prot      = IPPROTO_UDP,
	.rx_enable      = sock_enable,
	.rx_disable     = sock_disable,
	.rx_unbind      = sock_unbind,
	.rx_listening   = quic_sock_accepting_conn,
	.default_iocb   = quic_lstnr_sock_fd_iocb,
#ifdef SO_REUSEPORT
	.flags          = PROTO_F_REUSEPORT_SUPPORTED,
#endif
};

INITCALL1(STG_REGISTER, protocol_register, &proto_quic6);

/* Binds ipv4/ipv6 address <local> to socket <fd>, unless <flags> is set, in which
 * case we try to bind <remote>. <flags> is a 2-bit field consisting of :
 *  - 0 : ignore remote address (may even be a NULL pointer)
 *  - 1 : use provided address
 *  - 2 : use provided port
 *  - 3 : use both
 *
 * The function supports multiple foreign binding methods :
 *   - linux_tproxy: we directly bind to the foreign address
 * The second one can be used as a fallback for the first one.
 * This function returns 0 when everything's OK, 1 if it could not bind, to the
 * local address, 2 if it could not bind to the foreign address.
 */
int quic_bind_socket(int fd, int flags, struct sockaddr_storage *local, struct sockaddr_storage *remote)
{
	struct sockaddr_storage bind_addr;
	int foreign_ok = 0;
	int ret;
	static THREAD_LOCAL int ip_transp_working = 1;
	static THREAD_LOCAL int ip6_transp_working = 1;

	switch (local->ss_family) {
	case AF_INET:
		if (flags && ip_transp_working) {
			/* This deserves some explanation. Some platforms will support
			 * multiple combinations of certain methods, so we try the
			 * supported ones until one succeeds.
			 */
			if (sock_inet4_make_foreign(fd))
				foreign_ok = 1;
			else
				ip_transp_working = 0;
		}
		break;
	case AF_INET6:
		if (flags && ip6_transp_working) {
			if (sock_inet6_make_foreign(fd))
				foreign_ok = 1;
			else
				ip6_transp_working = 0;
		}
		break;
	}

	if (flags) {
		memset(&bind_addr, 0, sizeof(bind_addr));
		bind_addr.ss_family = remote->ss_family;
		switch (remote->ss_family) {
		case AF_INET:
			if (flags & 1)
				((struct sockaddr_in *)&bind_addr)->sin_addr = ((struct sockaddr_in *)remote)->sin_addr;
			if (flags & 2)
				((struct sockaddr_in *)&bind_addr)->sin_port = ((struct sockaddr_in *)remote)->sin_port;
			break;
		case AF_INET6:
			if (flags & 1)
				((struct sockaddr_in6 *)&bind_addr)->sin6_addr = ((struct sockaddr_in6 *)remote)->sin6_addr;
			if (flags & 2)
				((struct sockaddr_in6 *)&bind_addr)->sin6_port = ((struct sockaddr_in6 *)remote)->sin6_port;
			break;
		default:
			/* we don't want to try to bind to an unknown address family */
			foreign_ok = 0;
		}
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (foreign_ok) {
		if (is_inet_addr(&bind_addr)) {
			ret = bind(fd, (struct sockaddr *)&bind_addr, get_addr_len(&bind_addr));
			if (ret < 0)
				return 2;
		}
	}
	else {
		if (is_inet_addr(local)) {
			ret = bind(fd, (struct sockaddr *)local, get_addr_len(local));
			if (ret < 0)
				return 1;
		}
	}

	if (!flags)
		return 0;

	if (!foreign_ok)
		/* we could not bind to a foreign address */
		return 2;

	return 0;
}

/*
 * This function initiates a QUIC connection establishment to the target assigned
 * to connection <conn> using (si->{target,dst}). A source address may be
 * pointed to by conn->src in case of transparent proxying. Normal source
 * bind addresses are still determined locally (due to the possible need of a
 * source port). conn->target may point either to a valid server or to a backend,
 * depending on conn->target. Only OBJ_TYPE_PROXY and OBJ_TYPE_SERVER are
 * supported. The <data> parameter is a boolean indicating whether there are data
 * waiting for being sent or not, in order to adjust data write polling and on
 * some platforms, the ability to avoid an empty initial ACK. The <flags> argument
 * is not used.
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

int quic_connect_server(struct connection *conn, int flags)
{
	int fd, stream_err;
	struct server *srv;
	struct proxy *be;
	struct conn_src *src;
	struct sockaddr_storage *addr;

	BUG_ON(!conn->dst);

	conn->flags |= CO_FL_WAIT_L4_CONN; /* connection in progress */

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

	/* FD is ok, perform protocol specific settings */
	/* allow specific binding :
	 * - server-specific at first
	 * - proxy-specific next
	 */
	if (srv && srv->conn_src.opts & CO_SRC_BIND)
		src = &srv->conn_src;
	else if (be->conn_src.opts & CO_SRC_BIND)
		src = &be->conn_src;
	else
		src = NULL;

	if (src) {
		int ret, flags = 0;

		if (conn->src && is_inet_addr(conn->src)) {
			switch (src->opts & CO_SRC_TPROXY_MASK) {
			case CO_SRC_TPROXY_CLI:
				conn_set_private(conn);
				__fallthrough;
			case CO_SRC_TPROXY_ADDR:
				flags = 3;
				break;
			case CO_SRC_TPROXY_CIP:
			case CO_SRC_TPROXY_DYN:
				conn_set_private(conn);
				flags = 1;
				break;
			}
		}

#ifdef SO_BINDTODEVICE
		/* Note: this might fail if not CAP_NET_RAW */
		if (src->iface_name)
			setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, src->iface_name, src->iface_len + 1);
#endif

		if (src->sport_range) {
			int attempts = 10; /* should be more than enough to find a spare port */
			struct sockaddr_storage sa;

			ret = 1;
			memcpy(&sa, &src->source_addr, sizeof(sa));

			do {
				/* note: in case of retry, we may have to release a previously
				 * allocated port, hence this loop's construct.
				 */
				port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
				fdinfo[fd].port_range = NULL;

				if (!attempts)
					break;
				attempts--;

				fdinfo[fd].local_port = port_range_alloc_port(src->sport_range);
				if (!fdinfo[fd].local_port) {
					conn->err_code = CO_ER_PORT_RANGE;
					break;
				}

				fdinfo[fd].port_range = src->sport_range;
				set_host_port(&sa, fdinfo[fd].local_port);

				ret = quic_bind_socket(fd, flags, &sa, conn->src);
				if (ret != 0)
					conn->err_code = CO_ER_CANT_BIND;
			} while (ret != 0); /* binding NOK */
		}
		else {
#ifdef IP_BIND_ADDRESS_NO_PORT
			static THREAD_LOCAL int bind_address_no_port = 1;
			setsockopt(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, (const void *) &bind_address_no_port, sizeof(int));
#endif
			ret = quic_bind_socket(fd, flags, &src->source_addr, conn->src);
			if (ret != 0)
				conn->err_code = CO_ER_CANT_BIND;
		}

		if (unlikely(ret != 0)) {
			port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
			fdinfo[fd].port_range = NULL;
			close(fd);

			if (ret == 1) {
				ha_alert("Cannot bind to source address before connect() for backend %s. Aborting.\n",
					 be->id);
				send_log(be, LOG_EMERG,
					 "Cannot bind to source address before connect() for backend %s.\n",
					 be->id);
			} else {
				ha_alert("Cannot bind to tproxy source address before connect() for backend %s. Aborting.\n",
					 be->id);
				send_log(be, LOG_EMERG,
					 "Cannot bind to tproxy source address before connect() for backend %s.\n",
					 be->id);
			}
			conn->flags |= CO_FL_ERROR;
			return SF_ERR_RESOURCE;
		}
	}

	if (global.tune.server_sndbuf)
                setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &global.tune.server_sndbuf, sizeof(global.tune.server_sndbuf));

	if (global.tune.server_rcvbuf)
                setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &global.tune.server_rcvbuf, sizeof(global.tune.server_rcvbuf));

	addr = (conn->flags & CO_FL_SOCKS4) ? &srv->socks4_addr : conn->dst;
	if (connect(fd, (const struct sockaddr *)addr, get_addr_len(addr)) == -1) {
		if (errno == EINPROGRESS || errno == EALREADY) {
			/* common case, let's wait for connect status */
			conn->flags |= CO_FL_WAIT_L4_CONN;
		}
		else if (errno == EISCONN) {
			/* should normally not happen but if so, indicates that it's OK */
			conn->flags &= ~CO_FL_WAIT_L4_CONN;
		}
		else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EADDRINUSE || errno == EADDRNOTAVAIL) {
			char *msg;
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EADDRNOTAVAIL) {
				msg = "no free ports";
				conn->err_code = CO_ER_FREE_PORTS;
			}
			else {
				msg = "local address already in use";
				conn->err_code = CO_ER_ADDR_INUSE;
			}

			qfprintf(stderr,"Connect() failed for backend %s: %s.\n", be->id, msg);
			port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
			fdinfo[fd].port_range = NULL;
			close(fd);
			send_log(be, LOG_ERR, "Connect() failed for backend %s: %s.\n", be->id, msg);
			conn->flags |= CO_FL_ERROR;
			return SF_ERR_RESOURCE;
		} else if (errno == ETIMEDOUT) {
			//qfprintf(stderr,"Connect(): ETIMEDOUT");
			port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
			fdinfo[fd].port_range = NULL;
			close(fd);
			conn->err_code = CO_ER_SOCK_ERR;
			conn->flags |= CO_FL_ERROR;
			return SF_ERR_SRVTO;
		} else {
			// (errno == ECONNREFUSED || errno == ENETUNREACH || errno == EACCES || errno == EPERM)
			//qfprintf(stderr,"Connect(): %d", errno);
			port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
			fdinfo[fd].port_range = NULL;
			close(fd);
			conn->err_code = CO_ER_SOCK_ERR;
			conn->flags |= CO_FL_ERROR;
			return SF_ERR_SRVCL;
		}
	}
	else {
		/* connect() == 0, this is great! */
		conn->flags &= ~CO_FL_WAIT_L4_CONN;
	}

	conn_ctrl_init(conn);       /* registers the FD */
	HA_ATOMIC_OR(&fdtab[fd].state, FD_LINGER_RISK);  /* close hard if needed */

	if (conn->flags & CO_FL_WAIT_L4_CONN) {
		fd_want_send(fd);
		fd_cant_send(fd);
		fd_cant_recv(fd);
	}

	return SF_ERR_NONE;  /* connection is OK */
}

/* Allocate the RX buffers for <l> listener.
 * Return 1 if succeeded, 0 if not.
 */
static int quic_alloc_rxbufs_listener(struct listener *l)
{
	int i;
	struct quic_receiver_buf *tmp;

	MT_LIST_INIT(&l->rx.rxbuf_list);
	for (i = 0; i < my_popcountl(l->rx.bind_thread); i++) {
		struct quic_receiver_buf *rxbuf;
		char *buf;

		rxbuf = calloc(1, sizeof(*rxbuf));
		if (!rxbuf)
			goto err;

		buf = pool_alloc(pool_head_quic_rxbuf);
		if (!buf) {
			free(rxbuf);
			goto err;
		}

		rxbuf->buf = b_make(buf, QUIC_RX_BUFSZ, 0, 0);
		LIST_INIT(&rxbuf->dgram_list);
		MT_LIST_APPEND(&l->rx.rxbuf_list, &rxbuf->rxbuf_el);
	}

	return 1;

 err:
	while ((tmp = MT_LIST_POP(&l->rx.rxbuf_list, typeof(tmp), rxbuf_el))) {
		pool_free(pool_head_quic_rxbuf, tmp->buf.area);
		free(tmp);
	}
	return 0;
}

/* Check for platform support of a set of advanced UDP network API features
 * used by haproxy QUIC stack. Automatically disable unsupported features.
 * Listener <l> serves to test the ability of binding multiple sockets on the
 * same address.
 */
static int quic_test_socketopts(struct listener *l)
{
	const struct receiver *rx = &l->rx;
	int fdtest = -1;

	/* Check if IP destination address can be retrieved on recvfrom()
	 * operation.
	 */
	if (global.tune.options & GTUNE_QUIC_SOCK_PER_CONN) {
		fdtest = socket(rx->proto->fam->sock_domain,
				rx->proto->sock_type, rx->proto->sock_prot);
		if (fdtest < 0)
			goto err;

#if defined(IP_PKTINFO) || defined(IP_RECVDSTADDR)
		/* Check if platform support multiple UDP sockets bind on the same
		 * local address. Create a dummy socket and bind it on the same address
		 * as <l> listener. If bind system call fails, deactivate socket per
		 * connection. All other errors are not taken into account.
		 */
		if (setsockopt(fdtest, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) &&
		    bind(fdtest, (struct sockaddr *)&rx->addr, rx->proto->fam->sock_addrlen) < 0) {
			ha_alert("Your platform does not seem to support multiple UDP sockets binded on the same address. "
			         "QUIC connections will use listener socket.\n");
			global.tune.options &= ~GTUNE_QUIC_SOCK_PER_CONN;
		}
#else
		ha_alert("Your platform does not seem to support UDP source address retrieval through IP_PKTINFO or an alternative flag. "
		         "QUIC connections will use listener socket.\n");
		global.tune.options &= ~GTUNE_QUIC_SOCK_PER_CONN;
#endif
	}

	/* Check for UDP GSO support. */
	if (!(global.tune.options & GTUNE_QUIC_NO_UDP_GSO)) {
		if (fdtest < 0) {
			fdtest = socket(rx->proto->fam->sock_domain,
					rx->proto->sock_type, rx->proto->sock_prot);
			if (fdtest < 0)
				goto err;
		}

#ifdef UDP_SEGMENT
		if (setsockopt(fdtest, SOL_UDP, UDP_SEGMENT, &zero, sizeof(zero))) {
			ha_alert("Your platform does not support UDP GSO. "
			         "This will be automatically disabled for QUIC transfer.\n");
			global.tune.options |= GTUNE_QUIC_NO_UDP_GSO;
		}
#else
		ha_alert("Your platform does not support UDP GSO. "
		         "This will be automatically disabled for QUIC transfer.\n");
		global.tune.options |= GTUNE_QUIC_NO_UDP_GSO;
#endif
	}

	if (fdtest >= 0)
		close(fdtest);
	return ERR_NONE;

 err:
	ha_alert("Fatal error on quic_test_sockopts(): %s.\n", strerror(errno));
	return ERR_FATAL;
}

/* This function tries to bind a QUIC4/6 listener. It may return a warning or
 * an error message in <errmsg> if the message is at most <errlen> bytes long
 * (including '\0'). Note that <errmsg> may be NULL if <errlen> is also zero.
 * The return value is composed from ERR_ABORT, ERR_WARN,
 * ERR_ALERT, ERR_RETRYABLE and ERR_FATAL. ERR_NONE indicates that everything
 * was alright and that no message was returned. ERR_RETRYABLE means that an
 * error occurred but that it may vanish after a retry (eg: port in use), and
 * ERR_FATAL indicates a non-fixable error. ERR_WARN and ERR_ALERT do not alter
 * the meaning of the error, but just indicate that a message is present which
 * should be displayed with the respective level. Last, ERR_ABORT indicates
 * that it's pointless to try to start other listeners. No error message is
 * returned if errlen is NULL.
 */
static int quic_bind_listener(struct listener *listener, char *errmsg, int errlen)
{
	const struct sockaddr_storage addr = listener->rx.addr;
	int fd, err = ERR_NONE;
	char *msg = NULL;

	/* ensure we never return garbage */
	if (errlen)
		*errmsg = 0;

	if (listener->state != LI_ASSIGNED)
		return ERR_NONE; /* already bound */

	if (!(listener->rx.flags & RX_F_BOUND)) {
		msg = "receiving socket not bound";
		goto udp_return;
	}

	/* Duplicate quic_mode setting from bind_conf. Useful to overwrite it
	 * at runtime per receiver instance.
	 */
	listener->rx.quic_mode = listener->bind_conf->quic_mode;

	/* Set IP_PKTINFO to retrieve destination address on recv. */
	fd = listener->rx.fd;
	switch (addr.ss_family) {
	case AF_INET:
#if defined(IP_PKTINFO)
		setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
#elif defined(IP_RECVDSTADDR)
		setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &one, sizeof(one));
#endif /* IP_PKTINFO || IP_RECVDSTADDR */
		break;
	case AF_INET6:
#ifdef IPV6_RECVPKTINFO
		setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
#endif
		break;
	default:
		break;
	}

	if (!quic_alloc_rxbufs_listener(listener)) {
		msg = "could not initialize tx/rx rings";
		err |= ERR_WARN;
		goto udp_return;
	}

	if (quic_test_socketopts(listener))
		return ERR_FATAL;

	if (global.tune.frontend_rcvbuf)
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &global.tune.frontend_rcvbuf, sizeof(global.tune.frontend_rcvbuf));

	if (global.tune.frontend_sndbuf)
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &global.tune.frontend_sndbuf, sizeof(global.tune.frontend_sndbuf));

	listener_set_state(listener, LI_LISTEN);

 udp_return:
	if (msg && errlen) {
		char pn[INET6_ADDRSTRLEN];

		addr_to_str(&listener->rx.addr, pn, sizeof(pn));
		snprintf(errmsg, errlen, "%s for [%s:%d]", msg, pn, get_host_port(&listener->rx.addr));
	}
	return err;
}

/* Enable receipt of incoming connections for listener <l>. The receiver must
 * still be valid. Does nothing in early boot (needs fd_updt).
 */
static void quic_enable_listener(struct listener *l)
{
	/* FIXME: The following statements are incorrect. This
	 * is the responsibility of the QUIC xprt to stop accepting new
	 * connections.
	 */
	if (fd_updt)
		fd_want_recv(l->rx.fd);
}

/* Disable receipt of incoming connections for listener <l>. The receiver must
 * still be valid. Does nothing in early boot (needs fd_updt).
 */
static void quic_disable_listener(struct listener *l)
{
	/* FIXME: The following statements are incorrect. This
	 * is the responsibility of the QUIC xprt to start accepting new
	 * connections again.
	 */
	if (fd_updt)
		fd_stop_recv(l->rx.fd);
}

static int quic_get_info(struct connection *conn, long long int *info, int info_num)
{
	struct quic_conn *qc = conn->handle.qc;

	switch (info_num) {
	case 0:  *info = qc->path->loss.srtt * 1000;      break;
	case 1:  *info = qc->path->loss.rtt_var * 1000;   break;
	case 4:  *info = qc->path->loss.nb_lost_pkt;      break;
	case 7:  *info = qc->path->loss.nb_reordered_pkt; break;
	default: return 0;
	}

	return 1;
}

/* change the connection's thread to <new_tid>. For frontend connections, the
 * target is a listener, and the caller is responsible for guaranteeing that
 * the listener assigned to the connection is bound to the requested thread.
 */
static int quic_bind_tid_prep(struct connection *conn, int new_tid)
{
	struct quic_conn *qc = conn->handle.qc;
	return qc_bind_tid_prep(qc, new_tid);
}

static void quic_bind_tid_commit(struct connection *conn)
{
	struct quic_conn *qc = conn->handle.qc;
	qc_bind_tid_commit(qc, objt_listener(conn->target));
}

static void quic_bind_tid_reset(struct connection *conn)
{
	struct quic_conn *qc = conn->handle.qc;
	qc_bind_tid_reset(qc);
}

static int quic_alloc_dghdlrs(void)
{
	int i;

	quic_dghdlrs = calloc(global.nbthread, sizeof(*quic_dghdlrs));
	if (!quic_dghdlrs) {
		ha_alert("Failed to allocate the quic datagram handlers.\n");
		return 0;
	}

	for (i = 0; i < global.nbthread; i++) {
		struct quic_dghdlr *dghdlr = &quic_dghdlrs[i];

		dghdlr->task = tasklet_new();
		if (!dghdlr->task) {
			ha_alert("Failed to allocate the quic datagram handler on thread %d.\n", i);
			return 0;
		}

		tasklet_set_tid(dghdlr->task, i);
		dghdlr->task->context = dghdlr;
		dghdlr->task->process = quic_lstnr_dghdlr;

		MT_LIST_INIT(&dghdlr->dgrams);
	}

	return 1;
}
REGISTER_POST_CHECK(quic_alloc_dghdlrs);

static int quic_deallocate_dghdlrs(void)
{
	int i;

	if (quic_dghdlrs) {
		for (i = 0; i < global.nbthread; ++i)
			tasklet_free(quic_dghdlrs[i].task);
		free(quic_dghdlrs);
	}

	return 1;
}
REGISTER_POST_DEINIT(quic_deallocate_dghdlrs);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
