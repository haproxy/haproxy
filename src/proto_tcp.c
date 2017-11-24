/*
 * AF_INET/AF_INET6 SOCK_STREAM protocol layer (tcp)
 *
 * Copyright 2000-2013 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

/* this is to have tcp_info defined on systems using musl
 * library, such as Alpine Linux
 */
#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <netinet/tcp.h>
#include <netinet/in.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/errors.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/namespace.h>

#include <types/action.h>
#include <types/connection.h>
#include <types/global.h>
#include <types/stream.h>

#include <proto/arg.h>
#include <proto/channel.h>
#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/listener.h>
#include <proto/log.h>
#include <proto/port_range.h>
#include <proto/protocol.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/proxy.h>
#include <proto/sample.h>
#include <proto/server.h>
#include <proto/task.h>
#include <proto/tcp_rules.h>

static int tcp_bind_listeners(struct protocol *proto, char *errmsg, int errlen);
static int tcp_bind_listener(struct listener *listener, char *errmsg, int errlen);
static void tcpv4_add_listener(struct listener *listener, int port);
static void tcpv6_add_listener(struct listener *listener, int port);

/* Note: must not be declared <const> as its list will be overwritten */
static struct protocol proto_tcpv4 = {
	.name = "tcpv4",
	.sock_domain = AF_INET,
	.sock_type = SOCK_STREAM,
	.sock_prot = IPPROTO_TCP,
	.sock_family = AF_INET,
	.sock_addrlen = sizeof(struct sockaddr_in),
	.l3_addrlen = 32/8,
	.accept = &listener_accept,
	.connect = tcp_connect_server,
	.bind = tcp_bind_listener,
	.bind_all = tcp_bind_listeners,
	.unbind_all = unbind_all_listeners,
	.enable_all = enable_all_listeners,
	.get_src = tcp_get_src,
	.get_dst = tcp_get_dst,
	.drain = tcp_drain,
	.pause = tcp_pause_listener,
	.add = tcpv4_add_listener,
	.listeners = LIST_HEAD_INIT(proto_tcpv4.listeners),
	.nb_listeners = 0,
};

/* Note: must not be declared <const> as its list will be overwritten */
static struct protocol proto_tcpv6 = {
	.name = "tcpv6",
	.sock_domain = AF_INET6,
	.sock_type = SOCK_STREAM,
	.sock_prot = IPPROTO_TCP,
	.sock_family = AF_INET6,
	.sock_addrlen = sizeof(struct sockaddr_in6),
	.l3_addrlen = 128/8,
	.accept = &listener_accept,
	.connect = tcp_connect_server,
	.bind = tcp_bind_listener,
	.bind_all = tcp_bind_listeners,
	.unbind_all = unbind_all_listeners,
	.enable_all = enable_all_listeners,
	.get_src = tcp_get_src,
	.get_dst = tcp_get_dst,
	.drain = tcp_drain,
	.pause = tcp_pause_listener,
	.add = tcpv6_add_listener,
	.listeners = LIST_HEAD_INIT(proto_tcpv6.listeners),
	.nb_listeners = 0,
};

/* Default TCP parameters, got by opening a temporary TCP socket. */
#ifdef TCP_MAXSEG
static THREAD_LOCAL int default_tcp_maxseg = -1;
static THREAD_LOCAL int default_tcp6_maxseg = -1;
#endif

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
int tcp_bind_socket(int fd, int flags, struct sockaddr_storage *local, struct sockaddr_storage *remote)
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
			if (0
#if defined(IP_TRANSPARENT)
			    || (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one)) == 0)
#endif
#if defined(IP_FREEBIND)
			    || (setsockopt(fd, SOL_IP, IP_FREEBIND, &one, sizeof(one)) == 0)
#endif
#if defined(IP_BINDANY)
			    || (setsockopt(fd, IPPROTO_IP, IP_BINDANY, &one, sizeof(one)) == 0)
#endif
#if defined(SO_BINDANY)
			    || (setsockopt(fd, SOL_SOCKET, SO_BINDANY, &one, sizeof(one)) == 0)
#endif
			    )
				foreign_ok = 1;
			else
				ip_transp_working = 0;
		}
		break;
	case AF_INET6:
		if (flags && ip6_transp_working) {
			if (0
#if defined(IPV6_TRANSPARENT) && defined(SOL_IPV6)
			    || (setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &one, sizeof(one)) == 0)
#endif
#if defined(IP_FREEBIND)
			    || (setsockopt(fd, SOL_IP, IP_FREEBIND, &one, sizeof(one)) == 0)
#endif
#if defined(IPV6_BINDANY)
			    || (setsockopt(fd, IPPROTO_IPV6, IPV6_BINDANY, &one, sizeof(one)) == 0)
#endif
#if defined(SO_BINDANY)
			    || (setsockopt(fd, SOL_SOCKET, SO_BINDANY, &one, sizeof(one)) == 0)
#endif
			    )
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

static int create_server_socket(struct connection *conn)
{
	const struct netns_entry *ns = NULL;

#ifdef CONFIG_HAP_NS
	if (objt_server(conn->target)) {
		if (__objt_server(conn->target)->flags & SRV_F_USE_NS_FROM_PP)
			ns = conn->proxy_netns;
		else
			ns = __objt_server(conn->target)->netns;
	}
#endif
	return my_socketat(ns, conn->addr.to.ss_family, SOCK_STREAM, IPPROTO_TCP);
}

/*
 * This function initiates a TCP connection establishment to the target assigned
 * to connection <conn> using (si->{target,addr.to}). A source address may be
 * pointed to by conn->addr.from in case of transparent proxying. Normal source
 * bind addresses are still determined locally (due to the possible need of a
 * source port). conn->target may point either to a valid server or to a backend,
 * depending on conn->target. Only OBJ_TYPE_PROXY and OBJ_TYPE_SERVER are
 * supported. The <data> parameter is a boolean indicating whether there are data
 * waiting for being sent or not, in order to adjust data write polling and on
 * some platforms, the ability to avoid an empty initial ACK. The <delack> argument
 * allows the caller to force using a delayed ACK when establishing the connection :
 *   - 0 = no delayed ACK unless data are advertised and backend has tcp-smart-connect
 *   - 1 = delayed ACK if backend has tcp-smart-connect, regardless of data
 *   - 2 = delayed ACK regardless of backend options
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

int tcp_connect_server(struct connection *conn, int data, int delack)
{
	int fd;
	struct server *srv;
	struct proxy *be;
	struct conn_src *src;

	conn->flags = CO_FL_WAIT_L4_CONN; /* connection in progress */

	switch (obj_type(conn->target)) {
	case OBJ_TYPE_PROXY:
		be = objt_proxy(conn->target);
		srv = NULL;
		break;
	case OBJ_TYPE_SERVER:
		srv = objt_server(conn->target);
		be = srv->proxy;
		break;
	default:
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_INTERNAL;
	}

	fd = conn->handle.fd = create_server_socket(conn);

	if (fd == -1) {
		qfprintf(stderr, "Cannot get a server socket.\n");

		if (errno == ENFILE) {
			conn->err_code = CO_ER_SYS_FDLIM;
			send_log(be, LOG_EMERG,
				 "Proxy %s reached system FD limit at %d. Please check system tunables.\n",
				 be->id, maxfd);
		}
		else if (errno == EMFILE) {
			conn->err_code = CO_ER_PROC_FDLIM;
			send_log(be, LOG_EMERG,
				 "Proxy %s reached process FD limit at %d. Please check 'ulimit-n' and restart.\n",
				 be->id, maxfd);
		}
		else if (errno == ENOBUFS || errno == ENOMEM) {
			conn->err_code = CO_ER_SYS_MEMLIM;
			send_log(be, LOG_EMERG,
				 "Proxy %s reached system memory limit at %d sockets. Please check system tunables.\n",
				 be->id, maxfd);
		}
		else if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT) {
			conn->err_code = CO_ER_NOPROTO;
		}
		else
			conn->err_code = CO_ER_SOCK_ERR;

		/* this is a resource error */
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_RESOURCE;
	}

	if (fd >= global.maxsock) {
		/* do not log anything there, it's a normal condition when this option
		 * is used to serialize connections to a server !
		 */
		ha_alert("socket(): not enough free sockets. Raise -n argument. Giving up.\n");
		close(fd);
		conn->err_code = CO_ER_CONF_FDLIM;
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_PRXCOND; /* it is a configuration limit */
	}

	if ((fcntl(fd, F_SETFL, O_NONBLOCK)==-1) ||
	    (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == -1)) {
		qfprintf(stderr,"Cannot set client socket to non blocking mode.\n");
		close(fd);
		conn->err_code = CO_ER_SOCK_ERR;
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_INTERNAL;
	}

	if (be->options & PR_O_TCP_SRV_KA)
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));

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

		if (is_inet_addr(&conn->addr.from)) {
			switch (src->opts & CO_SRC_TPROXY_MASK) {
			case CO_SRC_TPROXY_CLI:
				conn->flags |= CO_FL_PRIVATE;
				/* fall through */
			case CO_SRC_TPROXY_ADDR:
				flags = 3;
				break;
			case CO_SRC_TPROXY_CIP:
			case CO_SRC_TPROXY_DYN:
				conn->flags |= CO_FL_PRIVATE;
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

				ret = tcp_bind_socket(fd, flags, &sa, &conn->addr.from);
				if (ret != 0)
					conn->err_code = CO_ER_CANT_BIND;
			} while (ret != 0); /* binding NOK */
		}
		else {
#ifdef IP_BIND_ADDRESS_NO_PORT
			static THREAD_LOCAL int bind_address_no_port = 1;
			setsockopt(fd, SOL_IP, IP_BIND_ADDRESS_NO_PORT, (const void *) &bind_address_no_port, sizeof(int));
#endif
			ret = tcp_bind_socket(fd, flags, &src->source_addr, &conn->addr.from);
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

#if defined(TCP_QUICKACK)
	/* disabling tcp quick ack now allows the first request to leave the
	 * machine with the first ACK. We only do this if there are pending
	 * data in the buffer.
	 */
	if (delack == 2 || ((delack || data || conn->send_proxy_ofs) && (be->options2 & PR_O2_SMARTCON)))
                setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &zero, sizeof(zero));
#endif

#ifdef TCP_USER_TIMEOUT
	/* there is not much more we can do here when it fails, it's still minor */
	if (srv && srv->tcp_ut)
		setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &srv->tcp_ut, sizeof(srv->tcp_ut));
#endif
	if (global.tune.server_sndbuf)
                setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &global.tune.server_sndbuf, sizeof(global.tune.server_sndbuf));

	if (global.tune.server_rcvbuf)
                setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &global.tune.server_rcvbuf, sizeof(global.tune.server_rcvbuf));

	if (connect(fd, (struct sockaddr *)&conn->addr.to, get_addr_len(&conn->addr.to)) == -1) {
		if (errno == EINPROGRESS || errno == EALREADY) {
			/* common case, let's wait for connect status */
			conn->flags |= CO_FL_WAIT_L4_CONN;
		}
		else if (errno == EISCONN) {
			/* should normally not happen but if so, indicates that it's OK */
			conn->flags &= ~CO_FL_WAIT_L4_CONN;
		}
		else if (errno == EAGAIN || errno == EADDRINUSE || errno == EADDRNOTAVAIL) {
			char *msg;
			if (errno == EAGAIN || errno == EADDRNOTAVAIL) {
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

	conn->flags |= CO_FL_ADDR_TO_SET;

	/* Prepare to send a few handshakes related to the on-wire protocol. */
	if (conn->send_proxy_ofs)
		conn->flags |= CO_FL_SEND_PROXY;

	conn_ctrl_init(conn);       /* registers the FD */
	fdtab[fd].linger_risk = 1;  /* close hard if needed */

	if (conn_xprt_init(conn) < 0) {
		conn_full_close(conn);
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_RESOURCE;
	}

	if (conn->flags & (CO_FL_HANDSHAKE | CO_FL_WAIT_L4_CONN | CO_FL_EARLY_SSL_HS)) {
		conn_sock_want_send(conn);  /* for connect status, proxy protocol or SSL */
		if (conn->flags & CO_FL_EARLY_SSL_HS)
			conn_xprt_want_send(conn);
	}
	else {
		/* If there's no more handshake, we need to notify the data
		 * layer when the connection is already OK otherwise we'll have
		 * no other opportunity to do it later (eg: health checks).
		 */
		data = 1;
	}

	if (data)
		conn_xprt_want_send(conn);  /* prepare to send data if any */

	return SF_ERR_NONE;  /* connection is OK */
}


/*
 * Retrieves the source address for the socket <fd>, with <dir> indicating
 * if we're a listener (=0) or an initiator (!=0). It returns 0 in case of
 * success, -1 in case of error. The socket's source address is stored in
 * <sa> for <salen> bytes.
 */
int tcp_get_src(int fd, struct sockaddr *sa, socklen_t salen, int dir)
{
	if (dir)
		return getsockname(fd, sa, &salen);
	else
		return getpeername(fd, sa, &salen);
}


/*
 * Retrieves the original destination address for the socket <fd>, with <dir>
 * indicating if we're a listener (=0) or an initiator (!=0). In the case of a
 * listener, if the original destination address was translated, the original
 * address is retrieved. It returns 0 in case of success, -1 in case of error.
 * The socket's source address is stored in <sa> for <salen> bytes.
 */
int tcp_get_dst(int fd, struct sockaddr *sa, socklen_t salen, int dir)
{
	if (dir)
		return getpeername(fd, sa, &salen);
	else {
		int ret = getsockname(fd, sa, &salen);

		if (ret < 0)
			return ret;

#if defined(TPROXY) && defined(SO_ORIGINAL_DST)
		/* For TPROXY and Netfilter's NAT, we can retrieve the original
		 * IPv4 address before DNAT/REDIRECT. We must not do that with
		 * other families because v6-mapped IPv4 addresses are still
		 * reported as v4.
		 */
		if (((struct sockaddr_storage *)sa)->ss_family == AF_INET
		    && getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, sa, &salen) == 0)
			return 0;
#endif
		return ret;
	}
}

/* Tries to drain any pending incoming data from the socket to reach the
 * receive shutdown. Returns positive if the shutdown was found, negative
 * if EAGAIN was hit, otherwise zero. This is useful to decide whether we
 * can close a connection cleanly are we must kill it hard.
 */
int tcp_drain(int fd)
{
	int turns = 2;
	int len;

	while (turns) {
#ifdef MSG_TRUNC_CLEARS_INPUT
		len = recv(fd, NULL, INT_MAX, MSG_DONTWAIT | MSG_NOSIGNAL | MSG_TRUNC);
		if (len == -1 && errno == EFAULT)
#endif
			len = recv(fd, trash.str, trash.size, MSG_DONTWAIT | MSG_NOSIGNAL);

		if (len == 0) {
			/* cool, shutdown received */
			fdtab[fd].linger_risk = 0;
			return 1;
		}

		if (len < 0) {
			if (errno == EAGAIN) {
				/* connection not closed yet */
				fd_cant_recv(fd);
				return -1;
			}
			if (errno == EINTR)  /* oops, try again */
				continue;
			/* other errors indicate a dead connection, fine. */
			fdtab[fd].linger_risk = 0;
			return 1;
		}
		/* OK we read some data, let's try again once */
		turns--;
	}
	/* some data are still present, give up */
	return 0;
}

/* This is the callback which is set when a connection establishment is pending
 * and we have nothing to send. It updates the FD polling status. It returns 0
 * if it fails in a fatal way or needs to poll to go further, otherwise it
 * returns non-zero and removes the CO_FL_WAIT_L4_CONN flag from the connection's
 * flags. In case of error, it sets CO_FL_ERROR and leaves the error code in
 * errno. The error checking is done in two passes in order to limit the number
 * of syscalls in the normal case :
 *   - if POLL_ERR was reported by the poller, we check for a pending error on
 *     the socket before proceeding. If found, it's assigned to errno so that
 *     upper layers can see it.
 *   - otherwise connect() is used to check the connection state again, since
 *     the getsockopt return cannot reliably be used to know if the connection
 *     is still pending or ready. This one may often return an error as well,
 *     since we don't always have POLL_ERR (eg: OSX or cached events).
 */
int tcp_connect_probe(struct connection *conn)
{
	int fd = conn->handle.fd;
	socklen_t lskerr;
	int skerr;

	if (conn->flags & CO_FL_ERROR)
		return 0;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!(conn->flags & CO_FL_WAIT_L4_CONN))
		return 1; /* strange we were called while ready */

	if (!fd_send_ready(fd))
		return 0;

	/* we might be the first witness of FD_POLL_ERR. Note that FD_POLL_HUP
	 * without FD_POLL_IN also indicates a hangup without input data meaning
	 * there was no connection.
	 */
	if (fdtab[fd].ev & FD_POLL_ERR ||
	    (fdtab[fd].ev & (FD_POLL_IN|FD_POLL_HUP)) == FD_POLL_HUP) {
		skerr = 0;
		lskerr = sizeof(skerr);
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
		errno = skerr;
		if (errno == EAGAIN)
			errno = 0;
		if (errno)
			goto out_error;
	}

	/* Use connect() to check the state of the socket. This has the
	 * advantage of giving us the following info :
	 *  - error
	 *  - connecting (EALREADY, EINPROGRESS)
	 *  - connected (EISCONN, 0)
	 */
	if (connect(fd, (struct sockaddr *)&conn->addr.to, get_addr_len(&conn->addr.to)) < 0) {
		if (errno == EALREADY || errno == EINPROGRESS) {
			__conn_sock_stop_recv(conn);
			fd_cant_send(fd);
			return 0;
		}

		if (errno && errno != EISCONN)
			goto out_error;

		/* otherwise we're connected */
	}

	/* The FD is ready now, we'll mark the connection as complete and
	 * forward the event to the transport layer which will notify the
	 * data layer.
	 */
	conn->flags &= ~CO_FL_WAIT_L4_CONN;
	return 1;

 out_error:
	/* Write error on the file descriptor. Report it to the connection
	 * and disable polling on this FD.
	 */
	fdtab[fd].linger_risk = 0;
	conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
	__conn_sock_stop_both(conn);
	return 0;
}

/* XXX: Should probably be elsewhere */
static int compare_sockaddr(struct sockaddr_storage *a, struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family) {
		return (-1);
	}
	switch (a->ss_family) {
	case AF_INET:
		{
			struct sockaddr_in *a4 = (void *)a, *b4 = (void *)b;
			if (a4->sin_port != b4->sin_port)
				return (-1);
			return (memcmp(&a4->sin_addr, &b4->sin_addr,
			    sizeof(a4->sin_addr)));
		}
	case AF_INET6:
		{
			struct sockaddr_in6 *a6 = (void *)a, *b6 = (void *)b;
			if (a6->sin6_port != b6->sin6_port)
				return (-1);
			return (memcmp(&a6->sin6_addr, &b6->sin6_addr,
			    sizeof(a6->sin6_addr)));
		}
	default:
		return (-1);
	}

}

#define LI_MANDATORY_FLAGS	(LI_O_FOREIGN | LI_O_V6ONLY | LI_O_V4V6)
/* When binding the listeners, check if a socket has been sent to us by the
 * previous process that we could reuse, instead of creating a new one.
 */
static int tcp_find_compatible_fd(struct listener *l)
{
	struct xfer_sock_list *xfer_sock = xfer_sock_list;
	int ret = -1;

	while (xfer_sock) {
		if (!compare_sockaddr(&xfer_sock->addr, &l->addr)) {
			if ((l->interface == NULL && xfer_sock->iface == NULL) ||
			    (l->interface != NULL && xfer_sock->iface != NULL &&
			     !strcmp(l->interface, xfer_sock->iface))) {
				if ((l->options & LI_MANDATORY_FLAGS) ==
				    (xfer_sock->options & LI_MANDATORY_FLAGS)) {
					if ((xfer_sock->namespace == NULL &&
					    l->netns == NULL)
#ifdef CONFIG_HAP_NS
					    || (xfer_sock->namespace != NULL &&
					    l->netns != NULL &&
					    !strcmp(xfer_sock->namespace,
					    l->netns->node.key))
#endif
					   ) {
						break;
					}

				}
			}
		}
		xfer_sock = xfer_sock->next;
	}
	if (xfer_sock != NULL) {
		ret = xfer_sock->fd;
		if (xfer_sock == xfer_sock_list)
			xfer_sock_list = xfer_sock->next;
		if (xfer_sock->prev)
			xfer_sock->prev->next = xfer_sock->next;
		if (xfer_sock->next)
			xfer_sock->next->prev = xfer_sock->prev;
		free(xfer_sock->iface);
		free(xfer_sock->namespace);
		free(xfer_sock);
	}
	return ret;
}
#undef L1_MANDATORY_FLAGS

/* This function tries to bind a TCPv4/v6 listener. It may return a warning or
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
int tcp_bind_listener(struct listener *listener, char *errmsg, int errlen)
{
	__label__ tcp_return, tcp_close_return;
	int fd, err;
	int ext, ready;
	socklen_t ready_len;
	const char *msg = NULL;
#ifdef TCP_MAXSEG

	/* Create a temporary TCP socket to get default parameters we can't
	 * guess.
	 * */
	ready_len = sizeof(default_tcp_maxseg);
	if (default_tcp_maxseg == -1) {
		default_tcp_maxseg = -2;
		fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (fd < 0)
			ha_warning("Failed to create a temporary socket!\n");
		else {
			if (getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &default_tcp_maxseg,
			    &ready_len) == -1)
				ha_warning("Failed to get the default value of TCP_MAXSEG\n");
		}
		close(fd);
	}
	if (default_tcp6_maxseg == -1) {
		default_tcp6_maxseg = -2;
		fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		if (fd >= 0) {
			if (getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &default_tcp6_maxseg,
			    &ready_len) == -1)
				ha_warning("Failed ot get the default value of TCP_MAXSEG for IPv6\n");
			close(fd);
		}
	}
#endif


	/* ensure we never return garbage */
	if (errlen)
		*errmsg = 0;

	if (listener->state != LI_ASSIGNED)
		return ERR_NONE; /* already bound */

	err = ERR_NONE;

	if (listener->fd == -1)
		listener->fd = tcp_find_compatible_fd(listener);

	/* if the listener already has an fd assigned, then we were offered the
	 * fd by an external process (most likely the parent), and we don't want
	 * to create a new socket. However we still want to set a few flags on
	 * the socket.
	 */
	fd = listener->fd;
	ext = (fd >= 0);

	if (!ext) {
		fd = my_socketat(listener->netns, listener->addr.ss_family, SOCK_STREAM, IPPROTO_TCP);

		if (fd == -1) {
			err |= ERR_RETRYABLE | ERR_ALERT;
			msg = "cannot create listening socket";
			goto tcp_return;
		}
	}

	if (fd >= global.maxsock) {
		err |= ERR_FATAL | ERR_ABORT | ERR_ALERT;
		msg = "not enough free sockets (raise '-n' parameter)";
		goto tcp_close_return;
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		err |= ERR_FATAL | ERR_ALERT;
		msg = "cannot make socket non-blocking";
		goto tcp_close_return;
	}

	if (!ext && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1) {
		/* not fatal but should be reported */
		msg = "cannot do so_reuseaddr";
		err |= ERR_ALERT;
	}

	if (listener->options & LI_O_NOLINGER)
		setsockopt(fd, SOL_SOCKET, SO_LINGER, &nolinger, sizeof(struct linger));
	else {
		struct linger tmplinger;
		socklen_t len = sizeof(tmplinger);
		if (getsockopt(fd, SOL_SOCKET, SO_LINGER, &tmplinger, &len) == 0 &&
		    (tmplinger.l_onoff == 1 || tmplinger.l_linger == 0)) {
			tmplinger.l_onoff = 0;
			tmplinger.l_linger = 0;
			setsockopt(fd, SOL_SOCKET, SO_LINGER, &tmplinger,
			    sizeof(tmplinger));
		}
	}

#ifdef SO_REUSEPORT
	/* OpenBSD and Linux 3.9 support this. As it's present in old libc versions of
	 * Linux, it might return an error that we will silently ignore.
	 */
	if (!ext && (global.tune.options & GTUNE_USE_REUSEPORT))
		setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif

	if (!ext && (listener->options & LI_O_FOREIGN)) {
		switch (listener->addr.ss_family) {
		case AF_INET:
			if (1
#if defined(IP_TRANSPARENT)
			    && (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one)) == -1)
#endif
#if defined(IP_FREEBIND)
			    && (setsockopt(fd, SOL_IP, IP_FREEBIND, &one, sizeof(one)) == -1)
#endif
#if defined(IP_BINDANY)
			    && (setsockopt(fd, IPPROTO_IP, IP_BINDANY, &one, sizeof(one)) == -1)
#endif
#if defined(SO_BINDANY)
			    && (setsockopt(fd, SOL_SOCKET, SO_BINDANY, &one, sizeof(one)) == -1)
#endif
			    ) {
				msg = "cannot make listening socket transparent";
				err |= ERR_ALERT;
			}
		break;
		case AF_INET6:
			if (1
#if defined(IPV6_TRANSPARENT) && defined(SOL_IPV6)
			    && (setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &one, sizeof(one)) == -1)
#endif
#if defined(IP_FREEBIND)
			    && (setsockopt(fd, SOL_IP, IP_FREEBIND, &one, sizeof(one)) == -1)
#endif
#if defined(IPV6_BINDANY)
			    && (setsockopt(fd, IPPROTO_IPV6, IPV6_BINDANY, &one, sizeof(one)) == -1)
#endif
#if defined(SO_BINDANY)
			    && (setsockopt(fd, SOL_SOCKET, SO_BINDANY, &one, sizeof(one)) == -1)
#endif
			    ) {
				msg = "cannot make listening socket transparent";
				err |= ERR_ALERT;
			}
		break;
		}
	}

#ifdef SO_BINDTODEVICE
	/* Note: this might fail if not CAP_NET_RAW */
	if (!ext && listener->interface) {
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
			       listener->interface, strlen(listener->interface) + 1) == -1) {
			msg = "cannot bind listener to device";
			err |= ERR_WARN;
		}
	}
#endif
#if defined(TCP_MAXSEG)
	if (listener->maxseg > 0) {
		if (setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG,
			       &listener->maxseg, sizeof(listener->maxseg)) == -1) {
			msg = "cannot set MSS";
			err |= ERR_WARN;
		}
	} else if (ext) {
		int tmpmaxseg = -1;
		int defaultmss;
		socklen_t len = sizeof(tmpmaxseg);

		if (listener->addr.ss_family == AF_INET)
			defaultmss = default_tcp_maxseg;
		else
			defaultmss = default_tcp6_maxseg;

		getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &tmpmaxseg, &len);
		if (tmpmaxseg != defaultmss && setsockopt(fd, IPPROTO_TCP,
						TCP_MAXSEG, &defaultmss,
						sizeof(defaultmss)) == -1) {
			msg = "cannot set MSS";
			err |= ERR_WARN;
		}
	}
#endif
#if defined(TCP_USER_TIMEOUT)
	if (listener->tcp_ut) {
		if (setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT,
			       &listener->tcp_ut, sizeof(listener->tcp_ut)) == -1) {
			msg = "cannot set TCP User Timeout";
			err |= ERR_WARN;
		}
	} else
		setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &zero,
		    sizeof(zero));
#endif
#if defined(TCP_DEFER_ACCEPT)
	if (listener->options & LI_O_DEF_ACCEPT) {
		/* defer accept by up to one second */
		int accept_delay = 1;
		if (setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &accept_delay, sizeof(accept_delay)) == -1) {
			msg = "cannot enable DEFER_ACCEPT";
			err |= ERR_WARN;
		}
	} else
		setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &zero,
		    sizeof(zero));
#endif
#if defined(TCP_FASTOPEN)
	if (listener->options & LI_O_TCP_FO) {
		/* TFO needs a queue length, let's use the configured backlog */
		int qlen = listener->backlog ? listener->backlog : listener->maxconn;
		if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen)) == -1) {
			msg = "cannot enable TCP_FASTOPEN";
			err |= ERR_WARN;
		}
	} else {
		socklen_t len;
		int qlen;
		len = sizeof(qlen);
		/* Only disable fast open if it was enabled, we don't want
		 * the kernel to create a fast open queue if there's none.
		 */
		if (getsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &qlen, &len) == 0 &&
		    qlen != 0) {
			if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &zero,
			    sizeof(zero)) == -1) {
				msg = "cannot disable TCP_FASTOPEN";
				err |= ERR_WARN;
			}
		}
	}
#endif
#if defined(IPV6_V6ONLY)
	if (listener->options & LI_O_V6ONLY)
                setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
	else if (listener->options & LI_O_V4V6)
                setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
#endif

	if (!ext && bind(fd, (struct sockaddr *)&listener->addr, listener->proto->sock_addrlen) == -1) {
		err |= ERR_RETRYABLE | ERR_ALERT;
		msg = "cannot bind socket";
		goto tcp_close_return;
	}

	ready = 0;
	ready_len = sizeof(ready);
	if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &ready, &ready_len) == -1)
		ready = 0;

	if (!(ext && ready) && /* only listen if not already done by external process */
	    listen(fd, listener->backlog ? listener->backlog : listener->maxconn) == -1) {
		err |= ERR_RETRYABLE | ERR_ALERT;
		msg = "cannot listen to socket";
		goto tcp_close_return;
	}

#if defined(TCP_QUICKACK)
	if (listener->options & LI_O_NOQUICKACK)
		setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &zero, sizeof(zero));
	else
		setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
#endif

	/* the socket is ready */
	listener->fd = fd;
	listener->state = LI_LISTEN;

	fdtab[fd].owner = listener; /* reference the listener instead of a task */
	fdtab[fd].iocb = listener->proto->accept;
	if (listener->bind_conf->bind_thread[relative_pid-1])
		fd_insert(fd, listener->bind_conf->bind_thread[relative_pid-1]);
	else
		fd_insert(fd, MAX_THREADS_MASK);

 tcp_return:
	if (msg && errlen) {
		char pn[INET6_ADDRSTRLEN];

		addr_to_str(&listener->addr, pn, sizeof(pn));
		snprintf(errmsg, errlen, "%s [%s:%d]", msg, pn, get_host_port(&listener->addr));
	}
	return err;

 tcp_close_return:
	close(fd);
	goto tcp_return;
}

/* This function creates all TCP sockets bound to the protocol entry <proto>.
 * It is intended to be used as the protocol's bind_all() function.
 * The sockets will be registered but not added to any fd_set, in order not to
 * loose them across the fork(). A call to enable_all_listeners() is needed
 * to complete initialization. The return value is composed from ERR_*.
 */
static int tcp_bind_listeners(struct protocol *proto, char *errmsg, int errlen)
{
	struct listener *listener;
	int err = ERR_NONE;

	list_for_each_entry(listener, &proto->listeners, proto_list) {
		err |= tcp_bind_listener(listener, errmsg, errlen);
		if (err & ERR_ABORT)
			break;
	}

	return err;
}

/* Add <listener> to the list of tcpv4 listeners, on port <port>. The
 * listener's state is automatically updated from LI_INIT to LI_ASSIGNED.
 * The number of listeners for the protocol is updated.
 */
static void tcpv4_add_listener(struct listener *listener, int port)
{
	if (listener->state != LI_INIT)
		return;
	listener->state = LI_ASSIGNED;
	listener->proto = &proto_tcpv4;
	((struct sockaddr_in *)(&listener->addr))->sin_port = htons(port);
	LIST_ADDQ(&proto_tcpv4.listeners, &listener->proto_list);
	proto_tcpv4.nb_listeners++;
}

/* Add <listener> to the list of tcpv6 listeners, on port <port>. The
 * listener's state is automatically updated from LI_INIT to LI_ASSIGNED.
 * The number of listeners for the protocol is updated.
 */
static void tcpv6_add_listener(struct listener *listener, int port)
{
	if (listener->state != LI_INIT)
		return;
	listener->state = LI_ASSIGNED;
	listener->proto = &proto_tcpv6;
	((struct sockaddr_in *)(&listener->addr))->sin_port = htons(port);
	LIST_ADDQ(&proto_tcpv6.listeners, &listener->proto_list);
	proto_tcpv6.nb_listeners++;
}

/* Pause a listener. Returns < 0 in case of failure, 0 if the listener
 * was totally stopped, or > 0 if correctly paused.
 */
int tcp_pause_listener(struct listener *l)
{
	if (shutdown(l->fd, SHUT_WR) != 0)
		return -1; /* Solaris dies here */

	if (listen(l->fd, l->backlog ? l->backlog : l->maxconn) != 0)
		return -1; /* OpenBSD dies here */

	if (shutdown(l->fd, SHUT_RD) != 0)
		return -1; /* should always be OK */
	return 1;
}

/*
 * Execute the "set-src" action. May be called from {tcp,http}request.
 * It only changes the address and tries to preserve the original port. If the
 * previous family was neither AF_INET nor AF_INET6, the port is set to zero.
 */
enum act_return tcp_action_req_set_src(struct act_rule *rule, struct proxy *px,
                                              struct session *sess, struct stream *s, int flags)
{
	struct connection *cli_conn;

	if ((cli_conn = objt_conn(sess->origin)) && conn_ctrl_ready(cli_conn)) {
		struct sample *smp;

		smp = sample_fetch_as_type(px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->arg.expr, SMP_T_ADDR);
		if (smp) {
			int port = get_net_port(&cli_conn->addr.from);

			if (smp->data.type == SMP_T_IPV4) {
				((struct sockaddr_in *)&cli_conn->addr.from)->sin_family = AF_INET;
				((struct sockaddr_in *)&cli_conn->addr.from)->sin_addr.s_addr = smp->data.u.ipv4.s_addr;
				((struct sockaddr_in *)&cli_conn->addr.from)->sin_port = port;
			} else if (smp->data.type == SMP_T_IPV6) {
				((struct sockaddr_in6 *)&cli_conn->addr.from)->sin6_family = AF_INET6;
				memcpy(&((struct sockaddr_in6 *)&cli_conn->addr.from)->sin6_addr, &smp->data.u.ipv6, sizeof(struct in6_addr));
				((struct sockaddr_in6 *)&cli_conn->addr.from)->sin6_port = port;
			}
		}
		cli_conn->flags |= CO_FL_ADDR_FROM_SET;
	}
	return ACT_RET_CONT;
}

/*
 * Execute the "set-dst" action. May be called from {tcp,http}request.
 * It only changes the address and tries to preserve the original port. If the
 * previous family was neither AF_INET nor AF_INET6, the port is set to zero.
 */
enum act_return tcp_action_req_set_dst(struct act_rule *rule, struct proxy *px,
                                              struct session *sess, struct stream *s, int flags)
{
	struct connection *cli_conn;

	if ((cli_conn = objt_conn(sess->origin)) && conn_ctrl_ready(cli_conn)) {
		struct sample *smp;

		smp = sample_fetch_as_type(px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->arg.expr, SMP_T_ADDR);
		if (smp) {
			int port = get_net_port(&cli_conn->addr.to);

			if (smp->data.type == SMP_T_IPV4) {
				((struct sockaddr_in *)&cli_conn->addr.to)->sin_family = AF_INET;
				((struct sockaddr_in *)&cli_conn->addr.to)->sin_addr.s_addr = smp->data.u.ipv4.s_addr;
			} else if (smp->data.type == SMP_T_IPV6) {
				((struct sockaddr_in6 *)&cli_conn->addr.to)->sin6_family = AF_INET6;
				memcpy(&((struct sockaddr_in6 *)&cli_conn->addr.to)->sin6_addr, &smp->data.u.ipv6, sizeof(struct in6_addr));
				((struct sockaddr_in6 *)&cli_conn->addr.to)->sin6_port = port;
			}
			cli_conn->flags |= CO_FL_ADDR_TO_SET;
		}
	}
	return ACT_RET_CONT;
}

/*
 * Execute the "set-src-port" action. May be called from {tcp,http}request.
 * We must test the sin_family before setting the port. If the address family
 * is neither AF_INET nor AF_INET6, the address is forced to AF_INET "0.0.0.0"
 * and the port is assigned.
 */
enum act_return tcp_action_req_set_src_port(struct act_rule *rule, struct proxy *px,
                                              struct session *sess, struct stream *s, int flags)
{
	struct connection *cli_conn;

	if ((cli_conn = objt_conn(sess->origin)) && conn_ctrl_ready(cli_conn)) {
		struct sample *smp;

		conn_get_from_addr(cli_conn);

		smp = sample_fetch_as_type(px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->arg.expr, SMP_T_SINT);
		if (smp) {
			if (cli_conn->addr.from.ss_family == AF_INET6) {
				((struct sockaddr_in6 *)&cli_conn->addr.from)->sin6_port = htons(smp->data.u.sint);
			} else {
				if (cli_conn->addr.from.ss_family != AF_INET) {
					cli_conn->addr.from.ss_family = AF_INET;
					((struct sockaddr_in *)&cli_conn->addr.from)->sin_addr.s_addr = 0;
				}
				((struct sockaddr_in *)&cli_conn->addr.from)->sin_port = htons(smp->data.u.sint);
			}
		}
	}
	return ACT_RET_CONT;
}

/*
 * Execute the "set-dst-port" action. May be called from {tcp,http}request.
 * We must test the sin_family before setting the port. If the address family
 * is neither AF_INET nor AF_INET6, the address is forced to AF_INET "0.0.0.0"
 * and the port is assigned.
 */
enum act_return tcp_action_req_set_dst_port(struct act_rule *rule, struct proxy *px,
                                              struct session *sess, struct stream *s, int flags)
{
	struct connection *cli_conn;

	if ((cli_conn = objt_conn(sess->origin)) && conn_ctrl_ready(cli_conn)) {
		struct sample *smp;

		conn_get_to_addr(cli_conn);

		smp = sample_fetch_as_type(px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->arg.expr, SMP_T_SINT);
		if (smp) {
			if (cli_conn->addr.to.ss_family == AF_INET6) {
				((struct sockaddr_in6 *)&cli_conn->addr.to)->sin6_port = htons(smp->data.u.sint);
			} else {
				if (cli_conn->addr.to.ss_family != AF_INET) {
					cli_conn->addr.to.ss_family = AF_INET;
					((struct sockaddr_in *)&cli_conn->addr.to)->sin_addr.s_addr = 0;
				}
				((struct sockaddr_in *)&cli_conn->addr.to)->sin_port = htons(smp->data.u.sint);
			}
		}
	}
	return ACT_RET_CONT;
}

/* Executes the "silent-drop" action. May be called from {tcp,http}{request,response} */
static enum act_return tcp_exec_action_silent_drop(struct act_rule *rule, struct proxy *px, struct session *sess, struct stream *strm, int flags)
{
	struct connection *conn = objt_conn(sess->origin);

	if (!conn)
		goto out;

	if (!conn_ctrl_ready(conn))
		goto out;

#ifdef TCP_QUICKACK
	/* drain is needed only to send the quick ACK */
	conn_sock_drain(conn);

	/* re-enable quickack if it was disabled to ack all data and avoid
	 * retransmits from the client that might trigger a real reset.
	 */
	setsockopt(conn->handle.fd, SOL_TCP, TCP_QUICKACK, &one, sizeof(one));
#endif
	/* lingering must absolutely be disabled so that we don't send a
	 * shutdown(), this is critical to the TCP_REPAIR trick. When no stream
	 * is present, returning with ERR will cause lingering to be disabled.
	 */
	if (strm)
		strm->si[0].flags |= SI_FL_NOLINGER;

	/* We're on the client-facing side, we must force to disable lingering to
	 * ensure we will use an RST exclusively and kill any pending data.
	 */
	fdtab[conn->handle.fd].linger_risk = 1;

#ifdef TCP_REPAIR
	if (setsockopt(conn->handle.fd, SOL_TCP, TCP_REPAIR, &one, sizeof(one)) == 0) {
		/* socket will be quiet now */
		goto out;
	}
#endif
	/* either TCP_REPAIR is not defined or it failed (eg: permissions).
	 * Let's fall back on the TTL trick, though it only works for routed
	 * network and has no effect on local net.
	 */
#ifdef IP_TTL
	setsockopt(conn->handle.fd, SOL_IP, IP_TTL, &one, sizeof(one));
#endif
 out:
	/* kill the stream if any */
	if (strm) {
		channel_abort(&strm->req);
		channel_abort(&strm->res);
		strm->req.analysers = 0;
		strm->res.analysers = 0;
		HA_ATOMIC_ADD(&strm->be->be_counters.denied_req, 1);
		if (!(strm->flags & SF_ERR_MASK))
			strm->flags |= SF_ERR_PRXCOND;
		if (!(strm->flags & SF_FINST_MASK))
			strm->flags |= SF_FINST_R;
	}

	HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->denied_req, 1);

	return ACT_RET_STOP;
}

/* parse "set-{src,dst}[-port]" action */
enum act_parse_ret tcp_parse_set_src_dst(const char **args, int *orig_arg, struct proxy *px, struct act_rule *rule, char **err)
{
	int cur_arg;
	struct sample_expr *expr;
	unsigned int where;

	cur_arg = *orig_arg;
	expr = sample_parse_expr((char **)args, &cur_arg, px->conf.args.file, px->conf.args.line, err, &px->conf.args);
	if (!expr)
		return ACT_RET_PRS_ERR;

	where = 0;
	if (px->cap & PR_CAP_FE)
		where |= SMP_VAL_FE_HRQ_HDR;
	if (px->cap & PR_CAP_BE)
		where |= SMP_VAL_BE_HRQ_HDR;

	if (!(expr->fetch->val & where)) {
		memprintf(err,
			  "fetch method '%s' extracts information from '%s', none of which is available here",
			  args[cur_arg-1], sample_src_names(expr->fetch->use));
		free(expr);
		return ACT_RET_PRS_ERR;
	}
	rule->arg.expr = expr;
	rule->action = ACT_CUSTOM;

	if (!strcmp(args[*orig_arg-1], "set-src")) {
		rule->action_ptr = tcp_action_req_set_src;
	} else if (!strcmp(args[*orig_arg-1], "set-src-port")) {
		rule->action_ptr = tcp_action_req_set_src_port;
	} else if (!strcmp(args[*orig_arg-1], "set-dst")) {
		rule->action_ptr = tcp_action_req_set_dst;
	} else if (!strcmp(args[*orig_arg-1], "set-dst-port")) {
		rule->action_ptr = tcp_action_req_set_dst_port;
	} else {
		return ACT_RET_PRS_ERR;
	}

	(*orig_arg)++;

	return ACT_RET_PRS_OK;
}


/* Parse a "silent-drop" action. It takes no argument. It returns ACT_RET_PRS_OK on
 * success, ACT_RET_PRS_ERR on error.
 */
static enum act_parse_ret tcp_parse_silent_drop(const char **args, int *orig_arg, struct proxy *px,
                                                struct act_rule *rule, char **err)
{
	rule->action     = ACT_CUSTOM;
	rule->action_ptr = tcp_exec_action_silent_drop;
	return ACT_RET_PRS_OK;
}


/************************************************************************/
/*       All supported sample fetch functions must be declared here     */
/************************************************************************/

/* fetch the connection's source IPv4/IPv6 address */
int smp_fetch_src(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *cli_conn = objt_conn(smp->sess->origin);

	if (!cli_conn)
		return 0;

	switch (cli_conn->addr.from.ss_family) {
	case AF_INET:
		smp->data.u.ipv4 = ((struct sockaddr_in *)&cli_conn->addr.from)->sin_addr;
		smp->data.type = SMP_T_IPV4;
		break;
	case AF_INET6:
		smp->data.u.ipv6 = ((struct sockaddr_in6 *)&cli_conn->addr.from)->sin6_addr;
		smp->data.type = SMP_T_IPV6;
		break;
	default:
		return 0;
	}

	smp->flags = 0;
	return 1;
}

/* set temp integer to the connection's source port */
static int
smp_fetch_sport(const struct arg *args, struct sample *smp, const char *k, void *private)
{
	struct connection *cli_conn = objt_conn(smp->sess->origin);

	if (!cli_conn)
		return 0;

	smp->data.type = SMP_T_SINT;
	if (!(smp->data.u.sint = get_host_port(&cli_conn->addr.from)))
		return 0;

	smp->flags = 0;
	return 1;
}

/* fetch the connection's destination IPv4/IPv6 address */
static int
smp_fetch_dst(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *cli_conn = objt_conn(smp->sess->origin);

	if (!cli_conn)
		return 0;

	conn_get_to_addr(cli_conn);

	switch (cli_conn->addr.to.ss_family) {
	case AF_INET:
		smp->data.u.ipv4 = ((struct sockaddr_in *)&cli_conn->addr.to)->sin_addr;
		smp->data.type = SMP_T_IPV4;
		break;
	case AF_INET6:
		smp->data.u.ipv6 = ((struct sockaddr_in6 *)&cli_conn->addr.to)->sin6_addr;
		smp->data.type = SMP_T_IPV6;
		break;
	default:
		return 0;
	}

	smp->flags = 0;
	return 1;
}

/* check if the destination address of the front connection is local to the
 * system or if it was intercepted.
 */
int smp_fetch_dst_is_local(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn = objt_conn(smp->sess->origin);
	struct listener *li = smp->sess->listener;

	if (!conn)
		return 0;

	conn_get_to_addr(conn);
	if (!(conn->flags & CO_FL_ADDR_TO_SET))
		return 0;

	smp->data.type = SMP_T_BOOL;
	smp->flags = 0;
	smp->data.u.sint = addr_is_local(li->netns, &conn->addr.to);
	return smp->data.u.sint >= 0;
}

/* check if the source address of the front connection is local to the system
 * or not.
 */
int smp_fetch_src_is_local(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn = objt_conn(smp->sess->origin);
	struct listener *li = smp->sess->listener;

	if (!conn)
		return 0;

	conn_get_from_addr(conn);
	if (!(conn->flags & CO_FL_ADDR_FROM_SET))
		return 0;

	smp->data.type = SMP_T_BOOL;
	smp->flags = 0;
	smp->data.u.sint = addr_is_local(li->netns, &conn->addr.from);
	return smp->data.u.sint >= 0;
}

/* set temp integer to the frontend connexion's destination port */
static int
smp_fetch_dport(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *cli_conn = objt_conn(smp->sess->origin);

	if (!cli_conn)
		return 0;

	conn_get_to_addr(cli_conn);

	smp->data.type = SMP_T_SINT;
	if (!(smp->data.u.sint = get_host_port(&cli_conn->addr.to)))
		return 0;

	smp->flags = 0;
	return 1;
}

#ifdef TCP_INFO

/* Returns some tcp_info data is its avalaible. "dir" must be set to 0 if
 * the client connection is require, otherwise it is set to 1. "val" represents
 * the required value. Use 0 for rtt and 1 for rttavg. "unit" is the expected unit
 * by default, the rtt is in us. Id "unit" is set to 0, the unit is us, if it is
 * set to 1, the untis are milliseconds.
 * If the function fails it returns 0, otherwise it returns 1 and "result" is filled.
 */
static inline int get_tcp_info(const struct arg *args, struct sample *smp,
                               int dir, int val)
{
	struct connection *conn;
	struct tcp_info info;
	socklen_t optlen;

	/* strm can be null. */
	if (!smp->strm)
		return 0;

	/* get the object associated with the stream interface.The
	 * object can be other thing than a connection. For example,
	 * it be a appctx. */
	conn = cs_conn(objt_cs(smp->strm->si[dir].end));
	if (!conn)
		return 0;

	/* The fd may not be available for the tcp_info struct, and the
	  syscal can fail. */
	optlen = sizeof(info);
	if (getsockopt(conn->handle.fd, SOL_TCP, TCP_INFO, &info, &optlen) == -1)
		return 0;

	/* extract the value. */
	smp->data.type = SMP_T_SINT;
	switch (val) {
	case 0:  smp->data.u.sint = info.tcpi_rtt;            break;
	case 1:  smp->data.u.sint = info.tcpi_rttvar;         break;
#if defined(__linux__)
	/* these ones are common to all Linux versions */
	case 2:  smp->data.u.sint = info.tcpi_unacked;        break;
	case 3:  smp->data.u.sint = info.tcpi_sacked;         break;
	case 4:  smp->data.u.sint = info.tcpi_lost;           break;
	case 5:  smp->data.u.sint = info.tcpi_retrans;        break;
	case 6:  smp->data.u.sint = info.tcpi_fackets;        break;
	case 7:  smp->data.u.sint = info.tcpi_reordering;     break;
#elif defined(__FreeBSD__) || defined(__NetBSD__)
	/* the ones are found on FreeBSD and NetBSD featuring TCP_INFO */
	case 2:  smp->data.u.sint = info.__tcpi_unacked;      break;
	case 3:  smp->data.u.sint = info.__tcpi_sacked;       break;
	case 4:  smp->data.u.sint = info.__tcpi_lost;         break;
	case 5:  smp->data.u.sint = info.__tcpi_retrans;      break;
	case 6:  smp->data.u.sint = info.__tcpi_fackets;      break;
	case 7:  smp->data.u.sint = info.__tcpi_reordering;   break;
#endif
	default: return 0;
	}

	/* Convert the value as expected. */
	if (args) {
		if (args[0].type == ARGT_STR) {
			if (strcmp(args[0].data.str.str, "us") == 0) {
				/* Do nothing. */
			} else if (strcmp(args[0].data.str.str, "ms") == 0) {
				smp->data.u.sint = (smp->data.u.sint + 500) / 1000;
			} else
				return 0;
		} else if (args[0].type == ARGT_STOP) {
			smp->data.u.sint = (smp->data.u.sint + 500) / 1000;
		} else
			return 0;
	}

	return 1;
}

/* get the mean rtt of a client connexion */
static int
smp_fetch_fc_rtt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 0))
		return 0;
	return 1;
}

/* get the variance of the mean rtt of a client connexion */
static int
smp_fetch_fc_rttvar(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 1))
		return 0;
	return 1;
}

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)

/* get the unacked counter on a client connexion */
static int
smp_fetch_fc_unacked(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 2))
		return 0;
	return 1;
}

/* get the sacked counter on a client connexion */
static int
smp_fetch_fc_sacked(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 3))
		return 0;
	return 1;
}

/* get the lost counter on a client connexion */
static int
smp_fetch_fc_lost(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 4))
		return 0;
	return 1;
}

/* get the retrans counter on a client connexion */
static int
smp_fetch_fc_retrans(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 5))
		return 0;
	return 1;
}

/* get the fackets counter on a client connexion */
static int
smp_fetch_fc_fackets(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 6))
		return 0;
	return 1;
}

/* get the reordering counter on a client connexion */
static int
smp_fetch_fc_reordering(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 7))
		return 0;
	return 1;
}
#endif // linux || freebsd || netbsd
#endif // TCP_INFO

#ifdef IPV6_V6ONLY
/* parse the "v4v6" bind keyword */
static int bind_parse_v4v6(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;

	list_for_each_entry(l, &conf->listeners, by_bind) {
		if (l->addr.ss_family == AF_INET6)
			l->options |= LI_O_V4V6;
	}

	return 0;
}

/* parse the "v6only" bind keyword */
static int bind_parse_v6only(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;

	list_for_each_entry(l, &conf->listeners, by_bind) {
		if (l->addr.ss_family == AF_INET6)
			l->options |= LI_O_V6ONLY;
	}

	return 0;
}
#endif

#ifdef CONFIG_HAP_TRANSPARENT
/* parse the "transparent" bind keyword */
static int bind_parse_transparent(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;

	list_for_each_entry(l, &conf->listeners, by_bind) {
		if (l->addr.ss_family == AF_INET || l->addr.ss_family == AF_INET6)
			l->options |= LI_O_FOREIGN;
	}

	return 0;
}
#endif

#ifdef TCP_DEFER_ACCEPT
/* parse the "defer-accept" bind keyword */
static int bind_parse_defer_accept(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;

	list_for_each_entry(l, &conf->listeners, by_bind) {
		if (l->addr.ss_family == AF_INET || l->addr.ss_family == AF_INET6)
			l->options |= LI_O_DEF_ACCEPT;
	}

	return 0;
}
#endif

#ifdef TCP_FASTOPEN
/* parse the "tfo" bind keyword */
static int bind_parse_tfo(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;

	list_for_each_entry(l, &conf->listeners, by_bind) {
		if (l->addr.ss_family == AF_INET || l->addr.ss_family == AF_INET6)
			l->options |= LI_O_TCP_FO;
	}

	return 0;
}
#endif

#ifdef TCP_MAXSEG
/* parse the "mss" bind keyword */
static int bind_parse_mss(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;
	int mss;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing MSS value", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	mss = atoi(args[cur_arg + 1]);
	if (!mss || abs(mss) > 65535) {
		memprintf(err, "'%s' : expects an MSS with and absolute value between 1 and 65535", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	list_for_each_entry(l, &conf->listeners, by_bind) {
		if (l->addr.ss_family == AF_INET || l->addr.ss_family == AF_INET6)
			l->maxseg = mss;
	}

	return 0;
}
#endif

#ifdef TCP_USER_TIMEOUT
/* parse the "tcp-ut" bind keyword */
static int bind_parse_tcp_ut(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	const char *ptr = NULL;
	struct listener *l;
	unsigned int timeout;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing TCP User Timeout value", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	ptr = parse_time_err(args[cur_arg + 1], &timeout, TIME_UNIT_MS);
	if (ptr) {
		memprintf(err, "'%s' : expects a positive delay in milliseconds", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	list_for_each_entry(l, &conf->listeners, by_bind) {
		if (l->addr.ss_family == AF_INET || l->addr.ss_family == AF_INET6)
			l->tcp_ut = timeout;
	}

	return 0;
}
#endif

#ifdef SO_BINDTODEVICE
/* parse the "interface" bind keyword */
static int bind_parse_interface(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing interface name", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	list_for_each_entry(l, &conf->listeners, by_bind) {
		if (l->addr.ss_family == AF_INET || l->addr.ss_family == AF_INET6)
			l->interface = strdup(args[cur_arg + 1]);
	}

	return 0;
}
#endif

#ifdef CONFIG_HAP_NS
/* parse the "namespace" bind keyword */
static int bind_parse_namespace(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;
	char *namespace = NULL;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing namespace id", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	namespace = args[cur_arg + 1];

	list_for_each_entry(l, &conf->listeners, by_bind) {
		l->netns = netns_store_lookup(namespace, strlen(namespace));

		if (l->netns == NULL)
			l->netns = netns_store_insert(namespace);

		if (l->netns == NULL) {
			ha_alert("Cannot open namespace '%s'.\n", args[cur_arg + 1]);
			return ERR_ALERT | ERR_FATAL;
		}
	}
	return 0;
}
#endif

#ifdef TCP_USER_TIMEOUT
/* parse the "tcp-ut" server keyword */
static int srv_parse_tcp_ut(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	const char *ptr = NULL;
	unsigned int timeout;

	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing TCP User Timeout value", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	ptr = parse_time_err(args[*cur_arg + 1], &timeout, TIME_UNIT_MS);
	if (ptr) {
		memprintf(err, "'%s' : expects a positive delay in milliseconds", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (newsrv->addr.ss_family == AF_INET || newsrv->addr.ss_family == AF_INET6)
		newsrv->tcp_ut = timeout;

	return 0;
}
#endif


/* Note: must not be declared <const> as its list will be overwritten.
 * Note: fetches that may return multiple types must be declared as the lowest
 * common denominator, the type that can be casted into all other ones. For
 * instance v4/v6 must be declared v4.
 */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
	{ "dst",      smp_fetch_dst,   0, NULL, SMP_T_IPV4, SMP_USE_L4CLI },
	{ "dst_is_local", smp_fetch_dst_is_local, 0, NULL, SMP_T_BOOL, SMP_USE_L4CLI },
	{ "dst_port", smp_fetch_dport, 0, NULL, SMP_T_SINT, SMP_USE_L4CLI },
	{ "src",      smp_fetch_src,   0, NULL, SMP_T_IPV4, SMP_USE_L4CLI },
	{ "src_is_local", smp_fetch_src_is_local, 0, NULL, SMP_T_BOOL, SMP_USE_L4CLI },
	{ "src_port", smp_fetch_sport, 0, NULL, SMP_T_SINT, SMP_USE_L4CLI },
#ifdef TCP_INFO
	{ "fc_rtt",           smp_fetch_fc_rtt,           ARG1(0,STR), NULL, SMP_T_SINT, SMP_USE_L4CLI },
	{ "fc_rttvar",        smp_fetch_fc_rttvar,        ARG1(0,STR), NULL, SMP_T_SINT, SMP_USE_L4CLI },
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)
	{ "fc_unacked",       smp_fetch_fc_unacked,       ARG1(0,STR), NULL, SMP_T_SINT, SMP_USE_L4CLI },
	{ "fc_sacked",        smp_fetch_fc_sacked,        ARG1(0,STR), NULL, SMP_T_SINT, SMP_USE_L4CLI },
	{ "fc_retrans",       smp_fetch_fc_retrans,       ARG1(0,STR), NULL, SMP_T_SINT, SMP_USE_L4CLI },
	{ "fc_fackets",       smp_fetch_fc_fackets,       ARG1(0,STR), NULL, SMP_T_SINT, SMP_USE_L4CLI },
	{ "fc_lost",          smp_fetch_fc_lost,          ARG1(0,STR), NULL, SMP_T_SINT, SMP_USE_L4CLI },
	{ "fc_reordering",    smp_fetch_fc_reordering,    ARG1(0,STR), NULL, SMP_T_SINT, SMP_USE_L4CLI },
#endif // linux || freebsd || netbsd
#endif // TCP_INFO
	{ /* END */ },
}};

/************************************************************************/
/*           All supported bind keywords must be declared here.         */
/************************************************************************/

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 */
static struct bind_kw_list bind_kws = { "TCP", { }, {
#ifdef TCP_DEFER_ACCEPT
	{ "defer-accept",  bind_parse_defer_accept, 0 }, /* wait for some data for 1 second max before doing accept */
#endif
#ifdef SO_BINDTODEVICE
	{ "interface",     bind_parse_interface,    1 }, /* specifically bind to this interface */
#endif
#ifdef TCP_MAXSEG
	{ "mss",           bind_parse_mss,          1 }, /* set MSS of listening socket */
#endif
#ifdef TCP_USER_TIMEOUT
	{ "tcp-ut",        bind_parse_tcp_ut,       1 }, /* set User Timeout on listening socket */
#endif
#ifdef TCP_FASTOPEN
	{ "tfo",           bind_parse_tfo,          0 }, /* enable TCP_FASTOPEN of listening socket */
#endif
#ifdef CONFIG_HAP_TRANSPARENT
	{ "transparent",   bind_parse_transparent,  0 }, /* transparently bind to the specified addresses */
#endif
#ifdef IPV6_V6ONLY
	{ "v4v6",          bind_parse_v4v6,         0 }, /* force socket to bind to IPv4+IPv6 */
	{ "v6only",        bind_parse_v6only,       0 }, /* force socket to bind to IPv6 only */
#endif
#ifdef CONFIG_HAP_NS
	{ "namespace",     bind_parse_namespace,    1 },
#endif
	/* the versions with the NULL parse function*/
	{ "defer-accept",  NULL,  0 },
	{ "interface",     NULL,  1 },
	{ "mss",           NULL,  1 },
	{ "transparent",   NULL,  0 },
	{ "v4v6",          NULL,  0 },
	{ "v6only",        NULL,  0 },
	{ NULL, NULL, 0 },
}};

static struct srv_kw_list srv_kws = { "TCP", { }, {
#ifdef TCP_USER_TIMEOUT
	{ "tcp-ut",        srv_parse_tcp_ut,        1,  1 }, /* set TCP user timeout on server */
#endif
	{ NULL, NULL, 0 },
}};

static struct action_kw_list tcp_req_conn_actions = {ILH, {
	{ "silent-drop",  tcp_parse_silent_drop },
	{ "set-src",      tcp_parse_set_src_dst },
	{ "set-src-port", tcp_parse_set_src_dst },
	{ "set-dst"     , tcp_parse_set_src_dst },
	{ "set-dst-port", tcp_parse_set_src_dst },
	{ /* END */ }
}};

static struct action_kw_list tcp_req_sess_actions = {ILH, {
	{ "silent-drop",  tcp_parse_silent_drop },
	{ "set-src",      tcp_parse_set_src_dst },
	{ "set-src-port", tcp_parse_set_src_dst },
	{ "set-dst"     , tcp_parse_set_src_dst },
	{ "set-dst-port", tcp_parse_set_src_dst },
	{ /* END */ }
}};

static struct action_kw_list tcp_req_cont_actions = {ILH, {
	{ "silent-drop", tcp_parse_silent_drop },
	{ /* END */ }
}};

static struct action_kw_list tcp_res_cont_actions = {ILH, {
	{ "silent-drop", tcp_parse_silent_drop },
	{ /* END */ }
}};

static struct action_kw_list http_req_actions = {ILH, {
	{ "silent-drop",  tcp_parse_silent_drop },
	{ "set-src",      tcp_parse_set_src_dst },
	{ "set-src-port", tcp_parse_set_src_dst },
	{ "set-dst",      tcp_parse_set_src_dst },
	{ "set-dst-port", tcp_parse_set_src_dst },
	{ /* END */ }
}};

static struct action_kw_list http_res_actions = {ILH, {
	{ "silent-drop", tcp_parse_silent_drop },
	{ /* END */ }
}};


__attribute__((constructor))
static void __tcp_protocol_init(void)
{
	protocol_register(&proto_tcpv4);
	protocol_register(&proto_tcpv6);
	sample_register_fetches(&sample_fetch_keywords);
	bind_register_keywords(&bind_kws);
	srv_register_keywords(&srv_kws);
	tcp_req_conn_keywords_register(&tcp_req_conn_actions);
	tcp_req_sess_keywords_register(&tcp_req_sess_actions);
	tcp_req_cont_keywords_register(&tcp_req_cont_actions);
	tcp_res_cont_keywords_register(&tcp_res_cont_actions);
	http_req_keywords_register(&http_req_actions);
	http_res_keywords_register(&http_res_actions);


	hap_register_build_opts("Built with transparent proxy support using:"
#if defined(IP_TRANSPARENT)
	       " IP_TRANSPARENT"
#endif
#if defined(IPV6_TRANSPARENT)
	       " IPV6_TRANSPARENT"
#endif
#if defined(IP_FREEBIND)
	       " IP_FREEBIND"
#endif
#if defined(IP_BINDANY)
	       " IP_BINDANY"
#endif
#if defined(IPV6_BINDANY)
	       " IPV6_BINDANY"
#endif
#if defined(SO_BINDANY)
	       " SO_BINDANY"
#endif
		"", 0);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
