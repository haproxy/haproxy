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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/tcp.h>
#include <netinet/in.h>

#include <haproxy/api.h>
#include <haproxy/arg.h>
#include <haproxy/connection.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/namespace.h>
#include <haproxy/port_range.h>
#include <haproxy/proto_tcp.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy-t.h>
#include <haproxy/sock.h>
#include <haproxy/sock_inet.h>
#include <haproxy/tools.h>


static int tcp_bind_listener(struct listener *listener, char *errmsg, int errlen);
static int tcp_suspend_receiver(struct receiver *rx);
static int tcp_resume_receiver(struct receiver *rx);
static void tcp_enable_listener(struct listener *listener);
static void tcp_disable_listener(struct listener *listener);

/* Note: must not be declared <const> as its list will be overwritten */
struct protocol proto_tcpv4 = {
	.name           = "tcpv4",

	/* connection layer */
	.ctrl_type      = SOCK_STREAM,
	.listen         = tcp_bind_listener,
	.enable         = tcp_enable_listener,
	.disable        = tcp_disable_listener,
	.add            = default_add_listener,
	.unbind         = default_unbind_listener,
	.suspend        = default_suspend_listener,
	.resume         = default_resume_listener,
	.accept_conn    = sock_accept_conn,
	.ctrl_init      = sock_conn_ctrl_init,
	.ctrl_close     = sock_conn_ctrl_close,
	.connect        = tcp_connect_server,
	.drain          = sock_drain,
	.check_events   = sock_check_events,
	.ignore_events  = sock_ignore_events,

	/* binding layer */
	.rx_suspend     = tcp_suspend_receiver,
	.rx_resume      = tcp_resume_receiver,

	/* address family */
	.fam            = &proto_fam_inet4,

	/* socket layer */
	.proto_type     = PROTO_TYPE_STREAM,
	.sock_type      = SOCK_STREAM,
	.sock_prot      = IPPROTO_TCP,
	.rx_enable      = sock_enable,
	.rx_disable     = sock_disable,
	.rx_unbind      = sock_unbind,
	.rx_listening   = sock_accepting_conn,
	.default_iocb   = sock_accept_iocb,
	.receivers      = LIST_HEAD_INIT(proto_tcpv4.receivers),
	.nb_receivers   = 0,
};

INITCALL1(STG_REGISTER, protocol_register, &proto_tcpv4);

/* Note: must not be declared <const> as its list will be overwritten */
struct protocol proto_tcpv6 = {
	.name           = "tcpv6",

	/* connection layer */
	.ctrl_type      = SOCK_STREAM,
	.listen         = tcp_bind_listener,
	.enable         = tcp_enable_listener,
	.disable        = tcp_disable_listener,
	.add            = default_add_listener,
	.unbind         = default_unbind_listener,
	.suspend        = default_suspend_listener,
	.resume         = default_resume_listener,
	.accept_conn    = sock_accept_conn,
	.ctrl_init      = sock_conn_ctrl_init,
	.ctrl_close     = sock_conn_ctrl_close,
	.connect        = tcp_connect_server,
	.drain          = sock_drain,
	.check_events   = sock_check_events,
	.ignore_events  = sock_ignore_events,

	/* binding layer */
	.rx_suspend     = tcp_suspend_receiver,
	.rx_resume      = tcp_resume_receiver,

	/* address family */
	.fam            = &proto_fam_inet6,

	/* socket layer */
	.proto_type     = PROTO_TYPE_STREAM,
	.sock_type      = SOCK_STREAM,
	.sock_prot      = IPPROTO_TCP,
	.rx_enable      = sock_enable,
	.rx_disable     = sock_disable,
	.rx_unbind      = sock_unbind,
	.rx_listening   = sock_accepting_conn,
	.default_iocb   = sock_accept_iocb,
	.receivers      = LIST_HEAD_INIT(proto_tcpv6.receivers),
	.nb_receivers   = 0,
};

INITCALL1(STG_REGISTER, protocol_register, &proto_tcpv6);

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
 * This function initiates a TCP connection establishment to the target assigned
 * to connection <conn> using (si->{target,dst}). A source address may be
 * pointed to by conn->src in case of transparent proxying. Normal source
 * bind addresses are still determined locally (due to the possible need of a
 * source port). conn->target may point either to a valid server or to a backend,
 * depending on conn->target. Only OBJ_TYPE_PROXY and OBJ_TYPE_SERVER are
 * supported. The <data> parameter is a boolean indicating whether there are data
 * waiting for being sent or not, in order to adjust data write polling and on
 * some platforms, the ability to avoid an empty initial ACK. The <flags> argument
 * allows the caller to force using a delayed ACK when establishing the connection
 *   - 0 = no delayed ACK unless data are advertised and backend has tcp-smart-connect
 *   - CONNECT_DELACK_SMART_CONNECT = delayed ACK if backend has tcp-smart-connect, regardless of data
 *   - CONNECT_DELACK_ALWAYS = delayed ACK regardless of backend options
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

int tcp_connect_server(struct connection *conn, int flags)
{
	int fd;
	struct server *srv;
	struct proxy *be;
	struct conn_src *src;
	int use_fastopen = 0;
	struct sockaddr_storage *addr;

	conn->flags |= CO_FL_WAIT_L4_CONN; /* connection in progress */

	switch (obj_type(conn->target)) {
	case OBJ_TYPE_PROXY:
		be = __objt_proxy(conn->target);
		srv = NULL;
		break;
	case OBJ_TYPE_SERVER:
		srv = __objt_server(conn->target);
		be = srv->proxy;
		/* Make sure we check that we have data before activating
		 * TFO, or we could trigger a kernel issue whereby after
		 * a successful connect() == 0, any subsequent connect()
		 * will return EINPROGRESS instead of EISCONN.
		 */
		use_fastopen = (srv->flags & SRV_F_FASTOPEN) &&
		               ((flags & (CONNECT_CAN_USE_TFO | CONNECT_HAS_DATA)) ==
				(CONNECT_CAN_USE_TFO | CONNECT_HAS_DATA));
		break;
	default:
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_INTERNAL;
	}

	if (!conn->dst) {
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_INTERNAL;
	}

	fd = conn->handle.fd = sock_create_server_socket(conn);

	if (fd == -1) {
		qfprintf(stderr, "Cannot get a server socket.\n");

		if (errno == ENFILE) {
			conn->err_code = CO_ER_SYS_FDLIM;
			send_log(be, LOG_EMERG,
				 "Proxy %s reached system FD limit (maxsock=%d). Please check system tunables.\n",
				 be->id, global.maxsock);
		}
		else if (errno == EMFILE) {
			conn->err_code = CO_ER_PROC_FDLIM;
			send_log(be, LOG_EMERG,
				 "Proxy %s reached process FD limit (maxsock=%d). Please check 'ulimit-n' and restart.\n",
				 be->id, global.maxsock);
		}
		else if (errno == ENOBUFS || errno == ENOMEM) {
			conn->err_code = CO_ER_SYS_MEMLIM;
			send_log(be, LOG_EMERG,
				 "Proxy %s reached system memory limit (maxsock=%d). Please check system tunables.\n",
				 be->id, global.maxsock);
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

	if (master == 1 && (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)) {
		ha_alert("Cannot set CLOEXEC on client socket.\n");
		close(fd);
		conn->err_code = CO_ER_SOCK_ERR;
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_INTERNAL;
	}

	if (be->options & PR_O_TCP_SRV_KA) {
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));

#ifdef TCP_KEEPCNT
		if (be->srvtcpka_cnt)
			setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &be->srvtcpka_cnt, sizeof(be->srvtcpka_cnt));
#endif

#ifdef TCP_KEEPIDLE
		if (be->srvtcpka_idle)
			setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &be->srvtcpka_idle, sizeof(be->srvtcpka_idle));
#endif

#ifdef TCP_KEEPINTVL
		if (be->srvtcpka_intvl)
			setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &be->srvtcpka_intvl, sizeof(be->srvtcpka_intvl));
#endif
	}

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
			case CO_SRC_TPROXY_ADDR:
				flags = 3;
				break;
			case CO_SRC_TPROXY_CIP:
			case CO_SRC_TPROXY_DYN:
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

				ret = tcp_bind_socket(fd, flags, &sa, conn->src);
				if (ret != 0)
					conn->err_code = CO_ER_CANT_BIND;
			} while (ret != 0); /* binding NOK */
		}
		else {
#ifdef IP_BIND_ADDRESS_NO_PORT
			static THREAD_LOCAL int bind_address_no_port = 1;
			setsockopt(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, (const void *) &bind_address_no_port, sizeof(int));
#endif
			ret = tcp_bind_socket(fd, flags, &src->source_addr, conn->src);
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
	if (flags & (CONNECT_DELACK_ALWAYS) ||
	    ((flags & CONNECT_DELACK_SMART_CONNECT ||
	      (flags & CONNECT_HAS_DATA) || conn->send_proxy_ofs) &&
	     (be->options2 & PR_O2_SMARTCON)))
                setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &zero, sizeof(zero));
#endif

#ifdef TCP_USER_TIMEOUT
	/* there is not much more we can do here when it fails, it's still minor */
	if (srv && srv->tcp_ut)
		setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &srv->tcp_ut, sizeof(srv->tcp_ut));
#endif

	if (use_fastopen) {
#if defined(TCP_FASTOPEN_CONNECT)
                setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &one, sizeof(one));
#endif
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

	conn_ctrl_init(conn);       /* registers the FD */
	HA_ATOMIC_OR(&fdtab[fd].state, FD_LINGER_RISK);  /* close hard if needed */

	if (conn->flags & CO_FL_WAIT_L4_CONN) {
		fd_want_send(fd);
		fd_cant_send(fd);
		fd_cant_recv(fd);
	}

	return SF_ERR_NONE;  /* connection is OK */
}

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
		chunk_appendf(msg, "%sreceiving socket not bound", msg->data ? ", " : "");
		goto tcp_return;
	}

	fd = listener->rx.fd;

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

#if defined(TCP_MAXSEG)
	if (listener->maxseg > 0) {
		if (setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG,
			       &listener->maxseg, sizeof(listener->maxseg)) == -1) {
			chunk_appendf(msg, "%scannot set MSS to %d", msg->data ? ", " : "", listener->maxseg);
			err |= ERR_WARN;
		}
	} else {
		/* we may want to try to restore the default MSS if the socket was inherited */
		int tmpmaxseg = -1;
		int defaultmss;
		socklen_t len = sizeof(tmpmaxseg);

		if (listener->rx.addr.ss_family == AF_INET)
			defaultmss = sock_inet_tcp_maxseg_default;
		else
			defaultmss = sock_inet6_tcp_maxseg_default;

		getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &tmpmaxseg, &len);
		if (defaultmss > 0 &&
		    tmpmaxseg != defaultmss &&
		    setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &defaultmss, sizeof(defaultmss)) == -1) {
			chunk_appendf(msg, "%scannot set MSS to %d", msg->data ? ", " : "", defaultmss);
			err |= ERR_WARN;
		}
	}
#endif
#if defined(TCP_USER_TIMEOUT)
	if (listener->tcp_ut) {
		if (setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT,
			       &listener->tcp_ut, sizeof(listener->tcp_ut)) == -1) {
			chunk_appendf(msg, "%scannot set TCP User Timeout", msg->data ? ", " : "");
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
			chunk_appendf(msg, "%scannot enable DEFER_ACCEPT", msg->data ? ", " : "");
			err |= ERR_WARN;
		}
	} else
		setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &zero,
		    sizeof(zero));
#endif
#if defined(TCP_FASTOPEN)
	if (listener->options & LI_O_TCP_FO) {
		/* TFO needs a queue length, let's use the configured backlog */
		int qlen = listener_backlog(listener);
		if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen)) == -1) {
			chunk_appendf(msg, "%scannot enable TCP_FASTOPEN", msg->data ? ", " : "");
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
				chunk_appendf(msg, "%scannot disable TCP_FASTOPEN", msg->data ? ", " : "");
				err |= ERR_WARN;
			}
		}
	}
#endif

	ready = sock_accepting_conn(&listener->rx) > 0;

	if (!ready && /* only listen if not already done by external process */
	    listen(fd, listener_backlog(listener)) == -1) {
		err |= ERR_RETRYABLE | ERR_ALERT;
		chunk_appendf(msg, "%scannot listen to socket", msg->data ? ", " : "");
		goto tcp_close_return;
	}

#if !defined(TCP_DEFER_ACCEPT) && defined(SO_ACCEPTFILTER)
	/* the socket needs to listen first */
	if (listener->options & LI_O_DEF_ACCEPT) {
		struct accept_filter_arg accept;
		memset(&accept, 0, sizeof(accept));
		strcpy(accept.af_name, "dataready");
		if (setsockopt(fd, SOL_SOCKET, SO_ACCEPTFILTER, &accept, sizeof(accept)) == -1) {
			chunk_appendf(msg, "%scannot enable ACCEPT_FILTER", msg->data ? ", " : "");
			err |= ERR_WARN;
		}
	}
#endif
#if defined(TCP_QUICKACK)
	if (listener->options & LI_O_NOQUICKACK)
		setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &zero, sizeof(zero));
	else
		setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
#endif

	/* the socket is ready */
	listener_set_state(listener, LI_LISTEN);
	goto tcp_return;

 tcp_close_return:
	free_trash_chunk(msg);
	msg = NULL;
	close(fd);
 tcp_return:
	if (msg && errlen && msg->data) {
		char pn[INET6_ADDRSTRLEN];

		addr_to_str(&listener->rx.addr, pn, sizeof(pn));
		snprintf(errmsg, errlen, "%s for [%s:%d]", msg->area, pn, get_host_port(&listener->rx.addr));
	}
	free_trash_chunk(msg);
	msg = NULL;
	return err;
}

/* Enable receipt of incoming connections for listener <l>. The receiver must
 * still be valid.
 */
static void tcp_enable_listener(struct listener *l)
{
	fd_want_recv_safe(l->rx.fd);
}

/* Disable receipt of incoming connections for listener <l>. The receiver must
 * still be valid.
 */
static void tcp_disable_listener(struct listener *l)
{
	fd_stop_recv(l->rx.fd);
}

/* Suspend a receiver. Returns < 0 in case of failure, 0 if the receiver
 * was totally stopped, or > 0 if correctly suspended.
 */
static int tcp_suspend_receiver(struct receiver *rx)
{
	const struct sockaddr sa = { .sa_family = AF_UNSPEC };
	int ret;

	/* we never do that with a shared FD otherwise we'd break it in the
	 * parent process and any possible subsequent worker inheriting it.
	 */
	if (rx->flags & RX_F_INHERITED)
		return -1;

	if (connect(rx->fd, &sa, sizeof(sa)) < 0)
		goto check_already_done;

	fd_stop_recv(rx->fd);
	return 1;

 check_already_done:
	/* in case one of the shutdown() above fails, it might be because we're
	 * dealing with a socket that is shared with other processes doing the
	 * same. Let's check if it's still accepting connections.
	 */
	ret = sock_accepting_conn(rx);
	if (ret <= 0) {
		/* unrecoverable or paused by another process */
		fd_stop_recv(rx->fd);
		return ret == 0;
	}

	/* still listening, that's not good */
	return -1;
}

/* Resume a receiver. Returns < 0 in case of failure, 0 if the receiver
 * was totally stopped, or > 0 if correctly suspended.
 */
static int tcp_resume_receiver(struct receiver *rx)
{
	struct listener *l = LIST_ELEM(rx, struct listener *, rx);

	if (rx->fd < 0)
		return 0;

	if (listen(rx->fd, listener_backlog(l)) == 0) {
		fd_want_recv(l->rx.fd);
		return 1;
	}
	return -1;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
