/*
 * AF_INET/AF_INET6 SOCK_STREAM protocol layer (tcp)
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

#include <common/cfgparse.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/errors.h>
#include <common/mini-clist.h>
#include <common/standard.h>

#include <types/global.h>
#include <types/server.h>

#include <proto/acl.h>
#include <proto/buffers.h>
#include <proto/frontend.h>
#include <proto/log.h>
#include <proto/pattern.h>
#include <proto/port_range.h>
#include <proto/protocols.h>
#include <proto/proto_tcp.h>
#include <proto/proxy.h>
#include <proto/stream_sock.h>

#ifdef CONFIG_HAP_CTTPROXY
#include <import/ip_tproxy.h>
#endif

static int tcp_bind_listeners(struct protocol *proto);

/* Note: must not be declared <const> as its list will be overwritten */
static struct protocol proto_tcpv4 = {
	.name = "tcpv4",
	.sock_domain = AF_INET,
	.sock_type = SOCK_STREAM,
	.sock_prot = IPPROTO_TCP,
	.sock_family = AF_INET,
	.sock_addrlen = sizeof(struct sockaddr_in),
	.l3_addrlen = 32/8,
	.accept = &stream_sock_accept,
	.read = &stream_sock_read,
	.write = &stream_sock_write,
	.bind_all = tcp_bind_listeners,
	.unbind_all = unbind_all_listeners,
	.enable_all = enable_all_listeners,
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
	.accept = &stream_sock_accept,
	.read = &stream_sock_read,
	.write = &stream_sock_write,
	.bind_all = tcp_bind_listeners,
	.unbind_all = unbind_all_listeners,
	.enable_all = enable_all_listeners,
	.listeners = LIST_HEAD_INIT(proto_tcpv6.listeners),
	.nb_listeners = 0,
};


/* Binds ipv4 address <local> to socket <fd>, unless <flags> is set, in which
 * case we try to bind <remote>. <flags> is a 2-bit field consisting of :
 *  - 0 : ignore remote address (may even be a NULL pointer)
 *  - 1 : use provided address
 *  - 2 : use provided port
 *  - 3 : use both
 *
 * The function supports multiple foreign binding methods :
 *   - linux_tproxy: we directly bind to the foreign address
 *   - cttproxy: we bind to a local address then nat.
 * The second one can be used as a fallback for the first one.
 * This function returns 0 when everything's OK, 1 if it could not bind, to the
 * local address, 2 if it could not bind to the foreign address.
 */
int tcpv4_bind_socket(int fd, int flags, struct sockaddr_in *local, struct sockaddr_in *remote)
{
	struct sockaddr_in bind_addr;
	int foreign_ok = 0;
	int ret;

#ifdef CONFIG_HAP_LINUX_TPROXY
	static int ip_transp_working = 1;
	if (flags && ip_transp_working) {
		if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, (char *) &one, sizeof(one)) == 0
		    || setsockopt(fd, SOL_IP, IP_FREEBIND, (char *) &one, sizeof(one)) == 0)
			foreign_ok = 1;
		else
			ip_transp_working = 0;
	}
#endif
	if (flags) {
		memset(&bind_addr, 0, sizeof(bind_addr));
		if (flags & 1)
			bind_addr.sin_addr = remote->sin_addr;
		if (flags & 2)
			bind_addr.sin_port = remote->sin_port;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one));
	if (foreign_ok) {
		ret = bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
		if (ret < 0)
			return 2;
	}
	else {
		ret = bind(fd, (struct sockaddr *)local, sizeof(*local));
		if (ret < 0)
			return 1;
	}

	if (!flags)
		return 0;

#ifdef CONFIG_HAP_CTTPROXY
	if (!foreign_ok) {
		struct in_tproxy itp1, itp2;
		memset(&itp1, 0, sizeof(itp1));

		itp1.op = TPROXY_ASSIGN;
		itp1.v.addr.faddr = bind_addr.sin_addr;
		itp1.v.addr.fport = bind_addr.sin_port;

		/* set connect flag on socket */
		itp2.op = TPROXY_FLAGS;
		itp2.v.flags = ITP_CONNECT | ITP_ONCE;

		if (setsockopt(fd, SOL_IP, IP_TPROXY, &itp1, sizeof(itp1)) != -1 &&
		    setsockopt(fd, SOL_IP, IP_TPROXY, &itp2, sizeof(itp2)) != -1) {
			foreign_ok = 1;
		}
	}
#endif
	if (!foreign_ok)
		/* we could not bind to a foreign address */
		return 2;

	return 0;
}


/*
 * This function initiates a connection to the server assigned to this session
 * (s->srv, s->srv_addr). It will assign a server if none is assigned yet. A
 * source address may be pointed to by <from_addr>. Note that this is only used
 * in case of transparent proxying. Normal source bind addresses are still
 * determined locally (due to the possible need of a source port).
 *
 * It can return one of :
 *  - SN_ERR_NONE if everything's OK
 *  - SN_ERR_SRVTO if there are no more servers
 *  - SN_ERR_SRVCL if the connection was refused by the server
 *  - SN_ERR_PRXCOND if the connection has been limited by the proxy (maxconn)
 *  - SN_ERR_RESOURCE if a system resource is lacking (eg: fd limits, ports, ...)
 *  - SN_ERR_INTERNAL for any other purely internal errors
 * Additionnally, in the case of SN_ERR_RESOURCE, an emergency log will be emitted.
 */
int tcpv4_connect_server(struct stream_interface *si,
			 struct proxy *be, struct server *srv,
			 struct sockaddr *srv_addr, struct sockaddr *from_addr)
{
	int fd;

	if ((fd = si->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		qfprintf(stderr, "Cannot get a server socket.\n");

		if (errno == ENFILE)
			send_log(be, LOG_EMERG,
				 "Proxy %s reached system FD limit at %d. Please check system tunables.\n",
				 be->id, maxfd);
		else if (errno == EMFILE)
			send_log(be, LOG_EMERG,
				 "Proxy %s reached process FD limit at %d. Please check 'ulimit-n' and restart.\n",
				 be->id, maxfd);
		else if (errno == ENOBUFS || errno == ENOMEM)
			send_log(be, LOG_EMERG,
				 "Proxy %s reached system memory limit at %d sockets. Please check system tunables.\n",
				 be->id, maxfd);
		/* this is a resource error */
		return SN_ERR_RESOURCE;
	}

	if (fd >= global.maxsock) {
		/* do not log anything there, it's a normal condition when this option
		 * is used to serialize connections to a server !
		 */
		Alert("socket(): not enough free sockets. Raise -n argument. Giving up.\n");
		close(fd);
		return SN_ERR_PRXCOND; /* it is a configuration limit */
	}

	if ((fcntl(fd, F_SETFL, O_NONBLOCK)==-1) ||
	    (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &one, sizeof(one)) == -1)) {
		qfprintf(stderr,"Cannot set client socket to non blocking mode.\n");
		close(fd);
		return SN_ERR_INTERNAL;
	}

	if (be->options & PR_O_TCP_SRV_KA)
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(one));

	if (be->options & PR_O_TCP_NOLING)
		setsockopt(fd, SOL_SOCKET, SO_LINGER, (struct linger *) &nolinger, sizeof(struct linger));

	/* allow specific binding :
	 * - server-specific at first
	 * - proxy-specific next
	 */
	if (srv != NULL && srv->state & SRV_BIND_SRC) {
		int ret, flags = 0;

		switch (srv->state & SRV_TPROXY_MASK) {
		case SRV_TPROXY_ADDR:
		case SRV_TPROXY_CLI:
			flags = 3;
			break;
		case SRV_TPROXY_CIP:
		case SRV_TPROXY_DYN:
			flags = 1;
			break;
		}

#ifdef SO_BINDTODEVICE
		/* Note: this might fail if not CAP_NET_RAW */
		if (srv->iface_name)
			setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, srv->iface_name, srv->iface_len + 1);
#endif

		if (srv->sport_range) {
			int attempts = 10; /* should be more than enough to find a spare port */
			struct sockaddr_in src;

			ret = 1;
			src = srv->source_addr;

			do {
				/* note: in case of retry, we may have to release a previously
				 * allocated port, hence this loop's construct.
				 */
				port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
				fdinfo[fd].port_range = NULL;

				if (!attempts)
					break;
				attempts--;

				fdinfo[fd].local_port = port_range_alloc_port(srv->sport_range);
				if (!fdinfo[fd].local_port)
					break;

				fdinfo[fd].port_range = srv->sport_range;
				src.sin_port = htons(fdinfo[fd].local_port);

				ret = tcpv4_bind_socket(fd, flags, &src, (struct sockaddr_in *)from_addr);
			} while (ret != 0); /* binding NOK */
		}
		else {
			ret = tcpv4_bind_socket(fd, flags, &srv->source_addr, (struct sockaddr_in *)from_addr);
		}

		if (ret) {
			port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
			fdinfo[fd].port_range = NULL;
			close(fd);

			if (ret == 1) {
				Alert("Cannot bind to source address before connect() for server %s/%s. Aborting.\n",
				      be->id, srv->id);
				send_log(be, LOG_EMERG,
					 "Cannot bind to source address before connect() for server %s/%s.\n",
					 be->id, srv->id);
			} else {
				Alert("Cannot bind to tproxy source address before connect() for server %s/%s. Aborting.\n",
				      be->id, srv->id);
				send_log(be, LOG_EMERG,
					 "Cannot bind to tproxy source address before connect() for server %s/%s.\n",
					 be->id, srv->id);
			}
			return SN_ERR_RESOURCE;
		}
	}
	else if (be->options & PR_O_BIND_SRC) {
		int ret, flags = 0;

		switch (be->options & PR_O_TPXY_MASK) {
		case PR_O_TPXY_ADDR:
		case PR_O_TPXY_CLI:
			flags = 3;
			break;
		case PR_O_TPXY_CIP:
		case PR_O_TPXY_DYN:
			flags = 1;
			break;
		}

#ifdef SO_BINDTODEVICE
		/* Note: this might fail if not CAP_NET_RAW */
		if (be->iface_name)
			setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, be->iface_name, be->iface_len + 1);
#endif
		ret = tcpv4_bind_socket(fd, flags, &be->source_addr, (struct sockaddr_in *)from_addr);
		if (ret) {
			close(fd);
			if (ret == 1) {
				Alert("Cannot bind to source address before connect() for proxy %s. Aborting.\n",
				      be->id);
				send_log(be, LOG_EMERG,
					 "Cannot bind to source address before connect() for proxy %s.\n",
					 be->id);
			} else {
				Alert("Cannot bind to tproxy source address before connect() for proxy %s. Aborting.\n",
				      be->id);
				send_log(be, LOG_EMERG,
					 "Cannot bind to tproxy source address before connect() for proxy %s.\n",
					 be->id);
			}
			return SN_ERR_RESOURCE;
		}
	}

#if defined(TCP_QUICKACK)
	/* disabling tcp quick ack now allows the first request to leave the
	 * machine with the first ACK. We only do this if there are pending
	 * data in the buffer.
	 */
	if ((be->options2 & PR_O2_SMARTCON) && si->ob->send_max)
                setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, (char *) &zero, sizeof(zero));
#endif

	if (global.tune.server_sndbuf)
                setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &global.tune.server_sndbuf, sizeof(global.tune.server_sndbuf));

	if (global.tune.server_rcvbuf)
                setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &global.tune.server_rcvbuf, sizeof(global.tune.server_rcvbuf));

	if ((connect(fd, (struct sockaddr *)srv_addr, sizeof(struct sockaddr_in)) == -1) &&
	    (errno != EINPROGRESS) && (errno != EALREADY) && (errno != EISCONN)) {

		if (errno == EAGAIN || errno == EADDRINUSE) {
			char *msg;
			if (errno == EAGAIN) /* no free ports left, try again later */
				msg = "no free ports";
			else
				msg = "local address already in use";

			qfprintf(stderr,"Cannot connect: %s.\n",msg);
			port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
			fdinfo[fd].port_range = NULL;
			close(fd);
			send_log(be, LOG_EMERG,
				 "Connect() failed for server %s/%s: %s.\n",
				 be->id, srv->id, msg);
			return SN_ERR_RESOURCE;
		} else if (errno == ETIMEDOUT) {
			//qfprintf(stderr,"Connect(): ETIMEDOUT");
			port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
			fdinfo[fd].port_range = NULL;
			close(fd);
			return SN_ERR_SRVTO;
		} else {
			// (errno == ECONNREFUSED || errno == ENETUNREACH || errno == EACCES || errno == EPERM)
			//qfprintf(stderr,"Connect(): %d", errno);
			port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
			fdinfo[fd].port_range = NULL;
			close(fd);
			return SN_ERR_SRVCL;
		}
	}

	fdtab[fd].owner = si;
	fdtab[fd].state = FD_STCONN; /* connection in progress */
	fdtab[fd].flags = FD_FL_TCP | FD_FL_TCP_NODELAY;
	fdtab[fd].cb[DIR_RD].f = &stream_sock_read;
	fdtab[fd].cb[DIR_RD].b = si->ib;
	fdtab[fd].cb[DIR_WR].f = &stream_sock_write;
	fdtab[fd].cb[DIR_WR].b = si->ob;

	fdinfo[fd].peeraddr = (struct sockaddr *)srv_addr;
	fdinfo[fd].peerlen = sizeof(struct sockaddr_in);

	fd_insert(fd);
	EV_FD_SET(fd, DIR_WR);  /* for connect status */

	si->state = SI_ST_CON;
	si->flags |= SI_FL_CAP_SPLTCP; /* TCP supports splicing */
	si->exp = tick_add_ifset(now_ms, be->timeout.connect);

	return SN_ERR_NONE;  /* connection is OK */
}


/* This function tries to bind a TCPv4/v6 listener. It may return a warning or
 * an error message in <err> if the message is at most <errlen> bytes long
 * (including '\0'). The return value is composed from ERR_ABORT, ERR_WARN,
 * ERR_ALERT, ERR_RETRYABLE and ERR_FATAL. ERR_NONE indicates that everything
 * was alright and that no message was returned. ERR_RETRYABLE means that an
 * error occurred but that it may vanish after a retry (eg: port in use), and
 * ERR_FATAL indicates a non-fixable error.ERR_WARN and ERR_ALERT do not alter
 * the meaning of the error, but just indicate that a message is present which
 * should be displayed with the respective level. Last, ERR_ABORT indicates
 * that it's pointless to try to start other listeners. No error message is
 * returned if errlen is NULL.
 */
int tcp_bind_listener(struct listener *listener, char *errmsg, int errlen)
{
	__label__ tcp_return, tcp_close_return;
	int fd, err;
	const char *msg = NULL;

	/* ensure we never return garbage */
	if (errmsg && errlen)
		*errmsg = 0;

	if (listener->state != LI_ASSIGNED)
		return ERR_NONE; /* already bound */

	err = ERR_NONE;

	if ((fd = socket(listener->addr.ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		err |= ERR_RETRYABLE | ERR_ALERT;
		msg = "cannot create listening socket";
		goto tcp_return;
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

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one)) == -1) {
		/* not fatal but should be reported */
		msg = "cannot do so_reuseaddr";
		err |= ERR_ALERT;
	}

	if (listener->options & LI_O_NOLINGER)
		setsockopt(fd, SOL_SOCKET, SO_LINGER, (struct linger *) &nolinger, sizeof(struct linger));

#ifdef SO_REUSEPORT
	/* OpenBSD supports this. As it's present in old libc versions of Linux,
	 * it might return an error that we will silently ignore.
	 */
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (char *) &one, sizeof(one));
#endif
#ifdef CONFIG_HAP_LINUX_TPROXY
	if ((listener->options & LI_O_FOREIGN)
	    && (setsockopt(fd, SOL_IP, IP_TRANSPARENT, (char *) &one, sizeof(one)) == -1)
	    && (setsockopt(fd, SOL_IP, IP_FREEBIND, (char *) &one, sizeof(one)) == -1)) {
		msg = "cannot make listening socket transparent";
		err |= ERR_ALERT;
	}
#endif
#ifdef SO_BINDTODEVICE
	/* Note: this might fail if not CAP_NET_RAW */
	if (listener->interface) {
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
			       listener->interface, strlen(listener->interface) + 1) == -1) {
			msg = "cannot bind listener to device";
			err |= ERR_WARN;
		}
	}
#endif
#if defined(TCP_MAXSEG)
	if (listener->maxseg) {
		if (setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG,
			       &listener->maxseg, sizeof(listener->maxseg)) == -1) {
			msg = "cannot set MSS";
			err |= ERR_WARN;
		}
	}
#endif
#if defined(TCP_DEFER_ACCEPT)
	if (listener->options & LI_O_DEF_ACCEPT) {
		/* defer accept by up to one second */
		int accept_delay = 1;
		if (setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &accept_delay, sizeof(accept_delay)) == -1) {
			msg = "cannot enable DEFER_ACCEPT";
			err |= ERR_WARN;
		}
	}
#endif
	if (bind(fd, (struct sockaddr *)&listener->addr, listener->proto->sock_addrlen) == -1) {
		err |= ERR_RETRYABLE | ERR_ALERT;
		msg = "cannot bind socket";
		goto tcp_close_return;
	}

	if (listen(fd, listener->backlog ? listener->backlog : listener->maxconn) == -1) {
		err |= ERR_RETRYABLE | ERR_ALERT;
		msg = "cannot listen to socket";
		goto tcp_close_return;
	}

#if defined(TCP_QUICKACK)
	if (listener->options & LI_O_NOQUICKACK)
		setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, (char *) &zero, sizeof(zero));
#endif

	/* the socket is ready */
	listener->fd = fd;
	listener->state = LI_LISTEN;

	fdtab[fd].owner = listener; /* reference the listener instead of a task */
	fdtab[fd].state = FD_STLISTEN;
	fdtab[fd].flags = FD_FL_TCP | ((listener->options & LI_O_NOLINGER) ? FD_FL_TCP_NOLING : 0);
	fdtab[fd].cb[DIR_RD].f = listener->proto->accept;
	fdtab[fd].cb[DIR_WR].f = NULL; /* never called */
	fdtab[fd].cb[DIR_RD].b = fdtab[fd].cb[DIR_WR].b = NULL;

	fdinfo[fd].peeraddr = NULL;
	fdinfo[fd].peerlen = 0;
	fd_insert(fd);

 tcp_return:
	if (msg && errlen)
		strlcpy2(errmsg, msg, errlen);
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
static int tcp_bind_listeners(struct protocol *proto)
{
	struct listener *listener;
	int err = ERR_NONE;

	list_for_each_entry(listener, &proto->listeners, proto_list) {
		err |= tcp_bind_listener(listener, NULL, 0);
		if ((err & ERR_CODE) == ERR_ABORT)
			break;
	}

	return err;
}

/* Add listener to the list of tcpv4 listeners. The listener's state
 * is automatically updated from LI_INIT to LI_ASSIGNED. The number of
 * listeners is updated. This is the function to use to add a new listener.
 */
void tcpv4_add_listener(struct listener *listener)
{
	if (listener->state != LI_INIT)
		return;
	listener->state = LI_ASSIGNED;
	listener->proto = &proto_tcpv4;
	LIST_ADDQ(&proto_tcpv4.listeners, &listener->proto_list);
	proto_tcpv4.nb_listeners++;
}

/* Add listener to the list of tcpv4 listeners. The listener's state
 * is automatically updated from LI_INIT to LI_ASSIGNED. The number of
 * listeners is updated. This is the function to use to add a new listener.
 */
void tcpv6_add_listener(struct listener *listener)
{
	if (listener->state != LI_INIT)
		return;
	listener->state = LI_ASSIGNED;
	listener->proto = &proto_tcpv6;
	LIST_ADDQ(&proto_tcpv6.listeners, &listener->proto_list);
	proto_tcpv6.nb_listeners++;
}

/* This function performs the TCP request analysis on the current request. It
 * returns 1 if the processing can continue on next analysers, or zero if it
 * needs more data, encounters an error, or wants to immediately abort the
 * request. It relies on buffers flags, and updates s->req->analysers. Its
 * behaviour is rather simple:
 *  - the analyser should check for errors and timeouts, and react as expected.
 *    It does not have to close anything upon error, the caller will. Note that
 *    the caller also knows how to report errors and timeouts.
 *  - if the analyser does not have enough data, it must return 0 without calling
 *    other ones. It should also probably do a buffer_write_dis() to ensure
 *    that unprocessed data will not be forwarded. But that probably depends on
 *    the protocol.
 *  - if an analyser has enough data, it just has to pass on to the next
 *    analyser without using buffer_write_dis() (enabled by default).
 *  - if an analyser thinks it has no added value anymore staying here, it must
 *    reset its bit from the analysers flags in order not to be called anymore.
 *
 * In the future, analysers should be able to indicate that they want to be
 * called after XXX bytes have been received (or transfered), and the min of
 * all's wishes will be used to ring back (unless a special condition occurs).
 */
int tcp_inspect_request(struct session *s, struct buffer *req, int an_bit)
{
	struct tcp_rule *rule;
	int partial;

	DPRINTF(stderr,"[%u] %s: session=%p b=%p, exp(r,w)=%u,%u bf=%08x bl=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->l,
		req->analysers);

	/* We don't know whether we have enough data, so must proceed
	 * this way :
	 * - iterate through all rules in their declaration order
	 * - if one rule returns MISS, it means the inspect delay is
	 *   not over yet, then return immediately, otherwise consider
	 *   it as a non-match.
	 * - if one rule returns OK, then return OK
	 * - if one rule returns KO, then return KO
	 */

	if (req->flags & BF_SHUTR || !s->fe->tcp_req.inspect_delay || tick_is_expired(req->analyse_exp, now_ms))
		partial = 0;
	else
		partial = ACL_PARTIAL;

	list_for_each_entry(rule, &s->fe->tcp_req.inspect_rules, list) {
		int ret = ACL_PAT_PASS;

		if (rule->cond) {
			ret = acl_exec_cond(rule->cond, s->fe, s, &s->txn, ACL_DIR_REQ | partial);
			if (ret == ACL_PAT_MISS) {
				buffer_dont_connect(req);
				/* just set the request timeout once at the beginning of the request */
				if (!tick_isset(req->analyse_exp) && s->fe->tcp_req.inspect_delay)
					req->analyse_exp = tick_add_ifset(now_ms, s->fe->tcp_req.inspect_delay);
				return 0;
			}

			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			/* we have a matching rule. */
			if (rule->action == TCP_ACT_REJECT) {
				buffer_abort(req);
				buffer_abort(s->rep);
				req->analysers = 0;

				s->fe->counters.denied_req++;
				if (s->listener->counters)
					s->listener->counters->denied_req++;

				if (!(s->flags & SN_ERR_MASK))
					s->flags |= SN_ERR_PRXCOND;
				if (!(s->flags & SN_FINST_MASK))
					s->flags |= SN_FINST_R;
				return 0;
			}
				/* otherwise accept */
			break;
		}
	}

	/* if we get there, it means we have no rule which matches, or
	 * we have an explicit accept, so we apply the default accept.
	 */
	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;
	return 1;
}

/* This function should be called to parse a line starting with the "tcp-request"
 * keyword.
 */
static int tcp_parse_tcp_req(char **args, int section_type, struct proxy *curpx,
			     struct proxy *defpx, char *err, int errlen)
{
	const char *ptr = NULL;
	unsigned int val;
	int retlen;
	int action;
	int warn = 0;
	int pol = ACL_COND_NONE;
	struct acl_cond *cond;
	struct tcp_rule *rule;

	if (!*args[1]) {
		snprintf(err, errlen, "missing argument for '%s' in %s '%s'",
			 args[0], proxy_type_str(proxy), curpx->id);
		return -1;
	}

	if (!strcmp(args[1], "inspect-delay")) {
		if (curpx == defpx) {
			snprintf(err, errlen, "%s %s is not allowed in 'defaults' sections",
				 args[0], args[1]);
			return -1;
		}

		if (!(curpx->cap & PR_CAP_FE)) {
			snprintf(err, errlen, "%s %s will be ignored because %s '%s' has no %s capability",
				 args[0], args[1], proxy_type_str(proxy), curpx->id,
				 "frontend");
			return 1;
		}

		if (!*args[2] || (ptr = parse_time_err(args[2], &val, TIME_UNIT_MS))) {
			retlen = snprintf(err, errlen,
					  "'%s %s' expects a positive delay in milliseconds, in %s '%s'",
					  args[0], args[1], proxy_type_str(proxy), curpx->id);
			if (ptr && retlen < errlen)
				retlen += snprintf(err+retlen, errlen - retlen,
						   " (unexpected character '%c')", *ptr);
			return -1;
		}

		if (curpx->tcp_req.inspect_delay) {
			snprintf(err, errlen, "ignoring %s %s (was already defined) in %s '%s'",
				 args[0], args[1], proxy_type_str(proxy), curpx->id);
			return 1;
		}
		curpx->tcp_req.inspect_delay = val;
		return 0;
	}

	if (!strcmp(args[1], "content")) {
		if (curpx == defpx) {
			snprintf(err, errlen, "%s %s is not allowed in 'defaults' sections",
				 args[0], args[1]);
			return -1;
		}

		if (!strcmp(args[2], "accept"))
			action = TCP_ACT_ACCEPT;
		else if (!strcmp(args[2], "reject"))
			action = TCP_ACT_REJECT;
		else {
			retlen = snprintf(err, errlen,
					  "'%s %s' expects 'accept' or 'reject', in %s '%s' (was '%s')",
					  args[0], args[1], proxy_type_str(curpx), curpx->id, args[2]);
			return -1;
		}

		pol = ACL_COND_NONE;
		cond = NULL;

		if (strcmp(args[3], "if") == 0 || strcmp(args[3], "unless") == 0) {
			if ((cond = build_acl_cond(NULL, 0, curpx, (const char **)args+3)) == NULL) {
				retlen = snprintf(err, errlen,
						  "error detected in %s '%s' while parsing '%s' condition",
						  proxy_type_str(curpx), curpx->id, args[3]);
				return -1;
			}
		}
		else if (*args[3]) {
			retlen = snprintf(err, errlen,
					  "'%s %s %s' only accepts 'if' or 'unless', in %s '%s' (was '%s')",
					  args[0], args[1], args[2], proxy_type_str(curpx), curpx->id, args[3]);
			return -1;
		}

		if (cond && (cond->requires & ACL_USE_RTR_ANY)) {
			struct acl *acl;
			const char *name;

			acl = cond_find_require(cond, ACL_USE_RTR_ANY);
			name = acl ? acl->name : "(unknown)";

			retlen = snprintf(err, errlen,
					  "acl '%s' involves some response-only criteria which will be ignored.",
					  name);
			warn++;
		}
		rule = (struct tcp_rule *)calloc(1, sizeof(*rule));
		rule->cond = cond;
		rule->action = action;
		LIST_INIT(&rule->list);
		LIST_ADDQ(&curpx->tcp_req.inspect_rules, &rule->list);
		return warn;
	}

	/* OK so we're in front of plain L4 rules */
	if (!strcmp(args[1], "accept"))
		action = TCP_ACT_ACCEPT;
	else if (!strcmp(args[1], "reject"))
		action = TCP_ACT_REJECT;
	else {
		retlen = snprintf(err, errlen,
				  "'%s' expects 'inspect-delay', 'content', 'accept' or 'reject', in %s '%s' (was '%s')",
				  args[0], proxy_type_str(curpx), curpx->id, args[1]);
		return -1;
	}

	if (curpx == defpx) {
		snprintf(err, errlen, "%s %s is not allowed in 'defaults' sections",
			 args[0], args[1]);
		return -1;
	}

	pol = ACL_COND_NONE;
	cond = NULL;

	if (strcmp(args[2], "if") == 0 || strcmp(args[2], "unless") == 0) {
		if ((cond = build_acl_cond(NULL, 0, curpx, (const char **)args+2)) == NULL) {
			retlen = snprintf(err, errlen,
					  "error detected in %s '%s' while parsing '%s' condition",
					  proxy_type_str(curpx), curpx->id, args[2]);
			return -1;
		}
	}
	else if (*args[2]) {
		retlen = snprintf(err, errlen,
				  "'%s %s' only accepts 'if' or 'unless', in %s '%s' (was '%s')",
				  args[0], args[1], proxy_type_str(curpx), curpx->id, args[2]);
		return -1;
	}

	if (cond && (cond->requires & (ACL_USE_RTR_ANY|ACL_USE_L6_ANY|ACL_USE_L7_ANY))) {
		struct acl *acl;
		const char *name;

		acl = cond_find_require(cond, ACL_USE_RTR_ANY|ACL_USE_L6_ANY|ACL_USE_L7_ANY);
		name = acl ? acl->name : "(unknown)";

		if (acl->requires & (ACL_USE_L6_ANY|ACL_USE_L7_ANY)) {
			retlen = snprintf(err, errlen,
					  "'%s %s' may not reference acl '%s' which makes use of payload in %s '%s'. Please use '%s content' for this.",
					  args[0], args[1], name, proxy_type_str(curpx), curpx->id, args[0]);
			return -1;
		}
		if (acl->requires & ACL_USE_RTR_ANY)
			retlen = snprintf(err, errlen,
					  "acl '%s' involves some response-only criteria which will be ignored.",
					  name);

		warn++;
	}

	rule = (struct tcp_rule *)calloc(1, sizeof(*rule));
	rule->cond = cond;
	rule->action = action;
	LIST_INIT(&rule->list);
	LIST_ADDQ(&curpx->tcp_req.l4_rules, &rule->list);
	return warn;
}


/************************************************************************/
/*           All supported ACL keywords must be declared here.          */
/************************************************************************/

/* set test->ptr to point to the source IPv4/IPv6 address and test->i to the family */
static int
acl_fetch_src(struct proxy *px, struct session *l4, void *l7, int dir,
              struct acl_expr *expr, struct acl_test *test)
{
	test->i = l4->cli_addr.ss_family;
	if (test->i == AF_INET)
		test->ptr = (void *)&((struct sockaddr_in *)&l4->cli_addr)->sin_addr;
	else
		test->ptr = (void *)&((struct sockaddr_in6 *)(&l4->cli_addr))->sin6_addr;
	test->flags = ACL_TEST_F_READ_ONLY;
	return 1;
}

/* extract the connection's source address */
static int
pattern_fetch_src(struct proxy *px, struct session *l4, void *l7, int dir,
                  const char *arg, int arg_len, union pattern_data *data)
{
	data->ip.s_addr = ((struct sockaddr_in *)&l4->cli_addr)->sin_addr.s_addr;
	return 1;
}


/* set test->i to the connection's source port */
static int
acl_fetch_sport(struct proxy *px, struct session *l4, void *l7, int dir,
                struct acl_expr *expr, struct acl_test *test)
{
	if (l4->cli_addr.ss_family == AF_INET)
		test->i = ntohs(((struct sockaddr_in *)&l4->cli_addr)->sin_port);
	else
		test->i = ntohs(((struct sockaddr_in6 *)(&l4->cli_addr))->sin6_port);
	test->flags = 0;
	return 1;
}


/* set test->ptr to point to the frontend's IPv4/IPv6 address and test->i to the family */
static int
acl_fetch_dst(struct proxy *px, struct session *l4, void *l7, int dir,
              struct acl_expr *expr, struct acl_test *test)
{
	if (!(l4->flags & SN_FRT_ADDR_SET))
		get_frt_addr(l4);

	test->i = l4->frt_addr.ss_family;
	if (test->i == AF_INET)
		test->ptr = (void *)&((struct sockaddr_in *)&l4->frt_addr)->sin_addr;
	else
		test->ptr = (void *)&((struct sockaddr_in6 *)(&l4->frt_addr))->sin6_addr;
	test->flags = ACL_TEST_F_READ_ONLY;
	return 1;
}


/* extract the connection's destination address */
static int
pattern_fetch_dst(struct proxy *px, struct session *l4, void *l7, int dir,
                  const char *arg, int arg_len, union pattern_data *data)
{
	data->ip.s_addr = ((struct sockaddr_in *)&l4->frt_addr)->sin_addr.s_addr;
	return 1;
}

/* set test->i to the frontend connexion's destination port */
static int
acl_fetch_dport(struct proxy *px, struct session *l4, void *l7, int dir,
                struct acl_expr *expr, struct acl_test *test)
{
	if (!(l4->flags & SN_FRT_ADDR_SET))
		get_frt_addr(l4);

	if (l4->frt_addr.ss_family == AF_INET)
		test->i = ntohs(((struct sockaddr_in *)&l4->frt_addr)->sin_port);
	else
		test->i = ntohs(((struct sockaddr_in6 *)(&l4->frt_addr))->sin6_port);
	test->flags = 0;
	return 1;
}

static int
pattern_fetch_dport(struct proxy *px, struct session *l4, void *l7, int dir,
                    const char *arg, int arg_len, union pattern_data *data)

{
	data->integer = ntohs(((struct sockaddr_in *)&l4->frt_addr)->sin_port);
	return 1;
}


static struct cfg_kw_list cfg_kws = {{ },{
	{ CFG_LISTEN, "tcp-request", tcp_parse_tcp_req },
	{ 0, NULL, NULL },
}};

/* Note: must not be declared <const> as its list will be overwritten */
static struct acl_kw_list acl_kws = {{ },{
	{ "src_port",   acl_parse_int,   acl_fetch_sport,    acl_match_int, ACL_USE_TCP_PERMANENT  },
	{ "src",        acl_parse_ip,    acl_fetch_src,      acl_match_ip,  ACL_USE_TCP4_PERMANENT|ACL_MAY_LOOKUP },
	{ "dst",        acl_parse_ip,    acl_fetch_dst,      acl_match_ip,  ACL_USE_TCP4_PERMANENT|ACL_MAY_LOOKUP },
	{ "dst_port",   acl_parse_int,   acl_fetch_dport,    acl_match_int, ACL_USE_TCP_PERMANENT  },
	{ NULL, NULL, NULL, NULL },
}};

/* Note: must not be declared <const> as its list will be overwritten */
static struct pattern_fetch_kw_list pattern_fetch_keywords = {{ },{
	{ "src",       pattern_fetch_src,   PATTERN_TYPE_IP,      PATTERN_FETCH_REQ },
	{ "dst",       pattern_fetch_dst,   PATTERN_TYPE_IP,      PATTERN_FETCH_REQ },
	{ "dst_port",  pattern_fetch_dport, PATTERN_TYPE_INTEGER, PATTERN_FETCH_REQ },
	{ NULL, NULL, 0, 0 },
}};

__attribute__((constructor))
static void __tcp_protocol_init(void)
{
	protocol_register(&proto_tcpv4);
	protocol_register(&proto_tcpv6);
	pattern_register_fetches(&pattern_fetch_keywords);
	cfg_register_keywords(&cfg_kws);
	acl_register_keywords(&acl_kws);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
