/*
 * AF_CUST_UDP/AF_CUST_UDP6 UDP protocol layer
 *
 * Copyright 2019 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
 *
 * Partial merge by Emeric Brun <ebrun@haproxy.com>
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

#include <netinet/udp.h>
#include <netinet/in.h>

#include <haproxy/fd.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/namespace.h>
#include <haproxy/port_range.h>
#include <haproxy/protocol.h>
#include <haproxy/proto_udp.h>
#include <haproxy/proxy.h>
#include <haproxy/server.h>
#include <haproxy/task.h>

static int udp_bind_listeners(struct protocol *proto, char *errmsg, int errlen);
static int udp_bind_listener(struct listener *listener, char *errmsg, int errlen);
static void udp4_add_listener(struct listener *listener, int port);
static void udp6_add_listener(struct listener *listener, int port);

/* Note: must not be declared <const> as its list will be overwritten */
static struct protocol proto_udp4 = {
	.name = "udp4",
	.sock_domain = AF_CUST_UDP4,
	.sock_type = SOCK_DGRAM,
	.sock_prot = IPPROTO_UDP,
	.sock_family = AF_INET,
	.sock_addrlen = sizeof(struct sockaddr_in),
	.l3_addrlen = 32/8,
	.accept = NULL,
	.connect = NULL,
	.bind = udp_bind_listener,
	.bind_all = udp_bind_listeners,
	.unbind_all = unbind_all_listeners,
	.enable_all = enable_all_listeners,
	.get_src = udp_get_src,
	.get_dst = udp_get_dst,
	.pause = udp_pause_listener,
	.add = udp4_add_listener,
	.listeners = LIST_HEAD_INIT(proto_udp4.listeners),
	.nb_listeners = 0,
};

INITCALL1(STG_REGISTER, protocol_register, &proto_udp4);

/* Note: must not be declared <const> as its list will be overwritten */
static struct protocol proto_udp6 = {
	.name = "udp6",
	.sock_domain = AF_CUST_UDP6,
	.sock_type = SOCK_DGRAM,
	.sock_prot = IPPROTO_UDP,
	.sock_family = AF_INET6,
	.sock_addrlen = sizeof(struct sockaddr_in6),
	.l3_addrlen = 128/8,
	.accept = NULL,
	.connect = NULL,
	.bind = udp_bind_listener,
	.bind_all = udp_bind_listeners,
	.unbind_all = unbind_all_listeners,
	.enable_all = enable_all_listeners,
	.get_src = udp_get_src,
	.get_dst = udp_get_dst,
	.pause = udp_pause_listener,
	.add = udp6_add_listener,
	.listeners = LIST_HEAD_INIT(proto_udp6.listeners),
	.nb_listeners = 0,
};

INITCALL1(STG_REGISTER, protocol_register, &proto_udp6);

/*
 * Retrieves the source address for the socket <fd>, with <dir> indicating
 * if we're a listener (=0) or an initiator (!=0). It returns 0 in case of
 * success, -1 in case of error. The socket's source address is stored in
 * <sa> for <salen> bytes.
 */
int udp_get_src(int fd, struct sockaddr *sa, socklen_t salen, int dir)
{
	int ret;

	if (dir)
		ret = getsockname(fd, sa, &salen);
	else
		ret = getpeername(fd, sa, &salen);

	if (!ret) {
		if (sa->sa_family == AF_INET)
			sa->sa_family = AF_CUST_UDP4;
		else if (sa->sa_family == AF_INET6)
			sa->sa_family = AF_CUST_UDP6;
	}

	return ret;
}


/*
 * Retrieves the original destination address for the socket <fd>, with <dir>
 * indicating if we're a listener (=0) or an initiator (!=0). In the case of a
 * listener, if the original destination address was translated, the original
 * address is retrieved. It returns 0 in case of success, -1 in case of error.
 * The socket's source address is stored in <sa> for <salen> bytes.
 */
int udp_get_dst(int fd, struct sockaddr *sa, socklen_t salen, int dir)
{
	int ret;

	if (dir)
		ret = getpeername(fd, sa, &salen);
	else {
		ret = getsockname(fd, sa, &salen);

		if (ret < 0)
			return ret;

#if defined(USE_TPROXY) && defined(SO_ORIGINAL_DST)
		/* For TPROXY and Netfilter's NAT, we can retrieve the original
		 * IPv4 address before DNAT/REDIRECT. We must not do that with
		 * other families because v6-mapped IPv4 addresses are still
		 * reported as v4.
		 */
		if (((struct sockaddr_storage *)sa)->ss_family == AF_INET
		    && getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, sa, &salen) == 0) {
			sa->sa_family = AF_CUST_UDP4;
			return 0;
		}
#endif
	}

	if (!ret) {
		if (sa->sa_family == AF_INET)
			sa->sa_family = AF_CUST_UDP4;
		else if (sa->sa_family == AF_INET6)
			sa->sa_family = AF_CUST_UDP6;
	}

	return ret;
}

/* This function tries to bind a UDPv4/v6 listener. It may return a warning or
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
int udp_bind_listener(struct listener *listener, char *errmsg, int errlen)
{
	__label__ udp_return, udp_close_return;
	int fd, err;
	const char *msg = NULL;
	/* copy listener addr because sometimes we need to switch family */
	struct sockaddr_storage addr_inet = listener->addr;

	/* force to classic sock family */
	addr_inet.ss_family = listener->proto->sock_family;

	/* ensure we never return garbage */
	if (errlen)
		*errmsg = 0;

	if (listener->state != LI_ASSIGNED)
		return ERR_NONE; /* already bound */

	err = ERR_NONE;

	/* TODO: Implement reuse fd. Take care that to identify fd to reuse
	 * listeners uses a special AF_CUST_ family and we MUST consider
	 * IPPROTO (sockaddr is not enough)
	 */

	fd = my_socketat(listener->netns, listener->proto->sock_family, listener->proto->sock_type, listener->proto->sock_prot);
	if (fd == -1) {
		err |= ERR_RETRYABLE | ERR_ALERT;
		msg = "cannot create listening socket";
		goto udp_return;
	}

	if (fd >= global.maxsock) {
		err |= ERR_FATAL | ERR_ABORT | ERR_ALERT;
		msg = "not enough free sockets (raise '-n' parameter)";
		goto udp_close_return;
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		err |= ERR_FATAL | ERR_ALERT;
		msg = "cannot make socket non-blocking";
		goto udp_close_return;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1) {
		/* not fatal but should be reported */
		msg = "cannot do so_reuseaddr";
		err |= ERR_ALERT;
	}

#ifdef SO_REUSEPORT
	/* OpenBSD and Linux 3.9 support this. As it's present in old libc versions of
	 * Linux, it might return an error that we will silently ignore.
	 */
	if (global.tune.options & GTUNE_USE_REUSEPORT)
		setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif

	if (listener->options & LI_O_FOREIGN) {
		switch (addr_inet.ss_family) {
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
	if (listener->interface) {
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
			       listener->interface, strlen(listener->interface) + 1) == -1) {
			msg = "cannot bind listener to device";
			err |= ERR_WARN;
		}
	}
#endif
#if defined(IPV6_V6ONLY)
	if (listener->options & LI_O_V6ONLY)
                setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
	else if (listener->options & LI_O_V4V6)
                setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
#endif

	if (bind(fd, (struct sockaddr *)&addr_inet, listener->proto->sock_addrlen) < 0) {
		err |= ERR_RETRYABLE | ERR_ALERT;
		msg = "cannot bind socket";
		goto udp_close_return;
	}

	/* the socket is ready */
	listener->fd = fd;
	listener->state = LI_LISTEN;

	if (listener->bind_conf->frontend->mode == PR_MODE_SYSLOG)
		fd_insert(fd, listener, syslog_fd_handler,
		          thread_mask(listener->bind_conf->bind_thread) & all_threads_mask);
	else {
		err |= ERR_FATAL | ERR_ALERT;
		msg = "UDP is not yet supported on this proxy mode";
		goto udp_close_return;
	}

 udp_return:
	if (msg && errlen) {
		char pn[INET6_ADDRSTRLEN];

		addr_to_str(&addr_inet, pn, sizeof(pn));
		snprintf(errmsg, errlen, "%s [%s:%d]", msg, pn, get_host_port(&addr_inet));
	}
	return err;

 udp_close_return:
	close(fd);
	goto udp_return;
}

/* This function creates all UDP sockets bound to the protocol entry <proto>.
 * It is intended to be used as the protocol's bind_all() function.
 * The sockets will be registered but not added to any fd_set, in order not to
 * loose them across the fork(). A call to enable_all_listeners() is needed
 * to complete initialization. The return value is composed from ERR_*.
 */
static int udp_bind_listeners(struct protocol *proto, char *errmsg, int errlen)
{
	struct listener *listener;
	int err = ERR_NONE;

	list_for_each_entry(listener, &proto->listeners, proto_list) {
		err |= udp_bind_listener(listener, errmsg, errlen);
		if (err & ERR_ABORT)
			break;
	}

	return err;
}

/* Add <listener> to the list of udp4 listeners, on port <port>. The
 * listener's state is automatically updated from LI_INIT to LI_ASSIGNED.
 * The number of listeners for the protocol is updated.
 */
static void udp4_add_listener(struct listener *listener, int port)
{
	if (listener->state != LI_INIT)
		return;
	listener->state = LI_ASSIGNED;
	listener->proto = &proto_udp4;
	((struct sockaddr_in *)(&listener->addr))->sin_port = htons(port);
	LIST_ADDQ(&proto_udp4.listeners, &listener->proto_list);
	proto_udp4.nb_listeners++;
}

/* Add <listener> to the list of udp6 listeners, on port <port>. The
 * listener's state is automatically updated from LI_INIT to LI_ASSIGNED.
 * The number of listeners for the protocol is updated.
 */
static void udp6_add_listener(struct listener *listener, int port)
{
	if (listener->state != LI_INIT)
		return;
	listener->state = LI_ASSIGNED;
	listener->proto = &proto_udp6;
	((struct sockaddr_in *)(&listener->addr))->sin_port = htons(port);
	LIST_ADDQ(&proto_udp6.listeners, &listener->proto_list);
	proto_udp6.nb_listeners++;
}

/* Pause a listener. Returns < 0 in case of failure, 0 if the listener
 * was totally stopped, or > 0 if correctly paused.
 */
int udp_pause_listener(struct listener *l)
{
	/* we don't support pausing on UDP */
	return -1;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
