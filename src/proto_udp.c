/*
 * UDP protocol layer on top of AF_INET/AF_INET6
 *
 * Copyright 2019 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
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
#include <haproxy/sock.h>
#include <haproxy/sock_inet.h>
#include <haproxy/task.h>
#include <haproxy/tools.h>

static int udp_bind_listener(struct listener *listener, char *errmsg, int errlen);
static void udp_enable_listener(struct listener *listener);
static void udp_disable_listener(struct listener *listener);

/* Note: must not be declared <const> as its list will be overwritten */
struct protocol proto_udp4 = {
	.name           = "udp4",

	/* connection layer */
	.xprt_type      = PROTO_TYPE_DGRAM,
	.listen         = udp_bind_listener,
	.enable         = udp_enable_listener,
	.disable        = udp_disable_listener,
	.add            = default_add_listener,
	.unbind         = default_unbind_listener,
	.suspend        = default_suspend_listener,
	.resume         = default_resume_listener,

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
#ifdef SO_REUSEPORT
	.flags          = PROTO_F_REUSEPORT_SUPPORTED,
#endif
};

INITCALL1(STG_REGISTER, protocol_register, &proto_udp4);

/* Note: must not be declared <const> as its list will be overwritten */
struct protocol proto_udp6 = {
	.name           = "udp6",

	/* connection layer */
	.xprt_type      = PROTO_TYPE_DGRAM,
	.listen         = udp_bind_listener,
	.enable         = udp_enable_listener,
	.disable        = udp_disable_listener,
	.add            = default_add_listener,
	.unbind         = default_unbind_listener,
	.suspend        = default_suspend_listener,
	.resume         = default_resume_listener,

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
#ifdef SO_REUSEPORT
	.flags          = PROTO_F_REUSEPORT_SUPPORTED,
#endif
};

INITCALL1(STG_REGISTER, protocol_register, &proto_udp6);

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
	int err = ERR_NONE;
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

	/* we may want to adjust the output buffer (tune.sndbuf.backend) */
	if (global.tune.frontend_rcvbuf)
		setsockopt(listener->rx.fd, SOL_SOCKET, SO_RCVBUF, &global.tune.frontend_rcvbuf, sizeof(global.tune.frontend_rcvbuf));

	if (global.tune.frontend_sndbuf)
		setsockopt(listener->rx.fd, SOL_SOCKET, SO_SNDBUF, &global.tune.frontend_sndbuf, sizeof(global.tune.frontend_sndbuf));

	if (listener->rx.flags & RX_F_PASS_PKTINFO) {
		/* set IP_PKTINFO to retrieve destination address on recv */
		switch (listener->rx.addr.ss_family) {
		case AF_INET:
#if defined(IP_PKTINFO)
			setsockopt(listener->rx.fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
#elif defined(IP_RECVDSTADDR)
			setsockopt(listener->rx.fd, IPPROTO_IP, IP_RECVDSTADDR, &one, sizeof(one));
#endif /* IP_PKTINFO || IP_RECVDSTADDR */
			break;
		case AF_INET6:
#ifdef IPV6_RECVPKTINFO
			setsockopt(listener->rx.fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
#endif
			break;
		default:
			break;
		}
	}

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
 * still be valid.
 */
static void udp_enable_listener(struct listener *l)
{
	fd_want_recv_safe(l->rx.fd);
}

/* Disable receipt of incoming connections for listener <l>. The receiver must
 * still be valid.
 */
static void udp_disable_listener(struct listener *l)
{
	fd_stop_recv(l->rx.fd);
}

/* Suspend a receiver. Returns < 0 in case of failure, 0 if the receiver
 * was totally stopped, or > 0 if correctly suspended.
 * The principle is a bit ugly but works well, at least on Linux: in order to
 * suspend the receiver, we want it to stop receiving traffic, which means that
 * the socket must be unhashed from the kernel's socket table. The simple way
 * to do this is to connect to any address that is reachable and will not be
 * used by regular traffic, and a great one is reconnecting to self. Note that
 * inherited FDs are neither suspended nor resumed, we only enable/disable
 * polling on them.
 */
int udp_suspend_receiver(struct receiver *rx)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);

	if (rx->fd < 0)
		return 0;

	/* we never do that with a shared FD otherwise we'd break it in the
	 * parent process and any possible subsequent worker inheriting it.
	 */
	if (rx->flags & RX_F_INHERITED)
		goto done;

	if (getsockname(rx->fd, (struct sockaddr *)&ss, &len) < 0)
		return -1;

	if (connect(rx->fd, (struct sockaddr *)&ss, len) < 0)
		return -1;
 done:
	/* not necessary but may make debugging clearer */
	fd_stop_recv(rx->fd);
	return 1;
}

/* Resume a receiver. Returns < 0 in case of failure, 0 if the receiver
 * was totally stopped, or > 0 if correctly suspended.
 * The principle is to reverse the change above, we'll break the connection by
 * connecting to AF_UNSPEC. The association breaks and the socket starts to
 * receive from everywhere again. Note that inherited FDs are neither suspended
 * nor resumed, we only enable/disable polling on them.
 */
int udp_resume_receiver(struct receiver *rx)
{
	const struct sockaddr sa = { .sa_family = AF_UNSPEC };

	if (rx->fd < 0)
		return 0;

	if (!(rx->flags & RX_F_INHERITED) && connect(rx->fd, &sa, sizeof(sa)) < 0)
		return -1;

	fd_want_recv(rx->fd);
	return 1;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
