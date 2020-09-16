/*
 * UDP protocol layer on top of AF_INET/AF_INET6
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
#include <haproxy/sock.h>
#include <haproxy/sock_inet.h>
#include <haproxy/task.h>

static int udp_bind_listener(struct listener *listener, char *errmsg, int errlen);
static void udp4_add_listener(struct listener *listener, int port);
static void udp6_add_listener(struct listener *listener, int port);

/* Note: must not be declared <const> as its list will be overwritten */
static struct protocol proto_udp4 = {
	.name = "udp4",
	.fam = &proto_fam_inet4,
	.ctrl_type = SOCK_DGRAM,
	.sock_domain = AF_INET,
	.sock_type = SOCK_DGRAM,
	.sock_prot = IPPROTO_UDP,
	.accept = NULL,
	.connect = NULL,
	.listen = udp_bind_listener,
	.enable_all = enable_all_listeners,
	.pause = udp_pause_listener,
	.add = udp4_add_listener,
	.listeners = LIST_HEAD_INIT(proto_udp4.listeners),
	.nb_listeners = 0,
};

INITCALL1(STG_REGISTER, protocol_register, &proto_udp4);

/* Note: must not be declared <const> as its list will be overwritten */
static struct protocol proto_udp6 = {
	.name = "udp6",
	.fam = &proto_fam_inet6,
	.ctrl_type = SOCK_DGRAM,
	.sock_domain = AF_INET6,
	.sock_type = SOCK_DGRAM,
	.sock_prot = IPPROTO_UDP,
	.accept = NULL,
	.connect = NULL,
	.listen = udp_bind_listener,
	.enable_all = enable_all_listeners,
	.pause = udp_pause_listener,
	.add = udp6_add_listener,
	.listeners = LIST_HEAD_INIT(proto_udp6.listeners),
	.nb_listeners = 0,
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

	listener->state = LI_LISTEN;

 udp_return:
	if (msg && errlen) {
		char pn[INET6_ADDRSTRLEN];

		addr_to_str(&listener->rx.addr, pn, sizeof(pn));
		snprintf(errmsg, errlen, "%s [%s:%d]", msg, pn, get_host_port(&listener->rx.addr));
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
	listener->rx.proto = &proto_udp4;
	((struct sockaddr_in *)(&listener->rx.addr))->sin_port = htons(port);
	LIST_ADDQ(&proto_udp4.listeners, &listener->rx.proto_list);
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
	listener->rx.proto = &proto_udp6;
	((struct sockaddr_in *)(&listener->rx.addr))->sin_port = htons(port);
	LIST_ADDQ(&proto_udp6.listeners, &listener->rx.proto_list);
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
