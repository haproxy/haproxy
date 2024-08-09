/*
 * DGRAM protocol layer on top of AF_UNIX
 *
 * Copyright 2020 HAProxy Technologies, Emeric Brun <ebrun@haproxy.com>
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
#include <sys/un.h>

#include <haproxy/fd.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/namespace.h>
#include <haproxy/protocol.h>
#include <haproxy/sock.h>
#include <haproxy/sock_unix.h>
#include <haproxy/tools.h>

static int uxdg_bind_listener(struct listener *listener, char *errmsg, int errlen);
static void uxdg_enable_listener(struct listener *listener);
static void uxdg_disable_listener(struct listener *listener);
static int uxdg_suspend_receiver(struct receiver *rx);

/* Note: must not be declared <const> as its list will be overwritten */
struct protocol proto_uxdg = {
	.name           = "uxdg",

	/* connection layer */
	.xprt_type      = PROTO_TYPE_DGRAM,
	.listen         = uxdg_bind_listener,
	.enable         = uxdg_enable_listener,
	.disable        = uxdg_disable_listener,
	.add            = default_add_listener,
	.unbind         = default_unbind_listener,
	.suspend        = default_suspend_listener,
	.resume         = default_resume_listener,

	/* binding layer */
	.rx_suspend     = uxdg_suspend_receiver,

	/* address family */
	.fam            = &proto_fam_unix,

	/* socket layer */
	.proto_type     = PROTO_TYPE_DGRAM,
	.sock_type      = SOCK_DGRAM,
	.sock_prot      = 0,
	.rx_enable      = sock_enable,
	.rx_disable     = sock_disable,
	.rx_unbind      = sock_unbind,
};

/* Note: must not be declared <const> as its list will be overwritten */
struct protocol proto_abns_dgram = {
	.name           = "abns_dgram",

	/* connection layer */
	.xprt_type      = PROTO_TYPE_DGRAM,
	.listen         = uxdg_bind_listener,
	.enable         = uxdg_enable_listener,
	.disable        = uxdg_disable_listener,
	.add            = default_add_listener,
	.unbind         = default_unbind_listener,
	.suspend        = default_suspend_listener,
	.resume         = default_resume_listener,

	/* binding layer */
	.rx_suspend     = uxdg_suspend_receiver,

	/* address family */
	.fam            = &proto_fam_abns,

	/* socket layer */
	.proto_type     = PROTO_TYPE_DGRAM,
	.sock_type      = SOCK_DGRAM,
	.sock_prot      = 0,
	.rx_enable      = sock_enable,
	.rx_disable     = sock_disable,
	.rx_unbind      = sock_unbind,
	.receivers      = LIST_HEAD_INIT(proto_abns_dgram.receivers),
	.nb_receivers   = 0,
};

/* Note: must not be declared <const> as its list will be overwritten */
struct protocol proto_abnsz_dgram = {
	.name           = "abnsz_dgram",

	/* connection layer */
	.xprt_type      = PROTO_TYPE_DGRAM,
	.listen         = uxdg_bind_listener,
	.enable         = uxdg_enable_listener,
	.disable        = uxdg_disable_listener,
	.add            = default_add_listener,
	.unbind         = default_unbind_listener,
	.suspend        = default_suspend_listener,
	.resume         = default_resume_listener,

	/* binding layer */
	.rx_suspend     = uxdg_suspend_receiver,

	/* address family */
	.fam            = &proto_fam_abnsz,

	/* socket layer */
	.proto_type     = PROTO_TYPE_DGRAM,
	.sock_type      = SOCK_DGRAM,
	.sock_prot      = 0,
	.rx_enable      = sock_enable,
	.rx_disable     = sock_disable,
	.rx_unbind      = sock_unbind,
	.receivers      = LIST_HEAD_INIT(proto_abnsz_dgram.receivers),
	.nb_receivers   = 0,
};

INITCALL1(STG_REGISTER, protocol_register, &proto_uxdg);
INITCALL1(STG_REGISTER, protocol_register, &proto_abns_dgram);
INITCALL1(STG_REGISTER, protocol_register, &proto_abnsz_dgram);

/* This function tries to bind dgram unix socket listener. It may return a warning or
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
int uxdg_bind_listener(struct listener *listener, char *errmsg, int errlen)
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
		err |= ERR_FATAL | ERR_ALERT;
		goto uxdg_return;
	}

	listener_set_state(listener, LI_LISTEN);

 uxdg_return:
	if (msg && errlen) {
		char *path_str;

		path_str = sa2str((struct sockaddr_storage *)&listener->rx.addr, 0, 0);
		snprintf(errmsg, errlen, "%s for [%s]", msg, ((path_str) ? path_str : ""));
		ha_free(&path_str);
	}
	return err;
}

/* Enable receipt of incoming connections for listener <l>. The receiver must
 * still be valid.
 */
static void uxdg_enable_listener(struct listener *l)
{
	fd_want_recv_safe(l->rx.fd);
}

/* Disable receipt of incoming connections for listener <l>. The receiver must
 * still be valid.
 */
static void uxdg_disable_listener(struct listener *l)
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
static int uxdg_suspend_receiver(struct receiver *rx)
{
        struct listener *l = LIST_ELEM(rx, struct listener *, rx);

        if (((struct sockaddr_un *)&rx->addr)->sun_path[0]) {
		uxdg_disable_listener(l);
                return 1;
	}

        /* Listener's lock already held. Call lockless version of
         * unbind_listener. */
        do_unbind_listener(l);
        return 0;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
