/*
 * Generic code for native (BSD-compatible) sockets
 *
 * Copyright 2000-2020 Willy Tarreau <w@1wt.eu>
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

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/listener-t.h>
#include <haproxy/namespace.h>
#include <haproxy/sock.h>
#include <haproxy/sock_inet.h>
#include <haproxy/tools.h>

/* the list of remaining sockets transferred from an older process */
struct xfer_sock_list *xfer_sock_list = NULL;

/* Create a socket to connect to the server in conn->dst (which MUST be valid),
 * using the configured namespace if needed, or the one passed by the proxy
 * protocol if required to do so. It ultimately calls socket() or socketat()
 * and returns the FD or error code.
 */
int sock_create_server_socket(struct connection *conn)
{
	const struct netns_entry *ns = NULL;

#ifdef USE_NS
	if (objt_server(conn->target)) {
		if (__objt_server(conn->target)->flags & SRV_F_USE_NS_FROM_PP)
			ns = conn->proxy_netns;
		else
			ns = __objt_server(conn->target)->netns;
	}
#endif
	return my_socketat(ns, conn->dst->ss_family, SOCK_STREAM, 0);
}

/*
 * Retrieves the source address for the socket <fd>, with <dir> indicating
 * if we're a listener (=0) or an initiator (!=0). It returns 0 in case of
 * success, -1 in case of error. The socket's source address is stored in
 * <sa> for <salen> bytes.
 */
int sock_get_src(int fd, struct sockaddr *sa, socklen_t salen, int dir)
{
	if (dir)
		return getsockname(fd, sa, &salen);
	else
		return getpeername(fd, sa, &salen);
}

/*
 * Retrieves the original destination address for the socket <fd>, with <dir>
 * indicating if we're a listener (=0) or an initiator (!=0). It returns 0 in
 * case of success, -1 in case of error. The socket's source address is stored
 * in <sa> for <salen> bytes.
 */
int sock_get_dst(int fd, struct sockaddr *sa, socklen_t salen, int dir)
{
	if (dir)
		return getpeername(fd, sa, &salen);
	else
		return getsockname(fd, sa, &salen);
}

/* When binding the listeners, check if a socket has been sent to us by the
 * previous process that we could reuse, instead of creating a new one. Note
 * that some address family-specific options are checked on the listener and
 * on the socket. Typically for AF_INET and AF_INET6, we check for transparent
 * mode, and for AF_INET6 we also check for "v4v6" or "v6only". The reused
 * socket is automatically removed from the list so that it's not proposed
 * anymore.
 */
int sock_find_compatible_fd(const struct listener *l)
{
	struct xfer_sock_list *xfer_sock = xfer_sock_list;
	int options = l->options & (LI_O_FOREIGN | LI_O_V6ONLY | LI_O_V4V6);
	int if_namelen = 0;
	int ns_namelen = 0;
	int ret = -1;

	if (!l->proto->addrcmp)
		return -1;

	if (l->addr.ss_family == AF_INET6) {
		/* Prepare to match the v6only option against what we really want. Note
		 * that sadly the two options are not exclusive to each other and that
		 * v6only is stronger than v4v6.
		 */
		if ((options & LI_O_V6ONLY) || (sock_inet6_v6only_default && !(options & LI_O_V4V6)))
			options |= LI_O_V6ONLY;
		else if ((options & LI_O_V4V6) || !sock_inet6_v6only_default)
			options &= ~LI_O_V6ONLY;
	}
	options &= ~LI_O_V4V6;

	if (l->interface)
		if_namelen = strlen(l->interface);
#ifdef USE_NS
	if (l->netns)
		ns_namelen = l->netns->name_len;
#endif

	while (xfer_sock) {
		if (((options ^ xfer_sock->options) & (LI_O_FOREIGN | LI_O_V6ONLY)) == 0 &&
		    (if_namelen == xfer_sock->if_namelen) &&
		    (ns_namelen == xfer_sock->ns_namelen) &&
		    (!if_namelen || strcmp(l->interface, xfer_sock->iface) == 0) &&
#ifdef USE_NS
		    (!ns_namelen || strcmp(l->netns->node.key, xfer_sock->namespace) == 0) &&
#endif
		    l->proto->addrcmp(&xfer_sock->addr, &l->addr) == 0)
			break;
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

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
