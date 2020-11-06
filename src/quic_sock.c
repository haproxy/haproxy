/*
 * QUIC socket management.
 *
 * Copyright 2020 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <haproxy/connection.h>
#include <haproxy/listener.h>

/* Tests if the receiver supports accepting connections. Returns positive on
 * success, 0 if not possible
 */
int quic_sock_accepting_conn(const struct receiver *rx)
{
	return 1;
}

/* Accept an incoming connection from listener <l>, and return it, as well as
 * a CO_AC_* status code into <status> if not null. Null is returned on error.
 * <l> must be a valid listener with a valid frontend.
 */
struct connection *quic_sock_accept_conn(struct listener *l, int *status)
{
	/* TO DO */
	return NULL;
}

/* Function called on a read event from a listening socket. It tries
 * to handle as many connections as possible.
 */
void quic_sock_fd_iocb(int fd)
{
	ssize_t ret;
	struct buffer *buf;
	struct listener *l = objt_listener(fdtab[fd].owner);
	/* Source address */
	struct sockaddr_storage saddr = {0};
	socklen_t saddrlen;

	if (!l)
		ABORT_NOW();

	if (!(fdtab[fd].ev & FD_POLL_IN) || !fd_recv_ready(fd))
		return;

	buf = get_trash_chunk();
	saddrlen = sizeof saddr;
	do {
		ret = recvfrom(fd, buf->area, buf->size, 0,
		               (struct sockaddr *)&saddr, &saddrlen);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				fd_cant_recv(fd);
			return;
		}
	} while (0);

	buf->data = ret;
}
