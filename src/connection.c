/*
 * Connection management functions
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/compat.h>
#include <common/config.h>

#include <types/connection.h>

#include <proto/proto_tcp.h>
#include <proto/stream_interface.h>

/* I/O callback for fd-based connections. It calls the read/write handlers
 * provided by the connection's sock_ops, which must be valid. It returns
 * FD_WAIT_*.
 */
int conn_fd_handler(int fd)
{
	struct connection *conn = fdtab[fd].owner;
	int ret = 0;

	if (unlikely(!conn))
		goto leave;

 process_handshake:
	while (unlikely(conn->flags & CO_FL_HANDSHAKE)) {
		if (unlikely(conn->flags & CO_FL_ERROR))
			goto leave;

		if (conn->flags & CO_FL_SI_SEND_PROXY)
			if ((ret = conn_si_send_proxy(conn, CO_FL_SI_SEND_PROXY)))
				goto leave;
	}

	/* OK now we're in the data phase now */

	if (fdtab[fd].ev & (FD_POLL_IN | FD_POLL_HUP | FD_POLL_ERR))
		if (!conn->data->read(conn))
			ret |= FD_WAIT_READ;

	if (unlikely(conn->flags & CO_FL_ERROR))
		goto leave;

	/* It may happen during the data phase that a handshake is
	 * enabled again (eg: SSL)
	 */
	if (unlikely(conn->flags & CO_FL_HANDSHAKE))
		goto process_handshake;

	if (fdtab[fd].ev & (FD_POLL_OUT | FD_POLL_ERR))
		if (!conn->data->write(conn))
			ret |= FD_WAIT_WRITE;

	if (unlikely(conn->flags & CO_FL_ERROR))
		goto leave;

	/* It may happen during the data phase that a handshake is
	 * enabled again (eg: SSL)
	 */
	if (unlikely(conn->flags & CO_FL_HANDSHAKE))
		goto process_handshake;

	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN)) {
		/* still waiting for a connection to establish and no data to
		 * send in order to probe it ? Then let's retry the connect().
		 */
		if (!tcp_connect_probe(conn))
			ret |= FD_WAIT_WRITE;
	}

 leave:
	if (conn->flags & CO_FL_NOTIFY_SI)
		stream_sock_update_conn(conn);

	/* Last check, verify if the connection just established */
	if (unlikely(!(conn->flags & (CO_FL_WAIT_L4_CONN | CO_FL_WAIT_L6_CONN | CO_FL_CONNECTED))))
		conn->flags |= CO_FL_CONNECTED;

	/* remove the events before leaving */
	fdtab[fd].ev &= ~(FD_POLL_IN | FD_POLL_OUT | FD_POLL_HUP | FD_POLL_ERR);
	return ret;
}
