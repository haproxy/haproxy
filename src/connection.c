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

#include <proto/connection.h>
#include <proto/proto_tcp.h>
#include <proto/session.h>
#include <proto/stream_interface.h>

/* I/O callback for fd-based connections. It calls the read/write handlers
 * provided by the connection's sock_ops, which must be valid. It returns 0.
 */
int conn_fd_handler(int fd)
{
	struct connection *conn = fdtab[fd].owner;

	if (unlikely(!conn))
		return 0;

	/* before engaging there, we clear the new WAIT_* flags so that we can
	 * more easily detect an EAGAIN condition from anywhere.
	 */
	conn->flags &= ~(CO_FL_WAIT_DATA|CO_FL_WAIT_ROOM|CO_FL_WAIT_RD|CO_FL_WAIT_WR);

 process_handshake:
	/* The handshake callbacks are called in sequence. If either of them is
	 * missing something, it must enable the required polling at the socket
	 * layer of the connection. Polling state is not guaranteed when entering
	 * these handlers, so any handshake handler which does not complete its
	 * work must explicitly disable events it's not interested in.
	 */
	while (unlikely(conn->flags & CO_FL_HANDSHAKE)) {
		if (unlikely(conn->flags & (CO_FL_ERROR|CO_FL_WAIT_RD|CO_FL_WAIT_WR)))
			goto leave;

		if (conn->flags & CO_FL_ACCEPT_PROXY)
			if (!conn_recv_proxy(conn, CO_FL_ACCEPT_PROXY))
				goto leave;

		if (conn->flags & CO_FL_SI_SEND_PROXY)
			if (!conn_si_send_proxy(conn, CO_FL_SI_SEND_PROXY))
				goto leave;
	}

	/* Once we're purely in the data phase, we disable handshake polling */
	if (!(conn->flags & CO_FL_POLL_SOCK))
		__conn_sock_stop_both(conn);

	/* Maybe we need to finish initializing an incoming session. The
	 * function may fail and cause the connection to be destroyed, thus
	 * we must not use it anymore and should immediately leave instead.
	 */
	if ((conn->flags & CO_FL_INIT_SESS) &&
	    conn_session_complete(conn, CO_FL_INIT_SESS) < 0)
		return 0;

	if ((fdtab[fd].ev & (FD_POLL_IN | FD_POLL_HUP | FD_POLL_ERR)) &&
	    !(conn->flags & (CO_FL_WAIT_RD|CO_FL_WAIT_ROOM)))
		conn->app_cb->recv(conn);

	if (unlikely(conn->flags & CO_FL_ERROR))
		goto leave;

	/* It may happen during the data phase that a handshake is
	 * enabled again (eg: SSL)
	 */
	if (unlikely(conn->flags & CO_FL_HANDSHAKE))
		goto process_handshake;

	if ((fdtab[fd].ev & (FD_POLL_OUT | FD_POLL_ERR)) &&
	    !(conn->flags & (CO_FL_WAIT_WR|CO_FL_WAIT_DATA)))
		conn->app_cb->send(conn);

	if (unlikely(conn->flags & CO_FL_ERROR))
		goto leave;

	/* It may happen during the data phase that a handshake is
	 * enabled again (eg: SSL)
	 */
	if (unlikely(conn->flags & CO_FL_HANDSHAKE))
		goto process_handshake;

	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && !(conn->flags & CO_FL_WAIT_WR)) {
		/* still waiting for a connection to establish and nothing was
		 * attempted yet to probe the connection. Then let's retry the
		 * connect().
		 */
		if (!tcp_connect_probe(conn))
			goto leave;
	}

 leave:
	/* we may need to release the connection which is an embryonic session */
	if ((conn->flags & (CO_FL_ERROR|CO_FL_INIT_SESS)) == (CO_FL_ERROR|CO_FL_INIT_SESS)) {
		conn->flags |= CO_FL_ERROR;
		conn_session_complete(conn, CO_FL_INIT_SESS);
		return 0;
	}

	if (conn->flags & CO_FL_NOTIFY_SI)
		conn_notify_si(conn);

	/* Last check, verify if the connection just established */
	if (unlikely(!(conn->flags & (CO_FL_WAIT_L4_CONN | CO_FL_WAIT_L6_CONN | CO_FL_CONNECTED))))
		conn->flags |= CO_FL_CONNECTED;

	/* remove the events before leaving */
	fdtab[fd].ev &= ~(FD_POLL_IN | FD_POLL_OUT | FD_POLL_HUP | FD_POLL_ERR);

	/* commit polling changes */
	conn_cond_update_polling(conn);
	return 0;
}

/* Update polling on connection <c>'s file descriptor depending on its current
 * state as reported in the connection's CO_FL_CURR_* flags, reports of EAGAIN
 * in CO_FL_WAIT_*, and the data layer expectations indicated by CO_FL_DATA_*.
 * The connection flags are updated with the new flags at the end of the
 * operation.
 */
void conn_update_data_polling(struct connection *c)
{
	unsigned int f = c->flags;

	/* update read status if needed */
	if (unlikely((f & (CO_FL_CURR_RD_ENA|CO_FL_DATA_RD_ENA)) == CO_FL_CURR_RD_ENA)) {
		f &= ~(CO_FL_CURR_RD_ENA|CO_FL_CURR_RD_POL);
		fd_stop_recv(c->t.sock.fd);
	}
	else if (unlikely((f & (CO_FL_CURR_RD_ENA|CO_FL_CURR_RD_POL)) != (CO_FL_CURR_RD_ENA|CO_FL_CURR_RD_POL) &&
	                  (f & (CO_FL_DATA_RD_ENA|CO_FL_WAIT_RD)) == (CO_FL_DATA_RD_ENA|CO_FL_WAIT_RD))) {
		f |= (CO_FL_CURR_RD_ENA|CO_FL_CURR_RD_POL);
		fd_poll_recv(c->t.sock.fd);
	}
	else if (unlikely((f & (CO_FL_CURR_RD_ENA|CO_FL_DATA_RD_ENA)) == CO_FL_DATA_RD_ENA)) {
		f |= CO_FL_CURR_RD_ENA;
		fd_want_recv(c->t.sock.fd);
	}

	/* update write status if needed */
	if (unlikely((f & (CO_FL_CURR_WR_ENA|CO_FL_DATA_WR_ENA)) == CO_FL_CURR_WR_ENA)) {
		f &= ~(CO_FL_CURR_WR_ENA|CO_FL_CURR_WR_POL);
		fd_stop_send(c->t.sock.fd);
	}
	else if (unlikely((f & (CO_FL_CURR_WR_ENA|CO_FL_CURR_WR_POL)) != (CO_FL_CURR_WR_ENA|CO_FL_CURR_WR_POL) &&
	                  (f & (CO_FL_DATA_WR_ENA|CO_FL_WAIT_WR)) == (CO_FL_DATA_WR_ENA|CO_FL_WAIT_WR))) {
		f |= (CO_FL_CURR_WR_ENA|CO_FL_CURR_WR_POL);
		fd_poll_send(c->t.sock.fd);
	}
	else if (unlikely((f & (CO_FL_CURR_WR_ENA|CO_FL_DATA_WR_ENA)) == CO_FL_DATA_WR_ENA)) {
		f |= CO_FL_CURR_WR_ENA;
		fd_want_send(c->t.sock.fd);
	}
	c->flags = f;
}

/* Update polling on connection <c>'s file descriptor depending on its current
 * state as reported in the connection's CO_FL_CURR_* flags, reports of EAGAIN
 * in CO_FL_WAIT_*, and the sock layer expectations indicated by CO_FL_SOCK_*.
 * The connection flags are updated with the new flags at the end of the
 * operation.
 */
void conn_update_sock_polling(struct connection *c)
{
	unsigned int f = c->flags;

	/* update read status if needed */
	if (unlikely((f & (CO_FL_CURR_RD_ENA|CO_FL_SOCK_RD_ENA)) == CO_FL_CURR_RD_ENA)) {
		f &= ~(CO_FL_CURR_RD_ENA|CO_FL_CURR_RD_POL);
		fd_stop_recv(c->t.sock.fd);
	}
	else if (unlikely((f & (CO_FL_CURR_RD_ENA|CO_FL_CURR_RD_POL)) != (CO_FL_CURR_RD_ENA|CO_FL_CURR_RD_POL) &&
	                  (f & (CO_FL_SOCK_RD_ENA|CO_FL_WAIT_RD)) == (CO_FL_SOCK_RD_ENA|CO_FL_WAIT_RD))) {
		f |= (CO_FL_CURR_RD_ENA|CO_FL_CURR_RD_POL);
		fd_poll_recv(c->t.sock.fd);
	}
	else if (unlikely((f & (CO_FL_CURR_RD_ENA|CO_FL_SOCK_RD_ENA)) == CO_FL_SOCK_RD_ENA)) {
		f |= CO_FL_CURR_RD_ENA;
		fd_want_recv(c->t.sock.fd);
	}

	/* update write status if needed */
	if (unlikely((f & (CO_FL_CURR_WR_ENA|CO_FL_SOCK_WR_ENA)) == CO_FL_CURR_WR_ENA)) {
		f &= ~(CO_FL_CURR_WR_ENA|CO_FL_CURR_WR_POL);
		fd_stop_send(c->t.sock.fd);
	}
	else if (unlikely((f & (CO_FL_CURR_WR_ENA|CO_FL_CURR_WR_POL)) != (CO_FL_CURR_WR_ENA|CO_FL_CURR_WR_POL) &&
	                  (f & (CO_FL_SOCK_WR_ENA|CO_FL_WAIT_WR)) == (CO_FL_SOCK_WR_ENA|CO_FL_WAIT_WR))) {
		f |= (CO_FL_CURR_WR_ENA|CO_FL_CURR_WR_POL);
		fd_poll_send(c->t.sock.fd);
	}
	else if (unlikely((f & (CO_FL_CURR_WR_ENA|CO_FL_SOCK_WR_ENA)) == CO_FL_SOCK_WR_ENA)) {
		f |= CO_FL_CURR_WR_ENA;
		fd_want_send(c->t.sock.fd);
	}
	c->flags = f;
}
