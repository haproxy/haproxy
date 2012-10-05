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

#include <errno.h>

#include <common/compat.h>
#include <common/config.h>

#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/frontend.h>
#include <proto/proto_tcp.h>
#include <proto/session.h>
#include <proto/stream_interface.h>

#ifdef USE_OPENSSL
#include <proto/ssl_sock.h>
#endif

/* I/O callback for fd-based connections. It calls the read/write handlers
 * provided by the connection's sock_ops, which must be valid. It returns 0.
 */
int conn_fd_handler(int fd)
{
	struct connection *conn = fdtab[fd].owner;
	unsigned int flags;

	if (unlikely(!conn))
		return 0;

	/* before engaging there, we clear the new WAIT_* flags so that we can
	 * more easily detect an EAGAIN condition from anywhere.
	 */
	flags = conn->flags &= ~(CO_FL_WAIT_DATA|CO_FL_WAIT_ROOM|CO_FL_WAIT_RD|CO_FL_WAIT_WR);

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

		if (conn->flags & CO_FL_LOCAL_SPROXY)
			if (!conn_local_send_proxy(conn, CO_FL_LOCAL_SPROXY))
				goto leave;
#ifdef USE_OPENSSL
		if (conn->flags & CO_FL_SSL_WAIT_HS)
			if (!ssl_sock_handshake(conn, CO_FL_SSL_WAIT_HS))
				goto leave;
#endif
	}

	/* Once we're purely in the data phase, we disable handshake polling */
	if (!(conn->flags & CO_FL_POLL_SOCK))
		__conn_sock_stop_both(conn);

	/* The data layer might not be ready yet (eg: when using embryonic
	 * sessions). If we're about to move data, we must initialize it first.
	 * The function may fail and cause the connection to be destroyed, thus
	 * we must not use it anymore and should immediately leave instead.
	 */
	if ((conn->flags & CO_FL_INIT_DATA) && conn->data->init(conn) < 0)
		return 0;

	/* The data transfer starts here and stops on error and handshakes */
	if ((fdtab[fd].ev & (FD_POLL_IN | FD_POLL_HUP | FD_POLL_ERR)) &&
	    !(conn->flags & (CO_FL_WAIT_RD|CO_FL_WAIT_ROOM|CO_FL_ERROR|CO_FL_HANDSHAKE))) {
		/* force detection of a flag change : it's impossible to have both
		 * CONNECTED and WAIT_CONN so we're certain to trigger a change.
		 */
		flags = CO_FL_WAIT_L4_CONN | CO_FL_CONNECTED;
		conn->data->recv(conn);
	}

	if ((fdtab[fd].ev & (FD_POLL_OUT | FD_POLL_ERR)) &&
	    !(conn->flags & (CO_FL_WAIT_WR|CO_FL_WAIT_DATA|CO_FL_ERROR|CO_FL_HANDSHAKE))) {
		/* force detection of a flag change : it's impossible to have both
		 * CONNECTED and WAIT_CONN so we're certain to trigger a change.
		 */
		flags = CO_FL_WAIT_L4_CONN | CO_FL_CONNECTED;
		conn->data->send(conn);
	}

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
	/* The wake callback may be used to process a critical error and abort the
	 * connection. If so, we don't want to go further as the connection will
	 * have been released and the FD destroyed.
	 */
	if ((conn->flags & CO_FL_WAKE_DATA) &&
	    ((conn->flags ^ flags) & CO_FL_CONN_STATE) &&
	    conn->data->wake(conn) < 0)
		return 0;

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
 * operation. Polling is totally disabled if an error was reported.
 */
void conn_update_data_polling(struct connection *c)
{
	unsigned int f = c->flags;

	if (unlikely(f & CO_FL_ERROR)) {
		c->flags &= ~(CO_FL_CURR_RD_ENA | CO_FL_CURR_WR_ENA |
		              CO_FL_SOCK_RD_ENA | CO_FL_SOCK_WR_ENA |
		              CO_FL_DATA_RD_ENA | CO_FL_DATA_WR_ENA);
		fd_stop_both(c->t.sock.fd);
		return;
	}

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
 * operation. Polling is totally disabled if an error was reported.
 */
void conn_update_sock_polling(struct connection *c)
{
	unsigned int f = c->flags;

	if (unlikely(f & CO_FL_ERROR)) {
		c->flags &= ~(CO_FL_CURR_RD_ENA | CO_FL_CURR_WR_ENA |
		              CO_FL_SOCK_RD_ENA | CO_FL_SOCK_WR_ENA |
		              CO_FL_DATA_RD_ENA | CO_FL_DATA_WR_ENA);
		fd_stop_both(c->t.sock.fd);
		return;
	}

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

/* This handshake handler waits a PROXY protocol header at the beginning of the
 * raw data stream. The header looks like this :
 *
 *   "PROXY" <SP> PROTO <SP> SRC3 <SP> DST3 <SP> SRC4 <SP> <DST4> "\r\n"
 *
 * There must be exactly one space between each field. Fields are :
 *  - PROTO : layer 4 protocol, which must be "TCP4" or "TCP6".
 *  - SRC3  : layer 3 (eg: IP) source address in standard text form
 *  - DST3  : layer 3 (eg: IP) destination address in standard text form
 *  - SRC4  : layer 4 (eg: TCP port) source address in standard text form
 *  - DST4  : layer 4 (eg: TCP port) destination address in standard text form
 *
 * This line MUST be at the beginning of the buffer and MUST NOT wrap.
 *
 * The header line is small and in all cases smaller than the smallest normal
 * TCP MSS. So it MUST always be delivered as one segment, which ensures we
 * can safely use MSG_PEEK and avoid buffering.
 *
 * Once the data is fetched, the values are set in the connection's address
 * fields, and data are removed from the socket's buffer. The function returns
 * zero if it needs to wait for more data or if it fails, or 1 if it completed
 * and removed itself.
 */
int conn_recv_proxy(struct connection *conn, int flag)
{
	char *line, *end;
	int len;

	/* we might have been called just after an asynchronous shutr */
	if (conn->flags & CO_FL_SOCK_RD_SH)
		goto fail;

	do {
		len = recv(conn->t.sock.fd, trash, trashlen, MSG_PEEK);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				conn_sock_poll_recv(conn);
				return 0;
			}
			goto fail;
		}
	} while (0);

	if (len < 6)
		goto missing;

	line = trash;
	end = trash + len;

	/* Decode a possible proxy request, fail early if it does not match */
	if (strncmp(line, "PROXY ", 6) != 0)
		goto fail;

	line += 6;
	if (len < 18) /* shortest possible line */
		goto missing;

	if (!memcmp(line, "TCP4 ", 5) != 0) {
		u32 src3, dst3, sport, dport;

		line += 5;

		src3 = inetaddr_host_lim_ret(line, end, &line);
		if (line == end)
			goto missing;
		if (*line++ != ' ')
			goto fail;

		dst3 = inetaddr_host_lim_ret(line, end, &line);
		if (line == end)
			goto missing;
		if (*line++ != ' ')
			goto fail;

		sport = read_uint((const char **)&line, end);
		if (line == end)
			goto missing;
		if (*line++ != ' ')
			goto fail;

		dport = read_uint((const char **)&line, end);
		if (line > end - 2)
			goto missing;
		if (*line++ != '\r')
			goto fail;
		if (*line++ != '\n')
			goto fail;

		/* update the session's addresses and mark them set */
		((struct sockaddr_in *)&conn->addr.from)->sin_family      = AF_INET;
		((struct sockaddr_in *)&conn->addr.from)->sin_addr.s_addr = htonl(src3);
		((struct sockaddr_in *)&conn->addr.from)->sin_port        = htons(sport);

		((struct sockaddr_in *)&conn->addr.to)->sin_family        = AF_INET;
		((struct sockaddr_in *)&conn->addr.to)->sin_addr.s_addr   = htonl(dst3);
		((struct sockaddr_in *)&conn->addr.to)->sin_port          = htons(dport);
		conn->flags |= CO_FL_ADDR_FROM_SET | CO_FL_ADDR_TO_SET;
	}
	else if (!memcmp(line, "TCP6 ", 5) != 0) {
		u32 sport, dport;
		char *src_s;
		char *dst_s, *sport_s, *dport_s;
		struct in6_addr src3, dst3;

		line += 5;

		src_s = line;
		dst_s = sport_s = dport_s = NULL;
		while (1) {
			if (line > end - 2) {
				goto missing;
			}
			else if (*line == '\r') {
				*line = 0;
				line++;
				if (*line++ != '\n')
					goto fail;
				break;
			}

			if (*line == ' ') {
				*line = 0;
				if (!dst_s)
					dst_s = line + 1;
				else if (!sport_s)
					sport_s = line + 1;
				else if (!dport_s)
					dport_s = line + 1;
			}
			line++;
		}

		if (!dst_s || !sport_s || !dport_s)
			goto fail;

		sport = read_uint((const char **)&sport_s,dport_s - 1);
		if (*sport_s != 0)
			goto fail;

		dport = read_uint((const char **)&dport_s,line - 2);
		if (*dport_s != 0)
			goto fail;

		if (inet_pton(AF_INET6, src_s, (void *)&src3) != 1)
			goto fail;

		if (inet_pton(AF_INET6, dst_s, (void *)&dst3) != 1)
			goto fail;

		/* update the session's addresses and mark them set */
		((struct sockaddr_in6 *)&conn->addr.from)->sin6_family      = AF_INET6;
		memcpy(&((struct sockaddr_in6 *)&conn->addr.from)->sin6_addr, &src3, sizeof(struct in6_addr));
		((struct sockaddr_in6 *)&conn->addr.from)->sin6_port        = htons(sport);

		((struct sockaddr_in6 *)&conn->addr.to)->sin6_family        = AF_INET6;
		memcpy(&((struct sockaddr_in6 *)&conn->addr.to)->sin6_addr, &dst3, sizeof(struct in6_addr));
		((struct sockaddr_in6 *)&conn->addr.to)->sin6_port          = htons(dport);
		conn->flags |= CO_FL_ADDR_FROM_SET | CO_FL_ADDR_TO_SET;
	}
	else {
		goto fail;
	}

	/* remove the PROXY line from the request. For this we re-read the
	 * exact line at once. If we don't get the exact same result, we
	 * fail.
	 */
	len = line - trash;
	do {
		int len2 = recv(conn->t.sock.fd, trash, len, 0);
		if (len2 < 0 && errno == EINTR)
			continue;
		if (len2 != len)
			goto fail;
	} while (0);

	conn->flags &= ~flag;
	return 1;

 missing:
	/* Missing data. Since we're using MSG_PEEK, we can only poll again if
	 * we have not read anything. Otherwise we need to fail because we won't
	 * be able to poll anymore.
	 */
 fail:
	conn_sock_stop_both(conn);
	conn->flags |= CO_FL_ERROR;
	conn->flags &= ~flag;
	return 0;
}

/* Makes a PROXY protocol line from the two addresses. The output is sent to
 * buffer <buf> for a maximum size of <buf_len> (including the trailing zero).
 * It returns the number of bytes composing this line (including the trailing
 * LF), or zero in case of failure (eg: not enough space). It supports TCP4,
 * TCP6 and "UNKNOWN" formats.
 */
int make_proxy_line(char *buf, int buf_len, struct sockaddr_storage *src, struct sockaddr_storage *dst)
{
	int ret = 0;

	if (src->ss_family == dst->ss_family && src->ss_family == AF_INET) {
		ret = snprintf(buf + ret, buf_len - ret, "PROXY TCP4 ");
		if (ret >= buf_len)
			return 0;

		/* IPv4 src */
		if (!inet_ntop(src->ss_family, &((struct sockaddr_in *)src)->sin_addr, buf + ret, buf_len - ret))
			return 0;

		ret += strlen(buf + ret);
		if (ret >= buf_len)
			return 0;

		buf[ret++] = ' ';

		/* IPv4 dst */
		if (!inet_ntop(dst->ss_family, &((struct sockaddr_in *)dst)->sin_addr, buf + ret, buf_len - ret))
			return 0;

		ret += strlen(buf + ret);
		if (ret >= buf_len)
			return 0;

		/* source and destination ports */
		ret += snprintf(buf + ret, buf_len - ret, " %u %u\r\n",
				ntohs(((struct sockaddr_in *)src)->sin_port),
				ntohs(((struct sockaddr_in *)dst)->sin_port));
		if (ret >= buf_len)
			return 0;
	}
	else if (src->ss_family == dst->ss_family && src->ss_family == AF_INET6) {
		ret = snprintf(buf + ret, buf_len - ret, "PROXY TCP6 ");
		if (ret >= buf_len)
			return 0;

		/* IPv6 src */
		if (!inet_ntop(src->ss_family, &((struct sockaddr_in6 *)src)->sin6_addr, buf + ret, buf_len - ret))
			return 0;

		ret += strlen(buf + ret);
		if (ret >= buf_len)
			return 0;

		buf[ret++] = ' ';

		/* IPv6 dst */
		if (!inet_ntop(dst->ss_family, &((struct sockaddr_in6 *)dst)->sin6_addr, buf + ret, buf_len - ret))
			return 0;

		ret += strlen(buf + ret);
		if (ret >= buf_len)
			return 0;

		/* source and destination ports */
		ret += snprintf(buf + ret, buf_len - ret, " %u %u\r\n",
				ntohs(((struct sockaddr_in6 *)src)->sin6_port),
				ntohs(((struct sockaddr_in6 *)dst)->sin6_port));
		if (ret >= buf_len)
			return 0;
	}
	else {
		/* unknown family combination */
		ret = snprintf(buf, buf_len, "PROXY UNKNOWN\r\n");
		if (ret >= buf_len)
			return 0;
	}
	return ret;
}

/* This callback is used to send a valid PROXY protocol line to a socket being
 * established from the local machine. It sets the protocol addresses to the
 * local and remote address. This is typically used with health checks or when
 * it is not possible to determine the other end's address. It returns 0 if it
 * fails in a fatal way or needs to poll to go further, otherwise it returns
 * non-zero and removes itself from the connection's flags (the bit is provided
 * in <flag> by the caller). It is designed to be called by the connection
 * handler and relies on it to commit polling changes. Note that this function
 * expects to be able to send the whole line at once, which should always be
 * possible since it is supposed to start at the first byte of the outgoing
 * data segment.
 */
int conn_local_send_proxy(struct connection *conn, unsigned int flag)
{
	int ret, len;

	/* we might have been called just after an asynchronous shutw */
	if (conn->flags & CO_FL_SOCK_WR_SH)
		goto out_error;

	/* The target server expects a PROXY line to be sent first. */
	conn_get_from_addr(conn);
	if (!(conn->flags & CO_FL_ADDR_FROM_SET))
		goto out_error;

	conn_get_to_addr(conn);
	if (!(conn->flags & CO_FL_ADDR_TO_SET))
		goto out_error;

	len = make_proxy_line(trash, trashlen, &conn->addr.from, &conn->addr.to);
	if (!len)
		goto out_error;

	/* we have to send trash from len bytes. If the data layer has a
	 * pending write, we'll also set MSG_MORE.
	 */
	ret = send(conn->t.sock.fd, trash, len, (conn->flags & CO_FL_DATA_WR_ENA) ? MSG_MORE : 0);

	if (ret == 0)
		goto out_wait;

	if (ret < 0) {
		if (errno == EAGAIN)
			goto out_wait;
		goto out_error;
	}

	if (ret != len)
		goto out_error;

	/* The connection is ready now, simply return and let the connection
	 * handler notify upper layers if needed.
	 */
	if (conn->flags & CO_FL_WAIT_L4_CONN)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;
	conn->flags &= ~flag;
	return 1;

 out_error:
	/* Write error on the file descriptor */
	conn->flags |= CO_FL_ERROR;
	conn->flags &= ~flag;
	return 0;

 out_wait:
	__conn_sock_stop_recv(conn);
	__conn_sock_poll_send(conn);
	return 0;
}
