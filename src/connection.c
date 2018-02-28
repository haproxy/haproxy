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
#include <common/namespace.h>

#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/frontend.h>
#include <proto/proto_tcp.h>
#include <proto/stream_interface.h>
#include <proto/sample.h>

#ifdef USE_OPENSSL
#include <proto/ssl_sock.h>
#endif

struct pool_head *pool_head_connection;
struct pool_head *pool_head_connstream;
struct xprt_ops *registered_xprt[XPRT_ENTRIES] = { NULL, };

/* List head of all known muxes for ALPN */
struct alpn_mux_list alpn_mux_list = {
        .list = LIST_HEAD_INIT(alpn_mux_list.list)
};

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_connection()
{
	pool_head_connection = create_pool("connection", sizeof (struct connection), MEM_F_SHARED);
	if (!pool_head_connection)
		goto fail_conn;

	pool_head_connstream = create_pool("conn_stream", sizeof(struct conn_stream), MEM_F_SHARED);
	if (!pool_head_connstream)
		goto fail_cs;

	return 1;
 fail_cs:
	pool_destroy(pool_head_connection);
	pool_head_connection = NULL;
 fail_conn:
	return 0;
}

/* I/O callback for fd-based connections. It calls the read/write handlers
 * provided by the connection's sock_ops, which must be valid.
 */
void conn_fd_handler(int fd)
{
	struct connection *conn = fdtab[fd].owner;
	unsigned int flags;

	if (unlikely(!conn)) {
		activity[tid].conn_dead++;
		return;
	}

	conn_refresh_polling_flags(conn);
	conn->flags |= CO_FL_WILL_UPDATE;

	flags = conn->flags & ~CO_FL_ERROR; /* ensure to call the wake handler upon error */

 process_handshake:
	/* The handshake callbacks are called in sequence. If either of them is
	 * missing something, it must enable the required polling at the socket
	 * layer of the connection. Polling state is not guaranteed when entering
	 * these handlers, so any handshake handler which does not complete its
	 * work must explicitly disable events it's not interested in. Error
	 * handling is also performed here in order to reduce the number of tests
	 * around.
	 */
	while (unlikely(conn->flags & (CO_FL_HANDSHAKE | CO_FL_ERROR))) {
		if (unlikely(conn->flags & CO_FL_ERROR))
			goto leave;

		if (conn->flags & CO_FL_ACCEPT_CIP)
			if (!conn_recv_netscaler_cip(conn, CO_FL_ACCEPT_CIP))
				goto leave;

		if (conn->flags & CO_FL_ACCEPT_PROXY)
			if (!conn_recv_proxy(conn, CO_FL_ACCEPT_PROXY))
				goto leave;

		if (conn->flags & CO_FL_SEND_PROXY)
			if (!conn_si_send_proxy(conn, CO_FL_SEND_PROXY))
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

	/* The connection owner might want to be notified about an end of
	 * handshake indicating the connection is ready, before we proceed with
	 * any data exchange. The callback may fail and cause the connection to
	 * be destroyed, thus we must not use it anymore and should immediately
	 * leave instead. The caller must immediately unregister itself once
	 * called.
	 */
	if (conn->xprt_done_cb && conn->xprt_done_cb(conn) < 0)
		return;

	if (conn->xprt && fd_send_ready(fd) &&
	    ((conn->flags & (CO_FL_XPRT_WR_ENA|CO_FL_ERROR|CO_FL_HANDSHAKE)) == CO_FL_XPRT_WR_ENA)) {
		/* force reporting of activity by clearing the previous flags :
		 * we'll have at least ERROR or CONNECTED at the end of an I/O,
		 * both of which will be detected below.
		 */
		flags = 0;
		conn->mux->send(conn);
	}

	/* The data transfer starts here and stops on error and handshakes. Note
	 * that we must absolutely test conn->xprt at each step in case it suddenly
	 * changes due to a quick unexpected close().
	 */
	if (conn->xprt && fd_recv_ready(fd) &&
	    ((conn->flags & (CO_FL_XPRT_RD_ENA|CO_FL_WAIT_ROOM|CO_FL_ERROR|CO_FL_HANDSHAKE)) == CO_FL_XPRT_RD_ENA)) {
		/* force reporting of activity by clearing the previous flags :
		 * we'll have at least ERROR or CONNECTED at the end of an I/O,
		 * both of which will be detected below.
		 */
		flags = 0;
		conn->mux->recv(conn);
	}

	/* It may happen during the data phase that a handshake is
	 * enabled again (eg: SSL)
	 */
	if (unlikely(conn->flags & (CO_FL_HANDSHAKE | CO_FL_ERROR)))
		goto process_handshake;

	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN)) {
		/* still waiting for a connection to establish and nothing was
		 * attempted yet to probe the connection. Then let's retry the
		 * connect().
		 */
		if (!tcp_connect_probe(conn))
			goto leave;
	}
 leave:
	/* Verify if the connection just established. */
	if (unlikely(!(conn->flags & (CO_FL_WAIT_L4_CONN | CO_FL_WAIT_L6_CONN | CO_FL_CONNECTED))))
		conn->flags |= CO_FL_CONNECTED;

	/* The connection owner might want to be notified about failures to
	 * complete the handshake. The callback may fail and cause the
	 * connection to be destroyed, thus we must not use it anymore and
	 * should immediately leave instead. The caller must immediately
	 * unregister itself once called.
	 */
	if (((conn->flags ^ flags) & CO_FL_NOTIFY_DONE) &&
	    conn->xprt_done_cb && conn->xprt_done_cb(conn) < 0)
		return;

	/* The wake callback is normally used to notify the data layer about
	 * data layer activity (successful send/recv), connection establishment,
	 * shutdown and fatal errors. We need to consider the following
	 * situations to wake up the data layer :
	 *  - change among the CO_FL_NOTIFY_DATA flags :
	 *      {DATA,SOCK}_{RD,WR}_SH, ERROR,
	 *  - absence of any of {L4,L6}_CONN and CONNECTED, indicating the
	 *    end of handshake and transition to CONNECTED
	 *  - raise of CONNECTED with HANDSHAKE down
	 *  - end of HANDSHAKE with CONNECTED set
	 *  - regular data layer activity
	 *
	 * Note that the wake callback is allowed to release the connection and
	 * the fd (and return < 0 in this case).
	 */
	if ((((conn->flags ^ flags) & CO_FL_NOTIFY_DATA) ||
	     ((flags & (CO_FL_CONNECTED|CO_FL_HANDSHAKE)) != CO_FL_CONNECTED &&
	      (conn->flags & (CO_FL_CONNECTED|CO_FL_HANDSHAKE)) == CO_FL_CONNECTED)) &&
	    conn->mux->wake(conn) < 0)
		return;

	/* remove the events before leaving */
	fdtab[fd].ev &= FD_POLL_STICKY;

	/* commit polling changes */
	conn->flags &= ~CO_FL_WILL_UPDATE;
	conn_cond_update_polling(conn);
	return;
}

/* Update polling on connection <c>'s file descriptor depending on its current
 * state as reported in the connection's CO_FL_CURR_* flags, reports of EAGAIN
 * in CO_FL_WAIT_*, and the data layer expectations indicated by CO_FL_XPRT_*.
 * The connection flags are updated with the new flags at the end of the
 * operation. Polling is totally disabled if an error was reported.
 */
void conn_update_xprt_polling(struct connection *c)
{
	unsigned int f = c->flags;

	if (!conn_ctrl_ready(c))
		return;

	/* update read status if needed */
	if (unlikely((f & (CO_FL_CURR_RD_ENA|CO_FL_XPRT_RD_ENA)) == CO_FL_XPRT_RD_ENA)) {
		fd_want_recv(c->handle.fd);
		f |= CO_FL_CURR_RD_ENA;
	}
	else if (unlikely((f & (CO_FL_CURR_RD_ENA|CO_FL_XPRT_RD_ENA)) == CO_FL_CURR_RD_ENA)) {
		fd_stop_recv(c->handle.fd);
		f &= ~CO_FL_CURR_RD_ENA;
	}

	/* update write status if needed */
	if (unlikely((f & (CO_FL_CURR_WR_ENA|CO_FL_XPRT_WR_ENA)) == CO_FL_XPRT_WR_ENA)) {
		fd_want_send(c->handle.fd);
		f |= CO_FL_CURR_WR_ENA;
	}
	else if (unlikely((f & (CO_FL_CURR_WR_ENA|CO_FL_XPRT_WR_ENA)) == CO_FL_CURR_WR_ENA)) {
		fd_stop_send(c->handle.fd);
		f &= ~CO_FL_CURR_WR_ENA;
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

	if (!conn_ctrl_ready(c))
		return;

	/* update read status if needed */
	if (unlikely((f & (CO_FL_CURR_RD_ENA|CO_FL_SOCK_RD_ENA)) == CO_FL_SOCK_RD_ENA)) {
		fd_want_recv(c->handle.fd);
		f |= CO_FL_CURR_RD_ENA;
	}
	else if (unlikely((f & (CO_FL_CURR_RD_ENA|CO_FL_SOCK_RD_ENA)) == CO_FL_CURR_RD_ENA)) {
		fd_stop_recv(c->handle.fd);
		f &= ~CO_FL_CURR_RD_ENA;
	}

	/* update write status if needed */
	if (unlikely((f & (CO_FL_CURR_WR_ENA|CO_FL_SOCK_WR_ENA)) == CO_FL_SOCK_WR_ENA)) {
		fd_want_send(c->handle.fd);
		f |= CO_FL_CURR_WR_ENA;
	}
	else if (unlikely((f & (CO_FL_CURR_WR_ENA|CO_FL_SOCK_WR_ENA)) == CO_FL_CURR_WR_ENA)) {
		fd_stop_send(c->handle.fd);
		f &= ~CO_FL_CURR_WR_ENA;
	}
	c->flags = f;
}

/* Send a message over an established connection. It makes use of send() and
 * returns the same return code and errno. If the socket layer is not ready yet
 * then -1 is returned and ENOTSOCK is set into errno. If the fd is not marked
 * as ready, or if EAGAIN or ENOTCONN is returned, then we return 0. It returns
 * EMSGSIZE if called with a zero length message. The purpose is to simplify
 * some rare attempts to directly write on the socket from above the connection
 * (typically send_proxy). In case of EAGAIN, the fd is marked as "cant_send".
 * It automatically retries on EINTR. Other errors cause the connection to be
 * marked as in error state. It takes similar arguments as send() except the
 * first one which is the connection instead of the file descriptor. Note,
 * MSG_DONTWAIT and MSG_NOSIGNAL are forced on the flags.
 */
int conn_sock_send(struct connection *conn, const void *buf, int len, int flags)
{
	int ret;

	ret = -1;
	errno = ENOTSOCK;

	if (conn->flags & CO_FL_SOCK_WR_SH)
		goto fail;

	if (!conn_ctrl_ready(conn))
		goto fail;

	errno = EMSGSIZE;
	if (!len)
		goto fail;

	if (!fd_send_ready(conn->handle.fd))
		goto wait;

	do {
		ret = send(conn->handle.fd, buf, len, flags | MSG_DONTWAIT | MSG_NOSIGNAL);
	} while (ret < 0 && errno == EINTR);


	if (ret > 0)
		return ret;

	if (ret == 0 || errno == EAGAIN || errno == ENOTCONN) {
	wait:
		fd_cant_send(conn->handle.fd);
		return 0;
	}
 fail:
	conn->flags |= CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH | CO_FL_ERROR;
	return ret;
}

/* Drains possibly pending incoming data on the file descriptor attached to the
 * connection and update the connection's flags accordingly. This is used to
 * know whether we need to disable lingering on close. Returns non-zero if it
 * is safe to close without disabling lingering, otherwise zero. The SOCK_RD_SH
 * flag may also be updated if the incoming shutdown was reported by the drain()
 * function.
 */
int conn_sock_drain(struct connection *conn)
{
	if (!conn_ctrl_ready(conn))
		return 1;

	if (conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH))
		return 1;

	if (fdtab[conn->handle.fd].ev & (FD_POLL_ERR|FD_POLL_HUP)) {
		fdtab[conn->handle.fd].linger_risk = 0;
	}
	else {
		if (!fd_recv_ready(conn->handle.fd))
			return 0;

		/* disable draining if we were called and have no drain function */
		if (!conn->ctrl->drain) {
			__conn_xprt_stop_recv(conn);
			return 0;
		}

		if (conn->ctrl->drain(conn->handle.fd) <= 0)
			return 0;
	}

	conn->flags |= CO_FL_SOCK_RD_SH;
	return 1;
}

/*
 * Get data length from tlv
 */
static int get_tlv_length(const struct tlv *src)
{
	return (src->length_hi << 8) | src->length_lo;
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
	struct proxy_hdr_v2 *hdr_v2;
	const char v2sig[] = PP2_SIGNATURE;
	int tlv_length = 0;
	int tlv_offset = 0;

	/* we might have been called just after an asynchronous shutr */
	if (conn->flags & CO_FL_SOCK_RD_SH)
		goto fail;

	if (!conn_ctrl_ready(conn))
		goto fail;

	if (!fd_recv_ready(conn->handle.fd))
		return 0;

	do {
		trash.len = recv(conn->handle.fd, trash.str, trash.size, MSG_PEEK);
		if (trash.len < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				fd_cant_recv(conn->handle.fd);
				return 0;
			}
			goto recv_abort;
		}
	} while (0);

	if (!trash.len) {
		/* client shutdown */
		conn->err_code = CO_ER_PRX_EMPTY;
		goto fail;
	}

	if (trash.len < 6)
		goto missing;

	line = trash.str;
	end = trash.str + trash.len;

	/* Decode a possible proxy request, fail early if it does not match */
	if (strncmp(line, "PROXY ", 6) != 0)
		goto not_v1;

	line += 6;
	if (trash.len < 9) /* shortest possible line */
		goto missing;

	if (memcmp(line, "TCP4 ", 5) == 0) {
		u32 src3, dst3, sport, dport;

		line += 5;

		src3 = inetaddr_host_lim_ret(line, end, &line);
		if (line == end)
			goto missing;
		if (*line++ != ' ')
			goto bad_header;

		dst3 = inetaddr_host_lim_ret(line, end, &line);
		if (line == end)
			goto missing;
		if (*line++ != ' ')
			goto bad_header;

		sport = read_uint((const char **)&line, end);
		if (line == end)
			goto missing;
		if (*line++ != ' ')
			goto bad_header;

		dport = read_uint((const char **)&line, end);
		if (line > end - 2)
			goto missing;
		if (*line++ != '\r')
			goto bad_header;
		if (*line++ != '\n')
			goto bad_header;

		/* update the session's addresses and mark them set */
		((struct sockaddr_in *)&conn->addr.from)->sin_family      = AF_INET;
		((struct sockaddr_in *)&conn->addr.from)->sin_addr.s_addr = htonl(src3);
		((struct sockaddr_in *)&conn->addr.from)->sin_port        = htons(sport);

		((struct sockaddr_in *)&conn->addr.to)->sin_family        = AF_INET;
		((struct sockaddr_in *)&conn->addr.to)->sin_addr.s_addr   = htonl(dst3);
		((struct sockaddr_in *)&conn->addr.to)->sin_port          = htons(dport);
		conn->flags |= CO_FL_ADDR_FROM_SET | CO_FL_ADDR_TO_SET;
	}
	else if (memcmp(line, "TCP6 ", 5) == 0) {
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
					goto bad_header;
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
			goto bad_header;

		sport = read_uint((const char **)&sport_s,dport_s - 1);
		if (*sport_s != 0)
			goto bad_header;

		dport = read_uint((const char **)&dport_s,line - 2);
		if (*dport_s != 0)
			goto bad_header;

		if (inet_pton(AF_INET6, src_s, (void *)&src3) != 1)
			goto bad_header;

		if (inet_pton(AF_INET6, dst_s, (void *)&dst3) != 1)
			goto bad_header;

		/* update the session's addresses and mark them set */
		((struct sockaddr_in6 *)&conn->addr.from)->sin6_family      = AF_INET6;
		memcpy(&((struct sockaddr_in6 *)&conn->addr.from)->sin6_addr, &src3, sizeof(struct in6_addr));
		((struct sockaddr_in6 *)&conn->addr.from)->sin6_port        = htons(sport);

		((struct sockaddr_in6 *)&conn->addr.to)->sin6_family        = AF_INET6;
		memcpy(&((struct sockaddr_in6 *)&conn->addr.to)->sin6_addr, &dst3, sizeof(struct in6_addr));
		((struct sockaddr_in6 *)&conn->addr.to)->sin6_port          = htons(dport);
		conn->flags |= CO_FL_ADDR_FROM_SET | CO_FL_ADDR_TO_SET;
	}
	else if (memcmp(line, "UNKNOWN\r\n", 9) == 0) {
		/* This can be a UNIX socket forwarded by an haproxy upstream */
		line += 9;
	}
	else {
		/* The protocol does not match something known (TCP4/TCP6/UNKNOWN) */
		conn->err_code = CO_ER_PRX_BAD_PROTO;
		goto fail;
	}

	trash.len = line - trash.str;
	goto eat_header;

 not_v1:
	/* try PPv2 */
	if (trash.len < PP2_HEADER_LEN)
		goto missing;

	hdr_v2 = (struct proxy_hdr_v2 *)trash.str;

	if (memcmp(hdr_v2->sig, v2sig, PP2_SIGNATURE_LEN) != 0 ||
	    (hdr_v2->ver_cmd & PP2_VERSION_MASK) != PP2_VERSION) {
		conn->err_code = CO_ER_PRX_NOT_HDR;
		goto fail;
	}

	if (trash.len < PP2_HEADER_LEN + ntohs(hdr_v2->len))
		goto missing;

	switch (hdr_v2->ver_cmd & PP2_CMD_MASK) {
	case 0x01: /* PROXY command */
		switch (hdr_v2->fam) {
		case 0x11:  /* TCPv4 */
			if (ntohs(hdr_v2->len) < PP2_ADDR_LEN_INET)
				goto bad_header;

			((struct sockaddr_in *)&conn->addr.from)->sin_family = AF_INET;
			((struct sockaddr_in *)&conn->addr.from)->sin_addr.s_addr = hdr_v2->addr.ip4.src_addr;
			((struct sockaddr_in *)&conn->addr.from)->sin_port = hdr_v2->addr.ip4.src_port;
			((struct sockaddr_in *)&conn->addr.to)->sin_family = AF_INET;
			((struct sockaddr_in *)&conn->addr.to)->sin_addr.s_addr = hdr_v2->addr.ip4.dst_addr;
			((struct sockaddr_in *)&conn->addr.to)->sin_port = hdr_v2->addr.ip4.dst_port;
			conn->flags |= CO_FL_ADDR_FROM_SET | CO_FL_ADDR_TO_SET;
			tlv_offset = PP2_HEADER_LEN + PP2_ADDR_LEN_INET;
			tlv_length = ntohs(hdr_v2->len) - PP2_ADDR_LEN_INET;
			break;
		case 0x21:  /* TCPv6 */
			if (ntohs(hdr_v2->len) < PP2_ADDR_LEN_INET6)
				goto bad_header;

			((struct sockaddr_in6 *)&conn->addr.from)->sin6_family = AF_INET6;
			memcpy(&((struct sockaddr_in6 *)&conn->addr.from)->sin6_addr, hdr_v2->addr.ip6.src_addr, 16);
			((struct sockaddr_in6 *)&conn->addr.from)->sin6_port = hdr_v2->addr.ip6.src_port;
			((struct sockaddr_in6 *)&conn->addr.to)->sin6_family = AF_INET6;
			memcpy(&((struct sockaddr_in6 *)&conn->addr.to)->sin6_addr, hdr_v2->addr.ip6.dst_addr, 16);
			((struct sockaddr_in6 *)&conn->addr.to)->sin6_port = hdr_v2->addr.ip6.dst_port;
			conn->flags |= CO_FL_ADDR_FROM_SET | CO_FL_ADDR_TO_SET;
			tlv_offset = PP2_HEADER_LEN + PP2_ADDR_LEN_INET6;
			tlv_length = ntohs(hdr_v2->len) - PP2_ADDR_LEN_INET6;
			break;
		}

		/* TLV parsing */
		if (tlv_length > 0) {
			while (tlv_offset + TLV_HEADER_SIZE <= trash.len) {
				const struct tlv *tlv_packet = (struct tlv *) &trash.str[tlv_offset];
				const int tlv_len = get_tlv_length(tlv_packet);
				tlv_offset += tlv_len + TLV_HEADER_SIZE;

				switch (tlv_packet->type) {
#ifdef CONFIG_HAP_NS
				case PP2_TYPE_NETNS: {
					const struct netns_entry *ns;
					ns = netns_store_lookup((char*)tlv_packet->value, tlv_len);
					if (ns)
						conn->proxy_netns = ns;
					break;
				}
#endif
				default:
					break;
				}
			}
		}

		/* unsupported protocol, keep local connection address */
		break;
	case 0x00: /* LOCAL command */
		/* keep local connection address for LOCAL */
		break;
	default:
		goto bad_header; /* not a supported command */
	}

	trash.len = PP2_HEADER_LEN + ntohs(hdr_v2->len);
	goto eat_header;

 eat_header:
	/* remove the PROXY line from the request. For this we re-read the
	 * exact line at once. If we don't get the exact same result, we
	 * fail.
	 */
	do {
		int len2 = recv(conn->handle.fd, trash.str, trash.len, 0);
		if (len2 < 0 && errno == EINTR)
			continue;
		if (len2 != trash.len)
			goto recv_abort;
	} while (0);

	conn->flags &= ~flag;
	conn->flags |= CO_FL_RCVD_PROXY;
	return 1;

 missing:
	/* Missing data. Since we're using MSG_PEEK, we can only poll again if
	 * we have not read anything. Otherwise we need to fail because we won't
	 * be able to poll anymore.
	 */
	conn->err_code = CO_ER_PRX_TRUNCATED;
	goto fail;

 bad_header:
	/* This is not a valid proxy protocol header */
	conn->err_code = CO_ER_PRX_BAD_HDR;
	goto fail;

 recv_abort:
	conn->err_code = CO_ER_PRX_ABORT;
	conn->flags |= CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
	goto fail;

 fail:
	__conn_sock_stop_both(conn);
	conn->flags |= CO_FL_ERROR;
	return 0;
}

/* This handshake handler waits a NetScaler Client IP insertion header
 * at the beginning of the raw data stream. The header format is
 * described in doc/netscaler-client-ip-insertion-protocol.txt
 *
 * This line MUST be at the beginning of the buffer and MUST NOT be
 * fragmented.
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
int conn_recv_netscaler_cip(struct connection *conn, int flag)
{
	char *line;
	uint32_t hdr_len;
	uint8_t ip_v;

	/* we might have been called just after an asynchronous shutr */
	if (conn->flags & CO_FL_SOCK_RD_SH)
		goto fail;

	if (!conn_ctrl_ready(conn))
		goto fail;

	if (!fd_recv_ready(conn->handle.fd))
		return 0;

	do {
		trash.len = recv(conn->handle.fd, trash.str, trash.size, MSG_PEEK);
		if (trash.len < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				fd_cant_recv(conn->handle.fd);
				return 0;
			}
			goto recv_abort;
		}
	} while (0);

	if (!trash.len) {
		/* client shutdown */
		conn->err_code = CO_ER_CIP_EMPTY;
		goto fail;
	}

	/* Fail if buffer length is not large enough to contain
	 * CIP magic, header length or
	 * CIP magic, CIP length, CIP type, header length */
	if (trash.len < 12)
		goto missing;

	line = trash.str;

	/* Decode a possible NetScaler Client IP request, fail early if
	 * it does not match */
	if (ntohl(*(uint32_t *)line) != objt_listener(conn->target)->bind_conf->ns_cip_magic)
		goto bad_magic;

	/* Legacy CIP protocol */
	if ((trash.str[8] & 0xD0) == 0x40) {
		hdr_len = ntohl(*(uint32_t *)(line+4));
		line += 8;
	}
	/* Standard CIP protocol */
	else if (trash.str[8] == 0x00) {
		hdr_len = ntohs(*(uint32_t *)(line+10));
		line += 12;
	}
	/* Unknown CIP protocol */
	else {
		conn->err_code = CO_ER_CIP_BAD_PROTO;
		goto fail;
	}

	/* Fail if buffer length is not large enough to contain
	 * a minimal IP header */
	if (trash.len < 20)
		goto missing;

	/* Get IP version from the first four bits */
	ip_v = (*line & 0xf0) >> 4;

	if (ip_v == 4) {
		struct ip *hdr_ip4;
		struct my_tcphdr *hdr_tcp;

		hdr_ip4 = (struct ip *)line;

		if (trash.len < 40 || trash.len < hdr_len) {
			/* Fail if buffer length is not large enough to contain
			 * IPv4 header, TCP header */
			goto missing;
		}
		else if (hdr_ip4->ip_p != IPPROTO_TCP) {
			/* The protocol does not include a TCP header */
			conn->err_code = CO_ER_CIP_BAD_PROTO;
			goto fail;
		}

		hdr_tcp = (struct my_tcphdr *)(line + (hdr_ip4->ip_hl * 4));

		/* update the session's addresses and mark them set */
		((struct sockaddr_in *)&conn->addr.from)->sin_family = AF_INET;
		((struct sockaddr_in *)&conn->addr.from)->sin_addr.s_addr = hdr_ip4->ip_src.s_addr;
		((struct sockaddr_in *)&conn->addr.from)->sin_port = hdr_tcp->source;

		((struct sockaddr_in *)&conn->addr.to)->sin_family = AF_INET;
		((struct sockaddr_in *)&conn->addr.to)->sin_addr.s_addr = hdr_ip4->ip_dst.s_addr;
		((struct sockaddr_in *)&conn->addr.to)->sin_port = hdr_tcp->dest;

		conn->flags |= CO_FL_ADDR_FROM_SET | CO_FL_ADDR_TO_SET;
	}
	else if (ip_v == 6) {
		struct ip6_hdr *hdr_ip6;
		struct my_tcphdr *hdr_tcp;

		hdr_ip6 = (struct ip6_hdr *)line;

		if (trash.len < 60 || trash.len < hdr_len) {
			/* Fail if buffer length is not large enough to contain
			 * IPv6 header, TCP header */
			goto missing;
		}
		else if (hdr_ip6->ip6_nxt != IPPROTO_TCP) {
			/* The protocol does not include a TCP header */
			conn->err_code = CO_ER_CIP_BAD_PROTO;
			goto fail;
		}

		hdr_tcp = (struct my_tcphdr *)(line + sizeof(struct ip6_hdr));

		/* update the session's addresses and mark them set */
		((struct sockaddr_in6 *)&conn->addr.from)->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)&conn->addr.from)->sin6_addr = hdr_ip6->ip6_src;
		((struct sockaddr_in6 *)&conn->addr.from)->sin6_port = hdr_tcp->source;

		((struct sockaddr_in6 *)&conn->addr.to)->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)&conn->addr.to)->sin6_addr = hdr_ip6->ip6_dst;
		((struct sockaddr_in6 *)&conn->addr.to)->sin6_port = hdr_tcp->dest;

		conn->flags |= CO_FL_ADDR_FROM_SET | CO_FL_ADDR_TO_SET;
	}
	else {
		/* The protocol does not match something known (IPv4/IPv6) */
		conn->err_code = CO_ER_CIP_BAD_PROTO;
		goto fail;
	}

	line += hdr_len;
	trash.len = line - trash.str;

	/* remove the NetScaler Client IP header from the request. For this
	 * we re-read the exact line at once. If we don't get the exact same
	 * result, we fail.
	 */
	do {
		int len2 = recv(conn->handle.fd, trash.str, trash.len, 0);
		if (len2 < 0 && errno == EINTR)
			continue;
		if (len2 != trash.len)
			goto recv_abort;
	} while (0);

	conn->flags &= ~flag;
	return 1;

 missing:
	/* Missing data. Since we're using MSG_PEEK, we can only poll again if
	 * we have not read anything. Otherwise we need to fail because we won't
	 * be able to poll anymore.
	 */
	conn->err_code = CO_ER_CIP_TRUNCATED;
	goto fail;

 bad_magic:
	conn->err_code = CO_ER_CIP_BAD_MAGIC;
	goto fail;

 recv_abort:
	conn->err_code = CO_ER_CIP_ABORT;
	conn->flags |= CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
	goto fail;

 fail:
	__conn_sock_stop_both(conn);
	conn->flags |= CO_FL_ERROR;
	return 0;
}

int make_proxy_line(char *buf, int buf_len, struct server *srv, struct connection *remote)
{
	int ret = 0;

	if (srv && (srv->pp_opts & SRV_PP_V2)) {
		ret = make_proxy_line_v2(buf, buf_len, srv, remote);
	}
	else {
		if (remote)
			ret = make_proxy_line_v1(buf, buf_len, &remote->addr.from, &remote->addr.to);
		else
			ret = make_proxy_line_v1(buf, buf_len, NULL, NULL);
	}

	return ret;
}

/* Makes a PROXY protocol line from the two addresses. The output is sent to
 * buffer <buf> for a maximum size of <buf_len> (including the trailing zero).
 * It returns the number of bytes composing this line (including the trailing
 * LF), or zero in case of failure (eg: not enough space). It supports TCP4,
 * TCP6 and "UNKNOWN" formats. If any of <src> or <dst> is null, UNKNOWN is
 * emitted as well.
 */
int make_proxy_line_v1(char *buf, int buf_len, struct sockaddr_storage *src, struct sockaddr_storage *dst)
{
	int ret = 0;

	if (src && dst && src->ss_family == dst->ss_family && src->ss_family == AF_INET) {
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
	else if (src && dst && src->ss_family == dst->ss_family && src->ss_family == AF_INET6) {
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

static int make_tlv(char *dest, int dest_len, char type, uint16_t length, const char *value)
{
	struct tlv *tlv;

	if (!dest || (length + sizeof(*tlv) > dest_len))
		return 0;

	tlv = (struct tlv *)dest;

	tlv->type = type;
	tlv->length_hi = length >> 8;
	tlv->length_lo = length & 0x00ff;
	memcpy(tlv->value, value, length);
	return length + sizeof(*tlv);
}

int make_proxy_line_v2(char *buf, int buf_len, struct server *srv, struct connection *remote)
{
	const char pp2_signature[] = PP2_SIGNATURE;
	int ret = 0;
	struct proxy_hdr_v2 *hdr = (struct proxy_hdr_v2 *)buf;
	struct sockaddr_storage null_addr = { .ss_family = 0 };
	struct sockaddr_storage *src = &null_addr;
	struct sockaddr_storage *dst = &null_addr;
	const char *value;
	int value_len;

	if (buf_len < PP2_HEADER_LEN)
		return 0;
	memcpy(hdr->sig, pp2_signature, PP2_SIGNATURE_LEN);

	if (remote) {
		src = &remote->addr.from;
		dst = &remote->addr.to;
	}

	if (src && dst && src->ss_family == dst->ss_family && src->ss_family == AF_INET) {
		if (buf_len < PP2_HDR_LEN_INET)
			return 0;
		hdr->ver_cmd = PP2_VERSION | PP2_CMD_PROXY;
		hdr->fam = PP2_FAM_INET | PP2_TRANS_STREAM;
		hdr->addr.ip4.src_addr = ((struct sockaddr_in *)src)->sin_addr.s_addr;
		hdr->addr.ip4.dst_addr = ((struct sockaddr_in *)dst)->sin_addr.s_addr;
		hdr->addr.ip4.src_port = ((struct sockaddr_in *)src)->sin_port;
		hdr->addr.ip4.dst_port = ((struct sockaddr_in *)dst)->sin_port;
		ret = PP2_HDR_LEN_INET;
	}
	else if (src && dst && src->ss_family == dst->ss_family && src->ss_family == AF_INET6) {
		if (buf_len < PP2_HDR_LEN_INET6)
			return 0;
		hdr->ver_cmd = PP2_VERSION | PP2_CMD_PROXY;
		hdr->fam = PP2_FAM_INET6 | PP2_TRANS_STREAM;
		memcpy(hdr->addr.ip6.src_addr, &((struct sockaddr_in6 *)src)->sin6_addr, 16);
		memcpy(hdr->addr.ip6.dst_addr, &((struct sockaddr_in6 *)dst)->sin6_addr, 16);
		hdr->addr.ip6.src_port = ((struct sockaddr_in6 *)src)->sin6_port;
		hdr->addr.ip6.dst_port = ((struct sockaddr_in6 *)dst)->sin6_port;
		ret = PP2_HDR_LEN_INET6;
	}
	else {
		if (buf_len < PP2_HDR_LEN_UNSPEC)
			return 0;
		hdr->ver_cmd = PP2_VERSION | PP2_CMD_LOCAL;
		hdr->fam = PP2_FAM_UNSPEC | PP2_TRANS_UNSPEC;
		ret = PP2_HDR_LEN_UNSPEC;
	}

	if (conn_get_alpn(remote, &value, &value_len)) {
		if ((buf_len - ret) < sizeof(struct tlv))
			return 0;
		ret += make_tlv(&buf[ret], (buf_len - ret), PP2_TYPE_ALPN, value_len, value);
	}

#ifdef USE_OPENSSL
	if (srv->pp_opts & SRV_PP_V2_SSL) {
		struct tlv_ssl *tlv;
		int ssl_tlv_len = 0;
		if ((buf_len - ret) < sizeof(struct tlv_ssl))
			return 0;
		tlv = (struct tlv_ssl *)&buf[ret];
		memset(tlv, 0, sizeof(struct tlv_ssl));
		ssl_tlv_len += sizeof(struct tlv_ssl);
		tlv->tlv.type = PP2_TYPE_SSL;
		if (ssl_sock_is_ssl(remote)) {
			tlv->client |= PP2_CLIENT_SSL;
			value = ssl_sock_get_proto_version(remote);
			if (value) {
				ssl_tlv_len += make_tlv(&buf[ret+ssl_tlv_len], (buf_len-ret-ssl_tlv_len), PP2_SUBTYPE_SSL_VERSION, strlen(value), value);
			}
			if (ssl_sock_get_cert_used_sess(remote)) {
				tlv->client |= PP2_CLIENT_CERT_SESS;
				tlv->verify = htonl(ssl_sock_get_verify_result(remote));
				if (ssl_sock_get_cert_used_conn(remote))
					tlv->client |= PP2_CLIENT_CERT_CONN;
			}
			if (srv->pp_opts & SRV_PP_V2_SSL_CN) {
				struct chunk *cn_trash = get_trash_chunk();
				if (ssl_sock_get_remote_common_name(remote, cn_trash) > 0) {
					ssl_tlv_len += make_tlv(&buf[ret+ssl_tlv_len], (buf_len - ret - ssl_tlv_len), PP2_SUBTYPE_SSL_CN, cn_trash->len, cn_trash->str);
				}
			}
		}
		tlv->tlv.length_hi = (uint16_t)(ssl_tlv_len - sizeof(struct tlv)) >> 8;
		tlv->tlv.length_lo = (uint16_t)(ssl_tlv_len - sizeof(struct tlv)) & 0x00ff;
		ret += ssl_tlv_len;
	}
#endif

#ifdef CONFIG_HAP_NS
	if (remote && (remote->proxy_netns)) {
		if ((buf_len - ret) < sizeof(struct tlv))
			return 0;
		ret += make_tlv(&buf[ret], (buf_len - ret), PP2_TYPE_NETNS, remote->proxy_netns->name_len, remote->proxy_netns->node.key);
	}
#endif

	hdr->len = htons((uint16_t)(ret - PP2_HEADER_LEN));

	return ret;
}

/* return the major HTTP version as 1 or 2 depending on how the request arrived
 * before being processed.
 */
static int
smp_fetch_fc_http_major(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn = objt_conn(smp->sess->origin);

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = (conn && strcmp(conn_get_mux_name(conn), "H2") == 0) ? 2 : 1;
	return 1;
}

/* fetch if the received connection used a PROXY protocol header */
int smp_fetch_fc_rcvd_proxy(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	smp->flags = 0;
	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = (conn->flags & CO_FL_RCVD_PROXY) ? 1 : 0;

	return 1;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Note: fetches that may return multiple types must be declared as the lowest
 * common denominator, the type that can be casted into all other ones. For
 * instance v4/v6 must be declared v4.
 */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
	{ "fc_http_major", smp_fetch_fc_http_major, 0, NULL, SMP_T_SINT, SMP_USE_L4CLI },
	{ "fc_rcvd_proxy", smp_fetch_fc_rcvd_proxy, 0, NULL, SMP_T_BOOL, SMP_USE_L4CLI },
	{ /* END */ },
}};


__attribute__((constructor))
static void __connection_init(void)
{
	sample_register_fetches(&sample_fetch_keywords);
}
