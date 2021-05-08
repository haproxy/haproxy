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

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/connection.h>
#include <haproxy/fd.h>
#include <haproxy/frontend.h>
#include <haproxy/hash.h>
#include <haproxy/log-t.h>
#include <haproxy/namespace.h>
#include <haproxy/net_helper.h>
#include <haproxy/proto_tcp.h>
#include <haproxy/sample.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/stream_interface.h>
#include <haproxy/tools.h>


DECLARE_POOL(pool_head_connection,     "connection",     sizeof(struct connection));
DECLARE_POOL(pool_head_connstream,     "conn_stream",    sizeof(struct conn_stream));
DECLARE_POOL(pool_head_conn_hash_node, "conn_hash_node", sizeof(struct conn_hash_node));
DECLARE_POOL(pool_head_sockaddr,       "sockaddr",       sizeof(struct sockaddr_storage));
DECLARE_POOL(pool_head_authority,      "authority",      PP2_AUTHORITY_MAX);

struct idle_conns idle_conns[MAX_THREADS] = { };
struct xprt_ops *registered_xprt[XPRT_ENTRIES] = { NULL, };

/* List head of all known muxes for PROTO */
struct mux_proto_list mux_proto_list = {
        .list = LIST_HEAD_INIT(mux_proto_list.list)
};

struct mux_stopping_data mux_stopping_data[MAX_THREADS];

/* disables sending of proxy-protocol-v2's LOCAL command */
static int pp2_never_send_local;

int conn_create_mux(struct connection *conn)
{
	if (conn_is_back(conn)) {
		struct server *srv;
		struct conn_stream *cs = conn->ctx;
		struct session *sess = conn->owner;

		if (conn->flags & CO_FL_ERROR)
			goto fail;

		if (sess && obj_type(sess->origin) == OBJ_TYPE_CHECK) {
			if (conn_install_mux_chk(conn, conn->ctx, sess) < 0)
				goto fail;
		}
		else if (conn_install_mux_be(conn, conn->ctx, sess) < 0)
			goto fail;
		srv = objt_server(conn->target);

		/* If we're doing http-reuse always, and the connection is not
		 * private with available streams (an http2 connection), add it
		 * to the available list, so that others can use it right
		 * away. If the connection is private, add it in the session
		 * server list.
		 */
		if (srv && ((srv->proxy->options & PR_O_REUSE_MASK) == PR_O_REUSE_ALWS) &&
		    !(conn->flags & CO_FL_PRIVATE) && conn->mux->avail_streams(conn) > 0)
			ebmb_insert(&srv->per_thr[tid].avail_conns, &conn->hash_node->node, sizeof(conn->hash_node->hash));
		else if (conn->flags & CO_FL_PRIVATE) {
			/* If it fail now, the same will be done in mux->detach() callback */
			session_add_conn(sess, conn, conn->target);
		}
		return 0;
fail:
		/* let the upper layer know the connection failed */
		cs->data_cb->wake(cs);
		return -1;
	} else
		return conn_complete_session(conn);

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
 * first one which is the connection instead of the file descriptor. <flags>
 * only support CO_SFL_MSG_MORE.
 */
int conn_ctrl_send(struct connection *conn, const void *buf, int len, int flags)
{
	const struct buffer buffer = b_make((char*)buf, len, 0, len);
	const struct xprt_ops *xprt = xprt_get(XPRT_RAW);
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

	/* snd_buf() already takes care of updating conn->flags and handling
	 * the FD polling status.
	 */
	ret = xprt->snd_buf(conn, NULL, &buffer, buffer.data, flags);
	if (conn->flags & CO_FL_ERROR)
		ret = -1;
	return ret;
 fail:
	conn->flags |= CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH | CO_FL_ERROR;
	return ret;
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The event subscriber <es> is not allowed to change from a previous call as
 * long as at least one event is still subscribed. The <event_type> must only
 * be a combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0.
 */
int conn_unsubscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(conn->subs && conn->subs != es);

	es->events &= ~event_type;
	if (!es->events)
		conn->subs = NULL;

	if (conn_ctrl_ready(conn) && conn->ctrl->ignore_events)
		conn->ctrl->ignore_events(conn, event_type);

	return 0;
}

/* Called from the upper layer, to subscribe <es> to events <event_type>.
 * The <es> struct is not allowed to differ from the one passed during a
 * previous call to subscribe(). If the connection's ctrl layer is ready,
 * the wait_event is immediately woken up and the subcription is cancelled.
 * It always returns zero.
 */
int conn_subscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	int ret = 0;

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(conn->subs && conn->subs != es);

	if (conn->subs && (conn->subs->events & event_type) == event_type)
		return 0;

	if (conn_ctrl_ready(conn) && conn->ctrl->check_events) {
		ret = conn->ctrl->check_events(conn, event_type);
		if (ret)
			tasklet_wakeup(es->tasklet);
	}

	es->events = (es->events | event_type) & ~ret;
	conn->subs = es->events ? es : NULL;
	return 0;
}

/* Drains possibly pending incoming data on the connection and update the flags
 * accordingly. This is used to know whether we need to disable lingering on
 * close. Returns non-zero if it is safe to close without disabling lingering,
 * otherwise zero. The CO_FL_SOCK_RD_SH flag may also be updated if the incoming
 * shutdown was reported by the ->drain() function.
 */
int conn_ctrl_drain(struct connection *conn)
{
	int ret = 0;

	if (!conn_ctrl_ready(conn) || conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH))
		ret = 1;
	else if (conn->ctrl->drain) {
		ret = conn->ctrl->drain(conn);
		if (ret)
			conn->flags |= CO_FL_SOCK_RD_SH;
	}
	return ret;
}

/*
 * Get data length from tlv
 */
static inline size_t get_tlv_length(const struct tlv *src)
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
	size_t total_v2_len;
	size_t tlv_offset = 0;
	int ret;

	if (!conn_ctrl_ready(conn))
		goto fail;

	if (!sockaddr_alloc(&conn->src, NULL, 0) || !sockaddr_alloc(&conn->dst, NULL, 0))
		goto fail;

	if (!fd_recv_ready(conn->handle.fd))
		goto not_ready;

	while (1) {
		ret = recv(conn->handle.fd, trash.area, trash.size, MSG_PEEK);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				fd_cant_recv(conn->handle.fd);
				goto not_ready;
			}
			goto recv_abort;
		}
		trash.data = ret;
		break;
	}

	if (!trash.data) {
		/* client shutdown */
		conn->err_code = CO_ER_PRX_EMPTY;
		goto fail;
	}

	conn->flags &= ~CO_FL_WAIT_L4_CONN;

	if (trash.data < 6)
		goto missing;

	line = trash.area;
	end = trash.area + trash.data;

	/* Decode a possible proxy request, fail early if it does not match */
	if (strncmp(line, "PROXY ", 6) != 0)
		goto not_v1;

	line += 6;
	if (trash.data < 9) /* shortest possible line */
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
		((struct sockaddr_in *)conn->src)->sin_family      = AF_INET;
		((struct sockaddr_in *)conn->src)->sin_addr.s_addr = htonl(src3);
		((struct sockaddr_in *)conn->src)->sin_port        = htons(sport);

		((struct sockaddr_in *)conn->dst)->sin_family        = AF_INET;
		((struct sockaddr_in *)conn->dst)->sin_addr.s_addr   = htonl(dst3);
		((struct sockaddr_in *)conn->dst)->sin_port          = htons(dport);
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
		((struct sockaddr_in6 *)conn->src)->sin6_family      = AF_INET6;
		memcpy(&((struct sockaddr_in6 *)conn->src)->sin6_addr, &src3, sizeof(struct in6_addr));
		((struct sockaddr_in6 *)conn->src)->sin6_port        = htons(sport);

		((struct sockaddr_in6 *)conn->dst)->sin6_family        = AF_INET6;
		memcpy(&((struct sockaddr_in6 *)conn->dst)->sin6_addr, &dst3, sizeof(struct in6_addr));
		((struct sockaddr_in6 *)conn->dst)->sin6_port          = htons(dport);
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

	trash.data = line - trash.area;
	goto eat_header;

 not_v1:
	/* try PPv2 */
	if (trash.data < PP2_HEADER_LEN)
		goto missing;

	hdr_v2 = (struct proxy_hdr_v2 *) trash.area;

	if (memcmp(hdr_v2->sig, v2sig, PP2_SIGNATURE_LEN) != 0 ||
	    (hdr_v2->ver_cmd & PP2_VERSION_MASK) != PP2_VERSION) {
		conn->err_code = CO_ER_PRX_NOT_HDR;
		goto fail;
	}

	total_v2_len = PP2_HEADER_LEN + ntohs(hdr_v2->len);
	if (trash.data < total_v2_len)
		goto missing;

	switch (hdr_v2->ver_cmd & PP2_CMD_MASK) {
	case 0x01: /* PROXY command */
		switch (hdr_v2->fam) {
		case 0x11:  /* TCPv4 */
			if (ntohs(hdr_v2->len) < PP2_ADDR_LEN_INET)
				goto bad_header;

			((struct sockaddr_in *)conn->src)->sin_family = AF_INET;
			((struct sockaddr_in *)conn->src)->sin_addr.s_addr = hdr_v2->addr.ip4.src_addr;
			((struct sockaddr_in *)conn->src)->sin_port = hdr_v2->addr.ip4.src_port;
			((struct sockaddr_in *)conn->dst)->sin_family = AF_INET;
			((struct sockaddr_in *)conn->dst)->sin_addr.s_addr = hdr_v2->addr.ip4.dst_addr;
			((struct sockaddr_in *)conn->dst)->sin_port = hdr_v2->addr.ip4.dst_port;
			conn->flags |= CO_FL_ADDR_FROM_SET | CO_FL_ADDR_TO_SET;
			tlv_offset = PP2_HEADER_LEN + PP2_ADDR_LEN_INET;
			break;
		case 0x21:  /* TCPv6 */
			if (ntohs(hdr_v2->len) < PP2_ADDR_LEN_INET6)
				goto bad_header;

			((struct sockaddr_in6 *)conn->src)->sin6_family = AF_INET6;
			memcpy(&((struct sockaddr_in6 *)conn->src)->sin6_addr, hdr_v2->addr.ip6.src_addr, 16);
			((struct sockaddr_in6 *)conn->src)->sin6_port = hdr_v2->addr.ip6.src_port;
			((struct sockaddr_in6 *)conn->dst)->sin6_family = AF_INET6;
			memcpy(&((struct sockaddr_in6 *)conn->dst)->sin6_addr, hdr_v2->addr.ip6.dst_addr, 16);
			((struct sockaddr_in6 *)conn->dst)->sin6_port = hdr_v2->addr.ip6.dst_port;
			conn->flags |= CO_FL_ADDR_FROM_SET | CO_FL_ADDR_TO_SET;
			tlv_offset = PP2_HEADER_LEN + PP2_ADDR_LEN_INET6;
			break;
		}

		/* TLV parsing */
		while (tlv_offset < total_v2_len) {
			struct tlv *tlv_packet;
			struct ist tlv;

			/* Verify that we have at least TLV_HEADER_SIZE bytes left */
			if (tlv_offset + TLV_HEADER_SIZE > total_v2_len)
				goto bad_header;

			tlv_packet = (struct tlv *) &trash.area[tlv_offset];
			tlv = ist2((const char *)tlv_packet->value, get_tlv_length(tlv_packet));
			tlv_offset += istlen(tlv) + TLV_HEADER_SIZE;

			/* Verify that the TLV length does not exceed the total PROXYv2 length */
			if (tlv_offset > total_v2_len)
				goto bad_header;

			switch (tlv_packet->type) {
			case PP2_TYPE_CRC32C: {
				uint32_t n_crc32c;

				/* Verify that this TLV is exactly 4 bytes long */
				if (istlen(tlv) != 4)
					goto bad_header;

				n_crc32c = read_n32(istptr(tlv));
				write_n32(istptr(tlv), 0); // compute with CRC==0

				if (hash_crc32c(trash.area, total_v2_len) != n_crc32c)
					goto bad_header;
				break;
			}
#ifdef USE_NS
			case PP2_TYPE_NETNS: {
				const struct netns_entry *ns;

				ns = netns_store_lookup(istptr(tlv), istlen(tlv));
				if (ns)
					conn->proxy_netns = ns;
				break;
			}
#endif
			case PP2_TYPE_AUTHORITY: {
				if (istlen(tlv) > PP2_AUTHORITY_MAX)
					goto bad_header;
				conn->proxy_authority = ist2(pool_alloc(pool_head_authority), 0);
				if (!isttest(conn->proxy_authority))
					goto fail;
				if (istcpy(&conn->proxy_authority, tlv, PP2_AUTHORITY_MAX) < 0) {
					/* This is technically unreachable, because we verified above
					 * that the TLV value fits.
					 */
					goto fail;
				}
				break;
			}
			case PP2_TYPE_UNIQUE_ID: {
				if (istlen(tlv) > UNIQUEID_LEN)
					goto bad_header;
				conn->proxy_unique_id = ist2(pool_alloc(pool_head_uniqueid), 0);
				if (!isttest(conn->proxy_unique_id))
					goto fail;
				if (istcpy(&conn->proxy_unique_id, tlv, UNIQUEID_LEN) < 0) {
					/* This is technically unreachable, because we verified above
					 * that the TLV value fits.
					 */
					goto fail;
				}
				break;
			}
			default:
				break;
			}
		}

		/* Verify that the PROXYv2 header ends at a TLV boundary.
		 * This is technically unreachable, because the TLV parsing already
		 * verifies that a TLV does not exceed the total length and also
		 * that there is space for a TLV header.
		 */
		if (tlv_offset != total_v2_len)
			goto bad_header;

		/* unsupported protocol, keep local connection address */
		break;
	case 0x00: /* LOCAL command */
		/* keep local connection address for LOCAL */
		break;
	default:
		goto bad_header; /* not a supported command */
	}

	trash.data = total_v2_len;
	goto eat_header;

 eat_header:
	/* remove the PROXY line from the request. For this we re-read the
	 * exact line at once. If we don't get the exact same result, we
	 * fail.
	 */
	while (1) {
		ssize_t len2 = recv(conn->handle.fd, trash.area, trash.data, 0);

		if (len2 < 0 && errno == EINTR)
			continue;
		if (len2 != trash.data)
			goto recv_abort;
		break;
	}

	conn->flags &= ~flag;
	conn->flags |= CO_FL_RCVD_PROXY;
	return 1;

 not_ready:
	return 0;

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
	uint8_t ip_ver;
	int ret;

	if (!conn_ctrl_ready(conn))
		goto fail;

	if (!sockaddr_alloc(&conn->src, NULL, 0) || !sockaddr_alloc(&conn->dst, NULL, 0))
		goto fail;

	if (!fd_recv_ready(conn->handle.fd))
		goto not_ready;

	while (1) {
		ret = recv(conn->handle.fd, trash.area, trash.size, MSG_PEEK);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				fd_cant_recv(conn->handle.fd);
				goto not_ready;
			}
			goto recv_abort;
		}
		trash.data = ret;
		break;
	}

	conn->flags &= ~CO_FL_WAIT_L4_CONN;

	if (!trash.data) {
		/* client shutdown */
		conn->err_code = CO_ER_CIP_EMPTY;
		goto fail;
	}

	/* Fail if buffer length is not large enough to contain
	 * CIP magic, header length or
	 * CIP magic, CIP length, CIP type, header length */
	if (trash.data < 12)
		goto missing;

	line = trash.area;

	/* Decode a possible NetScaler Client IP request, fail early if
	 * it does not match */
	if (ntohl(read_u32(line)) != __objt_listener(conn->target)->bind_conf->ns_cip_magic)
		goto bad_magic;

	/* Legacy CIP protocol */
	if ((trash.area[8] & 0xD0) == 0x40) {
		hdr_len = ntohl(read_u32((line+4)));
		line += 8;
	}
	/* Standard CIP protocol */
	else if (trash.area[8] == 0x00) {
		hdr_len = ntohs(read_u32((line+10)));
		line += 12;
	}
	/* Unknown CIP protocol */
	else {
		conn->err_code = CO_ER_CIP_BAD_PROTO;
		goto fail;
	}

	/* Fail if buffer length is not large enough to contain
	 * a minimal IP header */
	if (trash.data < 20)
		goto missing;

	/* Get IP version from the first four bits */
	ip_ver = (*line & 0xf0) >> 4;

	if (ip_ver == 4) {
		struct ip *hdr_ip4;
		struct my_tcphdr *hdr_tcp;

		hdr_ip4 = (struct ip *)line;

		if (trash.data < 40 || trash.data < hdr_len) {
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
		((struct sockaddr_in *)conn->src)->sin_family = AF_INET;
		((struct sockaddr_in *)conn->src)->sin_addr.s_addr = hdr_ip4->ip_src.s_addr;
		((struct sockaddr_in *)conn->src)->sin_port = hdr_tcp->source;

		((struct sockaddr_in *)conn->dst)->sin_family = AF_INET;
		((struct sockaddr_in *)conn->dst)->sin_addr.s_addr = hdr_ip4->ip_dst.s_addr;
		((struct sockaddr_in *)conn->dst)->sin_port = hdr_tcp->dest;

		conn->flags |= CO_FL_ADDR_FROM_SET | CO_FL_ADDR_TO_SET;
	}
	else if (ip_ver == 6) {
		struct ip6_hdr *hdr_ip6;
		struct my_tcphdr *hdr_tcp;

		hdr_ip6 = (struct ip6_hdr *)line;

		if (trash.data < 60 || trash.data < hdr_len) {
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
		((struct sockaddr_in6 *)conn->src)->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)conn->src)->sin6_addr = hdr_ip6->ip6_src;
		((struct sockaddr_in6 *)conn->src)->sin6_port = hdr_tcp->source;

		((struct sockaddr_in6 *)conn->dst)->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)conn->dst)->sin6_addr = hdr_ip6->ip6_dst;
		((struct sockaddr_in6 *)conn->dst)->sin6_port = hdr_tcp->dest;

		conn->flags |= CO_FL_ADDR_FROM_SET | CO_FL_ADDR_TO_SET;
	}
	else {
		/* The protocol does not match something known (IPv4/IPv6) */
		conn->err_code = CO_ER_CIP_BAD_PROTO;
		goto fail;
	}

	line += hdr_len;
	trash.data = line - trash.area;

	/* remove the NetScaler Client IP header from the request. For this
	 * we re-read the exact line at once. If we don't get the exact same
	 * result, we fail.
	 */
	while (1) {
		int len2 = recv(conn->handle.fd, trash.area, trash.data, 0);
		if (len2 < 0 && errno == EINTR)
			continue;
		if (len2 != trash.data)
			goto recv_abort;
		break;
	}

	conn->flags &= ~flag;
	return 1;

 not_ready:
	return 0;

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
	conn->flags |= CO_FL_ERROR;
	return 0;
}


int conn_send_socks4_proxy_request(struct connection *conn)
{
	struct socks4_request req_line;

	if (!conn_ctrl_ready(conn))
		goto out_error;

	if (!conn_get_dst(conn))
		goto out_error;

	req_line.version = 0x04;
	req_line.command = 0x01;
	req_line.port    = get_net_port(conn->dst);
	req_line.ip      = is_inet_addr(conn->dst);
	memcpy(req_line.user_id, "HAProxy\0", 8);

	if (conn->send_proxy_ofs > 0) {
		/*
		 * This is the first call to send the request
		 */
		conn->send_proxy_ofs = -(int)sizeof(req_line);
	}

	if (conn->send_proxy_ofs < 0) {
		int ret = 0;

		/* we are sending the socks4_req_line here. If the data layer
		 * has a pending write, we'll also set MSG_MORE.
		 */
		ret = conn_ctrl_send(
				conn,
				((char *)(&req_line)) + (sizeof(req_line)+conn->send_proxy_ofs),
				-conn->send_proxy_ofs,
				(conn->subs && conn->subs->events & SUB_RETRY_SEND) ? CO_SFL_MSG_MORE : 0);

		DPRINTF(stderr, "SOCKS PROXY HS FD[%04X]: Before send remain is [%d], sent [%d]\n",
				conn->handle.fd, -conn->send_proxy_ofs, ret);

		if (ret < 0) {
			goto out_error;
		}

		conn->send_proxy_ofs += ret; /* becomes zero once complete */
		if (conn->send_proxy_ofs != 0) {
			goto out_wait;
		}
	}

	/* OK we've the whole request sent */
	conn->flags &= ~CO_FL_SOCKS4_SEND;

	/* The connection is ready now, simply return and let the connection
	 * handler notify upper layers if needed.
	 */
	conn->flags &= ~CO_FL_WAIT_L4_CONN;

	if (conn->flags & CO_FL_SEND_PROXY) {
		/*
		 * Get the send_proxy_ofs ready for the send_proxy due to we are
		 * reusing the "send_proxy_ofs", and SOCKS4 handshake should be done
		 * before sending PROXY Protocol.
		 */
		conn->send_proxy_ofs = 1;
	}
	return 1;

 out_error:
	/* Write error on the file descriptor */
	conn->flags |= CO_FL_ERROR;
	if (conn->err_code == CO_ER_NONE) {
		conn->err_code = CO_ER_SOCKS4_SEND;
	}
	return 0;

 out_wait:
	return 0;
}

int conn_recv_socks4_proxy_response(struct connection *conn)
{
	char line[SOCKS4_HS_RSP_LEN];
	int ret;

	if (!conn_ctrl_ready(conn))
		goto fail;

	if (!fd_recv_ready(conn->handle.fd))
		goto not_ready;

	while (1) {
		/* SOCKS4 Proxy will response with 8 bytes, 0x00 | 0x5A | 0x00 0x00 | 0x00 0x00 0x00 0x00
		 * Try to peek into it, before all 8 bytes ready.
		 */
		ret = recv(conn->handle.fd, line, SOCKS4_HS_RSP_LEN, MSG_PEEK);

		if (ret == 0) {
			/* the socket has been closed or shutdown for send */
			DPRINTF(stderr, "SOCKS PROXY HS FD[%04X]: Received ret[%d], errno[%d], looks like the socket has been closed or shutdown for send\n",
					conn->handle.fd, ret, errno);
			if (conn->err_code == CO_ER_NONE) {
				conn->err_code = CO_ER_SOCKS4_RECV;
			}
			goto fail;
		}

		if (ret > 0) {
			if (ret == SOCKS4_HS_RSP_LEN) {
				DPRINTF(stderr, "SOCKS PROXY HS FD[%04X]: Received 8 bytes, the response is [%02X|%02X|%02X %02X|%02X %02X %02X %02X]\n",
						conn->handle.fd, line[0], line[1], line[2], line[3], line[4], line[5], line[6], line[7]);
			}else{
				DPRINTF(stderr, "SOCKS PROXY HS FD[%04X]: Received ret[%d], first byte is [%02X], last bye is [%02X]\n", conn->handle.fd, ret, line[0], line[ret-1]);
			}
		} else {
			DPRINTF(stderr, "SOCKS PROXY HS FD[%04X]: Received ret[%d], errno[%d]\n", conn->handle.fd, ret, errno);
		}

		if (ret < 0) {
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN) {
				fd_cant_recv(conn->handle.fd);
				goto not_ready;
			}
			goto recv_abort;
		}
		break;
	}

	conn->flags &= ~CO_FL_WAIT_L4_CONN;

	if (ret < SOCKS4_HS_RSP_LEN) {
		/* Missing data. Since we're using MSG_PEEK, we can only poll again if
		 * we are not able to read enough data.
		 */
		goto not_ready;
	}

	/*
	 * Base on the SOCSK4 protocol:
	 *
	 *			+----+----+----+----+----+----+----+----+
	 *			| VN | CD | DSTPORT |      DSTIP        |
	 *			+----+----+----+----+----+----+----+----+
	 *	# of bytes:	   1    1      2              4
	 *	VN is the version of the reply code and should be 0. CD is the result
	 *	code with one of the following values:
	 *	90: request granted
	 *	91: request rejected or failed
	 *	92: request rejected because SOCKS server cannot connect to identd on the client
	 *	93: request rejected because the client program and identd report different user-ids
	 *	The remaining fields are ignored.
	 */
	if (line[1] != 90) {
		conn->flags &= ~CO_FL_SOCKS4_RECV;

		DPRINTF(stderr, "SOCKS PROXY HS FD[%04X]: FAIL, the response is [%02X|%02X|%02X %02X|%02X %02X %02X %02X]\n",
				conn->handle.fd, line[0], line[1], line[2], line[3], line[4], line[5], line[6], line[7]);
		if (conn->err_code == CO_ER_NONE) {
			conn->err_code = CO_ER_SOCKS4_DENY;
		}
		goto fail;
	}

	/* remove the 8 bytes response from the stream */
	while (1) {
		ret = recv(conn->handle.fd, line, SOCKS4_HS_RSP_LEN, 0);
		if (ret < 0 && errno == EINTR) {
			continue;
		}
		if (ret != SOCKS4_HS_RSP_LEN) {
			if (conn->err_code == CO_ER_NONE) {
				conn->err_code = CO_ER_SOCKS4_RECV;
			}
			goto fail;
		}
		break;
	}

	conn->flags &= ~CO_FL_SOCKS4_RECV;
	return 1;

 not_ready:
	return 0;

 recv_abort:
	if (conn->err_code == CO_ER_NONE) {
		conn->err_code = CO_ER_SOCKS4_ABORT;
	}
	conn->flags |= (CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH);
	goto fail;

 fail:
	conn->flags |= CO_FL_ERROR;
	return 0;
}

/* Lists the known proto mux on <out> */
void list_mux_proto(FILE *out)
{
	struct mux_proto_list *item;
	struct buffer *chk = get_trash_chunk();
	struct ist proto;
	char *mode, *side;

	fprintf(out, "Available multiplexer protocols :\n"
		"(protocols marked as <default> cannot be specified using 'proto' keyword)\n");
	list_for_each_entry(item, &mux_proto_list.list, list) {
		proto = item->token;

		if (item->mode == PROTO_MODE_ANY)
			mode = "TCP|HTTP";
		else if (item->mode == PROTO_MODE_TCP)
			mode = "TCP";
		else if (item->mode == PROTO_MODE_HTTP)
			mode = "HTTP";
		else
			mode = "NONE";

		if (item->side == PROTO_SIDE_BOTH)
			side = "FE|BE";
		else if (item->side == PROTO_SIDE_FE)
			side = "FE";
		else if (item->side == PROTO_SIDE_BE)
			side = "BE";
		else
			side = "NONE";

		chunk_reset(chk);
		if (item->mux->flags & MX_FL_HTX)
			chunk_strcpy(chk, "HTX");
		if (item->mux->flags & MX_FL_CLEAN_ABRT)
			chunk_appendf(chk, "%sCLEAN_ABRT", (b_data(chk) ? "|": ""));
		if (item->mux->flags & MX_FL_HOL_RISK)
			chunk_appendf(chk, "%sHOL_RISK", (b_data(chk) ? "|": ""));
		if (item->mux->flags & MX_FL_NO_UPG)
			chunk_appendf(chk, "%sNO_UPG", (b_data(chk) ? "|": ""));

		fprintf(out, " %15s : mode=%-10s side=%-8s  mux=%-8s flags=%.*s\n",
			(proto.len ? proto.ptr : "<default>"), mode, side, item->mux->name,
			(int)b_data(chk), b_orig(chk));
	}
}

/* Note: <remote> is explicitly allowed to be NULL */
int make_proxy_line(char *buf, int buf_len, struct server *srv, struct connection *remote, struct stream *strm)
{
	int ret = 0;

	if (srv && (srv->pp_opts & SRV_PP_V2)) {
		ret = make_proxy_line_v2(buf, buf_len, srv, remote, strm);
	}
	else {
		if (remote && conn_get_src(remote) && conn_get_dst(remote))
			ret = make_proxy_line_v1(buf, buf_len, remote->src, remote->dst);
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
	char * protocol;
	char src_str[MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];
	char dst_str[MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];
	in_port_t src_port;
	in_port_t dst_port;

	if (   !src
	    || !dst
	    || (src->ss_family != AF_INET && src->ss_family != AF_INET6)
	    || (dst->ss_family != AF_INET && dst->ss_family != AF_INET6)) {
		/* unknown family combination */
		ret = snprintf(buf, buf_len, "PROXY UNKNOWN\r\n");
		if (ret >= buf_len)
			return 0;

		return ret;
	}

	/* IPv4 for both src and dst */
	if (src->ss_family == AF_INET && dst->ss_family == AF_INET) {
		protocol = "TCP4";
		if (!inet_ntop(AF_INET, &((struct sockaddr_in *)src)->sin_addr, src_str, sizeof(src_str)))
			return 0;
		src_port = ((struct sockaddr_in *)src)->sin_port;
		if (!inet_ntop(AF_INET, &((struct sockaddr_in *)dst)->sin_addr, dst_str, sizeof(dst_str)))
			return 0;
		dst_port = ((struct sockaddr_in *)dst)->sin_port;
	}
	/* IPv6 for at least one of src and dst */
	else {
		struct in6_addr tmp;

		protocol = "TCP6";

		if (src->ss_family == AF_INET) {
			/* Convert src to IPv6 */
			v4tov6(&tmp, &((struct sockaddr_in *)src)->sin_addr);
			src_port = ((struct sockaddr_in *)src)->sin_port;
		}
		else {
			tmp = ((struct sockaddr_in6 *)src)->sin6_addr;
			src_port = ((struct sockaddr_in6 *)src)->sin6_port;
		}

		if (!inet_ntop(AF_INET6, &tmp, src_str, sizeof(src_str)))
			return 0;

		if (dst->ss_family == AF_INET) {
			/* Convert dst to IPv6 */
			v4tov6(&tmp, &((struct sockaddr_in *)dst)->sin_addr);
			dst_port = ((struct sockaddr_in *)dst)->sin_port;
		}
		else {
			tmp = ((struct sockaddr_in6 *)dst)->sin6_addr;
			dst_port = ((struct sockaddr_in6 *)dst)->sin6_port;
		}

		if (!inet_ntop(AF_INET6, &tmp, dst_str, sizeof(dst_str)))
			return 0;
	}

	ret = snprintf(buf, buf_len, "PROXY %s %s %s %u %u\r\n", protocol, src_str, dst_str, ntohs(src_port), ntohs(dst_port));
	if (ret >= buf_len)
		return 0;

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

/* Note: <remote> is explicitly allowed to be NULL */
int make_proxy_line_v2(char *buf, int buf_len, struct server *srv, struct connection *remote, struct stream *strm)
{
	const char pp2_signature[] = PP2_SIGNATURE;
	void *tlv_crc32c_p = NULL;
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

	if (remote && conn_get_src(remote) && conn_get_dst(remote)) {
		src = remote->src;
		dst = remote->dst;
	}

	/* At least one of src or dst is not of AF_INET or AF_INET6 */
	if (  !src
	   || !dst
	   || (!pp2_never_send_local && conn_is_back(remote)) // locally initiated connection
	   || (src->ss_family != AF_INET && src->ss_family != AF_INET6)
	   || (dst->ss_family != AF_INET && dst->ss_family != AF_INET6)) {
		if (buf_len < PP2_HDR_LEN_UNSPEC)
			return 0;
		hdr->ver_cmd = PP2_VERSION | PP2_CMD_LOCAL;
		hdr->fam = PP2_FAM_UNSPEC | PP2_TRANS_UNSPEC;
		ret = PP2_HDR_LEN_UNSPEC;
	}
	else {
		hdr->ver_cmd = PP2_VERSION | PP2_CMD_PROXY;
		/* IPv4 for both src and dst */
		if (src->ss_family == AF_INET && dst->ss_family == AF_INET) {
			if (buf_len < PP2_HDR_LEN_INET)
				return 0;
			hdr->fam = PP2_FAM_INET | PP2_TRANS_STREAM;
			hdr->addr.ip4.src_addr = ((struct sockaddr_in *)src)->sin_addr.s_addr;
			hdr->addr.ip4.src_port = ((struct sockaddr_in *)src)->sin_port;
			hdr->addr.ip4.dst_addr = ((struct sockaddr_in *)dst)->sin_addr.s_addr;
			hdr->addr.ip4.dst_port = ((struct sockaddr_in *)dst)->sin_port;
			ret = PP2_HDR_LEN_INET;
		}
		/* IPv6 for at least one of src and dst */
		else {
			struct in6_addr tmp;

			if (buf_len < PP2_HDR_LEN_INET6)
				return 0;
			hdr->fam = PP2_FAM_INET6 | PP2_TRANS_STREAM;
			if (src->ss_family == AF_INET) {
				v4tov6(&tmp, &((struct sockaddr_in *)src)->sin_addr);
				memcpy(hdr->addr.ip6.src_addr, &tmp, 16);
				hdr->addr.ip6.src_port = ((struct sockaddr_in *)src)->sin_port;
			}
			else {
				memcpy(hdr->addr.ip6.src_addr, &((struct sockaddr_in6 *)src)->sin6_addr, 16);
				hdr->addr.ip6.src_port = ((struct sockaddr_in6 *)src)->sin6_port;
			}
			if (dst->ss_family == AF_INET) {
				v4tov6(&tmp, &((struct sockaddr_in *)dst)->sin_addr);
				memcpy(hdr->addr.ip6.dst_addr, &tmp, 16);
				hdr->addr.ip6.dst_port = ((struct sockaddr_in *)dst)->sin_port;
			}
			else {
				memcpy(hdr->addr.ip6.dst_addr, &((struct sockaddr_in6 *)dst)->sin6_addr, 16);
				hdr->addr.ip6.dst_port = ((struct sockaddr_in6 *)dst)->sin6_port;
			}

			ret = PP2_HDR_LEN_INET6;
		}
	}

	if (srv->pp_opts & SRV_PP_V2_CRC32C) {
		uint32_t zero_crc32c = 0;

		if ((buf_len - ret) < sizeof(struct tlv))
			return 0;
		tlv_crc32c_p = (void *)((struct tlv *)&buf[ret])->value;
		ret += make_tlv(&buf[ret], (buf_len - ret), PP2_TYPE_CRC32C, sizeof(zero_crc32c), (const char *)&zero_crc32c);
	}

	if (remote && conn_get_alpn(remote, &value, &value_len)) {
		if ((buf_len - ret) < sizeof(struct tlv))
			return 0;
		ret += make_tlv(&buf[ret], (buf_len - ret), PP2_TYPE_ALPN, value_len, value);
	}

	if (srv->pp_opts & SRV_PP_V2_AUTHORITY) {
		value = NULL;
		if (remote && isttest(remote->proxy_authority)) {
			value = istptr(remote->proxy_authority);
			value_len = istlen(remote->proxy_authority);
		}
#ifdef USE_OPENSSL
		else {
			if ((value = ssl_sock_get_sni(remote)))
				value_len = strlen(value);
		}
#endif
		if (value) {
			if ((buf_len - ret) < sizeof(struct tlv))
				return 0;
			ret += make_tlv(&buf[ret], (buf_len - ret), PP2_TYPE_AUTHORITY, value_len, value);
		}
	}

	if (strm && (srv->pp_opts & SRV_PP_V2_UNIQUE_ID)) {
		struct session* sess = strm_sess(strm);
		struct ist unique_id = stream_generate_unique_id(strm, &sess->fe->format_unique_id);

		value = unique_id.ptr;
		value_len = unique_id.len;

		if (value_len >= 0) {
			if ((buf_len - ret) < sizeof(struct tlv))
				return 0;
			ret += make_tlv(&buf[ret], (buf_len - ret), PP2_TYPE_UNIQUE_ID, value_len, value);
		}
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
				struct buffer *cn_trash = get_trash_chunk();
				if (ssl_sock_get_remote_common_name(remote, cn_trash) > 0) {
					ssl_tlv_len += make_tlv(&buf[ret+ssl_tlv_len], (buf_len - ret - ssl_tlv_len), PP2_SUBTYPE_SSL_CN,
								cn_trash->data,
								cn_trash->area);
				}
			}
			if (srv->pp_opts & SRV_PP_V2_SSL_KEY_ALG) {
				struct buffer *pkey_trash = get_trash_chunk();
				if (ssl_sock_get_pkey_algo(remote, pkey_trash) > 0) {
					ssl_tlv_len += make_tlv(&buf[ret+ssl_tlv_len], (buf_len - ret - ssl_tlv_len), PP2_SUBTYPE_SSL_KEY_ALG,
								pkey_trash->data,
								pkey_trash->area);
				}
			}
			if (srv->pp_opts & SRV_PP_V2_SSL_SIG_ALG) {
				value = ssl_sock_get_cert_sig(remote);
				if (value) {
					ssl_tlv_len += make_tlv(&buf[ret+ssl_tlv_len], (buf_len - ret - ssl_tlv_len), PP2_SUBTYPE_SSL_SIG_ALG, strlen(value), value);
				}
			}
			if (srv->pp_opts & SRV_PP_V2_SSL_CIPHER) {
				value = ssl_sock_get_cipher_name(remote);
				if (value) {
					ssl_tlv_len += make_tlv(&buf[ret+ssl_tlv_len], (buf_len - ret - ssl_tlv_len), PP2_SUBTYPE_SSL_CIPHER, strlen(value), value);
				}
			}
		}
		tlv->tlv.length_hi = (uint16_t)(ssl_tlv_len - sizeof(struct tlv)) >> 8;
		tlv->tlv.length_lo = (uint16_t)(ssl_tlv_len - sizeof(struct tlv)) & 0x00ff;
		ret += ssl_tlv_len;
	}
#endif

#ifdef USE_NS
	if (remote && (remote->proxy_netns)) {
		if ((buf_len - ret) < sizeof(struct tlv))
			return 0;
		ret += make_tlv(&buf[ret], (buf_len - ret), PP2_TYPE_NETNS, remote->proxy_netns->name_len, remote->proxy_netns->node.key);
	}
#endif

	hdr->len = htons((uint16_t)(ret - PP2_HEADER_LEN));

	if (tlv_crc32c_p) {
		write_u32(tlv_crc32c_p, htonl(hash_crc32c(buf, ret)));
	}

	return ret;
}

/* returns 0 on success */
static int cfg_parse_pp2_never_send_local(char **args, int section_type, struct proxy *curpx,
                                          const struct proxy *defpx, const char *file, int line,
                                          char **err)
{
	if (too_many_args(0, args, err, NULL))
		return -1;
	pp2_never_send_local = 1;
	return 0;
}

/* return the major HTTP version as 1 or 2 depending on how the request arrived
 * before being processed.
 *
 * WARNING: Should be updated if a new major HTTP version is added.
 */
static int
smp_fetch_fc_http_major(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn = NULL;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
                conn = (kw[0] == 'b') ? cs_conn(__objt_check(smp->sess->origin)->cs) : NULL;
        else
                conn = (kw[0] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	/* No connection or a connection with a RAW muxx */
	if (!conn || (conn->mux && !(conn->mux->flags & MX_FL_HTX)))
		return 0;

	/* No mux install, this may change */
	if (!conn->mux) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = (strcmp(conn_get_mux_name(conn), "H2") == 0) ? 2 : 1;
	return 1;
}

/* fetch if the received connection used a PROXY protocol header */
int smp_fetch_fc_rcvd_proxy(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	smp->flags = 0;
	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = (conn->flags & CO_FL_RCVD_PROXY) ? 1 : 0;

	return 1;
}

/* fetch the authority TLV from a PROXY protocol header */
int smp_fetch_fc_pp_authority(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (!isttest(conn->proxy_authority))
		return 0;

	smp->flags = 0;
	smp->data.type = SMP_T_STR;
	smp->data.u.str.area = istptr(conn->proxy_authority);
	smp->data.u.str.data = istlen(conn->proxy_authority);

	return 1;
}

/* fetch the unique ID TLV from a PROXY protocol header */
int smp_fetch_fc_pp_unique_id(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (!isttest(conn->proxy_unique_id))
		return 0;

	smp->flags = 0;
	smp->data.type = SMP_T_STR;
	smp->data.u.str.area = istptr(conn->proxy_unique_id);
	smp->data.u.str.data = istlen(conn->proxy_unique_id);

	return 1;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Note: fetches that may return multiple types must be declared as the lowest
 * common denominator, the type that can be casted into all other ones. For
 * instance v4/v6 must be declared v4.
 */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
	{ "fc_http_major", smp_fetch_fc_http_major, 0, NULL, SMP_T_SINT, SMP_USE_L4CLI },
	{ "bc_http_major", smp_fetch_fc_http_major, 0, NULL, SMP_T_SINT, SMP_USE_L4SRV },
	{ "fc_rcvd_proxy", smp_fetch_fc_rcvd_proxy, 0, NULL, SMP_T_BOOL, SMP_USE_L4CLI },
	{ "fc_pp_authority", smp_fetch_fc_pp_authority, 0, NULL, SMP_T_STR, SMP_USE_L4CLI },
	{ "fc_pp_unique_id", smp_fetch_fc_pp_unique_id, 0, NULL, SMP_T_STR, SMP_USE_L4CLI },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &sample_fetch_keywords);

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "pp2-never-send-local", cfg_parse_pp2_never_send_local },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/* private function to handle sockaddr as input for connection hash */
static void conn_calculate_hash_sockaddr(const struct sockaddr_storage *ss,
                                         char *buf, size_t *idx,
                                         enum conn_hash_params_t *hash_flags,
                                         enum conn_hash_params_t param_type_addr,
                                         enum conn_hash_params_t param_type_port)
{
	struct sockaddr_in *addr;
	struct sockaddr_in6 *addr6;

	switch (ss->ss_family) {
	case AF_INET:
		addr = (struct sockaddr_in *)ss;

		conn_hash_update(buf, idx,
		                 &addr->sin_addr, sizeof(addr->sin_addr),
		                 hash_flags, param_type_addr);

		if (addr->sin_port) {
			conn_hash_update(buf, idx,
			                 &addr->sin_port, sizeof(addr->sin_port),
			                 hash_flags, param_type_port);
		}

		break;

	case AF_INET6:
		addr6 = (struct sockaddr_in6 *)ss;

		conn_hash_update(buf, idx,
		                 &addr6->sin6_addr, sizeof(addr6->sin6_addr),
		                 hash_flags, param_type_addr);

		if (addr6->sin6_port) {
			conn_hash_update(buf, idx,
			                 &addr6->sin6_port, sizeof(addr6->sin6_port),
			                 hash_flags, param_type_port);
		}

		break;
	}
}

XXH64_hash_t conn_calculate_hash(const struct conn_hash_params *params)
{
	char *buf;
	size_t idx = 0;
	XXH64_hash_t hash = 0;
	enum conn_hash_params_t hash_flags = 0;

	buf = trash.area;

	conn_hash_update(buf, &idx, &params->target, sizeof(params->target), &hash_flags, 0);

	if (params->sni_prehash) {
		conn_hash_update(buf, &idx,
		                 &params->sni_prehash, sizeof(params->sni_prehash),
		                 &hash_flags, CONN_HASH_PARAMS_TYPE_SNI);
	}

	if (params->dst_addr) {
		conn_calculate_hash_sockaddr(params->dst_addr,
		                             buf, &idx, &hash_flags,
		                             CONN_HASH_PARAMS_TYPE_DST_ADDR,
		                             CONN_HASH_PARAMS_TYPE_DST_PORT);
	}

	if (params->src_addr) {
		conn_calculate_hash_sockaddr(params->src_addr,
		                             buf, &idx, &hash_flags,
		                             CONN_HASH_PARAMS_TYPE_SRC_ADDR,
		                             CONN_HASH_PARAMS_TYPE_SRC_PORT);
	}

	if (params->proxy_prehash) {
		conn_hash_update(buf, &idx,
		                 &params->proxy_prehash, sizeof(params->proxy_prehash),
		                 &hash_flags, CONN_HASH_PARAMS_TYPE_PROXY);
	}

	hash = conn_hash_digest(buf, idx, hash_flags);
	return hash;
}
