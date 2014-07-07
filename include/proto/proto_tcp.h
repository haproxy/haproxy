/*
 * include/proto/proto_tcp.h
 * This file contains TCP socket protocol definitions.
 *
 * Copyright (C) 2000-2013 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _PROTO_PROTO_TCP_H
#define _PROTO_PROTO_TCP_H

#include <common/config.h>
#include <types/proto_tcp.h>
#include <types/task.h>
#include <proto/stick_table.h>

int tcp_bind_socket(int fd, int flags, struct sockaddr_storage *local, struct sockaddr_storage *remote);
void tcpv4_add_listener(struct listener *listener);
void tcpv6_add_listener(struct listener *listener);
int tcp_pause_listener(struct listener *l);
int tcp_connect_server(struct connection *conn, int data, int delack);
int tcp_connect_probe(struct connection *conn);
int tcp_get_src(int fd, struct sockaddr *sa, socklen_t salen, int dir);
int tcp_get_dst(int fd, struct sockaddr *sa, socklen_t salen, int dir);
int tcp_drain(int fd);
int tcp_inspect_request(struct session *s, struct channel *req, int an_bit);
int tcp_inspect_response(struct session *s, struct channel *rep, int an_bit);
int tcp_exec_req_rules(struct session *s);

/* Converts the INET/INET6 source address to a stick_table key usable for table
 * lookups. <type> can be STKTABLE_TYPE_IP or STKTABLE_TYPE_IPV6. The function
 * try to convert the incoming IP to the type expected by the sticktable.
 * Returns either NULL if the source cannot be converted (eg: not IPv4) or a
 * pointer to the converted result in static_table_key in the appropriate format
 * (IP).
 */
static inline struct stktable_key *addr_to_stktable_key(struct sockaddr_storage *addr, long type)
{
	switch (addr->ss_family) {
	case AF_INET:
		/* Convert IPv4 to IPv4 key. */
		if (type == STKTABLE_TYPE_IP) {
			static_table_key->key = (void *)&((struct sockaddr_in *)addr)->sin_addr;
			break;
		}
		/* Convert IPv4 to IPv6 key. */
		if (type == STKTABLE_TYPE_IPV6) {
			v4tov6(&static_table_key->data.ipv6, &((struct sockaddr_in *)addr)->sin_addr);
			static_table_key->key = &static_table_key->data.ipv6;
			break;
		}
		return NULL;

	case AF_INET6:
		/* Convert IPv6 to IPv4 key. This conversion can be failed. */
		if (type == STKTABLE_TYPE_IP) {
			if (!v6tov4(&static_table_key->data.ip, &((struct sockaddr_in6 *)addr)->sin6_addr))
				return NULL;
			static_table_key->key = &static_table_key->data.ip;
			break;
		}
		/* Convert IPv6 to IPv6 key. */
		if (type == STKTABLE_TYPE_IPV6) {
			static_table_key->key = (void *)&((struct sockaddr_in6 *)addr)->sin6_addr;
			break;
		}
		return NULL;
	default:
		return NULL;
	}
	return static_table_key;
}

/* for a tcp-request action TCP_ACT_TRK_*, return a tracking index starting at
 * zero for SC0. Unknown actions also return zero.
 */
static inline int tcp_trk_idx(int trk_action)
{
	return trk_action - TCP_ACT_TRK_SC0;
}

#endif /* _PROTO_PROTO_TCP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
