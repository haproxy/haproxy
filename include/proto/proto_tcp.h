/*
 * include/proto/proto_tcp.h
 * This file contains TCP socket protocol definitions.
 *
 * Copyright (C) 2000-2010 Willy Tarreau - w@1wt.eu
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

int tcpv4_bind_socket(int fd, int flags, struct sockaddr_in *local, struct sockaddr_in *remote);
void tcpv4_add_listener(struct listener *listener);
void tcpv6_add_listener(struct listener *listener);
int tcpv4_connect_server(struct stream_interface *si,
			 struct proxy *be, struct server *srv,
			 struct sockaddr *srv_addr, struct sockaddr *from_addr);
int tcp_inspect_request(struct session *s, struct buffer *req, int an_bit);
int tcp_inspect_response(struct session *s, struct buffer *rep, int an_bit);
int tcp_persist_rdp_cookie(struct session *s, struct buffer *req, int an_bit);
int tcp_exec_req_rules(struct session *s);

/* Converts the TCPv4 source address to a stick_table key usable for table
 * lookups. Returns either NULL if the source cannot be converted (eg: not
 * IPv4) or a pointer to the converted result in static_table_key in the
 * appropriate format (IP).
 */
static inline struct stktable_key *tcpv4_src_to_stktable_key(struct session *s)
{
	/* right now we only support IPv4 */
	if (s->cli_addr.ss_family != AF_INET)
		return NULL;

	static_table_key.key = (void *)&((struct sockaddr_in *)&s->cli_addr)->sin_addr;
	return &static_table_key;
}


#endif /* _PROTO_PROTO_TCP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
