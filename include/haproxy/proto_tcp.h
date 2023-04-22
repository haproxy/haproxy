/*
 * include/haproxy/proto_tcp.h
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

#ifndef _HAPROXY_PROTO_TCP_H
#define _HAPROXY_PROTO_TCP_H

#include <haproxy/api.h>
#include <haproxy/arg-t.h>
#include <haproxy/connection-t.h>
#include <haproxy/listener-t.h>
#include <haproxy/sample-t.h>

extern struct protocol proto_tcpv4;
extern struct protocol proto_tcpv6;

int tcp_bind_socket(int fd, int flags, struct sockaddr_storage *local, struct sockaddr_storage *remote);
int tcp_connect_server(struct connection *conn, int flags);
int tcp_is_foreign(int fd, sa_family_t family);

#endif /* _HAPROXY_PROTO_TCP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
