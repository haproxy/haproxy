/*
 * include/haproxy/sock.h
 * This file contains declarations for native (BSD-compatible) sockets.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_SOCK_H
#define _HAPROXY_SOCK_H

#include <sys/socket.h>
#include <sys/types.h>

#include <haproxy/api.h>
#include <haproxy/connection-t.h>
#include <haproxy/listener-t.h>
#include <haproxy/sock-t.h>

extern struct xfer_sock_list *xfer_sock_list;

int sock_create_server_socket(struct connection *conn);
void sock_enable(struct receiver *rx);
void sock_disable(struct receiver *rx);
void sock_unbind(struct receiver *rx);
int sock_get_src(int fd, struct sockaddr *sa, socklen_t salen, int dir);
int sock_get_dst(int fd, struct sockaddr *sa, socklen_t salen, int dir);
int sock_get_old_sockets(const char *unixsocket);
int sock_find_compatible_fd(const struct receiver *rx);
int sock_accepting_conn(const struct receiver *rx);
struct connection *sock_accept_conn(struct listener *l, int *status);
void sock_accept_iocb(int fd);
void sock_conn_ctrl_init(struct connection *conn);
void sock_conn_ctrl_close(struct connection *conn);
void sock_conn_iocb(int fd);
int sock_conn_check(struct connection *conn);
int sock_drain(struct connection *conn);
int sock_check_events(struct connection *conn, int event_type);
void sock_ignore_events(struct connection *conn, int event_type);


#endif /* _HAPROXY_SOCK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
