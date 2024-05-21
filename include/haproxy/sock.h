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

int sock_create_server_socket(struct connection *conn, struct proxy *be, int *stream_err);
void sock_enable(struct receiver *rx);
void sock_disable(struct receiver *rx);
void sock_unbind(struct receiver *rx);
int sock_get_src(int fd, struct sockaddr *sa, socklen_t salen, int dir);
int sock_get_dst(int fd, struct sockaddr *sa, socklen_t salen, int dir);
int sock_get_old_sockets(const char *unixsocket);
int sock_find_compatible_fd(const struct receiver *rx);
void sock_drop_unused_old_sockets();
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
int _sock_supports_reuseport(const struct proto_fam *fam, int type, int protocol);

/* Sets tos sockopt on socket depending on addr target family */
static inline void sock_set_tos(int fd, struct sockaddr_storage *addr, int tos)
{
#ifdef IP_TOS
	if (addr->ss_family == AF_INET)
		setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
#endif
#ifdef IPV6_TCLASS
	if (addr->ss_family == AF_INET6) {
		if (IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)addr)->sin6_addr))
			/* v4-mapped addresses need IP_TOS */
			setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
		else
			setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos));
	}
#endif
}

/* Sets mark sockopt on socket */
static inline void sock_set_mark(int fd, sa_family_t sock_family, int mark)
{
	if ((sock_family == AF_INET) || (sock_family == AF_INET6)) {
#if defined(SO_MARK)
		setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
/* FreeBSD */
#elif defined(SO_USER_COOKIE)
		setsockopt(fd, SOL_SOCKET, SO_USER_COOKIE, &mark, sizeof(mark));
/* OpenBSD */
#elif defined(SO_RTABLE)
		setsockopt(fd, SOL_SOCKET, SO_RTABLE, &mark, sizeof(mark));
#endif
	}
}

#endif /* _HAPROXY_SOCK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
