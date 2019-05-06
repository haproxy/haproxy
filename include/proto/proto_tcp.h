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
#include <types/action.h>
#include <types/task.h>
#include <proto/stick_table.h>

int tcp_bind_socket(int fd, int flags, struct sockaddr_storage *local, struct sockaddr_storage *remote);
int tcp_pause_listener(struct listener *l);
int tcp_connect_server(struct connection *conn, int flags);
int tcp_connect_probe(struct connection *conn);
int tcp_get_src(int fd, struct sockaddr *sa, socklen_t salen, int dir);
int tcp_get_dst(int fd, struct sockaddr *sa, socklen_t salen, int dir);

/* Export some samples. */
int smp_fetch_src(const struct arg *args, struct sample *smp, const char *kw, void *private);

#endif /* _PROTO_PROTO_TCP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
