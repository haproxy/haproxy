/*
  include/proto/proto_tcp.h
  This file contains TCP socket protocol definitions.

  Copyright (C) 2000-2008 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _PROTO_PROTO_TCP_H
#define _PROTO_PROTO_TCP_H

#include <common/config.h>
#include <types/proto_tcp.h>
#include <types/session.h>
#include <types/task.h>

int tcp_event_accept(int fd);
int tcpv4_bind_socket(int fd, int flags, struct sockaddr_in *local, struct sockaddr_in *remote);
void tcpv4_add_listener(struct listener *listener);
void tcpv6_add_listener(struct listener *listener);
int tcp_bind_listener(struct listener *listener, char *errmsg, int errlen);
int tcp_inspect_request(struct session *s, struct buffer *req, int an_bit);

#endif /* _PROTO_PROTO_TCP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
