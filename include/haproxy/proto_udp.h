/*
 * include/proto/proto_udp.h
 * This file contains UDP socket protocol definitions.
 *
 * Copyright 2019 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
 *
 * Partial merge by Emeric Brun <ebrun@haproxy.com>
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

#ifndef _PROTO_PROTO_UDP_H
#define _PROTO_PROTO_UDP_H

int udp_bind_socket(int fd, int flags, struct sockaddr_storage *local, struct sockaddr_storage *remote);
int udp_pause_listener(struct listener *l);
int udp_get_src(int fd, struct sockaddr *sa, socklen_t salen, int dir);
int udp_get_dst(int fd, struct sockaddr *sa, socklen_t salen, int dir);

#endif /* _PROTO_PROTO_UDP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
