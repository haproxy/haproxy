/*
 * include/haproxy/proto_udp.h
 * This file contains UDP socket protocol definitions.
 *
 * Copyright 2019 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
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

#include <haproxy/receiver-t.h>

extern struct protocol proto_udp4;
extern struct protocol proto_udp6;

int udp_bind_socket(int fd, int flags, struct sockaddr_storage *local, struct sockaddr_storage *remote);
int udp_suspend_receiver(struct receiver *rx);
int udp_resume_receiver(struct receiver *rx);

#endif /* _PROTO_PROTO_UDP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
