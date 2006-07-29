/*
  include/proto/stream_sock.h
  This file contains client-side definitions.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
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

#ifndef _PROTO_STREAM_SOCK_H
#define _PROTO_STREAM_SOCK_H

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <common/config.h>


/* main event functions used to move data between sockets and buffers */
int stream_sock_read(int fd);
int stream_sock_write(int fd);


/* This either returns the sockname or the original destination address. Code
 * inspired from Patrick Schaaf's example of nf_getsockname() implementation.
 */
static inline int get_original_dst(int fd, struct sockaddr_in *sa, socklen_t *salen) {
#if defined(TPROXY) && defined(SO_ORIGINAL_DST)
    return getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, (void *)sa, salen);
#else
#if defined(TPROXY) && defined(USE_GETSOCKNAME)
    return getsockname(fd, (struct sockaddr *)sa, salen);
#else
    return -1;
#endif
#endif
}


#endif /* _PROTO_STREAM_SOCK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
