/*
 * include/proto/stream_sock.h
 * This file contains client-side definitions.
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

#ifndef _PROTO_STREAM_SOCK_H
#define _PROTO_STREAM_SOCK_H

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <common/config.h>
#include <types/stream_interface.h>


/* main event functions used to move data between sockets and buffers */
int stream_sock_accept(int fd);
int stream_sock_read(int fd);
int stream_sock_write(int fd);
void stream_sock_data_finish(struct stream_interface *si);
void stream_sock_shutr(struct stream_interface *si);
void stream_sock_shutw(struct stream_interface *si);
void stream_sock_chk_rcv(struct stream_interface *si);
void stream_sock_chk_snd(struct stream_interface *si);

extern struct sock_ops stream_sock;

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


/*
 * Retrieves the original destination address for the stream interface. On the
 * client side, if the original destination address was translated, the original
 * address is retrieved.
 */
static inline void stream_sock_get_to_addr(struct stream_interface *si)
{
	socklen_t namelen;

	if (si->flags & SI_FL_TO_SET)
		return;

	namelen = sizeof(si->addr.to);

#if defined(TPROXY) && defined(SO_ORIGINAL_DST)
	if (getsockopt(si->fd, SOL_IP, SO_ORIGINAL_DST, (struct sockaddr *)&si->addr.to, &namelen) != -1) {
		si->flags |= SI_FL_TO_SET;
		return;
	}
#endif
	if (si->get_dst &&
	    si->get_dst(si->fd, (struct sockaddr *)&si->addr.to, &namelen) != -1)
		si->flags |= SI_FL_TO_SET;
	return;
}

/*
 * Retrieves the source address for the stream interface.
 */
static inline void stream_sock_get_from_addr(struct stream_interface *si)
{
	socklen_t namelen;

	if (si->flags & SI_FL_FROM_SET)
		return;

	namelen = sizeof(si->addr.to);
	if (si->get_src &&
	    si->get_src(si->fd, (struct sockaddr *)&si->addr.from, &namelen) != -1)
		si->flags |= SI_FL_FROM_SET;
	return;
}


#endif /* _PROTO_STREAM_SOCK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
