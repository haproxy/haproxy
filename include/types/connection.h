/*
 * include/types/connection.h
 * This file describes the connection struct and associated constants.
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
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

#ifndef _TYPES_CONNECTION_H
#define _TYPES_CONNECTION_H

#include <stdlib.h>
#include <sys/socket.h>

#include <common/config.h>

/* referenced below */
struct sock_ops;
struct protocol;

/* This structure describes a connection with its methods and data.
 * A connection may be performed to proxy or server via a local or remote
 * socket, and can also be made to an internal applet. It can support
 * several data schemes (applet, raw, ssl, ...). It can support several
 * connection control schemes, generally a protocol for socket-oriented
 * connections, but other methods for applets.
 */
struct connection {
	const struct sock_ops *data;  /* operations at the data layer */
	const struct protocol *ctrl;  /* operations at the control layer, generally a protocol */
	union {                       /* definitions which depend on connection type */
		struct {              /*** information used by socket-based connections ***/
			int fd;       /* file descriptor for a stream driver when known */
		} sock;
	} t;
	int data_st;                  /* data layer state, initialized to zero */
	void *data_ctx;               /* general purpose pointer, initialized to NULL */
	struct sockaddr *peeraddr;    /* pointer to peer's network address, or NULL if unset */
	socklen_t peerlen;            /* peer's address length, or 0 if unset */
};

#endif /* _TYPES_CONNECTION_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
