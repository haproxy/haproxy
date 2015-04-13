/*
 * include/types/proto_udp.h
 * This file provides structures and types for UDP protocol.
 *
 * Copyright (C) 2014 Baptiste Assmann <bedis9@gmail.com>
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

#ifndef _TYPES_PROTO_UDP_H
#define _TYPES_PROTO_UDP_H

#include <arpa/inet.h>

/*
 * datagram related structure
 */
struct dgram_conn {
	const struct dgram_data_cb *data;	/* data layer callbacks. Must be set before */
	void *owner;				/* pointer to upper layer's entity */
	union {					/* definitions which depend on connection type */
		struct {			/*** information used by socket-based dgram ***/
			int fd;			/* file descriptor */
		} sock;
	} t;
	struct {
		struct sockaddr_storage from;	/* client address, or address to spoof when connecting to the server */
		struct sockaddr_storage to;	/* address reached by the client, or address to connect to */
	} addr;					/* addresses of the remote side, client for producer and server for consumer */
};

/*
 * datagram callback structure
 */
struct dgram_data_cb {
	void (*recv)(struct dgram_conn *dgram); /* recv callback */
	void (*send)(struct dgram_conn *dgram); /* send callback */
};

#endif /* _TYPES_PROTO_UDP_H */
