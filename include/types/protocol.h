/*
 * include/types/protocol.h
 * This file defines the structures used by generic network protocols.
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

#ifndef _TYPES_PROTOCOL_H
#define _TYPES_PROTOCOL_H

#include <sys/types.h>
#include <sys/socket.h>

#include <common/config.h>
#include <common/mini-clist.h>
#include <eb32tree.h>

/* some pointer types referenced below */
struct listener;
struct connection;

/*
 * Custom network family for str2sa parsing.  Should be ok to do this since
 * sa_family_t is standardized as an unsigned integer
 */

#define AF_CUST_SOCKPAIR     (AF_MAX + 1)
#define AF_CUST_MAX          (AF_MAX + 2)

/*
 * Test in case AF_CUST_MAX overflows the sa_family_t (unsigned int)
 */
#if (AF_CUST_MAX < AF_MAX)
# error "Can't build on the target system, AF_CUST_MAX overflow"
#endif



/* max length of a protcol name, including trailing zero */
#define PROTO_NAME_LEN 16

/* This structure contains all information needed to easily handle a protocol.
 * Its primary goal is to ease listeners maintenance. Specifically, the
 * bind_all() primitive must be used before any fork(), and the enable_all()
 * primitive must be called after the fork() to enable all fds. Last, the
 * unbind_all() primitive closes all listeners.
 */
struct protocol {
	char name[PROTO_NAME_LEN];			/* protocol name, zero-terminated */
	int sock_domain;				/* socket domain, as passed to socket()   */
	int sock_type;					/* socket type, as passed to socket()     */
	int sock_prot;					/* socket protocol, as passed to socket() */
	sa_family_t sock_family;			/* socket family, for sockaddr */
	socklen_t sock_addrlen;				/* socket address length, used by bind() */
	int l3_addrlen;					/* layer3 address length, used by hashes */
	void (*accept)(int fd);				/* generic accept function */
	int (*bind)(struct listener *l, char *errmsg, int errlen); /* bind a listener */
	int (*bind_all)(struct protocol *proto, char *errmsg, int errlen); /* bind all unbound listeners */
	int (*unbind_all)(struct protocol *proto);	/* unbind all bound listeners */
	int (*enable_all)(struct protocol *proto);	/* enable all bound listeners */
	int (*disable_all)(struct protocol *proto);	/* disable all bound listeners */
	int (*connect)(struct connection *, int flags); /* connect function if any, see below for flags values */
	int (*get_src)(int fd, struct sockaddr *, socklen_t, int dir); /* syscall used to retrieve src addr */
	int (*get_dst)(int fd, struct sockaddr *, socklen_t, int dir); /* syscall used to retrieve dst addr */
	int (*drain)(int fd);                           /* indicates whether we can safely close the fd */
	int (*pause)(struct listener *l);               /* temporarily pause this listener for a soft restart */
	void (*add)(struct listener *l, int port);      /* add a listener for this protocol and port */

	struct list listeners;				/* list of listeners using this protocol (under proto_lock) */
	int nb_listeners;				/* number of listeners (under proto_lock) */
	struct list list;				/* list of registered protocols (under proto_lock) */
};

#define CONNECT_HAS_DATA                        0x00000001 /* There's data available to be sent */
#define CONNECT_DELACK_SMART_CONNECT            0x00000002 /* Use a delayed ACK if the backend has tcp-smart-connect */
#define CONNECT_DELACK_ALWAYS                   0x00000004 /* Use a delayed ACK */
#define CONNECT_CAN_USE_TFO                     0x00000008 /* We can use TFO for this connection */
#endif /* _TYPES_PROTOCOL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
