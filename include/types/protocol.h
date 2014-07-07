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
	int (*accept)(int fd);				/* generic accept function */
	int (*bind)(struct listener *l, char *errmsg, int errlen); /* bind a listener */
	int (*bind_all)(struct protocol *proto, char *errmsg, int errlen); /* bind all unbound listeners */
	int (*unbind_all)(struct protocol *proto);	/* unbind all bound listeners */
	int (*enable_all)(struct protocol *proto);	/* enable all bound listeners */
	int (*disable_all)(struct protocol *proto);	/* disable all bound listeners */
	int (*connect)(struct connection *, int data, int delack);  /* connect function if any */
	int (*get_src)(int fd, struct sockaddr *, socklen_t, int dir); /* syscall used to retrieve src addr */
	int (*get_dst)(int fd, struct sockaddr *, socklen_t, int dir); /* syscall used to retrieve dst addr */
	int (*drain)(int fd);                           /* indicates whether we can safely close the fd */
	int (*pause)(struct listener *l);               /* temporarily pause this listener for a soft restart */

	struct list listeners;				/* list of listeners using this protocol */
	int nb_listeners;				/* number of listeners */
	struct list list;				/* list of registered protocols */
};

#endif /* _TYPES_PROTOCOL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
