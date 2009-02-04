/*
  include/types/protocols.h
  This file defines the structures used by generic network protocols.

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

#ifndef _TYPES_PROTOCOLS_H
#define _TYPES_PROTOCOLS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <common/config.h>
#include <common/mini-clist.h>

#include <types/task.h>

/* max length of a protcol name, including trailing zero */
#define PROTO_NAME_LEN 16

/* listener state */
#define LI_NEW		0	/* not initialized yet */
#define LI_INIT		1	/* all parameters filled in, but not assigned yet */
#define LI_ASSIGNED	2	/* assigned to the protocol, but not listening yet */
#define LI_LISTEN	3	/* started, listening but not enabled */
#define LI_READY	4	/* started, listening and enabled */
#define LI_FULL		5	/* reached its connection limit */

/* Listener transitions
 * calloc()     set()      add_listener()       bind()
 * -------> NEW ----> INIT ----------> ASSIGNED -----> LISTEN
 * <-------     <----      <----------          <-----
 *    free()   bzero()     del_listener()       unbind()
 *
 * The file descriptor is valid only during these three states :
 *
 *             disable()
 * LISTEN <------------ READY
 *   A|   ------------>  |A
 *   ||  !max & enable() ||
 *   ||                  ||
 *   ||              max ||
 *   || max & enable()   V| !max
 *   |+---------------> FULL
 *   +-----------------
 *            disable()
 *
 */

/* listener socket options */
#define LI_O_NONE	0x0000
#define LI_O_NOLINGER	0x0001	/* disable linger on this socket */
#define LI_O_FOREIGN	0x0002	/* permit listening on foreing addresses */

/* The listener will be directly referenced by the fdtab[] which holds its
 * socket. The listener provides the protocol-specific accept() function to
 * the fdtab.
 */
struct listener {
	int fd;				/* the listen socket */
	int state;			/* state: NEW, INIT, ASSIGNED, LISTEN, READY, FULL */
	int options;			/* socket options : LI_O_* */
	struct sockaddr_storage addr;	/* the address we listen to */
	struct protocol *proto;		/* protocol this listener belongs to */
	int nbconn;			/* current number of connections on this listener */
	int maxconn;			/* maximum connections allowed on this listener */
	unsigned int backlog;		/* if set, listen backlog */
	struct listener *next;		/* next address for the same proxy, or NULL */
	struct list proto_list;         /* list in the protocol header */
	int (*accept)(int fd);		/* accept() function passed to fdtab[] */
	void (*handler)(struct task *t, int *next); /* protocol handler */
	int  *timeout;                  /* pointer to client-side timeout */
	void *private;			/* any private data which may be used by accept() */
	unsigned int analysers;		/* bitmap of required protocol analysers */
	union {				/* protocol-dependant access restrictions */
		struct {		/* UNIX socket permissions */
			uid_t uid;	/* -1 to leave unchanged */
			gid_t gid;	/* -1 to leave unchanged */
			mode_t mode;	/* 0 to leave unchanged */
		} ux;
	} perm;
	char *interface;		/* interface name or NULL */
};

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
	int (*read)(int fd);				/* generic read function */
	int (*write)(int fd);				/* generic write function */
	int (*bind_all)(struct protocol *proto);	/* bind all unbound listeners */
	int (*unbind_all)(struct protocol *proto);	/* unbind all bound listeners */
	int (*enable_all)(struct protocol *proto);	/* enable all bound listeners */
	int (*disable_all)(struct protocol *proto);	/* disable all bound listeners */
	struct list listeners;				/* list of listeners using this protocol */
	int nb_listeners;				/* number of listeners */
	struct list list;				/* list of registered protocols */
};

#endif /* _TYPES_PROTOCOLS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
