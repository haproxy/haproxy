/*
 * include/types/protocols.h
 * This file defines the structures used by generic network protocols.
 *
 * Copyright (C) 2000-2011 Willy Tarreau - w@1wt.eu
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

#ifndef _TYPES_PROTOCOLS_H
#define _TYPES_PROTOCOLS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <common/config.h>
#include <common/mini-clist.h>
#include <eb32tree.h>

#include <types/counters.h>
#include <types/task.h>

/* max length of a protcol name, including trailing zero */
#define PROTO_NAME_LEN 16

/* listener state */
enum {
	LI_NEW	= 0,    /* not initialized yet */
	LI_INIT,        /* all parameters filled in, but not assigned yet */
	LI_ASSIGNED,    /* assigned to the protocol, but not listening yet */
	LI_PAUSED,      /* listener was paused, it's bound but not listening  */
	LI_LISTEN,      /* started, listening but not enabled */
	LI_READY,       /* started, listening and enabled */
	LI_FULL,        /* reached its connection limit */
	LI_LIMITED,     /* transient state: limits have been reached, listener is queued */
};

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
 * The LIMITED state my be used when a limit has been detected just before
 * using a listener. In this case, the listener MUST be queued into the
 * appropriate wait queue (either the proxy's or the global one). It may be
 * set back to the READY state at any instant and for any reason, so one must
 * not rely on this state.
 */

/* listener socket options */
#define LI_O_NONE	0x0000
#define LI_O_NOLINGER	0x0001	/* disable linger on this socket */
#define LI_O_FOREIGN	0x0002	/* permit listening on foreing addresses */
#define LI_O_NOQUICKACK	0x0004	/* disable quick ack of immediate data (linux) */
#define LI_O_DEF_ACCEPT	0x0008	/* wait up to 1 second for data before accepting */
#define LI_O_TCP_RULES  0x0010  /* run TCP rules checks on the incoming connection */
#define LI_O_CHK_MONNET 0x0020  /* check the source against a monitor-net rule */
#define LI_O_ACC_PROXY  0x0040  /* find the proxied address in the first request line */
#define LI_O_UNLIMITED  0x0080  /* listener not subject to global limits (peers & stats socket) */

/* Note: if a listener uses LI_O_UNLIMITED, it is highly recommended that it adds its own
 * maxconn setting to the global.maxsock value so that its resources are reserved.
 */

/* The listener will be directly referenced by the fdtab[] which holds its
 * socket. The listener provides the protocol-specific accept() function to
 * the fdtab.
 */
struct listener {
	int fd;				/* the listen socket */
	char *name;			/* */
	int luid;			/* listener universally unique ID, used for SNMP */
	int state;			/* state: NEW, INIT, ASSIGNED, LISTEN, READY, FULL */
	int options;			/* socket options : LI_O_* */
	struct licounters *counters;	/* statistics counters */
	struct protocol *proto;		/* protocol this listener belongs to */
	struct data_ops *data;          /* data-layer operations operations for this socket */
	int nbconn;			/* current number of connections on this listener */
	int maxconn;			/* maximum connections allowed on this listener */
	unsigned int backlog;		/* if set, listen backlog */
	struct listener *next;		/* next address for the same proxy, or NULL */
	struct list proto_list;         /* list in the protocol header */
	int (*accept)(struct listener *l, int fd, struct sockaddr_storage *addr); /* upper layer's accept() */
	struct task * (*handler)(struct task *t); /* protocol handler. It is a task */
	int  *timeout;                  /* pointer to client-side timeout */
	struct proxy *frontend;		/* the frontend this listener belongs to, or NULL */
	struct list wait_queue;		/* link element to make the listener wait for something (LI_LIMITED)  */
	unsigned int analysers;		/* bitmap of required protocol analysers */
	int nice;			/* nice value to assign to the instanciated tasks */
	union {				/* protocol-dependant access restrictions */
		struct {		/* UNIX socket permissions */
			uid_t uid;	/* -1 to leave unchanged */
			gid_t gid;	/* -1 to leave unchanged */
			mode_t mode;	/* 0 to leave unchanged */
			int level;	/* access level (ACCESS_LVL_*) */
		} ux;
	} perm;
	char *interface;		/* interface name or NULL */
	int maxseg;			/* for TCP, advertised MSS */

	/* warning: this struct is huge, keep it at the bottom */
	struct sockaddr_storage addr;	/* the address we listen to */
	struct {
		const char *file;	/* file where the section appears */
		int line;		/* line where the section appears */
		struct eb32_node id;	/* place in the tree of used IDs */
	} conf;				/* config information */
};

struct stream_interface;

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
	int (*connect)(struct stream_interface *);      /* connect function if any */
	int (*get_src)(int fd, struct sockaddr *, socklen_t, int dir); /* syscall used to retrieve src addr */
	int (*get_dst)(int fd, struct sockaddr *, socklen_t, int dir); /* syscall used to retrieve dst addr */

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
