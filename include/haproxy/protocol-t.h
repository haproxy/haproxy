/*
 * include/haproxy/protocol-t.h
 * This file defines the structures used by generic network protocols.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_PROTOCOL_T_H
#define _HAPROXY_PROTOCOL_T_H

#include <sys/types.h>
#include <sys/socket.h>

#include <import/ebtree-t.h>
#include <haproxy/api-t.h>

/* some pointer types referenced below */
struct listener;
struct receiver;
struct connection;

/*
 * Custom network family for str2sa parsing.  Should be ok to do this since
 * sa_family_t is standardized as an unsigned integer
 */
#define AF_CUST_EXISTING_FD  (AF_MAX + 1)
#define AF_CUST_SOCKPAIR     (AF_MAX + 2)
#define AF_CUST_RHTTP_SRV    (AF_MAX + 3)
#define AF_CUST_ABNS         (AF_MAX + 4)
#define AF_CUST_ABNSZ        (AF_MAX + 5)
#define AF_CUST_MAX          (AF_MAX + 6)

/*
 * Test in case AF_CUST_MAX overflows the sa_family_t (unsigned int)
 */
#if (AF_CUST_MAX < AF_MAX)
# error "Can't build on the target system, AF_CUST_MAX overflow"
#endif

/* socket-level protocol types, used for protocol selection */
enum proto_type {
	PROTO_TYPE_STREAM,      /* streaming protocol (like TCP) */
	PROTO_TYPE_DGRAM,       /* datagram protocol (like UDP) */
	PROTO_NUM_TYPES         /* must be the last one */
};

/* max length of a protocol name, including trailing zero */
#define PROTO_NAME_LEN 16

/* flags for ->connect() */
#define CONNECT_HAS_DATA                        0x00000001 /* There's data available to be sent */
#define CONNECT_DELACK_SMART_CONNECT            0x00000002 /* Use a delayed ACK if the backend has tcp-smart-connect */
#define CONNECT_DELACK_ALWAYS                   0x00000004 /* Use a delayed ACK */
#define CONNECT_CAN_USE_TFO                     0x00000008 /* We can use TFO for this connection */

/* Flags for protocol->flags */
#define PROTO_F_REUSEPORT_SUPPORTED             0x00000001 /* SO_REUSEPORT is supported */
#define PROTO_F_REUSEPORT_TESTED                0x00000002 /* SO_REUSEPORT support was tested */

/* protocol families define standard functions acting on a given address family
 * for a socket implementation, such as AF_INET/PF_INET for example. There is
 * permanent confusion between domain and family. Here's how it works:
 *   - the domain defines the format of addresses (e.g. sockaddr_in etc),
 *     it is passed as the first argument to socket()
 *   - the socket family is part of the address and is stored in receivers,
 *     servers and everywhere there is an address. It's also a proto_fam
 *     selector.
 *   - the real family is the one passed to bind() and connect() to map
 *     custom families to their real equivalent one.
 *
 * Domains are often PF_xxx though man 2 socket on Linux quotes 4.x BSD's man
 * that says AF_* can be used everywhere. At least it tends to keep the code
 * clearer about the intent. In HAProxy we're defining new address families
 * with AF_CUST_* which appear in addresses, and they cannot be used for the
 * domain, the socket() call must use sock_domain instead.
 */
struct proto_fam {
	char name[PROTO_NAME_LEN];                      /* family name, zero-terminated */
	int sock_domain;				/* socket domain, as passed to socket()   */
	sa_family_t sock_family;			/* socket family, for sockaddr */
	sa_family_t real_family;			/* the socket family passed to syscalls */
	ushort l3_addrlen;				/* layer3 address length, used by hashes */
	socklen_t sock_addrlen;				/* socket address length, used by bind() */
	/* 4-bytes hole here */
	int (*addrcmp)(const struct sockaddr_storage *, const struct sockaddr_storage *); /* compare addresses (like memcmp) */
	int (*bind)(struct receiver *rx, char **errmsg); /* bind a receiver */
	int (*get_src)(int fd, struct sockaddr *, socklen_t, int dir); /* syscall used to retrieve connection's src addr */
	int (*get_dst)(int fd, struct sockaddr *, socklen_t, int dir); /* syscall used to retrieve connection's dst addr */
	void (*set_port)(struct sockaddr_storage *, int port);  /* set the port on the address; NULL if not implemented */
};

/* This structure contains all information needed to easily handle a protocol.
 * Its primary goal is to ease listeners maintenance. Specifically, the
 * bind() primitive must be used before any fork(). rx_suspend()/rx_resume()
 * return >0 on success, 0 if rx stopped, -1 on failure to proceed. rx_* may
 * be null if the protocol doesn't provide direct access to the receiver.
 */
struct protocol {
	char name[PROTO_NAME_LEN];			/* protocol name, zero-terminated */
	struct proto_fam *fam;                          /* protocol family */
	int xprt_type;                                  /* transport layer type (PROTO_TYPE_STREAM/PROTO_TYPE_DGRAM) */
	enum proto_type proto_type;                     /* protocol type at the socket layer (PROTO_TYPE_*) */
	int sock_type;					/* socket type, as passed to socket()     */
	int sock_prot;					/* socket protocol, as passed to socket() */

	/* functions acting on the listener */
	void (*add)(struct protocol *p, struct listener *l); /* add a listener for this protocol */
	int (*listen)(struct listener *l, char *errmsg, int errlen); /* start a listener */
	void (*enable)(struct listener *l);             /* enable receipt of new connections */
	void (*disable)(struct listener *l);            /* disable receipt of new connections */
	void (*unbind)(struct listener *l);             /* unbind the listener and possibly its receiver */
	int (*suspend)(struct listener *l);             /* try to suspend the listener */
	int (*resume)(struct listener *l);              /* try to resume a suspended listener */
	struct connection *(*accept_conn)(struct listener *l, int *status); /* accept a new connection */

	/* functions acting on connections */
	void (*ctrl_init)(struct connection *);         /* completes initialization of the connection */
	void (*ctrl_close)(struct connection *);        /* completes release of the connection */
	int (*connect)(struct connection *, int flags); /* connect function if any, see below for flags values */
	int (*drain)(struct connection *);              /* drain pending data; 0=failed, >0=success */
	int (*check_events)(struct connection *conn, int event_type);  /* subscribe to socket events */
	void (*ignore_events)(struct connection *conn, int event_type);  /* unsubscribe from socket events */
	int (*get_src)(struct connection *conn, struct sockaddr *, socklen_t); /* retrieve connection's source address; -1=fail */
	int (*get_dst)(struct connection *conn, struct sockaddr *, socklen_t); /* retrieve connection's dest address; -1=fail */

	/* API for thread affinity notification from listener_accept()
	 * [ tid selected ] -->
	 *   <bind_tid_prep> --> [ acc queue push ] == OK --> <bind_tid_commit>
	 *                                          == ERR -> <bind_tid_reset>
	 */
	/* prepare rebind connection on a new thread, may fail */
	int (*bind_tid_prep)(struct connection *conn, int new_tid);
	/* complete connection thread rebinding, no error possible */
	void (*bind_tid_commit)(struct connection *conn);
	/* cancel connection thread rebinding */
	void (*bind_tid_reset)(struct connection *conn);

	/* functions acting on the receiver */
	int (*rx_suspend)(struct receiver *rx);         /* temporarily suspend this receiver for a soft restart */
	int (*rx_resume)(struct receiver *rx);          /* try to resume a temporarily suspended receiver */
	void (*rx_enable)(struct receiver *rx);         /* enable receiving on the receiver */
	void (*rx_disable)(struct receiver *rx);        /* disable receiving on the receiver */
	void (*rx_unbind)(struct receiver *rx);         /* unbind the receiver, most often closing the FD */
	int (*rx_listening)(const struct receiver *rx); /* is the receiver listening ? 0=no, >0=OK, <0=unrecoverable */

	/* default I/O handler */
	void (*default_iocb)(int fd);                   /* generic I/O handler (typically accept callback) */
	int (*get_info)(struct connection *conn, long long int *info, int info_num);       /* Callback to get connection level statistical counters */

	uint flags;                                     /* flags describing protocol support (PROTO_F_*) */
	uint nb_receivers;                              /* number of receivers (under proto_lock) */
	struct list receivers;				/* list of receivers using this protocol (under proto_lock) */
	struct list list;				/* list of registered protocols (under proto_lock) */
};

/* Transport protocol identifiers which can be used as masked values. */
enum ha_proto {
	HA_PROTO_NONE = 0x00,

	HA_PROTO_TCP  = 0x01,
	HA_PROTO_UDP  = 0x02,
	HA_PROTO_QUIC = 0x04,

	HA_PROTO_ANY  = 0xff,
};

#endif /* _HAPROXY_PROTOCOL_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
