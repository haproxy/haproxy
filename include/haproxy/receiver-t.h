/*
 * include/haproxy/receiver-t.h
 * This file defines the structures needed to manage receivers.
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

#ifndef _HAPROXY_RECEIVER_T_H
#define _HAPROXY_RECEIVER_T_H

#include <sys/types.h>
#include <sys/socket.h>

#include <haproxy/api-t.h>
#include <haproxy/namespace-t.h>
#include <haproxy/proto_rhttp-t.h>
#include <haproxy/quic_sock-t.h>
#include <haproxy/thread.h>

/* Bit values for receiver->flags */
#define RX_F_BOUND              0x00000001  /* receiver already bound */
#define RX_F_INHERITED          0x00000002  /* inherited FD from the parent process (fd@) or duped from another local receiver */
#define RX_F_MWORKER            0x00000004  /* keep the FD open in the master but close it in the children */
#define RX_F_MUST_DUP           0x00000008  /* this receiver's fd must be dup() from a reference; ignore socket-level ops here */
#define RX_F_NON_SUSPENDABLE    0x00000010  /* this socket cannot be suspended hence must always be unbound */
#define RX_F_PASS_PKTINFO       0x00000020  /* pass pktinfo in received messages */

/* Bit values for rx_settings->options */
#define RX_O_FOREIGN            0x00000001  /* receives on foreign addresses */
#define RX_O_V4V6               0x00000002  /* binds to both IPv4 and IPv6 addresses if !V6ONLY */
#define RX_O_V6ONLY             0x00000004  /* binds to IPv6 addresses only */

/* All the settings that are used to configure a receiver */
struct rx_settings {
	struct {                          /* UNIX socket permissions */
		uid_t uid;                /* -1 to leave unchanged */
		gid_t gid;                /* -1 to leave unchanged */
		mode_t mode;              /* 0 to leave unchanged */
	} ux;
	char *interface;                  /* interface name or NULL */
	const struct netns_entry *netns;  /* network namespace of the listener*/
	unsigned int options;             /* receiver options (RX_O_*) */
	int shards;                       /* number of shards, 0=not set yet, -1="by-thread" */
};

/* info about a shard that is shared between multiple groups. Receivers that
 * are alone in their shard do not have a shard_info.
 */
struct shard_info {
	uint nbgroups;                         /* number of groups in this shard (=#rx); Zero = unused. */
	uint nbthreads;                        /* number of threads in this shard (>=nbgroups) */
	ulong tgroup_mask;                     /* bitmask of thread groups having a member here */
	struct receiver *ref;                  /* first one, reference for FDs to duplicate */
	struct receiver *members[MAX_TGROUPS]; /* all members of the shard (one per thread group) */
};

/* This describes a receiver with all its characteristics (address, options, etc) */
struct receiver {
	int fd;                          /* handle we receive from (fd only for now) */
	unsigned int flags;              /* receiver options (RX_F_*) */
	struct protocol *proto;          /* protocol this receiver belongs to */
	void *owner;                     /* receiver's owner (usually a listener) */
	void (*iocb)(int fd);            /* generic I/O handler (typically accept callback) */
	unsigned long bind_thread;       /* bitmask of threads allowed on this receiver */
	uint bind_tgroup;                /* thread group ID: 0=global IDs, non-zero=local IDs */
	struct rx_settings *settings;    /* points to the settings used by this receiver */
	struct shard_info *shard_info;   /* points to info about the owning shard, NULL if single rx */
	struct list proto_list;          /* list in the protocol header */
#ifdef USE_QUIC
	struct mt_list rxbuf_list;       /* list of buffers to receive and dispatch QUIC datagrams. */
	enum quic_sock_mode quic_mode;   /* QUIC socket allocation strategy */
	unsigned int quic_curr_handshake; /* count of active QUIC handshakes */
	unsigned int quic_curr_accept;   /* count of QUIC conns waiting for accept */
#endif
	struct {
		struct task *task;  /* Task used to open connection for reverse. */
		struct server *srv; /* Underlying server used to initiate reverse pre-connect. */
		struct connection *pend_conn; /* Pending connection waiting to complete reversal before being accepted. */
		enum li_preconn_state state; /* State for transition logging. */
	} rhttp;

	/* warning: this struct is huge, keep it at the bottom */
	struct sockaddr_storage addr;    /* the address the socket is bound to */
};

#endif /* _HAPROXY_RECEIVER_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
