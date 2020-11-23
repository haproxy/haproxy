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
#include <haproxy/thread.h>

/* Bit values for receiver->flags */
#define RX_F_BOUND              0x00000001  /* receiver already bound */
#define RX_F_INHERITED          0x00000002  /* inherited FD from the parent process (fd@) */
#define RX_F_MWORKER            0x00000004  /* keep the FD open in the master but close it in the children */

/* Bit values for rx_settings->options */
#define RX_O_FOREIGN            0x00000001  /* receives on foreign addresses */
#define RX_O_V4V6               0x00000002  /* binds to both IPv4 and IPv6 addresses if !V6ONLY */
#define RX_O_V6ONLY             0x00000004  /* binds to IPv6 addresses only */

/* All the settings that are used to configure a receiver */
struct rx_settings {
	unsigned long bind_proc;          /* bitmask of processes allowed to use these listeners */
	unsigned long bind_thread;        /* bitmask of threads allowed to use these listeners */
	struct {                          /* UNIX socket permissions */
		uid_t uid;                /* -1 to leave unchanged */
		gid_t gid;                /* -1 to leave unchanged */
		mode_t mode;              /* 0 to leave unchanged */
	} ux;
	char *interface;                  /* interface name or NULL */
	const struct netns_entry *netns;  /* network namespace of the listener*/
	unsigned int options;             /* receiver options (RX_O_*) */
};

/* This describes a receiver with all its characteristics (address, options, etc) */
struct receiver {
	int fd;                          /* handle we receive from (fd only for now) */
	unsigned int flags;              /* receiver options (RX_F_*) */
	struct protocol *proto;          /* protocol this receiver belongs to */
	void *owner;                     /* receiver's owner (usually a listener) */
	void (*iocb)(int fd);            /* generic I/O handler (typically accept callback) */
	struct rx_settings *settings;    /* points to the settings used by this receiver */
	struct list proto_list;          /* list in the protocol header */
#ifdef USE_QUIC
	struct list qpkts;               /* QUIC Initial packets to accept new connections */
	struct eb_root odcids;           /* QUIC original destination connection IDs. */
	struct eb_root cids;             /* QUIC connection IDs. */
#endif
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
