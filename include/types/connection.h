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

#include <types/listener.h>
#include <types/protocol.h>

/* referenced below */
struct connection;
struct buffer;
struct pipe;
struct server;
struct proxy;
struct si_applet;
struct task;

/* Polling flags that are manipulated by I/O callbacks and handshake callbacks
 * indicate what they expect from a file descriptor at each layer. For each
 * direction, we have 2 bits, one stating whether any suspected activity on the
 * FD induce a call to the iocb, and another one indicating that the FD has
 * already returned EAGAIN and that polling on it is essential before calling
 * the iocb again :
 *   POL ENA  state
 *    0   0   STOPPED : any activity on this FD is ignored
 *    0   1   ENABLED : any (suspected) activity may call the iocb
 *    1   0   STOPPED : as above
 *    1   1   POLLED  : the FD is being polled for activity
 *
 * - Enabling an I/O event consists in ORing with 1.
 * - Stopping an I/O event consists in ANDing with ~1.
 * - Polling for an I/O event consists in ORing with ~3.
 *
 * The last computed state is remembered in CO_FL_CURR_* so that differential
 * changes can be applied. After bits are applied, the POLL status bits are
 * cleared so that it is possible to detect when an EAGAIN was encountered. For
 * pollers that do not support speculative I/O, POLLED is the same as ENABLED
 * and the POL flag can safely be ignored. However it makes a difference for
 * the connection handler.
 *
 * The ENA flags are per-layer (one pair for SOCK, another one for DATA).
 * The POL flags are only for the socket layer since they indicate that EAGAIN
 * was encountered. Thus, the DATA layer uses its own ENA flag and the socket
 * layer's POL flag.
 *
 * The bits are arranged so that it is possible to detect a change by performing
 * only a left shift followed by a xor and applying a mask to the result. The
 * principle is that depending on what we want to check (data polling changes or
 * sock polling changes), we mask different bits. The bits are arranged this way :
 *
 *    S(ock) - W(ait) - C(urr) - P(oll) - D(ata)
 *
 * SOCK changes are reported when (S != C) || (W != P) => (S:W) != (C:P)
 * DATA changes are reported when (D != C) || (W != P) => (W:C) != (P:D)
 * The R and W bits are split apart so that we never shift more than 2 bits at
 * a time, allowing move+shift to be done as a single operation on x86.
 */

/* flags for use in connection->flags */
enum {
	CO_FL_NONE          = 0x00000000,  /* Just for initialization purposes */

	/* Do not change these values without updating conn_*_poll_changes() ! */
	CO_FL_DATA_RD_ENA   = 0x00000001,  /* receiving data is allowed */
	CO_FL_CURR_RD_POL   = 0x00000002,  /* receiving needs to poll first */
	CO_FL_CURR_RD_ENA   = 0x00000004,  /* receiving is currently allowed */
	CO_FL_WAIT_RD       = 0x00000008,  /* receiving needs to poll first */
	CO_FL_SOCK_RD_ENA   = 0x00000010,  /* receiving handshakes is allowed */
	CO_FL_DATA_WR_ENA   = 0x00000020,  /* sending data is desired */
	CO_FL_CURR_WR_POL   = 0x00000040,  /* sending needs to poll first */
	CO_FL_CURR_WR_ENA   = 0x00000080,  /* sending is currently desired */
	CO_FL_WAIT_WR       = 0x00000100,  /* sending needs to poll first */
	CO_FL_SOCK_WR_ENA   = 0x00000200,  /* sending handshakes is desired */

	/* These flags are used by data layers to indicate they had to stop
	 * sending data because a buffer was empty (WAIT_DATA) or stop receiving
	 * data because a buffer was full (WAIT_ROOM). The connection handler
	 * clears them before first calling the I/O and data callbacks.
	 */
	CO_FL_WAIT_DATA     = 0x00000400,  /* data source is empty */
	CO_FL_WAIT_ROOM     = 0x00000800,  /* data sink is full */

	/* These flags are used to report whether the from/to addresses are set or not */
	CO_FL_ADDR_FROM_SET = 0x00001000,  /* addr.from is set */
	CO_FL_ADDR_TO_SET   = 0x00002000,  /* addr.to is set */

	/* flags indicating what event type the data layer is interested in */
	CO_FL_INIT_DATA     = 0x00004000,  /* initialize the data layer before using it */
	CO_FL_WAKE_DATA     = 0x00008000,  /* wake-up data layer upon activity at the transport layer */

	/* flags used to remember what shutdown have been performed/reported */
	CO_FL_DATA_RD_SH    = 0x00010000,  /* DATA layer was notified about shutr/read0 */
	CO_FL_DATA_WR_SH    = 0x00020000,  /* DATA layer asked for shutw */
	CO_FL_SOCK_RD_SH    = 0x00040000,  /* SOCK layer was notified about shutr/read0 */
	CO_FL_SOCK_WR_SH    = 0x00080000,  /* SOCK layer asked for shutw */

	/* flags used to report connection status and errors */
	CO_FL_ERROR         = 0x00100000,  /* a fatal error was reported     */
	CO_FL_CONNECTED     = 0x00200000,  /* the connection is now established */
	CO_FL_WAIT_L4_CONN  = 0x00400000,  /* waiting for L4 to be connected */
	CO_FL_WAIT_L6_CONN  = 0x00800000,  /* waiting for L6 to be connected (eg: SSL) */

	/* synthesis of the flags above */
	CO_FL_CONN_STATE    = 0x00FF0000,  /* all shut/connected flags */

	/*** All the flags below are used for connection handshakes. Any new
	 * handshake should be added after this point, and CO_FL_HANDSHAKE
	 * should be updated.
	 */
	CO_FL_SI_SEND_PROXY = 0x01000000,  /* send a valid PROXY protocol header */
	CO_FL_SSL_WAIT_HS   = 0x02000000,  /* wait for an SSL handshake to complete */
	CO_FL_ACCEPT_PROXY  = 0x04000000,  /* send a valid PROXY protocol header */

	/* below we have all handshake flags grouped into one */
	CO_FL_HANDSHAKE     = CO_FL_SI_SEND_PROXY | CO_FL_SSL_WAIT_HS | CO_FL_ACCEPT_PROXY,

	/* when any of these flags is set, polling is defined by socket-layer
	 * operations, as opposed to data-layer. Transport is explicitly not
	 * mentionned here to avoid any confusion, since it can be the same
	 * as DATA or SOCK on some implementations.
	 */
	CO_FL_POLL_SOCK     = CO_FL_HANDSHAKE | CO_FL_WAIT_L4_CONN | CO_FL_WAIT_L6_CONN,
};

/* target types */
enum {
	TARG_TYPE_NONE = 0,         /* no target set, pointer is NULL by definition */
	TARG_TYPE_CLIENT,           /* target is a client, pointer is NULL by definition */
	TARG_TYPE_PROXY,            /* target is a proxy   ; use address with the proxy's settings */
	TARG_TYPE_SERVER,           /* target is a server  ; use address with server's and its proxy's settings */
	TARG_TYPE_APPLET,           /* target is an applet ; use only the applet */
	TARG_TYPE_TASK,             /* target is a task running an external applet */
};


/* xprt_ops describes transport-layer operations for a connection. They
 * generally run over a socket-based control layer, but not always. Some
 * of them are used for data transfer with the upper layer (rcv_*, snd_*)
 * and the other ones are used to setup and release the transport layer.
 */
struct xprt_ops {
	int  (*rcv_buf)(struct connection *conn, struct buffer *buf, int count); /* recv callback */
	int  (*snd_buf)(struct connection *conn, struct buffer *buf, int flags); /* send callback */
	int  (*rcv_pipe)(struct connection *conn, struct pipe *pipe, unsigned int count); /* recv-to-pipe callback */
	int  (*snd_pipe)(struct connection *conn, struct pipe *pipe); /* send-to-pipe callback */
	void (*shutr)(struct connection *, int);    /* shutr function */
	void (*shutw)(struct connection *, int);    /* shutw function */
	void (*close)(struct connection *);         /* close the transport layer */
	int  (*init)(struct connection *conn);      /* initialize the transport layer */
};

/* data_cb describes the data layer's recv and send callbacks which are called
 * when I/O activity was detected after the transport layer is ready. These
 * callbacks are supposed to make use of the xprt_ops above to exchange data
 * from/to buffers and pipes. The <wake> callback is used to report activity
 * at the transport layer, which can be a connection opening/close, or any
 * data movement. The <init> callback may be called by the connection handler
 * at the end of a transport handshake, when it is about to transfer data and
 * the data layer is not ready yet. Both <wake> and <init> may abort a connection
 * by returning < 0.
 */
struct data_cb {
	void (*recv)(struct connection *conn);  /* data-layer recv callback */
	void (*send)(struct connection *conn);  /* data-layer send callback */
	int  (*wake)(struct connection *conn);  /* data-layer callback to report activity */
	int  (*init)(struct connection *conn);  /* data-layer initialization */
};

/* a target describes what is on the remote side of the connection. */
struct target {
	int type;
	union {
		void *v;              /* pointer value, for any type */
		struct proxy *p;      /* when type is TARG_TYPE_PROXY  */
		struct server *s;     /* when type is TARG_TYPE_SERVER */
		struct si_applet *a;  /* when type is TARG_TYPE_APPLET */
		struct task *t;       /* when type is TARG_TYPE_TASK */
		struct listener *l;   /* when type is TARG_TYPE_CLIENT */
	} ptr;
};

/* This structure describes a connection with its methods and data.
 * A connection may be performed to proxy or server via a local or remote
 * socket, and can also be made to an internal applet. It can support
 * several transport schemes (applet, raw, ssl, ...). It can support several
 * connection control schemes, generally a protocol for socket-oriented
 * connections, but other methods for applets.
 */
struct connection {
	const struct xprt_ops *xprt;  /* operations at the transport layer */
	const struct protocol *ctrl;  /* operations at the socket layer */
	const struct data_cb  *data;  /* data layer callbacks */
	void *owner;                  /* pointer to upper layer's entity (eg: stream interface) */
	union {                       /* definitions which depend on connection type */
		struct {              /*** information used by socket-based connections ***/
			int fd;       /* file descriptor for a stream driver when known */
		} sock;
	} t;
	unsigned int flags;           /* CO_F_* */
	int xprt_st;                  /* transport layer state, initialized to zero */
	void *xprt_ctx;               /* general purpose pointer, initialized to NULL */
	struct target target;         /* the target to connect to (server, proxy, applet, ...) */
	struct {
		struct sockaddr_storage from;	/* client address, or address to spoof when connecting to the server */
		struct sockaddr_storage to;	/* address reached by the client, or address to connect to */
	} addr; /* addresses of the remote side, client for producer and server for consumer */
};

#endif /* _TYPES_CONNECTION_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
