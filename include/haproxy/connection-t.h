/*
 * include/haproxy/connection-t.h
 * This file describes the connection struct and associated constants.
 *
 * Copyright (C) 2000-2014 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_CONNECTION_T_H
#define _HAPROXY_CONNECTION_T_H

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <import/ebtree-t.h>
#include <import/ist.h>

#include <haproxy/api-t.h>
#include <haproxy/buf-t.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/port_range-t.h>
#include <haproxy/protocol-t.h>
#include <haproxy/show_flags-t.h>
#include <haproxy/thread-t.h>

/* referenced below */
struct connection;
struct stconn;
struct sedesc;
struct cs_info;
struct buffer;
struct proxy;
struct server;
struct session;
struct pipe;
struct quic_conn;
struct bind_conf;
struct qcs;
struct ssl_sock_ctx;

/* Note: subscribing to these events is only valid after the caller has really
 * attempted to perform the operation, and failed to proceed or complete.
 */
enum sub_event_type {
	SUB_RETRY_RECV       = 0x00000001,  /* Schedule the tasklet when we can attempt to recv again */
	SUB_RETRY_SEND       = 0x00000002,  /* Schedule the tasklet when we can attempt to send again */
};

/* For each direction, we have a CO_FL_XPRT_<DIR>_ENA flag, which
 * indicates if read or write is desired in that direction for the respective
 * layers. The current status corresponding to the current layer being used is
 * remembered in the CO_FL_XPRT_<DIR>_ENA flag. The need to poll (ie receipt of
 * EAGAIN) is remembered at the file descriptor level so that even when the
 * activity is stopped and restarted, we still remember whether it was needed
 * to poll before attempting the I/O.
 *
 * The FD state is updated according to CO_FL_XPRT_<DIR>_ENA in
 * conn_cond_update_polling().
 */

/* flags for use in connection->flags. Please also update the conn_show_flags()
 * function below in case of changes.
 */
enum {
	CO_FL_NONE          = 0x00000000,  /* Just for initialization purposes */

	/* Do not change these values without updating conn_*_poll_changes() ! */
	CO_FL_SAFE_LIST     = 0x00000001,  /* 0 = not in any list, 1 = in safe_list  */
	CO_FL_IDLE_LIST     = 0x00000002,  /* 2 = in idle_list, 3 = invalid */
	CO_FL_LIST_MASK     = 0x00000003,  /* Is the connection in any server-managed list ? */

	CO_FL_REVERSED      = 0x00000004,  /* connection has been reversed to backend / reversed and accepted on frontend */
	CO_FL_ACT_REVERSING = 0x00000008,  /* connection has been reversed to frontend but not yet accepted */
	/* unused : 0x00000008 */

	/* unused : 0x00000010 */
	/* unused : 0x00000020 */
	/* unused : 0x00000040, 0x00000080 */

	/* These flags indicate whether the Control and Transport layers are initialized */
	CO_FL_CTRL_READY    = 0x00000100, /* FD was registered, fd_delete() needed */
	CO_FL_XPRT_READY    = 0x00000200, /* xprt_start() done, xprt can be used */

	CO_FL_WANT_DRAIN    = 0x00000400, /* try to drain pending data when closing */

	/* This flag is used by data layers to indicate they had to stop
	 * receiving data because a buffer was full. The connection handler
	 * clears it before first calling the I/O and data callbacks.
	 */
	CO_FL_WAIT_ROOM     = 0x00000800,  /* data sink is full */

	/* These flags are used to report whether the from/to addresses are set or not */
	/* unused: 0x00001000 */
	/* unused: 0x00002000 */

	CO_FL_EARLY_SSL_HS  = 0x00004000,  /* We have early data pending, don't start SSL handshake yet */
	CO_FL_EARLY_DATA    = 0x00008000,  /* At least some of the data are early data */
	CO_FL_SOCKS4_SEND   = 0x00010000,  /* handshaking with upstream SOCKS4 proxy, going to send the handshake */
	CO_FL_SOCKS4_RECV   = 0x00020000,  /* handshaking with upstream SOCKS4 proxy, going to check if handshake succeed */

	/* flags used to remember what shutdown have been performed/reported */
	CO_FL_SOCK_RD_SH    = 0x00040000,  /* SOCK layer was notified about shutr/read0 */
	CO_FL_SOCK_WR_SH    = 0x00080000,  /* SOCK layer asked for shutw */

	/* flags used to report connection errors or other closing conditions */
	CO_FL_ERROR         = 0x00100000,  /* a fatal error was reported     */
	CO_FL_NOTIFY_DONE   = 0x001C0000,  /* any xprt shut/error flags above needs to be reported */

	CO_FL_FDLESS        = 0x00200000,  /* this connection doesn't use any FD (e.g. QUIC) */

	/* flags used to report connection status updates */
	CO_FL_WAIT_L4_CONN  = 0x00400000,  /* waiting for L4 to be connected */
	CO_FL_WAIT_L6_CONN  = 0x00800000,  /* waiting for L6 to be connected (eg: SSL) */
	CO_FL_WAIT_L4L6     = 0x00C00000,  /* waiting for L4 and/or L6 to be connected */

	/* All the flags below are used for connection handshakes. Any new
	 * handshake should be added after this point, and CO_FL_HANDSHAKE
	 * should be updated.
	 */
	CO_FL_SEND_PROXY    = 0x01000000,  /* send a valid PROXY protocol header */
	CO_FL_ACCEPT_PROXY  = 0x02000000,  /* receive a valid PROXY protocol header */
	CO_FL_ACCEPT_CIP    = 0x04000000,  /* receive a valid NetScaler Client IP header */

	/* below we have all handshake flags grouped into one */
	CO_FL_HANDSHAKE     = CO_FL_SEND_PROXY | CO_FL_ACCEPT_PROXY | CO_FL_ACCEPT_CIP | CO_FL_SOCKS4_SEND | CO_FL_SOCKS4_RECV,
	CO_FL_WAIT_XPRT     = CO_FL_WAIT_L4_CONN | CO_FL_HANDSHAKE | CO_FL_WAIT_L6_CONN,

	CO_FL_SSL_WAIT_HS   = 0x08000000,  /* wait for an SSL handshake to complete */

	/* This connection may not be shared between clients */
	CO_FL_PRIVATE       = 0x10000000,

	/* This flag is used to know that a PROXY protocol header was sent by the client */
	CO_FL_RCVD_PROXY    = 0x20000000,

	/* The connection is unused by its owner */
	CO_FL_SESS_IDLE     = 0x40000000,

	/* This last flag indicates that the transport layer is used (for instance
	 * by logs) and must not be cleared yet. The last call to conn_xprt_close()
	 * must be done after clearing this flag.
	 */
	CO_FL_XPRT_TRACKED  = 0x80000000,

	/* below we have all SOCKS handshake flags grouped into one */
	CO_FL_SOCKS4        = CO_FL_SOCKS4_SEND | CO_FL_SOCKS4_RECV,
};

/* This function is used to report flags in debugging tools. Please reflect
 * below any single-bit flag addition above in the same order via the
 * __APPEND_FLAG macro. The new end of the buffer is returned.
 */
static forceinline char *conn_show_flags(char *buf, size_t len, const char *delim, uint flg)
{
#define _(f, ...) __APPEND_FLAG(buf, len, delim, flg, f, #f, __VA_ARGS__)
	/* prologue */
	_(0);
	/* flags */
	_(CO_FL_SAFE_LIST, _(CO_FL_IDLE_LIST, _(CO_FL_CTRL_READY,
	_(CO_FL_REVERSED, _(CO_FL_ACT_REVERSING, _(CO_FL_XPRT_READY,
	_(CO_FL_WANT_DRAIN, _(CO_FL_WAIT_ROOM, _(CO_FL_EARLY_SSL_HS, _(CO_FL_EARLY_DATA,
	_(CO_FL_SOCKS4_SEND, _(CO_FL_SOCKS4_RECV, _(CO_FL_SOCK_RD_SH, _(CO_FL_SOCK_WR_SH,
	_(CO_FL_ERROR, _(CO_FL_FDLESS, _(CO_FL_WAIT_L4_CONN, _(CO_FL_WAIT_L6_CONN,
	_(CO_FL_SEND_PROXY, _(CO_FL_ACCEPT_PROXY, _(CO_FL_ACCEPT_CIP, _(CO_FL_SSL_WAIT_HS,
	_(CO_FL_PRIVATE, _(CO_FL_RCVD_PROXY, _(CO_FL_SESS_IDLE, _(CO_FL_XPRT_TRACKED
	))))))))))))))))))))))))));
	/* epilogue */
	_(~0U);
	return buf;
#undef _
}

/* Possible connection error codes.
 * Warning: Do not reorder the codes, they are fetchable through the
 * "fc_err" sample fetch. If a new code is added, please add an error label
 * in conn_err_code_str and in the "fc_err_str" sample fetch documentation.
 */
enum {
	CO_ER_NONE,             /* no error */

	CO_ER_CONF_FDLIM,       /* reached process's configured FD limitation */
	CO_ER_PROC_FDLIM,       /* reached process's FD limitation */
	CO_ER_SYS_FDLIM,        /* reached system's FD limitation */
	CO_ER_SYS_MEMLIM,       /* reached system buffers limitation */
	CO_ER_NOPROTO,          /* protocol not supported */
	CO_ER_SOCK_ERR,         /* other socket error */

	CO_ER_PORT_RANGE,       /* source port range exhausted */
	CO_ER_CANT_BIND,        /* can't bind to source address */
	CO_ER_FREE_PORTS,       /* no more free ports on the system */
	CO_ER_ADDR_INUSE,       /* local address already in use */

	CO_ER_PRX_EMPTY,        /* nothing received in PROXY protocol header */
	CO_ER_PRX_ABORT,        /* client abort during PROXY protocol header */
	CO_ER_PRX_TIMEOUT,      /* timeout while waiting for a PROXY header */
	CO_ER_PRX_TRUNCATED,    /* truncated PROXY protocol header */
	CO_ER_PRX_NOT_HDR,      /* not a PROXY protocol header */
	CO_ER_PRX_BAD_HDR,      /* bad PROXY protocol header */
	CO_ER_PRX_BAD_PROTO,    /* unsupported protocol in PROXY header */

	CO_ER_CIP_EMPTY,        /* nothing received in NetScaler Client IP header */
	CO_ER_CIP_ABORT,        /* client abort during NetScaler Client IP header */
	CO_ER_CIP_TIMEOUT,      /* timeout while waiting for a NetScaler Client IP header */
	CO_ER_CIP_TRUNCATED,    /* truncated NetScaler Client IP header */
	CO_ER_CIP_BAD_MAGIC,    /* bad magic number in NetScaler Client IP header */
	CO_ER_CIP_BAD_PROTO,    /* unsupported protocol in NetScaler Client IP header */

	CO_ER_SSL_EMPTY,        /* client closed during SSL handshake */
	CO_ER_SSL_ABORT,        /* client abort during SSL handshake */
	CO_ER_SSL_TIMEOUT,      /* timeout during SSL handshake */
	CO_ER_SSL_TOO_MANY,     /* too many SSL connections */
	CO_ER_SSL_NO_MEM,       /* no more memory to allocate an SSL connection */
	CO_ER_SSL_RENEG,        /* forbidden client renegotiation */
	CO_ER_SSL_CA_FAIL,      /* client cert verification failed in the CA chain */
	CO_ER_SSL_CRT_FAIL,     /* client cert verification failed on the certificate */
	CO_ER_SSL_MISMATCH,     /* Server presented an SSL certificate different from the configured one */
	CO_ER_SSL_MISMATCH_SNI, /* Server presented an SSL certificate different from the expected one */
	CO_ER_SSL_HANDSHAKE,    /* SSL error during handshake */
	CO_ER_SSL_HANDSHAKE_HB, /* SSL error during handshake with heartbeat present */
	CO_ER_SSL_KILLED_HB,    /* Stopped a TLSv1 heartbeat attack (CVE-2014-0160) */
	CO_ER_SSL_NO_TARGET,    /* unknown target (not client nor server) */
	CO_ER_SSL_EARLY_FAILED, /* Server refused early data */

	CO_ER_SOCKS4_SEND,       /* SOCKS4 Proxy write error during handshake */
	CO_ER_SOCKS4_RECV,       /* SOCKS4 Proxy read error during handshake */
	CO_ER_SOCKS4_DENY,       /* SOCKS4 Proxy deny the request */
	CO_ER_SOCKS4_ABORT,      /* SOCKS4 Proxy handshake aborted by server */

	CO_ERR_SSL_FATAL,        /* SSL fatal error during a SSL_read or SSL_write */

	CO_ER_REVERSE,           /* Error during reverse connect */
};

/* error return codes for accept_conn() */
enum {
	CO_AC_NONE = 0,  /* no error, valid connection returned */
	CO_AC_DONE,      /* reached the end of the queue (typically EAGAIN) */
	CO_AC_RETRY,     /* late signal delivery or anything requiring the caller to try again */
	CO_AC_YIELD,     /* short-lived limitation that requires a short pause */
	CO_AC_PAUSE,     /* long-lived issue (resource/memory allocation error, paused FD) */
	CO_AC_PERMERR,   /* permanent, non-recoverable error (e.g. closed listener socket) */
};

/* source address settings for outgoing connections */
enum {
	/* Tproxy exclusive values from 0 to 7 */
	CO_SRC_TPROXY_ADDR = 0x0001,    /* bind to this non-local address when connecting */
	CO_SRC_TPROXY_CIP  = 0x0002,    /* bind to the client's IP address when connecting */
	CO_SRC_TPROXY_CLI  = 0x0003,    /* bind to the client's IP+port when connecting */
	CO_SRC_TPROXY_DYN  = 0x0004,    /* bind to a dynamically computed non-local address */
	CO_SRC_TPROXY_MASK = 0x0007,    /* bind to a non-local address when connecting */

	CO_SRC_BIND        = 0x0008,    /* bind to a specific source address when connecting */
};

/* flags that can be passed to xprt->rcv_buf() and mux->rcv_buf() */
enum {
	CO_RFL_BUF_WET       = 0x0001,    /* Buffer still has some output data present */
	CO_RFL_BUF_FLUSH     = 0x0002,    /* Flush mux's buffers but don't read more data */
	CO_RFL_READ_ONCE     = 0x0004,    /* don't loop even if the request/response is small */
	CO_RFL_KEEP_RECV     = 0x0008,    /* Instruct the mux to still wait for read events  */
	CO_RFL_BUF_NOT_STUCK = 0x0010,    /* Buffer is not stuck. Optims are possible during data copy */
	CO_RFL_MAY_SPLICE    = 0x0020,    /* The producer can use the kernel splicing */
};

/* flags that can be passed to xprt->snd_buf() and mux->snd_buf() */
enum {
	CO_SFL_MSG_MORE    = 0x0001,    /* More data to come afterwards */
	CO_SFL_STREAMER    = 0x0002,    /* Producer is continuously streaming data */
};

/* mux->shutr() modes */
enum co_shr_mode {
	CO_SHR_DRAIN        = 0,           /* read shutdown, drain any extra stuff */
	CO_SHR_RESET        = 1,           /* read shutdown, reset any extra stuff */
};

/* mux->shutw() modes */
enum co_shw_mode {
	CO_SHW_NORMAL       = 0,           /* regular write shutdown */
	CO_SHW_SILENT       = 1,           /* imminent close, don't notify peer */
};

/* known transport layers (for ease of lookup) */
enum {
	XPRT_RAW = 0,
	XPRT_SSL = 1,
	XPRT_HANDSHAKE = 2,
	XPRT_QUIC = 3,
	XPRT_ENTRIES /* must be last one */
};

/* MUX-specific flags */
enum {
	MX_FL_NONE        = 0x00000000,
	MX_FL_HTX         = 0x00000001, /* set if it is an HTX multiplexer */
	MX_FL_HOL_RISK    = 0x00000002, /* set if the protocol is subject the to head-of-line blocking on server */
	MX_FL_NO_UPG      = 0x00000004, /* set if mux does not support any upgrade */
	MX_FL_FRAMED      = 0x00000008, /* mux working on top of a framed transport layer (QUIC) */
	MX_FL_REVERSABLE  = 0x00000010, /* mux supports connection reversal */
};

/* PROTO token registration */
enum proto_proxy_mode {
	PROTO_MODE_NONE = 0,
	PROTO_MODE_TCP  = 1 << 0, // must not be changed!
	PROTO_MODE_HTTP = 1 << 1, // must not be changed!
	PROTO_MODE_ANY  = PROTO_MODE_TCP | PROTO_MODE_HTTP,
};

enum proto_proxy_side {
	PROTO_SIDE_NONE = 0,
	PROTO_SIDE_FE   = 1, // same as PR_CAP_FE
	PROTO_SIDE_BE   = 2, // same as PR_CAP_BE
	PROTO_SIDE_BOTH = PROTO_SIDE_FE | PROTO_SIDE_BE,
};

/* ctl command used by mux->ctl() */
enum mux_ctl_type {
	MUX_CTL_STATUS, /* Expects an int as output, sets it to a combinaison of MUX_CTL_STATUS flags */
	MUX_CTL_EXIT_STATUS, /* Expects an int as output, sets the mux exist/error/http status, if known or 0 */
	MUX_CTL_REVERSE_CONN, /* Notify about an active reverse connection accepted. */
	MUX_CTL_SUBS_RECV, /* Notify the mux it must wait for read events again  */
	MUX_CTL_GET_GLITCHES, /* returns number of glitches on the connection */
};

/* sctl command used by mux->sctl() */
enum mux_sctl_type {
	MUX_SCTL_SID, /* Return the mux stream ID as output, as a signed 64bits integer */
};

/* response for ctl MUX_STATUS */
#define MUX_STATUS_READY (1 << 0)

enum mux_exit_status {
	MUX_ES_SUCCESS,      /* Success */
	MUX_ES_INVALID_ERR,  /* invalid input */
	MUX_ES_TOUT_ERR,     /* timeout */
	MUX_ES_NOTIMPL_ERR,  /* not-implemented error */
	MUX_ES_INTERNAL_ERR, /* internal error */
	MUX_ES_UNKNOWN       /* unknown status (must be the last) */
};

/* socks4 response length */
#define SOCKS4_HS_RSP_LEN 8

/* socks4 upstream proxy definitions */
struct socks4_request {
	uint8_t version;	/* SOCKS version number, 1 byte, must be 0x04 for this version */
	uint8_t command;	/* 0x01 = establish a TCP/IP stream connection */
	uint16_t port;		/* port number, 2 bytes (in network byte order) */
	uint32_t ip;		/* IP address, 4 bytes (in network byte order) */
	char user_id[8];	/* the user ID string, variable length, terminated with a null (0x00); Using "HAProxy\0" */
};

/* Describes a set of subscriptions. Multiple events may be registered at the
 * same time. The callee should assume everything not pending for completion is
 * implicitly possible. It's illegal to change the tasklet if events are still
 * registered.
 */
struct wait_event {
	struct tasklet *tasklet;
	int events;             /* set of enum sub_event_type above */
};

/* A connection handle is how we differentiate two connections on the lower
 * layers. It usually is a file descriptor but can be a connection id. The
 * CO_FL_FDLESS flag indicates which one is relevant.
 */
union conn_handle {
	struct quic_conn *qc;   /* Only present if this connection is a QUIC one (CO_FL_FDLESS=1) */
	int fd;                 /* file descriptor, for regular sockets (CO_FL_FDLESS=0) */
};

/* xprt_ops describes transport-layer operations for a connection. They
 * generally run over a socket-based control layer, but not always. Some
 * of them are used for data transfer with the upper layer (rcv_*, snd_*)
 * and the other ones are used to setup and release the transport layer.
 */
struct xprt_ops {
	size_t (*rcv_buf)(struct connection *conn, void *xprt_ctx, struct buffer *buf, size_t count, int flags); /* recv callback */
	size_t (*snd_buf)(struct connection *conn, void *xprt_ctx, const struct buffer *buf, size_t count, int flags); /* send callback */
	int  (*rcv_pipe)(struct connection *conn, void *xprt_ctx, struct pipe *pipe, unsigned int count); /* recv-to-pipe callback */
	int  (*snd_pipe)(struct connection *conn, void *xprt_ctx, struct pipe *pipe, unsigned int count); /* send-to-pipe callback */
	void (*shutr)(struct connection *conn, void *xprt_ctx, int);    /* shutr function */
	void (*shutw)(struct connection *conn, void *xprt_ctx, int);    /* shutw function */
	void (*close)(struct connection *conn, void *xprt_ctx);         /* close the transport layer */
	int  (*init)(struct connection *conn, void **ctx);      /* initialize the transport layer */
	int  (*start)(struct connection *conn, void *ctx);      /* Start the transport layer, if needed */
	int  (*prepare_bind_conf)(struct bind_conf *conf); /* prepare a whole bind_conf */
	void (*destroy_bind_conf)(struct bind_conf *conf); /* destroy a whole bind_conf */
	int  (*prepare_srv)(struct server *srv);    /* prepare a server context */
	void (*destroy_srv)(struct server *srv);    /* destroy a server context */
	int  (*get_alpn)(const struct connection *conn, void *xprt_ctx, const char **str, int *len); /* get application layer name */
	int (*takeover)(struct connection *conn, void *xprt_ctx, int orig_tid); /* Let the xprt know the fd have been taken over */
	void (*set_idle)(struct connection *conn, void *xprt_ctx); /* notify the xprt that the connection becomes idle. implies set_used. */
	void (*set_used)(struct connection *conn, void *xprt_ctx); /* notify the xprt that the connection leaves idle. implies set_idle. */
	char name[8];                               /* transport layer name, zero-terminated */
	int (*subscribe)(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es); /* Subscribe <es> to events, such as "being able to send" */
	int (*unsubscribe)(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es); /* Unsubscribe <es> from events */
	int (*remove_xprt)(struct connection *conn, void *xprt_ctx, void *toremove_ctx, const struct xprt_ops *newops, void *newctx); /* Remove an xprt from the connection, used by temporary xprt such as the handshake one */
	int (*add_xprt)(struct connection *conn, void *xprt_ctx, void *toadd_ctx, const struct xprt_ops *toadd_ops, void **oldxprt_ctx, const struct xprt_ops **oldxprt_ops); /* Add a new XPRT as the new xprt, and return the old one */
	struct ssl_sock_ctx *(*get_ssl_sock_ctx)(struct connection *); /* retrieve the ssl_sock_ctx in use, or NULL if none */
	int (*show_fd)(struct buffer *, const struct connection *, const void *ctx); /* append some data about xprt for "show fd"; returns non-zero if suspicious */
};

/* mux_ops describes the mux operations, which are to be performed at the
 * connection level after data are exchanged with the transport layer in order
 * to propagate them to streams. The <init> function will automatically be
 * called once the mux is instantiated by the connection's owner at the end
 * of a transport handshake, when it is about to transfer data and the data
 * layer is not ready yet.
 */
struct mux_ops {
	int  (*init)(struct connection *conn, struct proxy *prx, struct session *sess, struct buffer *input);  /* early initialization */
	int  (*wake)(struct connection *conn);        /* mux-layer callback to report activity, mandatory */
	size_t (*rcv_buf)(struct stconn *sc, struct buffer *buf, size_t count, int flags); /* Called from the upper layer to get data */
	size_t (*snd_buf)(struct stconn *sc, struct buffer *buf, size_t count, int flags); /* Called from the upper layer to send data */
	size_t (*nego_fastfwd)(struct stconn *sc, struct buffer *input, size_t count, unsigned int may_splice); /* Callback to fill the SD iobuf */
	size_t (*done_fastfwd)(struct stconn *sc); /* Callback to terminate fast data forwarding */
	int (*fastfwd)(struct stconn *sc, unsigned int count, unsigned int flags); /* Callback to init fast data forwarding */
	int (*resume_fastfwd)(struct stconn *sc, unsigned int flags); /* Callback to resume fast data forwarding */
	void (*shutr)(struct stconn *sc, enum co_shr_mode);     /* shutr function */
	void (*shutw)(struct stconn *sc, enum co_shw_mode);     /* shutw function */

	int (*attach)(struct connection *conn, struct sedesc *, struct session *sess); /* attach a stconn to an outgoing connection */
	struct stconn *(*get_first_sc)(const struct connection *); /* retrieves any valid stconn from this connection */
	void (*detach)(struct sedesc *); /* Detach an stconn from the stdesc from an outgoing connection, when the request is done */
	int (*show_fd)(struct buffer *, struct connection *); /* append some data about connection into chunk for "show fd"; returns non-zero if suspicious */
	int (*show_sd)(struct buffer *, struct sedesc *, const char *pfx); /* append some data about the mux stream into chunk for "show sess"; returns non-zero if suspicious */
	int (*subscribe)(struct stconn *sc, int event_type,  struct wait_event *es); /* Subscribe <es> to events, such as "being able to send" */
	int (*unsubscribe)(struct stconn *sc, int event_type,  struct wait_event *es); /* Unsubscribe <es> from events */
	int (*sctl)(struct stconn *sc, enum mux_sctl_type mux_sctl, void *arg); /* Provides information about the mux stream */
	int (*avail_streams)(struct connection *conn); /* Returns the number of streams still available for a connection */
	int (*avail_streams_bidi)(struct connection *conn); /* Returns the number of bidirectional streams still available for a connection */
	int (*avail_streams_uni)(struct connection *conn); /* Returns the number of unidirectional streams still available for a connection */
	int (*used_streams)(struct connection *conn);  /* Returns the number of streams in use on a connection. */
	void (*destroy)(void *ctx); /* Let the mux know one of its users left, so it may have to disappear */
	int (*ctl)(struct connection *conn, enum mux_ctl_type mux_ctl, void *arg); /* Provides information about the mux connection */
	int (*takeover)(struct connection *conn, int orig_tid); /* Attempts to migrate the connection to the current thread */
	unsigned int flags;                           /* some flags characterizing the mux's capabilities (MX_FL_*) */
	char name[8];                                 /* mux layer name, zero-terminated */
};

/* list of frontend connections. Used to call mux wake operation on soft-stop
 * to close idling connections.
 */
struct mux_stopping_data {
	struct list list; /* list of registered frontend connections */
	struct task *task; /* task woken up on soft-stop */
};

struct my_tcphdr {
	uint16_t source;
	uint16_t dest;
};

/* a connection source profile defines all the parameters needed to properly
 * bind an outgoing connection for a server or proxy.
 */
struct conn_src {
	unsigned int opts;                   /* CO_SRC_* */
	int iface_len;                       /* bind interface name length */
	char *iface_name;                    /* bind interface name or NULL */
	struct port_range *sport_range;      /* optional per-server TCP source ports */
	struct sockaddr_storage source_addr; /* the address to which we want to bind for connect() */
#if defined(CONFIG_HAP_TRANSPARENT)
	struct sockaddr_storage tproxy_addr; /* non-local address we want to bind to for connect() */
	char *bind_hdr_name;                 /* bind to this header name if defined */
	int bind_hdr_len;                    /* length of the name of the header above */
	int bind_hdr_occ;                    /* occurrence number of header above: >0 = from first, <0 = from end, 0=disabled */
#endif
};

/* Hash header flag reflecting the input parameters present
 * CAUTION! Always update CONN_HASH_PARAMS_TYPE_COUNT when adding a new entry.
 */
enum conn_hash_params_t {
	CONN_HASH_PARAMS_TYPE_SNI      = 0x1,
	CONN_HASH_PARAMS_TYPE_DST_ADDR = 0x2,
	CONN_HASH_PARAMS_TYPE_DST_PORT = 0x4,
	CONN_HASH_PARAMS_TYPE_SRC_ADDR = 0x8,
	CONN_HASH_PARAMS_TYPE_SRC_PORT = 0x10,
	CONN_HASH_PARAMS_TYPE_PROXY    = 0x20,
};
#define CONN_HASH_PARAMS_TYPE_COUNT 6

#define CONN_HASH_PAYLOAD_LEN \
	(((sizeof(((struct conn_hash_node *)0)->node.key)) * 8) - CONN_HASH_PARAMS_TYPE_COUNT)

#define CONN_HASH_GET_PAYLOAD(hash) \
	(((hash) << CONN_HASH_PARAMS_TYPE_COUNT) >> CONN_HASH_PARAMS_TYPE_COUNT)

/* To avoid overflow, dynamically sized parameters must be pre-hashed. Their
 * hashed will then be reused as input for the generation of the final
 * connection hash.
 */
struct conn_hash_params {
	uint64_t sni_prehash;
	uint64_t proxy_prehash;
	void *target;
	struct sockaddr_storage *src_addr;
	struct sockaddr_storage *dst_addr;
};

/*
 * This structure describes an TLV entry consisting of its type
 * and corresponding payload. This can be used to construct a list
 * from which arbitrary TLV payloads can be fetched.
 * It might be possible to embed the 'tlv struct' here in the future.
 */
struct conn_tlv_list {
	struct list list;
	unsigned short len; // 65535 should be more than enough!
	unsigned char type;
	char value[0];
} __attribute__((packed));

/* This structure describes a connection with its methods and data.
 * A connection may be performed to proxy or server via a local or remote
 * socket, and can also be made to an internal applet. It can support
 * several transport schemes (raw, ssl, ...). It can support several
 * connection control schemes, generally a protocol for socket-oriented
 * connections, but other methods for applets.
 */
struct connection {
	/* first cache line */
	enum obj_type obj_type;       /* differentiates connection from applet context */
	unsigned char err_code;       /* CO_ER_* */
	signed short send_proxy_ofs;  /* <0 = offset to (re)send from the end, >0 = send all (reused for SOCKS4) */
	unsigned int flags;           /* CO_FL_* */
	const struct protocol *ctrl;  /* operations at the socket layer */
	const struct xprt_ops *xprt;  /* operations at the transport layer */
	const struct mux_ops  *mux;   /* mux layer operations. Must be set before xprt->init() */
	void *xprt_ctx;               /* general purpose pointer, initialized to NULL */
	void *ctx;                    /* highest level context (usually the mux), initialized to NULL */
	void *owner;                  /* pointer to the owner session, or NULL */
	enum obj_type *target;        /* the target to connect to (server, proxy, applet, ...) */

	/* second cache line */
	struct wait_event *subs; /* Task to wake when awaited events are ready */
	union {
		struct list    idle_list; /* list element for idle connection in server idle list */
		struct mt_list toremove_list; /* list element when idle connection is ready to be purged */
	};
	union {
		struct list session_list;  /* used by backend conns, list of attached connections to a session */
		struct list stopping_list; /* used by frontend conns, attach point in mux stopping list */
	};
	union conn_handle handle;     /* connection handle at the socket layer */
	const struct netns_entry *proxy_netns;

	/* third cache line and beyond */
	void (*destroy_cb)(struct connection *conn);  /* callback to notify of imminent death of the connection */
	struct sockaddr_storage *src; /* source address (pool), when known, otherwise NULL */
	struct sockaddr_storage *dst; /* destination address (pool), when known, otherwise NULL */
	struct list tlv_list;         /* list of TLVs received via PROXYv2 */

	/* used to identify a backend connection for http-reuse,
	 * thus only present if conn.target is of type OBJ_TYPE_SERVER
	 */
	struct conn_hash_node *hash_node;

	/* Members used if connection must be reversed. */
	struct {
		enum obj_type *target; /* Listener for active reverse, server for passive. */
		struct buffer name;    /* Only used for passive reverse. Used as SNI when connection added to server idle pool. */
	} reverse;
};

/* node for backend connection in the idle trees for http-reuse
 * A connection is identified by a hash generated from its specific parameters
 */
struct conn_hash_node {
	struct eb64_node node;   /* contains the hashing key */
	struct connection *conn; /* connection owner of the node */
};

struct mux_proto_list {
	const struct ist token;    /* token name and length. Empty is catch-all */
	enum proto_proxy_mode mode;
	enum proto_proxy_side side;
	const struct mux_ops *mux;
	struct list list;
};

/* proxy protocol stuff below */

/* proxy protocol v2 definitions */
#define PP2_SIGNATURE        "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
#define PP2_SIGNATURE_LEN    12
#define PP2_HEADER_LEN       16

/* ver_cmd byte */
#define PP2_CMD_LOCAL        0x00
#define PP2_CMD_PROXY        0x01
#define PP2_CMD_MASK         0x0F

#define PP2_VERSION          0x20
#define PP2_VERSION_MASK     0xF0

/* fam byte */
#define PP2_TRANS_UNSPEC     0x00
#define PP2_TRANS_STREAM     0x01
#define PP2_TRANS_DGRAM      0x02
#define PP2_TRANS_MASK       0x0F

#define PP2_FAM_UNSPEC       0x00
#define PP2_FAM_INET         0x10
#define PP2_FAM_INET6        0x20
#define PP2_FAM_UNIX         0x30
#define PP2_FAM_MASK         0xF0

#define PP2_ADDR_LEN_UNSPEC  (0)
#define PP2_ADDR_LEN_INET    (4 + 4 + 2 + 2)
#define PP2_ADDR_LEN_INET6   (16 + 16 + 2 + 2)
#define PP2_ADDR_LEN_UNIX    (108 + 108)

#define PP2_HDR_LEN_UNSPEC   (PP2_HEADER_LEN + PP2_ADDR_LEN_UNSPEC)
#define PP2_HDR_LEN_INET     (PP2_HEADER_LEN + PP2_ADDR_LEN_INET)
#define PP2_HDR_LEN_INET6    (PP2_HEADER_LEN + PP2_ADDR_LEN_INET6)
#define PP2_HDR_LEN_UNIX     (PP2_HEADER_LEN + PP2_ADDR_LEN_UNIX)

#define PP2_TYPE_ALPN           0x01
#define PP2_TYPE_AUTHORITY      0x02
#define PP2_TYPE_CRC32C         0x03
#define PP2_TYPE_NOOP           0x04
#define PP2_TYPE_UNIQUE_ID      0x05
#define PP2_TYPE_SSL            0x20
#define PP2_SUBTYPE_SSL_VERSION 0x21
#define PP2_SUBTYPE_SSL_CN      0x22
#define PP2_SUBTYPE_SSL_CIPHER  0x23
#define PP2_SUBTYPE_SSL_SIG_ALG 0x24
#define PP2_SUBTYPE_SSL_KEY_ALG 0x25
#define PP2_TYPE_NETNS          0x30

#define PP2_CLIENT_SSL           0x01
#define PP2_CLIENT_CERT_CONN     0x02
#define PP2_CLIENT_CERT_SESS     0x04

#define PP2_CRC32C_LEN 4 /* Length of a CRC32C TLV value */

#define TLV_HEADER_SIZE 3

#define HA_PP2_AUTHORITY_MAX 255  /* Maximum length of an authority TLV */
#define HA_PP2_TLV_VALUE_128 128  /* E.g., accommodate unique IDs (128 B) */
#define HA_PP2_TLV_VALUE_256 256  /* E.g., accommodate authority TLVs (currently, <= 255 B) */
#define HA_PP2_MAX_ALLOC     1024 /* Maximum TLV value for PPv2 to prevent DoS */

struct proxy_hdr_v2 {
	uint8_t sig[12];   /* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
	uint8_t ver_cmd;   /* protocol version and command */
	uint8_t fam;       /* protocol family and transport */
	uint16_t len;      /* number of following bytes part of the header */
	union {
		struct {   /* for TCP/UDP over IPv4, len = 12 */
			uint32_t src_addr;
			uint32_t dst_addr;
			uint16_t src_port;
			uint16_t dst_port;
		} ip4;
		struct {   /* for TCP/UDP over IPv6, len = 36 */
			uint8_t  src_addr[16];
			uint8_t  dst_addr[16];
			uint16_t src_port;
			uint16_t dst_port;
		} ip6;
		struct {   /* for AF_UNIX sockets, len = 216 */
			uint8_t src_addr[108];
			uint8_t dst_addr[108];
		} unx;
	} addr;
};

struct tlv {
	uint8_t type;
	uint8_t length_hi;
	uint8_t length_lo;
	uint8_t value[0]; // WT: don't use VAR_ARRAY here, it's an end of struct marker
}__attribute__((packed));

struct tlv_ssl {
	struct tlv tlv;
	uint8_t client;
	uint32_t verify;
	uint8_t sub_tlv[VAR_ARRAY];
}__attribute__((packed));


/* This structure is used to manage idle connections, their locking, and the
 * list of such idle connections to be removed. It is per-thread and must be
 * accessible from foreign threads.
 */
struct idle_conns {
	struct mt_list toremove_conns;
	struct task *cleanup_task;
	__decl_thread(HA_SPINLOCK_T idle_conns_lock);
} THREAD_ALIGNED(64);

#endif /* _HAPROXY_CONNECTION_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
