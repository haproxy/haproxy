/*
 * include/haproxy/conn_stream-t.h
 * This file describes the stream connector struct and associated constants.
 *
 * Copyright 2021 Christopher Faulet <cfaulet@haproxy.com>
 *
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

#ifndef _HAPROXY_CONN_STREAM_T_H
#define _HAPROXY_CONN_STREAM_T_H

#include <haproxy/obj_type-t.h>
#include <haproxy/connection-t.h>

/* Stream Endpoint Flags */
enum se_flags {
	SE_FL_NONE       = 0x00000000, /* For initialization purposes */

	 /* Endpoint types */
	SE_FL_T_MUX      = 0x00000001, /* The endpoint is a mux (the target may be NULL before the mux init) */
	SE_FL_T_APPLET   = 0x00000002, /* The endpoint is an applet */

	 /* unused: 0x00000004 .. 0x00000008 */

	 /* Endpoint states: none == attached to a mux with a stream connector */
	SE_FL_DETACHED   = 0x00000010, /* The endpoint is detached (no mux/no applet) */
	SE_FL_ORPHAN     = 0x00000020, /* The endpoint is orphan (no stream connector) */

	 /* unused: 0x00000040 .. 0x00000080 */

	SE_FL_SHRD       = 0x00000100,  /* read shut, draining extra data */
	SE_FL_SHRR       = 0x00000200,  /* read shut, resetting extra data */
	SE_FL_SHR        = SE_FL_SHRD | SE_FL_SHRR, /* read shut status */

	SE_FL_SHWN       = 0x00000400,  /* write shut, verbose mode */
	SE_FL_SHWS       = 0x00000800,  /* write shut, silent mode */
	SE_FL_SHW        = SE_FL_SHWN | SE_FL_SHWS, /* write shut status */

	/* following flags are supposed to be set by the endpoint and read by
	 * the app layer :
	 */

	 /* Permanent flags */
	SE_FL_NOT_FIRST  = 0x00001000,  /* This stream connector is not the first one for the endpoint */
	SE_FL_WEBSOCKET  = 0x00002000,  /* The endpoint uses the websocket proto */
	SE_FL_EOI        = 0x00004000,  /* end-of-input reached */
	SE_FL_EOS        = 0x00008000,  /* End of stream delivered to data layer */
	SE_FL_ERROR      = 0x00010000,  /* a fatal error was reported */
	/* Transient flags */
	SE_FL_ERR_PENDING= 0x00020000,  /* An error is pending, but there's still data to be read */
	SE_FL_MAY_SPLICE = 0x00040000,  /* The endpoint may use the kernel splicing to forward data to the other side (implies SE_FL_CAN_SPLICE) */
	SE_FL_RCV_MORE   = 0x00080000,  /* Endpoint may have more bytes to transfer */
	SE_FL_WANT_ROOM  = 0x00100000,  /* More bytes to transfer, but not enough room */
	SE_FL_ENDP_MASK  = 0x001ff000,  /* Mask for flags set by the endpoint */

	/* following flags are supposed to be set by the app layer and read by
	 * the endpoint :
	 */
	SE_FL_WAIT_FOR_HS   = 0x00200000,  /* This stream is waiting for handhskae */
	SE_FL_KILL_CONN     = 0x00400000,  /* must kill the connection when the CS closes */
	SE_FL_WAIT_DATA     = 0x00800000,  /* stream endpoint cannot work without more data from the stream's output */
	SE_FL_WILL_CONSUME  = 0x01000000,  /* stream endpoint is interested in consuming more data */
	SE_FL_HAVE_NO_DATA  = 0x02000000,  /* the endpoint has no more data to deliver to the stream */
	SE_FL_APP_MASK      = 0x02e00000,  /* Mask for flags set by the app layer */
	/* unused             0x04000000,*/
	/* unused             0x08000000,*/
	/* unused             0x10000000,*/
	/* unused             0x20000000,*/
	SE_FL_APPLET_NEED_CONN = 0x40000000,  /* applet is waiting for the other side to (fail to) connect */
};

/* stconn flags */
enum sc_flags {
	SC_FL_NONE          = 0x00000000,  /* Just for initialization purposes */
	SC_FL_ISBACK        = 0x00000001,  /* Set for SC on back-side */

	/* not used: 0x00000002 */
	/* not used: 0x00000004 */

	SC_FL_NOLINGER      = 0x00000008,  /* may close without lingering. One-shot. */
	SC_FL_NOHALF        = 0x00000010,  /* no half close, close both sides at once */
	SC_FL_DONT_WAKE     = 0x00000020,  /* resync in progress, don't wake up */
	SC_FL_INDEP_STR     = 0x00000040,  /* independent streams = don't update rex on write */

	SC_FL_WONT_READ     = 0x00000080,  /* SC doesn't want to read data */
	SC_FL_NEED_BUFF     = 0x00000100,  /* SC waits for an rx buffer allocation to complete */
	SC_FL_NEED_ROOM     = 0x00000200,  /* SC needs more room in the rx buffer to store incoming data */
};

/* A conn stream must have its own errors independently of the buffer's, so that
 * applications can rely on what the buffer reports while the conn stream is
 * performing some retries (eg: connection error). Some states are transient and
 * do not last beyond process_session().
 */
enum cs_state {
	SC_ST_INI = 0,           /* CS not sollicitated yet */
	SC_ST_REQ,               /* [transient] connection initiation desired and not started yet */
	SC_ST_QUE,               /* CS waiting in queue */
	SC_ST_TAR,               /* CS in turn-around state after failed connect attempt */
	SC_ST_ASS,               /* server just assigned to this CS */
	SC_ST_CON,               /* initiated connection request (resource exists) */
	SC_ST_CER,               /* [transient] previous connection attempt failed (resource released) */
	SC_ST_RDY,               /* [transient] ready proven after I/O success during SC_ST_CON */
	SC_ST_EST,               /* connection established (resource exists) */
	SC_ST_DIS,               /* [transient] disconnected from other side, but cleanup not done yet */
	SC_ST_CLO,               /* CS closed, might not existing anymore. Buffers shut. */
} __attribute__((packed));

/* state bits for use with lists of states */
enum cs_state_bit {
	SC_SB_NONE = 0,
	SC_SB_INI = 1U << SC_ST_INI,
	SC_SB_REQ = 1U << SC_ST_REQ,
	SC_SB_QUE = 1U << SC_ST_QUE,
	SC_SB_TAR = 1U << SC_ST_TAR,
	SC_SB_ASS = 1U << SC_ST_ASS,
	SC_SB_CON = 1U << SC_ST_CON,
	SC_SB_CER = 1U << SC_ST_CER,
	SC_SB_RDY = 1U << SC_ST_RDY,
	SC_SB_EST = 1U << SC_ST_EST,
	SC_SB_DIS = 1U << SC_ST_DIS,
	SC_SB_CLO = 1U << SC_ST_CLO,
	SC_SB_ALL = SC_SB_INI|SC_SB_REQ|SC_SB_QUE|SC_SB_TAR|SC_SB_ASS|SC_SB_CON|SC_SB_CER|SC_SB_RDY|SC_SB_EST|SC_SB_DIS|SC_SB_CLO,
};

struct stconn;

/* A Stream Endpoint Descriptor (sedesc) is the link between the stream
 * connector (ex. conn_stream) and the Stream Endpoint (mux or appctx).
 * It always exists for either of them, and binds them together. It also
 * contains some shared information relative to the endpoint. It is created by
 * the first one which needs it and is shared by the other one, i.e. on the
 * client side, it's created the mux or applet and shared with the connector.
 * An sedesc without stconn is called an ORPHANED descriptor. An sedesc with
 * no mux/applet is called a DETACHED descriptor. Upon detach, the connector
 * transfers the whole responsibility of the endpoint descriptor to the
 * endpoint itself (mux/applet) and eventually creates a new sedesc (for
 * instance on connection retries).
 *
 * <se>     is the stream endpoint, i.e. the mux stream or the appctx
 * <conn>   is the connection for connection-based streams
 * <sc>     is the stream connector we're attached to, or NULL
 * <flags>  SE_FL_*
*/
struct sedesc {
	void *se;
	struct connection *conn;
	struct stconn *sc;
	unsigned int flags;
};

/* sc_app_ops describes the application layer's operations and notification
 * callbacks when I/O activity is reported and to use to perform shutr/shutw.
 * There are very few combinations in practice (strm/chk <-> none/mux/applet).
 */
struct sc_app_ops {
	void (*chk_rcv)(struct stconn *);    /* chk_rcv function, may not be null */
	void (*chk_snd)(struct stconn *);    /* chk_snd function, may not be null */
	void (*shutr)(struct stconn *);      /* shut read function, may not be null */
	void (*shutw)(struct stconn *);      /* shut write function, may not be null */
	int  (*wake)(struct stconn *);       /* data-layer callback to report activity */
	char name[8];                        /* data layer name, zero-terminated */
};

/*
 * This structure describes the elements of a connection relevant to a stream
 */
struct stconn {
	enum obj_type obj_type;              /* differentiates connection from applet context */
	enum cs_state state;                 /* CS_ST* */
	/* 2 bytes hole here */

	unsigned int flags;                  /* SC_FL_* */
	unsigned int hcto;                   /* half-closed timeout (0 = unset) */
	struct wait_event wait_event;        /* We're in a wait list */
	struct sedesc *sedesc;               /* points to the stream endpoint descriptor */
	enum obj_type *app;                  /* points to the applicative point (stream or check) */
	const struct sc_app_ops *app_ops;    /* general operations used at the app layer */
	struct sockaddr_storage *src;        /* source address (pool), when known, otherwise NULL */
	struct sockaddr_storage *dst;        /* destination address (pool), when known, otherwise NULL */
};


#endif /* _HAPROXY_CONN_STREAM_T_H */
