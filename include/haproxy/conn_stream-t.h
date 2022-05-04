/*
 * include/haproxy/conn_stream-t.h
 * This file describes the conn-stream struct and associated constants.
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

/* CS endpoint flags */
 enum {
	 CS_EP_NONE       = 0x00000000, /* For initialization purposes */

	 /* Endpoint types */
	 CS_EP_T_MUX      = 0x00000001, /* The endpoint is a mux (the target may be NULL before the mux init) */
	 CS_EP_T_APPLET   = 0x00000002, /* The endpoint is an applet */

	 /* unused: 0x00000004 .. 0x00000008 */

	 /* Endpoint states: none == attached to a mux with a conn-stream */
	 CS_EP_DETACHED   = 0x00000010, /* The endpoint is detached (no mux/no applet) */
	 CS_EP_ORPHAN     = 0x00000020, /* The endpoint is orphan (no conn-stream) */

	 /* unused: 0x00000040 .. 0x00000080 */

	 CS_EP_SHRD       = 0x00000100,  /* read shut, draining extra data */
	 CS_EP_SHRR       = 0x00000200,  /* read shut, resetting extra data */
	 CS_EP_SHR        = CS_EP_SHRD | CS_EP_SHRR, /* read shut status */

	 CS_EP_SHWN       = 0x00000400,  /* write shut, verbose mode */
	 CS_EP_SHWS       = 0x00000800,  /* write shut, silent mode */
	 CS_EP_SHW        = CS_EP_SHWN | CS_EP_SHWS, /* write shut status */

	/* following flags are supposed to be set by the endpoint and read by
	 * the app layer :
	 */
	 /* Permanent flags */
	CS_EP_NOT_FIRST  = 0x00001000,  /* This conn-stream is not the first one for the endpoint */
	CS_EP_WEBSOCKET  = 0x00002000,  /* The endpoint uses the websocket proto */
	CS_EP_EOI        = 0x00004000,  /* end-of-input reached */
	CS_EP_EOS        = 0x00008000,  /* End of stream delivered to data layer */
	CS_EP_ERROR      = 0x00010000,  /* a fatal error was reported */
	/* Transient flags */
	CS_EP_ERR_PENDING= 0x00020000,  /* An error is pending, but there's still data to be read */
	CS_EP_MAY_SPLICE = 0x00040000,  /* The endpoint may use the kernel splicing to forward data to the other side (implies CS_EP_CAN_SPLICE) */
	CS_EP_RCV_MORE   = 0x00080000,  /* Endpoint may have more bytes to transfer */
	CS_EP_WANT_ROOM  = 0x00100000,  /* More bytes to transfer, but not enough room */
	CS_EP_ENDP_MASK  = 0x001ff000,  /* Mask for flags set by the endpoint */

	/* following flags are supposed to be set by the app layer and read by
	 * the endpoint :
	 */
	CS_EP_WAIT_FOR_HS   = 0x00200000,  /* This stream is waiting for handhskae */
	CS_EP_KILL_CONN     = 0x00400000,  /* must kill the connection when the CS closes */
	CS_EP_WAIT_DATA     = 0x00800000,  /* CS waits for more outgoing data to send */
	CS_EP_WANT_GET      = 0x01000000,  /* CS would like to get some data from the buffer */
	CS_EP_RX_WAIT_EP    = 0x02000000,  /* CS waits for more data from the end point */
	CS_EP_RXBLK_CHAN    = 0x04000000,  /* the channel doesn't want the CS to introduce data */
	CS_EP_RXBLK_BUFF    = 0x08000000,  /* CS waits for a buffer allocation to complete */
	CS_EP_RXBLK_ROOM    = 0x10000000,  /* CS waits for more buffer room to store incoming data */
	CS_EP_RXBLK_SHUT    = 0x20000000,  /* input is now closed, nothing new will ever come */
	CS_EP_RXBLK_CONN    = 0x40000000,  /* other side is not connected */
	CS_EP_RXBLK_ANY     = 0x7C000000,  /* any of the RXBLK flags above */
	CS_EP_APP_MASK      = 0x7fe00000,  /* Mask for flags set by the app layer */
 };

/* conn_stream flags */
enum {
	CS_FL_NONE          = 0x00000000,  /* Just for initialization purposes */
	CS_FL_ISBACK        = 0x00000001,  /* Set for CS on back-side */

	/* not used: 0x00000002 */
	/* not used: 0x00000004 */

	CS_FL_NOLINGER      = 0x00000008,  /* may close without lingering. One-shot. */
	CS_FL_NOHALF        = 0x00000010,  /* no half close, close both sides at once */
	CS_FL_DONT_WAKE     = 0x00000020,  /* resync in progress, don't wake up */
	CS_FL_INDEP_STR     = 0x00000040,  /* independent streams = don't update rex on write */
};

/* A conn stream must have its own errors independently of the buffer's, so that
 * applications can rely on what the buffer reports while the conn stream is
 * performing some retries (eg: connection error). Some states are transient and
 * do not last beyond process_session().
 */
enum cs_state {
	CS_ST_INI = 0,           /* CS not sollicitated yet */
	CS_ST_REQ,               /* [transient] connection initiation desired and not started yet */
	CS_ST_QUE,               /* CS waiting in queue */
	CS_ST_TAR,               /* CS in turn-around state after failed connect attempt */
	CS_ST_ASS,               /* server just assigned to this CS */
	CS_ST_CON,               /* initiated connection request (resource exists) */
	CS_ST_CER,               /* [transient] previous connection attempt failed (resource released) */
	CS_ST_RDY,               /* [transient] ready proven after I/O success during CS_ST_CON */
	CS_ST_EST,               /* connection established (resource exists) */
	CS_ST_DIS,               /* [transient] disconnected from other side, but cleanup not done yet */
	CS_ST_CLO,               /* CS closed, might not existing anymore. Buffers shut. */
} __attribute__((packed));

/* state bits for use with lists of states */
enum cs_state_bit {
	CS_SB_NONE = 0,
	CS_SB_INI = 1U << CS_ST_INI,
	CS_SB_REQ = 1U << CS_ST_REQ,
	CS_SB_QUE = 1U << CS_ST_QUE,
	CS_SB_TAR = 1U << CS_ST_TAR,
	CS_SB_ASS = 1U << CS_ST_ASS,
	CS_SB_CON = 1U << CS_ST_CON,
	CS_SB_CER = 1U << CS_ST_CER,
	CS_SB_RDY = 1U << CS_ST_RDY,
	CS_SB_EST = 1U << CS_ST_EST,
	CS_SB_DIS = 1U << CS_ST_DIS,
	CS_SB_CLO = 1U << CS_ST_CLO,
	CS_SB_ALL = CS_SB_INI|CS_SB_REQ|CS_SB_QUE|CS_SB_TAR|CS_SB_ASS|CS_SB_CON|CS_SB_CER|CS_SB_RDY|CS_SB_EST|CS_SB_DIS|CS_SB_CLO,
};

struct conn_stream;

/* cs_data_cb describes the data layer's recv and send callbacks which are called
 * when I/O activity was detected after the transport layer is ready. These
 * callbacks are supposed to make use of the xprt_ops above to exchange data
 * from/to buffers and pipes. The <wake> callback is used to report activity
 * at the transport layer, which can be a connection opening/close, or any
 * data movement. It may abort a connection by returning < 0.
 */
struct data_cb {
	int  (*wake)(struct conn_stream *cs);  /* data-layer callback to report activity */
	char name[8];                           /* data layer name, zero-terminated */
};


/* cs_endpoint is the link between the conn-stream and the endpoint (mux or
 * appctx). It is created by the mux/applet on the client side and share with
 * the conn-stream. On the server side, it is the opposite. A cs-endpoint
 * without conn-stream is called an orphan endpoint. A cs-endpoint with no
 * mux/applet is called a detached endpoint. On detach, the conn-stream
 * transfers the whole responsibility to the mux/applet and eventually create a
 * new cs-endpoint (for instance on connection retries).
 *
 * <target> is the mux or the appctx
 * <ctx>    is the context set and used by <target>
 * <flags>  CS_EP_*
*/
struct cs_endpoint {
	void *target;
	void *ctx;
	unsigned int flags;
};

/* operations available on a conn-stream */
struct cs_app_ops {
	void (*chk_rcv)(struct conn_stream *); /* chk_rcv function, may not be null */
	void (*chk_snd)(struct conn_stream *); /* chk_snd function, may not be null */
	void (*shutr)(struct conn_stream *);   /* shut read function, may not be null */
	void (*shutw)(struct conn_stream *);   /* shut write function, may not be null */
};

/*
 * This structure describes the elements of a connection relevant to a stream
 */
struct conn_stream {
	enum obj_type obj_type;              /* differentiates connection from applet context */
	enum cs_state state;                 /* CS_ST* */
	/* 2 bytes hole here */

	unsigned int flags;                  /* CS_FL_* */
	unsigned int hcto;                   /* half-closed timeout (0 = unset) */
	struct wait_event wait_event;        /* We're in a wait list */
	struct cs_endpoint *endp;            /* points to the end point (MUX stream or appctx) */
	enum obj_type *app;                  /* points to the applicative point (stream or check) */
	const struct data_cb *data_cb;       /* data layer callbacks. Must be set before xprt->init() */
	struct cs_app_ops *ops;              /* general operations used at the app layer */
	struct sockaddr_storage *src;        /* source address (pool), when known, otherwise NULL */
	struct sockaddr_storage *dst;        /* destination address (pool), when known, otherwise NULL */
};


#endif /* _HAPROXY_CONN_STREAM_T_H */
