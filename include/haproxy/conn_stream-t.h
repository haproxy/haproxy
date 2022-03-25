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

struct stream_interface;

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

	 /* unused: 0x00200000 ..  0x00800000 */

	/* following flags are supposed to be set by the app layer and read by
	 * the endpoint :
	 */
	CS_EP_WAIT_FOR_HS   = 0x01000000,  /* This stream is waiting for handhskae */
	CS_EP_KILL_CONN     = 0x02000000,  /* must kill the connection when the CS closes */
 };

/* conn_stream flags */
enum {
	CS_FL_NONE          = 0x00000000,  /* Just for initialization purposes */
	CS_FL_ISBACK        = 0x00000001,  /* Set for CS on back-side */
};

/* cs_shutr() modes */
enum cs_shr_mode {
	CS_SHR_DRAIN        = 0,           /* read shutdown, drain any extra stuff */
	CS_SHR_RESET        = 1,           /* read shutdown, reset any extra stuff */
};

/* cs_shutw() modes */
enum cs_shw_mode {
	CS_SHW_NORMAL       = 0,           /* regular write shutdown */
	CS_SHW_SILENT       = 1,           /* imminent close, don't notify peer */
};

struct conn_stream;

/* data_cb describes the data layer's recv and send callbacks which are called
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


struct cs_endpoint {
	void *target;
	void *ctx;
	unsigned int flags;
};

/*
 * This structure describes the elements of a connection relevant to a stream
 */
struct conn_stream {
	enum obj_type obj_type;              /* differentiates connection from applet context */
	/* 3 bytes hole here */
	unsigned int flags;                  /* CS_FL_* */
	struct cs_endpoint *endp;            /* points to the end point (MUX stream or appctx) */
	enum obj_type *app;                  /* points to the applicative point (stream or check) */
	struct stream_interface *si;
	const struct data_cb *data_cb;       /* data layer callbacks. Must be set before xprt->init() */
};


#endif /* _HAPROXY_CONN_STREAM_T_H */
