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

/* conn_stream flags */
enum {
	CS_FL_NONE          = 0x00000000,  /* Just for initialization purposes */
	CS_FL_SHRD          = 0x00000010,  /* read shut, draining extra data */
	CS_FL_SHRR          = 0x00000020,  /* read shut, resetting extra data */
	CS_FL_SHR           = CS_FL_SHRD | CS_FL_SHRR, /* read shut status */

	CS_FL_SHWN          = 0x00000040,  /* write shut, verbose mode */
	CS_FL_SHWS          = 0x00000080,  /* write shut, silent mode */
	CS_FL_SHW           = CS_FL_SHWN | CS_FL_SHWS, /* write shut status */


	CS_FL_ERROR         = 0x00000100,  /* a fatal error was reported */
	CS_FL_RCV_MORE      = 0x00000200,  /* We may have more bytes to transfer */
	CS_FL_WANT_ROOM     = 0x00000400,  /* More bytes to transfer, but not enough room */
	CS_FL_ERR_PENDING   = 0x00000800,  /* An error is pending, but there's still data to be read */
	CS_FL_EOS           = 0x00001000,  /* End of stream delivered to data layer */
	/* unused: 0x00002000 */
	CS_FL_EOI           = 0x00004000,  /* end-of-input reached */
	CS_FL_MAY_SPLICE    = 0x00008000,  /* caller may use rcv_pipe() only if this flag is set */
	CS_FL_WAIT_FOR_HS   = 0x00010000,  /* This stream is waiting for handhskae */
	CS_FL_KILL_CONN     = 0x00020000,  /* must kill the connection when the CS closes */

	/* following flags are supposed to be set by the mux and read/unset by
	 * the stream-interface :
	 */
	CS_FL_NOT_FIRST     = 0x00100000,  /* this stream is not the first one */

	/* flags set by the mux relayed to the stream */
	CS_FL_WEBSOCKET     = 0x00200000,  /* websocket stream */
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

/*
 * This structure describes the elements of a connection relevant to a stream
 */
struct conn_stream {
	enum obj_type obj_type;              /* differentiates connection from applet context */
	/* 3 bytes hole here */
	unsigned int flags;                  /* CS_FL_* */
	enum obj_type *end;                  /* points to the end point (connection or appctx) */
	enum obj_type *app;                  /* points to the applicative point (stream or check) */
	struct stream_interface *si;
	const struct data_cb *data_cb;       /* data layer callbacks. Must be set before xprt->init() */
	void *ctx;                           /* mux-specific context */
};


#endif /* _HAPROXY_CONN_STREAM_T_H */
