/*
 * include/haproxy/stconn-t.h
 * This file describes the stream connector struct and associated constants.
 *
 * Copyright 2021 Christopher Faulet <cfaulet@haproxy.com>
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

#ifndef _HAPROXY_STCONN_T_H
#define _HAPROXY_STCONN_T_H

#include <haproxy/obj_type-t.h>
#include <haproxy/connection-t.h>
#include <haproxy/pipe-t.h>
#include <haproxy/show_flags-t.h>
#include <haproxy/task-t.h>
#include <haproxy/xref-t.h>

enum iobuf_flags {
	IOBUF_FL_NONE             = 0x00000000, /* For initialization purposes */
	IOBUF_FL_NO_FF            = 0x00000001, /* Fast-forwarding is not supported */
	IOBUF_FL_NO_SPLICING      = 0x00000002, /* Splicing is not supported or unusable for this stream */
	IOBUF_FL_FF_BLOCKED       = 0x00000004, /* Fast-forwarding is blocked (buffer allocation/full) */

	IOBUF_FL_INTERIM_FF       = 0x00000008, /* Producer side warn it will immediately retry a fast-forward.
						 *  .done_fastfwd() on consumer side must take care of this flag
						 */
	IOBUF_FL_EOI              = 0x00000010, /* A EOI was encountered on producer side */
	IOBUF_FL_FF_WANT_ROOM     = 0x00000020, /* Producer need more room in the IOBUF to forward data */
};

/* Flags used */
enum nego_ff_flags {
	NEGO_FF_FL_NONE           = 0x00000000, /* For initialization purposes */
	NEGO_FF_FL_MAY_SPLICE     = 0x00000001, /* Consumer may choose to use kernel splicing if it supports it */
	NEGO_FF_FL_EXACT_SIZE     = 0x00000002, /* Size passed for the nego is the expected exact size to forwarded */
};

struct iobuf {
	struct pipe *pipe;     /* non-NULL only when data present */
	struct buffer *buf;
	size_t offset;
	size_t data;
	unsigned int flags;
};

/* Stream Endpoint Flags.
 * Please also update the se_show_flags() function below in case of changes.
 */
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
	SE_FL_RCV_MORE   = 0x00040000,  /* Endpoint may have more bytes to transfer */
	SE_FL_WANT_ROOM  = 0x00080000,  /* More bytes to transfer, but not enough room */
	SE_FL_EXP_NO_DATA= 0x00100000,  /* No data expected by the endpoint */
	SE_FL_MAY_FASTFWD_PROD = 0x00200000, /* The endpoint may produce data via zero-copy forwarding */
	SE_FL_MAY_FASTFWD_CONS = 0x00400000, /* The endpoint may consume data via zero-copy forwarding */
	SE_FL_ENDP_MASK  = 0x004ff000,  /* Mask for flags set by the endpoint */

	/* following flags are supposed to be set by the app layer and read by
	 * the endpoint :
	 */
	/* unused             0x00800000,*/
	/* unused             0x01000000,*/
	/* unused             0x02000000,*/
	SE_FL_WAIT_FOR_HS   = 0x04000000,  /* This stream is waiting for handhskae */
	SE_FL_KILL_CONN     = 0x08000000,  /* must kill the connection when the SC closes */
	SE_FL_WAIT_DATA     = 0x10000000,  /* stream endpoint cannot work without more data from the stream's output */
	SE_FL_WONT_CONSUME  = 0x20000000,  /* stream endpoint will not consume more data */
	SE_FL_HAVE_NO_DATA  = 0x40000000,  /* the endpoint has no more data to deliver to the stream */
	SE_FL_APPLET_NEED_CONN = 0x80000000,  /* applet is waiting for the other side to (fail to) connect */
};

/* Shutdown modes */
enum se_shut_mode {
	SE_SHR_DRAIN  = 0x00000001, /* read shutdown, drain any extra stuff */
	SE_SHR_RESET  = 0x00000002, /* read shutdown, reset any extra stuff */
	SE_SHW_NORMAL = 0x00000004, /* regular write shutdown */
	SE_SHW_SILENT = 0x00000008, /* imminent close, don't notify peer */
};

/* This function is used to report flags in debugging tools. Please reflect
 * below any single-bit flag addition above in the same order via the
 * __APPEND_FLAG macro. The new end of the buffer is returned.
 */
static forceinline char *se_show_flags(char *buf, size_t len, const char *delim, uint flg)
{
#define _(f, ...) __APPEND_FLAG(buf, len, delim, flg, f, #f, __VA_ARGS__)
	/* prologue */
	_(0);
	/* flags */
	_(SE_FL_T_MUX, _(SE_FL_T_APPLET, _(SE_FL_DETACHED, _(SE_FL_ORPHAN,
	_(SE_FL_SHRD, _(SE_FL_SHRR, _(SE_FL_SHWN, _(SE_FL_SHWS,
	_(SE_FL_NOT_FIRST, _(SE_FL_WEBSOCKET, _(SE_FL_EOI, _(SE_FL_EOS,
	_(SE_FL_ERROR, _(SE_FL_ERR_PENDING,  _(SE_FL_RCV_MORE,
	_(SE_FL_WANT_ROOM, _(SE_FL_EXP_NO_DATA, _(SE_FL_MAY_FASTFWD_PROD, _(SE_FL_MAY_FASTFWD_CONS,
	_(SE_FL_WAIT_FOR_HS, _(SE_FL_KILL_CONN, _(SE_FL_WAIT_DATA,
	_(SE_FL_WONT_CONSUME, _(SE_FL_HAVE_NO_DATA, _(SE_FL_APPLET_NEED_CONN)))))))))))))))))))))))));
	/* epilogue */
	_(~0U);
	return buf;
#undef _
}

/* stconn flags.
 * Please also update the sc_show_flags() function below in case of changes.
 *
 * When SC_FL_ABRT_WANTED/SC_FL_EOS is set, it is strictly forbidden for the
 * producer to alter the buffer contents. In this case, the consumer is free to
 * perform a shutdown when it has consumed the last contents, otherwise the
 * session processor will do it anyway. SC_FL_ABRT* are set at the upper layer
 * level (the stream) while SC_FL_EOS is set at the SE layer.
 *
 * The SC_FL_SHUT_WANTED flaga should be set by the session processor when
 * SC_FLABRT_DONE/SC_FL_EOS and CF_AUTO_CLOSE are both set. And it may also be
 * set by the producer when it detects SC_FL_EOS while directly forwarding data to the
 * consumer.
 *
 * The SHUT/ABRT flags work like this :
 *
 *  ABRT_WANTED ABRT_DONE  meaning
 *      0           0      normal case, connection still open and data is being read
 *      1           0      closing : the producer cannot feed data anymore but can close
 *     0/1          1      closed: the producer has closed its input channel.
 *
 *  SHUT_WANTED SHUT_DONE  meaning
 *      0          0      normal case, connection still open and data is being written
 *      1          0      closing: the consumer can send last data and may then close
 *     0/1         1      closed: the consumer has closed its output channel.
 *
 *
 * The ABRT_WANTED flag is mostly used to force the producer to abort when an error is
 * detected on the consumer side.
 *
 */
enum sc_flags {
	SC_FL_NONE          = 0x00000000,  /* Just for initialization purposes */
	SC_FL_ISBACK        = 0x00000001,  /* Set for SC on back-side */

	SC_FL_EOI           = 0x00000002,  /* End of input was reached. no more data will be received from the endpoint */
	SC_FL_ERROR         = 0x00000004,  /* A fatal error was reported */

	SC_FL_NOLINGER      = 0x00000008,  /* may close without lingering. One-shot. */
	SC_FL_NOHALF        = 0x00000010,  /* no half close, close both sides at once */
	SC_FL_DONT_WAKE     = 0x00000020,  /* resync in progress, don't wake up */
	SC_FL_INDEP_STR     = 0x00000040,  /* independent streams = don't update rex on write */

	SC_FL_WONT_READ     = 0x00000080,  /* SC doesn't want to read data */
	SC_FL_NEED_BUFF     = 0x00000100,  /* SC waits for an rx buffer allocation to complete */
	SC_FL_NEED_ROOM     = 0x00000200,  /* SC needs more room in the rx buffer to store incoming data */

	SC_FL_RCV_ONCE      = 0x00000400,  /* Don't loop to receive data. cleared after a successful receive */
	SC_FL_SND_ASAP      = 0x00000800,  /* Don't wait for sending. cleared when all data were sent */
	SC_FL_SND_NEVERWAIT = 0x00001000,  /* Never wait for sending (permanent) */
	SC_FL_SND_EXP_MORE  = 0x00002000,  /* More data expected to be sent very soon. cleared when all data were sent */

	SC_FL_ABRT_WANTED   = 0x00004000,  /* An abort was requested and must be performed ASAP (up side to down side) */
	SC_FL_SHUT_WANTED   = 0x00008000,  /* A shutdown was requested and mux be performed ASAP (up side to down side) */
	SC_FL_ABRT_DONE     = 0x00010000,  /* An abort was performed for the SC */
	SC_FL_SHUT_DONE     = 0x00020000,  /* A shutdown was performed for the SC */

	SC_FL_EOS           = 0x00040000,  /* End of stream was reached (from down side to up side) */
	SC_FL_HAVE_BUFF     = 0x00080000,  /* A buffer is ready, flag will be cleared once allocated */
};

/* This function is used to report flags in debugging tools. Please reflect
 * below any single-bit flag addition above in the same order via the
 * __APPEND_FLAG macro. The new end of the buffer is returned.
 */
static forceinline char *sc_show_flags(char *buf, size_t len, const char *delim, uint flg)
{
#define _(f, ...) __APPEND_FLAG(buf, len, delim, flg, f, #f, __VA_ARGS__)
	/* prologue */
	_(0);
	/* flags */
	_(SC_FL_ISBACK, _(SC_FL_EOI, _(SC_FL_ERROR, _(SC_FL_NOLINGER, _(SC_FL_NOHALF,
	_(SC_FL_DONT_WAKE, _(SC_FL_INDEP_STR, _(SC_FL_WONT_READ,
	_(SC_FL_NEED_BUFF, _(SC_FL_NEED_ROOM,
        _(SC_FL_RCV_ONCE, _(SC_FL_SND_ASAP, _(SC_FL_SND_NEVERWAIT, _(SC_FL_SND_EXP_MORE,
	_(SC_FL_ABRT_WANTED, _(SC_FL_SHUT_WANTED, _(SC_FL_ABRT_DONE, _(SC_FL_SHUT_DONE,
	_(SC_FL_EOS, _(SC_FL_HAVE_BUFF))))))))))))))))))));
	/* epilogue */
	_(~0U);
	return buf;
#undef _
}

/* A conn stream must have its own errors independently of the buffer's, so that
 * applications can rely on what the buffer reports while the conn stream is
 * performing some retries (eg: connection error). Some states are transient and
 * do not last beyond process_session().
 */
enum sc_state {
	SC_ST_INI = 0,           /* SC not sollicitated yet */
	SC_ST_REQ,               /* [transient] connection initiation desired and not started yet */
	SC_ST_QUE,               /* SC waiting in queue */
	SC_ST_TAR,               /* SC in turn-around state after failed connect attempt */
	SC_ST_ASS,               /* server just assigned to this SC */
	SC_ST_CON,               /* initiated connection request (resource exists) */
	SC_ST_CER,               /* [transient] previous connection attempt failed (resource released) */
	SC_ST_RDY,               /* [transient] ready proven after I/O success during SC_ST_CON */
	SC_ST_EST,               /* connection established (resource exists) */
	SC_ST_DIS,               /* [transient] disconnected from other side, but cleanup not done yet */
	SC_ST_CLO,               /* SC closed, might not existing anymore. Buffers shut. */
} __attribute__((packed));

/* state bits for use with lists of states */
enum sc_state_bit {
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

/* represent the abort code, enriched with contextual info:
 *  - First 5 bits are used for the source (31 possible sources)
 *  - other bits are reserved for now
 */
#define SE_ABRT_SRC_SHIFT 0
#define SE_ABRT_SRC_MASK  0x0000001f

#define SE_ABRT_SRC_MUX_PT    0x01 /* Code set by the PT mux */
#define SE_ABRT_SRC_MUX_H1    0x02 /* Code set by the H1 mux */
#define SE_ABRT_SRC_MUX_H2    0x03 /* Code set by the H2 mux */
#define SE_ABRT_SRC_MUX_QUIC  0x04 /* Code set by the QUIC/H3 mux */
#define SE_ABRT_SRC_MUX_FCGI  0x05 /* Code set by the FCGI mux */
#define SE_ABRT_SRC_MUX_SPOP  0x06 /* Code set by the SPOP mux */

struct se_abort_info {
	uint32_t info;
	uint64_t code;
};

/* A Stream Endpoint Descriptor (sedesc) is the link between the stream
 * connector (ex. stconn) and the Stream Endpoint (mux or appctx).
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
 * <lra> should be updated when a read activity at the endpoint level is
 *       detected. It can be a successful receive or when a EOS/EOI is reported.
 *       A read activity is also reported when receives are unblocked.

 * <fsb> should be updated when the first send of a series is blocked and reset
 *       when a successful send is reported.
 *
 *
 * NOTE: <lra> and <fsb> must only be used via the SC api to compute read/write
 *       expiration date.
 *
 */
struct sedesc {
	void *se;                  /* the stream endpoint, i.e. the mux stream or the appctx */
	struct connection *conn;   /* the connection for connection-based streams */
	struct stconn *sc;         /* the stream connector we're attached to, or NULL */
	struct iobuf iobuf;        /* contains data forwarded by the other side and that must be sent by the stream endpoint */
	unsigned int flags;        /* SE_FL_* */
	uint32_t term_evts_log;    /* Termination events log: first 4 events reported */
	struct se_abort_info abort_info; /* Info about abort, as reported by the endpoint and eventually enriched by the app level */
	unsigned int lra;          /* the last read activity */
	unsigned int fsb;          /* the first send blocked */
	struct xref xref;          /* cross reference with the opposite SC */
};

/* sc_app_ops describes the application layer's operations and notification
 * callbacks when I/O activity is reported and to use to perform shutr/shutw.
 * There are very few combinations in practice (strm/chk <-> none/mux/applet).
 */
struct sc_app_ops {
	void (*chk_rcv)(struct stconn *);    /* chk_rcv function, may not be null */
	void (*chk_snd)(struct stconn *);    /* chk_snd function, may not be null */
	void (*abort)(struct stconn *);      /* abort function, may not be null */
	void (*shutdown)(struct stconn *);   /* shutdown function, may not be null */
	int  (*wake)(struct stconn *);       /* data-layer callback to report activity */
	char name[8];                        /* data layer name, zero-terminated */
};

/*
 * This structure describes the elements of a connection relevant to a stream
 */
struct stconn {
	enum obj_type obj_type;              /* differentiates connection from applet context */
	enum sc_state state;                 /* SC_ST* */
	/* 2 bytes hole here */

	unsigned int flags;                  /* SC_FL_* */
	unsigned int ioto;                   /* I/O activity timeout */
	uint32_t term_evts_log;              /* termination events log aggregating SE + connection events */
	ssize_t room_needed;                 /* free space in the input buffer required to receive more data.
					      *    -1   : the SC is waiting for room but not on a specific amount of data
					      *    >= 0 : min free space required to progress. 0 means SC must be unblocked ASAP
					      */
	struct wait_event wait_event;        /* We're in a wait list */
	struct sedesc *sedesc;               /* points to the stream endpoint descriptor */
	enum obj_type *app;                  /* points to the applicative point (stream or check) */
	const struct sc_app_ops *app_ops;    /* general operations used at the app layer */
	struct sockaddr_storage *src;        /* source address (pool), when known, otherwise NULL */
	struct sockaddr_storage *dst;        /* destination address (pool), when known, otherwise NULL */
};


#endif /* _HAPROXY_STCONN_T_H */
