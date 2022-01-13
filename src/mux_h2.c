/*
 * HTTP/2 mux-demux for connections
 *
 * Copyright 2017 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <import/eb32tree.h>
#include <import/ebmbtree.h>
#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/connection.h>
#include <haproxy/h2.h>
#include <haproxy/hpack-dec.h>
#include <haproxy/hpack-enc.h>
#include <haproxy/hpack-tbl.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/istbuf.h>
#include <haproxy/log.h>
#include <haproxy/net_helper.h>
#include <haproxy/session-t.h>
#include <haproxy/stats.h>
#include <haproxy/stream.h>
#include <haproxy/stream_interface.h>
#include <haproxy/trace.h>


/* dummy streams returned for closed, error, refused, idle and states */
static const struct h2s *h2_closed_stream;
static const struct h2s *h2_error_stream;
static const struct h2s *h2_refused_stream;
static const struct h2s *h2_idle_stream;

/* Connection flags (32 bit), in h2c->flags */
#define H2_CF_NONE              0x00000000

/* Flags indicating why writing to the mux is blocked. */
#define H2_CF_MUX_MALLOC        0x00000001  // mux blocked on lack of connection's mux buffer
#define H2_CF_MUX_MFULL         0x00000002  // mux blocked on connection's mux buffer full
#define H2_CF_MUX_BLOCK_ANY     0x00000003  // aggregate of the mux flags above

/* Flags indicating why writing to the demux is blocked.
 * The first two ones directly affect the ability for the mux to receive data
 * from the connection. The other ones affect the mux's ability to demux
 * received data.
 */
#define H2_CF_DEM_DALLOC        0x00000004  // demux blocked on lack of connection's demux buffer
#define H2_CF_DEM_DFULL         0x00000008  // demux blocked on connection's demux buffer full

#define H2_CF_DEM_MBUSY         0x00000010  // demux blocked on connection's mux side busy
#define H2_CF_DEM_MROOM         0x00000020  // demux blocked on lack of room in mux buffer
#define H2_CF_DEM_SALLOC        0x00000040  // demux blocked on lack of stream's request buffer
#define H2_CF_DEM_SFULL         0x00000080  // demux blocked on stream request buffer full
#define H2_CF_DEM_TOOMANY       0x00000100  // demux blocked waiting for some conn_streams to leave
#define H2_CF_DEM_BLOCK_ANY     0x000001F0  // aggregate of the demux flags above except DALLOC/DFULL
                                            // (SHORT_READ is also excluded)

#define H2_CF_DEM_SHORT_READ    0x00000200  // demux blocked on incomplete frame

/* other flags */
#define H2_CF_GOAWAY_SENT       0x00001000  // a GOAWAY frame was successfully sent
#define H2_CF_GOAWAY_FAILED     0x00002000  // a GOAWAY frame failed to be sent
#define H2_CF_WAIT_FOR_HS       0x00004000  // We did check that at least a stream was waiting for handshake
#define H2_CF_IS_BACK           0x00008000  // this is an outgoing connection
#define H2_CF_WINDOW_OPENED     0x00010000  // demux increased window already advertised
#define H2_CF_RCVD_SHUT         0x00020000  // a recv() attempt already failed on a shutdown
#define H2_CF_END_REACHED       0x00040000  // pending data too short with RCVD_SHUT present

#define H2_CF_RCVD_RFC8441      0x00100000  // settings from RFC8441 has been received indicating support for Extended CONNECT
#define H2_CF_SHTS_UPDATED      0x00200000  // SETTINGS_HEADER_TABLE_SIZE updated
#define H2_CF_DTSU_EMITTED      0x00400000  // HPACK Dynamic Table Size Update opcode emitted

/* H2 connection state, in h2c->st0 */
enum h2_cs {
	H2_CS_PREFACE,   // init done, waiting for connection preface
	H2_CS_SETTINGS1, // preface OK, waiting for first settings frame
	H2_CS_FRAME_H,   // first settings frame ok, waiting for frame header
	H2_CS_FRAME_P,   // frame header OK, waiting for frame payload
	H2_CS_FRAME_A,   // frame payload OK, trying to send ACK frame
	H2_CS_FRAME_E,   // frame payload OK, trying to send RST frame
	H2_CS_ERROR,     // send GOAWAY(errcode) and close the connection ASAP
	H2_CS_ERROR2,    // GOAWAY(errcode) sent, close the connection ASAP
	H2_CS_ENTRIES    // must be last
} __attribute__((packed));


/* 32 buffers: one for the ring's root, rest for the mbuf itself */
#define H2C_MBUF_CNT 32

/* H2 connection descriptor */
struct h2c {
	struct connection *conn;

	enum h2_cs st0; /* mux state */
	enum h2_err errcode; /* H2 err code (H2_ERR_*) */

	/* 16 bit hole here */
	uint32_t flags; /* connection flags: H2_CF_* */
	uint32_t streams_limit; /* maximum number of concurrent streams the peer supports */
	int32_t max_id; /* highest ID known on this connection, <0 before preface */
	uint32_t rcvd_c; /* newly received data to ACK for the connection */
	uint32_t rcvd_s; /* newly received data to ACK for the current stream (dsi) */

	/* states for the demux direction */
	struct hpack_dht *ddht; /* demux dynamic header table */
	struct buffer dbuf;    /* demux buffer */

	int32_t dsi; /* demux stream ID (<0 = idle) */
	int32_t dfl; /* demux frame length (if dsi >= 0) */
	int8_t  dft; /* demux frame type   (if dsi >= 0) */
	int8_t  dff; /* demux frame flags  (if dsi >= 0) */
	uint8_t dpl; /* demux pad length (part of dfl), init to 0 */
	/* 8 bit hole here */
	int32_t last_sid; /* last processed stream ID for GOAWAY, <0 before preface */

	/* states for the mux direction */
	struct buffer mbuf[H2C_MBUF_CNT];   /* mux buffers (ring) */
	int32_t msi; /* mux stream ID (<0 = idle) */
	int32_t mfl; /* mux frame length (if dsi >= 0) */
	int8_t  mft; /* mux frame type   (if dsi >= 0) */
	int8_t  mff; /* mux frame flags  (if dsi >= 0) */
	/* 16 bit hole here */
	int32_t miw; /* mux initial window size for all new streams */
	int32_t mws; /* mux window size. Can be negative. */
	int32_t mfs; /* mux's max frame size */

	int timeout;        /* idle timeout duration in ticks */
	int shut_timeout;   /* idle timeout duration in ticks after GOAWAY was sent */
	unsigned int nb_streams;  /* number of streams in the tree */
	unsigned int nb_cs;       /* number of attached conn_streams */
	unsigned int nb_reserved; /* number of reserved streams */
	unsigned int stream_cnt;  /* total number of streams seen */
	struct proxy *proxy; /* the proxy this connection was created for */
	struct task *task;  /* timeout management task */
	struct h2_counters *px_counters; /* h2 counters attached to proxy */
	struct eb_root streams_by_id; /* all active streams by their ID */
	struct list send_list; /* list of blocked streams requesting to send */
	struct list fctl_list; /* list of streams blocked by connection's fctl */
	struct list blocked_list; /* list of streams blocked for other reasons (e.g. sfctl, dep) */
	struct buffer_wait buf_wait; /* wait list for buffer allocations */
	struct wait_event wait_event;  /* To be used if we're waiting for I/Os */
};

/* H2 stream state, in h2s->st */
enum h2_ss {
	H2_SS_IDLE = 0, // idle
	H2_SS_RLOC,     // reserved(local)
	H2_SS_RREM,     // reserved(remote)
	H2_SS_OPEN,     // open
	H2_SS_HREM,     // half-closed(remote)
	H2_SS_HLOC,     // half-closed(local)
	H2_SS_ERROR,    // an error needs to be sent using RST_STREAM
	H2_SS_CLOSED,   // closed
	H2_SS_ENTRIES   // must be last
} __attribute__((packed));

#define H2_SS_MASK(state) (1UL << (state))
#define H2_SS_IDLE_BIT    (1UL << H2_SS_IDLE)
#define H2_SS_RLOC_BIT    (1UL << H2_SS_RLOC)
#define H2_SS_RREM_BIT    (1UL << H2_SS_RREM)
#define H2_SS_OPEN_BIT    (1UL << H2_SS_OPEN)
#define H2_SS_HREM_BIT    (1UL << H2_SS_HREM)
#define H2_SS_HLOC_BIT    (1UL << H2_SS_HLOC)
#define H2_SS_ERROR_BIT   (1UL << H2_SS_ERROR)
#define H2_SS_CLOSED_BIT  (1UL << H2_SS_CLOSED)

/* HTTP/2 stream flags (32 bit), in h2s->flags */
#define H2_SF_NONE              0x00000000
#define H2_SF_ES_RCVD           0x00000001
#define H2_SF_ES_SENT           0x00000002

#define H2_SF_RST_RCVD          0x00000004 // received RST_STREAM
#define H2_SF_RST_SENT          0x00000008 // sent RST_STREAM

/* stream flags indicating the reason the stream is blocked */
#define H2_SF_BLK_MBUSY         0x00000010 // blocked waiting for mux access (transient)
#define H2_SF_BLK_MROOM         0x00000020 // blocked waiting for room in the mux (must be in send list)
#define H2_SF_BLK_MFCTL         0x00000040 // blocked due to mux fctl (must be in fctl list)
#define H2_SF_BLK_SFCTL         0x00000080 // blocked due to stream fctl (must be in blocked list)
#define H2_SF_BLK_ANY           0x000000F0 // any of the reasons above

/* stream flags indicating how data is supposed to be sent */
#define H2_SF_DATA_CLEN         0x00000100 // data sent using content-length
#define H2_SF_BODYLESS_RESP     0x00000200 /* Bodyless response message */
#define H2_SF_BODY_TUNNEL       0x00000400 // Attempt to establish a Tunnelled stream (the result depends on the status code)


#define H2_SF_NOTIFIED          0x00000800  // a paused stream was notified to try to send again
#define H2_SF_HEADERS_SENT      0x00001000  // a HEADERS frame was sent for this stream
#define H2_SF_OUTGOING_DATA     0x00002000  // set whenever we've seen outgoing data

#define H2_SF_HEADERS_RCVD      0x00004000  // a HEADERS frame was received for this stream

#define H2_SF_WANT_SHUTR        0x00008000  // a stream couldn't shutr() (mux full/busy)
#define H2_SF_WANT_SHUTW        0x00010000  // a stream couldn't shutw() (mux full/busy)
#define H2_SF_KILL_CONN         0x00020000  // kill the whole connection with this stream

#define H2_SF_EXT_CONNECT_SENT  0x00040000  // rfc 8441 an Extended CONNECT has been sent
#define H2_SF_EXT_CONNECT_RCVD  0x00080000  // rfc 8441 an Extended CONNECT has been received and parsed

#define H2_SF_TUNNEL_ABRT       0x00100000  // A tunnel attempt was aborted

/* H2 stream descriptor, describing the stream as it appears in the H2C, and as
 * it is being processed in the internal HTTP representation (HTX).
 */
struct h2s {
	struct conn_stream *cs;
	struct session *sess;
	struct h2c *h2c;
	struct eb32_node by_id; /* place in h2c's streams_by_id */
	int32_t id; /* stream ID */
	uint32_t flags;      /* H2_SF_* */
	int sws;             /* stream window size, to be added to the mux's initial window size */
	enum h2_err errcode; /* H2 err code (H2_ERR_*) */
	enum h2_ss st;
	uint16_t status;     /* HTTP response status */
	unsigned long long body_len; /* remaining body length according to content-length if H2_SF_DATA_CLEN */
	struct buffer rxbuf; /* receive buffer, always valid (buf_empty or real buffer) */
	struct wait_event *subs;      /* recv wait_event the conn_stream associated is waiting on (via h2_subscribe) */
	struct list list; /* To be used when adding in h2c->send_list or h2c->fctl_lsit */
	struct tasklet *shut_tl;  /* deferred shutdown tasklet, to retry to send an RST after we failed to,
				   * in case there's no other subscription to do it */

	char upgrade_protocol[16]; /* rfc 8441: requested protocol on Extended CONNECT */
};

/* descriptor for an h2 frame header */
struct h2_fh {
	uint32_t len;       /* length, host order, 24 bits */
	uint32_t sid;       /* stream id, host order, 31 bits */
	uint8_t ft;         /* frame type */
	uint8_t ff;         /* frame flags */
};

/* trace source and events */
static void h2_trace(enum trace_level level, uint64_t mask, \
                     const struct trace_source *src,
                     const struct ist where, const struct ist func,
                     const void *a1, const void *a2, const void *a3, const void *a4);

/* The event representation is split like this :
 *   strm  - application layer
 *   h2s   - internal H2 stream
 *   h2c   - internal H2 connection
 *   conn  - external connection
 *
 */
static const struct trace_event h2_trace_events[] = {
#define           H2_EV_H2C_NEW       (1ULL <<  0)
	{ .mask = H2_EV_H2C_NEW,      .name = "h2c_new",     .desc = "new H2 connection" },
#define           H2_EV_H2C_RECV      (1ULL <<  1)
	{ .mask = H2_EV_H2C_RECV,     .name = "h2c_recv",    .desc = "Rx on H2 connection" },
#define           H2_EV_H2C_SEND      (1ULL <<  2)
	{ .mask = H2_EV_H2C_SEND,     .name = "h2c_send",    .desc = "Tx on H2 connection" },
#define           H2_EV_H2C_FCTL      (1ULL <<  3)
	{ .mask = H2_EV_H2C_FCTL,     .name = "h2c_fctl",    .desc = "H2 connection flow-controlled" },
#define           H2_EV_H2C_BLK       (1ULL <<  4)
	{ .mask = H2_EV_H2C_BLK,      .name = "h2c_blk",     .desc = "H2 connection blocked" },
#define           H2_EV_H2C_WAKE      (1ULL <<  5)
	{ .mask = H2_EV_H2C_WAKE,     .name = "h2c_wake",    .desc = "H2 connection woken up" },
#define           H2_EV_H2C_END       (1ULL <<  6)
	{ .mask = H2_EV_H2C_END,      .name = "h2c_end",     .desc = "H2 connection terminated" },
#define           H2_EV_H2C_ERR       (1ULL <<  7)
	{ .mask = H2_EV_H2C_ERR,      .name = "h2c_err",     .desc = "error on H2 connection" },
#define           H2_EV_RX_FHDR       (1ULL <<  8)
	{ .mask = H2_EV_RX_FHDR,      .name = "rx_fhdr",     .desc = "H2 frame header received" },
#define           H2_EV_RX_FRAME      (1ULL <<  9)
	{ .mask = H2_EV_RX_FRAME,     .name = "rx_frame",    .desc = "receipt of any H2 frame" },
#define           H2_EV_RX_EOI        (1ULL << 10)
	{ .mask = H2_EV_RX_EOI,       .name = "rx_eoi",      .desc = "receipt of end of H2 input (ES or RST)" },
#define           H2_EV_RX_PREFACE    (1ULL << 11)
	{ .mask = H2_EV_RX_PREFACE,   .name = "rx_preface",  .desc = "receipt of H2 preface" },
#define           H2_EV_RX_DATA       (1ULL << 12)
	{ .mask = H2_EV_RX_DATA,      .name = "rx_data",     .desc = "receipt of H2 DATA frame" },
#define           H2_EV_RX_HDR        (1ULL << 13)
	{ .mask = H2_EV_RX_HDR,       .name = "rx_hdr",      .desc = "receipt of H2 HEADERS frame" },
#define           H2_EV_RX_PRIO       (1ULL << 14)
	{ .mask = H2_EV_RX_PRIO,      .name = "rx_prio",     .desc = "receipt of H2 PRIORITY frame" },
#define           H2_EV_RX_RST        (1ULL << 15)
	{ .mask = H2_EV_RX_RST,       .name = "rx_rst",      .desc = "receipt of H2 RST_STREAM frame" },
#define           H2_EV_RX_SETTINGS   (1ULL << 16)
	{ .mask = H2_EV_RX_SETTINGS,  .name = "rx_settings", .desc = "receipt of H2 SETTINGS frame" },
#define           H2_EV_RX_PUSH       (1ULL << 17)
	{ .mask = H2_EV_RX_PUSH,      .name = "rx_push",     .desc = "receipt of H2 PUSH_PROMISE frame" },
#define           H2_EV_RX_PING       (1ULL << 18)
	{ .mask = H2_EV_RX_PING,      .name = "rx_ping",     .desc = "receipt of H2 PING frame" },
#define           H2_EV_RX_GOAWAY     (1ULL << 19)
	{ .mask = H2_EV_RX_GOAWAY,    .name = "rx_goaway",   .desc = "receipt of H2 GOAWAY frame" },
#define           H2_EV_RX_WU         (1ULL << 20)
	{ .mask = H2_EV_RX_WU,        .name = "rx_wu",       .desc = "receipt of H2 WINDOW_UPDATE frame" },
#define           H2_EV_RX_CONT       (1ULL << 21)
	{ .mask = H2_EV_RX_CONT,      .name = "rx_cont",     .desc = "receipt of H2 CONTINUATION frame" },
#define           H2_EV_TX_FRAME      (1ULL << 22)
	{ .mask = H2_EV_TX_FRAME,     .name = "tx_frame",    .desc = "transmission of any H2 frame" },
#define           H2_EV_TX_EOI        (1ULL << 23)
	{ .mask = H2_EV_TX_EOI,       .name = "tx_eoi",      .desc = "transmission of H2 end of input (ES or RST)" },
#define           H2_EV_TX_PREFACE    (1ULL << 24)
	{ .mask = H2_EV_TX_PREFACE,   .name = "tx_preface",  .desc = "transmission of H2 preface" },
#define           H2_EV_TX_DATA       (1ULL << 25)
	{ .mask = H2_EV_TX_DATA,      .name = "tx_data",     .desc = "transmission of H2 DATA frame" },
#define           H2_EV_TX_HDR        (1ULL << 26)
	{ .mask = H2_EV_TX_HDR,       .name = "tx_hdr",      .desc = "transmission of H2 HEADERS frame" },
#define           H2_EV_TX_PRIO       (1ULL << 27)
	{ .mask = H2_EV_TX_PRIO,      .name = "tx_prio",     .desc = "transmission of H2 PRIORITY frame" },
#define           H2_EV_TX_RST        (1ULL << 28)
	{ .mask = H2_EV_TX_RST,       .name = "tx_rst",      .desc = "transmission of H2 RST_STREAM frame" },
#define           H2_EV_TX_SETTINGS   (1ULL << 29)
	{ .mask = H2_EV_TX_SETTINGS,  .name = "tx_settings", .desc = "transmission of H2 SETTINGS frame" },
#define           H2_EV_TX_PUSH       (1ULL << 30)
	{ .mask = H2_EV_TX_PUSH,      .name = "tx_push",     .desc = "transmission of H2 PUSH_PROMISE frame" },
#define           H2_EV_TX_PING       (1ULL << 31)
	{ .mask = H2_EV_TX_PING,      .name = "tx_ping",     .desc = "transmission of H2 PING frame" },
#define           H2_EV_TX_GOAWAY     (1ULL << 32)
	{ .mask = H2_EV_TX_GOAWAY,    .name = "tx_goaway",   .desc = "transmission of H2 GOAWAY frame" },
#define           H2_EV_TX_WU         (1ULL << 33)
	{ .mask = H2_EV_TX_WU,        .name = "tx_wu",       .desc = "transmission of H2 WINDOW_UPDATE frame" },
#define           H2_EV_TX_CONT       (1ULL << 34)
	{ .mask = H2_EV_TX_CONT,      .name = "tx_cont",     .desc = "transmission of H2 CONTINUATION frame" },
#define           H2_EV_H2S_NEW       (1ULL << 35)
	{ .mask = H2_EV_H2S_NEW,      .name = "h2s_new",     .desc = "new H2 stream" },
#define           H2_EV_H2S_RECV      (1ULL << 36)
	{ .mask = H2_EV_H2S_RECV,     .name = "h2s_recv",    .desc = "Rx for H2 stream" },
#define           H2_EV_H2S_SEND      (1ULL << 37)
	{ .mask = H2_EV_H2S_SEND,     .name = "h2s_send",    .desc = "Tx for H2 stream" },
#define           H2_EV_H2S_FCTL      (1ULL << 38)
	{ .mask = H2_EV_H2S_FCTL,     .name = "h2s_fctl",    .desc = "H2 stream flow-controlled" },
#define           H2_EV_H2S_BLK       (1ULL << 39)
	{ .mask = H2_EV_H2S_BLK,      .name = "h2s_blk",     .desc = "H2 stream blocked" },
#define           H2_EV_H2S_WAKE      (1ULL << 40)
	{ .mask = H2_EV_H2S_WAKE,     .name = "h2s_wake",    .desc = "H2 stream woken up" },
#define           H2_EV_H2S_END       (1ULL << 41)
	{ .mask = H2_EV_H2S_END,      .name = "h2s_end",     .desc = "H2 stream terminated" },
#define           H2_EV_H2S_ERR       (1ULL << 42)
	{ .mask = H2_EV_H2S_ERR,      .name = "h2s_err",     .desc = "error on H2 stream" },
#define           H2_EV_STRM_NEW      (1ULL << 43)
	{ .mask = H2_EV_STRM_NEW,     .name = "strm_new",    .desc = "app-layer stream creation" },
#define           H2_EV_STRM_RECV     (1ULL << 44)
	{ .mask = H2_EV_STRM_RECV,    .name = "strm_recv",   .desc = "receiving data for stream" },
#define           H2_EV_STRM_SEND     (1ULL << 45)
	{ .mask = H2_EV_STRM_SEND,    .name = "strm_send",   .desc = "sending data for stream" },
#define           H2_EV_STRM_FULL     (1ULL << 46)
	{ .mask = H2_EV_STRM_FULL,    .name = "strm_full",   .desc = "stream buffer full" },
#define           H2_EV_STRM_WAKE     (1ULL << 47)
	{ .mask = H2_EV_STRM_WAKE,    .name = "strm_wake",   .desc = "stream woken up" },
#define           H2_EV_STRM_SHUT     (1ULL << 48)
	{ .mask = H2_EV_STRM_SHUT,    .name = "strm_shut",   .desc = "stream shutdown" },
#define           H2_EV_STRM_END      (1ULL << 49)
	{ .mask = H2_EV_STRM_END,     .name = "strm_end",    .desc = "detaching app-layer stream" },
#define           H2_EV_STRM_ERR      (1ULL << 50)
	{ .mask = H2_EV_STRM_ERR,     .name = "strm_err",    .desc = "stream error" },
#define           H2_EV_PROTO_ERR     (1ULL << 51)
	{ .mask = H2_EV_PROTO_ERR,    .name = "proto_err",   .desc = "protocol error" },
	{ }
};

static const struct name_desc h2_trace_lockon_args[4] = {
	/* arg1 */ { /* already used by the connection */ },
	/* arg2 */ { .name="h2s", .desc="H2 stream" },
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct name_desc h2_trace_decoding[] = {
#define H2_VERB_CLEAN    1
	{ .name="clean",    .desc="only user-friendly stuff, generally suitable for level \"user\"" },
#define H2_VERB_MINIMAL  2
	{ .name="minimal",  .desc="report only h2c/h2s state and flags, no real decoding" },
#define H2_VERB_SIMPLE   3
	{ .name="simple",   .desc="add request/response status line or frame info when available" },
#define H2_VERB_ADVANCED 4
	{ .name="advanced", .desc="add header fields or frame decoding when available" },
#define H2_VERB_COMPLETE 5
	{ .name="complete", .desc="add full data dump when available" },
	{ /* end */ }
};

static struct trace_source trace_h2 __read_mostly = {
	.name = IST("h2"),
	.desc = "HTTP/2 multiplexer",
	.arg_def = TRC_ARG1_CONN,  // TRACE()'s first argument is always a connection
	.default_cb = h2_trace,
	.known_events = h2_trace_events,
	.lockon_args = h2_trace_lockon_args,
	.decoding = h2_trace_decoding,
	.report_events = ~0,  // report everything by default
};

#define TRACE_SOURCE &trace_h2
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

/* h2 stats module */
enum {
	H2_ST_HEADERS_RCVD,
	H2_ST_DATA_RCVD,
	H2_ST_SETTINGS_RCVD,
	H2_ST_RST_STREAM_RCVD,
	H2_ST_GOAWAY_RCVD,

	H2_ST_CONN_PROTO_ERR,
	H2_ST_STRM_PROTO_ERR,
	H2_ST_RST_STREAM_RESP,
	H2_ST_GOAWAY_RESP,

	H2_ST_OPEN_CONN,
	H2_ST_OPEN_STREAM,
	H2_ST_TOTAL_CONN,
	H2_ST_TOTAL_STREAM,

	H2_STATS_COUNT /* must be the last member of the enum */
};

static struct name_desc h2_stats[] = {
	[H2_ST_HEADERS_RCVD]    = { .name = "h2_headers_rcvd",
	                            .desc = "Total number of received HEADERS frames" },
	[H2_ST_DATA_RCVD]       = { .name = "h2_data_rcvd",
	                            .desc = "Total number of received DATA frames" },
	[H2_ST_SETTINGS_RCVD]   = { .name = "h2_settings_rcvd",
	                            .desc = "Total number of received SETTINGS frames" },
	[H2_ST_RST_STREAM_RCVD] = { .name = "h2_rst_stream_rcvd",
	                            .desc = "Total number of received RST_STREAM frames" },
	[H2_ST_GOAWAY_RCVD]     = { .name = "h2_goaway_rcvd",
	                            .desc = "Total number of received GOAWAY frames" },

	[H2_ST_CONN_PROTO_ERR]  = { .name = "h2_detected_conn_protocol_errors",
	                            .desc = "Total number of connection protocol errors" },
	[H2_ST_STRM_PROTO_ERR]  = { .name = "h2_detected_strm_protocol_errors",
	                            .desc = "Total number of stream protocol errors" },
	[H2_ST_RST_STREAM_RESP] = { .name = "h2_rst_stream_resp",
	                            .desc = "Total number of RST_STREAM sent on detected error" },
	[H2_ST_GOAWAY_RESP]     = { .name = "h2_goaway_resp",
	                            .desc = "Total number of GOAWAY sent on detected error" },

	[H2_ST_OPEN_CONN]    = { .name = "h2_open_connections",
	                         .desc = "Count of currently open connections" },
	[H2_ST_OPEN_STREAM]  = { .name = "h2_backend_open_streams",
	                         .desc = "Count of currently open streams" },
	[H2_ST_TOTAL_CONN]   = { .name = "h2_total_connections",
	                         .desc = "Total number of connections" },
	[H2_ST_TOTAL_STREAM] = { .name = "h2_backend_total_streams",
	                         .desc = "Total number of streams" },
};

static struct h2_counters {
	long long headers_rcvd;    /* total number of HEADERS frame received */
	long long data_rcvd;       /* total number of DATA frame received */
	long long settings_rcvd;   /* total number of SETTINGS frame received */
	long long rst_stream_rcvd; /* total number of RST_STREAM frame received */
	long long goaway_rcvd;     /* total number of GOAWAY frame received */

	long long conn_proto_err;  /* total number of protocol errors detected */
	long long strm_proto_err;  /* total number of protocol errors detected */
	long long rst_stream_resp; /* total number of RST_STREAM frame sent on error */
	long long goaway_resp;     /* total number of GOAWAY frame sent on error */

	long long open_conns;    /* count of currently open connections */
	long long open_streams;  /* count of currently open streams */
	long long total_conns;   /* total number of connections */
	long long total_streams; /* total number of streams */
} h2_counters;

static void h2_fill_stats(void *data, struct field *stats)
{
	struct h2_counters *counters = data;

	stats[H2_ST_HEADERS_RCVD]    = mkf_u64(FN_COUNTER, counters->headers_rcvd);
	stats[H2_ST_DATA_RCVD]       = mkf_u64(FN_COUNTER, counters->data_rcvd);
	stats[H2_ST_SETTINGS_RCVD]   = mkf_u64(FN_COUNTER, counters->settings_rcvd);
	stats[H2_ST_RST_STREAM_RCVD] = mkf_u64(FN_COUNTER, counters->rst_stream_rcvd);
	stats[H2_ST_GOAWAY_RCVD]     = mkf_u64(FN_COUNTER, counters->goaway_rcvd);

	stats[H2_ST_CONN_PROTO_ERR]  = mkf_u64(FN_COUNTER, counters->conn_proto_err);
	stats[H2_ST_STRM_PROTO_ERR]  = mkf_u64(FN_COUNTER, counters->strm_proto_err);
	stats[H2_ST_RST_STREAM_RESP] = mkf_u64(FN_COUNTER, counters->rst_stream_resp);
	stats[H2_ST_GOAWAY_RESP]     = mkf_u64(FN_COUNTER, counters->goaway_resp);

	stats[H2_ST_OPEN_CONN]    = mkf_u64(FN_GAUGE,   counters->open_conns);
	stats[H2_ST_OPEN_STREAM]  = mkf_u64(FN_GAUGE,   counters->open_streams);
	stats[H2_ST_TOTAL_CONN]   = mkf_u64(FN_COUNTER, counters->total_conns);
	stats[H2_ST_TOTAL_STREAM] = mkf_u64(FN_COUNTER, counters->total_streams);
}

static struct stats_module h2_stats_module = {
	.name          = "h2",
	.fill_stats    = h2_fill_stats,
	.stats         = h2_stats,
	.stats_count   = H2_STATS_COUNT,
	.counters      = &h2_counters,
	.counters_size = sizeof(h2_counters),
	.domain_flags  = MK_STATS_PROXY_DOMAIN(STATS_PX_CAP_FE|STATS_PX_CAP_BE),
	.clearable     = 1,
};

INITCALL1(STG_REGISTER, stats_register_module, &h2_stats_module);

/* the h2c connection pool */
DECLARE_STATIC_POOL(pool_head_h2c, "h2c", sizeof(struct h2c));

/* the h2s stream pool */
DECLARE_STATIC_POOL(pool_head_h2s, "h2s", sizeof(struct h2s));

/* The default connection window size is 65535, it may only be enlarged using
 * a WINDOW_UPDATE message. Since the window must never be larger than 2G-1,
 * we'll pretend we already received the difference between the two to send
 * an equivalent window update to enlarge it to 2G-1.
 */
#define H2_INITIAL_WINDOW_INCREMENT ((1U<<31)-1 - 65535)

/* maximum amount of data we're OK with re-aligning for buffer optimizations */
#define MAX_DATA_REALIGN 1024

/* a few settings from the global section */
static int h2_settings_header_table_size      =  4096; /* initial value */
static int h2_settings_initial_window_size    = 65535; /* initial value */
static unsigned int h2_settings_max_concurrent_streams = 100;
static int h2_settings_max_frame_size         = 0;     /* unset */

/* a dmumy closed stream */
static const struct h2s *h2_closed_stream = &(const struct h2s){
	.cs        = NULL,
	.h2c       = NULL,
	.st        = H2_SS_CLOSED,
	.errcode   = H2_ERR_STREAM_CLOSED,
	.flags     = H2_SF_RST_RCVD,
	.id        = 0,
};

/* a dmumy closed stream returning a PROTOCOL_ERROR error */
static const struct h2s *h2_error_stream = &(const struct h2s){
	.cs        = NULL,
	.h2c       = NULL,
	.st        = H2_SS_CLOSED,
	.errcode   = H2_ERR_PROTOCOL_ERROR,
	.flags     = 0,
	.id        = 0,
};

/* a dmumy closed stream returning a REFUSED_STREAM error */
static const struct h2s *h2_refused_stream = &(const struct h2s){
	.cs        = NULL,
	.h2c       = NULL,
	.st        = H2_SS_CLOSED,
	.errcode   = H2_ERR_REFUSED_STREAM,
	.flags     = 0,
	.id        = 0,
};

/* and a dummy idle stream for use with any unannounced stream */
static const struct h2s *h2_idle_stream = &(const struct h2s){
	.cs        = NULL,
	.h2c       = NULL,
	.st        = H2_SS_IDLE,
	.errcode   = H2_ERR_STREAM_CLOSED,
	.id        = 0,
};

struct task *h2_timeout_task(struct task *t, void *context, unsigned int state);
static int h2_send(struct h2c *h2c);
static int h2_recv(struct h2c *h2c);
static int h2_process(struct h2c *h2c);
/* h2_io_cb is exported to see it resolved in "show fd" */
struct task *h2_io_cb(struct task *t, void *ctx, unsigned int state);
static inline struct h2s *h2c_st_by_id(struct h2c *h2c, int id);
static int h2c_decode_headers(struct h2c *h2c, struct buffer *rxbuf, uint32_t *flags, unsigned long long *body_len, char *upgrade_protocol);
static int h2_frt_transfer_data(struct h2s *h2s);
struct task *h2_deferred_shut(struct task *t, void *ctx, unsigned int state);
static struct h2s *h2c_bck_stream_new(struct h2c *h2c, struct conn_stream *cs, struct session *sess);
static void h2s_alert(struct h2s *h2s);

/* returns a h2c state as an abbreviated 3-letter string, or "???" if unknown */
static inline const char *h2c_st_to_str(enum h2_cs st)
{
	switch (st) {
	case H2_CS_PREFACE:   return "PRF";
	case H2_CS_SETTINGS1: return "STG";
	case H2_CS_FRAME_H:   return "FRH";
	case H2_CS_FRAME_P:   return "FRP";
	case H2_CS_FRAME_A:   return "FRA";
	case H2_CS_FRAME_E:   return "FRE";
	case H2_CS_ERROR:     return "ERR";
	case H2_CS_ERROR2:    return "ER2";
	default:              return "???";
	}
}

/* returns a h2s state as an abbreviated 3-letter string, or "???" if unknown */
static inline const char *h2s_st_to_str(enum h2_ss st)
{
	switch (st) {
	case H2_SS_IDLE:   return "IDL"; // idle
	case H2_SS_RLOC:   return "RSL"; // reserved local
	case H2_SS_RREM:   return "RSR"; // reserved remote
	case H2_SS_OPEN:   return "OPN"; // open
	case H2_SS_HREM:   return "HCR"; // half-closed remote
	case H2_SS_HLOC:   return "HCL"; // half-closed local
	case H2_SS_ERROR : return "ERR"; // error
	case H2_SS_CLOSED: return "CLO"; // closed
	default:           return "???";
	}
}

/* the H2 traces always expect that arg1, if non-null, is of type connection
 * (from which we can derive h2c), that arg2, if non-null, is of type h2s, and
 * that arg3, if non-null, is either of type htx for tx headers, or of type
 * buffer for everything else.
 */
static void h2_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                     const struct ist where, const struct ist func,
                     const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct connection *conn = a1;
	const struct h2c *h2c    = conn ? conn->ctx : NULL;
	const struct h2s *h2s    = a2;
	const struct buffer *buf = a3;
	const struct htx *htx;
	int pos;

	if (!h2c) // nothing to add
		return;

	if (src->verbosity > H2_VERB_CLEAN) {
		chunk_appendf(&trace_buf, " : h2c=%p(%c,%s)", h2c, conn_is_back(conn) ? 'B' : 'F', h2c_st_to_str(h2c->st0));

		if (mask & H2_EV_H2C_NEW) // inside h2_init, otherwise it's hard to match conn & h2c
			conn_append_debug_info(&trace_buf, conn, " : ");

		if (h2c->errcode)
			chunk_appendf(&trace_buf, " err=%s/%02x", h2_err_str(h2c->errcode), h2c->errcode);

		if (h2c->dsi >= 0 &&
		    (mask & (H2_EV_RX_FRAME|H2_EV_RX_FHDR)) == (H2_EV_RX_FRAME|H2_EV_RX_FHDR)) {
			chunk_appendf(&trace_buf, " dft=%s/%02x dfl=%d", h2_ft_str(h2c->dft), h2c->dff, h2c->dfl);
		}

		if (h2s) {
			if (h2s->id <= 0)
				chunk_appendf(&trace_buf, " dsi=%d", h2c->dsi);
			chunk_appendf(&trace_buf, " h2s=%p(%d,%s)", h2s, h2s->id, h2s_st_to_str(h2s->st));
			if (h2s->id && h2s->errcode)
				chunk_appendf(&trace_buf, " err=%s/%02x", h2_err_str(h2s->errcode), h2s->errcode);
		}
	}

	/* Let's dump decoded requests and responses right after parsing. They
	 * are traced at level USER with a few recognizable flags.
	 */
	if ((mask == (H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_STRM_NEW) ||
	     mask == (H2_EV_RX_FRAME|H2_EV_RX_HDR)) && buf)
		htx = htxbuf(buf); // recv req/res
	else if (mask == (H2_EV_TX_FRAME|H2_EV_TX_HDR))
		htx = a3; // send req/res
	else
		htx = NULL;

	if (level == TRACE_LEVEL_USER && src->verbosity != H2_VERB_MINIMAL && htx && (pos = htx_get_head(htx)) != -1) {
		const struct htx_blk    *blk  = htx_get_blk(htx, pos);
		const struct htx_sl     *sl   = htx_get_blk_ptr(htx, blk);
		enum htx_blk_type        type = htx_get_blk_type(blk);

		if (type == HTX_BLK_REQ_SL)
			chunk_appendf(&trace_buf, " : [%d] H2 REQ: %.*s %.*s %.*s",
				      h2s ? h2s->id : h2c->dsi,
				      HTX_SL_P1_LEN(sl), HTX_SL_P1_PTR(sl),
				      HTX_SL_P2_LEN(sl), HTX_SL_P2_PTR(sl),
				      HTX_SL_P3_LEN(sl), HTX_SL_P3_PTR(sl));
		else if (type == HTX_BLK_RES_SL)
			chunk_appendf(&trace_buf, " : [%d] H2 RES: %.*s %.*s %.*s",
				      h2s ? h2s->id : h2c->dsi,
				      HTX_SL_P1_LEN(sl), HTX_SL_P1_PTR(sl),
				      HTX_SL_P2_LEN(sl), HTX_SL_P2_PTR(sl),
				      HTX_SL_P3_LEN(sl), HTX_SL_P3_PTR(sl));
	}
}


/* Detect a pending read0 for a H2 connection. It happens if a read0 was
 * already reported on a previous xprt->rcvbuf() AND a frame parser failed
 * to parse pending data, confirming no more progress is possible because
 * we're facing a truncated frame. The function returns 1 to report a read0
 * or 0 otherwise.
 */
static inline int h2c_read0_pending(struct h2c *h2c)
{
	return !!(h2c->flags & H2_CF_END_REACHED);
}

/* returns true if the connection is allowed to expire, false otherwise. A
 * connection may expire when:
 *   - it has no stream
 *   - it has data in the mux buffer
 *   - it has streams in the blocked list
 *   - it has streams in the fctl list
 *   - it has streams in the send list
 * Otherwise it means some streams are waiting in the data layer and it should
 * not expire.
 */
static inline int h2c_may_expire(const struct h2c *h2c)
{
	return eb_is_empty(&h2c->streams_by_id) ||
	       br_data(h2c->mbuf) ||
	       !LIST_ISEMPTY(&h2c->blocked_list) ||
	       !LIST_ISEMPTY(&h2c->fctl_list) ||
	       !LIST_ISEMPTY(&h2c->send_list);
}

static __inline int
h2c_is_dead(const struct h2c *h2c)
{
	if (eb_is_empty(&h2c->streams_by_id) &&     /* don't close if streams exist */
	    ((h2c->conn->flags & CO_FL_ERROR) ||    /* errors close immediately */
	     (h2c->st0 >= H2_CS_ERROR && !h2c->task) || /* a timeout stroke earlier */
	     (!(h2c->conn->owner)) || /* Nobody's left to take care of the connection, drop it now */
	     (!br_data(h2c->mbuf) &&  /* mux buffer empty, also process clean events below */
	      (conn_xprt_read0_pending(h2c->conn) ||
	       (h2c->last_sid >= 0 && h2c->max_id >= h2c->last_sid)))))
		return 1;

	return 0;
}

/*****************************************************/
/* functions below are for dynamic buffer management */
/*****************************************************/

/* indicates whether or not the we may call the h2_recv() function to attempt
 * to receive data into the buffer and/or demux pending data. The condition is
 * a bit complex due to some API limits for now. The rules are the following :
 *   - if an error or a shutdown was detected on the connection and the buffer
 *     is empty, we must not attempt to receive
 *   - if the demux buf failed to be allocated, we must not try to receive and
 *     we know there is nothing pending
 *   - if no flag indicates a blocking condition, we may attempt to receive,
 *     regardless of whether the demux buffer is full or not, so that only
 *     de demux part decides whether or not to block. This is needed because
 *     the connection API indeed prevents us from re-enabling receipt that is
 *     already enabled in a polled state, so we must always immediately stop
 *     as soon as the demux can't proceed so as never to hit an end of read
 *     with data pending in the buffers.
 *   - otherwise must may not attempt
 */
static inline int h2_recv_allowed(const struct h2c *h2c)
{
	if (b_data(&h2c->dbuf) == 0 &&
	    (h2c->st0 >= H2_CS_ERROR ||
	     h2c->conn->flags & CO_FL_ERROR ||
	     conn_xprt_read0_pending(h2c->conn)))
		return 0;

	if (!(h2c->flags & H2_CF_DEM_DALLOC) &&
	    !(h2c->flags & H2_CF_DEM_BLOCK_ANY))
		return 1;

	return 0;
}

/* restarts reading on the connection if it was not enabled */
static inline void h2c_restart_reading(const struct h2c *h2c, int consider_buffer)
{
	if (!h2_recv_allowed(h2c))
		return;
	if ((!consider_buffer || !b_data(&h2c->dbuf))
	    && (h2c->wait_event.events & SUB_RETRY_RECV))
		return;
	tasklet_wakeup(h2c->wait_event.tasklet);
}


/* returns true if the front connection has too many conn_streams attached */
static inline int h2_frt_has_too_many_cs(const struct h2c *h2c)
{
	return h2c->nb_cs > h2_settings_max_concurrent_streams;
}

/* Tries to grab a buffer and to re-enable processing on mux <target>. The h2c
 * flags are used to figure what buffer was requested. It returns 1 if the
 * allocation succeeds, in which case the connection is woken up, or 0 if it's
 * impossible to wake up and we prefer to be woken up later.
 */
static int h2_buf_available(void *target)
{
	struct h2c *h2c = target;
	struct h2s *h2s;

	if ((h2c->flags & H2_CF_DEM_DALLOC) && b_alloc(&h2c->dbuf)) {
		h2c->flags &= ~H2_CF_DEM_DALLOC;
		h2c_restart_reading(h2c, 1);
		return 1;
	}

	if ((h2c->flags & H2_CF_MUX_MALLOC) && b_alloc(br_tail(h2c->mbuf))) {
		h2c->flags &= ~H2_CF_MUX_MALLOC;

		if (h2c->flags & H2_CF_DEM_MROOM) {
			h2c->flags &= ~H2_CF_DEM_MROOM;
			h2c_restart_reading(h2c, 1);
		}
		return 1;
	}

	if ((h2c->flags & H2_CF_DEM_SALLOC) &&
	    (h2s = h2c_st_by_id(h2c, h2c->dsi)) && h2s->cs &&
	    b_alloc(&h2s->rxbuf)) {
		h2c->flags &= ~H2_CF_DEM_SALLOC;
		h2c_restart_reading(h2c, 1);
		return 1;
	}

	return 0;
}

static inline struct buffer *h2_get_buf(struct h2c *h2c, struct buffer *bptr)
{
	struct buffer *buf = NULL;

	if (likely(!LIST_INLIST(&h2c->buf_wait.list)) &&
	    unlikely((buf = b_alloc(bptr)) == NULL)) {
		h2c->buf_wait.target = h2c;
		h2c->buf_wait.wakeup_cb = h2_buf_available;
		LIST_APPEND(&th_ctx->buffer_wq, &h2c->buf_wait.list);
	}
	return buf;
}

static inline void h2_release_buf(struct h2c *h2c, struct buffer *bptr)
{
	if (bptr->size) {
		b_free(bptr);
		offer_buffers(NULL, 1);
	}
}

static inline void h2_release_mbuf(struct h2c *h2c)
{
	struct buffer *buf;
	unsigned int count = 0;

	while (b_size(buf = br_head_pick(h2c->mbuf))) {
		b_free(buf);
		count++;
	}
	if (count)
		offer_buffers(NULL, count);
}

/* returns the number of allocatable outgoing streams for the connection taking
 * the last_sid and the reserved ones into account.
 */
static inline int h2_streams_left(const struct h2c *h2c)
{
	int ret;

	/* consider the number of outgoing streams we're allowed to create before
	 * reaching the last GOAWAY frame seen. max_id is the last assigned id,
	 * nb_reserved is the number of streams which don't yet have an ID.
	 */
	ret = (h2c->last_sid >= 0) ? h2c->last_sid : 0x7FFFFFFF;
	ret = (unsigned int)(ret - h2c->max_id) / 2 - h2c->nb_reserved - 1;
	if (ret < 0)
		ret = 0;
	return ret;
}

/* returns the number of streams in use on a connection to figure if it's
 * idle or not. We check nb_cs and not nb_streams as the caller will want
 * to know if it was the last one after a detach().
 */
static int h2_used_streams(struct connection *conn)
{
	struct h2c *h2c = conn->ctx;

	return h2c->nb_cs;
}

/* returns the number of concurrent streams available on the connection */
static int h2_avail_streams(struct connection *conn)
{
	struct server *srv = objt_server(conn->target);
	struct h2c *h2c = conn->ctx;
	int ret1, ret2;

	/* RFC7540#6.8: Receivers of a GOAWAY frame MUST NOT open additional
	 * streams on the connection.
	 */
	if (h2c->last_sid >= 0)
		return 0;

	if (h2c->st0 >= H2_CS_ERROR)
		return 0;

	/* note: may be negative if a SETTINGS frame changes the limit */
	ret1 = h2c->streams_limit - h2c->nb_streams;

	/* we must also consider the limit imposed by stream IDs */
	ret2 = h2_streams_left(h2c);
	ret1 = MIN(ret1, ret2);
	if (ret1 > 0 && srv && srv->max_reuse >= 0) {
		ret2 = h2c->stream_cnt <= srv->max_reuse ? srv->max_reuse - h2c->stream_cnt + 1: 0;
		ret1 = MIN(ret1, ret2);
	}
	return ret1;
}


/*****************************************************************/
/* functions below are dedicated to the mux setup and management */
/*****************************************************************/

/* Initialize the mux once it's attached. For outgoing connections, the context
 * is already initialized before installing the mux, so we detect incoming
 * connections from the fact that the context is still NULL (even during mux
 * upgrades). <input> is always used as Input buffer and may contain data. It is
 * the caller responsibility to not reuse it anymore. Returns < 0 on error.
 */
static int h2_init(struct connection *conn, struct proxy *prx, struct session *sess,
		   struct buffer *input)
{
	struct h2c *h2c;
	struct task *t = NULL;
	void *conn_ctx = conn->ctx;

	TRACE_ENTER(H2_EV_H2C_NEW);

	h2c = pool_alloc(pool_head_h2c);
	if (!h2c)
		goto fail_no_h2c;

	if (conn_is_back(conn)) {
		h2c->flags = H2_CF_IS_BACK;
		h2c->shut_timeout = h2c->timeout = prx->timeout.server;
		if (tick_isset(prx->timeout.serverfin))
			h2c->shut_timeout = prx->timeout.serverfin;

		h2c->px_counters = EXTRA_COUNTERS_GET(prx->extra_counters_be,
		                                      &h2_stats_module);
	} else {
		h2c->flags = H2_CF_NONE;
		h2c->shut_timeout = h2c->timeout = prx->timeout.client;
		if (tick_isset(prx->timeout.clientfin))
			h2c->shut_timeout = prx->timeout.clientfin;

		h2c->px_counters = EXTRA_COUNTERS_GET(prx->extra_counters_fe,
		                                      &h2_stats_module);
	}

	h2c->proxy = prx;
	h2c->task = NULL;
	if (tick_isset(h2c->timeout)) {
		t = task_new_here();
		if (!t)
			goto fail;

		h2c->task = t;
		t->process = h2_timeout_task;
		t->context = h2c;
		t->expire = tick_add(now_ms, h2c->timeout);
	}

	h2c->wait_event.tasklet = tasklet_new();
	if (!h2c->wait_event.tasklet)
		goto fail;
	h2c->wait_event.tasklet->process = h2_io_cb;
	h2c->wait_event.tasklet->context = h2c;
	h2c->wait_event.events = 0;
	if (!conn_is_back(conn)) {
		/* Connection might already be in the stopping_list if subject
		 * to h1->h2 upgrade.
		 */
		if (!LIST_INLIST(&conn->stopping_list)) {
			LIST_APPEND(&mux_stopping_data[tid].list,
			            &conn->stopping_list);
		}
	}

	h2c->ddht = hpack_dht_alloc();
	if (!h2c->ddht)
		goto fail;

	/* Initialise the context. */
	h2c->st0 = H2_CS_PREFACE;
	h2c->conn = conn;
	h2c->streams_limit = h2_settings_max_concurrent_streams;
	h2c->max_id = -1;
	h2c->errcode = H2_ERR_NO_ERROR;
	h2c->rcvd_c = 0;
	h2c->rcvd_s = 0;
	h2c->nb_streams = 0;
	h2c->nb_cs = 0;
	h2c->nb_reserved = 0;
	h2c->stream_cnt = 0;

	h2c->dbuf = *input;
	h2c->dsi = -1;
	h2c->msi = -1;

	h2c->last_sid = -1;

	br_init(h2c->mbuf, sizeof(h2c->mbuf) / sizeof(h2c->mbuf[0]));
	h2c->miw = 65535; /* mux initial window size */
	h2c->mws = 65535; /* mux window size */
	h2c->mfs = 16384; /* initial max frame size */
	h2c->streams_by_id = EB_ROOT;
	LIST_INIT(&h2c->send_list);
	LIST_INIT(&h2c->fctl_list);
	LIST_INIT(&h2c->blocked_list);
	LIST_INIT(&h2c->buf_wait.list);

	conn->ctx = h2c;

	TRACE_USER("new H2 connection", H2_EV_H2C_NEW, conn);

	if (t)
		task_queue(t);

	if (h2c->flags & H2_CF_IS_BACK) {
		/* FIXME: this is temporary, for outgoing connections we need
		 * to immediately allocate a stream until the code is modified
		 * so that the caller calls ->attach(). For now the outgoing cs
		 * is stored as conn->ctx by the caller and saved in conn_ctx.
		 */
		struct h2s *h2s;

		h2s = h2c_bck_stream_new(h2c, conn_ctx, sess);
		if (!h2s)
			goto fail_stream;
	}

	HA_ATOMIC_INC(&h2c->px_counters->open_conns);
	HA_ATOMIC_INC(&h2c->px_counters->total_conns);

	/* prepare to read something */
	h2c_restart_reading(h2c, 1);
	TRACE_LEAVE(H2_EV_H2C_NEW, conn);
	return 0;
  fail_stream:
	hpack_dht_free(h2c->ddht);
  fail:
	task_destroy(t);
	if (h2c->wait_event.tasklet)
		tasklet_free(h2c->wait_event.tasklet);
	pool_free(pool_head_h2c, h2c);
  fail_no_h2c:
	if (!conn_is_back(conn))
		LIST_DEL_INIT(&conn->stopping_list);
	conn->ctx = conn_ctx; /* restore saved ctx */
	TRACE_DEVEL("leaving in error", H2_EV_H2C_NEW|H2_EV_H2C_END|H2_EV_H2C_ERR);
	return -1;
}

/* returns the next allocatable outgoing stream ID for the H2 connection, or
 * -1 if no more is allocatable.
 */
static inline int32_t h2c_get_next_sid(const struct h2c *h2c)
{
	int32_t id = (h2c->max_id + 1) | 1;

	if ((id & 0x80000000U) || (h2c->last_sid >= 0 && id > h2c->last_sid))
		id = -1;
	return id;
}

/* returns the stream associated with id <id> or NULL if not found */
static inline struct h2s *h2c_st_by_id(struct h2c *h2c, int id)
{
	struct eb32_node *node;

	if (id == 0)
		return (struct h2s *)h2_closed_stream;

	if (id > h2c->max_id)
		return (struct h2s *)h2_idle_stream;

	node = eb32_lookup(&h2c->streams_by_id, id);
	if (!node)
		return (struct h2s *)h2_closed_stream;

	return container_of(node, struct h2s, by_id);
}

/* release function. This one should be called to free all resources allocated
 * to the mux.
 */
static void h2_release(struct h2c *h2c)
{
	struct connection *conn = NULL;

	TRACE_ENTER(H2_EV_H2C_END);

	if (h2c) {
		/* The connection must be aattached to this mux to be released */
		if (h2c->conn && h2c->conn->ctx == h2c)
			conn = h2c->conn;

		TRACE_DEVEL("freeing h2c", H2_EV_H2C_END, conn);
		hpack_dht_free(h2c->ddht);

		if (LIST_INLIST(&h2c->buf_wait.list))
			LIST_DEL_INIT(&h2c->buf_wait.list);

		h2_release_buf(h2c, &h2c->dbuf);
		h2_release_mbuf(h2c);

		if (h2c->task) {
			h2c->task->context = NULL;
			task_wakeup(h2c->task, TASK_WOKEN_OTHER);
			h2c->task = NULL;
		}
		if (h2c->wait_event.tasklet)
			tasklet_free(h2c->wait_event.tasklet);
		if (conn && h2c->wait_event.events != 0)
			conn->xprt->unsubscribe(conn, conn->xprt_ctx, h2c->wait_event.events,
						&h2c->wait_event);

		HA_ATOMIC_DEC(&h2c->px_counters->open_conns);

		pool_free(pool_head_h2c, h2c);
	}

	if (conn) {
		if (!conn_is_back(conn))
			LIST_DEL_INIT(&conn->stopping_list);

		conn->mux = NULL;
		conn->ctx = NULL;
		TRACE_DEVEL("freeing conn", H2_EV_H2C_END, conn);

		conn_stop_tracking(conn);

		/* there might be a GOAWAY frame still pending in the TCP
		 * stack, and if the peer continues to send (i.e. window
		 * updates etc), this can result in losing the GOAWAY. For
		 * this reason we try to drain anything received in between.
		 */
		conn->flags |= CO_FL_WANT_DRAIN;

		conn_xprt_shutw(conn);
		conn_xprt_close(conn);
		conn_sock_shutw(conn, !conn_is_back(conn));
		conn_ctrl_close(conn);

		if (conn->destroy_cb)
			conn->destroy_cb(conn);
		conn_free(conn);
	}

	TRACE_LEAVE(H2_EV_H2C_END);
}


/******************************************************/
/* functions below are for the H2 protocol processing */
/******************************************************/

/* returns the stream if of stream <h2s> or 0 if <h2s> is NULL */
static inline __maybe_unused int h2s_id(const struct h2s *h2s)
{
	return h2s ? h2s->id : 0;
}

/* returns the sum of the stream's own window size and the mux's initial
 * window, which together form the stream's effective window size.
 */
static inline int h2s_mws(const struct h2s *h2s)
{
	return h2s->sws + h2s->h2c->miw;
}

/* returns true of the mux is currently busy as seen from stream <h2s> */
static inline __maybe_unused int h2c_mux_busy(const struct h2c *h2c, const struct h2s *h2s)
{
	if (h2c->msi < 0)
		return 0;

	if (h2c->msi == h2s_id(h2s))
		return 0;

	return 1;
}

/* marks an error on the connection */
static inline __maybe_unused void h2c_error(struct h2c *h2c, enum h2_err err)
{
	TRACE_POINT(H2_EV_H2C_ERR, h2c->conn, 0, 0, (void *)(long)(err));
	h2c->errcode = err;
	h2c->st0 = H2_CS_ERROR;
}

/* marks an error on the stream. It may also update an already closed stream
 * (e.g. to report an error after an RST was received).
 */
static inline __maybe_unused void h2s_error(struct h2s *h2s, enum h2_err err)
{
	if (h2s->id && h2s->st != H2_SS_ERROR) {
		TRACE_POINT(H2_EV_H2S_ERR, h2s->h2c->conn, h2s, 0, (void *)(long)(err));
		h2s->errcode = err;
		if (h2s->st < H2_SS_ERROR)
			h2s->st = H2_SS_ERROR;
		if (h2s->cs)
			cs_set_error(h2s->cs);
	}
}

/* attempt to notify the data layer of recv availability */
static void __maybe_unused h2s_notify_recv(struct h2s *h2s)
{
	if (h2s->subs && h2s->subs->events & SUB_RETRY_RECV) {
		TRACE_POINT(H2_EV_STRM_WAKE, h2s->h2c->conn, h2s);
		tasklet_wakeup(h2s->subs->tasklet);
		h2s->subs->events &= ~SUB_RETRY_RECV;
		if (!h2s->subs->events)
			h2s->subs = NULL;
	}
}

/* attempt to notify the data layer of send availability */
static void __maybe_unused h2s_notify_send(struct h2s *h2s)
{
	if (h2s->subs && h2s->subs->events & SUB_RETRY_SEND) {
		TRACE_POINT(H2_EV_STRM_WAKE, h2s->h2c->conn, h2s);
		h2s->flags |= H2_SF_NOTIFIED;
		tasklet_wakeup(h2s->subs->tasklet);
		h2s->subs->events &= ~SUB_RETRY_SEND;
		if (!h2s->subs->events)
			h2s->subs = NULL;
	}
	else if (h2s->flags & (H2_SF_WANT_SHUTR | H2_SF_WANT_SHUTW)) {
		TRACE_POINT(H2_EV_STRM_WAKE, h2s->h2c->conn, h2s);
		tasklet_wakeup(h2s->shut_tl);
	}
}

/* alerts the data layer, trying to wake it up by all means, following
 * this sequence :
 *   - if the h2s' data layer is subscribed to recv, then it's woken up for recv
 *   - if its subscribed to send, then it's woken up for send
 *   - if it was subscribed to neither, its ->wake() callback is called
 * It is safe to call this function with a closed stream which doesn't have a
 * conn_stream anymore.
 */
static void __maybe_unused h2s_alert(struct h2s *h2s)
{
	TRACE_ENTER(H2_EV_H2S_WAKE, h2s->h2c->conn, h2s);

	if (h2s->subs ||
	    (h2s->flags & (H2_SF_WANT_SHUTR | H2_SF_WANT_SHUTW))) {
		h2s_notify_recv(h2s);
		h2s_notify_send(h2s);
	}
	else if (h2s->cs && h2s->cs->data_cb->wake != NULL) {
		TRACE_POINT(H2_EV_STRM_WAKE, h2s->h2c->conn, h2s);
		h2s->cs->data_cb->wake(h2s->cs);
	}

	TRACE_LEAVE(H2_EV_H2S_WAKE, h2s->h2c->conn, h2s);
}

/* writes the 24-bit frame size <len> at address <frame> */
static inline __maybe_unused void h2_set_frame_size(void *frame, uint32_t len)
{
	uint8_t *out = frame;

	*out = len >> 16;
	write_n16(out + 1, len);
}

/* reads <bytes> bytes from buffer <b> starting at relative offset <o> from the
 * current pointer, dealing with wrapping, and stores the result in <dst>. It's
 * the caller's responsibility to verify that there are at least <bytes> bytes
 * available in the buffer's input prior to calling this function. The buffer
 * is assumed not to hold any output data.
 */
static inline __maybe_unused void h2_get_buf_bytes(void *dst, size_t bytes,
                                    const struct buffer *b, int o)
{
	readv_bytes(dst, bytes, b_peek(b, o), b_wrap(b) - b_peek(b, o), b_orig(b));
}

static inline __maybe_unused uint16_t h2_get_n16(const struct buffer *b, int o)
{
	return readv_n16(b_peek(b, o), b_wrap(b) - b_peek(b, o), b_orig(b));
}

static inline __maybe_unused uint32_t h2_get_n32(const struct buffer *b, int o)
{
	return readv_n32(b_peek(b, o), b_wrap(b) - b_peek(b, o), b_orig(b));
}

static inline __maybe_unused uint64_t h2_get_n64(const struct buffer *b, int o)
{
	return readv_n64(b_peek(b, o), b_wrap(b) - b_peek(b, o), b_orig(b));
}


/* Peeks an H2 frame header from offset <o> of buffer <b> into descriptor <h>.
 * The algorithm is not obvious. It turns out that H2 headers are neither
 * aligned nor do they use regular sizes. And to add to the trouble, the buffer
 * may wrap so each byte read must be checked. The header is formed like this :
 *
 *       b0         b1       b2     b3   b4         b5..b8
 *  +----------+---------+--------+----+----+----------------------+
 *  |len[23:16]|len[15:8]|len[7:0]|type|flag|sid[31:0] (big endian)|
 *  +----------+---------+--------+----+----+----------------------+
 *
 * Here we read a big-endian 64 bit word from h[1]. This way in a single read
 * we get the sid properly aligned and ordered, and 16 bits of len properly
 * ordered as well. The type and flags can be extracted using bit shifts from
 * the word, and only one extra read is needed to fetch len[16:23].
 * Returns zero if some bytes are missing, otherwise non-zero on success. The
 * buffer is assumed not to contain any output data.
 */
static __maybe_unused int h2_peek_frame_hdr(const struct buffer *b, int o, struct h2_fh *h)
{
	uint64_t w;

	if (b_data(b) < o + 9)
		return 0;

	w = h2_get_n64(b, o + 1);
	h->len = *(uint8_t*)b_peek(b, o) << 16;
	h->sid = w & 0x7FFFFFFF; /* RFC7540#4.1: R bit must be ignored */
	h->ff = w >> 32;
	h->ft = w >> 40;
	h->len += w >> 48;
	return 1;
}

/* skip the next 9 bytes corresponding to the frame header possibly parsed by
 * h2_peek_frame_hdr() above.
 */
static inline __maybe_unused void h2_skip_frame_hdr(struct buffer *b)
{
	b_del(b, 9);
}

/* same as above, automatically advances the buffer on success */
static inline __maybe_unused int h2_get_frame_hdr(struct buffer *b, struct h2_fh *h)
{
	int ret;

	ret = h2_peek_frame_hdr(b, 0, h);
	if (ret > 0)
		h2_skip_frame_hdr(b);
	return ret;
}


/* try to fragment the headers frame present at the beginning of buffer <b>,
 * enforcing a limit of <mfs> bytes per frame. Returns 0 on failure, 1 on
 * success. Typical causes of failure include a buffer not large enough to
 * add extra frame headers. The existing frame size is read in the current
 * frame. Its EH flag will be cleared if CONTINUATION frames need to be added,
 * and its length will be adjusted. The stream ID for continuation frames will
 * be copied from the initial frame's.
 */
static int h2_fragment_headers(struct buffer *b, uint32_t mfs)
{
	size_t remain    = b->data - 9;
	int extra_frames = (remain - 1) / mfs;
	size_t fsize;
	char *fptr;
	int frame;

	if (b->data <= mfs + 9)
		return 1;

	/* Too large a frame, we need to fragment it using CONTINUATION
	 * frames. We start from the end and move tails as needed.
	 */
	if (b->data + extra_frames * 9 > b->size)
		return 0;

	for (frame = extra_frames; frame; frame--) {
		fsize = ((remain - 1) % mfs) + 1;
		remain -= fsize;

		/* move data */
		fptr = b->area + 9 + remain + (frame - 1) * 9;
		memmove(fptr + 9, b->area + 9 + remain, fsize);
		b->data += 9;

		/* write new frame header */
		h2_set_frame_size(fptr, fsize);
		fptr[3] = H2_FT_CONTINUATION;
		fptr[4] = (frame == extra_frames) ? H2_F_HEADERS_END_HEADERS : 0;
		write_n32(fptr + 5, read_n32(b->area + 5));
	}

	b->area[4] &= ~H2_F_HEADERS_END_HEADERS;
	h2_set_frame_size(b->area, remain);
	return 1;
}


/* marks stream <h2s> as CLOSED and decrement the number of active streams for
 * its connection if the stream was not yet closed. Please use this exclusively
 * before closing a stream to ensure stream count is well maintained.
 */
static inline void h2s_close(struct h2s *h2s)
{
	if (h2s->st != H2_SS_CLOSED) {
		TRACE_ENTER(H2_EV_H2S_END, h2s->h2c->conn, h2s);
		h2s->h2c->nb_streams--;
		if (!h2s->id)
			h2s->h2c->nb_reserved--;
		if (h2s->cs) {
			if (!(h2s->cs->flags & CS_FL_EOS) && !b_data(&h2s->rxbuf))
				h2s_notify_recv(h2s);
		}
		HA_ATOMIC_DEC(&h2s->h2c->px_counters->open_streams);

		TRACE_LEAVE(H2_EV_H2S_END, h2s->h2c->conn, h2s);
	}
	h2s->st = H2_SS_CLOSED;
}

/* detaches an H2 stream from its H2C and releases it to the H2S pool. */
/* h2s_destroy should only ever be called by the thread that owns the stream,
 * that means that a tasklet should be used if we want to destroy the h2s
 * from another thread
 */
static void h2s_destroy(struct h2s *h2s)
{
	struct connection *conn = h2s->h2c->conn;

	TRACE_ENTER(H2_EV_H2S_END, conn, h2s);

	h2s_close(h2s);
	eb32_delete(&h2s->by_id);
	if (b_size(&h2s->rxbuf)) {
		b_free(&h2s->rxbuf);
		offer_buffers(NULL, 1);
	}

	if (h2s->subs)
		h2s->subs->events = 0;

	/* There's no need to explicitly call unsubscribe here, the only
	 * reference left would be in the h2c send_list/fctl_list, and if
	 * we're in it, we're getting out anyway
	 */
	LIST_DEL_INIT(&h2s->list);

	/* ditto, calling tasklet_free() here should be ok */
	tasklet_free(h2s->shut_tl);
	pool_free(pool_head_h2s, h2s);

	TRACE_LEAVE(H2_EV_H2S_END, conn);
}

/* allocates a new stream <id> for connection <h2c> and adds it into h2c's
 * stream tree. In case of error, nothing is added and NULL is returned. The
 * causes of errors can be any failed memory allocation. The caller is
 * responsible for checking if the connection may support an extra stream
 * prior to calling this function.
 */
static struct h2s *h2s_new(struct h2c *h2c, int id)
{
	struct h2s *h2s;

	TRACE_ENTER(H2_EV_H2S_NEW, h2c->conn);

	h2s = pool_alloc(pool_head_h2s);
	if (!h2s)
		goto out;

	h2s->shut_tl = tasklet_new();
	if (!h2s->shut_tl) {
		pool_free(pool_head_h2s, h2s);
		goto out;
	}
	h2s->subs = NULL;
	h2s->shut_tl->process = h2_deferred_shut;
	h2s->shut_tl->context = h2s;
	LIST_INIT(&h2s->list);
	h2s->h2c       = h2c;
	h2s->cs        = NULL;
	h2s->sws       = 0;
	h2s->flags     = H2_SF_NONE;
	h2s->errcode   = H2_ERR_NO_ERROR;
	h2s->st        = H2_SS_IDLE;
	h2s->status    = 0;
	h2s->body_len  = 0;
	h2s->rxbuf     = BUF_NULL;
	memset(h2s->upgrade_protocol, 0, sizeof(h2s->upgrade_protocol));

	h2s->by_id.key = h2s->id = id;
	if (id > 0)
		h2c->max_id      = id;
	else
		h2c->nb_reserved++;

	eb32_insert(&h2c->streams_by_id, &h2s->by_id);
	h2c->nb_streams++;
	h2c->stream_cnt++;

	HA_ATOMIC_INC(&h2c->px_counters->open_streams);
	HA_ATOMIC_INC(&h2c->px_counters->total_streams);

	TRACE_LEAVE(H2_EV_H2S_NEW, h2c->conn, h2s);
	return h2s;
 out:
	TRACE_DEVEL("leaving in error", H2_EV_H2S_ERR|H2_EV_H2S_END, h2c->conn);
	return NULL;
}

/* creates a new stream <id> on the h2c connection and returns it, or NULL in
 * case of memory allocation error. <input> is used as input buffer for the new
 * stream. On success, it is transferred to the stream and the mux is no longer
 * responsible of it. On error, <input> is unchanged, thus the mux must still
 * take care of it.
 */
static struct h2s *h2c_frt_stream_new(struct h2c *h2c, int id, struct buffer *input, uint32_t flags)
{
	struct session *sess = h2c->conn->owner;
	struct conn_stream *cs;
	struct h2s *h2s;

	TRACE_ENTER(H2_EV_H2S_NEW, h2c->conn);

	if (h2c->nb_streams >= h2_settings_max_concurrent_streams)
		goto out;

	h2s = h2s_new(h2c, id);
	if (!h2s)
		goto out;

	cs = cs_new(h2c->conn, h2c->conn->target);
	if (!cs)
		goto out_close;

	cs->flags |= CS_FL_NOT_FIRST;
	h2s->cs = cs;
	cs->ctx = h2s;
	h2c->nb_cs++;

	/* FIXME wrong analogy between ext-connect and websocket, this need to
	 * be refine.
	 */
	if (flags & H2_SF_EXT_CONNECT_RCVD)
		cs->flags |= CS_FL_WEBSOCKET;

	if (stream_create_from_cs(cs, input) < 0)
		goto out_free_cs;

	/* We want the accept date presented to the next stream to be the one
	 * we have now, the handshake time to be null (since the next stream
	 * is not delayed by a handshake), and the idle time to count since
	 * right now.
	 */
	sess->accept_date = date;
	sess->tv_accept   = now;
	sess->t_handshake = 0;

	/* OK done, the stream lives its own life now */
	if (h2_frt_has_too_many_cs(h2c))
		h2c->flags |= H2_CF_DEM_TOOMANY;
	TRACE_LEAVE(H2_EV_H2S_NEW, h2c->conn);
	return h2s;

 out_free_cs:
	h2c->nb_cs--;
	cs_free(cs);
	h2s->cs = NULL;
 out_close:
	h2s_destroy(h2s);
 out:
	sess_log(sess);
	TRACE_LEAVE(H2_EV_H2S_NEW|H2_EV_H2S_ERR|H2_EV_H2S_END, h2c->conn);
	return NULL;
}

/* allocates a new stream associated to conn_stream <cs> on the h2c connection
 * and returns it, or NULL in case of memory allocation error or if the highest
 * possible stream ID was reached.
 */
static struct h2s *h2c_bck_stream_new(struct h2c *h2c, struct conn_stream *cs, struct session *sess)
{
	struct h2s *h2s = NULL;

	TRACE_ENTER(H2_EV_H2S_NEW, h2c->conn);

	if (h2c->nb_streams >= h2c->streams_limit)
		goto out;

	if (h2_streams_left(h2c) < 1)
		goto out;

	/* Defer choosing the ID until we send the first message to create the stream */
	h2s = h2s_new(h2c, 0);
	if (!h2s)
		goto out;

	h2s->cs = cs;
	h2s->sess = sess;
	cs->ctx = h2s;
	h2c->nb_cs++;

 out:
	if (likely(h2s))
		TRACE_LEAVE(H2_EV_H2S_NEW, h2c->conn, h2s);
	else
		TRACE_LEAVE(H2_EV_H2S_NEW|H2_EV_H2S_ERR|H2_EV_H2S_END, h2c->conn, h2s);
	return h2s;
}

/* try to send a settings frame on the connection. Returns > 0 on success, 0 if
 * it couldn't do anything. It may return an error in h2c. See RFC7540#11.3 for
 * the various settings codes.
 */
static int h2c_send_settings(struct h2c *h2c)
{
	struct buffer *res;
	char buf_data[100]; // enough for 15 settings
	struct buffer buf;
	int mfs;
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_SETTINGS, h2c->conn);

	if (h2c_mux_busy(h2c, NULL)) {
		h2c->flags |= H2_CF_DEM_MBUSY;
		goto out;
	}

	chunk_init(&buf, buf_data, sizeof(buf_data));
	chunk_memcpy(&buf,
	       "\x00\x00\x00"      /* length    : 0 for now */
	       "\x04\x00"          /* type      : 4 (settings), flags : 0 */
	       "\x00\x00\x00\x00", /* stream ID : 0 */
	       9);

	if (h2c->flags & H2_CF_IS_BACK) {
		/* send settings_enable_push=0 */
		chunk_memcat(&buf, "\x00\x02\x00\x00\x00\x00", 6);
	}

	/* rfc 8441 #3 SETTINGS_ENABLE_CONNECT_PROTOCOL=1,
	 * sent automatically unless disabled in the global config */
	if (!(global.tune.options & GTUNE_DISABLE_H2_WEBSOCKET))
		chunk_memcat(&buf, "\x00\x08\x00\x00\x00\x01", 6);

	if (h2_settings_header_table_size != 4096) {
		char str[6] = "\x00\x01"; /* header_table_size */

		write_n32(str + 2, h2_settings_header_table_size);
		chunk_memcat(&buf, str, 6);
	}

	if (h2_settings_initial_window_size != 65535) {
		char str[6] = "\x00\x04"; /* initial_window_size */

		write_n32(str + 2, h2_settings_initial_window_size);
		chunk_memcat(&buf, str, 6);
	}

	if (h2_settings_max_concurrent_streams != 0) {
		char str[6] = "\x00\x03"; /* max_concurrent_streams */

		/* Note: 0 means "unlimited" for haproxy's config but not for
		 * the protocol, so never send this value!
		 */
		write_n32(str + 2, h2_settings_max_concurrent_streams);
		chunk_memcat(&buf, str, 6);
	}

	mfs = h2_settings_max_frame_size;
	if (mfs > global.tune.bufsize)
		mfs = global.tune.bufsize;

	if (!mfs)
		mfs = global.tune.bufsize;

	if (mfs != 16384) {
		char str[6] = "\x00\x05"; /* max_frame_size */

		/* note: similarly we could also emit MAX_HEADER_LIST_SIZE to
		 * match bufsize - rewrite size, but at the moment it seems
		 * that clients don't take care of it.
		 */
		write_n32(str + 2, mfs);
		chunk_memcat(&buf, str, 6);
	}

	h2_set_frame_size(buf.area, buf.data - 9);

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		goto out;
	}

	ret = b_istput(res, ist2(buf.area, buf.data));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			if ((res = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;
			h2c->flags |= H2_CF_MUX_MFULL;
			h2c->flags |= H2_CF_DEM_MROOM;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			ret = 0;
		}
	}
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_SETTINGS, h2c->conn);
	return ret;
}

/* Try to receive a connection preface, then upon success try to send our
 * preface which is a SETTINGS frame. Returns > 0 on success or zero on
 * missing data. It may return an error in h2c.
 */
static int h2c_frt_recv_preface(struct h2c *h2c)
{
	int ret1;
	int ret2;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_PREFACE, h2c->conn);

	ret1 = b_isteq(&h2c->dbuf, 0, b_data(&h2c->dbuf), ist(H2_CONN_PREFACE));

	if (unlikely(ret1 <= 0)) {
		if (!ret1)
			h2c->flags |= H2_CF_DEM_SHORT_READ;
		if (ret1 < 0 || conn_xprt_read0_pending(h2c->conn)) {
			TRACE_ERROR("I/O error or short read", H2_EV_RX_FRAME|H2_EV_RX_PREFACE, h2c->conn);
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			if (b_data(&h2c->dbuf) ||
			    !(((const struct session *)h2c->conn->owner)->fe->options & PR_O_IGNORE_PRB))
				HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
		}
		ret2 = 0;
		goto out;
	}

	ret2 = h2c_send_settings(h2c);
	if (ret2 > 0)
		b_del(&h2c->dbuf, ret1);
 out:
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_PREFACE, h2c->conn);
	return ret2;
}

/* Try to send a connection preface, then upon success try to send our
 * preface which is a SETTINGS frame. Returns > 0 on success or zero on
 * missing data. It may return an error in h2c.
 */
static int h2c_bck_send_preface(struct h2c *h2c)
{
	struct buffer *res;
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_PREFACE, h2c->conn);

	if (h2c_mux_busy(h2c, NULL)) {
		h2c->flags |= H2_CF_DEM_MBUSY;
		goto out;
	}

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		goto out;
	}

	if (!b_data(res)) {
		/* preface not yet sent */
		ret = b_istput(res, ist(H2_CONN_PREFACE));
		if (unlikely(ret <= 0)) {
			if (!ret) {
				if ((res = br_tail_add(h2c->mbuf)) != NULL)
					goto retry;
				h2c->flags |= H2_CF_MUX_MFULL;
				h2c->flags |= H2_CF_DEM_MROOM;
				goto out;
			}
			else {
				h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
				ret = 0;
				goto out;
			}
		}
	}
	ret = h2c_send_settings(h2c);
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_PREFACE, h2c->conn);
	return ret;
}

/* try to send a GOAWAY frame on the connection to report an error or a graceful
 * shutdown, with h2c->errcode as the error code. Returns > 0 on success or zero
 * if nothing was done. It uses h2c->last_sid as the advertised ID, or copies it
 * from h2c->max_id if it's not set yet (<0). In case of lack of room to write
 * the message, it subscribes the requester (either <h2s> or <h2c>) to future
 * notifications. It sets H2_CF_GOAWAY_SENT on success, and H2_CF_GOAWAY_FAILED
 * on unrecoverable failure. It will not attempt to send one again in this last
 * case so that it is safe to use h2c_error() to report such errors.
 */
static int h2c_send_goaway_error(struct h2c *h2c, struct h2s *h2s)
{
	struct buffer *res;
	char str[17];
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_GOAWAY, h2c->conn);

	if (h2c->flags & H2_CF_GOAWAY_FAILED) {
		ret = 1; // claim that it worked
		goto out;
	}

	if (h2c_mux_busy(h2c, h2s)) {
		if (h2s)
			h2s->flags |= H2_SF_BLK_MBUSY;
		else
			h2c->flags |= H2_CF_DEM_MBUSY;
		goto out;
	}

	/* len: 8, type: 7, flags: none, sid: 0 */
	memcpy(str, "\x00\x00\x08\x07\x00\x00\x00\x00\x00", 9);

	if (h2c->last_sid < 0)
		h2c->last_sid = h2c->max_id;

	write_n32(str + 9, h2c->last_sid);
	write_n32(str + 13, h2c->errcode);

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		if (h2s)
			h2s->flags |= H2_SF_BLK_MROOM;
		else
			h2c->flags |= H2_CF_DEM_MROOM;
		goto out;
	}

	ret = b_istput(res, ist2(str, 17));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			if ((res = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;
			h2c->flags |= H2_CF_MUX_MFULL;
			if (h2s)
				h2s->flags |= H2_SF_BLK_MROOM;
			else
				h2c->flags |= H2_CF_DEM_MROOM;
			goto out;
		}
		else {
			/* we cannot report this error using GOAWAY, so we mark
			 * it and claim a success.
			 */
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			h2c->flags |= H2_CF_GOAWAY_FAILED;
			ret = 1;
			goto out;
		}
	}
	h2c->flags |= H2_CF_GOAWAY_SENT;

	/* some codes are not for real errors, just attempts to close cleanly */
	switch (h2c->errcode) {
	case H2_ERR_NO_ERROR:
	case H2_ERR_ENHANCE_YOUR_CALM:
	case H2_ERR_REFUSED_STREAM:
	case H2_ERR_CANCEL:
		break;
	default:
		HA_ATOMIC_INC(&h2c->px_counters->goaway_resp);
	}
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_GOAWAY, h2c->conn);
	return ret;
}

/* Try to send an RST_STREAM frame on the connection for the indicated stream
 * during mux operations. This stream must be valid and cannot be closed
 * already. h2s->id will be used for the stream ID and h2s->errcode will be
 * used for the error code. h2s->st will be update to H2_SS_CLOSED if it was
 * not yet.
 *
 * Returns > 0 on success or zero if nothing was done. In case of lack of room
 * to write the message, it subscribes the stream to future notifications.
 */
static int h2s_send_rst_stream(struct h2c *h2c, struct h2s *h2s)
{
	struct buffer *res;
	char str[13];
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_RST, h2c->conn, h2s);

	if (!h2s || h2s->st == H2_SS_CLOSED) {
		ret = 1;
		goto out;
	}

	/* RFC7540#5.4.2: To avoid looping, an endpoint MUST NOT send a
	 * RST_STREAM in response to a RST_STREAM frame.
	 */
	if (h2c->dsi == h2s->id && h2c->dft == H2_FT_RST_STREAM) {
		ret = 1;
		goto ignore;
	}

	if (h2c_mux_busy(h2c, h2s)) {
		h2s->flags |= H2_SF_BLK_MBUSY;
		goto out;
	}

	/* len: 4, type: 3, flags: none */
	memcpy(str, "\x00\x00\x04\x03\x00", 5);
	write_n32(str + 5, h2s->id);
	write_n32(str + 9, h2s->errcode);

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		goto out;
	}

	ret = b_istput(res, ist2(str, 13));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			if ((res = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;
			h2c->flags |= H2_CF_MUX_MFULL;
			h2s->flags |= H2_SF_BLK_MROOM;
			goto out;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			ret = 0;
			goto out;
		}
	}

 ignore:
	h2s->flags |= H2_SF_RST_SENT;
	h2s_close(h2s);
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_RST, h2c->conn, h2s);
	return ret;
}

/* Try to send an RST_STREAM frame on the connection for the stream being
 * demuxed using h2c->dsi for the stream ID. It will use h2s->errcode as the
 * error code, even if the stream is one of the dummy ones, and will update
 * h2s->st to H2_SS_CLOSED if it was not yet.
 *
 * Returns > 0 on success or zero if nothing was done. In case of lack of room
 * to write the message, it blocks the demuxer and subscribes it to future
 * notifications. It's worth mentioning that an RST may even be sent for a
 * closed stream.
 */
static int h2c_send_rst_stream(struct h2c *h2c, struct h2s *h2s)
{
	struct buffer *res;
	char str[13];
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_RST, h2c->conn, h2s);

	/* RFC7540#5.4.2: To avoid looping, an endpoint MUST NOT send a
	 * RST_STREAM in response to a RST_STREAM frame.
	 */
	if (h2c->dft == H2_FT_RST_STREAM) {
		ret = 1;
		goto ignore;
	}

	if (h2c_mux_busy(h2c, h2s)) {
		h2c->flags |= H2_CF_DEM_MBUSY;
		goto out;
	}

	/* len: 4, type: 3, flags: none */
	memcpy(str, "\x00\x00\x04\x03\x00", 5);

	write_n32(str + 5, h2c->dsi);
	write_n32(str + 9, h2s->errcode);

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		goto out;
	}

	ret = b_istput(res, ist2(str, 13));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			if ((res = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;
			h2c->flags |= H2_CF_MUX_MFULL;
			h2c->flags |= H2_CF_DEM_MROOM;
			goto out;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			ret = 0;
			goto out;
		}
	}

 ignore:
	if (h2s->id) {
		h2s->flags |= H2_SF_RST_SENT;
		h2s_close(h2s);
	}

 out:
	HA_ATOMIC_INC(&h2c->px_counters->rst_stream_resp);
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_RST, h2c->conn, h2s);
	return ret;
}

/* try to send an empty DATA frame with the ES flag set to notify about the
 * end of stream and match a shutdown(write). If an ES was already sent as
 * indicated by HLOC/ERROR/RESET/CLOSED states, nothing is done. Returns > 0
 * on success or zero if nothing was done. In case of lack of room to write the
 * message, it subscribes the requesting stream to future notifications.
 */
static int h2_send_empty_data_es(struct h2s *h2s)
{
	struct h2c *h2c = h2s->h2c;
	struct buffer *res;
	char str[9];
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_DATA|H2_EV_TX_EOI, h2c->conn, h2s);

	if (h2s->st == H2_SS_HLOC || h2s->st == H2_SS_ERROR || h2s->st == H2_SS_CLOSED) {
		ret = 1;
		goto out;
	}

	if (h2c_mux_busy(h2c, h2s)) {
		h2s->flags |= H2_SF_BLK_MBUSY;
		goto out;
	}

	/* len: 0x000000, type: 0(DATA), flags: ES=1 */
	memcpy(str, "\x00\x00\x00\x00\x01", 5);
	write_n32(str + 5, h2s->id);

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		goto out;
	}

	ret = b_istput(res, ist2(str, 9));
	if (likely(ret > 0)) {
		h2s->flags |= H2_SF_ES_SENT;
	}
	else if (!ret) {
		if ((res = br_tail_add(h2c->mbuf)) != NULL)
			goto retry;
		h2c->flags |= H2_CF_MUX_MFULL;
		h2s->flags |= H2_SF_BLK_MROOM;
	}
	else {
		h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
		ret = 0;
	}
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_DATA|H2_EV_TX_EOI, h2c->conn, h2s);
	return ret;
}

/* wake a specific stream and assign its conn_stream some CS_FL_* flags among
 * CS_FL_ERR_PENDING and CS_FL_ERROR if needed. The stream's state
 * is automatically updated accordingly. If the stream is orphaned, it is
 * destroyed.
 */
static void h2s_wake_one_stream(struct h2s *h2s)
{
	struct h2c *h2c = h2s->h2c;

	TRACE_ENTER(H2_EV_H2S_WAKE, h2c->conn, h2s);

	if (!h2s->cs) {
		/* this stream was already orphaned */
		h2s_destroy(h2s);
		TRACE_DEVEL("leaving with no h2s", H2_EV_H2S_WAKE, h2c->conn);
		return;
	}

	if (h2c_read0_pending(h2s->h2c)) {
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HREM;
		else if (h2s->st == H2_SS_HLOC)
			h2s_close(h2s);
	}

	if ((h2s->h2c->st0 >= H2_CS_ERROR || h2s->h2c->conn->flags & CO_FL_ERROR) ||
	    (h2s->h2c->last_sid > 0 && (!h2s->id || h2s->id > h2s->h2c->last_sid))) {
		h2s->cs->flags |= CS_FL_ERR_PENDING;
		if (h2s->cs->flags & CS_FL_EOS)
			h2s->cs->flags |= CS_FL_ERROR;

		if (h2s->st < H2_SS_ERROR)
			h2s->st = H2_SS_ERROR;
	}

	h2s_alert(h2s);
	TRACE_LEAVE(H2_EV_H2S_WAKE, h2c->conn);
}

/* wake the streams attached to the connection, whose id is greater than <last>
 * or unassigned.
 */
static void h2_wake_some_streams(struct h2c *h2c, int last)
{
	struct eb32_node *node;
	struct h2s *h2s;

	TRACE_ENTER(H2_EV_H2S_WAKE, h2c->conn);

	/* Wake all streams with ID > last */
	node = eb32_lookup_ge(&h2c->streams_by_id, last + 1);
	while (node) {
		h2s = container_of(node, struct h2s, by_id);
		node = eb32_next(node);
		h2s_wake_one_stream(h2s);
	}

	/* Wake all streams with unassigned ID (ID == 0) */
	node = eb32_lookup(&h2c->streams_by_id, 0);
	while (node) {
		h2s = container_of(node, struct h2s, by_id);
		if (h2s->id > 0)
			break;
		node = eb32_next(node);
		h2s_wake_one_stream(h2s);
	}

	TRACE_LEAVE(H2_EV_H2S_WAKE, h2c->conn);
}

/* Wake up all blocked streams whose window size has become positive after the
 * mux's initial window was adjusted. This should be done after having processed
 * SETTINGS frames which have updated the mux's initial window size.
 */
static void h2c_unblock_sfctl(struct h2c *h2c)
{
	struct h2s *h2s;
	struct eb32_node *node;

	TRACE_ENTER(H2_EV_H2C_WAKE, h2c->conn);

	node = eb32_first(&h2c->streams_by_id);
	while (node) {
		h2s = container_of(node, struct h2s, by_id);
		if (h2s->flags & H2_SF_BLK_SFCTL && h2s_mws(h2s) > 0) {
			h2s->flags &= ~H2_SF_BLK_SFCTL;
			LIST_DEL_INIT(&h2s->list);
			if ((h2s->subs && h2s->subs->events & SUB_RETRY_SEND) ||
			    h2s->flags & (H2_SF_WANT_SHUTR|H2_SF_WANT_SHUTW))
				LIST_APPEND(&h2c->send_list, &h2s->list);
		}
		node = eb32_next(node);
	}

	TRACE_LEAVE(H2_EV_H2C_WAKE, h2c->conn);
}

/* processes a SETTINGS frame whose payload is <payload> for <plen> bytes, and
 * ACKs it if needed. Returns > 0 on success or zero on missing data. It may
 * return an error in h2c. The caller must have already verified frame length
 * and stream ID validity. Described in RFC7540#6.5.
 */
static int h2c_handle_settings(struct h2c *h2c)
{
	unsigned int offset;
	int error;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_SETTINGS, h2c->conn);

	if (h2c->dff & H2_F_SETTINGS_ACK) {
		if (h2c->dfl) {
			error = H2_ERR_FRAME_SIZE_ERROR;
			goto fail;
		}
		goto done;
	}

	/* process full frame only */
	if (b_data(&h2c->dbuf) < h2c->dfl) {
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		goto out0;
	}

	/* parse the frame */
	for (offset = 0; offset < h2c->dfl; offset += 6) {
		uint16_t type = h2_get_n16(&h2c->dbuf, offset);
		int32_t  arg  = h2_get_n32(&h2c->dbuf, offset + 2);

		switch (type) {
		case H2_SETTINGS_INITIAL_WINDOW_SIZE:
			/* we need to update all existing streams with the
			 * difference from the previous iws.
			 */
			if (arg < 0) { // RFC7540#6.5.2
				error = H2_ERR_FLOW_CONTROL_ERROR;
				goto fail;
			}
			h2c->miw = arg;
			break;
		case H2_SETTINGS_MAX_FRAME_SIZE:
			if (arg < 16384 || arg > 16777215) { // RFC7540#6.5.2
				TRACE_ERROR("MAX_FRAME_SIZE out of range", H2_EV_RX_FRAME|H2_EV_RX_SETTINGS, h2c->conn);
				error = H2_ERR_PROTOCOL_ERROR;
				HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
				goto fail;
			}
			h2c->mfs = arg;
			break;
		case H2_SETTINGS_HEADER_TABLE_SIZE:
			h2c->flags |= H2_CF_SHTS_UPDATED;
			break;
		case H2_SETTINGS_ENABLE_PUSH:
			if (arg < 0 || arg > 1) { // RFC7540#6.5.2
				TRACE_ERROR("ENABLE_PUSH out of range", H2_EV_RX_FRAME|H2_EV_RX_SETTINGS, h2c->conn);
				error = H2_ERR_PROTOCOL_ERROR;
				HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
				goto fail;
			}
			break;
		case H2_SETTINGS_MAX_CONCURRENT_STREAMS:
			if (h2c->flags & H2_CF_IS_BACK) {
				/* the limit is only for the backend; for the frontend it is our limit */
				if ((unsigned int)arg > h2_settings_max_concurrent_streams)
					arg = h2_settings_max_concurrent_streams;
				h2c->streams_limit = arg;
			}
			break;
		case H2_SETTINGS_ENABLE_CONNECT_PROTOCOL:
			if (arg == 1)
				h2c->flags |= H2_CF_RCVD_RFC8441;
			break;
		}
	}

	/* need to ACK this frame now */
	h2c->st0 = H2_CS_FRAME_A;
 done:
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_SETTINGS, h2c->conn);
	return 1;
 fail:
	if (!(h2c->flags & H2_CF_IS_BACK))
		sess_log(h2c->conn->owner);
	h2c_error(h2c, error);
 out0:
	TRACE_DEVEL("leaving with missing data or error", H2_EV_RX_FRAME|H2_EV_RX_SETTINGS, h2c->conn);
	return 0;
}

/* try to send an ACK for a settings frame on the connection. Returns > 0 on
 * success or one of the h2_status values.
 */
static int h2c_ack_settings(struct h2c *h2c)
{
	struct buffer *res;
	char str[9];
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_SETTINGS, h2c->conn);

	if (h2c_mux_busy(h2c, NULL)) {
		h2c->flags |= H2_CF_DEM_MBUSY;
		goto out;
	}

	memcpy(str,
	       "\x00\x00\x00"     /* length : 0 (no data)  */
	       "\x04" "\x01"      /* type   : 4, flags : ACK */
	       "\x00\x00\x00\x00" /* stream ID */, 9);

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		goto out;
	}

	ret = b_istput(res, ist2(str, 9));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			if ((res = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;
			h2c->flags |= H2_CF_MUX_MFULL;
			h2c->flags |= H2_CF_DEM_MROOM;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			ret = 0;
		}
	}
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_SETTINGS, h2c->conn);
	return ret;
}

/* processes a PING frame and schedules an ACK if needed. The caller must pass
 * the pointer to the payload in <payload>. Returns > 0 on success or zero on
 * missing data. The caller must have already verified frame length
 * and stream ID validity.
 */
static int h2c_handle_ping(struct h2c *h2c)
{
	/* schedule a response */
	if (!(h2c->dff & H2_F_PING_ACK))
		h2c->st0 = H2_CS_FRAME_A;
	return 1;
}

/* Try to send a window update for stream id <sid> and value <increment>.
 * Returns > 0 on success or zero on missing room or failure. It may return an
 * error in h2c.
 */
static int h2c_send_window_update(struct h2c *h2c, int sid, uint32_t increment)
{
	struct buffer *res;
	char str[13];
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_WU, h2c->conn);

	if (h2c_mux_busy(h2c, NULL)) {
		h2c->flags |= H2_CF_DEM_MBUSY;
		goto out;
	}

	/* length: 4, type: 8, flags: none */
	memcpy(str, "\x00\x00\x04\x08\x00", 5);
	write_n32(str + 5, sid);
	write_n32(str + 9, increment);

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		goto out;
	}

	ret = b_istput(res, ist2(str, 13));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			if ((res = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;
			h2c->flags |= H2_CF_MUX_MFULL;
			h2c->flags |= H2_CF_DEM_MROOM;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			ret = 0;
		}
	}
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_WU, h2c->conn);
	return ret;
}

/* try to send pending window update for the connection. It's safe to call it
 * with no pending updates. Returns > 0 on success or zero on missing room or
 * failure. It may return an error in h2c.
 */
static int h2c_send_conn_wu(struct h2c *h2c)
{
	int ret = 1;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_WU, h2c->conn);

	if (h2c->rcvd_c <= 0)
		goto out;

	if (!(h2c->flags & H2_CF_WINDOW_OPENED)) {
		/* increase the advertised connection window to 2G on
		 * first update.
		 */
		h2c->flags |= H2_CF_WINDOW_OPENED;
		h2c->rcvd_c += H2_INITIAL_WINDOW_INCREMENT;
	}

	/* send WU for the connection */
	ret = h2c_send_window_update(h2c, 0, h2c->rcvd_c);
	if (ret > 0)
		h2c->rcvd_c = 0;

 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_WU, h2c->conn);
	return ret;
}

/* try to send pending window update for the current dmux stream. It's safe to
 * call it with no pending updates. Returns > 0 on success or zero on missing
 * room or failure. It may return an error in h2c.
 */
static int h2c_send_strm_wu(struct h2c *h2c)
{
	int ret = 1;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_WU, h2c->conn);

	if (h2c->rcvd_s <= 0)
		goto out;

	/* send WU for the stream */
	ret = h2c_send_window_update(h2c, h2c->dsi, h2c->rcvd_s);
	if (ret > 0)
		h2c->rcvd_s = 0;
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_WU, h2c->conn);
	return ret;
}

/* try to send an ACK for a ping frame on the connection. Returns > 0 on
 * success, 0 on missing data or one of the h2_status values.
 */
static int h2c_ack_ping(struct h2c *h2c)
{
	struct buffer *res;
	char str[17];
	int ret = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_PING, h2c->conn);

	if (b_data(&h2c->dbuf) < 8)
		goto out;

	if (h2c_mux_busy(h2c, NULL)) {
		h2c->flags |= H2_CF_DEM_MBUSY;
		goto out;
	}

	memcpy(str,
	       "\x00\x00\x08"     /* length : 8 (same payload) */
	       "\x06" "\x01"      /* type   : 6, flags : ACK   */
	       "\x00\x00\x00\x00" /* stream ID */, 9);

	/* copy the original payload */
	h2_get_buf_bytes(str + 9, 8, &h2c->dbuf, 0);

	res = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, res)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		goto out;
	}

	ret = b_istput(res, ist2(str, 17));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			if ((res = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;
			h2c->flags |= H2_CF_MUX_MFULL;
			h2c->flags |= H2_CF_DEM_MROOM;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			ret = 0;
		}
	}
 out:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_PING, h2c->conn);
	return ret;
}

/* processes a WINDOW_UPDATE frame whose payload is <payload> for <plen> bytes.
 * Returns > 0 on success or zero on missing data. It may return an error in
 * h2c or h2s. The caller must have already verified frame length and stream ID
 * validity. Described in RFC7540#6.9.
 */
static int h2c_handle_window_update(struct h2c *h2c, struct h2s *h2s)
{
	int32_t inc;
	int error;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn);

	/* process full frame only */
	if (b_data(&h2c->dbuf) < h2c->dfl) {
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		goto out0;
	}

	inc = h2_get_n32(&h2c->dbuf, 0);

	if (h2c->dsi != 0) {
		/* stream window update */

		/* it's not an error to receive WU on a closed stream */
		if (h2s->st == H2_SS_CLOSED)
			goto done;

		if (!inc) {
			TRACE_ERROR("stream WINDOW_UPDATE inc=0", H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn, h2s);
			error = H2_ERR_PROTOCOL_ERROR;
			HA_ATOMIC_INC(&h2c->px_counters->strm_proto_err);
			goto strm_err;
		}

		if (h2s_mws(h2s) >= 0 && h2s_mws(h2s) + inc < 0) {
			TRACE_ERROR("stream WINDOW_UPDATE inc<0", H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn, h2s);
			error = H2_ERR_FLOW_CONTROL_ERROR;
			HA_ATOMIC_INC(&h2c->px_counters->strm_proto_err);
			goto strm_err;
		}

		h2s->sws += inc;
		if (h2s_mws(h2s) > 0 && (h2s->flags & H2_SF_BLK_SFCTL)) {
			h2s->flags &= ~H2_SF_BLK_SFCTL;
			LIST_DEL_INIT(&h2s->list);
			if ((h2s->subs && h2s->subs->events & SUB_RETRY_SEND) ||
			    h2s->flags & (H2_SF_WANT_SHUTR|H2_SF_WANT_SHUTW))
				LIST_APPEND(&h2c->send_list, &h2s->list);
		}
	}
	else {
		/* connection window update */
		if (!inc) {
			TRACE_ERROR("conn WINDOW_UPDATE inc=0", H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn);
			error = H2_ERR_PROTOCOL_ERROR;
			HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
			goto conn_err;
		}

		if (h2c->mws >= 0 && h2c->mws + inc < 0) {
			error = H2_ERR_FLOW_CONTROL_ERROR;
			goto conn_err;
		}

		h2c->mws += inc;
	}

 done:
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn);
	return 1;

 conn_err:
	h2c_error(h2c, error);
 out0:
	TRACE_DEVEL("leaving on missing data or error", H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn);
	return 0;

 strm_err:
	h2s_error(h2s, error);
	h2c->st0 = H2_CS_FRAME_E;
	TRACE_DEVEL("leaving on stream error", H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn);
	return 0;
}

/* processes a GOAWAY frame, and signals all streams whose ID is greater than
 * the last ID. Returns > 0 on success or zero on missing data. The caller must
 * have already verified frame length and stream ID validity. Described in
 * RFC7540#6.8.
 */
static int h2c_handle_goaway(struct h2c *h2c)
{
	int last;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_GOAWAY, h2c->conn);
	/* process full frame only */
	if (b_data(&h2c->dbuf) < h2c->dfl) {
		TRACE_DEVEL("leaving on missing data", H2_EV_RX_FRAME|H2_EV_RX_GOAWAY, h2c->conn);
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		return 0;
	}

	last = h2_get_n32(&h2c->dbuf, 0);
	h2c->errcode = h2_get_n32(&h2c->dbuf, 4);
	if (h2c->last_sid < 0)
		h2c->last_sid = last;
	h2_wake_some_streams(h2c, last);
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_GOAWAY, h2c->conn);
	return 1;
}

/* processes a PRIORITY frame, and either skips it or rejects if it is
 * invalid. Returns > 0 on success or zero on missing data. It may return an
 * error in h2c. The caller must have already verified frame length and stream
 * ID validity. Described in RFC7540#6.3.
 */
static int h2c_handle_priority(struct h2c *h2c)
{
	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_PRIO, h2c->conn);

	/* process full frame only */
	if (b_data(&h2c->dbuf) < h2c->dfl) {
		TRACE_DEVEL("leaving on missing data", H2_EV_RX_FRAME|H2_EV_RX_PRIO, h2c->conn);
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		return 0;
	}

	if (h2_get_n32(&h2c->dbuf, 0) == h2c->dsi) {
		/* 7540#5.3 : can't depend on itself */
		TRACE_ERROR("PRIORITY depends on itself", H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn);
		h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
		HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
		TRACE_DEVEL("leaving on error", H2_EV_RX_FRAME|H2_EV_RX_PRIO, h2c->conn);
		return 0;
	}
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_PRIO, h2c->conn);
	return 1;
}

/* processes an RST_STREAM frame, and sets the 32-bit error code on the stream.
 * Returns > 0 on success or zero on missing data. The caller must have already
 * verified frame length and stream ID validity. Described in RFC7540#6.4.
 */
static int h2c_handle_rst_stream(struct h2c *h2c, struct h2s *h2s)
{
	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_RST|H2_EV_RX_EOI, h2c->conn, h2s);

	/* process full frame only */
	if (b_data(&h2c->dbuf) < h2c->dfl) {
		TRACE_DEVEL("leaving on missing data", H2_EV_RX_FRAME|H2_EV_RX_RST|H2_EV_RX_EOI, h2c->conn, h2s);
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		return 0;
	}

	/* late RST, already handled */
	if (h2s->st == H2_SS_CLOSED) {
		TRACE_DEVEL("leaving on stream closed", H2_EV_RX_FRAME|H2_EV_RX_RST|H2_EV_RX_EOI, h2c->conn, h2s);
		return 1;
	}

	h2s->errcode = h2_get_n32(&h2c->dbuf, 0);
	h2s_close(h2s);

	if (h2s->cs) {
		cs_set_error(h2s->cs);
		h2s_alert(h2s);
	}

	h2s->flags |= H2_SF_RST_RCVD;
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_RST|H2_EV_RX_EOI, h2c->conn, h2s);
	return 1;
}

/* processes a HEADERS frame. Returns h2s on success or NULL on missing data.
 * It may return an error in h2c or h2s. The caller must consider that the
 * return value is the new h2s in case one was allocated (most common case).
 * Described in RFC7540#6.2. Most of the
 * errors here are reported as connection errors since it's impossible to
 * recover from such errors after the compression context has been altered.
 */
static struct h2s *h2c_frt_handle_headers(struct h2c *h2c, struct h2s *h2s)
{
	struct buffer rxbuf = BUF_NULL;
	unsigned long long body_len = 0;
	uint32_t flags = 0;
	int error;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);

	if (!b_size(&h2c->dbuf)) {
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		goto out; // empty buffer
	}

	if (b_data(&h2c->dbuf) < h2c->dfl && !b_full(&h2c->dbuf)) {
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		goto out; // incomplete frame
	}

	/* now either the frame is complete or the buffer is complete */
	if (h2s->st != H2_SS_IDLE) {
		/* The stream exists/existed, this must be a trailers frame */
		if (h2s->st != H2_SS_CLOSED) {
			error = h2c_decode_headers(h2c, &h2s->rxbuf, &h2s->flags, &body_len, NULL);
			/* unrecoverable error ? */
			if (h2c->st0 >= H2_CS_ERROR)
				goto out;

			if (error == 0) {
				/* Demux not blocked because of the stream, it is an incomplete frame */
				if (!(h2c->flags &H2_CF_DEM_BLOCK_ANY))
					h2c->flags |= H2_CF_DEM_SHORT_READ;
				goto out; // missing data
			}

			if (error < 0) {
				/* Failed to decode this frame (e.g. too large request)
				 * but the HPACK decompressor is still synchronized.
				 */
				h2s_error(h2s, H2_ERR_INTERNAL_ERROR);
				h2c->st0 = H2_CS_FRAME_E;
				goto out;
			}
			goto done;
		}
		/* the connection was already killed by an RST, let's consume
		 * the data and send another RST.
		 */
		error = h2c_decode_headers(h2c, &rxbuf, &flags, &body_len, NULL);
		h2s = (struct h2s*)h2_error_stream;
		goto send_rst;
	}
	else if (h2c->dsi <= h2c->max_id || !(h2c->dsi & 1)) {
		/* RFC7540#5.1.1 stream id > prev ones, and must be odd here */
		error = H2_ERR_PROTOCOL_ERROR;
		TRACE_ERROR("HEADERS on invalid stream ID", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn);
		HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
		sess_log(h2c->conn->owner);
		goto conn_err;
	}
	else if (h2c->flags & H2_CF_DEM_TOOMANY)
		goto out; // IDLE but too many cs still present

	error = h2c_decode_headers(h2c, &rxbuf, &flags, &body_len, NULL);

	/* unrecoverable error ? */
	if (h2c->st0 >= H2_CS_ERROR)
		goto out;

	if (error <= 0) {
		if (error == 0) {
			/* Demux not blocked because of the stream, it is an incomplete frame */
			if (!(h2c->flags &H2_CF_DEM_BLOCK_ANY))
				h2c->flags |= H2_CF_DEM_SHORT_READ;
			goto out; // missing data
		}

		/* Failed to decode this stream (e.g. too large request)
		 * but the HPACK decompressor is still synchronized.
		 */
		h2s = (struct h2s*)h2_error_stream;
		goto send_rst;
	}

	TRACE_USER("rcvd H2 request  ", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_STRM_NEW, h2c->conn, 0, &rxbuf);

	/* Note: we don't emit any other logs below because ff we return
	 * positively from h2c_frt_stream_new(), the stream will report the error,
	 * and if we return in error, h2c_frt_stream_new() will emit the error.
	 *
	 * Xfer the rxbuf to the stream. On success, the new stream owns the
	 * rxbuf. On error, it is released here.
	 */
	h2s = h2c_frt_stream_new(h2c, h2c->dsi, &rxbuf, flags);
	if (!h2s) {
		h2s = (struct h2s*)h2_refused_stream;
		goto send_rst;
	}

	h2s->st = H2_SS_OPEN;
	h2s->flags |= flags;
	h2s->body_len = body_len;

 done:
	if (h2c->dff & H2_F_HEADERS_END_STREAM)
		h2s->flags |= H2_SF_ES_RCVD;

	if (h2s->flags & H2_SF_ES_RCVD) {
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HREM;
		else
			h2s_close(h2s);
	}

	/* update the max stream ID if the request is being processed */
	if (h2s->id > h2c->max_id)
		h2c->max_id = h2s->id;

	return h2s;

 conn_err:
	h2c_error(h2c, error);
	goto out;

 out:
	h2_release_buf(h2c, &rxbuf);
	TRACE_DEVEL("leaving on missing data or error", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);
	return NULL;

 send_rst:
	/* make the demux send an RST for the current stream. We may only
	 * do this if we're certain that the HEADERS frame was properly
	 * decompressed so that the HPACK decoder is still kept up to date.
	 */
	h2_release_buf(h2c, &rxbuf);
	h2c->st0 = H2_CS_FRAME_E;

	TRACE_USER("rejected H2 request", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_STRM_NEW|H2_EV_STRM_END, h2c->conn, 0, &rxbuf);
	TRACE_DEVEL("leaving on error", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);
	return h2s;
}

/* processes a HEADERS frame. Returns h2s on success or NULL on missing data.
 * It may return an error in h2c or h2s. Described in RFC7540#6.2. Most of the
 * errors here are reported as connection errors since it's impossible to
 * recover from such errors after the compression context has been altered.
 */
static struct h2s *h2c_bck_handle_headers(struct h2c *h2c, struct h2s *h2s)
{
	struct buffer rxbuf = BUF_NULL;
	unsigned long long body_len = 0;
	uint32_t flags = 0;
	int error;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);

	if (!b_size(&h2c->dbuf)) {
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		goto fail; // empty buffer
	}

	if (b_data(&h2c->dbuf) < h2c->dfl && !b_full(&h2c->dbuf)) {
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		goto fail; // incomplete frame
	}

	if (h2s->st != H2_SS_CLOSED) {
		error = h2c_decode_headers(h2c, &h2s->rxbuf, &h2s->flags, &h2s->body_len, h2s->upgrade_protocol);
	}
	else {
		/* the connection was already killed by an RST, let's consume
		 * the data and send another RST.
		 */
		error = h2c_decode_headers(h2c, &rxbuf, &flags, &body_len, NULL);
		h2s = (struct h2s*)h2_error_stream;
		h2c->st0 = H2_CS_FRAME_E;
		goto send_rst;
	}

	/* unrecoverable error ? */
	if (h2c->st0 >= H2_CS_ERROR)
		goto fail;

	if (h2s->st != H2_SS_OPEN && h2s->st != H2_SS_HLOC) {
		/* RFC7540#5.1 */
		TRACE_ERROR("response HEADERS in invalid state", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);
		h2s_error(h2s, H2_ERR_STREAM_CLOSED);
		h2c->st0 = H2_CS_FRAME_E;
		HA_ATOMIC_INC(&h2c->px_counters->strm_proto_err);
		goto fail;
	}

	if (error <= 0) {
		if (error == 0) {
			/* Demux not blocked because of the stream, it is an incomplete frame */
			if (!(h2c->flags &H2_CF_DEM_BLOCK_ANY))
				h2c->flags |= H2_CF_DEM_SHORT_READ;
			goto fail; // missing data
		}

		/* stream error : send RST_STREAM */
		TRACE_ERROR("couldn't decode response HEADERS", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);
		h2s_error(h2s, H2_ERR_PROTOCOL_ERROR);
		h2c->st0 = H2_CS_FRAME_E;
		HA_ATOMIC_INC(&h2c->px_counters->strm_proto_err);
		goto fail;
	}

	if (h2c->dff & H2_F_HEADERS_END_STREAM)
		h2s->flags |= H2_SF_ES_RCVD;

	if (h2s->cs && h2s->cs->flags & CS_FL_ERROR && h2s->st < H2_SS_ERROR)
		h2s->st = H2_SS_ERROR;
	else if (h2s->flags & H2_SF_ES_RCVD) {
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HREM;
		else if (h2s->st == H2_SS_HLOC)
			h2s_close(h2s);
	}

	/* Unblock busy server h2s waiting for the response headers to validate
	 * the tunnel establishment or the end of the response of an oborted
	 * tunnel
	 */
	if ((h2s->flags & (H2_SF_BODY_TUNNEL|H2_SF_BLK_MBUSY)) == (H2_SF_BODY_TUNNEL|H2_SF_BLK_MBUSY) ||
	    (h2s->flags & (H2_SF_TUNNEL_ABRT|H2_SF_ES_RCVD|H2_SF_BLK_MBUSY)) == (H2_SF_TUNNEL_ABRT|H2_SF_ES_RCVD|H2_SF_BLK_MBUSY)) {
		TRACE_STATE("Unblock h2s blocked on tunnel establishment/abort", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
		h2s->flags &= ~H2_SF_BLK_MBUSY;
	}

	TRACE_USER("rcvd H2 response ", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, 0, &h2s->rxbuf);
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);
	return h2s;
 fail:
	TRACE_DEVEL("leaving on missing data or error", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);
	return NULL;

 send_rst:
	/* make the demux send an RST for the current stream. We may only
	 * do this if we're certain that the HEADERS frame was properly
	 * decompressed so that the HPACK decoder is still kept up to date.
	 */
	h2_release_buf(h2c, &rxbuf);
	h2c->st0 = H2_CS_FRAME_E;

	TRACE_USER("rejected H2 response", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_STRM_NEW|H2_EV_STRM_END, h2c->conn, 0, &rxbuf);
	TRACE_DEVEL("leaving on error", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);
	return h2s;
}

/* processes a DATA frame. Returns > 0 on success or zero on missing data.
 * It may return an error in h2c or h2s. Described in RFC7540#6.1.
 */
static int h2c_handle_data(struct h2c *h2c, struct h2s *h2s)
{
	int error;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);

	/* note that empty DATA frames are perfectly valid and sometimes used
	 * to signal an end of stream (with the ES flag).
	 */

	if (!b_size(&h2c->dbuf) && h2c->dfl) {
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		goto fail; // empty buffer
	}

	if (b_data(&h2c->dbuf) < h2c->dfl && !b_full(&h2c->dbuf)) {
		h2c->flags |= H2_CF_DEM_SHORT_READ;
		goto fail; // incomplete frame
	}

	/* now either the frame is complete or the buffer is complete */

	if (h2s->st != H2_SS_OPEN && h2s->st != H2_SS_HLOC) {
		/* RFC7540#6.1 */
		error = H2_ERR_STREAM_CLOSED;
		goto strm_err;
	}

	if ((h2s->flags & H2_SF_DATA_CLEN) && (h2c->dfl - h2c->dpl) > h2s->body_len) {
		/* RFC7540#8.1.2 */
		TRACE_ERROR("DATA frame larger than content-length", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
		error = H2_ERR_PROTOCOL_ERROR;
		HA_ATOMIC_INC(&h2c->px_counters->strm_proto_err);
		goto strm_err;
	}
	if (!(h2c->flags & H2_CF_IS_BACK) &&
	    (h2s->flags & (H2_SF_TUNNEL_ABRT|H2_SF_ES_SENT)) == (H2_SF_TUNNEL_ABRT|H2_SF_ES_SENT) &&
	    ((h2c->dfl - h2c->dpl) || !(h2c->dff & H2_F_DATA_END_STREAM))) {
		/* a tunnel attempt was aborted but the client still try to send some raw data.
		 * Thus the stream is closed with the CANCEL error. Here we take care it is not
		 * an empty DATA Frame with the ES flag. The error is only handled if ES was
		 * already sent to the client because depending on the scheduling, these data may
		 * have been sent before the server response but not handle here.
		 */
		TRACE_ERROR("Request DATA frame for aborted tunnel", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
		error = H2_ERR_CANCEL;
		goto strm_err;
	}

	if (!h2_frt_transfer_data(h2s))
		goto fail;

	/* call the upper layers to process the frame, then let the upper layer
	 * notify the stream about any change.
	 */
	if (!h2s->cs) {
		/* The upper layer has already closed, this may happen on
		 * 4xx/redirects during POST, or when receiving a response
		 * from an H2 server after the client has aborted.
		 */
		error = H2_ERR_CANCEL;
		goto strm_err;
	}

	if (h2c->st0 >= H2_CS_ERROR)
		goto fail;

	if (h2s->st >= H2_SS_ERROR) {
		/* stream error : send RST_STREAM */
		h2c->st0 = H2_CS_FRAME_E;
	}

	/* check for completion : the callee will change this to FRAME_A or
	 * FRAME_H once done.
	 */
	if (h2c->st0 == H2_CS_FRAME_P)
		goto fail;

	/* last frame */
	if (h2c->dff & H2_F_DATA_END_STREAM) {
		h2s->flags |= H2_SF_ES_RCVD;
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HREM;
		else
			h2s_close(h2s);

		if (h2s->flags & H2_SF_DATA_CLEN && h2s->body_len) {
			/* RFC7540#8.1.2 */
			TRACE_ERROR("ES on DATA frame before content-length", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
			error = H2_ERR_PROTOCOL_ERROR;
			HA_ATOMIC_INC(&h2c->px_counters->strm_proto_err);
			goto strm_err;
		}
	}

	/* Unblock busy server h2s waiting for the end of the response for an
	 * aborted tunnel
	 */
	if ((h2c->flags & H2_CF_IS_BACK) &&
	    (h2s->flags & (H2_SF_TUNNEL_ABRT|H2_SF_ES_RCVD|H2_SF_BLK_MBUSY)) == (H2_SF_TUNNEL_ABRT|H2_SF_ES_RCVD|H2_SF_BLK_MBUSY)) {
		TRACE_STATE("Unblock h2s blocked on tunnel abort", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
		h2s->flags &= ~H2_SF_BLK_MBUSY;
	}

	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
	return 1;

 strm_err:
	h2s_error(h2s, error);
	h2c->st0 = H2_CS_FRAME_E;
 fail:
	TRACE_DEVEL("leaving on missing data or error", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
	return 0;
}

/* check that the current frame described in h2c->{dsi,dft,dfl,dff,...} is
 * valid for the current stream state. This is needed only after parsing the
 * frame header but in practice it can be performed at any time during
 * H2_CS_FRAME_P since no state transition happens there. Returns >0 on success
 * or 0 in case of error, in which case either h2s or h2c will carry an error.
 */
static int h2_frame_check_vs_state(struct h2c *h2c, struct h2s *h2s)
{
	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_FHDR, h2c->conn, h2s);

	if (h2s->st == H2_SS_IDLE &&
	    h2c->dft != H2_FT_HEADERS && h2c->dft != H2_FT_PRIORITY) {
		/* RFC7540#5.1: any frame other than HEADERS or PRIORITY in
		 * this state MUST be treated as a connection error
		 */
		TRACE_ERROR("invalid frame type for IDLE state", H2_EV_RX_FRAME|H2_EV_RX_FHDR, h2c->conn, h2s);
		h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
		if (!h2c->nb_streams && !(h2c->flags & H2_CF_IS_BACK)) {
			/* only log if no other stream can report the error */
			sess_log(h2c->conn->owner);
		}
		HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
		TRACE_DEVEL("leaving in error (idle&!hdrs&!prio)", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn, h2s);
		return 0;
	}

	if (h2s->st == H2_SS_IDLE && (h2c->flags & H2_CF_IS_BACK)) {
		/* only PUSH_PROMISE would be permitted here */
		TRACE_ERROR("invalid frame type for IDLE state (back)", H2_EV_RX_FRAME|H2_EV_RX_FHDR, h2c->conn, h2s);
		h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
		HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
		TRACE_DEVEL("leaving in error (idle&back)", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn, h2s);
		return 0;
	}

	if (h2s->st == H2_SS_HREM && h2c->dft != H2_FT_WINDOW_UPDATE &&
	    h2c->dft != H2_FT_RST_STREAM && h2c->dft != H2_FT_PRIORITY) {
		/* RFC7540#5.1: any frame other than WU/PRIO/RST in
		 * this state MUST be treated as a stream error.
		 * 6.2, 6.6 and 6.10 further mandate that HEADERS/
		 * PUSH_PROMISE/CONTINUATION cause connection errors.
		 */
		if (h2_ft_bit(h2c->dft) & H2_FT_HDR_MASK) {
			TRACE_ERROR("invalid frame type for HREM state", H2_EV_RX_FRAME|H2_EV_RX_FHDR, h2c->conn, h2s);
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
		}
		else {
			h2s_error(h2s, H2_ERR_STREAM_CLOSED);
		}
		TRACE_DEVEL("leaving in error (hrem&!wu&!rst&!prio)", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn, h2s);
		return 0;
	}

	/* Below the management of frames received in closed state is a
	 * bit hackish because the spec makes strong differences between
	 * streams closed by receiving RST, sending RST, and seeing ES
	 * in both directions. In addition to this, the creation of a
	 * new stream reusing the identifier of a closed one will be
	 * detected here. Given that we cannot keep track of all closed
	 * streams forever, we consider that unknown closed streams were
	 * closed on RST received, which allows us to respond with an
	 * RST without breaking the connection (eg: to abort a transfer).
	 * Some frames have to be silently ignored as well.
	 */
	if (h2s->st == H2_SS_CLOSED && h2c->dsi) {
		if (!(h2c->flags & H2_CF_IS_BACK) && h2_ft_bit(h2c->dft) & H2_FT_HDR_MASK) {
			/* #5.1.1: The identifier of a newly
			 * established stream MUST be numerically
			 * greater than all streams that the initiating
			 * endpoint has opened or reserved. This
			 * governs streams that are opened using a
			 * HEADERS frame and streams that are reserved
			 * using PUSH_PROMISE. An endpoint that
			 * receives an unexpected stream identifier
			 * MUST respond with a connection error.
			 */
			h2c_error(h2c, H2_ERR_STREAM_CLOSED);
			TRACE_DEVEL("leaving in error (closed&hdrmask)", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn, h2s);
			return 0;
		}

		if (h2s->flags & H2_SF_RST_RCVD &&
		    !(h2_ft_bit(h2c->dft) & (H2_FT_HDR_MASK | H2_FT_RST_STREAM_BIT | H2_FT_PRIORITY_BIT | H2_FT_WINDOW_UPDATE_BIT))) {
			/* RFC7540#5.1:closed: an endpoint that
			 * receives any frame other than PRIORITY after
			 * receiving a RST_STREAM MUST treat that as a
			 * stream error of type STREAM_CLOSED.
			 *
			 * Note that old streams fall into this category
			 * and will lead to an RST being sent.
			 *
			 * However, we cannot generalize this to all frame types. Those
			 * carrying compression state must still be processed before
			 * being dropped or we'll desynchronize the decoder. This can
			 * happen with request trailers received after sending an
			 * RST_STREAM, or with header/trailers responses received after
			 * sending RST_STREAM (aborted stream).
			 *
			 * In addition, since our CLOSED streams always carry the
			 * RST_RCVD bit, we don't want to accidentally catch valid
			 * frames for a closed stream, i.e. RST/PRIO/WU.
			 */
			h2s_error(h2s, H2_ERR_STREAM_CLOSED);
			h2c->st0 = H2_CS_FRAME_E;
			TRACE_DEVEL("leaving in error (rst_rcvd&!hdrmask)", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn, h2s);
			return 0;
		}

		/* RFC7540#5.1:closed: if this state is reached as a
		 * result of sending a RST_STREAM frame, the peer that
		 * receives the RST_STREAM might have already sent
		 * frames on the stream that cannot be withdrawn. An
		 * endpoint MUST ignore frames that it receives on
		 * closed streams after it has sent a RST_STREAM
		 * frame. An endpoint MAY choose to limit the period
		 * over which it ignores frames and treat frames that
		 * arrive after this time as being in error.
		 */
		if (h2s->id && !(h2s->flags & H2_SF_RST_SENT)) {
			/* RFC7540#5.1:closed: any frame other than
			 * PRIO/WU/RST in this state MUST be treated as
			 * a connection error
			 */
			if (h2c->dft != H2_FT_RST_STREAM &&
			    h2c->dft != H2_FT_PRIORITY &&
			    h2c->dft != H2_FT_WINDOW_UPDATE) {
				h2c_error(h2c, H2_ERR_STREAM_CLOSED);
				TRACE_DEVEL("leaving in error (rst_sent&!rst&!prio&!wu)", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn, h2s);
				return 0;
			}
		}
	}
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_FHDR, h2c->conn, h2s);
	return 1;
}

/* process Rx frames to be demultiplexed */
static void h2_process_demux(struct h2c *h2c)
{
	struct h2s *h2s = NULL, *tmp_h2s;
	struct h2_fh hdr;
	unsigned int padlen = 0;
	int32_t old_iw = h2c->miw;

	TRACE_ENTER(H2_EV_H2C_WAKE, h2c->conn);

	if (h2c->st0 >= H2_CS_ERROR)
		goto out;

	if (unlikely(h2c->st0 < H2_CS_FRAME_H)) {
		if (h2c->st0 == H2_CS_PREFACE) {
			TRACE_STATE("expecting preface", H2_EV_RX_PREFACE, h2c->conn);
			if (h2c->flags & H2_CF_IS_BACK)
				goto out;

			if (unlikely(h2c_frt_recv_preface(h2c) <= 0)) {
				/* RFC7540#3.5: a GOAWAY frame MAY be omitted */
				if (h2c->st0 == H2_CS_ERROR) {
					TRACE_PROTO("failed to receive preface", H2_EV_RX_PREFACE|H2_EV_PROTO_ERR, h2c->conn);
					h2c->st0 = H2_CS_ERROR2;
					if (b_data(&h2c->dbuf) ||
					    !(((const struct session *)h2c->conn->owner)->fe->options & (PR_O_NULLNOLOG|PR_O_IGNORE_PRB)))
						sess_log(h2c->conn->owner);
				}
				goto done;
			}
			TRACE_PROTO("received preface", H2_EV_RX_PREFACE, h2c->conn);

			h2c->max_id = 0;
			h2c->st0 = H2_CS_SETTINGS1;
			TRACE_STATE("switching to SETTINGS1", H2_EV_RX_PREFACE, h2c->conn);
		}

		if (h2c->st0 == H2_CS_SETTINGS1) {
			/* ensure that what is pending is a valid SETTINGS frame
			 * without an ACK.
			 */
			TRACE_STATE("expecting settings", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_SETTINGS, h2c->conn);
			if (!h2_get_frame_hdr(&h2c->dbuf, &hdr)) {
				/* RFC7540#3.5: a GOAWAY frame MAY be omitted */
				h2c->flags |= H2_CF_DEM_SHORT_READ;
				if (h2c->st0 == H2_CS_ERROR) {
					TRACE_ERROR("failed to receive settings", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_SETTINGS|H2_EV_PROTO_ERR, h2c->conn);
					h2c->st0 = H2_CS_ERROR2;
					if (!(h2c->flags & H2_CF_IS_BACK))
						sess_log(h2c->conn->owner);
				}
				goto done;
			}

			if (hdr.sid || hdr.ft != H2_FT_SETTINGS || hdr.ff & H2_F_SETTINGS_ACK) {
				/* RFC7540#3.5: a GOAWAY frame MAY be omitted */
				TRACE_ERROR("unexpected frame type or flags", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_SETTINGS|H2_EV_PROTO_ERR, h2c->conn);
				h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
				h2c->st0 = H2_CS_ERROR2;
				if (!(h2c->flags & H2_CF_IS_BACK))
					sess_log(h2c->conn->owner);
				HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
				goto done;
			}

			if ((int)hdr.len < 0 || (int)hdr.len > global.tune.bufsize) {
				/* RFC7540#3.5: a GOAWAY frame MAY be omitted */
				TRACE_ERROR("invalid settings frame length", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_SETTINGS|H2_EV_PROTO_ERR, h2c->conn);
				h2c_error(h2c, H2_ERR_FRAME_SIZE_ERROR);
				h2c->st0 = H2_CS_ERROR2;
				if (!(h2c->flags & H2_CF_IS_BACK))
					sess_log(h2c->conn->owner);
				goto done;
			}

			/* that's OK, switch to FRAME_P to process it. This is
			 * a SETTINGS frame whose header has already been
			 * deleted above.
			 */
			padlen = 0;
			HA_ATOMIC_INC(&h2c->px_counters->settings_rcvd);
			goto new_frame;
		}
	}

	/* process as many incoming frames as possible below */
	while (1) {
		int ret = 0;

		if (!b_data(&h2c->dbuf)) {
			TRACE_DEVEL("no more Rx data", H2_EV_RX_FRAME, h2c->conn);
			h2c->flags |= H2_CF_DEM_SHORT_READ;
			break;
		}

		if (h2c->st0 >= H2_CS_ERROR) {
			TRACE_STATE("end of connection reported", H2_EV_RX_FRAME|H2_EV_RX_EOI, h2c->conn);
			break;
		}

		if (h2c->st0 == H2_CS_FRAME_H) {
			h2c->rcvd_s = 0;

			TRACE_STATE("expecting H2 frame header", H2_EV_RX_FRAME|H2_EV_RX_FHDR, h2c->conn);
			if (!h2_peek_frame_hdr(&h2c->dbuf, 0, &hdr)) {
				h2c->flags |= H2_CF_DEM_SHORT_READ;
				break;
			}

			if ((int)hdr.len < 0 || (int)hdr.len > global.tune.bufsize) {
				TRACE_ERROR("invalid H2 frame length", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn);
				h2c_error(h2c, H2_ERR_FRAME_SIZE_ERROR);
				if (!h2c->nb_streams && !(h2c->flags & H2_CF_IS_BACK)) {
					/* only log if no other stream can report the error */
					sess_log(h2c->conn->owner);
				}
				HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
				break;
			}

			padlen = 0;
			if (h2_ft_bit(hdr.ft) & H2_FT_PADDED_MASK && hdr.ff & H2_F_PADDED) {
				/* If the frame is padded (HEADERS, PUSH_PROMISE or DATA),
				 * we read the pad length and drop it from the remaining
				 * payload (one byte + the 9 remaining ones = 10 total
				 * removed), so we have a frame payload starting after the
				 * pad len. Flow controlled frames (DATA) also count the
				 * padlen in the flow control, so it must be adjusted.
				 */
				if (hdr.len < 1) {
					TRACE_ERROR("invalid H2 padded frame length", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn);
					h2c_error(h2c, H2_ERR_FRAME_SIZE_ERROR);
					if (!(h2c->flags & H2_CF_IS_BACK))
						sess_log(h2c->conn->owner);
					HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
					goto done;
				}
				hdr.len--;

				if (b_data(&h2c->dbuf) < 10) {
					h2c->flags |= H2_CF_DEM_SHORT_READ;
					break; // missing padlen
				}

				padlen = *(uint8_t *)b_peek(&h2c->dbuf, 9);

				if (padlen > hdr.len) {
					TRACE_ERROR("invalid H2 padding length", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn);
					/* RFC7540#6.1 : pad length = length of
					 * frame payload or greater => error.
					 */
					h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
					if (!(h2c->flags & H2_CF_IS_BACK))
						sess_log(h2c->conn->owner);
					HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
					goto done;
				}

				if (h2_ft_bit(hdr.ft) & H2_FT_FC_MASK) {
					h2c->rcvd_c++;
					h2c->rcvd_s++;
				}
				b_del(&h2c->dbuf, 1);
			}
			h2_skip_frame_hdr(&h2c->dbuf);

		new_frame:
			h2c->dfl = hdr.len;
			h2c->dsi = hdr.sid;
			h2c->dft = hdr.ft;
			h2c->dff = hdr.ff;
			h2c->dpl = padlen;
			TRACE_STATE("rcvd H2 frame header, switching to FRAME_P state", H2_EV_RX_FRAME|H2_EV_RX_FHDR, h2c->conn);
			h2c->st0 = H2_CS_FRAME_P;

			/* check for minimum basic frame format validity */
			ret = h2_frame_check(h2c->dft, 1, h2c->dsi, h2c->dfl, global.tune.bufsize);
			if (ret != H2_ERR_NO_ERROR) {
				TRACE_ERROR("received invalid H2 frame header", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_PROTO_ERR, h2c->conn);
				h2c_error(h2c, ret);
				if (!(h2c->flags & H2_CF_IS_BACK))
					sess_log(h2c->conn->owner);
				HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
				goto done;
			}
		}

		/* Only H2_CS_FRAME_P, H2_CS_FRAME_A and H2_CS_FRAME_E here.
		 * H2_CS_FRAME_P indicates an incomplete previous operation
		 * (most often the first attempt) and requires some validity
		 * checks for the frame and the current state. The two other
		 * ones are set after completion (or abortion) and must skip
		 * validity checks.
		 */
		tmp_h2s = h2c_st_by_id(h2c, h2c->dsi);

		if (tmp_h2s != h2s && h2s && h2s->cs &&
		    (b_data(&h2s->rxbuf) ||
		     h2c_read0_pending(h2c) ||
		     h2s->st == H2_SS_CLOSED ||
		     (h2s->flags & H2_SF_ES_RCVD) ||
		     (h2s->cs->flags & (CS_FL_ERROR|CS_FL_ERR_PENDING|CS_FL_EOS)))) {
			/* we may have to signal the upper layers */
			TRACE_DEVEL("notifying stream before switching SID", H2_EV_RX_FRAME|H2_EV_STRM_WAKE, h2c->conn, h2s);
			h2s->cs->flags |= CS_FL_RCV_MORE;
			h2s_notify_recv(h2s);
		}
		h2s = tmp_h2s;

		if (h2c->st0 == H2_CS_FRAME_E ||
		    (h2c->st0 == H2_CS_FRAME_P && !h2_frame_check_vs_state(h2c, h2s))) {
			TRACE_PROTO("stream error reported", H2_EV_RX_FRAME|H2_EV_PROTO_ERR, h2c->conn, h2s);
			goto strm_err;
		}

		switch (h2c->dft) {
		case H2_FT_SETTINGS:
			if (h2c->st0 == H2_CS_FRAME_P) {
				TRACE_PROTO("receiving H2 SETTINGS frame", H2_EV_RX_FRAME|H2_EV_RX_SETTINGS, h2c->conn, h2s);
				ret = h2c_handle_settings(h2c);
			}
			HA_ATOMIC_INC(&h2c->px_counters->settings_rcvd);

			if (h2c->st0 == H2_CS_FRAME_A) {
				TRACE_PROTO("sending H2 SETTINGS ACK frame", H2_EV_TX_FRAME|H2_EV_RX_SETTINGS, h2c->conn, h2s);
				ret = h2c_ack_settings(h2c);
			}
			break;

		case H2_FT_PING:
			if (h2c->st0 == H2_CS_FRAME_P) {
				TRACE_PROTO("receiving H2 PING frame", H2_EV_RX_FRAME|H2_EV_RX_PING, h2c->conn, h2s);
				ret = h2c_handle_ping(h2c);
			}

			if (h2c->st0 == H2_CS_FRAME_A) {
				TRACE_PROTO("sending H2 PING ACK frame", H2_EV_TX_FRAME|H2_EV_TX_SETTINGS, h2c->conn, h2s);
				ret = h2c_ack_ping(h2c);
			}
			break;

		case H2_FT_WINDOW_UPDATE:
			if (h2c->st0 == H2_CS_FRAME_P) {
				TRACE_PROTO("receiving H2 WINDOW_UPDATE frame", H2_EV_RX_FRAME|H2_EV_RX_WU, h2c->conn, h2s);
				ret = h2c_handle_window_update(h2c, h2s);
			}
			break;

		case H2_FT_CONTINUATION:
			/* RFC7540#6.10: CONTINUATION may only be preceded by
			 * a HEADERS/PUSH_PROMISE/CONTINUATION frame. These
			 * frames' parsers consume all following CONTINUATION
			 * frames so this one is out of sequence.
			 */
			TRACE_ERROR("received unexpected H2 CONTINUATION frame", H2_EV_RX_FRAME|H2_EV_RX_CONT|H2_EV_H2C_ERR, h2c->conn, h2s);
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			if (!(h2c->flags & H2_CF_IS_BACK))
				sess_log(h2c->conn->owner);
			HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
			goto done;

		case H2_FT_HEADERS:
			if (h2c->st0 == H2_CS_FRAME_P) {
				TRACE_PROTO("receiving H2 HEADERS frame", H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn, h2s);
				if (h2c->flags & H2_CF_IS_BACK)
					tmp_h2s = h2c_bck_handle_headers(h2c, h2s);
				else
					tmp_h2s = h2c_frt_handle_headers(h2c, h2s);
				if (tmp_h2s) {
					h2s = tmp_h2s;
					ret = 1;
				}
			}
			HA_ATOMIC_INC(&h2c->px_counters->headers_rcvd);
			break;

		case H2_FT_DATA:
			if (h2c->st0 == H2_CS_FRAME_P) {
				TRACE_PROTO("receiving H2 DATA frame", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
				ret = h2c_handle_data(h2c, h2s);
			}
			HA_ATOMIC_INC(&h2c->px_counters->data_rcvd);

			if (h2c->st0 == H2_CS_FRAME_A) {
				TRACE_PROTO("sending stream WINDOW_UPDATE frame", H2_EV_TX_FRAME|H2_EV_TX_WU, h2c->conn, h2s);
				ret = h2c_send_strm_wu(h2c);
			}
			break;

		case H2_FT_PRIORITY:
			if (h2c->st0 == H2_CS_FRAME_P) {
				TRACE_PROTO("receiving H2 PRIORITY frame", H2_EV_RX_FRAME|H2_EV_RX_PRIO, h2c->conn, h2s);
				ret = h2c_handle_priority(h2c);
			}
			break;

		case H2_FT_RST_STREAM:
			if (h2c->st0 == H2_CS_FRAME_P) {
				TRACE_PROTO("receiving H2 RST_STREAM frame", H2_EV_RX_FRAME|H2_EV_RX_RST|H2_EV_RX_EOI, h2c->conn, h2s);
				ret = h2c_handle_rst_stream(h2c, h2s);
			}
			HA_ATOMIC_INC(&h2c->px_counters->rst_stream_rcvd);
			break;

		case H2_FT_GOAWAY:
			if (h2c->st0 == H2_CS_FRAME_P) {
				TRACE_PROTO("receiving H2 GOAWAY frame", H2_EV_RX_FRAME|H2_EV_RX_GOAWAY, h2c->conn, h2s);
				ret = h2c_handle_goaway(h2c);
			}
			HA_ATOMIC_INC(&h2c->px_counters->goaway_rcvd);
			break;

			/* implement all extra frame types here */
		default:
			TRACE_PROTO("receiving H2 ignored frame", H2_EV_RX_FRAME, h2c->conn, h2s);
			/* drop frames that we ignore. They may be larger than
			 * the buffer so we drain all of their contents until
			 * we reach the end.
			 */
			ret = MIN(b_data(&h2c->dbuf), h2c->dfl);
			b_del(&h2c->dbuf, ret);
			h2c->dfl -= ret;
			ret = h2c->dfl == 0;
		}

	strm_err:
		/* We may have to send an RST if not done yet */
		if (h2s->st == H2_SS_ERROR) {
			TRACE_STATE("stream error, switching to FRAME_E", H2_EV_RX_FRAME|H2_EV_H2S_ERR, h2c->conn, h2s);
			h2c->st0 = H2_CS_FRAME_E;
		}

		if (h2c->st0 == H2_CS_FRAME_E) {
			TRACE_PROTO("sending H2 RST_STREAM frame", H2_EV_TX_FRAME|H2_EV_TX_RST|H2_EV_TX_EOI, h2c->conn, h2s);
			ret = h2c_send_rst_stream(h2c, h2s);
		}

		/* error or missing data condition met above ? */
		if (ret <= 0)
			break;

		if (h2c->st0 != H2_CS_FRAME_H) {
			if (h2c->dfl)
				TRACE_DEVEL("skipping remaining frame payload", H2_EV_RX_FRAME, h2c->conn, h2s);
			ret = MIN(b_data(&h2c->dbuf), h2c->dfl);
			b_del(&h2c->dbuf, ret);
			h2c->dfl -= ret;
			if (!h2c->dfl) {
				TRACE_STATE("switching to FRAME_H", H2_EV_RX_FRAME|H2_EV_RX_FHDR, h2c->conn);
				h2c->st0 = H2_CS_FRAME_H;
				h2c->dsi = -1;
			}
		}
	}

	if (h2c->rcvd_c > 0 &&
	    !(h2c->flags & (H2_CF_MUX_MFULL | H2_CF_DEM_MBUSY | H2_CF_DEM_MROOM))) {
		TRACE_PROTO("sending H2 WINDOW_UPDATE frame", H2_EV_TX_FRAME|H2_EV_TX_WU, h2c->conn);
		h2c_send_conn_wu(h2c);
	}

 done:
	if (h2c->st0 >= H2_CS_ERROR || (h2c->flags & H2_CF_DEM_SHORT_READ)) {
		if (h2c->flags & H2_CF_RCVD_SHUT)
			h2c->flags |= H2_CF_END_REACHED;
	}

	if (h2s && h2s->cs &&
	    (b_data(&h2s->rxbuf) ||
	     h2c_read0_pending(h2c) ||
	     h2s->st == H2_SS_CLOSED ||
	     (h2s->flags & H2_SF_ES_RCVD) ||
	     (h2s->cs->flags & (CS_FL_ERROR|CS_FL_ERR_PENDING|CS_FL_EOS)))) {
		/* we may have to signal the upper layers */
		TRACE_DEVEL("notifying stream before switching SID", H2_EV_RX_FRAME|H2_EV_H2S_WAKE, h2c->conn, h2s);
		h2s->cs->flags |= CS_FL_RCV_MORE;
		h2s_notify_recv(h2s);
	}

	if (old_iw != h2c->miw) {
		TRACE_STATE("notifying streams about SFCTL increase", H2_EV_RX_FRAME|H2_EV_H2S_WAKE, h2c->conn);
		h2c_unblock_sfctl(h2c);
	}

	h2c_restart_reading(h2c, 0);
 out:
	TRACE_LEAVE(H2_EV_H2C_WAKE, h2c->conn);
	return;
}

/* resume each h2s eligible for sending in list head <head> */
static void h2_resume_each_sending_h2s(struct h2c *h2c, struct list *head)
{
	struct h2s *h2s, *h2s_back;

	TRACE_ENTER(H2_EV_H2C_SEND|H2_EV_H2S_WAKE, h2c->conn);

	list_for_each_entry_safe(h2s, h2s_back, head, list) {
		if (h2c->mws <= 0 ||
		    h2c->flags & H2_CF_MUX_BLOCK_ANY ||
		    h2c->st0 >= H2_CS_ERROR)
			break;

		h2s->flags &= ~H2_SF_BLK_ANY;

		if (h2s->flags & H2_SF_NOTIFIED)
			continue;

		/* If the sender changed his mind and unsubscribed, let's just
		 * remove the stream from the send_list.
		 */
		if (!(h2s->flags & (H2_SF_WANT_SHUTR|H2_SF_WANT_SHUTW)) &&
		    (!h2s->subs || !(h2s->subs->events & SUB_RETRY_SEND))) {
			LIST_DEL_INIT(&h2s->list);
			continue;
		}

		if (h2s->subs && h2s->subs->events & SUB_RETRY_SEND) {
			h2s->flags |= H2_SF_NOTIFIED;
			tasklet_wakeup(h2s->subs->tasklet);
			h2s->subs->events &= ~SUB_RETRY_SEND;
			if (!h2s->subs->events)
				h2s->subs = NULL;
		}
		else if (h2s->flags & (H2_SF_WANT_SHUTR|H2_SF_WANT_SHUTW)) {
			tasklet_wakeup(h2s->shut_tl);
		}
	}

	TRACE_LEAVE(H2_EV_H2C_SEND|H2_EV_H2S_WAKE, h2c->conn);
}

/* process Tx frames from streams to be multiplexed. Returns > 0 if it reached
 * the end.
 */
static int h2_process_mux(struct h2c *h2c)
{
	TRACE_ENTER(H2_EV_H2C_WAKE, h2c->conn);

	if (unlikely(h2c->st0 < H2_CS_FRAME_H)) {
		if (unlikely(h2c->st0 == H2_CS_PREFACE && (h2c->flags & H2_CF_IS_BACK))) {
			if (unlikely(h2c_bck_send_preface(h2c) <= 0)) {
				/* RFC7540#3.5: a GOAWAY frame MAY be omitted */
				if (h2c->st0 == H2_CS_ERROR)
					h2c->st0 = H2_CS_ERROR2;
				goto fail;
			}
			h2c->st0 = H2_CS_SETTINGS1;
		}
		/* need to wait for the other side */
		if (h2c->st0 < H2_CS_FRAME_H)
			goto done;
	}

	/* start by sending possibly pending window updates */
	if (h2c->rcvd_s > 0 &&
	    !(h2c->flags & (H2_CF_MUX_MFULL | H2_CF_MUX_MALLOC)) &&
	    h2c_send_strm_wu(h2c) < 0)
		goto fail;

	if (h2c->rcvd_c > 0 &&
	    !(h2c->flags & (H2_CF_MUX_MFULL | H2_CF_MUX_MALLOC)) &&
	    h2c_send_conn_wu(h2c) < 0)
		goto fail;

	/* First we always process the flow control list because the streams
	 * waiting there were already elected for immediate emission but were
	 * blocked just on this.
	 */
	h2_resume_each_sending_h2s(h2c, &h2c->fctl_list);
	h2_resume_each_sending_h2s(h2c, &h2c->send_list);

 fail:
	if (unlikely(h2c->st0 >= H2_CS_ERROR)) {
		if (h2c->st0 == H2_CS_ERROR) {
			if (h2c->max_id >= 0) {
				h2c_send_goaway_error(h2c, NULL);
				if (h2c->flags & H2_CF_MUX_BLOCK_ANY)
					goto out0;
			}

			h2c->st0 = H2_CS_ERROR2; // sent (or failed hard) !
		}
	}
 done:
	TRACE_LEAVE(H2_EV_H2C_WAKE, h2c->conn);
	return 1;
 out0:
	TRACE_DEVEL("leaving in blocked situation", H2_EV_H2C_WAKE, h2c->conn);
	return 0;
}


/* Attempt to read data, and subscribe if none available.
 * The function returns 1 if data has been received, otherwise zero.
 */
static int h2_recv(struct h2c *h2c)
{
	struct connection *conn = h2c->conn;
	struct buffer *buf;
	int max;
	size_t ret;

	TRACE_ENTER(H2_EV_H2C_RECV, h2c->conn);

	if (h2c->wait_event.events & SUB_RETRY_RECV) {
		TRACE_DEVEL("leaving on sub_recv", H2_EV_H2C_RECV, h2c->conn);
		return (b_data(&h2c->dbuf));
	}

	if (!h2_recv_allowed(h2c)) {
		TRACE_DEVEL("leaving on !recv_allowed", H2_EV_H2C_RECV, h2c->conn);
		return 1;
	}

	buf = h2_get_buf(h2c, &h2c->dbuf);
	if (!buf) {
		h2c->flags |= H2_CF_DEM_DALLOC;
		TRACE_DEVEL("leaving on !alloc", H2_EV_H2C_RECV, h2c->conn);
		return 0;
	}

	if (h2c->flags & H2_CF_RCVD_SHUT) {
		TRACE_DEVEL("leaving on rcvd_shut", H2_EV_H2C_RECV, h2c->conn);
		return 1;
	}

	if (!b_data(buf)) {
		/* try to pre-align the buffer like the
		 * rxbufs will be to optimize memory copies. We'll make
		 * sure that the frame header lands at the end of the
		 * HTX block to alias it upon recv. We cannot use the
		 * head because rcv_buf() will realign the buffer if
		 * it's empty. Thus we cheat and pretend we already
		 * have a few bytes there.
		 */
		max = buf_room_for_htx_data(buf) + 9;
		buf->head = sizeof(struct htx) - 9;
	}
	else
		max = b_room(buf);

	ret = max ? conn->xprt->rcv_buf(conn, conn->xprt_ctx, buf, max, 0) : 0;

	if (max && !ret && h2_recv_allowed(h2c)) {
		TRACE_DATA("failed to receive data, subscribing", H2_EV_H2C_RECV, h2c->conn);
		conn->xprt->subscribe(conn, conn->xprt_ctx, SUB_RETRY_RECV, &h2c->wait_event);
	} else if (ret) {
		TRACE_DATA("received data", H2_EV_H2C_RECV, h2c->conn, 0, 0, (void*)(long)ret);
		h2c->flags &= ~H2_CF_DEM_SHORT_READ;
	}

	if (conn_xprt_read0_pending(h2c->conn)) {
		TRACE_DATA("received read0", H2_EV_H2C_RECV, h2c->conn);
		h2c->flags |= H2_CF_RCVD_SHUT;
	}

	if (!b_data(buf)) {
		h2_release_buf(h2c, &h2c->dbuf);
		TRACE_LEAVE(H2_EV_H2C_RECV, h2c->conn);
		return (conn->flags & CO_FL_ERROR || conn_xprt_read0_pending(conn));
	}

	if (b_data(buf) == buf->size) {
		h2c->flags |= H2_CF_DEM_DFULL;
		TRACE_STATE("demux buffer full", H2_EV_H2C_RECV|H2_EV_H2C_BLK, h2c->conn);
	}

	TRACE_LEAVE(H2_EV_H2C_RECV, h2c->conn);
	return !!ret || (conn->flags & CO_FL_ERROR) || conn_xprt_read0_pending(conn);
}

/* Try to send data if possible.
 * The function returns 1 if data have been sent, otherwise zero.
 */
static int h2_send(struct h2c *h2c)
{
	struct connection *conn = h2c->conn;
	int done;
	int sent = 0;

	TRACE_ENTER(H2_EV_H2C_SEND, h2c->conn);

	if (conn->flags & CO_FL_ERROR) {
		TRACE_DEVEL("leaving on error", H2_EV_H2C_SEND, h2c->conn);
		return 1;
	}

	if (conn->flags & CO_FL_WAIT_XPRT) {
		/* a handshake was requested */
		goto schedule;
	}

	/* This loop is quite simple : it tries to fill as much as it can from
	 * pending streams into the existing buffer until it's reportedly full
	 * or the end of send requests is reached. Then it tries to send this
	 * buffer's contents out, marks it not full if at least one byte could
	 * be sent, and tries again.
	 *
	 * The snd_buf() function normally takes a "flags" argument which may
	 * be made of a combination of CO_SFL_MSG_MORE to indicate that more
	 * data immediately comes and CO_SFL_STREAMER to indicate that the
	 * connection is streaming lots of data (used to increase TLS record
	 * size at the expense of latency). The former can be sent any time
	 * there's a buffer full flag, as it indicates at least one stream
	 * attempted to send and failed so there are pending data. An
	 * alternative would be to set it as long as there's an active stream
	 * but that would be problematic for ACKs until we have an absolute
	 * guarantee that all waiters have at least one byte to send. The
	 * latter should possibly not be set for now.
	 */

	done = 0;
	while (!done) {
		unsigned int flags = 0;
		unsigned int released = 0;
		struct buffer *buf;

		/* fill as much as we can into the current buffer */
		while (((h2c->flags & (H2_CF_MUX_MFULL|H2_CF_MUX_MALLOC)) == 0) && !done)
			done = h2_process_mux(h2c);

		if (h2c->flags & H2_CF_MUX_MALLOC)
			done = 1; // we won't go further without extra buffers

		if ((conn->flags & (CO_FL_SOCK_WR_SH|CO_FL_ERROR)) ||
		    (h2c->flags & H2_CF_GOAWAY_FAILED))
			break;

		if (h2c->flags & (H2_CF_MUX_MFULL | H2_CF_DEM_MBUSY | H2_CF_DEM_MROOM))
			flags |= CO_SFL_MSG_MORE;

		for (buf = br_head(h2c->mbuf); b_size(buf); buf = br_del_head(h2c->mbuf)) {
			if (b_data(buf)) {
				int ret = conn->xprt->snd_buf(conn, conn->xprt_ctx, buf, b_data(buf), flags);
				if (!ret) {
					done = 1;
					break;
				}
				sent = 1;
				TRACE_DATA("sent data", H2_EV_H2C_SEND, h2c->conn, 0, buf, (void*)(long)ret);
				b_del(buf, ret);
				if (b_data(buf)) {
					done = 1;
					break;
				}
			}
			b_free(buf);
			released++;
		}

		if (released)
			offer_buffers(NULL, released);

		/* wrote at least one byte, the buffer is not full anymore */
		if (sent)
			h2c->flags &= ~(H2_CF_MUX_MFULL | H2_CF_DEM_MROOM);
	}

	if (conn->flags & CO_FL_SOCK_WR_SH) {
		/* output closed, nothing to send, clear the buffer to release it */
		b_reset(br_tail(h2c->mbuf));
	}
	/* We're not full anymore, so we can wake any task that are waiting
	 * for us.
	 */
	if (!(h2c->flags & (H2_CF_MUX_MFULL | H2_CF_DEM_MROOM)) && h2c->st0 >= H2_CS_FRAME_H)
		h2_resume_each_sending_h2s(h2c, &h2c->send_list);

	/* We're done, no more to send */
	if (!br_data(h2c->mbuf)) {
		TRACE_DEVEL("leaving with everything sent", H2_EV_H2C_SEND, h2c->conn);
		return sent;
	}
schedule:
	if (!(conn->flags & CO_FL_ERROR) && !(h2c->wait_event.events & SUB_RETRY_SEND)) {
		TRACE_STATE("more data to send, subscribing", H2_EV_H2C_SEND, h2c->conn);
		conn->xprt->subscribe(conn, conn->xprt_ctx, SUB_RETRY_SEND, &h2c->wait_event);
	}

	TRACE_DEVEL("leaving with some data left to send", H2_EV_H2C_SEND, h2c->conn);
	return sent;
}

/* this is the tasklet referenced in h2c->wait_event.tasklet */
struct task *h2_io_cb(struct task *t, void *ctx, unsigned int state)
{
	struct connection *conn;
	struct tasklet *tl = (struct tasklet *)t;
	int conn_in_list;
	struct h2c *h2c = ctx;
	int ret = 0;

	if (state & TASK_F_USR1) {
		/* the tasklet was idling on an idle connection, it might have
		 * been stolen, let's be careful!
		 */
		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		if (t->context == NULL) {
			/* The connection has been taken over by another thread,
			 * we're no longer responsible for it, so just free the
			 * tasklet, and do nothing.
			 */
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			tasklet_free(tl);
			t = NULL;
			goto leave;
		}
		conn = h2c->conn;
		TRACE_ENTER(H2_EV_H2C_WAKE, conn);

		conn_in_list = conn->flags & CO_FL_LIST_MASK;

		/* Remove the connection from the list, to be sure nobody attempts
		 * to use it while we handle the I/O events
		 */
		if (conn_in_list)
			conn_delete_from_tree(&conn->hash_node->node);

		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
	} else {
		/* we're certain the connection was not in an idle list */
		conn = h2c->conn;
		TRACE_ENTER(H2_EV_H2C_WAKE, conn);
		conn_in_list = 0;
	}

	if (!(h2c->wait_event.events & SUB_RETRY_SEND))
		ret = h2_send(h2c);
	if (!(h2c->wait_event.events & SUB_RETRY_RECV))
		ret |= h2_recv(h2c);
	if (ret || b_data(&h2c->dbuf))
		ret = h2_process(h2c);

	/* If we were in an idle list, we want to add it back into it,
	 * unless h2_process() returned -1, which mean it has destroyed
	 * the connection (testing !ret is enough, if h2_process() wasn't
	 * called then ret will be 0 anyway.
	 */
	if (ret < 0)
		t = NULL;

	if (!ret && conn_in_list) {
		struct server *srv = objt_server(conn->target);

		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		if (conn_in_list == CO_FL_SAFE_LIST)
			ebmb_insert(&srv->per_thr[tid].safe_conns, &conn->hash_node->node, sizeof(conn->hash_node->hash));
		else
			ebmb_insert(&srv->per_thr[tid].idle_conns, &conn->hash_node->node, sizeof(conn->hash_node->hash));
		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
	}

leave:
	TRACE_LEAVE(H2_EV_H2C_WAKE);
	return t;
}

/* callback called on any event by the connection handler.
 * It applies changes and returns zero, or < 0 if it wants immediate
 * destruction of the connection (which normally doesn not happen in h2).
 */
static int h2_process(struct h2c *h2c)
{
	struct connection *conn = h2c->conn;

	TRACE_ENTER(H2_EV_H2C_WAKE, conn);

	if (!(h2c->flags & H2_CF_DEM_BLOCK_ANY) &&
	    (b_data(&h2c->dbuf) || (h2c->flags & H2_CF_RCVD_SHUT))) {
		h2_process_demux(h2c);

		if (h2c->st0 >= H2_CS_ERROR || conn->flags & CO_FL_ERROR)
			b_reset(&h2c->dbuf);

		if (!b_full(&h2c->dbuf))
			h2c->flags &= ~H2_CF_DEM_DFULL;
	}
	h2_send(h2c);

	if (unlikely(h2c->proxy->flags & (PR_FL_DISABLED|PR_FL_STOPPED)) && !(h2c->flags & H2_CF_IS_BACK)) {
		/* frontend is stopping, reload likely in progress, let's try
		 * to announce a graceful shutdown if not yet done. We don't
		 * care if it fails, it will be tried again later.
		 */
		TRACE_STATE("proxy stopped, sending GOAWAY", H2_EV_H2C_WAKE|H2_EV_TX_FRAME, conn);
		if (!(h2c->flags & (H2_CF_GOAWAY_SENT|H2_CF_GOAWAY_FAILED))) {
			if (h2c->last_sid < 0)
				h2c->last_sid = (1U << 31) - 1;
			h2c_send_goaway_error(h2c, NULL);
		}
	}

	/*
	 * If we received early data, and the handshake is done, wake
	 * any stream that was waiting for it.
	 */
	if (!(h2c->flags & H2_CF_WAIT_FOR_HS) &&
	    (conn->flags & (CO_FL_EARLY_SSL_HS | CO_FL_WAIT_XPRT | CO_FL_EARLY_DATA)) == CO_FL_EARLY_DATA) {
		struct eb32_node *node;
		struct h2s *h2s;

		h2c->flags |= H2_CF_WAIT_FOR_HS;
		node = eb32_lookup_ge(&h2c->streams_by_id, 1);

		while (node) {
			h2s = container_of(node, struct h2s, by_id);
			if (h2s->cs && h2s->cs->flags & CS_FL_WAIT_FOR_HS)
				h2s_notify_recv(h2s);
			node = eb32_next(node);
		}
	}

	if (conn->flags & CO_FL_ERROR || h2c_read0_pending(h2c) ||
	    h2c->st0 == H2_CS_ERROR2 || h2c->flags & H2_CF_GOAWAY_FAILED ||
	    (eb_is_empty(&h2c->streams_by_id) && h2c->last_sid >= 0 &&
	     h2c->max_id >= h2c->last_sid)) {
		h2_wake_some_streams(h2c, 0);

		if (eb_is_empty(&h2c->streams_by_id)) {
			/* no more stream, kill the connection now */
			h2_release(h2c);
			TRACE_DEVEL("leaving after releasing the connection", H2_EV_H2C_WAKE);
			return -1;
		}

		/* connections in error must be removed from the idle lists */
		if (conn->flags & CO_FL_LIST_MASK) {
			HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			conn_delete_from_tree(&conn->hash_node->node);
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		}
	}
	else if (h2c->st0 == H2_CS_ERROR) {
		/* connections in error must be removed from the idle lists */
		if (conn->flags & CO_FL_LIST_MASK) {
			HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			conn_delete_from_tree(&conn->hash_node->node);
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		}
	}

	if (!b_data(&h2c->dbuf))
		h2_release_buf(h2c, &h2c->dbuf);

	if ((conn->flags & CO_FL_SOCK_WR_SH) ||
	    h2c->st0 == H2_CS_ERROR2 || (h2c->flags & H2_CF_GOAWAY_FAILED) ||
	    (h2c->st0 != H2_CS_ERROR &&
	     !br_data(h2c->mbuf) &&
	     (h2c->mws <= 0 || LIST_ISEMPTY(&h2c->fctl_list)) &&
	     ((h2c->flags & H2_CF_MUX_BLOCK_ANY) || LIST_ISEMPTY(&h2c->send_list))))
		h2_release_mbuf(h2c);

	if (h2c->task) {
		if (h2c_may_expire(h2c))
			h2c->task->expire = tick_add(now_ms, h2c->last_sid < 0 ? h2c->timeout : h2c->shut_timeout);
		else
			h2c->task->expire = TICK_ETERNITY;
		task_queue(h2c->task);
	}

	h2_send(h2c);
	TRACE_LEAVE(H2_EV_H2C_WAKE, conn);
	return 0;
}

/* wake-up function called by the connection layer (mux_ops.wake) */
static int h2_wake(struct connection *conn)
{
	struct h2c *h2c = conn->ctx;
	int ret;

	TRACE_ENTER(H2_EV_H2C_WAKE, conn);
	ret = h2_process(h2c);
	if (ret >= 0)
		h2_wake_some_streams(h2c, 0);
	TRACE_LEAVE(H2_EV_H2C_WAKE);
	return ret;
}

/* Connection timeout management. The principle is that if there's no receipt
 * nor sending for a certain amount of time, the connection is closed. If the
 * MUX buffer still has lying data or is not allocatable, the connection is
 * immediately killed. If it's allocatable and empty, we attempt to send a
 * GOAWAY frame.
 */
struct task *h2_timeout_task(struct task *t, void *context, unsigned int state)
{
	struct h2c *h2c = context;
	int expired = tick_is_expired(t->expire, now_ms);

	TRACE_ENTER(H2_EV_H2C_WAKE, h2c ? h2c->conn : NULL);

	if (h2c) {
		 /* Make sure nobody stole the connection from us */
		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);

		/* Somebody already stole the connection from us, so we should not
		 * free it, we just have to free the task.
		 */
		if (!t->context) {
			h2c = NULL;
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			goto do_leave;
		}


		if (!expired) {
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			TRACE_DEVEL("leaving (not expired)", H2_EV_H2C_WAKE, h2c->conn);
			return t;
		}

		if (!h2c_may_expire(h2c)) {
			/* we do still have streams but all of them are idle, waiting
			 * for the data layer, so we must not enforce the timeout here.
			 */
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			t->expire = TICK_ETERNITY;
			return t;
		}

		/* We're about to destroy the connection, so make sure nobody attempts
		 * to steal it from us.
		 */
		if (h2c->conn->flags & CO_FL_LIST_MASK)
			conn_delete_from_tree(&h2c->conn->hash_node->node);

		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
	}

do_leave:
	task_destroy(t);

	if (!h2c) {
		/* resources were already deleted */
		TRACE_DEVEL("leaving (not more h2c)", H2_EV_H2C_WAKE);
		return NULL;
	}

	h2c->task = NULL;
	h2c_error(h2c, H2_ERR_NO_ERROR);
	h2_wake_some_streams(h2c, 0);

	if (br_data(h2c->mbuf)) {
		/* don't even try to send a GOAWAY, the buffer is stuck */
		h2c->flags |= H2_CF_GOAWAY_FAILED;
	}

	/* try to send but no need to insist */
	h2c->last_sid = h2c->max_id;
	if (h2c_send_goaway_error(h2c, NULL) <= 0)
		h2c->flags |= H2_CF_GOAWAY_FAILED;

	if (br_data(h2c->mbuf) && !(h2c->flags & H2_CF_GOAWAY_FAILED) && conn_xprt_ready(h2c->conn)) {
		unsigned int released = 0;
		struct buffer *buf;

		for (buf = br_head(h2c->mbuf); b_size(buf); buf = br_del_head(h2c->mbuf)) {
			if (b_data(buf)) {
				int ret = h2c->conn->xprt->snd_buf(h2c->conn, h2c->conn->xprt_ctx, buf, b_data(buf), 0);
				if (!ret)
					break;
				b_del(buf, ret);
				if (b_data(buf))
					break;
				b_free(buf);
				released++;
			}
		}

		if (released)
			offer_buffers(NULL, released);
	}

	/* in any case this connection must not be considered idle anymore */
	if (h2c->conn->flags & CO_FL_LIST_MASK) {
		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		conn_delete_from_tree(&h2c->conn->hash_node->node);
		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
	}

	/* either we can release everything now or it will be done later once
	 * the last stream closes.
	 */
	if (eb_is_empty(&h2c->streams_by_id))
		h2_release(h2c);

	TRACE_LEAVE(H2_EV_H2C_WAKE);
	return NULL;
}


/*******************************************/
/* functions below are used by the streams */
/*******************************************/

/*
 * Attach a new stream to a connection
 * (Used for outgoing connections)
 */
static struct conn_stream *h2_attach(struct connection *conn, struct session *sess)
{
	struct conn_stream *cs;
	struct h2s *h2s;
	struct h2c *h2c = conn->ctx;

	TRACE_ENTER(H2_EV_H2S_NEW, conn);
	cs = cs_new(conn, conn->target);
	if (!cs) {
		TRACE_DEVEL("leaving on CS allocation failure", H2_EV_H2S_NEW|H2_EV_H2S_ERR, conn);
		return NULL;
	}
	h2s = h2c_bck_stream_new(h2c, cs, sess);
	if (!h2s) {
		TRACE_DEVEL("leaving on stream creation failure", H2_EV_H2S_NEW|H2_EV_H2S_ERR, conn);
		cs_free(cs);
		return NULL;
	}

	/* the connection is not idle anymore, let's mark this */
	HA_ATOMIC_AND(&h2c->wait_event.tasklet->state, ~TASK_F_USR1);
	xprt_set_used(h2c->conn, h2c->conn->xprt, h2c->conn->xprt_ctx);

	TRACE_LEAVE(H2_EV_H2S_NEW, conn, h2s);
	return cs;
}

/* Retrieves the first valid conn_stream from this connection, or returns NULL.
 * We have to scan because we may have some orphan streams. It might be
 * beneficial to scan backwards from the end to reduce the likeliness to find
 * orphans.
 */
static const struct conn_stream *h2_get_first_cs(const struct connection *conn)
{
	struct h2c *h2c = conn->ctx;
	struct h2s *h2s;
	struct eb32_node *node;

	node = eb32_first(&h2c->streams_by_id);
	while (node) {
		h2s = container_of(node, struct h2s, by_id);
		if (h2s->cs)
			return h2s->cs;
		node = eb32_next(node);
	}
	return NULL;
}

static int h2_ctl(struct connection *conn, enum mux_ctl_type mux_ctl, void *output)
{
	int ret = 0;
	struct h2c *h2c = conn->ctx;

	switch (mux_ctl) {
	case MUX_STATUS:
		/* Only consider the mux to be ready if we're done with
		 * the preface and settings, and we had no error.
		 */
		if (h2c->st0 >= H2_CS_FRAME_H && h2c->st0 < H2_CS_ERROR)
			ret |= MUX_STATUS_READY;
		return ret;
	case MUX_EXIT_STATUS:
		return MUX_ES_UNKNOWN;
	default:
		return -1;
	}
}

/*
 * Destroy the mux and the associated connection, if it is no longer used
 */
static void h2_destroy(void *ctx)
{
	struct h2c *h2c = ctx;

	TRACE_ENTER(H2_EV_H2C_END, h2c->conn);
	if (eb_is_empty(&h2c->streams_by_id) || !h2c->conn || h2c->conn->ctx != h2c)
		h2_release(h2c);
	TRACE_LEAVE(H2_EV_H2C_END);
}

/*
 * Detach the stream from the connection and possibly release the connection.
 */
static void h2_detach(struct conn_stream *cs)
{
	struct h2s *h2s = cs->ctx;
	struct h2c *h2c;
	struct session *sess;

	TRACE_ENTER(H2_EV_STRM_END, h2s ? h2s->h2c->conn : NULL, h2s);

	cs->ctx = NULL;
	if (!h2s) {
		TRACE_LEAVE(H2_EV_STRM_END);
		return;
	}

	/* there's no txbuf so we're certain not to be able to send anything */
	h2s->flags &= ~H2_SF_NOTIFIED;

	sess = h2s->sess;
	h2c = h2s->h2c;
	h2s->cs = NULL;
	h2c->nb_cs--;
	if ((h2c->flags & (H2_CF_IS_BACK|H2_CF_DEM_TOOMANY)) == H2_CF_DEM_TOOMANY &&
	    !h2_frt_has_too_many_cs(h2c)) {
		/* frontend connection was blocking new streams creation */
		h2c->flags &= ~H2_CF_DEM_TOOMANY;
		h2c_restart_reading(h2c, 1);
	}

	/* this stream may be blocked waiting for some data to leave (possibly
	 * an ES or RST frame), so orphan it in this case.
	 */
	if (!(cs->conn->flags & CO_FL_ERROR) &&
	    (h2c->st0 < H2_CS_ERROR) &&
	    (h2s->flags & (H2_SF_BLK_MBUSY | H2_SF_BLK_MROOM | H2_SF_BLK_MFCTL)) &&
	    ((h2s->flags & (H2_SF_WANT_SHUTR | H2_SF_WANT_SHUTW)) || h2s->subs)) {
		TRACE_DEVEL("leaving on stream blocked", H2_EV_STRM_END|H2_EV_H2S_BLK, h2c->conn, h2s);
		return;
	}

	if ((h2c->flags & H2_CF_DEM_BLOCK_ANY && h2s->id == h2c->dsi) ||
	    (h2c->flags & H2_CF_MUX_BLOCK_ANY && h2s->id == h2c->msi)) {
		/* unblock the connection if it was blocked on this
		 * stream.
		 */
		h2c->flags &= ~H2_CF_DEM_BLOCK_ANY;
		h2c->flags &= ~H2_CF_MUX_BLOCK_ANY;
		h2c_restart_reading(h2c, 1);
	}

	h2s_destroy(h2s);

	if (h2c->flags & H2_CF_IS_BACK) {
		if (!(h2c->conn->flags &
		    (CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH))) {
			if (h2c->conn->flags & CO_FL_PRIVATE) {
				/* Add the connection in the session server list, if not already done */
				if (!session_add_conn(sess, h2c->conn, h2c->conn->target)) {
					h2c->conn->owner = NULL;
					if (eb_is_empty(&h2c->streams_by_id)) {
						h2c->conn->mux->destroy(h2c);
						TRACE_DEVEL("leaving on error after killing outgoing connection", H2_EV_STRM_END|H2_EV_H2C_ERR);
						return;
					}
				}
				if (eb_is_empty(&h2c->streams_by_id)) {
					if (session_check_idle_conn(h2c->conn->owner, h2c->conn) != 0) {
						/* At this point either the connection is destroyed, or it's been added to the server idle list, just stop */
						TRACE_DEVEL("leaving without reusable idle connection", H2_EV_STRM_END);
						return;
					}
				}
			}
			else {
				if (eb_is_empty(&h2c->streams_by_id)) {
					/* If the connection is owned by the session, first remove it
					 * from its list
					 */
					if (h2c->conn->owner) {
						session_unown_conn(h2c->conn->owner, h2c->conn);
						h2c->conn->owner = NULL;
					}

					/* mark that the tasklet may lose its context to another thread and
					 * that the handler needs to check it under the idle conns lock.
					 */
					HA_ATOMIC_OR(&h2c->wait_event.tasklet->state, TASK_F_USR1);
					xprt_set_idle(h2c->conn, h2c->conn->xprt, h2c->conn->xprt_ctx);

					if (!srv_add_to_idle_list(objt_server(h2c->conn->target), h2c->conn, 1)) {
						/* The server doesn't want it, let's kill the connection right away */
						h2c->conn->mux->destroy(h2c);
						TRACE_DEVEL("leaving on error after killing outgoing connection", H2_EV_STRM_END|H2_EV_H2C_ERR);
						return;
					}
					/* At this point, the connection has been added to the
					 * server idle list, so another thread may already have
					 * hijacked it, so we can't do anything with it.
					 */
					TRACE_DEVEL("reusable idle connection", H2_EV_STRM_END);
					return;

				}
				else if (!h2c->conn->hash_node->node.node.leaf_p &&
					 h2_avail_streams(h2c->conn) > 0 && objt_server(h2c->conn->target) &&
					 !LIST_INLIST(&h2c->conn->session_list)) {
					ebmb_insert(&__objt_server(h2c->conn->target)->per_thr[tid].avail_conns,
					            &h2c->conn->hash_node->node,
					            sizeof(h2c->conn->hash_node->hash));
				}
			}
		}
	}

	/* We don't want to close right now unless we're removing the
	 * last stream, and either the connection is in error, or it
	 * reached the ID already specified in a GOAWAY frame received
	 * or sent (as seen by last_sid >= 0).
	 */
	if (h2c_is_dead(h2c)) {
		/* no more stream will come, kill it now */
		TRACE_DEVEL("leaving and killing dead connection", H2_EV_STRM_END, h2c->conn);
		h2_release(h2c);
	}
	else if (h2c->task) {
		if (h2c_may_expire(h2c))
			h2c->task->expire = tick_add(now_ms, h2c->last_sid < 0 ? h2c->timeout : h2c->shut_timeout);
		else
			h2c->task->expire = TICK_ETERNITY;
		task_queue(h2c->task);
		TRACE_DEVEL("leaving, refreshing connection's timeout", H2_EV_STRM_END, h2c->conn);
	}
	else
		TRACE_DEVEL("leaving", H2_EV_STRM_END, h2c->conn);
}

/* Performs a synchronous or asynchronous shutr(). */
static void h2_do_shutr(struct h2s *h2s)
{
	struct h2c *h2c = h2s->h2c;

	if (h2s->st == H2_SS_CLOSED)
		goto done;

	TRACE_ENTER(H2_EV_STRM_SHUT, h2c->conn, h2s);

	/* a connstream may require us to immediately kill the whole connection
	 * for example because of a "tcp-request content reject" rule that is
	 * normally used to limit abuse. In this case we schedule a goaway to
	 * close the connection.
	 */
	if ((h2s->flags & H2_SF_KILL_CONN) &&
	    !(h2c->flags & (H2_CF_GOAWAY_SENT|H2_CF_GOAWAY_FAILED))) {
		TRACE_STATE("stream wants to kill the connection", H2_EV_STRM_SHUT, h2c->conn, h2s);
		h2c_error(h2c, H2_ERR_ENHANCE_YOUR_CALM);
		h2s_error(h2s, H2_ERR_ENHANCE_YOUR_CALM);
	}
	else if (!(h2s->flags & H2_SF_HEADERS_SENT)) {
		/* Nothing was never sent for this stream, so reset with
		 * REFUSED_STREAM error to let the client retry the
		 * request.
		 */
		TRACE_STATE("no headers sent yet, trying a retryable abort", H2_EV_STRM_SHUT, h2c->conn, h2s);
		h2s_error(h2s, H2_ERR_REFUSED_STREAM);
	}
	else {
		/* a final response was already provided, we don't want this
		 * stream anymore. This may happen when the server responds
		 * before the end of an upload and closes quickly (redirect,
		 * deny, ...)
		 */
		h2s_error(h2s, H2_ERR_CANCEL);
	}

	if (!(h2s->flags & H2_SF_RST_SENT) &&
	    h2s_send_rst_stream(h2c, h2s) <= 0)
		goto add_to_list;

	if (!(h2c->wait_event.events & SUB_RETRY_SEND))
		tasklet_wakeup(h2c->wait_event.tasklet);
	h2s_close(h2s);
 done:
	h2s->flags &= ~H2_SF_WANT_SHUTR;
	TRACE_LEAVE(H2_EV_STRM_SHUT, h2c->conn, h2s);
	return;
add_to_list:
	/* Let the handler know we want to shutr, and add ourselves to the
	 * most relevant list if not yet done. h2_deferred_shut() will be
	 * automatically called via the shut_tl tasklet when there's room
	 * again.
	 */
	h2s->flags |= H2_SF_WANT_SHUTR;
	if (!LIST_INLIST(&h2s->list)) {
		if (h2s->flags & H2_SF_BLK_MFCTL)
			LIST_APPEND(&h2c->fctl_list, &h2s->list);
		else if (h2s->flags & (H2_SF_BLK_MBUSY|H2_SF_BLK_MROOM))
			LIST_APPEND(&h2c->send_list, &h2s->list);
	}
	TRACE_LEAVE(H2_EV_STRM_SHUT, h2c->conn, h2s);
	return;
}

/* Performs a synchronous or asynchronous shutw(). */
static void h2_do_shutw(struct h2s *h2s)
{
	struct h2c *h2c = h2s->h2c;

	if (h2s->st == H2_SS_HLOC || h2s->st == H2_SS_CLOSED)
		goto done;

	TRACE_ENTER(H2_EV_STRM_SHUT, h2c->conn, h2s);

	if (h2s->st != H2_SS_ERROR && (h2s->flags & H2_SF_HEADERS_SENT)) {
		/* we can cleanly close using an empty data frame only after headers */

		if (!(h2s->flags & (H2_SF_ES_SENT|H2_SF_RST_SENT)) &&
		    h2_send_empty_data_es(h2s) <= 0)
			goto add_to_list;

		if (h2s->st == H2_SS_HREM)
			h2s_close(h2s);
		else
			h2s->st = H2_SS_HLOC;
	} else {
		/* a connstream may require us to immediately kill the whole connection
		 * for example because of a "tcp-request content reject" rule that is
		 * normally used to limit abuse. In this case we schedule a goaway to
		 * close the connection.
		 */
		if ((h2s->flags & H2_SF_KILL_CONN) &&
		    !(h2c->flags & (H2_CF_GOAWAY_SENT|H2_CF_GOAWAY_FAILED))) {
			TRACE_STATE("stream wants to kill the connection", H2_EV_STRM_SHUT, h2c->conn, h2s);
			h2c_error(h2c, H2_ERR_ENHANCE_YOUR_CALM);
			h2s_error(h2s, H2_ERR_ENHANCE_YOUR_CALM);
		}
		else {
			/* Nothing was never sent for this stream, so reset with
			 * REFUSED_STREAM error to let the client retry the
			 * request.
			 */
			TRACE_STATE("no headers sent yet, trying a retryable abort", H2_EV_STRM_SHUT, h2c->conn, h2s);
			h2s_error(h2s, H2_ERR_REFUSED_STREAM);
		}

		if (!(h2s->flags & H2_SF_RST_SENT) &&
		    h2s_send_rst_stream(h2c, h2s) <= 0)
			goto add_to_list;

		h2s_close(h2s);
	}

	if (!(h2c->wait_event.events & SUB_RETRY_SEND))
		tasklet_wakeup(h2c->wait_event.tasklet);

	TRACE_LEAVE(H2_EV_STRM_SHUT, h2c->conn, h2s);

 done:
	h2s->flags &= ~H2_SF_WANT_SHUTW;
	return;

 add_to_list:
	/* Let the handler know we want to shutw, and add ourselves to the
	 * most relevant list if not yet done. h2_deferred_shut() will be
	 * automatically called via the shut_tl tasklet when there's room
	 * again.
	 */
	h2s->flags |= H2_SF_WANT_SHUTW;
	if (!LIST_INLIST(&h2s->list)) {
		if (h2s->flags & H2_SF_BLK_MFCTL)
			LIST_APPEND(&h2c->fctl_list, &h2s->list);
		else if (h2s->flags & (H2_SF_BLK_MBUSY|H2_SF_BLK_MROOM))
			LIST_APPEND(&h2c->send_list, &h2s->list);
	}
	TRACE_LEAVE(H2_EV_STRM_SHUT, h2c->conn, h2s);
	return;
}

/* This is the tasklet referenced in h2s->shut_tl, it is used for
 * deferred shutdowns when the h2_detach() was done but the mux buffer was full
 * and prevented the last frame from being emitted.
 */
struct task *h2_deferred_shut(struct task *t, void *ctx, unsigned int state)
{
	struct h2s *h2s = ctx;
	struct h2c *h2c = h2s->h2c;

	TRACE_ENTER(H2_EV_STRM_SHUT, h2c->conn, h2s);

	if (h2s->flags & H2_SF_NOTIFIED) {
		/* some data processing remains to be done first */
		goto end;
	}

	if (h2s->flags & H2_SF_WANT_SHUTW)
		h2_do_shutw(h2s);

	if (h2s->flags & H2_SF_WANT_SHUTR)
		h2_do_shutr(h2s);

	if (!(h2s->flags & (H2_SF_WANT_SHUTR|H2_SF_WANT_SHUTW))) {
		/* We're done trying to send, remove ourself from the send_list */
		LIST_DEL_INIT(&h2s->list);

		if (!h2s->cs) {
			h2s_destroy(h2s);
			if (h2c_is_dead(h2c)) {
				h2_release(h2c);
				t = NULL;
			}
		}
	}
 end:
	TRACE_LEAVE(H2_EV_STRM_SHUT);
	return t;
}

/* shutr() called by the conn_stream (mux_ops.shutr) */
static void h2_shutr(struct conn_stream *cs, enum cs_shr_mode mode)
{
	struct h2s *h2s = cs->ctx;

	TRACE_ENTER(H2_EV_STRM_SHUT, h2s->h2c->conn, h2s);
	if (cs->flags & CS_FL_KILL_CONN)
		h2s->flags |= H2_SF_KILL_CONN;

	if (mode)
		h2_do_shutr(h2s);

	TRACE_LEAVE(H2_EV_STRM_SHUT, h2s->h2c->conn, h2s);
}

/* shutw() called by the conn_stream (mux_ops.shutw) */
static void h2_shutw(struct conn_stream *cs, enum cs_shw_mode mode)
{
	struct h2s *h2s = cs->ctx;

	TRACE_ENTER(H2_EV_STRM_SHUT, h2s->h2c->conn, h2s);
	if (cs->flags & CS_FL_KILL_CONN)
		h2s->flags |= H2_SF_KILL_CONN;

	h2_do_shutw(h2s);
	TRACE_LEAVE(H2_EV_STRM_SHUT, h2s->h2c->conn, h2s);
}

/* Decode the payload of a HEADERS frame and produce the HTX request or response
 * depending on the connection's side. Returns a positive value on success, a
 * negative value on failure, or 0 if it couldn't proceed. May report connection
 * errors in h2c->errcode if the frame is non-decodable and the connection
 * unrecoverable. In absence of connection error when a failure is reported, the
 * caller must assume a stream error.
 *
 * The function may fold CONTINUATION frames into the initial HEADERS frame
 * by removing padding and next frame header, then moving the CONTINUATION
 * frame's payload and adjusting h2c->dfl to match the new aggregated frame,
 * leaving a hole between the main frame and the beginning of the next one.
 * The possibly remaining incomplete or next frame at the end may be moved
 * if the aggregated frame is not deleted, in order to fill the hole. Wrapped
 * HEADERS frames are unwrapped into a temporary buffer before decoding.
 *
 * A buffer at the beginning of processing may look like this :
 *
 *  ,---.---------.-----.--------------.--------------.------.---.
 *  |///| HEADERS | PAD | CONTINUATION | CONTINUATION | DATA |///|
 *  `---^---------^-----^--------------^--------------^------^---'
 *  |   |         <----->                                    |   |
 * area |           dpl                                      |  wrap
 *      |<-------------->                                    |
 *      |       dfl                                          |
 *      |<-------------------------------------------------->|
 *    head                    data
 *
 * Padding is automatically overwritten when folding, participating to the
 * hole size after dfl :
 *
 *  ,---.------------------------.-----.--------------.------.---.
 *  |///| HEADERS : CONTINUATION |/////| CONTINUATION | DATA |///|
 *  `---^------------------------^-----^--------------^------^---'
 *  |   |                        <----->                     |   |
 * area |                          hole                      |  wrap
 *      |<----------------------->                           |
 *      |           dfl                                      |
 *      |<-------------------------------------------------->|
 *    head                    data
 *
 * Please note that the HEADERS frame is always deprived from its PADLEN byte
 * however it may start with the 5 stream-dep+weight bytes in case of PRIORITY
 * bit.
 *
 * The <flags> field must point to either the stream's flags or to a copy of it
 * so that the function can update the following flags :
 *   - H2_SF_DATA_CLEN when content-length is seen
 *   - H2_SF_HEADERS_RCVD once the frame is successfully decoded
 *
 * The H2_SF_HEADERS_RCVD flag is also looked at in the <flags> field prior to
 * decoding, in order to detect if we're dealing with a headers or a trailers
 * block (the trailers block appears after H2_SF_HEADERS_RCVD was seen).
 */
static int h2c_decode_headers(struct h2c *h2c, struct buffer *rxbuf, uint32_t *flags, unsigned long long *body_len, char *upgrade_protocol)
{
	const uint8_t *hdrs = (uint8_t *)b_head(&h2c->dbuf);
	struct buffer *tmp = get_trash_chunk();
	struct http_hdr list[global.tune.max_http_hdr * 2];
	struct buffer *copy = NULL;
	unsigned int msgf;
	struct htx *htx = NULL;
	int flen; // header frame len
	int hole = 0;
	int ret = 0;
	int outlen;
	int wrap;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn);

next_frame:
	if (b_data(&h2c->dbuf) - hole < h2c->dfl)
		goto leave; // incomplete input frame

	/* No END_HEADERS means there's one or more CONTINUATION frames. In
	 * this case, we'll try to paste it immediately after the initial
	 * HEADERS frame payload and kill any possible padding. The initial
	 * frame's length will be increased to represent the concatenation
	 * of the two frames. The next frame is read from position <tlen>
	 * and written at position <flen> (minus padding if some is present).
	 */
	if (unlikely(!(h2c->dff & H2_F_HEADERS_END_HEADERS))) {
		struct h2_fh hdr;
		int clen; // CONTINUATION frame's payload length

		TRACE_STATE("EH missing, expecting continuation frame", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_HDR, h2c->conn);
		if (!h2_peek_frame_hdr(&h2c->dbuf, h2c->dfl + hole, &hdr)) {
			/* no more data, the buffer may be full, either due to
			 * too large a frame or because of too large a hole that
			 * we're going to compact at the end.
			 */
			goto leave;
		}

		if (hdr.ft != H2_FT_CONTINUATION) {
			/* RFC7540#6.10: frame of unexpected type */
			TRACE_STATE("not continuation!", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_HDR|H2_EV_RX_CONT|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
			goto fail;
		}

		if (hdr.sid != h2c->dsi) {
			/* RFC7540#6.10: frame of different stream */
			TRACE_STATE("different stream ID!", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_HDR|H2_EV_RX_CONT|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
			goto fail;
		}

		if ((unsigned)hdr.len > (unsigned)global.tune.bufsize) {
			/* RFC7540#4.2: invalid frame length */
			TRACE_STATE("too large frame!", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_HDR|H2_EV_RX_CONT|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
			h2c_error(h2c, H2_ERR_FRAME_SIZE_ERROR);
			goto fail;
		}

		/* detect when we must stop aggragating frames */
		h2c->dff |= hdr.ff & H2_F_HEADERS_END_HEADERS;

		/* Take as much as we can of the CONTINUATION frame's payload */
		clen = b_data(&h2c->dbuf) - (h2c->dfl + hole + 9);
		if (clen > hdr.len)
			clen = hdr.len;

		/* Move the frame's payload over the padding, hole and frame
		 * header. At least one of hole or dpl is null (see diagrams
		 * above). The hole moves after the new aggragated frame.
		 */
		b_move(&h2c->dbuf, b_peek_ofs(&h2c->dbuf, h2c->dfl + hole + 9), clen, -(h2c->dpl + hole + 9));
		h2c->dfl += hdr.len - h2c->dpl;
		hole     += h2c->dpl + 9;
		h2c->dpl  = 0;
		TRACE_STATE("waiting for next continuation frame", H2_EV_RX_FRAME|H2_EV_RX_FHDR|H2_EV_RX_CONT|H2_EV_RX_HDR, h2c->conn);
		goto next_frame;
	}

	flen = h2c->dfl - h2c->dpl;

	/* if the input buffer wraps, take a temporary copy of it (rare) */
	wrap = b_wrap(&h2c->dbuf) - b_head(&h2c->dbuf);
	if (wrap < h2c->dfl) {
		copy = alloc_trash_chunk();
		if (!copy) {
			TRACE_DEVEL("failed to allocate temporary buffer", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2C_ERR, h2c->conn);
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			goto fail;
		}
		memcpy(copy->area, b_head(&h2c->dbuf), wrap);
		memcpy(copy->area + wrap, b_orig(&h2c->dbuf), h2c->dfl - wrap);
		hdrs = (uint8_t *) copy->area;
	}

	/* Skip StreamDep and weight for now (we don't support PRIORITY) */
	if (h2c->dff & H2_F_HEADERS_PRIORITY) {
		if (read_n32(hdrs) == h2c->dsi) {
			/* RFC7540#5.3.1 : stream dep may not depend on itself */
			TRACE_STATE("invalid stream dependency!", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
			goto fail;
		}

		if (flen < 5) {
			TRACE_STATE("frame too short for priority!", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
			h2c_error(h2c, H2_ERR_FRAME_SIZE_ERROR);
			goto fail;
		}

		hdrs += 5; // stream dep = 4, weight = 1
		flen -= 5;
	}

	if (!h2_get_buf(h2c, rxbuf)) {
		TRACE_STATE("waiting for h2c rxbuf allocation", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2C_BLK, h2c->conn);
		h2c->flags |= H2_CF_DEM_SALLOC;
		goto leave;
	}

	/* we can't retry a failed decompression operation so we must be very
	 * careful not to take any risks. In practice the output buffer is
	 * always empty except maybe for trailers, in which case we simply have
	 * to wait for the upper layer to finish consuming what is available.
	 */
	htx = htx_from_buf(rxbuf);
	if (!htx_is_empty(htx)) {
		TRACE_STATE("waiting for room in h2c rxbuf", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2C_BLK, h2c->conn);
		h2c->flags |= H2_CF_DEM_SFULL;
		goto leave;
	}

	/* past this point we cannot roll back in case of error */
	outlen = hpack_decode_frame(h2c->ddht, hdrs, flen, list,
	                            sizeof(list)/sizeof(list[0]), tmp);
	if (outlen < 0) {
		TRACE_STATE("failed to decompress HPACK", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
		h2c_error(h2c, H2_ERR_COMPRESSION_ERROR);
		goto fail;
	}

	/* The PACK decompressor was updated, let's update the input buffer and
	 * the parser's state to commit these changes and allow us to later
	 * fail solely on the stream if needed.
	 */
	b_del(&h2c->dbuf, h2c->dfl + hole);
	h2c->dfl = hole = 0;
	h2c->st0 = H2_CS_FRAME_H;

	/* OK now we have our header list in <list> */
	msgf = (h2c->dff & H2_F_HEADERS_END_STREAM) ? 0 : H2_MSGF_BODY;
	msgf |= (*flags & H2_SF_BODY_TUNNEL) ? H2_MSGF_BODY_TUNNEL: 0;
	/* If an Extended CONNECT has been sent on this stream, set message flag
	 * to convert 200 response to 101 htx response */
	msgf |= (*flags & H2_SF_EXT_CONNECT_SENT) ? H2_MSGF_EXT_CONNECT: 0;

	if (*flags & H2_SF_HEADERS_RCVD)
		goto trailers;

	/* This is the first HEADERS frame so it's a headers block */
	if (h2c->flags & H2_CF_IS_BACK)
		outlen = h2_make_htx_response(list, htx, &msgf, body_len, upgrade_protocol);
	else
		outlen = h2_make_htx_request(list, htx, &msgf, body_len);

	if (outlen < 0 || htx_free_space(htx) < global.tune.maxrewrite) {
		/* too large headers? this is a stream error only */
		TRACE_STATE("message headers too large", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2S_ERR|H2_EV_PROTO_ERR, h2c->conn);
		htx->flags |= HTX_FL_PARSING_ERROR;
		goto fail;
	}

	if (msgf & H2_MSGF_BODY) {
		/* a payload is present */
		if (msgf & H2_MSGF_BODY_CL) {
			*flags |= H2_SF_DATA_CLEN;
			htx->extra = *body_len;
		}
	}
	if (msgf & H2_MSGF_BODYLESS_RSP)
		*flags |= H2_SF_BODYLESS_RESP;

	if (msgf & H2_MSGF_BODY_TUNNEL)
		*flags |= H2_SF_BODY_TUNNEL;
	else {
		/* Abort the tunnel attempt, if any */
		if (*flags & H2_SF_BODY_TUNNEL)
			*flags |= H2_SF_TUNNEL_ABRT;
		*flags &= ~H2_SF_BODY_TUNNEL;
	}

 done:
	/* indicate that a HEADERS frame was received for this stream, except
	 * for 1xx responses. For 1xx responses, another HEADERS frame is
	 * expected.
	 */
	if (!(msgf & H2_MSGF_RSP_1XX))
		*flags |= H2_SF_HEADERS_RCVD;

	if (h2c->dff & H2_F_HEADERS_END_STREAM) {
		/* no more data are expected for this message */
		htx->flags |= HTX_FL_EOM;
	}

	if (msgf & H2_MSGF_EXT_CONNECT)
		*flags |= H2_SF_EXT_CONNECT_RCVD;

	/* success */
	ret = 1;

 leave:
	/* If there is a hole left and it's not at the end, we are forced to
	 * move the remaining data over it.
	 */
	if (hole) {
		if (b_data(&h2c->dbuf) > h2c->dfl + hole)
			b_move(&h2c->dbuf, b_peek_ofs(&h2c->dbuf, h2c->dfl + hole),
			       b_data(&h2c->dbuf) - (h2c->dfl + hole), -hole);
		b_sub(&h2c->dbuf, hole);
	}

	if (b_full(&h2c->dbuf) && h2c->dfl) {
		/* too large frames */
		h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
		ret = -1;
	}

	if (htx)
		htx_to_buf(htx, rxbuf);
	free_trash_chunk(copy);
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_HDR, h2c->conn);
	return ret;

 fail:
	ret = -1;
	goto leave;

 trailers:
	/* This is the last HEADERS frame hence a trailer */
	if (!(h2c->dff & H2_F_HEADERS_END_STREAM)) {
		/* It's a trailer but it's missing ES flag */
		TRACE_STATE("missing EH on trailers frame", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2C_ERR|H2_EV_PROTO_ERR, h2c->conn);
		h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
		HA_ATOMIC_INC(&h2c->px_counters->conn_proto_err);
		goto fail;
	}

	/* Trailers terminate a DATA sequence */
	if (h2_make_htx_trailers(list, htx) <= 0) {
		TRACE_STATE("failed to append HTX trailers into rxbuf", H2_EV_RX_FRAME|H2_EV_RX_HDR|H2_EV_H2S_ERR, h2c->conn);
		goto fail;
	}
	goto done;
}

/* Transfer the payload of a DATA frame to the HTTP/1 side. The HTTP/2 frame
 * parser state is automatically updated. Returns > 0 if it could completely
 * send the current frame, 0 if it couldn't complete, in which case
 * CS_FL_RCV_MORE must be checked to know if some data remain pending (an empty
 * DATA frame can return 0 as a valid result). Stream errors are reported in
 * h2s->errcode and connection errors in h2c->errcode. The caller must already
 * have checked the frame header and ensured that the frame was complete or the
 * buffer full. It changes the frame state to FRAME_A once done.
 */
static int h2_frt_transfer_data(struct h2s *h2s)
{
	struct h2c *h2c = h2s->h2c;
	int block;
	unsigned int flen = 0;
	struct htx *htx = NULL;
	struct buffer *csbuf;
	unsigned int sent;

	TRACE_ENTER(H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);

	h2c->flags &= ~H2_CF_DEM_SFULL;

	csbuf = h2_get_buf(h2c, &h2s->rxbuf);
	if (!csbuf) {
		h2c->flags |= H2_CF_DEM_SALLOC;
		TRACE_STATE("waiting for an h2s rxbuf", H2_EV_RX_FRAME|H2_EV_RX_DATA|H2_EV_H2S_BLK, h2c->conn, h2s);
		goto fail;
	}
	htx = htx_from_buf(csbuf);

try_again:
	flen = h2c->dfl - h2c->dpl;
	if (!flen)
		goto end_transfer;

	if (flen > b_data(&h2c->dbuf)) {
		flen = b_data(&h2c->dbuf);
		if (!flen)
			goto fail;
	}

	block = htx_free_data_space(htx);
	if (!block) {
		h2c->flags |= H2_CF_DEM_SFULL;
		TRACE_STATE("h2s rxbuf is full", H2_EV_RX_FRAME|H2_EV_RX_DATA|H2_EV_H2S_BLK, h2c->conn, h2s);
		goto fail;
	}
	if (flen > block)
		flen = block;

	/* here, flen is the max we can copy into the output buffer */
	block = b_contig_data(&h2c->dbuf, 0);
	if (flen > block)
		flen = block;

	sent = htx_add_data(htx, ist2(b_head(&h2c->dbuf), flen));
	TRACE_DATA("move some data to h2s rxbuf", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s, 0, (void *)(long)sent);

	b_del(&h2c->dbuf, sent);
	h2c->dfl    -= sent;
	h2c->rcvd_c += sent;
	h2c->rcvd_s += sent;  // warning, this can also affect the closed streams!

	if (h2s->flags & H2_SF_DATA_CLEN) {
		h2s->body_len -= sent;
		htx->extra = h2s->body_len;
	}

	if (sent < flen) {
		h2c->flags |= H2_CF_DEM_SFULL;
		TRACE_STATE("h2s rxbuf is full", H2_EV_RX_FRAME|H2_EV_RX_DATA|H2_EV_H2S_BLK, h2c->conn, h2s);
		goto fail;
	}

	goto try_again;

 end_transfer:
	/* here we're done with the frame, all the payload (except padding) was
	 * transferred.
	 */

	if (!(h2s->flags & H2_SF_BODY_TUNNEL) && (h2c->dff & H2_F_DATA_END_STREAM)) {
		/* no more data are expected for this message. This add the EOM
		 * flag but only on the response path or if no tunnel attempt
		 * was aborted. Otherwise (request path + tunnel abrted), the
		 * EOM was already reported.
		 */
		if ((h2c->flags & H2_CF_IS_BACK) || !(h2s->flags & H2_SF_TUNNEL_ABRT)) {
			/* If we receive an empty DATA frame with ES flag while the HTX
			 * message is empty, we must be sure to push a block to be sure
			 * the HTX EOM flag will be handled on the other side. It is a
			 * workaround because for now it is not possible to push empty
			 * HTX DATA block. And without this block, there is no way to
			 * "commit" the end of the message.
			 */
			if (htx_is_empty(htx)) {
				if (!htx_add_endof(htx, HTX_BLK_EOT))
					goto fail;
			}
			htx->flags |= HTX_FL_EOM;
		}
	}

	h2c->rcvd_c += h2c->dpl;
	h2c->rcvd_s += h2c->dpl;
	h2c->dpl = 0;
	h2c->st0 = H2_CS_FRAME_A; // send the corresponding window update
	htx_to_buf(htx, csbuf);
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
	return 1;
 fail:
	if (htx)
		htx_to_buf(htx, csbuf);
	TRACE_LEAVE(H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
	return 0;
}

/* Try to send a HEADERS frame matching HTX response present in HTX message
 * <htx> for the H2 stream <h2s>. Returns the number of bytes sent. The caller
 * must check the stream's status to detect any error which might have happened
 * subsequently to a successful send. The htx blocks are automatically removed
 * from the message. The htx message is assumed to be valid since produced from
 * the internal code, hence it contains a start line, an optional series of
 * header blocks and an end of header, otherwise an invalid frame could be
 * emitted and the resulting htx message could be left in an inconsistent state.
 */
static size_t h2s_frt_make_resp_headers(struct h2s *h2s, struct htx *htx)
{
	struct http_hdr list[global.tune.max_http_hdr];
	struct h2c *h2c = h2s->h2c;
	struct htx_blk *blk;
	struct buffer outbuf;
	struct buffer *mbuf;
	struct htx_sl *sl;
	enum htx_blk_type type;
	int es_now = 0;
	int ret = 0;
	int hdr;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);

	if (h2c_mux_busy(h2c, h2s)) {
		TRACE_STATE("mux output busy", H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);
		h2s->flags |= H2_SF_BLK_MBUSY;
		TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);
		return 0;
	}

	/* get the start line (we do have one) and the rest of the headers,
	 * that we dump starting at header 0 */
	sl = NULL;
	hdr = 0;
	for (blk = htx_get_head_blk(htx); blk; blk = htx_get_next_blk(htx, blk)) {
		type = htx_get_blk_type(blk);

		if (type == HTX_BLK_UNUSED)
			continue;

		if (type == HTX_BLK_EOH)
			break;

		if (type == HTX_BLK_HDR) {
			BUG_ON(!sl); /* The start-line mut be defined before any headers */
			if (unlikely(hdr >= sizeof(list)/sizeof(list[0]) - 1)) {
				TRACE_ERROR("too many headers", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
				goto fail;
			}

			list[hdr].n = htx_get_blk_name(htx, blk);
			list[hdr].v = htx_get_blk_value(htx, blk);
			hdr++;
		}
		else if (type == HTX_BLK_RES_SL) {
			BUG_ON(sl); /* Only one start-line expected */
			sl = htx_get_blk_ptr(htx, blk);
			h2s->status = sl->info.res.status;
			if (h2s->status == 204 || h2s->status == 304)
				h2s->flags |= H2_SF_BODYLESS_RESP;
			if (h2s->status < 100 || h2s->status > 999) {
				TRACE_ERROR("will not encode an invalid status code", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
				goto fail;
			}
			else if (h2s->status == 101) {
				if (unlikely(h2s->flags & H2_SF_EXT_CONNECT_RCVD)) {
					/* If an Extended CONNECT has been received, we need to convert 101 to 200 */
					h2s->status = 200;
					h2s->flags &= ~H2_SF_EXT_CONNECT_RCVD;
				}
				else {
					/* Otherwise, 101 responses are not supported in H2, so return a error (RFC7540#8.1.1) */
					TRACE_ERROR("will not encode an invalid status code", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
					goto fail;
				}
			}
			else if ((h2s->flags & H2_SF_BODY_TUNNEL) && h2s->status >= 300) {
				/* Abort the tunnel attempt */
				h2s->flags &= ~H2_SF_BODY_TUNNEL;
				h2s->flags |= H2_SF_TUNNEL_ABRT;
			}
		}
		else {
			TRACE_ERROR("will not encode unexpected htx block", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
			goto fail;
		}
	}

	/* The start-line me be defined */
	BUG_ON(!sl);

	/* marker for end of headers */
	list[hdr].n = ist("");

	mbuf = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, mbuf)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		TRACE_STATE("waiting for room in output buffer", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_BLK, h2c->conn, h2s);
		return 0;
	}

	chunk_reset(&outbuf);

	while (1) {
		outbuf = b_make(b_tail(mbuf), b_contig_space(mbuf), 0, 0);
		if (outbuf.size >= 9 || !b_space_wraps(mbuf))
			break;
	realign_again:
		b_slow_realign(mbuf, trash.area, b_data(mbuf));
	}

	if (outbuf.size < 9)
		goto full;

	/* len: 0x000000 (fill later), type: 1(HEADERS), flags: ENDH=4 */
	memcpy(outbuf.area, "\x00\x00\x00\x01\x04", 5);
	write_n32(outbuf.area + 5, h2s->id); // 4 bytes
	outbuf.data = 9;

	if ((h2c->flags & (H2_CF_SHTS_UPDATED|H2_CF_DTSU_EMITTED)) == H2_CF_SHTS_UPDATED) {
		/* SETTINGS_HEADER_TABLE_SIZE changed, we must send an HPACK
		 * dynamic table size update so that some clients are not
		 * confused. In practice we only need to send the DTSU when the
		 * advertised size is lower than the current one, and since we
		 * don't use it and don't care about the default 4096 bytes,
		 * we only ack it with a zero size thus we at most have to deal
		 * with this once. See RFC7541#4.2 and #6.3 for the spec, and
		 * below for the whole context and interoperability risks:
		 * https://lists.w3.org/Archives/Public/ietf-http-wg/2021OctDec/0235.html
		 */
		if (b_room(&outbuf) < 1)
			goto full;
		outbuf.area[outbuf.data++] = 0x20; // HPACK DTSU 0 bytes

		/* let's not update the flags now but only once the buffer is
		 * really committed.
		 */
	}

	/* encode status, which necessarily is the first one */
	if (!hpack_encode_int_status(&outbuf, h2s->status)) {
		if (b_space_wraps(mbuf))
			goto realign_again;
		goto full;
	}

	/* encode all headers, stop at empty name */
	for (hdr = 0; hdr < sizeof(list)/sizeof(list[0]); hdr++) {
		/* these ones do not exist in H2 and must be dropped. */
		if (isteq(list[hdr].n, ist("connection")) ||
		    isteq(list[hdr].n, ist("proxy-connection")) ||
		    isteq(list[hdr].n, ist("keep-alive")) ||
		    isteq(list[hdr].n, ist("upgrade")) ||
		    isteq(list[hdr].n, ist("transfer-encoding")))
			continue;

		/* Skip all pseudo-headers */
		if (*(list[hdr].n.ptr) == ':')
			continue;

		if (isteq(list[hdr].n, ist("")))
			break; // end

		if (!hpack_encode_header(&outbuf, list[hdr].n, list[hdr].v)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}
	}

	/* update the frame's size */
	h2_set_frame_size(outbuf.area, outbuf.data - 9);

	if (outbuf.data > h2c->mfs + 9) {
		if (!h2_fragment_headers(&outbuf, h2c->mfs)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}
	}

	TRACE_USER("sent H2 response ", H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s, htx);

	/* remove all header blocks including the EOH and compute the
	 * corresponding size.
	 */
	ret = 0;
	blk = htx_get_head_blk(htx);
	while (blk) {
		type = htx_get_blk_type(blk);
		ret += htx_get_blksz(blk);
		blk = htx_remove_blk(htx, blk);
		/* The removed block is the EOH */
		if (type == HTX_BLK_EOH)
			break;
	}

	if (!h2s->cs || h2s->cs->flags & CS_FL_SHW) {
		/* Response already closed: add END_STREAM */
		es_now = 1;
	}
	else if ((htx->flags & HTX_FL_EOM) && htx_is_empty(htx) && h2s->status >= 200) {
		/* EOM+empty: we may need to add END_STREAM except for 1xx
		 * responses and tunneled response.
		 */
		if (!(h2s->flags & H2_SF_BODY_TUNNEL) || h2s->status >= 300)
			es_now = 1;
	}

	if (es_now)
		outbuf.area[4] |= H2_F_HEADERS_END_STREAM;

	/* commit the H2 response */
	b_add(mbuf, outbuf.data);

	/* indicates the HEADERS frame was sent, except for 1xx responses. For
	 * 1xx responses, another HEADERS frame is expected.
	 */
	if (h2s->status >= 200)
		h2s->flags |= H2_SF_HEADERS_SENT;

	if (h2c->flags & H2_CF_SHTS_UPDATED) {
		/* was sent above */
		h2c->flags |= H2_CF_DTSU_EMITTED;
		h2c->flags &= H2_CF_SHTS_UPDATED;
	}

	if (es_now) {
		h2s->flags |= H2_SF_ES_SENT;
		TRACE_PROTO("setting ES on HEADERS frame", H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s, htx);
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HLOC;
		else
			h2s_close(h2s);
	}

	/* OK we could properly deliver the response */
 end:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);
	return ret;
 full:
	if ((mbuf = br_tail_add(h2c->mbuf)) != NULL)
		goto retry;
	h2c->flags |= H2_CF_MUX_MFULL;
	h2s->flags |= H2_SF_BLK_MROOM;
	ret = 0;
	TRACE_STATE("mux buffer full", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_BLK, h2c->conn, h2s);
	goto end;
 fail:
	/* unparsable HTX messages, too large ones to be produced in the local
	 * list etc go here (unrecoverable errors).
	 */
	h2s_error(h2s, H2_ERR_INTERNAL_ERROR);
	ret = 0;
	goto end;
}

/* Try to send a HEADERS frame matching HTX request present in HTX message
 * <htx> for the H2 stream <h2s>. Returns the number of bytes sent. The caller
 * must check the stream's status to detect any error which might have happened
 * subsequently to a successful send. The htx blocks are automatically removed
 * from the message. The htx message is assumed to be valid since produced from
 * the internal code, hence it contains a start line, an optional series of
 * header blocks and an end of header, otherwise an invalid frame could be
 * emitted and the resulting htx message could be left in an inconsistent state.
 */
static size_t h2s_bck_make_req_headers(struct h2s *h2s, struct htx *htx)
{
	struct http_hdr list[global.tune.max_http_hdr];
	struct h2c *h2c = h2s->h2c;
	struct htx_blk *blk;
	struct buffer outbuf;
	struct buffer *mbuf;
	struct htx_sl *sl;
	struct ist meth, uri, auth, host = IST_NULL;
	enum htx_blk_type type;
	int es_now = 0;
	int ret = 0;
	int hdr;
	int extended_connect = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);

	if (h2c_mux_busy(h2c, h2s)) {
		TRACE_STATE("mux output busy", H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);
		h2s->flags |= H2_SF_BLK_MBUSY;
		TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);
		return 0;
	}

	/* get the start line (we do have one) and the rest of the headers,
	 * that we dump starting at header 0 */
	sl = NULL;
	hdr = 0;
	for (blk = htx_get_head_blk(htx); blk; blk = htx_get_next_blk(htx, blk)) {
		type = htx_get_blk_type(blk);

		if (type == HTX_BLK_UNUSED)
			continue;

		if (type == HTX_BLK_EOH)
			break;

		if (type == HTX_BLK_HDR) {
			BUG_ON(!sl); /* The start-line mut be defined before any headers */
			if (unlikely(hdr >= sizeof(list)/sizeof(list[0]) - 1)) {
				TRACE_ERROR("too many headers", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
				goto fail;
			}

			list[hdr].n = htx_get_blk_name(htx, blk);
			list[hdr].v = htx_get_blk_value(htx, blk);

			/* Skip header if same name is used to add the server name */
			if ((h2c->flags & H2_CF_IS_BACK) && h2c->proxy->server_id_hdr_name &&
			    isteq(list[hdr].n, ist2(h2c->proxy->server_id_hdr_name, h2c->proxy->server_id_hdr_len)))
				continue;

			/* Convert connection: upgrade to Extended connect from rfc 8441 */
			if ((sl->flags & HTX_SL_F_CONN_UPG) && isteqi(list[hdr].n, ist("connection"))) {
				/* rfc 7230 #6.1 Connection = list of tokens */
				struct ist connection_ist = list[hdr].v;
				do {
					if (isteqi(iststop(connection_ist, ','),
					           ist("upgrade"))) {
						if (!(h2c->flags & H2_CF_RCVD_RFC8441)) {
							TRACE_STATE("reject upgrade because of no RFC8441 support", H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);
							goto fail;
						}

						TRACE_STATE("convert upgrade to extended connect method", H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);
						h2s->flags |= (H2_SF_BODY_TUNNEL|H2_SF_EXT_CONNECT_SENT);
						sl->info.req.meth = HTTP_METH_CONNECT;
						meth = ist("CONNECT");

						extended_connect = 1;
						break;
					}

					connection_ist = istadv(istfind(connection_ist, ','), 1);
				} while (istlen(connection_ist));
			}

			if ((sl->flags & HTX_SL_F_CONN_UPG) && isteq(list[hdr].n, ist("upgrade"))) {
				/* rfc 7230 #6.7 Upgrade = list of protocols
				 * rfc 8441 #4 Extended connect = :protocol is single-valued
				 *
				 * only first HTTP/1 protocol is preserved
				 */
				const struct ist protocol = iststop(list[hdr].v, ',');
				/* upgrade_protocol field is 16 bytes long in h2s */
				istpad(h2s->upgrade_protocol, isttrim(protocol, 15));
			}

			if (isteq(list[hdr].n, ist("host")))
				host = list[hdr].v;

			hdr++;
		}
		else if (type == HTX_BLK_REQ_SL) {
			BUG_ON(sl); /* Only one start-line expected */
			sl = htx_get_blk_ptr(htx, blk);
			meth = htx_sl_req_meth(sl);
			uri  = htx_sl_req_uri(sl);
			if (sl->info.req.meth == HTTP_METH_HEAD)
				h2s->flags |= H2_SF_BODYLESS_RESP;
			if (unlikely(uri.len == 0)) {
				TRACE_ERROR("no URI in HTX request", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
				goto fail;
			}
		}
		else {
			TRACE_ERROR("will not encode unexpected htx block", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
			goto fail;
		}
	}

	/* The start-line me be defined */
	BUG_ON(!sl);

	/* Now add the server name to a header (if requested) */
	if ((h2c->flags & H2_CF_IS_BACK) && h2c->proxy->server_id_hdr_name) {
		struct server *srv = objt_server(h2c->conn->target);

		if (srv) {
			list[hdr].n = ist2(h2c->proxy->server_id_hdr_name, h2c->proxy->server_id_hdr_len);
			list[hdr].v = ist(srv->id);
			hdr++;
		}
	}

	/* marker for end of headers */
	list[hdr].n = ist("");

	mbuf = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, mbuf)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		TRACE_STATE("waiting for room in output buffer", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_BLK, h2c->conn, h2s);
		return 0;
	}

	chunk_reset(&outbuf);

	while (1) {
		outbuf = b_make(b_tail(mbuf), b_contig_space(mbuf), 0, 0);
		if (outbuf.size >= 9 || !b_space_wraps(mbuf))
			break;
	realign_again:
		b_slow_realign(mbuf, trash.area, b_data(mbuf));
	}

	if (outbuf.size < 9)
		goto full;

	/* len: 0x000000 (fill later), type: 1(HEADERS), flags: ENDH=4 */
	memcpy(outbuf.area, "\x00\x00\x00\x01\x04", 5);
	write_n32(outbuf.area + 5, h2s->id); // 4 bytes
	outbuf.data = 9;

	/* encode the method, which necessarily is the first one */
	if (!hpack_encode_method(&outbuf, sl->info.req.meth, meth)) {
		if (b_space_wraps(mbuf))
			goto realign_again;
		goto full;
	}

	auth = ist(NULL);

	/* RFC7540 #8.3: the CONNECT method must have :
	 *   - :authority set to the URI part (host:port)
	 *   - :method set to CONNECT
	 *   - :scheme and :path omitted
	 *
	 *   Note that this is not applicable in case of the Extended CONNECT
	 *   protocol from rfc 8441.
	 */
	if (unlikely(sl->info.req.meth == HTTP_METH_CONNECT) && !extended_connect) {
		auth = uri;

		if (!hpack_encode_header(&outbuf, ist(":authority"), auth)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}
		h2s->flags |= H2_SF_BODY_TUNNEL;
	} else {
		/* other methods need a :scheme. If an authority is known from
		 * the request line, it must be sent, otherwise only host is
		 * sent. Host is never sent as the authority.
		 *
		 * This code is also applicable for Extended CONNECT protocol
		 * from rfc 8441.
		 */
		struct ist scheme = { };

		if (uri.ptr[0] != '/' && uri.ptr[0] != '*') {
			/* the URI seems to start with a scheme */
			int len = 1;

			while (len < uri.len && uri.ptr[len] != ':')
				len++;

			if (len + 2 < uri.len && uri.ptr[len + 1] == '/' && uri.ptr[len + 2] == '/') {
				/* make the uri start at the authority now */
				scheme = ist2(uri.ptr, len);
				uri = istadv(uri, len + 3);

				/* find the auth part of the URI */
				auth = ist2(uri.ptr, 0);
				while (auth.len < uri.len && auth.ptr[auth.len] != '/')
					auth.len++;

				uri = istadv(uri, auth.len);
			}
		}

		/* For Extended CONNECT, the :authority must be present.
		 * Use host value for it.
		 */
		if (unlikely(extended_connect) && isttest(host))
			auth = host;

		if (!scheme.len) {
			/* no explicit scheme, we're using an origin-form URI,
			 * probably from an H1 request transcoded to H2 via an
			 * external layer, then received as H2 without authority.
			 * So we have to look up the scheme from the HTX flags.
			 * In such a case only http and https are possible, and
			 * https is the default (sent by browsers).
			 */
			if ((sl->flags & (HTX_SL_F_HAS_SCHM|HTX_SL_F_SCHM_HTTP)) == (HTX_SL_F_HAS_SCHM|HTX_SL_F_SCHM_HTTP))
				scheme = ist("http");
			else
				scheme = ist("https");
		}

		if (!hpack_encode_scheme(&outbuf, scheme)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}

		if (auth.len && !hpack_encode_header(&outbuf, ist(":authority"), auth)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}

		/* encode the path. RFC7540#8.1.2.3: if path is empty it must
		 * be sent as '/' or '*'.
		 */
		if (unlikely(!uri.len)) {
			if (sl->info.req.meth == HTTP_METH_OPTIONS)
				uri = ist("*");
			else
				uri = ist("/");
		}

		if (!hpack_encode_path(&outbuf, uri)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}

		/* encode the pseudo-header protocol from rfc8441 if using
		 * Extended CONNECT method.
		 */
		if (unlikely(extended_connect)) {
			const struct ist protocol = ist(h2s->upgrade_protocol);
			if (isttest(protocol)) {
				if (!hpack_encode_header(&outbuf,
				                         ist(":protocol"),
				                         protocol)) {
					/* output full */
					if (b_space_wraps(mbuf))
						goto realign_again;
					goto full;
				}
			}
		}
	}

	/* encode all headers, stop at empty name. Host is only sent if we
	 * do not provide an authority.
	 */
	for (hdr = 0; hdr < sizeof(list)/sizeof(list[0]); hdr++) {
		struct ist n = list[hdr].n;
		struct ist v = list[hdr].v;

		/* these ones do not exist in H2 and must be dropped. */
		if (isteq(n, ist("connection")) ||
		    (auth.len && isteq(n, ist("host"))) ||
		    isteq(n, ist("proxy-connection")) ||
		    isteq(n, ist("keep-alive")) ||
		    isteq(n, ist("upgrade")) ||
		    isteq(n, ist("transfer-encoding")))
			continue;

		if (isteq(n, ist("te"))) {
			/* "te" may only be sent with "trailers" if this value
			 * is present, otherwise it must be deleted.
			 */
			v = istist(v, ist("trailers"));
			if (!isttest(v) || (v.len > 8 && v.ptr[8] != ','))
				continue;
			v = ist("trailers");
		}

		/* Skip all pseudo-headers */
		if (*(n.ptr) == ':')
			continue;

		if (isteq(n, ist("")))
			break; // end

		if (!hpack_encode_header(&outbuf, n, v)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}
	}

	/* update the frame's size */
	h2_set_frame_size(outbuf.area, outbuf.data - 9);

	if (outbuf.data > h2c->mfs + 9) {
		if (!h2_fragment_headers(&outbuf, h2c->mfs)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}
	}

	TRACE_USER("sent H2 request  ", H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s, htx);

	/* remove all header blocks including the EOH and compute the
	 * corresponding size.
	 */
	ret = 0;
	blk = htx_get_head_blk(htx);
	while (blk) {
		type = htx_get_blk_type(blk);
		ret += htx_get_blksz(blk);
		blk = htx_remove_blk(htx, blk);
		/* The removed block is the EOH */
		if (type == HTX_BLK_EOH)
			break;
	}

	if (!h2s->cs || h2s->cs->flags & CS_FL_SHW) {
		/* Request already closed: add END_STREAM */
		es_now = 1;
	}
	if ((htx->flags & HTX_FL_EOM) && htx_is_empty(htx)) {
		/* EOM+empty: we may need to add END_STREAM (except for CONNECT
		 * request)
		 */
		if (!(h2s->flags & H2_SF_BODY_TUNNEL))
			es_now = 1;
	}

	if (es_now)
		outbuf.area[4] |= H2_F_HEADERS_END_STREAM;

	/* commit the H2 response */
	b_add(mbuf, outbuf.data);
	h2s->flags |= H2_SF_HEADERS_SENT;
	h2s->st = H2_SS_OPEN;

	if (es_now) {
		TRACE_PROTO("setting ES on HEADERS frame", H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s, htx);
		// trim any possibly pending data (eg: inconsistent content-length)
		h2s->flags |= H2_SF_ES_SENT;
		h2s->st = H2_SS_HLOC;
	}

 end:
	return ret;
 full:
	if ((mbuf = br_tail_add(h2c->mbuf)) != NULL)
		goto retry;
	h2c->flags |= H2_CF_MUX_MFULL;
	h2s->flags |= H2_SF_BLK_MROOM;
	ret = 0;
	TRACE_STATE("mux buffer full", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_BLK, h2c->conn, h2s);
	goto end;
 fail:
	/* unparsable HTX messages, too large ones to be produced in the local
	 * list etc go here (unrecoverable errors).
	 */
	h2s_error(h2s, H2_ERR_INTERNAL_ERROR);
	ret = 0;
	goto end;
}

/* Try to send a DATA frame matching HTTP response present in HTX structure
 * present in <buf>, for stream <h2s>. Returns the number of bytes sent. The
 * caller must check the stream's status to detect any error which might have
 * happened subsequently to a successful send. Returns the number of data bytes
 * consumed, or zero if nothing done.
 */
static size_t h2s_make_data(struct h2s *h2s, struct buffer *buf, size_t count)
{
	struct h2c *h2c = h2s->h2c;
	struct htx *htx;
	struct buffer outbuf;
	struct buffer *mbuf;
	size_t total = 0;
	int es_now = 0;
	int bsize; /* htx block size */
	int fsize; /* h2 frame size  */
	struct htx_blk *blk;
	enum htx_blk_type type;
	int trunc_out; /* non-zero if truncated on out buf */

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);

	if (h2c_mux_busy(h2c, h2s)) {
		TRACE_STATE("mux output busy", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
		h2s->flags |= H2_SF_BLK_MBUSY;
		TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
		goto end;
	}

	htx = htx_from_buf(buf);

	/* We only come here with HTX_BLK_DATA blocks */

 new_frame:
	if (!count || htx_is_empty(htx))
		goto end;

	if ((h2c->flags & H2_CF_IS_BACK) &&
		 (h2s->flags & (H2_SF_HEADERS_RCVD|H2_SF_BODY_TUNNEL)) == H2_SF_BODY_TUNNEL) {
		/* The response HEADERS frame not received yet. Thus the tunnel
		 * is not fully established yet. In this situation, we block
		 * data sending.
		 */
		h2s->flags |= H2_SF_BLK_MBUSY;
		TRACE_STATE("Request DATA frame blocked waiting for tunnel establishment", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
		goto end;
	}
	else if ((h2c->flags & H2_CF_IS_BACK) && (h2s->flags & H2_SF_TUNNEL_ABRT)) {
		/* a tunnel attempt was aborted but the is pending raw data to xfer to the server.
		 * Thus the stream is closed with the CANCEL error. The error will be reported to
		 * the upper layer as aserver abort. But at this stage there is nothing more we can
		 * do. We just wait for the end of the response to be sure to not truncate it.
		 */
		if (!(h2s->flags & H2_SF_ES_RCVD)) {
			TRACE_STATE("Request DATA frame blocked waiting end of aborted tunnel", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
			h2s->flags |= H2_SF_BLK_MBUSY;
		}
		else {
			TRACE_ERROR("Request DATA frame for aborted tunnel", H2_EV_RX_FRAME|H2_EV_RX_DATA, h2c->conn, h2s);
			h2s_error(h2s, H2_ERR_CANCEL);
		}
		goto end;
	}

	blk   = htx_get_head_blk(htx);
	type  = htx_get_blk_type(blk);
	bsize = htx_get_blksz(blk);
	fsize = bsize;
	trunc_out = 0;
	if (type != HTX_BLK_DATA)
		goto end;

	mbuf = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, mbuf)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		TRACE_STATE("waiting for room in output buffer", H2_EV_TX_FRAME|H2_EV_TX_DATA|H2_EV_H2S_BLK, h2c->conn, h2s);
		goto end;
	}

	/* Perform some optimizations to reduce the number of buffer copies.
	 * First, if the mux's buffer is empty and the htx area contains
	 * exactly one data block of the same size as the requested count, and
	 * this count fits within the frame size, the stream's window size, and
	 * the connection's window size, then it's possible to simply swap the
	 * caller's buffer with the mux's output buffer and adjust offsets and
	 * length to match the entire DATA HTX block in the middle. In this
	 * case we perform a true zero-copy operation from end-to-end. This is
	 * the situation that happens all the time with large files. Second, if
	 * this is not possible, but the mux's output buffer is empty, we still
	 * have an opportunity to avoid the copy to the intermediary buffer, by
	 * making the intermediary buffer's area point to the output buffer's
	 * area. In this case we want to skip the HTX header to make sure that
	 * copies remain aligned and that this operation remains possible all
	 * the time. This goes for headers, data blocks and any data extracted
	 * from the HTX blocks.
	 */
	if (unlikely(fsize == count &&
	             htx_nbblks(htx) == 1 && type == HTX_BLK_DATA &&
	             fsize <= h2s_mws(h2s) && fsize <= h2c->mws && fsize <= h2c->mfs)) {
		void *old_area = mbuf->area;

		if (b_data(mbuf)) {
			/* Too bad there are data left there. We're willing to memcpy/memmove
			 * up to 1/4 of the buffer, which means that it's OK to copy a large
			 * frame into a buffer containing few data if it needs to be realigned,
			 * and that it's also OK to copy few data without realigning. Otherwise
			 * we'll pretend the mbuf is full and wait for it to become empty.
			 */
			if (fsize + 9 <= b_room(mbuf) &&
			    (b_data(mbuf) <= b_size(mbuf) / 4 ||
			     (fsize <= b_size(mbuf) / 4 && fsize + 9 <= b_contig_space(mbuf)))) {
				TRACE_STATE("small data present in output buffer, appending", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
				goto copy;
			}

			if ((mbuf = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;

			h2c->flags |= H2_CF_MUX_MFULL;
			h2s->flags |= H2_SF_BLK_MROOM;
			TRACE_STATE("too large data present in output buffer, waiting for emptiness", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
			goto end;
		}

		if (htx->flags & HTX_FL_EOM) {
			/* EOM+empty: we may need to add END_STREAM (except for tunneled
			 * message)
			 */
			if (!(h2s->flags & H2_SF_BODY_TUNNEL))
				es_now = 1;
		}
		/* map an H2 frame to the HTX block so that we can put the
		 * frame header there.
		 */
		*mbuf = b_make(buf->area, buf->size, sizeof(struct htx) + blk->addr - 9, fsize + 9);
		outbuf.area    = b_head(mbuf);

		/* prepend an H2 DATA frame header just before the DATA block */
		memcpy(outbuf.area, "\x00\x00\x00\x00\x00", 5);
		write_n32(outbuf.area + 5, h2s->id); // 4 bytes
		if (es_now)
			outbuf.area[4] |= H2_F_DATA_END_STREAM;
		h2_set_frame_size(outbuf.area, fsize);

		/* update windows */
		h2s->sws -= fsize;
		h2c->mws -= fsize;

		/* and exchange with our old area */
		buf->area = old_area;
		buf->data = buf->head = 0;
		total += fsize;
		fsize = 0;

		TRACE_PROTO("sent H2 DATA frame (zero-copy)", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
		goto out;
	}

 copy:
	/* for DATA and EOM we'll have to emit a frame, even if empty */

	while (1) {
		outbuf = b_make(b_tail(mbuf), b_contig_space(mbuf), 0, 0);
		if (outbuf.size >= 9 || !b_space_wraps(mbuf))
			break;
	realign_again:
		b_slow_realign(mbuf, trash.area, b_data(mbuf));
	}

	if (outbuf.size < 9) {
		if ((mbuf = br_tail_add(h2c->mbuf)) != NULL)
			goto retry;
		h2c->flags |= H2_CF_MUX_MFULL;
		h2s->flags |= H2_SF_BLK_MROOM;
		TRACE_STATE("output buffer full", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
		goto end;
	}

	/* len: 0x000000 (fill later), type: 0(DATA), flags: none=0 */
	memcpy(outbuf.area, "\x00\x00\x00\x00\x00", 5);
	write_n32(outbuf.area + 5, h2s->id); // 4 bytes
	outbuf.data = 9;

	/* we have in <fsize> the exact number of bytes we need to copy from
	 * the HTX buffer. We need to check this against the connection's and
	 * the stream's send windows, and to ensure that this fits in the max
	 * frame size and in the buffer's available space minus 9 bytes (for
	 * the frame header). The connection's flow control is applied last so
	 * that we can use a separate list of streams which are immediately
	 * unblocked on window opening. Note: we don't implement padding.
	 */

	if (!fsize)
		goto send_empty;

	if (h2s_mws(h2s) <= 0) {
		h2s->flags |= H2_SF_BLK_SFCTL;
		if (LIST_INLIST(&h2s->list))
			LIST_DEL_INIT(&h2s->list);
		LIST_APPEND(&h2c->blocked_list, &h2s->list);
		TRACE_STATE("stream window <=0, flow-controlled", H2_EV_TX_FRAME|H2_EV_TX_DATA|H2_EV_H2S_FCTL, h2c->conn, h2s);
		goto end;
	}

	if (fsize > count)
		fsize = count;

	if (fsize > h2s_mws(h2s))
		fsize = h2s_mws(h2s); // >0

	if (h2c->mfs && fsize > h2c->mfs)
		fsize = h2c->mfs; // >0

	if (fsize + 9 > outbuf.size) {
		/* It doesn't fit at once. If it at least fits once split and
		 * the amount of data to move is low, let's defragment the
		 * buffer now.
		 */
		if (b_space_wraps(mbuf) &&
		    (fsize + 9 <= b_room(mbuf)) &&
		    b_data(mbuf) <= MAX_DATA_REALIGN)
			goto realign_again;
		fsize = outbuf.size - 9;
		trunc_out = 1;

		if (fsize <= 0) {
			/* no need to send an empty frame here */
			if ((mbuf = br_tail_add(h2c->mbuf)) != NULL)
				goto retry;
			h2c->flags |= H2_CF_MUX_MFULL;
			h2s->flags |= H2_SF_BLK_MROOM;
			TRACE_STATE("output buffer full", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
			goto end;
		}
	}

	if (h2c->mws <= 0) {
		h2s->flags |= H2_SF_BLK_MFCTL;
		TRACE_STATE("connection window <=0, stream flow-controlled", H2_EV_TX_FRAME|H2_EV_TX_DATA|H2_EV_H2C_FCTL, h2c->conn, h2s);
		goto end;
	}

	if (fsize > h2c->mws)
		fsize = h2c->mws;

	/* now let's copy this this into the output buffer */
	memcpy(outbuf.area + 9, htx_get_blk_ptr(htx, blk), fsize);
	h2s->sws -= fsize;
	h2c->mws -= fsize;
	count    -= fsize;

 send_empty:
	/* update the frame's size */
	h2_set_frame_size(outbuf.area, fsize);

	/* consume incoming HTX block */
	total += fsize;
	if (fsize == bsize) {
		htx_remove_blk(htx, blk);
		if ((htx->flags & HTX_FL_EOM) && htx_is_empty(htx)) {
			/* EOM+empty: we may need to add END_STREAM (except for tunneled
			 * message)
			 */
			if (!(h2s->flags & H2_SF_BODY_TUNNEL))
				es_now = 1;
		}
	}
	else {
		/* we've truncated this block */
		htx_cut_data_blk(htx, blk, fsize);
	}

	if (es_now)
		outbuf.area[4] |= H2_F_DATA_END_STREAM;

	/* commit the H2 response */
	b_add(mbuf, fsize + 9);

 out:
	if (es_now) {
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HLOC;
		else
			h2s_close(h2s);

		h2s->flags |= H2_SF_ES_SENT;
		TRACE_PROTO("ES flag set on outgoing frame", H2_EV_TX_FRAME|H2_EV_TX_DATA|H2_EV_TX_EOI, h2c->conn, h2s);
	}
	else if (fsize) {
		if (fsize == bsize) {
			TRACE_DEVEL("more data may be available, trying to send another frame", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
			goto new_frame;
		}
		else if (trunc_out) {
			/* we've truncated this block */
			goto new_frame;
		}
	}

 end:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
	return total;
}

/* Skip the message payload (DATA blocks) and emit an empty DATA frame with the
 * ES flag set for stream <h2s>. This function is called for response known to
 * have no payload. Only DATA blocks are skipped. This means the trailers are
 * still emitted. The caller must check the stream's status to detect any error
 * which might have happened subsequently to a successful send. Returns the
 * number of data bytes consumed, or zero if nothing done.
 */
static size_t h2s_skip_data(struct h2s *h2s, struct buffer *buf, size_t count)
{
	struct h2c *h2c = h2s->h2c;
	struct htx *htx;
	int bsize; /* htx block size */
	int fsize; /* h2 frame size  */
	struct htx_blk *blk;
	enum htx_blk_type type;
	size_t total = 0;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);

	if (h2c_mux_busy(h2c, h2s)) {
		TRACE_STATE("mux output busy", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
		h2s->flags |= H2_SF_BLK_MBUSY;
		TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
		goto end;
	}

	htx = htx_from_buf(buf);

 next_data:
	if (!count || htx_is_empty(htx))
		goto end;
	blk   = htx_get_head_blk(htx);
	type  = htx_get_blk_type(blk);
	bsize = htx_get_blksz(blk);
	fsize = bsize;
	if (type != HTX_BLK_DATA)
		goto end;

	if (fsize > count)
		fsize = count;

	if (fsize != bsize)
		goto skip_data;

	if (!(htx->flags & HTX_FL_EOM) || !htx_is_unique_blk(htx, blk))
		goto skip_data;

	/* Here, it is the last block and it is also the end of the message. So
	 * we can emit an empty DATA frame with the ES flag set
	 */
	if (h2_send_empty_data_es(h2s) <= 0)
		goto end;

	if (h2s->st == H2_SS_OPEN)
		h2s->st = H2_SS_HLOC;
	else
		h2s_close(h2s);

 skip_data:
	/* consume incoming HTX block */
	total += fsize;
	if (fsize == bsize) {
		TRACE_DEVEL("more data may be available, trying to skip another frame", H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
		htx_remove_blk(htx, blk);
		goto next_data;
	}
	else {
		/* we've truncated this block */
		htx_cut_data_blk(htx, blk, fsize);
	}

 end:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_DATA, h2c->conn, h2s);
	return total;
}

/* Try to send a HEADERS frame matching HTX_BLK_TLR series of blocks present in
 * HTX message <htx> for the H2 stream <h2s>. Returns the number of bytes
 * processed. The caller must check the stream's status to detect any error
 * which might have happened subsequently to a successful send. The htx blocks
 * are automatically removed from the message. The htx message is assumed to be
 * valid since produced from the internal code. Processing stops when meeting
 * the EOT, which *is* removed. All trailers are processed at once and sent as a
 * single frame. The ES flag is always set.
 */
static size_t h2s_make_trailers(struct h2s *h2s, struct htx *htx)
{
	struct http_hdr list[global.tune.max_http_hdr];
	struct h2c *h2c = h2s->h2c;
	struct htx_blk *blk;
	struct buffer outbuf;
	struct buffer *mbuf;
	enum htx_blk_type type;
	int ret = 0;
	int hdr;
	int idx;

	TRACE_ENTER(H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);

	if (h2c_mux_busy(h2c, h2s)) {
		TRACE_STATE("mux output busy", H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);
		h2s->flags |= H2_SF_BLK_MBUSY;
		TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);
		goto end;
	}

	/* get trailers. */
	hdr = 0;
	for (blk = htx_get_head_blk(htx); blk; blk = htx_get_next_blk(htx, blk)) {
		type = htx_get_blk_type(blk);

		if (type == HTX_BLK_UNUSED)
			continue;

		if (type == HTX_BLK_EOT)
			break;
		if (type == HTX_BLK_TLR) {
			if (unlikely(hdr >= sizeof(list)/sizeof(list[0]) - 1)) {
				TRACE_ERROR("too many headers", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
				goto fail;
			}

			list[hdr].n = htx_get_blk_name(htx, blk);
			list[hdr].v = htx_get_blk_value(htx, blk);
			hdr++;
		}
		else {
			TRACE_ERROR("will not encode unexpected htx block", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_ERR, h2c->conn, h2s);
			goto fail;
		}
	}

	/* marker for end of trailers */
	list[hdr].n = ist("");

	mbuf = br_tail(h2c->mbuf);
 retry:
	if (!h2_get_buf(h2c, mbuf)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		TRACE_STATE("waiting for room in output buffer", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_BLK, h2c->conn, h2s);
		goto end;
	}

	chunk_reset(&outbuf);

	while (1) {
		outbuf = b_make(b_tail(mbuf), b_contig_space(mbuf), 0, 0);
		if (outbuf.size >= 9 || !b_space_wraps(mbuf))
			break;
	realign_again:
		b_slow_realign(mbuf, trash.area, b_data(mbuf));
	}

	if (outbuf.size < 9)
		goto full;

	/* len: 0x000000 (fill later), type: 1(HEADERS), flags: ENDH=4,ES=1 */
	memcpy(outbuf.area, "\x00\x00\x00\x01\x05", 5);
	write_n32(outbuf.area + 5, h2s->id); // 4 bytes
	outbuf.data = 9;

	/* encode all headers */
	for (idx = 0; idx < hdr; idx++) {
		/* these ones do not exist in H2 or must not appear in
		 * trailers and must be dropped.
		 */
		if (isteq(list[idx].n, ist("host")) ||
		    isteq(list[idx].n, ist("content-length")) ||
		    isteq(list[idx].n, ist("connection")) ||
		    isteq(list[idx].n, ist("proxy-connection")) ||
		    isteq(list[idx].n, ist("keep-alive")) ||
		    isteq(list[idx].n, ist("upgrade")) ||
		    isteq(list[idx].n, ist("te")) ||
		    isteq(list[idx].n, ist("transfer-encoding")))
			continue;

		/* Skip all pseudo-headers */
		if (*(list[idx].n.ptr) == ':')
			continue;

		if (!hpack_encode_header(&outbuf, list[idx].n, list[idx].v)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}
	}

	if (outbuf.data == 9) {
		/* here we have a problem, we have nothing to emit (either we
		 * received an empty trailers block followed or we removed its
		 * contents above). Because of this we can't send a HEADERS
		 * frame, so we have to cheat and instead send an empty DATA
		 * frame conveying the ES flag.
		 */
		outbuf.area[3] = H2_FT_DATA;
		outbuf.area[4] = H2_F_DATA_END_STREAM;
	}

	/* update the frame's size */
	h2_set_frame_size(outbuf.area, outbuf.data - 9);

	if (outbuf.data > h2c->mfs + 9) {
		if (!h2_fragment_headers(&outbuf, h2c->mfs)) {
			/* output full */
			if (b_space_wraps(mbuf))
				goto realign_again;
			goto full;
		}
	}

	/* commit the H2 response */
	TRACE_PROTO("sent H2 trailers HEADERS frame", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_TX_EOI, h2c->conn, h2s);
	b_add(mbuf, outbuf.data);
	h2s->flags |= H2_SF_ES_SENT;

	if (h2s->st == H2_SS_OPEN)
		h2s->st = H2_SS_HLOC;
	else
		h2s_close(h2s);

	/* OK we could properly deliver the response */
 done:
	/* remove all header blocks till the end and compute the corresponding size. */
	ret = 0;
	blk = htx_get_head_blk(htx);
	while (blk) {
		type = htx_get_blk_type(blk);
		ret += htx_get_blksz(blk);
		blk = htx_remove_blk(htx, blk);
		/* The removed block is the EOT */
		if (type == HTX_BLK_EOT)
			break;
	}

 end:
	TRACE_LEAVE(H2_EV_TX_FRAME|H2_EV_TX_HDR, h2c->conn, h2s);
	return ret;
 full:
	if ((mbuf = br_tail_add(h2c->mbuf)) != NULL)
		goto retry;
	h2c->flags |= H2_CF_MUX_MFULL;
	h2s->flags |= H2_SF_BLK_MROOM;
	ret = 0;
	TRACE_STATE("mux buffer full", H2_EV_TX_FRAME|H2_EV_TX_HDR|H2_EV_H2S_BLK, h2c->conn, h2s);
	goto end;
 fail:
	/* unparsable HTX messages, too large ones to be produced in the local
	 * list etc go here (unrecoverable errors).
	 */
	h2s_error(h2s, H2_ERR_INTERNAL_ERROR);
	ret = 0;
	goto end;
}

/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be a
 * combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0.
 */
static int h2_subscribe(struct conn_stream *cs, int event_type, struct wait_event *es)
{
	struct h2s *h2s = cs->ctx;
	struct h2c *h2c = h2s->h2c;

	TRACE_ENTER(H2_EV_STRM_SEND|H2_EV_STRM_RECV, h2c->conn, h2s);

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(h2s->subs && h2s->subs != es);

	es->events |= event_type;
	h2s->subs = es;

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("subscribe(recv)", H2_EV_STRM_RECV, h2c->conn, h2s);

	if (event_type & SUB_RETRY_SEND) {
		TRACE_DEVEL("subscribe(send)", H2_EV_STRM_SEND, h2c->conn, h2s);
		if (!(h2s->flags & H2_SF_BLK_SFCTL) &&
		    !LIST_INLIST(&h2s->list)) {
			if (h2s->flags & H2_SF_BLK_MFCTL)
				LIST_APPEND(&h2c->fctl_list, &h2s->list);
			else
				LIST_APPEND(&h2c->send_list, &h2s->list);
		}
	}
	TRACE_LEAVE(H2_EV_STRM_SEND|H2_EV_STRM_RECV, h2c->conn, h2s);
	return 0;
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int h2_unsubscribe(struct conn_stream *cs, int event_type, struct wait_event *es)
{
	struct h2s *h2s = cs->ctx;

	TRACE_ENTER(H2_EV_STRM_SEND|H2_EV_STRM_RECV, h2s->h2c->conn, h2s);

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(h2s->subs && h2s->subs != es);

	es->events &= ~event_type;
	if (!es->events)
		h2s->subs = NULL;

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("unsubscribe(recv)", H2_EV_STRM_RECV, h2s->h2c->conn, h2s);

	if (event_type & SUB_RETRY_SEND) {
		TRACE_DEVEL("subscribe(send)", H2_EV_STRM_SEND, h2s->h2c->conn, h2s);
		h2s->flags &= ~H2_SF_NOTIFIED;
		if (!(h2s->flags & (H2_SF_WANT_SHUTR | H2_SF_WANT_SHUTW)))
			LIST_DEL_INIT(&h2s->list);
	}

	TRACE_LEAVE(H2_EV_STRM_SEND|H2_EV_STRM_RECV, h2s->h2c->conn, h2s);
	return 0;
}


/* Called from the upper layer, to receive data
 *
 * The caller is responsible for defragmenting <buf> if necessary. But <flags>
 * must be tested to know the calling context. If CO_RFL_BUF_FLUSH is set, it
 * means the caller wants to flush input data (from the mux buffer and the
 * channel buffer) to be able to use kernel splicing or any kind of mux-to-mux
 * xfer. If CO_RFL_KEEP_RECV is set, the mux must always subscribe for read
 * events before giving back. CO_RFL_BUF_WET is set if <buf> is congested with
 * data scheduled for leaving soon. CO_RFL_BUF_NOT_STUCK is set to instruct the
 * mux it may optimize the data copy to <buf> if necessary. Otherwise, it should
 * copy as much data as possible.
 */
static size_t h2_rcv_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	struct h2s *h2s = cs->ctx;
	struct h2c *h2c = h2s->h2c;
	struct htx *h2s_htx = NULL;
	struct htx *buf_htx = NULL;
	size_t ret = 0;

	TRACE_ENTER(H2_EV_STRM_RECV, h2c->conn, h2s);

	/* transfer possibly pending data to the upper layer */
	h2s_htx = htx_from_buf(&h2s->rxbuf);
	if (htx_is_empty(h2s_htx)) {
		/* Here htx_to_buf() will set buffer data to 0 because
		 * the HTX is empty.
		 */
		htx_to_buf(h2s_htx, &h2s->rxbuf);
		goto end;
	}

	ret = h2s_htx->data;
	buf_htx = htx_from_buf(buf);

	/* <buf> is empty and the message is small enough, swap the
	 * buffers. */
	if (htx_is_empty(buf_htx) && htx_used_space(h2s_htx) <= count) {
		htx_to_buf(buf_htx, buf);
		htx_to_buf(h2s_htx, &h2s->rxbuf);
		b_xfer(buf, &h2s->rxbuf, b_data(&h2s->rxbuf));
		goto end;
	}

	htx_xfer_blks(buf_htx, h2s_htx, count, HTX_BLK_UNUSED);

	if (h2s_htx->flags & HTX_FL_PARSING_ERROR) {
		buf_htx->flags |= HTX_FL_PARSING_ERROR;
		if (htx_is_empty(buf_htx))
			cs->flags |= CS_FL_EOI;
	}
	else if (htx_is_empty(h2s_htx))
		buf_htx->flags |= (h2s_htx->flags & HTX_FL_EOM);

	buf_htx->extra = (h2s_htx->extra ? (h2s_htx->data + h2s_htx->extra) : 0);
	htx_to_buf(buf_htx, buf);
	htx_to_buf(h2s_htx, &h2s->rxbuf);
	ret -= h2s_htx->data;

  end:
	if (b_data(&h2s->rxbuf))
		cs->flags |= (CS_FL_RCV_MORE | CS_FL_WANT_ROOM);
	else {
		cs->flags &= ~(CS_FL_RCV_MORE | CS_FL_WANT_ROOM);
		if (h2s->flags & H2_SF_ES_RCVD) {
			cs->flags |= CS_FL_EOI;
			/* Add EOS flag for tunnel */
			if (h2s->flags & H2_SF_BODY_TUNNEL)
				cs->flags |= CS_FL_EOS;
		}
		if (h2c_read0_pending(h2c) || h2s->st == H2_SS_CLOSED)
			cs->flags |= CS_FL_EOS;
		if (cs->flags & CS_FL_ERR_PENDING)
			cs->flags |= CS_FL_ERROR;
		if (b_size(&h2s->rxbuf)) {
			b_free(&h2s->rxbuf);
			offer_buffers(NULL, 1);
		}
	}

	if (ret && h2c->dsi == h2s->id) {
		/* demux is blocking on this stream's buffer */
		h2c->flags &= ~H2_CF_DEM_SFULL;
		h2c_restart_reading(h2c, 1);
	}

	TRACE_LEAVE(H2_EV_STRM_RECV, h2c->conn, h2s);
	return ret;
}


/* Called from the upper layer, to send data from buffer <buf> for no more than
 * <count> bytes. Returns the number of bytes effectively sent. Some status
 * flags may be updated on the conn_stream.
 */
static size_t h2_snd_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	struct h2s *h2s = cs->ctx;
	size_t total = 0;
	size_t ret;
	struct htx *htx;
	struct htx_blk *blk;
	enum htx_blk_type btype;
	uint32_t bsize;
	int32_t idx;

	TRACE_ENTER(H2_EV_H2S_SEND|H2_EV_STRM_SEND, h2s->h2c->conn, h2s);

	/* If we were not just woken because we wanted to send but couldn't,
	 * and there's somebody else that is waiting to send, do nothing,
	 * we will subscribe later and be put at the end of the list
	 */
	if (!(h2s->flags & H2_SF_NOTIFIED) &&
	    (!LIST_ISEMPTY(&h2s->h2c->send_list) || !LIST_ISEMPTY(&h2s->h2c->fctl_list))) {
		TRACE_DEVEL("other streams already waiting, going to the queue and leaving", H2_EV_H2S_SEND|H2_EV_H2S_BLK, h2s->h2c->conn, h2s);
		return 0;
	}
	h2s->flags &= ~H2_SF_NOTIFIED;

	if (h2s->h2c->st0 < H2_CS_FRAME_H) {
		TRACE_DEVEL("connection not ready, leaving", H2_EV_H2S_SEND|H2_EV_H2S_BLK, h2s->h2c->conn, h2s);
		return 0;
	}

	if (h2s->h2c->st0 >= H2_CS_ERROR) {
		cs->flags |= CS_FL_ERROR;
		TRACE_DEVEL("connection is in error, leaving in error", H2_EV_H2S_SEND|H2_EV_H2S_BLK|H2_EV_H2S_ERR|H2_EV_STRM_ERR, h2s->h2c->conn, h2s);
		return 0;
	}

	htx = htx_from_buf(buf);

	if (!(h2s->flags & H2_SF_OUTGOING_DATA) && count)
		h2s->flags |= H2_SF_OUTGOING_DATA;

	if (h2s->id == 0) {
		int32_t id = h2c_get_next_sid(h2s->h2c);

		if (id < 0) {
			cs->flags |= CS_FL_ERROR;
			TRACE_DEVEL("couldn't get a stream ID, leaving in error", H2_EV_H2S_SEND|H2_EV_H2S_BLK|H2_EV_H2S_ERR|H2_EV_STRM_ERR, h2s->h2c->conn, h2s);
			return 0;
		}

		eb32_delete(&h2s->by_id);
		h2s->by_id.key = h2s->id = id;
		h2s->h2c->max_id = id;
		h2s->h2c->nb_reserved--;
		eb32_insert(&h2s->h2c->streams_by_id, &h2s->by_id);
	}

	while (h2s->st < H2_SS_HLOC && !(h2s->flags & H2_SF_BLK_ANY) &&
	       count && !htx_is_empty(htx)) {
		idx   = htx_get_head(htx);
		blk   = htx_get_blk(htx, idx);
		btype = htx_get_blk_type(blk);
		bsize = htx_get_blksz(blk);

		switch (btype) {
			case HTX_BLK_REQ_SL:
				/* start-line before headers */
				ret = h2s_bck_make_req_headers(h2s, htx);
				if (ret > 0) {
					total += ret;
					count -= ret;
					if (ret < bsize)
						goto done;
				}
				break;

			case HTX_BLK_RES_SL:
				/* start-line before headers */
				ret = h2s_frt_make_resp_headers(h2s, htx);
				if (ret > 0) {
					total += ret;
					count -= ret;
					if (ret < bsize)
						goto done;
				}
				break;

			case HTX_BLK_DATA:
				/* all these cause the emission of a DATA frame (possibly empty) */
				if (!(h2s->h2c->flags & H2_CF_IS_BACK) &&
				    (h2s->flags & (H2_SF_BODY_TUNNEL|H2_SF_BODYLESS_RESP)) == H2_SF_BODYLESS_RESP)
					ret = h2s_skip_data(h2s, buf, count);
				else
					ret = h2s_make_data(h2s, buf, count);
				if (ret > 0) {
					htx = htx_from_buf(buf);
					total += ret;
					count -= ret;
					if (ret < bsize)
						goto done;
				}
				break;

			case HTX_BLK_TLR:
			case HTX_BLK_EOT:
				/* This is the first trailers block, all the subsequent ones */
				ret = h2s_make_trailers(h2s, htx);
				if (ret > 0) {
					total += ret;
					count -= ret;
					if (ret < bsize)
						goto done;
				}
				break;

			default:
				htx_remove_blk(htx, blk);
				total += bsize;
				count -= bsize;
				break;
		}
	}

  done:
	if (h2s->st >= H2_SS_HLOC) {
		/* trim any possibly pending data after we close (extra CR-LF,
		 * unprocessed trailers, abnormal extra data, ...)
		 */
		total += count;
		count = 0;
	}

	/* RST are sent similarly to frame acks */
	if (h2s->st == H2_SS_ERROR || h2s->flags & H2_SF_RST_RCVD) {
		TRACE_DEVEL("reporting RST/error to the app-layer stream", H2_EV_H2S_SEND|H2_EV_H2S_ERR|H2_EV_STRM_ERR, h2s->h2c->conn, h2s);
		cs_set_error(cs);
		if (h2s_send_rst_stream(h2s->h2c, h2s) > 0)
			h2s_close(h2s);
	}

	htx_to_buf(htx, buf);

	if (total > 0) {
		if (!(h2s->h2c->wait_event.events & SUB_RETRY_SEND)) {
			TRACE_DEVEL("data queued, waking up h2c sender", H2_EV_H2S_SEND|H2_EV_H2C_SEND, h2s->h2c->conn, h2s);
			tasklet_wakeup(h2s->h2c->wait_event.tasklet);
		}

	}
	/* If we're waiting for flow control, and we got a shutr on the
	 * connection, we will never be unlocked, so add an error on
	 * the conn_stream.
	 */
	if (conn_xprt_read0_pending(h2s->h2c->conn) &&
	    !b_data(&h2s->h2c->dbuf) &&
	    (h2s->flags & (H2_SF_BLK_SFCTL | H2_SF_BLK_MFCTL))) {
		TRACE_DEVEL("fctl with shutr, reporting error to app-layer", H2_EV_H2S_SEND|H2_EV_STRM_SEND|H2_EV_STRM_ERR, h2s->h2c->conn, h2s);
		if (cs->flags & CS_FL_EOS)
			cs->flags |= CS_FL_ERROR;
		else
			cs->flags |= CS_FL_ERR_PENDING;
	}

	if (total > 0 && !(h2s->flags & H2_SF_BLK_SFCTL) &&
	    !(h2s->flags & (H2_SF_WANT_SHUTR|H2_SF_WANT_SHUTW))) {
		/* Ok we managed to send something, leave the send_list if we were still there */
		LIST_DEL_INIT(&h2s->list);
	}

	TRACE_LEAVE(H2_EV_H2S_SEND|H2_EV_STRM_SEND, h2s->h2c->conn, h2s);
	return total;
}

/* for debugging with CLI's "show fd" command */
static int h2_show_fd(struct buffer *msg, struct connection *conn)
{
	struct h2c *h2c = conn->ctx;
	struct h2s *h2s = NULL;
	struct eb32_node *node;
	int fctl_cnt = 0;
	int send_cnt = 0;
	int tree_cnt = 0;
	int orph_cnt = 0;
	struct buffer *hmbuf, *tmbuf;
	int ret = 0;

	if (!h2c)
		return ret;

	list_for_each_entry(h2s, &h2c->fctl_list, list)
		fctl_cnt++;

	list_for_each_entry(h2s, &h2c->send_list, list)
		send_cnt++;

	h2s = NULL;
	node = eb32_first(&h2c->streams_by_id);
	while (node) {
		h2s = container_of(node, struct h2s, by_id);
		tree_cnt++;
		if (!h2s->cs)
			orph_cnt++;
		node = eb32_next(node);
	}

	hmbuf = br_head(h2c->mbuf);
	tmbuf = br_tail(h2c->mbuf);
	chunk_appendf(msg, " h2c.st0=%s .err=%d .maxid=%d .lastid=%d .flg=0x%04x"
		      " .nbst=%u .nbcs=%u .fctl_cnt=%d .send_cnt=%d .tree_cnt=%d"
		      " .orph_cnt=%d .sub=%d .dsi=%d .dbuf=%u@%p+%u/%u .msi=%d"
		      " .mbuf=[%u..%u|%u],h=[%u@%p+%u/%u],t=[%u@%p+%u/%u]",
		      h2c_st_to_str(h2c->st0), h2c->errcode, h2c->max_id, h2c->last_sid, h2c->flags,
		      h2c->nb_streams, h2c->nb_cs, fctl_cnt, send_cnt, tree_cnt, orph_cnt,
		      h2c->wait_event.events, h2c->dsi,
		      (unsigned int)b_data(&h2c->dbuf), b_orig(&h2c->dbuf),
		      (unsigned int)b_head_ofs(&h2c->dbuf), (unsigned int)b_size(&h2c->dbuf),
		      h2c->msi,
		      br_head_idx(h2c->mbuf), br_tail_idx(h2c->mbuf), br_size(h2c->mbuf),
		      (unsigned int)b_data(hmbuf), b_orig(hmbuf),
		      (unsigned int)b_head_ofs(hmbuf), (unsigned int)b_size(hmbuf),
		      (unsigned int)b_data(tmbuf), b_orig(tmbuf),
		      (unsigned int)b_head_ofs(tmbuf), (unsigned int)b_size(tmbuf));

	if (h2s) {
		chunk_appendf(msg, " last_h2s=%p .id=%d .st=%s .flg=0x%04x .rxbuf=%u@%p+%u/%u .cs=%p",
			      h2s, h2s->id, h2s_st_to_str(h2s->st), h2s->flags,
			      (unsigned int)b_data(&h2s->rxbuf), b_orig(&h2s->rxbuf),
			      (unsigned int)b_head_ofs(&h2s->rxbuf), (unsigned int)b_size(&h2s->rxbuf),
			      h2s->cs);
		if (h2s->cs)
			chunk_appendf(msg, "(.flg=0x%08x .data=%p)",
				      h2s->cs->flags, h2s->cs->data);

		chunk_appendf(&trash, " .subs=%p", h2s->subs);
		if (h2s->subs) {
			chunk_appendf(&trash, "(ev=%d tl=%p", h2s->subs->events, h2s->subs->tasklet);
			chunk_appendf(&trash, " tl.calls=%d tl.ctx=%p tl.fct=",
				      h2s->subs->tasklet->calls,
				      h2s->subs->tasklet->context);
			if (h2s->subs->tasklet->calls >= 1000000)
				ret = 1;
			resolve_sym_name(&trash, NULL, h2s->subs->tasklet->process);
			chunk_appendf(&trash, ")");
		}
	}
	return ret;
}

/* Migrate the the connection to the current thread.
 * Return 0 if successful, non-zero otherwise.
 * Expected to be called with the old thread lock held.
 */
static int h2_takeover(struct connection *conn, int orig_tid)
{
	struct h2c *h2c = conn->ctx;
	struct task *task;

	if (fd_takeover(conn->handle.fd, conn) != 0)
		return -1;

	if (conn->xprt->takeover && conn->xprt->takeover(conn, conn->xprt_ctx, orig_tid) != 0) {
		/* We failed to takeover the xprt, even if the connection may
		 * still be valid, flag it as error'd, as we have already
		 * taken over the fd, and wake the tasklet, so that it will
		 * destroy it.
		 */
		conn->flags |= CO_FL_ERROR;
		tasklet_wakeup_on(h2c->wait_event.tasklet, orig_tid);
		return -1;
	}

	if (h2c->wait_event.events)
		h2c->conn->xprt->unsubscribe(h2c->conn, h2c->conn->xprt_ctx,
		    h2c->wait_event.events, &h2c->wait_event);
	/* To let the tasklet know it should free itself, and do nothing else,
	 * set its context to NULL.
	 */
	h2c->wait_event.tasklet->context = NULL;
	tasklet_wakeup_on(h2c->wait_event.tasklet, orig_tid);

	task = h2c->task;
	if (task) {
		task->context = NULL;
		h2c->task = NULL;
		__ha_barrier_store();
		task_kill(task);

		h2c->task = task_new_here();
		if (!h2c->task) {
			h2_release(h2c);
			return -1;
		}
		h2c->task->process = h2_timeout_task;
		h2c->task->context = h2c;
	}
	h2c->wait_event.tasklet = tasklet_new();
	if (!h2c->wait_event.tasklet) {
		h2_release(h2c);
		return -1;
	}
	h2c->wait_event.tasklet->process = h2_io_cb;
	h2c->wait_event.tasklet->context = h2c;
	h2c->conn->xprt->subscribe(h2c->conn, h2c->conn->xprt_ctx,
		                   SUB_RETRY_RECV, &h2c->wait_event);

	return 0;
}

/*******************************************************/
/* functions below are dedicated to the config parsers */
/*******************************************************/

/* config parser for global "tune.h2.header-table-size" */
static int h2_parse_header_table_size(char **args, int section_type, struct proxy *curpx,
                                      const struct proxy *defpx, const char *file, int line,
                                      char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	h2_settings_header_table_size = atoi(args[1]);
	if (h2_settings_header_table_size < 4096 || h2_settings_header_table_size > 65536) {
		memprintf(err, "'%s' expects a numeric value between 4096 and 65536.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.initial-window-size" */
static int h2_parse_initial_window_size(char **args, int section_type, struct proxy *curpx,
                                        const struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	h2_settings_initial_window_size = atoi(args[1]);
	if (h2_settings_initial_window_size < 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.max-concurrent-streams" */
static int h2_parse_max_concurrent_streams(char **args, int section_type, struct proxy *curpx,
                                           const struct proxy *defpx, const char *file, int line,
                                           char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	h2_settings_max_concurrent_streams = atoi(args[1]);
	if ((int)h2_settings_max_concurrent_streams < 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.max-frame-size" */
static int h2_parse_max_frame_size(char **args, int section_type, struct proxy *curpx,
                                   const struct proxy *defpx, const char *file, int line,
                                   char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	h2_settings_max_frame_size = atoi(args[1]);
	if (h2_settings_max_frame_size < 16384 || h2_settings_max_frame_size > 16777215) {
		memprintf(err, "'%s' expects a numeric value between 16384 and 16777215.", args[0]);
		return -1;
	}
	return 0;
}


/****************************************/
/* MUX initialization and instantiation */
/***************************************/

/* The mux operations */
static const struct mux_ops h2_ops = {
	.init = h2_init,
	.wake = h2_wake,
	.snd_buf = h2_snd_buf,
	.rcv_buf = h2_rcv_buf,
	.subscribe = h2_subscribe,
	.unsubscribe = h2_unsubscribe,
	.attach = h2_attach,
	.get_first_cs = h2_get_first_cs,
	.detach = h2_detach,
	.destroy = h2_destroy,
	.avail_streams = h2_avail_streams,
	.used_streams = h2_used_streams,
	.shutr = h2_shutr,
	.shutw = h2_shutw,
	.ctl = h2_ctl,
	.show_fd = h2_show_fd,
	.takeover = h2_takeover,
	.flags = MX_FL_CLEAN_ABRT|MX_FL_HTX|MX_FL_HOL_RISK|MX_FL_NO_UPG,
	.name = "H2",
};

static struct mux_proto_list mux_proto_h2 =
	{ .token = IST("h2"), .mode = PROTO_MODE_HTTP, .side = PROTO_SIDE_BOTH, .mux = &h2_ops };

INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_h2);

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.h2.header-table-size",      h2_parse_header_table_size      },
	{ CFG_GLOBAL, "tune.h2.initial-window-size",    h2_parse_initial_window_size    },
	{ CFG_GLOBAL, "tune.h2.max-concurrent-streams", h2_parse_max_concurrent_streams },
	{ CFG_GLOBAL, "tune.h2.max-frame-size",         h2_parse_max_frame_size         },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/* initialize internal structs after the config is parsed.
 * Returns zero on success, non-zero on error.
 */
static int init_h2()
{
	pool_head_hpack_tbl = create_pool("hpack_tbl",
	                                  h2_settings_header_table_size,
	                                  MEM_F_SHARED|MEM_F_EXACT);
	if (!pool_head_hpack_tbl) {
		ha_alert("failed to allocate hpack_tbl memory pool\n");
		return (ERR_ALERT | ERR_FATAL);
	}
	return ERR_NONE;
}

REGISTER_POST_CHECK(init_h2);
