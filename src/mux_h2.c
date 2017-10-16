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

#include <common/cfgparse.h>
#include <common/config.h>
#include <common/h2.h>
#include <common/hpack-tbl.h>
#include <proto/connection.h>
#include <proto/stream.h>
#include <eb32tree.h>


/* the h2c connection pool */
static struct pool_head *pool2_h2c;
/* the h2s stream pool */
static struct pool_head *pool2_h2s;

/* Connection flags (32 bit), in h2c->flags */
#define H2_CF_NONE              0x00000000

/* H2 connection state, in h2c->st0 */
enum h2_cs {
	H2_CS_PREFACE,   // init done, waiting for connection preface
	H2_CS_SETTINGS1, // preface OK, waiting for first settings frame
	H2_CS_FRAME_H,   // first settings frame ok, waiting for frame header
	H2_CS_FRAME_P,   // frame header OK, waiting for frame payload
	H2_CS_FRAME_A,   // frame payload OK, trying to send ACK/RST frame
	H2_CS_ERROR,     // send GOAWAY(errcode) and close the connection ASAP
	H2_CS_ERROR2,    // GOAWAY(errcode) sent, close the connection ASAP
	H2_CS_ENTRIES    // must be last
} __attribute__((packed));

/* H2 connection descriptor */
struct h2c {
	struct connection *conn;

	enum h2_cs st0; /* mux state */
	enum h2_err errcode; /* H2 err code (H2_ERR_*) */

	/* 16 bit hole here */
	uint32_t flags; /* connection flags: H2_CF_* */
	int32_t max_id; /* highest ID known on this connection, <0 before preface */
	uint32_t rcvd_c; /* newly received data to ACK for the connection */
	uint32_t rcvd_s; /* newly received data to ACK for the current stream (dsi) */

	/* states for the demux direction */
	struct hpack_dht *ddht; /* demux dynamic header table */
	struct buffer *dbuf;    /* demux buffer */

	int32_t dsi; /* demux stream ID (<0 = idle) */
	int32_t dfl; /* demux frame length (if dsi >= 0) */
	int8_t  dft; /* demux frame type   (if dsi >= 0) */
	int8_t  dff; /* demux frame flags  (if dsi >= 0) */
	/* 16 bit hole here */
	int32_t last_sid; /* last processed stream ID for GOAWAY, <0 before preface */

	/* states for the mux direction */
	struct buffer *mbuf;    /* mux buffer */
	int32_t msi; /* mux stream ID (<0 = idle) */
	int32_t mfl; /* mux frame length (if dsi >= 0) */
	int8_t  mft; /* mux frame type   (if dsi >= 0) */
	int8_t  mff; /* mux frame flags  (if dsi >= 0) */
	/* 16 bit hole here */
	int32_t miw; /* mux initial window size for all new streams */
	int32_t mws; /* mux window size. Can be negative. */
	int32_t mfs; /* mux's max frame size */

	struct eb_root streams_by_id; /* all active streams by their ID */
	struct list send_list; /* list of blocked streams requesting to send */
	struct list fctl_list; /* list of streams blocked by connection's fctl */
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
	H2_SS_RESET,    // closed after sending RST_STREAM
	H2_SS_CLOSED,   // closed
	H2_SS_ENTRIES   // must be last
} __attribute__((packed));

/* HTTP/2 stream flags (32 bit), in h2s->flags */
#define H2_SF_NONE              0x00000000
#define H2_SF_ES_RCVD           0x00000001
#define H2_SF_ES_SENT           0x00000002

#define H2_SF_RST_RCVD          0x00000004 // received RST_STREAM
#define H2_SF_RST_SENT          0x00000008 // sent RST_STREAM

/* H2 stream descriptor, describing the stream as it appears in the H2C, and as
 * it is being processed in the internal HTTP representation (H1 for now).
 */
struct h2s {
	struct conn_stream *cs;
	struct h2c *h2c;
	struct h1m req, res;      /* request and response parser state for H1 */
	struct eb32_node by_id; /* place in h2c's streams_by_id */
	struct list list; /* position in active/blocked lists if blocked>0 */
	int32_t id; /* stream ID */
	uint32_t flags;      /* H2_SF_* */
	int mws;             /* mux window size for this stream */
	enum h2_err errcode; /* H2 err code (H2_ERR_*) */
	enum h2_ss st;
};

/* a few settings from the global section */
static int h2_settings_header_table_size      =  4096; /* initial value */
static int h2_settings_initial_window_size    = 65535; /* initial value */
static int h2_settings_max_concurrent_streams =   100;


/*****************************************************************/
/* functions below are dedicated to the mux setup and management */
/*****************************************************************/

/* Initialize the mux once it's attached. For outgoing connections, the context
 * is already initialized before installing the mux, so we detect incoming
 * connections from the fact that the context is still NULL. Returns < 0 on
 * error.
 */
static int h2_init(struct connection *conn)
{
	if (conn->mux_ctx) {
		/* we don't support outgoing connections for now */
		return -1;
	}

	/* not implemented yet */
	return -1;
}

/* release function for a connection. This one should be called to free all
 * resources allocated to the mux.
 */
static void h2_release(struct connection *conn)
{
}


/*********************************************************/
/* functions below are I/O callbacks from the connection */
/*********************************************************/

/* callback called on recv event by the connection handler */
static void h2_recv(struct connection *conn)
{
}

/* callback called on send event by the connection handler */
static void h2_send(struct connection *conn)
{
}

/* callback called on any event by the connection handler.
 * It applies changes and returns zero, or < 0 if it wants immediate
 * destruction of the connection (which normally doesn not happen in h2).
 */
static int h2_wake(struct connection *conn)
{
	return 0;
}

/*******************************************/
/* functions below are used by the streams */
/*******************************************/

/*
 * Attach a new stream to a connection
 * (Used for outgoing connections)
 */
static struct conn_stream *h2_attach(struct connection *conn)
{
	return NULL;
}

/* callback used to update the mux's polling flags after changing a cs' status.
 * The caller (cs_update_mux_polling) will take care of propagating any changes
 * to the transport layer.
 */
static void h2_update_poll(struct conn_stream *cs)
{
}

/*
 * Detach the stream from the connection and possibly release the connection.
 */
static void h2_detach(struct conn_stream *cs)
{
}

static void h2_shutr(struct conn_stream *cs, enum cs_shr_mode mode)
{
}

static void h2_shutw(struct conn_stream *cs, enum cs_shw_mode mode)
{
}

/*
 * Called from the upper layer, to get more data
 */
static int h2_rcv_buf(struct conn_stream *cs, struct buffer *buf, int count)
{
	/* FIXME: not handled for now */
	cs->flags |= CS_FL_ERROR;
	return 0;
}

/* Called from the upper layer, to send data */
static int h2_snd_buf(struct conn_stream *cs, struct buffer *buf, int flags)
{
	/* FIXME: not handled for now */
	cs->flags |= CS_FL_ERROR;
	return 0;
}


/*******************************************************/
/* functions below are dedicated to the config parsers */
/*******************************************************/

/* config parser for global "tune.h2.header-table-size" */
static int h2_parse_header_table_size(char **args, int section_type, struct proxy *curpx,
                                      struct proxy *defpx, const char *file, int line,
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
                                        struct proxy *defpx, const char *file, int line,
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
                                           struct proxy *defpx, const char *file, int line,
                                           char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	h2_settings_max_concurrent_streams = atoi(args[1]);
	if (h2_settings_max_concurrent_streams < 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	return 0;
}


/****************************************/
/* MUX initialization and instanciation */
/***************************************/

/* The mux operations */
const struct mux_ops h2_ops = {
	.init = h2_init,
	.recv = h2_recv,
	.send = h2_send,
	.wake = h2_wake,
	.update_poll = h2_update_poll,
	.rcv_buf = h2_rcv_buf,
	.snd_buf = h2_snd_buf,
	.attach = h2_attach,
	.detach = h2_detach,
	.shutr = h2_shutr,
	.shutw = h2_shutw,
	.release = h2_release,
	.name = "H2",
};

/* ALPN selection : this mux registers ALPN tolen "h2" */
static struct alpn_mux_list alpn_mux_h2 =
	{ .token = IST("h2"), .mode = ALPN_MODE_HTTP, .mux = &h2_ops };

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.h2.header-table-size",      h2_parse_header_table_size      },
	{ CFG_GLOBAL, "tune.h2.initial-window-size",    h2_parse_initial_window_size    },
	{ CFG_GLOBAL, "tune.h2.max-concurrent-streams", h2_parse_max_concurrent_streams },
	{ 0, NULL, NULL }
}};

static void __h2_deinit(void)
{
	pool_destroy2(pool2_h2s);
	pool_destroy2(pool2_h2c);
}

__attribute__((constructor))
static void __h2_init(void)
{
	alpn_register_mux(&alpn_mux_h2);
	cfg_register_keywords(&cfg_kws);
	hap_register_post_deinit(__h2_deinit);
	pool2_h2c = create_pool("h2c", sizeof(struct h2c), MEM_F_SHARED);
	pool2_h2s = create_pool("h2s", sizeof(struct h2s), MEM_F_SHARED);
}
