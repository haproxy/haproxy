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
#include <common/net_helper.h>
#include <proto/applet.h>
#include <proto/connection.h>
#include <proto/h1.h>
#include <proto/stream.h>
#include <eb32tree.h>


/* dummy streams returned for idle and closed states */
static const struct h2s *h2_closed_stream;
static const struct h2s *h2_idle_stream;

/* the h2c connection pool */
static struct pool_head *pool2_h2c;
/* the h2s stream pool */
static struct pool_head *pool2_h2s;

/* Connection flags (32 bit), in h2c->flags */
#define H2_CF_NONE              0x00000000

/* Flags indicating why writing to the mux is blocked. */
#define H2_CF_MUX_MALLOC        0x00000001  // mux blocked on lack of connection's mux buffer
#define H2_CF_MUX_MFULL         0x00000002  // mux blocked on connection's mux buffer full
#define H2_CF_MUX_BLOCK_ANY     0x00000003  // aggregate of the mux flags above

/* Flags indicating why writing to the demux is blocked. */
#define H2_CF_DEM_DALLOC        0x00000004  // demux blocked on lack of connection's demux buffer
#define H2_CF_DEM_DFULL         0x00000008  // demux blocked on connection's demux buffer full
#define H2_CF_DEM_MBUSY         0x00000010  // demux blocked on connection's mux side busy
#define H2_CF_DEM_MROOM         0x00000020  // demux blocked on lack of room in mux buffer
#define H2_CF_DEM_SALLOC        0x00000040  // demux blocked on lack of stream's request buffer
#define H2_CF_DEM_SFULL         0x00000080  // demux blocked on stream request buffer full
#define H2_CF_DEM_BLOCK_ANY     0x000000FC  // aggregate of the demux flags above

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
	struct buffer_wait dbuf_wait; /* wait list for demux buffer allocation */
	struct buffer_wait mbuf_wait; /* wait list for mux buffer allocation */
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

/* stream flags indicating the reason the stream is blocked */
#define H2_SF_BLK_MBUSY         0x00000010 // blocked waiting for mux access (transient)
#define H2_SF_BLK_MROOM         0x00000020 // blocked waiting for room in the mux
#define H2_SF_BLK_MFCTL         0x00000040 // blocked due to mux fctl
#define H2_SF_BLK_SFCTL         0x00000080 // blocked due to stream fctl
#define H2_SF_BLK_ANY           0x000000F0 // any of the reasons above

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

/* descriptor for an h2 frame header */
struct h2_fh {
	uint32_t len;       /* length, host order, 24 bits */
	uint32_t sid;       /* stream id, host order, 31 bits */
	uint8_t ft;         /* frame type */
	uint8_t ff;         /* frame flags */
};

/* a few settings from the global section */
static int h2_settings_header_table_size      =  4096; /* initial value */
static int h2_settings_initial_window_size    = 65535; /* initial value */
static int h2_settings_max_concurrent_streams =   100;

/* a dmumy closed stream */
static const struct h2s *h2_closed_stream = &(const struct h2s){
	.cs        = NULL,
	.h2c       = NULL,
	.st        = H2_SS_CLOSED,
	.id        = 0,
};

/* and a dummy idle stream for use with any unannounced stream */
static const struct h2s *h2_idle_stream = &(const struct h2s){
	.cs        = NULL,
	.h2c       = NULL,
	.st        = H2_SS_IDLE,
	.id        = 0,
};


/*****************************************************/
/* functions below are for dynamic buffer management */
/*****************************************************/

/* re-enables receiving on mux <target> after a buffer was allocated. It returns
 * 1 if the allocation succeeds, in which case the connection is woken up, or 0
 * if it's impossible to wake up and we prefer to be woken up later.
 */
static int h2_dbuf_available(void *target)
{
	struct h2c *h2c = target;

	/* take the buffer now as we'll get scheduled waiting for ->wake() */
	if (b_alloc_margin(&h2c->dbuf, 0)) {
		h2c->flags &= ~H2_CF_DEM_DALLOC;
		if (!(h2c->flags & H2_CF_DEM_BLOCK_ANY))
			conn_xprt_want_recv(h2c->conn);
		return 1;
	}
	return 0;
}

static inline struct buffer *h2_get_dbuf(struct h2c *h2c)
{
	struct buffer *buf = NULL;

	if (likely(LIST_ISEMPTY(&h2c->dbuf_wait.list)) &&
	    unlikely((buf = b_alloc_margin(&h2c->dbuf, 0)) == NULL)) {
		h2c->dbuf_wait.target = h2c->conn;
		h2c->dbuf_wait.wakeup_cb = h2_dbuf_available;
		SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		LIST_ADDQ(&buffer_wq, &h2c->dbuf_wait.list);
		SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		__conn_xprt_stop_recv(h2c->conn);
	}
	return buf;
}

static inline void h2_release_dbuf(struct h2c *h2c)
{
	if (h2c->dbuf->size) {
		b_free(&h2c->dbuf);
		offer_buffers(h2c->dbuf_wait.target,
			      tasks_run_queue + applets_active_queue);
	}
}

/* re-enables sending on mux <target> after a buffer was allocated. It returns
 * 1 if the allocation succeeds, in which case the connection is woken up, or 0
 * if it's impossible to wake up and we prefer to be woken up later.
 */
static int h2_mbuf_available(void *target)
{
	struct h2c *h2c = target;

	/* take the buffer now as we'll get scheduled waiting for ->wake(). */
	if (b_alloc_margin(&h2c->mbuf, 0)) {
		if (h2c->flags & H2_CF_MUX_MALLOC) {
			h2c->flags &= ~H2_CF_MUX_MALLOC;
			if (!(h2c->flags & H2_CF_MUX_BLOCK_ANY))
				conn_xprt_want_send(h2c->conn);
		}

		if (h2c->flags & H2_CF_DEM_MROOM) {
			h2c->flags &= ~H2_CF_DEM_MROOM;
			if (!(h2c->flags & H2_CF_DEM_BLOCK_ANY))
				conn_xprt_want_recv(h2c->conn);
		}

		/* FIXME: we should in fact call something like h2_update_poll()
		 * now to recompte the polling. For now it will be enough like
		 * this.
		 */
		return 1;
	}
	return 0;
}

static inline struct buffer *h2_get_mbuf(struct h2c *h2c)
{
	struct buffer *buf = NULL;

	if (likely(LIST_ISEMPTY(&h2c->mbuf_wait.list)) &&
	    unlikely((buf = b_alloc_margin(&h2c->mbuf, 0)) == NULL)) {
		h2c->mbuf_wait.target = h2c;
		h2c->mbuf_wait.wakeup_cb = h2_mbuf_available;
		SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		LIST_ADDQ(&buffer_wq, &h2c->mbuf_wait.list);
		SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);

		/* FIXME: we should in fact only block the direction being
		 * currently used. For now it will be enough like this.
		 */
		__conn_xprt_stop_send(h2c->conn);
		__conn_xprt_stop_recv(h2c->conn);
	}
	return buf;
}

static inline void h2_release_mbuf(struct h2c *h2c)
{
	if (h2c->mbuf->size) {
		b_free(&h2c->mbuf);
		offer_buffers(h2c->mbuf_wait.target,
			      tasks_run_queue + applets_active_queue);
	}
}


/*****************************************************************/
/* functions below are dedicated to the mux setup and management */
/*****************************************************************/

/* tries to initialize the inbound h2c mux. Returns < 0 in case of failure. */
static int h2c_frt_init(struct connection *conn)
{
	struct h2c *h2c;

	h2c = pool_alloc2(pool2_h2c);
	if (!h2c)
		goto fail;

	h2c->ddht = hpack_dht_alloc(h2_settings_header_table_size);
	if (!h2c->ddht)
		goto fail;

	/* Initialise the context. */
	h2c->st0 = H2_CS_PREFACE;
	h2c->conn = conn;
	h2c->max_id = -1;
	h2c->errcode = H2_ERR_NO_ERROR;
	h2c->flags = H2_CF_NONE;
	h2c->rcvd_c = 0;
	h2c->rcvd_s = 0;

	h2c->dbuf = &buf_empty;
	h2c->dsi = -1;
	h2c->msi = -1;
	h2c->last_sid = -1;

	h2c->mbuf = &buf_empty;
	h2c->miw = 65535; /* mux initial window size */
	h2c->mws = 65535; /* mux window size */
	h2c->mfs = 16384; /* initial max frame size */
	h2c->streams_by_id = EB_ROOT_UNIQUE;
	LIST_INIT(&h2c->send_list);
	LIST_INIT(&h2c->fctl_list);
	LIST_INIT(&h2c->dbuf_wait.list);
	LIST_INIT(&h2c->mbuf_wait.list);
	conn->mux_ctx = h2c;

	conn_xprt_want_recv(conn);
	/* mux->wake will be called soon to complete the operation */
	return 0;
 fail:
	pool_free2(pool2_h2c, h2c);
	return -1;
}

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

	return h2c_frt_init(conn);
}

/* returns the stream associated with id <id> or NULL if not found */
static inline struct h2s *h2c_st_by_id(struct h2c *h2c, int id)
{
	struct eb32_node *node;

	if (id > h2c->max_id)
		return (struct h2s *)h2_idle_stream;

	node = eb32_lookup(&h2c->streams_by_id, id);
	if (!node)
		return (struct h2s *)h2_closed_stream;

	return container_of(node, struct h2s, by_id);
}

/* release function for a connection. This one should be called to free all
 * resources allocated to the mux.
 */
static void h2_release(struct connection *conn)
{
	struct h2c *h2c = conn->mux_ctx;

	LIST_DEL(&conn->list);

	if (h2c) {
		hpack_dht_free(h2c->ddht);
		h2_release_dbuf(h2c);
		SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		LIST_DEL(&h2c->dbuf_wait.list);
		SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);

		h2_release_mbuf(h2c);
		SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		LIST_DEL(&h2c->mbuf_wait.list);
		SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);

		pool_free2(pool2_h2c, h2c);
	}

	conn->mux = NULL;
	conn->mux_ctx = NULL;

	conn_stop_tracking(conn);
	conn_full_close(conn);
	if (conn->destroy_cb)
		conn->destroy_cb(conn);
	conn_free(conn);
}


/******************************************************/
/* functions below are for the H2 protocol processing */
/******************************************************/

/* returns the stream if of stream <h2s> or 0 if <h2s> is NULL */
static inline int h2s_id(const struct h2s *h2s)
{
	return h2s ? h2s->id : 0;
}

/* returns true of the mux is currently busy as seen from stream <h2s> */
static inline int h2c_mux_busy(const struct h2c *h2c, const struct h2s *h2s)
{
	if (h2c->msi < 0)
		return 0;

	if (h2c->msi == h2s_id(h2s))
		return 0;

	return 1;
}

/* marks an error on the connection */
static inline void h2c_error(struct h2c *h2c, enum h2_err err)
{
	h2c->errcode = err;
	h2c->st0 = H2_CS_ERROR;
}

/* marks an error on the stream */
static inline void h2s_error(struct h2s *h2s, enum h2_err err)
{
	if (h2s->st > H2_SS_IDLE && h2s->st < H2_SS_ERROR) {
		h2s->errcode = err;
		h2s->st = H2_SS_ERROR;
		if (h2s->cs)
			h2s->cs->flags |= CS_FL_ERROR;
	}
}

/* writes the 24-bit frame size <len> at address <frame> */
static inline void h2_set_frame_size(void *frame, uint32_t len)
{
	uint8_t *out = frame;

	*out = len >> 16;
	write_n16(out + 1, len);
}

/* reads <bytes> bytes from buffer <b> starting at relative offset <o> from the
 * current pointer, dealing with wrapping, and stores the result in <dst>. It's
 * the caller's responsibility to verify that there are at least <bytes> bytes
 * available in the buffer's input prior to calling this function.
 */
static inline void h2_get_buf_bytes(void *dst, size_t bytes,
                                    const struct buffer *b, int o)
{
	readv_bytes(dst, bytes, b_ptr(b, o), b_end(b) - b_ptr(b, o), b->data);
}

static inline uint16_t h2_get_n16(const struct buffer *b, int o)
{
	return readv_n16(b_ptr(b, o), b_end(b) - b_ptr(b, o), b->data);
}

static inline uint32_t h2_get_n32(const struct buffer *b, int o)
{
	return readv_n32(b_ptr(b, o), b_end(b) - b_ptr(b, o), b->data);
}

static inline uint64_t h2_get_n64(const struct buffer *b, int o)
{
	return readv_n64(b_ptr(b, o), b_end(b) - b_ptr(b, o), b->data);
}


/* Peeks an H2 frame header from buffer <b> into descriptor <h>. The algorithm
 * is not obvious. It turns out that H2 headers are neither aligned nor do they
 * use regular sizes. And to add to the trouble, the buffer may wrap so each
 * byte read must be checked. The header is formed like this :
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
 * Returns zero if some bytes are missing, otherwise non-zero on success.
 */
static int h2_peek_frame_hdr(const struct buffer *b, struct h2_fh *h)
{
	uint64_t w;

	if (b->i < 9)
		return 0;

	w = readv_n64(b_ptr(b,1), b_end(b) - b_ptr(b,1), b->data);
	h->len = *b->p << 16;
	h->sid = w & 0x7FFFFFFF; /* RFC7540#4.1: R bit must be ignored */
	h->ff = w >> 32;
	h->ft = w >> 40;
	h->len += w >> 48;
	return 1;
}

/* skip the next 9 bytes corresponding to the frame header possibly parsed by
 * h2_peek_frame_hdr() above.
 */
static inline void h2_skip_frame_hdr(struct buffer *b)
{
	bi_del(b, 9);
}

/* same as above, automatically advances the buffer on success */
static inline int h2_get_frame_hdr(struct buffer *b, struct h2_fh *h)
{
	int ret;

	ret = h2_peek_frame_hdr(b, h);
	if (ret > 0)
		h2_skip_frame_hdr(b);
	return ret;
}

/* creates a new stream <id> on the h2c connection and returns it, or NULL in
 * case of memory allocation error.
 */
static struct h2s *h2c_stream_new(struct h2c *h2c, int id)
{
	struct conn_stream *cs;
	struct h2s *h2s;

	h2s = pool_alloc2(pool2_h2s);
	if (!h2s)
		goto out;

	h2s->h2c       = h2c;
	h2s->mws       = h2c->miw;
	h2s->flags     = H2_SF_NONE;
	h2s->errcode   = H2_ERR_NO_ERROR;
	h2s->st        = H2_SS_IDLE;
	h1m_init(&h2s->req);
	h1m_init(&h2s->res);
	h2s->by_id.key = h2s->id = id;
	h2c->max_id    = id;
	LIST_INIT(&h2s->list);

	eb32_insert(&h2c->streams_by_id, &h2s->by_id);

	cs = cs_new(h2c->conn);
	if (!cs)
		goto out_close;

	h2s->cs = cs;
	cs->ctx = h2s;

	if (stream_create_from_cs(cs) < 0)
		goto out_free_cs;

	/* OK done, the stream lives its own life now */
	return h2s;

 out_free_cs:
	cs_free(cs);
 out_close:
	eb32_delete(&h2s->by_id);
	pool_free2(pool2_h2s, h2s);
	h2s = NULL;
 out:
	return h2s;
}


/*********************************************************/
/* functions below are I/O callbacks from the connection */
/*********************************************************/

/* callback called on recv event by the connection handler */
static void h2_recv(struct connection *conn)
{
	struct h2c *h2c = conn->mux_ctx;
	struct buffer *buf;
	int max;

	if (conn->flags & CO_FL_ERROR)
		return;

	if (h2c->flags & H2_CF_DEM_BLOCK_ANY)
		return;

	buf = h2_get_dbuf(h2c);
	if (!buf) {
		h2c->flags |= H2_CF_DEM_DALLOC;
		return;
	}

	/* note: buf->o == 0 */
	max = buf->size - buf->i;
	if (!max) {
		h2c->flags |= H2_CF_DEM_DFULL;
		return;
	}

	conn->xprt->rcv_buf(conn, buf, max);
	if (conn->flags & CO_FL_ERROR)
		return;

	if (!buf->i) {
		h2_release_dbuf(h2c);
		return;
	}

	if (buf->i == buf->size)
		h2c->flags |= H2_CF_DEM_DFULL;

	/* FIXME: should we try to process streams here instead of doing it in ->wake ? */

	/* after streams have been processed, we should have made some room */
	if (buf->i != buf->size)
		h2c->flags &= ~H2_CF_DEM_DFULL;
	return;
}

/* callback called on send event by the connection handler */
static void h2_send(struct connection *conn)
{
	struct h2c *h2c = conn->mux_ctx;

	/* FIXME: should we try to process pending streams here instead of doing it in ->wake ? */

	if (conn->flags & CO_FL_ERROR)
		return;

	if (conn->flags & (CO_FL_HANDSHAKE|CO_FL_WAIT_L4_CONN|CO_FL_WAIT_L6_CONN)) {
		/* a handshake was requested */
		return;
	}

	if (conn->flags & CO_FL_SOCK_WR_SH) {
		/* output closed, nothing to send, clear the buffer to release it */
		h2c->mbuf->o = 0;
	}

	/* pending response data, we need to try to send or subscribe to
	 * writes. The snd_buf() function takes a "flags" argument which
	 * may be made of a combination of CO_SFL_MSG_MORE to indicate
	 * that more data immediately comes and CO_SFL_STREAMER to
	 * indicate that the connection is streaming lots of data (used
	 * to increase TLS record size at the expense of latency). The
	 * former could be sent any time there's a buffer full flag, as
	 * it indicates at least one stream attempted to send and failed
	 * so there are pending data. And alternative would be to set it
	 * as long as there's an active stream but that would be
	 * problematic for ACKs. The latter should possibly not be set
	 * for now.
	 */
	if (conn->xprt->snd_buf(conn, h2c->mbuf, 0) > 0)
		h2c->flags &= ~(H2_CF_MUX_MFULL | H2_CF_DEM_MROOM);

	if (conn->flags & CO_FL_ERROR)
		return;
}

/* call the wake up function of all streams attached to the connection */
static void h2_wake_all_streams(struct h2c *h2c)
{
	struct eb32_node *node;
	struct h2s *h2s;
	unsigned int flags = 0;

	if (h2c->st0 >= H2_CS_ERROR || h2c->conn->flags & CO_FL_ERROR)
		flags |= CS_FL_ERROR;

	if (conn_xprt_read0_pending(h2c->conn))
		flags |= CS_FL_EOS;

	node = eb32_first(&h2c->streams_by_id);
	while (node) {
		h2s = container_of(node, struct h2s, by_id);
		node = eb32_next(node);
		if (h2s->cs) {
			h2s->cs->flags |= flags;
			/* recv is used to force to detect CS_FL_EOS that wake()
			 * doesn't handle in the stream int code.
			 */
			h2s->cs->data_cb->recv(h2s->cs);
			h2s->cs->data_cb->wake(h2s->cs);
		}
	}
}

/* callback called on any event by the connection handler.
 * It applies changes and returns zero, or < 0 if it wants immediate
 * destruction of the connection (which normally doesn not happen in h2).
 */
static int h2_wake(struct connection *conn)
{
	struct h2c *h2c = conn->mux_ctx;

	if (conn->flags & CO_FL_ERROR || conn_xprt_read0_pending(conn) ||
	    h2c->st0 == H2_CS_ERROR2) {
		h2_wake_all_streams(h2c);

		if (eb_is_empty(&h2c->streams_by_id)) {
			/* no more stream, kill the connection now */
			h2_release(conn);
			return -1;
		}
		else {
			/* some streams still there, we need to signal them all and
			 * wait for their departure.
			 */
			__conn_xprt_stop_recv(conn);
			__conn_xprt_stop_send(conn);
			return 0;
		}
	}

	if (!h2c->dbuf->i)
		h2_release_dbuf(h2c);

	/* stop being notified of incoming data if we can't process them */
	if (h2c->st0 >= H2_CS_ERROR ||
	    (h2c->flags & H2_CF_DEM_BLOCK_ANY) || conn_xprt_read0_pending(conn)) {
		/* FIXME: we should clear a read timeout here */
		__conn_xprt_stop_recv(conn);
	}
	else {
		/* FIXME: we should (re-)arm a read timeout here */
		__conn_xprt_want_recv(conn);
	}

	/* adjust output polling */
	if ((h2c->st0 == H2_CS_ERROR || h2c->mbuf->o) &&
	    !(conn->flags & CO_FL_SOCK_WR_SH)) {
		/* FIXME: we should (re-)arm a send timeout here */
		__conn_xprt_want_send(conn);
	}
	else {
		/* FIXME: we should clear a send timeout here */
		h2_release_mbuf(h2c);
		__conn_xprt_stop_send(conn);
	}

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
