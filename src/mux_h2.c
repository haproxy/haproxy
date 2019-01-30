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
#include <common/h1.h>
#include <common/h2.h>
#include <common/hpack-dec.h>
#include <common/hpack-enc.h>
#include <common/hpack-tbl.h>
#include <common/htx.h>
#include <common/initcall.h>
#include <common/net_helper.h>
#include <proto/connection.h>
#include <proto/http_htx.h>
#include <proto/session.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <types/session.h>
#include <eb32tree.h>


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

/* other flags */
#define H2_CF_GOAWAY_SENT       0x00001000  // a GOAWAY frame was successfully sent
#define H2_CF_GOAWAY_FAILED     0x00002000  // a GOAWAY frame failed to be sent
#define H2_CF_WAIT_FOR_HS       0x00004000  // We did check that at least a stream was waiting for handshake
#define H2_CF_IS_BACK           0x00008000  // this is an outgoing connection
#define H2_CF_WINDOW_OPENED     0x00010000 // demux increased window already advertised

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
	struct buffer dbuf;    /* demux buffer */

	int32_t dsi; /* demux stream ID (<0 = idle) */
	int32_t dfl; /* demux frame length (if dsi >= 0) */
	int8_t  dft; /* demux frame type   (if dsi >= 0) */
	int8_t  dff; /* demux frame flags  (if dsi >= 0) */
	uint8_t dpl; /* demux pad length (part of dfl), init to 0 */
	/* 8 bit hole here */
	int32_t last_sid; /* last processed stream ID for GOAWAY, <0 before preface */

	/* states for the mux direction */
	struct buffer mbuf;    /* mux buffer */
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
	struct eb_root streams_by_id; /* all active streams by their ID */
	struct list send_list; /* list of blocked streams requesting to send */
	struct list fctl_list; /* list of streams blocked by connection's fctl */
	struct list sending_list; /* list of h2s scheduled to send data */
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

/* stream flags indicating how data is supposed to be sent */
#define H2_SF_DATA_CLEN         0x00000100 // data sent using content-length
#define H2_SF_DATA_CHNK         0x00000200 // data sent using chunked-encoding

/* step we're currently in when sending chunks. This is needed because we may
 * have to transfer chunks as large as a full buffer so there's no room left
 * for size nor crlf around.
 */
#define H2_SF_CHNK_SIZE         0x00000000 // trying to send chunk size
#define H2_SF_CHNK_DATA         0x00000400 // trying to send chunk data
#define H2_SF_CHNK_CRLF         0x00000800 // trying to send chunk crlf after data

#define H2_SF_CHNK_MASK         0x00000C00 // trying to send chunk size

#define H2_SF_HEADERS_SENT      0x00001000  // a HEADERS frame was sent for this stream
#define H2_SF_OUTGOING_DATA     0x00002000  // set whenever we've seen outgoing data

#define H2_SF_HEADERS_RCVD      0x00004000  // a HEADERS frame was received for this stream

/* H2 stream descriptor, describing the stream as it appears in the H2C, and as
 * it is being processed in the internal HTTP representation (H1 for now).
 */
struct h2s {
	struct conn_stream *cs;
	struct session *sess;
	struct h2c *h2c;
	struct h1m h1m;         /* request or response parser state for H1 */
	struct eb32_node by_id; /* place in h2c's streams_by_id */
	int32_t id; /* stream ID */
	uint32_t flags;      /* H2_SF_* */
	int mws;             /* mux window size for this stream */
	enum h2_err errcode; /* H2 err code (H2_ERR_*) */
	enum h2_ss st;
	uint16_t status;     /* HTTP response status */
	unsigned long long body_len; /* remaining body length according to content-length if H2_SF_DATA_CLEN */
	struct buffer rxbuf; /* receive buffer, always valid (buf_empty or real buffer) */
	struct wait_event wait_event; /* Wait list, when we're attempting to send a RST but we can't send */
	struct wait_event *recv_wait; /* Address of the wait_event the conn_stream associated is waiting on */
	struct wait_event *send_wait; /* The streeam is waiting for flow control */
	struct list list; /* To be used when adding in h2c->send_list or h2c->fctl_lsit */
};

/* descriptor for an h2 frame header */
struct h2_fh {
	uint32_t len;       /* length, host order, 24 bits */
	uint32_t sid;       /* stream id, host order, 31 bits */
	uint8_t ft;         /* frame type */
	uint8_t ff;         /* frame flags */
};

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

/* a few settings from the global section */
static int h2_settings_header_table_size      =  4096; /* initial value */
static int h2_settings_initial_window_size    = 65535; /* initial value */
static int h2_settings_max_concurrent_streams =   100;

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

static struct task *h2_timeout_task(struct task *t, void *context, unsigned short state);
static int h2_send(struct h2c *h2c);
static int h2_recv(struct h2c *h2c);
static int h2_process(struct h2c *h2c);
static struct task *h2_io_cb(struct task *t, void *ctx, unsigned short state);
static inline struct h2s *h2c_st_by_id(struct h2c *h2c, int id);
static int h2c_decode_headers(struct h2c *h2c, struct buffer *rxbuf, uint32_t *flags, unsigned long long *body_len);
static int h2_frt_transfer_data(struct h2s *h2s);
static struct task *h2_deferred_shut(struct task *t, void *ctx, unsigned short state);
static struct h2s *h2c_bck_stream_new(struct h2c *h2c, struct conn_stream *cs, struct session *sess);
static void h2s_alert(struct h2s *h2s);

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
static inline void h2c_restart_reading(const struct h2c *h2c)
{
	if (!h2_recv_allowed(h2c))
		return;
	if (!b_data(&h2c->dbuf) && (h2c->wait_event.events & SUB_RETRY_RECV))
		return;
	tasklet_wakeup(h2c->wait_event.task);
}


/* returns true if the connection has too many conn_streams attached */
static inline int h2_has_too_many_cs(const struct h2c *h2c)
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

	if ((h2c->flags & H2_CF_DEM_DALLOC) && b_alloc_margin(&h2c->dbuf, 0)) {
		h2c->flags &= ~H2_CF_DEM_DALLOC;
		h2c_restart_reading(h2c);
		return 1;
	}

	if ((h2c->flags & H2_CF_MUX_MALLOC) && b_alloc_margin(&h2c->mbuf, 0)) {
		h2c->flags &= ~H2_CF_MUX_MALLOC;

		if (h2c->flags & H2_CF_DEM_MROOM) {
			h2c->flags &= ~H2_CF_DEM_MROOM;
			h2c_restart_reading(h2c);
		}
		return 1;
	}

	if ((h2c->flags & H2_CF_DEM_SALLOC) &&
	    (h2s = h2c_st_by_id(h2c, h2c->dsi)) && h2s->cs &&
	    b_alloc_margin(&h2s->rxbuf, 0)) {
		h2c->flags &= ~H2_CF_DEM_SALLOC;
		h2c_restart_reading(h2c);
		return 1;
	}

	return 0;
}

static inline struct buffer *h2_get_buf(struct h2c *h2c, struct buffer *bptr)
{
	struct buffer *buf = NULL;

	if (likely(LIST_ISEMPTY(&h2c->buf_wait.list)) &&
	    unlikely((buf = b_alloc_margin(bptr, 0)) == NULL)) {
		h2c->buf_wait.target = h2c;
		h2c->buf_wait.wakeup_cb = h2_buf_available;
		HA_SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		LIST_ADDQ(&buffer_wq, &h2c->buf_wait.list);
		HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		__conn_xprt_stop_recv(h2c->conn);
	}
	return buf;
}

static inline void h2_release_buf(struct h2c *h2c, struct buffer *bptr)
{
	if (bptr->size) {
		b_free(bptr);
		offer_buffers(h2c->buf_wait.target, tasks_run_queue);
	}
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

	/* XXX Should use the negociated max concurrent stream nb instead of the conf value */
	ret1 = h2_settings_max_concurrent_streams - h2c->nb_streams;

	/* we must also consider the limit imposed by stream IDs */
	ret2 = h2_streams_left(h2c);
	ret1 = MIN(ret1, ret2);
	if (ret1 && srv && srv->max_reuse >= 0) {
		ret2 = h2c->stream_cnt <= srv->max_reuse ? srv->max_reuse - h2c->stream_cnt + 1: 0;
		ret1 = MIN(ret1, ret2);
	}
	return ret1;
}

static int h2_max_streams(struct connection *conn)
{
	/* XXX Should use the negociated max concurrent stream nb instead of the conf value */
	return h2_settings_max_concurrent_streams;
}


/*****************************************************************/
/* functions below are dedicated to the mux setup and management */
/*****************************************************************/

/* Initialize the mux once it's attached. For outgoing connections, the context
 * is already initialized before installing the mux, so we detect incoming
 * connections from the fact that the context is still NULL. Returns < 0 on
 * error.
 */
static int h2_init(struct connection *conn, struct proxy *prx, struct session *sess)
{
	struct h2c *h2c;
	struct task *t = NULL;

	h2c = pool_alloc(pool_head_h2c);
	if (!h2c)
		goto fail_no_h2c;

	if (conn->ctx) {
		h2c->flags = H2_CF_IS_BACK;
		h2c->shut_timeout = h2c->timeout = prx->timeout.server;
		if (tick_isset(prx->timeout.serverfin))
			h2c->shut_timeout = prx->timeout.serverfin;
	} else {
		h2c->flags = H2_CF_NONE;
		h2c->shut_timeout = h2c->timeout = prx->timeout.client;
		if (tick_isset(prx->timeout.clientfin))
			h2c->shut_timeout = prx->timeout.clientfin;
	}

	h2c->proxy = prx;
	h2c->task = NULL;
	if (tick_isset(h2c->timeout)) {
		t = task_new(tid_bit);
		if (!t)
			goto fail;

		h2c->task = t;
		t->process = h2_timeout_task;
		t->context = h2c;
		t->expire = tick_add(now_ms, h2c->timeout);
	}

	h2c->wait_event.task = tasklet_new();
	if (!h2c->wait_event.task)
		goto fail;
	h2c->wait_event.task->process = h2_io_cb;
	h2c->wait_event.task->context = h2c;
	h2c->wait_event.events = 0;

	h2c->ddht = hpack_dht_alloc(h2_settings_header_table_size);
	if (!h2c->ddht)
		goto fail;

	/* Initialise the context. */
	h2c->st0 = H2_CS_PREFACE;
	h2c->conn = conn;
	h2c->max_id = -1;
	h2c->errcode = H2_ERR_NO_ERROR;
	h2c->rcvd_c = 0;
	h2c->rcvd_s = 0;
	h2c->nb_streams = 0;
	h2c->nb_cs = 0;
	h2c->nb_reserved = 0;
	h2c->stream_cnt = 0;

	h2c->dbuf = BUF_NULL;
	h2c->dsi = -1;
	h2c->msi = -1;

	h2c->last_sid = -1;

	h2c->mbuf = BUF_NULL;
	h2c->miw = 65535; /* mux initial window size */
	h2c->mws = 65535; /* mux window size */
	h2c->mfs = 16384; /* initial max frame size */
	h2c->streams_by_id = EB_ROOT;
	LIST_INIT(&h2c->send_list);
	LIST_INIT(&h2c->fctl_list);
	LIST_INIT(&h2c->sending_list);
	LIST_INIT(&h2c->buf_wait.list);

	if (t)
		task_queue(t);

	if (h2c->flags & H2_CF_IS_BACK) {
		/* FIXME: this is temporary, for outgoing connections we need
		 * to immediately allocate a stream until the code is modified
		 * so that the caller calls ->attach(). For now the outgoing cs
		 * is stored as conn->ctx by the caller.
		 */
		struct h2s *h2s;

		h2s = h2c_bck_stream_new(h2c, conn->ctx, sess);
		if (!h2s)
			goto fail_stream;
	}

	conn->ctx = h2c;

	/* prepare to read something */
	h2c_restart_reading(h2c);
	return 0;
  fail_stream:
	hpack_dht_free(h2c->ddht);
  fail:
	if (t)
		task_free(t);
	if (h2c->wait_event.task)
		tasklet_free(h2c->wait_event.task);
	pool_free(pool_head_h2c, h2c);
  fail_no_h2c:
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

/* release function for a connection. This one should be called to free all
 * resources allocated to the mux.
 */
static void h2_release(struct connection *conn)
{
	struct h2c *h2c = conn->ctx;

	LIST_DEL(&conn->list);

	if (h2c) {
		hpack_dht_free(h2c->ddht);

		HA_SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		LIST_DEL(&h2c->buf_wait.list);
		HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);

		h2_release_buf(h2c, &h2c->dbuf);
		h2_release_buf(h2c, &h2c->mbuf);

		if (h2c->task) {
			h2c->task->context = NULL;
			task_wakeup(h2c->task, TASK_WOKEN_OTHER);
			h2c->task = NULL;
		}
		if (h2c->wait_event.task)
			tasklet_free(h2c->wait_event.task);
		if (h2c->wait_event.events != 0)
			conn->xprt->unsubscribe(conn, h2c->wait_event.events,
			    &h2c->wait_event);

		pool_free(pool_head_h2c, h2c);
	}

	conn->mux = NULL;
	conn->ctx = NULL;

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
static inline __maybe_unused int h2s_id(const struct h2s *h2s)
{
	return h2s ? h2s->id : 0;
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
	h2c->errcode = err;
	h2c->st0 = H2_CS_ERROR;
}

/* marks an error on the stream. It may also update an already closed stream
 * (e.g. to report an error after an RST was received).
 */
static inline __maybe_unused void h2s_error(struct h2s *h2s, enum h2_err err)
{
	if (h2s->id && h2s->st != H2_SS_ERROR) {
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
	struct wait_event *sw;

	if (h2s->recv_wait) {
		sw = h2s->recv_wait;
		sw->events &= ~SUB_RETRY_RECV;
		tasklet_wakeup(sw->task);
		h2s->recv_wait = NULL;
	}
}

/* attempt to notify the data layer of send availability */
static void __maybe_unused h2s_notify_send(struct h2s *h2s)
{
	struct wait_event *sw;

	if (h2s->send_wait) {
		sw = h2s->send_wait;
		sw->events &= ~SUB_RETRY_SEND;
		tasklet_wakeup(sw->task);
		h2s->send_wait = NULL;
		LIST_DEL(&h2s->list);
		LIST_INIT(&h2s->list);
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
	if (h2s->recv_wait || h2s->send_wait) {
		h2s_notify_recv(h2s);
		h2s_notify_send(h2s);
	}
	else if (h2s->cs && h2s->cs->data_cb->wake != NULL)
		h2s->cs->data_cb->wake(h2s->cs);
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

/* marks stream <h2s> as CLOSED and decrement the number of active streams for
 * its connection if the stream was not yet closed. Please use this exclusively
 * before closing a stream to ensure stream count is well maintained.
 */
static inline void h2s_close(struct h2s *h2s)
{
	if (h2s->st != H2_SS_CLOSED) {
		h2s->h2c->nb_streams--;
		if (!h2s->id)
			h2s->h2c->nb_reserved--;
	}
	h2s->st = H2_SS_CLOSED;
}

/* detaches an H2 stream from its H2C and releases it to the H2S pool. */
static void h2s_destroy(struct h2s *h2s)
{
	h2s_close(h2s);
	eb32_delete(&h2s->by_id);
	if (b_size(&h2s->rxbuf)) {
		b_free(&h2s->rxbuf);
		offer_buffers(NULL, tasks_run_queue);
	}
	if (h2s->send_wait != NULL)
		h2s->send_wait->events &= ~SUB_RETRY_SEND;
	if (h2s->recv_wait != NULL)
		h2s->recv_wait->events &= ~SUB_RETRY_RECV;
	/* There's no need to explicitly call unsubscribe here, the only
	 * reference left would be in the h2c send_list/fctl_list, and if
	 * we're in it, we're getting out anyway
	 */
	LIST_DEL(&h2s->list);
	LIST_INIT(&h2s->list);
	tasklet_free(h2s->wait_event.task);
	pool_free(pool_head_h2s, h2s);
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

	h2s = pool_alloc(pool_head_h2s);
	if (!h2s)
		goto out;

	h2s->wait_event.task = tasklet_new();
	if (!h2s->wait_event.task) {
		pool_free(pool_head_h2s, h2s);
		goto out;
	}
	h2s->send_wait = NULL;
	h2s->recv_wait = NULL;
	h2s->wait_event.task->process = h2_deferred_shut;
	h2s->wait_event.task->context = h2s;
	h2s->wait_event.handle = NULL;
	h2s->wait_event.events = 0;
	LIST_INIT(&h2s->list);
	h2s->h2c       = h2c;
	h2s->cs        = NULL;
	h2s->mws       = h2c->miw;
	h2s->flags     = H2_SF_NONE;
	h2s->errcode   = H2_ERR_NO_ERROR;
	h2s->st        = H2_SS_IDLE;
	h2s->status    = 0;
	h2s->body_len  = 0;
	h2s->rxbuf     = BUF_NULL;

	if (h2c->flags & H2_CF_IS_BACK) {
		h1m_init_req(&h2s->h1m);
		h2s->h1m.err_pos = -1; // don't care about errors on the request path
		h2s->h1m.flags |= H1_MF_TOLOWER;
	} else {
		h1m_init_res(&h2s->h1m);
		h2s->h1m.err_pos = -1; // don't care about errors on the response path
		h2s->h1m.flags |= H1_MF_TOLOWER;
	}

	h2s->by_id.key = h2s->id = id;
	if (id > 0)
		h2c->max_id      = id;
	else
		h2c->nb_reserved++;

	eb32_insert(&h2c->streams_by_id, &h2s->by_id);
	h2c->nb_streams++;
	h2c->stream_cnt++;

	return h2s;

 out_free_h2s:
	pool_free(pool_head_h2s, h2s);
 out:
	return NULL;
}

/* creates a new stream <id> on the h2c connection and returns it, or NULL in
 * case of memory allocation error.
 */
static struct h2s *h2c_frt_stream_new(struct h2c *h2c, int id)
{
	struct session *sess = h2c->conn->owner;
	struct conn_stream *cs;
	struct h2s *h2s;

	if (h2c->nb_streams >= h2_settings_max_concurrent_streams)
		goto out;

	h2s = h2s_new(h2c, id);
	if (!h2s)
		goto out;

	cs = cs_new(h2c->conn);
	if (!cs)
		goto out_close;

	cs->flags |= CS_FL_NOT_FIRST;
	h2s->cs = cs;
	cs->ctx = h2s;
	h2c->nb_cs++;

	if (stream_create_from_cs(cs) < 0)
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
	if (h2_has_too_many_cs(h2c))
		h2c->flags |= H2_CF_DEM_TOOMANY;
	return h2s;

 out_free_cs:
	h2c->nb_cs--;
	cs_free(cs);
 out_close:
	h2s_destroy(h2s);
 out:
	sess_log(sess);
	return NULL;
}

/* allocates a new stream associated to conn_stream <cs> on the h2c connection
 * and returns it, or NULL in case of memory allocation error or if the highest
 * possible stream ID was reached.
 */
static struct h2s *h2c_bck_stream_new(struct h2c *h2c, struct conn_stream *cs, struct session *sess)
{
	struct h2s *h2s = NULL;

	if (h2c->nb_streams >= h2_settings_max_concurrent_streams)
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
	int ret;

	if (h2c_mux_busy(h2c, NULL)) {
		h2c->flags |= H2_CF_DEM_MBUSY;
		return 0;
	}

	res = h2_get_buf(h2c, &h2c->mbuf);
	if (!res) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		return 0;
	}

	chunk_init(&buf, buf_data, sizeof(buf_data));
	chunk_memcpy(&buf,
	       "\x00\x00\x00"      /* length    : 0 for now */
	       "\x04\x00"          /* type      : 4 (settings), flags : 0 */
	       "\x00\x00\x00\x00", /* stream ID : 0 */
	       9);

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

	if (global.tune.bufsize != 16384) {
		char str[6] = "\x00\x05"; /* max_frame_size */

		/* note: similarly we could also emit MAX_HEADER_LIST_SIZE to
		 * match bufsize - rewrite size, but at the moment it seems
		 * that clients don't take care of it.
		 */
		write_n32(str + 2, global.tune.bufsize);
		chunk_memcat(&buf, str, 6);
	}

	h2_set_frame_size(buf.area, buf.data - 9);
	ret = b_istput(res, ist2(buf.area, buf.data));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			h2c->flags |= H2_CF_MUX_MFULL;
			h2c->flags |= H2_CF_DEM_MROOM;
			return 0;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			return 0;
		}
	}
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

	ret1 = b_isteq(&h2c->dbuf, 0, b_data(&h2c->dbuf), ist(H2_CONN_PREFACE));

	if (unlikely(ret1 <= 0)) {
		if (ret1 < 0)
			sess_log(h2c->conn->owner);

		if (ret1 < 0 || conn_xprt_read0_pending(h2c->conn))
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
		return 0;
	}

	ret2 = h2c_send_settings(h2c);
	if (ret2 > 0)
		b_del(&h2c->dbuf, ret1);

	return ret2;
}

/* Try to send a connection preface, then upon success try to send our
 * preface which is a SETTINGS frame. Returns > 0 on success or zero on
 * missing data. It may return an error in h2c.
 */
static int h2c_bck_send_preface(struct h2c *h2c)
{
	struct buffer *res;

	if (h2c_mux_busy(h2c, NULL)) {
		h2c->flags |= H2_CF_DEM_MBUSY;
		return 0;
	}

	res = h2_get_buf(h2c, &h2c->mbuf);
	if (!res) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		return 0;
	}

	if (!b_data(res)) {
		/* preface not yet sent */
		b_istput(res, ist(H2_CONN_PREFACE));
	}

	return h2c_send_settings(h2c);
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
	int ret;

	if (h2c->flags & H2_CF_GOAWAY_FAILED)
		return 1; // claim that it worked

	if (h2c_mux_busy(h2c, h2s)) {
		if (h2s)
			h2s->flags |= H2_SF_BLK_MBUSY;
		else
			h2c->flags |= H2_CF_DEM_MBUSY;
		return 0;
	}

	res = h2_get_buf(h2c, &h2c->mbuf);
	if (!res) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		if (h2s)
			h2s->flags |= H2_SF_BLK_MROOM;
		else
			h2c->flags |= H2_CF_DEM_MROOM;
		return 0;
	}

	/* len: 8, type: 7, flags: none, sid: 0 */
	memcpy(str, "\x00\x00\x08\x07\x00\x00\x00\x00\x00", 9);

	if (h2c->last_sid < 0)
		h2c->last_sid = h2c->max_id;

	write_n32(str + 9, h2c->last_sid);
	write_n32(str + 13, h2c->errcode);
	ret = b_istput(res, ist2(str, 17));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			h2c->flags |= H2_CF_MUX_MFULL;
			if (h2s)
				h2s->flags |= H2_SF_BLK_MROOM;
			else
				h2c->flags |= H2_CF_DEM_MROOM;
			return 0;
		}
		else {
			/* we cannot report this error using GOAWAY, so we mark
			 * it and claim a success.
			 */
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			h2c->flags |= H2_CF_GOAWAY_FAILED;
			return 1;
		}
	}
	h2c->flags |= H2_CF_GOAWAY_SENT;
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
	int ret;

	if (!h2s || h2s->st == H2_SS_CLOSED)
		return 1;

	/* RFC7540#5.4.2: To avoid looping, an endpoint MUST NOT send a
	 * RST_STREAM in response to a RST_STREAM frame.
	 */
	if (h2c->dft == H2_FT_RST_STREAM) {
		ret = 1;
		goto ignore;
	}

	if (h2c_mux_busy(h2c, h2s)) {
		h2s->flags |= H2_SF_BLK_MBUSY;
		return 0;
	}

	res = h2_get_buf(h2c, &h2c->mbuf);
	if (!res) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		return 0;
	}

	/* len: 4, type: 3, flags: none */
	memcpy(str, "\x00\x00\x04\x03\x00", 5);
	write_n32(str + 5, h2s->id);
	write_n32(str + 9, h2s->errcode);
	ret = b_istput(res, ist2(str, 13));

	if (unlikely(ret <= 0)) {
		if (!ret) {
			h2c->flags |= H2_CF_MUX_MFULL;
			h2s->flags |= H2_SF_BLK_MROOM;
			return 0;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			return 0;
		}
	}

 ignore:
	h2s->flags |= H2_SF_RST_SENT;
	h2s_close(h2s);
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
	int ret;

	/* RFC7540#5.4.2: To avoid looping, an endpoint MUST NOT send a
	 * RST_STREAM in response to a RST_STREAM frame.
	 */
	if (h2c->dft == H2_FT_RST_STREAM) {
		ret = 1;
		goto ignore;
	}

	if (h2c_mux_busy(h2c, h2s)) {
		h2c->flags |= H2_CF_DEM_MBUSY;
		return 0;
	}

	res = h2_get_buf(h2c, &h2c->mbuf);
	if (!res) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		return 0;
	}

	/* len: 4, type: 3, flags: none */
	memcpy(str, "\x00\x00\x04\x03\x00", 5);

	write_n32(str + 5, h2c->dsi);
	write_n32(str + 9, h2s->errcode);
	ret = b_istput(res, ist2(str, 13));

	if (unlikely(ret <= 0)) {
		if (!ret) {
			h2c->flags |= H2_CF_MUX_MFULL;
			h2c->flags |= H2_CF_DEM_MROOM;
			return 0;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			return 0;
		}
	}

 ignore:
	if (h2s->id) {
		h2s->flags |= H2_SF_RST_SENT;
		h2s_close(h2s);
	}

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
	int ret;

	if (h2s->st == H2_SS_HLOC || h2s->st == H2_SS_ERROR || h2s->st == H2_SS_CLOSED)
		return 1;

	if (h2c_mux_busy(h2c, h2s)) {
		h2s->flags |= H2_SF_BLK_MBUSY;
		return 0;
	}

	res = h2_get_buf(h2c, &h2c->mbuf);
	if (!res) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		return 0;
	}

	/* len: 0x000000, type: 0(DATA), flags: ES=1 */
	memcpy(str, "\x00\x00\x00\x00\x01", 5);
	write_n32(str + 5, h2s->id);
	ret = b_istput(res, ist2(str, 9));
	if (likely(ret > 0)) {
		h2s->flags |= H2_SF_ES_SENT;
	}
	else if (!ret) {
		h2c->flags |= H2_CF_MUX_MFULL;
		h2s->flags |= H2_SF_BLK_MROOM;
		return 0;
	}
	else {
		h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
		return 0;
	}
	return ret;
}

/* wake the streams attached to the connection, whose id is greater than <last>,
 * and assign their conn_stream the CS_FL_* flags <flags> in addition to
 * CS_FL_ERROR in case of error and CS_FL_REOS in case of closed connection.
 * The stream's state is automatically updated accordingly.
 */
static void h2_wake_some_streams(struct h2c *h2c, int last, uint32_t flags)
{
	struct eb32_node *node;
	struct h2s *h2s;

	if (h2c->st0 >= H2_CS_ERROR || h2c->conn->flags & CO_FL_ERROR)
		flags |= CS_FL_ERR_PENDING;

	if (conn_xprt_read0_pending(h2c->conn))
		flags |= CS_FL_REOS;

	node = eb32_lookup_ge(&h2c->streams_by_id, last + 1);
	while (node) {
		h2s = container_of(node, struct h2s, by_id);
		if (h2s->id <= last)
			break;
		node = eb32_next(node);

		if (!h2s->cs) {
			/* this stream was already orphaned */
			h2s_destroy(h2s);
			continue;
		}

		h2s->cs->flags |= flags;
		if ((flags & CS_FL_ERR_PENDING) && (h2s->cs->flags & CS_FL_EOS))
			h2s->cs->flags |= CS_FL_ERROR;

		h2s_alert(h2s);

		if (flags & CS_FL_ERR_PENDING && h2s->st < H2_SS_ERROR)
			h2s->st = H2_SS_ERROR;
		else if (flags & CS_FL_REOS && h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HREM;
		else if (flags & CS_FL_REOS && h2s->st == H2_SS_HLOC)
			h2s_close(h2s);
	}
}

/* Increase all streams' outgoing window size by the difference passed in
 * argument. This is needed upon receipt of the settings frame if the initial
 * window size is different. The difference may be negative and the resulting
 * window size as well, for the time it takes to receive some window updates.
 */
static void h2c_update_all_ws(struct h2c *h2c, int diff)
{
	struct h2s *h2s;
	struct eb32_node *node;

	if (!diff)
		return;

	node = eb32_first(&h2c->streams_by_id);
	while (node) {
		h2s = container_of(node, struct h2s, by_id);
		h2s->mws += diff;

		if (h2s->mws > 0 && (h2s->flags & H2_SF_BLK_SFCTL)) {
			h2s->flags &= ~H2_SF_BLK_SFCTL;
			if (h2s->send_wait)
				LIST_ADDQ(&h2c->send_list, &h2s->list);

		}

		node = eb32_next(node);
	}
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

	if (h2c->dff & H2_F_SETTINGS_ACK) {
		if (h2c->dfl) {
			error = H2_ERR_FRAME_SIZE_ERROR;
			goto fail;
		}
		return 1;
	}

	/* process full frame only */
	if (b_data(&h2c->dbuf) < h2c->dfl)
		return 0;

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
			h2c_update_all_ws(h2c, arg - h2c->miw);
			h2c->miw = arg;
			break;
		case H2_SETTINGS_MAX_FRAME_SIZE:
			if (arg < 16384 || arg > 16777215) { // RFC7540#6.5.2
				error = H2_ERR_PROTOCOL_ERROR;
				goto fail;
			}
			h2c->mfs = arg;
			break;
		case H2_SETTINGS_ENABLE_PUSH:
			if (arg < 0 || arg > 1) { // RFC7540#6.5.2
				error = H2_ERR_PROTOCOL_ERROR;
				goto fail;
			}
			break;
		}
	}

	/* need to ACK this frame now */
	h2c->st0 = H2_CS_FRAME_A;
	return 1;
 fail:
	sess_log(h2c->conn->owner);
	h2c_error(h2c, error);
	return 0;
}

/* try to send an ACK for a settings frame on the connection. Returns > 0 on
 * success or one of the h2_status values.
 */
static int h2c_ack_settings(struct h2c *h2c)
{
	struct buffer *res;
	char str[9];
	int ret = -1;

	if (h2c_mux_busy(h2c, NULL)) {
		h2c->flags |= H2_CF_DEM_MBUSY;
		return 0;
	}

	res = h2_get_buf(h2c, &h2c->mbuf);
	if (!res) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		return 0;
	}

	memcpy(str,
	       "\x00\x00\x00"     /* length : 0 (no data)  */
	       "\x04" "\x01"      /* type   : 4, flags : ACK */
	       "\x00\x00\x00\x00" /* stream ID */, 9);

	ret = b_istput(res, ist2(str, 9));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			h2c->flags |= H2_CF_MUX_MFULL;
			h2c->flags |= H2_CF_DEM_MROOM;
			return 0;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			return 0;
		}
	}
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
	int ret = -1;

	if (h2c_mux_busy(h2c, NULL)) {
		h2c->flags |= H2_CF_DEM_MBUSY;
		return 0;
	}

	res = h2_get_buf(h2c, &h2c->mbuf);
	if (!res) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		return 0;
	}

	/* length: 4, type: 8, flags: none */
	memcpy(str, "\x00\x00\x04\x08\x00", 5);
	write_n32(str + 5, sid);
	write_n32(str + 9, increment);

	ret = b_istput(res, ist2(str, 13));

	if (unlikely(ret <= 0)) {
		if (!ret) {
			h2c->flags |= H2_CF_MUX_MFULL;
			h2c->flags |= H2_CF_DEM_MROOM;
			return 0;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			return 0;
		}
	}
	return ret;
}

/* try to send pending window update for the connection. It's safe to call it
 * with no pending updates. Returns > 0 on success or zero on missing room or
 * failure. It may return an error in h2c.
 */
static int h2c_send_conn_wu(struct h2c *h2c)
{
	int ret = 1;

	if (h2c->rcvd_c <= 0)
		return 1;

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

	return ret;
}

/* try to send pending window update for the current dmux stream. It's safe to
 * call it with no pending updates. Returns > 0 on success or zero on missing
 * room or failure. It may return an error in h2c.
 */
static int h2c_send_strm_wu(struct h2c *h2c)
{
	int ret = 1;

	if (h2c->rcvd_s <= 0)
		return 1;

	/* send WU for the stream */
	ret = h2c_send_window_update(h2c, h2c->dsi, h2c->rcvd_s);
	if (ret > 0)
		h2c->rcvd_s = 0;

	return ret;
}

/* try to send an ACK for a ping frame on the connection. Returns > 0 on
 * success, 0 on missing data or one of the h2_status values.
 */
static int h2c_ack_ping(struct h2c *h2c)
{
	struct buffer *res;
	char str[17];
	int ret = -1;

	if (b_data(&h2c->dbuf) < 8)
		return 0;

	if (h2c_mux_busy(h2c, NULL)) {
		h2c->flags |= H2_CF_DEM_MBUSY;
		return 0;
	}

	res = h2_get_buf(h2c, &h2c->mbuf);
	if (!res) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2c->flags |= H2_CF_DEM_MROOM;
		return 0;
	}

	memcpy(str,
	       "\x00\x00\x08"     /* length : 8 (same payload) */
	       "\x06" "\x01"      /* type   : 6, flags : ACK   */
	       "\x00\x00\x00\x00" /* stream ID */, 9);

	/* copy the original payload */
	h2_get_buf_bytes(str + 9, 8, &h2c->dbuf, 0);

	ret = b_istput(res, ist2(str, 17));
	if (unlikely(ret <= 0)) {
		if (!ret) {
			h2c->flags |= H2_CF_MUX_MFULL;
			h2c->flags |= H2_CF_DEM_MROOM;
			return 0;
		}
		else {
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			return 0;
		}
	}
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

	/* process full frame only */
	if (b_data(&h2c->dbuf) < h2c->dfl)
		return 0;

	inc = h2_get_n32(&h2c->dbuf, 0);

	if (h2c->dsi != 0) {
		/* stream window update */

		/* it's not an error to receive WU on a closed stream */
		if (h2s->st == H2_SS_CLOSED)
			return 1;

		if (!inc) {
			error = H2_ERR_PROTOCOL_ERROR;
			goto strm_err;
		}

		if (h2s->mws >= 0 && h2s->mws + inc < 0) {
			error = H2_ERR_FLOW_CONTROL_ERROR;
			goto strm_err;
		}

		h2s->mws += inc;
		if (h2s->mws > 0 && (h2s->flags & H2_SF_BLK_SFCTL)) {
			h2s->flags &= ~H2_SF_BLK_SFCTL;
			if (h2s->send_wait)
				LIST_ADDQ(&h2c->send_list, &h2s->list);

		}
	}
	else {
		/* connection window update */
		if (!inc) {
			error = H2_ERR_PROTOCOL_ERROR;
			goto conn_err;
		}

		if (h2c->mws >= 0 && h2c->mws + inc < 0) {
			error = H2_ERR_FLOW_CONTROL_ERROR;
			goto conn_err;
		}

		h2c->mws += inc;
	}

	return 1;

 conn_err:
	h2c_error(h2c, error);
	return 0;

 strm_err:
	h2s_error(h2s, error);
	h2c->st0 = H2_CS_FRAME_E;
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

	/* process full frame only */
	if (b_data(&h2c->dbuf) < h2c->dfl)
		return 0;

	last = h2_get_n32(&h2c->dbuf, 0);
	h2c->errcode = h2_get_n32(&h2c->dbuf, 4);
	h2_wake_some_streams(h2c, last, CS_FL_ERR_PENDING);
	if (h2c->last_sid < 0)
		h2c->last_sid = last;
	return 1;
}

/* processes a PRIORITY frame, and either skips it or rejects if it is
 * invalid. Returns > 0 on success or zero on missing data. It may return an
 * error in h2c. The caller must have already verified frame length and stream
 * ID validity. Described in RFC7540#6.3.
 */
static int h2c_handle_priority(struct h2c *h2c)
{
	/* process full frame only */
	if (b_data(&h2c->dbuf) < h2c->dfl)
		return 0;

	if (h2_get_n32(&h2c->dbuf, 0) == h2c->dsi) {
		/* 7540#5.3 : can't depend on itself */
		h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
		return 0;
	}
	return 1;
}

/* processes an RST_STREAM frame, and sets the 32-bit error code on the stream.
 * Returns > 0 on success or zero on missing data. The caller must have already
 * verified frame length and stream ID validity. Described in RFC7540#6.4.
 */
static int h2c_handle_rst_stream(struct h2c *h2c, struct h2s *h2s)
{
	/* process full frame only */
	if (b_data(&h2c->dbuf) < h2c->dfl)
		return 0;

	/* late RST, already handled */
	if (h2s->st == H2_SS_CLOSED)
		return 1;

	h2s->errcode = h2_get_n32(&h2c->dbuf, 0);
	h2s_close(h2s);

	if (h2s->cs) {
		cs_set_error(h2s->cs);
		h2s_alert(h2s);
	}

	h2s->flags |= H2_SF_RST_RCVD;
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

	if (!b_size(&h2c->dbuf))
		return NULL; // empty buffer

	if (b_data(&h2c->dbuf) < h2c->dfl && !b_full(&h2c->dbuf))
		return NULL; // incomplete frame

	/* now either the frame is complete or the buffer is complete */
	if (h2s->st != H2_SS_IDLE) {
		/* The stream exists/existed, this must be a trailers frame */
		if (h2s->st != H2_SS_CLOSED) {
			if (h2c_decode_headers(h2c, &h2s->rxbuf, &h2s->flags, &body_len) <= 0)
				goto out;
			goto done;
		}
		/* the connection was already killed by an RST, let's consume
		 * the data and send another RST.
		 */
		error = h2c_decode_headers(h2c, &rxbuf, &flags, &body_len);
		h2s = (struct h2s*)h2_error_stream;
		goto send_rst;
	}
	else if (h2c->dsi <= h2c->max_id || !(h2c->dsi & 1)) {
		/* RFC7540#5.1.1 stream id > prev ones, and must be odd here */
		error = H2_ERR_PROTOCOL_ERROR;
		sess_log(h2c->conn->owner);
		goto conn_err;
	}
	else if (h2c->flags & H2_CF_DEM_TOOMANY)
		goto out; // IDLE but too many cs still present

	error = h2c_decode_headers(h2c, &rxbuf, &flags, &body_len);

	/* unrecoverable error ? */
	if (h2c->st0 >= H2_CS_ERROR)
		goto out;

	if (error <= 0) {
		if (error == 0)
			goto out; // missing data

		/* Failed to decode this stream (e.g. too large request)
		 * but the HPACK decompressor is still synchronized.
		 */
		h2s = (struct h2s*)h2_error_stream;
		goto send_rst;
	}

	/* Note: we don't emit any other logs below because ff we return
	 * positively from h2c_frt_stream_new(), the stream will report the error,
	 * and if we return in error, h2c_frt_stream_new() will emit the error.
	 */
	h2s = h2c_frt_stream_new(h2c, h2c->dsi);
	if (!h2s) {
		h2s = (struct h2s*)h2_refused_stream;
		goto send_rst;
	}

	h2s->st = H2_SS_OPEN;
	h2s->rxbuf = rxbuf;
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
		h2s->cs->flags |= CS_FL_REOS;
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
	return NULL;

 send_rst:
	/* make the demux send an RST for the current stream. We may only
	 * do this if we're certain that the HEADERS frame was properly
	 * decompressed so that the HPACK decoder is still kept up to date.
	 */
	h2_release_buf(h2c, &rxbuf);
	h2c->st0 = H2_CS_FRAME_E;
	return h2s;
}

/* processes a HEADERS frame. Returns h2s on success or NULL on missing data.
 * It may return an error in h2c or h2s. Described in RFC7540#6.2. Most of the
 * errors here are reported as connection errors since it's impossible to
 * recover from such errors after the compression context has been altered.
 */
static struct h2s *h2c_bck_handle_headers(struct h2c *h2c, struct h2s *h2s)
{
	int error;

	if (!b_size(&h2c->dbuf))
		return NULL; // empty buffer

	if (b_data(&h2c->dbuf) < h2c->dfl && !b_full(&h2c->dbuf))
		return NULL; // incomplete frame

	error = h2c_decode_headers(h2c, &h2s->rxbuf, &h2s->flags, &h2s->body_len);

	/* unrecoverable error ? */
	if (h2c->st0 >= H2_CS_ERROR)
		return NULL;

	if (h2s->st != H2_SS_OPEN && h2s->st != H2_SS_HLOC) {
		/* RFC7540#5.1 */
		h2s_error(h2s, H2_ERR_STREAM_CLOSED);
		h2c->st0 = H2_CS_FRAME_E;
		return NULL;
	}

	if (error <= 0) {
		if (error == 0)
			return NULL; // missing data

		/* stream error : send RST_STREAM */
		h2s_error(h2s, H2_ERR_PROTOCOL_ERROR);
		h2c->st0 = H2_CS_FRAME_E;
		return NULL;
	}

	if (h2c->dff & H2_F_HEADERS_END_STREAM) {
		h2s->flags |= H2_SF_ES_RCVD;
		h2s->cs->flags |= CS_FL_REOS;
	}

	if (h2s->cs->flags & CS_FL_ERROR && h2s->st < H2_SS_ERROR)
		h2s->st = H2_SS_ERROR;
	else if (h2s->cs->flags & CS_FL_REOS && h2s->st == H2_SS_OPEN)
		h2s->st = H2_SS_HREM;
	else if (h2s->cs->flags & CS_FL_REOS && h2s->st == H2_SS_HLOC)
		h2s_close(h2s);

	return h2s;
}

/* processes a DATA frame. Returns > 0 on success or zero on missing data.
 * It may return an error in h2c or h2s. Described in RFC7540#6.1.
 */
static int h2c_frt_handle_data(struct h2c *h2c, struct h2s *h2s)
{
	int error;

	/* note that empty DATA frames are perfectly valid and sometimes used
	 * to signal an end of stream (with the ES flag).
	 */

	if (!b_size(&h2c->dbuf) && h2c->dfl)
		return 0; // empty buffer

	if (b_data(&h2c->dbuf) < h2c->dfl && !b_full(&h2c->dbuf))
		return 0; // incomplete frame

	/* now either the frame is complete or the buffer is complete */

	if (h2s->st != H2_SS_OPEN && h2s->st != H2_SS_HLOC) {
		/* RFC7540#6.1 */
		error = H2_ERR_STREAM_CLOSED;
		goto strm_err;
	}

	if ((h2s->flags & H2_SF_DATA_CLEN) && h2c->dfl > h2s->body_len) {
		/* RFC7540#8.1.2 */
		error = H2_ERR_PROTOCOL_ERROR;
		goto strm_err;
	}

	if (!h2_frt_transfer_data(h2s))
		return 0;

	/* call the upper layers to process the frame, then let the upper layer
	 * notify the stream about any change.
	 */
	if (!h2s->cs) {
		error = H2_ERR_STREAM_CLOSED;
		goto strm_err;
	}

	if (h2c->st0 >= H2_CS_ERROR)
		return 0;

	if (h2s->st >= H2_SS_ERROR) {
		/* stream error : send RST_STREAM */
		h2c->st0 = H2_CS_FRAME_E;
	}

	/* check for completion : the callee will change this to FRAME_A or
	 * FRAME_H once done.
	 */
	if (h2c->st0 == H2_CS_FRAME_P)
		return 0;

	/* last frame */
	if (h2c->dff & H2_F_DATA_END_STREAM) {
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HREM;
		else
			h2s_close(h2s);

		h2s->flags |= H2_SF_ES_RCVD;
		h2s->cs->flags |= CS_FL_REOS;

		if (h2s->flags & H2_SF_DATA_CLEN && h2s->body_len) {
			/* RFC7540#8.1.2 */
			error = H2_ERR_PROTOCOL_ERROR;
			goto strm_err;
		}
	}

	return 1;

 strm_err:
	h2s_error(h2s, error);
	h2c->st0 = H2_CS_FRAME_E;
	return 0;
}

/* process Rx frames to be demultiplexed */
static void h2_process_demux(struct h2c *h2c)
{
	struct h2s *h2s = NULL, *tmp_h2s;
	struct h2_fh hdr;
	unsigned int padlen = 0;

	if (h2c->st0 >= H2_CS_ERROR)
		return;

	if (unlikely(h2c->st0 < H2_CS_FRAME_H)) {
		if (h2c->st0 == H2_CS_PREFACE) {
			if (h2c->flags & H2_CF_IS_BACK)
				return;
			if (unlikely(h2c_frt_recv_preface(h2c) <= 0)) {
				/* RFC7540#3.5: a GOAWAY frame MAY be omitted */
				if (h2c->st0 == H2_CS_ERROR) {
					h2c->st0 = H2_CS_ERROR2;
					sess_log(h2c->conn->owner);
				}
				goto fail;
			}

			h2c->max_id = 0;
			h2c->st0 = H2_CS_SETTINGS1;
		}

		if (h2c->st0 == H2_CS_SETTINGS1) {
			/* ensure that what is pending is a valid SETTINGS frame
			 * without an ACK.
			 */
			if (!h2_get_frame_hdr(&h2c->dbuf, &hdr)) {
				/* RFC7540#3.5: a GOAWAY frame MAY be omitted */
				if (h2c->st0 == H2_CS_ERROR) {
					h2c->st0 = H2_CS_ERROR2;
					sess_log(h2c->conn->owner);
				}
				goto fail;
			}

			if (hdr.sid || hdr.ft != H2_FT_SETTINGS || hdr.ff & H2_F_SETTINGS_ACK) {
				/* RFC7540#3.5: a GOAWAY frame MAY be omitted */
				h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
				h2c->st0 = H2_CS_ERROR2;
				sess_log(h2c->conn->owner);
				goto fail;
			}

			if ((int)hdr.len < 0 || (int)hdr.len > global.tune.bufsize) {
				/* RFC7540#3.5: a GOAWAY frame MAY be omitted */
				h2c_error(h2c, H2_ERR_FRAME_SIZE_ERROR);
				h2c->st0 = H2_CS_ERROR2;
				sess_log(h2c->conn->owner);
				goto fail;
			}

			/* that's OK, switch to FRAME_P to process it. This is
			 * a SETTINGS frame whose header has already been
			 * deleted above.
			 */
			padlen = 0;
			goto new_frame;
		}
	}

	/* process as many incoming frames as possible below */
	while (b_data(&h2c->dbuf)) {
		int ret = 0;

		if (h2c->st0 >= H2_CS_ERROR)
			break;

		if (h2c->st0 == H2_CS_FRAME_H) {
			if (!h2_peek_frame_hdr(&h2c->dbuf, 0, &hdr))
				break;

			if ((int)hdr.len < 0 || (int)hdr.len > global.tune.bufsize) {
				h2c_error(h2c, H2_ERR_FRAME_SIZE_ERROR);
				if (!h2c->nb_streams) {
					/* only log if no other stream can report the error */
					sess_log(h2c->conn->owner);
				}
				break;
			}

			if (h2_ft_bit(hdr.ft) & H2_FT_PADDED_MASK && hdr.ff & H2_F_PADDED) {
				/* If the frame is padded (HEADERS, PUSH_PROMISE or DATA),
				 * we read the pad length and drop it from the remaining
				 * payload (one byte + the 9 remaining ones = 10 total
				 * removed), so we have a frame payload starting after the
				 * pad len. Flow controlled frames (DATA) also count the
				 * padlen in the flow control, so it must be adjusted.
				 */
				if (hdr.len < 1) {
					h2c_error(h2c, H2_ERR_FRAME_SIZE_ERROR);
					sess_log(h2c->conn->owner);
					goto fail;
				}
				hdr.len--;

				if (b_data(&h2c->dbuf) < 10)
					break; // missing padlen

				padlen = *(uint8_t *)b_peek(&h2c->dbuf, 9);

				if (padlen > hdr.len) {
					/* RFC7540#6.1 : pad length = length of
					 * frame payload or greater => error.
					 */
					h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
					sess_log(h2c->conn->owner);
					goto fail;
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
			h2c->st0 = H2_CS_FRAME_P;

			/* check for minimum basic frame format validity */
			ret = h2_frame_check(h2c->dft, 1, h2c->dsi, h2c->dfl, global.tune.bufsize);
			if (ret != H2_ERR_NO_ERROR) {
				h2c_error(h2c, ret);
				sess_log(h2c->conn->owner);
				goto fail;
			}
		}

		/* Only H2_CS_FRAME_P and H2_CS_FRAME_A here */
		tmp_h2s = h2c_st_by_id(h2c, h2c->dsi);

		if (tmp_h2s != h2s && h2s && h2s->cs &&
		    (b_data(&h2s->rxbuf) ||
		     (h2s->cs->flags & (CS_FL_ERROR|CS_FL_ERR_PENDING|CS_FL_EOS|CS_FL_REOS)))) {
			/* we may have to signal the upper layers */
			h2s->cs->flags |= CS_FL_RCV_MORE;
			h2s_notify_recv(h2s);
		}
		h2s = tmp_h2s;

		if (h2c->st0 == H2_CS_FRAME_E)
			goto strm_err;

		if (h2s->st == H2_SS_IDLE &&
		    h2c->dft != H2_FT_HEADERS && h2c->dft != H2_FT_PRIORITY) {
			/* RFC7540#5.1: any frame other than HEADERS or PRIORITY in
			 * this state MUST be treated as a connection error
			 */
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			if (!h2c->nb_streams) {
				/* only log if no other stream can report the error */
				sess_log(h2c->conn->owner);
			}
			break;
		}

		if (h2s->st == H2_SS_HREM && h2c->dft != H2_FT_WINDOW_UPDATE &&
		    h2c->dft != H2_FT_RST_STREAM && h2c->dft != H2_FT_PRIORITY) {
			/* RFC7540#5.1: any frame other than WU/PRIO/RST in
			 * this state MUST be treated as a stream error.
			 * 6.2, 6.6 and 6.10 further mandate that HEADERS/
			 * PUSH_PROMISE/CONTINUATION cause connection errors.
			 */
			if (h2_ft_bit(h2c->dft) & H2_FT_HDR_MASK)
				h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			else
				h2s_error(h2s, H2_ERR_STREAM_CLOSED);
			goto strm_err;
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
				goto strm_err;
			}

			if (h2s->flags & H2_SF_RST_RCVD && h2_ft_bit(h2c->dft) & H2_FT_HDR_MASK) {
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
				 */
				h2s_error(h2s, H2_ERR_STREAM_CLOSED);
				h2c->st0 = H2_CS_FRAME_E;
				goto strm_err;
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
					goto strm_err;
				}
			}
		}

#if 0
		// problem below: it is not possible to completely ignore such
		// streams as we need to maintain the compression state as well
		// and for this we need to completely process these frames (eg:
		// HEADERS frames) as well as counting DATA frames to emit
		// proper WINDOW UPDATES and ensure the connection doesn't stall.
		// This is a typical case of layer violation where the
		// transported contents are critical to the connection's
		// validity and must be ignored at the same time :-(

		/* graceful shutdown, ignore streams whose ID is higher than
		 * the one advertised in GOAWAY. RFC7540#6.8.
		 */
		if (unlikely(h2c->last_sid >= 0) && h2c->dsi > h2c->last_sid) {
			ret = MIN(b_data(&h2c->dbuf), h2c->dfl);
			b_del(&h2c->dbuf, ret);
			h2c->dfl -= ret;
			ret = h2c->dfl == 0;
			goto strm_err;
		}
#endif

		switch (h2c->dft) {
		case H2_FT_SETTINGS:
			if (h2c->st0 == H2_CS_FRAME_P)
				ret = h2c_handle_settings(h2c);

			if (h2c->st0 == H2_CS_FRAME_A)
				ret = h2c_ack_settings(h2c);
			break;

		case H2_FT_PING:
			if (h2c->st0 == H2_CS_FRAME_P)
				ret = h2c_handle_ping(h2c);

			if (h2c->st0 == H2_CS_FRAME_A)
				ret = h2c_ack_ping(h2c);
			break;

		case H2_FT_WINDOW_UPDATE:
			if (h2c->st0 == H2_CS_FRAME_P)
				ret = h2c_handle_window_update(h2c, h2s);
			break;

		case H2_FT_CONTINUATION:
			/* RFC7540#6.10: CONTINUATION may only be preceeded by
			 * a HEADERS/PUSH_PROMISE/CONTINUATION frame. These
			 * frames' parsers consume all following CONTINUATION
			 * frames so this one is out of sequence.
			 */
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			sess_log(h2c->conn->owner);
			goto fail;

		case H2_FT_HEADERS:
			if (h2c->st0 == H2_CS_FRAME_P) {
				if (h2c->flags & H2_CF_IS_BACK)
					tmp_h2s = h2c_bck_handle_headers(h2c, h2s);
				else
					tmp_h2s = h2c_frt_handle_headers(h2c, h2s);
				if (tmp_h2s) {
					h2s = tmp_h2s;
					ret = 1;
				}
			}
			break;

		case H2_FT_DATA:
			if (h2c->st0 == H2_CS_FRAME_P)
				ret = h2c_frt_handle_data(h2c, h2s);

			if (h2c->st0 == H2_CS_FRAME_A)
				ret = h2c_send_strm_wu(h2c);
			break;

		case H2_FT_PRIORITY:
			if (h2c->st0 == H2_CS_FRAME_P)
				ret = h2c_handle_priority(h2c);
			break;

		case H2_FT_RST_STREAM:
			if (h2c->st0 == H2_CS_FRAME_P)
				ret = h2c_handle_rst_stream(h2c, h2s);
			break;

		case H2_FT_GOAWAY:
			if (h2c->st0 == H2_CS_FRAME_P)
				ret = h2c_handle_goaway(h2c);
			break;

			/* implement all extra frame types here */
		default:
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
		if (h2s->st == H2_SS_ERROR)
			h2c->st0 = H2_CS_FRAME_E;

		if (h2c->st0 == H2_CS_FRAME_E)
			ret = h2c_send_rst_stream(h2c, h2s);

		/* error or missing data condition met above ? */
		if (ret <= 0)
			break;

		if (h2c->st0 != H2_CS_FRAME_H) {
			b_del(&h2c->dbuf, h2c->dfl);
			h2c->st0 = H2_CS_FRAME_H;
		}
	}

	if (h2c->rcvd_c > 0 &&
	    !(h2c->flags & (H2_CF_MUX_MFULL | H2_CF_DEM_MBUSY | H2_CF_DEM_MROOM)))
		h2c_send_conn_wu(h2c);

 fail:
	/* we can go here on missing data, blocked response or error */
	if (h2s && h2s->cs &&
	    (b_data(&h2s->rxbuf) ||
	     (h2s->cs->flags & (CS_FL_ERROR|CS_FL_ERR_PENDING|CS_FL_EOS|CS_FL_REOS)))) {
		/* we may have to signal the upper layers */
		h2s->cs->flags |= CS_FL_RCV_MORE;
		h2s_notify_recv(h2s);
	}

	h2c_restart_reading(h2c);
}

/* process Tx frames from streams to be multiplexed. Returns > 0 if it reached
 * the end.
 */
static int h2_process_mux(struct h2c *h2c)
{
	struct h2s *h2s, *h2s_back;

	if (unlikely(h2c->st0 < H2_CS_FRAME_H)) {
		if (unlikely(h2c->st0 == H2_CS_PREFACE && (h2c->flags & H2_CF_IS_BACK))) {
			if (unlikely(h2c_bck_send_preface(h2c) <= 0)) {
				/* RFC7540#3.5: a GOAWAY frame MAY be omitted */
				if (h2c->st0 == H2_CS_ERROR) {
					h2c->st0 = H2_CS_ERROR2;
					sess_log(h2c->conn->owner);
				}
				goto fail;
			}
			h2c->st0 = H2_CS_SETTINGS1;
		}
		/* need to wait for the other side */
		if (h2c->st0 < H2_CS_FRAME_H)
			return 1;
	}

	/* start by sending possibly pending window updates */
	if (h2c->rcvd_c > 0 &&
	    !(h2c->flags & (H2_CF_MUX_MFULL | H2_CF_MUX_MALLOC)) &&
	    h2c_send_conn_wu(h2c) < 0)
		goto fail;

	/* First we always process the flow control list because the streams
	 * waiting there were already elected for immediate emission but were
	 * blocked just on this.
	 */

	list_for_each_entry_safe(h2s, h2s_back, &h2c->fctl_list, list) {
		if (h2c->mws <= 0 || h2c->flags & H2_CF_MUX_BLOCK_ANY ||
		    h2c->st0 >= H2_CS_ERROR)
			break;

		h2s->flags &= ~H2_SF_BLK_ANY;
		h2s->send_wait->events &= ~SUB_RETRY_SEND;
		h2s->send_wait->events |= SUB_CALL_UNSUBSCRIBE;
		tasklet_wakeup(h2s->send_wait->task);
		LIST_DEL(&h2s->list);
		LIST_INIT(&h2s->list);
		LIST_ADDQ(&h2c->sending_list, &h2s->list);
	}

	list_for_each_entry_safe(h2s, h2s_back, &h2c->send_list, list) {
		if (h2c->st0 >= H2_CS_ERROR || h2c->flags & H2_CF_MUX_BLOCK_ANY)
			break;

		h2s->flags &= ~H2_SF_BLK_ANY;
		h2s->send_wait->events &= ~SUB_RETRY_SEND;
		h2s->send_wait->events |= SUB_CALL_UNSUBSCRIBE;
		tasklet_wakeup(h2s->send_wait->task);
		LIST_DEL(&h2s->list);
		LIST_INIT(&h2s->list);
		LIST_ADDQ(&h2c->sending_list, &h2s->list);
	}

 fail:
	if (unlikely(h2c->st0 >= H2_CS_ERROR)) {
		if (h2c->st0 == H2_CS_ERROR) {
			if (h2c->max_id >= 0) {
				h2c_send_goaway_error(h2c, NULL);
				if (h2c->flags & H2_CF_MUX_BLOCK_ANY)
					return 0;
			}

			h2c->st0 = H2_CS_ERROR2; // sent (or failed hard) !
		}
		return 1;
	}
	return (h2c->mws <= 0 || LIST_ISEMPTY(&h2c->fctl_list)) && LIST_ISEMPTY(&h2c->send_list);
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

	if (h2c->wait_event.events & SUB_RETRY_RECV)
		return (b_data(&h2c->dbuf));

	if (!h2_recv_allowed(h2c))
		return 1;

	buf = h2_get_buf(h2c, &h2c->dbuf);
	if (!buf) {
		h2c->flags |= H2_CF_DEM_DALLOC;
		return 0;
	}

	do {
		b_realign_if_empty(buf);
		if (!b_data(buf) && (h2c->proxy->options2 & PR_O2_USE_HTX)) {
			/* HTX in use : try to pre-align the buffer like the
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

		if (max)
			ret = conn->xprt->rcv_buf(conn, buf, max, 0);
		else
			ret = 0;
	} while (ret > 0);

	if (h2_recv_allowed(h2c) && (b_data(buf) < buf->size))
		conn->xprt->subscribe(conn, SUB_RETRY_RECV, &h2c->wait_event);

	if (!b_data(buf)) {
		h2_release_buf(h2c, &h2c->dbuf);
		return (conn->flags & CO_FL_ERROR || conn_xprt_read0_pending(conn));
	}

	if (b_data(buf) == buf->size)
		h2c->flags |= H2_CF_DEM_DFULL;
	return 1;
}

/* Try to send data if possible.
 * The function returns 1 if data have been sent, otherwise zero.
 */
static int h2_send(struct h2c *h2c)
{
	struct connection *conn = h2c->conn;
	int done;
	int sent = 0;

	if (conn->flags & CO_FL_ERROR)
		return 1;


	if (conn->flags & (CO_FL_HANDSHAKE|CO_FL_WAIT_L4_CONN|CO_FL_WAIT_L6_CONN)) {
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

		/* fill as much as we can into the current buffer */
		while (((h2c->flags & (H2_CF_MUX_MFULL|H2_CF_MUX_MALLOC)) == 0) && !done)
			done = h2_process_mux(h2c);

		if (h2c->flags & H2_CF_MUX_MALLOC)
			break;

		if (conn->flags & CO_FL_ERROR)
			break;

		if (h2c->flags & (H2_CF_MUX_MFULL | H2_CF_DEM_MBUSY | H2_CF_DEM_MROOM))
			flags |= CO_SFL_MSG_MORE;

		if (b_data(&h2c->mbuf)) {
			int ret = conn->xprt->snd_buf(conn, &h2c->mbuf, b_data(&h2c->mbuf), flags);
			if (!ret)
				break;
			sent = 1;
			b_del(&h2c->mbuf, ret);
			b_realign_if_empty(&h2c->mbuf);
		}

		/* wrote at least one byte, the buffer is not full anymore */
		h2c->flags &= ~(H2_CF_MUX_MFULL | H2_CF_DEM_MROOM);
	}

	if (conn->flags & CO_FL_SOCK_WR_SH) {
		/* output closed, nothing to send, clear the buffer to release it */
		b_reset(&h2c->mbuf);
	}
	/* We're not full anymore, so we can wake any task that are waiting
	 * for us.
	 */
	if (!(h2c->flags & (H2_CF_MUX_MFULL | H2_CF_DEM_MROOM))) {
		while (!LIST_ISEMPTY(&h2c->send_list)) {
			struct h2s *h2s = LIST_ELEM(h2c->send_list.n,
			    struct h2s *, list);
			LIST_DEL(&h2s->list);
			LIST_INIT(&h2s->list);
			LIST_ADDQ(&h2c->sending_list, &h2s->list);
			h2s->send_wait->events &= ~SUB_RETRY_SEND;
			h2s->send_wait->events |= SUB_CALL_UNSUBSCRIBE;
			tasklet_wakeup(h2s->send_wait->task);
		}
	}
	/* We're done, no more to send */
	if (!b_data(&h2c->mbuf))
		return sent;
schedule:
	if (!(h2c->wait_event.events & SUB_RETRY_SEND))
		conn->xprt->subscribe(conn, SUB_RETRY_SEND, &h2c->wait_event);
	return sent;
}

static struct task *h2_io_cb(struct task *t, void *ctx, unsigned short status)
{
	struct h2c *h2c = ctx;
	int ret = 0;

	if (!(h2c->wait_event.events & SUB_RETRY_SEND))
		ret = h2_send(h2c);
	if (!(h2c->wait_event.events & SUB_RETRY_RECV))
		ret |= h2_recv(h2c);
	if (ret || b_data(&h2c->dbuf))
		h2_process(h2c);
	return NULL;
}

/* callback called on any event by the connection handler.
 * It applies changes and returns zero, or < 0 if it wants immediate
 * destruction of the connection (which normally doesn not happen in h2).
 */
static int h2_process(struct h2c *h2c)
{
	struct connection *conn = h2c->conn;

	if (b_data(&h2c->dbuf) && !(h2c->flags & H2_CF_DEM_BLOCK_ANY)) {
		h2_process_demux(h2c);

		if (h2c->st0 >= H2_CS_ERROR || conn->flags & CO_FL_ERROR)
			b_reset(&h2c->dbuf);

		if (!b_full(&h2c->dbuf))
			h2c->flags &= ~H2_CF_DEM_DFULL;
	}
	h2_send(h2c);

	if (unlikely(h2c->proxy->state == PR_STSTOPPED)) {
		/* frontend is stopping, reload likely in progress, let's try
		 * to announce a graceful shutdown if not yet done. We don't
		 * care if it fails, it will be tried again later.
		 */
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
	    (conn->flags & (CO_FL_EARLY_SSL_HS | CO_FL_HANDSHAKE | CO_FL_EARLY_DATA)) == CO_FL_EARLY_DATA) {
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

	if (conn->flags & CO_FL_ERROR || conn_xprt_read0_pending(conn) ||
	    h2c->st0 == H2_CS_ERROR2 || h2c->flags & H2_CF_GOAWAY_FAILED ||
	    (eb_is_empty(&h2c->streams_by_id) && h2c->last_sid >= 0 &&
	     h2c->max_id >= h2c->last_sid)) {
		h2_wake_some_streams(h2c, 0, 0);

		if (eb_is_empty(&h2c->streams_by_id)) {
			/* no more stream, kill the connection now */
			h2_release(conn);
			return -1;
		}
	}

	if (!b_data(&h2c->dbuf))
		h2_release_buf(h2c, &h2c->dbuf);

	if ((conn->flags & CO_FL_SOCK_WR_SH) ||
	    h2c->st0 == H2_CS_ERROR2 || (h2c->flags & H2_CF_GOAWAY_FAILED) ||
	    (h2c->st0 != H2_CS_ERROR &&
	     !b_data(&h2c->mbuf) &&
	     (h2c->mws <= 0 || LIST_ISEMPTY(&h2c->fctl_list)) &&
	     ((h2c->flags & H2_CF_MUX_BLOCK_ANY) || LIST_ISEMPTY(&h2c->send_list))))
		h2_release_buf(h2c, &h2c->mbuf);

	if (h2c->task) {
		if (eb_is_empty(&h2c->streams_by_id) || b_data(&h2c->mbuf)) {
			h2c->task->expire = tick_add(now_ms, h2c->last_sid < 0 ? h2c->timeout : h2c->shut_timeout);
			task_queue(h2c->task);
		}
		else
			h2c->task->expire = TICK_ETERNITY;
	}

	h2_send(h2c);
	return 0;
}

static int h2_wake(struct connection *conn)
{
	struct h2c *h2c = conn->ctx;

	return (h2_process(h2c));
}

/* Connection timeout management. The principle is that if there's no receipt
 * nor sending for a certain amount of time, the connection is closed. If the
 * MUX buffer still has lying data or is not allocatable, the connection is
 * immediately killed. If it's allocatable and empty, we attempt to send a
 * GOAWAY frame.
 */
static struct task *h2_timeout_task(struct task *t, void *context, unsigned short state)
{
	struct h2c *h2c = context;
	int expired = tick_is_expired(t->expire, now_ms);

	if (!expired && h2c)
		return t;

	task_delete(t);
	task_free(t);

	if (!h2c) {
		/* resources were already deleted */
		return NULL;
	}

	h2c->task = NULL;
	h2c_error(h2c, H2_ERR_NO_ERROR);
	h2_wake_some_streams(h2c, 0, 0);

	if (b_data(&h2c->mbuf)) {
		/* don't even try to send a GOAWAY, the buffer is stuck */
		h2c->flags |= H2_CF_GOAWAY_FAILED;
	}

	/* try to send but no need to insist */
	h2c->last_sid = h2c->max_id;
	if (h2c_send_goaway_error(h2c, NULL) <= 0)
		h2c->flags |= H2_CF_GOAWAY_FAILED;

	if (b_data(&h2c->mbuf) && !(h2c->flags & H2_CF_GOAWAY_FAILED) && conn_xprt_ready(h2c->conn)) {
		int ret = h2c->conn->xprt->snd_buf(h2c->conn, &h2c->mbuf, b_data(&h2c->mbuf), 0);
		if (ret > 0) {
			b_del(&h2c->mbuf, ret);
			b_realign_if_empty(&h2c->mbuf);
		}
	}

	/* either we can release everything now or it will be done later once
	 * the last stream closes.
	 */
	if (eb_is_empty(&h2c->streams_by_id))
		h2_release(h2c->conn);

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

	cs = cs_new(conn);
	if (!cs)
		return NULL;
	h2s = h2c_bck_stream_new(h2c, cs, sess);
	if (!h2s) {
		cs_free(cs);
		return NULL;
	}
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

/*
 * Destroy the mux and the associated connection, if it is no longer used
 */
static void h2_destroy(struct connection *conn)
{
	struct h2c *h2c = conn->ctx;

	if (eb_is_empty(&h2c->streams_by_id))
		h2_release(h2c->conn);
}

/*
 * Detach the stream from the connection and possibly release the connection.
 */
static void h2_detach(struct conn_stream *cs)
{
	struct h2s *h2s = cs->ctx;
	struct h2c *h2c;
	struct session *sess;

	cs->ctx = NULL;
	if (!h2s)
		return;

	sess = h2s->sess;
	h2c = h2s->h2c;
	h2s->cs = NULL;
	h2c->nb_cs--;
	if (h2c->flags & H2_CF_DEM_TOOMANY &&
	    !h2_has_too_many_cs(h2c)) {
		h2c->flags &= ~H2_CF_DEM_TOOMANY;
		h2c_restart_reading(h2c);
	}

	/* this stream may be blocked waiting for some data to leave (possibly
	 * an ES or RST frame), so orphan it in this case.
	 */
	if (!(cs->conn->flags & CO_FL_ERROR) &&
	    (h2c->st0 < H2_CS_ERROR) &&
	    (h2s->flags & (H2_SF_BLK_MBUSY | H2_SF_BLK_MROOM | H2_SF_BLK_MFCTL)))
		return;

	if ((h2c->flags & H2_CF_DEM_BLOCK_ANY && h2s->id == h2c->dsi) ||
	    (h2c->flags & H2_CF_MUX_BLOCK_ANY && h2s->id == h2c->msi)) {
		/* unblock the connection if it was blocked on this
		 * stream.
		 */
		h2c->flags &= ~H2_CF_DEM_BLOCK_ANY;
		h2c->flags &= ~H2_CF_MUX_BLOCK_ANY;
		h2c_restart_reading(h2c);
	}

	h2s_destroy(h2s);

	if (h2c->flags & H2_CF_IS_BACK &&
	    (h2c->proxy->options2 & PR_O2_USE_HTX)) {
		if (!(h2c->conn->flags &
		    (CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH))) {
			if (!h2c->conn->owner) {
				h2c->conn->owner = sess;
				if (!session_add_conn(sess, h2c->conn, h2c->conn->target)) {
					h2c->conn->owner = NULL;
					if (eb_is_empty(&h2c->streams_by_id)) {
						if (!srv_add_to_idle_list(objt_server(h2c->conn->target), h2c->conn))
							/* The server doesn't want it, let's kill the connection right away */
							h2c->conn->mux->destroy(h2c->conn);
						return;
					}
				}
			}
			if (eb_is_empty(&h2c->streams_by_id)) {
				if (session_check_idle_conn(h2c->conn->owner, h2c->conn) != 0)
					/* At this point either the connection is destroyed, or it's been added to the server idle list, just stop */
					return;
			}
			/* Never ever allow to reuse a connection from a non-reuse backend */
			if ((h2c->proxy->options & PR_O_REUSE_MASK) == PR_O_REUSE_NEVR)
				h2c->conn->flags |= CO_FL_PRIVATE;
			if (LIST_ISEMPTY(&h2c->conn->list) && h2c->nb_streams < h2_settings_max_concurrent_streams) {
				struct server *srv = objt_server(h2c->conn->target);

				if (srv) {
					if (h2c->conn->flags & CO_FL_PRIVATE)
						LIST_ADD(&srv->priv_conns[tid], &h2c->conn->list);
					else
						LIST_ADD(&srv->idle_conns[tid], &h2c->conn->list);
				}

			}
		}
	}

	/* We don't want to close right now unless we're removing the
	 * last stream, and either the connection is in error, or it
	 * reached the ID already specified in a GOAWAY frame received
	 * or sent (as seen by last_sid >= 0).
	 */
	if (eb_is_empty(&h2c->streams_by_id) &&     /* don't close if streams exist */
	    ((h2c->conn->flags & CO_FL_ERROR) ||    /* errors close immediately */
	     (h2c->st0 >= H2_CS_ERROR && !h2c->task) || /* a timeout stroke earlier */
	     (h2c->flags & (H2_CF_GOAWAY_FAILED | H2_CF_GOAWAY_SENT)) ||
	     (!(h2c->conn->owner)) || /* Nobody's left to take care of the connection, drop it now */
	     (!b_data(&h2c->mbuf) &&  /* mux buffer empty, also process clean events below */
	      (conn_xprt_read0_pending(h2c->conn) ||
	       (h2c->last_sid >= 0 && h2c->max_id >= h2c->last_sid))))) {
		/* no more stream will come, kill it now */
		h2_release(h2c->conn);
	}
	else if (h2c->task) {
		if (eb_is_empty(&h2c->streams_by_id) || b_data(&h2c->mbuf)) {
			h2c->task->expire = tick_add(now_ms, h2c->last_sid < 0 ? h2c->timeout : h2c->shut_timeout);
			task_queue(h2c->task);
		}
		else
			h2c->task->expire = TICK_ETERNITY;
	}
}

static void h2_do_shutr(struct h2s *h2s)
{
	struct h2c *h2c = h2s->h2c;
	struct wait_event *sw = &h2s->wait_event;

	if (h2s->st == H2_SS_HLOC || h2s->st == H2_SS_ERROR || h2s->st == H2_SS_CLOSED)
		return;

	/* if no outgoing data was seen on this stream, it means it was
	 * closed with a "tcp-request content" rule that is normally
	 * used to kill the connection ASAP (eg: limit abuse). In this
	 * case we send a goaway to close the connection.
	 */
	if (!(h2s->flags & H2_SF_RST_SENT) &&
	    h2s_send_rst_stream(h2c, h2s) <= 0)
		goto add_to_list;

	if (!(h2s->flags & H2_SF_OUTGOING_DATA) &&
	    !(h2s->h2c->flags & (H2_CF_GOAWAY_SENT|H2_CF_GOAWAY_FAILED)) &&
	    h2c_send_goaway_error(h2c, h2s) <= 0)
		return;

	if (!(h2c->wait_event.events & SUB_RETRY_SEND))
		tasklet_wakeup(h2c->wait_event.task);
	h2s_close(h2s);

	return;
add_to_list:
	if (LIST_ISEMPTY(&h2s->list)) {
		sw->events |= SUB_RETRY_SEND;
		if (h2s->flags & H2_SF_BLK_MFCTL) {
			LIST_ADDQ(&h2c->fctl_list, &h2s->list);
			h2s->send_wait = sw;
		} else if (h2s->flags & (H2_SF_BLK_MBUSY|H2_SF_BLK_MROOM)) {
			h2s->send_wait = sw;
			LIST_ADDQ(&h2c->send_list, &h2s->list);
		}
	}
	/* Let the handler know we want shutr */
	sw->handle = (void *)((long)sw->handle | 1);

}

static void h2_do_shutw(struct h2s *h2s)
{
	struct h2c *h2c = h2s->h2c;
	struct wait_event *sw = &h2s->wait_event;

	if (h2s->st == H2_SS_HLOC || h2s->st == H2_SS_ERROR || h2s->st == H2_SS_CLOSED)
		return;

	if (h2s->flags & H2_SF_HEADERS_SENT) {
		/* we can cleanly close using an empty data frame only after headers */

		if (!(h2s->flags & (H2_SF_ES_SENT|H2_SF_RST_SENT)) &&
		    h2_send_empty_data_es(h2s) <= 0)
			goto add_to_list;

		if (h2s->st == H2_SS_HREM)
			h2s_close(h2s);
		else
			h2s->st = H2_SS_HLOC;
	} else {
		/* if no outgoing data was seen on this stream, it means it was
		 * closed with a "tcp-request content" rule that is normally
		 * used to kill the connection ASAP (eg: limit abuse). In this
		 * case we send a goaway to close the connection.
		 */
		if (!(h2s->flags & H2_SF_RST_SENT) &&
		    h2s_send_rst_stream(h2c, h2s) <= 0)
			goto add_to_list;

		if (!(h2s->flags & H2_SF_OUTGOING_DATA) &&
		    !(h2s->h2c->flags & (H2_CF_GOAWAY_SENT|H2_CF_GOAWAY_FAILED)) &&
		    h2c_send_goaway_error(h2c, h2s) <= 0)
			goto add_to_list;

		h2s_close(h2s);
	}

	if (!(h2c->wait_event.events & SUB_RETRY_SEND))
		tasklet_wakeup(h2c->wait_event.task);
	return;

 add_to_list:
	if (LIST_ISEMPTY(&h2s->list)) {
		sw->events |= SUB_RETRY_SEND;
		if (h2s->flags & H2_SF_BLK_MFCTL) {
			LIST_ADDQ(&h2c->fctl_list, &h2s->list);
			h2s->send_wait = sw;
		} else if (h2s->flags & (H2_SF_BLK_MBUSY|H2_SF_BLK_MROOM)) {
			h2s->send_wait = sw;
			LIST_ADDQ(&h2c->send_list, &h2s->list);
		}
	}
       /* let the handler know we want to shutw */
       sw->handle = (void *)((long)(sw->handle) | 2);

}

static struct task *h2_deferred_shut(struct task *t, void *ctx, unsigned short state)
{
	struct h2s *h2s = ctx;
	long reason = (long)h2s->wait_event.handle;

	if (h2s->send_wait) {
		h2s->send_wait->events &= ~SUB_CALL_UNSUBSCRIBE;
		h2s->send_wait = NULL;
		LIST_DEL(&h2s->list);
		LIST_INIT(&h2s->list);
	}
	if (reason & 2)
		h2_do_shutw(h2s);
	if (reason & 1)
		h2_do_shutr(h2s);

	if (h2s->st == H2_SS_CLOSED &&
	    !((h2s->flags & (H2_SF_BLK_MBUSY | H2_SF_BLK_MROOM | H2_SF_BLK_MFCTL))) && !h2s->cs)
		h2s_destroy(h2s);
	return NULL;
}

static void h2_shutr(struct conn_stream *cs, enum cs_shr_mode mode)
{
	struct h2s *h2s = cs->ctx;

	if (!mode)
		return;

	h2_do_shutr(h2s);
}

static void h2_shutw(struct conn_stream *cs, enum cs_shw_mode mode)
{
	struct h2s *h2s = cs->ctx;

	h2_do_shutw(h2s);
}

/* Decode the payload of a HEADERS frame and produce the equivalent HTTP/1 or
 * HTX request or response depending on the connection's side. Returns a
 * positive value on success, a negative value on failure, or 0 if it couldn't
 * proceed. May report connection errors in h2c->errcode if the frame is
 * non-decodable and the connection unrecoverable. In absence of connection
 * error when a failure is reported, the caller must assume a stream error.
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
 *   - H2_SF_DATA_CHNK when chunking should be used for the H1 conversion
 *   - H2_SF_HEADERS_RCVD once the frame is successfully decoded
 *
 * The H2_SF_HEADERS_RCVD flag is also looked at in the <flags> field prior to
 * decoding, in order to detect if we're dealing with a headers or a trailers
 * block (the trailers block appears after H2_SF_HEADERS_RCVD was seen).
 */
static int h2c_decode_headers(struct h2c *h2c, struct buffer *rxbuf, uint32_t *flags, unsigned long long *body_len)
{
	const uint8_t *hdrs = (uint8_t *)b_head(&h2c->dbuf);
	struct buffer *tmp = get_trash_chunk();
	struct http_hdr list[MAX_HTTP_HDR * 2];
	struct buffer *copy = NULL;
	unsigned int msgf;
	struct htx *htx = NULL;
	int flen; // header frame len
	int hole = 0;
	int ret = 0;
	int outlen;
	int wrap;
	int try = 0;

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

		if (!h2_peek_frame_hdr(&h2c->dbuf, h2c->dfl + hole, &hdr)) {
			/* no more data, the buffer may be full, either due to
			 * too large a frame or because of too large a hole that
			 * we're going to compact at the end.
			 */
			goto leave;
		}

		if (hdr.ft != H2_FT_CONTINUATION) {
			/* RFC7540#6.10: frame of unexpected type */
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			goto fail;
		}

		if (hdr.sid != h2c->dsi) {
			/* RFC7540#6.10: frame of different stream */
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			goto fail;
		}

		if ((unsigned)hdr.len > (unsigned)global.tune.bufsize) {
			/* RFC7540#4.2: invalid frame length */
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
		h2c->dfl += clen - h2c->dpl;
		hole     += h2c->dpl + 9;
		h2c->dpl  = 0;
		goto next_frame;
	}

	flen = h2c->dfl - h2c->dpl;

	/* if the input buffer wraps, take a temporary copy of it (rare) */
	wrap = b_wrap(&h2c->dbuf) - b_head(&h2c->dbuf);
	if (wrap < h2c->dfl) {
		copy = alloc_trash_chunk();
		if (!copy) {
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
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
			goto fail;
		}

		if (flen < 5) {
			h2c_error(h2c, H2_ERR_FRAME_SIZE_ERROR);
			goto fail;
		}

		hdrs += 5; // stream dep = 4, weight = 1
		flen -= 5;
	}

	if (!h2_get_buf(h2c, rxbuf)) {
		h2c->flags |= H2_CF_DEM_SALLOC;
		goto leave;
	}

	/* we can't retry a failed decompression operation so we must be very
	 * careful not to take any risks. In practice the output buffer is
	 * always empty except maybe for trailers, in which case we simply have
	 * to wait for the upper layer to finish consuming what is available.
	 */

	if (h2c->proxy->options2 & PR_O2_USE_HTX) {
		htx = htx_from_buf(rxbuf);
		if (!htx_is_empty(htx)) {
			h2c->flags |= H2_CF_DEM_SFULL;
			goto leave;
		}
	} else {
		if (b_data(rxbuf)) {
			h2c->flags |= H2_CF_DEM_SFULL;
			goto leave;
		}

		rxbuf->head = 0;
		try = b_size(rxbuf);
	}

	/* past this point we cannot roll back in case of error */
	outlen = hpack_decode_frame(h2c->ddht, hdrs, flen, list,
	                            sizeof(list)/sizeof(list[0]), tmp);
	if (outlen < 0) {
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

	if (*flags & H2_SF_HEADERS_RCVD)
		goto trailers;

	/* This is the first HEADERS frame so it's a headers block */
	if (htx) {
		/* HTX mode */
		if (h2c->flags & H2_CF_IS_BACK)
			outlen = h2_make_htx_response(list, htx, &msgf, body_len);
		else
			outlen = h2_make_htx_request(list, htx, &msgf, body_len);
	} else {
		/* HTTP/1 mode */
		outlen = h2_make_h1_request(list, b_tail(rxbuf), try, &msgf, body_len);
		if (outlen > 0)
			b_add(rxbuf, outlen);
	}

	if (outlen < 0) {
		/* too large headers? this is a stream error only */
		goto fail;
	}

	if (msgf & H2_MSGF_BODY) {
		/* a payload is present */
		if (msgf & H2_MSGF_BODY_CL)
			*flags |= H2_SF_DATA_CLEN;
		else if (!(msgf & H2_MSGF_BODY_TUNNEL) && !htx)
			*flags |= H2_SF_DATA_CHNK;
	}

 done:
	/* indicate that a HEADERS frame was received for this stream */
	*flags |= H2_SF_HEADERS_RCVD;

	if (h2c->dff & H2_F_HEADERS_END_STREAM) {
		/* Mark the end of message, either using EOM in HTX or with the
		 * trailing CRLF after the end of trailers. Note that DATA_CHNK
		 * is not set during headers with END_STREAM.
		 */
		if (htx) {
			if (!htx_add_endof(htx, HTX_BLK_EOM))
				goto fail;
		}
		else if (*flags & H2_SF_DATA_CHNK) {
			if (!b_putblk(rxbuf, "\r\n", 2))
				goto fail;
		}
	}

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

	if (b_full(&h2c->dbuf) && h2c->dfl > b_data(&h2c->dbuf)) {
		/* too large frames */
		h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
		ret = -1;
	}

	if (htx)
		htx_to_buf(htx, rxbuf);
	free_trash_chunk(copy);
	return ret;

 fail:
	ret = -1;
	goto leave;

 trailers:
	/* This is the last HEADERS frame hence a trailer */

	if (!(h2c->dff & H2_F_HEADERS_END_STREAM)) {
		/* It's a trailer but it's missing ES flag */
		h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
		goto fail;
	}

	/* Trailers terminate a DATA sequence. In HTX we have to emit an EOD
	 * block, and when using chunks we must send the 0 CRLF marker. For
	 * other modes, the trailers are silently dropped.
	 */
	if (htx) {
		if (!htx_add_endof(htx, HTX_BLK_EOD))
			goto fail;
		if (h2_make_htx_trailers(list, htx) <= 0)
			goto fail;
	}
	else if (*flags & H2_SF_DATA_CHNK) {
		/* Legacy mode with chunked encoding : we must finalize the
		 * data block message emit the trailing CRLF */
		if (!b_putblk(rxbuf, "0\r\n", 3))
			goto fail;

		outlen = h2_make_h1_trailers(list, b_tail(rxbuf), try);
		if (outlen > 0)
			b_add(rxbuf, outlen);
		else
			goto fail;
	}

	goto done;
}

/* Transfer the payload of a DATA frame to the HTTP/1 side. When content-length
 * or a tunnel is used, the contents are copied as-is. When chunked encoding is
 * in use, a new chunk is emitted for each frame. This is supposed to fit
 * because the smallest chunk takes 1 byte for the size, 2 for CRLF, X for the
 * data, 2 for the extra CRLF, so that's 5+X, while on the H2 side the smallest
 * frame will be 9+X bytes based on the same buffer size. The HTTP/2 frame
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
	int block1, block2;
	unsigned int flen = 0;
	unsigned int chklen = 0;
	struct htx *htx = NULL;
	struct buffer *csbuf;

	h2c->flags &= ~H2_CF_DEM_SFULL;

	csbuf = h2_get_buf(h2c, &h2s->rxbuf);
	if (!csbuf) {
		h2c->flags |= H2_CF_DEM_SALLOC;
		goto fail;
	}

try_again:
	flen = h2c->dfl - h2c->dpl;
	if (h2c->proxy->options2 & PR_O2_USE_HTX)
		htx = htx_from_buf(csbuf);
	if (!flen)
		goto end_transfer;

	if (flen > b_data(&h2c->dbuf)) {
		flen = b_data(&h2c->dbuf);
		if (!flen)
			goto fail;
	}

	if (h2c->proxy->options2 & PR_O2_USE_HTX) {
		block1 = htx_free_data_space(htx);
		if (!block1) {
			h2c->flags |= H2_CF_DEM_SFULL;
			goto fail;
		}
		if (flen > block1)
			flen = block1;

		/* here, flen is the max we can copy into the output buffer */
		block1 = b_contig_data(&h2c->dbuf, 0);
		if (flen > block1)
			flen = block1;

		if (!htx_add_data(htx, ist2(b_head(&h2c->dbuf), flen))) {
			h2c->flags |= H2_CF_DEM_SFULL;
			goto fail;
		}

		b_del(&h2c->dbuf, flen);
		h2c->dfl    -= flen;
		h2c->rcvd_c += flen;
		h2c->rcvd_s += flen;  // warning, this can also affect the closed streams!

		if (h2s->flags & H2_SF_DATA_CLEN)
			h2s->body_len -= flen;
		goto try_again;
	}
	else if (unlikely(b_space_wraps(csbuf))) {
		/* it doesn't fit and the buffer is fragmented,
		 * so let's defragment it and try again.
		 */
		b_slow_realign(csbuf, trash.area, 0);
	}

	/* chunked-encoding requires more room */
	if (h2s->flags & H2_SF_DATA_CHNK) {
		chklen = MIN(flen, b_room(csbuf));
		chklen = (chklen < 16) ? 1 : (chklen < 256) ? 2 :
			(chklen < 4096) ? 3 : (chklen < 65536) ? 4 :
			(chklen < 1048576) ? 4 : 8;
		chklen += 4; // CRLF, CRLF
	}

	/* does it fit in output buffer or should we wait ? */
	if (flen + chklen > b_room(csbuf)) {
		if (chklen >= b_room(csbuf)) {
			h2c->flags |= H2_CF_DEM_SFULL;
			goto fail;
		}
		flen = b_room(csbuf) - chklen;
	}

	if (h2s->flags & H2_SF_DATA_CHNK) {
		/* emit the chunk size */
		unsigned int chksz = flen;
		char str[10];
		char *beg;

		beg = str + sizeof(str);
		*--beg = '\n';
		*--beg = '\r';
		do {
			*--beg = hextab[chksz & 0xF];
		} while (chksz >>= 4);
		b_putblk(csbuf, beg, str + sizeof(str) - beg);
	}

	/* Block1 is the length of the first block before the buffer wraps,
	 * block2 is the optional second block to reach the end of the frame.
	 */
	block1 = b_contig_data(&h2c->dbuf, 0);
	if (block1 > flen)
		block1 = flen;
	block2 = flen - block1;

	if (block1)
		b_putblk(csbuf, b_head(&h2c->dbuf), block1);

	if (block2)
		b_putblk(csbuf, b_peek(&h2c->dbuf, block1), block2);

	if (h2s->flags & H2_SF_DATA_CHNK) {
		/* emit the CRLF */
		b_putblk(csbuf, "\r\n", 2);
	}

	/* now mark the input data as consumed (will be deleted from the buffer
	 * by the caller when seeing FRAME_A after sending the window update).
	 */
	b_del(&h2c->dbuf, flen);
	h2c->dfl    -= flen;
	h2c->rcvd_c += flen;
	h2c->rcvd_s += flen;  // warning, this can also affect the closed streams!

	if (h2s->flags & H2_SF_DATA_CLEN)
		h2s->body_len -= flen;

	if (h2c->dfl > h2c->dpl) {
		/* more data available, transfer stalled on stream full */
		h2c->flags |= H2_CF_DEM_SFULL;
		goto fail;
	}

 end_transfer:
	/* here we're done with the frame, all the payload (except padding) was
	 * transferred.
	 */

	if (h2c->dff & H2_F_DATA_END_STREAM) {
		if (htx) {
			if (!htx_add_endof(htx, HTX_BLK_EOM)) {
				h2c->flags |= H2_CF_DEM_SFULL;
				goto fail;
			}
		}
		else if (h2s->flags & H2_SF_DATA_CHNK) {
			/* emit the trailing 0 CRLF CRLF */
			if (b_room(csbuf) < 5) {
				h2c->flags |= H2_CF_DEM_SFULL;
				goto fail;
			}
			chklen += 5;
			b_putblk(csbuf, "0\r\n\r\n", 5);
		}
	}

	h2c->rcvd_c += h2c->dpl;
	h2c->rcvd_s += h2c->dpl;
	h2c->dpl = 0;
	h2c->st0 = H2_CS_FRAME_A; // send the corresponding window update

	if (h2c->dff & H2_F_DATA_END_STREAM) {
		h2s->flags |= H2_SF_ES_RCVD;
		h2s->cs->flags |= CS_FL_REOS;
	}
	if (htx)
		htx_to_buf(htx, csbuf);
	return 1;
 fail:
	if (htx)
		htx_to_buf(htx, csbuf);
	return 0;
}

/* Try to send a HEADERS frame matching HTTP/1 response present at offset <ofs>
 * and for <max> bytes in buffer <buf> for the H2 stream <h2s>. Returns the
 * number of bytes sent. The caller must check the stream's status to detect
 * any error which might have happened subsequently to a successful send.
 */
static size_t h2s_frt_make_resp_headers(struct h2s *h2s, const struct buffer *buf, size_t ofs, size_t max)
{
	struct http_hdr list[MAX_HTTP_HDR];
	struct h2c *h2c = h2s->h2c;
	struct h1m *h1m = &h2s->h1m;
	struct buffer outbuf;
	union h1_sl sl;
	int es_now = 0;
	int ret = 0;
	int hdr;

	if (h2c_mux_busy(h2c, h2s)) {
		h2s->flags |= H2_SF_BLK_MBUSY;
		return 0;
	}

	if (!h2_get_buf(h2c, &h2c->mbuf)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		return 0;
	}

	/* First, try to parse the H1 response and index it into <list>.
	 * NOTE! Since it comes from haproxy, we *know* that a response header
	 * block does not wrap and we can safely read it this way without
	 * having to realign the buffer.
	 */
	ret = h1_headers_to_hdr_list(b_peek(buf, ofs), b_peek(buf, ofs) + max,
	                             list, sizeof(list)/sizeof(list[0]), h1m, &sl);
	if (ret <= 0) {
		/* incomplete or invalid response, this is abnormal coming from
		 * haproxy and may only result in a bad errorfile or bad Lua code
		 * so that won't be fixed, raise an error now.
		 *
		 * FIXME: we should instead add the ability to only return a
		 * 502 bad gateway. But in theory this is not supposed to
		 * happen.
		 */
		h2s_error(h2s, H2_ERR_INTERNAL_ERROR);
		ret = 0;
		goto end;
	}

	h2s->status = sl.st.status;

	/* certain statuses have no body or an empty one, regardless of
	 * what the headers say.
	 */
	if (sl.st.status >= 100 && sl.st.status < 200) {
		h1m->flags &= ~(H1_MF_CLEN | H1_MF_CHNK);
		h1m->curr_len = h1m->body_len = 0;
	}
	else if (sl.st.status == 204 || sl.st.status == 304) {
		/* no contents, claim c-len is present and set to zero */
		h1m->flags &= ~H1_MF_CHNK;
		h1m->flags |=  H1_MF_CLEN;
		h1m->curr_len = h1m->body_len = 0;
	}

	chunk_reset(&outbuf);

	while (1) {
		outbuf.area  = b_tail(&h2c->mbuf);
		outbuf.size = b_contig_space(&h2c->mbuf);
		outbuf.data = 0;

		if (outbuf.size >= 9 || !b_space_wraps(&h2c->mbuf))
			break;
	realign_again:
		b_slow_realign(&h2c->mbuf, trash.area, b_data(&h2c->mbuf));
	}

	if (outbuf.size < 9)
		goto full;

	/* len: 0x000000 (fill later), type: 1(HEADERS), flags: ENDH=4 */
	memcpy(outbuf.area, "\x00\x00\x00\x01\x04", 5);
	write_n32(outbuf.area + 5, h2s->id); // 4 bytes
	outbuf.data = 9;

	/* encode status, which necessarily is the first one */
	if (unlikely(list[0].v.len != 3)) {
		/* this is an unparsable response */
		h2s_error(h2s, H2_ERR_INTERNAL_ERROR);
		ret = 0;
		goto end;
	}

	if (!hpack_encode_str_status(&outbuf, h2s->status, list[0].v)) {
		if (b_space_wraps(&h2c->mbuf))
			goto realign_again;
		goto full;
	}

	/* encode all headers, stop at empty name */
	for (hdr = 1; hdr < sizeof(list)/sizeof(list[0]); hdr++) {
		/* these ones do not exist in H2 and must be dropped. */
		if (isteq(list[hdr].n, ist("connection")) ||
		    isteq(list[hdr].n, ist("proxy-connection")) ||
		    isteq(list[hdr].n, ist("keep-alive")) ||
		    isteq(list[hdr].n, ist("upgrade")) ||
		    isteq(list[hdr].n, ist("transfer-encoding")))
			continue;

		if (isteq(list[hdr].n, ist("")))
			break; // end

		if (!hpack_encode_header(&outbuf, list[hdr].n, list[hdr].v)) {
			/* output full */
			if (b_space_wraps(&h2c->mbuf))
				goto realign_again;
			goto full;
		}
	}

	/* we may need to add END_STREAM */
	if (((h1m->flags & H1_MF_CLEN) && !h1m->body_len) || h2s->cs->flags & CS_FL_SHW)
		es_now = 1;

	/* update the frame's size */
	h2_set_frame_size(outbuf.area, outbuf.data - 9);

	if (es_now)
		outbuf.area[4] |= H2_F_HEADERS_END_STREAM;

	/* consume incoming H1 response */
	max -= ret;

	/* commit the H2 response */
	b_add(&h2c->mbuf, outbuf.data);
	h2s->flags |= H2_SF_HEADERS_SENT;

	if (es_now) {
		// trim any possibly pending data (eg: inconsistent content-length)
		ret += max;

		h1m->state = H1_MSG_DONE;
		h2s->flags |= H2_SF_ES_SENT;
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HLOC;
		else
			h2s_close(h2s);
	}
	else if (h2s->status >= 100 && h2s->status < 200) {
		/* we'll let the caller check if it has more headers to send */
		h1m_init_res(h1m);
		h1m->err_pos = -1; // don't care about errors on the response path
		h2s->h1m.flags |= H1_MF_TOLOWER;
		goto end;
	}

	/* now the h1m state is either H1_MSG_CHUNK_SIZE or H1_MSG_DATA */

 end:
	//fprintf(stderr, "[%d] sent simple H2 response (sid=%d) = %d bytes (%d in, ep=%u, es=%s)\n", h2c->st0, h2s->id, outbuf.len, ret, h1m->err_pos, h1m_state_str(h1m->err_state));
	return ret;
 full:
	h1m_init_res(h1m);
	h1m->err_pos = -1; // don't care about errors on the response path
	h2c->flags |= H2_CF_MUX_MFULL;
	h2s->flags |= H2_SF_BLK_MROOM;
	ret = 0;
	goto end;
}

/* Try to send a DATA frame matching HTTP/1 response present at offset <ofs>
 * for up to <max> bytes in response buffer <buf>, for stream <h2s>. Returns
 * the number of bytes sent. The caller must check the stream's status to
 * detect any error which might have happened subsequently to a successful send.
 */
static size_t h2s_frt_make_resp_data(struct h2s *h2s, const struct buffer *buf, size_t ofs, size_t max)
{
	struct h2c *h2c = h2s->h2c;
	struct h1m *h1m = &h2s->h1m;
	struct buffer outbuf;
	int ret = 0;
	size_t total = 0;
	int es_now = 0;
	int size = 0;
	const char *blk1, *blk2;
	size_t len1, len2;

	if (h2c_mux_busy(h2c, h2s)) {
		h2s->flags |= H2_SF_BLK_MBUSY;
		goto end;
	}

	if (!h2_get_buf(h2c, &h2c->mbuf)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		goto end;
	}

 new_frame:
	if (!max)
		goto end;

	chunk_reset(&outbuf);

	while (1) {
		outbuf.area  = b_tail(&h2c->mbuf);
		outbuf.size = b_contig_space(&h2c->mbuf);
		outbuf.data = 0;

		if (outbuf.size >= 9 || !b_space_wraps(&h2c->mbuf))
			break;
	realign_again:
		/* If there are pending data in the output buffer, and we have
		 * less than 1/4 of the mbuf's size and everything fits, we'll
		 * still perform a copy anyway. Otherwise we'll pretend the mbuf
		 * is full and wait, to save some slow realign calls.
		 */
		if ((max + 9 > b_room(&h2c->mbuf) || max >= b_size(&h2c->mbuf) / 4)) {
			h2c->flags |= H2_CF_MUX_MFULL;
			h2s->flags |= H2_SF_BLK_MROOM;
			goto end;
		}

		b_slow_realign(&h2c->mbuf, trash.area, b_data(&h2c->mbuf));
	}

	if (outbuf.size < 9) {
		h2c->flags |= H2_CF_MUX_MFULL;
		h2s->flags |= H2_SF_BLK_MROOM;
		goto end;
	}

	/* len: 0x000000 (fill later), type: 0(DATA), flags: none=0 */
	memcpy(outbuf.area, "\x00\x00\x00\x00\x00", 5);
	write_n32(outbuf.area + 5, h2s->id); // 4 bytes
	outbuf.data = 9;

	switch (h1m->flags & (H1_MF_CLEN|H1_MF_CHNK)) {
	case 0:           /* no content length, read till SHUTW */
		size = max;
		h1m->curr_len = size;
		break;
	case H1_MF_CLEN:  /* content-length: read only h2m->body_len */
		size = max;
		if ((long long)size > h1m->curr_len)
			size = h1m->curr_len;
		break;
	default:          /* te:chunked : parse chunks */
		if (h1m->state == H1_MSG_CHUNK_CRLF) {
			ret = h1_skip_chunk_crlf(buf, ofs, ofs + max);
			if (!ret)
				goto end;

			if (ret < 0) {
				/* FIXME: bad contents. how to proceed here when we're in H2 ? */
				h1m->err_pos = ofs + max + ret;
				h2s_error(h2s, H2_ERR_INTERNAL_ERROR);
				goto end;
			}
			max -= ret;
			ofs += ret;
			total += ret;
			h1m->state = H1_MSG_CHUNK_SIZE;
		}

		if (h1m->state == H1_MSG_CHUNK_SIZE) {
			unsigned int chunk;
			ret = h1_parse_chunk_size(buf, ofs, ofs + max, &chunk);
			if (!ret)
				goto end;

			if (ret < 0) {
				/* FIXME: bad contents. how to proceed here when we're in H2 ? */
				h1m->err_pos = ofs + max + ret;
				h2s_error(h2s, H2_ERR_INTERNAL_ERROR);
				goto end;
			}

			size = chunk;
			h1m->curr_len = chunk;
			h1m->body_len += chunk;
			max -= ret;
			ofs += ret;
			total += ret;
			h1m->state = size ? H1_MSG_DATA : H1_MSG_TRAILERS;
			if (!size)
				goto send_empty;
		}

		/* in MSG_DATA state, continue below */
		size = h1m->curr_len;
		break;
	}

	/* we have in <size> the exact number of bytes we need to copy from
	 * the H1 buffer. We need to check this against the connection's and
	 * the stream's send windows, and to ensure that this fits in the max
	 * frame size and in the buffer's available space minus 9 bytes (for
	 * the frame header). The connection's flow control is applied last so
	 * that we can use a separate list of streams which are immediately
	 * unblocked on window opening. Note: we don't implement padding.
	 */

	if (size > max)
		size = max;

	if (size > h2s->mws)
		size = h2s->mws;

	if (size <= 0) {
		h2s->flags |= H2_SF_BLK_SFCTL;
		if (h2s->send_wait) {
			LIST_DEL(&h2s->list);
			LIST_INIT(&h2s->list);
		}
		goto end;
	}

	if (h2c->mfs && size > h2c->mfs)
		size = h2c->mfs;

	if (size + 9 > outbuf.size) {
		/* we have an opportunity for enlarging the too small
		 * available space, let's try.
		 */
		if (b_space_wraps(&h2c->mbuf))
			goto realign_again;
		size = outbuf.size - 9;
	}

	if (size <= 0) {
		h2c->flags |= H2_CF_MUX_MFULL;
		h2s->flags |= H2_SF_BLK_MROOM;
		goto end;
	}

	if (size > h2c->mws)
		size = h2c->mws;

	if (size <= 0) {
		h2s->flags |= H2_SF_BLK_MFCTL;
		goto end;
	}

	/* copy whatever we can */
	blk1 = blk2 = NULL; // silence a maybe-uninitialized warning
	ret = b_getblk_nc(buf, &blk1, &len1, &blk2, &len2, ofs, max);
	if (ret == 1)
		len2 = 0;

	if (!ret || len1 + len2 < size) {
		/* FIXME: must normally never happen */
		h2s_error(h2s, H2_ERR_INTERNAL_ERROR);
		goto end;
	}

	/* limit len1/len2 to size */
	if (len1 + len2 > size) {
		int sub = len1 + len2 - size;

		if (len2 > sub)
			len2 -= sub;
		else {
			sub -= len2;
			len2 = 0;
			len1 -= sub;
		}
	}

	/* now let's copy this this into the output buffer */
	memcpy(outbuf.area + 9, blk1, len1);
	if (len2)
		memcpy(outbuf.area + 9 + len1, blk2, len2);

 send_empty:
	/* we may need to add END_STREAM */
	/* FIXME: we should also detect shutdown(w) below, but how ? Maybe we
	 * could rely on the MSG_MORE flag as a hint for this ?
	 *
	 * FIXME: what we do here is not correct because we send end_stream
	 * before knowing if we'll have to send a HEADERS frame for the
	 * trailers. More importantly we're not consuming the trailing CRLF
	 * after the end of trailers, so it will be left to the caller to
	 * eat it. The right way to do it would be to measure trailers here
	 * and to send ES only if there are no trailers.
	 *
	 */
	if (((h1m->flags & H1_MF_CLEN) && !(h1m->curr_len - size)) ||
	    !h1m->curr_len || h1m->state >= H1_MSG_DONE)
		es_now = 1;

	/* update the frame's size */
	h2_set_frame_size(outbuf.area, size);

	if (es_now)
		outbuf.area[4] |= H2_F_DATA_END_STREAM;

	/* commit the H2 response */
	b_add(&h2c->mbuf, size + 9);

	/* consume incoming H1 response */
	if (size > 0) {
		max -= size;
		ofs += size;
		total += size;
		h1m->curr_len -= size;
		h2s->mws -= size;
		h2c->mws -= size;

		if (size && !h1m->curr_len && (h1m->flags & H1_MF_CHNK)) {
			h1m->state = H1_MSG_CHUNK_CRLF;
			goto new_frame;
		}
	}

	if (es_now) {
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HLOC;
		else
			h2s_close(h2s);

		if (!(h1m->flags & H1_MF_CHNK)) {
			// trim any possibly pending data (eg: inconsistent content-length)
			total += max;
			ofs += max;
			max = 0;

			h1m->state = H1_MSG_DONE;
		}

		h2s->flags |= H2_SF_ES_SENT;
	}

 end:
	trace("[%d] sent simple H2 DATA response (sid=%d) = %d bytes out (%u in, st=%s, ep=%u, es=%s, h2cws=%d h2sws=%d) data=%u", h2c->st0, h2s->id, size+9, (unsigned int)total, h1m_state_str(h1m->state), h1m->err_pos, h1m_state_str(h1m->err_state), h2c->mws, h2s->mws, (unsigned int)b_data(buf));
	return total;
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
static size_t h2s_htx_frt_make_resp_headers(struct h2s *h2s, struct htx *htx)
{
	struct http_hdr list[MAX_HTTP_HDR];
	struct h2c *h2c = h2s->h2c;
	struct htx_blk *blk;
	struct htx_blk *blk_end;
	struct buffer outbuf;
	struct htx_sl *sl;
	enum htx_blk_type type;
	int es_now = 0;
	int ret = 0;
	int hdr;
	int idx;

	if (h2c_mux_busy(h2c, h2s)) {
		h2s->flags |= H2_SF_BLK_MBUSY;
		return 0;
	}

	if (!h2_get_buf(h2c, &h2c->mbuf)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		return 0;
	}

	/* determine the first block which must not be deleted, blk_end may
	 * be NULL if all blocks have to be deleted.
	 */
	idx = htx_get_head(htx);
	blk_end = NULL;
	while (idx != -1) {
		type = htx_get_blk_type(htx_get_blk(htx, idx));
		idx = htx_get_next(htx, idx);
		if (type == HTX_BLK_EOH) {
			if (idx != -1)
				blk_end = htx_get_blk(htx, idx);
			break;
		}
	}

	/* get the start line, we do have one */
	sl = htx_get_stline(htx);
	ALREADY_CHECKED(sl);
	h2s->status = sl->info.res.status;
	if (h2s->status < 100 || h2s->status > 999)
		goto fail;

	/* and the rest of the headers, that we dump starting at header 0 */
	hdr = 0;

	idx = htx_get_head(htx); // returns the SL that we skip
	while ((idx = htx_get_next(htx, idx)) != -1) {
		blk = htx_get_blk(htx, idx);
		type = htx_get_blk_type(blk);

		if (type == HTX_BLK_UNUSED)
			continue;

		if (type != HTX_BLK_HDR)
			break;

		if (unlikely(hdr >= sizeof(list)/sizeof(list[0]) - 1))
			goto fail;

		list[hdr].n = htx_get_blk_name(htx, blk);
		list[hdr].v = htx_get_blk_value(htx, blk);
		hdr++;
	}

	/* marker for end of headers */
	list[hdr].n = ist("");

	if (h2s->status == 204 || h2s->status == 304) {
		/* no contents, claim c-len is present and set to zero */
		es_now = 1;
	}

	chunk_reset(&outbuf);

	while (1) {
		outbuf.area  = b_tail(&h2c->mbuf);
		outbuf.size = b_contig_space(&h2c->mbuf);
		outbuf.data = 0;

		if (outbuf.size >= 9 || !b_space_wraps(&h2c->mbuf))
			break;
	realign_again:
		b_slow_realign(&h2c->mbuf, trash.area, b_data(&h2c->mbuf));
	}

	if (outbuf.size < 9)
		goto full;

	/* len: 0x000000 (fill later), type: 1(HEADERS), flags: ENDH=4 */
	memcpy(outbuf.area, "\x00\x00\x00\x01\x04", 5);
	write_n32(outbuf.area + 5, h2s->id); // 4 bytes
	outbuf.data = 9;

	/* encode status, which necessarily is the first one */
	if (!hpack_encode_int_status(&outbuf, h2s->status)) {
		if (b_space_wraps(&h2c->mbuf))
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

		if (isteq(list[hdr].n, ist("")))
			break; // end

		if (!hpack_encode_header(&outbuf, list[hdr].n, list[hdr].v)) {
			/* output full */
			if (b_space_wraps(&h2c->mbuf))
				goto realign_again;
			goto full;
		}
	}

	/* we may need to add END_STREAM.
	 * FIXME: we should also set it when we know for sure that the
	 * content-length is zero as well as on 204/304
	 */
	if (blk_end && htx_get_blk_type(blk_end) == HTX_BLK_EOM)
		es_now = 1;

	if (h2s->cs->flags & CS_FL_SHW)
		es_now = 1;

	/* update the frame's size */
	h2_set_frame_size(outbuf.area, outbuf.data - 9);

	if (es_now)
		outbuf.area[4] |= H2_F_HEADERS_END_STREAM;

	/* commit the H2 response */
	b_add(&h2c->mbuf, outbuf.data);
	h2s->flags |= H2_SF_HEADERS_SENT;

	if (es_now) {
		h2s->flags |= H2_SF_ES_SENT;
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HLOC;
		else
			h2s_close(h2s);
	}

	/* OK we could properly deliver the response */

	/* remove all header blocks including the EOH and compute the
	 * corresponding size.
	 *
	 * FIXME: We should remove everything when es_now is set.
	 */
	ret = 0;
	idx = htx_get_head(htx);
	blk = htx_get_blk(htx, idx);
	while (blk != blk_end) {
		ret += htx_get_blksz(blk);
		blk = htx_remove_blk(htx, blk);
	}

	if (blk_end && htx_get_blk_type(blk_end) == HTX_BLK_EOM)
		htx_remove_blk(htx, blk_end);
 end:
	return ret;
 full:
	h2c->flags |= H2_CF_MUX_MFULL;
	h2s->flags |= H2_SF_BLK_MROOM;
	ret = 0;
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
static size_t h2s_htx_bck_make_req_headers(struct h2s *h2s, struct htx *htx)
{
	struct http_hdr list[MAX_HTTP_HDR];
	struct h2c *h2c = h2s->h2c;
	struct htx_blk *blk;
	struct htx_blk *blk_end;
	struct buffer outbuf;
	struct htx_sl *sl;
	struct ist meth, path;
	enum htx_blk_type type;
	int es_now = 0;
	int ret = 0;
	int hdr;
	int idx;

	if (h2c_mux_busy(h2c, h2s)) {
		h2s->flags |= H2_SF_BLK_MBUSY;
		return 0;
	}

	if (!h2_get_buf(h2c, &h2c->mbuf)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		return 0;
	}

	/* determine the first block which must not be deleted, blk_end may
	 * be NULL if all blocks have to be deleted.
	 */
	idx = htx_get_head(htx);
	blk_end = NULL;
	while (idx != -1) {
		type = htx_get_blk_type(htx_get_blk(htx, idx));
		idx = htx_get_next(htx, idx);
		if (type == HTX_BLK_EOH) {
			if (idx != -1)
				blk_end = htx_get_blk(htx, idx);
			break;
		}
	}

	/* get the start line, we do have one */
	sl = htx_get_stline(htx);
	ALREADY_CHECKED(sl);
	meth = htx_sl_req_meth(sl);
	path = htx_sl_req_uri(sl);

	/* and the rest of the headers, that we dump starting at header 0 */
	hdr = 0;

	idx = htx_get_head(htx); // returns the SL that we skip
	while ((idx = htx_get_next(htx, idx)) != -1) {
		blk = htx_get_blk(htx, idx);
		type = htx_get_blk_type(blk);

		if (type == HTX_BLK_UNUSED)
			continue;

		if (type != HTX_BLK_HDR)
			break;

		if (unlikely(hdr >= sizeof(list)/sizeof(list[0]) - 1))
			goto fail;

		list[hdr].n = htx_get_blk_name(htx, blk);
		list[hdr].v = htx_get_blk_value(htx, blk);
		hdr++;
	}

	/* marker for end of headers */
	list[hdr].n = ist("");

	chunk_reset(&outbuf);

	while (1) {
		outbuf.area  = b_tail(&h2c->mbuf);
		outbuf.size = b_contig_space(&h2c->mbuf);
		outbuf.data = 0;

		if (outbuf.size >= 9 || !b_space_wraps(&h2c->mbuf))
			break;
	realign_again:
		b_slow_realign(&h2c->mbuf, trash.area, b_data(&h2c->mbuf));
	}

	if (outbuf.size < 9)
		goto full;

	/* len: 0x000000 (fill later), type: 1(HEADERS), flags: ENDH=4 */
	memcpy(outbuf.area, "\x00\x00\x00\x01\x04", 5);
	write_n32(outbuf.area + 5, h2s->id); // 4 bytes
	outbuf.data = 9;

	/* encode the method, which necessarily is the first one */
	if (!hpack_encode_method(&outbuf, sl->info.req.meth, meth)) {
		if (b_space_wraps(&h2c->mbuf))
			goto realign_again;
		goto full;
	}

	/* encode the scheme which is always "https" (or 0x86 for "http") */
	if (!hpack_encode_scheme(&outbuf, ist("https"))) {
		/* output full */
		if (b_space_wraps(&h2c->mbuf))
			goto realign_again;
		goto full;
	}

	/* encode the path, which necessarily is the second one */
	if (!hpack_encode_path(&outbuf, path)) {
		/* output full */
		if (b_space_wraps(&h2c->mbuf))
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

		if (isteq(list[hdr].n, ist("")))
			break; // end

		if (!hpack_encode_header(&outbuf, list[hdr].n, list[hdr].v)) {
			/* output full */
			if (b_space_wraps(&h2c->mbuf))
				goto realign_again;
			goto full;
		}
	}

	/* we may need to add END_STREAM if we have no body :
	 *  - request already closed, or :
	 *  - no transfer-encoding, and :
	 *  - no content-length or content-length:0
	 * Fixme: this doesn't take into account CONNECT requests.
	 */
	if (blk_end && htx_get_blk_type(blk_end) == HTX_BLK_EOM)
		es_now = 1;

	if (sl->flags & HTX_SL_F_BODYLESS)
		es_now = 1;

	if (h2s->cs->flags & CS_FL_SHW)
		es_now = 1;

	/* update the frame's size */
	h2_set_frame_size(outbuf.area, outbuf.data - 9);

	if (es_now)
		outbuf.area[4] |= H2_F_HEADERS_END_STREAM;

	/* commit the H2 response */
	b_add(&h2c->mbuf, outbuf.data);
	h2s->flags |= H2_SF_HEADERS_SENT;
	h2s->st = H2_SS_OPEN;

	if (es_now) {
		// trim any possibly pending data (eg: inconsistent content-length)
		h2s->flags |= H2_SF_ES_SENT;
		h2s->st = H2_SS_HLOC;
	}

	/* remove all header blocks including the EOH and compute the
	 * corresponding size.
	 *
	 * FIXME: We should remove everything when es_now is set.
	 */
	ret = 0;
	idx = htx_get_head(htx);
	blk = htx_get_blk(htx, idx);
	while (blk != blk_end) {
		ret += htx_get_blksz(blk);
		blk = htx_remove_blk(htx, blk);
	}

	if (blk_end && htx_get_blk_type(blk_end) == HTX_BLK_EOM)
		htx_remove_blk(htx, blk_end);

 end:
	return ret;
 full:
	h2c->flags |= H2_CF_MUX_MFULL;
	h2s->flags |= H2_SF_BLK_MROOM;
	ret = 0;
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
 * consumed, or zero if nothing done. Note that EOD/EOM count for 1 byte.
 */
static size_t h2s_htx_frt_make_resp_data(struct h2s *h2s, struct buffer *buf, size_t count)
{
	struct h2c *h2c = h2s->h2c;
	struct htx *htx;
	struct buffer outbuf;
	size_t total = 0;
	int es_now = 0;
	int bsize; /* htx block size */
	int fsize; /* h2 frame size  */
	struct htx_blk *blk;
	enum htx_blk_type type;
	int idx;

	if (h2c_mux_busy(h2c, h2s)) {
		h2s->flags |= H2_SF_BLK_MBUSY;
		goto end;
	}

	if (!h2_get_buf(h2c, &h2c->mbuf)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		goto end;
	}

	htx = htx_from_buf(buf);

	/* We only come here with HTX_BLK_DATA or HTX_BLK_EOD blocks. However,
	 * while looping, we can meet an HTX_BLK_EOM block that we'll leave to
	 * the caller to handle.
	 */

 new_frame:
	if (!count || htx_is_empty(htx))
		goto end;

	idx   = htx_get_head(htx);
	blk   = htx_get_blk(htx, idx);
	type  = htx_get_blk_type(blk); // DATA or EOD or EOM
	bsize = htx_get_blksz(blk);
	fsize = bsize;

	if (type == HTX_BLK_EOD) {
		/* if we have an EOD, we're dealing with chunked data. We may
		 * have a set of trailers after us that the caller will want to
		 * deal with. Let's simply remove the EOD and return.
		 */
		htx_remove_blk(htx, blk);
		total++; // EOD counts as one byte
		count--;
		goto end;
	}
	else if (type == HTX_BLK_EOM) {
		if (h2s->flags & H2_SF_ES_SENT) {
			/* ES already sent */
			htx_remove_blk(htx, blk);
			total++; // EOM counts as one byte
			count--;
			goto end;
		}
	}
	else if (type != HTX_BLK_DATA)
		goto end;

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
	             htx->used == 1 && type == HTX_BLK_DATA &&
	             fsize <= h2s->mws && fsize <= h2c->mws && fsize <= h2c->mfs)) {
		void *old_area = h2c->mbuf.area;

		if (b_data(&h2c->mbuf)) {
			/* too bad there are data left there. If we have less
			 * than 1/4 of the mbuf's size and everything fits,
			 * we'll perform a copy anyway. Otherwise we'll pretend
			 * the mbuf is full and wait.
			 */
			if (fsize <= b_size(&h2c->mbuf) / 4 && fsize + 9 <= b_room(&h2c->mbuf))
				goto copy;
			h2c->flags |= H2_CF_MUX_MFULL;
			h2s->flags |= H2_SF_BLK_MROOM;
			goto end;
		}

		/* map an H2 frame to the HTX block so that we can put the
		 * frame header there.
		 */
		h2c->mbuf.area = buf->area;
		h2c->mbuf.head = sizeof(struct htx) + blk->addr - 9;
		h2c->mbuf.data = fsize + 9;
		outbuf.area    = b_head(&h2c->mbuf);

		/* prepend an H2 DATA frame header just before the DATA block */
		memcpy(outbuf.area, "\x00\x00\x00\x00\x00", 5);
		write_n32(outbuf.area + 5, h2s->id); // 4 bytes
		h2_set_frame_size(outbuf.area, fsize);

		/* update windows */
		h2s->mws -= fsize;
		h2c->mws -= fsize;

		/* and exchange with our old area */
		buf->area = old_area;
		buf->data = buf->head = 0;
		total += fsize;
		goto end;
	}

 copy:
	/* for DATA and EOM we'll have to emit a frame, even if empty */

	while (1) {
		outbuf.area  = b_tail(&h2c->mbuf);
		outbuf.size = b_contig_space(&h2c->mbuf);
		outbuf.data = 0;

		if (outbuf.size >= 9 || !b_space_wraps(&h2c->mbuf))
			break;
	realign_again:
		b_slow_realign(&h2c->mbuf, trash.area, b_data(&h2c->mbuf));
	}

	if (outbuf.size < 9) {
		h2c->flags |= H2_CF_MUX_MFULL;
		h2s->flags |= H2_SF_BLK_MROOM;
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

	/* EOM is presented with bsize==1 but would lead to the emission of an
	 * empty frame, thus we force it to zero here.
	 */
	if (type == HTX_BLK_EOM)
		bsize = fsize = 0;

	if (!fsize)
		goto send_empty;

	if (h2s->mws <= 0) {
		h2s->flags |= H2_SF_BLK_SFCTL;
		if (h2s->send_wait) {
			LIST_DEL(&h2s->list);
			LIST_INIT(&h2s->list);
		}
		goto end;
	}

	if (fsize > count)
		fsize = count;

	if (fsize > h2s->mws)
		fsize = h2s->mws; // >0

	if (h2c->mfs && fsize > h2c->mfs)
		fsize = h2c->mfs; // >0

	if (fsize + 9 > outbuf.size) {
		/* we have an opportunity for enlarging the too small
		 * available space, let's try.
		 * FIXME: is this really interesting to do? Maybe we'll
		 * spend lots of time realigning instead of using two
		 * frames.
		 */
		if (b_space_wraps(&h2c->mbuf))
			goto realign_again;
		fsize = outbuf.size - 9;

		if (fsize <= 0) {
			/* no need to send an empty frame here */
			h2c->flags |= H2_CF_MUX_MFULL;
			h2s->flags |= H2_SF_BLK_MROOM;
			goto end;
		}
	}

	if (h2c->mws <= 0) {
		h2s->flags |= H2_SF_BLK_MFCTL;
		goto end;
	}

	if (fsize > h2c->mws)
		fsize = h2c->mws;

	/* now let's copy this this into the output buffer */
	memcpy(outbuf.area + 9, htx_get_blk_ptr(htx, blk), fsize);
	h2s->mws -= fsize;
	h2c->mws -= fsize;
	count    -= fsize;

 send_empty:
	/* update the frame's size */
	h2_set_frame_size(outbuf.area, fsize);

	/* FIXME: for now we only set the ES flag on empty DATA frames, once
	 * meeting EOM. We should optimize this later.
	 */
	if (type == HTX_BLK_EOM) {
		total++; // EOM counts as one byte
		count--;
		es_now = 1;
	}

	if (es_now)
		outbuf.area[4] |= H2_F_DATA_END_STREAM;

	/* commit the H2 response */
	b_add(&h2c->mbuf, fsize + 9);

	/* consume incoming HTX block, including EOM */
	total += fsize;
	if (fsize == bsize) {
		htx_remove_blk(htx, blk);
		if (fsize)
			goto new_frame;
	} else {
		/* we've truncated this block */
		htx_cut_data_blk(htx, blk, fsize);
	}

	if (es_now) {
		if (h2s->st == H2_SS_OPEN)
			h2s->st = H2_SS_HLOC;
		else
			h2s_close(h2s);

		h2s->flags |= H2_SF_ES_SENT;
	}

 end:
	return total;
}

/* Try to send a HEADERS frame matching HTX_BLK_TLR series of blocks present in
 * HTX message <htx> for the H2 stream <h2s>. Returns the number of bytes
 * processed. The caller must check the stream's status to detect any error
 * which might have happened subsequently to a successful send. The htx blocks
 * are automatically removed from the message. The htx message is assumed to be
 * valid since produced from the internal code. Processing stops when meeting
 * the EOM, which is also removed. All trailers are processed at once and sent
 * as a single frame. The ES flag is always set.
 */
static size_t h2s_htx_make_trailers(struct h2s *h2s, struct htx *htx)
{
	struct http_hdr list[MAX_HTTP_HDR];
	struct h2c *h2c = h2s->h2c;
	struct htx_blk *blk;
	struct htx_blk *blk_end;
	struct buffer outbuf;
	struct h1m h1m;
	enum htx_blk_type type;
	uint32_t size;
	int ret = 0;
	int hdr;
	int idx;
	void *start;

	if (h2c_mux_busy(h2c, h2s)) {
		h2s->flags |= H2_SF_BLK_MBUSY;
		goto end;
	}

	if (!h2_get_buf(h2c, &h2c->mbuf)) {
		h2c->flags |= H2_CF_MUX_MALLOC;
		h2s->flags |= H2_SF_BLK_MROOM;
		goto end;
	}

	/* The principle is that we parse each and every trailers block using
	 * the H1 headers parser, and append it to the list. We don't proceed
	 * until EOM is met. blk_end will point to the EOM block.
	 */
	hdr = 0;
	memset(list, 0, sizeof(list));
	blk_end = NULL;

	for (idx = htx_get_head(htx); idx != -1; idx = htx_get_next(htx, idx)) {
		blk = htx_get_blk(htx, idx);
		type = htx_get_blk_type(blk);

		if (type == HTX_BLK_UNUSED)
			continue;

		if (type != HTX_BLK_TLR) {
			if (type == HTX_BLK_EOM)
				blk_end = blk;
			break;
		}

		if (unlikely(hdr >= sizeof(list)/sizeof(list[0]) - 1))
			goto fail;

		size = htx_get_blksz(blk);
		start = htx_get_blk_ptr(htx, blk);

		h1m.flags = H1_MF_HDRS_ONLY | H1_MF_TOLOWER;
		h1m.err_pos = 0;
		ret = h1_headers_to_hdr_list(start, start + size,
					     list + hdr, sizeof(list)/sizeof(list[0]) - hdr,
					     &h1m, NULL);
		if (ret < 0)
			goto fail;

		/* ret == 0 if an incomplete trailers block was found (missing
		 * empty line), or > 0 if it was found. We have to continue on
		 * incomplete messages because the trailers block might be
		 * incomplete.
		 */

		/* search the new end */
		while (hdr <= sizeof(list)/sizeof(list[0])) {
			if (!list[hdr].n.len)
				break;
			hdr++;
		}
	}

	if (!blk_end)
		goto end; // end not found yet

	if (!hdr)
		goto done;

	chunk_reset(&outbuf);

	while (1) {
		outbuf.area  = b_tail(&h2c->mbuf);
		outbuf.size = b_contig_space(&h2c->mbuf);
		outbuf.data = 0;

		if (outbuf.size >= 9 || !b_space_wraps(&h2c->mbuf))
			break;
	realign_again:
		b_slow_realign(&h2c->mbuf, trash.area, b_data(&h2c->mbuf));
	}

	if (outbuf.size < 9)
		goto full;

	/* len: 0x000000 (fill later), type: 1(HEADERS), flags: ENDH=4,ES=1 */
	memcpy(outbuf.area, "\x00\x00\x00\x01\x05", 5);
	write_n32(outbuf.area + 5, h2s->id); // 4 bytes
	outbuf.data = 9;

	/* encode status, which necessarily is the first one */
	if (!hpack_encode_int_status(&outbuf, h2s->status)) {
		if (b_space_wraps(&h2c->mbuf))
			goto realign_again;
		goto full;
	}

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

		if (!hpack_encode_header(&outbuf, list[idx].n, list[idx].v)) {
			/* output full */
			if (b_space_wraps(&h2c->mbuf))
				goto realign_again;
			goto full;
		}
	}

	/* update the frame's size */
	h2_set_frame_size(outbuf.area, outbuf.data - 9);

	/* commit the H2 response */
	b_add(&h2c->mbuf, outbuf.data);
	h2s->flags |= H2_SF_ES_SENT;

	if (h2s->st == H2_SS_OPEN)
		h2s->st = H2_SS_HLOC;
	else
		h2s_close(h2s);

	/* OK we could properly deliver the response */
 done:
	/* remove all header blocks including EOM and compute the corresponding size. */
	ret = 0;
	idx = htx_get_head(htx);
	blk = htx_get_blk(htx, idx);
	while (blk != blk_end) {
		ret += htx_get_blksz(blk);
		blk = htx_remove_blk(htx, blk);
	}
	blk = htx_remove_blk(htx, blk);
 end:
	return ret;
 full:
	h2c->flags |= H2_CF_MUX_MFULL;
	h2s->flags |= H2_SF_BLK_MROOM;
	ret = 0;
	goto end;
 fail:
	/* unparsable HTX messages, too large ones to be produced in the local
	 * list etc go here (unrecoverable errors).
	 */
	h2s_error(h2s, H2_ERR_INTERNAL_ERROR);
	ret = 0;
	goto end;
}

/* Called from the upper layer, to subscribe to events, such as being able to send */
static int h2_subscribe(struct conn_stream *cs, int event_type, void *param)
{
	struct wait_event *sw;
	struct h2s *h2s = cs->ctx;
	struct h2c *h2c = h2s->h2c;

	if (event_type & SUB_RETRY_RECV) {
		sw = param;
		if (!(sw->events & SUB_RETRY_RECV)) {
			sw->events |= SUB_RETRY_RECV;
			sw->handle = h2s;
			h2s->recv_wait = sw;
		}
		event_type &= ~SUB_RETRY_RECV;
	}
	if (event_type & SUB_RETRY_SEND) {
		sw = param;
		if (!(sw->events & SUB_RETRY_SEND)) {
			sw->events |= SUB_RETRY_SEND;
			sw->handle = h2s;
			h2s->send_wait = sw;
			if (!(h2s->flags & H2_SF_BLK_SFCTL)) {
				if (h2s->flags & H2_SF_BLK_MFCTL)
					LIST_ADDQ(&h2c->fctl_list, &h2s->list);
				else
					LIST_ADDQ(&h2c->send_list, &h2s->list);
			}
		}
		event_type &= ~SUB_RETRY_SEND;
	}
	if (event_type != 0)
		return -1;
	return 0;


}

static int h2_unsubscribe(struct conn_stream *cs, int event_type, void *param)
{
	struct wait_event *sw;
	struct h2s *h2s = cs->ctx;

	if (event_type & SUB_RETRY_RECV) {
		sw = param;
		if (h2s->recv_wait == sw) {
			sw->events &= ~SUB_RETRY_RECV;
			h2s->recv_wait = NULL;
		}
	}
	if (event_type & SUB_RETRY_SEND) {
		sw = param;
		if (h2s->send_wait == sw) {
			LIST_DEL(&h2s->list);
			LIST_INIT(&h2s->list);
			sw->events &= ~SUB_RETRY_SEND;
			h2s->send_wait = NULL;
		}
	}
	if (event_type & SUB_CALL_UNSUBSCRIBE) {
		sw = param;
		if (h2s->send_wait == sw) {
			sw->events &= ~SUB_CALL_UNSUBSCRIBE;
			h2s->send_wait = NULL;
			LIST_DEL(&h2s->list);
			LIST_INIT(&h2s->list);
		}
	}
	return 0;
}


/* Called from the upper layer, to receive data */
static size_t h2_rcv_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	struct h2s *h2s = cs->ctx;
	struct h2c *h2c = h2s->h2c;
	struct htx *h2s_htx = NULL;
	struct htx *buf_htx = NULL;
	struct htx_ret htx_ret;
	size_t ret = 0;

	/* transfer possibly pending data to the upper layer */
	if (h2c->proxy->options2 & PR_O2_USE_HTX) {
		/* in HTX mode we ignore the count argument */
		h2s_htx = htx_from_buf(&h2s->rxbuf);
		if (htx_is_empty(h2s_htx)) {
			if (cs->flags & CS_FL_REOS)
				cs->flags |= CS_FL_EOS;
			if (cs->flags & CS_FL_ERR_PENDING)
				cs->flags |= CS_FL_ERROR;
			goto end;
		}

		buf_htx = htx_from_buf(buf);
		count = htx_free_data_space(buf_htx);
		if (flags & CO_RFL_KEEP_RSV) {
			if (count <= global.tune.maxrewrite)
				goto end;
			count -= global.tune.maxrewrite;
		}

		htx_ret = htx_xfer_blks(buf_htx, h2s_htx, count, HTX_BLK_EOM);

		buf_htx->extra = h2s_htx->extra;
		htx_to_buf(buf_htx, buf);
		htx_to_buf(h2s_htx, &h2s->rxbuf);
		ret = htx_ret.ret;
	}
	else {
		ret = b_xfer(buf, &h2s->rxbuf, count);
	}

	if (b_data(&h2s->rxbuf))
		cs->flags |= (CS_FL_RCV_MORE | CS_FL_WANT_ROOM);
	else {
		cs->flags &= ~(CS_FL_RCV_MORE | CS_FL_WANT_ROOM);
		if (cs->flags & CS_FL_REOS)
			cs->flags |= CS_FL_EOS;
		if (cs->flags & CS_FL_ERR_PENDING)
			cs->flags |= CS_FL_ERROR;
		if (b_size(&h2s->rxbuf)) {
			b_free(&h2s->rxbuf);
			offer_buffers(NULL, tasks_run_queue);
		}
	}

	if (ret && h2c->dsi == h2s->id) {
		/* demux is blocking on this stream's buffer */
		h2c->flags &= ~H2_CF_DEM_SFULL;
		h2c_restart_reading(h2c);
	}
end:
	return ret;
}

static void h2_stop_senders(struct h2c *h2c)
{
	struct h2s *h2s, *h2s_back;

	list_for_each_entry_safe(h2s, h2s_back, &h2c->sending_list, list) {
		/* Don't unschedule the stream if the mux is just busy waiting for more data fro mthat stream */
		if (h2c->msi == h2s_id(h2s))
			continue;
		LIST_DEL(&h2s->list);
		LIST_INIT(&h2s->list);
		task_remove_from_task_list((struct task *)h2s->send_wait->task);
		h2s->send_wait->events |= SUB_RETRY_SEND;
		h2s->send_wait->events &= ~SUB_CALL_UNSUBSCRIBE;
		LIST_ADD(&h2c->send_list, &h2s->list);
	}
}

/* Called from the upper layer, to send data */
static size_t h2_snd_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	struct h2s *h2s = cs->ctx;
	size_t orig_count = count;
	size_t total = 0;
	size_t ret;
	struct htx *htx;
	struct htx_blk *blk;
	enum htx_blk_type btype;
	uint32_t bsize;
	int32_t idx;

	if (h2s->send_wait) {
		h2s->send_wait->events &= ~SUB_CALL_UNSUBSCRIBE;
		h2s->send_wait = NULL;
		LIST_DEL(&h2s->list);
		LIST_INIT(&h2s->list);
	}
	if (h2s->h2c->st0 < H2_CS_FRAME_H)
		return 0;

	/* htx will be enough to decide if we're using HTX or legacy */
	htx = (h2s->h2c->proxy->options2 & PR_O2_USE_HTX) ? htx_from_buf(buf) : NULL;

	if (!(h2s->flags & H2_SF_OUTGOING_DATA) && count)
		h2s->flags |= H2_SF_OUTGOING_DATA;

	if (h2s->id == 0) {
		int32_t id = h2c_get_next_sid(h2s->h2c);

		if (id < 0) {
			cs->flags |= CS_FL_ERROR;
			return 0;
		}

		eb32_delete(&h2s->by_id);
		h2s->by_id.key = h2s->id = id;
		h2s->h2c->max_id = id;
		h2s->h2c->nb_reserved--;
		eb32_insert(&h2s->h2c->streams_by_id, &h2s->by_id);
	}

	if (htx) {
		while (h2s->st < H2_SS_ERROR && !(h2s->flags & H2_SF_BLK_ANY) &&
		       count && !htx_is_empty(htx)) {
			idx   = htx_get_head(htx);
			blk   = htx_get_blk(htx, idx);
			btype = htx_get_blk_type(blk);
			bsize = htx_get_blksz(blk);

			switch (btype) {
			case HTX_BLK_REQ_SL:
				/* start-line before headers */
				ret = h2s_htx_bck_make_req_headers(h2s, htx);
				if (ret > 0) {
					total += ret;
					count -= ret;
					if (ret < bsize)
						goto done;
				}
				break;

			case HTX_BLK_RES_SL:
				/* start-line before headers */
				ret = h2s_htx_frt_make_resp_headers(h2s, htx);
				if (ret > 0) {
					total += ret;
					count -= ret;
					if (ret < bsize)
						goto done;
				}
				break;

			case HTX_BLK_DATA:
			case HTX_BLK_EOD:
			case HTX_BLK_EOM:
				/* all these cause the emission of a DATA frame (possibly empty).
				 * This EOM necessarily is one before trailers, as the EOM following
				 * trailers would have been consumed by the trailers parser.
				 */
				ret = h2s_htx_frt_make_resp_data(h2s, buf, count);
				if (ret > 0) {
					htx = htx_from_buf(buf);
					total += ret;
					count -= ret;
					if (ret < bsize)
						goto done;
				}
				break;

			case HTX_BLK_TLR:
				/* This is the first trailers block, all the subsequent ones AND
				 * the EOM will be swallowed by the parser.
				 */
				ret = h2s_htx_make_trailers(h2s, htx);
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
		goto done;
	}

	/* legacy transfer mode */
	while (h2s->h1m.state < H1_MSG_DONE && count) {
		if (h2s->h1m.state <= H1_MSG_LAST_LF) {
			if (h2s->h2c->flags & H2_CF_IS_BACK)
				ret = -1;
			else
				ret = h2s_frt_make_resp_headers(h2s, buf, total, count);
		}
		else if (h2s->h1m.state < H1_MSG_TRAILERS) {
			ret = h2s_frt_make_resp_data(h2s, buf, total, count);
		}
		else if (h2s->h1m.state == H1_MSG_TRAILERS) {
			/* consume the trailers if any (we don't forward them for now) */
			ret = h1_measure_trailers(buf, total, count);

			if (unlikely((int)ret <= 0)) {
				if ((int)ret < 0)
					h2s_error(h2s, H2_ERR_INTERNAL_ERROR);
				break;
			}
			// trim any possibly pending data (eg: extra CR-LF, ...)
			total += count;
			count  = 0;
			h2s->h1m.state = H1_MSG_DONE;
			break;
		}
		else {
			cs_set_error(cs);
			break;
		}

		total += ret;
		count -= ret;

		if (h2s->st >= H2_SS_ERROR)
			break;

		if (h2s->flags & H2_SF_BLK_ANY)
			break;
	}

 done:
	if (h2s->st >= H2_SS_ERROR) {
		/* trim any possibly pending data after we close (extra CR-LF,
		 * unprocessed trailers, abnormal extra data, ...)
		 */
		total += count;
		count = 0;
	}

	/* RST are sent similarly to frame acks */
	if (h2s->st == H2_SS_ERROR || h2s->flags & H2_SF_RST_RCVD) {
		cs_set_error(cs);
		if (h2s_send_rst_stream(h2s->h2c, h2s) > 0)
			h2s_close(h2s);
	}

	if (htx) {
		htx_to_buf(htx, buf);
	} else {
		b_del(buf, total);
	}

	/* The mux is full, cancel the pending tasks */
	if ((h2s->h2c->flags & H2_CF_MUX_BLOCK_ANY) ||
	    (h2s->flags & H2_SF_BLK_MBUSY))
		h2_stop_senders(h2s->h2c);

	/* If we're running HTX, and we read the whole buffer, then pretend
	 * we read exactly what the caller specified, as with HTX the caller
	 * will always give the buffer size, instead of the amount of data
	 * available.
	 */
	if (htx && !b_data(buf))
		total = orig_count;

	if (total > 0) {
		if (!(h2s->h2c->wait_event.events & SUB_RETRY_SEND))
			tasklet_wakeup(h2s->h2c->wait_event.task);

	}
	/* If we're waiting for flow control, and we got a shutr on the
	 * connection, we will never be unlocked, so add an error on
	 * the conn_stream.
	 */
	if (conn_xprt_read0_pending(h2s->h2c->conn) &&
	    !b_data(&h2s->h2c->dbuf) &&
	    (h2s->flags & (H2_SF_BLK_SFCTL | H2_SF_BLK_MFCTL))) {
		if (cs->flags & CS_FL_EOS)
			cs->flags |= CS_FL_ERROR;
		else
			cs->flags |= CS_FL_ERR_PENDING;
	}
	return total;
}

/* for debugging with CLI's "show fd" command */
static void h2_show_fd(struct buffer *msg, struct connection *conn)
{
	struct h2c *h2c = conn->ctx;
	struct h2s *h2s = NULL;
	struct eb32_node *node;
	int fctl_cnt = 0;
	int send_cnt = 0;
	int tree_cnt = 0;
	int orph_cnt = 0;

	if (!h2c)
		return;

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

	chunk_appendf(msg, " h2c.st0=%d .err=%d .maxid=%d .lastid=%d .flg=0x%04x"
		      " .nbst=%u .nbcs=%u .fctl_cnt=%d .send_cnt=%d .tree_cnt=%d"
		      " .orph_cnt=%d .sub=%d .dsi=%d .dbuf=%u@%p+%u/%u .msi=%d .mbuf=%u@%p+%u/%u",
		      h2c->st0, h2c->errcode, h2c->max_id, h2c->last_sid, h2c->flags,
		      h2c->nb_streams, h2c->nb_cs, fctl_cnt, send_cnt, tree_cnt, orph_cnt,
		      h2c->wait_event.events, h2c->dsi,
		      (unsigned int)b_data(&h2c->dbuf), b_orig(&h2c->dbuf),
		      (unsigned int)b_head_ofs(&h2c->dbuf), (unsigned int)b_size(&h2c->dbuf),
		      h2c->msi,
		      (unsigned int)b_data(&h2c->mbuf), b_orig(&h2c->mbuf),
		      (unsigned int)b_head_ofs(&h2c->mbuf), (unsigned int)b_size(&h2c->mbuf));

	if (h2s) {
		chunk_appendf(msg, " last_h2s=%p .id=%d .flg=0x%04x .rxbuf=%u@%p+%u/%u .cs=%p",
			      h2s, h2s->id, h2s->flags,
			      (unsigned int)b_data(&h2s->rxbuf), b_orig(&h2s->rxbuf),
			      (unsigned int)b_head_ofs(&h2s->rxbuf), (unsigned int)b_size(&h2s->rxbuf),
			      h2s->cs);
		if (h2s->cs)
			chunk_appendf(msg, " .cs.flg=0x%08x .cs.data=%p",
				      h2s->cs->flags, h2s->cs->data);
	}
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
	.max_streams = h2_max_streams,
	.shutr = h2_shutr,
	.shutw = h2_shutw,
	.show_fd = h2_show_fd,
	.flags = MX_FL_CLEAN_ABRT,
	.name = "H2",
};

/* PROTO selection : this mux registers PROTO token "h2" */
static struct mux_proto_list mux_proto_h2 =
	{ .token = IST("h2"), .mode = PROTO_MODE_HTTP, .side = PROTO_SIDE_FE, .mux = &h2_ops };

INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_h2);

static struct mux_proto_list mux_proto_h2_htx =
	{ .token = IST("h2"), .mode = PROTO_MODE_HTX, .side = PROTO_SIDE_BOTH, .mux = &h2_ops };

INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_h2_htx);

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.h2.header-table-size",      h2_parse_header_table_size      },
	{ CFG_GLOBAL, "tune.h2.initial-window-size",    h2_parse_initial_window_size    },
	{ CFG_GLOBAL, "tune.h2.max-concurrent-streams", h2_parse_max_concurrent_streams },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
