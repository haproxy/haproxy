/*
 * HTT/1 mux-demux for connections
 *
 * Copyright 2018 Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */
#include <common/cfgparse.h>
#include <common/config.h>

#include <types/proxy.h>
#include <types/session.h>

#include <proto/connection.h>
#include <proto/h1.h>
#include <proto/log.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>

/*
 *  H1 Connection flags (32 bits)
 */
#define H1C_F_NONE           0x00000000

/* Flags indicating why writing output data are blocked */
#define H1C_F_OUT_ALLOC      0x00000001 /* mux is blocked on lack of output buffer */
#define H1C_F_OUT_FULL       0x00000002 /* mux is blocked on output buffer full */
/* 0x00000004 - 0x00000008 unused */

/* Flags indicating why reading input data are blocked. */
#define H1C_F_IN_ALLOC       0x00000010 /* mux is blocked on lack of input buffer */
#define H1C_F_IN_FULL        0x00000020 /* mux is blocked on input buffer full */
/* 0x00000040 - 0x00000080 unused */

/* Flags indicating why parsing data are blocked */
#define H1C_F_RX_ALLOC       0x00000100 /* mux is blocked on lack of rx buffer */
#define H1C_F_RX_FULL        0x00000200 /* mux is blocked on rx buffer full */
/* 0x00000400 - 0x00000800 unused */

#define H1C_F_CS_ERROR       0x00001000 /* connection must be closed ASAP because an error occurred */
#define H1C_F_CS_SHUTW_NOW   0x00002000 /* connection must be shut down for writes ASAP */
#define H1C_F_CS_SHUTW       0x00004000 /* connection is already shut down */

#define H1C_F_WAIT_NEXT_REQ  0x00010000 /*  waiting for the next request to start, use keep-alive timeout */

/*
 * H1 Stream flags (32 bits)
 */
#define H1S_F_NONE           0x00000000
#define H1S_F_ERROR          0x00000001 /* An error occurred on the H1 stream */
#define H1S_F_REQ_ERROR      0x00000002 /* An error occurred during the request parsing/xfer */
#define H1S_F_RES_ERROR      0x00000004 /* An error occurred during the response parsing/xfer */
#define H1S_F_MSG_XFERED     0x00000008 /* current message was transferred to the data layer */
#define H1S_F_WANT_KAL       0x00000010
#define H1S_F_WANT_TUN       0x00000020
#define H1S_F_WANT_CLO       0x00000040
#define H1S_F_WANT_MSK       0x00000070
#define H1S_F_NOT_FIRST      0x00000080 /* The H1 stream is not the first one */


/* H1 connection descriptor */
struct h1c {
	struct connection *conn;
	struct proxy *px;
	uint32_t flags;                  /* Connection flags: H1C_F_* */

	struct buffer ibuf;              /* Input buffer to store data before parsing */
	struct buffer obuf;              /* Output buffer to store data after reformatting */

	struct buffer_wait buf_wait;     /* Wait list for buffer allocation */
	struct wait_event wait_event;    /* To be used if we're waiting for I/Os */

	struct h1s *h1s;                 /* H1 stream descriptor */
	struct task *task;               /* timeout management task */

	int idle_exp;                    /* expiration date for idle connections, in ticks (client-side only)*/
	int http_exp;                    /* expiration date for HTTP headers parsing (client-side only) */
};

/* H1 stream descriptor */
struct h1s {
	struct h1c *h1c;
	struct conn_stream *cs;
	uint32_t flags; /* Connection flags: H1S_F_* */

	struct buffer rxbuf; /*receive buffer, always valid (buf_empty or real buffer) */

	struct wait_event *recv_wait; /* Address of the wait_event the conn_stream associated is waiting on */
	struct wait_event *send_wait; /* Address of the wait_event the conn_stream associated is waiting on */

	struct h1m req;
	struct h1m res;

	enum http_meth_t meth; /* HTTP resquest method */
	uint16_t status;       /* HTTP response status */
};

/* the h1c and h1s pools */
static struct pool_head *pool_head_h1c;
static struct pool_head *pool_head_h1s;

static struct task *h1_timeout_task(struct task *t, void *context, unsigned short state);
static int h1_recv(struct h1c *h1c);
static int h1_send(struct h1c *h1c);
static int h1_process(struct h1c *h1c);
static struct task *h1_io_cb(struct task *t, void *ctx, unsigned short state);
static void h1_shutw_conn(struct connection *conn);

/*****************************************************/
/* functions below are for dynamic buffer management */
/*****************************************************/
/*
 * Indicates whether or not the we may call the h1_recv() function to
 * attempt to receive data into the buffer and/or parse pending data. The
 * condition is a bit complex due to some API limits for now. The rules are the
 * following :
 *   - if an error or a shutdown was detected on the connection and the buffer
 *     is empty, we must not attempt to receive
 *   - if the input buffer failed to be allocated, we must not try to receive
 *      and we know there is nothing pending
 *   - if no flag indicates a blocking condition, we may attempt to receive,
 *     regardless of whether the input buffer is full or not, so that only de
 *     receiving part decides whether or not to block. This is needed because
 *     the connection API indeed prevents us from re-enabling receipt that is
 *     already enabled in a polled state, so we must always immediately stop as
 *     soon as the mux can't proceed so as never to hit an end of read with data
 *     pending in the buffers.
 *   - otherwise must may not attempt to receive
 */
static inline int h1_recv_allowed(const struct h1c *h1c)
{
	if (b_data(&h1c->ibuf) == 0 &&
	    (h1c->flags & (H1C_F_CS_ERROR||H1C_F_CS_SHUTW) ||
	     h1c->conn->flags & CO_FL_ERROR ||
	     conn_xprt_read0_pending(h1c->conn)))
		return 0;

	if (!(h1c->flags & (H1C_F_IN_ALLOC|H1C_F_IN_FULL)))
		return 1;

	return 0;
}

/*
 * Tries to grab a buffer and to re-enables processing on mux <target>. The h1
 * flags are used to figure what buffer was requested. It returns 1 if the
 * allocation succeeds, in which case the connection is woken up, or 0 if it's
 * impossible to wake up and we prefer to be woken up later.
 */
static int h1_buf_available(void *target)
{
	struct h1c *h1c = target;

	if ((h1c->flags & H1C_F_IN_ALLOC) && b_alloc_margin(&h1c->ibuf, 0)) {
		h1c->flags &= ~H1C_F_IN_ALLOC;
		if (h1_recv_allowed(h1c))
			tasklet_wakeup(h1c->wait_event.task);
		return 1;
	}

	if ((h1c->flags & H1C_F_OUT_ALLOC) && b_alloc_margin(&h1c->obuf, 0)) {
		h1c->flags &= ~H1C_F_OUT_ALLOC;
		tasklet_wakeup(h1c->wait_event.task);
		return 1;
	}

	if ((h1c->flags & H1C_F_RX_ALLOC) && h1c->h1s && b_alloc_margin(&h1c->h1s->rxbuf, 0)) {
		h1c->flags &= ~H1C_F_RX_ALLOC;
		if (h1_recv_allowed(h1c))
			tasklet_wakeup(h1c->wait_event.task);
		return 1;
	}

	return 0;
}

/*
 * Allocate a buffer. If if fails, it adds the mux in buffer wait queue.
 */
static inline struct buffer *h1_get_buf(struct h1c *h1c, struct buffer *bptr)
{
	struct buffer *buf = NULL;

	if (likely(LIST_ISEMPTY(&h1c->buf_wait.list)) &&
	    unlikely((buf = b_alloc_margin(bptr, 0)) == NULL)) {
		h1c->buf_wait.target = h1c;
		h1c->buf_wait.wakeup_cb = h1_buf_available;
		HA_SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		LIST_ADDQ(&buffer_wq, &h1c->buf_wait.list);
		HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		__conn_xprt_stop_recv(h1c->conn);
	}
	return buf;
}

/*
 * Release a buffer, if any, and try to wake up entities waiting in the buffer
 * wait queue.
 */
static inline void h1_release_buf(struct h1c *h1c, struct buffer *bptr)
{
	if (bptr->size) {
		b_free(bptr);
		offer_buffers(h1c->buf_wait.target, tasks_run_queue);
	}
}

static int h1_avail_streams(struct connection *conn)
{
	struct h1c *h1c = conn->mux_ctx;

	return h1c->h1s ? 0 : 1;
}


/*****************************************************************/
/* functions below are dedicated to the mux setup and management */
/*****************************************************************/
static struct h1s *h1s_create(struct h1c *h1c, struct conn_stream *cs)
{
	struct h1s *h1s;

	h1s = pool_alloc(pool_head_h1s);
	if (!h1s)
		goto end;

	h1s->h1c = h1c;
	h1c->h1s = h1s;

	h1s->cs    = NULL;
	h1s->rxbuf = BUF_NULL;
	h1s->flags = H1S_F_NONE;

	h1s->recv_wait = NULL;
	h1s->send_wait = NULL;

	h1m_init_req(&h1s->req);
	h1m_init_res(&h1s->res);

	h1s->status = 0;
	h1s->meth   = HTTP_METH_OTHER;

	if (!conn_is_back(h1c->conn)) {
		if (h1c->px->options2 & PR_O2_REQBUG_OK)
			h1s->req.err_pos = -1;

		if (h1c->flags & H1C_F_WAIT_NEXT_REQ)
			h1s->flags |= H1S_F_NOT_FIRST;
		h1c->flags &= ~H1C_F_WAIT_NEXT_REQ;
		h1c->http_exp = tick_add_ifset(now_ms, h1c->px->timeout.httpreq);
	}
	else {
		if (h1c->px->options2 & PR_O2_RSPBUG_OK)
			h1s->res.err_pos = -1;
	}

	/* If a conn_stream already exists, attach it to this H1S */
	if (cs) {
		cs->ctx = h1s;
		h1s->cs = cs;
	}
  end:
	return h1s;
}

static void h1s_destroy(struct h1s *h1s)
{
	if (h1s) {
		struct h1c *h1c = h1s->h1c;

		h1c->h1s = NULL;
		h1c->flags &= ~(H1C_F_RX_FULL|H1C_F_RX_ALLOC);

		if (h1s->recv_wait != NULL)
			h1s->recv_wait->wait_reason &= ~SUB_CAN_RECV;
		if (h1s->send_wait != NULL)
			h1s->send_wait->wait_reason &= ~SUB_CAN_SEND;

		if (!conn_is_back(h1c->conn)) {
			h1c->flags |= H1C_F_WAIT_NEXT_REQ;
			h1c->http_exp = tick_add_ifset(now_ms, h1c->px->timeout.httpka);
		}

		h1_release_buf(h1c, &h1s->rxbuf);
		cs_free(h1s->cs);
		pool_free(pool_head_h1s, h1s);
	}
}

static struct conn_stream *h1s_new_cs(struct h1s *h1s)
{
	struct conn_stream *cs;

	cs = cs_new(h1s->h1c->conn);
	if (!cs)
		goto err;
	h1s->cs = cs;
	cs->ctx = h1s;

	if (h1s->flags & H1S_F_NOT_FIRST)
		cs->flags |= CS_FL_NOT_FIRST;

	if (stream_create_from_cs(cs) < 0)
		goto err;
	return cs;

  err:
	cs_free(cs);
	h1s->cs = NULL;
	return NULL;
}

/*
 * Initialize the mux once it's attached. It is expected that conn->mux_ctx
 * points to the existing conn_stream (for outgoing connections) or NULL (for
 * incoming ones). Returns < 0 on error.
 */
static int h1_init(struct connection *conn, struct proxy *proxy)
{
	struct h1c *h1c;
	struct task *t = NULL;

	h1c = pool_alloc(pool_head_h1c);
	if (!h1c)
		goto fail_h1c;
	h1c->conn = conn;
	h1c->px   = proxy;

	h1c->flags = H1C_F_NONE;
	h1c->ibuf  = BUF_NULL;
	h1c->obuf  = BUF_NULL;
	h1c->h1s   = NULL;

	t = task_new(tid_bit);
	if (!t)
		goto fail;
	h1c->task  = t;
	t->process = h1_timeout_task;
	t->context = h1c;
	t->expire  = TICK_ETERNITY;

	h1c->idle_exp = TICK_ETERNITY;
	h1c->http_exp = TICK_ETERNITY;

	LIST_INIT(&h1c->buf_wait.list);
	h1c->wait_event.task = tasklet_new();
	if (!h1c->wait_event.task)
		goto fail;
	h1c->wait_event.task->process = h1_io_cb;
	h1c->wait_event.task->context = h1c;
	h1c->wait_event.wait_reason   = 0;

	/* Always Create a new H1S */
	if (!h1s_create(h1c, conn->mux_ctx))
		goto fail;

	conn->mux_ctx = h1c;
	task_wakeup(t, TASK_WOKEN_INIT);

	/* Try to read, if nothing is available yet we'll just subscribe */
	if (h1_recv(h1c))
		h1_process(h1c);

	/* mux->wake will be called soon to complete the operation */
	return 0;

  fail:
	if (t)
		task_free(t);
	if (h1c && h1c->wait_event.task)
		tasklet_free(h1c->wait_event.task);
	pool_free(pool_head_h1c, h1c);
 fail_h1c:
	return -1;
}


/* release function for a connection. This one should be called to free all
 * resources allocated to the mux.
 */
static void h1_release(struct connection *conn)
{
	struct h1c *h1c = conn->mux_ctx;

	LIST_DEL(&conn->list);

	if (h1c) {
		if (!LIST_ISEMPTY(&h1c->buf_wait.list)) {
			HA_SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
			LIST_DEL(&h1c->buf_wait.list);
			LIST_INIT(&h1c->buf_wait.list);
			HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		}

		h1_release_buf(h1c, &h1c->ibuf);
		h1_release_buf(h1c, &h1c->obuf);

		if (h1c->task) {
			h1c->task->context = NULL;
			task_wakeup(h1c->task, TASK_WOKEN_OTHER);
			h1c->task = NULL;
		}
		if (h1c->wait_event.task)
			tasklet_free(h1c->wait_event.task);

		h1s_destroy(h1c->h1s);
		if (h1c->wait_event.wait_reason != 0)
			conn->xprt->unsubscribe(conn, h1c->wait_event.wait_reason,
			    &h1c->wait_event);
		pool_free(pool_head_h1c, h1c);
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
/* functions below are for the H1 protocol processing */
/******************************************************/
/*
 * Set the appropriate error message. It first tries to get it from the proxy if
 * it exists. Otherwise, it falls back on default one.
 */
static void h1_cpy_error_message(struct h1c *h1c, struct buffer *dst, int status)
{
	const int msgnum = http_get_status_idx(status);
	const struct buffer *err;

	err = (h1c->px->errmsg[msgnum].area
	       ? &h1c->px->errmsg[msgnum]
	       : &http_err_chunks[msgnum]);
	b_putblk(dst, b_head(err), b_data(err));
}

/* Remove all "Connection:" headers from the buffer <buf>, using the array of
 * parsed headers <hdrs>. It returns the number of bytes removed. This should
 * happen just after the headers parsing, so the buffer should not wrap. At the
 * ends, all entries of <hdrs> reamin valid.
 */
static int h1_remove_conn_hdrs(struct h1m *h1m, struct http_hdr *hdrs, struct buffer *buf)
{
	int src, dst, delta;

	delta = 0;
	for (src = 0, dst = 0; hdrs[src].n.len; src++) {

		if (hdrs[src].n.ptr >= buf->area && hdrs[src].n.ptr < buf->area + buf->size)
			hdrs[src].n.ptr += delta;
		hdrs[src].v.ptr += delta;

		if (!isteqi(hdrs[src].n, ist("Connection"))) {
			if (src != dst)
				hdrs[dst] = hdrs[src];
			dst++;
			continue;
		}
		delta += b_rep_blk(buf, hdrs[src].n.ptr, hdrs[src+1].n.ptr+delta, NULL, 0);
	}

	/* Don't forget to copy EOH */
	hdrs[src].n.ptr += delta;
	hdrs[dst] = hdrs[src];

	h1m->flags &= ~(H1_MF_CONN_KAL|H1_MF_CONN_CLO);
	return delta;
}

/* Add a "Connection:" header into the buffer <buf>. If <type> is 0, the header
 * is set to "keep-alive", otherwise it is set to "close", It returns the number
 * of bytes added. This should happen just after the headers parsing, so the
 * buffer should not wrap. At the ends, all entries of <hdrs> reamin valid.
 */
static int h1_add_conn_hdrs(struct h1m *h1m, struct http_hdr *hdrs, struct buffer *buf,
			    int type)
{
	const char *conn_hdr;
	size_t nlen, vlen;
	int i, delta;

	if (type == 0) { /* keep-alive */
		conn_hdr = "Connection: keep-alive\r\n";
		nlen = 10; vlen = 10;
	}
	else { /* close */
		conn_hdr = "Connection: close\r\n";
		nlen = 10; vlen = 5;
	}

	/* Find EOH*/
	for (i = 0; hdrs[i].n.len; i++);

	/* Insert the "Connection: " header */
	delta = b_rep_blk(buf, hdrs[i].n.ptr, hdrs[i].n.ptr, conn_hdr, nlen+vlen+4);

	/* Update the header list */
	http_set_hdr(&hdrs[i], ist2(hdrs[i].n.ptr, nlen), ist2(hdrs[i].n.ptr+nlen+2, vlen));
	http_set_hdr(&hdrs[i+1], ist2(hdrs[i].n.ptr+delta, 0), ist(""));

	return delta;
}

/* Deduce the connection mode of the client connection, depending on the
 * configuration and the H1 message flags. This function is called twice, the
 * first time when the request is parsed and the second time when the response
 * is parsed.
 */
static void h1_set_cli_conn_mode(struct h1s *h1s, struct h1m *h1m)
{
	struct proxy *fe = h1s->h1c->px;
	int flag = H1S_F_WANT_KAL; /* For client connection: server-close == keepalive */

	/* Tunnel mode can only by set on the frontend */
	if ((fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_TUN)
		flag = H1S_F_WANT_TUN;
	else if ((fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_CLO)
		flag = H1S_F_WANT_CLO;

	/* flags order: CLO > SCL > TUN > KAL */
	if ((h1s->flags & H1S_F_WANT_MSK) < flag)
		h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | flag;

	if (h1m->flags & H1_MF_RESP) {
		/* Either we've established an explicit tunnel, or we're
		 * switching the protocol. In both cases, we're very unlikely to
		 * understand the next protocols. We have to switch to tunnel
		 * mode, so that we transfer the request and responses then let
		 * this protocol pass unmodified. When we later implement
		 * specific parsers for such protocols, we'll want to check the
		 * Upgrade header which contains information about that protocol
		 * for responses with status 101 (eg: see RFC2817 about TLS).
		 */
		if ((h1s->meth == HTTP_METH_CONNECT && h1s->status == 200) ||
		    h1s->status == 101)
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_TUN;
		else if (!(h1m->flags & H1_MF_XFER_LEN)) /* no length known => close */
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
	}
	else {
		if (h1s->flags & H1S_F_WANT_KAL &&
		    (!(h1m->flags & (H1_MF_VER_11|H1_MF_CONN_KAL)) || /* no KA in HTTP/1.0 */
		     h1m->flags & H1_MF_CONN_CLO))                    /* explicit close */
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
	}

	/* If KAL, check if the frontend is stopping. If yes, switch in CLO mode */
	if (h1s->flags & H1S_F_WANT_KAL && fe->state == PR_STSTOPPED)
		h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
}

/* Deduce the connection mode of the client connection, depending on the
 * configuration and the H1 message flags. This function is called twice, the
 * first time when the request is parsed and the second time when the response
 * is parsed.
 */
static void h1_set_srv_conn_mode(struct h1s *h1s, struct h1m *h1m)
{
	struct proxy *be = h1s->h1c->px;
	struct proxy *fe = strm_fe(si_strm(h1s->cs->data));
	int flag =  H1S_F_WANT_KAL;

	/* Tunnel mode can only by set on the frontend */
	if ((fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_TUN)
		flag = H1S_F_WANT_TUN;

	/* For the server connection: server-close == httpclose */
	if ((fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_SCL ||
	    (be->options & PR_O_HTTP_MODE) == PR_O_HTTP_SCL ||
	    (fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_CLO ||
	    (be->options & PR_O_HTTP_MODE) == PR_O_HTTP_CLO)
		flag = H1S_F_WANT_CLO;

	/* flags order: CLO > SCL > TUN > KAL */
	if ((h1s->flags & H1S_F_WANT_MSK) < flag)
		h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | flag;

	if (h1m->flags & H1_MF_RESP) {
		/* Either we've established an explicit tunnel, or we're
		 * switching the protocol. In both cases, we're very unlikely to
		 * understand the next protocols. We have to switch to tunnel
		 * mode, so that we transfer the request and responses then let
		 * this protocol pass unmodified. When we later implement
		 * specific parsers for such protocols, we'll want to check the
		 * Upgrade header which contains information about that protocol
		 * for responses with status 101 (eg: see RFC2817 about TLS).
		 */
		if ((h1s->meth == HTTP_METH_CONNECT && h1s->status == 200) ||
		    h1s->status == 101)
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_TUN;
		else if (!(h1m->flags & H1_MF_XFER_LEN)) /* no length known => close */
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
		else if (h1s->flags & H1S_F_WANT_KAL &&
			 (!(h1m->flags & (H1_MF_VER_11|H1_MF_CONN_KAL)) || /* no KA in HTTP/1.0 */
			  h1m->flags & H1_MF_CONN_CLO))                    /* explicit close */
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
	}

	/* If KAL, check if the backend is stopping. If yes, switch in CLO mode */
	if (h1s->flags & H1S_F_WANT_KAL && be->state == PR_STSTOPPED)
		h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;

	/* TODO: For now on the server-side, we disable keep-alive */
	if (h1s->flags & H1S_F_WANT_KAL)
		h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
}

static int h1_update_req_conn_hdr(struct h1s *h1s, struct h1m *h1m,
				   struct http_hdr *hdrs, struct buffer *buf)
{
	struct proxy *px = h1s->h1c->px;
	int ret = 0;

	/* Don't update "Connection:" header in TUNNEL mode or if "Upgrage"
	 * token is found
	 */
	if (h1s->flags & H1S_F_WANT_TUN || h1m->flags & H1_MF_CONN_UPG)
		goto end;

	if (h1s->flags & H1S_F_WANT_KAL || px->options2 & PR_O2_FAKE_KA) {
		if (h1m->flags & H1_MF_CONN_CLO)
			ret += h1_remove_conn_hdrs(h1m, hdrs, buf);
		if (!(h1m->flags & (H1_MF_VER_11|H1_MF_CONN_KAL)))
			ret += h1_add_conn_hdrs(h1m, hdrs, buf, 0);
	}
	else { /* H1S_F_WANT_CLO && !PR_O2_FAKE_KA */
		if (h1m->flags & H1_MF_CONN_KAL)
			ret += h1_remove_conn_hdrs(h1m, hdrs, buf);
		if ((h1m->flags & (H1_MF_VER_11|H1_MF_CONN_CLO)) == H1_MF_VER_11)
			ret += h1_add_conn_hdrs(h1m, hdrs, buf, 1);
	}

  end:
	return ret;
}

static int h1_update_res_conn_hdr(struct h1s *h1s, struct h1m *h1m,
				   struct http_hdr *hdrs, struct buffer *buf)
{
	int ret = 0;

	/* Don't update "Connection:" header in TUNNEL mode or if "Upgrage"
	 * token is found
	 */
	if (h1s->flags & H1S_F_WANT_TUN || h1m->flags & H1_MF_CONN_UPG)
		goto end;

	if (h1s->flags & H1S_F_WANT_KAL) {
		if (h1m->flags & H1_MF_CONN_CLO)
			ret += h1_remove_conn_hdrs(h1m, hdrs, buf);
		if (!(h1m->flags & (H1_MF_VER_11|H1_MF_CONN_KAL)))
			ret += h1_add_conn_hdrs(h1m, hdrs, buf, 0);
	}
	else { /* H1S_F_WANT_CLO */
		if (h1m->flags & H1_MF_CONN_KAL)
			ret += h1_remove_conn_hdrs(h1m, hdrs, buf);
		if ((h1m->flags & (H1_MF_VER_11|H1_MF_CONN_CLO)) == H1_MF_VER_11)
			ret += h1_add_conn_hdrs(h1m, hdrs, buf, 1);
	}

  end:
	return ret;
}

/*
 * Parse HTTP/1 headers. It returns the number of bytes parsed if > 0, or 0 if
 * it couldn't proceed. Parsing errors are reported by setting H1S_F_*_ERROR
 * flag and filling h1s->err_pos and h1s->err_state fields. This functions is
 * responsibile to update the parser state <h1m>.
 */
static size_t h1_process_headers(struct h1s *h1s, struct h1m *h1m,
				 struct buffer *buf, size_t *ofs, size_t max)
{
	struct http_hdr hdrs[MAX_HTTP_HDR];
	union h1_sl sl;
	int ret = 0;

	/* Realing input buffer if necessary */
	if (b_head(buf) + b_data(buf) > b_wrap(buf))
		b_slow_realign(buf, trash.area, 0);

	ret = h1_headers_to_hdr_list(b_peek(buf, *ofs), b_peek(buf, *ofs) + max,
				     hdrs, sizeof(hdrs)/sizeof(hdrs[0]), h1m, &sl);
	if (ret <= 0) {
		/* Incomplete or invalid message. If the buffer is full, it's an
		 * error because headers are too large to be handled by the
		 * parser. */
		if (ret < 0 || (!ret && b_full(buf)))
			goto error;
		goto end;
	}

	/* messages headers fully parsed, do some checks to prepare the body
	 * parsing.
	 */

	/* Be sure to keep some space to do headers rewritting */
	if (ret > (b_size(buf) - global.tune.maxrewrite))
		goto error;

	/* Save the request's method or the response's status and check if the
	 * body length is known */
	if (!(h1m->flags & H1_MF_RESP)) {
		h1s->meth = sl.rq.meth;
		/* Request have always a known length */
		h1m->flags |= H1_MF_XFER_LEN;
		if (!(h1m->flags & H1_MF_CHNK) && !h1m->body_len)
			h1m->state = H1_MSG_DONE;
	}
	else {
		h1s->status = sl.st.status;

		if ((h1s->meth == HTTP_METH_HEAD) ||
		    (h1s->status >= 100 && h1s->status < 200) ||
		    (h1s->status == 204) || (h1s->status == 304) ||
		    (h1s->meth == HTTP_METH_CONNECT && h1s->status == 200)) {
			h1m->flags &= ~(H1_MF_CLEN|H1_MF_CHNK);
			h1m->flags |= H1_MF_XFER_LEN;
			h1m->curr_len = h1m->body_len = 0;
			h1m->state = H1_MSG_DONE;
		}
		else if (h1m->flags & (H1_MF_CLEN|H1_MF_CHNK)) {
			h1m->flags |= H1_MF_XFER_LEN;
			if ((h1m->flags & H1_MF_CLEN) && !h1m->body_len)
				h1m->state = H1_MSG_DONE;
		}
		else
			h1m->state = H1_MSG_TUNNEL;
	}

	*ofs += ret;
	if (!conn_is_back(h1s->h1c->conn)) {
		h1_set_cli_conn_mode(h1s, h1m);
		if (h1m->flags & H1_MF_RESP)
			*ofs += h1_update_res_conn_hdr(h1s, h1m, hdrs, buf);
	}
	else {
		h1_set_srv_conn_mode(h1s, h1m);
		if (!(h1m->flags & H1_MF_RESP))
			*ofs += h1_update_req_conn_hdr(h1s, h1m, hdrs, buf);
	}
  end:
	return ret;

  error:
	h1s->flags |= (!(h1m->flags & H1_MF_RESP) ? H1S_F_REQ_ERROR : H1S_F_RES_ERROR);
	h1m->err_state = h1m->state;
	h1m->err_pos = h1m->next;
	ret = 0;
	goto end;
}

/*
 * Parse HTTP/1 body. It returns the number of bytes parsed if > 0, or 0 if it
 * couldn't proceed. Parsing errors are reported by setting H1S_F_*_ERROR flag
 * and filling h1s->err_pos and h1s->err_state fields. This functions is
 * responsibile to update the parser state <h1m>.
 */
static size_t h1_process_data(struct h1s *h1s, struct h1m *h1m,
			      struct buffer *buf, size_t *ofs, size_t max)
{
	size_t total = 0;
	int ret = 0;

	if (h1m->flags & H1_MF_XFER_LEN) {
		if (h1m->flags & H1_MF_CLEN) {
			/* content-length: read only h2m->body_len */
			ret = max;
			if ((uint64_t)ret > h1m->curr_len)
				ret = h1m->curr_len;
			h1m->curr_len -= ret;
			*ofs += ret;
			total += ret;
			if (!h1m->curr_len)
				h1m->state = H1_MSG_DONE;
		}
		else if (h1m->flags & H1_MF_CHNK) {
		  new_chunk:
			/* te:chunked : parse chunks */
			if (h1m->state == H1_MSG_CHUNK_CRLF) {
				ret = h1_skip_chunk_crlf(buf, *ofs, *ofs + max);
				if (ret <= 0)
					goto end;
				max -= ret;
				*ofs += ret;
				total += ret;
				h1m->state = H1_MSG_CHUNK_SIZE;
			}

			if (h1m->state == H1_MSG_CHUNK_SIZE) {
				unsigned int chksz;

				ret = h1_parse_chunk_size(buf, *ofs, *ofs + max, &chksz);
				if (ret <= 0)
					goto end;
				h1m->curr_len  = chksz;
				h1m->body_len += chksz;
				max -= ret;
				*ofs += ret;
				total += ret;
				h1m->state = (!chksz ? H1_MSG_TRAILERS : H1_MSG_DATA);
			}

			if (h1m->state == H1_MSG_DATA) {
				ret = max;
				if (!ret)
					goto end;
				if ((uint64_t)ret > h1m->curr_len)
					ret = h1m->curr_len;
				h1m->curr_len -= ret;
				max -= ret;
				*ofs += ret;
				total += ret;
				if (h1m->curr_len)
					goto end;
				h1m->state = H1_MSG_CHUNK_CRLF;
				goto new_chunk;
			}

			if (h1m->state == H1_MSG_TRAILERS) {
				ret = h1_measure_trailers(buf, *ofs, *ofs + max);
				if (ret <= 0)
					goto end;
				max -= ret;
				*ofs += ret;
				total += ret;
				h1m->state = H1_MSG_DONE;
			}
		}
		else {
			/* XFER_LEN is set but not CLEN nor CHNK, it means there
			 * is no body. Switch the message in DONE state
			 */
			h1m->state = H1_MSG_DONE;
		}
	}
	else {
		/* no content length, read till SHUTW */
		*ofs += max;
		total = max;
	}

  end:
	if (ret < 0) {
		h1s->flags |= (!(h1m->flags & H1_MF_RESP) ? H1S_F_REQ_ERROR : H1S_F_RES_ERROR);
		h1m->err_state = h1m->state;
		h1m->err_pos = *ofs + max + ret;
		return 0;
	}

	return total;
}

/*
 * Synchronize the request and the response before reseting them. Except for 1xx
 * responses, we wait that the request and the response are in DONE state and
 * that all data are forwarded for both. For 1xx responses, only the response is
 * reset, waiting the final one. Many 1xx messages can be sent.
 */
static void h1_sync_messages(struct h1c *h1c)
{
	struct h1s *h1s = h1c->h1s;

	if (!h1s)
		return;

	if (h1s->res.state == H1_MSG_DONE &&
	    (h1s->status < 200 && (h1s->status == 100 || h1s->status >= 102)) &&
	    ((conn_is_back(h1c->conn) && !b_data(&h1c->obuf)) || !b_data(&h1s->rxbuf))) {
		/* For 100-Continue response or any other informational 1xx
		 * response which is non-final, don't reset the request, the
		 * transaction is not finished. We take care the response was
		 * transferred before.
		 */
		h1m_init_res(&h1s->res);
	}
	else if (!b_data(&h1s->rxbuf) && !b_data(&h1c->obuf) &&
		 h1s->req.state == H1_MSG_DONE && h1s->res.state == H1_MSG_DONE) {
		if (h1s->flags & H1S_F_WANT_TUN) {
			h1s->req.state = H1_MSG_TUNNEL;
			h1s->res.state = H1_MSG_TUNNEL;
		}
	}
}

/*
 * Process incoming data. It parses data and transfer them from h1c->ibuf into
 * h1s->rxbuf. It returns the number of bytes parsed and transferred if > 0, or
 * 0 if it couldn't proceed.
 */
static size_t h1_process_input(struct h1c *h1c, struct buffer *buf, size_t count)
{
	struct h1s *h1s = NULL;
	struct h1m *h1m;
	size_t total = 0;
	size_t ret = 0;
	size_t max;
	int errflag;

	if (h1c->flags & H1C_F_CS_ERROR)
		goto end;

	/* Create a new H1S without CS if not already done */
	if (!h1c->h1s && !h1s_create(h1c, NULL))
		goto err;
	h1s = h1c->h1s;

#if 0
	// FIXME: Use a proxy option to enable early creation of the CS
	/* Create the CS if not already attached to the H1S */
	if (!h1s->cs && !h1s_new_cs(h1s))
		goto err;
#endif

	if (!h1_get_buf(h1c, &h1s->rxbuf)) {
		h1c->flags |= H1C_F_RX_ALLOC;
		goto end;
	}

	if (count > b_room(&h1s->rxbuf))
		count = b_room(&h1s->rxbuf);
	max = count;

	if (!conn_is_back(h1c->conn)) {
		h1m = &h1s->req;
		errflag = H1S_F_REQ_ERROR;
	}
	else {
		h1m = &h1s->res;
		errflag = H1S_F_RES_ERROR;
	}
	while (!(h1s->flags & errflag) && max) {
		if (h1m->state <= H1_MSG_LAST_LF) {
			ret = h1_process_headers(h1s, h1m, buf, &total, max);
			if (!ret)
				break;

			/* Reset request timeout */
			h1s->h1c->http_exp = TICK_ETERNITY;

			/* Create the CS if not already attached to the H1S */
			if (!h1s->cs && !h1s_new_cs(h1s))
				goto err;
		}
		else if (h1m->state <= H1_MSG_TRAILERS) {
			/* Do not parse the body if the header part is not yet
			 * transferred to the stream.
			 */
			if (!(h1s->flags & H1S_F_MSG_XFERED))
				break;
			ret = h1_process_data(h1s, h1m, buf, &total, max);
			if (!ret)
				break;
		}
		else if (h1m->state == H1_MSG_DONE)
			break;
		else if (h1m->state == H1_MSG_TUNNEL) {
			total += max;
			max = 0;
			break;
		}
		else {
			h1s->flags |= errflag;
			break;
		}

		max -= ret;
	}

	if (h1s->flags & errflag) {
		/* For now, if an error occurred during the message parsing when
		 * a stream is already attached to the mux, we transfer
		 * everything to let the stream handle the error itself. We
		 * suppose the stream will detect the same error of
		 * course. Otherwise, we generate the error here.
		 */
		if (!h1s->cs) {
			if (!h1_get_buf(h1c, &h1c->obuf)) {
				h1c->flags |= H1C_F_OUT_ALLOC;
				goto err;
			}
			h1_cpy_error_message(h1c, &h1c->obuf, 400);
			goto err;
		}
		total += max;
		max = 0;
	}

	b_xfer(&h1s->rxbuf, buf, total);

	if (b_data(&h1s->rxbuf)) {
		h1s->cs->flags |= CS_FL_RCV_MORE;
		if (b_full(&h1s->rxbuf))
			h1c->flags |= H1C_F_RX_FULL;
	}
	ret = count - max;
  end:
	return ret;

  err:
	h1s_destroy(h1s);
	h1c->flags |= H1C_F_CS_ERROR;
	sess_log(h1c->conn->owner);
	ret = 0;
	goto end;
}

/*
 * Process outgoing data. It parses data and transfer them from the channel buffer into
 * h1c->obuf. It returns the number of bytes parsed and transferred if > 0, or
 * 0 if it couldn't proceed.
 */
static size_t h1_process_output(struct h1c *h1c, struct buffer *buf, size_t count)
{
	struct h1s *h1s = h1c->h1s;
	struct h1m *h1m;
	size_t max;
	size_t total = 0;
	size_t ret = 0;
	int errflag;

	if (!h1_get_buf(h1c, &h1c->obuf)) {
		h1c->flags |= H1C_F_OUT_ALLOC;
		goto end;
	}
	if (count > b_room(&h1c->obuf))
		count = b_room(&h1c->obuf);

	max = count;
	if (!conn_is_back(h1c->conn)) {
		h1m = &h1s->res;
		errflag = H1S_F_RES_ERROR;
	}
	else {
		h1m = &h1s->req;
		errflag = H1S_F_REQ_ERROR;
	}
	while (!(h1s->flags & errflag) && max) {
		if (h1m->state <= H1_MSG_LAST_LF) {
			ret = h1_process_headers(h1s, h1m, buf, &total, max);
			if (!ret) {
				/* incomplete or invalid response, this is abnormal coming from
				 * haproxy and may only result in a bad errorfile or bad Lua code
				 * so that won't be fixed, raise an error now.
				 */
				h1s->flags |= errflag;
				break;
			}
		}
		else if (h1m->state <= H1_MSG_TRAILERS) {
			ret = h1_process_data(h1s, h1m, buf, &total, max);
			if (!ret)
				break;
		}
		else if (h1m->state == H1_MSG_DONE)
			break;
		else if (h1m->state == H1_MSG_TUNNEL) {
			total += max;
			max = 0;
			break;
		}
		else {
			h1s->flags |= errflag;
			break;
		}

		max -= ret;
	}

	// TODO: Handle H1S errors
	b_xfer(&h1c->obuf, buf, total);

	if (b_full(&h1c->obuf))
		h1c->flags |= H1C_F_OUT_FULL;
	ret = count - max;
 end:
	return ret;
}

/*
 * Transfer data from h1s->rxbuf into the channel buffer. It returns the number
 * of bytes transferred.
 */
static size_t h1_xfer(struct h1s *h1s, struct buffer *buf, size_t count)
{
	struct h1c *h1c = h1s->h1c;
	struct conn_stream *cs = h1s->cs;
	size_t ret = 0;

	/* transfer possibly pending data to the upper layer */
	ret = b_xfer(buf, &h1s->rxbuf, count);

	if (b_data(&h1s->rxbuf)) {
		if (!b_full(&h1s->rxbuf)) {
			h1c->flags &= ~H1C_F_RX_FULL;
		}
		cs->flags |= CS_FL_RCV_MORE;
	}
	else {
		if (!(h1s->flags & H1S_F_MSG_XFERED))
			h1s->flags |= H1S_F_MSG_XFERED;

		h1c->flags &= ~H1C_F_RX_FULL;
		h1_release_buf(h1c, &h1s->rxbuf);
		h1_sync_messages(h1c);

		cs->flags &= ~CS_FL_RCV_MORE;
		if (!b_data(&h1c->ibuf) && (cs->flags & CS_FL_REOS))
			cs->flags |= CS_FL_EOS;
	}
	return ret;
}

/*********************************************************/
/* functions below are I/O callbacks from the connection */
/*********************************************************/
/*
 * Attempt to read data, and subscribe if none available
 */
static int h1_recv(struct h1c *h1c)
{
	struct connection *conn = h1c->conn;
	size_t ret, max;
	int rcvd = 0;

	if (h1c->wait_event.wait_reason & SUB_CAN_RECV)
		return 0;

	if (!h1_recv_allowed(h1c)) {
		if (h1c->h1s && b_data(&h1c->h1s->rxbuf))
			return 1;
		return 0;
	}

	if (!h1_get_buf(h1c, &h1c->ibuf)) {
		h1c->flags |= H1C_F_IN_ALLOC;
		return 0;
	}

	ret = 0;
	max = b_room(&h1c->ibuf);
	if (max) {
		h1c->flags &= ~H1C_F_IN_FULL;
		ret = conn->xprt->rcv_buf(conn, &h1c->ibuf, max, 0);
	}
	if (ret > 0)
		rcvd = 1;

	if (h1_recv_allowed(h1c))
		conn->xprt->subscribe(conn, SUB_CAN_RECV, &h1c->wait_event);

	if (!b_data(&h1c->ibuf))
		h1_release_buf(h1c, &h1c->ibuf);
	else if (b_full(&h1c->ibuf))
		h1c->flags |= H1C_F_IN_FULL;
	return rcvd;
}


/*
 * Try to send data if possible
 */
static int h1_send(struct h1c *h1c)
{
	struct connection *conn = h1c->conn;
	unsigned int flags = 0;
	size_t ret;
	int sent = 0;

	if (conn->flags & CO_FL_ERROR)
		return 0;

	if (!b_data(&h1c->obuf))
		goto end;

	if (h1c->flags & H1C_F_OUT_FULL)
		flags |= CO_SFL_MSG_MORE;

	ret = conn->xprt->snd_buf(conn, &h1c->obuf, b_data(&h1c->obuf), flags);
	if (ret > 0) {
		h1c->flags &= ~H1C_F_OUT_FULL;
		b_del(&h1c->obuf, ret);
		sent = 1;
	}

  end:
	/* We're done, no more to send */
	if (!b_data(&h1c->obuf)) {
		h1_release_buf(h1c, &h1c->obuf);
		h1_sync_messages(h1c);
		if (h1c->flags & H1C_F_CS_SHUTW_NOW)
			h1_shutw_conn(conn);
	}
	else if (!(h1c->wait_event.wait_reason & SUB_CAN_SEND))
		conn->xprt->subscribe(conn, SUB_CAN_SEND, &h1c->wait_event);

	return sent;
}


static void h1_wake_stream(struct h1c *h1c)
{
	struct connection *conn = h1c->conn;
	struct h1s *h1s = h1c->h1s;
	uint32_t flags = 0;
	int dont_wake = 0;

	if (!h1s || !h1s->cs)
		return;

	if ((h1c->flags & H1C_F_CS_ERROR) || (conn->flags & CO_FL_ERROR))
		flags |= CS_FL_ERROR;
	if (conn_xprt_read0_pending(conn))
		flags |= CS_FL_REOS;

	h1s->cs->flags |= flags;
	if (h1s->recv_wait) {
		h1s->recv_wait->wait_reason &= ~SUB_CAN_RECV;
		tasklet_wakeup(h1s->recv_wait->task);
		h1s->recv_wait = NULL;
		dont_wake = 1;
	}
	if (h1s->send_wait) {
		h1s->send_wait->wait_reason &= ~SUB_CAN_SEND;
		tasklet_wakeup(h1s->send_wait->task);
		h1s->send_wait = NULL;
		dont_wake = 1;
	}
	if (!dont_wake && h1s->cs->data_cb->wake)
		h1s->cs->data_cb->wake(h1s->cs);
}

/* callback called on any event by the connection handler.
 * It applies changes and returns zero, or < 0 if it wants immediate
 * destruction of the connection.
 */
static int h1_process(struct h1c * h1c)
{
	struct connection *conn = h1c->conn;

	if (b_data(&h1c->ibuf) && !(h1c->flags & (H1C_F_RX_FULL|H1C_F_RX_ALLOC))) {
		size_t ret;

		ret = h1_process_input(h1c, &h1c->ibuf, b_data(&h1c->ibuf));
		if (ret > 0) {
			h1c->flags &= ~H1C_F_IN_FULL;
			if (!b_data(&h1c->ibuf))
				h1_release_buf(h1c, &h1c->ibuf);
		}
	}

	h1_send(h1c);

	h1_wake_stream(h1c);

	if (!conn->mux_ctx)
		return -1;

	if ((h1c->flags & H1C_F_CS_ERROR) || (conn->flags & CO_FL_ERROR) || conn_xprt_read0_pending(conn)) {
		if (!h1c->h1s || !h1c->h1s->cs) {
			h1_release(conn);
			return -1;
		}
	}

	/* If there is a stream attached to the mux, let it
	 * handle the timeout.
	 */
	if (h1c->h1s && h1c->h1s->cs)
		h1c->idle_exp = TICK_ETERNITY;
	else {
		int tout = (!conn_is_back(conn)
			    ? h1c->px->timeout.client
			    : h1c->px->timeout.server);
		h1c->idle_exp = tick_add_ifset(now_ms, tout);
	}
	h1c->task->expire = tick_first(h1c->http_exp, h1c->idle_exp);
	if (tick_isset(h1c->task->expire))
		task_queue(h1c->task);
	return 0;
}

static struct task *h1_io_cb(struct task *t, void *ctx, unsigned short status)
{
	struct h1c *h1c = ctx;
	int ret = 0;

	if (!(h1c->wait_event.wait_reason & SUB_CAN_SEND))
		ret = h1_send(h1c);
	if (!(h1c->wait_event.wait_reason & SUB_CAN_RECV))
		ret |= h1_recv(h1c);
	if (ret || b_data(&h1c->ibuf))
		h1_process(h1c);
	return NULL;
}


static int h1_wake(struct connection *conn)
{
	struct h1c *h1c = conn->mux_ctx;

	return (h1_process(h1c));
}


/* Connection timeout management. The principle is that if there's no receipt
 * nor sending for a certain amount of time, the connection is closed.
 */
static struct task *h1_timeout_task(struct task *t, void *context, unsigned short state)
{
	struct h1c *h1c = context;
	int expired = tick_is_expired(t->expire, now_ms);

	if (!h1c)
		goto end;

	if (!expired) {
		t->expire = tick_first(t->expire, tick_first(h1c->idle_exp, h1c->http_exp));
		return t;
	}

	h1c->flags   |= H1C_F_CS_ERROR;
	h1c->idle_exp = TICK_ETERNITY;
	h1c->http_exp = TICK_ETERNITY;
	t->expire     = TICK_ETERNITY;

	/* Don't try send error message on the server-side */
	if (conn_is_back(h1c->conn))
		goto release;

	/* Don't send error message if no input data is pending _AND_ if null
	 * requests is ignored or it's not the first request.
	 */
	if (!b_data(&h1c->ibuf) && (h1c->px->options & PR_O_IGNORE_PRB ||
				    h1c->flags & H1C_F_WAIT_NEXT_REQ))
		goto release;

	/* Try to allocate output buffer to store the error message. If
	 * allocation fails, just go away.
	 */
	if (!h1_get_buf(h1c, &h1c->obuf))
		goto release;

	h1_cpy_error_message(h1c, &h1c->obuf, 408);
	tasklet_wakeup(h1c->wait_event.task);
	sess_log(h1c->conn->owner);
	return t;

  release:
	if (h1c->h1s) {
		tasklet_wakeup(h1c->wait_event.task);
		return t;
	}
	h1c->task = NULL;
	h1_release(h1c->conn);
  end:
	task_delete(t);
	task_free(t);
	return NULL;
}

/*******************************************/
/* functions below are used by the streams */
/*******************************************/
/*
 * Attach a new stream to a connection
 * (Used for outgoing connections)
 */
static struct conn_stream *h1_attach(struct connection *conn)
{
	struct h1c *h1c = conn->mux_ctx;
	struct conn_stream *cs = NULL;
	struct h1s *h1s;

	if (h1c->flags & H1C_F_CS_ERROR)
		goto end;

	cs = cs_new(h1c->conn);
	if (!cs)
		goto end;

	h1s = h1s_create(h1c, cs);
	if (h1s == NULL)
		goto end;

	return cs;
  end:
	cs_free(cs);
	return NULL;
}

/* Retrieves a valid conn_stream from this connection, or returns NULL. For
 * this mux, it's easy as we can only store a single conn_stream.
 */
static const struct conn_stream *h1_get_first_cs(const struct connection *conn)
{
	struct h1c *h1c = conn->mux_ctx;
	struct h1s *h1s = h1c->h1s;

	if (h1s)
		return h1s->cs;

	return NULL;
}

static void h1_destroy(struct connection *conn)
{
	struct h1c *h1c = conn->mux_ctx;

	if (!h1c->h1s)
		h1_release(conn);
}

/*
 * Detach the stream from the connection and possibly release the connection.
 */
static void h1_detach(struct conn_stream *cs)
{
	struct h1s *h1s = cs->ctx;
	struct h1c *h1c;

	cs->ctx = NULL;
	if (!h1s)
		return;

	h1c = h1s->h1c;
	h1s->cs = NULL;

	h1s_destroy(h1s);

	/* We don't want to close right now unless the connection is in error */
	if ((h1c->flags & (H1C_F_CS_ERROR|H1C_F_CS_SHUTW)) ||
	    (h1c->conn->flags & CO_FL_ERROR))
		h1_release(h1c->conn);
	else
		tasklet_wakeup(h1c->wait_event.task);
}


static void h1_shutr(struct conn_stream *cs, enum cs_shr_mode mode)
{
	struct h1s *h1s = cs->ctx;

	if (!h1s)
		return;

	if ((h1s->flags & H1S_F_WANT_KAL) && !(cs->flags & (CS_FL_REOS|CS_FL_EOS)))
		return;

	/* NOTE: Be sure to handle abort (cf. h2_shutr) */
	if (cs->flags & CS_FL_SHR)
		return;
	if (conn_xprt_ready(cs->conn) && cs->conn->xprt->shutr)
		cs->conn->xprt->shutr(cs->conn, (mode == CS_SHR_DRAIN));
	if (cs->flags & CS_FL_SHW) {
		h1s->h1c->flags = (h1s->h1c->flags & ~H1C_F_CS_SHUTW_NOW) | H1C_F_CS_SHUTW;
		conn_full_close(cs->conn);
	}
}

static void h1_shutw(struct conn_stream *cs, enum cs_shw_mode mode)
{
	struct h1s *h1s = cs->ctx;
	struct h1c *h1c;

	if (!h1s)
		return;
	h1c = h1s->h1c;

	if ((h1s->flags & H1S_F_WANT_KAL) &&
	    !(cs->flags & (CS_FL_REOS|CS_FL_EOS)) &&
	    h1s->req.state == H1_MSG_DONE && h1s->res.state == H1_MSG_DONE)
		return;

	h1c->flags |= H1C_F_CS_SHUTW_NOW;
	if ((cs->flags & CS_FL_SHW) || b_data(&h1c->obuf))
		return;

	h1_shutw_conn(cs->conn);
}

static void h1_shutw_conn(struct connection *conn)
{
	struct h1c *h1c = conn->mux_ctx;

	if (conn_xprt_ready(conn) && conn->xprt->shutw)
		conn->xprt->shutw(conn, 1);
	if (!(conn->flags & CO_FL_SOCK_RD_SH))
		conn_sock_shutw(conn, 1);
	else {
		h1c->flags = (h1c->flags & ~H1C_F_CS_SHUTW_NOW) | H1C_F_CS_SHUTW;
		conn_full_close(conn);
	}
}

/* Called from the upper layer, to unsubscribe to events */
static int h1_unsubscribe(struct conn_stream *cs, int event_type, void *param)
{
	struct wait_event *sw;
	struct h1s *h1s = cs->ctx;

	if (!h1s)
		return 0;

	if (event_type & SUB_CAN_RECV) {
		sw = param;
		if (h1s->recv_wait == sw) {
			sw->wait_reason &= ~SUB_CAN_RECV;
			h1s->recv_wait = NULL;
		}
	}
	if (event_type & SUB_CAN_SEND) {
		sw = param;
		if (h1s->send_wait == sw) {
			sw->wait_reason &= ~SUB_CAN_SEND;
			h1s->send_wait = NULL;
		}
	}
	return 0;
}

/* Called from the upper layer, to subscribe to events, such as being able to send */
static int h1_subscribe(struct conn_stream *cs, int event_type, void *param)
{
	struct wait_event *sw;
	struct h1s *h1s = cs->ctx;

	if (!h1s)
		return -1;

	switch (event_type) {
		case SUB_CAN_RECV:
			sw = param;
			if (!(sw->wait_reason & SUB_CAN_RECV)) {
				sw->wait_reason |= SUB_CAN_RECV;
				sw->handle = h1s;
				h1s->recv_wait = sw;
			}
			return 0;
		case SUB_CAN_SEND:
			sw = param;
			if (!(sw->wait_reason & SUB_CAN_SEND)) {
				sw->wait_reason |= SUB_CAN_SEND;
				sw->handle = h1s;
				h1s->send_wait = sw;
			}
			return 0;
		default:
			break;
	}
	return -1;
}

/* Called from the upper layer, to receive data */
static size_t h1_rcv_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	struct h1s *h1s = cs->ctx;
	size_t ret = 0;

	if (!h1s)
		return ret;

	if (!(h1s->h1c->flags & H1C_F_RX_ALLOC))
		ret = h1_xfer(h1s, buf, count);
	if (ret > 0) {
		if (!(h1s->h1c->wait_event.wait_reason & SUB_CAN_RECV))
			tasklet_wakeup(h1s->h1c->wait_event.task);
	}
	return ret;
}


/* Called from the upper layer, to send data */
static size_t h1_snd_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	struct h1s *h1s = cs->ctx;
	struct h1c *h1c;
	size_t ret = 0;

	if (!h1s)
		return ret;

	h1c = h1s->h1c;

	/* FIXME: There is a problem when the backend server is down. Channel
	 * data are consumed, so CF_WROTE_DATA is set by the stream
	 * interface. We should wait the connection is established before, but
	 * to do so, we need to have a notification of the connection
	 * establishment.
	 */

	if (!(h1c->flags & (H1C_F_OUT_FULL|H1C_F_OUT_ALLOC)) && b_data(buf))
		ret = h1_process_output(h1c, buf, count);
	if (ret > 0) {
		h1_send(h1c);

		/* We need to do that because of the infinite forwarding. */
		if (!b_data(buf))
			ret = count;
	}
	return ret;

}

/****************************************/
/* MUX initialization and instanciation */
/****************************************/

/* The mux operations */
const struct mux_ops mux_h1_ops = {
	.init        = h1_init,
	.wake        = h1_wake,
	.attach      = h1_attach,
	.get_first_cs = h1_get_first_cs,
	.detach      = h1_detach,
	.destroy     = h1_destroy,
	.avail_streams = h1_avail_streams,
	.rcv_buf     = h1_rcv_buf,
	.snd_buf     = h1_snd_buf,
	.subscribe   = h1_subscribe,
	.unsubscribe = h1_unsubscribe,
	.shutr       = h1_shutr,
	.shutw       = h1_shutw,
	.flags       = MX_FL_NONE,
	.name        = "h1",
};


/* this mux registers default HTX proto */
static struct mux_proto_list mux_proto_htx =
{ .token = IST(""), .mode = PROTO_MODE_HTX, .side = PROTO_SIDE_BOTH, .mux = &mux_h1_ops };

static void __h1_deinit(void)
{
	pool_destroy(pool_head_h1c);
	pool_destroy(pool_head_h1s);
}

__attribute__((constructor))
static void __h1_init(void)
{
	register_mux_proto(&mux_proto_htx);
	hap_register_post_deinit(__h1_deinit);
	pool_head_h1c = create_pool("h1c", sizeof(struct h1c), MEM_F_SHARED);
	pool_head_h1s = create_pool("h1s", sizeof(struct h1s), MEM_F_SHARED);
}
/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
