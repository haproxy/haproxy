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
#include <common/h1.h>
#include <common/htx.h>
#include <common/initcall.h>

#include <types/pipe.h>
#include <types/proxy.h>
#include <types/session.h>

#include <proto/connection.h>
#include <proto/http_htx.h>
#include <proto/log.h>
#include <proto/session.h>
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
#define H1C_F_IN_BUSY        0x00000040
/* 0x00000040 - 0x00000800 unused */

#define H1C_F_CS_ERROR       0x00001000 /* connection must be closed ASAP because an error occurred */
#define H1C_F_CS_SHUTW_NOW   0x00002000 /* connection must be shut down for writes ASAP */
#define H1C_F_CS_SHUTDOWN    0x00004000 /* connection is shut down for read and writes */
#define H1C_F_CS_WAIT_CONN   0x00008000 /* waiting for the connection establishment */

#define H1C_F_WAIT_NEXT_REQ  0x00010000 /*  waiting for the next request to start, use keep-alive timeout */

/*
 * H1 Stream flags (32 bits)
 */
#define H1S_F_NONE           0x00000000
#define H1S_F_ERROR          0x00000001 /* An error occurred on the H1 stream */
#define H1S_F_REQ_ERROR      0x00000002 /* An error occurred during the request parsing/xfer */
#define H1S_F_RES_ERROR      0x00000004 /* An error occurred during the response parsing/xfer */
/* 0x00000008 unused */
#define H1S_F_WANT_KAL       0x00000010
#define H1S_F_WANT_TUN       0x00000020
#define H1S_F_WANT_CLO       0x00000040
#define H1S_F_WANT_MSK       0x00000070
#define H1S_F_NOT_FIRST      0x00000080 /* The H1 stream is not the first one */
#define H1S_F_BUF_FLUSH      0x00000100 /* Flush input buffer and don't read more data */
#define H1S_F_SPLICED_DATA   0x00000200 /* Set when the kernel splicing is in used */
#define H1S_F_HAVE_I_EOD     0x00000400 /* Set during input process to know the last empty chunk was processed */
#define H1S_F_HAVE_I_TLR     0x00000800 /* Set during input process to know the trailers were processed */
#define H1S_F_HAVE_O_EOD     0x00001000 /* Set during output process to know the last empty chunk was processed */
#define H1S_F_HAVE_O_TLR     0x00002000 /* Set during output process to know the trailers were processed */

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
	int timeout;                     /* idle timeout duration in ticks */
	int shut_timeout;                /* idle timeout duration in ticks after stream shutdown */
};

/* H1 stream descriptor */
struct h1s {
	struct h1c *h1c;
	struct conn_stream *cs;
	struct cs_info csinfo;         /* CS info, only used for client connections */
	uint32_t flags;                /* Connection flags: H1S_F_* */

	struct wait_event *recv_wait; /* Address of the wait_event the conn_stream associated is waiting on */
	struct wait_event *send_wait; /* Address of the wait_event the conn_stream associated is waiting on */

	struct session *sess;         /* Associated session */
	struct h1m req;
	struct h1m res;

	enum http_meth_t meth; /* HTTP resquest method */
	uint16_t status;       /* HTTP response status */
};

/* the h1c and h1s pools */
DECLARE_STATIC_POOL(pool_head_h1c, "h1c", sizeof(struct h1c));
DECLARE_STATIC_POOL(pool_head_h1s, "h1s", sizeof(struct h1s));

static int h1_recv(struct h1c *h1c);
static int h1_send(struct h1c *h1c);
static int h1_process(struct h1c *h1c);
static struct task *h1_io_cb(struct task *t, void *ctx, unsigned short state);
static void h1_shutw_conn(struct connection *conn, enum cs_shw_mode mode);
static struct task *h1_timeout_task(struct task *t, void *context, unsigned short state);

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
	if (b_data(&h1c->ibuf) == 0 && (h1c->flags & (H1C_F_CS_ERROR|H1C_F_CS_SHUTDOWN)))
		return 0;

	if (h1c->conn->flags & CO_FL_ERROR || conn_xprt_read0_pending(h1c->conn))
		return 0;

	if (!(h1c->flags & (H1C_F_IN_ALLOC|H1C_F_IN_FULL|H1C_F_IN_BUSY)))
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
	struct h1c *h1c = conn->ctx;

	return h1c->h1s ? 0 : 1;
}

static int h1_max_streams(struct connection *conn)
{
	return 1;
}

/*****************************************************************/
/* functions below are dedicated to the mux setup and management */
/*****************************************************************/
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

static struct h1s *h1s_create(struct h1c *h1c, struct conn_stream *cs, struct session *sess)
{
	struct h1s *h1s;

	h1s = pool_alloc(pool_head_h1s);
	if (!h1s)
		goto fail;

	h1s->h1c = h1c;
	h1c->h1s = h1s;

	h1s->sess = sess;

	h1s->cs    = NULL;
	h1s->flags = H1S_F_NONE;

	h1s->recv_wait = NULL;
	h1s->send_wait = NULL;

	h1m_init_req(&h1s->req);
	h1s->req.flags |= H1_MF_NO_PHDR;

	h1m_init_res(&h1s->res);
	h1s->res.flags |= H1_MF_NO_PHDR;

	h1s->status = 0;
	h1s->meth   = HTTP_METH_OTHER;

	if (h1c->flags & H1C_F_WAIT_NEXT_REQ)
		h1s->flags |= H1S_F_NOT_FIRST;
	h1c->flags &= ~H1C_F_WAIT_NEXT_REQ;

	if (!conn_is_back(h1c->conn)) {
		if (h1c->px->options2 & PR_O2_REQBUG_OK)
			h1s->req.err_pos = -1;
	}
	else {
		if (h1c->px->options2 & PR_O2_RSPBUG_OK)
			h1s->res.err_pos = -1;
	}

	/* If a conn_stream already exists, attach it to this H1S. Otherwise we
	 * create a new one.
	 */
	if (cs) {
		h1s->csinfo.create_date = date;
		h1s->csinfo.tv_create   = now;
		h1s->csinfo.t_handshake = 0;
		h1s->csinfo.t_idle      = -1;

		cs->ctx = h1s;
		h1s->cs = cs;
	}
	else {
		/* For frontend connections we should always have a session */
		sess = h1c->conn->owner;

		h1s->csinfo.create_date = sess->accept_date;
		h1s->csinfo.tv_create   = sess->tv_accept;
		h1s->csinfo.t_handshake = sess->t_handshake;
		h1s->csinfo.t_idle      = -1;

		cs = h1s_new_cs(h1s);
		if (!cs)
			goto fail;
	}
	return h1s;

  fail:
	pool_free(pool_head_h1s, h1s);
	return NULL;
}

static void h1s_destroy(struct h1s *h1s)
{
	if (h1s) {
		struct h1c *h1c = h1s->h1c;

		h1c->h1s = NULL;

		if (h1s->recv_wait != NULL)
			h1s->recv_wait->events &= ~SUB_RETRY_RECV;
		if (h1s->send_wait != NULL)
			h1s->send_wait->events &= ~SUB_RETRY_SEND;

		h1c->flags &= ~H1C_F_IN_BUSY;
		h1c->flags |= H1C_F_WAIT_NEXT_REQ;
		if (h1s->flags & (H1S_F_REQ_ERROR|H1S_F_RES_ERROR))
			h1c->flags |= H1C_F_CS_ERROR;

		cs_free(h1s->cs);
		pool_free(pool_head_h1s, h1s);
	}
}

static const struct cs_info *h1_get_cs_info(struct conn_stream *cs)
{
	struct h1s *h1s = cs->ctx;

	if (h1s && !conn_is_back(cs->conn))
		return &h1s->csinfo;
	return NULL;
}

/*
 * Initialize the mux once it's attached. It is expected that conn->ctx
 * points to the existing conn_stream (for outgoing connections) or NULL (for
 * incoming ones). Returns < 0 on error.
 */
static int h1_init(struct connection *conn, struct proxy *proxy, struct session *sess)
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
	h1c->task = NULL;

	LIST_INIT(&h1c->buf_wait.list);
	h1c->wait_event.task = tasklet_new();
	if (!h1c->wait_event.task)
		goto fail;
	h1c->wait_event.task->process = h1_io_cb;
	h1c->wait_event.task->context = h1c;
	h1c->wait_event.events   = 0;

	if (conn->ctx) {
		h1c->shut_timeout = h1c->timeout = proxy->timeout.server;
		if (tick_isset(proxy->timeout.serverfin))
			h1c->shut_timeout = proxy->timeout.serverfin;
	} else {
		h1c->shut_timeout = h1c->timeout = proxy->timeout.client;
		if (tick_isset(proxy->timeout.clientfin))
			h1c->shut_timeout = proxy->timeout.clientfin;
	}
	if (tick_isset(h1c->timeout)) {
		t = task_new(tid_bit);
		if (!t)
			goto fail;

		h1c->task = t;
		t->process = h1_timeout_task;
		t->context = h1c;
		t->expire = tick_add(now_ms, h1c->timeout);
	}

	if (!(conn->flags & CO_FL_CONNECTED))
		h1c->flags |= H1C_F_CS_WAIT_CONN;

	/* Always Create a new H1S */
	if (!h1s_create(h1c, conn->ctx, sess))
		goto fail;

	conn->ctx = h1c;


	if (t)
		task_queue(t);

	/* Try to read, if nothing is available yet we'll just subscribe */
	tasklet_wakeup(h1c->wait_event.task);

	/* mux->wake will be called soon to complete the operation */
	return 0;

  fail:
	if (t)
		task_free(t);
	if (h1c->wait_event.task)
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
	struct h1c *h1c = conn->ctx;

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
		if (h1c->wait_event.events != 0)
			conn->xprt->unsubscribe(conn, h1c->wait_event.events,
			    &h1c->wait_event);
		pool_free(pool_head_h1c, h1c);
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
/* functions below are for the H1 protocol processing */
/******************************************************/
/* Parse the request version and set H1_MF_VER_11 on <h1m> if the version is
 * greater or equal to 1.1
 */
static void h1_parse_req_vsn(struct h1m *h1m, const struct htx_sl *sl)
{
	const char *p = HTX_SL_REQ_VPTR(sl);

	if ((HTX_SL_REQ_VLEN(sl) == 8) &&
	    (*(p + 5) > '1' ||
	     (*(p + 5) == '1' && *(p + 7) >= '1')))
		h1m->flags |= H1_MF_VER_11;
}

/* Parse the response version and set H1_MF_VER_11 on <h1m> if the version is
 * greater or equal to 1.1
 */
static void h1_parse_res_vsn(struct h1m *h1m, const struct htx_sl *sl)
{
	const char *p = HTX_SL_RES_VPTR(sl);

	if ((HTX_SL_RES_VLEN(sl) == 8) &&
	    (*(p + 5) > '1' ||
	     (*(p + 5) == '1' && *(p + 7) >= '1')))
		h1m->flags |= H1_MF_VER_11;
}

/*
 * Check the validity of the request version. If the version is valid, it
 * returns 1. Otherwise, it returns 0.
 */
static int h1_process_req_vsn(struct h1s *h1s, struct h1m *h1m, union h1_sl sl)
{
	struct h1c *h1c = h1s->h1c;

	/* RFC7230#2.6 has enforced the format of the HTTP version string to be
	 * exactly one digit "." one digit. This check may be disabled using
	 * option accept-invalid-http-request.
	 */
	if (!(h1c->px->options2 & PR_O2_REQBUG_OK)) {
		if (sl.rq.v.len != 8)
			return 0;

		if (*(sl.rq.v.ptr + 4) != '/' ||
		    !isdigit((unsigned char)*(sl.rq.v.ptr + 5)) ||
		    *(sl.rq.v.ptr + 6) != '.' ||
		    !isdigit((unsigned char)*(sl.rq.v.ptr + 7)))
			return 0;
	}
	else if (!sl.rq.v.len) {
		/* try to convert HTTP/0.9 requests to HTTP/1.0 */

		/* RFC 1945 allows only GET for HTTP/0.9 requests */
		if (sl.rq.meth != HTTP_METH_GET)
			return 0;

		/* HTTP/0.9 requests *must* have a request URI, per RFC 1945 */
		if (!sl.rq.u.len)
			return 0;

		/* Add HTTP version */
		sl.rq.v = ist("HTTP/1.0");
		return 1;
	}

	if ((sl.rq.v.len == 8) &&
	    ((*(sl.rq.v.ptr + 5) > '1') ||
	     ((*(sl.rq.v.ptr + 5) == '1') && (*(sl.rq.v.ptr + 7) >= '1'))))
		h1m->flags |= H1_MF_VER_11;
	return 1;
}

/*
 * Check the validity of the response version. If the version is valid, it
 * returns 1. Otherwise, it returns 0.
 */
static int h1_process_res_vsn(struct h1s *h1s, struct h1m *h1m, union h1_sl sl)
{
	struct h1c *h1c = h1s->h1c;

	/* RFC7230#2.6 has enforced the format of the HTTP version string to be
	 * exactly one digit "." one digit. This check may be disabled using
	 * option accept-invalid-http-request.
	 */
	if (!(h1c->px->options2 & PR_O2_RSPBUG_OK)) {
		if (sl.st.v.len != 8)
			return 0;

		if (*(sl.st.v.ptr + 4) != '/' ||
		    !isdigit((unsigned char)*(sl.st.v.ptr + 5)) ||
		    *(sl.st.v.ptr + 6) != '.' ||
		    !isdigit((unsigned char)*(sl.st.v.ptr + 7)))
			return 0;
	}

	if ((sl.st.v.len == 8) &&
	    ((*(sl.st.v.ptr + 5) > '1') ||
	     ((*(sl.st.v.ptr + 5) == '1') && (*(sl.st.v.ptr + 7) >= '1'))))
		h1m->flags |= H1_MF_VER_11;

	return 1;
}
/* Remove all "Connection:" headers from the HTX message <htx> */
static void h1_remove_conn_hdrs(struct h1m *h1m, struct htx *htx)
{
	struct ist hdr = {.ptr = "Connection", .len = 10};
	struct http_hdr_ctx ctx;

	while (http_find_header(htx, hdr, &ctx, 1))
		http_remove_header(htx, &ctx);

	h1m->flags &= ~(H1_MF_CONN_KAL|H1_MF_CONN_CLO);
}

/* Add a "Connection:" header with the value <value> into the HTX message
 * <htx>.
 */
static void h1_add_conn_hdr(struct h1m *h1m, struct htx *htx, struct ist value)
{
	struct ist hdr = {.ptr = "Connection", .len = 10};

	http_add_header(htx, hdr, value);
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
		else if (!(h1m->flags & H1_MF_XFER_LEN) || /* no length known => close */
			 (h1m->flags & H1_MF_CONN_CLO && h1s->req.state != H1_MSG_DONE)) /*explicit close and unfinished request */
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
	struct h1c *h1c = h1s->h1c;
	struct session *sess = h1s->sess;
	struct proxy *be = h1c->px;
	int flag =  H1S_F_WANT_KAL;
	int fe_flags = sess ? sess->fe->options : 0;

	/* Tunnel mode can only by set on the frontend */
	if ((fe_flags & PR_O_HTTP_MODE) == PR_O_HTTP_TUN)
		flag = H1S_F_WANT_TUN;

	/* For the server connection: server-close == httpclose */
	if ((fe_flags & PR_O_HTTP_MODE) == PR_O_HTTP_SCL ||
	    (be->options & PR_O_HTTP_MODE) == PR_O_HTTP_SCL ||
	    (fe_flags & PR_O_HTTP_MODE) == PR_O_HTTP_CLO ||
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
	else {
		if (h1s->flags & H1S_F_WANT_KAL &&
		    (!(h1m->flags & (H1_MF_VER_11|H1_MF_CONN_KAL)) || /* no KA in HTTP/1.0 */
		     h1m->flags & H1_MF_CONN_CLO))                    /* explicit close */
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
	}

	/* If KAL, check if the backend is stopping. If yes, switch in CLO mode */
	if (h1s->flags & H1S_F_WANT_KAL && be->state == PR_STSTOPPED)
		h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
}

static void h1_update_req_conn_hdr(struct h1s *h1s, struct h1m *h1m,
				   struct htx *htx, struct ist *conn_val)
{
	struct proxy *px = h1s->h1c->px;

	/* Don't update "Connection:" header in TUNNEL mode or if "Upgrage"
	 * token is found
	 */
	if (h1s->flags & H1S_F_WANT_TUN || h1m->flags & H1_MF_CONN_UPG)
		return;

	if (h1s->flags & H1S_F_WANT_KAL || px->options2 & PR_O2_FAKE_KA) {
		if (h1m->flags & H1_MF_CONN_CLO) {
			if (conn_val)
				*conn_val = ist("");
			if (htx)
				h1_remove_conn_hdrs(h1m, htx);
		}
		if (!(h1m->flags & (H1_MF_VER_11|H1_MF_CONN_KAL))) {
			if (conn_val)
				*conn_val = ist("keep-alive");
			if (htx)
				h1_add_conn_hdr(h1m, htx, ist("keep-alive"));
		}
		if ((h1m->flags & (H1_MF_VER_11|H1_MF_CONN_KAL)) == (H1_MF_VER_11|H1_MF_CONN_KAL)) {
			if (conn_val)
				*conn_val = ist("");
			if (htx)
				h1_remove_conn_hdrs(h1m, htx);
		}
	}
	else { /* H1S_F_WANT_CLO && !PR_O2_FAKE_KA */
		if (h1m->flags & H1_MF_CONN_KAL) {
			if (conn_val)
				*conn_val = ist("");
			if (htx)
				h1_remove_conn_hdrs(h1m, htx);
		}
		if ((h1m->flags & (H1_MF_VER_11|H1_MF_CONN_CLO)) == H1_MF_VER_11) {
			if (conn_val)
				*conn_val = ist("close");
			if (htx)
				h1_add_conn_hdr(h1m, htx, ist("close"));
		}
		if ((h1m->flags & (H1_MF_VER_11|H1_MF_CONN_CLO)) == H1_MF_CONN_CLO) {
			if (conn_val)
				*conn_val = ist("");
			if (htx)
				h1_remove_conn_hdrs(h1m, htx);
		}
	}
}

static void h1_update_res_conn_hdr(struct h1s *h1s, struct h1m *h1m,
					 struct htx *htx, struct ist *conn_val)
{
	/* Don't update "Connection:" header in TUNNEL mode or if "Upgrage"
	 * token is found
	 */
	if (h1s->flags & H1S_F_WANT_TUN || h1m->flags & H1_MF_CONN_UPG)
		return;

	if (h1s->flags & H1S_F_WANT_KAL) {
		if (h1m->flags & H1_MF_CONN_CLO) {
			if (conn_val)
				*conn_val = ist("");
			if (htx)
				h1_remove_conn_hdrs(h1m, htx);
		}
		if (!(h1m->flags & (H1_MF_VER_11|H1_MF_CONN_KAL))) {
			if (conn_val)
				*conn_val = ist("keep-alive");
			if (htx)
				h1_add_conn_hdr(h1m, htx, ist("keep-alive"));
		}
		if ((h1m->flags & (H1_MF_VER_11|H1_MF_CONN_KAL)) == (H1_MF_VER_11|H1_MF_CONN_KAL)) {
			if (conn_val)
				*conn_val = ist("");
			if (htx)
				h1_remove_conn_hdrs(h1m, htx);
		}
	}
	else { /* H1S_F_WANT_CLO */
		if (h1m->flags & H1_MF_CONN_KAL) {
			if (conn_val)
				*conn_val = ist("");
			if (htx)
				h1_remove_conn_hdrs(h1m, htx);
		}
		if ((h1m->flags & (H1_MF_VER_11|H1_MF_CONN_CLO)) == H1_MF_VER_11) {
			if (conn_val)
				*conn_val = ist("close");
			if (htx)
				h1_add_conn_hdr(h1m, htx, ist("close"));
		}
		if ((h1m->flags & (H1_MF_VER_11|H1_MF_CONN_CLO)) == H1_MF_CONN_CLO) {
			if (conn_val)
				*conn_val = ist("");
			if (htx)
				h1_remove_conn_hdrs(h1m, htx);
		}
	}
}

/* Set the right connection mode and update "Connection:" header if
 * needed. <htx> and <conn_val> can be NULL. When <htx> is not NULL, the HTX
 * message is updated accordingly. When <conn_val> is not NULL, it is set with
 * the new header value.
 */
static void h1_process_conn_mode(struct h1s *h1s, struct h1m *h1m,
				 struct htx *htx, struct ist *conn_val)
{
	if (!conn_is_back(h1s->h1c->conn)) {
		h1_set_cli_conn_mode(h1s, h1m);
		if (h1m->flags & H1_MF_RESP)
			h1_update_res_conn_hdr(h1s, h1m, htx, conn_val);
	}
	else {
		h1_set_srv_conn_mode(h1s, h1m);
		if (!(h1m->flags & H1_MF_RESP))
			h1_update_req_conn_hdr(h1s, h1m, htx, conn_val);
	}
}


/* Append the description of what is present in error snapshot <es> into <out>.
 * The description must be small enough to always fit in a buffer. The output
 * buffer may be the trash so the trash must not be used inside this function.
 */
static void h1_show_error_snapshot(struct buffer *out, const struct error_snapshot *es)
{
	chunk_appendf(out,
		      "  H1 connection flags 0x%08x, H1 stream flags 0x%08x\n"
		      "  H1 msg state %s(%d), H1 msg flags 0x%08x\n"
		      "  H1 chunk len %lld bytes, H1 body len %lld bytes :\n",
		      es->ctx.h1.c_flags, es->ctx.h1.s_flags,
		      h1m_state_str(es->ctx.h1.state), es->ctx.h1.state,
		      es->ctx.h1.m_flags, es->ctx.h1.m_clen, es->ctx.h1.m_blen);
}
/*
 * Capture a bad request or response and archive it in the proxy's structure.
 * By default it tries to report the error position as h1m->err_pos. However if
 * this one is not set, it will then report h1m->next, which is the last known
 * parsing point. The function is able to deal with wrapping buffers. It always
 * displays buffers as a contiguous area starting at buf->p. The direction is
 * determined thanks to the h1m's flags.
 */
static void h1_capture_bad_message(struct h1c *h1c, struct h1s *h1s,
				   struct h1m *h1m, struct buffer *buf)
{
	struct session *sess = h1c->conn->owner;
	struct proxy *proxy = h1c->px;
	struct proxy *other_end = sess->fe;
	union error_snapshot_ctx ctx;

	if (h1s->cs->data && !(h1m->flags & H1_MF_RESP))
		other_end = si_strm(h1s->cs->data)->be;

	/* http-specific part now */
	ctx.h1.state   = h1m->state;
	ctx.h1.c_flags = h1c->flags;
	ctx.h1.s_flags = h1s->flags;
	ctx.h1.m_flags = h1m->flags;
	ctx.h1.m_clen  = h1m->curr_len;
	ctx.h1.m_blen  = h1m->body_len;

	proxy_capture_error(proxy, !!(h1m->flags & H1_MF_RESP), other_end,
			    h1c->conn->target, sess, buf, 0, 0,
			    (h1m->err_pos >= 0) ? h1m->err_pos : h1m->next,
			    &ctx, h1_show_error_snapshot);
}

/* Emit the chunksize followed by a CRLF in front of data of the buffer
 * <buf>. It goes backwards and starts with the byte before the buffer's
 * head. The caller is responsible for ensuring there is enough room left before
 * the buffer's head for the string.
 */
static void h1_emit_chunk_size(struct buffer *buf, size_t chksz)
{
	char *beg, *end;

	beg = end = b_head(buf);
	*--beg = '\n';
	*--beg = '\r';
	do {
		*--beg = hextab[chksz & 0xF];
	} while (chksz >>= 4);
	buf->head -= (end - beg);
	b_add(buf, end - beg);
}

/* Emit a CRLF after the data of the buffer <buf>. The caller is responsible for
 * ensuring there is enough room left in the buffer for the string. */
static void h1_emit_chunk_crlf(struct buffer *buf)
{
	*(b_peek(buf, b_data(buf)))     = '\r';
	*(b_peek(buf, b_data(buf) + 1)) = '\n';
	b_add(buf, 2);
}

/*
 * Parse HTTP/1 headers. It returns the number of bytes parsed if > 0, or 0 if
 * it couldn't proceed. Parsing errors are reported by setting H1S_F_*_ERROR
 * flag and filling h1s->err_pos and h1s->err_state fields. This functions is
 * responsible to update the parser state <h1m>.
 */
static size_t h1_process_headers(struct h1s *h1s, struct h1m *h1m, struct htx *htx,
				 struct buffer *buf, size_t *ofs, size_t max)
{
	struct http_hdr hdrs[MAX_HTTP_HDR];
	union h1_sl h1sl;
	unsigned int flags = HTX_SL_F_NONE;
	int ret = 0;

	if (!max)
		goto end;

	/* Realing input buffer if necessary */
	if (b_head(buf) + b_data(buf) > b_wrap(buf))
		b_slow_realign(buf, trash.area, 0);

	ret = h1_headers_to_hdr_list(b_peek(buf, *ofs), b_peek(buf, *ofs) + max,
				     hdrs, sizeof(hdrs)/sizeof(hdrs[0]), h1m, &h1sl);
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

	/* Save the request's method or the response's status, check if the body
	 * length is known and check the VSN validity */
	if (!(h1m->flags & H1_MF_RESP)) {
		h1s->meth = h1sl.rq.meth;

		/* Request have always a known length */
		h1m->flags |= H1_MF_XFER_LEN;
		if (!(h1m->flags & H1_MF_CHNK) && !h1m->body_len)
			h1m->state = H1_MSG_DONE;

		if (!h1_process_req_vsn(h1s, h1m, h1sl)) {
			h1m->err_pos = h1sl.rq.v.ptr - b_head(buf);
			h1m->err_state = h1m->state;
			goto vsn_error;
		}
	}
	else {
		h1s->status = h1sl.st.status;

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

		if (!h1_process_res_vsn(h1s, h1m, h1sl)) {
			h1m->err_pos = h1sl.st.v.ptr - b_head(buf);
			h1m->err_state = h1m->state;
			goto vsn_error;
		}
	}

	/* Set HTX start-line flags */
	if (h1m->flags & H1_MF_VER_11)
		flags |= HTX_SL_F_VER_11;
	if (h1m->flags & H1_MF_XFER_ENC)
		flags |= HTX_SL_F_XFER_ENC;
	if (h1m->flags & H1_MF_XFER_LEN) {
		flags |= HTX_SL_F_XFER_LEN;
		if (h1m->flags & H1_MF_CHNK)
			flags |= HTX_SL_F_CHNK;
		else if (h1m->flags & H1_MF_CLEN)
			flags |= HTX_SL_F_CLEN;
		if (h1m->state == H1_MSG_DONE)
			flags |= HTX_SL_F_BODYLESS;
	}

	if (!(h1m->flags & H1_MF_RESP)) {
		struct htx_sl *sl;

		sl = htx_add_stline(htx, HTX_BLK_REQ_SL, flags, h1sl.rq.m, h1sl.rq.u, h1sl.rq.v);
		if (!sl || !htx_add_all_headers(htx, hdrs))
			goto error;
		sl->info.req.meth = h1s->meth;
	}
	else {
		struct htx_sl *sl;

		flags |= HTX_SL_F_IS_RESP;
		sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, h1sl.st.v, h1sl.st.c, h1sl.st.r);
		if (!sl || !htx_add_all_headers(htx, hdrs))
			goto error;
		sl->info.res.status = h1s->status;
	}

	if (h1m->state == H1_MSG_DONE)
		if (!htx_add_endof(htx, HTX_BLK_EOM))
			goto error;

	h1_process_conn_mode(h1s, h1m, htx, NULL);

	/* If body length cannot be determined, set htx->extra to
	 * ULLONG_MAX. This value is impossible in other cases.
	 */
	htx->extra = ((h1m->flags & H1_MF_XFER_LEN) ? h1m->curr_len : ULLONG_MAX);

	/* Recheck there is enough space to do headers rewritting */
	if (htx_used_space(htx) > b_size(buf) - global.tune.maxrewrite)
		goto error;

	*ofs += ret;
  end:
	return ret;

  error:
	h1m->err_state = h1m->state;
	h1m->err_pos = h1m->next;
  vsn_error:
	h1s->flags |= (!(h1m->flags & H1_MF_RESP) ? H1S_F_REQ_ERROR : H1S_F_RES_ERROR);
	h1_capture_bad_message(h1s->h1c, h1s, h1m, buf);
	ret = 0;
	goto end;
}

/*
 * Parse HTTP/1 body. It returns the number of bytes parsed if > 0, or 0 if it
 * couldn't proceed. Parsing errors are reported by setting H1S_F_*_ERROR flag
 * and filling h1s->err_pos and h1s->err_state fields. This functions is
 * responsible to update the parser state <h1m>.
 */
static size_t h1_process_data(struct h1s *h1s, struct h1m *h1m, struct htx *htx,
			      struct buffer *buf, size_t *ofs, size_t max,
			      struct buffer *htxbuf)
{
	uint32_t data_space = htx_free_data_space(htx);
	size_t total = 0;
	int ret = 0;

	if (h1m->flags & H1_MF_XFER_LEN) {
		if (h1m->flags & H1_MF_CLEN) {
			/* content-length: read only h2m->body_len */
			ret = max;
			if (ret > data_space)
				ret = data_space;
			if ((uint64_t)ret > h1m->curr_len)
				ret = h1m->curr_len;
			if (ret > b_contig_data(buf, *ofs))
				ret = b_contig_data(buf, *ofs);
			if (ret) {
				/* very often with large files we'll face the following
				 * situation :
				 *   - htx is empty and points to <htxbuf>
				 *   - ret == buf->data
				 *   - buf->head == sizeof(struct htx)
				 *   => we can swap the buffers and place an htx header into
				 *      the target buffer instead
				 */
				if (unlikely(htx_is_empty(htx) && ret == b_data(buf) &&
					     !*ofs && b_head_ofs(buf) == sizeof(struct htx))) {
					void *raw_area = buf->area;
					void *htx_area = htxbuf->area;
					struct htx_blk *blk;

					buf->area = htx_area;
					htxbuf->area = raw_area;
					htx = (struct htx *)htxbuf->area;
					htx->size = htxbuf->size - sizeof(*htx);
					htx_reset(htx);
					b_set_data(htxbuf, b_size(htxbuf));

					blk = htx_add_blk(htx, HTX_BLK_DATA, ret);
					blk->info += ret;
					/* nothing else to do, the old buffer now contains an
					 * empty pre-initialized HTX header
					 */
				}
				else if (!htx_add_data(htx, ist2(b_peek(buf, *ofs), ret)))
					goto end;
				h1m->curr_len -= ret;
				*ofs += ret;
				total += ret;
			}

			if (!h1m->curr_len) {
				if (!htx_add_endof(htx, HTX_BLK_EOM))
					goto end;
				h1m->state = H1_MSG_DONE;
			}
		}
		else if (h1m->flags & H1_MF_CHNK) {
		  new_chunk:
			/* te:chunked : parse chunks */
			if (h1m->state == H1_MSG_CHUNK_CRLF) {
				ret = h1_skip_chunk_crlf(buf, *ofs, *ofs + max);
				if (ret <= 0)
					goto end;
				h1m->state = H1_MSG_CHUNK_SIZE;

				max -= ret;
				*ofs += ret;
				total += ret;
			}

			if (h1m->state == H1_MSG_CHUNK_SIZE) {
				unsigned int chksz;

				ret = h1_parse_chunk_size(buf, *ofs, *ofs + max, &chksz);
				if (ret <= 0)
					goto end;
				if (!chksz) {
					if (!htx_add_endof(htx, HTX_BLK_EOD))
						goto end;
					h1s->flags |= H1S_F_HAVE_I_EOD;
					h1m->state = H1_MSG_TRAILERS;
				}
				else
					h1m->state = H1_MSG_DATA;

				h1m->curr_len  = chksz;
				h1m->body_len += chksz;
				max -= ret;
				*ofs += ret;
				total += ret;
			}

			if (h1m->state == H1_MSG_DATA) {
				ret = max;
				if (ret > data_space)
					ret = data_space;
				if ((uint64_t)ret > h1m->curr_len)
					ret = h1m->curr_len;
				if (ret > b_contig_data(buf, *ofs))
					ret = b_contig_data(buf, *ofs);
				if (ret) {
					if (!htx_add_data(htx, ist2(b_peek(buf, *ofs), ret)))
						goto end;
					h1m->curr_len -= ret;
					max -= ret;
					*ofs += ret;
					total += ret;
				}
				if (!h1m->curr_len) {
					h1m->state = H1_MSG_CHUNK_CRLF;
					goto new_chunk;
				}
				goto end;
			}

			if (h1m->state == H1_MSG_TRAILERS) {
				/* Trailers were alread parsed, only the EOM
				 * need to be added */
				if (h1s->flags & H1S_F_HAVE_I_TLR)
					goto skip_tlr_parsing;

				ret = h1_measure_trailers(buf, *ofs, *ofs + max);
				if (ret > data_space)
					ret = (htx_is_empty(htx) ? -1 : 0);
				if (ret <= 0)
					goto end;

				/* Realing input buffer if tailers wrap. For now
				 * this is a workaroung. Because trailers are
				 * not split on CRLF, like headers, there is no
				 * way to know where to split it when trailers
				 * wrap. This is a limitation of
				 * h1_measure_trailers.
				 */
				if (b_peek(buf, *ofs) > b_peek(buf, *ofs + ret))
					b_slow_realign(buf, trash.area, 0);

				if (!htx_add_trailer(htx, ist2(b_peek(buf, *ofs), ret)))
					goto end;
				h1s->flags |= H1S_F_HAVE_I_TLR;
				max -= ret;
				*ofs += ret;
				total += ret;

			  skip_tlr_parsing:
				if (!htx_add_endof(htx, HTX_BLK_EOM))
					goto end;
				h1m->state = H1_MSG_DONE;
			}
		}
		else {
			/* XFER_LEN is set but not CLEN nor CHNK, it means there
			 * is no body. Switch the message in DONE state
			 */
			if (!htx_add_endof(htx, HTX_BLK_EOM))
				goto end;
			h1m->state = H1_MSG_DONE;
		}
	}
	else {
		/* no content length, read till SHUTW */
		ret = max;
		if (ret > data_space)
			ret = data_space;
		if (ret > b_contig_data(buf, *ofs))
			ret = b_contig_data(buf, *ofs);
		if (ret) {
			if (!htx_add_data(htx, ist2(b_peek(buf, *ofs), ret)))
				goto end;

			*ofs += ret;
			total = ret;
		}
	}

  end:
	if (ret < 0) {
		h1s->flags |= (!(h1m->flags & H1_MF_RESP) ? H1S_F_REQ_ERROR : H1S_F_RES_ERROR);
		h1m->err_state = h1m->state;
		h1m->err_pos = *ofs + max + ret;
		h1_capture_bad_message(h1s->h1c, h1s, h1m, buf);
		return 0;
	}
	/* update htx->extra, only when the body length is known */
	if (h1m->flags & H1_MF_XFER_LEN)
		htx->extra = h1m->curr_len;
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
	    (conn_is_back(h1c->conn) || !b_data(&h1c->obuf))) {
		/* For 100-Continue response or any other informational 1xx
		 * response which is non-final, don't reset the request, the
		 * transaction is not finished. We take care the response was
		 * transferred before.
		 */
		h1m_init_res(&h1s->res);
		h1s->res.flags |= H1_MF_NO_PHDR;
		h1c->flags &= ~H1C_F_IN_BUSY;
	}
	else if (!b_data(&h1c->obuf) &&
		 h1s->req.state == H1_MSG_DONE && h1s->res.state == H1_MSG_DONE) {
		if (h1s->flags & H1S_F_WANT_TUN) {
			h1m_init_req(&h1s->req);
			h1m_init_res(&h1s->res);
			h1s->req.state = H1_MSG_TUNNEL;
			h1s->res.state = H1_MSG_TUNNEL;
			h1c->flags &= ~H1C_F_IN_BUSY;
		}
	}
}

/*
 * Process incoming data. It parses data and transfer them from h1c->ibuf into
 * <buf>. It returns the number of bytes parsed and transferred if > 0, or 0 if
 * it couldn't proceed.
 */
static size_t h1_process_input(struct h1c *h1c, struct buffer *buf, int flags)
{
	struct h1s *h1s = h1c->h1s;
	struct h1m *h1m;
	struct htx *htx;
	size_t total = 0;
	size_t ret = 0;
	size_t count, max;
	int errflag;

	htx = htx_from_buf(buf);
	count = b_data(&h1c->ibuf);
	max = htx_free_space(htx);
	if (flags & CO_RFL_KEEP_RSV) {
		if (max < global.tune.maxrewrite)
			goto end;
		max -= global.tune.maxrewrite;
	}
	if (count > max)
		count = max;

	if (!count)
		goto end;

	if (!conn_is_back(h1c->conn)) {
		h1m = &h1s->req;
		errflag = H1S_F_REQ_ERROR;
	}
	else {
		h1m = &h1s->res;
		errflag = H1S_F_RES_ERROR;
	}

	do {
		if (h1m->state <= H1_MSG_LAST_LF) {
			ret = h1_process_headers(h1s, h1m, htx, &h1c->ibuf, &total, count);
			if (!ret)
				break;
		}
		else if (h1m->state <= H1_MSG_TRAILERS) {
			ret = h1_process_data(h1s, h1m, htx, &h1c->ibuf, &total, count, buf);
			htx = htx_from_buf(buf);
			if (!ret)
				break;
		}
		else if (h1m->state == H1_MSG_DONE) {
			h1c->flags |= H1C_F_IN_BUSY;
			break;
		}
		else if (h1m->state == H1_MSG_TUNNEL) {
			ret = h1_process_data(h1s, h1m, htx, &h1c->ibuf, &total, count, buf);
			htx = htx_from_buf(buf);
			if (!ret)
				break;
		}
		else {
			h1s->flags |= errflag;
			break;
		}

		count -= ret;
	} while (!(h1s->flags & errflag) && count);

	if (h1s->flags & errflag)
		goto parsing_err;

	b_del(&h1c->ibuf, total);

  end:
	htx_to_buf(htx, buf);

	if (h1c->flags & H1C_F_IN_FULL && buf_room_for_htx_data(&h1c->ibuf)) {
		h1c->flags &= ~H1C_F_IN_FULL;
		tasklet_wakeup(h1c->wait_event.task);
	}

	h1s->cs->flags &= ~(CS_FL_RCV_MORE | CS_FL_WANT_ROOM);

	if (!b_data(&h1c->ibuf)) {
		h1_release_buf(h1c, &h1c->ibuf);
		h1_sync_messages(h1c);
	}
	else if (!htx_is_empty(htx))
		h1s->cs->flags |= CS_FL_RCV_MORE | CS_FL_WANT_ROOM;

	if ((h1s->cs->flags & CS_FL_REOS) && (!b_data(&h1c->ibuf) || htx_is_empty(htx))) {
		h1s->cs->flags |= CS_FL_EOS;
	}

	return total;

  parsing_err:
	b_reset(&h1c->ibuf);
	htx->flags |= HTX_FL_PARSING_ERROR;
	htx_to_buf(htx, buf);
	h1s->cs->flags |= CS_FL_EOS;
	return 0;
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
	struct htx *chn_htx;
	struct htx_blk *blk;
	struct buffer *tmp;
	size_t total = 0;
	int process_conn_mode = 1; /* If still 1 on EOH, process the connection mode */
	int errflag;

	if (!count)
		goto end;

	chn_htx = htx_from_buf(buf);
	if (htx_is_empty(chn_htx))
		goto end;

	if (!h1_get_buf(h1c, &h1c->obuf)) {
		h1c->flags |= H1C_F_OUT_ALLOC;
		goto end;
	}

	if (!conn_is_back(h1c->conn)) {
		h1m = &h1s->res;
		errflag = H1S_F_RES_ERROR;
	}
	else {
		h1m = &h1s->req;
		errflag = H1S_F_REQ_ERROR;
	}

	/* the htx is non-empty thus has at least one block */
	blk = htx_get_head_blk(chn_htx);

	tmp = get_trash_chunk();

	/* Perform some optimizations to reduce the number of buffer copies.
	 * First, if the mux's buffer is empty and the htx area contains
	 * exactly one data block of the same size as the requested count,
	 * then it's possible to simply swap the caller's buffer with the
	 * mux's output buffer and adjust offsets and length to match the
	 * entire DATA HTX block in the middle. In this case we perform a
	 * true zero-copy operation from end-to-end. This is the situation
	 * that happens all the time with large files. Second, if this is not
	 * possible, but the mux's output buffer is empty, we still have an
	 * opportunity to avoid the copy to the intermediary buffer, by making
	 * the intermediary buffer's area point to the output buffer's area.
	 * In this case we want to skip the HTX header to make sure that copies
	 * remain aligned and that this operation remains possible all the
	 * time. This goes for headers, data blocks and any data extracted from
	 * the HTX blocks.
	 */
	if (!b_data(&h1c->obuf)) {
		h1c->obuf.head = sizeof(struct htx) + blk->addr;

		if (chn_htx->used == 1 &&
		    htx_get_blk_type(blk) == HTX_BLK_DATA &&
		    htx_get_blk_value(chn_htx, blk).len == count) {
			void *old_area = h1c->obuf.area;

			h1c->obuf.area = buf->area;
			h1c->obuf.data = count;

			buf->area = old_area;
			buf->data = buf->head = 0;

			/* The message is chunked. We need to emit the chunk
			 * size. We have at least the size of the struct htx to
			 * write the chunk envelope. It should be enough.
			 */
			if (h1m->flags & H1_MF_CHNK) {
				h1_emit_chunk_size(&h1c->obuf, count);
				h1_emit_chunk_crlf(&h1c->obuf);
			}

			total += count;
			goto out;
		}
		tmp->area = h1c->obuf.area + h1c->obuf.head;
	}

	tmp->size = b_room(&h1c->obuf);

	while (count && !(h1s->flags & errflag) && blk) {
		struct htx_sl *sl;
		struct ist n, v;
		enum htx_blk_type type = htx_get_blk_type(blk);
		uint32_t sz = htx_get_blksz(blk);
		uint32_t vlen;

		vlen = sz;
		if (vlen > count) {
			if (type != HTX_BLK_DATA && type != HTX_BLK_TLR)
				goto copy;
			vlen = count;
		}

		switch (type) {
			case HTX_BLK_UNUSED:
				break;

			case HTX_BLK_REQ_SL:
				h1m_init_req(h1m);
				h1m->flags |= H1_MF_NO_PHDR;
				sl = htx_get_blk_ptr(chn_htx, blk);
				h1s->meth = sl->info.req.meth;
				h1_parse_req_vsn(h1m, sl);
				if (!htx_reqline_to_h1(sl, tmp))
					goto copy;
				h1m->flags |= H1_MF_XFER_LEN;
				h1m->state = H1_MSG_HDR_FIRST;
				break;

			case HTX_BLK_RES_SL:
				h1m_init_res(h1m);
				h1m->flags |= H1_MF_NO_PHDR;
				sl = htx_get_blk_ptr(chn_htx, blk);
				h1s->status = sl->info.res.status;
				h1_parse_res_vsn(h1m, sl);
				if (!htx_stline_to_h1(sl, tmp))
					goto copy;
				if (sl->flags & HTX_SL_F_XFER_LEN)
					h1m->flags |= H1_MF_XFER_LEN;
				if (sl->info.res.status < 200 &&
				    (sl->info.res.status == 100 || sl->info.res.status >= 102))
					process_conn_mode = 0;
				h1m->state = H1_MSG_HDR_FIRST;
				break;

			case HTX_BLK_HDR:
				h1m->state = H1_MSG_HDR_NAME;
				n = htx_get_blk_name(chn_htx, blk);
				v = htx_get_blk_value(chn_htx, blk);

				if (isteqi(n, ist("transfer-encoding")))
					h1_parse_xfer_enc_header(h1m, v);
				else if (isteqi(n, ist("content-length"))) {
					if (h1_parse_cont_len_header(h1m, &v) <= 0)
						goto skip_hdr;
				}
				else if (isteqi(n, ist("connection"))) {
					h1_parse_connection_header(h1m, v);
					h1_process_conn_mode(h1s, h1m, NULL, &v);
					process_conn_mode = 0;
					if (!v.len)
						goto skip_hdr;
				}

				if (!htx_hdr_to_h1(n, v, tmp))
					goto copy;
			  skip_hdr:
				h1m->state = H1_MSG_HDR_L2_LWS;
				break;

			case HTX_BLK_PHDR:
				/* not implemented yet */
				h1m->flags |= errflag;
				break;

			case HTX_BLK_EOH:
				if (h1m->state != H1_MSG_LAST_LF && process_conn_mode) {
					/* There is no "Connection:" header and
					 * it the conn_mode must be
					 * processed. So do it */
					n = ist("Connection");
					v = ist("");
					h1_process_conn_mode(h1s, h1m, NULL, &v);
					process_conn_mode = 0;
					if (v.len) {
						if (!htx_hdr_to_h1(n, v, tmp))
							goto copy;
					}
				}

				if ((h1m->flags & (H1_MF_VER_11|H1_MF_RESP|H1_MF_CLEN|H1_MF_CHNK|H1_MF_XFER_LEN)) ==
				    (H1_MF_VER_11|H1_MF_RESP|H1_MF_XFER_LEN)) {
					/* chunking needed but header not seen */
					if (!chunk_memcat(tmp, "transfer-encoding: chunked\r\n", 28))
						goto copy;
					h1m->flags |= H1_MF_CHNK;
				}

				h1m->state = H1_MSG_LAST_LF;
				if (!chunk_memcat(tmp, "\r\n", 2))
					goto copy;

				h1m->state = H1_MSG_DATA;
				break;

			case HTX_BLK_DATA:
				v = htx_get_blk_value(chn_htx, blk);
				v.len = vlen;
				if (!htx_data_to_h1(v, tmp, !!(h1m->flags & H1_MF_CHNK)))
					goto copy;
				break;

			case HTX_BLK_EOD:
				if (!chunk_memcat(tmp, "0\r\n", 3))
					goto copy;
				h1s->flags |= H1S_F_HAVE_O_EOD;
				h1m->state = H1_MSG_TRAILERS;
				break;

			case HTX_BLK_TLR:
				if (!(h1s->flags & H1S_F_HAVE_O_EOD)) {
					if (!chunk_memcat(tmp, "0\r\n", 3))
						goto copy;
					h1s->flags |= H1S_F_HAVE_O_EOD;
				}
				v = htx_get_blk_value(chn_htx, blk);
				v.len = vlen;
				if (!htx_trailer_to_h1(v, tmp))
					goto copy;
				h1s->flags |= H1S_F_HAVE_O_TLR;
				break;

			case HTX_BLK_EOM:
				if ((h1m->flags & H1_MF_CHNK)) {
					if (!(h1s->flags & H1S_F_HAVE_O_EOD)) {
						if (!chunk_memcat(tmp, "0\r\n", 3))
							goto copy;
						h1s->flags |= H1S_F_HAVE_O_EOD;
					}
					if (!(h1s->flags & H1S_F_HAVE_O_TLR)) {
						if (!chunk_memcat(tmp, "\r\n", 2))
							goto copy;
						h1s->flags |= H1S_F_HAVE_O_TLR;
					}
				}
				h1m->state = H1_MSG_DONE;
				break;

			case HTX_BLK_OOB:
				v = htx_get_blk_value(chn_htx, blk);
				if (!chunk_memcat(tmp, v.ptr, v.len))
					goto copy;
				break;

			default:
				h1m->flags |= errflag;
				break;
		}
		total += vlen;
		count -= vlen;
		if (sz == vlen)
			blk = htx_remove_blk(chn_htx, blk);
		else {
			htx_cut_data_blk(chn_htx, blk, vlen);
			break;
		}
	}

  copy:
	/* when the output buffer is empty, tmp shares the same area so that we
	 * only have to update pointers and lengths.
	 */
	if (tmp->area == h1c->obuf.area)
		h1c->obuf.data = tmp->data;
	else
		b_putblk(&h1c->obuf, tmp->area, tmp->data);

	htx_to_buf(chn_htx, buf);
 out:
	if (!buf_room_for_htx_data(&h1c->obuf))
		h1c->flags |= H1C_F_OUT_FULL;
  end:
	return total;
}

/*********************************************************/
/* functions below are I/O callbacks from the connection */
/*********************************************************/
static void h1_wake_stream_for_recv(struct h1s *h1s)
{
	if (h1s && h1s->recv_wait) {
		h1s->recv_wait->events &= ~SUB_RETRY_RECV;
		tasklet_wakeup(h1s->recv_wait->task);
		h1s->recv_wait = NULL;
	}
}
static void h1_wake_stream_for_send(struct h1s *h1s)
{
	if (h1s && h1s->send_wait) {
		h1s->send_wait->events &= ~SUB_RETRY_SEND;
		tasklet_wakeup(h1s->send_wait->task);
		h1s->send_wait = NULL;
	}
}

/*
 * Attempt to read data, and subscribe if none available
 */
static int h1_recv(struct h1c *h1c)
{
	struct connection *conn = h1c->conn;
		struct h1s *h1s = h1c->h1s;
	size_t ret = 0, max;
	int rcvd = 0;

	if (h1c->wait_event.events & SUB_RETRY_RECV)
		return (b_data(&h1c->ibuf));

	if (!h1_recv_allowed(h1c)) {
		rcvd = 1;
		goto end;
	}

	if (h1s && (h1s->flags & (H1S_F_BUF_FLUSH|H1S_F_SPLICED_DATA))) {
		rcvd = 1;
		goto end;
	}

	if (!h1_get_buf(h1c, &h1c->ibuf)) {
		h1c->flags |= H1C_F_IN_ALLOC;
		goto end;
	}

	/*
	 * If we only have a small amount of data, realign it,
	 * it's probably cheaper than doing 2 recv() calls.
	 */
	if (b_data(&h1c->ibuf) > 0 && b_data(&h1c->ibuf) < 128)
		b_slow_realign(&h1c->ibuf, trash.area, 0);

	max = buf_room_for_htx_data(&h1c->ibuf);
	if (max) {
		h1c->flags &= ~H1C_F_IN_FULL;

		b_realign_if_empty(&h1c->ibuf);
		if (!b_data(&h1c->ibuf)) {
			/* try to pre-align the buffer like the rxbufs will be
			 * to optimize memory copies.
			 */
			h1c->ibuf.head  = sizeof(struct htx);
		}
		ret = conn->xprt->rcv_buf(conn, &h1c->ibuf, max, 0);
	}
	if (ret > 0) {
		rcvd = 1;
		if (h1s && h1s->cs) {
			h1s->cs->flags |= (CS_FL_READ_PARTIAL|CS_FL_RCV_MORE);
			if (h1s->csinfo.t_idle == -1)
				h1s->csinfo.t_idle = tv_ms_elapsed(&h1s->csinfo.tv_create, &now) - h1s->csinfo.t_handshake;
		}
	}

	if (!h1_recv_allowed(h1c) || !buf_room_for_htx_data(&h1c->ibuf)) {
		rcvd = 1;
		goto end;
	}

	conn->xprt->subscribe(conn, SUB_RETRY_RECV, &h1c->wait_event);

  end:
	if (ret > 0 || (conn->flags & CO_FL_ERROR) || conn_xprt_read0_pending(conn))
		h1_wake_stream_for_recv(h1s);

	if (conn_xprt_read0_pending(conn) && h1s && h1s->cs)
		h1s->cs->flags |= CS_FL_REOS;
	if (!b_data(&h1c->ibuf))
		h1_release_buf(h1c, &h1c->ibuf);
	else if (!buf_room_for_htx_data(&h1c->ibuf))
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

	if (h1c->flags & H1C_F_CS_WAIT_CONN) {
		if (!(h1c->wait_event.events & SUB_RETRY_SEND))
			conn->xprt->subscribe(conn, SUB_RETRY_SEND, &h1c->wait_event);
		return 0;
	}

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

	if (conn->flags & (CO_FL_ERROR|CO_FL_SOCK_WR_SH)) {
		/* error or output closed, nothing to send, clear the buffer to release it */
		b_reset(&h1c->obuf);
	}

  end:
	if (!(h1c->flags & H1C_F_OUT_FULL))
		h1_wake_stream_for_send(h1c->h1s);

	/* We're done, no more to send */
	if (!b_data(&h1c->obuf)) {
		h1_release_buf(h1c, &h1c->obuf);
		h1_sync_messages(h1c);
		if (h1c->flags & H1C_F_CS_SHUTW_NOW)
			h1_shutw_conn(conn, CS_SHW_NORMAL);
	}
	else if (!(h1c->wait_event.events & SUB_RETRY_SEND))
		conn->xprt->subscribe(conn, SUB_RETRY_SEND, &h1c->wait_event);

	return sent;
}


/* callback called on any event by the connection handler.
 * It applies changes and returns zero, or < 0 if it wants immediate
 * destruction of the connection.
 */
static int h1_process(struct h1c * h1c)
{
	struct connection *conn = h1c->conn;
	struct h1s *h1s = h1c->h1s;

	if (!conn->ctx)
		return -1;

	if (h1c->flags & H1C_F_CS_WAIT_CONN) {
		if (!(conn->flags & (CO_FL_CONNECTED|CO_FL_ERROR)))
			goto end;
		h1c->flags &= ~H1C_F_CS_WAIT_CONN;
		h1_wake_stream_for_send(h1s);
	}

	if (!h1s) {
		if (h1c->flags & H1C_F_CS_ERROR   ||
		    conn->flags & CO_FL_ERROR     ||
		    conn_xprt_read0_pending(conn))
			goto release;
		if (!conn_is_back(conn) && !(h1c->flags & (H1C_F_CS_SHUTW_NOW|H1C_F_CS_SHUTDOWN))) {
			if (!h1s_create(h1c, NULL, NULL))
				goto release;
		}
		else
			goto end;
		h1s = h1c->h1s;
	}

	if (b_data(&h1c->ibuf) && h1s->csinfo.t_idle == -1)
		h1s->csinfo.t_idle = tv_ms_elapsed(&h1s->csinfo.tv_create, &now) - h1s->csinfo.t_handshake;

	if (!b_data(&h1c->ibuf) && h1s && h1s->cs && h1s->cs->data_cb->wake &&
	    (conn_xprt_read0_pending(conn) || h1c->flags & H1C_F_CS_ERROR ||
	    conn->flags & CO_FL_ERROR)) {
		int flags = 0;

		if (h1c->flags & H1C_F_CS_ERROR || conn->flags & CO_FL_ERROR)
			flags |= CS_FL_ERROR;
		if (conn_xprt_read0_pending(conn))
			flags |= CS_FL_EOS;
		h1s->cs->flags |= flags;
		h1s->cs->data_cb->wake(h1s->cs);
	}
  end:
	if (h1c->task) {
		h1c->task->expire = TICK_ETERNITY;
		if (b_data(&h1c->obuf)) {
			h1c->task->expire = tick_add(now_ms, ((h1c->flags & (H1C_F_CS_SHUTW_NOW|H1C_F_CS_SHUTDOWN))
							      ? h1c->shut_timeout
							      : h1c->timeout));
			task_queue(h1c->task);
		}
	}
	return 0;

  release:
	h1_release(conn);
	return -1;
}

static struct task *h1_io_cb(struct task *t, void *ctx, unsigned short status)
{
	struct h1c *h1c = ctx;
	int ret = 0;

	if (!(h1c->wait_event.events & SUB_RETRY_SEND))
		ret = h1_send(h1c);
	if (!(h1c->wait_event.events & SUB_RETRY_RECV))
		ret |= h1_recv(h1c);
	if (ret || !h1c->h1s)
		h1_process(h1c);
	return NULL;
}

static void h1_reset(struct connection *conn)
{
	struct h1c *h1c = conn->ctx;

	/* Reset the flags, and let the mux know we're waiting for a connection */
	h1c->flags = H1C_F_CS_WAIT_CONN;
}

static int h1_wake(struct connection *conn)
{
	struct h1c *h1c = conn->ctx;
	int ret;

	h1_send(h1c);
	ret = h1_process(h1c);
	if (ret == 0) {
		struct h1s *h1s = h1c->h1s;

		if (h1s && h1s->cs && h1s->cs->data_cb->wake)
			ret = h1s->cs->data_cb->wake(h1s->cs);
	}
	return ret;
}

/* Connection timeout management. The principle is that if there's no receipt
 * nor sending for a certain amount of time, the connection is closed.
 */
static struct task *h1_timeout_task(struct task *t, void *context, unsigned short state)
{
	struct h1c *h1c = context;
	int expired = tick_is_expired(t->expire, now_ms);

	if (!expired && h1c)
		return t;

	task_delete(t);
	task_free(t);

	if (!h1c) {
		/* resources were already deleted */
		return NULL;
	}

	h1c->task = NULL;
	/* If a stream is still attached to the mux, just set an error and wait
	 * for the stream's timeout. Otherwise, release the mux. This is only ok
	 * because same timeouts are used.
	 */
	if (h1c->h1s && h1c->h1s->cs)
		h1c->flags |= H1C_F_CS_ERROR;
	else
		h1_release(h1c->conn);
	return NULL;
}

/*******************************************/
/* functions below are used by the streams */
/*******************************************/
/*
 * Attach a new stream to a connection
 * (Used for outgoing connections)
 */
static struct conn_stream *h1_attach(struct connection *conn, struct session *sess)
{
	struct h1c *h1c = conn->ctx;
	struct conn_stream *cs = NULL;
	struct h1s *h1s;

	if (h1c->flags & H1C_F_CS_ERROR)
		goto end;

	cs = cs_new(h1c->conn);
	if (!cs)
		goto end;

	h1s = h1s_create(h1c, cs, sess);
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
	struct h1c *h1c = conn->ctx;
	struct h1s *h1s = h1c->h1s;

	if (h1s)
		return h1s->cs;

	return NULL;
}

static void h1_destroy(struct connection *conn)
{
	struct h1c *h1c = conn->ctx;

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
	struct session *sess;
	int has_keepalive;
	int is_not_first;

	cs->ctx = NULL;
	if (!h1s)
		return;

	sess = h1s->sess;
	h1c = h1s->h1c;
	h1s->cs = NULL;

	has_keepalive = h1s->flags & H1S_F_WANT_KAL;
	is_not_first = h1s->flags & H1S_F_NOT_FIRST;
	h1s_destroy(h1s);

	if (conn_is_back(h1c->conn) && has_keepalive &&
	    !(h1c->conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH))) {
		/* Never ever allow to reuse a connection from a non-reuse backend */
		if ((h1c->px->options & PR_O_REUSE_MASK) == PR_O_REUSE_NEVR)
			h1c->conn->flags |= CO_FL_PRIVATE;

		if (!(h1c->conn->owner)) {
			h1c->conn->owner = sess;
			if (!session_add_conn(sess, h1c->conn, h1c->conn->target)) {
				h1c->conn->owner = NULL;
				if (!srv_add_to_idle_list(objt_server(h1c->conn->target), h1c->conn))
					/* The server doesn't want it, let's kill the connection right away */
					h1c->conn->mux->destroy(h1c->conn);
				else
					tasklet_wakeup(h1c->wait_event.task);
				return;

			}
		}
		if (h1c->conn->owner == sess) {
			int ret = session_check_idle_conn(sess, h1c->conn);
			if (ret == -1)
				/* The connection got destroyed, let's leave */
				return;
			else if (ret == 1) {
				/* The connection was added to the server list,
				 * wake the task so we can subscribe to events
				 */
				tasklet_wakeup(h1c->wait_event.task);
				return;
			}
		}
		/* we're in keep-alive with an idle connection, monitor it if not already done */
		if (LIST_ISEMPTY(&h1c->conn->list)) {
			struct server *srv = objt_server(h1c->conn->target);

			if (srv) {
				if (h1c->conn->flags & CO_FL_PRIVATE)
					LIST_ADD(&srv->priv_conns[tid], &h1c->conn->list);
				else if (is_not_first)
					LIST_ADD(&srv->safe_conns[tid], &h1c->conn->list);
				else
					LIST_ADD(&srv->idle_conns[tid], &h1c->conn->list);
			}
		}
	}

	/* We don't want to close right now unless the connection is in error */
	if ((h1c->flags & (H1C_F_CS_ERROR|H1C_F_CS_SHUTDOWN)) ||
	    (h1c->conn->flags & CO_FL_ERROR) || !h1c->conn->owner)
		h1_release(h1c->conn);
	else {
		tasklet_wakeup(h1c->wait_event.task);
		if (h1c->task) {
			h1c->task->expire = TICK_ETERNITY;
			if (b_data(&h1c->obuf)) {
				h1c->task->expire = tick_add(now_ms, ((h1c->flags & (H1C_F_CS_SHUTW_NOW|H1C_F_CS_SHUTDOWN))
								      ? h1c->shut_timeout
								      : h1c->timeout));
				task_queue(h1c->task);
			}
		}
	}
}


static void h1_shutr(struct conn_stream *cs, enum cs_shr_mode mode)
{
	struct h1s *h1s = cs->ctx;

	if (!h1s)
		return;

	if ((h1s->flags & H1S_F_WANT_KAL) &&
	    !(cs->conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH)))
		return;

	/* NOTE: Be sure to handle abort (cf. h2_shutr) */
	if (cs->flags & CS_FL_SHR)
		return;
	if (conn_xprt_ready(cs->conn) && cs->conn->xprt->shutr)
		cs->conn->xprt->shutr(cs->conn, (mode == CS_SHR_DRAIN));
	if ((cs->conn->flags & (CO_FL_SOCK_RD_SH|CO_FL_SOCK_WR_SH)) == (CO_FL_SOCK_RD_SH|CO_FL_SOCK_WR_SH))
		h1s->h1c->flags = (h1s->h1c->flags & ~H1C_F_CS_SHUTW_NOW) | H1C_F_CS_SHUTDOWN;
}

static void h1_shutw(struct conn_stream *cs, enum cs_shw_mode mode)
{
	struct h1s *h1s = cs->ctx;
	struct h1c *h1c;

	if (!h1s)
		return;
	h1c = h1s->h1c;

	if ((h1s->flags & H1S_F_WANT_KAL) &&
	    !(h1c->conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH)) &&

	    h1s->req.state == H1_MSG_DONE && h1s->res.state == H1_MSG_DONE)
		return;

	h1c->flags |= H1C_F_CS_SHUTW_NOW;
	if ((cs->flags & CS_FL_SHW) || b_data(&h1c->obuf))
		return;

	h1_shutw_conn(cs->conn, mode);
}

static void h1_shutw_conn(struct connection *conn, enum cs_shw_mode mode)
{
	struct h1c *h1c = conn->ctx;

	conn_xprt_shutw(conn);
	conn_sock_shutw(conn, (mode == CS_SHW_NORMAL));
	if ((conn->flags & (CO_FL_SOCK_RD_SH|CO_FL_SOCK_WR_SH)) == (CO_FL_SOCK_RD_SH|CO_FL_SOCK_WR_SH))
		h1c->flags = (h1c->flags & ~H1C_F_CS_SHUTW_NOW) | H1C_F_CS_SHUTDOWN;
}

/* Called from the upper layer, to unsubscribe to events */
static int h1_unsubscribe(struct conn_stream *cs, int event_type, void *param)
{
	struct wait_event *sw;
	struct h1s *h1s = cs->ctx;

	if (!h1s)
		return 0;

	if (event_type & SUB_RETRY_RECV) {
		sw = param;
		if (h1s->recv_wait == sw) {
			sw->events &= ~SUB_RETRY_RECV;
			h1s->recv_wait = NULL;
		}
	}
	if (event_type & SUB_RETRY_SEND) {
		sw = param;
		if (h1s->send_wait == sw) {
			sw->events &= ~SUB_RETRY_SEND;
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
		case SUB_RETRY_RECV:
			sw = param;
			if (!(sw->events & SUB_RETRY_RECV)) {
				sw->events |= SUB_RETRY_RECV;
				sw->handle = h1s;
				h1s->recv_wait = sw;
			}
			return 0;
		case SUB_RETRY_SEND:
			sw = param;
			if (!(sw->events & SUB_RETRY_SEND)) {
				sw->events |= SUB_RETRY_SEND;
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
	struct h1c *h1c = h1s->h1c;
	size_t ret = 0;

	if (!(h1c->flags & H1C_F_IN_ALLOC))
		ret = h1_process_input(h1c, buf, flags);

	if (flags & CO_RFL_BUF_FLUSH)
		h1s->flags |= H1S_F_BUF_FLUSH;
	else if (ret > 0 || (h1s->flags & H1S_F_SPLICED_DATA)) {
		h1s->flags &= ~H1S_F_SPLICED_DATA;
		if (!(h1c->wait_event.events & SUB_RETRY_RECV))
			tasklet_wakeup(h1c->wait_event.task);
	}
	return ret;
}


/* Called from the upper layer, to send data */
static size_t h1_snd_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	struct h1s *h1s = cs->ctx;
	struct h1c *h1c;
	size_t total = 0;

	if (!h1s)
		return 0;

	h1c = h1s->h1c;
	if (h1c->flags & H1C_F_CS_WAIT_CONN)
		return 0;

	while (total != count) {
		size_t ret = 0;

		if (!(h1c->flags & (H1C_F_OUT_FULL|H1C_F_OUT_ALLOC)))
			ret = h1_process_output(h1c, buf, count);
		if (!ret)
			break;
		total += ret;
		if (!h1_send(h1c))
			break;
	}

	return total;
}

#if defined(CONFIG_HAP_LINUX_SPLICE)
/* Send and get, using splicing */
static int h1_rcv_pipe(struct conn_stream *cs, struct pipe *pipe, unsigned int count)
{
	struct h1s *h1s = cs->ctx;
	struct h1m *h1m = (!conn_is_back(cs->conn) ? &h1s->req : &h1s->res);
	int ret = 0;

	if (b_data(&h1s->h1c->ibuf)) {
		h1s->flags |= H1S_F_BUF_FLUSH;
		goto end;
	}

	h1s->flags &= ~H1S_F_BUF_FLUSH;
	h1s->flags |= H1S_F_SPLICED_DATA;
	if (h1m->state == H1_MSG_DATA && count > h1m->curr_len)
		count = h1m->curr_len;
	ret = cs->conn->xprt->rcv_pipe(cs->conn, pipe, count);
	if (h1m->state == H1_MSG_DATA && ret > 0)
		h1m->curr_len -= ret;
  end:
	return ret;

}

static int h1_snd_pipe(struct conn_stream *cs, struct pipe *pipe)
{
	struct h1s *h1s = cs->ctx;
	int ret = 0;

	if (b_data(&h1s->h1c->obuf))
		goto end;

	ret = cs->conn->xprt->snd_pipe(cs->conn, pipe);
  end:
	if (pipe->data) {
		if (!(h1s->h1c->wait_event.events & SUB_RETRY_SEND))
			cs->conn->xprt->subscribe(cs->conn, SUB_RETRY_SEND, &h1s->h1c->wait_event);
	}
	return ret;
}
#endif

/* for debugging with CLI's "show fd" command */
static void h1_show_fd(struct buffer *msg, struct connection *conn)
{
	struct h1c *h1c = conn->ctx;
	struct h1s *h1s = h1c->h1s;

	chunk_appendf(msg, " h1c.flg=0x%x .sub=%d .ibuf=%u@%p+%u/%u .obuf=%u@%p+%u/%u",
		      h1c->flags,  h1c->wait_event.events,
		      (unsigned int)b_data(&h1c->ibuf), b_orig(&h1c->ibuf),
		      (unsigned int)b_head_ofs(&h1c->ibuf), (unsigned int)b_size(&h1c->ibuf),
		       (unsigned int)b_data(&h1c->obuf), b_orig(&h1c->obuf),
		      (unsigned int)b_head_ofs(&h1c->obuf), (unsigned int)b_size(&h1c->obuf));

	if (h1s) {
		char *method;

		if (h1s->meth < HTTP_METH_OTHER)
			method = http_known_methods[h1s->meth].ptr;
		else
			method = "UNKNOWN";
		chunk_appendf(msg, " h1s=%p h1s.flg=0x%x .req.state=%s .res.state=%s"
		    " .meth=%s status=%d",
			      h1s, h1s->flags,
			      h1m_state_str(h1s->req.state),
			      h1m_state_str(h1s->res.state), method, h1s->status);
		if (h1s->cs)
			chunk_appendf(msg, " .cs.flg=0x%08x .cs.data=%p",
				      h1s->cs->flags, h1s->cs->data);
	}
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
	.get_cs_info = h1_get_cs_info,
	.detach      = h1_detach,
	.destroy     = h1_destroy,
	.avail_streams = h1_avail_streams,
	.max_streams = h1_max_streams,
	.rcv_buf     = h1_rcv_buf,
	.snd_buf     = h1_snd_buf,
#if defined(CONFIG_HAP_LINUX_SPLICE)
	.rcv_pipe    = h1_rcv_pipe,
	.snd_pipe    = h1_snd_pipe,
#endif
	.subscribe   = h1_subscribe,
	.unsubscribe = h1_unsubscribe,
	.shutr       = h1_shutr,
	.shutw       = h1_shutw,
	.show_fd     = h1_show_fd,
	.reset       = h1_reset,
	.flags       = MX_FL_NONE,
	.name        = "h1",
};


/* this mux registers default HTX proto */
static struct mux_proto_list mux_proto_htx =
{ .token = IST(""), .mode = PROTO_MODE_HTX, .side = PROTO_SIDE_BOTH, .mux = &mux_h1_ops };

INITCALL1(STG_REGISTER, register_mux_proto, &mux_proto_htx);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
