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

#include <proto/connection.h>
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

/*
 * H1 Stream flags (32 bits)
 */
// TODO

/* H1 connection descriptor */
//struct h1s;
struct h1c {
	struct connection *conn;
	struct proxy *px;
	uint32_t flags;                  /* Connection flags: H1C_F_* */

	struct buffer ibuf;              /* Input buffer to store data before parsing */
	struct buffer obuf;              /* Output buffer to store data after reformatting */

	struct buffer_wait buf_wait;     /* Wait list for buffer allocation */
	struct wait_event wait_event;    /* To be used if we're waiting for I/Os */

	struct h1s *h1s;                 /* H1 stream descriptor */
	int timeout;                     /* idle timeout */
	struct task *task;               /* timeout management task */
};

/* H1 stream descriptor */
struct h1s {
	struct h1c *h1c;
	struct conn_stream *cs;
	uint32_t flags; /* Connection flags: H1S_F_* */

	struct buffer rxbuf; /*receive buffer, always valid (buf_empty or real buffer) */

	struct wait_event *recv_wait; /* Address of the wait_event the conn_stream associated is waiting on */
	struct wait_event *send_wait; /* Address of the wait_event the conn_stream associated is waiting on */
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
static struct h1s *h1s_create(struct h1c *h1c)
{
	struct h1s *h1s;

	h1s = pool_alloc(pool_head_h1s);
	if (!h1s)
		goto end;

	h1s->h1c = h1c;
	h1c->h1s = h1s;

	h1s->cs    = NULL;
	h1s->rxbuf = BUF_NULL;

	h1s->recv_wait = NULL;
	h1s->send_wait = NULL;
  end:
	return h1s;
}

static void h1s_destroy(struct h1s *h1s)
{
	struct h1c *h1c = h1s->h1c;

	h1c->h1s = NULL;
	h1c->flags &= ~H1C_F_RX_FULL;

	if (h1s->recv_wait != NULL)
		h1s->recv_wait->wait_reason &= ~SUB_CAN_RECV;
	if (h1s->send_wait != NULL)
		h1s->send_wait->wait_reason &= ~SUB_CAN_SEND;

	h1_release_buf(h1c, &h1s->rxbuf);
	pool_free(pool_head_h1s, h1s);
}

/*
 * Initialize the mux once it's attached. It is expected that conn->mux_ctx
 * points to the existing conn_stream (for outgoing connections) or NULL (for
 * incoming ones). Returns < 0 on error.
 */
static int h1_init(struct connection *conn, struct proxy *proxy)
{
	struct conn_stream *cs = conn->mux_ctx;
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
	h1c->timeout = 0;

	t = task_new(tid_bit);
	if (!t)
		goto fail;
	h1c->task  = t;
	t->process = h1_timeout_task;
	t->context = h1c;
	t->expire  = TICK_ETERNITY;

	LIST_INIT(&h1c->buf_wait.list);
	h1c->wait_event.task = tasklet_new();
	if (!h1c->wait_event.task)
		goto fail;
	h1c->wait_event.task->process = h1_io_cb;
	h1c->wait_event.task->context = h1c;
	h1c->wait_event.wait_reason   = 0;

	conn->mux_ctx = h1c;

	if (cs) {
		struct h1s *h1s;

		h1s = h1s_create(h1c);
		if (!h1s)
			goto fail;
		h1s->cs = cs;
		cs->ctx = h1s;
	}

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
static void h1_process_input(struct h1c *h1c)
{
	struct h1s *h1s = h1c->h1s;
	struct conn_stream *cs = NULL;

	if (h1c->flags & H1C_F_CS_ERROR)
		goto end;

	if (!h1s) {
		h1s = h1s_create(h1c);
		if (h1s == NULL)
			goto err;

		cs = cs_new(h1c->conn);
		if (!cs)
			goto err;

		h1s->cs = cs;
		cs->ctx = h1s;
		if (stream_create_from_cs(cs) < 0)
			goto err;
	}

	if (!h1_get_buf(h1c, &h1s->rxbuf)) {
		h1c->flags |= H1C_F_RX_ALLOC;
		goto end;
	}

	b_xfer(&h1s->rxbuf, &h1c->ibuf, b_room(&h1s->rxbuf));

	if (!b_full(&h1c->ibuf)) {
		h1c->flags &= ~H1C_F_IN_FULL;
		if (!b_data(&h1c->ibuf))
			h1_release_buf(h1c, &h1c->ibuf);
	}
	if (b_data(&h1s->rxbuf)) {
		h1s->cs->flags |= CS_FL_RCV_MORE;
		if (b_full(&h1s->rxbuf))
			h1c->flags |= H1C_F_RX_FULL;
	}
  end:
	return;

  err:
	if (cs)
		cs_free(cs);
	if (h1s)
		h1s_destroy(h1s);
	h1c->flags |= H1C_F_CS_ERROR;
	goto end;
}

static size_t h1_process_output(struct h1c *h1c, struct buffer *buf, size_t count)
{
	size_t ret = 0;

	if (!h1_get_buf(h1c, &h1c->obuf)) {
		h1c->flags |= H1C_F_OUT_ALLOC;
		goto end;
	}
	if (count > b_room(&h1c->obuf))
		count = b_room(&h1c->obuf);

	ret = b_xfer(&h1c->obuf, buf, count);

	if (b_full(&h1c->obuf))
		h1c->flags |= H1C_F_OUT_FULL;
  end:
	return ret;
}

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
		h1c->flags &= ~H1C_F_RX_FULL;
		h1_release_buf(h1c, &h1s->rxbuf);
		cs->flags &= ~CS_FL_RCV_MORE;
		if (!b_data(&h1c->ibuf) && cs->flags & CS_FL_REOS)
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

	if (b_data(&h1c->ibuf) && !(h1c->flags & (H1C_F_RX_FULL|H1C_F_RX_ALLOC)))
		h1_process_input(h1c);

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

	if (h1c->task) {
		// TODO: update task's timeout and queue it if necessary
	}
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

	if (!expired && h1c)
		return t;

	task_delete(t);
	task_free(t);

	if (!h1c) {
		/* resources were already deleted */
		return NULL;
	}

	h1c->task = NULL;

	// TODO

	/* either we can release everything now or it will be done later once
	 * the stream closes.
	 */
	if (!h1c->h1s)
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

	h1s = h1s_create(h1c);
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
