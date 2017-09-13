/*
 * Pass-through mux-demux for connections
 *
 * Copyright 2017 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/config.h>
#include <proto/connection.h>
#include <proto/stream.h>

/* Initialize the mux once it's attached. If conn->mux_ctx is NULL, it is
 * assumed that no data layer has yet been instanciated so the mux is
 * attached to an incoming connection and will instanciate a new stream. If
 * conn->mux_ctx exists, it is assumed that it is an outgoing connection
 * requested for this context. Returns < 0 on error.
 */
static int mux_pt_init(struct connection *conn)
{
	if (!conn->mux_ctx)
		return stream_create_from_conn(conn);
	return 0;
}

/* callback to be used by default for the pass-through mux. It calls the data
 * layer wake() callback if it is set otherwise returns 0.
 */
static int mux_pt_wake(struct connection *conn)
{
	return conn->data->wake ? conn->data->wake(conn) : 0;
}

/* callback used to update the mux's polling flags after changing a cs' status.
 * The caller (cs_mux_update_poll) will take care of propagating any changes to
 * the transport layer.
 */
static void mux_pt_update_poll(struct conn_stream *cs)
{
	struct connection *conn = cs->conn;
	int flags = 0;

	conn_refresh_polling_flags(conn);

	if (cs->flags & CS_FL_DATA_RD_ENA)
		flags |= CO_FL_XPRT_RD_ENA;
	if (cs->flags & CS_FL_DATA_WR_ENA)
		flags |= CO_FL_XPRT_WR_ENA;

	conn->flags = (conn->flags & ~(CO_FL_XPRT_RD_ENA | CO_FL_XPRT_WR_ENA)) | flags;
	conn_cond_update_xprt_polling(conn);
}

/* callback to be used by default for the pass-through mux. It simply calls the
 * data layer recv() callback much must be set.
 */
static void mux_pt_recv(struct connection *conn)
{
	conn->data->recv(conn);
}

/* callback to be used by default for the pass-through mux. It simply calls the
 * data layer send() callback which must be set.
 */
static void mux_pt_send(struct connection *conn)
{
	conn->data->send(conn);
}

/*
 * Attach a new stream to a connection
 * (Used for outgoing connections)
 */
static struct conn_stream *mux_pt_attach(struct connection *conn)
{
	return NULL;
}

/*
 * Detach the stream from the connection
 * (Used for outgoing connections)
 */
static void mux_pt_detach(struct conn_stream *cs)
{
}

static void mux_pt_shutr(struct conn_stream *cs, int clean)
{
	if (conn_xprt_ready(cs->conn) && cs->conn->xprt->shutr)
		cs->conn->xprt->shutr(cs->conn, clean);
}

static void mux_pt_shutw(struct conn_stream *cs, int clean)
{
	if (conn_xprt_ready(cs->conn) && cs->conn->xprt->shutw)
		cs->conn->xprt->shutw(cs->conn, clean);
}

/*
 * Called from the upper layer, to get more data
 */
static int mux_pt_rcv_buf(struct conn_stream *cs, struct buffer *buf, int count)
{
	int ret;

	ret = cs->conn->xprt->rcv_buf(cs->conn, buf, count);
	if (conn_xprt_read0_pending(cs->conn))
		cs->flags |= CS_FL_EOS;
	return (ret);
}

/* Called from the upper layer, to send data */
static int mux_pt_snd_buf(struct conn_stream *cs, struct buffer *buf, int flags)
{
	return (cs->conn->xprt->snd_buf(cs->conn, buf, flags));
}

/* Send and get, using splicing */
static int mux_pt_rcv_pipe(struct conn_stream *cs, struct pipe *pipe, unsigned int count)
{
	int ret;

	ret = cs->conn->xprt->rcv_pipe(cs->conn, pipe, count);
	if (conn_xprt_read0_pending(cs->conn))
		cs->flags |= CS_FL_EOS;
	return (ret);
}

static int mux_pt_snd_pipe(struct conn_stream *cs, struct pipe *pipe)
{
	return (cs->conn->xprt->snd_pipe(cs->conn, pipe));
}

/* The mux operations */
const struct mux_ops mux_pt_ops = {
	.init = mux_pt_init,
	.recv = mux_pt_recv,
	.send = mux_pt_send,
	.wake = mux_pt_wake,
	.update_poll = mux_pt_update_poll,
	.rcv_buf = mux_pt_rcv_buf,
	.snd_buf = mux_pt_snd_buf,
#if defined(CONFIG_HAP_LINUX_SPLICE)
	.rcv_pipe = mux_pt_rcv_pipe,
	.snd_pipe = mux_pt_snd_pipe,
#endif
	.attach = mux_pt_attach,
	.detach = mux_pt_detach,
	.shutr = mux_pt_shutr,
	.shutw = mux_pt_shutw,
	.name = "PASS",
};

/* ALPN selection : default mux has empty name */
static struct alpn_mux_list alpn_mux_pt =
	{ .token = IST(""), .mode = ALPN_MODE_ANY, .mux = &mux_pt_ops };

__attribute__((constructor))
static void __mux_pt_init(void)
{
	alpn_register_mux(&alpn_mux_pt);
}
