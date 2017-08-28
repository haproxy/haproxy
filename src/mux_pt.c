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

/* The mux operations */
const struct mux_ops mux_pt_ops = {
	.init = mux_pt_init,
	.recv = mux_pt_recv,
	.send = mux_pt_send,
	.wake = mux_pt_wake,
	.name = "PASS",
};
