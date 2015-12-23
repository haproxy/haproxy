/*
 * include/proto/stream_interface.h
 * This file contains stream_interface function prototypes
 *
 * Copyright (C) 2000-2014 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_STREAM_INTERFACE_H
#define _PROTO_STREAM_INTERFACE_H

#include <stdlib.h>

#include <common/config.h>
#include <types/server.h>
#include <types/stream.h>
#include <types/stream_interface.h>
#include <proto/applet.h>
#include <proto/channel.h>
#include <proto/connection.h>


/* main event functions used to move data between sockets and buffers */
int stream_int_check_timeouts(struct stream_interface *si);
void stream_int_report_error(struct stream_interface *si);
void stream_int_retnclose(struct stream_interface *si, const struct chunk *msg);
int conn_si_send_proxy(struct connection *conn, unsigned int flag);
void stream_sock_read0(struct stream_interface *si);

extern struct si_ops si_embedded_ops;
extern struct si_ops si_conn_ops;
extern struct si_ops si_applet_ops;
extern struct data_cb si_conn_cb;
extern struct data_cb si_idle_conn_cb;

struct appctx *stream_int_register_handler(struct stream_interface *si, struct applet *app);
void si_applet_wake_cb(struct stream_interface *si);
void stream_int_update(struct stream_interface *si);
void stream_int_update_conn(struct stream_interface *si);
void stream_int_update_applet(struct stream_interface *si);
void stream_int_notify(struct stream_interface *si);

/* returns the channel which receives data from this stream interface (input channel) */
static inline struct channel *si_ic(struct stream_interface *si)
{
	if (si->flags & SI_FL_ISBACK)
		return &LIST_ELEM(si, struct stream *, si[1])->res;
	else
		return &LIST_ELEM(si, struct stream *, si[0])->req;
}

/* returns the channel which feeds data to this stream interface (output channel) */
static inline struct channel *si_oc(struct stream_interface *si)
{
	if (si->flags & SI_FL_ISBACK)
		return &LIST_ELEM(si, struct stream *, si[1])->req;
	else
		return &LIST_ELEM(si, struct stream *, si[0])->res;
}

/* returns the buffer which receives data from this stream interface (input channel's buffer) */
static inline struct buffer *si_ib(struct stream_interface *si)
{
	return si_ic(si)->buf;
}

/* returns the buffer which feeds data to this stream interface (output channel's buffer) */
static inline struct buffer *si_ob(struct stream_interface *si)
{
	return si_oc(si)->buf;
}

/* returns the stream associated to a stream interface */
static inline struct stream *si_strm(struct stream_interface *si)
{
	if (si->flags & SI_FL_ISBACK)
		return LIST_ELEM(si, struct stream *, si[1]);
	else
		return LIST_ELEM(si, struct stream *, si[0]);
}

/* returns the task associated to this stream interface */
static inline struct task *si_task(struct stream_interface *si)
{
	if (si->flags & SI_FL_ISBACK)
		return LIST_ELEM(si, struct stream *, si[1])->task;
	else
		return LIST_ELEM(si, struct stream *, si[0])->task;
}

/* returns the stream interface on the other side. Used during forwarding. */
static inline struct stream_interface *si_opposite(struct stream_interface *si)
{
	if (si->flags & SI_FL_ISBACK)
		return &LIST_ELEM(si, struct stream *, si[1])->si[0];
	else
		return &LIST_ELEM(si, struct stream *, si[0])->si[1];
}

/* initializes a stream interface in the SI_ST_INI state. It's detached from
 * any endpoint and only keeps its side which is expected to have already been
 * set.
 */
static inline void si_reset(struct stream_interface *si)
{
	si->err_type       = SI_ET_NONE;
	si->conn_retries   = 0;  /* used for logging too */
	si->exp            = TICK_ETERNITY;
	si->flags         &= SI_FL_ISBACK;
	si->end            = NULL;
	si->state          = si->prev_state = SI_ST_INI;
	si->ops            = &si_embedded_ops;
}

/* sets the current and previous state of a stream interface to <state>. This
 * is mainly used to create one in the established state on incoming
 * conncetions.
 */
static inline void si_set_state(struct stream_interface *si, int state)
{
	si->state = si->prev_state = state;
}

/* only detaches the endpoint from the SI, which means that it's set to
 * NULL and that ->ops is mapped to si_embedded_ops. The previous endpoint
 * is returned.
 */
static inline enum obj_type *si_detach_endpoint(struct stream_interface *si)
{
	enum obj_type *prev = si->end;

	si->end = NULL;
	si->ops = &si_embedded_ops;
	return prev;
}

/* Release the endpoint if it's a connection or an applet, then nullify it.
 * Note: released connections are closed then freed.
 */
static inline void si_release_endpoint(struct stream_interface *si)
{
	struct connection *conn;
	struct appctx *appctx;

	if (!si->end)
		return;

	if ((conn = objt_conn(si->end))) {
		LIST_DEL(&conn->list);
		conn_force_close(conn);
		conn_free(conn);
	}
	else if ((appctx = objt_appctx(si->end))) {
		if (appctx->applet->release && si->state < SI_ST_DIS)
			appctx->applet->release(appctx);
		appctx_free(appctx); /* we share the connection pool */
	}
	si_detach_endpoint(si);
}

/* Turn an existing connection endpoint of stream interface <si> to idle mode,
 * which means that the connection will be polled for incoming events and might
 * be killed by the underlying I/O handler. If <pool> is not null, the
 * connection will also be added at the head of this list. This connection
 * remains assigned to the stream interface it is currently attached to.
 */
static inline void si_idle_conn(struct stream_interface *si, struct list *pool)
{
	struct connection *conn = __objt_conn(si->end);

	if (pool)
		LIST_ADD(pool, &conn->list);

	conn_attach(conn, si, &si_idle_conn_cb);
	conn_data_want_recv(conn);
}

/* Attach connection <conn> to the stream interface <si>. The stream interface
 * is configured to work with a connection and the connection it configured
 * with a stream interface data layer.
 */
static inline void si_attach_conn(struct stream_interface *si, struct connection *conn)
{
	si->ops = &si_conn_ops;
	si->end = &conn->obj_type;
	conn_attach(conn, si, &si_conn_cb);
}

/* Returns true if a connection is attached to the stream interface <si> and
 * if this connection is ready.
 */
static inline int si_conn_ready(struct stream_interface *si)
{
	struct connection *conn = objt_conn(si->end);

	return conn && conn_ctrl_ready(conn) && conn_xprt_ready(conn);
}

/* Attach appctx <appctx> to the stream interface <si>. The stream interface
 * is configured to work with an applet context.
 */
static inline void si_attach_appctx(struct stream_interface *si, struct appctx *appctx)
{
	si->ops = &si_applet_ops;
	si->end = &appctx->obj_type;
	appctx->owner = si;
}

/* returns a pointer to the appctx being run in the SI or NULL if none */
static inline struct appctx *si_appctx(struct stream_interface *si)
{
	return objt_appctx(si->end);
}

/* call the applet's release function if any. Needs to be called upon close() */
static inline void si_applet_release(struct stream_interface *si)
{
	struct appctx *appctx;

	appctx = si_appctx(si);
	if (appctx && appctx->applet->release && si->state < SI_ST_DIS)
		appctx->applet->release(appctx);
}

/* let an applet indicate that it wants to put some data into the input buffer */
static inline void si_applet_want_put(struct stream_interface *si)
{
	si->flags |= SI_FL_WANT_PUT;
}

/* let an applet indicate that it wanted to put some data into the input buffer
 * but it couldn't.
 */
static inline void si_applet_cant_put(struct stream_interface *si)
{
	si->flags |= SI_FL_WANT_PUT | SI_FL_WAIT_ROOM;
}

/* let an applet indicate that it doesn't want to put data into the input buffer */
static inline void si_applet_stop_put(struct stream_interface *si)
{
	si->flags &= ~SI_FL_WANT_PUT;
}

/* let an applet indicate that it wants to get some data from the output buffer */
static inline void si_applet_want_get(struct stream_interface *si)
{
	si->flags |= SI_FL_WANT_GET;
}

/* let an applet indicate that it wanted to get some data from the output buffer
 * but it couldn't.
 */
static inline void si_applet_cant_get(struct stream_interface *si)
{
	si->flags |= SI_FL_WANT_GET | SI_FL_WAIT_DATA;
}

/* let an applet indicate that it doesn't want to get data from the input buffer */
static inline void si_applet_stop_get(struct stream_interface *si)
{
	si->flags &= ~SI_FL_WANT_GET;
}

/* Try to allocate a new connection and assign it to the interface. If
 * an endpoint was previously allocated, it is released first. The newly
 * allocated connection is initialized, assigned to the stream interface,
 * and returned.
 */
static inline struct connection *si_alloc_conn(struct stream_interface *si)
{
	struct connection *conn;

	si_release_endpoint(si);

	conn = conn_new();
	if (conn)
		si_attach_conn(si, conn);

	return conn;
}

/* Release the interface's existing endpoint (connection or appctx) and
 * allocate then initialize a new appctx which is assigned to the interface
 * and returned. NULL may be returned upon memory shortage. Applet <applet>
 * is assigned to the appctx, but it may be NULL.
 */
static inline struct appctx *si_alloc_appctx(struct stream_interface *si, struct applet *applet)
{
	struct appctx *appctx;

	si_release_endpoint(si);
	appctx = appctx_new(applet);
	if (appctx)
		si_attach_appctx(si, appctx);

	return appctx;
}

/* Sends a shutr to the connection using the data layer */
static inline void si_shutr(struct stream_interface *si)
{
	si->ops->shutr(si);
}

/* Sends a shutw to the connection using the data layer */
static inline void si_shutw(struct stream_interface *si)
{
	si->ops->shutw(si);
}

/* Updates the stream interface and timers, then updates the data layer below */
static inline void si_update(struct stream_interface *si)
{
	stream_int_update(si);
	if (si->ops->update)
		si->ops->update(si);
}

/* Calls chk_rcv on the connection using the data layer */
static inline void si_chk_rcv(struct stream_interface *si)
{
	si->ops->chk_rcv(si);
}

/* Calls chk_snd on the connection using the data layer */
static inline void si_chk_snd(struct stream_interface *si)
{
	si->ops->chk_snd(si);
}

/* Calls chk_snd on the connection using the ctrl layer */
static inline int si_connect(struct stream_interface *si)
{
	struct connection *conn = objt_conn(si->end);
	int ret = SF_ERR_NONE;

	if (unlikely(!conn || !conn->ctrl || !conn->ctrl->connect))
		return SF_ERR_INTERNAL;

	if (!conn_ctrl_ready(conn) || !conn_xprt_ready(conn)) {
		ret = conn->ctrl->connect(conn, !channel_is_empty(si_oc(si)), 0);
		if (ret != SF_ERR_NONE)
			return ret;

		/* we need to be notified about connection establishment */
		conn->flags |= CO_FL_WAKE_DATA;

		/* we're in the process of establishing a connection */
		si->state = SI_ST_CON;
	}
	else {
		/* reuse the existing connection */
		if (!channel_is_empty(si_oc(si))) {
			/* we'll have to send a request there. */
			conn_data_want_send(conn);
		}

		/* the connection is established */
		si->state = SI_ST_EST;
	}

	/* needs src ip/port for logging */
	if (si->flags & SI_FL_SRC_ADDR)
		conn_get_from_addr(conn);

	return ret;
}

/* for debugging, reports the stream interface state name */
static inline const char *si_state_str(int state)
{
	switch (state) {
	case SI_ST_INI: return "INI";
	case SI_ST_REQ: return "REQ";
	case SI_ST_QUE: return "QUE";
	case SI_ST_TAR: return "TAR";
	case SI_ST_ASS: return "ASS";
	case SI_ST_CON: return "CON";
	case SI_ST_CER: return "CER";
	case SI_ST_EST: return "EST";
	case SI_ST_DIS: return "DIS";
	case SI_ST_CLO: return "CLO";
	default:        return "???";
	}
}

#endif /* _PROTO_STREAM_INTERFACE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
