/*
 * include/proto/stream_interface.h
 * This file contains stream_interface function prototypes
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
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
#include <types/session.h>
#include <types/stream_interface.h>
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
extern struct data_cb si_conn_cb;
extern struct data_cb si_idle_conn_cb;

struct appctx *stream_int_register_handler(struct stream_interface *si, struct si_applet *app);
void stream_int_unregister_handler(struct stream_interface *si);

/* Initializes all required fields for a new appctx. Note that it does the
 * minimum acceptable initialization for an appctx. This means only the
 * 3 integer states st0, st1, st2 are zeroed.
 */
static inline void appctx_init(struct appctx *appctx)
{
	appctx->st0 = appctx->st1 = appctx->st2 = 0;
}

/* sets <appctx>'s applet to point to <applet> */
static inline void appctx_set_applet(struct appctx *appctx, struct si_applet *applet)
{
	appctx->applet = applet;
}

/* Tries to allocate a new appctx and initialize its main fields. The
 * appctx is returned on success, NULL on failure. The appctx must be
 * released using pool_free2(connection) or appctx_free(), since it's
 * allocated from the connection pool.
 */
static inline struct appctx *appctx_new()
{
	struct appctx *appctx;

	appctx = pool_alloc2(pool2_connection);
	if (likely(appctx != NULL)) {
		appctx->obj_type = OBJ_TYPE_APPCTX;
		appctx->applet = NULL;
		appctx_init(appctx);
	}
	return appctx;
}

/* Releases an appctx previously allocated by appctx_new(). Note that
 * we share the connection pool.
 */
static inline void appctx_free(struct appctx *appctx)
{
	pool_free2(pool2_connection, appctx);
}

/* initializes a stream interface in the SI_ST_INI state. It's detached from
 * any endpoint and is only attached to an owner (generally a task).
 */
static inline void si_reset(struct stream_interface *si, void *owner)
{
	si->owner          = owner;
	si->err_type       = SI_ET_NONE;
	si->conn_retries   = 0;  /* used for logging too */
	si->exp            = TICK_ETERNITY;
	si->flags          = SI_FL_NONE;
	si->end            = NULL;
	si->state          = si->prev_state = SI_ST_INI;
}

/* sets the current and previous state of a stream interface to <state>. This
 * is mainly used to create one in the established state on incoming
 * conncetions.
 */
static inline void si_set_state(struct stream_interface *si, int state)
{
	si->state = si->prev_state = state;
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
		conn_force_close(conn);
		conn_free(conn);
	}
	else if ((appctx = objt_appctx(si->end))) {
		if (appctx->applet->release)
			appctx->applet->release(si);
		appctx_free(appctx); /* we share the connection pool */
	}
	si->end = NULL;
}

static inline void si_detach(struct stream_interface *si)
{
	si_release_endpoint(si);
	si->ops = &si_embedded_ops;
}

/* Turn a possibly existing connection endpoint of stream interface <si> to
 * idle mode, which means that the connection will be polled for incoming events
 * and might be killed by the underlying I/O handler.
 */
static inline void si_idle_conn(struct stream_interface *si)
{
	struct connection *conn = objt_conn(si->end);

	if (!conn)
		return;

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
 * is configured to work with an applet context. It is left to the caller to
 * call appctx_set_applet() to assign an applet to this context.
 */
static inline void si_attach_appctx(struct stream_interface *si, struct appctx *appctx)
{
	si->ops = &si_embedded_ops;
	appctx->obj_type = OBJ_TYPE_APPCTX;
	si->end = &appctx->obj_type;
}

/* returns a pointer to the appctx being run in the SI or NULL if none */
static inline struct appctx *si_appctx(struct stream_interface *si)
{
	return objt_appctx(si->end);
}

/* returns a pointer to the applet being run in the SI or NULL if none */
static inline const struct si_applet *si_applet(struct stream_interface *si)
{
	const struct appctx *appctx;

	appctx = si_appctx(si);
	if (appctx)
		return appctx->applet;
	return NULL;
}

/* Call the applet's main function when an appctx is attached to the stream
 * interface. Returns zero if no call was made, or non-zero if a call was made.
 */
static inline int si_applet_call(struct stream_interface *si)
{
	const struct si_applet *applet;

	applet = si_applet(si);
	if (applet) {
		applet->fct(si);
		return 1;
	}
	return 0;
}

/* call the applet's release function if any. Needs to be called upon close() */
static inline void si_applet_release(struct stream_interface *si)
{
	const struct si_applet *applet;

	applet = si_applet(si);
	if (applet && applet->release)
		applet->release(si);
}

/* Try to allocate a new connection and assign it to the interface. If
 * a connection was previously allocated and the <reuse> flag is set,
 * it is returned unmodified. Otherwise it is reset.
 */
/* Returns the stream interface's existing connection if one such already
 * exists, or tries to allocate and initialize a new one which is then
 * assigned to the stream interface.
 */
static inline struct connection *si_alloc_conn(struct stream_interface *si, int reuse)
{
	struct connection *conn;

	/* If we find a connection, we return it, otherwise it's an applet
	 * and we start by releasing it.
	 */
	if (si->end) {
		conn = objt_conn(si->end);
		if (conn) {
			if (!reuse) {
				conn_force_close(conn);
				conn_init(conn);
			}
			return conn;
		}
		/* it was an applet then */
		si_release_endpoint(si);
	}

	conn = conn_new();
	if (conn)
		si_attach_conn(si, conn);

	return conn;
}

/* Release the interface's existing endpoint (connection or appctx) and
 * allocate then initialize a new appctx which is assigned to the interface
 * and returned. NULL may be returned upon memory shortage. It is left to the
 * caller to call appctx_set_applet() to assign an applet to this context.
 */
static inline struct appctx *si_alloc_appctx(struct stream_interface *si)
{
	struct appctx *appctx;

	si_release_endpoint(si);
	appctx = appctx_new();
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

/* Calls the data state update on the stream interfaace */
static inline void si_update(struct stream_interface *si)
{
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
	int ret = SN_ERR_NONE;

	if (unlikely(!conn || !conn->ctrl || !conn->ctrl->connect))
		return SN_ERR_INTERNAL;

	if (!conn_ctrl_ready(conn) || !conn_xprt_ready(conn)) {
		ret = conn->ctrl->connect(conn, !channel_is_empty(si->ob), 0);
		if (ret != SN_ERR_NONE)
			return ret;

		/* we need to be notified about connection establishment */
		conn->flags |= CO_FL_WAKE_DATA;

		/* we're in the process of establishing a connection */
		si->state = SI_ST_CON;
	}
	else if (!channel_is_empty(si->ob)) {
		/* reuse the existing connection, we'll have to send a
		 * request there.
		 */
		conn_data_want_send(conn);

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
