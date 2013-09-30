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

struct task *stream_int_register_handler(struct stream_interface *si,
					 struct si_applet *app);
void stream_int_unregister_handler(struct stream_interface *si);

static inline void si_prepare_none(struct stream_interface *si)
{
	si->ops = &si_embedded_ops;
	si->end = NULL;
	si->appctx.applet = NULL;
}

static inline void si_prepare_conn(struct stream_interface *si, const struct protocol *ctrl, const struct xprt_ops *xprt)
{
	si->ops = &si_conn_ops;
	si->end = &si->conn->obj_type;
	conn_prepare(si->conn, &si_conn_cb, ctrl, xprt, si);
}

static inline void si_takeover_conn(struct stream_interface *si, const struct protocol *ctrl, const struct xprt_ops *xprt)
{
	si->ops = &si_conn_ops;
	si->end = &si->conn->obj_type;
	conn_assign(si->conn, &si_conn_cb, ctrl, xprt, si);
}

static inline void si_prepare_applet(struct stream_interface *si, struct si_applet *applet)
{
	si->ops = &si_embedded_ops;
	si->appctx.applet = applet;
	si->appctx.obj_type = OBJ_TYPE_APPCTX;
	si->end = &si->appctx.obj_type;
}

/* returns a pointer to the applet being run in the SI or NULL if none */
static inline const struct si_applet *si_applet(struct stream_interface *si)
{
	if (objt_appctx(si->end))
		return si->appctx.applet;
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
	int ret;

	if (unlikely(!si->conn->ctrl || !si->conn->ctrl->connect))
		return SN_ERR_INTERNAL;

	ret = si->conn->ctrl->connect(si->conn, !channel_is_empty(si->ob), !!si->send_proxy_ofs);
	if (ret != SN_ERR_NONE)
		return ret;

	/* needs src ip/port for logging */
	if (si->flags & SI_FL_SRC_ADDR)
		conn_get_from_addr(si->conn);

	/* Prepare to send a few handshakes related to the on-wire protocol. */
	if (si->send_proxy_ofs)
		si->conn->flags |= CO_FL_SI_SEND_PROXY;

	/* we need to be notified about connection establishment */
	si->conn->flags |= CO_FL_WAKE_DATA;

	/* we're in the process of establishing a connection */
	si->state = SI_ST_CON;

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
