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
void conn_notify_si(struct connection *conn);
int stream_int_shutr(struct stream_interface *si);
int stream_int_shutw(struct stream_interface *si);
void si_conn_recv_cb(struct connection *conn);
void si_conn_send_cb(struct connection *conn);
void stream_sock_read0(struct stream_interface *si);

extern struct si_ops si_embedded_ops;
extern struct si_ops si_task_ops;
extern struct si_ops si_conn_ops;
extern struct app_cb si_conn_cb;

struct task *stream_int_register_handler(struct stream_interface *si,
					 struct si_applet *app);
struct task *stream_int_register_handler_task(struct stream_interface *si,
					      struct task *(*fct)(struct task *));
void stream_int_unregister_handler(struct stream_interface *si);

static inline const struct protocol *si_ctrl(struct stream_interface *si)
{
	return si->conn.ctrl;
}

static inline int si_fd(struct stream_interface *si)
{
	return si->conn.t.sock.fd;
}

static inline void si_prepare_conn(struct stream_interface *si, const struct protocol *ctrl, const struct data_ops *ops)
{
	si->ops = &si_conn_ops;
	conn_prepare(&si->conn, &si_conn_cb, ctrl, ops);
}

static inline void si_prepare_embedded(struct stream_interface *si)
{
	si->ops = &si_embedded_ops;
	conn_prepare(&si->conn, NULL, NULL, NULL);
}

static inline void si_prepare_task(struct stream_interface *si)
{
	si->ops = &si_task_ops;
	conn_prepare(&si->conn, NULL, NULL, NULL);
}

/* Sends a shutr to the connection using the data layer */
static inline void si_shutr(struct stream_interface *si)
{
	if (stream_int_shutr(si))
		conn_data_stop_recv(&si->conn);
}

/* Sends a shutw to the connection using the data layer */
static inline void si_shutw(struct stream_interface *si)
{
	if (stream_int_shutw(si))
		conn_data_stop_send(&si->conn);
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

	if (unlikely(!si_ctrl(si) || !si_ctrl(si)->connect))
		return SN_ERR_INTERNAL;

	ret = si_ctrl(si)->connect(&si->conn, !channel_is_empty(si->ob));
	if (ret != SN_ERR_NONE)
		return ret;

	/* needs src ip/port for logging */
	if (si->flags & SI_FL_SRC_ADDR)
		conn_get_from_addr(&si->conn);

	/* Prepare to send a few handshakes related to the on-wire protocol. */
	if (si->send_proxy_ofs)
		si->conn.flags |= CO_FL_SI_SEND_PROXY;

	/* we need to be notified about connection establishment */
	si->conn.flags |= CO_FL_NOTIFY_SI;

	/* we're in the process of establishing a connection */
	si->state = SI_ST_CON;

	return ret;
}

#endif /* _PROTO_STREAM_INTERFACE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
