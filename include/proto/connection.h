/*
 * include/proto/connection.h
 * This file contains connection function prototypes
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

#ifndef _PROTO_CONNECTION_H
#define _PROTO_CONNECTION_H

#include <common/config.h>
#include <types/connection.h>
#include <types/listener.h>

/* I/O callback for fd-based connections. It calls the read/write handlers
 * provided by the connection's sock_ops. Returns 0.
 */
int conn_fd_handler(int fd);

/* receive a PROXY protocol header over a connection */
int conn_recv_proxy(struct connection *conn, int flag);

/* calls the init() function of the data layer if any. Returns <0 in case of
 * error.
 */
static inline int conn_data_init(struct connection *conn)
{
	if (conn->data && conn->data->init)
		return conn->data->init(conn);
	return 0;
}

/* Calls the close() function of the data layer if any */
static inline void conn_data_close(struct connection *conn)
{
	if (conn->data && conn->data->close)
		conn->data->close(conn);
}

/* Update polling on connection <c>'s file descriptor depending on its current
 * state as reported in the connection's CO_FL_CURR_* flags, reports of EAGAIN
 * in CO_FL_WAIT_*, and the sock layer expectations indicated by CO_FL_SOCK_*.
 * The connection flags are updated with the new flags at the end of the
 * operation.
 */
void conn_update_sock_polling(struct connection *c);

/* Update polling on connection <c>'s file descriptor depending on its current
 * state as reported in the connection's CO_FL_CURR_* flags, reports of EAGAIN
 * in CO_FL_WAIT_*, and the data layer expectations indicated by CO_FL_DATA_*.
 * The connection flags are updated with the new flags at the end of the
 * operation.
 */
void conn_update_data_polling(struct connection *c);

/* inspects c->flags and returns non-zero if DATA ENA changes from the CURR ENA
 * or if the WAIT flags set new flags that were not in CURR POL.
 */
static inline unsigned int conn_data_polling_changes(const struct connection *c)
{
	return (((c->flags << 6) ^ (c->flags << 2)) |     /* changes in ENA go to bits 30&31 */
		(((c->flags << 8) & ~c->flags))) &        /* new bits in POL go to bits 30&31 */
		0xC0000000;
}

/* inspects c->flags and returns non-zero if SOCK ENA changes from the CURR ENA
 * or if the WAIT flags set new flags that were not in CURR POL.
 */
static inline unsigned int conn_sock_polling_changes(const struct connection *c)
{
	return (((c->flags << 4) ^ (c->flags << 2)) |     /* changes in ENA go to bits 30&31 */
		(((c->flags << 8) & ~c->flags))) &        /* new bits in POL go to bits 30&31 */
		0xC0000000;
}

/* Automatically updates polling on connection <c> depending on the DATA flags
 * if no handshake is in progress.
 */
static inline void conn_cond_update_data_polling(struct connection *c)
{
	if (!(c->flags & CO_FL_POLL_SOCK) && conn_data_polling_changes(c))
		conn_update_data_polling(c);
}

/* Automatically updates polling on connection <c> depending on the SOCK flags
 * if a handshake is in progress.
 */
static inline void conn_cond_update_sock_polling(struct connection *c)
{
	if ((c->flags & CO_FL_POLL_SOCK) && conn_sock_polling_changes(c))
		conn_update_sock_polling(c);
}

/* Automatically update polling on connection <c> depending on the DATA and
 * SOCK flags, and on whether a handshake is in progress or not. This may be
 * called at any moment when there is a doubt about the effectiveness of the
 * polling state, for instance when entering or leaving the handshake state.
 */
static inline void conn_cond_update_polling(struct connection *c)
{
	if (!(c->flags & CO_FL_POLL_SOCK) && conn_data_polling_changes(c))
		conn_update_data_polling(c);
	else if ((c->flags & CO_FL_POLL_SOCK) && conn_sock_polling_changes(c))
		conn_update_sock_polling(c);
}

/***** Event manipulation primitives for use by DATA I/O callbacks *****/
/* The __conn_* versions do not propagate to lower layers and are only meant
 * to be used by handlers called by the connection handler. The other ones
 * may be used anywhere.
 */
static inline void __conn_data_want_recv(struct connection *c)
{
	c->flags |= CO_FL_DATA_RD_ENA;
}

static inline void __conn_data_stop_recv(struct connection *c)
{
	c->flags &= ~CO_FL_DATA_RD_ENA;
}

static inline void __conn_data_poll_recv(struct connection *c)
{
	c->flags |= CO_FL_WAIT_RD | CO_FL_DATA_RD_ENA;
}

static inline void __conn_data_want_send(struct connection *c)
{
	c->flags |= CO_FL_DATA_WR_ENA;
}

static inline void __conn_data_stop_send(struct connection *c)
{
	c->flags &= ~CO_FL_DATA_WR_ENA;
}

static inline void __conn_data_poll_send(struct connection *c)
{
	c->flags |= CO_FL_WAIT_WR | CO_FL_DATA_WR_ENA;
}

static inline void __conn_data_stop_both(struct connection *c)
{
	c->flags &= ~(CO_FL_DATA_WR_ENA | CO_FL_DATA_RD_ENA);
}

static inline void conn_data_want_recv(struct connection *c)
{
	__conn_data_want_recv(c);
	conn_cond_update_data_polling(c);
}

static inline void conn_data_stop_recv(struct connection *c)
{
	__conn_data_stop_recv(c);
	conn_cond_update_data_polling(c);
}

static inline void conn_data_poll_recv(struct connection *c)
{
	__conn_data_poll_recv(c);
	conn_cond_update_data_polling(c);
}

static inline void conn_data_want_send(struct connection *c)
{
	__conn_data_want_send(c);
	conn_cond_update_data_polling(c);
}

static inline void conn_data_stop_send(struct connection *c)
{
	__conn_data_stop_send(c);
	conn_cond_update_data_polling(c);
}

static inline void conn_data_poll_send(struct connection *c)
{
	__conn_data_poll_send(c);
	conn_cond_update_data_polling(c);
}

static inline void conn_data_stop_both(struct connection *c)
{
	__conn_data_stop_both(c);
	conn_cond_update_data_polling(c);
}

/***** Event manipulation primitives for use by handshake I/O callbacks *****/
/* The __conn_* versions do not propagate to lower layers and are only meant
 * to be used by handlers called by the connection handler. The other ones
 * may be used anywhere.
 */
static inline void __conn_sock_want_recv(struct connection *c)
{
	c->flags |= CO_FL_SOCK_RD_ENA;
}

static inline void __conn_sock_stop_recv(struct connection *c)
{
	c->flags &= ~CO_FL_SOCK_RD_ENA;
}

static inline void __conn_sock_poll_recv(struct connection *c)
{
	c->flags |= CO_FL_WAIT_RD | CO_FL_SOCK_RD_ENA;
}

static inline void __conn_sock_want_send(struct connection *c)
{
	c->flags |= CO_FL_SOCK_WR_ENA;
}

static inline void __conn_sock_stop_send(struct connection *c)
{
	c->flags &= ~CO_FL_SOCK_WR_ENA;
}

static inline void __conn_sock_poll_send(struct connection *c)
{
	c->flags |= CO_FL_WAIT_WR | CO_FL_SOCK_WR_ENA;
}

static inline void __conn_sock_stop_both(struct connection *c)
{
	c->flags &= ~(CO_FL_SOCK_WR_ENA | CO_FL_SOCK_RD_ENA);
}

static inline void conn_sock_want_recv(struct connection *c)
{
	__conn_sock_want_recv(c);
	conn_cond_update_sock_polling(c);
}

static inline void conn_sock_stop_recv(struct connection *c)
{
	__conn_sock_stop_recv(c);
	conn_cond_update_sock_polling(c);
}

static inline void conn_sock_poll_recv(struct connection *c)
{
	__conn_sock_poll_recv(c);
	conn_cond_update_sock_polling(c);
}

static inline void conn_sock_want_send(struct connection *c)
{
	__conn_sock_want_send(c);
	conn_cond_update_sock_polling(c);
}

static inline void conn_sock_stop_send(struct connection *c)
{
	__conn_sock_stop_send(c);
	conn_cond_update_sock_polling(c);
}

static inline void conn_sock_poll_send(struct connection *c)
{
	__conn_sock_poll_send(c);
	conn_cond_update_sock_polling(c);
}

static inline void conn_sock_stop_both(struct connection *c)
{
	__conn_sock_stop_both(c);
	conn_cond_update_sock_polling(c);
}

/* shutdown management */
static inline void conn_sock_read0(struct connection *c)
{
	c->flags |= CO_FL_SOCK_RD_SH;
	__conn_sock_stop_recv(c);
}

static inline void conn_data_read0(struct connection *c)
{
	c->flags |= CO_FL_DATA_RD_SH;
	__conn_data_stop_recv(c);
}

static inline void conn_sock_shutw(struct connection *c)
{
	c->flags |= CO_FL_SOCK_WR_SH;
	__conn_sock_stop_send(c);
}

static inline void conn_data_shutw(struct connection *c)
{
	c->flags |= CO_FL_DATA_WR_SH;
	__conn_data_stop_send(c);
}

/* detect sock->data read0 transition */
static inline int conn_data_read0_pending(struct connection *c)
{
	return (c->flags & (CO_FL_DATA_RD_SH | CO_FL_SOCK_RD_SH)) == CO_FL_SOCK_RD_SH;
}

/* detect data->sock shutw transition */
static inline int conn_sock_shutw_pending(struct connection *c)
{
	return (c->flags & (CO_FL_DATA_WR_SH | CO_FL_SOCK_WR_SH)) == CO_FL_DATA_WR_SH;
}

static inline void clear_target(struct target *dest)
{
	dest->type = TARG_TYPE_NONE;
	dest->ptr.v = NULL;
}

static inline void set_target_client(struct target *dest, struct listener *l)
{
	dest->type = TARG_TYPE_CLIENT;
	dest->ptr.l = l;
}

static inline void set_target_server(struct target *dest, struct server *s)
{
	dest->type = TARG_TYPE_SERVER;
	dest->ptr.s = s;
}

static inline void set_target_proxy(struct target *dest, struct proxy *p)
{
	dest->type = TARG_TYPE_PROXY;
	dest->ptr.p = p;
}

static inline void set_target_applet(struct target *dest, struct si_applet *a)
{
	dest->type = TARG_TYPE_APPLET;
	dest->ptr.a = a;
}

static inline void set_target_task(struct target *dest, struct task *t)
{
	dest->type = TARG_TYPE_TASK;
	dest->ptr.t = t;
}

static inline struct target *copy_target(struct target *dest, struct target *src)
{
	*dest = *src;
	return dest;
}

static inline int target_match(struct target *a, struct target *b)
{
	return a->type == b->type && a->ptr.v == b->ptr.v;
}

static inline struct server *target_srv(struct target *t)
{
	if (!t || t->type != TARG_TYPE_SERVER)
		return NULL;
	return t->ptr.s;
}

static inline struct listener *target_client(struct target *t)
{
	if (!t || t->type != TARG_TYPE_CLIENT)
		return NULL;
	return t->ptr.l;
}

/* Retrieves the connection's source address */
static inline void conn_get_from_addr(struct connection *conn)
{
	if (conn->flags & CO_FL_ADDR_FROM_SET)
		return;

	if (!conn->ctrl || !conn->ctrl->get_src)
		return;

	if (conn->ctrl->get_src(conn->t.sock.fd, (struct sockaddr *)&conn->addr.from,
	                         sizeof(conn->addr.from),
	                         conn->target.type != TARG_TYPE_CLIENT) == -1)
		return;
	conn->flags |= CO_FL_ADDR_FROM_SET;
}

/* Retrieves the connection's original destination address */
static inline void conn_get_to_addr(struct connection *conn)
{
	if (conn->flags & CO_FL_ADDR_TO_SET)
		return;

	if (!conn->ctrl || !conn->ctrl->get_dst)
		return;

	if (conn->ctrl->get_dst(conn->t.sock.fd, (struct sockaddr *)&conn->addr.to,
	                         sizeof(conn->addr.to),
	                         conn->target.type != TARG_TYPE_CLIENT) == -1)
		return;
	conn->flags |= CO_FL_ADDR_TO_SET;
}

/* prepares a connection with the appropriate app_cb, ctrl and data layers. The
 * data state and context are set to 0, and the connection's owner is set.
 */
static inline void conn_prepare(struct connection *conn, const struct app_cb *app,
                                const struct protocol *ctrl, const struct data_ops *data,
                                void *owner)
{
	conn->app_cb = app;
	conn->ctrl = ctrl;
	conn->data = data;
	conn->owner = owner;
	conn->data_st = 0;
	conn->data_ctx = NULL;
}

#endif /* _PROTO_CONNECTION_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
