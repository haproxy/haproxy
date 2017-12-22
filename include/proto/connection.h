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
#include <common/ist.h>
#include <common/memory.h>
#include <types/connection.h>
#include <types/listener.h>
#include <proto/fd.h>
#include <proto/obj_type.h>

extern struct pool_head *pool_head_connection;
extern struct pool_head *pool_head_connstream;
extern struct xprt_ops *registered_xprt[XPRT_ENTRIES];
extern struct alpn_mux_list alpn_mux_list;

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_connection();

/* I/O callback for fd-based connections. It calls the read/write handlers
 * provided by the connection's sock_ops.
 */
void conn_fd_handler(int fd);

/* receive a PROXY protocol header over a connection */
int conn_recv_proxy(struct connection *conn, int flag);
int make_proxy_line(char *buf, int buf_len, struct server *srv, struct connection *remote);
int make_proxy_line_v1(char *buf, int buf_len, struct sockaddr_storage *src, struct sockaddr_storage *dst);
int make_proxy_line_v2(char *buf, int buf_len, struct server *srv, struct connection *remote);

/* receive a NetScaler Client IP insertion header over a connection */
int conn_recv_netscaler_cip(struct connection *conn, int flag);

/* raw send() directly on the socket */
int conn_sock_send(struct connection *conn, const void *buf, int len, int flags);

/* drains any pending bytes from the socket */
int conn_sock_drain(struct connection *conn);

/* returns true is the transport layer is ready */
static inline int conn_xprt_ready(const struct connection *conn)
{
	return (conn->flags & CO_FL_XPRT_READY);
}

/* returns true is the control layer is ready */
static inline int conn_ctrl_ready(const struct connection *conn)
{
	return (conn->flags & CO_FL_CTRL_READY);
}

/* Calls the init() function of the transport layer if any and if not done yet,
 * and sets the CO_FL_XPRT_READY flag to indicate it was properly initialized.
 * Returns <0 in case of error.
 */
static inline int conn_xprt_init(struct connection *conn)
{
	int ret = 0;

	if (!conn_xprt_ready(conn) && conn->xprt && conn->xprt->init)
		ret = conn->xprt->init(conn);

	if (ret >= 0)
		conn->flags |= CO_FL_XPRT_READY;

	return ret;
}

/* Calls the close() function of the transport layer if any and if not done
 * yet, and clears the CO_FL_XPRT_READY flag. However this is not done if the
 * CO_FL_XPRT_TRACKED flag is set, which allows logs to take data from the
 * transport layer very late if needed.
 */
static inline void conn_xprt_close(struct connection *conn)
{
	if ((conn->flags & (CO_FL_XPRT_READY|CO_FL_XPRT_TRACKED)) == CO_FL_XPRT_READY) {
		if (conn->xprt->close)
			conn->xprt->close(conn);
		conn->flags &= ~CO_FL_XPRT_READY;
	}
}

/* Initializes the connection's control layer which essentially consists in
 * registering the file descriptor for polling and setting the CO_FL_CTRL_READY
 * flag. The caller is responsible for ensuring that the control layer is
 * already assigned to the connection prior to the call.
 */
static inline void conn_ctrl_init(struct connection *conn)
{
	if (!conn_ctrl_ready(conn)) {
		int fd = conn->handle.fd;

		fdtab[fd].owner = conn;
		fdtab[fd].iocb = conn_fd_handler;
		fd_insert(fd, tid_bit);
		/* mark the fd as ready so as not to needlessly poll at the beginning */
		fd_may_recv(fd);
		fd_may_send(fd);
		conn->flags |= CO_FL_CTRL_READY;
	}
}

/* Deletes the FD if the transport layer is already gone. Once done,
 * it then removes the CO_FL_CTRL_READY flag.
 */
static inline void conn_ctrl_close(struct connection *conn)
{
	if ((conn->flags & (CO_FL_XPRT_READY|CO_FL_CTRL_READY)) == CO_FL_CTRL_READY) {
		fd_delete(conn->handle.fd);
		conn->handle.fd = DEAD_FD_MAGIC;
		conn->flags &= ~CO_FL_CTRL_READY;
	}
}

/* If the connection still has a transport layer, then call its close() function
 * if any, and delete the file descriptor if a control layer is set. This is
 * used to close everything at once and atomically. However this is not done if
 * the CO_FL_XPRT_TRACKED flag is set, which allows logs to take data from the
 * transport layer very late if needed.
 */
static inline void conn_full_close(struct connection *conn)
{
	conn_xprt_close(conn);
	conn_ctrl_close(conn);
}

/* stop tracking a connection, allowing conn_full_close() to always
 * succeed.
 */
static inline void conn_stop_tracking(struct connection *conn)
{
	conn->flags &= ~CO_FL_XPRT_TRACKED;
}

/* Update polling on connection <c>'s file descriptor depending on its current
 * state as reported in the connection's CO_FL_CURR_* flags, reports of EAGAIN
 * in CO_FL_WAIT_*, and the sock layer expectations indicated by CO_FL_SOCK_*.
 * The connection flags are updated with the new flags at the end of the
 * operation. Polling is totally disabled if an error was reported.
 */
void conn_update_sock_polling(struct connection *c);

/* Update polling on connection <c>'s file descriptor depending on its current
 * state as reported in the connection's CO_FL_CURR_* flags, reports of EAGAIN
 * in CO_FL_WAIT_*, and the upper layer expectations indicated by CO_FL_XPRT_*.
 * The connection flags are updated with the new flags at the end of the
 * operation. Polling is totally disabled if an error was reported.
 */
void conn_update_xprt_polling(struct connection *c);

/* Refresh the connection's polling flags from its file descriptor status.
 * This should be called at the beginning of a connection handler. It does
 * nothing if CO_FL_WILL_UPDATE is present, indicating that an upper caller
 * has already done it.
 */
static inline void conn_refresh_polling_flags(struct connection *conn)
{
	if (conn_ctrl_ready(conn) && !(conn->flags & CO_FL_WILL_UPDATE)) {
		unsigned int flags = conn->flags;

		flags &= ~(CO_FL_CURR_RD_ENA | CO_FL_CURR_WR_ENA | CO_FL_WAIT_ROOM);
		if (fd_recv_active(conn->handle.fd))
			flags |= CO_FL_CURR_RD_ENA;
		if (fd_send_active(conn->handle.fd))
			flags |= CO_FL_CURR_WR_ENA;
		conn->flags = flags;
	}
}

/* inspects c->flags and returns non-zero if XPRT ENA changes from the CURR ENA
 * or if the WAIT flags are set with their respective ENA flags. Additionally,
 * non-zero is also returned if an error was reported on the connection. This
 * function is used quite often and is inlined. In order to proceed optimally
 * with very little code and CPU cycles, the bits are arranged so that a change
 * can be detected by a few left shifts, a xor, and a mask. These operations
 * detect when W&D are both enabled for either direction, when C&D differ for
 * either direction and when Error is set. The trick consists in first keeping
 * only the bits we're interested in, since they don't collide when shifted,
 * and to perform the AND at the end. In practice, the compiler is able to
 * replace the last AND with a TEST in boolean conditions. This results in
 * checks that are done in 4-6 cycles and less than 30 bytes.
 */
static inline unsigned int conn_xprt_polling_changes(const struct connection *c)
{
	unsigned int f = c->flags;
	f &= CO_FL_XPRT_WR_ENA | CO_FL_XPRT_RD_ENA | CO_FL_CURR_WR_ENA |
	     CO_FL_CURR_RD_ENA | CO_FL_ERROR;

	f = (f ^ (f << 1)) & (CO_FL_CURR_WR_ENA|CO_FL_CURR_RD_ENA);    /* test C ^ D */
	return f & (CO_FL_CURR_WR_ENA | CO_FL_CURR_RD_ENA | CO_FL_ERROR);
}

/* inspects c->flags and returns non-zero if SOCK ENA changes from the CURR ENA
 * or if the WAIT flags are set with their respective ENA flags. Additionally,
 * non-zero is also returned if an error was reported on the connection. This
 * function is used quite often and is inlined. In order to proceed optimally
 * with very little code and CPU cycles, the bits are arranged so that a change
 * can be detected by a few left shifts, a xor, and a mask. These operations
 * detect when W&S are both enabled for either direction, when C&S differ for
 * either direction and when Error is set. The trick consists in first keeping
 * only the bits we're interested in, since they don't collide when shifted,
 * and to perform the AND at the end. In practice, the compiler is able to
 * replace the last AND with a TEST in boolean conditions. This results in
 * checks that are done in 4-6 cycles and less than 30 bytes.
 */
static inline unsigned int conn_sock_polling_changes(const struct connection *c)
{
	unsigned int f = c->flags;
	f &= CO_FL_SOCK_WR_ENA | CO_FL_SOCK_RD_ENA | CO_FL_CURR_WR_ENA |
	     CO_FL_CURR_RD_ENA | CO_FL_ERROR;

	f = (f ^ (f << 2)) & (CO_FL_CURR_WR_ENA|CO_FL_CURR_RD_ENA);    /* test C ^ S */
	return f & (CO_FL_CURR_WR_ENA | CO_FL_CURR_RD_ENA | CO_FL_ERROR);
}

/* Automatically updates polling on connection <c> depending on the XPRT flags
 * if no handshake is in progress. It does nothing if CO_FL_WILL_UPDATE is
 * present, indicating that an upper caller is going to do it again later.
 */
static inline void conn_cond_update_xprt_polling(struct connection *c)
{
	if (!(c->flags & CO_FL_WILL_UPDATE))
		if (!(c->flags & CO_FL_POLL_SOCK) && conn_xprt_polling_changes(c))
			conn_update_xprt_polling(c);
}

/* Automatically updates polling on connection <c> depending on the SOCK flags
 * if a handshake is in progress. It does nothing if CO_FL_WILL_UPDATE is
 * present, indicating that an upper caller is going to do it again later.
 */
static inline void conn_cond_update_sock_polling(struct connection *c)
{
	if (!(c->flags & CO_FL_WILL_UPDATE))
		if ((c->flags & CO_FL_POLL_SOCK) && conn_sock_polling_changes(c))
			conn_update_sock_polling(c);
}

/* Stop all polling on the fd. This might be used when an error is encountered
 * for example. It does not propage the change to the fd layer if
 * CO_FL_WILL_UPDATE is present, indicating that an upper caller is going to do
 * it later.
 */
static inline void conn_stop_polling(struct connection *c)
{
	c->flags &= ~(CO_FL_CURR_RD_ENA | CO_FL_CURR_WR_ENA |
		      CO_FL_SOCK_RD_ENA | CO_FL_SOCK_WR_ENA |
		      CO_FL_XPRT_RD_ENA | CO_FL_XPRT_WR_ENA);
	if (!(c->flags & CO_FL_WILL_UPDATE) && conn_ctrl_ready(c))
		fd_stop_both(c->handle.fd);
}

/* Automatically update polling on connection <c> depending on the XPRT and
 * SOCK flags, and on whether a handshake is in progress or not. This may be
 * called at any moment when there is a doubt about the effectiveness of the
 * polling state, for instance when entering or leaving the handshake state.
 * It does nothing if CO_FL_WILL_UPDATE is present, indicating that an upper
 * caller is going to do it again later.
 */
static inline void conn_cond_update_polling(struct connection *c)
{
	if (unlikely(c->flags & CO_FL_ERROR))
		conn_stop_polling(c);
	else if (!(c->flags & CO_FL_WILL_UPDATE)) {
		if (!(c->flags & CO_FL_POLL_SOCK) && conn_xprt_polling_changes(c))
			conn_update_xprt_polling(c);
		else if ((c->flags & CO_FL_POLL_SOCK) && conn_sock_polling_changes(c))
			conn_update_sock_polling(c);
	}
}

/* recompute the mux polling flags after updating the current conn_stream and
 * propagate the result down the transport layer.
 */
static inline void cs_update_mux_polling(struct conn_stream *cs)
{
	struct connection *conn = cs->conn;

	if (conn->mux && conn->mux->update_poll)
		conn->mux->update_poll(cs);
}

/***** Event manipulation primitives for use by DATA I/O callbacks *****/
/* The __conn_* versions do not propagate to lower layers and are only meant
 * to be used by handlers called by the connection handler. The other ones
 * may be used anywhere.
 */
static inline void __conn_xprt_want_recv(struct connection *c)
{
	c->flags |= CO_FL_XPRT_RD_ENA;
}

static inline void __conn_xprt_stop_recv(struct connection *c)
{
	c->flags &= ~CO_FL_XPRT_RD_ENA;
}

static inline void __cs_want_recv(struct conn_stream *cs)
{
	cs->flags |= CS_FL_DATA_RD_ENA;
}

static inline void __cs_stop_recv(struct conn_stream *cs)
{
	cs->flags &= ~CS_FL_DATA_RD_ENA;
}

static inline void cs_want_recv(struct conn_stream *cs)
{
	__cs_want_recv(cs);
	cs_update_mux_polling(cs);
}

static inline void cs_stop_recv(struct conn_stream *cs)
{
	__cs_stop_recv(cs);
	cs_update_mux_polling(cs);
}

/* this one is used only to stop speculative recv(). It doesn't stop it if the
 * fd is already polled in order to avoid expensive polling status changes.
 * Since it might require the upper layer to re-enable reading, we'll return 1
 * if we've really stopped something otherwise zero.
 */
static inline int __conn_xprt_done_recv(struct connection *c)
{
	if (!conn_ctrl_ready(c) || !fd_recv_polled(c->handle.fd)) {
		c->flags &= ~CO_FL_XPRT_RD_ENA;
		return 1;
	}
	return 0;
}

static inline void __conn_xprt_want_send(struct connection *c)
{
	c->flags |= CO_FL_XPRT_WR_ENA;
}

static inline void __conn_xprt_stop_send(struct connection *c)
{
	c->flags &= ~CO_FL_XPRT_WR_ENA;
}

static inline void __conn_xprt_stop_both(struct connection *c)
{
	c->flags &= ~(CO_FL_XPRT_WR_ENA | CO_FL_XPRT_RD_ENA);
}

static inline void __cs_want_send(struct conn_stream *cs)
{
	cs->flags |= CS_FL_DATA_WR_ENA;
}

static inline void __cs_stop_send(struct conn_stream *cs)
{
	cs->flags &= ~CS_FL_DATA_WR_ENA;
}

static inline void cs_stop_send(struct conn_stream *cs)
{
	__cs_stop_send(cs);
	cs_update_mux_polling(cs);
}

static inline void cs_want_send(struct conn_stream *cs)
{
	__cs_want_send(cs);
	cs_update_mux_polling(cs);
}

static inline void __cs_stop_both(struct conn_stream *cs)
{
	cs->flags &= ~(CS_FL_DATA_WR_ENA | CS_FL_DATA_RD_ENA);
}

static inline void cs_stop_both(struct conn_stream *cs)
{
	__cs_stop_both(cs);
	cs_update_mux_polling(cs);
}


static inline void conn_xprt_want_recv(struct connection *c)
{
	__conn_xprt_want_recv(c);
	conn_cond_update_xprt_polling(c);
}

static inline void conn_xprt_stop_recv(struct connection *c)
{
	__conn_xprt_stop_recv(c);
	conn_cond_update_xprt_polling(c);
}

static inline void conn_xprt_want_send(struct connection *c)
{
	__conn_xprt_want_send(c);
	conn_cond_update_xprt_polling(c);
}

static inline void conn_xprt_stop_send(struct connection *c)
{
	__conn_xprt_stop_send(c);
	conn_cond_update_xprt_polling(c);
}

static inline void conn_xprt_stop_both(struct connection *c)
{
	__conn_xprt_stop_both(c);
	conn_cond_update_xprt_polling(c);
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

static inline void __conn_sock_want_send(struct connection *c)
{
	c->flags |= CO_FL_SOCK_WR_ENA;
}

static inline void __conn_sock_stop_send(struct connection *c)
{
	c->flags &= ~CO_FL_SOCK_WR_ENA;
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

static inline void conn_sock_stop_both(struct connection *c)
{
	__conn_sock_stop_both(c);
	conn_cond_update_sock_polling(c);
}

/* read shutdown, called from the rcv_buf/rcv_pipe handlers when
 * detecting an end of connection.
 */
static inline void conn_sock_read0(struct connection *c)
{
	c->flags |= CO_FL_SOCK_RD_SH;
	__conn_sock_stop_recv(c);
	/* we don't risk keeping ports unusable if we found the
	 * zero from the other side.
	 */
	if (conn_ctrl_ready(c))
		fdtab[c->handle.fd].linger_risk = 0;
}

/* write shutdown, indication that the upper layer is not willing to send
 * anything anymore and wants to close after pending data are sent. The
 * <clean> argument will allow not to perform the socket layer shutdown if
 * equal to 0.
 */
static inline void conn_sock_shutw(struct connection *c, int clean)
{
	c->flags |= CO_FL_SOCK_WR_SH;
	conn_refresh_polling_flags(c);
	__conn_sock_stop_send(c);
	conn_cond_update_sock_polling(c);

	/* don't perform a clean shutdown if we're going to reset or
	 * if the shutr was already received.
	 */
	if (conn_ctrl_ready(c) && !(c->flags & CO_FL_SOCK_RD_SH) && clean)
		shutdown(c->handle.fd, SHUT_WR);
}

static inline void conn_xprt_shutw(struct connection *c)
{
	__conn_xprt_stop_send(c);

	/* clean data-layer shutdown */
	if (c->xprt && c->xprt->shutw)
		c->xprt->shutw(c, 1);
}

static inline void conn_xprt_shutw_hard(struct connection *c)
{
	__conn_xprt_stop_send(c);

	/* unclean data-layer shutdown */
	if (c->xprt && c->xprt->shutw)
		c->xprt->shutw(c, 0);
}

/* shut read */
static inline void cs_shutr(struct conn_stream *cs, enum cs_shr_mode mode)
{
	__cs_stop_recv(cs);

	/* clean data-layer shutdown */
	if (cs->conn->mux && cs->conn->mux->shutr)
		cs->conn->mux->shutr(cs, mode);
	cs->flags |= (mode == CS_SHR_DRAIN) ? CS_FL_SHRD : CS_FL_SHRR;
}

/* shut write */
static inline void cs_shutw(struct conn_stream *cs, enum cs_shw_mode mode)
{
	__cs_stop_send(cs);

	/* clean data-layer shutdown */
	if (cs->conn->mux && cs->conn->mux->shutw)
		cs->conn->mux->shutw(cs, mode);
	cs->flags |= (mode == CS_SHW_NORMAL) ? CS_FL_SHWN : CS_FL_SHWS;
}

/* completely close a conn_stream (but do not detach it) */
static inline void cs_close(struct conn_stream *cs)
{
	cs_shutw(cs, CS_SHW_SILENT);
	cs_shutr(cs, CS_SHR_RESET);
	cs->flags = CS_FL_NONE;
}

/* detect sock->data read0 transition */
static inline int conn_xprt_read0_pending(struct connection *c)
{
	return (c->flags & CO_FL_SOCK_RD_SH) != 0;
}

/* prepares a connection to work with protocol <proto> and transport <xprt>.
 * The transport's is initialized as well, and the mux and its context are
 * cleared.
 */
static inline void conn_prepare(struct connection *conn, const struct protocol *proto, const struct xprt_ops *xprt)
{
	conn->ctrl = proto;
	conn->xprt = xprt;
	conn->mux  = NULL;
	conn->xprt_st = 0;
	conn->xprt_ctx = NULL;
	conn->mux_ctx = NULL;
}

/*
 * Initializes all required fields for a new conn_strema.
 */
static inline void cs_init(struct conn_stream *cs, struct connection *conn)
{
	cs->obj_type = OBJ_TYPE_CS;
	cs->flags = CS_FL_NONE;
	cs->conn = conn;
}

/* Initializes all required fields for a new connection. Note that it does the
 * minimum acceptable initialization for a connection that already exists and
 * is about to be reused. It also leaves the addresses untouched, which makes
 * it usable across connection retries to reset a connection to a known state.
 */
static inline void conn_init(struct connection *conn)
{
	conn->obj_type = OBJ_TYPE_CONN;
	conn->flags = CO_FL_NONE;
	conn->tmp_early_data = -1;
	conn->sent_early_data = 0;
	conn->mux = NULL;
	conn->mux_ctx = NULL;
	conn->owner = NULL;
	conn->send_proxy_ofs = 0;
	conn->handle.fd = DEAD_FD_MAGIC;
	conn->err_code = CO_ER_NONE;
	conn->target = NULL;
	conn->xprt_done_cb = NULL;
	conn->destroy_cb = NULL;
	conn->proxy_netns = NULL;
	LIST_INIT(&conn->list);
}

/* sets <owner> as the connection's owner */
static inline void conn_set_owner(struct connection *conn, void *owner, void (*cb)(struct connection *))
{
	conn->owner = owner;
	conn->destroy_cb = cb;
}

/* registers <cb> as a callback to notify for transport's readiness or failure */
static inline void conn_set_xprt_done_cb(struct connection *conn, int (*cb)(struct connection *))
{
	conn->xprt_done_cb = cb;
}

/* unregisters the callback to notify for transport's readiness or failure */
static inline void conn_clear_xprt_done_cb(struct connection *conn)
{
	conn->xprt_done_cb = NULL;
}

/* Tries to allocate a new connection and initialized its main fields. The
 * connection is returned on success, NULL on failure. The connection must
 * be released using pool_free() or conn_free().
 */
static inline struct connection *conn_new()
{
	struct connection *conn;

	conn = pool_alloc(pool_head_connection);
	if (likely(conn != NULL))
		conn_init(conn);
	return conn;
}

/* Releases a conn_stream previously allocated by cs_new() */
static inline void cs_free(struct conn_stream *cs)
{
	pool_free(pool_head_connstream, cs);
}

/* Tries to allocate a new conn_stream and initialize its main fields. If
 * <conn> is NULL, then a new connection is allocated on the fly, initialized,
 * and assigned to cs->conn ; this connection will then have to be released
 * using pool_free() or conn_free(). The conn_stream is initialized and added
 * to the mux's stream list on success, then returned. On failure, nothing is
 * allocated and NULL is returned.
 */
static inline struct conn_stream *cs_new(struct connection *conn)
{
	struct conn_stream *cs;

	cs = pool_alloc(pool_head_connstream);
	if (!likely(cs))
		return NULL;

	if (!conn) {
		conn = conn_new();
		if (!likely(conn)) {
			cs_free(cs);
			return NULL;
		}
		conn_init(conn);
	}

	cs_init(cs, conn);
	return cs;
}

/* Releases a connection previously allocated by conn_new() */
static inline void conn_free(struct connection *conn)
{
	pool_free(pool_head_connection, conn);
}

/* Release a conn_stream, and kill the connection if it was the last one */
static inline void cs_destroy(struct conn_stream *cs)
{
	cs->conn->mux->detach(cs);
	cs_free(cs);
}

/* Returns the conn from a cs. If cs is NULL, returns NULL */
static inline struct connection *cs_conn(const struct conn_stream *cs)
{
	return cs ? cs->conn : NULL;
}

/* Retrieves the connection's source address */
static inline void conn_get_from_addr(struct connection *conn)
{
	if (conn->flags & CO_FL_ADDR_FROM_SET)
		return;

	if (!conn_ctrl_ready(conn) || !conn->ctrl->get_src)
		return;

	if (conn->ctrl->get_src(conn->handle.fd, (struct sockaddr *)&conn->addr.from,
	                        sizeof(conn->addr.from),
	                        obj_type(conn->target) != OBJ_TYPE_LISTENER) == -1)
		return;
	conn->flags |= CO_FL_ADDR_FROM_SET;
}

/* Retrieves the connection's original destination address */
static inline void conn_get_to_addr(struct connection *conn)
{
	if (conn->flags & CO_FL_ADDR_TO_SET)
		return;

	if (!conn_ctrl_ready(conn) || !conn->ctrl->get_dst)
		return;

	if (conn->ctrl->get_dst(conn->handle.fd, (struct sockaddr *)&conn->addr.to,
	                        sizeof(conn->addr.to),
	                        obj_type(conn->target) != OBJ_TYPE_LISTENER) == -1)
		return;
	conn->flags |= CO_FL_ADDR_TO_SET;
}

/* Attaches a conn_stream to a data layer and sets the relevant callbacks */
static inline void cs_attach(struct conn_stream *cs, void *data, const struct data_cb *data_cb)
{
	cs->data_cb = data_cb;
	cs->data = data;
}

/* Installs the connection's mux layer for upper context <ctx>.
 * Returns < 0 on error.
 */
static inline int conn_install_mux(struct connection *conn, const struct mux_ops *mux, void *ctx)
{
	conn->mux = mux;
	conn->mux_ctx = ctx;
	return mux->init ? mux->init(conn) : 0;
}

/* returns a human-readable error code for conn->err_code, or NULL if the code
 * is unknown.
 */
static inline const char *conn_err_code_str(struct connection *c)
{
	switch (c->err_code) {
	case CO_ER_NONE:          return "Success";

	case CO_ER_CONF_FDLIM:    return "Reached configured maxconn value";
	case CO_ER_PROC_FDLIM:    return "Too many sockets on the process";
	case CO_ER_SYS_FDLIM:     return "Too many sockets on the system";
	case CO_ER_SYS_MEMLIM:    return "Out of system buffers";
	case CO_ER_NOPROTO:       return "Protocol or address family not supported";
	case CO_ER_SOCK_ERR:      return "General socket error";
	case CO_ER_PORT_RANGE:    return "Source port range exhausted";
	case CO_ER_CANT_BIND:     return "Can't bind to source address";
	case CO_ER_FREE_PORTS:    return "Out of local source ports on the system";
	case CO_ER_ADDR_INUSE:    return "Local source address already in use";

	case CO_ER_PRX_EMPTY:     return "Connection closed while waiting for PROXY protocol header";
	case CO_ER_PRX_ABORT:     return "Connection error while waiting for PROXY protocol header";
	case CO_ER_PRX_TIMEOUT:   return "Timeout while waiting for PROXY protocol header";
	case CO_ER_PRX_TRUNCATED: return "Truncated PROXY protocol header received";
	case CO_ER_PRX_NOT_HDR:   return "Received something which does not look like a PROXY protocol header";
	case CO_ER_PRX_BAD_HDR:   return "Received an invalid PROXY protocol header";
	case CO_ER_PRX_BAD_PROTO: return "Received an unhandled protocol in the PROXY protocol header";

	case CO_ER_CIP_EMPTY:     return "Connection closed while waiting for NetScaler Client IP header";
	case CO_ER_CIP_ABORT:     return "Connection error while waiting for NetScaler Client IP header";
	case CO_ER_CIP_TRUNCATED: return "Truncated NetScaler Client IP header received";
	case CO_ER_CIP_BAD_MAGIC: return "Received an invalid NetScaler Client IP magic number";
	case CO_ER_CIP_BAD_PROTO: return "Received an unhandled protocol in the NetScaler Client IP header";

	case CO_ER_SSL_EMPTY:     return "Connection closed during SSL handshake";
	case CO_ER_SSL_ABORT:     return "Connection error during SSL handshake";
	case CO_ER_SSL_TIMEOUT:   return "Timeout during SSL handshake";
	case CO_ER_SSL_TOO_MANY:  return "Too many SSL connections";
	case CO_ER_SSL_NO_MEM:    return "Out of memory when initializing an SSL connection";
	case CO_ER_SSL_RENEG:     return "Rejected a client-initiated SSL renegociation attempt";
	case CO_ER_SSL_CA_FAIL:   return "SSL client CA chain cannot be verified";
	case CO_ER_SSL_CRT_FAIL:  return "SSL client certificate not trusted";
	case CO_ER_SSL_MISMATCH:  return "Server presented an SSL certificate different from the configured one";
	case CO_ER_SSL_MISMATCH_SNI: return "Server presented an SSL certificate different from the expected one";
	case CO_ER_SSL_HANDSHAKE: return "SSL handshake failure";
	case CO_ER_SSL_HANDSHAKE_HB: return "SSL handshake failure after heartbeat";
	case CO_ER_SSL_KILLED_HB: return "Stopped a TLSv1 heartbeat attack (CVE-2014-0160)";
	case CO_ER_SSL_NO_TARGET: return "Attempt to use SSL on an unknown target (internal error)";
	}
	return NULL;
}

static inline const char *conn_get_ctrl_name(const struct connection *conn)
{
	if (!conn_ctrl_ready(conn))
		return "NONE";
	return conn->ctrl->name;
}

static inline const char *conn_get_xprt_name(const struct connection *conn)
{
	if (!conn_xprt_ready(conn))
		return "NONE";
	return conn->xprt->name;
}

static inline const char *conn_get_mux_name(const struct connection *conn)
{
	if (!conn->mux)
		return "NONE";
	return conn->mux->name;
}

static inline const char *cs_get_data_name(const struct conn_stream *cs)
{
	if (!cs->data_cb)
		return "NONE";
	return cs->data_cb->name;
}

/* registers pointer to transport layer <id> (XPRT_*) */
static inline void xprt_register(int id, struct xprt_ops *xprt)
{
	if (id >= XPRT_ENTRIES)
		return;
	registered_xprt[id] = xprt;
}

/* returns pointer to transport layer <id> (XPRT_*) or NULL if not registered */
static inline struct xprt_ops *xprt_get(int id)
{
	if (id >= XPRT_ENTRIES)
		return NULL;
	return registered_xprt[id];
}

static inline int conn_get_alpn(const struct connection *conn, const char **str, int *len)
{
	if (!conn_xprt_ready(conn) || !conn->xprt->get_alpn)
		return 0;
	return conn->xprt->get_alpn(conn, str, len);
}

/* registers alpn mux list <list>. Modifies the list element! */
static inline void alpn_register_mux(struct alpn_mux_list *list)
{
	LIST_ADDQ(&alpn_mux_list.list, &list->list);
}

/* unregisters alpn mux list <list> */
static inline void alpn_unregister_mux(struct alpn_mux_list *list)
{
	LIST_DEL(&list->list);
	LIST_INIT(&list->list);
}

/* returns the first mux in the list matching the exact same token and
 * compatible with the proxy's mode (http or tcp). Mode "health" has to be
 * considered as TCP here. Ie passing "px->mode == PR_MODE_HTTP" is fine. Will
 * fall back to the first compatible mux with empty ALPN name. May return null
 * if the code improperly registered the default mux to use as a fallback.
 */
static inline const struct mux_ops *alpn_get_mux(const struct ist token, int http_mode)
{
	struct alpn_mux_list *item;
	const struct mux_ops *fallback = NULL;

	http_mode = 1 << !!http_mode;

	list_for_each_entry(item, &alpn_mux_list.list, list) {
		if (!(item->mode & http_mode))
			continue;
		if (isteq(token, item->token))
			return item->mux;
		if (!istlen(item->token))
			fallback = item->mux;
	}
	return fallback;
}

/* finds the best mux for incoming connection <conn> and mode <http_mode> for
 * the proxy. Null cannot be returned unless there's a serious bug somewhere
 * else (no fallback mux registered).
 */
static inline const struct mux_ops *conn_find_best_mux(struct connection *conn, int http_mode)
{
	const char *alpn_str;
	int alpn_len;

	if (!conn_get_alpn(conn, &alpn_str, &alpn_len))
		alpn_len = 0;

	return alpn_get_mux(ist2(alpn_str, alpn_len), http_mode);
}

/* finds the best mux for incoming connection <conn>, a proxy in and http mode
 * <mode>, and installs it on the connection for upper context <ctx>. Returns
 * < 0 on error.
 */
static inline int conn_install_best_mux(struct connection *conn, int mode, void *ctx)
{
	const struct mux_ops *mux_ops;

	mux_ops = conn_find_best_mux(conn, mode);
	if (!mux_ops)
		return -1;
	return conn_install_mux(conn, mux_ops, ctx);
}

#endif /* _PROTO_CONNECTION_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
