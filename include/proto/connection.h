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
#include <common/memory.h>
#include <types/connection.h>
#include <types/listener.h>
#include <proto/fd.h>
#include <proto/obj_type.h>

extern struct pool_head *pool2_connection;

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_connection();

/* I/O callback for fd-based connections. It calls the read/write handlers
 * provided by the connection's sock_ops. Returns 0.
 */
int conn_fd_handler(int fd);

/* receive a PROXY protocol header over a connection */
int conn_recv_proxy(struct connection *conn, int flag);
int make_proxy_line(char *buf, int buf_len, struct server *srv, struct connection *remote);
int make_proxy_line_v1(char *buf, int buf_len, struct sockaddr_storage *src, struct sockaddr_storage *dst);
int make_proxy_line_v2(char *buf, int buf_len, struct server *srv, struct connection *remote);

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
		int fd = conn->t.sock.fd;

		fd_insert(fd);
		/* mark the fd as ready so as not to needlessly poll at the beginning */
		fd_may_recv(fd);
		fd_may_send(fd);
		fdtab[fd].owner = conn;
		fdtab[fd].iocb = conn_fd_handler;
		conn->flags |= CO_FL_CTRL_READY;
	}
}

/* Deletes the FD if the transport layer is already gone. Once done,
 * it then removes the CO_FL_CTRL_READY flag.
 */
static inline void conn_ctrl_close(struct connection *conn)
{
	if ((conn->flags & (CO_FL_XPRT_READY|CO_FL_CTRL_READY)) == CO_FL_CTRL_READY) {
		fd_delete(conn->t.sock.fd);
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

/* Force to close the connection whatever the tracking state. This is mainly
 * used on the error path where the tracking does not make sense, or to kill
 * an idle connection we want to abort immediately.
 */
static inline void conn_force_close(struct connection *conn)
{
	if (conn_xprt_ready(conn) && conn->xprt->close)
		conn->xprt->close(conn);

	if (conn_ctrl_ready(conn))
		fd_delete(conn->t.sock.fd);

	conn->flags &= ~(CO_FL_XPRT_READY|CO_FL_CTRL_READY);
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
 * in CO_FL_WAIT_*, and the data layer expectations indicated by CO_FL_DATA_*.
 * The connection flags are updated with the new flags at the end of the
 * operation. Polling is totally disabled if an error was reported.
 */
void conn_update_data_polling(struct connection *c);

/* Refresh the connection's polling flags from its file descriptor status.
 * This should be called at the beginning of a connection handler.
 */
static inline void conn_refresh_polling_flags(struct connection *conn)
{
	conn->flags &= ~(CO_FL_WAIT_ROOM | CO_FL_WAIT_DATA);

	if (conn_ctrl_ready(conn)) {
		unsigned int flags = conn->flags & ~(CO_FL_CURR_RD_ENA | CO_FL_CURR_WR_ENA);

		if (fd_recv_active(conn->t.sock.fd))
			flags |= CO_FL_CURR_RD_ENA;
		if (fd_send_active(conn->t.sock.fd))
			flags |= CO_FL_CURR_WR_ENA;
		conn->flags = flags;
	}
}

/* inspects c->flags and returns non-zero if DATA ENA changes from the CURR ENA
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
static inline unsigned int conn_data_polling_changes(const struct connection *c)
{
	unsigned int f = c->flags;
	f &= CO_FL_DATA_WR_ENA | CO_FL_DATA_RD_ENA | CO_FL_CURR_WR_ENA |
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

/* Stop all polling on the fd. This might be used when an error is encountered
 * for example.
 */
static inline void conn_stop_polling(struct connection *c)
{
	c->flags &= ~(CO_FL_CURR_RD_ENA | CO_FL_CURR_WR_ENA |
		      CO_FL_SOCK_RD_ENA | CO_FL_SOCK_WR_ENA |
		      CO_FL_DATA_RD_ENA | CO_FL_DATA_WR_ENA);
	fd_stop_both(c->t.sock.fd);
}

/* Automatically update polling on connection <c> depending on the DATA and
 * SOCK flags, and on whether a handshake is in progress or not. This may be
 * called at any moment when there is a doubt about the effectiveness of the
 * polling state, for instance when entering or leaving the handshake state.
 */
static inline void conn_cond_update_polling(struct connection *c)
{
	if (unlikely(c->flags & CO_FL_ERROR))
		conn_stop_polling(c);
	else if (!(c->flags & CO_FL_POLL_SOCK) && conn_data_polling_changes(c))
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

static inline void __conn_data_want_send(struct connection *c)
{
	c->flags |= CO_FL_DATA_WR_ENA;
}

static inline void __conn_data_stop_send(struct connection *c)
{
	c->flags &= ~CO_FL_DATA_WR_ENA;
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

/* shutdown management */
static inline void conn_sock_read0(struct connection *c)
{
	c->flags |= CO_FL_SOCK_RD_SH;
	__conn_sock_stop_recv(c);
	/* we don't risk keeping ports unusable if we found the
	 * zero from the other side.
	 */
	if (conn_ctrl_ready(c))
		fdtab[c->t.sock.fd].linger_risk = 0;
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

/* prepares a connection to work with protocol <proto> and transport <xprt>.
 * The transport's context is initialized as well.
 */
static inline void conn_prepare(struct connection *conn, const struct protocol *proto, const struct xprt_ops *xprt)
{
	conn->ctrl = proto;
	conn->xprt = xprt;
	conn->xprt_st = 0;
	conn->xprt_ctx = NULL;
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
	conn->data = NULL;
	conn->owner = NULL;
	conn->send_proxy_ofs = 0;
	conn->t.sock.fd = -1; /* just to help with debugging */
	conn->err_code = CO_ER_NONE;
	conn->target = NULL;
}

/* Tries to allocate a new connection and initialized its main fields. The
 * connection is returned on success, NULL on failure. The connection must
 * be released using pool_free2() or conn_free().
 */
static inline struct connection *conn_new()
{
	struct connection *conn;

	conn = pool_alloc2(pool2_connection);
	if (likely(conn != NULL))
		conn_init(conn);
	return conn;
}

/* Releases a connection previously allocated by conn_new() */
static inline void conn_free(struct connection *conn)
{
	pool_free2(pool2_connection, conn);
}


/* Retrieves the connection's source address */
static inline void conn_get_from_addr(struct connection *conn)
{
	if (conn->flags & CO_FL_ADDR_FROM_SET)
		return;

	if (!conn_ctrl_ready(conn) || !conn->ctrl->get_src)
		return;

	if (conn->ctrl->get_src(conn->t.sock.fd, (struct sockaddr *)&conn->addr.from,
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

	if (conn->ctrl->get_dst(conn->t.sock.fd, (struct sockaddr *)&conn->addr.to,
	                        sizeof(conn->addr.to),
	                        obj_type(conn->target) != OBJ_TYPE_LISTENER) == -1)
		return;
	conn->flags |= CO_FL_ADDR_TO_SET;
}

/* Attaches a connection to an owner and assigns a data layer */
static inline void conn_attach(struct connection *conn, void *owner, const struct data_cb *data)
{
	conn->data = data;
	conn->owner = owner;
}

/* Drains possibly pending incoming data on the file descriptor attached to the
 * connection and update the connection's flags accordingly. This is used to
 * know whether we need to disable lingering on close. Returns non-zero if it
 * is safe to close without disabling lingering, otherwise zero. The SOCK_RD_SH
 * flag may also be updated if the incoming shutdown was reported by the drain()
 * function.
 */
static inline int conn_drain(struct connection *conn)
{
	if (!conn_ctrl_ready(conn))
		return 1;

	if (conn->flags & CO_FL_SOCK_RD_SH)
		return 1;

	if (!fd_recv_ready(conn->t.sock.fd))
		return 0;

	if (!conn->ctrl->drain)
		return 0;

	if (conn->ctrl->drain(conn->t.sock.fd) <= 0)
		return 0;

	conn->flags |= CO_FL_SOCK_RD_SH;
	return 1;
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
	case CO_ER_SSL_EMPTY:     return "Connection closed during SSL handshake";
	case CO_ER_SSL_ABORT:     return "Connection error during SSL handshake";
	case CO_ER_SSL_TIMEOUT:   return "Timeout during SSL handshake";
	case CO_ER_SSL_TOO_MANY:  return "Too many SSL connections";
	case CO_ER_SSL_NO_MEM:    return "Out of memory when initializing an SSL connection";
	case CO_ER_SSL_RENEG:     return "Rejected a client-initiated SSL renegociation attempt";
	case CO_ER_SSL_CA_FAIL:   return "SSL client CA chain cannot be verified";
	case CO_ER_SSL_CRT_FAIL:  return "SSL client certificate not trusted";
	case CO_ER_SSL_HANDSHAKE: return "SSL handshake failure";
	case CO_ER_SSL_HANDSHAKE_HB: return "SSL handshake failure after heartbeat";
	case CO_ER_SSL_KILLED_HB: return "Stopped a TLSv1 heartbeat attack (CVE-2014-0160)";
	case CO_ER_SSL_NO_TARGET: return "Attempt to use SSL on an unknown target (internal error)";
	}
	return NULL;
}

#endif /* _PROTO_CONNECTION_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
