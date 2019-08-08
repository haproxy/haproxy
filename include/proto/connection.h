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
#include <proto/session.h>
#include <proto/task.h>

extern struct pool_head *pool_head_connection;
extern struct pool_head *pool_head_connstream;
extern struct pool_head *pool_head_sockaddr;
extern struct pool_head *pool_head_authority;
extern struct xprt_ops *registered_xprt[XPRT_ENTRIES];
extern struct mux_proto_list mux_proto_list;

/* I/O callback for fd-based connections. It calls the read/write handlers
 * provided by the connection's sock_ops.
 */
void conn_fd_handler(int fd);

/* receive a PROXY protocol header over a connection */
int conn_recv_proxy(struct connection *conn, int flag);
int make_proxy_line(char *buf, int buf_len, struct server *srv, struct connection *remote);
int make_proxy_line_v1(char *buf, int buf_len, struct sockaddr_storage *src, struct sockaddr_storage *dst);
int make_proxy_line_v2(char *buf, int buf_len, struct server *srv, struct connection *remote);

int conn_subscribe(struct connection *conn, void *xprt_ctx, int event_type, void *param);
int conn_unsubscribe(struct connection *conn, void *xprt_ctx, int event_type, void *param);

/* receive a NetScaler Client IP insertion header over a connection */
int conn_recv_netscaler_cip(struct connection *conn, int flag);

/* raw send() directly on the socket */
int conn_sock_send(struct connection *conn, const void *buf, int len, int flags);

/* drains any pending bytes from the socket */
int conn_sock_drain(struct connection *conn);

/* scoks4 proxy handshake */
int conn_send_socks4_proxy_request(struct connection *conn);
int conn_recv_socks4_proxy_response(struct connection *conn);

__decl_hathreads(extern HA_SPINLOCK_T toremove_lock[MAX_THREADS]);

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
		ret = conn->xprt->init(conn, &conn->xprt_ctx);

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
			conn->xprt->close(conn, conn->xprt_ctx);
		conn->xprt_ctx = NULL;
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

		fd_insert(fd, conn, conn_fd_handler, tid_bit);
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

/* Automatically updates polling on connection <c> depending on the XPRT flags.
 * It does nothing if CO_FL_WILL_UPDATE is present, indicating that an upper
 * caller is going to do it again later.
 */
static inline void conn_cond_update_xprt_polling(struct connection *c)
{
	if (!(c->flags & CO_FL_WILL_UPDATE))
		if (conn_xprt_polling_changes(c))
			conn_update_xprt_polling(c);
}

/* Stop all polling on the fd. This might be used when an error is encountered
 * for example. It does not propage the change to the fd layer if
 * CO_FL_WILL_UPDATE is present, indicating that an upper caller is going to do
 * it later.
 */
static inline void conn_stop_polling(struct connection *c)
{
	c->flags &= ~(CO_FL_CURR_RD_ENA | CO_FL_CURR_WR_ENA |
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
		if (conn_xprt_polling_changes(c))
			conn_update_xprt_polling(c);
	}
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

/* read shutdown, called from the rcv_buf/rcv_pipe handlers when
 * detecting an end of connection.
 */
static inline void conn_sock_read0(struct connection *c)
{
	c->flags |= CO_FL_SOCK_RD_SH;
	__conn_xprt_stop_recv(c);
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
	__conn_xprt_stop_send(c);
	conn_cond_update_xprt_polling(c);

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
		c->xprt->shutw(c, c->xprt_ctx, 1);
}

static inline void conn_xprt_shutw_hard(struct connection *c)
{
	__conn_xprt_stop_send(c);

	/* unclean data-layer shutdown */
	if (c->xprt && c->xprt->shutw)
		c->xprt->shutw(c, c->xprt_ctx, 0);
}

/* shut read */
static inline void cs_shutr(struct conn_stream *cs, enum cs_shr_mode mode)
{

	/* clean data-layer shutdown */
	if (cs->conn->mux && cs->conn->mux->shutr)
		cs->conn->mux->shutr(cs, mode);
	cs->flags |= (mode == CS_SHR_DRAIN) ? CS_FL_SHRD : CS_FL_SHRR;
}

/* shut write */
static inline void cs_shutw(struct conn_stream *cs, enum cs_shw_mode mode)
{

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

/* sets CS_FL_ERROR or CS_FL_ERR_PENDING on the cs */
static inline void cs_set_error(struct conn_stream *cs)
{
	if (cs->flags & CS_FL_EOS)
		cs->flags |= CS_FL_ERROR;
	else
		cs->flags |= CS_FL_ERR_PENDING;
}

/* detect sock->data read0 transition */
static inline int conn_xprt_read0_pending(struct connection *c)
{
	return (c->flags & CO_FL_SOCK_RD_SH) != 0;
}

/* prepares a connection to work with protocol <proto> and transport <xprt>.
 * The transport's is initialized as well, and the mux and its context are
 * cleared. The target is not reinitialized and it is recommended that it is
 * set prior to calling this function so that the function may make use of it
 * in the future to refine the mux choice if needed.
 */
static inline void conn_prepare(struct connection *conn, const struct protocol *proto, const struct xprt_ops *xprt)
{
	conn->ctrl = proto;
	conn->xprt = xprt;
	conn->mux  = NULL;
	conn->xprt_ctx = NULL;
	conn->ctx = NULL;
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
	conn->mux = NULL;
	conn->ctx = NULL;
	conn->owner = NULL;
	conn->send_proxy_ofs = 0;
	conn->handle.fd = DEAD_FD_MAGIC;
	conn->err_code = CO_ER_NONE;
	conn->target = NULL;
	conn->xprt_done_cb = NULL;
	conn->destroy_cb = NULL;
	conn->proxy_netns = NULL;
	LIST_INIT(&conn->list);
	LIST_INIT(&conn->session_list);
	conn->send_wait = NULL;
	conn->recv_wait = NULL;
	conn->idle_time = 0;
	conn->src = NULL;
	conn->dst = NULL;
	conn->proxy_authority = NULL;
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

/* Allocates a struct sockaddr from the pool if needed, assigns it to *sap and
 * returns it. If <sap> is NULL, the address is always allocated and returned.
 * if <sap> is non-null, an address will only be allocated if it points to a
 * non-null pointer. In this case the allocated address will be assigned there.
 * In both situations the new pointer is returned.
 */
static inline struct sockaddr_storage *sockaddr_alloc(struct sockaddr_storage **sap)
{
	struct sockaddr_storage *sa;

	if (sap && *sap)
		return *sap;

	sa = pool_alloc(pool_head_sockaddr);
	if (sap)
		*sap = sa;
	return sa;
}

/* Releases the struct sockaddr potentially pointed to by <sap> to the pool. It
 * may be NULL or may point to NULL. If <sap> is not NULL, a NULL is placed
 * there.
 */
static inline void sockaddr_free(struct sockaddr_storage **sap)
{
	if (!sap)
		return;
	pool_free(pool_head_sockaddr, *sap);
	*sap = NULL;
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

/* Releases a conn_stream previously allocated by cs_new(), as well as any
 * buffer it would still hold.
 */
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

/* Retrieves any valid conn_stream from this connection, preferably the first
 * valid one. The purpose is to be able to figure one other end of a private
 * connection for purposes like source binding or proxy protocol header
 * emission. In such cases, any conn_stream is expected to be valid so the
 * mux is encouraged to return the first one it finds. If the connection has
 * no mux or the mux has no get_first_cs() method or the mux has no valid
 * conn_stream, NULL is returned. The output pointer is purposely marked
 * const to discourage the caller from modifying anything there.
 */
static inline const struct conn_stream *cs_get_first(const struct connection *conn)
{
	if (!conn || !conn->mux || !conn->mux->get_first_cs)
		return NULL;
	return conn->mux->get_first_cs(conn);
}

static inline void conn_force_unsubscribe(struct connection *conn)
{
	if (conn->recv_wait) {
		conn->recv_wait->events &= ~SUB_RETRY_RECV;
		conn->recv_wait = NULL;
	}
	if (conn->send_wait) {
		conn->send_wait->events &= ~SUB_RETRY_SEND;
		conn->send_wait = NULL;
	}

}

/* Releases a connection previously allocated by conn_new() */
static inline void conn_free(struct connection *conn)
{
	/* Remove ourself from the session's connections list, if any. */
	if (!LIST_ISEMPTY(&conn->session_list)) {
		struct session *sess = conn->owner;
		if (conn->flags & CO_FL_SESS_IDLE)
			sess->idle_conns--;
		session_unown_conn(sess, conn);
	}

	sockaddr_free(&conn->src);
	sockaddr_free(&conn->dst);

	if (conn->proxy_authority != NULL) {
		pool_free(pool_head_authority, conn->proxy_authority);
		conn->proxy_authority = NULL;
	}

	/* By convention we always place a NULL where the ctx points to if the
	 * mux is null. It may have been used to store the connection as a
	 * stream_interface's end point for example.
	 */
	if (conn->ctx != NULL && conn->mux == NULL)
		*(void **)conn->ctx = NULL;

	/* The connection is currently in the server's idle list, so tell it
	 * there's one less connection available in that list.
	 */
	if (conn->idle_time > 0) {
		struct server *srv = __objt_server(conn->target);
		_HA_ATOMIC_SUB(&srv->curr_idle_conns, 1);
		srv->curr_idle_thr[tid]--;
	}

	conn_force_unsubscribe(conn);
	HA_SPIN_LOCK(OTHER_LOCK, &toremove_lock[tid]);
	MT_LIST_DEL((struct mt_list *)&conn->list);
	HA_SPIN_UNLOCK(OTHER_LOCK, &toremove_lock[tid]);
	pool_free(pool_head_connection, conn);
}

/* Release a conn_stream */
static inline void cs_destroy(struct conn_stream *cs)
{
	if (cs->conn->mux)
		cs->conn->mux->detach(cs);
	else {
		/* It's too early to have a mux, let's just destroy
		 * the connection
		 */
		struct connection *conn = cs->conn;

		conn_stop_tracking(conn);
		conn_full_close(conn);
		if (conn->destroy_cb)
			conn->destroy_cb(conn);
		conn_free(conn);
	}
	cs_free(cs);
}

/* Returns the conn from a cs. If cs is NULL, returns NULL */
static inline struct connection *cs_conn(const struct conn_stream *cs)
{
	return cs ? cs->conn : NULL;
}

/* Retrieves the connection's original source address. Returns non-zero on
 * success or zero on failure. The operation is only performed once and the
 * address is stored in the connection for future use.
 */
static inline int conn_get_src(struct connection *conn)
{
	if (conn->flags & CO_FL_ADDR_FROM_SET)
		return 1;

	if (!conn_ctrl_ready(conn) || !conn->ctrl->get_src)
		return 0;

	if (!sockaddr_alloc(&conn->src))
		return 0;

	if (conn->ctrl->get_src(conn->handle.fd, (struct sockaddr *)conn->src,
	                        sizeof(*conn->src),
	                        obj_type(conn->target) != OBJ_TYPE_LISTENER) == -1)
		return 0;
	conn->flags |= CO_FL_ADDR_FROM_SET;
	return 1;
}

/* Retrieves the connection's original destination address. Returns non-zero on
 * success or zero on failure. The operation is only performed once and the
 * address is stored in the connection for future use.
 */
static inline int conn_get_dst(struct connection *conn)
{
	if (conn->flags & CO_FL_ADDR_TO_SET)
		return 1;

	if (!conn_ctrl_ready(conn) || !conn->ctrl->get_dst)
		return 0;

	if (!sockaddr_alloc(&conn->dst))
		return 0;

	if (conn->ctrl->get_dst(conn->handle.fd, (struct sockaddr *)conn->dst,
	                        sizeof(*conn->dst),
	                        obj_type(conn->target) != OBJ_TYPE_LISTENER) == -1)
		return 0;
	conn->flags |= CO_FL_ADDR_TO_SET;
	return 1;
}

/* Sets the TOS header in IPv4 and the traffic class header in IPv6 packets
 * (as per RFC3260 #4 and BCP37 #4.2 and #5.2). The connection is tested and if
 * it is null, nothing is done.
 */
static inline void conn_set_tos(const struct connection *conn, int tos)
{
	if (!conn || !conn_ctrl_ready(conn))
		return;

#ifdef IP_TOS
	if (conn->src->ss_family == AF_INET)
		setsockopt(conn->handle.fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
#endif
#ifdef IPV6_TCLASS
	if (conn->src->ss_family == AF_INET6) {
		if (IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)conn->src)->sin6_addr))
			/* v4-mapped addresses need IP_TOS */
			setsockopt(conn->handle.fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
		else
			setsockopt(conn->handle.fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos));
	}
#endif
}

/* Sets the netfilter mark on the connection's socket. The connection is tested
 * and if it is null, nothing is done.
 */
static inline void conn_set_mark(const struct connection *conn, int mark)
{
	if (!conn || !conn_ctrl_ready(conn))
		return;

#ifdef SO_MARK
	setsockopt(conn->handle.fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
#endif
}

/* Sets adjust the TCP quick-ack feature on the connection's socket. The
 * connection is tested and if it is null, nothing is done.
 */
static inline void conn_set_quickack(const struct connection *conn, int value)
{
	if (!conn || !conn_ctrl_ready(conn))
		return;

#ifdef TCP_QUICKACK
	setsockopt(conn->handle.fd, IPPROTO_TCP, TCP_QUICKACK, &value, sizeof(value));
#endif
}

/* Attaches a conn_stream to a data layer and sets the relevant callbacks */
static inline void cs_attach(struct conn_stream *cs, void *data, const struct data_cb *data_cb)
{
	cs->data_cb = data_cb;
	cs->data = data;
}

static inline struct wait_event *wl_set_waitcb(struct wait_event *wl, struct task *(*cb)(struct task *, void *, unsigned short), void *ctx)
{
	if (!wl->tasklet->process) {
		wl->tasklet->process = cb;
		wl->tasklet->context = ctx;
	}
	return wl;
}

/* Installs the connection's mux layer for upper context <ctx>.
 * Returns < 0 on error.
 */
static inline int conn_install_mux(struct connection *conn, const struct mux_ops *mux,
                                   void *ctx, struct proxy *prx, struct session *sess)
{
	int ret;

	conn->mux = mux;
	conn->ctx = ctx;
	ret = mux->init ? mux->init(conn, prx, sess, &BUF_NULL) : 0;
	if (ret < 0) {
		conn->mux = NULL;
		conn->ctx = NULL;
	}
	return ret;
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

	case CO_ER_SOCKS4_SEND:    return "SOCKS4 Proxy write error during handshake";
	case CO_ER_SOCKS4_RECV:    return "SOCKS4 Proxy read error during handshake";
	case CO_ER_SOCKS4_DENY:    return "SOCKS4 Proxy deny the request";
	case CO_ER_SOCKS4_ABORT:   return "SOCKS4 Proxy handshake aborted by server";
	}
	return NULL;
}

static inline const char *conn_get_ctrl_name(const struct connection *conn)
{
	if (!conn || !conn_ctrl_ready(conn))
		return "NONE";
	return conn->ctrl->name;
}

static inline const char *conn_get_xprt_name(const struct connection *conn)
{
	if (!conn || !conn_xprt_ready(conn))
		return "NONE";
	return conn->xprt->name;
}

static inline const char *conn_get_mux_name(const struct connection *conn)
{
	if (!conn || !conn->mux)
		return "NONE";
	return conn->mux->name;
}

static inline const char *cs_get_data_name(const struct conn_stream *cs)
{
	if (!cs || !cs->data_cb)
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

/* Try to add a handshake pseudo-XPRT. If the connection's first XPRT is
 * raw_sock, then just use the new XPRT as the connection XPRT, otherwise
 * call the xprt's add_xprt() method.
 * Returns 0 on success, or non-zero on failure.
 */
static inline int xprt_add_hs(struct connection *conn)
{
	void *xprt_ctx = NULL;
	const struct xprt_ops *ops = xprt_get(XPRT_HANDSHAKE);
	void *nextxprt_ctx = NULL;
	const struct xprt_ops *nextxprt_ops = NULL;

	if (conn->flags & CO_FL_ERROR)
		return -1;
	if (ops->init(conn, &xprt_ctx) < 0)
		return -1;
	if (conn->xprt == xprt_get(XPRT_RAW)) {
		nextxprt_ctx = conn->xprt_ctx;
		nextxprt_ops = conn->xprt;
		conn->xprt_ctx = xprt_ctx;
		conn->xprt = ops;
	} else {
		if (conn->xprt->add_xprt(conn, conn->xprt_ctx, xprt_ctx, ops,
		                         &nextxprt_ctx, &nextxprt_ops) != 0) {
			ops->close(conn, xprt_ctx);
			return -1;
		}
	}
	if (ops->add_xprt(conn, xprt_ctx, nextxprt_ctx, nextxprt_ops, NULL, NULL) != 0) {
		ops->close(conn, xprt_ctx);
		return -1;
	}
	return 0;
}

static inline int conn_get_alpn(const struct connection *conn, const char **str, int *len)
{
	if (!conn_xprt_ready(conn) || !conn->xprt->get_alpn)
		return 0;
	return conn->xprt->get_alpn(conn, conn->xprt_ctx, str, len);
}

/* registers proto mux list <list>. Modifies the list element! */
static inline void register_mux_proto(struct mux_proto_list *list)
{
	LIST_ADDQ(&mux_proto_list.list, &list->list);
}

/* unregisters proto mux list <list> */
static inline void unregister_mux_proto(struct mux_proto_list *list)
{
	LIST_DEL(&list->list);
	LIST_INIT(&list->list);
}

static inline struct mux_proto_list *get_mux_proto(const struct ist proto)
{
	struct mux_proto_list *item;

	list_for_each_entry(item, &mux_proto_list.list, list) {
		if (isteq(proto, item->token))
			return item;
	}
	return NULL;
}

/* Lists the known proto mux on <out> */
static inline void list_mux_proto(FILE *out)
{
	struct mux_proto_list *item;
	struct ist proto;
	char *mode, *side;

	fprintf(out, "Available multiplexer protocols :\n"
		"(protocols marked as <default> cannot be specified using 'proto' keyword)\n");
	list_for_each_entry(item, &mux_proto_list.list, list) {
		proto = item->token;

		if (item->mode == PROTO_MODE_ANY)
			mode = "TCP|HTTP";
		else if (item->mode == PROTO_MODE_TCP)
			mode = "TCP";
		else if (item->mode == PROTO_MODE_HTTP)
			mode = "HTTP";
		else
			mode = "NONE";

		if (item->side == PROTO_SIDE_BOTH)
			side = "FE|BE";
		else if (item->side == PROTO_SIDE_FE)
			side = "FE";
		else if (item->side == PROTO_SIDE_BE)
			side = "BE";
		else
			side = "NONE";

		fprintf(out, " %15s : mode=%-10s side=%-8s  mux=%s\n",
			(proto.len ? proto.ptr : "<default>"), mode, side, item->mux->name);
	}
}

/* returns the first mux entry in the list matching the exact same <mux_proto>
 * and compatible with the <proto_side> (FE or BE) and the <proto_mode> (TCP or
 * HTTP). <mux_proto> can be empty. Will fall back to the first compatible mux
 * with exactly the same <proto_mode> or with an empty name. May return
 * null if the code improperly registered the default mux to use as a fallback.
 */
static inline const struct mux_proto_list *conn_get_best_mux_entry(
        const struct ist mux_proto,
        int proto_side, int proto_mode)
{
	struct mux_proto_list *item;
	struct mux_proto_list *fallback = NULL;

	list_for_each_entry(item, &mux_proto_list.list, list) {
		if (!(item->side & proto_side) || !(item->mode & proto_mode))
			continue;
		if (istlen(mux_proto) && isteq(mux_proto, item->token))
			return item;
		else if (!istlen(item->token)) {
			if (!fallback || (item->mode == proto_mode && fallback->mode != proto_mode))
				fallback = item;
		}
	}
	return fallback;

}

/* returns the first mux in the list matching the exact same <mux_proto> and
 * compatible with the <proto_side> (FE or BE) and the <proto_mode> (TCP or
 * HTTP). <mux_proto> can be empty. Will fall back to the first compatible mux
 * with exactly the same <proto_mode> or with an empty name. May return
 * null if the code improperly registered the default mux to use as a fallback.
 */
static inline const struct mux_ops *conn_get_best_mux(struct connection *conn,
						      const struct ist mux_proto,
						      int proto_side, int proto_mode)
{
	const struct mux_proto_list *item;

	item = conn_get_best_mux_entry(mux_proto, proto_side, proto_mode);

	return item ? item->mux : NULL;
}

/* returns 0 if the connection is valid and is a frontend connection, otherwise
 * returns 1 indicating it's a backend connection. And uninitialized connection
 * also returns 1 to better handle the usage in the middle of initialization.
 */
static inline int conn_is_back(const struct connection *conn)
{
	return !objt_listener(conn->target);
}

/* returns a pointer to the proxy associated with this connection. For a front
 * connection it returns a pointer to the frontend ; for a back connection, it
 * returns a pointer to the backend.
 */
static inline struct proxy *conn_get_proxy(const struct connection *conn)
{
	struct listener *l;
	struct server *s;

	/* check if it's a frontend connection */
	l = objt_listener(conn->target);
	if (l)
		return l->bind_conf->frontend;

	/* check if it's a backend connection */
	s = objt_server(conn->target);
	if (s)
		return s->proxy;

	return objt_proxy(conn->target);
}

/* installs the best mux for incoming connection <conn> using the upper context
 * <ctx>. If the mux protocol is forced, we use it to find the best
 * mux. Otherwise we use the ALPN name, if any. Returns < 0 on error.
 */
static inline int conn_install_mux_fe(struct connection *conn, void *ctx)
{
	struct bind_conf     *bind_conf = __objt_listener(conn->target)->bind_conf;
	const struct mux_ops *mux_ops;

	if (bind_conf->mux_proto)
		mux_ops = bind_conf->mux_proto->mux;
	else {
		struct ist mux_proto;
		const char *alpn_str = NULL;
		int alpn_len = 0;
		int mode;

		if (bind_conf->frontend->mode == PR_MODE_HTTP)
			mode = PROTO_MODE_HTTP;
		else
			mode = PROTO_MODE_TCP;

		conn_get_alpn(conn, &alpn_str, &alpn_len);
		mux_proto = ist2(alpn_str, alpn_len);
		mux_ops = conn_get_best_mux(conn, mux_proto, PROTO_SIDE_FE, mode);
		if (!mux_ops)
			return -1;
	}
	return conn_install_mux(conn, mux_ops, ctx, bind_conf->frontend, conn->owner);
}

/* installs the best mux for outgoing connection <conn> using the upper context
 * <ctx>. If the mux protocol is forced, we use it to find the best mux. Returns
 * < 0 on error.
 */
static inline int conn_install_mux_be(struct connection *conn, void *ctx, struct session *sess)
{
	struct server *srv = objt_server(conn->target);
	struct proxy  *prx = objt_proxy(conn->target);
	const struct mux_ops *mux_ops;

	if (srv)
		prx = srv->proxy;

	if (!prx) // target must be either proxy or server
		return -1;

	if (srv && srv->mux_proto)
		mux_ops = srv->mux_proto->mux;
	else {
		struct ist mux_proto;
		const char *alpn_str = NULL;
		int alpn_len = 0;
		int mode;

		if (prx->mode == PR_MODE_HTTP)
			mode = PROTO_MODE_HTTP;
		else
			mode = PROTO_MODE_TCP;

		conn_get_alpn(conn, &alpn_str, &alpn_len);
		mux_proto = ist2(alpn_str, alpn_len);

		mux_ops = conn_get_best_mux(conn, mux_proto, PROTO_SIDE_BE, mode);
		if (!mux_ops)
			return -1;
	}
	return conn_install_mux(conn, mux_ops, ctx, prx, sess);
}

/* Change the mux for the connection.
 * The caller should make sure he's not subscribed to the underlying XPRT.
 */
static inline int conn_upgrade_mux_fe(struct connection *conn, void *ctx, struct buffer *buf,
				      struct ist mux_proto, int mode)
{
	struct bind_conf *bind_conf = __objt_listener(conn->target)->bind_conf;
	const struct mux_ops *old_mux, *new_mux;
	void *old_mux_ctx;
	const char *alpn_str = NULL;
	int alpn_len = 0;

	if (!mux_proto.len) {
		conn_get_alpn(conn, &alpn_str, &alpn_len);
		mux_proto = ist2(alpn_str, alpn_len);
	}
	new_mux = conn_get_best_mux(conn, mux_proto, PROTO_SIDE_FE, mode);
	old_mux = conn->mux;

	/* No mux found */
	if (!new_mux)
		return -1;

	/* Same mux, nothing to do */
	if (old_mux == new_mux)
		return 0;

	old_mux_ctx = conn->ctx;
	conn->mux = new_mux;
	conn->ctx = ctx;
	if (new_mux->init(conn, bind_conf->frontend, conn->owner, buf) == -1) {
		/* The mux upgrade failed, so restore the old mux */
		conn->ctx = old_mux_ctx;
		conn->mux = old_mux;
		return -1;
	}

	/* The mux was upgraded, destroy the old one */
	*buf = BUF_NULL;
	old_mux->destroy(old_mux_ctx);
	return 0;
}

#endif /* _PROTO_CONNECTION_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
