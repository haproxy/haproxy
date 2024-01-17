/*
 * Connection management functions
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>

#include <import/ebmbtree.h>

#include <haproxy/api.h>
#include <haproxy/arg.h>
#include <haproxy/cfgparse.h>
#include <haproxy/connection.h>
#include <haproxy/fd.h>
#include <haproxy/frontend.h>
#include <haproxy/hash.h>
#include <haproxy/list.h>
#include <haproxy/log.h>
#include <haproxy/namespace.h>
#include <haproxy/net_helper.h>
#include <haproxy/proto_rhttp.h>
#include <haproxy/proto_tcp.h>
#include <haproxy/sample.h>
#include <haproxy/sc_strm.h>
#include <haproxy/server.h>
#include <haproxy/session.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/stconn.h>
#include <haproxy/tools.h>
#include <haproxy/xxhash.h>


DECLARE_POOL(pool_head_connection,     "connection",     sizeof(struct connection));
DECLARE_POOL(pool_head_conn_hash_node, "conn_hash_node", sizeof(struct conn_hash_node));
DECLARE_POOL(pool_head_sockaddr,       "sockaddr",       sizeof(struct sockaddr_storage));
DECLARE_POOL(pool_head_pp_tlv_128,     "pp_tlv_128",     sizeof(struct conn_tlv_list) + HA_PP2_TLV_VALUE_128);
DECLARE_POOL(pool_head_pp_tlv_256,     "pp_tlv_256",     sizeof(struct conn_tlv_list) + HA_PP2_TLV_VALUE_256);

struct idle_conns idle_conns[MAX_THREADS] = { };
struct xprt_ops *registered_xprt[XPRT_ENTRIES] = { NULL, };

/* List head of all known muxes for PROTO */
struct mux_proto_list mux_proto_list = {
        .list = LIST_HEAD_INIT(mux_proto_list.list)
};

struct mux_stopping_data mux_stopping_data[MAX_THREADS];

/* disables sending of proxy-protocol-v2's LOCAL command */
static int pp2_never_send_local;

/* find the value of a received TLV for a given type */
struct conn_tlv_list *conn_get_tlv(struct connection *conn, int type)
{
	struct conn_tlv_list *tlv = NULL;

	if (!conn)
		return NULL;

	list_for_each_entry(tlv, &conn->tlv_list, list) {
		if (tlv->type == type)
			return tlv;
	}

	return NULL;
}

/* Remove <conn> idle connection from its attached tree (idle, safe or avail).
 * If also present in the secondary server idle list, conn is removed from it.
 *
 * Must be called with idle_conns_lock held.
 */
void conn_delete_from_tree(struct connection *conn)
{
	LIST_DEL_INIT(&conn->idle_list);
	eb64_delete(&conn->hash_node->node);
}

int conn_create_mux(struct connection *conn)
{
	if (conn_is_back(conn)) {
		struct server *srv;
		struct stconn *sc = conn->ctx;
		struct session *sess = conn->owner;

		if (conn->flags & CO_FL_ERROR)
			goto fail;

		if (sess && obj_type(sess->origin) == OBJ_TYPE_CHECK) {
			if (conn_install_mux_chk(conn, conn->ctx, sess) < 0)
				goto fail;
		}
		else if (conn_install_mux_be(conn, conn->ctx, sess, NULL) < 0)
			goto fail;
		srv = objt_server(conn->target);

		/* If we're doing http-reuse always, and the connection is not
		 * private with available streams (an http2 connection), add it
		 * to the available list, so that others can use it right
		 * away. If the connection is private, add it in the session
		 * server list.
		 */
		if (srv && ((srv->proxy->options & PR_O_REUSE_MASK) == PR_O_REUSE_ALWS) &&
		    !(conn->flags & CO_FL_PRIVATE) && conn->mux->avail_streams(conn) > 0) {
			srv_add_to_avail_list(srv, conn);
		}
		else if (conn->flags & CO_FL_PRIVATE) {
			/* If it fail now, the same will be done in mux->detach() callback */
			session_add_conn(sess, conn, conn->target);
		}
		return 0;
fail:
		/* let the upper layer know the connection failed */
		if (sc) {
			sc->app_ops->wake(sc);
		}
		else if (conn_reverse_in_preconnect(conn)) {
			struct listener *l = conn_active_reverse_listener(conn);

			/* If mux init failed, consider connection on error.
			 * This is necessary to ensure connection is freed by
			 * proto-rhttp receiver task.
			 */
			if (!conn->mux)
				conn->flags |= CO_FL_ERROR;

			/* If connection is interrupted  without CO_FL_ERROR, receiver task won't free it. */
			BUG_ON(!(conn->flags & CO_FL_ERROR));

			task_wakeup(l->rx.rhttp.task, TASK_WOKEN_ANY);
		}
		return -1;
	} else
		return conn_complete_session(conn);

}

/* This is used at the end of the socket IOCB to possibly create the mux if it
 * was not done yet, or wake it up if flags changed compared to old_flags or if
 * need_wake insists on this. It returns <0 if the connection was destroyed and
 * must not be used, >=0 otherwise.
 */
int conn_notify_mux(struct connection *conn, int old_flags, int forced_wake)
{
	int ret = 0;

	/* If we don't yet have a mux, that means we were waiting for
	 * information to create one, typically from the ALPN. If we're
	 * done with the handshake, attempt to create one.
	 */
	if (unlikely(!conn->mux) && !(conn->flags & CO_FL_WAIT_XPRT)) {
		ret = conn_create_mux(conn);
		if (ret < 0)
			goto done;
	}

	/* The wake callback is normally used to notify the data layer about
	 * data layer activity (successful send/recv), connection establishment,
	 * shutdown and fatal errors. We need to consider the following
	 * situations to wake up the data layer :
	 *  - change among the CO_FL_NOTIFY_DONE flags :
	 *      SOCK_{RD,WR}_SH, ERROR,
	 *  - absence of any of {L4,L6}_CONN and CONNECTED, indicating the
	 *    end of handshake and transition to CONNECTED
	 *  - raise of CONNECTED with HANDSHAKE down
	 *  - end of HANDSHAKE with CONNECTED set
	 *  - regular data layer activity
	 *
	 * One tricky case is the wake up on read0 or error on an idle
	 * backend connection, that can happen on a connection that is still
	 * polled while at the same moment another thread is about to perform a
	 * takeover. The solution against this is to remove the connection from
	 * the idle list if it was in it, and possibly reinsert it at the end
	 * if the connection remains valid. The cost is non-null (locked tree
	 * removal) but remains low given that this is extremely rarely called.
	 * In any case it's guaranteed by the FD's thread_mask that we're
	 * called from the same thread the connection is queued in.
	 *
	 * Note that the wake callback is allowed to release the connection and
	 * the fd (and return < 0 in this case).
	 */
	if ((forced_wake ||
	     ((conn->flags ^ old_flags) & CO_FL_NOTIFY_DONE) ||
	     ((old_flags & CO_FL_WAIT_XPRT) && !(conn->flags & CO_FL_WAIT_XPRT))) &&
	    conn->mux && conn->mux->wake) {
		uint conn_in_list = conn->flags & CO_FL_LIST_MASK;
		struct server *srv = objt_server(conn->target);

		if (conn_in_list) {
			HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			conn_delete_from_tree(conn);
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		}

		ret = conn->mux->wake(conn);
		if (ret < 0)
			goto done;

		if (conn_in_list) {
			HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			_srv_add_idle(srv, conn, conn_in_list == CO_FL_SAFE_LIST);
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		}
	}
 done:
	return ret;
}

/* Change the mux for the connection.
 * The caller should make sure he's not subscribed to the underlying XPRT.
 */
int conn_upgrade_mux_fe(struct connection *conn, void *ctx, struct buffer *buf,
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

/* installs the best mux for incoming connection <conn> using the upper context
 * <ctx>. If the mux protocol is forced, we use it to find the best
 * mux. Otherwise we use the ALPN name, if any. Returns < 0 on error.
 */
int conn_install_mux_fe(struct connection *conn, void *ctx)
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

	/* Ensure a valid protocol is selected if connection is targeted by a
	 * tcp-request session attach-srv rule.
	 */
	if (conn->reverse.target && !(mux_ops->flags & MX_FL_REVERSABLE)) {
		conn->err_code = CO_ER_REVERSE;
		return -1;
	}

	return conn_install_mux(conn, mux_ops, ctx, bind_conf->frontend, conn->owner);
}

/* installs the best mux for outgoing connection <conn> using the upper context
 * <ctx>. If the server mux protocol is forced, we use it to find the best mux.
 * It's also possible to specify an alternative mux protocol <force_mux_ops>,
 * in which case it will be used instead of the default server mux protocol.
 *
 * Returns < 0 on error.
 */
int conn_install_mux_be(struct connection *conn, void *ctx, struct session *sess,
                        const struct mux_ops *force_mux_ops)
{
	struct server *srv = objt_server(conn->target);
	struct proxy  *prx = objt_proxy(conn->target);
	const struct mux_ops *mux_ops;

	if (srv)
		prx = srv->proxy;

	if (!prx) // target must be either proxy or server
		return -1;

	if (srv && srv->mux_proto && likely(!force_mux_ops)) {
		mux_ops = srv->mux_proto->mux;
	}
	else if (srv && unlikely(force_mux_ops)) {
		mux_ops = force_mux_ops;
	}
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

/* installs the best mux for outgoing connection <conn> for a check using the
 * upper context <ctx>. If the mux protocol is forced by the check, we use it to
 * find the best mux. Returns < 0 on error.
 */
int conn_install_mux_chk(struct connection *conn, void *ctx, struct session *sess)
{
	struct check *check = objt_check(sess->origin);
	struct server *srv = objt_server(conn->target);
	struct proxy *prx = objt_proxy(conn->target);
	const struct mux_ops *mux_ops;

	if (!check) // Check must be defined
		return -1;

	if (srv)
		prx = srv->proxy;

	if (!prx) // target must be either proxy or server
		return -1;

	if (check->mux_proto)
		mux_ops = check->mux_proto->mux;
	else {
		struct ist mux_proto;
		const char *alpn_str = NULL;
		int alpn_len = 0;
		int mode;

		if ((check->tcpcheck_rules->flags & TCPCHK_RULES_PROTO_CHK) == TCPCHK_RULES_HTTP_CHK)
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

/* Set the ALPN of connection <conn> to <alpn>. If force is false, <alpn> must
 * be a subset or identical to the registered protos for the parent SSL_CTX.
 * In this case <alpn> must be a single protocol value, not a list.
 *
 * Returns 0 if ALPN is updated else -1.
 */
int conn_update_alpn(struct connection *conn, const struct ist alpn, int force)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	size_t alpn_len = istlen(alpn);
	char *ctx_alpn_str = NULL;
	int ctx_alpn_len = 0, found = 0;

	/* if not force, first search if alpn is a subset or identical to the
	 * parent SSL_CTX.
	 */
	if (!force) {
		/* retrieve the SSL_CTX according to the connection side. */
		if (conn_is_back(conn)) {
			if (obj_type(conn->target) == OBJ_TYPE_SERVER) {
				struct server *srv = __objt_server(conn->target);
				ctx_alpn_str = srv->ssl_ctx.alpn_str;
				ctx_alpn_len = srv->ssl_ctx.alpn_len;
			}
		}
		else {
			struct session *sess = conn->owner;
			struct listener *li = sess->listener;

			if (li->bind_conf && li->bind_conf->options & BC_O_USE_SSL) {
				ctx_alpn_str = li->bind_conf->ssl_conf.alpn_str;
				ctx_alpn_len = li->bind_conf->ssl_conf.alpn_len;
			}
		}

		if (ctx_alpn_str) {
			/* search if ALPN is present in SSL_CTX ALPN before
			 * using it.
			 */
			while (ctx_alpn_len) {
				/* skip ALPN whose size is not 8 */
				if (*ctx_alpn_str != alpn_len - 1) {
					ctx_alpn_len -= *ctx_alpn_str + 1;
				}
				else {
					if (isteqi(ist2(ctx_alpn_str, alpn_len), alpn)) {
						found = 1;
						break;
					}
				}
				ctx_alpn_str += *ctx_alpn_str + 1;

				/* This indicates an invalid ALPN formatted
				 * string and should never happen. */
				BUG_ON(ctx_alpn_len < 0);
			}
		}
	}

	if (found || force) {
		ssl_sock_set_alpn(conn, (const uchar *)istptr(alpn), istlen(alpn));
		return 0;
	}

#endif
	return -1;
}

/* Initializes all required fields for a new connection. Note that it does the
 * minimum acceptable initialization for a connection that already exists and
 * is about to be reused. It also leaves the addresses untouched, which makes
 * it usable across connection retries to reset a connection to a known state.
 */
void conn_init(struct connection *conn, void *target)
{
	conn->obj_type = OBJ_TYPE_CONN;
	conn->flags = CO_FL_NONE;
	conn->mux = NULL;
	conn->ctx = NULL;
	conn->owner = NULL;
	conn->send_proxy_ofs = 0;
	conn->handle.fd = DEAD_FD_MAGIC;
	conn->err_code = CO_ER_NONE;
	conn->target = target;
	conn->destroy_cb = NULL;
	conn->proxy_netns = NULL;
	MT_LIST_INIT(&conn->toremove_list);
	if (conn_is_back(conn))
		LIST_INIT(&conn->session_list);
	else
		LIST_INIT(&conn->stopping_list);
	LIST_INIT(&conn->tlv_list);
	conn->subs = NULL;
	conn->src = NULL;
	conn->dst = NULL;
	conn->hash_node = NULL;
	conn->xprt = NULL;
	conn->reverse.target = NULL;
	conn->reverse.name = BUF_NULL;
}

/* Initialize members used for backend connections.
 *
 * Returns 0 on success else non-zero.
 */
static int conn_backend_init(struct connection *conn)
{
	if (!sockaddr_alloc(&conn->dst, 0, 0))
		return 1;

	conn->hash_node = conn_alloc_hash_node(conn);
	if (unlikely(!conn->hash_node))
		return 1;

	return 0;
}

/* Release connection elements reserved for backend side usage. It also takes
 * care to detach it if linked to a session or a server instance.
 *
 * This function is useful when freeing a connection or reversing it to the
 * frontend side.
 */
static void conn_backend_deinit(struct connection *conn)
{
	/* If the connection is owned by the session, remove it from its list
	 */
	if (conn_is_back(conn) && LIST_INLIST(&conn->session_list)) {
		session_unown_conn(conn->owner, conn);
	}
	else if (!(conn->flags & CO_FL_PRIVATE)) {
		if (obj_type(conn->target) == OBJ_TYPE_SERVER)
			srv_release_conn(__objt_server(conn->target), conn);
	}

	/* Make sure the connection is not left in the idle connection tree */
	if (conn->hash_node != NULL)
		BUG_ON(conn->hash_node->node.node.leaf_p != NULL);

	pool_free(pool_head_conn_hash_node, conn->hash_node);
	conn->hash_node = NULL;

}

/* Tries to allocate a new connection and initialized its main fields. The
 * connection is returned on success, NULL on failure. The connection must
 * be released using pool_free() or conn_free().
 */
struct connection *conn_new(void *target)
{
	struct connection *conn;

	conn = pool_alloc(pool_head_connection);
	if (unlikely(!conn))
		return NULL;

	conn_init(conn, target);

	if (conn_is_back(conn)) {
		if (obj_type(target) == OBJ_TYPE_SERVER)
			srv_use_conn(__objt_server(target), conn);

		if (conn_backend_init(conn)) {
			conn_free(conn);
			return NULL;
		}
	}

	return conn;
}

/* Releases a connection previously allocated by conn_new() */
void conn_free(struct connection *conn)
{
	struct conn_tlv_list *tlv, *tlv_back = NULL;

	if (conn_is_back(conn))
		conn_backend_deinit(conn);

	/* Remove the conn from toremove_list.
	 *
	 * This is needed to prevent a double-free in case the connection was
	 * already scheduled from cleaning but is freed before via another
	 * call.
	 */
	MT_LIST_DELETE(&conn->toremove_list);

	sockaddr_free(&conn->src);
	sockaddr_free(&conn->dst);

	/* Free all previously allocated TLVs */
	list_for_each_entry_safe(tlv, tlv_back, &conn->tlv_list, list) {
		LIST_DELETE(&tlv->list);
		if (tlv->len > HA_PP2_TLV_VALUE_256)
			free(tlv);
		else if (tlv->len <= HA_PP2_TLV_VALUE_128)
			pool_free(pool_head_pp_tlv_128, tlv);
		else
			pool_free(pool_head_pp_tlv_256, tlv);
	}

	ha_free(&conn->reverse.name.area);

	if (conn_reverse_in_preconnect(conn)) {
		struct listener *l = conn_active_reverse_listener(conn);
		rhttp_notify_preconn_err(l);
		HA_ATOMIC_DEC(&th_ctx->nb_rhttp_conns);
	}
	else if (conn->flags & CO_FL_REVERSED) {
		HA_ATOMIC_DEC(&th_ctx->nb_rhttp_conns);
	}


	conn_force_unsubscribe(conn);
	pool_free(pool_head_connection, conn);
}

struct conn_hash_node *conn_alloc_hash_node(struct connection *conn)
{
	struct conn_hash_node *hash_node = NULL;

	hash_node = pool_zalloc(pool_head_conn_hash_node);
	if (unlikely(!hash_node))
		return NULL;

	hash_node->conn = conn;

	return hash_node;
}

/* Allocates a struct sockaddr from the pool if needed, assigns it to *sap and
 * returns it. If <sap> is NULL, the address is always allocated and returned.
 * if <sap> is non-null, an address will only be allocated if it points to a
 * non-null pointer. In this case the allocated address will be assigned there.
 * If <orig> is non-null and <len> positive, the address in <sa> will be copied
 * into the allocated address. In both situations the new pointer is returned.
 */
struct sockaddr_storage *sockaddr_alloc(struct sockaddr_storage **sap, const struct sockaddr_storage *orig, socklen_t len)
{
	struct sockaddr_storage *sa;

	if (sap && *sap)
		return *sap;

	sa = pool_alloc(pool_head_sockaddr);
	if (sa && orig && len > 0)
		memcpy(sa, orig, len);
	if (sap)
		*sap = sa;
	return sa;
}

/* Releases the struct sockaddr potentially pointed to by <sap> to the pool. It
 * may be NULL or may point to NULL. If <sap> is not NULL, a NULL is placed
 * there.
 */
void sockaddr_free(struct sockaddr_storage **sap)
{
	if (!sap)
		return;
	pool_free(pool_head_sockaddr, *sap);
	*sap = NULL;
}

/* Try to add a handshake pseudo-XPRT. If the connection's first XPRT is
 * raw_sock, then just use the new XPRT as the connection XPRT, otherwise
 * call the xprt's add_xprt() method.
 * Returns 0 on success, or non-zero on failure.
 */
int xprt_add_hs(struct connection *conn)
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

/* returns a human-readable error code for conn->err_code, or NULL if the code
 * is unknown.
 */
const char *conn_err_code_str(struct connection *c)
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
	case CO_ER_CIP_TIMEOUT:   return "Timeout while waiting for a NetScaler Client IP header";
	case CO_ER_CIP_TRUNCATED: return "Truncated NetScaler Client IP header received";
	case CO_ER_CIP_BAD_MAGIC: return "Received an invalid NetScaler Client IP magic number";
	case CO_ER_CIP_BAD_PROTO: return "Received an unhandled protocol in the NetScaler Client IP header";

	case CO_ER_SSL_EMPTY:     return "Connection closed during SSL handshake";
	case CO_ER_SSL_ABORT:     return "Connection error during SSL handshake";
	case CO_ER_SSL_TIMEOUT:   return "Timeout during SSL handshake";
	case CO_ER_SSL_TOO_MANY:  return "Too many SSL connections";
	case CO_ER_SSL_NO_MEM:    return "Out of memory when initializing an SSL connection";
	case CO_ER_SSL_RENEG:     return "Rejected a client-initiated SSL renegotiation attempt";
	case CO_ER_SSL_CA_FAIL:   return "SSL client CA chain cannot be verified";
	case CO_ER_SSL_CRT_FAIL:  return "SSL client certificate not trusted";
	case CO_ER_SSL_MISMATCH:  return "Server presented an SSL certificate different from the configured one";
	case CO_ER_SSL_MISMATCH_SNI: return "Server presented an SSL certificate different from the expected one";
	case CO_ER_SSL_HANDSHAKE: return "SSL handshake failure";
	case CO_ER_SSL_HANDSHAKE_HB: return "SSL handshake failure after heartbeat";
	case CO_ER_SSL_KILLED_HB: return "Stopped a TLSv1 heartbeat attack (CVE-2014-0160)";
	case CO_ER_SSL_NO_TARGET: return "Attempt to use SSL on an unknown target (internal error)";
	case CO_ER_SSL_EARLY_FAILED: return "Server refused early data";

	case CO_ER_SOCKS4_SEND:    return "SOCKS4 Proxy write error during handshake";
	case CO_ER_SOCKS4_RECV:    return "SOCKS4 Proxy read error during handshake";
	case CO_ER_SOCKS4_DENY:    return "SOCKS4 Proxy deny the request";
	case CO_ER_SOCKS4_ABORT:   return "SOCKS4 Proxy handshake aborted by server";

	case CO_ERR_SSL_FATAL:     return "SSL fatal error";

	case CO_ER_REVERSE:        return "Reverse connect failure";
	}
	return NULL;
}

/* Send a message over an established connection. It makes use of send() and
 * returns the same return code and errno. If the socket layer is not ready yet
 * then -1 is returned and ENOTSOCK is set into errno. If the fd is not marked
 * as ready, or if EAGAIN or ENOTCONN is returned, then we return 0. It returns
 * EMSGSIZE if called with a zero length message. The purpose is to simplify
 * some rare attempts to directly write on the socket from above the connection
 * (typically send_proxy). In case of EAGAIN, the fd is marked as "cant_send".
 * It automatically retries on EINTR. Other errors cause the connection to be
 * marked as in error state. It takes similar arguments as send() except the
 * first one which is the connection instead of the file descriptor. <flags>
 * only support CO_SFL_MSG_MORE.
 */
int conn_ctrl_send(struct connection *conn, const void *buf, int len, int flags)
{
	const struct buffer buffer = b_make((char*)buf, len, 0, len);
	const struct xprt_ops *xprt = xprt_get(XPRT_RAW);
	int ret;

	ret = -1;
	errno = ENOTSOCK;

	if (conn->flags & CO_FL_SOCK_WR_SH)
		goto fail;

	if (!conn_ctrl_ready(conn))
		goto fail;

	errno = EMSGSIZE;
	if (!len)
		goto fail;

	/* snd_buf() already takes care of updating conn->flags and handling
	 * the FD polling status.
	 */
	ret = xprt->snd_buf(conn, NULL, &buffer, buffer.data, flags);
	if (conn->flags & CO_FL_ERROR)
		ret = -1;
	return ret;
 fail:
	conn->flags |= CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH | CO_FL_ERROR;
	return ret;
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The event subscriber <es> is not allowed to change from a previous call as
 * long as at least one event is still subscribed. The <event_type> must only
 * be a combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0.
 */
int conn_unsubscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(conn->subs && conn->subs != es);

	es->events &= ~event_type;
	if (!es->events)
		conn->subs = NULL;

	if (conn_ctrl_ready(conn) && conn->ctrl->ignore_events)
		conn->ctrl->ignore_events(conn, event_type);

	return 0;
}

/* Called from the upper layer, to subscribe <es> to events <event_type>.
 * The <es> struct is not allowed to differ from the one passed during a
 * previous call to subscribe(). If the connection's ctrl layer is ready,
 * the wait_event is immediately woken up and the subscription is cancelled.
 * It always returns zero.
 */
int conn_subscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	int ret = 0;

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(conn->subs && conn->subs != es);

	if (conn->subs && (conn->subs->events & event_type) == event_type)
		return 0;

	if (conn_ctrl_ready(conn) && conn->ctrl->check_events) {
		ret = conn->ctrl->check_events(conn, event_type);
		if (ret)
			tasklet_wakeup(es->tasklet);
	}

	es->events = (es->events | event_type) & ~ret;
	conn->subs = es->events ? es : NULL;
	return 0;
}

/* Drains possibly pending incoming data on the connection and update the flags
 * accordingly. This is used to know whether we need to disable lingering on
 * close. Returns non-zero if it is safe to close without disabling lingering,
 * otherwise zero. The CO_FL_SOCK_RD_SH flag may also be updated if the incoming
 * shutdown was reported by the ->drain() function.
 */
int conn_ctrl_drain(struct connection *conn)
{
	int ret = 0;

	if (!conn_ctrl_ready(conn) || conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH))
		ret = 1;
	else if (conn->ctrl->drain) {
		ret = conn->ctrl->drain(conn);
		if (ret)
			conn->flags |= CO_FL_SOCK_RD_SH;
	}
	return ret;
}

/*
 * Get data length from tlv
 */
static inline size_t get_tlv_length(const struct tlv *src)
{
	return (src->length_hi << 8) | src->length_lo;
}

/* This handshake handler waits a PROXY protocol header at the beginning of the
 * raw data stream. The header looks like this :
 *
 *   "PROXY" <SP> PROTO <SP> SRC3 <SP> DST3 <SP> SRC4 <SP> <DST4> "\r\n"
 *
 * There must be exactly one space between each field. Fields are :
 *  - PROTO : layer 4 protocol, which must be "TCP4" or "TCP6".
 *  - SRC3  : layer 3 (eg: IP) source address in standard text form
 *  - DST3  : layer 3 (eg: IP) destination address in standard text form
 *  - SRC4  : layer 4 (eg: TCP port) source address in standard text form
 *  - DST4  : layer 4 (eg: TCP port) destination address in standard text form
 *
 * This line MUST be at the beginning of the buffer and MUST NOT wrap.
 *
 * The header line is small and in all cases smaller than the smallest normal
 * TCP MSS. So it MUST always be delivered as one segment, which ensures we
 * can safely use MSG_PEEK and avoid buffering.
 *
 * Once the data is fetched, the values are set in the connection's address
 * fields, and data are removed from the socket's buffer. The function returns
 * zero if it needs to wait for more data or if it fails, or 1 if it completed
 * and removed itself.
 */
int conn_recv_proxy(struct connection *conn, int flag)
{
	struct session *sess = conn->owner;
	char *line, *end;
	struct proxy_hdr_v2 *hdr_v2;
	const char v2sig[] = PP2_SIGNATURE;
	size_t total_v2_len;
	size_t tlv_offset = 0;
	int ret;

	if (!conn_ctrl_ready(conn))
		goto fail;

	BUG_ON(conn->flags & CO_FL_FDLESS);

	if (!fd_recv_ready(conn->handle.fd))
		goto not_ready;

	while (1) {
		ret = recv(conn->handle.fd, trash.area, trash.size, MSG_PEEK);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				fd_cant_recv(conn->handle.fd);
				goto not_ready;
			}
			goto recv_abort;
		}
		trash.data = ret;
		break;
	}

	if (!trash.data) {
		/* client shutdown */
		conn->err_code = CO_ER_PRX_EMPTY;
		goto fail;
	}

	conn->flags &= ~CO_FL_WAIT_L4_CONN;

	if (trash.data < 6)
		goto missing;

	line = trash.area;
	end = trash.area + trash.data;

	/* Decode a possible proxy request, fail early if it does not match */
	if (strncmp(line, "PROXY ", 6) != 0)
		goto not_v1;

	line += 6;
	if (trash.data < 9) /* shortest possible line */
		goto missing;

	if (memcmp(line, "TCP4 ", 5) == 0) {
		u32 src3, dst3, sport, dport;

		line += 5;

		src3 = inetaddr_host_lim_ret(line, end, &line);
		if (line == end)
			goto missing;
		if (*line++ != ' ')
			goto bad_header;

		dst3 = inetaddr_host_lim_ret(line, end, &line);
		if (line == end)
			goto missing;
		if (*line++ != ' ')
			goto bad_header;

		sport = read_uint((const char **)&line, end);
		if (line == end)
			goto missing;
		if (*line++ != ' ')
			goto bad_header;

		dport = read_uint((const char **)&line, end);
		if (line > end - 2)
			goto missing;
		if (*line++ != '\r')
			goto bad_header;
		if (*line++ != '\n')
			goto bad_header;

		if (!sess || !sockaddr_alloc(&sess->src, NULL, 0) || !sockaddr_alloc(&sess->dst, NULL, 0))
			goto fail;

		/* update the session's addresses and mark them set */
		((struct sockaddr_in *)sess->src)->sin_family      = AF_INET;
		((struct sockaddr_in *)sess->src)->sin_addr.s_addr = htonl(src3);
		((struct sockaddr_in *)sess->src)->sin_port        = htons(sport);

		((struct sockaddr_in *)sess->dst)->sin_family        = AF_INET;
		((struct sockaddr_in *)sess->dst)->sin_addr.s_addr   = htonl(dst3);
		((struct sockaddr_in *)sess->dst)->sin_port          = htons(dport);
	}
	else if (memcmp(line, "TCP6 ", 5) == 0) {
		u32 sport, dport;
		char *src_s;
		char *dst_s, *sport_s, *dport_s;
		struct in6_addr src3, dst3;

		line += 5;

		src_s = line;
		dst_s = sport_s = dport_s = NULL;
		while (1) {
			if (line > end - 2) {
				goto missing;
			}
			else if (*line == '\r') {
				*line = 0;
				line++;
				if (*line++ != '\n')
					goto bad_header;
				break;
			}

			if (*line == ' ') {
				*line = 0;
				if (!dst_s)
					dst_s = line + 1;
				else if (!sport_s)
					sport_s = line + 1;
				else if (!dport_s)
					dport_s = line + 1;
			}
			line++;
		}

		if (!dst_s || !sport_s || !dport_s)
			goto bad_header;

		sport = read_uint((const char **)&sport_s,dport_s - 1);
		if (*sport_s != 0)
			goto bad_header;

		dport = read_uint((const char **)&dport_s,line - 2);
		if (*dport_s != 0)
			goto bad_header;

		if (inet_pton(AF_INET6, src_s, (void *)&src3) != 1)
			goto bad_header;

		if (inet_pton(AF_INET6, dst_s, (void *)&dst3) != 1)
			goto bad_header;

		if (!sess || !sockaddr_alloc(&sess->src, NULL, 0) || !sockaddr_alloc(&sess->dst, NULL, 0))
			goto fail;

		/* update the session's addresses and mark them set */
		((struct sockaddr_in6 *)sess->src)->sin6_family      = AF_INET6;
		memcpy(&((struct sockaddr_in6 *)sess->src)->sin6_addr, &src3, sizeof(struct in6_addr));
		((struct sockaddr_in6 *)sess->src)->sin6_port        = htons(sport);

		((struct sockaddr_in6 *)sess->dst)->sin6_family        = AF_INET6;
		memcpy(&((struct sockaddr_in6 *)sess->dst)->sin6_addr, &dst3, sizeof(struct in6_addr));
		((struct sockaddr_in6 *)sess->dst)->sin6_port          = htons(dport);
	}
	else if (memcmp(line, "UNKNOWN\r\n", 9) == 0) {
		/* This can be a UNIX socket forwarded by an haproxy upstream */
		line += 9;
	}
	else {
		/* The protocol does not match something known (TCP4/TCP6/UNKNOWN) */
		conn->err_code = CO_ER_PRX_BAD_PROTO;
		goto fail;
	}

	trash.data = line - trash.area;
	goto eat_header;

 not_v1:
	/* try PPv2 */
	if (trash.data < PP2_HEADER_LEN)
		goto missing;

	hdr_v2 = (struct proxy_hdr_v2 *) trash.area;

	if (memcmp(hdr_v2->sig, v2sig, PP2_SIGNATURE_LEN) != 0 ||
	    (hdr_v2->ver_cmd & PP2_VERSION_MASK) != PP2_VERSION) {
		conn->err_code = CO_ER_PRX_NOT_HDR;
		goto fail;
	}

	total_v2_len = PP2_HEADER_LEN + ntohs(hdr_v2->len);
	if (trash.data < total_v2_len)
		goto missing;

	switch (hdr_v2->ver_cmd & PP2_CMD_MASK) {
	case 0x01: /* PROXY command */
		switch (hdr_v2->fam) {
		case 0x11:  /* TCPv4 */
			if (ntohs(hdr_v2->len) < PP2_ADDR_LEN_INET)
				goto bad_header;

			if (!sess || !sockaddr_alloc(&sess->src, NULL, 0) || !sockaddr_alloc(&sess->dst, NULL, 0))
				goto fail;

			((struct sockaddr_in *)sess->src)->sin_family = AF_INET;
			((struct sockaddr_in *)sess->src)->sin_addr.s_addr = hdr_v2->addr.ip4.src_addr;
			((struct sockaddr_in *)sess->src)->sin_port = hdr_v2->addr.ip4.src_port;
			((struct sockaddr_in *)sess->dst)->sin_family = AF_INET;
			((struct sockaddr_in *)sess->dst)->sin_addr.s_addr = hdr_v2->addr.ip4.dst_addr;
			((struct sockaddr_in *)sess->dst)->sin_port = hdr_v2->addr.ip4.dst_port;
			tlv_offset = PP2_HEADER_LEN + PP2_ADDR_LEN_INET;
			break;
		case 0x21:  /* TCPv6 */
			if (ntohs(hdr_v2->len) < PP2_ADDR_LEN_INET6)
				goto bad_header;

			if (!sess || !sockaddr_alloc(&sess->src, NULL, 0) || !sockaddr_alloc(&sess->dst, NULL, 0))
				goto fail;

			((struct sockaddr_in6 *)sess->src)->sin6_family = AF_INET6;
			memcpy(&((struct sockaddr_in6 *)sess->src)->sin6_addr, hdr_v2->addr.ip6.src_addr, 16);
			((struct sockaddr_in6 *)sess->src)->sin6_port = hdr_v2->addr.ip6.src_port;
			((struct sockaddr_in6 *)sess->dst)->sin6_family = AF_INET6;
			memcpy(&((struct sockaddr_in6 *)sess->dst)->sin6_addr, hdr_v2->addr.ip6.dst_addr, 16);
			((struct sockaddr_in6 *)sess->dst)->sin6_port = hdr_v2->addr.ip6.dst_port;
			tlv_offset = PP2_HEADER_LEN + PP2_ADDR_LEN_INET6;
			break;
		}

		/* TLV parsing */
		while (tlv_offset < total_v2_len) {
			struct ist tlv;
			struct tlv *tlv_packet = NULL;
			struct conn_tlv_list *new_tlv = NULL;
			size_t data_len = 0;

			/* Verify that we have at least TLV_HEADER_SIZE bytes left */
			if (tlv_offset + TLV_HEADER_SIZE > total_v2_len)
				goto bad_header;

			tlv_packet = (struct tlv *) &trash.area[tlv_offset];
			tlv = ist2((const char *)tlv_packet->value, get_tlv_length(tlv_packet));
			tlv_offset += istlen(tlv) + TLV_HEADER_SIZE;

			/* Verify that the TLV length does not exceed the total PROXYv2 length */
			if (tlv_offset > total_v2_len)
				goto bad_header;

			/* Prepare known TLV types */
			switch (tlv_packet->type) {
			case PP2_TYPE_CRC32C: {
				uint32_t n_crc32c;

				/* Verify that this TLV is exactly 4 bytes long */
				if (istlen(tlv) != PP2_CRC32C_LEN)
					goto bad_header;

				n_crc32c = read_n32(istptr(tlv));
				write_n32(istptr(tlv), 0); // compute with CRC==0

				if (hash_crc32c(trash.area, total_v2_len) != n_crc32c)
					goto bad_header;
				break;
			}
#ifdef USE_NS
			case PP2_TYPE_NETNS: {
				const struct netns_entry *ns;

				ns = netns_store_lookup(istptr(tlv), istlen(tlv));
				if (ns)
					conn->proxy_netns = ns;
				break;
			}
#endif
			case PP2_TYPE_AUTHORITY: {
				/* For now, keep the length restriction by HAProxy */
				if (istlen(tlv) > HA_PP2_AUTHORITY_MAX)
					goto bad_header;

				break;
			}
			case PP2_TYPE_UNIQUE_ID: {
				if (istlen(tlv) > UNIQUEID_LEN)
					goto bad_header;
				break;
			}
			default:
				break;
			}

			/* If we did not find a known TLV type that we can optimize for, we generically allocate it */
			data_len = get_tlv_length(tlv_packet);

			/* Prevent attackers from allocating too much memory */
			if (unlikely(data_len > HA_PP2_MAX_ALLOC))
				goto fail;

			/* Alloc memory based on data_len */
			if (data_len > HA_PP2_TLV_VALUE_256)
				new_tlv = malloc(get_tlv_length(tlv_packet) + sizeof(struct conn_tlv_list));
			else if (data_len <= HA_PP2_TLV_VALUE_128)
				new_tlv = pool_alloc(pool_head_pp_tlv_128);
			else
				new_tlv = pool_alloc(pool_head_pp_tlv_256);

			if (unlikely(!new_tlv))
				goto fail;

			new_tlv->type = tlv_packet->type;

			/* Save TLV to make it accessible via sample fetch */
			memcpy(new_tlv->value, tlv.ptr, data_len);
			new_tlv->len = data_len;

			LIST_APPEND(&conn->tlv_list, &new_tlv->list);
		}


		/* Verify that the PROXYv2 header ends at a TLV boundary.
		 * This is can not be true, because the TLV parsing already
		 * verifies that a TLV does not exceed the total length and
		 * also that there is space for a TLV header.
		 */
		BUG_ON(tlv_offset != total_v2_len);

		/* unsupported protocol, keep local connection address */
		break;
	case 0x00: /* LOCAL command */
		/* keep local connection address for LOCAL */
		break;
	default:
		goto bad_header; /* not a supported command */
	}

	trash.data = total_v2_len;
	goto eat_header;

 eat_header:
	/* remove the PROXY line from the request. For this we re-read the
	 * exact line at once. If we don't get the exact same result, we
	 * fail.
	 */
	while (1) {
		ssize_t len2 = recv(conn->handle.fd, trash.area, trash.data, 0);

		if (len2 < 0 && errno == EINTR)
			continue;
		if (len2 != trash.data)
			goto recv_abort;
		break;
	}

	conn->flags &= ~flag;
	conn->flags |= CO_FL_RCVD_PROXY;
	return 1;

 not_ready:
	return 0;

 missing:
	/* Missing data. Since we're using MSG_PEEK, we can only poll again if
	 * we have not read anything. Otherwise we need to fail because we won't
	 * be able to poll anymore.
	 */
	conn->err_code = CO_ER_PRX_TRUNCATED;
	goto fail;

 bad_header:
	/* This is not a valid proxy protocol header */
	conn->err_code = CO_ER_PRX_BAD_HDR;
	goto fail;

 recv_abort:
	conn->err_code = CO_ER_PRX_ABORT;
	conn->flags |= CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
	goto fail;

 fail:
	conn->flags |= CO_FL_ERROR;
	return 0;
}

/* This callback is used to send a valid PROXY protocol line to a socket being
 * established. It returns 0 if it fails in a fatal way or needs to poll to go
 * further, otherwise it returns non-zero and removes itself from the connection's
 * flags (the bit is provided in <flag> by the caller). It is designed to be
 * called by the connection handler and relies on it to commit polling changes.
 * Note that it can emit a PROXY line by relying on the other end's address
 * when the connection is attached to a stream connector, or by resolving the
 * local address otherwise (also called a LOCAL line).
 */
int conn_send_proxy(struct connection *conn, unsigned int flag)
{
	if (!conn_ctrl_ready(conn))
		goto out_error;

	/* If we have a PROXY line to send, we'll use this to validate the
	 * connection, in which case the connection is validated only once
	 * we've sent the whole proxy line. Otherwise we use connect().
	 */
	if (conn->send_proxy_ofs) {
		struct stconn *sc;
		int ret;

		/* If there is no mux attached to the connection, it means the
		 * connection context is a stream connector.
		 */
		sc = conn->mux ? conn_get_first_sc(conn) : conn->ctx;

		/* The target server expects a PROXY line to be sent first.
		 * If the send_proxy_ofs is negative, it corresponds to the
		 * offset to start sending from then end of the proxy string
		 * (which is recomputed every time since it's constant). If
		 * it is positive, it means we have to send from the start.
		 * We can only send a "normal" PROXY line when the connection
		 * is attached to a stream connector. Otherwise we can only
		 * send a LOCAL line (eg: for use with health checks).
		 */

		if (sc && sc_strm(sc)) {
			ret = make_proxy_line(trash.area, trash.size,
					      objt_server(conn->target),
					      sc_conn(sc_opposite(sc)),
					      __sc_strm(sc));
		}
		else {
			/* The target server expects a LOCAL line to be sent first. Retrieving
			 * local or remote addresses may fail until the connection is established.
			 */
			if (!conn_get_src(conn) || !conn_get_dst(conn))
				goto out_wait;

			ret = make_proxy_line(trash.area, trash.size,
					      objt_server(conn->target), conn,
					      NULL);
		}

		if (!ret)
			goto out_error;

		if (conn->send_proxy_ofs > 0)
			conn->send_proxy_ofs = -ret; /* first call */

		/* we have to send trash from (ret+sp for -sp bytes). If the
		 * data layer has a pending write, we'll also set MSG_MORE.
		 */
		ret = conn_ctrl_send(conn,
				     trash.area + ret + conn->send_proxy_ofs,
		                     -conn->send_proxy_ofs,
		                     (conn->subs && conn->subs->events & SUB_RETRY_SEND) ? CO_SFL_MSG_MORE : 0);

		if (ret < 0)
			goto out_error;

		conn->send_proxy_ofs += ret; /* becomes zero once complete */
		if (conn->send_proxy_ofs != 0)
			goto out_wait;

		/* OK we've sent the whole line, we're connected */
	}

	/* The connection is ready now, simply return and let the connection
	 * handler notify upper layers if needed.
	 */
	conn->flags &= ~CO_FL_WAIT_L4_CONN;
	conn->flags &= ~flag;
	return 1;

 out_error:
	/* Write error on the file descriptor */
	conn->flags |= CO_FL_ERROR;
	return 0;

 out_wait:
	return 0;
}

/* This handshake handler waits a NetScaler Client IP insertion header
 * at the beginning of the raw data stream. The header format is
 * described in doc/netscaler-client-ip-insertion-protocol.txt
 *
 * This line MUST be at the beginning of the buffer and MUST NOT be
 * fragmented.
 *
 * The header line is small and in all cases smaller than the smallest normal
 * TCP MSS. So it MUST always be delivered as one segment, which ensures we
 * can safely use MSG_PEEK and avoid buffering.
 *
 * Once the data is fetched, the values are set in the connection's address
 * fields, and data are removed from the socket's buffer. The function returns
 * zero if it needs to wait for more data or if it fails, or 1 if it completed
 * and removed itself.
 */
int conn_recv_netscaler_cip(struct connection *conn, int flag)
{
	struct session *sess = conn->owner;
	char *line;
	uint32_t hdr_len;
	uint8_t ip_ver;
	int ret;

	if (!conn_ctrl_ready(conn))
		goto fail;

	BUG_ON(conn->flags & CO_FL_FDLESS);

	if (!fd_recv_ready(conn->handle.fd))
		goto not_ready;

	while (1) {
		ret = recv(conn->handle.fd, trash.area, trash.size, MSG_PEEK);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				fd_cant_recv(conn->handle.fd);
				goto not_ready;
			}
			goto recv_abort;
		}
		trash.data = ret;
		break;
	}

	conn->flags &= ~CO_FL_WAIT_L4_CONN;

	if (!trash.data) {
		/* client shutdown */
		conn->err_code = CO_ER_CIP_EMPTY;
		goto fail;
	}

	/* Fail if buffer length is not large enough to contain
	 * CIP magic, header length or
	 * CIP magic, CIP length, CIP type, header length */
	if (trash.data < 12)
		goto missing;

	line = trash.area;

	/* Decode a possible NetScaler Client IP request, fail early if
	 * it does not match */
	if (ntohl(read_u32(line)) != __objt_listener(conn->target)->bind_conf->ns_cip_magic)
		goto bad_magic;

	/* Legacy CIP protocol */
	if ((trash.area[8] & 0xD0) == 0x40) {
		hdr_len = ntohl(read_u32((line+4)));
		line += 8;
	}
	/* Standard CIP protocol */
	else if (trash.area[8] == 0x00) {
		hdr_len = ntohs(read_u32((line+10)));
		line += 12;
	}
	/* Unknown CIP protocol */
	else {
		conn->err_code = CO_ER_CIP_BAD_PROTO;
		goto fail;
	}

	/* Fail if buffer length is not large enough to contain
	 * a minimal IP header */
	if (trash.data < 20)
		goto missing;

	/* Get IP version from the first four bits */
	ip_ver = (*line & 0xf0) >> 4;

	if (ip_ver == 4) {
		struct ip *hdr_ip4;
		struct my_tcphdr *hdr_tcp;

		hdr_ip4 = (struct ip *)line;

		if (trash.data < 40 || trash.data < hdr_len) {
			/* Fail if buffer length is not large enough to contain
			 * IPv4 header, TCP header */
			goto missing;
		}
		else if (hdr_ip4->ip_p != IPPROTO_TCP) {
			/* The protocol does not include a TCP header */
			conn->err_code = CO_ER_CIP_BAD_PROTO;
			goto fail;
		}

		hdr_tcp = (struct my_tcphdr *)(line + (hdr_ip4->ip_hl * 4));

		if (!sess || !sockaddr_alloc(&sess->src, NULL, 0) || !sockaddr_alloc(&sess->dst, NULL, 0))
			goto fail;

		/* update the session's addresses and mark them set */
		((struct sockaddr_in *)sess->src)->sin_family = AF_INET;
		((struct sockaddr_in *)sess->src)->sin_addr.s_addr = hdr_ip4->ip_src.s_addr;
		((struct sockaddr_in *)sess->src)->sin_port = hdr_tcp->source;

		((struct sockaddr_in *)sess->dst)->sin_family = AF_INET;
		((struct sockaddr_in *)sess->dst)->sin_addr.s_addr = hdr_ip4->ip_dst.s_addr;
		((struct sockaddr_in *)sess->dst)->sin_port = hdr_tcp->dest;
	}
	else if (ip_ver == 6) {
		struct ip6_hdr *hdr_ip6;
		struct my_tcphdr *hdr_tcp;

		hdr_ip6 = (struct ip6_hdr *)line;

		if (trash.data < 60 || trash.data < hdr_len) {
			/* Fail if buffer length is not large enough to contain
			 * IPv6 header, TCP header */
			goto missing;
		}
		else if (hdr_ip6->ip6_nxt != IPPROTO_TCP) {
			/* The protocol does not include a TCP header */
			conn->err_code = CO_ER_CIP_BAD_PROTO;
			goto fail;
		}

		hdr_tcp = (struct my_tcphdr *)(line + sizeof(struct ip6_hdr));

		if (!sess || !sockaddr_alloc(&sess->src, NULL, 0) || !sockaddr_alloc(&sess->dst, NULL, 0))
			goto fail;

		/* update the session's addresses and mark them set */
		((struct sockaddr_in6 *)sess->src)->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)sess->src)->sin6_addr = hdr_ip6->ip6_src;
		((struct sockaddr_in6 *)sess->src)->sin6_port = hdr_tcp->source;

		((struct sockaddr_in6 *)sess->dst)->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)sess->dst)->sin6_addr = hdr_ip6->ip6_dst;
		((struct sockaddr_in6 *)sess->dst)->sin6_port = hdr_tcp->dest;
	}
	else {
		/* The protocol does not match something known (IPv4/IPv6) */
		conn->err_code = CO_ER_CIP_BAD_PROTO;
		goto fail;
	}

	line += hdr_len;
	trash.data = line - trash.area;

	/* remove the NetScaler Client IP header from the request. For this
	 * we re-read the exact line at once. If we don't get the exact same
	 * result, we fail.
	 */
	while (1) {
		int len2 = recv(conn->handle.fd, trash.area, trash.data, 0);
		if (len2 < 0 && errno == EINTR)
			continue;
		if (len2 != trash.data)
			goto recv_abort;
		break;
	}

	conn->flags &= ~flag;
	return 1;

 not_ready:
	return 0;

 missing:
	/* Missing data. Since we're using MSG_PEEK, we can only poll again if
	 * we have not read anything. Otherwise we need to fail because we won't
	 * be able to poll anymore.
	 */
	conn->err_code = CO_ER_CIP_TRUNCATED;
	goto fail;

 bad_magic:
	conn->err_code = CO_ER_CIP_BAD_MAGIC;
	goto fail;

 recv_abort:
	conn->err_code = CO_ER_CIP_ABORT;
	conn->flags |= CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
	goto fail;

 fail:
	conn->flags |= CO_FL_ERROR;
	return 0;
}


int conn_send_socks4_proxy_request(struct connection *conn)
{
	struct socks4_request req_line;

	if (!conn_ctrl_ready(conn))
		goto out_error;

	if (!conn_get_dst(conn))
		goto out_error;

	req_line.version = 0x04;
	req_line.command = 0x01;
	req_line.port    = get_net_port(conn->dst);
	req_line.ip      = is_inet_addr(conn->dst);
	memcpy(req_line.user_id, "HAProxy\0", 8);

	if (conn->send_proxy_ofs > 0) {
		/*
		 * This is the first call to send the request
		 */
		conn->send_proxy_ofs = -(int)sizeof(req_line);
	}

	if (conn->send_proxy_ofs < 0) {
		int ret = 0;

		/* we are sending the socks4_req_line here. If the data layer
		 * has a pending write, we'll also set MSG_MORE.
		 */
		ret = conn_ctrl_send(
				conn,
				((char *)(&req_line)) + (sizeof(req_line)+conn->send_proxy_ofs),
				-conn->send_proxy_ofs,
				(conn->subs && conn->subs->events & SUB_RETRY_SEND) ? CO_SFL_MSG_MORE : 0);

		DPRINTF(stderr, "SOCKS PROXY HS FD[%04X]: Before send remain is [%d], sent [%d]\n",
			conn_fd(conn), -conn->send_proxy_ofs, ret);

		if (ret < 0) {
			goto out_error;
		}

		conn->send_proxy_ofs += ret; /* becomes zero once complete */
		if (conn->send_proxy_ofs != 0) {
			goto out_wait;
		}
	}

	/* OK we've the whole request sent */
	conn->flags &= ~CO_FL_SOCKS4_SEND;

	/* The connection is ready now, simply return and let the connection
	 * handler notify upper layers if needed.
	 */
	conn->flags &= ~CO_FL_WAIT_L4_CONN;

	if (conn->flags & CO_FL_SEND_PROXY) {
		/*
		 * Get the send_proxy_ofs ready for the send_proxy due to we are
		 * reusing the "send_proxy_ofs", and SOCKS4 handshake should be done
		 * before sending PROXY Protocol.
		 */
		conn->send_proxy_ofs = 1;
	}
	return 1;

 out_error:
	/* Write error on the file descriptor */
	conn->flags |= CO_FL_ERROR;
	if (conn->err_code == CO_ER_NONE) {
		conn->err_code = CO_ER_SOCKS4_SEND;
	}
	return 0;

 out_wait:
	return 0;
}

int conn_recv_socks4_proxy_response(struct connection *conn)
{
	char line[SOCKS4_HS_RSP_LEN];
	int ret;

	if (!conn_ctrl_ready(conn))
		goto fail;

	BUG_ON(conn->flags & CO_FL_FDLESS);

	if (!fd_recv_ready(conn->handle.fd))
		goto not_ready;

	while (1) {
		/* SOCKS4 Proxy will response with 8 bytes, 0x00 | 0x5A | 0x00 0x00 | 0x00 0x00 0x00 0x00
		 * Try to peek into it, before all 8 bytes ready.
		 */
		ret = recv(conn->handle.fd, line, SOCKS4_HS_RSP_LEN, MSG_PEEK);

		if (ret == 0) {
			/* the socket has been closed or shutdown for send */
			DPRINTF(stderr, "SOCKS PROXY HS FD[%04X]: Received ret[%d], errno[%d], looks like the socket has been closed or shutdown for send\n",
					conn->handle.fd, ret, errno);
			if (conn->err_code == CO_ER_NONE) {
				conn->err_code = CO_ER_SOCKS4_RECV;
			}
			goto fail;
		}

		if (ret > 0) {
			if (ret == SOCKS4_HS_RSP_LEN) {
				DPRINTF(stderr, "SOCKS PROXY HS FD[%04X]: Received 8 bytes, the response is [%02X|%02X|%02X %02X|%02X %02X %02X %02X]\n",
						conn->handle.fd, line[0], line[1], line[2], line[3], line[4], line[5], line[6], line[7]);
			}else{
				DPRINTF(stderr, "SOCKS PROXY HS FD[%04X]: Received ret[%d], first byte is [%02X], last bye is [%02X]\n", conn->handle.fd, ret, line[0], line[ret-1]);
			}
		} else {
			DPRINTF(stderr, "SOCKS PROXY HS FD[%04X]: Received ret[%d], errno[%d]\n", conn->handle.fd, ret, errno);
		}

		if (ret < 0) {
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				fd_cant_recv(conn->handle.fd);
				goto not_ready;
			}
			goto recv_abort;
		}
		break;
	}

	conn->flags &= ~CO_FL_WAIT_L4_CONN;

	if (ret < SOCKS4_HS_RSP_LEN) {
		/* Missing data. Since we're using MSG_PEEK, we can only poll again if
		 * we are not able to read enough data.
		 */
		goto not_ready;
	}

	/*
	 * Base on the SOCSK4 protocol:
	 *
	 *			+----+----+----+----+----+----+----+----+
	 *			| VN | CD | DSTPORT |      DSTIP        |
	 *			+----+----+----+----+----+----+----+----+
	 *	# of bytes:	   1    1      2              4
	 *	VN is the version of the reply code and should be 0. CD is the result
	 *	code with one of the following values:
	 *	90: request granted
	 *	91: request rejected or failed
	 *	92: request rejected because SOCKS server cannot connect to identd on the client
	 *	93: request rejected because the client program and identd report different user-ids
	 *	The remaining fields are ignored.
	 */
	if (line[1] != 90) {
		conn->flags &= ~CO_FL_SOCKS4_RECV;

		DPRINTF(stderr, "SOCKS PROXY HS FD[%04X]: FAIL, the response is [%02X|%02X|%02X %02X|%02X %02X %02X %02X]\n",
				conn->handle.fd, line[0], line[1], line[2], line[3], line[4], line[5], line[6], line[7]);
		if (conn->err_code == CO_ER_NONE) {
			conn->err_code = CO_ER_SOCKS4_DENY;
		}
		goto fail;
	}

	/* remove the 8 bytes response from the stream */
	while (1) {
		ret = recv(conn->handle.fd, line, SOCKS4_HS_RSP_LEN, 0);
		if (ret < 0 && errno == EINTR) {
			continue;
		}
		if (ret != SOCKS4_HS_RSP_LEN) {
			if (conn->err_code == CO_ER_NONE) {
				conn->err_code = CO_ER_SOCKS4_RECV;
			}
			goto fail;
		}
		break;
	}

	conn->flags &= ~CO_FL_SOCKS4_RECV;
	return 1;

 not_ready:
	return 0;

 recv_abort:
	if (conn->err_code == CO_ER_NONE) {
		conn->err_code = CO_ER_SOCKS4_ABORT;
	}
	conn->flags |= (CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH);
	goto fail;

 fail:
	conn->flags |= CO_FL_ERROR;
	return 0;
}

/* registers proto mux list <list>. Modifies the list element! */
void register_mux_proto(struct mux_proto_list *list)
{
	LIST_APPEND(&mux_proto_list.list, &list->list);
}

/* Lists the known proto mux on <out>. This function is used by "haproxy -vv"
 * and is suitable for early boot just after the "REGISTER" stage because it
 * doesn't depend on anything to be already allocated.
 */
void list_mux_proto(FILE *out)
{
	struct mux_proto_list *item;
	struct ist proto;
	char *mode, *side;
	int done;

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

		fprintf(out, " %10s : mode=%-5s side=%-6s mux=%-5s flags=",
			(proto.len ? proto.ptr : "<default>"), mode, side, item->mux->name);

		done = 0;

		/* note: the block below could be simplified using macros but for only
		 * 4 flags it's not worth it.
		 */
		if (item->mux->flags & MX_FL_HTX)
			done |= fprintf(out, "%sHTX", done ? "|" : "");

		if (item->mux->flags & MX_FL_HOL_RISK)
			done |= fprintf(out, "%sHOL_RISK", done ? "|" : "");

		if (item->mux->flags & MX_FL_NO_UPG)
			done |= fprintf(out, "%sNO_UPG", done ? "|" : "");

		if (item->mux->flags & MX_FL_FRAMED)
			done |= fprintf(out, "%sFRAMED", done ? "|" : "");

		fprintf(out, "\n");
	}
}

/* Makes a PROXY protocol line from the two addresses. The output is sent to
 * buffer <buf> for a maximum size of <buf_len> (including the trailing zero).
 * It returns the number of bytes composing this line (including the trailing
 * LF), or zero in case of failure (eg: not enough space). It supports TCP4,
 * TCP6 and "UNKNOWN" formats. If any of <src> or <dst> is null, UNKNOWN is
 * emitted as well.
 */
static int make_proxy_line_v1(char *buf, int buf_len, const struct sockaddr_storage *src, const struct sockaddr_storage *dst)
{
	int ret = 0;
	char * protocol;
	char src_str[MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];
	char dst_str[MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];
	in_port_t src_port;
	in_port_t dst_port;

	if (   !src
	    || !dst
	    || (src->ss_family != AF_INET && src->ss_family != AF_INET6)
	    || (dst->ss_family != AF_INET && dst->ss_family != AF_INET6)) {
		/* unknown family combination */
		ret = snprintf(buf, buf_len, "PROXY UNKNOWN\r\n");
		if (ret >= buf_len)
			return 0;

		return ret;
	}

	/* IPv4 for both src and dst */
	if (src->ss_family == AF_INET && dst->ss_family == AF_INET) {
		protocol = "TCP4";
		if (!inet_ntop(AF_INET, &((struct sockaddr_in *)src)->sin_addr, src_str, sizeof(src_str)))
			return 0;
		src_port = ((struct sockaddr_in *)src)->sin_port;
		if (!inet_ntop(AF_INET, &((struct sockaddr_in *)dst)->sin_addr, dst_str, sizeof(dst_str)))
			return 0;
		dst_port = ((struct sockaddr_in *)dst)->sin_port;
	}
	/* IPv6 for at least one of src and dst */
	else {
		struct in6_addr tmp;

		protocol = "TCP6";

		if (src->ss_family == AF_INET) {
			/* Convert src to IPv6 */
			v4tov6(&tmp, &((struct sockaddr_in *)src)->sin_addr);
			src_port = ((struct sockaddr_in *)src)->sin_port;
		}
		else {
			tmp = ((struct sockaddr_in6 *)src)->sin6_addr;
			src_port = ((struct sockaddr_in6 *)src)->sin6_port;
		}

		if (!inet_ntop(AF_INET6, &tmp, src_str, sizeof(src_str)))
			return 0;

		if (dst->ss_family == AF_INET) {
			/* Convert dst to IPv6 */
			v4tov6(&tmp, &((struct sockaddr_in *)dst)->sin_addr);
			dst_port = ((struct sockaddr_in *)dst)->sin_port;
		}
		else {
			tmp = ((struct sockaddr_in6 *)dst)->sin6_addr;
			dst_port = ((struct sockaddr_in6 *)dst)->sin6_port;
		}

		if (!inet_ntop(AF_INET6, &tmp, dst_str, sizeof(dst_str)))
			return 0;
	}

	ret = snprintf(buf, buf_len, "PROXY %s %s %s %u %u\r\n", protocol, src_str, dst_str, ntohs(src_port), ntohs(dst_port));
	if (ret >= buf_len)
		return 0;

	return ret;
}

static int make_tlv(char *dest, int dest_len, char type, uint16_t length, const char *value)
{
	struct tlv *tlv;

	if (!dest || (length + sizeof(*tlv) > dest_len))
		return 0;

	tlv = (struct tlv *)dest;

	tlv->type = type;
	tlv->length_hi = length >> 8;
	tlv->length_lo = length & 0x00ff;
	memcpy(tlv->value, value, length);
	return length + sizeof(*tlv);
}

/* Note: <remote> is explicitly allowed to be NULL */
static int make_proxy_line_v2(char *buf, int buf_len, struct server *srv, struct connection *remote, struct stream *strm)
{
	const char pp2_signature[] = PP2_SIGNATURE;
	void *tlv_crc32c_p = NULL;
	int ret = 0;
	struct proxy_hdr_v2 *hdr = (struct proxy_hdr_v2 *)buf;
	struct sockaddr_storage null_addr = { .ss_family = 0 };
	struct srv_pp_tlv_list *srv_tlv = NULL;
	const struct sockaddr_storage *src = &null_addr;
	const struct sockaddr_storage *dst = &null_addr;
	const char *value = "";
	int value_len = 0;

	if (buf_len < PP2_HEADER_LEN)
		return 0;
	memcpy(hdr->sig, pp2_signature, PP2_SIGNATURE_LEN);

	if (strm) {
		src = sc_src(strm->scf);
		dst = sc_dst(strm->scf);
	}
	else if (remote && conn_get_src(remote) && conn_get_dst(remote)) {
		src = conn_src(remote);
		dst = conn_dst(remote);
	}

	/* At least one of src or dst is not of AF_INET or AF_INET6 */
	if (  !src
	   || !dst
	   || (!pp2_never_send_local && conn_is_back(remote)) // locally initiated connection
	   || (src->ss_family != AF_INET && src->ss_family != AF_INET6)
	   || (dst->ss_family != AF_INET && dst->ss_family != AF_INET6)) {
		if (buf_len < PP2_HDR_LEN_UNSPEC)
			return 0;
		hdr->ver_cmd = PP2_VERSION | PP2_CMD_LOCAL;
		hdr->fam = PP2_FAM_UNSPEC | PP2_TRANS_UNSPEC;
		ret = PP2_HDR_LEN_UNSPEC;
	}
	else {
		hdr->ver_cmd = PP2_VERSION | PP2_CMD_PROXY;
		/* IPv4 for both src and dst */
		if (src->ss_family == AF_INET && dst->ss_family == AF_INET) {
			if (buf_len < PP2_HDR_LEN_INET)
				return 0;
			hdr->fam = PP2_FAM_INET | PP2_TRANS_STREAM;
			hdr->addr.ip4.src_addr = ((struct sockaddr_in *)src)->sin_addr.s_addr;
			hdr->addr.ip4.src_port = ((struct sockaddr_in *)src)->sin_port;
			hdr->addr.ip4.dst_addr = ((struct sockaddr_in *)dst)->sin_addr.s_addr;
			hdr->addr.ip4.dst_port = ((struct sockaddr_in *)dst)->sin_port;
			ret = PP2_HDR_LEN_INET;
		}
		/* IPv6 for at least one of src and dst */
		else {
			struct in6_addr tmp;

			if (buf_len < PP2_HDR_LEN_INET6)
				return 0;
			hdr->fam = PP2_FAM_INET6 | PP2_TRANS_STREAM;
			if (src->ss_family == AF_INET) {
				v4tov6(&tmp, &((struct sockaddr_in *)src)->sin_addr);
				memcpy(hdr->addr.ip6.src_addr, &tmp, 16);
				hdr->addr.ip6.src_port = ((struct sockaddr_in *)src)->sin_port;
			}
			else {
				memcpy(hdr->addr.ip6.src_addr, &((struct sockaddr_in6 *)src)->sin6_addr, 16);
				hdr->addr.ip6.src_port = ((struct sockaddr_in6 *)src)->sin6_port;
			}
			if (dst->ss_family == AF_INET) {
				v4tov6(&tmp, &((struct sockaddr_in *)dst)->sin_addr);
				memcpy(hdr->addr.ip6.dst_addr, &tmp, 16);
				hdr->addr.ip6.dst_port = ((struct sockaddr_in *)dst)->sin_port;
			}
			else {
				memcpy(hdr->addr.ip6.dst_addr, &((struct sockaddr_in6 *)dst)->sin6_addr, 16);
				hdr->addr.ip6.dst_port = ((struct sockaddr_in6 *)dst)->sin6_port;
			}

			ret = PP2_HDR_LEN_INET6;
		}
	}

	if (strm) {
		struct buffer *replace = NULL;

		list_for_each_entry(srv_tlv, &srv->pp_tlvs, list) {
			replace = NULL;

			/* Users will always need to provide a value, in case of forwarding, they should use fc_pp_tlv.
			 * for generic types. Otherwise, we will send an empty TLV.
			 */
			if (!LIST_ISEMPTY(&srv_tlv->fmt)) {
				replace = alloc_trash_chunk();
				if (unlikely(!replace))
					return 0;

				replace->data = build_logline(strm, replace->area, replace->size, &srv_tlv->fmt);

				if (unlikely((buf_len - ret) < sizeof(struct tlv))) {
					free_trash_chunk(replace);
					return 0;
				}
				ret += make_tlv(&buf[ret], (buf_len - ret), srv_tlv->type, replace->data, replace->area);
				free_trash_chunk(replace);
			}
			else {
				/* Create empty TLV as no value was specified */
				ret += make_tlv(&buf[ret], (buf_len - ret), srv_tlv->type, 0, NULL);
			}
		}
	}

	/* Handle predefined TLVs as usual */
	if (srv->pp_opts & SRV_PP_V2_CRC32C) {
		uint32_t zero_crc32c = 0;

		if ((buf_len - ret) < sizeof(struct tlv))
			return 0;
		tlv_crc32c_p = (void *)((struct tlv *)&buf[ret])->value;
		ret += make_tlv(&buf[ret], (buf_len - ret), PP2_TYPE_CRC32C, sizeof(zero_crc32c), (const char *)&zero_crc32c);
	}

	if (remote && conn_get_alpn(remote, &value, &value_len)) {
		if ((buf_len - ret) < sizeof(struct tlv))
			return 0;
		ret += make_tlv(&buf[ret], (buf_len - ret), PP2_TYPE_ALPN, value_len, value);
	}

	if (srv->pp_opts & SRV_PP_V2_AUTHORITY) {
		struct conn_tlv_list *tlv = conn_get_tlv(remote, PP2_TYPE_AUTHORITY);

		value = NULL;
		if (tlv) {
			value_len = tlv->len;
			value = tlv->value;
		}
#ifdef USE_OPENSSL
		else {
			if ((value = ssl_sock_get_sni(remote)))
				value_len = strlen(value);
		}
#endif
		if (value) {
			if ((buf_len - ret) < sizeof(struct tlv))
				return 0;
			ret += make_tlv(&buf[ret], (buf_len - ret), PP2_TYPE_AUTHORITY, value_len, value);
		}
	}

	if (strm && (srv->pp_opts & SRV_PP_V2_UNIQUE_ID)) {
		struct session* sess = strm_sess(strm);
		struct ist unique_id = stream_generate_unique_id(strm, &sess->fe->format_unique_id);

		value = unique_id.ptr;
		value_len = unique_id.len;

		if (value_len >= 0) {
			if ((buf_len - ret) < sizeof(struct tlv))
				return 0;
			ret += make_tlv(&buf[ret], (buf_len - ret), PP2_TYPE_UNIQUE_ID, value_len, value);
		}
	}

#ifdef USE_OPENSSL
	if (srv->pp_opts & SRV_PP_V2_SSL) {
		struct tlv_ssl *tlv;
		int ssl_tlv_len = 0;

		if ((buf_len - ret) < sizeof(struct tlv_ssl))
			return 0;
		tlv = (struct tlv_ssl *)&buf[ret];
		memset(tlv, 0, sizeof(struct tlv_ssl));
		ssl_tlv_len += sizeof(struct tlv_ssl);
		tlv->tlv.type = PP2_TYPE_SSL;
		if (conn_is_ssl(remote)) {
			tlv->client |= PP2_CLIENT_SSL;
			value = ssl_sock_get_proto_version(remote);
			if (value) {
				ssl_tlv_len += make_tlv(&buf[ret+ssl_tlv_len], (buf_len-ret-ssl_tlv_len), PP2_SUBTYPE_SSL_VERSION, strlen(value), value);
			}
			if (ssl_sock_get_cert_used_sess(remote)) {
				tlv->client |= PP2_CLIENT_CERT_SESS;
				tlv->verify = htonl(ssl_sock_get_verify_result(remote));
				if (ssl_sock_get_cert_used_conn(remote))
					tlv->client |= PP2_CLIENT_CERT_CONN;
			}
			if (srv->pp_opts & SRV_PP_V2_SSL_CN) {
				struct buffer *cn_trash = get_trash_chunk();
				if (ssl_sock_get_remote_common_name(remote, cn_trash) > 0) {
					ssl_tlv_len += make_tlv(&buf[ret+ssl_tlv_len], (buf_len - ret - ssl_tlv_len), PP2_SUBTYPE_SSL_CN,
								cn_trash->data,
								cn_trash->area);
				}
			}
			if (srv->pp_opts & SRV_PP_V2_SSL_KEY_ALG) {
				struct buffer *pkey_trash = get_trash_chunk();
				if (ssl_sock_get_pkey_algo(remote, pkey_trash) > 0) {
					ssl_tlv_len += make_tlv(&buf[ret+ssl_tlv_len], (buf_len - ret - ssl_tlv_len), PP2_SUBTYPE_SSL_KEY_ALG,
								pkey_trash->data,
								pkey_trash->area);
				}
			}
			if (srv->pp_opts & SRV_PP_V2_SSL_SIG_ALG) {
				value = ssl_sock_get_cert_sig(remote);
				if (value) {
					ssl_tlv_len += make_tlv(&buf[ret+ssl_tlv_len], (buf_len - ret - ssl_tlv_len), PP2_SUBTYPE_SSL_SIG_ALG, strlen(value), value);
				}
			}
			if (srv->pp_opts & SRV_PP_V2_SSL_CIPHER) {
				value = ssl_sock_get_cipher_name(remote);
				if (value) {
					ssl_tlv_len += make_tlv(&buf[ret+ssl_tlv_len], (buf_len - ret - ssl_tlv_len), PP2_SUBTYPE_SSL_CIPHER, strlen(value), value);
				}
			}
		}
		tlv->tlv.length_hi = (uint16_t)(ssl_tlv_len - sizeof(struct tlv)) >> 8;
		tlv->tlv.length_lo = (uint16_t)(ssl_tlv_len - sizeof(struct tlv)) & 0x00ff;
		ret += ssl_tlv_len;
	}
#endif

#ifdef USE_NS
	if (remote && (remote->proxy_netns)) {
		if ((buf_len - ret) < sizeof(struct tlv))
			return 0;
		ret += make_tlv(&buf[ret], (buf_len - ret), PP2_TYPE_NETNS, remote->proxy_netns->name_len, remote->proxy_netns->node.key);
	}
#endif

	hdr->len = htons((uint16_t)(ret - PP2_HEADER_LEN));

	if (tlv_crc32c_p) {
		write_u32(tlv_crc32c_p, htonl(hash_crc32c(buf, ret)));
	}

	return ret;
}

/* Note: <remote> is explicitly allowed to be NULL */
int make_proxy_line(char *buf, int buf_len, struct server *srv, struct connection *remote, struct stream *strm)
{
	int ret = 0;

	if (srv && (srv->pp_opts & SRV_PP_V2)) {
		ret = make_proxy_line_v2(buf, buf_len, srv, remote, strm);
	}
	else {
		const struct sockaddr_storage *src = NULL;
		const struct sockaddr_storage *dst = NULL;

		if (strm) {
			src = sc_src(strm->scf);
			dst = sc_dst(strm->scf);
		}
		else if (remote && conn_get_src(remote) && conn_get_dst(remote)) {
			src = conn_src(remote);
			dst = conn_dst(remote);
		}

		if (src && dst)
			ret = make_proxy_line_v1(buf, buf_len, src, dst);
		else
			ret = make_proxy_line_v1(buf, buf_len, NULL, NULL);
	}

	return ret;
}

/* returns 0 on success */
static int cfg_parse_pp2_never_send_local(char **args, int section_type, struct proxy *curpx,
                                          const struct proxy *defpx, const char *file, int line,
                                          char **err)
{
	if (too_many_args(0, args, err, NULL))
		return -1;
	pp2_never_send_local = 1;
	return 0;
}

/* extracts some info from the connection and appends them to buffer <buf>. The
 * connection's pointer, its direction, target (fe/be/srv), xprt/ctrl, source
 * when set, destination when set, are printed in a compact human-readable format
 * fitting on a single line. This is handy to complete traces or debug output.
 * It is permitted to pass a NULL conn pointer. The number of characters emitted
 * is returned. A prefix <pfx> might be prepended before the first field if not
 * NULL.
 */
int conn_append_debug_info(struct buffer *buf, const struct connection *conn, const char *pfx)
{
	const struct listener *li;
	const struct server   *sv;
	const struct proxy    *px;
	char addr[40];
	int old_len = buf->data;

	if (!conn)
		return 0;

	chunk_appendf(buf, "%sconn=%p(%s)", pfx ? pfx : "", conn, conn_is_back(conn) ? "OUT" : "IN");

	if ((li = objt_listener(conn->target)))
		chunk_appendf(buf, " fe=%s", li->bind_conf->frontend->id);
	else if ((sv = objt_server(conn->target)))
		chunk_appendf(buf, " sv=%s/%s", sv->proxy->id, sv->id);
	else if ((px = objt_proxy(conn->target)))
		chunk_appendf(buf, " be=%s", px->id);

	chunk_appendf(buf, " %s/%s", conn_get_xprt_name(conn), conn_get_ctrl_name(conn));

	if (conn->src && addr_to_str(conn->src, addr, sizeof(addr)))
		chunk_appendf(buf, " src=%s:%d", addr, get_host_port(conn->src));

	if (conn->dst && addr_to_str(conn->dst, addr, sizeof(addr)))
		chunk_appendf(buf, " dst=%s:%d", addr, get_host_port(conn->dst));

	return buf->data - old_len;
}

/* return the number of glitches experienced on the mux connection. */
static int
smp_fetch_fc_glitches(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn = NULL;
	int ret;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
                conn = (kw[0] == 'b') ? sc_conn(__objt_check(smp->sess->origin)->sc) : NULL;
        else
                conn = (kw[0] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? sc_conn(smp->strm->scb) : NULL;

	/* No connection or a connection with an unsupported mux */
	if (!conn || (conn->mux && !conn->mux->ctl))
		return 0;

	/* Mux not installed yet, this may change */
	if (!conn->mux) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	ret = conn->mux->ctl(conn, MUX_CTL_GET_GLITCHES, NULL);
	if (ret < 0) {
		/* not supported by the mux */
		return 0;
	}

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = ret;
	return 1;
}

/* return the major HTTP version as 1 or 2 depending on how the request arrived
 * before being processed.
 *
 * WARNING: Should be updated if a new major HTTP version is added.
 */
static int
smp_fetch_fc_http_major(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn = NULL;
	const char *mux_name = NULL;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
                conn = (kw[0] == 'b') ? sc_conn(__objt_check(smp->sess->origin)->sc) : NULL;
        else
                conn = (kw[0] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? sc_conn(smp->strm->scb) : NULL;

	/* No connection or a connection with a RAW muxx */
	if (!conn || (conn->mux && !(conn->mux->flags & MX_FL_HTX)))
		return 0;

	/* No mux install, this may change */
	if (!conn->mux) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	mux_name = conn_get_mux_name(conn);

	smp->data.type = SMP_T_SINT;
	if (strcmp(mux_name, "QUIC") == 0)
		smp->data.u.sint = 3;
	else if (strcmp(mux_name, "H2") == 0)
		smp->data.u.sint = 2;
	else
		smp->data.u.sint = 1;

	return 1;
}

/* fetch if the received connection used a PROXY protocol header */
int smp_fetch_fc_rcvd_proxy(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	smp->flags = 0;
	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = (conn->flags & CO_FL_RCVD_PROXY) ? 1 : 0;

	return 1;
}

/*
 * This function checks the TLV type converter configuration.
 * It expects the corresponding TLV type as a string representing the number
 * or a constant. args[0] will be turned into the numerical value of the
 * TLV type string.
 */
static int smp_check_tlv_type(struct arg *args, char **err)
{
	int type;
	char *endp;
	struct ist input = ist2(args[0].data.str.area, args[0].data.str.data);

	if (isteqi(input, ist("ALPN")) != 0)
		type = PP2_TYPE_ALPN;
	else if (isteqi(input, ist("AUTHORITY")) != 0)
		type = PP2_TYPE_AUTHORITY;
	else if (isteqi(input, ist("CRC32C")) != 0)
		type = PP2_TYPE_CRC32C;
	else if (isteqi(input, ist("NOOP")) != 0)
		type = PP2_TYPE_NOOP;
	else if (isteqi(input, ist("UNIQUE_ID")) != 0)
		type = PP2_TYPE_UNIQUE_ID;
	else if (isteqi(input, ist("SSL")) != 0)
		type = PP2_TYPE_SSL;
	else if (isteqi(input, ist("SSL_VERSION")) != 0)
		type = PP2_SUBTYPE_SSL_VERSION;
	else if (isteqi(input, ist("SSL_CN")) != 0)
		type = PP2_SUBTYPE_SSL_CN;
	else if (isteqi(input, ist("SSL_CIPHER")) != 0)
		type = PP2_SUBTYPE_SSL_CIPHER;
	else if (isteqi(input, ist("SSL_SIG_ALG")) != 0)
		type = PP2_SUBTYPE_SSL_SIG_ALG;
	else if (isteqi(input, ist("SSL_KEY_ALG")) != 0)
		type = PP2_SUBTYPE_SSL_KEY_ALG;
	else if (isteqi(input, ist("NETNS")) != 0)
		type = PP2_TYPE_NETNS;
	else {
		type = strtoul(input.ptr, &endp, 0);
		if (endp && *endp != '\0') {
			memprintf(err, "Could not convert type '%s'", input.ptr);
			return 0;
		}
	}

	if (type < 0 || type > 255) {
		memprintf(err, "Invalid TLV Type '%s'", input.ptr);
		return 0;
	}

	chunk_destroy(&args[0].data.str);
	args[0].type = ARGT_SINT;
	args[0].data.sint = type;

	return 1;
}

/* fetch an arbitrary TLV from a PROXY protocol v2 header */
int smp_fetch_fc_pp_tlv(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int idx;
	struct connection *conn = NULL;
	struct conn_tlv_list *conn_tlv = NULL;

	conn = objt_conn(smp->sess->origin);
	if (!conn)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (args[0].type != ARGT_SINT)
		return 0;

	idx = args[0].data.sint;
	conn_tlv = smp->ctx.p ? smp->ctx.p : LIST_ELEM(conn->tlv_list.n, struct conn_tlv_list *, list);
	list_for_each_entry_from(conn_tlv, &conn->tlv_list, list) {
		if (conn_tlv->type == idx) {
			smp->flags |= SMP_F_NOT_LAST;
			smp->data.type = SMP_T_STR;
			smp->data.u.str.area = conn_tlv->value;
			smp->data.u.str.data = conn_tlv->len;
			smp->ctx.p = conn_tlv;

			return 1;
		}
	}

	smp->flags &= ~SMP_F_NOT_LAST;

	return 0;
}

/* fetch the authority TLV from a PROXY protocol header */
int smp_fetch_fc_pp_authority(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct arg tlv_arg;
	int ret;

	set_tlv_arg(PP2_TYPE_AUTHORITY, &tlv_arg);
	ret = smp_fetch_fc_pp_tlv(&tlv_arg, smp, kw, private);
	smp->flags &= ~SMP_F_NOT_LAST; // return only the first authority
	return ret;
}

/* fetch the unique ID TLV from a PROXY protocol header */
int smp_fetch_fc_pp_unique_id(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct arg tlv_arg;
	int ret;

	set_tlv_arg(PP2_TYPE_UNIQUE_ID, &tlv_arg);
	ret = smp_fetch_fc_pp_tlv(&tlv_arg, smp, kw, private);
	smp->flags &= ~SMP_F_NOT_LAST; // return only the first unique ID
	return ret;
}

/* fetch the error code of a connection */
int smp_fetch_fc_err(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
                conn = (kw[0] == 'b') ? sc_conn(__objt_check(smp->sess->origin)->sc) : NULL;
        else
                conn = (kw[0] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? sc_conn(smp->strm->scb) : NULL;

	if (!conn)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT && !conn->err_code) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	smp->flags = 0;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = (unsigned long long int)conn->err_code;

	return 1;
}

/* fetch a string representation of the error code of a connection */
int smp_fetch_fc_err_str(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	const char *err_code_str;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
                conn = (kw[0] == 'b') ? sc_conn(__objt_check(smp->sess->origin)->sc) : NULL;
        else
                conn = (kw[0] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? sc_conn(smp->strm->scb) : NULL;

	if (!conn)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT && !conn->err_code) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	err_code_str = conn_err_code_str(conn);

	if (!err_code_str)
		return 0;

	smp->flags = 0;
	smp->data.type = SMP_T_STR;
	smp->data.u.str.area = (char*)err_code_str;
	smp->data.u.str.data = strlen(err_code_str);

	return 1;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Note: fetches that may return multiple types should be declared using the
 * appropriate pseudo-type. If not available it must be declared as the lowest
 * common denominator, the type that can be casted into all other ones.
 */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
	{ "bc_err", smp_fetch_fc_err, 0, NULL, SMP_T_SINT, SMP_USE_L4SRV },
	{ "bc_err_str", smp_fetch_fc_err_str, 0, NULL, SMP_T_STR, SMP_USE_L4SRV },
	{ "bc_glitches", smp_fetch_fc_glitches, 0, NULL, SMP_T_SINT, SMP_USE_L4SRV },
	{ "bc_http_major", smp_fetch_fc_http_major, 0, NULL, SMP_T_SINT, SMP_USE_L4SRV },
	{ "fc_err", smp_fetch_fc_err, 0, NULL, SMP_T_SINT, SMP_USE_L4CLI },
	{ "fc_err_str", smp_fetch_fc_err_str, 0, NULL, SMP_T_STR, SMP_USE_L4CLI },
	{ "fc_glitches", smp_fetch_fc_glitches, 0, NULL, SMP_T_SINT, SMP_USE_L4CLI },
	{ "fc_http_major", smp_fetch_fc_http_major, 0, NULL, SMP_T_SINT, SMP_USE_L4CLI },
	{ "fc_rcvd_proxy", smp_fetch_fc_rcvd_proxy, 0, NULL, SMP_T_BOOL, SMP_USE_L4CLI },
	{ "fc_pp_authority", smp_fetch_fc_pp_authority, 0, NULL, SMP_T_STR, SMP_USE_L4CLI },
	{ "fc_pp_unique_id", smp_fetch_fc_pp_unique_id, 0, NULL, SMP_T_STR, SMP_USE_L4CLI },
	{ "fc_pp_tlv", smp_fetch_fc_pp_tlv, ARG1(1, STR), smp_check_tlv_type, SMP_T_STR, SMP_USE_L4CLI },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &sample_fetch_keywords);

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "pp2-never-send-local", cfg_parse_pp2_never_send_local },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/* private function to handle sockaddr as input for connection hash */
static void conn_calculate_hash_sockaddr(const struct sockaddr_storage *ss,
                                         char *buf, size_t *idx,
                                         enum conn_hash_params_t *hash_flags,
                                         enum conn_hash_params_t param_type_addr,
                                         enum conn_hash_params_t param_type_port)
{
	struct sockaddr_in *addr;
	struct sockaddr_in6 *addr6;

	switch (ss->ss_family) {
	case AF_INET:
		addr = (struct sockaddr_in *)ss;

		conn_hash_update(buf, idx,
		                 &addr->sin_addr, sizeof(addr->sin_addr),
		                 hash_flags, param_type_addr);

		if (addr->sin_port) {
			conn_hash_update(buf, idx,
			                 &addr->sin_port, sizeof(addr->sin_port),
			                 hash_flags, param_type_port);
		}

		break;

	case AF_INET6:
		addr6 = (struct sockaddr_in6 *)ss;

		conn_hash_update(buf, idx,
		                 &addr6->sin6_addr, sizeof(addr6->sin6_addr),
		                 hash_flags, param_type_addr);

		if (addr6->sin6_port) {
			conn_hash_update(buf, idx,
			                 &addr6->sin6_port, sizeof(addr6->sin6_port),
			                 hash_flags, param_type_port);
		}

		break;
	}
}

/* Generate the hash of a connection with params as input
 * Each non-null field of params is taken into account for the hash calcul.
 */
uint64_t conn_hash_prehash(char *buf, size_t size)
{
	return XXH64(buf, size, 0);
}

/* Append <data> into <buf> at <idx> offset in preparation for connection hash
 * calcul. <idx> is incremented beyond data <size>. In the same time, <flags>
 * are updated with <type> for the hash header.
 */
void conn_hash_update(char *buf, size_t *idx,
                      const void *data, size_t size,
                      enum conn_hash_params_t *flags,
                      enum conn_hash_params_t type)
{
	memcpy(&buf[*idx], data, size);
	*idx += size;
	*flags |= type;
}

uint64_t conn_hash_digest(char *buf, size_t bufsize,
                          enum conn_hash_params_t flags)
{
	const uint64_t flags_u64 = (uint64_t)flags;
	const uint64_t hash = XXH64(buf, bufsize, 0);

	return (flags_u64 << CONN_HASH_PAYLOAD_LEN) | CONN_HASH_GET_PAYLOAD(hash);
}

uint64_t conn_calculate_hash(const struct conn_hash_params *params)
{
	char *buf;
	size_t idx = 0;
	uint64_t hash = 0;
	enum conn_hash_params_t hash_flags = 0;

	buf = trash.area;

	conn_hash_update(buf, &idx, &params->target, sizeof(params->target), &hash_flags, 0);

	if (params->sni_prehash) {
		conn_hash_update(buf, &idx,
		                 &params->sni_prehash, sizeof(params->sni_prehash),
		                 &hash_flags, CONN_HASH_PARAMS_TYPE_SNI);
	}

	if (params->dst_addr) {
		conn_calculate_hash_sockaddr(params->dst_addr,
		                             buf, &idx, &hash_flags,
		                             CONN_HASH_PARAMS_TYPE_DST_ADDR,
		                             CONN_HASH_PARAMS_TYPE_DST_PORT);
	}

	if (params->src_addr) {
		conn_calculate_hash_sockaddr(params->src_addr,
		                             buf, &idx, &hash_flags,
		                             CONN_HASH_PARAMS_TYPE_SRC_ADDR,
		                             CONN_HASH_PARAMS_TYPE_SRC_PORT);
	}

	if (params->proxy_prehash) {
		conn_hash_update(buf, &idx,
		                 &params->proxy_prehash, sizeof(params->proxy_prehash),
		                 &hash_flags, CONN_HASH_PARAMS_TYPE_PROXY);
	}

	hash = conn_hash_digest(buf, idx, hash_flags);
	return hash;
}

/* Reverse a <conn> connection instance. This effectively moves the connection
 * from frontend to backend side or vice-versa depending on its initial status.
 *
 * For active reversal, 'reverse' member points to the listener used as the new
 * connection target. Once transition is completed, the connection needs to be
 * accepted on the listener to instantiate its parent session before using
 * streams.
 *
 * For passive reversal, 'reverse' member points to the server used as the new
 * connection target. Once transition is completed, the connection appears as a
 * normal backend connection.
 *
 * Returns 0 on success else non-zero.
 */
int conn_reverse(struct connection *conn)
{
	struct conn_hash_params hash_params;
	int64_t hash = 0;
	struct session *sess = conn->owner;

	if (!conn_is_back(conn)) {
		/* srv must have been set by a previous 'attach-srv' rule. */
		struct server *srv = objt_server(conn->reverse.target);
		BUG_ON(!srv);

		if (conn_backend_init(conn))
			return 1;

		/* Initialize hash value for usage as idle conns. */
		memset(&hash_params, 0, sizeof(hash_params));
		hash_params.target = srv;

		if (b_data(&conn->reverse.name)) {
			/* data cannot wrap else prehash usage is incorrect */
			BUG_ON(b_data(&conn->reverse.name) != b_contig_data(&conn->reverse.name, 0));

			hash_params.sni_prehash =
			  conn_hash_prehash(b_head(&conn->reverse.name),
			                    b_data(&conn->reverse.name));
		}

		hash = conn_calculate_hash(&hash_params);
		conn->hash_node->node.key = hash;

		conn->target = &srv->obj_type;
		srv_use_conn(srv, conn);

		/* Free the session after detaching the connection from it. */
		session_unown_conn(sess, conn);
		sess->origin = NULL;
		session_free(sess);
		conn_set_owner(conn, NULL, NULL);

		conn->flags |= CO_FL_REVERSED;
	}
	else {
		/* Wake up receiver to proceed to connection accept. */
		struct listener *l = __objt_listener(conn->reverse.target);

		conn_backend_deinit(conn);

		conn->target = &l->obj_type;
		conn->flags |= CO_FL_ACT_REVERSING;
		task_wakeup(l->rx.rhttp.task, TASK_WOKEN_ANY);
	}

	/* Invert source and destination addresses if already set. */
	SWAP(conn->src, conn->dst);

	conn->reverse.target = NULL;
	ha_free(&conn->reverse.name.area);
	conn->reverse.name = BUF_NULL;

	return 0;
}

/* Handler of the task of mux_stopping_data.
 * Called on soft-stop.
 */
static struct task *mux_stopping_process(struct task *t, void *ctx, unsigned int state)
{
	struct connection *conn, *back;

	list_for_each_entry_safe(conn, back, &mux_stopping_data[tid].list, stopping_list) {
		if (conn->mux && conn->mux->wake)
			conn->mux->wake(conn);
	}

	return t;
}

static int allocate_mux_cleanup(void)
{
	/* allocates the thread bound mux_stopping_data task */
	mux_stopping_data[tid].task = task_new_here();
	if (!mux_stopping_data[tid].task) {
		ha_alert("Failed to allocate the task for connection cleanup on thread %d.\n", tid);
		return 0;
	}

	mux_stopping_data[tid].task->process = mux_stopping_process;
	LIST_INIT(&mux_stopping_data[tid].list);

	return 1;
}
REGISTER_PER_THREAD_ALLOC(allocate_mux_cleanup);

static int deallocate_mux_cleanup(void)
{
	task_destroy(mux_stopping_data[tid].task);
	return 1;
}
REGISTER_PER_THREAD_FREE(deallocate_mux_cleanup);

static void deinit_idle_conns(void)
{
	int i;

	for (i = 0; i < global.nbthread; i++) {
		task_destroy(idle_conns[i].cleanup_task);
	}
}
REGISTER_POST_DEINIT(deinit_idle_conns);
