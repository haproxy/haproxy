/*
 * include/haproxy/cs_utils.h
 * This file contains stream connector util functions prototypes
 *
 * Copyright 2022 Christopher Faulet <cfaulet@haproxy.com>
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

#ifndef _HAPROXY_CS_UTILS_H
#define _HAPROXY_CS_UTILS_H

#include <haproxy/api.h>
#include <haproxy/buf-t.h>
#include <haproxy/channel-t.h>
#include <haproxy/stream-t.h>
#include <haproxy/task-t.h>
#include <haproxy/connection.h>
#include <haproxy/conn_stream.h>
#include <haproxy/channel.h>
#include <haproxy/session.h>
#include <haproxy/stream.h>

void cs_update_rx(struct stconn *cs);
void cs_update_tx(struct stconn *cs);

struct task *sc_conn_io_cb(struct task *t, void *ctx, unsigned int state);
int sc_conn_sync_recv(struct stconn *cs);
void sc_conn_sync_send(struct stconn *cs);


/* returns the channel which receives data from this stream connector (input channel) */
static inline struct channel *sc_ic(const struct stconn *cs)
{
	struct stream *strm = __sc_strm(cs);

	return ((cs->flags & SC_FL_ISBACK) ? &(strm->res) : &(strm->req));
}

/* returns the channel which feeds data to this stream connector (output channel) */
static inline struct channel *sc_oc(const struct stconn *cs)
{
	struct stream *strm = __sc_strm(cs);

	return ((cs->flags & SC_FL_ISBACK) ? &(strm->req) : &(strm->res));
}

/* returns the buffer which receives data from this stream connector (input channel's buffer) */
static inline struct buffer *sc_ib(const struct stconn *cs)
{
	return &sc_ic(cs)->buf;
}

/* returns the buffer which feeds data to this stream connector (output channel's buffer) */
static inline struct buffer *sc_ob(const struct stconn *cs)
{
	return &sc_oc(cs)->buf;
}
/* returns the stream's task associated to this stream connector */
static inline struct task *sc_strm_task(const struct stconn *cs)
{
	struct stream *strm = __sc_strm(cs);

	return strm->task;
}

/* returns the stream connector on the other side. Used during forwarding. */
static inline struct stconn *cs_opposite(const struct stconn *cs)
{
	struct stream *strm = __sc_strm(cs);

	return ((cs->flags & SC_FL_ISBACK) ? strm->scf : strm->scb);
}


/* to be called only when in SC_ST_DIS with SC_FL_ERR */
static inline void cs_report_error(struct stconn *cs)
{
	if (!__sc_strm(cs)->conn_err_type)
		__sc_strm(cs)->conn_err_type = STRM_ET_DATA_ERR;

	sc_oc(cs)->flags |= CF_WRITE_ERROR;
	sc_ic(cs)->flags |= CF_READ_ERROR;
}

/* sets the current and previous state of a stream connector to <state>. This is
 * mainly used to create one in the established state on incoming conncetions.
 */
static inline void cs_set_state(struct stconn *cs, int state)
{
	cs->state = __sc_strm(cs)->prev_conn_state = state;
}

/* returns a bit for a stream connector state, to match against SC_SB_* */
static inline enum cs_state_bit cs_state_bit(enum cs_state state)
{
	BUG_ON(state > SC_ST_CLO);
	return 1U << state;
}

/* returns true if <state> matches one of the SC_SB_* bits in <mask> */
static inline int cs_state_in(enum cs_state state, enum cs_state_bit mask)
{
	BUG_ON(mask & ~SC_SB_ALL);
	return !!(cs_state_bit(state) & mask);
}

/* Returns true if a connection is attached to the stream connector <cs> and if this
 * connection is ready.
 */
static inline int sc_conn_ready(const struct stconn *cs)
{
	const struct connection *conn = sc_conn(cs);

	return conn && conn_ctrl_ready(conn) && conn_xprt_ready(conn);
}


/* The stream connector is only responsible for the connection during the early
 * states, before plugging a mux. Thus it should only care about CO_FL_ERROR
 * before SC_ST_EST, and after that it must absolutely ignore it since the mux
 * may hold pending data. This function returns true if such an error was
 * reported. Both the CS and the CONN must be valid.
 */
static inline int cs_is_conn_error(const struct stconn *cs)
{
	const struct connection *conn;

	if (cs->state >= SC_ST_EST)
		return 0;

	conn = __sc_conn(cs);
	BUG_ON(!conn);
	return !!(conn->flags & CO_FL_ERROR);
}

/* Try to allocate a buffer for the stream connector's input channel. It relies on
 * channel_alloc_buffer() for this so it abides by its rules. It returns 0 on
 * failure, non-zero otherwise. If no buffer is available, the requester,
 * represented by the <wait> pointer, will be added in the list of objects
 * waiting for an available buffer, and SE_FL_RXBLK_BUFF will be set on the
 * stream connector and SE_FL_RX_WAIT_EP cleared. The requester will be responsible
 * for calling this function to try again once woken up.
 */
static inline int cs_alloc_ibuf(struct stconn *cs, struct buffer_wait *wait)
{
	int ret;

	ret = channel_alloc_buffer(sc_ic(cs), wait);
	if (!ret)
		sc_need_buff(cs);
	return ret;
}


/* Returns the source address of the stream connector and, if not set, fallbacks on
 * the session for frontend CS and the server connection for the backend CS. It
 * returns a const address on success or NULL on failure.
 */
static inline const struct sockaddr_storage *cs_src(const struct stconn *cs)
{
	if (cs->src)
		return cs->src;
	if (!(cs->flags & SC_FL_ISBACK))
		return sess_src(strm_sess(__sc_strm(cs)));
	else {
		struct connection *conn = sc_conn(cs);

		if (conn)
			return conn_src(conn);
	}
	return NULL;
}


/* Returns the destination address of the stream connector and, if not set, fallbacks
 * on the session for frontend CS and the server connection for the backend
 * CS. It returns a const address on success or NULL on failure.
 */
static inline const struct sockaddr_storage *cs_dst(const struct stconn *cs)
{
	if (cs->dst)
		return cs->dst;
	if (!(cs->flags & SC_FL_ISBACK))
		return sess_dst(strm_sess(__sc_strm(cs)));
	else {
		struct connection *conn = sc_conn(cs);

		if (conn)
			return conn_dst(conn);
	}
	return NULL;
}

/* Retrieves the source address of the stream connector. Returns non-zero on success
 * or zero on failure. The operation is only performed once and the address is
 * stored in the stream connector for future use. On the first call, the stream connector
 * source address is copied from the session one for frontend CS and the server
 * connection for the backend CS.
 */
static inline int cs_get_src(struct stconn *cs)
{
	const struct sockaddr_storage *src = NULL;

	if (cs->src)
		return 1;

	if (!(cs->flags & SC_FL_ISBACK))
		src = sess_src(strm_sess(__sc_strm(cs)));
	else {
		struct connection *conn = sc_conn(cs);

		if (conn)
			src = conn_src(conn);
	}
	if (!src)
		return 0;

	if (!sockaddr_alloc(&cs->src, src, sizeof(*src)))
		return 0;

	return 1;
}

/* Retrieves the destination address of the stream connector. Returns non-zero on
 * success or zero on failure. The operation is only performed once and the
 * address is stored in the stream connector for future use. On the first call, the
 * stream connector destination address is copied from the session one for frontend
 * CS and the server connection for the backend CS.
 */
static inline int cs_get_dst(struct stconn *cs)
{
	const struct sockaddr_storage *dst = NULL;

	if (cs->dst)
		return 1;

	if (!(cs->flags & SC_FL_ISBACK))
		dst = sess_dst(strm_sess(__sc_strm(cs)));
	else {
		struct connection *conn = sc_conn(cs);

		if (conn)
			dst = conn_dst(conn);
	}
	if (!dst)
		return 0;

	if (!sockaddr_alloc(&cs->dst, dst, sizeof(*dst)))
		return 0;

	return 1;
}


/* Marks on the stream connector that next shutw must kill the whole connection */
static inline void cs_must_kill_conn(struct stconn *cs)
{
	sc_ep_set(cs, SE_FL_KILL_CONN);
}


/* Sends a shutr to the endpoint using the data layer */
static inline void cs_shutr(struct stconn *cs)
{
	if (likely(cs->app_ops->shutr))
		cs->app_ops->shutr(cs);
}

/* Sends a shutw to the endpoint using the data layer */
static inline void cs_shutw(struct stconn *cs)
{
	if (likely(cs->app_ops->shutw))
		cs->app_ops->shutw(cs);
}

/* This is to be used after making some room available in a channel. It will
 * return without doing anything if the stream connector's RX path is blocked.
 * It will automatically mark the stream connector as busy processing the end
 * point in order to avoid useless repeated wakeups.
 * It will then call ->chk_rcv() to enable receipt of new data.
 */
static inline void cs_chk_rcv(struct stconn *cs)
{
	struct channel *ic = sc_ic(cs);

	if (sc_ep_test(cs, SE_FL_APPLET_NEED_CONN) &&
	    cs_state_in(cs_opposite(cs)->state, SC_SB_RDY|SC_SB_EST|SC_SB_DIS|SC_SB_CLO))
		sc_ep_clr(cs, SE_FL_APPLET_NEED_CONN);

	if (ic->flags & CF_SHUTR)
		return;

	if (sc_ep_test(cs, SE_FL_APPLET_NEED_CONN) ||
	    cs_rx_blocked(cs) || !cs_rx_endp_ready(cs))
		return;

	if (!cs_state_in(cs->state, SC_SB_RDY|SC_SB_EST))
		return;

	sc_ep_set(cs, SE_FL_RX_WAIT_EP);
	if (likely(cs->app_ops->chk_rcv))
		cs->app_ops->chk_rcv(cs);
}

/* Calls chk_snd on the endpoint using the data layer */
static inline void cs_chk_snd(struct stconn *cs)
{
	if (likely(cs->app_ops->chk_snd))
		cs->app_ops->chk_snd(cs);
}

/* Combines both cs_update_rx() and cs_update_tx() at once */
static inline void cs_update(struct stconn *cs)
{
	cs_update_rx(cs);
	cs_update_tx(cs);
}

/* for debugging, reports the stream connector state name */
static inline const char *cs_state_str(int state)
{
	switch (state) {
	case SC_ST_INI: return "INI";
	case SC_ST_REQ: return "REQ";
	case SC_ST_QUE: return "QUE";
	case SC_ST_TAR: return "TAR";
	case SC_ST_ASS: return "ASS";
	case SC_ST_CON: return "CON";
	case SC_ST_CER: return "CER";
	case SC_ST_RDY: return "RDY";
	case SC_ST_EST: return "EST";
	case SC_ST_DIS: return "DIS";
	case SC_ST_CLO: return "CLO";
	default:        return "???";
	}
}

/* indicates if the connector may send data to the endpoint, that is, the
 * endpoint is both willing to receive data and ready to do so. This is only
 * used with applets so there's always a stream attached to this connector.
 */
__attribute__((warn_unused_result))
static inline int sc_is_send_allowed(const struct stconn *sc)
{
	struct channel *oc = sc_oc(sc);

	if (oc->flags & CF_SHUTW)
		return 0;

	return cs_tx_endp_ready(sc) && !cs_tx_blocked(sc);
}

#endif /* _HAPROXY_CS_UTILS_H */
