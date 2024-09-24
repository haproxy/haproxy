/*
 * include/haproxy/sc_strm.h
 * This file contains stream-specific stream-connector functions prototypes
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

#ifndef _HAPROXY_SC_STRM_H
#define _HAPROXY_SC_STRM_H

#include <haproxy/api.h>
#include <haproxy/buf-t.h>
#include <haproxy/channel-t.h>
#include <haproxy/stream-t.h>
#include <haproxy/task-t.h>
#include <haproxy/connection.h>
#include <haproxy/channel.h>
#include <haproxy/session.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>

void sc_update_rx(struct stconn *sc);
void sc_update_tx(struct stconn *sc);

struct task *sc_conn_io_cb(struct task *t, void *ctx, unsigned int state);
int sc_conn_sync_recv(struct stconn *sc);
void sc_conn_sync_send(struct stconn *sc);

int sc_applet_sync_recv(struct stconn *sc);
void sc_applet_sync_send(struct stconn *sc);

int sc_applet_sync_recv(struct stconn *sc);
void sc_applet_sync_send(struct stconn *sc);


/* returns the channel which receives data from this stream connector (input channel) */
static inline struct channel *sc_ic(const struct stconn *sc)
{
	struct stream *strm = __sc_strm(sc);

	return ((sc->flags & SC_FL_ISBACK) ? &(strm->res) : &(strm->req));
}

/* returns the channel which feeds data to this stream connector (output channel) */
static inline struct channel *sc_oc(const struct stconn *sc)
{
	struct stream *strm = __sc_strm(sc);

	return ((sc->flags & SC_FL_ISBACK) ? &(strm->req) : &(strm->res));
}

/* returns the buffer which receives data from this stream connector (input channel's buffer) */
static inline struct buffer *sc_ib(const struct stconn *sc)
{
	return &sc_ic(sc)->buf;
}

/* returns the buffer which feeds data to this stream connector (output channel's buffer) */
static inline struct buffer *sc_ob(const struct stconn *sc)
{
	return &sc_oc(sc)->buf;
}
/* returns the stream's task associated to this stream connector */
static inline struct task *sc_strm_task(const struct stconn *sc)
{
	struct stream *strm = __sc_strm(sc);

	return strm->task;
}

/* returns the stream connector on the other side. Used during forwarding. */
static inline struct stconn *sc_opposite(const struct stconn *sc)
{
	struct stream *strm = __sc_strm(sc);

	return ((sc->flags & SC_FL_ISBACK) ? strm->scf : strm->scb);
}


/* sets the current and previous state of a stream connector to <state>. This is
 * mainly used to create one in the established state on incoming connections.
 */
static inline void sc_set_state(struct stconn *sc, int state)
{
	sc->state = __sc_strm(sc)->prev_conn_state = state;
}

/* returns a bit for a stream connector state, to match against SC_SB_* */
static inline enum sc_state_bit sc_state_bit(enum sc_state state)
{
	BUG_ON(state > SC_ST_CLO);
	return 1U << state;
}

/* returns true if <state> matches one of the SC_SB_* bits in <mask> */
static inline int sc_state_in(enum sc_state state, enum sc_state_bit mask)
{
	BUG_ON(mask & ~SC_SB_ALL);
	return !!(sc_state_bit(state) & mask);
}

/* Returns true if a connection is attached to the stream connector <sc> and if this
 * connection is ready.
 */
static inline int sc_conn_ready(const struct stconn *sc)
{
	const struct connection *conn = sc_conn(sc);

	return conn && conn_ctrl_ready(conn) && conn_xprt_ready(conn);
}


/* The stream connector is only responsible for the connection during the early
 * states, before plugging a mux. Thus it should only care about CO_FL_ERROR
 * before SC_ST_EST, and after that it must absolutely ignore it since the mux
 * may hold pending data. This function returns true if such an error was
 * reported. Both the SC and the CONN must be valid.
 */
static inline int sc_is_conn_error(const struct stconn *sc)
{
	const struct connection *conn;

	if (sc->state >= SC_ST_EST)
		return 0;

	conn = __sc_conn(sc);
	BUG_ON(!conn);
	return !!(conn->flags & CO_FL_ERROR);
}

/* Try to allocate a buffer for the stream connector's input channel. It relies on
 * channel_alloc_buffer() for this so it abides by its rules. It returns 0 on
 * failure, non-zero otherwise. If no buffer is available, the requester,
 * represented by the <wait> pointer, will be added in the list of objects
 * waiting for an available buffer, and SC_FL_NEED_BUFF will be set on the
 * stream connector and SE_FL_HAVE_NO_DATA cleared. The requester will be responsible
 * for calling this function to try again once woken up.
 */
static inline int sc_alloc_ibuf(struct stconn *sc, struct buffer_wait *wait)
{
	int ret;

	ret = channel_alloc_buffer(sc_ic(sc), wait);
	if (ret)
		sc_used_buff(sc);
	else
		sc_need_buff(sc);

	return ret;
}


/* Returns the source address of the stream connector and, if not set, fallbacks on
 * the session for frontend SC and the server connection for the backend SC. It
 * returns a const address on success or NULL on failure.
 */
static inline const struct sockaddr_storage *sc_src(const struct stconn *sc)
{
	if (sc->src)
		return sc->src;
	if (!(sc->flags & SC_FL_ISBACK))
		return sess_src(strm_sess(__sc_strm(sc)));
	else {
		struct connection *conn = sc_conn(sc);

		if (conn)
			return conn_src(conn);
	}
	return NULL;
}


/* Returns the destination address of the stream connector and, if not set, fallbacks
 * on the session for frontend SC and the server connection for the backend
 * SC. It returns a const address on success or NULL on failure.
 */
static inline const struct sockaddr_storage *sc_dst(const struct stconn *sc)
{
	if (sc->dst)
		return sc->dst;
	if (!(sc->flags & SC_FL_ISBACK))
		return sess_dst(strm_sess(__sc_strm(sc)));
	else {
		struct connection *conn = sc_conn(sc);

		if (conn)
			return conn_dst(conn);
	}
	return NULL;
}

/* Retrieves the source address of the stream connector. Returns non-zero on success
 * or zero on failure. The operation is only performed once and the address is
 * stored in the stream connector for future use. On the first call, the stream connector
 * source address is copied from the session one for frontend SC and the server
 * connection for the backend SC.
 */
static inline int sc_get_src(struct stconn *sc)
{
	const struct sockaddr_storage *src = NULL;

	if (sc->src)
		return 1;

	if (!(sc->flags & SC_FL_ISBACK))
		src = sess_src(strm_sess(__sc_strm(sc)));
	else {
		struct connection *conn = sc_conn(sc);

		if (conn)
			src = conn_src(conn);
	}
	if (!src)
		return 0;

	if (!sockaddr_alloc(&sc->src, src, sizeof(*src)))
		return 0;

	return 1;
}

/* Retrieves the destination address of the stream connector. Returns non-zero on
 * success or zero on failure. The operation is only performed once and the
 * address is stored in the stream connector for future use. On the first call, the
 * stream connector destination address is copied from the session one for frontend
 * SC and the server connection for the backend SC.
 */
static inline int sc_get_dst(struct stconn *sc)
{
	const struct sockaddr_storage *dst = NULL;

	if (sc->dst)
		return 1;

	if (!(sc->flags & SC_FL_ISBACK))
		dst = sess_dst(strm_sess(__sc_strm(sc)));
	else {
		struct connection *conn = sc_conn(sc);

		if (conn)
			dst = conn_dst(conn);
	}
	if (!dst)
		return 0;

	if (!sockaddr_alloc(&sc->dst, dst, sizeof(*dst)))
		return 0;

	return 1;
}


/* Marks on the stream connector that next shutdown must kill the whole connection */
static inline void sc_must_kill_conn(struct stconn *sc)
{
	sc_ep_set(sc, SE_FL_KILL_CONN);
}


/* Returns non-zero if the stream connector is allowed to receive from the
 * endpoint, which means that no flag indicating a blocked channel, lack of
 * buffer or room is set, and that the endpoint is not waiting for the
 * application to complete a connection setup on the other side, and that
 * the stream's channel is not shut for reads. This is only used by stream
 * applications.
 */
__attribute__((warn_unused_result))
static inline int sc_is_recv_allowed(const struct stconn *sc)
{
	if (sc->flags & (SC_FL_ABRT_DONE|SC_FL_EOS))
		return 0;

	if (sc_ep_test(sc, SE_FL_APPLET_NEED_CONN))
		return 0;

	if (sc_ep_test(sc, SE_FL_HAVE_NO_DATA))
		return 0;

	if (sc_ep_test(sc, SE_FL_MAY_FASTFWD_PROD) && (sc_opposite(sc)->sedesc->iobuf.flags & IOBUF_FL_FF_BLOCKED))
		return 0;

	return !(sc->flags & (SC_FL_WONT_READ|SC_FL_NEED_BUFF|SC_FL_NEED_ROOM));
}

/* This is to be used after making some room available in a channel. It will
 * return without doing anything if the stream connector's RX path is blocked.
 * It will automatically mark the stream connector as busy processing the end
 * point in order to avoid useless repeated wakeups.
 * It will then call ->chk_rcv() to enable receipt of new data.
 */
static inline void sc_chk_rcv(struct stconn *sc)
{
	if (sc_ep_test(sc, SE_FL_APPLET_NEED_CONN) &&
	    sc_state_in(sc_opposite(sc)->state, SC_SB_RDY|SC_SB_EST|SC_SB_DIS|SC_SB_CLO)) {
		sc_ep_clr(sc, SE_FL_APPLET_NEED_CONN);
		sc_ep_report_read_activity(sc);
	}

	if (!sc_is_recv_allowed(sc))
		return;

	if (!sc_state_in(sc->state, SC_SB_RDY|SC_SB_EST))
		return;

	sc_ep_set(sc, SE_FL_HAVE_NO_DATA);
	if (likely(sc->app_ops->chk_rcv))
		sc->app_ops->chk_rcv(sc);
}

/* Calls chk_snd on the endpoint using the data layer */
static inline void sc_chk_snd(struct stconn *sc)
{
	if (likely(sc->app_ops->chk_snd))
		sc->app_ops->chk_snd(sc);
}


/* Perform a synchronous receive using the right version, depending the endpoing
 * is a connection or an applet.
 */
static inline int sc_sync_recv(struct stconn *sc)
{
	if (sc_ep_test(sc, SE_FL_T_MUX))
		return sc_conn_sync_recv(sc);
	else if (sc_ep_test(sc, SE_FL_T_APPLET))
		return sc_applet_sync_recv(sc);
	return 0;
}

/* Perform a synchronous send using the right version, depending the endpoing is
 * a connection or an applet.
 */
static inline void sc_sync_send(struct stconn *sc)
{
	if (sc_ep_test(sc, SE_FL_T_MUX))
		sc_conn_sync_send(sc);
	else if (sc_ep_test(sc, SE_FL_T_APPLET)) {
		sc_applet_sync_send(sc);
		if (sc_oc(sc)->flags & CF_WRITE_EVENT) {
			/* Data was send, wake the applet up. It is safe to do so becasuse sc_applet_sync_send()
			 * removes CF_WRITE_EVENT flag from the channel before trying to send data to the applet.
			 */
			task_wakeup(__sc_appctx(sc)->t, TASK_WOKEN_OTHER);
		}
	}
}

/* Combines both sc_update_rx() and sc_update_tx() at once */
static inline void sc_update(struct stconn *sc)
{
	sc_update_rx(sc);
	sc_update_tx(sc);
}

/* for debugging, reports the stream connector state name */
static inline const char *sc_state_str(int state)
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
	if (sc->flags & SC_FL_SHUT_DONE)
		return 0;

	return !sc_ep_test(sc, SE_FL_WAIT_DATA | SE_FL_WONT_CONSUME);
}

static inline int sc_rcv_may_expire(const struct stconn *sc)
{
	if ((sc->flags & (SC_FL_ABRT_DONE|SC_FL_EOS)) || (sc_ic(sc)->flags & CF_READ_TIMEOUT))
		return 0;
	if (sc->flags & (SC_FL_EOI|SC_FL_WONT_READ|SC_FL_NEED_BUFF|SC_FL_NEED_ROOM))
		return 0;
	if (sc_ep_test(sc, SE_FL_APPLET_NEED_CONN) || sc_ep_test(sc_opposite(sc), SE_FL_EXP_NO_DATA))
		return 0;
	return 1;
}

static inline int sc_snd_may_expire(const struct stconn *sc)
{
	if ((sc->flags & SC_FL_SHUT_DONE) || (sc_oc(sc)->flags & CF_WRITE_TIMEOUT))
		return 0;
	if (sc_ep_test(sc, SE_FL_WONT_CONSUME))
		return 0;
	return 1;
}

static forceinline int sc_ep_rcv_ex(const struct stconn *sc)
{
	return ((tick_isset(sc->sedesc->lra) && sc_rcv_may_expire(sc))
		? tick_add_ifset(sc->sedesc->lra, sc->ioto)
		: TICK_ETERNITY);
}

static forceinline int sc_ep_snd_ex(const struct stconn *sc)
{
	return ((tick_isset(sc->sedesc->fsb) && sc_snd_may_expire(sc))
		? tick_add_ifset(sc->sedesc->fsb, sc->ioto)
		: TICK_ETERNITY);
}

static inline void sc_check_timeouts(const struct stconn *sc)
{
	if (unlikely(tick_is_expired(sc_ep_rcv_ex(sc), now_ms)))
		sc_ic(sc)->flags |= CF_READ_TIMEOUT;
	if (unlikely(tick_is_expired(sc_ep_snd_ex(sc), now_ms)))
		sc_oc(sc)->flags |= CF_WRITE_TIMEOUT;
}

static inline void sc_set_hcto(struct stconn *sc)
{
	struct stream *strm = __sc_strm(sc);

	if (IS_HTX_STRM(strm))
		return;

	if (sc->flags & SC_FL_ISBACK) {
		if ((strm->flags & SF_BE_ASSIGNED) && tick_isset(strm->be->timeout.serverfin))
			sc->ioto = strm->be->timeout.serverfin;
	}
	else {
		if (tick_isset(strm_fe(strm)->timeout.clientfin))
			sc->ioto = strm_fe(strm)->timeout.clientfin;
	}

}

/* Schedule an abort for the SC */
static inline void sc_schedule_abort(struct stconn *sc)
{
	sc->flags |= SC_FL_ABRT_WANTED;
}

/* Abort the SC and notify the endpoint using the data layer */
static inline void sc_abort(struct stconn *sc)
{
	if (likely(sc->app_ops->abort))
		sc->app_ops->abort(sc);
}

/* Schedule a shutdown for the SC */
static inline void sc_schedule_shutdown(struct stconn *sc)
{
	sc->flags |= SC_FL_SHUT_WANTED;
}

/* Shutdown the SC and notify the endpoint using the data layer */
static inline void sc_shutdown(struct stconn *sc)
{
	if (likely(sc->app_ops->shutdown))
		sc->app_ops->shutdown(sc);
}

#endif /* _HAPROXY_SC_STRM_H */
