/*
 * include/haproxy/conn_stream.h
 * This file contains stream connector function prototypes
 *
 * Copyright 2021 Christopher Faulet <cfaulet@haproxy.com>
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

#ifndef _HAPROXY_CONN_STREAM_H
#define _HAPROXY_CONN_STREAM_H

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/conn_stream-t.h>
#include <haproxy/obj_type.h>

struct buffer;
struct session;
struct appctx;
struct stream;
struct check;

#define IS_HTX_CS(cs)     (cs_conn(cs) && IS_HTX_CONN(__cs_conn(cs)))

struct sedesc *sedesc_new();
void sedesc_free(struct sedesc *sedesc);

struct stconn *cs_new_from_endp(struct sedesc *sedesc, struct session *sess, struct buffer *input);
struct stconn *cs_new_from_strm(struct stream *strm, unsigned int flags);
struct stconn *cs_new_from_check(struct check *check, unsigned int flags);
void cs_free(struct stconn *cs);

int cs_attach_mux(struct stconn *cs, void *target, void *ctx);
int cs_attach_strm(struct stconn *cs, struct stream *strm);

void cs_destroy(struct stconn *cs);
int cs_reset_endp(struct stconn *cs);

struct appctx *cs_applet_create(struct stconn *cs, struct applet *app);

/* The se_fl_*() set of functions manipulate the stream endpoint flags from
 * the stream endpoint itself. The sc_ep_*() set of functions manipulate the
 * stream endpoint flags from the the stream connector (ex. conn_stream).
 * _zero() clears all flags, _clr() clears a set of flags (&=~), _set() sets
 * a set of flags (|=), _test() tests the presence of a set of flags, _get()
 * retrieves the exact flags, _setall() replaces the flags with the new value.
 * All functions are purposely marked "forceinline" to avoid slowing down
 * debugging code too much. None of these functions is atomic-safe.
 */

/* stream endpoint version */
static forceinline void se_fl_zero(struct sedesc *se)
{
	se->flags = 0;
}

static forceinline void se_fl_setall(struct sedesc *se, uint all)
{
	se->flags = all;
}

static forceinline void se_fl_set(struct sedesc *se, uint on)
{
	se->flags |= on;
}

static forceinline void se_fl_clr(struct sedesc *se, uint off)
{
	se->flags &= ~off;
}

static forceinline uint se_fl_test(const struct sedesc *se, uint test)
{
	return !!(se->flags & test);
}

static forceinline uint se_fl_get(const struct sedesc *se)
{
	return se->flags;
}

/* stream connector version */
static forceinline void sc_ep_zero(struct stconn *sc)
{
	se_fl_zero(sc->sedesc);
}

static forceinline void sc_ep_setall(struct stconn *sc, uint all)
{
	se_fl_setall(sc->sedesc, all);
}

static forceinline void sc_ep_set(struct stconn *sc, uint on)
{
	se_fl_set(sc->sedesc, on);
}

static forceinline void sc_ep_clr(struct stconn *sc, uint off)
{
	se_fl_clr(sc->sedesc, off);
}

static forceinline uint sc_ep_test(const struct stconn *sc, uint test)
{
	return se_fl_test(sc->sedesc, test);
}

static forceinline uint sc_ep_get(const struct stconn *sc)
{
	return se_fl_get(sc->sedesc);
}


/* Returns the endpoint target without any control */
static inline void *__cs_endp_target(const struct stconn *cs)
{
	return cs->sedesc->se;
}

/* Returns the connection from a cs if the endpoint is a mux stream. Otherwise
 * NULL is returned. __cs_conn() returns the connection without any control
 * while cs_conn() check the endpoint type.
 */
static inline struct connection *__cs_conn(const struct stconn *cs)
{
	return cs->sedesc->conn;
}
static inline struct connection *cs_conn(const struct stconn *cs)
{
	if (sc_ep_test(cs, SE_FL_T_MUX))
		return __cs_conn(cs);
	return NULL;
}

/* Returns the mux ops of the connection from a cs if the endpoint is a
 * mux stream. Otherwise NULL is returned.
 */
static inline const struct mux_ops *cs_conn_mux(const struct stconn *cs)
{
	const struct connection *conn = cs_conn(cs);

	return (conn ? conn->mux : NULL);
}

/* Returns the mux from a cs if the endpoint is a mux. Otherwise
 * NULL is returned. __cs_mux() returns the mux without any control
 * while cs_mux() check the endpoint type.
 */
static inline void *__cs_mux(const struct stconn *cs)
{
	return __cs_endp_target(cs);
}
static inline struct appctx *cs_mux(const struct stconn *cs)
{
	if (sc_ep_test(cs, SE_FL_T_MUX))
		return __cs_mux(cs);
	return NULL;
}

/* Returns the appctx from a cs if the endpoint is an appctx. Otherwise
 * NULL is returned. __cs_appctx() returns the appctx without any control
 * while cs_appctx() check the endpoint type.
 */
static inline struct appctx *__cs_appctx(const struct stconn *cs)
{
	return __cs_endp_target(cs);
}
static inline struct appctx *cs_appctx(const struct stconn *cs)
{
	if (sc_ep_test(cs, SE_FL_T_APPLET))
		return __cs_appctx(cs);
	return NULL;
}

/* Returns the stream from a cs if the application is a stream. Otherwise
 * NULL is returned. __cs_strm() returns the stream without any control
 * while cs_strm() check the application type.
 */
static inline struct stream *__cs_strm(const struct stconn *cs)
{
	return __objt_stream(cs->app);
}

static inline struct stream *cs_strm(const struct stconn *cs)
{
	if (obj_type(cs->app) == OBJ_TYPE_STREAM)
		return __cs_strm(cs);
	return NULL;
}

/* Returns the healthcheck from a cs if the application is a
 * healthcheck. Otherwise NULL is returned. __cs_check() returns the healthcheck
 * without any control while cs_check() check the application type.
 */
static inline struct check *__cs_check(const struct stconn *cs)
{
	return __objt_check(cs->app);
}
static inline struct check *cs_check(const struct stconn *cs)
{
	if (obj_type(cs->app) == OBJ_TYPE_CHECK)
		return __objt_check(cs->app);
	return NULL;
}
static inline const char *cs_get_data_name(const struct stconn *cs)
{
	if (!cs->app_ops)
		return "NONE";
	return cs->app_ops->name;
}

/* shut read */
static inline void cs_conn_shutr(struct stconn *cs, enum co_shr_mode mode)
{
	const struct mux_ops *mux;

	BUG_ON(!cs_conn(cs));

	if (sc_ep_test(cs, SE_FL_SHR))
		return;

	/* clean data-layer shutdown */
	mux = cs_conn_mux(cs);
	if (mux && mux->shutr)
		mux->shutr(cs, mode);
	sc_ep_set(cs, (mode == CO_SHR_DRAIN) ? SE_FL_SHRD : SE_FL_SHRR);
}

/* shut write */
static inline void cs_conn_shutw(struct stconn *cs, enum co_shw_mode mode)
{
	const struct mux_ops *mux;

	BUG_ON(!cs_conn(cs));

	if (sc_ep_test(cs, SE_FL_SHW))
		return;

	/* clean data-layer shutdown */
	mux = cs_conn_mux(cs);
	if (mux && mux->shutw)
		mux->shutw(cs, mode);
	sc_ep_set(cs, (mode == CO_SHW_NORMAL) ? SE_FL_SHWN : SE_FL_SHWS);
}

/* completely close a stream connector (but do not detach it) */
static inline void cs_conn_shut(struct stconn *cs)
{
	cs_conn_shutw(cs, CO_SHW_SILENT);
	cs_conn_shutr(cs, CO_SHR_RESET);
}

/* completely close a stream connector after draining possibly pending data (but do not detach it) */
static inline void cs_conn_drain_and_shut(struct stconn *cs)
{
	cs_conn_shutw(cs, CO_SHW_SILENT);
	cs_conn_shutr(cs, CO_SHR_DRAIN);
}

/* sets SE_FL_ERROR or SE_FL_ERR_PENDING on the endpoint */
static inline void cs_ep_set_error(struct sedesc *endp)
{
	if (se_fl_test(endp, SE_FL_EOS))
		se_fl_set(endp, SE_FL_ERROR);
	else
		se_fl_set(endp, SE_FL_ERR_PENDING);
}

/* Retrieves any valid stream connector from this connection, preferably the first
 * valid one. The purpose is to be able to figure one other end of a private
 * connection for purposes like source binding or proxy protocol header
 * emission. In such cases, any stream connector is expected to be valid so the
 * mux is encouraged to return the first one it finds. If the connection has
 * no mux or the mux has no get_first_cs() method or the mux has no valid
 * stream connector, NULL is returned. The output pointer is purposely marked
 * const to discourage the caller from modifying anything there.
 */
static inline struct stconn *cs_conn_get_first(const struct connection *conn)
{
	BUG_ON(!conn || !conn->mux);

	if (!conn->mux->get_first_cs)
		return NULL;
	return conn->mux->get_first_cs(conn);
}


/* Returns non-zero if the stream connector's Rx path is blocked */
static inline int cs_rx_blocked(const struct stconn *cs)
{
	return !!sc_ep_test(cs, SE_FL_RXBLK_ANY);
}


/* Returns non-zero if the stream connector's Rx path is blocked because of lack
 * of room in the input buffer.
 */
static inline int cs_rx_blocked_room(const struct stconn *cs)
{
	return !!sc_ep_test(cs, SE_FL_RXBLK_ROOM);
}

/* Returns non-zero if the stream connector's endpoint is ready to receive */
static inline int cs_rx_endp_ready(const struct stconn *cs)
{
	return !sc_ep_test(cs, SE_FL_RX_WAIT_EP);
}

/* The stream connector announces it is ready to try to deliver more data to the input buffer */
static inline void cs_rx_endp_more(struct stconn *cs)
{
	sc_ep_clr(cs, SE_FL_RX_WAIT_EP);
}

/* The stream connector announces it doesn't have more data for the input buffer */
static inline void cs_rx_endp_done(struct stconn *cs)
{
	sc_ep_set(cs, SE_FL_RX_WAIT_EP);
}

/* Tell a stream connector the input channel is OK with it sending it some data */
static inline void cs_rx_chan_rdy(struct stconn *cs)
{
	sc_ep_clr(cs, SE_FL_RXBLK_CHAN);
}

/* Tell a stream connector the input channel is not OK with it sending it some data */
static inline void cs_rx_chan_blk(struct stconn *cs)
{
	sc_ep_set(cs, SE_FL_RXBLK_CHAN);
}

/* Tell a stream connector the other side is connected */
static inline void cs_rx_conn_rdy(struct stconn *cs)
{
	sc_ep_clr(cs, SE_FL_RXBLK_CONN);
}

/* Tell a stream connector it must wait for the other side to connect */
static inline void cs_rx_conn_blk(struct stconn *cs)
{
	sc_ep_set(cs, SE_FL_RXBLK_CONN);
}

/* The stream connector just got the input buffer it was waiting for */
static inline void cs_rx_buff_rdy(struct stconn *cs)
{
	sc_ep_clr(cs, SE_FL_RXBLK_BUFF);
}

/* The stream connector failed to get an input buffer and is waiting for it.
 * Since it indicates a willingness to deliver data to the buffer that will
 * have to be retried, we automatically clear RXBLK_ENDP to be called again
 * as soon as RXBLK_BUFF is cleared.
 */
static inline void cs_rx_buff_blk(struct stconn *cs)
{
	sc_ep_set(cs, SE_FL_RXBLK_BUFF);
}

/* Tell a stream connector some room was made in the input buffer */
static inline void cs_rx_room_rdy(struct stconn *cs)
{
	sc_ep_clr(cs, SE_FL_RXBLK_ROOM);
}

/* The stream connector announces it failed to put data into the input buffer
 * by lack of room. Since it indicates a willingness to deliver data to the
 * buffer that will have to be retried, we automatically clear RXBLK_ENDP to
 * be called again as soon as RXBLK_ROOM is cleared.
 */
static inline void cs_rx_room_blk(struct stconn *cs)
{
	sc_ep_set(cs, SE_FL_RXBLK_ROOM);
}

/* The stream connector announces it will never put new data into the input
 * buffer and that it's not waiting for its endpoint to deliver anything else.
 * This function obviously doesn't have a _rdy equivalent.
 */
static inline void cs_rx_shut_blk(struct stconn *cs)
{
	sc_ep_set(cs, SE_FL_RXBLK_SHUT);
}

/* Returns non-zero if the stream connector's Tx path is blocked */
static inline int cs_tx_blocked(const struct stconn *cs)
{
	return !!sc_ep_test(cs, SE_FL_WAIT_DATA);
}

/* Returns non-zero if the stream connector's endpoint is ready to transmit */
static inline int cs_tx_endp_ready(const struct stconn *cs)
{
	return sc_ep_test(cs, SE_FL_WANT_GET);
}

/* Report that a stream connector wants to get some data from the output buffer */
static inline void cs_want_get(struct stconn *cs)
{
	sc_ep_set(cs, SE_FL_WANT_GET);
}

/* Report that a stream connector failed to get some data from the output buffer */
static inline void cs_cant_get(struct stconn *cs)
{
	sc_ep_set(cs, SE_FL_WANT_GET | SE_FL_WAIT_DATA);
}

/* Report that a stream connector doesn't want to get data from the output buffer */
static inline void cs_stop_get(struct stconn *cs)
{
	sc_ep_clr(cs, SE_FL_WANT_GET);
}

/* Report that a stream connector won't get any more data from the output buffer */
static inline void cs_done_get(struct stconn *cs)
{
	sc_ep_clr(cs, SE_FL_WANT_GET | SE_FL_WAIT_DATA);
}

#endif /* _HAPROXY_CONN_STREAM_H */
