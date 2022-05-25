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

#define IS_HTX_CS(cs)     (sc_conn(cs) && IS_HTX_CONN(__sc_conn(cs)))

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

/* sets SE_FL_ERROR or SE_FL_ERR_PENDING on the endpoint */
static inline void se_fl_set_error(struct sedesc *se)
{
	if (se_fl_test(se, SE_FL_EOS))
		se_fl_set(se, SE_FL_ERROR);
	else
		se_fl_set(se, SE_FL_ERR_PENDING);
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


/* Returns the stream endpoint from an connector, without any control */
static inline void *__sc_endp(const struct stconn *cs)
{
	return cs->sedesc->se;
}

/* Returns the connection from a cs if the endpoint is a mux stream. Otherwise
 * NULL is returned. __sc_conn() returns the connection without any control
 * while sc_conn() check the endpoint type.
 */
static inline struct connection *__sc_conn(const struct stconn *cs)
{
	return cs->sedesc->conn;
}
static inline struct connection *sc_conn(const struct stconn *cs)
{
	if (sc_ep_test(cs, SE_FL_T_MUX))
		return __sc_conn(cs);
	return NULL;
}

/* Returns the mux ops of the connection from an stconn if the endpoint is a
 * mux stream. Otherwise NULL is returned.
 */
static inline const struct mux_ops *sc_mux_ops(const struct stconn *cs)
{
	const struct connection *conn = sc_conn(cs);

	return (conn ? conn->mux : NULL);
}

/* Returns a pointer to the mux stream from a connector if the endpoint is
 * a mux. Otherwise NULL is returned. __sc_mux_strm() returns the mux without
 * any control while sc_mux_strm() checks the endpoint type.
 */
static inline void *__sc_mux_strm(const struct stconn *cs)
{
	return __sc_endp(cs);
}
static inline struct appctx *sc_mux_strm(const struct stconn *cs)
{
	if (sc_ep_test(cs, SE_FL_T_MUX))
		return __sc_mux_strm(cs);
	return NULL;
}

/* Returns the appctx from a cs if the endpoint is an appctx. Otherwise
 * NULL is returned. __sc_appctx() returns the appctx without any control
 * while sc_appctx() checks the endpoint type.
 */
static inline struct appctx *__sc_appctx(const struct stconn *cs)
{
	return __sc_endp(cs);
}
static inline struct appctx *sc_appctx(const struct stconn *cs)
{
	if (sc_ep_test(cs, SE_FL_T_APPLET))
		return __sc_appctx(cs);
	return NULL;
}

/* Returns the stream from a cs if the application is a stream. Otherwise
 * NULL is returned. __sc_strm() returns the stream without any control
 * while sc_strm() check the application type.
 */
static inline struct stream *__sc_strm(const struct stconn *cs)
{
	return __objt_stream(cs->app);
}

static inline struct stream *sc_strm(const struct stconn *cs)
{
	if (obj_type(cs->app) == OBJ_TYPE_STREAM)
		return __sc_strm(cs);
	return NULL;
}

/* Returns the healthcheck from a cs if the application is a
 * healthcheck. Otherwise NULL is returned. __sc_check() returns the healthcheck
 * without any control while sc_check() check the application type.
 */
static inline struct check *__sc_check(const struct stconn *cs)
{
	return __objt_check(cs->app);
}
static inline struct check *sc_check(const struct stconn *cs)
{
	if (obj_type(cs->app) == OBJ_TYPE_CHECK)
		return __objt_check(cs->app);
	return NULL;
}

/* Returns the name of the application layer's name for the stconn,
 * or "NONE" when none is attached.
 */
static inline const char *sc_get_data_name(const struct stconn *cs)
{
	if (!cs->app_ops)
		return "NONE";
	return cs->app_ops->name;
}

/* shut read */
static inline void sc_conn_shutr(struct stconn *cs, enum co_shr_mode mode)
{
	const struct mux_ops *mux;

	BUG_ON(!sc_conn(cs));

	if (sc_ep_test(cs, SE_FL_SHR))
		return;

	/* clean data-layer shutdown */
	mux = sc_mux_ops(cs);
	if (mux && mux->shutr)
		mux->shutr(cs, mode);
	sc_ep_set(cs, (mode == CO_SHR_DRAIN) ? SE_FL_SHRD : SE_FL_SHRR);
}

/* shut write */
static inline void sc_conn_shutw(struct stconn *cs, enum co_shw_mode mode)
{
	const struct mux_ops *mux;

	BUG_ON(!sc_conn(cs));

	if (sc_ep_test(cs, SE_FL_SHW))
		return;

	/* clean data-layer shutdown */
	mux = sc_mux_ops(cs);
	if (mux && mux->shutw)
		mux->shutw(cs, mode);
	sc_ep_set(cs, (mode == CO_SHW_NORMAL) ? SE_FL_SHWN : SE_FL_SHWS);
}

/* completely close a stream connector (but do not detach it) */
static inline void sc_conn_shut(struct stconn *cs)
{
	sc_conn_shutw(cs, CO_SHW_SILENT);
	sc_conn_shutr(cs, CO_SHR_RESET);
}

/* completely close a stream connector after draining possibly pending data (but do not detach it) */
static inline void sc_conn_drain_and_shut(struct stconn *cs)
{
	sc_conn_shutw(cs, CO_SHW_SILENT);
	sc_conn_shutr(cs, CO_SHR_DRAIN);
}

/* Returns non-zero if the stream connector's Rx path is blocked because of
 * lack of room in the input buffer. This usually happens after applets failed
 * to deliver data into the channel's buffer and reported it via sc_need_room().
 */
__attribute__((warn_unused_result))
static inline int sc_waiting_room(const struct stconn *sc)
{
	return !!(sc->flags & SC_FL_NEED_ROOM);
}

/* The stream endpoint announces it has more data to deliver to the stream's
 * input buffer.
 */
static inline void se_have_more_data(struct sedesc *se)
{
	se_fl_clr(se, SE_FL_HAVE_NO_DATA);
}

/* The stream endpoint announces it doesn't have more data for the stream's
 * input buffer.
 */
static inline void se_have_no_more_data(struct sedesc *se)
{
	se_fl_set(se, SE_FL_HAVE_NO_DATA);
}

/* The application layer informs a stream connector that it's willing to
 * receive data from the endpoint.
 */
static inline void sc_will_read(struct stconn *sc)
{
	sc->flags &= ~SC_FL_WONT_READ;
}

/* The application layer informs a stream connector that it will not receive
 * data from the endpoint (e.g. need to flush, bw limitations etc). Usually
 * it corresponds to the channel's CF_DONT_READ flag.
 */
static inline void sc_wont_read(struct stconn *sc)
{
	sc->flags |= SC_FL_WONT_READ;
}

/* An frontend (applet) stream endpoint tells the connector it needs the other
 * side to connect or fail before continuing to work. This is used for example
 * to allow an applet not to deliver data to a request channel before a
 * connection is confirmed.
 */
static inline void se_need_remote_conn(struct sedesc *se)
{
	se_fl_set(se, SE_FL_APPLET_NEED_CONN);
}

/* The application layer tells the stream connector that it just got the input
 * buffer it was waiting for.
 */
static inline void sc_have_buff(struct stconn *sc)
{
	sc->flags &= ~SC_FL_NEED_BUFF;
}

/* The stream connector failed to get an input buffer and is waiting for it.
 * It indicates a willingness to deliver data to the buffer that will have to
 * be retried. As such, callers will often automatically clear SE_FL_HAVE_NO_DATA
 * to be called again as soon as SC_FL_NEED_BUFF is cleared.
 */
static inline void sc_need_buff(struct stconn *sc)
{
	sc->flags |= SC_FL_NEED_BUFF;
}

/* Tell a stream connector some room was made in the input buffer and any
 * failed attempt to inject data into it may be tried again. This is usually
 * called after a successful transfer of buffer contents to the other side.
 */
static inline void sc_have_room(struct stconn *sc)
{
	sc->flags &= ~SC_FL_NEED_ROOM;
}

/* The stream connector announces it failed to put data into the input buffer
 * by lack of room. Since it indicates a willingness to deliver data to the
 * buffer that will have to be retried. Usually the caller will also clear
 * SE_FL_HAVE_NO_DATA to be called again as soon as SC_FL_NEED_ROOM is cleared.
 */
static inline void sc_need_room(struct stconn *sc)
{
	sc->flags |= SC_FL_NEED_ROOM;
}

/* Report that a stream connector wants to get some data from the output buffer */
static inline void cs_want_get(struct stconn *cs)
{
	sc_ep_set(cs, SE_FL_WILL_CONSUME);
}

/* Report that a stream connector failed to get some data from the output buffer */
static inline void cs_cant_get(struct stconn *cs)
{
	sc_ep_set(cs, SE_FL_WILL_CONSUME | SE_FL_WAIT_DATA);
}

/* Report that a stream connector doesn't want to get data from the output buffer */
static inline void cs_stop_get(struct stconn *cs)
{
	sc_ep_clr(cs, SE_FL_WILL_CONSUME);
}

#endif /* _HAPROXY_CONN_STREAM_H */
