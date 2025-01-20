/*
 * include/haproxy/stconn.h
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

#ifndef _HAPROXY_STCONN_H
#define _HAPROXY_STCONN_H

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/htx-t.h>
#include <haproxy/obj_type.h>
#include <haproxy/stconn-t.h>
#include <haproxy/xref.h>

struct buffer;
struct session;
struct appctx;
struct stream;
struct check;

#define IS_HTX_SC(sc)     ((sc_conn(sc) && IS_HTX_CONN(__sc_conn(sc))) || (sc_appctx(sc) && IS_HTX_STRM(__sc_strm(sc))))

struct sedesc *sedesc_new();
void sedesc_free(struct sedesc *sedesc);

void se_shutdown(struct sedesc *sedesc, enum se_shut_mode mode);

struct stconn *sc_new_from_endp(struct sedesc *sedesc, struct session *sess, struct buffer *input);
struct stconn *sc_new_from_strm(struct stream *strm, unsigned int flags);
struct stconn *sc_new_from_check(struct check *check, unsigned int flags);
void sc_free(struct stconn *sc);

int sc_attach_mux(struct stconn *sc, void *target, void *ctx);
int sc_attach_strm(struct stconn *sc, struct stream *strm);

void sc_destroy(struct stconn *sc);
int sc_reset_endp(struct stconn *sc);

struct appctx *sc_applet_create(struct stconn *sc, struct applet *app);

void sc_conn_prepare_endp_upgrade(struct stconn *sc);
void sc_conn_abort_endp_upgrade(struct stconn *sc);
void sc_conn_commit_endp_upgrade(struct stconn *sc);

/* The se_fl_*() set of functions manipulate the stream endpoint flags from
 * the stream endpoint itself. The sc_ep_*() set of functions manipulate the
 * stream endpoint flags from the the stream connector (ex. stconn).
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

/* sets flags <on> on se->flags and handles ERR_PENDING to ERROR promotion if
 * needed (upon EOI/EOS).
 */
static forceinline void se_fl_set(struct sedesc *se, uint on)
{
	if (((on & (SE_FL_EOS|SE_FL_EOI)) && se->flags & SE_FL_ERR_PENDING) ||
	    ((on & SE_FL_ERR_PENDING) && se->flags & (SE_FL_EOI|SE_FL_EOS)))
		on |= SE_FL_ERROR;
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
	if (se_fl_test(se, (SE_FL_EOS|SE_FL_EOI)))
		se_fl_set(se, SE_FL_ERROR);
	else
		se_fl_set(se, SE_FL_ERR_PENDING);
}

static inline void se_expect_no_data(struct sedesc *se)
{
	se_fl_set(se, SE_FL_EXP_NO_DATA);
}

static inline void se_expect_data(struct sedesc *se)
{
	se_fl_clr(se, SE_FL_EXP_NO_DATA);
}

static inline unsigned int se_have_ff_data(struct sedesc *se)
{
	return (se->iobuf.data | (long)se->iobuf.pipe);
}

static inline size_t se_ff_data(struct sedesc *se)
{
	return (se->iobuf.data + (se->iobuf.pipe ? se->iobuf.pipe->data : 0));
}


static inline struct sedesc *se_opposite(struct sedesc *se)
{
	struct xref *peer = xref_get_peer_and_lock(&se->xref);
	struct sedesc *seo = NULL;;

	if (peer) {
		seo = container_of(peer, struct sedesc, xref);
		xref_unlock(&se->xref, peer);
	}
	return seo;
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

/* Return the last read activity timestamp. May be TICK_ETERNITY */
static forceinline unsigned int sc_ep_lra(const struct stconn *sc)
{
	return sc->sedesc->lra;
}

/* Return the first send blocked timestamp. May be TICK_ETERNITY */
static forceinline unsigned int sc_ep_fsb(const struct stconn *sc)
{
	return sc->sedesc->fsb;
}

/* Report a read activity. This function sets <lra> to now_ms */
static forceinline void sc_ep_report_read_activity(struct stconn *sc)
{
	sc->sedesc->lra = now_ms;
}

/* Report a send blocked. This function sets <fsb> to now_ms if it was not
 * already set or if something was sent (to renew <fsb>).
 *
 * if something was sent (<did_send> != 0), a read activity is also reported for
 * non-independent stream.
 */
static forceinline void sc_ep_report_blocked_send(struct stconn *sc, int did_send)
{
	if (did_send || !tick_isset(sc->sedesc->fsb)) {
		sc->sedesc->fsb = now_ms;
		if (did_send && !(sc->flags & SC_FL_INDEP_STR))
			sc_ep_report_read_activity(sc);
	}
}

/* Report a send activity by setting <fsb> to TICK_ETERNITY.
 * For non-independent stream, a read activity is reported.
 */
static forceinline void sc_ep_report_send_activity(struct stconn *sc)
{
	sc->sedesc->fsb = TICK_ETERNITY;
	if (!(sc->flags & SC_FL_INDEP_STR))
		sc_ep_report_read_activity(sc);
}

static forceinline unsigned int sc_ep_have_ff_data(struct stconn *sc)
{
	return se_have_ff_data(sc->sedesc);
}

static forceinline size_t sc_ep_ff_data(struct stconn *sc)
{
	return se_ff_data(sc->sedesc);
}

/* Returns the stream endpoint from an connector, without any control */
static inline void *__sc_endp(const struct stconn *sc)
{
	return sc->sedesc->se;
}

/* Returns the connection from a sc if the endpoint is a mux stream. Otherwise
 * NULL is returned. __sc_conn() returns the connection without any control
 * while sc_conn() check the endpoint type.
 */
static inline struct connection *__sc_conn(const struct stconn *sc)
{
	return sc->sedesc->conn;
}
static inline struct connection *sc_conn(const struct stconn *sc)
{
	if (sc_ep_test(sc, SE_FL_T_MUX))
		return __sc_conn(sc);
	return NULL;
}

/* Returns the mux ops of the connection from an stconn if the endpoint is a
 * mux stream. Otherwise NULL is returned.
 */
static inline const struct mux_ops *sc_mux_ops(const struct stconn *sc)
{
	const struct connection *conn = sc_conn(sc);

	return (conn ? conn->mux : NULL);
}

/* Returns a pointer to the mux stream from a connector if the endpoint is
 * a mux. Otherwise NULL is returned. __sc_mux_strm() returns the mux without
 * any control while sc_mux_strm() checks the endpoint type.
 */
static inline void *__sc_mux_strm(const struct stconn *sc)
{
	return __sc_endp(sc);
}
static inline void *sc_mux_strm(const struct stconn *sc)
{
	if (sc_ep_test(sc, SE_FL_T_MUX))
		return __sc_mux_strm(sc);
	return NULL;
}

/* Returns the appctx from a sc if the endpoint is an appctx. Otherwise
 * NULL is returned. __sc_appctx() returns the appctx without any control
 * while sc_appctx() checks the endpoint type.
 */
static inline struct appctx *__sc_appctx(const struct stconn *sc)
{
	return __sc_endp(sc);
}
static inline struct appctx *sc_appctx(const struct stconn *sc)
{
	if (sc_ep_test(sc, SE_FL_T_APPLET))
		return __sc_appctx(sc);
	return NULL;
}

/* Returns the stream from a sc if the application is a stream. Otherwise
 * NULL is returned. __sc_strm() returns the stream without any control
 * while sc_strm() check the application type.
 */
static inline struct stream *__sc_strm(const struct stconn *sc)
{
	return __objt_stream(sc->app);
}

static inline struct stream *sc_strm(const struct stconn *sc)
{
	if (obj_type(sc->app) == OBJ_TYPE_STREAM)
		return __sc_strm(sc);
	return NULL;
}

/* Returns the healthcheck from a sc if the application is a
 * healthcheck. Otherwise NULL is returned. __sc_check() returns the healthcheck
 * without any control while sc_check() check the application type.
 */
static inline struct check *__sc_check(const struct stconn *sc)
{
	return __objt_check(sc->app);
}
static inline struct check *sc_check(const struct stconn *sc)
{
	if (obj_type(sc->app) == OBJ_TYPE_CHECK)
		return __objt_check(sc->app);
	return NULL;
}

/* Returns the name of the application layer's name for the stconn,
 * or "NONE" when none is attached.
 */
static inline const char *sc_get_data_name(const struct stconn *sc)
{
	if (!sc->app_ops)
		return "NONE";
	return sc->app_ops->name;
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
 * receive data from the endpoint. A read activity is reported.
 */
static inline void sc_will_read(struct stconn *sc)
{
	if (sc->flags & SC_FL_WONT_READ) {
		sc->flags &= ~SC_FL_WONT_READ;
		sc_ep_report_read_activity(sc);
	}
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
 * buffer it was waiting for. A read activity is reported. The SC_FL_HAVE_BUFF
 * flag is set and held until sc_used_buff() is called to indicate it was
 * used.
 */
static inline void sc_have_buff(struct stconn *sc)
{
	if (sc->flags & SC_FL_NEED_BUFF) {
		sc->flags &= ~SC_FL_NEED_BUFF;
		sc->flags |=  SC_FL_HAVE_BUFF;
		sc_ep_report_read_activity(sc);
	}
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

/* The stream connector indicates that it has successfully allocated the buffer
 * it was previously waiting for so it drops the SC_FL_HAVE_BUFF bit.
 */
static inline void sc_used_buff(struct stconn *sc)
{
	sc->flags &= ~SC_FL_HAVE_BUFF;
}

/* Tell a stream connector some room was made in the input buffer and any
 * failed attempt to inject data into it may be tried again. This is usually
 * called after a successful transfer of buffer contents to the other side.
 *  A read activity is reported.
 */
static inline void sc_have_room(struct stconn *sc)
{
	if (sc->flags & SC_FL_NEED_ROOM) {
		sc->flags &= ~SC_FL_NEED_ROOM;
		sc->room_needed = 0;
		sc_ep_report_read_activity(sc);
	}
}

/* The stream connector announces it failed to put data into the input buffer
 * by lack of room. Since it indicates a willingness to deliver data to the
 * buffer that will have to be retried. Usually the caller will also clear
 * SE_FL_HAVE_NO_DATA to be called again as soon as SC_FL_NEED_ROOM is cleared.
 *
 * The caller is responsible to specified the amount of free space required to
 * progress. It must take care to not exceed the buffer size.
 */
static inline void sc_need_room(struct stconn *sc, ssize_t room_needed)
{
	sc->flags |= SC_FL_NEED_ROOM;
	BUG_ON_HOT(room_needed > (ssize_t)global.tune.bufsize);
	sc->room_needed = room_needed;
}

/* The stream endpoint indicates that it's ready to consume data from the
 * stream's output buffer. Report a send activity if the SE is unblocked.
 */
static inline void se_will_consume(struct sedesc *se)
{
	if (se_fl_test(se, SE_FL_WONT_CONSUME)) {
		se_fl_clr(se, SE_FL_WONT_CONSUME);
		sc_ep_report_send_activity(se->sc);
	}
}

/* The stream endpoint indicates that it's not willing to consume data from the
 * stream's output buffer.
 */
static inline void se_wont_consume(struct sedesc *se)
{
	se_fl_set(se, SE_FL_WONT_CONSUME);
}

/* The stream endpoint indicates that it's willing to consume data from the
 * stream's output buffer, but that there's not enough, so it doesn't want to
 * be woken up until more are presented.
 */
static inline void se_need_more_data(struct sedesc *se)
{
	se_will_consume(se);
	se_fl_set(se, SE_FL_WAIT_DATA);
}


static inline size_t se_nego_ff(struct sedesc *se, struct buffer *input, size_t count, unsigned int flags)
{
	size_t ret = 0;

	if (se_fl_test(se, SE_FL_T_MUX)) {
		const struct mux_ops *mux = se->conn->mux;

		se->iobuf.flags &= ~(IOBUF_FL_FF_BLOCKED|IOBUF_FL_FF_WANT_ROOM);
		if (mux->nego_fastfwd && mux->done_fastfwd) {
			/* Disable zero-copy forwarding if an error was reported. */
			if (se_fl_test(se, SE_FL_ERROR|SE_FL_ERR_PENDING)) {
				se->iobuf.flags |= IOBUF_FL_NO_FF;
				goto end;
			}

			ret = mux->nego_fastfwd(se->sc, input, count, flags);
			if (se->iobuf.flags & IOBUF_FL_FF_BLOCKED) {
				sc_ep_report_blocked_send(se->sc, 0);

				if (!(se->sc->wait_event.events & SUB_RETRY_SEND)) {
					/* The SC must be subs for send to be notify when some
					 * space is made
					 */
					mux->subscribe(se->sc, SUB_RETRY_SEND, &se->sc->wait_event);
				}
			}
			goto end;
		}
	}
	se->iobuf.flags |= IOBUF_FL_NO_FF;

  end:
	return ret;
}

/* Returns the number of bytes forwarded. May be 0 if nothing is forwarded. It
 * may also be 0 if there is nothing to forward. Note it is not dependent on
 * data in the buffer but only on the amount of data to forward.
 */
static inline size_t se_done_ff(struct sedesc *se)
{
	size_t ret = 0;

	if (se_fl_test(se, SE_FL_T_MUX)) {
		const struct mux_ops *mux = se->conn->mux;
		size_t to_send = se_ff_data(se);

		BUG_ON(!mux->done_fastfwd);
		ret = mux->done_fastfwd(se->sc);
		if (ret) {
			/* Something was forwarded, unblock the zero-copy forwarding.
			 * If all data was sent, report and send activity.
			 * Otherwise report a conditional blocked send.
			 */
			se->iobuf.flags &= ~IOBUF_FL_FF_BLOCKED;
			if (ret == to_send)
				sc_ep_report_send_activity(se->sc);
			else
				sc_ep_report_blocked_send(se->sc, 1);
		}
		else {
			/* Nothing was forwarded. If there was something to forward,
			 * it means the sends are blocked.
			 * In addition, if the zero-copy forwarding is blocked because the
			 * producer requests more room, we must subs for sends.
			 */
			if (to_send)
				sc_ep_report_blocked_send(se->sc, 0);
			if (se->iobuf.flags & IOBUF_FL_FF_BLOCKED) {
				sc_ep_report_blocked_send(se->sc, 0);

				if (!(se->sc->wait_event.events & SUB_RETRY_SEND)) {
					/* The SC must be subs for send to be notify when some
					 * space is made
					 */
					mux->subscribe(se->sc, SUB_RETRY_SEND, &se->sc->wait_event);
				}
			}
		}
	}

	return ret;
}

static inline void se_report_term_evt(struct sedesc *se, enum se_term_event_type type)
{
	enum term_event_loc loc = tevt_loc_se;

	if (se->sc && se->sc->flags & SC_FL_ISBACK)
		loc += 8;
	se->term_evts_log = tevt_report_event(se->term_evts_log, loc, type);
}

static inline void sc_report_term_evt(struct stconn *sc, enum strm_term_event_type type)
{
	enum term_event_loc loc = tevt_loc_strm;

	if (sc->flags & SC_FL_ISBACK)
		loc += 8;
	sc->term_evts_log = tevt_report_event(sc->term_evts_log, loc, type);
	if (sc_strm(sc))
		__sc_strm(sc)->term_evts_log = tevt_report_event(__sc_strm(sc)->term_evts_log, loc, type);
}

#endif /* _HAPROXY_STCONN_H */
