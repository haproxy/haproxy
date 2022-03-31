/*
 * include/haproxy/cs_utils.h
 * This file contains conn-stream util functions prototypes
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
#include <haproxy/session.h>
#include <haproxy/stream.h>

/* returns the channel which receives data from this conn-stream (input channel) */
static inline struct channel *cs_ic(struct conn_stream *cs)
{
	struct stream *strm = __cs_strm(cs);

	return ((cs->flags & CS_FL_ISBACK) ? &(strm->res) : &(strm->req));
}

/* returns the channel which feeds data to this conn-stream (output channel) */
static inline struct channel *cs_oc(struct conn_stream *cs)
{
	struct stream *strm = __cs_strm(cs);

	return ((cs->flags & CS_FL_ISBACK) ? &(strm->req) : &(strm->res));
}

/* returns the buffer which receives data from this conn-stream (input channel's buffer) */
static inline struct buffer *cs_ib(struct conn_stream *cs)
{
	return &cs_ic(cs)->buf;
}

/* returns the buffer which feeds data to this conn-stream (output channel's buffer) */
static inline struct buffer *cs_ob(struct conn_stream *cs)
{
	return &cs_oc(cs)->buf;
}
/* returns the stream's task associated to this conn-stream */
static inline struct task *cs_strm_task(struct conn_stream *cs)
{
	struct stream *strm = __cs_strm(cs);

	return strm->task;
}

/* returns the conn-stream on the other side. Used during forwarding. */
static inline struct conn_stream *cs_opposite(struct conn_stream *cs)
{
	struct stream *strm = __cs_strm(cs);

	return ((cs->flags & CS_FL_ISBACK) ? strm->csf : strm->csb);
}


/* to be called only when in CS_ST_DIS with CS_FL_ERR */
static inline void cs_report_error(struct conn_stream *cs)
{
	if (!__cs_strm(cs)->conn_err_type)
		__cs_strm(cs)->conn_err_type = STRM_ET_DATA_ERR;

	cs_oc(cs)->flags |= CF_WRITE_ERROR;
	cs_ic(cs)->flags |= CF_READ_ERROR;
}

/* sets the current and previous state of a conn-stream to <state>. This is
 * mainly used to create one in the established state on incoming conncetions.
 */
static inline void cs_set_state(struct conn_stream *cs, int state)
{
	cs->state = __cs_strm(cs)->prev_conn_state = state;
}

/* returns a bit for a conn-stream state, to match against CS_SB_* */
static inline enum cs_state_bit cs_state_bit(enum cs_state state)
{
	BUG_ON(state > CS_ST_CLO);
	return 1U << state;
}

/* returns true if <state> matches one of the CS_SB_* bits in <mask> */
static inline int cs_state_in(enum cs_state state, enum cs_state_bit mask)
{
	BUG_ON(mask & ~CS_SB_ALL);
	return !!(cs_state_bit(state) & mask);
}

/* Returns the source address of the conn-stream and, if not set, fallbacks on
 * the session for frontend CS and the server connection for the backend CS. It
 * returns a const address on success or NULL on failure.
 */
static inline const struct sockaddr_storage *cs_src(struct conn_stream *cs)
{
	if (cs->flags & CS_FL_ADDR_FROM_SET)
		return cs->src;
	if (!(cs->flags & CS_FL_ISBACK))
		return sess_src(strm_sess(__cs_strm(cs)));
	else {
		struct connection *conn = cs_conn(cs);

		if (conn)
			return conn_src(conn);
	}
	return NULL;
}


/* Returns the destination address of the conn-stream and, if not set, fallbacks
 * on the session for frontend CS and the server connection for the backend
 * CS. It returns a const address on success or NULL on failure.
 */
static inline const struct sockaddr_storage *cs_dst(struct conn_stream *cs)
{
	if (cs->flags & CS_FL_ADDR_TO_SET)
		return cs->dst;
	if (!(cs->flags & CS_FL_ISBACK))
		return sess_dst(strm_sess(__cs_strm(cs)));
	else {
		struct connection *conn = cs_conn(cs);

		if (conn)
			return conn_dst(conn);
	}
	return NULL;
}

/* Retrieves the source address of the conn-stream. Returns non-zero on success
 * or zero on failure. The operation is only performed once and the address is
 * stored in the conn-stream for future use. On the first call, the conn-stream
 * source address is copied from the session one for frontend CS and the server
 * connection for the backend CS.
 */
static inline int cs_get_src(struct conn_stream *cs)
{
	const struct sockaddr_storage *src = NULL;

	if (cs->flags & CS_FL_ADDR_FROM_SET)
		return 1;

	if (!(cs->flags & CS_FL_ISBACK))
		src = sess_src(strm_sess(__cs_strm(cs)));
	else {
		struct connection *conn = cs_conn(cs);

		if (conn)
			src = conn_src(conn);
	}
	if (!src)
		return 0;

	if (!sockaddr_alloc(&cs->src, src, sizeof(*src)))
		return 0;

	cs->flags |= CS_FL_ADDR_FROM_SET;
	return 1;
}

/* Retrieves the destination address of the conn-stream. Returns non-zero on
 * success or zero on failure. The operation is only performed once and the
 * address is stored in the conn-stream for future use. On the first call, the
 * conn-stream destination address is copied from the session one for frontend
 * CS and the server connection for the backend CS.
 */
static inline int cs_get_dst(struct conn_stream *cs)
{
	const struct sockaddr_storage *dst = NULL;

	if (cs->flags & CS_FL_ADDR_TO_SET)
		return 1;

	if (!(cs->flags & CS_FL_ISBACK))
		dst = sess_dst(strm_sess(__cs_strm(cs)));
	else {
		struct connection *conn = cs_conn(cs);

		if (conn)
			dst = conn_dst(conn);
	}
	if (!dst)
		return 0;

	if (!sockaddr_alloc(&cs->dst, dst, sizeof(*dst)))
		return 0;

	cs->flags |= CS_FL_ADDR_TO_SET;
	return 1;
}


/* Marks on the conn-stream that next shutw must kill the whole connection */
static inline void cs_must_kill_conn(struct conn_stream *cs)
{
	cs->endp->flags |= CS_EP_KILL_CONN;
}

/* for debugging, reports the stream interface state name */
static inline const char *cs_state_str(int state)
{
	switch (state) {
	case CS_ST_INI: return "INI";
	case CS_ST_REQ: return "REQ";
	case CS_ST_QUE: return "QUE";
	case CS_ST_TAR: return "TAR";
	case CS_ST_ASS: return "ASS";
	case CS_ST_CON: return "CON";
	case CS_ST_CER: return "CER";
	case CS_ST_RDY: return "RDY";
	case CS_ST_EST: return "EST";
	case CS_ST_DIS: return "DIS";
	case CS_ST_CLO: return "CLO";
	default:        return "???";
	}
}

#endif /* _HAPROXY_CS_UTILS_H */
