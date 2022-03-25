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
#include <haproxy/conn_stream.h>

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


#endif /* _HAPROXY_CS_UTILS_H */
