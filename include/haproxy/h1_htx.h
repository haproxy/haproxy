/*
 * include/haproxy/h1_htx.h
 * This file defines function prototypes for H1 manipulation using the
 * internal representation.
 *
 * Copyright (C) 2019 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
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

#ifndef _HAPROXY_H1_HTX_H
#define _HAPROXY_H1_HTX_H

#include <import/ist.h>
#include <haproxy/api-t.h>
#include <haproxy/buf-t.h>
#include <haproxy/h1.h>
#include <haproxy/htx.h>

int h1_parse_msg_hdrs(struct h1m *h1m, union h1_sl *h1sl, struct htx *dsthtx,
		      struct buffer *srcbuf, size_t ofs, size_t max);
int h1_parse_msg_data(struct h1m *h1m, struct htx **dsthtx,
		      struct buffer *srcbuf, size_t ofs, size_t max,
		      struct buffer *htxbuf);
int h1_parse_msg_tlrs(struct h1m *h1m, struct htx *dsthtx,
		      struct buffer *srcbuf, size_t ofs, size_t max);

/* Returns the URI of an HTX message in the most common format for a H1 peer. It
 * is the path part of an absolute URI when the URI was normalized, ortherwise
 * it is the whole URI, as received. Concretely, it is only a special case for
 * URIs received from H2 clients, to be able to send a relative path the H1
 * servers.
 */
static inline struct ist h1_get_uri(const struct htx_sl *sl)
{
	struct ist uri;

	uri = htx_sl_req_uri(sl);
	if (sl->flags & HTX_SL_F_NORMALIZED_URI) {
		uri = http_get_path(uri);
		if (unlikely(!uri.len)) {
			if (sl->info.req.meth == HTTP_METH_OPTIONS)
				uri = ist("*");
			else
				uri = ist("/");
		}
	}
	return uri;
}

int h1_format_htx_reqline(const struct htx_sl *sl, struct buffer *chk);
int h1_format_htx_stline(const struct htx_sl *sl, struct buffer *chk);
int h1_format_htx_hdr(const struct ist n, const struct ist v, struct buffer *chk);
int h1_format_htx_data(const struct ist data, struct buffer *chk, int chunked);

#endif /* _HAPROXY_H1_HTX_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
