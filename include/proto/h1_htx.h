/*
 * include/types/h1_htx.h
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

#ifndef _PROTO_H1_HTX_H
#define _PROTO_H1_HTX_H

#include <common/buf.h>
#include <common/ist.h>
#include <common/h1.h>

int h1_parse_msg_hdrs(struct h1m *h1m, union h1_sl *h1sl, struct htx *dsthtx,
		      struct buffer *srcbuf, size_t ofs, size_t max);
int h1_parse_msg_data(struct h1m *h1m, struct htx **dsthtx,
		      struct buffer *srcbuf, size_t ofs, size_t max,
		      struct buffer *htxbuf);
int h1_parse_msg_tlrs(struct h1m *h1m, struct htx *dsthtx,
		      struct buffer *srcbuf, size_t ofs, size_t max);

int h1_format_htx_reqline(const struct htx_sl *sl, struct buffer *chk);
int h1_format_htx_stline(const struct htx_sl *sl, struct buffer *chk);
int h1_format_htx_hdr(const struct ist n, const struct ist v, struct buffer *chk);
int h1_format_htx_data(const struct ist data, struct buffer *chk, int chunked);

#endif /* _PROTO_H1_HTX_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
