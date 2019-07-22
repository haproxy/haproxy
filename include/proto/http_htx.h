/*
 * include/types/http_htx.h
 * This file defines function prototypes for HTTP manipulation using the
 * internal representation.
 *
 * Copyright (C) 2018 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
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

#ifndef _PROTO_HTTP_HTX_H
#define _PROTO_HTTP_HTX_H

#include <common/buf.h>
#include <common/ist.h>

#include <types/http_htx.h>

extern struct buffer http_err_chunks[HTTP_ERR_SIZE];

struct htx_sl *http_get_stline(struct htx *htx);
int http_find_header(const struct htx *htx, const struct ist name, struct http_hdr_ctx *ctx, int full);
int http_add_header(struct htx *htx, const struct ist n, const struct ist v);
int http_replace_stline(struct htx *htx, const struct ist p1, const struct ist p2, const struct ist p3);
int http_replace_req_meth(struct htx *htx, const struct ist meth);
int http_replace_req_uri(struct htx *htx, const struct ist uri);
int http_replace_req_path(struct htx *htx, const struct ist path);
int http_replace_req_query(struct htx *htx, const struct ist query);
int http_replace_res_status(struct htx *htx, const struct ist status);
int http_replace_res_reason(struct htx *htx, const struct ist reason);
int http_replace_header_value(struct htx *htx, struct http_hdr_ctx *ctx, const struct ist data);
int http_replace_header(struct htx *htx, struct http_hdr_ctx *ctx, const struct ist name, const struct ist value);
int http_remove_header(struct htx *htx, struct http_hdr_ctx *ctx);
unsigned int http_get_htx_hdr(const struct htx *htx, const struct ist hdr,
			      int occ, struct http_hdr_ctx *ctx, char **vptr, size_t *vlen);
unsigned int http_get_htx_fhdr(const struct htx *htx, const struct ist hdr,
			       int occ, struct http_hdr_ctx *ctx, char **vptr, size_t *vlen);
int http_str_to_htx(struct buffer *buf, struct ist raw);

#endif /* _PROTO_HTTP_HTX_H */
