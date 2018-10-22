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

#include <types/h1.h>
#include <types/http_htx.h>

union h1_sl http_find_stline(const struct htx *htx);
int http_find_header(const struct htx *htx, const struct ist name, struct http_hdr_ctx *ctx, int full);
int http_add_header(struct htx *htx, const struct ist n, const struct ist v);
int http_replace_reqline(struct htx *htx, const union h1_sl sl);
int http_replace_resline(struct htx *htx, const union h1_sl sl);
int http_replace_header_value(struct htx *htx, struct http_hdr_ctx *ctx, const struct ist data);
int http_replace_header(struct htx *htx, struct http_hdr_ctx *ctx, const struct ist name, const struct ist value);
int http_remove_header(struct htx *htx, struct http_hdr_ctx *ctx);

#endif /* _PROTO_HTTP_HTX_H */
