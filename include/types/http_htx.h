/*
 * include/types/http_htx.h
 * This file defines everything related to HTTP manipulation using the internal
 * representation.
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

#ifndef _TYPES_HTTP_HTX_H
#define _TYPES_HTTP_HTX_H

#include <common/htx.h>
#include <common/ist.h>

/* Context used to find/remove an HTTP header. */
struct http_hdr_ctx {
	struct htx_blk *blk;
	struct ist     value;
	uint16_t       lws_before;
	uint16_t       lws_after;
};

#endif /* _TYPES_HTTP_HTX_H */
