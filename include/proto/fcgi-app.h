/*
 * include/proto/fcgi-app.h
 * This file defines function prototypes for FCGI applications.
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

#ifndef _PROTO_HTTP_FCGI_H
#define _PROTO_HTTP_FCGI_H

#include <common/htx.h>

#include <types/fcgi-app.h>
#include <types/proxy.h>
#include <types/stream.h>

struct fcgi_app *fcgi_app_find_by_name(const char *name);
struct fcgi_flt_conf *find_px_fcgi_conf(struct proxy *px);
struct fcgi_flt_ctx *find_strm_fcgi_ctx(struct stream *s);
struct fcgi_app *get_px_fcgi_app(struct proxy *px);
struct fcgi_app *get_strm_fcgi_app(struct stream *s);

#endif /* _PROTO_HTTP_FCGI_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
