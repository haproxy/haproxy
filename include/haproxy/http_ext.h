/*
 * include/haproxy/http_ext.h
 * Functions for Version-agnostic and implementation-agnostic HTTP extensions
 *
 * Copyright 2022 HAProxy Technologies
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

#ifndef _HAPROXY_HTTPEXT_H
#define _HAPROXY_HTTPEXT_H

#include <haproxy/http_ext-t.h>
#include <haproxy/channel-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/stream-t.h>

int http_validate_7239_header(struct ist hdr, int required_steps, struct forwarded_header_ctx *ctx);

int http_handle_7239_header(struct stream *s, struct channel *req);
int http_handle_xff_header(struct stream *s, struct channel *req);
int http_handle_xot_header(struct stream *s, struct channel *req);

void http_ext_7239_clean(struct http_ext_7239 *);
void http_ext_xff_clean(struct http_ext_xff *);
void http_ext_xot_clean(struct http_ext_xot *);

void http_ext_7239_copy(struct http_ext_7239 *dest, const struct http_ext_7239 *orig);
void http_ext_xff_copy(struct http_ext_xff *dest, const struct http_ext_xff *orig);
void http_ext_xot_copy(struct http_ext_xot *dest, const struct http_ext_xot *orig);

int proxy_http_parse_7239(char **args, int cur_arg, struct proxy *curproxy, const struct proxy *defpx, const char *file, int linenum);
int proxy_http_compile_7239(struct proxy *curproxy);
int proxy_http_parse_xff(char **args, int cur_arg, struct proxy *curproxy, const struct proxy *defpx, const char *file, int linenum);
int proxy_http_parse_xot(char **args, int cur_arg, struct proxy *curproxy, const struct proxy *defpx, const char *file, int linenum);

#endif /* !_HAPROXY_HTTPEXT_H */
