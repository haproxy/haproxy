/*
 * include/haproxy/http_htx-t.h
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

#ifndef _HAPROXY_HTTP_HTX_H
#define _HAPROXY_HTTP_HTX_H

#include <import/ist.h>
#include <haproxy/buf-t.h>
#include <haproxy/http-hdr-t.h>
#include <haproxy/http_htx-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/regex-t.h>

extern struct buffer http_err_chunks[HTTP_ERR_SIZE];
extern struct http_reply http_err_replies[HTTP_ERR_SIZE];
extern struct list http_errors_list;

struct htx_sl *http_get_stline(const struct htx *htx);
size_t http_get_hdrs_size(struct htx *htx);
int http_find_header(const struct htx *htx, const struct ist name, struct http_hdr_ctx *ctx, int full);
int http_find_str_header(const struct htx *htx, const struct ist name, struct http_hdr_ctx *ctx, int full);
int http_find_pfx_header(const struct htx *htx, const struct ist prefix, struct http_hdr_ctx *ctx, int full);
int http_find_sfx_header(const struct htx *htx, const struct ist suffix, struct http_hdr_ctx *ctx, int full);
int http_find_sub_header(const struct htx *htx, const struct ist sub, struct http_hdr_ctx *ctx, int full);
int http_match_header(const struct htx *htx, const struct my_regex *re, struct http_hdr_ctx *ctx, int full);
int http_add_header(struct htx *htx, const struct ist n, const struct ist v);
int http_replace_stline(struct htx *htx, const struct ist p1, const struct ist p2, const struct ist p3);
int http_replace_req_meth(struct htx *htx, const struct ist meth);
int http_replace_req_uri(struct htx *htx, const struct ist uri);
int http_replace_req_path(struct htx *htx, const struct ist path, int with_qs);
int http_replace_req_query(struct htx *htx, const struct ist query);
int http_replace_res_status(struct htx *htx, const struct ist status, const struct ist reason);
int http_replace_res_reason(struct htx *htx, const struct ist reason);
int http_append_header_value(struct htx *htx, struct http_hdr_ctx *ctx, const struct ist data);
int http_prepend_header_value(struct htx *htx, struct http_hdr_ctx *ctx, const struct ist data);
int http_replace_header_value(struct htx *htx, struct http_hdr_ctx *ctx, const struct ist data);
int http_replace_header(struct htx *htx, struct http_hdr_ctx *ctx, const struct ist name, const struct ist value);
int http_remove_header(struct htx *htx, struct http_hdr_ctx *ctx);
int http_update_authority(struct htx *htx, struct htx_sl *sl, const struct ist host);
int http_update_host(struct htx *htx, struct htx_sl *sl, const struct ist uri);

unsigned int http_get_htx_hdr(const struct htx *htx, const struct ist hdr,
			      int occ, struct http_hdr_ctx *ctx, char **vptr, size_t *vlen);
unsigned int http_get_htx_fhdr(const struct htx *htx, const struct ist hdr,
			       int occ, struct http_hdr_ctx *ctx, char **vptr, size_t *vlen);
int http_str_to_htx(struct buffer *buf, struct ist raw, char **errmsg);

void release_http_reply(struct http_reply *http_reply);
int http_check_http_reply(struct http_reply *reply, struct proxy*px, char **errmsg);
struct http_reply *http_parse_http_reply(const char **args, int *orig_arg, struct proxy *px,
					 int default_status, char **errmsg);

int http_scheme_based_normalize(struct htx *htx);

void http_cookie_register(struct http_hdr *list, int idx, int *first, int *last);
int http_cookie_merge(struct htx *htx, struct http_hdr *list, int first);

struct buffer *http_load_errorfile(const char *file, char **errmsg);
struct buffer *http_load_errormsg(const char *key, const struct ist msg, char **errmsg);
struct buffer *http_parse_errorfile(int status, const char *file, char **errmsg);
struct buffer *http_parse_errorloc(int errloc, int status, const char *url, char **errmsg);
int proxy_dup_default_conf_errors(struct proxy *curpx, const struct proxy *defpx, char **errmsg);
void proxy_release_conf_errors(struct proxy *px);

#endif /* _HAPROXY_HTTP_HTX_H */
