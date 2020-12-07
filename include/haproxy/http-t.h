/*
 * include/haproxy/http-t.h
 *
 * Version-agnostic and implementation-agnostic HTTP protocol definitions.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_HTTP_T_H
#define _HAPROXY_HTTP_T_H

#include <inttypes.h>
#include <import/ist.h>
#include <haproxy/buf-t.h>

/*
 * some macros mainly used when parsing header fields.
 * from RFC7230:
 *   CTL                 = <any US-ASCII control character (octets 0 - 31) and DEL (127)>
 *   SEP                 = one of the 17 defined separators or SP or HT
 *   LWS                 = CR, LF, SP or HT
 *   SPHT                = SP or HT. Use this macro and not a boolean expression for best speed.
 *   CRLF                = CR or LF. Use this macro and not a boolean expression for best speed.
 *   token               = any CHAR except CTL or SEP. Use this macro and not a boolean expression for best speed.
 *
 * added for ease of use:
 *   ver_token           = 'H', 'P', 'T', '/', '.', and digits.
 */
#define HTTP_FLG_CTL  0x01
#define HTTP_FLG_SEP  0x02
#define HTTP_FLG_LWS  0x04
#define HTTP_FLG_SPHT 0x08
#define HTTP_FLG_CRLF 0x10
#define HTTP_FLG_TOK  0x20
#define HTTP_FLG_VER  0x40
#define HTTP_FLG_DIG  0x80

#define HTTP_IS_CTL(x)       (http_char_classes[(uint8_t)(x)] & HTTP_FLG_CTL)
#define HTTP_IS_SEP(x)       (http_char_classes[(uint8_t)(x)] & HTTP_FLG_SEP)
#define HTTP_IS_LWS(x)       (http_char_classes[(uint8_t)(x)] & HTTP_FLG_LWS)
#define HTTP_IS_SPHT(x)      (http_char_classes[(uint8_t)(x)] & HTTP_FLG_SPHT)
#define HTTP_IS_CRLF(x)      (http_char_classes[(uint8_t)(x)] & HTTP_FLG_CRLF)
#define HTTP_IS_TOKEN(x)     (http_char_classes[(uint8_t)(x)] & HTTP_FLG_TOK)
#define HTTP_IS_VER_TOKEN(x) (http_char_classes[(uint8_t)(x)] & HTTP_FLG_VER)
#define HTTP_IS_DIGIT(x)     (http_char_classes[(uint8_t)(x)] & HTTP_FLG_DIG)

/* Known HTTP methods */
enum http_meth_t {
	HTTP_METH_OPTIONS,
	HTTP_METH_GET,
	HTTP_METH_HEAD,
	HTTP_METH_POST,
	HTTP_METH_PUT,
	HTTP_METH_DELETE,
	HTTP_METH_TRACE,
	HTTP_METH_CONNECT,
	HTTP_METH_OTHER, /* Must be the last entry */
} __attribute__((packed));

/* Known HTTP authentication schemes */
enum ht_auth_m {
	HTTP_AUTH_WRONG		= -1,		/* missing or unknown */
	HTTP_AUTH_UNKNOWN	= 0,
	HTTP_AUTH_BASIC,
	HTTP_AUTH_DIGEST,
} __attribute__((packed));

/* All implemented HTTP status codes */
enum {
	HTTP_ERR_200 = 0,
	HTTP_ERR_400,
	HTTP_ERR_401,
	HTTP_ERR_403,
	HTTP_ERR_404,
	HTTP_ERR_405,
	HTTP_ERR_407,
	HTTP_ERR_408,
	HTTP_ERR_410,
	HTTP_ERR_413,
	HTTP_ERR_421,
	HTTP_ERR_425,
	HTTP_ERR_429,
	HTTP_ERR_500,
	HTTP_ERR_501,
	HTTP_ERR_502,
	HTTP_ERR_503,
	HTTP_ERR_504,
	HTTP_ERR_SIZE
};

/* Note: the strings below make use of chunks. Chunks may carry an allocated
 * size in addition to the length. The size counts from the beginning (str)
 * to the end. If the size is unknown, it MUST be zero, in which case the
 * sample will automatically be duplicated when a change larger than <len> has
 * to be performed. Thus it is safe to always set size to zero.
 */
struct http_meth {
	enum http_meth_t meth;
	struct buffer str;
};

struct http_auth_data {
	enum ht_auth_m method;                /* one of HTTP_AUTH_* */
	/* 7 bytes unused here */
	struct buffer method_data;            /* points to the creditial part from 'Authorization:' header */
	char *user, *pass;                    /* extracted username & password */
};

struct http_method_desc {
	enum http_meth_t meth;
	const struct ist text;
};

enum http_etag_type {
	ETAG_INVALID = 0,
	ETAG_STRONG,
	ETAG_WEAK
};

#endif /* _HAPROXY_HTTP_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
