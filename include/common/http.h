/*
 * include/common/http.h
 *
 * Version-agnostic and implementation-agnostic HTTP protocol definitions.
 *
 * Copyright (C) 2000-2018 Willy Tarreau - w@1wt.eu
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

#ifndef _COMMON_HTTP_H
#define _COMMON_HTTP_H

#include <common/buf.h>
#include <common/ist.h>

/*
 * some macros mainly used when parsing header fileds.
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
	HTTP_ERR_403,
	HTTP_ERR_405,
	HTTP_ERR_408,
	HTTP_ERR_421,
	HTTP_ERR_425,
	HTTP_ERR_429,
	HTTP_ERR_500,
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

extern const int http_err_codes[HTTP_ERR_SIZE];
extern const char *http_err_msgs[HTTP_ERR_SIZE];
extern const struct ist http_known_methods[HTTP_METH_OTHER];
extern const uint8_t http_char_classes[256];

extern const struct ist HTTP_100;
extern const struct ist HTTP_103;
extern const char *HTTP_301;
extern const char *HTTP_302;
extern const char *HTTP_303;
extern const char *HTTP_307;
extern const char *HTTP_308;
extern const char *HTTP_401_fmt;
extern const char *HTTP_407_fmt;

enum http_meth_t find_http_meth(const char *str, const int len);
int http_get_status_idx(unsigned int status);
const char *http_get_reason(unsigned int status);
struct ist http_get_authority(const struct ist uri, int no_userinfo);
struct ist http_get_path(const struct ist uri);
int http_header_match2(const char *hdr, const char *end,
                       const char *name, int len);
char *http_find_hdr_value_end(char *s, const char *e);
char *http_find_cookie_value_end(char *s, const char *e);
char *http_extract_cookie_value(char *hdr, const char *hdr_end,
                                char *cookie_name, size_t cookie_name_l,
                                int list, char **value, size_t *value_l);
int http_parse_qvalue(const char *qvalue, const char **end);
const char *http_find_url_param_pos(const char **chunks,
                                    const char* url_param_name,
                                    size_t url_param_name_l, char delim);
int http_find_next_url_param(const char **chunks,
                             const char* url_param_name, size_t url_param_name_l,
                             const char **vstart, const char **vend, char delim);

int http_parse_header(const struct ist hdr, struct ist *name, struct ist *value);
int http_parse_stline(const struct ist line, struct ist *p1, struct ist *p2, struct ist *p3);
int http_parse_status_val(const struct ist value, struct ist *status, struct ist *reason);

/*
 * Given a path string and its length, find the position of beginning of the
 * query string. Returns NULL if no query string is found in the path.
 *
 * Example: if path = "/foo/bar/fubar?yo=mama;ye=daddy", and n = 22:
 *
 * find_query_string(path, n, '?') points to "yo=mama;ye=daddy" string.
 */
static inline char *http_find_param_list(char *path, size_t path_l, char delim)
{
	char *p;

	p = memchr(path, delim, path_l);
	return p ? p + 1 : NULL;
}

static inline int http_is_param_delimiter(char c, char delim)
{
	return c == '&' || c == ';' || c == delim;
}

/* Match language range with language tag. RFC2616 14.4:
 *
 *    A language-range matches a language-tag if it exactly equals
 *    the tag, or if it exactly equals a prefix of the tag such
 *    that the first tag character following the prefix is "-".
 *
 * Return 1 if the strings match, else return 0.
 */
static inline int http_language_range_match(const char *range, int range_len,
                                            const char *tag, int tag_len)
{
	const char *end = range + range_len;
	const char *tend = tag + tag_len;

	while (range < end) {
		if (*range == '-' && tag == tend)
			return 1;
		if (*range != *tag || tag == tend)
			return 0;
		range++;
		tag++;
	}
	/* Return true only if the last char of the tag is matched. */
	return tag == tend;
}


#endif /* _COMMON_HTTP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
