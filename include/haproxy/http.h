/*
 * include/haproxy/http.h
 *
 * Functions for version-agnostic and implementation-agnostic HTTP protocol.
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

#ifndef _HAPROXY_HTTP_H
#define _HAPROXY_HTTP_H

#include <string.h>
#include <import/ist.h>
#include <haproxy/api.h>
#include <haproxy/http-t.h>
#include <haproxy/intops.h>

extern const int http_err_codes[HTTP_ERR_SIZE];
extern const char *http_err_msgs[HTTP_ERR_SIZE];
extern const struct ist http_known_methods[HTTP_METH_OTHER];
extern const uint8_t http_char_classes[256];
extern long http_err_status_codes[512 / sizeof(long)];
extern long http_fail_status_codes[512 / sizeof(long)];

enum http_meth_t find_http_meth(const char *str, const int len);
int http_get_status_idx(unsigned int status);
const char *http_get_reason(unsigned int status);
void http_status_add_range(long *array, uint low, uint high);
void http_status_del_range(long *array, uint low, uint high);
struct ist http_get_host_port(const struct ist host);
int http_is_default_port(const struct ist schm, const struct ist port);
int http_validate_scheme(const struct ist schm);
struct ist http_parse_scheme(struct http_uri_parser *parser);
struct ist http_parse_authority(struct http_uri_parser *parser, int no_userinfo);
struct ist http_parse_path(struct http_uri_parser *parser);
int http_parse_cont_len_header(struct ist *value, unsigned long long *body_len,
                               int not_first);
int http_header_match2(const char *hdr, const char *end,
                       const char *name, int len);
char *http_find_hdr_value_end(char *s, const char *e);
char *http_find_cookie_value_end(char *s, const char *e);
char *http_extract_cookie_value(char *hdr, const char *hdr_end,
                                char *cookie_name, size_t cookie_name_l,
                                int list, char **value, size_t *value_l);
char *http_extract_next_cookie_name(char *hdr_beg, char *hdr_end, int is_req,
                                    char **ptr, size_t *len);
int http_parse_qvalue(const char *qvalue, const char **end);
const char *http_find_url_param_pos(const char **chunks,
                                    const char* url_param_name,
                                    size_t url_param_name_l, char delim, char insensitive);
int http_find_next_url_param(const char **chunks,
                             const char* url_param_name, size_t url_param_name_l,
                             const char **vstart, const char **vend, char delim, char insensitive);

int http_parse_header(const struct ist hdr, struct ist *name, struct ist *value);
int http_parse_stline(const struct ist line, struct ist *p1, struct ist *p2, struct ist *p3);
int http_parse_status_val(const struct ist value, struct ist *status, struct ist *reason);

int http_compare_etags(struct ist etag1, struct ist etag2);

struct ist http_trim_leading_spht(struct ist value);
struct ist http_trim_trailing_spht(struct ist value);

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

static inline enum http_etag_type http_get_etag_type(const struct ist etag)
{
	/* An ETag must be at least 2 characters. */
	if (etag.len < 2)
		return ETAG_INVALID;

	/* The last character must be a `"`. */
	if (etag.ptr[etag.len - 1] != '"')
		return ETAG_INVALID;

	/* If the ETag starts with a `"` then it is a strong ETag. */
	if (etag.ptr[0] == '"')
		return ETAG_STRONG;

	/* If the ETag starts with `W/"` then it is a weak ETag. */
	if (istnmatch(etag, ist("W/\""), 3))
		return ETAG_WEAK;

	return ETAG_INVALID;
}

/* Initialize a HTTP URI parser to use it with http URI parsing functions. The
 * URI format is detected according to its first character.
 */
static inline struct http_uri_parser http_uri_parser_init(const struct ist uri)
{
	struct http_uri_parser parser = {
	  .uri    = uri,
	  .state  = URI_PARSER_STATE_BEFORE,
	};

	/* RFC7230, par. 2.7 :
	 * Request-URI = "*" | absuri | abspath | authority
	 */

	if (!istlen(parser.uri)) {
		parser.format = URI_PARSER_FORMAT_EMPTY;
	}
	else {
		/* detect the format according to the first URI character */
		switch (*istptr(parser.uri)) {
		case '*':
			parser.format = URI_PARSER_FORMAT_ASTERISK;
			break;

		case '/':
			parser.format = URI_PARSER_FORMAT_ABSPATH;
			break;

		default:
			parser.format = URI_PARSER_FORMAT_ABSURI_OR_AUTHORITY;
			break;
		}
	}

	return parser;
}

/* Looks into <ist> for forbidden characters for header values (0x00, 0x0A,
 * 0x0D), starting at pointer <start> which must be within <ist>. Returns
 * non-zero if such a character is found, 0 otherwise. When run on unlikely
 * header match, it's recommended to first check for the presence of control
 * chars using ist_find_ctl().
 */
static inline int http_header_has_forbidden_char(const struct ist ist, const char *start)
{
	do {
		if ((uint8_t)*start <= 0x0d &&
		    (1U << (uint8_t)*start) & ((1<<13) | (1<<10) | (1<<0)))
			return 1;
		start++;
	} while (start < istend(ist));
	return 0;
}

/* Check that method only contains token as required.
 * See RFC 9110 9. Methods
 */
static inline int http_method_has_forbidden_char(const struct ist ist)
{
	const char *start = istptr(ist);

	do {
		if (!HTTP_IS_TOKEN(*start))
			return 1;
		start++;
	} while (start < istend(ist));
	return 0;
}

/* Looks into <ist> for forbidden characters for :path values (0x00..0x1F,
 * 0x20, 0x23), starting at pointer <start> which must be within <ist>.
 * Returns non-zero if such a character is found, 0 otherwise. When run on
 * unlikely header match, it's recommended to first check for the presence
 * of control chars using ist_find_ctl().
 */
static inline int http_path_has_forbidden_char(const struct ist ist, const char *start)
{
	do {
		if ((uint8_t)*start <= 0x23) {
			if ((uint8_t)*start < 0x20)
				return 1;
			if ((1U << ((uint8_t)*start & 0x1F)) & ((1<<3) | (1<<0)))
				return 1;
		}
		start++;
	} while (start < istend(ist));
	return 0;
}

/* Checks status code array <array> for the presence of status code <status>.
 * Returns non-zero if the code is present, zero otherwise. Any status code is
 * permitted.
 */
static inline int http_status_matches(const long *array, uint status)
{
	if (status < 100 || status > 599)
		return 0;

	return ha_bit_test(status - 100, array);
}

#endif /* _HAPROXY_HTTP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
