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

extern const int http_err_codes[HTTP_ERR_SIZE];
extern const char *http_err_msgs[HTTP_ERR_SIZE];
extern const struct ist http_known_methods[HTTP_METH_OTHER];
extern const uint8_t http_char_classes[256];

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


#endif /* _HAPROXY_HTTP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
