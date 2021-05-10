/*
 * include/haproxy/uri_normalizer.h
 * HTTP request URI normalization.
 *
 * Copyright 2021 Tim Duesterhus <tim@bastelstu.be>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef _HAPROXY_URI_NORMALIZER_H
#define _HAPROXY_URI_NORMALIZER_H

#include <import/ist.h>

#include <haproxy/uri_normalizer-t.h>

/* Cuts the input at the first '#'. */
static inline enum uri_normalizer_err uri_normalizer_fragment_strip(const struct ist input, struct ist *dst)
{
	*dst = iststop(input, '#');

	return URI_NORMALIZER_ERR_NONE;
}

enum uri_normalizer_err uri_normalizer_fragment_encode(const struct ist input, struct ist *dst);
enum uri_normalizer_err uri_normalizer_percent_decode_unreserved(const struct ist input, int strict, struct ist *dst);
enum uri_normalizer_err uri_normalizer_percent_upper(const struct ist input, int strict, struct ist *dst);
enum uri_normalizer_err uri_normalizer_path_dot(const struct ist path, struct ist *dst);
enum uri_normalizer_err uri_normalizer_path_dotdot(const struct ist path, int full, struct ist *dst);
enum uri_normalizer_err uri_normalizer_path_merge_slashes(const struct ist path, struct ist *dst);
enum uri_normalizer_err uri_normalizer_query_sort(const struct ist query, const char delim, struct ist *dst);

#endif /* _HAPROXY_URI_NORMALIZER_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
