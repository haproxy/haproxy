/*
 * HTTP header management (new model) - type definitions
 *
 * Copyright (C) 2014-2017 Willy Tarreau <willy@haproxy.org>
 * Copyright (C) 2017 HAProxy Technologies
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef _COMMON_HTTP_HDR_H
#define _COMMON_HTTP_HDR_H

#include <inttypes.h>
#include <common/ist.h>

/* a header field made of a name and a value. Such structure stores 4 longs so
 * it takes 16 bytes on 32-bit systems and 32 bytes on 64-bit systems.
 */
struct http_hdr {
	struct ist n; /* name */
	struct ist v; /* value */
};

/* sets an http_hdr <hdr> to name <n> and value <v>. Useful to avoid casts in
 * immediate assignments.
 */
static inline void http_set_hdr(struct http_hdr *hdr, const struct ist n, const struct ist v)
{
	hdr->n = n;
	hdr->v = v;
}

/* removes all occurrences of header name <n> in list <hdr> and returns the new count. The
 * list must be terminated by the empty header.
 */
static inline int http_del_hdr(struct http_hdr *hdr, const struct ist n)
{
	int src = 0, dst = 0;

	do {
		if (!isteqi(hdr[src].n, n)) {
			if (src != dst)
				hdr[dst] = hdr[src];
			dst++;
		}
	} while (hdr[src++].n.len);

	return dst;
}
#endif /* _COMMON_HTTP_HDR_H */
