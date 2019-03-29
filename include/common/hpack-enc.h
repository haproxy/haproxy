/*
 * HPACK compressor (RFC7541)
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

#ifndef _COMMON_HPACK_ENC_H
#define _COMMON_HPACK_ENC_H

#include <inttypes.h>
#include <string.h>
#include <common/buf.h>
#include <common/config.h>
#include <common/http.h>
#include <common/ist.h>

int hpack_encode_header(struct buffer *out, const struct ist n,
			const struct ist v);

/* Returns the number of bytes required to encode the string length <len>. The
 * number of usable bits is an integral multiple of 7 plus 6 for the last byte.
 * The maximum number of bytes returned is 4 (2097279 max length). Larger values
 * return 0.
 */
static inline int hpack_len_to_bytes(size_t len)
{
	ssize_t slen = len;

	slen -= 127;
	if (__builtin_expect(slen < 0, 1))
		return 1;
	if (slen < (1 << 14)) {
		if (__builtin_expect(slen < (1 << 7), 1))
			return 2;
		else
			return 3;
	}
	if (slen < (1 << 21))
		return 4;
	return 0;
}

/* Encodes <len> into <out>+<pos> and return the new position. The caller is
 * responsible for checking for available room using hpack_len_to_bytes()
 * first.
 */
static inline int hpack_encode_len(char *out, int pos, int len)
{
	int code = len - 127;

	if (code < 0) {
		out[pos++] = len;
	} else {
		out[pos++] = 127;
		for (; code >= 128; code >>= 7)
			out[pos++] = code | 128;
		out[pos++] = code;
	}
	return pos;
}

/* Tries to encode header field index <idx> with short value <val> into the
 * aligned buffer <out>. Returns non-zero on success, 0 on failure (buffer
 * full). The caller is responsible for ensuring that the length of <val> is
 * strictly lower than 127, and that <idx> is lower than 64 (static list only),
 * and that the buffer is aligned (head==0).
 */
static inline int hpack_encode_short_idx(struct buffer *out, int idx, struct ist val)
{
	if (out->data + 2 + val.len > out->size)
		return 0;

	/* literal header field with incremental indexing */
	out->area[out->data++] = idx | 0x40;
	out->area[out->data++] = val.len;
	ist2bin(&out->area[out->data], val);
	out->data += val.len;
	return 1;
}

/* Tries to encode header field index <idx> with long value <val> into the
 * aligned buffer <out>. Returns non-zero on success, 0 on failure (buffer
 * full). The caller is responsible for ensuring <idx> is lower than 64 (static
 * list only), and that the buffer is aligned (head==0).
 */
static inline int hpack_encode_long_idx(struct buffer *out, int idx, struct ist val)
{
	int len = out->data;

	if (!hpack_len_to_bytes(val.len) ||
	    1 + len + hpack_len_to_bytes(val.len) + val.len > out->size)
		return 0;

	/* emit literal with indexing (7541#6.2.1) :
	 * [ 0 | 1 | Index (6+) ]
	 */
	out->area[len++] = idx | 0x40;
	len = hpack_encode_len(out->area, len, val.len);
	memcpy(out->area + len, val.ptr, val.len);
	len += val.len;

	out->data = len;
	return 1;
}

/* Tries to encode a :status pseudo-header with the integer status <status>
 * into the aligned buffer <out>. Returns non-zero on success, 0 on failure
 * (buffer full). The caller is responsible for ensuring that the status is
 * comprised between 100 and 999 inclusive and that the buffer is aligned. It's
 * inlined because it's easily optimizable by the compiler.
 */
static inline int hpack_encode_int_status(struct buffer *out, unsigned int status)
{
	int len = out->data;
	int size = out->size;
	unsigned char c = 0;

	/* try to emit a single byte code */
	len++;
	if (__builtin_expect(len > size, 0))
		goto fail;

	c = (status <= 304) ?
		(status <= 204) ?
			(status == 204) ? 0x89 :
			(status == 200) ? 0x88 :
		0: /* > 204 */
			(status == 304) ? 0x8b :
			(status == 206) ? 0x8a :
		0:
		(status <= 404) ?
			(status == 404) ? 0x8d :
			(status == 400) ? 0x8c :
		0: /* > 404 */
			(status == 500) ? 0x8e :
		0;

	if (c)
		goto last;

	/* fall back to literal */
	len += 4;
	if (__builtin_expect(len > size, 0))
		goto fail;

	/* basic encoding of the status code */
	out->area[len - 5] = 0x48; // indexed name -- name=":status" (idx 8)
	out->area[len - 4] = 0x03; // 3 bytes status
	out->area[len - 3] = '0' + status / 100;
	out->area[len - 2] = '0' + status / 10 % 10;
	c = '0' + status % 10;
 last:
	out->area[len - 1] = c;
	out->data = len;
	return 1;
 fail:
	return 0;
}

/* Tries to encode a :status pseudo-header with the integer status <status>
 * also represented by <str> into the aligned buffer <out>. Returns non-zero
 * on success or 0 on failure (buffer full). The caller is responsible for
 * ensuring that the status is comprised between 100 and 999 inclusive, that
 * <str> contains a valid representation of the numerical value, and that the
 * buffer is aligned. This version is preferred when the caller already knows
 * a string representation of the status because it avoids the computation in
 * the uncompressed case. It's inlined because it's easily optimizable.
 */
static inline int hpack_encode_str_status(struct buffer *out, unsigned int status, struct ist str)
{
	/* don't try too hard, we already have the ASCII value for less common cases */
	if (status == 200 || status == 304) {
		if (out->data >= out->size)
			return 0;
		out->area[out->data] = (status == 304) ? 0x8b : 0x88;
		out->data++;
		return 1;
	}
	return hpack_encode_short_idx(out, 8, str); // name=":status" (idx 8)
}

/* Tries to encode a :method pseudo-header with the method in <meth>, which
 * also exists as a string in <str>, into the aligned buffer <out>. Returns
 * non-zero on success or 0 on failure (buffer full). The caller is responsible
 * for ensuring that the string matches <meth>, that it's smaller than 127
 * bytes, and that the buffer is aligned. If <meth> is unknown then using
 * HTTP_METH_OTHER will lead to the string being encoded as a literal. It's
 * inlined because it's easily optimizable.
 */
static inline int hpack_encode_method(struct buffer *out, enum http_meth_t meth, struct ist str)
{
	if (out->data < out->size && meth == HTTP_METH_GET)
		out->area[out->data++] = 0x82; // indexed field : idx[02]=(":method", "GET")
	else if (out->data < out->size && meth == HTTP_METH_POST)
		out->area[out->data++] = 0x83; // indexed field : idx[03]=(":method", "POST")
	else
		return hpack_encode_short_idx(out, 2, str); // name=":method" (idx 2)
	return 1;
}

/* Tries to encode a :scheme pseudo-header with the scheme in <scheme>, into
 * the aligned buffer <out>. Returns non-zero on success or 0 on failure
 * (buffer full). Only "http" and "https" are recognized and handled as indexed
 * values, others are turned into short literals. The caller is responsible for
 * ensuring that the scheme is smaller than 127 bytes, and that the buffer is
 * aligned. Normally the compiler will detect constant strings in the comparison
 * if the code remains inlined.
 */
static inline int hpack_encode_scheme(struct buffer *out, struct ist scheme)
{
	if (out->data < out->size && isteq(scheme, ist("https")))
		out->area[out->data++] = 0x87; // indexed field : idx[07]=(":scheme", "https")
	else if (out->data < out->size && isteq(scheme, ist("http")))
		out->area[out->data++] = 0x86; // indexed field : idx[06]=(":scheme", "http")
	else
		return hpack_encode_short_idx(out, 6, scheme); // name=":scheme" (idx 6)
	return 1;
}

/* Tries to encode a :path pseudo-header with the path in <path>, into the
 * aligned buffer <out>. Returns non-zero on success or 0 on failure (buffer
 * full). The well-known values "/" and "/index.html" are recognized, and other
 * ones are handled as literals. The caller is responsible for ensuring that
 * the buffer is aligned.  Normally the compiler will detect constant strings
 * in the comparison if the code remains inlined.
 */
static inline int hpack_encode_path(struct buffer *out, struct ist path)
{
	if (out->data < out->size && isteq(path, ist("/")))
		out->area[out->data++] = 0x84; // indexed field : idx[04]=(":path", "/")
	else if (out->data < out->size && isteq(path, ist("/index.html")))
		out->area[out->data++] = 0x85; // indexed field : idx[05]=(":path", "/index.html")
	else if (path.len < 127)
		return hpack_encode_short_idx(out, 4, path); // name=":path" (idx 4)
	else
		return hpack_encode_long_idx(out, 4, path); // name=":path" (idx 4)
	return 1;
}


#endif /* _COMMON_HPACK_ENC_H */
