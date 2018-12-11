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

#include <stdint.h>
#include <common/buf.h>
#include <common/config.h>
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

#endif /* _COMMON_HPACK_ENC_H */
