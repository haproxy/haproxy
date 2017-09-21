/*
 * HPACK decompressor (RFC7541)
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/hpack-enc.h>
#include <common/http-hdr.h>
#include <common/ist.h>

#include <types/global.h>

/* returns the number of bytes required to encode the string length <len>. The
 * number of usable bits is an integral multiple of 7 plus 6 for the last byte.
 * The maximum number of bytes returned is 4 (2097279 max length). Larger values
 * return 0.
 */
static inline int len_to_bytes(size_t len)
{
	if (len < 127)
		return 1;
	if (len < 127 + (1 << 7))
		return 2;
	if (len < 127 + (1 << 14))
		return 3;
	if (len < 127 + (1 << 21))
		return 4;
	return 0;
}

/* Encode <len> into <out>+<pos> and return the new position. The caller is
 * responsible for checking for available room using len_to_bytes() first.
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


/* Tries to encode header whose name is <n> and value <v> into the chunk <out>.
 * Returns non-zero on success, 0 on failure (buffer full).
 */
int hpack_encode_header(struct chunk *out, const struct ist n, const struct ist v)
{
	int len = out->len;
	int size = out->size;

	if (len >= size)
		return 0;

	/* check a few very common response header fields to encode them using
	 * the static header table. The tests are sorted by size to help the
	 * compiler factor out the common sizes.
	 */
	if (isteq(n, ist("date")))
		out->str[len++] = 0x61; // literal with indexing -- name="date" (idx 33)
	else if (isteq(n, ist("etag")))
		out->str[len++] = 0x62; // literal with indexing -- name="etag" (idx 34)
	else if (isteq(n, ist("server")))
		out->str[len++] = 0x76; // literal with indexing -- name="server" (idx 54)
	else if (isteq(n, ist("location")))
		out->str[len++] = 0x6e; // literal with indexing -- name="location" (idx 46)
	else if (isteq(n, ist("content-type")))
		out->str[len++] = 0x5f; // literal with indexing -- name="content-type" (idx 31)
	else if (isteq(n, ist("last-modified")))
		out->str[len++] = 0x6c; // literal with indexing -- name="last-modified" (idx 44)
	else if (isteq(n, ist("accept-ranges")))
		out->str[len++] = 0x51; // literal with indexing -- name="accept-ranges" (idx 17)
	else if (isteq(n, ist("cache-control")))
		out->str[len++] = 0x58; // literal with indexing -- name="cache-control" (idx 24)
	else if (isteq(n, ist("content-length")))
		out->str[len++] = 0x5c; // literal with indexing -- name="content-length" (idx 28)
	else if (len_to_bytes(n.len) && len + len_to_bytes(n.len) + n.len <= size) {
		out->str[len++] = 0x00;      /* literal without indexing -- new name */

		len = hpack_encode_len(out->str, len, n.len);
		memcpy(out->str + len, n.ptr, n.len);
		len += n.len;
	}
	else {
		/* header field name too large for the buffer */
		return 0;
	}

	/* copy literal header field value */
	if (!len_to_bytes(v.len) || len + len_to_bytes(v.len) + v.len > size) {
		/* header value too large for the buffer */
		return 0;
	}

	len = hpack_encode_len(out->str, len, v.len);
	memcpy(out->str + len, v.ptr, v.len);
	len += v.len;

	out->len = len;
	return 1;
}
