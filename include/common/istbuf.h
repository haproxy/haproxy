/*
 * include/common/istbuf.h
 * Functions used to manipulate indirect strings with wrapping buffers.
 *
 * Copyright (C) 2000-2018 Willy Tarreau - w@1wt.eu
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

#ifndef _COMMON_ISTBUF_H
#define _COMMON_ISTBUF_H

#include <inttypes.h>
#include <common/buf.h>
#include <common/ist.h>


/* b_isteq() : returns > 0 if the first <n> characters of buffer <b> starting
 * at offset <o> relative to the buffer's head match <ist>. (empty strings do
 * match). It is designed to be used with reasonably small strings (it matches
 * a single byte per loop iteration). It is expected to be used with an offset
 * to skip old data. For example :
 * - "input" contents  :  b_isteq(b, old_cnt, new_cnt, ist);
 * - "output" contents :  b_isteq(b, 0, old_cnt, ist);
 * Return value :
 *   >0 : the number of matching bytes
 *   =0 : not enough bytes (or matching of empty string)
 *   <0 : non-matching byte found
 */
static inline ssize_t b_isteq(const struct buffer *b, size_t o, size_t n, const struct ist ist)
{
	struct ist r = ist;
	const char *p;
	const char *end = b_wrap(b);

	if (n < r.len)
		return 0;

	p = b_peek(b, o);
	while (r.len--) {
		if (*p++ != *r.ptr++)
			return -1;
		if (unlikely(p == end))
			p = b_orig(b);
	}
	return ist.len;
}

/* Same as b_isteq but case-insensitive */
static inline ssize_t b_isteqi(const struct buffer *b, size_t o, size_t n, const struct ist ist)
{
	struct ist r = ist;
	const char *p;
	const char *end = b_wrap(b);

	if (n < r.len)
		return 0;

	p = b_peek(b, o);
	while (r.len--) {
		if (*p != *r.ptr &&
		    ist_lc[(unsigned char)*p] != ist_lc[(unsigned char)*r.ptr])
			return -1;
		p++;
		r.ptr++;
		if (unlikely(p == end))
			p = b_orig(b);
	}
	return ist.len;
}

/* b_isteat() : "eats" string <ist> from the head of buffer <b>. Wrapping data
 * is explicitly supported. It matches a single byte per iteration so strings
 * should remain reasonably small. Returns :
 *   > 0 : number of bytes matched and eaten
 *   = 0 : not enough bytes (or matching an empty string)
 *   < 0 : non-matching byte found
 */
static inline ssize_t b_isteat(struct buffer *b, const struct ist ist)
{
	ssize_t ret = b_isteq(b, 0, b_data(b), ist);

	if (ret > 0)
		b_del(b, ret);
	return ret;
}

/* b_istput() : injects string <ist> at the tail of output buffer <b> provided
 * that it fits. Wrapping is supported. It's designed for small strings as it
 * only writes a single byte per iteration. Returns the number of characters
 * copied (ist.len), 0 if it temporarily does not fit, or -1 if it will never
 * fit. It will only modify the buffer upon success. In all cases, the contents
 * are copied prior to reporting an error, so that the destination at least
 * contains a valid but truncated string.
 */
static inline ssize_t b_istput(struct buffer *b, const struct ist ist)
{
	const char *end = b_wrap(b);
	struct ist r = ist;
	char *p;

	if (r.len > (size_t)b_room(b))
		return r.len < b->size ? 0 : -1;

	p = b_tail(b);
	b->data += r.len;
	while (r.len--) {
		*p++ = *r.ptr++;
		if (unlikely(p == end))
			p = b_orig(b);
	}
	return ist.len;
}

/* b_putist() : tries to copy as much as possible of string <ist> into buffer
 * <b> and returns the number of bytes copied (truncation is possible). It uses
 * b_putblk() and is suitable for large blocks.
 */
static inline size_t b_putist(struct buffer *b, const struct ist ist)
{
	return b_putblk(b, ist.ptr, ist.len);
}

#endif /* _COMMON_ISTBUF_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
