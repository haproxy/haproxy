/*
 * FastCGI protocol processing
 *
 * Copyright (C) 2019 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
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

#include <common/fcgi.h>


/* Encodes header of a FCGI record into the chunk <out>. It returns non-zero on
 * success and 0 on failure (buffer full). <out> is a chunk, so the wrapping is
 * not handled by this function. It is the caller responsibility to ensure
 * enough contiguous space is available
 */
int fcgi_encode_record_hdr(struct buffer *out, const struct fcgi_header *h)
{
	size_t len = out->data;

	if (len + 8 >= b_size(out))
		return 0;

	out->area[len++] = h->vsn;
	out->area[len++] = h->type;
	out->area[len++] = ((h->id >> 8) & 0xff);
	out->area[len++] = (h->id & 0xff);
	out->area[len++] = ((h->len >> 8) & 0xff);
	out->area[len++] = (h->len & 0xff);
	out->area[len++] = h->padding;
	len++; /* rsv */

	out->data = len;
	return 1;
}

/* Decodes a FCGI record header from offset <o> of buffer <in> into descriptor
 * <h>. The buffer may wrap so each byte read must be checked. The header is
 * formed like this :
 *
 *     b0    b1     b2    b3    b4      b5     b6      b7
 *  +-----+------+-----+-----+------+------+--------+-----+
 *  | vsn | type | id1 | id0 | len1 | len0 | padlen | rsv |
 *  +-----+------+-----+-----+------+------+--------+-----+
 *
 * Returns zero if some bytes are missing, otherwise the number of read bytes.
 */
size_t fcgi_decode_record_hdr(const struct buffer *in, size_t o, struct fcgi_header *h)
{
	if (b_data(in) < o + 8)
		return 0;

	h->vsn     = (uint8_t)(*b_peek(in, o));
	h->type    = (uint8_t)(*b_peek(in, o+1));
	h->id      = ((uint8_t)(*b_peek(in, o+2)) << 8) + (uint8_t)(*b_peek(in, o+3));
	h->len     = ((uint8_t)(*b_peek(in, o+4)) << 8) + (uint8_t)(*b_peek(in, o+5));
	h->padding = (uint8_t)(*b_peek(in, o+6));
	/* ignore rsv */

	return 8;
}

/* Encodes the payload part of a BEGIN_REQUEST record into the chunk <out>. It
 * returns non-zero on success and 0 on failure (buffer full). <out> is a chunk,
 * so the wrapping is not handled by this function. It is the caller
 * responsibility to ensure enough contiguous space is available
 */
int fcgi_encode_begin_request(struct buffer *out, const struct fcgi_begin_request *r)
{
	size_t len = out->data;

	if (len + 8 >= b_size(out))
		return 0;

	out->area[len++] = ((r->role >> 8) & 0xff);
	out->area[len++] = (r->role & 0xff);
	out->area[len++] = r->flags;
	len += 5; /* rsv */

	out->data = len;
	return 1;
}

/* Encodes a parameter, part of the payload of a PARAM record, into the chunk
 * <out>. It returns non-zero on success and 0 on failure (buffer full). <out>
 * is a chunk, so the wrapping is not handled by this function. It is the caller
 * responsibility to ensure enough contiguous space is available. The
 * parameter's name is converted to upper case and non-alphanumeric character
 * are replaced by an underscore.
 */
int fcgi_encode_param(struct buffer *out, const struct fcgi_param *p)
{
	size_t off, len = out->data;
	int nbytes, vbytes;

	nbytes = (!(p->n.len >> 7) ? 1 : 4);
	vbytes = (!(p->v.len >> 7) ? 1 : 4);
	if ((len + nbytes + p->n.len + vbytes + p->v.len) >= b_size(out))
		return 0;

	if (nbytes == 1)
		out->area[len++] = (p->n.len & 0xff);
	else {
		out->area[len++] = (((p->n.len >> 24) & 0xff) | 0x80);
		out->area[len++] = ((p->n.len >> 16) & 0xff);
		out->area[len++] = ((p->n.len >> 8) & 0xff);
		out->area[len++] = (p->n.len & 0xff);
	}

	if (vbytes == 1)
		out->area[len++] = (p->v.len & 0xff);
	else {
		out->area[len++] = (((p->v.len >> 24) & 0xff) | 0x80);
		out->area[len++] = ((p->v.len >> 16) & 0xff);
		out->area[len++] = ((p->v.len >> 8) & 0xff);
		out->area[len++] = (p->v.len & 0xff);
	}

	for (off = 0; off < p->n.len; off++) {
		if (isalnum((int)p->n.ptr[off]))
			out->area[len++] = ist_uc[(unsigned char)p->n.ptr[off]];
		else
			out->area[len++] = '_';
	}
	if (p->v.len) {
		ist2bin(out->area + len, p->v);
		len += p->v.len;
	}

	out->data = len;
	return 1;
}

/* Decodes a parameter of a PARAM record from offset <o> of buffer <in> into the
 * FCGI param <p>. The buffer may wrap so each byte read must be checked.
 * Returns zero if some bytes are missing, otherwise the number of read bytes.
 */
size_t fcgi_decode_param(const struct buffer *in, size_t o, struct fcgi_param *p)
{
	size_t data = b_data(in);
	size_t nlen, vlen, len = 0;
	uint8_t b0, b1, b2, b3;

	if (data < o + 1)
		return 0;
	b0 = *b_peek(in, o++);
	if (!(b0 >> 7)) {
		nlen = b0;
		len++;
	}
	else {
		if (data < o + 3)
			return 0;
		b1 = *b_peek(in, o++);
		b2 = *b_peek(in, o++);
		b3 = *b_peek(in, o++);
		nlen = ((b0 & 0x7f) << 24) + (b1 << 16) + (b2 << 8) + b3;
		len += 4;
	}

	if (data < o + 1)
		return 0;
	b0 = *b_peek(in, o++);
	if (!(b0 >> 7)) {
		vlen = b0;
		len++;
	}
	else {
		if (data < o + 3)
			return 0;
		b1 = *b_peek(in, o++);
		b2 = *b_peek(in, o++);
		b3 = *b_peek(in, o++);
		vlen = ((b0 & 0x7f) << 24) + (b1 << 16) + (b2 << 8) + b3;
		len += 4;
	}

	if (data < nlen + vlen)
		return 0;

	p->n.ptr = b_peek(in, o);
	p->n.len = nlen;
	p->v.ptr = b_peek(in, o+nlen);
	p->v.len = vlen;
	len += nlen + vlen;

	return len;
}


/* Decodes a parameter of a PARAM record from offset <o> of buffer <in> into the
 * FCGI param <p>. To call this function, the buffer must not wrap. Returns zero
 * if some bytes are missing, otherwise the number of read bytes.
 */
size_t fcgi_aligned_decode_param(const struct buffer *in, size_t o, struct fcgi_param *p)
{
	size_t data = b_data(in);
	size_t nlen, vlen, len = 0;
	uint8_t b0, b1, b2, b3;

	if (data < o + 1)
		return 0;
	b0 = in->area[o++];
	if (!(b0 >> 7)) {
		nlen = b0;
		len++;
	}
	else {
		if (data < o + 3)
			return 0;
		b1 = in->area[o++];
		b2 = in->area[o++];
		b3 = in->area[o++];
		nlen = ((b0 & 0x7f) << 24) + (b1 << 16) + (b2 << 8) + b3;
		len += 4;
	}

	if (data < o + 1)
		return 0;
	b0 = in->area[o++];
	if (!(b0 >> 7)) {
		vlen = b0;
		len++;
	}
	else {
		if (data < o + 3)
			return 0;
		b1 = in->area[o++];
		b2 = in->area[o++];
		b3 = in->area[o++];
		vlen = ((b0 & 0x7f) << 24) + (b1 << 16) + (b2 << 8) + b3;
		len += 4;
	}

	if (data < nlen + vlen)
		return 0;

	p->n.ptr = in->area + o;
	p->n.len = nlen;
	p->v.ptr = in->area + o + nlen;
	p->v.len = vlen;
	len += nlen + vlen;

	return len;
}

/* Decodes payload of a END_REQUEST record from offset <o> of buffer <in> into
 * the FCGI param <p>. The buffer may wrap so each byte read must be
 * checked. Returns zero if some bytes are missing, otherwise the number of read
 * bytes.
 */
size_t fcgi_decode_end_request(const struct buffer *in, size_t o, struct fcgi_end_request *rec)
{
	uint8_t b0, b1, b2, b3;

	if (b_data(in) < o + 8)
		return 0;

	b0 = *b_peek(in, o++);
	b1 = *b_peek(in, o++);
	b2 = *b_peek(in, o++);
	b3 = *b_peek(in, o++);
	rec->status = ((b0 & 0x7f) << 24) + (b1 << 16) + (b2 << 8) + b3;
	rec->errcode = *b_peek(in, o++);
        o += 3; /* ignore rsv */

	return 8;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
