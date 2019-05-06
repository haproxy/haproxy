/*
 * include/proto/spoe.h
 * Encoding/Decoding functions for the SPOE filters (and other helpers).
 *
 * Copyright (C) 2017 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
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

#ifndef _PROTO_SPOE_H
#define _PROTO_SPOE_H

#include <common/standard.h>

#include <types/spoe.h>

#include <proto/sample.h>


/* Encode a buffer. Its length <len> is encoded as a varint, followed by a copy
 * of <str>. It must have enough space in <*buf> to encode the buffer, else an
 * error is triggered.
 * On success, it returns <len> and <*buf> is moved after the encoded value. If
 * an error occurred, it returns -1. */
static inline int
spoe_encode_buffer(const char *str, size_t len, char **buf, char *end)
{
	char *p = *buf;
	int   ret;

	if (p >= end)
		return -1;

	if (!len) {
		*p++ = 0;
		*buf = p;
		return 0;
	}

	ret = encode_varint(len, &p, end);
	if (ret == -1 || p + len > end)
		return -1;

	memcpy(p, str, len);
	*buf = p + len;
	return len;
}

/* Encode a buffer, possibly partially. It does the same thing than
 * 'spoe_encode_buffer', but if there is not enough space, it does not fail.
 * On success, it returns the number of copied bytes and <*buf> is moved after
 * the encoded value. If an error occurred, it returns -1. */
static inline int
spoe_encode_frag_buffer(const char *str, size_t len, char **buf, char *end)
{
	char *p = *buf;
	int   ret;

	if (p >= end)
		return -1;

	if (!len) {
		*p++ = 0;
		*buf = p;
		return 0;
	}

	ret = encode_varint(len, &p, end);
	if (ret == -1 || p >= end)
		return -1;

	ret = (p+len < end) ? len : (end - p);
	memcpy(p, str, ret);
	*buf = p + ret;
	return ret;
}

/* Decode a buffer. The buffer length is decoded and saved in <*len>. <*str>
 * points on the first byte of the buffer.
 * On success, it returns the buffer length and <*buf> is moved after the
 * encoded buffer. Otherwise, it returns -1. */
static inline int
spoe_decode_buffer(char **buf, char *end, char **str, uint64_t *len)
{
	char    *p = *buf;
	uint64_t sz;
	int      ret;

	*str = NULL;
	*len = 0;

	ret = decode_varint(&p, end, &sz);
	if (ret == -1 || p + sz > end)
		return -1;

	*str = p;
	*len = sz;
	*buf = p + sz;
	return sz;
}

/* Encode a typed data using value in <smp>. On success, it returns the number
 * of copied bytes and <*buf> is moved after the encoded value. If an error
 * occurred, it returns -1.
 *
 * If the value is too big to be encoded, depending on its type, then encoding
 * failed or the value is partially encoded. Only strings and binaries can be
 * partially encoded. */
static inline int
spoe_encode_data(struct sample *smp, char **buf, char *end)
{
	char *p = *buf;
	int   ret;

	if (p >= end)
		return -1;

	if (smp == NULL) {
		*p++ = SPOE_DATA_T_NULL;
		goto end;
	}

	switch (smp->data.type) {
		case SMP_T_BOOL:
			*p    = SPOE_DATA_T_BOOL;
			*p++ |= ((!smp->data.u.sint) ? SPOE_DATA_FL_FALSE : SPOE_DATA_FL_TRUE);
			break;

		case SMP_T_SINT:
			*p++ = SPOE_DATA_T_INT64;
			if (encode_varint(smp->data.u.sint, &p, end) == -1)
				return -1;
			break;

		case SMP_T_IPV4:
			if (p + 5 > end)
				return -1;
			*p++ = SPOE_DATA_T_IPV4;
			memcpy(p, &smp->data.u.ipv4, 4);
			p += 4;
			break;

		case SMP_T_IPV6:
			if (p + 17 > end)
				return -1;
			*p++ = SPOE_DATA_T_IPV6;
			memcpy(p, &smp->data.u.ipv6, 16);
			p += 16;
			break;

		case SMP_T_STR:
		case SMP_T_BIN: {
			/* If defined, get length and offset of the sample by reading the sample
			 * context. ctx.a[0] is the pointer to the length and ctx.a[1] is the
			 * pointer to the offset. If the offset is greater than 0, it means the
			 * sample is partially encoded. In this case, we only need to encode the
			 * reamining. When all the sample is encoded, the offset is reset to 0.
			 * So the caller know it can try to encode the next sample. */
			struct buffer *chk = &smp->data.u.str;
			unsigned int *len  = smp->ctx.a[0];
			unsigned int *off  = smp->ctx.a[1];

			if (!*off) {
				/* First evaluation of the sample : encode the
				 * type (string or binary), the buffer length
				 * (as a varint) and at least 1 byte of the
				 * buffer. */
				struct buffer *chk = &smp->data.u.str;

				*p++ = (smp->data.type == SMP_T_STR)
					? SPOE_DATA_T_STR
					: SPOE_DATA_T_BIN;
				ret = spoe_encode_frag_buffer(chk->area,
							      chk->data, &p,
							      end);
				if (ret == -1)
					return -1;
				*len = chk->data;
			}
			else {
				/* The sample has been fragmented, encode remaining data */
				ret = MIN(*len - *off, end - p);
				memcpy(p, chk->area + *off, ret);
				p += ret;
			}
			/* Now update <*off> */
			if (ret + *off != *len)
				*off += ret;
			else
				*off = 0;
			break;
		}

		case SMP_T_METH: {
			char   *m;
			size_t  len;

			*p++ = SPOE_DATA_T_STR;
			switch (smp->data.u.meth.meth) {
				case HTTP_METH_OPTIONS: m = "OPTIONS"; len = 7; break;
				case HTTP_METH_GET    : m = "GET";     len = 3; break;
				case HTTP_METH_HEAD   : m = "HEAD";    len = 4; break;
				case HTTP_METH_POST   : m = "POST";    len = 4; break;
				case HTTP_METH_PUT    : m = "PUT";     len = 3; break;
				case HTTP_METH_DELETE : m = "DELETE";  len = 6; break;
				case HTTP_METH_TRACE  : m = "TRACE";   len = 5; break;
				case HTTP_METH_CONNECT: m = "CONNECT"; len = 7; break;

				default :
					m   = smp->data.u.meth.str.area;
					len = smp->data.u.meth.str.data;
			}
			if (spoe_encode_buffer(m, len, &p, end) == -1)
				return -1;
			break;
		}

		default:
			*p++ = SPOE_DATA_T_NULL;
			break;
	}

  end:
	ret  = (p - *buf);
	*buf = p;
	return ret;
}

/* Skip a typed data. If an error occurred, -1 is returned, otherwise the number
 * of skipped bytes is returned and the <*buf> is moved after skipped data.
 *
 * A types data is composed of a type (1 byte) and corresponding data:
 *  - boolean: non additional data (0 bytes)
 *  - integers: a variable-length integer (see decode_varint)
 *  - ipv4: 4 bytes
 *  - ipv6: 16 bytes
 *  - binary and string: a buffer prefixed by its size, a variable-length
 *    integer (see spoe_decode_buffer) */
static inline int
spoe_skip_data(char **buf, char *end)
{
	char    *str, *p = *buf;
	int      type, ret;
	uint64_t v, sz;

	if (p >= end)
		return -1;

	type = *p++;
	switch (type & SPOE_DATA_T_MASK) {
		case SPOE_DATA_T_BOOL:
			break;
		case SPOE_DATA_T_INT32:
		case SPOE_DATA_T_INT64:
		case SPOE_DATA_T_UINT32:
		case SPOE_DATA_T_UINT64:
			if (decode_varint(&p, end, &v) == -1)
				return -1;
			break;
		case SPOE_DATA_T_IPV4:
			if (p+4 > end)
				return -1;
			p += 4;
			break;
		case SPOE_DATA_T_IPV6:
			if (p+16 > end)
				return -1;
			p += 16;
			break;
		case SPOE_DATA_T_STR:
		case SPOE_DATA_T_BIN:
			/* All the buffer must be skipped */
			if (spoe_decode_buffer(&p, end, &str, &sz) == -1)
				return -1;
			break;
	}

	ret  = (p - *buf);
	*buf = p;
	return ret;
}

/* Decode a typed data and fill <smp>. If an error occurred, -1 is returned,
 * otherwise the number of read bytes is returned and <*buf> is moved after the
 * decoded data. See spoe_skip_data for details. */
static inline int
spoe_decode_data(char **buf, char *end, struct sample *smp)
{
	char  *str, *p = *buf;
	int    type, r = 0;
	uint64_t sz;

	if (p >= end)
		return -1;

	type = *p++;
	switch (type & SPOE_DATA_T_MASK) {
		case SPOE_DATA_T_BOOL:
			smp->data.u.sint = ((type & SPOE_DATA_FL_MASK) == SPOE_DATA_FL_TRUE);
			smp->data.type = SMP_T_BOOL;
			break;
		case SPOE_DATA_T_INT32:
		case SPOE_DATA_T_INT64:
		case SPOE_DATA_T_UINT32:
		case SPOE_DATA_T_UINT64:
			if (decode_varint(&p, end, (uint64_t *)&smp->data.u.sint) == -1)
				return -1;
			smp->data.type = SMP_T_SINT;
			break;
		case SPOE_DATA_T_IPV4:
			if (p+4 > end)
				return -1;
			smp->data.type = SMP_T_IPV4;
			memcpy(&smp->data.u.ipv4, p, 4);
			p += 4;
			break;
		case SPOE_DATA_T_IPV6:
			if (p+16 > end)
				return -1;
			memcpy(&smp->data.u.ipv6, p, 16);
			smp->data.type = SMP_T_IPV6;
			p += 16;
			break;
		case SPOE_DATA_T_STR:
		case SPOE_DATA_T_BIN:
			/* All the buffer must be decoded */
			if (spoe_decode_buffer(&p, end, &str, &sz) == -1)
				return -1;
			smp->data.u.str.area = str;
			smp->data.u.str.data = sz;
			smp->data.type = (type == SPOE_DATA_T_STR) ? SMP_T_STR : SMP_T_BIN;
			break;
	}

	r    = (p - *buf);
	*buf = p;
	return r;
}

#endif /* _PROTO_SPOE_H */
