/*
 * include/haproxy/spoe.h
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

#ifndef _HAPROXY_SPOE_H
#define _HAPROXY_SPOE_H

#include <haproxy/api.h>
#include <haproxy/intops.h>
#include <haproxy/sample-t.h>
#include <haproxy/spoe-t.h>

struct appctx;

extern const struct ist spop_err_reasons[SPOP_ERR_ENTRIES];
extern const struct spop_version spop_supported_versions[];

struct spoe_agent *spoe_appctx_agent(struct appctx *appctx);

/* Encode a buffer. Its length <len> is encoded as a varint, followed by a copy
 * of <str>. It must have enough space in <*buf> to encode the buffer, else an
 * error is triggered.
 * On success, it returns <len> and <*buf> is moved after the encoded value. If
 * an error occurred, it returns -1. */
static inline int spoe_encode_buffer(const char *str, size_t len, char **buf, char *end)
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

/* Decode a buffer. The buffer length is decoded and saved in <*len>. <*str>
 * points on the first byte of the buffer.
 * On success, it returns the buffer length and <*buf> is moved after the
 * encoded buffer. Otherwise, it returns -1. */
static inline int spoe_decode_buffer(char **buf, char *end, char **str, uint64_t *len)
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
static inline int spoe_encode_data(struct sample *smp, char **buf, char *end)
{
	char *p = *buf;
	int   ret;

	if (p >= end)
		return -1;

	if (smp == NULL) {
		*p++ = SPOP_DATA_T_NULL;
		goto end;
	}

	switch (smp->data.type) {
		case SMP_T_BOOL:
			*p    = SPOP_DATA_T_BOOL;
			*p++ |= ((!smp->data.u.sint) ? SPOP_DATA_FL_FALSE : SPOP_DATA_FL_TRUE);
			break;

		case SMP_T_SINT:
			*p++ = SPOP_DATA_T_INT64;
			if (encode_varint(smp->data.u.sint, &p, end) == -1)
				return -1;
			break;

		case SMP_T_IPV4:
			if (p + 5 > end)
				return -1;
			*p++ = SPOP_DATA_T_IPV4;
			memcpy(p, &smp->data.u.ipv4, 4);
			p += 4;
			break;

		case SMP_T_IPV6:
			if (p + 17 > end)
				return -1;
			*p++ = SPOP_DATA_T_IPV6;
			memcpy(p, &smp->data.u.ipv6, 16);
			p += 16;
			break;

		case SMP_T_STR:
		case SMP_T_BIN: {
			struct buffer *chk = &smp->data.u.str;

			*p++ = (smp->data.type == SMP_T_STR) ? SPOP_DATA_T_STR : SPOP_DATA_T_BIN;
			ret = spoe_encode_buffer(chk->area, chk->data, &p, end);
			if (ret == -1)
				return -1;
			break;
		}

		case SMP_T_METH: {
			char   *m;
			size_t  len;

			*p++ = SPOP_DATA_T_STR;
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
			*p++ = SPOP_DATA_T_NULL;
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
static inline int spoe_skip_data(char **buf, char *end)
{
	char    *str, *p = *buf;
	int      type, ret;
	uint64_t v, sz;

	if (p >= end)
		return -1;

	type = *p++;
	switch (type & SPOP_DATA_T_MASK) {
		case SPOP_DATA_T_BOOL:
			break;
		case SPOP_DATA_T_INT32:
		case SPOP_DATA_T_INT64:
		case SPOP_DATA_T_UINT32:
		case SPOP_DATA_T_UINT64:
			if (decode_varint(&p, end, &v) == -1)
				return -1;
			break;
		case SPOP_DATA_T_IPV4:
			if (p+4 > end)
				return -1;
			p += 4;
			break;
		case SPOP_DATA_T_IPV6:
			if (p+16 > end)
				return -1;
			p += 16;
			break;
		case SPOP_DATA_T_STR:
		case SPOP_DATA_T_BIN:
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
static inline int spoe_decode_data(char **buf, char *end, struct sample *smp)
{
	char  *str, *p = *buf;
	int    type, r = 0;
	uint64_t sz;

	if (p >= end)
		return -1;

	type = *p++;
	switch (type & SPOP_DATA_T_MASK) {
		case SPOP_DATA_T_BOOL:
			smp->data.u.sint = ((type & SPOP_DATA_FL_MASK) == SPOP_DATA_FL_TRUE);
			smp->data.type = SMP_T_BOOL;
			break;
		case SPOP_DATA_T_INT32:
		case SPOP_DATA_T_INT64:
		case SPOP_DATA_T_UINT32:
		case SPOP_DATA_T_UINT64:
			if (decode_varint(&p, end, (uint64_t *)&smp->data.u.sint) == -1)
				return -1;
			smp->data.type = SMP_T_SINT;
			break;
		case SPOP_DATA_T_IPV4:
			if (p+4 > end)
				return -1;
			smp->data.type = SMP_T_IPV4;
			memcpy(&smp->data.u.ipv4, p, 4);
			p += 4;
			break;
		case SPOP_DATA_T_IPV6:
			if (p+16 > end)
				return -1;
			memcpy(&smp->data.u.ipv6, p, 16);
			smp->data.type = SMP_T_IPV6;
			p += 16;
			break;
		case SPOP_DATA_T_STR:
		case SPOP_DATA_T_BIN:
			/* All the buffer must be decoded */
			if (spoe_decode_buffer(&p, end, &str, &sz) == -1)
				return -1;
			smp->data.u.str.area = str;
			smp->data.u.str.data = sz;
			smp->data.type = (type == SPOP_DATA_T_STR) ? SMP_T_STR : SMP_T_BIN;
			break;
	}

	r    = (p - *buf);
	*buf = p;
	return r;
}

/* Convert a string to a SPOP version value. The string must follow the format
 * "MAJOR.MINOR". It will be concerted into the integer (1000 * MAJOR + MINOR).
 * If an error occurred, -1 is returned.
 */
static inline int spoe_str_to_vsn(const char *str, size_t len)
{
	const char *p, *end;
	int   maj, min, vsn;

	p   = str;
	end = str+len;
	maj = min = 0;
	vsn = -1;

	/* skip leading spaces */
	while (p < end && isspace((unsigned char)*p))
		p++;

	/* parse Major number, until the '.' */
	while (*p != '.') {
		if (p >= end || *p < '0' || *p > '9')
			goto out;
		maj *= 10;
		maj += (*p - '0');
		p++;
	}

	/* check Major version */
	if (!maj)
		goto out;

	p++; /* skip the '.' */
	if (p >= end || *p < '0' || *p > '9') /* Minor number is missing */
		goto out;

	/* Parse Minor number */
	while (p < end) {
		if (*p < '0' || *p > '9')
			break;
		min *= 10;
		min += (*p - '0');
		p++;
	}

	/* check Minor number */
	if (min > 999)
		goto out;

	/* skip trailing spaces */
	while (p < end && isspace((unsigned char)*p))
		p++;
	if (p != end)
		goto out;

	vsn = maj * 1000 + min;
out:
	return vsn;
}

/* Check if vsn, converted into an integer, is supported by looping on the list
 * of supported versions. It return -1 on error and 0 on success.
 */
static inline int spoe_check_vsn(int vsn)
{
	int i;

	for (i = 0; spop_supported_versions[i].str != NULL; ++i) {
		if (vsn >= spop_supported_versions[i].min &&
		    vsn <= spop_supported_versions[i].max)
			break;
	}
	if (spop_supported_versions[i].str == NULL)
		return -1;
	return 0;
}

#endif /* _HAPROXY_SPOE_H */
