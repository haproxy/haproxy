/*
 * QPACK decompressor
 *
 * Copyright 2021 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
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

#ifndef _HAPROXY_QPACK_DEC_H
#define _HAPROXY_QPACK_DEC_H

#include <inttypes.h>

struct buffer;
struct http_hdr;

/* Internal QPACK processing errors.
 *Nothing to see with the RFC.
 */
enum {
	QPACK_RET_NONE = 0,  /* no error */
	QPACK_RET_DECOMP,    /* corresponds to RFC 9204 decompression error */
	QPACK_RET_RIC,       /* cannot decode Required Insert Count prefix field */
	QPACK_RET_DB,        /* cannot decode Delta Base prefix field */
	QPACK_RET_TRUNCATED, /* truncated stream */
	QPACK_RET_HUFFMAN,   /* huffman decoding error */
	QPACK_RET_TOO_LARGE, /* decoded request/response is too large */
};

struct qpack_dec {
	/* Insert count */
	uint64_t ic;
	/* Known received count */
	uint64_t krc;
};

int qpack_decode_fs(const unsigned char *buf, uint64_t len, struct buffer *tmp,
                    struct http_hdr *list, int list_size);
int qpack_decode_enc(struct buffer *buf, int fin, void *ctx);
int qpack_decode_dec(struct buffer *buf, int fin, void *ctx);

int qpack_err_decode(const int value);

#endif /* _HAPROXY_QPACK_DEC_H */
