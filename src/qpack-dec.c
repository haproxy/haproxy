/*
 * QPACK decompressor
 *
 * Copyright 2021 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <import/ist.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/h3.h>
#include <haproxy/qpack-t.h>
#include <haproxy/qpack-dec.h>
#include <haproxy/qpack-tbl.h>
#include <haproxy/hpack-huff.h>
#include <haproxy/hpack-tbl.h>
#include <haproxy/http-hdr.h>
#include <haproxy/tools.h>

#define DEBUG_HPACK

#if defined(DEBUG_HPACK)
#define qpack_debug_printf fprintf
#define qpack_debug_hexdump debug_hexdump
#else
#define qpack_debug_printf(...) do { } while (0)
#define qpack_debug_hexdump(...) do { } while (0)
#endif

/* Encoded field line bitmask */
#define QPACK_EFL_BITMASK  0xf0
#define QPACK_LFL_WPBNM    0x00 // Literal field line with post-base name reference
#define QPACK_IFL_WPBI     0x10 // Indexed field line with post-based index
#define QPACK_LFL_WLN_BIT  0x20 // Literal field line with literal name
#define QPACK_LFL_WNR_BIT  0x40 // Literal field line with name reference
#define QPACK_IFL_BIT      0x80 // Indexed field line

/* reads a varint from <raw>'s lowest <b> bits and <len> bytes max (raw included).
 * returns the 64-bit value on success after updating buf and len_in. Forces
 * len_in to (uint64_t)-1 on truncated input.
 * Note that this function is similar to the one used for HPACK (except that is supports
 * up to 62-bits integers).
 */
static uint64_t qpack_get_varint(const unsigned char **buf, uint64_t *len_in, int b)
{
	uint64_t ret = 0;
	int len = *len_in;
	const uint8_t *raw = *buf;
	uint8_t shift = 0;

	len--;
	ret = *raw++ & ((1 << b) - 1);
	if (ret != (uint64_t)((1 << b) - 1))
		goto end;

	while (len && (*raw & 128)) {
		ret += ((uint64_t)*raw++ & 127) << shift;
		shift += 7;
		len--;
	}

	/* last 7 bits */
	if (!len)
		goto too_short;

	len--;
	ret += ((uint64_t)*raw++ & 127) << shift;

 end:
	*buf = raw;
	*len_in = len;
	return ret;

 too_short:
	*len_in = (uint64_t)-1;
	return 0;
}

/* Decode an encoder stream */
int qpack_decode_enc(struct h3_uqs *h3_uqs, void *ctx)
{
	size_t len;
	struct buffer *rxbuf;
	unsigned char inst;

	rxbuf = &h3_uqs->qcs->rx.buf;
	len = b_data(rxbuf);
	qpack_debug_hexdump(stderr, "[QPACK-DEC-ENC] ", b_head(rxbuf), 0, len);

	if (!len) {
		qpack_debug_printf(stderr, "[QPACK-DEC-ENC] empty stream\n");
		return 0;
	}

	inst = (unsigned char)*b_head(rxbuf) & QPACK_ENC_INST_BITMASK;
	if (inst == QPACK_ENC_INST_DUP) {
		/* Duplicate */
	}
	else if (inst & QPACK_ENC_INST_IWNR_BIT) {
		/* Insert With Name Reference */
	}
	else if (inst & QPACK_ENC_INST_IWLN_BIT) {
		/* Insert with literal name */
	}
	else if (inst & QPACK_ENC_INST_SDTC_BIT) {
		/* Set dynamic table capacity */
	}

	return 1;
}

/* Decode an decoder stream */
int qpack_decode_dec(struct h3_uqs *h3_uqs, void *ctx)
{
	size_t len;
	struct buffer *rxbuf;
	unsigned char inst;

	rxbuf = &h3_uqs->qcs->rx.buf;
	len = b_data(rxbuf);
	qpack_debug_hexdump(stderr, "[QPACK-DEC-DEC] ", b_head(rxbuf), 0, len);

	if (!len) {
		qpack_debug_printf(stderr, "[QPACK-DEC-DEC] empty stream\n");
		return 0;
	}

	inst = (unsigned char)*b_head(rxbuf) & QPACK_DEC_INST_BITMASK;
	if (inst == QPACK_DEC_INST_ICINC) {
		/* Insert count increment */
	}
	else if (inst & QPACK_DEC_INST_SACK) {
		/* Section Acknowledgment */
	}
	else if (inst & QPACK_DEC_INST_SCCL) {
		/* Stream cancellation */
	}

	return 1;
}

/* Decode a field section prefix made of <enc_ric> and <db> two varints.
 * Also set the 'S' sign bit for <db>.
 * Return a negative error if failed, 0 if not.
 */
static int qpack_decode_fs_pfx(uint64_t *enc_ric, uint64_t *db, int *sign_bit,
                               const unsigned char **raw, size_t *len)
{
	*enc_ric = qpack_get_varint(raw, len, 8);
	if (*len == (uint64_t)-1)
		return -QPACK_ERR_RIC;

	*sign_bit = **raw & 0x8;
	*db = qpack_get_varint(raw, len, 7);
	if (*len == (uint64_t)-1)
		return -QPACK_ERR_DB;

	return 0;
}

/* Decode a field section from <len> bytes length <raw> buffer.
 * Produces the output into <tmp> buffer.
 */
int qpack_decode_fs(const unsigned char *raw, size_t len, struct buffer *tmp,
                    struct http_hdr *list)
{
	uint64_t enc_ric, db;
	int s;
	unsigned int efl_type;
	int ret;
	int hdr_idx = 0;

	qpack_debug_hexdump(stderr, "[QPACK-DEC-FS] ", (const char *)raw, 0, len);

	ret = qpack_decode_fs_pfx(&enc_ric, &db, &s, &raw, &len);
	if (ret < 0) {
		qpack_debug_printf(stderr, "##ERR@%d(%d)\n", __LINE__, ret);
		goto out;
	}

	chunk_reset(tmp);
	qpack_debug_printf(stderr, "enc_ric: %llu db: %llu s=%d\n", 
	                   (unsigned long long)enc_ric, (unsigned long long)db, !!s);
	/* Decode field lines */
	while (len) {
		qpack_debug_hexdump(stderr, "raw ", (const char *)raw, 0, len);
		efl_type = *raw & QPACK_EFL_BITMASK;
		qpack_debug_printf(stderr, "efl_type=0x%02x\n", efl_type);
		if (efl_type == QPACK_LFL_WPBNM) {
			/* Literal field line with post-base name reference */
			uint64_t index, length;
			unsigned int n, h;

			qpack_debug_printf(stderr, "literal field line with post-base name reference:");
			n = *raw & 0x08;
			index = qpack_get_varint(&raw, &len, 3);
			if (len == (uint64_t)-1) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_ERR_TRUNCATED;
				goto out;
			}

			qpack_debug_printf(stderr, " n=%d index=%llu", !!n, (unsigned long long)index);
			h = *raw & 0x80;
			length = qpack_get_varint(&raw, &len, 7);
			if (len == (uint64_t)-1) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_ERR_TRUNCATED;
				goto out;
			}

			qpack_debug_printf(stderr, " h=%d length=%llu", !!h, (unsigned long long)length);

			if (len < length) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_ERR_TRUNCATED;
				goto out;
			}

			/* XXX Value string XXX */
			raw += length;
			len -= length;
		}
		else if (efl_type == QPACK_IFL_WPBI) {
			/* Indexed field line with post-base index */
			uint64_t index;

			qpack_debug_printf(stderr, "indexed field line with post-base index:");
			index = qpack_get_varint(&raw, &len, 4);
			if (len == (uint64_t)-1) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_ERR_TRUNCATED;
				goto out;
			}

			qpack_debug_printf(stderr, " index=%llu", (unsigned long long)index);
		}
		else if (efl_type & QPACK_IFL_BIT) {
			/* Indexed field line */
			uint64_t index;
			unsigned int t;

			qpack_debug_printf(stderr, "indexed field line:");
			t = efl_type & 0x40;
			index = qpack_get_varint(&raw, &len, 6);
			if (len == (uint64_t)-1) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_ERR_TRUNCATED;
				goto out;
			}

			if (t)
				list[hdr_idx++] = qpack_sht[index];

			qpack_debug_printf(stderr,  " t=%d index=%llu", !!t, (unsigned long long)index);
		}
		else if (efl_type & QPACK_LFL_WNR_BIT) {
			/* Literal field line with name reference */
			uint64_t index, length;
			unsigned int t, n, h;

			qpack_debug_printf(stderr, "Literal field line with name reference:");
			n = efl_type & 0x20;
			t = efl_type & 0x10;
			index = qpack_get_varint(&raw, &len, 4);
			if (len == (uint64_t)-1) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_ERR_TRUNCATED;
				goto out;
			}

			if (t)
				list[hdr_idx] = qpack_sht[index];

			qpack_debug_printf(stderr, " n=%d t=%d index=%llu", !!n, !!t, (unsigned long long)index);
			h = *raw & 0x80;
			length = qpack_get_varint(&raw, &len, 7);
			if (len == (uint64_t)-1) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_ERR_TRUNCATED;
				goto out;
			}

			qpack_debug_printf(stderr, " h=%d length=%llu", !!h, (unsigned long long)length);
			if (h) {
				char *trash;
				int nlen;

				trash = chunk_newstr(tmp);
				if (!trash) {
					qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
					ret = -QPACK_DECOMPRESSION_FAILED;
					goto out;
				}
				nlen = huff_dec(raw, length, trash, tmp->size - tmp->data);
				if (nlen == (uint32_t)-1) {
					qpack_debug_printf(stderr, " can't decode huffman.\n");
					ret = -QPACK_ERR_HUFFMAN;
					goto out;
				}

				qpack_debug_printf(stderr, " [name huff %d->%d '%s']", (int)length, (int)nlen, trash);
				/* makes an ist from tmp storage */
				b_add(tmp, nlen);
				list[hdr_idx].v = ist2(trash, nlen);
			}
			else {
				list[hdr_idx].v = ist2(raw, length);
			}

			if (len < length) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_ERR_TRUNCATED;
				goto out;
			}

			raw += length;
			len -= length;
			++hdr_idx;
		}
		else if (efl_type & QPACK_LFL_WLN_BIT) {
			/* Literal field line with literal name */
			unsigned int n, hname, hvalue;
			uint64_t name_len, value_len;

			qpack_debug_printf(stderr, "Literal field line with literal name:");
			n = *raw & 0x10;
			hname = *raw & 0x08;
			name_len = qpack_get_varint(&raw, &len, 3);
			if (len == (uint64_t)-1) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_ERR_TRUNCATED;
				goto out;
			}

			qpack_debug_printf(stderr, " n=%d hanme=%d name_len=%llu", !!n, !!hname, (unsigned long long)name_len);
			/* Name string */

			if (len < name_len) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_ERR_TRUNCATED;
				goto out;
			}

			raw += name_len;
			len -= name_len;
			hvalue = *raw & 0x80;
			value_len = qpack_get_varint(&raw, &len, 7);
			if (len == (uint64_t)-1) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_ERR_TRUNCATED;
				goto out;
			}

			qpack_debug_printf(stderr, " hvalue=%d value_len=%llu", !!hvalue, (unsigned long long)value_len);

			if (len < value_len) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_ERR_TRUNCATED;
				goto out;
			}

			/* XXX Value string XXX */
			raw += value_len;
			len -= value_len;
		}
		qpack_debug_printf(stderr, "\n");
	}

	/* put an end marker */
	list[hdr_idx].n = list[hdr_idx].v = IST_NULL;

 out:
	qpack_debug_printf(stderr, "-- done: ret=%d\n", ret);
	return ret;
}
