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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <import/ist.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/h3.h>
#include <haproxy/mux_quic.h>
#include <haproxy/qpack-t.h>
#include <haproxy/qpack-dec.h>
#include <haproxy/qpack-tbl.h>
#include <haproxy/hpack-huff.h>
#include <haproxy/hpack-tbl.h>
#include <haproxy/http-hdr.h>
#include <haproxy/tools.h>

#if defined(DEBUG_QPACK)
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
	ret = *raw++ & ((1ULL << b) - 1);
	if (ret != (uint64_t)((1ULL << b) - 1))
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

/* Decode an encoder stream.
 *
 * Returns 0 on success else non-zero.
 */
int qpack_decode_enc(struct buffer *buf, int fin, void *ctx)
{
	struct qcs *qcs = ctx;
	size_t len;
	unsigned char inst;

	/* RFC 9204 4.2. Encoder and Decoder Streams
	 *
	 * The sender MUST NOT close either of these streams, and the receiver
	 * MUST NOT request that the sender close either of these streams.
	 * Closure of either unidirectional stream type MUST be treated as a
	 * connection error of type H3_CLOSED_CRITICAL_STREAM.
	 */
	if (fin) {
		qcc_set_error(qcs->qcc, H3_ERR_CLOSED_CRITICAL_STREAM, 1);
		return -1;
	}

	len = b_data(buf);
	qpack_debug_hexdump(stderr, "[QPACK-DEC-ENC] ", b_head(buf), 0, len);

	if (!len) {
		qpack_debug_printf(stderr, "[QPACK-DEC-ENC] empty stream\n");
		return 0;
	}

	inst = (unsigned char)*b_head(buf) & QPACK_ENC_INST_BITMASK;
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
		int capacity = *b_head(buf) & 0x1f;

		/* RFC 9204 4.3.1. Set Dynamic Table Capacity
		 *
		 * The decoder MUST treat a new dynamic table capacity
		 * value that exceeds this limit as a connection error of type
		 * QPACK_ENCODER_STREAM_ERROR.
		 */
		if (capacity) {
			qcc_set_error(qcs->qcc, QPACK_ERR_ENCODER_STREAM_ERROR, 1);
			return -1;
		}

	}

	return 0;
}

/* Decode an decoder stream.
 *
 * Returns 0 on success else non-zero.
 */
int qpack_decode_dec(struct buffer *buf, int fin, void *ctx)
{
	struct qcs *qcs = ctx;
	size_t len;
	unsigned char inst;

	/* RFC 9204 4.2. Encoder and Decoder Streams
	 *
	 * The sender MUST NOT close either of these streams, and the receiver
	 * MUST NOT request that the sender close either of these streams.
	 * Closure of either unidirectional stream type MUST be treated as a
	 * connection error of type H3_CLOSED_CRITICAL_STREAM.
	 */
	if (fin) {
		qcc_set_error(qcs->qcc, H3_ERR_CLOSED_CRITICAL_STREAM, 1);
		return -1;
	}

	len = b_data(buf);
	qpack_debug_hexdump(stderr, "[QPACK-DEC-DEC] ", b_head(buf), 0, len);

	if (!len) {
		qpack_debug_printf(stderr, "[QPACK-DEC-DEC] empty stream\n");
		return 0;
	}

	inst = (unsigned char)*b_head(buf) & QPACK_DEC_INST_BITMASK;
	if (inst == QPACK_DEC_INST_ICINC) {
		/* Insert count increment */

		/* RFC 9204 4.4.3. Insert Count Increment
		 *
		 * An encoder that receives an Increment field equal to zero, or one
		 * that increases the Known Received Count beyond what the encoder has
		 * sent, MUST treat this as a connection error of type
		 * QPACK_DECODER_STREAM_ERROR.
		 */

		/* For the moment haproxy does not emit dynamic table insertion. */
		qcc_set_error(qcs->qcc, QPACK_ERR_DECODER_STREAM_ERROR, 1);
		return -1;
	}
	else if (inst & QPACK_DEC_INST_SACK) {
		/* Section Acknowledgment */
	}
	else if (inst & QPACK_DEC_INST_SCCL) {
		/* Stream cancellation */
	}

	return 0;
}

/* Decode a field section prefix made of <enc_ric> and <db> two varints.
 * Also set the 'S' sign bit for <db>.
 * Return a negative error if failed, 0 if not.
 */
static int qpack_decode_fs_pfx(uint64_t *enc_ric, uint64_t *db, int *sign_bit,
                               const unsigned char **raw, uint64_t *len)
{
	*enc_ric = qpack_get_varint(raw, len, 8);
	if (*len == (uint64_t)-1)
		return -QPACK_RET_RIC;

	*sign_bit = **raw & 0x8;
	*db = qpack_get_varint(raw, len, 7);
	if (*len == (uint64_t)-1)
		return -QPACK_RET_DB;

	return 0;
}

/* Decode a field section from the <raw> buffer of <len> bytes. Each parsed
 * header is inserted into <list> of <list_size> entries max and uses <tmp> as
 * a storage for some elements pointing into it. An end marker is inserted at
 * the end of the list with empty strings as name/value.
 *
 * Returns the number of headers inserted into list excluding the end marker.
 * In case of error, a negative code QPACK_RET_* is returned.
 */
int qpack_decode_fs(const unsigned char *raw, uint64_t len, struct buffer *tmp,
                    struct http_hdr *list, int list_size)
{
	struct ist name, value;
	uint64_t enc_ric, db;
	int s;
	unsigned int efl_type;
	int ret;
	int hdr_idx = 0;

	qpack_debug_hexdump(stderr, "[QPACK-DEC-FS] ", (const char *)raw, 0, len);

	/* parse field section prefix */
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
		if (hdr_idx >= list_size) {
			qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
			ret = -QPACK_RET_TOO_LARGE;
			goto out;
		}

		/* parse field line representation */
		efl_type = *raw & QPACK_EFL_BITMASK;
		qpack_debug_printf(stderr, "efl_type=0x%02x\n", efl_type);

		if (efl_type == QPACK_LFL_WPBNM) {
			/* Literal field line with post-base name reference
			 * TODO adjust this when dynamic table support is implemented.
			 */
#if 0
			uint64_t index __maybe_unused, length;
			unsigned int n __maybe_unused, h __maybe_unused;

			qpack_debug_printf(stderr, "literal field line with post-base name reference:");
			n = *raw & 0x08;
			index = qpack_get_varint(&raw, &len, 3);
			if (len == (uint64_t)-1) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_RET_TRUNCATED;
				goto out;
			}

			qpack_debug_printf(stderr, " n=%d index=%llu", !!n, (unsigned long long)index);
			h = *raw & 0x80;
			length = qpack_get_varint(&raw, &len, 7);
			if (len == (uint64_t)-1) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_RET_TRUNCATED;
				goto out;
			}

			qpack_debug_printf(stderr, " h=%d length=%llu", !!h, (unsigned long long)length);

			if (len < length) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_RET_TRUNCATED;
				goto out;
			}

			raw += length;
			len -= length;
#endif

			/* RFC9204 2.2.3 Invalid References
			 *
			 * If the decoder encounters a reference in a field line representation
			 * to a dynamic table entry that has already been evicted or that has an
			 * absolute index greater than or equal to the declared Required Insert
			 * Count (Section 4.5.1), it MUST treat this as a connection error of
			 * type QPACK_DECOMPRESSION_FAILED.
			 */
			return -QPACK_RET_DECOMP;
		}
		else if (efl_type == QPACK_IFL_WPBI) {
			/* Indexed field line with post-base index
			 * TODO adjust this when dynamic table support is implemented.
			 */
#if 0
			uint64_t index __maybe_unused;

			qpack_debug_printf(stderr, "indexed field line with post-base index:");
			index = qpack_get_varint(&raw, &len, 4);
			if (len == (uint64_t)-1) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_RET_TRUNCATED;
				goto out;
			}

			qpack_debug_printf(stderr, " index=%llu", (unsigned long long)index);
#endif

			/* RFC9204 2.2.3 Invalid References
			 *
			 * If the decoder encounters a reference in a field line representation
			 * to a dynamic table entry that has already been evicted or that has an
			 * absolute index greater than or equal to the declared Required Insert
			 * Count (Section 4.5.1), it MUST treat this as a connection error of
			 * type QPACK_DECOMPRESSION_FAILED.
			 */
			return -QPACK_RET_DECOMP;
		}
		else if (efl_type & QPACK_IFL_BIT) {
			/* Indexed field line */
			uint64_t index;
			unsigned int static_tbl;

			qpack_debug_printf(stderr, "indexed field line:");
			static_tbl = efl_type & 0x40;
			index = qpack_get_varint(&raw, &len, 6);
			if (len == (uint64_t)-1) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_RET_TRUNCATED;
				goto out;
			}

			if (static_tbl && index < QPACK_SHT_SIZE) {
				name = qpack_sht[index].n;
				value = qpack_sht[index].v;
			}
			else {
				/* RFC9204 2.2.3 Invalid References
				 *
				 * If the decoder encounters a reference in a field line representation
				 * to a dynamic table entry that has already been evicted or that has an
				 * absolute index greater than or equal to the declared Required Insert
				 * Count (Section 4.5.1), it MUST treat this as a connection error of
				 * type QPACK_DECOMPRESSION_FAILED.
				 *
				 * TODO adjust this when dynamic table support is implemented.
				 */
				return -QPACK_RET_DECOMP;
			}

			qpack_debug_printf(stderr,  " t=%d index=%llu", !!static_tbl, (unsigned long long)index);
		}
		else if (efl_type & QPACK_LFL_WNR_BIT) {
			/* Literal field line with name reference */
			uint64_t index, length;
			unsigned int static_tbl, n __maybe_unused, h;

			qpack_debug_printf(stderr, "Literal field line with name reference:");
			n = efl_type & 0x20;
			static_tbl = efl_type & 0x10;
			index = qpack_get_varint(&raw, &len, 4);
			if (len == (uint64_t)-1) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_RET_TRUNCATED;
				goto out;
			}

			if (static_tbl && index < QPACK_SHT_SIZE) {
				name = qpack_sht[index].n;
			}
			else {
				/* RFC9204 2.2.3 Invalid References
				 *
				 * If the decoder encounters a reference in a field line representation
				 * to a dynamic table entry that has already been evicted or that has an
				 * absolute index greater than or equal to the declared Required Insert
				 * Count (Section 4.5.1), it MUST treat this as a connection error of
				 * type QPACK_DECOMPRESSION_FAILED.
				 *
				 * TODO adjust this when dynamic table support is implemented.
				 */
				return -QPACK_RET_DECOMP;
			}

			qpack_debug_printf(stderr, " n=%d t=%d index=%llu", !!n, !!static_tbl, (unsigned long long)index);
			h = *raw & 0x80;
			length = qpack_get_varint(&raw, &len, 7);
			if (len == (uint64_t)-1) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_RET_TRUNCATED;
				goto out;
			}

			qpack_debug_printf(stderr, " h=%d length=%llu", !!h, (unsigned long long)length);
			if (h) {
				char *trash;
				int nlen;

				trash = chunk_newstr(tmp);
				if (!trash) {
					qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
					ret = -QPACK_RET_TOO_LARGE;
					goto out;
				}
				nlen = huff_dec(raw, length, trash, tmp->size - tmp->data);
				if (nlen == (uint32_t)-1) {
					qpack_debug_printf(stderr, " can't decode huffman.\n");
					ret = -QPACK_RET_HUFFMAN;
					goto out;
				}

				qpack_debug_printf(stderr, " [name huff %d->%d '%s']", (int)length, (int)nlen, trash);
				/* makes an ist from tmp storage */
				b_add(tmp, nlen);
				value = ist2(trash, nlen);
			}
			else {
				value = ist2(raw, length);
			}

			if (len < length) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_RET_TRUNCATED;
				goto out;
			}

			raw += length;
			len -= length;
		}
		else if (efl_type & QPACK_LFL_WLN_BIT) {
			/* Literal field line with literal name */
			unsigned int n __maybe_unused, hname, hvalue;
			uint64_t name_len, value_len;

			qpack_debug_printf(stderr, "Literal field line with literal name:");
			n = *raw & 0x10;
			hname = *raw & 0x08;
			name_len = qpack_get_varint(&raw, &len, 3);
			if (len == (uint64_t)-1) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_RET_TRUNCATED;
				goto out;
			}

			qpack_debug_printf(stderr, " n=%d hname=%d name_len=%llu", !!n, !!hname, (unsigned long long)name_len);
			/* Name string */

			if (len < name_len) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_RET_TRUNCATED;
				goto out;
			}

			if (hname) {
				char *trash;
				int nlen;

				trash = chunk_newstr(tmp);
				if (!trash) {
					qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
					ret = -QPACK_RET_TOO_LARGE;
					goto out;
				}
				nlen = huff_dec(raw, name_len, trash, tmp->size - tmp->data);
				if (nlen == (uint32_t)-1) {
					qpack_debug_printf(stderr, " can't decode huffman.\n");
					ret = -QPACK_RET_HUFFMAN;
					goto out;
				}

				qpack_debug_printf(stderr, " [name huff %d->%d '%s']", (int)name_len, (int)nlen, trash);
				/* makes an ist from tmp storage */
				b_add(tmp, nlen);
				name = ist2(trash, nlen);
			}
			else {
				name = ist2(raw, name_len);
			}

			raw += name_len;
			len -= name_len;

			hvalue = *raw & 0x80;
			value_len = qpack_get_varint(&raw, &len, 7);
			if (len == (uint64_t)-1) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_RET_TRUNCATED;
				goto out;
			}

			qpack_debug_printf(stderr, " hvalue=%d value_len=%llu", !!hvalue, (unsigned long long)value_len);

			if (len < value_len) {
				qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
				ret = -QPACK_RET_TRUNCATED;
				goto out;
			}

			if (hvalue) {
				char *trash;
				int nlen;

				trash = chunk_newstr(tmp);
				if (!trash) {
					qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
					ret = -QPACK_RET_TOO_LARGE;
					goto out;
				}
				nlen = huff_dec(raw, value_len, trash, tmp->size - tmp->data);
				if (nlen == (uint32_t)-1) {
					qpack_debug_printf(stderr, " can't decode huffman.\n");
					ret = -QPACK_RET_HUFFMAN;
					goto out;
				}

				qpack_debug_printf(stderr, " [name huff %d->%d '%s']", (int)value_len, (int)nlen, trash);
				/* makes an ist from tmp storage */
				b_add(tmp, nlen);
				value = ist2(trash, nlen);
			}
			else {
				value = ist2(raw, value_len);
			}

			raw += value_len;
			len -= value_len;
		}

		/* We must not accept empty header names (forbidden by the spec and used
		 * as a list termination).
		 */
		if (!name.len) {
			qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
			ret = -QPACK_RET_DECOMP;
			goto out;
		}

		list[hdr_idx].n = name;
		list[hdr_idx].v = value;
		++hdr_idx;

		qpack_debug_printf(stderr, "\n");
	}

	if (hdr_idx >= list_size) {
		qpack_debug_printf(stderr, "##ERR@%d\n", __LINE__);
		ret = -QPACK_RET_TOO_LARGE;
		goto out;
	}

	/* put an end marker */
	list[hdr_idx].n = list[hdr_idx].v = IST_NULL;
	ret = hdr_idx;

 out:
	qpack_debug_printf(stderr, "-- done: ret=%d\n", ret);
	return ret;
}

/* Convert return value from qpack_decode_fs() to a standard error code usable
 * in CONNECTION_CLOSE or -1 for an internal error.
 */
int qpack_err_decode(const int value)
{
	return (value == -QPACK_RET_DECOMP) ? QPACK_ERR_DECOMPRESSION_FAILED : -1;
}
