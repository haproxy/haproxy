/*
 * include/haproxy/quic_enc.h
 * This file contains QUIC varint encoding function prototypes
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

#ifndef _HAPROXY_QUIC_ENC_H
#define _HAPROXY_QUIC_ENC_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <inttypes.h>

#include <haproxy/buf.h>
#include <haproxy/chunk.h>

/* The maximum size of a variable-length QUIC integer encoded with 1 byte */
#define QUIC_VARINT_1_BYTE_MAX       ((1UL <<  6) - 1)
/* The maximum size of a variable-length QUIC integer encoded with 2 bytes */
#define QUIC_VARINT_2_BYTE_MAX       ((1UL <<  14) - 1)
/* The maximum size of a variable-length QUIC integer encoded with 4 bytes */
#define QUIC_VARINT_4_BYTE_MAX       ((1UL <<  30) - 1)
/* The maximum size of a variable-length QUIC integer encoded with 8 bytes */
#define QUIC_VARINT_8_BYTE_MAX       ((1ULL <<  62) - 1)

/* The maximum size of a variable-length QUIC integer */
#define QUIC_VARINT_MAX_SIZE       8

/* The two most significant bits of byte #0 from a QUIC packet gives the 2
 * logarithm of the length of a variable length encoded integer.
 */
#define QUIC_VARINT_BYTE_0_BITMASK 0x3f
#define QUIC_VARINT_BYTE_0_SHIFT   6

/* Returns enough log2 of first powers of two to encode QUIC variable length
 * integers.
 * Returns -1 if <val> if out of the range of lengths supported by QUIC.
 */
static inline int quic_log2(unsigned int val)
{
	switch (val) {
	case 8:
		return 3;
	case 4:
		return 2;
	case 2:
		return 1;
	case 1:
		return 0;
	default:
		return -1;
	}
}

/* Returns the size in bytes required to encode a 64bits integer if
 * not out of range (< (1 << 62)), or 0 if out of range.
 */
static inline size_t quic_int_getsize(uint64_t val)
{
	switch (val) {
	case 0 ... QUIC_VARINT_1_BYTE_MAX:
		return 1;
	case QUIC_VARINT_1_BYTE_MAX + 1 ... QUIC_VARINT_2_BYTE_MAX:
		return 2;
	case QUIC_VARINT_2_BYTE_MAX + 1 ... QUIC_VARINT_4_BYTE_MAX:
		return 4;
	case QUIC_VARINT_4_BYTE_MAX + 1 ... QUIC_VARINT_8_BYTE_MAX:
		return 8;
	default:
		return 0;
	}
}

/* Returns the maximum value of a QUIC variable-length integer with <sz> as size */
static inline uint64_t quic_max_int(size_t sz)
{
	switch (sz) {
	case 1:
		return QUIC_VARINT_1_BYTE_MAX;
	case 2:
		return QUIC_VARINT_2_BYTE_MAX;
	case 4:
		return QUIC_VARINT_4_BYTE_MAX;
	case 8:
		return QUIC_VARINT_8_BYTE_MAX;
	}

	return -1;
}

/* Decode a QUIC variable-length integer from <buf> buffer into <val>.
 * Note that the result is a 64-bits integer but with the less significant
 * 62 bits as relevant information. The most significant 2 remaining bits encode
 * the length of the integer.
 * Returns 1 if succeeded there was enough data in <buf>), 0 if not.
 */
static inline int quic_dec_int(uint64_t *val,
                               const unsigned char **buf,
                               const unsigned char *end)
{
	size_t len;

	if (*buf >= end)
		return 0;

	len = 1 << (**buf >> QUIC_VARINT_BYTE_0_SHIFT);
	if (*buf + len > end)
		return 0;

	*val = *(*buf)++ & QUIC_VARINT_BYTE_0_BITMASK;
	while (--len)
		*val = (*val << 8) | *(*buf)++;

	return 1;
}

/* Decode a QUIC variable-length integer from <b> buffer into <val> supporting wrapping.
 * Note that the result is a 64-bits integer but with the less significant
 * 62 bits as relevant information. The most significant 2 bits encode
 * the length of the integer.
 * Note that this function update <b> buffer when a variable-length integer
 * has successfully been parsed.
 * Returns 1 and if succeeded (there was enough data in <buf>), 0 if not.
 * If <retlen> is not null, increment <*retlen> by the number of bytes consumed to decode
 * the varint.
 */
static inline size_t b_quic_dec_int(uint64_t *val, struct buffer *b, size_t *retlen)
{
	const unsigned char *pos = (const unsigned char *)b_head(b);
	const unsigned char *end = (const unsigned char *)b_wrap(b);
	size_t size = b_size(b);
	size_t data = b_data(b);
	size_t save_len, len;

	if (!data)
		return 0;

	save_len = len = 1 << (*pos >> QUIC_VARINT_BYTE_0_SHIFT);
	if (data < len)
		return 0;

	*val = *pos & QUIC_VARINT_BYTE_0_BITMASK;
	if (++pos == end)
		pos -= size;
	while (--len) {
		*val = (*val << 8) | *pos;
		if (++pos == end)
			pos -= size;
	}
	if (retlen)
		*retlen += save_len;
	b_del(b, save_len);

	return 1;
}

/* Encode a QUIC variable-length integer from <val> into <buf> buffer with <end> as first
 * byte address after the end of this buffer.
 * Returns 1 if succeeded (there was enough room in buf), 0 if not.
 */
static inline int quic_enc_int(unsigned char **buf, const unsigned char *end, uint64_t val)
{
	size_t len;
	unsigned int shift;
	unsigned char size_bits, *head;

	len = quic_int_getsize(val);
	if (!len || end - *buf < len)
		return 0;

	shift = (len - 1) * 8;
	/* set the bits of byte#0 which gives the length of the encoded integer */
	size_bits = quic_log2(len) << QUIC_VARINT_BYTE_0_SHIFT;
	head = *buf;
	while (len--) {
		*(*buf)++ = val >> shift;
		shift -= 8;
	}
	*head |= size_bits;

	return 1;
}

/* Encode a QUIC variable-length integer <val> into <b> buffer. <width> can be
 * set to specify the desired output width. By default use 0 for the minimal
 * integer size. Other valid values are 1, 2, 4 or 8.
 *
 * Returns 1 on success else 0.
 */
static inline int b_quic_enc_int(struct buffer *b, uint64_t val, int width)
{
	char *pos;
	int save_width, len;

	/* width can only by 0, 1, 2, 4 or 8 */
	BUG_ON(width && (width > 8 || atleast2(width)));

	len = quic_int_getsize(val);
	if (!len)
		return 0;

	/* Check that buffer room is sufficient and width big enough if set. */
	if (b_room(b) < len || (width && width < len))
		return 0;

	if (!width)
		width = len;
	save_width = width;

	pos = b_tail(b);
	while (width--) {
		/* Encode the shifted integer or 0 if width bigger than integer length. */
		*pos++ = width >= len ? 0 : val >> (width * 8);

		if (pos == b_wrap(b))
			pos = b_orig(b);
	}

	/* set the bits of byte#0 which gives the length of the encoded integer */
	*b_tail(b) |= quic_log2(save_width) << QUIC_VARINT_BYTE_0_SHIFT;
	b_add(b, save_width);

	return 1;
}

static inline size_t quic_incint_size_diff(uint64_t val)
{
	switch (val) {
	case QUIC_VARINT_1_BYTE_MAX:
		return 1;
	case QUIC_VARINT_2_BYTE_MAX:
		return 2;
	case QUIC_VARINT_4_BYTE_MAX:
		return 4;
	default:
		return 0;
	}
}

/* Return the difference between the encoded length of <val> and the encoded
 * length of <val-1>.
 */
static inline size_t quic_decint_size_diff(uint64_t val)
{
	switch (val) {
	case QUIC_VARINT_1_BYTE_MAX + 1:
		return 1;
	case QUIC_VARINT_2_BYTE_MAX + 1:
		return 2;
	case QUIC_VARINT_4_BYTE_MAX + 1:
		return 4;
	default:
		return 0;
	}
}

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_ENC_H */
