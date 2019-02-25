/*
 * include/proto/protocol_buffers.h
 * This file contains functions and macros declarations for protocol buffers decoding.
 *
 * Copyright 2012 Willy Tarreau <w@1wt.eu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _PROTO_PROTOCOL_BUFFERS_H
#define _PROTO_PROTOCOL_BUFFERS_H

#include <types/protocol_buffers.h>

#define PBUF_TYPE_VARINT           0
#define PBUF_TYPE_64BIT            1
#define PBUF_TYPE_LENGTH_DELIMITED 2
#define PBUF_TYPE_START_GROUP      3
#define PBUF_TYPE_STOP_GROUP       4
#define PBUF_TYPE_32BIT            5

#define PBUF_VARINT_DONT_STOP_BIT       7
#define PBUF_VARINT_DONT_STOP_BITMASK  (1 << PBUF_VARINT_DONT_STOP_BIT)
#define PBUF_VARINT_DATA_BITMASK            ~PBUF_VARINT_DONT_STOP_BITMASK

/*
 * Decode a protocol buffers varint located in a buffer at <pos> address with
 * <len> as length. The decoded value is stored at <val>.
 * Returns 1 if succeeded, 0 if not.
 */
static inline int
protobuf_varint(uint64_t *val, unsigned char *pos, size_t len)
{
	unsigned int shift;

	*val = 0;
	shift = 0;

	while (len > 0) {
		int stop = !(*pos & PBUF_VARINT_DONT_STOP_BITMASK);

		*val |= ((uint64_t)(*pos & PBUF_VARINT_DATA_BITMASK)) << shift;

		++pos;
		--len;

		if (stop)
			break;
		else if (!len)
			return 0;

		shift += 7;
		/* The maximum length in bytes of a 64-bit encoded value is 10. */
		if (shift > 70)
			return 0;
	}

	return 1;
}

/*
 * Decode a protocol buffers varint located in a buffer at <pos> offset address with
 * <len> as length address. Update <pos> and <len> consequently. Decrease <*len>
 * by the number of decoded bytes. The decoded value is stored at <val>.
 * Returns 1 if succeeded, 0 if not.
 */
static inline int
protobuf_decode_varint(uint64_t *val, unsigned char **pos, size_t *len)
{
	unsigned int shift;

	*val = 0;
	shift = 0;

	while (*len > 0) {
		int stop = !(**pos & PBUF_VARINT_DONT_STOP_BITMASK);

		*val |= ((uint64_t)**pos & PBUF_VARINT_DATA_BITMASK) << shift;

		++*pos;
		--*len;

		if (stop)
			break;
		else if (!*len)
			return 0;

		shift += 7;
		/* The maximum length in bytes of a 64-bit encoded value is 10. */
		if (shift > 70)
			return 0;
	}

	return 1;
}

/*
 * Skip a protocol buffer varint found at <pos> as position address with <len>
 * as available length address. Update <*pos> to make it point to the next
 * available byte. Decrease <*len> by the number of skipped bytes.
 * Returns 1 if succeeded, 0 if not.
 */
static inline int
protobuf_skip_varint(unsigned char **pos, size_t *len)
{
	unsigned int shift;

	shift = 0;

	while (*len > 0) {
		int stop = !(**pos & PBUF_VARINT_DONT_STOP_BITMASK);

		++*pos;
		--*len;

		if (stop)
			break;
		else if (!*len)
			return 0;

		shift += 7;
		/* The maximum length in bytes of a 64-bit encoded value is 10. */
		if (shift > 70)
			return 0;
	}

	return 1;
}

/*
 * If succeeded, return the length of a prococol buffers varint found at <pos> as
 * position address, with <len> as address of the available bytes at <*pos>.
 * Update <*pos> to make it point to the next available byte. Decrease <*len>
 * by the number of bytes used to encode this varint.
 * Return -1 if failed.
 */
static inline int
protobuf_varint_getlen(unsigned char **pos, size_t *len)
{
	unsigned char *spos;
	unsigned int shift;

	shift = 0;
	spos = *pos;

	while (*len > 0) {
		int stop = !(**pos & PBUF_VARINT_DONT_STOP_BITMASK);

		++*pos;
		--*len;

		if (stop)
			break;
		else if (!*len)
			return -1;

		shift += 7;
		/* The maximum length in bytes of a 64-bit encoded value is 10. */
		if (shift > 70)
			return -1;
	}

	return *pos - spos;
}

#endif /* _PROTO_PROTOCOL_BUFFERS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
