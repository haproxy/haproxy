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

#include <stdint.h>
#include <types/protocol_buffers.h>
#include <proto/sample.h>

#define PBUF_VARINT_DONT_STOP_BIT       7
#define PBUF_VARINT_DONT_STOP_BITMASK  (1 << PBUF_VARINT_DONT_STOP_BIT)
#define PBUF_VARINT_DATA_BITMASK            ~PBUF_VARINT_DONT_STOP_BITMASK

/* .skip and .smp_store prototypes. */
int protobuf_skip_varint(unsigned char **pos, size_t *len, size_t vlen);
int protobuf_smp_store_varint(struct sample *smp,
                              unsigned char *pos, size_t len, size_t vlen);
int protobuf_skip_64bit(unsigned char **pos, size_t *len, size_t vlen);
int protobuf_smp_store_64bit(struct sample *smp,
                             unsigned char *pos, size_t len, size_t vlen);
int protobuf_skip_vlen(unsigned char **pos, size_t *len, size_t vlen);
int protobuf_smp_store_vlen(struct sample *smp,
                            unsigned char *pos, size_t len, size_t vlen);
int protobuf_skip_32bit(unsigned char **pos, size_t *len, size_t vlen);
int protobuf_smp_store_32bit(struct sample *smp,
                             unsigned char *pos, size_t len, size_t vlen);

struct protobuf_parser_def protobuf_parser_defs [] = {
	[PBUF_TYPE_VARINT          ] = {
		.skip      = protobuf_skip_varint,
		.smp_store = protobuf_smp_store_varint,
	},
	[PBUF_TYPE_64BIT           ] = {
		.skip      = protobuf_skip_64bit,
		.smp_store = protobuf_smp_store_64bit,
	},
	[PBUF_TYPE_LENGTH_DELIMITED] = {
		.skip      = protobuf_skip_vlen,
		.smp_store = protobuf_smp_store_vlen,
	},
	[PBUF_TYPE_START_GROUP     ] = {
		/* XXX Deprecated XXX */
	},
	[PBUF_TYPE_STOP_GROUP      ] = {
		/* XXX Deprecated XXX */
	},
	[PBUF_TYPE_32BIT           ] = {
		.skip      = protobuf_skip_32bit,
		.smp_store = protobuf_smp_store_32bit,
	},
};

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
int
protobuf_skip_varint(unsigned char **pos, size_t *len, size_t vlen)
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
protobuf_varint_getlen(unsigned char *pos, size_t len)
{
	unsigned char *spos;
	unsigned int shift;

	shift = 0;
	spos = pos;

	while (len > 0) {
		int stop = !(*pos & PBUF_VARINT_DONT_STOP_BITMASK);

		++pos;
		--len;

		if (stop)
			break;
		else if (!len)
			return -1;

		shift += 7;
		/* The maximum length in bytes of a 64-bit encoded value is 10. */
		if (shift > 70)
			return -1;
	}

	return pos - spos;
}

/*
 * Store a raw varint field value in a sample from <pos> buffer
 * with <len> available bytes.
 * Return 1 if succeeded, 0 if not.
 */
int protobuf_smp_store_varint(struct sample *smp,
                              unsigned char *pos, size_t len, size_t vlen)
{
	int varint_len;

	varint_len = protobuf_varint_getlen(pos, len);
	if (varint_len == -1)
		return 0;

	smp->data.type = SMP_T_BIN;
	smp->data.u.str.area = (char *)pos;
	smp->data.u.str.data = varint_len;
	smp->flags = SMP_F_VOL_TEST;

	return 1;
}

/*
 * Move forward <*pos> buffer by 8 bytes. Used to skip a 64bit field.
 */
int protobuf_skip_64bit(unsigned char **pos, size_t *len, size_t vlen)
{
	if (*len < sizeof(uint64_t))
	    return 0;

	*pos += sizeof(uint64_t);
	*len -= sizeof(uint64_t);

	return 1;
}

/*
 * Store a fixed size 64bit field value in a sample from <pos> buffer
 * with <len> available bytes.
 * Return 1 if succeeded, 0 if not.
 */
int protobuf_smp_store_64bit(struct sample *smp,
                             unsigned char *pos, size_t len, size_t vlen)
{
	if (len < sizeof(uint64_t))
	    return 0;

	smp->data.type = SMP_T_BIN;
	smp->data.u.str.area = (char *)pos;
	smp->data.u.str.data = sizeof(uint64_t);
	smp->flags = SMP_F_VOL_TEST;

	return 1;
}

/*
 * Move forward <*pos> buffer by <vlen> bytes. Use to skip a length-delimited
 * field.
 */
int protobuf_skip_vlen(unsigned char **pos, size_t *len, size_t vlen)
{
	if (*len < vlen)
		return 0;

	*pos += vlen;
	*len -= vlen;

	return 1;
}

/*
 * Store a <vlen>-bytes length-delimited field value in a sample from <pos>
 * buffer with <len> available bytes.
 * Return 1 if succeeded, 0 if not.
 */
int protobuf_smp_store_vlen(struct sample *smp,
                            unsigned char *pos, size_t len, size_t vlen)
{
	if (len < vlen)
		return 0;

	smp->data.type = SMP_T_BIN;
	smp->data.u.str.area = (char *)pos;
	smp->data.u.str.data = vlen;
	smp->flags = SMP_F_VOL_TEST;

	return 1;
}

/*
 * Move forward <*pos> buffer by 4 bytes. Used to skip a 32bit field.
 */
int protobuf_skip_32bit(unsigned char **pos, size_t *len, size_t vlen)
{
	if (*len < sizeof(uint32_t))
	    return 0;

	*pos += sizeof(uint32_t);
	*len -= sizeof(uint32_t);

	return 1;
}

/*
 * Store a fixed size 32bit field value in a sample from <pos> buffer
 * with <len> available bytes.
 * Return 1 if succeeded, 0 if not.
 */
int protobuf_smp_store_32bit(struct sample *smp,
                             unsigned char *pos, size_t len, size_t vlen)
{
	if (len < sizeof(uint32_t))
	    return 0;

	smp->data.type = SMP_T_BIN;
	smp->data.u.str.area = (char *)pos;
	smp->data.u.str.data = sizeof(uint32_t);
	smp->flags = SMP_F_VOL_TEST;

	return 1;
}

#endif /* _PROTO_PROTOCOL_BUFFERS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
