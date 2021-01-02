/*
 * include/haproxy/protobuf.h
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

#ifndef _HAPROXY_PROTOBUF_H
#define _HAPROXY_PROTOBUF_H

#include <haproxy/api-t.h>
#include <haproxy/arg-t.h>
#include <haproxy/protobuf-t.h>
#include <haproxy/sample-t.h>

#define PBUF_VARINT_DONT_STOP_BIT       7
#define PBUF_VARINT_DONT_STOP_BITMASK  (1 << PBUF_VARINT_DONT_STOP_BIT)
#define PBUF_VARINT_DATA_BITMASK            ~PBUF_VARINT_DONT_STOP_BITMASK

/* .skip and .smp_store prototypes. */
int protobuf_skip_varint(unsigned char **pos, size_t *len, size_t vlen);
int protobuf_smp_store_varint(struct sample *smp, int type,
                              unsigned char *pos, size_t len, size_t vlen);
int protobuf_skip_64bit(unsigned char **pos, size_t *len, size_t vlen);
int protobuf_smp_store_64bit(struct sample *smp, int type,
                             unsigned char *pos, size_t len, size_t vlen);
int protobuf_skip_vlen(unsigned char **pos, size_t *len, size_t vlen);
int protobuf_smp_store_vlen(struct sample *smp, int type,
                            unsigned char *pos, size_t len, size_t vlen);
int protobuf_skip_32bit(unsigned char **pos, size_t *len, size_t vlen);
int protobuf_smp_store_32bit(struct sample *smp, int type,
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
 * Note that the field values with protocol buffers 32bit and 64bit fixed size as type
 * are sent in little-endian byte order to the network.
 */

/* Convert a little-endian ordered 32bit integer to the byte order of the host. */
static inline uint32_t pbuf_le32toh(uint32_t v)
{
	uint8_t *p = (uint8_t *)&v;
	return (p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

/* Convert a little-endian ordered 64bit integer to the byte order of the host. */
static inline uint64_t pbuf_le64toh(uint64_t v)
{
	return (uint64_t)(pbuf_le32toh(v >> 32)) << 32 | pbuf_le32toh(v);
}

/*
 * Return a protobuf type enum from <s> string if succedeed, -1 if not.
 */
int protobuf_type(const char *s)
{
	/* varint types. */
	if (strcmp(s, "int32") == 0)
		return PBUF_T_VARINT_INT32;
	else if (strcmp(s, "uint32") == 0)
		return PBUF_T_VARINT_UINT32;
	else if (strcmp(s, "sint32") == 0)
		return PBUF_T_VARINT_SINT32;
	else if (strcmp(s, "int64") == 0)
		return PBUF_T_VARINT_INT64;
	else if (strcmp(s, "uint64") == 0)
		return PBUF_T_VARINT_UINT64;
	else if (strcmp(s, "sint64") == 0)
		return PBUF_T_VARINT_SINT64;
	else if (strcmp(s, "bool") == 0)
		return PBUF_T_VARINT_BOOL;
	else if (strcmp(s, "enum") == 0)
		return PBUF_T_VARINT_ENUM;

	/* 32bit fixed size types. */
	else if (strcmp(s, "fixed32") == 0)
		return PBUF_T_32BIT_FIXED32;
	else if (strcmp(s, "sfixed32") == 0)
		return PBUF_T_32BIT_SFIXED32;
	else if (strcmp(s, "float") == 0)
		return PBUF_T_32BIT_FLOAT;

	/* 64bit fixed size types. */
	else if (strcmp(s, "fixed64") == 0)
		return PBUF_T_64BIT_FIXED64;
	else if (strcmp(s, "sfixed64") == 0)
		return PBUF_T_64BIT_SFIXED64;
	else if (strcmp(s, "double") == 0)
		return PBUF_T_64BIT_DOUBLE;
	else
		return -1;
}

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
		if (shift > 63)
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
		if (shift > 63)
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
		if (shift > 63)
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
		if (shift > 63)
			return -1;
	}

	return pos - spos;
}

/*
 * Store a varint field value in a sample from <pos> buffer
 * with <len> available bytes after having decoded it if needed
 * depending on <type> the expected protocol buffer type of the field.
 * Return 1 if succeeded, 0 if not.
 */
int protobuf_smp_store_varint(struct sample *smp, int type,
                              unsigned char *pos, size_t len, size_t vlen)
{
	switch (type) {
	case PBUF_T_BINARY:
	{
		int varint_len;

		varint_len = protobuf_varint_getlen(pos, len);
		if (varint_len == -1)
			return 0;

		smp->data.type = SMP_T_BIN;
		smp->data.u.str.area = (char *)pos;
		smp->data.u.str.data = varint_len;
		smp->flags = SMP_F_VOL_TEST;
		break;
	}

	case PBUF_T_VARINT_INT32 ... PBUF_T_VARINT_ENUM:
	{
		uint64_t varint;

		if (!protobuf_varint(&varint, pos, len))
			return 0;

		smp->data.u.sint = varint;
		smp->data.type = SMP_T_SINT;
		break;
	}

	case PBUF_T_VARINT_SINT32 ... PBUF_T_VARINT_SINT64:
	{
		uint64_t varint;

		if (!protobuf_varint(&varint, pos, len))
			return 0;

		/* zigzag decoding. */
		smp->data.u.sint = (varint >> 1) ^ -(varint & 1);
		smp->data.type = SMP_T_SINT;
		break;
	}

	default:
		return 0;

	}

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
 * with <len> available bytes after having decoded it depending on <type>
 * the expected protocol buffer type of the field.
 * Return 1 if succeeded, 0 if not.
 */
int protobuf_smp_store_64bit(struct sample *smp, int type,
                             unsigned char *pos, size_t len, size_t vlen)
{
	if (len < sizeof(uint64_t))
	    return 0;

	switch (type) {
	case PBUF_T_BINARY:
		smp->data.type = SMP_T_BIN;
		smp->data.u.str.area = (char *)pos;
		smp->data.u.str.data = sizeof(uint64_t);
		smp->flags = SMP_F_VOL_TEST;
		break;

	case PBUF_T_64BIT_FIXED64:
	case PBUF_T_64BIT_SFIXED64:
		smp->data.type = SMP_T_SINT;
		smp->data.u.sint = pbuf_le64toh(*(uint64_t *)pos);
		smp->flags = SMP_F_VOL_TEST;
		break;

	case PBUF_T_64BIT_DOUBLE:
		smp->data.type = SMP_T_SINT;
		smp->data.u.sint = pbuf_le64toh(*(double *)pos);
		smp->flags = SMP_F_VOL_TEST;
		break;

	default:
		return 0;
	}

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
int protobuf_smp_store_vlen(struct sample *smp, int type,
                            unsigned char *pos, size_t len, size_t vlen)
{
	if (len < vlen)
		return 0;

	if (type != PBUF_T_BINARY)
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
 * with <len> available bytes after having decoded it depending on <type>
 * the expected protocol buffer type of the field.
 * Return 1 if succeeded, 0 if not.
 */
int protobuf_smp_store_32bit(struct sample *smp, int type,
                             unsigned char *pos, size_t len, size_t vlen)
{
	if (len < sizeof(uint32_t))
	    return 0;

	switch (type) {
	case PBUF_T_BINARY:
		smp->data.type = SMP_T_BIN;
		smp->data.u.str.area = (char *)pos;
		smp->data.u.str.data = sizeof(uint32_t);
		smp->flags = SMP_F_VOL_TEST;
		break;

	case PBUF_T_32BIT_FIXED32:
		smp->data.type = SMP_T_SINT;
		smp->data.u.sint = pbuf_le32toh(*(uint32_t *)pos);
		smp->flags = SMP_F_VOL_TEST;
		break;

	case PBUF_T_32BIT_SFIXED32:
		smp->data.type = SMP_T_SINT;
		smp->data.u.sint = (int32_t)pbuf_le32toh(*(uint32_t *)pos);
		smp->flags = SMP_F_VOL_TEST;
		break;

	case PBUF_T_32BIT_FLOAT:
		smp->data.type = SMP_T_SINT;
		smp->data.u.sint = pbuf_le32toh(*(float *)pos);
		smp->flags = SMP_F_VOL_TEST;
		break;

	default:
		return 0;
	}

	return 1;
}

/*
 * Lookup for a protocol buffers field whose parameters are provided by <arg_p>
 * first argument in the buffer with <pos> as address and <len> as length address.
 * If found, store its value depending on the type of storage to use provided by <arg_p>
 * second argument and return 1, 0 if not.
 */
static inline int protobuf_field_lookup(const struct arg *arg_p, struct sample *smp,
                                        unsigned char **pos, size_t *len)
{
	unsigned int *fid;
	size_t fid_sz;
	int type;
	uint64_t elen;
	int field;

	fid = arg_p[0].data.fid.ids;
	fid_sz = arg_p[0].data.fid.sz;
	type = arg_p[1].data.sint;

	/* Length of the length-delimited messages if any. */
	elen = 0;
	field = 0;

	while (field < fid_sz) {
		int found;
		uint64_t key, sleft;
		struct protobuf_parser_def *pbuf_parser = NULL;
		unsigned int wire_type, field_number;

		if ((ssize_t)*len <= 0)
			return 0;

		/* Remaining bytes saving. */
		sleft = *len;

		/* Key decoding */
		if (!protobuf_decode_varint(&key, pos, len))
			return 0;

		wire_type = key & 0x7;
		field_number = key >> 3;
		found = field_number == fid[field];

		/* Skip the data if the current field does not match. */
		switch (wire_type) {
		case PBUF_TYPE_VARINT:
		case PBUF_TYPE_32BIT:
		case PBUF_TYPE_64BIT:
			pbuf_parser = &protobuf_parser_defs[wire_type];
			if (!found && !pbuf_parser->skip(pos, len, 0))
				return 0;
			break;

		case PBUF_TYPE_LENGTH_DELIMITED:
			/* Decode the length of this length-delimited field. */
			if (!protobuf_decode_varint(&elen, pos, len) || elen > *len)
				return 0;

			/* The size of the current field is computed from here to skip
			 * the bytes used to encode the previous length.*
			 */
			sleft = *len;
			pbuf_parser = &protobuf_parser_defs[wire_type];
			if (!found && !pbuf_parser->skip(pos, len, elen))
				return 0;
			break;

		default:
			return 0;
		}

		/* Store the data if found. Note that <pbuf_parser> is not NULL */
		if (found && field == fid_sz - 1)
			return pbuf_parser->smp_store(smp, type, *pos, *len, elen);

		if ((ssize_t)(elen) > 0)
			elen -= sleft - *len;

		if (found) {
			field++;
		}
		else if ((ssize_t)elen <= 0) {
			field = 0;
		}
	}

	return 0;
}

#endif /* _HAPROXY_PROTOBUF_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
