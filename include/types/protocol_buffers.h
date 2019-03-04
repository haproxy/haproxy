/*
 * include/types/protocol_buffers.h
 * This file contains structure declarations for protocol buffers.
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

#ifndef _TYPES_PROTOCOL_BUFFERS_H
#define _TYPES_PROTOCOL_BUFFERS_H

enum protobuf_wire_type {
	PBUF_TYPE_VARINT,
	PBUF_TYPE_64BIT,
	PBUF_TYPE_LENGTH_DELIMITED,
	PBUF_TYPE_START_GROUP,      /* Deprecated */
	PBUF_TYPE_STOP_GROUP,       /* Deprecated */
	PBUF_TYPE_32BIT,
};

struct pbuf_fid {
	unsigned int *ids;
	size_t sz;
};

struct protobuf_parser_def {
	int (*skip)(unsigned char **pos, size_t *left, size_t vlen);
	int (*smp_store)(struct sample *, unsigned char *pos, size_t left, size_t vlen);
};

#endif /* _TYPES_PROTOCOL_BUFFERS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
