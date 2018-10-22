/*
 * include/types/htx.h
 * This file contains the internal HTTP definitions.
 *
 * Copyright (C) 2018 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
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

#ifndef _TYPES_HTX_H
#define _TYPES_HTX_H

#include <common/ist.h>
#include <types/sample.h>

/*
 * The internal representation of an HTTP message is a contiguous array
 * containing both the blocks (htx_blk) and their contents. Blocks are stored
 * starting from the end of the array while their contents are stored at the
 * beginning.
 *
 * As data are sent to the peer, blocks and contents are released at the
 * edges. This free space is reused when no more space left. So blocks and
 * contents may wrap, not necessarily the same time.
 *
 * An HTTP block is as well a header as a body part or a trailer part. For all
 * these types of block, a content is attached to the block. It can also be a
 * mark, like the end-of-headers or end-of-message. For these blocks, there is
 * no content but it count for a byte. It is important to not skip it when data
 * are forwarded. An HTTP block is composed of 2 fields:
 *
 *     - .info : It a 32 bits field containing the block's type on 4 bits
 *               followed by content' length. See below for details.
 *
 *     - .addr : The content's address, if any, relatively to the beginning the
 *               array used to store the HTTP message itself.
 *
 * htx_blk.info representation:
 *
 *   0b 0000 0000 0000 0000 0000 0000 0000 0000
 *      ---- ------------------------ ---------
 *      type     value (1 MB max)     name length (header)
 *           ----------------------------------
 *                data length (256 MB max)
 *    (body, method, path, version, status, reason, trailers)
 *
 *   types:
 *     - 0000 = request  start-line
 *     - 0001 = response start-line
 *     - 0010 = header
 *     - 0011 = pseudo-header ou "special" header
 *     - 0100 = end-of-headers
 *     - 0101 = data
 *     - 0110 = end-of-data
 *     - 0111 = trailer
 *     - 1000 = end-of-message
 *       ...
 *     - 1101 = out-of-band
 *     - 1110 = error
 *     - 1111 = unused
 *
 */

/* HTX flags */
#define HTX_FL_NONE              0x00000000
#define HTX_FL_PARSING_ERROR     0x00000001


/* Pseudo header types (max 255). */
enum htx_phdr_type {
	HTX_PHDR_UNKNOWN =  0,
	HTX_PHDR_SIZE,
};

/* HTTP block's type (max 15). */
enum htx_blk_type {
	HTX_BLK_REQ_SL =  0, /* Request start-line */
	HTX_BLK_RES_SL =  1, /* Response start-line */
	HTX_BLK_HDR    =  2, /* header name/value block */
	HTX_BLK_PHDR   =  3, /* pseudo header block */
	HTX_BLK_EOH    =  4, /* end-of-headers block */
	HTX_BLK_DATA   =  5, /* data block */
	HTX_BLK_EOD    =  6, /* end-of-data block */
	HTX_BLK_TLR    =  7, /* trailer name/value block */
	HTX_BLK_EOM    =  8, /* end-of-message block */
	/* 9 .. 13 unused */
	HTX_BLK_OOB    = 14, /* Out of band block, don't alter the parser */
	HTX_BLK_UNUSED = 15, /* unused/removed block */
};

/* One HTTP block descriptor */
struct htx_blk {
	uint32_t addr; /* relative storage address of a data block */
	uint32_t info; /* information about data stored */
};

struct htx_ret {
	int32_t ret;
	struct htx_blk *blk;
};

union htx_sl {
	struct {
		enum http_meth_t meth; /* method */
		int m_len;             /* METHOD length */
		int u_len;             /* URI length */
		int v_len;             /* VERSION length */
		char l[0];
	} rq;                          /* request line : field, length, data */
	struct {
		uint16_t status;       /* status code */
		int v_len;             /* VERSION length */
		int c_len;             /* CODE length */
		int r_len;             /* REASON length */
		char l[0];
	} st;                          /* status line : field, length, data */
};

/* Internal representation of an HTTP message */
struct htx {
	uint32_t size;   /* the array size, in bytes, used to store the HTTP message itself */
	uint32_t data;   /* the data size, in bytes. To known to total size used by all allocated
			  * blocks (blocks and their contents), you need to add size used by blocks,
			  * i.e. [ used * sizeof(struct htx_blk *) ] */

	uint32_t used;   /* number of blocks in use */
	uint32_t tail;   /* last inserted block */
	uint32_t front;  /* block's position of the first content before the blocks table */
	uint32_t wrap;   /* the position were the blocks table wraps, if any */

	uint64_t extra;  /* known bytes amount remaining to receive */
	uint32_t flags;  /* HTX_FL_* */

	struct htx_blk blocks[0]; /* Blocks representing the HTTP message itself */
};

#endif /* _TYPES_HTX_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
