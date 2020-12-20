/*
 * include/haproxy/htx-t.h
 * This file declares the types and constants used the internal HTTP messages
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

#ifndef _HAPROXY_HTX_T_H
#define _HAPROXY_HTX_T_H

#include <haproxy/api.h>
#include <haproxy/http-t.h>

/*
 * The internal representation of an HTTP message, called HTX, is a structure
 * with useful information on the message followed by a contiguous array
 * containing parts of the message, called blocks. A block is composed of
 * metadata (htx_blk) and the associated payload. Blocks' metadata are stored
 * starting from the end of the array while their payload are stored at the
 * beginning. Blocks' metadata are often simply called blocks. it is a misuse of
 * language that's simplify explanations.
 *
 *
 *  +-----+---------------+------------------------------+--------------+
 *  | HTX |  PAYLOADS ==> |                              | <== HTX_BLKs |
 *  +-----+---------------+------------------------------+--------------+
 *        ^
 *        blocks[] (the beginning of the bocks array)
 *
 *
 * The blocks part remains linear and sorted. You may think about it as an array
 * with negative indexes. But, instead of using negative indexes, we use
 * positive positions to identify a block. This position is then converted to a
 * address relatively to the beginning of the blocks array.
 *
 *
 *      .....--+------------------------------+-----+-----+
 *             |                       ...    | BLK | BLK |
 *      .....--+------------------------------+-----+-----+
 *                                            ^     ^
 *                            Addr of the block     Addr of the block
 *                            at the position 1     at the position 0
 *
 *
 * The payloads part is a raw space that may wrap. You never access to a block's
 * payload directly. Instead you get a block to retrieve the address of its
 * payload. When no more space left between blocks and payloads parts, the free
 * space at the beginning, if any, is used.
 *
 *
 *        +----------- WRAPPING ------------------------+
 *        |                                             |
 *        V                                             |
 *  +-----+-------------+---------------+---------------++--------------+
 *  | HTX | PAYLOAD ==> |               |  PAYLOADS ==X || X== HTX_BLKs |
 *  +-----+-------------+---------------+---------------++--------------+
 *
 *
 * The blocks part, on its side, never wrap. If we have no space to allocate a
 * new block and if there is a hole at the beginning of the blocks part (so at
 * the end of the blocks array), we move back all blocks.x
 *
 *
 *    ...+--------------+----------+   blocks  ...+----------+--------------+
 *       | X== HTX_BLKS |          |   defrag     |          | <== HTX_BLKS |
 *    ...+--------------+----------+   =====>  ...+----------+--------------+
 *
 *
 * At the end, if payload wrapping or blocks defragmentation is not enough, some
 * free space may be get back with a full defragmentation. This way, the holes in
 * the middle are not reusable but count in the available free space. The only
 * way to reuse this lost space is to fully defragmenate the HTX message.
 *
 *                                   - * -
 *
 * An HTX block is as well a header as a body part or a trailer. For all these
 * types of block, a payload is attached to the block. It can also be a mark,
 * like the end-of-headers or end-of-message. For these blocks, there is no
 * payload but it count for a byte. It is important to not skip it when data are
 * forwarded. Metadata of an HTX block are composed of 2 fields :
 *
 *     - .info : It a 32 bits field containing the block's type on 4 bits
 *               followed by the payload length. See below for details.
 *
 *     - .addr : The payload's address, if any, relatively to the beginning the
 *               array used to store the HTX message itself.
 *
 * htx_blk.info representation :
 *
 *   0b 0000 0000 0000 0000 0000 0000 0000 0000
 *      ---- ------------------------ ---------
 *      type     value (1 MB max)     name length (header/trailer)
 *           ----------------------------------
 *                data length (256 MB max)
 *    (body, method, path, version, status, reason)
 *
 *   types :
 *     - 0000 = request  start-line
 *     - 0001 = response start-line
 *     - 0010 = header
 *     - 0011 = pseudo-header ou "special" header
 *     - 0100 = end-of-headers
 *     - 0101 = data
 *     - 0110 = trailer
 *     - 0111 = end-of-trailers
 *     - 1000 = end-of-message
 *       ...
 *     - 1111 = unused
 *
 */

/* HTX start-line flags */
#define HTX_SL_F_NONE           0x00000000
#define HTX_SL_F_IS_RESP        0x00000001 /* It is the response start-line (unset means the request one) */
#define HTX_SL_F_XFER_LEN       0x00000002 /* The message xfer size can be dertermined */
#define HTX_SL_F_XFER_ENC       0x00000004 /* The transfer-encoding header was found in message */
#define HTX_SL_F_CLEN           0x00000008 /* The content-length header was found in message */
#define HTX_SL_F_CHNK           0x00000010 /* The message payload is chunked */
#define HTX_SL_F_VER_11         0x00000020 /* The message indicates version 1.1 or above */
#define HTX_SL_F_BODYLESS       0x00000040 /* The message has no body (content-length = 0) */
#define HTX_SL_F_HAS_SCHM       0x00000080 /* The scheme is explicitly specified */
#define HTX_SL_F_SCHM_HTTP      0x00000100 /* The scheme HTTP should be used */
#define HTX_SL_F_SCHM_HTTPS     0x00000200 /* The scheme HTTPS should be used */
#define HTX_SL_F_HAS_AUTHORITY  0x00000400 /* The request authority is explicitly specified */
#define HTX_SL_F_NORMALIZED_URI 0x00000800 /* The received URI is normalized (an implicit absolute-uri form) */


/* HTX flags */
#define HTX_FL_NONE              0x00000000
#define HTX_FL_PARSING_ERROR     0x00000001 /* Set when a parsing error occurred */
#define HTX_FL_PROCESSING_ERROR  0x00000002 /* Set when a processing error occurred */
/* 0x00000004 unused */
#define HTX_FL_PROXY_RESP        0x00000008 /* Set when the response was generated by HAProxy */
#define HTX_FL_EOI               0x00000010 /* Set when end-of-input is reached from the HTX point of view
					     * (at worst, on the EOM block is missing)
					     */

/* HTX block's type (max 15). */
enum htx_blk_type {
	HTX_BLK_REQ_SL =  0, /* Request start-line */
	HTX_BLK_RES_SL =  1, /* Response start-line */
	HTX_BLK_HDR    =  2, /* header name/value block */
	HTX_BLK_EOH    =  3, /* end-of-headers block */
	HTX_BLK_DATA   =  4, /* data block */
	HTX_BLK_TLR    =  5, /* trailer name/value block */
	HTX_BLK_EOT    =  6, /* end-of-trailers block */
	HTX_BLK_EOM    =  7, /* end-of-message block */
	/* 8 .. 14 unused */
	HTX_BLK_UNUSED = 15, /* unused/removed block */
};

/* One HTX block descriptor */
struct htx_blk {
	uint32_t addr; /* relative storage address of the block's payload */
	uint32_t info; /* information about the block (type, length) */
};

/* Composite return value used by some HTX functions */
struct htx_ret {
	int32_t ret;         /* A numerical value */
	struct htx_blk *blk; /* An HTX block */
};

/* HTX start-line */
struct htx_sl {
	unsigned int flags; /* HTX_SL_F_* */
	union {
		struct {
			enum http_meth_t meth;   /* method */
		} req;
		struct {
			uint16_t         status; /* status code */
		} res;
	} info;

	/* XXX 2 bytes unused */

	int32_t hdrs_bytes;  /* Bytes held by all headers, as seen by the mux
			      * during parsing, from this start-line to the
			      * corresponding EOH. -1 if unknown */

	unsigned int len[3]; /* length of different parts of the start-line */
	char         l[VAR_ARRAY];
};

/* Internal representation of an HTTP message */
struct htx {
	uint32_t size;   /* the array size, in bytes, used to store the HTTP message itself */
	uint32_t data;   /* the data size, in bytes. To known to total size used by all allocated
			  * blocks (blocks and their contents), you need to add size used by blocks,
			  * i.e. [ used * sizeof(struct htx_blk *) ] */

	int32_t tail;   /* newest inserted block. -1 if the HTX message is empty */
	int32_t head;   /* oldest inserted block. -1 if the HTX message is empty */
	int32_t first;  /* position of the first block to (re)start the analyse. -1 if unset. */

	uint32_t tail_addr; /* start address of the free space in front of the the blocks table */
	uint32_t head_addr; /* start address of the free space at the beginning */
	uint32_t end_addr;  /* end address of the free space at the beginning */

	uint64_t extra;  /* known bytes amount remaining to receive */
	uint32_t flags;  /* HTX_FL_* */

	/* XXX 4 bytes unused */

	/* Blocks representing the HTTP message itself */
	char blocks[VAR_ARRAY] __attribute__((aligned(8)));
};

#endif /* _HAPROXY_HTX_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
