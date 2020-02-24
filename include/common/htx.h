/*
 * include/common/htx.h
 * This file defines everything related to the internal HTTP messages.
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

#ifndef _COMMON_HTX_H
#define _COMMON_HTX_H

#include <stdio.h>
#include <common/buf.h>
#include <common/config.h>
#include <common/ist.h>
#include <common/http.h>
#include <common/http-hdr.h>
#include <common/standard.h>

/*
 * The internal representation of an HTTP message, called HTX, is a structure
 * with useful information on the message followed by a contiguous array
 * containing parts of the message, called blocks. A block is composed of
 * metadata (htx_blk) and the associated payload. Blocks' metadata are stored
 * starting from the end of the array while their payload are stored at the
 * beginning. Blocks' metadata are often simply called blocks. it is a misuse of
 * language that's simplify explainations.
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
 * At the end, if payload wrapping or blocks defragmenation is not enough, some
 * free space may be get back with a full defragmenation. This way, the holes in
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
#define HTX_FL_UPGRADE           0x00000004 /* Set when an upgrade is in progress */
#define HTX_FL_PROXY_RESP        0x00000008 /* Set when the response was generated by HAProxy */


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

	unsigned int len[3]; /* length of differnt parts of the start-line */
	char         l[0];
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
	char blocks[0] __attribute__((aligned(8)));
};


extern struct htx htx_empty;

struct htx_blk *htx_defrag(struct htx *htx, struct htx_blk *blk);
struct htx_blk *htx_add_blk(struct htx *htx, enum htx_blk_type type, uint32_t blksz);
struct htx_blk *htx_remove_blk(struct htx *htx, struct htx_blk *blk);
struct htx_ret htx_find_offset(struct htx *htx, uint32_t offset);
void htx_truncate(struct htx *htx, uint32_t offset);
struct htx_ret htx_drain(struct htx *htx, uint32_t max);

struct htx_blk *htx_replace_blk_value(struct htx *htx, struct htx_blk *blk,
				      const struct ist old, const struct ist new);
struct htx_ret htx_xfer_blks(struct htx *dst, struct htx *src, uint32_t count,
			     enum htx_blk_type mark);

struct htx_sl *htx_add_stline(struct htx *htx, enum htx_blk_type type, unsigned int flags,
			      const struct ist p1, const struct ist p2, const struct ist p3);
struct htx_sl *htx_replace_stline(struct htx *htx, struct htx_blk *blk, const struct ist p1,
				  const struct ist p2, const struct ist p3);

struct htx_blk *htx_replace_header(struct htx *htx, struct htx_blk *blk,
				   const struct ist name, const struct ist value);

struct htx_blk *htx_add_header(struct htx *htx, const struct ist name, const struct ist value);
struct htx_blk *htx_add_trailer(struct htx *htx, const struct ist name, const struct ist value);
struct htx_blk *htx_add_all_headers(struct htx *htx, const struct http_hdr *hdrs);
struct htx_blk *htx_add_all_trailers(struct htx *htx, const struct http_hdr *hdrs);
struct htx_blk *htx_add_endof(struct htx *htx, enum htx_blk_type type);
struct htx_blk *htx_add_data_atonce(struct htx *htx, struct ist data);
size_t htx_add_data(struct htx *htx, const struct ist data);
struct htx_blk *htx_add_last_data(struct htx *htx, struct ist data);
void htx_move_blk_before(struct htx *htx, struct htx_blk **blk, struct htx_blk **ref);
int htx_append_msg(struct htx *dst, const struct htx *src);

/* Functions and macros to get parts of the start-line or legnth of these
 * parts. Request and response start-lines are both composed of 3 parts.
 */
#define HTX_SL_LEN(sl) ((sl)->len[0] + (sl)->len[1] + (sl)->len[2])

#define HTX_SL_P1_LEN(sl) ((sl)->len[0])
#define HTX_SL_P2_LEN(sl) ((sl)->len[1])
#define HTX_SL_P3_LEN(sl) ((sl)->len[2])
#define HTX_SL_P1_PTR(sl) ((sl)->l)
#define HTX_SL_P2_PTR(sl) (HTX_SL_P1_PTR(sl) + HTX_SL_P1_LEN(sl))
#define HTX_SL_P3_PTR(sl) (HTX_SL_P2_PTR(sl) + HTX_SL_P2_LEN(sl))

#define HTX_SL_REQ_MLEN(sl) HTX_SL_P1_LEN(sl)
#define HTX_SL_REQ_ULEN(sl) HTX_SL_P2_LEN(sl)
#define HTX_SL_REQ_VLEN(sl) HTX_SL_P3_LEN(sl)
#define HTX_SL_REQ_MPTR(sl) HTX_SL_P1_PTR(sl)
#define HTX_SL_REQ_UPTR(sl) HTX_SL_P2_PTR(sl)
#define HTX_SL_REQ_VPTR(sl) HTX_SL_P3_PTR(sl)

#define HTX_SL_RES_VLEN(sl) HTX_SL_P1_LEN(sl)
#define HTX_SL_RES_CLEN(sl) HTX_SL_P2_LEN(sl)
#define HTX_SL_RES_RLEN(sl) HTX_SL_P3_LEN(sl)
#define HTX_SL_RES_VPTR(sl) HTX_SL_P1_PTR(sl)
#define HTX_SL_RES_CPTR(sl) HTX_SL_P2_PTR(sl)
#define HTX_SL_RES_RPTR(sl) HTX_SL_P3_PTR(sl)

static inline struct ist htx_sl_p1(const struct htx_sl *sl)
{
	return ist2(HTX_SL_P1_PTR(sl), HTX_SL_P1_LEN(sl));
}

static inline struct ist htx_sl_p2(const struct htx_sl *sl)
{
	return ist2(HTX_SL_P2_PTR(sl), HTX_SL_P2_LEN(sl));
}

static inline struct ist htx_sl_p3(const struct htx_sl *sl)
{
	return ist2(HTX_SL_P3_PTR(sl), HTX_SL_P3_LEN(sl));
}

static inline struct ist htx_sl_req_meth(const struct htx_sl *sl)
{
	return htx_sl_p1(sl);
}

static inline struct ist htx_sl_req_uri(const struct htx_sl *sl)
{
	return htx_sl_p2(sl);
}

static inline struct ist htx_sl_req_vsn(const struct htx_sl *sl)
{
	return htx_sl_p3(sl);
}


static inline struct ist htx_sl_res_vsn(const struct htx_sl *sl)
{
	return htx_sl_p1(sl);
}

static inline struct ist htx_sl_res_code(const struct htx_sl *sl)
{
	return htx_sl_p2(sl);
}

static inline struct ist htx_sl_res_reason(const struct htx_sl *sl)
{
	return htx_sl_p3(sl);
}

/* Converts a position to the corresponding relative address */
static inline uint32_t htx_pos_to_addr(const struct htx *htx, uint32_t pos)
{
	return htx->size - (pos + 1) * sizeof(struct htx_blk);
}

/* Returns the position of the block <blk>. It is the caller responsibility to
 * be sure <blk> is part of <htx>. */
static inline uint32_t htx_get_blk_pos(const struct htx *htx, const struct htx_blk *blk)
{
	return ((htx->blocks + htx->size - (char *)blk) / sizeof(struct htx_blk) - 1);
}

/* Returns the block at the position <pos>. It is the caller responsibility to
 * be sure the block at the position <pos> exists. */
static inline struct htx_blk *htx_get_blk(const struct htx *htx, uint32_t pos)
{
	return (struct htx_blk *)(htx->blocks + htx_pos_to_addr(htx, pos));
}

/* Returns the type of the block <blk> */
static inline enum htx_blk_type htx_get_blk_type(const struct htx_blk *blk)
{
	return (blk->info >> 28);
}

/* Returns the size of the block <blk>, depending of its type */
static inline uint32_t htx_get_blksz(const struct htx_blk *blk)
{
	enum htx_blk_type type = htx_get_blk_type(blk);

	switch (type) {
		case HTX_BLK_HDR:
		case HTX_BLK_TLR:
			/*       name.length       +        value.length        */
			return ((blk->info & 0xff) + ((blk->info >> 8) & 0xfffff));
		default:
			/*         value.length      */
			return (blk->info & 0xfffffff);
	}
}

/* Returns the position of the oldest entry (head). It returns a signed 32-bits
 * integer, -1 means the HTX message is empty.
 */
static inline int32_t htx_get_head(const struct htx *htx)
{
	return htx->head;
}

/* Returns the oldest HTX block (head) if the HTX message is not
 * empty. Otherwise it returns NULL.
 */
static inline struct htx_blk *htx_get_head_blk(const struct htx *htx)
{
	int32_t head = htx_get_head(htx);

	return ((head == -1) ? NULL : htx_get_blk(htx, head));
}

/* Returns the type of the oldest HTX block (head) if the HTX message is not
 * empty. Otherwise it returns HTX_BLK_UNUSED.
 */
static inline enum htx_blk_type htx_get_head_type(const struct htx *htx)
{
	struct htx_blk *blk = htx_get_head_blk(htx);

	return (blk ? htx_get_blk_type(blk) : HTX_BLK_UNUSED);
}

/* Returns the position of the newest entry (tail).  It returns a signed 32-bits
 * integer, -1 means the HTX message is empty.
 */
static inline int32_t htx_get_tail(const struct htx *htx)
{
	return htx->tail;
}

/* Returns the newest HTX block (tail) if the HTX message is not
 * empty. Otherwise it returns NULL.
 */
static inline struct htx_blk *htx_get_tail_blk(const struct htx *htx)
{
	int32_t tail = htx_get_tail(htx);

	return ((tail == -1) ? NULL : htx_get_blk(htx, tail));
}

/* Returns the type of the newest HTX block (tail) if the HTX message is not
 * empty. Otherwise it returns HTX_BLK_UNUSED.
 */
static inline enum htx_blk_type htx_get_tail_type(const struct htx *htx)
{
	struct htx_blk *blk = htx_get_tail_blk(htx);

	return (blk ? htx_get_blk_type(blk) : HTX_BLK_UNUSED);
}

/* Returns the position of the first block in the HTX message <htx>. -1 means
 * the first block is unset or the HTS is empty.
 */
static inline int32_t htx_get_first(const struct htx *htx)
{
	return htx->first;
}

/* Returns the first HTX block in the HTX message <htx>. If unset or if <htx> is
 * empty, NULL returned.
 */
static inline struct htx_blk *htx_get_first_blk(const struct htx *htx)
{
	int32_t pos;

	pos = htx_get_first(htx);
	return ((pos == -1) ? NULL : htx_get_blk(htx, pos));
}

/* Returns the type of the first block in the HTX message <htx>. If unset or if
 * <htx> is empty, HTX_BLK_UNUSED is returned.
 */
static inline enum htx_blk_type htx_get_first_type(const struct htx *htx)
{
	struct htx_blk *blk = htx_get_first_blk(htx);

	return (blk ? htx_get_blk_type(blk) : HTX_BLK_UNUSED);
}

/* Returns the position of block immediately before the one pointed by <pos>. If
 * the message is empty or if <pos> is the position of the head, -1 returned.
 */
static inline int32_t htx_get_prev(const struct htx *htx, uint32_t pos)
{
	if (htx->head == -1 || pos == htx->head)
		return -1;
	return (pos - 1);
}

/* Returns the HTX block before <blk> in the HTX message <htx>. If <blk> is the
 * head, NULL returned.
 */
static inline struct htx_blk *htx_get_prev_blk(const struct htx *htx,
					       const struct htx_blk *blk)
{
	int32_t pos;

	pos = htx_get_prev(htx, htx_get_blk_pos(htx, blk));
	return ((pos == -1) ? NULL : htx_get_blk(htx, pos));
}

/* Returns the position of block immediately after the one pointed by <pos>. If
 * the message is empty or if <pos> is the position of the tail, -1 returned.
 */
static inline int32_t htx_get_next(const struct htx *htx, uint32_t pos)
{
	if (htx->tail == -1 || pos == htx->tail)
		return -1;
	return (pos + 1);

}

/* Returns the HTX block after <blk> in the HTX message <htx>. If <blk> is the
 * tail, NULL returned.
 */
static inline struct htx_blk *htx_get_next_blk(const struct htx *htx,
					       const struct htx_blk *blk)
{
	int32_t pos;

	pos = htx_get_next(htx, htx_get_blk_pos(htx, blk));
	return ((pos == -1) ? NULL : htx_get_blk(htx, pos));
}

/* Changes the size of the value. It is the caller responsibility to change the
 * value itself, make sure there is enough space and update allocated
 * value. This function updates the HTX message accordingly.
 */
static inline void htx_change_blk_value_len(struct htx *htx, struct htx_blk *blk, uint32_t newlen)
{
	enum htx_blk_type type = htx_get_blk_type(blk);
	uint32_t oldlen, sz;
	int32_t delta;

	sz = htx_get_blksz(blk);
	switch (type) {
		case HTX_BLK_HDR:
		case HTX_BLK_TLR:
			oldlen = (blk->info >> 8) & 0xfffff;
			blk->info = (type << 28) + (newlen << 8) + (blk->info & 0xff);
			break;
		default:
			oldlen = blk->info & 0xfffffff;
			blk->info = (type << 28) + newlen;
			break;
	}

	/* Update HTTP message */
	delta = (newlen - oldlen);
	htx->data += delta;
	if (blk->addr+sz == htx->tail_addr)
		htx->tail_addr += delta;
	else if (blk->addr+sz == htx->head_addr)
		htx->head_addr += delta;
}

/* Changes the size of the value. It is the caller responsibility to change the
 * value itself, make sure there is enough space and update allocated
 * value. Unlike the function htx_change_blk_value_len(), this one does not
 * update the HTX message. So it should be used with caution.
 */
static inline void htx_set_blk_value_len(struct htx_blk *blk, uint32_t vlen)
{
	enum htx_blk_type type = htx_get_blk_type(blk);

	switch (type) {
		case HTX_BLK_HDR:
		case HTX_BLK_TLR:
			blk->info = (type << 28) + (vlen << 8) + (blk->info & 0xff);
			break;
		case HTX_BLK_REQ_SL:
		case HTX_BLK_RES_SL:
		case HTX_BLK_DATA:
			blk->info = (type << 28) + vlen;
			break;
		default:
			/* Unexpected case */
			break;
	}
}

/* Returns the data pointer of the block <blk> */
static inline void *htx_get_blk_ptr(const struct htx *htx, const struct htx_blk *blk)
{
	return ((void *)htx->blocks + blk->addr);
}

/* Returns the name of the block <blk>, only if it is a header or a
 * trailer. Otherwise it returns an empty string.
 */
static inline struct ist htx_get_blk_name(const struct htx *htx, const struct htx_blk *blk)
{
	enum htx_blk_type type = htx_get_blk_type(blk);
	struct ist ret;

	switch (type) {
		case HTX_BLK_HDR:
		case HTX_BLK_TLR:
			ret.ptr = htx_get_blk_ptr(htx, blk);
			ret.len = blk->info & 0xff;
			break;

		default:
			return ist("");
	}
	return ret;
}


/* Returns the value of the block <blk>, depending on its type. If there is no
 * value (for end-of blocks), an empty one is retruned.
 */
static inline struct ist htx_get_blk_value(const struct htx *htx, const struct htx_blk *blk)
{
	enum htx_blk_type type = htx_get_blk_type(blk);
	struct ist ret;

	switch (type) {
		case HTX_BLK_HDR:
		case HTX_BLK_TLR:
			ret.ptr = htx_get_blk_ptr(htx, blk) + (blk->info & 0xff);
			ret.len = (blk->info >> 8) & 0xfffff;
			break;

		case HTX_BLK_REQ_SL:
		case HTX_BLK_RES_SL:
		case HTX_BLK_DATA:
			ret.ptr = htx_get_blk_ptr(htx, blk);
			ret.len = blk->info & 0xfffffff;
			break;

		default:
			return ist("");
	}
	return ret;
}

/* Removes <n> bytes from the beginning of DATA block <blk>. The block's start
 * address and its length are adjusted, and the htx's total data count is
 * updated. This is used to mark that part of some data were transfered
 * from a DATA block without removing this DATA block. No sanity check is
 * performed, the caller is reponsible for doing this exclusively on DATA
 * blocks, and never removing more than the block's size.
 */
static inline void htx_cut_data_blk(struct htx *htx, struct htx_blk *blk, uint32_t n)
{
	if (blk->addr == htx->end_addr)
		htx->end_addr += n;
	blk->addr += n;
	blk->info -= n;
	htx->data -= n;
}

/* Returns the space used by metadata in <htx>. */
static inline uint32_t htx_meta_space(const struct htx *htx)
{
	if (htx->tail == -1)
		return 0;

	return ((htx->tail + 1 - htx->head) * sizeof(struct htx_blk));
}

/* Returns the space used (payload + metadata) in <htx> */
static inline uint32_t htx_used_space(const struct htx *htx)
{
	return (htx->data + htx_meta_space(htx));
}

/* Returns the free space in <htx> */
static inline uint32_t htx_free_space(const struct htx *htx)
{
	return (htx->size - htx_used_space(htx));
}

/* Returns the maximum size available to store some data in <htx> if a new block
 * is reserved.
 */
static inline uint32_t htx_free_data_space(const struct htx *htx)
{
	uint32_t free = htx_free_space(htx);

	if (free < sizeof(struct htx_blk))
		return 0;
	return (free - sizeof(struct htx_blk));
}

/* Returns the maximum size for a block, not exceeding <max> bytes. <max> may be
 * set to -1 to have no limit.
 */
static inline uint32_t htx_get_max_blksz(const struct htx *htx, int32_t max)
{
	uint32_t free = htx_free_space(htx);

	if (max != -1 && free > max)
		free = max;
	if (free < sizeof(struct htx_blk))
		return 0;
	return (free - sizeof(struct htx_blk));
}

/* Returns 1 if the message has less than 1/4 of its capacity free, otherwise 0 */
static inline int htx_almost_full(const struct htx *htx)
{
	if (!htx->size || htx_free_space(htx) < htx->size / 4)
		return 1;
	return 0;
}

/* Resets an HTX message */
static inline void htx_reset(struct htx *htx)
{
	htx->tail = htx->head  = htx->first = -1;
	htx->data = 0;
	htx->tail_addr = htx->head_addr = htx->end_addr = 0;
	htx->extra = 0;
	htx->flags = HTX_FL_NONE;
}

/* Returns the available room for raw data in buffer <buf> once HTX overhead is
 * taken into account (one HTX header and two blocks). The purpose is to figure
 * the optimal fill length to avoid copies.
 */
static inline size_t buf_room_for_htx_data(const struct buffer *buf)
{
	size_t room;

	room = b_room(buf);
	if (room <= sizeof(struct htx) + 2 * sizeof(struct htx_blk))
		room = 0;
	else
		room -= sizeof(struct htx) + 2 * sizeof(struct htx_blk);

	return room;
}


/* Returns an HTX message using the buffer <buf>. Unlike htx_from_buf(), this
 * function does not update the buffer. So if the HTX message is updated, the
 * caller must call htx_to_buf() to be sure to also update the underlying buffer
 * accordingly.  Note that it always returns a valid pointer, either to an
 * initialized buffer or to the empty buffer. This function must always be
 * called with a buffer containing an HTX message (or an empty buffer).
 */
static inline struct htx *htxbuf(const struct buffer *buf)
{
	struct htx *htx;

	if (b_is_null(buf))
		return &htx_empty;
	htx = ((struct htx *)(buf->area));
	if (!b_data(buf)) {
		htx->size = buf->size - sizeof(*htx);
		htx_reset(htx);
	}
	return htx;
}

/* Returns an HTX message using the buffer <buf>. <buf> is updated to appear as
 * full. It should be used when you want to add something into the HTX message,
 * so the call to htx_to_buf() may be skipped. But, it is the caller
 * responsibility to call htx_to_buf() to reset <buf> if it is relevant. The
 * returned pointer is always valid. This function must always be called with a
 * buffer containing an HTX message (or an empty buffer).
 *
 * The caller can call htxbuf() function to avoid any update of the buffer.
 */
static inline struct htx *htx_from_buf(struct buffer *buf)
{
	struct htx *htx = htxbuf(buf);

	b_set_data(buf, b_size(buf));
	return htx;
}

/* Update <buf> accordingly to the HTX message <htx> */
static inline void htx_to_buf(struct htx *htx, struct buffer *buf)
{
	if ((htx->head == -1) &&
	    !(htx->flags & (HTX_FL_PARSING_ERROR|HTX_FL_PROCESSING_ERROR|HTX_FL_UPGRADE))) {
		htx_reset(htx);
		b_set_data(buf, 0);
	}
	else
		b_set_data(buf, b_size(buf));
}

/* Returns 1 if the message is empty, otherwise it returns 0. Note that it is
 * illegal to call this with htx == NULL.
 */
static inline int htx_is_empty(const struct htx *htx)
{
	return (htx->head == -1);
}

/* Returns 1 if the message is not empty, otherwise it returns 0. Note that it
 * is illegal to call this with htx == NULL.
 */
static inline int htx_is_not_empty(const struct htx *htx)
{
	return (htx->head != -1);
}

/* Returns the number of used blocks in the HTX message <htx>. Note that it is
 * illegal to call this function with htx == NULL. Note also blocks of type
 * HTX_BLK_UNUSED are part of used blocks.
 */
static inline int htx_nbblks(const struct htx *htx)
{
	return ((htx->head != -1) ? (htx->tail + 1 - htx->head) : 0);
}
/* For debugging purpose */
static inline const char *htx_blk_type_str(enum htx_blk_type type)
{
	switch (type) {
		case HTX_BLK_REQ_SL: return "HTX_BLK_REQ_SL";
		case HTX_BLK_RES_SL: return "HTX_BLK_RES_SL";
		case HTX_BLK_HDR:    return "HTX_BLK_HDR";
		case HTX_BLK_EOH:    return "HTX_BLK_EOH";
		case HTX_BLK_DATA:   return "HTX_BLK_DATA";
		case HTX_BLK_TLR:    return "HTX_BLK_TLR";
		case HTX_BLK_EOT:    return "HTX_BLK_EOT";
		case HTX_BLK_EOM:    return "HTX_BLK_EOM";
		case HTX_BLK_UNUSED: return "HTX_BLK_UNUSED";
		default:             return "HTX_BLK_???";
	};
}

/* For debugging purpose */
static inline void htx_dump(struct buffer *chunk, const struct htx *htx, int full)
{
	int32_t pos;

	chunk_appendf(chunk, " htx=%p(size=%u,data=%u,used=%u,wrap=%s,flags=0x%08x,extra=%llu,"
		      "first=%d,head=%d,tail=%d,tail_addr=%d,head_addr=%d,end_addr=%d)",
		      htx, htx->size, htx->data, htx_nbblks(htx), (!htx->head_addr) ? "NO" : "YES",
		      htx->flags, (unsigned long long)htx->extra, htx->first, htx->head, htx->tail,
		      htx->tail_addr, htx->head_addr, htx->end_addr);

	if (!full || !htx_nbblks(htx))
		return;
	chunk_memcat(chunk, "\n", 1);

	for (pos = htx_get_head(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_sl     *sl;
		struct htx_blk    *blk  = htx_get_blk(htx, pos);
		enum htx_blk_type  type = htx_get_blk_type(blk);
		uint32_t           sz   = htx_get_blksz(blk);
		struct ist         n, v;

		n = htx_get_blk_name(htx, blk);
		v = htx_get_blk_value(htx, blk);

		if (type == HTX_BLK_REQ_SL || type == HTX_BLK_RES_SL) {
			sl = htx_get_blk_ptr(htx, blk);
			chunk_appendf(chunk, "\t\t[%u] type=%-17s - size=%-6u - addr=%-6u\t%.*s %.*s %.*s\n",
				      pos, htx_blk_type_str(type), sz, blk->addr,
				      HTX_SL_P1_LEN(sl), HTX_SL_P1_PTR(sl),
				      HTX_SL_P2_LEN(sl), HTX_SL_P2_PTR(sl),
				      HTX_SL_P3_LEN(sl), HTX_SL_P3_PTR(sl));
		}
		else if (type == HTX_BLK_HDR || type == HTX_BLK_TLR)
			chunk_appendf(chunk, "\t\t[%u] type=%-17s - size=%-6u - addr=%-6u\t%.*s: %.*s\n",
				      pos, htx_blk_type_str(type), sz, blk->addr,
				      (int)n.len, n.ptr,
				      (int)v.len, v.ptr);
		else
			chunk_appendf(chunk, "\t\t[%u] type=%-17s - size=%-6u - addr=%-6u%s\n",
				      pos, htx_blk_type_str(type), sz, blk->addr,
				      (!v.len ? "\t<empty>" : ""));
	}
}

#endif /* _COMMON_HTX_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
