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

/*HTX start-line flags */
#define HTX_SL_F_NONE          0x00000000
#define HTX_SL_F_IS_RESP       0x00000001 /* It is the response start-line (unset means the request one) */
#define HTX_SL_F_XFER_LEN      0x00000002 /* The message xfer size can be dertermined */
#define HTX_SL_F_XFER_ENC      0x00000004 /* The transfer-encoding header was found in message */
#define HTX_SL_F_CLEN          0x00000008 /* The content-length header was found in message */
#define HTX_SL_F_CHNK          0x00000010 /* The message payload is chunked */
#define HTX_SL_F_VER_11        0x00000020 /* The message indicates version 1.1 or above */
#define HTX_SL_F_BODYLESS      0x00000040 /* The message has no body (content-length = 0) */

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

	unsigned int len[3]; /* length of differnt parts of the start-line */
	char         l[0];
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

	int32_t sl_off; /* Offset of the start-line of the HTTP message relatively to the beginning the
			   data block. -1 if unset */

	struct htx_blk blocks[0]; /* Blocks representing the HTTP message itself */
};


extern struct htx htx_empty;

struct htx_blk *htx_defrag(struct htx *htx, struct htx_blk *blk);
struct htx_blk *htx_add_blk(struct htx *htx, enum htx_blk_type type, uint32_t blksz);
struct htx_blk *htx_remove_blk(struct htx *htx, struct htx_blk *blk);
void htx_truncate(struct htx *htx, uint32_t offset);

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
struct htx_blk *htx_add_blk_type_size(struct htx *htx, enum htx_blk_type type, uint32_t blksz);
struct htx_blk *htx_add_all_headers(struct htx *htx, const struct http_hdr *hdrs);
struct htx_blk *htx_add_pseudo_header(struct htx *htx,  enum htx_phdr_type phdr, const struct ist value);
struct htx_blk *htx_add_endof(struct htx *htx, enum htx_blk_type type);
struct htx_blk *htx_add_data(struct htx *htx, const struct ist data);
struct htx_blk *htx_add_trailer(struct htx *htx, const struct ist tlr);
struct htx_blk *htx_add_oob(struct htx *htx, const struct ist oob);
struct htx_blk *htx_add_data_before(struct htx *htx, const struct htx_blk *ref, const struct ist data);

int htx_reqline_to_h1(const struct htx_sl *sl, struct buffer *chk);
int htx_stline_to_h1(const struct htx_sl *sl, struct buffer *chk);
int htx_hdr_to_h1(const struct ist n, const struct ist v, struct buffer *chk);
int htx_data_to_h1(const struct ist data, struct buffer *chk, int chunked);
int htx_trailer_to_h1(const struct ist tlr, struct buffer *chk);

/* Functions and macros to get parts of the start-line or legnth of these
 * parts
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

static inline const struct ist htx_sl_p1(const struct htx_sl *sl)
{
	return ist2(HTX_SL_P1_PTR(sl), HTX_SL_P1_LEN(sl));
}

static inline const struct ist htx_sl_p2(const struct htx_sl *sl)
{
	return ist2(HTX_SL_P2_PTR(sl), HTX_SL_P2_LEN(sl));
}

static inline const struct ist htx_sl_p3(const struct htx_sl *sl)
{
	return ist2(HTX_SL_P3_PTR(sl), HTX_SL_P3_LEN(sl));
}

static inline const struct ist htx_sl_req_meth(const struct htx_sl *sl)
{
	return htx_sl_p1(sl);
}

static inline const struct ist htx_sl_req_uri(const struct htx_sl *sl)
{
	return htx_sl_p2(sl);
}

static inline const struct ist htx_sl_req_vsn(const struct htx_sl *sl)
{
	return htx_sl_p3(sl);
}


static inline const struct ist htx_sl_res_vsn(const struct htx_sl *sl)
{
	return htx_sl_p1(sl);
}

static inline const struct ist htx_sl_res_code(const struct htx_sl *sl)
{
	return htx_sl_p2(sl);
}

static inline const struct ist htx_sl_res_reason(const struct htx_sl *sl)
{
	return htx_sl_p3(sl);
}

/* Returns the HTX start-line if set, otherwise it returns NULL. */
static inline struct htx_sl *htx_get_stline(struct htx *htx)
{
	struct htx_sl *sl = NULL;

	if (htx->sl_off != -1)
		sl = ((void *)htx->blocks + htx->sl_off);

	return sl;
}

/* Returns the array index of a block given its position <pos> */
static inline uint32_t htx_pos_to_idx(const struct htx *htx, uint32_t pos)
{
	return ((htx->size / sizeof(htx->blocks[0])) - pos - 1);
}

/* Returns the position of the block <blk> */
static inline uint32_t htx_get_blk_pos(const struct htx *htx, const struct htx_blk *blk)
{
	return (htx->blocks + (htx->size / sizeof(htx->blocks[0])) - blk - 1);
}

/* Returns the block at the position <pos> */
static inline struct htx_blk *htx_get_blk(const struct htx *htx, uint32_t pos)
{
	return ((struct htx_blk *)(htx->blocks) + htx_pos_to_idx(htx, pos));
}

/* Returns the type of the block <blk> */
static inline enum htx_blk_type htx_get_blk_type(const struct htx_blk *blk)
{
	return (blk->info >> 28);
}

/* Returns the pseudo-header type of the block <blk>. If it's not a
 * pseudo-header, HTX_PHDR_UNKNOWN is returned.
 */
static inline enum htx_phdr_type htx_get_blk_phdr(const struct htx_blk *blk)
{
	enum htx_blk_type type = htx_get_blk_type(blk);
	enum htx_phdr_type phdr;

	switch (type) {
		case HTX_BLK_PHDR:
			phdr = (blk->info & 0xff);
			return phdr;

		default:
			/* Not a pseudo-header */
			return HTX_PHDR_UNKNOWN;
	}
}

/* Returns the size of the block <blk>, depending of its type */
static inline uint32_t htx_get_blksz(const struct htx_blk *blk)
{
	enum htx_blk_type type = htx_get_blk_type(blk);

	switch (type) {
		case HTX_BLK_HDR:
			/*       name.length       +        value.length        */
			return ((blk->info & 0xff) + ((blk->info >> 8) & 0xfffff));
		case HTX_BLK_PHDR:
			/*          value.length          */
			return ((blk->info >> 8) & 0xfffff);
		default:
			/*         value.length      */
			return (blk->info & 0xfffffff);
	}
}

/* Returns the position of the oldest entry (head).
 *
 * An signed 32-bits integer is returned to handle -1 case. Blocks position are
 * store on unsigned 32-bits integer, but it is impossible to have so much
 * blocks to overflow a 32-bits signed integer !
 */
static inline int32_t htx_get_head(const struct htx *htx)
{
	if (!htx->used)
		return -1;

	return (((htx->tail + 1U < htx->used) ? htx->wrap : 0) + htx->tail + 1U - htx->used);
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

/* Returns the position of the newest entry (tail).
 *
 * An signed 32-bits integer is returned to handle -1 case. Blocks position are
 * store on unsigned 32-bits integer, but it is impossible to have so much
 * blocks to overflow a 32-bits signed integer !
 */
static inline int32_t htx_get_tail(const struct htx *htx)
{
	return (htx->used ? htx->tail : -1);
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

/* Returns the position of block immediately before the one pointed by <pos>. If
 * the message is empty or if <pos> is the position of the head, -1 returned.
 *
 * An signed 32-bits integer is returned to handle -1 case. Blocks position are
 * store on unsigned 32-bits integer, but it is impossible to have so much
 * blocks to overflow a 32-bits signed integer !
 */
static inline int32_t htx_get_prev(const struct htx *htx, uint32_t pos)
{
	int32_t head;

	head = htx_get_head(htx);
	if (head == -1 || pos == head)
		return -1;
	if (!pos)
		return (htx->wrap - 1);
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
 *
 * An signed 32-bits integer is returned to handle -1 case. Blocks position are
 * store on unsigned 32-bits integer, but it is impossible to have so much
 * blocks to overflow a 32-bits signed integer !
 */
static inline int32_t htx_get_next(const struct htx *htx, uint32_t pos)
{
	if (!htx->used)
		return -1;

	if (pos == htx->tail)
		return -1;
	pos++;
	if (pos >= htx->wrap)
		pos = 0;
	return pos;

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

static inline int32_t htx_find_front(const struct htx *htx)
{
	int32_t  front, pos;
	uint32_t addr = 0;

	if (!htx->used)
		return -1;

	front = -1;
	for (pos = htx_get_head(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_blk   *blk  = htx_get_blk(htx, pos);
		enum htx_blk_type type = htx_get_blk_type(blk);

		if (type != HTX_BLK_UNUSED && blk->addr >= addr) {
			front = pos;
			addr  = blk->addr;
		}
	}

	return front;
}

/* Returns the HTX block containing data with the <offset>, relatively to the
 * beginning of the HTX message <htx>. It returns an htx_ret. if the HTX block is
 * not found, htx_ret.blk is set to NULL. Otherwise, it points to the right HTX
 * block and htx_ret.ret is set to the remaining offset inside the block.
 */
static inline struct htx_ret htx_find_blk(const struct htx *htx, uint32_t offset)
{
	int32_t pos;

	for (pos = htx_get_head(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_blk *blk = htx_get_blk(htx, pos);
		uint32_t sz = htx_get_blksz(blk);

		if (offset < sz)
			return (struct htx_ret){ .blk = blk, .ret = offset };
		offset -= sz;
	}

	return (struct htx_ret){ .blk = NULL };
}
/* Changes the size of the value. It is the caller responsibility to change the
 * value itself, make sure there is enough space and update allocated value.
 */
static inline void htx_set_blk_value_len(struct htx_blk *blk, uint32_t vlen)
{
	enum htx_blk_type type = htx_get_blk_type(blk);

	switch (type) {
		case HTX_BLK_HDR:
		case HTX_BLK_PHDR:
			blk->info = (type << 28) + (vlen << 8) + (blk->info & 0xff);
			break;
		case HTX_BLK_REQ_SL:
		case HTX_BLK_RES_SL:
		case HTX_BLK_DATA:
		case HTX_BLK_TLR:
		case HTX_BLK_OOB:
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

/* Returns the name of the block <blk>, only if it is a header. Otherwise it
 * returns an empty name.
 */
static inline struct ist htx_get_blk_name(const struct htx *htx, const struct htx_blk *blk)
{
	enum htx_blk_type type = htx_get_blk_type(blk);
	struct ist ret;

	switch (type) {
		case HTX_BLK_HDR:
			ret.ptr = htx_get_blk_ptr(htx, blk);
			ret.len = blk->info & 0xff;
			break;

		default:
			return ist("");
	}
	return ret;
}


/* Returns the value of the block <blk>, depending on its type. If there is no
 * value, an empty one is retruned.
 */
static inline struct ist htx_get_blk_value(const struct htx *htx, const struct htx_blk *blk)
{
	enum htx_blk_type type = htx_get_blk_type(blk);
	struct ist ret;

	switch (type) {
		case HTX_BLK_HDR:
			ret.ptr = htx_get_blk_ptr(htx, blk) + (blk->info & 0xff);
			ret.len = (blk->info >> 8) & 0xfffff;
			break;

		case HTX_BLK_PHDR:
			ret.ptr = htx_get_blk_ptr(htx, blk);
			ret.len = (blk->info >> 8) & 0xfffff;
			break;

		case HTX_BLK_REQ_SL:
		case HTX_BLK_RES_SL:
		case HTX_BLK_DATA:
		case HTX_BLK_TLR:
		case HTX_BLK_OOB:
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
	blk->addr += n;
	blk->info -= n;
	htx->data -= n;
}

/* Returns the space used by metadata in <htx>. */
static inline uint32_t htx_meta_space(const struct htx *htx)
{
	return (htx->used * sizeof(htx->blocks[0]));
}

/* Returns the space used (data + metadata) in <htx> */
static inline uint32_t htx_used_space(const struct htx *htx)
{
	return (htx->data + htx_meta_space(htx));
}

/* Returns the free space in <htx> */
static inline uint32_t htx_free_space(const struct htx *htx)
{
	return (htx->size - htx_used_space(htx));
}

/* Returns the maximum space usable for data in <htx>. This is in fact the
 * maximum sice for a uniq block to fill the HTX message. */
static inline uint32_t htx_max_data_space(const struct htx *htx)
{
	if (!htx->size)
		return 0;
	return (htx->size - sizeof(htx->blocks[0]));
}

/* Returns the maximum size available to store some data in <htx> if a new block
 * is reserved.
 */
static inline uint32_t htx_free_data_space(const struct htx *htx)
{
	uint32_t free = htx_free_space(htx);

	if (free < sizeof(htx->blocks[0]))
		return 0;
	return (free - sizeof(htx->blocks[0]));
}

/* Returns 1 if the message has less than 1/4 of its capacity free, otherwise 0 */
static inline int htx_almost_full(const struct htx *htx)
{
	if (!htx->size || htx_free_space(htx) < htx->size / 4)
		return 1;
	return 0;
}

static inline void htx_reset(struct htx *htx)
{
	htx->data = htx->used = htx->tail = htx->wrap  = htx->front = 0;
	htx->extra = 0;
	htx->flags = HTX_FL_NONE;
	htx->sl_off = -1;
}

/* returns the available room for raw data in buffer <buf> once HTX overhead is
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
 * function does not update to the buffer.
 * Note that it always returns a valid pointer, either to an initialized buffer
 * or to the empty buffer.
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
 * full. It is the caller responsibility to call htx_to_buf() when it finish to
 * manipulate the HTX message to update <buf> accordingly. The returned pointer
 * is always valid.
 *
 * The caller can call htxbuf() function to avoid any update of the buffer.
 */
static inline struct htx *htx_from_buf(struct buffer *buf)
{
	struct htx *htx = htxbuf(buf);

	b_set_data(buf, b_size(buf));
	return htx;
}

/* Upate <buf> accordingly to the HTX message <htx> */
static inline void htx_to_buf(struct htx *htx, struct buffer *buf)
{
	if (!htx->used) {
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
	return !htx->used;
}

/* Returns 1 if the message is not empty, otherwise it returns 0. Note that it
 * is illegal to call this with htx == NULL.
 */
static inline int htx_is_not_empty(const struct htx *htx)
{
	return htx->used;
}

/* For debugging purpose */
static inline const char *htx_blk_type_str(enum htx_blk_type type)
{
	switch (type) {
		case HTX_BLK_REQ_SL: return "HTX_BLK_REQ_SL";
		case HTX_BLK_RES_SL: return "HTX_BLK_RES_SL";
		case HTX_BLK_HDR:    return "HTX_BLK_HDR";
		case HTX_BLK_PHDR:   return "HTX_BLK_PHDR";
		case HTX_BLK_EOH:    return "HTX_BLK_EOH";
		case HTX_BLK_DATA:   return "HTX_BLK_DATA";
		case HTX_BLK_EOD:    return "HTX_BLK_EOD";
		case HTX_BLK_TLR:    return "HTX_BLK_TLR";
		case HTX_BLK_EOM:    return "HTX_BLK_EOM";
		case HTX_BLK_OOB:    return "HTX_BLK_OOB";
		case HTX_BLK_UNUSED: return "HTX_BLK_UNUSED";
		default:             return "HTX_BLK_???";
	};
}

static inline const char *htx_blk_phdr_str(enum htx_phdr_type phdr)
{
	switch (phdr) {
		case HTX_PHDR_UNKNOWN: return "HTX_PHDR_UNKNOWN";
		default:               return "HTX_PHDR_???";
	}
}

static inline void htx_dump(struct htx *htx)
{
	int32_t pos;

	fprintf(stderr, "htx:%p [ size=%u - data=%u - used=%u - wrap=%s - extra=%llu]\n",
		htx, htx->size, htx->data, htx->used,
		(!htx->used || htx->tail+1 == htx->wrap) ? "NO" : "YES",
		(unsigned long long)htx->extra);
	fprintf(stderr, "\thead=%d - tail=%u - front=%u - wrap=%u\n",
		htx_get_head(htx), htx->tail, htx->front, htx->wrap);

	for (pos = htx_get_head(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_sl     *sl;
		struct htx_blk    *blk  = htx_get_blk(htx, pos);
		enum htx_blk_type  type = htx_get_blk_type(blk);
		enum htx_phdr_type phdr = htx_get_blk_phdr(blk);
		uint32_t           sz   = htx_get_blksz(blk);
		struct ist         n, v;

		n = htx_get_blk_name(htx, blk);
		v = htx_get_blk_value(htx, blk);

		if (type == HTX_BLK_REQ_SL || type == HTX_BLK_RES_SL) {
			sl = htx_get_blk_ptr(htx, blk);
			fprintf(stderr, "\t\t[%u] type=%-17s - size=%-6u - addr=%-6u\t%.*s %.*s %.*s\n",
				pos, htx_blk_type_str(type), sz, blk->addr,
				HTX_SL_P1_LEN(sl), HTX_SL_P1_PTR(sl),
				HTX_SL_P2_LEN(sl), HTX_SL_P2_PTR(sl),
				HTX_SL_P3_LEN(sl), HTX_SL_P3_PTR(sl));
		}
		else if (type == HTX_BLK_HDR)
			fprintf(stderr, "\t\t[%u] type=%-17s - size=%-6u - addr=%-6u\t%.*s: %.*s\n",
				pos, htx_blk_type_str(type), sz, blk->addr,
				(int)n.len, n.ptr,
				(int)v.len, v.ptr);

		else if (type == HTX_BLK_PHDR)
			fprintf(stderr, "\t\t[%u] type=%-17s - size=%-6u - addr=%-6u\t%.*s\n",
				pos, htx_blk_phdr_str(phdr), sz, blk->addr,
				(int)v.len, v.ptr);
		else
			fprintf(stderr, "\t\t[%u] type=%-17s - size=%-6u - addr=%-6u%s\n",
				pos, htx_blk_type_str(type), sz, blk->addr,
				(!v.len ? "\t<empty>" : ""));
	}
	fprintf(stderr, "\n");
}

#endif /* _COMMON_HTX_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
