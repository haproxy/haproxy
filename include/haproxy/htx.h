/*
 * include/haproxy/htx.h
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

#ifndef _HAPROXY_HTX_H
#define _HAPROXY_HTX_H

#include <import/ist.h>
#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/http-hdr-t.h>
#include <haproxy/http-t.h>
#include <haproxy/htx-t.h>

/* ->extra field value when the payload length is unknown (non-chunked message
 * with no "Content-length" header)
 */
#define HTX_UNKOWN_PAYLOAD_LENGTH ULLONG_MAX

extern struct htx htx_empty;

struct htx_blk *htx_defrag(struct htx *htx, struct htx_blk *blk, uint32_t info);
struct htx_blk *htx_add_blk(struct htx *htx, enum htx_blk_type type, uint32_t blksz);
struct htx_blk *htx_remove_blk(struct htx *htx, struct htx_blk *blk);
struct htx_ret htx_find_offset(struct htx *htx, uint32_t offset);
void htx_truncate(struct htx *htx, uint32_t offset);
struct htx_ret htx_drain(struct htx *htx, uint32_t max);

struct htx_blk *htx_replace_blk_value(struct htx *htx, struct htx_blk *blk,
				      const struct ist old, const struct ist new);
struct htx_ret htx_xfer_blks(struct htx *dst, struct htx *src, uint32_t count,
			     enum htx_blk_type mark);

struct htx_sl *htx_replace_stline(struct htx *htx, struct htx_blk *blk, const struct ist p1,
				  const struct ist p2, const struct ist p3);

struct htx_blk *htx_replace_header(struct htx *htx, struct htx_blk *blk,
				   const struct ist name, const struct ist value);

struct htx_ret htx_reserve_max_data(struct htx *htx);
struct htx_blk *htx_add_data_atonce(struct htx *htx, struct ist data);
size_t htx_add_data(struct htx *htx, const struct ist data);
struct htx_blk *htx_add_last_data(struct htx *htx, struct ist data);
void htx_move_blk_before(struct htx *htx, struct htx_blk **blk, struct htx_blk **ref);
int htx_append_msg(struct htx *dst, const struct htx *src);

/* Functions and macros to get parts of the start-line or length of these
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

/* same as above but unchecked, may only be used when certain that a block
 * exists.
 */
static inline struct htx_blk *__htx_get_head_blk(const struct htx *htx)
{
	int32_t head = htx_get_head(htx);

	return htx_get_blk(htx, head);
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

/* Returns 1 if <blk> is the block is the only one inside the HTX message <htx>,
 * excluding all unused blocks. Otherwise, it returns 0. If 1 is returned, this
 * means that there is only <blk> and eventually some unused ones in <htx>.
 */
static inline int htx_is_unique_blk(const struct htx *htx,
				    const struct htx_blk *blk)
{
	return (htx_get_blksz(blk) == htx->data);
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
			ret = ist2(htx_get_blk_ptr(htx, blk),
				   blk->info & 0xff);
			break;

		default:
			return ist("");
	}
	return ret;
}


/* Returns the value of the block <blk>, depending on its type. If there is no
 * value (for end-of blocks), an empty one is returned.
 */
static inline struct ist htx_get_blk_value(const struct htx *htx, const struct htx_blk *blk)
{
	enum htx_blk_type type = htx_get_blk_type(blk);
	struct ist ret;

	switch (type) {
		case HTX_BLK_HDR:
		case HTX_BLK_TLR:
			ret = ist2(htx_get_blk_ptr(htx, blk) + (blk->info & 0xff),
				   (blk->info >> 8) & 0xfffff);
			break;

		case HTX_BLK_REQ_SL:
		case HTX_BLK_RES_SL:
		case HTX_BLK_DATA:
			ret = ist2(htx_get_blk_ptr(htx, blk),
				   blk->info & 0xfffffff);
			break;

		default:
			return ist("");
	}
	return ret;
}

/* Add a new start-line. It returns it on success, otherwise it returns NULL. It
 * is the caller responsibility to set sl->info, if necessary.
 */
static inline struct htx_sl *htx_add_stline(struct htx *htx, enum htx_blk_type type, unsigned int flags,
					    const struct ist p1, const struct ist p2, const struct ist p3)
{
	struct htx_blk *blk;
	struct htx_sl  *sl;
	uint32_t size;

	if (type != HTX_BLK_REQ_SL && type != HTX_BLK_RES_SL)
		return NULL;

	size = sizeof(*sl) + p1.len + p2.len + p3.len;

	blk = htx_add_blk(htx, type, size);
	if (!blk)
		return NULL;
	blk->info += size;

	sl = htx_get_blk_ptr(htx, blk);
	sl->flags = flags;

	HTX_SL_P1_LEN(sl) = p1.len;
	HTX_SL_P2_LEN(sl) = p2.len;
	HTX_SL_P3_LEN(sl) = p3.len;

	memcpy(HTX_SL_P1_PTR(sl), p1.ptr, p1.len);
	memcpy(HTX_SL_P2_PTR(sl), p2.ptr, p2.len);
	memcpy(HTX_SL_P3_PTR(sl), p3.ptr, p3.len);

	return sl;
}

/* Adds an HTX block of type HDR in <htx>. It returns the new block on
 * success. Otherwise, it returns NULL. The header name is always lower cased.
 */
static inline struct htx_blk *htx_add_header(struct htx *htx, const struct ist name,
					     const struct ist value)
{
	struct htx_blk *blk;

	if (name.len > 255 || value.len > 1048575)
		return NULL;

	blk = htx_add_blk(htx, HTX_BLK_HDR, name.len + value.len);
	if (!blk)
		return NULL;

	blk->info += (value.len << 8) + name.len;
	ist2bin_lc(htx_get_blk_ptr(htx, blk), name);
	memcpy(htx_get_blk_ptr(htx, blk)  + name.len, value.ptr, value.len);
	return blk;
}

/* Adds an HTX block of type TLR in <htx>. It returns the new block on
 * success. Otherwise, it returns NULL. The trailer name is always lower cased.
 */
static inline struct htx_blk *htx_add_trailer(struct htx *htx, const struct ist name,
					      const struct ist value)
{
	struct htx_blk *blk;

	if (name.len > 255 || value.len > 1048575)
		return NULL;

	blk = htx_add_blk(htx, HTX_BLK_TLR, name.len + value.len);
	if (!blk)
		return NULL;

	blk->info += (value.len << 8) + name.len;
	ist2bin_lc(htx_get_blk_ptr(htx, blk), name);
	memcpy(htx_get_blk_ptr(htx, blk)  + name.len, value.ptr, value.len);
	return blk;
}

/* Adds an HTX block of type EOH or EOT in <htx>. It returns the new block on
 * success. Otherwise, it returns NULL.
 */
static inline struct htx_blk *htx_add_endof(struct htx *htx, enum htx_blk_type type)
{
	struct htx_blk *blk;

	blk = htx_add_blk(htx, type, 1);
	if (!blk)
		return NULL;

	blk->info += 1;
	return blk;
}

/* Add all headers from the list <hdrs> into the HTX message <htx>, followed by
 * the EOH. On success, it returns the last block inserted (the EOH), otherwise
 * NULL is returned.
 *
 * Headers with a NULL value (.ptr == NULL) are ignored but not those with empty
 * value (.len == 0 but .ptr != NULL)
 */
static inline struct htx_blk *htx_add_all_headers(struct htx *htx, const struct http_hdr *hdrs)
{
	int i;

	for (i = 0; hdrs[i].n.len; i++) {
		/* Don't check the value length because a header value may be empty */
		if (isttest(hdrs[i].v) == 0)
			continue;
		if (!htx_add_header(htx, hdrs[i].n, hdrs[i].v))
			return NULL;
	}
	return htx_add_endof(htx, HTX_BLK_EOH);
}

/* Add all trailers from the list <hdrs> into the HTX message <htx>, followed by
 * the EOT. On success, it returns the last block inserted (the EOT), otherwise
 * NULL is returned.
 *
 * Trailers with a NULL value (.ptr == NULL) are ignored but not those with
 * empty value (.len == 0 but .ptr != NULL)
 */
static inline struct htx_blk *htx_add_all_trailers(struct htx *htx, const struct http_hdr *hdrs)
{
	int i;

	for (i = 0; hdrs[i].n.len; i++) {
		/* Don't check the value length because a header value may be empty */
		if (isttest(hdrs[i].v) == 0)
			continue;
		if (!htx_add_trailer(htx, hdrs[i].n, hdrs[i].v))
			return NULL;
	}
	return htx_add_endof(htx, HTX_BLK_EOT);
}

/* Removes <n> bytes from the beginning of DATA block <blk>. The block's start
 * address and its length are adjusted, and the htx's total data count is
 * updated. This is used to mark that part of some data were transferred
 * from a DATA block without removing this DATA block. No sanity check is
 * performed, the caller is responsible for doing this exclusively on DATA
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

/* Returns non-zero only if the HTX message free space wraps */
static inline int htx_space_wraps(const struct htx *htx)
{
	uint32_t headroom, tailroom;

	headroom = (htx->end_addr - htx->head_addr);
	tailroom = (htx_pos_to_addr(htx, htx->tail) - htx->tail_addr);

	return (headroom && tailroom);
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
	if (room <= HTX_BUF_OVERHEAD)
		room = 0;
	else
		room -= HTX_BUF_OVERHEAD;

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
	if (htx->flags & HTX_FL_ALTERED_PAYLOAD)
		htx->extra = 0;
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
	    !(htx->flags & (HTX_FL_PARSING_ERROR|HTX_FL_PROCESSING_ERROR))) {
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

/* Returns 1 if no more data are expected for the message <htx>. Otherwise it
 * returns 0. Note that it is illegal to call this with htx == NULL. This
 * function relies on the HTX_FL_EOM flags. It means tunneled data are not
 * considered here.
 */
static inline int htx_expect_more(const struct htx *htx)
{
	return !(htx->flags & HTX_FL_EOM);
}

/* Set EOM flag in <htx>. This function is useful if the HTX message is empty.
 * In this case, an EOT block is appended first to ensure the EOM will be
 * forwarded as expected. This is a workaround as it is not possibly currently
 * to push an empty HTX DATA block.
 *
 * Returns 1 on success else 0.
 */
static inline int htx_set_eom(struct htx *htx)
{
	if (htx_is_empty(htx)) {
		if (!htx_add_endof(htx, HTX_BLK_EOT))
			return 0;
	}

	htx->flags |= HTX_FL_EOM;
	return 1;
}

/* Copy an HTX message stored in the buffer <msg> to <htx>. We take care to
 * not overwrite existing data. All the message is copied or nothing. It returns
 * 1 on success and 0 on error.
 */
static inline int htx_copy_msg(struct htx *htx, const struct buffer *msg)
{
	/* The destination HTX message is allocated and empty, we can do a raw copy */
	if (htx_is_empty(htx) && htx_free_space(htx)) {
		memcpy(htx, msg->area, msg->size);
		return 1;
	}

	/* Otherwise, we need to append the HTX message */
	return htx_append_msg(htx, htxbuf(msg));
}

/* Remove all blocks except headers. Trailers will also be removed too. */
static inline void htx_skip_msg_payload(struct htx *htx)
{
	struct htx_blk *blk = htx_get_first_blk(htx);

	while (blk) {
		enum htx_blk_type type = htx_get_blk_type(blk);

		blk = ((type > HTX_BLK_EOH)
		       ? htx_remove_blk(htx, blk)
		       : htx_get_next_blk(htx, blk));
	}
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
				      (int)MIN(n.len, 32), n.ptr,
				      (int)MIN(v.len, 64), v.ptr);
		else
			chunk_appendf(chunk, "\t\t[%u] type=%-17s - size=%-6u - addr=%-6u%s\n",
				      pos, htx_blk_type_str(type), sz, blk->addr,
				      (!v.len ? "\t<empty>" : ""));
	}
}

#endif /* _HAPROXY_HTX_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
