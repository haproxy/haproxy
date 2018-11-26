/*
 * include/proto/hx.h
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

#ifndef _PROTO_HTX_H
#define _PROTO_HTX_H

#include <common/buf.h>
#include <common/config.h>
#include <common/standard.h>
#include <common/http-hdr.h>

#include <types/h1.h>
#include <types/htx.h>

extern struct htx htx_empty;

struct htx_blk *htx_defrag(struct htx *htx, struct htx_blk *blk);
struct htx_blk *htx_add_blk(struct htx *htx, enum htx_blk_type type, uint32_t blksz);
struct htx_blk *htx_remove_blk(struct htx *htx, struct htx_blk *blk);

struct htx_blk *htx_replace_blk_value(struct htx *htx, struct htx_blk *blk,
                                      const struct ist old, const struct ist new);
struct htx_ret htx_xfer_blks(struct htx *dst, struct htx *src, uint32_t count,
			     enum htx_blk_type mark);

struct htx_blk *htx_replace_reqline(struct htx *htx, struct htx_blk *blk,
				    const union h1_sl sl);
struct htx_blk *htx_replace_resline(struct htx *htx, struct htx_blk *blk,
				    const union h1_sl sl);
struct htx_blk *htx_replace_header(struct htx *htx, struct htx_blk *blk,
                                   const struct ist name, const struct ist value);

struct htx_blk *htx_add_reqline(struct htx *htx, const union h1_sl sl);
struct htx_blk *htx_add_resline(struct htx *htx, const union h1_sl sl);
struct htx_blk *htx_add_header(struct htx *htx, const struct ist name, const struct ist value);
struct htx_blk *htx_add_all_headers(struct htx *htx, const struct http_hdr *hdrs);
struct htx_blk *htx_add_pseudo_header(struct htx *htx,  enum htx_phdr_type phdr, const struct ist value);
struct htx_blk *htx_add_endof(struct htx *htx, enum htx_blk_type type);
struct htx_blk *htx_add_data(struct htx *htx, const struct ist data);
struct htx_blk *htx_add_trailer(struct htx *htx, const struct ist tlr);
struct htx_blk *htx_add_oob(struct htx *htx, const struct ist oob);

int htx_reqline_to_str(const union htx_sl *sl, struct buffer *chk);
int htx_stline_to_str(const union htx_sl *sl, struct buffer *chk);
int htx_hdr_to_str(const struct ist n, const struct ist v, struct buffer *chk);
int htx_data_to_str(const struct ist data, struct buffer *chk, int chunked);
int htx_trailer_to_str(const struct ist tlr, struct buffer *chk);


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

/* Returns the position of block immediatly before the one pointed by <pos>. If
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

/* Returns the position of block immediatly after the one pointed by <pos>. If
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
}

/* Returns an HTX message using the buffer <buf>. */
static inline struct htx *htx_from_buf(struct buffer *buf)
{
        struct htx *htx;

        if (b_is_null(buf))
                return &htx_empty;
        htx = (struct htx *)(buf->area);
        htx->size = buf->size - sizeof(*htx);
        if (!b_data(buf))
                htx_reset(htx);
	return htx;
}

/* Returns 1 if the message is empty, otherwise it returns 0. */
static inline int htx_is_empty(const struct htx *htx)
{
        return (!htx || !htx->used);
}

/* Returns 1 if the message is not empty, otherwise it returns 0. */
static inline int htx_is_not_empty(const struct htx *htx)
{
        return (htx && htx->used);
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
		union htx_sl      *sl;
                struct htx_blk    *blk  = htx_get_blk(htx, pos);
                enum htx_blk_type  type = htx_get_blk_type(blk);
                enum htx_phdr_type phdr = htx_get_blk_phdr(blk);
                uint32_t           sz   = htx_get_blksz(blk);
                struct ist         n, v;

                n = htx_get_blk_name(htx, blk);
                v = htx_get_blk_value(htx, blk);

                if (type == HTX_BLK_REQ_SL) {
			sl = htx_get_blk_ptr(htx, blk);
                        fprintf(stderr, "\t\t[%u] type=%-17s - size=%-6u - addr=%-6u\t%.*s %.*s %.*s\n",
                                pos, htx_blk_type_str(type), sz, blk->addr,
                                (int)sl->rq.m_len, sl->rq.l,
                                (int)sl->rq.u_len, sl->rq.l + sl->rq.m_len,
                                (int)sl->rq.v_len, sl->rq.l + sl->rq.m_len + sl->rq.u_len);
		}
                else if (type == HTX_BLK_RES_SL) {
			sl = htx_get_blk_ptr(htx, blk);
                        fprintf(stderr, "\t\t[%u] type=%-17s - size=%-6u - addr=%-6u\t%.*s %.*s %.*s\n",
                                pos, htx_blk_type_str(type), sz, blk->addr,
                                (int)sl->st.v_len, sl->st.l,
                                (int)sl->st.c_len, sl->st.l + sl->st.v_len,
                                (int)sl->st.r_len, sl->st.l + sl->rq.v_len + sl->st.c_len);
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

#endif /* _PROTO_HTX_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
