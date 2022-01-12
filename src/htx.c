/*
 * internal HTTP message
 *
 * Copyright 2018 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/chunk.h>
#include <haproxy/htx.h>

struct htx htx_empty = { .size = 0, .data = 0, .head  = -1, .tail = -1, .first = -1 };

/* Defragments an HTX message. It removes unused blocks and unwraps the payloads
 * part. A temporary buffer is used to do so. This function never fails. Most of
 * time, we need keep a ref on a specific HTX block. Thus is <blk> is set, the
 * pointer on its new position, after defrag, is returned. In addition, if the
 * size of the block must be altered, <blkinfo> info must be provided (!=
 * 0). But in this case, it remains the caller responsibility to update the
 * block content.
 */
/* TODO: merge data blocks into one */
struct htx_blk *htx_defrag(struct htx *htx, struct htx_blk *blk, uint32_t blkinfo)
{
	struct buffer *chunk = get_trash_chunk();
	struct htx *tmp = htxbuf(chunk);
	struct htx_blk *newblk, *oldblk;
	uint32_t new, old, blkpos;
	uint32_t addr, blksz;
	int32_t first = -1;

	if (htx->head == -1)
		return NULL;

	blkpos = -1;

	new  = 0;
	addr = 0;
	tmp->size = htx->size;
	tmp->data = 0;

	/* start from the head */
	for (old = htx_get_head(htx); old != -1; old = htx_get_next(htx, old)) {
		oldblk = htx_get_blk(htx, old);
		if (htx_get_blk_type(oldblk) == HTX_BLK_UNUSED)
			continue;

		blksz = htx_get_blksz(oldblk);
		memcpy((void *)tmp->blocks + addr, htx_get_blk_ptr(htx, oldblk), blksz);

		/* update the start-line position */
		if (htx->first == old)
			first = new;

		newblk = htx_get_blk(tmp, new);
		newblk->addr = addr;
		newblk->info = oldblk->info;

		/* if <blk> is defined, save its new position */
		if (blk != NULL && blk == oldblk) {
			if (blkinfo)
				newblk->info = blkinfo;
			blkpos = new;
		}

		blksz = htx_get_blksz(newblk);
		addr += blksz;
		tmp->data += blksz;
		new++;
	}

	htx->data = tmp->data;
	htx->first = first;
	htx->head = 0;
	htx->tail = new - 1;
	htx->head_addr = htx->end_addr = 0;
	htx->tail_addr = addr;
	htx->flags &= ~HTX_FL_FRAGMENTED;
	memcpy((void *)htx->blocks, (void *)tmp->blocks, htx->size);

	return ((blkpos == -1) ? NULL : htx_get_blk(htx, blkpos));
}

/* Degragments HTX blocks of an HTX message. Payloads part is keep untouched
 * here. This function will move back all blocks starting at the position 0,
 * removing unused blocks. It must never be called with an empty message.
 */
static void htx_defrag_blks(struct htx *htx)
{
	int32_t pos, new;

	new = 0;
	for (pos = htx_get_head(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_blk *posblk, *newblk;

		if (pos == new) {
			new++;
			continue;
		}

		posblk = htx_get_blk(htx, pos);
		if (htx_get_blk_type(posblk) == HTX_BLK_UNUSED)
			continue;

		if (htx->first == pos)
			htx->first = new;
		newblk = htx_get_blk(htx, new++);
		newblk->info = posblk->info;
		newblk->addr = posblk->addr;
	}
	BUG_ON(!new);
	htx->head = 0;
	htx->tail = new - 1;
}

/* Reserves a new block in the HTX message <htx> with a content of <blksz>
 * bytes. If there is not enough space, NULL is returned. Otherwise the reserved
 * block is returned and the HTX message is updated. Space for this new block is
 * reserved in the HTX message. But it is the caller responsibility to set right
 * info in the block to reflect the stored data.
 */
static struct htx_blk *htx_reserve_nxblk(struct htx *htx, uint32_t blksz)
{
	struct htx_blk *blk;
	uint32_t tail, headroom, tailroom;

	if (blksz > htx_free_data_space(htx))
		return NULL; /* full */

	if (htx->head == -1) {
		/* Empty message */
		htx->head = htx->tail = htx->first = 0;
		blk = htx_get_blk(htx, htx->tail);
		blk->addr = 0;
		htx->data = blksz;
		htx->tail_addr = blksz;
		return blk;
	}

	/* Find the block's position. First, we try to get the next position in
	 * the message, increasing the tail by one. If this position is not
	 * available with some holes, we try to defrag the blocks without
	 * touching their paylood. If it is impossible, we fully defrag the
	 * message.
	 */
	tail = htx->tail + 1;
	if (htx_pos_to_addr(htx, tail) >= htx->tail_addr)
		;
	else if (htx->head > 0) {
		htx_defrag_blks(htx);
		tail = htx->tail + 1;
		BUG_ON(htx_pos_to_addr(htx, tail) < htx->tail_addr);
	}
	else
		goto defrag;

	/* Now, we have found the block's position. Try to find where to put its
	 * payload. The free space is split in two areas:
	 *
	 *   * The free space in front of the blocks table. This one is used if and
	 *     only if the other one was not used yet.
	 *
	 *   * The free space at the beginning of the message. Once this one is
	 *     used, the other one is never used again, until the next defrag.
	 */
	headroom = (htx->end_addr - htx->head_addr);
	tailroom = (!htx->head_addr ? htx_pos_to_addr(htx, tail) - htx->tail_addr : 0);
	BUG_ON((int32_t)headroom < 0);
	BUG_ON((int32_t)tailroom < 0);

	if (blksz <= tailroom) {
		blk = htx_get_blk(htx, tail);
		blk->addr = htx->tail_addr;
		htx->tail_addr += blksz;
	}
	else if (blksz <= headroom) {
		blk = htx_get_blk(htx, tail);
		blk->addr = htx->head_addr;
		htx->head_addr += blksz;
	}
	else {
	  defrag:
		/* need to defragment the message before inserting upfront */
		htx_defrag(htx, NULL, 0);
		tail = htx->tail + 1;
		blk = htx_get_blk(htx, tail);
		blk->addr = htx->tail_addr;
		htx->tail_addr += blksz;
	}

	htx->tail  = tail;
	htx->data += blksz;
	/* Set first position if not already set */
	if (htx->first == -1)
		htx->first = tail;

	BUG_ON((int32_t)htx->tail_addr < 0);
	BUG_ON((int32_t)htx->head_addr < 0);
	BUG_ON(htx->end_addr > htx->tail_addr);
	BUG_ON(htx->head_addr > htx->end_addr);

	return blk;
}

/* Prepares the block to an expansion of its payload. The payload will be
 * expanded by <delta> bytes and we need find where this expansion will be
 * performed. It can be a compression if <delta> is negative. This function only
 * updates all addresses. The caller have the responsibility to perform the
 * expansion and update the block and the HTX message accordingly. No error must
 * occur. It returns following values:
 *
 *  0: The expansion cannot be performed, there is not enough space.
 *
 *  1: the expansion must be performed in place, there is enough space after
 *      the block's payload to handle it. This is especially true if it is a
 *      compression and not an expension.
 *
 *  2: the block's payload must be moved at the new block address before doing
 *     the expansion.
 *
 *  3: the HTX message message must be defragmented
 */
static int htx_prepare_blk_expansion(struct htx *htx, struct htx_blk *blk, int32_t delta)
{
	uint32_t sz, tailroom, headroom;
	int ret = 3;

	BUG_ON(htx->head == -1);

	headroom = (htx->end_addr - htx->head_addr);
	tailroom = (htx_pos_to_addr(htx, htx->tail) - htx->tail_addr);
	BUG_ON((int32_t)headroom < 0);
	BUG_ON((int32_t)tailroom < 0);

	sz = htx_get_blksz(blk);
	if (delta <= 0) {
		/* It is a compression, it can be performed in place */
		if (blk->addr+sz == htx->tail_addr)
			htx->tail_addr += delta;
		else if (blk->addr+sz == htx->head_addr)
			htx->head_addr += delta;
		ret = 1;
	}
	else if (delta > htx_free_space(htx)) {
		/* There is not enough space to handle the expansion */
		ret = 0;
	}
	else if (blk->addr+sz == htx->tail_addr) {
		/* The block's payload is just before the tail room */
		if (delta < tailroom) {
			/* Expand the block's payload */
			htx->tail_addr += delta;
			ret = 1;
		}
		else if ((sz + delta) < headroom) {
			uint32_t oldaddr = blk->addr;

			/* Move the block's payload into the headroom */
			blk->addr = htx->head_addr;
			htx->tail_addr -= sz;
			htx->head_addr += sz + delta;
			if (oldaddr == htx->end_addr) {
				if (htx->end_addr == htx->tail_addr) {
					htx->tail_addr = htx->head_addr;
					htx->head_addr = htx->end_addr = 0;
				}
				else
					htx->end_addr += sz;
			}
			ret = 2;
		}
	}
	else if (blk->addr+sz == htx->head_addr) {
		/* The block's payload is just before the head room */
		if (delta < headroom) {
			/* Expand the block's payload */
			htx->head_addr += delta;
			ret = 1;
		}
	}
	else {
		/* The block's payload is not at the rooms edge */
		if (!htx->head_addr && sz+delta < tailroom) {
			/* Move the block's payload into the tailroom */
			if (blk->addr == htx->end_addr)
				htx->end_addr += sz;
			blk->addr = htx->tail_addr;
			htx->tail_addr += sz + delta;
			ret = 2;
		}
		else if (sz+delta < headroom) {
			/* Move the block's payload into the headroom */
			if (blk->addr == htx->end_addr)
				htx->end_addr += sz;
			blk->addr = htx->head_addr;
			htx->head_addr += sz + delta;
			ret = 2;
		}
	}
	/* Otherwise defrag the HTX message */

	BUG_ON((int32_t)htx->tail_addr < 0);
	BUG_ON((int32_t)htx->head_addr < 0);
	BUG_ON(htx->end_addr > htx->tail_addr);
	BUG_ON(htx->head_addr > htx->end_addr);
	return ret;
}

/* Adds a new block of type <type> in the HTX message <htx>. Its content size is
 * passed but it is the caller responsibility to do the copy.
 */
struct htx_blk *htx_add_blk(struct htx *htx, enum htx_blk_type type, uint32_t blksz)
{
	struct htx_blk *blk;

	BUG_ON(blksz >= 256 << 20);
	blk = htx_reserve_nxblk(htx, blksz);
	if (!blk)
		return NULL;
	BUG_ON(blk->addr > htx->size);

	blk->info = (type << 28);
	return blk;
}

/* Removes the block <blk> from the HTX message <htx>. The function returns the
 * block following <blk> or NULL if <blk> is the last block or the last inserted
 * one.
 */
struct htx_blk *htx_remove_blk(struct htx *htx, struct htx_blk *blk)
{
	enum htx_blk_type type;
	uint32_t pos, addr, sz;

	BUG_ON(htx->head == -1);

	/* This is the last block in use */
	if (htx->head == htx->tail) {
		uint32_t flags = (htx->flags & ~HTX_FL_FRAGMENTED); /* Preserve flags except FRAGMENTED */

		htx_reset(htx);
		htx->flags = flags; /* restore flags */
		return NULL;
	}

	type = htx_get_blk_type(blk);
	pos  = htx_get_blk_pos(htx, blk);
	sz   = htx_get_blksz(blk);
	addr = blk->addr;
	if (type != HTX_BLK_UNUSED) {
		/* Mark the block as unused, decrement allocated size */
		htx->data -= htx_get_blksz(blk);
		blk->info = ((uint32_t)HTX_BLK_UNUSED << 28);
	}

	/* There is at least 2 blocks, so tail is always > 0 */
	if (pos == htx->head) {
		/* move the head forward */
		htx->head++;
	}
	else if (pos == htx->tail) {
		/* remove the tail. this was the last inserted block so
		 * return NULL. */
		htx->tail--;
		blk = NULL;
		goto end;
	}
	else
		htx->flags |= HTX_FL_FRAGMENTED;

	blk = htx_get_blk(htx, pos+1);

  end:
	if (pos == htx->first)
		htx->first = (blk ? htx_get_blk_pos(htx, blk) : -1);

	if (htx->head == htx->tail) {
		/* If there is just one block in the HTX message, free space can
		 * be adjusted. This operation could save some defrags. */
		struct htx_blk *lastblk = htx_get_blk(htx, htx->tail);

		htx->head_addr = 0;
		htx->end_addr = lastblk->addr;
		htx->tail_addr = lastblk->addr+htx->data;
	}
	else {
		if (addr+sz == htx->tail_addr)
			htx->tail_addr = addr;
		else if (addr+sz == htx->head_addr)
			htx->head_addr = addr;
		if (addr == htx->end_addr) {
			if (htx->tail_addr == htx->end_addr) {
				htx->tail_addr = htx->head_addr;
				htx->head_addr = htx->end_addr = 0;
			}
			else
				htx->end_addr += sz;
		}
	}

	BUG_ON((int32_t)htx->tail_addr < 0);
	BUG_ON((int32_t)htx->head_addr < 0);
	BUG_ON(htx->end_addr > htx->tail_addr);
	BUG_ON(htx->head_addr > htx->end_addr);
	return blk;
}

/* Looks for the HTX block containing the offset <offset>, starting at the HTX
 * message's head. The function returns an htx_ret with the found HTX block and
 * the position inside this block where the offset is. If the offset <offset> is
 * outside of the HTX message, htx_ret.blk is set to NULL.
 */
struct htx_ret htx_find_offset(struct htx *htx, uint32_t offset)
{
	struct htx_blk *blk;
	struct htx_ret htxret = { .blk = NULL, .ret = 0 };

	if (offset >= htx->data)
		return htxret;

	for (blk = htx_get_head_blk(htx); blk && offset; blk = htx_get_next_blk(htx, blk)) {
		uint32_t sz = htx_get_blksz(blk);

		if (offset < sz)
			break;
		offset -= sz;
	}
	htxret.blk = blk;
	htxret.ret = offset;
	return htxret;
}

/* Removes all blocks after the one containing the offset <offset>. This last
 * one may be truncated if it is a DATA block.
 */
void htx_truncate(struct htx *htx, uint32_t offset)
{
	struct htx_blk *blk;
	struct htx_ret htxret = htx_find_offset(htx, offset);

	blk = htxret.blk;
	if (blk && htxret.ret && htx_get_blk_type(blk) == HTX_BLK_DATA) {
		htx_change_blk_value_len(htx, blk, htxret.ret);
		blk = htx_get_next_blk(htx, blk);
	}
	while (blk)
		blk = htx_remove_blk(htx, blk);
}

/* Drains <count> bytes from the HTX message <htx>. If the last block is a DATA
 * block, it will be cut if necessary. Others blocks will be removed at once if
 * <count> is large enough. The function returns an htx_ret with the first block
 * remaining in the message and the amount of data drained. If everything is
 * removed, htx_ret.blk is set to NULL.
 */
struct htx_ret htx_drain(struct htx *htx, uint32_t count)
{
	struct htx_blk *blk;
	struct htx_ret htxret = { .blk = NULL, .ret = 0 };

	if (count == htx->data) {
		uint32_t flags = (htx->flags & ~HTX_FL_FRAGMENTED); /* Preserve flags except FRAGMENTED */

		htx_reset(htx);
		htx->flags = flags; /* restore flags */
		htxret.ret = count;
		return htxret;
	}

	blk = htx_get_head_blk(htx);
	while (count && blk) {
		uint32_t sz = htx_get_blksz(blk);
		enum htx_blk_type type = htx_get_blk_type(blk);

		/* Ignore unused block */
		if (type == HTX_BLK_UNUSED)
			goto next;

		if (sz > count) {
			if (type == HTX_BLK_DATA) {
				htx_cut_data_blk(htx, blk, count);
				htxret.ret += count;
			}
			break;
		}
		count -= sz;
		htxret.ret += sz;
	  next:
		blk = htx_remove_blk(htx, blk);
	}
	htxret.blk = blk;

	return htxret;
}

/* Tries to append data to the last inserted block, if the type matches and if
 * there is enough space to take it all. If the space wraps, the buffer is
 * defragmented and a new block is inserted. If an error occurred, NULL is
 * returned. Otherwise, on success, the updated block (or the new one) is
 * returned. Due to its nature this function can be expensive and should be
 * avoided whenever possible.
 */
struct htx_blk *htx_add_data_atonce(struct htx *htx, struct ist data)
{
	struct htx_blk *blk, *tailblk;
	void *ptr;
	uint32_t len, sz, tailroom, headroom;

	if (htx->head == -1)
		goto add_new_block;

	/* Not enough space to store data */
	if (data.len > htx_free_data_space(htx))
		return NULL;

	/* get the tail block and its size */
	tailblk = htx_get_tail_blk(htx);
	if (tailblk == NULL)
		goto add_new_block;
	sz = htx_get_blksz(tailblk);

	/* Don't try to append data if the last inserted block is not of the
	 * same type */
	if (htx_get_blk_type(tailblk) != HTX_BLK_DATA)
		goto add_new_block;

	/*
	 * Same type and enough space: append data
	 */
	headroom = (htx->end_addr - htx->head_addr);
	tailroom = (htx_pos_to_addr(htx, htx->tail) - htx->tail_addr);
	BUG_ON((int32_t)headroom < 0);
	BUG_ON((int32_t)tailroom < 0);

	len = data.len;
	if (tailblk->addr+sz == htx->tail_addr) {
		if (data.len <= tailroom)
			goto append_data;
		else if (!htx->head_addr) {
			len = tailroom;
			goto append_data;
		}
	}
	else if (tailblk->addr+sz == htx->head_addr && data.len <= headroom)
		goto append_data;

	goto add_new_block;

  append_data:
	/* Append data and update the block itself */
	ptr = htx_get_blk_ptr(htx, tailblk);
	memcpy(ptr+sz, data.ptr, len);
	htx_change_blk_value_len(htx, tailblk, sz+len);

	if (data.len == len) {
		blk = tailblk;
		goto end;
	}
	data = istadv(data, len);

  add_new_block:
	blk = htx_add_blk(htx, HTX_BLK_DATA, data.len);
	if (!blk)
		return NULL;

	blk->info += data.len;
	memcpy(htx_get_blk_ptr(htx, blk), data.ptr, data.len);

  end:
	BUG_ON((int32_t)htx->tail_addr < 0);
	BUG_ON((int32_t)htx->head_addr < 0);
	BUG_ON(htx->end_addr > htx->tail_addr);
	BUG_ON(htx->head_addr > htx->end_addr);
	return blk;
}

/* Replaces a value part of a block by a new one. The new part can be smaller or
 * larger than the old one. This function works for any kind of block with
 * attached data. It returns the new block on success, otherwise it returns
 * NULL.
 */
struct htx_blk *htx_replace_blk_value(struct htx *htx, struct htx_blk *blk,
				      const struct ist old, const struct ist new)
{
	struct ist n, v;
	int32_t delta;
	int ret;

	n  = htx_get_blk_name(htx, blk);
	v  = htx_get_blk_value(htx, blk);
	delta = new.len - old.len;
	ret = htx_prepare_blk_expansion(htx, blk, delta);
	if (!ret)
		return NULL; /* not enough space */

	if (ret == 1) { /* Replace in place */
		if (delta <= 0) {
			/* compression: copy new data first then move the end */
			memcpy(old.ptr, new.ptr, new.len);
			memmove(old.ptr + new.len, istend(old),
				istend(v) - istend(old));
		}
		else {
			/* expansion: move the end first then copy new data */
			memmove(old.ptr + new.len, istend(old),
				istend(v) - istend(old));
			memcpy(old.ptr, new.ptr, new.len);
		}

		/* set the new block size and update HTX message */
		htx_set_blk_value_len(blk, v.len + delta);
		htx->data += delta;
	}
	else if (ret == 2) { /* New address but no defrag */
		void *ptr = htx_get_blk_ptr(htx, blk);

		/* Copy the name, if any */
		memcpy(ptr, n.ptr, n.len);
		ptr += n.len;

		/* Copy value before old part, if any */
		memcpy(ptr, v.ptr, old.ptr - v.ptr);
		ptr += old.ptr - v.ptr;

		/* Copy new value */
		memcpy(ptr, new.ptr, new.len);
		ptr += new.len;

		/* Copy value after old part, if any */
		memcpy(ptr, istend(old), istend(v) - istend(old));

		/* set the new block size and update HTX message */
		htx_set_blk_value_len(blk, v.len + delta);
		htx->data += delta;
	}
	else { /* Do a degrag first (it is always an expansion) */
		struct htx_blk tmpblk;
		int32_t offset;

		/* use tmpblk to set new block size before defrag and to compute
		 * the offset after defrag
		 */
		tmpblk.addr = blk->addr;
		tmpblk.info = blk->info;
		htx_set_blk_value_len(&tmpblk, v.len + delta);

		/* htx_defrag() will take care to update the block size and the htx message */
		blk = htx_defrag(htx, blk, tmpblk.info);

		/* newblk is now the new HTX block. Compute the offset to copy/move payload */
		offset = blk->addr - tmpblk.addr;

		/* move the end first and copy new data
		 */
		memmove(old.ptr + offset + new.len, old.ptr + offset + old.len,
			istend(v) - istend(old));
		memcpy(old.ptr + offset, new.ptr, new.len);
	}
	return blk;
}

/* Transfer HTX blocks from <src> to <dst>, stopping on the first block of the
 * type <mark> (typically EOH or EOT) or when <count> bytes were moved
 * (including payload and meta-data). It returns the number of bytes moved and
 * the last HTX block inserted in <dst>.
 */
struct htx_ret htx_xfer_blks(struct htx *dst, struct htx *src, uint32_t count,
			     enum htx_blk_type mark)
{
	struct htx_blk   *blk, *dstblk;
	struct htx_blk   *srcref, *dstref;
	enum htx_blk_type type;
	uint32_t	  info, max, sz, ret;

	ret = htx_used_space(dst);
	srcref = dstref = dstblk = NULL;

	/* blocks are not removed yet from <src> HTX message to be able to
	 * rollback the transfer if all the headers/trailers are not copied.
	 */
	for (blk = htx_get_head_blk(src); blk && count; blk = htx_get_next_blk(src, blk)) {
		type = htx_get_blk_type(blk);

		/* Ignore unused block */
		if (type == HTX_BLK_UNUSED)
			continue;


		max = htx_get_max_blksz(dst, count);
		if (!max)
			break;

		sz = htx_get_blksz(blk);
		info = blk->info;
		if (sz > max) {
			/* Only DATA blocks can be partially xferred */
			if (type != HTX_BLK_DATA)
				break;
			sz = max;
			info = (type << 28) + sz;
		}

		dstblk = htx_reserve_nxblk(dst, sz);
		if (!dstblk)
			break;
		dstblk->info = info;
		memcpy(htx_get_blk_ptr(dst, dstblk), htx_get_blk_ptr(src, blk), sz);

		count -= sizeof(dstblk) + sz;
		if (blk->info != info) {
			/* Partial xfer: don't remove <blk> from <src> but
			 * resize its content */
			htx_cut_data_blk(src, blk, sz);
			break;
		}

		if (type == mark) {
			blk = htx_get_next_blk(src, blk);
			srcref = dstref = NULL;
			break;
		}

		/* Save <blk> to <srcref> and <dstblk> to <dstref> when we start
		 * to xfer headers or trailers. When EOH/EOT block is reached,
		 * both are reset. It is mandatory to be able to rollback a
		 * partial transfer.
		 */
		if (!srcref && !dstref &&
		    (type == HTX_BLK_REQ_SL || type == HTX_BLK_RES_SL || type == HTX_BLK_TLR)) {
			srcref = blk;
			dstref = dstblk;
		}
		else if (type == HTX_BLK_EOH || type == HTX_BLK_EOT)
			srcref = dstref = NULL;
	}

	if (unlikely(dstref)) {
		/* Headers or trailers part was partially xferred, so rollback the copy
		 * by removing all block between <dstref> and <dstblk>, both included.
		 */
		while (dstref && dstref != dstblk)
			dstref = htx_remove_blk(dst, dstref);
		htx_remove_blk(dst, dstblk);

		/* <dst> HTX message is empty, it means the headers or trailers
		 * part is too big to be copied at once.
		 */
		if (htx_is_empty(dst))
			src->flags |= HTX_FL_PARSING_ERROR;
	}

	/* Now, remove xferred blocks from <src> htx message */
	if (!blk && !srcref) {
		/* End of src reached, all blocks were consumed, drain all data */
		htx_drain(src, src->data);
	}
	else {
		/* Remove all block from the head to <blk>, or <srcref> if defined, excluded */
		srcref = (srcref ? srcref : blk);
		for (blk = htx_get_head_blk(src); blk && blk != srcref; blk = htx_remove_blk(src, blk));
	}

  end:
	ret = htx_used_space(dst) - ret;
	return (struct htx_ret){.ret = ret, .blk = dstblk};
}

/* Replaces an header by a new one. The new header can be smaller or larger than
 * the old one. It returns the new block on success, otherwise it returns NULL.
 * The header name is always lower cased.
 */
struct htx_blk *htx_replace_header(struct htx *htx, struct htx_blk *blk,
				   const struct ist name, const struct ist value)
{
	enum htx_blk_type type;
	void *ptr;
	int32_t delta;
	int ret;

	type = htx_get_blk_type(blk);
	if (type != HTX_BLK_HDR)
		return NULL;

	delta = name.len + value.len - htx_get_blksz(blk);
	ret = htx_prepare_blk_expansion(htx, blk, delta);
	if (!ret)
		return NULL; /* not enough space */


	/* Replace in place or at a new address is the same. We replace all the
	 * header (name+value). Only take care to defrag the message if
	 * necessary. */
	if (ret == 3)
		blk = htx_defrag(htx, blk, (type << 28) + (value.len << 8) + name.len);
	else {
		/* Set the new block size and update HTX message */
		blk->info = (type << 28) + (value.len << 8) + name.len;
		htx->data += delta;
	}

	/* Finally, copy data. */
	ptr = htx_get_blk_ptr(htx, blk);
	ist2bin_lc(ptr, name);
	memcpy(ptr + name.len, value.ptr, value.len);
	return blk;
}

/* Replaces the parts of the start-line. It returns the new start-line on
 * success, otherwise it returns NULL. It is the caller responsibility to update
 * sl->info, if necessary.
 */
struct htx_sl *htx_replace_stline(struct htx *htx, struct htx_blk *blk, const struct ist p1,
				  const struct ist p2, const struct ist p3)
{
	enum htx_blk_type type;
	struct htx_sl *sl;
	struct htx_sl tmp; /* used to save sl->info and sl->flags */
	uint32_t sz;
	int32_t delta;
	int ret;

	type = htx_get_blk_type(blk);
	if (type != HTX_BLK_REQ_SL && type != HTX_BLK_RES_SL)
		return NULL;

	/* Save start-line info and flags */
	sl = htx_get_blk_ptr(htx, blk);
	tmp.info = sl->info;
	tmp.flags = sl->flags;

	sz = htx_get_blksz(blk);
	delta = sizeof(*sl) + p1.len + p2.len + p3.len - sz;
	ret = htx_prepare_blk_expansion(htx, blk, delta);
	if (!ret)
		return NULL; /* not enough space */

	/* Replace in place or at a new address is the same. We replace all the
	 * start-line. Only take care to defrag the message if necessary. */
	if (ret == 3)  {
		blk = htx_defrag(htx, blk, (type << 28) + sz + delta);
	}
	else {
		/* Set the new block size and update HTX message */
		blk->info = (type << 28) + sz + delta;
		htx->data += delta;
	}

	/* Restore start-line info and flags and copy parts of the start-line */
	sl = htx_get_blk_ptr(htx, blk);
	sl->info = tmp.info;
	sl->flags = tmp.flags;

	HTX_SL_P1_LEN(sl) = p1.len;
	HTX_SL_P2_LEN(sl) = p2.len;
	HTX_SL_P3_LEN(sl) = p3.len;

	memcpy(HTX_SL_P1_PTR(sl), p1.ptr, p1.len);
	memcpy(HTX_SL_P2_PTR(sl), p2.ptr, p2.len);
	memcpy(HTX_SL_P3_PTR(sl), p3.ptr, p3.len);

	return sl;
}

/* Reserves the maximum possible size for an HTX data block, by extending an
 * existing one or by creating a now one. It returns a compound result with the
 * HTX block and the position where new data must be inserted (0 for a new
 * block). If an error occurs or if there is no space left, NULL is returned
 * instead of a pointer on an HTX block.
 */
struct htx_ret htx_reserve_max_data(struct htx *htx)
{
       struct htx_blk *blk, *tailblk;
       uint32_t sz, room;
       int32_t len = htx_free_data_space(htx);

       if (htx->head == -1)
               goto rsv_new_block;

       if (!len)
               return (struct htx_ret){.ret = 0, .blk = NULL};

       /* get the tail and head block */
       tailblk = htx_get_tail_blk(htx);
       if (tailblk == NULL)
               goto rsv_new_block;
       sz = htx_get_blksz(tailblk);

       /* Don't try to append data if the last inserted block is not of the
        * same type */
       if (htx_get_blk_type(tailblk) != HTX_BLK_DATA)
               goto rsv_new_block;

       /*
        * Same type and enough space: append data
        */
       if (!htx->head_addr) {
               if (tailblk->addr+sz != htx->tail_addr)
                       goto rsv_new_block;
               room = (htx_pos_to_addr(htx, htx->tail) - htx->tail_addr);
       }
       else {
               if (tailblk->addr+sz != htx->head_addr)
                       goto rsv_new_block;
               room = (htx->end_addr - htx->head_addr);
       }
       BUG_ON((int32_t)room < 0);
       if (room < len)
               len = room;

  append_data:
       htx_change_blk_value_len(htx, tailblk, sz+len);

       BUG_ON((int32_t)htx->tail_addr < 0);
       BUG_ON((int32_t)htx->head_addr < 0);
       BUG_ON(htx->end_addr > htx->tail_addr);
       BUG_ON(htx->head_addr > htx->end_addr);
       return (struct htx_ret){.ret = sz, .blk = tailblk};

  rsv_new_block:
       blk = htx_add_blk(htx, HTX_BLK_DATA, len);
       if (!blk)
               return (struct htx_ret){.ret = 0, .blk = NULL};
       blk->info += len;
       return (struct htx_ret){.ret = 0, .blk = blk};
}

/* Adds an HTX block of type DATA in <htx>. It first tries to append data if
 * possible. It returns the number of bytes consumed from <data>, which may be
 * zero if nothing could be copied.
 */
size_t htx_add_data(struct htx *htx, const struct ist data)
{
	struct htx_blk *blk, *tailblk;
	void *ptr;
	uint32_t sz, room;
	int32_t len = data.len;

	/* Not enough space to store data */
	if (len > htx_free_data_space(htx))
		len = htx_free_data_space(htx);

	if (!len)
		return 0;

	if (htx->head == -1)
		goto add_new_block;

	/* get the tail and head block */
	tailblk = htx_get_tail_blk(htx);
	if (tailblk == NULL)
		goto add_new_block;
	sz = htx_get_blksz(tailblk);

	/* Don't try to append data if the last inserted block is not of the
	 * same type */
	if (htx_get_blk_type(tailblk) != HTX_BLK_DATA)
		goto add_new_block;

	/*
	 * Same type and enough space: append data
	 */
	if (!htx->head_addr) {
		if (tailblk->addr+sz != htx->tail_addr)
			goto add_new_block;
		room = (htx_pos_to_addr(htx, htx->tail) - htx->tail_addr);
	}
	else {
		if (tailblk->addr+sz != htx->head_addr)
			goto add_new_block;
		room = (htx->end_addr - htx->head_addr);
	}
	BUG_ON((int32_t)room < 0);
	if (room < len)
		len = room;

  append_data:
	/* Append data and update the block itself */
	ptr = htx_get_blk_ptr(htx, tailblk);
	memcpy(ptr + sz, data.ptr, len);
	htx_change_blk_value_len(htx, tailblk, sz+len);

	BUG_ON((int32_t)htx->tail_addr < 0);
	BUG_ON((int32_t)htx->head_addr < 0);
	BUG_ON(htx->end_addr > htx->tail_addr);
	BUG_ON(htx->head_addr > htx->end_addr);
	return len;

  add_new_block:
	blk = htx_add_blk(htx, HTX_BLK_DATA, len);
	if (!blk)
		return 0;

	blk->info += len;
	memcpy(htx_get_blk_ptr(htx, blk), data.ptr, len);
	return len;
}


/* Adds an HTX block of type DATA in <htx> just after all other DATA
 * blocks. Because it relies on htx_add_data_atonce(), It may be happened to a
 * DATA block if possible. But, if the function succeeds, it will be the last
 * DATA block in all cases. If an error occurred, NULL is returned. Otherwise,
 * on success, the updated block (or the new one) is returned.
 */
struct htx_blk *htx_add_last_data(struct htx *htx, struct ist data)
{
	struct htx_blk *blk, *pblk;

	blk = htx_add_data_atonce(htx, data);
	if (!blk)
		return NULL;

	for (pblk = htx_get_prev_blk(htx, blk); pblk; pblk = htx_get_prev_blk(htx, pblk)) {
		if (htx_get_blk_type(pblk) <= HTX_BLK_DATA)
			break;

		/* Swap .addr and .info fields */
		blk->addr ^= pblk->addr; pblk->addr ^= blk->addr; blk->addr ^= pblk->addr;
		blk->info ^= pblk->info; pblk->info ^= blk->info; blk->info ^= pblk->info;

		if (blk->addr == pblk->addr)
			blk->addr += htx_get_blksz(pblk);
		blk = pblk;
	}

	return blk;
}

/* Moves the block <blk> just before the block <ref>. Both blocks must be in the
 * HTX message <htx> and <blk> must be placed after <ref>. pointer to these
 * blocks are updated to remain valid after the move. */
void htx_move_blk_before(struct htx *htx, struct htx_blk **blk, struct htx_blk **ref)
{
	struct htx_blk *cblk, *pblk;

	cblk = *blk;
	for (pblk = htx_get_prev_blk(htx, cblk); pblk; pblk = htx_get_prev_blk(htx, pblk)) {
		/* Swap .addr and .info fields */
		cblk->addr ^= pblk->addr; pblk->addr ^= cblk->addr; cblk->addr ^= pblk->addr;
		cblk->info ^= pblk->info; pblk->info ^= cblk->info; cblk->info ^= pblk->info;

		if (cblk->addr == pblk->addr)
			cblk->addr += htx_get_blksz(pblk);
		if (pblk == *ref)
			break;
		cblk = pblk;
	}
	*blk = cblk;
	*ref = pblk;
}

/* Append the HTX message <src> to the HTX message <dst>. It returns 1 on
 * success and 0 on error.  All the message or nothing is copied. If an error
 * occurred, all blocks from <src> already appended to <dst> are truncated.
 */
int htx_append_msg(struct htx *dst, const struct htx *src)
{
	struct htx_blk *blk, *newblk;
	enum htx_blk_type type;
	uint32_t blksz, offset = dst->data;

	for (blk = htx_get_head_blk(src); blk; blk = htx_get_next_blk(src, blk)) {
		type = htx_get_blk_type(blk);

		if (type == HTX_BLK_UNUSED)
			continue;

		blksz = htx_get_blksz(blk);
		newblk = htx_add_blk(dst, type, blksz);
		if (!newblk)
			goto error;
		newblk->info = blk->info;
		memcpy(htx_get_blk_ptr(dst, newblk), htx_get_blk_ptr(src, blk), blksz);
	}

	return 1;

  error:
	htx_truncate(dst, offset);
	return 0;
}
