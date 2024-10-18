/*
 * Simple buffer handling - heavy functions definitions
 *
 * Most of the low-level operations are in buf.h, but this file centralizes
 * heavier functions that shouldn't be inlined.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later.
 *
 */

#include <sys/types.h>
#include <string.h>
#include <haproxy/api.h>
#include <haproxy/buf.h>

/* b_getblk_ofs() : gets one full block of data at once from a buffer, starting
 * from offset <offset> after the buffer's area, and for exactly <len> bytes.
 * As a convenience to avoid complex checks in callers, the offset is allowed
 * to exceed a valid one by no more than one buffer size, and will automatically
 * be wrapped. The caller is responsible for ensuring that <len> doesn't exceed
 * the known length of the available data at this position, otherwise undefined
 * data will be returned. This is meant to be used on concurrently accessed
 * buffers, so that a reader can read a known area while the buffer is being fed
 * and trimmed. The function guarantees never to use ->head nor ->data. The
 * buffer is left unaffected. It always returns the number of bytes copied.
 */
size_t b_getblk_ofs(const struct buffer *buf, char *blk, size_t len, size_t offset)
{
	size_t firstblock;

	if (offset >= buf->size)
		offset -= buf->size;

	BUG_ON(offset >= buf->size);

	firstblock = buf->size - offset;

	if (firstblock >= len)
		firstblock = len;

	memcpy(blk, b_orig(buf) + offset, firstblock);

	if (len > firstblock)
		memcpy(blk + firstblock, b_orig(buf), len - firstblock);
	return len;
}

/* b_getblk() : gets one full block of data at once from a buffer, starting
 * from offset <offset> after the buffer's head, and limited to no more than
 * <len> bytes. The caller is responsible for ensuring that neither <offset>
 * nor <offset>+<len> exceed the total number of bytes available in the buffer.
 * Return values :
 *   >0 : number of bytes read, equal to requested size.
 *   =0 : not enough data available. <blk> is left undefined.
 * The buffer is left unaffected.
 */
size_t b_getblk(const struct buffer *buf, char *blk, size_t len, size_t offset)
 {
	size_t firstblock;

	BUG_ON(buf->data > buf->size);
	BUG_ON(offset > buf->data);
	BUG_ON(offset + len > buf->data);

	if (len + offset > b_data(buf))
		return 0;

	firstblock = b_wrap(buf) - b_head(buf);
	if (firstblock > offset) {
		if (firstblock >= len + offset) {
			memcpy(blk, b_head(buf) + offset, len);
			return len;
		}

		memcpy(blk, b_head(buf) + offset, firstblock - offset);
		memcpy(blk + firstblock - offset, b_orig(buf), len - firstblock + offset);
		return len;
	}

	memcpy(blk, b_orig(buf) + offset - firstblock, len);
	return len;
}

/* Locates the longest part of the buffer that is composed exclusively of
 * characters not in the <delim> set, and delimited by one of these characters,
 * and returns the initial part and the first of such delimiters. A single
 * escape character in <escape> may be specified so that when not 0 and found,
 * the character that follows it is never taken as a delimiter. Note that
 * <delim> cannot contain the zero byte, hence this function is not usable with
 * byte zero as a delimiter.
 *
 * Return values :
 *   >0 : number of bytes read. Includes the sep if present before len or end.
 *   =0 : no sep before end found. <str> is left undefined.
 *
 * The buffer is left unaffected. Unused buffers are left in an undefined state.
 */
size_t b_getdelim(const struct buffer *buf, size_t offset, size_t count,
				char *str, size_t len, const char *delim, char escape)
{
	uchar delim_map[256 / 8];
	int found, escaped;
	uint pos, bit;
	size_t ret, max;
	uchar b;
	char *p;

	ret = 0;
	p = b_peek(buf, offset);

	max = len;
	if (!count || offset+count > b_data(buf))
		goto out;
	if (max > count) {
		max = count;
		str[max-1] = 0;
	}

	/* create the byte map */
	memset(delim_map, 0, sizeof(delim_map));
	while ((b = *delim)) {
		pos = b >> 3;
		bit = b &  7;
		delim_map[pos] |= 1 << bit;
		delim++;
	}

	found = escaped = 0;
	while (max) {
		*str++ = b = *p;
		ret++;
		max--;

		if (escape && (escaped || *p == escape)) {
			escaped = !escaped;
			goto skip;
		}

		pos = b >> 3;
		bit = b &  7;
		if (delim_map[pos] & (1 << bit)) {
			found = 1;
			break;
		}
	  skip:
		p = b_next(buf, p);
	}

	if (ret > 0 && !found)
		ret = 0;
 out:
	if (max)
		*str = 0;
	return ret;
}

/* Gets one text line out of aa buffer.
 * Return values :
 *   >0 : number of bytes read. Includes the \n if present before len or end.
 *   =0 : no '\n' before end found. <str> is left undefined.
 *
 * The buffer is left unaffected. Unused buffers are left in an undefined state.
 */
size_t b_getline(const struct buffer *buf, size_t offset, size_t count,
			       char *str, size_t len)
{
	size_t ret, max;
	char *p;

	ret = 0;
	p = b_peek(buf, offset);

	max = len;
	if (!count || offset+count > b_data(buf))
		goto out;
	if (max > count) {
		max = count;
		str[max-1] = 0;
	}

	while (max) {
		*str++ = *p;
		ret++;
		max--;

		if (*p == '\n')
			break;
		p = b_next(buf, p);
	}

	if (ret > 0 && *(str-1) != '\n')
		ret = 0;
 out:
	if (max)
		*str = 0;
	return ret;
}

/* b_slow_realign() : this function realigns a possibly wrapping buffer so that
 * the part remaining to be parsed is contiguous and starts at the beginning of
 * the buffer and the already parsed output part ends at the end of the buffer.
 * This provides the best conditions since it allows the largest inputs to be
 * processed at once and ensures that once the output data leaves, the whole
 * buffer is available at once. The number of output bytes supposedly present
 * at the beginning of the buffer and which need to be moved to the end must be
 * passed in <output>. A temporary swap area at least as large as b->size must
 * be provided in <swap>. It's up to the caller to ensure <output> is no larger
 * than the difference between the whole buffer's length and its input.
 */
void b_slow_realign(struct buffer *b, char *swap, size_t output)
{
	size_t block1 = output;
	size_t block2 = 0;

	BUG_ON_HOT(b->data > b->size);

	/* process output data in two steps to cover wrapping */
	if (block1 > b_size(b) - b_head_ofs(b)) {
		block2 = b_peek_ofs(b, block1);
		block1 -= block2;
	}
	memcpy(swap + b_size(b) - output, b_head(b), block1);
	memcpy(swap + b_size(b) - block2, b_orig(b), block2);

	/* process input data in two steps to cover wrapping */
	block1 = b_data(b) - output;
	block2 = 0;

	if (block1 > b_tail_ofs(b)) {
		block2 = b_tail_ofs(b);
		block1 = block1 - block2;
	}
	memcpy(swap, b_peek(b, output), block1);
	memcpy(swap + block1, b_orig(b), block2);

	/* reinject changes into the buffer */
	memcpy(b_orig(b), swap, b_data(b) - output);
	memcpy(b_wrap(b) - output, swap + b_size(b) - output, output);

	b->head = (output ? b_size(b) - output : 0);
}

/* b_slow_realign_ofs() : this function realigns a possibly wrapping buffer
 * setting its new head at <ofs>. Depending of the <ofs> value, the resulting
 * buffer may also wrap. A temporary swap area at least as large as b->size must
 * be provided in <swap>. It's up to the caller to ensuze <ofs> is not larger
 * than b->size.
 */
void b_slow_realign_ofs(struct buffer *b, char *swap, size_t ofs)
{
	size_t block1 = b_data(b);
	size_t block2 = 0;

	BUG_ON_HOT(b->data > b->size);
	BUG_ON_HOT(ofs > b->size);

	if (__b_tail_ofs(b) >= b_size(b)) {
		block2 = b_tail_ofs(b);
		block1 -= block2;
	}
	memcpy(swap, b_head(b), block1);
	memcpy(swap + block1, b_orig(b), block2);

	block1 = b_data(b);
	block2 = 0;
	if (block1 > b_size(b) - ofs) {
		block1 = b_size(b) - ofs;
		block2 = b_data(b) - block1;
	}
	memcpy(b_orig(b) + ofs, swap, block1);
	memcpy(b_orig(b), swap + block1, block2);

	b->head = ofs;
}

/* b_putblk_ofs(): puts one full block of data of length <len> from <blk> into
 * the buffer, starting from absolute offset <offset> after the buffer's area.
 * As a convenience to avoid complex checks in callers, the offset is allowed
 * to exceed a valid one by no more than one buffer size, and will automatically
 * be wrapped. The caller is responsible for ensuring that <len> doesn't exceed
 * the known length of the available room at this position, otherwise data may
 * be overwritten. The buffer's length is *not* updated, so generally the caller
 * will have updated it before calling this function. This is meant to be used
 * on concurrently accessed buffers, so that a writer can append data while a
 * reader is blocked by other means from reaching the current area The function
 * guarantees never to use ->head nor ->data. It always returns the number of
 * bytes copied.
 */
size_t b_putblk_ofs(struct buffer *buf, char *blk, size_t len, size_t offset)
{
	size_t firstblock;

	if (offset >= buf->size)
		offset -= buf->size;

	BUG_ON(offset >= buf->size);

	firstblock = buf->size - offset;

	if (firstblock >= len)
		firstblock = len;

	memcpy(b_orig(buf) + offset, blk, firstblock);

	if (len > firstblock)
		memcpy(b_orig(buf), blk + firstblock, len - firstblock);
	return len;
}

/* __b_putblk() : tries to append <len> bytes from block <blk> to the end of
 * buffer <b> without checking for free space (it's up to the caller to do it).
 * Supports wrapping. It must not be called with len == 0.
 */
void __b_putblk(struct buffer *b, const char *blk, size_t len)
{
	size_t half = b_contig_space(b);

	BUG_ON(b_data(b) + len > b_size(b));

	if (half > len)
		half = len;

	memcpy(b_tail(b), blk, half);

	if (len > half)
		memcpy(b_peek(b, b_data(b) + half), blk + half, len - half);
	b->data += len;
}

/* b_xfer() : transfers at most <count> bytes from buffer <src> to buffer <dst>
 * and returns the number of bytes copied. The bytes are removed from <src> and
 * added to <dst>. The caller is responsible for ensuring that <count> is not
 * larger than b_room(dst). Whenever possible (if the destination is empty and
 * at least as much as the source was requested), the buffers are simply
 * swapped instead of copied.
 */
size_t b_xfer(struct buffer *dst, struct buffer *src, size_t count)
{
	size_t ret, block1, block2;

	ret = 0;
	if (!count)
		goto leave;

	ret = b_data(src);
	if (!ret)
		goto leave;

	if (ret > count)
		ret = count;
	else if (!b_data(dst)) {
		/* zero copy is possible by just swapping buffers */
		struct buffer tmp = *dst;
		*dst = *src;
		*src = tmp;
		goto leave;
	}

	block1 = b_contig_data(src, 0);
	if (block1 > ret)
		block1 = ret;
	block2 = ret - block1;

	if (block1)
		__b_putblk(dst, b_head(src), block1);

	if (block2)
		__b_putblk(dst, b_peek(src, block1), block2);

	b_del(src, ret);
 leave:
	return ret;
}

/* b_ncat() : Copy <count> from <src> buffer at the end of <dst> buffer.
 * The caller is  responsible for  ensuring that <count> is not larger than
 * b_room(dst).
 * Returns the number of bytes copied.
 */
size_t b_ncat(struct buffer *dst, const struct buffer *src, size_t count)
{
	size_t ret, block1, block2;

	ret = 0;
	if (!count)
		goto leave;

	ret = b_data(src);
	if (!ret)
		goto leave;

	if (ret > count)
		ret = count;
	block1 = b_contig_data(src, 0);
	if (block1 > ret)
		block1 = ret;
	block2 = ret - block1;

	if (block1)
		__b_putblk(dst, b_head(src), block1);

	if (block2)
		__b_putblk(dst, b_peek(src, block1), block2);

 leave:
	return ret;
}

/* Moves <len> bytes from absolute position <src> of buffer <b> by <shift>
 * bytes, while supporting wrapping of both the source and the destination.
 * The position is relative to the buffer's origin and may overlap with the
 * target position. The <shift>'s absolute value must be strictly lower than
 * the buffer's size. The main purpose is to aggregate data block during
 * parsing while removing unused delimiters. The buffer's length is not
 * modified, and the caller must take care of size adjustments and holes by
 * itself.
 */
void b_move(const struct buffer *b, size_t src, size_t len, ssize_t shift)
{
	char  *orig = b_orig(b);
	size_t size = b_size(b);
	size_t dst  = src + size + shift;
	size_t cnt;

	BUG_ON(len > size);

	if (dst >= size)
		dst -= size;

	if (shift < 0) {
		BUG_ON(-shift >= size);
		/* copy from left to right */
		for (; (cnt = len); len -= cnt) {
			if (cnt > size - src)
				cnt = size - src;
			if (cnt > size - dst)
				cnt = size - dst;

			memmove(orig + dst, orig + src, cnt);
			dst += cnt;
			src += cnt;
			if (dst >= size)
				dst -= size;
			if (src >= size)
				src -= size;
		}
	}
	else if (shift > 0) {
		BUG_ON(shift >= size);
		/* copy from right to left */
		for (; (cnt = len); len -= cnt) {
			size_t src_end = src + len;
			size_t dst_end = dst + len;

			if (dst_end > size)
				dst_end -= size;
			if (src_end > size)
				src_end -= size;

			if (cnt > dst_end)
				cnt = dst_end;
			if (cnt > src_end)
				cnt = src_end;

			memmove(orig + dst_end - cnt, orig + src_end - cnt, cnt);
		}
	}
}

/* b_rep_blk() : writes the block <blk> at position <pos> which must be in
 * buffer <b>, and moves the part between <end> and the buffer's tail just
 * after the end of the copy of <blk>. This effectively replaces the part
 * located between <pos> and <end> with a copy of <blk> of length <len>. The
 * buffer's length is automatically updated. This is used to replace a block
 * with another one inside a buffer. The shift value (positive or negative) is
 * returned. If there's no space left, the move is not done. If <len> is null,
 * the <blk> pointer is allowed to be null, in order to erase a block.
 */
int b_rep_blk(struct buffer *b, char *pos, char *end, const char *blk, size_t len)
{
	int delta;

	BUG_ON(pos < b->area || pos >= b->area + b->size);

	delta = len - (end - pos);

	if (__b_tail(b) + delta > b_wrap(b))
		return 0;  /* no space left */

	if (b_data(b) &&
	    b_tail(b) + delta > b_head(b) &&
	    b_head(b) >= b_tail(b))
		return 0;  /* no space left before wrapping data */

	/* first, protect the end of the buffer */
	memmove(end + delta, end, b_tail(b) - end);

	/* now, copy blk over pos */
	if (len)
		memcpy(pos, blk, len);

	b_add(b, delta);
	b_realign_if_empty(b);

	return delta;
}

/* b_insert_blk(): inserts the block <blk> at the absolute offset <off> moving
 * data between this offset and the buffer's tail just after the end of the copy
 * of <blk>. The buffer's length is automatically updated. It Supports
 * wrapping. If there are not enough space to perform the copy, 0 is
 * returned. Otherwise, the number of bytes copied is returned
*/
int b_insert_blk(struct buffer *b, size_t off, const char *blk, size_t len)
{
	size_t pos;

	if (!len || len > b_room(b))
		return 0; /* nothing to copy or not enough space left */

	pos = b_peek_ofs(b, off);
	if (pos == b_tail_ofs(b))
		__b_putblk(b, blk, len);
	else {
		size_t delta = b_data(b) - off;

		/* first, protect the end of the buffer */
		b_move(b, pos, delta, len);

		/* change the amount of data in the buffer during the copy */
		b_sub(b, delta);
		__b_putblk(b, blk, len);
		b_add(b, delta);
	}
	return len;
}

/* __b_put_varint(): encode 64-bit value <v> as a varint into buffer <b>. The
 * caller must have checked that the encoded value fits in the buffer so that
 * there are no length checks. Wrapping is supported. You don't want to use
 * this function but b_put_varint() instead.
 */
void __b_put_varint(struct buffer *b, uint64_t v)
{
	size_t data = b->data;
	size_t size = b_size(b);
	char  *wrap = b_wrap(b);
	char  *tail = b_tail(b);

	BUG_ON_HOT(data >= size);

	if (v >= 0xF0) {
		/* more than one byte, first write the 4 least significant
		 * bits, then follow with 7 bits per byte.
		 */
		*tail = v | 0xF0;
		v = (v - 0xF0) >> 4;

		while (1) {
			if (++tail == wrap)
				tail -= size;
			data++;
			if (v < 0x80)
				break;
			*tail = v | 0x80;
			v = (v - 0x80) >> 7;
		}
	}

	/* last byte */
	*tail = v;
	BUG_ON_HOT(data >= size);
	data++;
	b->data = data;
}

/* b_put_varint(): try to encode value <v> as a varint into buffer <b>. Returns
 * the number of bytes written in case of success, or 0 if there is not enough
 * room. Wrapping is supported. No partial writes will be performed.
 */
int b_put_varint(struct buffer *b, uint64_t v)
{
	size_t data = b->data;
	size_t size = b_size(b);
	char  *wrap = b_wrap(b);
	char  *tail = b_tail(b);

	if (data != size && v >= 0xF0) {
		BUG_ON_HOT(data > size);

		/* more than one byte, first write the 4 least significant
		 * bits, then follow with 7 bits per byte.
		 */
		*tail = v | 0xF0;
		v = (v - 0xF0) >> 4;

		while (1) {
			if (++tail == wrap)
				tail -= size;
			data++;
			if (data == size || v < 0x80)
				break;
			*tail = v | 0x80;
			v = (v - 0x80) >> 7;
		}
	}

	/* last byte */
	if (data == size)
		return 0;

	*tail = v;
	data++;

	size = data - b->data;
	b->data = data;
	return size;
}

/* b_get_varint(): try to decode a varint from buffer <b> into value <vptr>.
 * Returns the number of bytes read in case of success, or 0 if there were not
 * enough bytes. Wrapping is supported. No partial reads will be performed.
 */
int b_get_varint(struct buffer *b, uint64_t *vptr)
{
	int size;

	size = b_peek_varint(b, 0, vptr);
	b_del(b, size);
	return size;
}


/*
 * Buffer List management.
 */

/* Deinits an array of buffer list. It's the caller's responsibility to check
 * that all buffers were already released. This should be done before any
 * free() of the array.
 */
void bl_deinit(struct bl_elem *head)
{
	BUG_ON_HOT(
		/* make sure that all elements are properly released, i.e. all
		 * are reachable from the free list.
		 */
		({
			uint32_t elem = 0, free = 1;
			if (head->next && !head->buf.data && !head->buf.head) {
				do {
					free++;
					elem = head[elem].next ? head[elem].next : elem + 1;
				} while (elem != ~0 && elem != head->buf.size);
			}
			free != head->buf.size;
		}), "bl_deinit() of a non-completely released list");
}

/* Gets the index of a spare entry in the buffer list, to be used after element
 * of index <idx>. It is detached, appended to the end of the existing list and
 * marked as the last one. If <idx> is zero, the caller requests the creation
 * of a new list entry. If no more buffer slots are available, the function
 * returns zero.
 */
uint32_t bl_get(struct bl_elem *head, uint32_t idx)
{
	uint32_t e, n;

	BUG_ON_HOT(idx >= head->buf.size);

	/* Get the first free element. In the head it's always a valid index or
	 * 0 to indicate the end of list. We can then always dereference it,
	 * and if 0 (empty, which is rare), it'll loop back to itself. This
	 * allows us to save a test in the fast path.
	 */
	e = head->next;    // element to be allocated
	n = head[e].next;  // next one to replace the free list's top
	if (!n) {
		/* Happens only with a freshly initialized array, or when the
		 * free list is depleted (e==0).
		 */
		if (!e)
			goto done;

		/* n is in the free area till the end, let's report the next
		 * free entry, otherwise leave it at zero to mark the end of
		 * the free list.
		 */
		if (e + 1 != head->buf.size)
			n = e + 1;
	}

	head->next = n == ~0U ? 0 : n;
	head->buf.data++;

	if (idx) {
		/* append to a tail: idx must point to a tail */
		BUG_ON_HOT(head[idx].next != ~0);
		head[idx].next = e;
	}
	else {
		/* allocate a new user and offer it this slot */
		head->buf.head++; // #users
	}

	head[e].next = ~0; // mark the end of list
 done:
	/* and finally return the element's index */
	return e;
}
