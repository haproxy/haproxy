/*
 * include/haproxy/buf.h
 * Simple buffer handling - functions definitions.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _HAPROXY_BUF_H
#define _HAPROXY_BUF_H

#include <sys/types.h>
#include <string.h>
#include <haproxy/api.h>
#include <haproxy/buf-t.h>

size_t b_getblk_ofs(const struct buffer *buf, char *blk, size_t len, size_t offset);
size_t b_getblk(const struct buffer *buf, char *blk, size_t len, size_t offset);
size_t b_getdelim(const struct buffer *buf, size_t offset, size_t count,
                  char *str, size_t len, const char *delim, char escape);
size_t b_getline(const struct buffer *buf, size_t offset, size_t count,
                 char *str, size_t len);
void b_slow_realign(struct buffer *b, char *swap, size_t output);
void b_slow_realign_ofs(struct buffer *b, char *swap, size_t ofs);
size_t b_putblk_ofs(struct buffer *buf, char *blk, size_t len, size_t offset);
void __b_putblk(struct buffer *b, const char *blk, size_t len);
size_t b_xfer(struct buffer *dst, struct buffer *src, size_t count);
size_t b_ncat(struct buffer *dst, const struct buffer *src, size_t count);
void b_move(const struct buffer *b, size_t src, size_t len, ssize_t shift);
int b_rep_blk(struct buffer *b, char *pos, char *end, const char *blk, size_t len);
int b_insert_blk(struct buffer *b, size_t off, const char *blk, size_t len);
void __b_put_varint(struct buffer *b, uint64_t v);
int b_put_varint(struct buffer *b, uint64_t v);
int b_get_varint(struct buffer *b, uint64_t *vptr);

void bl_deinit(struct bl_elem *head);
uint32_t bl_get(struct bl_elem *head, uint32_t idx);

/***************************************************************************/
/* Functions used to compute offsets and pointers. Most of them exist in   */
/* both wrapping-safe and unchecked ("__" prefix) variants. Some returning */
/* a pointer are also provided with an "_ofs" suffix when they return an   */
/* offset relative to the storage area.                                    */
/***************************************************************************/

/* b_is_null() : returns true if (and only if) the buffer is not yet allocated
 * and thus has an empty size. Its pointer may then be anything, including NULL
 * (unallocated) or an invalid pointer such as (char*)1 (allocation pending).
 */
static inline int b_is_null(const struct buffer *buf)
{
	return buf->size == 0;
}

/* b_orig() : returns the pointer to the origin of the storage, which is the
 * location of byte at offset zero. This is mostly used by functions which
 * handle the wrapping by themselves.
 */
static inline char *b_orig(const struct buffer *b)
{
	return b->area;
}

/* b_size() : returns the size of the buffer. */
static inline size_t b_size(const struct buffer *b)
{
	return b->size;
}

/* b_wrap() : returns the pointer to the wrapping position of the buffer area,
 * which is by definition the first byte not part of the buffer.
 */
static inline char *b_wrap(const struct buffer *b)
{
	return b->area + b->size;
}

/* b_data() : returns the number of bytes present in the buffer. */
static inline size_t b_data(const struct buffer *b)
{
	return b->data;
}

/* b_room() : returns the amount of room left in the buffer */
static inline size_t b_room(const struct buffer *b)
{
	BUG_ON_HOT(b->data > b->size);
	return b->size - b_data(b);
}

/* b_full() : returns true if the buffer is full. */
static inline size_t b_full(const struct buffer *b)
{
	return !b_room(b);
}

/* b_add_ofs() : return new offset within buffer after applying wrapping. Only
 * offsets resulting from initial positions added to counts within buffer size
 * limits are handled.
 */
static inline size_t b_add_ofs(const struct buffer *b, size_t ofs, size_t count)
{
	ofs += count;
	if (ofs >= b->size)
		ofs -= b->size;
	return ofs;
}

/* b_rel_ofs() : take an absolute offset in the buffer, and return it relative
 * to the buffer's head for use with b_peek().
 */
static inline size_t b_rel_ofs(const struct buffer *b, size_t ofs)
{
	if (ofs < b->head)
		ofs += b->size;
	return ofs - b->head;
}

/* b_stop() : returns the pointer to the byte following the end of the buffer,
 * which may be out of the buffer if the buffer ends on the last byte of the
 * area.
 */
static inline size_t __b_stop_ofs(const struct buffer *b)
{
	return b->head + b->data;
}

static inline const char *__b_stop(const struct buffer *b)
{
	return b_orig(b) + __b_stop_ofs(b);
}

static inline size_t b_stop_ofs(const struct buffer *b)
{
	size_t stop = __b_stop_ofs(b);

	if (stop > b->size)
		stop -= b->size;
	return stop;
}

static inline const char *b_stop(const struct buffer *b)
{
	return b_orig(b) + b_stop_ofs(b);
}


/* b_peek() : returns a pointer to the data at position <ofs> relative to the
 * head of the buffer. Will typically point to input data if called with the
 * amount of output data. The wrapped versions will only support wrapping once
 * before the beginning or after the end.
 */
static inline size_t __b_peek_ofs(const struct buffer *b, size_t ofs)
{
	return b->head + ofs;
}

static inline char *__b_peek(const struct buffer *b, size_t ofs)
{
	return b_orig(b) + __b_peek_ofs(b, ofs);
}

static inline size_t b_peek_ofs(const struct buffer *b, size_t ofs)
{
	size_t ret = __b_peek_ofs(b, ofs);

	if (likely(!__builtin_constant_p(ofs) || ofs))
		if (ret >= b->size)
			ret -= b->size;

	return ret;
}

static inline char *b_peek(const struct buffer *b, size_t ofs)
{
	return b_orig(b) + b_peek_ofs(b, ofs);
}


/* b_head() : returns the pointer to the buffer's head, which is the location
 * of the next byte to be dequeued. Note that for buffers of size zero, the
 * returned pointer may be outside of the buffer or even invalid.
 */
static inline size_t __b_head_ofs(const struct buffer *b)
{
	return b->head;
}

static inline char *__b_head(const struct buffer *b)
{
	return b_orig(b) + __b_head_ofs(b);
}

static inline size_t b_head_ofs(const struct buffer *b)
{
	return __b_head_ofs(b);
}

static inline char *b_head(const struct buffer *b)
{
	return __b_head(b);
}


/* b_tail() : returns the pointer to the tail of the buffer, which is the
 * location of the first byte where it is possible to enqueue new data. Note
 * that for buffers of size zero, the returned pointer may be outside of the
 * buffer or even invalid.
 */
static inline size_t __b_tail_ofs(const struct buffer *b)
{
	return __b_peek_ofs(b, b_data(b));
}

static inline char *__b_tail(const struct buffer *b)
{
	return __b_peek(b, b_data(b));
}

static inline size_t b_tail_ofs(const struct buffer *b)
{
	return b_peek_ofs(b, b_data(b));
}

static inline char *b_tail(const struct buffer *b)
{
	return b_peek(b, b_data(b));
}


/* b_next() : for an absolute pointer <p> or a relative offset <o> pointing to
 * a valid location within buffer <b>, returns either the absolute pointer or
 * the relative offset pointing to the next byte, which usually is at (p + 1)
 * unless p reaches the wrapping point and wrapping is needed.
 */
static inline size_t b_next_ofs(const struct buffer *b, size_t o)
{
	o++;
	BUG_ON_HOT(o > b->size);
	if (o == b->size)
		o = 0;
	return o;
}

static inline char *b_next(const struct buffer *b, const char *p)
{
	p++;
	BUG_ON_HOT(p > b_wrap(b));
	if (p == b_wrap(b))
		p = b_orig(b);
	return (char *)p;
}

/* b_dist() : returns the distance between two pointers, taking into account
 * the ability to wrap around the buffer's end. The operation is not defined if
 * either of the pointers does not belong to the buffer or if their distance is
 * greater than the buffer's size.
 */
static inline size_t b_dist(const struct buffer *b, const char *from, const char *to)
{
	ssize_t dist = to - from;

	BUG_ON_HOT((dist > 0 && dist > b_size(b)) || (dist < 0 && -dist > b_size(b)));
	dist += dist < 0 ? b_size(b) : 0;
	return dist;
}

/* b_almost_full() : returns 1 if the buffer uses at least 3/4 of its capacity,
 * otherwise zero. Buffers of size zero are considered full.
 */
static inline int b_almost_full(const struct buffer *b)
{
	BUG_ON_HOT(b->data > b->size);
	return b_data(b) >= b_size(b) * 3 / 4;
}

/* b_space_wraps() : returns non-zero only if the buffer's free space wraps :
 *  [     |xxxx|           ]    => yes
 *  [xxxx|                 ]    => no
 *  [                 |xxxx]    => no
 *  [xxxx|            |xxxx]    => no
 *  [xxxxxxxxxx|xxxxxxxxxxx]    => no
 *
 *  So the only case where the buffer does not wrap is when there's data either
 *  at the beginning or at the end of the buffer. Thus we have this :
 *  - if (head <= 0)    ==> doesn't wrap
 *  - if (tail >= size) ==> doesn't wrap
 *  - otherwise wraps
 */
static inline int b_space_wraps(const struct buffer *b)
{
	BUG_ON_HOT(b->data > b->size);
	if ((ssize_t)__b_head_ofs(b) <= 0)
		return 0;
	if (__b_tail_ofs(b) >= b_size(b))
		return 0;
	return 1;
}

/* b_contig_data() : returns the amount of data that can contiguously be read
 * at once starting from a relative offset <start> (which allows to easily
 * pre-compute blocks for memcpy). The start point will typically contain the
 * amount of past data already returned by a previous call to this function.
 */
static inline size_t b_contig_data(const struct buffer *b, size_t start)
{
	size_t data = b_wrap(b) - b_peek(b, start);
	size_t limit = b_data(b) - start;

	if (data > limit)
		data = limit;
	return data;
}

/* b_contig_space() : returns the amount of bytes that can be appended to the
 * buffer at once. We have 8 possible cases :
 *
 * [____________________]  return size
 * [______|_____________]  return size - tail_ofs
 * [XXXXXX|_____________]  return size - tail_ofs
 * [___|XXXXXX|_________]  return size - tail_ofs
 * [______________XXXXXX]  return head_ofs
 * [XXXX|___________|XXX]  return head_ofs - tail_ofs
 * [XXXXXXXXXX|XXXXXXXXX]  return 0
 * [XXXXXXXXXXXXXXXXXXXX]  return 0
 */
static inline size_t b_contig_space(const struct buffer *b)
{
	size_t left, right;

	BUG_ON_HOT(b->data > b->size);

	right = b_head_ofs(b);
	left  = right + b_data(b);

	left = b_size(b) - left;
	if ((ssize_t)left <= 0)
		left += right;
	return left;
}


/*********************************************/
/* Functions used to modify the buffer state */
/*********************************************/

/* b_reset() : resets a buffer. The size is not touched. */
static inline void b_reset(struct buffer *b)
{
	b->head = 0;
	b->data = 0;
}

/* b_make() : make a buffer from all parameters */
static inline struct buffer b_make(char *area, size_t size, size_t head, size_t data)
{
	struct buffer b;

	b.area = area;
	b.size = size;
	b.head = head;
	b.data = data;
	return b;
}

/* b_sub() : decreases the buffer length by <count> */
static inline void b_sub(struct buffer *b, size_t count)
{
	BUG_ON_HOT(b->data < count);
	b->data -= count;
}

/* b_add() : increase the buffer length by <count> */
static inline void b_add(struct buffer *b, size_t count)
{
	BUG_ON_HOT(b->data + count > b->size);
	b->data += count;
}

/* b_set_data() : sets the buffer's length */
static inline void b_set_data(struct buffer *b, size_t len)
{
	BUG_ON_HOT(len > b->size);
	b->data = len;
}

/* b_del() : skips <del> bytes in a buffer <b>. Covers both the output and the
 * input parts so it's up to the caller to know where it plays and that <del>
 * is always smaller than the amount of data in the buffer.
 */
static inline void b_del(struct buffer *b, size_t del)
{
	BUG_ON_HOT(b->data < del);
	b->data -= del;
	b->head += del;
	if (b->head >= b->size)
		b->head -= b->size;
}

/* b_realign_if_empty() : realigns a buffer if it's empty */
static inline void b_realign_if_empty(struct buffer *b)
{
	if (!b_data(b))
		b->head = 0;
}

/* b_putchar() : tries to append char <c> at the end of buffer <b>. Supports
 * wrapping. Data are truncated if buffer is full.
 */
static inline void b_putchr(struct buffer *b, char c)
{
	if (b_full(b))
		return;
	*b_tail(b) = c;
	b->data++;
}

/* b_putblk() : tries to append block <blk> at the end of buffer <b>. Supports
 * wrapping. Data are truncated if buffer is too short. It returns the number
 * of bytes copied.
 */
static inline size_t b_putblk(struct buffer *b, const char *blk, size_t len)
{
	if (len > b_room(b))
		len = b_room(b);
	if (len)
		__b_putblk(b, blk, len);
	return len;
}

/* b_force_xfer() : same as b_xfer() but without zero copy.
 * The caller is responsible for ensuring that <count> is not
 * larger than b_room(dst).
 */
static inline size_t b_force_xfer(struct buffer *dst, struct buffer *src, size_t count)
{
	size_t ret;

	ret = b_ncat(dst, src, count);
	b_del(src, ret);

	return ret;
}

/* b_getblk_nc() : gets one or two blocks of data at once from a buffer,
 * starting from offset <ofs> after the beginning of its output, and limited to
 * no more than <max> bytes. The caller is responsible for ensuring that
 * neither <ofs> nor <ofs>+<max> exceed the total number of bytes available in
 * the buffer. Return values :
 *   >0 : number of blocks filled (1 or 2). blk1 is always filled before blk2.
 *   =0 : not enough data available. <blk*> are left undefined.
 * The buffer is left unaffected. Unused buffers are left in an undefined state.
 */
static inline size_t b_getblk_nc(const struct buffer *buf, const char **blk1, size_t *len1, const char **blk2, size_t *len2, size_t ofs, size_t max)
{
	size_t l1;

	BUG_ON_HOT(buf->data > buf->size);
	BUG_ON_HOT(ofs > buf->data);
	BUG_ON_HOT(ofs + max > buf->data);

	if (!max)
		return 0;

	*blk1 = b_peek(buf, ofs);
	l1 = b_wrap(buf) - *blk1;
	if (l1 < max) {
		*len1 = l1;
		*len2 = max - l1;
		*blk2 = b_orig(buf);
		return 2;
	}
	*len1 = max;
	return 1;
}

/* b_peek_varint(): try to decode a varint from buffer <b> at offset <ofs>
 * relative to head, into value <vptr>. Returns the number of bytes parsed in
 * case of success, or 0 if there were not enough bytes, in which case the
 * contents of <vptr> are not updated. Wrapping is supported. The buffer's head
 * will NOT be updated. It is illegal to call this function with <ofs> greater
 * than b->data.
 */
static inline int b_peek_varint(struct buffer *b, size_t ofs, uint64_t *vptr)
{
	const uint8_t *head = (const uint8_t *)b_peek(b, ofs);
	const uint8_t *wrap = (const uint8_t *)b_wrap(b);
	size_t data = b_data(b) - ofs;
	size_t size = b_size(b);
	uint64_t v = 0;
	int bits = 0;

	BUG_ON_HOT(ofs > b_data(b));

	if (data != 0 && (*head >= 0xF0)) {
		v = *head;
		bits += 4;
		while (1) {
			if (++head == wrap)
				head -= size;
			data--;
			if (!data || !(*head & 0x80))
				break;
			v += (uint64_t)*head << bits;
			bits += 7;
		}
	}

	/* last byte */
	if (!data)
		return 0;

	v += (uint64_t)*head << bits;
	*vptr = v;
	data--;
	size = b->data - ofs - data;
	return size;
}


/*
 * Buffer ring management.
 *
 * A buffer ring is a circular list of buffers, with a head buffer (the oldest,
 * being read from) and a tail (the newest, being written to). Such a ring is
 * declared as an array of buffers. The first element in the array is the root
 * and is used differently. It stores the following elements :
 *  - size : number of allocated elements in the array, including the root
 *  - area : magic value BUF_RING (just to help debugging)
 *  - head : position of the head in the array (starts at one)
 *  - data : position of the tail in the array (starts at one).
 *
 * Note that contrary to a linear buffer, head and tail may be equal with room
 * available, since the producer is expected to fill the tail. Also, the tail
 * might pretty much be equal to BUF_WANTED if an allocation is pending, in
 * which case it's illegal to try to allocate past this point (only one entry
 * may be subscribed for allocation). It is illegal to allocate a buffer after
 * an empty one, so that BUF_NULL is always the last buffer. It is also illegal
 * to remove elements without freeing the buffers. Buffers between <tail> and
 * <head> are in an undefined state, but <tail> and <head> are always valid.
 * A ring may not contain less than 2 elements, since the root is mandatory,
 * and at least one entry is required to always present a valid buffer.
 *
 * Given that buffers are 16- or 32- bytes long, it's convenient to set the
 * size of the array to 2^N in order to keep (2^N)-1 elements, totalizing
 * 2^N*16(or 32) bytes. For example on a 64-bit system, a ring of 31 usable
 * buffers takes 1024 bytes.
 */

/* Initialization of a ring, the size argument contains the number of allocated
 * elements, including the root. There must always be at least 2 elements, one
 * for the root and one for storage.
 */
static inline void br_init(struct buffer *r, size_t size)
{
	BUG_ON(size < 2);

	r->size = size;
	r->area = BUF_RING.area;
	r->head = r->data = 1;
	r[1]    = BUF_NULL;
}

/* Returns number of elements in the ring, root included */
static inline unsigned int br_size(const struct buffer *r)
{
	BUG_ON_HOT(r->area != BUF_RING.area);

	return r->size;
}

/* Returns true if no more buffers may be added */
static inline unsigned int br_full(const struct buffer *r)
{
	BUG_ON_HOT(r->area != BUF_RING.area);

	return r->data + 1 == r->head || r->data + 1 == r->head - 1 + r->size;
}

/* Returns the number of buffers present */
static inline unsigned int br_count(const struct buffer *r)
{
	BUG_ON_HOT(r->area != BUF_RING.area);

	if (r->data >= r->head)
		return r->data - r->head + 1;
	else
		return r->data + r->size - r->head;
}

/* Returns true if a single buffer is assigned */
static inline unsigned int br_single(const struct buffer *r)
{
	BUG_ON_HOT(r->area != BUF_RING.area);

	return r->data == r->head;
}

/* Returns the index of the ring's head buffer */
static inline unsigned int br_head_idx(const struct buffer *r)
{
	BUG_ON_HOT(r->area != BUF_RING.area);

	return r->head;
}

/* Returns the index of the ring's tail buffer */
static inline unsigned int br_tail_idx(const struct buffer *r)
{
	BUG_ON_HOT(r->area != BUF_RING.area);

	return r->data;
}

/* Returns a pointer to the ring's head buffer */
static inline struct buffer *br_head(struct buffer *r)
{
	BUG_ON_HOT(r->area != BUF_RING.area);

	return r + br_head_idx(r);
}

/* Returns a pointer to the ring's tail buffer */
static inline struct buffer *br_tail(struct buffer *r)
{
	BUG_ON_HOT(r->area != BUF_RING.area);

	return r + br_tail_idx(r);
}

/* Returns the amount of data of the ring's HEAD buffer */
static inline unsigned int br_data(const struct buffer *r)
{
	BUG_ON_HOT(r->area != BUF_RING.area);

	return b_data(r + br_head_idx(r));
}

/* Returns non-zero if the ring is non-full or its tail has some room */
static inline unsigned int br_has_room(const struct buffer *r)
{
	BUG_ON_HOT(r->area != BUF_RING.area);

	if (!br_full(r))
		return 1;
	return b_room(r + br_tail_idx(r));
}

/* Advances the ring's tail if it points to a non-empty buffer, and returns the
 * buffer, or NULL if the ring is full or the tail buffer is already empty. A
 * new buffer is initialized to BUF_NULL before being returned. This is to be
 * used after failing to append data, in order to decide to retry or not.
 */
static inline struct buffer *br_tail_add(struct buffer *r)
{
	struct buffer *b;

	BUG_ON_HOT(r->area != BUF_RING.area);

	b = br_tail(r);
	if (!b_size(b))
		return NULL;

	if (br_full(r))
		return NULL;

	r->data++;
	if (r->data >= r->size)
		r->data = 1;

	b = br_tail(r);
	*b = BUF_NULL;
	return b;
}

/* Extracts the ring's head buffer and returns it. The last buffer (tail) is
 * never removed but it is returned. This guarantees that we stop on BUF_WANTED
 * or BUF_EMPTY and that at the end a valid buffer remains present. This is
 * used for pre-extraction during a free() loop for example. The caller is
 * expected to detect the end (e.g. using bsize() since b_free() voids the
 * buffer).
 */
static inline struct buffer *br_head_pick(struct buffer *r)
{
	struct buffer *b;

	BUG_ON_HOT(r->area != BUF_RING.area);

	b = br_head(r);
	if (r->head != r->data) {
		r->head++;
		if (r->head >= r->size)
			r->head = 1;
	}
	return b;
}

/* Advances the ring's head and returns the next buffer, unless it's already
 * the tail, in which case the tail itself is returned. This is used for post-
 * parsing deletion. The caller is expected to detect the end (e.g. a parser
 * will typically purge the head before proceeding).
 */
static inline struct buffer *br_del_head(struct buffer *r)
{
	BUG_ON_HOT(r->area != BUF_RING.area);

	if (r->head != r->data) {
		r->head++;
		if (r->head >= r->size)
			r->head = 1;
	}
	return br_head(r);
}

/*
 * Buffer list management.
 */

/* Returns the number of users of at least one entry */
static inline uint32_t bl_users(const struct bl_elem *head)
{
	return head->buf.head;
}

/* Returns the number of allocatable cells */
static inline uint32_t bl_size(const struct bl_elem *head)
{
	return head->buf.size - 1;
}

/* Returns the number of cells currently in use */
static inline uint32_t bl_used(const struct bl_elem *head)
{
	return head->buf.data;
}

/* Returns the number of cells still available */
static inline uint32_t bl_avail(const struct bl_elem *head)
{
	return bl_size(head) - bl_used(head);
}

/* Initializes an array of <nbelem> elements of type bl_elem (one less will be
 * allocatable). The initialized array is returned on success, otherwise NULL
 * on allocation failure.
 */
static inline void bl_init(struct bl_elem *head, uint32_t nbelem)
{
	BUG_ON_HOT(nbelem < 2);
	memset(head, 0, nbelem * sizeof(*head));
	head->buf.size = nbelem;
	head->next = 1;
}

/* Puts the cell at index <idx> back into the list <head>. It must have been
 * freed from its buffer before calling this, and must correspond to the head
 * of the caller. It returns the new head for the caller (the next cell
 * immediately after the current one), or zero if the list is empty, in which
 * case the caller is considered as no longer belonging to the list.
 */
static inline uint32_t bl_put(struct bl_elem *head, uint32_t idx)
{
	uint32_t n;

	BUG_ON_HOT(!idx || idx >= head->buf.size);
	n = head[idx].next;

	/* if the element was the last one (head[idx].next == ~0) then the
	 * chain is entirely gone and the caller is no longer in the list.
	 */
	if (n == ~0) {
		BUG_ON_HOT(!head->buf.head);
		head->buf.head--; // #users
		n = 0;            // no next
	}

	/* If the free list was empty (next==0), this element becomes both the
	 * first and the last one, otherwise it inserts itself before the
	 * previous first free element.
	 */
	head[idx].next = head->next ? head->next : ~0U;
	head->next = idx;
	BUG_ON_HOT(!head->buf.data);
	head->buf.data--; // one less allocated
	return n;
}

#endif /* _HAPROXY_BUF_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
