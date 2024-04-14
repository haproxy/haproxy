/*
 * include/haproxy/vecpair.h
 * Vector pair handling - functions definitions.
 *
 * Copyright (C) 2000-2024 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_VECPAIR_H
#define _HAPROXY_VECPAIR_H

#include <sys/types.h>
#include <string.h>
#include <import/ist.h>
#include <haproxy/api.h>


/* Principles of operation
 * -----------------------
 * These functions take two vectors represented as ISTs, they're each the
 * pointer to and the length of a work area. Functions operate over these
 * two areas as if they were a contiguous area. It is up to the caller to
 * use them to designate free space or data depending on whether it wants
 * to write or read to the area. This allows to easily represent a wrapping
 * buffer, both for data and free space.
 *
 * In order to ease sequencing of operations, most of the functions below
 * will:
 *   - always consider v1 before v2
 *   - always ignore any vector whose length is zero (the pointer is ignored)
 *   - automatically switch from v1 to v2 upon updates, including if their
 *     size is zero
 *   - end after both v1 and v2 are depleted (len==0)
 *   - update the affected vectors after operation (pointer, length) so that
 *     they can easily be chained without adding new tests
 *   - return the number of bytes processed after operation.
 *
 * These functions do not need to know the allocated size nor any such thing,
 * it's the caller's job to know that and to build the relevant vector pair.
 * See the vp_{ring,data,room}_to_{ring,data,room}() functions at the end for
 * this.
 */

/* vp_isempty(): returns true if both areas are empty */
static inline int vp_isempty(const struct ist v1, const struct ist v2)
{
	return !v1.len && !v2.len;
}

/* vp_size(): returns the total size of the two vectors */
static inline size_t vp_size(const struct ist v1, const struct ist v2)
{
	return v1.len + v2.len;
}

/* _vp_head() : returns the pointer to the head (beginning) of the area, which is
 * the address of the first byte of the first non-empty area. It must not be
 * called with both areas empty.
 */
static inline char *_vp_head(const struct ist v1, const struct ist v2)
{
	return v1.len ? v1.ptr : v2.ptr;
}

/* vp_head() : returns the pointer to the head (beginning) of the area, which is
 * the address of the first byte of the first non-empty area. It may return
 * NULL if both areas are empty.
 */
static inline char *vp_head(const struct ist v1, const struct ist v2)
{
	return v1.len ? v1.ptr : v2.len ? v2.ptr : NULL;
}

/* _vp_addr() : return the address corresponding to applying an offset <ofs>
 * after the head. It must not be called with an offset larger than the total
 * area size.
 */
static inline char *_vp_addr(const struct ist v1, const struct ist v2, size_t ofs)
{
	if (ofs < v1.len)
		return v1.ptr + ofs;
	else {
		ofs -= v1.len;
		return v2.ptr + ofs;
	}
}

/* vp_addr() : return the address corresponding to applying an offset <ofs>
 * after the head. It may return NULL if the length is beyond the total area
 * size.
 */
static inline char *vp_addr(const struct ist v1, const struct ist v2, size_t ofs)
{
	if (ofs < v1.len)
		return v1.ptr + ofs;
	else {
		ofs -= v1.len;
		if (ofs >= v2.len)
			return NULL;
		return v2.ptr + ofs;
	}
}

/* vp_ofs() : return the offset corresponding to the pointer <p> within either
 * v1 or v2, or a size equal to the sum of both lengths if <p> is outside both
 * areas.
 */
static inline size_t vp_ofs(const struct ist v1, const struct ist v2, const char *p)
{
	if (p >= v1.ptr && p < v1.ptr + v1.len)
		return p - v1.ptr;

	if (p >= v2.ptr && p < v2.ptr + v2.len)
		return v1.len + (p - v2.ptr);

	return v1.len + v2.len;
}

/* vp_next() : return the address of the next character after <p> or NULL if it
 * runs out of both v1 and v2.
 */
static inline char *vp_next(const struct ist v1, const struct ist v2, const char *p)
{
	size_t ofs = vp_ofs(v1, v2, p);

	return vp_addr(v1, v2, ofs + 1);
}

/* vp_seek_addr() : return the pointer to the byte at relative offset <seek> in
 * the area(s). The caller must ensure that seek is strictly smaller than the
 * total amount of bytes in the vectors.
 */
static inline char *vp_seek_addr(struct ist v1, struct ist v2, size_t seek)
{
	if (seek < v1.len)
		return v1.ptr + seek;
	else
		return v2.ptr + seek - v1.len;
}

/*********************************************/
/* Functions used to modify the buffer state */
/*********************************************/

/* vp_skip() : skip the requested amount of bytes from the area(s) and update
 * them accordingly. If the amount to skip exceeds the total size of the two
 * areas, they're emptied and the total number of emptied bytes is returned.
 * It is unspecified what area pointers point to after their len is emptied.
 */
static inline size_t vp_skip(struct ist *v1, struct ist *v2, size_t skip)
{
	if (skip <= v1->len) {
		v1->ptr += skip;
		v1->len -= skip;
	}
	else {
		if (skip > v1->len + v2->len)
			skip = v1->len + v2->len;

		v2->ptr += skip - v1->len;
		v2->len -= skip - v1->len;
		v1->ptr += v1->len;
		v1->len  = 0;
	}
	return skip;
}

/* vp_getchr() : tries to retrieve the next from the beginning of the area, and
 * advance the beginning by one char on success. An int equal to the unsigned
 * char is returned on success, otherwise a negative value if there is nothing
 * left in the area.
 */
static inline int vp_getchr(struct ist *v1, struct ist *v2)
{
	int c = -1;

	if (v1->len) {
		v1->len--;
		c = (unsigned char)*(v1->ptr++);
	}
	else if (v2->len) {
		v2->len--;
		c = (unsigned char)*(v2->ptr++);
	}

	return c;
}

/* vp_getblk_ofs() : gets one full block of data at once from a pair of vectors,
 * starting from offset <ofs> after the head, and for up to <len> bytes. The
 * caller is responsible for ensuring that <ofs> does not exceed the total
 * number of bytes available in the areas. The areas will then be updated so
 * that the next head points to the first unread byte (i.e. skip <ofs> plus
 * the number of bytes returned). The number of bytes copied is returned. This
 * is meant to be used on concurrently accessed areas, so that a reader can
 * read a known area while it is been concurrently fed and/or trimmed. Usually
 * you'd prefer to use the more convenient vp_getblk() or vp_peek_ofs().
 */
static inline size_t vp_getblk_ofs(struct ist *v1, struct ist *v2, size_t ofs, char *blk, size_t len)
{
	size_t ret = 0;
	size_t block;

	BUG_ON_HOT(ofs >= v1->len + v2->len);

	vp_skip(v1, v2, ofs);

	block = v1->len;
	if (block > len)
		block = len;

	if (block) {
		memcpy(blk + ret, v1->ptr, block);
		v1->ptr += block;
		v1->len -= block;
		ret += block;
		len -= block;
	}

	block = v2->len;
	if (block > len)
		block = len;

	if (block) {
		memcpy(blk + ret, v2->ptr, block);
		v2->ptr += block;
		v2->len -= block;
		ret += block;
	}

	return ret;
}

/* vp_getblk() : gets one full block of data at once from a pair of vectors,
 * starting from their head, and for up to <len> bytes. The areas will be
 * updated so that the next head points to the first unread byte. The number
 * of bytes copied is returned.  This is meant to be used on concurrently
 * accessed areas, so that a reader can read a known area while it is been
 * concurrently fed and/or trimmed. See also vp_peek_ofs().
 */
static inline size_t vp_getblk(struct ist *v1, struct ist *v2, char *blk, size_t len)
{
	return vp_getblk_ofs(v1, v2, 0, blk, len);
}

/* vp_peek() : gets one full block of data at once from a pair of vectors,
 * starting from offset <ofs> after the head, and for up to <len> bytes.
 * The caller is responsible for ensuring that <ofs> does not exceed the
 * total number of bytes available in the areas. The areas are *not* updated.
 * The number of bytes copied is returned. This is meant to be used on
 * concurrently accessed areas, so that a reader can read a known area while
 * it is been concurrently fed and/or trimmed. See also vp_getblk().
 */
static inline size_t vp_peek_ofs(struct ist v1, struct ist v2, size_t ofs, char *blk, size_t len)
{
	return vp_getblk_ofs(&v1, &v2, ofs, blk, len);
}

/* vp_putchr() : tries to append char <c> at the beginning of the area, and
 * advance the beginning by one char. Data are truncated if there is no room
 * left.
 */
static inline void vp_putchr(struct ist *v1, struct ist *v2, char c)
{
	if (v1->len) {
		v1->len--;
		*(v1->ptr++) = c;
	}
	else if (v2->len) {
		v2->len--;
		*(v2->ptr++) = c;
	}
}

/* vp_putblk_ofs() : put one full block of data at once into a pair of vectors,
 * starting from offset <ofs> after the head, and for exactly <len> bytes.
 * The caller is responsible for ensuring that <ofs> does not exceed the total
 * number of bytes available in the areas. The function will check that it is
 * indeed possible to put <len> bytes after <ofs> before proceeding. If the
 * areas can accept such data, they will then be updated so that the next
 * head points to the first untouched byte (i.e. skip <ofs> plus the number
 * of bytes sent). The number of bytes copied is returned on success, or 0 is
 * returned if it cannot be copied, in which case the areas are left
 * untouched. This is meant to be used on concurrently accessed areas, so that
 * a reader can read a known area while it is been concurrently fed and/or
 * trimmed. Usually you'd prefer to use the more convenient vp_putblk() or
 * vp_poke_ofs().
 */
static inline size_t vp_putblk_ofs(struct ist *v1, struct ist *v2, size_t ofs, const char *blk, size_t len)
{
	size_t ret = 0;
	size_t block;

	BUG_ON_HOT(ofs >= v1->len + v2->len);

	if (len && ofs + len <= v1->len + v2->len) {
		vp_skip(v1, v2, ofs);

		block = v1->len;
		if (block > len)
			block = len;

		if (block) {
			memcpy(v1->ptr, blk + ret, block);
			v1->ptr += block;
			v1->len -= block;
			ret += block;
			len -= block;
		}

		block = v2->len;
		if (block > len)
			block = len;

		if (block) {
			memcpy(v2->ptr, blk + ret, block);
			v2->ptr += block;
			v2->len -= block;
			ret += block;
		}
	}
	return ret;
}

/* vp_pokeblk() : puts one full block of data at once into a pair of vectors,
 * starting from offset <ofs> after the head, and for exactly <len> bytes.
 * The caller is responsible for ensuring that neither <ofs> nor <ofs> + <len>
 * exceed the total number of bytes available in the areas. This is meant to
 * be used on concurrently accessed areas, so that a reader can read a known
 * area while* it is been concurrently fed and/or trimmed. The area pointers
 * are left unaffected. The number of bytes copied is returned.
 */
static inline size_t vp_poke_ofs(struct ist v1, struct ist v2, size_t ofs, const char *blk, size_t len)
{
	return vp_putblk_ofs(&v1, &v2, ofs, blk, len);
}

/* vp_putblk() : put one full block of data at once into a pair of vectors,
 * starting at the head, and for exactly <len> bytes. The caller is
 * responsible for ensuring that <len> does not exceed the total number of
 * bytes available in the areas. This is meant to be used on concurrently
 * accessed areas, so that a reader can read a known area while it is been
 * concurrently fed and/or trimmed. The area pointers are updated according to
 * the amount of bytes copied. The number of bytes copied is returned.
 */
static inline size_t vp_putblk(struct ist *v1, struct ist *v2, const char *blk, size_t len)
{
	vp_putblk_ofs(v1, v2, 0, blk, len);
	return len;
}

/* vp_put_varint_ofs(): encode 64-bit value <v> as a varint into a pair of
 * vectors, starting at an offset after the head. The code assumes that the
 * caller has checked that the encoded value fits in the areas so that there
 * are no length checks inside the loop. Vectors are updated and the number of
 * written bytes is returned (excluding the offset).
 */
static inline size_t vp_put_varint_ofs(struct ist *v1, struct ist *v2, size_t ofs, uint64_t v)
{
	size_t data = 0;

	BUG_ON_HOT(ofs >= v1->len + v2->len);

	vp_skip(v1, v2, ofs);

	if (v >= 0xF0) {
		/* more than one byte, first write the 4 least significant
		 * bits, then follow with 7 bits per byte.
		 */
		vp_putchr(v1, v2, v | 0xF0);
		v = (v - 0xF0) >> 4;

		while (1) {
			data++;
			if (v < 0x80)
				break;
			vp_putchr(v1, v2, v | 0x80);
			v = (v - 0x80) >> 7;
		}
	}

	/* last byte */
	vp_putchr(v1, v2, v);
	data++;
	return data;
}

/* vp_put_varint(): encode 64-bit value <v> as a varint into a pair of vectors,
 * starting at the head. The code assumes that the caller has checked that
 * the encoded value fits in the areas so that there are no length checks
 * inside the loop. Vectors are updated and the number of written bytes is
 * returned.
 */
static inline size_t vp_put_varint(struct ist *v1, struct ist *v2, uint64_t v)
{
	return vp_put_varint_ofs(v1, v2, 0, v);
}

/* vp_get_varint_ofs(): try to decode a varint from a pair of vectors, starting
 * at offset <ofs> after the head, into value <vptr>. Returns the number of
 * bytes parsed in case of success, or 0 if there were not enough bytes, in
 * which case the contents of <vptr> are not updated. Vectors are updated to
 * skip the offset and the number of bytes parsed if there are enough bytes,
 * otherwise the parsing area is left untouched. The code assumes the caller
 * has checked that the offset is smaller than or equal to the number of bytes
 * in the vectors.
 */
static inline size_t vp_get_varint_ofs(struct ist *v1, struct ist *v2, size_t ofs, uint64_t *vptr)
{
	size_t data = v1->len + v2->len;
	const char *head, *wrap;
	uint64_t v = 0;
	int bits = 0;
	size_t ret;

	BUG_ON_HOT(ofs > data);

	vp_skip(v1, v2, ofs);

	/* let's see where we start from. The wrapping area only concerns the
	 * end of the first area, even if it's empty it does not overlap with
	 * the second one so we don't care about v1 being set or not.
	 */
	head = v1->len ? v1->ptr : v2->ptr;
	wrap = v1->ptr + v1->len;
	data -= ofs;

	if (data != 0 && ((uint8_t)*head >= 0xF0)) {
		v = (uint8_t)*head;
		bits += 4;
		while (1) {
			if (++head == wrap)
				head = v2->ptr;
			data--;
			if (!data || !(*head & 0x80))
				break;
			v += (uint64_t)(uint8_t)*head << bits;
			bits += 7;
		}
	}

	/* last byte */
	if (!data)
		return 0;

	v += (uint64_t)(uint8_t)*head << bits;
	*vptr = v;
	data--;

	ret = v1->len + v2->len - data;
	vp_skip(v1, v2, ret);
	return ret;
}

/* vp_get_varint(): try to decode a varint from a pair of vectors, starting at
 * the head, into value <vptr>. Returns the number of bytes parsed in case of
 * success, or 0 if there were not enough bytes, in which case the contents of
 * <vptr> are not updated. Vectors are updated to skip the bytes parsed if
 * there are enough bytes, otherwise they're left untouched.
 */
static inline size_t vp_get_varint(struct ist *v1, struct ist *v2, uint64_t *vptr)
{
	return vp_get_varint_ofs(v1, v2, 0, vptr);
}

/* vp_peek_varint_ofs(): try to decode a varint from a pair of vectors, starting at
 * the head, into value <vptr>. Returns the number of bytes parsed in case of
 * success, or 0 if there were not enough bytes, in which case the contents of
 * <vptr> are not updated.
 */
static inline size_t vp_peek_varint_ofs(struct ist v1, struct ist v2, size_t ofs, uint64_t *vptr)
{
	return vp_get_varint_ofs(&v1, &v2, ofs, vptr);
}


/************************************************************/
/* ring-buffer API                                          */
/* This is used to manipulate rings made of (head,tail)     */
/* It creates vectors for reading (data) and writing (room) */
/************************************************************/

/* build 2 vectors <v1> and <v2> corresponding to the available data in ring
 * buffer of size <size>, starting at address <area>, with a head <head> and
 * a tail <tail>. <v2> is non-empty only if the data wraps (i.e. tail<head).
 */
static inline void vp_ring_to_data(struct ist *v1, struct ist *v2, char *area, size_t size, size_t head, size_t tail)
{
	v1->ptr = area + head;
	v1->len = ((head <= tail) ? tail : size) - head;
	v2->ptr = area;
	v2->len = (tail < head) ? tail : 0;
}

/* build 2 vectors <v1> and <v2> corresponding to the available room in ring
 * buffer of size <size>, starting at address <area>, with a head <head> and
 * a tail <tail>. <v2> is non-empty only if the room wraps (i.e. head>tail).
 */
static inline void vp_ring_to_room(struct ist *v1, struct ist *v2, char *area, size_t size, size_t head, size_t tail)
{
	v1->ptr = area + tail;
	v1->len = ((tail <= head) ? head : size) - tail;
	v2->ptr = area;
	v2->len = (head < tail) ? head : 0;
}

/* Set a ring's <head> and <tail> according to the data area represented by the
 * concatenation of <v1> and <v2> which must point to two adjacent areas within
 * a ring buffer of <size> bytes starting at <area>. <v1>, if not empty, starts
 * at the head and <v2>, if not empty, ends at the tail. If both vectors are of
 * length zero, the ring is considered empty and both its head and tail will be
 * reset.
 */
static inline void vp_data_to_ring(const struct ist v1, const struct ist v2, char *area, size_t size, size_t *head, size_t *tail)
{
	size_t ofs;

	if (!v1.len && !v2.len) {
		*head = *tail = 0;
		return;
	}

	ofs = (v1.len ? v1.ptr : v2.ptr) - area;
	if (ofs >= size)
		ofs -= size;
	*head = ofs;

	ofs = (v2.len ? v2.ptr + v2.len : v1.ptr + v1.len) - area;
	if (ofs >= size)
		ofs -= size;
	*tail = ofs;
}

/* Set a ring's <head> and <tail> according to the room area represented by the
 * concatenation of <v1> and <v2> which must point to two adjacent areas within
 * a ring buffer of <size> bytes starting at <area>. <v1>, if not empty, starts
 * at the tail and <v2>, if not empty, ends at the head. If both vectors are of
 * length zero, the ring is considered full and both its head and tail will be
 * reset (which cannot be distinguished from empty). The caller must make sure
 * not to fill a ring with this API.
 */
static inline void vp_room_to_ring(const struct ist v1, const struct ist v2, char *area, size_t size, size_t *head, size_t *tail)
{
	size_t ofs;

	if (!v1.len && !v2.len) {
		*head = *tail = 0;
		return;
	}

	ofs = (v1.len ? v1.ptr : v2.ptr) - area;
	if (ofs >= size)
		ofs -= size;
	*tail = ofs;

	ofs = (v2.len ? v2.ptr + v2.len : v1.ptr + v1.len) - area;
	if (ofs >= size)
		ofs -= size;
	*head = ofs;
}

#endif /* _HAPROXY_VECPAIR_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
