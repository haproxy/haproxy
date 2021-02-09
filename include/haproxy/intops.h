/*
 * include/haproxy/intops.h
 * Functions for integer operations.
 *
 * Copyright (C) 2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_INTOPS_H
#define _HAPROXY_INTOPS_H

#include <haproxy/api.h>

/* exported functions, mostly integer parsing */
/* rounds <i> down to the closest value having max 2 digits */
unsigned int round_2dig(unsigned int i);
unsigned int full_hash(unsigned int a);
int varint_bytes(uint64_t v);
unsigned int read_uint(const char **s, const char *end);
long long read_int64(const char **s, const char *end);
unsigned long long read_uint64(const char **s, const char *end);
unsigned int str2ui(const char *s);
unsigned int str2uic(const char *s);
unsigned int strl2ui(const char *s, int len);
unsigned int strl2uic(const char *s, int len);
int strl2ic(const char *s, int len);
int strl2irc(const char *s, int len, int *ret);
int strl2llrc(const char *s, int len, long long *ret);
int strl2llrc_dotted(const char *text, int len, long long *ret);
unsigned int mask_find_rank_bit(unsigned int r, unsigned long m);
unsigned int mask_find_rank_bit_fast(unsigned int r, unsigned long m,
                                     unsigned long a, unsigned long b,
                                     unsigned long c, unsigned long d);
void mask_prep_rank_map(unsigned long m,
                        unsigned long *a, unsigned long *b,
                        unsigned long *c, unsigned long *d);


/* Multiply the two 32-bit operands and shift the 64-bit result right 32 bits.
 * This is used to compute fixed ratios by setting one of the operands to
 * (2^32*ratio).
 */
static inline unsigned int mul32hi(unsigned int a, unsigned int b)
{
	return ((unsigned long long)a * b + a) >> 32;
}

/* gcc does not know when it can safely divide 64 bits by 32 bits. Use this
 * function when you know for sure that the result fits in 32 bits, because
 * it is optimal on x86 and on 64bit processors.
 */
static inline unsigned int div64_32(unsigned long long o1, unsigned int o2)
{
	unsigned long long result;
#ifdef __i386__
	asm("divl %2"
	    : "=A" (result)
	    : "A"(o1), "rm"(o2));
#else
	result = o1 / o2;
#endif
	return result;
}

/* rotate left a 64-bit integer by <bits:[0-5]> bits */
static inline uint64_t rotl64(uint64_t v, uint8_t bits)
{
#if !defined(__ARM_ARCH_8A) && !defined(__x86_64__)
	bits &= 63;
#endif
	v = (v << bits) | (v >> (-bits & 63));
	return v;
}

/* rotate right a 64-bit integer by <bits:[0-5]> bits */
static inline uint64_t rotr64(uint64_t v, uint8_t bits)
{
#if !defined(__ARM_ARCH_8A) && !defined(__x86_64__)
	bits &= 63;
#endif
	v = (v >> bits) | (v << (-bits & 63));
	return v;
}

/* Simple popcountl implementation. It returns the number of ones in a word.
 * Described here : https://graphics.stanford.edu/~seander/bithacks.html
 */
static inline unsigned int my_popcountl(unsigned long a)
{
	a = a - ((a >> 1) & ~0UL/3);
	a = (a & ~0UL/15*3) + ((a >> 2) & ~0UL/15*3);
	a = (a + (a >> 4)) & ~0UL/255*15;
	return (unsigned long)(a * (~0UL/255)) >> (sizeof(unsigned long) - 1) * 8;
}

/* returns non-zero if <a> has at least 2 bits set */
static inline unsigned long atleast2(unsigned long a)
{
	return a & (a - 1);
}

/* Simple ffs implementation. It returns the position of the lowest bit set to
 * one, starting at 1. It is illegal to call it with a==0 (undefined result).
 */
static inline unsigned int my_ffsl(unsigned long a)
{
	unsigned long cnt;

#if defined(__x86_64__)
	__asm__("bsf %1,%0\n" : "=r" (cnt) : "rm" (a));
	cnt++;
#else

	cnt = 1;
#if LONG_MAX > 0x7FFFFFFFL /* 64bits */
	if (!(a & 0xFFFFFFFFUL)) {
		a >>= 32;
		cnt += 32;
	}
#endif
	if (!(a & 0XFFFFU)) {
		a >>= 16;
		cnt += 16;
	}
	if (!(a & 0XFF)) {
		a >>= 8;
		cnt += 8;
	}
	if (!(a & 0xf)) {
		a >>= 4;
		cnt += 4;
	}
	if (!(a & 0x3)) {
		a >>= 2;
		cnt += 2;
	}
	if (!(a & 0x1)) {
		cnt += 1;
	}
#endif /* x86_64 */

	return cnt;
}

/* Simple fls implementation. It returns the position of the highest bit set to
 * one, starting at 1. It is illegal to call it with a==0 (undefined result).
 */
static inline unsigned int my_flsl(unsigned long a)
{
	unsigned long cnt;

#if defined(__x86_64__)
	__asm__("bsr %1,%0\n" : "=r" (cnt) : "rm" (a));
	cnt++;
#else

	cnt = 1;
#if LONG_MAX > 0x7FFFFFFFUL /* 64bits */
	if (a & 0xFFFFFFFF00000000UL) {
		a >>= 32;
		cnt += 32;
	}
#endif
	if (a & 0XFFFF0000U) {
		a >>= 16;
		cnt += 16;
	}
	if (a & 0XFF00) {
		a >>= 8;
		cnt += 8;
	}
	if (a & 0xf0) {
		a >>= 4;
		cnt += 4;
	}
	if (a & 0xc) {
		a >>= 2;
		cnt += 2;
	}
	if (a & 0x2) {
		cnt += 1;
	}
#endif /* x86_64 */

	return cnt;
}

/* Build a word with the <bits> lower bits set (reverse of my_popcountl) */
static inline unsigned long nbits(int bits)
{
	if (--bits < 0)
		return 0;
	else
		return (2UL << bits) - 1;
}

/* Turns 64-bit value <a> from host byte order to network byte order.
 * The principle consists in letting the compiler detect we're playing
 * with a union and simplify most or all operations. The asm-optimized
 * htonl() version involving bswap (x86) / rev (arm) / other is a single
 * operation on little endian, or a NOP on big-endian. In both cases,
 * this lets the compiler "see" that we're rebuilding a 64-bit word from
 * two 32-bit quantities that fit into a 32-bit register. In big endian,
 * the whole code is optimized out. In little endian, with a decent compiler,
 * a few bswap and 2 shifts are left, which is the minimum acceptable.
 */
static inline unsigned long long my_htonll(unsigned long long a)
{
#if defined(__x86_64__)
	__asm__ volatile("bswapq %0" : "=r"(a) : "0"(a));
	return a;
#else
	union {
		struct {
			unsigned int w1;
			unsigned int w2;
		} by32;
		unsigned long long by64;
	} w = { .by64 = a };
	return ((unsigned long long)htonl(w.by32.w1) << 32) | htonl(w.by32.w2);
#endif
}

/* Turns 64-bit value <a> from network byte order to host byte order. */
static inline unsigned long long my_ntohll(unsigned long long a)
{
	return my_htonll(a);
}

/* sets bit <bit> into map <map>, which must be long-aligned */
static inline void ha_bit_set(unsigned long bit, long *map)
{
	map[bit / (8 * sizeof(*map))] |= 1UL << (bit & (8 * sizeof(*map) - 1));
}

/* clears bit <bit> from map <map>, which must be long-aligned */
static inline void ha_bit_clr(unsigned long bit, long *map)
{
	map[bit / (8 * sizeof(*map))] &= ~(1UL << (bit & (8 * sizeof(*map) - 1)));
}

/* flips bit <bit> from map <map>, which must be long-aligned */
static inline void ha_bit_flip(unsigned long bit, long *map)
{
	map[bit / (8 * sizeof(*map))] ^= 1UL << (bit & (8 * sizeof(*map) - 1));
}

/* returns non-zero if bit <bit> from map <map> is set, otherwise 0 */
static inline int ha_bit_test(unsigned long bit, const long *map)
{
	return !!(map[bit / (8 * sizeof(*map))] & 1UL << (bit & (8 * sizeof(*map) - 1)));
}

/* hash a 32-bit integer to another 32-bit integer. This code may be large when
 * inlined, use full_hash() instead.
 */
static inline unsigned int __full_hash(unsigned int a)
{
	/* This function is one of Bob Jenkins' full avalanche hashing
	 * functions, which when provides quite a good distribution for little
	 * input variations. The result is quite suited to fit over a 32-bit
	 * space with enough variations so that a randomly picked number falls
	 * equally before any server position.
	 * Check http://burtleburtle.net/bob/hash/integer.html for more info.
	 */
	a = (a+0x7ed55d16) + (a<<12);
	a = (a^0xc761c23c) ^ (a>>19);
	a = (a+0x165667b1) + (a<<5);
	a = (a+0xd3a2646c) ^ (a<<9);
	a = (a+0xfd7046c5) + (a<<3);
	a = (a^0xb55a4f09) ^ (a>>16);

	/* ensure values are better spread all around the tree by multiplying
	 * by a large prime close to 3/4 of the tree.
	 */
	return a * 3221225473U;
}

/*
 * Return integer equivalent of character <c> for a hex digit (0-9, a-f, A-F),
 * otherwise -1. This compact form helps gcc produce efficient code.
 */
static inline int hex2i(int c)
{
	if ((unsigned char)(c -= '0') > 9) {
		if ((unsigned char)(c -= 'A' - '0') > 5 &&
			      (unsigned char)(c -= 'a' - 'A') > 5)
			c = -11;
		c += 10;
	}
	return c;
}

/* This one is 6 times faster than strtoul() on athlon, but does
 * no check at all.
 */
static inline unsigned int __str2ui(const char *s)
{
	unsigned int i = 0;
	while (*s) {
		i = i * 10 - '0';
		i += (unsigned char)*s++;
	}
	return i;
}

/* This one is 5 times faster than strtoul() on athlon with checks.
 * It returns the value of the number composed of all valid digits read.
 */
static inline unsigned int __str2uic(const char *s)
{
	unsigned int i = 0;
	unsigned int j;

	while (1) {
		j = (*s++) - '0';
		if (j > 9)
			break;
		i *= 10;
		i += j;
	}
	return i;
}

/* This one is 28 times faster than strtoul() on athlon, but does
 * no check at all!
 */
static inline unsigned int __strl2ui(const char *s, int len)
{
	unsigned int i = 0;

	while (len-- > 0) {
		i = i * 10 - '0';
		i += (unsigned char)*s++;
	}
	return i;
}

/* This one is 7 times faster than strtoul() on athlon with checks.
 * It returns the value of the number composed of all valid digits read.
 */
static inline unsigned int __strl2uic(const char *s, int len)
{
	unsigned int i = 0;
	unsigned int j, k;

	while (len-- > 0) {
		j = (*s++) - '0';
		k = i * 10;
		if (j > 9)
			break;
		i = k + j;
	}
	return i;
}

/* This function reads an unsigned integer from the string pointed to by <s>
 * and returns it. The <s> pointer is adjusted to point to the first unread
 * char. The function automatically stops at <end>.
 */
static inline unsigned int __read_uint(const char **s, const char *end)
{
	const char *ptr = *s;
	unsigned int i = 0;
	unsigned int j, k;

	while (ptr < end) {
		j = *ptr - '0';
		k = i * 10;
		if (j > 9)
			break;
		i = k + j;
		ptr++;
	}
	*s = ptr;
	return i;
}

/* returns the number of bytes needed to encode <v> as a varint. Be careful, use
 * it only with constants as it generates a large code (typ. 180 bytes). Use the
 * varint_bytes() version instead in case of doubt.
 */
static inline int __varint_bytes(uint64_t v)
{
	switch (v) {
	case 0x0000000000000000 ... 0x00000000000000ef: return 1;
	case 0x00000000000000f0 ... 0x00000000000008ef: return 2;
	case 0x00000000000008f0 ... 0x00000000000408ef: return 3;
	case 0x00000000000408f0 ... 0x00000000020408ef: return 4;
	case 0x00000000020408f0 ... 0x00000001020408ef: return 5;
	case 0x00000001020408f0 ... 0x00000081020408ef: return 6;
	case 0x00000081020408f0 ... 0x00004081020408ef: return 7;
	case 0x00004081020408f0 ... 0x00204081020408ef: return 8;
	case 0x00204081020408f0 ... 0x10204081020408ef: return 9;
	default: return 10;
	}
}

/* Encode the integer <i> into a varint (variable-length integer). The encoded
 * value is copied in <*buf>. Here is the encoding format:
 *
 *        0 <= X < 240        : 1 byte  (7.875 bits)  [ XXXX XXXX ]
 *      240 <= X < 2288       : 2 bytes (11 bits)     [ 1111 XXXX ] [ 0XXX XXXX ]
 *     2288 <= X < 264432     : 3 bytes (18 bits)     [ 1111 XXXX ] [ 1XXX XXXX ]   [ 0XXX XXXX ]
 *   264432 <= X < 33818864   : 4 bytes (25 bits)     [ 1111 XXXX ] [ 1XXX XXXX ]*2 [ 0XXX XXXX ]
 * 33818864 <= X < 4328786160 : 5 bytes (32 bits)     [ 1111 XXXX ] [ 1XXX XXXX ]*3 [ 0XXX XXXX ]
 * ...
 *
 * On success, it returns the number of written bytes and <*buf> is moved after
 * the encoded value. Otherwise, it returns -1. */
static inline int encode_varint(uint64_t i, char **buf, char *end)
{
	unsigned char *p = (unsigned char *)*buf;
	int r;

	if (p >= (unsigned char *)end)
		return -1;

	if (i < 240) {
		*p++ = i;
		*buf = (char *)p;
		return 1;
	}

	*p++ = (unsigned char)i | 240;
	i = (i - 240) >> 4;
	while (i >= 128) {
		if (p >= (unsigned char *)end)
			return -1;
		*p++ = (unsigned char)i | 128;
		i = (i - 128) >> 7;
	}

	if (p >= (unsigned char *)end)
		return -1;
	*p++ = (unsigned char)i;

	r    = ((char *)p - *buf);
	*buf = (char *)p;
	return r;
}

/* Decode a varint from <*buf> and save the decoded value in <*i>. See
 * 'spoe_encode_varint' for details about varint.
 * On success, it returns the number of read bytes and <*buf> is moved after the
 * varint. Otherwise, it returns -1. */
static inline int decode_varint(char **buf, char *end, uint64_t *i)
{
	unsigned char *p = (unsigned char *)*buf;
	int r;

	if (p >= (unsigned char *)end)
		return -1;

	*i = *p++;
	if (*i < 240) {
		*buf = (char *)p;
		return 1;
	}

	r = 4;
	do {
		if (p >= (unsigned char *)end)
			return -1;
		*i += (uint64_t)*p << r;
		r  += 7;
	} while (*p++ >= 128);

	r    = ((char *)p - *buf);
	*buf = (char *)p;
	return r;
}

#endif /* _HAPROXY_INTOPS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
