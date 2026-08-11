/*
 * Copyright (C) 2013-2015 Willy Tarreau <w@1wt.eu>
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

#include "import/slz.h"
#include "import/slz-prv.h"
#include "import/slz-tables.h"

/*
 * =============================================================================
 *                        Legacy slz code that is shared between
 *                        slz (compress) and uslz (uncompress) APIs
 * =============================================================================
 */

/* if PRECOMPUTE_TABLES not set, then tables.h does not provide crc32_fast
 * table as we need to recompute it
 */
#ifndef PRECOMPUTE_TABLES

#if !defined(__ARM_FEATURE_CRC32)
static uint32_t crc32_fast[4][256];
#endif

#endif // ifndef PRECOMPUTE_TABLES

static inline uint32_t crc32_char(uint32_t crc, uint8_t x)
{
#if defined(__ARM_FEATURE_CRC32)
	crc = ~crc;
#  if defined(__ARM_ARCH_ISA_A64)
	// 64 bit mode
	__asm__ volatile("crc32b %w0,%w0,%w1" : "+r"(crc) : "r"(x));
#  else
	// 32 bit mode (e.g. armv7 compiler building for armv8
	__asm__ volatile("crc32b %0,%0,%1" : "+r"(crc) : "r"(x));
#  endif
	crc = ~crc;
#else
	crc = crc32_fast[0][(crc ^ x) & 0xff] ^ (crc >> 8);
#endif
	return crc;
}

#ifdef UNALIGNED_LE_OK
static inline uint32_t crc32_uint32(uint32_t data)
{
#if defined(__ARM_FEATURE_CRC32)
#  if defined(__ARM_ARCH_ISA_A64)
	// 64 bit mode
	__asm__ volatile("crc32w %w0,%w0,%w1" : "+r"(data) : "r"(~0UL));
#  else
	// 32 bit mode (e.g. armv7 compiler building for armv8
	__asm__ volatile("crc32w %0,%0,%1" : "+r"(data) : "r"(~0UL));
#  endif
	data = ~data;
#else
	data = crc32_fast[3][(data >>  0) & 0xff] ^
	       crc32_fast[2][(data >>  8) & 0xff] ^
	       crc32_fast[1][(data >> 16) & 0xff] ^
	       crc32_fast[0][(data >> 24) & 0xff];
#endif
	return data;
}
#endif

/* Modified version originally from RFC1952, working with non-inverting CRCs */
uint32_t slz_crc32_by1(uint32_t crc, const unsigned char *buf, int len)
{
	int n;

	for (n = 0; n < len; n++)
		crc = crc32_char(crc, buf[n]);
	return crc;
}

/* This version computes the crc32 of <buf> over <len> bytes, doing most of it
 * in 32-bit chunks.
 */
uint32_t slz_crc32_by4(uint32_t crc, const unsigned char *buf, int len)
{
	const unsigned char *end = buf + len;

	while (buf <= end - 16) {
#ifdef UNALIGNED_LE_OK
#if defined(__ARM_FEATURE_CRC32)
		crc = ~crc;
#  if defined(__ARM_ARCH_ISA_A64)
	// 64 bit mode
		__asm__ volatile("crc32w %w0,%w0,%w1" : "+r"(crc) : "r"(*(uint32_t*)(buf)));
		__asm__ volatile("crc32w %w0,%w0,%w1" : "+r"(crc) : "r"(*(uint32_t*)(buf + 4)));
		__asm__ volatile("crc32w %w0,%w0,%w1" : "+r"(crc) : "r"(*(uint32_t*)(buf + 8)));
		__asm__ volatile("crc32w %w0,%w0,%w1" : "+r"(crc) : "r"(*(uint32_t*)(buf + 12)));
#  else
	// 32 bit mode (e.g. armv7 compiler building for armv8
		__asm__ volatile("crc32w %0,%0,%1" : "+r"(crc) : "r"(*(uint32_t*)(buf)));
		__asm__ volatile("crc32w %0,%0,%1" : "+r"(crc) : "r"(*(uint32_t*)(buf + 4)));
		__asm__ volatile("crc32w %0,%0,%1" : "+r"(crc) : "r"(*(uint32_t*)(buf + 8)));
		__asm__ volatile("crc32w %0,%0,%1" : "+r"(crc) : "r"(*(uint32_t*)(buf + 12)));
#  endif
		crc = ~crc;
#else
		crc ^= *(uint32_t *)buf;
		crc = crc32_uint32(crc);

		crc ^= *(uint32_t *)(buf + 4);
		crc = crc32_uint32(crc);

		crc ^= *(uint32_t *)(buf + 8);
		crc = crc32_uint32(crc);

		crc ^= *(uint32_t *)(buf + 12);
		crc = crc32_uint32(crc);
#endif
#else
		crc = crc32_fast[3][(buf[0] ^ (crc >>  0)) & 0xff] ^
		      crc32_fast[2][(buf[1] ^ (crc >>  8)) & 0xff] ^
		      crc32_fast[1][(buf[2] ^ (crc >> 16)) & 0xff] ^
		      crc32_fast[0][(buf[3] ^ (crc >> 24)) & 0xff];

		crc = crc32_fast[3][(buf[4] ^ (crc >>  0)) & 0xff] ^
		      crc32_fast[2][(buf[5] ^ (crc >>  8)) & 0xff] ^
		      crc32_fast[1][(buf[6] ^ (crc >> 16)) & 0xff] ^
		      crc32_fast[0][(buf[7] ^ (crc >> 24)) & 0xff];

		crc = crc32_fast[3][(buf[8] ^ (crc >>  0)) & 0xff] ^
		      crc32_fast[2][(buf[9] ^ (crc >>  8)) & 0xff] ^
		      crc32_fast[1][(buf[10] ^ (crc >> 16)) & 0xff] ^
		      crc32_fast[0][(buf[11] ^ (crc >> 24)) & 0xff];

		crc = crc32_fast[3][(buf[12] ^ (crc >>  0)) & 0xff] ^
		      crc32_fast[2][(buf[13] ^ (crc >>  8)) & 0xff] ^
		      crc32_fast[1][(buf[14] ^ (crc >> 16)) & 0xff] ^
		      crc32_fast[0][(buf[15] ^ (crc >> 24)) & 0xff];
#endif
		buf += 16;
	}

	while (buf <= end - 4) {
#ifdef UNALIGNED_LE_OK
		crc ^= *(uint32_t *)buf;
		crc = crc32_uint32(crc);
#else
		crc = crc32_fast[3][(buf[0] ^ (crc >>  0)) & 0xff] ^
		      crc32_fast[2][(buf[1] ^ (crc >>  8)) & 0xff] ^
		      crc32_fast[1][(buf[2] ^ (crc >> 16)) & 0xff] ^
		      crc32_fast[0][(buf[3] ^ (crc >> 24)) & 0xff];
#endif
		buf += 4;
	}

	while (buf < end)
		crc = crc32_char(crc, *buf++);
	return crc;
}

/* Original version from RFC1950, verified and works OK */
uint32_t slz_adler32_by1(uint32_t crc, const unsigned char *buf, int len)
{
	uint32_t s1 = crc & 0xffff;
	uint32_t s2 = (crc >> 16) & 0xffff;
	int n;

	for (n = 0; n < len; n++) {
		s1 = (s1 + buf[n]) % 65521;
		s2 = (s2 + s1)     % 65521;
	}
	return (s2 << 16) + s1;
}

/* Computes the adler32 sum on <buf> for <len> bytes. It avoids the expensive
 * modulus by retrofitting the number of bytes missed between 65521 and 65536
 * which is easy to count : For every sum above 65536, the modulus is offset
 * by (65536-65521) = 15. So for any value, we can count the accumulated extra
 * values by dividing the sum by 65536 and multiplying this value by
 * (65536-65521). That's easier with a drawing with boxes and marbles. It gives
 * this :
 *          x % 65521 = (x % 65536) + (x / 65536) * (65536 - 65521)
 *                    = (x & 0xffff) + (x >> 16) * 15.
 */
uint32_t slz_adler32_block(uint32_t crc, const unsigned char *buf, long len)
{
	unsigned long s1 = crc & 0xffff;
	unsigned long s2 = (crc >> 16);
	long blk;
	long n;

	do {
		blk = len;
		/* ensure we never overflow s2 (limit is about 2^((32-8)/2) */
		if (blk > (1U << 12))
			blk = 1U << 12;
		len -= blk;

		for (n = 0; n < blk; n++) {
			s1 = (s1 + buf[n]);
			s2 = (s2 + s1);
		}

		/* Largest value here is 2^12 * 255 = 1044480 < 2^20. We can
		 * still overflow once, but not twice because the right hand
		 * size is 225 max, so the total is 65761. However we also
		 * have to take care of the values between 65521 and 65536.
		 */
		s1 = (s1 & 0xffff) + 15 * (s1 >> 16);
		if (s1 >= 65521)
			s1 -= 65521;

		/* For s2, the largest value is estimated to 2^32-1 for
		 * simplicity, so the right hand side is about 15*65535
		 * = 983025. We can overflow twice at most.
		 */
		s2 = (s2 & 0xffff) + 15 * (s2 >> 16);
		s2 = (s2 & 0xffff) + 15 * (s2 >> 16);
		if (s2 >= 65521)
			s2 -= 65521;

		buf += blk;
	} while (len);
	return (s2 << 16) + s1;
}

/* This used to be the function called to build the CRC table at init time.
 * Now it does nothing, it's only kept for API/ABI compatibility.
 */
void slz_make_crc_table(void)
{
}

/* does nothing anymore, only kept for ABI compatibility */
void slz_prepare_dist_table()
{
}

/* Make the table for a fast CRC.
 * Not thread-safe, must be called exactly once.
 */
static inline void __slz_make_crc_table(void)
{
#if !defined(PRECOMPUTE_TABLES) && !defined(__ARM_FEATURE_CRC32)

	uint32_t c;
	int n, k;

	for (n = 0; n < 256; n++) {
		c = (uint32_t) n ^ 255;
		for (k = 0; k < 8; k++) {
			if (c & 1) {
				c = 0xedb88320 ^ (c >> 1);
			} else {
				c = c >> 1;
			}
		}
		crc32_fast[0][n] = c ^ 0xff000000;
	}

	/* Note: here we *do not* have to invert the bits corresponding to the
	 * byte position, because [0] already has the 8 highest bits inverted,
	 * and these bits are shifted by 8 at the end of the operation, which
	 * results in having the next 8 bits shifted in turn. That's why we
	 * have the xor in the index used just after a computation.
	 */
	for (n = 0; n < 256; n++) {
		crc32_fast[1][n] = 0xff000000 ^ crc32_fast[0][(0xff000000 ^ crc32_fast[0][n] ^ 0xff) & 0xff] ^ (crc32_fast[0][n] >> 8);
		crc32_fast[2][n] = 0xff000000 ^ crc32_fast[0][(0x00ff0000 ^ crc32_fast[1][n] ^ 0xff) & 0xff] ^ (crc32_fast[1][n] >> 8);
		crc32_fast[3][n] = 0xff000000 ^ crc32_fast[0][(0x0000ff00 ^ crc32_fast[2][n] ^ 0xff) & 0xff] ^ (crc32_fast[2][n] >> 8);
	}
#endif
}

/*
 * =============================================================================
 *                        Common slz code that is shared between
 *                        slz (compress) and uslz (uncompress) APIs
 * =============================================================================
 */
__attribute__((constructor))
static void __slz_common_initialize(void)
{
#if !defined(__ARM_FEATURE_CRC32)
	__slz_make_crc_table(); // used by both slz and uslz
#endif
}
