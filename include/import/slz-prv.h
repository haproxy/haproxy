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

#ifndef _SLZ_PRV_H
#define _SLZ_PRV_H

/* We have two macros UNALIGNED_LE_OK and UNALIGNED_FASTER. The latter indicates
 * that using unaligned data is faster than a simple shift. On x86 32-bit at
 * least it is not the case as the per-byte access is 30% faster. A core2-duo on
 * x86_64 is 7% faster to read one byte + shifting by 8 than to read one word,
 * but a core i5 is 7% faster doing the unaligned read, so we privilege more
 * recent implementations here.
 */
#if defined(__x86_64__)
#define UNALIGNED_LE_OK
#define UNALIGNED_FASTER
#define HAVE_FAST_MULT
#elif defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__)
#define UNALIGNED_LE_OK
//#define UNALIGNED_FASTER
#elif defined(__ARMEL__) && defined(__ARM_ARCH_7A__)
#define UNALIGNED_LE_OK
#define UNALIGNED_FASTER
#elif defined(__ARM_ARCH_8A) || defined(__ARM_FEATURE_UNALIGNED)
#define UNALIGNED_LE_OK
#define UNALIGNED_FASTER
#define HAVE_FAST_MULT
#endif

/* Log2 of the size of the hash table used for the references table. */
#define HASH_BITS 13

/* uses the most suitable crc32 function to update crc on <buf, len> */
static inline uint32_t update_crc(uint32_t crc, const void *buf, int len)
{
	return slz_crc32_by4(crc, buf, len);
}

/* This hash provides good average results on HTML contents, and is among the
 * few which provide almost optimal results on various different pages.
 */
static inline uint32_t slz_hash(uint32_t a)
{
#if defined(__ARM_FEATURE_CRC32)
#  if defined(__ARM_ARCH_ISA_A64)
	// 64 bit mode
	__asm__ volatile("crc32w %w0,%w0,%w1" : "+r"(a) : "r"(0));
#  else
	// 32 bit mode (e.g. armv7 compiler building for armv8
	__asm__ volatile("crc32w %0,%0,%1" : "+r"(a) : "r"(0));
#  endif
	return a >> (32 - HASH_BITS);
#elif defined(__SSE4_2__) && defined(USE_CRC32C_HASH)
	// SSE 4.2 offers CRC32C which is a bit slower than the multiply
	// but provides a slightly smoother hash
	__asm__ volatile("crc32l %1,%0" : "+r"(a) : "r"(0));
	return a >> (32 - HASH_BITS);
#elif defined(HAVE_FAST_MULT)
	// optimal factor for HASH_BITS=12 and HASH_BITS=13 among 48k tested: 0x1af42f
	return (a * 0x1af42f) >> (32 - HASH_BITS);
#else
	return ((a << 19) + (a << 6) - a) >> (32 - HASH_BITS);
#endif
}

/* This function compares buffers <a> and <b> and reads 32 or 64 bits at a time
 * during the approach. It makes us of unaligned little endian memory accesses
 * on capable architectures. <max> is the maximum number of bytes that can be
 * read, so both <a> and <b> must have at least <max> bytes ahead. <max> may
 * safely be null or negative if that simplifies computations in the caller.
 */
static inline long memmatch(const unsigned char *a, const unsigned char *b, long max)
{
	long len = 0;

#ifdef UNALIGNED_LE_OK
	unsigned long xor;

	while (1) {
		if ((long)(len + 2 * sizeof(long)) > max) {
			while (len < max) {
				if (a[len] != b[len])
					break;
				len++;
			}
			return len;
		}

		xor = *(long *)&a[len] ^ *(long *)&b[len];
		if (xor)
			break;
		len += sizeof(long);

		xor = *(long *)&a[len] ^ *(long *)&b[len];
		if (xor)
			break;
		len += sizeof(long);
	}

#if defined(__x86_64__) || defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__)
	/* x86 has bsf. We know that xor is non-null here */
	asm("bsf %1,%0\n" : "=r"(xor) : "0" (xor));
	return len + xor / 8;
#else
	if (sizeof(long) > 4 && !(xor & 0xffffffff)) {
		/* This code is optimized out on 32-bit archs, but we still
		 * need to shift in two passes to avoid a warning. It is
		 * properly optimized out as a single shift.
		 */
		xor >>= 16; xor >>= 16;
		if (xor & 0xffff) {
			if (xor & 0xff)
				return len + 4;
			return len + 5;
		}
		if (xor & 0xffffff)
			return len + 6;
		return len + 7;
	}

	if (xor & 0xffff) {
		if (xor & 0xff)
			return len;
		return len + 1;
	}
	if (xor & 0xffffff)
		return len + 2;
	return len + 3;
#endif // x86

#else // UNALIGNED_LE_OK
	/* This is the generic version for big endian or unaligned-incompatible
	 * architectures.
	 */
	while (len < max) {
		if (a[len] != b[len])
			break;
		len++;
	}
	return len;

#endif
}

/* helper function to reverse bits in <input> which is expected to be
 * <len> bits long.
 */
static inline short rev_short(short input, int len)
{
	short ret = 0;

	while (len) {
		ret <<= 1;
		ret |= (input & 1);
		input >>= 1;
		len--;
	}

	return ret;
}

#endif
