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

/* This horrible mess is needed to shut up the fallthrough warning since the
 * stupid comment approach doesn't resist to separate preprocessing (e.g. as
 * used in distcc). Note that compilers which support the fallthrough attribute
 * also support __has_attribute.
 */
#ifndef __fallthrough
#  ifdef __has_attribute
#    if __has_attribute(fallthrough)
#      define __fallthrough __attribute__((fallthrough))
#    else
#      define __fallthrough do { } while (0)
#    endif
#  else
#    define __fallthrough do { } while (0)
#  endif
#endif

/* returns the max of <a> and <b>, must be constant since evaluated twice */
#define MIN_C(a, b) ({				\
	(a < b) ? a : b;			\
})

/* returns the min of <a> and <b>; both must be of compatible types and are
 * evaluated exactly once.
 */
#define MIN(a, b) ({				\
	typeof(a) _a = (a);			\
	typeof(a) _b = (b);			\
	(_a < _b) ? _a : _b;			\
})

/* returns the min of <a> and <b>; both cast to type <t>, are evaluated exactly
 * once.
 */
#define MIN_T(t, a, b) ({			\
	t _a = (t)(a);				\
	t _b = (t)(b);				\
	(_a < _b) ? _a : _b;			\
})

/* returns the max of <a> and <b>, must be constant since evaluated twice */
#define MAX_C(a, b) ({				\
	(a > b) ? a : b;			\
})

/* returns the max of <a> and <b>; both must be of compatible types and are
 * evaluated exactly once.
 */
#define MAX(a, b) ({				\
	typeof(a) _a = (a);			\
	typeof(a) _b = (b);			\
	(_a > _b) ? _a : _b;			\
})

/* returns the max of <a> and <b>; both cast to type <t>, are evaluated exactly
 * once.
 */
#define MAX_T(t, a, b) ({			\
	t _a = (t)(a);				\
	t _b = (t)(b);				\
	(_a > _b) ? _a : _b;			\
})


/* reads an unaligned 32-bit word in little endian order */
static inline uint32_t read_le32(const void *p)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	const union {  uint32_t u32; } __attribute__((packed)) *u = p;
	return u->u32;
#else
	const uint8_t *u8 = p;
	return (uint32_t)u8[0] | ((uint32_t)u8[1] << 8) |
	       ((uint32_t)u8[2] << 16) | ((uint32_t)u8[3] << 24);
#endif
}

/* reads an unaligned 64-bit word in little endian order, same as read_le32() */
static inline uint64_t read_le64(const void *p)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	const union {  uint64_t u64; } __attribute__((packed)) *u = p;
	return u->u64;
#else
	const uint8_t *u8 = p;
	return (uint64_t)read_le32(u8) | ((uint64_t)read_le32(u8 + 4) << 32);
#endif
}

/* reads an unaligned machine word in little endian order, same as read_le32() */
static inline unsigned long read_lelong(const void *p)
{
#if __SIZEOF_LONG__ > 4
	return read_le64(p);
#else
	return read_le32(p);
#endif
}

/* writes an unaligned 32-bit word in little endian order */
static inline void write_le32(void *p, uint32_t v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	union {  uint32_t u32; } __attribute__((packed)) *u = p;
	u->u32 = v;
#else
	uint8_t *u8 = p;
	u8[0] = v;
	u8[1] = v >> 8;
	u8[2] = v >> 16;
	u8[3] = v >> 24;
#endif
}

/* writes an unaligned 16-bit word in little order */
static inline void write_le16(void *p, uint16_t v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	union {  uint16_t u16; } __attribute__((packed)) *u = p;
	u->u16 = v;
#else
	uint8_t *u8 = p;
	u8[0] = v;
	u8[1] = v >> 8;
#endif
}

/* uses the most suitable crc32 function to update crc on <buf, len> */
static inline uint32_t update_crc(uint32_t crc, const void *buf, int len)
{
	return slz_crc32_by4(crc, buf, len);
}

/* reverses bits in 5bits len <v> input and returns the new value.
 * ie: 01100 becomes 00110. Bits 5 and above are ignored.
 */
#if defined(__aarch64__) || defined(__ARM_ARCH_7A__)

/* ARM >= v7 has a fast rbit instruction */
static inline uint32_t rbit5(uint32_t v)
{
#if defined(__ARM_ARCH_ISA_A64)
	// 64 bit mode
	__asm__ ("rbit %w0, %w0" : "+r" (v));
#else
	// 32 bit mode (e.g. armv7 compiler building for armv8
	__asm__ ("rbit %0, %0" : "+r" (v));
#endif
	return v >> 27;
}

#else /* not arm */

#define rbit5(v) ({                                                             \
	typeof(v) _v = (v);                                                     \
	((0xf7b3d591e6a2c480ULL >> ((_v & 0x1e) * 2)) & 0xf) + ((_v & 1) << 4); \
})

#endif

/* helper function to reverse up to 9 bits in <input> which is expected to be
 * <len> bits long. The generic version is exact up to 10 bits, use rbit15()
 * for longer codes.
 */
static inline uint32_t rbit9(uint32_t input, int len)
{
#if defined(__aarch64__) || defined(__ARM_ARCH_7A__)
	/* ARM >= v7 has a fast rbit instruction */
	input <<= 32 - len; // align left before reversal
#if defined(__ARM_ARCH_ISA_A64)
	// 64 bit mode
	__asm__ ("rbit %w0, %w0" : "+r" (input));
#else
	// 32 bit mode (e.g. armv7 compiler building for armv8
	__asm__ ("rbit %0, %0" : "+r" (input));
#endif
	return input;

#else /* not arm */
	uint32_t h, l;
	h = input >> 5;
	l = input;
	h = rbit5(h); l = rbit5(l);
	return ((l << 5) | h) >> (10 - len); /* new_h = [rev(l):5][rev(h):5] */
#endif
}

/* helper function to reverse up to 16 bits in <input> which is expected to be
 * <len> bits long, len being 1 to 16, the longest deflate code. It is meant
 * for table generation, not for the decoding path. On ARM the rbit instruction
 * covers any length. On other archs we do them the usual way in log2 masks.
 */
static inline uint32_t rbit16(uint32_t input, int len)
{
#if defined(__aarch64__) || defined(__ARM_ARCH_7A__)
	/* ARM >= v7 has a fast rbit instruction */
	input <<= 32 - len; // align left before reversal
# if defined(__ARM_ARCH_ISA_A64)
	// 64 bit mode
	__asm__ ("rbit %w0, %w0" : "+r" (input));
# else
	// 32 bit mode (e.g. armv7 compiler building for armv8
	__asm__ ("rbit %0, %0" : "+r" (input));
# endif
	return input;

#else /* not arm */
	input = ((input >> 1) & 0x5555) | ((input & 0x5555) << 1);
	input = ((input >> 2) & 0x3333) | ((input & 0x3333) << 2);
	input = ((input >> 4) & 0x0f0f) | ((input & 0x0f0f) << 4);
	input = ((input >> 8) & 0x00ff) | ((input & 0x00ff) << 8);
	return input >> (16 - len);
#endif
}

#endif
