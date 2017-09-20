/*
 * include/common/net_helper.h
 * This file contains miscellaneous network helper functions.
 *
 * Copyright (C) 2017 Olivier Houchard
 * Copyright (C) 2017 Willy Tarreau
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _COMMON_NET_HELPER_H
#define _COMMON_NET_HELPER_H

#include <common/compiler.h>
#include <common/standard.h>
#include <arpa/inet.h>

/* Functions to read/write various integers that may be unaligned */

/* Read a uint16_t in native host order */
static inline uint16_t read_u16(const void *p)
{
        const union {  uint16_t u16; } __attribute__((packed))*u = p;
        return u->u16;
}

/* Write a uint16_t in native host order */
static inline void write_u16(void *p, const uint16_t u16)
{
	union {  uint16_t u16; } __attribute__((packed))*u = p;
	u->u16 = u16;
}

/* Read a uint32_t in native host order */
static inline uint32_t read_u32(const void *p)
{
        const union {  uint32_t u32; } __attribute__((packed))*u = p;
        return u->u32;
}

/* Write a uint32_t in native host order */
static inline void write_u32(void *p, const uint32_t u32)
{
	union {  uint32_t u32; } __attribute__((packed))*u = p;
	u->u32 = u32;
}

/* Read a uint64_t in native host order */
static inline uint64_t read_u64(const void *p)
{
        const union {  uint64_t u64; } __attribute__((packed))*u = p;
        return u->u64;
}

/* Write a uint64_t in native host order */
static inline void write_u64(void *p, const uint64_t u64)
{
	union {  uint64_t u64; } __attribute__((packed))*u = p;
	u->u64 = u64;
}

/* Read a possibly wrapping number of bytes <bytes> into destination <dst>. The
 * first segment is composed of <s1> bytes at p1. The remaining byte(s), if any,
 * are read from <p2>. <s1> may be zero and may also be larger than <bytes>. The
 * caller is always responsible for providing enough bytes. Note: the function
 * is purposely *not* marked inline to let the compiler decide what to do with
 * it, because it's around 34 bytes long, placed on critical path but rarely
 * called, and uses uses a lot of arguments if not inlined. The compiler will
 * thus decide what's best to do with it depending on the context.
 */
static void readv_bytes(void *dst, const size_t bytes, const void *p1, size_t s1, const void *p2)
{
	size_t idx;

	p2 -= s1;
	for (idx = 0; idx < bytes; idx++) {
		if (idx == s1)
			p1 = p2;
		((uint8_t *)dst)[idx] = ((const uint8_t *)p1)[idx];
	}
	/* this memory barrier is critical otherwise gcc may over-optimize this
	 * code, completely removing it as well as any surrounding boundary
	 * check (4.7.1..6.4.0)!
	 */
	__asm__ volatile("" ::: "memory");
}

/* Write a possibly wrapping number of bytes <bytes> from location <src>. The
 * first segment is composed of <s1> bytes at p1. The remaining byte(s), if any,
 * are written to <p2>. <s1> may be zero and may also be larger than <bytes>.
 * The caller is always responsible for providing enough room. Note: the
 * function is purposely *not* marked inline to let the compiler decide what to
 * do with it, because it's around 34 bytes long, placed on critical path but
 * rarely called, and uses uses a lot of arguments if not inlined. The compiler
 * will thus decide what's best to do with it depending on the context.
 */
static void writev_bytes(const void *src, const size_t bytes, void *p1, size_t s1, void *p2)
{
	size_t idx;

	p2 -= s1;
	for (idx = 0; idx < bytes; idx++) {
		if (idx == s1)
			p1 = p2;
		((uint8_t *)p1)[idx] = ((const uint8_t *)src)[idx];
	}
}

/* Read a possibly wrapping uint16_t in native host order. The first segment is
 * composed of <s1> bytes at p1. The remaining byte(s), if any, are read from
 * <p2>. <s1> may be zero and may be larger than the type. The caller is always
 * responsible for providing enough bytes.
 */
static inline uint16_t readv_u16(const void *p1, size_t s1, const void *p2)
{
	if (unlikely(s1 == 1)) {
		volatile uint16_t u16;

		((uint8_t *)&u16)[0] = *(uint8_t *)p1;
		((uint8_t *)&u16)[1] = *(uint8_t *)p2;
		return u16;
	}
	else {
		const union {  uint16_t u16; } __attribute__((packed)) *u;

		u = (s1 == 0) ? p2 : p1;
		return u->u16;
	}
}

/* Write a possibly wrapping uint16_t in native host order. The first segment is
 * composed of <s1> bytes at p1. The remaining byte(s), if any, are written to
 * <p2>. <s1> may be zero and may be larger than the type. The caller is always
 * responsible for providing enough room.
 */
static inline void writev_u16(void *p1, size_t s1, void *p2, const uint16_t u16)
{
	union {  uint16_t u16; } __attribute__((packed)) *u;

	if (unlikely(s1 == 1)) {
		*(uint8_t *)p1 = ((const uint8_t *)&u16)[0];
		*(uint8_t *)p2 = ((const uint8_t *)&u16)[1];
	}
	else {
		u = (s1 == 0) ? p2 : p1;
		u->u16 = u16;
	}
}

/* Read a possibly wrapping uint32_t in native host order. The first segment is
 * composed of <s1> bytes at p1. The remaining byte(s), if any, are read from
 * <p2>. <s1> may be zero and may be larger than the type. The caller is always
 * responsible for providing enough bytes.
 */
static inline uint32_t readv_u32(const void *p1, size_t s1, const void *p2)
{
	uint32_t u32;

	if (!unlikely(s1 < sizeof(u32)))
		u32 = read_u32(p1);
	else
		readv_bytes(&u32, sizeof(u32), p1, s1, p2);
	return u32;
}

/* Write a possibly wrapping uint32_t in native host order. The first segment is
 * composed of <s1> bytes at p1. The remaining byte(s), if any, are written to
 * <p2>. <s1> may be zero and may be larger than the type. The caller is always
 * responsible for providing enough room.
 */
static inline void writev_u32(void *p1, size_t s1, void *p2, const uint32_t u32)
{
	if (!unlikely(s1 < sizeof(u32)))
		write_u32(p1, u32);
	else
		writev_bytes(&u32, sizeof(u32), p1, s1, p2);
}

/* Read a possibly wrapping uint64_t in native host order. The first segment is
 * composed of <s1> bytes at p1. The remaining byte(s), if any, are read from
 * <p2>. <s1> may be zero and may be larger than the type. The caller is always
 * responsible for providing enough bytes.
 */
static inline uint64_t readv_u64(const void *p1, size_t s1, const void *p2)
{
	uint64_t u64;

	if (!unlikely(s1 < sizeof(u64)))
		u64 = read_u64(p1);
	else
		readv_bytes(&u64, sizeof(u64), p1, s1, p2);
	return u64;
}

/* Write a possibly wrapping uint64_t in native host order. The first segment is
 * composed of <s1> bytes at p1. The remaining byte(s), if any, are written to
 * <p2>. <s1> may be zero and may be larger than the type. The caller is always
 * responsible for providing enough room.
 */
static inline void writev_u64(void *p1, size_t s1, void *p2, const uint64_t u64)
{
	if (!unlikely(s1 < sizeof(u64)))
		write_u64(p1, u64);
	else
		writev_bytes(&u64, sizeof(u64), p1, s1, p2);
}

/* Signed integer versions : return the same data but signed */

/* Read an int16_t in native host order */
static inline int16_t read_i16(const void *p)
{
	return read_u16(p);
}

/* Read an int32_t in native host order */
static inline int32_t read_i32(const void *p)
{
	return read_u32(p);
}

/* Read an int64_t in native host order */
static inline int64_t read_i64(const void *p)
{
	return read_u64(p);
}

/* Read a possibly wrapping int16_t in native host order */
static inline int16_t readv_i16(const void *p1, size_t s1, const void *p2)
{
	return readv_u16(p1, s1, p2);
}

/* Read a possibly wrapping int32_t in native host order */
static inline int32_t readv_i32(const void *p1, size_t s1, const void *p2)
{
	return readv_u32(p1, s1, p2);
}

/* Read a possibly wrapping int64_t in native host order */
static inline int64_t readv_i64(const void *p1, size_t s1, const void *p2)
{
	return readv_u64(p1, s1, p2);
}

/* Read a uint16_t, and convert from network order to host order */
static inline uint16_t read_n16(const void *p)
{
	return ntohs(read_u16(p));
}

/* Write a uint16_t after converting it from host order to network order */
static inline void write_n16(void *p, const uint16_t u16)
{
	write_u16(p, htons(u16));
}

/* Read a uint32_t, and convert from network order to host order */
static inline uint32_t read_n32(const void *p)
{
	return ntohl(read_u32(p));
}

/* Write a uint32_t after converting it from host order to network order */
static inline void write_n32(void *p, const uint32_t u32)
{
	write_u32(p, htonl(u32));
}

/* Read a uint64_t, and convert from network order to host order */
static inline uint64_t read_n64(const void *p)
{
	return my_ntohll(read_u64(p));
}

/* Write a uint64_t after converting it from host order to network order */
static inline void write_n64(void *p, const uint64_t u64)
{
	write_u64(p, my_htonll(u64));
}

/* Read a possibly wrapping uint16_t in network order. The first segment is
 * composed of <s1> bytes at p1. The remaining byte(s), if any, are read from
 * <p2>. <s1> may be zero and may be larger than the type. The caller is always
 * responsible for providing enough bytes.
 */
static inline uint16_t readv_n16(const void *p1, size_t s1, const void *p2)
{
	if (unlikely(s1 < 2)) {
		if (s1 == 0)
			p1 = p2++;
	}
	else
		p2 = p1 + 1;
	return (*(uint8_t *)p1 << 8) + *(uint8_t *)p2;
}

/* Write a possibly wrapping uint16_t in network order. The first segment is
 * composed of <s1> bytes at p1. The remaining byte(s), if any, are written to
 * <p2>. <s1> may be zero and may be larger than the type. The caller is always
 * responsible for providing enough room.
 */
static inline void writev_n16(const void *p1, size_t s1, const void *p2, const uint16_t u16)
{
	if (unlikely(s1 < 2)) {
		if (s1 == 0)
			p1 = p2++;
	}
	else
		p2 = p1 + 1;
	*(uint8_t *)p1 = u16 >> 8;
	*(uint8_t *)p2 = u16;
}

/* Read a possibly wrapping uint32_t in network order. The first segment is
 * composed of <s1> bytes at p1. The remaining byte(s), if any, are read from
 * <p2>. <s1> may be zero and may be larger than the type. The caller is always
 * responsible for providing enough bytes.
 */
static inline uint32_t readv_n32(const void *p1, size_t s1, const void *p2)
{
	return ntohl(readv_u32(p1, s1, p2));
}

/* Write a possibly wrapping uint32_t in network order. The first segment is
 * composed of <s1> bytes at p1. The remaining byte(s), if any, are written to
 * <p2>. <s1> may be zero and may be larger than the type. The caller is always
 * responsible for providing enough room.
 */
static inline void writev_n32(void *p1, size_t s1, void *p2, const uint32_t u32)
{
	writev_u32(p1, s1, p2, htonl(u32));
}

/* Read a possibly wrapping uint64_t in network order. The first segment is
 * composed of <s1> bytes at p1. The remaining byte(s), if any, are read from
 * <p2>. <s1> may be zero and may be larger than the type. The caller is always
 * responsible for providing enough bytes.
 */
static inline uint64_t readv_n64(const void *p1, size_t s1, const void *p2)
{
	return my_ntohll(readv_u64(p1, s1, p2));
}

/* Write a possibly wrapping uint64_t in network order. The first segment is
 * composed of <s1> bytes at p1. The remaining byte(s), if any, are written to
 * <p2>. <s1> may be zero and may be larger than the type. The caller is always
 * responsible for providing enough room.
 */
static inline void writev_n64(void *p1, size_t s1, void *p2, const uint64_t u64)
{
	writev_u64(p1, s1, p2, my_htonll(u64));
}

#endif /* COMMON_NET_HELPER_H */
