/*
 * include/common/net_helper.h
 * This file contains miscellaneous network helper functions.
 *
 * Copyright (C) 2017 Olivier Houchard
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

#include <arpa/inet.h>

/* Functions to read various integer that may be unaligned */

/* Read a uint16_t */
static inline uint16_t readu16(const void *p)
{
        const union {  uint16_t u16; } __attribute__((packed))*u = p;
        return u->u16;
}

/* Read a int16_t */
static inline int16_t readi16(const void *p)
{
        const union {  int16_t i16; } __attribute__((packed))*u = p;
        return u->i16;
}

/* Read a uint16_t, and convert from network order to host order */
static inline uint16_t readn16(const void *p)
{
        const union {  uint16_t u16; } __attribute__((packed))*u = p;
        return ntohs(u->u16);
}

/* Read a uint32_t */
static inline uint32_t readu32(const void *p)
{
        const union {  uint32_t u32; } __attribute__((packed))*u = p;
        return u->u32;
}

/* Read a int32_t */
static inline int16_t readi32(const void *p)
{
        const union {  int32_t i32; } __attribute__((packed))*u = p;
        return u->i32;
}

/* Read a uint32_t, and convert from network order to host order */
static inline uint32_t readn32(const void *p)
{
        const union {  uint32_t u32; } __attribute__((packed))*u = p;
        return ntohl(u->u32);
}

#endif /* COMMON_NET_HELPER_H */
