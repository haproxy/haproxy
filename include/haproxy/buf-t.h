/*
 * include/haproxy/buf-t.h
 * Simple buffer handling - types definitions.
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

#ifndef _HAPROXY_BUF_T_H
#define _HAPROXY_BUF_T_H

#include <haproxy/api-t.h>

/* Structure defining a buffer's head */
struct buffer {
	size_t size;                /* buffer size in bytes */
	char  *area;                /* points to <size> bytes */
	size_t data;                /* amount of data after head including wrapping */
	size_t head;                /* start offset of remaining data relative to area */
};

/* A buffer may be in 3 different states :
 *   - unallocated : size == 0, area == 0  (b_is_null() is true)
 *   - waiting     : size == 0, area != 0  (b_is_null() is true)
 *   - allocated   : size  > 0, area  > 0  (b_is_null() is false)
 */

/* initializers for certain buffer states. It is important that the NULL buffer
 * remains the one with all fields initialized to zero so that a calloc() or a
 * memset() on a struct automatically sets a NULL buffer.
 */
#define BUF_NULL   ((struct buffer){ })
#define BUF_WANTED ((struct buffer){ .area = (char *)1 })
#define BUF_RING   ((struct buffer){ .area = (char *)2 })

#endif /* _HAPROXY_BUF_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
