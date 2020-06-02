/*
 * include/haproxy/xref-t.h
 * Atomic cross-references between two elements - types
 *
 * Copyright (C) 2017 Thierry Fournier <thierry.fournier@ozon.io>
 * Copyright (C) 2020 Willy Tarreau - w@1wt.eu
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
#ifndef __HAPROXY_XREF_T_H__
#define __HAPROXY_XREF_T_H__

/* xref is used to create relation between two elements.
 * Once an element is released, it breaks the relation. If the
 * relation is already broken, it frees the xref struct.
 * The pointer between two elements is sort of a refcount with
 * max value 1. The relation is only between two elements.
 * The pointer and the type of elements a and b are conventional.
 */

#define XREF_BUSY ((struct xref *)1)

struct xref {
	struct xref *peer;
};

#endif /* __HAPROXY_XREF_T_H__ */
