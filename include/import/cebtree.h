/*
 * Compact Elastic Binary Trees - exported functions operating on node's address
 *
 * Copyright (C) 2014-2024 Willy Tarreau - w@1wt.eu
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

#ifndef _CEBTREE_H
#define _CEBTREE_H

#include <stddef.h>

/* offsetof() is provided as a builtin starting with gcc-4.1 */
#ifndef offsetof
# if (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 1))
#  define offsetof(type, field)  __builtin_offsetof(type, field)
# else
#  define offsetof(type, field) ((__size_t)(__uintptr_t)((const volatile void *)&((type *)0)->field))
# endif
#endif

/* Linux-like "container_of". It returns a pointer to the structure of type
 * <type> which has its member <name> stored at address <ptr>.
 */
#ifndef container_of
#define container_of(ptr, type, name) ((type *)(((char *)(ptr)) - offsetof(type, name)))
#endif

/* returns a pointer to the structure of type <type> which has its member <name>
 * stored at address <ptr>, unless <ptr> is 0, in which case 0 is returned.
 */
#ifndef container_of_safe
#define container_of_safe(ptr, type, name) \
	({ void *__p = (ptr); \
	   __p ? container_of(__p, type, name) : (type *)0; \
	})
#endif

/* This is what a tagged pointer points to, as found on the root or any branch.
 * It's only a forward declaration so that it is never directly dereferenced.
 */
struct ceb_root;

/* Standard node when using absolute pointers */
struct ceb_node {
	struct ceb_root *b[2]; /* branches: 0=left, 1=right */
};

/* initializes a root as an empty tree */
static inline void ceb_init_root(struct ceb_root **root)
{
	*root = NULL;
}

/* initializes a node as not belonging to a tree */
static inline void ceb_init_node(struct ceb_node *node)
{
	node->b[0] = NULL;
}

/* indicates whether a valid node is in a tree or not */
static inline int ceb_intree(const struct ceb_node *node)
{
	return !!node->b[0];
}

/* indicates whether a root is empty or not */
static inline int ceb_isempty(struct ceb_root * const*root)
{
	return !*root;
}

/* returns a pointer to the key from the node and offset, where node is
 * assumed to be non-null.
 */
static inline void *_ceb_key_ptr(const struct ceb_node *node, ptrdiff_t kofs)
{
	return (void*)((char *)node + kofs);
}

/* returns a pointer to the key from the node and offset if node is non-null,
 * otherwise null. I.e. this is made to safely return a pointer to the key
 * location from the return of a lookup operation.
 */
static inline void *ceb_key_ptr(const struct ceb_node *node, ptrdiff_t kofs)
{
	return node ? _ceb_key_ptr(node, kofs) : NULL;
}


#endif /* _CEBTREE_H */
