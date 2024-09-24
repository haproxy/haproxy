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
#include "ebtree.h"

/* Standard node when using absolute pointers */
struct ceb_node {
	struct ceb_node *b[2]; /* branches: 0=left, 1=right */
};

/* indicates whether a valid node is in a tree or not */
static inline int ceb_intree(const struct ceb_node *node)
{
	return !!node->b[0];
}

/* tag an untagged pointer */
static inline struct ceb_node *__ceb_dotag(const struct ceb_node *node)
{
	return (struct ceb_node *)((size_t)node + 1);
}

/* untag a tagged pointer */
static inline struct ceb_node *__ceb_untag(const struct ceb_node *node)
{
	return (struct ceb_node *)((size_t)node - 1);
}

/* clear a pointer's tag */
static inline struct ceb_node *__ceb_clrtag(const struct ceb_node *node)
{
	return (struct ceb_node *)((size_t)node & ~((size_t)1));
}

/* returns whether a pointer is tagged */
static inline int __ceb_tagged(const struct ceb_node *node)
{
	return !!((size_t)node & 1);
}

/* returns an integer equivalent of the pointer */
static inline size_t __ceb_intptr(struct ceb_node *tree)
{
	return (size_t)tree;
}

///* returns true if at least one of the branches is a subtree node, indicating
// * that the current node is at the top of a duplicate sub-tree and that all
// * values below it are the same.
// */
//static inline int __ceb_is_dup(const struct ceb_node *node)
//{
//	return __ceb_tagged((struct ceb_node *)(__ceb_intptr(node->l) | __ceb_intptr(node->r)));
//}

#endif /* _CEBTREE_H */
