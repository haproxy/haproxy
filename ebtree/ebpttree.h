/*
 * Elastic Binary Trees - macros and structures for operations on pointer nodes.
 * Version 6.0.6
 * (C) 2002-2011 - Willy Tarreau <w@1wt.eu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _EBPTTREE_H
#define _EBPTTREE_H

#include "ebtree.h"
#include "eb32tree.h"
#include "eb64tree.h"


/* Return the structure of type <type> whose member <member> points to <ptr> */
#define ebpt_entry(ptr, type, member) container_of(ptr, type, member)

#define EBPT_ROOT	EB_ROOT
#define EBPT_TREE_HEAD	EB_TREE_HEAD

/* on *almost* all platforms, a pointer can be cast into a size_t which is unsigned */
#ifndef PTR_INT_TYPE
#define PTR_INT_TYPE	size_t
#endif

typedef PTR_INT_TYPE ptr_t;

/* This structure carries a node, a leaf, and a key. It must start with the
 * eb_node so that it can be cast into an eb_node. We could also have put some
 * sort of transparent union here to reduce the indirection level, but the fact
 * is, the end user is not meant to manipulate internals, so this is pointless.
 * Internally, it is automatically cast as an eb32_node or eb64_node.
 */
struct ebpt_node {
	struct eb_node node; /* the tree node, must be at the beginning */
	void *key;
};

/*
 * Exported functions and macros.
 * Many of them are always inlined because they are extremely small, and
 * are generally called at most once or twice in a program.
 */

/* Return leftmost node in the tree, or NULL if none */
static forceinline struct ebpt_node *ebpt_first(struct eb_root *root)
{
	return ebpt_entry(eb_first(root), struct ebpt_node, node);
}

/* Return rightmost node in the tree, or NULL if none */
static forceinline struct ebpt_node *ebpt_last(struct eb_root *root)
{
	return ebpt_entry(eb_last(root), struct ebpt_node, node);
}

/* Return next node in the tree, or NULL if none */
static forceinline struct ebpt_node *ebpt_next(struct ebpt_node *ebpt)
{
	return ebpt_entry(eb_next(&ebpt->node), struct ebpt_node, node);
}

/* Return previous node in the tree, or NULL if none */
static forceinline struct ebpt_node *ebpt_prev(struct ebpt_node *ebpt)
{
	return ebpt_entry(eb_prev(&ebpt->node), struct ebpt_node, node);
}

/* Return next leaf node within a duplicate sub-tree, or NULL if none. */
static inline struct ebpt_node *ebpt_next_dup(struct ebpt_node *ebpt)
{
	return ebpt_entry(eb_next_dup(&ebpt->node), struct ebpt_node, node);
}

/* Return previous leaf node within a duplicate sub-tree, or NULL if none. */
static inline struct ebpt_node *ebpt_prev_dup(struct ebpt_node *ebpt)
{
	return ebpt_entry(eb_prev_dup(&ebpt->node), struct ebpt_node, node);
}

/* Return next node in the tree, skipping duplicates, or NULL if none */
static forceinline struct ebpt_node *ebpt_next_unique(struct ebpt_node *ebpt)
{
	return ebpt_entry(eb_next_unique(&ebpt->node), struct ebpt_node, node);
}

/* Return previous node in the tree, skipping duplicates, or NULL if none */
static forceinline struct ebpt_node *ebpt_prev_unique(struct ebpt_node *ebpt)
{
	return ebpt_entry(eb_prev_unique(&ebpt->node), struct ebpt_node, node);
}

/* Delete node from the tree if it was linked in. Mark the node unused. Note
 * that this function relies on a non-inlined generic function: eb_delete.
 */
static forceinline void ebpt_delete(struct ebpt_node *ebpt)
{
	eb_delete(&ebpt->node);
}

/*
 * The following functions are inlined but derived from the integer versions.
 */
static forceinline struct ebpt_node *ebpt_lookup(struct eb_root *root, void *x)
{
	if (sizeof(void *) == 4)
		return (struct ebpt_node *)eb32_lookup(root, (u32)(PTR_INT_TYPE)x);
	else
		return (struct ebpt_node *)eb64_lookup(root, (u64)(PTR_INT_TYPE)x);
}

static forceinline struct ebpt_node *ebpt_lookup_le(struct eb_root *root, void *x)
{
	if (sizeof(void *) == 4)
		return (struct ebpt_node *)eb32_lookup_le(root, (u32)(PTR_INT_TYPE)x);
	else
		return (struct ebpt_node *)eb64_lookup_le(root, (u64)(PTR_INT_TYPE)x);
}

static forceinline struct ebpt_node *ebpt_lookup_ge(struct eb_root *root, void *x)
{
	if (sizeof(void *) == 4)
		return (struct ebpt_node *)eb32_lookup_ge(root, (u32)(PTR_INT_TYPE)x);
	else
		return (struct ebpt_node *)eb64_lookup_ge(root, (u64)(PTR_INT_TYPE)x);
}

static forceinline struct ebpt_node *ebpt_insert(struct eb_root *root, struct ebpt_node *new)
{
	if (sizeof(void *) == 4)
		return (struct ebpt_node *)eb32_insert(root, (struct eb32_node *)new);
	else
		return (struct ebpt_node *)eb64_insert(root, (struct eb64_node *)new);
}

/*
 * The following functions are less likely to be used directly, because
 * their code is larger. The non-inlined version is preferred.
 */

/* Delete node from the tree if it was linked in. Mark the node unused. */
static forceinline void __ebpt_delete(struct ebpt_node *ebpt)
{
	__eb_delete(&ebpt->node);
}

static forceinline struct ebpt_node *__ebpt_lookup(struct eb_root *root, void *x)
{
	if (sizeof(void *) == 4)
		return (struct ebpt_node *)__eb32_lookup(root, (u32)(PTR_INT_TYPE)x);
	else
		return (struct ebpt_node *)__eb64_lookup(root, (u64)(PTR_INT_TYPE)x);
}

static forceinline struct ebpt_node *__ebpt_insert(struct eb_root *root, struct ebpt_node *new)
{
	if (sizeof(void *) == 4)
		return (struct ebpt_node *)__eb32_insert(root, (struct eb32_node *)new);
	else
		return (struct ebpt_node *)__eb64_insert(root, (struct eb64_node *)new);
}

#endif /* _EBPT_TREE_H */
