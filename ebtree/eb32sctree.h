/*
 * Elastic Binary Trees - macros and structures for operations on 32bit nodes.
 * Version 6.0.6 with backports from v7-dev
 * (C) 2002-2017 - Willy Tarreau <w@1wt.eu>
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

#ifndef _EB32SCTREE_H
#define _EB32SCTREE_H

#include "ebtree.h"


/* Return the structure of type <type> whose member <member> points to <ptr> */
#define eb32sc_entry(ptr, type, member) container_of(ptr, type, member)

/* These types may sometimes already be defined */
#ifndef _EB32TREE_H
typedef unsigned int u32;
typedef   signed int s32;
#endif

/* This structure carries a node, a leaf, a scope, and a key. It must start
 * with the eb_node so that it can be cast into an eb_node. We could also
 * have put some sort of transparent union here to reduce the indirection
 * level, but the fact is, the end user is not meant to manipulate internals,
 * so this is pointless.
 * In case sizeof(void*)>=sizeof(long), we know there will be some padding after
 * the leaf if it's unaligned. In this case we force the alignment on void* so
 * that we prefer to have the padding before for more efficient accesses.
 */
struct eb32sc_node {
	struct eb_node node; /* the tree node, must be at the beginning */
	MAYBE_ALIGN(sizeof(u32));
	u32 key;
	ALWAYS_ALIGN(sizeof(void*));
	unsigned long node_s; /* visibility of this node's branches */
	unsigned long leaf_s; /* visibility of this node's leaf */
} ALIGNED(sizeof(void*));

/*
 * Exported functions and macros.
 * Many of them are always inlined because they are extremely small, and
 * are generally called at most once or twice in a program.
 */

/*
 * The following functions are not inlined by default. They are declared
 * in eb32sctree.c, which simply relies on their inline version.
 */
struct eb32sc_node *eb32sc_lookup_ge(struct eb_root *root, u32 x, unsigned long scope);
struct eb32sc_node *eb32sc_lookup_ge_or_first(struct eb_root *root, u32 x, unsigned long scope);
struct eb32sc_node *eb32sc_insert(struct eb_root *root, struct eb32sc_node *new, unsigned long scope);
void eb32sc_delete(struct eb32sc_node *node);

/* Walks down left starting at root pointer <start>, and follow the leftmost
 * branch whose scope matches <scope>. It either returns the node hosting the
 * first leaf on that side, or NULL if no leaf is found. <start> may either be
 * NULL or a branch pointer. The pointer to the leaf (or NULL) is returned.
 */
static inline struct eb32sc_node *eb32sc_walk_down_left(eb_troot_t *start, unsigned long scope)
{
	struct eb_root *root;
	struct eb_node *node;
	struct eb32sc_node *eb32;

	if (unlikely(!start))
		return NULL;

	while (1) {
		if (eb_gettag(start) == EB_NODE) {
			root = eb_untag(start, EB_NODE);
			node = eb_root_to_node(root);
			eb32 = container_of(node, struct eb32sc_node, node);
			if (eb32->node_s & scope) {
				start = node->branches.b[EB_LEFT];
				continue;
			}
			start = node->node_p;
		}
		else {
			root = eb_untag(start, EB_LEAF);
			node = eb_root_to_node(root);
			eb32 = container_of(node, struct eb32sc_node, node);
			if (eb32->leaf_s & scope)
				return eb32;
			start = node->leaf_p;
		}

		/* here we're on a node that doesn't match the scope. We have
		 * to walk to the closest right location.
		 */
		while (eb_gettag(start) != EB_LEFT)
			/* Walking up from right branch, so we cannot be below root */
			start = (eb_root_to_node(eb_untag(start, EB_RGHT)))->node_p;

		/* Note that <start> cannot be NULL at this stage */
		root = eb_untag(start, EB_LEFT);
		start = root->b[EB_RGHT];
		if (eb_clrtag(start) == NULL)
			return NULL;
	}
}

/* Return next node in the tree, starting with tagged parent <start>, or NULL if none */
static inline struct eb32sc_node *eb32sc_next_with_parent(eb_troot_t *start, unsigned long scope)
{
	while (eb_gettag(start) != EB_LEFT)
		/* Walking up from right branch, so we cannot be below root */
		start = (eb_root_to_node(eb_untag(start, EB_RGHT)))->node_p;

	/* Note that <t> cannot be NULL at this stage */
	start = (eb_untag(start, EB_LEFT))->b[EB_RGHT];
	if (eb_clrtag(start) == NULL)
		return NULL;

	return eb32sc_walk_down_left(start, scope);
}

/* Return next node in the tree, or NULL if none */
static inline struct eb32sc_node *eb32sc_next(struct eb32sc_node *eb32, unsigned long scope)
{
	return eb32sc_next_with_parent(eb32->node.leaf_p, scope);
}

/* Return leftmost node in the tree, or NULL if none */
static inline struct eb32sc_node *eb32sc_first(struct eb_root *root, unsigned long scope)
{
	return eb32sc_walk_down_left(root->b[0], scope);
}

#endif /* _EB32SC_TREE_H */
