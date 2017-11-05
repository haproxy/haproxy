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
typedef unsigned int u32;
typedef   signed int s32;

/* This structure carries a node, a leaf, a scope, and a key. It must start
 * with the eb_node so that it can be cast into an eb_node. We could also
 * have put some sort of transparent union here to reduce the indirection
 * level, but the fact is, the end user is not meant to manipulate internals,
 * so this is pointless.
 */
struct eb32sc_node {
	struct eb_node node; /* the tree node, must be at the beginning */
	unsigned long node_s; /* visibility of this node's branches */
	unsigned long leaf_s; /* visibility of this node's leaf */
	u32 key;
};

/*
 * Exported functions and macros.
 * Many of them are always inlined because they are extremely small, and
 * are generally called at most once or twice in a program.
 */

/*
 * The following functions are not inlined by default. They are declared
 * in eb32sctree.c, which simply relies on their inline version.
 */
REGPRM2 struct eb32sc_node *eb32sc_lookup_ge(struct eb_root *root, u32 x, unsigned long scope);
REGPRM2 struct eb32sc_node *eb32sc_insert(struct eb_root *root, struct eb32sc_node *new, unsigned long scope);
void eb32sc_delete(struct eb32sc_node *node);

/* Walks down starting at root pointer <start>, and always walking on side
 * <side>. It either returns the node hosting the first leaf on that side,
 * or NULL if no leaf is found. <start> may either be NULL or a branch pointer.
 * The pointer to the leaf (or NULL) is returned.
 */
static inline struct eb32sc_node *eb32sc_walk_down(eb_troot_t *start, unsigned int side, unsigned long scope)
{
	/* A NULL pointer on an empty tree root will be returned as-is */
	while (eb_gettag(start) == EB_NODE)
		start = (eb_untag(start, EB_NODE))->b[side];
	/* NULL is left untouched (root==eb_node, EB_LEAF==0) */
	return eb32sc_entry(eb_root_to_node(eb_untag(start, EB_LEAF)), struct eb32sc_node, node);
}

/* Return next node in the tree, or NULL if none */
static inline struct eb32sc_node *eb32sc_next(struct eb32sc_node *eb32, unsigned long scope)
{
	struct eb_node *node = &eb32->node;
	eb_troot_t *t = node->leaf_p;

	while (eb_gettag(t) != EB_LEFT)
		/* Walking up from right branch, so we cannot be below root */
		t = (eb_root_to_node(eb_untag(t, EB_RGHT)))->node_p;

	/* Note that <t> cannot be NULL at this stage */
	t = (eb_untag(t, EB_LEFT))->b[EB_RGHT];
	if (eb_clrtag(t) == NULL)
		return NULL;

	return eb32sc_walk_down(t, EB_LEFT, scope);
}

/* Return leftmost node in the tree, or NULL if none */
static inline struct eb32sc_node *eb32sc_first(struct eb_root *root, unsigned long scope)
{
	return eb32sc_walk_down(root->b[0], EB_LEFT, scope);
}

#endif /* _EB32SC_TREE_H */
