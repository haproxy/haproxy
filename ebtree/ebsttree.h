/*
 * Elastic Binary Trees - macros to manipulate String data nodes.
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

/* These functions and macros rely on Multi-Byte nodes */

#ifndef _EBSTTREE_H
#define _EBSTTREE_H

#include "ebtree.h"
#include "ebmbtree.h"

/* The following functions are not inlined by default. They are declared
 * in ebsttree.c, which simply relies on their inline version.
 */
REGPRM2 struct ebmb_node *ebst_lookup(struct eb_root *root, const char *x);
REGPRM2 struct ebmb_node *ebst_insert(struct eb_root *root, struct ebmb_node *new);

/* Find the first occurence of a length <len> string <x> in the tree <root>.
 * It's the caller's reponsibility to use this function only on trees which
 * only contain zero-terminated strings, and that no null character is present
 * in string <x> in the first <len> chars. If none can be found, return NULL.
 */
static forceinline struct ebmb_node *
ebst_lookup_len(struct eb_root *root, const char *x, unsigned int len)
{
	struct ebmb_node *node;

	node = ebmb_lookup(root, x, len);
	if (!node || node->key[len] != 0)
		return NULL;
	return node;
}

/* Find the first occurence of a zero-terminated string <x> in the tree <root>.
 * It's the caller's reponsibility to use this function only on trees which
 * only contain zero-terminated strings. If none can be found, return NULL.
 */
static forceinline struct ebmb_node *__ebst_lookup(struct eb_root *root, const void *x)
{
	struct ebmb_node *node;
	eb_troot_t *troot;
	int bit;
	int node_bit;

	troot = root->b[EB_LEFT];
	if (unlikely(troot == NULL))
		return NULL;

	bit = 0;
	while (1) {
		if ((eb_gettag(troot) == EB_LEAF)) {
			node = container_of(eb_untag(troot, EB_LEAF),
					    struct ebmb_node, node.branches);
			if (strcmp((char *)node->key, x) == 0)
				return node;
			else
				return NULL;
		}
		node = container_of(eb_untag(troot, EB_NODE),
				    struct ebmb_node, node.branches);
		node_bit = node->node.bit;

		if (node_bit < 0) {
			/* We have a dup tree now. Either it's for the same
			 * value, and we walk down left, or it's a different
			 * one and we don't have our key.
			 */
			if (strcmp((char *)node->key, x) != 0)
				return NULL;

			troot = node->node.branches.b[EB_LEFT];
			while (eb_gettag(troot) != EB_LEAF)
				troot = (eb_untag(troot, EB_NODE))->b[EB_LEFT];
			node = container_of(eb_untag(troot, EB_LEAF),
					    struct ebmb_node, node.branches);
			return node;
		}

		/* OK, normal data node, let's walk down but don't compare data
		 * if we already reached the end of the key.
		 */
		if (likely(bit >= 0)) {
			bit = string_equal_bits(x, node->key, bit);
			if (likely(bit < node_bit)) {
				if (bit >= 0)
					return NULL; /* no more common bits */

				/* bit < 0 : we reached the end of the key. If we
				 * are in a tree with unique keys, we can return
				 * this node. Otherwise we have to walk it down
				 * and stop comparing bits.
				 */
				if (eb_gettag(root->b[EB_RGHT]))
					return node;
			}
			/* if the bit is larger than the node's, we must bound it
			 * because we might have compared too many bytes with an
			 * inappropriate leaf. For a test, build a tree from "0",
			 * "WW", "W", "S" inserted in this exact sequence and lookup
			 * "W" => "S" is returned without this assignment.
			 */
			else
				bit = node_bit;
		}

		troot = node->node.branches.b[(((unsigned char*)x)[node_bit >> 3] >>
					       (~node_bit & 7)) & 1];
	}
}

/* Insert ebmb_node <new> into subtree starting at node root <root>. Only
 * new->key needs be set with the zero-terminated string key. The ebmb_node is
 * returned. If root->b[EB_RGHT]==1, the tree may only contain unique keys. The
 * caller is responsible for properly terminating the key with a zero.
 */
static forceinline struct ebmb_node *
__ebst_insert(struct eb_root *root, struct ebmb_node *new)
{
	struct ebmb_node *old;
	unsigned int side;
	eb_troot_t *troot;
	eb_troot_t *root_right;
	int diff;
	int bit;
	int old_node_bit;

	side = EB_LEFT;
	troot = root->b[EB_LEFT];
	root_right = root->b[EB_RGHT];
	if (unlikely(troot == NULL)) {
		/* Tree is empty, insert the leaf part below the left branch */
		root->b[EB_LEFT] = eb_dotag(&new->node.branches, EB_LEAF);
		new->node.leaf_p = eb_dotag(root, EB_LEFT);
		new->node.node_p = NULL; /* node part unused */
		return new;
	}

	/* The tree descent is fairly easy :
	 *  - first, check if we have reached a leaf node
	 *  - second, check if we have gone too far
	 *  - third, reiterate
	 * Everywhere, we use <new> for the node node we are inserting, <root>
	 * for the node we attach it to, and <old> for the node we are
	 * displacing below <new>. <troot> will always point to the future node
	 * (tagged with its type). <side> carries the side the node <new> is
	 * attached to below its parent, which is also where previous node
	 * was attached.
	 */

	bit = 0;
	while (1) {
		if (unlikely(eb_gettag(troot) == EB_LEAF)) {
			eb_troot_t *new_left, *new_rght;
			eb_troot_t *new_leaf, *old_leaf;

			old = container_of(eb_untag(troot, EB_LEAF),
					    struct ebmb_node, node.branches);

			new_left = eb_dotag(&new->node.branches, EB_LEFT);
			new_rght = eb_dotag(&new->node.branches, EB_RGHT);
			new_leaf = eb_dotag(&new->node.branches, EB_LEAF);
			old_leaf = eb_dotag(&old->node.branches, EB_LEAF);

			new->node.node_p = old->node.leaf_p;

			/* Right here, we have 3 possibilities :
			 * - the tree does not contain the key, and we have
			 *   new->key < old->key. We insert new above old, on
			 *   the left ;
			 *
			 * - the tree does not contain the key, and we have
			 *   new->key > old->key. We insert new above old, on
			 *   the right ;
			 *
			 * - the tree does contain the key, which implies it
			 *   is alone. We add the new key next to it as a
			 *   first duplicate.
			 *
			 * The last two cases can easily be partially merged.
			 */
			if (bit >= 0)
				bit = string_equal_bits(new->key, old->key, bit);

			if (bit < 0) {
				/* key was already there */

				/* we may refuse to duplicate this key if the tree is
				 * tagged as containing only unique keys.
				 */
				if (eb_gettag(root_right))
					return old;

				/* new arbitrarily goes to the right and tops the dup tree */
				old->node.leaf_p = new_left;
				new->node.leaf_p = new_rght;
				new->node.branches.b[EB_LEFT] = old_leaf;
				new->node.branches.b[EB_RGHT] = new_leaf;
				new->node.bit = -1;
				root->b[side] = eb_dotag(&new->node.branches, EB_NODE);
				return new;
			}

			diff = cmp_bits(new->key, old->key, bit);
			if (diff < 0) {
				/* new->key < old->key, new takes the left */
				new->node.leaf_p = new_left;
				old->node.leaf_p = new_rght;
				new->node.branches.b[EB_LEFT] = new_leaf;
				new->node.branches.b[EB_RGHT] = old_leaf;
			} else {
				/* new->key > old->key, new takes the right */
				old->node.leaf_p = new_left;
				new->node.leaf_p = new_rght;
				new->node.branches.b[EB_LEFT] = old_leaf;
				new->node.branches.b[EB_RGHT] = new_leaf;
			}
			break;
		}

		/* OK we're walking down this link */
		old = container_of(eb_untag(troot, EB_NODE),
				   struct ebmb_node, node.branches);
		old_node_bit = old->node.bit;

		/* Stop going down when we don't have common bits anymore. We
		 * also stop in front of a duplicates tree because it means we
		 * have to insert above. Note: we can compare more bits than
		 * the current node's because as long as they are identical, we
		 * know we descend along the correct side.
		 */
		if (bit >= 0 && (bit < old_node_bit || old_node_bit < 0))
			bit = string_equal_bits(new->key, old->key, bit);

		if (unlikely(bit < 0)) {
			/* Perfect match, we must only stop on head of dup tree
			 * or walk down to a leaf.
			 */
			if (old_node_bit < 0) {
				/* We know here that string_equal_bits matched all
				 * bits and that we're on top of a dup tree, then
				 * we can perform the dup insertion and return.
				 */
				struct eb_node *ret;
				ret = eb_insert_dup(&old->node, &new->node);
				return container_of(ret, struct ebmb_node, node);
			}
			/* OK so let's walk down */
		}
		else if (bit < old_node_bit || old_node_bit < 0) {
			/* The tree did not contain the key, or we stopped on top of a dup
			 * tree, possibly containing the key. In the former case, we insert
			 * <new> before the node <old>, and set ->bit to designate the lowest
			 * bit position in <new> which applies to ->branches.b[]. In the later
			 * case, we add the key to the existing dup tree. Note that we cannot
			 * enter here if we match an intermediate node's key that is not the
			 * head of a dup tree.
			 */
			eb_troot_t *new_left, *new_rght;
			eb_troot_t *new_leaf, *old_node;

			new_left = eb_dotag(&new->node.branches, EB_LEFT);
			new_rght = eb_dotag(&new->node.branches, EB_RGHT);
			new_leaf = eb_dotag(&new->node.branches, EB_LEAF);
			old_node = eb_dotag(&old->node.branches, EB_NODE);

			new->node.node_p = old->node.node_p;

			/* we can never match all bits here */
			diff = cmp_bits(new->key, old->key, bit);
			if (diff < 0) {
				new->node.leaf_p = new_left;
				old->node.node_p = new_rght;
				new->node.branches.b[EB_LEFT] = new_leaf;
				new->node.branches.b[EB_RGHT] = old_node;
			}
			else {
				old->node.node_p = new_left;
				new->node.leaf_p = new_rght;
				new->node.branches.b[EB_LEFT] = old_node;
				new->node.branches.b[EB_RGHT] = new_leaf;
			}
			break;
		}

		/* walk down */
		root = &old->node.branches;
		side = (new->key[old_node_bit >> 3] >> (~old_node_bit & 7)) & 1;
		troot = root->b[side];
	}

	/* Ok, now we are inserting <new> between <root> and <old>. <old>'s
	 * parent is already set to <new>, and the <root>'s branch is still in
	 * <side>. Update the root's leaf till we have it. Note that we can also
	 * find the side by checking the side of new->node.node_p.
	 */

	/* We need the common higher bits between new->key and old->key.
	 * This number of bits is already in <bit>.
	 * NOTE: we can't get here whit bit < 0 since we found a dup !
	 */
	new->node.bit = bit;
	root->b[side] = eb_dotag(&new->node.branches, EB_NODE);
	return new;
}

#endif /* _EBSTTREE_H */

