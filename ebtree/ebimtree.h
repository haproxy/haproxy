/*
 * Elastic Binary Trees - macros for Indirect Multi-Byte data nodes.
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

#ifndef _EBIMTREE_H
#define _EBIMTREE_H

#include <string.h>
#include "ebtree.h"
#include "ebpttree.h"

/* These functions and macros rely on Pointer nodes and use the <key> entry as
 * a pointer to an indirect key. Most operations are performed using ebpt_*.
 */

/* The following functions are not inlined by default. They are declared
 * in ebimtree.c, which simply relies on their inline version.
 */
REGPRM3 struct ebpt_node *ebim_lookup(struct eb_root *root, const void *x, unsigned int len);
REGPRM3 struct ebpt_node *ebim_insert(struct eb_root *root, struct ebpt_node *new, unsigned int len);

/* Find the first occurrence of a key of a least <len> bytes matching <x> in the
 * tree <root>. The caller is responsible for ensuring that <len> will not exceed
 * the common parts between the tree's keys and <x>. In case of multiple matches,
 * the leftmost node is returned. This means that this function can be used to
 * lookup string keys by prefix if all keys in the tree are zero-terminated. If
 * no match is found, NULL is returned. Returns first node if <len> is zero.
 */
static forceinline struct ebpt_node *
__ebim_lookup(struct eb_root *root, const void *x, unsigned int len)
{
	struct ebpt_node *node;
	eb_troot_t *troot;
	int pos, side;
	int node_bit;

	troot = root->b[EB_LEFT];
	if (unlikely(troot == NULL))
		goto ret_null;

	if (unlikely(len == 0))
		goto walk_down;

	pos = 0;
	while (1) {
		if (eb_gettag(troot) == EB_LEAF) {
			node = container_of(eb_untag(troot, EB_LEAF),
					    struct ebpt_node, node.branches);
			if (memcmp(node->key + pos, x, len) != 0)
				goto ret_null;
			else
				goto ret_node;
		}
		node = container_of(eb_untag(troot, EB_NODE),
				    struct ebpt_node, node.branches);

		node_bit = node->node.bit;
		if (node_bit < 0) {
			/* We have a dup tree now. Either it's for the same
			 * value, and we walk down left, or it's a different
			 * one and we don't have our key.
			 */
			if (memcmp(node->key + pos, x, len) != 0)
				goto ret_null;
			else
				goto walk_left;
		}

		/* OK, normal data node, let's walk down. We check if all full
		 * bytes are equal, and we start from the last one we did not
		 * completely check. We stop as soon as we reach the last byte,
		 * because we must decide to go left/right or abort.
		 */
		node_bit = ~node_bit + (pos << 3) + 8; // = (pos<<3) + (7 - node_bit)
		if (node_bit < 0) {
			/* This surprising construction gives better performance
			 * because gcc does not try to reorder the loop. Tested to
			 * be fine with 2.95 to 4.2.
			 */
			while (1) {
				if (*(unsigned char*)(node->key + pos++) ^ *(unsigned char*)(x++))
					goto ret_null; /* more than one full byte is different */
				if (--len == 0)
					goto walk_left; /* return first node if all bytes matched */
				node_bit += 8;
				if (node_bit >= 0)
					break;
			}
		}

		/* here we know that only the last byte differs, so node_bit < 8.
		 * We have 2 possibilities :
		 *   - more than the last bit differs => return NULL
		 *   - walk down on side = (x[pos] >> node_bit) & 1
		 */
		side = *(unsigned char *)x >> node_bit;
		if (((*(unsigned char*)(node->key + pos) >> node_bit) ^ side) > 1)
			goto ret_null;
		side &= 1;
		troot = node->node.branches.b[side];
	}
 walk_left:
	troot = node->node.branches.b[EB_LEFT];
 walk_down:
	while (eb_gettag(troot) != EB_LEAF)
		troot = (eb_untag(troot, EB_NODE))->b[EB_LEFT];
	node = container_of(eb_untag(troot, EB_LEAF),
			    struct ebpt_node, node.branches);
 ret_node:
	return node;
 ret_null:
	return NULL;
}

/* Insert ebpt_node <new> into subtree starting at node root <root>.
 * Only new->key needs be set with the key. The ebpt_node is returned.
 * If root->b[EB_RGHT]==1, the tree may only contain unique keys. The
 * len is specified in bytes.
 */
static forceinline struct ebpt_node *
__ebim_insert(struct eb_root *root, struct ebpt_node *new, unsigned int len)
{
	struct ebpt_node *old;
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

	len <<= 3;

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
					    struct ebpt_node, node.branches);

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
			bit = equal_bits(new->key, old->key, bit, len);

			/* Note: we can compare more bits than the current node's because as
			 * long as they are identical, we know we descend along the correct
			 * side. However we don't want to start to compare past the end.
			 */
			diff = 0;
			if (((unsigned)bit >> 3) < len)
				diff = cmp_bits(new->key, old->key, bit);

			if (diff < 0) {
				new->node.leaf_p = new_left;
				old->node.leaf_p = new_rght;
				new->node.branches.b[EB_LEFT] = new_leaf;
				new->node.branches.b[EB_RGHT] = old_leaf;
			} else {
				/* we may refuse to duplicate this key if the tree is
				 * tagged as containing only unique keys.
				 */
				if (diff == 0 && eb_gettag(root_right))
					return old;

				/* new->key >= old->key, new goes the right */
				old->node.leaf_p = new_left;
				new->node.leaf_p = new_rght;
				new->node.branches.b[EB_LEFT] = old_leaf;
				new->node.branches.b[EB_RGHT] = new_leaf;

				if (diff == 0) {
					new->node.bit = -1;
					root->b[side] = eb_dotag(&new->node.branches, EB_NODE);
					return new;
				}
			}
			break;
		}

		/* OK we're walking down this link */
		old = container_of(eb_untag(troot, EB_NODE),
				   struct ebpt_node, node.branches);
		old_node_bit = old->node.bit;

		/* Stop going down when we don't have common bits anymore. We
		 * also stop in front of a duplicates tree because it means we
		 * have to insert above. Note: we can compare more bits than
		 * the current node's because as long as they are identical, we
		 * know we descend along the correct side.
		 */
		if (old_node_bit < 0) {
			/* we're above a duplicate tree, we must compare till the end */
			bit = equal_bits(new->key, old->key, bit, len);
			goto dup_tree;
		}
		else if (bit < old_node_bit) {
			bit = equal_bits(new->key, old->key, bit, old_node_bit);
		}

		if (bit < old_node_bit) { /* we don't have all bits in common */
			/* The tree did not contain the key, so we insert <new> before the node
			 * <old>, and set ->bit to designate the lowest bit position in <new>
			 * which applies to ->branches.b[].
			 */
			eb_troot_t *new_left, *new_rght;
			eb_troot_t *new_leaf, *old_node;

		dup_tree:
			new_left = eb_dotag(&new->node.branches, EB_LEFT);
			new_rght = eb_dotag(&new->node.branches, EB_RGHT);
			new_leaf = eb_dotag(&new->node.branches, EB_LEAF);
			old_node = eb_dotag(&old->node.branches, EB_NODE);

			new->node.node_p = old->node.node_p;

			/* Note: we can compare more bits than the current node's because as
			 * long as they are identical, we know we descend along the correct
			 * side. However we don't want to start to compare past the end.
			 */
			diff = 0;
			if (((unsigned)bit >> 3) < len)
				diff = cmp_bits(new->key, old->key, bit);

			if (diff < 0) {
				new->node.leaf_p = new_left;
				old->node.node_p = new_rght;
				new->node.branches.b[EB_LEFT] = new_leaf;
				new->node.branches.b[EB_RGHT] = old_node;
			}
			else if (diff > 0) {
				old->node.node_p = new_left;
				new->node.leaf_p = new_rght;
				new->node.branches.b[EB_LEFT] = old_node;
				new->node.branches.b[EB_RGHT] = new_leaf;
			}
			else {
				struct eb_node *ret;
				ret = eb_insert_dup(&old->node, &new->node);
				return container_of(ret, struct ebpt_node, node);
			}
			break;
		}

		/* walk down */
		root = &old->node.branches;
		side = (((unsigned char *)new->key)[old_node_bit >> 3] >> (~old_node_bit & 7)) & 1;
		troot = root->b[side];
	}

	/* Ok, now we are inserting <new> between <root> and <old>. <old>'s
	 * parent is already set to <new>, and the <root>'s branch is still in
	 * <side>. Update the root's leaf till we have it. Note that we can also
	 * find the side by checking the side of new->node.node_p.
	 */

	/* We need the common higher bits between new->key and old->key.
	 * This number of bits is already in <bit>.
	 */
	new->node.bit = bit;
	root->b[side] = eb_dotag(&new->node.branches, EB_NODE);
	return new;
}

#endif /* _EBIMTREE_H */
