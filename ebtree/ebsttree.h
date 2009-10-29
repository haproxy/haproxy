/*
 * Elastic Binary Trees - macros to manipulate String data nodes.
 * Version 5.0
 * (C) 2002-2009 - Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/* These functions and macros rely on Multi-Byte nodes */

#include "ebtree.h"
#include "ebmbtree.h"

/* The following functions are not inlined by default. They are declared
 * in ebsttree.c, which simply relies on their inline version.
 */
REGPRM2 struct ebmb_node *ebst_lookup(struct eb_root *root, const char *x);
REGPRM2 struct ebmb_node *ebst_insert(struct eb_root *root, struct ebmb_node *new);

/* Find the first occurence of a zero-terminated string <x> in the tree <root>.
 * It's the caller's reponsibility to use this function only on trees which
 * only contain zero-terminated strings. If none can be found, return NULL.
 */
static forceinline struct ebmb_node *__ebst_lookup(struct eb_root *root, const void *x)
{
	struct ebmb_node *node;
	eb_troot_t *troot;
	unsigned int bit;

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

		if (node->node.bit < 0) {
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

		/* OK, normal data node, let's walk down */
		bit = string_equal_bits(x, node->key, bit);
		if (bit < node->node.bit)
			return NULL; /* no more common bits */

		troot = node->node.branches.b[(((unsigned char*)x)[node->node.bit >> 3] >>
					       (~node->node.bit & 7)) & 1];
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
	eb_troot_t *root_right = root;
	int diff;
	int bit;

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
			bit = string_equal_bits(new->key, old->key, bit);
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
				   struct ebmb_node, node.branches);

		/* Stop going down when we don't have common bits anymore. We
		 * also stop in front of a duplicates tree because it means we
		 * have to insert above. Note: we can compare more bits than
		 * the current node's because as long as they are identical, we
		 * know we descend along the correct side.
		 */
		if (old->node.bit < 0) {
			/* we're above a duplicate tree, we must compare till the end */
			bit = string_equal_bits(new->key, old->key, bit);
			goto dup_tree;
		}
		else if (bit < old->node.bit) {
			bit = string_equal_bits(new->key, old->key, bit);
		}

		if (bit < old->node.bit) { /* we don't have all bits in common */
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
				return container_of(ret, struct ebmb_node, node);
			}
			break;
		}

		/* walk down */
		root = &old->node.branches;
		side = (new->key[old->node.bit >> 3] >> (~old->node.bit & 7)) & 1;
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

