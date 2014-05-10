/*
 * Elastic Binary Trees - macros and structures for Multi-Byte data nodes.
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

#ifndef _EBMBTREE_H
#define _EBMBTREE_H

#include <string.h>
#include "ebtree.h"

/* Return the structure of type <type> whose member <member> points to <ptr> */
#define ebmb_entry(ptr, type, member) container_of(ptr, type, member)

#define EBMB_ROOT	EB_ROOT
#define EBMB_TREE_HEAD	EB_TREE_HEAD

/* This structure carries a node, a leaf, and a key. It must start with the
 * eb_node so that it can be cast into an eb_node. We could also have put some
 * sort of transparent union here to reduce the indirection level, but the fact
 * is, the end user is not meant to manipulate internals, so this is pointless.
 * The 'node.bit' value here works differently from scalar types, as it contains
 * the number of identical bits between the two branches.
 */
struct ebmb_node {
	struct eb_node node; /* the tree node, must be at the beginning */
	unsigned char key[0]; /* the key, its size depends on the application */
};

/*
 * Exported functions and macros.
 * Many of them are always inlined because they are extremely small, and
 * are generally called at most once or twice in a program.
 */

/* Return leftmost node in the tree, or NULL if none */
static forceinline struct ebmb_node *ebmb_first(struct eb_root *root)
{
	return ebmb_entry(eb_first(root), struct ebmb_node, node);
}

/* Return rightmost node in the tree, or NULL if none */
static forceinline struct ebmb_node *ebmb_last(struct eb_root *root)
{
	return ebmb_entry(eb_last(root), struct ebmb_node, node);
}

/* Return next node in the tree, or NULL if none */
static forceinline struct ebmb_node *ebmb_next(struct ebmb_node *ebmb)
{
	return ebmb_entry(eb_next(&ebmb->node), struct ebmb_node, node);
}

/* Return previous node in the tree, or NULL if none */
static forceinline struct ebmb_node *ebmb_prev(struct ebmb_node *ebmb)
{
	return ebmb_entry(eb_prev(&ebmb->node), struct ebmb_node, node);
}

/* Return next leaf node within a duplicate sub-tree, or NULL if none. */
static inline struct ebmb_node *ebmb_next_dup(struct ebmb_node *ebmb)
{
	return ebmb_entry(eb_next_dup(&ebmb->node), struct ebmb_node, node);
}

/* Return previous leaf node within a duplicate sub-tree, or NULL if none. */
static inline struct ebmb_node *ebmb_prev_dup(struct ebmb_node *ebmb)
{
	return ebmb_entry(eb_prev_dup(&ebmb->node), struct ebmb_node, node);
}

/* Return next node in the tree, skipping duplicates, or NULL if none */
static forceinline struct ebmb_node *ebmb_next_unique(struct ebmb_node *ebmb)
{
	return ebmb_entry(eb_next_unique(&ebmb->node), struct ebmb_node, node);
}

/* Return previous node in the tree, skipping duplicates, or NULL if none */
static forceinline struct ebmb_node *ebmb_prev_unique(struct ebmb_node *ebmb)
{
	return ebmb_entry(eb_prev_unique(&ebmb->node), struct ebmb_node, node);
}

/* Delete node from the tree if it was linked in. Mark the node unused. Note
 * that this function relies on a non-inlined generic function: eb_delete.
 */
static forceinline void ebmb_delete(struct ebmb_node *ebmb)
{
	eb_delete(&ebmb->node);
}

/* The following functions are not inlined by default. They are declared
 * in ebmbtree.c, which simply relies on their inline version.
 */
REGPRM3 struct ebmb_node *ebmb_lookup(struct eb_root *root, const void *x, unsigned int len);
REGPRM3 struct ebmb_node *ebmb_insert(struct eb_root *root, struct ebmb_node *new, unsigned int len);
REGPRM2 struct ebmb_node *ebmb_lookup_longest(struct eb_root *root, const void *x);
REGPRM3 struct ebmb_node *ebmb_lookup_prefix(struct eb_root *root, const void *x, unsigned int pfx);
REGPRM3 struct ebmb_node *ebmb_insert_prefix(struct eb_root *root, struct ebmb_node *new, unsigned int len);

/* The following functions are less likely to be used directly, because their
 * code is larger. The non-inlined version is preferred.
 */

/* Delete node from the tree if it was linked in. Mark the node unused. */
static forceinline void __ebmb_delete(struct ebmb_node *ebmb)
{
	__eb_delete(&ebmb->node);
}

/* Find the first occurence of a key of a least <len> bytes matching <x> in the
 * tree <root>. The caller is responsible for ensuring that <len> will not exceed
 * the common parts between the tree's keys and <x>. In case of multiple matches,
 * the leftmost node is returned. This means that this function can be used to
 * lookup string keys by prefix if all keys in the tree are zero-terminated. If
 * no match is found, NULL is returned. Returns first node if <len> is zero.
 */
static forceinline struct ebmb_node *__ebmb_lookup(struct eb_root *root, const void *x, unsigned int len)
{
	struct ebmb_node *node;
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
					    struct ebmb_node, node.branches);
			if (memcmp(node->key + pos, x, len) != 0)
				goto ret_null;
			else
				goto ret_node;
		}
		node = container_of(eb_untag(troot, EB_NODE),
				    struct ebmb_node, node.branches);

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
			/* This surprizing construction gives better performance
			 * because gcc does not try to reorder the loop. Tested to
			 * be fine with 2.95 to 4.2.
			 */
			while (1) {
				if (node->key[pos++] ^ *(unsigned char*)(x++))
					goto ret_null;  /* more than one full byte is different */
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
		if (((node->key[pos] >> node_bit) ^ side) > 1)
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
			    struct ebmb_node, node.branches);
 ret_node:
	return node;
 ret_null:
	return NULL;
}

/* Insert ebmb_node <new> into subtree starting at node root <root>.
 * Only new->key needs be set with the key. The ebmb_node is returned.
 * If root->b[EB_RGHT]==1, the tree may only contain unique keys. The
 * len is specified in bytes. It is absolutely mandatory that this length
 * is the same for all keys in the tree. This function cannot be used to
 * insert strings.
 */
static forceinline struct ebmb_node *
__ebmb_insert(struct eb_root *root, struct ebmb_node *new, unsigned int len)
{
	struct ebmb_node *old;
	unsigned int side;
	eb_troot_t *troot, **up_ptr;
	eb_troot_t *root_right;
	int diff;
	int bit;
	eb_troot_t *new_left, *new_rght;
	eb_troot_t *new_leaf;
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
			/* insert above a leaf */
			old = container_of(eb_untag(troot, EB_LEAF),
					    struct ebmb_node, node.branches);
			new->node.node_p = old->node.leaf_p;
			up_ptr = &old->node.leaf_p;
			goto check_bit_and_break;
		}

		/* OK we're walking down this link */
		old = container_of(eb_untag(troot, EB_NODE),
				   struct ebmb_node, node.branches);
		old_node_bit = old->node.bit;

		if (unlikely(old->node.bit < 0)) {
			/* We're above a duplicate tree, so we must compare the whole value */
			new->node.node_p = old->node.node_p;
			up_ptr = &old->node.node_p;
		check_bit_and_break:
			bit = equal_bits(new->key, old->key, bit, len << 3);
			break;
		}

		/* Stop going down when we don't have common bits anymore. We
		 * also stop in front of a duplicates tree because it means we
		 * have to insert above. Note: we can compare more bits than
		 * the current node's because as long as they are identical, we
		 * know we descend along the correct side.
		 */

		bit = equal_bits(new->key, old->key, bit, old_node_bit);
		if (unlikely(bit < old_node_bit)) {
			/* The tree did not contain the key, so we insert <new> before the
			 * node <old>, and set ->bit to designate the lowest bit position in
			 * <new> which applies to ->branches.b[].
			 */
			new->node.node_p = old->node.node_p;
			up_ptr = &old->node.node_p;
			break;
		}
		/* we don't want to skip bits for further comparisons, so we must limit <bit>.
		 * However, since we're going down around <old_node_bit>, we know it will be
		 * properly matched, so we can skip this bit.
		 */
		bit = old_node_bit + 1;

		/* walk down */
		root = &old->node.branches;
		side = old_node_bit & 7;
		side ^= 7;
		side = (new->key[old_node_bit >> 3] >> side) & 1;
		troot = root->b[side];
	}

	new_left = eb_dotag(&new->node.branches, EB_LEFT);
	new_rght = eb_dotag(&new->node.branches, EB_RGHT);
	new_leaf = eb_dotag(&new->node.branches, EB_LEAF);

	new->node.bit = bit;

	/* Note: we can compare more bits than the current node's because as
	 * long as they are identical, we know we descend along the correct
	 * side. However we don't want to start to compare past the end.
	 */
	diff = 0;
	if (((unsigned)bit >> 3) < len)
		diff = cmp_bits(new->key, old->key, bit);

	if (diff == 0) {
		new->node.bit = -1; /* mark as new dup tree, just in case */

		if (likely(eb_gettag(root_right))) {
			/* we refuse to duplicate this key if the tree is
			 * tagged as containing only unique keys.
			 */
			return old;
		}

		if (eb_gettag(troot) != EB_LEAF) {
			/* there was already a dup tree below */
			struct eb_node *ret;
			ret = eb_insert_dup(&old->node, &new->node);
			return container_of(ret, struct ebmb_node, node);
		}
		/* otherwise fall through */
	}

	if (diff >= 0) {
		new->node.branches.b[EB_LEFT] = troot;
		new->node.branches.b[EB_RGHT] = new_leaf;
		new->node.leaf_p = new_rght;
		*up_ptr = new_left;
	}
	else if (diff < 0) {
		new->node.branches.b[EB_LEFT] = new_leaf;
		new->node.branches.b[EB_RGHT] = troot;
		new->node.leaf_p = new_left;
		*up_ptr = new_rght;
	}

	/* Ok, now we are inserting <new> between <root> and <old>. <old>'s
	 * parent is already set to <new>, and the <root>'s branch is still in
	 * <side>. Update the root's leaf till we have it. Note that we can also
	 * find the side by checking the side of new->node.node_p.
	 */

	root->b[side] = eb_dotag(&new->node.branches, EB_NODE);
	return new;
}


/* Find the first occurence of the longest prefix matching a key <x> in the
 * tree <root>. It's the caller's responsibility to ensure that key <x> is at
 * least as long as the keys in the tree. Note that this can be ensured by
 * having a byte at the end of <x> which cannot be part of any prefix, typically
 * the trailing zero for a string. If none can be found, return NULL.
 */
static forceinline struct ebmb_node *__ebmb_lookup_longest(struct eb_root *root, const void *x)
{
	struct ebmb_node *node;
	eb_troot_t *troot, *cover;
	int pos, side;
	int node_bit;

	troot = root->b[EB_LEFT];
	if (unlikely(troot == NULL))
		return NULL;

	cover = NULL;
	pos = 0;
	while (1) {
		if ((eb_gettag(troot) == EB_LEAF)) {
			node = container_of(eb_untag(troot, EB_LEAF),
					    struct ebmb_node, node.branches);
			if (check_bits(x - pos, node->key, pos, node->node.pfx))
				goto not_found;

			return node;
		}
		node = container_of(eb_untag(troot, EB_NODE),
				    struct ebmb_node, node.branches);

		node_bit = node->node.bit;
		if (node_bit < 0) {
			/* We have a dup tree now. Either it's for the same
			 * value, and we walk down left, or it's a different
			 * one and we don't have our key.
			 */
			if (check_bits(x - pos, node->key, pos, node->node.pfx))
				goto not_found;

			troot = node->node.branches.b[EB_LEFT];
			while (eb_gettag(troot) != EB_LEAF)
				troot = (eb_untag(troot, EB_NODE))->b[EB_LEFT];
			node = container_of(eb_untag(troot, EB_LEAF),
					    struct ebmb_node, node.branches);
			return node;
		}

		node_bit >>= 1; /* strip cover bit */
		node_bit = ~node_bit + (pos << 3) + 8; // = (pos<<3) + (7 - node_bit)
		if (node_bit < 0) {
			/* This uncommon construction gives better performance
			 * because gcc does not try to reorder the loop. Tested to
			 * be fine with 2.95 to 4.2.
			 */
			while (1) {
				x++; pos++;
				if (node->key[pos-1] ^ *(unsigned char*)(x-1))
					goto not_found; /* more than one full byte is different */
				node_bit += 8;
				if (node_bit >= 0)
					break;
			}
		}

		/* here we know that only the last byte differs, so 0 <= node_bit <= 7.
		 * We have 2 possibilities :
		 *   - more than the last bit differs => data does not match
		 *   - walk down on side = (x[pos] >> node_bit) & 1
		 */
		side = *(unsigned char *)x >> node_bit;
		if (((node->key[pos] >> node_bit) ^ side) > 1)
			goto not_found;

		if (!(node->node.bit & 1)) {
			/* This is a cover node, let's keep a reference to it
			 * for later. The covering subtree is on the left, and
			 * the covered subtree is on the right, so we have to
			 * walk down right.
			 */
			cover = node->node.branches.b[EB_LEFT];
			troot = node->node.branches.b[EB_RGHT];
			continue;
		}
		side &= 1;
		troot = node->node.branches.b[side];
	}

 not_found:
	/* Walk down last cover tre if it exists. It does not matter if cover is NULL */
	return ebmb_entry(eb_walk_down(cover, EB_LEFT), struct ebmb_node, node);
}


/* Find the first occurence of a prefix matching a key <x> of <pfx> BITS in the
 * tree <root>. It's the caller's responsibility to ensure that key <x> is at
 * least as long as the keys in the tree. Note that this can be ensured by
 * having a byte at the end of <x> which cannot be part of any prefix, typically
 * the trailing zero for a string. If none can be found, return NULL.
 */
static forceinline struct ebmb_node *__ebmb_lookup_prefix(struct eb_root *root, const void *x, unsigned int pfx)
{
	struct ebmb_node *node;
	eb_troot_t *troot;
	int pos, side;
	int node_bit;

	troot = root->b[EB_LEFT];
	if (unlikely(troot == NULL))
		return NULL;

	pos = 0;
	while (1) {
		if ((eb_gettag(troot) == EB_LEAF)) {
			node = container_of(eb_untag(troot, EB_LEAF),
					    struct ebmb_node, node.branches);
			if (node->node.pfx != pfx)
				return NULL;
			if (check_bits(x - pos, node->key, pos, node->node.pfx))
				return NULL;
			return node;
		}
		node = container_of(eb_untag(troot, EB_NODE),
				    struct ebmb_node, node.branches);

		node_bit = node->node.bit;
		if (node_bit < 0) {
			/* We have a dup tree now. Either it's for the same
			 * value, and we walk down left, or it's a different
			 * one and we don't have our key.
			 */
			if (node->node.pfx != pfx)
				return NULL;
			if (check_bits(x - pos, node->key, pos, node->node.pfx))
				return NULL;

			troot = node->node.branches.b[EB_LEFT];
			while (eb_gettag(troot) != EB_LEAF)
				troot = (eb_untag(troot, EB_NODE))->b[EB_LEFT];
			node = container_of(eb_untag(troot, EB_LEAF),
					    struct ebmb_node, node.branches);
			return node;
		}

		node_bit >>= 1; /* strip cover bit */
		node_bit = ~node_bit + (pos << 3) + 8; // = (pos<<3) + (7 - node_bit)
		if (node_bit < 0) {
			/* This uncommon construction gives better performance
			 * because gcc does not try to reorder the loop. Tested to
			 * be fine with 2.95 to 4.2.
			 */
			while (1) {
				x++; pos++;
				if (node->key[pos-1] ^ *(unsigned char*)(x-1))
					return NULL; /* more than one full byte is different */
				node_bit += 8;
				if (node_bit >= 0)
					break;
			}
		}

		/* here we know that only the last byte differs, so 0 <= node_bit <= 7.
		 * We have 2 possibilities :
		 *   - more than the last bit differs => data does not match
		 *   - walk down on side = (x[pos] >> node_bit) & 1
		 */
		side = *(unsigned char *)x >> node_bit;
		if (((node->key[pos] >> node_bit) ^ side) > 1)
			return NULL;

		if (!(node->node.bit & 1)) {
			/* This is a cover node, it may be the entry we're
			 * looking for. We already know that it matches all the
			 * bits, let's compare prefixes and descend the cover
			 * subtree if they match.
			 */
			if ((unsigned short)node->node.bit >> 1 == pfx)
				troot = node->node.branches.b[EB_LEFT];
			else
				troot = node->node.branches.b[EB_RGHT];
			continue;
		}
		side &= 1;
		troot = node->node.branches.b[side];
	}
}


/* Insert ebmb_node <new> into a prefix subtree starting at node root <root>.
 * Only new->key and new->pfx need be set with the key and its prefix length.
 * Note that bits between <pfx> and <len> are theorically ignored and should be
 * zero, as it is not certain yet that they will always be ignored everywhere
 * (eg in bit compare functions).
 * The ebmb_node is returned.
 * If root->b[EB_RGHT]==1, the tree may only contain unique keys. The
 * len is specified in bytes.
 */
static forceinline struct ebmb_node *
__ebmb_insert_prefix(struct eb_root *root, struct ebmb_node *new, unsigned int len)
{
	struct ebmb_node *old;
	unsigned int side;
	eb_troot_t *troot, **up_ptr;
	eb_troot_t *root_right;
	int diff;
	int bit;
	eb_troot_t *new_left, *new_rght;
	eb_troot_t *new_leaf;
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
	if (len > new->node.pfx)
		len = new->node.pfx;

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
			/* Insert above a leaf. Note that this leaf could very
			 * well be part of a cover node.
			 */
			old = container_of(eb_untag(troot, EB_LEAF),
					    struct ebmb_node, node.branches);
			new->node.node_p = old->node.leaf_p;
			up_ptr = &old->node.leaf_p;
			goto check_bit_and_break;
		}

		/* OK we're walking down this link */
		old = container_of(eb_untag(troot, EB_NODE),
				   struct ebmb_node, node.branches);
		old_node_bit = old->node.bit;
		/* Note that old_node_bit can be :
		 *   < 0    : dup tree
		 *   = 2N   : cover node for N bits
		 *   = 2N+1 : normal node at N bits
		 */

		if (unlikely(old_node_bit < 0)) {
			/* We're above a duplicate tree, so we must compare the whole value */
			new->node.node_p = old->node.node_p;
			up_ptr = &old->node.node_p;
		check_bit_and_break:
			/* No need to compare everything if the leaves are shorter than the new one. */
			if (len > old->node.pfx)
				len = old->node.pfx;
			bit = equal_bits(new->key, old->key, bit, len);
			break;
		}

		/* WARNING: for the two blocks below, <bit> is counted in half-bits */

		bit = equal_bits(new->key, old->key, bit, old_node_bit >> 1);
		bit = (bit << 1) + 1; // assume comparisons with normal nodes

		/* we must always check that our prefix is larger than the nodes
		 * we visit, otherwise we have to stop going down. The following
		 * test is able to stop before both normal and cover nodes.
		 */
		if (bit >= (new->node.pfx << 1) && (new->node.pfx << 1) < old_node_bit) {
			/* insert cover node here on the left */
			new->node.node_p = old->node.node_p;
			up_ptr = &old->node.node_p;
			new->node.bit = new->node.pfx << 1;
			diff = -1;
			goto insert_above;
		}

		if (unlikely(bit < old_node_bit)) {
			/* The tree did not contain the key, so we insert <new> before the
			 * node <old>, and set ->bit to designate the lowest bit position in
			 * <new> which applies to ->branches.b[]. We know that the bit is not
			 * greater than the prefix length thanks to the test above.
			 */
			new->node.node_p = old->node.node_p;
			up_ptr = &old->node.node_p;
			new->node.bit = bit;
			diff = cmp_bits(new->key, old->key, bit >> 1);
			goto insert_above;
		}

		if (!(old_node_bit & 1)) {
			/* if we encounter a cover node with our exact prefix length, it's
			 * necessarily the same value, so we insert there as a duplicate on
			 * the left. For that, we go down on the left and the leaf detection
			 * code will finish the job.
			 */
			if ((new->node.pfx << 1) == old_node_bit) {
				root = &old->node.branches;
				side = EB_LEFT;
				troot = root->b[side];
				continue;
			}

			/* cover nodes are always walked through on the right */
			side = EB_RGHT;
			bit = old_node_bit >> 1; /* recheck that bit */
			root = &old->node.branches;
			troot = root->b[side];
			continue;
		}

		/* we don't want to skip bits for further comparisons, so we must limit <bit>.
		 * However, since we're going down around <old_node_bit>, we know it will be
		 * properly matched, so we can skip this bit.
		 */
		old_node_bit >>= 1;
		bit = old_node_bit + 1;

		/* walk down */
		root = &old->node.branches;
		side = old_node_bit & 7;
		side ^= 7;
		side = (new->key[old_node_bit >> 3] >> side) & 1;
		troot = root->b[side];
	}

	/* Right here, we have 4 possibilities :
	 * - the tree does not contain any leaf matching the
	 *   key, and we have new->key < old->key. We insert
	 *   new above old, on the left ;
	 *
	 * - the tree does not contain any leaf matching the
	 *   key, and we have new->key > old->key. We insert
	 *   new above old, on the right ;
	 *
	 * - the tree does contain the key with the same prefix
	 *   length. We add the new key next to it as a first
	 *   duplicate (since it was alone).
	 *
	 * The last two cases can easily be partially merged.
	 *
	 * - the tree contains a leaf matching the key, we have
	 *   to insert above it as a cover node. The leaf with
	 *   the shortest prefix becomes the left subtree and
	 *   the leaf with the longest prefix becomes the right
	 *   one. The cover node gets the min of both prefixes
	 *   as its new bit.
	 */

	/* first we want to ensure that we compare the correct bit, which means
	 * the largest common to both nodes.
	 */
	if (bit > new->node.pfx)
		bit = new->node.pfx;
	if (bit > old->node.pfx)
		bit = old->node.pfx;

	new->node.bit = (bit << 1) + 1; /* assume normal node by default */

	/* if one prefix is included in the second one, we don't compare bits
	 * because they won't necessarily match, we just proceed with a cover
	 * node insertion.
	 */
	diff = 0;
	if (bit < old->node.pfx && bit < new->node.pfx)
		diff = cmp_bits(new->key, old->key, bit);

	if (diff == 0) {
		/* Both keys match. Either it's a duplicate entry or we have to
		 * put the shortest prefix left and the largest one right below
		 * a new cover node. By default, diff==0 means we'll be inserted
		 * on the right.
		 */
		new->node.bit--; /* anticipate cover node insertion */
		if (new->node.pfx == old->node.pfx) {
			new->node.bit = -1; /* mark as new dup tree, just in case */

			if (unlikely(eb_gettag(root_right))) {
				/* we refuse to duplicate this key if the tree is
				 * tagged as containing only unique keys.
				 */
				return old;
			}

			if (eb_gettag(troot) != EB_LEAF) {
				/* there was already a dup tree below */
				struct eb_node *ret;
				ret = eb_insert_dup(&old->node, &new->node);
				return container_of(ret, struct ebmb_node, node);
			}
			/* otherwise fall through to insert first duplicate */
		}
		/* otherwise we just rely on the tests below to select the right side */
		else if (new->node.pfx < old->node.pfx)
			diff = -1; /* force insertion to left side */
	}

 insert_above:
	new_left = eb_dotag(&new->node.branches, EB_LEFT);
	new_rght = eb_dotag(&new->node.branches, EB_RGHT);
	new_leaf = eb_dotag(&new->node.branches, EB_LEAF);

	if (diff >= 0) {
		new->node.branches.b[EB_LEFT] = troot;
		new->node.branches.b[EB_RGHT] = new_leaf;
		new->node.leaf_p = new_rght;
		*up_ptr = new_left;
	}
	else {
		new->node.branches.b[EB_LEFT] = new_leaf;
		new->node.branches.b[EB_RGHT] = troot;
		new->node.leaf_p = new_left;
		*up_ptr = new_rght;
	}

	root->b[side] = eb_dotag(&new->node.branches, EB_NODE);
	return new;
}



#endif /* _EBMBTREE_H */

