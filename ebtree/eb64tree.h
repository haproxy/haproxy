/*
 * Elastic Binary Trees - macros and structures for operations on 64bit nodes.
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

#ifndef _EB64TREE_H
#define _EB64TREE_H

#include "ebtree.h"


/* Return the structure of type <type> whose member <member> points to <ptr> */
#define eb64_entry(ptr, type, member) container_of(ptr, type, member)

#define EB64_ROOT	EB_ROOT
#define EB64_TREE_HEAD	EB_TREE_HEAD

/* These types may sometimes already be defined */
typedef unsigned long long u64;
typedef   signed long long s64;

/* This structure carries a node, a leaf, and a key. It must start with the
 * eb_node so that it can be cast into an eb_node. We could also have put some
 * sort of transparent union here to reduce the indirection level, but the fact
 * is, the end user is not meant to manipulate internals, so this is pointless.
 */
struct eb64_node {
	struct eb_node node; /* the tree node, must be at the beginning */
	u64 key;
};

/*
 * Exported functions and macros.
 * Many of them are always inlined because they are extremely small, and
 * are generally called at most once or twice in a program.
 */

/* Return leftmost node in the tree, or NULL if none */
static inline struct eb64_node *eb64_first(struct eb_root *root)
{
	return eb64_entry(eb_first(root), struct eb64_node, node);
}

/* Return rightmost node in the tree, or NULL if none */
static inline struct eb64_node *eb64_last(struct eb_root *root)
{
	return eb64_entry(eb_last(root), struct eb64_node, node);
}

/* Return next node in the tree, or NULL if none */
static inline struct eb64_node *eb64_next(struct eb64_node *eb64)
{
	return eb64_entry(eb_next(&eb64->node), struct eb64_node, node);
}

/* Return previous node in the tree, or NULL if none */
static inline struct eb64_node *eb64_prev(struct eb64_node *eb64)
{
	return eb64_entry(eb_prev(&eb64->node), struct eb64_node, node);
}

/* Return next leaf node within a duplicate sub-tree, or NULL if none. */
static inline struct eb64_node *eb64_next_dup(struct eb64_node *eb64)
{
	return eb64_entry(eb_next_dup(&eb64->node), struct eb64_node, node);
}

/* Return previous leaf node within a duplicate sub-tree, or NULL if none. */
static inline struct eb64_node *eb64_prev_dup(struct eb64_node *eb64)
{
	return eb64_entry(eb_prev_dup(&eb64->node), struct eb64_node, node);
}

/* Return next node in the tree, skipping duplicates, or NULL if none */
static inline struct eb64_node *eb64_next_unique(struct eb64_node *eb64)
{
	return eb64_entry(eb_next_unique(&eb64->node), struct eb64_node, node);
}

/* Return previous node in the tree, skipping duplicates, or NULL if none */
static inline struct eb64_node *eb64_prev_unique(struct eb64_node *eb64)
{
	return eb64_entry(eb_prev_unique(&eb64->node), struct eb64_node, node);
}

/* Delete node from the tree if it was linked in. Mark the node unused. Note
 * that this function relies on a non-inlined generic function: eb_delete.
 */
static inline void eb64_delete(struct eb64_node *eb64)
{
	eb_delete(&eb64->node);
}

/*
 * The following functions are not inlined by default. They are declared
 * in eb64tree.c, which simply relies on their inline version.
 */
REGPRM2 struct eb64_node *eb64_lookup(struct eb_root *root, u64 x);
REGPRM2 struct eb64_node *eb64i_lookup(struct eb_root *root, s64 x);
REGPRM2 struct eb64_node *eb64_lookup_le(struct eb_root *root, u64 x);
REGPRM2 struct eb64_node *eb64_lookup_ge(struct eb_root *root, u64 x);
REGPRM2 struct eb64_node *eb64_insert(struct eb_root *root, struct eb64_node *new);
REGPRM2 struct eb64_node *eb64i_insert(struct eb_root *root, struct eb64_node *new);

/*
 * The following functions are less likely to be used directly, because their
 * code is larger. The non-inlined version is preferred.
 */

/* Delete node from the tree if it was linked in. Mark the node unused. */
static forceinline void __eb64_delete(struct eb64_node *eb64)
{
	__eb_delete(&eb64->node);
}

/*
 * Find the first occurence of a key in the tree <root>. If none can be
 * found, return NULL.
 */
static forceinline struct eb64_node *__eb64_lookup(struct eb_root *root, u64 x)
{
	struct eb64_node *node;
	eb_troot_t *troot;
	u64 y;

	troot = root->b[EB_LEFT];
	if (unlikely(troot == NULL))
		return NULL;

	while (1) {
		if ((eb_gettag(troot) == EB_LEAF)) {
			node = container_of(eb_untag(troot, EB_LEAF),
					    struct eb64_node, node.branches);
			if (node->key == x)
				return node;
			else
				return NULL;
		}
		node = container_of(eb_untag(troot, EB_NODE),
				    struct eb64_node, node.branches);

		y = node->key ^ x;
		if (!y) {
			/* Either we found the node which holds the key, or
			 * we have a dup tree. In the later case, we have to
			 * walk it down left to get the first entry.
			 */
			if (node->node.bit < 0) {
				troot = node->node.branches.b[EB_LEFT];
				while (eb_gettag(troot) != EB_LEAF)
					troot = (eb_untag(troot, EB_NODE))->b[EB_LEFT];
				node = container_of(eb_untag(troot, EB_LEAF),
						    struct eb64_node, node.branches);
			}
			return node;
		}

		if ((y >> node->node.bit) >= EB_NODE_BRANCHES)
			return NULL; /* no more common bits */

		troot = node->node.branches.b[(x >> node->node.bit) & EB_NODE_BRANCH_MASK];
	}
}

/*
 * Find the first occurence of a signed key in the tree <root>. If none can
 * be found, return NULL.
 */
static forceinline struct eb64_node *__eb64i_lookup(struct eb_root *root, s64 x)
{
	struct eb64_node *node;
	eb_troot_t *troot;
	u64 key = x ^ (1ULL << 63);
	u64 y;

	troot = root->b[EB_LEFT];
	if (unlikely(troot == NULL))
		return NULL;

	while (1) {
		if ((eb_gettag(troot) == EB_LEAF)) {
			node = container_of(eb_untag(troot, EB_LEAF),
					    struct eb64_node, node.branches);
			if (node->key == (u64)x)
				return node;
			else
				return NULL;
		}
		node = container_of(eb_untag(troot, EB_NODE),
				    struct eb64_node, node.branches);

		y = node->key ^ x;
		if (!y) {
			/* Either we found the node which holds the key, or
			 * we have a dup tree. In the later case, we have to
			 * walk it down left to get the first entry.
			 */
			if (node->node.bit < 0) {
				troot = node->node.branches.b[EB_LEFT];
				while (eb_gettag(troot) != EB_LEAF)
					troot = (eb_untag(troot, EB_NODE))->b[EB_LEFT];
				node = container_of(eb_untag(troot, EB_LEAF),
						    struct eb64_node, node.branches);
			}
			return node;
		}

		if ((y >> node->node.bit) >= EB_NODE_BRANCHES)
			return NULL; /* no more common bits */

		troot = node->node.branches.b[(key >> node->node.bit) & EB_NODE_BRANCH_MASK];
	}
}

/* Insert eb64_node <new> into subtree starting at node root <root>.
 * Only new->key needs be set with the key. The eb64_node is returned.
 * If root->b[EB_RGHT]==1, the tree may only contain unique keys.
 */
static forceinline struct eb64_node *
__eb64_insert(struct eb_root *root, struct eb64_node *new) {
	struct eb64_node *old;
	unsigned int side;
	eb_troot_t *troot;
	u64 newkey; /* caching the key saves approximately one cycle */
	eb_troot_t *root_right;
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
	 * was attached. <newkey> carries the key being inserted.
	 */
	newkey = new->key;

	while (1) {
		if (unlikely(eb_gettag(troot) == EB_LEAF)) {
			eb_troot_t *new_left, *new_rght;
			eb_troot_t *new_leaf, *old_leaf;

			old = container_of(eb_untag(troot, EB_LEAF),
					    struct eb64_node, node.branches);

			new_left = eb_dotag(&new->node.branches, EB_LEFT);
			new_rght = eb_dotag(&new->node.branches, EB_RGHT);
			new_leaf = eb_dotag(&new->node.branches, EB_LEAF);
			old_leaf = eb_dotag(&old->node.branches, EB_LEAF);

			new->node.node_p = old->node.leaf_p;

			/* Right here, we have 3 possibilities :
			   - the tree does not contain the key, and we have
			     new->key < old->key. We insert new above old, on
			     the left ;

			   - the tree does not contain the key, and we have
			     new->key > old->key. We insert new above old, on
			     the right ;

			   - the tree does contain the key, which implies it
			     is alone. We add the new key next to it as a
			     first duplicate.

			   The last two cases can easily be partially merged.
			*/
			 
			if (new->key < old->key) {
				new->node.leaf_p = new_left;
				old->node.leaf_p = new_rght;
				new->node.branches.b[EB_LEFT] = new_leaf;
				new->node.branches.b[EB_RGHT] = old_leaf;
			} else {
				/* we may refuse to duplicate this key if the tree is
				 * tagged as containing only unique keys.
				 */
				if ((new->key == old->key) && eb_gettag(root_right))
					return old;

				/* new->key >= old->key, new goes the right */
				old->node.leaf_p = new_left;
				new->node.leaf_p = new_rght;
				new->node.branches.b[EB_LEFT] = old_leaf;
				new->node.branches.b[EB_RGHT] = new_leaf;

				if (new->key == old->key) {
					new->node.bit = -1;
					root->b[side] = eb_dotag(&new->node.branches, EB_NODE);
					return new;
				}
			}
			break;
		}

		/* OK we're walking down this link */
		old = container_of(eb_untag(troot, EB_NODE),
				    struct eb64_node, node.branches);
		old_node_bit = old->node.bit;

		/* Stop going down when we don't have common bits anymore. We
		 * also stop in front of a duplicates tree because it means we
		 * have to insert above.
		 */

		if ((old_node_bit < 0) || /* we're above a duplicate tree, stop here */
		    (((new->key ^ old->key) >> old_node_bit) >= EB_NODE_BRANCHES)) {
			/* The tree did not contain the key, so we insert <new> before the node
			 * <old>, and set ->bit to designate the lowest bit position in <new>
			 * which applies to ->branches.b[].
			 */
			eb_troot_t *new_left, *new_rght;
			eb_troot_t *new_leaf, *old_node;

			new_left = eb_dotag(&new->node.branches, EB_LEFT);
			new_rght = eb_dotag(&new->node.branches, EB_RGHT);
			new_leaf = eb_dotag(&new->node.branches, EB_LEAF);
			old_node = eb_dotag(&old->node.branches, EB_NODE);

			new->node.node_p = old->node.node_p;

			if (new->key < old->key) {
				new->node.leaf_p = new_left;
				old->node.node_p = new_rght;
				new->node.branches.b[EB_LEFT] = new_leaf;
				new->node.branches.b[EB_RGHT] = old_node;
			}
			else if (new->key > old->key) {
				old->node.node_p = new_left;
				new->node.leaf_p = new_rght;
				new->node.branches.b[EB_LEFT] = old_node;
				new->node.branches.b[EB_RGHT] = new_leaf;
			}
			else {
				struct eb_node *ret;
				ret = eb_insert_dup(&old->node, &new->node);
				return container_of(ret, struct eb64_node, node);
			}
			break;
		}

		/* walk down */
		root = &old->node.branches;
#if BITS_PER_LONG >= 64
		side = (newkey >> old_node_bit) & EB_NODE_BRANCH_MASK;
#else
		side = newkey;
		side >>= old_node_bit;
		if (old_node_bit >= 32) {
			side = newkey >> 32;
			side >>= old_node_bit & 0x1F;
		}
		side &= EB_NODE_BRANCH_MASK;
#endif
		troot = root->b[side];
	}

	/* Ok, now we are inserting <new> between <root> and <old>. <old>'s
	 * parent is already set to <new>, and the <root>'s branch is still in
	 * <side>. Update the root's leaf till we have it. Note that we can also
	 * find the side by checking the side of new->node.node_p.
	 */

	/* We need the common higher bits between new->key and old->key.
	 * What differences are there between new->key and the node here ?
	 * NOTE that bit(new) is always < bit(root) because highest
	 * bit of new->key and old->key are identical here (otherwise they
	 * would sit on different branches).
	 */
	// note that if EB_NODE_BITS > 1, we should check that it's still >= 0
	new->node.bit = fls64(new->key ^ old->key) - EB_NODE_BITS;
	root->b[side] = eb_dotag(&new->node.branches, EB_NODE);

	return new;
}

/* Insert eb64_node <new> into subtree starting at node root <root>, using
 * signed keys. Only new->key needs be set with the key. The eb64_node
 * is returned. If root->b[EB_RGHT]==1, the tree may only contain unique keys.
 */
static forceinline struct eb64_node *
__eb64i_insert(struct eb_root *root, struct eb64_node *new) {
	struct eb64_node *old;
	unsigned int side;
	eb_troot_t *troot;
	u64 newkey; /* caching the key saves approximately one cycle */
	eb_troot_t *root_right;
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
	 * was attached. <newkey> carries a high bit shift of the key being
	 * inserted in order to have negative keys stored before positive
	 * ones.
	 */
	newkey = new->key ^ (1ULL << 63);

	while (1) {
		if (unlikely(eb_gettag(troot) == EB_LEAF)) {
			eb_troot_t *new_left, *new_rght;
			eb_troot_t *new_leaf, *old_leaf;

			old = container_of(eb_untag(troot, EB_LEAF),
					    struct eb64_node, node.branches);

			new_left = eb_dotag(&new->node.branches, EB_LEFT);
			new_rght = eb_dotag(&new->node.branches, EB_RGHT);
			new_leaf = eb_dotag(&new->node.branches, EB_LEAF);
			old_leaf = eb_dotag(&old->node.branches, EB_LEAF);

			new->node.node_p = old->node.leaf_p;

			/* Right here, we have 3 possibilities :
			   - the tree does not contain the key, and we have
			     new->key < old->key. We insert new above old, on
			     the left ;

			   - the tree does not contain the key, and we have
			     new->key > old->key. We insert new above old, on
			     the right ;

			   - the tree does contain the key, which implies it
			     is alone. We add the new key next to it as a
			     first duplicate.

			   The last two cases can easily be partially merged.
			*/
			 
			if ((s64)new->key < (s64)old->key) {
				new->node.leaf_p = new_left;
				old->node.leaf_p = new_rght;
				new->node.branches.b[EB_LEFT] = new_leaf;
				new->node.branches.b[EB_RGHT] = old_leaf;
			} else {
				/* we may refuse to duplicate this key if the tree is
				 * tagged as containing only unique keys.
				 */
				if ((new->key == old->key) && eb_gettag(root_right))
					return old;

				/* new->key >= old->key, new goes the right */
				old->node.leaf_p = new_left;
				new->node.leaf_p = new_rght;
				new->node.branches.b[EB_LEFT] = old_leaf;
				new->node.branches.b[EB_RGHT] = new_leaf;

				if (new->key == old->key) {
					new->node.bit = -1;
					root->b[side] = eb_dotag(&new->node.branches, EB_NODE);
					return new;
				}
			}
			break;
		}

		/* OK we're walking down this link */
		old = container_of(eb_untag(troot, EB_NODE),
				    struct eb64_node, node.branches);
		old_node_bit = old->node.bit;

		/* Stop going down when we don't have common bits anymore. We
		 * also stop in front of a duplicates tree because it means we
		 * have to insert above.
		 */

		if ((old_node_bit < 0) || /* we're above a duplicate tree, stop here */
		    (((new->key ^ old->key) >> old_node_bit) >= EB_NODE_BRANCHES)) {
			/* The tree did not contain the key, so we insert <new> before the node
			 * <old>, and set ->bit to designate the lowest bit position in <new>
			 * which applies to ->branches.b[].
			 */
			eb_troot_t *new_left, *new_rght;
			eb_troot_t *new_leaf, *old_node;

			new_left = eb_dotag(&new->node.branches, EB_LEFT);
			new_rght = eb_dotag(&new->node.branches, EB_RGHT);
			new_leaf = eb_dotag(&new->node.branches, EB_LEAF);
			old_node = eb_dotag(&old->node.branches, EB_NODE);

			new->node.node_p = old->node.node_p;

			if ((s64)new->key < (s64)old->key) {
				new->node.leaf_p = new_left;
				old->node.node_p = new_rght;
				new->node.branches.b[EB_LEFT] = new_leaf;
				new->node.branches.b[EB_RGHT] = old_node;
			}
			else if ((s64)new->key > (s64)old->key) {
				old->node.node_p = new_left;
				new->node.leaf_p = new_rght;
				new->node.branches.b[EB_LEFT] = old_node;
				new->node.branches.b[EB_RGHT] = new_leaf;
			}
			else {
				struct eb_node *ret;
				ret = eb_insert_dup(&old->node, &new->node);
				return container_of(ret, struct eb64_node, node);
			}
			break;
		}

		/* walk down */
		root = &old->node.branches;
#if BITS_PER_LONG >= 64
		side = (newkey >> old_node_bit) & EB_NODE_BRANCH_MASK;
#else
		side = newkey;
		side >>= old_node_bit;
		if (old_node_bit >= 32) {
			side = newkey >> 32;
			side >>= old_node_bit & 0x1F;
		}
		side &= EB_NODE_BRANCH_MASK;
#endif
		troot = root->b[side];
	}

	/* Ok, now we are inserting <new> between <root> and <old>. <old>'s
	 * parent is already set to <new>, and the <root>'s branch is still in
	 * <side>. Update the root's leaf till we have it. Note that we can also
	 * find the side by checking the side of new->node.node_p.
	 */

	/* We need the common higher bits between new->key and old->key.
	 * What differences are there between new->key and the node here ?
	 * NOTE that bit(new) is always < bit(root) because highest
	 * bit of new->key and old->key are identical here (otherwise they
	 * would sit on different branches).
	 */
	// note that if EB_NODE_BITS > 1, we should check that it's still >= 0
	new->node.bit = fls64(new->key ^ old->key) - EB_NODE_BITS;
	root->b[side] = eb_dotag(&new->node.branches, EB_NODE);

	return new;
}

#endif /* _EB64_TREE_H */
