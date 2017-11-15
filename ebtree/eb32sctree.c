/*
 * Elastic Binary Trees - exported functions for operations on 32bit nodes.
 * Version 6.0.6 with backports from v7-dev
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

/* Consult eb32sctree.h for more details about those functions */

#include "eb32sctree.h"


/* This function is used to build a tree of duplicates by adding a new node to
 * a subtree of at least 2 entries.
 */
REGPRM1 struct eb32sc_node *eb32sc_insert_dup(struct eb_node *sub, struct eb_node *new, unsigned long scope)
{
	struct eb32sc_node *eb32;
	struct eb_node *head = sub;
	eb_troot_t *new_left = eb_dotag(&new->branches, EB_LEFT);
	eb_troot_t *new_rght = eb_dotag(&new->branches, EB_RGHT);
	eb_troot_t *new_leaf = eb_dotag(&new->branches, EB_LEAF);

	/* first, identify the deepest hole on the right branch */
	while (eb_gettag(head->branches.b[EB_RGHT]) != EB_LEAF) {
		struct eb_node *last = head;

		head = container_of(eb_untag(head->branches.b[EB_RGHT], EB_NODE),
				    struct eb_node, branches);

		if (unlikely(head->bit > last->bit + 1)) {
			/* there's a hole here, we must assign the top of the
			 * following sub-tree to <sub> and mark all intermediate
			 * nodes with the scope mask.
			 */
			do {
				eb32 = container_of(sub, struct eb32sc_node, node);
				if (!(eb32->node_s & scope))
					eb32->node_s |= scope;

				sub = container_of(eb_untag(sub->branches.b[EB_RGHT], EB_NODE),
				                   struct eb_node, branches);
			} while (sub != head);
		}

		eb32 = container_of(head, struct eb32sc_node, node);
		if (!(eb32->node_s & scope))
			eb32->node_s |= scope;
	}

	/* Here we have a leaf attached to (head)->b[EB_RGHT] */
	if (head->bit < -1) {
		/* A hole exists just before the leaf, we insert there */
		new->bit = -1;
		sub = container_of(eb_untag(head->branches.b[EB_RGHT], EB_LEAF),
				   struct eb_node, branches);
		head->branches.b[EB_RGHT] = eb_dotag(&new->branches, EB_NODE);

		new->node_p = sub->leaf_p;
		new->leaf_p = new_rght;
		sub->leaf_p = new_left;
		new->branches.b[EB_LEFT] = eb_dotag(&sub->branches, EB_LEAF);
		new->branches.b[EB_RGHT] = new_leaf;
		eb32 = container_of(new, struct eb32sc_node, node);
		eb32->node_s = container_of(sub, struct eb32sc_node, node)->leaf_s | scope;
		return eb32;
	} else {
		int side;
		/* No hole was found before a leaf. We have to insert above
		 * <sub>. Note that we cannot be certain that <sub> is attached
		 * to the right of its parent, as this is only true if <sub>
		 * is inside the dup tree, not at the head.
		 */
		new->bit = sub->bit - 1; /* install at the lowest level */
		side = eb_gettag(sub->node_p);
		head = container_of(eb_untag(sub->node_p, side), struct eb_node, branches);
		head->branches.b[side] = eb_dotag(&new->branches, EB_NODE);

		new->node_p = sub->node_p;
		new->leaf_p = new_rght;
		sub->node_p = new_left;
		new->branches.b[EB_LEFT] = eb_dotag(&sub->branches, EB_NODE);
		new->branches.b[EB_RGHT] = new_leaf;
		eb32 = container_of(new, struct eb32sc_node, node);
		eb32->node_s = container_of(sub, struct eb32sc_node, node)->node_s | scope;
		return eb32;
	}
}

/* Insert eb32sc_node <new> into subtree starting at node root <root>. Only
 * new->key needs be set with the key. The eb32sc_node is returned. This
 * implementation does NOT support unique trees.
 */
REGPRM2 struct eb32sc_node *eb32sc_insert(struct eb_root *root, struct eb32sc_node *new, unsigned long scope)
{
	struct eb32sc_node *old;
	unsigned int side;
	eb_troot_t *troot, **up_ptr;
	u32 newkey; /* caching the key saves approximately one cycle */
	eb_troot_t *new_left, *new_rght;
	eb_troot_t *new_leaf;
	int old_node_bit;
	unsigned long old_scope;

	side = EB_LEFT;
	troot = root->b[EB_LEFT];
	if (unlikely(troot == NULL)) {
		/* Tree is empty, insert the leaf part below the left branch */
		root->b[EB_LEFT] = eb_dotag(&new->node.branches, EB_LEAF);
		new->node.leaf_p = eb_dotag(root, EB_LEFT);
		new->node.node_p = NULL; /* node part unused */
		new->node_s = scope;
		new->leaf_s = scope;
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
		if (eb_gettag(troot) == EB_LEAF) {
			/* insert above a leaf */
			old = container_of(eb_untag(troot, EB_LEAF),
					    struct eb32sc_node, node.branches);
			new->node.node_p = old->node.leaf_p;
			up_ptr = &old->node.leaf_p;
			old_scope = old->leaf_s;
			break;
		}

		/* OK we're walking down this link */
		old = container_of(eb_untag(troot, EB_NODE),
				    struct eb32sc_node, node.branches);
		old_node_bit = old->node.bit;

		/* our new node will be found through this one, we must mark it */
		if ((old->node_s | scope) != old->node_s)
			old->node_s |= scope;

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
			new->node.node_p = old->node.node_p;
			up_ptr = &old->node.node_p;
			old_scope = old->node_s;
			break;
		}

		/* walk down */
		root = &old->node.branches;
		side = (newkey >> old_node_bit) & EB_NODE_BRANCH_MASK;
		troot = root->b[side];
	}

	new_left = eb_dotag(&new->node.branches, EB_LEFT);
	new_rght = eb_dotag(&new->node.branches, EB_RGHT);
	new_leaf = eb_dotag(&new->node.branches, EB_LEAF);

	/* We need the common higher bits between new->key and old->key.
	 * What differences are there between new->key and the node here ?
	 * NOTE that bit(new) is always < bit(root) because highest
	 * bit of new->key and old->key are identical here (otherwise they
	 * would sit on different branches).
	 */

	// note that if EB_NODE_BITS > 1, we should check that it's still >= 0
	new->node.bit = flsnz(new->key ^ old->key) - EB_NODE_BITS;
	new->leaf_s = scope;
	new->node_s = old_scope | scope;

	if (new->key == old->key) {
		new->node.bit = -1; /* mark as new dup tree, just in case */

		if (eb_gettag(troot) != EB_LEAF) {
			/* there was already a dup tree below */
			return eb32sc_insert_dup(&old->node, &new->node, scope);
		}
		/* otherwise fall through */
	}

	if (new->key >= old->key) {
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

	/* Ok, now we are inserting <new> between <root> and <old>. <old>'s
	 * parent is already set to <new>, and the <root>'s branch is still in
	 * <side>. Update the root's leaf till we have it. Note that we can also
	 * find the side by checking the side of new->node.node_p.
	 */

	root->b[side] = eb_dotag(&new->node.branches, EB_NODE);
	return new;
}

/*
 * Find the first occurrence of the lowest key in the tree <root>, which is
 * equal to or greater than <x>. NULL is returned is no key matches.
 */
REGPRM2 struct eb32sc_node *eb32sc_lookup_ge(struct eb_root *root, u32 x, unsigned long scope)
{
	struct eb32sc_node *node;
	eb_troot_t *troot;

	troot = root->b[EB_LEFT];
	if (unlikely(troot == NULL))
		return NULL;

	while (1) {
		if ((eb_gettag(troot) == EB_LEAF)) {
			/* We reached a leaf, which means that the whole upper
			 * parts were common. We will return either the current
			 * node or its next one if the former is too small.
			 */
			node = container_of(eb_untag(troot, EB_LEAF),
					    struct eb32sc_node, node.branches);
			if ((node->leaf_s & scope) && node->key >= x)
				return node;
			/* return next */
			troot = node->node.leaf_p;
			break;
		}
		node = container_of(eb_untag(troot, EB_NODE),
				    struct eb32sc_node, node.branches);

		if (node->node.bit < 0) {
			/* We're at the top of a dup tree. Either we got a
			 * matching value and we return the leftmost node, or
			 * we don't and we skip the whole subtree to return the
			 * next node after the subtree. Note that since we're
			 * at the top of the dup tree, we can simply return the
			 * next node without first trying to escape from the
			 * tree.
			 */
			if ((node->node_s & scope) && node->key >= x)
				troot = eb_dotag(&node->node.branches, EB_LEFT);
			else
				troot = node->node.node_p;
			break;
		}

		if (((x ^ node->key) >> node->node.bit) >= EB_NODE_BRANCHES) {
			/* No more common bits at all. Either this node is too
			 * large and we need to get its lowest value, or it is too
			 * small, and we need to get the next value.
			 */
			if ((node->node_s & scope) && (node->key >> node->node.bit) > (x >> node->node.bit))
				troot = eb_dotag(&node->node.branches, EB_LEFT);
			else
				troot = node->node.node_p;
			break;
		}
		troot = node->node.branches.b[(x >> node->node.bit) & EB_NODE_BRANCH_MASK];
	}

	/* If we get here, it means we want to report next node after the
	 * current one which is not below. <troot> is already initialised
	 * to the parent's branches.
	 */
	return eb32sc_next_with_parent(troot, scope);
}

/*
 * Find the first occurrence of the lowest key in the tree <root> which is
 * equal to or greater than <x>, matching scope <scope>. If not found, it loops
 * back to the beginning of the tree. NULL is returned is no key matches.
 */
REGPRM2 struct eb32sc_node *eb32sc_lookup_ge_or_first(struct eb_root *root, u32 x, unsigned long scope)
{
	struct eb32sc_node *eb32;
	eb_troot_t *troot;

	troot = root->b[EB_LEFT];
	if (unlikely(troot == NULL))
		return NULL;

	while (1) {
		if ((eb_gettag(troot) == EB_LEAF)) {
			/* We reached a leaf, which means that the whole upper
			 * parts were common. We will return either the current
			 * node or its next one if the former is too small.
			 */
			eb32 = container_of(eb_untag(troot, EB_LEAF),
					    struct eb32sc_node, node.branches);
			if ((eb32->leaf_s & scope) && eb32->key >= x)
				return eb32;
			/* return next */
			troot = eb32->node.leaf_p;
			break;
		}
		eb32 = container_of(eb_untag(troot, EB_NODE),
				    struct eb32sc_node, node.branches);

		if (eb32->node.bit < 0) {
			/* We're at the top of a dup tree. Either we got a
			 * matching value and we return the leftmost node, or
			 * we don't and we skip the whole subtree to return the
			 * next node after the subtree. Note that since we're
			 * at the top of the dup tree, we can simply return the
			 * next node without first trying to escape from the
			 * tree.
			 */
			if ((eb32->node_s & scope) && eb32->key >= x)
				troot = eb_dotag(&eb32->node.branches, EB_LEFT);
			else
				troot = eb32->node.node_p;
			break;
		}

		if (((x ^ eb32->key) >> eb32->node.bit) >= EB_NODE_BRANCHES) {
			/* No more common bits at all. Either this node is too
			 * large and we need to get its lowest value, or it is too
			 * small, and we need to get the next value.
			 */
			if ((eb32->node_s & scope) && (eb32->key >> eb32->node.bit) > (x >> eb32->node.bit))
				troot = eb_dotag(&eb32->node.branches, EB_LEFT);
			else
				troot = eb32->node.node_p;
			break;
		}
		troot = eb32->node.branches.b[(x >> eb32->node.bit) & EB_NODE_BRANCH_MASK];
	}

	/* If we get here, it means we want to report next node after the
	 * current one which is not below. <troot> is already initialised
	 * to the parent's branches.
	 */
	eb32 = eb32sc_next_with_parent(troot, scope);
	if (!eb32)
		eb32 = eb32sc_walk_down_left(root->b[EB_LEFT], scope);

	return eb32;
}

/* Removes a leaf node from the tree if it was still in it. Marks the node
 * as unlinked.
 */
void eb32sc_delete(struct eb32sc_node *eb32)
{
	struct eb_node *node = &eb32->node;
	unsigned int pside, gpside, sibtype;
	struct eb_node *parent;
	struct eb_root *gparent;
	unsigned long scope;

	if (!node->leaf_p)
		return;

	/* we need the parent, our side, and the grand parent */
	pside = eb_gettag(node->leaf_p);
	parent = eb_root_to_node(eb_untag(node->leaf_p, pside));

	/* We likely have to release the parent link, unless it's the root,
	 * in which case we only set our branch to NULL. Note that we can
	 * only be attached to the root by its left branch.
	 */

	if (eb_clrtag(parent->branches.b[EB_RGHT]) == NULL) {
		/* we're just below the root, it's trivial. */
		parent->branches.b[EB_LEFT] = NULL;
		goto delete_unlink;
	}

	/* To release our parent, we have to identify our sibling, and reparent
	 * it directly to/from the grand parent. Note that the sibling can
	 * either be a link or a leaf.
	 */

	gpside = eb_gettag(parent->node_p);
	gparent = eb_untag(parent->node_p, gpside);

	gparent->b[gpside] = parent->branches.b[!pside];
	sibtype = eb_gettag(gparent->b[gpside]);

	if (sibtype == EB_LEAF) {
		eb_root_to_node(eb_untag(gparent->b[gpside], EB_LEAF))->leaf_p =
			eb_dotag(gparent, gpside);
	} else {
		eb_root_to_node(eb_untag(gparent->b[gpside], EB_NODE))->node_p =
			eb_dotag(gparent, gpside);
	}
	/* Mark the parent unused. Note that we do not check if the parent is
	 * our own node, but that's not a problem because if it is, it will be
	 * marked unused at the same time, which we'll use below to know we can
	 * safely remove it.
	 */
	parent->node_p = NULL;

	/* The parent node has been detached, and is currently unused. It may
	 * belong to another node, so we cannot remove it that way. Also, our
	 * own node part might still be used. so we can use this spare node
	 * to replace ours if needed.
	 */

	/* If our link part is unused, we can safely exit now */
	if (!node->node_p)
		goto delete_unlink;

	/* From now on, <node> and <parent> are necessarily different, and the
	 * <node>'s node part is in use. By definition, <parent> is at least
	 * below <node>, so keeping its key for the bit string is OK. However
	 * its scope must be enlarged to cover the new branch it absorbs.
	 */

	parent->node_p = node->node_p;
	parent->branches = node->branches;
	parent->bit = node->bit;

	/* We must now update the new node's parent... */
	gpside = eb_gettag(parent->node_p);
	gparent = eb_untag(parent->node_p, gpside);
	gparent->b[gpside] = eb_dotag(&parent->branches, EB_NODE);

	/* ... and its branches */
	scope = 0;
	for (pside = 0; pside <= 1; pside++) {
		if (eb_gettag(parent->branches.b[pside]) == EB_NODE) {
			eb_root_to_node(eb_untag(parent->branches.b[pside], EB_NODE))->node_p =
				eb_dotag(&parent->branches, pside);
			scope |= container_of(eb_untag(parent->branches.b[pside], EB_NODE), struct eb32sc_node, node.branches)->node_s;
		} else {
			eb_root_to_node(eb_untag(parent->branches.b[pside], EB_LEAF))->leaf_p =
				eb_dotag(&parent->branches, pside);
			scope |= container_of(eb_untag(parent->branches.b[pside], EB_LEAF), struct eb32sc_node, node.branches)->leaf_s;
		}
	}
	container_of(parent, struct eb32sc_node, node)->node_s = scope;

 delete_unlink:
	/* Now the node has been completely unlinked */
	node->leaf_p = NULL;
	return; /* tree is not empty yet */
}
