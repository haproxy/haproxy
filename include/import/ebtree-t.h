/*
 * Elastic Binary Trees - types
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

#ifndef _EBTREE_T_H
#define _EBTREE_T_H

#include <haproxy/api-t.h>

/*
 * generic types for ebtree
 */

/* Number of bits per node, and number of leaves per node */
#define EB_NODE_BITS          1
#define EB_NODE_BRANCHES      (1 << EB_NODE_BITS)
#define EB_NODE_BRANCH_MASK   (EB_NODE_BRANCHES - 1)

/* Be careful not to tweak those values. The walking code is optimized for NULL
 * detection on the assumption that the following values are intact.
 */
#define EB_LEFT     0
#define EB_RGHT     1
#define EB_LEAF     0
#define EB_NODE     1

/* Tags to set in root->b[EB_RGHT] :
 * - EB_NORMAL is a normal tree which stores duplicate keys.
 * - EB_UNIQUE is a tree which stores unique keys.
 */
#define EB_NORMAL   0
#define EB_UNIQUE   1

/* This is the same as an eb_node pointer, except that the lower bit embeds
 * a tag. See eb_dotag()/eb_untag()/eb_gettag(). This tag has two meanings :
 *  - 0=left, 1=right to designate the parent's branch for leaf_p/node_p
 *  - 0=link, 1=leaf  to designate the branch's type for branch[]
 */
typedef void eb_troot_t;

/* The eb_root connects the node which contains it, to two nodes below it, one
 * of which may be the same node. At the top of the tree, we use an eb_root
 * too, which always has its right branch NULL (+/1 low-order bits).
 */
struct eb_root {
	eb_troot_t    *b[EB_NODE_BRANCHES]; /* left and right branches */
};

/* The eb_node contains the two parts, one for the leaf, which always exists,
 * and one for the node, which remains unused in the very first node inserted
 * into the tree. This structure is 20 bytes per node on 32-bit machines. Do
 * not change the order, benchmarks have shown that it's optimal this way.
 * Note: be careful about this struct's alignment if it gets included into
 * another struct and some atomic ops are expected on the keys or the node.
 */
struct eb_node {
	struct eb_root branches; /* branches, must be at the beginning */
	eb_troot_t    *node_p;  /* link node's parent */
	eb_troot_t    *leaf_p;  /* leaf node's parent */
	short int      bit;     /* link's bit position. */
	short unsigned int pfx; /* data prefix length, always related to leaf */
} __attribute__((packed));


/* The root of a tree is an eb_root initialized with both pointers NULL.
 * During its life, only the left pointer will change. The right one will
 * always remain NULL, which is the way we detect it.
 */
#define EB_ROOT						\
	(struct eb_root) {				\
		.b = {[0] = NULL, [1] = NULL },		\
	}

#define EB_ROOT_UNIQUE					\
	(struct eb_root) {				\
		.b = {[0] = NULL, [1] = (void *)1 },	\
	}

#define EB_TREE_HEAD(name)				\
	struct eb_root name = EB_ROOT


/*
 * types for eb32tree
 */

#define EB32_ROOT	EB_ROOT
#define EB32_TREE_HEAD	EB_TREE_HEAD

/* These types may sometimes already be defined */
typedef unsigned int u32;
typedef   signed int s32;

/* This structure carries a node, a leaf, and a key. It must start with the
 * eb_node so that it can be cast into an eb_node. We could also have put some
 * sort of transparent union here to reduce the indirection level, but the fact
 * is, the end user is not meant to manipulate internals, so this is pointless.
 */
struct eb32_node {
	struct eb_node node; /* the tree node, must be at the beginning */
	MAYBE_ALIGN(sizeof(u32));
	u32 key;
} ALIGNED(sizeof(void*));

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
 * types for eb64tree
 */

#define EB64_ROOT	EB_ROOT
#define EB64_TREE_HEAD	EB_TREE_HEAD

/* These types may sometimes already be defined */
typedef unsigned long long u64;
typedef   signed long long s64;

/* This structure carries a node, a leaf, and a key. It must start with the
 * eb_node so that it can be cast into an eb_node. We could also have put some
 * sort of transparent union here to reduce the indirection level, but the fact
 * is, the end user is not meant to manipulate internals, so this is pointless.
 * In case sizeof(void*)>=sizeof(u64), we know there will be some padding after
 * the key if it's unaligned. In this case we force the alignment on void* so
 * that we prefer to have the padding before for more efficient accesses.
 */
struct eb64_node {
	struct eb_node node; /* the tree node, must be at the beginning */
	MAYBE_ALIGN(sizeof(u64));
	ALWAYS_ALIGN(sizeof(void*));
	u64 key;
} ALIGNED(sizeof(void*));

#define EBPT_ROOT	EB_ROOT
#define EBPT_TREE_HEAD	EB_TREE_HEAD

/* on *almost* all platforms, a pointer can be cast into a size_t which is unsigned */
#ifndef PTR_INT_TYPE
#define PTR_INT_TYPE	size_t
#endif

/*
 * types for ebpttree
 */

typedef PTR_INT_TYPE ptr_t;

/* This structure carries a node, a leaf, and a key. It must start with the
 * eb_node so that it can be cast into an eb_node. We could also have put some
 * sort of transparent union here to reduce the indirection level, but the fact
 * is, the end user is not meant to manipulate internals, so this is pointless.
 * Internally, it is automatically cast as an eb32_node or eb64_node.
 * We always align the key since the struct itself will be padded to the same
 * size anyway.
 */
struct ebpt_node {
	struct eb_node node; /* the tree node, must be at the beginning */
	ALWAYS_ALIGN(sizeof(void*));
	void *key;
} ALIGNED(sizeof(void*));

/*
 * types for ebmbtree
 */

#define EBMB_ROOT	EB_ROOT
#define EBMB_TREE_HEAD	EB_TREE_HEAD

/* This structure carries a node, a leaf, and a key. It must start with the
 * eb_node so that it can be cast into an eb_node. We could also have put some
 * sort of transparent union here to reduce the indirection level, but the fact
 * is, the end user is not meant to manipulate internals, so this is pointless.
 * The 'node.bit' value here works differently from scalar types, as it contains
 * the number of identical bits between the two branches.
 * Note that we take a great care of making sure the key is located exactly at
 * the end of the struct even if that involves holes before it, so that it
 * always aliases any external key a user would append after. This is why the
 * key uses the same alignment as the struct.
 */
struct ebmb_node {
	struct eb_node node; /* the tree node, must be at the beginning */
	ALWAYS_ALIGN(sizeof(void*));
	unsigned char key[0]; /* the key, its size depends on the application */
} ALIGNED(sizeof(void*));

#endif /* _EB_TREE_T_H */
