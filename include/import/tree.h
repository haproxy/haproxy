/*
 * tree.h : tree manipulation macros and structures.
 * (C) 2002 - Willy Tarreau - willy@ant-computing.com
 *
 * 2007/05/13: adapted to mempools v2.
 *
 */

#ifndef __TREE_H__
#define __TREE_H__

#include <import/bitops.h>
#include <common/memory.h>

/* binary tree node : either 32 bits unsigned long int values, or
 * 64 bits in two 32 bits unsigned long int values
 */
struct ultree {
    unsigned long low;		/* 32 bits low value of this node */
    unsigned long high;		/* 32 bits high value of this node, not used in 32 bits */
    int level;			/* bit level of this node */
    void *data;			/* carried data */
    struct ultree *left, *right;	/* children : left and right. NULL = leaf */
    struct ultree *up;		/* parent node. NULL = root */
};

/* binary tree node : 64 bits unsigned long long values */
struct ulltree {
    unsigned long long value;	/* 64 bits value of this node */
    int level;			/* bit level of this node */
    void *data;			/* carried data */
    struct ulltree *left, *right;	/* children : left and right. NULL = leaf */
    struct ulltree *up;		/* parent node. NULL = root */
};

/* binary tree node : 64 bits in either one ull or two 32 bits unsigned long int values. This
 * is the common type for all the above trees, which should be cast into it. This makes
 * pool_free() far simpler since all types share a same pool.
 */
struct tree64 {
    union {
	struct {
	    unsigned long low;		/* 32 bits low value of this node */
	    unsigned long high;		/* 32 bits high value of this node */
	} ul;
	struct {
	    unsigned long long value;	/* 64 bits value of this node */
	} ull;
    } value;
    int level;				/* bit level of this node */
    void *data;				/* carried data */
    struct tree64 *left, *right;	/* children : left and right. NULL = leaf */
    struct tree64 *up;			/* parent node. NULL = root */
};

extern struct pool_head *pool2_tree64;

#define ULTREE_HEAD(l)		struct ultree (l) = { .left=NULL, .right=NULL, .up=NULL, .low=0, .level=LONGBITS, .data=NULL }
#define ULTREE_INIT(l)		{ (l)->data = (l)->left = (l)->right = NULL; }
#define ULTREE_INIT_ROOT(l)	{ (l)->left=(l)->right=(l)->up=(l)->data=NULL; (l)->low=0; (l)->level=LONGBITS; }

#define ULLTREE_HEAD(l)		struct ulltree (l) = { .left=NULL, .right=NULL, .up=NULL, .value=0, .level=LLONGBITS, .data=NULL }
#define ULLTREE_INIT(l)		{ (l)->data = (l)->left = (l)->right = NULL; }
#define ULLTREE_INIT_ROOT(l)	{ (l)->left=(l)->right=(l)->up=(l)->data=NULL; (l)->value=0; (l)->level=LLONGBITS; }

#define UL2TREE_HEAD(l)		struct ultree (l) = { .left=NULL, .right=NULL, .up=NULL, .high=0, .low=0, .level=LLONGBITS, .data=NULL }
#define UL2TREE_INIT(l)		{ (l)->left = (l)->right = (l)->data = NULL; }
#define UL2TREE_INIT_ROOT(l)	{ (l)->left=(l)->right=(l)->up=(l)->data=NULL; (l)->high=(l)->low=0; (l)->level=LLONGBITS; }

/*
 * inserts necessary nodes to reach <x> in tree starting at <root>. The node
 * is not created if it exists. It is returned.
 */
inline static struct ulltree *__ulltree_insert(struct ulltree *root, unsigned long long x) {
    int m;
    struct ulltree *next, *new, *node;
    struct ulltree **branch;
    int ffs;

    next = root;
    ffs = ffs_fast64(x);

    do {
	root = next;

	if (x == next->value) {
	    return next;
	}

	if (x & (1ULL << (next->level - 1))) { /* right branch */
	    branch = &next->right;
	    next = *branch;
	} else {
	    branch = &next->left;
	    next = *branch;
	}

	if (next == NULL) {
	    /* we'll have to insert our node here */
	    *branch = new = (struct ulltree *)pool_alloc2(pool2_tree64);
	    ULLTREE_INIT(new);
	    new->up = root;
	    new->value = x;
	    new->level = ffs;
	    return new;
	}

	/* we'll keep walking down as long as we have all bits in common */
    } while ((x & ~((1ULL << next->level) - 1)) == next->value);


    /* ok, now we know that we must insert between both. */

    /* the new interconnect node */
    *branch = node = (struct ulltree *)pool_alloc2(pool2_tree64); /* was <next> */
    ULLTREE_INIT(node);
    node->up = root;
    next->up = node;

    /* we need the common higher bits between x and next->value. */

    /* what differences are there between x and the node here ?
     * NOTE that m is always < level(parent) because highest bit
     * of x and next-value are identical here (else they would be
     * on a different branch).
     */
    m = fls_fast64(x ^ next->value) + 1; /* m = lowest identical bit */
    node->value = x & ~((1ULL << m) - 1); /* value of common bits */

    if (node->value == x) { /* <x> is exactly on this node */
	/* we must set its real position (eg: 8,10 => m=1 => val=8, m=3)*/
	node->level = ffs;

	if (next->value & (1ULL << (node->level - 1))) /* right branch */
	    node->right = next;
	else
	    node->left = next;
	return node;
    }

    /* the new leaf now */
    node->level = m; /* set the level to the lowest common bit */
    new = (struct ulltree *)pool_alloc2(pool2_tree64);
    ULLTREE_INIT(new);
    new->value = x;
    new->level = ffs;

    if (x > next->value) {
	node->left  = next;
	node->right = new;
    }
    else {
	node->left  = new;
	node->right = next;
    }
    new->up = node;
    return new;
}

/*
 * inserts necessary nodes to reach <x> in tree starting at <root>. The node
 * is not created if it exists. It is returned.
 */
inline static struct ultree *__ultree_insert(struct ultree *root, unsigned long x) {
    int m;
    struct ultree *next, *new, *node;
    struct ultree **branch;
    int ffs;

    next = root;
    ffs = ffs_fast32(x);

    do {
	root = next;

	if (x == next->low) {
	    return next;
	}

	if ((x >> (next->level - 1)) & 1) { /* right branch */
	    branch = &next->right;
	    next = *branch;
	} else {
	    branch = &next->left;
	    next = *branch;
	}

	if (next == NULL) {
	    /* we'll have to insert our node here */
	    *branch = new = (struct ultree *)pool_alloc2(pool2_tree64);
	    ULTREE_INIT(new);
	    new->up = root;
	    new->low = x;
	    new->level = ffs;
	    return new;
	}

	/* we'll keep walking down as long as we have all bits in common */
    } while ((x & ~((1 << next->level) - 1)) == next->low);

    /* ok, now we know that we must insert between both. */

    /* the new interconnect node */
    *branch = node = (struct ultree *)pool_alloc2(pool2_tree64); /* was <next> */
    ULTREE_INIT(node);
    node->up = root;
    next->up = node;

    /* we need the common higher bits between x and next->low. */

    /* what differences are there between x and the node here ?
     * NOTE that m is always < level(parent) because highest bit
     * of x and next->low are identical here (else they would be
     * on a different branch).
     */
    m = fls_fast32(x ^ next->low) + 1; /* m = lower identical bit */
    node->low = x & ~((1 << m) - 1); /* value of common bits */

    if (node->low == x) { /* <x> is exactly on this node */
	/* we must set its real position (eg: 8,10 => m=1 => val=8, m=3)*/
	node->level = ffs;

	if (next->low & (1 << (node->level - 1))) /* right branch */
	    node->right = next;
	else
	    node->left = next;
	return node;
    }

    /* the new leaf now */
    node->level = m; /* set the level to the lowest common bit */
    new = (struct ultree *)pool_alloc2(pool2_tree64);
    ULTREE_INIT(new);
    new->low = x;
    new->level = ffs;

    if (x > next->low) {
	node->left  = next;
	node->right = new;
    }
    else {
	node->left  = new;
	node->right = next;
    }
    new->up = node;
    return new;
}


/*
 * inserts necessary nodes to reach <h:l> in tree starting at <root>. The node
 * is not created if it exists. It is returned.
 */
inline static struct ultree *__ul2tree_insert(struct ultree *root, unsigned long h, unsigned long l) {
    int m;
    struct ultree *next, *new, *node;
    struct ultree **branch;

    next = root;

    do {
	root = next;

	if (h == next->high && l == next->low) {
	    return next;
	}

	branch = &next->left;
	if (next->level >= 33) {
	    if ((h >> (next->level - 33)) & 1) { /* right branch */
		branch = &next->right;
	    }
	}
	else {
	    if ((l >> (next->level - 1)) & 1) { /* right branch */
		branch = &next->right;
	    }
	}
	next = *branch;

	if (next == NULL) {
	    /* we'll have to insert our node here */
	    *branch = new =(struct ultree *)pool_alloc2(pool2_tree64);
	    UL2TREE_INIT(new);
	    new->up = root;
	    new->high = h;
	    new->low = l;
	    if (l)
		new->level = __ffs_fast32(l);
	    else
		new->level = __ffs_fast32(h) + 32;

	    return new;
	}

	/* we'll keep walking down as long as we have all bits in common */
	if (next->level >= 32) {
	    if ((h & ~((1 << (next->level-32)) - 1)) != next->high)
		break;
	}
	else {
	    if (h != next->high)
		break;
	    if ((l & ~((1 << next->level) - 1)) != next->low)
		break;
	}
    } while (1);

    /* ok, now we know that we must insert between both. */

    /* the new interconnect node */
    *branch = node = (struct ultree *)pool_alloc2(pool2_tree64); /* was <next> */
    UL2TREE_INIT(node);
    node->up = root;
    next->up = node;

    /* we need the common higher bits between x and next->high:low. */

    /* what differences are there between x and the node here ?
     * NOTE that m is always < level(parent) because highest bit
     * of x and next->high:low are identical here (else they would be
     * on a different branch).
     */
    if (h != next->high) {
	m = fls_fast32(h ^ next->high) + 1; /* m = lower identical bit */
	node->high = h & ~((1 << m) - 1); /* value of common bits */
	m += 32;
	node->low = 0;
    } else {
	node->high = h;
	m = fls_fast32(l ^ next->low) + 1;   /* m = lower identical bit */
	node->low = l & ~((1 << m) - 1); /* value of common bits */
    }

    if (node->high == h && node->low == l) { /* <h:l> is exactly on this node */
	/* we must set its real position (eg: 8,10 => m=1 => val=8, m=3)*/
	if (l) {
	    node->level = ffs_fast32(l);
	    if (next->low & (1 << (node->level - 1))) /* right branch */
		node->right = next;
	    else
		node->left = next;
	}
	else {
	    node->level = ffs_fast32(h) + 32;
	    if (next->high & (1 << (node->level - 33))) /* right branch */
		node->right = next;
	    else
		node->left = next;
	}
	return node;
    }

    /* the new leaf now */
    node->level = m; /* set the level to the lowest common bit */
    new = (struct ultree *)pool_alloc2(pool2_tree64);
    UL2TREE_INIT(new);
    new->high = h;
    new->low = l;
    if (l)
	new->level = __ffs_fast32(l);
    else
	new->level = __ffs_fast32(h) + 32;

    if (h > next->high || (h == next->high && l > next->low)) {
	node->left  = next;
	node->right = new;
    }
    else {
	node->left  = new;
	node->right = next;
    }
    new->up = node;
    return new;
}


/*
 * finds a value in the tree <root>. If it cannot be found, NULL is returned.
 */
inline static struct ultree *__ultree_find(struct ultree *root, unsigned long x) {
    do {
	if (x == root->low)
	    return root;

	if ((x >> (root->level - 1)) & 1)
	    root = root->right;
	else
	    root = root->left;

	if (root == NULL)
	    return NULL;

	/* we'll keep walking down as long as we have all bits in common */
    } while ((x & ~((1 << root->level) - 1)) == root->low);

    /* should be there, but nothing. */
    return NULL;
}

/*
 * finds a value in the tree <root>. If it cannot be found, NULL is returned.
 */
inline static struct ulltree *__ulltree_find(struct ulltree *root, unsigned long long x) {
    do {
	if (x == root->value)
	    return root;

	if ((x >> (root->level - 1)) & 1)
	    root = root->right;
	else
	    root = root->left;

	if (root == NULL)
	    return NULL;

	/* we'll keep walking down as long as we have all bits in common */
    } while ((x & ~((1ULL << root->level) - 1)) == root->value);

    /* should be there, but nothing. */
    return NULL;
}


/*
 * walks down the tree <__root> and assigns each of its data to <__data>.
 * <__stack> is an int array of at least N entries where N is the maximum number
 * of levels of the tree. <__slen> is an integer variable used as a stack index.
 * The instruction following the foreach statement is executed for each data,
 * after the data has been unlinked from the tree.
 * The nodes are deleted automatically, so it is illegal to manually delete a
 * node within this loop.
 */
#define tree64_foreach_destructive(__root, __data, __stack, __slen)	\
    for (__slen = 0, __stack[0] = __root, __data = NULL; ({		\
        __label__ __left, __right, __again, __end;			\
	typeof(__root) __ptr = __stack[__slen];				\
__again:								\
	__data = __ptr->data;						\
	if (__data != NULL) {						\
	    __ptr->data = NULL;						\
	    goto __end;							\
	}								\
	else if (__ptr->left != NULL) {					\
	    __stack[++__slen] = __ptr = __ptr->left;			\
	    goto __again;						\
	}								\
	else								\
__left:									\
	if (__ptr->right != NULL) {					\
	    __stack[++__slen] = __ptr = __ptr->right;			\
	    goto __again;						\
	}								\
	else								\
__right:								\
	if (!__slen--)							\
	    goto __end; /* nothing left, don't delete the root node */	\
	else {								\
	    typeof (__root) __old;					\
	    pool_free2(pool2_tree64, __ptr);				\
	    __old = __ptr;						\
	    __ptr = __stack[__slen];					\
	    if (__ptr->left == __old) {					\
		/* unlink this node from its parent */			\
		__ptr->left = NULL;					\
		goto __left;						\
	    }								\
	    else {							\
		/* no need to unlink, the parent will also die */	\
		goto __right;						\
	    }								\
	}								\
__end:									\
        (__slen >= 0); /* nothing after loop */}); )


/*
 * walks down the tree <__root> of type <__type> and assigns each of its data
 * to <__data>. <__stack> is an int array of at least N entries where N is the
 * maximum number of levels of the tree. <__slen> is an integer variable used
 * as a stack index. The instruction following the foreach statement is
 * executed for each data, after the data has been unlinked from the tree.
 */
#define tree_foreach_destructive(__type, __root, __data, __stack, __slen)		\
    for (__slen = 0, __stack[0] = __root, __data = NULL; ({		\
        __label__ __left, __right, __again, __end;			\
	typeof(__root) __ptr = __stack[__slen];				\
__again:								\
	__data = __ptr->data;						\
	if (__data != NULL) {						\
	    __ptr->data = NULL;						\
	    goto __end;							\
	}								\
	else if (__ptr->left != NULL) {					\
	    __stack[++__slen] = __ptr = __ptr->left;			\
	    goto __again;						\
	}								\
	else								\
__left:									\
	if (__ptr->right != NULL) {					\
	    __stack[++__slen] = __ptr = __ptr->right;			\
	    goto __again;						\
	}								\
	else								\
__right:								\
	if (!__slen--)							\
	    goto __end; /* nothing left, don't delete the root node */	\
	else {								\
	    typeof (__root) __old;					\
	    pool_free2(pool##__type, __ptr);				\
	    __old = __ptr;						\
	    __ptr = __stack[__slen];					\
	    if (__ptr->left == __old) {					\
		/* unlink this node from its parent */			\
		__ptr->left = NULL;					\
		goto __left;						\
	    }								\
	    else {							\
		/* no need to unlink, the parent will also die */	\
		goto __right;						\
	    }								\
	}								\
__end:									\
        (__slen >= 0); /* nothing after loop */}); )


/*
 * walks down the tree <__root> and assigns <__data> a pointer to each of its
 * data pointers. <__stack> is an int array of at least N entries where N is the
 * maximum number of levels of the tree. <__slen> is an integer variable used as
 * a stack index. The instruction following the foreach statement is executed
 * for each data.
 * The tree will walk down only when the data field is empty (NULL), so it
 * allows inner breaks, and will restart without losing items. The nodes data
 * will be set to NULL after the inner code, or when the inner code does
 * '__stack[__slen]->data = NULL';
 * The nodes are deleted automatically, so it is illegal to manually delete a
 * node within this loop.
 */
#define tree64_foreach(__root, __data, __stack, __slen)			\
    for (__slen = 0, __stack[0] = __root, __data = NULL; ({		\
        __label__ __left, __right, __again, __end;			\
	typeof(__root) __ptr = __stack[__slen];				\
__again:								\
	if (__ptr->data != NULL) {					\
	    __data = __ptr->data;					\
	    goto __end;							\
	}								\
	else if (__ptr->left != NULL) {					\
	    __stack[++__slen] = __ptr = __ptr->left;			\
	    goto __again;						\
	}								\
	else								\
__left:									\
	if (__ptr->right != NULL) {					\
	    __stack[++__slen] = __ptr = __ptr->right;			\
	    goto __again;						\
	}								\
	else								\
__right:								\
	if (!__slen--)							\
	    goto __end; /* nothing left, don't delete the root node */	\
	else {								\
	    typeof (__root) __old;					\
	    pool_free2(pool2_tree64, __ptr);				\
	    __old = __ptr;						\
	    __ptr = __stack[__slen];					\
	    if (__ptr->left == __old) {					\
		/* unlink this node from its parent */			\
		__ptr->left = NULL;					\
		goto __left;						\
	    }								\
	    else {							\
		/* no need to unlink, the parent will also die */	\
		goto __right;						\
	    }								\
	}								\
__end:									\
        (__slen >= 0); }); ((typeof(__root))__stack[__slen])->data = NULL)



/*
 * walks down the tree <__root> and assigns <__node> to each of its nodes.
 * <__stack> is an int array of at least N entries where N is the
 * maximum number of levels of the tree. <__slen> is an integer variable used as
 * a stack index. The instruction following the foreach statement is executed
 * for each node.
 * The tree will walk down only when the data field is empty (NULL), so it
 * allows inner breaks, and will restart without losing items. The nodes data
 * will be set to NULL after the inner code, or when the inner code does
 * '__node->data = NULL';
 * The nodes are deleted automatically, so it is illegal to manually delete a
 * node within this loop.
 */
#define tree64_foreach_node(__root, __node, __stack, __slen)		\
    for (__slen = 0, __stack[0] = __root; ({				\
        __label__ __left, __right, __again, __end;			\
	typeof(__root) __ptr = __stack[__slen];				\
__again:								\
	if (__ptr->data != NULL) {					\
	    __node = __ptr;						\
	    goto __end;							\
	}								\
	else if (__ptr->left != NULL) {					\
	    __stack[++__slen] = __ptr = __ptr->left;			\
	    goto __again;						\
	}								\
	else								\
__left:									\
	if (__ptr->right != NULL) {					\
	    __stack[++__slen] = __ptr = __ptr->right;			\
	    goto __again;						\
	}								\
	else								\
__right:								\
	if (!__slen--)							\
	    goto __end; /* nothing left, don't delete the root node */	\
	else {								\
	    typeof (__root) __old;					\
	    pool_free2(pool2_tree64, __ptr);				\
	    __old = __ptr;						\
	    __ptr = __stack[__slen];					\
	    if (__ptr->left == __old) {					\
		/* unlink this node from its parent */			\
		__ptr->left = NULL;					\
		goto __left;						\
	    }								\
	    else {							\
		/* no need to unlink, the parent will also die */	\
		goto __right;						\
	    }								\
	}								\
__end:									\
        (__slen >= 0); }); ((typeof(__root))__stack[__slen])->data = NULL)


/*
 * removes the current node if possible, and its parent if it doesn't handle
 * data. A pointer to the parent or grandparent is returned (the parent of the
 * last one deleted in fact). This function should be compatible with any
 * tree struct because of the void types.
 * WARNING : never call it from within a tree_foreach() because this last one
 * uses a stack which will not be updated.
 */

inline static void *__tree_delete_only_one(void *firstnode) {
    struct tree64 *down, **uplink;
    struct tree64 *node = firstnode;

    /* don't kill the root or a populated link */
    if (node->data || node->up == NULL)
	return node;
    if (node->left && node->right)
	return node;
    /* since we know that at least left or right is null, we can do arithmetics on them */
    down = (void *)((long)node->left | (long)node->right);
    /* find where we are linked */
    if (node == node->up->left)
	uplink = &node->up->left;
    else
	uplink = &node->up->right;

    *uplink = down; /* we relink the lower branch above us or simply cut it */
    if (down) {
	down->up = node->up;
	/* we know that we cannot do more because we kept one branch */
    }
    else {
	/* we'll redo this once for the node above us because there was no branch below us,
	 * so maybe it doesn't need to exist for only one branch
	 */
	down = node;
	node = node->up;
	pool_free2(pool2_tree64, down);
	if (node->data || node->up == NULL)
	    return node;
	/* now we're sure we were sharing this empty node with another branch, let's find it */
	down = (void *)((long)node->left | (long)node->right);
	if (node == node->up->left)
	    uplink = &node->up->left;
	else
	    uplink = &node->up->right;
	*uplink = down; /* we relink the lower branch above */
	down->up = node->up;
    }
    /* free the last node */
    pool_free2(pool2_tree64, node);
    return down->up;
}

/*
 * removes the current node if possible, and all of its parents which do not
 * carry data. A pointer to the parent of the last one deleted is returned.
 * This function should be compatible with any tree struct because of the void
 * types.
 * WARNING : never call it from within a tree_foreach() because this last one
 * uses a stack which will not be updated.
 */

inline static void *__tree_delete(void *firstnode) {
    struct tree64 *down, **uplink, *up;
    struct tree64 *node = firstnode;

    while (1) {
	/* don't kill the root or a populated link */
	if (node->data || (up = node->up) == NULL)
	    return node;
	if (node->left && node->right)
	    return node;
	/* since we know that at least left or right is null, we can do arithmetics on them */
	down = (void *)((long)node->left | (long)node->right);
	/* find where we are linked */
	if (node == up->left)
	    uplink = &up->left;
	else
	    uplink = &up->right;

	*uplink = down; /* we relink the lower branch above us or simply cut it */
	pool_free2(pool2_tree64, node);
	node = up;
	if (down)
	    down->up = node;
    }
}

#endif /* __TREE_H__ */
