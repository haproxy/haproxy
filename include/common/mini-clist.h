/*
 * list.h : list manipulation macros and structures.
 * Copyright 2002-2010 Willy Tarreau <w@1wt.eu>
 *
 */

#ifndef _COMMON_MINI_CLIST_H
#define _COMMON_MINI_CLIST_H

#include <common/config.h>

/* these are circular or bidirectionnal lists only. Each list pointer points to
 * another list pointer in a structure, and not the structure itself. The
 * pointer to the next element MUST be the first one so that the list is easily
 * cast as a single linked list or pointer.
 */
struct list {
    struct list *n;	/* next */
    struct list *p;	/* prev */
};

/* a back-ref is a pointer to a target list entry. It is used to detect when an
 * element being deleted is currently being tracked by another user. The best
 * example is a user dumping the session table. The table does not fit in the
 * output buffer so we have to set a mark on a session and go on later. But if
 * that marked session gets deleted, we don't want the user's pointer to go in
 * the wild. So we can simply link this user's request to the list of this
 * session's users, and put a pointer to the list element in ref, that will be
 * used as the mark for next iteration.
 */
struct bref {
	struct list users;
	struct list *ref; /* pointer to the target's list entry */
};

/* a word list is a generic list with a pointer to a string in each element. */
struct wordlist {
	struct list list;
	char *s;
};

/* this is the same as above with an additional pointer to a condition. */
struct cond_wordlist {
	struct list list;
	void *cond;
	char *s;
};

/* First undefine some macros which happen to also be defined on OpenBSD,
 * in sys/queue.h, used by sys/event.h
 */
#undef LIST_HEAD
#undef LIST_INIT
#undef LIST_NEXT

/* ILH = Initialized List Head : used to prevent gcc from moving an empty
 * list to BSS. Some older version tend to trim all the array and cause
 * corruption.
 */
#define ILH		{ .n = (struct list *)1, .p = (struct list *)2 }

#define LIST_HEAD(a)	((void *)(&(a)))

#define LIST_INIT(l) ((l)->n = (l)->p = (l))

#define LIST_HEAD_INIT(l) { &l, &l }

/* dual linked lists :
 * Start = (struct list *) pointer to the next elem's prev list entry
 * For each element :
 *   - prev = pointer to previous element's next (or start). Cannot be NULL
 *   - next = pointer to next element's prev. NULL = end.
 *
 */

/* adds an element at the beginning of a dual-linked list ; returns the element */
#define DLIST_ADD(lh, el) ({ typeof(el) __ret = (el); __ret->n = (void *)(lh); __ret->p = (void *)&(lh); if (likely(__ret->n != NULL)) __ret->n->p = __ret; (lh) = (typeof(lh))&__ret->n; __ret; })

/* removes an element from a dual-linked list and returns it */
#define DLIST_DEL(el) ({ typeof(el) __ret = (el); if (likely(__ret->n != NULL)) __ret->n->p = __ret->p; __ret->p->n = __ret->n; __ret; })

/*
 * iterates through a list of items of type "<struct_type>" which are
 * linked via a "struct list" member named <struct_member>. The head of the
 * list is stored at a location designed by <list_head>, which should be a
 * "struct list *". A variable <end_item> of type "<struct_type>" will
 * be used as temporary end of list pointer. It can be derived from <list_head>
 * since this one is only used before. <list_head> will be modified except for
 * foreach_dlist_item_cst which is slightly slower.
 * Major difference between FOREACH_ITEM is that it stops at NULL.
 * Example: foreach_dlist_item(cur_node, args, struct node *, list) { ... };
 *          foreach_dlist_item_cst(cur_node, &node->args, struct node *, list) { ... };
 */
#define foreach_dlist_item_cst(iterator, list_head, struct_type, struct_member)	\
	for ((iterator) = LIST_ELEM(&(list_head), struct_type, struct_member.n);	\
	     ((iterator)->struct_member.n != NULL) && \
             (((iterator) = LIST_ELEM((iterator)->struct_member.n, struct_type, struct_member.n)), 1);\
	     )

#define foreach_dlist_item(iterator, var_list_head, struct_type, struct_member)	\
	while ((var_list_head != NULL) &&			\
	       ((var_list_head=((iterator)=LIST_ELEM(var_list_head, struct_type, struct_member.n))->struct_member.n), 1))

/*
 * Like foreach_dlist_item, except that this one only operates on the head of
 * the list. It's to the inner instructions to iterate the list head. If not,
 * this will be an endless loop.
 */
#define while_dlist_item(iterator, var_list_head, struct_type, struct_member)	\
	while ((var_list_head != NULL) &&			\
	       (((iterator)=LIST_ELEM(var_list_head, struct_type, struct_member.n)),1))


/****** circular lists ********/

/* adds an element at the beginning of a list ; returns the element */
#define LIST_ADD(lh, el) ({ (el)->n = (lh)->n; (el)->n->p = (lh)->n = (el); (el)->p = (lh); (el); })

/* adds an element at the end of a list ; returns the element */
#define LIST_ADDQ(lh, el) ({ (el)->p = (lh)->p; (el)->p->n = (lh)->p = (el); (el)->n = (lh); (el); })

/* removes an element from a list and returns it */
#define LIST_DEL(el) ({ typeof(el) __ret = (el); (el)->n->p = (el)->p; (el)->p->n = (el)->n; (__ret); })

/* returns a pointer of type <pt> to a structure containing a list head called
 * <el> at address <lh>. Note that <lh> can be the result of a function or macro
 * since it's used only once.
 * Example: LIST_ELEM(cur_node->args.next, struct node *, args)
 */
#define LIST_ELEM(lh, pt, el) ((pt)(((void *)(lh)) - ((void *)&((pt)NULL)->el)))

/* checks if the list head <lh> is empty or not */
#define LIST_ISEMPTY(lh) ((lh)->n == (lh))

/* returns a pointer of type <pt> to a structure following the element
 * which contains list head <lh>, which is known as element <el> in
 * struct pt.
 * Example: LIST_NEXT(args, struct node *, list)
 */
#define LIST_NEXT(lh, pt, el) (LIST_ELEM((lh)->n, pt, el))


/* returns a pointer of type <pt> to a structure preceeding the element
 * which contains list head <lh>, which is known as element <el> in
 * struct pt.
 */
#define LIST_PREV(lh, pt, el) (LIST_ELEM((lh)->p, pt, el))

/*
 * DEPRECATED !!!  Use list_for_each_entry() below instead !
 *
 * iterates through a list of items of type "<struct_type>" which are
 * linked via a "struct list" member named <struct_member>. The head of the
 * list is stored at a location designed by <list_head>, which should be a
 * "struct list *". A variable <end_item> of type "<struct_type>" will
 * be used as temporary end of list pointer. It can be derived from <list_head>
 * since this one is only used before.
 * Example: FOREACH_ITEM(cur_node, &node->args, node, struct node *, neigh) { ... };
 */
#define FOREACH_ITEM(iterator, list_head, end_item, struct_type, struct_member) \
	iterator = end_item = LIST_ELEM(list_head, struct_type, struct_member); \
	while (((iterator) = LIST_ELEM((iterator)->struct_member.n, 		\
			     struct_type, struct_member)) != (end_item))

/*
 * DEPRECATED !!!  Use list_for_each_entry_safe() below instead !
 *
 * idem except that this one is safe against deletion, but it needs a backup
 * pointer of the element after the iterator.
 * Example: FOREACH_ITEM_SAFE(cur_node, backup, &node->args, node, struct node *, neigh) { ... };
 */
#define FOREACH_ITEM_SAFE(iterator, backup, list_head, end_item, struct_type, struct_member) \
	end_item = LIST_ELEM(list_head, struct_type, struct_member); \
	iterator = LIST_ELEM((end_item)->struct_member.n, struct_type, struct_member); \
	if ((iterator) != (end_item)) \
		backup = LIST_ELEM((iterator)->struct_member.n, struct_type, struct_member); \
	for ( ; (iterator) != (end_item); (iterator) = (backup),   \
		backup = LIST_ELEM((iterator)->struct_member.n, struct_type, struct_member))

/*
 * Simpler FOREACH_ITEM macro inspired from Linux sources.
 * Iterates <item> through a list of items of type "typeof(*item)" which are
 * linked via a "struct list" member named <member>. A pointer to the head of
 * the list is passed in <list_head>. No temporary variable is needed. Note
 * that <item> must not be modified during the loop.
 * Example: list_for_each_entry(cur_acl, known_acl, list) { ... };
 */ 
#define list_for_each_entry(item, list_head, member)                      \
	for (item = LIST_ELEM((list_head)->n, typeof(item), member);     \
	     &item->member != (list_head);                                \
	     item = LIST_ELEM(item->member.n, typeof(item), member))

/*
 * Simpler FOREACH_ITEM_SAFE macro inspired from Linux sources.
 * Iterates <item> through a list of items of type "typeof(*item)" which are
 * linked via a "struct list" member named <member>. A pointer to the head of
 * the list is passed in <list_head>. A temporary variable <back> of same type
 * as <item> is needed so that <item> may safely be deleted if needed.
 * Example: list_for_each_entry_safe(cur_acl, tmp, known_acl, list) { ... };
 */ 
#define list_for_each_entry_safe(item, back, list_head, member)           \
	for (item = LIST_ELEM((list_head)->n, typeof(item), member),     \
	     back = LIST_ELEM(item->member.n, typeof(item), member);     \
	     &item->member != (list_head);                                \
	     item = back, back = LIST_ELEM(back->member.n, typeof(back), member))


#endif /* _COMMON_MINI_CLIST_H */
