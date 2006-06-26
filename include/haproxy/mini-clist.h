/*
 * list.h : list manipulation macros and structures.
 * Copyright 2002-2006 Willy Tarreau <w@1wt.eu>
 *
 */

#ifndef _HAPROXY_MINI_CLIST_H
#define _HAPROXY_MINI_CLIST_H

/* these are circular or bidirectionnal lists only. Each list pointer points to
 * another list pointer in a structure, and not the structure itself. The
 * pointer to the next element MUST be the first one so that the list is easily
 * cast as a single linked list or pointer.
 */
struct list {
    struct list *n;	/* next */
    struct list *p;	/* prev */
};

#define LIST_HEAD(a)	((void *)(&(a)))

#define LIST_INIT(l) ((l)->n = (l)->p = (l))

/* dual linked lists :
 * Start = (struct list *) pointer to the next elem's prev list entry
 * For each element :
 *   - prev = pointer to previous element's next (or start). Cannot be NULL
 *   - next = pointer to next element's prev. NULL = end.
 *
 */

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

#endif /* _HAPROXY_MINI_CLIST_H */
