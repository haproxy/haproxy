/*
 * include/haproxy/list.h
 * Circular list manipulation macros and functions.
 *
 * Copyright (C) 2002-2020 Willy Tarreau - w@1wt.eu
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_LIST_H
#define _HAPROXY_LIST_H

#include <haproxy/api.h>
#include <haproxy/thread.h>
#include <import/mt_list.h>

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

/* adds an element at the beginning of a list ; returns the element */
#define LIST_INSERT(lh, el) ({ (el)->n = (lh)->n; (el)->n->p = (lh)->n = (el); (el)->p = (lh); (el); })

/* adds an element at the end of a list ; returns the element */
#define LIST_APPEND(lh, el) ({ (el)->p = (lh)->p; (el)->p->n = (lh)->p = (el); (el)->n = (lh); (el); })

/* adds the contents of a list <old> at the beginning of another list <new>. The old list head remains untouched. */
#define LIST_SPLICE(new, old) do {				     \
		if (!LIST_ISEMPTY(old)) {			     \
			(old)->p->n = (new)->n; (old)->n->p = (new); \
			(new)->n->p = (old)->p; (new)->n = (old)->n; \
		}						     \
	} while (0)

/* adds the contents of a list whose first element is <old> and last one is
 * <old->prev> at the end of another list <new>. The old list DOES NOT have
 * any head here.
 */
#define LIST_SPLICE_END_DETACHED(new, old) do {              \
		typeof(new) __t;                             \
		(new)->p->n = (old);                         \
		(old)->p->n = (new);                         \
		__t = (old)->p;                              \
		(old)->p = (new)->p;                         \
		(new)->p = __t;                              \
	} while (0)

/* removes an element from a list and returns it */
#if defined(DEBUG_LIST)
/* purposely corrupt the detached element to detect use-after-delete */
#define LIST_DELETE(el) ({ typeof(el) __ret = (el); (el)->n->p = (el)->p; (el)->p->n = (el)->n; *(__ret) = (struct list)ILH; (__ret);})
#else
#define LIST_DELETE(el) ({ typeof(el) __ret = (el); (el)->n->p = (el)->p; (el)->p->n = (el)->n; (__ret); })
#endif

/* removes an element from a list, initializes it and returns it.
 * This is faster than LIST_DELETE+LIST_INIT as we avoid reloading the pointers.
 */
#define LIST_DEL_INIT(el) ({ \
	typeof(el) __ret = (el);                        \
	typeof(__ret->n) __n = __ret->n;                \
	typeof(__ret->p) __p = __ret->p;                \
	__n->p = __p; __p->n = __n;                     \
	__ret->n = __ret->p = __ret;                    \
	__ret;                                          \
})

/* returns a pointer of type <pt> to a structure containing a list head called
 * <el> at address <lh>. Note that <lh> can be the result of a function or macro
 * since it's used only once.
 * Example: LIST_ELEM(cur_node->args.next, struct node *, args)
 */
#define LIST_ELEM(lh, pt, el) ((pt)(((const char *)(lh)) - ((size_t)&((pt)NULL)->el)))

/* checks if the list head <lh> is empty or not */
#define LIST_ISEMPTY(lh) ((lh)->n == (lh))

/* checks if the list element <el> was added to a list or not. This only
 * works when detached elements are reinitialized (using LIST_DEL_INIT)
 */
#define LIST_INLIST(el) ((el)->n != (el))

/* checks if the list element <el> has the same prev and next, i.e. it's either
 * detached or alone in a list since (it points to itself or to a single other
 * node). One can check that an element is strictly attached and alone by
 * combining this with LIST_INLIST().
 */
#define LIST_ATMOST1(el) ((el)->n == (el)->p)

/* atomically checks if the list element's next pointer points to anything
 * different from itself, implying the element should be part of a list. This
 * usually is similar to LIST_INLIST() except that while that one might be
 * instrumented using debugging code to perform further consistency checks,
 * the macro below guarantees to always perform a single atomic test and is
 * safe to use with barriers.
 */
#define LIST_INLIST_ATOMIC(el) ({                       \
	typeof(el) __ptr = (el);                        \
	HA_ATOMIC_LOAD(&(__ptr)->n) != __ptr;           \
})

/* returns a pointer of type <pt> to a structure following the element
 * which contains list head <lh>, which is known as element <el> in
 * struct pt.
 * Example: LIST_NEXT(args, struct node *, list)
 */
#define LIST_NEXT(lh, pt, el) (LIST_ELEM((lh)->n, pt, el))


/* returns a pointer of type <pt> to a structure preceding the element
 * which contains list head <lh>, which is known as element <el> in
 * struct pt.
 */
#undef LIST_PREV
#define LIST_PREV(lh, pt, el) (LIST_ELEM((lh)->p, pt, el))

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
 * Same as list_for_each_entry but starting from current point
 * Iterates <item> through the list starting from <item>
 * It's basically the same macro but without initializing item to the head of
 * the list.
 */
#define list_for_each_entry_from(item, list_head, member) \
	for ( ; &item->member != (list_head); \
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


/*
 * Same as list_for_each_entry_safe but starting from current point
 * Iterates <item> through the list starting from <item>
 * It's basically the same macro but without initializing item to the head of
 * the list.
 */
#define list_for_each_entry_safe_from(item, back, list_head, member) \
	for (back = LIST_ELEM(item->member.n, typeof(item), member);     \
	     &item->member != (list_head);                                \
	     item = back, back = LIST_ELEM(back->member.n, typeof(back), member))

/*
 * Iterate backwards <item> through a list of items of type "typeof(*item)"
 * which are linked via a "struct list" member named <member>. A pointer to
 * the head of the list is passed in <list_head>. No temporary variable is
 * needed. Note that <item> must not be modified during the loop.
 * Example: list_for_each_entry_rev(cur_acl, known_acl, list) { ... };
 */
#define list_for_each_entry_rev(item, list_head, member)                 \
	for (item = LIST_ELEM((list_head)->p, typeof(item), member);     \
	     &item->member != (list_head);                               \
	     item = LIST_ELEM(item->member.p, typeof(item), member))

/*
 * Same as list_for_each_entry_rev but starting from current point
 * Iterate backwards <item> through the list starting from <item>
 * It's basically the same macro but without initializing item to the head of
 * the list.
 */
#define list_for_each_entry_from_rev(item, list_head, member) \
	for ( ; &item->member != (list_head); \
	     item = LIST_ELEM(item->member.p, typeof(item), member))

/*
 * Iterate backwards <item> through a list of items of type "typeof(*item)"
 * which are linked via a "struct list" member named <member>. A pointer to
 * the head of the list is passed in <list_head>. A temporary variable <back>
 * of same type as <item> is needed so that <item> may safely be deleted
 * if needed.
 * Example: list_for_each_entry_safe_rev(cur_acl, tmp, known_acl, list) { ... };
 */
#define list_for_each_entry_safe_rev(item, back, list_head, member)      \
	for (item = LIST_ELEM((list_head)->p, typeof(item), member),     \
	     back = LIST_ELEM(item->member.p, typeof(item), member);     \
	     &item->member != (list_head);                               \
	     item = back, back = LIST_ELEM(back->member.p, typeof(back), member))

/*
 * Same as list_for_each_entry_safe_rev but starting from current point
 * Iterate backwards <item> through the list starting from <item>
 * It's basically the same macro but without initializing item to the head of
 * the list.
 */
#define list_for_each_entry_safe_from_rev(item, back, list_head, member) \
	for (back = LIST_ELEM(item->member.p, typeof(item), member);     \
	     &item->member != (list_head);                               \
	     item = back, back = LIST_ELEM(back->member.p, typeof(back), member))

static __inline struct list *mt_list_to_list(struct mt_list *list)
{
	union {
		struct mt_list *mt_list;
		struct list *list;
	} mylist;

	mylist.mt_list = list;
	return mylist.list;
}

static __inline struct mt_list *list_to_mt_list(struct list *list)
{
	union {
		struct mt_list *mt_list;
		struct list *list;
	} mylist;

	mylist.list = list;
	return mylist.mt_list;

}

/* Init a <w> watcher entry to track targets. <pptr> is the pointer to the
 * target pointer which will be updated via watcher_attach/detach operations.
 * <attach_off> is the offset to access the target mt_list attach point for the
 * watcher entry.
 */
static __inline void watcher_init(struct watcher *w, void *pptr, size_t attach_off)
{
	MT_LIST_INIT(&w->el);
	w->pptr = pptr;
	w->off = attach_off;
}

/* Tracks <target> via <w> watcher. Invalid if <w> is already attached. */
static __inline void watcher_attach(struct watcher *w, void *target)
{
	struct mt_list *list = target + w->off;

	BUG_ON_HOT(MT_LIST_INLIST(&w->el));

	*w->pptr = target;
	if (target)
		MT_LIST_APPEND(list, &w->el);
}

/* Untracks target via <w> watcher. Invalid if <w> is not attached first. */
static __inline void watcher_detach(struct watcher *w)
{
	BUG_ON_HOT(!MT_LIST_INLIST(&w->el));
	*w->pptr = NULL;
	MT_LIST_DELETE(&w->el);
}

/* Equivalent to a detach then attach on <target> via <w> watcher. Returns
 * <target> as a convenience to use this function as increment in a for-loop.
 */
static __inline void *watcher_next(struct watcher *w, void *target)
{
	watcher_detach(w);
	watcher_attach(w, target);
	return target;
}

#endif /* _HAPROXY_LIST_H */
