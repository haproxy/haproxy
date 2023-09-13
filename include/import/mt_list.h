/*
 * include/mt_list.h
 *
 * Multi-thread aware circular lists.
 *
 * Copyright (C) 2018-2023 Willy Tarreau
 * Copyright (C) 2018-2023 Olivier Houchard
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _MT_LIST_H
#define _MT_LIST_H

#include <inttypes.h>
#include <stddef.h>

/* set NOINLINE to forcefully disable user functions inlining */
#if defined(NOINLINE)
#define MT_INLINE __attribute__((noinline))
#else
#define MT_INLINE inline
#endif

// Note: already defined in list-t.h
#ifndef _HAPROXY_LIST_T_H
/* A list element, it's both a head or any element. Both pointers always point
 * to a valid list element (possibly itself for a detached element or an empty
 * list head), or are equal to MT_LIST_BUSY for a locked pointer indicating
 * that the target element is about to be modified.
 */
struct mt_list {
	struct mt_list *next;
	struct mt_list *prev;
};
#endif

/* This is the value of the locked list pointer. It is assigned to an mt_list's
 * ->next or ->prev pointer to lock the link to the other element while this
 * element is being inspected or modified.
 */
#define MT_LIST_BUSY ((struct mt_list *)1)

/* This is used to pre-initialize an mt_list element during its declaration.
 * The argument is the name of the variable being declared and being assigned
 * this value. Example:
 *
 *   struct mt_list pool_head = MT_LIST_HEAD_INIT(pool_head);
 */
#define MT_LIST_HEAD_INIT(l) { .next = &l, .prev = &l }


/* Returns a pointer of type <t> to the structure containing a member of type
 * mt_list called <m> that is accessible at address <a>. Note that <a> may be
 * the result of a function or macro since it's used only once. Example:
 *
 *   return MT_LIST_ELEM(cur_node->args.next, struct node *, args)
 */
#define MT_LIST_ELEM(a, t, m) ((t)(((const char *)(a)) - ((size_t)&((t)NULL)->m)))


/* Returns a pointer of type <t> to a structure following the element which
 * contains the list element at address <a>, which is known as member <m> in
 * struct t*. Example:
 *
 *   return MT_LIST_NEXT(args, struct node *, list);
 */
#define MT_LIST_NEXT(a, t, m) (MT_LIST_ELEM((a)->next, t, m))


/* Returns a pointer of type <t> to a structure preceeding the element which
 * contains the list element at address <a>, which is known as member <m> in
 * struct t*. Example:
 *
 *   return MT_LIST_PREV(args, struct node *, list);
 */
#define MT_LIST_PREV(a, t, m) (MT_LIST_ELEM((a)->prev, t, m))


/* This is used to prevent the compiler from knowing the origin of the
 * variable, and sometimes avoid being confused about possible null-derefs
 * that it sometimes believes are possible after pointer casts.
 */
#define MT_ALREADY_CHECKED(p) do { asm("" : "=rm"(p) : "0"(p)); } while (0)


/* Returns a pointer of type <t> to the structure containing a member of type
 * mt_list called <m> that comes from the first element in list <l>, that is
 * atomically detached. If the list is empty, NULL is returned instead.
 * Example:
 *
 *   while ((conn = MT_LIST_POP(queue, struct conn *, list))) ...
 */
#define MT_LIST_POP(lh, t, m)						\
	({								\
		struct mt_list *_n = mt_list_pop(lh);			\
		(_n ? MT_LIST_ELEM(_n, t, m) : NULL);			\
	})

/* Iterates <item> through a list of items of type "typeof(*item)" which are
 * linked via a "struct mt_list" member named <member>. A pointer to the head
 * of the list is passed in <list_head>.
 *
 * <back> is a temporary struct mt_list, used internally to store the current
 * element's ends while it is locked.
 *
 * This macro is implemented using two nested loops, each defined as a separate
 * macro for easier inspection. The inner loop will run for each element in the
 * list, and the outer loop will run only once to do some cleanup when the end
 * of the list is reached or user breaks from inner loop. It's safe to break
 * from this macro as the cleanup will be performed anyway, but it is strictly
 * forbidden to branch (goto or return) from the loop because skipping the
 * cleanup will lead to undefined behavior.
 *
 * The current element is detached from the list while being visited, with its
 * extremities locked, and re-attached when switching to the next item. As such
 * in order to delete the current item, it's sufficient to set it to NULL to
 * prevent the inner loop from attaching it back. In this case it's recommended
 * to re-init the item before reusing it in order to clear the locks.
 *
 * Example:
 *   MT_LIST_FOR_EACH_ENTRY_SAFE(item, list_head, list_member, back) {
 *     ...
 *   }
 */
#define MT_LIST_FOR_EACH_ENTRY_SAFE(item, list_head, member, back) 		\
	_MT_LIST_FOR_EACH_ENTRY_OUTER(item, list_head, member, back)	\
		_MT_LIST_FOR_EACH_ENTRY_INNER(item, list_head, member, back)


/* The macros below directly map to their function equivalent. They are
 * provided for ease of use. Please refer to the equivalent functions
 * for their decription.
 */
#define MT_LIST_INIT(e)                 (mt_list_init(e))
#define MT_LIST_ISEMPTY(e)              (mt_list_isempty(e))
#define MT_LIST_INLIST(e)               (mt_list_inlist(e))
#define MT_LIST_TRY_INSERT(l, e)        (mt_list_try_insert(l, e))
#define MT_LIST_TRY_APPEND(l, e)        (mt_list_try_append(l, e))
#define MT_LIST_BEHEAD(l)               (mt_list_behead(l))
#define MT_LIST_INSERT(l, e)            (mt_list_insert(l, e))
#define MT_LIST_APPEND(l, e)            (mt_list_append(l, e))
#define MT_LIST_DELETE(e)               (mt_list_delete(e))
#define MT_LIST_CUT_AFTER(el)           (mt_list_cut_after(el))
#define MT_LIST_CUT_BEFORE(el)          (mt_list_cut_before(el))
#define MT_LIST_CUT_AROUND(el)          (mt_list_cut_around(el))
#define MT_LIST_RECONNECT(ends)         (mt_list_reconnect(ends))
#define MT_LIST_CONNECT_ELEM(el, ends)  (mt_list_connect_elem(el, ends))


/* This is a Xorshift-based thread-local PRNG aimed at reducing the risk of
 * resonance between competing threads during exponential back-off. Threads
 * quickly become out of sync and use completely different values.
 */
static __thread unsigned int _prng_state = 0xEDCBA987;
static inline unsigned int mt_list_prng()
{
        unsigned int x = _prng_state;

        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        return _prng_state = x;
}

static inline unsigned int mt_list_wait(unsigned factor)
{
	//return ((uint64_t)factor * mt_list_prng() + factor) >> 32;
	return mt_list_prng() & factor;
}

/* This function relaxes the CPU during contention. It is meant to be
 * architecture-specific and may even be OS-specific, and always exists in a
 * generic version. It should return a non-null integer value that can be used
 * as a boolean in while() loops. The argument indicates the maximum number of
 * loops to be performed before returning.
 */
static inline __attribute__((always_inline)) unsigned long mt_list_cpu_relax(unsigned long loop)
{
	/* limit maximum wait time for unlucky threads */
	loop = mt_list_wait(loop);

	for (loop &= 0x7fffff; loop >= 32; loop--) {
#if defined(__x86_64__)
		/* This is a PAUSE instruction on x86_64 */
		asm volatile("rep;nop\n");
#elif defined(__aarch64__)
		/* This was shown to improve fairness on modern ARMv8
		 * such as Cortex A72 or Neoverse N1.
		 */
		asm volatile("isb");
#else
		/* Generic implementation */
		asm volatile("");
#endif
	}
	/* faster ending */
	while (loop--)
		asm volatile("");
	return 1;
}


/* Initialize list element <el>. It will point to itself, matching a list head
 * or a detached list element. The list element is returned.
 */
static inline struct mt_list *mt_list_init(struct mt_list *el)
{
	el->next = el->prev = el;
	return el;
}


/* Returns true if the list element <e> corresponds to an empty list head or a
 * detached element, false otherwise. Only the <next> member is checked.
 */
static inline long mt_list_isempty(const struct mt_list *el)
{
	return el->next == el;
}


/* Returns true if the list element <e> corresponds to a non-empty list head or
 * to an element that is part of a list, false otherwise. Only the <next> member
 * is checked.
 */
static inline long mt_list_inlist(const struct mt_list *el)
{
	return el->next != el;
}


/* Adds element <el> at the beginning of list <lh>, which means that element
 * <el> is added immediately after element <lh> (nothing strictly requires that
 * <lh> is effectively the list's head, any valid element will work). Returns
 * non-zero if the element was added, otherwise zero (because the element was
 * already part of a list).
 */
static MT_INLINE long mt_list_try_insert(struct mt_list *lh, struct mt_list *el)
{
	struct mt_list *n, *n2;
	struct mt_list *p, *p2;
	unsigned long loops = 0;
        long ret = 0;

	/* Note that the first element checked is the most likely to face
	 * contention, particularly on the list's head/tail. That's why we
	 * perform a prior load there: if the element is being modified by
	 * another thread, requesting a read-only access only leaves the
	 * other thread's cache line in shared mode, which will impact it
	 * less than if we attempted a change that would invalidate it.
	 */
	for (;; mt_list_cpu_relax(loops = loops * 8 + 7)) {
		if (__atomic_load_n(&lh->next, __ATOMIC_RELAXED) == MT_LIST_BUSY)
		        continue;

		n = __atomic_exchange_n(&lh->next, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (n == MT_LIST_BUSY)
		        continue;

		p = __atomic_exchange_n(&n->prev, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (p == MT_LIST_BUSY) {
			lh->next = n;
			__atomic_thread_fence(__ATOMIC_RELEASE);
			continue;
		}

		n2 = __atomic_exchange_n(&el->next, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (n2 != el) {
			/* This element was already attached elsewhere */
			if (n2 != MT_LIST_BUSY)
				el->next = n2;
			n->prev = p;
			__atomic_thread_fence(__ATOMIC_RELEASE);

			lh->next = n;
			__atomic_thread_fence(__ATOMIC_RELEASE);

			if (n2 == MT_LIST_BUSY)
				continue;
			break;
		}

		p2 = __atomic_exchange_n(&el->prev, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (p2 != el) {
			/* This element was already attached elsewhere */
			if (p2 != MT_LIST_BUSY)
				el->prev = p2;
			n->prev = p;
			el->next = el;
			__atomic_thread_fence(__ATOMIC_RELEASE);

			lh->next = n;
			__atomic_thread_fence(__ATOMIC_RELEASE);

			if (p2 == MT_LIST_BUSY)
				continue;
			break;
		}

		el->next = n;
		el->prev = p;
		__atomic_thread_fence(__ATOMIC_RELEASE);

		n->prev = el;
		__atomic_thread_fence(__ATOMIC_RELEASE);

		p->next = el;
		__atomic_thread_fence(__ATOMIC_RELEASE);

		ret = 1;
		break;
	}
	return ret;
}


/* Adds element <el> at the end of list <lh>, which means that element <el> is
 * added immediately before element <lh> (nothing strictly requires that <lh>
 * is effectively the list's head, any valid element will work). Returns non-
 * zero if the element was added, otherwise zero (because the element was
 * already part of a list).
 */
static MT_INLINE long mt_list_try_append(struct mt_list *lh, struct mt_list *el)
{
	struct mt_list *n, *n2;
	struct mt_list *p, *p2;
	unsigned long loops = 0;
	long ret = 0;

	/* Note that the first element checked is the most likely to face
	 * contention, particularly on the list's head/tail. That's why we
	 * perform a prior load there: if the element is being modified by
	 * another thread, requesting a read-only access only leaves the
	 * other thread's cache line in shared mode, which will impact it
	 * less than if we attempted a change that would invalidate it.
	 */
	for (;; mt_list_cpu_relax(loops = loops * 8 + 7)) {
		if (__atomic_load_n(&lh->prev, __ATOMIC_RELAXED) == MT_LIST_BUSY)
		        continue;

		p = __atomic_exchange_n(&lh->prev, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (p == MT_LIST_BUSY)
		        continue;

		n = __atomic_exchange_n(&p->next, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (n == MT_LIST_BUSY) {
			lh->prev = p;
			__atomic_thread_fence(__ATOMIC_RELEASE);
			continue;
		}

		p2 = __atomic_exchange_n(&el->prev, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (p2 != el) {
			/* This element was already attached elsewhere */
			if (p2 != MT_LIST_BUSY)
				el->prev = p2;
			p->next = n;
			__atomic_thread_fence(__ATOMIC_RELEASE);

			lh->prev = p;
			__atomic_thread_fence(__ATOMIC_RELEASE);

			if (p2 == MT_LIST_BUSY)
				continue;
			break;
		}

		n2 = __atomic_exchange_n(&el->next, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (n2 != el) {
			/* This element was already attached elsewhere */
			if (n2 != MT_LIST_BUSY)
				el->next = n2;
			p->next = n;
			el->prev = el;
			__atomic_thread_fence(__ATOMIC_RELEASE);

			lh->prev = p;
			__atomic_thread_fence(__ATOMIC_RELEASE);

			if (n2 == MT_LIST_BUSY)
				continue;
			break;
		}

		el->next = n;
		el->prev = p;
		__atomic_thread_fence(__ATOMIC_RELEASE);

		p->next = el;
		__atomic_thread_fence(__ATOMIC_RELEASE);

		n->prev = el;
		__atomic_thread_fence(__ATOMIC_RELEASE);

		ret = 1;
		break;
	}
	return ret;
}


/* Detaches a list from its head. A pointer to the first element is returned
 * and the list is closed. If the list was empty, NULL is returned. This may
 * exclusively be used with lists manipulated using mt_list_try_insert() and
 * mt_list_try_append(). This is incompatible with mt_list_delete() run
 * concurrently. If there's at least one element, the next of the last element
 * will always be NULL.
 */
static MT_INLINE struct mt_list *mt_list_behead(struct mt_list *lh)
{
	struct mt_list *n;
	struct mt_list *p;
	unsigned long loops = 0;

	for (;; mt_list_cpu_relax(loops = loops * 8 + 7)) {
		p = __atomic_exchange_n(&lh->prev, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (p == MT_LIST_BUSY)
		        continue;
		if (p == lh) {
			lh->prev = p;
			__atomic_thread_fence(__ATOMIC_RELEASE);
			n = NULL;
			break;
		}

		n = __atomic_exchange_n(&lh->next, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (n == MT_LIST_BUSY) {
			lh->prev = p;
			__atomic_thread_fence(__ATOMIC_RELEASE);
			continue;
		}
		if (n == lh) {
			lh->next = n;
			lh->prev = p;
			__atomic_thread_fence(__ATOMIC_RELEASE);
			n = NULL;
			break;
		}

		lh->next = lh->prev = lh;
		__atomic_thread_fence(__ATOMIC_RELEASE);

		n->prev = p;
		__atomic_thread_fence(__ATOMIC_RELEASE);

		p->next = NULL;
		__atomic_thread_fence(__ATOMIC_RELEASE);
		break;
	}
	return n;
}


/* Adds element <el> at the beginning of list <lh>, which means that element
 * <el> is added immediately after element <lh> (nothing strictly requires that
 * <lh> is effectively the list's head, any valid element will work). It is
 * assumed that the element cannot already be part of a list so it isn't
 * checked for this.
 */
static MT_INLINE void mt_list_insert(struct mt_list *lh, struct mt_list *el)
{
	struct mt_list *n;
	struct mt_list *p;
	unsigned long loops = 0;

	for (;; mt_list_cpu_relax(loops = loops * 8 + 7)) {
		n = __atomic_exchange_n(&lh->next, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (n == MT_LIST_BUSY)
		        continue;

		p = __atomic_exchange_n(&n->prev, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (p == MT_LIST_BUSY) {
			lh->next = n;
			__atomic_thread_fence(__ATOMIC_RELEASE);
			continue;
		}

		el->next = n;
		el->prev = p;
		__atomic_thread_fence(__ATOMIC_RELEASE);

		n->prev = el;
		__atomic_thread_fence(__ATOMIC_RELEASE);

		p->next = el;
		__atomic_thread_fence(__ATOMIC_RELEASE);
		break;
	}
}


/* Adds element <el> at the end of list <lh>, which means that element <el> is
 * added immediately after element <lh> (nothing strictly requires that <lh> is
 * effectively the list's head, any valid element will work). It is assumed
 * that the element cannot already be part of a list so it isn't checked for
 * this.
 */
static MT_INLINE void mt_list_append(struct mt_list *lh, struct mt_list *el)
{
	struct mt_list *n;
	struct mt_list *p;
	unsigned long loops = 0;

	for (;; mt_list_cpu_relax(loops = loops * 8 + 7)) {
		p = __atomic_exchange_n(&lh->prev, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (p == MT_LIST_BUSY)
		        continue;

		n = __atomic_exchange_n(&p->next, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (n == MT_LIST_BUSY) {
			lh->prev = p;
			__atomic_thread_fence(__ATOMIC_RELEASE);
			continue;
		}

		el->next = n;
		el->prev = p;
		__atomic_thread_fence(__ATOMIC_RELEASE);

		p->next = el;
		__atomic_thread_fence(__ATOMIC_RELEASE);

		n->prev = el;
		__atomic_thread_fence(__ATOMIC_RELEASE);
		break;
	}
}


/* Removes element <el> from the list it belongs to. The function returns
 * non-zero if the element could be removed, otherwise zero if the element
 * could not be removed, because it was already not in a list anymore.
 */
static MT_INLINE long mt_list_delete(struct mt_list *el)
{
	struct mt_list *n, *n2;
	struct mt_list *p, *p2;
	unsigned long loops = 0;
	long ret = 0;

	for (;; mt_list_cpu_relax(loops = loops * 8 + 7)) {
		p2 = NULL;
		n = __atomic_exchange_n(&el->next, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (n == MT_LIST_BUSY)
		        continue;

		p = __atomic_exchange_n(&el->prev, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (p == MT_LIST_BUSY) {
			el->next = n;
			__atomic_thread_fence(__ATOMIC_RELEASE);
			continue;
		}

		if (p != el) {
		        p2 = __atomic_exchange_n(&p->next, MT_LIST_BUSY, __ATOMIC_RELAXED);
		        if (p2 == MT_LIST_BUSY) {
		                el->prev = p;
				el->next = n;
				__atomic_thread_fence(__ATOMIC_RELEASE);
				continue;
			}
		}

		if (n != el) {
		        n2 = __atomic_exchange_n(&n->prev, MT_LIST_BUSY, __ATOMIC_RELAXED);
			if (n2 == MT_LIST_BUSY) {
				if (p2 != NULL)
					p->next = p2;
				el->prev = p;
				el->next = n;
				__atomic_thread_fence(__ATOMIC_RELEASE);
				continue;
			}
		}

		n->prev = p;
		p->next = n;
		__atomic_thread_fence(__ATOMIC_RELEASE);

		el->prev = el->next = el;
		__atomic_thread_fence(__ATOMIC_RELEASE);

		if (p != el && n != el)
			ret = 1;
		break;
	}
	return ret;
}


/* Removes the first element from the list <lh>, and returns it in detached
 * form. If the list is already empty, NULL is returned instead.
 */
static MT_INLINE struct mt_list *mt_list_pop(struct mt_list *lh)
{
	struct mt_list *n, *n2;
	struct mt_list *p, *p2;
	unsigned long loops = 0;

	for (;; mt_list_cpu_relax(loops = loops * 8 + 7)) {
		if (__atomic_load_n(&lh->next, __ATOMIC_RELAXED) == MT_LIST_BUSY)
		        continue;

		n = __atomic_exchange_n(&lh->next, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (n == MT_LIST_BUSY)
			continue;

		if (n == lh) {
			/* list is empty */
			lh->next = lh;
			__atomic_thread_fence(__ATOMIC_RELEASE);
			n = NULL;
			break;
		}

		p = __atomic_exchange_n(&n->prev, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (p == MT_LIST_BUSY) {
			lh->next = n;
			__atomic_thread_fence(__ATOMIC_RELEASE);
			continue;
		}

		n2 = __atomic_exchange_n(&n->next, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (n2 == MT_LIST_BUSY) {
			n->prev = p;
			__atomic_thread_fence(__ATOMIC_RELEASE);

			lh->next = n;
			__atomic_thread_fence(__ATOMIC_RELEASE);
			continue;
		}

		p2 = __atomic_exchange_n(&n2->prev, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (p2 == MT_LIST_BUSY) {
			n->next = n2;
			n->prev = p;
			__atomic_thread_fence(__ATOMIC_RELEASE);

			lh->next = n;
			__atomic_thread_fence(__ATOMIC_RELEASE);
			continue;
		}

		lh->next = n2;
		n2->prev = lh;
		__atomic_thread_fence(__ATOMIC_RELEASE);

		n->prev = n->next = n;
		__atomic_thread_fence(__ATOMIC_RELEASE);

		/* return n */
		break;
	}
	return n;
}


/* Opens the list just after <lh> which usually is the list's head, but not
 * necessarily. The link between <lh> and its next element is cut and replaced
 * with an MT_LIST_BUSY lock. The ends of the removed link are returned as an
 * mt_list entry. The operation can be cancelled using mt_list_reconnect() on
 * the returned value, which will restore the link and unlock the list, or
 * using mt_list_connect_elem() which will replace the link with another
 * element and also unlock the list, effectively resulting in inserting that
 * element after <lh>. Example:
 *
 *   struct mt_list *list_insert(struct mt_list *list)
 *   {
 *     struct mt_list tmp = mt_list_cut_after(list);
 *     struct mt_list *el = alloc_element_to_insert();
 *     if (el)
 *         mt_list_connect_elem(el, tmp);
 *     else
 *         mt_list_reconnect(tmp);
 *     return el;
 *   }
 */
static MT_INLINE struct mt_list mt_list_cut_after(struct mt_list *lh)
{
	struct mt_list el;
	unsigned long loops = 0;

	for (;; mt_list_cpu_relax(loops = loops * 8 + 7)) {
		el.next = __atomic_exchange_n(&lh->next, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (el.next == MT_LIST_BUSY)
		        continue;

		el.prev = __atomic_exchange_n(&el.next->prev, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (el.prev == MT_LIST_BUSY) {
			lh->next = el.next;
			__atomic_thread_fence(__ATOMIC_RELEASE);
			continue;
		}
		break;
	}
	return el;
}


/* Opens the list just before <lh> which usually is the list's head, but not
 * necessarily. The link between <lh> and its prev element is cut and replaced
 * with an MT_LIST_BUSY lock. The ends of the removed link are returned as an
 * mt_list entry. The operation can be cancelled using mt_list_reconnect() on
 * the returned value, which will restore the link and unlock the list, or
 * using mt_list_connect_elem() which will replace the link with another
 * element and also unlock the list, effectively resulting in inserting that
 * element before <lh>. Example:
 *
 *   struct mt_list *list_append(struct mt_list *list)
 *   {
 *     struct mt_list tmp = mt_list_cut_before(list);
 *     struct mt_list *el = alloc_element_to_insert();
 *     if (el)
 *         mt_list_connect_elem(el, tmp);
 *     else
 *         mt_list_reconnect(tmp);
 *     return el;
 *   }
 */
static MT_INLINE struct mt_list mt_list_cut_before(struct mt_list *lh)
{
	struct mt_list el;
	unsigned long loops = 0;

	for (;; mt_list_cpu_relax(loops = loops * 8 + 7)) {
		el.prev = __atomic_exchange_n(&lh->prev, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (el.prev == MT_LIST_BUSY)
		        continue;

		el.next = __atomic_exchange_n(&el.prev->next, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (el.next == MT_LIST_BUSY) {
			lh->prev = el.prev;
			__atomic_thread_fence(__ATOMIC_RELEASE);
			continue;
		}
		break;
	}
	return el;
}


/* Opens the list around element <el>. Both the links between <el> and its prev
 * element and between <el> and its next element are cut and replaced with an
 * MT_LIST_BUSY lock. The element itself also has its ends replaced with a
 * lock, and the ends of the element are returned as an mt_list entry. This
 * results in the element being detached from the list and both the element and
 * the list being locked. The operation can be terminated by calling
 * mt_list_reconnect() on the returned value, which will unlock the list and
 * effectively result in the removal of the element from the list, or by
 * calling mt_list_connect_elem() to reinstall the element at its place in the
 * list, effectively consisting in a temporary lock of this element. Example:
 *
 *   struct mt_list *grow_shrink_remove(struct mt_list *el, size_t new_size)
 *   {
 *     struct mt_list *tmp = mt_list_cut_around(&node->list);
 *     struct mt_list *new = new_size ? realloc(el, new_size) : NULL;
 *     if (new_size) {
 *         mt_list_connect_elem(new ? new : el, tmp);
 *     } else {
 *         free(el);
 *         mt_list_reconnect(tmp);
 *     }
 *     return new;
 *   }
 */
static MT_INLINE struct mt_list mt_list_cut_around(struct mt_list *el)
{
	struct mt_list *n2;
	struct mt_list *p2;
	struct mt_list ret;
	unsigned long loops = 0;

	for (;; mt_list_cpu_relax(loops = loops * 8 + 7)) {
		p2 = NULL;
		if (__atomic_load_n(&el->next, __ATOMIC_RELAXED) == MT_LIST_BUSY)
		        continue;

		ret.next = __atomic_exchange_n(&el->next, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (ret.next == MT_LIST_BUSY)
			continue;

		ret.prev = __atomic_exchange_n(&el->prev, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (ret.prev == MT_LIST_BUSY) {
			el->next = ret.next;
			__atomic_thread_fence(__ATOMIC_RELEASE);
			continue;
		}

		if (ret.prev != el) {
			p2 = __atomic_exchange_n(&ret.prev->next, MT_LIST_BUSY, __ATOMIC_RELAXED);
			if (p2 == MT_LIST_BUSY) {
				*el = ret;
				__atomic_thread_fence(__ATOMIC_RELEASE);
				continue;
			}
		}

		if (ret.next != el) {
			n2 = __atomic_exchange_n(&ret.next->prev, MT_LIST_BUSY, __ATOMIC_RELAXED);
			if (n2 == MT_LIST_BUSY) {
				if (p2 != NULL)
					ret.prev->next = p2;
				*el = ret;
				__atomic_thread_fence(__ATOMIC_RELEASE);
				continue;
			}
		}
		break;
	}
	return ret;
}

/* Reconnects two elements in a list. This is used to complete an element
 * removal or just to unlock a list previously locked with mt_list_cut_after(),
 * mt_list_cut_before(), or mt_list_cut_around(). The link element returned by
 * these function just needs to be passed to this one. See examples above.
 */
static inline void mt_list_reconnect(struct mt_list ends)
{
	ends.next->prev = ends.prev;
	ends.prev->next = ends.next;
}


/* Connects element <el> at both ends <ends> of a list which is still locked
 * hence has the link between these endpoints cut. This automatically unlocks
 * both the element and the list, and effectively results in inserting or
 * appending the element to that list if the ends were just after or just
 * before the list's head. It may also be used to unlock a previously locked
 * element since locking an element consists in cutting the links around it.
 * The element doesn't need to be previously initialized as it gets blindly
 * overwritten with <ends>. See examples above.
 */
static inline void mt_list_connect_elem(struct mt_list *el, struct mt_list ends)
{
	*el = ends;
	__atomic_thread_fence(__ATOMIC_RELEASE);

	if (__builtin_expect(ends.next != el, 1))
		ends.next->prev = el;
	if (__builtin_expect(ends.prev != el, 1))
		ends.prev->next = el;
}


/*****************************************************************************
 * The macros and functions below are only used by the iterators. These must *
 * not be used for other purposes!                                           *
 *****************************************************************************/


/* Unlocks element <el> from the backup copy of previous next pointer <back>.
 * It supports the special case where the list was empty and the element locked
 * while looping over itself (we don't need/want to overwrite ->prev in this
 * case).
 */
static inline void _mt_list_unlock_next(struct mt_list *el, struct mt_list *back)
{
	el->next = back;
	__atomic_thread_fence(__ATOMIC_RELEASE);

	if (back != el)
		back->prev = el;
}


/* Unlocks element <el> from the backup copy of previous prev pointer <back>.
 * <back> cannot be equal to <el> here because if the list is empty, the list's
 * head is not locked for prev and the caller has NULL in back.prev, thus does
 * not call this function.
 */
static inline void _mt_list_unlock_prev(struct mt_list *el, struct mt_list *back)
{
	el->prev = back;
	__atomic_thread_fence(__ATOMIC_RELEASE);

	back->next = el;
}


/* Locks the link designated by element <el>'s next pointer and returns its
 * previous value. If the element does not loop over itself (empty list head),
 * its reciprocal prev pointer is locked as well. This check is necessary
 * because we don't want to lock the head twice.
 */
static MT_INLINE struct mt_list *_mt_list_lock_next(struct mt_list *el)
{
	struct mt_list *n, *n2;
	unsigned long loops = 0;

	for (;; mt_list_cpu_relax(loops = loops * 8 + 7)) {
		if (__atomic_load_n(&el->next, __ATOMIC_RELAXED) == MT_LIST_BUSY)
			continue;
		n = __atomic_exchange_n(&el->next, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (n == MT_LIST_BUSY)
			continue;

		if (n != el) {
			n2 = __atomic_exchange_n(&n->prev, MT_LIST_BUSY, __ATOMIC_RELAXED);
			if (n2 == MT_LIST_BUSY) {
				el->next = n;
				__atomic_thread_fence(__ATOMIC_RELEASE);
				continue;
			}
		}
		break;
	}
	return n;
}


/* Locks the link designated by element <el>'s prev pointer and returns its
 * previous value. The element cannot loop over itself because the caller will
 * only lock the prev pointer on an non-empty list.
 */
static MT_INLINE struct mt_list *_mt_list_lock_prev(struct mt_list *el)
{
	struct mt_list *p, *p2;
	unsigned long loops = 0;

	for (;; mt_list_cpu_relax(loops = loops * 8 + 7)) {
		if (__atomic_load_n(&el->prev, __ATOMIC_RELAXED) == MT_LIST_BUSY)
			continue;
		p = __atomic_exchange_n(&el->prev, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (p == MT_LIST_BUSY)
			continue;

		p2 = __atomic_exchange_n(&p->next, MT_LIST_BUSY, __ATOMIC_RELAXED);
		if (p2 == MT_LIST_BUSY) {
			el->prev = p;
			__atomic_thread_fence(__ATOMIC_RELEASE);
			continue;
		}
		break;
	}
	return p;
}


/* Outer loop of MT_LIST_FOR_EACH_ENTRY_SAFE(). Do not use directly!
 * This loop is only used to unlock the last item after the end of the inner
 * loop is reached or if we break out of it.
 *
 * Trick: item starts with the impossible and unused value MT_LIST_BUSY that is
 * detected as the looping condition to force to enter the loop. The inner loop
 * will first replace it, making the compiler notice that this condition cannot
 * happen after the first iteration, and making it implement exactly one round
 * and no more.
 */
#define _MT_LIST_FOR_EACH_ENTRY_OUTER(item, lh, lm, back)			\
	for (/* init-expr: preset for one iteration */				\
	     (back).prev = NULL,						\
	     (back).next = _mt_list_lock_next(lh),				\
	     (item) = (void*)MT_LIST_BUSY;					\
	     /* condition-expr: only one iteration */				\
	     (void*)(item) == (void*)MT_LIST_BUSY;				\
	     /* loop-expr */							\
	     ({									\
		/* post loop cleanup:						\
		 * gets executed only once to perform cleanup			\
		 * after child loop has finished, or a break happened		\
		 */								\
		if (item != NULL) {						\
			/* last visited item still exists or is the list's head	\
			 * so we have to unlock it. back.prev may be null if 	\
			 * the list is empty and the inner loop did not run.	\
			 */							\
			if (back.prev)						\
				_mt_list_unlock_prev(&item->lm, back.prev);	\
			_mt_list_unlock_next(&item->lm, back.next);		\
		} else {							\
			/* last item was deleted by user, relink is required:	\
			 * prev->next = next					\
			 * next->prev = prev					\
			 * Note that gcc may believe that back.prev may be null \
			 * which is not possible by construction.		\
			 */							\
			MT_ALREADY_CHECKED(back.prev);				\
			mt_list_reconnect(back);				\
		}								\
	     })									\
	)


/* Inner loop of MT_LIST_FOR_EACH_ENTRY_SAFE(). Do not use directly!
 * This loop iterates over all list elements and unlocks the previously visited
 * element. It stops when reaching the list's head, without unlocking the last
 * element, which is left to the outer loop to deal with, just like when hitting
 * a break. In order to preserve the locking, the loop takes care of always
 * locking the next element before unlocking the previous one. During the first
 * iteration, the prev element might be NULL since the head is singly-locked.
 */
#define _MT_LIST_FOR_EACH_ENTRY_INNER(item, lh, lm, back)			\
	for (/* init-expr */							\
	     item = MT_LIST_ELEM(lh, typeof(item), lm);				\
	     /* cond-expr (thus executed before the body of the loop) */	\
	     (back.next != lh) && ({						\
		struct mt_list *__tmp_next = back.next;				\
		/* did not reach end of list yet */				\
		back.next = _mt_list_lock_next(back.next);			\
		if (item != NULL) {						\
			/* previous item was not deleted, we must unlock it */	\
			if (back.prev) {					\
				/* not executed on first run			\
				 * (back.prev == NULL on first run)		\
				 */						\
				_mt_list_unlock_prev(&item->lm, back.prev);	\
				/* unlock_prev will implicitly relink:		\
				 * item->lm.prev = prev				\
				 * prev->next = &item->lm			\
				 */						\
			}							\
			back.prev = &item->lm;					\
		}								\
		(item) = MT_LIST_ELEM(__tmp_next, typeof(item), lm);		\
		1; /* end of list not reached, we must execute */       	\
	     });								\
	     /* empty loop-expr */						\
	)

#endif /* _MT_LIST_H */
