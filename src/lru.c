/*
 * Copyright (C) 2015 Willy Tarreau <w@1wt.eu>
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

#include <import/lru.h>

/* Minimal list manipulation macros for lru64_list */
#define LIST_ADD(lh, el) ({ (el)->n = (lh)->n; (el)->n->p = (lh)->n = (el); (el)->p = (lh); })
#define LIST_DEL(el)     ({ (el)->n->p = (el)->p; (el)->p->n = (el)->n; })


/* Lookup key <key> in LRU cache <lru> for use with domain <domain> whose data's
 * current version is <revision>. It differs from lru64_get as it does not
 * create missing keys. The function returns NULL if an error or a cache miss
 * occurs. */
struct lru64 *lru64_lookup(unsigned long long key, struct lru64_head *lru,
			   void *domain, unsigned long long revision)
{
	struct eb64_node *node;
	struct lru64 *elem;

	if (!lru->spare) {
		if (!lru->cache_size)
			return NULL;
		lru->spare = malloc(sizeof(*lru->spare));
		if (!lru->spare)
			return NULL;
		lru->spare->domain = NULL;
	}

	node = __eb64_lookup(&lru->keys, key);
	elem = container_of(node, typeof(*elem), node);
	if (elem) {
		/* Existing entry found, check validity then move it at the
		 * head of the LRU list.
		 */
		if (elem->domain == domain && elem->revision == revision) {
			LIST_DEL(&elem->lru);
			LIST_ADD(&lru->list, &elem->lru);
			return elem;
		}
	}
	return NULL;
}

/* Get key <key> from LRU cache <lru> for use with domain <domain> whose data's
 * current revision is <revision>. If the key doesn't exist it's first created
 * with ->domain = NULL. The caller detects this situation by checking ->domain
 * and must perform the operation to be cached then call lru64_commit() to
 * complete the operation. A lock (mutex or spinlock) may be added around the
 * function to permit use in a multi-threaded environment. The function may
 * return NULL upon memory allocation failure.
 */
struct lru64 *lru64_get(unsigned long long key, struct lru64_head *lru,
			void *domain, unsigned long long revision)
{
	struct eb64_node *node;
	struct lru64 *elem;

	if (!lru->spare) {
		if (!lru->cache_size)
			return NULL;
		lru->spare = malloc(sizeof(*lru->spare));
		if (!lru->spare)
			return NULL;
		lru->spare->domain = NULL;
	}

	/* Lookup or insert */
	lru->spare->node.key = key;
	node = __eb64_insert(&lru->keys, &lru->spare->node);
	elem = container_of(node, typeof(*elem), node);

	if (elem != lru->spare) {
		/* Existing entry found, check validity then move it at the
		 * head of the LRU list.
		 */
		if (elem->domain == domain && elem->revision == revision) {
			LIST_DEL(&elem->lru);
			LIST_ADD(&lru->list, &elem->lru);
			return elem;
		}

		if (!elem->domain)
			return NULL; // currently locked

		/* recycle this entry */
		LIST_DEL(&elem->lru);
	}
	else {
		/* New entry inserted, initialize and move to the head of the
		 * LRU list, and lock it until commit.
		 */
		lru->cache_usage++;
		lru->spare = NULL; // used, need a new one next time
	}

	elem->domain = NULL;
	LIST_ADD(&lru->list, &elem->lru);

	if (lru->cache_usage > lru->cache_size) {
		/* try to kill oldest entry */
		struct lru64 *old;

		old = container_of(lru->list.p, typeof(*old), lru);
		if (old->domain) {
			/* not locked */
			LIST_DEL(&old->lru);
			__eb64_delete(&old->node);
			if (old->data && old->free)
				old->free(old->data);
			if (!lru->spare)
				lru->spare = old;
			else {
				free(old);
			}
			lru->cache_usage--;
		}
	}
	return elem;
}

/* Commit element <elem> with data <data>, domain <domain> and revision
 * <revision>.  <elem> is checked for NULL so that it's possible to call it
 * with the result from a call to lru64_get(). The caller might lock it using a
 * spinlock or mutex shared with the one around lru64_get().
 */
void lru64_commit(struct lru64 *elem, void *data, void *domain,
		  unsigned long long revision, void (*free)(void *))
{
	if (!elem)
		return;

	elem->data = data;
	elem->revision = revision;
	elem->domain = domain;
	elem->free = free;
}

/* Create a new LRU cache of <size> entries. Returns the new cache or NULL in
 * case of allocation failure.
 */
struct lru64_head *lru64_new(int size)
{
	struct lru64_head *lru;

	lru = malloc(sizeof(*lru));
	if (lru) {
		lru->list.p = lru->list.n = &lru->list;
		lru->keys = EB_ROOT_UNIQUE;
		lru->spare = NULL;
		lru->cache_size = size;
		lru->cache_usage = 0;
	}
	return lru;
}

/* Tries to destroy the LRU cache <lru>. Returns the number of locked entries
 * that prevent it from being destroyed, or zero meaning everything was done.
 */
int lru64_destroy(struct lru64_head *lru)
{
	struct lru64 *elem, *next;

	if (!lru)
		return 0;

	elem = container_of(lru->list.p, typeof(*elem), lru);
	while (&elem->lru != &lru->list) {
		next = container_of(elem->lru.p, typeof(*next), lru);
		if (elem->domain) {
			/* not locked */
			LIST_DEL(&elem->lru);
			eb64_delete(&elem->node);
			if (elem->data && elem->free)
				elem->free(elem->data);
			free(elem);
			lru->cache_usage--;
			lru->cache_size--;
		}
		elem = next;
	}

	if (lru->cache_usage)
		return lru->cache_usage;

	free(lru);
	return 0;
}

/* The code below is just for validation and performance testing. It's an
 * example of a function taking some time to return results that could be
 * cached.
 */
#ifdef STANDALONE

#include <stdio.h>

static unsigned int misses;

static unsigned long long sum(unsigned long long x)
{
#ifndef TEST_LRU_FAST_OPERATION
	if (x < 1)
		return 0;
	return x + sum(x * 99 / 100 - 1);
#else
	return (x << 16) - (x << 8) - 1;
#endif
}

static long get_value(struct lru64_head *lru, long a)
{
	struct lru64 *item;

	if (lru) {
		item = lru64_get(a, lru, lru, 0);
		if (item && item->domain)
			return (long)item->data;
	}
	misses++;
	/* do the painful work here */
	a = sum(a);
	if (item)
		lru64_commit(item, (void *)a, lru, 0);
	return a;
}

/* pass #of loops in argv[1] and set argv[2] to something to use the LRU */
int main(int argc, char **argv)
{
	struct lru64_head *lru = NULL;
	long long ret;
	int total, loops;

	if (argc < 2) {
		printf("Need a number of rounds and optionally an LRU cache size (0..65536)\n");
		exit(1);
	}

	total = atoi(argv[1]);

	if (argc > 2) /* cache size */
		lru = lru64_new(atoi(argv[2]));

	ret = 0;
	for (loops = 0; loops < total; loops++) {
		ret += get_value(lru, rand() & 65535);
	}
	/* just for accuracy control */
	printf("ret=%llx, hits=%d, misses=%d (%d %% hits)\n", ret, total-misses, misses, (int)((float)(total-misses) * 100.0 / total));

	while (lru64_destroy(lru));

	return 0;
}

#endif
