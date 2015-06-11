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

#include <eb64tree.h>

/* The LRU supports a global cache shared between multiple domains and multiple
 * versions of their datasets. The purpose is not to have to flush the whole
 * LRU once a key is updated and not valid anymore (eg: ACL files), as well as
 * to reliably support concurrent accesses and handle conflicts gracefully. For
 * each key a pointer to a dataset and its internal data revision are stored.
 * All lookups verify that these elements match those passed by the caller and
 * only return a valid entry upon matching. Otherwise the entry is either
 * allocated or recycled and considered new. New entries are always initialized
 * with a NULL domain pointer which is used by the caller to detect that the
 * entry is new and must be populated. Such entries never expire and are
 * protected from the risk of being recycled. It's then the caller's
 * responsibility to perform the operation and commit the entry with its latest
 * result. This domain thus serves as a lock to protect the entry during all
 * the computation needed to update it. In a simple use case where the cache is
 * dedicated, it is recommended to pass the LRU head as the domain pointer and
 * for example zero as the revision. The most common use case for the caller
 * consists in simply checking that the return is not null and that the domain
 * is not null, then to use the result. The get() function returns null if it
 * cannot allocate a node (memory or key being currently updated).
 */
struct lru64_list {
	struct lru64_list *n;
	struct lru64_list *p;
};

struct lru64_head {
	struct lru64_list list;
	struct eb_root keys;
	struct lru64  *spare;
	int cache_size;
	int cache_usage;
};

struct lru64 {
	struct eb64_node node;        /* indexing key, typically a hash64 */
	struct lru64_list lru;        /* LRU list */
	void *domain;                 /* who this data belongs to */
	unsigned long long revision;  /* data revision (to avoid use-after-free) */
	void *data;                   /* returned value, user decides how to use this */
	void (*free)(void *data);     /* function to release data, if needed */
};


struct lru64 *lru64_lookup(unsigned long long key, struct lru64_head *lru, void *domain, unsigned long long revision);
struct lru64 *lru64_get(unsigned long long key, struct lru64_head *lru, void *domain, unsigned long long revision);
void lru64_commit(struct lru64 *elem, void *data, void *domain, unsigned long long revision, void (*free)(void *));
struct lru64_head *lru64_new(int size);
int lru64_destroy(struct lru64_head *lru);
