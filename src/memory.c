/*
 * Memory management functions.
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <types/global.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>

#include <proto/log.h>

static struct list pools = LIST_HEAD_INIT(pools);
char mem_poison_byte = 0;

/* Try to find an existing shared pool with the same characteristics and
 * returns it, otherwise creates this one. NULL is returned if no memory
 * is available for a new creation.
 */
struct pool_head *create_pool(char *name, unsigned int size, unsigned int flags)
{
	struct pool_head *pool;
	struct pool_head *entry;
	struct list *start;
	unsigned int align;

	/* We need to store at least a (void *) in the chunks. Since we know
	 * that the malloc() function will never return such a small size,
	 * let's round the size up to something slightly bigger, in order to
	 * ease merging of entries. Note that the rounding is a power of two.
	 */

	align = 16;
	size  = (size + align - 1) & -align;

	start = &pools;
	pool = NULL;

	list_for_each_entry(entry, &pools, list) {
		if (entry->size == size) {
			/* either we can share this place and we take it, or
			 * we look for a sharable one or for the next position
			 * before which we will insert a new one.
			 */
			if (flags & entry->flags & MEM_F_SHARED) {
				/* we can share this one */
				pool = entry;
				DPRINTF(stderr, "Sharing %s with %s\n", name, pool->name);
				break;
			}
		}
		else if (entry->size > size) {
			/* insert before this one */
			start = &entry->list;
			break;
		}
	}

	if (!pool) {
		pool = CALLOC(1, sizeof(*pool));
		if (!pool)
			return NULL;
		if (name)
			strlcpy2(pool->name, name, sizeof(pool->name));
		pool->size = size;
		pool->flags = flags;
		LIST_ADDQ(start, &pool->list);
	}
	pool->users++;
	return pool;
}

/* Allocate a new entry for pool <pool>, and return it for immediate use.
 * NULL is returned if no memory is available for a new creation. A call
 * to the garbage collector is performed before returning NULL.
 */
void *pool_refill_alloc(struct pool_head *pool)
{
	void *ret;

	if (pool->limit && (pool->allocated >= pool->limit))
		return NULL;
	ret = CALLOC(1, pool->size);
	if (!ret) {
		pool_gc2();
		ret = CALLOC(1, pool->size);
		if (!ret)
			return NULL;
	}
	if (mem_poison_byte)
		memset(ret, mem_poison_byte, pool->size);
	pool->allocated++;
	pool->used++;
	return ret;
}

/*
 * This function frees whatever can be freed in pool <pool>.
 */
void pool_flush2(struct pool_head *pool)
{
	void *temp, *next;
	if (!pool)
		return;

	next = pool->free_list;
	while (next) {
		temp = next;
		next = *(void **)temp;
		pool->allocated--;
		FREE(temp);
	}
	pool->free_list = next;

	/* here, we should have pool->allocate == pool->used */
}

/*
 * This function frees whatever can be freed in all pools, but respecting
 * the minimum thresholds imposed by owners. It takes care of avoiding
 * recursion because it may be called from a signal handler.
 */
void pool_gc2()
{
	static int recurse;
	struct pool_head *entry;

	if (recurse++)
		goto out;

	list_for_each_entry(entry, &pools, list) {
		void *temp, *next;
		//qfprintf(stderr, "Flushing pool %s\n", entry->name);
		next = entry->free_list;
		while (next &&
		       entry->allocated > entry->minavail &&
		       entry->allocated > entry->used) {
			temp = next;
			next = *(void **)temp;
			entry->allocated--;
			FREE(temp);
		}
		entry->free_list = next;
	}
 out:
	recurse--;
}

/*
 * This function destroys a pool by freeing it completely, unless it's still
 * in use. This should be called only under extreme circumstances. It always
 * returns NULL if the resulting pool is empty, easing the clearing of the old
 * pointer, otherwise it returns the pool.
 * .
 */
void *pool_destroy2(struct pool_head *pool)
{
	if (pool) {
		pool_flush2(pool);
		if (pool->used)
			return pool;
		pool->users--;
		if (!pool->users) {
			LIST_DEL(&pool->list);
			FREE(pool);
		}
	}
	return NULL;
}

/* This function dumps memory usage information into the trash buffer. */
void dump_pools_to_trash()
{
	struct pool_head *entry;
	unsigned long allocated, used;
	int nbpools;

	allocated = used = nbpools = 0;
	chunk_printf(&trash, "Dumping pools usage. Use SIGQUIT to flush them.\n");
	list_for_each_entry(entry, &pools, list) {
		chunk_appendf(&trash, "  - Pool %s (%d bytes) : %d allocated (%u bytes), %d used, %d users%s\n",
			 entry->name, entry->size, entry->allocated,
			 entry->size * entry->allocated, entry->used,
			 entry->users, (entry->flags & MEM_F_SHARED) ? " [SHARED]" : "");

		allocated += entry->allocated * entry->size;
		used += entry->used * entry->size;
		nbpools++;
	}
	chunk_appendf(&trash, "Total: %d pools, %lu bytes allocated, %lu used.\n",
		 nbpools, allocated, used);
}

/* Dump statistics on pools usage. */
void dump_pools(void)
{
	dump_pools_to_trash();
	qfprintf(stderr, "%s", trash.str);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
