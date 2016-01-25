/*
 * include/common/memory.h
 * Memory management definitions..
 *
 * Copyright (C) 2000-2014 Willy Tarreau - w@1wt.eu
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

#ifndef _COMMON_MEMORY_H
#define _COMMON_MEMORY_H

#include <stdlib.h>
#include <string.h>

#include <common/config.h>
#include <common/mini-clist.h>

#ifndef DEBUG_DONT_SHARE_POOLS
#define MEM_F_SHARED	0x1
#else
#define MEM_F_SHARED	0
#endif
#define MEM_F_EXACT	0x2

/* reserve an extra void* at the end of a pool for linking */
#ifdef DEBUG_MEMORY_POOLS
#define POOL_EXTRA (sizeof(void *))
#define POOL_LINK(pool, item) (void **)(((char *)item) + (pool->size))
#else
#define POOL_EXTRA (0)
#define POOL_LINK(pool, item) ((void **)(item))
#endif

struct pool_head {
	void **free_list;
	struct list list;	/* list of all known pools */
	unsigned int used;	/* how many chunks are currently in use */
	unsigned int allocated;	/* how many chunks have been allocated */
	unsigned int limit;	/* hard limit on the number of chunks */
	unsigned int minavail;	/* how many chunks are expected to be used */
	unsigned int size;	/* chunk size */
	unsigned int flags;	/* MEM_F_* */
	unsigned int users;	/* number of pools sharing this zone */
	unsigned int failed;	/* failed allocations */
	char name[12];		/* name of the pool */
};

/* poison each newly allocated area with this byte if >= 0 */
extern int mem_poison_byte;

/*
 * This function destroys a pull by freeing it completely.
 * This should be called only under extreme circumstances.
 */
static inline void pool_destroy(void **pool)
{
	void *temp, *next;
	next = pool;
	while (next) {
		temp = next;
		next = *(void **)temp;
		free(temp);
	}
}

/* Allocates new entries for pool <pool> until there are at least <avail> + 1
 * available, then returns the last one for immediate use, so that at least
 * <avail> are left available in the pool upon return. NULL is returned if the
 * last entry could not be allocated. It's important to note that at least one
 * allocation is always performed even if there are enough entries in the pool.
 * A call to the garbage collector is performed at most once in case malloc()
 * returns an error, before returning NULL.
 */
void *pool_refill_alloc(struct pool_head *pool, unsigned int avail);

/* Try to find an existing shared pool with the same characteristics and
 * returns it, otherwise creates this one. NULL is returned if no memory
 * is available for a new creation.
 */
struct pool_head *create_pool(char *name, unsigned int size, unsigned int flags);

/* Dump statistics on pools usage.
 */
void dump_pools_to_trash();
void dump_pools(void);
int pool_total_failures();
unsigned long pool_total_allocated();
unsigned long pool_total_used();

/*
 * This function frees whatever can be freed in pool <pool>.
 */
void pool_flush2(struct pool_head *pool);

/*
 * This function frees whatever can be freed in all pools, but respecting
 * the minimum thresholds imposed by owners.
 */
void pool_gc2();

/*
 * This function destroys a pull by freeing it completely.
 * This should be called only under extreme circumstances.
 */
void *pool_destroy2(struct pool_head *pool);

/*
 * Returns a pointer to type <type> taken from the pool <pool_type> if
 * available, otherwise returns NULL. No malloc() is attempted, and poisonning
 * is never performed. The purpose is to get the fastest possible allocation.
 */
static inline void *pool_get_first(struct pool_head *pool)
{
	void *p;

	if ((p = pool->free_list) != NULL) {
		pool->free_list = *POOL_LINK(pool, p);
		pool->used++;
#ifdef DEBUG_MEMORY_POOLS
		/* keep track of where the element was allocated from */
		*POOL_LINK(pool, p) = (void *)pool;
#endif
	}
	return p;
}

/*
 * Returns a pointer to type <type> taken from the pool <pool_type> or
 * dynamically allocated. In the first case, <pool_type> is updated to point to
 * the next element in the list. No memory poisonning is ever performed on the
 * returned area.
 */
static inline void *pool_alloc_dirty(struct pool_head *pool)
{
	void *p;

	if ((p = pool_get_first(pool)) == NULL)
		p = pool_refill_alloc(pool, 0);

	return p;
}

/*
 * Returns a pointer to type <type> taken from the pool <pool_type> or
 * dynamically allocated. In the first case, <pool_type> is updated to point to
 * the next element in the list. Memory poisonning is performed if enabled.
 */
static inline void *pool_alloc2(struct pool_head *pool)
{
	void *p;

	p = pool_alloc_dirty(pool);
#ifdef DEBUG_MEMORY_POOLS
	if (p) {
		/* keep track of where the element was allocated from */
		*POOL_LINK(pool, p) = (void *)pool;
	}
#endif
	if (p && mem_poison_byte >= 0) {
		memset(p, mem_poison_byte, pool->size);
	}

	return p;
}

/*
 * Puts a memory area back to the corresponding pool.
 * Items are chained directly through a pointer that
 * is written in the beginning of the memory area, so
 * there's no need for any carrier cell. This implies
 * that each memory area is at least as big as one
 * pointer. Just like with the libc's free(), nothing
 * is done if <ptr> is NULL.
 */
static inline void pool_free2(struct pool_head *pool, void *ptr)
{
        if (likely(ptr != NULL)) {
#ifdef DEBUG_MEMORY_POOLS
		/* we'll get late corruption if we refill to the wrong pool or double-free */
		if (*POOL_LINK(pool, ptr) != (void *)pool)
			*(int *)0 = 0;
#endif
		*POOL_LINK(pool, ptr) = (void *)pool->free_list;
                pool->free_list = (void *)ptr;
                pool->used--;
	}
}


#endif /* _COMMON_MEMORY_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
