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

#include <sys/mman.h>

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <common/config.h>
#include <common/mini-clist.h>
#include <common/hathreads.h>

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

#ifdef CONFIG_HAP_LOCKLESS_POOLS
struct pool_free_list {
	void **free_list;
	uintptr_t seq;
};
#endif

struct pool_head {
	void **free_list;
#ifdef CONFIG_HAP_LOCKLESS_POOLS
	uintptr_t seq;
#else
	__decl_hathreads(HA_SPINLOCK_T lock); /* the spin lock */
#endif
	unsigned int used;	/* how many chunks are currently in use */
	unsigned int allocated;	/* how many chunks have been allocated */
	unsigned int limit;	/* hard limit on the number of chunks */
	unsigned int minavail;	/* how many chunks are expected to be used */
	unsigned int size;	/* chunk size */
	unsigned int flags;	/* MEM_F_* */
	unsigned int users;	/* number of pools sharing this zone */
	unsigned int failed;	/* failed allocations */
	struct list list;	/* list of all known pools */
	char name[12];		/* name of the pool */
} __attribute__((aligned(64)));

/* poison each newly allocated area with this byte if >= 0 */
extern int mem_poison_byte;

/* Allocates new entries for pool <pool> until there are at least <avail> + 1
 * available, then returns the last one for immediate use, so that at least
 * <avail> are left available in the pool upon return. NULL is returned if the
 * last entry could not be allocated. It's important to note that at least one
 * allocation is always performed even if there are enough entries in the pool.
 * A call to the garbage collector is performed at most once in case malloc()
 * returns an error, before returning NULL.
 */
void *__pool_refill_alloc(struct pool_head *pool, unsigned int avail);
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
void pool_flush(struct pool_head *pool);

/*
 * This function frees whatever can be freed in all pools, but respecting
 * the minimum thresholds imposed by owners.
 *
 * <pool_ctx> is used when pool_gc is called to release resources to allocate
 * an element in __pool_refill_alloc. It is important because <pool_ctx> is
 * already locked, so we need to skip the lock here.
 */
void pool_gc(struct pool_head *pool_ctx);

/*
 * This function destroys a pull by freeing it completely.
 * This should be called only under extreme circumstances.
 */
void *pool_destroy(struct pool_head *pool);

#ifdef CONFIG_HAP_LOCKLESS_POOLS
/*
 * Returns a pointer to type <type> taken from the pool <pool_type> if
 * available, otherwise returns NULL. No malloc() is attempted, and poisonning
 * is never performed. The purpose is to get the fastest possible allocation.
 */
static inline void *__pool_get_first(struct pool_head *pool)
{
	struct pool_free_list cmp, new;

	cmp.seq = pool->seq;
	__ha_barrier_load();

	cmp.free_list = pool->free_list;
	do {
		if (cmp.free_list == NULL)
			return NULL;
		new.seq = cmp.seq + 1;
		__ha_barrier_load();
		new.free_list = *POOL_LINK(pool, cmp.free_list);
	} while (__ha_cas_dw((void *)&pool->free_list, (void *)&cmp, (void *)&new) == 0);

	HA_ATOMIC_ADD(&pool->used, 1);
#ifdef DEBUG_MEMORY_POOLS
	/* keep track of where the element was allocated from */
	*POOL_LINK(pool, cmp.free_list) = (void *)pool;
#endif
	return cmp.free_list;
}

static inline void *pool_get_first(struct pool_head *pool)
{
	void *ret;

	ret = __pool_get_first(pool);
	return ret;
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

	if ((p = __pool_get_first(pool)) == NULL)
		p = __pool_refill_alloc(pool, 0);
	return p;
}

/*
 * Returns a pointer to type <type> taken from the pool <pool_type> or
 * dynamically allocated. In the first case, <pool_type> is updated to point to
 * the next element in the list. Memory poisonning is performed if enabled.
 */
static inline void *pool_alloc(struct pool_head *pool)
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
static inline void pool_free(struct pool_head *pool, void *ptr)
{
        if (likely(ptr != NULL)) {
		void *free_list;
#ifdef DEBUG_MEMORY_POOLS
		/* we'll get late corruption if we refill to the wrong pool or double-free */
		if (*POOL_LINK(pool, ptr) != (void *)pool)
			*(volatile int *)0 = 0;
#endif
		free_list = pool->free_list;
		do {
			*POOL_LINK(pool, ptr) = (void *)free_list;
			__ha_barrier_store();
		} while (!HA_ATOMIC_CAS(&pool->free_list, (void *)&free_list, ptr));

		HA_ATOMIC_SUB(&pool->used, 1);
	}
}

#else /* CONFIG_HAP_LOCKLESS_POOLS */
/*
 * Returns a pointer to type <type> taken from the pool <pool_type> if
 * available, otherwise returns NULL. No malloc() is attempted, and poisonning
 * is never performed. The purpose is to get the fastest possible allocation.
 */
static inline void *__pool_get_first(struct pool_head *pool)
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

static inline void *pool_get_first(struct pool_head *pool)
{
	void *ret;

	HA_SPIN_LOCK(POOL_LOCK, &pool->lock);
	ret = __pool_get_first(pool);
	HA_SPIN_UNLOCK(POOL_LOCK, &pool->lock);
	return ret;
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

	HA_SPIN_LOCK(POOL_LOCK, &pool->lock);
	if ((p = __pool_get_first(pool)) == NULL)
		p = __pool_refill_alloc(pool, 0);
	HA_SPIN_UNLOCK(POOL_LOCK, &pool->lock);
	return p;
}

#ifndef DEBUG_UAF /* normal allocator */

/* allocates an area of size <size> and returns it. The semantics are similar
 * to those of malloc().
 */
static inline void *pool_alloc_area(size_t size)
{
	return malloc(size);
}

/* frees an area <area> of size <size> allocated by pool_alloc_area(). The
 * semantics are identical to free() except that the size is specified and
 * may be ignored.
 */
static inline void pool_free_area(void *area, size_t __maybe_unused size)
{
	free(area);
}

#else  /* use-after-free detector */

/* allocates an area of size <size> and returns it. The semantics are similar
 * to those of malloc(). However the allocation is rounded up to 4kB so that a
 * full page is allocated. This ensures the object can be freed alone so that
 * future dereferences are easily detected. The returned object is always
 * 16-bytes aligned to avoid issues with unaligned structure objects. In case
 * some padding is added, the area's start address is copied at the end of the
 * padding to help detect underflows.
 */
static inline void *pool_alloc_area(size_t size)
{
	size_t pad = (4096 - size) & 0xFF0;
	void *ret;

	ret = mmap(NULL, (size + 4095) & -4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
	if (ret == MAP_FAILED)
		return NULL;
	if (pad >= sizeof(void *))
		*(void **)(ret + pad - sizeof(void *)) = ret + pad;
	return ret + pad;
}

/* frees an area <area> of size <size> allocated by pool_alloc_area(). The
 * semantics are identical to free() except that the size must absolutely match
 * the one passed to pool_alloc_area(). In case some padding is added, the
 * area's start address is compared to the one at the end of the padding, and
 * a segfault is triggered if they don't match, indicating an underflow.
 */
static inline void pool_free_area(void *area, size_t size)
{
	size_t pad = (4096 - size) & 0xFF0;

	if (pad >= sizeof(void *) && *(void **)(area - sizeof(void *)) != area)
		*(volatile int *)0 = 0;

	munmap(area - pad, (size + 4095) & -4096);
}

#endif /* DEBUG_UAF */

/*
 * Returns a pointer to type <type> taken from the pool <pool_type> or
 * dynamically allocated. In the first case, <pool_type> is updated to point to
 * the next element in the list. Memory poisonning is performed if enabled.
 */
static inline void *pool_alloc(struct pool_head *pool)
{
	void *p;

	p = pool_alloc_dirty(pool);
#ifdef DEBUG_MEMORY_POOLS
	if (p) {
		HA_SPIN_LOCK(POOL_LOCK, &pool->lock);
		/* keep track of where the element was allocated from */
		*POOL_LINK(pool, p) = (void *)pool;
		HA_SPIN_UNLOCK(POOL_LOCK, &pool->lock);
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
static inline void pool_free(struct pool_head *pool, void *ptr)
{
        if (likely(ptr != NULL)) {
		HA_SPIN_LOCK(POOL_LOCK, &pool->lock);
#ifdef DEBUG_MEMORY_POOLS
		/* we'll get late corruption if we refill to the wrong pool or double-free */
		if (*POOL_LINK(pool, ptr) != (void *)pool)
			*(int *)0 = 0;
#endif

#ifndef DEBUG_UAF /* normal pool behaviour */
		*POOL_LINK(pool, ptr) = (void *)pool->free_list;
                pool->free_list = (void *)ptr;
#else  /* release the entry for real to detect use after free */
		/* ensure we crash on double free or free of a const area*/
		*(uint32_t *)ptr = 0xDEADADD4;
		pool_free_area(ptr, pool->size + POOL_EXTRA);
		pool->allocated--;
#endif /* DEBUG_UAF */
                pool->used--;
		HA_SPIN_UNLOCK(POOL_LOCK, &pool->lock);
	}
}
#endif /* CONFIG_HAP_LOCKLESS_POOLS */
#endif /* _COMMON_MEMORY_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
