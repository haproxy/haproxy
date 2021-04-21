/*
 * include/haproxy/pool.h
 * Memory management definitions..
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_POOL_H
#define _HAPROXY_POOL_H

#include <string.h>

#include <haproxy/api.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/list.h>
#include <haproxy/pool-os.h>
#include <haproxy/pool-t.h>
#include <haproxy/thread.h>

/* This registers a call to create_pool_callback(ptr, name, size) */
#define REGISTER_POOL(ptr, name, size)  \
	INITCALL3(STG_POOL, create_pool_callback, (ptr), (name), (size))

/* This macro declares a pool head <ptr> and registers its creation */
#define DECLARE_POOL(ptr, name, size)   \
	struct pool_head *(ptr) __read_mostly = NULL; \
	REGISTER_POOL(&ptr, name, size)

/* This macro declares a static pool head <ptr> and registers its creation */
#define DECLARE_STATIC_POOL(ptr, name, size) \
	static struct pool_head *(ptr) __read_mostly; \
	REGISTER_POOL(&ptr, name, size)

/* poison each newly allocated area with this byte if >= 0 */
extern int mem_poison_byte;

void *pool_get_from_os(struct pool_head *pool);
void pool_put_to_os(struct pool_head *pool, void *ptr);
void *pool_alloc_nocache(struct pool_head *pool);
void pool_free_nocache(struct pool_head *pool, void *ptr);
void dump_pools_to_trash();
void dump_pools(void);
int pool_total_failures();
unsigned long pool_total_allocated();
unsigned long pool_total_used();
void pool_flush(struct pool_head *pool);
void pool_gc(struct pool_head *pool_ctx);
struct pool_head *create_pool(char *name, unsigned int size, unsigned int flags);
void create_pool_callback(struct pool_head **ptr, char *name, unsigned int size);
void *pool_destroy(struct pool_head *pool);
void pool_destroy_all();
int mem_should_fail(const struct pool_head *pool);


#ifdef CONFIG_HAP_POOLS

/****************** Thread-local cache management ******************/

extern THREAD_LOCAL size_t pool_cache_bytes;   /* total cache size */
extern THREAD_LOCAL size_t pool_cache_count;   /* #cache objects   */

void pool_evict_from_local_cache(struct pool_head *pool);
void pool_evict_from_local_caches();
void pool_put_to_cache(struct pool_head *pool, void *ptr);

/* returns true if the pool is considered to have too many free objects */
static inline int pool_is_crowded(const struct pool_head *pool)
{
	return pool->allocated >= swrate_avg(pool->needed_avg + pool->needed_avg / 4, POOL_AVG_SAMPLES) &&
	       (int)(pool->allocated - pool->used) >= pool->minavail;
}


#if defined(CONFIG_HAP_NO_GLOBAL_POOLS)

/* this is essentially used with local caches and a fast malloc library,
 * which may sometimes be faster than the local shared pools because it
 * will maintain its own per-thread arenas.
 */
static inline void *pool_get_from_shared_cache(struct pool_head *pool)
{
	return NULL;
}

static inline void pool_put_to_shared_cache(struct pool_head *pool, void *ptr)
{
	pool_free_nocache(pool, ptr);
}

#elif defined(CONFIG_HAP_LOCKLESS_POOLS)

/****************** Lockless pools implementation ******************/

/*
 * Returns a pointer to type <type> taken from the pool <pool_type> if
 * available, otherwise returns NULL. No malloc() is attempted, and poisonning
 * is never performed. The purpose is to get the fastest possible allocation.
 */
static inline void *pool_get_from_shared_cache(struct pool_head *pool)
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
	} while (HA_ATOMIC_DWCAS((void *)&pool->free_list, (void *)&cmp, (void *)&new) == 0);
	__ha_barrier_atomic_store();

	_HA_ATOMIC_INC(&pool->used);
#ifdef DEBUG_MEMORY_POOLS
	/* keep track of where the element was allocated from */
	*POOL_LINK(pool, cmp.free_list) = (void *)pool;
#endif
	return cmp.free_list;
}

/* Locklessly add item <ptr> to pool <pool>, then update the pool used count.
 * Both the pool and the pointer must be valid. Use pool_free() for normal
 * operations.
 */
static inline void pool_put_to_shared_cache(struct pool_head *pool, void *ptr)
{
	void **free_list = pool->free_list;

	_HA_ATOMIC_DEC(&pool->used);

	if (unlikely(pool_is_crowded(pool))) {
		pool_put_to_os(pool, ptr);
	} else {
		do {
			*POOL_LINK(pool, ptr) = (void *)free_list;
			__ha_barrier_store();
		} while (!_HA_ATOMIC_CAS(&pool->free_list, &free_list, ptr));
		__ha_barrier_atomic_store();
	}
	swrate_add(&pool->needed_avg, POOL_AVG_SAMPLES, pool->used);
}

#else /* CONFIG_HAP_LOCKLESS_POOLS */

/****************** Locked pools implementation ******************/

/*
 * Returns a pointer to type <type> taken from the pool <pool_type> if
 * available, otherwise returns NULL. No malloc() is attempted, and poisonning
 * is never performed. The purpose is to get the fastest possible allocation.
 * This version takes the pool's lock in order to do this.
 */
static inline void *pool_get_from_shared_cache(struct pool_head *pool)
{
	void *p;

	HA_SPIN_LOCK(POOL_LOCK, &pool->lock);
	if ((p = pool->free_list) != NULL)
		pool->free_list = *POOL_LINK(pool, p);
	HA_SPIN_UNLOCK(POOL_LOCK, &pool->lock);
	if (p)
		_HA_ATOMIC_INC(&pool->used);

#ifdef DEBUG_MEMORY_POOLS
	if (p) {
		/* keep track of where the element was allocated from */
		*POOL_LINK(pool, p) = (void *)pool;
	}
#endif
	return p;
}

/* unconditionally stores the object as-is into the global pool. The object
 * must not be NULL. Use pool_free() instead.
 */
static inline void pool_put_to_shared_cache(struct pool_head *pool, void *ptr)
{
	_HA_ATOMIC_DEC(&pool->used);

#ifndef DEBUG_UAF /* normal pool behaviour */

	HA_SPIN_LOCK(POOL_LOCK, &pool->lock);
	if (!pool_is_crowded(pool)) {
		*POOL_LINK(pool, ptr) = (void *)pool->free_list;
		pool->free_list = (void *)ptr;
		ptr = NULL;
	}
	HA_SPIN_UNLOCK(POOL_LOCK, &pool->lock);

#else
	/* release the entry for real to detect use after free */
	/* ensure we crash on double free or free of a const area */
	*(uint32_t *)ptr = 0xDEADADD4;

#endif /* DEBUG_UAF */

	if (ptr) {
		/* still not freed */
		pool_put_to_os(pool, ptr);
	}
	swrate_add(&pool->needed_avg, POOL_AVG_SAMPLES, pool->used);
}

#endif /* CONFIG_HAP_LOCKLESS_POOLS */

/* These are generic cache-aware wrappers that allocate/free from/to the local
 * cache first, then from the second level if it exists.
 */

/* Tries to retrieve an object from the local pool cache corresponding to pool
 * <pool>. If none is available, tries to allocate from the shared cache, and
 * returns NULL if nothing is available.
 */
static inline void *pool_get_from_cache(struct pool_head *pool)
{
	struct pool_cache_item *item;
	struct pool_cache_head *ph;

	ph = &pool->cache[tid];
	if (LIST_ISEMPTY(&ph->list))
		return pool_get_from_shared_cache(pool);

	item = LIST_NEXT(&ph->list, typeof(item), by_pool);
	ph->count--;
	pool_cache_bytes -= pool->size;
	pool_cache_count--;
	LIST_DELETE(&item->by_pool);
	LIST_DELETE(&item->by_lru);
#ifdef DEBUG_MEMORY_POOLS
	/* keep track of where the element was allocated from */
	*POOL_LINK(pool, item) = (void *)pool;
#endif
	return item;
}

#else /* CONFIG_HAP_POOLS */

/* no cache pools implementation */

static inline void *pool_get_from_cache(struct pool_head *pool)
{
	return NULL;
}

static inline void pool_put_to_cache(struct pool_head *pool, void *ptr)
{
	pool_free_nocache(pool, ptr);
}

#endif /* CONFIG_HAP_POOLS */


/****************** Common high-level code ******************/

/*
 * Returns a pointer to type <type> taken from the pool <pool_type> or
 * dynamically allocated. In the first case, <pool_type> is updated to point to
 * the next element in the list. <flags> is a binary-OR of POOL_F_* flags.
 * Prefer using pool_alloc() which does the right thing without flags.
 */
static inline void *__pool_alloc(struct pool_head *pool, unsigned int flags)
{
	void *p = NULL;

#ifdef DEBUG_FAIL_ALLOC
	if (!(flags & POOL_F_NO_FAIL) && mem_should_fail(pool))
		return NULL;
#endif

	if (!p)
		p = pool_get_from_cache(pool);
	if (!p)
		p = pool_alloc_nocache(pool);

	if (p) {
		if (flags & POOL_F_MUST_ZERO)
			memset(p, 0, pool->size);
		else if (!(flags & POOL_F_NO_POISON) && mem_poison_byte >= 0)
			memset(p, mem_poison_byte, pool->size);
	}
	return p;
}

/*
 * Returns a pointer to type <type> taken from the pool <pool_type> or
 * dynamically allocated. Memory poisonning is performed if enabled.
 */
static inline void *pool_alloc(struct pool_head *pool)
{
	return __pool_alloc(pool, 0);
}

/*
 * Returns a pointer to type <type> taken from the pool <pool_type> or
 * dynamically allocated. The area is zeroed.
 */
static inline void *pool_zalloc(struct pool_head *pool)
{
	return __pool_alloc(pool, POOL_F_MUST_ZERO);
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
#ifdef DEBUG_MEMORY_POOLS
		/* we'll get late corruption if we refill to the wrong pool or double-free */
		if (*POOL_LINK(pool, ptr) != (void *)pool)
			ABORT_NOW();
#endif
		if (unlikely(mem_poison_byte >= 0))
			memset(ptr, mem_poison_byte, pool->size);

		pool_put_to_cache(pool, ptr);
	}
}

#endif /* _HAPROXY_POOL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
