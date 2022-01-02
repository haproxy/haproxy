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

/* By default, free objects are linked by a pointer stored at the beginning of
 * the memory area. When DEBUG_MEMORY_POOLS is set, the allocated area is
 * inflated by the size of a pointer so that the link is placed at the end
 * of the objects. Hence free objects in pools remain intact. In addition,
 * this location is used to keep a pointer to the pool the object was
 * allocated from, and verify it's freed into the appropriate one.
 */
#ifdef DEBUG_MEMORY_POOLS

# define POOL_EXTRA (sizeof(void *))
# define POOL_DEBUG_SET_MARK(pool, item)				\
	do {								\
		typeof(pool) __p = (pool);				\
		typeof(item) __i = (item);				\
		*(typeof(pool)*)(((char *)__i) + __p->size) = __p;	\
	} while (0)

# define POOL_DEBUG_CHECK_MARK(pool, item)				\
	do {								\
		typeof(pool) __p = (pool);				\
		typeof(item) __i = (item);				\
		if (*(typeof(pool)*)(((char *)__i) + __p->size) != __p)	\
			ABORT_NOW();					\
	} while (0)

#else // DEBUG_MEMORY_POOLS

# define POOL_EXTRA (0)
# define POOL_DEBUG_SET_MARK(pool, item)   do { } while (0)
# define POOL_DEBUG_CHECK_MARK(pool, item) do { } while (0)

#endif // DEBUG_MEMORY_POOLS

/* poison each newly allocated area with this byte if >= 0 */
extern int mem_poison_byte;

void *pool_get_from_os(struct pool_head *pool);
void pool_put_to_os(struct pool_head *pool, void *ptr);
void *pool_alloc_nocache(struct pool_head *pool);
void pool_free_nocache(struct pool_head *pool, void *ptr);
void dump_pools_to_trash(void);
void dump_pools(void);
int pool_total_failures(void);
unsigned long pool_total_allocated(void);
unsigned long pool_total_used(void);
void pool_flush(struct pool_head *pool);
void pool_gc(struct pool_head *pool_ctx);
struct pool_head *create_pool(char *name, unsigned int size, unsigned int flags);
void create_pool_callback(struct pool_head **ptr, char *name, unsigned int size);
void *pool_destroy(struct pool_head *pool);
void pool_destroy_all(void);
int mem_should_fail(const struct pool_head *pool);


#ifdef CONFIG_HAP_POOLS

/****************** Thread-local cache management ******************/

extern THREAD_LOCAL size_t pool_cache_bytes;   /* total cache size */
extern THREAD_LOCAL size_t pool_cache_count;   /* #cache objects   */

void pool_evict_from_local_cache(struct pool_head *pool);
void pool_evict_from_local_caches(void);
void pool_put_to_cache(struct pool_head *pool, void *ptr);

#if defined(CONFIG_HAP_NO_GLOBAL_POOLS)

static inline int pool_is_crowded(const struct pool_head *pool)
{
	/* no shared pools, hence they're always full */
	return 1;
}

static inline uint pool_releasable(const struct pool_head *pool)
{
	/* no room left */
	return 0;
}

static inline void pool_refill_local_from_shared(struct pool_head *pool, struct pool_cache_head *pch)
{
	/* ignored without shared pools */
}

static inline void pool_put_to_shared_cache(struct pool_head *pool, struct pool_item *item, uint count)
{
	/* ignored without shared pools */
}

#else /* CONFIG_HAP_NO_GLOBAL_POOLS */

void pool_refill_local_from_shared(struct pool_head *pool, struct pool_cache_head *pch);
void pool_put_to_shared_cache(struct pool_head *pool, struct pool_item *item, uint count);

/* returns true if the pool is considered to have too many free objects */
static inline int pool_is_crowded(const struct pool_head *pool)
{
	return pool->allocated >= swrate_avg(pool->needed_avg + pool->needed_avg / 4, POOL_AVG_SAMPLES) &&
	       (int)(pool->allocated - pool->used) >= pool->minavail;
}

/* Returns the max number of entries that may be brought back to the pool
 * before it's considered as full. Note that it is only usable for releasing
 * objects, hence the function assumes that no more than ->used entries will
 * be released in the worst case, and that this value is always lower than or
 * equal to ->allocated. It's important to understand that under thread
 * contention these values may not always be accurate but the principle is that
 * any deviation remains contained.
 */
static inline uint pool_releasable(const struct pool_head *pool)
{
	uint alloc, used;

	alloc = HA_ATOMIC_LOAD(&pool->allocated);
	used = HA_ATOMIC_LOAD(&pool->used);
	if (used < alloc)
		used = alloc;

	if (alloc < swrate_avg(pool->needed_avg + pool->needed_avg / 4, POOL_AVG_SAMPLES))
		return used; // less than needed is allocated, can release everything

	if ((uint)(alloc - used) < pool->minavail)
		return pool->minavail - (alloc - used); // less than minimum available

	/* there are enough objects in this pool */
	return 0;
}


#endif /* CONFIG_HAP_NO_GLOBAL_POOLS */

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
	if (unlikely(LIST_ISEMPTY(&ph->list))) {
		pool_refill_local_from_shared(pool, ph);
		if (LIST_ISEMPTY(&ph->list))
			return NULL;
	}

	item = LIST_NEXT(&ph->list, typeof(item), by_pool);
	LIST_DELETE(&item->by_pool);
	LIST_DELETE(&item->by_lru);

	/* keep track of where the element was allocated from */
	POOL_DEBUG_SET_MARK(pool, item);

	ph->count--;
	pool_cache_bytes -= pool->size;
	pool_cache_count--;

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
		/* we'll get late corruption if we refill to the wrong pool or double-free */
		POOL_DEBUG_CHECK_MARK(pool, ptr);

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
