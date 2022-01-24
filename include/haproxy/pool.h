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

# define POOL_EXTRA_MARK (sizeof(void *))
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

# define POOL_EXTRA_MARK (0)
# define POOL_DEBUG_SET_MARK(pool, item)   do { } while (0)
# define POOL_DEBUG_CHECK_MARK(pool, item) do { } while (0)

#endif // DEBUG_MEMORY_POOLS

/* It's possible to trace callers of pool_free() by placing their pointer
 * after the end of the area and the optional mark above.
 */
#if defined(DEBUG_POOL_TRACING)
# define POOL_EXTRA_CALLER (sizeof(void *))
# define POOL_DEBUG_TRACE_CALLER(pool, item, caller)			\
	do {								\
		typeof(pool) __p = (pool);				\
		typeof(item) __i = (item);				\
		typeof(caller) __c = (caller);				\
		*(typeof(caller)*)(((char *)__i) + __p->size + POOL_EXTRA_MARK) = __c; \
	} while (0)

#else // DEBUG_POOL_TRACING

# define POOL_EXTRA_CALLER (0)
# define POOL_DEBUG_TRACE_CALLER(pool, item, caller)   do { } while (0)

#endif

# define POOL_EXTRA (POOL_EXTRA_MARK + POOL_EXTRA_CALLER)

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
void *__pool_alloc(struct pool_head *pool, unsigned int flags);
void __pool_free(struct pool_head *pool, void *ptr);


#ifdef CONFIG_HAP_POOLS

/****************** Thread-local cache management ******************/

extern THREAD_LOCAL size_t pool_cache_bytes;   /* total cache size */
extern THREAD_LOCAL size_t pool_cache_count;   /* #cache objects   */

void pool_evict_from_local_cache(struct pool_head *pool);
void pool_evict_from_local_caches(void);
void pool_put_to_cache(struct pool_head *pool, void *ptr, const void *caller);

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

#if defined(DEBUG_POOL_INTEGRITY)

/* Updates <pch>'s fill_pattern and fills the free area after <item> with it,
 * up to <size> bytes. The item part is left untouched.
 */
static inline void pool_fill_pattern(struct pool_cache_head *pch, struct pool_cache_item *item, uint size)
{
	ulong *ptr = (ulong *)item;
	uint ofs;
	ulong u;

	if (size <= sizeof(*item))
		return;

	/* Upgrade the fill_pattern to change about half of the bits
	 * (to be sure to catch static flag corruption), and apply it.
	 */
	u = pch->fill_pattern += ~0UL / 3; // 0x55...55
	ofs = sizeof(*item) / sizeof(*ptr);
	while (ofs < size / sizeof(*ptr))
		ptr[ofs++] = u;
}

/* check for a pool_cache_item integrity after extracting it from the cache. It
 * must have been previously initialized using pool_fill_pattern(). If any
 * corruption is detected, the function provokes an immediate crash.
 */
static inline void pool_check_pattern(struct pool_cache_head *pch, struct pool_cache_item *item, uint size)
{
	const ulong *ptr = (const ulong *)item;
	uint ofs;
	ulong u;

	if (size <= sizeof(*item))
		return;

	/* let's check that all words past *item are equal */
	ofs = sizeof(*item) / sizeof(*ptr);
	u = ptr[ofs++];
	while (ofs < size / sizeof(*ptr)) {
		if (unlikely(ptr[ofs] != u))
			ABORT_NOW();
		ofs++;
	}
}

#else

static inline void pool_fill_pattern(struct pool_cache_head *pch, struct pool_cache_item *item, uint size)
{
}

static inline void pool_check_pattern(struct pool_cache_head *pch, struct pool_cache_item *item, uint size)
{
}

#endif

/* Tries to retrieve an object from the local pool cache corresponding to pool
 * <pool>. If none is available, tries to allocate from the shared cache, and
 * returns NULL if nothing is available.
 */
static inline void *pool_get_from_cache(struct pool_head *pool, const void *caller)
{
	struct pool_cache_item *item;
	struct pool_cache_head *ph;

	ph = &pool->cache[tid];
	if (unlikely(LIST_ISEMPTY(&ph->list))) {
		pool_refill_local_from_shared(pool, ph);
		if (LIST_ISEMPTY(&ph->list))
			return NULL;
	}

#if defined(DEBUG_POOL_INTEGRITY)
	/* allocate oldest objects first so as to keep them as long as possible
	 * in the cache before being reused and maximizing the chance to detect
	 * an overwrite.
	 */
	item = LIST_PREV(&ph->list, typeof(item), by_pool);
	pool_check_pattern(ph, item, pool->size);
#else
	/* allocate hottest objects first */
	item = LIST_NEXT(&ph->list, typeof(item), by_pool);
#endif
	LIST_DELETE(&item->by_pool);
	LIST_DELETE(&item->by_lru);

	/* keep track of where the element was allocated from */
	POOL_DEBUG_SET_MARK(pool, item);
	POOL_DEBUG_TRACE_CALLER(pool, item, caller);

	ph->count--;
	pool_cache_bytes -= pool->size;
	pool_cache_count--;

	return item;
}

#else /* CONFIG_HAP_POOLS */

/* no cache pools implementation */

static inline void *pool_get_from_cache(struct pool_head *pool, const void *caller)
{
	return NULL;
}

static inline void pool_put_to_cache(struct pool_head *pool, void *ptr, const void *caller)
{
	pool_free_nocache(pool, ptr);
}

#endif /* CONFIG_HAP_POOLS */


/****************** Common high-level code ******************/

/*
 * Returns a pointer to type <type> taken from the pool <pool_type> or
 * dynamically allocated. Memory poisonning is performed if enabled.
 */
#define pool_alloc(pool) __pool_alloc((pool), 0)

/*
 * Returns a pointer to type <type> taken from the pool <pool_type> or
 * dynamically allocated. The area is zeroed.
 */
#define pool_zalloc(pool) __pool_alloc((pool), POOL_F_MUST_ZERO)

/*
 * Puts a memory area back to the corresponding pool. Just like with the libc's
 * free(), <ptr> may be NULL.
 */
#define pool_free(pool, ptr)				\
	do {						\
		typeof(ptr) __ptr = (ptr);		\
		if (likely((__ptr) != NULL))		\
			__pool_free(pool, __ptr);	\
	} while (0)

#endif /* _HAPROXY_POOL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
