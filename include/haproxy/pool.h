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
# define POOL_EXTRA_MARK (sizeof(void *))
# define POOL_DEBUG_SET_MARK(pool, item)				\
	do {								\
		typeof(pool) __p = (pool);				\
		typeof(item) __i = (item);				\
		if (likely(!(pool_debugging & POOL_DBG_TAG)))		\
			break;						\
		*(typeof(pool)*)(((char *)__i) + __p->size) = __p;	\
	} while (0)

# define POOL_DEBUG_RESET_MARK(pool, item)				\
	do {								\
		typeof(pool) __p = (pool);				\
		typeof(item) __i = (item);				\
		if (likely(!(pool_debugging & POOL_DBG_TAG)))		\
			break;						\
		*(typeof(pool)*)(((char *)__i) + __p->size) = __builtin_return_address(0); \
	} while (0)

# define POOL_DEBUG_CHECK_MARK(pool, item, caller)				\
	do {								\
		typeof(pool) __p = (pool);				\
		typeof(item) __i = (item);				\
		if (likely(!(pool_debugging & POOL_DBG_TAG)))		\
			break;						\
		if (*(typeof(pool)*)(((char *)__i) + __p->size) != __p)	{ \
			pool_inspect_item("tag mismatch on free()", __p, __i, caller, -1); \
			ABORT_NOW();					\
		}							\
	} while (0)

/* It's possible to trace callers of pool_free() by placing their pointer
 * after the end of the area and the optional mark above, which means the
 * end of the allocated array.
 */
# define POOL_EXTRA_CALLER (sizeof(void *))
# define POOL_DEBUG_TRACE_CALLER(pool, item, caller)			\
	do {								\
		typeof(pool) __p = (pool);				\
		typeof(item) __i = (item);				\
		typeof(caller) __c = (caller);				\
		if (likely(!(pool_debugging & POOL_DBG_CALLER)))	\
			break;						\
		*(typeof(caller)*)(((char *)__i) + __p->alloc_sz - sizeof(void*)) = __c; \
	} while (0)

/* poison each newly allocated area with this byte if >= 0 */
extern int mem_poison_byte;

/* trim() in progress */
extern int pool_trim_in_progress;

/* set of POOL_DBG_* flags */
extern uint pool_debugging;

/* pools are listed here */
extern struct list pools;

int malloc_trim(size_t pad);
void trim_all_pools(void);

void *pool_get_from_os_noinc(struct pool_head *pool);
void pool_put_to_os_nodec(struct pool_head *pool, void *ptr);
void *pool_alloc_nocache(struct pool_head *pool, const void *caller);
void pool_free_nocache(struct pool_head *pool, void *ptr);
void dump_pools(void);
int pool_parse_debugging(const char *str, char **err);
int pool_total_failures(void);
unsigned long long pool_total_allocated(void);
unsigned long long pool_total_used(void);
void pool_flush(struct pool_head *pool);
void pool_gc(struct pool_head *pool_ctx);
struct pool_head *create_pool(char *name, unsigned int size, unsigned int flags);
void create_pool_callback(struct pool_head **ptr, char *name, unsigned int size);
void *pool_destroy(struct pool_head *pool);
void pool_destroy_all(void);
void *__pool_alloc(struct pool_head *pool, unsigned int flags);
void __pool_free(struct pool_head *pool, void *ptr);
void pool_inspect_item(const char *msg, struct pool_head *pool, const void *item, const void *caller, ssize_t ofs);


/****************** Thread-local cache management ******************/

extern THREAD_LOCAL size_t pool_cache_bytes;   /* total cache size */
extern THREAD_LOCAL size_t pool_cache_count;   /* #cache objects   */

void pool_evict_from_local_cache(struct pool_head *pool, int full);
void pool_evict_from_local_caches(void);
void pool_put_to_cache(struct pool_head *pool, void *ptr, const void *caller);
void pool_fill_pattern(struct pool_cache_head *pch, struct pool_cache_item *item, uint size);
void pool_check_pattern(struct pool_cache_head *pch, struct pool_head *pool, struct pool_cache_item *item, const void *caller);
void pool_refill_local_from_shared(struct pool_head *pool, struct pool_cache_head *pch);
void pool_put_to_shared_cache(struct pool_head *pool, struct pool_item *item);

/* returns the total number of allocated entries for a pool across all buckets */
static inline uint pool_allocated(const struct pool_head *pool)
{
	int bucket;
	uint ret;

	for (bucket = ret = 0; bucket < CONFIG_HAP_POOL_BUCKETS; bucket++)
		ret += HA_ATOMIC_LOAD(&pool->buckets[bucket].allocated);
	return ret;
}

/* returns the total number of used entries for a pool across all buckets */
static inline uint pool_used(const struct pool_head *pool)
{
	int bucket;
	uint ret;

	for (bucket = ret = 0; bucket < CONFIG_HAP_POOL_BUCKETS; bucket++)
		ret += HA_ATOMIC_LOAD(&pool->buckets[bucket].used);
	return ret;
}

/* returns the raw total number needed entries across all buckets. It must
 * be passed to swrate_avg() to get something usable.
 */
static inline uint pool_needed_avg(const struct pool_head *pool)
{
	int bucket;
	uint ret;

	for (bucket = ret = 0; bucket < CONFIG_HAP_POOL_BUCKETS; bucket++)
		ret += HA_ATOMIC_LOAD(&pool->buckets[bucket].needed_avg);
	return ret;
}

/* returns the total number of failed allocations for a pool across all buckets */
static inline uint pool_failed(const struct pool_head *pool)
{
	int bucket;
	uint ret;

	for (bucket = ret = 0; bucket < CONFIG_HAP_POOL_BUCKETS; bucket++)
		ret += HA_ATOMIC_LOAD(&pool->buckets[bucket].failed);
	return ret;
}

/* Returns the max number of entries that may be brought back to the pool
 * before it's considered as full. Note that it is only usable for releasing
 * objects, hence the function assumes that no more than ->used entries will
 * be released in the worst case, and that this value is always lower than or
 * equal to ->allocated. It's important to understand that under thread
 * contention these values may not always be accurate but the principle is that
 * any deviation remains contained. When global pools are disabled, this
 * function always returns zero so that the caller knows it must free the
 * object via other ways.
 */
static inline uint pool_releasable(const struct pool_head *pool)
{
	uint alloc, used;
	uint needed_raw;

	if (unlikely(pool_debugging & (POOL_DBG_NO_CACHE|POOL_DBG_NO_GLOBAL)))
		return 0;

	alloc = pool_allocated(pool);
	used  = pool_used(pool);
	if (used > alloc)
		alloc = used;

	needed_raw = pool_needed_avg(pool);
	if (alloc < swrate_avg(needed_raw + needed_raw / 4, POOL_AVG_SAMPLES))
		return used; // less than needed is allocated, can release everything

	if ((uint)(alloc - used) < pool->minavail)
		return pool->minavail - (alloc - used); // less than minimum available

	/* there are enough objects in this pool */
	return 0;
}

/* These are generic cache-aware wrappers that allocate/free from/to the local
 * cache first, then from the second level if it exists.
 */

/* Tries to retrieve an object from the local pool cache corresponding to pool
 * <pool>. If none is available, tries to allocate from the shared cache if any
 * and returns NULL if nothing is available. Must not be used when pools are
 * disabled.
 */
static inline void *pool_get_from_cache(struct pool_head *pool, const void *caller)
{
	struct pool_cache_item *item;
	struct pool_cache_head *ph;

	BUG_ON(pool_debugging & POOL_DBG_NO_CACHE);

	ph = &pool->cache[tid];
	if (unlikely(LIST_ISEMPTY(&ph->list))) {
		if (!(pool_debugging & POOL_DBG_NO_GLOBAL))
			pool_refill_local_from_shared(pool, ph);
		if (LIST_ISEMPTY(&ph->list))
			return NULL;
	}

	/* allocate hottest objects first */
	item = LIST_NEXT(&ph->list, typeof(item), by_pool);

	if (unlikely(pool_debugging & (POOL_DBG_COLD_FIRST|POOL_DBG_INTEGRITY))) {
		/* allocate oldest objects first so as to keep them as long as possible
		 * in the cache before being reused and maximizing the chance to detect
		 * an overwrite.
		 */
		if (pool_debugging & POOL_DBG_COLD_FIRST)
			item = LIST_PREV(&ph->list, typeof(item), by_pool);

		if (pool_debugging & POOL_DBG_INTEGRITY)
			pool_check_pattern(ph, pool, item, caller);
	}

	BUG_ON(&item->by_pool == &ph->list);
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


/****************** Common high-level code ******************/

#if !defined(DEBUG_MEM_STATS)

/*
 * Returns a pointer to an object from pool <pool> allocated using
 * flags <flag> from the POOL_F_* set.
 */
#define pool_alloc_flag(pool, flag)  __pool_alloc((pool), (flag))

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


#else /* DEBUG_MEM_STATS is set below */

#define pool_free(pool, ptr)  ({					\
	struct pool_head *__pool = (pool);				\
	typeof(ptr) __ptr = (ptr);					\
	static struct mem_stats _ __attribute__((used,__section__("mem_stats"),__aligned__(sizeof(void*)))) = { \
		.caller = {						\
			.file = __FILE__, .line = __LINE__,		\
			.what = MEM_STATS_TYPE_P_FREE,			\
			.func = __func__,				\
		},							\
	};								\
	_.extra = __pool;						\
	HA_WEAK(__start_mem_stats);					\
	HA_WEAK(__stop_mem_stats);					\
	if (__ptr)  {							\
		_HA_ATOMIC_INC(&_.calls);				\
		_HA_ATOMIC_ADD(&_.size, __pool->size);			\
		__pool_free(__pool, __ptr);				\
	}								\
})

#define pool_alloc_flag(pool, flag)  ({					\
	struct pool_head *__pool = (pool);				\
	uint __flag = (flag);						\
	size_t __x = __pool->size;					\
	static struct mem_stats _ __attribute__((used,__section__("mem_stats"),__aligned__(sizeof(void*)))) = { \
		.caller = {						\
			.file = __FILE__, .line = __LINE__,		\
			.what = MEM_STATS_TYPE_P_ALLOC,			\
			.func = __func__,				\
		},							\
	};								\
	_.extra = __pool;						\
	HA_WEAK(__start_mem_stats);					\
	HA_WEAK(__stop_mem_stats);					\
	_HA_ATOMIC_INC(&_.calls);					\
	_HA_ATOMIC_ADD(&_.size, __x);					\
	__pool_alloc(__pool, __flag);					\
})

#define pool_alloc(pool) pool_alloc_flag(pool, 0)

#define pool_zalloc(pool) pool_alloc_flag(pool, POOL_F_MUST_ZERO)

#endif /* DEBUG_MEM_STATS */

#endif /* _HAPROXY_POOL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
