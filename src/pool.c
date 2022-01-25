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

#include <sys/mman.h>
#include <errno.h>

#include <haproxy/activity.h>
#include <haproxy/api.h>
#include <haproxy/applet-t.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/cli.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/list.h>
#include <haproxy/pool.h>
#include <haproxy/stats-t.h>
#include <haproxy/stream_interface.h>
#include <haproxy/thread.h>
#include <haproxy/tools.h>


#ifdef CONFIG_HAP_POOLS
/* These ones are initialized per-thread on startup by init_pools() */
THREAD_LOCAL size_t pool_cache_bytes = 0;                /* total cache size */
THREAD_LOCAL size_t pool_cache_count = 0;                /* #cache objects   */
#endif

static struct list pools = LIST_HEAD_INIT(pools);
int mem_poison_byte = -1;

#ifdef DEBUG_FAIL_ALLOC
static int mem_fail_rate = 0;
#endif

static int using_default_allocator = 1;
static int(*my_mallctl)(const char *, void *, size_t *, void *, size_t) = NULL;

/* ask the allocator to trim memory pools.
 * This must run under thread isolation so that competing threads trying to
 * allocate or release memory do not prevent the allocator from completing
 * its job. We just have to be careful as callers might already be isolated
 * themselves.
 */
static void trim_all_pools(void)
{
	int isolated = thread_isolated();

	if (!isolated)
		thread_isolate();

	if (my_mallctl) {
		unsigned int i, narenas = 0;
		size_t len = sizeof(narenas);

		if (my_mallctl("arenas.narenas", &narenas, &len, NULL, 0) == 0) {
			for (i = 0; i < narenas; i ++) {
				char mib[32] = {0};
				snprintf(mib, sizeof(mib), "arena.%u.purge", i);
				(void)my_mallctl(mib, NULL, NULL, NULL, 0);
			}
		}
	} else {
#if defined(HA_HAVE_MALLOC_TRIM)
		if (using_default_allocator)
			malloc_trim(0);
#elif defined(HA_HAVE_MALLOC_ZONE)
		if (using_default_allocator) {
			vm_address_t *zones;
			unsigned int i, nzones;

			if (malloc_get_all_zones(0, NULL, &zones, &nzones) == KERN_SUCCESS) {
				for (i = 0; i < nzones; i ++) {
					malloc_zone_t *zone = (malloc_zone_t *)zones[i];

					/* we cannot purge anonymous zones */
					if (zone->zone_name)
						malloc_zone_pressure_relief(zone, 0);
				}
			}
		}
#endif
	}

	if (!isolated)
		thread_release();
}

/* check if we're using the same allocator as the one that provides
 * malloc_trim() and mallinfo(). The principle is that on glibc, both
 * malloc_trim() and mallinfo() are provided, and using mallinfo() we
 * can check if malloc() is performed through glibc or any other one
 * the executable was linked against (e.g. jemalloc). Prior to this we
 * have to check whether we're running on jemalloc by verifying if the
 * mallctl() function is provided. Its pointer will be used later.
 */
static void detect_allocator(void)
{
#if defined(__ELF__)
	extern int mallctl(const char *, void *, size_t *, void *, size_t) __attribute__((weak));

	my_mallctl = mallctl;
#endif

	if (!my_mallctl) {
		my_mallctl = get_sym_curr_addr("mallctl");
		using_default_allocator = (my_mallctl == NULL);
	}

	if (!my_mallctl) {
#if defined(HA_HAVE_MALLOC_TRIM)
#ifdef HA_HAVE_MALLINFO2
		struct mallinfo2 mi1, mi2;
#else
		struct mallinfo mi1, mi2;
#endif
		void *ptr;

#ifdef HA_HAVE_MALLINFO2
		mi1 = mallinfo2();
#else
		mi1 = mallinfo();
#endif
		ptr = DISGUISE(malloc(1));
#ifdef HA_HAVE_MALLINFO2
		mi2 = mallinfo2();
#else
		mi2 = mallinfo();
#endif
		free(DISGUISE(ptr));

		using_default_allocator = !!memcmp(&mi1, &mi2, sizeof(mi1));
#elif defined(HA_HAVE_MALLOC_ZONE)
		using_default_allocator = (malloc_default_zone() != NULL);
#endif
	}
}

static int is_trim_enabled(void)
{
	return using_default_allocator;
}

/* Try to find an existing shared pool with the same characteristics and
 * returns it, otherwise creates this one. NULL is returned if no memory
 * is available for a new creation. Two flags are supported :
 *   - MEM_F_SHARED to indicate that the pool may be shared with other users
 *   - MEM_F_EXACT to indicate that the size must not be rounded up
 */
struct pool_head *create_pool(char *name, unsigned int size, unsigned int flags)
{
	struct pool_head *pool;
	struct pool_head *entry;
	struct list *start;
	unsigned int align;
	int thr __maybe_unused;

	/* We need to store a (void *) at the end of the chunks. Since we know
	 * that the malloc() function will never return such a small size,
	 * let's round the size up to something slightly bigger, in order to
	 * ease merging of entries. Note that the rounding is a power of two.
	 * This extra (void *) is not accounted for in the size computation
	 * so that the visible parts outside are not affected.
	 *
	 * Note: for the LRU cache, we need to store 2 doubly-linked lists.
	 */

	if (!(flags & MEM_F_EXACT)) {
		align = 4 * sizeof(void *); // 2 lists = 4 pointers min
		size  = ((size + POOL_EXTRA + align - 1) & -align) - POOL_EXTRA;
	}

	/* TODO: thread: we do not lock pool list for now because all pools are
	 * created during HAProxy startup (so before threads creation) */
	start = &pools;
	pool = NULL;

	list_for_each_entry(entry, &pools, list) {
		if (entry->size == size) {
			/* either we can share this place and we take it, or
			 * we look for a shareable one or for the next position
			 * before which we will insert a new one.
			 */
			if ((flags & entry->flags & MEM_F_SHARED)
#ifdef DEBUG_DONT_SHARE_POOLS
			    && strcmp(name, entry->name) == 0
#endif
			    ) {
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
		if (!pool)
			pool = calloc(1, sizeof(*pool));

		if (!pool)
			return NULL;
		if (name)
			strlcpy2(pool->name, name, sizeof(pool->name));
		pool->size = size;
		pool->flags = flags;
		LIST_APPEND(start, &pool->list);

#ifdef CONFIG_HAP_POOLS
		/* update per-thread pool cache if necessary */
		for (thr = 0; thr < MAX_THREADS; thr++) {
			LIST_INIT(&pool->cache[thr].list);
		}
#endif
	}
	pool->users++;
	return pool;
}

/* Tries to allocate an object for the pool <pool> using the system's allocator
 * and directly returns it. The pool's allocated counter is checked and updated,
 * but no other checks are performed.
 */
void *pool_get_from_os(struct pool_head *pool)
{
	if (!pool->limit || pool->allocated < pool->limit) {
		void *ptr = pool_alloc_area(pool->size + POOL_EXTRA);
		if (ptr) {
			_HA_ATOMIC_INC(&pool->allocated);
			return ptr;
		}
		_HA_ATOMIC_INC(&pool->failed);
	}
	activity[tid].pool_fail++;
	return NULL;

}

/* Releases a pool item back to the operating system and atomically updates
 * the allocation counter.
 */
void pool_put_to_os(struct pool_head *pool, void *ptr)
{
#ifdef DEBUG_UAF
	/* This object will be released for real in order to detect a use after
	 * free. We also force a write to the area to ensure we crash on double
	 * free or free of a const area.
	 */
	*(uint32_t *)ptr = 0xDEADADD4;
#endif /* DEBUG_UAF */

	pool_free_area(ptr, pool->size + POOL_EXTRA);
	_HA_ATOMIC_DEC(&pool->allocated);
}

/* Tries to allocate an object for the pool <pool> using the system's allocator
 * and directly returns it. The pool's counters are updated but the object is
 * never cached, so this is usable with and without local or shared caches.
 */
void *pool_alloc_nocache(struct pool_head *pool)
{
	void *ptr = NULL;

	ptr = pool_get_from_os(pool);
	if (!ptr)
		return NULL;

	swrate_add_scaled(&pool->needed_avg, POOL_AVG_SAMPLES, pool->used, POOL_AVG_SAMPLES/4);
	_HA_ATOMIC_INC(&pool->used);

	/* keep track of where the element was allocated from */
	POOL_DEBUG_SET_MARK(pool, ptr);
	POOL_DEBUG_TRACE_CALLER(pool, (struct pool_cache_item *)ptr, NULL);
	return ptr;
}

/* Release a pool item back to the OS and keeps the pool's counters up to date.
 * This is always defined even when pools are not enabled (their usage stats
 * are maintained).
 */
void pool_free_nocache(struct pool_head *pool, void *ptr)
{
	_HA_ATOMIC_DEC(&pool->used);
	swrate_add(&pool->needed_avg, POOL_AVG_SAMPLES, pool->used);
	pool_put_to_os(pool, ptr);
}


#ifdef CONFIG_HAP_POOLS

/* removes up to <count> items from the end of the local pool cache <ph> for
 * pool <pool>. The shared pool is refilled with these objects in the limit
 * of the number of acceptable objects, and the rest will be released to the
 * OS. It is not a problem is <count> is larger than the number of objects in
 * the local cache. The counters are automatically updated.
 */
static void pool_evict_last_items(struct pool_head *pool, struct pool_cache_head *ph, uint count)
{
	struct pool_cache_item *item;
	struct pool_item *pi, *head = NULL;
	uint released = 0;
	uint cluster = 0;
	uint to_free_max;

	to_free_max = pool_releasable(pool);

	while (released < count && !LIST_ISEMPTY(&ph->list)) {
		item = LIST_PREV(&ph->list, typeof(item), by_pool);
		pool_check_pattern(ph, item, pool->size);
		LIST_DELETE(&item->by_pool);
		LIST_DELETE(&item->by_lru);

		if (to_free_max > released || cluster) {
			pi = (struct pool_item *)item;
			pi->next = NULL;
			pi->down = head;
			head = pi;
			cluster++;
			if (cluster >= CONFIG_HAP_POOL_CLUSTER_SIZE) {
				/* enough to make a cluster */
				pool_put_to_shared_cache(pool, head, cluster);
				cluster = 0;
				head = NULL;
			}
		} else
			pool_free_nocache(pool, item);

		released++;
	}

	/* incomplete cluster left */
	if (cluster)
		pool_put_to_shared_cache(pool, head, cluster);

	ph->count -= released;
	pool_cache_count -= released;
	pool_cache_bytes -= released * pool->size;
}

/* Evicts some of the oldest objects from one local cache, until its number of
 * objects is no more than 16+1/8 of the total number of locally cached objects
 * or the total size of the local cache is no more than 75% of its maximum (i.e.
 * we don't want a single cache to use all the cache for itself). For this, the
 * list is scanned in reverse.
 */
void pool_evict_from_local_cache(struct pool_head *pool)
{
	struct pool_cache_head *ph = &pool->cache[tid];

	while (ph->count >= CONFIG_HAP_POOL_CLUSTER_SIZE &&
	       ph->count >= 16 + pool_cache_count / 8 &&
	       pool_cache_bytes > CONFIG_HAP_POOL_CACHE_SIZE * 3 / 4) {
		pool_evict_last_items(pool, ph, CONFIG_HAP_POOL_CLUSTER_SIZE);
	}
}

/* Evicts some of the oldest objects from the local cache, pushing them to the
 * global pool.
 */
void pool_evict_from_local_caches()
{
	struct pool_cache_item *item;
	struct pool_cache_head *ph;
	struct pool_head *pool;

	do {
		item = LIST_PREV(&th_ctx->pool_lru_head, struct pool_cache_item *, by_lru);
		/* note: by definition we remove oldest objects so they also are the
		 * oldest in their own pools, thus their next is the pool's head.
		 */
		ph = LIST_NEXT(&item->by_pool, struct pool_cache_head *, list);
		pool = container_of(ph - tid, struct pool_head, cache);
		pool_evict_last_items(pool, ph, CONFIG_HAP_POOL_CLUSTER_SIZE);
	} while (pool_cache_bytes > CONFIG_HAP_POOL_CACHE_SIZE * 7 / 8);
}

/* Frees an object to the local cache, possibly pushing oldest objects to the
 * shared cache, which itself may decide to release some of them to the OS.
 * While it is unspecified what the object becomes past this point, it is
 * guaranteed to be released from the users' perpective. A caller address may
 * be passed and stored into the area when DEBUG_POOL_TRACING is set.
 */
void pool_put_to_cache(struct pool_head *pool, void *ptr, const void *caller)
{
	struct pool_cache_item *item = (struct pool_cache_item *)ptr;
	struct pool_cache_head *ph = &pool->cache[tid];

	LIST_INSERT(&ph->list, &item->by_pool);
	LIST_INSERT(&th_ctx->pool_lru_head, &item->by_lru);
	POOL_DEBUG_TRACE_CALLER(pool, item, caller);
	ph->count++;
	pool_fill_pattern(ph, item, pool->size);
	pool_cache_count++;
	pool_cache_bytes += pool->size;

	if (unlikely(pool_cache_bytes > CONFIG_HAP_POOL_CACHE_SIZE * 3 / 4)) {
		if (ph->count >= 16 + pool_cache_count / 8 + CONFIG_HAP_POOL_CLUSTER_SIZE)
			pool_evict_from_local_cache(pool);
		if (pool_cache_bytes > CONFIG_HAP_POOL_CACHE_SIZE)
			pool_evict_from_local_caches();
	}
}

#if defined(CONFIG_HAP_NO_GLOBAL_POOLS)

/* legacy stuff */
void pool_flush(struct pool_head *pool)
{
}

/* This function might ask the malloc library to trim its buffers. */
void pool_gc(struct pool_head *pool_ctx)
{
	trim_all_pools();
}

#else /* CONFIG_HAP_NO_GLOBAL_POOLS */

/* Tries to refill the local cache <pch> from the shared one for pool <pool>.
 * This is only used when pools are in use and shared pools are enabled. No
 * malloc() is attempted, and poisonning is never performed. The purpose is to
 * get the fastest possible refilling so that the caller can easily check if
 * the cache has enough objects for its use.
 */
void pool_refill_local_from_shared(struct pool_head *pool, struct pool_cache_head *pch)
{
	struct pool_cache_item *item;
	struct pool_item *ret, *down;
	uint count;

	/* we'll need to reference the first element to figure the next one. We
	 * must temporarily lock it so that nobody allocates then releases it,
	 * or the dereference could fail.
	 */
	ret = _HA_ATOMIC_LOAD(&pool->free_list);
	do {
		while (unlikely(ret == POOL_BUSY)) {
			__ha_cpu_relax();
			ret = _HA_ATOMIC_LOAD(&pool->free_list);
		}
		if (ret == NULL)
			return;
	} while (unlikely((ret = _HA_ATOMIC_XCHG(&pool->free_list, POOL_BUSY)) == POOL_BUSY));

	if (unlikely(ret == NULL)) {
		HA_ATOMIC_STORE(&pool->free_list, NULL);
		return;
	}

	/* this releases the lock */
	HA_ATOMIC_STORE(&pool->free_list, ret->next);

	/* now store the retrieved object(s) into the local cache */
	count = 0;
	for (; ret; ret = down) {
		down = ret->down;
		/* keep track of where the element was allocated from */
		POOL_DEBUG_SET_MARK(pool, ret);

		item = (struct pool_cache_item *)ret;
		POOL_DEBUG_TRACE_CALLER(pool, item, NULL);
		LIST_INSERT(&pch->list, &item->by_pool);
		LIST_INSERT(&th_ctx->pool_lru_head, &item->by_lru);
		count++;
		pool_fill_pattern(pch, item, pool->size);
	}
	HA_ATOMIC_ADD(&pool->used, count);
	pch->count += count;
	pool_cache_count += count;
	pool_cache_bytes += count * pool->size;
}

/* Adds pool item cluster <item> to the shared cache, which contains <count>
 * elements. The caller is advised to first check using pool_releasable() if
 * it's wise to add this series of objects there. Both the pool and the item's
 * head must be valid.
 */
void pool_put_to_shared_cache(struct pool_head *pool, struct pool_item *item, uint count)
{
	struct pool_item *free_list;

	_HA_ATOMIC_SUB(&pool->used, count);
	free_list = _HA_ATOMIC_LOAD(&pool->free_list);
	do {
		while (unlikely(free_list == POOL_BUSY)) {
			__ha_cpu_relax();
			free_list = _HA_ATOMIC_LOAD(&pool->free_list);
		}
		_HA_ATOMIC_STORE(&item->next, free_list);
		__ha_barrier_atomic_store();
	} while (!_HA_ATOMIC_CAS(&pool->free_list, &free_list, item));
	__ha_barrier_atomic_store();
	swrate_add(&pool->needed_avg, POOL_AVG_SAMPLES, pool->used);
}

/*
 * This function frees whatever can be freed in pool <pool>.
 */
void pool_flush(struct pool_head *pool)
{
	struct pool_item *next, *temp, *down;

	if (!pool)
		return;

	/* The loop below atomically detaches the head of the free list and
	 * replaces it with a NULL. Then the list can be released.
	 */
	next = pool->free_list;
	do {
		while (unlikely(next == POOL_BUSY)) {
			__ha_cpu_relax();
			next = _HA_ATOMIC_LOAD(&pool->free_list);
		}
		if (next == NULL)
			return;
	} while (unlikely((next = _HA_ATOMIC_XCHG(&pool->free_list, POOL_BUSY)) == POOL_BUSY));
	_HA_ATOMIC_STORE(&pool->free_list, NULL);
	__ha_barrier_atomic_store();

	while (next) {
		temp = next;
		next = temp->next;
		for (; temp; temp = down) {
			down = temp->down;
			pool_put_to_os(pool, temp);
		}
	}
	/* here, we should have pool->allocated == pool->used */
}

/*
 * This function frees whatever can be freed in all pools, but respecting
 * the minimum thresholds imposed by owners. It makes sure to be alone to
 * run by using thread_isolate(). <pool_ctx> is unused.
 */
void pool_gc(struct pool_head *pool_ctx)
{
	struct pool_head *entry;
	int isolated = thread_isolated();

	if (!isolated)
		thread_isolate();

	list_for_each_entry(entry, &pools, list) {
		struct pool_item *temp, *down;

		while (entry->free_list &&
		       (int)(entry->allocated - entry->used) > (int)entry->minavail) {
			temp = entry->free_list;
			entry->free_list = temp->next;
			for (; temp; temp = down) {
				down = temp->down;
				pool_put_to_os(entry, temp);
			}
		}
	}

	trim_all_pools();

	if (!isolated)
		thread_release();
}
#endif /* CONFIG_HAP_NO_GLOBAL_POOLS */

#else  /* CONFIG_HAP_POOLS */

/* legacy stuff */
void pool_flush(struct pool_head *pool)
{
}

/* This function might ask the malloc library to trim its buffers. */
void pool_gc(struct pool_head *pool_ctx)
{
	trim_all_pools();
}

#endif /* CONFIG_HAP_POOLS */

/*
 * Returns a pointer to type <type> taken from the pool <pool_type> or
 * dynamically allocated. In the first case, <pool_type> is updated to point to
 * the next element in the list. <flags> is a binary-OR of POOL_F_* flags.
 * Prefer using pool_alloc() which does the right thing without flags.
 */
void *__pool_alloc(struct pool_head *pool, unsigned int flags)
{
	void *p = NULL;
	void *caller = NULL;

#ifdef DEBUG_FAIL_ALLOC
	if (unlikely(!(flags & POOL_F_NO_FAIL) && mem_should_fail(pool)))
		return NULL;
#endif

#if defined(DEBUG_POOL_TRACING)
	caller = __builtin_return_address(0);
#endif
	if (!p)
		p = pool_get_from_cache(pool, caller);
	if (unlikely(!p))
		p = pool_alloc_nocache(pool);

	if (likely(p)) {
		if (unlikely(flags & POOL_F_MUST_ZERO))
			memset(p, 0, pool->size);
		else if (unlikely(!(flags & POOL_F_NO_POISON) && mem_poison_byte >= 0))
			memset(p, mem_poison_byte, pool->size);
	}
	return p;
}

/*
 * Puts a memory area back to the corresponding pool. <ptr> be valid. Using
 * pool_free() is preferred.
 */
void __pool_free(struct pool_head *pool, void *ptr)
{
	const void *caller = NULL;

#if defined(DEBUG_POOL_TRACING)
	caller = __builtin_return_address(0);
#endif
	/* we'll get late corruption if we refill to the wrong pool or double-free */
	POOL_DEBUG_CHECK_MARK(pool, ptr);

	if (unlikely(mem_poison_byte >= 0))
		memset(ptr, mem_poison_byte, pool->size);

	pool_put_to_cache(pool, ptr, caller);
}


#ifdef DEBUG_UAF

/************* use-after-free allocator *************/

/* allocates an area of size <size> and returns it. The semantics are similar
 * to those of malloc(). However the allocation is rounded up to 4kB so that a
 * full page is allocated. This ensures the object can be freed alone so that
 * future dereferences are easily detected. The returned object is always
 * 16-bytes aligned to avoid issues with unaligned structure objects. In case
 * some padding is added, the area's start address is copied at the end of the
 * padding to help detect underflows.
 */
void *pool_alloc_area_uaf(size_t size)
{
	size_t pad = (4096 - size) & 0xFF0;
	void *ret;

	ret = mmap(NULL, (size + 4095) & -4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (ret != MAP_FAILED) {
		/* let's dereference the page before returning so that the real
		 * allocation in the system is performed without holding the lock.
		 */
		*(int *)ret = 0;
		if (pad >= sizeof(void *))
			*(void **)(ret + pad - sizeof(void *)) = ret + pad;
		ret += pad;
	} else {
		ret = NULL;
	}
	return ret;
}

/* frees an area <area> of size <size> allocated by pool_alloc_area(). The
 * semantics are identical to free() except that the size must absolutely match
 * the one passed to pool_alloc_area(). In case some padding is added, the
 * area's start address is compared to the one at the end of the padding, and
 * a segfault is triggered if they don't match, indicating an underflow.
 */
void pool_free_area_uaf(void *area, size_t size)
{
	size_t pad = (4096 - size) & 0xFF0;

	if (pad >= sizeof(void *) && *(void **)(area - sizeof(void *)) != area)
		ABORT_NOW();

	munmap(area - pad, (size + 4095) & -4096);
}

#endif /* DEBUG_UAF */

/*
 * This function destroys a pool by freeing it completely, unless it's still
 * in use. This should be called only under extreme circumstances. It always
 * returns NULL if the resulting pool is empty, easing the clearing of the old
 * pointer, otherwise it returns the pool.
 * .
 */
void *pool_destroy(struct pool_head *pool)
{
	if (pool) {
		pool_flush(pool);
		if (pool->used)
			return pool;
		pool->users--;
		if (!pool->users) {
			LIST_DELETE(&pool->list);
			/* note that if used == 0, the cache is empty */
			free(pool);
		}
	}
	return NULL;
}

/* This destroys all pools on exit. It is *not* thread safe. */
void pool_destroy_all()
{
	struct pool_head *entry, *back;

	list_for_each_entry_safe(entry, back, &pools, list)
		pool_destroy(entry);
}

/* This function dumps memory usage information into the trash buffer. */
void dump_pools_to_trash()
{
	struct pool_head *entry;
	unsigned long allocated, used;
	int nbpools;
#ifdef CONFIG_HAP_POOLS
	unsigned long cached_bytes = 0;
	uint cached = 0;
#endif

	allocated = used = nbpools = 0;
	chunk_printf(&trash, "Dumping pools usage. Use SIGQUIT to flush them.\n");
	list_for_each_entry(entry, &pools, list) {
#ifdef CONFIG_HAP_POOLS
		int i;
		for (cached = i = 0; i < global.nbthread; i++)
			cached += entry->cache[i].count;
		cached_bytes += cached * entry->size;
#endif
		chunk_appendf(&trash, "  - Pool %s (%u bytes) : %u allocated (%u bytes), %u used"
#ifdef CONFIG_HAP_POOLS
			      " (~%u by thread caches)"
#endif
			      ", needed_avg %u, %u failures, %u users, @%p%s\n",
		              entry->name, entry->size, entry->allocated,
		              entry->size * entry->allocated, entry->used,
#ifdef CONFIG_HAP_POOLS
		              cached,
#endif
		              swrate_avg(entry->needed_avg, POOL_AVG_SAMPLES), entry->failed,
		              entry->users, entry,
		              (entry->flags & MEM_F_SHARED) ? " [SHARED]" : "");

		allocated += entry->allocated * entry->size;
		used += entry->used * entry->size;
		nbpools++;
	}
	chunk_appendf(&trash, "Total: %d pools, %lu bytes allocated, %lu used"
#ifdef CONFIG_HAP_POOLS
		      " (~%lu by thread caches)"
#endif
		      ".\n",
	              nbpools, allocated, used
#ifdef CONFIG_HAP_POOLS
	              , cached_bytes
#endif
		      );
}

/* Dump statistics on pools usage. */
void dump_pools(void)
{
	dump_pools_to_trash();
	qfprintf(stderr, "%s", trash.area);
}

/* This function returns the total number of failed pool allocations */
int pool_total_failures()
{
	struct pool_head *entry;
	int failed = 0;

	list_for_each_entry(entry, &pools, list)
		failed += entry->failed;
	return failed;
}

/* This function returns the total amount of memory allocated in pools (in bytes) */
unsigned long pool_total_allocated()
{
	struct pool_head *entry;
	unsigned long allocated = 0;

	list_for_each_entry(entry, &pools, list)
		allocated += entry->allocated * entry->size;
	return allocated;
}

/* This function returns the total amount of memory used in pools (in bytes) */
unsigned long pool_total_used()
{
	struct pool_head *entry;
	unsigned long used = 0;

	list_for_each_entry(entry, &pools, list)
		used += entry->used * entry->size;
	return used;
}

/* This function dumps memory usage information onto the stream interface's
 * read buffer. It returns 0 as long as it does not complete, non-zero upon
 * completion. No state is used.
 */
static int cli_io_handler_dump_pools(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;

	dump_pools_to_trash();
	if (ci_putchk(si_ic(si), &trash) == -1) {
		si_rx_room_blk(si);
		return 0;
	}
	return 1;
}

/* callback used to create early pool <name> of size <size> and store the
 * resulting pointer into <ptr>. If the allocation fails, it quits with after
 * emitting an error message.
 */
void create_pool_callback(struct pool_head **ptr, char *name, unsigned int size)
{
	*ptr = create_pool(name, size, MEM_F_SHARED);
	if (!*ptr) {
		ha_alert("Failed to allocate pool '%s' of size %u : %s. Aborting.\n",
			 name, size, strerror(errno));
		exit(1);
	}
}

/* Initializes all per-thread arrays on startup */
static void init_pools()
{
#ifdef CONFIG_HAP_POOLS
	int thr;

	for (thr = 0; thr < MAX_THREADS; thr++) {
		LIST_INIT(&ha_thread_ctx[thr].pool_lru_head);
	}
#endif
	detect_allocator();
}

INITCALL0(STG_PREPARE, init_pools);

/* Report in build options if trim is supported */
static void pools_register_build_options(void)
{
	if (is_trim_enabled()) {
		char *ptr = NULL;
		memprintf(&ptr, "Support for malloc_trim() is enabled.");
		hap_register_build_opts(ptr, 1);
	}
}
INITCALL0(STG_REGISTER, pools_register_build_options);

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "pools",  NULL }, "show pools                              : report information about the memory pools usage", NULL, cli_io_handler_dump_pools },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

#ifdef DEBUG_FAIL_ALLOC

int mem_should_fail(const struct pool_head *pool)
{
	int ret = 0;

	if (mem_fail_rate > 0 && !(global.mode & MODE_STARTING)) {
		if (mem_fail_rate > statistical_prng_range(100))
			ret = 1;
		else
			ret = 0;
	}
	return ret;

}

/* config parser for global "tune.fail-alloc" */
static int mem_parse_global_fail_alloc(char **args, int section_type, struct proxy *curpx,
                                       const struct proxy *defpx, const char *file, int line,
                                       char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;
	mem_fail_rate = atoi(args[1]);
	if (mem_fail_rate < 0 || mem_fail_rate > 100) {
	    memprintf(err, "'%s' expects a numeric value between 0 and 100.", args[0]);
	    return -1;
	}
	return 0;
}
#endif

/* register global config keywords */
static struct cfg_kw_list mem_cfg_kws = {ILH, {
#ifdef DEBUG_FAIL_ALLOC
	{ CFG_GLOBAL, "tune.fail-alloc", mem_parse_global_fail_alloc },
#endif
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &mem_cfg_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
