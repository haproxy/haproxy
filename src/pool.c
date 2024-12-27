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

#include <errno.h>

#include <import/plock.h>

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
#include <haproxy/pool-os.h>
#include <haproxy/sc_strm.h>
#include <haproxy/stats-t.h>
#include <haproxy/stconn.h>
#include <haproxy/thread.h>
#include <haproxy/tools.h>


/* These ones are initialized per-thread on startup by init_pools() */
THREAD_LOCAL size_t pool_cache_bytes = 0;                /* total cache size */
THREAD_LOCAL size_t pool_cache_count = 0;                /* #cache objects   */

struct list pools __read_mostly = LIST_HEAD_INIT(pools);
int mem_poison_byte __read_mostly = 'P';
int pool_trim_in_progress = 0;
uint pool_debugging __read_mostly =               /* set of POOL_DBG_* flags */
#if defined(DEBUG_FAIL_ALLOC) && (DEBUG_FAIL_ALLOC > 0)
	POOL_DBG_FAIL_ALLOC |
#endif
#if defined(DEBUG_DONT_SHARE_POOLS) && (DEBUG_DONT_SHARE_POOLS > 0)
	POOL_DBG_DONT_MERGE |
#endif
#if defined(DEBUG_POOL_INTEGRITY) && (DEBUG_POOL_INTEGRITY > 0)
	POOL_DBG_COLD_FIRST |
	POOL_DBG_INTEGRITY  |
#endif
#if defined(CONFIG_HAP_NO_GLOBAL_POOLS)
	POOL_DBG_NO_GLOBAL  |
#endif
#if defined(DEBUG_NO_POOLS) && (DEBUG_NO_POOLS > 0)
	POOL_DBG_NO_CACHE   |
#endif
#if defined(DEBUG_POOL_TRACING) && (DEBUG_POOL_TRACING > 0)
	POOL_DBG_CALLER     |
#endif
#if defined(DEBUG_MEMORY_POOLS) && (DEBUG_MEMORY_POOLS > 0)
	POOL_DBG_TAG        |
#endif
#if defined(DEBUG_UAF) && (DEBUG_UAF > 0)
	POOL_DBG_NO_CACHE   |
	POOL_DBG_UAF        |
#endif
	0;

static const struct {
	uint flg;
	const char *set;
	const char *clr;
	const char *hlp;
} dbg_options[] = {
	/* flg,                 set,          clr,            hlp */
	{ POOL_DBG_FAIL_ALLOC, "fail",       "no-fail",      "randomly fail allocations" },
	{ POOL_DBG_DONT_MERGE, "no-merge",   "merge",        "disable merging of similar pools" },
	{ POOL_DBG_COLD_FIRST, "cold-first", "hot-first",    "pick cold objects first" },
	{ POOL_DBG_INTEGRITY,  "integrity",  "no-integrity", "enable cache integrity checks" },
	{ POOL_DBG_NO_GLOBAL,  "no-global",  "global",       "disable global shared cache" },
	{ POOL_DBG_NO_CACHE,   "no-cache",   "cache",        "disable thread-local cache" },
	{ POOL_DBG_CALLER,     "caller",     "no-caller",    "save caller information in cache" },
	{ POOL_DBG_TAG,        "tag",        "no-tag",       "add tag at end of allocated objects" },
	{ POOL_DBG_POISON,     "poison",     "no-poison",    "poison newly allocated objects" },
	{ POOL_DBG_UAF,        "uaf",        "no-uaf",       "enable use-after-free checks (slow)" },
	{ 0 /* end */ }
};

/* describes a snapshot of a pool line about to be dumped by "show pools" */
struct pool_dump_info {
	const struct pool_head *entry;
	ulong alloc_items;
	ulong alloc_bytes;
	ulong used_items;
	ulong cached_items;
	ulong need_avg;
	ulong failed_items;
};

/* context used by "show pools" */
struct show_pools_ctx {
	char *prefix;  /* if non-null, match this prefix name for the pool */
	int by_what; /* 0=no sort, 1=by name, 2=by item size, 3=by total alloc */
	int maxcnt;  /* 0=no limit, other=max number of output entries */
};

static int mem_fail_rate __read_mostly = 0;
static int using_default_allocator __read_mostly = 1; // linked-in allocator or LD_PRELOADed one ?
static int disable_trim __read_mostly = 0;
static int(*my_mallctl)(const char *, void *, size_t *, void *, size_t) = NULL;
static int(*_malloc_trim)(size_t) = NULL;

/* returns the pool hash bucket an object should use based on its pointer.
 * Objects will needed consistent bucket assignment so that they may be
 * allocated on one thread and released on another one. Thus only the
 * pointer is usable.
 */
static forceinline unsigned int pool_pbucket(const void *ptr)
{
	return ptr_hash(ptr, CONFIG_HAP_POOL_BUCKETS_BITS);
}

/* returns the pool hash bucket to use for the current thread. This should only
 * be used when no pointer is available (e.g. count alloc failures).
 */
static forceinline unsigned int pool_tbucket(void)
{
	return tid % CONFIG_HAP_POOL_BUCKETS;
}

/* ask the allocator to trim memory pools.
 * This must run under thread isolation so that competing threads trying to
 * allocate or release memory do not prevent the allocator from completing
 * its job. We just have to be careful as callers might already be isolated
 * themselves.
 */
void trim_all_pools(void)
{
	int isolated = thread_isolated();

	if (!isolated)
		thread_isolate();

	malloc_trim(0);

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
		/* trick: we won't enter here if mallctl() is known at link
		 * time. This allows to detect if the symbol was changed since
		 * the program was linked, indicating it's not running on the
		 * expected allocator (due to an LD_PRELOAD) and that we must
		 * be extra cautious and avoid some optimizations that are
		 * known to break such as malloc_trim().
		 */
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

	/* detect presence of malloc_trim() */
	_malloc_trim = get_sym_next_addr("malloc_trim");
}

/* replace the libc's malloc_trim() so that we can also intercept the calls
 * from child libraries when the allocator is not the default one.
 */
int malloc_trim(size_t pad)
{
	int ret = 0;

	if (disable_trim)
		return ret;

	HA_ATOMIC_INC(&pool_trim_in_progress);

	if (my_mallctl) {
		/* here we're on jemalloc and malloc_trim() is called either
		 * by haproxy or another dependency (the worst case that
		 * normally crashes). Instead of just failing, we can actually
		 * emulate it so let's do it now.
		 */
		unsigned int i, narenas = 0;
		size_t len = sizeof(narenas);

		if (my_mallctl("arenas.narenas", &narenas, &len, NULL, 0) == 0) {
			for (i = 0; i < narenas; i ++) {
				char mib[32] = {0};
				snprintf(mib, sizeof(mib), "arena.%u.purge", i);
				(void)my_mallctl(mib, NULL, NULL, NULL, 0);
				ret = 1; // success
			}
		}
	}
	else if (!using_default_allocator) {
		/* special allocators that can be LD_PRELOADed end here */
		ret = 0; // did nothing
	}
	else if (_malloc_trim) {
		/* we're typically on glibc and not overridden */
		ret = _malloc_trim(pad);
	}
#if defined(HA_HAVE_MALLOC_ZONE)
	else {
		/* we're on MacOS, there's an equivalent mechanism */
		vm_address_t *zones;
		unsigned int i, nzones;

		if (malloc_get_all_zones(0, NULL, &zones, &nzones) == KERN_SUCCESS) {
			for (i = 0; i < nzones; i ++) {
				malloc_zone_t *zone = (malloc_zone_t *)zones[i];

				/* we cannot purge anonymous zones */
				if (zone->zone_name) {
					malloc_zone_pressure_relief(zone, 0);
					ret = 1; // success
				}
			}
		}
	}
#endif
	HA_ATOMIC_DEC(&pool_trim_in_progress);

	/* here we have ret=0 if nothing was release, or 1 if some were */
	return ret;
}

static int mem_should_fail(const struct pool_head *pool)
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

/* Try to find an existing shared pool with the same characteristics and
 * returns it, otherwise creates this one. NULL is returned if no memory
 * is available for a new creation. Two flags are supported :
 *   - MEM_F_SHARED to indicate that the pool may be shared with other users
 *   - MEM_F_EXACT to indicate that the size must not be rounded up
 */
struct pool_head *create_pool(char *name, unsigned int size, unsigned int flags)
{
	unsigned int extra_mark, extra_caller, extra;
	struct pool_head *pool;
	struct pool_head *entry;
	struct list *start;
	unsigned int align;
	int thr __maybe_unused;

	extra_mark = (pool_debugging & POOL_DBG_TAG) ? POOL_EXTRA_MARK : 0;
	extra_caller = (pool_debugging & POOL_DBG_CALLER) ? POOL_EXTRA_CALLER : 0;
	extra = extra_mark + extra_caller;

	if (!(pool_debugging & POOL_DBG_NO_CACHE)) {
		/* we'll store two lists there, we need the room for this. Let's
		 * make sure it's always OK even when including the extra word
		 * that is stored after the pci struct.
		 */
		if (size + extra - extra_caller < sizeof(struct pool_cache_item))
			size = sizeof(struct pool_cache_item) + extra_caller - extra;
	}

	/* Now we know our size is set to the strict minimum possible. It may
	 * be OK for elements allocated with an exact size (e.g. buffers), but
	 * we're going to round the size up 16 bytes to merge almost identical
	 * pools together. We only round up however when we add the debugging
	 * tag since it's used to detect overflows. Otherwise we only round up
	 * to the size of a word to preserve alignment.
	 */
	if (!(flags & MEM_F_EXACT)) {
		align = (pool_debugging & POOL_DBG_TAG) ? sizeof(void *) : 16;
		size  = ((size + align - 1) & -align);
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
			if ((flags & entry->flags & MEM_F_SHARED) &&
			    (!(pool_debugging & POOL_DBG_DONT_MERGE) ||
			     strcmp(name, entry->name) == 0)) {
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
		void *pool_addr;

		pool_addr = calloc(1, sizeof(*pool) + __alignof__(*pool));
		if (!pool_addr)
			return NULL;

		/* always provide an aligned pool */
		pool = (struct pool_head*)((((size_t)pool_addr) + __alignof__(*pool)) & -(size_t)__alignof__(*pool));
		pool->base_addr = pool_addr; // keep it, it's the address to free later

		if (name)
			strlcpy2(pool->name, name, sizeof(pool->name));
		pool->alloc_sz = size + extra;
		pool->size = size;
		pool->flags = flags;
		LIST_APPEND(start, &pool->list);

		if (!(pool_debugging & POOL_DBG_NO_CACHE)) {
			/* update per-thread pool cache if necessary */
			for (thr = 0; thr < MAX_THREADS; thr++) {
				LIST_INIT(&pool->cache[thr].list);
				pool->cache[thr].tid = thr;
				pool->cache[thr].pool = pool;
			}
		}
	}
	pool->users++;
	return pool;
}

/* Tries to allocate an object for the pool <pool> using the system's allocator
 * and directly returns it. The pool's allocated counter is checked but NOT
 * updated, this is left to the caller, and but no other checks are performed.
 */
void *pool_get_from_os_noinc(struct pool_head *pool)
{
	if (!pool->limit || pool_allocated(pool) < pool->limit) {
		void *ptr;

		if (pool_debugging & POOL_DBG_UAF)
			ptr = pool_alloc_area_uaf(pool->alloc_sz);
		else
			ptr = pool_alloc_area(pool->alloc_sz);
		if (ptr)
			return ptr;
		_HA_ATOMIC_INC(&pool->buckets[pool_tbucket()].failed);
	}
	activity[tid].pool_fail++;
	return NULL;

}

/* Releases a pool item back to the operating system but DOES NOT update
 * the allocation counter, it's left to the caller to do it. It may be
 * done before or after, it doesn't matter, the function does not use it.
 */
void pool_put_to_os_nodec(struct pool_head *pool, void *ptr)
{
	if (pool_debugging & POOL_DBG_UAF)
		pool_free_area_uaf(ptr, pool->alloc_sz);
	else
		pool_free_area(ptr, pool->alloc_sz);
}

/* Tries to allocate an object for the pool <pool> using the system's allocator
 * and directly returns it. The pool's counters are updated but the object is
 * never cached, so this is usable with and without local or shared caches.
 */
void *pool_alloc_nocache(struct pool_head *pool, const void *caller)
{
	void *ptr = NULL;
	uint bucket;
	uint used;

	ptr = pool_get_from_os_noinc(pool);
	if (!ptr)
		return NULL;

	bucket = pool_pbucket(ptr);

	_HA_ATOMIC_INC(&pool->buckets[bucket].allocated);
	used = _HA_ATOMIC_FETCH_ADD(&pool->buckets[bucket].used, 1);
	swrate_add_scaled_opportunistic(&pool->buckets[bucket].needed_avg, POOL_AVG_SAMPLES, used, POOL_AVG_SAMPLES/4);

	/* keep track of where the element was allocated from */
	POOL_DEBUG_SET_MARK(pool, ptr);
	POOL_DEBUG_TRACE_CALLER(pool, (struct pool_cache_item *)ptr, caller);
	return ptr;
}

/* Release a pool item back to the OS and keeps the pool's counters up to date.
 * This is always defined even when pools are not enabled (their usage stats
 * are maintained).
 */
void pool_free_nocache(struct pool_head *pool, void *ptr)
{
	uint bucket = pool_pbucket(ptr);
	uint used;

	used = _HA_ATOMIC_SUB_FETCH(&pool->buckets[bucket].used, 1);
	_HA_ATOMIC_DEC(&pool->buckets[bucket].allocated);
	swrate_add_opportunistic(&pool->buckets[bucket].needed_avg, POOL_AVG_SAMPLES, used);

	pool_put_to_os_nodec(pool, ptr);
}


/* Updates <pch>'s fill_pattern and fills the free area after <item> with it,
 * up to <size> bytes. The item part is left untouched.
 */
void pool_fill_pattern(struct pool_cache_head *pch, struct pool_cache_item *item, uint size)
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
void pool_check_pattern(struct pool_cache_head *pch, struct pool_head *pool, struct pool_cache_item *item, const void *caller)
{
	const ulong *ptr = (const ulong *)item;
	uint size = pool->size;
	uint ofs;
	ulong u;

	if (size <= sizeof(*item))
		return;

	/* let's check that all words past *item are equal */
	ofs = sizeof(*item) / sizeof(*ptr);
	u = ptr[ofs++];
	while (ofs < size / sizeof(*ptr)) {
		if (unlikely(ptr[ofs] != u)) {
			pool_inspect_item("cache corruption detected", pool, item, caller, ofs * sizeof(*ptr));
			ABORT_NOW();
		}
		ofs++;
	}
}

/* removes up to <count> items from the end of the local pool cache <ph> for
 * pool <pool>. The shared pool is refilled with these objects in the limit
 * of the number of acceptable objects, and the rest will be released to the
 * OS. It is not a problem is <count> is larger than the number of objects in
 * the local cache. The counters are automatically updated. Must not be used
 * with pools disabled.
 */
static void pool_evict_last_items(struct pool_head *pool, struct pool_cache_head *ph, uint count)
{
	struct pool_cache_item *item;
	struct pool_item *pi, *head = NULL;
	void *caller = __builtin_return_address(0);
	uint released = 0;
	uint cluster = 0;
	uint to_free_max;
	uint bucket;
	uint used;

	BUG_ON(pool_debugging & POOL_DBG_NO_CACHE);

	/* Note: this will be zero when global pools are disabled */
	to_free_max = pool_releasable(pool);

	while (released < count && !LIST_ISEMPTY(&ph->list)) {
		item = LIST_PREV(&ph->list, typeof(item), by_pool);
		BUG_ON(&item->by_pool == &ph->list);
		if (unlikely(pool_debugging & POOL_DBG_INTEGRITY))
			pool_check_pattern(ph, pool, item, caller);
		LIST_DELETE(&item->by_pool);
		LIST_DELETE(&item->by_lru);

		bucket = pool_pbucket(item);
		used = _HA_ATOMIC_SUB_FETCH(&pool->buckets[bucket].used, 1);
		swrate_add_opportunistic(&pool->buckets[bucket].needed_avg, POOL_AVG_SAMPLES, used);

		if (to_free_max > released || cluster) {
			/* will never match when global pools are disabled */
			pi = (struct pool_item *)item;
			pi->next = NULL;
			pi->down = head;
			head = pi;
			cluster++;
			if (cluster >= CONFIG_HAP_POOL_CLUSTER_SIZE) {
				/* enough to make a cluster */
				pool_put_to_shared_cache(pool, head);
				cluster = 0;
				head = NULL;
			}
		} else {
			/* does pool_free_nocache() with a known bucket */
			_HA_ATOMIC_DEC(&pool->buckets[bucket].allocated);
			pool_put_to_os_nodec(pool, item);
		}

		released++;
	}

	/* incomplete cluster left */
	if (cluster)
		pool_put_to_shared_cache(pool, head);

	ph->count -= released;
	pool_cache_count -= released;
	pool_cache_bytes -= released * pool->size;
}

/* Evicts some of the oldest objects from one local cache, until its number of
 * objects is no more than 16+1/8 of the total number of locally cached objects
 * or the total size of the local cache is no more than 75% of its maximum (i.e.
 * we don't want a single cache to use all the cache for itself). For this, the
 * list is scanned in reverse. If <full> is non-null, all objects are evicted.
 * Must not be used when pools are disabled.
 */
void pool_evict_from_local_cache(struct pool_head *pool, int full)
{
	struct pool_cache_head *ph = &pool->cache[tid];

	BUG_ON(pool_debugging & POOL_DBG_NO_CACHE);

	while ((ph->count && full) ||
	       (ph->count >= CONFIG_HAP_POOL_CLUSTER_SIZE &&
	        ph->count >= 16 + pool_cache_count / 8 &&
	        pool_cache_bytes > global.tune.pool_cache_size * 3 / 4)) {
		pool_evict_last_items(pool, ph, CONFIG_HAP_POOL_CLUSTER_SIZE);
	}
}

/* Evicts some of the oldest objects from the local cache, pushing them to the
 * global pool. Must not be used when pools are disabled.
 */
void pool_evict_from_local_caches()
{
	struct pool_cache_item *item;
	struct pool_cache_head *ph;
	struct pool_head *pool;

	BUG_ON(pool_debugging & POOL_DBG_NO_CACHE);

	do {
		item = LIST_PREV(&th_ctx->pool_lru_head, struct pool_cache_item *, by_lru);
		BUG_ON(&item->by_lru == &th_ctx->pool_lru_head);
		/* note: by definition we remove oldest objects so they also are the
		 * oldest in their own pools, thus their next is the pool's head.
		 */
		ph = LIST_NEXT(&item->by_pool, struct pool_cache_head *, list);
		BUG_ON(ph->tid != tid);

		pool = container_of(ph - tid, struct pool_head, cache);
		BUG_ON(pool != ph->pool);

		pool_evict_last_items(pool, ph, CONFIG_HAP_POOL_CLUSTER_SIZE);
	} while (pool_cache_bytes > global.tune.pool_cache_size * 7 / 8);
}

/* Frees an object to the local cache, possibly pushing oldest objects to the
 * shared cache, which itself may decide to release some of them to the OS.
 * While it is unspecified what the object becomes past this point, it is
 * guaranteed to be released from the users' perspective. A caller address may
 * be passed and stored into the area when DEBUG_POOL_TRACING is set. Must not
 * be used with pools disabled.
 */
void pool_put_to_cache(struct pool_head *pool, void *ptr, const void *caller)
{
	struct pool_cache_item *item = (struct pool_cache_item *)ptr;
	struct pool_cache_head *ph = &pool->cache[tid];

	BUG_ON(pool_debugging & POOL_DBG_NO_CACHE);

	LIST_INSERT(&ph->list, &item->by_pool);
	LIST_INSERT(&th_ctx->pool_lru_head, &item->by_lru);
	POOL_DEBUG_TRACE_CALLER(pool, item, caller);
	ph->count++;
	if (unlikely(pool_debugging & POOL_DBG_INTEGRITY))
		pool_fill_pattern(ph, item, pool->size);
	pool_cache_count++;
	pool_cache_bytes += pool->size;

	if (unlikely(pool_cache_bytes > global.tune.pool_cache_size * 3 / 4)) {
		if (ph->count >= 16 + pool_cache_count / 8 + CONFIG_HAP_POOL_CLUSTER_SIZE)
			pool_evict_from_local_cache(pool, 0);
		if (pool_cache_bytes > global.tune.pool_cache_size)
			pool_evict_from_local_caches();
	}
}

/* Tries to refill the local cache <pch> from the shared one for pool <pool>.
 * This is only used when pools are in use and shared pools are enabled. No
 * malloc() is attempted, and poisonning is never performed. The purpose is to
 * get the fastest possible refilling so that the caller can easily check if
 * the cache has enough objects for its use. Must not be used when pools are
 * disabled.
 */
void pool_refill_local_from_shared(struct pool_head *pool, struct pool_cache_head *pch)
{
	struct pool_cache_item *item;
	struct pool_item *ret, *down;
	uint bucket;
	uint count;

	BUG_ON(pool_debugging & POOL_DBG_NO_CACHE);

	/* we'll need to reference the first element to figure the next one. We
	 * must temporarily lock it so that nobody allocates then releases it,
	 * or the dereference could fail. In order to limit the locking,
	 * threads start from a bucket that depends on their ID.
	 */

	bucket = pool_tbucket();
	ret = _HA_ATOMIC_LOAD(&pool->buckets[bucket].free_list);
	count = 0;
	do {
		/* look for an apparently non-busy entry. If we hit a busy pool
		 * we retry with another random bucket. And if we encounter a
		 * NULL, we retry once with another random bucket. This is in
		 * order to prevent object accumulation in other buckets.
		 */
		while (unlikely(ret == POOL_BUSY || (ret == NULL && count++ < 1))) {
			bucket = statistical_prng() % CONFIG_HAP_POOL_BUCKETS;
			ret = _HA_ATOMIC_LOAD(&pool->buckets[bucket].free_list);
		}
		if (ret == NULL)
			return;
	} while (unlikely((ret = _HA_ATOMIC_XCHG(&pool->buckets[bucket].free_list, POOL_BUSY)) == POOL_BUSY));

	if (unlikely(ret == NULL)) {
		HA_ATOMIC_STORE(&pool->buckets[bucket].free_list, NULL);
		return;
	}

	/* this releases the lock */
	HA_ATOMIC_STORE(&pool->buckets[bucket].free_list, ret->next);

	/* now store the retrieved object(s) into the local cache. Note that
	 * they don't all have the same hash and that it doesn't necessarily
	 * match the one from the pool.
	 */
	count = 0;
	for (; ret; ret = down) {
		down = ret->down;
		item = (struct pool_cache_item *)ret;
		POOL_DEBUG_TRACE_CALLER(pool, item, NULL);
		LIST_INSERT(&pch->list, &item->by_pool);
		LIST_INSERT(&th_ctx->pool_lru_head, &item->by_lru);
		_HA_ATOMIC_INC(&pool->buckets[pool_pbucket(item)].used);
		count++;
		if (unlikely(pool_debugging & POOL_DBG_INTEGRITY))
			pool_fill_pattern(pch, item, pool->size);

	}
	pch->count += count;
	pool_cache_count += count;
	pool_cache_bytes += count * pool->size;
}

/* Adds pool item cluster <item> to the shared cache, which contains <count>
 * elements. The caller is advised to first check using pool_releasable() if
 * it's wise to add this series of objects there. Both the pool and the item's
 * head must be valid.
 */
void pool_put_to_shared_cache(struct pool_head *pool, struct pool_item *item)
{
	struct pool_item *free_list;
	uint bucket = pool_pbucket(item);

	/* we prefer to put the item into the entry that corresponds to its own
	 * hash so that on return it remains in the right place, but that's not
	 * mandatory.
	 */
	free_list = _HA_ATOMIC_LOAD(&pool->buckets[bucket].free_list);
	do {
		/* look for an apparently non-busy entry */
		while (unlikely(free_list == POOL_BUSY)) {
			bucket = (bucket + 1) % CONFIG_HAP_POOL_BUCKETS;
			free_list = _HA_ATOMIC_LOAD(&pool->buckets[bucket].free_list);
		}
		_HA_ATOMIC_STORE(&item->next, free_list);
		__ha_barrier_atomic_store();
	} while (!_HA_ATOMIC_CAS(&pool->buckets[bucket].free_list, &free_list, item));
	__ha_barrier_atomic_store();
}

/*
 * This function frees whatever can be freed in pool <pool>.
 */
void pool_flush(struct pool_head *pool)
{
	struct pool_item *next, *temp, *down;
	uint bucket;

	if (!pool || (pool_debugging & (POOL_DBG_NO_CACHE|POOL_DBG_NO_GLOBAL)))
		return;

	/* The loop below atomically detaches the head of the free list and
	 * replaces it with a NULL. Then the list can be released.
	 */
	for (bucket = 0; bucket < CONFIG_HAP_POOL_BUCKETS; bucket++) {
		next = pool->buckets[bucket].free_list;
		while (1) {
			while (unlikely(next == POOL_BUSY))
				next = (void*)pl_wait_new_long((ulong*)&pool->buckets[bucket].free_list, (ulong)next);

			if (next == NULL)
				break;

			next = _HA_ATOMIC_XCHG(&pool->buckets[bucket].free_list, POOL_BUSY);
			if (next != POOL_BUSY) {
				HA_ATOMIC_STORE(&pool->buckets[bucket].free_list, NULL);
				break;
			}
		}

		while (next) {
			temp = next;
			next = temp->next;
			for (; temp; temp = down) {
				down = temp->down;
				_HA_ATOMIC_DEC(&pool->buckets[pool_pbucket(temp)].allocated);
				pool_put_to_os_nodec(pool, temp);
			}
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
		uint allocated = pool_allocated(entry);
		uint used = pool_used(entry);
		int bucket = 0;

		while ((int)(allocated - used) > (int)entry->minavail) {
			/* ok let's find next entry to evict */
			while (!entry->buckets[bucket].free_list && bucket < CONFIG_HAP_POOL_BUCKETS)
				bucket++;

			if (bucket >= CONFIG_HAP_POOL_BUCKETS)
				break;

			temp = entry->buckets[bucket].free_list;
			entry->buckets[bucket].free_list = temp->next;
			for (; temp; temp = down) {
				down = temp->down;
				allocated--;
				_HA_ATOMIC_DEC(&entry->buckets[pool_pbucket(temp)].allocated);
				pool_put_to_os_nodec(entry, temp);
			}
		}
	}

	trim_all_pools();

	if (!isolated)
		thread_release();
}

/*
 * Returns a pointer to type <type> taken from the pool <pool_type> or
 * dynamically allocated. In the first case, <pool_type> is updated to point to
 * the next element in the list. <flags> is a binary-OR of POOL_F_* flags.
 * Prefer using pool_alloc() which does the right thing without flags.
 */
void *__pool_alloc(struct pool_head *pool, unsigned int flags)
{
	void *p = NULL;
	void *caller = __builtin_return_address(0);

	if (unlikely(pool_debugging & POOL_DBG_FAIL_ALLOC))
		if (!(flags & POOL_F_NO_FAIL) && mem_should_fail(pool))
			return NULL;

	if (likely(!(pool_debugging & POOL_DBG_NO_CACHE)) && !p)
		p = pool_get_from_cache(pool, caller);

	if (unlikely(!p))
		p = pool_alloc_nocache(pool, caller);

	if (likely(p)) {
#ifdef USE_MEMORY_PROFILING
		if (unlikely(profiling & HA_PROF_MEMORY)) {
			extern struct memprof_stats memprof_stats[MEMPROF_HASH_BUCKETS + 1];
			struct memprof_stats *bin;

			bin = memprof_get_bin(__builtin_return_address(0), MEMPROF_METH_P_ALLOC);
			_HA_ATOMIC_ADD(&bin->alloc_calls, 1);
			_HA_ATOMIC_ADD(&bin->alloc_tot, pool->size);
			_HA_ATOMIC_STORE(&bin->info, pool);
			/* replace the caller with the allocated bin: this way
			 * we'll the pool_free() call will be able to update our
			 * entry. We only do it for non-colliding entries though,
			 * since these ones store the true caller location.
			 */
			if (bin >= &memprof_stats[0] && bin < &memprof_stats[MEMPROF_HASH_BUCKETS])
				POOL_DEBUG_TRACE_CALLER(pool, (struct pool_cache_item *)p, bin);
		}
#endif
		if (unlikely(flags & POOL_F_MUST_ZERO))
			memset(p, 0, pool->size);
		else if (unlikely(!(flags & POOL_F_NO_POISON) && (pool_debugging & POOL_DBG_POISON)))
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
	const void *caller = __builtin_return_address(0);

	/* we'll get late corruption if we refill to the wrong pool or double-free */
	POOL_DEBUG_CHECK_MARK(pool, ptr, caller);
	POOL_DEBUG_RESET_MARK(pool, ptr);

#ifdef USE_MEMORY_PROFILING
	if (unlikely(profiling & HA_PROF_MEMORY) && ptr) {
		extern struct memprof_stats memprof_stats[MEMPROF_HASH_BUCKETS + 1];
		struct memprof_stats *bin;

		bin = memprof_get_bin(__builtin_return_address(0), MEMPROF_METH_P_FREE);
		_HA_ATOMIC_ADD(&bin->free_calls, 1);
		_HA_ATOMIC_ADD(&bin->free_tot, pool->size);
		_HA_ATOMIC_STORE(&bin->info, pool);

		/* check if the caller is an allocator, and if so, let's update
		 * its free() count.
		 */
		bin = *(struct memprof_stats**)(((char *)ptr) + pool->alloc_sz - sizeof(void*));
		if (bin >= &memprof_stats[0] && bin < &memprof_stats[MEMPROF_HASH_BUCKETS]) {
			_HA_ATOMIC_ADD(&bin->free_calls, 1);
			_HA_ATOMIC_ADD(&bin->free_tot, pool->size);
		}
	}
#endif

	if (unlikely((pool_debugging & POOL_DBG_NO_CACHE) ||
		     global.tune.pool_cache_size < pool->size)) {
		pool_free_nocache(pool, ptr);
		return;
	}

	pool_put_to_cache(pool, ptr, caller);
}

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
		if (!(pool_debugging & POOL_DBG_NO_CACHE))
			pool_evict_from_local_cache(pool, 1);

		pool_flush(pool);
		if (pool_used(pool))
			return pool;
		pool->users--;
		if (!pool->users) {
			LIST_DELETE(&pool->list);
			/* note that if used == 0, the cache is empty */
			free(pool->base_addr);
		}

		/* make sure this pool is no longer referenced in memory profiling */
		memprof_remove_stale_info(pool);
	}
	return NULL;
}

/* This destroys all pools on exit. It is *not* thread safe. */
void pool_destroy_all()
{
	struct pool_head *entry, *back;

	list_for_each_entry_safe(entry, back, &pools, list) {
		/* there's only one occurrence of each pool in the list,
		 * and we're existing instead of looping on the whole
		 * list just to decrement users, force it to 1 here.
		 */
		entry->users = 1;
		pool_destroy(entry);
	}
}

/* carefully inspects an item upon fatal error and emit diagnostics.
 * If ofs < 0, no hint is provided regarding the content location. However if
 * ofs >= 0, then we also try to inspect around that place where corruption
 * was detected.
 */
void pool_inspect_item(const char *msg, struct pool_head *pool, const void *item, const void *caller, ssize_t ofs)
{
	const struct pool_head *the_pool = NULL;

	chunk_printf(&trash,
		     "FATAL: pool inconsistency detected in thread %d: %s.\n"
		     "  caller: %p (",
		     tid + 1, msg, caller);

	resolve_sym_name(&trash, NULL, caller);

	chunk_appendf(&trash,
		      ")\n"
		      "  item: %p\n"
		      "  pool: %p ('%s', size %u, real %u, users %u)\n",
		      item, pool, pool->name, pool->size, pool->alloc_sz, pool->users);

	if (ofs >= 0) {
		chunk_printf(&trash, "Contents around first corrupted address relative to pool item:.\n");
		dump_area_with_syms(&trash, item, item + ofs, NULL, NULL, NULL);
	}

	if (pool_debugging & POOL_DBG_TAG) {
		const void **pool_mark;
		struct pool_head *ph;
		const void *tag;

		pool_mark = (const void **)(((char *)item) + pool->size);
		tag =  may_access(pool_mark) ? *pool_mark : NULL;
		if (tag == pool) {
			chunk_appendf(&trash, "  tag: @%p = %p (%s)\n", pool_mark, tag, pool->name);
			the_pool = pool;
		}
		else {
			if (!may_access(pool_mark))
				chunk_appendf(&trash, "Tag not accessible. ");
			else
				chunk_appendf(&trash, "Tag does not match (%p). ", tag);

			list_for_each_entry(ph, &pools, list) {
				pool_mark = (const void **)(((char *)item) + ph->size);
				if (!may_access(pool_mark))
					continue;
				tag =  *pool_mark;

				if (tag == ph) {
					if (!the_pool)
						chunk_appendf(&trash, "Possible origin pool(s):\n");

					chunk_appendf(&trash, "  tag: @%p = %p (%s, size %u, real %u, users %u)\n",
						      pool_mark, tag, ph->name, ph->size, ph->alloc_sz, ph->users);
					if (!the_pool || the_pool->size < ph->size)
						the_pool = ph;
				}
			}

			if (!the_pool) {
				chunk_appendf(&trash,
					      "Tag does not match any other pool.\n");

				pool_mark = (const void **)(((char *)item) + pool->size);
				if (resolve_sym_name(&trash, "Resolving the tag as a pool_free() location: ", *pool_mark))
					chunk_appendf(&trash, "\n");
				else
					chunk_appendf(&trash, " (no match).\n");

				dump_area_with_syms(&trash, item, pool_mark, pool, "pool", pool->name);
			}
		}
	}

	if (pool_debugging & POOL_DBG_CALLER) {
		struct buffer *trash2 = get_trash_chunk();
		const struct pool_head *ph;
		const void **pool_mark;
		const void *tag, *rec_tag;

		ph = the_pool ? the_pool : pool;
		pool_mark = (const void **)(((char *)item) + ph->alloc_sz - sizeof(void*));
		rec_tag =  may_access(pool_mark) ? *pool_mark : NULL;

		if (rec_tag && resolve_sym_name(trash2, NULL, rec_tag))
			chunk_appendf(&trash,
				      "Recorded caller if pool '%s':\n  @%p (+%04u) = %p (%s)\n",
				      ph->name, pool_mark, (uint)(ph->alloc_sz - sizeof(void*)),
				      rec_tag, trash2->area);

		if (!the_pool) {
			/* the pool couldn't be formally verified */
			chunk_appendf(&trash, "Other possible callers:\n");
			list_for_each_entry(ph, &pools, list) {
				if (ph == pool)
					continue;
				pool_mark = (const void **)(((char *)item) + ph->alloc_sz - sizeof(void*));
				if (!may_access(pool_mark))
					continue;
				tag = *pool_mark;
				if (tag == rec_tag)
					continue;

				/* see if we can resolve something */
				chunk_printf(trash2, "@%p (+%04u) = %p (", pool_mark, (uint)(ph->alloc_sz - sizeof(void*)), tag);
				if (resolve_sym_name(trash2, NULL, tag)) {
					chunk_appendf(trash2, ")");
					chunk_appendf(&trash,
						      "  %s [as pool %s, size %u, real %u, users %u]\n",
						      trash2->area, ph->name, ph->size, ph->alloc_sz, ph->users);
				}
			}
		}
	}

	chunk_appendf(&trash, "\n");
	DISGUISE(write(2, trash.area, trash.data));
}

/* used by qsort in "show pools" to sort by name */
static int cmp_dump_pools_name(const void *a, const void *b)
{
	const struct pool_dump_info *l = (const struct pool_dump_info *)a;
	const struct pool_dump_info *r = (const struct pool_dump_info *)b;

	return strcmp(l->entry->name, r->entry->name);
}

/* used by qsort in "show pools" to sort by item size */
static int cmp_dump_pools_size(const void *a, const void *b)
{
	const struct pool_dump_info *l = (const struct pool_dump_info *)a;
	const struct pool_dump_info *r = (const struct pool_dump_info *)b;

	if (l->entry->size > r->entry->size)
		return -1;
	else if (l->entry->size < r->entry->size)
		return 1;
	else
		return 0;
}

/* used by qsort in "show pools" to sort by usage */
static int cmp_dump_pools_usage(const void *a, const void *b)
{
	const struct pool_dump_info *l = (const struct pool_dump_info *)a;
	const struct pool_dump_info *r = (const struct pool_dump_info *)b;

	if (l->alloc_bytes > r->alloc_bytes)
		return -1;
	else if (l->alloc_bytes < r->alloc_bytes)
		return 1;
	else
		return 0;
}

/* will not dump more than this number of entries. Anything beyond this will
 * likely not fit into a regular output buffer anyway.
 */
#define POOLS_MAX_DUMPED_ENTRIES 1024

/* This function dumps memory usage information into the trash buffer.
 * It may sort by a criterion if <by_what> is non-zero, and limit the
 * number of output lines if <max> is non-zero. It may limit only to
 * pools whose names start with <pfx> if <pfx> is non-null.
 */
void dump_pools_to_trash(int by_what, int max, const char *pfx)
{
	struct pool_dump_info pool_info[POOLS_MAX_DUMPED_ENTRIES];
	struct pool_head *entry;
	unsigned long long allocated, used;
	int nbpools, i;
	unsigned long long cached_bytes = 0;
	uint cached = 0;
	uint alloc_items;

	allocated = used = nbpools = 0;

	list_for_each_entry(entry, &pools, list) {
		if (nbpools >= POOLS_MAX_DUMPED_ENTRIES)
			break;

		alloc_items = pool_allocated(entry);
		/* do not dump unused entries when sorting by usage */
		if (by_what == 3 && !alloc_items)
			continue;

		/* verify the pool name if a prefix is requested */
		if (pfx && strncmp(entry->name, pfx, strlen(pfx)) != 0)
			continue;

		if (!(pool_debugging & POOL_DBG_NO_CACHE)) {
			for (cached = i = 0; i < global.nbthread; i++)
				cached += entry->cache[i].count;
		}
		pool_info[nbpools].entry = entry;
		pool_info[nbpools].alloc_items = alloc_items;
		pool_info[nbpools].alloc_bytes = (ulong)entry->size * alloc_items;
		pool_info[nbpools].used_items = pool_used(entry);
		pool_info[nbpools].cached_items = cached;
		pool_info[nbpools].need_avg = swrate_avg(pool_needed_avg(entry), POOL_AVG_SAMPLES);
		pool_info[nbpools].failed_items = pool_failed(entry);
		nbpools++;
	}

	if (by_what == 1)  /* sort by name */
		qsort(pool_info, nbpools, sizeof(pool_info[0]), cmp_dump_pools_name);
	else if (by_what == 2)  /* sort by item size */
		qsort(pool_info, nbpools, sizeof(pool_info[0]), cmp_dump_pools_size);
	else if (by_what == 3)  /* sort by total usage */
		qsort(pool_info, nbpools, sizeof(pool_info[0]), cmp_dump_pools_usage);

	chunk_printf(&trash, "Dumping pools usage");
	if (!max || max >= POOLS_MAX_DUMPED_ENTRIES)
		max = POOLS_MAX_DUMPED_ENTRIES;
	if (nbpools >= max)
		chunk_appendf(&trash, " (limited to the first %u entries)", max);
	chunk_appendf(&trash, ". Use SIGQUIT to flush them.\n");

	for (i = 0; i < nbpools && i < max; i++) {
		chunk_appendf(&trash, "  - Pool %s (%lu bytes) : %lu allocated (%lu bytes), %lu used"
			      " (~%lu by thread caches)"
			      ", needed_avg %lu, %lu failures, %u users, @%p%s\n",
		              pool_info[i].entry->name, (ulong)pool_info[i].entry->size,
			      pool_info[i].alloc_items, pool_info[i].alloc_bytes,
			      pool_info[i].used_items, pool_info[i].cached_items,
			      pool_info[i].need_avg, pool_info[i].failed_items,
		              pool_info[i].entry->users, pool_info[i].entry,
		              (pool_info[i].entry->flags & MEM_F_SHARED) ? " [SHARED]" : "");

		cached_bytes += pool_info[i].cached_items * (ulong)pool_info[i].entry->size;
		allocated    += pool_info[i].alloc_items  * (ulong)pool_info[i].entry->size;
		used         += pool_info[i].used_items   * (ulong)pool_info[i].entry->size;
	}

	chunk_appendf(&trash, "Total: %d pools, %llu bytes allocated, %llu used"
		      " (~%llu by thread caches)"
		      ".\n",
	              nbpools, allocated, used, cached_bytes
		      );
}

/* Dump statistics on pools usage. */
void dump_pools(void)
{
	dump_pools_to_trash(0, 0, NULL);
	qfprintf(stderr, "%s", trash.area);
}

/* This function returns the total number of failed pool allocations */
int pool_total_failures()
{
	struct pool_head *entry;
	int failed = 0;

	list_for_each_entry(entry, &pools, list)
		failed += pool_failed(entry);
	return failed;
}

/* This function returns the total amount of memory allocated in pools (in bytes) */
unsigned long long pool_total_allocated()
{
	struct pool_head *entry;
	unsigned long long allocated = 0;

	list_for_each_entry(entry, &pools, list)
		allocated += pool_allocated(entry) * (ullong)entry->size;
	return allocated;
}

/* This function returns the total amount of memory used in pools (in bytes) */
unsigned long long pool_total_used()
{
	struct pool_head *entry;
	unsigned long long used = 0;

	list_for_each_entry(entry, &pools, list)
		used += pool_used(entry) * (ullong)entry->size;
	return used;
}

/* This function parses a string made of a set of debugging features as
 * specified after -dM on the command line, and will set pool_debugging
 * accordingly. On success it returns a strictly positive value. It may zero
 * with the first warning in <err>, -1 with a help message in <err>, or -2 with
 * the first error in <err> return the first error in <err>. <err> is undefined
 * on success, and will be non-null and locally allocated on help/error/warning.
 * The caller must free it. Warnings are used to report features that were not
 * enabled at build time, and errors are used to report unknown features.
 */
int pool_parse_debugging(const char *str, char **err)
{
	struct ist args;
	char *end;
	uint new_dbg;
	int v;


	/* if it's empty or starts with a number, it's the mem poisonning byte */
	v = strtol(str, &end, 0);
	if (!*end || *end == ',') {
		mem_poison_byte = *str ? v : 'P';
		if (mem_poison_byte >= 0)
			pool_debugging |=  POOL_DBG_POISON;
		else
			pool_debugging &= ~POOL_DBG_POISON;
		str = end;
	}

	new_dbg = pool_debugging;

	for (args = ist(str); istlen(args); args = istadv(istfind(args, ','), 1)) {
		struct ist feat = iststop(args, ',');

		if (!istlen(feat))
			continue;

		if (isteq(feat, ist("help"))) {
			ha_free(err);
			memprintf(err,
				  "-dM alone enables memory poisonning with byte 0x50 on allocation. A numeric\n"
				  "value may be appended immediately after -dM to use another value (0 supported).\n"
				  "Then an optional list of comma-delimited keywords may be appended to set or\n"
				  "clear some debugging options ('*' marks the current setting):\n\n"
				  "    set               clear            description\n"
				  "  -----------------+-----------------+-----------------------------------------\n");

			for (v = 0; dbg_options[v].flg; v++) {
				memprintf(err, "%s  %c %-15s|%c %-15s| %s\n",
					  *err,
					  (pool_debugging & dbg_options[v].flg) ? '*' : ' ',
					  dbg_options[v].set,
					  (pool_debugging & dbg_options[v].flg) ? ' ' : '*',
					  dbg_options[v].clr,
					  dbg_options[v].hlp);
			}

			memprintf(err,
			          "%s  -----------------+-----------------+-----------------------------------------\n"
				  "Examples:\n"
				  "  Disable merging and enable poisonning with byte 'P': -dM0x50,no-merge\n"
				  "  Randomly fail allocations: -dMfail\n"
				  "  Detect out-of-bound corruptions: -dMno-merge,tag\n"
				  "  Detect post-free cache corruptions: -dMno-merge,cold-first,integrity,caller\n"
				  "  Detect all cache corruptions: -dMno-merge,cold-first,integrity,tag,caller\n"
				  "  Detect UAF (disables cache, very slow): -dMuaf\n"
				  "  Detect post-cache UAF: -dMuaf,cache,no-merge,cold-first,integrity,tag,caller\n"
				  "  Detect post-free cache corruptions: -dMno-merge,cold-first,integrity,caller\n",
			          *err);
			return -1;
		}

		for (v = 0; dbg_options[v].flg; v++) {
			if (isteq(feat, ist(dbg_options[v].set))) {
				new_dbg |= dbg_options[v].flg;
				/* UAF implicitly disables caching, but it's
				 * still possible to forcefully re-enable it.
				 */
				if (dbg_options[v].flg == POOL_DBG_UAF)
					new_dbg |= POOL_DBG_NO_CACHE;
				/* fail should preset the tune.fail-alloc ratio to 1%  */
				if (dbg_options[v].flg == POOL_DBG_FAIL_ALLOC)
					mem_fail_rate = 1;
				break;
			}
			else if (isteq(feat, ist(dbg_options[v].clr))) {
				new_dbg &= ~dbg_options[v].flg;
				/* no-fail should reset the tune.fail-alloc ratio */
				if (dbg_options[v].flg == POOL_DBG_FAIL_ALLOC)
					mem_fail_rate = 0;
				break;
			}
		}

		if (!dbg_options[v].flg) {
			memprintf(err, "unknown pool debugging feature <%.*s>", (int)istlen(feat), istptr(feat));
			return -2;
		}
	}

	pool_debugging = new_dbg;
	return 1;
}

/* parse a "show pools" command. It returns 1 on failure, 0 if it starts to dump. */
static int cli_parse_show_pools(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_pools_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	int arg;

	for (arg = 2; *args[arg]; arg++) {
		if (strcmp(args[arg], "byname") == 0) {
			ctx->by_what = 1; // sort output by name
		}
		else if (strcmp(args[arg], "bysize") == 0) {
			ctx->by_what = 2; // sort output by item size
		}
		else if (strcmp(args[arg], "byusage") == 0) {
			ctx->by_what = 3; // sort output by total allocated size
		}
		else if (strcmp(args[arg], "match") == 0 && *args[arg+1]) {
			ctx->prefix = strdup(args[arg+1]); // only pools starting with this
			if (!ctx->prefix)
				return cli_err(appctx, "Out of memory.\n");
			arg++;
		}
		else if (isdigit((unsigned char)*args[arg])) {
			ctx->maxcnt = atoi(args[arg]); // number of entries to dump
		}
		else
			return cli_err(appctx, "Expects either 'byname', 'bysize', 'byusage', 'match <pfx>', or a max number of output lines.\n");
	}
	return 0;
}

/* release the "show pools" context */
static void cli_release_show_pools(struct appctx *appctx)
{
	struct show_pools_ctx *ctx = appctx->svcctx;

	ha_free(&ctx->prefix);
}

/* This function dumps memory usage information onto the stream connector's
 * read buffer. It returns 0 as long as it does not complete, non-zero upon
 * completion. No state is used.
 */
static int cli_io_handler_dump_pools(struct appctx *appctx)
{
	struct show_pools_ctx *ctx = appctx->svcctx;

	dump_pools_to_trash(ctx->by_what, ctx->maxcnt, ctx->prefix);
	if (applet_putchk(appctx, &trash) == -1)
		return 0;
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
	int thr;

	for (thr = 0; thr < MAX_THREADS; thr++) {
		LIST_INIT(&ha_thread_ctx[thr].pool_lru_head);
	}

	detect_allocator();
}

INITCALL0(STG_PREPARE, init_pools);

/* Report in build options if trim is supported */
static void pools_register_build_options(void)
{
	if (!using_default_allocator) {
		char *ptr = NULL;
		memprintf(&ptr, "Running with a replaced memory allocator (e.g. via LD_PRELOAD).");
		hap_register_build_opts(ptr, 1);
		mark_tainted(TAINTED_REPLACED_MEM_ALLOCATOR);
	}
}
INITCALL0(STG_REGISTER, pools_register_build_options);

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "pools",  NULL }, "show pools [by*] [match <pfx>] [nb]     : report information about the memory pools usage", cli_parse_show_pools, cli_io_handler_dump_pools, cli_release_show_pools },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);


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

/* config parser for global "tune.memory.hot-size" */
static int mem_parse_global_hot_size(char **args, int section_type, struct proxy *curpx,
                                       const struct proxy *defpx, const char *file, int line,
                                       char **err)
{
	long size;

	if (too_many_args(1, args, err, NULL))
		return -1;

	size = atol(args[1]);
	if (size <= 0) {
	    memprintf(err, "'%s' expects a strictly positive value.", args[0]);
	    return -1;
	}

	global.tune.pool_cache_size = size;
	return 0;
}

/* config parser for global "no-memory-trimming" */
static int mem_parse_global_no_mem_trim(char **args, int section_type, struct proxy *curpx,
                                       const struct proxy *defpx, const char *file, int line,
                                       char **err)
{
	if (too_many_args(0, args, err, NULL))
		return -1;
	disable_trim = 1;
	return 0;
}

/* register global config keywords */
static struct cfg_kw_list mem_cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.fail-alloc", mem_parse_global_fail_alloc },
	{ CFG_GLOBAL, "tune.memory.hot-size", mem_parse_global_hot_size },
	{ CFG_GLOBAL, "no-memory-trimming", mem_parse_global_no_mem_trim },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &mem_cfg_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
