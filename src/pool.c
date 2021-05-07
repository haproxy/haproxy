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

#include <haproxy/activity-t.h>
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
		HA_SPIN_INIT(&pool->lock);
	}
	pool->users++;
	return pool;
}

/* Tries to allocate an object for the pool <pool> using the system's allocator
 * and directly returns it. The pool's allocated counter is checked and updated,
 * but no other checks are performed. The pool's lock is not used and is not a
 * problem either.
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
	pool_free_area(ptr, pool->size + POOL_EXTRA);
	_HA_ATOMIC_DEC(&pool->allocated);
}

/* Tries to allocate an object for the pool <pool> using the system's allocator
 * and directly returns it. The pool's counters are updated but the object is
 * never cached, so this is usable with and without local or shared caches.
 * This may be called with or without the pool lock held, so it must not use
 * the pool's lock.
 */
void *pool_alloc_nocache(struct pool_head *pool)
{
	void *ptr = NULL;

	ptr = pool_get_from_os(pool);
	if (!ptr)
		return NULL;

	swrate_add_scaled(&pool->needed_avg, POOL_AVG_SAMPLES, pool->used, POOL_AVG_SAMPLES/4);
	_HA_ATOMIC_INC(&pool->used);

#ifdef DEBUG_MEMORY_POOLS
	/* keep track of where the element was allocated from */
	*POOL_LINK(pool, ptr) = (void *)pool;
#endif
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

/* Evicts some of the oldest objects from one local cache, until its number of
 * objects is no more than 16+1/8 of the total number of locally cached objects
 * or the total size of the local cache is no more than 75% of its maximum (i.e.
 * we don't want a single cache to use all the cache for itself). For this, the
 * list is scanned in reverse.
 */
void pool_evict_from_local_cache(struct pool_head *pool)
{
	struct pool_cache_head *ph = &pool->cache[tid];
	struct pool_cache_item *item;

	while (ph->count >= 16 + pool_cache_count / 8 &&
	       pool_cache_bytes > CONFIG_HAP_POOL_CACHE_SIZE * 3 / 4) {
		item = LIST_NEXT(&ph->list, typeof(item), by_pool);
		ph->count--;
		pool_cache_bytes -= pool->size;
		pool_cache_count--;
		LIST_DELETE(&item->by_pool);
		LIST_DELETE(&item->by_lru);
		pool_put_to_shared_cache(pool, item);
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
		item = LIST_PREV(&ti->pool_lru_head, struct pool_cache_item *, by_lru);
		/* note: by definition we remove oldest objects so they also are the
		 * oldest in their own pools, thus their next is the pool's head.
		 */
		ph = LIST_NEXT(&item->by_pool, struct pool_cache_head *, list);
		pool = container_of(ph - tid, struct pool_head, cache);
		LIST_DELETE(&item->by_pool);
		LIST_DELETE(&item->by_lru);
		ph->count--;
		pool_cache_count--;
		pool_cache_bytes -= pool->size;
		pool_put_to_shared_cache(pool, item);
	} while (pool_cache_bytes > CONFIG_HAP_POOL_CACHE_SIZE * 7 / 8);
}

/* Frees an object to the local cache, possibly pushing oldest objects to the
 * shared cache, which itself may decide to release some of them to the OS.
 * While it is unspecified what the object becomes past this point, it is
 * guaranteed to be released from the users' perpective.
 */
void pool_put_to_cache(struct pool_head *pool, void *ptr)
{
	struct pool_cache_item *item = (struct pool_cache_item *)ptr;
	struct pool_cache_head *ph = &pool->cache[tid];

	LIST_INSERT(&ph->list, &item->by_pool);
	LIST_INSERT(&ti->pool_lru_head, &item->by_lru);
	ph->count++;
	pool_cache_count++;
	pool_cache_bytes += pool->size;

	if (unlikely(pool_cache_bytes > CONFIG_HAP_POOL_CACHE_SIZE * 3 / 4)) {
		if (ph->count >= 16 + pool_cache_count / 8)
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
#if defined(HA_HAVE_MALLOC_TRIM)
	malloc_trim(0);
#endif
}

#elif defined(CONFIG_HAP_LOCKLESS_POOLS)

/*
 * This function frees whatever can be freed in pool <pool>.
 */
void pool_flush(struct pool_head *pool)
{
	struct pool_free_list cmp, new;
	void **next, *temp;

	if (!pool)
		return;
	HA_SPIN_LOCK(POOL_LOCK, &pool->lock);
	do {
		cmp.free_list = pool->free_list;
		cmp.seq = pool->seq;
		new.free_list = NULL;
		new.seq = cmp.seq + 1;
	} while (!_HA_ATOMIC_DWCAS(&pool->free_list, &cmp, &new));
	__ha_barrier_atomic_store();
	HA_SPIN_UNLOCK(POOL_LOCK, &pool->lock);
	next = cmp.free_list;
	while (next) {
		temp = next;
		next = *POOL_LINK(pool, temp);
		pool_put_to_os(pool, temp);
	}
	pool->free_list = next;
	/* here, we should have pool->allocate == pool->used */
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
		while ((int)((volatile int)entry->allocated - (volatile int)entry->used) > (int)entry->minavail) {
			struct pool_free_list cmp, new;

			cmp.seq = entry->seq;
			__ha_barrier_load();
			cmp.free_list = entry->free_list;
			__ha_barrier_load();
			if (cmp.free_list == NULL)
				break;
			new.free_list = *POOL_LINK(entry, cmp.free_list);
			new.seq = cmp.seq + 1;
			if (HA_ATOMIC_DWCAS(&entry->free_list, &cmp, &new) == 0)
				continue;
			pool_put_to_os(entry, cmp.free_list);
		}
	}

	if (!isolated)
		thread_release();

#if defined(HA_HAVE_MALLOC_TRIM)
	malloc_trim(0);
#endif
}

#else /* CONFIG_HAP_LOCKLESS_POOLS */

/*
 * This function frees whatever can be freed in pool <pool>.
 */
void pool_flush(struct pool_head *pool)
{
	void *temp;

	if (!pool)
		return;

	while (1) {
		HA_SPIN_LOCK(POOL_LOCK, &pool->lock);
		temp = pool->free_list;
		if (!temp) {
			HA_SPIN_UNLOCK(POOL_LOCK, &pool->lock);
			break;
		}
		pool->free_list = *POOL_LINK(pool, temp);
		HA_SPIN_UNLOCK(POOL_LOCK, &pool->lock);
		pool_put_to_os(pool, temp);
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
		void *temp;
		//qfprintf(stderr, "Flushing pool %s\n", entry->name);
		while (entry->free_list &&
		       (int)(entry->allocated - entry->used) > (int)entry->minavail) {
			temp = entry->free_list;
			entry->free_list = *POOL_LINK(entry, temp);
			pool_put_to_os(entry, temp);
		}
	}

	if (!isolated)
		thread_release();
}
#endif /* CONFIG_HAP_LOCKLESS_POOLS */

#else  /* CONFIG_HAP_POOLS */

/* legacy stuff */
void pool_flush(struct pool_head *pool)
{
}

/* This function might ask the malloc library to trim its buffers. */
void pool_gc(struct pool_head *pool_ctx)
{
#if defined(HA_HAVE_MALLOC_TRIM)
	malloc_trim(0);
#endif
}

#endif /* CONFIG_HAP_POOLS */

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
#ifndef CONFIG_HAP_LOCKLESS_POOLS
			HA_SPIN_DESTROY(&pool->lock);
#endif
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

	allocated = used = nbpools = 0;
	chunk_printf(&trash, "Dumping pools usage. Use SIGQUIT to flush them.\n");
	list_for_each_entry(entry, &pools, list) {
#ifndef CONFIG_HAP_LOCKLESS_POOLS
		HA_SPIN_LOCK(POOL_LOCK, &entry->lock);
#endif
		chunk_appendf(&trash, "  - Pool %s (%u bytes) : %u allocated (%u bytes), %u used, needed_avg %u, %u failures, %u users, @%p%s\n",
			 entry->name, entry->size, entry->allocated,
		         entry->size * entry->allocated, entry->used,
		         swrate_avg(entry->needed_avg, POOL_AVG_SAMPLES), entry->failed,
			 entry->users, entry,
			 (entry->flags & MEM_F_SHARED) ? " [SHARED]" : "");

		allocated += entry->allocated * entry->size;
		used += entry->used * entry->size;
		nbpools++;
#ifndef CONFIG_HAP_LOCKLESS_POOLS
		HA_SPIN_UNLOCK(POOL_LOCK, &entry->lock);
#endif
	}
	chunk_appendf(&trash, "Total: %d pools, %lu bytes allocated, %lu used.\n",
		 nbpools, allocated, used);
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
		LIST_INIT(&ha_thread_info[thr].pool_lru_head);
	}
#endif
}

INITCALL0(STG_PREPARE, init_pools);

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
