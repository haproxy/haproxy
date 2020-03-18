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

#include <types/applet.h>
#include <types/cli.h>
#include <types/global.h>
#include <types/stats.h>

#include <common/cfgparse.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/hathreads.h>
#include <common/initcall.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>

#include <types/activity.h>

#include <proto/applet.h>
#include <proto/cli.h>
#include <proto/channel.h>
#include <proto/log.h>
#include <proto/stream_interface.h>
#include <proto/stats.h>

/* These are the most common pools, expected to be initialized first. These
 * ones are allocated from an array, allowing to map them to an index.
 */
struct pool_head pool_base_start[MAX_BASE_POOLS] = { };
unsigned int pool_base_count = 0;

/* These ones are initialized per-thread on startup by init_pools() */
struct pool_cache_head pool_cache[MAX_THREADS][MAX_BASE_POOLS];
static struct list pool_lru_head[MAX_THREADS];           /* oldest objects   */
THREAD_LOCAL size_t pool_cache_bytes = 0;                /* total cache size */
THREAD_LOCAL size_t pool_cache_count = 0;                /* #cache objects   */

static struct list pools = LIST_HEAD_INIT(pools);
int mem_poison_byte = -1;

#ifdef DEBUG_FAIL_ALLOC
static int mem_fail_rate = 0;
static int mem_should_fail(const struct pool_head *);
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
	int thr, idx;

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
		if (pool_base_count < MAX_BASE_POOLS)
			pool = &pool_base_start[pool_base_count++];

		if (!pool) {
			/* look for a freed entry */
			for (entry = pool_base_start; entry != pool_base_start + MAX_BASE_POOLS; entry++) {
				if (!entry->size) {
					pool = entry;
					break;
				}
			}
		}

		if (!pool)
			pool = calloc(1, sizeof(*pool));

		if (!pool)
			return NULL;
		if (name)
			strlcpy2(pool->name, name, sizeof(pool->name));
		pool->size = size;
		pool->flags = flags;
		LIST_ADDQ(start, &pool->list);

		/* update per-thread pool cache if necessary */
		idx = pool_get_index(pool);
		if (idx >= 0) {
			for (thr = 0; thr < MAX_THREADS; thr++)
				pool_cache[thr][idx].size = size;
		}
#ifndef CONFIG_HAP_LOCKLESS_POOLS
		HA_SPIN_INIT(&pool->lock);
#else
		HA_SPIN_INIT(&pool->flush_lock);
#endif
	}
	pool->users++;
	return pool;
}

#ifdef CONFIG_HAP_LOCKLESS_POOLS
/* Allocates new entries for pool <pool> until there are at least <avail> + 1
 * available, then returns the last one for immediate use, so that at least
 * <avail> are left available in the pool upon return. NULL is returned if the
 * last entry could not be allocated. It's important to note that at least one
 * allocation is always performed even if there are enough entries in the pool.
 * A call to the garbage collector is performed at most once in case malloc()
 * returns an error, before returning NULL.
 */
void *__pool_refill_alloc(struct pool_head *pool, unsigned int avail)
{
	void *ptr = NULL, **free_list;
	int failed = 0;
	int size = pool->size;
	int limit = pool->limit;
	int allocated = pool->allocated, allocated_orig = allocated;

	/* stop point */
	avail += pool->used;

	while (1) {
		if (limit && allocated >= limit) {
			_HA_ATOMIC_ADD(&pool->allocated, allocated - allocated_orig);
			activity[tid].pool_fail++;
			return NULL;
		}

		ptr = malloc(size + POOL_EXTRA);
		if (!ptr) {
			_HA_ATOMIC_ADD(&pool->failed, 1);
			if (failed) {
				activity[tid].pool_fail++;
				return NULL;
			}
			failed++;
			pool_gc(pool);
			continue;
		}
		if (++allocated > avail)
			break;

		free_list = pool->free_list;
		do {
			*POOL_LINK(pool, ptr) = free_list;
			__ha_barrier_store();
		} while (_HA_ATOMIC_CAS(&pool->free_list, &free_list, ptr) == 0);
	}
	__ha_barrier_atomic_store();

	_HA_ATOMIC_ADD(&pool->allocated, allocated - allocated_orig);
	_HA_ATOMIC_ADD(&pool->used, 1);

#ifdef DEBUG_MEMORY_POOLS
	/* keep track of where the element was allocated from */
	*POOL_LINK(pool, ptr) = (void *)pool;
#endif
	return ptr;
}
void *pool_refill_alloc(struct pool_head *pool, unsigned int avail)
{
	void *ptr;

	ptr = __pool_refill_alloc(pool, avail);
	return ptr;
}
/*
 * This function frees whatever can be freed in pool <pool>.
 */
void pool_flush(struct pool_head *pool)
{
	struct pool_free_list cmp, new;
	void **next, *temp;
	int removed = 0;

	if (!pool)
		return;
	HA_SPIN_LOCK(POOL_LOCK, &pool->flush_lock);
	do {
		cmp.free_list = pool->free_list;
		cmp.seq = pool->seq;
		new.free_list = NULL;
		new.seq = cmp.seq + 1;
	} while (!_HA_ATOMIC_DWCAS(&pool->free_list, &cmp, &new));
	__ha_barrier_atomic_store();
	HA_SPIN_UNLOCK(POOL_LOCK, &pool->flush_lock);
	next = cmp.free_list;
	while (next) {
		temp = next;
		next = *POOL_LINK(pool, temp);
		removed++;
		free(temp);
	}
	pool->free_list = next;
	_HA_ATOMIC_SUB(&pool->allocated, removed);
	/* here, we should have pool->allocate == pool->used */
}

/*
 * This function frees whatever can be freed in all pools, but respecting
 * the minimum thresholds imposed by owners. It takes care of avoiding
 * recursion because it may be called from a signal handler.
 *
 * <pool_ctx> is unused
 */
void pool_gc(struct pool_head *pool_ctx)
{
	static int recurse;
	int cur_recurse = 0;
	struct pool_head *entry;

	if (recurse || !_HA_ATOMIC_CAS(&recurse, &cur_recurse, 1))
		return;

	list_for_each_entry(entry, &pools, list) {
		HA_SPIN_LOCK(POOL_LOCK, &entry->flush_lock);
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
			free(cmp.free_list);
			_HA_ATOMIC_SUB(&entry->allocated, 1);
		}
		HA_SPIN_UNLOCK(POOL_LOCK, &entry->flush_lock);
	}

	_HA_ATOMIC_STORE(&recurse, 0);
}

/* frees an object to the local cache, possibly pushing oldest objects to the
 * global pool. Must not be called directly.
 */
void __pool_put_to_cache(struct pool_head *pool, void *ptr, ssize_t idx)
{
	struct pool_cache_item *item = (struct pool_cache_item *)ptr;
	struct pool_cache_head *ph = &pool_cache[tid][idx];

	LIST_ADD(&ph->list, &item->by_pool);
	LIST_ADD(&pool_lru_head[tid], &item->by_lru);
	ph->count++;
	pool_cache_count++;
	pool_cache_bytes += ph->size;

	if (pool_cache_bytes <= CONFIG_HAP_POOL_CACHE_SIZE)
		return;

	do {
		item = LIST_PREV(&pool_lru_head[tid], struct pool_cache_item *, by_lru);
		/* note: by definition we remove oldest objects so they also are the
		 * oldest in their own pools, thus their next is the pool's head.
		 */
		ph = LIST_NEXT(&item->by_pool, struct pool_cache_head *, list);
		LIST_DEL(&item->by_pool);
		LIST_DEL(&item->by_lru);
		ph->count--;
		pool_cache_count--;
		pool_cache_bytes -= ph->size;
		__pool_free(pool_base_start + (ph - pool_cache[tid]), item);
	} while (pool_cache_bytes > CONFIG_HAP_POOL_CACHE_SIZE * 7 / 8);
}

#else /* CONFIG_HAP_LOCKLESS_POOLS */

/* Allocates new entries for pool <pool> until there are at least <avail> + 1
 * available, then returns the last one for immediate use, so that at least
 * <avail> are left available in the pool upon return. NULL is returned if the
 * last entry could not be allocated. It's important to note that at least one
 * allocation is always performed even if there are enough entries in the pool.
 * A call to the garbage collector is performed at most once in case malloc()
 * returns an error, before returning NULL.
 */
void *__pool_refill_alloc(struct pool_head *pool, unsigned int avail)
{
	void *ptr = NULL;
	int failed = 0;

#ifdef DEBUG_FAIL_ALLOC
	if (mem_should_fail(pool))
		return NULL;
#endif
	/* stop point */
	avail += pool->used;

	while (1) {
		if (pool->limit && pool->allocated >= pool->limit) {
			activity[tid].pool_fail++;
			return NULL;
		}

		HA_SPIN_UNLOCK(POOL_LOCK, &pool->lock);
		ptr = pool_alloc_area(pool->size + POOL_EXTRA);
#ifdef DEBUG_MEMORY_POOLS
		/* keep track of where the element was allocated from. This
		 * is done out of the lock so that the system really allocates
		 * the data without harming other threads waiting on the lock.
		 */
		if (ptr)
			*POOL_LINK(pool, ptr) = (void *)pool;
#endif
		HA_SPIN_LOCK(POOL_LOCK, &pool->lock);
		if (!ptr) {
			pool->failed++;
			if (failed) {
				activity[tid].pool_fail++;
				return NULL;
			}
			failed++;
			pool_gc(pool);
			continue;
		}
		if (++pool->allocated > avail)
			break;

		*POOL_LINK(pool, ptr) = (void *)pool->free_list;
		pool->free_list = ptr;
	}
	pool->used++;
	return ptr;
}
void *pool_refill_alloc(struct pool_head *pool, unsigned int avail)
{
	void *ptr;

	HA_SPIN_LOCK(POOL_LOCK, &pool->lock);
	ptr = __pool_refill_alloc(pool, avail);
	HA_SPIN_UNLOCK(POOL_LOCK, &pool->lock);
	return ptr;
}
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
		pool->allocated--;
		HA_SPIN_UNLOCK(POOL_LOCK, &pool->lock);
		pool_free_area(temp, pool->size + POOL_EXTRA);
	}
	/* here, we should have pool->allocated == pool->used */
}

/*
 * This function frees whatever can be freed in all pools, but respecting
 * the minimum thresholds imposed by owners. It takes care of avoiding
 * recursion because it may be called from a signal handler.
 *
 * <pool_ctx> is used when pool_gc is called to release resources to allocate
 * an element in __pool_refill_alloc. It is important because <pool_ctx> is
 * already locked, so we need to skip the lock here.
 */
void pool_gc(struct pool_head *pool_ctx)
{
	static int recurse;
	int cur_recurse = 0;
	struct pool_head *entry;

	if (recurse || !_HA_ATOMIC_CAS(&recurse, &cur_recurse, 1))
		return;

	list_for_each_entry(entry, &pools, list) {
		void *temp;
		//qfprintf(stderr, "Flushing pool %s\n", entry->name);
		if (entry != pool_ctx)
			HA_SPIN_LOCK(POOL_LOCK, &entry->lock);
		while (entry->free_list &&
		       (int)(entry->allocated - entry->used) > (int)entry->minavail) {
			temp = entry->free_list;
			entry->free_list = *POOL_LINK(entry, temp);
			entry->allocated--;
			if (entry != pool_ctx)
				HA_SPIN_UNLOCK(POOL_LOCK, &entry->lock);
			pool_free_area(temp, entry->size + POOL_EXTRA);
			if (entry != pool_ctx)
				HA_SPIN_LOCK(POOL_LOCK, &entry->lock);
		}
		if (entry != pool_ctx)
			HA_SPIN_UNLOCK(POOL_LOCK, &entry->lock);
	}

	_HA_ATOMIC_STORE(&recurse, 0);
}
#endif

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
			LIST_DEL(&pool->list);
#ifndef CONFIG_HAP_LOCKLESS_POOLS
			HA_SPIN_DESTROY(&pool->lock);
#endif
			if ((pool - pool_base_start) < MAX_BASE_POOLS)
				memset(pool, 0, sizeof(*pool));
			else
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
		chunk_appendf(&trash, "  - Pool %s (%d bytes) : %d allocated (%u bytes), %d used, %d failures, %d users, @%p=%02d%s\n",
			 entry->name, entry->size, entry->allocated,
		         entry->size * entry->allocated, entry->used, entry->failed,
			 entry->users, entry, (int)pool_get_index(entry),
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
	int thr, idx;

	for (thr = 0; thr < MAX_THREADS; thr++) {
		for (idx = 0; idx < MAX_BASE_POOLS; idx++) {
			LIST_INIT(&pool_cache[thr][idx].list);
			pool_cache[thr][idx].size = 0;
		}
		LIST_INIT(&pool_lru_head[thr]);
	}
}

INITCALL0(STG_PREPARE, init_pools);

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "pools",  NULL }, "show pools     : report information about the memory pools usage", NULL, cli_io_handler_dump_pools },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

#ifdef DEBUG_FAIL_ALLOC
#define MEM_FAIL_MAX_CHAR 32
#define MEM_FAIL_MAX_STR 128
static int mem_fail_cur_idx;
static char mem_fail_str[MEM_FAIL_MAX_CHAR * MEM_FAIL_MAX_STR];
__decl_hathreads(static HA_SPINLOCK_T mem_fail_lock);

int mem_should_fail(const struct pool_head *pool)
{
	int ret = 0;
	int n;

	if (mem_fail_rate > 0 && !(global.mode & MODE_STARTING)) {
		int randnb = ha_random() % 100;

		if (mem_fail_rate > randnb)
			ret = 1;
		else
			ret = 0;
	}
	HA_SPIN_LOCK(POOL_LOCK, &mem_fail_lock);
	n = snprintf(&mem_fail_str[mem_fail_cur_idx * MEM_FAIL_MAX_CHAR],
	    MEM_FAIL_MAX_CHAR - 2,
	    "%d %.18s %d %d", mem_fail_cur_idx, pool->name, ret, tid);
	while (n < MEM_FAIL_MAX_CHAR - 1)
		mem_fail_str[mem_fail_cur_idx * MEM_FAIL_MAX_CHAR + n++] = ' ';
	if (mem_fail_cur_idx < MEM_FAIL_MAX_STR - 1)
		mem_fail_str[mem_fail_cur_idx * MEM_FAIL_MAX_CHAR + n] = '\n';
	else
		mem_fail_str[mem_fail_cur_idx * MEM_FAIL_MAX_CHAR + n] = 0;
	mem_fail_cur_idx++;
	if (mem_fail_cur_idx == MEM_FAIL_MAX_STR)
		mem_fail_cur_idx = 0;
	HA_SPIN_UNLOCK(POOL_LOCK, &mem_fail_lock);
	return ret;

}

/* config parser for global "tune.fail-alloc" */
static int mem_parse_global_fail_alloc(char **args, int section_type, struct proxy *curpx,
                                      struct proxy *defpx, const char *file, int line,
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
