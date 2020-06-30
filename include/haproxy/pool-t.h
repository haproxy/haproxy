/*
 * include/haproxy/pool-t.h
 * Memory pools configuration and type definitions.
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

#ifndef _HAPROXY_POOL_T_H
#define _HAPROXY_POOL_T_H

#include <haproxy/api-t.h>
#include <haproxy/list-t.h>
#include <haproxy/thread-t.h>

/* On architectures supporting threads and double-word CAS, we can implement
 * lock-less memory pools. This isn't supported for debugging modes however.
 */
#if defined(USE_THREAD) && defined(HA_HAVE_CAS_DW) && !defined(DEBUG_NO_LOCKLESS_POOLS) && !defined(DEBUG_UAF) && !defined(DEBUG_FAIL_ALLOC)
#define CONFIG_HAP_LOCKLESS_POOLS
#endif

/* On architectures supporting threads we can amortize the locking cost using
 * local pools.
 */
#if defined(USE_THREAD) && !defined(DEBUG_NO_LOCAL_POOLS) && !defined(DEBUG_UAF) && !defined(DEBUG_FAIL_ALLOC)
#define CONFIG_HAP_LOCAL_POOLS
#endif

/* Pools of very similar size are shared by default, unless macro
 * DEBUG_DONT_SHARE_POOLS is set.
 */
#ifndef DEBUG_DONT_SHARE_POOLS
#define MEM_F_SHARED	0x1
#else
#define MEM_F_SHARED	0
#endif
#define MEM_F_EXACT	0x2

/* By default, free objects are linked by a pointer stored at the beginning of
 * the memory area. When DEBUG_MEMORY_POOLS is set, the allocated area is
 * inflated by the size of a pointer so that the link is placed at the end
 * of the objects. Hence free objects in pools remain intact. In addition,
 * this location is used to keep a pointer to the pool the object was
 * allocated from, and verify it's freed into the appropriate one.
 */
#ifdef DEBUG_MEMORY_POOLS
#define POOL_EXTRA (sizeof(void *))
#define POOL_LINK(pool, item) (void **)(((char *)(item)) + ((pool)->size))
#else
#define POOL_EXTRA (0)
#define POOL_LINK(pool, item) ((void **)(item))
#endif

#ifndef MAX_BASE_POOLS
#define MAX_BASE_POOLS 64
#endif

#define POOL_AVG_SAMPLES 1024


struct pool_cache_head {
	struct list list;    /* head of objects in this pool */
	size_t size;         /* size of an object */
	unsigned int count;  /* number of objects in this pool */
};

struct pool_cache_item {
	struct list by_pool; /* link to objects in this pool */
	struct list by_lru;  /* link to objects by LRU order */
};

struct pool_free_list {
	void **free_list;
	uintptr_t seq;
};

/* Note below, in case of lockless pools, we still need the lock only for
 * the flush() operation.
 */
struct pool_head {
	void **free_list;
#ifdef CONFIG_HAP_LOCKLESS_POOLS
	uintptr_t seq;
#endif
	__decl_thread(HA_SPINLOCK_T lock); /* the spin lock */
	unsigned int used;	/* how many chunks are currently in use */
	unsigned int needed_avg;/* floating indicator between used and allocated */
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

#endif /* _HAPROXY_POOL_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
