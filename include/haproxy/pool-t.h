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

#define MEM_F_SHARED	0x1
#define MEM_F_EXACT	0x2

/* A special pointer for the pool's free_list that indicates someone is
 * currently manipulating it. Serves as a short-lived lock.
 */
#define POOL_BUSY ((void *)1)

#define POOL_AVG_SAMPLES 1024

/* possible flags for __pool_alloc() */
#define POOL_F_NO_POISON    0x00000001  // do not poison the area
#define POOL_F_MUST_ZERO    0x00000002  // zero the returned area
#define POOL_F_NO_FAIL      0x00000004  // do not randomly fail


/* This is the head of a thread-local cache */
struct pool_cache_head {
	struct list list;    /* head of objects in this pool */
	unsigned int count;  /* number of objects in this pool */
#if defined(DEBUG_POOL_INTEGRITY)
	ulong fill_pattern;  /* pattern used to fill the area on free */
#endif
} THREAD_ALIGNED(64);

/* This represents one item stored in the thread-local cache. <by_pool> links
 * the object to the list of objects in the pool, and <by_lru> links the object
 * to the local thread's list of hottest objects. This way it's possible to
 * allocate a fresh object from the cache, or to release cold objects from any
 * pool (no bookkeeping is needed since shared pools do not know how many
 * objects they store).
 */
struct pool_cache_item {
	struct list by_pool; /* link to objects in this pool */
	struct list by_lru;  /* link to objects by LRU order */
};

/* This structure is used to represent an element in the pool's shared
 * free_list. An item may carry a series of other items allocated or released
 * as a same cluster. The storage then looks like this:
 *     +------+   +------+   +------+
 *  -->| next |-->| next |-->| NULL |
 *     +------+   +------+   +------+
 *     | NULL |   | down |   | down |
 *     +------+   +--|---+   +--|---+
 *                   V	        V
 *                +------+   +------+
 *                | NULL |   | NULL |
 *                +------+   +------+
 *                | down |   | NULL |
 *                +--|---+   +------+
 *                   V
 *                +------+
 *                | NULL |
 *                +------+
 *                | NULL |
 *                +------+
 */
struct pool_item {
	struct pool_item *next;
	struct pool_item *down; // link to other items of the same cluster
};

/* This describes a complete pool, with its status, usage statistics and the
 * thread-local caches if any. Even if pools are disabled, these descriptors
 * are valid and are used at least to get names and sizes. For small builds
 * using neither threads nor pools, this structure might be reduced, and
 * alignment could be removed.
 */
struct pool_head {
	struct pool_item *free_list; /* list of free shared objects */
	unsigned int used;	/* how many chunks are currently in use */
	unsigned int needed_avg;/* floating indicator between used and allocated */
	unsigned int allocated;	/* how many chunks have been allocated */
	unsigned int limit;	/* hard limit on the number of chunks */
	unsigned int minavail;	/* how many chunks are expected to be used */
	unsigned int size;	/* chunk size */
	unsigned int flags;	/* MEM_F_* */
	unsigned int users;	/* number of pools sharing this zone */
	unsigned int failed;	/* failed allocations */
	/* 32-bit hole here */
	struct list list;	/* list of all known pools */
	char name[12];		/* name of the pool */
#ifdef CONFIG_HAP_POOLS
	struct pool_cache_head cache[MAX_THREADS]; /* pool caches */
#endif
} __attribute__((aligned(64)));

#endif /* _HAPROXY_POOL_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
