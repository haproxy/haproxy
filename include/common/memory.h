/*
  include/common/memory.h
  Memory management definitions..

  Copyright (C) 2000-2008 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _COMMON_MEMORY_H
#define _COMMON_MEMORY_H

#include <stdlib.h>

#include <common/config.h>
#include <common/mini-clist.h>

/*
 * Returns a pointer to an area of <__len> bytes taken from the pool <pool> or
 * dynamically allocated. In the first case, <__pool> is updated to point to
 * the next element in the list.
 */
#define pool_alloc_from(__pool, __len)                      \
({                                                          \
        void *__p;                                          \
        if ((__p = (__pool)) == NULL)                       \
                __p = malloc(((__len) >= sizeof (void *)) ? \
                      (__len) : sizeof(void *));            \
        else {                                              \
                (__pool) = *(void **)(__pool);		    \
        }                                                   \
        __p;                                                \
})

/*
 * Puts a memory area back to the corresponding pool.
 * Items are chained directly through a pointer that
 * is written in the beginning of the memory area, so
 * there's no need for any carrier cell. This implies
 * that each memory area is at least as big as one
 * pointer.
 */
#define pool_free_to(__pool, __ptr)             \
({                                              \
        *(void **)(__ptr) = (void *)(__pool);   \
        __pool = (void *)(__ptr);               \
})


#ifdef  CONFIG_HAP_MEM_OPTIM
/*
 * Returns a pointer to type <type> taken from the
 * pool <pool_type> or dynamically allocated. In the
 * first case, <pool_type> is updated to point to the
 * next element in the list.
 */
#define pool_alloc(type)                                \
({                                                      \
        void *__p;                                      \
        if ((__p = pool_##type) == NULL)                \
                __p = malloc(sizeof_##type);            \
        else {                                          \
                pool_##type = *(void **)pool_##type;	\
        }                                               \
        __p;                                            \
})

/*
 * Puts a memory area back to the corresponding pool.
 * Items are chained directly through a pointer that
 * is written in the beginning of the memory area, so
 * there's no need for any carrier cell. This implies
 * that each memory area is at least as big as one
 * pointer.
 */
#define pool_free(type, ptr)                            \
({                                                      \
        *(void **)(ptr) = (void *)pool_##type;		\
        pool_##type = (void *)(ptr);			\
})

#else
#define pool_alloc(type) (calloc(1,sizeof_##type))
#define pool_free(type, ptr) (free(ptr))
#endif	/* CONFIG_HAP_MEM_OPTIM */

/*
 * This function destroys a pull by freeing it completely.
 * This should be called only under extreme circumstances.
 */
static inline void pool_destroy(void **pool)
{
	void *temp, *next;
	next = pool;
	while (next) {
		temp = next;
		next = *(void **)temp;
		free(temp);
	}
}


/******* pools version 2 ********/

#define MEM_F_SHARED	0x1

struct pool_head {
	void **free_list;
	struct list list;	/* list of all known pools */
	unsigned int used;	/* how many chunks are currently in use */
	unsigned int allocated;	/* how many chunks have been allocated */
	unsigned int limit;	/* hard limit on the number of chunks */
	unsigned int minavail;	/* how many chunks are expected to be used */
	unsigned int size;	/* chunk size */
	unsigned int flags;	/* MEM_F_* */
	unsigned int users;	/* number of pools sharing this zone */
	char name[12];		/* name of the pool */
};

/* poison each newly allocated area with this byte if not null */
extern char mem_poison_byte;

/* Allocate a new entry for pool <pool>, and return it for immediate use.
 * NULL is returned if no memory is available for a new creation.
 */
void *pool_refill_alloc(struct pool_head *pool);

/* Try to find an existing shared pool with the same characteristics and
 * returns it, otherwise creates this one. NULL is returned if no memory
 * is available for a new creation.
 */
struct pool_head *create_pool(char *name, unsigned int size, unsigned int flags);

/* Dump statistics on pools usage.
 */
void dump_pools_to_trash();
void dump_pools(void);

/*
 * This function frees whatever can be freed in pool <pool>.
 */
void pool_flush2(struct pool_head *pool);

/*
 * This function frees whatever can be freed in all pools, but respecting
 * the minimum thresholds imposed by owners.
 */
void pool_gc2();

/*
 * This function destroys a pull by freeing it completely.
 * This should be called only under extreme circumstances.
 */
void *pool_destroy2(struct pool_head *pool);

/*
 * Returns a pointer to type <type> taken from the
 * pool <pool_type> or dynamically allocated. In the
 * first case, <pool_type> is updated to point to the
 * next element in the list.
 */
#define pool_alloc2(pool)                                       \
({                                                              \
        void *__p;                                              \
        if ((__p = (pool)->free_list) == NULL)			\
                __p = pool_refill_alloc(pool);                  \
        else {                                                  \
                (pool)->free_list = *(void **)(pool)->free_list;\
		(pool)->used++;					\
        }                                                       \
        __p;                                                    \
})

/*
 * Puts a memory area back to the corresponding pool.
 * Items are chained directly through a pointer that
 * is written in the beginning of the memory area, so
 * there's no need for any carrier cell. This implies
 * that each memory area is at least as big as one
 * pointer. Just like with the libc's free(), nothing
 * is done if <ptr> is NULL.
 */
#define pool_free2(pool, ptr)                           \
({                                                      \
        if (likely((ptr) != NULL)) {                    \
                *(void **)(ptr) = (void *)(pool)->free_list;	\
                (pool)->free_list = (void *)(ptr);	\
                (pool)->used--;				\
        }                                               \
})


#endif /* _COMMON_MEMORY_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
