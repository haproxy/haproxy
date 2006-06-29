/*
  include/common/memory.h
  Memory management definitions..

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
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

#define sizeof_requri   REQURI_LEN
#define sizeof_capture  CAPTURE_LEN
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
                __pool = *(void **)(__pool);                \
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
        *(void **)ptr = (void *)pool_##type;            \
        pool_##type = (void *)ptr;                      \
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

#endif /* _COMMON_MEMORY_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
