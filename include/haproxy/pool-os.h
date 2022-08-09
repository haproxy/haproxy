/*
 * include/haproxy/pool-os.h
 * OS-level interface for memory management
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

#ifndef _HAPROXY_POOL_OS_H
#define _HAPROXY_POOL_OS_H

#include <stdlib.h>
#include <haproxy/api.h>


#ifndef DEBUG_UAF

/************* normal allocator *************/

/* allocates an area of size <size> and returns it. The semantics are similar
 * to those of malloc().
 */
static forceinline void *pool_alloc_area(size_t size)
{
	return malloc(size);
}

/* frees an area <area> of size <size> allocated by pool_alloc_area(). The
 * semantics are identical to free() except that the size is specified and
 * may be ignored.
 */
static forceinline void pool_free_area(void *area, size_t __maybe_unused size)
{
	will_free(area, size);
	free(area);
}

#else

/************* use-after-free allocator *************/

void *pool_alloc_area_uaf(size_t size);
void pool_free_area_uaf(void *area, size_t size);


/* allocates an area of size <size> and returns it. The semantics are similar
 * to those of malloc().
 */
static forceinline void *pool_alloc_area(size_t size)
{
	return pool_alloc_area_uaf(size);
}

/* frees an area <area> of size <size> allocated by pool_alloc_area(). The
 * semantics are identical to free() except that the size is specified and
 * may be ignored.
 */
static forceinline void pool_free_area(void *area, size_t size)
{
	pool_free_area_uaf(area, size);
}

#endif /* DEBUG_UAF */

#endif /* _HAPROXY_POOL_OS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
