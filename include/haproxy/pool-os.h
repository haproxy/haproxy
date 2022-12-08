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

#include <sys/mman.h>
#include <stdlib.h>
#include <haproxy/api.h>


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

/************* use-after-free allocator *************/

/* allocates an area of size <size> and returns it. The semantics are similar
 * to those of malloc(). However the allocation is rounded up to 4kB so that a
 * full page is allocated. This ensures the object can be freed alone so that
 * future dereferences are easily detected. The returned object is always
 * 16-bytes aligned to avoid issues with unaligned structure objects. In case
 * some padding is added, the area's start address is copied at the end of the
 * padding to help detect underflows.
 */
static inline void *pool_alloc_area_uaf(size_t size)
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

/* frees an area <area> of size <size> allocated by pool_alloc_area_uaf(). The
 * semantics are identical to free() except that the size must absolutely match
 * the one passed to pool_alloc_area_uaf(). In case some padding is added, the
 * area's start address is compared to the one at the end of the padding, and
 * a segfault is triggered if they don't match, indicating an underflow.
 */
static inline void pool_free_area_uaf(void *area, size_t size)
{
	size_t pad = (4096 - size) & 0xFF0;

	/* This object will be released for real in order to detect a use after
	 * free. We also force a write to the area to ensure we crash on double
	 * free or free of a const area.
	 */
	*(uint32_t *)area = 0xDEADADD4;

	if (pad >= sizeof(void *) && *(void **)(area - sizeof(void *)) != area)
		ABORT_NOW();

	munmap(area - pad, (size + 4095) & -4096);
}

#endif /* _HAPROXY_POOL_OS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
