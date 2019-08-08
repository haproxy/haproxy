/*
 * include/common/buffer.h
 * Buffer management definitions, macros and inline functions.
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
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

#ifndef _COMMON_BUFFER_H
#define _COMMON_BUFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/buf.h>
#include <common/chunk.h>
#include <common/config.h>
#include <common/ist.h>
#include <common/istbuf.h>
#include <common/memory.h>

#include <proto/activity.h>

/* an element of the <buffer_wq> list. It represents an object that need to
 * acquire a buffer to continue its process. */
struct buffer_wait {
	void *target;              /* The waiting object that should be woken up */
	int (*wakeup_cb)(void *);  /* The function used to wake up the <target>, passed as argument */
	struct list list;          /* Next element in the <buffer_wq> list */
};

extern struct pool_head *pool_head_buffer;
extern struct list buffer_wq;
__decl_hathreads(extern HA_SPINLOCK_T buffer_wq_lock);

int init_buffer();
void buffer_dump(FILE *o, struct buffer *b, int from, int to);

/*****************************************************************/
/* These functions are used to compute various buffer area sizes */
/*****************************************************************/

/* Return 1 if the buffer has less than 1/4 of its capacity free, otherwise 0 */
static inline int buffer_almost_full(const struct buffer *buf)
{
	if (b_is_null(buf))
		return 0;

	return b_almost_full(buf);
}

/**************************************************/
/* Functions below are used for buffer allocation */
/**************************************************/

/* Allocates a buffer and assigns it to *buf. If no memory is available,
 * ((char *)1) is assigned instead with a zero size. No control is made to
 * check if *buf already pointed to another buffer. The allocated buffer is
 * returned, or NULL in case no memory is available.
 */
static inline struct buffer *b_alloc(struct buffer *buf)
{
	char *area;

	*buf = BUF_WANTED;
	area = pool_alloc_dirty(pool_head_buffer);
	if (unlikely(!area)) {
		activity[tid].buf_wait++;
		return NULL;
	}

	buf->area = area;
	buf->size = pool_head_buffer->size;
	return buf;
}

/* Allocates a buffer and assigns it to *buf. If no memory is available,
 * ((char *)1) is assigned instead with a zero size. No control is made to
 * check if *buf already pointed to another buffer. The allocated buffer is
 * returned, or NULL in case no memory is available. The difference with
 * b_alloc() is that this function only picks from the pool and never calls
 * malloc(), so it can fail even if some memory is available.
 */
static inline struct buffer *b_alloc_fast(struct buffer *buf)
{
	char *area;

	*buf = BUF_WANTED;
	area = pool_get_first(pool_head_buffer);
	if (unlikely(!area))
		return NULL;

	buf->area = area;
	buf->size = pool_head_buffer->size;
	return buf;
}

/* Releases buffer <buf> (no check of emptiness). The buffer's head is marked
 * empty.
 */
static inline void __b_free(struct buffer *buf)
{
	char *area = buf->area;

	/* let's first clear the area to save an occasional "show sess all"
	 * glancing over our shoulder from getting a dangling pointer.
	 */
	*buf = BUF_NULL;
	__ha_barrier_store();
	pool_free(pool_head_buffer, area);
}

/* Releases buffer <buf> if allocated, and marks it empty. */
static inline void b_free(struct buffer *buf)
{
	if (buf->size)
		__b_free(buf);
}

/* Ensures that <buf> is allocated. If an allocation is needed, it ensures that
 * there are still at least <margin> buffers available in the pool after this
 * allocation so that we don't leave the pool in a condition where a session or
 * a response buffer could not be allocated anymore, resulting in a deadlock.
 * This means that we sometimes need to try to allocate extra entries even if
 * only one buffer is needed.
 *
 * We need to lock the pool here to be sure to have <margin> buffers available
 * after the allocation, regardless how many threads that doing it in the same
 * time. So, we use internal and lockless memory functions (prefixed with '__').
 */
static inline struct buffer *b_alloc_margin(struct buffer *buf, int margin)
{
	char *area;
	ssize_t idx;
	unsigned int cached;

	if (buf->size)
		return buf;

	cached = 0;
	idx = pool_get_index(pool_head_buffer);
	if (idx >= 0)
		cached = pool_cache[tid][idx].count;

	*buf = BUF_WANTED;

#ifndef CONFIG_HAP_LOCKLESS_POOLS
	HA_SPIN_LOCK(POOL_LOCK, &pool_head_buffer->lock);
#endif

	/* fast path */
	if ((pool_head_buffer->allocated - pool_head_buffer->used + cached) > margin) {
		area = __pool_get_first(pool_head_buffer);
		if (likely(area)) {
#ifndef CONFIG_HAP_LOCKLESS_POOLS
			HA_SPIN_UNLOCK(POOL_LOCK, &pool_head_buffer->lock);
#endif
			goto done;
		}
	}

	/* slow path, uses malloc() */
	area = __pool_refill_alloc(pool_head_buffer, margin);

#ifndef CONFIG_HAP_LOCKLESS_POOLS
	HA_SPIN_UNLOCK(POOL_LOCK, &pool_head_buffer->lock);
#endif

	if (unlikely(!area)) {
		activity[tid].buf_wait++;
		return NULL;
	}

 done:
	buf->area = area;
	buf->size = pool_head_buffer->size;
	return buf;
}


/* Offer a buffer currently belonging to target <from> to whoever needs one.
 * Any pointer is valid for <from>, including NULL. Its purpose is to avoid
 * passing a buffer to oneself in case of failed allocations (e.g. need two
 * buffers, get one, fail, release it and wake up self again). In case of
 * normal buffer release where it is expected that the caller is not waiting
 * for a buffer, NULL is fine.
 */
void __offer_buffer(void *from, unsigned int threshold);

static inline void offer_buffers(void *from, unsigned int threshold)
{
	if (LIST_ISEMPTY(&buffer_wq))
		return;

	HA_SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
	if (!LIST_ISEMPTY(&buffer_wq))
		__offer_buffer(from, threshold);
	HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
}


#endif /* _COMMON_BUFFER_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
