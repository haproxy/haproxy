/*
 * include/haproxy/dynbuf.h
 * Buffer management functions.
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

#ifndef _HAPROXY_DYNBUF_H
#define _HAPROXY_DYNBUF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <import/ist.h>
#include <haproxy/activity.h>
#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/dynbuf-t.h>
#include <haproxy/global.h>
#include <haproxy/pool.h>

extern struct pool_head *pool_head_buffer;

int init_buffer(void);
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

/* returns non-zero if one may try to allocate a buffer for criticality flags
 * <crit> (made of a criticality and optional flags).
 */
static inline int b_may_alloc_for_crit(uint crit)
{
	int q = DB_CRIT_TO_QUEUE(crit & DB_F_CRIT_MASK);

	/* if this queue or any more critical ones have entries, we must wait */
	if (!(crit & DB_F_NOQUEUE) && th_ctx->bufq_map & ((2 << q) - 1))
		return 0;

	/* If the emergency buffers are too low, we won't try to allocate a
	 * buffer either so that we speed up their release. As a corrolary, it
	 * means that we're always allowed to try to fall back to an emergency
	 * buffer if pool_alloc() fails. The minimum number of available
	 * emergency buffers for an allocation depends on the queue:
	 *  q == 0 -> 0%
	 *  q == 1 -> 33%
	 *  q == 2 -> 66%
	 *  q == 3 -> 100%
	 */
	if (th_ctx->emergency_bufs_left * 3 < q * global.tune.reserved_bufs)
		return 0;
	return 1;
}

/* Allocates one of the emergency buffers or returns NULL if there are none left */
static inline char *__b_get_emergency_buf(void)
{
	char *ret;

	if (!th_ctx->emergency_bufs_left)
		return NULL;

	th_ctx->emergency_bufs_left--;
	ret = th_ctx->emergency_bufs[th_ctx->emergency_bufs_left];
	th_ctx->emergency_bufs[th_ctx->emergency_bufs_left] = NULL;
	return ret;
}

/* Ensures that <buf> is allocated, or allocates it. If no memory is available,
 * ((char *)1) is assigned instead with a zero size. The allocated buffer is
 * returned, or NULL in case no memory is available. Since buffers only contain
 * user data, poisonning is always disabled as it brings no benefit and impacts
 * performance. Due to the difficult buffer_wait management, they are not
 * subject to forced allocation failures either. If other waiters are present
 * at higher criticality levels, we refrain from allocating.
 */
#define b_alloc(_buf, _crit)						\
({									\
	char *_area = NULL;						\
	struct buffer *_retbuf = _buf;					\
	uint _criticality = _crit;					\
									\
	if (!_retbuf->size) {						\
		*_retbuf = BUF_WANTED;					\
		if (b_may_alloc_for_crit(_criticality)) {		\
			_area = pool_alloc_flag(pool_head_buffer, POOL_F_NO_POISON | POOL_F_NO_FAIL); \
			if (unlikely(!_area))				\
				_area = __b_get_emergency_buf();	\
		}							\
		if (unlikely(!_area)) {					\
			activity[tid].buf_wait++;			\
			_retbuf = NULL;					\
		}							\
		else {							\
			_retbuf->area = _area;				\
			_retbuf->size = pool_head_buffer->size;		\
		}							\
	}								\
	_retbuf;							\
 })

/* Releases buffer <buf> (no check of emptiness). The buffer's head is marked
 * empty.
 */
#define __b_free(_buf)							\
	do {								\
		char *area = (_buf)->area;				\
									\
		/* let's first clear the area to save an occasional "show sess all" \
		 * glancing over our shoulder from getting a dangling pointer.      \
		 */							            \
		*(_buf) = BUF_NULL;					\
		__ha_barrier_store();					\
		if (th_ctx->emergency_bufs_left < global.tune.reserved_bufs) \
			th_ctx->emergency_bufs[th_ctx->emergency_bufs_left++] = area; \
		else							\
			pool_free(pool_head_buffer, area);		\
	} while (0)							\

/* Releases buffer <buf> if allocated, and marks it empty. */
#define b_free(_buf)				\
	do {					\
		if ((_buf)->size)		\
			__b_free((_buf));	\
	} while (0)

/* Offer one or multiple buffer currently belonging to target <from> to whoever
 * needs one. Any pointer is valid for <from>, including NULL. Its purpose is
 * to avoid passing a buffer to oneself in case of failed allocations (e.g.
 * need two buffers, get one, fail, release it and wake up self again). In case
 * of normal buffer release where it is expected that the caller is not waiting
 * for a buffer, NULL is fine. It will wake waiters on the current thread only.
 */
void __offer_buffers(void *from, unsigned int count);

static inline void offer_buffers(void *from, unsigned int count)
{
	int q;

	if (likely(!th_ctx->bufq_map))
		return;

	for (q = 0; q < DYNBUF_NBQ; q++) {
		if (!(th_ctx->bufq_map & (1 << q)))
			continue;

		BUG_ON_HOT(LIST_ISEMPTY(&th_ctx->buffer_wq[q]));
		__offer_buffers(from, count);
		break;
	}
}

/* Queues a buffer request for the current thread via <bw>, and returns
 * non-zero if the criticality allows to queue a request, otherwise returns
 * zero. If the <bw> was already queued, non-zero is returned so that the call
 * is idempotent. It is assumed that the buffer_wait struct had already been
 * preset with its context and callback, otherwise please use b_queue()
 * instead.
 */
static inline int b_requeue(enum dynbuf_crit crit, struct buffer_wait *bw)
{
	int q = DB_CRIT_TO_QUEUE(crit);

	if (LIST_INLIST(&bw->list))
		return 1;

	/* these ones are never queued */
	if (crit < DB_MUX_RX)
		return 0;

	th_ctx->bufq_map |= 1 << q;
	LIST_APPEND(&th_ctx->buffer_wq[q], &bw->list);
	return 1;
}

/* Queues a buffer request for the current thread via <bw> with the given <ctx>
 * and <cb>, and returns non-zero if the criticality allows to queue a request,
 * otherwise returns zero. If the <bw> was already queued, non-zero is returned
 * so that the call is idempotent.  If the buffer_wait struct had already been
 * preset with the ctx and cb, please use the lighter b_requeue() instead.
 */
static inline int b_queue(enum dynbuf_crit crit, struct buffer_wait *bw, void *ctx, int (*cb)(void *))
{
	bw->target    = ctx;
	bw->wakeup_cb = cb;
	return b_requeue(crit, bw);
}

/* Dequeues bw element <bw> from its list at for thread <thr> and updates the
 * thread's bufq_map if it was the last element. The element is assumed to be
 * in a list (it's the caller's job to test it). This is only meant to really
 * be used either by the owner thread or under thread isolation. You should
 * use b_dequeue() instead.
 */
static inline void _b_dequeue(struct buffer_wait *bw, int thr)
{
	struct thread_ctx *ctx = &ha_thread_ctx[thr];
	uint q;

	/* trick: detect if we're the last one and pointing to a root, so we
	 * can figure the queue number since the root belongs to an array.
	 */
	if (LIST_ATMOST1(&bw->list)) {
		/* OK then which root? */
		q = bw->list.n - &ctx->buffer_wq[0];
		BUG_ON_HOT(q >= DYNBUF_NBQ);
		ctx->bufq_map &= ~(1 << q);
	}
	LIST_DEL_INIT(&bw->list);
}

/* Dequeues bw element <bw> from its list and updates the bufq_map if if was
 * the last element. All users of buffer_wait should use this to dequeue (e.g.
 * when killing a pending request on timeout) so as to make sure that we keep
 * consistency between the list heads and the bitmap.
 */
static inline void b_dequeue(struct buffer_wait *bw)
{
	if (unlikely(LIST_INLIST(&bw->list)))
		_b_dequeue(bw, tid);
}

#endif /* _HAPROXY_DYNBUF_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
