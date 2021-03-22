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
#include <haproxy/pool.h>

extern struct pool_head *pool_head_buffer;

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

/* Ensures that <buf> is allocated, or allocates it. If no memory is available,
 * ((char *)1) is assigned instead with a zero size. The allocated buffer is
 * returned, or NULL in case no memory is available.
 */
static inline struct buffer *b_alloc(struct buffer *buf)
{
	char *area;

	if (buf->size)
		return buf;

	*buf = BUF_WANTED;
	area = __pool_alloc(pool_head_buffer, POOL_F_NO_POISON);
	if (unlikely(!area)) {
		activity[tid].buf_wait++;
		return NULL;
	}

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
	if (!LIST_ISEMPTY(&ti->buffer_wq))
		__offer_buffers(from, count);
}


#endif /* _HAPROXY_DYNBUF_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
