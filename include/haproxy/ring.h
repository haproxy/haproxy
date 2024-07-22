/*
 * include/haproxy/ring.h
 * Exported functions for ring buffers used for disposable data.
 *
 * Copyright (C) 2000-2019 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_RING_H
#define _HAPROXY_RING_H

#include <stdlib.h>
#include <import/ist.h>
#include <haproxy/ring-t.h>
#include <haproxy/vecpair.h>

struct appctx;

struct ring *ring_new(size_t size);
struct ring *ring_make_from_area(void *area, size_t size, int reset);
void ring_init(struct ring *ring, void *area, size_t size, int reset);
struct ring *ring_resize(struct ring *ring, size_t size);
void ring_free(struct ring *ring);
ssize_t ring_write(struct ring *ring, size_t maxlen, const struct ist pfx[], size_t npfx, const struct ist msg[], size_t nmsg);
int ring_attach(struct ring *ring);
void ring_detach_appctx(struct ring *ring, struct appctx *appctx, size_t ofs);
int ring_attach_cli(struct ring *ring, struct appctx *appctx, uint flags);
int cli_io_handler_show_ring(struct appctx *appctx);
void cli_io_release_show_ring(struct appctx *appctx);

size_t ring_max_payload(const struct ring *ring);
int ring_dispatch_messages(struct ring *ring, void *ctx, size_t *ofs_ptr, size_t *last_ofs_ptr, uint flags,
                           ssize_t (*msg_handler)(void *ctx, struct ist v1, struct ist v2, size_t ofs, size_t len),
                           size_t *processed);

/* returns the ring storage's usable area */
static inline void *ring_area(const struct ring *ring)
{
	return ring->storage->area;
}

/* returns the allocated area for the ring. It covers the whole
 * area made of both the ring_storage and the usable area.
 */
static inline void *ring_allocated_area(const struct ring *ring)
{
	return ring->storage;
}

/* returns the number of bytes in the ring */
static inline size_t ring_data(const struct ring *ring)
{
	size_t tail = HA_ATOMIC_LOAD(&ring->storage->tail) & ~RING_TAIL_LOCK;

	return ((ring->storage->head <= tail) ?
		0 : ring->storage->size) + tail - ring->storage->head;
}

/* returns the usable size in bytes for the ring. It is smaller than
 * the allocate size by the size of the ring_storage header.
 */
static inline size_t ring_size(const struct ring *ring)
{
	return ring->storage->size;
}

/* returns the allocated size in bytes for the ring. It covers the whole
 * area made of both the ring_storage and the usable area.
 */
static inline size_t ring_allocated_size(const struct ring *ring)
{
	return ring->storage->size + ring->storage->rsvd;
}

/* returns the head offset of the ring */
static inline size_t ring_head(const struct ring *ring)
{
	return ring->storage->head;
}

/* returns the ring's tail offset without the lock bit */
static inline size_t ring_tail(const struct ring *ring)
{
	return HA_ATOMIC_LOAD(&ring->storage->tail) & ~RING_TAIL_LOCK;
}

/* duplicates ring <src> over ring <dst> for no more than <max> bytes or no
 * more than the amount of data present in <src>. It's assumed that the
 * destination ring is always large enough for <max>. The number of bytes
 * copied (the min of src's size and max) is returned.
 */
static inline size_t ring_dup(struct ring *dst, const struct ring *src, size_t max)
{
	struct ist v1, v2;

	vp_ring_to_data(&v1, &v2, ring_area(src), ring_size(src), ring_head(src), ring_tail(src));

	if (max > ring_data(src))
		max = ring_data(src);

	BUG_ON(max > ring_size(dst));

	vp_peek_ofs(v1, v2, 0, ring_area(dst), max);
	dst->storage->head = 0;
	dst->storage->tail = max;
	return max;
}

#endif /* _HAPROXY_RING_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
