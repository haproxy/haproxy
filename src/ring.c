/*
 * Ring buffer management
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

#include <stdlib.h>
#include <common/buf.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/hathreads.h>
#include <proto/ring.h>

/* Creates and returns a ring buffer of size <size> bytes. Returns NULL on
 * allocation failure.
 */
struct ring *ring_new(size_t size)
{
	struct ring *ring = NULL;
	void *area = NULL;

	if (size < 2)
		goto fail;

	ring = malloc(sizeof(*ring));
	if (!ring)
		goto fail;

	area = malloc(size);
	if (!area)
		goto fail;

	HA_RWLOCK_INIT(&ring->lock);
	ring->readers_count = 0;
	ring->ofs = 0;
	ring->buf = b_make(area, size, 0, 0);
	/* write the initial RC byte */
	b_putchr(&ring->buf, 0);
	return ring;
 fail:
	free(area);
	free(ring);
	return NULL;
}

/* Resizes existing ring <ring> to <size> which must be larger, without losing
 * its contents. The new size must be at least as large as the previous one or
 * no change will be performed. The pointer to the ring is returned on success,
 * or NULL on allocation failure. This will lock the ring for writes.
 */
struct ring *ring_resize(struct ring *ring, size_t size)
{
	void *area;

	if (b_size(&ring->buf) >= size)
		return ring;

	area = malloc(size);
	if (!area)
		return NULL;

	HA_RWLOCK_WRLOCK(LOGSRV_LOCK, &ring->lock);

	/* recheck the buffer's size, it may have changed during the malloc */
	if (b_size(&ring->buf) < size) {
		/* copy old contents */
		b_getblk(&ring->buf, area, ring->buf.data, 0);
		area = HA_ATOMIC_XCHG(&ring->buf.area, area);
		ring->buf.size = size;
		ring->buf.head = 0;
	}

	HA_RWLOCK_WRUNLOCK(LOGSRV_LOCK, &ring->lock);

	free(area);
	return ring;
}

/* destroys and frees ring <ring> */
void ring_free(struct ring *ring)
{
	if (!ring)
		return;
	free(ring->buf.area);
	free(ring);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
