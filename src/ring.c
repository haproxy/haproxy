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
#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/buf.h>
#include <haproxy/cfgparse.h>
#include <haproxy/cli.h>
#include <haproxy/ring.h>
#include <haproxy/sc_strm.h>
#include <haproxy/stconn.h>
#include <haproxy/thread.h>
#include <haproxy/vecpair.h>

/* context used to dump the contents of a ring via "show events" or "show errors" */
struct show_ring_ctx {
	struct ring *ring; /* ring to be dumped */
	size_t ofs;        /* storage offset to restart from; ~0=oldest */
	uint flags;        /* set of RING_WF_* */
};

/* Initialize a pre-allocated ring with the buffer area of size <size>.
 * Makes the storage point to the indicated area and adjusts the declared
 * ring size according to the position of the area in the storage. If <reset>
 * is non-zero, the storage area is reset, otherwise it's left intact (except
 * for the area origin pointer which is updated so that the area can come from
 * an mmap()).
 */
void ring_init(struct ring *ring, void *area, size_t size, int reset)
{
	MT_LIST_INIT(&ring->waiters);
	ring->readers_count = 0;
	ring->flags = 0;
	ring->storage = area;
	ring->pending = 0;
	ring->waking = 0;
	memset(&ring->queue, 0, sizeof(ring->queue));

	if (reset) {
		ring->storage->size = size - sizeof(*ring->storage);
		ring->storage->rsvd = sizeof(*ring->storage);
		ring->storage->head = 0;
		ring->storage->tail = 0;

		/* write the initial RC byte */
		*ring->storage->area = 0;
		ring->storage->tail = 1;
	}
}

/* Creates a ring and its storage area at address <area> for <size> bytes.
 * If <area> is null, then it's allocated of the requested size. The ring
 * storage struct is part of the area so the usable area is slightly reduced.
 * However the storage is immediately adjacent to the struct so that the ring
 * remains consistent on-disk. ring_free() will ignore such ring storages and
 * will only release the ring part, so the caller is responsible for releasing
 * them. If <reset> is non-zero, the storage area is reset, otherwise it's left
 * intact.
 */
struct ring *ring_make_from_area(void *area, size_t size, int reset)
{
	struct ring *ring = NULL;
	uint flags = 0;

	if (size < sizeof(*ring->storage) + 2)
		return NULL;

	ring = malloc(sizeof(*ring));
	if (!ring)
		goto fail;

	if (!area)
		area = malloc(size);
	else
		flags |= RING_FL_MAPPED;

	if (!area)
		goto fail;

	ring_init(ring, area, size, reset);
	ring->flags |= flags;
	return ring;
 fail:
	free(ring);
	return NULL;
}

/* Creates and returns a ring buffer of size <size> bytes. Returns NULL on
 * allocation failure. The size is the area size, not the usable size.
 */
struct ring *ring_new(size_t size)
{
	return ring_make_from_area(NULL, size, 1);
}

/* Resizes existing ring <ring> to <size> which must be larger, without losing
 * its contents. The new size must be at least as large as the previous one or
 * no change will be performed. The pointer to the ring is returned on success,
 * or NULL on allocation failure. This will lock the ring for writes. The size
 * is the allocated area size, and includes the ring_storage header.
 */
struct ring *ring_resize(struct ring *ring, size_t size)
{
	struct ring_storage *old, *new;

	if (size <= ring_data(ring) + sizeof(*ring->storage))
		return ring;

	old = ring->storage;
	new = malloc(size);
	if (!new)
		return NULL;

	thread_isolate();

	/* recheck the ring's size, it may have changed during the malloc */
	if (size > ring_data(ring) + sizeof(*ring->storage)) {
		/* copy old contents */
		struct ist v1, v2;
		size_t len;

		vp_ring_to_data(&v1, &v2, old->area, old->size, old->head, old->tail);
		len = vp_size(v1, v2);
		vp_peek_ofs(v1, v2, 0, new->area, len);
		new->size = size - sizeof(*ring->storage);
		new->rsvd = sizeof(*ring->storage);
		new->head = 0;
		new->tail = len;
		new = HA_ATOMIC_XCHG(&ring->storage, new);
	}

	thread_release();

	/* free the unused one */
	free(new);
	return ring;
}

/* destroys and frees ring <ring> */
void ring_free(struct ring *ring)
{
	if (!ring)
		return;

	/* make sure it was not allocated by ring_make_from_area */
	if (!(ring->flags & RING_FL_MAPPED))
		free(ring->storage);
	free(ring);
}

/* Tries to send <npfx> parts from <prefix> followed by <nmsg> parts from <msg>
 * to ring <ring>. The message is sent atomically. It may be truncated to
 * <maxlen> bytes if <maxlen> is non-null. There is no distinction between the
 * two lists, it's just a convenience to help the caller prepend some prefixes
 * when necessary. It takes the ring's write lock to make sure no other thread
 * will touch the buffer during the update. Returns the number of bytes sent,
 * or <=0 on failure.
 */
ssize_t ring_write(struct ring *ring, size_t maxlen, const struct ist pfx[], size_t npfx, const struct ist msg[], size_t nmsg)
{
	struct ring_wait_cell **ring_queue_ptr = DISGUISE(&ring->queue[ti->ring_queue].ptr);
	struct ring_wait_cell cell, *next_cell, *curr_cell;
	size_t *tail_ptr = &ring->storage->tail;
	size_t head_ofs, tail_ofs, new_tail_ofs;
	size_t ring_size;
	char *ring_area;
	struct ist v1, v2;
	size_t msglen = 0;
	size_t lenlen;
	size_t needed;
	uint64_t dellen;
	int dellenlen;
	uint8_t *lock_ptr;
	uint8_t readers;
	ssize_t sent = 0;
	int i;

	/* we have to find some room to add our message (the buffer is
	 * never empty and at least contains the previous counter) and
	 * to update both the buffer contents and heads at the same
	 * time (it's doable using atomic ops but not worth the
	 * trouble, let's just lock). For this we first need to know
	 * the total message's length. We cannot measure it while
	 * copying due to the varint encoding of the length.
	 */
	for (i = 0; i < npfx; i++)
		msglen += pfx[i].len;
	for (i = 0; i < nmsg; i++)
		msglen += msg[i].len;

	if (msglen > maxlen)
		msglen = maxlen;

	lenlen = varint_bytes(msglen);

	/* We need:
	 *   - lenlen bytes for the size encoding
	 *   - msglen for the message
	 *   - one byte for the new marker
	 *
	 * Note that we'll also reserve one extra byte to make sure we never
	 * leave a full buffer (the vec-to-ring conversion cannot be done if
	 * both areas are of size 0).
	 */
	needed = lenlen + msglen + 1;

	/* these ones do not change under us (only resize affects them and it
	 * must be done under thread isolation).
	 */
	ring_area = ring->storage->area;
	ring_size = ring->storage->size;

	if (needed + 1 > ring_size)
		goto leave;

	cell.to_send_self = needed;
	cell.needed_tot = 0; // only when non-zero the cell is considered ready.
	cell.maxlen = msglen;
	cell.pfx = pfx;
	cell.npfx = npfx;
	cell.msg = msg;
	cell.nmsg = nmsg;

	/* insert our cell into the queue before the previous one. We may have
	 * to wait a bit if the queue's leader is attempting an election to win
	 * the tail, hence the busy value (should be rare enough).
	 */
	next_cell = HA_ATOMIC_XCHG(ring_queue_ptr, &cell);

	/* let's add the cumulated size of pending messages to ours */
	cell.next = next_cell;
	if (next_cell) {
		size_t next_needed;

		while ((next_needed = HA_ATOMIC_LOAD(&next_cell->needed_tot)) == 0)
			__ha_cpu_relax_for_read();
		needed += next_needed;
	}

	/* now <needed> will represent the size to store *all* messages. The
	 * atomic store may unlock a subsequent thread waiting for this one.
	 */
	HA_ATOMIC_STORE(&cell.needed_tot, needed);

	/* OK now we're the queue leader, it's our job to try to get ownership
	 * of the tail, if we succeeded above, we don't even enter the loop. If
	 * we failed, we set ourselves at the top the queue, waiting for the
	 * tail to be unlocked again. We stop doing that if another thread
	 * comes in and becomes the leader in turn.
	 */

	/* Wait for another thread to take the lead or for the tail to
	 * be available again. It's critical to be read-only in this
	 * loop so as not to lose time synchronizing cache lines. Also,
	 * we must detect a new leader ASAP so that the fewest possible
	 * threads check the tail.
	 */

	while (1) {
		if ((curr_cell = HA_ATOMIC_LOAD(ring_queue_ptr)) != &cell)
			goto wait_for_flush;
		__ha_cpu_relax_for_read();

#if !defined(__ARM_FEATURE_ATOMICS)
		/* ARMv8.1-a has a true atomic OR and doesn't need the preliminary read */
		if ((tail_ofs = HA_ATOMIC_LOAD(tail_ptr)) & RING_TAIL_LOCK) {
			__ha_cpu_relax_for_read();
			continue;
		}
#endif
		/* OK the queue is locked, let's attempt to get the tail lock */
		tail_ofs = HA_ATOMIC_FETCH_OR(tail_ptr, RING_TAIL_LOCK);

		/* did we get it ? */
		if (!(tail_ofs & RING_TAIL_LOCK)) {
			/* Here we own the tail. We can go on if we're still the leader,
			 * which we'll confirm by trying to reset the queue. If we're
			 * still the leader, we're done.
			 */
			if (HA_ATOMIC_CAS(ring_queue_ptr, &curr_cell, NULL))
				break; // Won!

			/* oops, no, let's give it back to another thread and wait.
			 * This does not happen often enough to warrant more complex
			 * approaches (tried already).
			 */
			HA_ATOMIC_STORE(tail_ptr, tail_ofs);
			goto wait_for_flush;
		}
		__ha_cpu_relax_for_read();
	}

	head_ofs = HA_ATOMIC_LOAD(&ring->storage->head);

	/* this is the byte before tail, it contains the users count */
	lock_ptr = (uint8_t*)ring_area + (tail_ofs > 0 ? tail_ofs - 1 : ring_size - 1);

	/* Take the lock on the area. We're guaranteed to be the only writer
	 * here.
	 */
	readers = HA_ATOMIC_XCHG(lock_ptr, RING_WRITING_SIZE);

	vp_ring_to_data(&v1, &v2, ring_area, ring_size, head_ofs, tail_ofs);

	while (vp_size(v1, v2) > ring_size - needed - 1 - 1) {
		/* we need to delete the oldest message (from the end),
		 * and we have to stop if there's a reader stuck there.
		 * Unless there's corruption in the buffer it's guaranteed
		 * that we have enough data to find 1 counter byte, a
		 * varint-encoded length (1 byte min) and the message
		 * payload (0 bytes min).
		 */
		if (*_vp_head(v1, v2))
			break;
		dellenlen = vp_peek_varint_ofs(v1, v2, 1, &dellen);
		if (!dellenlen)
			break;
		BUG_ON_HOT(vp_size(v1, v2) < 1 + dellenlen + dellen);
		vp_skip(&v1, &v2, 1 + dellenlen + dellen);
	}

	/* now let's update the buffer with the new tail if our message will fit */
	new_tail_ofs = tail_ofs;
	if (vp_size(v1, v2) <= ring_size - needed - 1 - 1) {
		vp_data_to_ring(v1, v2, ring_area, ring_size, &head_ofs, &tail_ofs);

		/* update the new space in the buffer */
		HA_ATOMIC_STORE(&ring->storage->head, head_ofs);

		/* calculate next tail pointer */
		new_tail_ofs += needed;
		if (new_tail_ofs >= ring_size)
			new_tail_ofs -= ring_size;

		/* reset next read counter before releasing writers */
		HA_ATOMIC_STORE(ring_area + (new_tail_ofs > 0 ? new_tail_ofs - 1 : ring_size - 1), 0);
	}
	else {
		/* release readers right now, before writing the tail, so as
		 * not to expose the readers count byte to another writer.
		 */
		HA_ATOMIC_STORE(lock_ptr, readers);
	}

	/* and release other writers */
	HA_ATOMIC_STORE(tail_ptr, new_tail_ofs);

	vp_ring_to_room(&v1, &v2, ring_area, ring_size, (new_tail_ofs > 0 ? new_tail_ofs - 1 : ring_size - 1), tail_ofs);

	if (likely(tail_ofs != new_tail_ofs)) {
		/* the list stops on a NULL */
		for (curr_cell = &cell; curr_cell; curr_cell = HA_ATOMIC_LOAD(&curr_cell->next)) {
			maxlen = curr_cell->maxlen;
			pfx = curr_cell->pfx;
			npfx = curr_cell->npfx;
			msg = curr_cell->msg;
			nmsg = curr_cell->nmsg;

			/* let's write the message size */
			vp_put_varint(&v1, &v2, maxlen);

			/* then write the messages */
			msglen = 0;
			for (i = 0; i < npfx; i++) {
				size_t len = pfx[i].len;

				if (len + msglen > maxlen)
					len = maxlen - msglen;
				if (len)
					vp_putblk(&v1, &v2, pfx[i].ptr, len);
				msglen += len;
			}

			for (i = 0; i < nmsg; i++) {
				size_t len = msg[i].len;

				if (len + msglen > maxlen)
					len = maxlen - msglen;
				if (len)
					vp_putblk(&v1, &v2, msg[i].ptr, len);
				msglen += len;
			}

			/* for all but the last message we need to write the
			 * readers count byte.
			 */
			if (curr_cell->next)
				vp_putchr(&v1, &v2, 0);
		}

		/* now release */
		for (curr_cell = &cell; curr_cell; curr_cell = next_cell) {
			next_cell = HA_ATOMIC_LOAD(&curr_cell->next);
			_HA_ATOMIC_STORE(&curr_cell->next, curr_cell);
		}

		/* unlock the message area */
		HA_ATOMIC_STORE(lock_ptr, readers);
	} else {
		/* messages were dropped, notify about this and release them  */
		for (curr_cell = &cell; curr_cell; curr_cell = next_cell) {
			next_cell = HA_ATOMIC_LOAD(&curr_cell->next);
			HA_ATOMIC_STORE(&curr_cell->to_send_self, 0);
			_HA_ATOMIC_STORE(&curr_cell->next, curr_cell);
		}
	}

	/* we must not write the trailing read counter, it was already done,
	 * plus we could ruin the one of the next writer. And the front was
	 * unlocked either at the top if the ring was full, or just above if it
	 * could be properly filled.
	 */

	sent = cell.to_send_self;

	/* notify potential readers */
	if (sent && HA_ATOMIC_LOAD(&ring->readers_count)) {
		HA_ATOMIC_INC(&ring->pending);
		while (HA_ATOMIC_LOAD(&ring->pending) && HA_ATOMIC_XCHG(&ring->waking, 1) == 0) {
			struct mt_list back;
			struct appctx *appctx;

			HA_ATOMIC_STORE(&ring->pending, 0);
			MT_LIST_FOR_EACH_ENTRY_LOCKED(appctx, &ring->waiters, wait_entry, back)
				appctx_wakeup(appctx);
			HA_ATOMIC_STORE(&ring->waking, 0);
		}
	}

 leave:
	return sent;

 wait_for_flush:
	/* if we arrive here, it means we found another leader */

	/* The leader will write our own pointer in the cell's next to
	 * mark it as released. Let's wait for this.
	 */
	do {
		next_cell = HA_ATOMIC_LOAD(&cell.next);
	} while (next_cell != &cell && __ha_cpu_relax_for_read());

	/* OK our message was queued. Retrieving the sent size in the ring cell
	 * allows another leader thread to zero it if it finally couldn't send
	 * it (should only happen when using too small ring buffers to store
	 * all competing threads' messages at once).
	 */
	return HA_ATOMIC_LOAD(&cell.to_send_self);
}

/* Tries to attach appctx <appctx> as a new reader on ring <ring>. This is
 * meant to be used by low level appctx code such as CLI or ring forwarding.
 * For higher level functions, please see the relevant parts in appctx or CLI.
 * It returns non-zero on success or zero on failure if too many users are
 * already attached. On success, the caller MUST call ring_detach_appctx()
 * to detach itself, even if it was never woken up.
 */
int ring_attach(struct ring *ring)
{
	int users = ring->readers_count;

	do {
		if (users >= RING_MAX_READERS)
			return 0;
	} while (!_HA_ATOMIC_CAS(&ring->readers_count, &users, users + 1));
	return 1;
}

/* detach an appctx from a ring. The appctx is expected to be waiting at offset
 * <ofs> relative to the beginning of the storage, or ~0 if not waiting yet.
 * Nothing is done if <ring> is NULL.
 */
void ring_detach_appctx(struct ring *ring, struct appctx *appctx, size_t ofs)
{
	if (!ring)
		return;

	HA_ATOMIC_DEC(&ring->readers_count);

	if (ofs != ~0) {
		/* reader was still attached */
		uint8_t *area = (uint8_t *)ring_area(ring);
		uint8_t readers;

		BUG_ON(ofs >= ring_size(ring));
		MT_LIST_DELETE(&appctx->wait_entry);

		/* dec readers count */
		do {
			readers = _HA_ATOMIC_LOAD(area + ofs);
		} while ((readers > RING_MAX_READERS ||
			  !_HA_ATOMIC_CAS(area + ofs, &readers, readers - 1)) && __ha_cpu_relax());
	}
}

/* Tries to attach CLI handler <appctx> as a new reader on ring <ring>. This is
 * meant to be used when registering a CLI function to dump a buffer, so it
 * returns zero on success, or non-zero on failure with a message in the appctx
 * CLI context. It automatically sets the io_handler and io_release callbacks if
 * they were not set. The <flags> take a combination of RING_WF_*.
 */
int ring_attach_cli(struct ring *ring, struct appctx *appctx, uint flags)
{
	struct show_ring_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	if (!ring_attach(ring))
		return cli_err(appctx,
		               "Sorry, too many watchers (" TOSTR(RING_MAX_READERS) ") on this ring buffer. "
		               "What could it have so interesting to attract so many watchers ?");

	if (!appctx->io_handler)
		appctx->io_handler = cli_io_handler_show_ring;
	if (!appctx->io_release)
                appctx->io_release = cli_io_release_show_ring;

	memset(ctx, 0, sizeof(*ctx));
	ctx->ring  = ring;
	ctx->ofs   = ~0; // start from the oldest event
	ctx->flags = flags;
	return 0;
}


/* parses as many messages as possible from ring <ring>, starting at the offset
 * stored at *ofs_ptr, with RING_WF_* flags in <flags>, and passes them to
 * the message handler <msg_handler>. If <last_of_ptr> is not NULL, a copy of
 * the last known tail pointer will be copied there so that the caller may use
 * this to detect new data have arrived since we left the function. Returns 0
 * if it needs to pause, 1 once finished.
 *
 * If <processed> is not NULL, it will be set to the number of messages
 * processed by the function (even when the function returns 0)
 */
int ring_dispatch_messages(struct ring *ring, void *ctx, size_t *ofs_ptr, size_t *last_ofs_ptr, uint flags,
                           ssize_t (*msg_handler)(void *ctx, struct ist v1, struct ist v2, size_t ofs, size_t len),
                           size_t *processed)
{
	size_t head_ofs, tail_ofs, prev_ofs;
	size_t ring_size;
	uint8_t *ring_area;
	struct ist v1, v2;
	uint64_t msg_len;
	size_t len, cnt;
	size_t msg_count = 0;
	ssize_t copied;
	uint8_t readers;
	int ret;

	ring_area = (uint8_t *)ring->storage->area;
	ring_size = ring->storage->size;

	/* explanation for the initialization below: it would be better to do
	 * this in the parsing function but this would occasionally result in
	 * dropped events because we'd take a reference on the oldest message
	 * and keep it while being scheduled. Thus instead let's take it the
	 * first time we enter here so that we have a chance to pass many
	 * existing messages before grabbing a reference to a location. This
	 * value cannot be produced after initialization. The first offset
	 * needs to be taken under isolation as it must not move while we're
	 * trying to catch it.
	 */
	if (unlikely(*ofs_ptr == ~0)) {
		thread_isolate();

		head_ofs = HA_ATOMIC_LOAD(&ring->storage->head);
		tail_ofs = ring_tail(ring);

		if (flags & RING_WF_SEEK_NEW) {
			/* going to the end means looking at tail-1 */
			head_ofs = tail_ofs + ring_size - 1;
			if (head_ofs >= ring_size)
				head_ofs -= ring_size;
		}

		/* reserve our slot here (inc readers count) */
		do {
			readers = _HA_ATOMIC_LOAD(ring_area + head_ofs);
		} while ((readers > RING_MAX_READERS ||
			  !_HA_ATOMIC_CAS(ring_area + head_ofs, &readers, readers + 1)) && __ha_cpu_relax());

		thread_release();

		/* store this precious offset in our context, and we're done */
		*ofs_ptr = head_ofs;
	}

	/* we have the guarantee we can restart from our own head */
	head_ofs = *ofs_ptr;
	BUG_ON(head_ofs >= ring_size);

	/* the tail will continue to move but we're getting a safe value
	 * here that will continue to work.
	 */
	tail_ofs = ring_tail(ring);

	/* we keep track of where we were and we don't release it before
	 * we've protected the next place.
	 */
	prev_ofs = head_ofs;

	/* in this loop, head_ofs always points to the counter byte that precedes
	 * the message so that we can take our reference there if we have to
	 * stop before the end (ret=0). The reference is relative to the ring's
	 * origin, while pos is relative to the ring's head.
	 */
	ret = 1;
	vp_ring_to_data(&v1, &v2, (char *)ring_area, ring_size, head_ofs, tail_ofs);

	while (1) {
		if (vp_size(v1, v2) <= 1) {
			/* no more data */
			break;
		}

		readers = _HA_ATOMIC_LOAD(_vp_addr(v1, v2, 0));
		if (readers > RING_MAX_READERS) {
			/* we just met a writer which hasn't finished */
			break;
		}

		cnt = 1;
		len = vp_peek_varint_ofs(v1, v2, cnt, &msg_len);
		if (!len)
			break;
		cnt += len;

		BUG_ON(msg_len + cnt + 1 > vp_size(v1, v2));

		copied = msg_handler(ctx, v1, v2, cnt, msg_len);
		if (copied == -2) {
			/* too large a message to ever fit, let's skip it */
			goto skip;
		}
		else if (copied == -1) {
			/* output full */
			ret = 0;
			break;
		}
	skip:
		msg_count += 1;
		vp_skip(&v1, &v2, cnt + msg_len);
	}

	vp_data_to_ring(v1, v2, (char *)ring_area, ring_size, &head_ofs, &tail_ofs);

	if (head_ofs != prev_ofs) {
		/* inc readers count on new place */
		do {
			readers = _HA_ATOMIC_LOAD(ring_area + head_ofs);
		} while ((readers > RING_MAX_READERS ||
			  !_HA_ATOMIC_CAS(ring_area + head_ofs, &readers, readers + 1)) && __ha_cpu_relax());

		/* dec readers count on old place */
		do {
			readers = _HA_ATOMIC_LOAD(ring_area + prev_ofs);
		} while ((readers > RING_MAX_READERS ||
			  !_HA_ATOMIC_CAS(ring_area + prev_ofs, &readers, readers - 1)) && __ha_cpu_relax());
	}

	if (last_ofs_ptr)
		*last_ofs_ptr = tail_ofs;
	*ofs_ptr = head_ofs;
	if (processed)
		*processed = msg_count;
	return ret;
}

/* This function dumps all events from the ring whose pointer is in <p0> into
 * the appctx's output buffer, and takes from <o0> the seek offset into the
 * buffer's history (0 for oldest known event). It looks at <i0> for boolean
 * options: bit0 means it must wait for new data or any key to be pressed. Bit1
 * means it must seek directly to the end to wait for new contents. It returns
 * 0 if the output buffer or events are missing is full and it needs to be
 * called again, otherwise non-zero. It is meant to be used with
 * cli_release_show_ring() to clean up.
 */
int cli_io_handler_show_ring(struct appctx *appctx)
{
	struct show_ring_ctx *ctx = appctx->svcctx;
	struct stconn *sc = appctx_sc(appctx);
	struct ring *ring = ctx->ring;
	size_t last_ofs;
	size_t ofs;
	int ret;

	MT_LIST_DELETE(&appctx->wait_entry);

	ret = ring_dispatch_messages(ring, appctx, &ctx->ofs, &last_ofs, ctx->flags, applet_append_line, NULL);

	if (ret && (ctx->flags & RING_WF_WAIT_MODE)) {
		/* we've drained everything and are configured to wait for more
		 * data or an event (keypress, close)
		 */
		if (!sc_oc(sc)->output && !(sc->flags & SC_FL_SHUT_DONE)) {
			/* let's be woken up once new data arrive */
			MT_LIST_APPEND(&ring->waiters, &appctx->wait_entry);
			ofs = ring_tail(ring);
			if (ofs != last_ofs) {
				/* more data was added into the ring between the
				 * unlock and the lock, and the writer might not
				 * have seen us. We need to reschedule a read.
				 */
				applet_have_more_data(appctx);
			} else
				applet_have_no_more_data(appctx);
			ret = 0;
		}
		/* always drain all the request */
		co_skip(sc_oc(sc), sc_oc(sc)->output);
	}

	applet_expect_no_data(appctx);
	return ret;
}

/* must be called after cli_io_handler_show_ring() above */
void cli_io_release_show_ring(struct appctx *appctx)
{
	struct show_ring_ctx *ctx = appctx->svcctx;
	struct ring *ring = ctx->ring;
	size_t ofs = ctx->ofs;

	ring_detach_appctx(ring, appctx, ofs);
}

/* Returns the MAXIMUM payload len that could theoretically fit into the ring
 * based on ring buffer size.
 *
 * Computation logic relies on implementation details from 'ring-t.h'.
 */
size_t ring_max_payload(const struct ring *ring)
{
	size_t max;

	/* initial max = bufsize - 1 (initial RC) - 1 (payload RC) */
	max = ring_size(ring) - 1 - 1;

	/* subtract payload VI (varint-encoded size) */
	max -= varint_bytes(max);
	return max;
}

/* config parser for global "tune.ring.queues", accepts a number from 0 to RING_WAIT_QUEUES */
static int cfg_parse_tune_ring_queues(char **args, int section_type, struct proxy *curpx,
                                       const struct proxy *defpx, const char *file, int line,
                                       char **err)
{
	int queues;

	if (too_many_args(1, args, err, NULL))
		return -1;

	queues = atoi(args[1]);
	if (queues < 0 || queues > RING_WAIT_QUEUES) {
		memprintf(err, "'%s' expects a number between 0 and %d but got '%s'.", args[0], RING_WAIT_QUEUES, args[1]);
		return -1;
	}

	global.tune.ring_queues = queues;
	return 0;
}

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.ring.queues", cfg_parse_tune_ring_queues },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
