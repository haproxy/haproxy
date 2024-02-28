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
	HA_RWLOCK_INIT(&ring->lock);
	LIST_INIT(&ring->waiters);
	ring->readers_count = 0;
	ring->flags = 0;
	ring->storage = area;

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
 * remains consistent on-disk. ring_free() will ignore such ring stoages and
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
 * allocation failure.
 */
struct ring *ring_new(size_t size)
{
	return ring_make_from_area(NULL, size, 1);
}

/* Resizes existing ring <ring> to <size> which must be larger, without losing
 * its contents. The new size must be at least as large as the previous one or
 * no change will be performed. The pointer to the ring is returned on success,
 * or NULL on allocation failure. This will lock the ring for writes.
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
	size_t head_ofs, tail_ofs;
	size_t ring_size;
	char *ring_area;
	struct ist v1, v2;
	struct appctx *appctx;
	size_t msglen = 0;
	size_t lenlen;
	size_t needed;
	uint64_t dellen;
	int dellenlen;
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

	HA_RWLOCK_WRLOCK(RING_LOCK, &ring->lock);
	if (needed + 1 > ring_size)
		goto leave;

	head_ofs = ring_head(ring);
	tail_ofs = ring_tail(ring);

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

	/* now let's update the buffer with the new head and size */
	vp_data_to_ring(v1, v2, ring_area, ring_size, &head_ofs, &tail_ofs);

	if (vp_size(v1, v2) > ring_size - needed - 1 - 1)
		goto done_update_buf;

	/* now focus on free room */
	vp_ring_to_room(&v1, &v2, ring_area, ring_size, head_ofs, tail_ofs);

	/* let's write the message size */
	vp_put_varint(&v1, &v2, msglen);

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

	vp_putchr(&v1, &v2, 0); // new read counter
	sent = lenlen + msglen + 1;
	BUG_ON_HOT(sent != needed);

	vp_room_to_ring(v1, v2, ring_area, ring_size, &head_ofs, &tail_ofs);

 done_update_buf:
	/* update the new space in the buffer */
	ring->storage->head = head_ofs;
	ring->storage->tail = tail_ofs;

	/* notify potential readers */
	if (sent) {
		list_for_each_entry(appctx, &ring->waiters, wait_entry)
			appctx_wakeup(appctx);
	}

 leave:
	HA_RWLOCK_WRUNLOCK(RING_LOCK, &ring->lock);
	return sent;
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

	HA_RWLOCK_WRLOCK(RING_LOCK, &ring->lock);
	if (ofs != ~0) {
		/* reader was still attached */
		uint8_t *area = (uint8_t *)ring_area(ring);
		uint8_t readers;

		BUG_ON(ofs >= ring_size(ring));
		LIST_DEL_INIT(&appctx->wait_entry);

		/* dec readers count */
		do {
			readers = _HA_ATOMIC_LOAD(area + ofs);
		} while ((readers > RING_MAX_READERS ||
			  !_HA_ATOMIC_CAS(area + ofs, &readers, readers - 1)) && __ha_cpu_relax());
	}
	HA_ATOMIC_DEC(&ring->readers_count);
	HA_RWLOCK_WRUNLOCK(RING_LOCK, &ring->lock);
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
 */
int ring_dispatch_messages(struct ring *ring, void *ctx, size_t *ofs_ptr, size_t *last_ofs_ptr, uint flags,
			   ssize_t (*msg_handler)(void *ctx, struct ist v1, struct ist v2, size_t ofs, size_t len))
{
	size_t head_ofs, tail_ofs;
	size_t ring_size;
	uint8_t *ring_area;
	struct ist v1, v2;
	uint64_t msg_len;
	size_t len, cnt;
	ssize_t copied;
	uint8_t readers;
	int ret;

	ring_area = (uint8_t *)ring->storage->area;
	ring_size = ring->storage->size;

	HA_RWLOCK_RDLOCK(RING_LOCK, &ring->lock);

	head_ofs = ring->storage->head;
	tail_ofs = ring->storage->tail;

	/* explanation for the initialization below: it would be better to do
	 * this in the parsing function but this would occasionally result in
	 * dropped events because we'd take a reference on the oldest message
	 * and keep it while being scheduled. Thus instead let's take it the
	 * first time we enter here so that we have a chance to pass many
	 * existing messages before grabbing a reference to a location. This
	 * value cannot be produced after initialization.
	 */
	if (unlikely(*ofs_ptr == ~0)) {
		if (flags & RING_WF_SEEK_NEW) {
			/* going to the end means looking at tail-1 */
			head_ofs = tail_ofs + ring_size - 1;
			if (head_ofs >= ring_size)
				head_ofs -= ring_size;
		}

		/* make ctx->ofs relative to the beginning of the buffer now */
		*ofs_ptr = head_ofs;

		/* and reserve our slot here (inc readers count) */
		do {
			readers = _HA_ATOMIC_LOAD(ring_area + head_ofs);
		} while ((readers > RING_MAX_READERS ||
			  !_HA_ATOMIC_CAS(ring_area + head_ofs, &readers, readers + 1)) && __ha_cpu_relax());
	}

	/* we have the guarantee we can restart from our own head */
	head_ofs = *ofs_ptr;
	BUG_ON(head_ofs >= ring_size);

	/* dec readers count */
	do {
		readers = _HA_ATOMIC_LOAD(ring_area + head_ofs);
	} while ((readers > RING_MAX_READERS ||
		  !_HA_ATOMIC_CAS(ring_area + head_ofs, &readers, readers - 1)) && __ha_cpu_relax());

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
		vp_skip(&v1, &v2, cnt + msg_len);
	}

	vp_data_to_ring(v1, v2, (char *)ring_area, ring_size, &head_ofs, &tail_ofs);

	/* inc readers count */
	do {
		readers = _HA_ATOMIC_LOAD(ring_area + head_ofs);
	} while ((readers > RING_MAX_READERS ||
		  !_HA_ATOMIC_CAS(ring_area + head_ofs, &readers, readers + 1)) && __ha_cpu_relax());

	if (last_ofs_ptr)
		*last_ofs_ptr = tail_ofs;
	*ofs_ptr = head_ofs;
	HA_RWLOCK_RDUNLOCK(RING_LOCK, &ring->lock);
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

	/* FIXME: Don't watch the other side !*/
	if (unlikely(sc_opposite(sc)->flags & SC_FL_SHUT_DONE))
		return 1;

	HA_RWLOCK_WRLOCK(RING_LOCK, &ring->lock);
	LIST_DEL_INIT(&appctx->wait_entry);
	HA_RWLOCK_WRUNLOCK(RING_LOCK, &ring->lock);

	ret = ring_dispatch_messages(ring, appctx, &ctx->ofs, &last_ofs, ctx->flags, applet_append_line);

	if (ret && (ctx->flags & RING_WF_WAIT_MODE)) {
		/* we've drained everything and are configured to wait for more
		 * data or an event (keypress, close)
		 */
		if (!sc_oc(sc)->output && !(sc->flags & SC_FL_SHUT_DONE)) {
			/* let's be woken up once new data arrive */
			HA_RWLOCK_WRLOCK(RING_LOCK, &ring->lock);
			LIST_APPEND(&ring->waiters, &appctx->wait_entry);
			ofs = ring_tail(ring);
			HA_RWLOCK_WRUNLOCK(RING_LOCK, &ring->lock);
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

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
