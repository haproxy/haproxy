/*
 * include/haproxy/dynbuf-t.h
 * Structure definitions for dynamic buffer management.
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

#ifndef _HAPROXY_DYNBUF_T_H
#define _HAPROXY_DYNBUF_T_H

#include <haproxy/list-t.h>

/* Describe the levels of criticality of each allocation based on the expected
 * use case. We distinguish multiple use cases, from the least important to the
 * most important one:
 *   - allocate a buffer to grow a non-empty ring: this should be avoided when
 *     resources are becoming scarce.
 *   - allocate a buffer for very unlikely situations (e.g. L7 retries, early
 *     data). These may acceptably fail on low resources.
 *   - buffer used to receive data in the mux at the connection level. Please
 *     note that this level might later be resplit into two levels, one for
 *     initial data such as a new request, which may be rejected and postponed,
 *     and one for data continuation, which may be needed to complete a request
 *     or receive some control data allowing another buffer to be flushed.
 *   - buffer used to produce data at the endpoint for internal consumption,
 *     typically mux streams and applets. These buffers will be allocated until
 *     a channel picks them. Not processing them might sometimes lead to a mux
 *     being clogged and blocking other streams from progressing.
 *   - channel buffer: this one may be allocated to perform a synchronous recv,
 *     or just preparing for the possibility of an instant response. The
 *     response channel always allocates a buffer when entering process_stream,
 *     which is immediately released if unused when leaving.
 *   - buffer used by the mux sending side, often allocated by the mux's
 *     snd_buf() handler to encode the outgoing channel's data.
 *   - buffer permanently allocated at boot (e.g. temporary compression
 *     buffers). If these fail, we can't boot.
 *
 * Please DO NOT CHANGE THESE LEVELS without first getting a full understanding
 * of how all this works and touching the DB_F_CRIT_MASK and DB_CRIT_TO_QUEUE()
 * macros below!
 */
enum dynbuf_crit {
	DB_GROW_RING = 0, // used to grow an existing buffer ring
	DB_UNLIKELY,      // unlikely to be needed (e.g. L7 retries)
	/* The 4 levels below are subject to queueing */
	DB_MUX_RX,        // buffer used to store incoming data from the system
	DB_SE_RX,         // buffer used to store incoming data for the channel
	DB_CHANNEL,       // buffer used by the channel for synchronous reads
	DB_MUX_TX,        // buffer used to store outgoing mux data
	/* The one below may never fail */
	DB_PERMANENT,     // buffers permanently allocated.
};

/* The values above are expected to be passed to b_alloc(). In addition, some
 * Extra flags can be passed by oring the crit value above with one of these
 * high-bit flags.
 */
#define DB_F_NOQUEUE   0x80000000U   // ignore presence of others in queue
#define DB_F_CRIT_MASK 0x000000FFU   // mask to keep the criticality bits


/* We'll deal with 4 queues, with indexes numbered from 0 to 3 based on the
 * criticality of the allocation. All criticality levels are mapped to a 2-bit
 * queue index. While some levels never use the queue (the first two), some of
 * the others will share a same queue, and all levels will define a ratio of
 * allocated emergency buffers below which we refrain from trying to allocate.
 * In practice, for now the thresholds will just be the queue number times 33%
 * so that queue 0 is allowed to deplete emergency buffers and queue 3 not at
 * all. This gives us: queue idx=3 for DB_MUX_RX and below, 2 for DB_SE_RX,
 * 1 for DB_CHANNEL, 0 for DB_MUX_TX and above. This must match the DYNBUF_NBQ
 * in tinfo-t.h.
 */

#define DB_CRIT_TO_QUEUE(crit) ((0x000001BF >> ((crit) * 2)) & 3)

#define DB_GROW_RING_Q      DB_CRIT_TO_QUEUE(DB_GROW_RING)
#define DB_UNLIKELY_Q       DB_CRIT_TO_QUEUE(DB_UNLIKELY)
#define DB_MUX_RX_Q         DB_CRIT_TO_QUEUE(DB_MUX_RX)
#define DB_SE_RX_Q          DB_CRIT_TO_QUEUE(DB_SE_RX)
#define DB_CHANNEL_Q        DB_CRIT_TO_QUEUE(DB_CHANNEL)
#define DB_MUX_TX_Q         DB_CRIT_TO_QUEUE(DB_MUX_TX)
#define DB_PERMANENT_Q      DB_CRIT_TO_QUEUE(DB_PERMANENT)


/* an element of the <buffer_wq> list. It represents an object that need to
 * acquire a buffer to continue its process. */
struct buffer_wait {
	void *target;              /* The waiting object that should be woken up */
	int (*wakeup_cb)(void *);  /* The function used to wake up the <target>, passed as argument */
	struct list list;          /* Next element in the <buffer_wq> list */
};

#endif /* _HAPROXY_DYNBUF_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
