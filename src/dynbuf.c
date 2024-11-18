/*
 * Buffer management functions.
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/dynbuf.h>
#include <haproxy/global.h>
#include <haproxy/list.h>
#include <haproxy/pool.h>
#include <haproxy/tools.h>

struct pool_head *pool_head_buffer __read_mostly;

/* perform minimal initializations, report 0 in case of error, 1 if OK. */
int init_buffer()
{
	void *buffer;
	int thr;
	int done;
	int i;

	pool_head_buffer = create_pool("buffer", global.tune.bufsize, MEM_F_SHARED|MEM_F_EXACT);
	if (!pool_head_buffer)
		return 0;

	/* make sure any change to the queues assignment isn't overlooked */
	BUG_ON(DB_PERMANENT - DB_UNLIKELY - 1 != DYNBUF_NBQ);
	BUG_ON(DB_MUX_RX_Q  < DB_SE_RX_Q   || DB_MUX_RX_Q  >= DYNBUF_NBQ);
	BUG_ON(DB_SE_RX_Q   < DB_CHANNEL_Q || DB_SE_RX_Q   >= DYNBUF_NBQ);
	BUG_ON(DB_CHANNEL_Q < DB_MUX_TX_Q  || DB_CHANNEL_Q >= DYNBUF_NBQ);
	BUG_ON(DB_MUX_TX_Q >= DYNBUF_NBQ);

	for (thr = 0; thr < MAX_THREADS; thr++) {
		for (i = 0; i < DYNBUF_NBQ; i++)
			LIST_INIT(&ha_thread_ctx[thr].buffer_wq[i]);
		ha_thread_ctx[thr].bufq_map = 0;
	}


	/* The reserved buffer is what we leave behind us. Thus we always need
	 * at least one extra buffer in minavail otherwise we'll end up waking
	 * up tasks with no memory available, causing a lot of useless wakeups.
	 * That means that we always want to have at least 3 buffers available
	 * (2 for current session, one for next session that might be needed to
	 * release a server connection).
	 */
	pool_head_buffer->minavail = MAX(global.tune.reserved_bufs, 3);
	if (global.tune.buf_limit)
		pool_head_buffer->limit = global.tune.buf_limit;

	for (done = 0; done < pool_head_buffer->minavail - 1; done++) {
		buffer = pool_alloc_nocache(pool_head_buffer, init_buffer);
		if (!buffer)
			return 0;
		pool_free(pool_head_buffer, buffer);
	}
	return 1;
}

/*
 * Dumps part or all of a buffer.
 */
void buffer_dump(FILE *o, struct buffer *b, int from, int to)
{
	fprintf(o, "Dumping buffer %p\n", b);
	fprintf(o, "            orig=%p size=%u head=%u tail=%u data=%u\n",
		b_orig(b), (unsigned int)b_size(b), (unsigned int)b_head_ofs(b), (unsigned int)b_tail_ofs(b), (unsigned int)b_data(b));

	fprintf(o, "Dumping contents from byte %d to byte %d\n", from, to);
	fprintf(o, "         0  1  2  3  4  5  6  7    8  9  a  b  c  d  e  f\n");
	/* dump hexa */
	while (from < to) {
		int i;

		fprintf(o, "  %04x: ", from);
		for (i = 0; ((from + i) < to) && (i < 16) ; i++) {
			fprintf(o, "%02x ", (unsigned char)b_orig(b)[from + i]);
			if (i  == 7)
				fprintf(o, "- ");
		}
		if (to - from < 16) {
			int j = 0;

			for (j = 0; j <  from + 16 - to; j++)
				fprintf(o, "   ");
			if (j > 8)
				fprintf(o, "  ");
		}
		fprintf(o, "  ");
		for (i = 0; (from + i < to) && (i < 16) ; i++) {
			fprintf(o, "%c", isprint((unsigned char)b_orig(b)[from + i]) ? b_orig(b)[from + i] : '.') ;
			if ((i == 15) && ((from + i) != to-1))
				fprintf(o, "\n");
		}
		from += i;
	}
	fprintf(o, "\n--\n");
	fflush(o);
}

/* see offer_buffers() for details */
void __offer_buffers(void *from, unsigned int count)
{
	struct buffer_wait *wait, *wait_back;
	int q;

	/* For now, we consider that all objects need 1 buffer, so we can stop
	 * waking up them once we have enough of them to eat all the available
	 * buffers. Note that we don't really know if they are streams or just
	 * other tasks, but that's a rough estimate. Similarly, for each cached
	 * event we'll need 1 buffer.
	 */
	for (q = 0; q < DYNBUF_NBQ; q++) {
		if (!(th_ctx->bufq_map & (1 << q)))
			continue;
		BUG_ON_HOT(LIST_ISEMPTY(&th_ctx->buffer_wq[q]));

		list_for_each_entry_safe(wait, wait_back, &th_ctx->buffer_wq[q], list) {
			if (!count)
				break;

			if (wait->target == from || !wait->wakeup_cb(wait->target))
				continue;

			LIST_DEL_INIT(&wait->list);
			count--;
		}
		if (LIST_ISEMPTY(&th_ctx->buffer_wq[q]))
			th_ctx->bufq_map &= ~(1 << q);
	}
}

/* config parser for global "tune.buffers.limit", accepts a number >= 0 */
static int cfg_parse_tune_buffers_limit(char **args, int section_type, struct proxy *curpx,
                                        const struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	int limit;

	if (too_many_args(1, args, err, NULL))
		return -1;

	limit = atoi(args[1]);
	if (limit < 0) {
		memprintf(err, "'%s' expects a non-negative number but got '%s'.", args[0], args[1]);
		return -1;
	}

	global.tune.buf_limit = limit;
	if (global.tune.buf_limit) {
		if (global.tune.buf_limit < 3)
			global.tune.buf_limit = 3;
	}

	return 0;
}

/* config parser for global "tune.buffers.reserve", accepts a number >= 0 */
static int cfg_parse_tune_buffers_reserve(char **args, int section_type, struct proxy *curpx,
                                          const struct proxy *defpx, const char *file, int line,
                                          char **err)
{
	int reserve;

	if (too_many_args(1, args, err, NULL))
		return -1;

	reserve = atoi(args[1]);
	if (reserve < 0) {
		memprintf(err, "'%s' expects a non-negative number but got '%s'.", args[0], args[1]);
		return -1;
	}

	global.tune.reserved_bufs = reserve;
	return 0;
}

/* config parse for global "tune.bufsize.small" */
static int cfg_parse_tune_bufsize_small(char **args, int section_type,
                                        struct proxy *curpx, const struct proxy *defpx,
                                        const char *file, int line, char **err)
{
	const char *res;
	uint size;

	if (too_many_args(1, args, err, NULL))
		goto err;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects an integer argument.\n", args[0]);
		goto err;
	}

	res = parse_size_err(args[1], &size);
	if (res != NULL) {
		memprintf(err, "unexpected '%s' after size passed to '%s'", res, args[0]);
		goto err;
	}

	if (size <= 0) {
		memprintf(err, "'%s' expects a positive integer argument.\n", args[0]);
		goto err;
	}

	global.tune.bufsize_small = size;
	return 0;

 err:
	return -1;
}

/* allocate emergency buffers for the thread */
static int alloc_emergency_buffers_per_thread(void)
{
	int idx;

	th_ctx->emergency_bufs_left = global.tune.reserved_bufs;
	th_ctx->emergency_bufs = calloc(global.tune.reserved_bufs, sizeof(*th_ctx->emergency_bufs));
	if (!th_ctx->emergency_bufs)
		return 0;

	for (idx = 0; idx < global.tune.reserved_bufs; idx++) {
		/* reserved bufs are not subject to the limit, so we must push it */
		if (_HA_ATOMIC_LOAD(&pool_head_buffer->limit))
			_HA_ATOMIC_INC(&pool_head_buffer->limit);
		th_ctx->emergency_bufs[idx] = pool_alloc_flag(pool_head_buffer, POOL_F_NO_POISON | POOL_F_NO_FAIL);
		if (!th_ctx->emergency_bufs[idx])
			return 0;
	}

	return 1;
}

/* frees the thread's emergency buffers */
static void free_emergency_buffers_per_thread(void)
{
	int idx;

	if (th_ctx->emergency_bufs) {
		for (idx = 0; idx < global.tune.reserved_bufs; idx++)
			pool_free(pool_head_buffer, th_ctx->emergency_bufs[idx]);
	}

	ha_free(&th_ctx->emergency_bufs);
}

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.buffers.limit", cfg_parse_tune_buffers_limit },
	{ CFG_GLOBAL, "tune.buffers.reserve", cfg_parse_tune_buffers_reserve },
	{ CFG_GLOBAL, "tune.bufsize.small", cfg_parse_tune_bufsize_small },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
REGISTER_PER_THREAD_ALLOC(alloc_emergency_buffers_per_thread);
REGISTER_PER_THREAD_FREE(free_emergency_buffers_per_thread);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
