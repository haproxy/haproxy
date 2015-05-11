/*
 * HTTP compression.
 *
 * Copyright 2012 Exceliance, David Du Colombier <dducolombier@exceliance.fr>
 *                            William Lallemand <wlallemand@exceliance.fr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdio.h>

#if defined(USE_SLZ)
#include <slz.h>
#elif defined(USE_ZLIB)
/* Note: the crappy zlib and openssl libs both define the "free_func" type.
 * That's a very clever idea to use such a generic name in general purpose
 * libraries, really... The zlib one is easier to redefine than openssl's,
 * so let's only fix this one.
 */
#define free_func zlib_free_func
#include <zlib.h>
#undef free_func
#endif /* USE_ZLIB */

#include <common/compat.h>
#include <common/memory.h>

#include <types/global.h>
#include <types/compression.h>

#include <proto/acl.h>
#include <proto/compression.h>
#include <proto/freq_ctr.h>
#include <proto/proto_http.h>
#include <proto/stream.h>


#ifdef USE_ZLIB

static void *alloc_zlib(void *opaque, unsigned int items, unsigned int size);
static void free_zlib(void *opaque, void *ptr);

/* zlib allocation  */
static struct pool_head *zlib_pool_deflate_state = NULL;
static struct pool_head *zlib_pool_window = NULL;
static struct pool_head *zlib_pool_prev = NULL;
static struct pool_head *zlib_pool_head = NULL;
static struct pool_head *zlib_pool_pending_buf = NULL;

long zlib_used_memory = 0;

#endif

unsigned int compress_min_idle = 0;
static struct pool_head *pool_comp_ctx = NULL;

static int identity_init(struct comp_ctx **comp_ctx, int level);
static int identity_add_data(struct comp_ctx *comp_ctx, const char *in_data, int in_len, struct buffer *out);
static int identity_flush(struct comp_ctx *comp_ctx, struct buffer *out);
static int identity_finish(struct comp_ctx *comp_ctx, struct buffer *out);
static int identity_end(struct comp_ctx **comp_ctx);

#if defined(USE_SLZ)

static int rfc1950_init(struct comp_ctx **comp_ctx, int level);
static int rfc1951_init(struct comp_ctx **comp_ctx, int level);
static int rfc1952_init(struct comp_ctx **comp_ctx, int level);
static int rfc195x_add_data(struct comp_ctx *comp_ctx, const char *in_data, int in_len, struct buffer *out);
static int rfc195x_flush(struct comp_ctx *comp_ctx, struct buffer *out);
static int rfc195x_finish(struct comp_ctx *comp_ctx, struct buffer *out);
static int rfc195x_end(struct comp_ctx **comp_ctx);

#elif defined(USE_ZLIB)

static int gzip_init(struct comp_ctx **comp_ctx, int level);
static int raw_def_init(struct comp_ctx **comp_ctx, int level);
static int deflate_init(struct comp_ctx **comp_ctx, int level);
static int deflate_add_data(struct comp_ctx *comp_ctx, const char *in_data, int in_len, struct buffer *out);
static int deflate_flush(struct comp_ctx *comp_ctx, struct buffer *out);
static int deflate_finish(struct comp_ctx *comp_ctx, struct buffer *out);
static int deflate_end(struct comp_ctx **comp_ctx);

#endif /* USE_ZLIB */


const struct comp_algo comp_algos[] =
{
	{ "identity",     8, "identity", 8, identity_init, identity_add_data, identity_flush, identity_finish, identity_end },
#if defined(USE_SLZ)
	{ "deflate",      7, "deflate",  7, rfc1950_init,  rfc195x_add_data,  rfc195x_flush,  rfc195x_finish,  rfc195x_end },
	{ "raw-deflate", 11, "deflate",  7, rfc1951_init,  rfc195x_add_data,  rfc195x_flush,  rfc195x_finish,  rfc195x_end },
	{ "gzip",         4, "gzip",     4, rfc1952_init,  rfc195x_add_data,  rfc195x_flush,  rfc195x_finish,  rfc195x_end },
#elif defined(USE_ZLIB)
	{ "deflate",      7, "deflate",  7, deflate_init,  deflate_add_data,  deflate_flush,  deflate_finish,  deflate_end },
	{ "raw-deflate", 11, "deflate",  7, raw_def_init,  deflate_add_data,  deflate_flush,  deflate_finish,  deflate_end },
	{ "gzip",         4, "gzip",     4, gzip_init,     deflate_add_data,  deflate_flush,  deflate_finish,  deflate_end },
#endif /* USE_ZLIB */
	{ NULL,       0, NULL,          0, NULL ,         NULL,              NULL,           NULL,           NULL }
};

/*
 * Add a content-type in the configuration
 */
int comp_append_type(struct comp *comp, const char *type)
{
	struct comp_type *comp_type;

	comp_type = calloc(1, sizeof(struct comp_type));
	comp_type->name_len = strlen(type);
	comp_type->name = strdup(type);
	comp_type->next = comp->types;
	comp->types = comp_type;
	return 0;
}

/*
 * Add an algorithm in the configuration
 */
int comp_append_algo(struct comp *comp, const char *algo)
{
	struct comp_algo *comp_algo;
	int i;

	for (i = 0; comp_algos[i].cfg_name; i++) {
		if (!strcmp(algo, comp_algos[i].cfg_name)) {
			comp_algo = calloc(1, sizeof(struct comp_algo));
			memmove(comp_algo, &comp_algos[i], sizeof(struct comp_algo));
			comp_algo->next = comp->algos;
			comp->algos = comp_algo;
			return 0;
		}
	}
	return -1;
}

/* emit the chunksize followed by a CRLF on the output and return the number of
 * bytes written. It goes backwards and starts with the byte before <end>. It
 * returns the number of bytes written which will not exceed 10 (8 digits, CR,
 * and LF). The caller is responsible for ensuring there is enough room left in
 * the output buffer for the string.
 */
int http_emit_chunk_size(char *end, unsigned int chksz)
{
	char *beg = end;

	*--beg = '\n';
	*--beg = '\r';
	do {
		*--beg = hextab[chksz & 0xF];
	} while (chksz >>= 4);
	return end - beg;
}

/*
 * Init HTTP compression
 */
int http_compression_buffer_init(struct stream *s, struct buffer *in, struct buffer *out)
{
	/* output stream requires at least 10 bytes for the gzip header, plus
	 * at least 8 bytes for the gzip trailer (crc+len), plus a possible
	 * plus at most 5 bytes per 32kB block and 2 bytes to close the stream.
	 */
	if (in->size - buffer_len(in) < 20 + 5 * ((in->i + 32767) >> 15))
		return -1;

	/* prepare an empty output buffer in which we reserve enough room for
	 * copying the output bytes from <in>, plus 10 extra bytes to write
	 * the chunk size. We don't copy the bytes yet so that if we have to
	 * cancel the operation later, it's cheap.
	 */
	b_reset(out);
	out->o = in->o;
	out->p += out->o;
	out->i = 10;
	return 0;
}

/*
 * Add data to compress
 */
int http_compression_buffer_add_data(struct stream *s, struct buffer *in, struct buffer *out)
{
	struct http_msg *msg = &s->txn->rsp;
	int consumed_data = 0;
	int data_process_len;
	int block1, block2;

	/*
	 * Temporarily skip already parsed data and chunks to jump to the
	 * actual data block. It is fixed before leaving.
	 */
	b_adv(in, msg->next);

	/*
	 * select the smallest size between the announced chunk size, the input
	 * data, and the available output buffer size. The compressors are
	 * assumed to be able to process all the bytes we pass to them at once.
	 */
	data_process_len = MIN(in->i, msg->chunk_len);
	data_process_len = MIN(out->size - buffer_len(out), data_process_len);

	block1 = data_process_len;
	if (block1 > bi_contig_data(in))
		block1 = bi_contig_data(in);
	block2 = data_process_len - block1;

	/* compressors return < 0 upon error or the amount of bytes read */
	consumed_data = s->comp_algo->add_data(s->comp_ctx, bi_ptr(in), block1, out);
	if (consumed_data >= 0 && block2 > 0) {
		consumed_data = s->comp_algo->add_data(s->comp_ctx, in->data, block2, out);
		if (consumed_data >= 0)
			consumed_data += block1;
	}

	/* restore original buffer pointer */
	b_rew(in, msg->next);

	if (consumed_data > 0) {
		msg->next += consumed_data;
		msg->chunk_len -= consumed_data;
	}
	return consumed_data;
}

/*
 * Flush data in process, and write the header and footer of the chunk. Upon
 * success, in and out buffers are swapped to avoid a copy.
 */
int http_compression_buffer_end(struct stream *s, struct buffer **in, struct buffer **out, int end)
{
	int to_forward;
	int left;
	struct http_msg *msg = &s->txn->rsp;
	struct buffer *ib = *in, *ob = *out;
	char *tail;

#if defined(USE_SLZ) || defined(USE_ZLIB)
	int ret;

	/* flush data here */

	if (end)
		ret = s->comp_algo->finish(s->comp_ctx, ob); /* end of data */
	else
		ret = s->comp_algo->flush(s->comp_ctx, ob); /* end of buffer */

	if (ret < 0)
		return -1; /* flush failed */

#endif /* USE_ZLIB */

	if (ob->i == 10) {
		/* No data were appended, let's drop the output buffer and
		 * keep the input buffer unchanged.
		 */
		return 0;
	}

	/* OK so at this stage, we have an output buffer <ob> looking like this :
	 *
	 *        <-- o --> <------ i ----->
	 *       +---------+---+------------+-----------+
	 *       |   out   | c |  comp_in   |   empty   |
	 *       +---------+---+------------+-----------+
	 *     data        p                           size
	 *
	 * <out> is the room reserved to copy ib->o. It starts at ob->data and
	 * has not yet been filled. <c> is the room reserved to write the chunk
	 * size (10 bytes). <comp_in> is the compressed equivalent of the data
	 * part of ib->i. <empty> is the amount of empty bytes at the end of
	 * the buffer, into which we may have to copy the remaining bytes from
	 * ib->i after the data (chunk size, trailers, ...).
	 */

	/* Write real size at the begining of the chunk, no need of wrapping.
	 * We write the chunk using a dynamic length and adjust ob->p and ob->i
	 * accordingly afterwards. That will move <out> away from <data>.
	 */
	left = 10 - http_emit_chunk_size(ob->p + 10, ob->i - 10);
	ob->p += left;
	ob->i -= left;

	/* Copy previous data from ib->o into ob->o */
	if (ib->o > 0) {
		left = bo_contig_data(ib);
		memcpy(ob->p - ob->o, bo_ptr(ib), left);
		if (ib->o - left) /* second part of the buffer */
			memcpy(ob->p - ob->o + left, ib->data, ib->o - left);
	}

	/* chunked encoding requires CRLF after data */
	tail = ob->p + ob->i;
	*tail++ = '\r';
	*tail++ = '\n';

	/* At the end of data, we must write the empty chunk 0<CRLF>,
	 * and terminate the trailers section with a last <CRLF>. If
	 * we're forwarding a chunked-encoded response, we'll have a
	 * trailers section after the empty chunk which needs to be
	 * forwarded and which will provide the last CRLF. Otherwise
	 * we write it ourselves.
	 */
	if (msg->msg_state >= HTTP_MSG_TRAILERS) {
		memcpy(tail, "0\r\n", 3);
		tail += 3;
		if (msg->msg_state >= HTTP_MSG_DONE) {
			memcpy(tail, "\r\n", 2);
			tail += 2;
		}
	}
	ob->i = tail - ob->p;

	to_forward = ob->i;

	/* update input rate */
	if (s->comp_ctx && s->comp_ctx->cur_lvl > 0) {
		update_freq_ctr(&global.comp_bps_in, msg->next);
		strm_fe(s)->fe_counters.comp_in += msg->next;
		s->be->be_counters.comp_in += msg->next;
	} else {
		strm_fe(s)->fe_counters.comp_byp += msg->next;
		s->be->be_counters.comp_byp += msg->next;
	}

	/* copy the remaining data in the tmp buffer. */
	b_adv(ib, msg->next);
	msg->next = 0;

	if (ib->i > 0) {
		left = bi_contig_data(ib);
		memcpy(ob->p + ob->i, bi_ptr(ib), left);
		ob->i += left;
		if (ib->i - left) {
			memcpy(ob->p + ob->i, ib->data, ib->i - left);
			ob->i += ib->i - left;
		}
	}

	/* swap the buffers */
	*in = ob;
	*out = ib;

	if (s->comp_ctx && s->comp_ctx->cur_lvl > 0) {
		update_freq_ctr(&global.comp_bps_out, to_forward);
		strm_fe(s)->fe_counters.comp_out += to_forward;
		s->be->be_counters.comp_out += to_forward;
	}

	/* forward the new chunk without remaining data */
	b_adv(ob, to_forward);

	return to_forward;
}

/*
 * Alloc the comp_ctx
 */
static inline int init_comp_ctx(struct comp_ctx **comp_ctx)
{
#ifdef USE_ZLIB
	z_stream *strm;

	if (global.maxzlibmem > 0 && (global.maxzlibmem - zlib_used_memory) < sizeof(struct comp_ctx))
		return -1;
#endif

	if (unlikely(pool_comp_ctx == NULL))
		pool_comp_ctx = create_pool("comp_ctx", sizeof(struct comp_ctx), MEM_F_SHARED);

	*comp_ctx = pool_alloc2(pool_comp_ctx);
	if (*comp_ctx == NULL)
		return -1;
#if defined(USE_SLZ)
	(*comp_ctx)->direct_ptr = NULL;
	(*comp_ctx)->direct_len = 0;
	(*comp_ctx)->queued = NULL;
#elif defined(USE_ZLIB)
	zlib_used_memory += sizeof(struct comp_ctx);

	strm = &(*comp_ctx)->strm;
	strm->zalloc = alloc_zlib;
	strm->zfree = free_zlib;
	strm->opaque = *comp_ctx;
#endif
	return 0;
}

/*
 * Dealloc the comp_ctx
 */
static inline int deinit_comp_ctx(struct comp_ctx **comp_ctx)
{
	if (!*comp_ctx)
		return 0;

	pool_free2(pool_comp_ctx, *comp_ctx);
	*comp_ctx = NULL;

#ifdef USE_ZLIB
	zlib_used_memory -= sizeof(struct comp_ctx);
#endif
	return 0;
}


/****************************
 **** Identity algorithm ****
 ****************************/

/*
 * Init the identity algorithm
 */
static int identity_init(struct comp_ctx **comp_ctx, int level)
{
	return 0;
}

/*
 * Process data
 *   Return size of consumed data or -1 on error
 */
static int identity_add_data(struct comp_ctx *comp_ctx, const char *in_data, int in_len, struct buffer *out)
{
	char *out_data = bi_end(out);
	int out_len = out->size - buffer_len(out);

	if (out_len < in_len)
		return -1;

	memcpy(out_data, in_data, in_len);

	out->i += in_len;

	return in_len;
}

static int identity_flush(struct comp_ctx *comp_ctx, struct buffer *out)
{
	return 0;
}

static int identity_finish(struct comp_ctx *comp_ctx, struct buffer *out)
{
	return 0;
}

/*
 * Deinit the algorithm
 */
static int identity_end(struct comp_ctx **comp_ctx)
{
	return 0;
}


#ifdef USE_SLZ

/* SLZ's gzip format (RFC1952). Returns < 0 on error. */
static int rfc1952_init(struct comp_ctx **comp_ctx, int level)
{
	if (init_comp_ctx(comp_ctx) < 0)
		return -1;

	(*comp_ctx)->cur_lvl = !!level;
	return slz_rfc1952_init(&(*comp_ctx)->strm, !!level);
}

/* SLZ's raw deflate format (RFC1951). Returns < 0 on error. */
static int rfc1951_init(struct comp_ctx **comp_ctx, int level)
{
	if (init_comp_ctx(comp_ctx) < 0)
		return -1;

	(*comp_ctx)->cur_lvl = !!level;
	return slz_rfc1951_init(&(*comp_ctx)->strm, !!level);
}

/* SLZ's zlib format (RFC1950). Returns < 0 on error. */
static int rfc1950_init(struct comp_ctx **comp_ctx, int level)
{
	if (init_comp_ctx(comp_ctx) < 0)
		return -1;

	(*comp_ctx)->cur_lvl = !!level;
	return slz_rfc1950_init(&(*comp_ctx)->strm, !!level);
}

/* Return the size of consumed data or -1. The output buffer is unused at this
 * point, we only keep a reference to the input data or a copy of them if the
 * reference is already used.
 */
static int rfc195x_add_data(struct comp_ctx *comp_ctx, const char *in_data, int in_len, struct buffer *out)
{
	static struct buffer *tmpbuf = &buf_empty;

	if (in_len <= 0)
		return 0;

	if (comp_ctx->direct_ptr && !comp_ctx->queued) {
		/* data already being pointed to, we're in front of fragmented
		 * data and need a buffer now. We reuse the same buffer, as it's
		 * not used out of the scope of a series of add_data()*, end().
		 */
		if (unlikely(!tmpbuf->size)) {
			/* this is the first time we need the compression buffer */
			if (b_alloc(&tmpbuf) == NULL)
				return -1; /* no memory */
		}
		b_reset(tmpbuf);
		memcpy(bi_end(tmpbuf), comp_ctx->direct_ptr, comp_ctx->direct_len);
		tmpbuf->i += comp_ctx->direct_len;
		comp_ctx->direct_ptr = NULL;
		comp_ctx->direct_len = 0;
		comp_ctx->queued = tmpbuf;
		/* fall through buffer copy */
	}

	if (comp_ctx->queued) {
		/* data already pending */
		memcpy(bi_end(comp_ctx->queued), in_data, in_len);
		comp_ctx->queued->i += in_len;
		return in_len;
	}

	comp_ctx->direct_ptr = in_data;
	comp_ctx->direct_len = in_len;
	return in_len;
}

/* Compresses the data accumulated using add_data(), and optionally sends the
 * format-specific trailer if <finish> is non-null. <out> is expected to have a
 * large enough free non-wrapping space as verified by http_comp_buffer_init().
 * The number of bytes emitted is reported.
 */
static int rfc195x_flush_or_finish(struct comp_ctx *comp_ctx, struct buffer *out, int finish)
{
	struct slz_stream *strm = &comp_ctx->strm;
	const char *in_ptr;
	int in_len;
	int out_len;

	in_ptr = comp_ctx->direct_ptr;
	in_len = comp_ctx->direct_len;

	if (comp_ctx->queued) {
		in_ptr = comp_ctx->queued->p;
		in_len = comp_ctx->queued->i;
	}

	out_len = out->i;

	if (in_ptr)
		out->i += slz_encode(strm, bi_end(out), in_ptr, in_len, !finish);

	if (finish)
		out->i += slz_finish(strm, bi_end(out));

	out_len = out->i - out_len;

	/* very important, we must wipe the data we've just flushed */
	comp_ctx->direct_len = 0;
	comp_ctx->direct_ptr = NULL;
	comp_ctx->queued     = NULL;

	/* Verify compression rate limiting and CPU usage */
	if ((global.comp_rate_lim > 0 && (read_freq_ctr(&global.comp_bps_out) > global.comp_rate_lim)) ||    /* rate */
	   (idle_pct < compress_min_idle)) {                                                                 /* idle */
		if (comp_ctx->cur_lvl > 0)
			strm->level = --comp_ctx->cur_lvl;
	}
	else if (comp_ctx->cur_lvl < global.tune.comp_maxlevel && comp_ctx->cur_lvl < 1) {
		strm->level = ++comp_ctx->cur_lvl;
	}

	/* and that's all */
	return out_len;
}

static int rfc195x_flush(struct comp_ctx *comp_ctx, struct buffer *out)
{
	return rfc195x_flush_or_finish(comp_ctx, out, 0);
}

static int rfc195x_finish(struct comp_ctx *comp_ctx, struct buffer *out)
{
	return rfc195x_flush_or_finish(comp_ctx, out, 1);
}

/* we just need to free the comp_ctx here, nothing was allocated */
static int rfc195x_end(struct comp_ctx **comp_ctx)
{
	deinit_comp_ctx(comp_ctx);
	return 0;
}

#elif defined(USE_ZLIB)  /* ! USE_SLZ */

/*
 * This is a tricky allocation function using the zlib.
 * This is based on the allocation order in deflateInit2.
 */
static void *alloc_zlib(void *opaque, unsigned int items, unsigned int size)
{
	struct comp_ctx *ctx = opaque;
	static char round = 0; /* order in deflateInit2 */
	void *buf = NULL;
	struct pool_head *pool = NULL;

	if (global.maxzlibmem > 0 && (global.maxzlibmem - zlib_used_memory) < (long)(items * size))
		goto end;

	switch (round) {
		case 0:
			if (zlib_pool_deflate_state == NULL)
				zlib_pool_deflate_state = create_pool("zlib_state", size * items, MEM_F_SHARED);
			pool = zlib_pool_deflate_state;
			ctx->zlib_deflate_state = buf = pool_alloc2(pool);
		break;

		case 1:
			if (zlib_pool_window == NULL)
				zlib_pool_window = create_pool("zlib_window", size * items, MEM_F_SHARED);
			pool = zlib_pool_window;
			ctx->zlib_window = buf = pool_alloc2(pool);
		break;

		case 2:
			if (zlib_pool_prev == NULL)
				zlib_pool_prev = create_pool("zlib_prev", size * items, MEM_F_SHARED);
			pool = zlib_pool_prev;
			ctx->zlib_prev = buf = pool_alloc2(pool);
		break;

		case 3:
			if (zlib_pool_head == NULL)
				zlib_pool_head = create_pool("zlib_head", size * items, MEM_F_SHARED);
			pool = zlib_pool_head;
			ctx->zlib_head = buf = pool_alloc2(pool);
		break;

		case 4:
			if (zlib_pool_pending_buf == NULL)
				zlib_pool_pending_buf = create_pool("zlib_pending_buf", size * items, MEM_F_SHARED);
			pool = zlib_pool_pending_buf;
			ctx->zlib_pending_buf = buf = pool_alloc2(pool);
		break;
	}
	if (buf != NULL)
		zlib_used_memory += pool->size;

end:

	/* deflateInit2() first allocates and checks the deflate_state, then if
	 * it succeeds, it allocates all other 4 areas at ones and checks them
	 * at the end. So we want to correctly count the rounds depending on when
	 * zlib is supposed to abort.
	 */
	if (buf || round)
		round = (round + 1) % 5;
	return buf;
}

static void free_zlib(void *opaque, void *ptr)
{
	struct comp_ctx *ctx = opaque;
	struct pool_head *pool = NULL;

	if (ptr == ctx->zlib_window)
		pool = zlib_pool_window;
	else if (ptr == ctx->zlib_deflate_state)
		pool = zlib_pool_deflate_state;
	else if (ptr == ctx->zlib_prev)
		pool = zlib_pool_prev;
	else if (ptr == ctx->zlib_head)
		pool = zlib_pool_head;
	else if (ptr == ctx->zlib_pending_buf)
		pool = zlib_pool_pending_buf;

	pool_free2(pool, ptr);
	zlib_used_memory -= pool->size;
}

/**************************
****  gzip algorithm   ****
***************************/
static int gzip_init(struct comp_ctx **comp_ctx, int level)
{
	z_stream *strm;

	if (init_comp_ctx(comp_ctx) < 0)
		return -1;

	strm = &(*comp_ctx)->strm;

	if (deflateInit2(strm, level, Z_DEFLATED, global.tune.zlibwindowsize + 16, global.tune.zlibmemlevel, Z_DEFAULT_STRATEGY) != Z_OK) {
		deinit_comp_ctx(comp_ctx);
		return -1;
	}

	(*comp_ctx)->cur_lvl = level;

	return 0;
}

/* Raw deflate algorithm */
static int raw_def_init(struct comp_ctx **comp_ctx, int level)
{
	z_stream *strm;

	if (init_comp_ctx(comp_ctx) < 0)
		return -1;

	strm = &(*comp_ctx)->strm;

	if (deflateInit2(strm, level, Z_DEFLATED, -global.tune.zlibwindowsize, global.tune.zlibmemlevel, Z_DEFAULT_STRATEGY) != Z_OK) {
		deinit_comp_ctx(comp_ctx);
		return -1;
	}

	(*comp_ctx)->cur_lvl = level;
	return 0;
}

/**************************
**** Deflate algorithm ****
***************************/

static int deflate_init(struct comp_ctx **comp_ctx, int level)
{
	z_stream *strm;

	if (init_comp_ctx(comp_ctx) < 0)
		return -1;

	strm = &(*comp_ctx)->strm;

	if (deflateInit2(strm, level, Z_DEFLATED, global.tune.zlibwindowsize, global.tune.zlibmemlevel, Z_DEFAULT_STRATEGY) != Z_OK) {
		deinit_comp_ctx(comp_ctx);
		return -1;
	}

	(*comp_ctx)->cur_lvl = level;

	return 0;
}

/* Return the size of consumed data or -1 */
static int deflate_add_data(struct comp_ctx *comp_ctx, const char *in_data, int in_len, struct buffer *out)
{
	int ret;
	z_stream *strm = &comp_ctx->strm;
	char *out_data = bi_end(out);
	int out_len = out->size - buffer_len(out);

	if (in_len <= 0)
		return 0;


	if (out_len <= 0)
		return -1;

	strm->next_in = (unsigned char *)in_data;
	strm->avail_in = in_len;
	strm->next_out = (unsigned char *)out_data;
	strm->avail_out = out_len;

	ret = deflate(strm, Z_NO_FLUSH);
	if (ret != Z_OK)
		return -1;

	/* deflate update the available data out */
	out->i += out_len - strm->avail_out;

	return in_len - strm->avail_in;
}

static int deflate_flush_or_finish(struct comp_ctx *comp_ctx, struct buffer *out, int flag)
{
	int ret;
	int out_len = 0;
	z_stream *strm = &comp_ctx->strm;

	strm->next_out = (unsigned char *)bi_end(out);
	strm->avail_out = out->size - buffer_len(out);

	ret = deflate(strm, flag);
	if (ret != Z_OK && ret != Z_STREAM_END)
		return -1;

	out_len = (out->size - buffer_len(out)) - strm->avail_out;
	out->i += out_len;

	/* compression limit */
	if ((global.comp_rate_lim > 0 && (read_freq_ctr(&global.comp_bps_out) > global.comp_rate_lim)) ||    /* rate */
	   (idle_pct < compress_min_idle)) {                                                                     /* idle */
		/* decrease level */
		if (comp_ctx->cur_lvl > 0) {
			comp_ctx->cur_lvl--;
			deflateParams(&comp_ctx->strm, comp_ctx->cur_lvl, Z_DEFAULT_STRATEGY);
		}

	} else if (comp_ctx->cur_lvl < global.tune.comp_maxlevel) {
		/* increase level */
		comp_ctx->cur_lvl++ ;
		deflateParams(&comp_ctx->strm, comp_ctx->cur_lvl, Z_DEFAULT_STRATEGY);
	}

	return out_len;
}

static int deflate_flush(struct comp_ctx *comp_ctx, struct buffer *out)
{
	return deflate_flush_or_finish(comp_ctx, out, Z_SYNC_FLUSH);
}

static int deflate_finish(struct comp_ctx *comp_ctx, struct buffer *out)
{
	return deflate_flush_or_finish(comp_ctx, out, Z_FINISH);
}

static int deflate_end(struct comp_ctx **comp_ctx)
{
	z_stream *strm = &(*comp_ctx)->strm;
	int ret;

	ret = deflateEnd(strm);

	deinit_comp_ctx(comp_ctx);

	return ret;
}

#endif /* USE_ZLIB */

/* boolean, returns true if compression is used (either gzip or deflate) in the response */
static int
smp_fetch_res_comp(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->type = SMP_T_BOOL;
	smp->data.uint = (smp->strm->comp_algo != NULL);
	return 1;
}

/* string, returns algo */
static int
smp_fetch_res_comp_algo(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!smp->strm->comp_algo)
		return 0;

	smp->type = SMP_T_STR;
	smp->flags = SMP_F_CONST;
	smp->data.str.str = smp->strm->comp_algo->cfg_name;
	smp->data.str.len = smp->strm->comp_algo->cfg_name_len;
	return 1;
}

/* Note: must not be declared <const> as its list will be overwritten */
static struct acl_kw_list acl_kws = {ILH, {
	{ /* END */ },
}};

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
	{ "res.comp",             smp_fetch_res_comp,      0,                NULL,    SMP_T_BOOL, SMP_USE_HRSHP },
	{ "res.comp_algo",        smp_fetch_res_comp_algo, 0,                NULL,    SMP_T_STR, SMP_USE_HRSHP },
	{ /* END */ },
}};

__attribute__((constructor))
static void __comp_fetch_init(void)
{
#ifdef USE_SLZ
	slz_make_crc_table();
	slz_prepare_dist_table();
#endif
	acl_register_keywords(&acl_kws);
	sample_register_fetches(&sample_fetch_keywords);
}
