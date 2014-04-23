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

#ifdef USE_ZLIB
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


const struct comp_algo comp_algos[] =
{
	{ "identity", 8, identity_init, identity_add_data, identity_flush, identity_reset, identity_end },
#ifdef USE_ZLIB
	{ "deflate",  7, deflate_init,  deflate_add_data,  deflate_flush,  deflate_reset,  deflate_end },
	{ "gzip",     4, gzip_init,     deflate_add_data,  deflate_flush,  deflate_reset,  deflate_end },
#endif /* USE_ZLIB */
	{ NULL,       0, NULL ,         NULL,              NULL,           NULL,           NULL }
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

	for (i = 0; comp_algos[i].name; i++) {
		if (!strcmp(algo, comp_algos[i].name)) {
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
 * bytes written. Appends <add_crlf> additional CRLF after the first one. Chunk
 * sizes are truncated to 6 hex digits (16 MB) and padded left. The caller is
 * responsible for ensuring there is enough room left in the output buffer for
 * the string (8 bytes * add_crlf*2).
 */
int http_emit_chunk_size(char *out, unsigned int chksz, int add_crlf)
{
	int shift;
	int pos = 0;

	for (shift = 20; shift >= 0; shift -= 4)
		out[pos++] = hextab[(chksz >> shift) & 0xF];

	do {
		out[pos++] = '\r';
		out[pos++] = '\n';
	} while (--add_crlf >= 0);

	return pos;
}

/*
 * Init HTTP compression
 */
int http_compression_buffer_init(struct session *s, struct buffer *in, struct buffer *out)
{
	int left;

	/* not enough space */
	if (in->size - buffer_len(in) < 40)
	    return -1;

	/* We start by copying the current buffer's pending outgoing data into
	 * a new temporary buffer that we initialize with a new empty chunk.
	 */

	out->size = global.tune.bufsize;
	out->i = 0;
	out->o = 0;
	out->p = out->data;

	if (in->o > 0) {
		left = in->o - bo_contig_data(in);
		memcpy(out->data, bo_ptr(in), bo_contig_data(in));
		out->p += bo_contig_data(in);
		if (left > 0) { /* second part of the buffer */
			memcpy(out->p, in->data, left);
			out->p += left;
		}
		out->o = in->o;
	}
	out->i += http_emit_chunk_size(out->p, 0, 0);

	return 0;
}

/*
 * Add data to compress
 */
int http_compression_buffer_add_data(struct session *s, struct buffer *in, struct buffer *out)
{
	struct http_msg *msg = &s->txn.rsp;
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
int http_compression_buffer_end(struct session *s, struct buffer **in, struct buffer **out, int end)
{
	int to_forward;
	int left;
	struct http_msg *msg = &s->txn.rsp;
	struct buffer *ib = *in, *ob = *out;

#ifdef USE_ZLIB
	int ret;

	/* flush data here */

	if (end)
		ret = s->comp_algo->flush(s->comp_ctx, ob, Z_FINISH); /* end of data */
	else
		ret = s->comp_algo->flush(s->comp_ctx, ob, Z_SYNC_FLUSH); /* end of buffer */

	if (ret < 0)
		return -1; /* flush failed */

#endif /* USE_ZLIB */

	if (ob->i > 8) {
		/* more than a chunk size => some data were emitted */
		char *tail = ob->p + ob->i;

		/* write real size at the begining of the chunk, no need of wrapping */
		http_emit_chunk_size(ob->p, ob->i - 8, 0);

		/* chunked encoding requires CRLF after data */
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
	} else {
		/* no data were sent, cancel the chunk size */
		ob->i = 0;
	}

	to_forward = ob->i;

	/* update input rate */
	if (s->comp_ctx && s->comp_ctx->cur_lvl > 0) {
		update_freq_ctr(&global.comp_bps_in, msg->next);
		s->fe->fe_counters.comp_in += msg->next;
		s->be->be_counters.comp_in += msg->next;
	} else {
		s->fe->fe_counters.comp_byp += msg->next;
		s->be->be_counters.comp_byp += msg->next;
	}

	/* copy the remaining data in the tmp buffer. */
	b_adv(ib, msg->next);
	msg->next = 0;

	if (ib->i > 0) {
		left = ib->i - bi_contig_data(ib);
		memcpy(bi_end(ob), bi_ptr(ib), bi_contig_data(ib));
		ob->i += bi_contig_data(ib);
		if (left > 0) {
			memcpy(bi_end(ob), ib->data, left);
			ob->i += left;
		}
	}

	/* swap the buffers */
	*in = ob;
	*out = ib;

	if (s->comp_ctx && s->comp_ctx->cur_lvl > 0) {
		update_freq_ctr(&global.comp_bps_out, to_forward);
		s->fe->fe_counters.comp_out += to_forward;
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
#ifdef USE_ZLIB
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
int identity_init(struct comp_ctx **comp_ctx, int level)
{
	return 0;
}

/*
 * Process data
 *   Return size of consumed data or -1 on error
 */
int identity_add_data(struct comp_ctx *comp_ctx, const char *in_data, int in_len, struct buffer *out)
{
	char *out_data = bi_end(out);
	int out_len = out->size - buffer_len(out);

	if (out_len < in_len)
		return -1;

	memcpy(out_data, in_data, in_len);

	out->i += in_len;

	return in_len;
}

int identity_flush(struct comp_ctx *comp_ctx, struct buffer *out, int flag)
{
	return 0;
}

int identity_reset(struct comp_ctx *comp_ctx)
{
	return 0;
}

/*
 * Deinit the algorithm
 */
int identity_end(struct comp_ctx **comp_ctx)
{
	return 0;
}


#ifdef USE_ZLIB
/*
 * This is a tricky allocation function using the zlib.
 * This is based on the allocation order in deflateInit2.
 */
static void *alloc_zlib(void *opaque, unsigned int items, unsigned int size)
{
	struct comp_ctx *ctx = opaque;
	static char round = 0; /* order in deflateInit2 */
	void *buf = NULL;

	if (global.maxzlibmem > 0 && (global.maxzlibmem - zlib_used_memory) < (long)(items * size))
		goto end;

	switch (round) {
		case 0:
			if (zlib_pool_deflate_state == NULL)
				zlib_pool_deflate_state = create_pool("zlib_state", size * items, MEM_F_SHARED);
			ctx->zlib_deflate_state = buf = pool_alloc2(zlib_pool_deflate_state);
		break;

		case 1:
			if (zlib_pool_window == NULL)
				zlib_pool_window = create_pool("zlib_window", size * items, MEM_F_SHARED);
			ctx->zlib_window = buf = pool_alloc2(zlib_pool_window);
		break;

		case 2:
			if (zlib_pool_prev == NULL)
				zlib_pool_prev = create_pool("zlib_prev", size * items, MEM_F_SHARED);
			ctx->zlib_prev = buf = pool_alloc2(zlib_pool_prev);
		break;

		case 3:
			if (zlib_pool_head == NULL)
				zlib_pool_head = create_pool("zlib_head", size * items, MEM_F_SHARED);
			ctx->zlib_head = buf = pool_alloc2(zlib_pool_head);
		break;

		case 4:
			if (zlib_pool_pending_buf == NULL)
				zlib_pool_pending_buf = create_pool("zlib_pending_buf", size * items, MEM_F_SHARED);
			ctx->zlib_pending_buf = buf = pool_alloc2(zlib_pool_pending_buf);
		break;
	}
	if (buf != NULL)
		zlib_used_memory += items * size;

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
int gzip_init(struct comp_ctx **comp_ctx, int level)
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
/**************************
**** Deflate algorithm ****
***************************/

int deflate_init(struct comp_ctx **comp_ctx, int level)
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
int deflate_add_data(struct comp_ctx *comp_ctx, const char *in_data, int in_len, struct buffer *out)
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

int deflate_flush(struct comp_ctx *comp_ctx, struct buffer *out, int flag)
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

int deflate_reset(struct comp_ctx *comp_ctx)
{
	z_stream *strm = &comp_ctx->strm;

	if (deflateReset(strm) == Z_OK)
		return 0;
	return -1;
}

int deflate_end(struct comp_ctx **comp_ctx)
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
smp_fetch_res_comp(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                 const struct arg *args, struct sample *smp, const char *kw)
{
	smp->type = SMP_T_BOOL;
	smp->data.uint = (l4->comp_algo != NULL);
	return 1;
}

/* string, returns algo */
static int
smp_fetch_res_comp_algo(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                 const struct arg *args, struct sample *smp, const char *kw)
{
	if (!l4->comp_algo)
		return 0;

	smp->type = SMP_T_STR;
	smp->flags = SMP_F_CONST;
	smp->data.str.str = l4->comp_algo->name;
	smp->data.str.len = l4->comp_algo->name_len;
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
	acl_register_keywords(&acl_kws);
	sample_register_fetches(&sample_fetch_keywords);
}
