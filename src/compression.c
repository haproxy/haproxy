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

#include <common/cfgparse.h>
#include <common/compat.h>
#include <common/hathreads.h>
#include <common/initcall.h>
#include <common/memory.h>

#include <types/global.h>
#include <types/compression.h>

#include <proto/acl.h>
#include <proto/compression.h>
#include <proto/freq_ctr.h>
#include <proto/stream.h>


#if defined(USE_ZLIB)
__decl_spinlock(comp_pool_lock);
#endif

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

static int global_tune_zlibmemlevel = 8;            /* zlib memlevel */
static int global_tune_zlibwindowsize = MAX_WBITS;  /* zlib window size */

#endif

unsigned int compress_min_idle = 0;

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

	comp_type = calloc(1, sizeof(*comp_type));
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
			comp_algo = calloc(1, sizeof(*comp_algo));
			memmove(comp_algo, &comp_algos[i], sizeof(struct comp_algo));
			comp_algo->next = comp->algos;
			comp->algos = comp_algo;
			return 0;
		}
	}
	return -1;
}

#if defined(USE_ZLIB) || defined(USE_SLZ)
DECLARE_STATIC_POOL(pool_comp_ctx, "comp_ctx", sizeof(struct comp_ctx));

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

	*comp_ctx = pool_alloc(pool_comp_ctx);
	if (*comp_ctx == NULL)
		return -1;
#if defined(USE_SLZ)
	(*comp_ctx)->direct_ptr = NULL;
	(*comp_ctx)->direct_len = 0;
	(*comp_ctx)->queued = BUF_NULL;
#elif defined(USE_ZLIB)
	_HA_ATOMIC_ADD(&zlib_used_memory, sizeof(struct comp_ctx));
	__ha_barrier_atomic_store();

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

	pool_free(pool_comp_ctx, *comp_ctx);
	*comp_ctx = NULL;

#ifdef USE_ZLIB
	_HA_ATOMIC_SUB(&zlib_used_memory, sizeof(struct comp_ctx));
	__ha_barrier_atomic_store();
#endif
	return 0;
}
#endif


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
	char *out_data = b_tail(out);
	int out_len = b_room(out);

	if (out_len < in_len)
		return -1;

	memcpy(out_data, in_data, in_len);

	b_add(out, in_len);

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
	static THREAD_LOCAL struct buffer tmpbuf = BUF_NULL;

	if (in_len <= 0)
		return 0;

	if (comp_ctx->direct_ptr && b_is_null(&comp_ctx->queued)) {
		/* data already being pointed to, we're in front of fragmented
		 * data and need a buffer now. We reuse the same buffer, as it's
		 * not used out of the scope of a series of add_data()*, end().
		 */
		if (unlikely(!tmpbuf.size)) {
			/* this is the first time we need the compression buffer */
			if (b_alloc(&tmpbuf) == NULL)
				return -1; /* no memory */
		}
		b_reset(&tmpbuf);
		memcpy(b_tail(&tmpbuf), comp_ctx->direct_ptr, comp_ctx->direct_len);
		b_add(&tmpbuf, comp_ctx->direct_len);
		comp_ctx->direct_ptr = NULL;
		comp_ctx->direct_len = 0;
		comp_ctx->queued = tmpbuf;
		/* fall through buffer copy */
	}

	if (!b_is_null(&comp_ctx->queued)) {
		/* data already pending */
		memcpy(b_tail(&comp_ctx->queued), in_data, in_len);
		b_add(&comp_ctx->queued, in_len);
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

	if (!b_is_null(&comp_ctx->queued)) {
		in_ptr = b_head(&comp_ctx->queued);
		in_len = b_data(&comp_ctx->queued);
	}

	out_len = b_data(out);

	if (in_ptr)
		b_add(out, slz_encode(strm, b_tail(out), in_ptr, in_len, !finish));

	if (finish)
		b_add(out, slz_finish(strm, b_tail(out)));

	out_len = b_data(out) - out_len;

	/* very important, we must wipe the data we've just flushed */
	comp_ctx->direct_len = 0;
	comp_ctx->direct_ptr = NULL;
	comp_ctx->queued     = BUF_NULL;

	/* Verify compression rate limiting and CPU usage */
	if ((global.comp_rate_lim > 0 && (read_freq_ctr(&global.comp_bps_out) > global.comp_rate_lim)) ||    /* rate */
	   (ti->idle_pct < compress_min_idle)) {                                                                 /* idle */
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
	static THREAD_LOCAL char round = 0; /* order in deflateInit2 */
	void *buf = NULL;
	struct pool_head *pool = NULL;

	if (global.maxzlibmem > 0 && (global.maxzlibmem - zlib_used_memory) < (long)(items * size))
		goto end;

	switch (round) {
		case 0:
			if (zlib_pool_deflate_state == NULL) {
				HA_SPIN_LOCK(COMP_POOL_LOCK, &comp_pool_lock);
				if (zlib_pool_deflate_state == NULL)
					zlib_pool_deflate_state = create_pool("zlib_state", size * items, MEM_F_SHARED);
				HA_SPIN_UNLOCK(COMP_POOL_LOCK, &comp_pool_lock);
			}
			pool = zlib_pool_deflate_state;
			ctx->zlib_deflate_state = buf = pool_alloc(pool);
		break;

		case 1:
			if (zlib_pool_window == NULL) {
				HA_SPIN_LOCK(COMP_POOL_LOCK, &comp_pool_lock);
				if (zlib_pool_window == NULL)
					zlib_pool_window = create_pool("zlib_window", size * items, MEM_F_SHARED);
				HA_SPIN_UNLOCK(COMP_POOL_LOCK, &comp_pool_lock);
			}
			pool = zlib_pool_window;
			ctx->zlib_window = buf = pool_alloc(pool);
		break;

		case 2:
			if (zlib_pool_prev == NULL) {
				HA_SPIN_LOCK(COMP_POOL_LOCK, &comp_pool_lock);
				if (zlib_pool_prev == NULL)
					zlib_pool_prev = create_pool("zlib_prev", size * items, MEM_F_SHARED);
				HA_SPIN_UNLOCK(COMP_POOL_LOCK, &comp_pool_lock);
			}
			pool = zlib_pool_prev;
			ctx->zlib_prev = buf = pool_alloc(pool);
		break;

		case 3:
			if (zlib_pool_head == NULL) {
				HA_SPIN_LOCK(COMP_POOL_LOCK, &comp_pool_lock);
				if (zlib_pool_head == NULL)
					zlib_pool_head = create_pool("zlib_head", size * items, MEM_F_SHARED);
				HA_SPIN_UNLOCK(COMP_POOL_LOCK, &comp_pool_lock);
			}
			pool = zlib_pool_head;
			ctx->zlib_head = buf = pool_alloc(pool);
		break;

		case 4:
			if (zlib_pool_pending_buf == NULL) {
				HA_SPIN_LOCK(COMP_POOL_LOCK, &comp_pool_lock);
				if (zlib_pool_pending_buf == NULL)
					zlib_pool_pending_buf = create_pool("zlib_pending_buf", size * items, MEM_F_SHARED);
				HA_SPIN_UNLOCK(COMP_POOL_LOCK, &comp_pool_lock);
			}
			pool = zlib_pool_pending_buf;
			ctx->zlib_pending_buf = buf = pool_alloc(pool);
		break;
	}
	if (buf != NULL) {
		_HA_ATOMIC_ADD(&zlib_used_memory, pool->size);
		__ha_barrier_atomic_store();
	}

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

	pool_free(pool, ptr);
	_HA_ATOMIC_SUB(&zlib_used_memory, pool->size);
	__ha_barrier_atomic_store();
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

	if (deflateInit2(strm, level, Z_DEFLATED, global_tune_zlibwindowsize + 16, global_tune_zlibmemlevel, Z_DEFAULT_STRATEGY) != Z_OK) {
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

	if (deflateInit2(strm, level, Z_DEFLATED, -global_tune_zlibwindowsize, global_tune_zlibmemlevel, Z_DEFAULT_STRATEGY) != Z_OK) {
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

	if (deflateInit2(strm, level, Z_DEFLATED, global_tune_zlibwindowsize, global_tune_zlibmemlevel, Z_DEFAULT_STRATEGY) != Z_OK) {
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
	char *out_data = b_tail(out);
	int out_len = b_room(out);

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
	b_add(out, out_len - strm->avail_out);

	return in_len - strm->avail_in;
}

static int deflate_flush_or_finish(struct comp_ctx *comp_ctx, struct buffer *out, int flag)
{
	int ret;
	int out_len = 0;
	z_stream *strm = &comp_ctx->strm;

	strm->next_in = NULL;
	strm->avail_in = 0;
	strm->next_out = (unsigned char *)b_tail(out);
	strm->avail_out = b_room(out);

	ret = deflate(strm, flag);
	if (ret != Z_OK && ret != Z_STREAM_END)
		return -1;

	out_len = b_room(out) - strm->avail_out;
	b_add(out, out_len);

	/* compression limit */
	if ((global.comp_rate_lim > 0 && (read_freq_ctr(&global.comp_bps_out) > global.comp_rate_lim)) ||    /* rate */
	   (ti->idle_pct < compress_min_idle)) {                                                                     /* idle */
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

/* config parser for global "tune.zlibmemlevel" */
static int zlib_parse_global_memlevel(char **args, int section_type, struct proxy *curpx,
                                      struct proxy *defpx, const char *file, int line,
                                      char **err)
{
        if (too_many_args(1, args, err, NULL))
                return -1;

        if (*(args[1]) == 0) {
                memprintf(err, "'%s' expects a numeric value between 1 and 9.", args[0]);
                return -1;
        }

	global_tune_zlibmemlevel = atoi(args[1]);
	if (global_tune_zlibmemlevel < 1 || global_tune_zlibmemlevel > 9) {
                memprintf(err, "'%s' expects a numeric value between 1 and 9.", args[0]);
                return -1;
	}
        return 0;
}


/* config parser for global "tune.zlibwindowsize" */
static int zlib_parse_global_windowsize(char **args, int section_type, struct proxy *curpx,
                                        struct proxy *defpx, const char *file, int line,
                                        char **err)
{
        if (too_many_args(1, args, err, NULL))
                return -1;

        if (*(args[1]) == 0) {
                memprintf(err, "'%s' expects a numeric value between 8 and 15.", args[0]);
                return -1;
        }

	global_tune_zlibwindowsize = atoi(args[1]);
	if (global_tune_zlibwindowsize < 8 || global_tune_zlibwindowsize > 15) {
                memprintf(err, "'%s' expects a numeric value between 8 and 15.", args[0]);
                return -1;
	}
        return 0;
}

#endif /* USE_ZLIB */


/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
#ifdef USE_ZLIB
	{ CFG_GLOBAL, "tune.zlib.memlevel",   zlib_parse_global_memlevel },
	{ CFG_GLOBAL, "tune.zlib.windowsize", zlib_parse_global_windowsize },
#endif
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

__attribute__((constructor))
static void __comp_fetch_init(void)
{
#ifdef USE_SLZ
	slz_make_crc_table();
	slz_prepare_dist_table();
#endif

#if defined(USE_ZLIB) && defined(DEFAULT_MAXZLIBMEM)
	global.maxzlibmem = DEFAULT_MAXZLIBMEM * 1024U * 1024U;
#endif
}

static void comp_register_build_opts(void)
{
	char *ptr = NULL;
	int i;

#ifdef USE_ZLIB
	memprintf(&ptr, "Built with zlib version : " ZLIB_VERSION);
	memprintf(&ptr, "%s\nRunning on zlib version : %s", ptr, zlibVersion());
#elif defined(USE_SLZ)
	memprintf(&ptr, "Built with libslz for stateless compression.");
#else
	memprintf(&ptr, "Built without compression support (neither USE_ZLIB nor USE_SLZ are set).");
#endif
	memprintf(&ptr, "%s\nCompression algorithms supported :", ptr);

	for (i = 0; comp_algos[i].cfg_name; i++)
		memprintf(&ptr, "%s%s %s(\"%s\")", ptr, (i == 0 ? "" : ","), comp_algos[i].cfg_name, comp_algos[i].ua_name);

	if (i == 0)
		memprintf(&ptr, "%s none", ptr);

	hap_register_build_opts(ptr, 1);
}

INITCALL0(STG_REGISTER, comp_register_build_opts);
