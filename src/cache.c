/*
 * Cache management
 *
 * Copyright 2017 HAProxy Technologies
 * William Lallemand <wlallemand@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <eb32tree.h>
#include <import/sha1.h>

#include <types/action.h>
#include <types/cli.h>
#include <types/filters.h>
#include <types/proxy.h>
#include <types/shctx.h>

#include <proto/channel.h>
#include <proto/cli.h>
#include <proto/proxy.h>
#include <proto/http_htx.h>
#include <proto/filters.h>
#include <proto/http_rules.h>
#include <proto/http_ana.h>
#include <proto/log.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/shctx.h>


#include <common/cfgparse.h>
#include <common/hash.h>
#include <common/htx.h>
#include <common/initcall.h>

#define CACHE_FLT_F_IMPLICIT_DECL  0x00000001 /* The cache filtre was implicitly declared (ie without
					       * the filter keyword) */

const char *cache_store_flt_id = "cache store filter";

extern struct applet http_cache_applet;

struct flt_ops cache_ops;

struct cache {
	struct list list;        /* cache linked list */
	struct eb_root entries;  /* head of cache entries based on keys */
	unsigned int maxage;     /* max-age */
	unsigned int maxblocks;
	unsigned int maxobjsz;   /* max-object-size (in bytes) */
	char id[33];             /* cache name */
};

/* cache config for filters */
struct cache_flt_conf {
	union {
		struct cache *cache; /* cache used by the filter */
		char *name;          /* cache name used during conf parsing */
	} c;
	unsigned int flags;   /* CACHE_FLT_F_* */
};

/*
 * cache ctx for filters
 */
struct cache_st {
	struct shared_block *first_block;
};

struct cache_entry {
	unsigned int latest_validation;     /* latest validation date */
	unsigned int expire;      /* expiration date */
	unsigned int age;         /* Origin server "Age" header value */

	struct eb32_node eb;     /* ebtree node used to hold the cache object */
	char hash[20];
	unsigned char data[0];
};

#define CACHE_BLOCKSIZE 1024
#define CACHE_ENTRY_MAX_AGE 2147483648U

static struct list caches = LIST_HEAD_INIT(caches);
static struct list caches_config = LIST_HEAD_INIT(caches_config); /* cache config to init */
static struct cache *tmp_cache_config = NULL;

DECLARE_STATIC_POOL(pool_head_cache_st, "cache_st", sizeof(struct cache_st));

struct cache_entry *entry_exist(struct cache *cache, char *hash)
{
	struct eb32_node *node;
	struct cache_entry *entry;

	node = eb32_lookup(&cache->entries, (*(unsigned int *)hash));
	if (!node)
		return NULL;

	entry = eb32_entry(node, struct cache_entry, eb);

	/* if that's not the right node */
	if (memcmp(entry->hash, hash, sizeof(entry->hash)))
		return NULL;

	if (entry->expire > now.tv_sec) {
		return entry;
	} else {
		eb32_delete(node);
		entry->eb.key = 0;
	}
	return NULL;

}

static inline struct shared_context *shctx_ptr(struct cache *cache)
{
	return (struct shared_context *)((unsigned char *)cache - ((struct shared_context *)NULL)->data);
}

static inline struct shared_block *block_ptr(struct cache_entry *entry)
{
	return (struct shared_block *)((unsigned char *)entry - ((struct shared_block *)NULL)->data);
}



static int
cache_store_init(struct proxy *px, struct flt_conf *fconf)
{
	fconf->flags |= FLT_CFG_FL_HTX;
	return 0;
}

static void
cache_store_deinit(struct proxy *px, struct flt_conf *fconf)
{
	struct cache_flt_conf *cconf = fconf->conf;

	free(cconf);
}

static int
cache_store_check(struct proxy *px, struct flt_conf *fconf)
{
	struct cache_flt_conf *cconf = fconf->conf;
	struct flt_conf *f;
	struct cache *cache;
	int comp = 0;

	/* Find the cache corresponding to the name in the filter config.  The
	*  cache will not be referenced now in the filter config because it is
	*  not fully allocated. This step will be performed during the cache
	*  post_check.
	*/
	list_for_each_entry(cache, &caches_config, list) {
		if (!strcmp(cache->id, cconf->c.name))
			goto found;
	}

	ha_alert("config: %s '%s': unable to find the cache '%s' referenced by the filter 'cache'.\n",
		 proxy_type_str(px), px->id, (char *)cconf->c.name);
	return 1;

  found:
	/* Here <cache> points on the cache the filter must use and <cconf>
	 * points on the cache filter configuration. */

	/* Check all filters for proxy <px> to know if the compression is
	 * enabled and if it is after the cache. When the compression is before
	 * the cache, an error is returned. Also check if the cache filter must
	 * be explicitly declaired or not. */
	list_for_each_entry(f, &px->filter_configs, list) {
		if (f == fconf) {
			/* The compression filter must be evaluated after the cache. */
			if (comp) {
				ha_alert("config: %s '%s': unable to enable the compression filter before "
					 "the cache '%s'.\n", proxy_type_str(px), px->id, cache->id);
				return 1;
			}
		}
		else if (f->id == http_comp_flt_id)
			comp = 1;
		else if (f->id == fcgi_flt_id)
			continue;
		else if ((f->id != fconf->id) && (cconf->flags & CACHE_FLT_F_IMPLICIT_DECL)) {
			/* Implicit declaration is only allowed with the
			 * compression and fcgi. For other filters, an implicit
			 * declaration is required. */
			ha_alert("config: %s '%s': require an explicit filter declaration "
				 "to use the cache '%s'.\n", proxy_type_str(px), px->id, cache->id);
			return 1;
		}

	}
	return 0;
}

static int
cache_store_chn_start_analyze(struct stream *s, struct filter *filter, struct channel *chn)
{
	if (!(chn->flags & CF_ISRESP))
		return 1;

	if (filter->ctx == NULL) {
		struct cache_st *st;

		st = pool_alloc_dirty(pool_head_cache_st);
		if (st == NULL)
			return -1;

		st->first_block = NULL;
		filter->ctx     = st;

		/* Register post-analyzer on AN_RES_WAIT_HTTP */
		filter->post_analyzers |= AN_RES_WAIT_HTTP;
	}

	return 1;
}

static int
cache_store_chn_end_analyze(struct stream *s, struct filter *filter, struct channel *chn)
{
	struct cache_st *st = filter->ctx;
	struct cache_flt_conf *cconf = FLT_CONF(filter);
	struct cache *cache = cconf->c.cache;
	struct shared_context *shctx = shctx_ptr(cache);

	if (!(chn->flags & CF_ISRESP))
		return 1;

	/* Everything should be released in the http_end filter, but we need to do it
	 * there too, in case of errors */

	if (st && st->first_block) {

		shctx_lock(shctx);
		shctx_row_dec_hot(shctx, st->first_block);
		shctx_unlock(shctx);

	}
	if (st) {
		pool_free(pool_head_cache_st, st);
		filter->ctx = NULL;
	}

	return 1;
}

static int
cache_store_post_analyze(struct stream *s, struct filter *filter, struct channel *chn,
			 unsigned an_bit)
{
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->rsp;
	struct cache_st *st = filter->ctx;

	if (an_bit != AN_RES_WAIT_HTTP)
		goto end;

	/* Here we need to check if any compression filter precedes the cache
	 * filter. This is only possible when the compression is configured in
	 * the frontend while the cache filter is configured on the
	 * backend. This case cannot be detected during HAProxy startup. So in
	 * such cases, the cache is disabled.
	 */
	if (st && (msg->flags & HTTP_MSGF_COMPRESSING)) {
		pool_free(pool_head_cache_st, st);
		filter->ctx = NULL;
	}

  end:
	return 1;
}

static int
cache_store_http_headers(struct stream *s, struct filter *filter, struct http_msg *msg)
{
	struct cache_st *st = filter->ctx;

	if (!(msg->chn->flags & CF_ISRESP) || !st)
		return 1;

	if (st->first_block)
		register_data_filter(s, msg->chn, filter);
	return 1;
}

static inline void disable_cache_entry(struct cache_st *st,
                                       struct filter *filter, struct shared_context *shctx)
{
	struct cache_entry *object;

	object = (struct cache_entry *)st->first_block->data;
	filter->ctx = NULL; /* disable cache  */
	shctx_lock(shctx);
	shctx_row_dec_hot(shctx, st->first_block);
	object->eb.key = 0;
	shctx_unlock(shctx);
	pool_free(pool_head_cache_st, st);
}

static int
cache_store_http_payload(struct stream *s, struct filter *filter, struct http_msg *msg,
			 unsigned int offset, unsigned int len)
{
	struct cache_flt_conf *cconf = FLT_CONF(filter);
	struct shared_context *shctx = shctx_ptr(cconf->c.cache);
	struct cache_st *st = filter->ctx;
	struct htx *htx = htxbuf(&msg->chn->buf);
	struct htx_blk *blk;
	struct shared_block *fb;
	unsigned int orig_len, to_forward;
	int ret;

	if (!len)
		return len;

	if (!st->first_block) {
		unregister_data_filter(s, msg->chn, filter);
		return len;
	}

	chunk_reset(&trash);
	orig_len = len;
	to_forward = 0;
	for (blk = htx_get_first_blk(htx); blk && len; blk = htx_get_next_blk(htx, blk)) {
		enum htx_blk_type type = htx_get_blk_type(blk);
		uint32_t info, sz = htx_get_blksz(blk);
		struct ist v;

		if (offset >= sz) {
			offset -= sz;
			continue;
		}

		switch (type) {
			case HTX_BLK_UNUSED:
				break;

			case HTX_BLK_DATA:
				v = htx_get_blk_value(htx, blk);
				v.ptr += offset;
				v.len -= offset;
				if (v.len > len)
					v.len = len;

				info = (type << 28) + v.len;
				chunk_memcat(&trash, (char *)&info, sizeof(info));
				chunk_memcat(&trash, v.ptr, v.len);
				to_forward += v.len;
				len -= v.len;
				break;

			default:
				/* Here offset must always be 0 because only
				 * DATA blocks can be partially transferred. */
				if (offset)
					goto no_cache;
				if (sz > len)
					goto end;

				chunk_memcat(&trash, (char *)&blk->info, sizeof(blk->info));
				chunk_memcat(&trash, htx_get_blk_ptr(htx, blk), sz);
				to_forward += sz;
				len -= sz;
				break;
		}

		offset = 0;
	}

  end:
	shctx_lock(shctx);
	fb = shctx_row_reserve_hot(shctx, st->first_block, trash.data);
	if (!fb) {
		shctx_unlock(shctx);
		goto no_cache;
	}
	shctx_unlock(shctx);

	ret = shctx_row_data_append(shctx, st->first_block, st->first_block->last_append,
				    (unsigned char *)b_head(&trash), b_data(&trash));
	if (ret < 0)
		goto no_cache;

	return to_forward;

  no_cache:
	disable_cache_entry(st, filter, shctx);
	unregister_data_filter(s, msg->chn, filter);
	return orig_len;
}

static int
cache_store_http_end(struct stream *s, struct filter *filter,
                     struct http_msg *msg)
{
	struct cache_st *st = filter->ctx;
	struct cache_flt_conf *cconf = FLT_CONF(filter);
	struct cache *cache = cconf->c.cache;
	struct shared_context *shctx = shctx_ptr(cache);
	struct cache_entry *object;

	if (!(msg->chn->flags & CF_ISRESP))
		return 1;

	if (st && st->first_block) {

		object = (struct cache_entry *)st->first_block->data;

		/* does not need to test if the insertion worked, if it
		 * doesn't, the blocks will be reused anyway */

		shctx_lock(shctx);
		if (eb32_insert(&cache->entries, &object->eb) != &object->eb) {
			object->eb.key = 0;
		}
		/* remove from the hotlist */
		shctx_row_dec_hot(shctx, st->first_block);
		shctx_unlock(shctx);

	}
	if (st) {
		pool_free(pool_head_cache_st, st);
		filter->ctx = NULL;
	}

	return 1;
}

 /*
  * This intends to be used when checking HTTP headers for some
  * word=value directive. Return a pointer to the first character of value, if
  * the word was not found or if there wasn't any value assigned ot it return NULL
  */
char *directive_value(const char *sample, int slen, const char *word, int wlen)
{
	int st = 0;

	if (slen < wlen)
		return 0;

	while (wlen) {
		char c = *sample ^ *word;
		if (c && c != ('A' ^ 'a'))
			return NULL;
		sample++;
		word++;
		slen--;
		wlen--;
	}

	while (slen) {
		if (st == 0) {
			if (*sample != '=')
				return NULL;
			sample++;
			slen--;
			st = 1;
			continue;
		} else {
			return (char *)sample;
		}
	}

	return NULL;
}

/*
 * Return the maxage in seconds of an HTTP response.
 * Compute the maxage using either:
 *  - the assigned max-age of the cache
 *  - the s-maxage directive
 *  - the max-age directive
 *  - (Expires - Data) headers
 *  - the default-max-age of the cache
 *
 */
int http_calc_maxage(struct stream *s, struct cache *cache)
{
	struct htx *htx = htxbuf(&s->res.buf);
	struct http_hdr_ctx ctx = { .blk = NULL };
	int smaxage = -1;
	int maxage = -1;

	while (http_find_header(htx, ist("cache-control"), &ctx, 0)) {
		char *value;

		value = directive_value(ctx.value.ptr, ctx.value.len, "s-maxage", 8);
		if (value) {
			struct buffer *chk = get_trash_chunk();

			chunk_strncat(chk, value, ctx.value.len - 8 + 1);
			chunk_strncat(chk, "", 1);
			maxage = atoi(chk->area);
		}

		value = directive_value(ctx.value.ptr, ctx.value.len, "max-age", 7);
		if (value) {
			struct buffer *chk = get_trash_chunk();

			chunk_strncat(chk, value, ctx.value.len - 7 + 1);
			chunk_strncat(chk, "", 1);
			smaxage = atoi(chk->area);
		}
	}

	/* TODO: Expires - Data */


	if (smaxage > 0)
		return MIN(smaxage, cache->maxage);

	if (maxage > 0)
		return MIN(maxage, cache->maxage);

	return cache->maxage;

}


static void cache_free_blocks(struct shared_block *first, struct shared_block *block)
{
	struct cache_entry *object = (struct cache_entry *)block->data;

	if (first == block && object->eb.key)
		eb32_delete(&object->eb);
	object->eb.key = 0;
}

/*
 * This fonction will store the headers of the response in a buffer and then
 * register a filter to store the data
 */
enum act_return http_action_store_cache(struct act_rule *rule, struct proxy *px,
					struct session *sess, struct stream *s, int flags)
{
	unsigned int age;
	long long hdr_age;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->rsp;
	struct filter *filter;
	struct shared_block *first = NULL;
	struct cache_flt_conf *cconf = rule->arg.act.p[0];
	struct shared_context *shctx = shctx_ptr(cconf->c.cache);
	struct cache_st *cache_ctx = NULL;
	struct cache_entry *object, *old;
	unsigned int key = *(unsigned int *)txn->cache_hash;
	struct htx *htx;
	struct http_hdr_ctx ctx;
	size_t hdrs_len = 0;
	int32_t pos;

	/* Don't cache if the response came from a cache */
	if ((obj_type(s->target) == OBJ_TYPE_APPLET) &&
	    s->target == &http_cache_applet.obj_type) {
		goto out;
	}

	/* cache only HTTP/1.1 */
	if (!(txn->req.flags & HTTP_MSGF_VER_11))
		goto out;

	/* cache only GET method */
	if (txn->meth != HTTP_METH_GET)
		goto out;

	/* cache key was not computed */
	if (!key)
		goto out;

	/* cache only 200 status code */
	if (txn->status != 200)
		goto out;

	/* Find the corresponding filter instance for the current stream */
	list_for_each_entry(filter, &s->strm_flt.filters, list) {
		if (FLT_ID(filter) == cache_store_flt_id  && FLT_CONF(filter) == cconf) {
			/* No filter ctx, don't cache anything */
			if (!filter->ctx)
				goto out;
			cache_ctx = filter->ctx;
			break;
		}
	}

	/* from there, cache_ctx is always defined */
	htx = htxbuf(&s->res.buf);

	/* Do not cache too big objects. */
	if ((msg->flags & HTTP_MSGF_CNT_LEN) && shctx->max_obj_size > 0 &&
	    htx->data + htx->extra > shctx->max_obj_size)
		goto out;

	/* Does not manage Vary at the moment. We will need a secondary key later for that */
	ctx.blk = NULL;
	if (http_find_header(htx, ist("Vary"), &ctx, 0))
		goto out;

	http_check_response_for_cacheability(s, &s->res);

	if (!(txn->flags & TX_CACHEABLE) || !(txn->flags & TX_CACHE_COOK))
		goto out;

	age = 0;
	ctx.blk = NULL;
	if (http_find_header(htx, ist("Age"), &ctx, 0)) {
		if (!strl2llrc(ctx.value.ptr, ctx.value.len, &hdr_age) && hdr_age > 0) {
			if (unlikely(hdr_age > CACHE_ENTRY_MAX_AGE))
				hdr_age = CACHE_ENTRY_MAX_AGE;
			age = hdr_age;
		}
		http_remove_header(htx, &ctx);
	}

	chunk_reset(&trash);
	for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_blk *blk = htx_get_blk(htx, pos);
		enum htx_blk_type type = htx_get_blk_type(blk);
		uint32_t sz = htx_get_blksz(blk);

		hdrs_len += sizeof(*blk) + sz;
		chunk_memcat(&trash, (char *)&blk->info, sizeof(blk->info));
		chunk_memcat(&trash, htx_get_blk_ptr(htx, blk), sz);
		if (type == HTX_BLK_EOH)
			break;
	}

	/* Do not cache objects if the headers are too big. */
	if (hdrs_len > htx->size - global.tune.maxrewrite)
		goto out;

	shctx_lock(shctx);
	first = shctx_row_reserve_hot(shctx, NULL, sizeof(struct cache_entry) + trash.data);
	if (!first) {
		shctx_unlock(shctx);
		goto out;
	}
	shctx_unlock(shctx);

	/* the received memory is not initialized, we need at least to mark
	 * the object as not indexed yet.
	 */
	object = (struct cache_entry *)first->data;
	object->eb.node.leaf_p = NULL;
	object->eb.key = 0;
	object->age = age;

	/* reserve space for the cache_entry structure */
	first->len = sizeof(struct cache_entry);
	first->last_append = NULL;
	/* cache the headers in a http action because it allows to chose what
	 * to cache, for example you might want to cache a response before
	 * modifying some HTTP headers, or on the contrary after modifying
	 * those headers.
	 */

	/* does not need to be locked because it's in the "hot" list,
	 * copy the headers */
	if (shctx_row_data_append(shctx, first, NULL, (unsigned char *)trash.area, trash.data) < 0)
		goto out;

	/* register the buffer in the filter ctx for filling it with data*/
	if (cache_ctx) {
		cache_ctx->first_block = first;

		object->eb.key = key;

		memcpy(object->hash, txn->cache_hash, sizeof(object->hash));
		/* Insert the node later on caching success */

		shctx_lock(shctx);

		old = entry_exist(cconf->c.cache, txn->cache_hash);
		if (old) {
			eb32_delete(&old->eb);
			old->eb.key = 0;
		}
		shctx_unlock(shctx);

		/* store latest value and expiration time */
		object->latest_validation = now.tv_sec;
		object->expire = now.tv_sec + http_calc_maxage(s, cconf->c.cache);
		return ACT_RET_CONT;
	}

out:
	/* if does not cache */
	if (first) {
		shctx_lock(shctx);
		first->len = 0;
		object->eb.key = 0;
		shctx_row_dec_hot(shctx, first);
		shctx_unlock(shctx);
	}

	return ACT_RET_CONT;
}

#define 	HTX_CACHE_INIT   0  /* Initial state. */
#define 	HTX_CACHE_HEADER 1  /* Cache entry headers forwarding */
#define 	HTX_CACHE_DATA   2  /* Cache entry data forwarding */
#define 	HTX_CACHE_EOM    3  /* Cache entry completely forwarded. Finish the HTX message */
#define 	HTX_CACHE_END    4  /* Cache entry treatment terminated */

static void http_cache_applet_release(struct appctx *appctx)
{
	struct cache_flt_conf *cconf = appctx->rule->arg.act.p[0];
	struct cache_entry *cache_ptr = appctx->ctx.cache.entry;
	struct cache *cache = cconf->c.cache;
	struct shared_block *first = block_ptr(cache_ptr);

	shctx_lock(shctx_ptr(cache));
	shctx_row_dec_hot(shctx_ptr(cache), first);
	shctx_unlock(shctx_ptr(cache));
}


static unsigned int htx_cache_dump_blk(struct appctx *appctx, struct htx *htx, enum htx_blk_type type,
				       uint32_t info, struct shared_block *shblk, unsigned int offset)
{
	struct cache_flt_conf *cconf = appctx->rule->arg.act.p[0];
	struct shared_context *shctx = shctx_ptr(cconf->c.cache);
	struct htx_blk *blk;
	char *ptr;
	unsigned int max, total;
	uint32_t blksz;

	max = htx_get_max_blksz(htx, channel_htx_recv_max(si_ic(appctx->owner), htx));
	if (!max)
		return 0;
	blksz = ((type == HTX_BLK_HDR || type == HTX_BLK_TLR)
		 ? (info & 0xff) + ((info >> 8) & 0xfffff)
		 : info & 0xfffffff);
	if (blksz > max)
		return 0;

	blk = htx_add_blk(htx, type, blksz);
	if (!blk)
		return 0;

	blk->info = info;
	total = 4;
	ptr = htx_get_blk_ptr(htx, blk);
	while (blksz) {
		max = MIN(blksz, shctx->block_size - offset);
		memcpy(ptr, (const char *)shblk->data + offset, max);
		offset += max;
		blksz  -= max;
		total  += max;
		ptr    += max;
		if (blksz || offset == shctx->block_size) {
			shblk = LIST_NEXT(&shblk->list, typeof(shblk), list);
			offset = 0;
		}
	}
	appctx->ctx.cache.offset = offset;
	appctx->ctx.cache.next   = shblk;
	appctx->ctx.cache.sent  += total;
	return total;
}

static unsigned int htx_cache_dump_data_blk(struct appctx *appctx, struct htx *htx,
					    uint32_t info, struct shared_block *shblk, unsigned int offset)
{

	struct cache_flt_conf *cconf = appctx->rule->arg.act.p[0];
	struct shared_context *shctx = shctx_ptr(cconf->c.cache);
	unsigned int max, total, rem_data;
	uint32_t blksz;

	max = htx_get_max_blksz(htx, channel_htx_recv_max(si_ic(appctx->owner), htx));
	if (!max)
		return 0;

	rem_data = 0;
	if (appctx->ctx.cache.rem_data) {
		blksz = appctx->ctx.cache.rem_data;
		total = 0;
	}
	else {
		blksz = (info & 0xfffffff);
		total = 4;
	}
	if (blksz > max) {
		rem_data = blksz - max;
		blksz = max;
	}

	while (blksz) {
		size_t sz;

		max = MIN(blksz, shctx->block_size - offset);
		sz  = htx_add_data(htx, ist2(shblk->data + offset, max));
		offset += sz;
		blksz  -= sz;
		total  += sz;
		if (sz < max)
			break;
		if (blksz || offset == shctx->block_size) {
			shblk = LIST_NEXT(&shblk->list, typeof(shblk), list);
			offset = 0;
		}
	}

	appctx->ctx.cache.offset   = offset;
	appctx->ctx.cache.next     = shblk;
	appctx->ctx.cache.sent    += total;
	appctx->ctx.cache.rem_data = rem_data + blksz;
	return total;
}

static size_t htx_cache_dump_msg(struct appctx *appctx, struct htx *htx, unsigned int len,
				 enum htx_blk_type mark)
{
	struct cache_flt_conf *cconf = appctx->rule->arg.act.p[0];
	struct shared_context *shctx = shctx_ptr(cconf->c.cache);
	struct shared_block   *shblk;
	unsigned int offset, sz;
	unsigned int ret, total = 0;

	while (len) {
		enum htx_blk_type type;
		uint32_t info;

		shblk  = appctx->ctx.cache.next;
		offset = appctx->ctx.cache.offset;
		if (appctx->ctx.cache.rem_data) {
			type = HTX_BLK_DATA;
			info = 0;
			goto add_data_blk;
		}

		/* Get info of the next HTX block. May be splitted on 2 shblk */
		sz = MIN(4, shctx->block_size - offset);
		memcpy((char *)&info, (const char *)shblk->data + offset, sz);
		offset += sz;
		if (sz < 4) {
			shblk = LIST_NEXT(&shblk->list, typeof(shblk), list);
			memcpy(((char *)&info)+sz, (const char *)shblk->data, 4 - sz);
			offset = (4 - sz);
		}

		/* Get payload of the next HTX block and insert it. */
		type = (info >> 28);
		if (type != HTX_BLK_DATA)
			ret = htx_cache_dump_blk(appctx, htx, type, info, shblk, offset);
		else {
		  add_data_blk:
			ret = htx_cache_dump_data_blk(appctx, htx, info, shblk, offset);
		}

		if (!ret)
			break;
		total += ret;
		len   -= ret;

		if (appctx->ctx.cache.rem_data || type == mark)
			break;
	}

	return total;
}

static int htx_cache_add_age_hdr(struct appctx *appctx, struct htx *htx)
{
	struct cache_entry *cache_ptr = appctx->ctx.cache.entry;
	unsigned int age;
	char *end;

	chunk_reset(&trash);
	age = MAX(0, (int)(now.tv_sec - cache_ptr->latest_validation)) + cache_ptr->age;
	if (unlikely(age > CACHE_ENTRY_MAX_AGE))
		age = CACHE_ENTRY_MAX_AGE;
	end = ultoa_o(age, b_head(&trash), b_size(&trash));
	b_set_data(&trash, end - b_head(&trash));
	if (!http_add_header(htx, ist("Age"), ist2(b_head(&trash), b_data(&trash))))
		return 0;
	return 1;
}

static void http_cache_io_handler(struct appctx *appctx)
{
	struct cache_entry *cache_ptr = appctx->ctx.cache.entry;
	struct shared_block *first = block_ptr(cache_ptr);
	struct stream_interface *si = appctx->owner;
	struct channel *req = si_oc(si);
	struct channel *res = si_ic(si);
	struct htx *req_htx, *res_htx;
	struct buffer *errmsg;
	unsigned int len;
	size_t ret, total = 0;

	res_htx = htxbuf(&res->buf);
	total = res_htx->data;

	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		goto out;

	/* Check if the input buffer is avalaible. */
	if (!b_size(&res->buf)) {
		si_rx_room_blk(si);
		goto out;
	}

	if (res->flags & (CF_SHUTW|CF_SHUTR|CF_SHUTW_NOW))
		appctx->st0 = HTX_CACHE_END;

	if (appctx->st0 == HTX_CACHE_INIT) {
		appctx->ctx.cache.next = block_ptr(cache_ptr);
		appctx->ctx.cache.offset = sizeof(*cache_ptr);
		appctx->ctx.cache.sent = 0;
		appctx->ctx.cache.rem_data = 0;
		appctx->st0 = HTX_CACHE_HEADER;
	}

	if (appctx->st0 == HTX_CACHE_HEADER) {
		/* Headers must be dump at once. Otherwise it is an error */
		len = first->len - sizeof(*cache_ptr) - appctx->ctx.cache.sent;
		ret = htx_cache_dump_msg(appctx, res_htx, len, HTX_BLK_EOH);
		if (!ret || (htx_get_tail_type(res_htx) != HTX_BLK_EOH) ||
		    !htx_cache_add_age_hdr(appctx, res_htx))
			goto error;

		/* Skip response body for HEAD requests */
		if (si_strm(si)->txn->meth == HTTP_METH_HEAD)
			appctx->st0 = HTX_CACHE_EOM;
		else
			appctx->st0 = HTX_CACHE_DATA;
	}

	if (appctx->st0 == HTX_CACHE_DATA) {
		len = first->len - sizeof(*cache_ptr) - appctx->ctx.cache.sent;
		if (len) {
			ret = htx_cache_dump_msg(appctx, res_htx, len, HTX_BLK_EOM);
			if (ret < len) {
				si_rx_room_blk(si);
				goto out;
			}
		}
		appctx->st0 = HTX_CACHE_END;
	}

	if (appctx->st0 == HTX_CACHE_EOM) {
		if (!htx_add_endof(res_htx, HTX_BLK_EOM)) {
			si_rx_room_blk(si);
			goto out;
		}
		appctx->st0 = HTX_CACHE_END;
	}

  end:
	if (!(res->flags & CF_SHUTR) && appctx->st0 == HTX_CACHE_END) {
		res->flags |= CF_READ_NULL;
		si_shutr(si);
	}

  out:
	total = res_htx->data - total;
	if (total)
		channel_add_input(res, total);
	htx_to_buf(res_htx, &res->buf);

	/* eat the whole request */
	if (co_data(req)) {
		req_htx = htx_from_buf(&req->buf);
		co_htx_skip(req, req_htx, co_data(req));
		htx_to_buf(req_htx, &req->buf);
	}
	return;

  error:
	/* Sent and HTTP error 500 */
	b_reset(&res->buf);
	errmsg = &http_err_chunks[HTTP_ERR_500];
	res->buf.data = b_data(errmsg);
	memcpy(res->buf.area, b_head(errmsg), b_data(errmsg));
	res_htx = htx_from_buf(&res->buf);

	total = 0;
	appctx->st0 = HTX_CACHE_END;
	goto end;
}


static int parse_cache_rule(struct proxy *proxy, const char *name, struct act_rule *rule, char **err)
{
	struct flt_conf *fconf;
	struct cache_flt_conf *cconf = NULL;

	if (!*name || strcmp(name, "if") == 0 || strcmp(name, "unless") == 0) {
		memprintf(err, "expects a cache name");
		goto err;
	}

	/* check if a cache filter was already registered with this cache
	 * name, if that's the case, must use it. */
	list_for_each_entry(fconf, &proxy->filter_configs, list) {
		if (fconf->id == cache_store_flt_id) {
			cconf = fconf->conf;
			if (cconf && !strcmp((char *)cconf->c.name, name)) {
				rule->arg.act.p[0] = cconf;
				return 1;
			}
		}
	}

	/* Create the filter cache config  */
	cconf = calloc(1, sizeof(*cconf));
	if (!cconf) {
		memprintf(err, "out of memory\n");
		goto err;
	}
	cconf->flags = CACHE_FLT_F_IMPLICIT_DECL;
	cconf->c.name = strdup(name);
	if (!cconf->c.name) {
		memprintf(err, "out of memory\n");
		goto err;
	}

	/* register a filter to fill the cache buffer */
	fconf = calloc(1, sizeof(*fconf));
	if (!fconf) {
		memprintf(err, "out of memory\n");
		goto err;
	}
	fconf->id = cache_store_flt_id;
	fconf->conf = cconf;
	fconf->ops  = &cache_ops;
	LIST_ADDQ(&proxy->filter_configs, &fconf->list);

	rule->arg.act.p[0] = cconf;
	return 1;

  err:
	free(cconf);
	return 0;
}

enum act_parse_ret parse_cache_store(const char **args, int *orig_arg, struct proxy *proxy,
                                          struct act_rule *rule, char **err)
{
	rule->action       = ACT_CUSTOM;
	rule->action_ptr   = http_action_store_cache;

	if (!parse_cache_rule(proxy, args[*orig_arg], rule, err))
		return ACT_RET_PRS_ERR;

	(*orig_arg)++;
	return ACT_RET_PRS_OK;
}

/* This produces a sha1 hash of the concatenation of the HTTP method,
 * the first occurrence of the Host header followed by the path component
 * if it begins with a slash ('/'). */
int sha1_hosturi(struct stream *s)
{
	struct http_txn *txn = s->txn;
	struct htx *htx = htxbuf(&s->req.buf);
	struct htx_sl *sl;
	struct http_hdr_ctx ctx;
	struct ist uri;
	blk_SHA_CTX sha1_ctx;
	struct buffer *trash;

	trash = get_trash_chunk();
	ctx.blk = NULL;

	switch (txn->meth) {
	case HTTP_METH_HEAD:
	case HTTP_METH_GET:
		chunk_memcat(trash, "GET", 3);
		break;
	default:
		return 0;
	}

	sl = http_get_stline(htx);
	uri = htx_sl_req_uri(sl); // whole uri
	if (!uri.len)
		return 0;

	/* In HTTP/1, most URIs are seen in origin form ('/path/to/resource'),
	 * unless haproxy is deployed in front of an outbound cache. In HTTP/2,
	 * URIs are almost always sent in absolute form with their scheme. In
	 * this case, the scheme is almost always "https". In order to support
	 * sharing of cache objects between H1 and H2, we'll hash the absolute
	 * URI whenever known, or prepend "https://" + the Host header for
	 * relative URIs. The difference will only appear on absolute HTTP/1
	 * requests sent to an origin server, which practically is never met in
	 * the real world so we don't care about the ability to share the same
	 * key here.URIs are normalized from the absolute URI to an origin form as
	 * well.
	 */
	if (!(sl->flags & HTX_SL_F_HAS_AUTHORITY)) {
		chunk_istcat(trash, ist("https://"));
		if (!http_find_header(htx, ist("Host"), &ctx, 0))
			return 0;
		chunk_istcat(trash, ctx.value);
	}

	chunk_memcat(trash, uri.ptr, uri.len);

	/* hash everything */
	blk_SHA1_Init(&sha1_ctx);
	blk_SHA1_Update(&sha1_ctx, trash->area, trash->data);
	blk_SHA1_Final((unsigned char *)txn->cache_hash, &sha1_ctx);

	return 1;
}

enum act_return http_action_req_cache_use(struct act_rule *rule, struct proxy *px,
                                         struct session *sess, struct stream *s, int flags)
{

	struct http_txn *txn = s->txn;
	struct cache_entry *res;
	struct cache_flt_conf *cconf = rule->arg.act.p[0];
	struct cache *cache = cconf->c.cache;

	/* Ignore cache for HTTP/1.0 requests and for requests other than GET
	 * and HEAD */
	if (!(txn->req.flags & HTTP_MSGF_VER_11) ||
	    (txn->meth != HTTP_METH_GET && txn->meth != HTTP_METH_HEAD))
		txn->flags |= TX_CACHE_IGNORE;

	http_check_request_for_cacheability(s, &s->req);

	if ((s->txn->flags & (TX_CACHE_IGNORE|TX_CACHEABLE)) == TX_CACHE_IGNORE)
		return ACT_RET_CONT;

	if (!sha1_hosturi(s))
		return ACT_RET_CONT;

	if (s->txn->flags & TX_CACHE_IGNORE)
		return ACT_RET_CONT;

	if (px == strm_fe(s))
		_HA_ATOMIC_ADD(&px->fe_counters.p.http.cache_lookups, 1);
	else
		_HA_ATOMIC_ADD(&px->be_counters.p.http.cache_lookups, 1);

	shctx_lock(shctx_ptr(cache));
	res = entry_exist(cache, s->txn->cache_hash);
	if (res) {
		struct appctx *appctx;
		shctx_row_inc_hot(shctx_ptr(cache), block_ptr(res));
		shctx_unlock(shctx_ptr(cache));
		s->target = &http_cache_applet.obj_type;
		if ((appctx = si_register_handler(&s->si[1], objt_applet(s->target)))) {
			appctx->st0 = HTX_CACHE_INIT;
			appctx->rule = rule;
			appctx->ctx.cache.entry = res;
			appctx->ctx.cache.next = NULL;
			appctx->ctx.cache.sent = 0;

			if (px == strm_fe(s))
				_HA_ATOMIC_ADD(&px->fe_counters.p.http.cache_hits, 1);
			else
				_HA_ATOMIC_ADD(&px->be_counters.p.http.cache_hits, 1);
			return ACT_RET_CONT;
		} else {
			shctx_lock(shctx_ptr(cache));
			shctx_row_dec_hot(shctx_ptr(cache), block_ptr(res));
			shctx_unlock(shctx_ptr(cache));
			return ACT_RET_YIELD;
		}
	}
	shctx_unlock(shctx_ptr(cache));
	return ACT_RET_CONT;
}


enum act_parse_ret parse_cache_use(const char **args, int *orig_arg, struct proxy *proxy,
                                          struct act_rule *rule, char **err)
{
	rule->action       = ACT_CUSTOM;
	rule->action_ptr   = http_action_req_cache_use;

	if (!parse_cache_rule(proxy, args[*orig_arg], rule, err))
		return ACT_RET_PRS_ERR;

	(*orig_arg)++;
	return ACT_RET_PRS_OK;
}

int cfg_parse_cache(const char *file, int linenum, char **args, int kwm)
{
	int err_code = 0;

	if (strcmp(args[0], "cache") == 0) { /* new cache section */

		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects an <id> argument\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		if (tmp_cache_config == NULL) {
			tmp_cache_config = calloc(1, sizeof(*tmp_cache_config));
			if (!tmp_cache_config) {
				ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			strlcpy2(tmp_cache_config->id, args[1], 33);
			if (strlen(args[1]) > 32) {
				ha_warning("parsing [%s:%d]: cache id is limited to 32 characters, truncate to '%s'.\n",
					   file, linenum, tmp_cache_config->id);
				err_code |= ERR_WARN;
			}
			tmp_cache_config->maxage = 60;
			tmp_cache_config->maxblocks = 0;
			tmp_cache_config->maxobjsz = 0;
		}
	} else if (strcmp(args[0], "total-max-size") == 0) {
		unsigned long int maxsize;
		char *err;

		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		maxsize = strtoul(args[1], &err, 10);
		if (err == args[1] || *err != '\0') {
			ha_warning("parsing [%s:%d]: total-max-size wrong value '%s'\n",
			           file, linenum, args[1]);
			err_code |= ERR_ABORT;
			goto out;
		}

		if (maxsize > (UINT_MAX >> 20)) {
			ha_warning("parsing [%s:%d]: \"total-max-size\" (%s) must not be greater than %u\n",
			           file, linenum, args[1], UINT_MAX >> 20);
			err_code |= ERR_ABORT;
			goto out;
		}

		/* size in megabytes */
		maxsize *= 1024 * 1024 / CACHE_BLOCKSIZE;
		tmp_cache_config->maxblocks = maxsize;
	} else if (strcmp(args[0], "max-age") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		if (!*args[1]) {
			ha_warning("parsing [%s:%d]: '%s' expects an age parameter in seconds.\n",
			        file, linenum, args[0]);
			err_code |= ERR_WARN;
		}

		tmp_cache_config->maxage = atoi(args[1]);
	} else if (strcmp(args[0], "max-object-size") == 0) {
		unsigned int maxobjsz;
		char *err;

		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		if (!*args[1]) {
			ha_warning("parsing [%s:%d]: '%s' expects a maximum file size parameter in bytes.\n",
			        file, linenum, args[0]);
			err_code |= ERR_WARN;
		}

		maxobjsz = strtoul(args[1], &err, 10);
		if (err == args[1] || *err != '\0') {
			ha_warning("parsing [%s:%d]: max-object-size wrong value '%s'\n",
			           file, linenum, args[1]);
			err_code |= ERR_ABORT;
			goto out;
		}
		tmp_cache_config->maxobjsz = maxobjsz;
	}
	else if (*args[0] != 0) {
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in 'cache' section\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
out:
	return err_code;
}

/* once the cache section is parsed */

int cfg_post_parse_section_cache()
{
	int err_code = 0;

	if (tmp_cache_config) {

		if (tmp_cache_config->maxblocks <= 0) {
			ha_alert("Size not specified for cache '%s'\n", tmp_cache_config->id);
			err_code |= ERR_FATAL | ERR_ALERT;
			goto out;
		}

		if (!tmp_cache_config->maxobjsz) {
			/* Default max. file size is a 256th of the cache size. */
			tmp_cache_config->maxobjsz =
				(tmp_cache_config->maxblocks * CACHE_BLOCKSIZE) >> 8;
		}
		else if (tmp_cache_config->maxobjsz > tmp_cache_config->maxblocks * CACHE_BLOCKSIZE / 2) {
			ha_alert("\"max-object-size\" is limited to an half of \"total-max-size\" => %u\n", tmp_cache_config->maxblocks * CACHE_BLOCKSIZE / 2);
			err_code |= ERR_FATAL | ERR_ALERT;
			goto out;
		}

		/* add to the list of cache to init and reinit tmp_cache_config
		 * for next cache section, if any.
		 */
		LIST_ADDQ(&caches_config, &tmp_cache_config->list);
		tmp_cache_config = NULL;
		return err_code;
	}
out:
	free(tmp_cache_config);
	tmp_cache_config = NULL;
	return err_code;

}

int post_check_cache()
{
	struct proxy *px;
	struct cache *back, *cache_config, *cache;
	struct shared_context *shctx;
	int ret_shctx;
	int err_code = 0;

	list_for_each_entry_safe(cache_config, back, &caches_config, list) {

		ret_shctx = shctx_init(&shctx, cache_config->maxblocks, CACHE_BLOCKSIZE,
		                       cache_config->maxobjsz, sizeof(struct cache), 1);

		if (ret_shctx <= 0) {
			if (ret_shctx == SHCTX_E_INIT_LOCK)
				ha_alert("Unable to initialize the lock for the cache.\n");
			else
				ha_alert("Unable to allocate cache.\n");

			err_code |= ERR_FATAL | ERR_ALERT;
			goto out;
		}
		shctx->free_block = cache_free_blocks;
		/* the cache structure is stored in the shctx and added to the
		 * caches list, we can remove the entry from the caches_config
		 * list */
		memcpy(shctx->data, cache_config, sizeof(struct cache));
		cache = (struct cache *)shctx->data;
		cache->entries = EB_ROOT_UNIQUE;
		LIST_ADDQ(&caches, &cache->list);
		LIST_DEL(&cache_config->list);
		free(cache_config);

		/* Find all references for this cache in the existing filters
		 * (over all proxies) and reference it in matching filters.
		 */
		for (px = proxies_list; px; px = px->next) {
			struct flt_conf *fconf;
			struct cache_flt_conf *cconf;

			list_for_each_entry(fconf, &px->filter_configs, list) {
				if (fconf->id != cache_store_flt_id)
					continue;

				cconf = fconf->conf;
				if (!strcmp(cache->id, cconf->c.name)) {
					free(cconf->c.name);
					cconf->c.cache = cache;
					break;
				}
			}
		}
	}

out:
	return err_code;

}

struct flt_ops cache_ops = {
	.init   = cache_store_init,
	.check  = cache_store_check,
	.deinit = cache_store_deinit,

	/* Handle channels activity */
	.channel_start_analyze = cache_store_chn_start_analyze,
	.channel_end_analyze = cache_store_chn_end_analyze,
	.channel_post_analyze = cache_store_post_analyze,

	/* Filter HTTP requests and responses */
	.http_headers        = cache_store_http_headers,
	.http_payload        = cache_store_http_payload,
	.http_end            = cache_store_http_end,
};



static int
parse_cache_flt(char **args, int *cur_arg, struct proxy *px,
		struct flt_conf *fconf, char **err, void *private)
{
	struct flt_conf *f, *back;
	struct cache_flt_conf *cconf = NULL;
	char *name = NULL;
	int pos = *cur_arg;

	/* Get the cache filter name*/
	if (!strcmp(args[pos], "cache")) {
		if (!*args[pos + 1]) {
			memprintf(err, "%s : expects an <id> argument", args[pos]);
			goto error;
		}
		name = strdup(args[pos + 1]);
		if (!name) {
			memprintf(err, "%s '%s' : out of memory", args[pos], args[pos + 1]);
			goto error;
		}
		pos += 2;
	}

	/* Check if an implicit filter with the same name already exists. If so,
	 * we remove the implicit filter to use the explicit one. */
	list_for_each_entry_safe(f, back, &px->filter_configs, list) {
		if (f->id != cache_store_flt_id)
			continue;

		cconf = f->conf;
		if (strcmp(name, cconf->c.name)) {
			cconf = NULL;
			continue;
		}

		if (!(cconf->flags & CACHE_FLT_F_IMPLICIT_DECL)) {
			cconf = NULL;
			memprintf(err, "%s: multiple explicit declarations of the cache filter '%s'",
				  px->id, name);
			return -1;
		}

		/* Remove the implicit filter. <cconf> is kept for the explicit one */
		LIST_DEL(&f->list);
		free(f);
		free(name);
		break;
	}

	/* No implicit cache filter found, create configuration for the explicit one */
	if (!cconf) {
		cconf = calloc(1, sizeof(*cconf));
		if (!cconf) {
			memprintf(err, "%s: out of memory", args[*cur_arg]);
			goto error;
		}
		cconf->c.name = name;
	}

	cconf->flags = 0;
	fconf->id   = cache_store_flt_id;
	fconf->conf = cconf;
	fconf->ops  = &cache_ops;

	*cur_arg = pos;
	return 0;

  error:
	free(name);
	free(cconf);
	return -1;
}

static int cli_parse_show_cache(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	return 0;
}

static int cli_io_handler_show_cache(struct appctx *appctx)
{
	struct cache* cache = appctx->ctx.cli.p0;
	struct stream_interface *si = appctx->owner;

	if (cache == NULL) {
		cache = LIST_ELEM((caches).n, typeof(struct cache *), list);
	}

	list_for_each_entry_from(cache, &caches, list) {
		struct eb32_node *node = NULL;
		unsigned int next_key;
		struct cache_entry *entry;

		next_key = appctx->ctx.cli.i0;
		if (!next_key) {
			chunk_printf(&trash, "%p: %s (shctx:%p, available blocks:%d)\n", cache, cache->id, shctx_ptr(cache), shctx_ptr(cache)->nbav);
			if (ci_putchk(si_ic(si), &trash) == -1) {
				si_rx_room_blk(si);
				return 0;
			}
		}

		appctx->ctx.cli.p0 = cache;

		while (1) {

			shctx_lock(shctx_ptr(cache));
			node = eb32_lookup_ge(&cache->entries, next_key);
			if (!node) {
				shctx_unlock(shctx_ptr(cache));
				appctx->ctx.cli.i0 = 0;
				break;
			}

			entry = container_of(node, struct cache_entry, eb);
			chunk_printf(&trash, "%p hash:%u size:%u (%u blocks), refcount:%u, expire:%d\n", entry, (*(unsigned int *)entry->hash), block_ptr(entry)->len, block_ptr(entry)->block_count, block_ptr(entry)->refcount, entry->expire - (int)now.tv_sec);

			next_key = node->key + 1;
			appctx->ctx.cli.i0 = next_key;

			shctx_unlock(shctx_ptr(cache));

			if (ci_putchk(si_ic(si), &trash) == -1) {
				si_rx_room_blk(si);
				return 0;
			}
		}

	}

	return 1;

}

/* Declare the filter parser for "cache" keyword */
static struct flt_kw_list filter_kws = { "CACHE", { }, {
		{ "cache", parse_cache_flt, NULL },
		{ NULL, NULL, NULL },
	}
};

INITCALL1(STG_REGISTER, flt_register_keywords, &filter_kws);

static struct cli_kw_list cli_kws = {{},{
	{ { "show", "cache", NULL }, "show cache     : show cache status", cli_parse_show_cache, cli_io_handler_show_cache, NULL, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

static struct action_kw_list http_res_actions = {
	.kw = {
		{ "cache-store", parse_cache_store },
		{ NULL, NULL }
	}
};

INITCALL1(STG_REGISTER, http_res_keywords_register, &http_res_actions);

static struct action_kw_list http_req_actions = {
	.kw = {
		{ "cache-use", parse_cache_use },
		{ NULL, NULL }
	}
};

INITCALL1(STG_REGISTER, http_req_keywords_register, &http_req_actions);

struct applet http_cache_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<CACHE>", /* used for logging */
	.fct = http_cache_io_handler,
	.release = http_cache_applet_release,
};

/* config parsers for this section */
REGISTER_CONFIG_SECTION("cache", cfg_parse_cache, cfg_post_parse_section_cache);
REGISTER_POST_CHECK(post_check_cache);
