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
#include <proto/hdr_idx.h>
#include <proto/filters.h>
#include <proto/proto_http.h>
#include <proto/log.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/shctx.h>


#include <common/cfgparse.h>
#include <common/hash.h>

/* flt_cache_store */

static const char *cache_store_flt_id = "cache store filter";

static struct pool_head *pool_head_cache_st = NULL;

struct applet http_cache_applet;

struct flt_ops cache_ops;

struct cache {
	struct list list;        /* cache linked list */
	struct eb_root entries;  /* head of cache entries based on keys */
	unsigned int maxage;     /* max-age */
	unsigned int maxblocks;
	char id[33];             /* cache name */
};

/*
 * cache ctx for filters
 */
struct cache_st {
	int hdrs_len;
	struct shared_block *first_block;
};

struct cache_entry {
	unsigned int latest_validation;     /* latest validation date */
	unsigned int expire;      /* expiration date */
	struct eb32_node eb;     /* ebtree node used to hold the cache object */
	char hash[20];
	unsigned char data[0];
};

#define CACHE_BLOCKSIZE 1024

static struct list caches = LIST_HEAD_INIT(caches);
static struct cache *tmp_cache_config = NULL;

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
cache_store_init(struct proxy *px, struct flt_conf *f1conf)
{
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

		st->hdrs_len    = 0;
		st->first_block = NULL;
		filter->ctx     = st;
	}

	register_data_filter(s, chn, filter);

	return 1;
}

static int
cache_store_chn_end_analyze(struct stream *s, struct filter *filter, struct channel *chn)
{
	struct cache_st *st = filter->ctx;
	struct cache *cache = filter->config->conf;
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
cache_store_http_headers(struct stream *s, struct filter *filter, struct http_msg *msg)
{
	struct cache_st *st = filter->ctx;

	if (!(msg->chn->flags & CF_ISRESP) || !st)
		return 1;

	st->hdrs_len = msg->sov;

	return 1;
}

static int
cache_store_http_forward_data(struct stream *s, struct filter *filter,
		       struct http_msg *msg, unsigned int len)
{
	struct cache_st *st = filter->ctx;
	struct shared_context *shctx = shctx_ptr((struct cache *)filter->config->conf);
	struct cache_entry *object;
	int ret;

	/*
	 * We need to skip the HTTP headers first, because we saved them in the
	 * http-response action.
	 */
	if (!(msg->chn->flags & CF_ISRESP) || !st)
		return len;

	if (!len) {
		/* Nothing to foward */
		ret = len;
	}
	else if (st->hdrs_len >= len) {
		/* Forward part of headers */
		ret           = len;
		st->hdrs_len -= len;
	}
	else {
		/* Forward data */
		if (filter->ctx && st->first_block) {
			/* disable buffering if too much data (never greater than a buffer size */
			if (len - st->hdrs_len > global.tune.bufsize - global.tune.maxrewrite - st->first_block->len) {
			  disable_cache:
				object = (struct cache_entry *)st->first_block->data;
				filter->ctx = NULL; /* disable cache  */
				shctx_lock(shctx);
				shctx_row_dec_hot(shctx, st->first_block);
				object->eb.key = 0;
				shctx_unlock(shctx);
				pool_free(pool_head_cache_st, st);
			} else {
				/* Skip remaining headers to fill the cache */
				b_adv(msg->chn->buf, st->hdrs_len);
				ret = shctx_row_data_append(shctx,
							    st->first_block,
							    (unsigned char *)bi_ptr(msg->chn->buf),
							    MIN(bi_contig_data(msg->chn->buf), len - st->hdrs_len));
				/* Rewind the buffer to forward all data */
				b_rew(msg->chn->buf, st->hdrs_len);
				st->hdrs_len = 0;
				if (ret)
					goto disable_cache;
			}
		}
		ret = len;
	}

	if ((ret != len) ||
	    (FLT_NXT(filter, msg->chn) != FLT_FWD(filter, msg->chn) + ret))
		task_wakeup(s->task, TASK_WOKEN_MSG);

	return ret;
}

static int
cache_store_http_end(struct stream *s, struct filter *filter,
                     struct http_msg *msg)
{
	struct cache_st *st = filter->ctx;
	struct cache *cache = filter->config->conf;
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
	struct http_txn *txn = s->txn;
	struct hdr_ctx ctx;

	int smaxage = -1;
	int maxage = -1;


	ctx.idx = 0;

	/* loop on the Cache-Control values */
	while (http_find_header2("Cache-Control", 13, s->res.buf->p, &txn->hdr_idx, &ctx)) {
		char *directive = ctx.line + ctx.val;
		char *value;

		value = directive_value(directive, ctx.vlen, "s-maxage", 8);
		if (value) {
			struct chunk *chk = get_trash_chunk();

			chunk_strncat(chk, value, ctx.vlen - 8 + 1);
			chunk_strncat(chk, "", 1);
			maxage = atoi(chk->str);
		}

		value = directive_value(ctx.line + ctx.val, ctx.vlen, "max-age", 7);
		if (value) {
			struct chunk *chk = get_trash_chunk();

			chunk_strncat(chk, value, ctx.vlen - 7 + 1);
			chunk_strncat(chk, "", 1);
			smaxage = atoi(chk->str);
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
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->rsp;
	struct filter *filter;
	struct hdr_ctx ctx;
	struct shared_block *first = NULL;
	struct cache *cache = (struct cache *)rule->arg.act.p[0];
	struct shared_context *shctx = shctx_ptr(cache);
	struct cache_entry *object;


	/* Don't cache if the response came from a cache */
	if ((obj_type(s->target) == OBJ_TYPE_APPLET) &&
	    s->target == &http_cache_applet.obj_type) {
		goto out;
	}

	/* cache only HTTP/1.1 */
	if (!(txn->req.flags & HTTP_MSGF_VER_11))
		goto out;

	/* does not cache if Content-Length unknown */
	if (!(msg->flags & HTTP_MSGF_CNT_LEN))
		goto out;

	/* cache only GET method */
	if (txn->meth != HTTP_METH_GET)
		goto out;

	/* cache only 200 status code */
	if (txn->status != 200)
		goto out;

	/* Does not manage Vary at the moment. We will need a secondary key later for that */
	ctx.idx = 0;
	if (http_find_header2("Vary", 4, txn->rsp.chn->buf->p, &txn->hdr_idx, &ctx))
		goto out;

	check_response_for_cacheability(s, &s->res);

	if (!(txn->flags & TX_CACHEABLE) || !(txn->flags & TX_CACHE_COOK))
		goto out;

	if ((msg->sov + msg->body_len) > (global.tune.bufsize - global.tune.maxrewrite))
		goto out;

	shctx_lock(shctx);

	first = shctx_row_reserve_hot(shctx, sizeof(struct cache_entry) + msg->sov + msg->body_len);
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

	/* reserve space for the cache_entry structure */
	first->len = sizeof(struct cache_entry);

	/* cache the headers in a http action because it allows to chose what
	 * to cache, for example you might want to cache a response before
	 * modifying some HTTP headers, or on the contrary after modifying
	 * those headers.
	 */

	/* does not need to be locked because it's in the "hot" list,
	 * copy the headers */
	if (shctx_row_data_append(shctx, first, (unsigned char *)s->res.buf->p, msg->sov) < 0)
		goto out;

	/* register the buffer in the filter ctx for filling it with data*/
	if (!LIST_ISEMPTY(&s->strm_flt.filters)) {
		list_for_each_entry(filter, &s->strm_flt.filters, list) {
			if (filter->config->id == cache_store_flt_id  &&
			    filter->config->conf == rule->arg.act.p[0]) {
				if (filter->ctx) {
					struct cache_st *cache_ctx = filter->ctx;
					struct cache_entry *old;

					cache_ctx->first_block = first;

					object->eb.key = (*(unsigned int *)&txn->cache_hash);
					memcpy(object->hash, txn->cache_hash, sizeof(object->hash));
					/* Insert the node later on caching success */

					shctx_lock(shctx);

					old = entry_exist(cache, txn->cache_hash);
					if (old) {
						eb32_delete(&old->eb);
						old->eb.key = 0;
					}
					shctx_unlock(shctx);

					/* store latest value and expiration time */
					object->latest_validation = now.tv_sec;
					object->expire = now.tv_sec + http_calc_maxage(s, cache);
				}
				return ACT_RET_CONT;
			}
		}
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

#define 	HTTP_CACHE_INIT 0
#define 	HTTP_CACHE_FWD 1
#define 	HTTP_CACHE_END 2

static void http_cache_applet_release(struct appctx *appctx)
{
	struct cache *cache = (struct cache *)appctx->rule->arg.act.p[0];
	struct cache_entry *cache_ptr = appctx->ctx.cache.entry;
	struct shared_block *first = block_ptr(cache_ptr);

	shctx_lock(shctx_ptr(cache));
	shctx_row_dec_hot(shctx_ptr(cache), first);
	shctx_unlock(shctx_ptr(cache));
}

static void http_cache_io_handler(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct channel *res = si_ic(si);
	struct cache *cache = (struct cache *)appctx->rule->arg.act.p[0];
	struct cache_entry *cache_ptr = appctx->ctx.cache.entry;
	struct shared_context *shctx = shctx_ptr(cache);
	struct shared_block *first = block_ptr(cache_ptr);

	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		goto out;

	/* Check if the input buffer is avalaible. */
	if (res->buf->size == 0) {
		si_applet_cant_put(si);
		goto out;
	}

	if (res->flags & (CF_SHUTW|CF_SHUTW_NOW))
		appctx->st0 = HTTP_CACHE_END;

	/* buffer are aligned there, should be fine */
	if (appctx->st0 == HTTP_CACHE_INIT) {
		int len = first->len - sizeof(struct cache_entry);
		if ((shctx_row_data_get(shctx, first, (unsigned char *)bi_end(res->buf), sizeof(struct cache_entry), len)) != 0) {
			/* should never get there, because at the moment, a
			 * cache object can never be bigger than a buffer */
			 abort();

			si_applet_cant_put(si);
			goto out;
		}
		res->buf->i += len;
		res->total += len;
		appctx->st0 = HTTP_CACHE_FWD;
	}

	if (appctx->st0 == HTTP_CACHE_FWD) {
		/* eat the whole request */
		co_skip(si_oc(si), si_ob(si)->o);   // NOTE: when disabled does not repport the  correct status code
		res->flags |= CF_READ_NULL;
		si_shutr(si);
	}

	if ((res->flags & CF_SHUTR) && (si->state == SI_ST_EST))
		si_shutw(si);
out:
	;
}

enum act_parse_ret parse_cache_store(const char **args, int *orig_arg, struct proxy *proxy,
                                          struct act_rule *rule, char **err)
{
	struct flt_conf *fconf;
	int cur_arg = *orig_arg;
	rule->action       = ACT_CUSTOM;
	rule->action_ptr   = http_action_store_cache;

	if (!*args[cur_arg] || strcmp(args[cur_arg], "if") == 0 || strcmp(args[cur_arg], "unless") == 0) {
		memprintf(err, "expects a cache name");
		return ACT_RET_PRS_ERR;
	}

	/* check if a cache filter was already registered with this cache
	 * name, if that's the case, must use it. */
	list_for_each_entry(fconf, &proxy->filter_configs, list) {
		if (fconf->id == cache_store_flt_id && !strcmp((char *)fconf->conf, args[cur_arg])) {
			rule->arg.act.p[0] = fconf->conf;
			(*orig_arg)++;
			/* filter already registered */
			return ACT_RET_PRS_OK;
		}
	}

	rule->arg.act.p[0] = strdup(args[cur_arg]);
	if (!rule->arg.act.p[0]) {
		ha_alert("config: %s '%s': out of memory\n", proxy_type_str(proxy), proxy->id);
		err++;
		goto err;
	}
	/* register a filter to fill the cache buffer */
	fconf = calloc(1, sizeof(*fconf));
	if (!fconf) {
		ha_alert("config: %s '%s': out of memory\n",
			 proxy_type_str(proxy), proxy->id);
		err++;
		goto err;
	}
	fconf->id   = cache_store_flt_id;
	fconf->conf = rule->arg.act.p[0]; /* store the proxy name */
	fconf->ops  = &cache_ops;
	LIST_ADDQ(&proxy->filter_configs, &fconf->list);

	(*orig_arg)++;

	return ACT_RET_PRS_OK;

err:
	return ACT_RET_PRS_ERR;
}

/* This produces a sha1 hash of the concatenation of the first
 * occurrence of the Host header followed by the path component if it
 * begins with a slash ('/'). */
int sha1_hosturi(struct http_txn *txn)
{
	struct hdr_ctx ctx;

	blk_SHA_CTX sha1_ctx;
	struct chunk *trash;
	char *path;
	char *end;
	trash = get_trash_chunk();

	/* retrive the host */
	ctx.idx = 0;
	if (!http_find_header2("Host", 4, txn->req.chn->buf->p, &txn->hdr_idx, &ctx))
		return 0;
	chunk_strncat(trash, ctx.line + ctx.val, ctx.vlen);

	/* now retrieve the path */
	end = txn->req.chn->buf->p + txn->req.sl.rq.u + txn->req.sl.rq.u_l;
	path = http_get_path(txn);
	if (!path)
		return 0;
	chunk_strncat(trash, path, end - path);

	/* hash everything */
	blk_SHA1_Init(&sha1_ctx);
	blk_SHA1_Update(&sha1_ctx, trash->str, trash->len);
	blk_SHA1_Final((unsigned char *)txn->cache_hash, &sha1_ctx);

	return 1;
}



enum act_return http_action_req_cache_use(struct act_rule *rule, struct proxy *px,
                                         struct session *sess, struct stream *s, int flags)
{

	struct cache_entry *res;
	struct cache *cache = (struct cache *)rule->arg.act.p[0];

	check_request_for_cacheability(s, &s->req);
	if ((s->txn->flags & (TX_CACHE_IGNORE|TX_CACHEABLE)) == TX_CACHE_IGNORE)
		return ACT_RET_CONT;

	if (!sha1_hosturi(s->txn))
		return ACT_RET_CONT;

	if (s->txn->flags & TX_CACHE_IGNORE)
		return ACT_RET_CONT;

	shctx_lock(shctx_ptr(cache));
	res = entry_exist(cache, s->txn->cache_hash);
	if (res) {
		struct appctx *appctx;
		shctx_row_inc_hot(shctx_ptr(cache), block_ptr(res));
		shctx_unlock(shctx_ptr(cache));
		s->target = &http_cache_applet.obj_type;
		if ((appctx = stream_int_register_handler(&s->si[1], objt_applet(s->target)))) {
			appctx->st0 = HTTP_CACHE_INIT;
			appctx->rule = rule;
			appctx->ctx.cache.entry = res;
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
	int cur_arg = *orig_arg;

	rule->action       = ACT_CUSTOM;
	rule->action_ptr   = http_action_req_cache_use;

	if (!*args[cur_arg] || strcmp(args[cur_arg], "if") == 0 || strcmp(args[cur_arg], "unless") == 0) {
		memprintf(err, "expects a cache name");
		return ACT_RET_PRS_ERR;
	}

	rule->arg.act.p[0] = strdup(args[cur_arg]);
	if (!rule->arg.act.p[0]) {
		ha_alert("config: %s '%s': out of memory\n", proxy_type_str(proxy), proxy->id);
		err++;
		goto err;
	}

	(*orig_arg)++;
	return ACT_RET_PRS_OK;

err:
	return ACT_RET_PRS_ERR;

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
		}
	} else if (strcmp(args[0], "total-max-size") == 0) {
		int maxsize;

		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		/* size in megabytes */
		maxsize = atoi(args[1]) * 1024 * 1024 / CACHE_BLOCKSIZE;
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
	} else if (*args[0] != 0) {
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
	struct shared_context *shctx;
	int err_code = 0;
	int ret_shctx;

	if (tmp_cache_config) {
		struct cache *cache;

		if (tmp_cache_config->maxblocks <= 0) {
			ha_alert("Size not specified for cache '%s'\n", tmp_cache_config->id);
			err_code |= ERR_FATAL | ERR_ALERT;
			goto out;
		}

		ret_shctx = shctx_init(&shctx, tmp_cache_config->maxblocks, CACHE_BLOCKSIZE, sizeof(struct cache), 1);

		if (ret_shctx < 0) {
			if (ret_shctx == SHCTX_E_INIT_LOCK)
				ha_alert("Unable to initialize the lock for the cache.\n");
			else
				ha_alert("Unable to allocate cache.\n");

			err_code |= ERR_FATAL | ERR_ALERT;
			goto out;
		}
		shctx->free_block = cache_free_blocks;
		memcpy(shctx->data, tmp_cache_config, sizeof(struct cache));
		cache = (struct cache *)shctx->data;
		cache->entries = EB_ROOT_UNIQUE;
		LIST_ADDQ(&caches, &cache->list);
	}
out:
	free(tmp_cache_config);
	tmp_cache_config = NULL;
	return err_code;

}

/*
 * Resolve the cache name to a pointer once the file is completely read.
 */
int cfg_cache_postparser()
{
	struct act_rule *hresrule, *hrqrule;
	void *cache_ptr;
	struct cache *cache;
	struct proxy *curproxy = NULL;
	int err = 0;
	struct flt_conf *fconf;

	for (curproxy = proxies_list; curproxy; curproxy = curproxy->next) {

		/* resolve the http response cache name to a ptr in the action rule */
		list_for_each_entry(hresrule, &curproxy->http_res_rules, list) {
			if (hresrule->action  != ACT_CUSTOM ||
			    hresrule->action_ptr != http_action_store_cache)
				continue;

			cache_ptr = hresrule->arg.act.p[0];

			list_for_each_entry(cache, &caches, list) {
				if (!strcmp(cache->id, cache_ptr)) {
					/* don't free there, it's still used in the filter conf */
					cache_ptr = cache;
					break;
				}
			}

			if (cache_ptr == hresrule->arg.act.p[0]) {
				ha_alert("Proxy '%s': unable to find the cache '%s' referenced by http-response cache-store rule.\n",
					 curproxy->id, (char *)hresrule->arg.act.p[0]);
				err++;
			}

			hresrule->arg.act.p[0] = cache_ptr;
		}

		/* resolve the http request cache name to a ptr in the action rule */
		list_for_each_entry(hrqrule, &curproxy->http_req_rules, list) {
			if (hrqrule->action  != ACT_CUSTOM ||
			    hrqrule->action_ptr != http_action_req_cache_use)
				continue;

			cache_ptr = hrqrule->arg.act.p[0];

			list_for_each_entry(cache, &caches, list) {
				if (!strcmp(cache->id, cache_ptr)) {
					free(cache_ptr);
					cache_ptr = cache;
					break;
				}
			}

			if (cache_ptr == hrqrule->arg.act.p[0]) {
				ha_alert("Proxy '%s': unable to find the cache '%s' referenced by http-request cache-use rule.\n",
					 curproxy->id, (char *)hrqrule->arg.act.p[0]);
				err++;
			}

			hrqrule->arg.act.p[0] = cache_ptr;
		}

		/* resolve the cache name to a ptr in the filter config */
		list_for_each_entry(fconf, &curproxy->filter_configs, list) {

			if (fconf->id != cache_store_flt_id)
				continue;

			cache_ptr = fconf->conf;

			list_for_each_entry(cache, &caches, list) {
				if (!strcmp(cache->id, cache_ptr)) {
					/* there can be only one filter per cache, so we free it there */
					free(cache_ptr);
					cache_ptr = cache;
					break;
				}
			}

			if (cache_ptr == fconf->conf) {
				ha_alert("Proxy '%s': unable to find the cache '%s' referenced by the filter 'cache'.\n",
					 curproxy->id, (char *)fconf->conf);
				err++;
			}
			fconf->conf = cache_ptr;
		}
	}
	return err;
}


struct flt_ops cache_ops = {
	.init   = cache_store_init,

	/* Handle channels activity */
	.channel_start_analyze = cache_store_chn_start_analyze,
	.channel_end_analyze = cache_store_chn_end_analyze,

	/* Filter HTTP requests and responses */
	.http_headers        = cache_store_http_headers,
	.http_end            = cache_store_http_end,

	.http_forward_data   = cache_store_http_forward_data,

};

static int cli_parse_show_cache(char **args, struct appctx *appctx, void *private)
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
				si_applet_cant_put(si);
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
				si_applet_cant_put(si);
				return 0;
			}
		}

	}

	return 1;

}

static struct cli_kw_list cli_kws = {{},{
	{ { "show", "cache", NULL }, "show cache     : show cache status", cli_parse_show_cache, cli_io_handler_show_cache, NULL, NULL },
	{{},}
}};


static struct action_kw_list http_res_actions = {
	.kw = {
		{ "cache-store", parse_cache_store },
		{ NULL, NULL }
	}
};

static struct action_kw_list http_req_actions = {
	.kw = {
		{ "cache-use", parse_cache_use },
		{ NULL, NULL }
	}
};

struct applet http_cache_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<CACHE>", /* used for logging */
	.fct = http_cache_io_handler,
	.release = http_cache_applet_release,
};

__attribute__((constructor))
static void __cache_init(void)
{
	cfg_register_section("cache", cfg_parse_cache, cfg_post_parse_section_cache);
	cfg_register_postparser("cache", cfg_cache_postparser);
	cli_register_kw(&cli_kws);
	http_res_keywords_register(&http_res_actions);
	http_req_keywords_register(&http_req_actions);
	pool_head_cache_st = create_pool("cache_st", sizeof(struct cache_st), MEM_F_SHARED);
}

