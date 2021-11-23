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

#include <import/eb32tree.h>
#include <import/sha1.h>

#include <haproxy/action-t.h>
#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/cli.h>
#include <haproxy/errors.h>
#include <haproxy/filters.h>
#include <haproxy/hash.h>
#include <haproxy/http.h>
#include <haproxy/http_ana.h>
#include <haproxy/http_htx.h>
#include <haproxy/http_rules.h>
#include <haproxy/htx.h>
#include <haproxy/net_helper.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/shctx.h>
#include <haproxy/stream.h>
#include <haproxy/stream_interface.h>
#include <haproxy/tools.h>

#define CACHE_FLT_F_IMPLICIT_DECL  0x00000001 /* The cache filtre was implicitly declared (ie without
					       * the filter keyword) */
#define CACHE_FLT_INIT             0x00000002 /* Whether the cache name was freed. */

const char *cache_store_flt_id = "cache store filter";

extern struct applet http_cache_applet;

struct flt_ops cache_ops;

struct cache {
	struct list list;        /* cache linked list */
	struct eb_root entries;  /* head of cache entries based on keys */
	unsigned int maxage;     /* max-age */
	unsigned int maxblocks;
	unsigned int maxobjsz;   /* max-object-size (in bytes) */
	unsigned int max_secondary_entries;  /* maximum number of secondary entries with the same primary hash */
	uint8_t vary_processing_enabled;     /* boolean : manage Vary header (disabled by default) */
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
 * Vary-related structures and functions
 */
enum vary_header_bit {
	VARY_ACCEPT_ENCODING = (1 << 0),
	VARY_REFERER =         (1 << 1),
	VARY_LAST  /* should always be last */
};

/*
 * Encoding list extracted from
 * https://www.iana.org/assignments/http-parameters/http-parameters.xhtml
 * and RFC7231#5.3.4.
 */
enum vary_encoding {
	VARY_ENCODING_GZIP =		(1 << 0),
	VARY_ENCODING_DEFLATE =		(1 << 1),
	VARY_ENCODING_BR =		(1 << 2),
	VARY_ENCODING_COMPRESS =	(1 << 3),
	VARY_ENCODING_AES128GCM =	(1 << 4),
	VARY_ENCODING_EXI =		(1 << 5),
	VARY_ENCODING_PACK200_GZIP =	(1 << 6),
	VARY_ENCODING_ZSTD =		(1 << 7),
	VARY_ENCODING_IDENTITY =	(1 << 8),
	VARY_ENCODING_STAR =		(1 << 9),
	VARY_ENCODING_OTHER =		(1 << 10)
};

struct vary_hashing_information {
	struct ist hdr_name;                 /* Header name */
	enum vary_header_bit value;          /* Bit representing the header in a vary signature */
	unsigned int hash_length;            /* Size of the sub hash for this header's value */
	int(*norm_fn)(struct htx*,struct ist hdr_name,char* buf,unsigned int* buf_len);  /* Normalization function */
	int(*cmp_fn)(const void *ref, const void *new, unsigned int len); /* Comparison function, should return 0 if the hashes are alike */
};

static int http_request_prebuild_full_secondary_key(struct stream *s);
static int http_request_build_secondary_key(struct stream *s, int vary_signature);
static int http_request_reduce_secondary_key(unsigned int vary_signature,
					     char prebuilt_key[HTTP_CACHE_SEC_KEY_LEN]);

static int parse_encoding_value(struct ist value, unsigned int *encoding_value,
				unsigned int *has_null_weight);

static int accept_encoding_normalizer(struct htx *htx, struct ist hdr_name,
				      char *buf, unsigned int *buf_len);
static int default_normalizer(struct htx *htx, struct ist hdr_name,
			      char *buf, unsigned int *buf_len);

static int accept_encoding_bitmap_cmp(const void *ref, const void *new, unsigned int len);

/* Warning : do not forget to update HTTP_CACHE_SEC_KEY_LEN when new items are
 * added to this array. */
const struct vary_hashing_information vary_information[] = {
	{ IST("accept-encoding"), VARY_ACCEPT_ENCODING, sizeof(uint32_t), &accept_encoding_normalizer, &accept_encoding_bitmap_cmp },
	{ IST("referer"), VARY_REFERER, sizeof(int), &default_normalizer, NULL },
};


/*
 * cache ctx for filters
 */
struct cache_st {
	struct shared_block *first_block;
};

#define DEFAULT_MAX_SECONDARY_ENTRY 10

struct cache_entry {
	unsigned int complete;    /* An entry won't be valid until complete is not null. */
	unsigned int latest_validation;     /* latest validation date */
	unsigned int expire;      /* expiration date */
	unsigned int age;         /* Origin server "Age" header value */

	struct eb32_node eb;     /* ebtree node used to hold the cache object */
	char hash[20];

	char secondary_key[HTTP_CACHE_SEC_KEY_LEN];  /* Optional secondary key. */
	unsigned int secondary_key_signature;  /* Bitfield of the HTTP headers that should be used
					        * to build secondary keys for this cache entry. */
	unsigned int secondary_entries_count;  /* Should only be filled in the last entry of a list of dup entries */
	unsigned int last_clear_ts;          /* Timestamp of the last call to clear_expired_duplicates. */

	unsigned int etag_length; /* Length of the ETag value (if one was found in the response). */
	unsigned int etag_offset; /* Offset of the ETag value in the data buffer. */

	time_t last_modified; /* Origin server "Last-Modified" header value converted in
			       * seconds since epoch. If no "Last-Modified"
			       * header is found, use "Date" header value,
			       * otherwise use reception time. This field will
			       * be used in case of an "If-Modified-Since"-based
			       * conditional request. */

	unsigned char data[0];
};

#define CACHE_BLOCKSIZE 1024
#define CACHE_ENTRY_MAX_AGE 2147483648U

static struct list caches = LIST_HEAD_INIT(caches);
static struct list caches_config = LIST_HEAD_INIT(caches_config); /* cache config to init */
static struct cache *tmp_cache_config = NULL;

DECLARE_STATIC_POOL(pool_head_cache_st, "cache_st", sizeof(struct cache_st));

static struct eb32_node *insert_entry(struct cache *cache, struct cache_entry *new_entry);
static void delete_entry(struct cache_entry *del_entry);

struct cache_entry *entry_exist(struct cache *cache, char *hash)
{
	struct eb32_node *node;
	struct cache_entry *entry;

	node = eb32_lookup(&cache->entries, read_u32(hash));
	if (!node)
		return NULL;

	entry = eb32_entry(node, struct cache_entry, eb);

	/* if that's not the right node */
	if (memcmp(entry->hash, hash, sizeof(entry->hash)))
		return NULL;

	if (entry->expire > now.tv_sec) {
		return entry;
	} else {
		delete_entry(entry);
		entry->eb.key = 0;
	}
	return NULL;

}


/*
 * Compare a newly built secondary key to the one found in a cache_entry.
 * Every sub-part of the key is compared to the reference through the dedicated
 * comparison function of the sub-part (that might do more than a simple
 * memcmp).
 * Returns 0 if the keys are alike.
 */
static int secondary_key_cmp(const char *ref_key, const char *new_key)
{
	int retval = 0;
	size_t idx = 0;
	unsigned int offset = 0;
	const struct vary_hashing_information *info;

	for (idx = 0; idx < sizeof(vary_information)/sizeof(*vary_information) && !retval; ++idx) {
		info = &vary_information[idx];

		if (info->cmp_fn)
			retval = info->cmp_fn(&ref_key[offset], &new_key[offset], info->hash_length);
		else
			retval = memcmp(&ref_key[offset], &new_key[offset], info->hash_length);

		offset += info->hash_length;
	}

	return retval;
}

/*
 * There can be multiple entries with the same primary key in the ebtree so in
 * order to get the proper one out of the list, we use a secondary_key.
 * This function simply iterates over all the entries with the same primary_key
 * until it finds the right one.
 * Returns the cache_entry in case of success, NULL otherwise.
 */
struct cache_entry *secondary_entry_exist(struct cache *cache, struct cache_entry *entry,
					  const char *secondary_key)
{
	struct eb32_node *node = &entry->eb;

	if (!entry->secondary_key_signature)
		return NULL;

	while (entry && secondary_key_cmp(entry->secondary_key, secondary_key) != 0) {
		node = eb32_next_dup(node);

		/* Make the best use of this iteration and clear expired entries
		 * when we find them. Calling delete_entry would be too costly
		 * so we simply call eb32_delete. The secondary_entry count will
		 * be updated when we try to insert a new entry to this list. */
		if (entry->expire <= now.tv_sec) {
			eb32_delete(&entry->eb);
			entry->eb.key = 0;
		}

		entry = node ? eb32_entry(node, struct cache_entry, eb) : NULL;
	}

	/* Expired entry */
	if (entry && entry->expire <= now.tv_sec) {
		eb32_delete(&entry->eb);
		entry->eb.key = 0;
		entry = NULL;
	}

	return entry;
}


/*
 * Remove all expired entries from a list of duplicates.
 * Return the number of alive entries in the list and sets dup_tail to the
 * current last item of the list.
 */
static unsigned int clear_expired_duplicates(struct eb32_node **dup_tail)
{
	unsigned int entry_count = 0;
	struct cache_entry *entry = NULL;
	struct eb32_node *prev = *dup_tail;
	struct eb32_node *tail = NULL;

	while (prev) {
		entry = container_of(prev, struct cache_entry, eb);
		prev = eb32_prev_dup(prev);
		if (entry->expire <= now.tv_sec) {
			eb32_delete(&entry->eb);
			entry->eb.key = 0;
		}
		else {
			if (!tail)
				tail = &entry->eb;
			++entry_count;
		}
	}

	*dup_tail = tail;

	return entry_count;
}


/*
 * This function inserts a cache_entry in the cache's ebtree. In case of
 * duplicate entries (vary), it then checks that the number of entries did not
 * reach the max number of secondary entries. If this entry should not have been
 * created, remove it.
 * In the regular case (unique entries), this function does not do more than a
 * simple insert. In case of secondary entries, it will at most cost an
 * insertion+max_sec_entries time checks and entry deletion.
 * Returns the newly inserted node in case of success, NULL otherwise.
 */
static struct eb32_node *insert_entry(struct cache *cache, struct cache_entry *new_entry)
{
	struct eb32_node *prev = NULL;
	struct cache_entry *entry = NULL;
	unsigned int entry_count = 0;
	unsigned int last_clear_ts = now.tv_sec;

	struct eb32_node *node = eb32_insert(&cache->entries, &new_entry->eb);

	/* We should not have multiple entries with the same primary key unless
	 * the entry has a non null vary signature. */
	if (!new_entry->secondary_key_signature)
		return node;

	prev = eb32_prev_dup(node);
	if (prev != NULL) {
		/* The last entry of a duplicate list should contain the current
		 * number of entries in the list. */
		entry = container_of(prev, struct cache_entry, eb);
		entry_count = entry->secondary_entries_count;
		last_clear_ts = entry->last_clear_ts;

		if (entry_count >= cache->max_secondary_entries) {
			/* Some entries of the duplicate list might be expired so
			 * we will iterate over all the items in order to free some
			 * space. In order to avoid going over the same list too
			 * often, we first check the timestamp of the last check
			 * performed. */
			if (last_clear_ts == now.tv_sec) {
				/* Too many entries for this primary key, clear the
				 * one that was inserted. */
				eb32_delete(node);
				node->key = 0;
				return NULL;
			}

			entry_count = clear_expired_duplicates(&prev);
			if (entry_count >= cache->max_secondary_entries) {
				/* Still too many entries for this primary key, delete
				 * the newly inserted one. */
				entry = container_of(prev, struct cache_entry, eb);
				entry->last_clear_ts = now.tv_sec;
				eb32_delete(node);
				node->key = 0;
				return NULL;
			}
		}
	}

	new_entry->secondary_entries_count = entry_count + 1;
	new_entry->last_clear_ts = last_clear_ts;

	return node;
}


/*
 * This function removes an entry from the ebtree. If the entry was a duplicate
 * (in case of Vary), it updates the secondary entry counter in another
 * duplicate entry (the last entry of the dup list).
 */
static void delete_entry(struct cache_entry *del_entry)
{
	struct eb32_node *prev = NULL, *next = NULL;
	struct cache_entry *entry = NULL;
	struct eb32_node *last = NULL;

	if (del_entry->secondary_key_signature) {
		next = &del_entry->eb;

		/* Look for last entry of the duplicates list. */
		while ((next = eb32_next_dup(next))) {
			last = next;
		}

		if (last) {
			entry = container_of(last, struct cache_entry, eb);
			--entry->secondary_entries_count;
		}
		else {
			/* The current entry is the last one, look for the
			 * previous one to update its counter. */
			prev = eb32_prev_dup(&del_entry->eb);
			if (prev) {
				entry = container_of(prev, struct cache_entry, eb);
				entry->secondary_entries_count = del_entry->secondary_entries_count - 1;
			}
		}
	}
	eb32_delete(&del_entry->eb);
	del_entry->eb.key = 0;
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

	if (!(cconf->flags & CACHE_FLT_INIT))
		free(cconf->c.name);
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
		if (strcmp(cache->id, cconf->c.name) == 0)
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
cache_store_strm_init(struct stream *s, struct filter *filter)
{
	struct cache_st *st;

	st = pool_alloc(pool_head_cache_st);
	if (st == NULL)
		return -1;

	st->first_block = NULL;
	filter->ctx     = st;

	/* Register post-analyzer on AN_RES_WAIT_HTTP */
	filter->post_analyzers |= AN_RES_WAIT_HTTP;
	return 1;
}

static void
cache_store_strm_deinit(struct stream *s, struct filter *filter)
{
	struct cache_st *st = filter->ctx;
	struct cache_flt_conf *cconf = FLT_CONF(filter);
	struct cache *cache = cconf->c.cache;
	struct shared_context *shctx = shctx_ptr(cache);

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
	eb32_delete(&object->eb);
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
	struct htx_ret htxret;
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

	htxret = htx_find_offset(htx, offset);
	blk = htxret.blk;
	offset = htxret.ret;
	for (; blk && len; blk = htx_get_next_blk(htx, blk)) {
		enum htx_blk_type type = htx_get_blk_type(blk);
		uint32_t info, sz = htx_get_blksz(blk);
		struct ist v;

		switch (type) {
			case HTX_BLK_UNUSED:
				break;

			case HTX_BLK_DATA:
				v = htx_get_blk_value(htx, blk);
				v = istadv(v, offset);
				v = isttrim(v, len);

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

		shctx_lock(shctx);
		/* The whole payload was cached, the entry can now be used. */
		object->complete = 1;
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
  * the word was not found or if there wasn't any value assigned to it return NULL
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
 * The returned value will always take the cache's configuration into account
 * (cache->maxage) but the actual max age of the response will be set in the
 * true_maxage parameter. It will be used to determine if a response is already
 * stale or not.
 * Compute the maxage using either:
 *  - the assigned max-age of the cache
 *  - the s-maxage directive
 *  - the max-age directive
 *  - (Expires - Data) headers
 *  - the default-max-age of the cache
 *
 */
int http_calc_maxage(struct stream *s, struct cache *cache, int *true_maxage)
{
	struct htx *htx = htxbuf(&s->res.buf);
	struct http_hdr_ctx ctx = { .blk = NULL };
	long smaxage = -1;
	long maxage = -1;
	int expires = -1;
	struct tm tm = {};
	time_t expires_val = 0;
	char *endptr = NULL;
	int offset = 0;

	/* The Cache-Control max-age and s-maxage directives should be followed by
	 * a positive numerical value (see RFC 7234#5.2.1.1). According to the
	 * specs, a sender "should not" generate a quoted-string value but we will
	 * still accept this format since it isn't strictly forbidden. */
	while (http_find_header(htx, ist("cache-control"), &ctx, 0)) {
		char *value;

		value = directive_value(ctx.value.ptr, ctx.value.len, "s-maxage", 8);
		if (value) {
			struct buffer *chk = get_trash_chunk();

			chunk_memcat(chk, value, ctx.value.len - 8 + 1);
			chunk_memcat(chk, "", 1);
			offset = (*chk->area == '"') ? 1 : 0;
			smaxage = strtol(chk->area + offset, &endptr, 10);
			if (unlikely(smaxage < 0 || endptr == chk->area + offset))
				return -1;
		}

		value = directive_value(ctx.value.ptr, ctx.value.len, "max-age", 7);
		if (value) {
			struct buffer *chk = get_trash_chunk();

			chunk_memcat(chk, value, ctx.value.len - 7 + 1);
			chunk_memcat(chk, "", 1);
			offset = (*chk->area == '"') ? 1 : 0;
			maxage = strtol(chk->area + offset, &endptr, 10);
			if (unlikely(maxage < 0 || endptr == chk->area + offset))
				return -1;
		}
	}

	/* Look for Expires header if no s-maxage or max-age Cache-Control data
	 * was found. */
	if (maxage == -1 && smaxage == -1) {
		ctx.blk = NULL;
		if (http_find_header(htx, ist("expires"), &ctx, 1)) {
			if (parse_http_date(istptr(ctx.value), istlen(ctx.value), &tm)) {
				expires_val = my_timegm(&tm);
				/* A request having an expiring date earlier
				 * than the current date should be considered as
				 * stale. */
				expires = (expires_val >= now.tv_sec) ?
					(expires_val - now.tv_sec) : 0;
			}
			else {
				/* Following RFC 7234#5.3, an invalid date
				 * format must be treated as a date in the past
				 * so the cache entry must be seen as already
				 * expired. */
				expires = 0;
			}
		}
	}


	if (smaxage > 0) {
		if (true_maxage)
			*true_maxage = smaxage;
		return MIN(smaxage, cache->maxage);
	}

	if (maxage > 0) {
		if (true_maxage)
			*true_maxage = maxage;
		return MIN(maxage, cache->maxage);
	}

	if (expires >= 0) {
		if (true_maxage)
			*true_maxage = expires;
		return MIN(expires, cache->maxage);
	}

	return cache->maxage;

}


static void cache_free_blocks(struct shared_block *first, struct shared_block *block)
{
	struct cache_entry *object = (struct cache_entry *)block->data;

	if (first == block && object->eb.key)
		delete_entry(object);
	object->eb.key = 0;
}


/* As per RFC 7234#4.3.2, in case of "If-Modified-Since" conditional request, the
 * date value should be compared to a date determined by in a previous response (for
 * the same entity). This date could either be the "Last-Modified" value, or the "Date"
 * value of the response's reception time (by decreasing order of priority). */
static time_t get_last_modified_time(struct htx *htx)
{
	time_t last_modified = 0;
	struct http_hdr_ctx ctx = { .blk = NULL };
	struct tm tm = {};

	if (http_find_header(htx, ist("last-modified"), &ctx, 1)) {
		if (parse_http_date(istptr(ctx.value), istlen(ctx.value), &tm)) {
			last_modified = my_timegm(&tm);
		}
	}

	if (!last_modified) {
		ctx.blk = NULL;
		if (http_find_header(htx, ist("date"), &ctx, 1)) {
			if (parse_http_date(istptr(ctx.value), istlen(ctx.value), &tm)) {
				last_modified = my_timegm(&tm);
			}
		}
	}

	/* Fallback on the current time if no "Last-Modified" or "Date" header
	 * was found. */
	if (!last_modified)
		last_modified = now.tv_sec;

	return last_modified;
}

/*
 * Checks the vary header's value. The headers on which vary should be applied
 * must be explicitly supported in the vary_information array (see cache.c). If
 * any other header is mentioned, we won't store the response.
 * Returns 1 if Vary-based storage can work, 0 otherwise.
 */
static int http_check_vary_header(struct htx *htx, unsigned int *vary_signature)
{
	unsigned int vary_idx;
	unsigned int vary_info_count;
	const struct vary_hashing_information *vary_info;
	struct http_hdr_ctx ctx = { .blk = NULL };

	int retval = 1;

	*vary_signature = 0;

	vary_info_count = sizeof(vary_information)/sizeof(*vary_information);
	while (retval && http_find_header(htx, ist("Vary"), &ctx, 0)) {
		for (vary_idx = 0; vary_idx < vary_info_count; ++vary_idx) {
			vary_info = &vary_information[vary_idx];
			if (isteqi(ctx.value, vary_info->hdr_name)) {
				*vary_signature |= vary_info->value;
				break;
			}
		}
		retval = (vary_idx < vary_info_count);
	}

	return retval;
}


/*
 * Look for the accept-encoding part of the secondary_key and replace the
 * encoding bitmap part of the hash with the actual encoding of the response,
 * extracted from the content-encoding header value.
 * Responses that have an unknown encoding will not be cached if they also
 * "vary" on the accept-encoding value.
 * Returns 0 if we found a known encoding in the response, -1 otherwise.
 */
static int set_secondary_key_encoding(struct htx *htx, char *secondary_key)
{
	unsigned int resp_encoding_bitmap = 0;
	const struct vary_hashing_information *info = vary_information;
	unsigned int offset = 0;
	unsigned int count = 0;
	unsigned int hash_info_count = sizeof(vary_information)/sizeof(*vary_information);
	unsigned int encoding_value;
	struct http_hdr_ctx ctx = { .blk = NULL };

	/* Look for the accept-encoding part of the secondary_key. */
	while (count < hash_info_count && info->value != VARY_ACCEPT_ENCODING) {
		offset += info->hash_length;
		++info;
		++count;
	}

	if (count == hash_info_count)
		return -1;

	while (http_find_header(htx, ist("content-encoding"), &ctx, 0)) {
		if (parse_encoding_value(ctx.value, &encoding_value, NULL))
			return -1; /* Do not store responses with an unknown encoding */
		resp_encoding_bitmap |= encoding_value;
	}

	if (!resp_encoding_bitmap)
		resp_encoding_bitmap |= VARY_ENCODING_IDENTITY;

	/* Rewrite the bitmap part of the hash with the new bitmap that only
	 * corresponds the the response's encoding. */
	write_u32(secondary_key + offset, resp_encoding_bitmap);

	return 0;
}


/*
 * This function will store the headers of the response in a buffer and then
 * register a filter to store the data
 */
enum act_return http_action_store_cache(struct act_rule *rule, struct proxy *px,
					struct session *sess, struct stream *s, int flags)
{
	int effective_maxage = 0;
	int true_maxage = 0;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->rsp;
	struct filter *filter;
	struct shared_block *first = NULL;
	struct cache_flt_conf *cconf = rule->arg.act.p[0];
	struct cache *cache = cconf->c.cache;
	struct shared_context *shctx = shctx_ptr(cache);
	struct cache_st *cache_ctx = NULL;
	struct cache_entry *object, *old;
	unsigned int key = read_u32(txn->cache_hash);
	struct htx *htx;
	struct http_hdr_ctx ctx;
	size_t hdrs_len = 0;
	int32_t pos;
	unsigned int vary_signature = 0;

	/* Don't cache if the response came from a cache */
	if ((obj_type(s->target) == OBJ_TYPE_APPLET) &&
	    s->target == &http_cache_applet.obj_type) {
		goto out;
	}

	/* cache only HTTP/1.1 */
	if (!(txn->req.flags & HTTP_MSGF_VER_11))
		goto out;

	/* cache only GET method */
	if (txn->meth != HTTP_METH_GET) {
		/* In case of successful unsafe method on a stored resource, the
		 * cached entry must be invalidated (see RFC7234#4.4).
		 * A "non-error response" is one with a 2xx (Successful) or 3xx
		 * (Redirection) status code. */
		if (txn->status >= 200 && txn->status < 400) {
			switch (txn->meth) {
			case HTTP_METH_OPTIONS:
			case HTTP_METH_GET:
			case HTTP_METH_HEAD:
			case HTTP_METH_TRACE:
				break;

			default: /* Any unsafe method */
				/* Discard any corresponding entry in case of successful
				 * unsafe request (such as PUT, POST or DELETE). */
				shctx_lock(shctx);

				old = entry_exist(cconf->c.cache, txn->cache_hash);
				if (old) {
					eb32_delete(&old->eb);
					old->eb.key = 0;
				}
				shctx_unlock(shctx);
			}
		}
		goto out;
	}

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

	/* Only a subset of headers are supported in our Vary implementation. If
	 * any other header is present in the Vary header value, we won't be
	 * able to use the cache. Likewise, if Vary header support is disabled,
	 * avoid caching responses that contain such a header. */
	ctx.blk = NULL;
	if (cache->vary_processing_enabled) {
		if (!http_check_vary_header(htx, &vary_signature))
			goto out;
		if (vary_signature) {
			/* If something went wrong during the secondary key
			 * building, do not store the response. */
			if (!(txn->flags & TX_CACHE_HAS_SEC_KEY))
				goto out;
			http_request_reduce_secondary_key(vary_signature, txn->cache_secondary_hash);
		}
	}
	else if (http_find_header(htx, ist("Vary"), &ctx, 0)) {
		goto out;
	}

	http_check_response_for_cacheability(s, &s->res);

	if (!(txn->flags & TX_CACHEABLE) || !(txn->flags & TX_CACHE_COOK) || (txn->flags & TX_CACHE_IGNORE))
		goto out;

	shctx_lock(shctx);
	old = entry_exist(cache, txn->cache_hash);
	if (old) {
		if (vary_signature)
			old = secondary_entry_exist(cconf->c.cache, old,
						    txn->cache_secondary_hash);
		if (old) {
			if (!old->complete) {
				/* An entry with the same primary key is already being
				 * created, we should not try to store the current
				 * response because it will waste space in the cache. */
				shctx_unlock(shctx);
				goto out;
			}
			delete_entry(old);
			old->eb.key = 0;
		}
	}
	first = shctx_row_reserve_hot(shctx, NULL, sizeof(struct cache_entry));
	if (!first) {
		shctx_unlock(shctx);
		goto out;
	}
	/* the received memory is not initialized, we need at least to mark
	 * the object as not indexed yet.
	 */
	object = (struct cache_entry *)first->data;
	memset(object, 0, sizeof(*object));
	object->eb.key = key;
	object->secondary_key_signature = vary_signature;
	/* We need to temporarily set a valid expiring time until the actual one
	 * is set by the end of this function (in case of concurrent accesses to
	 * the same resource). This way the second access will find an existing
	 * but not yet usable entry in the tree and will avoid storing its data. */
	object->expire = now.tv_sec + 2;

	memcpy(object->hash, txn->cache_hash, sizeof(object->hash));
	if (vary_signature)
		memcpy(object->secondary_key, txn->cache_secondary_hash, HTTP_CACHE_SEC_KEY_LEN);

	/* Insert the entry in the tree even if the payload is not cached yet. */
	if (insert_entry(cache, object) != &object->eb) {
		object->eb.key = 0;
		shctx_unlock(shctx);
		goto out;
	}
	shctx_unlock(shctx);

	/* reserve space for the cache_entry structure */
	first->len = sizeof(struct cache_entry);
	first->last_append = NULL;

	/* Determine the entry's maximum age (taking into account the cache's
	 * configuration) as well as the response's explicit max age (extracted
	 * from cache-control directives or the expires header). */
	effective_maxage = http_calc_maxage(s, cconf->c.cache, &true_maxage);

	ctx.blk = NULL;
	if (http_find_header(htx, ist("Age"), &ctx, 0)) {
		long long hdr_age;
		if (!strl2llrc(ctx.value.ptr, ctx.value.len, &hdr_age) && hdr_age > 0) {
			if (unlikely(hdr_age > CACHE_ENTRY_MAX_AGE))
				hdr_age = CACHE_ENTRY_MAX_AGE;
			/* A response with an Age value greater than its
			 * announced max age is stale and should not be stored. */
			object->age = hdr_age;
			if (unlikely(object->age > true_maxage))
				goto out;
		}
		else
			goto out;
		http_remove_header(htx, &ctx);
	}

	/* Build a last-modified time that will be stored in the cache_entry and
	 * compared to a future If-Modified-Since client header. */
	object->last_modified = get_last_modified_time(htx);

	chunk_reset(&trash);
	for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_blk *blk = htx_get_blk(htx, pos);
		enum htx_blk_type type = htx_get_blk_type(blk);
		uint32_t sz = htx_get_blksz(blk);

		hdrs_len += sizeof(*blk) + sz;
		chunk_memcat(&trash, (char *)&blk->info, sizeof(blk->info));
		chunk_memcat(&trash, htx_get_blk_ptr(htx, blk), sz);

		/* Look for optional ETag header.
		 * We need to store the offset of the ETag value in order for
		 * future conditional requests to be able to perform ETag
		 * comparisons. */
		if (type == HTX_BLK_HDR) {
			struct ist header_name = htx_get_blk_name(htx, blk);
			if (isteq(header_name, ist("etag"))) {
				object->etag_length = sz - istlen(header_name);
				object->etag_offset = sizeof(struct cache_entry) + b_data(&trash) - sz + istlen(header_name);
			}
		}
		if (type == HTX_BLK_EOH)
			break;
	}

	/* Do not cache objects if the headers are too big. */
	if (hdrs_len > htx->size - global.tune.maxrewrite)
		goto out;

	/* If the response has a secondary_key, fill its key part related to
	 * encodings with the actual encoding of the response. This way any
	 * subsequent request having the same primary key will have its accepted
	 * encodings tested upon the cached response's one.
	 * We will not cache a response that has an unknown encoding (not
	 * explicitly supported in parse_encoding_value function). */
	if (cache->vary_processing_enabled && vary_signature)
		if (set_secondary_key_encoding(htx, object->secondary_key))
		    goto out;

	shctx_lock(shctx);
	if (!shctx_row_reserve_hot(shctx, first, trash.data)) {
		shctx_unlock(shctx);
		goto out;
	}
	shctx_unlock(shctx);

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
		/* store latest value and expiration time */
		object->latest_validation = now.tv_sec;
		object->expire = now.tv_sec + effective_maxage;
		return ACT_RET_CONT;
	}

out:
	/* if does not cache */
	if (first) {
		shctx_lock(shctx);
		first->len = 0;
		if (object->eb.key)
			delete_entry(object);
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

		/* Get info of the next HTX block. May be split on 2 shblk */
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

	/* Check if the input buffer is available. */
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

		/* In case of a conditional request, we might want to send a
		 * "304 Not Modified" response instead of the stored data. */
		if (appctx->ctx.cache.send_notmodified) {
			if (!http_replace_res_status(res_htx, ist("304"), ist("Not Modified"))) {
				/* If replacing the status code fails we need to send the full response. */
				appctx->ctx.cache.send_notmodified = 0;
			}
		}

		/* Skip response body for HEAD requests or in case of "304 Not
		 * Modified" response. */
		if (si_strm(si)->txn->meth == HTTP_METH_HEAD || appctx->ctx.cache.send_notmodified)
			appctx->st0 = HTX_CACHE_EOM;
		else
			appctx->st0 = HTX_CACHE_DATA;
	}

	if (appctx->st0 == HTX_CACHE_DATA) {
		len = first->len - sizeof(*cache_ptr) - appctx->ctx.cache.sent;
		if (len) {
			ret = htx_cache_dump_msg(appctx, res_htx, len, HTX_BLK_UNUSED);
			if (ret < len) {
				si_rx_room_blk(si);
				goto out;
			}
		}
		appctx->st0 = HTX_CACHE_EOM;
	}

	if (appctx->st0 == HTX_CACHE_EOM) {
		 /* no more data are expected. */
		res_htx->flags |= HTX_FL_EOM;
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
			if (cconf && strcmp((char *)cconf->c.name, name) == 0) {
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
	LIST_APPEND(&proxy->filter_configs, &fconf->list);

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

	chunk_istcat(trash, uri);

	/* hash everything */
	blk_SHA1_Init(&sha1_ctx);
	blk_SHA1_Update(&sha1_ctx, trash->area, trash->data);
	blk_SHA1_Final((unsigned char *)txn->cache_hash, &sha1_ctx);

	return 1;
}

/* Looks for "If-None-Match" headers in the request and compares their value
 * with the one that might have been stored in the cache_entry. If any of them
 * matches, a "304 Not Modified" response should be sent instead of the cached
 * data.
 * Although unlikely in a GET/HEAD request, the "If-None-Match: *" syntax is
 * valid and should receive a "304 Not Modified" response (RFC 7234#4.3.2).
 *
 * If no "If-None-Match" header was found, look for an "If-Modified-Since"
 * header and compare its value (date) to the one stored in the cache_entry.
 * If the request's date is later than the cached one, we also send a
 * "304 Not Modified" response (see RFCs 7232#3.3 and 7234#4.3.2).
 *
 * Returns 1 if "304 Not Modified" should be sent, 0 otherwise.
 */
static int should_send_notmodified_response(struct cache *cache, struct htx *htx,
                                            struct cache_entry *entry)
{
	int retval = 0;

	struct http_hdr_ctx ctx = { .blk = NULL };
	struct ist cache_entry_etag = IST_NULL;
	struct buffer *etag_buffer = NULL;
	int if_none_match_found = 0;

	struct tm tm = {};
	time_t if_modified_since = 0;

	/* If we find a "If-None-Match" header in the request, rebuild the
	 * cache_entry's ETag in order to perform comparisons.
	 * There could be multiple "if-none-match" header lines. */
	while (http_find_header(htx, ist("if-none-match"), &ctx, 0)) {
		if_none_match_found = 1;

		/* A '*' matches everything. */
		if (isteq(ctx.value, ist("*")) != 0) {
			retval = 1;
			break;
		}

		/* No need to rebuild an etag if none was stored in the cache. */
		if (entry->etag_length == 0)
			break;

		/* Rebuild the stored ETag. */
		if (etag_buffer == NULL) {
			etag_buffer = get_trash_chunk();

			if (shctx_row_data_get(shctx_ptr(cache), block_ptr(entry),
					       (unsigned char*)b_orig(etag_buffer),
					       entry->etag_offset, entry->etag_length) == 0) {
				cache_entry_etag = ist2(b_orig(etag_buffer), entry->etag_length);
			} else {
				/* We could not rebuild the ETag in one go, we
				 * won't send a "304 Not Modified" response. */
				break;
			}
		}

		if (http_compare_etags(cache_entry_etag, ctx.value) == 1) {
			retval = 1;
			break;
		}
	}

	/* If the request did not contain an "If-None-Match" header, we look for
	 * an "If-Modified-Since" header (see RFC 7232#3.3). */
	if (retval == 0 && if_none_match_found == 0) {
		ctx.blk = NULL;
		if (http_find_header(htx, ist("if-modified-since"), &ctx, 1)) {
			if (parse_http_date(istptr(ctx.value), istlen(ctx.value), &tm)) {
				if_modified_since = my_timegm(&tm);

				/* We send a "304 Not Modified" response if the
				 * entry's last modified date is earlier than
				 * the one found in the "If-Modified-Since"
				 * header. */
				retval = (entry->last_modified <= if_modified_since);
			}
		}
	}

	return retval;
}

enum act_return http_action_req_cache_use(struct act_rule *rule, struct proxy *px,
                                         struct session *sess, struct stream *s, int flags)
{

	struct http_txn *txn = s->txn;
	struct cache_entry *res, *sec_entry = NULL;
	struct cache_flt_conf *cconf = rule->arg.act.p[0];
	struct cache *cache = cconf->c.cache;
	struct shared_block *entry_block;


	/* Ignore cache for HTTP/1.0 requests and for requests other than GET
	 * and HEAD */
	if (!(txn->req.flags & HTTP_MSGF_VER_11) ||
	    (txn->meth != HTTP_METH_GET && txn->meth != HTTP_METH_HEAD))
		txn->flags |= TX_CACHE_IGNORE;

	http_check_request_for_cacheability(s, &s->req);

	/* The request's hash has to be calculated for all requests, even POSTs
	 * or PUTs for instance because RFC7234 specifies that a successful
	 * "unsafe" method on a stored resource must invalidate it
	 * (see RFC7234#4.4). */
	if (!sha1_hosturi(s))
		return ACT_RET_CONT;

	if (s->txn->flags & TX_CACHE_IGNORE)
		return ACT_RET_CONT;

	if (px == strm_fe(s))
		_HA_ATOMIC_INC(&px->fe_counters.p.http.cache_lookups);
	else
		_HA_ATOMIC_INC(&px->be_counters.p.http.cache_lookups);

	shctx_lock(shctx_ptr(cache));
	res = entry_exist(cache, s->txn->cache_hash);
	/* We must not use an entry that is not complete. */
	if (res && res->complete) {
		struct appctx *appctx;
		entry_block = block_ptr(res);
		shctx_row_inc_hot(shctx_ptr(cache), entry_block);
		shctx_unlock(shctx_ptr(cache));

		/* In case of Vary, we could have multiple entries with the same
		 * primary hash. We need to calculate the secondary hash in order
		 * to find the actual entry we want (if it exists). */
		if (res->secondary_key_signature) {
			if (!http_request_build_secondary_key(s, res->secondary_key_signature)) {
				shctx_lock(shctx_ptr(cache));
				sec_entry = secondary_entry_exist(cache, res,
								 s->txn->cache_secondary_hash);
				if (sec_entry && sec_entry != res) {
					/* The wrong row was added to the hot list. */
					shctx_row_dec_hot(shctx_ptr(cache), entry_block);
					entry_block = block_ptr(sec_entry);
					shctx_row_inc_hot(shctx_ptr(cache), entry_block);
				}
				res = sec_entry;
				shctx_unlock(shctx_ptr(cache));
			}
			else
				res = NULL;
		}

		/* We looked for a valid secondary entry and could not find one,
		 * the request must be forwarded to the server. */
		if (!res) {
			shctx_lock(shctx_ptr(cache));
			shctx_row_dec_hot(shctx_ptr(cache), entry_block);
			shctx_unlock(shctx_ptr(cache));
			return ACT_RET_CONT;
		}

		s->target = &http_cache_applet.obj_type;
		if ((appctx = si_register_handler(&s->si[1], objt_applet(s->target)))) {
			appctx->st0 = HTX_CACHE_INIT;
			appctx->rule = rule;
			appctx->ctx.cache.entry = res;
			appctx->ctx.cache.next = NULL;
			appctx->ctx.cache.sent = 0;
			appctx->ctx.cache.send_notmodified =
                                should_send_notmodified_response(cache, htxbuf(&s->req.buf), res);

			if (px == strm_fe(s))
				_HA_ATOMIC_INC(&px->fe_counters.p.http.cache_hits);
			else
				_HA_ATOMIC_INC(&px->be_counters.p.http.cache_hits);
			return ACT_RET_CONT;
		} else {
			shctx_lock(shctx_ptr(cache));
			shctx_row_dec_hot(shctx_ptr(cache), entry_block);
			shctx_unlock(shctx_ptr(cache));
			return ACT_RET_YIELD;
		}
	}
	shctx_unlock(shctx_ptr(cache));

	/* Shared context does not need to be locked while we calculate the
	 * secondary hash. */
	if (!res && cache->vary_processing_enabled) {
		/* Build a complete secondary hash until the server response
		 * tells us which fields should be kept (if any). */
		http_request_prebuild_full_secondary_key(s);
	}
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
			ha_alert("parsing [%s:%d] : '%s' expects a <name> argument\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		if (tmp_cache_config == NULL) {
			struct cache *cache_config;

			tmp_cache_config = calloc(1, sizeof(*tmp_cache_config));
			if (!tmp_cache_config) {
				ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			strlcpy2(tmp_cache_config->id, args[1], 33);
			if (strlen(args[1]) > 32) {
				ha_warning("parsing [%s:%d]: cache name is limited to 32 characters, truncate to '%s'.\n",
					   file, linenum, tmp_cache_config->id);
				err_code |= ERR_WARN;
			}

			list_for_each_entry(cache_config, &caches_config, list) {
				if (strcmp(tmp_cache_config->id, cache_config->id) == 0) {
					ha_alert("parsing [%s:%d]: Duplicate cache name '%s'.\n",
					         file, linenum, tmp_cache_config->id);
					err_code |= ERR_ALERT | ERR_ABORT;
					goto out;
				}
			}

			tmp_cache_config->maxage = 60;
			tmp_cache_config->maxblocks = 0;
			tmp_cache_config->maxobjsz = 0;
			tmp_cache_config->max_secondary_entries = DEFAULT_MAX_SECONDARY_ENTRY;
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
	} else if (strcmp(args[0], "process-vary") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		if (!*args[1]) {
			ha_warning("parsing [%s:%d]: '%s' expects \"on\" or \"off\" (enable or disable vary processing).\n",
				   file, linenum, args[0]);
			err_code |= ERR_WARN;
		}
		if (strcmp(args[1], "on") == 0)
			tmp_cache_config->vary_processing_enabled = 1;
		else if (strcmp(args[1], "off") == 0)
			tmp_cache_config->vary_processing_enabled = 0;
		else {
			ha_warning("parsing [%s:%d]: '%s' expects \"on\" or \"off\" (enable or disable vary processing).\n",
				   file, linenum, args[0]);
			err_code |= ERR_WARN;
		}
	} else if (strcmp(args[0], "max-secondary-entries") == 0) {
		unsigned int max_sec_entries;
		char *err;

		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		if (!*args[1]) {
			ha_warning("parsing [%s:%d]: '%s' expects a strictly positive number.\n",
				   file, linenum, args[0]);
			err_code |= ERR_WARN;
		}

		max_sec_entries = strtoul(args[1], &err, 10);
		if (err == args[1] || *err != '\0' || max_sec_entries == 0) {
			ha_warning("parsing [%s:%d]: max-secondary-entries wrong value '%s'\n",
			           file, linenum, args[1]);
			err_code |= ERR_ABORT;
			goto out;
		}
		tmp_cache_config->max_secondary_entries = max_sec_entries;
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
		LIST_APPEND(&caches_config, &tmp_cache_config->list);
		tmp_cache_config = NULL;
		return err_code;
	}
out:
	ha_free(&tmp_cache_config);
	return err_code;

}

int post_check_cache()
{
	struct proxy *px;
	struct cache *back, *cache_config, *cache;
	struct shared_context *shctx;
	int ret_shctx;
	int err_code = ERR_NONE;

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
		cache->entries = EB_ROOT;
		LIST_APPEND(&caches, &cache->list);
		LIST_DELETE(&cache_config->list);
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
				if (strcmp(cache->id, cconf->c.name) == 0) {
					free(cconf->c.name);
					cconf->flags |= CACHE_FLT_INIT;
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

	/* Handle stream init/deinit */
	.attach = cache_store_strm_init,
	.detach = cache_store_strm_deinit,

	/* Handle channels activity */
	.channel_post_analyze = cache_store_post_analyze,

	/* Filter HTTP requests and responses */
	.http_headers        = cache_store_http_headers,
	.http_payload        = cache_store_http_payload,
	.http_end            = cache_store_http_end,
};


#define CHECK_ENCODING(str, encoding_name, encoding_value) \
	({ \
		int retval = 0; \
		if (istmatch(str, (struct ist){ .ptr = encoding_name+1, .len = sizeof(encoding_name) - 2 })) { \
			retval = encoding_value; \
			encoding = istadv(encoding, sizeof(encoding_name) - 2); \
		} \
		(retval); \
	})

/*
 * Parse the encoding <encoding> and try to match the encoding part upon an
 * encoding list of explicitly supported encodings (which all have a specific
 * bit in an encoding bitmap). If a weight is included in the value, find out if
 * it is null or not. The bit value will be set in the <encoding_value>
 * parameter and the <has_null_weight> will be set to 1 if the weight is strictly
 * 0, 1 otherwise.
 * The encodings list is extracted from
 * https://www.iana.org/assignments/http-parameters/http-parameters.xhtml.
 * Returns 0 in case of success and -1 in case of error.
 */
static int parse_encoding_value(struct ist encoding, unsigned int *encoding_value,
				unsigned int *has_null_weight)
{
	int retval = 0;

	if (!encoding_value)
		return -1;

	if (!istlen(encoding))
		return -1;	/* Invalid encoding */

	*encoding_value = 0;
	if (has_null_weight)
		*has_null_weight = 0;

	switch (*encoding.ptr) {
	case 'a':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "aes128gcm", VARY_ENCODING_AES128GCM);
		break;
	case 'b':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "br", VARY_ENCODING_BR);
		break;
	case 'c':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "compress", VARY_ENCODING_COMPRESS);
		break;
	case 'd':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "deflate", VARY_ENCODING_DEFLATE);
		break;
	case 'e':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "exi", VARY_ENCODING_EXI);
		break;
	case 'g':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "gzip", VARY_ENCODING_GZIP);
		break;
	case 'i':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "identity", VARY_ENCODING_IDENTITY);
		break;
	case 'p':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "pack200-gzip", VARY_ENCODING_PACK200_GZIP);
		break;
	case 'x':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "x-gzip", VARY_ENCODING_GZIP);
		if (!*encoding_value)
			*encoding_value = CHECK_ENCODING(encoding, "x-compress", VARY_ENCODING_COMPRESS);
		break;
	case 'z':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "zstd", VARY_ENCODING_ZSTD);
		break;
	case '*':
		encoding = istnext(encoding);
		*encoding_value = VARY_ENCODING_STAR;
		break;
	default:
		retval = -1; /* Unmanaged encoding */
		break;
	}

	/* Process the optional weight part of the encoding. */
	if (*encoding_value) {
		encoding = http_trim_leading_spht(encoding);
		if (istlen(encoding)) {
			if (*encoding.ptr != ';')
				return -1;

			if (has_null_weight) {
				encoding = istnext(encoding);

				encoding = http_trim_leading_spht(encoding);

				*has_null_weight = isteq(encoding, ist("q=0"));
			}
		}
	}

	return retval;
}

#define ACCEPT_ENCODING_MAX_ENTRIES 16
/*
 * Build a bitmap of the accept-encoding header.
 *
 * The bitmap is built by matching every sub-part of the accept-encoding value
 * with a subset of explicitly supported encodings, which all have their own bit
 * in the bitmap. This bitmap will be used to determine if a response can be
 * served to a client (that is if it has an encoding that is accepted by the
 * client). Any unknown encodings will be indicated by the VARY_ENCODING_OTHER
 * bit.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
static int accept_encoding_normalizer(struct htx *htx, struct ist hdr_name,
				      char *buf, unsigned int *buf_len)
{
	size_t count = 0;
	uint32_t encoding_bitmap = 0;
	unsigned int encoding_bmp_bl = -1;
	struct http_hdr_ctx ctx = { .blk = NULL };
	unsigned int encoding_value;
	unsigned int rejected_encoding;

	/* A user agent always accepts an unencoded value unless it explicitly
	 * refuses it through an "identity;q=0" accept-encoding value. */
	encoding_bitmap |= VARY_ENCODING_IDENTITY;

	/* Iterate over all the ACCEPT_ENCODING_MAX_ENTRIES first accept-encoding
	 * values that might span acrosse multiple accept-encoding headers. */
	while (http_find_header(htx, hdr_name, &ctx, 0) && count < ACCEPT_ENCODING_MAX_ENTRIES) {
		count++;

		/* As per RFC7231#5.3.4, "An Accept-Encoding header field with a
		 * combined field-value that is empty implies that the user agent
		 * does not want any content-coding in response."
		 *
		 * We must (and did) count the existence of this empty header to not
		 * hit the `count == 0` case below, but must ignore the value to not
		 * include VARY_ENCODING_OTHER into the final bitmap.
		 */
		if (istlen(ctx.value) == 0)
			continue;

		/* Turn accept-encoding value to lower case */
		ist2bin_lc(istptr(ctx.value), ctx.value);

		/* Try to identify a known encoding and to manage null weights. */
		if (!parse_encoding_value(ctx.value, &encoding_value, &rejected_encoding)) {
			if (rejected_encoding)
				encoding_bmp_bl &= ~encoding_value;
			else
				encoding_bitmap |= encoding_value;
		}
		else {
			/* Unknown encoding */
			encoding_bitmap |= VARY_ENCODING_OTHER;
		}
	}

	/* If a "*" was found in the accepted encodings (without a null weight),
	 * all the encoding are accepted except the ones explicitly rejected. */
	if (encoding_bitmap & VARY_ENCODING_STAR) {
		encoding_bitmap = ~0;
	}

	/* Clear explicitly rejected encodings from the bitmap */
	encoding_bitmap &= encoding_bmp_bl;

	/* As per RFC7231#5.3.4, "If no Accept-Encoding field is in the request,
	 * any content-coding is considered acceptable by the user agent". */
	if (count == 0)
		encoding_bitmap = ~0;

	/* A request with more than ACCEPT_ENCODING_MAX_ENTRIES accepted
	 * encodings might be illegitimate so we will not use it. */
	if (count == ACCEPT_ENCODING_MAX_ENTRIES)
		return -1;

	write_u32(buf, encoding_bitmap);
	*buf_len = sizeof(encoding_bitmap);

	/* This function fills the hash buffer correctly even if no header was
	 * found, hence the 0 return value (success). */
	return 0;
}
#undef ACCEPT_ENCODING_MAX_ENTRIES

/*
 * Normalizer used by default for the Referer header. It only
 * calculates a simple crc of the whole value.
 * Only the first occurrence of the header will be taken into account in the
 * hash.
 * Returns 0 in case of success, 1 if the hash buffer should be filled with 0s
 * and -1 in case of error.
 */
static int default_normalizer(struct htx *htx, struct ist hdr_name,
			      char *buf, unsigned int *buf_len)
{
	int retval = 1;
	struct http_hdr_ctx ctx = { .blk = NULL };

	if (http_find_header(htx, hdr_name, &ctx, 1)) {
		retval = 0;
		write_u32(buf, hash_crc32(istptr(ctx.value), istlen(ctx.value)));
		*buf_len = sizeof(int);
	}

	return retval;
}

/*
 * Accept-Encoding bitmap comparison function.
 * Returns 0 if the bitmaps are compatible.
 */
static int accept_encoding_bitmap_cmp(const void *ref, const void *new, unsigned int len)
{
	uint32_t ref_bitmap = read_u32(ref);
	uint32_t new_bitmap = read_u32(new);

	if (!(ref_bitmap & VARY_ENCODING_OTHER)) {
		/* All the bits set in the reference bitmap correspond to the
		 * stored response' encoding and should all be set in the new
		 * encoding bitmap in order for the client to be able to manage
		 * the response.
		 *
		 * If this is the case the cached response has encodings that
		 * are accepted by the client. It can be served directly by
		 * the cache (as far as the accept-encoding part is concerned).
		 */

		return (ref_bitmap & new_bitmap) != ref_bitmap;
	}
	else {
		return 1;
	}
}


/*
 * Pre-calculate the hashes of all the supported headers (in our Vary
 * implementation) of a given request. We have to calculate all the hashes
 * in advance because the actual Vary signature won't be known until the first
 * response.
 * Only the first occurrence of every header will be taken into account in the
 * hash.
 * If the header is not present, the hash portion of the given header will be
 * filled with zeros.
 * Returns 0 in case of success.
 */
static int http_request_prebuild_full_secondary_key(struct stream *s)
{
	/* The fake signature (second parameter) will ensure that every part of the
	 * secondary key is calculated. */
	return http_request_build_secondary_key(s, ~0);
}


/*
 * Calculate the secondary key for a request for which we already have a known
 * vary signature. The key is made by aggregating hashes calculated for every
 * header mentioned in the vary signature.
 * Only the first occurrence of every header will be taken into account in the
 * hash.
 * If the header is not present, the hash portion of the given header will be
 * filled with zeros.
 * Returns 0 in case of success.
 */
static int http_request_build_secondary_key(struct stream *s, int vary_signature)
{
	struct http_txn *txn = s->txn;
	struct htx *htx = htxbuf(&s->req.buf);

	unsigned int idx;
	const struct vary_hashing_information *info = NULL;
	unsigned int hash_length = 0;
	int retval = 0;
	int offset = 0;

	for (idx = 0; idx < sizeof(vary_information)/sizeof(*vary_information) && retval >= 0; ++idx) {
		info = &vary_information[idx];

		/* The normalizing functions will be in charge of getting the
		 * header values from the htx. This way they can manage multiple
		 * occurrences of their processed header. */
		if ((vary_signature & info->value) && info->norm_fn != NULL &&
		    !(retval = info->norm_fn(htx, info->hdr_name, &txn->cache_secondary_hash[offset], &hash_length))) {
			offset += hash_length;
		}
		else {
			/* Fill hash with 0s. */
			hash_length = info->hash_length;
			memset(&txn->cache_secondary_hash[offset], 0, hash_length);
			offset += hash_length;
		}
	}

	if (retval >= 0)
		txn->flags |= TX_CACHE_HAS_SEC_KEY;

	return (retval < 0);
}

/*
 * Build the actual secondary key of a given request out of the prebuilt key and
 * the actual vary signature (extracted from the response).
 * Returns 0 in case of success.
 */
static int http_request_reduce_secondary_key(unsigned int vary_signature,
					     char prebuilt_key[HTTP_CACHE_SEC_KEY_LEN])
{
	int offset = 0;
	int global_offset = 0;
	int vary_info_count = 0;
	int keep = 0;
	unsigned int vary_idx;
	const struct vary_hashing_information *vary_info;

	vary_info_count = sizeof(vary_information)/sizeof(*vary_information);
	for (vary_idx = 0; vary_idx < vary_info_count; ++vary_idx) {
		vary_info = &vary_information[vary_idx];
		keep = (vary_signature & vary_info->value) ? 0xff : 0;

		for (offset = 0; offset < vary_info->hash_length; ++offset,++global_offset) {
			prebuilt_key[global_offset] &= keep;
		}
	}

	return 0;
}



static int
parse_cache_flt(char **args, int *cur_arg, struct proxy *px,
		struct flt_conf *fconf, char **err, void *private)
{
	struct flt_conf *f, *back;
	struct cache_flt_conf *cconf = NULL;
	char *name = NULL;
	int pos = *cur_arg;

	/* Get the cache filter name. <pos> point on "cache" keyword */
	if (!*args[pos + 1]) {
		memprintf(err, "%s : expects a <name> argument", args[pos]);
		goto error;
	}
	name = strdup(args[pos + 1]);
	if (!name) {
		memprintf(err, "%s '%s' : out of memory", args[pos], args[pos + 1]);
		goto error;
	}
	pos += 2;

	/* Check if an implicit filter with the same name already exists. If so,
	 * we remove the implicit filter to use the explicit one. */
	list_for_each_entry_safe(f, back, &px->filter_configs, list) {
		if (f->id != cache_store_flt_id)
			continue;

		cconf = f->conf;
		if (strcmp(name, cconf->c.name) != 0) {
			cconf = NULL;
			continue;
		}

		if (!(cconf->flags & CACHE_FLT_F_IMPLICIT_DECL)) {
			cconf = NULL;
			memprintf(err, "%s: multiple explicit declarations of the cache filter '%s'",
				  px->id, name);
			goto error;
		}

		/* Remove the implicit filter. <cconf> is kept for the explicit one */
		LIST_DELETE(&f->list);
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
		unsigned int i;

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
			chunk_printf(&trash, "%p hash:%u vary:0x", entry, read_u32(entry->hash));
			for (i = 0; i < HTTP_CACHE_SEC_KEY_LEN; ++i)
				chunk_appendf(&trash, "%02x", (unsigned char)entry->secondary_key[i]);
			chunk_appendf(&trash, " size:%u (%u blocks), refcount:%u, expire:%d\n", block_ptr(entry)->len, block_ptr(entry)->block_count, block_ptr(entry)->refcount, entry->expire - (int)now.tv_sec);

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


/*
 * boolean, returns true if response was built out of a cache entry.
 */
static int
smp_fetch_res_cache_hit(const struct arg *args, struct sample *smp,
                        const char *kw, void *private)
{
	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = (smp->strm ? (smp->strm->target == &http_cache_applet.obj_type) : 0);

	return 1;
}

/*
 * string, returns cache name (if response came from a cache).
 */
static int
smp_fetch_res_cache_name(const struct arg *args, struct sample *smp,
                         const char *kw, void *private)
{
	struct appctx *appctx = NULL;

	struct cache_flt_conf *cconf = NULL;
	struct cache *cache = NULL;

	if (!smp->strm || smp->strm->target != &http_cache_applet.obj_type)
		return 0;

	/* Get appctx from the stream_interface. */
	appctx = si_appctx(&smp->strm->si[1]);
	if (appctx && appctx->rule) {
		cconf = appctx->rule->arg.act.p[0];
		if (cconf) {
			cache = cconf->c.cache;

			smp->data.type = SMP_T_STR;
			smp->flags = SMP_F_CONST;
			smp->data.u.str.area = cache->id;
			smp->data.u.str.data = strlen(cache->id);
			return 1;
		}
	}

	return 0;
}

/* Declare the filter parser for "cache" keyword */
static struct flt_kw_list filter_kws = { "CACHE", { }, {
		{ "cache", parse_cache_flt, NULL },
		{ NULL, NULL, NULL },
	}
};

INITCALL1(STG_REGISTER, flt_register_keywords, &filter_kws);

static struct cli_kw_list cli_kws = {{},{
	{ { "show", "cache", NULL }, "show cache                              : show cache status", cli_parse_show_cache, cli_io_handler_show_cache, NULL, NULL },
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


/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
		{ "res.cache_hit",  smp_fetch_res_cache_hit,  0, NULL, SMP_T_BOOL, SMP_USE_HRSHP, SMP_VAL_RESPONSE },
		{ "res.cache_name", smp_fetch_res_cache_name, 0, NULL, SMP_T_STR,  SMP_USE_HRSHP, SMP_VAL_RESPONSE },
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, sample_register_fetches, &sample_fetch_keywords);
