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

#include <proto/channel.h>
#include <proto/proxy.h>
#include <proto/hdr_idx.h>
#include <proto/filters.h>
#include <proto/proto_http.h>
#include <proto/log.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/shctx.h>

#include <types/action.h>
#include <types/filters.h>
#include <types/proxy.h>
#include <types/shctx.h>

#include <common/cfgparse.h>
#include <common/hash.h>

/* flt_cache_store */

static const char *cache_store_flt_id = "cache store filter";

struct applet http_cache_applet;

struct flt_ops cache_ops;

struct cache {
	char id[33];             /* cache name */
	unsigned int maxage;  /* max-age */
	unsigned int maxblocks;
	struct list list;     /* cache linked list */
	struct eb_root entries;  /* head of cache entries based on keys */
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
	unsigned char data[0];
};

#define CACHE_BLOCKSIZE 1024

static struct list caches = LIST_HEAD_INIT(caches);
static struct cache *tmp_cache_config = NULL;

static int
cache_store_init(struct proxy *px, struct flt_conf *f1conf)
{
	return 0;
}

/*
 * This fonction will store the headers of the response in a buffer and then
 * register a filter to store the data
 */
enum act_return http_action_store_cache(struct act_rule *rule, struct proxy *px,
                                              struct session *sess, struct stream *s, int flags)
{
	return ACT_RET_CONT;
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
		Alert("config: %s '%s': out of memory\n", proxy_type_str(proxy), proxy->id);
		err++;
		goto err;
	}
	/* register a filter to fill the cache buffer */
	fconf = calloc(1, sizeof(*fconf));
	if (!fconf) {
		Alert("config: %s '%s': out of memory\n",
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
	return ACT_RET_ERR;
}


enum act_return http_action_req_cache_use(struct act_rule *rule, struct proxy *px,
                                         struct session *sess, struct stream *s, int flags)
{
	return ACT_RET_PRS_OK;
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
		Alert("config: %s '%s': out of memory\n", proxy_type_str(proxy), proxy->id);
		err++;
		goto err;
	}

	(*orig_arg)++;
	return ACT_RET_PRS_OK;

err:
	return ACT_RET_ERR;

}

int cfg_parse_cache(const char *file, int linenum, char **args, int kwm)
{
	int err_code = 0;

	if (strcmp(args[0], "cache") == 0) { /* new cache section */

		if (!*args[1]) {
			Alert("parsing [%s:%d] : '%s' expects an <id> argument\n",
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
				Alert("parsing [%s:%d]: out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			strlcpy2(tmp_cache_config->id, args[1], 33);
			if (strlen(args[1]) > 32) {
				Warning("parsing [%s:%d]: cache id is limited to 32 characters, truncate to '%s'.\n",
				        file, linenum, tmp_cache_config->id);
				err_code |= ERR_WARN;
			}

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

	} else if (*args[0] != 0) {
		Alert("parsing [%s:%d] : unknown keyword '%s' in 'cache' section\n", file, linenum, args[0]);
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
			Alert("Size not specified for cache '%s'\n", tmp_cache_config->id);
			err_code |= ERR_FATAL | ERR_ALERT;
			goto out;
		}

		ret_shctx = shctx_init(&shctx, tmp_cache_config->maxblocks, CACHE_BLOCKSIZE, sizeof(struct cache), 1);
		if (ret_shctx < 0) {
			if (ret_shctx == SHCTX_E_INIT_LOCK)
				Alert("Unable to initialize the lock for the cache.\n");
			else
				Alert("Unable to allocate cache.\n");

			err_code |= ERR_FATAL | ERR_ALERT;
			goto out;
		}
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

	for (curproxy = proxy; curproxy; curproxy = curproxy->next) {

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
				Alert("Proxy '%s': unable to find the cache '%s' referenced by http-response cache-store rule.\n",
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
				Alert("Proxy '%s': unable to find the cache '%s' referenced by http-request cache-use rule.\n",
				      curproxy->id, (char *)hrqrule->arg.act.p[0]);
				err++;
			}

			hrqrule->arg.act.p[0] = cache_ptr;
		}

		/* resolve the cache name to a ptr in the filter config */
		list_for_each_entry(fconf, &curproxy->filter_configs, list) {

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
				Alert("Proxy '%s': unable to find the cache '%s' referenced by the filter 'cache'.\n",
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

};

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
	.fct = NULL,
	.release = NULL,
};

__attribute__((constructor))
static void __cache_init(void)
{
	cfg_register_section("cache", cfg_parse_cache, cfg_post_parse_section_cache);
	cfg_register_postparser("cache", cfg_cache_postparser);
	http_res_keywords_register(&http_res_actions);
	http_req_keywords_register(&http_req_actions);
}

