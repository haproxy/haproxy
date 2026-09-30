/*
 * Stream filters related variables and functions.
 *
 * Copyright (C) 2015 Qualys Inc., Christopher Faulet <cfaulet@qualys.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/api.h>
#include <haproxy/buf-t.h>
#include <haproxy/cfgparse.h>
#include <haproxy/cli.h>
#include <haproxy/cli-t.h>
#include <haproxy/compression.h>
#include <haproxy/errors.h>
#include <haproxy/filters.h>
#include <haproxy/flt_decomp.h>
#include <haproxy/flt_http_comp.h>
#include <haproxy/http_ana.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/log.h>
#include <haproxy/namespace.h>
#include <haproxy/proxy.h>
#include <haproxy/stream.h>
#include <haproxy/tools.h>
#include <haproxy/trace.h>


#define TRACE_SOURCE &trace_strm

/* All internal filter classes (should be extended if new filters are added) */
struct filter_class flt_trace_cls;
struct filter_class flt_cache_store_cls;
struct filter_class flt_http_comp_req_cls;
struct filter_class flt_http_comp_res_cls;
struct filter_class flt_decomp_req_cls;
struct filter_class flt_decomp_res_cls;
#if defined(USE_SPOE)
struct filter_class flt_spoe_cls;
#endif
#if defined(USE_LUA)
struct filter_class flt_lua_cls;
#endif
struct filter_class flt_bwlim_in_cls;
struct filter_class flt_bwlim_out_cls;
#if defined(USE_FCGI)
struct filter_class flt_fcgi_cls;
#endif

/* Global list of all filter classes */
static struct list filter_classes = LIST_HEAD_INIT(filter_classes);

/* Ordered list of filter classes dedicated to the request/response processing */
static struct list req_filter_classes = LIST_HEAD_INIT(req_filter_classes);
static struct list res_filter_classes = LIST_HEAD_INIT(res_filter_classes);

/* Used to be sure internal filters classes are initialized before any other ones */
static int filter_classes_initialized = 0;

/* Pool used to allocate filters */
DECLARE_STATIC_TYPED_POOL(pool_head_filter, "filter", struct filter);

static int handle_analyzer_result(struct stream *s, struct channel *chn, unsigned int an_bit, int ret);

/* Frees a filter instance and all its content */
static void flt_free_instance(struct filter_instance *inst)
{
	if (!inst)
		return;
	if (LIST_INLIST(&inst->req.list))
		LIST_DELETE(&inst->req.list);
	if (LIST_INLIST(&inst->res.list))
		LIST_DELETE(&inst->res.list);
	if (inst->conf.argv) {
		int i;

		for (i = 0; i < inst->conf.argc; i++)
			free(inst->conf.argv[i]);
		free(inst->conf.argv);
	}
	free(inst->conf.file);
	free((void *)inst->id);
	free(inst->fconf);
	free(inst);
}

/* Frees a filter_enabled element */
static void flt_free_enabled(struct filter_enabled *flt_en)
{
	if (!flt_en)
		return;
	if (LIST_INLIST(&flt_en->list))
		LIST_DELETE(&flt_en->list);
	free((void *)flt_en->cls_name);
	free((void *)flt_en->id);
	free(flt_en->file);
	free(flt_en);
}

/* Frees a filter_sequence element */
static void flt_free_sequence(struct filter_sequence *flt_seq)
{
	if (!flt_seq)
		return;
	if (LIST_INLIST(&flt_seq->list))
		LIST_DELETE(&flt_seq->list);
	free((void *)flt_seq->cls_name);
	free((void *)flt_seq->id);
	free((void *)flt_seq->cls_ref_name);
	free((void *)flt_seq->ref_id);
	free(flt_seq->file);
	free(flt_seq);
}

/* Frees the instances of the list <instances> for side <side>, recursively */
static void flt_free_inst_list(struct list *instances, unsigned int side)
{
	struct filter_instance *inst, *back;

	if (side == FLT_SIDE_REQ) {
		list_for_each_entry_safe(inst, back, instances, req.list) {
			flt_free_inst_list(&inst->req.reordered_before, side);
			flt_free_inst_list(&inst->req.reordered_after, side);
			flt_free_instance(inst);
		}
	}
	else {
		list_for_each_entry_safe(inst, back, instances, res.list) {
			flt_free_inst_list(&inst->res.reordered_before, side);
			flt_free_inst_list(&inst->res.reordered_after, side);
			flt_free_instance(inst);
		}
	}
}

/*
 * The API below is similar to flt_list_start() and flt_list_next() except that it can be
 * interrupted and resumed!
 *
 * - resume_filter_list_start() and resume_filter_list_next() must always be used together.
 *   The first one sets the first filter value and the second one allows to get the
 *   next one until NULL is returned
 *
 * - resume_filter_list_break() must be used to break the iteration and set the filter
 *   from which to resume the next time (that is, resume_filter_list_start() will allow
 *   to resume from value at the time of the break)
 *
 *  Here is an example:
 *
 *    struct filter *filter;
 *
 *    for (filter = resume_filter_list_start(stream, channel); filter
 *         filter = resume_filter_list_next(stream, channel, filter)) {
 *	...
 *	if (cond) {
 *		resume_filter_list_break(stream, channel, filter, ret);
		goto label;
 *      }
 *    }
 *    ...
 *     label:
 *    ...
 *
 */
static inline struct filter *resume_filter_list_start(struct stream *strm, struct channel *chn)
{
	struct filter *filter;

	if (chn->flt.current) {
		filter = chn->flt.current;
		if (!(chn_prod(chn)->flags & SC_FL_ERROR) &&
		    !(chn->flags & (CF_READ_TIMEOUT|CF_WRITE_TIMEOUT))) {
			(strm)->waiting_entity.type = STRM_ENTITY_NONE;
			(strm)->waiting_entity.ptr = NULL;
		}
	}
	else {
		filter = flt_list_start(strm, chn);
		chn->flt.current = filter;
	}

	return filter;
}

static inline struct filter *resume_filter_list_next(struct stream *strm, struct channel *chn,
                                                     struct filter *filter)
{
	filter = flt_list_next(strm, chn, filter);
	chn->flt.current = filter;
	return filter;
}

static inline void resume_filter_list_break(struct stream *strm, struct channel *chn,
                                            struct filter *filter, int ret)
{
	chn->flt.current = NULL;
	if (ret == 0) {
		strm->waiting_entity.type = STRM_ENTITY_FILTER;
		strm->waiting_entity.ptr  = filter;
		chn->flt.current = filter;
	}
	else if (ret < 0) {
		strm->last_entity.type = STRM_ENTITY_FILTER;
		strm->last_entity.ptr = filter;
	}
}

/* List head of all known filter keywords */
static struct flt_kw_list flt_keywords = {
	.list = LIST_HEAD_INIT(flt_keywords.list)
};

/*
 * Registers the filter keyword list <kwl> as a list of valid keywords for next
 * parsing sessions.
 */
void
flt_register_keywords(struct flt_kw_list *kwl)
{
	LIST_APPEND(&flt_keywords.list, &kwl->list);
}

/*
 * Returns a pointer to the filter keyword <kw>, or NULL if not found. If the
 * keyword is found with a NULL ->parse() function, then an attempt is made to
 * find one with a valid ->parse() function. This way it is possible to declare
 * platform-dependant, known keywords as NULL, then only declare them as valid
 * if some options are met. Note that if the requested keyword contains an
 * opening parenthesis, everything from this point is ignored.
 */
struct flt_kw *
flt_find_kw(const char *kw)
{
	int index;
	const char *kwend;
	struct flt_kw_list *kwl;
	struct flt_kw *ret = NULL;

	kwend = strchr(kw, '(');
	if (!kwend)
		kwend = kw + strlen(kw);

	list_for_each_entry(kwl, &flt_keywords.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if ((strncmp(kwl->kw[index].kw, kw, kwend - kw) == 0) &&
			    kwl->kw[index].kw[kwend-kw] == 0) {
				if (kwl->kw[index].parse)
					return &kwl->kw[index]; /* found it !*/
				else
					ret = &kwl->kw[index];  /* may be OK */
			}
		}
	}
	return ret;
}

/*
 * Dumps all registered "filter" keywords to the <out> string pointer. The
 * unsupported keywords are only dumped if their supported form was not found.
 * If <out> is NULL, the output is emitted using a more compact format on stdout.
 */
void
flt_dump_kws(char **out)
{
	struct flt_kw_list *kwl;
	const struct flt_kw *kwp, *kw;
	const char *scope = NULL;
	int index;

	if (out)
		*out = NULL;

	for (kw = kwp = NULL;; kwp = kw) {
		list_for_each_entry(kwl, &flt_keywords.list, list) {
			for (index = 0; kwl->kw[index].kw != NULL; index++) {
				if ((kwl->kw[index].parse ||
				     flt_find_kw(kwl->kw[index].kw) == &kwl->kw[index])
				    && strordered(kwp ? kwp->kw : NULL,
						  kwl->kw[index].kw,
						  kw != kwp ? kw->kw : NULL)) {
					kw = &kwl->kw[index];
					scope = kwl->scope;
				}
			}
		}

		if (kw == kwp)
			break;

		if (out)
			memprintf(out, "%s[%4s] %s%s\n", *out ? *out : "",
				  scope,
				  kw->kw,
				  kw->parse ? "" : " (not supported)");
		else
			printf("%s [%s]\n",
			       kw->kw, scope);
	}
}

/*
 * Lists the known filters on <out>
 */
void
list_filters(FILE *out)
{
	char *filters, *p, *f;

	fprintf(out, "Available filters :\n");
	flt_dump_kws(&filters);
	for (p = filters; (f = strtok_r(p,"\n",&p));)
		fprintf(out, "\t%s\n", f);
	free(filters);
}

/*
 * Parses the "filter" keyword. All keywords must be handled by filters
 * themselves
 */
static int
parse_filter(char **args, int section_type, struct proxy *curpx,
	     const struct proxy *defpx, const char *file, int line, char **err)
{
	struct flt_conf *fconf = NULL;

	/* Filter cannot be defined on a default proxy */
	if (curpx == defpx) {
		memprintf(err, "parsing [%s:%d] : %s is not allowed in a 'default' section.",
			  file, line, args[0]);
		return -1;
	}
	if (strcmp(args[0], "filter") == 0) {
		struct flt_kw *kw;
		int cur_arg;

		if (!*args[1]) {
			memprintf(err,
				  "parsing [%s:%d] : missing argument for '%s' in %s '%s'.",
				  file, line, args[0], proxy_type_str(curpx), curpx->id);
			goto error;
		}
		fconf = calloc(1, sizeof(*fconf));
		if (!fconf) {
			memprintf(err, "'%s' : out of memory", args[0]);
			goto error;
		}

		cur_arg = 1;
		kw = flt_find_kw(args[cur_arg]);
		if (kw) {
			if (!kw->parse) {
				memprintf(err, "parsing [%s:%d] : '%s' : "
					  "'%s' option is not implemented in this version (check build options).",
					  file, line, args[0], args[cur_arg]);
				goto error;
			}
			if (kw->parse(args, &cur_arg, curpx, fconf, err, kw->private) != 0) {
				if (err && *err)
					memprintf(err, "'%s' : %s",
						  args[0], *err);
				else
					memprintf(err, "'%s' : error encountered while processing '%s'",
						  args[0], args[cur_arg]);
				goto error;
			}
		}
		else {
			flt_dump_kws(err);
			indent_msg(err, 4);
			memprintf(err, "'%s' : unknown keyword '%s'.%s%s",
			          args[0], args[cur_arg],
			          err && *err ? " Registered keywords :" : "", err && *err ? *err : "");
			goto error;
		}
		if (*args[cur_arg]) {
			memprintf(err, "'%s %s' : unknown keyword '%s'.",
			          args[0], args[1], args[cur_arg]);
			goto error;
		}
		if (fconf->ops == NULL) {
			memprintf(err, "'%s %s' : no callbacks defined.",
			          args[0], args[1]);
			goto error;
		}

		LIST_APPEND(&curpx->filter_configs, &fconf->list);
	}
	return 0;

  error:
	free(fconf);
	return -1;


}

/*
 * Calls 'init' callback for all filters attached to a proxy. This happens after
 * the configuration parsing. Filters can finish to fill their config. Returns
 * (ERR_ALERT|ERR_FATAL) if an error occurs, 0 otherwise.
 *
 * The callback is called for the legacy filters (px->filter_configs) and
 * for the finalized filter instances (inst->fconf). Nothing is shared
 * between the legacy filters and the instances. When the instances are
 * attached to the evaluation path, the legacy mode or the instances mode
 * will be chosen and only the corresponding list will be iterated here.
 */
static int
flt_init(struct proxy *proxy)
{
	struct filter_instance *inst;
	struct flt_conf *fconf;

	list_for_each_entry(fconf, &proxy->filter_configs, list) {
		if (fconf->ops->init && fconf->ops->init(proxy, fconf) < 0)
			return ERR_ALERT|ERR_FATAL;
	}
	list_for_each_entry(inst, &proxy->filter_req_instances, req.list) {
		fconf = inst->fconf;
		if (!fconf)
			continue;
		if (fconf->ops->init && fconf->ops->init(proxy, fconf) < 0)
			return ERR_ALERT|ERR_FATAL;
	}
	list_for_each_entry(inst, &proxy->filter_res_instances, res.list) {
		if (LIST_INLIST(&inst->req.list))
			continue; /* already handled from the request side */
		fconf = inst->fconf;
		if (!fconf)
			continue;
		if (fconf->ops->init && fconf->ops->init(proxy, fconf) < 0)
			return ERR_ALERT|ERR_FATAL;
	}
	return 0;
}

/*
 * Calls 'init_per_thread' callback for all filters attached to a proxy for each
 * threads. This happens after the thread creation. Filters can finish to fill
 * their config. Returns (ERR_ALERT|ERR_FATAL) if an error occurs, 0 otherwise.
 *
 * The callback is called for the legacy filters (px->filter_configs) and
 * for the finalized filter instances (inst->fconf). Nothing is shared
 * between the legacy filters and the instances. When the instances are
 * attached to the evaluation path, the legacy mode or the instances mode
 * will be chosen and only the corresponding list will be iterated here.
 */
static int
flt_init_per_thread(struct proxy *proxy)
{
	struct filter_instance *inst;
	struct flt_conf *fconf;

	list_for_each_entry(fconf, &proxy->filter_configs, list) {
		if (fconf->ops->init_per_thread && fconf->ops->init_per_thread(proxy, fconf) < 0)
			return ERR_ALERT|ERR_FATAL;
	}
	list_for_each_entry(inst, &proxy->filter_req_instances, req.list) {
		fconf = inst->fconf;
		if (!fconf)
			continue;
		if (fconf->ops->init_per_thread && fconf->ops->init_per_thread(proxy, fconf) < 0)
			return ERR_ALERT|ERR_FATAL;
	}
	list_for_each_entry(inst, &proxy->filter_res_instances, res.list) {
		if (LIST_INLIST(&inst->req.list))
			continue; /* already handled from the request side */
		fconf = inst->fconf;
		if (!fconf)
			continue;
		if (fconf->ops->init_per_thread && fconf->ops->init_per_thread(proxy, fconf) < 0)
			return ERR_ALERT|ERR_FATAL;
	}
	return 0;
}

/* Calls flt_init() for all proxies, see above */
static int
flt_init_all()
{
	struct proxy *px;
	int err_code = ERR_NONE;

	list_for_each_entry(px, &main_proxies, el) {
		if (px->flags & (PR_FL_DISABLED|PR_FL_STOPPED))
			continue;

		err_code |= flt_init(px);
		if (err_code & (ERR_ABORT|ERR_FATAL)) {
			ha_alert("Failed to initialize filters for proxy '%s'.\n",
				 px->id);
			return err_code;
		}
	}
	return 0;
}

/* Calls flt_init_per_thread() for all proxies, see above.  Be careful here, it
 * returns 0 if an error occurred. This is the opposite of flt_init_all. */
static int
flt_init_all_per_thread()
{
	struct proxy *px;
	int err_code = 0;

	list_for_each_entry(px, &main_proxies, el) {
		if (px->flags & (PR_FL_DISABLED|PR_FL_STOPPED))
			continue;

		err_code = flt_init_per_thread(px);
		if (err_code & (ERR_ABORT|ERR_FATAL)) {
			ha_alert("Failed to initialize filters for proxy '%s' for thread %u.\n",
				 px->id, tid);
			return 0;
		}
	}
	return 1;
}

/*
 * Calls 'check' callback for all filters attached to a proxy. This happens
 * after the configuration parsing but before filters initialization. Returns
 * the number of encountered errors.
 */
/* Note: for now, only the legacy filters (px->filter_configs) are handled
 * here. When the filter instances are attached to the evaluation path, we
 * will have to choose between the legacy mode and the instances mode, and
 * iterate the right list here. Do not forget!
 */
int
flt_check(struct proxy *proxy)
{
	struct flt_conf *fconf;
	int err = 0;

	err += check_implicit_decomp_flt(proxy);
	err += check_implicit_http_comp_flt(proxy);
	list_for_each_entry(fconf, &proxy->filter_configs, list) {
		if (fconf->ops->check)
			err += fconf->ops->check(proxy, fconf);
	}
	return err;
}

/* Calls 'check' callback for all finalized filter instances of the proxy
 * <px>, during the post-proxy-check stage (the instances are not
 * finalized yet during the configuration checks, see flt_check()). Returns
 * a combination of ERR_* flags, ERR_NONE on success.
 */
static int flt_check_instances(struct proxy *px)
{
	struct filter_instance *inst;
	struct flt_conf *fconf;
	int err = 0;

	list_for_each_entry(inst, &px->filter_req_instances, req.list) {
		fconf = inst->fconf;
		if (!fconf)
			continue;
		if (fconf->ops->check)
			err += fconf->ops->check(px, fconf);
	}
	list_for_each_entry(inst, &px->filter_res_instances, res.list) {
		if (LIST_INLIST(&inst->req.list))
			continue; /* already handled from the request side */
		fconf = inst->fconf;
		if (!fconf)
			continue;
		if (fconf->ops->check)
			err += fconf->ops->check(px, fconf);
	}
	if (err)
		err = ERR_ALERT | ERR_FATAL;
	return err;
}

/*
 * Calls 'deinit' callback for all filters attached to a proxy. This happens
 * when HAProxy is stopped.
 *
 * The callback is called for the legacy filters (px->filter_configs) and
 * for the finalized filter instances (inst->fconf). Nothing is shared
 * between the legacy filters and the instances. When the instances are
 * attached to the evaluation path, the legacy mode or the instances mode
 * will be chosen and only the corresponding list will be iterated here.
 */
void
flt_deinit(struct proxy *proxy)
{
	struct filter_instance *inst;
	struct flt_conf *fconf, *back;

	list_for_each_entry_safe(fconf, back, &proxy->filter_configs, list) {
		if (fconf->ops->deinit)
			fconf->ops->deinit(proxy, fconf);
		LIST_DELETE(&fconf->list);
		free(fconf);
	}
	list_for_each_entry(inst, &proxy->filter_req_instances, req.list) {
		fconf = inst->fconf;
		if (!fconf)
			continue;
		if (fconf->ops->deinit)
			fconf->ops->deinit(proxy, fconf);
	}
	list_for_each_entry(inst, &proxy->filter_res_instances, res.list) {
		if (LIST_INLIST(&inst->req.list))
			continue; /* already handled from the request side */
		fconf = inst->fconf;
		if (fconf && fconf->ops && fconf->ops->deinit)
			fconf->ops->deinit(proxy, fconf);
	}
	flt_free_instances(proxy);
}

/*
 * Calls 'deinit_per_thread' callback for all filters attached to a proxy for
 * each threads. This happens before exiting a thread.
 *
 * The callback is called for the legacy filters (px->filter_configs) and
 * for the finalized filter instances (inst->fconf), iterating the flat
 * per-side lists of the proxy.
 */
void
flt_deinit_per_thread(struct proxy *proxy)
{
	struct filter_instance *inst;
	struct flt_conf *fconf, *back;

	list_for_each_entry_safe(fconf, back, &proxy->filter_configs, list) {
		if (fconf->ops->deinit_per_thread)
			fconf->ops->deinit_per_thread(proxy, fconf);
	}
	list_for_each_entry(inst, &proxy->filter_req_instances, req.list) {
		fconf = inst->fconf;
		if (!fconf)
			continue;
		if (fconf->ops->deinit_per_thread)
			fconf->ops->deinit_per_thread(proxy, fconf);
	}
	list_for_each_entry(inst, &proxy->filter_res_instances, res.list) {
		if (LIST_INLIST(&inst->req.list))
			continue; /* already handled from the request side */
		fconf = inst->fconf;
		if (!fconf)
			continue;
		if (fconf->ops->deinit_per_thread)
			fconf->ops->deinit_per_thread(proxy, fconf);
	}
}


/* Calls flt_deinit_per_thread() for all proxies, see above */
static void
flt_deinit_all_per_thread()
{
	struct proxy *px;

	list_for_each_entry(px, &main_proxies, el)
		flt_deinit_per_thread(px);
}

/* Attaches a filter to a stream. Returns -1 if an error occurs, 0 otherwise. */
static int
flt_stream_add_filter(struct stream *s, struct flt_conf *fconf, unsigned int flags)
{
	struct filter *f;

	if (IS_HTX_STRM(s) && !(fconf->flags & FLT_CFG_FL_HTX))
		return 0;

	f = pool_zalloc(pool_head_filter);
	if (!f) /* not enough memory */
		return -1;
	f->config = fconf;
	f->flags |= flags;

	if (FLT_OPS(f)->attach) {
		struct thread_exec_ctx exec_ctx = EXEC_CTX_MAKE(TH_EX_CTX_FLT, f->config);
		int ret = EXEC_CTX_WITH_RET(exec_ctx, FLT_OPS(f)->attach(s, f));
		if (ret <= 0) {
			pool_free(pool_head_filter, f);
			return ret;
		}
	}

	LIST_APPEND(&strm_flt(s)->filters, &f->list);

	/* for now f->req_list == f->res_list to preserve
	 * historical behavior, but the ordering will change
	 * in the future
	 */
	LIST_APPEND(&s->req.flt.filters, &f->req_list);
	LIST_APPEND(&s->res.flt.filters, &f->res_list);

	strm_flt(s)->flags |= STRM_FLT_FL_HAS_FILTERS;
	return 0;
}

/*
 * Called when a stream is created. It attaches all frontend filters to the
 * stream. Returns -1 if an error occurs, 0 otherwise.
 */
int
flt_stream_init(struct stream *s)
{
	struct flt_conf *fconf;

	memset(strm_flt(s), 0, sizeof(*strm_flt(s)));
	LIST_INIT(&strm_flt(s)->filters);
	memset(&s->req.flt, 0, sizeof(s->req.flt));
	LIST_INIT(&s->req.flt.filters);
	memset(&s->res.flt, 0, sizeof(s->res.flt));
	LIST_INIT(&s->res.flt.filters);
	list_for_each_entry(fconf, &strm_fe(s)->filter_configs, list) {
		if (flt_stream_add_filter(s, fconf, 0) < 0)
			return -1;
	}
	return 0;
}

/*
 * Called when a stream is closed or when analyze ends (For an HTTP stream, this
 * happens after each request/response exchange). When analyze ends, backend
 * filters are removed. When the stream is closed, all filters attached to the
 * stream are removed.
 */
void
flt_stream_release(struct stream *s, int only_backend)
{
	struct filter *filter, *back;

	list_for_each_entry_safe(filter, back, &strm_flt(s)->filters, list) {
		if (!only_backend || (filter->flags & FLT_FL_IS_BACKEND_FILTER)) {
			filter->calls++;
			if (FLT_OPS(filter)->detach) {
				struct thread_exec_ctx exec_ctx = EXEC_CTX_MAKE(TH_EX_CTX_FLT, filter->config);
				EXEC_CTX_NO_RET(exec_ctx, FLT_OPS(filter)->detach(s, filter));
			}
			LIST_DELETE(&filter->list);
			LIST_DELETE(&filter->req_list);
			LIST_DELETE(&filter->res_list);
			pool_free(pool_head_filter, filter);
		}
	}
	if (LIST_ISEMPTY(&strm_flt(s)->filters))
		strm_flt(s)->flags &= ~STRM_FLT_FL_HAS_FILTERS;
}

/*
 * Calls 'stream_start' for all filters attached to a stream. This happens when
 * the stream is created, just after calling flt_stream_init
 * function. Returns -1 if an error occurs, 0 otherwise.
 */
int
flt_stream_start(struct stream *s)
{
	struct filter *filter;

	list_for_each_entry(filter, &strm_flt(s)->filters, list) {
		if (FLT_OPS(filter)->stream_start) {
			struct thread_exec_ctx exec_ctx = EXEC_CTX_MAKE(TH_EX_CTX_FLT, filter->config);

			filter->calls++;
			if (EXEC_CTX_WITH_RET(exec_ctx, FLT_OPS(filter)->stream_start(s, filter) < 0)) {
				s->last_entity.type = STRM_ENTITY_FILTER;
				s->last_entity.ptr = filter;
				return -1;
			}
		}
	}
	if (strm_li(s) && (strm_li(s)->bind_conf->analysers & AN_REQ_FLT_START_FE)) {
		s->req.flags |= CF_FLT_ANALYZE;
		s->req.analysers |= AN_REQ_FLT_END;
	}
	return 0;
}

/*
 * Calls 'stream_stop' for all filters attached to a stream. This happens when
 * the stream is stopped, just before calling flt_stream_release function.
 */
void
flt_stream_stop(struct stream *s)
{
	struct filter *filter;

	list_for_each_entry(filter, &strm_flt(s)->filters, list) {
		if (FLT_OPS(filter)->stream_stop) {
			struct thread_exec_ctx exec_ctx = EXEC_CTX_MAKE(TH_EX_CTX_FLT, filter->config);

			filter->calls++;
			EXEC_CTX_NO_RET(exec_ctx, FLT_OPS(filter)->stream_stop(s, filter));
		}
	}
}

/*
 * Calls 'check_timeouts' for all filters attached to a stream. This happens when
 * the stream is woken up because of expired timer.
 */
void
flt_stream_check_timeouts(struct stream *s)
{
	struct filter *filter;

	list_for_each_entry(filter, &strm_flt(s)->filters, list) {
		if (FLT_OPS(filter)->check_timeouts) {
			struct thread_exec_ctx exec_ctx = EXEC_CTX_MAKE(TH_EX_CTX_FLT, filter->config);

			filter->calls++;
			EXEC_CTX_NO_RET(exec_ctx, FLT_OPS(filter)->check_timeouts(s, filter));
		}
	}
}

/*
 * Called when a backend is set for a stream. If the frontend and the backend
 * are not the same, this function attaches all backend filters to the
 * stream. Returns -1 if an error occurs, 0 otherwise.
 */
int
flt_set_stream_backend(struct stream *s, struct proxy *be)
{
	struct flt_conf *fconf;
	struct filter   *filter;

	if (strm_fe(s) == be)
		goto end;

	list_for_each_entry(fconf, &be->filter_configs, list) {
		if (flt_stream_add_filter(s, fconf, FLT_FL_IS_BACKEND_FILTER) < 0)
			return -1;
	}

  end:
	list_for_each_entry(filter, &strm_flt(s)->filters, list) {
		if (FLT_OPS(filter)->stream_set_backend) {
			struct thread_exec_ctx exec_ctx = EXEC_CTX_MAKE(TH_EX_CTX_FLT, filter->config);

			filter->calls++;
			if (EXEC_CTX_WITH_RET(exec_ctx, FLT_OPS(filter)->stream_set_backend(s, filter, be) < 0)) {
				s->last_entity.type = STRM_ENTITY_FILTER;
				s->last_entity.ptr = filter;
				return -1;
			}
		}
	}
	if (be->be_req_ana & AN_REQ_FLT_START_BE) {
		s->req.flags |= CF_FLT_ANALYZE;
		s->req.analysers |= AN_REQ_FLT_END;
	}
	if ((strm_fe(s)->fe_rsp_ana | be->be_rsp_ana) & (AN_RES_FLT_START_FE|AN_RES_FLT_START_BE)) {
		s->res.flags |= CF_FLT_ANALYZE;
		s->res.analysers |= AN_RES_FLT_END;
	}

	return 0;
}


/*
 * Calls 'http_end' callback for all filters attached to a stream. All filters
 * are called here, but only if there is at least one "data" filter. This
 * functions is called when all data were parsed and forwarded. 'http_end'
 * callback is resumable, so this function returns a negative value if an error
 * occurs, 0 if it needs to wait for some reason, any other value otherwise.
 */
int
flt_http_end(struct stream *s, struct http_msg *msg)
{
	struct filter *filter;
	unsigned long long *strm_off = &FLT_STRM_OFF(s, msg->chn);
	unsigned int offset = 0;
	int ret = 1;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_FLT_ANA, s,
			s->txn.http, msg);
	for (filter = resume_filter_list_start(s, msg->chn); filter;
	     filter = resume_filter_list_next(s, msg->chn, filter)) {
		unsigned long long flt_off = FLT_OFF(filter, msg->chn);
		offset = flt_off - *strm_off;

		/* Call http_end for data filters only. But the filter offset is
		 * still valid for all filters
		 . */
		if (!IS_DATA_FILTER(filter, msg->chn))
			continue;

		if (FLT_OPS(filter)->http_end) {
			struct thread_exec_ctx exec_ctx = EXEC_CTX_MAKE(TH_EX_CTX_FLT, filter->config);

			DBG_TRACE_DEVEL(FLT_ID(filter), STRM_EV_HTTP_ANA|STRM_EV_FLT_ANA, s);
			filter->calls++;
			ret = EXEC_CTX_WITH_RET(exec_ctx, FLT_OPS(filter)->http_end(s, filter, msg));
			if (ret <= 0) {
				resume_filter_list_break(s, msg->chn, filter, ret);
				goto end;
			}
		}
	}

	c_adv(msg->chn, offset);
	*strm_off += offset;

end:
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_FLT_ANA, s);
	return ret;
}

/*
 * Calls 'http_reset' callback for all filters attached to a stream. This
 * happens when a 100-continue response is received.
 */
void
flt_http_reset(struct stream *s, struct http_msg *msg)
{
	struct filter *filter;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_FLT_ANA, s,
			s->txn.http, msg);
	for (filter = flt_list_start(s, msg->chn); filter;
	     filter = flt_list_next(s, msg->chn, filter)) {
		if (FLT_OPS(filter)->http_reset) {
			struct thread_exec_ctx exec_ctx = EXEC_CTX_MAKE(TH_EX_CTX_FLT, filter->config);

			DBG_TRACE_DEVEL(FLT_ID(filter), STRM_EV_HTTP_ANA|STRM_EV_FLT_ANA, s);
			filter->calls++;
			EXEC_CTX_NO_RET(exec_ctx, FLT_OPS(filter)->http_reset(s, filter, msg));
		}
	}
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_FLT_ANA, s);
}

/*
 * Calls 'http_reply' callback for all filters attached to a stream when HA
 * decides to stop the HTTP message processing.
 */
void
flt_http_reply(struct stream *s, short status, const struct buffer *msg)
{
	struct filter *filter;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_FLT_ANA, s,
			s->txn.http, msg);
	list_for_each_entry(filter, &strm_flt(s)->filters, list) {
		if (FLT_OPS(filter)->http_reply) {
			struct thread_exec_ctx exec_ctx = EXEC_CTX_MAKE(TH_EX_CTX_FLT, filter->config);

			DBG_TRACE_DEVEL(FLT_ID(filter), STRM_EV_HTTP_ANA|STRM_EV_FLT_ANA, s);
			filter->calls++;
			EXEC_CTX_NO_RET(exec_ctx, FLT_OPS(filter)->http_reply(s, filter, status, msg));
		}
	}
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_FLT_ANA, s);
}

/*
 * Calls 'http_payload' callback for all "data" filters attached to a
 * stream. This function is called when some data can be forwarded in the
 * AN_REQ_HTTP_XFER_BODY and AN_RES_HTTP_XFER_BODY analyzers. It takes care to
 * update the filters and the stream offset to be sure that a filter cannot
 * forward more data than its predecessors. A filter can choose to not forward
 * all data. Returns a negative value if an error occurs, else the number of
 * forwarded bytes.
 */
int
flt_http_payload(struct stream *s, struct http_msg *msg, unsigned int len)
{
	struct filter *filter;
	unsigned long long *strm_off = &FLT_STRM_OFF(s, msg->chn);
	unsigned int out = co_data(msg->chn);
	int ret, data;

	strm_flt(s)->flags &= ~STRM_FLT_FL_HOLD_HTTP_HDRS;

	ret = data = len - out;
	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_FLT_ANA, s,
			s->txn.http, msg);
	for (filter = flt_list_start(s, msg->chn); filter;
	     filter = flt_list_next(s, msg->chn, filter)) {
		struct thread_exec_ctx exec_ctx = EXEC_CTX_MAKE(TH_EX_CTX_FLT, filter->config);
		unsigned long long *flt_off = &FLT_OFF(filter, msg->chn);
		unsigned int offset = *flt_off - *strm_off;

		/* Call http_payload for filters only. Forward all data for
		 * others and update the filter offset
		 */
		if (!IS_DATA_FILTER(filter, msg->chn) || !FLT_OPS(filter)->http_payload) {
			*flt_off += data - offset;
			continue;
		}

		DBG_TRACE_DEVEL(FLT_ID(filter), STRM_EV_HTTP_ANA|STRM_EV_FLT_ANA, s);
		filter->calls++;
		ret = EXEC_CTX_WITH_RET(exec_ctx, FLT_OPS(filter)->http_payload(s, filter, msg, out + offset, data - offset));
		if (ret < 0) {
			resume_filter_list_break(s, msg->chn, filter, ret);
			goto end;
		}
		data = ret + *flt_off - *strm_off;
		*flt_off += ret;
	}

	/* If nothing was forwarded yet, we take care to hold the headers if
	 * following conditions are met :
	 *
	 *  - *strm_off == 0 (nothing forwarded yet)
	 *  - ret == 0       (no data forwarded at all on this turn)
	 *  - STRM_FLT_FL_HOLD_HTTP_HDRS flag set (at least one filter want to hold the headers)
	 *
	 * Be careful, STRM_FLT_FL_HOLD_HTTP_HDRS is removed before each http_payload loop.
	 * Thus, it must explicitly be set when necessary. We must do that to hold the headers
	 * when there is no payload.
	 */
	if (!ret && !*strm_off && (strm_flt(s)->flags & STRM_FLT_FL_HOLD_HTTP_HDRS))
		goto end;

	ret = data;
	*strm_off += ret;
 end:
	chn_prod(msg->chn)->sedesc->kip = 0;
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_FLT_ANA, s);
	return ret;
}

/*
 * Calls 'channel_start_analyze' callback for all filters attached to a
 * stream. This function is called when we start to analyze a request or a
 * response. For frontend filters, it is called before all other analyzers. For
 * backend ones, it is called before all backend
 * analyzers. 'channel_start_analyze' callback is resumable, so this function
 * returns 0 if an error occurs or if it needs to wait, any other value
 * otherwise.
 */
int
flt_start_analyze(struct stream *s, struct channel *chn, unsigned int an_bit)
{
	struct filter *filter;
	int ret = 1;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_FLT_ANA, s);

	/* If this function is called, this means there is at least one filter,
	 * so we do not need to check the filter list's emptiness. */

	/* Set flag on channel to tell that the channel is filtered */
	chn->flags |= CF_FLT_ANALYZE;
	chn->analysers |= ((chn->flags & CF_ISRESP) ? AN_RES_FLT_END : AN_REQ_FLT_END);

	for (filter = resume_filter_list_start(s, chn); filter;
	     filter = resume_filter_list_next(s, chn, filter)) {
		if (!(chn->flags & CF_ISRESP)) {
			if (an_bit == AN_REQ_FLT_START_BE &&
			    !(filter->flags & FLT_FL_IS_BACKEND_FILTER))
				continue;
		}
		else {
			if (an_bit == AN_RES_FLT_START_BE &&
			    !(filter->flags & FLT_FL_IS_BACKEND_FILTER))
				continue;
		}

		FLT_OFF(filter, chn) = 0;
		if (FLT_OPS(filter)->channel_start_analyze) {
			struct thread_exec_ctx exec_ctx = EXEC_CTX_MAKE(TH_EX_CTX_FLT, filter->config);

			DBG_TRACE_DEVEL(FLT_ID(filter), STRM_EV_FLT_ANA, s);
			filter->calls++;
			ret = EXEC_CTX_WITH_RET(exec_ctx, FLT_OPS(filter)->channel_start_analyze(s, filter, chn));
			if (ret <= 0) {
				resume_filter_list_break(s, chn, filter, ret);
				goto end;
			}
		}
	}

 end:
	ret = handle_analyzer_result(s, chn, an_bit, ret);
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_FLT_ANA, s);
	return ret;
}

/*
 * Calls 'channel_pre_analyze' callback for all filters attached to a
 * stream. This function is called BEFORE each analyzer attached to a channel,
 * expects analyzers responsible for data sending. 'channel_pre_analyze'
 * callback is resumable, so this function returns 0 if an error occurs or if it
 * needs to wait, any other value otherwise.
 *
 * Note this function can be called many times for the same analyzer. In fact,
 * it is called until the analyzer finishes its processing.
 */
int
flt_pre_analyze(struct stream *s, struct channel *chn, unsigned int an_bit)
{
	struct filter *filter;
	int ret = 1;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_FLT_ANA, s);

	for (filter = resume_filter_list_start(s, chn); filter;
	     filter = resume_filter_list_next(s, chn, filter)) {
		if (FLT_OPS(filter)->channel_pre_analyze && (filter->pre_analyzers & an_bit)) {
			struct thread_exec_ctx exec_ctx = EXEC_CTX_MAKE(TH_EX_CTX_FLT, filter->config);

			DBG_TRACE_DEVEL(FLT_ID(filter), STRM_EV_FLT_ANA, s);
			filter->calls++;
			ret = EXEC_CTX_WITH_RET(exec_ctx, FLT_OPS(filter)->channel_pre_analyze(s, filter, chn, an_bit));
			if (ret <= 0) {
				resume_filter_list_break(s, chn, filter, ret);
				goto check_result;
			}
			filter->pre_analyzers &= ~an_bit;
		}
	}

 check_result:
	ret = handle_analyzer_result(s, chn, 0, ret);
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_FLT_ANA, s);
	return ret;
}

/*
 * Calls 'channel_post_analyze' callback for all filters attached to a
 * stream. This function is called AFTER each analyzer attached to a channel,
 * expects analyzers responsible for data sending. 'channel_post_analyze'
 * callback is NOT resumable, so this function returns a 0 if an error occurs,
 * any other value otherwise.
 *
 * Here, AFTER means when the analyzer finishes its processing.
 */
int
flt_post_analyze(struct stream *s, struct channel *chn, unsigned int an_bit)
{
	struct filter *filter;
	int            ret = 1;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_FLT_ANA, s);

	for (filter = flt_list_start(s, chn); filter;
	     filter = flt_list_next(s, chn, filter)) {
		if (FLT_OPS(filter)->channel_post_analyze &&  (filter->post_analyzers & an_bit)) {
			struct thread_exec_ctx exec_ctx = EXEC_CTX_MAKE(TH_EX_CTX_FLT, filter->config);

			DBG_TRACE_DEVEL(FLT_ID(filter), STRM_EV_FLT_ANA, s);
			filter->calls++;
			ret = EXEC_CTX_WITH_RET(exec_ctx, FLT_OPS(filter)->channel_post_analyze(s, filter, chn, an_bit));
			if (ret < 0) {
				resume_filter_list_break(s, chn, filter, ret);
				break;
			}
			filter->post_analyzers &= ~an_bit;
		}
	}
	ret = handle_analyzer_result(s, chn, 0, ret);
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_FLT_ANA, s);
	return ret;
}

/*
 * This function is the AN_REQ/RES_FLT_HTTP_HDRS analyzer, used to filter HTTP
 * headers or a request or a response. Returns 0 if an error occurs or if it
 * needs to wait, any other value otherwise.
 */
int
flt_analyze_http_headers(struct stream *s, struct channel *chn, unsigned int an_bit)
{
	struct http_msg *msg;
	struct filter *filter;
	int              ret = 1;

	msg = ((chn->flags & CF_ISRESP) ? &s->txn.http->rsp : &s->txn.http->req);
	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_FLT_ANA, s,
			s->txn.http, msg);

	for (filter = resume_filter_list_start(s, chn); filter;
	     filter = resume_filter_list_next(s, chn, filter)) {
		if (FLT_OPS(filter)->http_headers) {
			struct thread_exec_ctx exec_ctx = EXEC_CTX_MAKE(TH_EX_CTX_FLT, filter->config);

			DBG_TRACE_DEVEL(FLT_ID(filter), STRM_EV_HTTP_ANA|STRM_EV_FLT_ANA, s);
			filter->calls++;
			ret = EXEC_CTX_WITH_RET(exec_ctx, FLT_OPS(filter)->http_headers(s, filter, msg));
			if (ret <= 0) {
				resume_filter_list_break(s, chn, filter, ret);
				goto check_result;
			}
		}
	}

	if (HAS_DATA_FILTERS(s, chn)) {
		size_t data = http_get_hdrs_size(htxbuf(&chn->buf));
		struct filter *f;

		for (f = flt_list_start(s, chn); f;
		     f = flt_list_next(s, chn, f))
			FLT_OFF(f, chn) = data;
	}

 check_result:
	ret = handle_analyzer_result(s, chn, an_bit, ret);
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_HTTP_ANA|STRM_EV_FLT_ANA, s);
	return ret;
}

/*
 * Calls 'channel_end_analyze' callback for all filters attached to a
 * stream. This function is called when we stop to analyze a request or a
 * response. It is called after all other analyzers. 'channel_end_analyze'
 * callback is resumable, so this function returns 0 if an error occurs or if it
 * needs to wait, any other value otherwise.
 */
int
flt_end_analyze(struct stream *s, struct channel *chn, unsigned int an_bit)
{
	int ret = 1;
	struct filter *filter;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_FLT_ANA, s);

	/* Check if all filters attached on the stream have finished their
	 * processing on this channel. */
	if (!(chn->flags & CF_FLT_ANALYZE))
		goto sync;

	for (filter = resume_filter_list_start(s, chn); filter;
	     filter = resume_filter_list_next(s, chn, filter)) {
		FLT_OFF(filter, chn) = 0;
		unregister_data_filter(s, chn, filter);

		if (FLT_OPS(filter)->channel_end_analyze) {
			struct thread_exec_ctx exec_ctx = EXEC_CTX_MAKE(TH_EX_CTX_FLT, filter->config);

			DBG_TRACE_DEVEL(FLT_ID(filter), STRM_EV_FLT_ANA, s);
			filter->calls++;
			ret = EXEC_CTX_WITH_RET(exec_ctx, FLT_OPS(filter)->channel_end_analyze(s, filter, chn));
			if (ret <= 0) {
				resume_filter_list_break(s, chn, filter, ret);
				goto end;
			}
		}
	}

 end:
	/* We don't remove yet this analyzer because we need to synchronize the
	 * both channels. So here, we just remove the flag CF_FLT_ANALYZE. */
	ret = handle_analyzer_result(s, chn, 0, ret);
	if (ret) {
		chn->flags &= ~CF_FLT_ANALYZE;

		/* Pretend there is an activity on both channels. Flag on the
		 * current one will be automatically removed, so only the other
		 * one will remain. This is a way to be sure that
		 * 'channel_end_analyze' callback will have a chance to be
		 * called at least once for the other side to finish the current
		 * processing. Of course, this is the filter responsibility to
		 * wakeup the stream if it choose to loop on this callback. */
		s->req.flags |= CF_WAKE_ONCE;
		s->res.flags |= CF_WAKE_ONCE;
	}


 sync:
	/* Now we can check if filters have finished their work on the both
	 * channels */
	if (!(s->req.flags & CF_FLT_ANALYZE) && !(s->res.flags & CF_FLT_ANALYZE)) {
		/* Sync channels by removing this analyzer for the both channels */
		s->req.analysers &= ~AN_REQ_FLT_END;
		s->res.analysers &= ~AN_RES_FLT_END;

		/* Remove backend filters from the list */
		flt_stream_release(s, 1);
		DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_FLT_ANA, s);
	}
	else {
		DBG_TRACE_DEVEL("waiting for sync", STRM_EV_STRM_ANA|STRM_EV_FLT_ANA, s);
	}
	return ret;
}


/*
 * Calls 'tcp_payload' callback for all "data" filters attached to a
 * stream. This function is called when some data can be forwarded in the
 * AN_REQ_FLT_XFER_BODY and AN_RES_FLT_XFER_BODY analyzers. It takes care to
 * update the filters and the stream offset to be sure that a filter cannot
 * forward more data than its predecessors. A filter can choose to not forward
 * all data. Returns a negative value if an error occurs, else the number of
 * forwarded bytes.
 */
int
flt_tcp_payload(struct stream *s, struct channel *chn, unsigned int len)
{
	struct filter *filter;
	unsigned long long *strm_off = &FLT_STRM_OFF(s, chn);
	unsigned int out = co_data(chn);
	int ret, data;

	ret = data = len - out;
	DBG_TRACE_ENTER(STRM_EV_TCP_ANA|STRM_EV_FLT_ANA, s);
	for (filter = flt_list_start(s, chn); filter;
	     filter = flt_list_next(s, chn, filter)) {
		struct thread_exec_ctx exec_ctx = EXEC_CTX_MAKE(TH_EX_CTX_FLT, filter->config);
		unsigned long long *flt_off = &FLT_OFF(filter, chn);
		unsigned int offset = *flt_off - *strm_off;

		/* Call tcp_payload for filters only. Forward all data for
		 * others and update the filter offset
		 */
		if (!IS_DATA_FILTER(filter, chn) || !FLT_OPS(filter)->tcp_payload) {
			*flt_off += data - offset;
			continue;
		}

		DBG_TRACE_DEVEL(FLT_ID(filter), STRM_EV_TCP_ANA|STRM_EV_FLT_ANA, s);
		filter->calls++;
		ret = EXEC_CTX_WITH_RET(exec_ctx, FLT_OPS(filter)->tcp_payload(s, filter, chn, out + offset, data - offset));
		if (ret < 0) {
			resume_filter_list_break(s, chn, filter, ret);
			goto end;
		}
		data = ret + *flt_off - *strm_off;
		*flt_off += ret;
	}

	/* Only forward data if the last filter decides to forward something */
	if (ret > 0) {
		ret = data;
		*strm_off += ret;
	}
 end:
	chn_prod(chn)->sedesc->kip = 0;
	DBG_TRACE_LEAVE(STRM_EV_TCP_ANA|STRM_EV_FLT_ANA, s);
	return ret;
}

/*
 * Called when TCP data must be filtered on a channel. This function is the
 * AN_REQ/RES_FLT_XFER_DATA analyzer. When called, it is responsible to forward
 * data when the proxy is not in http mode. Behind the scene, it calls
 * consecutively 'tcp_data' and 'tcp_forward_data' callbacks for all "data"
 * filters attached to a stream. Returns 0 if an error occurs or if it needs to
 * wait, any other value otherwise.
 */
int
flt_xfer_data(struct stream *s, struct channel *chn, unsigned int an_bit)
{
	unsigned int len;
	int ret = 1;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_TCP_ANA|STRM_EV_FLT_ANA, s);

	/* If there is no "data" filters, we do nothing */
	if (!HAS_DATA_FILTERS(s, chn))
		goto end;

	if (s->flags & SF_HTX) {
		struct htx *htx = htxbuf(&chn->buf);
		len = htx->data;
	}
	else
		len = c_data(chn);

	ret = flt_tcp_payload(s, chn, len);
	if (ret < 0)
		goto end;
	c_adv(chn, ret);

	/* Stop waiting data if:
	 *  - it the output is closed
	 *  - the input in closed and no data is pending
	 *  - There is a READ/WRITE timeout
	 */
	if (chn_cons(chn)->flags & SC_FL_SHUT_DONE) {
		ret = 1;
		goto end;
	}
	if (chn_prod(chn)->flags & (SC_FL_ABRT_DONE|SC_FL_EOS)) {
		if (((s->flags & SF_HTX) && htx_is_empty(htxbuf(&chn->buf))) || c_empty(chn)) {
			ret = 1;
			goto end;
		}
	}
	if (chn->flags & (CF_READ_TIMEOUT|CF_WRITE_TIMEOUT)) {
		ret = 1;
		goto end;
	}

	/* Wait for data */
	DBG_TRACE_DEVEL("waiting for more data", STRM_EV_STRM_ANA|STRM_EV_TCP_ANA|STRM_EV_FLT_ANA, s);

	/* DATA filtering is not finished and some data may still be blocked in
	 * the channel. So take care to disable auto close
	 */
	if (HAS_DATA_FILTERS(s, chn))
		channel_dont_close(chn);

	return 0;

 end:
	/* Terminate the data filtering. If <ret> is negative, an error was
	 * encountered during the filtering. */
	ret = handle_analyzer_result(s, chn, an_bit, ret);
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_TCP_ANA|STRM_EV_FLT_ANA, s);
	return ret;
}

/*
 * Handles result of filter's analyzers. It returns 0 if an error occurs or if
 * it needs to wait, any other value otherwise.
 */
static int
handle_analyzer_result(struct stream *s, struct channel *chn,
		       unsigned int an_bit, int ret)
{
	if (ret < 0)
		goto return_bad_req;
	else if (!ret)
		goto wait;

	/* End of job, return OK */
	if (an_bit) {
		chn->analysers  &= ~an_bit;
		chn->analyse_exp = TICK_ETERNITY;
	}
	return 1;

 return_bad_req:
	/* An error occurs */
	if (IS_HTX_STRM(s)) {
		http_set_term_flags(s);

		if (s->txn.http->status > 0)
			http_reply_and_close(s, s->txn.http->status, NULL);
		else {
			s->txn.http->status = (!(chn->flags & CF_ISRESP)) ? 400 : 502;
			http_reply_and_close(s, s->txn.http->status,
					     http_error_message(s));
		}
	}
	else {
		sess_set_term_flags(s);
		stream_retnclose(s, NULL);
	}

	if (!(chn->flags & CF_ISRESP))
		s->req.analysers &= AN_REQ_FLT_END;
	else
		s->res.analysers &= AN_RES_FLT_END;


	DBG_TRACE_DEVEL("leaving on error", STRM_EV_FLT_ANA|STRM_EV_FLT_ERR, s);
	return 0;

 wait:
	if (!(chn->flags & CF_ISRESP))
		channel_dont_connect(chn);
	DBG_TRACE_DEVEL("wairing for more data", STRM_EV_FLT_ANA, s);
	return 0;
}

/* Iterates over the instances of the list <instances> for side <side>,
 * recursively. <fct> is called for each instance and must return 0 to
 * continue, any other value to stop immediately; that value is then returned.
 *
 * Note: it must only be used on loop-free structures (the sequence loop
 * detection runs after the sequences are applied, and aborts the startup
 * on a loop).
 */
static int flt_foreach_instance(struct list *instances, unsigned int side,
			   int (*fct)(struct filter_instance *inst, void *data), void *data)
{
	struct filter_instance *inst;
	int ret;

	if (side == FLT_SIDE_REQ) {
		list_for_each_entry(inst, instances, req.list) {
			ret = fct(inst, data);
			if (ret)
				return ret;
			ret = flt_foreach_instance(&inst->req.reordered_before, side, fct, data);
			if (ret)
				return ret;
			ret = flt_foreach_instance(&inst->req.reordered_after, side, fct, data);
			if (ret)
				return ret;
		}
	}
	else {
		list_for_each_entry(inst, instances, res.list) {
			ret = fct(inst, data);
			if (ret)
				return ret;
			ret = flt_foreach_instance(&inst->res.reordered_before, side, fct, data);
			if (ret)
				return ret;
			ret = flt_foreach_instance(&inst->res.reordered_after, side, fct, data);
			if (ret)
				return ret;
		}
	}
	return 0;
}

/* Iterates over all the instances of the proxy <px> for side <side>,
 * recursively.
 */
static int flt_foreach_instance_side(struct proxy *px, unsigned int side,
				int (*fct)(struct filter_instance *inst, void *data), void *data)
{
	struct list *refs = (side == FLT_SIDE_REQ ? &px->conf.filter_classes_req : &px->conf.filter_classes_res);
	struct filter_class_ref *ref;
	int ret;

	list_for_each_entry(ref, refs, list) {
		ret = flt_foreach_instance(&ref->instances, side, fct, data);
		if (ret)
			return ret;
		ret = flt_foreach_instance(&ref->reordered_before, side, fct, data);
		if (ret)
			return ret;
		ret = flt_foreach_instance(&ref->reordered_after, side, fct, data);
		if (ret)
			return ret;
	}
	return 0;
}

/* Finds the class reference of the class <cls> in the proxy <px> for side
 * <side>.
 * Returns the class reference, or NULL if not found for the given side.
 */
static struct filter_class_ref *flt_get_class_ref(struct proxy *px, struct filter_class *cls,
						  unsigned int side)
{
	struct list *refs = (side == FLT_SIDE_REQ ? &px->conf.filter_classes_req : &px->conf.filter_classes_res);
	struct filter_class_ref *ref;

	list_for_each_entry(ref, refs, list) {
		if (ref->class == cls)
			return ref;
	}
	return NULL;
}

/* Context for flt_match_instance_cb() */
struct flt_match_instance_ctx {
	struct filter_class *cls;   /* the class to match */
	const char *id;             /* the id to match, NULL for any id */
	unsigned int side;          /* the side being iterated (FLT_SIDE_REQ or FLT_SIDE_RES) */
	struct filter_instance *found; /* the first matching instance, if any */
	int count;                  /* the number of matching instances */
};

/* Callback matching the instances of the class ctx->cls with the id
 * ctx->id (any id if NULL). The first match is recorded in ctx->found and
 * the matches are counted in ctx->count (a instance of a class placed on
 * both sides is counted once). With an id, the iteration stops at the
 * first match.
 */
static int flt_match_instance_cb(struct filter_instance *inst, void *data)
{
	struct flt_match_instance_ctx *ctx = data;

	if (inst->class != ctx->cls)
		return 0;
	if (ctx->side == FLT_SIDE_RES && LIST_INLIST(&inst->req.list))
		return 0; /* already matched from the request side */
	if (ctx->id && (!inst->id || strcmp(inst->id, ctx->id) != 0))
		return 0;
	if (!ctx->found)
		ctx->found = inst;
	ctx->count++;
	return ctx->id ? 1 : 0;
}

/* Context for flt_enable_cb() */
struct flt_enable_ctx {
	struct filter_class *cls;   /* the class to match */
	const char *id;             /* the id to match, NULL for any id */
	unsigned int enable;        /* the value to set inst->enabled to */
	int found;                  /* the number of matching instances */
};

/* Callback enabling/disabling the matching instances with ctx->enable. */
static int flt_enable_cb(struct filter_instance *inst, void *data)
{
	struct flt_enable_ctx *ctx = data;

	if (inst->class != ctx->cls)
		return 0;
	if (ctx->id && (!inst->id || strcmp(inst->id, ctx->id) != 0))
		return 0;
	inst->enabled = ctx->enable;
	ctx->found++;
	return 0;
}

/* Finds the filter instance of the class <cls> with the id <id> in the proxy
 * <px>. If <id> is NULL, the first instance of the class is returned.  The
 * number of matching instances is returned in <*count> if not NULL.
 * Returns NULL if not found.
 */
static struct filter_instance *flt_find_instance_count(struct proxy *px, struct filter_class *cls,
						   const char *id, int *count)
{
	struct flt_match_instance_ctx ctx = { .cls = cls, .id = id, .found = NULL, .count = 0 };

	/* instances are in the flat per-side lists of the proxy, or in the
	 * class references if the configuration was not flattened yet (or
	 * for the defaults sections): the request side first, then the
	 * response side
	 */
	ctx.side = FLT_SIDE_REQ;
	if (flt_foreach_instance(&px->filter_req_instances, FLT_SIDE_REQ, flt_match_instance_cb, &ctx) && ctx.found)
		goto end;
	ctx.side = FLT_SIDE_RES;
	if (flt_foreach_instance(&px->filter_res_instances, FLT_SIDE_RES, flt_match_instance_cb, &ctx) && ctx.found)
		goto end;
	ctx.side = FLT_SIDE_REQ;
	if (flt_foreach_instance_side(px, FLT_SIDE_REQ, flt_match_instance_cb, &ctx) && ctx.found)
		goto end;
	ctx.side = FLT_SIDE_RES;
	flt_foreach_instance_side(px, FLT_SIDE_RES, flt_match_instance_cb, &ctx);

  end:
	if (count)
		*count = ctx.count;
	return ctx.found;
}

/* Finds the filter instance of the class <cls> with the id <id> in the proxy
 * <px>. If <id> is NULL, the first instance of the class is returned.
 * Returns NULL if not found.
 */
struct filter_instance *flt_find_instance(struct proxy *px, struct filter_class *cls, const char *id)
{
	return flt_find_instance_count(px, cls, id, NULL);
}


/* Initializes the lists of the filter instance <inst> and links it in the
 * class references of the proxy <px>, on each side the class is placed on.
 * Returns 0 on success, -1 if the class is placed on no side (the
 * instance cannot be evaluated).
 */
static int flt_init_instance(struct filter_instance *inst, struct proxy *px)
{
	struct filter_class_ref *ref;
	int linked = 0;

	inst->px = px;
	LIST_INIT(&inst->req.reordered_before);
	LIST_INIT(&inst->req.reordered_after);
	LIST_INIT(&inst->req.list);
	LIST_INIT(&inst->res.reordered_before);
	LIST_INIT(&inst->res.reordered_after);
	LIST_INIT(&inst->res.list);

	if (LIST_INLIST(&inst->class->req.list)) {
		ref = flt_get_class_ref(px, inst->class, FLT_SIDE_REQ);
		if (!ref)
			return -1;
		LIST_APPEND(&ref->instances, &inst->req.list);
		linked = 1;
	}
	if (LIST_INLIST(&inst->class->res.list)) {
		ref = flt_get_class_ref(px, inst->class, FLT_SIDE_RES);
		if (!ref)
			return -1;
		LIST_APPEND(&ref->instances, &inst->res.list);
		linked = 1;
	}
	return linked ? 0 : -1;
}

/* Frees all filter instances of the proxy <px>, its filter class
 * references, its filter-enable entries and its filter sequences.
 */
void flt_free_instances(struct proxy *px)
{
	struct filter_class_ref *ref, *refback;
	struct filter_enabled *flt_en, *enback;
	struct filter_sequence *seq, *seqback;

	flt_free_inst_list(&px->filter_req_instances, FLT_SIDE_REQ);
	flt_free_inst_list(&px->filter_res_instances, FLT_SIDE_RES);
	list_for_each_entry_safe(ref, refback, &px->conf.filter_classes_req, list) {
		flt_free_inst_list(&ref->instances, FLT_SIDE_REQ);
		flt_free_inst_list(&ref->reordered_before, FLT_SIDE_REQ);
		flt_free_inst_list(&ref->reordered_after, FLT_SIDE_REQ);
		LIST_DELETE(&ref->list);
		free(ref);
	}
	list_for_each_entry_safe(ref, refback, &px->conf.filter_classes_res, list) {
		flt_free_inst_list(&ref->instances, FLT_SIDE_RES);
		flt_free_inst_list(&ref->reordered_before, FLT_SIDE_RES);
		flt_free_inst_list(&ref->reordered_after, FLT_SIDE_RES);
		LIST_DELETE(&ref->list);
		free(ref);
	}
	list_for_each_entry_safe(flt_en, enback, &px->conf.filter_enabled, list)
		flt_free_enabled(flt_en);

	list_for_each_entry_safe(seq, seqback, &px->conf.filter_sequences, list)
		flt_free_sequence(seq);
}

/* Deep-copies the filter instances of the defaults proxy <defpx> into the
 * proxy <px>, so that proxies inherit the filter instances of their
 * defaults section. It must be called before any instance is added to <px>,
 * so that locally defined ones can replace the inherited ones.
 * Returns 0 on success, -1 on error.
 */
static int flt_copy_instance(struct proxy *px, const struct filter_instance *inst)
{
	struct filter_instance *new_inst;
	int i;

	new_inst = calloc(1, sizeof(*new_inst));
	if (!new_inst)
		return -1;

	new_inst->class   = inst->class;
	new_inst->enabled = inst->enabled;
	new_inst->flags   = inst->flags | FLT_INST_F_INHERITED;

	if (inst->id) {
		new_inst->id = strdup(inst->id);
		if (!new_inst->id)
			goto error;
	}
	new_inst->conf.file = strdup(inst->conf.file);
	if (!new_inst->conf.file)
		goto error;
	new_inst->conf.line = inst->conf.line;
	new_inst->conf.argc = inst->conf.argc;
	new_inst->conf.argv = calloc(inst->conf.argc + 1, sizeof(*new_inst->conf.argv));
	if (!new_inst->conf.argv)
		goto error;
	for (i = 0; i < inst->conf.argc; i++) {
		new_inst->conf.argv[i] = strdup(inst->conf.argv[i]);
		if (!new_inst->conf.argv[i])
			goto error;
	}

	if (flt_init_instance(new_inst, px) < 0)
		goto error;
	return 0;

  error:
	flt_free_instance(new_inst);
	return -1;
}

/* Copy all filter deinitions of the defaults proxy <defpx> into the proxy <px>.
 * Returns 0 on success, -1 on error (out of memory).
 */
int flt_copy_instances(struct proxy *px, const struct proxy *defpx)
{
	struct filter_class_ref *ref;
	struct filter_instance *inst;
	struct filter_enabled *flt_en, *new_en;
	struct filter_sequence *seq, *new_seq;

	/* iterate over all the instances of the defaults proxy: the request
	 * side first, then the instances of the classes with no request side
	 * from the response side
	 */
	list_for_each_entry(ref, &defpx->conf.filter_classes_req, list) {
		list_for_each_entry(inst, &ref->instances, req.list)
			if (flt_copy_instance(px, inst) < 0)
				goto error;
	}
	list_for_each_entry(ref, &defpx->conf.filter_classes_res, list) {
		list_for_each_entry(inst, &ref->instances, res.list) {
			if (LIST_INLIST(&inst->req.list))
				continue; /* already copied from the request side */
			if (flt_copy_instance(px, inst) < 0)
				goto error;
		}
	}

	/* inherit the filter-enable entries too */
	list_for_each_entry(flt_en, &defpx->conf.filter_enabled, list) {
		new_en = calloc(1, sizeof(*new_en));
		if (!new_en)
			goto error;
		new_en->cls_name = strdup(flt_en->cls_name);
		new_en->id = flt_en->id ? strdup(flt_en->id) : NULL;
		new_en->enable = flt_en->enable;
		new_en->file = strdup(flt_en->file);
		new_en->line = flt_en->line;
		if (!new_en->cls_name || (flt_en->id && !new_en->id) || !new_en->file) {
			flt_free_enabled(new_en);
			goto error;
		}
		LIST_APPEND(&px->conf.filter_enabled, &new_en->list);
	}

	/* inherit the filter sequences too, in configuration order */
	list_for_each_entry(seq, &defpx->conf.filter_sequences, list) {
		new_seq = calloc(1, sizeof(*new_seq));
		if (!new_seq)
			goto error;
		new_seq->cls_name = strdup(seq->cls_name);
		new_seq->id = seq->id ? strdup(seq->id) : NULL;
		new_seq->cls_ref_name = strdup(seq->cls_ref_name);
		new_seq->ref_id = seq->ref_id ? strdup(seq->ref_id) : NULL;
		new_seq->side = seq->side;
		new_seq->pos = seq->pos;
		new_seq->file = strdup(seq->file);
		new_seq->line = seq->line;
		if (!new_seq->cls_name || (seq->id && !new_seq->id) ||
		    !new_seq->cls_ref_name || (seq->ref_id && !new_seq->ref_id) ||
		    !new_seq->file) {
			flt_free_sequence(new_seq);
			goto error;
		}
		LIST_APPEND(&px->conf.filter_sequences, &new_seq->list);
	}
	return 0;

  error:
	flt_free_instances(px);
	return -1;
}

/* Adds an implicit filter instance for the class <cls> to the proxy <px>,
 * with the id <id> (may be NULL) and the arguments <args> (terminated by an
 * empty string). It is used when a filter is implicitly configured by
 * another directive (e.g. with the cache-store action). The instance is
 * marked with FLT_INST_F_IMPLICIT and is enabled, since the directive
 * implies the filter usage.
 *
 * If a instance with the same class and id already exists, nothing is
 * done: an explicit declaration always wins over an implicit one, and the
 * first implicit declaration wins. Returns 0 on success, -1 on error (out
 * of memory).
 */
int flt_add_implicit_instance(struct proxy *px, struct filter_class *cls, const char *id,
				char **args, const char *file, int line)
{
	struct filter_instance *inst;
	int argc = 0;
	int i;

	/* a instance already exists for this class and id: explicit or
	 * implicit, it wins over a new implicit one.
	 */
	if (flt_find_instance(px, cls, id))
		return 0;

	inst = calloc(1, sizeof(*inst));
	if (!inst)
		return -1;

	inst->class   = cls;
	inst->enabled = 1; /* the directive implies the filter usage */
	inst->flags   = FLT_INST_F_IMPLICIT;

	if (id) {
		inst->id = strdup(id);
		if (!inst->id)
			goto error;
	}
	inst->conf.file = strdup(file);
	if (!inst->conf.file)
		goto error;
	inst->conf.line = line;

	for (argc = 0; args && *args[argc]; argc++)
		;
	inst->conf.argc = argc;
	inst->conf.argv = calloc(argc + 1, sizeof(*inst->conf.argv));
	if (!inst->conf.argv)
		goto error;
	for (i = 0; i < argc; i++) {
		inst->conf.argv[i] = strdup(args[i]);
		if (!inst->conf.argv[i])
			goto error;
	}

	if (flt_init_instance(inst, px) < 0)
		goto error;
	return 0;

  error:
	flt_free_instance(inst);
	return -1;
}

/*
 * Parses the "filter-config" keyword. A filter instance is created for the
 * given filter class and attached to the current proxy. The instance
 * arguments are only copied here, they will be finalized during the
 * post-check stage. The syntax is:
 *
 *   filter-config <class-name> [ id <id> ] [enabled] args...
 *
 * The "id" and "enabled" tokens, if set, must be the first options, in that
 * order. The id is optional, but it is mandatory for filter classes allowing
 * several instances per proxy. A instance inherited from a defaults
 * section or coming from an implicit declaration (e.g. use-fcgi-app) may be
 * overridden by a instance with the same class and id, but duplicating an
 * explicit instance inside the same proxy is rejected.
 */
static int parse_filter_config(char **args, int section_type, struct proxy *curpx,
			       const struct proxy *defpx, const char *file, int line, char **err)
{
	struct filter_instance *inst, *old_inst;
	struct filter_class *cls;
	const char *id = NULL;
	const char *err2;
	int enabled = 0;
	int cur_arg = 1;
	int i;

	inst = NULL;
	if (!*args[cur_arg]) {
		memprintf(err,
			  "parsing [%s:%d] : missing argument for '%s' in %s '%s'.",
			  file, line, args[0], proxy_type_str(curpx), curpx->id);
		goto error;
	}

	cls = filter_find_class(args[cur_arg]);
	if (!cls) {
		memprintf(err,
			  "parsing [%s:%d] : '%s' : unknown filter class '%s'.",
			  file, line, args[0], args[cur_arg]);
		goto error;
	}
	cur_arg++;

	/* optional "id <id>" and "enabled" tokens, in that order */
	if (strcmp(args[cur_arg], "id") == 0) {
		if (!*args[cur_arg+1]) {
			memprintf(err,
				  "parsing [%s:%d] : '%s %s' : missing filter instance id.",
				  file, line, args[0], args[1]);
			goto error;
		}
		id = args[cur_arg+1];
		err2 = invalid_prefix_char(id);
		if (err2) {
			memprintf(err,
				  "parsing [%s:%d] : '%s %s' : invalid character '%c' in filter instance id '%s'.",
				  file, line, args[0], args[1], *err2, id);
			goto error;
		}
		cur_arg += 2;
	}
	if (strcmp(args[cur_arg], "enabled") == 0) {
		enabled = 1;
		cur_arg++;
	}

	if ((cls->flags & FLT_CLS_FL_MULTI) && !id) {
		memprintf(err,
			  "parsing [%s:%d] : '%s %s' : missing filter instance id, several instances are allowed for this filter class.",
			  file, line, args[0], args[1]);
		goto error;
	}

	inst = calloc(1, sizeof(*inst));
	if (!inst)
		goto oom;

	inst->class   = cls;
	inst->px      = curpx;
	inst->enabled = enabled;
	inst->flags   = 0; /* explicit declaration */

	if (id) {
		inst->id = strdup(id);
		if (!inst->id)
			goto oom;
	}
	inst->conf.file = strdup(file);
	if (!inst->conf.file)
		goto oom;
	inst->conf.line = line;

	/* copy the instance arguments, they will be finalized later */
	for (i = cur_arg; *args[i]; i++);

	inst->conf.argc = i - cur_arg;
	inst->conf.argv = calloc(inst->conf.argc + 1, sizeof(*inst->conf.argv));
	if (!inst->conf.argv)
		goto oom;
	for (i = 0; i < inst->conf.argc; i++) {
		inst->conf.argv[i] = strdup(args[cur_arg + i]);
		if (!inst->conf.argv[i])
			goto oom;
	}

	/* A instance inherited from a defaults section or coming from an
	 * implicit declaration is overridden by the new one (last wins). But
	 * an explicit instance declared in this same proxy cannot be
	 * duplicated.
	 */
	old_inst = flt_find_instance(curpx, cls, id);
	if (old_inst) {
		if (!(old_inst->flags & (FLT_INST_F_INHERITED|FLT_INST_F_IMPLICIT))) {
			memprintf(err,
				  "'%s %s%s%s%s' : duplicate filter instance, already declared at %s:%d.",
				  args[0], args[1],
				  id ? " id " : "", id ? id : "", enabled ? " enabled" : "",
				  old_inst->conf.file, old_inst->conf.line);
			goto error;
		}
		flt_free_instance(old_inst);
	}

	if (flt_init_instance(inst, curpx) < 0) {
		memprintf(err,
			  "parsing [%s:%d] : '%s %s' : filter class reference not found in %s '%s'.",
			  file, line, args[0], args[1], proxy_type_str(curpx), curpx->id);
		goto error;
	}
	return 0;

  error:
	if (inst)
		flt_free_instance(inst);
	return -1;

  oom:
	memprintf(err, "parsing [%s:%d] : '%s' : out of memory", file, line, args[0]);
	goto error;
}


/* Parses one "filter-enable"/"filter-disable" entry "<class>[/<id>]" and
 * records it in the proxy <curpx>. <enable> is != 0 for "filter-enable" and
 * 0 for "filter-disable".
 * Returns 0 on success, -1 on error.
 */
static int parse_filter_enable_entry(const char *entry, unsigned int enable, struct proxy *curpx,
				     const char *file, int line, char **err)
{
	struct filter_enabled *flt_en;
	const char *sep;
	const char *err2;
	size_t len;

	sep = strchr(entry, '/');
	len = sep ? (size_t)(sep - entry) : strlen(entry);
	if (!len || (sep && !*(sep + 1))) {
		memprintf(err,
			  "parsing [%s:%d] : 'filter-%s' : invalid entry '%s'. The syntax is: filter-%s <class>[/<id>] [<class>[/<id>] ...].",
			  file, line, enable ? "enable" : "disable", entry,
			  enable ? "enable" : "disable");
		return -1;
	}

	flt_en = calloc(1, sizeof(*flt_en));
	if (!flt_en) {
		memprintf(err, "'filter-%s' : out of memory", enable ? "enable" : "disable");
		return -1;
	}

	flt_en->cls_name = my_strndup(entry, len);
	flt_en->id = sep ? strdup(sep + 1) : NULL;
	flt_en->enable = enable;
	flt_en->file = strdup(file);
	flt_en->line = line;
	if (!flt_en->cls_name || (sep && !flt_en->id) || !flt_en->file) {
		memprintf(err, "'filter-%s' : out of memory", enable ? "enable" : "disable");
		goto error;
	}

	if (!filter_find_class(flt_en->cls_name)) {
		memprintf(err,
			  "parsing [%s:%d] : 'filter-%s' : unknown filter class '%s'.",
			  file, line, enable ? "enable" : "disable", flt_en->cls_name);
		goto error;
	}
	if (flt_en->id) {
		err2 = invalid_prefix_char(flt_en->id);
		if (err2) {
			memprintf(err,
				  "parsing [%s:%d] : 'filter-%s' : invalid character '%c' in filter instance id '%s'.",
				  file, line, enable ? "enable" : "disable", *err2, flt_en->id);
			goto error;
		}
	}

	LIST_APPEND(&curpx->conf.filter_enabled, &flt_en->list);
	return 0;

  error:
	flt_free_enabled(flt_en);
	return -1;
}

/*
 * Parses the "filter-enable" and "filter-disable" keywords. The syntax is:
 *
 *   filter-enable <class>[/<id>] [<class>[/<id>] ...]
 *   filter-disable <class>[/<id>] [<class>[/<id>] ...]
 *
 * The directive is only recorded here, the corresponding filter instances
 * are enabled/disabled during the post-parsing stage (see
 * flt_enable_filters()), so the directive order does not matter. Without id,
 * all the instances of the class are concerned.
 */
static int parse_filter_enable(char **args, int section_type, struct proxy *curpx,
			       const struct proxy *defpx, const char *file, int line, char **err)
{
	unsigned int enable = (strcmp(args[0], "filter-enable") == 0);
	int cur_arg;

	if (!*args[1]) {
		memprintf(err,
			  "parsing [%s:%d] : missing argument for '%s' in %s '%s'.",
			  file, line, args[0], proxy_type_str(curpx), curpx->id);
		return -1;
	}

	for (cur_arg = 1; *args[cur_arg]; cur_arg++) {
		if (parse_filter_enable_entry(args[cur_arg], enable, curpx, file, line, err) < 0)
			return -1;
	}
	return 0;
}

/* Splits the entity reference <str>, in the form "class[/id]": the class
 * name and the id (NULL if not set) are returned in newly allocated strings
 * in <*cls_name> and <*id>. Returns 0 on success, -1 on error.
 */
static int flt_parse_entity(const char *str, const char **cls_name, const char **id, char **err)
{
	const char *sep;
	const char *err2;
	size_t len;

	sep = strchr(str, '/');
	len = sep ? (size_t)(sep - str) : strlen(str);
	if (!len || (sep && !*(sep + 1))) {
		memprintf(err, "invalid entity '%s', expecting <class>[/<id>]", str);
		return -1;
	}

	*cls_name = my_strndup(str, len);
	*id = sep ? strdup(sep + 1) : NULL;
	if (!*cls_name || (sep && !*id)) {
		memprintf(err, "out of memory");
		goto error;
	}

	if (*id) {
		err2 = invalid_prefix_char(*id);
		if (err2) {
			memprintf(err, "invalid character '%c' in filter instance id '%s'", *err2, *id);
			goto error;
		}
	}
	return 0;

  error:
	free((void *)*cls_name);
	free((void *)*id);
	*cls_name = *id = NULL;
	return -1;
}

/*
 * Parses the "filter-sequence" keyword. The syntax is:
 *
 *   filter-sequence {request|response} <inst>:<pos>(<entity>) [<inst>:<pos>(<entity>) ...]
 *
 * where <pos> is 'before' or 'after': "A:before(B)" means the instance A
 * is evaluated before the entity B (a class or a instance), "A:after(B)"
 * means A is evaluated after B. The directive is
 * only recorded here, the sequences are applied during the post-parsing
 * stage (see flt_apply_sequences()).
 */
static int parse_filter_sequence(char **args, int section_type, struct proxy *curpx,
				 const struct proxy *defpx, const char *file, int line, char **err)
{
	struct filter_sequence *seq = NULL;
	const char *sep;
	const char *entity;
	char *left = NULL;
	char *ref;
	unsigned int side;
	size_t entity_len;
	enum flt_pos pos;
	int cur_arg;
	int ret = 0;

	if (!*args[1]) {
		memprintf(err, "missing argument for '%s' in %s '%s'.", args[0], proxy_type_str(curpx), curpx->id);
		goto error;
	}
	if (strcmp(args[1], "request") == 0)
		side = FLT_SIDE_REQ;
	else if (strcmp(args[1], "response") == 0)
		side = FLT_SIDE_RES;
	else {
		memprintf(err, "'request' or 'response' expected.");
		goto error;
	}
	if (!*args[2]) {
		memprintf(err, "missing sequence. The syntax is: filter-sequence {request|response} <inst>:<pos>(<entity>) [<inst>:<pos>(<entity>) ...], with <pos> being 'before' or 'after'.");
		goto error;
	}

	for (cur_arg = 2; *args[cur_arg]; cur_arg++) {
		sep = strchr(args[cur_arg], ':');
		if (!sep || sep == args[cur_arg])
			goto invalid;
		if (strncmp(sep + 1, "before(", 7) == 0)
			pos = FLT_POS_BEFORE;
		else if (strncmp(sep + 1, "after(", 6) == 0)
			pos = FLT_POS_AFTER;
		else
			goto invalid;
		entity = sep + 1 + (pos == FLT_POS_BEFORE ? 7 : 6);
		entity_len = strlen(entity);
		if (entity_len < 2 || entity[entity_len - 1] != ')')
			goto invalid;
		entity_len--;

		seq = calloc(1, sizeof(*seq));
		if (!seq)
			goto oom;
		LIST_INIT(&seq->list);
		seq->side = side;
		seq->pos = pos;
		seq->file = strdup(file);
		seq->line = line;
		if (!seq->file)
			goto oom;

		left = my_strndup(args[cur_arg], sep - args[cur_arg]);
		if (!left)
			goto oom;
		ret = flt_parse_entity(left, &seq->cls_name, &seq->id, err);
		free(left);
		left = NULL;
		if (ret < 0)
			goto error;
		ref = my_strndup(entity, entity_len);
		if (!ref)
			goto oom;
		ret = flt_parse_entity(ref, &seq->cls_ref_name, &seq->ref_id, err);
		free(ref);
		if (ret < 0)
			goto error;

		LIST_APPEND(&curpx->conf.filter_sequences, &seq->list);
		seq = NULL;
	}
	return 0;

  invalid:
	memprintf(err, "invalid sequence '%s', expecting <inst>:before(<entity>) or <inst>:after(<entity>).",
		  args[cur_arg]);
	goto error;

  oom:
	memprintf(err, "out of memory");
	/* fallthrough */
  error:
	memprintf(err, "parsing [%s:%d] : '%s' : %s.",
		  file, line, args[0], err && *err ? *err : "invalid sequence");
	flt_free_sequence(seq);
	free(left);
	return -1;

}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled. */
static struct cfg_kw_list cfg_kws = {ILH, {
		{ CFG_LISTEN, "filter", parse_filter },
		{ CFG_LISTEN, "filter-config", parse_filter_config },
		{ CFG_LISTEN, "filter-disable", parse_filter_enable },
		{ CFG_LISTEN, "filter-enable", parse_filter_enable },
		{ CFG_LISTEN, "filter-sequence", parse_filter_sequence },
		{ 0, NULL, NULL },
	}
};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/* Enables or disables the filter instances referenced by the
 * "filter-enable" and "filter-disable" directives of the proxy <proxy>.
 * This happens during the post-parsing stage, so the directive order does
 * not matter and inherited instances can be enabled/disabled. An error is
 * reported if a referenced instance does not exist.
 * Returns a combination of ERR_* flags, ERR_NONE on success.
 */
static int flt_enable_filters(struct proxy *proxy)
{
	struct filter_enabled *flt_en;
	struct filter_class *cls;
	int err_code = ERR_NONE;

	list_for_each_entry(flt_en, &proxy->conf.filter_enabled, list) {
		struct flt_enable_ctx ctx;

		cls = filter_find_class(flt_en->cls_name);
		if (!cls) {
			ha_alert("config: %s '%s' : 'filter-%s' : unknown filter class '%s' (from %s:%d).\n",
				 proxy_type_str(proxy), proxy->id,
				 flt_en->enable ? "enable" : "disable", flt_en->cls_name,
				 flt_en->file, flt_en->line);
			err_code |= ERR_ALERT | ERR_FATAL;
			continue;
		}

		ctx.cls = cls;
		ctx.id = flt_en->id;
		ctx.enable = flt_en->enable;
		ctx.found = 0;
		flt_foreach_instance_side(proxy, FLT_SIDE_REQ, flt_enable_cb, &ctx);
		flt_foreach_instance_side(proxy, FLT_SIDE_RES, flt_enable_cb, &ctx);
		if (!ctx.found) {
			ha_alert("config: %s '%s' : 'filter-%s' : no instance of filter class '%s'%s%s%s (from %s:%d).\n",
				 proxy_type_str(proxy), proxy->id,
				 flt_en->enable ? "enable" : "disable", flt_en->cls_name,
				 flt_en->id ? " with id '" : "",
				 flt_en->id ? flt_en->id : "",
				 flt_en->id ? "'" : "",
				 flt_en->file, flt_en->line);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}
	return err_code;
}


/* Recursively checks that the instance <inst> does not create a loop in
 * the reordered lists for side <side>. A instance is linked in exactly
 * one list per side, so the structure is a forest: the FLT_INST_F_SEXPLORE
 * flag, marking the instances on the current path, is enough to detect
 * the loops. The flag is always cleared on the way out, even on error.
 * Returns 0 if no loop is found, -1 otherwise.
 */
static int flt_check_instance_loop(struct filter_instance *inst, unsigned int side)
{
	struct filter_instance *d;
	int ret;

	if (inst->flags & FLT_INST_F_SEXPLORE)
		goto error; /* loop */
	inst->flags |= FLT_INST_F_SEXPLORE;
	if (side == FLT_SIDE_REQ) {
		list_for_each_entry(d, &inst->req.reordered_before, req.list) {
			if (flt_check_instance_loop(d, side) < 0)
				goto error;
		}
		list_for_each_entry(d, &inst->req.reordered_after, req.list) {
			if (flt_check_instance_loop(d, side) < 0)
				goto error;
		}
	}
	else {
		list_for_each_entry(d, &inst->res.reordered_before, res.list) {
			if (flt_check_instance_loop(d, side) < 0)
				goto error;
		}
		list_for_each_entry(d, &inst->res.reordered_after, res.list) {
			if (flt_check_instance_loop(d, side) < 0)
				goto error;
		}
	}
	ret = 0;

  out:
	inst->flags &= ~FLT_INST_F_SEXPLORE;
	return ret;

  error:
	ret = -1;
	goto out;
}

/* Applies the filter sequences of the proxy <proxy>, in configuration
 * order. Each sequence moves a instance from its current list (its class
 * instances list or a reordered list) to the reordered list of the
 * reference entity: the reordered list of the class reference for the
 * sequence's side, or the reordered list of the reference instance. A
 * sequence is ignored if the instance to move does not exist, but the
 * reference entity must exist.
 * Returns a combination of ERR_* flags, ERR_NONE on success.
 */
static int flt_apply_sequences(struct proxy *proxy)
{
	struct filter_class_ref *ref;
	struct filter_instance *inst, *ref_inst;
	struct filter_sequence *seq;
	struct filter_class *cls, *ref_cls;
	int err_code = ERR_NONE;
	int count;

	list_for_each_entry(seq, &proxy->conf.filter_sequences, list) {
		/* find the instance to move. Without id, the class must have
		 * exactly one instance. If it does not exist, just ignore the
		 * sequence.
		 */
		cls = filter_find_class(seq->cls_name);
		if (!cls)
			continue;
		inst = flt_find_instance_count(proxy, cls, seq->id, &count);
		if (!inst)
			continue;
		if (count > 1) {
			ha_alert("config: %s '%s' : 'filter-sequence' : several instances of filter class '%s', an id is required (from %s:%d).\n",
				 proxy_type_str(proxy), proxy->id, seq->cls_name,
				 seq->file, seq->line);
			err_code |= ERR_ALERT | ERR_FATAL;
			continue;
		}

		/* the instance has no existence on a side its class is not
		 * placed on: ignore the sequence
		 */
		if ((seq->side == FLT_SIDE_REQ && !LIST_INLIST(&inst->class->req.list)) ||
		    (seq->side == FLT_SIDE_RES && !LIST_INLIST(&inst->class->res.list)))
			continue;

		/* find the reference entity */
		ref_cls = filter_find_class(seq->cls_ref_name);
		if (!ref_cls) {
			ha_alert("config: %s '%s' : 'filter-sequence' : unknown filter class '%s' (from %s:%d).\n",
				 proxy_type_str(proxy), proxy->id, seq->cls_ref_name,
				 seq->file, seq->line);
			err_code |= ERR_ALERT | ERR_FATAL;
			continue;
		}
		ref = flt_get_class_ref(proxy, ref_cls, seq->side);
		if (!ref) {
			ha_alert("config: %s '%s' : 'filter-sequence' : filter class '%s' has no %s side (from %s:%d).\n",
				 proxy_type_str(proxy), proxy->id, seq->cls_ref_name,
				 (seq->side == FLT_SIDE_REQ) ? "request" : "response",
				 seq->file, seq->line);
			err_code |= ERR_ALERT | ERR_FATAL;
			continue;
		}
		ref_inst = NULL;
		if (seq->ref_id) {
			ref_inst = flt_find_instance(proxy, ref_cls, seq->ref_id);
			if (!ref_inst) {
				ha_alert("config: %s '%s' : 'filter-sequence' : no instance of filter class '%s' with id '%s' (from %s:%d).\n",
					 proxy_type_str(proxy), proxy->id, seq->cls_ref_name,
					 seq->ref_id, seq->file, seq->line);
				err_code |= ERR_ALERT | ERR_FATAL;
				continue;
			}
		}

		/* unlink the instance from its current side list, if any,
		 * and append it in the right reordered list
		 */
		if (seq->side == FLT_SIDE_REQ) {
			if (LIST_INLIST(&inst->req.list))
				LIST_DEL_INIT(&inst->req.list);
			if (seq->pos == FLT_POS_BEFORE) {
				if (ref_inst)
					LIST_APPEND(&ref_inst->req.reordered_before, &inst->req.list);
				else
					LIST_APPEND(&ref->reordered_before, &inst->req.list);
			}
			else {
				if (ref_inst)
					LIST_APPEND(&ref_inst->req.reordered_after, &inst->req.list);
				else
					LIST_APPEND(&ref->reordered_after, &inst->req.list);
			}
		}
		else {
			if (LIST_INLIST(&inst->res.list))
				LIST_DEL_INIT(&inst->res.list);
			if (seq->pos == FLT_POS_BEFORE) {
				if (ref_inst)
					LIST_APPEND(&ref_inst->res.reordered_before, &inst->res.list);
				else
					LIST_APPEND(&ref->reordered_before, &inst->res.list);
			}
			else {
				if (ref_inst)
					LIST_APPEND(&ref_inst->res.reordered_after, &inst->res.list);
				else
					LIST_APPEND(&ref->reordered_after, &inst->res.list);
			}
		}

		/* a loop must not be created by the sequences: check from the
		 * moved instance after each sequence. It is enough: before
		 * the move, there is no loop (checked after the previous
		 * sequence), so a new loop necessarily involves the moved
		 * instance.
		 */
		if (flt_check_instance_loop(inst, seq->side) < 0) {
			ha_alert("config: %s '%s' : 'filter-sequence' : a loop is detected around instance '%s%s%s' (from %s:%d).\n",
				 proxy_type_str(proxy), proxy->id, inst->class->name,
				 inst->id ? "/" : "", inst->id ? inst->id : "",
				 seq->file, seq->line);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}
	return err_code;
}

/* Moves the instance <inst> from the class references tree to the flat
 * per-side list of the proxy <px>, recursively: the instances reordered
 * to be executed before <inst> are moved first, then <inst> itself and
 * finally the instances reordered to be executed after it.
 */
static void flt_flatten_instance(struct proxy *px, struct filter_instance *inst, unsigned int side)
{
	struct filter_instance *d, *back;

	if (side == FLT_SIDE_REQ) {
		list_for_each_entry_safe(d, back, &inst->req.reordered_before, req.list)
			flt_flatten_instance(px, d, side);
		LIST_DEL_INIT(&inst->req.list);
		LIST_APPEND(&px->filter_req_instances, &inst->req.list);
		list_for_each_entry_safe(d, back, &inst->req.reordered_after, req.list)
			flt_flatten_instance(px, d, side);
	}
	else {
		list_for_each_entry_safe(d, back, &inst->res.reordered_before, res.list)
			flt_flatten_instance(px, d, side);
		LIST_DEL_INIT(&inst->res.list);
		LIST_APPEND(&px->filter_res_instances, &inst->res.list);
		list_for_each_entry_safe(d, back, &inst->res.reordered_after, res.list)
			flt_flatten_instance(px, d, side);
	}
}

/* Moves the instances of the list <instances> to the flat per-side list of the
 * proxy <px>, in evaluation order (see flt_flatten_instance()).
 */
static void flt_flatten_inst_list(struct proxy *px, struct list *instances, unsigned int side)
{
	struct filter_instance *inst, *back;

	if (side == FLT_SIDE_REQ) {
		list_for_each_entry_safe(inst, back, instances, req.list)
			flt_flatten_instance(px, inst, side);
	}
	else {
		list_for_each_entry_safe(inst, back, instances, res.list)
			flt_flatten_instance(px, inst, side);
	}
}

/* Flattens the filter instances of the proxy <px>: the class references
 * tree is consumed to produce the flat per-side lists of the proxy, in
 * evaluation order. The class references and the consumed filter-enable and
 * filter-sequence entries are released.
 */
static void flt_flatten_instances(struct proxy *px)
{
	struct filter_class_ref *ref, *refback;
	struct filter_enabled *flt_en, *enback;
	struct filter_sequence *seq, *seqback;

	list_for_each_entry_safe(ref, refback, &px->conf.filter_classes_req, list) {
		flt_flatten_inst_list(px, &ref->reordered_before, FLT_SIDE_REQ);
		flt_flatten_inst_list(px, &ref->instances, FLT_SIDE_REQ);
		flt_flatten_inst_list(px, &ref->reordered_after, FLT_SIDE_REQ);
		LIST_DELETE(&ref->list);
		free(ref);
	}
	list_for_each_entry_safe(ref, refback, &px->conf.filter_classes_res, list) {
		flt_flatten_inst_list(px, &ref->reordered_before, FLT_SIDE_RES);
		flt_flatten_inst_list(px, &ref->instances, FLT_SIDE_RES);
		flt_flatten_inst_list(px, &ref->reordered_after, FLT_SIDE_RES);
		LIST_DELETE(&ref->list);
		free(ref);
	}

	/* release the consumed filter-enable and filter-sequence entries */
	list_for_each_entry_safe(flt_en, enback, &px->conf.filter_enabled, list)
		flt_free_enabled(flt_en);
	list_for_each_entry_safe(seq, seqback, &px->conf.filter_sequences, list)
		flt_free_sequence(seq);
}

/* Post-parses the filter instances of the proxy <proxy>. For each
 * instance, some sanity checks are performed and the ->parse() callback of
 * the filter class is called to produce the filter configuration
 * (inst->fconf). This happens after the configuration parsing, during the
 * post-parsing stage. Returns a combination of ERR_* flags, ERR_NONE on
 * success.
 */
static int flt_precheck_instance(struct proxy *proxy, struct filter_instance *inst)
{
	char *err = NULL;

	if (!inst->class->parse) {
		ha_alert("config: %s '%s' : filter class '%s' does not support 'filter-config' (instance from %s:%d).\n",
			 proxy_type_str(proxy), proxy->id, inst->class->name,
			 inst->conf.file, inst->conf.line);
		return ERR_ALERT | ERR_FATAL;
	}

	inst->fconf = calloc(1, sizeof(*inst->fconf));
	if (!inst->fconf) {
		ha_alert("config: %s '%s' : out of memory.\n",
			 proxy_type_str(proxy), proxy->id);
		return ERR_ALERT | ERR_FATAL;
	}
	inst->fconf->name = inst->class->name;

	if (inst->class->parse(inst->conf.argv, proxy, inst, &err) < 0) {
		ha_alert("config: %s '%s' : error in instance of filter class '%s' from %s:%d : %s.\n",
			 proxy_type_str(proxy), proxy->id, inst->class->name,
			 inst->conf.file, inst->conf.line,
			 err && *err ? err : "unknown error");
		return ERR_ALERT | ERR_FATAL;
	}
	if (!inst->fconf->ops) {
		ha_alert("config: %s '%s' : filter class '%s' defined no callbacks for the instance from %s:%d.\n",
			 proxy_type_str(proxy), proxy->id, inst->class->name,
			 inst->conf.file, inst->conf.line);
		return ERR_ALERT | ERR_FATAL;
	}
	return ERR_NONE;
}

/* Post-parses the instances of the class reference <ref>. Only one
 * instance is allowed for classes without FLT_CLS_FL_MULTI. Returns a
 * combination of ERR_* flags, ERR_NONE on success.
 */
static int flt_precheck_class_instances(struct proxy *proxy, struct filter_class_ref *ref, unsigned int side)
{
	struct filter_instance *inst;
	int err_code = ERR_NONE;
	int count = 0;

	if (side == FLT_SIDE_REQ) {
		list_for_each_entry(inst, &ref->instances, req.list)
			count++;
	}
	else {
		list_for_each_entry(inst, &ref->instances, res.list)
			count++;
	}

	if (count > 1 && !(ref->class->flags & FLT_CLS_FL_MULTI)) {
		if (side == FLT_SIDE_REQ) {
			list_for_each_entry(inst, &ref->instances, req.list) {
				ha_alert("config: %s '%s' : several instances of filter class '%s', but only one is allowed (see %s:%d).\n",
					 proxy_type_str(proxy), proxy->id, ref->class->name,
					 inst->conf.file, inst->conf.line);
			}
		}
		else {
			list_for_each_entry(inst, &ref->instances, res.list) {
				ha_alert("config: %s '%s' : several instances of filter class '%s', but only one is allowed (see %s:%d).\n",
					 proxy_type_str(proxy), proxy->id, ref->class->name,
					 inst->conf.file, inst->conf.line);
			}
		}
		return ERR_ALERT | ERR_FATAL;
	}

	if (side == FLT_SIDE_REQ) {
		list_for_each_entry(inst, &ref->instances, req.list)
			err_code |= flt_precheck_instance(proxy, inst);
	}
	else {
		list_for_each_entry(inst, &ref->instances, res.list)
			err_code |= flt_precheck_instance(proxy, inst);
	}
	return err_code;
}

static int flt_precheck_instances(struct proxy *proxy)
{
	struct filter_class_ref *ref;
	int err_code = ERR_NONE;

	/* iterate over all the class references of the proxy: the request side
	 * first, then the references of the classes with no request side from
	 * the response side
	 */
	list_for_each_entry(ref, &proxy->conf.filter_classes_req, list)
		err_code |= flt_precheck_class_instances(proxy, ref, FLT_SIDE_REQ);
	list_for_each_entry(ref, &proxy->conf.filter_classes_res, list) {
		if (LIST_INLIST(&ref->class->req.list))
			continue; /* already handled from the request side */
		err_code |= flt_precheck_class_instances(proxy, ref, FLT_SIDE_RES);
	}
	return err_code;
}


/* Calls flt_precheck_instances() for all proxies, see above */
static int flt_precheck_instances_all()
{
	struct proxy *px;
	int err_code = ERR_NONE;

	list_for_each_entry(px, &main_proxies, el) {
		if (px->flags & (PR_FL_DISABLED|PR_FL_STOPPED))
			continue;

		err_code |= flt_precheck_instances(px);
		if (err_code & (ERR_ABORT|ERR_FATAL)) {
			ha_alert("Failed to parse the filter instances of proxy '%s'.\n",
				 px->id);
			return err_code;
		}
		err_code |= flt_enable_filters(px);
		if (err_code & (ERR_ABORT|ERR_FATAL)) {
			ha_alert("Failed to apply the filter-enable/filter-disable directives of proxy '%s'.\n",
				 px->id);
			return err_code;
		}
		err_code |= flt_apply_sequences(px);
		if (err_code & (ERR_ABORT|ERR_FATAL)) {
			ha_alert("Failed to apply the filter sequences of proxy '%s'.\n",
				 px->id);
			return err_code;
		}
		/* produce the flat per-side lists of the proxy and release the
		 * configuration structures
		 */
		flt_flatten_instances(px);
	}
	return 0;
}

/* Dumps the request classes. The classes inserted in the before/after lists are
 * inserted around the class they are attached to.
 */
static void cli_dump_flt_req_classes(struct buffer *out, struct list *classes)
{
	struct filter_class *cls;
	int first = 1;

	list_for_each_entry(cls, classes, req.list) {
		if (!first)
			chunk_appendf(out, " > ");
		if (!LIST_ISEMPTY(&cls->req.before)) {
			cli_dump_flt_req_classes(out, &cls->req.before);
			chunk_appendf(out, " > ");
		}
		chunk_appendf(out, cls->name);
		if (!LIST_ISEMPTY(&cls->req.after)) {
			chunk_appendf(out, " > ");
			cli_dump_flt_req_classes(out, &cls->req.after);
		}
		first = 0;
	}
	chunk_appendf(&trash, "\n");
}

/* Dumps the response classes. The classes inserted in the before/after lists are
 * inserted around the class they are attached to.
 */
static void cli_dump_flt_res_classes(struct buffer *out, struct list *classes)
{
	struct filter_class *cls;
	int first = 1;

	list_for_each_entry(cls, classes, res.list) {
		if (!first)
			chunk_appendf(out, " > ");
		if (!LIST_ISEMPTY(&cls->res.before)) {
			cli_dump_flt_res_classes(out, &cls->res.before);
			chunk_appendf(out, " > ");
		}
		chunk_appendf(out, cls->name);
		if (!LIST_ISEMPTY(&cls->res.after)) {
			chunk_appendf(out, " > ");
			cli_dump_flt_res_classes(out, &cls->res.after);
		}
		first = 0;
	}
	chunk_appendf(&trash, "\n");
}

/* Parses "show filter classes [request|response]" */
static int cli_parse_show_flt_classes(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	chunk_reset(&trash);

	if (!*args[3] || strcmp(args[3], "request") == 0) {
		chunk_appendf(&trash, "request: ");
		cli_dump_flt_req_classes(&trash, &req_filter_classes);
	}
	if (!*args[3] || strcmp(args[3], "response") == 0) {
		chunk_appendf(&trash, "response: ");
		cli_dump_flt_res_classes(&trash, &res_filter_classes);
	}
	if (*args[3] && strcmp(args[3], "request") != 0 && strcmp(args[3], "response") != 0)
		return cli_err(appctx, "'request' or 'response' expected\n");

	return cli_msg(appctx, LOG_INFO, trash.area);
}



/* Dumps the filter instance <inst> as "<cls>[:<id>]", prefixed by " > "
 * unless <first> is set.
 */
static void cli_dump_flat_flt_def(struct buffer *out, struct filter_instance *inst, int *first)
{
	chunk_appendf(out, "%s%s", *first ? "" : " > ", inst->class->name);
	if (inst->id)
		chunk_appendf(out, ":%s", inst->id);
	*first = 0;
}

/* Parse "show filter instances <px> [request|response]". Displays the filter
 * instances of the proxy <px>, one line per side (both sides if no side is
 * selected).
 */
static int cli_parse_show_flt_instances(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct proxy *px;
	struct filter_instance *inst;
	int first = 1;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "a proxy name is expected\n");

	px = proxy_find_by_name(args[3], 0, 0);
	if (!px)
		px = proxy_find_by_name(args[3], PR_CAP_DEF, 0);
	if (!px)
		return cli_err(appctx, "unknown proxy\n");

	if (*args[4] && strcmp(args[4], "request") != 0 && strcmp(args[4], "response") != 0)
		return cli_err(appctx, "'request' or 'response' expected\n");

	chunk_reset(&trash);

	if (!*args[4] || strcmp(args[4], "request") == 0) {
		chunk_appendf(&trash, "request: ");
		list_for_each_entry(inst, &px->filter_req_instances, req.list)
			cli_dump_flat_flt_def(&trash, inst, &first);
	}
	if (!*args[4] || strcmp(args[4], "response") == 0) {
		chunk_appendf(&trash, "response: ");
		list_for_each_entry(inst, &px->filter_res_instances, res.list)
			cli_dump_flat_flt_def(&trash, inst, &first);
	}

	if (first)
		chunk_appendf(&trash, "<none>");
	chunk_appendf(&trash, "\n");

	return cli_msg(appctx, LOG_INFO, trash.area);
}

/* Parse "show filter instance <px> <class[/id]>". Displays all the
 * information of a single filter instance of the proxy <px>.
 */
static int cli_parse_show_flt_instance(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct filter_instance *found = NULL;
	struct filter_class *cls;
	struct proxy *px;
	char *id = NULL;
	int count = 0;
	int i;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	if (!*args[3] || !*args[4])
		return cli_err(appctx, "a proxy name and a instance (class[/id]) are expected\n");

	px = proxy_find_by_name(args[3], 0, 0);
	if (!px)
		px = proxy_find_by_name(args[3], PR_CAP_DEF, 0);
	if (!px)
		return cli_err(appctx, "unknown proxy\n");

	/* split the class[/id] argument (args are strdup'ed, it can be
	 * modified in place)
	 */
	id = strchr(args[4], '/');
	if (id)
		*id++ = '\0';

	cls = filter_find_class(args[4]);
	if (cls)
		found = flt_find_instance_count(px, cls, id, &count);
	else
		return cli_err(appctx, "unknown filter class\n");

	if (id && !found)
		return cli_err(appctx, "unknown instance\n");
	if (!id && count > 1)
		return cli_err(appctx, "several instances of this class, an id is required\n");
	if (!found)
		return cli_err(appctx, "no instance of this class for this proxy\n");

	chunk_reset(&trash);
	chunk_appendf(&trash, "class:      %s\n", found->class->name);
	chunk_appendf(&trash, "id:         %s\n", found->id ? found->id : "<none>");
	chunk_appendf(&trash, "state:      %s%s%s\n",
		      found->enabled ? "enabled" : "disabled",
		      (found->flags & FLT_INST_F_IMPLICIT) ? ", implicit" : "",
		      (found->flags & FLT_INST_F_INHERITED) ? ", inherited" : "");
	chunk_appendf(&trash, "sides:     %s%s\n",
		      LIST_INLIST(&found->class->req.list) ? " request" : "",
		      LIST_INLIST(&found->class->res.list) ? " response" : "");
	chunk_appendf(&trash, "defined at: %s:%d\n", found->conf.file, found->conf.line);
	chunk_appendf(&trash, "args:      ");
	if (found->conf.argc) {
		for (i = 0; i < found->conf.argc; i++)
			chunk_appendf(&trash, " %s", found->conf.argv[i]);
	}
	else
		chunk_appendf(&trash, " <none>");
	chunk_appendf(&trash, "\n");

	return cli_msg(appctx, LOG_INFO, trash.area);
}

static struct cli_kw_list cli_kws = {ILH, {
	{{ "show", "filter", "classes", NULL }, "show filter classes [request|response]     : display all filter classes", cli_parse_show_flt_classes, NULL, NULL, NULL },
	{{ "show", "filter", "instance", NULL }, "show filter instance <px> <class[/id]> : display a filter instance of a proxy", cli_parse_show_flt_instance, NULL, NULL, NULL },
	{{ "show", "filter", "instances", NULL }, "show filter instances <px> [side]     : display the filter instances of a proxy", cli_parse_show_flt_instances, NULL, NULL, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/* Checks that all registered filter classes are placed on at least one
 * side. The classes are placed with filter_place_class() (see
 * filter_init_classes() for the internal classes), so a class without
 * placement is useless and most probably comes from a module registration
 * bug.
 * Returns a combination of ERR_* flags, ERR_NONE on success.
 */
static int flt_precheck_classes()
{
	struct filter_class *cls;
	int err_code = ERR_NONE;

	list_for_each_entry(cls, &filter_classes, list) {
		if (!LIST_INLIST(&cls->req.list) && !LIST_INLIST(&cls->res.list)) {
			ha_alert("filters: class '%s' is placed neither on the request side nor on the response side.\n",
				 cls->name);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}
	return err_code;
}

/* Helper function used to initialized a filter class with the given name,
 * flags (FLT_CLS_FL_*) and instance parsing function (may be NULL).
 */
static inline void flt_init_class(struct filter_class *cls, const char *name, unsigned int flags,
				  int (*parse)(char **args, struct proxy *px,
					       struct filter_instance *inst, char **err))
{
	cls->name = name;
	cls->flags = flags;
	cls->parse = parse;
	LIST_INIT(&cls->req.before);
	LIST_INIT(&cls->req.after);
	LIST_INIT(&cls->req.list);

	LIST_INIT(&cls->res.before);
	LIST_INIT(&cls->res.after);
	LIST_INIT(&cls->res.list);

	LIST_INIT(&cls->list);
}

/* Finds a filter class by name in the global list, NULL if unknown. */
struct filter_class *filter_find_class(const char *name)
{
	struct filter_class *cls;

	list_for_each_entry(cls, &filter_classes, list) {
		if (strcmp(cls->name, name) == 0)
			return cls;
	}
	return NULL;
}

/* Creates the filter class references for the request side.  Returns 0 on
 * success, -1 on error.
 */
static int flt_init_req_class_refs(struct proxy *px, struct list *classes)
{
	struct filter_class *cls;
	struct filter_class_ref *ref;

	list_for_each_entry(cls, classes, req.list) {
		if (flt_init_req_class_refs(px, &cls->req.before) == -1)
			goto error;

		ref = calloc(1, sizeof(*ref));
		if (!ref)
			goto error;
		ref->class = cls;
		LIST_INIT(&ref->instances);
		LIST_INIT(&ref->reordered_before);
		LIST_INIT(&ref->reordered_after);
		LIST_APPEND(&px->conf.filter_classes_req, &ref->list);

		if (flt_init_req_class_refs(px, &cls->req.after) == -1)
			goto error;
	}

	return 0;
  error:
	return -1;
}

/* Creates the filter class references for the response side.  Returns 0 on
 * success, -1 on error.
 */
static int flt_init_res_class_refs(struct proxy *px, struct list *classes)
{
	struct filter_class *cls;
	struct filter_class_ref *ref;

	list_for_each_entry(cls, classes, res.list) {
		if (flt_init_res_class_refs(px, &cls->res.before) == -1)
			goto error;

		ref = calloc(1, sizeof(*ref));
		if (!ref)
			goto error;
		ref->class = cls;
		LIST_INIT(&ref->instances);
		LIST_INIT(&ref->reordered_before);
		LIST_INIT(&ref->reordered_after);
		LIST_APPEND(&px->conf.filter_classes_res, &ref->list);

		if (flt_init_res_class_refs(px, &cls->res.after) == -1)
			goto error;
	}

	return 0;
  error:
	return -1;
}

/* Creates the filter class references of the proxy <px>: one reference per
 * registered filter class, linked in the per-side lists of the proxy following
 * the global class order of each side.
 * It is called during the proxy initialization, so all filter classes must be
 * registered first.
 * Returns 0 on success, -1 on error.
 */
int flt_init_class_refs(struct proxy *px)
{
	if (flt_init_req_class_refs(px, &req_filter_classes) == -1)
		goto error;
	if (flt_init_res_class_refs(px, &res_filter_classes) == -1)
		goto error;
	return 0;

  error:
	flt_free_instances(px);
	return -1;
}

/* Helper function for filter classes: calls the legacy "filter" keyword
 * parsing function <parse> on the arguments of the filter instance <inst>,
 * as if the line "filter <kw> <inst args...>" was found in the configuration
 * of the proxy <px>. <private> is passed as-is to the parsing function.
 * Returns 0 on success, < 0 on error.
 */
int flt_parse_instance_legacy(struct proxy *px, struct filter_instance *inst, char **err,
			 const char *kw,
			 int (*parse)(char **args, int *cur_arg, struct proxy *px,
				      struct flt_conf *fconf, char **err, void *private),
			 void *private)
{
	char *fargs[MAX_LINE_ARGS+1];
	int i, ret, cur_arg;

	/* the legacy parsing functions expect the keyword at args[*cur_arg],
	 * followed by the filter arguments. Like for the config parser, the
	 * arguments must be terminated by an empty string, not a NULL pointer.
	 */

	fargs[0] = (char *)kw;
	for (i = 0; inst->conf.argv[i] && *inst->conf.argv[i]; i++)
		fargs[i+1] = inst->conf.argv[i];
	fargs[i+1] = "";

	cur_arg = 0;
	ret = parse(fargs, &cur_arg, px, inst->fconf, err, private);
	if (ret == 0 && *fargs[cur_arg]) {
		/* some arguments were not consumed by the parsing function */
		memprintf(err, "'filter-config %s' : unknown keyword '%s'",
		          inst->class->name, fargs[cur_arg]);
		ret = -1;
	}
	return ret;
}

/* Registers a new filter class, with the parsing function <parse> used to
 * finalize the filter instances of this class (may be NULL if the class does
 * not support the "filter-config" directive). The class is initialized and
 * added to the global "filter_classes" list only — it is not usable on any side
 * until placed with filter_place_class(). Must be called after
 * filter_init_classes().
 * Returns 0 on success, -1 on error (too early call, duplicate name).
 */
int filter_register_class(struct filter_class *cls, const char *name,
			  int (*parse)(char **args, struct proxy *px,
				       struct filter_instance *inst, char **err))
{
	const char *err;
	int ret = -1;

	if (!filter_classes_initialized) {
		ha_alert("filters: class '%s' registered before internal classes were initialized\n", name);
		goto out;
	}
	if (filter_find_class(name)) {
		ha_alert("filters: duplicate filter class name '%s'\n", name);
		goto out;
	}
	err = invalid_prefix_char(name);
	if (err) {
		ha_alert("filters: character '%c' is not permitted in filter class name.\n", *err);
		goto out;
	}

	flt_init_class(cls, name, 0, parse);
	LIST_APPEND(&filter_classes, &cls->list);
	ret = 0;
  out:
	return ret;
}

/* Places <cls> on <side> (FLT_SIDE_REQ or FLT_SIDE_RES), before or after the
 * reference class <ref_name>. The class is appended in the reference class'
 * req/res .before or .after constraint list; the final evaluation order is
 * resolved later. The global ordered lists are never touched here.  Call it
 * once per side; the positions may differ per side.
 * Returns 0 on success, -1 on error (unknown ref, ref not present on that side,
 * class already placed on that side).
 */
int filter_place_class(struct filter_class *cls, unsigned int side,
		       const char *ref_name, enum flt_pos pos)
{
	struct filter_class *ref;
	int ret = -1;

	if (!filter_classes_initialized) {
		ha_alert("filters: class '%s' placed before internal classes were initialized\n", cls->name);
		goto out;
	}
	ref = filter_find_class(ref_name);
	if (!ref) {
		ha_alert("filters: unknown reference class '%s' for class '%s'\n", ref_name, cls->name);
		goto out;
	}

	if (side == FLT_SIDE_REQ) {
		if (LIST_INLIST(&cls->req.list)) {
			ha_alert("filters: class '%s' already placed on request side\n", cls->name);
			goto out;
		}
		if (!LIST_INLIST(&ref->req.list)) {
			ha_alert("filters: reference class '%s' has no request side\n", ref_name);
			goto out;
		}
		LIST_APPEND((pos == FLT_POS_BEFORE) ? &ref->req.before : &ref->req.after,
			    &cls->req.list);
	}
	else {
		if (LIST_INLIST(&cls->res.list)) {
			ha_alert("filters: class '%s' already placed on response side\n", cls->name);
			goto out;
		}
		if (!LIST_INLIST(&ref->res.list)) {
			ha_alert("filters: reference class '%s' has no response side\n", ref_name);
			goto out;
		}
		LIST_APPEND((pos == FLT_POS_BEFORE) ? &ref->res.before : &ref->res.after,
			    &cls->res.list);
	}
	ret = 0;
  out:
	return ret;
}

/* Registers a new filter class named <name> and places it on both sides,
 * before or after the reference class <ref_name>. Convenience function for
 * the common symmetric case, equivalent to filter_register_class() followed
 * by filter_place_class() on FLT_SIDE_REQ and FLT_SIDE_RES.
 * Returns 0 on success, -1 on error. */
int filter_register_class_full(struct filter_class *cls, const char *name,
			       int (*parse)(char **args, struct proxy *px,
					    struct filter_instance *inst, char **err),
			       const char *ref_name, enum flt_pos pos)
{
	if (filter_register_class(cls, name, parse) < 0)
		goto err;
	if (filter_place_class(cls, FLT_SIDE_REQ, ref_name, pos) < 0)
		goto cleanup_on_err;
	if (filter_place_class(cls, FLT_SIDE_RES, ref_name, pos) < 0)
		goto cleanup_on_err;

	return 0;

  cleanup_on_err:
	LIST_DELETE(&cls->list);
	LIST_INIT(&cls->list);
	/* fallthrough */
  err:
	return -1;
}

/* Init function responsible to initialize all intenral filter classes and to
 * insert them is global list above. The default evaluation order of all
 * internal filters is defined in this function.
 *
 * Exemple to register a new filter class:
 *
 * static struct filter_class flt_myfilter_cls;
 *
 * static int myfilter_register_class(void)
 * {
 *    if (filter_register_class(&flt_myfilter_cls, "myfilter", myfilter_parse_def) < 0)
 *       return -1;
 *
 *    // before spoe on request, after lua on response
 *     if (filter_place_class(&flt_myfilter_cls, FLT_SIDE_REQ, "spoe", FLT_POS_BEFORE) < 0)
 *       return -1;
 *    if (filter_place_class(&flt_myfilter_cls, FLT_SIDE_RES, "lua", FLT_POS_AFTER) < 0)
 *       return -1;
 *    return 0;
 * }
 * INITCALL1(STG_INIT, myfilter_register_class);
 */
static void filter_init_classes(void)
{
	/* TODO: the filter names must come from the filters (the filter id most probably) */
	flt_init_class(&flt_trace_cls,         trace_filter_cls_name,         FLT_CLS_FL_MULTI, trace_flt_parse_instance);
	flt_init_class(&flt_cache_store_cls,   cache_store_filter_cls_name,   FLT_CLS_FL_MULTI, cache_store_flt_parse_instance);
	flt_init_class(&flt_http_comp_req_cls, http_comp_req_filter_cls_name, 0,                http_comp_req_flt_parse_instance);
	flt_init_class(&flt_http_comp_res_cls, http_comp_res_filter_cls_name, 0,                http_comp_res_flt_parse_instance);
	flt_init_class(&flt_decomp_req_cls,    decomp_req_filter_cls_name,    0,                decomp_req_flt_parse_instance);
	flt_init_class(&flt_decomp_res_cls,    decomp_res_filter_cls_name,    0,                decomp_res_flt_parse_instance);
#if defined(USE_SPOE)
	flt_init_class(&flt_spoe_cls,          spoe_filter_cls_name,          FLT_CLS_FL_MULTI, spoe_flt_parse_instance);
#endif
#if defined(USE_LUA)
	flt_init_class(&flt_lua_cls,           hlua_filter_cls_name,          FLT_CLS_FL_MULTI, hlua_flt_parse_instance);
#endif
	flt_init_class(&flt_bwlim_in_cls,      bwlim_in_filter_cls_name,      FLT_CLS_FL_MULTI, bwlim_in_flt_parse_instance);
	flt_init_class(&flt_bwlim_out_cls,     bwlim_out_filter_cls_name,     FLT_CLS_FL_MULTI, bwlim_out_flt_parse_instance);
#if defined(USE_FCGI)
	flt_init_class(&flt_fcgi_cls,          fcgi_filter_cls_name,          0,                fcgi_flt_parse_instance);
#endif

	LIST_APPEND(&filter_classes, &flt_trace_cls.list);
	LIST_APPEND(&filter_classes, &flt_cache_store_cls.list);
	LIST_APPEND(&filter_classes, &flt_decomp_req_cls.list);
	LIST_APPEND(&filter_classes, &flt_decomp_res_cls.list);
#if defined(USE_SPOE)
	LIST_APPEND(&filter_classes, &flt_spoe_cls.list);
#endif
#if defined(USE_LUA)
	LIST_APPEND(&filter_classes, &flt_lua_cls.list);
#endif
	LIST_APPEND(&filter_classes, &flt_http_comp_req_cls.list);
	LIST_APPEND(&filter_classes, &flt_http_comp_res_cls.list);
	LIST_APPEND(&filter_classes, &flt_bwlim_in_cls.list);
	LIST_APPEND(&filter_classes, &flt_bwlim_out_cls.list);
#if defined(USE_FCGI)
	LIST_APPEND(&filter_classes, &flt_fcgi_cls.list);
#endif

	LIST_APPEND(&req_filter_classes, &flt_trace_cls.req.list);
	LIST_APPEND(&req_filter_classes, &flt_decomp_req_cls.req.list);
#if defined(USE_LUA)
	LIST_APPEND(&req_filter_classes, &flt_lua_cls.req.list);
#endif
#if defined(USE_SPOE)
	LIST_APPEND(&req_filter_classes, &flt_spoe_cls.req.list);
#endif
	LIST_APPEND(&req_filter_classes, &flt_http_comp_res_cls.req.list);
	LIST_APPEND(&req_filter_classes, &flt_decomp_res_cls.req.list);
	LIST_APPEND(&req_filter_classes, &flt_http_comp_req_cls.req.list);
	LIST_APPEND(&req_filter_classes, &flt_bwlim_in_cls.req.list);
#if defined(USE_FCGI)
	LIST_APPEND(&req_filter_classes, &flt_fcgi_cls.req.list);
#endif

#if defined(USE_FCGI)
	LIST_APPEND(&res_filter_classes, &flt_fcgi_cls.res.list);
#endif
	LIST_APPEND(&res_filter_classes, &flt_trace_cls.res.list);
	LIST_APPEND(&res_filter_classes, &flt_decomp_res_cls.res.list);
	LIST_APPEND(&res_filter_classes, &flt_cache_store_cls.res.list);
#if defined(USE_SPOE)
	LIST_APPEND(&res_filter_classes, &flt_spoe_cls.res.list);
#endif
#if defined(USE_LUA)
	LIST_APPEND(&res_filter_classes, &flt_lua_cls.res.list);
#endif
	LIST_APPEND(&res_filter_classes, &flt_http_comp_res_cls.res.list);
	LIST_APPEND(&res_filter_classes, &flt_decomp_req_cls.res.list);
	LIST_APPEND(&res_filter_classes, &flt_bwlim_out_cls.res.list);

	filter_classes_initialized = 1;
}



REGISTER_PRE_CHECK(flt_precheck_instances_all);
REGISTER_PRE_CHECK(flt_precheck_classes);
REGISTER_POST_PROXY_CHECK(flt_check_instances);
REGISTER_POST_CHECK(flt_init_all);
REGISTER_PER_THREAD_INIT(flt_init_all_per_thread);
REGISTER_PER_THREAD_DEINIT(flt_deinit_all_per_thread);

INITCALL0(STG_REGISTER, filter_init_classes);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
