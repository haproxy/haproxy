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

#include <common/buffer.h>
#include <common/debug.h>
#include <common/cfgparse.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/errors.h>
#include <common/namespace.h>
#include <common/standard.h>
#include <common/hathreads.h>

#include <types/filters.h>
#include <types/proto_http.h>

#include <proto/compression.h>
#include <proto/filters.h>
#include <proto/flt_http_comp.h>
#include <proto/proto_http.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>

/* Pool used to allocate filters */
struct pool_head *pool_head_filter = NULL;

static int handle_analyzer_result(struct stream *s, struct channel *chn, unsigned int an_bit, int ret);

/* - RESUME_FILTER_LOOP and RESUME_FILTER_END must always be used together.
 *   The first one begins a loop and the seconds one ends it.
 *
 * - BREAK_EXECUTION must be used to break the loop and set the filter from
 *   which to resume the next time.
 *
 *  Here is an exemple:
 *
 *    RESUME_FILTER_LOOP(stream, channel) {
 *        ...
 *        if (cond)
 *             BREAK_EXECUTION(stream, channel, label);
 *        ...
 *    } RESUME_FILTER_END;
 *    ...
 *     label:
 *    ...
 *
 */
#define RESUME_FILTER_LOOP(strm, chn)					\
	do {								\
		struct filter *filter;					\
									\
		if (strm_flt(strm)->current[CHN_IDX(chn)]) {	\
			filter = strm_flt(strm)->current[CHN_IDX(chn)]; \
			strm_flt(strm)->current[CHN_IDX(chn)] = NULL; \
			goto resume_execution;				\
		}							\
									\
		list_for_each_entry(filter, &strm_flt(s)->filters, list) { \
		resume_execution:

#define RESUME_FILTER_END					\
		}						\
	} while(0)

#define BREAK_EXECUTION(strm, chn, label)				\
	do {								\
		strm_flt(strm)->current[CHN_IDX(chn)] = filter;	\
		goto label;						\
	} while (0)


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
	LIST_ADDQ(&flt_keywords.list, &kwl->list);
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
 */
void
flt_dump_kws(char **out)
{
	struct flt_kw_list *kwl;
	int index;

	*out = NULL;
	list_for_each_entry(kwl, &flt_keywords.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if (kwl->kw[index].parse ||
			    flt_find_kw(kwl->kw[index].kw) == &kwl->kw[index]) {
				memprintf(out, "%s[%4s] %s%s\n", *out ? *out : "",
				          kwl->scope,
				          kwl->kw[index].kw,
				          kwl->kw[index].parse ? "" : " (not supported)");
			}
		}
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
	     struct proxy *defpx, const char *file, int line, char **err)
{
	struct flt_conf *fconf = NULL;

	/* Filter cannot be defined on a default proxy */
	if (curpx == defpx) {
		memprintf(err, "parsing [%s:%d] : %s is not allowed in a 'default' section.",
			  file, line, args[0]);
		return -1;
	}
	if (!strcmp(args[0], "filter")) {
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
					memprintf(err, "'%s' : '%s'",
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

		LIST_ADDQ(&curpx->filter_configs, &fconf->list);
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
 */
static int
flt_init(struct proxy *proxy)
{
	struct flt_conf *fconf;

	list_for_each_entry(fconf, &proxy->filter_configs, list) {
		if (fconf->ops->init && fconf->ops->init(proxy, fconf) < 0)
			return ERR_ALERT|ERR_FATAL;
	}
	return 0;
}

/*
 * Calls 'init_per_thread' callback for all filters attached to a proxy for each
 * threads. This happens after the thread creation. Filters can finish to fill
 * their config. Returns (ERR_ALERT|ERR_FATAL) if an error occurs, 0 otherwise.
 */
static int
flt_init_per_thread(struct proxy *proxy)
{
	struct flt_conf *fconf;

	list_for_each_entry(fconf, &proxy->filter_configs, list) {
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
	int err_code = 0;

	for (px = proxies_list; px; px = px->next) {
		err_code |= flt_init(px);
		if (err_code & (ERR_ABORT|ERR_FATAL)) {
			ha_alert("Failed to initialize filters for proxy '%s'.\n",
				 px->id);
			return err_code;
		}
	}
	return 0;
}

/* Calls flt_init_per_thread() for all proxies, see above.  Be carefull here, it
 * returns 0 if an error occured. This is the opposite of flt_init_all. */
static int
flt_init_all_per_thread()
{
	struct proxy *px;
	int err_code = 0;

	for (px = proxies_list; px; px = px->next) {
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
int
flt_check(struct proxy *proxy)
{
	struct flt_conf *fconf;
	int err = 0;

	list_for_each_entry(fconf, &proxy->filter_configs, list) {
		if (fconf->ops->check)
			err += fconf->ops->check(proxy, fconf);
	}
	err += check_legacy_http_comp_flt(proxy);
	return err;
}

/*
 * Calls 'denit' callback for all filters attached to a proxy. This happens when
 * HAProxy is stopped.
 */
void
flt_deinit(struct proxy *proxy)
{
	struct flt_conf *fconf, *back;

	list_for_each_entry_safe(fconf, back, &proxy->filter_configs, list) {
		if (fconf->ops->deinit)
			fconf->ops->deinit(proxy, fconf);
		LIST_DEL(&fconf->list);
		free(fconf);
	}
}

/*
 * Calls 'denit_per_thread' callback for all filters attached to a proxy for
 * each threads. This happens before exiting a thread.
 */
void
flt_deinit_per_thread(struct proxy *proxy)
{
	struct flt_conf *fconf, *back;

	list_for_each_entry_safe(fconf, back, &proxy->filter_configs, list) {
		if (fconf->ops->deinit_per_thread)
			fconf->ops->deinit_per_thread(proxy, fconf);
	}
}


/* Calls flt_deinit_per_thread() for all proxies, see above */
static void
flt_deinit_all_per_thread()
{
	struct proxy *px;

	for (px = proxies_list; px; px = px->next)
		flt_deinit_per_thread(px);
}

/* Attaches a filter to a stream. Returns -1 if an error occurs, 0 otherwise. */
static int
flt_stream_add_filter(struct stream *s, struct flt_conf *fconf, unsigned int flags)
{
	struct filter *f = pool_alloc(pool_head_filter);

	if (!f) /* not enough memory */
		return -1;
	memset(f, 0, sizeof(*f));
	f->config = fconf;
	f->flags |= flags;

	if (FLT_OPS(f)->attach) {
		int ret = FLT_OPS(f)->attach(s, f);
		if (ret <= 0) {
			pool_free(pool_head_filter, f);
			return ret;
		}
	}

	LIST_ADDQ(&strm_flt(s)->filters, &f->list);
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
			if (FLT_OPS(filter)->detach)
				FLT_OPS(filter)->detach(s, filter);
			LIST_DEL(&filter->list);
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
		if (FLT_OPS(filter)->stream_start && FLT_OPS(filter)->stream_start(s, filter) < 0)
			return -1;
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
		if (FLT_OPS(filter)->stream_stop)
			FLT_OPS(filter)->stream_stop(s, filter);
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
		if (FLT_OPS(filter)->check_timeouts)
			FLT_OPS(filter)->check_timeouts(s, filter);
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
		if (FLT_OPS(filter)->stream_set_backend &&
		    FLT_OPS(filter)->stream_set_backend(s, filter, be) < 0)
			return -1;
	}

	return 0;
}

/*
 * Calls 'http_data' callback for all "data" filters attached to a stream. This
 * function is called when incoming data are available (excluding chunks
 * envelope for chunked messages) in the AN_REQ_HTTP_XFER_BODY and
 * AN_RES_HTTP_XFER_BODY analyzers. It takes care to update the next offset of
 * filters and adjusts available data to be sure that a filter cannot parse more
 * data than its predecessors. A filter can choose to not consume all available
 * data. Returns -1 if an error occurs, the number of consumed bytes otherwise.
 */
int
flt_http_data(struct stream *s, struct http_msg *msg)
{
	struct filter *filter;
	unsigned int   buf_i;
	int            delta = 0, ret = 0;

	/* Save buffer state */
	buf_i = msg->chn->buf->i;

	list_for_each_entry(filter, &strm_flt(s)->filters, list) {
		unsigned int *nxt;

		/* Call "data" filters only */
		if (!IS_DATA_FILTER(filter, msg->chn))
			continue;

		/* If the HTTP parser is ahead, we update the next offset of the
		 * current filter. This happens for chunked messages, at the
		 * begining of a new chunk. */
		nxt = &FLT_NXT(filter, msg->chn);
		if (msg->next > *nxt)
			*nxt = msg->next;

		if (FLT_OPS(filter)->http_data) {
			unsigned int i = msg->chn->buf->i;

			ret = FLT_OPS(filter)->http_data(s, filter, msg);
			if (ret < 0)
				break;
			delta += (int)(msg->chn->buf->i - i);

			/* Update the next offset of the current filter */
			*nxt += ret;

			/* And set this value as the bound for the next
			 * filter. It will not able to parse more data than this
			 * one. */
			msg->chn->buf->i = *nxt;
		}
		else {
			/* Consume all available data and update the next offset
			 * of the current filter. buf->i is untouched here. */
			ret = MIN(msg->chunk_len + msg->next, msg->chn->buf->i) - *nxt;
			*nxt += ret;
		}
	}

	/* Restore the original buffer state */
	msg->chn->buf->i = buf_i + delta;

	return ret;
}

/*
 * Calls 'http_chunk_trailers' callback for all "data" filters attached to a
 * stream. This function is called for chunked messages only when a part of the
 * trailers was parsed in the AN_REQ_HTTP_XFER_BODY and AN_RES_HTTP_XFER_BODY
 * analyzers. Filters can know how much data were parsed by the HTTP parsing
 * until the last call with the msg->sol value. Returns a negative value if an
 * error occurs, any other value otherwise.
 */
int
flt_http_chunk_trailers(struct stream *s, struct http_msg *msg)
{
	struct filter *filter;
	int            ret = 1;

	list_for_each_entry(filter, &strm_flt(s)->filters, list) {
		unsigned int *nxt;

		/* Call "data" filters only */
		if (!IS_DATA_FILTER(filter, msg->chn))
			continue;

		/* Be sure to set the next offset of the filter at the right
		 * place. This is really useful when the first part of the
		 * trailers was parsed. */
		nxt = &FLT_NXT(filter, msg->chn);
		*nxt = msg->next;

		if (FLT_OPS(filter)->http_chunk_trailers) {
			ret = FLT_OPS(filter)->http_chunk_trailers(s, filter, msg);
			if (ret < 0)
				break;
		}
		/* Update the next offset of the current filter. Here all data
		 * are always consumed. */
		*nxt += msg->sol;
	}
	return ret;
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
	int ret = 1;

	RESUME_FILTER_LOOP(s, msg->chn) {
		if (FLT_OPS(filter)->http_end) {
			ret = FLT_OPS(filter)->http_end(s, filter, msg);
			if (ret <= 0)
				BREAK_EXECUTION(s, msg->chn, end);
		}
	} RESUME_FILTER_END;
end:
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

	list_for_each_entry(filter, &strm_flt(s)->filters, list) {
		if (FLT_OPS(filter)->http_reset)
			FLT_OPS(filter)->http_reset(s, filter, msg);
	}
}

/*
 * Calls 'http_reply' callback for all filters attached to a stream when HA
 * decides to stop the HTTP message processing.
 */
void
flt_http_reply(struct stream *s, short status, const struct chunk *msg)
{
	struct filter *filter;

	list_for_each_entry(filter, &strm_flt(s)->filters, list) {
		if (FLT_OPS(filter)->http_reply)
			FLT_OPS(filter)->http_reply(s, filter, status, msg);
	}
}

/*
 * Calls 'http_forward_data' callback for all "data" filters attached to a
 * stream. This function is called when some data can be forwarded in the
 * AN_REQ_HTTP_XFER_BODY and AN_RES_HTTP_XFER_BODY analyzers. It takes care to
 * update the forward offset of filters and adjusts "forwardable" data to be
 * sure that a filter cannot forward more data than its predecessors. A filter
 * can choose to not forward all parsed data. Returns a negative value if an
 * error occurs, else the number of forwarded bytes.
 */
int
flt_http_forward_data(struct stream *s, struct http_msg *msg, unsigned int len)
{
	struct filter *filter;
	int            ret = len;

	list_for_each_entry(filter, &strm_flt(s)->filters, list) {
		unsigned int *nxt, *fwd;

		/* Call "data" filters only */
		if (!IS_DATA_FILTER(filter, msg->chn))
			continue;

		/* If the HTTP parser is ahead, we update the next offset of the
		 * current filter. This happens for chunked messages, when the
		 * chunk envelope is parsed. */
		nxt = &FLT_NXT(filter, msg->chn);
		fwd = &FLT_FWD(filter, msg->chn);
		if (msg->next > *nxt)
			*nxt = msg->next;

		if (FLT_OPS(filter)->http_forward_data) {
			/* Remove bytes that the current filter considered as
			 * forwarded */
			ret = FLT_OPS(filter)->http_forward_data(s, filter, msg, ret - *fwd);
			if (ret < 0)
				goto end;
		}

		/* Adjust bytes that the current filter considers as
		 * forwarded */
		*fwd += ret;

		/* And set this value as the bound for the next filter. It will
		 * not able to forward more data than the current one. */
		ret = *fwd;
	}

	if (!ret)
		goto end;

	/* Finally, adjust filters offsets by removing data that HAProxy will
	 * forward. */
	list_for_each_entry(filter, &strm_flt(s)->filters, list) {
		if (!IS_DATA_FILTER(filter, msg->chn))
			continue;
		FLT_NXT(filter, msg->chn) -= ret;
		FLT_FWD(filter, msg->chn) -= ret;
	}
 end:
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
	int ret = 1;

	/* If this function is called, this means there is at least one filter,
	 * so we do not need to check the filter list's emptiness. */

	/* Set flag on channel to tell that the channel is filtered */
	chn->flags |= CF_FLT_ANALYZE;

	RESUME_FILTER_LOOP(s, chn) {
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

		FLT_NXT(filter, chn) = 0;
		FLT_FWD(filter, chn) = 0;

		if (FLT_OPS(filter)->channel_start_analyze) {
			ret = FLT_OPS(filter)->channel_start_analyze(s, filter, chn);
			if (ret <= 0)
				BREAK_EXECUTION(s, chn, end);
		}
	} RESUME_FILTER_END;

 end:
	return handle_analyzer_result(s, chn, an_bit, ret);
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
	int ret = 1;

	RESUME_FILTER_LOOP(s, chn) {
		if (FLT_OPS(filter)->channel_pre_analyze && (filter->pre_analyzers & an_bit)) {
			ret = FLT_OPS(filter)->channel_pre_analyze(s, filter, chn, an_bit);
			if (ret <= 0)
				BREAK_EXECUTION(s, chn, check_result);
		}
	} RESUME_FILTER_END;

 check_result:
	return handle_analyzer_result(s, chn, 0, ret);
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

	list_for_each_entry(filter, &strm_flt(s)->filters, list) {
		if (FLT_OPS(filter)->channel_post_analyze &&  (filter->post_analyzers & an_bit)) {
			ret = FLT_OPS(filter)->channel_post_analyze(s, filter, chn, an_bit);
			if (ret < 0)
				break;
		}
	}
	return handle_analyzer_result(s, chn, 0, ret);
}

/*
 * This function is the AN_REQ/RES_FLT_HTTP_HDRS analyzer, used to filter HTTP
 * headers or a request or a response. Returns 0 if an error occurs or if it
 * needs to wait, any other value otherwise.
 */
int
flt_analyze_http_headers(struct stream *s, struct channel *chn, unsigned int an_bit)
{
	struct filter   *filter;
	struct http_msg *msg;
	int              ret = 1;

	msg = ((chn->flags & CF_ISRESP) ? &s->txn->rsp : &s->txn->req);
	RESUME_FILTER_LOOP(s, chn) {
		if (FLT_OPS(filter)->http_headers) {
			ret = FLT_OPS(filter)->http_headers(s, filter, msg);
			if (ret <= 0)
				BREAK_EXECUTION(s, chn, check_result);
		}
	} RESUME_FILTER_END;

	/* We increase next offset of all "data" filters after all processing on
	 * headers because any filter can alter them. So the definitive size of
	 * headers (msg->sov) is only known when all filters have been
	 * called. */
	list_for_each_entry(filter, &strm_flt(s)->filters, list) {
		/* Handle "data" filters only */
		if (!IS_DATA_FILTER(filter, chn))
			continue;
		FLT_NXT(filter, chn) = msg->sov;
	}

 check_result:
	return handle_analyzer_result(s, chn, an_bit, ret);
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

	/* Check if all filters attached on the stream have finished their
	 * processing on this channel. */
	if (!(chn->flags & CF_FLT_ANALYZE))
		goto sync;

	RESUME_FILTER_LOOP(s, chn) {
		FLT_NXT(filter, chn) = 0;
		FLT_FWD(filter, chn) = 0;
		unregister_data_filter(s, chn, filter);

		if (FLT_OPS(filter)->channel_end_analyze) {
			ret = FLT_OPS(filter)->channel_end_analyze(s, filter, chn);
			if (ret <= 0)
				BREAK_EXECUTION(s, chn, end);
		}
	} RESUME_FILTER_END;

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
		 * processing. Of course, this is the filter responsiblity to
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

		/* Clean up the HTTP transaction if needed */
		if (s->txn && (s->txn->flags & TX_WAIT_CLEANUP))
			http_end_txn_clean_session(s);

		/* Remove backend filters from the list */
		flt_stream_release(s, 1);
	}

	return ret;
}


/*
 * Calls 'tcp_data' callback for all "data" filters attached to a stream. This
 * function is called when incoming data are available. It takes care to update
 * the next offset of filters and adjusts available data to be sure that a
 * filter cannot parse more data than its predecessors. A filter can choose to
 * not consume all available data. Returns -1 if an error occurs, the number of
 * consumed bytes otherwise.
 */
static int
flt_data(struct stream *s, struct channel *chn)
{
	struct filter *filter;
	unsigned int   buf_i;
	int            delta = 0, ret = 0;

	/* Save buffer state */
	buf_i = chn->buf->i;

	list_for_each_entry(filter, &strm_flt(s)->filters, list) {
		unsigned int *nxt;

		/* Call "data" filters only */
		if (!IS_DATA_FILTER(filter, chn))
			continue;

		nxt = &FLT_NXT(filter, chn);
		if (FLT_OPS(filter)->tcp_data) {
			unsigned int i = chn->buf->i;

			ret = FLT_OPS(filter)->tcp_data(s, filter, chn);
			if (ret < 0)
				break;
			delta += (int)(chn->buf->i - i);

			/* Increase next offset of the current filter */
			*nxt += ret;

			/* And set this value as the bound for the next
			 * filter. It will not able to parse more data than the
			 * current one. */
			chn->buf->i = *nxt;
		}
		else {
			/* Consume all available data */
			*nxt = chn->buf->i;
		}

		/* Update <ret> value to be sure to have the last one when we
		 * exit from the loop. This value will be used to know how much
		 * data are "forwardable" */
		ret = *nxt;
	}

	/* Restore the original buffer state */
	chn->buf->i = buf_i + delta;

	return ret;
}

/*
 * Calls 'tcp_forward_data' callback for all "data" filters attached to a
 * stream. This function is called when some data can be forwarded. It takes
 * care to update the forward offset of filters and adjusts "forwardable" data
 * to be sure that a filter cannot forward more data than its predecessors. A
 * filter can choose to not forward all parsed data. Returns a negative value if
 * an error occurs, else the number of forwarded bytes.
 */
static int
flt_forward_data(struct stream *s, struct channel *chn, unsigned int len)
{
	struct filter *filter;
	int            ret = len;

	list_for_each_entry(filter, &strm_flt(s)->filters, list) {
		unsigned int *fwd;

		/* Call "data" filters only */
		if (!IS_DATA_FILTER(filter, chn))
			continue;

		fwd = &FLT_FWD(filter, chn);
		if (FLT_OPS(filter)->tcp_forward_data) {
			/* Remove bytes that the current filter considered as
			 * forwarded */
			ret = FLT_OPS(filter)->tcp_forward_data(s, filter, chn, ret - *fwd);
			if (ret < 0)
				goto end;
		}

		/* Adjust bytes that the current filter considers as
		 * forwarded */
		*fwd += ret;

		/* And set this value as the bound for the next filter. It will
		 * not able to forward more data than the current one. */
		ret = *fwd;
	}

	if (!ret)
		goto end;

	/* Finally, adjust filters offsets by removing data that HAProxy will
	 * forward. */
	list_for_each_entry(filter, &strm_flt(s)->filters, list) {
		if (!IS_DATA_FILTER(filter, chn))
			continue;
		FLT_NXT(filter, chn) -= ret;
		FLT_FWD(filter, chn) -= ret;
	}

 end:
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
	int ret = 1;

	/* If there is no "data" filters, we do nothing */
	if (!HAS_DATA_FILTERS(s, chn))
		goto end;

	/* Be sure that the output is still opened. Else we stop the data
	 * filtering. */
	if ((chn->flags & (CF_READ_ERROR|CF_READ_TIMEOUT|CF_WRITE_ERROR|CF_WRITE_TIMEOUT)) ||
	    ((chn->flags & CF_SHUTW) && (chn->to_forward || chn->buf->o)))
		goto end;

	/* Let all "data" filters parsing incoming data */
	ret = flt_data(s, chn);
	if (ret < 0)
		goto end;

	/* And forward them */
	ret = flt_forward_data(s, chn, ret);
	if (ret < 0)
		goto end;

	/* Consume data that all filters consider as forwarded. */
	b_adv(chn->buf, ret);

	/* Stop waiting data if the input in closed and no data is pending or if
	 * the output is closed. */
	if ((chn->flags & CF_SHUTW) ||
	    ((chn->flags & CF_SHUTR) && !buffer_pending(chn->buf))) {
		ret = 1;
		goto end;
	}

	/* Wait for data */
	return 0;
 end:
	/* Terminate the data filtering. If <ret> is negative, an error was
	 * encountered during the filtering. */
	return handle_analyzer_result(s, chn, an_bit, ret);
}

/*
 * Handles result of filter's analyzers. It returns 0 if an error occurs or if
 * it needs to wait, any other value otherwise.
 */
static int
handle_analyzer_result(struct stream *s, struct channel *chn,
		       unsigned int an_bit, int ret)
{
	int finst;

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
	channel_abort(&s->req);
	channel_abort(&s->res);

	if (!(chn->flags & CF_ISRESP)) {
		s->req.analysers &= AN_REQ_FLT_END;
		finst = SF_FINST_R;
		/* FIXME: incr counters */
	}
	else {
		s->res.analysers &= AN_RES_FLT_END;
		finst = SF_FINST_H;
		/* FIXME: incr counters */
	}

	if (s->txn) {
		/* Do not do that when we are waiting for the next request */
		if (s->txn->status)
			http_reply_and_close(s, s->txn->status, NULL);
		else {
			s->txn->status = 400;
			http_reply_and_close(s, 400, http_error_message(s));
		}
	}

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= finst;
	return 0;

 wait:
	if (!(chn->flags & CF_ISRESP))
		channel_dont_connect(chn);
	return 0;
}


/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled. */
static struct cfg_kw_list cfg_kws = {ILH, {
		{ CFG_LISTEN, "filter", parse_filter },
		{ 0, NULL, NULL },
	}
};

__attribute__((constructor))
static void
__filters_init(void)
{
        pool_head_filter = create_pool("filter", sizeof(struct filter), MEM_F_SHARED);
	cfg_register_keywords(&cfg_kws);
	hap_register_post_check(flt_init_all);
	hap_register_per_thread_init(flt_init_all_per_thread);
	hap_register_per_thread_deinit(flt_deinit_all_per_thread);
}

__attribute__((destructor))
static void
__filters_deinit(void)
{
	pool_destroy(pool_head_filter);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
