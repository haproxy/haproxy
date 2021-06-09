/***
 * Copyright 2020 HAProxy Technologies
 *
 * This file is part of the HAProxy OpenTracing filter.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include "include.h"


/*
 * OpenTracing filter id, used to identify OpenTracing filters.
 * The name of this variable is consistent with the other filter names
 * declared in include/haproxy/filters.h .
 */
const char *ot_flt_id = "the OpenTracing filter";


/***
 * NAME
 *   flt_ot_is_disabled -
 *
 * ARGUMENTS
 *   f     -
 *   event -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
bool flt_ot_is_disabled(const struct filter *f FLT_OT_DBG_ARGS(, int event))
{
#ifdef DEBUG_OT
	const struct flt_ot_conf *conf = FLT_OT_CONF(f);
	const char               *msg;
#endif
	bool                      retval;

	retval = FLT_OT_RT_CTX(f->ctx)->flag_disabled ? 1 : 0;

#ifdef DEBUG_OT
	msg    = retval ? " (disabled)" : "";

	if (FLT_OT_IN_RANGE(event, 0, FLT_OT_EVENT_MAX - 1))
		FLT_OT_DBG(2, "filter '%s', type: %s, event: '%s' %d%s", conf->id, flt_ot_type(f), flt_ot_event_data[event].name, event, msg);
	else
		FLT_OT_DBG(2, "filter '%s', type: %s%s", conf->id, flt_ot_type(f), msg);
#endif

	return retval;
}


/***
 * NAME
 *   flt_ot_return_int -
 *
 * ARGUMENTS
 *   f      -
 *   err    -
 *   retval -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static int flt_ot_return_int(const struct filter *f, char **err, int retval)
{
	struct flt_ot_runtime_context *rt_ctx = f->ctx;

	if ((retval == FLT_OT_RET_ERROR) || ((err != NULL) && (*err != NULL))) {
		if (rt_ctx->flag_harderr) {
			FLT_OT_DBG(1, "WARNING: filter hard-error (disabled)");

			rt_ctx->flag_disabled = 1;

			_HA_ATOMIC_ADD(FLT_OT_CONF(f)->cnt.disabled + 1, 1);
		} else {
			FLT_OT_DBG(1, "WARNING: filter soft-error");
		}

		retval = FLT_OT_RET_OK;
	}

	FLT_OT_ERR_FREE(*err);

	return retval;
}


/***
 * NAME
 *   flt_ot_return_void -
 *
 * ARGUMENTS
 *   f   -
 *   err -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_ot_return_void(const struct filter *f, char **err)
{
	struct flt_ot_runtime_context *rt_ctx = f->ctx;

	if ((err != NULL) && (*err != NULL)) {
		if (rt_ctx->flag_harderr) {
			FLT_OT_DBG(1, "WARNING: filter hard-error (disabled)");

			rt_ctx->flag_disabled = 1;

			_HA_ATOMIC_ADD(FLT_OT_CONF(f)->cnt.disabled + 1, 1);
		} else {
			FLT_OT_DBG(1, "WARNING: filter soft-error");
		}
	}

	FLT_OT_ERR_FREE(*err);
}


/***
 * NAME
 *   flt_ot_init - Initialize the filter.
 *
 * ARGUMENTS
 *   p     -
 *   fconf -
 *
 * DESCRIPTION
 *   It initializes the filter for a proxy.  You may define this callback
 *   if you need to complete your filter configuration.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, any other value otherwise.
 */
static int flt_ot_init(struct proxy *p, struct flt_conf *fconf)
{
	struct flt_ot_conf *conf = FLT_OT_DEREF(fconf, conf, NULL);
	char               *err = NULL;
	int                 retval = FLT_OT_RET_ERROR;

	FLT_OT_FUNC("%p, %p", p, fconf);

	if (conf == NULL)
		FLT_OT_RETURN(retval);

	flt_ot_cli_init();

	/*
	 * Initialize the OpenTracing library.
	 * Enable HTX streams filtering.
	 */
	retval = ot_init(&(conf->tracer->tracer), conf->tracer->config, conf->tracer->plugin, &err);
	if (retval != FLT_OT_RET_ERROR)
		fconf->flags |= FLT_CFG_FL_HTX;
	else if (err != NULL) {
		FLT_OT_ALERT("%s", err);

		FLT_OT_ERR_FREE(err);
	}

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_deinit - Free resources allocated by the filter.
 *
 * ARGUMENTS
 *   p     -
 *   fconf -
 *
 * DESCRIPTION
 *   It cleans up what the parsing function and the init callback have done.
 *   This callback is useful to release memory allocated for the filter
 *   configuration.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_ot_deinit(struct proxy *p, struct flt_conf *fconf)
{
	struct flt_ot_conf **conf = (fconf == NULL) ? NULL : (typeof(conf))&(fconf->conf);
#ifdef DEBUG_OT
	int                  i;
#endif

	FLT_OT_FUNC("%p, %p", p, fconf);

	if (conf == NULL)
		FLT_OT_RETURN();

	ot_debug();
	ot_close(&((*conf)->tracer->tracer));

#ifdef DEBUG_OT
	FLT_OT_DBG(0, "--- used events ----------");
	for (i = 0; i < FLT_OT_TABLESIZE((*conf)->cnt.event); i++)
		if ((*conf)->cnt.event[i].flag_used)
			FLT_OT_DBG(0, "  %02d: %" PRIu64 " / %" PRIu64, i, (*conf)->cnt.event[i].htx[0], (*conf)->cnt.event[i].htx[1]);
#endif

	flt_ot_conf_free(conf);

	FLT_OT_MEMINFO();

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_check - Check configuration of the filter for the specified proxy.
 *
 * ARGUMENTS
 *   p     -
 *   fconf -
 *
 * DESCRIPTION
 *   Optionally, by implementing the flt_ot_check() callback, you add a
 *   step to check the internal configuration of your filter after the
 *   parsing phase, when the HAProxy configuration is fully defined.
 *
 * RETURN VALUE
 *   Returns the number of encountered errors.
 */
static int flt_ot_check(struct proxy *p, struct flt_conf *fconf)
{
	struct proxy             *px;
	struct flt_ot_conf       *conf = FLT_OT_DEREF(fconf, conf, NULL);
	struct flt_ot_conf_group *conf_group;
	struct flt_ot_conf_scope *conf_scope;
	struct flt_ot_conf_ph    *ph_group, *ph_scope;
	int                       retval = 0, scope_unused_cnt = 0, span_root_cnt = 0;

	FLT_OT_FUNC("%p, %p", p, fconf);

	if (conf == NULL)
		FLT_OT_RETURN(++retval);

	/*
	 * If only the proxy specified with the <p> parameter is checked, then
	 * no duplicate filters can be found that are not defined in the same
	 * configuration sections.
	 */
	for (px = proxies_list; px != NULL; px = px->next) {
		struct flt_conf *fconf_tmp;

		FLT_OT_DBG(2, "proxy '%s'", px->id);

		/*
		 * The names of all OT filters (filter ID) should be checked,
		 * they must be unique.
		 */
		list_for_each_entry(fconf_tmp, &(px->filter_configs), list)
			if ((fconf_tmp != fconf) && (fconf_tmp->id == ot_flt_id)) {
				struct flt_ot_conf *conf_tmp = fconf_tmp->conf;

				FLT_OT_DBG(2, "  OT filter '%s'", conf_tmp->id);

				if (strcmp(conf_tmp->id, conf->id) == 0) {
					FLT_OT_ALERT("''%s' : duplicated filter ID'", conf_tmp->id);

					retval++;
				}
			}
	}

	if (FLT_OT_DEREF(conf->tracer, id, NULL) == NULL) {
		FLT_OT_ALERT("''%s' : no tracer found'", conf->id);

		retval++;
	}

	/*
	 * Checking that all defined 'ot-group' sections have correctly declared
	 * 'ot-scope' sections (ie whether the declared 'ot-scope' sections have
	 * corresponding definitions).
	 */
	list_for_each_entry(conf_group, &(conf->groups), list)
		list_for_each_entry(ph_scope, &(conf_group->ph_scopes), list) {
			bool flag_found = 0;

			list_for_each_entry(conf_scope, &(conf->scopes), list)
				if (strcmp(ph_scope->id, conf_scope->id) == 0) {
					ph_scope->ptr         = conf_scope;
					conf_scope->flag_used = 1;
					flag_found            = 1;

					break;
				}

			if (!flag_found) {
				FLT_OT_ALERT("'" FLT_OT_PARSE_SECTION_GROUP_ID " '%s' : try to use undefined " FLT_OT_PARSE_SECTION_SCOPE_ID " '%s''", conf_group->id, ph_scope->id);

				retval++;
			}
		}

	if (conf->tracer != NULL) {
		/*
		 * Checking that all declared 'groups' keywords have correctly
		 * defined 'ot-group' sections.
		 */
		list_for_each_entry(ph_group, &(conf->tracer->ph_groups), list) {
			bool flag_found = 0;

			list_for_each_entry(conf_group, &(conf->groups), list)
				if (strcmp(ph_group->id, conf_group->id) == 0) {
					ph_group->ptr         = conf_group;
					conf_group->flag_used = 1;
					flag_found            = 1;

					break;
				}

			if (!flag_found) {
				FLT_OT_ALERT("'" FLT_OT_PARSE_SECTION_TRACER_ID " '%s' : try to use undefined " FLT_OT_PARSE_SECTION_GROUP_ID " '%s''", conf->tracer->id, ph_group->id);

				retval++;
			}
		}

		/*
		 * Checking that all declared 'scopes' keywords have correctly
		 * defined 'ot-scope' sections.
		 */
		list_for_each_entry(ph_scope, &(conf->tracer->ph_scopes), list) {
			bool flag_found = 0;

			list_for_each_entry(conf_scope, &(conf->scopes), list)
				if (strcmp(ph_scope->id, conf_scope->id) == 0) {
					ph_scope->ptr         = conf_scope;
					conf_scope->flag_used = 1;
					flag_found            = 1;

					break;
				}

			if (!flag_found) {
				FLT_OT_ALERT("'" FLT_OT_PARSE_SECTION_TRACER_ID " '%s' : try to use undefined " FLT_OT_PARSE_SECTION_SCOPE_ID " '%s''", conf->tracer->id, ph_scope->id);

				retval++;
			}
		}
	}

	FLT_OT_DBG(3, "--- filter '%s' configuration ----------", conf->id);
	FLT_OT_DBG(3, "- defined spans ----------");

	list_for_each_entry(conf_scope, &(conf->scopes), list) {
		if (conf_scope->flag_used) {
			struct flt_ot_conf_span *conf_span;

			/*
			 * In principle, only one span should be labeled
			 * as a root span.
			 */
			list_for_each_entry(conf_span, &(conf_scope->spans), list) {
				FLT_OT_DBG_CONF_SPAN("   ", conf_span);

				span_root_cnt += conf_span->flag_root ? 1 : 0;
			}

#ifdef DEBUG_OT
			conf->cnt.event[conf_scope->event].flag_used = 1;
#endif

			/* Set the flags of the analyzers used. */
			conf->tracer->analyzers |= flt_ot_event_data[conf_scope->event].an_bit;
		} else {
			FLT_OT_ALERT("''%s' : unused " FLT_OT_PARSE_SECTION_SCOPE_ID " '%s''", conf->id, conf_scope->id);

			scope_unused_cnt++;
		}
	}

	/*
	 * Unused scopes or a number of root spans other than one do not
	 * necessarily have to be errors, but it is good to print it when
	 * starting HAProxy.
	 */
	if (scope_unused_cnt > 0)
		FLT_OT_ALERT("''%s' : %d scope(s) not in use'", conf->id, scope_unused_cnt);

	if (LIST_ISEMPTY(&(conf->scopes)))
		/* Do nothing. */;
	else if (span_root_cnt == 0)
		FLT_OT_ALERT("''%s' : no span is marked as the root span'", conf->id);
	else if (span_root_cnt > 1)
		FLT_OT_ALERT("''%s' : multiple spans are marked as the root span'", conf->id);

	FLT_OT_DBG_LIST(conf, group, "", "defined", _group,
	                FLT_OT_DBG_CONF_GROUP("   ", _group);
	                FLT_OT_DBG_LIST(_group, ph_scope, "   ", "used", _scope, FLT_OT_DBG_CONF_PH("      ", _scope)));
	FLT_OT_DBG_LIST(conf, scope, "", "defined", _scope, FLT_OT_DBG_CONF_SCOPE("   ", _scope));

	if (conf->tracer != NULL) {
		FLT_OT_DBG(3, "   --- tracer '%s' configuration ----------", conf->tracer->id);
		FLT_OT_DBG_LIST(conf->tracer, ph_group, "   ", "used", _group, FLT_OT_DBG_CONF_PH("      ", _group));
		FLT_OT_DBG_LIST(conf->tracer, ph_scope, "   ", "used", _scope, FLT_OT_DBG_CONF_PH("      ", _scope));
	}

	FLT_OT_RETURN(retval);
}


#ifdef DEBUG_OT

/***
 * NAME
 *   flt_ot_init_per_thread -
 *
 * ARGUMENTS
 *   p     -
 *   fconf -
 *
 * DESCRIPTION
 *   It initializes the filter for each thread.  It works the same way than
 *   flt_ot_init() but in the context of a thread.  This callback is called
 *   after the thread creation.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, any other value otherwise.
 */
static int flt_ot_init_per_thread(struct proxy *p, struct flt_conf *fconf)
{
	int retval = FLT_OT_RET_OK;

	FLT_OT_FUNC("%p, %p", p, fconf);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_deinit_per_thread -
 *
 * ARGUMENTS
 *   p     -
 *   fconf -
 *
 * DESCRIPTION
 *   It cleans up what the init_per_thread callback have done.  It is called
 *   in the context of a thread, before exiting it.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_ot_deinit_per_thread(struct proxy *p, struct flt_conf *fconf)
{
	FLT_OT_FUNC("%p, %p", p, fconf);

	FLT_OT_RETURN();
}

#endif /* DEBUG_OT */


/***
 * NAME
 *   flt_ot_attach - Called when a filter instance is created and attach to a stream.
 *
 * ARGUMENTS
 *   s -
 *   f -
 *
 * DESCRIPTION
 *   It is called after a filter instance creation, when it is attached to a
 *   stream.  This happens when the stream is started for filters defined on
 *   the stream's frontend and when the backend is set for filters declared
 *   on the stream's backend.  It is possible to ignore the filter, if needed,
 *   by returning 0.  This could be useful to have conditional filtering.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 to ignore the filter,
 *   any other value otherwise.
 */
static int flt_ot_attach(struct stream *s, struct filter *f)
{
	const struct flt_ot_conf *conf = FLT_OT_CONF(f);
	char                     *err = NULL;

	FLT_OT_FUNC("%p, %p", s, f);

	if (conf->tracer->flag_disabled) {
		FLT_OT_DBG(2, "filter '%s', type: %s (disabled)", conf->id, flt_ot_type(f));

		FLT_OT_RETURN(FLT_OT_RET_IGNORE);
	}
	else if (conf->tracer->rate_limit < FLT_OT_FLOAT_U32(FLT_OT_RATE_LIMIT_MAX, FLT_OT_RATE_LIMIT_MAX)) {
		uint32_t rnd = ha_random32();

		if (conf->tracer->rate_limit <= rnd) {
			FLT_OT_DBG(2, "filter '%s', type: %s (ignored: %u <= %u)", conf->id, flt_ot_type(f), conf->tracer->rate_limit, rnd);

			FLT_OT_RETURN(FLT_OT_RET_IGNORE);
		}
	}

	FLT_OT_DBG(2, "filter '%s', type: %s (run)", conf->id, flt_ot_type(f));

	f->ctx = flt_ot_runtime_context_init(s, f, &err);
	FLT_OT_ERR_FREE(err);
	if (f->ctx == NULL) {
		FLT_OT_LOG(LOG_EMERG, "failed to create context");

		FLT_OT_RETURN(FLT_OT_RET_IGNORE);
	}

	/*
	 * AN_REQ_WAIT_HTTP and AN_RES_WAIT_HTTP analyzers can only be used
	 * in the .channel_post_analyze callback function.
	 */
	f->pre_analyzers  |= conf->tracer->analyzers & ((AN_REQ_ALL & ~AN_REQ_WAIT_HTTP & ~AN_REQ_HTTP_TARPIT) | (AN_RES_ALL & ~AN_RES_WAIT_HTTP));
	f->post_analyzers |= conf->tracer->analyzers & (AN_REQ_WAIT_HTTP | AN_RES_WAIT_HTTP);

	FLT_OT_LOG(LOG_INFO, "%08x %08x", f->pre_analyzers, f->post_analyzers);

	flt_ot_vars_dump(s);
	flt_ot_http_headers_dump(&(s->req));

	FLT_OT_RETURN(FLT_OT_RET_OK);
}


#ifdef DEBUG_OT

/***
 * NAME
 *   flt_ot_stream_start - Called when a stream is created.
 *
 * ARGUMENTS
 *   s -
 *   f -
 *
 * DESCRIPTION
 *   It is called when a stream is started.  This callback can fail by
 *   returning a negative value.  It will be considered as a critical error
 *   by HAProxy which disabled the listener for a short time.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, any other value otherwise.
 */
static int flt_ot_stream_start(struct stream *s, struct filter *f)
{
	char *err = NULL;
	int   retval = FLT_OT_RET_OK;

	FLT_OT_FUNC("%p, %p", s, f);

	if (flt_ot_is_disabled(f FLT_OT_DBG_ARGS(, -1)))
		FLT_OT_RETURN(retval);

	FLT_OT_RETURN(flt_ot_return_int(f, &err, retval));
}


/***
 * NAME
 *   flt_ot_stream_set_backend - Called when a backend is set for a stream.
 *
 * ARGUMENTS
 *   s  -
 *   f  -
 *   be -
 *
 * DESCRIPTION
 *   It is called when a backend is set for a stream.  This callbacks will be
 *   called for all filters attached to a stream (frontend and backend).  Note
 *   this callback is not called if the frontend and the backend are the same.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, any other value otherwise.
 */
static int flt_ot_stream_set_backend(struct stream *s, struct filter *f, struct proxy *be)
{
	char *err = NULL;
	int   retval = FLT_OT_RET_OK;

	FLT_OT_FUNC("%p, %p, %p", s, f, be);

	if (flt_ot_is_disabled(f FLT_OT_DBG_ARGS(, -1)))
		FLT_OT_RETURN(retval);

	FLT_OT_DBG(3, "backend: %s", be->id);

	FLT_OT_RETURN(flt_ot_return_int(f, &err, retval));
}


/***
 * NAME
 *   flt_ot_stream_stop - Called when a stream is destroyed.
 *
 * ARGUMENTS
 *   s -
 *   f -
 *
 * DESCRIPTION
 *   It is called when a stream is stopped.  This callback always succeed.
 *   Anyway, it is too late to return an error.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_ot_stream_stop(struct stream *s, struct filter *f)
{
	char *err = NULL;

	FLT_OT_FUNC("%p, %p", s, f);

	if (flt_ot_is_disabled(f FLT_OT_DBG_ARGS(, -1)))
		FLT_OT_RETURN();

	flt_ot_return_void(f, &err);

	FLT_OT_RETURN();
}

#endif /* DEBUG_OT */


/***
 * NAME
 *   flt_ot_detach - Called when a filter instance is detach from a stream, just before its destruction.
 *
 * ARGUMENTS
 *   s -
 *   f -
 *
 * DESCRIPTION
 *   It is called when a filter instance is detached from a stream, before its
 *   destruction.  This happens when the stream is stopped for filters defined
 *   on the stream's frontend and when the analyze ends for filters defined on
 *   the stream's backend.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_ot_detach(struct stream *s, struct filter *f)
{
	FLT_OT_FUNC("%p, %p", s, f);

	FLT_OT_DBG(2, "filter '%s', type: %s", FLT_OT_CONF(f)->id, flt_ot_type(f));

	flt_ot_runtime_context_free(f);

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_check_timeouts - Called when a stream is woken up because of an expired timer.
 *
 * ARGUMENTS
 *   s -
 *   f -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_ot_check_timeouts(struct stream *s, struct filter *f)
{
	char *err = NULL;

	FLT_OT_FUNC("%p, %p", s, f);

	if (flt_ot_is_disabled(f FLT_OT_DBG_ARGS(, -1)))
		FLT_OT_RETURN();

	s->pending_events |= TASK_WOKEN_MSG;

	flt_ot_return_void(f, &err);

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_channel_start_analyze - Called when analyze starts for a given channel.
 *
 * ARGUMENTS
 *   s   -
 *   f   -
 *   chn -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_ot_channel_start_analyze(struct stream *s, struct filter *f, struct channel *chn)
{
	char *err = NULL;
	int   retval;

	FLT_OT_FUNC("%p, %p, %p", s, f, chn);

	if (flt_ot_is_disabled(f FLT_OT_DBG_ARGS(, (chn->flags & CF_ISRESP) ? FLT_OT_EVENT_RES_SERVER_SESS_START : FLT_OT_EVENT_REQ_CLIENT_SESS_START)))
		FLT_OT_RETURN(FLT_OT_RET_OK);

	FLT_OT_DBG(3, "channel: %s, mode: %s (%s)", flt_ot_chn_label(chn), flt_ot_pr_mode(s), flt_ot_stream_pos(s));

	if (chn->flags & CF_ISRESP) {
		/* The response channel. */
		chn->analysers |= f->pre_analyzers & AN_RES_ALL;

		/* The event 'on-server-session-start'. */
		retval = flt_ot_event_run(s, f, chn, FLT_OT_EVENT_RES_SERVER_SESS_START, &err);
		if (retval == FLT_OT_RET_WAIT) {
			channel_dont_read(chn);
			channel_dont_close(chn);
		}
	} else {
		/* The request channel. */
		chn->analysers |= f->pre_analyzers & AN_REQ_ALL;

		/* The event 'on-client-session-start'. */
		retval = flt_ot_event_run(s, f, chn, FLT_OT_EVENT_REQ_CLIENT_SESS_START, &err);
	}

//	register_data_filter(s, chn, f);

	FLT_OT_RETURN(flt_ot_return_int(f, &err, retval));
}


/***
 * NAME
 *   flt_ot_channel_pre_analyze - Called before a processing happens on a given channel.
 *
 * ARGUMENTS
 *   s      -
 *   f      -
 *   chn    - the channel on which the analyzing is done
 *   an_bit - the analyzer id
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_ot_channel_pre_analyze(struct stream *s, struct filter *f, struct channel *chn, uint an_bit)
{
	char *err = NULL;
	int   i, event = -1, retval;

	FLT_OT_FUNC("%p, %p, %p, 0x%08x", s, f, chn, an_bit);

	for (i = 0; i < FLT_OT_TABLESIZE(flt_ot_event_data); i++)
		if (flt_ot_event_data[i].an_bit == an_bit) {
			event = i;

			break;
		}

	if (flt_ot_is_disabled(f FLT_OT_DBG_ARGS(, event)))
		FLT_OT_RETURN(FLT_OT_RET_OK);

	FLT_OT_DBG(3, "channel: %s, mode: %s (%s), analyzer: %s", flt_ot_chn_label(chn), flt_ot_pr_mode(s), flt_ot_stream_pos(s), flt_ot_analyzer(an_bit));

	retval = flt_ot_event_run(s, f, chn, event, &err);

	if ((retval == FLT_OT_RET_WAIT) && (chn->flags & CF_ISRESP)) {
		channel_dont_read(chn);
		channel_dont_close(chn);
	}

	FLT_OT_RETURN(flt_ot_return_int(f, &err, retval));
}


/***
 * NAME
 *   flt_ot_channel_post_analyze - Called after a processing happens on a given channel.
 *
 * ARGUMENTS
 *   s      -
 *   f      -
 *   chn    -
 *   an_bit -
 *
 * DESCRIPTION
 *   This function, for its part, is not resumable.  It is called when a
 *   filterable analyzer finishes its processing.  So it called once for
 *   the same analyzer.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_ot_channel_post_analyze(struct stream *s, struct filter *f, struct channel *chn, uint an_bit)
{
	char *err = NULL;
	int   i, event = -1, retval;

	FLT_OT_FUNC("%p, %p, %p, 0x%08x", s, f, chn, an_bit);

	for (i = 0; i < FLT_OT_TABLESIZE(flt_ot_event_data); i++)
		if (flt_ot_event_data[i].an_bit == an_bit) {
			event = i;

			break;
		}

	if (flt_ot_is_disabled(f FLT_OT_DBG_ARGS(, event)))
		FLT_OT_RETURN(FLT_OT_RET_OK);

	FLT_OT_DBG(3, "channel: %s, mode: %s (%s), analyzer: %s", flt_ot_chn_label(chn), flt_ot_pr_mode(s), flt_ot_stream_pos(s), flt_ot_analyzer(an_bit));

	retval = flt_ot_event_run(s, f, chn, event, &err);

	FLT_OT_RETURN(flt_ot_return_int(f, &err, retval));
}


/***
 * NAME
 *   flt_ot_channel_end_analyze - Called when analyze ends for a given channel.
 *
 * ARGUMENTS
 *   s   -
 *   f   -
 *   chn -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_ot_channel_end_analyze(struct stream *s, struct filter *f, struct channel *chn)
{
	char *err = NULL;
	int   rc, retval;

	FLT_OT_FUNC("%p, %p, %p", s, f, chn);

	if (flt_ot_is_disabled(f FLT_OT_DBG_ARGS(, (chn->flags & CF_ISRESP) ? FLT_OT_EVENT_RES_SERVER_SESS_END : FLT_OT_EVENT_REQ_CLIENT_SESS_END)))
		FLT_OT_RETURN(FLT_OT_RET_OK);

	FLT_OT_DBG(3, "channel: %s, mode: %s (%s)", flt_ot_chn_label(chn), flt_ot_pr_mode(s), flt_ot_stream_pos(s));

	if (chn->flags & CF_ISRESP) {
		/* The response channel, event 'on-server-session-end'. */
		retval = flt_ot_event_run(s, f, chn, FLT_OT_EVENT_RES_SERVER_SESS_END, &err);
	} else {
		/* The request channel, event 'on-client-session-end'. */
		retval = flt_ot_event_run(s, f, chn, FLT_OT_EVENT_REQ_CLIENT_SESS_END, &err);

		/*
		 * In case an event using server response is defined and not
		 * executed, event 'on-server-unavailable' is called here.
		 */
		if ((FLT_OT_CONF(f)->tracer->analyzers & AN_RES_ALL) && !(FLT_OT_RT_CTX(f->ctx)->analyzers & AN_RES_ALL)) {
			rc = flt_ot_event_run(s, f, chn, FLT_OT_EVENT_REQ_SERVER_UNAVAILABLE, &err);
			if ((retval == FLT_OT_RET_OK) && (rc != FLT_OT_RET_OK))
				retval = rc;
		}
	}

	FLT_OT_RETURN(flt_ot_return_int(f, &err, retval));
}


#ifdef DEBUG_OT

/***
 * NAME
 *   flt_ot_http_headers -
 *
 * ARGUMENTS
 *   s   -
 *   f   -
 *   msg -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_ot_http_headers(struct stream *s, struct filter *f, struct http_msg *msg)
{
	char          *err = NULL;
	struct htx    *htx = htxbuf(&(msg->chn->buf));
	struct htx_sl *sl = http_get_stline(htx);
	int            retval = FLT_OT_RET_OK;

	FLT_OT_FUNC("%p, %p, %p", s, f, msg);

	if (flt_ot_is_disabled(f FLT_OT_DBG_ARGS(, -1)))
		FLT_OT_RETURN(retval);

	FLT_OT_DBG(3, "channel: %s, mode: %s (%s), %.*s %.*s %.*s", flt_ot_chn_label(msg->chn), flt_ot_pr_mode(s), flt_ot_stream_pos(s), HTX_SL_P1_LEN(sl), HTX_SL_P1_PTR(sl), HTX_SL_P2_LEN(sl), HTX_SL_P2_PTR(sl), HTX_SL_P3_LEN(sl), HTX_SL_P3_PTR(sl));

	FLT_OT_RETURN(flt_ot_return_int(f, &err, retval));
}


/***
 * NAME
 *   flt_ot_http_payload -
 *
 * ARGUMENTS
 *   s      -
 *   f      -
 *   msg    -
 *   offset -
 *   len    -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, any other value otherwise.
 */
static int flt_ot_http_payload(struct stream *s, struct filter *f, struct http_msg *msg, uint offset, uint len)
{
	char *err = NULL;
	int   retval = len;

	FLT_OT_FUNC("%p, %p, %p, %u, %u", s, f, msg, offset, len);

	if (flt_ot_is_disabled(f FLT_OT_DBG_ARGS(, -1)))
		FLT_OT_RETURN(len);

	FLT_OT_DBG(3, "channel: %s, mode: %s (%s), offset: %u, len: %u, forward: %d", flt_ot_chn_label(msg->chn), flt_ot_pr_mode(s), flt_ot_stream_pos(s), offset, len, retval);

	if (retval != len)
		task_wakeup(s->task, TASK_WOKEN_MSG);

	FLT_OT_RETURN(flt_ot_return_int(f, &err, retval));
}


/***
 * NAME
 *   flt_ot_http_end -
 *
 * ARGUMENTS
 *   s   -
 *   f   -
 *   msg -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_ot_http_end(struct stream *s, struct filter *f, struct http_msg *msg)
{
	char *err = NULL;
	int   retval = FLT_OT_RET_OK;

	FLT_OT_FUNC("%p, %p, %p", s, f, msg);

	if (flt_ot_is_disabled(f FLT_OT_DBG_ARGS(, -1)))
		FLT_OT_RETURN(retval);

	FLT_OT_DBG(3, "channel: %s, mode: %s (%s)", flt_ot_chn_label(msg->chn), flt_ot_pr_mode(s), flt_ot_stream_pos(s));

	FLT_OT_RETURN(flt_ot_return_int(f, &err, retval));
}


/***
 * NAME
 *   flt_ot_http_reset -
 *
 * ARGUMENTS
 *   s   -
 *   f   -
 *   msg -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_ot_http_reset(struct stream *s, struct filter *f, struct http_msg *msg)
{
	char *err = NULL;

	FLT_OT_FUNC("%p, %p, %p", s, f, msg);

	if (flt_ot_is_disabled(f FLT_OT_DBG_ARGS(, -1)))
		FLT_OT_RETURN();

	FLT_OT_DBG(3, "channel: %s, mode: %s (%s)", flt_ot_chn_label(msg->chn), flt_ot_pr_mode(s), flt_ot_stream_pos(s));

	flt_ot_return_void(f, &err);

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_http_reply -
 *
 * ARGUMENTS
 *   s      -
 *   f      -
 *   status -
 *   msg    -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_ot_http_reply(struct stream *s, struct filter *f, short status, const struct buffer *msg)
{
	char *err = NULL;

	FLT_OT_FUNC("%p, %p, %hd, %p", s, f, status, msg);

	if (flt_ot_is_disabled(f FLT_OT_DBG_ARGS(, -1)))
		FLT_OT_RETURN();

	FLT_OT_DBG(3, "channel: -, mode: %s (%s)", flt_ot_pr_mode(s), flt_ot_stream_pos(s));

	flt_ot_return_void(f, &err);

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_tcp_payload -
 *
 * ARGUMENTS
 *   s      -
 *   f      -
 *   chn    -
 *   offset -
 *   len    -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, any other value otherwise.
 */
static int flt_ot_tcp_payload(struct stream *s, struct filter *f, struct channel *chn, uint offset, uint len)
{
	char *err = NULL;
	int   retval = len;

	FLT_OT_FUNC("%p, %p, %p, %u, %u", s, f, chn, offset, len);

	if (flt_ot_is_disabled(f FLT_OT_DBG_ARGS(, -1)))
		FLT_OT_RETURN(len);

	FLT_OT_DBG(3, "channel: %s, mode: %s (%s), offset: %u, len: %u, forward: %d", flt_ot_chn_label(chn), flt_ot_pr_mode(s), flt_ot_stream_pos(s), offset, len, retval);

	if (s->flags & SF_HTX) {
	} else {
	}

	if (retval != len)
		task_wakeup(s->task, TASK_WOKEN_MSG);

	FLT_OT_RETURN(flt_ot_return_int(f, &err, retval));
}

#endif /* DEBUG_OT */


struct flt_ops flt_ot_ops = {
	/* Callbacks to manage the filter lifecycle. */
	.init                  = flt_ot_init,
	.deinit                = flt_ot_deinit,
	.check                 = flt_ot_check,
	.init_per_thread       = FLT_OT_DBG_IFDEF(flt_ot_init_per_thread, NULL),
	.deinit_per_thread     = FLT_OT_DBG_IFDEF(flt_ot_deinit_per_thread, NULL),

	/* Stream callbacks. */
	.attach                = flt_ot_attach,
	.stream_start          = FLT_OT_DBG_IFDEF(flt_ot_stream_start, NULL),
	.stream_set_backend    = FLT_OT_DBG_IFDEF(flt_ot_stream_set_backend, NULL),
	.stream_stop           = FLT_OT_DBG_IFDEF(flt_ot_stream_stop, NULL),
	.detach                = flt_ot_detach,
	.check_timeouts        = flt_ot_check_timeouts,

	/* Channel callbacks. */
	.channel_start_analyze = flt_ot_channel_start_analyze,
	.channel_pre_analyze   = flt_ot_channel_pre_analyze,
	.channel_post_analyze  = flt_ot_channel_post_analyze,
	.channel_end_analyze   = flt_ot_channel_end_analyze,

	/* HTTP callbacks. */
	.http_headers          = FLT_OT_DBG_IFDEF(flt_ot_http_headers, NULL),
	.http_payload          = FLT_OT_DBG_IFDEF(flt_ot_http_payload, NULL),
	.http_end              = FLT_OT_DBG_IFDEF(flt_ot_http_end, NULL),
	.http_reset            = FLT_OT_DBG_IFDEF(flt_ot_http_reset, NULL),
	.http_reply            = FLT_OT_DBG_IFDEF(flt_ot_http_reply, NULL),

	/* TCP callbacks. */
	.tcp_payload           = FLT_OT_DBG_IFDEF(flt_ot_tcp_payload, NULL)
};


REGISTER_BUILD_OPTS("Built with OpenTracing support.");

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
