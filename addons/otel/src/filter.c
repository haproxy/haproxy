/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../include/include.h"


/*
 * OpenTelemetry filter id, used to identify OpenTelemetry filters.  The name
 * of this variable is consistent with the other filter names declared in
 * include/haproxy/filters.h .
 */
const char *otel_flt_id = "the OpenTelemetry filter";


/***
 * NAME
 *   flt_otel_ops_init - filter init callback (flt_ops.init)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_init(struct proxy *p, struct flt_conf *fconf)
 *
 * ARGUMENTS
 *   p     - the proxy to which the filter is attached
 *   fconf - the filter configuration
 *
 * DESCRIPTION
 *   It initializes the filter for a proxy.  You may define this callback if you
 *   need to complete your filter configuration.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, any other value otherwise.
 */
static int flt_otel_ops_init(struct proxy *p, struct flt_conf *fconf)
{
	OTELC_FUNC("%p, %p", p, fconf);

	OTELC_RETURN_INT(0);
}


/***
 * NAME
 *   flt_otel_ops_deinit - filter deinit callback (flt_ops.deinit)
 *
 * SYNOPSIS
 *   static void flt_otel_ops_deinit(struct proxy *p, struct flt_conf *fconf)
 *
 * ARGUMENTS
 *   p     - the proxy to which the filter is attached
 *   fconf - the filter configuration
 *
 * DESCRIPTION
 *   It cleans up what the parsing function and the init callback have done.
 *   This callback is useful to release memory allocated for the filter
 *   configuration.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_ops_deinit(struct proxy *p, struct flt_conf *fconf)
{
	OTELC_FUNC("%p, %p", p, fconf);

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_ops_check - filter check callback (flt_ops.check)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_check(struct proxy *p, struct flt_conf *fconf)
 *
 * ARGUMENTS
 *   p     - the proxy to which the filter is attached
 *   fconf - the filter configuration
 *
 * DESCRIPTION
 *   Validates the internal configuration of the OTel filter after the parsing
 *   phase, when the HAProxy configuration is fully defined.  The following
 *   checks are performed: duplicate filter IDs across all proxies, presence of
 *   an instrumentation section and its configuration file, duplicate group and
 *   scope names, empty groups, group-to-scope and instrumentation-to-group/scope
 *   cross-references, unused scopes, root span count, analyzer bits, and
 *   create-form instrument name uniqueness and update-form instrument
 *   resolution.
 *
 * RETURN VALUE
 *   Returns the number of encountered errors.
 */
static int flt_otel_ops_check(struct proxy *p, struct flt_conf *fconf)
{
	struct proxy               *px;
	struct flt_otel_conf       *conf = FLT_OTEL_DEREF(fconf, conf, NULL);
	struct flt_otel_conf_group *conf_group;
	struct flt_otel_conf_scope *conf_scope;
	struct flt_otel_conf_ph    *ph_group, *ph_scope;
	int                         retval = 0, scope_unused_cnt = 0, span_root_cnt = 0;

	OTELC_FUNC("%p, %p", p, fconf);

	if (conf == NULL)
		OTELC_RETURN_INT(++retval);

	/*
	 * Resolve deferred OTEL sample fetch arguments.
	 *
	 * These were kept out of the proxy's arg list during parsing to avoid
	 * the global smp_resolve_args() call, which would reject backend-only
	 * fetches on a frontend proxy.  All backends and servers are now
	 * available, so resolve under full FE+BE capabilities.
	 */
	if (!LIST_ISEMPTY(&(conf->smp_args))) {
		char *err = NULL;
		uint  saved_cap = p->cap;

		LIST_SPLICE(&(p->conf.args.list), &(conf->smp_args));
		LIST_INIT(&(conf->smp_args));
		p->cap |= PR_CAP_LISTEN;

		if (smp_resolve_args(p, &err) != 0) {
			FLT_OTEL_ALERT("%s", err);
			ha_free(&err);

			retval++;
		}

		p->cap = saved_cap;
	}

	/*
	 * If only the proxy specified with the <p> parameter is checked, then
	 * no duplicate filters can be found that are not defined in the same
	 * configuration sections.
	 */
	for (px = proxies_list; px != NULL; px = px->next) {
		struct flt_conf *fconf_tmp;

		OTELC_DBG(NOTICE, "proxy '%s'", px->id);

		/*
		 * The names of all OTEL filters (filter ID) should be checked,
		 * they must be unique.
		 */
		list_for_each_entry(fconf_tmp, &(px->filter_configs), list)
			if ((fconf_tmp != fconf) && (fconf_tmp->id == otel_flt_id)) {
				struct flt_otel_conf *conf_tmp = fconf_tmp->conf;

				OTELC_DBG(NOTICE, "  OTEL filter '%s'", conf_tmp->id);

				if (strcmp(conf_tmp->id, conf->id) == 0) {
					FLT_OTEL_ALERT("''%s' : duplicated filter ID'", conf_tmp->id);

					retval++;
				}
			}
	}

	if (FLT_OTEL_DEREF(conf->instr, id, NULL) == NULL) {
		FLT_OTEL_ALERT("''%s' : no instrumentation found'", conf->id);

		retval++;
	}

	if ((conf->instr != NULL) && (conf->instr->config == NULL)) {
		FLT_OTEL_ALERT("''%s' : no configuration file specified'", conf->instr->id);

		retval++;
	}

	/*
	 * Checking that defined 'otel-group' section names are unique.
	 */
	list_for_each_entry(conf_group, &(conf->groups), list) {
		struct flt_otel_conf_group *conf_group_tmp;

		list_for_each_entry(conf_group_tmp, &(conf->groups), list) {
			if ((conf_group_tmp != conf_group) && (strcmp(conf_group_tmp->id, conf_group->id) == 0)) {
				FLT_OTEL_ALERT("''%s' : duplicated " FLT_OTEL_PARSE_SECTION_GROUP_ID " '%s''", conf->id, conf_group->id);

				retval++;

				break;
			}
		}
	}

	/*
	 * Checking that defined 'otel-scope' section names are unique.
	 */
	list_for_each_entry(conf_scope, &(conf->scopes), list) {
		struct flt_otel_conf_scope *conf_scope_tmp;

		list_for_each_entry(conf_scope_tmp, &(conf->scopes), list) {
			if ((conf_scope_tmp != conf_scope) && (strcmp(conf_scope_tmp->id, conf_scope->id) == 0)) {
				FLT_OTEL_ALERT("''%s' : duplicated " FLT_OTEL_PARSE_SECTION_SCOPE_ID " '%s''", conf->id, conf_scope->id);

				retval++;

				break;
			}
		}
	}

	/*
	 * Checking that defined 'otel-group' sections are not empty.
	 */
	list_for_each_entry(conf_group, &(conf->groups), list)
		if (LIST_ISEMPTY(&(conf_group->ph_scopes)))
			FLT_OTEL_ALERT("''%s' : " FLT_OTEL_PARSE_SECTION_GROUP_ID " '%s' has no scopes'", conf->id, conf_group->id);

	/*
	 * Checking that all defined 'otel-group' sections have correctly declared
	 * 'otel-scope' sections (ie whether the declared 'otel-scope' sections have
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
				FLT_OTEL_ALERT("'" FLT_OTEL_PARSE_SECTION_GROUP_ID " '%s' : references undefined " FLT_OTEL_PARSE_SECTION_SCOPE_ID " '%s''", conf_group->id, ph_scope->id);

				retval++;
			}
		}

	if (conf->instr != NULL) {
		/*
		 * Checking that all declared 'groups' keywords have correctly
		 * defined 'otel-group' sections.
		 */
		list_for_each_entry(ph_group, &(conf->instr->ph_groups), list) {
			bool flag_found = 0;

			list_for_each_entry(conf_group, &(conf->groups), list)
				if (strcmp(ph_group->id, conf_group->id) == 0) {
					ph_group->ptr         = conf_group;
					conf_group->flag_used = 1;
					flag_found            = 1;

					break;
				}

			if (!flag_found) {
				FLT_OTEL_ALERT("'" FLT_OTEL_PARSE_SECTION_INSTR_ID " '%s' : references undefined " FLT_OTEL_PARSE_SECTION_GROUP_ID " '%s''", conf->instr->id, ph_group->id);

				retval++;
			}
		}

		/*
		 * Checking that all declared 'scopes' keywords have correctly
		 * defined 'otel-scope' sections.
		 */
		list_for_each_entry(ph_scope, &(conf->instr->ph_scopes), list) {
			bool flag_found = 0;

			list_for_each_entry(conf_scope, &(conf->scopes), list)
				if (strcmp(ph_scope->id, conf_scope->id) == 0) {
					ph_scope->ptr         = conf_scope;
					conf_scope->flag_used = 1;
					flag_found            = 1;

					break;
				}

			if (!flag_found) {
				FLT_OTEL_ALERT("'" FLT_OTEL_PARSE_SECTION_INSTR_ID " '%s' : references undefined " FLT_OTEL_PARSE_SECTION_SCOPE_ID " '%s''", conf->instr->id, ph_scope->id);

				retval++;
			}
		}
	}

	OTELC_DBG(DEBUG, "--- filter '%s' configuration ----------", conf->id);
	OTELC_DBG(DEBUG, "- defined spans ----------");

	/*
	 * Walk every configured scope: for used ones, log the defined spans,
	 * count root spans, and set the required analyzer bits; for unused
	 * ones, record a warning so the operator is notified.
	 */
	list_for_each_entry(conf_scope, &(conf->scopes), list) {
		if (conf_scope->flag_used) {
			struct flt_otel_conf_span *conf_span;

			/*
			 * In principle, only one span should be labeled
			 * as a root span.
			 */
			list_for_each_entry(conf_span, &(conf_scope->spans), list) {
				FLT_OTEL_DBG_CONF_SPAN("   ", conf_span);

				span_root_cnt += conf_span->flag_root ? 1 : 0;
			}

#ifdef DEBUG_OTEL
			conf->cnt.event[conf_scope->event].flag_used = 1;
#endif

			/* Set the flags of the analyzers used. */
			conf->instr->analyzers |= flt_otel_event_data[conf_scope->event].an_bit;

			/* Track the minimum idle timeout. */
			if (conf_scope->event == FLT_OTEL_EVENT__IDLE_TIMEOUT)
				if ((conf->instr->idle_timeout == 0) || (conf_scope->idle_timeout < conf->instr->idle_timeout))
					conf->instr->idle_timeout = conf_scope->idle_timeout;
		} else {
			FLT_OTEL_ALERT("''%s' : unused " FLT_OTEL_PARSE_SECTION_SCOPE_ID " '%s''", conf->id, conf_scope->id);

			scope_unused_cnt++;
		}
	}

	/*
	 * Unused scopes or a number of root spans other than one do not
	 * necessarily have to be errors, but it is good to print it when
	 * starting HAProxy.
	 */
	if (scope_unused_cnt > 0)
		FLT_OTEL_ALERT("''%s' : %d scope(s) not in use'", conf->id, scope_unused_cnt);

	if (LIST_ISEMPTY(&(conf->scopes)))
		/* Do nothing. */;
	else if (span_root_cnt == 0)
		FLT_OTEL_ALERT("''%s' : no span is marked as the root span'", conf->id);
	else if (span_root_cnt > 1)
		FLT_OTEL_ALERT("''%s' : multiple spans are marked as the root span'", conf->id);

	FLT_OTEL_DBG_LIST(conf, group, "", "defined", _group,
	                  FLT_OTEL_DBG_CONF_GROUP("   ", _group);
	                  FLT_OTEL_DBG_LIST(_group, ph_scope, "   ", "used", _scope, FLT_OTEL_DBG_CONF_PH("      ", _scope)));
	FLT_OTEL_DBG_LIST(conf, scope, "", "defined", _scope, FLT_OTEL_DBG_CONF_SCOPE("   ", _scope));

	if (conf->instr != NULL) {
		OTELC_DBG(DEBUG, "   --- instrumentation '%s' configuration ----------", conf->instr->id);
		FLT_OTEL_DBG_LIST(conf->instr, ph_group, "   ", "used", _group, FLT_OTEL_DBG_CONF_PH("      ", _group));
		FLT_OTEL_DBG_LIST(conf->instr, ph_scope, "   ", "used", _scope, FLT_OTEL_DBG_CONF_PH("      ", _scope));
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_ops_init_per_thread - per-thread init callback (flt_ops.init_per_thread)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_init_per_thread(struct proxy *p, struct flt_conf *fconf)
 *
 * ARGUMENTS
 *   p     - the proxy to which the filter is attached
 *   fconf - the filter configuration
 *
 * DESCRIPTION
 *   Per-thread filter initialization called after thread creation.  Starts
 *   the OTel tracer and meter threads via their start operations and enables
 *   HTX stream filtering.  Subsequent calls on the same filter are no-ops.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, any other value otherwise.
 */
static int flt_otel_ops_init_per_thread(struct proxy *p, struct flt_conf *fconf)
{
	OTELC_FUNC("%p, %p", p, fconf);

	OTELC_RETURN_INT(FLT_OTEL_RET_OK);
}


#ifdef DEBUG_OTEL

/***
 * NAME
 *   flt_otel_ops_deinit_per_thread - per-thread deinit callback (flt_ops.deinit_per_thread)
 *
 * SYNOPSIS
 *   static void flt_otel_ops_deinit_per_thread(struct proxy *p, struct flt_conf *fconf)
 *
 * ARGUMENTS
 *   p     - the proxy to which the filter is attached
 *   fconf - the filter configuration
 *
 * DESCRIPTION
 *   It cleans up what the init_per_thread callback have done.  It is called
 *   in the context of a thread, before exiting it.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_ops_deinit_per_thread(struct proxy *p, struct flt_conf *fconf)
{
	OTELC_FUNC("%p, %p", p, fconf);

	OTELC_RETURN();
}

#endif /* DEBUG_OTEL */


/***
 * NAME
 *   flt_otel_ops_attach - filter attach callback (flt_ops.attach)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_attach(struct stream *s, struct filter *f)
 *
 * ARGUMENTS
 *   s - the stream to which the filter is being attached
 *   f - the filter instance
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
static int flt_otel_ops_attach(struct stream *s, struct filter *f)
{
	OTELC_FUNC("%p, %p", s, f);

	OTELC_RETURN_INT(FLT_OTEL_RET_OK);
}


/***
 * NAME
 *   flt_otel_ops_stream_start - stream start callback (flt_ops.stream_start)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_stream_start(struct stream *s, struct filter *f)
 *
 * ARGUMENTS
 *   s - the stream that is being started
 *   f - the filter instance
 *
 * DESCRIPTION
 *   It is called when a stream is started.  This callback can fail by returning
 *   a negative value.  It will be considered as a critical error by HAProxy
 *   which disabled the listener for a short time.  After the stream-start
 *   event, it initializes the idle timer in the runtime context from the
 *   precomputed minimum idle_timeout in the instrumentation configuration.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, any other value otherwise.
 */
static int flt_otel_ops_stream_start(struct stream *s, struct filter *f)
{
	OTELC_FUNC("%p, %p", s, f);

	OTELC_RETURN_INT(FLT_OTEL_RET_OK);
}


/***
 * NAME
 *   flt_otel_ops_stream_set_backend - stream set-backend callback (flt_ops.stream_set_backend)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_stream_set_backend(struct stream *s, struct filter *f, struct proxy *be)
 *
 * ARGUMENTS
 *   s  - the stream being processed
 *   f  - the filter instance
 *   be - the backend proxy being assigned
 *
 * DESCRIPTION
 *   It is called when a backend is set for a stream.  This callback will be
 *   called for all filters attached to a stream (frontend and backend).  Note
 *   this callback is not called if the frontend and the backend are the same.
 *   It fires the on-backend-set event.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, any other value otherwise.
 */
static int flt_otel_ops_stream_set_backend(struct stream *s, struct filter *f, struct proxy *be)
{
	OTELC_FUNC("%p, %p, %p", s, f, be);

	OTELC_RETURN_INT(FLT_OTEL_RET_OK);
}


/***
 * NAME
 *   flt_otel_ops_stream_stop - stream stop callback (flt_ops.stream_stop)
 *
 * SYNOPSIS
 *   static void flt_otel_ops_stream_stop(struct stream *s, struct filter *f)
 *
 * ARGUMENTS
 *   s - the stream being stopped
 *   f - the filter instance
 *
 * DESCRIPTION
 *   It is called when a stream is stopped.  This callback always succeed.
 *   Anyway, it is too late to return an error.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_ops_stream_stop(struct stream *s, struct filter *f)
{
	OTELC_FUNC("%p, %p", s, f);

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_ops_detach - filter detach callback (flt_ops.detach)
 *
 * SYNOPSIS
 *   static void flt_otel_ops_detach(struct stream *s, struct filter *f)
 *
 * ARGUMENTS
 *   s - the stream from which the filter is being detached
 *   f - the filter instance
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
static void flt_otel_ops_detach(struct stream *s, struct filter *f)
{
	OTELC_FUNC("%p, %p", s, f);

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_ops_check_timeouts - timeout callback (flt_ops.check_timeouts)
 *
 * SYNOPSIS
 *   static void flt_otel_ops_check_timeouts(struct stream *s, struct filter *f)
 *
 * ARGUMENTS
 *   s - the stream whose timer has expired
 *   f - the filter instance
 *
 * DESCRIPTION
 *   Timeout callback for the filter.  When the idle-timeout timer has expired,
 *   it fires the on-idle-timeout event via flt_otel_event_run() and reschedules
 *   the timer for the next interval.  It also sets the STRM_EVT_MSG pending
 *   event flag on the <s> stream so that the stream processing loop
 *   re-evaluates the message state after the timeout.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_ops_check_timeouts(struct stream *s, struct filter *f)
{
	OTELC_FUNC("%p, %p", s, f);

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_ops_channel_start_analyze - channel start-analyze callback
 *
 * SYNOPSIS
 *   static int flt_otel_ops_channel_start_analyze(struct stream *s, struct filter *f, struct channel *chn)
 *
 * ARGUMENTS
 *   s   - the stream being analyzed
 *   f   - the filter instance
 *   chn - the channel on which the analyzing starts
 *
 * DESCRIPTION
 *   Channel start-analyze callback.  It registers the configured analyzers
 *   on the <chn> channel and runs the client or server session-start event
 *   depending on the channel direction.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_otel_ops_channel_start_analyze(struct stream *s, struct filter *f, struct channel *chn)
{
	OTELC_FUNC("%p, %p, %p", s, f, chn);

	OTELC_RETURN_INT(FLT_OTEL_RET_OK);
}


/***
 * NAME
 *   flt_otel_ops_channel_pre_analyze - channel pre-analyze callback
 *
 * SYNOPSIS
 *   static int flt_otel_ops_channel_pre_analyze(struct stream *s, struct filter *f, struct channel *chn, uint an_bit)
 *
 * ARGUMENTS
 *   s      - the stream being analyzed
 *   f      - the filter instance
 *   chn    - the channel on which the analyzing is done
 *   an_bit - the analyzer identifier bit
 *
 * DESCRIPTION
 *   Channel pre-analyze callback.  It maps the <an_bit> analyzer bit to an
 *   event index and runs the corresponding event via flt_otel_event_run().
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_otel_ops_channel_pre_analyze(struct stream *s, struct filter *f, struct channel *chn, uint an_bit)
{
	OTELC_FUNC("%p, %p, %p, 0x%08x", s, f, chn, an_bit);

	OTELC_RETURN_INT(FLT_OTEL_RET_OK);
}


/***
 * NAME
 *   flt_otel_ops_channel_post_analyze - channel post-analyze callback
 *
 * SYNOPSIS
 *   static int flt_otel_ops_channel_post_analyze(struct stream *s, struct filter *f, struct channel *chn, uint an_bit)
 *
 * ARGUMENTS
 *   s      - the stream being analyzed
 *   f      - the filter instance
 *   chn    - the channel on which the analyzing is done
 *   an_bit - the analyzer identifier bit
 *
 * DESCRIPTION
 *   This function, for its part, is not resumable.  It is called when a
 *   filterable analyzer finishes its processing.  So it is called once for
 *   the same analyzer.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_otel_ops_channel_post_analyze(struct stream *s, struct filter *f, struct channel *chn, uint an_bit)
{
	OTELC_FUNC("%p, %p, %p, 0x%08x", s, f, chn, an_bit);

	OTELC_RETURN_INT(FLT_OTEL_RET_OK);
}


/***
 * NAME
 *   flt_otel_ops_channel_end_analyze - channel end-analyze callback
 *
 * SYNOPSIS
 *   static int flt_otel_ops_channel_end_analyze(struct stream *s, struct filter *f, struct channel *chn)
 *
 * ARGUMENTS
 *   s   - the stream being analyzed
 *   f   - the filter instance
 *   chn - the channel on which the analyzing ends
 *
 * DESCRIPTION
 *   Channel end-analyze callback.  It runs the client or server session-end
 *   event depending on the <chn> channel direction.  For the request channel,
 *   it also fires the server-unavailable event if response analyzers were
 *   configured but never executed.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_otel_ops_channel_end_analyze(struct stream *s, struct filter *f, struct channel *chn)
{
	OTELC_FUNC("%p, %p, %p", s, f, chn);

	OTELC_RETURN_INT(FLT_OTEL_RET_OK);
}


/***
 * NAME
 *   flt_otel_ops_http_headers - HTTP headers callback (flt_ops.http_headers)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_http_headers(struct stream *s, struct filter *f, struct http_msg *msg)
 *
 * ARGUMENTS
 *   s   - the stream being processed
 *   f   - the filter instance
 *   msg - the HTTP message whose headers are ready
 *
 * DESCRIPTION
 *   HTTP headers callback.  It fires the on-http-headers-request or
 *   on-http-headers-response event depending on the channel direction.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_otel_ops_http_headers(struct stream *s, struct filter *f, struct http_msg *msg)
{
	OTELC_FUNC("%p, %p, %p", s, f, msg);

	OTELC_RETURN_INT(FLT_OTEL_RET_OK);
}


#ifdef DEBUG_OTEL

/***
 * NAME
 *   flt_otel_ops_http_payload - HTTP payload callback (flt_ops.http_payload)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_http_payload(struct stream *s, struct filter *f, struct http_msg *msg, uint offset, uint len)
 *
 * ARGUMENTS
 *   s      - the stream being processed
 *   f      - the filter instance
 *   msg    - the HTTP message containing the payload
 *   offset - the offset in the HTX message where data starts
 *   len    - the maximum number of bytes to forward
 *
 * DESCRIPTION
 *   Debug-only HTTP payload callback.  It logs the channel direction, proxy
 *   mode, offset and data length.  No actual data processing is performed.
 *
 * RETURN VALUE
 *   Returns the number of bytes to forward, or a negative value on error.
 */
static int flt_otel_ops_http_payload(struct stream *s, struct filter *f, struct http_msg *msg, uint offset, uint len)
{
	OTELC_FUNC("%p, %p, %p, %u, %u", s, f, msg, offset, len);

	OTELC_RETURN_INT(len);
}

#endif /* DEBUG_OTEL */


/***
 * NAME
 *   flt_otel_ops_http_end - HTTP end callback (flt_ops.http_end)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_http_end(struct stream *s, struct filter *f, struct http_msg *msg)
 *
 * ARGUMENTS
 *   s   - the stream being processed
 *   f   - the filter instance
 *   msg - the HTTP message that has ended
 *
 * DESCRIPTION
 *   HTTP end callback.  It fires the on-http-end-request or
 *   on-http-end-response event depending on the channel direction.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_otel_ops_http_end(struct stream *s, struct filter *f, struct http_msg *msg)
{
	OTELC_FUNC("%p, %p, %p", s, f, msg);

	OTELC_RETURN_INT(FLT_OTEL_RET_OK);
}


/***
 * NAME
 *   flt_otel_ops_http_reply - HTTP reply callback (flt_ops.http_reply)
 *
 * SYNOPSIS
 *   static void flt_otel_ops_http_reply(struct stream *s, struct filter *f, short status, const struct buffer *msg)
 *
 * ARGUMENTS
 *   s      - the stream being processed
 *   f      - the filter instance
 *   status - the HTTP status code of the reply
 *   msg    - the reply message buffer, or NULL
 *
 * DESCRIPTION
 *   HTTP reply callback.  It fires the on-http-reply event when HAProxy
 *   generates an internal reply (e.g. error page or deny response).
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_ops_http_reply(struct stream *s, struct filter *f, short status, const struct buffer *msg)
{
	OTELC_FUNC("%p, %p, %hd, %p", s, f, status, msg);

	OTELC_RETURN();
}


#ifdef DEBUG_OTEL

/***
 * NAME
 *   flt_otel_ops_http_reset - HTTP reset callback (flt_ops.http_reset)
 *
 * SYNOPSIS
 *   static void flt_otel_ops_http_reset(struct stream *s, struct filter *f, struct http_msg *msg)
 *
 * ARGUMENTS
 *   s   - the stream being processed
 *   f   - the filter instance
 *   msg - the HTTP message being reset
 *
 * DESCRIPTION
 *   Debug-only HTTP reset callback.  It logs the channel direction and proxy
 *   mode when an HTTP message is reset (e.g. due to a redirect or retry).
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_ops_http_reset(struct stream *s, struct filter *f, struct http_msg *msg)
{
	OTELC_FUNC("%p, %p, %p", s, f, msg);

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_ops_tcp_payload - TCP payload callback (flt_ops.tcp_payload)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_tcp_payload(struct stream *s, struct filter *f, struct channel *chn, uint offset, uint len)
 *
 * ARGUMENTS
 *   s      - the stream being processed
 *   f      - the filter instance
 *   chn    - the channel containing the payload data
 *   offset - the offset in the buffer where data starts
 *   len    - the maximum number of bytes to forward
 *
 * DESCRIPTION
 *   Debug-only TCP payload callback.  It logs the channel direction, proxy
 *   mode, offset and data length.  No actual data processing is performed.
 *
 * RETURN VALUE
 *   Returns the number of bytes to forward, or a negative value on error.
 */
static int flt_otel_ops_tcp_payload(struct stream *s, struct filter *f, struct channel *chn, uint offset, uint len)
{
	OTELC_FUNC("%p, %p, %p, %u, %u", s, f, chn, offset, len);

	OTELC_RETURN_INT(len);
}

#endif /* DEBUG_OTEL */


struct flt_ops flt_otel_ops = {
	/* Callbacks to manage the filter lifecycle. */
	.init                  = flt_otel_ops_init,
	.deinit                = flt_otel_ops_deinit,
	.check                 = flt_otel_ops_check,
	.init_per_thread       = flt_otel_ops_init_per_thread,
	.deinit_per_thread     = OTELC_DBG_IFDEF(flt_otel_ops_deinit_per_thread, NULL),

	/* Stream callbacks. */
	.attach                = flt_otel_ops_attach,
	.stream_start          = flt_otel_ops_stream_start,
	.stream_set_backend    = flt_otel_ops_stream_set_backend,
	.stream_stop           = flt_otel_ops_stream_stop,
	.detach                = flt_otel_ops_detach,
	.check_timeouts        = flt_otel_ops_check_timeouts,

	/* Channel callbacks. */
	.channel_start_analyze = flt_otel_ops_channel_start_analyze,
	.channel_pre_analyze   = flt_otel_ops_channel_pre_analyze,
	.channel_post_analyze  = flt_otel_ops_channel_post_analyze,
	.channel_end_analyze   = flt_otel_ops_channel_end_analyze,

	/* HTTP callbacks. */
	.http_headers          = flt_otel_ops_http_headers,
	.http_payload          = OTELC_DBG_IFDEF(flt_otel_ops_http_payload, NULL),
	.http_end              = flt_otel_ops_http_end,
	.http_reset            = OTELC_DBG_IFDEF(flt_otel_ops_http_reset, NULL),
	.http_reply            = flt_otel_ops_http_reply,

	/* TCP callbacks. */
	.tcp_payload           = OTELC_DBG_IFDEF(flt_otel_ops_tcp_payload, NULL)
};


/* Advertise OTel support in haproxy -vv output. */
REGISTER_BUILD_OPTS("Built with OpenTelemetry support (C++ version " OTELCPP_VERSION ", C Wrapper version " OTELC_VERSION ").");

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
