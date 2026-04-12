/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../include/include.h"


/* Event data table built from the X-macro list. */
#define FLT_OTEL_EVENT_DEF(a,b,c,d,e,f)   { AN_##b##_##a, OTELC_STRINGIFY_ARG(AN_##b##_##a), SMP_OPT_DIR_##b, SMP_VAL_FE_##c, SMP_VAL_BE_##d, e, f },
const struct flt_otel_event_data flt_otel_event_data[FLT_OTEL_EVENT_MAX] = { FLT_OTEL_EVENT_DEFINES };
#undef FLT_OTEL_EVENT_DEF


/***
 * NAME
 *   flt_otel_scope_run_span - single span execution
 *
 * SYNOPSIS
 *   static int flt_otel_scope_run_span(struct stream *s, struct filter *f, struct channel *chn, uint dir, struct flt_otel_scope_span *span, struct flt_otel_scope_data *data, const struct flt_otel_conf_span *conf_span, const struct timespec *ts_steady, const struct timespec *ts_system, char **err)
 *
 * ARGUMENTS
 *   s         - the stream being processed
 *   f         - the filter instance
 *   chn       - the channel used for HTTP header injection
 *   dir       - the sample fetch direction (SMP_OPT_DIR_REQ/RES)
 *   span      - the runtime scope span to execute
 *   data      - the evaluated scope data (attributes, events, links, status)
 *   conf_span - the span configuration
 *   ts_steady - the monotonic timestamp for span creation
 *   ts_system - the wall-clock timestamp for span events
 *   err       - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Executes a single span: creates the OTel span on first call via the tracer,
 *   adds links, baggage, attributes, events and status from <data>, then
 *   injects the span context into HTTP headers if configured in <conf_span>.
 *
 * RETURN VALUE
 *   Returns FLT_OTEL_RET_OK on success, FLT_OTEL_RET_ERROR on failure.
 */
static int flt_otel_scope_run_span(struct stream *s, struct filter *f, struct channel *chn, uint dir, struct flt_otel_scope_span *span, struct flt_otel_scope_data *data, const struct flt_otel_conf_span *conf_span, const struct timespec *ts_steady, const struct timespec *ts_system, char **err)
{
	struct flt_otel_conf *conf = FLT_OTEL_CONF(f);
	int                   retval = FLT_OTEL_RET_OK;

	OTELC_FUNC("%p, %p, %p, %u, %p, %p, %p, %p, %p, %p:%p", s, f, chn, dir, span, data, conf_span, ts_steady, ts_system, OTELC_DPTR_ARGS(err));

	if (span == NULL)
		OTELC_RETURN_INT(retval);

	/* Create the OTel span on first invocation. */
	if (span->span == NULL) {
		span->span = OTELC_OPS(conf->instr->tracer, start_span_with_options, span->id, span->ref_span, span->ref_ctx, ts_steady, ts_system, OTELC_SPAN_KIND_SERVER, NULL, 0);
		if (span->span == NULL)
			OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);
	}

	/* Set baggage key-value pairs on the span. */
	if (data->baggage.attr != NULL)
		if (OTELC_OPS(span->span, set_baggage_kv_n, data->baggage.attr, data->baggage.cnt) == -1)
			retval = FLT_OTEL_RET_ERROR;

	/* Set span attributes. */
	if (data->attributes.attr != NULL)
		if (OTELC_OPS(span->span, set_attribute_kv_n, data->attributes.attr, data->attributes.cnt) == -1)
			retval = FLT_OTEL_RET_ERROR;

	/* Add span events in reverse order. */
	if (!LIST_ISEMPTY(&(data->events))) {
		struct flt_otel_scope_data_event *event;

		list_for_each_entry_rev(event, &(data->events), list)
			if (OTELC_OPS(span->span, add_event_kv_n, event->name, ts_system, event->attr, event->cnt) == -1)
				retval = FLT_OTEL_RET_ERROR;
	}

	/* Set span status code and description. */
	if (data->status.description != NULL)
		if (OTELC_OPS(span->span, set_status, data->status.code, data->status.description) == -1)
			retval = FLT_OTEL_RET_ERROR;

	/* Inject span context into HTTP headers. */
	if (conf_span->ctx_id != NULL) {
		struct otelc_http_headers_writer  writer;
		struct otelc_text_map            *text_map = NULL;

		if (flt_otel_inject_http_headers(span->span, &writer) != FLT_OTEL_RET_ERROR) {
			int i = 0;

			if (conf_span->ctx_flags & FLT_OTEL_CTX_USE_HEADERS) {
				for (text_map = &(writer.text_map); i < text_map->count; i++) {
					if (!(conf_span->ctx_flags & FLT_OTEL_CTX_USE_HEADERS))
						/* Do nothing. */;
					else if (flt_otel_http_header_set(chn, conf_span->ctx_id, text_map->key[i], text_map->value[i], err) == FLT_OTEL_RET_ERROR)
						retval = FLT_OTEL_RET_ERROR;
				}
			}

			otelc_text_map_destroy(&text_map);
		}
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_scope_run - scope execution engine
 *
 * SYNOPSIS
 *   int flt_otel_scope_run(struct stream *s, struct filter *f, struct channel *chn, struct flt_otel_conf_scope *conf_scope, const struct timespec *ts_steady, const struct timespec *ts_system, uint dir, char **err)
 *
 * ARGUMENTS
 *   s          - the stream being processed
 *   f          - the filter instance
 *   chn        - the channel for context extraction and injection
 *   conf_scope - the scope configuration to execute
 *   ts_steady  - the monotonic timestamp, or NULL to use current time
 *   ts_system  - the wall-clock timestamp, or NULL to use current time
 *   dir        - the sample fetch direction (SMP_OPT_DIR_REQ/RES)
 *   err        - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Executes a complete scope: evaluates ACL conditions, extracts contexts
 *   from HTTP headers, iterates over configured spans (resolving links,
 *   evaluating sample expressions for attributes, events, baggage and status),
 *   calls flt_otel_scope_run_span() for each, processes metric instruments,
 *   then marks and finishes completed spans.
 *
 * RETURN VALUE
 *   Returns FLT_OTEL_RET_OK on success, FLT_OTEL_RET_ERROR on failure.
 */
int flt_otel_scope_run(struct stream *s, struct filter *f, struct channel *chn, struct flt_otel_conf_scope *conf_scope, const struct timespec *ts_steady, const struct timespec *ts_system, uint dir, char **err)
{
	struct flt_otel_conf         *conf = FLT_OTEL_CONF(f);
	struct flt_otel_conf_context *conf_ctx;
	struct flt_otel_conf_span    *conf_span;
	struct flt_otel_conf_str     *span_to_finish;
	struct timespec               ts_now_steady, ts_now_system;
	int                           retval = FLT_OTEL_RET_OK;

	OTELC_FUNC("%p, %p, %p, %p, %p, %p, %u, %p:%p", s, f, chn, conf_scope, ts_steady, ts_system, dir, OTELC_DPTR_ARGS(err));

	OTELC_DBG(DEBUG, "channel: %s, mode: %s (%s)", flt_otel_chn_label(chn), flt_otel_pr_mode(s), flt_otel_stream_pos(s));
	OTELC_DBG(DEBUG, "run scope '%s' %d", conf_scope->id, conf_scope->event);
	FLT_OTEL_DBG_CONF_SCOPE("run scope ", conf_scope);

	if (ts_steady == NULL) {
		(void)clock_gettime(CLOCK_MONOTONIC, &ts_now_steady);

		ts_steady = &ts_now_steady;
	}
	if (ts_system == NULL) {
		(void)clock_gettime(CLOCK_REALTIME, &ts_now_system);

		ts_system = &ts_now_system;
	}

	/* Evaluate the scope's ACL condition; skip this scope on mismatch. */
	if (conf_scope->cond != NULL) {
		enum acl_test_res res;
		int               rc;

		res = acl_exec_cond(conf_scope->cond, s->be, s->sess, s, dir | SMP_OPT_FINAL);
		rc  = acl_pass(res);
		if (conf_scope->cond->pol == ACL_COND_UNLESS)
			rc = !rc;

		OTELC_DBG(DEBUG, "the ACL rule %s", rc ? "matches" : "does not match");

		/*
		 * If the rule does not match, the current scope is skipped.
		 *
		 * If it is a root span, further processing of the session is
		 * disabled.  As soon as the first span is encountered which
		 * is marked as root, further search is interrupted.
		 */
		if (rc == 0) {
			list_for_each_entry(conf_span, &(conf_scope->spans), list)
				if (conf_span->flag_root) {
					OTELC_DBG(LOG, "session disabled");

					FLT_OTEL_RT_CTX(f->ctx)->flag_disabled = 1;

#ifdef FLT_OTEL_USE_COUNTERS
					_HA_ATOMIC_ADD(conf->cnt.disabled + 0, 1);
#endif

					break;
				}

			OTELC_RETURN_INT(retval);
		}
	}

	/* Extract and initialize OpenTelemetry propagation contexts. */
	list_for_each_entry(conf_ctx, &(conf_scope->contexts), list) {
		struct otelc_text_map *text_map = NULL;

		OTELC_DBG(DEBUG, "run context '%s' -> '%s'", conf_scope->id, conf_ctx->id);
		FLT_OTEL_DBG_CONF_CONTEXT("run context ", conf_ctx);

		/*
		 * The OpenTelemetry context is read from the HTTP headers.
		 */
		if (conf_ctx->flags & FLT_OTEL_CTX_USE_HEADERS)
			text_map = flt_otel_http_headers_get(chn, conf_ctx->id, conf_ctx->id_len, err);

		if (text_map != NULL) {
			if (flt_otel_scope_context_init(f->ctx, conf->instr->tracer, conf_ctx->id, conf_ctx->id_len, text_map, dir, err) == NULL)
				retval = FLT_OTEL_RET_ERROR;

			otelc_text_map_destroy(&text_map);
		} else {
			retval = FLT_OTEL_RET_ERROR;
		}
	}

	/* Process configured spans: resolve links and collect samples. */
	list_for_each_entry(conf_span, &(conf_scope->spans), list) {
		struct flt_otel_scope_data   data;
		struct flt_otel_scope_span  *span;
		struct flt_otel_conf_sample *sample;

		OTELC_DBG(DEBUG, "run span '%s' -> '%s'", conf_scope->id, conf_span->id);
		FLT_OTEL_DBG_CONF_SPAN("run span ", conf_span);

		flt_otel_scope_data_init(&data);

		span = flt_otel_scope_span_init(f->ctx, conf_span->id, conf_span->id_len, conf_span->ref_id, conf_span->ref_id_len, dir, err);
		if (span == NULL)
			retval = FLT_OTEL_RET_ERROR;

		list_for_each_entry(sample, &(conf_span->attributes), list) {
			OTELC_DBG(DEBUG, "adding attribute '%s' -> '%s'", sample->key, sample->fmt_string);

			if (flt_otel_sample_add(s, dir, sample, &data, FLT_OTEL_EVENT_SAMPLE_ATTRIBUTE, err) == FLT_OTEL_RET_ERROR)
				retval = FLT_OTEL_RET_ERROR;
		}

		list_for_each_entry(sample, &(conf_span->events), list) {
			OTELC_DBG(DEBUG, "adding event '%s' -> '%s'", sample->key, sample->fmt_string);

			if (flt_otel_sample_add(s, dir, sample, &data, FLT_OTEL_EVENT_SAMPLE_EVENT, err) == FLT_OTEL_RET_ERROR)
				retval = FLT_OTEL_RET_ERROR;
		}

		list_for_each_entry(sample, &(conf_span->baggages), list) {
			OTELC_DBG(DEBUG, "adding baggage '%s' -> '%s'", sample->key, sample->fmt_string);

			if (flt_otel_sample_add(s, dir, sample, &data, FLT_OTEL_EVENT_SAMPLE_BAGGAGE, err) == FLT_OTEL_RET_ERROR)
				retval = FLT_OTEL_RET_ERROR;
		}

		/*
		 * Regardless of the use of the list, only one status per event
		 * is allowed.
		 */
		list_for_each_entry(sample, &(conf_span->statuses), list) {
			OTELC_DBG(DEBUG, "adding status '%s' -> '%s'", sample->key, sample->fmt_string);

			if (flt_otel_sample_add(s, dir, sample, &data, FLT_OTEL_EVENT_SAMPLE_STATUS, err) == FLT_OTEL_RET_ERROR)
				retval = FLT_OTEL_RET_ERROR;
		}

		/* Attempt to run the span regardless of earlier errors. */
		if (span != NULL)
			if (flt_otel_scope_run_span(s, f, chn, dir, span, &data, conf_span, ts_steady, ts_system, err) == FLT_OTEL_RET_ERROR)
				retval = FLT_OTEL_RET_ERROR;

		flt_otel_scope_data_free(&data);
	}

	/* Mark the configured spans for finishing and clean up. */
	list_for_each_entry(span_to_finish, &(conf_scope->spans_to_finish), list)
		if (flt_otel_scope_finish_mark(f->ctx, span_to_finish->str, span_to_finish->str_len) == FLT_OTEL_RET_ERROR)
			retval = FLT_OTEL_RET_ERROR;

	flt_otel_scope_finish_marked(f->ctx, ts_steady);
	flt_otel_scope_free_unused(f->ctx, chn);

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_event_run - top-level event dispatcher
 *
 * SYNOPSIS
 *   int flt_otel_event_run(struct stream *s, struct filter *f, struct channel *chn, int event, char **err)
 *
 * ARGUMENTS
 *   s     - the stream being processed
 *   f     - the filter instance
 *   chn   - the channel being analyzed
 *   event - the event index (FLT_OTEL_EVENT_*)
 *   err   - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Top-level event dispatcher called from filter callbacks.  It iterates over
 *   all scopes matching the <event> index and calls flt_otel_scope_run() for
 *   each.  All spans within a single event share the same monotonic and
 *   wall-clock timestamps.
 *
 * RETURN VALUE
 *   Returns FLT_OTEL_RET_OK on success, FLT_OTEL_RET_ERROR on failure.
 */
int flt_otel_event_run(struct stream *s, struct filter *f, struct channel *chn, int event, char **err)
{
	struct flt_otel_conf       *conf = FLT_OTEL_CONF(f);
	struct flt_otel_conf_scope *conf_scope;
	struct timespec             ts_steady, ts_system;
	int                         retval = FLT_OTEL_RET_OK;

	OTELC_FUNC("%p, %p, %p, %d, %p:%p", s, f, chn, event, OTELC_DPTR_ARGS(err));

	OTELC_DBG(DEBUG, "channel: %s, mode: %s (%s)", flt_otel_chn_label(chn), flt_otel_pr_mode(s), flt_otel_stream_pos(s));
	OTELC_DBG(DEBUG, "run event '%s' %d %s", flt_otel_event_data[event].name, event, flt_otel_event_data[event].an_name);

#ifdef DEBUG_OTEL
	_HA_ATOMIC_ADD(conf->cnt.event[event].htx + ((chn == NULL) ? 1 : (htx_is_empty(htxbuf(&(chn->buf))) ? 1 : 0)), 1);
#endif

	FLT_OTEL_RT_CTX(f->ctx)->analyzers |= flt_otel_event_data[event].an_bit;

	/* All spans should be created/completed at the same time. */
	(void)clock_gettime(CLOCK_MONOTONIC, &ts_steady);
	(void)clock_gettime(CLOCK_REALTIME, &ts_system);

	/*
	 * It is possible that there are defined multiple scopes that use the
	 * same event.  Therefore, there must not be a 'break' here, ie an exit
	 * from the 'for' loop.
	 */
	list_for_each_entry(conf_scope, &(conf->scopes), list) {
		if (conf_scope->event != event)
			/* Do nothing. */;
		else if (!conf_scope->flag_used)
			OTELC_DBG(DEBUG, "scope '%s' %d not used", conf_scope->id, conf_scope->event);
		else if (flt_otel_scope_run(s, f, chn, conf_scope, &ts_steady, &ts_system, flt_otel_event_data[event].smp_opt_dir, err) == FLT_OTEL_RET_ERROR)
			retval = FLT_OTEL_RET_ERROR;
	}

	flt_otel_http_headers_dump(chn);

	OTELC_DBG(DEBUG, "event = %d %s, chn = %p, s->req = %p, s->res = %p", event, flt_otel_event_data[event].an_name, chn, &(s->req), &(s->res));

	OTELC_RETURN_INT(retval);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
