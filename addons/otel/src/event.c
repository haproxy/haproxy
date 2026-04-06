/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../include/include.h"


/* Event data table built from the X-macro list. */
#define FLT_OTEL_EVENT_DEF(a,b,c,d,e,f)   { AN_##b##_##a, OTELC_STRINGIFY_ARG(AN_##b##_##a), SMP_OPT_DIR_##b, SMP_VAL_FE_##c, SMP_VAL_BE_##d, e, f },
const struct flt_otel_event_data flt_otel_event_data[FLT_OTEL_EVENT_MAX] = { FLT_OTEL_EVENT_DEFINES };
#undef FLT_OTEL_EVENT_DEF


/***
 * NAME
 *   flt_otel_scope_run_instrument_record - metric instrument value recorder
 *
 * SYNOPSIS
 *   static int flt_otel_scope_run_instrument_record(struct stream *s, uint dir, struct otelc_meter *meter, struct flt_otel_conf_instrument *instr_ref, struct flt_otel_conf_instrument *instr, char **err)
 *
 * ARGUMENTS
 *   s         - the stream providing the sample context
 *   dir       - the sample fetch direction (SMP_OPT_DIR_REQ/RES)
 *   meter     - the OTel meter instance
 *   instr_ref - the create-form instrument providing samples and meter index
 *   instr     - the update-form instrument providing per-scope attributes
 *   err       - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Evaluates sample expressions from a create-form instrument and records
 *   the resulting value via the <meter> API.  Each expression is evaluated
 *   with sample_process(), converted to an otelc_value via
 *   flt_otel_sample_to_value(), and recorded via
 *   <meter>->update_instrument_kv_n().
 *
 * RETURN VALUE
 *   Returns FLT_OTEL_RET_OK on success, FLT_OTEL_RET_ERROR on failure.
 */
static int flt_otel_scope_run_instrument_record(struct stream *s, uint dir, struct otelc_meter *meter, struct flt_otel_conf_instrument *instr_ref, struct flt_otel_conf_instrument *instr, char **err)
{
	struct flt_otel_conf_sample      *sample;
	struct flt_otel_conf_sample_expr *expr;
	struct sample                     smp;
	struct otelc_value                value;
	struct flt_otel_scope_data_kv     instr_attr;
	int                               retval = FLT_OTEL_RET_OK;

	OTELC_FUNC("%p, %u, %p, %p, %p, %p:%p", s, dir, meter, instr_ref, instr, OTELC_DPTR_ARGS(err));

	/* Evaluate instrument attributes from sample expressions. */
	(void)memset(&instr_attr, 0, sizeof(instr_attr));

	list_for_each_entry(sample, &(instr->attributes), list) {
		struct otelc_value attr_value;

		OTELC_DBG(DEBUG, "adding instrument attribute '%s' -> '%s'", sample->key, sample->fmt_string);

		if (flt_otel_sample_eval(s, dir, sample, true, &attr_value, err) == FLT_OTEL_RET_ERROR) {
			retval = FLT_OTEL_RET_ERROR;

			continue;
		}

		if (flt_otel_sample_add_kv(&instr_attr, sample->key, &attr_value) == FLT_OTEL_RET_ERROR) {
			if (attr_value.u_type == OTELC_VALUE_DATA)
				OTELC_SFREE(attr_value.u.value_data);

			retval = FLT_OTEL_RET_ERROR;
		}
	}

	/* The samples list always contains exactly one entry. */
	sample = LIST_NEXT(&(instr_ref->samples), struct flt_otel_conf_sample *, list);

	(void)memset(&smp, 0, sizeof(smp));

	if (sample->lf_used) {
		/*
		 * Log-format path: evaluate into a temporary buffer and present
		 * the result as a string sample.
		 */
		smp.data.u.str.area = OTELC_CALLOC(1, global.tune.bufsize);
		if (smp.data.u.str.area == NULL) {
			FLT_OTEL_ERR("out of memory");

			otelc_kv_destroy(&(instr_attr.attr), instr_attr.cnt);

			OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);
		}

		smp.data.type       = SMP_T_STR;
		smp.data.u.str.data = build_logline(s, smp.data.u.str.area, global.tune.bufsize, &(sample->lf_expr));
	} else {
		/* The expressions list always contains exactly one entry. */
		expr = LIST_NEXT(&(sample->exprs), struct flt_otel_conf_sample_expr *, list);

		FLT_OTEL_DBG_CONF_SAMPLE_EXPR("sample expression ", expr);

		if (sample_process(s->be, s->sess, s, dir | SMP_OPT_FINAL, expr->expr, &smp) == NULL) {
			OTELC_DBG(NOTICE, "WARNING: failed to fetch '%s'", expr->fmt_expr);

			retval = FLT_OTEL_RET_ERROR;
		}
	}

	if (retval == FLT_OTEL_RET_ERROR) {
		/* Do nothing. */
	}
	else if (flt_otel_sample_to_value(sample->key, &(smp.data), &value, err) == FLT_OTEL_RET_ERROR) {
		if (value.u_type == OTELC_VALUE_DATA)
			OTELC_SFREE(value.u.value_data);

		retval = FLT_OTEL_RET_ERROR;
	}
	else {
		OTELC_DBG_VALUE(DEBUG, "value ", &value);

		/*
		 * Metric instruments expect numeric values (INT64 or DOUBLE).
		 * Reject OTELC_VALUE_DATA since the meter cannot interpret
		 * arbitrary string data as a numeric measurement.
		 */
		if (value.u_type == OTELC_VALUE_DATA) {
			OTELC_DBG(NOTICE, "WARNING: non-numeric value type for instrument '%s'", instr_ref->id);

			if (otelc_value_strtonum(&value, OTELC_VALUE_INT64) == OTELC_RET_ERROR) {
				OTELC_SFREE(value.u.value_data);

				retval = FLT_OTEL_RET_ERROR;
			}
		}

		if (retval != FLT_OTEL_RET_ERROR)
			if (OTELC_OPS(meter, update_instrument_kv_n, HA_ATOMIC_LOAD(&(instr_ref->idx)), &value, instr_attr.attr, instr_attr.cnt) == OTELC_RET_ERROR)
				retval = FLT_OTEL_RET_ERROR;
	}

	otelc_kv_destroy(&(instr_attr.attr), instr_attr.cnt);

	if (sample->lf_used)
		OTELC_SFREE(smp.data.u.str.area);

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_scope_run_instrument - metric instrument processor
 *
 * SYNOPSIS
 *   static int flt_otel_scope_run_instrument(struct stream *s, uint dir, struct flt_otel_conf_scope *scope, struct otelc_meter *meter, char **err)
 *
 * ARGUMENTS
 *   s     - the stream providing the sample context
 *   dir   - the sample fetch direction (SMP_OPT_DIR_REQ/RES)
 *   scope - the scope configuration containing the instrument list
 *   meter - the OTel meter instance
 *   err   - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Processes all metric instruments configured in <scope>.  Runs in two
 *   passes: the first pass lazily creates create-form instruments via <meter>
 *   on first use, using HA_ATOMIC_CAS on the instrument index to guarantee
 *   thread-safe one-time initialization.  The second pass iterates over
 *   update-form instruments and records measurements via
 *   flt_otel_scope_run_instrument_record().  Instruments whose index is still
 *   negative (UNUSED or PENDING) are skipped, so that a concurrent creation by
 *   another thread does not cause an invalid <meter> access.
 *
 * RETURN VALUE
 *   Returns FLT_OTEL_RET_OK on success, FLT_OTEL_RET_ERROR on failure.
 */
static int flt_otel_scope_run_instrument(struct stream *s, uint dir, struct flt_otel_conf_scope *scope, struct otelc_meter *meter, char **err)
{
	struct flt_otel_conf_instrument *conf_instr;
	int                              retval = FLT_OTEL_RET_OK;

	OTELC_FUNC("%p, %u, %p, %p, %p:%p", s, dir, scope, meter, OTELC_DPTR_ARGS(err));

	list_for_each_entry(conf_instr, &(scope->instruments), list) {
		if (conf_instr->type == OTELC_METRIC_INSTRUMENT_UPDATE) {
			/* Do nothing. */
		}
		else if (HA_ATOMIC_LOAD(&(conf_instr->idx)) == OTELC_METRIC_INSTRUMENT_UNSET) {
			int64_t expected = OTELC_METRIC_INSTRUMENT_UNSET;
			int     rc;

			OTELC_DBG(DEBUG, "run instrument '%s' -> '%s'", scope->id, conf_instr->id);
			FLT_OTEL_DBG_CONF_INSTRUMENT("", conf_instr);

			/*
			 * Create form: use this instrument directly.  Lazily
			 * create the instrument on first use.  Use CAS to
			 * ensure only one thread performs the creation in a
			 * multi-threaded environment.
			 */
			if (!HA_ATOMIC_CAS(&(conf_instr->idx), &expected, OTELC_METRIC_INSTRUMENT_PENDING))
				continue;

			/*
			 * The view must be created before the instrument,
			 * otherwise bucket boundaries cannot be set.
			 */
			if ((conf_instr->bounds != NULL) && (conf_instr->bounds_num > 0))
				if (OTELC_OPS(meter, add_view, conf_instr->id, conf_instr->description, conf_instr->id, conf_instr->unit, conf_instr->type, conf_instr->aggr_type, conf_instr->bounds, conf_instr->bounds_num) == OTELC_RET_ERROR)
					OTELC_DBG(NOTICE, "WARNING: failed to add view for instrument '%s'", conf_instr->id);

			rc = OTELC_OPS(meter, create_instrument, conf_instr->id, conf_instr->description, conf_instr->unit, conf_instr->type, NULL);
			if (rc == OTELC_RET_ERROR) {
				OTELC_DBG(NOTICE, "WARNING: failed to create instrument '%s'", conf_instr->id);

				HA_ATOMIC_STORE(&(conf_instr->idx), OTELC_METRIC_INSTRUMENT_UNSET);

				retval = FLT_OTEL_RET_ERROR;

				continue;
			} else {
				HA_ATOMIC_STORE(&(conf_instr->idx), rc);
			}
		}
	}

	list_for_each_entry(conf_instr, &(scope->instruments), list)
		if (conf_instr->type == OTELC_METRIC_INSTRUMENT_UPDATE) {
			struct flt_otel_conf_instrument *instr = conf_instr->ref;

			OTELC_DBG(DEBUG, "run instrument '%s' -> '%s'", scope->id, conf_instr->id);
			FLT_OTEL_DBG_CONF_INSTRUMENT("", conf_instr);

			/*
			 * Update form: record a measurement using an existing
			 * create-form instrument.
			 */
			if (instr == NULL) {
				OTELC_DBG(NOTICE, "WARNING: invalid reference instrument '%s'", conf_instr->id);

				retval = FLT_OTEL_RET_ERROR;
			}
			else if (HA_ATOMIC_LOAD(&(instr->idx)) < 0) {
				OTELC_DBG(NOTICE, "WARNING: instrument '%s' not yet created, skipping", instr->id);
			}
			else if (flt_otel_scope_run_instrument_record(s, dir, meter, instr, conf_instr, err) == FLT_OTEL_RET_ERROR) {
				retval = FLT_OTEL_RET_ERROR;
			}
		}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_scope_run_log_record - log record emitter
 *
 * SYNOPSIS
 *   static int flt_otel_scope_run_log_record(struct stream *s, struct filter *f, uint dir, struct flt_otel_conf_scope *scope, struct otelc_logger *logger, const struct timespec *ts, char **err)
 *
 * ARGUMENTS
 *   s      - the stream providing the sample context
 *   f      - the filter instance
 *   dir    - the sample fetch direction (SMP_OPT_DIR_REQ/RES)
 *   scope  - the scope configuration containing the log record list
 *   logger - the OTel logger instance
 *   ts     - the wall-clock timestamp for the log record
 *   err    - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Processes all log records configured in <scope>.  For each record, checks
 *   whether the logger is enabled for the configured severity, evaluates the
 *   sample expressions into a body string, resolves the optional span reference
 *   against the runtime context, and emits the log record via the logger's
 *   log_span operation.
 *
 * RETURN VALUE
 *   Returns FLT_OTEL_RET_OK on success, FLT_OTEL_RET_ERROR on failure.
 */
static int flt_otel_scope_run_log_record(struct stream *s, struct filter *f, uint dir, struct flt_otel_conf_scope *scope, struct otelc_logger *logger, const struct timespec *ts, char **err)
{
	struct flt_otel_conf_log_record *conf_log;
	int                              retval = FLT_OTEL_RET_OK;

	OTELC_FUNC("%p, %p, %u, %p, %p, %p, %p:%p", s, f, dir, scope, logger, ts, OTELC_DPTR_ARGS(err));

	list_for_each_entry(conf_log, &(scope->log_records), list) {
		struct flt_otel_conf_sample      *sample;
		struct flt_otel_conf_sample_expr *expr;
		struct sample                     smp;
		struct otelc_span                *otel_span = NULL;
		struct flt_otel_scope_data_kv     log_attr;
		struct buffer                     buffer;
		int                               rc;

		OTELC_DBG(DEBUG, "run log-record '%s' -> '%s'", scope->id, conf_log->id);

		/* Skip if the logger is not enabled for this severity. */
		if (OTELC_OPS(logger, enabled, conf_log->severity) == 0)
			continue;

		/* Evaluate log record attributes from sample expressions. */
		(void)memset(&log_attr, 0, sizeof(log_attr));

		list_for_each_entry(sample, &(conf_log->attributes), list) {
			struct otelc_value attr_value;

			OTELC_DBG(DEBUG, "adding log-record attribute '%s' -> '%s'", sample->key, sample->fmt_string);

			if (flt_otel_sample_eval(s, dir, sample, true, &attr_value, err) == FLT_OTEL_RET_ERROR) {
				retval = FLT_OTEL_RET_ERROR;

				continue;
			}

			if (flt_otel_sample_add_kv(&log_attr, sample->key, &attr_value) == FLT_OTEL_RET_ERROR) {
				if (attr_value.u_type == OTELC_VALUE_DATA)
					OTELC_SFREE(attr_value.u.value_data);

				retval = FLT_OTEL_RET_ERROR;
			}
		}

		/* The samples list has exactly one entry. */
		sample = LIST_NEXT(&(conf_log->samples), typeof(sample), list);

		(void)memset(&buffer, 0, sizeof(buffer));

		if (sample->lf_used) {
			/*
			 * Log-format path: evaluate the log-format expression
			 * into a dynamically allocated buffer.
			 */
			chunk_init(&buffer, OTELC_CALLOC(1, global.tune.bufsize), global.tune.bufsize);
			if (buffer.area != NULL)
				buffer.data = build_logline(s, buffer.area, buffer.size, &(sample->lf_expr));
		} else {
			/*
			 * Bare sample expression path: evaluate each expression
			 * and concatenate the results.
			 */
			list_for_each_entry(expr, &(sample->exprs), list) {
				(void)memset(&smp, 0, sizeof(smp));

				if (sample_process(s->be, s->sess, s, dir | SMP_OPT_FINAL, expr->expr, &smp) == NULL) {
					OTELC_DBG(NOTICE, "WARNING: failed to fetch '%s'", expr->fmt_expr);

					retval = FLT_OTEL_RET_ERROR;

					break;
				}

				if (buffer.area == NULL) {
					chunk_init(&buffer, OTELC_CALLOC(1, global.tune.bufsize), global.tune.bufsize);
					if (buffer.area == NULL)
						break;
				}

				rc = flt_otel_sample_to_str(&(smp.data), buffer.area + buffer.data, buffer.size - buffer.data, err);
				if (rc == FLT_OTEL_RET_ERROR) {
					retval = FLT_OTEL_RET_ERROR;

					break;
				}

				buffer.data += rc;
			}
		}

		if (buffer.area == NULL) {
			FLT_OTEL_ERR("out of memory");

			retval = FLT_OTEL_RET_ERROR;

			otelc_kv_destroy(&(log_attr.attr), log_attr.cnt);

			continue;
		}

		/*
		 * If the log record references a span, resolve it against the
		 * runtime context.  A missing span is not fatal -- the log
		 * record is emitted without span correlation.
		 */
		if (conf_log->span != NULL) {
			struct flt_otel_runtime_context *rt_ctx = FLT_OTEL_RT_CTX(f->ctx);
			struct flt_otel_scope_span      *sc_span;

			list_for_each_entry(sc_span, &(rt_ctx->spans), list)
				if (strcmp(sc_span->id, conf_log->span) == 0) {
					otel_span = sc_span->span;

					break;
				}

			if (otel_span == NULL)
				OTELC_DBG(NOTICE, "WARNING: cannot find span '%s' for log-record", conf_log->span);
		}

		if (OTELC_OPS(logger, log_span, conf_log->severity, conf_log->event_id, conf_log->event_name, otel_span, ts, log_attr.attr, log_attr.cnt, "%s", buffer.area) == OTELC_RET_ERROR)
			retval = FLT_OTEL_RET_ERROR;

		otelc_kv_destroy(&(log_attr.attr), log_attr.cnt);
		OTELC_SFREE(buffer.area);
	}

	OTELC_RETURN_INT(retval);
}


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
 *   injects the span context into HTTP headers or HAProxy variables if
 *   configured in <conf_span>.
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

	/* Add all resolved span links to the current span. */
	if (!LIST_ISEMPTY(&(data->links))) {
		struct flt_otel_scope_data_link *link;

		list_for_each_entry(link, &(data->links), list) {
			OTELC_DBG(DEBUG, "adding link %p %p", link->span, link->context);

			if (OTELC_OPS(span->span, add_link, link->span, link->context, NULL, 0) == -1)
				retval = FLT_OTEL_RET_ERROR;
		}
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

	/* Inject span context into HTTP headers and variables. */
	if (conf_span->ctx_id != NULL) {
		struct otelc_http_headers_writer  writer;
		struct otelc_text_map            *text_map = NULL;

		if (flt_otel_inject_http_headers(span->span, &writer) != FLT_OTEL_RET_ERROR) {
			int i = 0;

			if (conf_span->ctx_flags & (FLT_OTEL_CTX_USE_VARS | FLT_OTEL_CTX_USE_HEADERS)) {
				for (text_map = &(writer.text_map); i < text_map->count; i++) {
#ifdef USE_OTEL_VARS
					if (!(conf_span->ctx_flags & FLT_OTEL_CTX_USE_VARS))
						/* Do nothing. */;
					else if (flt_otel_var_register(FLT_OTEL_VARS_SCOPE, conf_span->ctx_id, text_map->key[i], err) == FLT_OTEL_RET_ERROR)
						retval = FLT_OTEL_RET_ERROR;
					else if (flt_otel_var_set(s, FLT_OTEL_VARS_SCOPE, conf_span->ctx_id, text_map->key[i], text_map->value[i], dir, err) == FLT_OTEL_RET_ERROR)
						retval = FLT_OTEL_RET_ERROR;
#endif

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
 *   from HTTP headers or HAProxy variables, iterates over configured spans
 *   (resolving links, evaluating sample expressions for attributes, events,
 *   baggage and status), calls flt_otel_scope_run_span() for each, processes
 *   metric instruments, emits log records, then marks and finishes completed
 *   spans.
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
		 * The OpenTelemetry context is read from the HTTP header
		 * or from HAProxy variables.
		 */
		if (conf_ctx->flags & FLT_OTEL_CTX_USE_HEADERS)
			text_map = flt_otel_http_headers_get(chn, conf_ctx->id, conf_ctx->id_len, err);
#ifdef USE_OTEL_VARS
		else
			text_map = flt_otel_vars_get(s, FLT_OTEL_VARS_SCOPE, conf_ctx->id, dir, err);
#endif

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

		/*
		 * Resolve configured span links against the runtime context.
		 * Each link name is looked up first in the active spans, then
		 * in the extracted contexts.
		 */
		if (!LIST_ISEMPTY(&(conf_span->links))) {
			struct flt_otel_runtime_context *rt_ctx = FLT_OTEL_RT_CTX(f->ctx);
			struct flt_otel_conf_link       *conf_link;

			list_for_each_entry(conf_link, &(conf_span->links), list) {
				struct flt_otel_scope_data_link *data_link;
				struct otelc_span               *link_span = NULL;
				struct otelc_span_context       *link_ctx = NULL;
				struct flt_otel_scope_span      *sc_span;
				struct flt_otel_scope_context   *sc_ctx;

				/* Try to find a matching span first. */
				list_for_each_entry(sc_span, &(rt_ctx->spans), list)
					if (FLT_OTEL_CONF_STR_CMP(sc_span->id, conf_link->span)) {
						link_span = sc_span->span;

						break;
					}

				/* If no span found, try to find a matching context. */
				if (link_span == NULL) {
					list_for_each_entry(sc_ctx, &(rt_ctx->contexts), list)
						if (FLT_OTEL_CONF_STR_CMP(sc_ctx->id, conf_link->span)) {
							link_ctx = sc_ctx->context;

							break;
						}
				}

				if ((link_span == NULL) && (link_ctx == NULL)) {
					OTELC_DBG(NOTICE, "WARNING: cannot find linked span/context '%s'", conf_link->span);

					continue;
				}

				data_link = OTELC_CALLOC(1, sizeof(*data_link));
				if (data_link == NULL) {
					retval = FLT_OTEL_RET_ERROR;

					break;
				}

				data_link->span    = link_span;
				data_link->context = link_ctx;
				LIST_APPEND(&(data.links), &(data_link->list));

				OTELC_DBG(DEBUG, "resolved link '%s' -> %p %p", conf_link->span, link_span, link_ctx);
			}
		}

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

	/* Process metric instruments. */
	if (!LIST_ISEMPTY(&(conf_scope->instruments)))
		if (flt_otel_scope_run_instrument(s, dir, conf_scope, conf->instr->meter, err) == FLT_OTEL_RET_ERROR)
			retval = FLT_OTEL_RET_ERROR;

	/* Emit log records. */
	if (!LIST_ISEMPTY(&(conf_scope->log_records)))
		if (flt_otel_scope_run_log_record(s, f, dir, conf_scope, conf->instr->logger, ts_system, err) == FLT_OTEL_RET_ERROR)
			retval = FLT_OTEL_RET_ERROR;

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

#ifdef USE_OTEL_VARS
	flt_otel_vars_dump(s);
#endif
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
