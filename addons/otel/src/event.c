/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../include/include.h"


/* Event data table built from the X-macro list. */
#define FLT_OTEL_EVENT_DEF(a,b,c,d,e,f)   { AN_##b##_##a, OTELC_STRINGIFY_ARG(AN_##b##_##a), SMP_OPT_DIR_##b, SMP_VAL_FE_##c, SMP_VAL_BE_##d, e, f },
const struct flt_otel_event_data flt_otel_event_data[FLT_OTEL_EVENT_MAX] = { FLT_OTEL_EVENT_DEFINES };
#undef FLT_OTEL_EVENT_DEF


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
static int flt_otel_scope_run(struct stream *s, struct filter *f, struct channel *chn, struct flt_otel_conf_scope *conf_scope, const struct timespec *ts_steady, const struct timespec *ts_system, uint dir, char **err)
{
	OTELC_FUNC("%p, %p, %p, %p, %p, %p, %u, %p:%p", s, f, chn, conf_scope, ts_steady, ts_system, dir, OTELC_DPTR_ARGS(err));

	OTELC_DBG(DEBUG, "channel: %s, mode: %s (%s)", flt_otel_chn_label(chn), flt_otel_pr_mode(s), flt_otel_stream_pos(s));
	OTELC_DBG(DEBUG, "run scope '%s' %d", conf_scope->id, conf_scope->event);
	FLT_OTEL_DBG_CONF_SCOPE("run scope ", conf_scope);

	OTELC_RETURN_INT(FLT_OTEL_RET_OK);
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
