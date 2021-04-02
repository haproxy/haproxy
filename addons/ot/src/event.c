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


#define FLT_OT_EVENT_DEF(a,b,c,d,e,f)   { AN_##b##_##a, SMP_OPT_DIR_##b, SMP_VAL_FE_##c, SMP_VAL_BE_##d, e, f },
const struct flt_ot_event_data flt_ot_event_data[FLT_OT_EVENT_MAX] = { FLT_OT_EVENT_DEFINES };
#undef FLT_OT_EVENT_DEF


/***
 * NAME
 *   flt_ot_scope_run_span -
 *
 * ARGUMENTS
 *   s         -
 *   f         -
 *   chn       -
 *   dir       -
 *   span      -
 *   data      -
 *   conf_span -
 *   ts        -
 *   err       -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_ot_scope_run_span(struct stream *s, struct filter *f, struct channel *chn, uint dir, struct flt_ot_scope_span *span, struct flt_ot_scope_data *data, const struct flt_ot_conf_span *conf_span, const struct timespec *ts, char **err)
{
	struct flt_ot_conf *conf = FLT_OT_CONF(f);
	int                 retval = FLT_OT_RET_OK;

	FLT_OT_FUNC("%p, %p, %p, %u, %p, %p, %p, %p, %p:%p", s, f, chn, dir, span, data, conf_span, ts, FLT_OT_DPTR_ARGS(err));

	if (span == NULL)
		FLT_OT_RETURN(retval);

	if (span->span == NULL) {
		span->span = ot_span_init(conf->tracer->tracer, span->id, ts, NULL, span->ref_type, FLT_OT_DEREF(span->ref_ctx, idx, -1), span->ref_span, data->tags, data->num_tags, err);
		if (span->span == NULL)
			retval = FLT_OT_RET_ERROR;
	}
	else if (data->num_tags > 0)
		if (ot_span_tag(span->span, data->tags, data->num_tags) == -1)
			retval = FLT_OT_RET_ERROR;

	if ((span->span != NULL) && (data->baggage != NULL))
		if (ot_span_set_baggage(span->span, data->baggage) == -1)
			retval = FLT_OT_RET_ERROR;

	if ((span->span != NULL) && (data->num_log_fields > 0))
		if (ot_span_log(span->span, data->log_fields, data->num_log_fields) == -1)
			retval = FLT_OT_RET_ERROR;

	if ((span->span != NULL) && (conf_span->ctx_id != NULL)) {
		struct otc_http_headers_writer  writer;
		struct otc_text_map            *text_map = NULL;
		struct otc_span_context        *span_ctx;

		span_ctx = ot_inject_http_headers(conf->tracer->tracer, span->span, &writer, err);
		if (span_ctx != NULL) {
			int i = 0;

			if (conf_span->ctx_flags & (FLT_OT_CTX_USE_VARS | FLT_OT_CTX_USE_HEADERS)) {
				for (text_map = &(writer.text_map); i < text_map->count; i++) {
					if (!(conf_span->ctx_flags & FLT_OT_CTX_USE_VARS))
						/* Do nothing. */;
					else if (flt_ot_var_register(FLT_OT_VARS_SCOPE, conf_span->ctx_id, text_map->key[i], err) == -1)
						retval = FLT_OT_RET_ERROR;
					else if (flt_ot_var_set(s, FLT_OT_VARS_SCOPE, conf_span->ctx_id, text_map->key[i], text_map->value[i], dir, err) == -1)
						retval = FLT_OT_RET_ERROR;

					if (!(conf_span->ctx_flags & FLT_OT_CTX_USE_HEADERS))
						/* Do nothing. */;
					else if (flt_ot_http_header_set(chn, conf_span->ctx_id, text_map->key[i], text_map->value[i], err) == -1)
						retval = FLT_OT_RET_ERROR;
				}
			}

			span_ctx->destroy(&span_ctx);
			otc_text_map_destroy(&text_map, OTC_TEXT_MAP_FREE_KEY | OTC_TEXT_MAP_FREE_VALUE);
		}
	}

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_scope_run -
 *
 * ARGUMENTS
 *   s          -
 *   f          -
 *   chn        -
 *   conf_scope -
 *   ts         -
 *   dir        -
 *   err        -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
int flt_ot_scope_run(struct stream *s, struct filter *f, struct channel *chn, struct flt_ot_conf_scope *conf_scope, const struct timespec *ts, uint dir, char **err)
{
	struct flt_ot_conf         *conf = FLT_OT_CONF(f);
	struct flt_ot_conf_context *conf_ctx;
	struct flt_ot_conf_span    *conf_span;
	struct flt_ot_conf_str     *finish;
	struct timespec             ts_now;
	int                         retval = FLT_OT_RET_OK;

	FLT_OT_FUNC("%p, %p, %p, %p, %p, %u, %p:%p", s, f, chn, conf_scope, ts, dir, FLT_OT_DPTR_ARGS(err));

	FLT_OT_DBG(3, "channel: %s, mode: %s (%s)", flt_ot_chn_label(chn), flt_ot_pr_mode(s), flt_ot_stream_pos(s));
	FLT_OT_DBG(3, "run scope '%s' %d", conf_scope->id, conf_scope->event);
	FLT_OT_DBG_CONF_SCOPE("run scope ", conf_scope);

	if (ts == NULL) {
		(void)clock_gettime(CLOCK_MONOTONIC, &ts_now);

		ts = &ts_now;
	}

	if (conf_scope->cond != NULL) {
		enum acl_test_res res;
		int               rc;

		res = acl_exec_cond(conf_scope->cond, s->be, s->sess, s, dir | SMP_OPT_FINAL);
		rc  = acl_pass(res);
		if (conf_scope->cond->pol == ACL_COND_UNLESS)
			rc = !rc;

		FLT_OT_DBG(3, "the ACL rule %s", rc ? "matches" : "does not match");

		/*
		 * If the rule does not match, the current scope is skipped.
		 *
		 * If it is a root span, further processing of the session is
		 * disabled.  As soon as the first span is encountered which
		 * is marked as root, further search is interrupted.
		 */
		if (!rc) {
			list_for_each_entry(conf_span, &(conf_scope->spans), list)
				if (conf_span->flag_root) {
					FLT_OT_DBG(0, "session disabled");

					FLT_OT_RT_CTX(f->ctx)->flag_disabled = 1;

					_HA_ATOMIC_ADD(conf->cnt.disabled + 0, 1);

					break;
				}

			FLT_OT_RETURN(retval);
		}
	}

	list_for_each_entry(conf_ctx, &(conf_scope->contexts), list) {
		struct otc_text_map *text_map;

		FLT_OT_DBG(3, "run context '%s' -> '%s'", conf_scope->id, conf_ctx->id);
		FLT_OT_DBG_CONF_CONTEXT("run context ", conf_ctx);

		/*
		 * The OpenTracing context is read from the HTTP header
		 * or from HAProxy variables.
		 */
		if (conf_ctx->flags & FLT_OT_CTX_USE_HEADERS)
			text_map = flt_ot_http_headers_get(chn, conf_ctx->id, conf_ctx->id_len, err);
		else
			text_map = flt_ot_vars_get(s, FLT_OT_VARS_SCOPE, conf_ctx->id, dir, err);

		if (text_map != NULL) {
			if (flt_ot_scope_context_init(f->ctx, conf->tracer->tracer, conf_ctx->id, conf_ctx->id_len, text_map, dir, err) == NULL)
				retval = FLT_OT_RET_ERROR;

			otc_text_map_destroy(&text_map, OTC_TEXT_MAP_FREE_KEY | OTC_TEXT_MAP_FREE_VALUE);
		} else {
			retval = FLT_OT_RET_ERROR;
		}
	}

	list_for_each_entry(conf_span, &(conf_scope->spans), list) {
		struct flt_ot_scope_data   data;
		struct flt_ot_scope_span  *span;
		struct flt_ot_conf_sample *sample;

		FLT_OT_DBG(3, "run span '%s' -> '%s'", conf_scope->id, conf_span->id);
		FLT_OT_DBG_CONF_SPAN("run span ", conf_span);

		(void)memset(&data, 0, sizeof(data));

		span = flt_ot_scope_span_init(f->ctx, conf_span->id, conf_span->id_len, conf_span->ref_type, conf_span->ref_id, conf_span->ref_id_len, dir, err);
		if (span == NULL)
			retval = FLT_OT_RET_ERROR;

		list_for_each_entry(sample, &(conf_span->tags), list) {
			FLT_OT_DBG(3, "adding tag '%s' -> '%s'", sample->key, sample->value);

			if (flt_ot_sample_add(s, dir, sample, &data, FLT_OT_EVENT_SAMPLE_TAG, err) == FLT_OT_RET_ERROR)
				retval = FLT_OT_RET_ERROR;
		}

		list_for_each_entry(sample, &(conf_span->logs), list) {
			FLT_OT_DBG(3, "adding log '%s' -> '%s'", sample->key, sample->value);

			if (flt_ot_sample_add(s, dir, sample, &data, FLT_OT_EVENT_SAMPLE_LOG, err) == FLT_OT_RET_ERROR)
				retval = FLT_OT_RET_ERROR;
		}

		list_for_each_entry(sample, &(conf_span->baggages), list) {
			FLT_OT_DBG(3, "adding baggage '%s' -> '%s'", sample->key, sample->value);

			if (flt_ot_sample_add(s, dir, sample, &data, FLT_OT_EVENT_SAMPLE_BAGGAGE, err) == FLT_OT_RET_ERROR)
				retval = FLT_OT_RET_ERROR;
		}

		if (retval != FLT_OT_RET_ERROR)
			if (flt_ot_scope_run_span(s, f, chn, dir, span, &data, conf_span, ts, err) == FLT_OT_RET_ERROR)
				retval = FLT_OT_RET_ERROR;

		flt_ot_scope_data_free(&data);
	}

	list_for_each_entry(finish, &(conf_scope->finish), list)
		if (flt_ot_scope_finish_mark(f->ctx, finish->str, finish->str_len) == -1)
			retval = FLT_OT_RET_ERROR;

	flt_ot_scope_finish_marked(f->ctx, ts);
	flt_ot_scope_free_unused(f->ctx, chn);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_event_run -
 *
 * ARGUMENTS
 *   s     -
 *   f     -
 *   chn   -
 *   event -
 *   err   -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
int flt_ot_event_run(struct stream *s, struct filter *f, struct channel *chn, int event, char **err)
{
	struct flt_ot_conf       *conf = FLT_OT_CONF(f);
	struct flt_ot_conf_scope *conf_scope;
	struct timespec           ts;
	int                       retval = FLT_OT_RET_OK;

	FLT_OT_FUNC("%p, %p, %p, %d, %p:%p", s, f, chn, event, FLT_OT_DPTR_ARGS(err));

	FLT_OT_DBG(3, "channel: %s, mode: %s (%s)", flt_ot_chn_label(chn), flt_ot_pr_mode(s), flt_ot_stream_pos(s));
	FLT_OT_DBG(3, "run event '%s' %d", flt_ot_event_data[event].name, event);

#ifdef DEBUG_OT
	_HA_ATOMIC_ADD(conf->cnt.event[event].htx + (htx_is_empty(htxbuf(&(chn->buf))) ? 1 : 0), 1);
#endif

	FLT_OT_RT_CTX(f->ctx)->analyzers |= flt_ot_event_data[event].an_bit;

	/* All spans should be created/completed at the same time. */
	(void)clock_gettime(CLOCK_MONOTONIC, &ts);

	/*
	 * It is possible that there are defined multiple scopes that use the
	 * same event.  Therefore, there must not be a 'break' here, ie an
	 * exit from the 'for' loop.
	 */
	list_for_each_entry(conf_scope, &(conf->scopes), list) {
		if (conf_scope->event != event)
			/* Do nothing. */;
		else if (!conf_scope->flag_used)
			FLT_OT_DBG(3, "scope '%s' %d not used", conf_scope->id, conf_scope->event);
		else if (flt_ot_scope_run(s, f, chn, conf_scope, &ts, flt_ot_event_data[event].smp_opt_dir, err) == FLT_OT_RET_ERROR)
			retval = FLT_OT_RET_ERROR;
	}

	flt_ot_vars_dump(s);
	flt_ot_http_headers_dump(chn);

	FLT_OT_DBG(3, "event = %d, chn = %p, s->req = %p, s->res = %p", event, chn, &(s->req), &(s->res));

	FLT_OT_RETURN(retval);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
