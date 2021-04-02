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


static struct pool_head *pool_head_ot_scope_span = NULL;
static struct pool_head *pool_head_ot_scope_context = NULL;
static struct pool_head *pool_head_ot_runtime_context = NULL;

#ifdef USE_POOL_OT_SCOPE_SPAN
REGISTER_POOL(&pool_head_ot_scope_span, "ot_scope_span", sizeof(struct flt_ot_scope_span));
#endif
#ifdef USE_POOL_OT_SCOPE_CONTEXT
REGISTER_POOL(&pool_head_ot_scope_context, "ot_scope_context", sizeof(struct flt_ot_scope_context));
#endif
#ifdef USE_POOL_OT_RUNTIME_CONTEXT
REGISTER_POOL(&pool_head_ot_runtime_context, "ot_runtime_context", sizeof(struct flt_ot_runtime_context));
#endif


#ifdef DEBUG_OT

/***
 * NAME
 *   flt_ot_pools_info -
 *
 * ARGUMENTS
 *   This function takes no arguments.
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_pools_info(void)
{
	/*
	 * In case we have some error in the configuration file,
	 * it is possible that this pool was not initialized.
	 */
#ifdef USE_POOL_BUFFER
	FLT_OT_DBG(2, "sizeof_pool(buffer) = %u", FLT_OT_DEREF(pool_head_buffer, size, 0));
#endif
#ifdef USE_TRASH_CHUNK
	FLT_OT_DBG(2, "sizeof_pool(trash) = %u", FLT_OT_DEREF(pool_head_trash, size, 0));
#endif

#ifdef USE_POOL_OT_SCOPE_SPAN
	FLT_OT_DBG(2, "sizeof_pool(ot_scope_span) = %u", pool_head_ot_scope_span->size);
#endif
#ifdef USE_POOL_OT_SCOPE_CONTEXT
	FLT_OT_DBG(2, "sizeof_pool(ot_scope_context) = %u", pool_head_ot_scope_context->size);
#endif
#ifdef USE_POOL_OT_RUNTIME_CONTEXT
	FLT_OT_DBG(2, "sizeof_pool(ot_runtime_context) = %u", pool_head_ot_runtime_context->size);
#endif
}

#endif /* DEBUG_OT */


/***
 * NAME
 *   flt_ot_runtime_context_init -
 *
 * ARGUMENTS
 *   s   -
 *   f   -
 *   err -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct flt_ot_runtime_context *flt_ot_runtime_context_init(struct stream *s, struct filter *f, char **err)
{
	const struct flt_ot_conf      *conf = FLT_OT_CONF(f);
	struct flt_ot_runtime_context *retptr = NULL;

	FLT_OT_FUNC("%p, %p, %p:%p", s, f, FLT_OT_DPTR_ARGS(err));

	retptr = flt_ot_pool_alloc(pool_head_ot_runtime_context, sizeof(*retptr), 1, err);
	if (retptr == NULL)
		FLT_OT_RETURN(retptr);

	retptr->stream        = s;
	retptr->filter        = f;
	retptr->uuid.u64[0]   = ha_random64();
	retptr->uuid.u64[1]   = ha_random64();
	retptr->flag_harderr  = conf->tracer->flag_harderr;
	retptr->flag_disabled = conf->tracer->flag_disabled;
	retptr->logging       = conf->tracer->logging;
	LIST_INIT(&(retptr->spans));
	LIST_INIT(&(retptr->contexts));

	(void)snprintf(retptr->uuid.s, sizeof(retptr->uuid.s), "%08x-%04hx-%04hx-%04hx-%012" PRIx64,
	               retptr->uuid.time_low,
	               retptr->uuid.time_mid,
	               (retptr->uuid.time_hi_and_version & UINT16_C(0xfff)) | UINT16_C(0x4000),
	               retptr->uuid.clock_seq | UINT16_C(0x8000),
	               (uint64_t)retptr->uuid.node);

	if (flt_ot_var_register(FTL_OT_VAR_UUID, err) != -1)
		(void)flt_ot_var_set(s, FTL_OT_VAR_UUID, retptr->uuid.s, SMP_OPT_DIR_REQ, err);

	FLT_OT_DBG_RUNTIME_CONTEXT("session context: ", retptr);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_runtime_context_free -
 *
 * ARGUMENTS
 *   f -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_runtime_context_free(struct filter *f)
{
	struct flt_ot_runtime_context *rt_ctx = f->ctx;

	FLT_OT_FUNC("%p", f);

	if (rt_ctx == NULL)
		FLT_OT_RETURN();

	FLT_OT_DBG_RUNTIME_CONTEXT("session context: ", rt_ctx);

	if (!LIST_ISEMPTY(&(rt_ctx->spans))) {
		struct timespec           ts;
		struct flt_ot_scope_span *span, *span_back;

		/* All spans should be completed at the same time. */
		(void)clock_gettime(CLOCK_MONOTONIC, &ts);

		list_for_each_entry_safe(span, span_back, &(rt_ctx->spans), list) {
			ot_span_finish(&(span->span), &ts, NULL, NULL, NULL);
			flt_ot_scope_span_free(&span);
		}
	}

	if (!LIST_ISEMPTY(&(rt_ctx->contexts))) {
		struct flt_ot_scope_context *ctx, *ctx_back;

		list_for_each_entry_safe(ctx, ctx_back, &(rt_ctx->contexts), list)
			flt_ot_scope_context_free(&ctx);
	}

	flt_ot_pool_free(pool_head_ot_runtime_context, &(f->ctx));

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_scope_span_init -
 *
 * ARGUMENTS
 *   rt_ctx     -
 *   id         -
 *   id_len     -
 *   ref_type   -
 *   ref_id     -
 *   ref_id_len -
 *   dir        -
 *   err        -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct flt_ot_scope_span *flt_ot_scope_span_init(struct flt_ot_runtime_context *rt_ctx, const char *id, size_t id_len, otc_span_reference_type_t ref_type, const char *ref_id, size_t ref_id_len, uint dir, char **err)
{
	struct otc_span             *ref_span = NULL;
	struct otc_span_context     *ref_ctx = NULL;
	struct flt_ot_scope_span    *span, *retptr = NULL;
	struct flt_ot_scope_context *ctx;

	FLT_OT_FUNC("%p, \"%s\", %zu, %d, \"%s\", %zu, %u, %p:%p", rt_ctx, id, id_len, ref_type, ref_id, ref_id_len, dir, FLT_OT_DPTR_ARGS(err));

	if ((rt_ctx == NULL) || (id == NULL))
		FLT_OT_RETURN(retptr);

	list_for_each_entry(span, &(rt_ctx->spans), list)
		if ((span->id_len == id_len) && (memcmp(span->id, id, id_len) == 0)) {
			FLT_OT_DBG(2, "found span %p", span);

			FLT_OT_RETURN(span);
		}

	if (ref_id != NULL) {
		list_for_each_entry(span, &(rt_ctx->spans), list)
			if ((span->id_len == ref_id_len) && (memcmp(span->id, ref_id, ref_id_len) == 0)) {
				ref_span = span->span;

				break;
			}

		if (ref_span != NULL) {
			FLT_OT_DBG(2, "found referenced span %p", span);
		} else {
			list_for_each_entry(ctx, &(rt_ctx->contexts), list)
				if ((ctx->id_len == ref_id_len) && (memcmp(ctx->id, ref_id, ref_id_len) == 0)) {
					ref_ctx = ctx->context;

					break;
				}

			if (ref_ctx != NULL) {
				FLT_OT_DBG(2, "found referenced context %p", ctx);
			} else {
				FLT_OT_ERR("cannot find referenced span/context '%s'", ref_id);

				FLT_OT_RETURN(retptr);
			}
		}
	}

	retptr = flt_ot_pool_alloc(pool_head_ot_scope_span, sizeof(*retptr), 1, err);
	if (retptr == NULL)
		FLT_OT_RETURN(retptr);

	retptr->id          = id;
	retptr->id_len      = id_len;
	retptr->smp_opt_dir = dir;
	retptr->ref_type    = ref_type;
	retptr->ref_span    = ref_span;
	retptr->ref_ctx     = ref_ctx;
	LIST_ADD(&(rt_ctx->spans), &(retptr->list));

	FLT_OT_DBG_SCOPE_SPAN("new span ", retptr);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_scope_span_free -
 *
 * ARGUMENTS
 *   ptr -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_scope_span_free(struct flt_ot_scope_span **ptr)
{
	FLT_OT_FUNC("%p:%p", FLT_OT_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		FLT_OT_RETURN();

	FLT_OT_DBG_SCOPE_SPAN("", *ptr);

	/* If the span is still active, do nothing. */
	if ((*ptr)->span != NULL) {
		FLT_OT_DBG(2, "cannot finish active span");

		FLT_OT_RETURN();
	}

	FLT_OT_LIST_DEL(&((*ptr)->list));
	flt_ot_pool_free(pool_head_ot_scope_span, (void **)ptr);

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_scope_context_init -
 *
 * ARGUMENTS
 *   rt_ctx   -
 *   tracer   -
 *   id       -
 *   id_len   -
 *   text_map -
 *   dir      -
 *   err      -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct flt_ot_scope_context *flt_ot_scope_context_init(struct flt_ot_runtime_context *rt_ctx, struct otc_tracer *tracer, const char *id, size_t id_len, const struct otc_text_map *text_map, uint dir, char **err)
{
	struct otc_http_headers_reader  reader;
	struct otc_span_context        *span_ctx;
	struct flt_ot_scope_context    *retptr = NULL;

	FLT_OT_FUNC("%p, %p, \"%s\", %zu, %p, %u, %p:%p", rt_ctx, tracer, id, id_len, text_map, dir, FLT_OT_DPTR_ARGS(err));

	if ((rt_ctx == NULL) || (tracer == NULL) || (id == NULL) || (text_map == NULL))
		FLT_OT_RETURN(retptr);

	list_for_each_entry(retptr, &(rt_ctx->contexts), list)
		if ((retptr->id_len == id_len) && (memcmp(retptr->id, id, id_len) == 0)) {
			FLT_OT_DBG(2, "found context %p", retptr);

			FLT_OT_RETURN(retptr);
		}

	retptr = flt_ot_pool_alloc(pool_head_ot_scope_context, sizeof(*retptr), 1, err);
	if (retptr == NULL)
		FLT_OT_RETURN(retptr);

	span_ctx = ot_extract_http_headers(tracer, &reader, text_map, err);
	if (span_ctx == NULL) {
		flt_ot_scope_context_free(&retptr);

		FLT_OT_RETURN(retptr);
	}

	retptr->id          = id;
	retptr->id_len      = id_len;
	retptr->smp_opt_dir = dir;
	retptr->context     = span_ctx;
	LIST_ADD(&(rt_ctx->contexts), &(retptr->list));

	FLT_OT_DBG_SCOPE_CONTEXT("new context ", retptr);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_scope_context_free -
 *
 * ARGUMENTS
 *   ptr -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_scope_context_free(struct flt_ot_scope_context **ptr)
{
	FLT_OT_FUNC("%p:%p", FLT_OT_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		FLT_OT_RETURN();

	FLT_OT_DBG_SCOPE_CONTEXT("", *ptr);

	if ((*ptr)->context != NULL)
		(*ptr)->context->destroy(&((*ptr)->context));

	FLT_OT_LIST_DEL(&((*ptr)->list));
	flt_ot_pool_free(pool_head_ot_scope_context, (void **)ptr);

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_scope_data_free -
 *
 * ARGUMENTS
 *   ptr -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_scope_data_free(struct flt_ot_scope_data *ptr)
{
	int i;

	FLT_OT_FUNC("%p", ptr);

	if (ptr == NULL)
		FLT_OT_RETURN();

	FLT_OT_DBG_SCOPE_DATA("", ptr);

	for (i = 0; i < ptr->num_tags; i++)
		if (ptr->tags[i].value.type == otc_value_string)
			FLT_OT_FREE_VOID(ptr->tags[i].value.value.string_value);
	otc_text_map_destroy(&(ptr->baggage), OTC_TEXT_MAP_FREE_VALUE);
	for (i = 0; i < ptr->num_log_fields; i++)
		if (ptr->log_fields[i].value.type == otc_value_string)
			FLT_OT_FREE_VOID(ptr->log_fields[i].value.value.string_value);

	(void)memset(ptr, 0, sizeof(*ptr));

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_scope_finish_mark -
 *
 * ARGUMENTS
 *   rt_ctx -
 *   id     -
 *   id_len -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int flt_ot_scope_finish_mark(const struct flt_ot_runtime_context *rt_ctx, const char *id, size_t id_len)
{
	struct flt_ot_scope_span    *span;
	struct flt_ot_scope_context *ctx;
	int                          span_cnt = 0, ctx_cnt = 0, retval;

	FLT_OT_FUNC("%p, \"%s\", %zu", rt_ctx, id, id_len);

	if (FLT_OT_STR_CMP(FLT_OT_SCOPE_SPAN_FINISH_ALL, id, id_len)) {
		list_for_each_entry(span, &(rt_ctx->spans), list) {
			span->flag_finish = 1;
			span_cnt++;
		}

		list_for_each_entry(ctx, &(rt_ctx->contexts), list) {
			ctx->flag_finish = 1;
			ctx_cnt++;
		}

		FLT_OT_DBG(2, "marked %d span(s), %d context(s)", span_cnt, ctx_cnt);
	}
	else if (FLT_OT_STR_CMP(FLT_OT_SCOPE_SPAN_FINISH_REQ, id, id_len)) {
		list_for_each_entry(span, &(rt_ctx->spans), list)
			if (span->smp_opt_dir == SMP_OPT_DIR_REQ) {
				span->flag_finish = 1;
				span_cnt++;
			}

		list_for_each_entry(ctx, &(rt_ctx->contexts), list)
			if (ctx->smp_opt_dir == SMP_OPT_DIR_REQ) {
				ctx->flag_finish = 1;
				span_cnt++;
			}

		FLT_OT_DBG(2, "marked REQuest channel %d span(s), %d context(s)", span_cnt, ctx_cnt);
	}
	else if (FLT_OT_STR_CMP(FLT_OT_SCOPE_SPAN_FINISH_RES, id, id_len)) {
		list_for_each_entry(span, &(rt_ctx->spans), list)
			if (span->smp_opt_dir == SMP_OPT_DIR_RES) {
				span->flag_finish = 1;
				span_cnt++;
			}

		list_for_each_entry(ctx, &(rt_ctx->contexts), list)
			if (ctx->smp_opt_dir == SMP_OPT_DIR_RES) {
				ctx->flag_finish = 1;
				ctx_cnt++;
			}

		FLT_OT_DBG(2, "marked RESponse channel %d span(s), %d context(s)", span_cnt, ctx_cnt);
	}
	else {
		list_for_each_entry(span, &(rt_ctx->spans), list)
			if ((span->id_len == id_len) && (memcmp(span->id, id, id_len) == 0)) {
				span->flag_finish = 1;
				span_cnt++;

				break;
			}

		list_for_each_entry(ctx, &(rt_ctx->contexts), list)
			if ((ctx->id_len == id_len) && (memcmp(ctx->id, id, id_len) == 0)) {
				ctx->flag_finish = 1;
				ctx_cnt++;

				break;
			}

		if (span_cnt > 0)
			FLT_OT_DBG(2, "marked span '%s'", id);
		if (ctx_cnt > 0)
			FLT_OT_DBG(2, "marked context '%s'", id);
		if ((span_cnt + ctx_cnt) == 0)
			FLT_OT_DBG(2, "cannot find span/context '%s'", id);
	}

	retval = span_cnt + ctx_cnt;

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_scope_finish_marked -
 *
 * ARGUMENTS
 *   rt_ctx    -
 *   ts_finish -
 *
 * DESCRIPTION
 *   Finish marked spans.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_scope_finish_marked(const struct flt_ot_runtime_context *rt_ctx, const struct timespec *ts_finish)
{
	struct flt_ot_scope_span    *span;
	struct flt_ot_scope_context *ctx;

	FLT_OT_FUNC("%p, %p", rt_ctx, ts_finish);

	list_for_each_entry(span, &(rt_ctx->spans), list)
		if (span->flag_finish) {
			FLT_OT_DBG_SCOPE_SPAN("finishing span ", span);

			ot_span_finish(&(span->span), ts_finish, NULL, NULL, NULL);

			span->flag_finish = 0;
		}

	list_for_each_entry(ctx, &(rt_ctx->contexts), list)
		if (ctx->flag_finish) {
			FLT_OT_DBG_SCOPE_CONTEXT("finishing context ", ctx);

			if (ctx->context != NULL)
				ctx->context->destroy(&(ctx->context));

			ctx->flag_finish = 0;
		}

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_scope_free_unused -
 *
 * ARGUMENTS
 *   rt_ctx -
 *   chn    -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_scope_free_unused(struct flt_ot_runtime_context *rt_ctx, struct channel *chn)
{
	FLT_OT_FUNC("%p", rt_ctx);

	if (rt_ctx == NULL)
		FLT_OT_RETURN();

	if (!LIST_ISEMPTY(&(rt_ctx->spans))) {
		struct flt_ot_scope_span *span, *span_back;

		list_for_each_entry_safe(span, span_back, &(rt_ctx->spans), list)
			if (span->span == NULL)
				flt_ot_scope_span_free(&span);
	}

	if (!LIST_ISEMPTY(&(rt_ctx->contexts))) {
		struct flt_ot_scope_context *ctx, *ctx_back;

		list_for_each_entry_safe(ctx, ctx_back, &(rt_ctx->contexts), list)
			if (ctx->context == NULL) {
				/*
				 * All headers and variables associated with
				 * the context in question should be deleted.
				 */
				(void)flt_ot_http_headers_remove(chn, ctx->id, NULL);
				(void)flt_ot_vars_unset(rt_ctx->stream, FLT_OT_VARS_SCOPE, ctx->id, ctx->smp_opt_dir, NULL);

				flt_ot_scope_context_free(&ctx);
			}
	}

	FLT_OT_DBG_RUNTIME_CONTEXT("session context: ", rt_ctx);

	FLT_OT_RETURN();
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
