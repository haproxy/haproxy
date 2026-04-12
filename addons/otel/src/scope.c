/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../include/include.h"


/***
 * NAME
 *   flt_otel_runtime_context_init - per-stream runtime context allocation
 *
 * SYNOPSIS
 *   struct flt_otel_runtime_context *flt_otel_runtime_context_init(struct stream *s, struct filter *f, char **err)
 *
 * ARGUMENTS
 *   s   - the stream to which the context belongs
 *   f   - the filter instance
 *   err - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Allocates and initializes a per-stream runtime context from pool memory.
 *   It copies the hard-error, disabled and logging flags from the filter
 *   configuration, generates a UUID and stores it in the sess.otel.uuid
 *   HAProxy variable.
 *
 * RETURN VALUE
 *   Returns a pointer to the new runtime context, or NULL on failure.
 */
struct flt_otel_runtime_context *flt_otel_runtime_context_init(struct stream *s, struct filter *f, char **err)
{
	const struct flt_otel_conf      *conf = FLT_OTEL_CONF(f);
	struct buffer                    uuid;
	struct flt_otel_runtime_context *retptr = NULL;

	OTELC_FUNC("%p, %p, %p:%p", s, f, OTELC_DPTR_ARGS(err));

	retptr = flt_otel_pool_alloc(pool_head_otel_runtime_context, sizeof(*retptr), 1, err);
	if (retptr == NULL)
		OTELC_RETURN_PTR(retptr);

	/* Initialize runtime context fields and generate a session UUID. */
	retptr->stream        = s;
	retptr->filter        = f;
	retptr->flag_harderr  = _HA_ATOMIC_LOAD(&(conf->instr->flag_harderr));
	retptr->flag_disabled = _HA_ATOMIC_LOAD(&(conf->instr->flag_disabled));
	retptr->logging       = _HA_ATOMIC_LOAD(&(conf->instr->logging));
	retptr->idle_timeout  = 0;
	retptr->idle_exp      = TICK_ETERNITY;
	LIST_INIT(&(retptr->spans));
	LIST_INIT(&(retptr->contexts));

	uuid = b_make(retptr->uuid, sizeof(retptr->uuid), 0, 0);
	ha_generate_uuid_v4(&uuid);

	FLT_OTEL_DBG_RUNTIME_CONTEXT("session context: ", retptr);

	OTELC_RETURN_PTR(retptr);
}


/***
 * NAME
 *   flt_otel_runtime_context_free - per-stream runtime context cleanup
 *
 * SYNOPSIS
 *   void flt_otel_runtime_context_free(struct filter *f)
 *
 * ARGUMENTS
 *   f - the filter instance whose runtime context is to be freed
 *
 * DESCRIPTION
 *   Frees the per-stream runtime context attached to <f>.  It ends all active
 *   spans with the current monotonic timestamp, destroys all extracted
 *   contexts, and returns the pool memory.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_runtime_context_free(struct filter *f)
{
	struct flt_otel_runtime_context *rt_ctx = f->ctx;

	OTELC_FUNC("%p", f);

	if (rt_ctx == NULL)
		OTELC_RETURN();

	FLT_OTEL_DBG_RUNTIME_CONTEXT("session context: ", rt_ctx);

	/* End all active spans with a common timestamp. */
	if (!LIST_ISEMPTY(&(rt_ctx->spans))) {
		struct timespec             ts_steady;
		struct flt_otel_scope_span *span, *span_back;

		/* All spans should be completed at the same time. */
		(void)clock_gettime(CLOCK_MONOTONIC, &ts_steady);

		list_for_each_entry_safe(span, span_back, &(rt_ctx->spans), list) {
			OTELC_OPSR(span->span, end_with_options, &ts_steady, OTELC_SPAN_STATUS_IGNORE, NULL);
			flt_otel_scope_span_free(&span);
		}
	}

	/* Destroy all extracted span contexts. */
	if (!LIST_ISEMPTY(&(rt_ctx->contexts))) {
		struct flt_otel_scope_context *ctx, *ctx_back;

		list_for_each_entry_safe(ctx, ctx_back, &(rt_ctx->contexts), list)
			flt_otel_scope_context_free(&ctx);
	}

	flt_otel_pool_free(pool_head_otel_runtime_context, &(f->ctx));

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_scope_span_init - scope span lookup or creation
 *
 * SYNOPSIS
 *   struct flt_otel_scope_span *flt_otel_scope_span_init(struct flt_otel_runtime_context *rt_ctx, const char *id, size_t id_len, const char *ref_id, size_t ref_id_len, uint dir, char **err)
 *
 * ARGUMENTS
 *   rt_ctx     - the runtime context owning the span list
 *   id         - the span operation name
 *   id_len     - length of the <id> string
 *   ref_id     - the parent span or context name, or NULL
 *   ref_id_len - length of the <ref_id> string
 *   dir        - the sample fetch direction (SMP_OPT_DIR_REQ/RES)
 *   err        - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Finds an existing scope span by <id> in the runtime context or creates a
 *   new one.  If <ref_id> is set, it resolves the parent reference by searching
 *   the span list first, then the extracted context list.
 *
 * RETURN VALUE
 *   Returns the existing or new scope span, or NULL on failure.
 */
struct flt_otel_scope_span *flt_otel_scope_span_init(struct flt_otel_runtime_context *rt_ctx, const char *id, size_t id_len, const char *ref_id, size_t ref_id_len, uint dir, char **err)
{
	struct otelc_span             *ref_span = NULL;
	struct otelc_span_context     *ref_ctx = NULL;
	struct flt_otel_scope_span    *span, *retptr = NULL;
	struct flt_otel_scope_context *ctx;

	OTELC_FUNC("%p, \"%s\", %zu, \"%s\", %zu, %u, %p:%p", rt_ctx, OTELC_STR_ARG(id), id_len, OTELC_STR_ARG(ref_id), ref_id_len, dir, OTELC_DPTR_ARGS(err));

	if ((rt_ctx == NULL) || (id == NULL))
		OTELC_RETURN_PTR(retptr);

	/* Return the existing span if one matches this ID. */
	list_for_each_entry(span, &(rt_ctx->spans), list)
		if (FLT_OTEL_CONF_STR_CMP(span->id, id)) {
			OTELC_DBG(NOTICE, "found span %p", span);

			OTELC_RETURN_PTR(span);
		}

	/* Resolve the parent reference from spans or contexts. */
	if (ref_id != NULL) {
		list_for_each_entry(span, &(rt_ctx->spans), list)
			if (FLT_OTEL_CONF_STR_CMP(span->id, ref_id)) {
				ref_span = span->span;

				break;
			}

		if (ref_span != NULL) {
			OTELC_DBG(NOTICE, "found referenced span %p", span);
		} else {
			list_for_each_entry(ctx, &(rt_ctx->contexts), list)
				if (FLT_OTEL_CONF_STR_CMP(ctx->id, ref_id)) {
					ref_ctx = ctx->context;

					break;
				}

			if (ref_ctx != NULL) {
				OTELC_DBG(NOTICE, "found referenced context %p", ctx);
			} else {
				FLT_OTEL_ERR("cannot find referenced span/context '%s'", ref_id);

				OTELC_RETURN_PTR(retptr);
			}
		}
	}

	retptr = flt_otel_pool_alloc(pool_head_otel_scope_span, sizeof(*retptr), 1, err);
	if (retptr == NULL)
		OTELC_RETURN_PTR(retptr);

	/* Populate the new scope span and insert it into the list. */
	retptr->id          = id;
	retptr->id_len      = id_len;
	retptr->smp_opt_dir = dir;
	retptr->ref_span    = ref_span;
	retptr->ref_ctx     = ref_ctx;
	LIST_INSERT(&(rt_ctx->spans), &(retptr->list));

	FLT_OTEL_DBG_SCOPE_SPAN("new span ", retptr);

	OTELC_RETURN_PTR(retptr);
}


/***
 * NAME
 *   flt_otel_scope_span_free - scope span cleanup
 *
 * SYNOPSIS
 *   void flt_otel_scope_span_free(struct flt_otel_scope_span **ptr)
 *
 * ARGUMENTS
 *   ptr - pointer to the scope span pointer to free
 *
 * DESCRIPTION
 *   Frees a scope span entry pointed to by <ptr> and removes it from its list.
 *   If the OTel span is still active (non-NULL), the function refuses to free
 *   it and returns immediately.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_scope_span_free(struct flt_otel_scope_span **ptr)
{
	OTELC_FUNC("%p:%p", OTELC_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		OTELC_RETURN();

	FLT_OTEL_DBG_SCOPE_SPAN("", *ptr);

	/* If the span is still active, do nothing. */
	if ((*ptr)->span != NULL) {
		OTELC_DBG(NOTICE, "cannot finish active span");

		OTELC_RETURN();
	}

	FLT_OTEL_LIST_DEL(&((*ptr)->list));
	flt_otel_pool_free(pool_head_otel_scope_span, (void **)ptr);

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_scope_context_init - scope context extraction
 *
 * SYNOPSIS
 *   struct flt_otel_scope_context *flt_otel_scope_context_init(struct flt_otel_runtime_context *rt_ctx, struct otelc_tracer *tracer, const char *id, size_t id_len, const struct otelc_text_map *text_map, uint dir, char **err)
 *
 * ARGUMENTS
 *   rt_ctx   - the runtime context owning the context list
 *   tracer   - the OTel tracer used for context extraction
 *   id       - the context name
 *   id_len   - length of the <id> string
 *   text_map - the carrier text map to extract from
 *   dir      - the sample fetch direction (SMP_OPT_DIR_REQ/RES)
 *   err      - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Finds an existing scope context by <id> in the runtime context or creates
 *   a new one by extracting the span context from the <text_map> carrier via
 *   the <tracer>.
 *
 * RETURN VALUE
 *   Returns the existing or new scope context, or NULL on failure.
 */
struct flt_otel_scope_context *flt_otel_scope_context_init(struct flt_otel_runtime_context *rt_ctx, struct otelc_tracer *tracer, const char *id, size_t id_len, const struct otelc_text_map *text_map, uint dir, char **err)
{
	struct flt_otel_scope_context *retptr = NULL;

	OTELC_FUNC("%p, %p, \"%s\", %zu, %p, %u, %p:%p", rt_ctx, tracer, OTELC_STR_ARG(id), id_len, text_map, dir, OTELC_DPTR_ARGS(err));

	if ((rt_ctx == NULL) || (tracer == NULL) || (id == NULL) || (text_map == NULL))
		OTELC_RETURN_PTR(retptr);

	/* Return the existing context if one matches this ID. */
	list_for_each_entry(retptr, &(rt_ctx->contexts), list)
		if (FLT_OTEL_CONF_STR_CMP(retptr->id, id)) {
			OTELC_DBG(NOTICE, "found context %p", retptr);

			OTELC_RETURN_PTR(retptr);
		}

	retptr = flt_otel_pool_alloc(pool_head_otel_scope_context, sizeof(*retptr), 1, err);
	if (retptr == NULL)
		OTELC_RETURN_PTR(retptr);

	/* Populate the new scope context and insert it into the list. */
	retptr->id          = id;
	retptr->id_len      = id_len;
	retptr->smp_opt_dir = dir;
	LIST_INSERT(&(rt_ctx->contexts), &(retptr->list));

	FLT_OTEL_DBG_SCOPE_CONTEXT("new context ", retptr);

	OTELC_RETURN_PTR(retptr);
}


/***
 * NAME
 *   flt_otel_scope_context_free - scope context cleanup
 *
 * SYNOPSIS
 *   void flt_otel_scope_context_free(struct flt_otel_scope_context **ptr)
 *
 * ARGUMENTS
 *   ptr - pointer to the scope context pointer to free
 *
 * DESCRIPTION
 *   Frees a scope context entry pointed to by <ptr>.  It destroys the
 *   underlying OTel span context, removes the entry from its list, and
 *   returns the pool memory.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_scope_context_free(struct flt_otel_scope_context **ptr)
{
	OTELC_FUNC("%p:%p", OTELC_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		OTELC_RETURN();

	FLT_OTEL_DBG_SCOPE_CONTEXT("", *ptr);

	if ((*ptr)->context != NULL)
		OTELC_OPSR((*ptr)->context, destroy);

	FLT_OTEL_LIST_DEL(&((*ptr)->list));
	flt_otel_pool_free(pool_head_otel_scope_context, (void **)ptr);

	OTELC_RETURN();
}


#ifdef DEBUG_OTEL

/***
 * NAME
 *   flt_otel_scope_data_dump - debug scope data dump
 *
 * SYNOPSIS
 *   void flt_otel_scope_data_dump(const struct flt_otel_scope_data *data)
 *
 * ARGUMENTS
 *   data - the scope data structure to dump
 *
 * DESCRIPTION
 *   Dumps the contents of a scope <data> structure for debugging: baggage
 *   key-value pairs, attributes, events with their attributes, span links,
 *   and the status code/description.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_scope_data_dump(const struct flt_otel_scope_data *data)
{
	size_t i;

	if (data == NULL)
		return;

	if (data->baggage.attr == NULL) {
		OTELC_DBG(WORKER, "baggage %p:{ }", &(data->baggage));
	} else {
		OTELC_DBG(WORKER, "baggage %p:{", &(data->baggage));
		for (i = 0; i < data->baggage.cnt; i++)
			OTELC_DBG_KV(WORKER, "  ", data->baggage.attr + i);
		OTELC_DBG(WORKER, "}");
	}

	if (data->attributes.attr == NULL) {
		OTELC_DBG(WORKER, "attributes %p:{ }", &(data->attributes));
	} else {
		OTELC_DBG(WORKER, "attributes %p:{", &(data->attributes));
		for (i = 0; i < data->attributes.cnt; i++)
			OTELC_DBG_KV(WORKER, "  ", data->attributes.attr + i);
		OTELC_DBG(WORKER, "}");
	}

	if (LIST_ISEMPTY(&(data->events))) {
		OTELC_DBG(WORKER, "events %p:{ }", &(data->events));
	} else {
		struct flt_otel_scope_data_event *event;

		OTELC_DBG(WORKER, "events %p:{", &(data->events));
		list_for_each_entry_rev(event, &(data->events), list) {
			OTELC_DBG(WORKER, "  '%s' %zu/%zu", event->name, event->cnt, event->size);
			if (event->attr != NULL)
				for (i = 0; i < event->cnt; i++)
					OTELC_DBG_KV(WORKER, "  ", event->attr + i);
		}
		OTELC_DBG(WORKER, "}");
	}

	if ((data->status.code == 0) && (data->status.description == NULL))
		OTELC_DBG(WORKER, "status %p:{ }", &(data->status));
	else
		FLT_OTEL_DBG_SCOPE_DATA_STATUS("status ", &(data->status));
}

#endif /* DEBUG_OTEL */


/***
 * NAME
 *   flt_otel_scope_data_init - scope data zero-initialization
 *
 * SYNOPSIS
 *   void flt_otel_scope_data_init(struct flt_otel_scope_data *ptr)
 *
 * ARGUMENTS
 *   ptr - the scope data structure to initialize
 *
 * DESCRIPTION
 *   Zero-initializes the scope data structure pointed to by <ptr> and sets up
 *   the event and link list heads.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_scope_data_init(struct flt_otel_scope_data *ptr)
{
	OTELC_FUNC("%p", ptr);

	if (ptr == NULL)
		OTELC_RETURN();

	(void)memset(ptr, 0, sizeof(*ptr));
	LIST_INIT(&(ptr->events));

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_scope_data_free - scope data cleanup
 *
 * SYNOPSIS
 *   void flt_otel_scope_data_free(struct flt_otel_scope_data *ptr)
 *
 * ARGUMENTS
 *   ptr - the scope data structure to free
 *
 * DESCRIPTION
 *   Frees all contents of the scope data structure pointed to by <ptr>: baggage
 *   and attribute key-value arrays, event entries with their attributes, link
 *   entries, and the status description string.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_scope_data_free(struct flt_otel_scope_data *ptr)
{
	struct flt_otel_scope_data_event *event, *event_back;

	OTELC_FUNC("%p", ptr);

	if (ptr == NULL)
		OTELC_RETURN();

	FLT_OTEL_DBG_SCOPE_DATA("", ptr);

	/* Destroy all dynamic scope data contents. */
	otelc_kv_destroy(&(ptr->baggage.attr), ptr->baggage.cnt);
	otelc_kv_destroy(&(ptr->attributes.attr), ptr->attributes.cnt);
	list_for_each_entry_safe(event, event_back, &(ptr->events), list) {
		otelc_kv_destroy(&(event->attr), event->cnt);
		OTELC_SFREE(event->name);
		OTELC_SFREE(event);
	}
	OTELC_SFREE(ptr->status.description);

	(void)memset(ptr, 0, sizeof(*ptr));

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_scope_finish_mark - mark spans and contexts for finishing
 *
 * SYNOPSIS
 *   int flt_otel_scope_finish_mark(const struct flt_otel_runtime_context *rt_ctx, const char *id, size_t id_len)
 *
 * ARGUMENTS
 *   rt_ctx - the runtime context containing spans and contexts
 *   id     - the target name, or a wildcard ("*", "*req*", "*res*")
 *   id_len - length of the <id> string
 *
 * DESCRIPTION
 *   Marks spans and contexts for finishing.  The <id> argument supports
 *   wildcards: "*" marks all spans and contexts, "*req*" marks the request
 *   channel only, "*res*" marks the response channel only.  Otherwise, a named
 *   span or context is looked up by exact match.
 *
 * RETURN VALUE
 *   Returns the number of spans and contexts that were marked.
 */
int flt_otel_scope_finish_mark(const struct flt_otel_runtime_context *rt_ctx, const char *id, size_t id_len)
{
	struct flt_otel_scope_span    *span;
	struct flt_otel_scope_context *ctx;
	int                            span_cnt = 0, ctx_cnt = 0, retval;

	OTELC_FUNC("%p, \"%s\", %zu", rt_ctx, OTELC_STR_ARG(id), id_len);

	/* Handle wildcard finish marks: all, request-only, response-only. */
	if (FLT_OTEL_STR_CMP(FLT_OTEL_SCOPE_SPAN_FINISH_ALL, id)) {
		list_for_each_entry(span, &(rt_ctx->spans), list) {
			span->flag_finish = 1;
			span_cnt++;
		}

		list_for_each_entry(ctx, &(rt_ctx->contexts), list) {
			ctx->flag_finish = 1;
			ctx_cnt++;
		}

		OTELC_DBG(NOTICE, "marked %d span(s), %d context(s)", span_cnt, ctx_cnt);
	}
	else if (FLT_OTEL_STR_CMP(FLT_OTEL_SCOPE_SPAN_FINISH_REQ, id)) {
		list_for_each_entry(span, &(rt_ctx->spans), list)
			if (span->smp_opt_dir == SMP_OPT_DIR_REQ) {
				span->flag_finish = 1;
				span_cnt++;
			}

		list_for_each_entry(ctx, &(rt_ctx->contexts), list)
			if (ctx->smp_opt_dir == SMP_OPT_DIR_REQ) {
				ctx->flag_finish = 1;
				ctx_cnt++;
			}

		OTELC_DBG(NOTICE, "marked REQuest channel %d span(s), %d context(s)", span_cnt, ctx_cnt);
	}
	else if (FLT_OTEL_STR_CMP(FLT_OTEL_SCOPE_SPAN_FINISH_RES, id)) {
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

		OTELC_DBG(NOTICE, "marked RESponse channel %d span(s), %d context(s)", span_cnt, ctx_cnt);
	}
	else {
		list_for_each_entry(span, &(rt_ctx->spans), list)
			if (FLT_OTEL_CONF_STR_CMP(span->id, id)) {
				span->flag_finish = 1;
				span_cnt++;

				break;
			}

		list_for_each_entry(ctx, &(rt_ctx->contexts), list)
			if (FLT_OTEL_CONF_STR_CMP(ctx->id, id)) {
				ctx->flag_finish = 1;
				ctx_cnt++;

				break;
			}

		if (span_cnt > 0)
			OTELC_DBG(NOTICE, "marked span '%s'", id);
		if (ctx_cnt > 0)
			OTELC_DBG(NOTICE, "marked context '%s'", id);
		if ((span_cnt + ctx_cnt) == 0)
			OTELC_DBG(NOTICE, "cannot find span/context '%s'", id);
	}

	retval = span_cnt + ctx_cnt;

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_scope_finish_marked - finish marked spans and contexts
 *
 * SYNOPSIS
 *   void flt_otel_scope_finish_marked(const struct flt_otel_runtime_context *rt_ctx, const struct timespec *ts_finish)
 *
 * ARGUMENTS
 *   rt_ctx    - the runtime context containing spans and contexts
 *   ts_finish - the monotonic timestamp to use as the span end time
 *
 * DESCRIPTION
 *   Ends all spans and destroys all contexts that have been marked for
 *   finishing by flt_otel_scope_finish_mark().  Each span is ended with the
 *   <ts_finish> timestamp; each context's OTel span context is destroyed.
 *   The finish flags are cleared after processing.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_scope_finish_marked(const struct flt_otel_runtime_context *rt_ctx, const struct timespec *ts_finish)
{
	struct flt_otel_scope_span    *span;
	struct flt_otel_scope_context *ctx;

	OTELC_FUNC("%p, %p", rt_ctx, ts_finish);

	/* End all spans that have been marked for finishing. */
	list_for_each_entry(span, &(rt_ctx->spans), list)
		if (span->flag_finish) {
			FLT_OTEL_DBG_SCOPE_SPAN("finishing span ", span);

			OTELC_OPSR(span->span, end_with_options, ts_finish, OTELC_SPAN_STATUS_IGNORE, NULL);

			span->flag_finish = 0;
		}

	/* Destroy all contexts that have been marked for finishing. */
	list_for_each_entry(ctx, &(rt_ctx->contexts), list)
		if (ctx->flag_finish) {
			FLT_OTEL_DBG_SCOPE_CONTEXT("finishing context ", ctx);

			if (ctx->context != NULL)
				OTELC_OPSR(ctx->context, destroy);

			ctx->flag_finish = 0;
		}

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_scope_free_unused - remove unused spans and contexts
 *
 * SYNOPSIS
 *   void flt_otel_scope_free_unused(struct flt_otel_runtime_context *rt_ctx, struct channel *chn)
 *
 * ARGUMENTS
 *   rt_ctx - the runtime context to clean up
 *   chn    - the channel for HTTP header cleanup
 *
 * DESCRIPTION
 *   Removes scope spans with a NULL OTel span and scope contexts with a NULL
 *   OTel context from the runtime context.  For each removed context, the
 *   associated HTTP headers are also cleaned up via <chn>.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_scope_free_unused(struct flt_otel_runtime_context *rt_ctx, struct channel *chn)
{
	OTELC_FUNC("%p, %p", rt_ctx, chn);

	if (rt_ctx == NULL)
		OTELC_RETURN();

	/* Remove spans that were never successfully created. */
	if (!LIST_ISEMPTY(&(rt_ctx->spans))) {
		struct flt_otel_scope_span *span, *span_back;

		list_for_each_entry_safe(span, span_back, &(rt_ctx->spans), list)
			if (span->span == NULL)
				flt_otel_scope_span_free(&span);
	}

	FLT_OTEL_DBG_RUNTIME_CONTEXT("session context: ", rt_ctx);

	OTELC_RETURN();
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
