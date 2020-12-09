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


static struct pool_head *pool_head_ot_span_context = NULL;

#ifdef USE_POOL_OT_SPAN_CONTEXT
REGISTER_POOL(&pool_head_ot_span_context, "ot_span_context", MAX(sizeof(struct otc_span), sizeof(struct otc_span_context)));
#endif


#ifdef DEBUG_OT

/***
 * NAME
 *   ot_text_map_show -
 *
 * ARGUMENTS
 *   text_map -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void ot_text_map_show(const struct otc_text_map *text_map)
{
	FLT_OT_FUNC("%p", text_map);

	if (text_map == NULL)
		FLT_OT_RETURN();

	FLT_OT_DBG_TEXT_MAP(text_map);

	if ((text_map->key != NULL) && (text_map->value != NULL) && (text_map->count > 0)) {
		size_t i;

		for (i = 0; i < text_map->count; i++)
			FLT_OT_DBG(3, "  \"%s\" -> \"%s\"", text_map->key[i], text_map->value[i]);
	}

	FLT_OT_RETURN();
}


/***
 * NAME
 *   ot_debug -
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
void ot_debug(void)
{
	char buffer[BUFSIZ];

	FLT_OT_FUNC("");

	otc_statistics(buffer, sizeof(buffer));
	FLT_OT_DBG(0, "%s", buffer);

	FLT_OT_RETURN();
}

#endif /* DEBUG_OT */


/***
 * NAME
 *   ot_mem_malloc -
 *
 * ARGUMENTS
 *   func -
 *   line -
 *   size -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static void *ot_mem_malloc(FLT_OT_DBG_ARGS(const char *func, int line, ) size_t size)
{
	return flt_ot_pool_alloc(pool_head_ot_span_context, size, 1, NULL);
}


/***
 * NAME
 *   ot_mem_free -
 *
 * ARGUMENTS
 *   func -
 *   line -
 *   ptr  -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void ot_mem_free(FLT_OT_DBG_ARGS(const char *func, int line, ) void *ptr)
{
	flt_ot_pool_free(pool_head_ot_span_context, &ptr);
}


/***
 * NAME
 *   ot_init -
 *
 * ARGUMENTS
 *   tracer -
 *   config -
 *   plugin -
 *   err    -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int ot_init(struct otc_tracer **tracer, const char *config, const char *plugin, char **err)
{
	char cwd[PATH_MAX], path[PATH_MAX], errbuf[BUFSIZ] = "";
	int  rc, retval = -1;

	FLT_OT_FUNC("%p:%p \"%s\", \"%s\", %p:%p", FLT_OT_DPTR_ARGS(tracer), config, plugin, FLT_OT_DPTR_ARGS(err));

	flt_ot_pools_info();
#ifdef USE_POOL_OT_SPAN_CONTEXT
	FLT_OT_DBG(2, "sizeof_pool(ot_span_context) = %u", pool_head_ot_span_context->size);
#endif

	if (getcwd(cwd, sizeof(cwd)) == NULL) {
		FLT_OT_ERR("failed to get current working directory");

		FLT_OT_RETURN(retval);
	}
	rc = snprintf(path, sizeof(path), "%s/%s", cwd, plugin);
	if ((rc == -1) || (rc >= sizeof(path))) {
		FLT_OT_ERR("failed to construct the OpenTracing plugin path");

		FLT_OT_RETURN(retval);
	}

	*tracer = otc_tracer_init(path, config, NULL, errbuf, sizeof(errbuf));
	if (*tracer == NULL) {
		FLT_OT_ERR("%s", (*errbuf == '\0') ? "failed to initialize tracing library" : errbuf);
	} else {
		otc_ext_init(ot_mem_malloc, ot_mem_free);

		retval = 0;
	}

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   ot_close -
 *
 * ARGUMENTS
 *   tracer -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void ot_close(struct otc_tracer **tracer)
{
	FLT_OT_FUNC("%p:%p", FLT_OT_DPTR_ARGS(tracer));

	if ((tracer == NULL) || (*tracer == NULL))
		FLT_OT_RETURN();

	(*tracer)->close(*tracer);

	*tracer = NULL;

	FLT_OT_RETURN();
}


/***
 * NAME
 *   ot_span_init -
 *
 * ARGUMENTS
 *   tracer         -
 *   operation_name -
 *   ts_steady      -
 *   ts_system      -
 *   ref_type       -
 *   ref_ctx_idx    -
 *   ref_span       -
 *   tags           -
 *   num_tags       -
 *   err            -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct otc_span *ot_span_init(struct otc_tracer *tracer, const char *operation_name, const struct timespec *ts_steady, const struct timespec *ts_system, int ref_type, int ref_ctx_idx, const struct otc_span *ref_span, const struct otc_tag *tags, int num_tags, char **err)
{
	struct otc_start_span_options  options;
	struct otc_span_context        context = { .idx = ref_ctx_idx, .span = ref_span };
	struct otc_span_reference      references = { ref_type, &context };
	struct otc_span               *retptr = NULL;

	FLT_OT_FUNC("%p, \"%s\", %p, %p, %d, %d, %p, %p, %d, %p:%p", tracer, operation_name, ts_steady, ts_system, ref_type, ref_ctx_idx, ref_span, tags, num_tags, FLT_OT_DPTR_ARGS(err));

	if (operation_name == NULL)
		FLT_OT_RETURN(retptr);
	else if (tracer == NULL)
		FLT_OT_RETURN(retptr);

	(void)memset(&options, 0, sizeof(options));

	if (ts_steady != NULL)
		(void)memcpy(&(options.start_time_steady.value), ts_steady, sizeof(options.start_time_steady.value));

	if (ts_system != NULL)
		(void)memcpy(&(options.start_time_system.value), ts_system, sizeof(options.start_time_system.value));

	if (FLT_OT_IN_RANGE(ref_type, otc_span_reference_child_of, otc_span_reference_follows_from)) {
		options.references     = &references;
		options.num_references = 1;
	}

	options.tags     = tags;
	options.num_tags = num_tags;

	retptr = tracer->start_span_with_options(tracer, operation_name, &options);
	if (retptr == NULL)
		FLT_OT_ERR("failed to init new span");
	else
		FLT_OT_DBG(2, "span %p:%zd initialized", retptr, retptr->idx);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   ot_span_init_va -
 *
 * ARGUMENTS
 *   tracer         -
 *   operation_name -
 *   ts_steady      -
 *   ts_system      -
 *   ref_type       -
 *   ref_ctx_idx    -
 *   ref_span       -
 *   err            -
 *   tag_key        -
 *   tag_value      -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct otc_span *ot_span_init_va(struct otc_tracer *tracer, const char *operation_name, const struct timespec *ts_steady, const struct timespec *ts_system, int ref_type, int ref_ctx_idx, const struct otc_span *ref_span, char **err, const char *tag_key, const char *tag_value, ...)
{
	struct otc_tag   tags[FLT_OT_MAXTAGS];
	int              num_tags = 0;
	struct otc_span *retptr;

	FLT_OT_FUNC("%p, \"%s\", %p, %p, %d, %d, %p, %p:%p, \"%s\", \"%s\", ...", tracer, operation_name, ts_steady, ts_system, ref_type, ref_ctx_idx, ref_span, FLT_OT_DPTR_ARGS(err), tag_key, tag_value);

	if (tag_key != NULL) {
		va_list ap;

		va_start(ap, tag_value);
		for (num_tags = 0; (num_tags < FLT_OT_TABLESIZE(tags)) && (tag_key != NULL) && (tag_value != NULL); num_tags++) {
			tags[num_tags].key = (char *)tag_key;
			FLT_OT_VSET(&(tags[num_tags].value), string, tag_value);

			tag_key = va_arg(ap, typeof(tag_key));
			if (tag_key != NULL)
				tag_value = va_arg(ap, typeof(tag_value));
		}
		va_end(ap);
	}

	retptr = ot_span_init(tracer, operation_name, ts_steady, ts_system, ref_type, ref_ctx_idx, ref_span, tags, num_tags, err);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   ot_span_tag -
 *
 * ARGUMENTS
 *   span     -
 *   tags     -
 *   num_tags -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int ot_span_tag(struct otc_span *span, const struct otc_tag *tags, int num_tags)
{
	int retval = -1;

	FLT_OT_FUNC("%p, %p, %d", span, tags, num_tags);

	if ((span == NULL) || (tags == NULL))
		FLT_OT_RETURN(retval);

	for (retval = 0; retval < num_tags; retval++)
		span->set_tag(span, tags[retval].key, &(tags[retval].value));

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   ot_span_tag_va -
 *
 * ARGUMENTS
 *   span  -
 *   key   -
 *   type  -
 *   value -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int ot_span_tag_va(struct otc_span *span, const char *key, int type, ...)
{
	va_list          ap;
	struct otc_value ot_value;
	int              retval = -1;

	FLT_OT_FUNC("%p, \"%s\", %d, ...", span, key, type);

	if ((span == NULL) || (key == NULL))
		FLT_OT_RETURN(retval);

	va_start(ap, type);
	for (retval = 0; (key != NULL) && FLT_OT_IN_RANGE(type, otc_value_bool, otc_value_null); retval++) {
		ot_value.type = type;
		if (type == otc_value_bool)
			ot_value.value.bool_value = va_arg(ap, typeof(ot_value.value.bool_value));
		else if (type == otc_value_double)
			ot_value.value.double_value = va_arg(ap, typeof(ot_value.value.double_value));
		else if (type == otc_value_int64)
			ot_value.value.int64_value = va_arg(ap, typeof(ot_value.value.int64_value));
		else if (type == otc_value_uint64)
			ot_value.value.uint64_value = va_arg(ap, typeof(ot_value.value.uint64_value));
		else if (type == otc_value_string)
			ot_value.value.string_value = va_arg(ap, typeof(ot_value.value.string_value));
		else if (type == otc_value_null)
			ot_value.value.string_value = va_arg(ap, typeof(ot_value.value.string_value));
		span->set_tag(span, key, &ot_value);

		key = va_arg(ap, typeof(key));
		if (key != NULL)
			type = va_arg(ap, typeof(type));
	}
	va_end(ap);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   ot_span_log -
 *
 * ARGUMENTS
 *   span       -
 *   log_fields -
 *   num_fields -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int ot_span_log(struct otc_span *span, const struct otc_log_field *log_fields, int num_fields)
{
	int retval = -1;

	FLT_OT_FUNC("%p, %p, %d", span, log_fields, num_fields);

	if ((span == NULL) || (log_fields == NULL))
		FLT_OT_RETURN(retval);

	retval = MIN(OTC_MAXLOGFIELDS, num_fields);

	span->log_fields(span, log_fields, retval);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   ot_span_log_va -
 *
 * ARGUMENTS
 *   span  -
 *   key   -
 *   value -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int ot_span_log_va(struct otc_span *span, const char *key, const char *value, ...)
{
	va_list              ap;
	struct otc_log_field log_field[OTC_MAXLOGFIELDS];
	int                  retval = -1;

	FLT_OT_FUNC("%p, \"%s\", \"%s\", ...", span, key, value);

	if ((span == NULL) || (key == NULL) || (value == NULL))
		FLT_OT_RETURN(retval);

	va_start(ap, value);
	for (retval = 0; (retval < FLT_OT_TABLESIZE(log_field)) && (key != NULL); retval++) {
		log_field[retval].key                      = key;
		log_field[retval].value.type               = otc_value_string;
		log_field[retval].value.value.string_value = value;

		key = va_arg(ap, typeof(key));
		if (key != NULL)
			value = va_arg(ap, typeof(value));
	}
	va_end(ap);

	span->log_fields(span, log_field, retval);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   ot_span_log_fmt -
 *
 * ARGUMENTS
 *   span   -
 *   key    -
 *   format -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int ot_span_log_fmt(struct otc_span *span, const char *key, const char *format, ...)
{
	va_list ap;
	char    value[BUFSIZ];
	int     n;

	FLT_OT_FUNC("%p, \"%s\", \"%s\", ...", span, key, format);

	if ((span == NULL) || (key == NULL) || (format == NULL))
		FLT_OT_RETURN(-1);

	va_start(ap, format);
	n = vsnprintf(value, sizeof(value), format, ap);
	if (!FLT_OT_IN_RANGE(n, 0, sizeof(value) - 1)) {
		FLT_OT_DBG(2, "WARNING: log buffer too small (%d > %zu)", n, sizeof(value));

		FLT_OT_STR_ELLIPSIS(value, sizeof(value));
	}
	va_end(ap);

	FLT_OT_RETURN(ot_span_log_va(span, key, value, NULL));
}


/***
 * NAME
 *   ot_span_set_baggage -
 *
 * ARGUMENTS
 *   span    -
 *   baggage -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int ot_span_set_baggage(struct otc_span *span, const struct otc_text_map *baggage)
{
	size_t i;
	int    retval = -1;

	FLT_OT_FUNC("%p, %p", span, baggage);

	if ((span == NULL) || (baggage == NULL))
		FLT_OT_RETURN(retval);

	if ((baggage->key == NULL) || (baggage->value == NULL))
		FLT_OT_RETURN(retval);

	for (retval = i = 0; i < baggage->count; i++) {
		FLT_OT_DBG(3, "set baggage: \"%s\" -> \"%s\"", baggage->key[i], baggage->value[i]);

		if ((baggage->key[i] != NULL) && (baggage->value[i] != NULL)) {
			span->set_baggage_item(span, baggage->key[i], baggage->value[i]);

			retval++;
		}
	}

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   ot_span_set_baggage_va -
 *
 * ARGUMENTS
 *   span  -
 *   key   -
 *   value -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int ot_span_set_baggage_va(struct otc_span *span, const char *key, const char *value, ...)
{
	va_list ap;
	int     retval = -1;

	FLT_OT_FUNC("%p, \"%s\", \"%s\", ...", span, key, value);

	if ((span == NULL) || (key == NULL) || (value == NULL))
		FLT_OT_RETURN(retval);

	va_start(ap, value);
	for (retval = 0; (key != NULL); retval++) {
		FLT_OT_DBG(3, "set baggage: \"%s\" -> \"%s\"", key, value);

		span->set_baggage_item(span, key, value);

		key = va_arg(ap, typeof(key));
		if (key != NULL)
			value = va_arg(ap, typeof(value));
	}
	va_end(ap);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   ot_span_baggage_va -
 *
 * ARGUMENTS
 *   span -
 *   key  -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct otc_text_map *ot_span_baggage_va(const struct otc_span *span, const char *key, ...)
{
	va_list              ap;
	struct otc_text_map *retptr = NULL;
	int                  i, n;

	FLT_OT_FUNC("%p, \"%s\", ...", span, key);

	if ((span == NULL) || (key == NULL))
		FLT_OT_RETURN(retptr);

	va_start(ap, key);
	for (n = 1; va_arg(ap, typeof(key)) != NULL; n++);
	va_end(ap);

	retptr = otc_text_map_new(NULL, n);
	if (retptr == NULL)
		FLT_OT_RETURN(retptr);

	va_start(ap, key);
	for (i = 0; (i < n) && (key != NULL); i++) {
		char *value = (char *)span->baggage_item(span, key);

		if (value != NULL) {
			(void)otc_text_map_add(retptr, key, 0, value, 0, OTC_TEXT_MAP_DUP_KEY | OTC_TEXT_MAP_DUP_VALUE);

			FLT_OT_DBG(3, "get baggage[%d]: \"%s\" -> \"%s\"", i, retptr->key[i], retptr->value[i]);
		} else {
			FLT_OT_DBG(3, "get baggage[%d]: \"%s\" -> invalid key", i, key);
		}

		key = va_arg(ap, typeof(key));
	}
	va_end(ap);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   ot_inject_text_map -
 *
 * ARGUMENTS
 *   tracer  -
 *   span    -
 *   carrier -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct otc_span_context *ot_inject_text_map(struct otc_tracer *tracer, const struct otc_span *span, struct otc_text_map_writer *carrier)
{
	struct otc_span_context *retptr = NULL;
	int                      rc;

	FLT_OT_FUNC("%p, %p, %p", tracer, span, carrier);

	if ((span == NULL) || (carrier == NULL))
		FLT_OT_RETURN(retptr);
	else if (tracer == NULL)
		FLT_OT_RETURN(retptr);

	retptr = span->span_context((struct otc_span *)span);
	if (retptr == NULL)
		FLT_OT_RETURN(retptr);

	(void)memset(carrier, 0, sizeof(*carrier));

	rc = tracer->inject_text_map(tracer, carrier, retptr);
	if (rc != otc_propagation_error_code_success) {
		FLT_OT_FREE_CLEAR(retptr);
	} else {
#ifdef DEBUG_OT
		FLT_OT_DBG_TEXT_CARRIER(carrier, set);
		ot_text_map_show(&(carrier->text_map));
		FLT_OT_DBG_SPAN_CONTEXT(retptr);
#endif
	}

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   ot_inject_http_headers -
 *
 * ARGUMENTS
 *   tracer  -
 *   span    -
 *   carrier -
 *   err     -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct otc_span_context *ot_inject_http_headers(struct otc_tracer *tracer, const struct otc_span *span, struct otc_http_headers_writer *carrier, char **err)
{
	struct otc_span_context *retptr = NULL;
	int                      rc;

	FLT_OT_FUNC("%p, %p, %p, %p:%p", tracer, span, carrier, FLT_OT_DPTR_ARGS(err));

	if ((span == NULL) || (carrier == NULL))
		FLT_OT_RETURN(retptr);
	else if (tracer == NULL)
		FLT_OT_RETURN(retptr);

	retptr = span->span_context((struct otc_span *)span);
	if (retptr == NULL) {
		FLT_OT_ERR("failed to create span context");

		FLT_OT_RETURN(retptr);
	}

	(void)memset(carrier, 0, sizeof(*carrier));

	rc = tracer->inject_http_headers(tracer, carrier, retptr);
	if (rc != otc_propagation_error_code_success) {
		FLT_OT_ERR("failed to inject HTTP headers data");

		FLT_OT_FREE_CLEAR(retptr);
	} else {
#ifdef DEBUG_OT
		FLT_OT_DBG_TEXT_CARRIER(carrier, set);
		ot_text_map_show(&(carrier->text_map));
		FLT_OT_DBG_SPAN_CONTEXT(retptr);
#endif
	}

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   ot_inject_binary -
 *
 * ARGUMENTS
 *   tracer  -
 *   span    -
 *   carrier -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct otc_span_context *ot_inject_binary(struct otc_tracer *tracer, const struct otc_span *span, struct otc_custom_carrier_writer *carrier)
{
	struct otc_span_context *retptr = NULL;
	int                      rc;

	FLT_OT_FUNC("%p, %p, %p", tracer, span, carrier);

	if ((span == NULL) || (carrier == NULL))
		FLT_OT_RETURN(retptr);
	else if (tracer == NULL)
		FLT_OT_RETURN(retptr);

	retptr = span->span_context((struct otc_span *)span);
	if (retptr == NULL)
		FLT_OT_RETURN(retptr);

	(void)memset(carrier, 0, sizeof(*carrier));

	rc = tracer->inject_binary(tracer, carrier, retptr);
	if (rc != otc_propagation_error_code_success) {
		FLT_OT_FREE_CLEAR(retptr);
	} else {
#ifdef DEBUG_OT
		struct otc_jaeger_trace_context *ctx = carrier->binary_data.data;

		FLT_OT_DBG_CUSTOM_CARRIER(carrier, inject);
		FLT_OT_DBG(3, "trace context: %016" PRIx64 "%016" PRIx64 ":%016" PRIx64 ":%016" PRIx64 ":%02hhx <%s> <%s>",
		           ctx->trace_id[0], ctx->trace_id[1], ctx->span_id, ctx->parent_span_id, ctx->flags,
		           flt_ot_str_hex(ctx->baggage, carrier->binary_data.size - sizeof(*ctx)),
		           flt_ot_str_ctrl(ctx->baggage, carrier->binary_data.size - sizeof(*ctx)));
		FLT_OT_DBG_SPAN_CONTEXT(retptr);
#endif
	}

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   ot_extract_text_map -
 *
 * ARGUMENTS
 *   tracer   -
 *   carrier  -
 *   text_map -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct otc_span_context *ot_extract_text_map(struct otc_tracer *tracer, struct otc_text_map_reader *carrier, const struct otc_text_map *text_map)
{
	struct otc_span_context *retptr = NULL;
	int                      rc;

	FLT_OT_FUNC("%p, %p, %p", tracer, carrier, text_map);

	if (carrier == NULL)
		FLT_OT_RETURN(retptr);
	else if (tracer == NULL)
		FLT_OT_RETURN(retptr);

	if (text_map != NULL) {
		(void)memset(carrier, 0, sizeof(*carrier));
		(void)memcpy(&(carrier->text_map), text_map, sizeof(carrier->text_map));

		FLT_OT_DBG_TEXT_CARRIER(carrier, foreach_key);
	}

	rc = tracer->extract_text_map(tracer, carrier, &retptr);
	if (rc != otc_propagation_error_code_success)
		FLT_OT_FREE_CLEAR(retptr);
	else if (retptr != NULL)
		FLT_OT_DBG_SPAN_CONTEXT(retptr);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   ot_extract_http_headers -
 *
 * ARGUMENTS
 *   tracer   -
 *   carrier  -
 *   text_map -
 *   err      -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct otc_span_context *ot_extract_http_headers(struct otc_tracer *tracer, struct otc_http_headers_reader *carrier, const struct otc_text_map *text_map, char **err)
{
	struct otc_span_context *retptr = NULL;
	int                      rc;

	FLT_OT_FUNC("%p, %p, %p, %p:%p", tracer, carrier, text_map, FLT_OT_DPTR_ARGS(err));

	if (carrier == NULL)
		FLT_OT_RETURN(retptr);
	else if (tracer == NULL)
		FLT_OT_RETURN(retptr);

	if (text_map != NULL) {
		(void)memset(carrier, 0, sizeof(*carrier));
		(void)memcpy(&(carrier->text_map), text_map, sizeof(carrier->text_map));

		FLT_OT_DBG_TEXT_CARRIER(carrier, foreach_key);
	}

	rc = tracer->extract_http_headers(tracer, carrier, &retptr);
	if (rc != otc_propagation_error_code_success) {
		FLT_OT_ERR("failed to extract HTTP headers data");

		FLT_OT_FREE_CLEAR(retptr);
	}
	else if (retptr != NULL)
		FLT_OT_DBG_SPAN_CONTEXT(retptr);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   ot_extract_binary -
 *
 * ARGUMENTS
 *   tracer      -
 *   carrier     -
 *   binary_data -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct otc_span_context *ot_extract_binary(struct otc_tracer *tracer, struct otc_custom_carrier_reader *carrier, const struct otc_binary_data *binary_data)
{
	struct otc_span_context *retptr = NULL;
	int                      rc;

	FLT_OT_FUNC("%p, %p, %p", tracer, carrier, binary_data);

	if (carrier == NULL)
		FLT_OT_RETURN(retptr);
	else if (tracer == NULL)
		FLT_OT_RETURN(retptr);

	if ((FLT_OT_DEREF(binary_data, data, NULL) != NULL) && (binary_data->size > 0)) {
		(void)memset(carrier, 0, sizeof(*carrier));
		(void)memcpy(&(carrier->binary_data), binary_data, sizeof(carrier->binary_data));

		FLT_OT_DBG_CUSTOM_CARRIER(carrier, extract);
	}

	rc = tracer->extract_binary(tracer, carrier, &retptr);
	if (rc != otc_propagation_error_code_success)
		FLT_OT_FREE_CLEAR(retptr);
	else if (retptr != NULL)
		FLT_OT_DBG_SPAN_CONTEXT(retptr);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   ot_span_finish -
 *
 * ARGUMENTS
 *   span      -
 *   ts_finish -
 *   log_ts    -
 *   log_key   -
 *   log_value -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void ot_span_finish(struct otc_span **span, const struct timespec *ts_finish, const struct timespec *log_ts, const char *log_key, const char *log_value, ...)
{
	struct otc_finish_span_options options;
	struct otc_log_field           log_field[OTC_MAXLOGFIELDS];
	struct otc_log_record          log_records = { .fields = log_field, .num_fields = 0 };
#ifdef DEBUG_OT
	typeof((*span)->idx)           idx = FLT_OT_DDEREF(span, idx, 0);
#endif

	FLT_OT_FUNC("%p:%p, %p, %p, \"%s\", \"%s\", ...", FLT_OT_DPTR_ARGS(span), ts_finish, log_ts, log_key, log_value);

	if ((span == NULL) || (*span == NULL))
		FLT_OT_RETURN();

	(void)memset(&options, 0, sizeof(options));

	if (ts_finish != NULL)
		(void)memcpy(&(options.finish_time.value), ts_finish, sizeof(options.finish_time.value));

	if (log_key != NULL) {
		va_list ap;
		int     i;

		if (log_ts != NULL)
			(void)memcpy(&(log_records.timestamp.value), log_ts, sizeof(log_records.timestamp.value));

		va_start(ap, log_value);
		for (i = 0; (i < FLT_OT_TABLESIZE(log_field)) && (log_key != NULL); i++) {
			log_field[i].key                      = log_key;
			log_field[i].value.type               = otc_value_string;
			log_field[i].value.value.string_value = log_value;

			log_key = va_arg(ap, typeof(log_key));
			if (log_key != NULL)
				log_value = va_arg(ap, typeof(log_value));
		}
		va_end(ap);

		log_records.num_fields  = i;
		options.log_records     = &log_records;
		options.num_log_records = 1;
	}

	/*
	 * Caution: memory allocated for the span is released
	 *          in the function finish_with_options().
	 */
	(*span)->finish_with_options(*span, &options);

	FLT_OT_DBG(2, "span %p:%zu finished", *span, idx);

	*span = NULL;

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
