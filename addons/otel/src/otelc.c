/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../include/include.h"


/***
 * NAME
 *   flt_otel_text_map_writer_set_cb - text map injection writer callback
 *
 * SYNOPSIS
 *   static int flt_otel_text_map_writer_set_cb(struct otelc_text_map_writer *writer, const char *key, const char *value)
 *
 * ARGUMENTS
 *   writer - text map writer instance
 *   key    - context key name
 *   value  - context key value
 *
 * DESCRIPTION
 *   Writer callback for text map injection.  Called by the OTel C wrapper
 *   library during span context injection to store each key-value pair in the
 *   <writer>'s text map.
 *
 * RETURN VALUE
 *   Returns the result of OTELC_TEXT_MAP_ADD().
 */
static int flt_otel_text_map_writer_set_cb(struct otelc_text_map_writer *writer, const char *key, const char *value)
{
	OTELC_FUNC("%p, \"%s\", \"%s\"", writer, OTELC_STR_ARG(key), OTELC_STR_ARG(value));

	OTELC_RETURN_INT(OTELC_TEXT_MAP_ADD(&(writer->text_map), key, 0, value, 0, OTELC_TEXT_MAP_AUTO));
}


/***
 * NAME
 *   flt_otel_http_headers_writer_set_cb - HTTP headers injection writer callback
 *
 * SYNOPSIS
 *   static int flt_otel_http_headers_writer_set_cb(struct otelc_http_headers_writer *writer, const char *key, const char *value)
 *
 * ARGUMENTS
 *   writer - HTTP headers writer instance
 *   key    - context key name
 *   value  - context key value
 *
 * DESCRIPTION
 *   Writer callback for HTTP headers injection.  Called by the OTel C wrapper
 *   library during span context injection to store each key-value pair in the
 *   <writer>'s text map.
 *
 * RETURN VALUE
 *   Returns the result of OTELC_TEXT_MAP_ADD().
 */
static int flt_otel_http_headers_writer_set_cb(struct otelc_http_headers_writer *writer, const char *key, const char *value)
{
	OTELC_FUNC("%p, \"%s\", \"%s\"", writer, OTELC_STR_ARG(key), OTELC_STR_ARG(value));

	OTELC_RETURN_INT(OTELC_TEXT_MAP_ADD(&(writer->text_map), key, 0, value, 0, OTELC_TEXT_MAP_AUTO));
}


/***
 * NAME
 *   flt_otel_inject_text_map - text map context injection
 *
 * SYNOPSIS
 *   int flt_otel_inject_text_map(const struct otelc_span *span, struct otelc_text_map_writer *carrier)
 *
 * ARGUMENTS
 *   span    - span instance to inject context from
 *   carrier - text map writer carrier
 *
 * DESCRIPTION
 *   Injects the span context into a text map carrier.  Initializes the
 *   <carrier> structure, sets the writer callback to
 *   flt_otel_text_map_writer_set_cb(), and delegates to the <span>'s
 *   inject_text_map() method.
 *
 * RETURN VALUE
 *   Returns the result of the <span>'s inject_text_map() method,
 *   or FLT_OTEL_RET_ERROR if arguments are NULL.
 */
int flt_otel_inject_text_map(const struct otelc_span *span, struct otelc_text_map_writer *carrier)
{
	OTELC_FUNC("%p, %p", span, carrier);

	if ((span == NULL) || (carrier == NULL))
		OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);

	(void)memset(carrier, 0, sizeof(*carrier));
	carrier->set = flt_otel_text_map_writer_set_cb;

	OTELC_RETURN_INT(OTELC_OPS(span, inject_text_map, carrier));
}


/***
 * NAME
 *   flt_otel_inject_http_headers - HTTP headers context injection
 *
 * SYNOPSIS
 *   int flt_otel_inject_http_headers(const struct otelc_span *span, struct otelc_http_headers_writer *carrier)
 *
 * ARGUMENTS
 *   span    - span instance to inject context from
 *   carrier - HTTP headers writer carrier
 *
 * DESCRIPTION
 *   Injects the span context into an HTTP headers carrier.  Initializes the
 *   <carrier> structure, sets the writer callback to
 *   flt_otel_http_headers_writer_set_cb(), and delegates to the <span>'s
 *   inject_http_headers() method.
 *
 * RETURN VALUE
 *   Returns the result of the <span>'s inject_http_headers() method,
 *   or FLT_OTEL_RET_ERROR if arguments are NULL.
 */
int flt_otel_inject_http_headers(const struct otelc_span *span, struct otelc_http_headers_writer *carrier)
{
	OTELC_FUNC("%p, %p", span, carrier);

	if ((span == NULL) || (carrier == NULL))
		OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);

	(void)memset(carrier, 0, sizeof(*carrier));
	carrier->set = flt_otel_http_headers_writer_set_cb;

	OTELC_RETURN_INT(OTELC_OPS(span, inject_http_headers, carrier));
}


/***
 * NAME
 *   flt_otel_text_map_reader_foreach_key_cb - text map extraction reader callback
 *
 * SYNOPSIS
 *   static int flt_otel_text_map_reader_foreach_key_cb(const struct otelc_text_map_reader *reader, int (*handler)(void *arg, const char *key, const char *value), void *arg)
 *
 * ARGUMENTS
 *   reader  - text map reader instance
 *   handler - callback function invoked for each key-value pair
 *   arg     - opaque argument passed to the handler
 *
 * DESCRIPTION
 *   Reader callback for text map extraction.  Iterates over all key-value
 *   pairs in the <reader>'s text map and invokes <handler> for each.  Iteration
 *   stops if the <handler> returns -1.
 *
 * RETURN VALUE
 *   Returns the last <handler> return value, or 0 if the text map is empty.
 */
static int flt_otel_text_map_reader_foreach_key_cb(const struct otelc_text_map_reader *reader, int (*handler)(void *arg, const char *key, const char *value), void *arg)
{
	size_t i;
	int    retval = 0;

	OTELC_FUNC("%p, %p, %p", reader, handler, arg);

	for (i = 0; (retval != -1) && (i < reader->text_map.count); i++) {
		OTELC_DBG(OTELC, "\"%s\" -> \"%s\"", OTELC_STR_ARG(reader->text_map.key[i]), OTELC_STR_ARG(reader->text_map.value[i]));

		retval = handler(arg, reader->text_map.key[i], reader->text_map.value[i]);
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_http_headers_reader_foreach_key_cb - HTTP headers extraction reader callback
 *
 * SYNOPSIS
 *   static int flt_otel_http_headers_reader_foreach_key_cb(const struct otelc_http_headers_reader *reader, int (*handler)(void *arg, const char *key, const char *value), void *arg)
 *
 * ARGUMENTS
 *   reader  - HTTP headers reader instance
 *   handler - callback function invoked for each key-value pair
 *   arg     - opaque argument passed to the handler
 *
 * DESCRIPTION
 *   Reader callback for HTTP headers extraction.  Iterates over all key-value
 *   pairs in the <reader>'s text map and invokes <handler> for each.  Iteration
 *   stops if the <handler> returns -1.
 *
 * RETURN VALUE
 *   Returns the last <handler> return value, or 0 if the text map is empty.
 */
static int flt_otel_http_headers_reader_foreach_key_cb(const struct otelc_http_headers_reader *reader, int (*handler)(void *arg, const char *key, const char *value), void *arg)
{
	size_t i;
	int    retval = 0;

	OTELC_FUNC("%p, %p, %p", reader, handler, arg);

	for (i = 0; (retval != -1) && (i < reader->text_map.count); i++) {
		OTELC_DBG(OTELC, "\"%s\" -> \"%s\"", OTELC_STR_ARG(reader->text_map.key[i]), OTELC_STR_ARG(reader->text_map.value[i]));

		retval = handler(arg, reader->text_map.key[i], reader->text_map.value[i]);
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_extract_text_map - text map context extraction
 *
 * SYNOPSIS
 *   struct otelc_span_context *flt_otel_extract_text_map(struct otelc_tracer *tracer, struct otelc_text_map_reader *carrier, const struct otelc_text_map *text_map)
 *
 * ARGUMENTS
 *   tracer   - OTel tracer instance
 *   carrier  - text map reader carrier
 *   text_map - text map containing the context data (or NULL)
 *
 * DESCRIPTION
 *   Extracts a span context from a text map carrier via the <tracer>.
 *   Initializes the <carrier> structure, sets the foreach_key callback to
 *   flt_otel_text_map_reader_foreach_key_cb(), and copies the <text_map> data
 *   into the <carrier>.  Delegates to the <tracer>'s extract_text_map() method.
 *
 * RETURN VALUE
 *   Returns a pointer to the extracted span context, or NULL on failure.
 */
struct otelc_span_context *flt_otel_extract_text_map(struct otelc_tracer *tracer, struct otelc_text_map_reader *carrier, const struct otelc_text_map *text_map)
{
	OTELC_FUNC("%p, %p, %p", tracer, carrier, text_map);

	if ((tracer == NULL) || (carrier == NULL))
		OTELC_RETURN_PTR(NULL);

	(void)memset(carrier, 0, sizeof(*carrier));
	carrier->foreach_key = flt_otel_text_map_reader_foreach_key_cb;

	if (text_map != NULL)
		(void)memcpy(&(carrier->text_map), text_map, sizeof(carrier->text_map));

	OTELC_RETURN_PTR(OTELC_OPS(tracer, extract_text_map, carrier));
}


/***
 * NAME
 *   flt_otel_extract_http_headers - HTTP headers context extraction
 *
 * SYNOPSIS
 *   struct otelc_span_context *flt_otel_extract_http_headers(struct otelc_tracer *tracer, struct otelc_http_headers_reader *carrier, const struct otelc_text_map *text_map)
 *
 * ARGUMENTS
 *   tracer   - OTel tracer instance
 *   carrier  - HTTP headers reader carrier
 *   text_map - text map containing the context data (or NULL)
 *
 * DESCRIPTION
 *   Extracts a span context from an HTTP headers carrier via the <tracer>.
 *   Initializes the <carrier> structure, sets the foreach_key callback to
 *   flt_otel_http_headers_reader_foreach_key_cb(), and copies the <text_map>
 *   data into the <carrier>.  Delegates to the <tracer>'s
 *   extract_http_headers() method.
 *
 * RETURN VALUE
 *   Returns a pointer to the extracted span context, or NULL on failure.
 */
struct otelc_span_context *flt_otel_extract_http_headers(struct otelc_tracer *tracer, struct otelc_http_headers_reader *carrier, const struct otelc_text_map *text_map)
{
	OTELC_FUNC("%p, %p, %p", tracer, carrier, text_map);

	if ((tracer == NULL) || (carrier == NULL))
		OTELC_RETURN_PTR(NULL);

	(void)memset(carrier, 0, sizeof(*carrier));
	carrier->foreach_key = flt_otel_http_headers_reader_foreach_key_cb;

	if (text_map != NULL)
		(void)memcpy(&(carrier->text_map), text_map, sizeof(carrier->text_map));

	OTELC_RETURN_PTR(OTELC_OPS(tracer, extract_http_headers, carrier));
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
