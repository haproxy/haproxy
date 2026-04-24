/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../include/include.h"


#ifdef DEBUG_OTEL

/***
 * NAME
 *   flt_otel_http_headers_dump - debug HTTP headers dump
 *
 * SYNOPSIS
 *   void flt_otel_http_headers_dump(const struct channel *chn)
 *
 * ARGUMENTS
 *   chn - channel to dump HTTP headers from
 *
 * DESCRIPTION
 *   Dumps all HTTP headers from the channel's HTX buffer.  Iterates over HTX
 *   blocks, logging each header name-value pair at NOTICE level.  Processing
 *   stops at the end-of-headers marker.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_http_headers_dump(const struct channel *chn)
{
	const struct htx *htx;
	int32_t           pos;

	OTELC_FUNC("%p", chn);

	if (chn == NULL)
		OTELC_RETURN();

	htx = htxbuf(&(chn->buf));

	if (htx_is_empty(htx))
		OTELC_RETURN();

	/* Walk HTX blocks and log each header until end-of-headers. */
	for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_blk    *blk  = htx_get_blk(htx, pos);
		enum htx_blk_type  type = htx_get_blk_type(blk);

		if (type == HTX_BLK_HDR) {
			struct ist n = htx_get_blk_name(htx, blk);
			struct ist v = htx_get_blk_value(htx, blk);

			OTELC_DBG(NOTICE, "'%.*s: %.*s'", (int)n.len, n.ptr, (int)v.len, v.ptr);
		}
		else if (type == HTX_BLK_EOH)
			break;
	}

	OTELC_RETURN();
}

#endif /* DEBUG_OTEL */


/***
 * NAME
 *   flt_otel_http_headers_get - HTTP header extraction to text map
 *
 * SYNOPSIS
 *   struct otelc_text_map *flt_otel_http_headers_get(struct channel *chn, const char *prefix, size_t len, char **err)
 *
 * ARGUMENTS
 *   chn    - channel containing HTTP headers
 *   prefix - header name prefix to match (or NULL for all)
 *   len    - length of the prefix string
 *   err    - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Extracts HTTP headers matching a <prefix> from the channel's HTX buffer
 *   into a newly allocated text map.  When <prefix> is NULL or its length is
 *   zero, all headers are extracted.  If the prefix starts with
 *   FLT_OTEL_PARSE_CTX_IGNORE_NAME, prefix matching is bypassed.  The prefix
 *   (including the separator dash) is stripped from header names before storing
 *   in the text map.  Empty header values are replaced with an empty string to
 *   avoid misinterpretation by otelc_text_map_add().  This function is used by
 *   the "extract" keyword to read span context from incoming request headers.
 *
 * RETURN VALUE
 *   Returns a pointer to the populated text map, or NULL on failure or when
 *   no matching headers are found.
 */
struct otelc_text_map *flt_otel_http_headers_get(struct channel *chn, const char *prefix, size_t len, char **err)
{
	const struct htx    *htx;
	size_t               prefix_len = (!OTELC_STR_IS_VALID(prefix) || (len == 0)) ? 0 : (len + 1);
	int32_t              pos;
	struct otelc_text_map *retptr = NULL;

	OTELC_FUNC("%p, \"%s\", %zu, %p:%p", chn, OTELC_STR_ARG(prefix), len, OTELC_DPTR_ARGS(err));

	if (chn == NULL)
		OTELC_RETURN_PTR(retptr);

	/*
	 * The keyword 'inject' allows you to define the name of the OpenTelemetry
	 * context without using a prefix.  In that case all HTTP headers are
	 * transferred because it is not possible to separate them from the
	 * OpenTelemetry context (this separation is usually done via a prefix).
	 *
	 * When using the 'extract' keyword, the context name must be specified.
	 * To allow all HTTP headers to be extracted, the first character of
	 * that name must be set to FLT_OTEL_PARSE_CTX_IGNORE_NAME.
	 */
	if (OTELC_STR_IS_VALID(prefix) && (*prefix == FLT_OTEL_PARSE_CTX_IGNORE_NAME))
		prefix_len = 0;

	htx = htxbuf(&(chn->buf));

	for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_blk    *blk  = htx_get_blk(htx, pos);
		enum htx_blk_type  type = htx_get_blk_type(blk);

		if (type == HTX_BLK_HDR) {
			struct ist v, n = htx_get_blk_name(htx, blk);

			if ((prefix_len == 0) || ((n.len >= prefix_len) && (strncasecmp(n.ptr, prefix, len) == 0))) {
				if (retptr == NULL) {
					retptr = OTELC_TEXT_MAP_NEW(NULL, 8);
					if (retptr == NULL) {
						FLT_OTEL_ERR("failed to create HTTP header data");

						break;
					}
				}

				v = htx_get_blk_value(htx, blk);

				/*
				 * In case the data of the HTTP header is not
				 * specified, v.ptr will have some non-null
				 * value and v.len will be equal to 0.  The
				 * otelc_text_map_add() function will not
				 * interpret this well.  In this case v.ptr
				 * is set to an empty string.
				 */
				if (v.len == 0)
					v = ist("");

				/*
				 * Here, an HTTP header (which is actually part
				 * of the span context) is added to the text_map.
				 *
				 * Before adding, the prefix is removed from the
				 * HTTP header name.
				 */
				if (OTELC_TEXT_MAP_ADD(retptr, n.ptr + prefix_len, n.len - prefix_len, v.ptr, v.len, OTELC_TEXT_MAP_AUTO) == -1) {
					FLT_OTEL_ERR("failed to add HTTP header data");

					otelc_text_map_destroy(&retptr);

					break;
				}
			}
		}
		else if (type == HTX_BLK_EOH)
			break;
	}

	OTELC_TEXT_MAP_DUMP(retptr, "extracted HTTP headers");

	if ((retptr != NULL) && (retptr->count == 0)) {
		OTELC_DBG(NOTICE, "WARNING: no HTTP headers found");

		otelc_text_map_destroy(&retptr);
	}

	OTELC_RETURN_PTR(retptr);
}


/***
 * NAME
 *   flt_otel_http_header_set - HTTP header set or remove
 *
 * SYNOPSIS
 *   int flt_otel_http_header_set(struct channel *chn, const char *prefix, const char *name, const char *value, char **err)
 *
 * ARGUMENTS
 *   chn    - channel containing HTTP headers
 *   prefix - header name prefix (or NULL)
 *   name   - header name suffix (or NULL)
 *   value  - header value to set (or NULL to remove only)
 *   err    - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Sets or removes an HTTP header in the channel's HTX buffer.  The full
 *   header name is constructed by combining <prefix> and <name> with a dash
 *   separator; if only one is provided, it is used directly.  All existing
 *   occurrences of the header are removed first.  If <name> is NULL, all
 *   headers starting with <prefix> are removed.  If <value> is non-NULL, the
 *   header is then added with the new value.  A NULL <value> causes only the
 *   removal, with no subsequent addition.
 *
 * RETURN VALUE
 *   Returns 0 on success, or FLT_OTEL_RET_ERROR on failure.
 */
int flt_otel_http_header_set(struct channel *chn, const char *prefix, const char *name, const char *value, char **err)
{
	struct http_hdr_ctx  ctx = { .blk = NULL };
	struct ist           ist_name;
	struct buffer       *buffer = NULL;
	struct htx          *htx;
	int                  retval = FLT_OTEL_RET_ERROR;

	OTELC_FUNC("%p, \"%s\", \"%s\", \"%s\", %p:%p", chn, OTELC_STR_ARG(prefix), OTELC_STR_ARG(name), OTELC_STR_ARG(value), OTELC_DPTR_ARGS(err));

	if ((chn == NULL) || (!OTELC_STR_IS_VALID(prefix) && !OTELC_STR_IS_VALID(name)))
		OTELC_RETURN_INT(retval);

	htx = htxbuf(&(chn->buf));

	/*
	 * Very rare (about 1% of cases), htx is empty.
	 * In order to avoid segmentation fault, we exit this function.
	 */
	if (htx_is_empty(htx)) {
		FLT_OTEL_ERR("HTX is empty");

		OTELC_RETURN_INT(retval);
	}

	if (!OTELC_STR_IS_VALID(prefix)) {
		ist_name = ist2((char *)name, strlen(name));
	}
	else if (!OTELC_STR_IS_VALID(name)) {
		ist_name = ist2((char *)prefix, strlen(prefix));
	}
	else {
		buffer = flt_otel_trash_alloc(0, err);
		if (buffer == NULL)
			OTELC_RETURN_INT(retval);

		(void)chunk_printf(buffer, "%s-%s", prefix, name);

		ist_name = ist2(buffer->area, buffer->data);
	}

	/* Remove all occurrences of the header. */
	while (http_find_header(htx, ist(""), &ctx, 1) == 1) {
		struct ist n = htx_get_blk_name(htx, ctx.blk);
#ifdef DEBUG_OTEL
		struct ist v = htx_get_blk_value(htx, ctx.blk);
#endif

		/*
		 * If the <name> parameter is not set, then remove all headers
		 * that start with the contents of the <prefix> parameter.
		 */
		if (!OTELC_STR_IS_VALID(name))
			n.len = ist_name.len;

		if (isteqi(n, ist_name))
			if (http_remove_header(htx, &ctx) == 1)
				OTELC_DBG(DEBUG, "HTTP header '%.*s: %.*s' removed", (int)n.len, n.ptr, (int)v.len, v.ptr);
	}

	/*
	 * If the value pointer has a value of NULL, the HTTP header is not set
	 * after deletion.
	 */
	if (value == NULL) {
		retval = 0;
	}
	else if (http_add_header(htx, ist_name, ist(value), 1) == 1) {
		retval = 0;

		OTELC_DBG(DEBUG, "HTTP header '%s: %s' added", ist_name.ptr, value);
	}
	else {
		FLT_OTEL_ERR("failed to set HTTP header '%s: %s'", ist_name.ptr, value);
	}

	flt_otel_trash_free(&buffer);

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_http_headers_remove - HTTP headers removal by prefix
 *
 * SYNOPSIS
 *   int flt_otel_http_headers_remove(struct channel *chn, const char *prefix, char **err)
 *
 * ARGUMENTS
 *   chn    - channel containing HTTP headers
 *   prefix - header name prefix to match for removal
 *   err    - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Removes all HTTP headers matching the given <prefix> from the channel's HTX
 *   buffer.  This is a convenience wrapper around flt_otel_http_header_set()
 *   with NULL <name> and <value> arguments.
 *
 * RETURN VALUE
 *   Returns 0 on success, or FLT_OTEL_RET_ERROR on failure.
 */
int flt_otel_http_headers_remove(struct channel *chn, const char *prefix, char **err)
{
	int retval;

	OTELC_FUNC("%p, \"%s\", %p:%p", chn, OTELC_STR_ARG(prefix), OTELC_DPTR_ARGS(err));

	retval = flt_otel_http_header_set(chn, prefix, NULL, NULL, err);

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
