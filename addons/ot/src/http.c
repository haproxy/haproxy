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


#ifdef DEBUG_OT

/***
 * NAME
 *   flt_ot_http_headers_dump -
 *
 * ARGUMENTS
 *   chn -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_http_headers_dump(const struct channel *chn)
{
	const struct htx *htx;
	int32_t           pos;

	FLT_OT_FUNC("%p", chn);

	if (chn == NULL)
		FLT_OT_RETURN();

	htx = htxbuf(&(chn->buf));

	if (htx_is_empty(htx))
		FLT_OT_RETURN();

	for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_blk    *blk  = htx_get_blk(htx, pos);
		enum htx_blk_type  type = htx_get_blk_type(blk);

		if (type == HTX_BLK_HDR) {
			struct ist n = htx_get_blk_name(htx, blk);
			struct ist v = htx_get_blk_value(htx, blk);

			FLT_OT_DBG(2, "'%.*s: %.*s'", (int)n.len, n.ptr, (int)v.len, v.ptr);
		}
		else if (type == HTX_BLK_EOH)
			break;
	}

	FLT_OT_RETURN();
}

#endif /* DEBUG_OT */


/***
 * NAME
 *   flt_ot_http_headers_get -
 *
 * ARGUMENTS
 *   chn    -
 *   prefix -
 *   len    -
 *   err    -
 *
 * DESCRIPTION
 *   This function is very similar to function http_action_set_header(), from
 *   the HAProxy source.
 *
 * RETURN VALUE
 *   -
 */
struct otc_text_map *flt_ot_http_headers_get(struct channel *chn, const char *prefix, size_t len, char **err)
{
	const struct htx    *htx;
	size_t               prefix_len = (!FLT_OT_STR_ISVALID(prefix) || (len == 0)) ? 0 : (len + 1);
	int32_t              pos;
	struct otc_text_map *retptr = NULL;

	FLT_OT_FUNC("%p, \"%s\", %zu, %p:%p", chn, prefix, len, FLT_OT_DPTR_ARGS(err));

	if (chn == NULL)
		FLT_OT_RETURN(retptr);

	htx = htxbuf(&(chn->buf));

	for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_blk    *blk  = htx_get_blk(htx, pos);
		enum htx_blk_type  type = htx_get_blk_type(blk);

		if (type == HTX_BLK_HDR) {
			struct ist v, n = htx_get_blk_name(htx, blk);

			if ((prefix_len == 0) || ((n.len >= prefix_len) && (strncasecmp(n.ptr, prefix, len) == 0))) {
				if (retptr == NULL) {
					retptr = otc_text_map_new(NULL, 8);
					if (retptr == NULL) {
						FLT_OT_ERR("failed to create HTTP header data");

						break;
					}
				}

				v = htx_get_blk_value(htx, blk);

				/*
				 * Here, an HTTP header (which is actually part
				 * of the span context is added to the text_map.
				 *
				 * Before adding, the prefix is removed from the
				 * HTTP header name.
				 */
				if (otc_text_map_add(retptr, n.ptr + prefix_len, n.len - prefix_len, v.ptr, v.len, OTC_TEXT_MAP_DUP_KEY | OTC_TEXT_MAP_DUP_VALUE) == -1) {
					FLT_OT_ERR("failed to add HTTP header data");

					otc_text_map_destroy(&retptr, OTC_TEXT_MAP_FREE_KEY | OTC_TEXT_MAP_FREE_VALUE);

					break;
				}
			}
		}
		else if (type == HTX_BLK_EOH)
			break;
	}

	ot_text_map_show(retptr);

	if ((retptr != NULL) && (retptr->count == 0)) {
		FLT_OT_DBG(2, "WARNING: no HTTP headers found");

		otc_text_map_destroy(&retptr, OTC_TEXT_MAP_FREE_KEY | OTC_TEXT_MAP_FREE_VALUE);
	}

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_http_header_set -
 *
 * ARGUMENTS
 *   chn    -
 *   prefix -
 *   name   -
 *   value  -
 *   err    -
 *
 * DESCRIPTION
 *   This function is very similar to function http_action_set_header(), from
 *   the HAProxy source.
 *
 * RETURN VALUE
 *   -
 */
int flt_ot_http_header_set(struct channel *chn, const char *prefix, const char *name, const char *value, char **err)
{
	struct http_hdr_ctx  ctx = { .blk = NULL };
	struct ist           ist_name;
	struct buffer       *buffer = NULL;
	struct htx          *htx;
	int                  retval = -1;

	FLT_OT_FUNC("%p, \"%s\", \"%s\", \"%s\", %p:%p", chn, prefix, name, value, FLT_OT_DPTR_ARGS(err));

	if ((chn == NULL) || (!FLT_OT_STR_ISVALID(prefix) && !FLT_OT_STR_ISVALID(name)))
		FLT_OT_RETURN(retval);

	htx = htxbuf(&(chn->buf));

	/*
	 * Very rare (about 1% of cases), htx is empty.
	 * In order to avoid segmentation fault, we exit this function.
	 */
	if (htx_is_empty(htx)) {
		FLT_OT_ERR("HTX is empty");

		FLT_OT_RETURN(retval);
	}

	if (!FLT_OT_STR_ISVALID(prefix)) {
		ist_name.ptr = (char *)name;
		ist_name.len = strlen(name);
	}
	else if (!FLT_OT_STR_ISVALID(name)) {
		ist_name.ptr = (char *)prefix;
		ist_name.len = strlen(prefix);
	}
	else {
		buffer = flt_ot_trash_alloc(0, err);
		if (buffer == NULL)
			FLT_OT_RETURN(retval);

		(void)chunk_printf(buffer, "%s-%s", prefix, name);

		ist_name.ptr = buffer->area;
		ist_name.len = buffer->data;
	}

	/* Remove all occurrences of the header. */
	while (http_find_header(htx, ist(""), &ctx, 1) == 1) {
		struct ist n = htx_get_blk_name(htx, ctx.blk);
#ifdef DEBUG_OT
		struct ist v = htx_get_blk_value(htx, ctx.blk);
#endif

		/*
		 * If the <name> parameter is not set, then remove all headers
		 * that start with the contents of the <prefix> parameter.
		 */
		if (!FLT_OT_STR_ISVALID(name))
			n.len = ist_name.len;

		if (isteqi(n, ist_name))
			if (http_remove_header(htx, &ctx) == 1)
				FLT_OT_DBG(3, "HTTP header '%.*s: %.*s' removed", (int)n.len, n.ptr, (int)v.len, v.ptr);
	}

	/*
	 * If the value pointer has a value of NULL, the HTTP header is not set
	 * after deletion.
	 */
	if (value == NULL) {
		/* Do nothing. */
	}
	else if (http_add_header(htx, ist_name, ist(value)) == 1) {
		retval = 0;

		FLT_OT_DBG(3, "HTTP header '%s: %s' added", ist_name.ptr, value);
	}
	else {
		FLT_OT_ERR("failed to set HTTP header '%s: %s'", ist_name.ptr, value);
	}

	flt_ot_trash_free(&buffer);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_http_headers_remove -
 *
 * ARGUMENTS
 *   chn    -
 *   prefix -
 *   err    -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int flt_ot_http_headers_remove(struct channel *chn, const char *prefix, char **err)
{
	int retval;

	FLT_OT_FUNC("%p, \"%s\", %p:%p", chn, prefix, FLT_OT_DPTR_ARGS(err));

	retval = flt_ot_http_header_set(chn, prefix, NULL, NULL, err);

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
