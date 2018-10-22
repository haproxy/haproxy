/*
 * Functions to manipulate HTTP messages using the internal representation.
 *
 * Copyright (C) 2018 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/config.h>
#include <common/http.h>

#include <proto/http_htx.h>
#include <proto/htx.h>

/* Finds the start line in the HTX message stopping at the first
 * end-of-message. It returns an empty start line when not found, otherwise, it
 * returns the corresponding <struct h1_sl>.
 */
union h1_sl http_find_stline(const struct htx *htx)
{
	union htx_sl *htx_sl;
	union h1_sl sl;
	int32_t pos;

        for (pos = htx_get_head(htx); pos != -1; pos = htx_get_next(htx, pos)) {
                struct htx_blk    *blk  = htx_get_blk(htx, pos);
                enum htx_blk_type  type = htx_get_blk_type(blk);

		if (type == HTX_BLK_REQ_SL) {
			htx_sl = htx_get_blk_ptr(htx, blk);
			sl.rq.meth = htx_sl->rq.meth;
			sl.rq.m = ist2(htx_sl->rq.l, htx_sl->rq.m_len);
			sl.rq.u = ist2(htx_sl->rq.l + htx_sl->rq.m_len, htx_sl->rq.u_len);
			sl.rq.v = ist2(htx_sl->rq.l + htx_sl->rq.m_len + htx_sl->rq.u_len, htx_sl->rq.v_len);
			return sl;
		}

		if (type == HTX_BLK_RES_SL) {
			htx_sl = htx_get_blk_ptr(htx, blk);
			sl.st.status = htx_sl->st.status;
			sl.st.v = ist2(htx_sl->st.l, htx_sl->st.v_len);
			sl.st.c = ist2(htx_sl->st.l + htx_sl->st.v_len, htx_sl->st.c_len);
			sl.st.r = ist2(htx_sl->st.l + htx_sl->st.v_len + htx_sl->st.c_len, htx_sl->st.r_len);
			return sl;
		}
		if (type == HTX_BLK_EOM)
			break;
	}

	sl.rq.m = ist("");
	sl.rq.u = ist("");
	sl.rq.v = ist("");
	return sl;
}

/* Finds the first or next occurrence of header <name> in the HTX message <htx>
 * using the context <ctx>. This structure holds everything necessary to use the
 * header and find next occurrence. If its <blk> member is NULL, the header is
 * searched from the beginning. Otherwise, the next occurrence is returned. The
 * function returns 1 when it finds a value, and 0 when there is no more. It is
 * designed to work with headers defined as comma-separated lists. If <full> is
 * set, it works on full-line headers in whose comma is not a delimiter but is
 * part of the syntax. A special case, if ctx->value is NULL when searching for
 * a new values of a header, the current header is rescanned. This allows
 * rescanning after a header deletion.
 */
int http_find_header(const struct htx *htx, const struct ist name,
		    struct http_hdr_ctx *ctx, int full)
{
	struct htx_blk *blk = ctx->blk;
	struct ist n, v;
	enum htx_blk_type type;
	uint32_t pos;

	if (blk) {
		char *p;

		pos = htx_get_blk_pos(htx, blk);
		if (!ctx->value.ptr)
			goto rescan_hdr;
		if (full)
			goto next_blk;
		v = htx_get_blk_value(htx, blk);
		p = ctx->value.ptr + ctx->value.len + ctx->lws_after;
		v.len -= (p - v.ptr);
		v.ptr  = p;
		if (!v.len)
			goto next_blk;
		/* Skip comma */
		if (*(v.ptr) == ',') {
			v.ptr++;
			v.len--;
		}

		goto return_hdr;
	}

	if (!htx->used)
		return 0;

	pos = htx_get_head(htx);
	while (1) {
	  rescan_hdr:
		blk  = htx_get_blk(htx, pos);
		type = htx_get_blk_type(blk);
		if (type != HTX_BLK_HDR)
			goto next_blk;
		if (name.len) {
			/* If no name was passed, we want any header. So skip the comparison */
			n = htx_get_blk_name(htx, blk);
			if (!isteqi(n, name))
				goto next_blk;
		}
		v = htx_get_blk_value(htx, blk);

	  return_hdr:
		ctx->lws_before = 0;
		ctx->lws_after = 0;
		while (v.len && HTTP_IS_LWS(*v.ptr)) {
			v.ptr++;
			v.len--;
			ctx->lws_before++;
		}
		if (!full)
			v.len = http_find_hdr_value_end(v.ptr, v.ptr + v.len) - v.ptr;
		while (v.len && HTTP_IS_LWS(*(v.ptr + v.len - 1))) {
			v.len--;
			ctx->lws_after++;
		}
		if (!v.len)
			goto next_blk;
		ctx->blk   = blk;
		ctx->value = v;
		return 1;

	  next_blk:
		if (pos == htx->tail)
			break;
		pos++;
		if (pos >= htx->wrap)
			pos = 0;
	}

	ctx->blk   = NULL;
	ctx->value = ist("");
	ctx->lws_before = ctx->lws_after = 0;
	return 0;
}

/* Adds a header block int the HTX message <htx>, just before the EOH block. It
 * returns 1 on success, otherwise it returns 0.
 */
int http_add_header(struct htx *htx, const struct ist n, const struct ist v)
{
	struct htx_blk *blk;
	enum htx_blk_type type = htx_get_tail_type(htx);
	int32_t prev;

	blk = htx_add_header(htx, n, v);
	if (!blk)
		return 0;

	if (unlikely(type < HTX_BLK_EOH))
		return 1;

	/* <blk> is the head, swap it iteratively with its predecessor to place
	 * it just before the end-of-header block. So blocks remains ordered. */
	for (prev = htx_get_prev(htx, htx->tail); prev != -1; prev = htx_get_prev(htx, prev)) {
		struct htx_blk   *pblk = htx_get_blk(htx, prev);
		enum htx_blk_type type = htx_get_blk_type(pblk);

		/* Swap .addr and .info fields */
		blk->addr ^= pblk->addr; pblk->addr ^= blk->addr; blk->addr ^= pblk->addr;
		blk->info ^= pblk->info; pblk->info ^= blk->info; blk->info ^= pblk->info;

		if (blk->addr == pblk->addr)
			blk->addr += htx_get_blksz(pblk);
		htx->front = prev;

		/* Stop when end-of-header is reached */
		if (type == HTX_BLK_EOH)
			break;

		blk = pblk;
	}
	return 1;
}

/* Replaces the request start line of the HTX message <htx> by <sl>. It returns
 * 1 on success, otherwise it returns 0. The start line must be found in the
 * message.
 */
int http_replace_reqline(struct htx *htx, const union h1_sl sl)
{
	int32_t pos;

        for (pos = htx_get_head(htx); pos != -1; pos = htx_get_next(htx, pos)) {
                struct htx_blk    *blk  = htx_get_blk(htx, pos);
                enum htx_blk_type  type = htx_get_blk_type(blk);

		if (type == HTX_BLK_REQ_SL) {
			blk = htx_replace_reqline(htx, blk, sl);
			if (!blk)
				return 0;
			return 1;
		}
		if (type == HTX_BLK_EOM)
			break;
	}

	return 0;
}


/* Replaces the response start line of the HTX message <htx> by <sl>. It returns
 * 1 on success, otherwise it returns 0. The start line must be found in the
 * message.
 */
int http_replace_resline(struct htx *htx, const union h1_sl sl)
{
	int32_t pos;

        for (pos = htx_get_head(htx); pos != -1; pos = htx_get_next(htx, pos)) {
                struct htx_blk    *blk  = htx_get_blk(htx, pos);
                enum htx_blk_type  type = htx_get_blk_type(blk);

		if (type == HTX_BLK_RES_SL) {
			blk = htx_replace_resline(htx, blk, sl);
			if (!blk)
				return 0;
			return 1;
		}
		if (type == HTX_BLK_EOM)
			break;
	}

	return 0;
}

/* Replaces a part of a header value referenced in the context <ctx> by
 * <data>. It returns 1 on success, otherwise it returns 0. The context is
 * updated if necessary.
 */
int http_replace_header_value(struct htx *htx, struct http_hdr_ctx *ctx, const struct ist data)
{
	struct htx_blk *blk = ctx->blk;
	char *start;
	struct ist v;
	uint32_t len, off;

	if (!blk)
		return 0;

	v     = htx_get_blk_value(htx, blk);
	start = ctx->value.ptr - ctx->lws_before;
	len   = ctx->lws_before + ctx->value.len + ctx->lws_after;
	off   = start - v.ptr;

	blk = htx_replace_blk_value(htx, blk, ist2(start, len), data);
	if (!blk)
		return 0;

	v = htx_get_blk_value(htx, blk);
	ctx->blk = blk;
	ctx->value.ptr = v.ptr + off;
	ctx->value.len = data.len;
	ctx->lws_before = ctx->lws_after = 0;

	return 1;
}

/* Fully replaces a header referenced in the context <ctx> by the name <name>
 * with the value <value>. It returns 1 on success, otherwise it returns 0. The
 * context is updated if necessary.
 */
int http_replace_header(struct htx *htx, struct http_hdr_ctx *ctx,
			const struct ist name, const struct ist value)
{
	struct htx_blk *blk = ctx->blk;

	if (!blk)
		return 0;

	blk = htx_replace_header(htx, blk, name, value);
	if (!blk)
		return 0;

	ctx->blk = blk;
	ctx->value = ist(NULL);
	ctx->lws_before = ctx->lws_after = 0;

	return 1;
}

/* Remove one value of a header. This only works on a <ctx> returned by
 * http_find_header function. The value is removed, as well as surrounding commas
 * if any. If the removed value was alone, the whole header is removed.  The
 * <ctx> is always updated accordingly, as well as the HTX message <htx>. It
 * returns 1 on success. Otherwise, it returns 0. The <ctx> is always left in a
 * form that can be handled by http_find_header() to find next occurrence.
 */
int http_remove_header(struct htx *htx, struct http_hdr_ctx *ctx)
{
	struct htx_blk *blk = ctx->blk;
	char *start;
	struct ist v;
	uint32_t len;

	if (!blk)
		return 0;

	start = ctx->value.ptr - ctx->lws_before;
	len   = ctx->lws_before + ctx->value.len + ctx->lws_after;

	v = htx_get_blk_value(htx, blk);
	if (len == v.len) {
		blk = htx_remove_blk(htx, blk);
		if (blk || !htx->used) {
			ctx->blk = blk;
			ctx->value = ist2(NULL, 0);
			ctx->lws_before = ctx->lws_after = 0;
		}
		else {
			ctx->blk = htx_get_blk(htx, htx->tail);
			ctx->value = htx_get_blk_value(htx, ctx->blk);
			ctx->lws_before = ctx->lws_after = 0;
		}
		return 1;
	}

	/* This was not the only value of this header. We have to remove the
	 * part pointed by ctx->value. If it is the last entry of the list, we
	 * remove the last separator.
	 */
	if (start == v.ptr) {
		/* It's the first header part but not the only one. So remove
		 * the comma after it. */
		len++;
	}
	else {
		/* There is at least one header part before the removed one. So
		 * remove the comma between them. */
		start--;
		len++;
	}
	/* Update the block content and its len */
	memmove(start, start+len, v.len-len);
	htx_set_blk_value_len(blk, v.len-len);

	/* Update HTX msg */
	htx->data -= len;

	/* Finally update the ctx */
	ctx->value.ptr = start;
	ctx->value.len = 0;
	ctx->lws_before = ctx->lws_after = 0;

	return 1;
}
