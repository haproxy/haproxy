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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <types/global.h>

#include <common/config.h>
#include <common/debug.h>
#include <common/cfgparse.h>
#include <common/h1.h>
#include <common/http.h>
#include <common/htx.h>

#include <proto/arg.h>
#include <proto/http_htx.h>
#include <proto/http_fetch.h>
#include <proto/sample.h>

struct buffer http_err_chunks[HTTP_ERR_SIZE];
struct eb_root http_error_messages = EB_ROOT;
struct list http_errors_list = LIST_HEAD_INIT(http_errors_list);

/* The declaration of an errorfiles/errorfile directives. Used during config
 * parsing only. */
struct conf_errors {
	char type;                                  /* directive type (0: errorfiles, 1: errorfile) */
	union {
		struct {
			int status;                 /* the status code associated to this error */
			struct buffer *msg;         /* the HTX error message */
		} errorfile;                        /* describe an "errorfile" directive */
		struct {
			char *name;                 /* the http-errors section name */
			char status[HTTP_ERR_SIZE]; /* list of status to import (0: ignore, 1: implicit import, 2: explicit import) */
		} errorfiles;                       /* describe an "errorfiles" directive */
	} info;

	char *file;                                 /* file where the directive appears */
	int line;                                   /* line where the directive appears */

	struct list list;                           /* next conf_errors */
};

static int http_update_authority(struct htx *htx, struct htx_sl *sl, const struct ist host);
static int http_update_host(struct htx *htx, struct htx_sl *sl, const struct ist uri);

/* Returns the next unporocessed start line in the HTX message. It returns NULL
 * if the start-line is undefined (first == -1). Otherwise, it returns the
 * pointer on the htx_sl structure.
 */
struct htx_sl *http_get_stline(struct htx *htx)
{
	struct htx_blk *blk;

	BUG_ON(htx->first == -1);
	blk = htx_get_first_blk(htx);
	if (!blk)
		return NULL;
	BUG_ON(htx_get_blk_type(blk) != HTX_BLK_REQ_SL && htx_get_blk_type(blk) != HTX_BLK_RES_SL);
	return htx_get_blk_ptr(htx, blk);
}

/* Returns the headers size in the HTX message */
size_t http_get_hdrs_size(struct htx *htx)
{
	struct htx_blk *blk;
	size_t sz = 0;

	blk = htx_get_first_blk(htx);
	if (!blk || htx_get_blk_type(blk) > HTX_BLK_EOH)
		return sz;

	for (; blk; blk = htx_get_next_blk(htx, blk)) {
		sz += htx_get_blksz(blk);
		if (htx_get_blk_type(blk) == HTX_BLK_EOH)
			break;
	}
	return sz;
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

	if (blk) {
		char *p;

		if (!isttest(ctx->value))
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

	if (htx_is_empty(htx))
		return 0;

	for (blk = htx_get_first_blk(htx); blk; blk = htx_get_next_blk(htx, blk)) {
	  rescan_hdr:
		type = htx_get_blk_type(blk);
		if (type == HTX_BLK_EOH || type == HTX_BLK_EOM)
			break;
		if (type != HTX_BLK_HDR)
			continue;
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
		ctx->blk   = blk;
		ctx->value = v;
		return 1;

	  next_blk:
		;
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
	struct htx_sl *sl;
	enum htx_blk_type type = htx_get_tail_type(htx);
	int32_t prev;

	blk = htx_add_header(htx, n, v);
	if (!blk)
		goto fail;

	if (unlikely(type < HTX_BLK_EOH))
		goto end;

	/* <blk> is the head, swap it iteratively with its predecessor to place
	 * it just before the end-of-header block. So blocks remains ordered. */
	for (prev = htx_get_prev(htx, htx->tail); prev != htx->first; prev = htx_get_prev(htx, prev)) {
		struct htx_blk   *pblk = htx_get_blk(htx, prev);
		enum htx_blk_type type = htx_get_blk_type(pblk);

		/* Swap .addr and .info fields */
		blk->addr ^= pblk->addr; pblk->addr ^= blk->addr; blk->addr ^= pblk->addr;
		blk->info ^= pblk->info; pblk->info ^= blk->info; blk->info ^= pblk->info;

		if (blk->addr == pblk->addr)
			blk->addr += htx_get_blksz(pblk);

		/* Stop when end-of-header is reached */
		if (type == HTX_BLK_EOH)
			break;

		blk = pblk;
	}

  end:
	sl = http_get_stline(htx);
	if (sl && (sl->flags & HTX_SL_F_HAS_AUTHORITY) && isteqi(n, ist("host"))) {
		if (!http_update_authority(htx, sl, v))
			goto fail;
	}
	return 1;

  fail:
	return 0;
}

/* Replaces parts of the start-line of the HTX message <htx>. It returns 1 on
 * success, otherwise it returns 0.
 */
int http_replace_stline(struct htx *htx, const struct ist p1, const struct ist p2, const struct ist p3)
{
	struct htx_blk *blk;

	blk = htx_get_first_blk(htx);
	if (!blk || !htx_replace_stline(htx, blk, p1, p2, p3))
		return 0;
	return 1;
}

/* Replace the request method in the HTX message <htx> by <meth>. It returns 1
 * on success, otherwise 0.
 */
int http_replace_req_meth(struct htx *htx, const struct ist meth)
{
	struct buffer *temp = get_trash_chunk();
	struct htx_sl *sl = http_get_stline(htx);
	struct ist uri, vsn;

	if (!sl)
		return 0;

	/* Start by copying old uri and version */
	chunk_memcat(temp, HTX_SL_REQ_UPTR(sl), HTX_SL_REQ_ULEN(sl)); /* uri */
	uri = ist2(temp->area, HTX_SL_REQ_ULEN(sl));

	chunk_memcat(temp, HTX_SL_REQ_VPTR(sl), HTX_SL_REQ_VLEN(sl)); /* vsn */
	vsn = ist2(temp->area + uri.len, HTX_SL_REQ_VLEN(sl));

	/* create the new start line */
	sl->info.req.meth = find_http_meth(meth.ptr, meth.len);
	return http_replace_stline(htx, meth, uri, vsn);
}

/* Replace the request uri in the HTX message <htx> by <uri>. It returns 1 on
 * success, otherwise 0.
 */
int http_replace_req_uri(struct htx *htx, const struct ist uri)
{
	struct buffer *temp = get_trash_chunk();
	struct htx_sl *sl = http_get_stline(htx);
	struct ist meth, vsn;

	if (!sl)
		goto fail;

	/* Start by copying old method and version */
	chunk_memcat(temp, HTX_SL_REQ_MPTR(sl), HTX_SL_REQ_MLEN(sl)); /* meth */
	meth = ist2(temp->area, HTX_SL_REQ_MLEN(sl));

	chunk_memcat(temp, HTX_SL_REQ_VPTR(sl), HTX_SL_REQ_VLEN(sl)); /* vsn */
	vsn = ist2(temp->area + meth.len, HTX_SL_REQ_VLEN(sl));

	/* create the new start line */
	if (!http_replace_stline(htx, meth, uri, vsn))
		goto fail;

	sl = http_get_stline(htx);
	if (!http_update_host(htx, sl, uri))
		goto fail;

	return 1;
  fail:
	return 0;
}

/* Replace the request path in the HTX message <htx> by <path>. The host part
 * and the query string are preserved. It returns 1 on success, otherwise 0.
 */
int http_replace_req_path(struct htx *htx, const struct ist path)
{
	struct buffer *temp = get_trash_chunk();
	struct htx_sl *sl = http_get_stline(htx);
	struct ist meth, uri, vsn, p;
	size_t plen = 0;

	if (!sl)
		return 0;

	uri = htx_sl_req_uri(sl);
	p = http_get_path(uri);
	if (!isttest(p))
		p = uri;
	while (plen < p.len && *(p.ptr + plen) != '?')
		plen++;

	/* Start by copying old method and version and create the new uri */
	chunk_memcat(temp, HTX_SL_REQ_MPTR(sl), HTX_SL_REQ_MLEN(sl)); /* meth */
	meth = ist2(temp->area, HTX_SL_REQ_MLEN(sl));

	chunk_memcat(temp, HTX_SL_REQ_VPTR(sl), HTX_SL_REQ_VLEN(sl)); /* vsn */
	vsn = ist2(temp->area + meth.len, HTX_SL_REQ_VLEN(sl));

	chunk_memcat(temp, uri.ptr, p.ptr - uri.ptr);         /* uri: host part */
	chunk_memcat(temp, path.ptr, path.len);               /* uri: new path */
	chunk_memcat(temp, p.ptr + plen, p.len - plen);       /* uri: QS part */
	uri = ist2(temp->area + meth.len + vsn.len, uri.len - plen + path.len);

	/* create the new start line */
	return http_replace_stline(htx, meth, uri, vsn);
}

/* Replace the request query-string in the HTX message <htx> by <query>. The
 * host part and the path are preserved. It returns 1 on success, otherwise
 * 0.
 */
int http_replace_req_query(struct htx *htx, const struct ist query)
{
	struct buffer *temp = get_trash_chunk();
	struct htx_sl *sl = http_get_stline(htx);
	struct ist meth, uri, vsn, q;
	int offset = 1;

	if (!sl)
		return 0;

	uri = htx_sl_req_uri(sl);
	q = uri;
	while (q.len > 0 && *(q.ptr) != '?') {
		q.ptr++;
		q.len--;
	}

	/* skip the question mark or indicate that we must insert it
	 * (but only if the format string is not empty then).
	 */
	if (q.len) {
		q.ptr++;
		q.len--;
	}
	else if (query.len > 1)
		offset = 0;

	/* Start by copying old method and version and create the new uri */
	chunk_memcat(temp, HTX_SL_REQ_MPTR(sl), HTX_SL_REQ_MLEN(sl)); /* meth */
	meth = ist2(temp->area, HTX_SL_REQ_MLEN(sl));

	chunk_memcat(temp, HTX_SL_REQ_VPTR(sl), HTX_SL_REQ_VLEN(sl)); /* vsn */
	vsn = ist2(temp->area + meth.len, HTX_SL_REQ_VLEN(sl));

	chunk_memcat(temp, uri.ptr, q.ptr - uri.ptr);               /* uri: host + path part */
	chunk_memcat(temp, query.ptr + offset, query.len - offset); /* uri: new QS */
	uri = ist2(temp->area + meth.len + vsn.len, uri.len - q.len + query.len - offset);

	/* create the new start line */
	return http_replace_stline(htx, meth, uri, vsn);
}

/* Replace the response status in the HTX message <htx> by <status>. It returns
 * 1 on success, otherwise 0.
*/
int http_replace_res_status(struct htx *htx, const struct ist status)
{
	struct buffer *temp = get_trash_chunk();
	struct htx_sl *sl = http_get_stline(htx);
	struct ist vsn, reason;

	if (!sl)
		return 0;

	/* Start by copying old uri and version */
	chunk_memcat(temp, HTX_SL_RES_VPTR(sl), HTX_SL_RES_VLEN(sl)); /* vsn */
	vsn = ist2(temp->area, HTX_SL_RES_VLEN(sl));

	chunk_memcat(temp, HTX_SL_RES_RPTR(sl), HTX_SL_RES_RLEN(sl)); /* reason */
	reason = ist2(temp->area + vsn.len, HTX_SL_RES_RLEN(sl));

	/* create the new start line */
	sl->info.res.status = strl2ui(status.ptr, status.len);
	return http_replace_stline(htx, vsn, status, reason);
}

/* Replace the response reason in the HTX message <htx> by <reason>. It returns
 * 1 on success, otherwise 0.
*/
int http_replace_res_reason(struct htx *htx, const struct ist reason)
{
	struct buffer *temp = get_trash_chunk();
	struct htx_sl *sl = http_get_stline(htx);
	struct ist vsn, status;

	if (!sl)
		return 0;

	/* Start by copying old uri and version */
	chunk_memcat(temp, HTX_SL_RES_VPTR(sl), HTX_SL_RES_VLEN(sl)); /* vsn */
	vsn = ist2(temp->area, HTX_SL_RES_VLEN(sl));

	chunk_memcat(temp, HTX_SL_RES_CPTR(sl), HTX_SL_RES_CLEN(sl)); /* code */
	status = ist2(temp->area + vsn.len, HTX_SL_RES_CLEN(sl));

	/* create the new start line */
	return http_replace_stline(htx, vsn, status, reason);
}

/* Replaces a part of a header value referenced in the context <ctx> by
 * <data>. It returns 1 on success, otherwise it returns 0. The context is
 * updated if necessary.
 */
int http_replace_header_value(struct htx *htx, struct http_hdr_ctx *ctx, const struct ist data)
{
	struct htx_blk *blk = ctx->blk;
	struct htx_sl *sl;
	char *start;
	struct ist v;
	uint32_t len, off;

	if (!blk)
		goto fail;

	v     = htx_get_blk_value(htx, blk);
	start = ctx->value.ptr - ctx->lws_before;
	len   = ctx->lws_before + ctx->value.len + ctx->lws_after;
	off   = start - v.ptr;

	blk = htx_replace_blk_value(htx, blk, ist2(start, len), data);
	if (!blk)
		goto fail;

	v = htx_get_blk_value(htx, blk);

	sl = http_get_stline(htx);
	if (sl && (sl->flags & HTX_SL_F_HAS_AUTHORITY)) {
		struct ist n = htx_get_blk_name(htx, blk);

		if (isteq(n, ist("host"))) {
			if (!http_update_authority(htx, sl, v))
				goto fail;
			ctx->blk = NULL;
			http_find_header(htx, ist("host"), ctx, 1);
			blk = ctx->blk;
			v = htx_get_blk_value(htx, blk);
		}
	}

	ctx->blk = blk;
	ctx->value.ptr = v.ptr + off;
	ctx->value.len = data.len;
	ctx->lws_before = ctx->lws_after = 0;

	return 1;
  fail:
	return 0;
}

/* Fully replaces a header referenced in the context <ctx> by the name <name>
 * with the value <value>. It returns 1 on success, otherwise it returns 0. The
 * context is updated if necessary.
 */
int http_replace_header(struct htx *htx, struct http_hdr_ctx *ctx,
			const struct ist name, const struct ist value)
{
	struct htx_blk *blk = ctx->blk;
	struct htx_sl *sl;

	if (!blk)
		goto fail;

	blk = htx_replace_header(htx, blk, name, value);
	if (!blk)
		goto fail;

	sl = http_get_stline(htx);
	if (sl && (sl->flags & HTX_SL_F_HAS_AUTHORITY) && isteqi(name, ist("host"))) {
		if (!http_update_authority(htx, sl, value))
			goto fail;
		ctx->blk = NULL;
		http_find_header(htx, ist("host"), ctx, 1);
		blk = ctx->blk;
	}

	ctx->blk = blk;
	ctx->value = ist(NULL);
	ctx->lws_before = ctx->lws_after = 0;

	return 1;
  fail:
	return 0;
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
		if (blk || htx_is_empty(htx)) {
			ctx->blk = blk;
			ctx->value = IST_NULL;
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
	htx_change_blk_value_len(htx, blk, v.len-len);

	/* Finally update the ctx */
	ctx->value.ptr = start;
	ctx->value.len = 0;
	ctx->lws_before = ctx->lws_after = 0;

	return 1;
}

/* Updates the authority part of the uri with the value <host>. It happens when
 * the header host is modified. It returns 0 on failure and 1 on success. It is
 * the caller responsibility to provide the start-line and to be sure the uri
 * contains an authority. Thus, if no authority is found in the uri, an error is
 * returned.
 */
static int http_update_authority(struct htx *htx, struct htx_sl *sl, const struct ist host)
{
	struct buffer *temp = get_trash_chunk();
	struct ist meth, vsn, uri, authority;

	uri = htx_sl_req_uri(sl);
	authority = http_get_authority(uri, 1);
	if (!authority.len)
		return 0;

	/* Don't update the uri if there is no change */
	if (isteq(host, authority))
		return 1;

	/* Start by copying old method and version */
	chunk_memcat(temp, HTX_SL_REQ_MPTR(sl), HTX_SL_REQ_MLEN(sl)); /* meth */
	meth = ist2(temp->area, HTX_SL_REQ_MLEN(sl));

	chunk_memcat(temp, HTX_SL_REQ_VPTR(sl), HTX_SL_REQ_VLEN(sl)); /* vsn */
	vsn = ist2(temp->area + meth.len, HTX_SL_REQ_VLEN(sl));

	chunk_memcat(temp, uri.ptr, authority.ptr - uri.ptr);
	chunk_memcat(temp, host.ptr, host.len);
	chunk_memcat(temp, authority.ptr + authority.len, uri.ptr + uri.len - (authority.ptr + authority.len));
	uri = ist2(temp->area + meth.len + vsn.len, host.len + uri.len - authority.len); /* uri */

	return http_replace_stline(htx, meth, uri, vsn);

}

/* Update the header host by extracting the authority of the uri <uri>. flags of
 * the start-line are also updated accordingly. For orgin-form and asterisk-form
 * uri, the header host is not changed and the flag HTX_SL_F_HAS_AUTHORITY is
 * removed from the flags of the start-line. Otherwise, this flag is set and the
 * authority is used to set the value of the header host. This function returns
 * 0 on failure and 1 on success.
*/
static int http_update_host(struct htx *htx, struct htx_sl *sl, const struct ist uri)
{
	struct ist authority;
	struct http_hdr_ctx ctx;

	if (!uri.len || uri.ptr[0] == '/' ||  uri.ptr[0] == '*') {
		// origin-form or a asterisk-form (RFC7320 #5.3.1 and #5.3.4)
		sl->flags &= ~HTX_SL_F_HAS_AUTHORITY;
	}
	else {
		sl->flags |= HTX_SL_F_HAS_AUTHORITY;
		if (sl->info.req.meth != HTTP_METH_CONNECT) {
			// absolute-form (RFC7320 #5.3.2)
			sl->flags |= HTX_SL_F_HAS_SCHM;
			if (uri.len > 4 && (uri.ptr[0] | 0x20) == 'h')
				sl->flags |= ((uri.ptr[4] == ':') ? HTX_SL_F_SCHM_HTTP : HTX_SL_F_SCHM_HTTPS);

			authority = http_get_authority(uri, 1);
			if (!authority.len)
				goto fail;
		}
		else {
			// authority-form (RFC7320 #5.3.3)
			authority = uri;
		}

		/* Replace header host value */
		ctx.blk = NULL;
		while (http_find_header(htx, ist("host"), &ctx, 1)) {
			if (!http_replace_header_value(htx, &ctx, authority))
				goto fail;
		}

	}
	return 1;
  fail:
	return 0;
}

/* Return in <vptr> and <vlen> the pointer and length of occurrence <occ> of
 * header whose name is <hname> of length <hlen>. If <ctx> is null, lookup is
 * performed over the whole headers. Otherwise it must contain a valid header
 * context, initialised with ctx->blk=NULL for the first lookup in a series. If
 * <occ> is positive or null, occurrence #occ from the beginning (or last ctx)
 * is returned. Occ #0 and #1 are equivalent. If <occ> is negative (and no less
 * than -MAX_HDR_HISTORY), the occurrence is counted from the last one which is
 * -1. The value fetch stops at commas, so this function is suited for use with
 * list headers.
 * The return value is 0 if nothing was found, or non-zero otherwise.
 */
unsigned int http_get_htx_hdr(const struct htx *htx, const struct ist hdr,
			      int occ, struct http_hdr_ctx *ctx, char **vptr, size_t *vlen)
{
	struct http_hdr_ctx local_ctx;
	struct ist val_hist[MAX_HDR_HISTORY];
	unsigned int hist_idx;
	int found;

	if (!ctx) {
		local_ctx.blk = NULL;
		ctx = &local_ctx;
	}

	if (occ >= 0) {
		/* search from the beginning */
		while (http_find_header(htx, hdr, ctx, 0)) {
			occ--;
			if (occ <= 0) {
				*vptr = ctx->value.ptr;
				*vlen = ctx->value.len;
				return 1;
			}
		}
		return 0;
	}

	/* negative occurrence, we scan all the list then walk back */
	if (-occ > MAX_HDR_HISTORY)
		return 0;

	found = hist_idx = 0;
	while (http_find_header(htx, hdr, ctx, 0)) {
		val_hist[hist_idx] = ctx->value;
		if (++hist_idx >= MAX_HDR_HISTORY)
			hist_idx = 0;
		found++;
	}
	if (-occ > found)
		return 0;

	/* OK now we have the last occurrence in [hist_idx-1], and we need to
	 * find occurrence -occ. 0 <= hist_idx < MAX_HDR_HISTORY, and we have
	 * -10 <= occ <= -1. So we have to check [hist_idx%MAX_HDR_HISTORY+occ]
	 * to remain in the 0..9 range.
	 */
	hist_idx += occ + MAX_HDR_HISTORY;
	if (hist_idx >= MAX_HDR_HISTORY)
		hist_idx -= MAX_HDR_HISTORY;
	*vptr = val_hist[hist_idx].ptr;
	*vlen = val_hist[hist_idx].len;
	return 1;
}

/* Return in <vptr> and <vlen> the pointer and length of occurrence <occ> of
 * header whose name is <hname> of length <hlen>. If <ctx> is null, lookup is
 * performed over the whole headers. Otherwise it must contain a valid header
 * context, initialised with ctx->blk=NULL for the first lookup in a series. If
 * <occ> is positive or null, occurrence #occ from the beginning (or last ctx)
 * is returned. Occ #0 and #1 are equivalent. If <occ> is negative (and no less
 * than -MAX_HDR_HISTORY), the occurrence is counted from the last one which is
 * -1. This function differs from http_get_hdr() in that it only returns full
 * line header values and does not stop at commas.
 * The return value is 0 if nothing was found, or non-zero otherwise.
 */
unsigned int http_get_htx_fhdr(const struct htx *htx, const struct ist hdr,
			       int occ, struct http_hdr_ctx *ctx, char **vptr, size_t *vlen)
{
	struct http_hdr_ctx local_ctx;
	struct ist val_hist[MAX_HDR_HISTORY];
	unsigned int hist_idx;
	int found;

	if (!ctx) {
		local_ctx.blk = NULL;
		ctx = &local_ctx;
	}

	if (occ >= 0) {
		/* search from the beginning */
		while (http_find_header(htx, hdr, ctx, 1)) {
			occ--;
			if (occ <= 0) {
				*vptr = ctx->value.ptr;
				*vlen = ctx->value.len;
				return 1;
			}
		}
		return 0;
	}

	/* negative occurrence, we scan all the list then walk back */
	if (-occ > MAX_HDR_HISTORY)
		return 0;

	found = hist_idx = 0;
	while (http_find_header(htx, hdr, ctx, 1)) {
		val_hist[hist_idx] = ctx->value;
		if (++hist_idx >= MAX_HDR_HISTORY)
			hist_idx = 0;
		found++;
	}
	if (-occ > found)
		return 0;

	/* OK now we have the last occurrence in [hist_idx-1], and we need to
	 * find occurrence -occ. 0 <= hist_idx < MAX_HDR_HISTORY, and we have
	 * -10 <= occ <= -1. So we have to check [hist_idx%MAX_HDR_HISTORY+occ]
	 * to remain in the 0..9 range.
	 */
	hist_idx += occ + MAX_HDR_HISTORY;
	if (hist_idx >= MAX_HDR_HISTORY)
		hist_idx -= MAX_HDR_HISTORY;
	*vptr = val_hist[hist_idx].ptr;
	*vlen = val_hist[hist_idx].len;
	return 1;
}

int http_str_to_htx(struct buffer *buf, struct ist raw)
{
	struct htx *htx;
	struct htx_sl *sl;
	struct h1m h1m;
	struct http_hdr hdrs[global.tune.max_http_hdr];
	union h1_sl h1sl;
	unsigned int flags = HTX_SL_F_IS_RESP;
	int ret = 0;

	b_reset(buf);
	if (!raw.len) {
		buf->size = 0;
		buf->area = malloc(raw.len);
		return 1;
	}

	buf->size = global.tune.bufsize;
	buf->area = (char *)malloc(buf->size);
	if (!buf->area)
		goto error;

	h1m_init_res(&h1m);
	h1m.flags |= H1_MF_NO_PHDR;
	ret = h1_headers_to_hdr_list(raw.ptr, raw.ptr + raw.len,
				     hdrs, sizeof(hdrs)/sizeof(hdrs[0]), &h1m, &h1sl);
	if (ret <= 0)
		goto error;

	if (unlikely(h1sl.st.v.len != 8))
		goto error;
	if ((*(h1sl.st.v.ptr + 5) > '1') ||
	    ((*(h1sl.st.v.ptr + 5) == '1') && (*(h1sl.st.v.ptr + 7) >= '1')))
		h1m.flags |= H1_MF_VER_11;

	if (h1sl.st.status < 200 && (h1sl.st.status == 100 || h1sl.st.status >= 102))
		goto error;

	if (h1m.flags & H1_MF_VER_11)
		flags |= HTX_SL_F_VER_11;
	if (h1m.flags & H1_MF_XFER_ENC)
		flags |= HTX_SL_F_XFER_ENC;
	if (h1m.flags & H1_MF_CLEN) {
		flags |= (HTX_SL_F_XFER_LEN|HTX_SL_F_CLEN);
		if (h1m.body_len == 0)
			flags |= HTX_SL_F_BODYLESS;
	}
	if (h1m.flags & H1_MF_CHNK)
		goto error; /* Unsupported because there is no body parsing */

	htx = htx_from_buf(buf);
	sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, h1sl.st.v, h1sl.st.c, h1sl.st.r);
	if (!sl || !htx_add_all_headers(htx, hdrs))
		goto error;
	sl->info.res.status = h1sl.st.status;

	while (raw.len > ret) {
		int sent = htx_add_data(htx, ist2(raw.ptr + ret, raw.len - ret));
		if (!sent)
			goto error;
		ret += sent;
	}

	if (!htx_add_endof(htx, HTX_BLK_EOM))
		goto error;

	return 1;

error:
	if (buf->size)
		free(buf->area);
	return 0;
}

static int http_htx_init(void)
{
	struct buffer chk;
	struct ist raw;
	int rc;
	int err_code = 0;

	for (rc = 0; rc < HTTP_ERR_SIZE; rc++) {
		if (!http_err_msgs[rc]) {
			ha_alert("Internal error: no message defined for HTTP return code %d", rc);
			err_code |= ERR_ALERT | ERR_FATAL;
			continue;
		}

		raw = ist2(http_err_msgs[rc], strlen(http_err_msgs[rc]));
		if (!http_str_to_htx(&chk, raw)) {
			ha_alert("Internal error: Unable to convert message in HTX for HTTP return code %d.\n",
				 http_err_codes[rc]);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
		http_err_chunks[rc] = chk;
	}
end:
	return err_code;
}

static void http_htx_deinit(void)
{
	struct http_errors *http_errs, *http_errsb;
	struct ebpt_node *node, *next;
	struct http_error *http_err;

	node = ebpt_first(&http_error_messages);
	while (node) {
		next = ebpt_next(node);
		ebpt_delete(node);
		http_err = container_of(node, typeof(*http_err), node);
		chunk_destroy(&http_err->msg);
		free(node->key);
		free(http_err);
		node = next;
	}

	list_for_each_entry_safe(http_errs, http_errsb, &http_errors_list, list) {
		free(http_errs->conf.file);
		free(http_errs->id);
		LIST_DEL(&http_errs->list);
		free(http_errs);
	}
}

REGISTER_CONFIG_POSTPARSER("http_htx", http_htx_init);
REGISTER_POST_DEINIT(http_htx_deinit);

/* Reads content of the error file <file> and convert it into an HTX message. On
 * success, the HTX message is returned. On error, NULL is returned and an error
 * message is written into the <errmsg> buffer.
 */
struct buffer *http_load_errorfile(const char *file, char **errmsg)
{
	struct buffer *buf = NULL;
	struct buffer chk;
	struct ebpt_node *node;
	struct http_error *http_err;
	struct stat stat;
	char *err = NULL;
	int errnum, errlen;
	int fd = -1;

	/* already loaded */
	node = ebis_lookup_len(&http_error_messages, file, strlen(file));
	if (node) {
		http_err = container_of(node,  typeof(*http_err), node);
		buf = &http_err->msg;
		goto out;
	}

	/* Read the error file content */
	fd = open(file, O_RDONLY);
	if ((fd < 0) || (fstat(fd, &stat) < 0)) {
		memprintf(errmsg, "error opening file '%s'.", file);
		goto out;
	}

	if (stat.st_size <= global.tune.bufsize)
		errlen = stat.st_size;
	else {
		ha_warning("custom error message file '%s' larger than %d bytes. Truncating.\n",
			   file, global.tune.bufsize);
		errlen = global.tune.bufsize;
	}

	err = malloc(errlen);
	if (!err) {
		memprintf(errmsg, "out of memory.");
		goto out;
	}

	errnum = read(fd, err, errlen);
	if (errnum != errlen) {
		memprintf(errmsg, "error reading file '%s'.", file);
		goto out;
	}

	/* Create the node corresponding to the error file */
	http_err = calloc(1, sizeof(*http_err));
	if (!http_err) {
		memprintf(errmsg, "out of memory.");
		goto out;
	}
	http_err->node.key = strdup(file);
	if (!http_err->node.key) {
		memprintf(errmsg, "out of memory.");
		free(http_err);
		goto out;
	}

	/* Convert the error file into an HTX message */
	if (!http_str_to_htx(&chk, ist2(err, errlen))) {
		memprintf(errmsg, "unable to convert custom error message file '%s' in HTX.", file);
		free(http_err->node.key);
		free(http_err);
		goto out;
	}

	/* Insert the node in the tree and return the HTX message */
	http_err->msg = chk;
	ebis_insert(&http_error_messages, &http_err->node);
	buf = &http_err->msg;

  out:
	if (fd >= 0)
		close(fd);
	free(err);
	return buf;
}

/* Convert the raw http message <msg> into an HTX message. On success, the HTX
 * message is returned. On error, NULL is returned and an error message is
 * written into the <errmsg> buffer.
 */
struct buffer *http_load_errormsg(const char *key, const struct ist msg, char **errmsg)
{
	struct buffer *buf = NULL;
	struct buffer chk;
	struct ebpt_node *node;
	struct http_error *http_err;

	/* already loaded */
	node = ebis_lookup_len(&http_error_messages, key, strlen(key));
	if (node) {
		http_err = container_of(node,  typeof(*http_err), node);
		buf = &http_err->msg;
		goto out;
	}
	/* Create the node corresponding to the error file */
	http_err = calloc(1, sizeof(*http_err));
	if (!http_err) {
		memprintf(errmsg, "out of memory.");
		goto out;
	}
	http_err->node.key = strdup(key);
	if (!http_err->node.key) {
		memprintf(errmsg, "out of memory.");
		free(http_err);
		goto out;
	}

	/* Convert the error file into an HTX message */
	if (!http_str_to_htx(&chk, msg)) {
		memprintf(errmsg, "unable to convert message in HTX.");
		free(http_err->node.key);
		free(http_err);
		goto out;
	}

	/* Insert the node in the tree and return the HTX message */
	http_err->msg = chk;
	ebis_insert(&http_error_messages, &http_err->node);
	buf = &http_err->msg;
  out:
	return buf;
}

/* This function parses the raw HTTP error file <file> for the status code
 * <status>. It returns NULL if there is any error, otherwise it return the
 * corresponding HTX message.
 */
struct buffer *http_parse_errorfile(int status, const char *file, char **errmsg)
{
	struct buffer *buf = NULL;
	int rc;

	for (rc = 0; rc < HTTP_ERR_SIZE; rc++) {
		if (http_err_codes[rc] == status) {
			buf = http_load_errorfile(file, errmsg);
			break;
		}
	}

	if (rc >= HTTP_ERR_SIZE)
		memprintf(errmsg, "status code '%d' not handled.", status);
	return buf;
}

/* This function creates HTX error message corresponding to a redirect message
 * for the status code <status>. <url> is used as location url for the
 * redirect. <errloc> is used to know if it is a 302 or a 303 redirect. It
 * returns NULL if there is any error, otherwise it return the corresponding HTX
 * message.
 */
struct buffer *http_parse_errorloc(int errloc, int status, const char *url, char **errmsg)
{
	struct buffer *buf = NULL;
	const char *msg;
	char *key = NULL, *err = NULL;
	int rc, errlen;

	for (rc = 0; rc < HTTP_ERR_SIZE; rc++) {
		if (http_err_codes[rc] == status) {
			/*  Create the error key */
			if (!memprintf(&key, "errorloc%d %s", errloc, url)) {
				memprintf(errmsg, "out of memory.");
				goto out;
			}
			/* Create the error message */
			msg = (errloc == 302 ? HTTP_302 : HTTP_303);
			errlen = strlen(msg) + strlen(url) + 5;
			err = malloc(errlen);
			if (!err) {
				memprintf(errmsg, "out of memory.");
				goto out;
			}
			errlen = snprintf(err, errlen, "%s%s\r\n\r\n", msg, url);

			/* Load it */
			buf = http_load_errormsg(key, ist2(err, errlen), errmsg);
			break;
		}
	}

	if (rc >= HTTP_ERR_SIZE)
		memprintf(errmsg, "status code '%d' not handled.", status);
out:
	free(key);
	free(err);
	return buf;
}

/* Parses the "errorloc[302|303]" proxy keyword */
static int proxy_parse_errorloc(char **args, int section, struct proxy *curpx,
				  struct proxy *defpx, const char *file, int line,
				  char **errmsg)
{
	struct conf_errors *conf_err;
	struct buffer *msg;
	int errloc, status;
	int ret = 0;

	if (warnifnotcap(curpx, PR_CAP_FE | PR_CAP_BE, file, line, args[0], NULL)) {
		ret = 1;
		goto out;
	}

	if (*(args[1]) == 0 || *(args[2]) == 0) {
		memprintf(errmsg, "%s : expects <status_code> and <url> as arguments.\n", args[0]);
		ret = -1;
		goto out;
	}

	status = atol(args[1]);
	errloc = (!strcmp(args[0], "errorloc303") ? 303 : 302);
	msg = http_parse_errorloc(errloc, status, args[2], errmsg);
	if (!msg) {
		memprintf(errmsg, "%s : %s", args[0], *errmsg);
		ret = -1;
		goto out;
	}

	conf_err = calloc(1, sizeof(*conf_err));
	if (!conf_err) {
		memprintf(errmsg, "%s : out of memory.", args[0]);
		ret = -1;
		goto out;
	}
	conf_err->type = 1;
	conf_err->info.errorfile.status = status;
	conf_err->info.errorfile.msg = msg;
	conf_err->file = strdup(file);
	conf_err->line = line;
	LIST_ADDQ(&curpx->conf.errors, &conf_err->list);

  out:
	return ret;

}

/* Parses the "errorfile" proxy keyword */
static int proxy_parse_errorfile(char **args, int section, struct proxy *curpx,
				 struct proxy *defpx, const char *file, int line,
				 char **errmsg)
{
	struct conf_errors *conf_err;
	struct buffer *msg;
	int status;
	int ret = 0;

	if (warnifnotcap(curpx, PR_CAP_FE | PR_CAP_BE, file, line, args[0], NULL)) {
		ret = 1;
		goto out;
	}

	if (*(args[1]) == 0 || *(args[2]) == 0) {
		memprintf(errmsg, "%s : expects <status_code> and <file> as arguments.\n", args[0]);
		ret = -1;
		goto out;
	}

	status = atol(args[1]);
	msg = http_parse_errorfile(status, args[2], errmsg);
	if (!msg) {
		memprintf(errmsg, "%s : %s", args[0], *errmsg);
		ret = -1;
		goto out;
	}

	conf_err = calloc(1, sizeof(*conf_err));
	if (!conf_err) {
		memprintf(errmsg, "%s : out of memory.", args[0]);
		ret = -1;
		goto out;
	}
	conf_err->type = 1;
	conf_err->info.errorfile.status = status;
	conf_err->info.errorfile.msg = msg;
	conf_err->file = strdup(file);
	conf_err->line = line;
	LIST_ADDQ(&curpx->conf.errors, &conf_err->list);

  out:
	return ret;

}

/* Parses the "errorfiles" proxy keyword */
static int proxy_parse_errorfiles(char **args, int section, struct proxy *curpx,
				  struct proxy *defpx, const char *file, int line,
				  char **err)
{
	struct conf_errors *conf_err = NULL;
	char *name = NULL;
	int rc, ret = 0;

	if (warnifnotcap(curpx, PR_CAP_FE | PR_CAP_BE, file, line, args[0], NULL)) {
		ret = 1;
		goto out;
	}

	if (!*(args[1])) {
		memprintf(err, "%s : expects <name> as argument.", args[0]);
		ret = -1;
		goto out;
	}

	name = strdup(args[1]);
	conf_err = calloc(1, sizeof(*conf_err));
	if (!name || !conf_err) {
		memprintf(err, "%s : out of memory.", args[0]);
		goto error;
	}
	conf_err->type = 0;

	conf_err->info.errorfiles.name = name;
	if (!*(args[2])) {
		for (rc = 0; rc < HTTP_ERR_SIZE; rc++)
			conf_err->info.errorfiles.status[rc] = 1;
	}
	else {
		int cur_arg, status;
		for (cur_arg = 2; *(args[cur_arg]); cur_arg++) {
			status = atol(args[cur_arg]);

			for (rc = 0; rc < HTTP_ERR_SIZE; rc++) {
				if (http_err_codes[rc] == status) {
					conf_err->info.errorfiles.status[rc] = 2;
					break;
				}
			}
			if (rc >= HTTP_ERR_SIZE) {
				memprintf(err, "%s : status code '%d' not handled.", args[0], status);
				goto error;
			}
		}
	}
	conf_err->file = strdup(file);
	conf_err->line = line;
	LIST_ADDQ(&curpx->conf.errors, &conf_err->list);
  out:
	return ret;

  error:
	free(name);
	free(conf_err);
	ret = -1;
	goto out;
}

/* Check "errorfiles" proxy keyword */
static int proxy_check_errors(struct proxy *px)
{
	struct conf_errors *conf_err, *conf_err_back;
	struct http_errors *http_errs;
	int rc, err = 0;

	list_for_each_entry_safe(conf_err, conf_err_back, &px->conf.errors, list) {
		if (conf_err->type == 1) {
			/* errorfile */
			rc = http_get_status_idx(conf_err->info.errorfile.status);
			px->errmsg[rc] = conf_err->info.errorfile.msg;
		}
		else {
			/* errorfiles */
			list_for_each_entry(http_errs, &http_errors_list, list) {
				if (strcmp(http_errs->id, conf_err->info.errorfiles.name) == 0)
					break;
			}

			/* unknown http-errors section */
			if (&http_errs->list == &http_errors_list) {
				ha_alert("config : proxy '%s': unknown http-errors section '%s' (at %s:%d).\n",
					 px->id, conf_err->info.errorfiles.name, conf_err->file, conf_err->line);
				err |= ERR_ALERT | ERR_FATAL;
				free(conf_err->info.errorfiles.name);
				goto next;
			}

			free(conf_err->info.errorfiles.name);
			for (rc = 0; rc < HTTP_ERR_SIZE; rc++) {
				if (conf_err->info.errorfiles.status[rc] > 0) {
					if (http_errs->errmsg[rc])
						px->errmsg[rc] = http_errs->errmsg[rc];
					else if (conf_err->info.errorfiles.status[rc] == 2)
						ha_warning("config: proxy '%s' : status '%d' not declared in"
							   " http-errors section '%s' (at %s:%d).\n",
							   px->id, http_err_codes[rc], http_errs->id,
							   conf_err->file, conf_err->line);
				}
			}
		}
	  next:
		LIST_DEL(&conf_err->list);
		free(conf_err->file);
		free(conf_err);
	}

  out:
	return err;
}

static int post_check_errors()
{
	struct ebpt_node *node;
	struct http_error *http_err;
	struct htx *htx;
	int err_code = 0;

	node = ebpt_first(&http_error_messages);
	while (node) {
		http_err = container_of(node, typeof(*http_err), node);
		if (b_is_null(&http_err->msg))
			goto next;
		htx = htxbuf(&http_err->msg);
		if (htx_free_data_space(htx) < global.tune.maxrewrite) {
			ha_warning("config: errorfile '%s' runs over the buffer space"
				   " reserved to headers rewritting. It may lead to internal errors if "
				   " http-after-response rules are evaluated on this message.\n",
				   (char *)node->key);
			err_code |= ERR_WARN;
		}
	  next:
		node = ebpt_next(node);
	}

	return err_code;
}

int proxy_dup_default_conf_errors(struct proxy *curpx, struct proxy *defpx, char **errmsg)
{
	struct conf_errors *conf_err, *new_conf_err = NULL;
	int ret = 0;

	list_for_each_entry(conf_err, &defpx->conf.errors, list) {
		new_conf_err = calloc(1, sizeof(*new_conf_err));
		if (!new_conf_err) {
			memprintf(errmsg, "unable to duplicate default errors (out of memory).");
			goto out;
		}
		new_conf_err->type = conf_err->type;
		if (conf_err->type == 1) {
			new_conf_err->info.errorfile.status = conf_err->info.errorfile.status;
			new_conf_err->info.errorfile.msg    = conf_err->info.errorfile.msg;
		}
		else {
			new_conf_err->info.errorfiles.name = strdup(conf_err->info.errorfiles.name);
			if (!new_conf_err->info.errorfiles.name) {
				memprintf(errmsg, "unable to duplicate default errors (out of memory).");
				goto out;
			}
			memcpy(&new_conf_err->info.errorfiles.status, &conf_err->info.errorfiles.status,
			       sizeof(conf_err->info.errorfiles.status));
		}
		new_conf_err->file = strdup(conf_err->file);
		new_conf_err->line = conf_err->line;
		LIST_ADDQ(&curpx->conf.errors, &new_conf_err->list);
		new_conf_err = NULL;
	}
	ret = 1;

  out:
	free(new_conf_err);
	return ret;
}

void proxy_release_conf_errors(struct proxy *px)
{
	struct conf_errors *conf_err, *conf_err_back;

	list_for_each_entry_safe(conf_err, conf_err_back, &px->conf.errors, list) {
		if (conf_err->type == 0)
			free(conf_err->info.errorfiles.name);
		LIST_DEL(&conf_err->list);
		free(conf_err->file);
		free(conf_err);
	}
}

/*
 * Parse an <http-errors> section.
 * Returns the error code, 0 if OK, or any combination of :
 *  - ERR_ABORT: must abort ASAP
 *  - ERR_FATAL: we can continue parsing but not start the service
 *  - ERR_WARN: a warning has been emitted
 *  - ERR_ALERT: an alert has been emitted
 * Only the two first ones can stop processing, the two others are just
 * indicators.
 */
static int cfg_parse_http_errors(const char *file, int linenum, char **args, int kwm)
{
	static struct http_errors *curr_errs = NULL;
	int err_code = 0;
	const char *err;
	char *errmsg = NULL;

	if (strcmp(args[0], "http-errors") == 0) { /* new errors section */
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : missing name for http-errors section.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
				 file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
		}

		list_for_each_entry(curr_errs, &http_errors_list, list) {
			/* Error if two errors section owns the same name */
			if (strcmp(curr_errs->id, args[1]) == 0) {
				ha_alert("parsing [%s:%d]: http-errors section '%s' already exists (declared at %s:%d).\n",
					 file, linenum, args[1], curr_errs->conf.file, curr_errs->conf.line);
				err_code |= ERR_ALERT | ERR_FATAL;
			}
		}

		if ((curr_errs = calloc(1, sizeof(*curr_errs))) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		LIST_ADDQ(&http_errors_list, &curr_errs->list);
		curr_errs->id = strdup(args[1]);
		curr_errs->conf.file = strdup(file);
		curr_errs->conf.line = linenum;
	}
	else if (!strcmp(args[0], "errorfile")) { /* error message from a file */
		struct buffer *msg;
		int status, rc;

		if (*(args[1]) == 0 || *(args[2]) == 0) {
			ha_alert("parsing [%s:%d] : %s: expects <status_code> and <file> as arguments.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		status = atol(args[1]);
		msg = http_parse_errorfile(status, args[2], &errmsg);
		if (!msg) {
			ha_alert("parsing [%s:%d] : %s : %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		rc = http_get_status_idx(status);
		curr_errs->errmsg[rc] = msg;
	}
	else if (*args[0] != 0) {
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], cursection);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

out:
	free(errmsg);
	return err_code;
}

static struct cfg_kw_list cfg_kws = {ILH, {
        { CFG_LISTEN, "errorloc",     proxy_parse_errorloc },
        { CFG_LISTEN, "errorloc302",  proxy_parse_errorloc },
        { CFG_LISTEN, "errorloc303",  proxy_parse_errorloc },
        { CFG_LISTEN, "errorfile",    proxy_parse_errorfile },
        { CFG_LISTEN, "errorfiles",   proxy_parse_errorfiles },
        { 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
REGISTER_POST_PROXY_CHECK(proxy_check_errors);
REGISTER_POST_CHECK(post_check_errors);

REGISTER_CONFIG_SECTION("http-errors", cfg_parse_http_errors, NULL);

/************************************************************************/
/*                             HTX sample fetches                       */
/************************************************************************/

/* Returns 1 if a stream is an HTX stream. Otherwise, it returns 0. */
static int
smp_fetch_is_htx(const struct arg *arg_p, struct sample *smp, const char *kw, void *private)
{
	if (!smp->strm)
		return 0;

	smp->data.u.sint = !!IS_HTX_STRM(smp->strm);
	smp->data.type   = SMP_T_BOOL;
	return 1;
}

/* Returns the number of blocks in an HTX message. The channel is chosen
 * depending on the sample direction. */
static int
smp_fetch_htx_nbblks(const struct arg *arg_p, struct sample *smp, const char *kw, void *private)
{
	struct channel *chn;
	struct htx *htx;

	if (!smp->strm)
		return 0;

	chn = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_RES) ? &smp->strm->res : &smp->strm->req;
	htx = smp_prefetch_htx(smp, chn, 0);
	if (!htx)
		return 0;

	smp->data.u.sint = htx_nbblks(htx);
	smp->data.type   = SMP_T_SINT;
	smp->flags = SMP_F_VOLATILE | SMP_F_MAY_CHANGE;
	return 1;
}

/* Returns the size of an HTX message. The channel is chosen depending on the
 * sample direction. */
static int
smp_fetch_htx_size(const struct arg *arg_p, struct sample *smp, const char *kw, void *private)
{
	struct channel *chn;
	struct htx *htx;

	if (!smp->strm)
		return 0;

	chn = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_RES) ? &smp->strm->res : &smp->strm->req;
	htx = smp_prefetch_htx(smp, chn, 0);
	if (!htx)
		return 0;

	smp->data.u.sint = htx->size;
	smp->data.type   = SMP_T_SINT;
	smp->flags = SMP_F_VOLATILE | SMP_F_MAY_CHANGE;
	return 1;
}

/* Returns the data size of an HTX message. The channel is chosen depending on the
 * sample direction. */
static int
smp_fetch_htx_data(const struct arg *arg_p, struct sample *smp, const char *kw, void *private)
{
	struct channel *chn;
	struct htx *htx;

	if (!smp->strm)
		return 0;

	chn = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_RES) ? &smp->strm->res : &smp->strm->req;
	htx = smp_prefetch_htx(smp, chn, 0);
	if (!htx)
		return 0;

	smp->data.u.sint = htx->data;
	smp->data.type   = SMP_T_SINT;
	smp->flags = SMP_F_VOLATILE | SMP_F_MAY_CHANGE;
	return 1;
}

/* Returns the used space (data+meta) of an HTX message. The channel is chosen
 * depending on the sample direction. */
static int
smp_fetch_htx_used(const struct arg *arg_p, struct sample *smp, const char *kw, void *private)
{
	struct channel *chn;
	struct htx *htx;

	if (!smp->strm)
		return 0;

	chn = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_RES) ? &smp->strm->res : &smp->strm->req;
	htx = smp_prefetch_htx(smp, chn, 0);
	if (!htx)
		return 0;

	smp->data.u.sint = htx_used_space(htx);
	smp->data.type   = SMP_T_SINT;
	smp->flags = SMP_F_VOLATILE | SMP_F_MAY_CHANGE;
	return 1;
}

/* Returns the free space (size-used) of an HTX message. The channel is chosen
 * depending on the sample direction. */
static int
smp_fetch_htx_free(const struct arg *arg_p, struct sample *smp, const char *kw, void *private)
{
	struct channel *chn;
	struct htx *htx;

	if (!smp->strm)
		return 0;

	chn = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_RES) ? &smp->strm->res : &smp->strm->req;
	htx = smp_prefetch_htx(smp, chn, 0);
	if (!htx)
		return 0;

	smp->data.u.sint = htx_free_space(htx);
	smp->data.type   = SMP_T_SINT;
	smp->flags = SMP_F_VOLATILE | SMP_F_MAY_CHANGE;
	return 1;
}

/* Returns the free space for data (free-sizeof(blk)) of an HTX message. The
 * channel is chosen depending on the sample direction. */
static int
smp_fetch_htx_free_data(const struct arg *arg_p, struct sample *smp, const char *kw, void *private)
{
	struct channel *chn;
	struct htx *htx;

	if (!smp->strm)
		return 0;

	chn = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_RES) ? &smp->strm->res : &smp->strm->req;
	htx = smp_prefetch_htx(smp, chn, 0);
	if (!htx)
		return 0;

	smp->data.u.sint = htx_free_data_space(htx);
	smp->data.type   = SMP_T_SINT;
	smp->flags = SMP_F_VOLATILE | SMP_F_MAY_CHANGE;
	return 1;
}

/* Returns 1 if the HTX message contains an EOM block. Otherwise it returns
 * 0. Concretely, it only checks the tail. The channel is chosen depending on
 * the sample direction. */
static int
smp_fetch_htx_has_eom(const struct arg *arg_p, struct sample *smp, const char *kw, void *private)
{
	struct channel *chn;
	struct htx *htx;

	if (!smp->strm)
		return 0;

	chn = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_RES) ? &smp->strm->res : &smp->strm->req;
	htx = smp_prefetch_htx(smp, chn, 0);
	if (!htx)
		return 0;

	smp->data.u.sint = (htx_get_tail_type(htx) == HTX_BLK_EOM);
	smp->data.type   = SMP_T_BOOL;
	smp->flags = SMP_F_VOLATILE | SMP_F_MAY_CHANGE;
	return 1;
}

/* Returns the type of a specific HTX block, if found in the message. Otherwise
 * HTX_BLK_UNUSED is returned. Any positive integer (>= 0) is supported or
 * "head", "tail" or "first". The channel is chosen depending on the sample
 * direction. */
static int
smp_fetch_htx_blk_type(const struct arg *arg_p, struct sample *smp, const char *kw, void *private)
{
	struct channel *chn;
	struct htx *htx;
	enum htx_blk_type type;
	int32_t pos;

	if (!smp->strm || !arg_p)
		return 0;

	chn = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_RES) ? &smp->strm->res : &smp->strm->req;
	htx = smp_prefetch_htx(smp, chn, 0);
	if (!htx)
		return 0;

	pos = arg_p[0].data.sint;
	if (pos == -1)
		type = htx_get_head_type(htx);
	else if (pos == -2)
		type = htx_get_tail_type(htx);
	else if (pos == -3)
		type = htx_get_first_type(htx);
	else
		type = ((pos >= htx->head && pos <= htx->tail)
			? htx_get_blk_type(htx_get_blk(htx, pos))
			: HTX_BLK_UNUSED);

	chunk_initstr(&smp->data.u.str, htx_blk_type_str(type));
	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_CONST | SMP_F_VOLATILE | SMP_F_MAY_CHANGE;
	return 1;
}

/* Returns the size of a specific HTX block, if found in the message. Otherwise
 * 0 is returned. Any positive integer (>= 0) is supported or "head", "tail" or
 * "first". The channel is chosen depending on the sample direction. */
static int
smp_fetch_htx_blk_size(const struct arg *arg_p, struct sample *smp, const char *kw, void *private)
{
	struct channel *chn;
	struct htx *htx;
	struct htx_blk *blk;
	int32_t pos;

	if (!smp->strm || !arg_p)
		return 0;

	chn = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_RES) ? &smp->strm->res : &smp->strm->req;
	htx = smp_prefetch_htx(smp, chn, 0);
	if (!htx)
		return 0;

	pos = arg_p[0].data.sint;
	if (pos == -1)
		blk = htx_get_head_blk(htx);
	else if (pos == -2)
		blk = htx_get_tail_blk(htx);
	else if (pos == -3)
		blk = htx_get_first_blk(htx);
	else
		blk = ((pos >= htx->head && pos <= htx->tail) ? htx_get_blk(htx, pos) : NULL);

	smp->data.u.sint = (blk ? htx_get_blksz(blk) : 0);
	smp->data.type = SMP_T_SINT;
	smp->flags = SMP_F_VOLATILE | SMP_F_MAY_CHANGE;
	return 1;
}

/* Returns the start-line if the selected HTX block exists and is a
 * start-line. Otherwise 0 an empty string. Any positive integer (>= 0) is
 * supported or "head", "tail" or "first". The channel is chosen depending on
 * the sample direction. */
static int
smp_fetch_htx_blk_stline(const struct arg *arg_p, struct sample *smp, const char *kw, void *private)
{
	struct buffer *temp;
	struct channel *chn;
	struct htx *htx;
	struct htx_blk *blk;
	struct htx_sl *sl;
	int32_t pos;

	if (!smp->strm || !arg_p)
		return 0;

	chn = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_RES) ? &smp->strm->res : &smp->strm->req;
	htx = smp_prefetch_htx(smp, chn, 0);
	if (!htx)
		return 0;

	pos = arg_p[0].data.sint;
	if (pos == -1)
		blk = htx_get_head_blk(htx);
	else if (pos == -2)
		blk = htx_get_tail_blk(htx);
	else if (pos == -3)
		blk = htx_get_first_blk(htx);
	else
		blk = ((pos >= htx->head && pos <= htx->tail) ? htx_get_blk(htx, pos) : NULL);

	if (!blk || (htx_get_blk_type(blk) != HTX_BLK_REQ_SL && htx_get_blk_type(blk) != HTX_BLK_RES_SL)) {
		smp->data.u.str.size = 0;
		smp->data.u.str.area = "";
		smp->data.u.str.data = 0;
	}
	else {
		sl = htx_get_blk_ptr(htx, blk);

		temp = get_trash_chunk();
		chunk_istcat(temp, htx_sl_p1(sl));
		temp->area[temp->data++] = ' ';
		chunk_istcat(temp, htx_sl_p2(sl));
		temp->area[temp->data++] = ' ';
		chunk_istcat(temp, htx_sl_p3(sl));

		smp->data.u.str = *temp;
	}

	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_VOLATILE | SMP_F_MAY_CHANGE;
	return 1;
}

/* Returns the header name if the selected HTX block exists and is a header or a
 * trailer. Otherwise 0 an empty string. Any positive integer (>= 0) is
 * supported or "head", "tail" or "first". The channel is chosen depending on
 * the sample direction. */
static int
smp_fetch_htx_blk_hdrname(const struct arg *arg_p, struct sample *smp, const char *kw, void *private)
{
	struct channel *chn;
	struct htx *htx;
	struct htx_blk *blk;
	int32_t pos;

	if (!smp->strm || !arg_p)
		return 0;

	chn = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_RES) ? &smp->strm->res : &smp->strm->req;
	htx = smp_prefetch_htx(smp, chn, 0);
	if (!htx)
		return 0;

	pos = arg_p[0].data.sint;
	if (pos == -1)
		blk = htx_get_head_blk(htx);
	else if (pos == -2)
		blk = htx_get_tail_blk(htx);
	else if (pos == -3)
		blk = htx_get_first_blk(htx);
	else
		blk = ((pos >= htx->head && pos <= htx->tail) ? htx_get_blk(htx, pos) : NULL);

	if (!blk || (htx_get_blk_type(blk) != HTX_BLK_HDR && htx_get_blk_type(blk) != HTX_BLK_TLR)) {
		smp->data.u.str.size = 0;
		smp->data.u.str.area = "";
		smp->data.u.str.data = 0;
	}
	else {
		struct ist name = htx_get_blk_name(htx, blk);

		chunk_initlen(&smp->data.u.str, name.ptr, name.len, name.len);
	}
	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_CONST | SMP_F_VOLATILE | SMP_F_MAY_CHANGE;
	return 1;
}

/* Returns the header value if the selected HTX block exists and is a header or
 * a trailer. Otherwise 0 an empty string. Any positive integer (>= 0) is
 * supported or "head", "tail" or "first". The channel is chosen depending on
 * the sample direction. */
static int
smp_fetch_htx_blk_hdrval(const struct arg *arg_p, struct sample *smp, const char *kw, void *private)
{
	struct channel *chn;
	struct htx *htx;
	struct htx_blk *blk;
	int32_t pos;

	if (!smp->strm || !arg_p)
		return 0;

	chn = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_RES) ? &smp->strm->res : &smp->strm->req;
	htx = smp_prefetch_htx(smp, chn, 0);
	if (!htx)
		return 0;

	pos = arg_p[0].data.sint;
	if (pos == -1)
		blk = htx_get_head_blk(htx);
	else if (pos == -2)
		blk = htx_get_tail_blk(htx);
	else if (pos == -3)
		blk = htx_get_first_blk(htx);
	else
		blk = ((pos >= htx->head && pos <= htx->tail) ? htx_get_blk(htx, pos) : NULL);

	if (!blk || (htx_get_blk_type(blk) != HTX_BLK_HDR && htx_get_blk_type(blk) != HTX_BLK_TLR)) {
		smp->data.u.str.size = 0;
		smp->data.u.str.area = "";
		smp->data.u.str.data = 0;
	}
	else {
		struct ist val = htx_get_blk_value(htx, blk);

		chunk_initlen(&smp->data.u.str, val.ptr, val.len, val.len);
	}
	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_CONST | SMP_F_VOLATILE | SMP_F_MAY_CHANGE;
	return 1;
}

/* Returns the value if the selected HTX block exists and is a data
 * block. Otherwise 0 an empty string. Any positive integer (>= 0) is supported
 * or "head", "tail" or "first". The channel is chosen depending on the sample
 * direction. */
static int
smp_fetch_htx_blk_data(const struct arg *arg_p, struct sample *smp, const char *kw, void *private)
{
	struct channel *chn;
	struct htx *htx;
	struct htx_blk *blk;
	int32_t pos;

	if (!smp->strm || !arg_p)
		return 0;

	chn = ((smp->opt & SMP_OPT_DIR) == SMP_OPT_DIR_RES) ? &smp->strm->res : &smp->strm->req;
	htx = smp_prefetch_htx(smp, chn, 0);
	if (!htx)
		return 0;

	pos = arg_p[0].data.sint;
	if (pos == -1)
		blk = htx_get_head_blk(htx);
	else if (pos == -2)
		blk = htx_get_tail_blk(htx);
	else if (pos == -3)
		blk = htx_get_first_blk(htx);
	else
		blk = ((pos >= htx->head && pos <= htx->tail) ? htx_get_blk(htx, pos) : NULL);

	if (!blk || htx_get_blk_type(blk) != HTX_BLK_DATA) {
		smp->data.u.str.size = 0;
		smp->data.u.str.area = "";
		smp->data.u.str.data = 0;
	}
	else {
		struct ist val = htx_get_blk_value(htx, blk);

		chunk_initlen(&smp->data.u.str, val.ptr, val.len, val.len);
	}
	smp->data.type = SMP_T_BIN;
	smp->flags = SMP_F_CONST | SMP_F_VOLATILE | SMP_F_MAY_CHANGE;
	return 1;
}

/* This function is used to validate the arguments passed to any "htx_blk" fetch
 * keywords. An argument is expected by these keywords. It must be a positive
 * integer or on of the following strings: "head", "tail" or "first". It returns
 * 0 on error, and a non-zero value if OK.
 */
int val_blk_arg(struct arg *arg, char **err_msg)
{
	if (arg[0].type != ARGT_STR || !arg[0].data.str.data) {
		memprintf(err_msg, "a block position is expected (> 0) or a special block name (head, tail, first)");
		return 0;
	}
	if (arg[0].data.str.data == 4 && !strncmp(arg[0].data.str.area, "head", 4)) {
		free(arg[0].data.str.area);
		arg[0].type = ARGT_SINT;
		arg[0].data.sint = -1;
	}
	else if (arg[0].data.str.data == 4 && !strncmp(arg[0].data.str.area, "tail", 4)) {
		free(arg[0].data.str.area);
		arg[0].type = ARGT_SINT;
		arg[0].data.sint = -2;
	}
	else if (arg[0].data.str.data == 5 && !strncmp(arg[0].data.str.area, "first", 5)) {
		free(arg[0].data.str.area);
		arg[0].type = ARGT_SINT;
		arg[0].data.sint = -3;
	}
	else {
		int pos;

		for (pos = 0; pos < arg[0].data.str.data; pos++) {
			if (!isdigit((unsigned char)arg[0].data.str.area[pos])) {
				memprintf(err_msg, "invalid block position");
				return 0;
			}
		}

		pos = strl2uic(arg[0].data.str.area, arg[0].data.str.data);
		if (pos < 0) {
			memprintf(err_msg, "block position must not be negative");
			return 0;
		}
		free(arg[0].data.str.area);
		arg[0].type = ARGT_SINT;
		arg[0].data.sint = pos;
	}

	return 1;
}


/* Note: must not be declared <const> as its list will be overwritten.
 * Note: htx sample fetches should only used for development purpose.
 */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
	{ "internal.strm.is_htx",         smp_fetch_is_htx,           0,            NULL,           SMP_T_BOOL, SMP_USE_L6REQ },

	{ "internal.htx.nbblks",          smp_fetch_htx_nbblks,       0,            NULL,           SMP_T_SINT,  SMP_USE_HRQHV|SMP_USE_HRSHV},
	{ "internal.htx.size",            smp_fetch_htx_size,         0,            NULL,           SMP_T_SINT,  SMP_USE_HRQHV|SMP_USE_HRSHV},
	{ "internal.htx.data",            smp_fetch_htx_data,         0,            NULL,           SMP_T_SINT,  SMP_USE_HRQHV|SMP_USE_HRSHV},
	{ "internal.htx.used",            smp_fetch_htx_used,         0,            NULL,           SMP_T_SINT,  SMP_USE_HRQHV|SMP_USE_HRSHV},
	{ "internal.htx.free",            smp_fetch_htx_free,         0,            NULL,           SMP_T_SINT,  SMP_USE_HRQHV|SMP_USE_HRSHV},
	{ "internal.htx.free_data",       smp_fetch_htx_free_data,    0,            NULL,           SMP_T_SINT,  SMP_USE_HRQHV|SMP_USE_HRSHV},
	{ "internal.htx.has_eom",         smp_fetch_htx_has_eom,      0,            NULL,           SMP_T_BOOL,  SMP_USE_HRQHV|SMP_USE_HRSHV},

	{ "internal.htx_blk.type",        smp_fetch_htx_blk_type,     ARG1(1,STR),  val_blk_arg,    SMP_T_STR,   SMP_USE_HRQHV|SMP_USE_HRSHV},
	{ "internal.htx_blk.size",        smp_fetch_htx_blk_size,     ARG1(1,STR),  val_blk_arg,    SMP_T_SINT,  SMP_USE_HRQHV|SMP_USE_HRSHV},
	{ "internal.htx_blk.start_line",  smp_fetch_htx_blk_stline,   ARG1(1,STR),  val_blk_arg,    SMP_T_STR,   SMP_USE_HRQHV|SMP_USE_HRSHV},
	{ "internal.htx_blk.hdrname",     smp_fetch_htx_blk_hdrname,  ARG1(1,STR),  val_blk_arg,    SMP_T_STR,   SMP_USE_HRQHV|SMP_USE_HRSHV},
	{ "internal.htx_blk.hdrval",      smp_fetch_htx_blk_hdrval,   ARG1(1,STR),  val_blk_arg,    SMP_T_STR,   SMP_USE_HRQHV|SMP_USE_HRSHV},
	{ "internal.htx_blk.data",        smp_fetch_htx_blk_data,     ARG1(1,STR),  val_blk_arg,    SMP_T_BIN,   SMP_USE_HRQHV|SMP_USE_HRSHV},

	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &sample_fetch_keywords);
