/*
 * Legacy HTTP protocol manipulation
 * If you think you need something from this file, you're mistaken as it will
 * soon be removed. Please check http_htx.c instead!
 *
 * Copyright 2000-2011 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */
#include <proto/channel.h>
#include <proto/hdr_idx.h>
#include <proto/proto_http.h>

/*
 * Adds a header and its CRLF at the tail of the message's buffer, just before
 * the last CRLF. <len> bytes are copied, not counting the CRLF.
 * The header is also automatically added to the index <hdr_idx>, and the end
 * of headers is automatically adjusted. The number of bytes added is returned
 * on success, otherwise <0 is returned indicating an error.
 */
int http_header_add_tail2(struct http_msg *msg,
                          struct hdr_idx *hdr_idx, const char *text, int len)
{
	int bytes;

	bytes = ci_insert_line2(msg->chn, msg->eoh, text, len);
	if (!bytes)
		return -1;
	http_msg_move_end(msg, bytes);
	return hdr_idx_add(len, 1, hdr_idx, hdr_idx->tail);
}

/* Find the first or next occurrence of header <name> in message buffer <sol>
 * using headers index <idx>, and return it in the <ctx> structure. This
 * structure holds everything necessary to use the header and find next
 * occurrence. If its <idx> member is 0, the header is searched from the
 * beginning. Otherwise, the next occurrence is returned. The function returns
 * 1 when it finds a value, and 0 when there is no more. It is very similar to
 * http_find_header2() except that it is designed to work with full-line headers
 * whose comma is not a delimiter but is part of the syntax. As a special case,
 * if ctx->val is NULL when searching for a new values of a header, the current
 * header is rescanned. This allows rescanning after a header deletion.
 */
int http_find_full_header2(const char *name, int len,
                           char *sol, struct hdr_idx *idx,
                           struct hdr_ctx *ctx)
{
	char *eol, *sov;
	int cur_idx, old_idx;

	cur_idx = ctx->idx;
	if (cur_idx) {
		/* We have previously returned a header, let's search another one */
		sol = ctx->line;
		eol = sol + idx->v[cur_idx].len;
		goto next_hdr;
	}

	/* first request for this header */
	sol += hdr_idx_first_pos(idx);
	old_idx = 0;
	cur_idx = hdr_idx_first_idx(idx);
	while (cur_idx) {
		eol = sol + idx->v[cur_idx].len;

		if (len == 0) {
			/* No argument was passed, we want any header.
			 * To achieve this, we simply build a fake request. */
			while (sol + len < eol && sol[len] != ':')
				len++;
			name = sol;
		}

		if ((len < eol - sol) &&
		    (sol[len] == ':') &&
		    (strncasecmp(sol, name, len) == 0)) {
			ctx->del = len;
			sov = sol + len + 1;
			while (sov < eol && HTTP_IS_LWS(*sov))
				sov++;

			ctx->line = sol;
			ctx->prev = old_idx;
			ctx->idx  = cur_idx;
			ctx->val  = sov - sol;
			ctx->tws = 0;
			while (eol > sov && HTTP_IS_LWS(*(eol - 1))) {
				eol--;
				ctx->tws++;
			}
			ctx->vlen = eol - sov;
			return 1;
		}
	next_hdr:
		sol = eol + idx->v[cur_idx].cr + 1;
		old_idx = cur_idx;
		cur_idx = idx->v[cur_idx].next;
	}
	return 0;
}

/* Find the first or next header field in message buffer <sol> using headers
 * index <idx>, and return it in the <ctx> structure. This structure holds
 * everything necessary to use the header and find next occurrence. If its
 * <idx> member is 0, the first header is retrieved. Otherwise, the next
 * occurrence is returned. The function returns 1 when it finds a value, and
 * 0 when there is no more. It is equivalent to http_find_full_header2() with
 * no header name.
 */
int http_find_next_header(char *sol, struct hdr_idx *idx, struct hdr_ctx *ctx)
{
	char *eol, *sov;
	int cur_idx, old_idx;
	int len;

	cur_idx = ctx->idx;
	if (cur_idx) {
		/* We have previously returned a header, let's search another one */
		sol = ctx->line;
		eol = sol + idx->v[cur_idx].len;
		goto next_hdr;
	}

	/* first request for this header */
	sol += hdr_idx_first_pos(idx);
	old_idx = 0;
	cur_idx = hdr_idx_first_idx(idx);
	while (cur_idx) {
		eol = sol + idx->v[cur_idx].len;

		len = 0;
		while (1) {
			if (len >= eol - sol)
				goto next_hdr;
			if (sol[len] == ':')
				break;
			len++;
		}

		ctx->del = len;
		sov = sol + len + 1;
		while (sov < eol && HTTP_IS_LWS(*sov))
			sov++;

		ctx->line = sol;
		ctx->prev = old_idx;
		ctx->idx  = cur_idx;
		ctx->val  = sov - sol;
		ctx->tws = 0;

		while (eol > sov && HTTP_IS_LWS(*(eol - 1))) {
			eol--;
			ctx->tws++;
		}
		ctx->vlen = eol - sov;
		return 1;

	next_hdr:
		sol = eol + idx->v[cur_idx].cr + 1;
		old_idx = cur_idx;
		cur_idx = idx->v[cur_idx].next;
	}
	return 0;
}

/* Find the first or next occurrence of header <name> in message buffer <sol>
 * using headers index <idx>, and return it in the <ctx> structure. This
 * structure holds everything necessary to use the header and find next
 * occurrence. If its <idx> member is 0, the header is searched from the
 * beginning. Otherwise, the next occurrence is returned. The function returns
 * 1 when it finds a value, and 0 when there is no more. It is designed to work
 * with headers defined as comma-separated lists. As a special case, if ctx->val
 * is NULL when searching for a new values of a header, the current header is
 * rescanned. This allows rescanning after a header deletion.
 */
int http_find_header2(const char *name, int len,
		      char *sol, struct hdr_idx *idx,
		      struct hdr_ctx *ctx)
{
	char *eol, *sov;
	int cur_idx, old_idx;

	cur_idx = ctx->idx;
	if (cur_idx) {
		/* We have previously returned a value, let's search
		 * another one on the same line.
		 */
		sol = ctx->line;
		ctx->del = ctx->val + ctx->vlen + ctx->tws;
		sov = sol + ctx->del;
		eol = sol + idx->v[cur_idx].len;

		if (sov >= eol)
			/* no more values in this header */
			goto next_hdr;

		/* values remaining for this header, skip the comma but save it
		 * for later use (eg: for header deletion).
		 */
		sov++;
		while (sov < eol && HTTP_IS_LWS((*sov)))
			sov++;

		goto return_hdr;
	}

	/* first request for this header */
	sol += hdr_idx_first_pos(idx);
	old_idx = 0;
	cur_idx = hdr_idx_first_idx(idx);
	while (cur_idx) {
		eol = sol + idx->v[cur_idx].len;

		if (len == 0) {
			/* No argument was passed, we want any header.
			 * To achieve this, we simply build a fake request. */
			while (sol + len < eol && sol[len] != ':')
				len++;
			name = sol;
		}

		if ((len < eol - sol) &&
		    (sol[len] == ':') &&
		    (strncasecmp(sol, name, len) == 0)) {
			ctx->del = len;
			sov = sol + len + 1;
			while (sov < eol && HTTP_IS_LWS(*sov))
				sov++;

			ctx->line = sol;
			ctx->prev = old_idx;
		return_hdr:
			ctx->idx  = cur_idx;
			ctx->val  = sov - sol;

			eol = http_find_hdr_value_end(sov, eol);
			ctx->tws = 0;
			while (eol > sov && HTTP_IS_LWS(*(eol - 1))) {
				eol--;
				ctx->tws++;
			}
			ctx->vlen = eol - sov;
			return 1;
		}
	next_hdr:
		sol = eol + idx->v[cur_idx].cr + 1;
		old_idx = cur_idx;
		cur_idx = idx->v[cur_idx].next;
	}
	return 0;
}

/* Remove one value of a header. This only works on a <ctx> returned by one of
 * the http_find_header functions. The value is removed, as well as surrounding
 * commas if any. If the removed value was alone, the whole header is removed.
 * The ctx is always updated accordingly, as well as the buffer and HTTP
 * message <msg>. The new index is returned. If it is zero, it means there is
 * no more header, so any processing may stop. The ctx is always left in a form
 * that can be handled by http_find_header2() to find next occurrence.
 */
int http_remove_header2(struct http_msg *msg, struct hdr_idx *idx, struct hdr_ctx *ctx)
{
	int cur_idx = ctx->idx;
	char *sol = ctx->line;
	struct hdr_idx_elem *hdr;
	int delta, skip_comma;

	if (!cur_idx)
		return 0;

	hdr = &idx->v[cur_idx];
	if (sol[ctx->del] == ':' && ctx->val + ctx->vlen + ctx->tws == hdr->len) {
		/* This was the only value of the header, we must now remove it entirely. */
		delta = b_rep_blk(&msg->chn->buf, sol, sol + hdr->len + hdr->cr + 1, NULL, 0);
		http_msg_move_end(msg, delta);
		idx->used--;
		hdr->len = 0;   /* unused entry */
		idx->v[ctx->prev].next = idx->v[ctx->idx].next;
		if (idx->tail == ctx->idx)
			idx->tail = ctx->prev;
		ctx->idx = ctx->prev;    /* walk back to the end of previous header */
		ctx->line -= idx->v[ctx->idx].len + idx->v[ctx->idx].cr + 1;
		ctx->val = idx->v[ctx->idx].len; /* point to end of previous header */
		ctx->tws = ctx->vlen = 0;
		return ctx->idx;
	}

	/* This was not the only value of this header. We have to remove between
	 * ctx->del+1 and ctx->val+ctx->vlen+ctx->tws+1 included. If it is the
	 * last entry of the list, we remove the last separator.
	 */

	skip_comma = (ctx->val + ctx->vlen + ctx->tws == hdr->len) ? 0 : 1;
	delta = b_rep_blk(&msg->chn->buf, sol + ctx->del + skip_comma,
				sol + ctx->val + ctx->vlen + ctx->tws + skip_comma,
				NULL, 0);
	hdr->len += delta;
	http_msg_move_end(msg, delta);
	ctx->val = ctx->del;
	ctx->tws = ctx->vlen = 0;
	return ctx->idx;
}

int http_legacy_replace_header(struct hdr_idx *idx, struct http_msg *msg,
                               const char *name, unsigned int name_len,
                               const char *str, struct my_regex *re,
                               struct buffer *output)
{
	struct hdr_ctx ctx;
	char *buf = ci_head(msg->chn);

	ctx.idx = 0;
	while (http_find_header2(name, name_len, buf, idx, &ctx)) {
		struct hdr_idx_elem *hdr = idx->v + ctx.idx;
		int delta, len;
		char *val = ctx.line + ctx.val;
		char* val_end = val + ctx.vlen;

		if (!regex_exec_match2(re, val, val_end-val, MAX_MATCH, pmatch, 0))
			continue;

		len = exp_replace(output->area, output->size, val, str, pmatch);
		if (len == -1)
			return -1;

		delta = b_rep_blk(&msg->chn->buf, val, val_end, output->area, len);

		hdr->len += delta;
		http_msg_move_end(msg, delta);

		/* Adjust the length of the current value of the index. */
		ctx.vlen += delta;
	}
	return 0;
}

int http_legacy_replace_full_header(struct hdr_idx *idx, struct http_msg *msg,
                                    const char *name, unsigned int name_len,
                                    const char *str, struct my_regex *re,
                                    struct buffer *output)
{
	struct hdr_ctx ctx;
	char *buf = ci_head(msg->chn);

	ctx.idx = 0;
	while (http_find_full_header2(name, name_len, buf, idx, &ctx)) {
		struct hdr_idx_elem *hdr = idx->v + ctx.idx;
		int delta, len;
		char *val = ctx.line + ctx.val;
		char* val_end = val + ctx.vlen;

		if (!regex_exec_match2(re, val, val_end-val, MAX_MATCH, pmatch, 0))
			continue;

		len = exp_replace(output->area, output->size, val, str, pmatch);
		if (len == -1)
			return -1;

		delta = b_rep_blk(&msg->chn->buf, val, val_end, output->area, len);

		hdr->len += delta;
		http_msg_move_end(msg, delta);

		/* Adjust the length of the current value of the index. */
		ctx.vlen += delta;
	}
	return 0;
}

/* Return in <vptr> and <vlen> the pointer and length of occurrence <occ> of
 * header whose name is <hname> of length <hlen>. If <ctx> is null, lookup is
 * performed over the whole headers. Otherwise it must contain a valid header
 * context, initialised with ctx->idx=0 for the first lookup in a series. If
 * <occ> is positive or null, occurrence #occ from the beginning (or last ctx)
 * is returned. Occ #0 and #1 are equivalent. If <occ> is negative (and no less
 * than -MAX_HDR_HISTORY), the occurrence is counted from the last one which is
 * -1. The value fetch stops at commas, so this function is suited for use with
 * list headers.
 * The return value is 0 if nothing was found, or non-zero otherwise.
 */
unsigned int http_get_hdr(const struct http_msg *msg, const char *hname, int hlen,
			  struct hdr_idx *idx, int occ,
			  struct hdr_ctx *ctx, char **vptr, size_t *vlen)
{
	struct hdr_ctx local_ctx;
	char *ptr_hist[MAX_HDR_HISTORY];
	unsigned int len_hist[MAX_HDR_HISTORY];
	unsigned int hist_ptr;
	int found;

	if (!ctx) {
		local_ctx.idx = 0;
		ctx = &local_ctx;
	}

	if (occ >= 0) {
		/* search from the beginning */
		while (http_find_header2(hname, hlen, ci_head(msg->chn), idx, ctx)) {
			occ--;
			if (occ <= 0) {
				*vptr = ctx->line + ctx->val;
				*vlen = ctx->vlen;
				return 1;
			}
		}
		return 0;
	}

	/* negative occurrence, we scan all the list then walk back */
	if (-occ > MAX_HDR_HISTORY)
		return 0;

	found = hist_ptr = 0;
	while (http_find_header2(hname, hlen, ci_head(msg->chn), idx, ctx)) {
		ptr_hist[hist_ptr] = ctx->line + ctx->val;
		len_hist[hist_ptr] = ctx->vlen;
		if (++hist_ptr >= MAX_HDR_HISTORY)
			hist_ptr = 0;
		found++;
	}
	if (-occ > found)
		return 0;
	/* OK now we have the last occurrence in [hist_ptr-1], and we need to
	 * find occurrence -occ. 0 <= hist_ptr < MAX_HDR_HISTORY, and we have
	 * -10 <= occ <= -1. So we have to check [hist_ptr%MAX_HDR_HISTORY+occ]
	 * to remain in the 0..9 range.
	 */
	hist_ptr += occ + MAX_HDR_HISTORY;
	if (hist_ptr >= MAX_HDR_HISTORY)
		hist_ptr -= MAX_HDR_HISTORY;
	*vptr = ptr_hist[hist_ptr];
	*vlen = len_hist[hist_ptr];
	return 1;
}

/* Return in <vptr> and <vlen> the pointer and length of occurrence <occ> of
 * header whose name is <hname> of length <hlen>. If <ctx> is null, lookup is
 * performed over the whole headers. Otherwise it must contain a valid header
 * context, initialised with ctx->idx=0 for the first lookup in a series. If
 * <occ> is positive or null, occurrence #occ from the beginning (or last ctx)
 * is returned. Occ #0 and #1 are equivalent. If <occ> is negative (and no less
 * than -MAX_HDR_HISTORY), the occurrence is counted from the last one which is
 * -1. This function differs from http_get_hdr() in that it only returns full
 * line header values and does not stop at commas.
 * The return value is 0 if nothing was found, or non-zero otherwise.
 */
unsigned int http_get_fhdr(const struct http_msg *msg, const char *hname, int hlen,
			   struct hdr_idx *idx, int occ,
			   struct hdr_ctx *ctx, char **vptr, size_t *vlen)
{
	struct hdr_ctx local_ctx;
	char *ptr_hist[MAX_HDR_HISTORY];
	unsigned int len_hist[MAX_HDR_HISTORY];
	unsigned int hist_ptr;
	int found;

	if (!ctx) {
		local_ctx.idx = 0;
		ctx = &local_ctx;
	}

	if (occ >= 0) {
		/* search from the beginning */
		while (http_find_full_header2(hname, hlen, ci_head(msg->chn), idx, ctx)) {
			occ--;
			if (occ <= 0) {
				*vptr = ctx->line + ctx->val;
				*vlen = ctx->vlen;
				return 1;
			}
		}
		return 0;
	}

	/* negative occurrence, we scan all the list then walk back */
	if (-occ > MAX_HDR_HISTORY)
		return 0;

	found = hist_ptr = 0;
	while (http_find_full_header2(hname, hlen, ci_head(msg->chn), idx, ctx)) {
		ptr_hist[hist_ptr] = ctx->line + ctx->val;
		len_hist[hist_ptr] = ctx->vlen;
		if (++hist_ptr >= MAX_HDR_HISTORY)
			hist_ptr = 0;
		found++;
	}
	if (-occ > found)
		return 0;

	/* OK now we have the last occurrence in [hist_ptr-1], and we need to
	 * find occurrence -occ. 0 <= hist_ptr < MAX_HDR_HISTORY, and we have
	 * -10 <= occ <= -1. So we have to check [hist_ptr%MAX_HDR_HISTORY+occ]
	 * to remain in the 0..9 range.
	 */
	hist_ptr += occ + MAX_HDR_HISTORY;
	if (hist_ptr >= MAX_HDR_HISTORY)
		hist_ptr -= MAX_HDR_HISTORY;
	*vptr = ptr_hist[hist_ptr];
	*vlen = len_hist[hist_ptr];
	return 1;
}

