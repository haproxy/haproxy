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

/* Macros used in the HTTP/1 parser, to check for the expected presence of
 * certain bytes (ef: LF) or to skip to next byte and yield in case of failure.
 */

/* Expects to find an LF at <ptr>. If not, set <state> to <where> and jump to
 * <bad>.
 */
#define EXPECT_LF_HERE(ptr, bad, state, where)                  \
	do {                                                    \
		if (unlikely(*(ptr) != '\n')) {                 \
			state = (where);                        \
			goto bad;                               \
		}                                               \
	} while (0)

/* Increments pointer <ptr>, continues to label <more> if it's still below
 * pointer <end>, or goes to <stop> and sets <state> to <where> if the end
 * of buffer was reached.
 */
#define EAT_AND_JUMP_OR_RETURN(ptr, end, more, stop, state, where)        \
	do {                                                              \
		if (likely(++(ptr) < (end)))                              \
			goto more;                                        \
		else {                                                    \
			state = (where);                                  \
			goto stop;                                        \
		}                                                         \
	} while (0)

/*
 * This function parses a status line between <ptr> and <end>, starting with
 * parser state <state>. Only states HTTP_MSG_RPVER, HTTP_MSG_RPVER_SP,
 * HTTP_MSG_RPCODE, HTTP_MSG_RPCODE_SP and HTTP_MSG_RPREASON are handled. Others
 * will give undefined results.
 * Note that it is upon the caller's responsibility to ensure that ptr < end,
 * and that msg->sol points to the beginning of the response.
 * If a complete line is found (which implies that at least one CR or LF is
 * found before <end>, the updated <ptr> is returned, otherwise NULL is
 * returned indicating an incomplete line (which does not mean that parts have
 * not been updated). In the incomplete case, if <ret_ptr> or <ret_state> are
 * non-NULL, they are fed with the new <ptr> and <state> values to be passed
 * upon next call.
 *
 * This function was intentionally designed to be called from
 * http_msg_analyzer() with the lowest overhead. It should integrate perfectly
 * within its state machine and use the same macros, hence the need for same
 * labels and variable names. Note that msg->sol is left unchanged.
 */
const char *http_parse_stsline(struct http_msg *msg,
                               enum h1_state state, const char *ptr, const char *end,
                               unsigned int *ret_ptr, enum h1_state *ret_state)
{
	const char *msg_start = ci_head(msg->chn);

	switch (state)	{
	case HTTP_MSG_RPVER:
	http_msg_rpver:
		if (likely(HTTP_IS_VER_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpver, http_msg_ood, state, HTTP_MSG_RPVER);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			msg->sl.st.v_l = ptr - msg_start;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpver_sp, http_msg_ood, state, HTTP_MSG_RPVER_SP);
		}
		msg->err_state = HTTP_MSG_RPVER;
		state = HTTP_MSG_ERROR;
		break;

	case HTTP_MSG_RPVER_SP:
	http_msg_rpver_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			msg->sl.st.c = ptr - msg_start;
			goto http_msg_rpcode;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpver_sp, http_msg_ood, state, HTTP_MSG_RPVER_SP);
		/* so it's a CR/LF, this is invalid */
		msg->err_state = HTTP_MSG_RPVER_SP;
		state = HTTP_MSG_ERROR;
		break;

	case HTTP_MSG_RPCODE:
	http_msg_rpcode:
		if (likely(!HTTP_IS_LWS(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpcode, http_msg_ood, state, HTTP_MSG_RPCODE);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			msg->sl.st.c_l = ptr - msg_start - msg->sl.st.c;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpcode_sp, http_msg_ood, state, HTTP_MSG_RPCODE_SP);
		}

		/* so it's a CR/LF, so there is no reason phrase */
		msg->sl.st.c_l = ptr - msg_start - msg->sl.st.c;
	http_msg_rsp_reason:
		/* FIXME: should we support HTTP responses without any reason phrase ? */
		msg->sl.st.r = ptr - msg_start;
		msg->sl.st.r_l = 0;
		goto http_msg_rpline_eol;

	case HTTP_MSG_RPCODE_SP:
	http_msg_rpcode_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			msg->sl.st.r = ptr - msg_start;
			goto http_msg_rpreason;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpcode_sp, http_msg_ood, state, HTTP_MSG_RPCODE_SP);
		/* so it's a CR/LF, so there is no reason phrase */
		goto http_msg_rsp_reason;

	case HTTP_MSG_RPREASON:
	http_msg_rpreason:
		if (likely(!HTTP_IS_CRLF(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpreason, http_msg_ood, state, HTTP_MSG_RPREASON);
		msg->sl.st.r_l = ptr - msg_start - msg->sl.st.r;
	http_msg_rpline_eol:
		/* We have seen the end of line. Note that we do not
		 * necessarily have the \n yet, but at least we know that we
		 * have EITHER \r OR \n, otherwise the response would not be
		 * complete. We can then record the response length and return
		 * to the caller which will be able to register it.
		 */
		msg->sl.st.l = ptr - msg_start - msg->sol;
		return ptr;

	default:
#ifdef DEBUG_FULL
		fprintf(stderr, "FIXME !!!! impossible state at %s:%d = %d\n", __FILE__, __LINE__, state);
		exit(1);
#endif
		;
	}

 http_msg_ood:
	/* out of valid data */
	if (ret_state)
		*ret_state = state;
	if (ret_ptr)
		*ret_ptr = ptr - msg_start;
	return NULL;
}

/*
 * This function parses a request line between <ptr> and <end>, starting with
 * parser state <state>. Only states HTTP_MSG_RQMETH, HTTP_MSG_RQMETH_SP,
 * HTTP_MSG_RQURI, HTTP_MSG_RQURI_SP and HTTP_MSG_RQVER are handled. Others
 * will give undefined results.
 * Note that it is upon the caller's responsibility to ensure that ptr < end,
 * and that msg->sol points to the beginning of the request.
 * If a complete line is found (which implies that at least one CR or LF is
 * found before <end>, the updated <ptr> is returned, otherwise NULL is
 * returned indicating an incomplete line (which does not mean that parts have
 * not been updated). In the incomplete case, if <ret_ptr> or <ret_state> are
 * non-NULL, they are fed with the new <ptr> and <state> values to be passed
 * upon next call.
 *
 * This function was intentionally designed to be called from
 * http_msg_analyzer() with the lowest overhead. It should integrate perfectly
 * within its state machine and use the same macros, hence the need for same
 * labels and variable names. Note that msg->sol is left unchanged.
 */
const char *http_parse_reqline(struct http_msg *msg,
			       enum h1_state state, const char *ptr, const char *end,
			       unsigned int *ret_ptr, enum h1_state *ret_state)
{
	const char *msg_start = ci_head(msg->chn);

	switch (state)	{
	case HTTP_MSG_RQMETH:
	http_msg_rqmeth:
		if (likely(HTTP_IS_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqmeth, http_msg_ood, state, HTTP_MSG_RQMETH);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			msg->sl.rq.m_l = ptr - msg_start;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqmeth_sp, http_msg_ood, state, HTTP_MSG_RQMETH_SP);
		}

		if (likely(HTTP_IS_CRLF(*ptr))) {
			/* HTTP 0.9 request */
			msg->sl.rq.m_l = ptr - msg_start;
		http_msg_req09_uri:
			msg->sl.rq.u = ptr - msg_start;
		http_msg_req09_uri_e:
			msg->sl.rq.u_l = ptr - msg_start - msg->sl.rq.u;
		http_msg_req09_ver:
			msg->sl.rq.v = ptr - msg_start;
			msg->sl.rq.v_l = 0;
			goto http_msg_rqline_eol;
		}
		msg->err_state = HTTP_MSG_RQMETH;
		state = HTTP_MSG_ERROR;
		break;

	case HTTP_MSG_RQMETH_SP:
	http_msg_rqmeth_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			msg->sl.rq.u = ptr - msg_start;
			goto http_msg_rquri;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqmeth_sp, http_msg_ood, state, HTTP_MSG_RQMETH_SP);
		/* so it's a CR/LF, meaning an HTTP 0.9 request */
		goto http_msg_req09_uri;

	case HTTP_MSG_RQURI:
	http_msg_rquri:
#if defined(__x86_64__) ||						\
    defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || \
    defined(__ARM_ARCH_7A__)
		/* speedup: skip bytes not between 0x21 and 0x7e inclusive */
		while (ptr <= end - sizeof(int)) {
			int x = *(int *)ptr - 0x21212121;
			if (x & 0x80808080)
				break;

			x -= 0x5e5e5e5e;
			if (!(x & 0x80808080))
				break;

			ptr += sizeof(int);
		}
#endif
		if (ptr >= end) {
			state = HTTP_MSG_RQURI;
			goto http_msg_ood;
		}
	http_msg_rquri2:
		if (likely((unsigned char)(*ptr - 33) <= 93)) /* 33 to 126 included */
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rquri2, http_msg_ood, state, HTTP_MSG_RQURI);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			msg->sl.rq.u_l = ptr - msg_start - msg->sl.rq.u;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rquri_sp, http_msg_ood, state, HTTP_MSG_RQURI_SP);
		}

		if (likely((unsigned char)*ptr >= 128)) {
			/* non-ASCII chars are forbidden unless option
			 * accept-invalid-http-request is enabled in the frontend.
			 * In any case, we capture the faulty char.
			 */
			if (msg->err_pos < -1)
				goto invalid_char;
			if (msg->err_pos == -1)
				msg->err_pos = ptr - msg_start;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rquri, http_msg_ood, state, HTTP_MSG_RQURI);
		}

		if (likely(HTTP_IS_CRLF(*ptr))) {
			/* so it's a CR/LF, meaning an HTTP 0.9 request */
			goto http_msg_req09_uri_e;
		}

		/* OK forbidden chars, 0..31 or 127 */
	invalid_char:
		msg->err_pos = ptr - msg_start;
		msg->err_state = HTTP_MSG_RQURI;
		state = HTTP_MSG_ERROR;
		break;

	case HTTP_MSG_RQURI_SP:
	http_msg_rquri_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			msg->sl.rq.v = ptr - msg_start;
			goto http_msg_rqver;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rquri_sp, http_msg_ood, state, HTTP_MSG_RQURI_SP);
		/* so it's a CR/LF, meaning an HTTP 0.9 request */
		goto http_msg_req09_ver;

	case HTTP_MSG_RQVER:
	http_msg_rqver:
		if (likely(HTTP_IS_VER_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqver, http_msg_ood, state, HTTP_MSG_RQVER);

		if (likely(HTTP_IS_CRLF(*ptr))) {
			msg->sl.rq.v_l = ptr - msg_start - msg->sl.rq.v;
		http_msg_rqline_eol:
			/* We have seen the end of line. Note that we do not
			 * necessarily have the \n yet, but at least we know that we
			 * have EITHER \r OR \n, otherwise the request would not be
			 * complete. We can then record the request length and return
			 * to the caller which will be able to register it.
			 */
			msg->sl.rq.l = ptr - msg_start - msg->sol;
			return ptr;
		}

		/* neither an HTTP_VER token nor a CRLF */
		msg->err_state = HTTP_MSG_RQVER;
		state = HTTP_MSG_ERROR;
		break;

	default:
#ifdef DEBUG_FULL
		fprintf(stderr, "FIXME !!!! impossible state at %s:%d = %d\n", __FILE__, __LINE__, state);
		exit(1);
#endif
		;
	}

 http_msg_ood:
	/* out of valid data */
	if (ret_state)
		*ret_state = state;
	if (ret_ptr)
		*ret_ptr = ptr - msg_start;
	return NULL;
}

/*
 * This function parses an HTTP message, either a request or a response,
 * depending on the initial msg->msg_state. The caller is responsible for
 * ensuring that the message does not wrap. The function can be preempted
 * everywhere when data are missing and recalled at the exact same location
 * with no information loss. The message may even be realigned between two
 * calls. The header index is re-initialized when switching from
 * MSG_R[PQ]BEFORE to MSG_RPVER|MSG_RQMETH. It modifies msg->sol among other
 * fields. Note that msg->sol will be initialized after completing the first
 * state, so that none of the msg pointers has to be initialized prior to the
 * first call.
 */
void http_msg_analyzer(struct http_msg *msg, struct hdr_idx *idx)
{
	enum h1_state state;       /* updated only when leaving the FSM */
	register const char *ptr, *end; /* request pointers, to avoid dereferences */
	struct buffer *buf = &msg->chn->buf;
	char *input = b_head(buf);

	state = msg->msg_state;
	ptr = input + msg->next;
	end = b_stop(buf);

	if (unlikely(ptr >= end))
		goto http_msg_ood;

	switch (state)	{
	/*
	 * First, states that are specific to the response only.
	 * We check them first so that request and headers are
	 * closer to each other (accessed more often).
	 */
	case HTTP_MSG_RPBEFORE:
	http_msg_rpbefore:
		if (likely(HTTP_IS_TOKEN(*ptr))) {
			/* we have a start of message, but we have to check
			 * first if we need to remove some CRLF. We can only
			 * do this when o=0.
			 */
			if (unlikely(ptr != input)) {
				if (co_data(msg->chn))
					goto http_msg_ood;
				/* Remove empty leading lines, as recommended by RFC2616. */
				b_del(buf, ptr - input);
				input = b_head(buf);
			}
			msg->sol = 0;
			msg->sl.st.l = 0; /* used in debug mode */
			hdr_idx_init(idx);
			state = HTTP_MSG_RPVER;
			goto http_msg_rpver;
		}

		if (unlikely(!HTTP_IS_CRLF(*ptr))) {
			state = HTTP_MSG_RPBEFORE;
			goto http_msg_invalid;
		}

		if (unlikely(*ptr == '\n'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpbefore, http_msg_ood, state, HTTP_MSG_RPBEFORE);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpbefore_cr, http_msg_ood, state, HTTP_MSG_RPBEFORE_CR);
		/* stop here */

	case HTTP_MSG_RPBEFORE_CR:
	http_msg_rpbefore_cr:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_RPBEFORE_CR);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpbefore, http_msg_ood, state, HTTP_MSG_RPBEFORE);
		/* stop here */

	case HTTP_MSG_RPVER:
	http_msg_rpver:
	case HTTP_MSG_RPVER_SP:
	case HTTP_MSG_RPCODE:
	case HTTP_MSG_RPCODE_SP:
	case HTTP_MSG_RPREASON:
		ptr = (char *)http_parse_stsline(msg,
						 state, ptr, end,
						 &msg->next, &msg->msg_state);
		if (unlikely(!ptr))
			return;

		/* we have a full response and we know that we have either a CR
		 * or an LF at <ptr>.
		 */
		hdr_idx_set_start(idx, msg->sl.st.l, *ptr == '\r');

		msg->sol = ptr - input;
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpline_end, http_msg_ood, state, HTTP_MSG_RPLINE_END);
		goto http_msg_rpline_end;

	case HTTP_MSG_RPLINE_END:
	http_msg_rpline_end:
		/* msg->sol must point to the first of CR or LF. */
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_RPLINE_END);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_first, http_msg_ood, state, HTTP_MSG_HDR_FIRST);
		/* stop here */

	/*
	 * Second, states that are specific to the request only
	 */
	case HTTP_MSG_RQBEFORE:
	http_msg_rqbefore:
		if (likely(HTTP_IS_TOKEN(*ptr))) {
			/* we have a start of message, but we have to check
			 * first if we need to remove some CRLF. We can only
			 * do this when o=0.
			 */
			if (likely(ptr != input)) {
				if (co_data(msg->chn))
					goto http_msg_ood;
				/* Remove empty leading lines, as recommended by RFC2616. */
				b_del(buf, ptr - input);
				input = b_head(buf);
			}
			msg->sol = 0;
			msg->sl.rq.l = 0; /* used in debug mode */
			state = HTTP_MSG_RQMETH;
			goto http_msg_rqmeth;
		}

		if (unlikely(!HTTP_IS_CRLF(*ptr))) {
			state = HTTP_MSG_RQBEFORE;
			goto http_msg_invalid;
		}

		if (unlikely(*ptr == '\n'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqbefore, http_msg_ood, state, HTTP_MSG_RQBEFORE);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqbefore_cr, http_msg_ood, state, HTTP_MSG_RQBEFORE_CR);
		/* stop here */

	case HTTP_MSG_RQBEFORE_CR:
	http_msg_rqbefore_cr:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_RQBEFORE_CR);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqbefore, http_msg_ood, state, HTTP_MSG_RQBEFORE);
		/* stop here */

	case HTTP_MSG_RQMETH:
	http_msg_rqmeth:
	case HTTP_MSG_RQMETH_SP:
	case HTTP_MSG_RQURI:
	case HTTP_MSG_RQURI_SP:
	case HTTP_MSG_RQVER:
		ptr = (char *)http_parse_reqline(msg,
						 state, ptr, end,
						 &msg->next, &msg->msg_state);
		if (unlikely(!ptr))
			return;

		/* we have a full request and we know that we have either a CR
		 * or an LF at <ptr>.
		 */
		hdr_idx_set_start(idx, msg->sl.rq.l, *ptr == '\r');

		msg->sol = ptr - input;
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqline_end, http_msg_ood, state, HTTP_MSG_RQLINE_END);
		goto http_msg_rqline_end;

	case HTTP_MSG_RQLINE_END:
	http_msg_rqline_end:
		/* check for HTTP/0.9 request : no version information available.
		 * msg->sol must point to the first of CR or LF.
		 */
		if (unlikely(msg->sl.rq.v_l == 0))
			goto http_msg_last_lf;

		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_RQLINE_END);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_first, http_msg_ood, state, HTTP_MSG_HDR_FIRST);
		/* stop here */

	/*
	 * Common states below
	 */
	case HTTP_MSG_HDR_FIRST:
	http_msg_hdr_first:
		msg->sol = ptr - input;
		if (likely(!HTTP_IS_CRLF(*ptr))) {
			goto http_msg_hdr_name;
		}

		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_last_lf, http_msg_ood, state, HTTP_MSG_LAST_LF);
		goto http_msg_last_lf;

	case HTTP_MSG_HDR_NAME:
	http_msg_hdr_name:
		/* assumes msg->sol points to the first char */
		if (likely(HTTP_IS_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_name, http_msg_ood, state, HTTP_MSG_HDR_NAME);

		if (likely(*ptr == ':'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_sp, http_msg_ood, state, HTTP_MSG_HDR_L1_SP);

		if (likely(msg->err_pos < -1) || *ptr == '\n') {
			state = HTTP_MSG_HDR_NAME;
			goto http_msg_invalid;
		}

		if (msg->err_pos == -1) /* capture error pointer */
			msg->err_pos = ptr - input; /* >= 0 now */

		/* and we still accept this non-token character */
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_name, http_msg_ood, state, HTTP_MSG_HDR_NAME);

	case HTTP_MSG_HDR_L1_SP:
	http_msg_hdr_l1_sp:
		/* assumes msg->sol points to the first char */
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_sp, http_msg_ood, state, HTTP_MSG_HDR_L1_SP);

		/* header value can be basically anything except CR/LF */
		msg->sov = ptr - input;

		if (likely(!HTTP_IS_CRLF(*ptr))) {
			goto http_msg_hdr_val;
		}

		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_lf, http_msg_ood, state, HTTP_MSG_HDR_L1_LF);
		goto http_msg_hdr_l1_lf;

	case HTTP_MSG_HDR_L1_LF:
	http_msg_hdr_l1_lf:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_HDR_L1_LF);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_lws, http_msg_ood, state, HTTP_MSG_HDR_L1_LWS);

	case HTTP_MSG_HDR_L1_LWS:
	http_msg_hdr_l1_lws:
		if (likely(HTTP_IS_SPHT(*ptr))) {
			/* replace HT,CR,LF with spaces */
			for (; input + msg->sov < ptr; msg->sov++)
				input[msg->sov] = ' ';
			goto http_msg_hdr_l1_sp;
		}
		/* we had a header consisting only in spaces ! */
		msg->eol = msg->sov;
		goto http_msg_complete_header;

	case HTTP_MSG_HDR_VAL:
	http_msg_hdr_val:
		/* assumes msg->sol points to the first char, and msg->sov
		 * points to the first character of the value.
		 */

		/* speedup: we'll skip packs of 4 or 8 bytes not containing bytes 0x0D
		 * and lower. In fact since most of the time is spent in the loop, we
		 * also remove the sign bit test so that bytes 0x8e..0x0d break the
		 * loop, but we don't care since they're very rare in header values.
		 */
#if defined(__x86_64__)
		while (ptr <= end - sizeof(long)) {
			if ((*(long *)ptr - 0x0e0e0e0e0e0e0e0eULL) & 0x8080808080808080ULL)
				goto http_msg_hdr_val2;
			ptr += sizeof(long);
		}
#endif
#if defined(__x86_64__) || \
    defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || \
    defined(__ARM_ARCH_7A__)
		while (ptr <= end - sizeof(int)) {
			if ((*(int*)ptr - 0x0e0e0e0e) & 0x80808080)
				goto http_msg_hdr_val2;
			ptr += sizeof(int);
		}
#endif
		if (ptr >= end) {
			state = HTTP_MSG_HDR_VAL;
			goto http_msg_ood;
		}
	http_msg_hdr_val2:
		if (likely(!HTTP_IS_CRLF(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_val2, http_msg_ood, state, HTTP_MSG_HDR_VAL);

		msg->eol = ptr - input;
		/* Note: we could also copy eol into ->eoh so that we have the
		 * real header end in case it ends with lots of LWS, but is this
		 * really needed ?
		 */
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l2_lf, http_msg_ood, state, HTTP_MSG_HDR_L2_LF);
		goto http_msg_hdr_l2_lf;

	case HTTP_MSG_HDR_L2_LF:
	http_msg_hdr_l2_lf:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_HDR_L2_LF);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l2_lws, http_msg_ood, state, HTTP_MSG_HDR_L2_LWS);

	case HTTP_MSG_HDR_L2_LWS:
	http_msg_hdr_l2_lws:
		if (unlikely(HTTP_IS_SPHT(*ptr))) {
			/* LWS: replace HT,CR,LF with spaces */
			for (; input + msg->eol < ptr; msg->eol++)
				input[msg->eol] = ' ';
			goto http_msg_hdr_val;
		}
	http_msg_complete_header:
		/*
		 * It was a new header, so the last one is finished.
		 * Assumes msg->sol points to the first char, msg->sov points
		 * to the first character of the value and msg->eol to the
		 * first CR or LF so we know how the line ends. We insert last
		 * header into the index.
		 */
		if (unlikely(hdr_idx_add(msg->eol - msg->sol, input[msg->eol] == '\r',
					 idx, idx->tail) < 0)) {
			state = HTTP_MSG_HDR_L2_LWS;
			goto http_msg_invalid;
		}

		msg->sol = ptr - input;
		if (likely(!HTTP_IS_CRLF(*ptr))) {
			goto http_msg_hdr_name;
		}

		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_last_lf, http_msg_ood, state, HTTP_MSG_LAST_LF);
		goto http_msg_last_lf;

	case HTTP_MSG_LAST_LF:
	http_msg_last_lf:
		/* Assumes msg->sol points to the first of either CR or LF.
		 * Sets ->sov and ->next to the total header length, ->eoh to
		 * the last CRLF, and ->eol to the last CRLF length (1 or 2).
		 */
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_LAST_LF);
		ptr++;
		msg->sov = msg->next = ptr - input;
		msg->eoh = msg->sol;
		msg->sol = 0;
		msg->eol = msg->sov - msg->eoh;
		msg->msg_state = HTTP_MSG_BODY;
		return;

	case HTTP_MSG_ERROR:
		/* this may only happen if we call http_msg_analyser() twice with an error */
		break;

	default:
#ifdef DEBUG_FULL
		fprintf(stderr, "FIXME !!!! impossible state at %s:%d = %d\n", __FILE__, __LINE__, state);
		exit(1);
#endif
		;
	}
 http_msg_ood:
	/* out of data */
	msg->msg_state = state;
	msg->next = ptr - input;
	return;

 http_msg_invalid:
	/* invalid message */
	msg->err_state = state;
	msg->msg_state = HTTP_MSG_ERROR;
	msg->next = ptr - input;
	return;
}

/* This function skips trailers in the buffer associated with HTTP message
 * <msg>. The first visited position is msg->next. If the end of the trailers is
 * found, the function returns >0. So, the caller can automatically schedul it
 * to be forwarded, and switch msg->msg_state to HTTP_MSG_DONE. If not enough
 * data are available, the function does not change anything except maybe
 * msg->sol if it could parse some lines, and returns zero.  If a parse error
 * is encountered, the function returns < 0 and does not change anything except
 * maybe msg->sol. Note that the message must already be in HTTP_MSG_TRAILERS
 * state before calling this function, which implies that all non-trailers data
 * have already been scheduled for forwarding, and that msg->next exactly
 * matches the length of trailers already parsed and not forwarded. It is also
 * important to note that this function is designed to be able to parse wrapped
 * headers at end of buffer.
 */
int http_forward_trailers(struct http_msg *msg)
{
	const struct buffer *buf = &msg->chn->buf;
	const char *parse = ci_head(msg->chn);
	const char *stop  = b_tail(buf);

	/* we have msg->next which points to next line. Look for CRLF. But
	 * first, we reset msg->sol */
	msg->sol = 0;
	while (1) {
		const char *p1 = NULL, *p2 = NULL;
		const char *start = c_ptr(msg->chn, msg->next + msg->sol);
		const char *ptr   = start;

		/* scan current line and stop at LF or CRLF */
		while (1) {
			if (ptr == stop)
				return 0;

			if (*ptr == '\n') {
				if (!p1)
					p1 = ptr;
				p2 = ptr;
				break;
			}

			if (*ptr == '\r') {
				if (p1) {
					msg->err_pos = b_dist(buf, parse, ptr);
					return -1;
				}
				p1 = ptr;
			}

			ptr = b_next(buf, ptr);
		}

		/* after LF; point to beginning of next line */
		p2 = b_next(buf, p2);
		msg->sol += b_dist(buf, start, p2);

		/* LF/CRLF at beginning of line => end of trailers at p2.
		 * Everything was scheduled for forwarding, there's nothing left
		 * from this message. */
		if (p1 == start)
			return 1;

		/* OK, next line then */
	}
}
