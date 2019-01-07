/*
 * Stream filters related variables and functions.
 *
 * Copyright (C) 2015 Qualys Inc., Christopher Faulet <cfaulet@qualys.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/buffer.h>
#include <common/cfgparse.h>
#include <common/htx.h>
#include <common/initcall.h>
#include <common/mini-clist.h>
#include <common/standard.h>

#include <types/compression.h>
#include <types/filters.h>
#include <types/proxy.h>
#include <types/sample.h>

#include <proto/compression.h>
#include <proto/filters.h>
#include <proto/hdr_idx.h>
#include <proto/http_htx.h>
#include <proto/proto_http.h>
#include <proto/sample.h>
#include <proto/stream.h>

const char *http_comp_flt_id = "compression filter";

struct flt_ops comp_ops;

struct comp_state {
	struct comp_ctx  *comp_ctx;   /* compression context */
	struct comp_algo *comp_algo;  /* compression algorithm if not NULL */

	/* Following fields are used by the legacy code only: */
	int hdrs_len;
	int tlrs_len;
	int consumed;
	int initialized;
	int finished;
};

/* Pools used to allocate comp_state structs */
DECLARE_STATIC_POOL(pool_head_comp_state, "comp_state", sizeof(struct comp_state));

static THREAD_LOCAL struct buffer tmpbuf;
static THREAD_LOCAL struct buffer zbuf;

static int select_compression_request_header(struct comp_state *st,
					     struct stream *s,
					     struct http_msg *msg);
static int select_compression_response_header(struct comp_state *st,
					      struct stream *s,
					      struct http_msg *msg);
static int set_compression_response_header(struct comp_state *st,
					   struct stream *s,
					   struct http_msg *msg);

static int htx_compression_buffer_init(struct htx *htx, struct buffer *out);
static int htx_compression_buffer_add_data(struct comp_state *st, const char *data, size_t len,
					    struct buffer *out);
static int htx_compression_buffer_end(struct comp_state *st, struct buffer *out, int end);

static int http_compression_buffer_init(struct channel *inc, struct buffer *out);
static int http_compression_buffer_add_data(struct comp_state *st,
					    struct buffer *in,
					    int in_out,
					    struct buffer *out, int sz);
static int http_compression_buffer_end(struct comp_state *st, struct stream *s,
				       struct channel *chn, struct buffer *out,
				       int end);

/***********************************************************************/
static int
comp_flt_init(struct proxy *px, struct flt_conf *fconf)
{
	fconf->flags |= FLT_CFG_FL_HTX;
	return 0;
}

static int
comp_flt_init_per_thread(struct proxy *px, struct flt_conf *fconf)
{
	if (!tmpbuf.size && b_alloc(&tmpbuf) == NULL)
		return -1;
	if (!zbuf.size && b_alloc(&zbuf) == NULL)
		return -1;
	return 0;
}

static void
comp_flt_deinit_per_thread(struct proxy *px, struct flt_conf *fconf)
{
	if (tmpbuf.size)
		b_free(&tmpbuf);
	if (zbuf.size)
		b_free(&zbuf);
}

static int
comp_start_analyze(struct stream *s, struct filter *filter, struct channel *chn)
{

	if (filter->ctx == NULL) {
		struct comp_state *st;

		st = pool_alloc_dirty(pool_head_comp_state);
		if (st == NULL)
			return -1;

		st->comp_algo   = NULL;
		st->comp_ctx    = NULL;
		st->hdrs_len    = 0;
		st->tlrs_len    = 0;
		st->consumed    = 0;
		st->initialized = 0;
		st->finished    = 0;
		filter->ctx     = st;

		/* Register post-analyzer on AN_RES_WAIT_HTTP because we need to
		 * analyze response headers before http-response rules execution
		 * to be sure we can use res.comp and res.comp_algo sample
		 * fetches */
		filter->post_analyzers |= AN_RES_WAIT_HTTP;
	}
	return 1;
}

static int
comp_end_analyze(struct stream *s, struct filter *filter, struct channel *chn)
{
	struct comp_state *st = filter->ctx;

	if (!st)
		goto end;

	/* release any possible compression context */
	if (st->comp_algo)
		st->comp_algo->end(&st->comp_ctx);
	pool_free(pool_head_comp_state, st);
	filter->ctx = NULL;
 end:
	return 1;
}

static int
comp_http_headers(struct stream *s, struct filter *filter, struct http_msg *msg)
{
	struct comp_state *st = filter->ctx;

	if (!strm_fe(s)->comp && !s->be->comp)
		goto end;

	if (!(msg->chn->flags & CF_ISRESP))
		select_compression_request_header(st, s, msg);
	else {
		/* Response headers have already been checked in
		 * comp_http_post_analyze callback. */
		if (st->comp_algo) {
			if (!set_compression_response_header(st, s, msg))
				goto end;
			register_data_filter(s, msg->chn, filter);
			if (!IS_HTX_STRM(s))
				st->hdrs_len = s->txn->rsp.sov;
		}
	}

  end:
	return 1;
}

static int
comp_http_post_analyze(struct stream *s, struct filter *filter,
		       struct channel *chn, unsigned an_bit)
{
	struct http_txn   *txn = s->txn;
	struct http_msg   *msg = &txn->rsp;
	struct comp_state *st  = filter->ctx;

	if (an_bit != AN_RES_WAIT_HTTP)
		goto end;

	if (!strm_fe(s)->comp && !s->be->comp)
		goto end;

	select_compression_response_header(st, s, msg);

  end:
	return 1;
}

static int
comp_http_payload(struct stream *s, struct filter *filter, struct http_msg *msg,
		  unsigned int offset, unsigned int len)
{
	struct comp_state *st = filter->ctx;
	struct htx *htx = htxbuf(&msg->chn->buf);
	struct htx_blk *blk;
	struct htx_ret htx_ret;
	int ret, consumed = 0, to_forward = 0;

	htx_ret = htx_find_blk(htx, offset);
	blk = htx_ret.blk;
	offset = htx_ret.ret;

	while (blk && len) {
		enum htx_blk_type type = htx_get_blk_type(blk);
		uint32_t sz = htx_get_blksz(blk);
		struct ist v;

		switch (type) {
			case HTX_BLK_UNUSED:
				break;

			case HTX_BLK_DATA:
				v = htx_get_blk_value(htx, blk);
				v.ptr += offset;
				v.len -= offset;
				if (v.len > len)
					v.len = len;
				if (htx_compression_buffer_init(htx, &trash) < 0) {
					msg->chn->flags |= CF_WAKE_WRITE;
					goto end;
				}
				ret = htx_compression_buffer_add_data(st, v.ptr, v.len, &trash);
				if (ret < 0)
					goto error;
				if (htx_compression_buffer_end(st, &trash, 0) < 0)
					goto error;
				len -= ret;
				consumed += ret;
				to_forward += b_data(&trash);
				if (ret == sz && !b_data(&trash)) {
					offset = 0;
					blk = htx_remove_blk(htx, blk);
					continue;
				}
				v.len = ret;
				blk = htx_replace_blk_value(htx, blk, v, ist2(b_head(&trash), b_data(&trash)));
				break;

			case HTX_BLK_EOD:
			case HTX_BLK_TLR:
			case HTX_BLK_EOM:
				if (msg->flags & HTTP_MSGF_COMPRESSING) {
					if (htx_compression_buffer_init(htx, &trash) < 0) {
						msg->chn->flags |= CF_WAKE_WRITE;
						goto end;
					}
					if (htx_compression_buffer_end(st, &trash, 1) < 0)
						goto error;
					if (b_data(&trash)) {
						blk = htx_add_data_before(htx, blk, ist2(b_head(&trash), b_data(&trash)));
						if (!blk)
							goto error;
						to_forward += b_data(&trash);
					}
					msg->flags &= ~HTTP_MSGF_COMPRESSING;
					/* We let the mux add last empty chunk and empty trailers */
				}
				/* fall through */

			default:
				sz -= offset;
				if (sz > len)
					sz = len;
				consumed += sz;
				to_forward += sz;
				len -= sz;
				break;
		}

		offset = 0;
		blk  = htx_get_next_blk(htx, blk);
	}

  end:
	if (to_forward != consumed)
		flt_update_offsets(filter, msg->chn, to_forward - consumed);

	if (st->comp_ctx && st->comp_ctx->cur_lvl > 0) {
		update_freq_ctr(&global.comp_bps_out, to_forward);
		HA_ATOMIC_ADD(&strm_fe(s)->fe_counters.comp_out, to_forward);
		HA_ATOMIC_ADD(&s->be->be_counters.comp_out, to_forward);
	}
	return to_forward;

  error:
	return -1;
}

static int
comp_http_data(struct stream *s, struct filter *filter, struct http_msg *msg)
{
	struct comp_state *st = filter->ctx;
	struct channel    *chn = msg->chn;
	unsigned int      *nxt = &flt_rsp_nxt(filter);
	unsigned int       len;
	int                ret;

	len = MIN(msg->chunk_len + msg->next, ci_data(chn)) - *nxt;
	if (!len)
		return len;

	if (!st->initialized) {
		unsigned int fwd = flt_rsp_fwd(filter) + st->hdrs_len;

		b_reset(&tmpbuf);
		c_adv(chn, fwd);
		ret = http_compression_buffer_init(chn, &zbuf);
		c_rew(chn, fwd);
		if (ret < 0) {
			msg->chn->flags |= CF_WAKE_WRITE;
			return 0;
		}
	}

	if (msg->flags & HTTP_MSGF_TE_CHNK) {
		int block;

		len = MIN(b_room(&tmpbuf), len);

		c_adv(chn, *nxt);
		block = ci_contig_data(chn);
		memcpy(b_tail(&tmpbuf), ci_head(chn), block);
		if (len > block)
			memcpy(b_tail(&tmpbuf)+block, b_orig(&chn->buf), len-block);
		c_rew(chn, *nxt);

		b_add(&tmpbuf, len);
		ret        = len;
	}
	else {
		c_adv(chn, *nxt);
		ret = http_compression_buffer_add_data(st, &chn->buf, co_data(chn), &zbuf, len);
		c_rew(chn, *nxt);
		if (ret < 0)
			return ret;
	}

	st->initialized = 1;
	msg->next      += ret;
	msg->chunk_len -= ret;
	*nxt            = msg->next;
	return 0;
}

static int
comp_http_chunk_trailers(struct stream *s, struct filter *filter,
			 struct http_msg *msg)
{
	struct comp_state *st = filter->ctx;

	if (!st->initialized) {
		if (!st->finished) {
			struct channel *chn = msg->chn;
			unsigned int   fwd = flt_rsp_fwd(filter) + st->hdrs_len;

			b_reset(&tmpbuf);
			c_adv(chn, fwd);
			http_compression_buffer_init(chn, &zbuf);
			c_rew(chn, fwd);
			st->initialized = 1;
		}
	}
	st->tlrs_len = msg->sol;
	return 1;
}


static int
comp_http_forward_data(struct stream *s, struct filter *filter,
		       struct http_msg *msg, unsigned int len)
{
	struct comp_state *st = filter->ctx;
	int                ret;

	/* To work, previous filters MUST forward all data */
	if (flt_rsp_fwd(filter) + len != flt_rsp_nxt(filter)) {
		ha_warning("HTTP compression failed: unexpected behavior of previous filters\n");
		return -1;
	}

	if (!st->initialized) {
		if (!len) {
			/* Nothing to forward */
			ret = len;
		}
		else if (st->hdrs_len > len) {
			/* Forward part of headers */
			ret           = len;
			st->hdrs_len -= len;
		}
		else if (st->hdrs_len > 0) {
			/* Forward remaining headers */
			ret          = st->hdrs_len;
			st->hdrs_len = 0;
		}
		else if (msg->msg_state < HTTP_MSG_TRAILERS) {
			/* Do not forward anything for now. This only happens
			 * with chunk-encoded responses. Waiting data are part
			 * of the chunk envelope (the chunk size or the chunk
			 * CRLF). These data will be skipped during the
			 * compression. */
			ret = 0;
		}
		else {
			/* Forward trailers data */
			ret = len;
		}
		return ret;
	}

	if (msg->flags & HTTP_MSGF_TE_CHNK) {
		ret = http_compression_buffer_add_data(st, &tmpbuf, 0,
		    &zbuf, b_data(&tmpbuf));
		if (ret != b_data(&tmpbuf)) {
			ha_warning("HTTP compression failed: Must consume %u bytes but only %d bytes consumed\n",
				   (unsigned int)b_data(&tmpbuf), ret);
			return -1;
		}
	}

	st->consumed = len - st->hdrs_len - st->tlrs_len;
	c_adv(msg->chn, flt_rsp_fwd(filter) + st->hdrs_len);
	ret = http_compression_buffer_end(st, s, msg->chn, &zbuf, msg->msg_state >= HTTP_MSG_TRAILERS);
	c_rew(msg->chn, flt_rsp_fwd(filter) + st->hdrs_len);
	if (ret < 0)
		return ret;

	flt_change_forward_size(filter, msg->chn, ret - st->consumed);
	msg->next += (ret - st->consumed);
	ret += st->hdrs_len + st->tlrs_len;

	st->initialized = 0;
	st->finished    = (msg->msg_state >= HTTP_MSG_TRAILERS);
	st->hdrs_len    = 0;
	st->tlrs_len    = 0;
	return ret;
}

static int
comp_http_end(struct stream *s, struct filter *filter,
	      struct http_msg *msg)
{
	struct comp_state *st = filter->ctx;

	if (!(msg->chn->flags & CF_ISRESP) || !st || !st->comp_algo)
		goto end;

	if (strm_fe(s)->mode == PR_MODE_HTTP)
		HA_ATOMIC_ADD(&strm_fe(s)->fe_counters.p.http.comp_rsp, 1);
	if ((s->flags & SF_BE_ASSIGNED) && (s->be->mode == PR_MODE_HTTP))
		HA_ATOMIC_ADD(&s->be->be_counters.p.http.comp_rsp, 1);
 end:
	return 1;
}
/***********************************************************************/
static int
http_set_comp_reshdr(struct comp_state *st, struct stream *s, struct http_msg *msg)
{
	struct http_txn *txn = s->txn;

	/*
	 * Add Content-Encoding header when it's not identity encoding.
         * RFC 2616 : Identity encoding: This content-coding is used only in the
	 * Accept-Encoding header, and SHOULD NOT be used in the Content-Encoding
	 * header.
	 */
	if (st->comp_algo->cfg_name_len != 8 || memcmp(st->comp_algo->cfg_name, "identity", 8) != 0) {
		trash.data = 18;
		memcpy(trash.area, "Content-Encoding: ", trash.data);
		memcpy(trash.area + trash.data, st->comp_algo->ua_name,
		       st->comp_algo->ua_name_len);
		trash.data += st->comp_algo->ua_name_len;
		trash.area[trash.data] = '\0';
		if (http_header_add_tail2(msg, &txn->hdr_idx, trash.area, trash.data) < 0)
			goto error;
	}

	/* remove Content-Length header */
	if (msg->flags & HTTP_MSGF_CNT_LEN) {
		struct hdr_ctx ctx;

		ctx.idx = 0;
		while (http_find_header2("Content-Length", 14, ci_head(&s->res), &txn->hdr_idx, &ctx))
			http_remove_header2(msg, &txn->hdr_idx, &ctx);
	}

	/* add Transfer-Encoding header */
	if (!(msg->flags & HTTP_MSGF_TE_CHNK)) {
		if (http_header_add_tail2(msg, &txn->hdr_idx, "Transfer-Encoding: chunked", 26) < 0)
			goto error;
	}


	return 1;

  error:
	st->comp_algo->end(&st->comp_ctx);
	st->comp_algo = NULL;
	return 0;
}

static int
htx_set_comp_reshdr(struct comp_state *st, struct stream *s, struct http_msg *msg)
{
	struct htx *htx = htxbuf(&msg->chn->buf);

	/*
	 * Add Content-Encoding header when it's not identity encoding.
	 * RFC 2616 : Identity encoding: This content-coding is used only in the
	 * Accept-Encoding header, and SHOULD NOT be used in the Content-Encoding
	 * header.
	 */
	if (st->comp_algo->cfg_name_len != 8 || memcmp(st->comp_algo->cfg_name, "identity", 8) != 0) {
		struct ist v = ist2(st->comp_algo->ua_name, st->comp_algo->ua_name_len);

		if (!http_add_header(htx, ist("Content-Encoding"), v))
			goto error;
	}

	/* remove Content-Length header */
	if (msg->flags & HTTP_MSGF_CNT_LEN) {
		struct http_hdr_ctx ctx;

		ctx.blk = NULL;
		while (http_find_header(htx, ist("Content-Length"), &ctx, 1))
			http_remove_header(htx, &ctx);
	}

	/* add "Transfer-Encoding: chunked" header */
	if (!(msg->flags & HTTP_MSGF_TE_CHNK)) {
		if (!http_add_header(htx, ist("Transfer-Encoding"), ist("chunked")))
			goto error;
	}

	return 1;

  error:
	st->comp_algo->end(&st->comp_ctx);
	st->comp_algo = NULL;
	return 0;
}

static int
set_compression_response_header(struct comp_state *st, struct stream *s, struct http_msg *msg)
{
	if (IS_HTX_STRM(s))
		return htx_set_comp_reshdr(st, s, msg);
	else
		return http_set_comp_reshdr(st, s, msg);
}

/*
 * Selects a compression algorithm depending on the client request.
 */
static int
http_select_comp_reqhdr(struct comp_state *st, struct stream *s, struct http_msg *msg)
{
	struct http_txn *txn = s->txn;
	struct channel *req = msg->chn;
	struct hdr_ctx ctx;
	struct comp_algo *comp_algo = NULL;
	struct comp_algo *comp_algo_back = NULL;

	/* Disable compression for older user agents announcing themselves as "Mozilla/4"
	 * unless they are known good (MSIE 6 with XP SP2, or MSIE 7 and later).
	 * See http://zoompf.com/2012/02/lose-the-wait-http-compression for more details.
	 */
	ctx.idx = 0;
	if (http_find_header2("User-Agent", 10, ci_head(req), &txn->hdr_idx, &ctx) &&
	    ctx.vlen >= 9 &&
	    memcmp(ctx.line + ctx.val, "Mozilla/4", 9) == 0 &&
	    (ctx.vlen < 31 ||
	     memcmp(ctx.line + ctx.val + 25, "MSIE ", 5) != 0 ||
	     ctx.line[ctx.val + 30] < '6' ||
	     (ctx.line[ctx.val + 30] == '6' &&
	      (ctx.vlen < 54 || memcmp(ctx.line + 51, "SV1", 3) != 0)))) {
		st->comp_algo = NULL;
		return 0;
	}

	/* search for the algo in the backend in priority or the frontend */
	if ((s->be->comp && (comp_algo_back = s->be->comp->algos)) ||
	    (strm_fe(s)->comp && (comp_algo_back = strm_fe(s)->comp->algos))) {
		int best_q = 0;

		ctx.idx = 0;
		while (http_find_header2("Accept-Encoding", 15, ci_head(req), &txn->hdr_idx, &ctx)) {
			const char *qval;
			int q;
			int toklen;

			/* try to isolate the token from the optional q-value */
			toklen = 0;
			while (toklen < ctx.vlen && HTTP_IS_TOKEN(*(ctx.line + ctx.val + toklen)))
				toklen++;

			qval = ctx.line + ctx.val + toklen;
			while (1) {
				while (qval < ctx.line + ctx.val + ctx.vlen && HTTP_IS_LWS(*qval))
					qval++;

				if (qval >= ctx.line + ctx.val + ctx.vlen || *qval != ';') {
					qval = NULL;
					break;
				}
				qval++;

				while (qval < ctx.line + ctx.val + ctx.vlen && HTTP_IS_LWS(*qval))
					qval++;

				if (qval >= ctx.line + ctx.val + ctx.vlen) {
					qval = NULL;
					break;
				}
				if (strncmp(qval, "q=", MIN(ctx.line + ctx.val + ctx.vlen - qval, 2)) == 0)
					break;

				while (qval < ctx.line + ctx.val + ctx.vlen && *qval != ';')
					qval++;
			}

			/* here we have qval pointing to the first "q=" attribute or NULL if not found */
			q = qval ? http_parse_qvalue(qval + 2, NULL) : 1000;

			if (q <= best_q)
				continue;

			for (comp_algo = comp_algo_back; comp_algo; comp_algo = comp_algo->next) {
				if (*(ctx.line + ctx.val) == '*' ||
				    word_match(ctx.line + ctx.val, toklen, comp_algo->ua_name, comp_algo->ua_name_len)) {
					st->comp_algo = comp_algo;
					best_q = q;
					break;
				}
			}
		}
	}

	/* remove all occurrences of the header when "compression offload" is set */
	if (st->comp_algo) {
		if ((s->be->comp && s->be->comp->offload) ||
		    (strm_fe(s)->comp && strm_fe(s)->comp->offload)) {
			http_remove_header2(msg, &txn->hdr_idx, &ctx);
			ctx.idx = 0;
			while (http_find_header2("Accept-Encoding", 15, ci_head(req), &txn->hdr_idx, &ctx)) {
				http_remove_header2(msg, &txn->hdr_idx, &ctx);
			}
		}
		return 1;
	}

	/* identity is implicit does not require headers */
	if ((s->be->comp && (comp_algo_back = s->be->comp->algos)) ||
	    (strm_fe(s)->comp && (comp_algo_back = strm_fe(s)->comp->algos))) {
		for (comp_algo = comp_algo_back; comp_algo; comp_algo = comp_algo->next) {
			if (comp_algo->cfg_name_len == 8 && memcmp(comp_algo->cfg_name, "identity", 8) == 0) {
				st->comp_algo = comp_algo;
				return 1;
			}
		}
	}

	st->comp_algo = NULL;
	return 0;
}

static int
htx_select_comp_reqhdr(struct comp_state *st, struct stream *s, struct http_msg *msg)
{
	struct htx *htx = htxbuf(&msg->chn->buf);
	struct http_hdr_ctx ctx;
	struct comp_algo *comp_algo = NULL;
	struct comp_algo *comp_algo_back = NULL;

	/* Disable compression for older user agents announcing themselves as "Mozilla/4"
	 * unless they are known good (MSIE 6 with XP SP2, or MSIE 7 and later).
	 * See http://zoompf.com/2012/02/lose-the-wait-http-compression for more details.
	 */
	ctx.blk = NULL;
	if (http_find_header(htx, ist("User-Agent"), &ctx, 1) &&
	    ctx.value.len >= 9 &&
	    memcmp(ctx.value.ptr, "Mozilla/4", 9) == 0 &&
	    (ctx.value.len < 31 ||
	     memcmp(ctx.value.ptr + 25, "MSIE ", 5) != 0 ||
	     *(ctx.value.ptr + 30) < '6' ||
	     (*(ctx.value.ptr + 30) == '6' &&
	      (ctx.value.len < 54 || memcmp(ctx.value.ptr + 51, "SV1", 3) != 0)))) {
		st->comp_algo = NULL;
		return 0;
	}

	/* search for the algo in the backend in priority or the frontend */
	if ((s->be->comp && (comp_algo_back = s->be->comp->algos)) ||
	    (strm_fe(s)->comp && (comp_algo_back = strm_fe(s)->comp->algos))) {
		int best_q = 0;

		ctx.blk = NULL;
		while (http_find_header(htx, ist("Accept-Encoding"), &ctx, 0)) {
			const char *qval;
			int q;
			int toklen;

			/* try to isolate the token from the optional q-value */
			toklen = 0;
			while (toklen < ctx.value.len && HTTP_IS_TOKEN(*(ctx.value.ptr + toklen)))
				toklen++;

			qval = ctx.value.ptr + toklen;
			while (1) {
				while (qval < ctx.value.ptr + ctx.value.len && HTTP_IS_LWS(*qval))
					qval++;

				if (qval >= ctx.value.ptr + ctx.value.len || *qval != ';') {
					qval = NULL;
					break;
				}
				qval++;

				while (qval < ctx.value.ptr + ctx.value.len && HTTP_IS_LWS(*qval))
					qval++;

				if (qval >= ctx.value.ptr + ctx.value.len) {
					qval = NULL;
					break;
				}
				if (strncmp(qval, "q=", MIN(ctx.value.ptr + ctx.value.len - qval, 2)) == 0)
					break;

				while (qval < ctx.value.ptr + ctx.value.len && *qval != ';')
					qval++;
			}

			/* here we have qval pointing to the first "q=" attribute or NULL if not found */
			q = qval ? http_parse_qvalue(qval + 2, NULL) : 1000;

			if (q <= best_q)
				continue;

			for (comp_algo = comp_algo_back; comp_algo; comp_algo = comp_algo->next) {
				if (*(ctx.value.ptr) == '*' ||
				    word_match(ctx.value.ptr, toklen, comp_algo->ua_name, comp_algo->ua_name_len)) {
					st->comp_algo = comp_algo;
					best_q = q;
					break;
				}
			}
		}
	}

	/* remove all occurrences of the header when "compression offload" is set */
	if (st->comp_algo) {
		if ((s->be->comp && s->be->comp->offload) ||
		    (strm_fe(s)->comp && strm_fe(s)->comp->offload)) {
			http_remove_header(htx, &ctx);
			ctx.blk = NULL;
			while (http_find_header(htx, ist("Accept-Encoding"), &ctx, 1))
				http_remove_header(htx, &ctx);
		}
		return 1;
	}

	/* identity is implicit does not require headers */
	if ((s->be->comp && (comp_algo_back = s->be->comp->algos)) ||
	    (strm_fe(s)->comp && (comp_algo_back = strm_fe(s)->comp->algos))) {
		for (comp_algo = comp_algo_back; comp_algo; comp_algo = comp_algo->next) {
			if (comp_algo->cfg_name_len == 8 && memcmp(comp_algo->cfg_name, "identity", 8) == 0) {
				st->comp_algo = comp_algo;
				return 1;
			}
		}
	}

	st->comp_algo = NULL;
	return 0;
}

static int
select_compression_request_header(struct comp_state *st, struct stream *s,
				  struct http_msg *msg)
{
	if (IS_HTX_STRM(s))
		return htx_select_comp_reqhdr(st, s, msg);
	else
		return http_select_comp_reqhdr(st, s, msg);
}

/*
 * Selects a comression algorithm depending of the server response.
 */
static int
http_select_comp_reshdr(struct comp_state *st, struct stream *s, struct http_msg *msg)
{
	struct http_txn *txn = s->txn;
	struct channel *c = msg->chn;
	struct hdr_ctx ctx;
	struct comp_type *comp_type;

	/* no common compression algorithm was found in request header */
	if (st->comp_algo == NULL)
		goto fail;

	/* compression already in progress */
	if (msg->flags & HTTP_MSGF_COMPRESSING)
		goto fail;

	/* HTTP < 1.1 should not be compressed */
	if (!(msg->flags & HTTP_MSGF_VER_11) || !(txn->req.flags & HTTP_MSGF_VER_11))
		goto fail;

	if (txn->meth == HTTP_METH_HEAD)
		goto fail;

	/* compress 200,201,202,203 responses only */
	if ((txn->status != 200) &&
	    (txn->status != 201) &&
	    (txn->status != 202) &&
	    (txn->status != 203))
		goto fail;


	/* Content-Length is null */
	if (!(msg->flags & HTTP_MSGF_TE_CHNK) && msg->body_len == 0)
		goto fail;

	/* content is already compressed */
	ctx.idx = 0;
	if (http_find_header2("Content-Encoding", 16, ci_head(c), &txn->hdr_idx, &ctx))
		goto fail;

	/* no compression when Cache-Control: no-transform is present in the message */
	ctx.idx = 0;
	while (http_find_header2("Cache-Control", 13, ci_head(c), &txn->hdr_idx, &ctx)) {
		if (word_match(ctx.line + ctx.val, ctx.vlen, "no-transform", 12))
			goto fail;
	}

	comp_type = NULL;

	/* we don't want to compress multipart content-types, nor content-types that are
	 * not listed in the "compression type" directive if any. If no content-type was
	 * found but configuration requires one, we don't compress either. Backend has
	 * the priority.
	 */
	ctx.idx = 0;
	if (http_find_header2("Content-Type", 12, ci_head(c), &txn->hdr_idx, &ctx)) {
		if (ctx.vlen >= 9 && strncasecmp("multipart", ctx.line+ctx.val, 9) == 0)
			goto fail;

		if ((s->be->comp && (comp_type = s->be->comp->types)) ||
		    (strm_fe(s)->comp && (comp_type = strm_fe(s)->comp->types))) {
			for (; comp_type; comp_type = comp_type->next) {
				if (ctx.vlen >= comp_type->name_len &&
				    strncasecmp(ctx.line+ctx.val, comp_type->name, comp_type->name_len) == 0)
					/* this Content-Type should be compressed */
					break;
			}
			/* this Content-Type should not be compressed */
			if (comp_type == NULL)
				goto fail;
		}
	}
	else { /* no content-type header */
		if ((s->be->comp && s->be->comp->types) ||
		    (strm_fe(s)->comp && strm_fe(s)->comp->types))
			goto fail; /* a content-type was required */
	}

	/* limit compression rate */
	if (global.comp_rate_lim > 0)
		if (read_freq_ctr(&global.comp_bps_in) > global.comp_rate_lim)
			goto fail;

	/* limit cpu usage */
	if (idle_pct < compress_min_idle)
		goto fail;

	/* initialize compression */
	if (st->comp_algo->init(&st->comp_ctx, global.tune.comp_maxlevel) < 0)
		goto fail;
	msg->flags |= HTTP_MSGF_COMPRESSING;
	return 1;

fail:
	st->comp_algo = NULL;
	return 0;
}

static int
htx_select_comp_reshdr(struct comp_state *st, struct stream *s, struct http_msg *msg)
{
	struct htx *htx = htxbuf(&msg->chn->buf);
	struct http_txn *txn = s->txn;
	struct http_hdr_ctx ctx;
	struct comp_type *comp_type;

	/* no common compression algorithm was found in request header */
	if (st->comp_algo == NULL)
		goto fail;

	/* compression already in progress */
	if (msg->flags & HTTP_MSGF_COMPRESSING)
		goto fail;

	/* HTTP < 1.1 should not be compressed */
	if (!(msg->flags & HTTP_MSGF_VER_11) || !(txn->req.flags & HTTP_MSGF_VER_11))
		goto fail;

	if (txn->meth == HTTP_METH_HEAD)
		goto fail;

	/* compress 200,201,202,203 responses only */
	if ((txn->status != 200) &&
	    (txn->status != 201) &&
	    (txn->status != 202) &&
	    (txn->status != 203))
		goto fail;

	if (!(msg->flags & HTTP_MSGF_XFER_LEN) || msg->flags & HTTP_MSGF_BODYLESS)
		goto fail;

	/* content is already compressed */
	ctx.blk = NULL;
	if (http_find_header(htx, ist("Content-Encoding"), &ctx, 1))
		goto fail;

	/* no compression when Cache-Control: no-transform is present in the message */
	ctx.blk = NULL;
	while (http_find_header(htx, ist("Cache-Control"), &ctx, 0)) {
		if (word_match(ctx.value.ptr, ctx.value.len, "no-transform", 12))
			goto fail;
	}

	comp_type = NULL;

	/* we don't want to compress multipart content-types, nor content-types that are
	 * not listed in the "compression type" directive if any. If no content-type was
	 * found but configuration requires one, we don't compress either. Backend has
	 * the priority.
	 */
	ctx.blk = NULL;
	if (http_find_header(htx, ist("Content-Type"), &ctx, 1)) {
		if (ctx.value.len >= 9 && strncasecmp("multipart", ctx.value.ptr, 9) == 0)
			goto fail;

		if ((s->be->comp && (comp_type = s->be->comp->types)) ||
		    (strm_fe(s)->comp && (comp_type = strm_fe(s)->comp->types))) {
			for (; comp_type; comp_type = comp_type->next) {
				if (ctx.value.len >= comp_type->name_len &&
				    strncasecmp(ctx.value.ptr, comp_type->name, comp_type->name_len) == 0)
					/* this Content-Type should be compressed */
					break;
			}
			/* this Content-Type should not be compressed */
			if (comp_type == NULL)
				goto fail;
		}
	}
	else { /* no content-type header */
		if ((s->be->comp && s->be->comp->types) ||
		    (strm_fe(s)->comp && strm_fe(s)->comp->types))
			goto fail; /* a content-type was required */
	}

	/* limit compression rate */
	if (global.comp_rate_lim > 0)
		if (read_freq_ctr(&global.comp_bps_in) > global.comp_rate_lim)
			goto fail;

	/* limit cpu usage */
	if (idle_pct < compress_min_idle)
		goto fail;

	/* initialize compression */
	if (st->comp_algo->init(&st->comp_ctx, global.tune.comp_maxlevel) < 0)
		goto fail;
	msg->flags |= HTTP_MSGF_COMPRESSING;
	return 1;

  deinit_comp_ctx:
	st->comp_algo->end(&st->comp_ctx);
  fail:
	st->comp_algo = NULL;
	return 0;
}

static int
select_compression_response_header(struct comp_state *st, struct stream *s, struct http_msg *msg)
{
	if (IS_HTX_STRM(s))
		return htx_select_comp_reshdr(st, s, msg);
	else
		return http_select_comp_reshdr(st, s, msg);
}
/***********************************************************************/
/* emit the chunksize followed by a CRLF on the output and return the number of
 * bytes written. It goes backwards and starts with the byte before <end>. It
 * returns the number of bytes written which will not exceed 10 (8 digits, CR,
 * and LF). The caller is responsible for ensuring there is enough room left in
 * the output buffer for the string.
 */
static int
http_emit_chunk_size(char *end, unsigned int chksz)
{
	char *beg = end;

	*--beg = '\n';
	*--beg = '\r';
	do {
		*--beg = hextab[chksz & 0xF];
	} while (chksz >>= 4);
	return end - beg;
}

/*
 * Init HTTP compression
 */
static int
http_compression_buffer_init(struct channel *inc, struct buffer *out)
{
	/* output stream requires at least 10 bytes for the gzip header, plus
	 * at least 8 bytes for the gzip trailer (crc+len), plus a possible
	 * plus at most 5 bytes per 32kB block and 2 bytes to close the stream.
	 */
	if (c_room(inc) < 20 + 5 * ((ci_data(inc) + 32767) >> 15))
		return -1;

	/* prepare an empty output buffer in which we reserve enough room for
	 * copying the output bytes from <in>, plus 10 extra bytes to write
	 * the chunk size. We don't copy the bytes yet so that if we have to
	 * cancel the operation later, it's cheap.
	 */
	b_reset(out);
	out->head += co_data(inc) + 10;
	return 0;
}

static int
htx_compression_buffer_init(struct htx *htx, struct buffer *out)
{
	/* output stream requires at least 10 bytes for the gzip header, plus
	 * at least 8 bytes for the gzip trailer (crc+len), plus a possible
	 * plus at most 5 bytes per 32kB block and 2 bytes to close the stream.
	 */
	if (htx_free_space(htx) < 20 + 5 * ((htx->data + 32767) >> 15))
		return -1;
	b_reset(out);
	return 0;
}

/*
 * Add data to compress
 */
static int
http_compression_buffer_add_data(struct comp_state *st, struct buffer *in,
				 int in_out, struct buffer *out, int sz)
{
	int consumed_data = 0;
	int data_process_len;
	int block1, block2;

	if (!sz)
		goto end;

	/* select the smallest size between the announced chunk size, the input
	 * data, and the available output buffer size. The compressors are
	 * assumed to be able to process all the bytes we pass to them at
	 * once. */
	data_process_len = MIN(b_room(out), sz);

	block1 = data_process_len;
	if (block1 > b_contig_data(in, in_out))
		block1 = b_contig_data(in, in_out);
	block2 = data_process_len - block1;

	/* compressors return < 0 upon error or the amount of bytes read */
	consumed_data = st->comp_algo->add_data(st->comp_ctx, b_peek(in, in_out), block1, out);
	if (consumed_data != block1 || !block2)
		goto end;
	consumed_data = st->comp_algo->add_data(st->comp_ctx, b_orig(in), block2, out);
	if (consumed_data < 0)
		goto end;
	consumed_data += block1;

 end:
	return consumed_data;
}

static int
htx_compression_buffer_add_data(struct comp_state *st, const char *data, size_t len,
				struct buffer *out)
{
	return st->comp_algo->add_data(st->comp_ctx, data, len, out);
}

/*
 * Flush data in process, and write the header and footer of the chunk. Upon
 * success, in and out buffers are swapped to avoid a copy.
 */
static int
http_compression_buffer_end(struct comp_state *st, struct stream *s,
			    struct channel *chn, struct buffer *out,
			    int end)
{
	struct buffer tmp_buf;
	char *tail;
	int   to_forward, left;

#if defined(USE_SLZ) || defined(USE_ZLIB)
	int ret;

	/* flush data here */
	if (end)
		ret = st->comp_algo->finish(st->comp_ctx, out); /* end of data */
	else
		ret = st->comp_algo->flush(st->comp_ctx, out); /* end of buffer */

	if (ret < 0)
		return -1; /* flush failed */

#endif /* USE_ZLIB */
	if (b_data(out) == 0) {
		/* No data were appended, let's drop the output buffer and
		 * keep the input buffer unchanged.
		 */
		return 0;
	}

	/* OK so at this stage, we have an output buffer <out> looking like this :
	 *
	 *        <-- o --> <------ i ----->
	 *       +---------+---+------------+-----------+
	 *       |   out   | c |  comp_in   |   empty   |
	 *       +---------+---+------------+-----------+
	 *     data        p                           size
	 *
	 * <out> is the room reserved to copy the channel output. It starts at
	 * out->area and has not yet been filled. <c> is the room reserved to
	 * write the chunk size (10 bytes). <comp_in> is the compressed
	 * equivalent of the data part of ib->len. <empty> is the amount of
	 * empty bytes at the end of  the buffer, into which we may have to
	 * copy the remaining bytes from ib->len after the data
	 * (chunk size, trailers, ...).
	 */

	/* Write real size at the beginning of the chunk, no need of wrapping.
	 * We write the chunk using a dynamic length and adjust out->p and out->i
	 * accordingly afterwards. That will move <out> away from <data>.
	 */
	left = http_emit_chunk_size(b_head(out), b_data(out));
	b_add(out, left);
	out->head -= co_data(chn) + (left);
	/* Copy previous data from chn into out */
	if (co_data(chn) > 0) {
		left = b_contig_data(&chn->buf, 0);
		if (left > co_data(chn))
			left = co_data(chn);

		memcpy(b_head(out), co_head(chn), left);
		b_add(out, left);
		if (co_data(chn) - left) {/* second part of the buffer */
			memcpy(b_head(out) + left, b_orig(&chn->buf), co_data(chn) - left);
			b_add(out, co_data(chn) - left);
		}
	}

	/* chunked encoding requires CRLF after data */
	tail = b_tail(out);
	*tail++ = '\r';
	*tail++ = '\n';

	/* At the end of data, we must write the empty chunk 0<CRLF>,
	 * and terminate the trailers section with a last <CRLF>. If
	 * we're forwarding a chunked-encoded response, we'll have a
	 * trailers section after the empty chunk which needs to be
	 * forwarded and which will provide the last CRLF. Otherwise
	 * we write it ourselves.
	 */
	if (end) {
		struct http_msg *msg = &s->txn->rsp;

		memcpy(tail, "0\r\n", 3);
		tail += 3;
		if (!(msg->flags & HTTP_MSGF_TE_CHNK)) {
			memcpy(tail, "\r\n", 2);
			tail += 2;
		}
	}

	b_add(out, tail - b_tail(out));
	to_forward = b_data(out) - co_data(chn);

	/* update input rate */
	if (st->comp_ctx && st->comp_ctx->cur_lvl > 0) {
		update_freq_ctr(&global.comp_bps_in, st->consumed);
		HA_ATOMIC_ADD(&strm_fe(s)->fe_counters.comp_in, st->consumed);
		HA_ATOMIC_ADD(&s->be->be_counters.comp_in,      st->consumed);
	} else {
		HA_ATOMIC_ADD(&strm_fe(s)->fe_counters.comp_byp, st->consumed);
		HA_ATOMIC_ADD(&s->be->be_counters.comp_byp,      st->consumed);
	}

	/* copy the remaining data in the tmp buffer. */
	c_adv(chn, st->consumed);
	if (b_data(&chn->buf) - co_data(chn) > 0) {
		left = ci_contig_data(chn);
		memcpy(b_tail(out), ci_head(chn), left);
		b_add(out, left);
		if (b_data(&chn->buf) - (co_data(chn) + left)) {
			memcpy(b_tail(out), b_orig(&chn->buf), b_data(&chn->buf) - left);
			b_add(out, b_data(&chn->buf) - left);
		}
	}
	c_rew(chn, st->consumed);

	/* swap the buffers */
	tmp_buf = chn->buf;
	chn->buf = *out;
	*out = tmp_buf;

	if (st->comp_ctx && st->comp_ctx->cur_lvl > 0) {
		update_freq_ctr(&global.comp_bps_out, to_forward);
		HA_ATOMIC_ADD(&strm_fe(s)->fe_counters.comp_out, to_forward);
		HA_ATOMIC_ADD(&s->be->be_counters.comp_out,      to_forward);
	}

	return to_forward;
}

static int
htx_compression_buffer_end(struct comp_state *st, struct buffer *out, int end)
{
	if (end)
		return st->comp_algo->finish(st->comp_ctx, out);
	else
		return st->comp_algo->flush(st->comp_ctx, out);
}


/***********************************************************************/
struct flt_ops comp_ops = {
	.init              = comp_flt_init,
	.init_per_thread   = comp_flt_init_per_thread,
	.deinit_per_thread = comp_flt_deinit_per_thread,

	.channel_start_analyze = comp_start_analyze,
	.channel_end_analyze   = comp_end_analyze,
	.channel_post_analyze  = comp_http_post_analyze,

	.http_headers          = comp_http_headers,
	.http_payload          = comp_http_payload,
	.http_end              = comp_http_end,

	.http_data             = comp_http_data,
	.http_chunk_trailers   = comp_http_chunk_trailers,
	.http_forward_data     = comp_http_forward_data,
};

static int
parse_compression_options(char **args, int section, struct proxy *proxy,
			  struct proxy *defpx, const char *file, int line,
			  char **err)
{
	struct comp    *comp;

	if (proxy->comp == NULL) {
		comp = calloc(1, sizeof(*comp));
		proxy->comp = comp;
	}
	else
		comp = proxy->comp;

	if (!strcmp(args[1], "algo")) {
		struct comp_ctx *ctx;
		int              cur_arg = 2;

		if (!*args[cur_arg]) {
			memprintf(err, "parsing [%s:%d] : '%s' expects <algorithm>\n",
				  file, line, args[0]);
			return -1;
		}
		while (*(args[cur_arg])) {
			if (comp_append_algo(comp, args[cur_arg]) < 0) {
				memprintf(err, "'%s' : '%s' is not a supported algorithm.\n",
					  args[0], args[cur_arg]);
				return -1;
			}
			if (proxy->comp->algos->init(&ctx, 9) == 0)
				proxy->comp->algos->end(&ctx);
			else {
				memprintf(err, "'%s' : Can't init '%s' algorithm.\n",
					  args[0], args[cur_arg]);
				return -1;
			}
			cur_arg++;
			continue;
		}
	}
	else if (!strcmp(args[1], "offload"))
		comp->offload = 1;
	else if (!strcmp(args[1], "type")) {
		int cur_arg = 2;

		if (!*args[cur_arg]) {
			memprintf(err, "'%s' expects <type>\n", args[0]);
			return -1;
		}
		while (*(args[cur_arg])) {
			comp_append_type(comp, args[cur_arg]);
			cur_arg++;
			continue;
		}
	}
	else {
		memprintf(err, "'%s' expects 'algo', 'type' or 'offload'\n",
			  args[0]);
		return -1;
	}

	return 0;
}

static int
parse_http_comp_flt(char **args, int *cur_arg, struct proxy *px,
                    struct flt_conf *fconf, char **err, void *private)
{
	struct flt_conf *fc, *back;

	list_for_each_entry_safe(fc, back, &px->filter_configs, list) {
		if (fc->id == http_comp_flt_id) {
			memprintf(err, "%s: Proxy supports only one compression filter\n", px->id);
			return -1;
		}
	}

	fconf->id   = http_comp_flt_id;
	fconf->conf = NULL;
	fconf->ops  = &comp_ops;
	(*cur_arg)++;

	return 0;
}


int
check_implicit_http_comp_flt(struct proxy *proxy)
{
	struct flt_conf *fconf;
	int explicit = 0;
	int comp = 0;
	int err = 0;

	if (proxy->comp == NULL)
		goto end;
	if (!LIST_ISEMPTY(&proxy->filter_configs)) {
		list_for_each_entry(fconf, &proxy->filter_configs, list) {
			if (fconf->id == http_comp_flt_id)
				comp = 1;
			else if (fconf->id == cache_store_flt_id) {
				if (comp) {
					ha_alert("config: %s '%s': unable to enable the compression filter "
						 "before any cache filter.\n",
						 proxy_type_str(proxy), proxy->id);
					err++;
					goto end;
				}
			}
			else
				explicit = 1;
		}
	}
	if (comp)
		goto end;
	else if (explicit) {
		ha_alert("config: %s '%s': require an explicit filter declaration to use "
			 "HTTP compression\n", proxy_type_str(proxy), proxy->id);
		err++;
		goto end;
	}

	/* Implicit declaration of the compression filter is always the last
	 * one */
	fconf = calloc(1, sizeof(*fconf));
	if (!fconf) {
		ha_alert("config: %s '%s': out of memory\n",
			 proxy_type_str(proxy), proxy->id);
		err++;
		goto end;
	}
	fconf->id   = http_comp_flt_id;
	fconf->conf = NULL;
	fconf->ops  = &comp_ops;
	LIST_ADDQ(&proxy->filter_configs, &fconf->list);
 end:
	return err;
}

/*
 * boolean, returns true if compression is used (either gzip or deflate) in the
 * response.
 */
static int
smp_fetch_res_comp(const struct arg *args, struct sample *smp, const char *kw,
		   void *private)
{
	struct http_txn *txn = smp->strm ? smp->strm->txn : NULL;

	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = (txn && (txn->rsp.flags & HTTP_MSGF_COMPRESSING));
	return 1;
}

/*
 * string, returns algo
 */
static int
smp_fetch_res_comp_algo(const struct arg *args, struct sample *smp,
			const char *kw, void *private)
{
	struct http_txn   *txn = smp->strm ? smp->strm->txn : NULL;
	struct filter     *filter;
	struct comp_state *st;

	if (!txn || !(txn->rsp.flags & HTTP_MSGF_COMPRESSING))
		return 0;

	list_for_each_entry(filter, &strm_flt(smp->strm)->filters, list) {
		if (FLT_ID(filter) != http_comp_flt_id)
			continue;

		if (!(st = filter->ctx))
			break;

		smp->data.type = SMP_T_STR;
		smp->flags = SMP_F_CONST;
		smp->data.u.str.area = st->comp_algo->cfg_name;
		smp->data.u.str.data = st->comp_algo->cfg_name_len;
		return 1;
	}
	return 0;
}

/* Declare the config parser for "compression" keyword */
static struct cfg_kw_list cfg_kws = {ILH, {
		{ CFG_LISTEN, "compression", parse_compression_options },
		{ 0, NULL, NULL },
	}
};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/* Declare the filter parser for "compression" keyword */
static struct flt_kw_list filter_kws = { "COMP", { }, {
		{ "compression", parse_http_comp_flt, NULL },
		{ NULL, NULL, NULL },
	}
};

INITCALL1(STG_REGISTER, flt_register_keywords, &filter_kws);

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
		{ "res.comp",      smp_fetch_res_comp,      0, NULL, SMP_T_BOOL, SMP_USE_HRSHP },
		{ "res.comp_algo", smp_fetch_res_comp_algo, 0, NULL, SMP_T_STR, SMP_USE_HRSHP },
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, sample_register_fetches, &sample_fetch_keywords);
