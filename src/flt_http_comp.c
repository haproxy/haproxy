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
#include <common/mini-clist.h>
#include <common/standard.h>

#include <types/compression.h>
#include <types/filters.h>
#include <types/proto_http.h>
#include <types/proxy.h>
#include <types/sample.h>

#include <proto/compression.h>
#include <proto/filters.h>
#include <proto/hdr_idx.h>
#include <proto/proto_http.h>
#include <proto/sample.h>
#include <proto/stream.h>

static const char *http_comp_flt_id = "compression filter";

struct flt_ops comp_ops;


/* Pools used to allocate comp_state structs */
static struct pool_head *pool_head_comp_state = NULL;

static THREAD_LOCAL struct buffer *tmpbuf = &buf_empty;
static THREAD_LOCAL struct buffer *zbuf   = &buf_empty;

struct comp_state {
	struct comp_ctx  *comp_ctx;   /* compression context */
	struct comp_algo *comp_algo;  /* compression algorithm if not NULL */
	int hdrs_len;
	int tlrs_len;
	int consumed;
	int initialized;
	int finished;
};

static int select_compression_request_header(struct comp_state *st,
					     struct stream *s,
					     struct http_msg *msg);
static int select_compression_response_header(struct comp_state *st,
					      struct stream *s,
					      struct http_msg *msg);

static int http_compression_buffer_init(struct buffer *in, struct buffer *out);
static int http_compression_buffer_add_data(struct comp_state *st,
					    struct buffer *in,
					    struct buffer *out, int sz);
static int http_compression_buffer_end(struct comp_state *st, struct stream *s,
				       struct buffer **in, struct buffer **out,
				       int end);

/***********************************************************************/
static int
comp_flt_init_per_thread(struct proxy *px, struct flt_conf *fconf)
{
	if (!tmpbuf->size && b_alloc(&tmpbuf) == NULL)
		return -1;
	if (!zbuf->size && b_alloc(&zbuf) == NULL)
		return -1;
	return 0;
}

static void
comp_flt_deinit_per_thread(struct proxy *px, struct flt_conf *fconf)
{
	if (tmpbuf->size)
		b_free(&tmpbuf);
	if (zbuf->size)
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
			register_data_filter(s, msg->chn, filter);
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
comp_http_data(struct stream *s, struct filter *filter, struct http_msg *msg)
{
	struct comp_state *st = filter->ctx;
	struct buffer     *buf = msg->chn->buf;
	unsigned int      *nxt = &flt_rsp_nxt(filter);
	unsigned int       len;
	int                ret;

	len = MIN(msg->chunk_len + msg->next, buf->i) - *nxt;
	if (!len)
		return len;

	if (!st->initialized) {
		unsigned int fwd = flt_rsp_fwd(filter) + st->hdrs_len;

		b_reset(tmpbuf);
		b_adv(buf, fwd);
		ret = http_compression_buffer_init(buf, zbuf);
		b_rew(buf, fwd);
		if (ret < 0) {
			msg->chn->flags |= CF_WAKE_WRITE;
			return 0;
		}
	}

	if (msg->flags & HTTP_MSGF_TE_CHNK) {
		int block;

		len = MIN(tmpbuf->size - buffer_len(tmpbuf), len);

		b_adv(buf, *nxt);
		block = bi_contig_data(buf);
		memcpy(bi_end(tmpbuf), bi_ptr(buf), block);
		if (len > block)
			memcpy(bi_end(tmpbuf)+block, buf->data, len-block);
		b_rew(buf, *nxt);

		tmpbuf->i += len;
		ret        = len;
	}
	else {
		b_adv(buf, *nxt);
		ret = http_compression_buffer_add_data(st, buf, zbuf, len);
		b_rew(buf, *nxt);
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
			struct buffer *buf = msg->chn->buf;
			unsigned int   fwd = flt_rsp_fwd(filter) + st->hdrs_len;

			b_reset(tmpbuf);
			b_adv(buf, fwd);
			http_compression_buffer_init(buf, zbuf);
			b_rew(buf, fwd);
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
			/* Nothing to foward */
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
		ret = http_compression_buffer_add_data(st, tmpbuf, zbuf, tmpbuf->i);
		if (ret != tmpbuf->i) {
			ha_warning("HTTP compression failed: Must consume %d bytes but only %d bytes consumed\n",
				   tmpbuf->i, ret);
			return -1;
		}
	}

	st->consumed = len - st->hdrs_len - st->tlrs_len;
	b_adv(msg->chn->buf, flt_rsp_fwd(filter) + st->hdrs_len);
	ret = http_compression_buffer_end(st, s, &msg->chn->buf, &zbuf, msg->msg_state >= HTTP_MSG_TRAILERS);
	b_rew(msg->chn->buf, flt_rsp_fwd(filter) + st->hdrs_len);
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
/*
 * Selects a compression algorithm depending on the client request.
 */
int
select_compression_request_header(struct comp_state *st, struct stream *s,
				  struct http_msg *msg)
{
	struct http_txn *txn = s->txn;
	struct buffer *req = msg->chn->buf;
	struct hdr_ctx ctx;
	struct comp_algo *comp_algo = NULL;
	struct comp_algo *comp_algo_back = NULL;

	/* Disable compression for older user agents announcing themselves as "Mozilla/4"
	 * unless they are known good (MSIE 6 with XP SP2, or MSIE 7 and later).
	 * See http://zoompf.com/2012/02/lose-the-wait-http-compression for more details.
	 */
	ctx.idx = 0;
	if (http_find_header2("User-Agent", 10, req->p, &txn->hdr_idx, &ctx) &&
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
		while (http_find_header2("Accept-Encoding", 15, req->p, &txn->hdr_idx, &ctx)) {
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
			q = qval ? parse_qvalue(qval + 2, NULL) : 1000;

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
			while (http_find_header2("Accept-Encoding", 15, req->p, &txn->hdr_idx, &ctx)) {
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


/*
 * Selects a comression algorithm depending of the server response.
 */
static int
select_compression_response_header(struct comp_state *st, struct stream *s, struct http_msg *msg)
{
	struct http_txn *txn = s->txn;
	struct buffer *res = msg->chn->buf;
	struct hdr_ctx ctx;
	struct comp_type *comp_type;

	/* no common compression algorithm was found in request header */
	if (st->comp_algo == NULL)
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
	if (http_find_header2("Content-Encoding", 16, res->p, &txn->hdr_idx, &ctx))
		goto fail;

	/* no compression when Cache-Control: no-transform is present in the message */
	ctx.idx = 0;
	while (http_find_header2("Cache-Control", 13, res->p, &txn->hdr_idx, &ctx)) {
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
	if (http_find_header2("Content-Type", 12, res->p, &txn->hdr_idx, &ctx)) {
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

	/* remove Content-Length header */
	ctx.idx = 0;
	if ((msg->flags & HTTP_MSGF_CNT_LEN) && http_find_header2("Content-Length", 14, res->p, &txn->hdr_idx, &ctx))
		http_remove_header2(msg, &txn->hdr_idx, &ctx);

	/* add Transfer-Encoding header */
	if (!(msg->flags & HTTP_MSGF_TE_CHNK))
		http_header_add_tail2(&txn->rsp, &txn->hdr_idx, "Transfer-Encoding: chunked", 26);

	/*
	 * Add Content-Encoding header when it's not identity encoding.
         * RFC 2616 : Identity encoding: This content-coding is used only in the
	 * Accept-Encoding header, and SHOULD NOT be used in the Content-Encoding
	 * header.
	 */
	if (st->comp_algo->cfg_name_len != 8 || memcmp(st->comp_algo->cfg_name, "identity", 8) != 0) {
		trash.len = 18;
		memcpy(trash.str, "Content-Encoding: ", trash.len);
		memcpy(trash.str + trash.len, st->comp_algo->ua_name, st->comp_algo->ua_name_len);
		trash.len += st->comp_algo->ua_name_len;
		trash.str[trash.len] = '\0';
		http_header_add_tail2(&txn->rsp, &txn->hdr_idx, trash.str, trash.len);
	}
	msg->flags |= HTTP_MSGF_COMPRESSING;
	return 1;

fail:
	st->comp_algo = NULL;
	return 0;
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
http_compression_buffer_init(struct buffer *in, struct buffer *out)
{
	/* output stream requires at least 10 bytes for the gzip header, plus
	 * at least 8 bytes for the gzip trailer (crc+len), plus a possible
	 * plus at most 5 bytes per 32kB block and 2 bytes to close the stream.
	 */
	if (in->size - buffer_len(in) < 20 + 5 * ((in->i + 32767) >> 15))
		return -1;

	/* prepare an empty output buffer in which we reserve enough room for
	 * copying the output bytes from <in>, plus 10 extra bytes to write
	 * the chunk size. We don't copy the bytes yet so that if we have to
	 * cancel the operation later, it's cheap.
	 */
	b_reset(out);
	out->o = in->o;
	out->p += out->o;
	out->i = 10;
	return 0;
}

/*
 * Add data to compress
 */
static int
http_compression_buffer_add_data(struct comp_state *st, struct buffer *in,
				 struct buffer *out, int sz)
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
	data_process_len = MIN(out->size - buffer_len(out), sz);

	block1 = data_process_len;
	if (block1 > bi_contig_data(in))
		block1 = bi_contig_data(in);
	block2 = data_process_len - block1;

	/* compressors return < 0 upon error or the amount of bytes read */
	consumed_data = st->comp_algo->add_data(st->comp_ctx, bi_ptr(in), block1, out);
	if (consumed_data != block1 || !block2)
		goto end;
	consumed_data = st->comp_algo->add_data(st->comp_ctx, in->data, block2, out);
	if (consumed_data < 0)
		goto end;
	consumed_data += block1;

 end:
	return consumed_data;
}

/*
 * Flush data in process, and write the header and footer of the chunk. Upon
 * success, in and out buffers are swapped to avoid a copy.
 */
static int
http_compression_buffer_end(struct comp_state *st, struct stream *s,
			    struct buffer **in, struct buffer **out,
			    int end)
{
	struct buffer *ib = *in, *ob = *out;
	char *tail;
	int   to_forward, left;

#if defined(USE_SLZ) || defined(USE_ZLIB)
	int ret;

	/* flush data here */
	if (end)
		ret = st->comp_algo->finish(st->comp_ctx, ob); /* end of data */
	else
		ret = st->comp_algo->flush(st->comp_ctx, ob); /* end of buffer */

	if (ret < 0)
		return -1; /* flush failed */

#endif /* USE_ZLIB */
	if (ob->i == 10) {
		/* No data were appended, let's drop the output buffer and
		 * keep the input buffer unchanged.
		 */
		return 0;
	}

	/* OK so at this stage, we have an output buffer <ob> looking like this :
	 *
	 *        <-- o --> <------ i ----->
	 *       +---------+---+------------+-----------+
	 *       |   out   | c |  comp_in   |   empty   |
	 *       +---------+---+------------+-----------+
	 *     data        p                           size
	 *
	 * <out> is the room reserved to copy ib->o. It starts at ob->data and
	 * has not yet been filled. <c> is the room reserved to write the chunk
	 * size (10 bytes). <comp_in> is the compressed equivalent of the data
	 * part of ib->i. <empty> is the amount of empty bytes at the end of
	 * the buffer, into which we may have to copy the remaining bytes from
	 * ib->i after the data (chunk size, trailers, ...).
	 */

	/* Write real size at the begining of the chunk, no need of wrapping.
	 * We write the chunk using a dynamic length and adjust ob->p and ob->i
	 * accordingly afterwards. That will move <out> away from <data>.
	 */
	left = 10 - http_emit_chunk_size(ob->p + 10, ob->i - 10);
	ob->p += left;
	ob->i -= left;

	/* Copy previous data from ib->o into ob->o */
	if (ib->o > 0) {
		left = bo_contig_data(ib);
		memcpy(ob->p - ob->o, bo_ptr(ib), left);
		if (ib->o - left) /* second part of the buffer */
			memcpy(ob->p - ob->o + left, ib->data, ib->o - left);
	}

	/* chunked encoding requires CRLF after data */
	tail = ob->p + ob->i;
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

	ob->i = tail - ob->p;
	to_forward = ob->i;

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
	b_adv(ib, st->consumed);
	if (ib->i > 0) {
		left = bi_contig_data(ib);
		memcpy(ob->p + ob->i, bi_ptr(ib), left);
		ob->i += left;
		if (ib->i - left) {
			memcpy(ob->p + ob->i, ib->data, ib->i - left);
			ob->i += ib->i - left;
		}
	}

	/* swap the buffers */
	*in = ob;
	*out = ib;


	if (st->comp_ctx && st->comp_ctx->cur_lvl > 0) {
		update_freq_ctr(&global.comp_bps_out, to_forward);
		HA_ATOMIC_ADD(&strm_fe(s)->fe_counters.comp_out, to_forward);
		HA_ATOMIC_ADD(&s->be->be_counters.comp_out,      to_forward);
	}

	return to_forward;
}


/***********************************************************************/
struct flt_ops comp_ops = {
	.init_per_thread   = comp_flt_init_per_thread,
	.deinit_per_thread = comp_flt_deinit_per_thread,

	.channel_start_analyze = comp_start_analyze,
	.channel_end_analyze   = comp_end_analyze,
	.channel_post_analyze  = comp_http_post_analyze,

	.http_headers          = comp_http_headers,
	.http_data             = comp_http_data,
	.http_chunk_trailers   = comp_http_chunk_trailers,
	.http_forward_data     = comp_http_forward_data,
	.http_end              = comp_http_end,
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
check_legacy_http_comp_flt(struct proxy *proxy)
{
	struct flt_conf *fconf;
	int err = 0;

	if (proxy->comp == NULL)
		goto end;
	if (!LIST_ISEMPTY(&proxy->filter_configs)) {
		list_for_each_entry(fconf, &proxy->filter_configs, list) {
			if (fconf->id == http_comp_flt_id)
				goto end;
		}
		ha_alert("config: %s '%s': require an explicit filter declaration to use HTTP compression\n",
			 proxy_type_str(proxy), proxy->id);
		err++;
		goto end;
	}

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
		smp->data.u.str.str = st->comp_algo->cfg_name;
		smp->data.u.str.len = st->comp_algo->cfg_name_len;
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

/* Declare the filter parser for "compression" keyword */
static struct flt_kw_list filter_kws = { "COMP", { }, {
		{ "compression", parse_http_comp_flt, NULL },
		{ NULL, NULL, NULL },
	}
};

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
		{ "res.comp",      smp_fetch_res_comp,      0, NULL, SMP_T_BOOL, SMP_USE_HRSHP },
		{ "res.comp_algo", smp_fetch_res_comp_algo, 0, NULL, SMP_T_STR, SMP_USE_HRSHP },
		{ /* END */ },
	}
};

__attribute__((constructor))
static void
__flt_http_comp_init(void)
{
	cfg_register_keywords(&cfg_kws);
	flt_register_keywords(&filter_kws);
	sample_register_fetches(&sample_fetch_keywords);
	pool_head_comp_state = create_pool("comp_state", sizeof(struct comp_state), MEM_F_SHARED);
}
