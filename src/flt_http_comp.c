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

static struct buffer *tmpbuf = &buf_empty;

struct comp_chunk {
	unsigned int start;   /* start of the chunk relative to FLT_FWD offset */
	unsigned int end;     /* end of the chunk relative to FLT_FWD offset */
	int          skip;    /* if set to 1, the chunk is skipped. Otherwise it is compressed */
	int          is_last; /* if set, this is the last chunk. Data after this
			       * chunk will be forwarded as it is. */
	struct list  list;
};

struct comp_state {
	struct comp_ctx  *comp_ctx;   /* compression context */
	struct comp_algo *comp_algo;  /* compression algorithm if not NULL */
	struct list  comp_chunks;     /* data chunks that should be compressed or skipped */
	unsigned int first;           /* offset of the first chunk. Data before
				       * this offset will be forwarded as it
				       * is. */
};

static int add_comp_chunk(struct comp_state *st, unsigned int start,
			  unsigned int len, int skip, int is_last);
static int skip_input_data(struct filter *filter, struct http_msg *msg,
			   unsigned int consumed);

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
				       unsigned int consumed, int end);

/***********************************************************************/
static int
comp_flt_init(struct proxy *px, struct filter *filter)
{

	/* We need a compression buffer in the DATA state to put the output of
	 * compressed data, and in CRLF state to let the TRAILERS state finish
	 * the job of removing the trailing CRLF.
	 */
	if (!tmpbuf->size) {
		if (b_alloc(&tmpbuf) == NULL)
			return -1;
	}
	return 0;
}

static void
comp_flt_deinit(struct proxy *px, struct filter *filter)
{
	if (tmpbuf->size)
		b_free(&tmpbuf);
}

static int
comp_start_analyze(struct stream *s, struct filter *filter, struct channel *chn)
{
	if (filter->ctx == NULL) {
		struct comp_state *st;

		if (!(st = malloc(sizeof(*st))))
			return -1;

		LIST_INIT(&st->comp_chunks);
		st->comp_algo = NULL;
		st->comp_ctx = NULL;
		st->first    = 0;
		filter->ctx  = st;
	}
	return 1;
}

static int
comp_analyze(struct stream *s, struct filter *filter, struct channel *chn,
	     unsigned int an_bit)
{
	struct comp_state *st = filter->ctx;

	if (!strm_fe(s)->comp && !s->be->comp)
		goto end;

	switch (an_bit) {
		case AN_RES_HTTP_PROCESS_BE:
			select_compression_response_header(st, s, &s->txn->rsp);
			break;
	}
  end:
	return 1;
}

static int
comp_end_analyze(struct stream *s, struct filter *filter, struct channel *chn)
{
	struct comp_state *st = filter->ctx;
	struct comp_chunk *cc, *back;

	if (!st || !(chn->flags & CF_ISRESP))
		goto end;

	list_for_each_entry_safe(cc, back, &st->comp_chunks, list) {
		LIST_DEL(&cc->list);
		free(cc);
	}

	if (!st->comp_algo || !s->txn->status)
		goto release_ctx;

	if (strm_fe(s)->mode == PR_MODE_HTTP)
		strm_fe(s)->fe_counters.p.http.comp_rsp++;
	if ((s->flags & SF_BE_ASSIGNED) && (s->be->mode == PR_MODE_HTTP))
		s->be->be_counters.p.http.comp_rsp++;

	/* release any possible compression context */
	st->comp_algo->end(&st->comp_ctx);

 release_ctx:
	free(st);
	filter->ctx = NULL;
 end:
	return 1;
}

static int
comp_http_headers(struct stream *s, struct filter *filter,
		  struct http_msg *msg)
{
	struct comp_state *st = filter->ctx;

	if (strm_fe(s)->comp || s->be->comp) {
		if (!(msg->chn->flags & CF_ISRESP))
			select_compression_request_header(st, s, msg);
	}
	return 1;
}

static int
comp_skip_http_chunk_envelope(struct stream *s, struct filter *filter,
			      struct http_msg *msg)
{
	struct comp_state *st = filter->ctx;
	unsigned int       start;
	int                ret;

	if (!(msg->chn->flags & CF_ISRESP) || !st->comp_algo) {
		flt_set_forward_data(filter, msg->chn);
		return 1;
	}

	start = FLT_NXT(filter, msg->chn) - FLT_FWD(filter, msg->chn);
	/* If this is the last chunk, we flag it */
	if (msg->chunk_len == 0 && msg->msg_state == HTTP_MSG_CHUNK_SIZE)
		ret = add_comp_chunk(st, start, 0, 1, 1);
	else
		ret = add_comp_chunk(st, start, msg->sol, 1, 0);

	return !ret ? 1 : -1;
}

static int
comp_http_data(struct stream *s, struct filter *filter,
		  struct http_msg *msg)
{
	struct comp_state *st = filter->ctx;
	unsigned int       start;
	int                is_last, ret;

	ret = MIN(msg->chunk_len + msg->next, msg->chn->buf->i) - FLT_NXT(filter, msg->chn);
	if (!(msg->chn->flags & CF_ISRESP) || !st->comp_algo) {
		flt_set_forward_data(filter, msg->chn);
		goto end;
	}
	if (!ret)
		goto end;

	start   = FLT_NXT(filter, msg->chn) - FLT_FWD(filter, msg->chn);
	is_last = (!(msg->flags & HTTP_MSGF_TE_CHNK) &&
		   (msg->chunk_len == ret - msg->next + FLT_NXT(filter, msg->chn)));

	if (add_comp_chunk(st, start, ret, 0, is_last) == -1)
		ret = -1;
 end:
	return ret;
}

static int
comp_http_forward_data(struct stream *s, struct filter *filter,
		       struct http_msg *msg, unsigned int len)
{
	struct comp_state *st = filter->ctx;
	struct comp_chunk *cc, *back;
	unsigned int       sz, consumed = 0, compressed = 0;
	int                is_last = 0, ret = len;

	if (!(msg->chn->flags & CF_ISRESP) || !st->comp_algo) {
		flt_set_forward_data(filter, msg->chn);
		goto end;
	}

	/* no data to forward or no chunk or the first chunk is too far */
	if (!len || LIST_ISEMPTY(&st->comp_chunks))
		goto end;
	if (st->first > len) {
		consumed = len;
		goto update_chunks;
	}

	/* initialize the buffer used to write compressed data */
	b_adv(msg->chn->buf, FLT_FWD(filter, msg->chn) + st->first);
	ret = http_compression_buffer_init(msg->chn->buf, tmpbuf);
	b_rew(msg->chn->buf, FLT_FWD(filter, msg->chn) + st->first);
	if (ret < 0) {
		msg->chn->flags |= CF_WAKE_WRITE;
		return 0;
	}

	/* Loop on all chunks */
	list_for_each_entry_safe(cc, back, &st->comp_chunks, list) {
		/* current chunk must not be handled yet */
		if (len <= cc->start) {
			consumed = len;
			break;
		}

		/* Get the number of bytes that must be handled in the current
		 * chunk */
		sz = MIN(len, cc->end) - cc->start;

		if (cc->skip) {
			/* No compression for this chunk, data must be
			 * skipped. This happens when the HTTP response is
			 * chunked, the chunk envelope is skipped. */
			ret = sz;
		}
		else {
			/* Compress the chunk */
			b_adv(msg->chn->buf, FLT_FWD(filter, msg->chn) + cc->start);
			ret = http_compression_buffer_add_data(st, msg->chn->buf, tmpbuf, sz);
			b_rew(msg->chn->buf, FLT_FWD(filter, msg->chn) + cc->start);
			if (ret < 0)
				goto end;
			compressed += ret;
		}

		/* Update the chunk by removing consumed bytes. If all bytes are
		 * consumed, the chunk is removed from the list and we
		 * loop. Otherwise, we stop here. */
		cc->start += ret;
		consumed = cc->start;
		if (cc->start != cc->end)
			break;

		/* Remember if this is the last chunk */
		is_last = cc->is_last;
		LIST_DEL(&cc->list);
		free(cc);
	}

	if (compressed) {
		/* Some data was compressed so we can switch buffers to replace
		 * uncompressed data by compressed ones. */
		b_adv(msg->chn->buf, FLT_FWD(filter, msg->chn) + st->first);
		ret = http_compression_buffer_end(st, s, &msg->chn->buf, &tmpbuf,
						  consumed - st->first, is_last);
		b_rew(msg->chn->buf, FLT_FWD(filter, msg->chn) + st->first);
	}
	else {
		/* Here some data was consumed but no compression was
		 * preformed. This means that all consumed data must be
		 * skipped.
		 */
		ret = skip_input_data(filter, msg, consumed);
	}

	if (is_last && !(msg->flags & HTTP_MSGF_TE_CHNK)) {
		/* At the end of data, if the original response was not
		 * chunked-encoded, we must write the empty chunk 0<CRLF>, and
		 * terminate the (empty) trailers section with a last <CRLF>. If
		 * we're forwarding a chunked-encoded response, these parts are
		 * preserved and not rewritten.
		 */
		char *p = bi_end(msg->chn->buf);
		memcpy(p, "0\r\n\r\n", 5);
		msg->chn->buf->i += 5;
		ret += 5;
	}

	/* Then, the last step. We need to update state of other filters. */
	if (ret >= 0) {
		flt_change_forward_size(filter, msg->chn, -(consumed - st->first - ret));
		msg->next -= (consumed - st->first - ret);
		ret += st->first;
	}

 update_chunks:
	/* Now, we need to update all remaining chunks to keep them synchronized
	 * with the next position of buf->p. If the chunk list is empty, we
	 * forward remaining data, if any. */
	st->first -= MIN(st->first, consumed);
	if (LIST_ISEMPTY(&st->comp_chunks))
		ret += len - consumed;
	else {
		list_for_each_entry(cc, &st->comp_chunks, list) {
			cc->start -= consumed;
			cc->end   -= consumed;
		}
	}

 end:
	return ret;
}

/***********************************************************************/
static int
add_comp_chunk(struct comp_state *st, unsigned int start, unsigned int len,
	       int skip, int is_last)
{
	struct comp_chunk *cc;

	if (!(cc = malloc(sizeof(*cc))))
		return -1;
	cc->start   = start;
	cc->end     = start + len;
	cc->skip    = skip;
	cc->is_last = is_last;

	if (LIST_ISEMPTY(&st->comp_chunks))
		st->first = cc->start;

	LIST_ADDQ(&st->comp_chunks, &cc->list);
	return 0;
}

/* This function might be moved in a filter function, probably with others to
 * add/remove/move/replace buffer data */
static int
skip_input_data(struct filter *filter, struct http_msg *msg,
		unsigned int consumed)
{
	struct comp_state *st = filter->ctx;
	int                block1, block2;

	/* 1. Copy input data, skipping consumed ones. */
	b_adv(msg->chn->buf, FLT_FWD(filter, msg->chn) + st->first + consumed);
	block1 = msg->chn->buf->i;
	if (block1 > bi_contig_data(msg->chn->buf))
		block1 = bi_contig_data(msg->chn->buf);
	block2 = msg->chn->buf->i - block1;

	memcpy(trash.str, bi_ptr(msg->chn->buf), block1);
	if (block2 > 0)
		memcpy(trash.str + block1, msg->chn->buf->data, block2);
	trash.len = block1 + block2;
	b_rew(msg->chn->buf, FLT_FWD(filter, msg->chn) + st->first + consumed);

	/* 2. Then write back these data at the right place in the buffer */
	b_adv(msg->chn->buf, FLT_FWD(filter, msg->chn) + st->first);
	block1 = trash.len;
	if (block1 > bi_contig_data(msg->chn->buf))
		block1 = bi_contig_data(msg->chn->buf);
	block2 = trash.len - block1;

	memcpy(bi_ptr(msg->chn->buf), trash.str, block1);
	if (block2 > 0)
		memcpy(msg->chn->buf->data, trash.str + block1, block2);
	b_rew(msg->chn->buf, FLT_FWD(filter, msg->chn) + st->first);

	/* Then adjut the input size */
	msg->chn->buf->i -= consumed;
	return 0;
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
			while (toklen < ctx.vlen && http_is_token[(unsigned char)*(ctx.line + ctx.val + toklen)])
				toklen++;

			qval = ctx.line + ctx.val + toklen;
			while (1) {
				while (qval < ctx.line + ctx.val + ctx.vlen && http_is_lws[(unsigned char)*qval])
					qval++;

				if (qval >= ctx.line + ctx.val + ctx.vlen || *qval != ';') {
					qval = NULL;
					break;
				}
				qval++;

				while (qval < ctx.line + ctx.val + ctx.vlen && http_is_lws[(unsigned char)*qval])
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
		return 0;

	/* select the smallest size between the announced chunk size, the input
	 * data, and the available output buffer size. The compressors are
	 * assumed to be able to process all the bytes we pass to them at
	 * once. */
	data_process_len = sz;
	data_process_len = MIN(out->size - buffer_len(out), data_process_len);


	block1 = data_process_len;
	if (block1 > bi_contig_data(in))
		block1 = bi_contig_data(in);
	block2 = data_process_len - block1;

	/* compressors return < 0 upon error or the amount of bytes read */
	consumed_data = st->comp_algo->add_data(st->comp_ctx, bi_ptr(in), block1, out);
	if (consumed_data >= 0 && block2 > 0) {
		consumed_data = st->comp_algo->add_data(st->comp_ctx, in->data, block2, out);
		if (consumed_data >= 0)
			consumed_data += block1;
	}
	return consumed_data;
}

/*
 * Flush data in process, and write the header and footer of the chunk. Upon
 * success, in and out buffers are swapped to avoid a copy.
 */
static int
http_compression_buffer_end(struct comp_state *st, struct stream *s,
			    struct buffer **in, struct buffer **out,
			    unsigned int consumed, int end)
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

	ob->i = tail - ob->p;
	to_forward = ob->i;

	/* update input rate */
	if (st->comp_ctx && st->comp_ctx->cur_lvl > 0) {
		update_freq_ctr(&global.comp_bps_in, consumed);
		strm_fe(s)->fe_counters.comp_in += consumed;
		s->be->be_counters.comp_in      += consumed;
	} else {
		strm_fe(s)->fe_counters.comp_byp += consumed;
		s->be->be_counters.comp_byp      += consumed;
	}

	/* copy the remaining data in the tmp buffer. */
	b_adv(ib, consumed);
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
		strm_fe(s)->fe_counters.comp_out += to_forward;
		s->be->be_counters.comp_out += to_forward;
	}

	return to_forward;
}


/***********************************************************************/
struct flt_ops comp_ops = {
	.init   = comp_flt_init,
	.deinit = comp_flt_deinit,

	.channel_start_analyze = comp_start_analyze,
	.channel_analyze       = comp_analyze,
	.channel_end_analyze   = comp_end_analyze,

	.http_headers      = comp_http_headers,
	.http_start_chunk  = comp_skip_http_chunk_envelope,
	.http_end_chunk    = comp_skip_http_chunk_envelope,
	.http_last_chunk   = comp_skip_http_chunk_envelope,
	.http_data         = comp_http_data,
	.http_forward_data = comp_http_forward_data,
};

static int
parse_compression_options(char **args, int section, struct proxy *proxy,
			  struct proxy *defpx, const char *file, int line,
			  char **err)
{
	struct comp    *comp;

	if (proxy->comp == NULL) {
		comp = calloc(1, sizeof(struct comp));
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
					 struct filter *filter, char **err)
{
	struct filter *flt, *back;

	list_for_each_entry_safe(flt, back, &px->filters, list) {
		if (flt->id == http_comp_flt_id) {
			memprintf(err, "%s: Proxy supports only one compression filter\n", px->id);
			return -1;
		}
	}

	filter->id   = http_comp_flt_id;
	filter->conf = NULL;
	filter->ops  = &comp_ops;
	(*cur_arg)++;

	return 0;
}


int
check_legacy_http_comp_flt(struct proxy *proxy)
{
	struct filter *filter;
	int err = 0;

	if (proxy->comp == NULL)
		goto end;
	if (!LIST_ISEMPTY(&proxy->filters)) {
		list_for_each_entry(filter, &proxy->filters, list) {
			if (filter->id == http_comp_flt_id)
				goto end;
		}
		Alert("config: %s '%s': require an explicit filter declaration to use HTTP compression\n",
		      proxy_type_str(proxy), proxy->id);
		err++;
		goto end;
	}

	filter = pool_alloc2(pool2_filter);
	if (!filter) {
		Alert("config: %s '%s': out of memory\n",
		      proxy_type_str(proxy), proxy->id);
		err++;
		goto end;
	}
	memset(filter, 0, sizeof(*filter));
	filter->id   = http_comp_flt_id;
	filter->conf = NULL;
	filter->ops  = &comp_ops;
	LIST_ADDQ(&proxy->filters, &filter->list);

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
	struct http_txn *txn = smp->strm->txn;

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
	struct http_txn   *txn = smp->strm->txn;
	struct filter     *filter;
	struct comp_state *st;

	if (!(txn || !(txn->rsp.flags & HTTP_MSGF_COMPRESSING)))
		return 0;

	list_for_each_entry(filter, &smp->strm->strm_flt.filters, list) {
		if (filter->id != http_comp_flt_id)
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
		{ "compression", parse_http_comp_flt },
		{ NULL, NULL },
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
}
