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
#include <proto/hdr_idx.h>
#include <proto/proto_http.h>
#include <proto/sample.h>
#include <proto/stream.h>


/***********************************************************************/
/*
 * Selects a compression algorithm depending on the client request.
 */
int
select_compression_request_header(struct stream *s, struct buffer *req)
{
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->req;
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
		s->comp_algo = NULL;
		return 0;
	}

	/* search for the algo in the backend in priority or the frontend */
	if ((s->be->comp && (comp_algo_back = s->be->comp->algos)) || (strm_fe(s)->comp && (comp_algo_back = strm_fe(s)->comp->algos))) {
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
					s->comp_algo = comp_algo;
					best_q = q;
					break;
				}
			}
		}
	}

	/* remove all occurrences of the header when "compression offload" is set */
	if (s->comp_algo) {
		if ((s->be->comp && s->be->comp->offload) || (strm_fe(s)->comp && strm_fe(s)->comp->offload)) {
			http_remove_header2(msg, &txn->hdr_idx, &ctx);
			ctx.idx = 0;
			while (http_find_header2("Accept-Encoding", 15, req->p, &txn->hdr_idx, &ctx)) {
				http_remove_header2(msg, &txn->hdr_idx, &ctx);
			}
		}
		return 1;
	}

	/* identity is implicit does not require headers */
	if ((s->be->comp && (comp_algo_back = s->be->comp->algos)) || (strm_fe(s)->comp && (comp_algo_back = strm_fe(s)->comp->algos))) {
		for (comp_algo = comp_algo_back; comp_algo; comp_algo = comp_algo->next) {
			if (comp_algo->cfg_name_len == 8 && memcmp(comp_algo->cfg_name, "identity", 8) == 0) {
				s->comp_algo = comp_algo;
				return 1;
			}
		}
	}

	s->comp_algo = NULL;
	return 0;
}

/*
 * Selects a comression algorithm depending of the server response.
 */
int
select_compression_response_header(struct stream *s, struct buffer *res)
{
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->rsp;
	struct hdr_ctx ctx;
	struct comp_type *comp_type;

	/* no common compression algorithm was found in request header */
	if (s->comp_algo == NULL)
		goto fail;

	/* HTTP < 1.1 should not be compressed */
	if (!(msg->flags & HTTP_MSGF_VER_11) || !(txn->req.flags & HTTP_MSGF_VER_11))
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
		if ((s->be->comp && s->be->comp->types) || (strm_fe(s)->comp && strm_fe(s)->comp->types))
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
	if (s->comp_algo->init(&s->comp_ctx, global.tune.comp_maxlevel) < 0)
		goto fail;

	s->flags |= SF_COMP_READY;

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
	if (s->comp_algo->cfg_name_len != 8 || memcmp(s->comp_algo->cfg_name, "identity", 8) != 0) {
		trash.len = 18;
		memcpy(trash.str, "Content-Encoding: ", trash.len);
		memcpy(trash.str + trash.len, s->comp_algo->ua_name, s->comp_algo->ua_name_len);
		trash.len += s->comp_algo->ua_name_len;
		trash.str[trash.len] = '\0';
		http_header_add_tail2(&txn->rsp, &txn->hdr_idx, trash.str, trash.len);
	}
	return 1;

fail:
	s->comp_algo = NULL;
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
int
http_compression_buffer_init(struct stream *s, struct buffer *in, struct buffer *out)
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
int
http_compression_buffer_add_data(struct stream *s, struct buffer *in, struct buffer *out)
{
	struct http_msg *msg = &s->txn->rsp;
	int consumed_data = 0;
	int data_process_len;
	int block1, block2;

	/*
	 * Temporarily skip already parsed data and chunks to jump to the
	 * actual data block. It is fixed before leaving.
	 */
	b_adv(in, msg->next);

	/*
	 * select the smallest size between the announced chunk size, the input
	 * data, and the available output buffer size. The compressors are
	 * assumed to be able to process all the bytes we pass to them at once.
	 */
	data_process_len = MIN(in->i, msg->chunk_len);
	data_process_len = MIN(out->size - buffer_len(out), data_process_len);

	block1 = data_process_len;
	if (block1 > bi_contig_data(in))
		block1 = bi_contig_data(in);
	block2 = data_process_len - block1;

	/* compressors return < 0 upon error or the amount of bytes read */
	consumed_data = s->comp_algo->add_data(s->comp_ctx, bi_ptr(in), block1, out);
	if (consumed_data >= 0 && block2 > 0) {
		consumed_data = s->comp_algo->add_data(s->comp_ctx, in->data, block2, out);
		if (consumed_data >= 0)
			consumed_data += block1;
	}

	/* restore original buffer pointer */
	b_rew(in, msg->next);
	return consumed_data;
}

/*
 * Flush data in process, and write the header and footer of the chunk. Upon
 * success, in and out buffers are swapped to avoid a copy.
 */
int
http_compression_buffer_end(struct stream *s, struct buffer **in, struct buffer **out, int end)
{
	int to_forward;
	int left;
	struct http_msg *msg = &s->txn->rsp;
	struct buffer *ib = *in, *ob = *out;
	char *tail;

#if defined(USE_SLZ) || defined(USE_ZLIB)
	int ret;

	/* flush data here */

	if (end)
		ret = s->comp_algo->finish(s->comp_ctx, ob); /* end of data */
	else
		ret = s->comp_algo->flush(s->comp_ctx, ob); /* end of buffer */

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
	if (msg->msg_state >= HTTP_MSG_TRAILERS) {
		memcpy(tail, "0\r\n", 3);
		tail += 3;
		if (msg->msg_state >= HTTP_MSG_ENDING) {
			memcpy(tail, "\r\n", 2);
			tail += 2;
		}
	}
	ob->i = tail - ob->p;

	to_forward = ob->i;

	/* update input rate */
	if (s->comp_ctx && s->comp_ctx->cur_lvl > 0) {
		update_freq_ctr(&global.comp_bps_in, msg->next);
		strm_fe(s)->fe_counters.comp_in += msg->next;
		s->be->be_counters.comp_in += msg->next;
	} else {
		strm_fe(s)->fe_counters.comp_byp += msg->next;
		s->be->be_counters.comp_byp += msg->next;
	}

	/* copy the remaining data in the tmp buffer. */
	b_adv(ib, msg->next);
	msg->next = 0;

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

	if (s->comp_ctx && s->comp_ctx->cur_lvl > 0) {
		update_freq_ctr(&global.comp_bps_out, to_forward);
		strm_fe(s)->fe_counters.comp_out += to_forward;
		s->be->be_counters.comp_out += to_forward;
	}

	/* forward the new chunk without remaining data */
	b_adv(ob, to_forward);

	return to_forward;
}


/***********************************************************************/
static int
parse_compression_options(char **args, int section, struct proxy *proxy,
			  struct proxy *defpx, const char *file, int line,
			  char **err)
{
	struct comp *comp;

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

/* boolean, returns true if compression is used (either gzip or deflate) in the response */
static int
smp_fetch_res_comp(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = (smp->strm->comp_algo != NULL);
	return 1;
}

/* string, returns algo */
static int
smp_fetch_res_comp_algo(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!smp->strm->comp_algo)
		return 0;

	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_CONST;
	smp->data.u.str.str = smp->strm->comp_algo->cfg_name;
	smp->data.u.str.len = smp->strm->comp_algo->cfg_name_len;
	return 1;
}

/* Declare the config parser for "compression" keyword */
static struct cfg_kw_list cfg_kws = {ILH, {
		{ CFG_LISTEN, "compression", parse_compression_options },
		{ 0, NULL, NULL },
	}
};

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
	{ "res.comp",      smp_fetch_res_comp,      0, NULL, SMP_T_BOOL, SMP_USE_HRSHP },
	{ "res.comp_algo", smp_fetch_res_comp_algo, 0, NULL, SMP_T_STR, SMP_USE_HRSHP },
	{ /* END */ },
}};

__attribute__((constructor))
static void __flt_http_comp_init(void)
{
	cfg_register_keywords(&cfg_kws);
	sample_register_fetches(&sample_fetch_keywords);
}
