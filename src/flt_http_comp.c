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

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/compression.h>
#include <haproxy/dynbuf.h>
#include <haproxy/filters.h>
#include <haproxy/http.h>
#include <haproxy/http_ana-t.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/list.h>
#include <haproxy/proxy-t.h>
#include <haproxy/sample.h>
#include <haproxy/stream.h>
#include <haproxy/tools.h>

const char *http_comp_flt_id = "compression filter";

struct flt_ops comp_ops;

struct comp_state {
	struct comp_ctx  *comp_ctx;   /* compression context */
	struct comp_algo *comp_algo;  /* compression algorithm if not NULL */
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
comp_strm_init(struct stream *s, struct filter *filter)
{
	struct comp_state *st;

	st = pool_alloc_dirty(pool_head_comp_state);
	if (st == NULL)
		return -1;

	st->comp_algo = NULL;
	st->comp_ctx  = NULL;
	filter->ctx   = st;

	/* Register post-analyzer on AN_RES_WAIT_HTTP because we need to
	 * analyze response headers before http-response rules execution
	 * to be sure we can use res.comp and res.comp_algo sample
	 * fetches */
	filter->post_analyzers |= AN_RES_WAIT_HTTP;
	return 1;
}

static void
comp_strm_deinit(struct stream *s, struct filter *filter)
{
	struct comp_state *st = filter->ctx;

	if (!st)
		return;

	/* release any possible compression context */
	if (st->comp_algo)
		st->comp_algo->end(&st->comp_ctx);
	pool_free(pool_head_comp_state, st);
	filter->ctx = NULL;
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
	struct htx_ret htxret = htx_find_offset(htx, offset);
	struct htx_blk *blk;
	int ret, consumed = 0, to_forward = 0;

	blk = htxret.blk;
	offset = htxret.ret;
	for (; blk && len; blk = htx_get_next_blk(htx, blk)) {
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

			case HTX_BLK_TLR:
			case HTX_BLK_EOT:
			case HTX_BLK_EOM:
				if (msg->flags & HTTP_MSGF_COMPRESSING) {
					if (htx_compression_buffer_init(htx, &trash) < 0) {
						msg->chn->flags |= CF_WAKE_WRITE;
						goto end;
					}
					if (htx_compression_buffer_end(st, &trash, 1) < 0)
						goto error;
					if (b_data(&trash)) {
						struct htx_blk *last = htx_add_last_data(htx, ist2(b_head(&trash), b_data(&trash)));
						if (!last)
							goto error;
						blk = htx_get_next_blk(htx, last);
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
	}

  end:
	if (to_forward != consumed)
		flt_update_offsets(filter, msg->chn, to_forward - consumed);

	if (st->comp_ctx && st->comp_ctx->cur_lvl > 0) {
		update_freq_ctr(&global.comp_bps_in, consumed);
		_HA_ATOMIC_ADD(&strm_fe(s)->fe_counters.comp_in, consumed);
		_HA_ATOMIC_ADD(&s->be->be_counters.comp_in, consumed);
		update_freq_ctr(&global.comp_bps_out, to_forward);
		_HA_ATOMIC_ADD(&strm_fe(s)->fe_counters.comp_out, to_forward);
		_HA_ATOMIC_ADD(&s->be->be_counters.comp_out, to_forward);
	} else {
		_HA_ATOMIC_ADD(&strm_fe(s)->fe_counters.comp_byp, consumed);
		_HA_ATOMIC_ADD(&s->be->be_counters.comp_byp, consumed);
	}
	return to_forward;

  error:
	return -1;
}


static int
comp_http_end(struct stream *s, struct filter *filter,
	      struct http_msg *msg)
{
	struct comp_state *st = filter->ctx;

	if (!(msg->chn->flags & CF_ISRESP) || !st || !st->comp_algo)
		goto end;

	if (strm_fe(s)->mode == PR_MODE_HTTP)
		_HA_ATOMIC_ADD(&strm_fe(s)->fe_counters.p.http.comp_rsp, 1);
	if ((s->flags & SF_BE_ASSIGNED) && (s->be->mode == PR_MODE_HTTP))
		_HA_ATOMIC_ADD(&s->be->be_counters.p.http.comp_rsp, 1);
 end:
	return 1;
}

/***********************************************************************/
static int
set_compression_response_header(struct comp_state *st, struct stream *s, struct http_msg *msg)
{
	struct htx *htx = htxbuf(&msg->chn->buf);
	struct http_hdr_ctx ctx;

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
		ctx.blk = NULL;
		while (http_find_header(htx, ist("Content-Length"), &ctx, 1))
			http_remove_header(htx, &ctx);
	}

	/* add "Transfer-Encoding: chunked" header */
	if (!(msg->flags & HTTP_MSGF_TE_CHNK)) {
		if (!http_add_header(htx, ist("Transfer-Encoding"), ist("chunked")))
			goto error;
	}

	/* convert "ETag" header to a weak ETag */
	ctx.blk = NULL;
	if (http_find_header(htx, ist("ETag"), &ctx, 1)) {
		if (ctx.value.ptr[0] == '"') {
			/* This a strong ETag. Convert it to a weak one. */
			struct ist v = ist2(trash.area, 0);
			if (istcat(&v, ist("W/"), trash.size) == -1 || istcat(&v, ctx.value, trash.size) == -1)
				goto error;

			if (!http_replace_header_value(htx, &ctx, v))
				goto error;
		}
	}

	if (!http_add_header(htx, ist("Vary"), ist("Accept-Encoding")))
		goto error;

	return 1;

  error:
	st->comp_algo->end(&st->comp_ctx);
	st->comp_algo = NULL;
	return 0;
}

/*
 * Selects a compression algorithm depending on the client request.
 */
static int
select_compression_request_header(struct comp_state *st, struct stream *s, struct http_msg *msg)
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

/*
 * Selects a compression algorithm depending of the server response.
 */
static int
select_compression_response_header(struct comp_state *st, struct stream *s, struct http_msg *msg)
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

	/* no compression when ETag is malformed */
	ctx.blk = NULL;
	if (http_find_header(htx, ist("ETag"), &ctx, 1)) {
		if (http_get_etag_type(ctx.value) == ETAG_INVALID)
			goto fail;
	}
	/* no compression when multiple ETags are present
	 * Note: Do not reset ctx.blk!
	 */
	if (http_find_header(htx, ist("ETag"), &ctx, 1))
		goto fail;

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
	if (ti->idle_pct < compress_min_idle)
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

/***********************************************************************/
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

static int
htx_compression_buffer_add_data(struct comp_state *st, const char *data, size_t len,
				struct buffer *out)
{
	return st->comp_algo->add_data(st->comp_ctx, data, len, out);
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

	.attach = comp_strm_init,
	.detach = comp_strm_deinit,

	.channel_post_analyze  = comp_http_post_analyze,

	.http_headers          = comp_http_headers,
	.http_payload          = comp_http_payload,
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

	if (strcmp(args[1], "algo") == 0) {
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
	else if (strcmp(args[1], "offload") == 0)
		comp->offload = 1;
	else if (strcmp(args[1], "type") == 0) {
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
			else if (fconf->id == fcgi_flt_id)
				continue;
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
