/*
 * Stream filters related to decompression.
 *
 * Copyright 2022 HAProxy Technologies
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
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
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/stream.h>
#include <haproxy/tools.h>

#define DECOMP_STATE_PROCESSING 0x01

const char *decomp_req_flt_id = "decomp-req filter";
const char *decomp_res_flt_id = "decomp-res filter";

struct flt_ops decomp_req_ops;
struct flt_ops decomp_res_ops;

struct decomp_state {
	struct decomp_ctx  *decomp_ctx;   /* decompression context */
	struct decomp_algo *decomp_algo;  /* decompression algorithm if not NULL */
	unsigned int      flags;          /* DECOMP_STATE_* */
};

/* Pools used to allocate comp_state structs */
DECLARE_STATIC_TYPED_POOL(pool_head_decomp_state, "decomp_state", struct decomp_state);

/***********************************************************************/
static int
decomp_flt_init(struct proxy *px, struct flt_conf *fconf)
{
	fconf->flags |= FLT_CFG_FL_HTX;
	return 0;
}

static int
decomp_strm_init(struct stream *s, struct filter *filter)
{
	struct decomp_dir *decomp_dir = FLT_CONF(filter);
	struct decomp_state *st;

	BUG_ON(!decomp_dir);

	if ((decomp_dir->flags & DECOMP_DIR_FL_MODE_NONE) || !decomp_dir->algos)
		return 0;

	st = pool_alloc(pool_head_decomp_state);
	if (st == NULL)
		return -1;

	st->decomp_algo = NULL;
	st->decomp_ctx = NULL;
	st->flags     = 0;
	filter->ctx   = st;

	return 1;
}

static void
decomp_strm_deinit(struct stream *s, struct filter *filter)
{
	struct decomp_state *st = filter->ctx;

	if (!st)
		return;

	/* release any possible decompression context */
	if (st->decomp_algo)
		st->decomp_algo->end(&st->decomp_ctx);
	pool_free(pool_head_decomp_state, st);
	filter->ctx = NULL;
}

/* for the non-htx decompression, returns the max number of bytes that
 * can be drained in the channel at a current time, depending on both
 * the channel buffer space available, the number of bytes about to be
 * consumed, and the number of bytes ready to be drained.
 */
static uint decomp_drainable_bytes(struct filter *f, struct channel *chn,
                                   uint consumed)
{
	struct decomp_state *st = f->ctx;
	int available;
	unsigned int max_drain;

	/* we take the responsibility to use some of the reserved space
	 * (global.tune.maxrewrite) as we work on output path and there is
	 * the possibility that we are called with no room left except for
	 * the reserve. As there may be another transformation filter right
	 * after us (ie: compression filter), we cannot simply use all the
	 * reserve space because this could cause such filters to stall. So
	 * instead we use up to one third of the reserve, which ensures that
	 * a potential compression filter coming right after us would work
	 * without any issue, at minima.
	 *
	 * We may need to compute this dynamically by taking into account
	 * the number of remaining filters in the chain some day FIXME.
	 *
	 * Note we rely on b_room() and not on b_contig_space() because
	 * b_rep_blk() is wrapping-proof, so a wrapping insertion is fine and
	 * the whole free space is usable.
	 */
	available = b_room(&chn->buf) - (global.tune.maxrewrite / 3);

	/* adjust available bytes according to consumed bytes which are about to be removed */
	available += consumed;

	if (available < 0)
		available = 0;

	max_drain = MIN(available, st->decomp_ctx->drain_len);

	return max_drain;
}

/* helper for decomp_strm_tcp_payload() function. It consumes as much input as
 * possible from <offset> in the channel buffer (up to <len> bytes), decompresses
 * it and writes the resulting bytes in place, where the consumed input was.
 *
 * It loops as long as it makes progress so that a single call flushes as much
 * data as the channel can take. This matters because the decompressed data may
 * be far bigger than the input: stopping after the first block would leave
 * pending data behind with nothing to trigger a new call once the input is
 * exhausted.
 *
 * The number of bytes ready to be forwarded is returned, or -1 on error.
 */
static int decomp_add_data(struct stream *s, struct filter *f, struct channel *chn,
                           unsigned int offset, unsigned int len)
{
	struct decomp_state *st = f->ctx;
	unsigned int total = 0; /* decompressed bytes written in the channel */
	int ret;

	while (1) {
		char *data = b_peek(&chn->buf, offset + total);
		unsigned int contig = b_contig_data(&chn->buf, offset + total);
		unsigned int consumed = 0;
		unsigned int data_len;
		uint drainable;

		/* we only look at contiguous input because b_rep_blk() requires
		 * the replaced block to not be interrupted by the wrapping
		 */
		data_len = MIN(len, contig);
		BUG_ON(data > b_wrap(&chn->buf));

		/* Refill the decompression buffer once the previous output was
		 * fully drained. An empty input is valid, it just asks the
		 * library to flush what it may still hold.
		 */
		if (!st->decomp_ctx->drain_len && !(st->decomp_ctx->flags & DECOMP_CTX_FL_DONE)) {
			ret = st->decomp_algo->add_data(st->decomp_ctx, data, data_len);
			if (ret == -1)
				goto error; /* fatal error */
			BUG_ON(ret > data_len);
			consumed = ret;
		}

		drainable = decomp_drainable_bytes(f, chn, consumed);

		if (!drainable && !consumed) {
			/* nothing moved: either no room left for the pending
			 * decompressed data, or the library needs more input
			 */
			break;
		}

		/* replace the consumed input with the decompressed data */
		b_rep_blk(&chn->buf, data, data + consumed,
			  (drainable ? st->decomp_ctx->drain : NULL), drainable);
		flt_update_offsets(f, chn, drainable - consumed);
		st->decomp_ctx->drain += drainable;
		st->decomp_ctx->drain_len -= drainable;
		total += drainable;
		len -= consumed;
	}

	if (len && !st->decomp_ctx->drain_len &&
	    (st->decomp_ctx->flags & DECOMP_CTX_FL_DONE)) {
		/* Decompression is over, drop any remaining input: it is not
		 * part of the compressed stream. This is not supposed to happen
		 * unless the input is garbage filled.
		 */
		char *data = b_peek(&chn->buf, offset + total);
		unsigned int drop = MIN(len, b_contig_data(&chn->buf, offset + total));

		b_rep_blk(&chn->buf, data, data + drop, NULL, 0);
		flt_update_offsets(f, chn, -drop);
		len -= drop;
	}

	if (st->decomp_ctx->drain_len) {
		/* We still have decompressed data to deliver but no room left
		 * for it. We surely don't want new input for now as it would
		 * eat up the space we need.
		 */
		channel_dont_read(chn);
	}
	else
		channel_auto_read(chn);

	return total;
  error:
	return -1;
}

static int decomp_strm_tcp_payload(struct stream *s, struct filter *f, struct channel *chn,
                                   unsigned int offset, unsigned int len)
{
	struct decomp_state *st = f->ctx;

	if (IS_HTX_STRM(s)) {
		/* TCP data within HTTP stream (ie: tunnel data) but it means
		 * the proxy was in HTTP mode, while we only care about TCP stream
		 * so let's ignore data.
		 */
		return len;
	}

	if (!chn->buf.area) {
		/* no buffer allocated for the channel, if we still have
		 * data to drain we actually need a buffer to write pending
		 * data
		 */
		if (!st->decomp_ctx->drain_len || channel_alloc_buffer(chn, &s->buffer_wait) == 0)
			return 0; /* either no data to drain, or failed to alloc buffer */
		/* we now have a buffer, let's continue */
	}

	return decomp_add_data(s, f, chn, offset, len);
}

/* decompress request oriented stream */
int decomp_strm_req_tcp_payload(struct stream *s, struct filter *f, struct channel *chn,
                                unsigned int offset, unsigned int len)
{
	if ((chn->flags & CF_ISRESP))
		return len; // nothing to do

	return decomp_strm_tcp_payload(s, f, chn, offset, len);
}

/* decompress response oriented stream */
int decomp_strm_res_tcp_payload(struct stream *s, struct filter *f, struct channel *chn,
                                unsigned int offset, unsigned int len)
{
	if (!(chn->flags & CF_ISRESP))
		return len; // nothing to do

	return decomp_strm_tcp_payload(s, f, chn, offset, len);
}

/* Returns decompression options to be used for <s> stream. Only
 * call this function when you know for sure that decompression filter
 * was declared on the proxy.
 * This function will never return NULL.
 */
static inline struct decomp *stream_get_decomp(struct stream *s)
{
	struct decomp *decomp;

	/* we consider be decompression options in over frontend ones
	 * unless it is not set at all on the be
	 */
	if (s->be->decomp && s->be->decomp->res.algos != NULL)
		decomp = s->be->decomp;
	else
		decomp = strm_fe(s)->decomp;

	/* we end up there via a filter callback in decompression context, thus
	 * we are not supposed to be called w/o decomp options allocated.
	 */
	BUG_ON(decomp == NULL);

	return decomp;
}

/* initialize decompression for decomp-req filter */
int decomp_channel_start_req_ana(struct stream *s, struct filter *f, struct channel *chn)
{
	struct decomp_state *st = f->ctx;
	struct decomp_dir *decomp_req = FLT_CONF(f);

	if ((chn->flags & CF_ISRESP))
		return 1; // nothing to do

	if (s->be->mode == PR_MODE_HTTP) {
		/* algo will be decided later based on HTTP headers */
		goto skip_algo;
	}

	/* in TCP, we only consider the first algo in the list, since the stream
	 * does not tell us which algo was used to compress it.
	 */
	st->decomp_algo = decomp_req->algos;
	if (st->decomp_algo->init(&st->decomp_ctx) < 0)
		goto fail;

	if (st->decomp_algo->stream_new && st->decomp_algo->stream_new(st->decomp_ctx) < 0)
		goto fail;

	st->flags |= DECOMP_STATE_PROCESSING;
	register_data_filter(s, chn, f);

 skip_algo:
	return 1;
 fail:
	return -1;
}

/* initialize decompression for decomp-res filter */
int decomp_channel_start_res_ana(struct stream *s, struct filter *f, struct channel *chn)
{
	struct decomp_state *st = f->ctx;
	struct decomp_dir *decomp_res = FLT_CONF(f);

	if (!(chn->flags & CF_ISRESP))
		return 1; // nothing to do

	if (s->be->mode == PR_MODE_HTTP) {
		/* algo will be decided later based on HTTP headers */
		goto skip_algo;
	}

	/* in TCP, we only consider the first algo in the list, since the stream
	 * does not tell us which algo was used to compress it.
	 */
	st->decomp_algo = decomp_res->algos;
	if (st->decomp_algo->init(&st->decomp_ctx) < 0)
		goto fail;

	if (st->decomp_algo->stream_new && st->decomp_algo->stream_new(st->decomp_ctx) < 0)
		goto fail;

	st->flags |= DECOMP_STATE_PROCESSING;
	register_data_filter(s, chn, f);

 skip_algo:
	return 1;
 fail:
	return -1;
}

int decomp_channel_end_ana(struct stream *s, struct filter *f, struct channel *chn)
{
	struct decomp_state *st = f->ctx;

	if (st->decomp_algo && st->decomp_algo->finish)
		return st->decomp_algo->finish(st->decomp_ctx);
	return 1;
}
/***********************************************************************/

struct flt_ops decomp_req_ops = {
	.init              = decomp_flt_init,

	.attach = decomp_strm_init,
	.detach = decomp_strm_deinit,
	.tcp_payload = decomp_strm_req_tcp_payload,
	.channel_start_analyze = decomp_channel_start_req_ana,
	.channel_end_analyze = decomp_channel_end_ana,
};

struct flt_ops decomp_res_ops = {
	.init              = decomp_flt_init,

	.attach = decomp_strm_init,
	.detach = decomp_strm_deinit,
	.tcp_payload = decomp_strm_res_tcp_payload,
	.channel_start_analyze = decomp_channel_start_res_ana,
	.channel_end_analyze = decomp_channel_end_ana,
};

/* returns decompression options from <proxy> proxy or allocates them if
 * needed
 *
 * When decompression options are created, flags will be set to <defaults>
 *
 * Returns NULL in case of memory error
 */
static inline struct decomp *proxy_get_decomp(struct proxy *proxy, int defaults)
{
	struct decomp    *decomp;

	if (proxy->decomp == NULL) {
		decomp = calloc(1, sizeof(*decomp));
		if (unlikely(!decomp))
			return NULL;
		decomp->flags = defaults;
		decomp->req.flags = DECOMP_DIR_FL_MODE_NONE;
		decomp->res.flags = DECOMP_DIR_FL_MODE_NONE;
		proxy->decomp = decomp;
	}
	return proxy->decomp;
}

static int
parse_decompression_options(char **args, int section, struct proxy *proxy,
			    const struct proxy *defpx, const char *file, int line,
			    char **err)
{
	struct decomp    *decomp;
	int ret = 0;

	decomp = proxy_get_decomp(proxy, DECOMP_FL_NONE);
	if (decomp == NULL) {
		memprintf(err, "'%s': out of memory.", args[0]);
		ret = -1;
		goto end;
	}

	if (strcmp(args[1], "algo-req") == 0) {
		struct decomp_ctx *ctx;
		int              cur_arg = 2;

		if (failifnotcap(proxy, PR_CAP_FE, file, line, args[1], NULL)) {
			ret = -1;
			goto end;
		}

		if (!*args[2]) {
			memprintf(err, "'%s %s' expects <algorithm>.", args[0], args[1]);
			ret = -1;
			goto end;
		}
		while (*(args[cur_arg])) {
			int retval;

			retval = decomp_append_algo(&decomp->req.algos, args[cur_arg]);
			if (retval) {
				if (retval < 0)
					memprintf(err, "'%s %s' : '%s' is not a supported algorithm.",
						  args[0], args[1], args[cur_arg]);
				else
					memprintf(err, "'%s %s' : out of memory while parsing algo '%s'.",
						  args[0], args[1], args[cur_arg]);
				ret = -1;
				goto end;
			}

			if (decomp->req.algos->init(&ctx) == 0)
				decomp->req.algos->end(&ctx);
			else {
				memprintf(err, "'%s %s' : Can't init '%s' algorithm.",
					  args[0], args[1], args[cur_arg]);
				ret = -1;
				goto end;
			}
			cur_arg++;
			continue;
		}
	}
	else if (strcmp(args[1], "algo-res") == 0) {
		struct decomp_ctx *ctx;
		int              cur_arg = 2;

		if (failifnotcap(proxy, PR_CAP_BE, file, line, args[1], NULL)) {
			ret = -1;
			goto end;
		}

		if (!*args[2]) {
			memprintf(err, "'%s %s' expects <algorithm>.", args[0], args[1]);
			ret = -1;
			goto end;
		}
		while (*(args[cur_arg])) {
			int retval;

			retval = decomp_append_algo(&decomp->res.algos, args[cur_arg]);
			if (retval) {
				if (retval < 0)
					memprintf(err, "'%s %s' : '%s' is not a supported algorithm.",
						  args[0], args[1], args[cur_arg]);
				else
					memprintf(err, "'%s %s' : out of memory while parsing algo '%s'.",
						  args[0], args[1], args[cur_arg]);
				ret = -1;
				goto end;
			}

			if (decomp->res.algos->init(&ctx) == 0)
				decomp->res.algos->end(&ctx);
			else {
				memprintf(err, "'%s %s' : Can't init '%s' algorithm.",
					  args[0], args[1], args[cur_arg]);
				ret = -1;
				goto end;
			}
			cur_arg++;
			continue;
		}
	}
	else if (strcmp(args[1], "mode-req") == 0 || strcmp(args[1], "mode-res") == 0) {
		int mode = 0;
		int req = 0;
		int err_code = 0;

		if (!*args[2]) {
			memprintf(err, "'%s %s' : expects 'none', 'auto' or 'always'.",
				  args[0], args[1]);
			ret = -1;
			goto end;
		}

		if (alertif_too_many_args_idx(1, 1, file, line, args, &err_code)) {
                        ret = -1;
			goto end;
                }

		if (strcmp(args[1] + 5, "req") == 0) {
			if (failifnotcap(proxy, PR_CAP_FE, file, line, args[1], NULL)) {
				ret = -1;
				goto end;
			}
			req = 1;
		}
		else if (failifnotcap(proxy, PR_CAP_BE, file, line, args[1], NULL)) {
			ret = -1;
			goto end;
		}


		if (strcmp(args[2], "none") == 0)
			mode = DECOMP_DIR_FL_MODE_NONE;
		else if (strcmp(args[2], "auto") == 0)
			mode = DECOMP_DIR_FL_MODE_AUTO;
		else if (strcmp(args[2], "always") == 0)
			mode = DECOMP_DIR_FL_MODE_ALWAYS;
		else {
			memprintf(err, "'%s %s' : expects 'none', 'auto' or 'always' (got '%s').",
				  args[0], args[1], args[2]);
			ret = -1;
			goto end;
		}

		if (req) {
			decomp->req.flags &= ~DECOMP_DIR_FL_MODE_MASK;
			decomp->req.flags |= mode;
		}
		else {
			decomp->res.flags &= ~DECOMP_DIR_FL_MODE_MASK;
			decomp->res.flags |= mode;
		}
	}
	else {
		memprintf(err, "'%s' : expects 'algo-req', 'algo-res', 'mode-req' or 'mode-res' (got '%s).",
			  args[0], args[1]);
		ret = -1;
		goto end;
	}

  end:
	return ret;
}

/* ensure decompression options are compatible with proxy configuration
 * during postparsing step.
 */
static int postcheck_decompression_options(struct proxy *px)
{
	if (px->decomp && px->mode != PR_MODE_HTTP &&
	    (((px->cap & PR_CAP_FE) && (px->decomp->req.flags & DECOMP_DIR_FL_MODE_AUTO)) ||
	     ((px->cap & PR_CAP_BE) && (px->decomp->res.flags & DECOMP_DIR_FL_MODE_AUTO)))) {
		ha_alert("%s '%s': cannot use 'auto' decompression mode with non HTTP proxy. Please review decompression options on the proxy.\n",  proxy_type_str(px), px->id);

		return ERR_ALERT | ERR_FATAL;
	}
	return ERR_NONE;
}
REGISTER_POST_PROXY_CHECK(postcheck_decompression_options);

static int
parse_decomp_req_flt(char **args, int *cur_arg, struct proxy *px,
                     struct flt_conf *fconf, char **err, void *private)
{
	struct flt_conf *fc;
	struct decomp *decomp;

	if (!(px->cap & PR_CAP_FE)) {
		memprintf(err, "'decomp-req' filter not allowed because %s '%s' has no frontend capability\n",
			  proxy_type_str(px), px->id);
		return -1;
	}

	list_for_each_entry(fc, &px->filter_configs, list) {
		if (fc->id == decomp_req_flt_id) {
			memprintf(err, "%s: Proxy supports only one decomp-req filter\n", px->id);
			return -1;
		}
	}

	decomp = proxy_get_decomp(px, 0);
	if (decomp == NULL) {
		memprintf(err, "memory failure\n");
		return -1;
	}
	decomp->flags |= DECOMP_FL_DIR_REQ;

	fconf->id   = decomp_req_flt_id;
	fconf->conf = &decomp->req;
	fconf->ops  = &decomp_req_ops;
	(*cur_arg)++;

	return 0;
}

static int
parse_decomp_res_flt(char **args, int *cur_arg, struct proxy *px,
                     struct flt_conf *fconf, char **err, void *private)
{
	struct flt_conf *fc;
	struct decomp *decomp;

	if (!(px->cap & PR_CAP_BE)) {
		memprintf(err, "'decomp-res' filter not allowed because %s '%s' has no backend capability\n",
			  proxy_type_str(px), px->id);
		return -1;
	}

	list_for_each_entry(fc, &px->filter_configs, list) {
		if (fc->id == decomp_res_flt_id) {
			memprintf(err, "%s: Proxy supports only one decomp-res filter\n", px->id);
			return -1;
		}
	}

	decomp = proxy_get_decomp(px, 0);
	if (decomp == NULL) {
		memprintf(err, "memory failure\n");
		return -1;
	}
	decomp->flags |= DECOMP_FL_DIR_RES;

	fconf->id   = decomp_res_flt_id;
	fconf->conf = &decomp->res;
	fconf->ops  = &decomp_res_ops;
	(*cur_arg)++;

	return 0;
}

/* Declare the config parser for "decompression" keyword */
static struct cfg_kw_list cfg_kws = {ILH, {
		{ CFG_LISTEN, "decompression", parse_decompression_options },
		{ 0, NULL, NULL },
	}
};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/* Declare the filter parser for "compression" keyword */
static struct flt_kw_list filter_kws = { "COMP", { }, {
		{ "decomp-req", parse_decomp_req_flt, NULL },
		{ "decomp-res", parse_decomp_res_flt, NULL },
		{ NULL, NULL, NULL },
	}
};

INITCALL1(STG_REGISTER, flt_register_keywords, &filter_kws);

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, sample_register_fetches, &sample_fetch_keywords);
