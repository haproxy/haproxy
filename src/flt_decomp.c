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
#define DECOMP_STATE_EOM_SEEN   0x02

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

	/* Register post-analyzer on AN_RES_WAIT_HTTP because we need to
	 * analyze response headers before http-response rules execution
	 */
	filter->post_analyzers |= AN_RES_WAIT_HTTP;

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

/* tries to write as many pending bytes (decoded bytes) as possible in the stream,
 * by taking into account the stream buffer space, and already <consumed> bytes
 * which will be removed first.
 */
static int decomp_stream_blk_drain(struct stream *s, struct filter *f, struct channel *chn,
                                   struct htx_blk **blk, char *offset, unsigned int consumed)
{
	struct decomp_state *st = f->ctx;
	struct htx *htx = htxbuf(&chn->buf);
	int drainable = 0;
	int free_space = htx_free_data_space(htx);

	if (!st->decomp_ctx->drain_len)
		return 0; // nothing to do

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
	 */
	free_space -= global.tune.maxrewrite / 3;

	/* adjust available bytes according to consumed bytes which are about to be removed
	 * block creation was already taken into account through htx_free_data_space()
	 */
	free_space += consumed;

	if (free_space < 0)
		free_space = 0;

	drainable = MIN(free_space, st->decomp_ctx->drain_len);

	if (blk) {
		struct htx_blk *new_blk;

		new_blk = htx_replace_blk_value(htx, *blk, ist2(offset, consumed), ist2(st->decomp_ctx->drain, drainable));
		if (!new_blk) {
			/* The expansion failed. The space was checked above so this
			 * can only be the trash chunk allocation of the defragmenting
			 * path. Leave the pending data untouched, the caller will
			 * retry later: advancing the drain state here would both lose
			 * the decompressed data and hand a NULL block to the caller.
			 */
			return 0;
		}
		*blk = new_blk;
	}
	else {
		/* first we have to convert the htx from buf using htx_from_buf()
		 * since we were given empty htx and we are about to fill it with data
		 */
		htx = htx_from_buf(&chn->buf);
		/* We use add_last_data on purpose (instead of add_data()) because we
		 * want to ensure that data is appended at the right place if the htx
		 * wasn't empty (ie: if there is EOT block in the HTX, we want to make
		 * sure the data is inserted before).
		 *
		 * <drainable> number of bytes were checked to fit in the htx above,
		 * but the insertion may still fail on a defragmentation failure
		 */
		if (!htx_add_last_data(htx, ist2(st->decomp_ctx->drain, drainable)))
			return 0;
	}

	flt_update_offsets(f, chn, drainable - consumed);
	st->decomp_ctx->drain += drainable;
	st->decomp_ctx->drain_len -= drainable;

	return drainable;
}

/* Reads input stream and decompress as many bytes as possible which will be removed
 * from the stream, then try to write as many decoded bytes as possible in the stream.
 */
static int decomp_stream_blk(struct stream *s, struct filter *f, struct channel *chn,
                             unsigned int offset, unsigned int len)
{
	struct decomp_state *st = f->ctx;
	struct htx *htx = htx_from_buf(&chn->buf);
	struct htx_ret htxret;
	struct htx_blk *blk, *next;
	struct ist val;
	uint32_t blk_remain;
	int ret;
	unsigned int consumed = 0;
	int total = 0;

	if (!st->decomp_ctx) {
		total = len;
		goto end;
	}

	htxret = htx_find_offset(htx, offset);
	offset = htxret.ret;
	blk = htxret.blk;

	/* Remove EOM flag from HTX message to be sure to not expose it too
	 * early to next filters. But save the information to be able to restore
	 * the flag at the end of the decompression.
	 */
	if (htx->flags & HTX_FL_EOM) {
		st->flags |= DECOMP_STATE_EOM_SEEN;
		htx->flags &= ~HTX_FL_EOM;
	}

	while (blk && len) {
		blk_remain = 0;
		/* next is special variable that must be set to NULL, it will be used at the
		 * end of the loop if != NULL instead of htx_get_next_blk(). This is to
		 * permit inner code (within the loop) to override the next blk when we know
		 * htx_get_next_blk() is not suitable (ie: when current blk is set to NULL because
		 * it was removed)
		 */
		next = NULL;
		switch (htx_get_blk_type(blk)) {
			case HTX_BLK_UNUSED:
				goto next;
			case HTX_BLK_DATA:
				val = htx_get_blk_value(htx, blk);
				val = istadv(val, offset);
				blk_remain = val.len;

				if (val.len > len)
					val.len = len;

				/* check if there remains undrained data from previous call before
				 * attempting to decompress new data. We will potentially increase
				 * blk size but not decrease it
				 */
				if (st->decomp_ctx->drain_len) {
					ret = decomp_stream_blk_drain(s, f, chn, &blk, val.ptr, 0);
					total += ret;

					if (st->decomp_ctx->drain_len) {
						/* out of space already, not worth decompressing for now */
						goto end;
					}

					val = htx_get_blk_value(htx, blk);
					val = istadv(val, offset + ret);
					if (val.len > len)
						val.len = len;
				}

				if (st->decomp_ctx->flags & DECOMP_CTX_FL_DONE) {
					/* nothing to do anymore, consume optional
					 * input data, although this is not supposed to
					 * happen if the input is not garbage filled and
					 * decompression library consumed all data
					 */
					flt_update_offsets(f, chn, -val.len);

					/* skip consumed bytes: remove the block if empty due to skipping
					 * bytes because it is not supported to leave empty htx data block
					 */
					if (val.len == htx_get_blksz(blk)) {
						next = htx_remove_blk(htx, blk);
						blk = NULL; // make sure we don't use the old block
					}
					else
						blk = htx_replace_blk_value(htx, blk, ist2(val.ptr, val.len), ist2("", 0));

					blk_remain -= val.len;
					len -= val.len;
					goto next;
				}

				/* try to decompress new data */
				ret = st->decomp_algo->add_data(st->decomp_ctx, val.ptr, val.len);

				if (ret == -1)
					goto error; // fatal error

				/* returned value = consumed bytes */
				consumed = ret;
				len -= consumed;
				blk_remain -= consumed;

				if (st->decomp_ctx->drain_len) {
					ret = decomp_stream_blk_drain(s, f, chn, &blk, val.ptr, consumed);
					total += ret;

					if (st->decomp_ctx->drain_len) {
						/* we need space to finish decompressing, but we surely don't want
						 * new input for now as it will eat up space
						 */
						channel_dont_read(chn);
						goto end;
					}
				}
				else {
					flt_update_offsets(f, chn, -consumed);

					/* skip consumed bytes: remove the block if empty due to skipping
					 * bytes because it is not supported to leave empty htx data block
					 */
					if (consumed == htx_get_blksz(blk)) {
						next = htx_remove_blk(htx, blk);
						blk = NULL; // make sure we don't use the old block
					}
					else
						blk = htx_replace_blk_value(htx, blk, ist2(val.ptr, consumed), ist2("", 0));
				}
				break;

			case HTX_BLK_EOT:
				if (st->decomp_ctx->drain_len) {
					/* there is still pending data that we need to drain */
					break;
				}
				if (!(st->decomp_ctx->flags & DECOMP_CTX_FL_DONE)) {
					char *data = "";

					/* ensure there isn't remaining data in the decomp state buffer:
					 * we don't have new input data, yet the library expects valid
					 * input pointer, so we just provide an empty buffer
					 */
					ret = st->decomp_algo->add_data(st->decomp_ctx, data, 0);
					if (ret == -1)
						goto error;

					break; /* if decomp_ctx->drain_len is set it will be taken
					        * care of
						*/

				}

				/* don't forget some out of payload data such as EOT count as forwarded
				 * bytes in HTX API
				 */
				total += htx_get_blksz(blk) - offset;

				break;

			default:
				/* nothing to do with that, just forward */
				total += htx_get_blksz(blk);
				break;
		}

 next:
		if (blk_remain) {
			/* not worth pursuing, we are not allowed to read past
			 * this point
			 */
			goto end;
		}

		if (next)
			blk = next; // next override requested
		else
			blk = htx_get_next_blk(htx, blk);
		offset = 0;
	}

	if (total) {
		/* ask for input data */
		channel_auto_read(chn);
	}
	else {
		/* nothing was written so far, either there is nothing to write and
		 * the following code will be NO-OP, else it means we were called without
		 * data block so there was no were to drain our data, in which case we
		 * pass NULL as blk argument to decomp_stream_blk_drain() so that it
		 * creates the block itself
		 */
		ret = decomp_stream_blk_drain(s, f, chn, NULL, NULL, 0);
		total += ret;

		if (!(st->decomp_ctx->flags & DECOMP_CTX_FL_DONE)) {
			char *data = "";

			/* ensure there isn't remaining data in the decomp state buffer:
			 * we don't have new input data, yet the library expects valid
			 * input pointer, so we just provide an empty buffer
			 */
			ret = st->decomp_algo->add_data(st->decomp_ctx, data, 0);
			if (ret == -1)
				goto error;

			ret = decomp_stream_blk_drain(s, f, chn, NULL, NULL, 0);
			total += ret;
		}
	}

	if ((st->decomp_ctx->flags & DECOMP_CTX_FL_DONE) && !st->decomp_ctx->drain_len) {
		st->flags &= ~DECOMP_STATE_PROCESSING;

		/* The decompression is finished and we must now restore the EOM
		 * flag on the HTX message. We must also take care to forward
		 * any EOT block added to support the EOM flag.
		 */
		if (st->flags & DECOMP_STATE_EOM_SEEN) {
			unsigned int data = htx->data;

			BUG_ON(!(st->decomp_ctx->flags & DECOMP_CTX_FL_DONE) || st->decomp_ctx->drain_len);
			htx_set_eom(htx);
			total += htx->data - data;
		}
	}
  end:
	htx_to_buf(htx, &chn->buf);
	return total;

  error:
	/* On error, restore HTX_FL_EOM flag */
	if (st->flags & DECOMP_STATE_EOM_SEEN)
		htx->flags |= HTX_FL_EOM;
	htx_to_buf(htx, &chn->buf);
	return -1;
}

/* checks the input HTTP headers to guess if the body is compressed and if we
 * support the encoding used. Then if we enabled decompression, add relevant
 * headers to stream the body in chunked mode since we don't know what will
 * be the final body size.
 */
static int decomp_strm_http_headers(struct stream *s, struct filter *f, struct http_msg *msg)
{
	struct decomp_dir *decomp_dir = FLT_CONF(f);
	struct decomp_state *st = f->ctx;
	struct htx *htx = htxbuf(&msg->chn->buf);
	struct htx_sl *sl;
	struct http_hdr_ctx ctx = { .blk = NULL };
	int encoded = 0; // set to 1 if the body is encoded

	/* Messages known to carry no payload must be left completely untouched:
	 * there is nothing to decompress, switching them to the chunked encoding
	 * would emit an invalid message (RFC9112#6.1 forbids a body, and thus any
	 * framing header, on 1xx/204/304 and on responses to HEAD) and the data
	 * filter would then wait forever for a body that never comes. Note we
	 * must not remove "Content-Encoding" either: on a 304 it describes the
	 * stored representation and caches rely on it to revalidate their entry.
	 */
	if (msg->flags & HTTP_MSGF_BODYLESS)
		goto no_decomp;

	if (msg->chn->flags & CF_ISRESP) {
		struct http_txn *txn = s->txn.http;

		/* 1xx/204/304 and responses to HEAD have no body. A 2xx reply to
		 * a CONNECT has no body either, what follows is tunneled data.
		 */
		if (txn->status < 200 || txn->status == 204 || txn->status == 304 ||
		    txn->meth == HTTP_METH_HEAD || txn->meth == HTTP_METH_CONNECT)
			goto no_decomp;
	}

	/* we call http_find_header with <full> set to 0, this way we
	 * will iterated over ALL individual values (separated by coma)
	 */
	while (http_find_header(htx, ist("content-encoding"), &ctx, 0)) {
		struct decomp_algo *decomp_algo = decomp_dir->algos;

		encoded = 1;
		while (decomp_algo) {
			/* content codings are case-insensitive (RFC9110#8.4.1), and the
			 * whole token must match: comparing over ctx.value.len only
			 * would make any prefix of the algo name match it
			 */
			if (decomp_algo->ua_name_len == ctx.value.len &&
			    strncasecmp(decomp_algo->ua_name, ctx.value.ptr, ctx.value.len) == 0) {
				/* content is compressed using supported (and selected)
				 * compression algorithm, so let's enable content decompression
				 */
				st->decomp_algo = decomp_algo;
				goto decomp;
			}
			decomp_algo = decomp_algo->next;
		}
        }

	if (!encoded)
		goto no_decomp;

	/* we arrive here if "content-encoding" is set but we didn't find a matching algo */
	if (decomp_dir->flags & DECOMP_DIR_FL_MODE_ALWAYS) {
		/* we're on the response and 'always' mode was requested on the response
		 * or we're on the request and 'always' mode was requested on the request:
		 * this is a hard error, we need to terminate the stream as we are not able
		 * to decompress it and thus not able to guarantee a decompressed output.
		 *
		 * FIXME: returning an error here will cause the stream to be closed right
		 * away, if this not what we intend, we will have to delay the error and
		 * allow some data like the headers to pass through?
		 */
		goto early_error;
	}

	/* we cannot decompress the stream, but we are in 'auto' mode, which is
	 * best-effort, so we simply let the stream flow, effectively bypassing the
	 * decompression filter (we didn't enable it on the stream), but we don't
	 * return any error.
	 */
 no_decomp:
	return 1;

 decomp:

	/* we need to init the decomp algo because with HTTP it was deferred
	 * until we learned the algo to be used from http headers.
	 */
	if (st->decomp_algo->init(&st->decomp_ctx) < 0)
		goto early_error;

	if (st->decomp_algo->stream_new && st->decomp_algo->stream_new(st->decomp_ctx) < 0)
		goto error;

	sl = http_get_stline(htx);
	if (!sl)
		goto error;

	/* add "Transfer-Encoding: chunked" header */
	if (!(msg->flags & HTTP_MSGF_TE_CHNK)) {
		if (!http_add_header(htx, ist("Transfer-Encoding"), ist("chunked"), 0))
			goto error;
		msg->flags |= HTTP_MSGF_TE_CHNK;
		sl->flags |= (HTX_SL_F_XFER_ENC|HTX_SL_F_CHNK);
	}

	/* remove Content-Length header */
	if (msg->flags & HTTP_MSGF_CNT_LEN) {
		ctx.blk = NULL;
		while (http_find_header(htx, ist("Content-Length"), &ctx, 1))
			http_remove_header(htx, &ctx);
		msg->flags &= ~HTTP_MSGF_CNT_LEN;
		sl->flags &= ~HTX_SL_F_CLEN;
	}

	/* remove content-encoding header */
	ctx.blk = NULL;
	while (http_find_header(htx, ist("Content-Encoding"), &ctx, 1))
		http_remove_header(htx, &ctx);

	if (msg->chn->flags & CF_ISRESP) {
		/* decompression enabled on the response, and we will alter it since
		 * we just engaged decompression. Let's remove any "accept-encoding"
		 * value from vary header
		 */
		ctx.blk = NULL;
		/* we call http_find_header with <full> set to 0, this way we
		 * will iterated over ALL individual values (separated by coma)
		 */
		while (http_find_header(htx, ist("Vary"), &ctx, 0)) {
			/* the whole token must match: comparing over ctx.value.len only
			 * would also remove any value that is a prefix of
			 * "accept-encoding", and "Vary: Accept" is a common one
			 */
			if (isteqi(ctx.value, ist("accept-encoding"))) {
				/* http_remove_header automatically removes the header
				 * if we removed the last value
				 */
				http_remove_header(htx, &ctx);
			}
		}
	}

	/* convert a strong "ETag" into a weak one: we are about to change the
	 * representation, so the entity tag can no longer be a strong validator
	 * for it. This mirrors what the compression filter does.
	 */
	ctx.blk = NULL;
	if (http_find_header(htx, ist("ETag"), &ctx, 1)) {
		if (ctx.value.len && ctx.value.ptr[0] == '"') {
			/* This a strong ETag. Convert it to a weak one. */
			struct ist v = ist2(trash.area, 0);

			if (istcat(&v, ist("W/"), trash.size) == -1 || istcat(&v, ctx.value, trash.size) == -1)
				goto error;

			if (!http_replace_header_value(htx, &ctx, v, 0))
				goto error;
		}
	}

	chn_prod(msg->chn)->flags |= SC_FL_NO_FASTFWD;
	st->flags |= DECOMP_STATE_PROCESSING;
	register_data_filter(s, msg->chn, f);
	return 1;

  error:
	st->decomp_algo->end(&st->decomp_ctx);
  early_error:
	st->decomp_algo = NULL;
	return -1;
}

/* analyze http headers for request oriented stream */
static int decomp_strm_req_http_headers(struct stream *s, struct filter *f, struct http_msg *msg)
{
	if (!(msg->chn->flags & CF_ISRESP))
		return decomp_strm_http_headers(s, f, msg);

	/* nothing else do on request */
	return 1;
}

/* analyze http headers for response oriented stream */
static int decomp_strm_res_http_headers(struct stream *s, struct filter *f, struct http_msg *msg)
{
	struct decomp_dir *decomp_res = FLT_CONF(f);

	if (!(msg->chn->flags & CF_ISRESP)) {
		struct htx *htx = htxbuf(&msg->chn->buf);
		struct decomp_algo *algo;
		struct http_hdr_ctx ctx;

		/* We are only decompressing the response so we don't care
		 * about the request. However, we can tell the endpoint
		 * that we do support compressed responses (with configured
		 * algos).
		 */
		if (decomp_res->flags & DECOMP_DIR_FL_MODE_ALWAYS) {
			/* remove any existing accept-encoding header since
			 * we won't let through responses with encodings we
			 * don't support
			 */
			ctx.blk = NULL;
			while (http_find_header(htx, ist("Accept-Encoding"), &ctx, 1))
				http_remove_header(htx, &ctx);

		}

		/* add our own supported algos
		 * FIXME: maybe we could make the effort to group algos within existing/single
		 * "accept-encoding", for now we add a duplicate header for each value.
		 */
		algo = decomp_res->algos;
		while (algo) {
			if (!http_add_header(htx, ist("Accept-Encoding"), ist2(algo->ua_name, algo->ua_name_len), 0))
				return -1;
			algo = algo->next;
		}
	}

	/* nothing else to do, on response path decomp_strm_http_headers() was alread
	 * handled by decomp_strm_res_http_post_analyze()
	 */
	return 1;

}


/* analyze http headers for response oriented stream, we do this before
 * http-response rules evaluation because the compression filter also
 * does it and we need to be in sync with it in case we chain decomp
 * and comp filters on the same proxy
 */
static int decomp_strm_res_http_post_analyze(struct stream *s, struct filter *f,
                                             struct channel *chn, unsigned an_bit)
{
	struct http_txn *txn = s->txn.http;
	struct http_msg *msg = &txn->rsp;

	if (!IS_HTX_STRM(s) || an_bit != AN_RES_WAIT_HTTP)
		return 1; // nothing to do

	return decomp_strm_http_headers(s, f, msg);
}

/* decompress http payload for request oriented stream */
int decomp_strm_req_http_payload(struct stream *s, struct filter *f, struct http_msg *msg,
                                 unsigned int offset, unsigned int len)
{
	if ((msg->chn->flags & CF_ISRESP))
		return len; // nothing to do

	return decomp_stream_blk(s, f, msg->chn, offset, len);
}

/* decompress http payload for response oriented stream */
int decomp_strm_res_http_payload(struct stream *s, struct filter *f, struct http_msg *msg,
                                 unsigned int offset, unsigned int len)
{
	if (!(msg->chn->flags & CF_ISRESP))
		return len; // nothing to do

	return decomp_stream_blk(s, f, msg->chn, offset, len);
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

	if (st && st->decomp_algo && st->decomp_algo->finish)
		return st->decomp_algo->finish(st->decomp_ctx);
	return 1;
}
/***********************************************************************/

struct flt_ops decomp_req_ops = {
	.init              = decomp_flt_init,

	.attach = decomp_strm_init,
	.detach = decomp_strm_deinit,
	.tcp_payload = decomp_strm_req_tcp_payload,
	.http_headers = decomp_strm_req_http_headers,
	.http_payload = decomp_strm_req_http_payload,
	.channel_start_analyze = decomp_channel_start_req_ana,
	.channel_end_analyze = decomp_channel_end_ana,
};

struct flt_ops decomp_res_ops = {
	.init              = decomp_flt_init,

	.attach = decomp_strm_init,
	.detach = decomp_strm_deinit,
	.tcp_payload = decomp_strm_res_tcp_payload,
	.http_headers = decomp_strm_res_http_headers,
	.channel_post_analyze = decomp_strm_res_http_post_analyze,
	.http_payload = decomp_strm_res_http_payload,
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

			if (proxy->mode != PR_MODE_TCP && strcmp(args[cur_arg], "uslz-auto") == 0) {
				memprintf(err, "'%s %s' : '%s' algorithm only allowed for TCP proxies.",
					  args[0], args[1], args[cur_arg]);
				ret = -1;
				goto end;
			}

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

			if (proxy->mode != PR_MODE_TCP && strcmp(args[cur_arg], "uslz-auto") == 0) {
				memprintf(err, "'%s %s' : '%s' algorithm only allowed for TCP proxies.",
					  args[0], args[1], args[cur_arg]);
				ret = -1;
				goto end;
			}

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

int
check_implicit_decomp_flt(struct proxy *proxy)
{
	struct flt_conf *fconf;
	struct flt_conf *fconf_req = NULL;
	struct flt_conf *fconf_res = NULL;
	int explicit = 0;
	int err = 0;

	if (proxy->decomp == NULL)
		goto end;

	if (!LIST_ISEMPTY(&proxy->filter_configs)) {
		list_for_each_entry(fconf, &proxy->filter_configs, list) {
			if ((proxy->cap & PR_CAP_FE) && fconf->id == decomp_req_flt_id)
				fconf_req = fconf;
			else if ((proxy->cap & PR_CAP_BE) && fconf->id == decomp_res_flt_id)
				fconf_res = fconf;
			else if (fconf->id == cache_store_flt_id) {
				if (((proxy->cap & PR_CAP_FE) && !fconf_req) || ((proxy->cap & PR_CAP_BE) && !fconf_res)) {
					ha_alert("config: %s '%s': cache filter declared before a decompression filter is invalid.\n",
						 proxy_type_str(proxy), proxy->id);
					err++;
					goto end;
				}
			}
			else if (fconf->id == http_comp_req_flt_id || fconf->id == http_comp_res_flt_id)
				continue;
#if defined(USE_FCGI)
			else if (fconf->id == fcgi_flt_id)
				continue;
#endif
			else
				explicit = 1;
		}
	}

	if ((proxy->cap & PR_CAP_FE) && proxy->decomp->req.algos && !fconf_req) {
		if (explicit) {
			ha_alert("config: %s '%s': require an explicit 'filter decomp-req' declaration to use "
				 "decompression.\n", proxy_type_str(proxy), proxy->id);
			err++;
			goto end;
		}
		/* Implicit declaration of the decomp-req filter should be at
		 * the beginning of the filter list.
		 */
		fconf_req = calloc(1, sizeof(*fconf));
		if (!fconf_req)
			goto out_of_memory;
		fconf_req->id   = decomp_req_flt_id;
		fconf_req->conf = &proxy->decomp->req;
		fconf_req->ops  = &decomp_req_ops;
		LIST_INSERT(&proxy->filter_configs, &fconf_req->list);
	}
	if ((proxy->cap & PR_CAP_BE) && proxy->decomp->res.algos && !fconf_res) {
		if (explicit) {
			ha_alert("config: %s '%s': require an explicit 'filter decomp-res' declaration to use "
				 "decompression.\n", proxy_type_str(proxy), proxy->id);
			err++;
			goto end;
		}
		/* Implicit declaration of the decomp-res filter should be at
		 * the beginning of the filter list.
		 */
		fconf_res = calloc(1, sizeof(*fconf));
		if (!fconf_res)
			goto out_of_memory;
		fconf_res->id   = decomp_res_flt_id;
		fconf_res->conf = &proxy->decomp->res;
		fconf_res->ops  = &decomp_res_ops;
		LIST_INSERT(&proxy->filter_configs, &fconf_res->list);
	}
 end:
	return err;

 out_of_memory:
	ha_alert("config: %s '%s': out of memory\n", proxy_type_str(proxy), proxy->id);
	err++;
	goto end;
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
