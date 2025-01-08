/*
 * Functions to manipulate H1 messages using the internal representation.
 *
 * Copyright (C) 2019 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/global.h>
#include <haproxy/h1.h>
#include <haproxy/h1_htx.h>
#include <haproxy/http.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/tools.h>

/* Estimate the size of the HTX headers after the parsing, including the EOH. */
static size_t h1_eval_htx_hdrs_size(const struct http_hdr *hdrs)
{
	size_t sz = 0;
	int i;

	for (i = 0; hdrs[i].n.len; i++)
		sz += sizeof(struct htx_blk) + hdrs[i].n.len + hdrs[i].v.len;
	sz += sizeof(struct htx_blk) + 1;
	return sz;
}

/* Estimate the size of the HTX request after the parsing. */
static size_t h1_eval_htx_size(const struct ist p1, const struct ist p2, const struct ist p3,
			       const struct http_hdr *hdrs)
{
	size_t sz;

	/* size of the HTX start-line */
	sz = sizeof(struct htx_blk) + sizeof(struct htx_sl) + p1.len + p2.len + p3.len;
	sz += h1_eval_htx_hdrs_size(hdrs);
	return sz;
}

/* Check the validity of the request version. If the version is valid, it
 * returns 1. Otherwise, it returns 0.
 */
static int h1_process_req_vsn(struct h1m *h1m, union h1_sl *sl)
{
	/* RFC7230#2.6 has enforced the format of the HTTP version string to be
	 * exactly one digit "." one digit. This check may be disabled using
	 * option accept-unsafe-violations-in-http-request.
	 */
	if (h1m->err_pos == -2) { /* PR_O2_REQBUG_OK not set */
		if (sl->rq.v.len != 8)
			return 0;

		if (!istnmatch(sl->rq.v, ist("HTTP/"), 5) ||
		    !isdigit((unsigned char)*(sl->rq.v.ptr + 5)) ||
		    *(sl->rq.v.ptr + 6) != '.' ||
		    !isdigit((unsigned char)*(sl->rq.v.ptr + 7)))
			return 0;
	}
	else if (!sl->rq.v.len) {
		/* try to convert HTTP/0.9 requests to HTTP/1.0 */

		/* RFC 1945 allows only GET for HTTP/0.9 requests */
		if (sl->rq.meth != HTTP_METH_GET)
			return 0;

		/* HTTP/0.9 requests *must* have a request URI, per RFC 1945 */
		if (!sl->rq.u.len)
			return 0;

		/* Add HTTP version */
		sl->rq.v = ist("HTTP/1.0");
		return 1;
	}

	if ((sl->rq.v.len == 8) &&
	    ((*(sl->rq.v.ptr + 5) > '1') ||
	     ((*(sl->rq.v.ptr + 5) == '1') && (*(sl->rq.v.ptr + 7) >= '1'))))
		h1m->flags |= H1_MF_VER_11;
	return 1;
}

/* Check the validity of the response version. If the version is valid, it
 * returns 1. Otherwise, it returns 0.
 */
static int h1_process_res_vsn(struct h1m *h1m, union h1_sl *sl)
{
	/* RFC7230#2.6 has enforced the format of the HTTP version string to be
	 * exactly one digit "." one digit. This check may be disabled using
	 * option accept-unsafe-violations-in-http-response.
	 */
	if (h1m->err_pos == -2) { /* PR_O2_RSPBUG_OK not set */
		if (sl->st.v.len != 8)
			return 0;

		if (*(sl->st.v.ptr + 4) != '/' ||
		    !isdigit((unsigned char)*(sl->st.v.ptr + 5)) ||
		    *(sl->st.v.ptr + 6) != '.' ||
		    !isdigit((unsigned char)*(sl->st.v.ptr + 7)))
			return 0;
	}

	if ((sl->st.v.len == 8) &&
	    ((*(sl->st.v.ptr + 5) > '1') ||
	     ((*(sl->st.v.ptr + 5) == '1') && (*(sl->st.v.ptr + 7) >= '1'))))
		h1m->flags |= H1_MF_VER_11;

	return 1;
}

/* Convert H1M flags to HTX start-line flags. */
static unsigned int h1m_htx_sl_flags(struct h1m *h1m)
{
	unsigned int flags = HTX_SL_F_NONE;

	if (h1m->flags & H1_MF_RESP)
		flags |= HTX_SL_F_IS_RESP;
	if (h1m->flags & H1_MF_VER_11)
		flags |= HTX_SL_F_VER_11;
	if (h1m->flags & H1_MF_XFER_ENC)
		flags |= HTX_SL_F_XFER_ENC;
	if (h1m->flags & H1_MF_XFER_LEN) {
		flags |= HTX_SL_F_XFER_LEN;
		if (h1m->flags & H1_MF_CHNK)
			flags |= HTX_SL_F_CHNK;
		else if (h1m->flags & H1_MF_CLEN) {
			flags |= HTX_SL_F_CLEN;
			if (h1m->body_len == 0)
				flags |= HTX_SL_F_BODYLESS;
		}
		else
			flags |= HTX_SL_F_BODYLESS;
	}
	if (h1m->flags & H1_MF_CONN_UPG)
		flags |= HTX_SL_F_CONN_UPG;
	return flags;
}

/* Postprocess the parsed headers for a request and convert them into an htx
 * message. It returns the number of bytes parsed if > 0, or 0 if it couldn't
 * proceed. Parsing errors are reported by setting the htx flag
 * HTX_FL_PARSING_ERROR and filling h1m->err_pos and h1m->err_state fields.
 */
static int h1_postparse_req_hdrs(struct h1m *h1m, union h1_sl *h1sl, struct htx *htx,
				 struct http_hdr *hdrs, size_t max)
{
	struct htx_sl *sl;
	struct ist meth, uri, vsn;
	unsigned int flags = 0;

	/* <h1sl> is always defined for a request */
	meth = h1sl->rq.m;
	uri  = h1sl->rq.u;
	vsn  = h1sl->rq.v;

	/* Be sure the message, once converted into HTX, will not exceed the max
	 * size allowed.
	 */
	if (h1_eval_htx_size(meth, uri, vsn, hdrs) > max) {
		if (htx_is_empty(htx)) {
			h1m->err_code = 431;
			goto error;
		}
		goto output_full;
	}

	/* By default, request have always a known length */
	h1m->flags |= H1_MF_XFER_LEN;

	if (h1sl->rq.meth == HTTP_METH_CONNECT) {
		h1m->flags &= ~(H1_MF_CLEN|H1_MF_CHNK);
		h1m->curr_len = h1m->body_len = 0;
		h1m->state = H1_MSG_DONE;
		htx->flags |= HTX_FL_EOM;
	}
	else {
		if (h1sl->rq.meth == HTTP_METH_HEAD)
			flags |= HTX_SL_F_BODYLESS_RESP;

		if (((h1m->flags & H1_MF_CLEN) && h1m->body_len == 0) ||
		    (h1m->flags & (H1_MF_XFER_LEN|H1_MF_CLEN|H1_MF_CHNK)) == H1_MF_XFER_LEN) {
			h1m->state = H1_MSG_DONE;
			htx->flags |= HTX_FL_EOM;
		}
	}

	flags |= h1m_htx_sl_flags(h1m);

	/* Remove Upgrade header in problematic cases :
	 * - "h2c" or "h2" token specified as token
	 */
	if ((h1m->flags & (H1_MF_CONN_UPG|H1_MF_UPG_H2C)) == (H1_MF_CONN_UPG|H1_MF_UPG_H2C)) {
		int i;

		for (i = 0; hdrs[i].n.len; i++) {
			if (isteqi(hdrs[i].n, ist("upgrade")))
				hdrs[i].v = IST_NULL;
		}
		h1m->flags &=~ H1_MF_CONN_UPG;
		flags &= ~HTX_SL_F_CONN_UPG;
	}

	sl = htx_add_stline(htx, HTX_BLK_REQ_SL, flags, meth, uri, vsn);
	if (!sl || !htx_add_all_headers(htx, hdrs))
		goto error;
	sl->info.req.meth = h1sl->rq.meth;

	/* Check if the uri contains an authority. Also check if it contains an
	 * explicit scheme and if it is "http" or "https". */
	if (h1sl->rq.meth == HTTP_METH_CONNECT)
		sl->flags |= HTX_SL_F_HAS_AUTHORITY;
	else if (uri.len && uri.ptr[0] != '/' && uri.ptr[0] != '*') {
		sl->flags |= (HTX_SL_F_HAS_AUTHORITY|HTX_SL_F_HAS_SCHM);
		if (uri.len > 4 && (uri.ptr[0] | 0x20) == 'h')
			sl->flags |= ((uri.ptr[4] == ':') ? HTX_SL_F_SCHM_HTTP : HTX_SL_F_SCHM_HTTPS);

		/* absolute-form target URI present, proceed to scheme-based
		 * normalization */
		http_scheme_based_normalize(htx);
	}

	/* If body length cannot be determined, set htx->extra to
	 * HTX_UNKOWN_PAYLOAD_LENGTH. This value is impossible in other cases.
	 */
	htx->extra = ((h1m->flags & H1_MF_XFER_LEN) ? h1m->curr_len : HTX_UNKOWN_PAYLOAD_LENGTH);

  end:
	return 1;
  output_full:
	h1m_init_req(h1m);
	h1m->flags |= (H1_MF_NO_PHDR|H1_MF_CLEAN_CONN_HDR);
	return -2;
  error:
	h1m->err_pos = h1m->next;
	h1m->err_state = h1m->state;
	htx->flags |= HTX_FL_PARSING_ERROR;
	return -1;
}

/* Postprocess the parsed headers for a response and convert them into an htx
 * message. It returns the number of bytes parsed if > 0, or 0 if it couldn't
 * proceed. Parsing errors are reported by setting the htx flag
 * HTX_FL_PARSING_ERROR and filling h1m->err_pos and h1m->err_state fields.
 */
static int h1_postparse_res_hdrs(struct h1m *h1m, union h1_sl *h1sl, struct htx *htx,
				 struct http_hdr *hdrs, size_t max)
{
	struct htx_sl *sl;
	struct ist vsn, status, reason;
	unsigned int flags = 0;
	uint16_t code = 0;

	if (h1sl) {
		/* For HTTP responses, the start-line was parsed */
		code   = h1sl->st.status;
		vsn    = h1sl->st.v;
		status = h1sl->st.c;
		reason = h1sl->st.r;
	}
	else {
		/* For FCGI responses, there is no start(-line but the "Status"
		 * header must be parsed, if found.
		 */
		int hdr;

		vsn = ((h1m->flags & H1_MF_VER_11) ? ist("HTTP/1.1") : ist("HTTP/1.0"));
		for (hdr = 0; hdrs[hdr].n.len; hdr++) {
			if (isteqi(hdrs[hdr].n, ist("status"))) {
				code = http_parse_status_val(hdrs[hdr].v, &status, &reason);
			}
			else if (isteqi(hdrs[hdr].n, ist("location"))) {
				code = 302;
				status = ist("302");
				reason = ist("Found");
			}
		}
		if (!code) {
			code = 200;
			status = ist("200");
			reason = ist("OK");
		}
		/* FIXME: Check the codes 1xx ? */
	}

	/* Be sure the message, once converted into HTX, will not exceed the max
	 * size allowed.
	 */
	if (h1_eval_htx_size(vsn, status, reason, hdrs) > max) {
		if (htx_is_empty(htx))
			goto error;
		goto output_full;
	}

	if ((h1m->flags & (H1_MF_CONN_UPG|H1_MF_UPG_WEBSOCKET)) && code != 101)
		h1m->flags &= ~(H1_MF_CONN_UPG|H1_MF_UPG_WEBSOCKET);

	if (((h1m->flags & H1_MF_METH_CONNECT) && code >= 200 && code < 300) || code == 101) {
		h1m->flags &= ~(H1_MF_CLEN|H1_MF_CHNK);
		h1m->flags |= H1_MF_XFER_LEN;
		h1m->curr_len = h1m->body_len = 0;
		h1m->state = H1_MSG_DONE;
		htx->flags |= HTX_FL_EOM;
	}
	else if ((h1m->flags & H1_MF_METH_HEAD) || (code >= 100 && code < 200) ||
		 (code == 204) || (code == 304)) {
		/* Responses known to have no body. */
		h1m->flags |= H1_MF_XFER_LEN;
		h1m->curr_len = h1m->body_len = 0;
		if (code >= 200)
			flags |= HTX_SL_F_BODYLESS_RESP;
		h1m->state = H1_MSG_DONE;
		htx->flags |= HTX_FL_EOM;
	}
	else {
		if (h1m->flags & (H1_MF_CLEN|H1_MF_CHNK)) {
			/* Responses with a known body length. */
			h1m->flags |= H1_MF_XFER_LEN;
		}

		if (((h1m->flags & H1_MF_CLEN) && h1m->body_len == 0) ||
		    (h1m->flags & (H1_MF_XFER_LEN|H1_MF_CLEN|H1_MF_CHNK)) == H1_MF_XFER_LEN) {
			h1m->state = H1_MSG_DONE;
			htx->flags |= HTX_FL_EOM;
		}
	}

	flags |= h1m_htx_sl_flags(h1m);
	sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, vsn, status, reason);
	if (!sl || !htx_add_all_headers(htx, hdrs))
		goto error;
	sl->info.res.status = code;

	/* If body length cannot be determined, set htx->extra to
	 * HTX_UNKOWN_PAYLOAD_LENGTH. This value is impossible in other cases.
	 */
	htx->extra = ((h1m->flags & H1_MF_XFER_LEN) ? h1m->curr_len : HTX_UNKOWN_PAYLOAD_LENGTH);

  end:
	return 1;
  output_full:
	h1m_init_res(h1m);
	h1m->flags |= (H1_MF_NO_PHDR|H1_MF_CLEAN_CONN_HDR);
	return -2;
  error:
	h1m->err_pos = h1m->next;
	h1m->err_state = h1m->state;
	htx->flags |= HTX_FL_PARSING_ERROR;
	return -1;
}

/* Parse HTTP/1 headers. It returns the number of bytes parsed on success, 0 if
 * headers are incomplete, -1 if an error occurred or -2 if it needs more space
 * to proceed while the output buffer is not empty. Parsing errors are reported
 * by setting the htx flag HTX_FL_PARSING_ERROR and filling h1m->err_pos and
 * h1m->err_state fields. This functions is responsible to update the parser
 * state <h1m> and the start-line <h1sl> if not NULL.  For the requests, <h1sl>
 * must always be provided. For responses, <h1sl> may be NULL and <h1m> flags
 * HTTP_METH_CONNECT of HTTP_METH_HEAD may be set.
 */
int h1_parse_msg_hdrs(struct h1m *h1m, union h1_sl *h1sl, struct htx *dsthtx,
		      struct buffer *srcbuf, size_t ofs, size_t max)
{
	struct http_hdr hdrs[global.tune.max_http_hdr];
	int total = 0, ret = 0;

	if (!max || !b_data(srcbuf))
		goto end;

	/* Realing input buffer if necessary */
	if (b_head(srcbuf) + b_data(srcbuf) > b_wrap(srcbuf))
		b_slow_realign_ofs(srcbuf, trash.area, 0);

	if (!h1sl) {
		/* If there no start-line, be sure to only parse the headers */
		h1m->flags |= H1_MF_HDRS_ONLY;
	}
	ret = h1_headers_to_hdr_list(b_peek(srcbuf, ofs), b_tail(srcbuf),
				     hdrs, sizeof(hdrs)/sizeof(hdrs[0]), h1m, h1sl);
	if (ret <= 0) {
		/* Incomplete or invalid message. If the input buffer only
		 * contains headers and is full, which is detected by it being
		 * full and the offset to be zero, it's an error because
		 * headers are too large to be handled by the parser. */
		if (ret < 0)
			goto error;
		if (!ret && !ofs && !buf_room_for_htx_data(srcbuf)) {
			if (!(h1m->flags & H1_MF_RESP))
				h1m->err_code = (h1m->err_state < H1_MSG_HDR_FIRST) ? 414: 431;
			goto error;
		}
		goto end;
	}
	total = ret;

	/* messages headers fully parsed, do some checks to prepare the body
	 * parsing.
	 */

	if (!(h1m->flags & H1_MF_RESP)) {
		if (!h1_process_req_vsn(h1m, h1sl)) {
			h1m->err_pos = h1sl->rq.v.ptr - b_head(srcbuf);
			h1m->err_state = h1m->state;
			goto vsn_error;
		}
		ret = h1_postparse_req_hdrs(h1m, h1sl, dsthtx, hdrs, max);
		if (ret < 0)
			return ret;
	}
	else {
		if (h1sl && !h1_process_res_vsn(h1m, h1sl)) {
			h1m->err_pos = h1sl->st.v.ptr - b_head(srcbuf);
			h1m->err_state = h1m->state;
			goto vsn_error;
		}
		ret = h1_postparse_res_hdrs(h1m, h1sl, dsthtx, hdrs, max);
		if (ret < 0)
			return ret;
	}

  end:
	return total;
  error:
	h1m->err_pos = h1m->next;
	h1m->err_state = h1m->state;
  vsn_error:
	dsthtx->flags |= HTX_FL_PARSING_ERROR;
	return -1;

}

/* Copy data from <srbuf> into an DATA block in <dsthtx>. If possible, a
 * zero-copy is performed. It returns the number of bytes copied.
 */
static size_t h1_copy_msg_data(struct htx **dsthtx, struct buffer *srcbuf, size_t ofs,
			       size_t count, size_t max, struct buffer *htxbuf)
{
	struct htx *tmp_htx = *dsthtx;
	size_t block1, block2, ret = 0;

	/* Be prepared to create at least one HTX block by reserving its size
	 * and adjust <count> accordingly.
	 */
	if (max <= sizeof(struct htx_blk))
		goto end;
	max -= sizeof(struct htx_blk);
	if (count > max)
		count = max;

	/* very often with large files we'll face the following
	 * situation :
	 *   - htx is empty and points to <htxbuf>
	 *   - count == srcbuf->data
	 *   - srcbuf->head == sizeof(struct htx)
	 *   => we can swap the buffers and place an htx header into
	 *      the target buffer instead
	 */
	if (unlikely(htx_is_empty(tmp_htx) && count == b_data(srcbuf) &&
		     !ofs && b_head_ofs(srcbuf) == sizeof(struct htx))) {
		void *raw_area = srcbuf->area;
		void *htx_area = htxbuf->area;
		struct htx_blk *blk;

		srcbuf->area = htx_area;
		htxbuf->area = raw_area;
		tmp_htx = (struct htx *)htxbuf->area;
		tmp_htx->size = htxbuf->size - sizeof(*tmp_htx);
		htx_reset(tmp_htx);
		b_set_data(htxbuf, b_size(htxbuf));

		blk = htx_add_blk(tmp_htx, HTX_BLK_DATA, count);
		blk->info += count;

		*dsthtx = tmp_htx;
		/* nothing else to do, the old buffer now contains an
		 * empty pre-initialized HTX header
		 */
		return count;
	}

	/* * First block is the copy of contiguous data starting at offset <ofs>
	 *   with <count> as max. <max> is updated accordingly
	 *
	 * * Second block is the remaining (count - block1) if <max> is large
	 *   enough. Another HTX block is reserved.
	 */
	block1 = b_contig_data(srcbuf, ofs);
	block2 = 0;
	if (block1 > count)
		block1 = count;
	max -= block1;

	if (max > sizeof(struct htx_blk)) {
		block2 = count - block1;
		max -= sizeof(struct htx_blk);
		if (block2 > max)
			block2 = max;
	}

	ret = htx_add_data(tmp_htx, ist2(b_peek(srcbuf, ofs), block1));
	if (ret == block1 && block2)
		ret += htx_add_data(tmp_htx, ist2(b_orig(srcbuf), block2));
  end:
	return ret;
}

static const char hextable[] = {
       -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
       -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
       -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
       -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
       -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
       -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
       -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
       -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

/* Generic function to parse the current HTTP chunk. It may be used to parsed
 * any kind of chunks, including incomplete HTTP chunks or split chunks
 * because the buffer wraps. This version tries to performed zero-copy on large
 * chunks if possible.
 */
static size_t h1_parse_chunk(struct h1m *h1m, struct htx **dsthtx,
			     struct buffer *srcbuf, size_t ofs, size_t *max,
			     struct buffer *htxbuf)
{
	uint64_t chksz;
	size_t sz, used, lmax, total = 0;
	int ret = 0;

	lmax = *max;
	switch (h1m->state) {
	case H1_MSG_DATA:
	  new_chunk:
		used = htx_used_space(*dsthtx);
		if (b_data(srcbuf) == ofs || lmax <= sizeof(struct htx_blk))
			break;

		sz =  b_data(srcbuf) - ofs;
		if (unlikely(sz > h1m->curr_len))
			sz = h1m->curr_len;
		sz = h1_copy_msg_data(dsthtx, srcbuf, ofs, sz, lmax, htxbuf);
		lmax -= htx_used_space(*dsthtx) - used;
		ofs += sz;
		total += sz;
		h1m->curr_len -= sz;
		if (h1m->curr_len)
			break;

		h1m->state = H1_MSG_CHUNK_CRLF;
		__fallthrough;

	case H1_MSG_CHUNK_CRLF:
		ret = h1_skip_chunk_crlf(srcbuf, ofs, b_data(srcbuf));
		if (ret <= 0)
			break;
		ofs += ret;
		total += ret;

		/* Don't parse next chunk to try to handle contiguous chunks if possible */
		h1m->state = H1_MSG_CHUNK_SIZE;
		break;

	case H1_MSG_CHUNK_SIZE:
		ret = h1_parse_chunk_size(srcbuf, ofs, b_data(srcbuf), &chksz);
		if (ret <= 0)
			break;
		h1m->state = ((!chksz) ? H1_MSG_TRAILERS : H1_MSG_DATA);
		h1m->curr_len  = chksz;
		h1m->body_len += chksz;
		ofs += ret;
		total += ret;

		if (h1m->curr_len) {
			h1m->state = H1_MSG_DATA;
			goto new_chunk;
		}
		h1m->state = H1_MSG_TRAILERS;
		break;

	default:
		/* unexpected */
		ret = -1;
		break;
	}

	if (ret < 0) {
		(*dsthtx)->flags |= HTX_FL_PARSING_ERROR;
		h1m->err_state = h1m->state;
		h1m->err_pos = ofs;
		total = 0;
	}

	/* Don't forget to update htx->extra */
	(*dsthtx)->extra = h1m->curr_len;
	*max = lmax;
	return total;
}

/* Parses full contiguous HTTP chunks. This version is optimized for small
 * chunks and does not performed zero-copy. It must be called in
 * H1_MSG_CHUNK_SIZE state. Be careful if you change something in this
 * function. It is really sensitive, any change may have an impact on
 * performance.
 */
static size_t h1_parse_full_contig_chunks(struct h1m *h1m, struct htx **dsthtx,
					  struct buffer *srcbuf, size_t ofs, size_t *max,
					  struct buffer *htxbuf)
{
	char *start, *end, *dptr;
	ssize_t dpos, ridx, save;
	size_t lmax, total = 0;
	uint64_t chksz;
	struct htx_ret htxret;

	lmax = *max;
	if (lmax <= sizeof(struct htx_blk))
		goto out;

	/* source info :
	 *  start : pointer at <ofs> position
	 *  end   : pointer marking the end of data to parse
	 *  ridx  : the reverse index (negative) marking the parser position (end[ridx])
	 */
	ridx = -b_contig_data(srcbuf, ofs);
	if (!ridx)
		goto out;
	start = b_peek(srcbuf, ofs);
	end = start - ridx;

	/* Reserve the maximum possible size for the data */
	htxret = htx_reserve_max_data(*dsthtx);
	if (!htxret.blk)
		goto out;

	/* destination info :
	 *  dptr : pointer on the beginning of the data
	 *  dpos : current position where to copy data
	 */
	dptr = htx_get_blk_ptr(*dsthtx, htxret.blk);
	dpos = htxret.ret;

	/* Empty DATA block is not possible, thus if <dpos> is the beginning of
	 * the block, it means it is a new block. We can remove the block size
	 * from <max>. Then we must adjust it if it exceeds the free size in the
	 * block.
	 */
	if (!dpos)
		lmax -= sizeof(struct htx_blk);
	if (lmax > htx_get_blksz(htxret.blk) - dpos)
		lmax = htx_get_blksz(htxret.blk) - dpos;

	while (1) {
		/* The chunk size is in the following form, though we are only
		 * interested in the size and CRLF :
		 *    1*HEXDIGIT *WSP *[ ';' extensions ] CRLF
		 */
		chksz = 0;
		save = ridx; /* Save the parser position to rewind if necessary */
		while (1) {
			int c;

			if (!ridx)
				goto end_parsing;

			/* Convert current character */
			c = hextable[(unsigned char)end[ridx]];

			/* not a hex digit anymore */
			if (c & 0xF0)
				break;

			/* Update current chunk size */
			chksz = (chksz << 4) + c;

			if (unlikely(chksz & 0xF0000000000000ULL)) {
				/* Don't get more than 13 hexa-digit (2^52 - 1)
				 * to never fed possibly bogus values from
				 * languages that use floats for their integers
				 */
				goto parsing_error;
			}
			++ridx;
		}

		if (unlikely(chksz > lmax))
			goto end_parsing;

		if (unlikely(ridx == save)) {
			/* empty size not allowed */
			goto parsing_error;
		}

		/* Skip spaces */
		while (HTTP_IS_SPHT(end[ridx])) {
			if (!++ridx)
				goto end_parsing;
		}

		/* Up to there, we know that at least one byte is present. Check
		 * for the end of chunk size.
		 */
		while (1) {
			if (likely(end[ridx] == '\r')) {
				/* Parse CRLF */
				if (!++ridx)
					goto end_parsing;
				if (unlikely(end[ridx] != '\n')) {
					/* CR must be followed by LF */
					goto parsing_error;
				}

				/* done */
				++ridx;
				break;
			}
			else if (likely(end[ridx] == ';')) {
				/* chunk extension, ends at next CRLF */
				if (!++ridx)
					goto end_parsing;
				while (!HTTP_IS_CRLF(end[ridx])) {
					if (!++ridx)
						goto end_parsing;
				}
				/* we have a CRLF now, loop above */
				continue;
			}
			else {
				/* all other characters are unexpected, especially LF alone */
				goto parsing_error;
			}
		}

		/* Exit if it is the last chunk */
		if (unlikely(!chksz)) {
			h1m->state = H1_MSG_TRAILERS;
			save = ridx;
			goto end_parsing;
		}

		/* Now check if the whole chunk is here (including the CRLF at
		 * the end), otherwise we switch in H1_MSG_DATA state.
		 */
		if (chksz + 2 > -ridx) {
			h1m->curr_len = chksz;
			h1m->body_len += chksz;
			h1m->state = H1_MSG_DATA;
			(*dsthtx)->extra = h1m->curr_len;
			save = ridx;
			goto end_parsing;
		}

		memcpy(dptr + dpos, end + ridx, chksz);
		h1m->body_len += chksz;
		lmax  -= chksz;
		dpos += chksz;
		ridx += chksz;

		/* Parse CRLF */
		if (unlikely(end[ridx] != '\r')) {
			h1m->state = H1_MSG_CHUNK_CRLF;
			goto parsing_error;
		}
		++ridx;
		if (end[ridx] != '\n') {
			h1m->state = H1_MSG_CHUNK_CRLF;
			goto parsing_error;
		}
		++ridx;
	}

  end_parsing:
	ridx = save;

	/* Adjust the HTX block size or remove the block if nothing was copied
	 * (Empty HTX data block are not supported).
	 */
	if (!dpos)
		htx_remove_blk(*dsthtx, htxret.blk);
	else
		htx_change_blk_value_len(*dsthtx, htxret.blk, dpos);
	total = end + ridx - start;
	*max = lmax;

  out:
	return total;

  parsing_error:
	(*dsthtx)->flags |= HTX_FL_PARSING_ERROR;
	h1m->err_state = h1m->state;
	h1m->err_pos = ofs + end + ridx - start;
	return 0;
}

/* Parse HTTP chunks. This function relies on an optimized function to parse
 * contiguous chunks if possible. Otherwise, when a chunk is incomplete or when
 * the underlying buffer is wrapping, a generic function is used.
 */
static size_t h1_parse_msg_chunks(struct h1m *h1m, struct htx **dsthtx,
			 struct buffer *srcbuf, size_t ofs, size_t max,
			 struct buffer *htxbuf)
{
	size_t ret, total = 0;

	while (ofs < b_data(srcbuf)) {
		ret = 0;

		/* First parse full contiguous chunks. It is only possible if we
		 * are waiting for the next chunk size.
		 */
		if (h1m->state == H1_MSG_CHUNK_SIZE) {
			ret = h1_parse_full_contig_chunks(h1m, dsthtx, srcbuf, ofs, &max, htxbuf);
			/* exit on error */
			if (!ret && (*dsthtx)->flags & HTX_FL_PARSING_ERROR) {
				total = 0;
				break;
			}
			/* or let a chance to parse remaining data */
			total += ret;
			ofs   += ret;
			ret = 0;
		}

		/* If some data remains, try to parse it using the generic
		 * function handling incomplete chunks and split chunks
		 * because of a wrapping buffer.
		 */
		if (h1m->state < H1_MSG_TRAILERS && ofs < b_data(srcbuf)) {
			ret = h1_parse_chunk(h1m, dsthtx, srcbuf, ofs, &max, htxbuf);
			total += ret;
			ofs   += ret;
		}

		/* nothing more was parsed or parsing was stopped on incomplete
		 * chunk, we can exit, handling parsing error if necessary.
		 */
		if (!ret || h1m->state != H1_MSG_CHUNK_SIZE) {
			if ((*dsthtx)->flags & HTX_FL_PARSING_ERROR)
				total = 0;
			break;
		}
	}

	return total;
}

/* Parse HTTP/1 body. It returns the number of bytes parsed if > 0, or 0 if it
 * couldn't proceed. Parsing errors are reported by setting the htx flags
 * HTX_FL_PARSING_ERROR and filling h1m->err_pos and h1m->err_state fields. This
 * functions is responsible to update the parser state <h1m>.
 */
size_t h1_parse_msg_data(struct h1m *h1m, struct htx **dsthtx,
			 struct buffer *srcbuf, size_t ofs, size_t max,
			 struct buffer *htxbuf)
{
	size_t sz, total = 0;

	if (b_data(srcbuf) == ofs)
		return 0;

	if (h1m->flags & H1_MF_CLEN) {
		/* content-length: read only h2m->body_len */
		sz = b_data(srcbuf) - ofs;
		if (unlikely(sz > h1m->curr_len))
			sz = h1m->curr_len;
		sz = h1_copy_msg_data(dsthtx, srcbuf, ofs, sz, max, htxbuf);
		h1m->curr_len -= sz;
		(*dsthtx)->extra = h1m->curr_len;
		total += sz;
		if (!h1m->curr_len) {
			h1m->state = H1_MSG_DONE;
			(*dsthtx)->flags |= HTX_FL_EOM;
		}
	}
	else if (h1m->flags & H1_MF_CHNK) {
		/* te:chunked : parse chunks */
		total += h1_parse_msg_chunks(h1m, dsthtx, srcbuf, ofs, max, htxbuf);
	}
	else if (h1m->flags & H1_MF_XFER_LEN) {
		/* XFER_LEN is set but not CLEN nor CHNK, it means there is no
		 * body. Switch the message in DONE state
		 */
		h1m->state = H1_MSG_DONE;
		(*dsthtx)->flags |= HTX_FL_EOM;
	}
	else {
		/* no content length, read till SHUTW */
		sz = b_data(srcbuf) - ofs;
		sz = h1_copy_msg_data(dsthtx, srcbuf, ofs, sz, max, htxbuf);
		total += sz;
	}

	return total;
}

/* Parse HTTP/1 trailers. It returns the number of bytes parsed on success, 0 if
 * trailers are incomplete, -1 if an error occurred or -2 if it needs more space
 * to proceed while the output buffer is not empty. Parsing errors are reported
 * by setting the htx flags HTX_FL_PARSING_ERROR and filling h1m->err_pos and
 * h1m->err_state fields. This functions is responsible to update the parser
 * state <h1m>.
 */
int h1_parse_msg_tlrs(struct h1m *h1m, struct htx *dsthtx,
		      struct buffer *srcbuf, size_t ofs, size_t max)
{
	struct http_hdr hdrs[global.tune.max_http_hdr];
	struct h1m tlr_h1m;
	int ret = 0;

	if (b_data(srcbuf) == ofs) {
		/* Nothing to parse */
		goto end;
	}
	if (!max) {
		/* No more room */
		goto output_full;
	}

	/* Realing input buffer if necessary */
	if (b_peek(srcbuf, ofs) > b_tail(srcbuf))
		b_slow_realign_ofs(srcbuf, trash.area, 0);

	tlr_h1m.flags = (H1_MF_NO_PHDR|H1_MF_HDRS_ONLY);
	tlr_h1m.err_pos = h1m->err_pos;
	ret = h1_headers_to_hdr_list(b_peek(srcbuf, ofs), b_tail(srcbuf),
				     hdrs, sizeof(hdrs)/sizeof(hdrs[0]), &tlr_h1m, NULL);
	if (ret <= 0) {
		/* Incomplete or invalid trailers. If the input buffer only
		 * contains trailers and is full, which is detected by it being
		 * full and the offset to be zero, it's an error because
		 * trailers are too large to be handled by the parser. */
		if (ret < 0 || (!ret && !ofs && !buf_room_for_htx_data(srcbuf)))
			goto error;
		goto end;
	}

	/* messages trailers fully parsed. */
	if (h1_eval_htx_hdrs_size(hdrs) > max) {
		if (htx_is_empty(dsthtx))
			goto error;
		goto output_full;
	}

	if (!htx_add_all_trailers(dsthtx, hdrs))
		goto error;

	h1m->state = H1_MSG_DONE;
	dsthtx->flags |= HTX_FL_EOM;

  end:
	return ret;
  output_full:
	return -2;
  error:
	h1m->err_state = h1m->state;
	h1m->err_pos = h1m->next;
	dsthtx->flags |= HTX_FL_PARSING_ERROR;
	return -1;
}

/* Appends the H1 representation of the request line <sl> to the chunk <chk>. It
 * returns 1 if data are successfully appended, otherwise it returns 0.
 * <chk> buffer must not wrap.
 */
int h1_format_htx_reqline(const struct htx_sl *sl, struct buffer *chk)
{
	struct ist uri;
	size_t sz = chk->data;

	uri = h1_get_uri(sl);
	if (!chunk_memcat(chk, HTX_SL_REQ_MPTR(sl), HTX_SL_REQ_MLEN(sl)) ||
	    !chunk_memcat(chk, " ", 1) ||
	    !chunk_memcat(chk, uri.ptr, uri.len) ||
	    !chunk_memcat(chk, " ", 1))
		goto full;

	if (sl->flags & HTX_SL_F_VER_11) {
		if (!chunk_memcat(chk, "HTTP/1.1", 8))
			goto full;
	}
	else {
		if (!chunk_memcat(chk, HTX_SL_REQ_VPTR(sl), HTX_SL_REQ_VLEN(sl)))
			goto full;
	}

	if (!chunk_memcat(chk, "\r\n", 2))
		goto full;

	return 1;

  full:
	chk->data = sz;
	return 0;
}

/* Appends the H1 representation of the status line <sl> to the chunk <chk>. It
 * returns 1 if data are successfully appended, otherwise it returns 0.
 * <chk> buffer must not wrap.
 */
int h1_format_htx_stline(const struct htx_sl *sl, struct buffer *chk)
{
	size_t sz = chk->data;
	struct ist reason;

	if (HTX_SL_LEN(sl) + 4 > b_room(chk))
		return 0;

	if (sl->flags & HTX_SL_F_VER_11) {
		if (!chunk_memcat(chk, "HTTP/1.1", 8))
			goto full;
	}
	else {
		if (!chunk_memcat(chk, HTX_SL_RES_VPTR(sl), HTX_SL_RES_VLEN(sl)))
			goto full;
	}

	reason = htx_sl_res_reason(sl);
	if (istlen(reason) == 0)
		reason = ist(http_get_reason(sl->info.res.status));

	if (!chunk_memcat(chk, " ", 1) ||
	    !chunk_memcat(chk, HTX_SL_RES_CPTR(sl), HTX_SL_RES_CLEN(sl)) ||
	    !chunk_memcat(chk, " ", 1) ||
	    !chunk_memcat(chk, istptr(reason), istlen(reason)) ||
	    !chunk_memcat(chk, "\r\n", 2))
		goto full;

	return 1;

  full:
	chk->data = sz;
	return 0;
}

/* Appends the H1 representation of the header <n> with the value <v> to the
 * chunk <chk>. It returns 1 if data are successfully appended, otherwise it
 * returns 0.
 * <chk> buffer must not wrap.
 */
int h1_format_htx_hdr(const struct ist n, const struct ist v, struct buffer *chk)
{
	size_t sz = chk->data;

	if (n.len + v.len + 4 > b_room(chk))
		return 0;

	if (!chunk_memcat(chk, n.ptr, n.len) ||
	    !chunk_memcat(chk, ": ", 2) ||
	    !chunk_memcat(chk, v.ptr, v.len) ||
	    !chunk_memcat(chk, "\r\n", 2))
		goto full;

	return 1;

  full:
	chk->data = sz;
	return 0;
}

/* Appends the H1 representation of the data <data> to the chunk <chk>. If
 * <chunked> is non-zero, it emits HTTP/1 chunk-encoded data. It returns 1 if
 * data are successfully appended, otherwise it returns 0.
 * <chk> buffer must not wrap.
 */
int h1_format_htx_data(const struct ist data, struct buffer *chk, int chunked)
{
	size_t sz = chk->data;

	if (chunked) {
		uint32_t chksz;
		char     tmp[10];
		char    *beg, *end;

		chksz = data.len;

		beg = end = tmp+10;
		*--beg = '\n';
		*--beg = '\r';
		do {
			*--beg = hextab[chksz & 0xF];
		} while (chksz >>= 4);

		if (!chunk_memcat(chk, beg, end - beg) ||
		    !chunk_memcat(chk, data.ptr, data.len) ||
		    !chunk_memcat(chk, "\r\n", 2))
			goto full;
	}
	else {
		if (!chunk_memcat(chk, data.ptr, data.len))
			return 0;
	}

	return 1;

  full:
	chk->data = sz;
	return 0;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
