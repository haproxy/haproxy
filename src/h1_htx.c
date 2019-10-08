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

#include <common/config.h>
#include <common/debug.h>
#include <common/cfgparse.h>
#include <common/h1.h>
#include <common/http.h>
#include <common/htx.h>

#include <proto/h1_htx.h>

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

/* Switch the message to tunnel mode. On the request, it must only be called for
 * a CONNECT method. On the response, this function must only be called on
 * successfull replies to CONNECT requests or on protocol switching.
 */
static void h1_set_tunnel_mode(struct h1m *h1m)
{
	h1m->flags &= ~(H1_MF_XFER_LEN|H1_MF_CLEN|H1_MF_CHNK);
	h1m->state = H1_MSG_TUNNEL;
}

/* Check the validity of the request version. If the version is valid, it
 * returns 1. Otherwise, it returns 0.
 */
static int h1_process_req_vsn(struct h1m *h1m, union h1_sl *sl)
{
	/* RFC7230#2.6 has enforced the format of the HTTP version string to be
	 * exactly one digit "." one digit. This check may be disabled using
	 * option accept-invalid-http-request.
	 */
	if (h1m->err_pos == -2) { /* PR_O2_REQBUG_OK not set */
		if (sl->rq.v.len != 8)
			return 0;

		if (*(sl->rq.v.ptr + 4) != '/' ||
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
	 * option accept-invalid-http-request.
	 */
	if (h1m->err_pos == -2) { /* PR_O2_REQBUG_OK not set */
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
	unsigned int flags;
	size_t used;

	/* <h1sl> is always defined for a request */
	meth = h1sl->rq.m;
	uri  = h1sl->rq.u;
	vsn  = h1sl->rq.v;

	/* Be sure the message, once converted into HTX, will not exceed the max
	 * size allowed.
	 */
	if (h1_eval_htx_size(meth, uri, vsn, hdrs) > max) {
		if (htx_is_empty(htx))
			goto error;
		h1m_init_res(h1m);
		h1m->flags |= (H1_MF_NO_PHDR|H1_MF_CLEAN_CONN_HDR);
		return 0;
	}

	/* By default, request have always a known length */
	h1m->flags |= H1_MF_XFER_LEN;

	if (h1sl->rq.meth == HTTP_METH_CONNECT) {
		/* Switch CONNECT requests to tunnel mode */
		h1_set_tunnel_mode(h1m);
	}

	used = htx_used_space(htx);
	flags = h1m_htx_sl_flags(h1m);
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
	}
	/* Set bytes used in the HTX mesage for the headers now */
	sl->hdrs_bytes = htx_used_space(htx) - used;

	/* If body length cannot be determined, set htx->extra to
	 * ULLONG_MAX. This value is impossible in other cases.
	 */
	htx->extra = ((h1m->flags & H1_MF_XFER_LEN) ? h1m->curr_len : ULLONG_MAX);

  end:
	return 1;
  error:
	h1m->err_pos = h1m->next;
	h1m->err_state = h1m->state;
	htx->flags |= HTX_FL_PARSING_ERROR;
	return 0;
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
	unsigned int flags;
	size_t used;
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
				reason = ist("Moved Temporarily");
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
		h1m_init_res(h1m);
		h1m->flags |= (H1_MF_NO_PHDR|H1_MF_CLEAN_CONN_HDR);
		return 0;
	}

	if (((h1m->flags & H1_MF_METH_CONNECT) && code == 200) || code == 101) {
		/* Switch successfull replies to CONNECT requests and
		 * protocol switching to tunnel mode. */
		h1_set_tunnel_mode(h1m);
	}
	else if ((h1m->flags & H1_MF_METH_HEAD) || (code >= 100 && code < 200) ||
		 (code == 204) || (code == 304)) {
		/* Responses known to have no body. */
		h1m->flags &= ~(H1_MF_CLEN|H1_MF_CHNK);
		h1m->flags |= H1_MF_XFER_LEN;
		h1m->curr_len = h1m->body_len = 0;
	}
	else if (h1m->flags & (H1_MF_CLEN|H1_MF_CHNK)) {
		/* Responses with a known body length. */
		h1m->flags |= H1_MF_XFER_LEN;
	}
	else {
		/* Responses with an unknown body length */
		h1m->state = H1_MSG_TUNNEL;
	}

	used = htx_used_space(htx);
	flags = h1m_htx_sl_flags(h1m);
	sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, vsn, status, reason);
	if (!sl || !htx_add_all_headers(htx, hdrs))
		goto error;
	sl->info.res.status = code;

	/* Set bytes used in the HTX mesage for the headers now */
	sl->hdrs_bytes = htx_used_space(htx) - used;

	/* If body length cannot be determined, set htx->extra to
	 * ULLONG_MAX. This value is impossible in other cases.
	 */
	htx->extra = ((h1m->flags & H1_MF_XFER_LEN) ? h1m->curr_len : ULLONG_MAX);

  end:
	return 1;
  error:
	h1m->err_pos = h1m->next;
	h1m->err_state = h1m->state;
	htx->flags |= HTX_FL_PARSING_ERROR;
	return 0;
}

/* Parse HTTP/1 headers. It returns the number of bytes parsed if > 0, or 0 if
 * it couldn't proceed. Parsing errors are reported by setting the htx flag
 * HTX_FL_PARSING_ERROR and filling h1m->err_pos and h1m->err_state fields. This
 * functions is responsible to update the parser state <h1m> and the start-line
 * <h1sl> if not NULL.
 * For the requests, <h1sl> must always be provided. For responses, <h1sl> may
 * be NULL and <h1m> flags HTTP_METH_CONNECT of HTTP_METH_HEAD may be set.
 */
int h1_parse_msg_hdrs(struct h1m *h1m, union h1_sl *h1sl, struct htx *dsthtx,
		       struct buffer *srcbuf, size_t ofs, size_t max)
{
	struct http_hdr hdrs[global.tune.max_http_hdr];
	int ret = 0;

	if (!max || !b_data(srcbuf))
		goto end;

	/* Realing input buffer if necessary */
	if (b_head(srcbuf) + b_data(srcbuf) > b_wrap(srcbuf))
		b_slow_realign(srcbuf, trash.area, 0);

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
		if (ret < 0 || (!ret && !ofs && !buf_room_for_htx_data(srcbuf)))
			goto error;
		goto end;
	}

	/* messages headers fully parsed, do some checks to prepare the body
	 * parsing.
	 */

	if (!(h1m->flags & H1_MF_RESP)) {
		if (!h1_process_req_vsn(h1m, h1sl)) {
			h1m->err_pos = h1sl->rq.v.ptr - b_head(srcbuf);
			h1m->err_state = h1m->state;
			goto vsn_error;
		}
		if (!h1_postparse_req_hdrs(h1m, h1sl, dsthtx, hdrs, max))
			ret = 0;
	}
	else {
		if (h1sl && !h1_process_res_vsn(h1m, h1sl)) {
			h1m->err_pos = h1sl->st.v.ptr - b_head(srcbuf);
			h1m->err_state = h1m->state;
			goto vsn_error;
		}
		if (!h1_postparse_res_hdrs(h1m, h1sl, dsthtx, hdrs, max))
			ret = 0;
	}

  end:
	return ret;
  error:
	h1m->err_pos = h1m->next;
	h1m->err_state = h1m->state;
  vsn_error:
	dsthtx->flags |= HTX_FL_PARSING_ERROR;
	return 0;

}

/* Copy data from <srbuf> into an DATA block in <dsthtx>. If possible, a
 * zero-copy is performed. It returns the number of bytes copied.
 */
static int h1_copy_msg_data(struct htx **dsthtx, struct buffer *srcbuf, size_t ofs,
			    size_t count, struct buffer *htxbuf)
{
	struct htx *tmp_htx = *dsthtx;

	/* very often with large files we'll face the following
	 * situation :
	 *   - htx is empty and points to <htxbuf>
	 *   - ret == srcbuf->data
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

	return htx_add_data(*dsthtx, ist2(b_peek(srcbuf, ofs), count));
}

/* Parse HTTP/1 body. It returns the number of bytes parsed if > 0, or 0 if it
 * couldn't proceed. Parsing errors are reported by setting the htx flags
 * HTX_FL_PARSING_ERROR and filling h1m->err_pos and h1m->err_state fields. This
 * functions is responsible to update the parser state <h1m>.
 */
int h1_parse_msg_data(struct h1m *h1m, struct htx **dsthtx,
		      struct buffer *srcbuf, size_t ofs, size_t max,
		      struct buffer *htxbuf)
{
	size_t total = 0;
	int32_t ret = 0;

	if (h1m->flags & H1_MF_CLEN) {
		/* content-length: read only h2m->body_len */
		ret = htx_get_max_blksz(*dsthtx, max);
		if ((uint64_t)ret > h1m->curr_len)
			ret = h1m->curr_len;
		if (ret > b_contig_data(srcbuf, ofs))
			ret = b_contig_data(srcbuf, ofs);
		if (ret) {
			int32_t try = ret;

			ret = h1_copy_msg_data(dsthtx, srcbuf, ofs, try, htxbuf);
			h1m->curr_len -= ret;
			max -= sizeof(struct htx_blk) + ret;
			ofs += ret;
			total += ret;
			if (ret < try)
				goto end;
		}

		if (!h1m->curr_len) {
			if (max < sizeof(struct htx_blk) + 1 || !htx_add_endof(*dsthtx, HTX_BLK_EOM))
				goto end;
			h1m->state = H1_MSG_DONE;
		}
	}
	else if (h1m->flags & H1_MF_CHNK) {
		/* te:chunked : parse chunks */
	  new_chunk:
		if (h1m->state == H1_MSG_CHUNK_CRLF) {
			ret = h1_skip_chunk_crlf(srcbuf, ofs, b_data(srcbuf));
			if (ret <= 0)
				goto end;
			h1m->state = H1_MSG_CHUNK_SIZE;
			ofs += ret;
			total += ret;
		}
		if (h1m->state == H1_MSG_CHUNK_SIZE) {
			unsigned int chksz;

			ret = h1_parse_chunk_size(srcbuf, ofs, b_data(srcbuf), &chksz);
			if (ret <= 0)
				goto end;
			h1m->state = ((!chksz) ? H1_MSG_TRAILERS : H1_MSG_DATA);
			h1m->curr_len  = chksz;
			h1m->body_len += chksz;
			ofs += ret;
			total += ret;
			if (!h1m->curr_len)
				goto end;
		}
		if (h1m->state == H1_MSG_DATA) {
			ret = htx_get_max_blksz(*dsthtx, max);
			if ((uint64_t)ret > h1m->curr_len)
				ret = h1m->curr_len;
			if (ret > b_contig_data(srcbuf, ofs))
				ret = b_contig_data(srcbuf, ofs);
			if (ret) {
				int32_t try = ret;

				ret = h1_copy_msg_data(dsthtx, srcbuf, ofs, try, htxbuf);
				h1m->curr_len -= ret;
				max -= sizeof(struct htx_blk) + ret;
				ofs += ret;
				total += ret;
				if (ret < try)
					goto end;
			}
			if (!h1m->curr_len) {
				h1m->state = H1_MSG_CHUNK_CRLF;
				goto new_chunk;
			}
			goto end;
		}
	}
	else if (h1m->flags & H1_MF_XFER_LEN) {
		/* XFER_LEN is set but not CLEN nor CHNK, it means there is no
		 * body. Switch the message in DONE state
		 */
		if (max < sizeof(struct htx_blk) + 1 || !htx_add_endof(*dsthtx, HTX_BLK_EOM))
			goto end;
		h1m->state = H1_MSG_DONE;
	}
	else {
		/* no content length, read till SHUTW */
		ret = htx_get_max_blksz(*dsthtx, max);
		if (ret > b_contig_data(srcbuf, ofs))
			ret = b_contig_data(srcbuf, ofs);
		if (ret)
			total += h1_copy_msg_data(dsthtx, srcbuf, ofs, ret, htxbuf);
	}

  end:
	if (ret < 0) {
		(*dsthtx)->flags |= HTX_FL_PARSING_ERROR;
		h1m->err_state = h1m->state;
		h1m->err_pos = ofs;
		total = 0;
	}

	/* update htx->extra, only when the body length is known */
	if (h1m->flags & H1_MF_XFER_LEN)
		(*dsthtx)->extra = h1m->curr_len;
	return total;
}

/* Parse HTTP/1 trailers. It returns the number of bytes parsed if > 0, or 0 if
 * it couldn't proceed. Parsing errors are reported by setting the htx flags
 * HTX_FL_PARSING_ERROR and filling h1m->err_pos and h1m->err_state fields. This
 * functions is responsible to update the parser state <h1m>.
 */
int h1_parse_msg_tlrs(struct h1m *h1m, struct htx *dsthtx,
		      struct buffer *srcbuf, size_t ofs, size_t max)
{
	struct http_hdr hdrs[global.tune.max_http_hdr];
	struct h1m tlr_h1m;
	int ret = 0;

	if (!max || !b_data(srcbuf))
		goto end;

	/* Realing input buffer if necessary */
	if (b_peek(srcbuf, ofs) > b_tail(srcbuf))
		b_slow_realign(srcbuf, trash.area, 0);

	tlr_h1m.flags = (H1_MF_NO_PHDR|H1_MF_HDRS_ONLY);
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
		ret = 0;
		goto end;
	}

	if (!htx_add_all_trailers(dsthtx, hdrs))
		goto error;

  end:
	return ret;
  error:
	h1m->err_state = h1m->state;
	h1m->err_pos = h1m->next;
	dsthtx->flags |= HTX_FL_PARSING_ERROR;
	return 0;
}


/* Appends the H1 representation of the request line <sl> to the chunk <chk>. It
 * returns 1 if data are successfully appended, otherwise it returns 0.
 */
int h1_format_htx_reqline(const struct htx_sl *sl, struct buffer *chk)
{
	struct ist uri;
	size_t sz = chk->data;

	uri = htx_sl_req_uri(sl);
	if (sl->flags & HTX_SL_F_NORMALIZED_URI) {
		uri = http_get_path(uri);
		if (unlikely(!uri.len)) {
			if (sl->info.req.meth == HTTP_METH_OPTIONS)
				uri = ist("*");
			else
				uri = ist("/");
		}
	}

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
 */
int h1_format_htx_stline(const struct htx_sl *sl, struct buffer *chk)
{
	size_t sz = chk->data;

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
	if (!chunk_memcat(chk, " ", 1) ||
	    !chunk_memcat(chk, HTX_SL_RES_CPTR(sl), HTX_SL_RES_CLEN(sl)) ||
	    !chunk_memcat(chk, " ", 1) ||
	    !chunk_memcat(chk, HTX_SL_RES_RPTR(sl), HTX_SL_RES_RLEN(sl)) ||
	    !chunk_memcat(chk, "\r\n", 2))
		goto full;

	return 1;

  full:
	chk->data = sz;
	return 0;
}

/* Appends the H1 representation of the header <n> witht the value <v> to the
 * chunk <chk>. It returns 1 if data are successfully appended, otherwise it
 * returns 0.
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
