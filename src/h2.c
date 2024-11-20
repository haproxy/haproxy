/*
 * HTTP/2 protocol processing
 *
 * Copyright 2017 Willy Tarreau <w@1wt.eu>
 * Copyright (C) 2017 HAProxy Technologies
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <inttypes.h>
#include <haproxy/api.h>
#include <haproxy/global.h>
#include <haproxy/h2.h>
#include <haproxy/http-hdr-t.h>
#include <haproxy/http.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <import/ist.h>


struct h2_frame_definition h2_frame_definition[H2_FT_ENTRIES] =	{
	 [H2_FT_DATA         ] = { .dir = 3, .min_id = 1, .max_id = H2_MAX_STREAM_ID, .min_len = 0, .max_len = H2_MAX_FRAME_LEN, },
	 [H2_FT_HEADERS      ] = { .dir = 3, .min_id = 1, .max_id = H2_MAX_STREAM_ID, .min_len = 1, .max_len = H2_MAX_FRAME_LEN, },
	 [H2_FT_PRIORITY     ] = { .dir = 3, .min_id = 1, .max_id = H2_MAX_STREAM_ID, .min_len = 5, .max_len = 5,                },
	 [H2_FT_RST_STREAM   ] = { .dir = 3, .min_id = 1, .max_id = H2_MAX_STREAM_ID, .min_len = 4, .max_len = 4,                },
	 [H2_FT_SETTINGS     ] = { .dir = 3, .min_id = 0, .max_id = 0,                .min_len = 0, .max_len = H2_MAX_FRAME_LEN, },
	 [H2_FT_PUSH_PROMISE ] = { .dir = 0, .min_id = 1, .max_id = H2_MAX_STREAM_ID, .min_len = 4, .max_len = H2_MAX_FRAME_LEN, },
	 [H2_FT_PING         ] = { .dir = 3, .min_id = 0, .max_id = 0,                .min_len = 8, .max_len = 8,                },
	 [H2_FT_GOAWAY       ] = { .dir = 3, .min_id = 0, .max_id = 0,                .min_len = 8, .max_len = H2_MAX_FRAME_LEN, },
	 [H2_FT_WINDOW_UPDATE] = { .dir = 3, .min_id = 0, .max_id = H2_MAX_STREAM_ID, .min_len = 4, .max_len = 4,                },
	 [H2_FT_CONTINUATION ] = { .dir = 3, .min_id = 1, .max_id = H2_MAX_STREAM_ID, .min_len = 0, .max_len = H2_MAX_FRAME_LEN, },
};

/* Prepare the request line into <htx> from pseudo headers stored in <phdr[]>.
 * <fields> indicates what was found so far. This should be called once at the
 * detection of the first general header field or at the end of the request if
 * no general header field was found yet. Returns the created start line on
 * success, or NULL on failure. Upon success, <msgf> is updated with a few
 * H2_MSGF_* flags indicating what was found while parsing.
 *
 * The rules below deserve a bit of explanation. There tends to be some
 * confusion regarding H2's authority vs the Host header. They are different
 * though may sometimes be exchanged. In H2, the request line is broken into :
 *   - :method
 *   - :scheme
 *   - :authority
 *   - :path
 *
 * An equivalent HTTP/1.x absolute-form request would then look like :
 *   <:method> <:scheme>://<:authority><:path> HTTP/x.y
 *
 * Except for CONNECT which doesn't have scheme nor path and looks like :
 *   <:method> <:authority> HTTP/x.y
 *
 * It's worth noting that H2 still supports an encoding to map H1 origin-form
 * and asterisk-form requests. These ones do not specify the authority. However
 * in H2 they must still specify the scheme, which is not present in H1. Also,
 * when encoding an absolute-form H1 request without a path, the path
 * automatically becomes "/" except for the OPTIONS method where it
 * becomes "*".
 *
 * As such it is explicitly permitted for an H2 client to send a request
 * featuring a Host header and no :authority, though it's not the recommended
 * way to use H2 for a client. It is however the only permitted way to encode
 * an origin-form H1 request over H2. Thus we need to respect such differences
 * as much as possible when re-encoding the H2 request into HTX.
 */
static struct htx_sl *h2_prepare_htx_reqline(uint32_t fields, struct ist *phdr, struct htx *htx, unsigned int *msgf)
{
	struct ist uri, meth_sl;
	unsigned int flags = HTX_SL_F_NONE;
	struct htx_sl *sl;
	enum http_meth_t meth;
	size_t i;

	if ((fields & H2_PHDR_FND_METH) && isteq(phdr[H2_PHDR_IDX_METH], ist("CONNECT"))) {
		if (fields & H2_PHDR_FND_PROT) {
			/* rfc 8441 Extended Connect Protocol
			 * #4 :scheme and :path must be present, as well as
			 * :authority like all h2 requests
			 */
			if (!(fields & H2_PHDR_FND_SCHM)) {
				/* missing scheme */
				goto fail;
			}
			else if (!(fields & H2_PHDR_FND_PATH)) {
				/* missing path */
				goto fail;
			}
			else if (!(fields & H2_PHDR_FND_AUTH)) {
				/* missing authority */
				goto fail;
			}

			flags |= HTX_SL_F_HAS_SCHM;
			if (isteqi(phdr[H2_PHDR_IDX_SCHM], ist("http")))
				flags |= HTX_SL_F_SCHM_HTTP;
			else if (isteqi(phdr[H2_PHDR_IDX_SCHM], ist("https")))
				flags |= HTX_SL_F_SCHM_HTTPS;
			else if (!http_validate_scheme(phdr[H2_PHDR_IDX_SCHM]))
				htx->flags |= HTX_FL_PARSING_ERROR;

			meth_sl = ist("GET");

			*msgf |= H2_MSGF_EXT_CONNECT;
			/* no ES on the HEADERS frame but no body either for
			 * Extended CONNECT */
			*msgf &= ~H2_MSGF_BODY;
		}
		else {
			/* RFC 7540 #8.2.6 regarding CONNECT: ":scheme" and ":path"
			 * MUST be omitted ; ":authority" contains the host and port
			 * to connect to.
			 */
			if (fields & H2_PHDR_FND_SCHM) {
				/* scheme not allowed */
				goto fail;
			}
			else if (fields & H2_PHDR_FND_PATH) {
				/* path not allowed */
				goto fail;
			}
			else if (!(fields & H2_PHDR_FND_AUTH)) {
				/* missing authority */
				goto fail;
			}

			meth_sl = phdr[H2_PHDR_IDX_METH];
		}

		*msgf |= H2_MSGF_BODY_TUNNEL;
	}
	else if ((fields & (H2_PHDR_FND_METH|H2_PHDR_FND_SCHM|H2_PHDR_FND_PATH)) !=
	         (H2_PHDR_FND_METH|H2_PHDR_FND_SCHM|H2_PHDR_FND_PATH)) {
		/* RFC 7540 #8.1.2.3 : all requests MUST include exactly one
		 * valid value for the ":method", ":scheme" and ":path" phdr
		 * unless it is a CONNECT request.
		 */
		if (!(fields & H2_PHDR_FND_METH)) {
			/* missing method */
			goto fail;
		}
		else if (!(fields & H2_PHDR_FND_SCHM)) {
			/* missing scheme */
			goto fail;
		}
		else {
			/* missing path */
			goto fail;
		}
	}
	else { /* regular methods */
		/* RFC3986#6.2.2.1: scheme is case-insensitive. We need to
		 * classify the scheme as "present/http", "present/https",
		 * "present/other", "absent" so as to decide whether or not
		 * we're facing a normalized URI that will have to be encoded
		 * in origin or absolute form. Indeed, 7540#8.1.2.3 says that
		 * clients should use the absolute form, thus we cannot infer
		 * whether or not the client wanted to use a proxy here.
		 */
		flags |= HTX_SL_F_HAS_SCHM;
		if (isteqi(phdr[H2_PHDR_IDX_SCHM], ist("http")))
			flags |= HTX_SL_F_SCHM_HTTP;
		else if (isteqi(phdr[H2_PHDR_IDX_SCHM], ist("https")))
			flags |= HTX_SL_F_SCHM_HTTPS;
		else if (!http_validate_scheme(phdr[H2_PHDR_IDX_SCHM]))
			htx->flags |= HTX_FL_PARSING_ERROR;

		meth_sl = phdr[H2_PHDR_IDX_METH];
	}

	if (fields & H2_PHDR_FND_PATH) {
		/* 7540#8.1.2.3: :path must not be empty, and must be either
		 * '*' or an RFC3986 "path-absolute" starting with a "/" but
		 * not with "//".
		 * However, this "path-absolute" was a mistake which was
		 * later fixed in http2bis as "absolute-path" to match
		 * HTTP/1, thus also allowing "//".
		 */
		if (unlikely(!phdr[H2_PHDR_IDX_PATH].len))
			goto fail;
		else if (unlikely(phdr[H2_PHDR_IDX_PATH].ptr[0] != '/')) {
			if (!isteq(phdr[H2_PHDR_IDX_PATH], ist("*")))
				goto fail;
		}
	}

	if (!(flags & HTX_SL_F_HAS_SCHM)) {
		/* no scheme, use authority only (CONNECT) */
		uri = phdr[H2_PHDR_IDX_AUTH];
		flags |= HTX_SL_F_HAS_AUTHORITY;
	}
	else if (fields & H2_PHDR_FND_AUTH) {
		/* authority is present, let's use the absolute form. We simply
		 * use the trash to concatenate them since all of them MUST fit
		 * in a bufsize since it's where they come from.
		 */
		uri = ist2bin(trash.area, phdr[H2_PHDR_IDX_SCHM]);
		istcat(&uri, ist("://"), trash.size);
		istcat(&uri, phdr[H2_PHDR_IDX_AUTH], trash.size);
		if (!isteq(phdr[H2_PHDR_IDX_PATH], ist("*")))
			istcat(&uri, phdr[H2_PHDR_IDX_PATH], trash.size);
		flags |= HTX_SL_F_HAS_AUTHORITY;

		if (flags & (HTX_SL_F_SCHM_HTTP|HTX_SL_F_SCHM_HTTPS)) {
			/* we don't know if it was originally an absolute or a
			 * relative request because newer versions of HTTP use
			 * the absolute URI format by default, which we call
			 * the normalized URI format internally. This is the
			 * strongly recommended way of sending a request for
			 * a regular client, so we cannot distinguish this
			 * from a request intended for a proxy. For other
			 * schemes however there is no doubt.
			 */
			flags |= HTX_SL_F_NORMALIZED_URI;
		}
	}
	else {
		/* usual schemes with or without authority, use origin form */
		uri = phdr[H2_PHDR_IDX_PATH];
		if (fields & H2_PHDR_FND_AUTH)
			flags |= HTX_SL_F_HAS_AUTHORITY;
	}

	/* The method is a non-empty token (RFC7231#4.1) */
	if (!meth_sl.len)
		goto fail;
	for (i = 0; i < meth_sl.len; i++) {
		if (!HTTP_IS_TOKEN(meth_sl.ptr[i]))
			htx->flags |= HTX_FL_PARSING_ERROR;
	}

	/* make sure the final URI isn't empty. Note that 7540#8.1.2.3 states
	 * that :path must not be empty.
	 */
	if (!uri.len)
		goto fail;

	/* The final URI must not contain LWS nor CTL characters */
	for (i = 0; i < uri.len; i++) {
		unsigned char c = uri.ptr[i];
		if (HTTP_IS_LWS(c) || HTTP_IS_CTL(c))
			htx->flags |= HTX_FL_PARSING_ERROR;
	}

	/* Set HTX start-line flags */
	flags |= HTX_SL_F_VER_11;    // V2 in fact
	flags |= HTX_SL_F_XFER_LEN;  // xfer len always known with H2


	meth = find_http_meth(meth_sl.ptr, meth_sl.len);
	if (meth == HTTP_METH_HEAD) {
		*msgf |= H2_MSGF_BODYLESS_RSP;
		flags |= HTX_SL_F_BODYLESS_RESP;
	}

	sl = htx_add_stline(htx, HTX_BLK_REQ_SL, flags, meth_sl, uri, ist("HTTP/2.0"));
	if (!sl)
		goto fail;
	sl->info.req.meth = meth;
	return sl;
 fail:
	return NULL;
}

/* Takes an H2 request present in the headers list <list> terminated by a name
 * being <NULL,0> and emits the equivalent HTX request according to the rules
 * documented in RFC7540 #8.1.2. The output contents are emitted in <htx>, and
 * non-zero is returned if some bytes were emitted. In case of error, a
 * negative error code is returned.
 *
 * Upon success, <msgf> is filled with a few H2_MSGF_* flags indicating what
 * was found while parsing. The caller must set it to zero in or H2_MSGF_BODY
 * if a body is detected (!ES).
 *
 * The headers list <list> must be composed of :
 *   - n.name != NULL, n.len  > 0 : literal header name
 *   - n.name == NULL, n.len  > 0 : indexed pseudo header name number <n.len>
 *                                  among H2_PHDR_IDX_*
 *   - n.name ignored, n.len == 0 : end of list
 *   - in all cases except the end of list, v.name and v.len must designate a
 *     valid value.
 *
 * The Cookie header will be reassembled at the end, and for this, the <list>
 * will be used to create a linked list, so its contents may be destroyed.
 *
 * When <relaxed> is non-nul, some non-dangerous checks will be ignored. This
 * is in order to satisfy "option accept-unsafe-violations-in-http-request" for
 * interoperability purposes.
 */
int h2_make_htx_request(struct http_hdr *list, struct htx *htx, unsigned int *msgf, unsigned long long *body_len, int relaxed)
{
	struct ist phdr_val[H2_PHDR_NUM_ENTRIES];
	uint32_t fields; /* bit mask of H2_PHDR_FND_* */
	uint32_t idx;
	int ck, lck; /* cookie index and last cookie index */
	int phdr;
	int ret;
	int i;
	struct htx_sl *sl = NULL;
	unsigned int sl_flags = 0;
	const char *ctl;

	lck = ck = -1; // no cookie for now
	fields = 0;
	for (idx = 0; list[idx].n.len != 0; idx++) {
		if (!isttest(list[idx].n)) {
			/* this is an indexed pseudo-header */
			phdr = list[idx].n.len;
		}
		else {
			/* this can be any type of header */
			/* RFC7540#8.1.2: upper case not allowed in header field names.
			 * #10.3: header names must be valid (i.e. match a token).
			 * For pseudo-headers we check from 2nd char and for other ones
			 * from the first char, because HTTP_IS_TOKEN() also excludes
			 * the colon.
			 */
			phdr = h2_str_to_phdr(list[idx].n);

			for (i = !!phdr; i < list[idx].n.len; i++)
				if ((uint8_t)(list[idx].n.ptr[i] - 'A') < 'Z' - 'A' || !HTTP_IS_TOKEN(list[idx].n.ptr[i]))
					goto fail;
		}

		/* RFC7540#10.3: intermediaries forwarding to HTTP/1 must take care of
		 * rejecting NUL, CR and LF characters. For :path we reject all CTL
		 * chars, spaces, and '#'.
		 */
		if (phdr == H2_PHDR_IDX_PATH && !relaxed) {
			ctl = ist_find_range(list[idx].v, 0, '#');
			if (unlikely(ctl) && http_path_has_forbidden_char(list[idx].v, ctl))
				goto fail;
		} else {
			ctl = ist_find_ctl(list[idx].v);
			if (unlikely(ctl) && http_header_has_forbidden_char(list[idx].v, ctl))
				goto fail;
		}

		if (phdr > 0 && phdr < H2_PHDR_NUM_ENTRIES) {
			/* insert a pseudo header by its index (in phdr) and value (in value) */
			if (fields & ((1 << phdr) | H2_PHDR_FND_NONE)) {
				if (fields & H2_PHDR_FND_NONE) {
					/* pseudo header field after regular headers */
					goto fail;
				}
				else {
					/* repeated pseudo header field */
					goto fail;
				}
			}
			fields |= 1 << phdr;
			phdr_val[phdr] = list[idx].v;
			continue;
		}
		else if (phdr != 0) {
			/* invalid pseudo header -- should never happen here */
			goto fail;
		}

		/* regular header field in (name,value) */
		if (unlikely(!(fields & H2_PHDR_FND_NONE))) {
			/* no more pseudo-headers, time to build the request line */
			sl = h2_prepare_htx_reqline(fields, phdr_val, htx, msgf);
			if (!sl)
				goto fail;
			fields |= H2_PHDR_FND_NONE;

			/* http2bis draft recommends to drop Host in favor of :authority when
			 * the latter is present. This is required to make sure there is no
			 * discrepancy between the authority and the host header, especially
			 * since routing rules usually involve Host. Here we already know if
			 * :authority was found so we can emit it right now and mark the host
			 * as filled so that it's skipped later.
			 */
			if (fields & H2_PHDR_FND_AUTH) {
				if (!htx_add_header(htx, ist("host"), phdr_val[H2_PHDR_IDX_AUTH]))
					goto fail;
				fields |= H2_PHDR_FND_HOST;
			}
		}

		if (isteq(list[idx].n, ist("host"))) {
			if (fields & H2_PHDR_FND_HOST)
				continue;

			fields |= H2_PHDR_FND_HOST;
		}

		if (isteq(list[idx].n, ist("content-length"))) {
			ret = http_parse_cont_len_header(&list[idx].v, body_len,
			                                 *msgf & H2_MSGF_BODY_CL);
			if (ret < 0)
				goto fail;

			*msgf |= H2_MSGF_BODY_CL;
			sl_flags |= HTX_SL_F_CLEN;
			if (ret == 0)
				continue; // skip this duplicate
		}

		/* these ones are forbidden in requests (RFC7540#8.1.2.2) */
		if (isteq(list[idx].n, ist("connection")) ||
		    isteq(list[idx].n, ist("proxy-connection")) ||
		    isteq(list[idx].n, ist("keep-alive")) ||
		    isteq(list[idx].n, ist("upgrade")) ||
		    isteq(list[idx].n, ist("transfer-encoding")))
			goto fail;

		if (isteq(list[idx].n, ist("te")) && !isteq(list[idx].v, ist("trailers")))
			goto fail;

		/* cookie requires special processing at the end */
		if (isteq(list[idx].n, ist("cookie"))) {
			http_cookie_register(list, idx, &ck, &lck);
			continue;
		}

		if (!htx_add_header(htx, list[idx].n, list[idx].v))
			goto fail;
	}

	/* RFC7540#8.1.2.1 mandates to reject response pseudo-headers (:status) */
	if (fields & H2_PHDR_FND_STAT)
		goto fail;

	/* Let's dump the request now if not yet emitted. */
	if (!(fields & H2_PHDR_FND_NONE)) {
		sl = h2_prepare_htx_reqline(fields, phdr_val, htx, msgf);
		if (!sl)
			goto fail;
	}

	if (*msgf & H2_MSGF_BODY_TUNNEL)
		*msgf &= ~(H2_MSGF_BODY|H2_MSGF_BODY_CL);

	if (!(*msgf & H2_MSGF_BODY) || ((*msgf & H2_MSGF_BODY_CL) && *body_len == 0) ||
	    (*msgf & H2_MSGF_BODY_TUNNEL)) {
		/* Request without body or tunnel requested */
		sl_flags |= HTX_SL_F_BODYLESS;
		if (*msgf & H2_MSGF_BODY_TUNNEL)
		    htx->flags |= HTX_FL_EOM;
	}

	if (*msgf & H2_MSGF_EXT_CONNECT) {
		/* Consider "h2c" / "h2" as invalid protocol value for Extended CONNECT. */
		if (isteqi(phdr_val[H2_PHDR_IDX_PROT], ist("h2c")) ||
		    isteqi(phdr_val[H2_PHDR_IDX_PROT], ist("h2"))) {
			goto fail;
		}

		if (!htx_add_header(htx, ist("upgrade"), phdr_val[H2_PHDR_IDX_PROT]))
			goto fail;
		if (!htx_add_header(htx, ist("connection"), ist("upgrade")))
			goto fail;
		sl_flags |= HTX_SL_F_CONN_UPG;
	}

	/* update the start line with last detected header info */
	sl->flags |= sl_flags;

	/* complete with missing Host if needed (we may validate this test if
	 * no regular header was found).
	 */
	if ((fields & (H2_PHDR_FND_HOST|H2_PHDR_FND_AUTH)) == H2_PHDR_FND_AUTH) {
		/* missing Host field, use :authority instead */
		if (!htx_add_header(htx, ist("host"), phdr_val[H2_PHDR_IDX_AUTH]))
			goto fail;
	}

	/* now we may have to build a cookie list. We'll dump the values of all
	 * visited headers.
	 */
	if (ck >= 0) {
		if (http_cookie_merge(htx, list, ck))
			goto fail;
	}

	/* Check the number of blocks agains "tune.http.maxhdr" value before adding EOH block */
	if (htx_nbblks(htx) > global.tune.max_http_hdr)
		goto fail;

	/* now send the end of headers marker */
	if (!htx_add_endof(htx, HTX_BLK_EOH))
		goto fail;

	/* proceed to scheme-based normalization on target-URI */
	if (fields & H2_PHDR_FND_SCHM)
		http_scheme_based_normalize(htx);

	ret = 1;
	return ret;

 fail:
	return -1;
}

/* Prepare the status line into <htx> from pseudo headers stored in <phdr[]>.
 * <fields> indicates what was found so far. This should be called once at the
 * detection of the first general header field or at the end of the message if
 * no general header field was found yet. Returns the created start line on
 * success, or NULL on failure. Upon success, <msgf> is updated with a few
 * H2_MSGF_* flags indicating what was found while parsing.
 */
static struct htx_sl *h2_prepare_htx_stsline(uint32_t fields, struct ist *phdr, struct htx *htx, unsigned int *msgf)
{
	unsigned int status, flags = HTX_SL_F_IS_RESP;
	struct htx_sl *sl;
	struct ist stat;

	/* only :status is allowed as a pseudo header */
	if (!(fields & H2_PHDR_FND_STAT))
		goto fail;

	if (phdr[H2_PHDR_IDX_STAT].len != 3)
		goto fail;

	/* if Extended CONNECT is used, convert status code from 200 to htx 101
	 * following rfc 8441 */
	if (unlikely(*msgf & H2_MSGF_EXT_CONNECT) &&
	    isteq(phdr[H2_PHDR_IDX_STAT], ist("200"))) {
		stat = ist("101");
		status = 101;
	}
	else {
		unsigned char h, t, u;

		stat = phdr[H2_PHDR_IDX_STAT];

		h = stat.ptr[0] - '0';
		t = stat.ptr[1] - '0';
		u = stat.ptr[2] - '0';
		if (h > 9 || t > 9 || u > 9)
			goto fail;
		status = h * 100 + t * 10 + u;
	}

	/* 101 responses are not supported in H2, so return a error.
	 * On 1xx responses there is no ES on the HEADERS frame but there is no
	 * body. So remove the flag H2_MSGF_BODY and add H2_MSGF_RSP_1XX to
	 * notify the decoder another HEADERS frame is expected.
	 * 204/304 response have no body by definition. So remove the flag
	 * H2_MSGF_BODY and set H2_MSGF_BODYLESS_RSP.
	 *
	 * Note however that there is a special condition for Extended CONNECT.
	 * In this case, we explicitly convert it to HTX 101 to mimic
	 * Get+Upgrade HTTP/1.1 mechanism
	 */
	if (status == 101) {
		if (!(*msgf & H2_MSGF_EXT_CONNECT))
			goto fail;
	}
	else if (status < 200) {
		*msgf |= H2_MSGF_RSP_1XX;
		*msgf &= ~H2_MSGF_BODY;
	}
	else if (status == 204 || status == 304) {
		*msgf &= ~H2_MSGF_BODY;
		*msgf |= H2_MSGF_BODYLESS_RSP;
		flags |= HTX_SL_F_BODYLESS_RESP;
	}

	/* Set HTX start-line flags */
	flags |= HTX_SL_F_VER_11;    // V2 in fact
	flags |= HTX_SL_F_XFER_LEN;  // xfer len always known with H2

	sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/2.0"), stat, ist(""));
	if (!sl)
		goto fail;
	sl->info.res.status = status;
	return sl;
 fail:
	return NULL;
}

/* Takes an H2 response present in the headers list <list> terminated by a name
 * being <NULL,0> and emits the equivalent HTX response according to the rules
 * documented in RFC7540 #8.1.2. The output contents are emitted in <htx>, and
 * a positive value is returned if some bytes were emitted. In case of error, a
 * negative error code is returned.
 *
 * Upon success, <msgf> is filled with a few H2_MSGF_* flags indicating what
 * was found while parsing. The caller must set it to zero in or H2_MSGF_BODY
 * if a body is detected (!ES).
 *
 * The headers list <list> must be composed of :
 *   - n.name != NULL, n.len  > 0 : literal header name
 *   - n.name == NULL, n.len  > 0 : indexed pseudo header name number <n.len>
 *                                  among H2_PHDR_IDX_*
 *   - n.name ignored, n.len == 0 : end of list
 *   - in all cases except the end of list, v.name and v.len must designate a
 *     valid value.
 *
 * <upgrade_protocol> is only used if the htx status code is 101 indicating a
 * response to an upgrade or h2-equivalent request.
 */
int h2_make_htx_response(struct http_hdr *list, struct htx *htx, unsigned int *msgf, unsigned long long *body_len, char *upgrade_protocol)
{
	struct ist phdr_val[H2_PHDR_NUM_ENTRIES];
	uint32_t fields; /* bit mask of H2_PHDR_FND_* */
	uint32_t idx;
	int phdr;
	int ret;
	int i;
	struct htx_sl *sl = NULL;
	unsigned int sl_flags = 0;
	const char *ctl;

	fields = 0;
	for (idx = 0; list[idx].n.len != 0; idx++) {
		if (!isttest(list[idx].n)) {
			/* this is an indexed pseudo-header */
			phdr = list[idx].n.len;
		}
		else {
			/* this can be any type of header */
			/* RFC7540#8.1.2: upper case not allowed in header field names.
			 * #10.3: header names must be valid (i.e. match a token).
			 * For pseudo-headers we check from 2nd char and for other ones
			 * from the first char, because HTTP_IS_TOKEN() also excludes
			 * the colon.
			 */
			phdr = h2_str_to_phdr(list[idx].n);

			for (i = !!phdr; i < list[idx].n.len; i++)
				if ((uint8_t)(list[idx].n.ptr[i] - 'A') < 'Z' - 'A' || !HTTP_IS_TOKEN(list[idx].n.ptr[i]))
					goto fail;
		}

		/* RFC7540#10.3: intermediaries forwarding to HTTP/1 must take care of
		 * rejecting NUL, CR and LF characters.
		 */
		ctl = ist_find_ctl(list[idx].v);
		if (unlikely(ctl) && http_header_has_forbidden_char(list[idx].v, ctl))
			goto fail;

		if (phdr > 0 && phdr < H2_PHDR_NUM_ENTRIES) {
			/* insert a pseudo header by its index (in phdr) and value (in value) */
			if (fields & ((1 << phdr) | H2_PHDR_FND_NONE)) {
				if (fields & H2_PHDR_FND_NONE) {
					/* pseudo header field after regular headers */
					goto fail;
				}
				else {
					/* repeated pseudo header field */
					goto fail;
				}
			}
			fields |= 1 << phdr;
			phdr_val[phdr] = list[idx].v;
			continue;
		}
		else if (phdr != 0) {
			/* invalid pseudo header -- should never happen here */
			goto fail;
		}

		/* regular header field in (name,value) */
		if (!(fields & H2_PHDR_FND_NONE)) {
			/* no more pseudo-headers, time to build the status line */
			sl = h2_prepare_htx_stsline(fields, phdr_val, htx, msgf);
			if (!sl)
				goto fail;
			fields |= H2_PHDR_FND_NONE;
		}

		if (isteq(list[idx].n, ist("content-length"))) {
			ret = http_parse_cont_len_header(&list[idx].v, body_len,
			                                 *msgf & H2_MSGF_BODY_CL);
			if (ret < 0)
				goto fail;

			*msgf |= H2_MSGF_BODY_CL;
			sl_flags |= HTX_SL_F_CLEN;
			if (ret == 0)
				continue; // skip this duplicate
		}

		/* these ones are forbidden in responses (RFC7540#8.1.2.2) */
		if (isteq(list[idx].n, ist("connection")) ||
		    isteq(list[idx].n, ist("proxy-connection")) ||
		    isteq(list[idx].n, ist("keep-alive")) ||
		    isteq(list[idx].n, ist("upgrade")) ||
		    isteq(list[idx].n, ist("transfer-encoding")))
			goto fail;

		if (!htx_add_header(htx, list[idx].n, list[idx].v))
			goto fail;
	}

	/* RFC7540#8.1.2.1 mandates to reject request pseudo-headers */
	if (fields & (H2_PHDR_FND_AUTH|H2_PHDR_FND_METH|H2_PHDR_FND_PATH|H2_PHDR_FND_SCHM))
		goto fail;

	/* Let's dump the request now if not yet emitted. */
	if (!(fields & H2_PHDR_FND_NONE)) {
		sl = h2_prepare_htx_stsline(fields, phdr_val, htx, msgf);
		if (!sl)
			goto fail;
	}

	if (sl->info.res.status == 101 && upgrade_protocol) {
		if (!htx_add_header(htx, ist("connection"), ist("upgrade")))
			goto fail;
		if (!htx_add_header(htx, ist("upgrade"), ist(upgrade_protocol)))
			goto fail;
		sl_flags |= HTX_SL_F_CONN_UPG;
	}

	if ((*msgf & H2_MSGF_BODY_TUNNEL) &&
	    ((sl->info.res.status >= 200 && sl->info.res.status < 300) || sl->info.res.status == 101))
		*msgf &= ~(H2_MSGF_BODY|H2_MSGF_BODY_CL);
	else
		*msgf &= ~H2_MSGF_BODY_TUNNEL;

	if (!(*msgf & H2_MSGF_BODY) || ((*msgf & H2_MSGF_BODY_CL) && *body_len == 0) ||
	    (*msgf & H2_MSGF_BODY_TUNNEL)) {
		/* Response without body or tunnel successfully established */
		sl_flags |= HTX_SL_F_BODYLESS;
		if (*msgf & H2_MSGF_BODY_TUNNEL)
		    htx->flags |= HTX_FL_EOM;
	}

	/* update the start line with last detected header info */
	sl->flags |= sl_flags;

	if ((*msgf & (H2_MSGF_BODY|H2_MSGF_BODY_TUNNEL|H2_MSGF_BODY_CL)) == H2_MSGF_BODY) {
		/* FIXME: Do we need to signal anything when we have a body and
		 * no content-length, to have the equivalent of H1's chunked
		 * encoding?
		 */
	}

	/* Check the number of blocks agains "tune.http.maxhdr" value before adding EOH block */
	if (htx_nbblks(htx) > global.tune.max_http_hdr)
		goto fail;

	/* now send the end of headers marker */
	if (!htx_add_endof(htx, HTX_BLK_EOH))
		goto fail;

	ret = 1;
	return ret;

 fail:
	return -1;
}

/* Takes an H2 headers list <list> terminated by a name being <NULL,0> and emits
 * the equivalent HTX trailers blocks. The output contents are emitted in <htx>,
 * and a positive value is returned if some bytes were emitted. In case of
 * error, a negative error code is returned. The caller must have verified that
 * the message in the buffer is compatible with receipt of trailers.
 *
 * The headers list <list> must be composed of :
 *   - n.name != NULL, n.len  > 0 : literal header name
 *   - n.name == NULL, n.len  > 0 : indexed pseudo header name number <n.len>
 *                                  among H2_PHDR_IDX_* (illegal here)
 *   - n.name ignored, n.len == 0 : end of list
 *   - in all cases except the end of list, v.name and v.len must designate a
 *     valid value.
 */
int h2_make_htx_trailers(struct http_hdr *list, struct htx *htx)
{
	const char *ctl;
	uint32_t idx;
	int i;

	for (idx = 0; list[idx].n.len != 0; idx++) {
		if (!isttest(list[idx].n)) {
			/* This is an indexed pseudo-header (RFC7540#8.1.2.1) */
			goto fail;
		}

		/* RFC7540#8.1.2: upper case not allowed in header field names.
		 * #10.3: header names must be valid (i.e. match a token). This
		 * also catches pseudo-headers which are forbidden in trailers.
		 */
		for (i = 0; i < list[idx].n.len; i++)
			if ((uint8_t)(list[idx].n.ptr[i] - 'A') < 'Z' - 'A' || !HTTP_IS_TOKEN(list[idx].n.ptr[i]))
				goto fail;

		/* these ones are forbidden in trailers (RFC7540#8.1.2.2) */
		if (isteq(list[idx].n, ist("host")) ||
		    isteq(list[idx].n, ist("content-length")) ||
		    isteq(list[idx].n, ist("connection")) ||
		    isteq(list[idx].n, ist("proxy-connection")) ||
		    isteq(list[idx].n, ist("keep-alive")) ||
		    isteq(list[idx].n, ist("upgrade")) ||
		    isteq(list[idx].n, ist("te")) ||
		    isteq(list[idx].n, ist("transfer-encoding")))
			goto fail;

		/* RFC7540#10.3: intermediaries forwarding to HTTP/1 must take care of
		 * rejecting NUL, CR and LF characters.
		 */
		ctl = ist_find_ctl(list[idx].v);
		if (unlikely(ctl) && http_header_has_forbidden_char(list[idx].v, ctl))
			goto fail;

		if (!htx_add_trailer(htx, list[idx].n, list[idx].v))
			goto fail;
	}

	/* Check the number of blocks agains "tune.http.maxhdr" value before adding EOT block */
	if (htx_nbblks(htx) > global.tune.max_http_hdr)
		goto fail;

	if (!htx_add_endof(htx, HTX_BLK_EOT))
		goto fail;

	return 1;

 fail:
	return -1;
}
