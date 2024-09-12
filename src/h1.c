/*
 * HTTP/1 protocol analyzer
 *
 * Copyright 2000-2017 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>

#include <import/sha1.h>

#include <haproxy/api.h>
#include <haproxy/base64.h>
#include <haproxy/cfgparse.h>
#include <haproxy/h1.h>
#include <haproxy/http-hdr.h>
#include <haproxy/tools.h>

/* by default, RFC9112#6.1 applies, t-e combined with c-l represents a risk of
 * smuggling if it crosses another 1.0 agent so we must close at the end of the
 * transaction. But it may cause difficulties to some very old broken devices.
 */
int h1_do_not_close_on_insecure_t_e = 0;

/* Parse the Content-Length header field of an HTTP/1 request. The function
 * checks all possible occurrences of a comma-delimited value, and verifies
 * if any of them doesn't match a previous value. It returns <0 if a value
 * differs, 0 if the whole header can be dropped (i.e. already known), or >0
 * if the value can be indexed (first one). In the last case, the value might
 * be adjusted and the caller must only add the updated value.
 */
int h1_parse_cont_len_header(struct h1m *h1m, struct ist *value)
{
	char *e, *n;
	long long cl;
	int not_first = !!(h1m->flags & H1_MF_CLEN);
	struct ist word;

	word.ptr = value->ptr;
	e = value->ptr + value->len;

	while (1) {
		if (word.ptr >= e) {
			/* empty header or empty value */
			goto fail;
		}

		/* skip leading delimiter and blanks */
		if (unlikely(HTTP_IS_LWS(*word.ptr))) {
			word.ptr++;
			continue;
		}

		/* digits only now */
		for (cl = 0, n = word.ptr; n < e; n++) {
			unsigned int c = *n - '0';
			if (unlikely(c > 9)) {
				/* non-digit */
				if (unlikely(n == word.ptr)) // spaces only
					goto fail;
				break;
			}

			if (unlikely(!cl && n > word.ptr)) {
				/* There was a leading zero before this digit,
				 * let's trim it.
				 */
				word.ptr = n;
			}

			if (unlikely(cl > ULLONG_MAX / 10ULL))
				goto fail; /* multiply overflow */
			cl = cl * 10ULL;
			if (unlikely(cl + c < cl))
				goto fail; /* addition overflow */
			cl = cl + c;
		}

		/* keep a copy of the exact cleaned value */
		word.len = n - word.ptr;

		/* skip trailing LWS till next comma or EOL */
		for (; n < e; n++) {
			if (!HTTP_IS_LWS(*n)) {
				if (unlikely(*n != ','))
					goto fail;
				break;
			}
		}

		/* if duplicate, must be equal */
		if (h1m->flags & H1_MF_CLEN && cl != h1m->body_len)
			goto fail;

		/* OK, store this result as the one to be indexed */
		h1m->flags |= H1_MF_CLEN;
		h1m->curr_len = h1m->body_len = cl;
		*value = word;

		/* Now either n==e and we're done, or n points to the comma,
		 * and we skip it and continue.
		 */
		if (n++ == e)
			break;

		word.ptr = n;
	}
	/* here we've reached the end with a single value or a series of
	 * identical values, all matching previous series if any. The last
	 * parsed value was sent back into <value>. We just have to decide
	 * if this occurrence has to be indexed (it's the first one) or
	 * silently skipped (it's not the first one)
	 */
	return !not_first;
 fail:
	return -1;
}

/* Parse the Transfer-Encoding: header field of an HTTP/1 request, looking for
 * "chunked" encoding to perform some checks (it must be the last encoding for
 * the request and must not be performed twice for any message). The
 * H1_MF_TE_CHUNKED is set if a valid "chunked" encoding is found. The
 * H1_MF_TE_OTHER flag is set if any other encoding is found. The H1_MF_XFER_ENC
 * flag is always set. The H1_MF_CHNK is set when "chunked" encoding is the last
 * one. Note that transfer codings are case-insensitive (cf RFC7230#4). This
 * function returns -2 for a fatal error, -1 for an error that may be hiidden by
 * config, 0 if the whole header can be dropped (not used yet), or >0 if the
 * value can be indexed.
 */
int h1_parse_xfer_enc_header(struct h1m *h1m, struct ist value)
{
	char *e, *n;
	struct ist word;
	int ret = 1;

	/* Reject empty header */
	if (istptr(value) == istend(value)) {
		ret = -1;
		goto end;
	}

	h1m->flags |= H1_MF_XFER_ENC;

	word.ptr = value.ptr - 1; // -1 for next loop's pre-increment
	e = istend(value);

	while (++word.ptr < e) {
		/* skip leading delimiter and blanks */
		if (HTTP_IS_LWS(*word.ptr))
			continue;

		n = http_find_hdr_value_end(word.ptr, e); // next comma or end of line

		/* a comma at the end means the last value is empty */
		if (n+1 == e)
			ret = -1;
		word.len = n - word.ptr;

		/* trim trailing blanks */
		while (word.len && HTTP_IS_LWS(word.ptr[word.len-1]))
			word.len--;

		h1m->flags &= ~H1_MF_CHNK;

		/* empty values are forbidden */
		if (!word.len)
			ret = -1;
		else if (isteqi(word, ist("chunked"))) {
			if (h1m->flags & H1_MF_TE_CHUNKED) {
				/* cf RFC7230#3.3.1 : A sender MUST NOT apply
				 * chunked more than once to a message body
				 * (i.e., chunking an already chunked message is
				 * not allowed)
				 */
				ret = -1;
			}
			h1m->flags |= (H1_MF_TE_CHUNKED|H1_MF_CHNK);
		}
		else {
			if ((h1m->flags & (H1_MF_RESP|H1_MF_TE_CHUNKED)) == H1_MF_TE_CHUNKED) {
				/* cf RFC7230#3.3.1 : If any transfer coding
				 * other than chunked is applied to a request
				 * payload body, the sender MUST apply chunked
				 * as the final transfer coding to ensure that
				 * the message is properly framed.
				 */
				ret = -2;
				goto end;
			}
			h1m->flags |= H1_MF_TE_OTHER;
		}

		word.ptr = n;
	}

  end:
	return ret;
}

/* Validate the authority and the host header value for CONNECT method. If there
 * is hast header, its value is normalized. 0 is returned on success, -1 if the
 * authority is invalid and -2 if the host is invalid.
 */
static int h1_validate_connect_authority(struct ist scheme, struct ist authority, struct ist *host_hdr)
{
	struct ist uri_host, uri_port, host, host_port;

	if (isttest(scheme) || !isttest(authority))
		goto invalid_authority;
	uri_host = authority;
	uri_port = http_get_host_port(authority);
	if (!istlen(uri_port))
		goto invalid_authority;
	uri_host.len -= (istlen(uri_port) + 1);

	if (!host_hdr || !isttest(*host_hdr))
		goto end;

	/* Get the port of the host header value, if any */
	host = *host_hdr;
	host_port = http_get_host_port(*host_hdr);
	if (isttest(host_port))
		host.len -= (istlen(host_port) + 1);

	if (istlen(host_port)) {
		if (!isteqi(host, uri_host) || !isteq(host_port, uri_port))
			goto invalid_host;
		if (http_is_default_port(IST_NULL, uri_port))
			*host_hdr = host; /* normalize */
	}
	else {
		if (!http_is_default_port(IST_NULL, uri_port) || !isteqi(host, uri_host))
			goto invalid_host;
	}

  end:
	return 0;

  invalid_authority:
	return -1;

  invalid_host:
	return -2;
}


/* Validate the authority and the host header value for non-CONNECT method, when
 * an absolute-URI is detected but when it does not exactly match the host
 * value. The idea is to detect default port (http or https). authority and host
 * are defined here. 0 is returned on success, -1 if the host is does not match
 * the authority.
 */
static int h1_validate_mismatch_authority(struct ist scheme, struct ist authority, struct ist host_hdr)
{
	struct ist uri_host, uri_port, host, host_port;

	if (!isttest(scheme))
		goto mismatch;

	uri_host = authority;
	uri_port = http_get_host_port(authority);
	if (isttest(uri_port))
		uri_host.len -= (istlen(uri_port) + 1);

	host = host_hdr;
	host_port = http_get_host_port(host_hdr);
	if (isttest(host_port))
	    host.len -= (istlen(host_port) + 1);

	if (!isttest(uri_port) && !isttest(host_port)) {
		/* No port on both: we already know the authority does not match
		 * the host value
		 */
		goto mismatch;
	}
	else if (isttest(uri_port) && !http_is_default_port(scheme, uri_port)) {
		/* here there is no port for the host value and the port for the
		 * authority is not the default one
		 */
		goto mismatch;
	}
	else if (isttest(host_port) && !http_is_default_port(scheme, host_port)) {
		/* here there is no port for the authority and the port for the
		 * host value is not the default one
		 */
		goto mismatch;
	}
	else {
		/* the authority or the host value contain a default port and
		 * there is no port on the other value
		 */
		if (!isteqi(uri_host, host))
			goto mismatch;
	}

	return 0;

  mismatch:
	return -1;
}


/* Parse the Connection: header of an HTTP/1 request, looking for "close",
 * "keep-alive", and "upgrade" values, and updating h1m->flags according to
 * what was found there. Note that flags are only added, not removed, so the
 * function is safe for being called multiple times if multiple occurrences
 * are found. If the flag H1_MF_CLEAN_CONN_HDR, the header value is cleaned
 * up from "keep-alive" and "close" values. To do so, the header value is
 * rewritten in place and its length is updated.
 */
void h1_parse_connection_header(struct h1m *h1m, struct ist *value)
{
	char *e, *n, *p;
	struct ist word;

	word.ptr = value->ptr - 1; // -1 for next loop's pre-increment
	p = value->ptr;
	e = value->ptr + value->len;
	if (h1m->flags & H1_MF_CLEAN_CONN_HDR)
		value->len = 0;

	while (++word.ptr < e) {
		/* skip leading delimiter and blanks */
		if (HTTP_IS_LWS(*word.ptr))
			continue;

		n = http_find_hdr_value_end(word.ptr, e); // next comma or end of line
		word.len = n - word.ptr;

		/* trim trailing blanks */
		while (word.len && HTTP_IS_LWS(word.ptr[word.len-1]))
			word.len--;

		if (isteqi(word, ist("keep-alive"))) {
			h1m->flags |= H1_MF_CONN_KAL;
			if (h1m->flags & H1_MF_CLEAN_CONN_HDR)
				goto skip_val;
		}
		else if (isteqi(word, ist("close"))) {
			h1m->flags |= H1_MF_CONN_CLO;
			if (h1m->flags & H1_MF_CLEAN_CONN_HDR)
				goto skip_val;
		}
		else if (isteqi(word, ist("upgrade")))
			h1m->flags |= H1_MF_CONN_UPG;

		if (h1m->flags & H1_MF_CLEAN_CONN_HDR) {
			if (value->ptr + value->len == p) {
				/* no rewrite done till now */
				value->len = n - value->ptr;
			}
			else {
				if (value->len)
					value->ptr[value->len++] = ',';
				istcat(value, word, e - value->ptr);
			}
		}

	  skip_val:
		word.ptr = p = n;
	}
}

/* Parse the Upgrade: header of an HTTP/1 request.
 * If "websocket" is found, set H1_MF_UPG_WEBSOCKET flag
 * If "h2c" or "h2" found, set H1_MF_UPG_H2C flag.
 */
void h1_parse_upgrade_header(struct h1m *h1m, struct ist value)
{
	char *e, *n;
	struct ist word;

	h1m->flags &= ~(H1_MF_UPG_WEBSOCKET|H1_MF_UPG_H2C);

	word.ptr = value.ptr - 1; // -1 for next loop's pre-increment
	e = istend(value);

	while (++word.ptr < e) {
		/* skip leading delimiter and blanks */
		if (HTTP_IS_LWS(*word.ptr))
			continue;

		n = http_find_hdr_value_end(word.ptr, e); // next comma or end of line
		word.len = n - word.ptr;

		/* trim trailing blanks */
		while (word.len && HTTP_IS_LWS(word.ptr[word.len-1]))
			word.len--;

		if (isteqi(word, ist("websocket")))
			h1m->flags |= H1_MF_UPG_WEBSOCKET;
		else if (isteqi(word, ist("h2c")) || isteqi(word, ist("h2")))
			h1m->flags |= H1_MF_UPG_H2C;

		word.ptr = n;
	}
}

/* Macros used in the HTTP/1 parser, to check for the expected presence of
 * certain bytes (ef: LF) or to skip to next byte and yield in case of failure.
 */

/* Expects to find an LF at <ptr>. If not, set <state> to <where> and jump to
 * <bad>.
 */
#define EXPECT_LF_HERE(ptr, bad, state, where)                  \
	do {                                                    \
		if (unlikely(*(ptr) != '\n')) {                 \
			state = (where);                        \
			goto bad;                               \
		}                                               \
	} while (0)

/* Increments pointer <ptr>, continues to label <more> if it's still below
 * pointer <end>, or goes to <stop> and sets <state> to <where> if the end
 * of buffer was reached.
 */
#define EAT_AND_JUMP_OR_RETURN(ptr, end, more, stop, state, where)        \
	do {                                                              \
		if (likely(++(ptr) < (end)))                              \
			goto more;                                        \
		else {                                                    \
			state = (where);                                  \
			goto stop;                                        \
		}                                                         \
	} while (0)

/* This function parses a contiguous HTTP/1 headers block starting at <start>
 * and ending before <stop>, at once, and converts it a list of (name,value)
 * pairs representing header fields into the array <hdr> of size <hdr_num>,
 * whose last entry will have an empty name and an empty value. If <hdr_num> is
 * too small to represent the whole message, an error is returned. Some
 * protocol elements such as content-length and transfer-encoding will be
 * parsed and stored into h1m as well. <hdr> may be null, in which case only
 * the parsing state will be updated. This may be used to restart the parsing
 * where it stopped for example.
 *
 * For now it's limited to the response. If the header block is incomplete,
 * 0 is returned, waiting to be called again with more data to try it again.
 * The caller is responsible for initializing h1m->state to H1_MSG_RPBEFORE,
 * and h1m->next to zero on the first call, the parser will do the rest. If
 * an incomplete message is seen, the caller only needs to present h1m->state
 * and h1m->next again, with an empty header list so that the parser can start
 * again. In this case, it will detect that it interrupted a previous session
 * and will first look for the end of the message before reparsing it again and
 * indexing it at the same time. This ensures that incomplete messages fed 1
 * character at a time are never processed entirely more than exactly twice,
 * and that there is no need to store all the internal state and pre-parsed
 * headers or start line between calls.
 *
 * A pointer to a start line descriptor may be passed in <slp>, in which case
 * the parser will fill it with whatever it found.
 *
 * The code derived from the main HTTP/1 parser above but was simplified and
 * optimized to process responses produced or forwarded by haproxy. The caller
 * is responsible for ensuring that the message doesn't wrap, and should ensure
 * it is complete to avoid having to retry the operation after a failed
 * attempt. The message is not supposed to be invalid, which is why a few
 * properties such as the character set used in the header field names are not
 * checked. In case of an unparsable response message, a negative value will be
 * returned with h1m->err_pos and h1m->err_state matching the location and
 * state where the error was met. Leading blank likes are tolerated but not
 * recommended. If flag H1_MF_HDRS_ONLY is set in h1m->flags, only headers are
 * parsed and the start line is skipped. It is not required to set h1m->state
 * nor h1m->next in this case.
 *
 * This function returns :
 *    -1 in case of error. In this case, h1m->err_state is filled (if h1m is
 *       set) with the state the error occurred in and h1m->err_pos with the
 *       the position relative to <start>
 *    -2 if the output is full (hdr_num reached). err_state and err_pos also
 *       indicate where it failed.
 *     0 in case of missing data.
 *   > 0 on success, it then corresponds to the number of bytes read since
 *       <start> so that the caller can go on with the payload.
 */
int h1_headers_to_hdr_list(char *start, const char *stop,
                           struct http_hdr *hdr, unsigned int hdr_num,
                           struct h1m *h1m, union h1_sl *slp)
{
	enum h1m_state state;
	register char *ptr;
	register const char *end;
	unsigned int hdr_count;
	unsigned int skip; /* number of bytes skipped at the beginning */
	unsigned int sol;  /* start of line */
	unsigned int col;  /* position of the colon */
	unsigned int eol;  /* end of line */
	unsigned int sov;  /* start of value */
	union h1_sl sl;
	int skip_update;
	int restarting;
	int host_idx;
	struct ist n, v;       /* header name and value during parsing */

	skip = 0; // do it only once to keep track of the leading CRLF.

 try_again:
	hdr_count = sol = col = eol = sov = 0;
	sl.st.status = 0;
	skip_update = restarting = 0;
	host_idx = -1;

	if (h1m->flags & H1_MF_HDRS_ONLY) {
		state = H1_MSG_HDR_FIRST;
		h1m->next = 0;
	}
	else {
		state = h1m->state;
		if (h1m->state != H1_MSG_RQBEFORE && h1m->state != H1_MSG_RPBEFORE)
			restarting = 1;
	}

	ptr   = start + h1m->next;
	end   = stop;

	if (unlikely(ptr >= end))
		goto http_msg_ood;

	/* don't update output if hdr is NULL or if we're restarting */
	if (!hdr || restarting)
		skip_update = 1;

	switch (state)	{
	case H1_MSG_RQBEFORE:
	http_msg_rqbefore:
		if (likely(HTTP_IS_TOKEN(*ptr))) {
			/* we have a start of message, we may have skipped some
			 * heading CRLF. Skip them now.
			 */
			skip += ptr - start;
			start = ptr;

			sol = 0;
			sl.rq.m.ptr = ptr;
			hdr_count = 0;
			state = H1_MSG_RQMETH;
			goto http_msg_rqmeth;
		}

		if (unlikely(!HTTP_IS_CRLF(*ptr))) {
			state = H1_MSG_RQBEFORE;
			goto http_msg_invalid;
		}

		if (unlikely(*ptr == '\n'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqbefore, http_msg_ood, state, H1_MSG_RQBEFORE);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqbefore_cr, http_msg_ood, state, H1_MSG_RQBEFORE_CR);
		/* stop here */

	case H1_MSG_RQBEFORE_CR:
	http_msg_rqbefore_cr:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, H1_MSG_RQBEFORE_CR);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqbefore, http_msg_ood, state, H1_MSG_RQBEFORE);
		/* stop here */

	case H1_MSG_RQMETH:
	http_msg_rqmeth:
		if (likely(HTTP_IS_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqmeth, http_msg_ood, state, H1_MSG_RQMETH);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			sl.rq.m.len = ptr - sl.rq.m.ptr;
			sl.rq.meth = find_http_meth(start, sl.rq.m.len);
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqmeth_sp, http_msg_ood, state, H1_MSG_RQMETH_SP);
		}

		if (likely(HTTP_IS_CRLF(*ptr))) {
			/* HTTP 0.9 request */
			sl.rq.m.len = ptr - sl.rq.m.ptr;
			sl.rq.meth = find_http_meth(sl.rq.m.ptr, sl.rq.m.len);
		http_msg_req09_uri:
			sl.rq.u.ptr = ptr;
		http_msg_req09_uri_e:
			sl.rq.u.len = ptr - sl.rq.u.ptr;
		http_msg_req09_ver:
			sl.rq.v = ist2(ptr, 0);
			goto http_msg_rqline_eol;
		}
		state = H1_MSG_RQMETH;
		goto http_msg_invalid;

	case H1_MSG_RQMETH_SP:
	http_msg_rqmeth_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			sl.rq.u.ptr = ptr;
			goto http_msg_rquri;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqmeth_sp, http_msg_ood, state, H1_MSG_RQMETH_SP);
		/* so it's a CR/LF, meaning an HTTP 0.9 request */
		goto http_msg_req09_uri;

	case H1_MSG_RQURI:
	http_msg_rquri:
#ifdef HA_UNALIGNED_LE
		/* speedup: skip bytes not between 0x24 and 0x7e inclusive */
		while (ptr <= end - sizeof(int)) {
			if (is_char4_outside(*(uint *)ptr, 0x24, 0x7e))
				break;

			ptr += sizeof(int);
		}
#endif
		if (ptr >= end) {
			state = H1_MSG_RQURI;
			goto http_msg_ood;
		}
	http_msg_rquri2:
		if (likely((unsigned char)(*ptr - 33) <= 93)) { /* 33 to 126 included */
			if (*ptr == '#') {
				if (h1m->err_pos < -1) /* PR_O2_REQBUG_OK not set */
					goto invalid_char;
				if (h1m->err_pos == -1) /* PR_O2_REQBUG_OK set: just log */
					h1m->err_pos = ptr - start + skip;
			}
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rquri2, http_msg_ood, state, H1_MSG_RQURI);
		}

		if (likely(HTTP_IS_SPHT(*ptr))) {
			sl.rq.u.len = ptr - sl.rq.u.ptr;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rquri_sp, http_msg_ood, state, H1_MSG_RQURI_SP);
		}
		if (likely((unsigned char)*ptr >= 128)) {
			/* non-ASCII chars are forbidden unless option
			 * accept-unsafe-violations-in-http-request is enabled in the frontend.
			 * In any case, we capture the faulty char.
			 */
			if (h1m->err_pos < -1)
				goto invalid_char;
			if (h1m->err_pos == -1)
				h1m->err_pos = ptr - start + skip;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rquri, http_msg_ood, state, H1_MSG_RQURI);
		}

		if (likely(HTTP_IS_CRLF(*ptr))) {
			/* so it's a CR/LF, meaning an HTTP 0.9 request */
			goto http_msg_req09_uri_e;
		}

		/* OK forbidden chars, 0..31 or 127 */
	invalid_char:
		state = H1_MSG_RQURI;
		goto http_msg_invalid;

	case H1_MSG_RQURI_SP:
	http_msg_rquri_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			sl.rq.v.ptr = ptr;
			goto http_msg_rqver;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rquri_sp, http_msg_ood, state, H1_MSG_RQURI_SP);
		/* so it's a CR/LF, meaning an HTTP 0.9 request */
		goto http_msg_req09_ver;


	case H1_MSG_RQVER:
	http_msg_rqver:
		if (likely(HTTP_IS_VER_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqver, http_msg_ood, state, H1_MSG_RQVER);

		if (likely(HTTP_IS_CRLF(*ptr))) {
			sl.rq.v.len = ptr - sl.rq.v.ptr;
		http_msg_rqline_eol:
			/* We have seen the end of line. Note that we do not
			 * necessarily have the \n yet, but at least we know that we
			 * have EITHER \r OR \n, otherwise the request would not be
			 * complete. We can then record the request length and return
			 * to the caller which will be able to register it.
			 */

			if (likely(!skip_update)) {
				if ((sl.rq.v.len == 8) &&
				    (*(sl.rq.v.ptr + 5) > '1' ||
				     (*(sl.rq.v.ptr + 5) == '1' && *(sl.rq.v.ptr + 7) >= '1')))
					h1m->flags |= H1_MF_VER_11;

				if (unlikely(hdr_count >= hdr_num)) {
					state = H1_MSG_RQVER;
					goto http_output_full;
				}
				if (!(h1m->flags & H1_MF_NO_PHDR))
					http_set_hdr(&hdr[hdr_count++], ist(":method"), sl.rq.m);

				if (unlikely(hdr_count >= hdr_num)) {
					state = H1_MSG_RQVER;
					goto http_output_full;
				}
				if (!(h1m->flags & H1_MF_NO_PHDR))
					http_set_hdr(&hdr[hdr_count++], ist(":path"), sl.rq.u);
			}

			sol = ptr - start;
			if (likely(*ptr == '\r'))
				EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqline_end, http_msg_ood, state, H1_MSG_RQLINE_END);
			goto http_msg_rqline_end;
		}

		/* neither an HTTP_VER token nor a CRLF */
		state = H1_MSG_RQVER;
		goto http_msg_invalid;

	case H1_MSG_RQLINE_END:
	http_msg_rqline_end:
		/* check for HTTP/0.9 request : no version information
		 * available. sol must point to the first of CR or LF. However
		 * since we don't save these elements between calls, if we come
		 * here from a restart, we don't necessarily know. Thus in this
		 * case we simply start over.
		 */
		if (restarting)
			goto restart;

		if (unlikely(sl.rq.v.len == 0))
			goto http_msg_last_lf;

		EXPECT_LF_HERE(ptr, http_msg_invalid, state, H1_MSG_RQLINE_END);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_first, http_msg_ood, state, H1_MSG_HDR_FIRST);
		/* stop here */

	/*
	 * Common states below
	 */
	case H1_MSG_RPBEFORE:
	http_msg_rpbefore:
		if (likely(HTTP_IS_TOKEN(*ptr))) {
			/* we have a start of message, we may have skipped some
			 * heading CRLF. Skip them now.
			 */
			skip += ptr - start;
			start = ptr;

			sol = 0;
			sl.st.v.ptr = ptr;
			hdr_count = 0;
			state = H1_MSG_RPVER;
			goto http_msg_rpver;
		}

		if (unlikely(!HTTP_IS_CRLF(*ptr))) {
			state = H1_MSG_RPBEFORE;
			goto http_msg_invalid;
		}

		if (unlikely(*ptr == '\n'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpbefore, http_msg_ood, state, H1_MSG_RPBEFORE);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpbefore_cr, http_msg_ood, state, H1_MSG_RPBEFORE_CR);
		/* stop here */

	case H1_MSG_RPBEFORE_CR:
	http_msg_rpbefore_cr:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, H1_MSG_RPBEFORE_CR);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpbefore, http_msg_ood, state, H1_MSG_RPBEFORE);
		/* stop here */

	case H1_MSG_RPVER:
	http_msg_rpver:
		if (likely(HTTP_IS_VER_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpver, http_msg_ood, state, H1_MSG_RPVER);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			sl.st.v.len = ptr - sl.st.v.ptr;

			if ((sl.st.v.len == 8) &&
			    (*(sl.st.v.ptr + 5) > '1' ||
			     (*(sl.st.v.ptr + 5) == '1' && *(sl.st.v.ptr + 7) >= '1')))
				h1m->flags |= H1_MF_VER_11;

			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpver_sp, http_msg_ood, state, H1_MSG_RPVER_SP);
		}
		state = H1_MSG_RPVER;
		goto http_msg_invalid;

	case H1_MSG_RPVER_SP:
	http_msg_rpver_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			sl.st.status = 0;
			sl.st.c.ptr = ptr;
			goto http_msg_rpcode;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpver_sp, http_msg_ood, state, H1_MSG_RPVER_SP);
		/* so it's a CR/LF, this is invalid */
		state = H1_MSG_RPVER_SP;
		goto http_msg_invalid;

	case H1_MSG_RPCODE:
	http_msg_rpcode:
		if (likely(HTTP_IS_DIGIT(*ptr))) {
			sl.st.status = sl.st.status * 10 + *ptr - '0';
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpcode, http_msg_ood, state, H1_MSG_RPCODE);
		}

		if (unlikely(!HTTP_IS_LWS(*ptr))) {
			state = H1_MSG_RPCODE;
			goto http_msg_invalid;
		}

		if (likely(HTTP_IS_SPHT(*ptr))) {
			sl.st.c.len = ptr - sl.st.c.ptr;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpcode_sp, http_msg_ood, state, H1_MSG_RPCODE_SP);
		}

		/* so it's a CR/LF, so there is no reason phrase */
		sl.st.c.len = ptr - sl.st.c.ptr;

	http_msg_rsp_reason:
		sl.st.r = ist2(ptr, 0);
		goto http_msg_rpline_eol;

	case H1_MSG_RPCODE_SP:
	http_msg_rpcode_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			sl.st.r.ptr = ptr;
			goto http_msg_rpreason;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpcode_sp, http_msg_ood, state, H1_MSG_RPCODE_SP);
		/* so it's a CR/LF, so there is no reason phrase */
		goto http_msg_rsp_reason;

	case H1_MSG_RPREASON:
	http_msg_rpreason:
		if (likely(!HTTP_IS_CRLF(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpreason, http_msg_ood, state, H1_MSG_RPREASON);
		sl.st.r.len = ptr - sl.st.r.ptr;
	http_msg_rpline_eol:
		/* We have seen the end of line. Note that we do not
		 * necessarily have the \n yet, but at least we know that we
		 * have EITHER \r OR \n, otherwise the response would not be
		 * complete. We can then record the response length and return
		 * to the caller which will be able to register it.
		 */

		if (likely(!skip_update)) {
			if (unlikely(hdr_count >= hdr_num)) {
				state = H1_MSG_RPREASON;
				goto http_output_full;
			}
			if (!(h1m->flags & H1_MF_NO_PHDR))
				http_set_hdr(&hdr[hdr_count++], ist(":status"), sl.st.c);
		}

		sol = ptr - start;
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpline_end, http_msg_ood, state, H1_MSG_RPLINE_END);
		goto http_msg_rpline_end;

	case H1_MSG_RPLINE_END:
	http_msg_rpline_end:
		/* sol must point to the first of CR or LF. */
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, H1_MSG_RPLINE_END);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_first, http_msg_ood, state, H1_MSG_HDR_FIRST);
		/* stop here */

	case H1_MSG_HDR_FIRST:
	http_msg_hdr_first:
		sol = ptr - start;
		if (likely(!HTTP_IS_CRLF(*ptr))) {
			goto http_msg_hdr_name;
		}

		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_last_lf, http_msg_ood, state, H1_MSG_LAST_LF);
		goto http_msg_last_lf;

	case H1_MSG_HDR_NAME:
	http_msg_hdr_name:
		/* assumes sol points to the first char */
		if (likely(HTTP_IS_TOKEN(*ptr))) {
			if (!skip_update) {
				/* turn it to lower case if needed */
				if (isupper((unsigned char)*ptr) && h1m->flags & H1_MF_TOLOWER)
					*ptr = tolower((unsigned char)*ptr);
			}
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_name, http_msg_ood, state, H1_MSG_HDR_NAME);
		}

		if (likely(*ptr == ':')) {
			col = ptr - start;
			if (col <= sol) {
				state = H1_MSG_HDR_NAME;
				goto http_msg_invalid;
			}
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_sp, http_msg_ood, state, H1_MSG_HDR_L1_SP);
		}

		if (likely(h1m->err_pos < -1) || *ptr == '\n') {
			state = H1_MSG_HDR_NAME;
			goto http_msg_invalid;
		}

		if (h1m->err_pos == -1) /* capture the error pointer */
			h1m->err_pos = ptr - start + skip; /* >= 0 now */

		/* and we still accept this non-token character */
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_name, http_msg_ood, state, H1_MSG_HDR_NAME);

	case H1_MSG_HDR_L1_SP:
	http_msg_hdr_l1_sp:
		/* assumes sol points to the first char */
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_sp, http_msg_ood, state, H1_MSG_HDR_L1_SP);

		/* header value can be basically anything except CR/LF */
		sov = ptr - start;

		if (likely(!HTTP_IS_CRLF(*ptr))) {
			goto http_msg_hdr_val;
		}

		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_lf, http_msg_ood, state, H1_MSG_HDR_L1_LF);
		goto http_msg_hdr_l1_lf;

	case H1_MSG_HDR_L1_LF:
	http_msg_hdr_l1_lf:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, H1_MSG_HDR_L1_LF);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_lws, http_msg_ood, state, H1_MSG_HDR_L1_LWS);

	case H1_MSG_HDR_L1_LWS:
	http_msg_hdr_l1_lws:
		if (likely(HTTP_IS_SPHT(*ptr))) {
			if (!skip_update) {
				/* replace HT,CR,LF with spaces */
				for (; start + sov < ptr; sov++)
					start[sov] = ' ';
			}
			goto http_msg_hdr_l1_sp;
		}
		/* we had a header consisting only in spaces ! */
		eol = sov;
		goto http_msg_complete_header;

	case H1_MSG_HDR_VAL:
	http_msg_hdr_val:
		/* assumes sol points to the first char, and sov
		 * points to the first character of the value.
		 */

		/* speedup: we'll skip packs of 4 or 8 bytes not containing bytes 0x0D
		 * and lower. In fact since most of the time is spent in the loop, we
		 * also remove the sign bit test so that bytes 0x8e..0x0d break the
		 * loop, but we don't care since they're very rare in header values.
		 */
#ifdef HA_UNALIGNED_LE64
		while (ptr <= end - sizeof(long)) {
			if (is_char8_below_opt(*(ulong *)ptr, 0x0e))
				goto http_msg_hdr_val2;
			ptr += sizeof(long);
		}
#endif
#ifdef HA_UNALIGNED_LE
		while (ptr <= end - sizeof(int)) {
			if (is_char4_below_opt(*(uint *)ptr, 0x0e))
				goto http_msg_hdr_val2;
			ptr += sizeof(int);
		}
#endif
		if (ptr >= end) {
			state = H1_MSG_HDR_VAL;
			goto http_msg_ood;
		}
	http_msg_hdr_val2:
		if (likely(!*ptr)) {
			/* RFC9110 clarified that NUL is explicitly forbidden in header values
			 * (like CR and LF).
			 */
			if (h1m->err_pos < -1) { /* PR_O2_REQBUG_OK not set */
				state = H1_MSG_HDR_VAL;
				goto http_msg_invalid;
			}
			if (h1m->err_pos == -1) /* PR_O2_REQBUG_OK set: just log */
				h1m->err_pos = ptr - start + skip;
		}
		if (likely(!HTTP_IS_CRLF(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_val2, http_msg_ood, state, H1_MSG_HDR_VAL);

		eol = ptr - start;
		/* Note: we could also copy eol into ->eoh so that we have the
		 * real header end in case it ends with lots of LWS, but is this
		 * really needed ?
		 */
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l2_lf, http_msg_ood, state, H1_MSG_HDR_L2_LF);
		goto http_msg_hdr_l2_lf;

	case H1_MSG_HDR_L2_LF:
	http_msg_hdr_l2_lf:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, H1_MSG_HDR_L2_LF);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l2_lws, http_msg_ood, state, H1_MSG_HDR_L2_LWS);

	case H1_MSG_HDR_L2_LWS:
	http_msg_hdr_l2_lws:
		if (unlikely(HTTP_IS_SPHT(*ptr))) {
			if (!skip_update) {
				/* LWS: replace HT,CR,LF with spaces */
				for (; start + eol < ptr; eol++)
					start[eol] = ' ';
			}
			goto http_msg_hdr_val;
		}
	http_msg_complete_header:
		/*
		 * It was a new header, so the last one is finished. Assumes
		 * <sol> points to the first char of the name, <col> to the
		 * colon, <sov> points to the first character of the value and
		 * <eol> to the first CR or LF so we know how the line ends. We
		 * will trim spaces around the value. It's possible to do it by
		 * adjusting <eol> and <sov> which are no more used after this.
		 * We can add the header field to the list.
		 */
		if (likely(!skip_update)) {
			while (sov < eol && HTTP_IS_LWS(start[sov]))
				sov++;

			while (eol - 1 > sov && HTTP_IS_LWS(start[eol - 1]))
				eol--;


			n = ist2(start + sol, col - sol);
			v = ist2(start + sov, eol - sov);

			do {
				int ret;

				if (unlikely(hdr_count >= hdr_num)) {
					state = H1_MSG_HDR_L2_LWS;
					goto http_output_full;
				}

				if (isteqi(n, ist("transfer-encoding"))) {
					ret = h1_parse_xfer_enc_header(h1m, v);
					if (ret < 0) {
						/* For the response only, don't report error if PR_O2_RSPBUG_OK is set
						 * and the error can be hidden */
						if (ret == -2 || !(h1m->flags & H1_MF_RESP) || (h1m->err_pos < -1)) {
							state = H1_MSG_HDR_L2_LWS;
							ptr = v.ptr; /* Set ptr on the error */
							goto http_msg_invalid;
						}
						if (h1m->err_pos == -1)
							h1m->err_pos = ptr - start + skip;
					}
					else if (ret == 0) {
						/* skip it */
						break;
					}
				}
				else if (isteqi(n, ist("content-length"))) {
					ret = h1_parse_cont_len_header(h1m, &v);

					if (ret < 0) {
						state = H1_MSG_HDR_L2_LWS;
						ptr = v.ptr; /* Set ptr on the error */
						goto http_msg_invalid;
					}
					else if (ret == 0) {
						/* skip it */
						break;
					}
				}
				else if (isteqi(n, ist("connection"))) {
					h1_parse_connection_header(h1m, &v);
					if (!v.len) {
						/* skip it */
						break;
					}
				}
				else if (isteqi(n, ist("upgrade"))) {
					h1_parse_upgrade_header(h1m, v);
				}
				else if (!(h1m->flags & H1_MF_RESP) && isteqi(n, ist("host"))) {
					if (host_idx == -1)
						host_idx = hdr_count;
					else {
						if (!isteqi(v, hdr[host_idx].v)) {
							state = H1_MSG_HDR_L2_LWS;
							ptr = v.ptr; /* Set ptr on the error */
							goto http_msg_invalid;
						}
						/* if the same host, skip it */
						break;
					}
				}

				http_set_hdr(&hdr[hdr_count++], n, v);
			} while (0);
		}

		sol = ptr - start;

		if (likely(!HTTP_IS_CRLF(*ptr)))
			goto http_msg_hdr_name;

		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_last_lf, http_msg_ood, state, H1_MSG_LAST_LF);
		goto http_msg_last_lf;

	case H1_MSG_LAST_LF:
	http_msg_last_lf:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, H1_MSG_LAST_LF);
		ptr++;
		/* <ptr> now points to the first byte of payload. If needed sol
		 * still points to the first of either CR or LF of the empty
		 * line ending the headers block.
		 */
		if (likely(!skip_update)) {
			if (unlikely(hdr_count >= hdr_num)) {
				state = H1_MSG_LAST_LF;
				goto http_output_full;
			}
			http_set_hdr(&hdr[hdr_count++], ist2(start+sol, 0), ist(""));
		}

		/* reaching here we've parsed the whole message. We may detect
		 * that we were already continuing an interrupted parsing pass
		 * so we were silently looking for the end of message not
		 * updating anything before deciding to parse it fully at once.
		 * It's guaranteed that we won't match this test twice in a row
		 * since restarting will turn zero.
		 */
		if (restarting)
			goto restart;


		if (!(h1m->flags & (H1_MF_HDRS_ONLY|H1_MF_RESP))) {
			struct http_uri_parser parser = http_uri_parser_init(sl.rq.u);
			struct ist scheme, authority = IST_NULL;
			int ret;

			/* WT: gcc seems to see a path where sl.rq.u.ptr was used
			 * uninitialized, but it doesn't know that the function is
			 * called with initial states making this impossible.
			 */
			ALREADY_CHECKED(sl.rq.u.ptr);
			switch (parser.format) {
			case URI_PARSER_FORMAT_ASTERISK:
				/* We must take care "PRI * HTTP/2.0" is supported here. check for OTHER methods here is enough */
				if ((sl.rq.meth != HTTP_METH_OTHER && sl.rq.meth != HTTP_METH_OPTIONS) || istlen(sl.rq.u) != 1) {
					ptr = sl.rq.u.ptr; /* Set ptr on the error */
					goto http_msg_invalid;
				}
				break;

			case URI_PARSER_FORMAT_ABSPATH:
				if (sl.rq.meth == HTTP_METH_CONNECT) {
					ptr = sl.rq.u.ptr; /* Set ptr on the error */
					goto http_msg_invalid;
				}
				break;

			case URI_PARSER_FORMAT_ABSURI_OR_AUTHORITY:
				scheme = http_parse_scheme(&parser);
				if (!isttest(scheme)) { /* scheme not found: MUST be an authority */
					struct ist *host = NULL;

					if (sl.rq.meth != HTTP_METH_CONNECT) {
						ptr = sl.rq.u.ptr; /* Set ptr on the error */
						goto http_msg_invalid;
					}
					if (host_idx != -1)
						host = &hdr[host_idx].v;
					authority = http_parse_authority(&parser, 1);
					ret = h1_validate_connect_authority(scheme, authority, host);
					if (ret < 0) {
						if (h1m->err_pos < -1) {
							state = H1_MSG_LAST_LF;
							/* WT: gcc seems to see a path where sl.rq.u.ptr was used
							 * uninitialized, but it doesn't know that the function is
							 * called with initial states making this impossible.
							 */
							ALREADY_CHECKED(sl.rq.u.ptr);
							ptr = ((ret == -1) ? sl.rq.u.ptr : host->ptr); /* Set ptr on the error */
							goto http_msg_invalid;
						}
						if (h1m->err_pos == -1) /* capture the error pointer */
							h1m->err_pos = ((ret == -1) ? sl.rq.u.ptr : host->ptr) - start + skip; /* >= 0 now */
					}
				}
				else { /* Scheme found:  MUST be an absolute-URI */
					struct ist host = IST_NULL;

					if (sl.rq.meth == HTTP_METH_CONNECT) {
						ptr = sl.rq.u.ptr; /* Set ptr on the error */
						goto http_msg_invalid;
					}

					if (host_idx != -1)
						host = hdr[host_idx].v;
					authority = http_parse_authority(&parser, 1);
					/* For non-CONNECT method, the authority must match the host header value */
					if (isttest(host) && !isteqi(authority, host)) {
						ret = h1_validate_mismatch_authority(scheme, authority, host);
						if (ret < 0) {
							if (h1m->err_pos < -1) {
								state = H1_MSG_LAST_LF;
								ptr = host.ptr; /* Set ptr on the error */
								goto http_msg_invalid;
							}
							if (h1m->err_pos == -1) /* capture the error pointer */
								h1m->err_pos = v.ptr - start + skip; /* >= 0 now */
						}
					}
				}
				break;

			default:
				ptr = sl.rq.u.ptr; /* Set ptr on the error */
				goto http_msg_invalid;
			}
		}

		state = H1_MSG_DATA;
		if (h1m->flags & H1_MF_XFER_ENC) {
			if (h1m->flags & H1_MF_CLEN) {
				/* T-E + C-L: force close and remove C-L */
				if (!h1_do_not_close_on_insecure_t_e)
					h1m->flags |= H1_MF_CONN_CLO;

				h1m->flags &= ~H1_MF_CLEN;
				h1m->curr_len = h1m->body_len = 0;
				hdr_count = http_del_hdr(hdr, ist("content-length"));
			}
			else if (!(h1m->flags & H1_MF_VER_11)) {
				/* T-E + HTTP/1.0: force close */
				h1m->flags |= H1_MF_CONN_CLO;
			}

			if (h1m->flags & H1_MF_CHNK)
				state = H1_MSG_CHUNK_SIZE;
			else if (!(h1m->flags & H1_MF_RESP)) {
				/* cf RFC7230#3.3.3 : transfer-encoding in
				 * request without chunked encoding is invalid.
				 */
				goto http_msg_invalid;
			}
		}

		break;

	default:
		/* impossible states */
		goto http_msg_invalid;
	}

	/* Now we've left the headers state and are either in H1_MSG_DATA or
	 * H1_MSG_CHUNK_SIZE.
	 */

	if (slp && !skip_update)
		*slp = sl;

	h1m->state = state;
	h1m->next  = ptr - start + skip;
	return h1m->next;

 http_msg_ood:
	/* out of data at <ptr> during state <state> */
	if (slp && !skip_update)
		*slp = sl;

	h1m->state = state;
	h1m->next  = ptr - start + skip;
	return 0;

 http_msg_invalid:
	/* invalid message, error at <ptr> */
	if (slp && !skip_update)
		*slp = sl;

	h1m->err_state = h1m->state = state;
	h1m->err_pos   = h1m->next  = ptr - start + skip;
	return -1;

 http_output_full:
	/* no more room to store the current header, error at <ptr> */
	if (slp && !skip_update)
		*slp = sl;

	h1m->err_state = h1m->state = state;
	h1m->err_pos   = h1m->next  = ptr - start + skip;
	return -2;

 restart:
	h1m->flags &= H1_MF_RESTART_MASK;
	h1m->curr_len = h1m->body_len = h1m->next  = 0;
	if (h1m->flags & H1_MF_RESP)
		h1m->state = H1_MSG_RPBEFORE;
	else
		h1m->state = H1_MSG_RQBEFORE;
	goto try_again;
}

/* Generate a random key for a WebSocket Handshake in respect with rfc6455
 * The key is 128-bits long encoded as a base64 string in <key_out> parameter
 * (25 bytes long).
 */
void h1_generate_random_ws_input_key(char key_out[25])
{
	/* generate a random websocket key */
	const uint64_t rand1 = ha_random64(), rand2 = ha_random64();
	char key[16];

	memcpy(key, &rand1, 8);
	memcpy(&key[8], &rand2, 8);
	a2base64(key, 16, key_out, 25);
}

#define H1_WS_KEY_SUFFIX_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/*
 * Calculate the WebSocket handshake response key from <key_in>. Following the
 * rfc6455, <key_in> must be 24 bytes longs. The result is  stored in <key_out>
 * as a 29 bytes long string.
 */
void h1_calculate_ws_output_key(const char *key, char *result)
{
	blk_SHA_CTX sha1_ctx;
	char hash_in[60], hash_out[20];

	/* concatenate the key with a fixed suffix */
	memcpy(hash_in, key, 24);
	memcpy(&hash_in[24], H1_WS_KEY_SUFFIX_GUID, 36);

	/* sha1 the result */
	blk_SHA1_Init(&sha1_ctx);
	blk_SHA1_Update(&sha1_ctx, hash_in, 60);
	blk_SHA1_Final((unsigned char *)hash_out, &sha1_ctx);

	/* encode in base64 the hash */
	a2base64(hash_out, 20, result, 29);
}

/* config parser for global "h1-do-not-close-on-insecure-transfer-encoding" */
static int cfg_parse_h1_do_not_close_insecure_t_e(char **args, int section_type, struct proxy *curpx,
                                                const struct proxy *defpx, const char *file, int line,
                                                char **err)
{
	if (too_many_args(0, args, err, NULL))
		return -1;

	h1_do_not_close_on_insecure_t_e = 1;
	return 0;
}

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {{ }, {
	{ CFG_GLOBAL, "h1-do-not-close-on-insecure-transfer-encoding", cfg_parse_h1_do_not_close_insecure_t_e },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
