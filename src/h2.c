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

#include <stdint.h>
#include <common/config.h>
#include <common/h2.h>
#include <common/http-hdr.h>
#include <common/ist.h>


/* Prepare the request line into <*ptr> (stopping at <end>) from pseudo headers
 * stored in <phdr[]>. <fields> indicates what was found so far. This should be
 * called once at the detection of the first general header field or at the end
 * of the request if no general header field was found yet. Returns 0 on success
 * or a negative error code on failure.
 */
static int h2_prepare_h1_reqline(uint32_t fields, struct ist *phdr, char **ptr, char *end)
{
	char *out = *ptr;
	int uri_idx = H2_PHDR_IDX_PATH;

	if ((fields & H2_PHDR_FND_METH) && isteq(phdr[H2_PHDR_IDX_METH], ist("CONNECT"))) {
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
		// otherwise OK ; let's use the authority instead of the URI
		uri_idx = H2_PHDR_IDX_AUTH;
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

	/* 7540#8.1.2.3: :path must not be empty */
	if (!phdr[uri_idx].len)
		goto fail;

	if (out + phdr[H2_PHDR_IDX_METH].len + 1 + phdr[uri_idx].len + 11 > end) {
		/* too large */
		goto fail;
	}

	memcpy(out, phdr[H2_PHDR_IDX_METH].ptr, phdr[H2_PHDR_IDX_METH].len);
	out += phdr[H2_PHDR_IDX_METH].len;
	*(out++) = ' ';

	memcpy(out, phdr[uri_idx].ptr, phdr[uri_idx].len);
	out += phdr[uri_idx].len;
	memcpy(out, " HTTP/1.1\r\n", 11);
	out += 11;

	*ptr = out;
	return 0;
 fail:
	return -1;
}

/* Takes an H2 request present in the headers list <list> terminated by a name
 * being <NULL,0> and emits the equivalent HTTP/1.1 request according to the
 * rules documented in RFC7540 #8.1.2. The output contents are emitted in <out>
 * for a max of <osize> bytes, and the amount of bytes emitted is returned. In
 * case of error, a negative error code is returned.
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
 */
int h2_make_h1_request(struct http_hdr *list, char *out, int osize)
{
	struct ist phdr_val[H2_PHDR_NUM_ENTRIES];
	char *out_end = out + osize;
	uint32_t fields; /* bit mask of H2_PHDR_FND_* */
	uint32_t idx;
	int ck, lck; /* cookie index and last cookie index */
	int phdr;
	int ret;
	int i;

	lck = ck = -1; // no cookie for now
	fields = 0;
	for (idx = 0; list[idx].n.len != 0; idx++) {
		if (!list[idx].n.ptr) {
			/* this is an indexed pseudo-header */
			phdr = list[idx].n.len;
		}
		else {
			/* this can be any type of header */
			/* RFC7540#8.1.2: upper case not allowed in header field names */
			for (i = 0; i < list[idx].n.len; i++)
				if ((uint8_t)(list[idx].n.ptr[i] - 'A') < 'Z' - 'A')
					goto fail;

			phdr = h2_str_to_phdr(list[idx].n);
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
		if (!(fields & H2_PHDR_FND_NONE)) {
			/* no more pseudo-headers, time to build the request line */
			ret = h2_prepare_h1_reqline(fields, phdr_val, &out, out_end);
			if (ret != 0)
				goto leave;
			fields |= H2_PHDR_FND_NONE;
		}

		if (isteq(list[idx].n, ist("host")))
			fields |= H2_PHDR_FND_HOST;

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
			list[idx].n.len = -1;

			if (ck < 0)
				ck = idx;
			else
				list[lck].n.len = idx;

			lck = idx;
			continue;
		}

		if (out + list[idx].n.len + 2 + list[idx].v.len + 2 > out_end) {
			/* too large */
			goto fail;
		}

		/* copy "name: value" */
		memcpy(out, list[idx].n.ptr, list[idx].n.len);
		out += list[idx].n.len;
		*(out++) = ':';
		*(out++) = ' ';

		memcpy(out, list[idx].v.ptr, list[idx].v.len);
		out += list[idx].v.len;
		*(out++) = '\r';
		*(out++) = '\n';
	}

	/* RFC7540#8.1.2.1 mandates to reject response pseudo-headers (:status) */
	if (fields & H2_PHDR_FND_STAT)
		goto fail;

	/* Let's dump the request now if not yet emitted. */
	if (!(fields & H2_PHDR_FND_NONE)) {
		ret = h2_prepare_h1_reqline(fields, phdr_val, &out, out_end);
		if (ret != 0)
			goto leave;
	}

	/* complete with missing Host if needed */
	if ((fields & (H2_PHDR_FND_HOST|H2_PHDR_FND_AUTH)) == H2_PHDR_FND_AUTH) {
		/* missing Host field, use :authority instead */
		if (out + 6 + phdr_val[H2_PHDR_IDX_AUTH].len + 2 > out_end) {
			/* too large */
			goto fail;
		}

		memcpy(out, "host: ", 6);
		memcpy(out + 6, phdr_val[H2_PHDR_IDX_AUTH].ptr, phdr_val[H2_PHDR_IDX_AUTH].len);
		out += 6 + phdr_val[H2_PHDR_IDX_AUTH].len;
		*(out++) = '\r';
		*(out++) = '\n';
	}

	/* now we may have to build a cookie list. We'll dump the values of all
	 * visited headers.
	 */
	if (ck >= 0) {
		if (out + 8 > out_end) {
			/* too large */
			goto fail;
		}
		memcpy(out, "cookie: ", 8);
		out += 8;

		do {
			if (out + list[ck].v.len + 2 > out_end) {
				/* too large */
				goto fail;
			}
			memcpy(out, list[ck].v.ptr, list[ck].v.len);
			out += list[ck].v.len;
			ck = list[ck].n.len;

			if (ck >= 0) {
				*(out++) = ';';
				*(out++) = ' ';
			}
		} while (ck >= 0);

		if (out + 2 > out_end) {
			/* too large */
			goto fail;
		}
		*(out++) = '\r';
		*(out++) = '\n';
	}

	/* And finish */
	if (out + 2 > out_end) {
		/* too large */
		goto fail;
	}

	*(out++) = '\r';
	*(out++) = '\n';
	ret = out + osize - out_end;
 leave:
	return ret;

 fail:
	return -1;
}
