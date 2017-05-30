/*
 * HPACK decompressor (RFC7541)
 *
 * Copyright (C) 2014-2017 Willy Tarreau <willy@haproxy.org>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/hpack-dec.h>
#include <common/hpack-huff.h>
#include <common/hpack-tbl.h>
#include <common/ist.h>

#include <types/global.h>

/* indexes of most important pseudo headers can be simplified to an almost
 * linear array by dividing the index by 2 for all values from 1 to 9, and
 * caping to 4 for values up to 14 ; thus it fits in a single 24-bit array
 * shifted by 3 times the index value/2, or a 32-bit array shifted by 4x.
 * Don't change these values, they are assumed by get_pseudo_hdr(). There
 * is an entry for the Host header field which is not a pseudo-header but
 * need to be tracked as we should only use :authority if it's absent.
 */
enum {
	PHDR_IDX_NONE = 0,
	PHDR_IDX_AUTH = 1, /* :authority = 1     */
	PHDR_IDX_METH = 2, /* :method    = 2..3  */
	PHDR_IDX_PATH = 3, /* :path      = 4..5  */
	PHDR_IDX_SCHM = 4, /* :scheme    = 6..7  */
	PHDR_IDX_STAT = 5, /* :status    = 8..14 */
	PHDR_IDX_HOST = 6, /* Host, never returned, just a place-holder */
	PHDR_NUM_ENTRIES   /* must be last */
};

/* bit fields indicating the pseudo-headers found. It also covers the HOST
 * header field ad well as any non-pseudo-header field (NONE).
 */
enum {
	PHDR_FND_NONE = 1 << PHDR_IDX_NONE, /* found a regular header */
	PHDR_FND_AUTH = 1 << PHDR_IDX_AUTH,
	PHDR_FND_METH = 1 << PHDR_IDX_METH,
	PHDR_FND_PATH = 1 << PHDR_IDX_PATH,
	PHDR_FND_SCHM = 1 << PHDR_IDX_SCHM,
	PHDR_FND_STAT = 1 << PHDR_IDX_STAT,
	PHDR_FND_HOST = 1 << PHDR_IDX_HOST,
};

static const struct ist phdr_names[PHDR_NUM_ENTRIES] = {
	{ "", 0},
	{ ":authority", 10},
	{ ":method", 7},
	{ ":path", 5},
	{ ":scheme", 7},
	{ ":status", 7},
	{ "Host", 4},
};


#if defined(DEBUG_HPACK)
#define hpack_debug_printf printf
#else
#define hpack_debug_printf(...) do { } while (0)
#endif

/* reads a varint from <raw>'s lowest <b> bits and <len> bytes max (raw included).
 * returns the 32-bit value on success after updating raw_in and len_in. Forces
 * len_in to (uint32_t)-1 on truncated input.
 */
static uint32_t get_var_int(const uint8_t **raw_in, uint32_t *len_in, int b)
{
	uint32_t ret = 0;
	int len = *len_in;
	const uint8_t *raw = *raw_in;
	uint8_t shift = 0;

	len--;
	ret = *(raw++) & ((1 << b) - 1);
	if (ret != (uint32_t)((1 << b) - 1))
		goto end;

	while (1) {
		if (!len)
			goto too_short;
		if (!(*raw & 128))
			break;
		ret += ((uint32_t)(*raw++) & 127) << shift;
		shift += 7;
		len--;
	}

	/* last 7 bits */
	if (!len)
		goto too_short;
	len--;
	ret += ((uint32_t)(*raw++) & 127) << shift;

 end:
	*raw_in = raw;
	*len_in = len;
	return ret;

 too_short:
	*len_in = (uint32_t)-1;
	return 0;
}

/* returns the pseudo-header <str> corresponds to among PHDR_IDX_*, 0 if not a
 * pseudo-header, or -1 if not a valid pseudo-header.
 */
static inline int hpack_str_to_phdr(const struct ist str)
{
	if (*str.ptr == ':') {
		if (isteq(str, ist(":path")))           return PHDR_IDX_PATH;
		else if (isteq(str, ist(":method")))    return PHDR_IDX_METH;
		else if (isteq(str, ist(":scheme")))    return PHDR_IDX_SCHM;
		else if (isteq(str, ist(":status")))    return PHDR_IDX_STAT;
		else if (isteq(str, ist(":authority"))) return PHDR_IDX_AUTH;

		/* all other names starting with ':' */
		return -1;
	}

	/* not a pseudo header */
	return 0;
}

/* returns the pseudo-header <idx> corresponds to among PHDR_IDX_*, or 0 the
 * header's string has to be parsed. The magic value at the end comes from
 * PHDR_IDX_* values.
 */
static inline int hpack_idx_to_phdr(uint32_t idx)
{
	if (idx > 14)
		return 0;

	idx >>= 1;
	idx <<= 2;
	return (0x55554321U >> idx) & 0xF;
}

/* Prepare the request line into <*ptr> (stopping at <end>) from pseudo headers
 * stored in <phdr[]>. <fields> indicates what was found so far. This should be
 * called once at the detection of the first general header field or at the end
 * of the request if no general header field was found yet. Returns 0 on success
 * or a negative HPACK_ERR_* error code.
 */
static int hpack_prepare_reqline(uint32_t fields, struct ist *phdr, char **ptr, char *end)
{
	char *out = *ptr;
	int uri_idx = PHDR_IDX_PATH;

	if ((fields & PHDR_FND_METH) && isteq(phdr[PHDR_IDX_METH], ist("CONNECT"))) {
		/* RFC 7540 #8.2.6 regarding CONNECT: ":scheme" and ":path"
		 * MUST be omitted ; ":authority" contains the host and port
		 * to connect to.
		 */
		if (fields & PHDR_FND_SCHM) {
			hpack_debug_printf("--:scheme not allowed with CONNECT--\n");
			return -HPACK_ERR_SCHEME_NOT_ALLOWED;
		}
		else if (fields & PHDR_FND_PATH) {
			hpack_debug_printf("--:path not allowed with CONNECT--\n");
			return -HPACK_ERR_PATH_NOT_ALLOWED;
		}
		else if (!(fields & PHDR_FND_AUTH)) {
			hpack_debug_printf("--CONNECT: missing :authority--\n");
			return -HPACK_ERR_MISSING_AUTHORITY;
		}
		// otherwise OK ; let's use the authority instead of the URI
		uri_idx = PHDR_IDX_AUTH;
	}
	else if ((fields & (PHDR_FND_METH|PHDR_FND_SCHM|PHDR_FND_PATH)) !=
	         (PHDR_FND_METH|PHDR_FND_SCHM|PHDR_FND_PATH)) {
		/* RFC 7540 #8.1.2.3 : all requests MUST include exactly one
		 * valid value for the ":method", ":scheme" and ":path" phdr
		 * unless it is a CONNECT request.
		 */
		if (!(fields & PHDR_FND_METH)) {
			hpack_debug_printf("--missing :method--\n");
			return -HPACK_ERR_MISSING_METHOD;
		}
		else if (!(fields & PHDR_FND_SCHM)) {
			hpack_debug_printf("--missing :scheme--\n");
			return -HPACK_ERR_MISSING_SCHEME;
		}
		else {
			hpack_debug_printf("--missing :path--\n");
			return -HPACK_ERR_MISSING_PATH;
		}
	}

	hpack_debug_printf("%s ", istpad(trash.str, phdr[PHDR_IDX_METH]).ptr);
	hpack_debug_printf("%s HTTP/1.1\r\n", istpad(trash.str, phdr[uri_idx]).ptr);

	if (out + phdr[uri_idx].len + 1 + phdr[uri_idx].len + 11 > end) {
		hpack_debug_printf("too large request\n");
		return -HPACK_ERR_TOO_LARGE;
	}

	memcpy(out, phdr[PHDR_IDX_METH].ptr, phdr[PHDR_IDX_METH].len);
	out += phdr[PHDR_IDX_METH].len;
	*(out++) = ' ';

	memcpy(out, phdr[uri_idx].ptr, phdr[uri_idx].len);
	out += phdr[uri_idx].len;
	memcpy(out, " HTTP/1.1\r\n", 11);
	out += 11;

	*ptr = out;
	return 0;
}

/* only takes care of frames affecting the dynamic table for now and directly
 * prints the output on stdout. Writes the output to <out> for at most <osize>
 * bytes. Returns the number of bytes written, or < 0 on error, in which case
 * the value is the negative of HPACK_ERR_*.
 */
int hpack_decode_frame(struct hpack_dht *dht, const uint8_t *raw, uint32_t len, char *out, int osize)
{
	uint32_t idx;
	uint32_t nlen;
	uint32_t vlen;
	uint8_t huff;
	uint32_t fields; /* bit mask of PHDR_FND_* */
	struct ist name;
	struct ist value;
	struct ist phdr_str[PHDR_NUM_ENTRIES];
	struct chunk *phdr_trash = get_trash_chunk();
	struct chunk *tmp = get_trash_chunk();
	char *phdr_next = phdr_trash->str;
	int phdr;
	int must_index;
	int ret;
	char *out_end = out + osize;

	fields = 0;
	while (len) {
		int code __attribute__((unused)) = *raw; /* first byte, only for debugging */

		must_index = 0;
		if (*raw >= 0x80) {
			/* indexed header field */
			if (*raw == 0x80) {
				hpack_debug_printf("unhandled code 0x%02x (raw=%p, len=%d)\n", *raw, raw, len);
				ret = -HPACK_ERR_UNKNOWN_OPCODE;
				goto leave;
			}

			hpack_debug_printf("%02x: p14: indexed header field : ", code);

			idx = get_var_int(&raw, &len, 7);
			if (len == (uint32_t)-1) { // truncated
				ret = -HPACK_ERR_TRUNCATED;
				goto leave;
			}

			value = hpack_idx_to_value(dht, idx);
			phdr = hpack_idx_to_phdr(idx);
			if (phdr > 0)
				goto phdr_by_idx;

			name = hpack_idx_to_name(dht, idx);
			phdr = hpack_str_to_phdr(name);
			if (phdr > 0)
				goto phdr_by_idx;
			if (phdr == 0)
				goto regular_hdr;

			/* invalid pseudo header -- should never happen here */
			goto bad_phdr;
		}
		else if (*raw >= 0x20 && *raw <= 0x3f) {
			/* max dyn table size change */
			idx = get_var_int(&raw, &len, 5);
			if (len == (uint32_t)-1) { // truncated
				ret = -HPACK_ERR_TRUNCATED;
				goto leave;
			}
			continue;
		}
		else if (!(*raw & (*raw - 0x10))) {
			/* 0x00, 0x10, and 0x40 (0x20 and 0x80 were already handled above) */

			/* literal header field without/never/with incremental indexing -- literal name */
			if (*raw == 0x00)
				hpack_debug_printf("%02x: p17: literal without indexing : ", code);
			else if (*raw == 0x10)
				hpack_debug_printf("%02x: p18: literal never indexed : ", code);
			else if (*raw == 0x40)
				hpack_debug_printf("%02x: p16: literal with indexing : ", code);

			if (*raw == 0x40)
				must_index = 1;

			raw++; len--;

			/* retrieve name */
			if (!len) { // truncated
				ret = -HPACK_ERR_TRUNCATED;
				goto leave;
			}

			huff = *raw & 0x80;
			nlen = get_var_int(&raw, &len, 7);
			if (len == (uint32_t)-1 || len < nlen) { // truncated
				ret = -HPACK_ERR_TRUNCATED;
				goto leave;
			}

			name = ist2(raw, nlen);

			raw += nlen;
			len -= nlen;
			chunk_reset(tmp);

			if (huff) {
				nlen = huff_dec((const uint8_t *)name.ptr, name.len, tmp->str, tmp->size);
				if (nlen == (uint32_t)-1) {
					hpack_debug_printf("2: can't decode huffman.\n");
					ret = -HPACK_ERR_HUFFMAN;
					goto leave;
				}
				tmp->len += nlen; // make room for the value
				name = ist2(tmp->str, nlen);
			}

			/* retrieve value */
			if (!len) { // truncated
				ret = -HPACK_ERR_TRUNCATED;
				goto leave;
			}

			huff = *raw & 0x80;
			vlen = get_var_int(&raw, &len, 7);
			if (len == (uint32_t)-1 || len < vlen) { // truncated
				ret = -HPACK_ERR_TRUNCATED;
				goto leave;
			}

			value = ist2(raw, vlen);
			raw += vlen;
			len -= vlen;

			if (huff) {
				char *vtrash = chunk_newstr(tmp);
				if (!vtrash) {
					ret = HPACK_ERR_TOO_LARGE;
					goto leave;
				}

				vlen = huff_dec((const uint8_t *)value.ptr, value.len, vtrash, tmp->str + tmp->size - vtrash);
				if (vlen == (uint32_t)-1) {
					hpack_debug_printf("3: can't decode huffman.\n");
					ret = -HPACK_ERR_HUFFMAN;
					goto leave;
				}
				value = ist2(vtrash, vlen);
			}

			phdr = hpack_str_to_phdr(name);
			if (phdr > 0)
				goto phdr_by_idx;
			if (phdr == 0)
				goto regular_hdr;

			/* invalid pseudo header -- should never happen here */
			goto bad_phdr;
		}
		else {
			/* 0x01..0x0f : literal header field without indexing -- indexed name */
			/* 0x11..0x1f : literal header field never indexed -- indexed name */
			/* 0x41..0x7f : literal header field with incremental indexing -- indexed name */

			if (*raw <= 0x0f)
				hpack_debug_printf("%02x: p16: literal without indexing -- indexed name : ", code);
			else if (*raw >= 0x41)
				hpack_debug_printf("%02x: p15: literal with indexing -- indexed name : ", code);
			else
				hpack_debug_printf("%02x: p16: literal never indexed -- indexed name : ", code);

			/* retrieve name index */
			if (*raw >= 0x41) {
				must_index = 1;
				idx = get_var_int(&raw, &len, 6);
			}
			else
				idx = get_var_int(&raw, &len, 4);

			if (len == (uint32_t)-1 || !len) { // truncated
				ret = -HPACK_ERR_TRUNCATED;
				goto leave;
			}

			/* retrieve value */
			huff = *raw & 0x80;
			vlen = get_var_int(&raw, &len, 7);
			if (len == (uint32_t)-1 || len < vlen) { // truncated
				ret = -HPACK_ERR_TRUNCATED;
				goto leave;
			}

			value = ist2(raw, vlen);
			raw += vlen;
			len -= vlen;

			if (huff) {
				vlen = huff_dec((const uint8_t *)value.ptr, value.len, tmp->str, tmp->size);
				if (vlen == (uint32_t)-1) {
					hpack_debug_printf("1: can't decode huffman.\n");
					ret = -HPACK_ERR_HUFFMAN;
					goto leave;
				}
				value = ist2(tmp->str, vlen);
			}

			phdr = hpack_idx_to_phdr(idx);
			if (phdr > 0)
				goto phdr_by_idx;

			name = hpack_idx_to_name(dht, idx);
			phdr = hpack_str_to_phdr(name);
			if (phdr > 0)
				goto phdr_by_idx;
			if (phdr == 0)
				goto regular_hdr;

			/* invalid pseudo header -- should never happen here */
			goto bad_phdr;
		}

	phdr_by_idx:
		/* insert a pseudo header by its index (in phdr) and value (in value) */
		if (fields & ((1 << phdr) | PHDR_FND_NONE)) {
			if (fields & PHDR_FND_NONE) {
				hpack_debug_printf("%02x: pseudo header field after regular headers : %d\n", code, phdr);
				ret = -HPACK_ERR_MISPLACED_PHDR;
				goto leave;
			}
			else {
				hpack_debug_printf("%02x: repeated pseudo header field %d\n", code, phdr);
				ret = -HPACK_ERR_DUPLICATE_PHDR;
				goto leave;
			}
		}
		fields |= 1 << phdr;

		if (phdr_next + value.len > phdr_trash->str + phdr_trash->size) {
			hpack_debug_printf("too large request\n");
			ret = -HPACK_ERR_TOO_LARGE;
			goto leave;
		}

		memcpy(phdr_next, value.ptr, value.len);
		phdr_str[phdr].ptr = phdr_next;
		phdr_str[phdr].len = value.len;
		phdr_next += value.len;

		if (must_index && hpack_dht_insert(dht, phdr_names[phdr], value) < 0) {
			hpack_debug_printf("failed to find some room in the dynamic table\n");
			ret = -HPACK_ERR_DHT_INSERT_FAIL;
			goto leave;
		}

		hpack_debug_printf("phdr=%d(\e[1;34m%s\e[0m) ptr=%d len=%d (\e[1;35m%s\e[0m) [idx=%d, used=%d]\n",
		       phdr, phdr_names[phdr].ptr,
		       (int)(phdr_str[phdr].ptr - phdr_trash->str), (int)phdr_str[phdr].len,
		       istpad(trash.str, phdr_str[phdr]).ptr, must_index, dht->used);
		continue;

	regular_hdr:
		/* regular header field in (name,value) */

		if (!(fields & PHDR_FND_NONE)) {
			hpack_debug_printf("--end of pseudo-headers--\n");
			ret = hpack_prepare_reqline(fields, phdr_str, &out, out_end);
			if (ret)
				goto leave;
			fields |= PHDR_FND_NONE;
		}

		if (must_index && hpack_dht_insert(dht, name, value) < 0) {
			hpack_debug_printf("failed to find some room in the dynamic table\n");
			ret = -HPACK_ERR_DHT_INSERT_FAIL;
			goto leave;
		}

		if (isteq(name, ist("host")))
			fields |= PHDR_FND_HOST;

		if (out + name.len + 2 + value.len + 2 > out_end) {
			hpack_debug_printf("too large request\n");
			ret = -HPACK_ERR_TOO_LARGE;
			goto leave;
		}

		memcpy(out, name.ptr, name.len);
		out += name.len;
		*(out++) = ':';
		*(out++) = ' ';

		memcpy(out, value.ptr, value.len);
		out += value.len;
		*(out++) = '\r';
		*(out++) = '\n';

		hpack_debug_printf("\e[1;34m%s\e[0m: ",
		                   istpad(trash.str, name).ptr);

		hpack_debug_printf("\e[1;35m%s\e[0m [idx=%d, used=%d]\n",
		                   istpad(trash.str, value).ptr,
		                   must_index, dht->used);

		continue;

	bad_phdr:
		hpack_debug_printf("%02x: invalid pseudo header field %d\n", code, phdr);
		ret = -HPACK_ERR_INVALID_PHDR;
		goto leave;
	}

	/* Let's dump the request now if not yet emitted. */
	if (!(fields & PHDR_FND_NONE)) {
		ret = hpack_prepare_reqline(fields, phdr_str, &out, out_end);
		if (ret)
			goto leave;
	}

	/* complete with missing Host if needed */
	if ((fields & (PHDR_FND_HOST|PHDR_FND_AUTH)) == PHDR_FND_AUTH) {
		/* missing Host field, use :authority instead */
		hpack_debug_printf("\e[1;34m%s\e[0m: \e[1;35m%s\e[0m\n", "Host", istpad(trash.str, phdr_str[PHDR_IDX_AUTH]).ptr);

		if (out + 6 + phdr_str[PHDR_IDX_AUTH].len + 2 > out_end) {
			hpack_debug_printf("too large request\n");
			ret = -HPACK_ERR_TOO_LARGE;
			goto leave;
		}

		memcpy(out, "host: ", 6);
		memcpy(out + 6, phdr_str[PHDR_IDX_AUTH].ptr, phdr_str[PHDR_IDX_AUTH].len);
		out += 6 + phdr_str[PHDR_IDX_AUTH].len;
		*(out++) = '\r';
		*(out++) = '\n';
	}

	/* And finish */
	if (out + 2 > out_end) {
		hpack_debug_printf("too large request\n");
		ret = -HPACK_ERR_TOO_LARGE;
		goto leave;
	}

	*(out++) = '\r';
	*(out++) = '\n';

	hpack_debug_printf("done : %d bytes emitted\n", (int)(out + osize - out_end));

	ret = out + osize - out_end;
 leave:
	return ret;
}
