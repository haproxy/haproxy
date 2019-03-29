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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/standard.h>
#include <common/hpack-dec.h>
#include <common/hpack-huff.h>
#include <common/hpack-tbl.h>
#include <common/chunk.h>
#include <common/h2.h>
#include <common/ist.h>

#include <types/global.h>


#if defined(DEBUG_HPACK)
#define hpack_debug_printf printf
#define hpack_debug_hexdump debug_hexdump
#else
#define hpack_debug_printf(...) do { } while (0)
#define hpack_debug_hexdump(...) do { } while (0)
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

/* returns the pseudo-header <idx> corresponds to among the following values :
 *   -  0 = unknown, the header's string needs to be used instead
 *   -  1 = ":authority"
 *   -  2 = ":method"
 *   -  3 = ":path"
 *   -  4 = ":scheme"
 *   -  5 = ":status"
 */
static inline int hpack_idx_to_phdr(uint32_t idx)
{
	if (idx > 14)
		return 0;

	idx >>= 1;
	idx <<= 2;
	return (0x55554321U >> idx) & 0xF;
}

/* If <idx> designates a static header, returns <in>. Otherwise allocates some
 * room from chunk <store> to duplicate <in> into it and returns the string
 * allocated there. In case of allocation failure, returns a string whose
 * pointer is NULL.
 */
static inline struct ist hpack_alloc_string(struct buffer *store, uint32_t idx,
					    struct ist in)
{
	struct ist out;

	if (idx < HPACK_SHT_SIZE)
		return in;

	out.len = in.len;
	out.ptr = chunk_newstr(store);
	if (unlikely(!out.ptr))
		return out;

	if (unlikely(store->data + out.len > store->size)) {
		out.ptr = NULL;
		return out;
	}

	store->data += out.len;
	memcpy(out.ptr, in.ptr, out.len);
	return out;
}

/* decode an HPACK frame starting at <raw> for <len> bytes, using the dynamic
 * headers table <dht>, produces the output into list <list> of <list_size>
 * entries max, and uses pre-allocated buffer <tmp> for temporary storage (some
 * list elements will point to it). Some <list> name entries may be made of a
 * NULL pointer and a len, in which case they will designate a pseudo header
 * index according to the values returned by hpack_idx_to_phdr() above. The
 * number of <list> entries used is returned on success, or <0 on failure, with
 * the opposite one of the HPACK_ERR_* codes. A last element is always zeroed
 * and is not counted in the number of returned entries. This way the caller
 * can use list[].n.len == 0 as a marker for the end of list.
 */
int hpack_decode_frame(struct hpack_dht *dht, const uint8_t *raw, uint32_t len,
                       struct http_hdr *list, int list_size,
                       struct buffer *tmp)
{
	uint32_t idx;
	uint32_t nlen;
	uint32_t vlen;
	uint8_t huff;
	struct ist name;
	struct ist value;
	int must_index;
	int ret;

	hpack_debug_hexdump(stderr, "[HPACK-DEC] ", (const char *)raw, 0, len);

	chunk_reset(tmp);
	ret = 0;
	while (len) {
		int __maybe_unused code = *raw; /* first byte, only for debugging */

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
				hpack_debug_printf("##ERR@%d##\n", __LINE__);
				ret = -HPACK_ERR_TRUNCATED;
				goto leave;
			}

			hpack_debug_printf(" idx=%u ", idx);

			if (!hpack_valid_idx(dht, idx)) {
				hpack_debug_printf("##ERR@%d##\n", __LINE__);
				ret = -HPACK_ERR_TOO_LARGE;
				goto leave;
			}

			value = hpack_alloc_string(tmp, idx, hpack_idx_to_value(dht, idx));
			if (!value.ptr) {
				hpack_debug_printf("##ERR@%d##\n", __LINE__);
				ret = -HPACK_ERR_TOO_LARGE;
				goto leave;
			}

			/* here we don't index so we can always keep the pseudo header number */
			name = ist2(NULL, hpack_idx_to_phdr(idx));

			if (!name.len) {
				name = hpack_alloc_string(tmp, idx, hpack_idx_to_name(dht, idx));
				if (!name.ptr) {
					hpack_debug_printf("##ERR@%d##\n", __LINE__);
					ret = -HPACK_ERR_TOO_LARGE;
					goto leave;
				}
			}
			/* <name> and <value> are now set and point to stable values */
		}
		else if (*raw >= 0x20 && *raw <= 0x3f) {
			/* max dyn table size change */
			hpack_debug_printf("%02x: p18: dynamic table size update : ", code);

			if (ret) {
				/* 7541#4.2.1 : DHT size update must only be at the beginning */
				hpack_debug_printf("##ERR@%d##\n", __LINE__);
				ret = -HPACK_ERR_TOO_LARGE;
				goto leave;
			}

			idx = get_var_int(&raw, &len, 5);
			if (len == (uint32_t)-1) { // truncated
				hpack_debug_printf("##ERR@%d##\n", __LINE__);
				ret = -HPACK_ERR_TRUNCATED;
				goto leave;
			}
			hpack_debug_printf(" new len=%u\n", idx);

			if (idx > dht->size) {
				hpack_debug_printf("##ERR@%d##\n", __LINE__);
				ret = -HPACK_ERR_INVALID_ARGUMENT;
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
				hpack_debug_printf("##ERR@%d##\n", __LINE__);
				ret = -HPACK_ERR_TRUNCATED;
				goto leave;
			}

			huff = *raw & 0x80;
			nlen = get_var_int(&raw, &len, 7);
			if (len == (uint32_t)-1 || len < nlen) { // truncated
				hpack_debug_printf("##ERR@%d## (truncated): nlen=%d len=%d\n",
				                   __LINE__, (int)nlen, (int)len);
				ret = -HPACK_ERR_TRUNCATED;
				goto leave;
			}

			name = ist2(raw, nlen);

			raw += nlen;
			len -= nlen;

			if (huff) {
				char *ntrash = chunk_newstr(tmp);
				if (!ntrash) {
					hpack_debug_printf("##ERR@%d##\n", __LINE__);
					ret = -HPACK_ERR_TOO_LARGE;
					goto leave;
				}

				nlen = huff_dec((const uint8_t *)name.ptr, name.len, ntrash,
						tmp->size - tmp->data);
				if (nlen == (uint32_t)-1) {
					hpack_debug_printf("2: can't decode huffman.\n");
					ret = -HPACK_ERR_HUFFMAN;
					goto leave;
				}
				hpack_debug_printf(" [name huff %d->%d] ", (int)name.len, (int)nlen);

				tmp->data += nlen; // make room for the value
				name = ist2(ntrash, nlen);
			}

			/* retrieve value */
			if (!len) { // truncated
				hpack_debug_printf("##ERR@%d##\n", __LINE__);
				ret = -HPACK_ERR_TRUNCATED;
				goto leave;
			}

			huff = *raw & 0x80;
			vlen = get_var_int(&raw, &len, 7);
			if (len == (uint32_t)-1 || len < vlen) { // truncated
				hpack_debug_printf("##ERR@%d## : vlen=%d len=%d\n",
				                   __LINE__, (int)vlen, (int)len);
				ret = -HPACK_ERR_TRUNCATED;
				goto leave;
			}

			value = ist2(raw, vlen);
			raw += vlen;
			len -= vlen;

			if (huff) {
				char *vtrash = chunk_newstr(tmp);
				if (!vtrash) {
					hpack_debug_printf("##ERR@%d##\n", __LINE__);
					ret = -HPACK_ERR_TOO_LARGE;
					goto leave;
				}

				vlen = huff_dec((const uint8_t *)value.ptr, value.len, vtrash,
						tmp->size - tmp->data);
				if (vlen == (uint32_t)-1) {
					hpack_debug_printf("3: can't decode huffman.\n");
					ret = -HPACK_ERR_HUFFMAN;
					goto leave;
				}
				hpack_debug_printf(" [value huff %d->%d] ", (int)value.len, (int)vlen);

				tmp->data += vlen; // make room for the value
				value = ist2(vtrash, vlen);
			}

			/* <name> and <value> are correctly filled here */
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

			hpack_debug_printf(" idx=%u ", idx);

			if (len == (uint32_t)-1 || !len) { // truncated
				hpack_debug_printf("##ERR@%d##\n", __LINE__);
				ret = -HPACK_ERR_TRUNCATED;
				goto leave;
			}

			if (!hpack_valid_idx(dht, idx)) {
				hpack_debug_printf("##ERR@%d##\n", __LINE__);
				ret = -HPACK_ERR_TOO_LARGE;
				goto leave;
			}

			/* retrieve value */
			huff = *raw & 0x80;
			vlen = get_var_int(&raw, &len, 7);
			if (len == (uint32_t)-1 || len < vlen) { // truncated
				hpack_debug_printf("##ERR@%d##\n", __LINE__);
				ret = -HPACK_ERR_TRUNCATED;
				goto leave;
			}

			value = ist2(raw, vlen);
			raw += vlen;
			len -= vlen;

			if (huff) {
				char *vtrash = chunk_newstr(tmp);
				if (!vtrash) {
					hpack_debug_printf("##ERR@%d##\n", __LINE__);
					ret = -HPACK_ERR_TOO_LARGE;
					goto leave;
				}

				vlen = huff_dec((const uint8_t *)value.ptr, value.len, vtrash,
						tmp->size - tmp->data);
				if (vlen == (uint32_t)-1) {
					hpack_debug_printf("##ERR@%d## can't decode huffman : ilen=%d osize=%d\n",
					                   __LINE__, (int)value.len,
					                   (int)(tmp->size - tmp->data));
					hpack_debug_hexdump(stderr, "[HUFFMAN] ", value.ptr, 0, value.len);
					ret = -HPACK_ERR_HUFFMAN;
					goto leave;
				}
				tmp->data += vlen; // make room for the value
				value = ist2(vtrash, vlen);
			}

			name = ist2(NULL, 0);
			if (!must_index)
				name.len = hpack_idx_to_phdr(idx);

			if (!name.len) {
				name = hpack_alloc_string(tmp, idx, hpack_idx_to_name(dht, idx));
				if (!name.ptr) {
					hpack_debug_printf("##ERR@%d##\n", __LINE__);
					ret = -HPACK_ERR_TOO_LARGE;
					goto leave;
				}
			}
			/* <name> and <value> are correctly filled here */
		}

		/* here's what we have here :
		 *   - name.len > 0
		 *   - value is filled with either const data or data allocated from tmp
		 *   - name.ptr == NULL && !must_index : known pseudo-header #name.len
		 *   - name.ptr != NULL || must_index : general header, unknown pseudo-header or index needed
		 */
		if (ret >= list_size) {
			hpack_debug_printf("##ERR@%d##\n", __LINE__);
			ret = -HPACK_ERR_TOO_LARGE;
			goto leave;
		}

		list[ret].n = name;
		list[ret].v = value;
		ret++;

		if (must_index && hpack_dht_insert(dht, name, value) < 0) {
			hpack_debug_printf("failed to find some room in the dynamic table\n");
			ret = -HPACK_ERR_DHT_INSERT_FAIL;
			goto leave;
		}

		hpack_debug_printf("\e[1;34m%s\e[0m: ",
				   name.ptr ? istpad(trash.area, name).ptr : h2_phdr_to_str(name.len));

		hpack_debug_printf("\e[1;35m%s\e[0m [mustidx=%d, used=%d] [n=(%p,%d) v=(%p,%d)]\n",
				   istpad(trash.area, value).ptr, must_index,
				   dht->used,
				   name.ptr, (int)name.len, value.ptr, (int)value.len);
	}

	if (ret >= list_size) {
		ret = -HPACK_ERR_TOO_LARGE;
		goto leave;
	}

	/* put an end marker */
	list[ret].n = list[ret].v = ist2(NULL, 0);
	ret++;

 leave:
	hpack_debug_printf("-- done: ret=%d list_size=%d --\n", (int)ret, (int)list_size);
	return ret;
}
