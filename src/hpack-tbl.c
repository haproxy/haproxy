/*
 * HPACK header table management (RFC7541)
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

#include <common/hpack-huff.h>
#include <common/hpack-tbl.h>
#include <common/ist.h>

#include <types/global.h>

/* static header table as in RFC7541 Appendix A. [0] unused. */
const struct http_hdr hpack_sht[HPACK_SHT_SIZE] = {
	[ 1] = { .n = IST(":authority"),                   .v = IST("")              },
	[ 2] = { .n = IST(":method"),                      .v = IST("GET")           },
	[ 3] = { .n = IST(":method"),                      .v = IST("POST")          },
	[ 4] = { .n = IST(":path"),                        .v = IST("/")             },
	[ 5] = { .n = IST(":path"),                        .v = IST("/index.html")   },
	[ 6] = { .n = IST(":scheme"),                      .v = IST("http")          },
	[ 7] = { .n = IST(":scheme"),                      .v = IST("https")         },
	[ 8] = { .n = IST(":status"),                      .v = IST("200")           },
	[ 9] = { .n = IST(":status"),                      .v = IST("204")           },
	[10] = { .n = IST(":status"),                      .v = IST("206")           },
	[11] = { .n = IST(":status"),                      .v = IST("304")           },
	[12] = { .n = IST(":status"),                      .v = IST("400")           },
	[13] = { .n = IST(":status"),                      .v = IST("404")           },
	[14] = { .n = IST(":status"),                      .v = IST("500")           },
	[15] = { .n = IST("accept-charset"),               .v = IST("")              },
	[16] = { .n = IST("accept-encoding"),              .v = IST("gzip, deflate") },
	[17] = { .n = IST("accept-language"),              .v = IST("")              },
	[18] = { .n = IST("accept-ranges"),                .v = IST("")              },
	[19] = { .n = IST("accept"),                       .v = IST("")              },
	[20] = { .n = IST("access-control-allow-origin"),  .v = IST("")              },
	[21] = { .n = IST("age"),                          .v = IST("")              },
	[22] = { .n = IST("allow"),                        .v = IST("")              },
	[23] = { .n = IST("authorization"),                .v = IST("")              },
	[24] = { .n = IST("cache-control"),                .v = IST("")              },
	[25] = { .n = IST("content-disposition"),          .v = IST("")              },
	[26] = { .n = IST("content-encoding"),             .v = IST("")              },
	[27] = { .n = IST("content-language"),             .v = IST("")              },
	[28] = { .n = IST("content-length"),               .v = IST("")              },
	[29] = { .n = IST("content-location"),             .v = IST("")              },
	[30] = { .n = IST("content-range"),                .v = IST("")              },
	[31] = { .n = IST("content-type") ,                .v = IST("")              },
	[32] = { .n = IST("cookie"),                       .v = IST("")              },
	[33] = { .n = IST("date"),                         .v = IST("")              },
	[34] = { .n = IST("etag"),                         .v = IST("")              },
	[35] = { .n = IST("expect"),                       .v = IST("")              },
	[36] = { .n = IST("expires"),                      .v = IST("")              },
	[37] = { .n = IST("from"),                         .v = IST("")              },
	[38] = { .n = IST("host"),                         .v = IST("")              },
	[39] = { .n = IST("if-match"),                     .v = IST("")              },
	[40] = { .n = IST("if-modified-since"),            .v = IST("")              },
	[41] = { .n = IST("if-none-match"),                .v = IST("")              },
	[42] = { .n = IST("if-range"),                     .v = IST("")              },
	[43] = { .n = IST("if-unmodified-since"),          .v = IST("")              },
	[44] = { .n = IST("last-modified"),                .v = IST("")              },
	[45] = { .n = IST("link"),                         .v = IST("")              },
	[46] = { .n = IST("location"),                     .v = IST("")              },
	[47] = { .n = IST("max-forwards"),                 .v = IST("")              },
	[48] = { .n = IST("proxy-authenticate"),           .v = IST("")              },
	[49] = { .n = IST("proxy-authorization"),          .v = IST("")              },
	[50] = { .n = IST("range"),                        .v = IST("")              },
	[51] = { .n = IST("referer"),                      .v = IST("")              },
	[52] = { .n = IST("refresh"),                      .v = IST("")              },
	[53] = { .n = IST("retry-after"),                  .v = IST("")              },
	[54] = { .n = IST("server"),                       .v = IST("")              },
	[55] = { .n = IST("set-cookie"),                   .v = IST("")              },
	[56] = { .n = IST("strict-transport-security"),    .v = IST("")              },
	[57] = { .n = IST("transfer-encoding"),            .v = IST("")              },
	[58] = { .n = IST("user-agent"),                   .v = IST("")              },
	[59] = { .n = IST("vary"),                         .v = IST("")              },
	[60] = { .n = IST("via"),                          .v = IST("")              },
	[61] = { .n = IST("www-authenticate"),             .v = IST("")              },
};

/* returns the slot number of the oldest entry (tail). Must not be used on an
 * empty table.
 */
static inline unsigned int hpack_dht_get_tail(const struct hpack_dht *dht)
{
	return ((dht->head + 1U < dht->used) ? dht->wrap : 0) + dht->head + 1U - dht->used;
}

#ifdef DEBUG_HPACK
/* dump the whole dynamic header table */
static void hpack_dht_dump(FILE *out, const struct hpack_dht *dht)
{
	unsigned int i;
	unsigned int slot;
	char name[4096], value[4096];

	for (i = HPACK_SHT_SIZE; i < HPACK_SHT_SIZE + dht->used; i++) {
		slot = (hpack_get_dte(dht, i - HPACK_SHT_SIZE + 1) - dht->dte);
		fprintf(out, "idx=%d slot=%u name=<%s> value=<%s> addr=%u-%u\n",
			i, slot,
			istpad(name, hpack_idx_to_name(dht, i)).ptr,
			istpad(value, hpack_idx_to_value(dht, i)).ptr,
			dht->dte[slot].addr, dht->dte[slot].addr+dht->dte[slot].nlen+dht->dte[slot].vlen-1);
	}
}

/* check for the whole dynamic header table consistency, abort on failures */
static void hpack_dht_check_consistency(const struct hpack_dht *dht)
{
	unsigned slot = hpack_dht_get_tail(dht);
	unsigned used2 = dht->used;
	unsigned total = 0;

	if (!dht->used)
		return;

	if (dht->front >= dht->wrap)
		abort();

	if (dht->used > dht->wrap)
		abort();

	if (dht->head >= dht->wrap)
		abort();

	while (used2--) {
		total += dht->dte[slot].nlen + dht->dte[slot].vlen;
		slot++;
		if (slot >= dht->wrap)
			slot = 0;
	}

	if (total != dht->total) {
		fprintf(stderr, "%d: total=%u dht=%u\n", __LINE__, total, dht->total);
		abort();
	}
}
#endif // DEBUG_HPACK

/* rebuild a new dynamic header table from <dht> with an unwrapped index and
 * contents at the end. The new table is returned, the caller must not use the
 * previous one anymore. NULL may be returned if no table could be allocated.
 */
static struct hpack_dht *hpack_dht_defrag(struct hpack_dht *dht)
{
	struct hpack_dht *alt_dht;
	uint16_t old, new;
	uint32_t addr;

	/* Note: for small tables we could use alloca() instead but
	 * portability especially for large tables can be problematic.
	 */
	alt_dht = hpack_dht_alloc(dht->size);
	if (!alt_dht)
		return NULL;

	alt_dht->total = dht->total;
	alt_dht->used = dht->used;
	alt_dht->wrap = dht->used;

	new = 0;
	addr = alt_dht->size;

	if (dht->used) {
		/* start from the tail */
		old = hpack_dht_get_tail(dht);
		do {
			alt_dht->dte[new].nlen = dht->dte[old].nlen;
			alt_dht->dte[new].vlen = dht->dte[old].vlen;
			addr -= dht->dte[old].nlen + dht->dte[old].vlen;
			alt_dht->dte[new].addr = addr;

			memcpy((void *)alt_dht + alt_dht->dte[new].addr,
			       (void *)dht + dht->dte[old].addr,
			       dht->dte[old].nlen + dht->dte[old].vlen);

			old++;
			if (old >= dht->wrap)
				old = 0;
			new++;
		} while (new < dht->used);
	}

	alt_dht->front = alt_dht->head = new - 1;

	memcpy(dht, alt_dht, dht->size);
	hpack_dht_free(alt_dht);

	return dht;
}

/* Purges table dht until a header field of <needed> bytes fits according to
 * the protocol (adding 32 bytes overhead). Returns non-zero on success, zero
 * on failure (ie: table empty but still not sufficient). It must only be
 * called when the table is not large enough to suit the new entry and there
 * are some entries left. In case of doubt, use dht_make_room() instead.
 */
int __hpack_dht_make_room(struct hpack_dht *dht, unsigned int needed)
{
	unsigned int used = dht->used;
	unsigned int wrap = dht->wrap;
	unsigned int tail;

	do {
		tail = ((dht->head + 1U < used) ? wrap : 0) + dht->head + 1U - used;
		dht->total -= dht->dte[tail].nlen + dht->dte[tail].vlen;
		if (tail == dht->front)
			dht->front = dht->head;
		used--;
	} while (used && used * 32 + dht->total + needed + 32 > dht->size);

	dht->used = used;

	/* realign if empty */
	if (!used)
		dht->front = dht->head = 0;

	/* pack the table if it doesn't wrap anymore */
	if (dht->head + 1U >= used)
		dht->wrap = dht->head + 1;

	/* no need to check for 'used' here as if it doesn't fit, used==0 */
	return needed + 32 <= dht->size;
}

/* tries to insert a new header <name>:<value> in front of the current head. A
 * negative value is returned on error.
 */
int hpack_dht_insert(struct hpack_dht *dht, struct ist name, struct ist value)
{
	unsigned int used;
	unsigned int head;
	unsigned int prev;
	unsigned int wrap;
	unsigned int tail;
	uint32_t headroom, tailroom;

	if (!hpack_dht_make_room(dht, name.len + value.len))
		return 0;

	/* Now there is enough room in the table, that's guaranteed by the
	 * protocol, but not necessarily where we need it.
	 */

	used = dht->used;
	if (!used) {
		/* easy, the table was empty */
		dht->front = dht->head = 0;
		dht->wrap  = dht->used = 1;
		dht->total = 0;
		head = 0;
		dht->dte[head].addr = dht->size - (name.len + value.len);
		goto copy;
	}

	/* compute the new head, used and wrap position */
	prev = head = dht->head;
	wrap = dht->wrap;
	tail = hpack_dht_get_tail(dht);

	used++;
	head++;

	if (head >= wrap) {
		/* head is leading the entries, we either need to push the
		 * table further or to loop back to released entries. We could
		 * force to loop back when at least half of the allocatable
		 * entries are free but in practice it never happens.
		 */
		if ((sizeof(*dht) + (wrap + 1) * sizeof(dht->dte[0]) <= dht->dte[dht->front].addr))
			wrap++;
		else if (head >= used) /* there's a hole at the beginning */
			head = 0;
		else {
			/* no more room, head hits tail and the index cannot be
			 * extended, we have to realign the whole table.
			 */
			if (!hpack_dht_defrag(dht))
				return -1;

			wrap = dht->wrap + 1;
			head = dht->head + 1;
			prev = head - 1;
			tail = 0;
		}
	}
	else if (used >= wrap) {
		/* we've hit the tail, we need to reorganize the index so that
		 * the head is at the end (but not necessarily move the data).
		 */
		if (!hpack_dht_defrag(dht))
			return -1;

		wrap = dht->wrap + 1;
		head = dht->head + 1;
		prev = head - 1;
		tail = 0;
	}

	/* Now we have updated head, used and wrap, we know that there is some
	 * available room at least from the protocol's perspective. This space
	 * is split in two areas :
	 *
	 *   1: if the previous head was the front cell, the space between the
	 *      end of the index table and the front cell's address.
	 *   2: if the previous head was the front cell, the space between the
	 *      end of the tail and the end of the table ; or if the previous
	 *      head was not the front cell, the space between the end of the
	 *      tail and the head's address.
	 */
	if (prev == dht->front) {
		/* the area was contiguous */
		headroom = dht->dte[dht->front].addr - (sizeof(*dht) + wrap * sizeof(dht->dte[0]));
		tailroom = dht->size - dht->dte[tail].addr - dht->dte[tail].nlen - dht->dte[tail].vlen;
	}
	else {
		/* it's already wrapped so we can't store anything in the headroom */
		headroom = 0;
		tailroom = dht->dte[prev].addr - dht->dte[tail].addr - dht->dte[tail].nlen - dht->dte[tail].vlen;
	}

	/* We can decide to stop filling the headroom as soon as there's enough
	 * room left in the tail to suit the protocol, but tests show that in
	 * practice it almost never happens in other situations so the extra
	 * test is useless and we simply fill the headroom as long as it's
	 * available and we don't wrap.
	 */
	if (prev == dht->front && headroom >= name.len + value.len) {
		/* install upfront and update ->front */
		dht->dte[head].addr = dht->dte[dht->front].addr - (name.len + value.len);
		dht->front = head;
	}
	else if (tailroom >= name.len + value.len) {
		dht->dte[head].addr = dht->dte[tail].addr + dht->dte[tail].nlen + dht->dte[tail].vlen + tailroom - (name.len + value.len);
	}
	else {
		/* need to defragment the table before inserting upfront */
		dht = hpack_dht_defrag(dht);
		wrap = dht->wrap + 1;
		head = dht->head + 1;
		dht->dte[head].addr = dht->dte[dht->front].addr - (name.len + value.len);
		dht->front = head;
	}

	dht->wrap = wrap;
	dht->head = head;
	dht->used = used;

 copy:
	dht->total         += name.len + value.len;
	dht->dte[head].nlen = name.len;
	dht->dte[head].vlen = value.len;

	memcpy((void *)dht + dht->dte[head].addr, name.ptr, name.len);
	memcpy((void *)dht + dht->dte[head].addr + name.len, value.ptr, value.len);
	return 0;
}
