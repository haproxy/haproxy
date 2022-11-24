/*
 * QPACK header table management (draft-ietf-quic-qpack-20)
 *
 * Copyright 2020 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
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

#include <import/ist.h>
#include <haproxy/http-hdr-t.h>
#include <haproxy/qpack-tbl.h>

/* static header table as in draft-ietf-quic-qpack-20 Appendix A. */
const struct http_hdr qpack_sht[QPACK_SHT_SIZE] = {
	[ 0] = { .n = IST(":authority"),                       .v = IST("")                         },
	[ 1] = { .n = IST(":path"),                            .v = IST("/")                        },
	[ 2] = { .n = IST("age"),                              .v = IST("0")                        },
	[ 3] = { .n = IST("content-disposition"),              .v = IST("")                         },
	[ 4] = { .n = IST("content-length"),                   .v = IST("0")                        },
	[ 5] = { .n = IST("cookie"),                           .v = IST("")                         },
	[ 6] = { .n = IST("date"),                             .v = IST("")                         },
	[ 7] = { .n = IST("etag"),                             .v = IST("")                         },
	[ 8] = { .n = IST("if-modified-since"),                .v = IST("")                         },
	[ 9] = { .n = IST("if-none-match"),                    .v = IST("")                         },
	[10] = { .n = IST("last-modified"),                    .v = IST("")                         },
	[11] = { .n = IST("link"),                             .v = IST("")                         },
	[12] = { .n = IST("location"),                         .v = IST("")                         },
	[13] = { .n = IST("referer"),                          .v = IST("")                         },
	[14] = { .n = IST("set-cookie"),                       .v = IST("")                         },
	[15] = { .n = IST(":method"),                          .v = IST("CONNECT")                  },
	[16] = { .n = IST(":method"),                          .v = IST("DELETE")                   },
	[17] = { .n = IST(":method"),                          .v = IST("GET")                      },
	[18] = { .n = IST(":method"),                          .v = IST("HEAD")                     },
	[19] = { .n = IST(":method"),                          .v = IST("OPTIONS")                  },
	[20] = { .n = IST(":method"),                          .v = IST("POST")                     },
	[21] = { .n = IST(":method"),                          .v = IST("PUT")                      },
	[22] = { .n = IST(":scheme"),                          .v = IST("http")                     },
	[23] = { .n = IST(":scheme"),                          .v = IST("https")                    },
	[24] = { .n = IST(":status"),                          .v = IST("103")                      },
	[25] = { .n = IST(":status"),                          .v = IST("200")                      },
	[26] = { .n = IST(":status"),                          .v = IST("304")                      },
	[27] = { .n = IST(":status"),                          .v = IST("404")                      },
	[28] = { .n = IST(":status"),                          .v = IST("503")                      },
	[29] = { .n = IST("accept"),                           .v = IST("*/*")                      },
	[30] = { .n = IST("accept"),                           .v = IST("application/dns-message")  },
	[31] = { .n = IST("accept-encoding"),                  .v = IST("gzip, deflate, br")        },
	[32] = { .n = IST("accept-ranges"),                    .v = IST("bytes")                    },
	[33] = { .n = IST("access-control-allow-headers"),     .v = IST("cache-control")            },
	[34] = { .n = IST("access-control-allow-headers"),     .v = IST("content-type")             },
	[35] = { .n = IST("access-control-allow-origin"),      .v = IST("*")                        },
	[36] = { .n = IST("cache-control"),                    .v = IST("max-age=0")                },
	[37] = { .n = IST("cache-control"),                    .v = IST("max-age=2592000")          },
	[38] = { .n = IST("cache-control"),                    .v = IST("max-age=604800")           },
	[39] = { .n = IST("cache-control"),                    .v = IST("no-cache")                 },
	[40] = { .n = IST("cache-control"),                    .v = IST("no-store")                 },
	[41] = { .n = IST("cache-control"),                    .v = IST("public, max-age=31536000") },
	[42] = { .n = IST("content-encoding"),                 .v = IST("br")                       },
	[43] = { .n = IST("content-encoding"),                 .v = IST("gzip")                     },
	[44] = { .n = IST("content-type"),                     .v = IST("application/dns-message")  },
	[45] = { .n = IST("content-type"),                     .v = IST("application/javascript")   },
	[46] = { .n = IST("content-type"),                     .v = IST("application/json")         },
	[47] = { .n = IST("content-type"),                     .v = IST("application/"
	                                                                "x-www-form-urlencoded")    },
	[48] = { .n = IST("content-type"),                     .v = IST("image/gif")                },
	[49] = { .n = IST("content-type"),                     .v = IST("image/jpeg")               },
	[50] = { .n = IST("content-type"),                     .v = IST("image/png")                },
	[51] = { .n = IST("content-type"),                     .v = IST("text/css")                 },
	[52] = { .n = IST("content-type"),                     .v = IST("text/html;"
	                                                                " charset=utf-8")           },
	[53] = { .n = IST("content-type"),                     .v = IST("text/plain")               },
	[54] = { .n = IST("content-type"),                     .v = IST("text/plain;"
	                                                                "charset=utf-8")            },
	[55] = { .n = IST("range"),                            .v = IST("bytes=0-")                 },
	[56] = { .n = IST("strict-transport-security"),        .v = IST("max-age=31536000")         },
	[57] = { .n = IST("strict-transport-security"),        .v = IST("max-age=31536000;"
	                                                                " includesubdomains")       },
	[58] = { .n = IST("strict-transport-security"),        .v = IST("max-age=31536000;"
	                                                                " includesubdomains;"
	                                                                " preload")                 },
	[59] = { .n = IST("vary"),                             .v = IST("accept-encoding")          },
	[60] = { .n = IST("vary"),                             .v = IST("origin")                   },
	[61] = { .n = IST("x-content-type-options"),           .v = IST("nosniff")                  },
	[62] = { .n = IST("x-xss-protection"),                 .v = IST("1; mode=block")            },
	[63] = { .n = IST(":status"),                          .v = IST("100")                      },
	[64] = { .n = IST(":status"),                          .v = IST("204")                      },
	[65] = { .n = IST(":status"),                          .v = IST("206")                      },
	[66] = { .n = IST(":status"),                          .v = IST("302")                      },
	[67] = { .n = IST(":status"),                          .v = IST("400")                      },
	[68] = { .n = IST(":status"),                          .v = IST("403")                      },
	[69] = { .n = IST(":status"),                          .v = IST("421")                      },
	[70] = { .n = IST(":status"),                          .v = IST("425")                      },
	[71] = { .n = IST(":status"),                          .v = IST("500")                      },
	[72] = { .n = IST("accept-language"),                  .v = IST("")                         },
	[73] = { .n = IST("access-control-allow-credentials"), .v = IST("FALSE")                    },
	[74] = { .n = IST("access-control-allow-credentials"), .v = IST("TRUE")                     },
	[75] = { .n = IST("access-control-allow-headers"),     .v = IST("*")                        },
	[76] = { .n = IST("access-control-allow-methods"),     .v = IST("get")                      },
	[77] = { .n = IST("access-control-allow-methods"),     .v = IST("get, post, options")       },
	[78] = { .n = IST("access-control-allow-methods"),     .v = IST("options")                  },
	[79] = { .n = IST("access-control-expose-headers"),    .v = IST("content-length")           },
	[80] = { .n = IST("access-control-request-headers"),   .v = IST("content-type")             },
	[81] = { .n = IST("access-control-request-method"),    .v = IST("get")                      },
	[82] = { .n = IST("access-control-request-method"),    .v = IST("post")                     },
	[83] = { .n = IST("alt-svc"),                          .v = IST("clear")                    },
	[84] = { .n = IST("authorization"),                    .v = IST("")                         },
	[85] = { .n = IST("content-security-policy"),          .v = IST("script-src 'none';"
	                                                                " object-src 'none';"
	                                                                " base-uri 'none'")         },
	[86] = { .n = IST("early-data"),                       .v = IST("1")                        },
	[87] = { .n = IST("expect-ct"),                        .v = IST("")                         },
	[88] = { .n = IST("forwarded"),                        .v = IST("")                         },
	[89] = { .n = IST("if-range"),                         .v = IST("")                         },
	[90] = { .n = IST("origin"),                           .v = IST("")                         },
	[91] = { .n = IST("purpose"),                          .v = IST("prefetch")                 },
	[92] = { .n = IST("server"),                           .v = IST("")                         },
	[93] = { .n = IST("timing-allow-origin"),              .v = IST("*")                        },
	[94] = { .n = IST("upgrade-insecure-requests"),        .v = IST("1")                        },
	[95] = { .n = IST("user-agent"),                       .v = IST("")                         },
	[96] = { .n = IST("x-forwarded-for"),                  .v = IST("")                         },
	[97] = { .n = IST("x-frame-options"),                  .v = IST("deny")                     },
	[98] = { .n = IST("x-frame-options"),                  .v = IST("sameorigin")               },
};

struct pool_head *pool_head_qpack_tbl = NULL;

#ifdef DEBUG_QPACK
/* dump the whole dynamic header table */
void qpack_dht_dump(FILE *out, const struct qpack_dht *dht)
{
	unsigned int i;
	unsigned int slot;
	char name[4096], value[4096];

	for (i = QPACK_SHT_SIZE; i < QPACK_SHT_SIZE + dht->used; i++) {
		slot = (qpack_get_dte(dht, i - QPACK_SHT_SIZE + 1) - dht->dte);
		fprintf(out, "idx=%u slot=%u name=<%s> value=<%s> addr=%u-%u\n",
			i, slot,
			istpad(name, qpack_idx_to_name(dht, i)).ptr,
			istpad(value, qpack_idx_to_value(dht, i)).ptr,
			dht->dte[slot].addr, dht->dte[slot].addr+dht->dte[slot].nlen+dht->dte[slot].vlen-1);
	}
}

/* check for the whole dynamic header table consistency, abort on failures */
void qpack_dht_check_consistency(const struct qpack_dht *dht)
{
	unsigned slot = qpack_dht_get_tail(dht);
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
#endif // DEBUG_QPACK

/* rebuild a new dynamic header table from <dht> with an unwrapped index and
 * contents at the end. The new table is returned, the caller must not use the
 * previous one anymore. NULL may be returned if no table could be allocated.
 */
static struct qpack_dht *qpack_dht_defrag(struct qpack_dht *dht)
{
	struct qpack_dht *alt_dht;
	uint16_t old, new;
	uint32_t addr;

	/* Note: for small tables we could use alloca() instead but
	 * portability especially for large tables can be problematic.
	 */
	alt_dht = qpack_dht_alloc();
	if (!alt_dht)
		return NULL;

	alt_dht->total = dht->total;
	alt_dht->used = dht->used;
	alt_dht->wrap = dht->used;

	new = 0;
	addr = alt_dht->size;

	if (dht->used) {
		/* start from the tail */
		old = qpack_dht_get_tail(dht);
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
	qpack_dht_free(alt_dht);

	return dht;
}

/* Purges table dht until a header field of <needed> bytes fits according to
 * the protocol (adding 32 bytes overhead). Returns non-zero on success, zero
 * on failure (ie: table empty but still not sufficient). It must only be
 * called when the table is not large enough to suit the new entry and there
 * are some entries left. In case of doubt, use dht_make_room() instead.
 */
int __qpack_dht_make_room(struct qpack_dht *dht, unsigned int needed)
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
int qpack_dht_insert(struct qpack_dht *dht, struct ist name, struct ist value)
{
	unsigned int used;
	unsigned int head;
	unsigned int prev;
	unsigned int wrap;
	unsigned int tail;
	uint32_t headroom, tailroom;

	if (!qpack_dht_make_room(dht, name.len + value.len))
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
	tail = qpack_dht_get_tail(dht);

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
			if (!qpack_dht_defrag(dht))
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
		if (!qpack_dht_defrag(dht))
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
		dht = qpack_dht_defrag(dht);
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
