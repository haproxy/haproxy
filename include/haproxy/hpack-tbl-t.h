/*
 * HPACK header table management (RFC7541) - type definitions
 *
 * Copyright (C) 2014-2020 Willy Tarreau <willy@haproxy.org>
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
#ifndef _HAPROXY_HPACK_TBL_T_H
#define _HAPROXY_HPACK_TBL_T_H

#include <inttypes.h>

/* Dynamic Headers Table, usable for tables up to 4GB long and values of 64kB-1.
 * The model can be improved by using offsets relative to the table entry's end
 * or to the end of the area, or by moving the descriptors at the end of the
 * table and the data at the beginning. This entry is 8 bytes long, which is 1/4
 * of the bookkeeping planned by the HPACK spec. Thus it saves 24 bytes per
 * header field, meaning that even with a single header, 24 extra bytes can be
 * stored (ie one such descriptor). At 29.2 average bytes per header field as
 * found in the hpack test case, that's slightly more than 1.5kB of space saved
 * from a 4kB block, resulting in contiguous space almost always being
 * available.
 *
 * Principle: the table is stored in a contiguous array containing both the
 * descriptors and the contents. Descriptors are stored at the beginning of the
 * array while contents are stored starting from the end. Most of the time there
 * is enough room left in the table to insert a new header field, thanks to the
 * savings on the descriptor size. Thus by inserting headers from the end it's
 * possible to maximize the delay before a collision of DTEs and data. In order
 * to always insert from the right, we need to keep a reference to the latest
 * inserted element and look before it. The last inserted cell's address defines
 * the lowest known address still in use, unless the area wraps in which case
 * the available space lies between the end of the tail and the beginning of the
 * head.
 *
 * In order to detect collisions between data blocks and DTEs, we also maintain
 * an index to the lowest element facing the DTE table, called "front". This one
 * is updated each time an element is inserted before it. Once the buffer wraps,
 * this element doesn't have to be updated anymore until it is released, in
 * which case the buffer doesn't wrap anymore and the front element becomes the
 * head again.
 *
 * Various heuristics are possible concerning the opportunity to wrap the
 * entries to limit the risk of collisions with the DTE, but experimentation
 * shows that thanks to the important savings made on the descriptors, the
 * likeliness of finding a large amount of free space at the end of the area is
 * much higher than the risk of colliding, so in the end the most naive
 * algorithms work pretty fine. Typical ratios of 1 collision per 2000 requests
 * have been observed.
 *
 * The defragmentation should be rare ; a study on live data shows on average
 * 29.2 bytes used per header field. This plus the 32 bytes overhead fix an
 * average of 66.9 header fields per 4kB table. This brings a 1606 bytes saving
 * using the current storage description, ensuring that oldest headers are
 * linearly removed by the sender before fragmentation occurs. This means that
 * for all smaller header fields there will not be any requirement to defragment
 * the area and most of the time it will even be possible to copy the old values
 * directly within the buffer after creating a new entry. On average within the
 * available space there will be enough room to store 1606/(29.2+8)=43 extra
 * header fields without switching to another place.
 *
 * The table header fits in the table itself, it only takes 16 bytes, so in the
 * worst case (1 single header) it's possible to store 4096 - 16 - 8 = 4072
 * data bytes, which is larger than the 4064 the protocol requires (4096 - 32).
 */

/*
 * Gcc before 3.0 needs [0] to declare a variable-size array
 */
#ifndef VAR_ARRAY
#if defined(__GNUC__) && (__GNUC__ < 3)
#define VAR_ARRAY	0
#else
#define VAR_ARRAY
#endif
#endif

/* One dynamic table entry descriptor */
struct hpack_dte {
	uint32_t addr;  /* storage address, relative to the dte address */
	uint16_t nlen;  /* header name length */
	uint16_t vlen;  /* header value length */
};

/* Note: the table's head plus a struct hpack_dte must be smaller than or equal to 32
 * bytes so that a single large header can always fit. Here that's 16 bytes for
 * the header, plus 8 bytes per slot.
 * Note that when <used> == 0, front, head, and wrap are undefined.
 */
struct hpack_dht {
	uint32_t size;  /* allocated table size in bytes */
	uint32_t total; /* sum of nlen + vlen in bytes */
	uint16_t front; /* slot number of the first node after the idx table */
	uint16_t wrap;  /* number of allocated slots, wraps here */
	uint16_t head;  /* last inserted slot number */
	uint16_t used;  /* number of slots in use */
	struct hpack_dte dte[VAR_ARRAY]; /* dynamic table entries */
};

/* supported hpack encoding/decoding errors */
enum {
	HPACK_ERR_NONE = 0,           /* no error */
	HPACK_ERR_ALLOC_FAIL,         /* memory allocation error */
	HPACK_ERR_UNKNOWN_OPCODE,     /* invalid first byte */
	HPACK_ERR_TRUNCATED,          /* truncated stream */
	HPACK_ERR_HUFFMAN,            /* huffman decoding error */
	HPACK_ERR_INVALID_PHDR,       /* invalid pseudo header field name */
	HPACK_ERR_MISPLACED_PHDR,     /* pseudo header field after a regular header field */
	HPACK_ERR_DUPLICATE_PHDR,     /* duplicate pseudo header field */
	HPACK_ERR_DHT_INSERT_FAIL,    /* failed to insert into DHT */
	HPACK_ERR_TOO_LARGE,          /* decoded request/response is too large */
	HPACK_ERR_MISSING_METHOD,     /* :method is missing */
	HPACK_ERR_MISSING_SCHEME,     /* :scheme is missing */
	HPACK_ERR_MISSING_PATH,       /* :path is missing */
	HPACK_ERR_MISSING_AUTHORITY,  /* :authority is missing with CONNECT */
	HPACK_ERR_SCHEME_NOT_ALLOWED, /* :scheme not allowed with CONNECT */
	HPACK_ERR_PATH_NOT_ALLOWED,   /* :path not allowed with CONNECT */
	HPACK_ERR_INVALID_ARGUMENT,   /* an invalid argument was passed */
};

/* static header table as in RFC7541 Appendix A. [0] unused. */
#define HPACK_SHT_SIZE 62

#endif /* _HAPROXY_HPACK_TBL_T_H */
