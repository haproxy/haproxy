/*
 * QPACK header table management (draft-ietf-quic-qpack-20) - type definitions
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
#ifndef _HAPROXY_QPACK_TBL_T_H
#define _HAPROXY_QPACK_TBL_T_H

#include <inttypes.h>

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
struct qpack_dte {
	uint32_t addr;  /* storage address, relative to the dte address */
	uint16_t nlen;  /* header name length */
	uint16_t vlen;  /* header value length */
};

/* Note: the table's head plus a struct qpack_dte must be smaller than or equal to 32
 * bytes so that a single large header can always fit. Here that's 16 bytes for
 * the header, plus 8 bytes per slot.
 * Note that when <used> == 0, front, head, and wrap are undefined.
 */
struct qpack_dht {
	uint32_t size;  /* allocated table size in bytes */
	uint32_t total; /* sum of nlen + vlen in bytes */
	uint16_t front; /* slot number of the first node after the idx table */
	uint16_t wrap;  /* number of allocated slots, wraps here */
	uint16_t head;  /* last inserted slot number */
	uint16_t used;  /* number of slots in use */
	struct qpack_dte dte[VAR_ARRAY]; /* dynamic table entries */
};

/* static header table as in draft-ietf-quic-qpack-20 Appendix A. [0] unused. */
#define QPACK_SHT_SIZE 99

#endif /* _HAPROXY_QPACK_TBL_T_H */
