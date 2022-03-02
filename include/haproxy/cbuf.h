/*
 * include/haprox/cbuf.h
 * This file contains definitions and prototypes for circular buffers.
 * Inspired from Linux circular buffers (include/linux/circ_buf.h).
 *
 * Copyright 2021 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_CBUF_H
#define _HAPROXY_CBUF_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif
#endif

#include <haproxy/atomic.h>
#include <haproxy/list.h>
#include <haproxy/cbuf-t.h>

struct cbuf *cbuf_new(unsigned char *buf, size_t sz);
void cbuf_free(struct cbuf *cbuf);

/* Amount of data between <rd> and <wr> */
#define CBUF_DATA(wr, rd, size)  (((wr) - (rd)) & ((size) - 1))

/* Return the writer position in <cbuf>.
 * To be used only by the writer!
 */
static inline unsigned char *cb_wr(struct cbuf *cbuf)
{
	return cbuf->buf + cbuf->wr;
}

/* Reset the reader index.
 * To be used by a reader!
 */
static inline void cb_rd_reset(struct cbuf *cbuf)
{
	cbuf->rd = 0;
}

/* Reset the writer index.
 * To be used by a writer!
 */
static inline void cb_wr_reset(struct cbuf *cbuf)
{
	cbuf->wr = 0;
}

/* Increase <cbuf> circular buffer data by <count>.
 * To be used by a writer!
 */
static inline void cb_add(struct cbuf *cbuf, size_t count)
{
	cbuf->wr = (cbuf->wr + count) & (cbuf->sz - 1);
}

/* Return the reader position in <cbuf>.
 * To be used only by the reader!
 */
static inline unsigned char *cb_rd(struct cbuf *cbuf)
{
	return cbuf->buf + cbuf->rd;
}

/* Skip <count> byte in <cbuf> circular buffer.
 * To be used by a reader!
 */
static inline void cb_del(struct cbuf *cbuf, size_t count)
{
	cbuf->rd = (cbuf->rd + count) & (cbuf->sz - 1);
}

/* Return the amount of data left in <cbuf>.
 * To be used only by the writer!
 */
static inline size_t cb_data(struct cbuf *cbuf)
{
	size_t rd;

	rd = HA_ATOMIC_LOAD(&cbuf->rd);
	return CBUF_DATA(cbuf->wr, rd, cbuf->sz);
}

/* Return the amount of room left in <cbuf> minus 1 to distinguish
 * the case where the buffer is full from the case where is is empty
 * To be used only by the write!
 */
static inline size_t cb_room(struct cbuf *cbuf)
{
	size_t rd;

	rd = HA_ATOMIC_LOAD(&cbuf->rd);
	return CBUF_DATA(rd, cbuf->wr + 1, cbuf->sz);
}

/* Return the amount of contiguous data left in <cbuf>.
 * To be used only by the reader!
 */
static inline size_t cb_contig_data(struct cbuf *cbuf)
{
	size_t end, n;

	end = cbuf->sz - cbuf->rd;
	n = (HA_ATOMIC_LOAD(&cbuf->wr) + end) & (cbuf->sz - 1);
	return n < end ? n : end;
}

/* Return the amount of contiguous space left in <cbuf>.
 * To be used only by the writer!
 */
static inline size_t cb_contig_space(struct cbuf *cbuf)
{
	size_t end, n;

	end = cbuf->sz - 1 - cbuf->wr;
	n = (HA_ATOMIC_LOAD(&cbuf->rd) + end) & (cbuf->sz - 1);
	return n <= end ? n : end + 1;
}

#endif /* _HAPROXY_CBUF_H */
