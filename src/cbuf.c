/*
 * Circular buffer management
 *
 * Copyright 2021 HAProxy Technologies, Frederic Lecaille <flecaill@haproxy.com>
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

#include <haproxy/list.h>
#include <haproxy/pool.h>
#include <haproxy/cbuf-t.h>

DECLARE_POOL(pool_head_cbuf, "cbuf", sizeof(struct cbuf));

/* Allocate and return a new circular buffer with <buf> as <sz> byte internal buffer
 * if succeeded, NULL if not.
 */
struct cbuf *cbuf_new(unsigned char *buf, size_t sz)
{
	struct cbuf *cbuf;

	cbuf = pool_alloc(pool_head_cbuf);
	if (cbuf) {
		cbuf->sz = sz;
		cbuf->buf = buf;
		cbuf->wr = 0;
		cbuf->rd = 0;
	}

	return cbuf;
}

/* Free QUIC ring <cbuf> */
void cbuf_free(struct cbuf *cbuf)
{
	if (!cbuf)
		return;

	pool_free(pool_head_cbuf, cbuf);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
