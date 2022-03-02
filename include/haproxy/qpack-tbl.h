/*
 * QPACK header table management - prototypes
 *
 * Copyright 2021 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
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
#ifndef _HAPROXY_QPACK_TBL_H
#define _HAPROXY_QPACK_TBL_H

#include <import/ist.h>
#include <haproxy/api.h>
#include <haproxy/qpack-tbl-t.h>
#include <haproxy/http-hdr-t.h>

/* when built outside of haproxy, QPACK_STANDALONE must be defined, and
 * pool_head_qpack_tbl->size must be set to the DHT size.
 */
#ifndef QPACK_STANDALONE
#include <haproxy/pool.h>
#define qpack_alloc(pool)      pool_alloc(pool)
#define qpack_free(pool, ptr)  pool_free(pool, ptr)
#else
#include <stdlib.h>
#include <haproxy/pool-t.h>
#define qpack_alloc(pool)      malloc(pool->size)
#define qpack_free(pool, ptr)  free(ptr)
#endif

extern const struct http_hdr qpack_sht[QPACK_SHT_SIZE];
extern struct pool_head *pool_head_qpack_tbl;

int __qpack_dht_make_room(struct qpack_dht *dht, unsigned int needed);
int qpack_dht_insert(struct qpack_dht *dht, struct ist name, struct ist value);

#ifdef DEBUG_QPACK
void qpack_dht_dump(FILE *out, const struct qpack_dht *dht);
void qpack_dht_check_consistency(const struct qpack_dht *dht);
#endif

/* return a pointer to the entry designated by index <idx> (starting at 0) or
 * NULL if this index is not there.
 */
static inline const struct qpack_dte *qpack_get_dte(const struct qpack_dht *dht, uint16_t idx)
{
	if (idx >= dht->used)
		return NULL;

	return &dht->dte[idx];
}

/* returns non-zero if <idx> is valid for table <dht> */
static inline int qpack_valid_idx(const struct qpack_dht *dht, uint32_t idx)
{
	return idx < dht->used;
}

/* return a pointer to the header name for entry <dte>. */
static inline struct ist qpack_get_name(const struct qpack_dht *dht, const struct qpack_dte *dte)
{
	struct ist ret = {
		.ptr = (void *)dht + dte->addr,
		.len = dte->nlen,
	};
	return ret;
}

/* return a pointer to the header value for entry <dte>. */
static inline struct ist qpack_get_value(const struct qpack_dht *dht, const struct qpack_dte *dte)
{
	struct ist ret = {
		.ptr = (void *)dht + dte->addr + dte->nlen,
		.len = dte->vlen,
	};
	return ret;
}

/* takes an idx, returns the associated name */
static inline struct ist qpack_idx_to_name(const struct qpack_dht *dht, uint32_t idx)
{
	const struct qpack_dte *dte;

	dte = qpack_get_dte(dht, idx);
	if (!dte)
		return ist("### ERR ###"); // error

	return qpack_get_name(dht, dte);
}

/* takes an idx, returns the associated value */
static inline struct ist qpack_idx_to_value(const struct qpack_dht *dht, uint32_t idx)
{
	const struct qpack_dte *dte;

	dte = qpack_get_dte(dht, idx);
	if (!dte)
		return ist("### ERR ###"); // error

	return qpack_get_value(dht, dte);
}

/* returns the slot number of the oldest entry (tail). Must not be used on an
 * empty table.
 */
static inline unsigned int qpack_dht_get_tail(const struct qpack_dht *dht)
{
	return ((dht->head + 1U < dht->used) ? dht->wrap : 0) + dht->head + 1U - dht->used;
}

/* Purges table dht until a header field of <needed> bytes fits according to
 * the protocol (adding 32 bytes overhead). Returns non-zero on success, zero
 * on failure (ie: table empty but still not sufficient).
 */
static inline int qpack_dht_make_room(struct qpack_dht *dht, unsigned int needed)
{
	if (dht->used * 32 + dht->total + needed + 32 <= dht->size)
		return 1;
	else if (!dht->used)
		return 0;

	return __qpack_dht_make_room(dht, needed);
}

/* allocate a dynamic headers table of <size> bytes and return it initialized */
static inline void qpack_dht_init(struct qpack_dht *dht, uint32_t size)
{
	dht->size = size;
	dht->total = 0;
	dht->used = 0;
}

/* allocate a dynamic headers table from the pool and return it initialized */
static inline struct qpack_dht *qpack_dht_alloc()
{
	struct qpack_dht *dht;

	if (unlikely(!pool_head_qpack_tbl))
		return NULL;

	dht = qpack_alloc(pool_head_qpack_tbl);
	if (dht)
		qpack_dht_init(dht, pool_head_qpack_tbl->size);
	return dht;
}

/* free a dynamic headers table */
static inline void qpack_dht_free(struct qpack_dht *dht)
{
	qpack_free(pool_head_qpack_tbl, dht);
}

#endif /* _HAPROXY_QPACK_TBL_H */
