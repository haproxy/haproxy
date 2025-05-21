#ifndef _HAPROXY_QUIC_UTILS_H
#define _HAPROXY_QUIC_UTILS_H

#ifdef USE_QUIC

#include <haproxy/quic_utils-t.h>

#include <haproxy/buf-t.h>
#include <haproxy/chunk.h>

static inline int quic_stream_is_uni(uint64_t id)
{
	return id & QCS_ID_DIR_BIT;
}

static inline int quic_stream_is_bidi(uint64_t id)
{
	return !quic_stream_is_uni(id);
}

static inline void bdata_ctr_init(struct bdata_ctr *ctr)
{
	ctr->tot  = 0;
	ctr->bcnt = 0;
	ctr->bmax = 0;
}

static inline void bdata_ctr_binc(struct bdata_ctr *ctr)
{
	++ctr->bcnt;
	ctr->bmax = MAX(ctr->bcnt, ctr->bmax);
}

static inline void bdata_ctr_bdec(struct bdata_ctr *ctr)
{
	--ctr->bcnt;
}

static inline void bdata_ctr_add(struct bdata_ctr *ctr, size_t data)
{
	ctr->tot += data;
}

static inline void bdata_ctr_del(struct bdata_ctr *ctr, size_t data)
{
	ctr->tot -= data;
}

static inline void bdata_ctr_print(struct buffer *chunk,
                                   const struct bdata_ctr *ctr,
                                   const char *prefix)
{
	chunk_appendf(chunk, " %s%d(%d)/%llu",
	              prefix, ctr->bcnt, ctr->bmax, (ullong)ctr->tot);
}

#endif /* USE_QUIC */

#endif /* _HAPROXY_QUIC_UTILS_H */
