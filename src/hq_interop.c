#include <haproxy/hq_interop.h>

#include <import/ist.h>
#include <haproxy/buf.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/htx.h>
#include <haproxy/http.h>
#include <haproxy/mux_quic-t.h>
#include <haproxy/stream.h>

static int hq_interop_decode_qcs(struct qcs *qcs, void *ctx)
{
	struct buffer *rxbuf = &qcs->rx.buf;
	struct htx *htx;
	struct htx_sl *sl;
	struct conn_stream *cs;
	struct buffer htx_buf = BUF_NULL;
	struct ist path;
	char *ptr;

	b_alloc(&htx_buf);
	htx = htx_from_buf(&htx_buf);

	/* skip method */
	ptr = b_orig(rxbuf);
	while (HTTP_IS_TOKEN(*ptr))
		++ptr;
	BUG_ON(!HTTP_IS_SPHT(*ptr));
	++ptr;

	/* extract path */
	BUG_ON(HTTP_IS_LWS(*ptr));
	path.ptr = ptr;
	while (!HTTP_IS_LWS(*ptr))
		++ptr;
	BUG_ON(!HTTP_IS_LWS(*ptr));
	path.len = ptr - path.ptr;

	sl = htx_add_stline(htx, HTX_BLK_REQ_SL, 0, ist("GET"), path, ist("HTTP/1.0"));
	if (!sl)
		return -1;

	sl->flags |= HTX_SL_F_BODYLESS;
	sl->info.req.meth = find_http_meth("GET", 3);

	htx_add_endof(htx, HTX_BLK_EOH);
	htx_to_buf(htx, &htx_buf);

	cs = cs_new(qcs->qcc->conn, qcs->qcc->conn->target);
	cs->ctx = qcs;
	stream_create_from_cs(cs, &htx_buf);

	b_del(rxbuf, b_data(rxbuf));
	b_free(&htx_buf);

	return 0;
}

static struct buffer *mux_get_buf(struct qcs *qcs)
{
	if (!b_size(&qcs->tx.buf))
		b_alloc(&qcs->tx.buf);

	return &qcs->tx.buf;
}

static size_t hq_interop_snd_buf(struct conn_stream *cs, struct buffer *buf,
                                 size_t count, int flags)
{
	struct qcs *qcs = cs->ctx;
	struct htx *htx;
	enum htx_blk_type btype;
	struct htx_blk *blk;
	int32_t idx;
	uint32_t bsize, fsize;
	struct buffer *res, outbuf;
	size_t total = 0;

	htx = htx_from_buf(buf);
	res = mux_get_buf(qcs);
	outbuf = b_make(b_tail(res), b_contig_space(res), 0, 0);

	while (count && !htx_is_empty(htx)) {
		/* Not implemented : QUIC on backend side */
		idx = htx_get_head(htx);
		blk = htx_get_blk(htx, idx);
		btype = htx_get_blk_type(blk);
		fsize = bsize = htx_get_blksz(blk);

		BUG_ON(btype == HTX_BLK_REQ_SL);

		switch (btype) {
		case HTX_BLK_DATA:
			if (fsize > count)
				fsize = count;
			b_putblk(&outbuf, htx_get_blk_ptr(htx, blk), fsize);
			total += fsize;
			count -= fsize;

			if (fsize == bsize)
				htx_remove_blk(htx, blk);
			else
				htx_cut_data_blk(htx, blk, fsize);
			break;

		/* only body is transfered on HTTP/0.9 */
		case HTX_BLK_RES_SL:
		case HTX_BLK_TLR:
		case HTX_BLK_EOT:
		default:
			htx_remove_blk(htx, blk);
			total += bsize;
			count -= bsize;
			break;
		}
	}

	if ((htx->flags & HTX_FL_EOM) && htx_is_empty(htx))
		qcs->flags |= QC_SF_FIN_STREAM;

	b_add(res, b_data(&outbuf));

	if (total) {
		if (!(qcs->qcc->wait_event.events & SUB_RETRY_SEND))
			tasklet_wakeup(qcs->qcc->wait_event.tasklet);
	}

	return total;
}

const struct qcc_app_ops hq_interop_ops = {
	.decode_qcs = hq_interop_decode_qcs,
	.snd_buf    = hq_interop_snd_buf,
};
