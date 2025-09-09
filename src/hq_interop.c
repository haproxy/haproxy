#include <haproxy/hq_interop.h>

#include <import/ist.h>
#include <haproxy/buf.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/htx.h>
#include <haproxy/http.h>
#include <haproxy/istbuf.h>
#include <haproxy/mux_quic.h>
#include <haproxy/qmux_http.h>
#include <haproxy/qmux_trace.h>
#include <haproxy/quic_utils.h>
#include <haproxy/trace.h>

/* HTTP/0.9 request -> HTX. */
static ssize_t hq_interop_rcv_buf_req(struct qcs *qcs, struct buffer *b, int fin)
{
	struct htx *htx;
	struct htx_sl *sl;
	struct buffer htx_buf = BUF_NULL;
	struct ist path;
	char *ptr = b_head(b);
	size_t data = b_data(b);

	/* hq-interop parser does not support buffer wrapping. */
	BUG_ON(b_data(b) != b_contig_data(b, 0));

	if (!b_data(b) && fin && quic_stream_is_bidi(qcs->id)) {
		if (qcs_http_handle_standalone_fin(qcs))
			return -1;
		return 0;
	}

	/* skip method */
	while (data && HTTP_IS_TOKEN(*ptr)) {
		ptr++;
		data--;
	}

	if (!data || !HTTP_IS_SPHT(*ptr)) {
		fprintf(stderr, "truncated stream\n");
		return 0;
	}

	ptr++;
	if (!--data) {
		fprintf(stderr, "truncated stream\n");
		return 0;
	}

	if (HTTP_IS_LWS(*ptr)) {
		fprintf(stderr, "malformed stream\n");
		return -1;
	}

	/* extract path */
	path.ptr = ptr;
	while (data && !HTTP_IS_LWS(*ptr)) {
		ptr++;
		data--;
	}

	if (!data) {
		fprintf(stderr, "truncated stream\n");
		return 0;
	}

	path.len = ptr - path.ptr;

	b_alloc(&htx_buf, DB_MUX_RX);
	htx = htx_from_buf(&htx_buf);

	sl = htx_add_stline(htx, HTX_BLK_REQ_SL, 0, ist("GET"), path, ist("HTTP/1.0"));
	if (!sl) {
		b_free(&htx_buf);
		return -1;
	}

	sl->flags |= HTX_SL_F_BODYLESS;
	sl->info.req.meth = find_http_meth("GET", 3);

	htx_add_endof(htx, HTX_BLK_EOH);
	htx->flags |= HTX_FL_EOM;
	htx_to_buf(htx, &htx_buf);

	if (qcs_attach_sc(qcs, &htx_buf, fin)) {
		b_free(&htx_buf);
		return -1;
	}

	b_free(&htx_buf);

	return b_data(b);
}

/* HTTP/0.9 response -> HTX. */
static ssize_t hq_interop_rcv_buf_res(struct qcs *qcs, struct buffer *b, int fin)
{
	struct htx *htx;
	struct htx_sl *sl;
	struct buffer *htx_buf;
	const struct stream *strm = __sc_strm(qcs->sd->sc);
	const unsigned int flags = HTX_SL_F_VER_11|HTX_SL_F_XFER_LEN;
	size_t to_copy = b_data(b);
	size_t htx_sent = 0;
	uint32_t htx_space;

	htx_buf = qcc_get_stream_rxbuf(qcs);
	BUG_ON(!htx_buf);
	htx = htx_from_buf(htx_buf);

	if (htx_is_empty(htx) && !strm->res.total) {
		/* First data transfer, add HTX response start-line first. */
		sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags,
		                    ist("HTTP/1.0"), ist("200"), ist(""));
		BUG_ON(!sl);
		sl->info.res.status = 200;
		if (fin && !to_copy)
			sl->flags |= HTX_SL_F_BODYLESS;
		htx_add_endof(htx, HTX_BLK_EOH);
	}

	if (!to_copy) {
		if (fin && quic_stream_is_bidi(qcs->id)) {
			if (qcs_http_handle_standalone_fin(qcs)) {
				htx_to_buf(htx, htx_buf);
				return -1;
			}
		}
	}
	else {
		BUG_ON(b_head(b) + to_copy > b_wrap(b)); /* TODO */

		htx_space = htx_free_data_space(htx);
		if (to_copy > htx_space) {
			to_copy = htx_space;
			fin = 0;
		}

		htx_sent = htx_add_data(htx, ist2(b_head(b), to_copy));
		BUG_ON(htx_sent < to_copy); /* TODO */

		if (fin && to_copy == htx_sent)
			htx->flags |= HTX_FL_EOM;
	}

	htx_to_buf(htx, htx_buf);
	return htx_sent;
}

/* Returns the amount of decoded bytes from <b> or a negative error code. */
static ssize_t hq_interop_rcv_buf(struct qcs *qcs, struct buffer *b, int fin)
{
	/* hq-interop parser does not support buffer wrapping. */
	BUG_ON(b_data(b) != b_contig_data(b, 0));

	return !(qcs->qcc->flags & QC_CF_IS_BACK) ?
	  hq_interop_rcv_buf_req(qcs, b, fin) :
	  hq_interop_rcv_buf_res(qcs, b, fin);
}

/* Returns the amount of consumed bytes from <buf>. */
static size_t hq_interop_snd_buf(struct qcs *qcs, struct buffer *buf,
                                 size_t count, char *fin)
{
	enum htx_blk_type btype;
	struct htx *htx = NULL;
	struct htx_blk *blk;
	struct htx_sl *sl = NULL;
	int32_t idx;
	uint32_t bsize, fsize;
	struct buffer *res = NULL;
	size_t total = 0;
	char eom;
	int err;

	*fin = 0;
	htx = htx_from_buf(buf);
	/* EOM is saved here, useful if 0-copy is performed with HTX buf. */
	eom = htx->flags & HTX_FL_EOM;

	while (count && !htx_is_empty(htx) && qcc_stream_can_send(qcs)) {
		/* Not implemented : QUIC on backend side */
		idx = htx_get_head(htx);
		blk = htx_get_blk(htx, idx);
		btype = htx_get_blk_type(blk);
		fsize = bsize = htx_get_blksz(blk);

		switch (btype) {
		case HTX_BLK_REQ_SL:
			res = qcc_get_stream_txbuf(qcs, &err, 0);
			if (!res) {
				BUG_ON(err); /* TODO */
				goto end;
			}

			BUG_ON_HOT(sl); /* Only one start-line expected */
			sl = htx_get_blk_ptr(htx, blk);

			/* Only GET supported for HTTP/0.9. */
			b_putist(res, ist("GET "));
			b_putist(res, htx_sl_req_uri(sl));
			b_putist(res, ist("\r\n"));
			htx_remove_blk(htx, blk);
			total += fsize;
			break;

		case HTX_BLK_DATA:
			res = qcc_get_stream_txbuf(qcs, &err, 0);
			if (!res) {
				if (err)
					ABORT_NOW();
				goto end;
			}

			if (unlikely(fsize == count &&
				     !b_data(res) &&
				     htx_nbblks(htx) == 1 && btype == HTX_BLK_DATA)) {
				void *old_area = res->area;

				TRACE_DATA("perform zero-copy DATA transfer", QMUX_EV_STRM_SEND,
					   qcs->qcc->conn, qcs);

				/* remap MUX buffer to HTX area */
				*res = b_make(buf->area, buf->size,
					      sizeof(struct htx) + blk->addr, fsize);

				/* assign old MUX area to HTX buffer. */
				buf->area = old_area;
				buf->data = buf->head = 0;
				total += fsize;

				/* reload HTX with empty buffer. */
				*htx = *htx_from_buf(buf);
				goto end;
			}

			if (fsize > count)
				fsize = count;

			if (b_contig_space(res) < fsize)
				fsize = b_contig_space(res);

			if (!fsize) {
				/* Release buf and restart parsing if sending still possible. */
				qcc_release_stream_txbuf(qcs);
				continue;
			}

			b_putblk(res, htx_get_blk_ptr(htx, blk), fsize);
			total += fsize;
			count -= fsize;

			if (fsize == bsize)
				htx_remove_blk(htx, blk);
			else
				htx_cut_data_blk(htx, blk, fsize);
			break;

		/* only body is transferred on HTTP/0.9 */
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

 end:
	if (eom && htx_is_empty(htx))
		*fin = 1;
	htx_to_buf(htx, buf);

	return total;
}

static size_t hq_interop_nego_ff(struct qcs *qcs, size_t count)
{
	int err, ret = 0;
	struct buffer *res;

 start:
	res = qcc_get_stream_txbuf(qcs, &err, 0);
	if (!res) {
		if (err)
			ABORT_NOW();
		qcs->sd->iobuf.flags |= IOBUF_FL_FF_BLOCKED;
		goto end;
	}

	if (!b_room(res)) {
		if (qcc_release_stream_txbuf(qcs)) {
			qcs->sd->iobuf.flags |= IOBUF_FL_FF_BLOCKED;
			goto end;
		}

		goto start;
	}

	/* No header required for HTTP/0.9, no need to reserve an offset. */
	qcs->sd->iobuf.buf = res;
	qcs->sd->iobuf.offset = 0;
	qcs->sd->iobuf.data = 0;

	ret = MIN(count, b_contig_space(res));
 end:
	return ret;
}

static size_t hq_interop_done_ff(struct qcs *qcs)
{
	/* No header required for HTTP/0.9. */
	return qcs->sd->iobuf.data;
}

static int hq_interop_attach(struct qcs *qcs, void *conn_ctx)
{
	qcs_wait_http_req(qcs);
	return 0;
}

const struct qcc_app_ops hq_interop_ops = {
	.rcv_buf    = hq_interop_rcv_buf,
	.snd_buf    = hq_interop_snd_buf,
	.nego_ff    = hq_interop_nego_ff,
	.done_ff    = hq_interop_done_ff,
	.attach     = hq_interop_attach,
};
