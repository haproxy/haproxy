#include <haproxy/hq_interop.h>

#include <import/ist.h>
#include <haproxy/buf.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/htx.h>
#include <haproxy/http.h>
#include <haproxy/istbuf.h>
#include <haproxy/mux_quic.h>
#include <haproxy/qcm_http.h>
#include <haproxy/qcm_trace.h>
#include <haproxy/quic_utils.h>
#include <haproxy/trace.h>

static void hq_trace_req(struct ist meth, struct ist path, uint64_t mask,
                         const struct ist trc_loc, const char *func,
                         struct qcs *qcs, struct qcc *qcc);

static void hq_trace_resp(struct ist status, uint64_t mask,
                          const struct ist trc_loc, const char *func,
                          struct qcs *qcs, struct qcc *qcc);

static void hq_trace_hdr(struct ist name, struct ist value, uint64_t mask,
                         const struct ist trc_loc, const char *func,
                         struct qcs *qcs, struct qcc *qcc);

/* HTTP/0.9 request -> HTX. */
static ssize_t hq_interop_rcv_buf_req(struct qcs *qcs, struct buffer *b, int fin)
{
	struct htx *htx;
	struct htx_sl *sl;
	struct buffer htx_buf = BUF_NULL;
	struct ist meth, path;
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
		if (b_size(b) - b_room(b) >= qcm_stream_rx_bufsz()) {
			fprintf(stderr, "content too big\n");
			return -1;
		}

		fprintf(stderr, "truncated stream\n");
		return 0;
	}

	ptr++;
	if (!--data) {
		if (b_size(b) - b_room(b) >= qcm_stream_rx_bufsz()) {
			fprintf(stderr, "content too big\n");
			return -1;
		}

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
		if (b_size(b) - b_room(b) >= qcm_stream_rx_bufsz()) {
			fprintf(stderr, "content too big\n");
			return -1;
		}

		fprintf(stderr, "truncated stream\n");
		return 0;
	}

	path.len = ptr - path.ptr;

	b_alloc(&htx_buf, DB_MUX_RX);
	htx = htx_from_buf(&htx_buf);

	meth = ist("GET");
	sl = htx_add_stline(htx, HTX_BLK_REQ_SL, 0, meth, path, ist("HTTP/1.0"));
	if (!sl) {
		b_free(&htx_buf);
		return -1;
	}

	sl->flags |= HTX_SL_F_BODYLESS;
	sl->info.req.meth = find_http_meth(istptr(meth), 3);

	htx_add_endof(htx, HTX_BLK_EOH);
	htx->flags |= HTX_FL_EOM;
	htx_to_buf(htx, &htx_buf);

	hq_trace_req(meth, path, QMUX_EV_QCC_RECV, ist(TRC_LOC), __FUNCTION__, qcs, qcs->qcc);

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
	const unsigned int flags = HTX_SL_F_VER_11|HTX_SL_F_XFER_LEN;
	size_t to_copy = b_data(b);
	size_t htx_sent = 0;
	uint32_t htx_space;
	struct ist status;
	char h, t, u;
	char *head;

	htx_buf = qcc_get_stream_rxbuf(qcs);
	BUG_ON(!htx_buf);
	htx = htx_from_buf(htx_buf);

	if (htx_is_empty(htx) && !qcs->rx.offset) {
		status = ist("200");
		h = status.ptr[0] - '0';
		t = status.ptr[1] - '0';
		u = status.ptr[2] - '0';

		/* First data transfer, add HTX response start-line first. */
		sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags,
		                    ist("HTTP/1.0"), status, ist(""));
		BUG_ON(!sl);
		sl->info.res.status = h * 100 + t * 10 + u;
		if (fin && !to_copy)
			sl->flags |= HTX_SL_F_BODYLESS;
		htx_add_endof(htx, HTX_BLK_EOH);

		hq_trace_resp(status, QMUX_EV_QCC_RECV, ist(TRC_LOC), __FUNCTION__, qcs, qcs->qcc);
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
		head = b_head(b);
 retry:
		htx_space = htx_free_data_space(htx);
		if (!htx_space) {
			qcs->flags |= QC_SF_DEM_FULL;
			goto out;
		}

		if (to_copy > htx_space) {
			to_copy = htx_space;
			fin = 0;
		}

		if (head + to_copy > b_wrap(b)) {
			size_t contig = b_wrap(b) - head;
			htx_sent = htx_add_data(htx, ist2(b_head(b), contig));
			if (htx_sent < contig) {
				qcs->flags |= QC_SF_DEM_FULL;
				goto out;
			}

			to_copy -= contig;
			head = b_orig(b);
			goto retry;
		}

		htx_sent = htx_add_data(htx, ist2(b_head(b), to_copy));
		if (htx_sent < to_copy) {
			qcs->flags |= QC_SF_DEM_FULL;
			goto out;
		}

		if (fin && to_copy == htx_sent)
			htx->flags |= HTX_FL_EOM;
	}

 out:
	htx_to_buf(htx, htx_buf);
	return htx_sent;
}

/* Returns the amount of decoded bytes from <b> or a negative error code. */
static ssize_t hq_interop_rcv_buf(struct qcs *qcs, struct buffer *b, int fin)
{
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
	struct http_uri_parser uri_parser;
	int32_t idx;
	uint32_t bsize, fsize;
	struct buffer *res = NULL;
	struct ist meth, path;
	size_t total = 0;
	struct ist status;
	char sts[4];
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
			meth = ist("GET");
			uri_parser = http_uri_parser_init(htx_sl_req_uri(sl));
			path = http_parse_path(&uri_parser);
			chunk_appendf(res, "%.*s %.*s\r\n",
			              (uint)istlen(meth), istptr(meth),
			              (uint)istlen(path), istptr(path));
			htx_remove_blk(htx, blk);
			total += fsize;

			hq_trace_req(meth, path, QMUX_EV_STRM_SEND, ist(TRC_LOC), __FUNCTION__, qcs, qcs->qcc);
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
			sl = htx_get_blk_ptr(htx, blk);
			if (!(sl->flags & HTX_SL_F_XFER_LEN))
				qcs->flags |= QC_SF_UNKNOWN_PL_LENGTH;
			htx_remove_blk(htx, blk);

			status = ist(ultoa_r(sl->info.res.status, sts, sizeof(sts)));
			hq_trace_resp(status, QMUX_EV_STRM_SEND, ist(TRC_LOC), __FUNCTION__, qcs, qcs->qcc);

			total += bsize;
			count -= bsize;
			break;

		case HTX_BLK_HDR:
			hq_trace_hdr(htx_get_blk_name(htx, blk),
			             htx_get_blk_value(htx, blk),
			             QMUX_EV_STRM_SEND, ist(TRC_LOC), __FUNCTION__, qcs, qcs->qcc);
			__fallthrough;
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

static void hq_interop_lclose(struct qcs *qcs, enum qcc_app_ops_lclose_mode mode)
{
	switch (mode) {
	case QCC_APP_OPS_LCLO_MODE_NORMAL:
		qcs->flags |= QC_SF_FIN_STREAM;
		qcc_send_stream(qcs, 0, 0);
		break;

	case QCC_APP_OPS_LCLO_MODE_ABORT:
		qcc_reset_stream(qcs, 0, se_tevt_type_cancelled);
		break;

	case QCC_APP_OPS_LCLO_MODE_KILL_CONN:
		qcc_reset_stream(qcs, 0, se_tevt_type_cancelled);
		if (!(qcs->qcc->flags & (QC_CF_ERR_CONN|QC_CF_ERRL)))
			qcc_set_error(qcs->qcc, 0, 0, muxc_tevt_type_graceful_shut);
		break;

	case QCC_APP_OPS_LCLO_MODE_READ:
		qcc_abort_stream_read(qcs, 0);
		break;
	}
}

static void _hq_trace_http(const char *line, uint64_t mask,
                           const struct ist trc_loc, const char *func,
                           struct qcs *qcs, struct qcc *qcc)
{
	const char *c_str __maybe_unused;
	const char *s_str __maybe_unused;

	c_str = chunk_newstr(&trash);
	if (qcc)
		chunk_appendf(&trash, "qcc=%p(%c)", qcc, (qcc->flags & QC_CF_IS_BACK) ? 'B' : 'F');

	s_str = chunk_newstr(&trash);
	if (qcs)
		chunk_appendf(&trash, " qcs=%p(%llu)", qcs, (ullong)qcs->id);

	TRACE_PRINTF_LOC(TRACE_LEVEL_USER, mask, trc_loc, func,
	                 qcs->qcc->conn, qcs, 0, 0,
	                 "%s%s %s %s", c_str, s_str,
	                 mask & QMUX_EV_STRM_SEND ? "sndh" : "rcvh", line);
}

static void hq_trace_req(struct ist meth, struct ist path, uint64_t mask,
                         const struct ist trc_loc, const char *func,
                         struct qcs *qcs, struct qcc *qcc)
{
	const char *line __maybe_unused;

	if (TRACE_ENABLED(TRACE_LEVEL_USER, mask, qcs->qcc->conn, qcs, 0, 0)) {
		chunk_reset(&trash);
		line = chunk_newstr(&trash);
		chunk_appendf(&trash, "HTTP/0.9 req: %.*s %.*s",
		              (uint)istlen(meth), istptr(meth),
		              (uint)istlen(path), istptr(path));

		_hq_trace_http(line, mask, trc_loc, func, qcs, qcc);
	}
}

static void hq_trace_resp(struct ist status, uint64_t mask,
                          const struct ist trc_loc, const char *func,
                          struct qcs *qcs, struct qcc *qcc)
{
	const char *line __maybe_unused;

	if (TRACE_ENABLED(TRACE_LEVEL_USER, mask, qcs->qcc->conn, qcs, 0, 0)) {
		chunk_reset(&trash);
		line = chunk_newstr(&trash);
		chunk_appendf(&trash, "HTTP/0.9 resp (%.*s)",
		              (uint)istlen(status), istptr(status));

		_hq_trace_http(line, mask, trc_loc, func, qcs, qcc);
	}
}

static void hq_trace_hdr(struct ist name, struct ist value, uint64_t mask,
                         const struct ist trc_loc, const char *func,
                         struct qcs *qcs, struct qcc *qcc)
{
	const char *line __maybe_unused;

	if (TRACE_ENABLED(TRACE_LEVEL_USER, mask, qcs->qcc->conn, qcs, 0, 0)) {
		chunk_reset(&trash);
		line = chunk_newstr(&trash);
		chunk_appendf(&trash, "HTTP/0.9 (%.*s: %.*s)",
		              (uint)istlen(name), istptr(name),
		              (uint)istlen(value), istptr(value));

		_hq_trace_http(line, mask, trc_loc, func, qcs, qcc);
	}
}

const struct qcc_app_ops hq_interop_ops = {
	.alpn       = "hq-interop",

	.rcv_buf    = hq_interop_rcv_buf,
	.snd_buf    = hq_interop_snd_buf,
	.nego_ff    = hq_interop_nego_ff,
	.done_ff    = hq_interop_done_ff,
	.attach     = hq_interop_attach,
	.lclose     = hq_interop_lclose,
};
