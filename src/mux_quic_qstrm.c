#include <haproxy/mux_quic_qstrm.h>

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/connection.h>
#include <haproxy/mux_quic.h>
#include <haproxy/mux_quic_priv.h>
#include <haproxy/proxy.h>
#include <haproxy/qmux_trace.h>
#include <haproxy/quic_fctl.h>
#include <haproxy/quic_frame.h>
#include <haproxy/trace.h>

/* Returns true if <frm> type can be used for QMux protocol. */
static int qstrm_is_frm_valid(const struct quic_frame *frm)
{
	return frm->type == QUIC_FT_PADDING ||
	  frm->type == QUIC_FT_RESET_STREAM ||
	  frm->type == QUIC_FT_STOP_SENDING ||
	  (frm->type >= QUIC_FT_STREAM_8 && frm->type <= QUIC_FT_STREAM_F) ||
	  frm->type == QUIC_FT_MAX_DATA ||
	  frm->type == QUIC_FT_MAX_STREAM_DATA ||
	  frm->type == QUIC_FT_MAX_STREAMS_BIDI ||
	  frm->type == QUIC_FT_MAX_STREAMS_UNI ||
	  frm->type == QUIC_FT_DATA_BLOCKED ||
	  frm->type == QUIC_FT_STREAM_DATA_BLOCKED ||
	  frm->type == QUIC_FT_STREAMS_BLOCKED_BIDI ||
	  frm->type == QUIC_FT_STREAMS_BLOCKED_UNI ||
	  frm->type == QUIC_FT_CONNECTION_CLOSE ||
	  frm->type == QUIC_FT_CONNECTION_CLOSE_APP;
}

/* Parse the next frame in <buf> and handle it by the MUX layer.
 *
 * Returns the frame length on success. If frame is truncated, 0 is returned.
 * A negative error code is used for fatal failures.
 */
static int qstrm_parse_frm(struct qcc *qcc, struct buffer *buf)
{
	struct quic_frame frm;
	const unsigned char *pos, *old, *end;
	int ret;

	old = pos = (unsigned char *)b_head(buf);
	end = (unsigned char *)b_head(buf) + b_data(buf);
	ret = qc_parse_frm_type(&frm, &pos, end, NULL);
	if (!ret)
		return 0;

	if (!qstrm_is_frm_valid(&frm)) {
		/* TODO close connection with FRAME_ENCODING_ERROR */
		b_reset(buf);
		return -1;
	}

	ret = qc_parse_frm_payload(&frm, &pos, end, NULL);
	if (!ret)
		return 0;

	if (frm.type >= QUIC_FT_STREAM_8 &&
	    frm.type <= QUIC_FT_STREAM_F) {
		struct qf_stream *strm_frm = &frm.stream;

		qcc_recv(qcc, strm_frm->id, strm_frm->len, strm_frm->offset,
		         (frm.type & QUIC_STREAM_FRAME_TYPE_FIN_BIT), (char *)strm_frm->data);
	}
	else if (frm.type == QUIC_FT_RESET_STREAM) {
		struct qf_reset_stream *rst_frm = &frm.reset_stream;
		qcc_recv_reset_stream(qcc, rst_frm->id, rst_frm->app_error_code, rst_frm->final_size);
	}
	else if (frm.type == QUIC_FT_MAX_DATA) {
		struct qf_max_data *md_frm = &frm.max_data;
		qcc_recv_max_data(qcc, md_frm->max_data);
	}
	else if (frm.type == QUIC_FT_MAX_STREAM_DATA) {
		struct qf_max_stream_data *msd_frm = &frm.max_stream_data;
		qcc_recv_max_stream_data(qcc, msd_frm->id, msd_frm->max_stream_data);
	}
	else if (frm.type == QUIC_FT_DATA_BLOCKED ||
	         frm.type == QUIC_FT_STREAM_DATA_BLOCKED ||
	         frm.type == QUIC_FT_STREAMS_BLOCKED_BIDI ||
	         frm.type == QUIC_FT_STREAMS_BLOCKED_UNI) {
	        /* TODO */
	}
	else {
		ABORT_NOW();
	}

	return pos - old;
}

/* Perform data reception for <qcc> connection. Content is parsed as QMux
 * frames. These operations are performed in loop until read returns no data.
 *
 * Returns the total amount of read data or -1 on error.
 */
int qcc_qstrm_recv(struct qcc *qcc)
{
	struct connection *conn = qcc->conn;
	struct buffer *buf = &qcc->rx.qstrm_buf;
	struct buffer buf_rec;
	int total = 0, frm_ret;
	size_t ret = 1;

	TRACE_ENTER(QMUX_EV_QCC_RECV, qcc->conn);

	do {
 recv:
		/* Wrapping is not supported for QMux reception. */
		BUG_ON(b_data(buf) != b_contig_data(buf, 0));

		/* If current record is too big, realign buffer for more room. */
		if (b_head(buf) + qcc->rx.rlen > b_wrap(buf)) {
			BUG_ON(qcc->rx.rlen > b_size(buf)); /* TODO max_record_size */
			memmove(b_orig(buf), b_head(buf), b_data(buf));
			buf->head = 0;
		}
		else {
			/* Ensure maximum room is always available. */
			b_realign_if_empty(buf);
		}

		if ((!b_data(buf) && !qcc->rx.rlen) || qcc->rx.rlen > b_data(buf)) {
			/* Previous realign operation should ensure send cannot result in data wrapping. */
			BUG_ON(b_data(buf) && b_tail(buf) == b_orig(buf));
			ret = conn->xprt->rcv_buf(conn, conn->xprt_ctx, buf, b_contig_space(buf), NULL, 0, 0);
			BUG_ON(conn->flags & CO_FL_ERROR); /* TODO handle errors */
			/* Previous realign operation should ensure send cannot result in data wrapping. */
			BUG_ON(b_data(buf) != b_contig_data(buf, 0));
		}

		if (b_data(buf) && !qcc->rx.rlen) {
			int ret2 = b_quic_dec_int(&qcc->rx.rlen, buf, NULL);
			BUG_ON(!ret2); /* TODO incomplete record length */
			if (b_head(buf) + qcc->rx.rlen > b_wrap(buf))
				goto recv;
			BUG_ON(b_data(buf) < qcc->rx.rlen); /* TODO incomplete record */
		}

		/* TODO realign necessary if record boundary at the extreme end of the buffer */
		BUG_ON(!qcc->rx.rlen && b_data(buf) && b_tail(buf) == b_orig(buf));

		while (qcc->rx.rlen && b_data(buf) >= qcc->rx.rlen) {
			buf_rec = b_make(b_orig(buf), b_size(buf),
			                 b_head_ofs(buf), qcc->rx.rlen);
			frm_ret = qstrm_parse_frm(qcc, &buf_rec);

			BUG_ON(frm_ret < 0); /* TODO handle fatal errors */
			if (!frm_ret) {
				/* emit FRAME_ENCODING_ERROR */
				ABORT_NOW();
			}

			/* A frame cannot be bigger than a record thanks to <buf_rec> delimitation. */
			BUG_ON(qcc->rx.rlen < frm_ret);
			b_del(buf, frm_ret);
			qcc->rx.rlen -= frm_ret;
			total += frm_ret;
		}
	} while (ret > 0);

	if (!conn_xprt_read0_pending(qcc->conn)) {
		conn->xprt->subscribe(conn, conn->xprt_ctx, SUB_RETRY_RECV,
		                      &qcc->wait_event);
	}

	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
	return total;

 err:
	return -1;
}

/* Updates a <qcs> stream after a successful emission of data of length <data>. */
static void qstrm_ctrl_send(struct qcs *qcs, uint64_t data)
{
	struct qcc *qcc = qcs->qcc;
	struct quic_fctl *fc_conn = &qcc->tx.fc;
	struct quic_fctl *fc_strm = &qcs->tx.fc;

	TRACE_ENTER(QMUX_EV_QCS_SEND, qcc->conn, qcs);

	qcs_idle_open(qcs);

	/* Ensure real offset never exceeds soft value. */
	BUG_ON(fc_conn->off_real + data > fc_conn->off_soft);
	BUG_ON(fc_strm->off_real + data > fc_strm->off_soft);

	/* increase offset on connection */
	if (qfctl_rinc(fc_conn, data)) {
		TRACE_STATE("connection flow-control reached",
		            QMUX_EV_QCS_SEND, qcc->conn);
	}

	/* increase offset on stream */
	if (qfctl_rinc(fc_strm, data)) {
		TRACE_STATE("stream flow-control reached",
		            QMUX_EV_QCS_SEND, qcc->conn, qcs);
	}

	b_del(&qcs->tx.qstrm_buf, data);
	/* Release buffer if everything sent and stream is waiting for room. */
	if (!qcs_prep_bytes(qcs) && (qcs->flags & QC_SF_BLK_MROOM)) {
		qcs->flags &= ~QC_SF_BLK_MROOM;
		qcs_notify_send(qcs);
	}

	/* Add measurement for send rate. This is done at the MUX layer
	 * to account only for STREAM frames without retransmission.
	 */
	increment_send_rate(data, 0);

	if (!qcs_prep_bytes(qcs)) {
		/* Remove stream from send_list if all was sent. */
		LIST_DEL_INIT(&qcs->el_send);
		TRACE_STATE("stream sent done", QMUX_EV_QCS_SEND, qcc->conn, qcs);

		if (qcs->flags & (QC_SF_FIN_STREAM|QC_SF_DETACH)) {
			/* Close stream locally. */
			qcs_close_local(qcs);

			if (qcs->flags & QC_SF_FIN_STREAM) {
				/* Reset flag to not emit multiple FIN STREAM frames. */
				qcs->flags &= ~QC_SF_FIN_STREAM;
			}

			if (qcs_is_completed(qcs)) {
				TRACE_STATE("add stream in purg_list", QMUX_EV_QCS_SEND, qcc->conn, qcs);
				LIST_APPEND(&qcc->purg_list, &qcs->el_send);
			}
		}
	}

	TRACE_LEAVE(QMUX_EV_QCS_SEND, qcc->conn, qcs);
}

/* Sends <frms> list of frames for <qcc> connection.
 *
 * Returns 0 if all data are emitted or a positive value if sending should be
 * retry later. A negative error code is used for a fatal failure.
 */
int qcc_qstrm_send_frames(struct qcc *qcc, struct list *frms)
{
	struct connection *conn = qcc->conn;
	struct quic_frame *frm, *frm_old;
	struct quic_frame *split_frm, *next_frm;
	struct buffer *buf = &qcc->tx.qstrm_buf;
	unsigned char *pos, *old, *end;
	size_t sent;
	int ret, lensz, enc;

	TRACE_ENTER(QMUX_EV_QCC_SEND, qcc->conn);

	/* Record size field length */
	lensz = quic_int_getsize(quic_int_cap_length(b_size(buf)));

	/* Purge buffer first if remaining data to send. */
	if (b_data(buf)) {
		sent = conn->xprt->snd_buf(conn, conn->xprt_ctx, buf, b_data(buf), NULL, 0, 0);
		if (!sent) {
			TRACE_DEVEL("snd_buf interrupted", QMUX_EV_QCC_SEND, qcc->conn);
			goto out;
		}

		if (sent != b_data(buf)) {
			/* TODO */
			ABORT_NOW();
		}
	}

	list_for_each_entry_safe(frm, frm_old, frms, list) {
 loop:
		split_frm = next_frm = NULL;
		b_reset(buf);
		/* Reserve bytes for the record header. */
		old = pos = (unsigned char *)b_orig(buf) + lensz;
		end = (unsigned char *)b_wrap(buf);

		BUG_ON(!frm);
		TRACE_PRINTF(TRACE_LEVEL_DEVELOPER, QMUX_EV_QCC_SEND, qcc->conn, 0, 0, 0,
		             "frm type %02llx", (ullong)frm->type);

		if (frm->type >= QUIC_FT_STREAM_8 && frm->type <= QUIC_FT_STREAM_F) {
			size_t flen, split_size;

			flen = quic_strm_frm_fillbuf(end - pos, frm, &split_size);
			if (!flen)
				continue;

			if (split_size) {
				split_frm = quic_strm_frm_split(frm, split_size);
				if (!split_frm) {
					ABORT_NOW();
					continue;
				}

				next_frm = frm;
				frm = split_frm;
			}
		}

		qc_build_frm(frm, &pos, end, NULL);
		BUG_ON(pos - old > global.tune.bufsize);
		BUG_ON(pos == old);

		/* Encode record header and save built payload. */
		enc = b_quic_enc_int(buf, pos - old, lensz);
		BUG_ON(!enc); /* Cannot fail as space already reserved earlier. */
		b_add(buf, pos - old);

		sent = conn->xprt->snd_buf(conn, conn->xprt_ctx, buf, b_data(buf), NULL, 0, 0);
		if (!sent) {
			TRACE_DEVEL("snd_buf interrupted", QMUX_EV_QCC_SEND, qcc->conn);
			if (split_frm)
				LIST_INSERT(frms, &split_frm->list);
			break;
		}

		/* TODO */
		BUG_ON(sent != b_data(buf));

		if (frm->type >= QUIC_FT_STREAM_8 && frm->type <= QUIC_FT_STREAM_F)
			qstrm_ctrl_send(frm->stream.stream, frm->stream.len);

		LIST_DEL_INIT(&frm->list);
		if (split_frm) {
			frm = next_frm;
			goto loop;
		}
	}

 out:
	if (conn->flags & CO_FL_ERROR) {
		/* TODO */
	}
	else if (!LIST_ISEMPTY(frms)) {
		if (!(qcc->wait_event.events & SUB_RETRY_SEND))
			conn->xprt->subscribe(conn, conn->xprt_ctx, SUB_RETRY_SEND, &qcc->wait_event);
		ret = 1;
	}
	else {
		ret = 0;
	}

	TRACE_LEAVE(QMUX_EV_QCC_SEND, qcc->conn);
	return ret;
}
