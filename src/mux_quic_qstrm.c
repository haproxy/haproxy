#include <haproxy/mux_quic_qstrm.h>

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/connection.h>
#include <haproxy/mux_quic.h>
#include <haproxy/qmux_trace.h>
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
	int total = 0, frm_ret;
	size_t ret;

	TRACE_ENTER(QMUX_EV_QCC_RECV, qcc->conn);

	do {
 recv:
		/* Wrapping is not supported for QMux reception. */
		BUG_ON(b_data(buf) != b_contig_data(buf, 0));

		/* Checks if there is no more room before wrapping position. */
		if (b_head(buf) + b_contig_data(buf, 0) == b_wrap(buf)) {
			if (!b_room(buf)) {
				/* TODO frame bigger than buffer, connection must be closed */
				ABORT_NOW();
			}

			/* Realign data in the buffer to have more room. */
			memmove(b_orig(buf), b_head(buf), b_data(buf));
			buf->head = 0;
		}
		else {
			/* Ensure maximum room is always available. */
			b_realign_if_empty(buf);
		}

		ret = conn->xprt->rcv_buf(conn, conn->xprt_ctx, buf, b_contig_space(buf), NULL, 0, 0);
		BUG_ON(conn->flags & CO_FL_ERROR);

		total += ret;
		while (b_data(buf)) {
			frm_ret = qstrm_parse_frm(qcc, buf);

			BUG_ON(frm_ret < 0); /* TODO handle fatal errors */
			if (!frm_ret) {
				/* Checks if wrapping position is reached, requires realign. */
				if (b_head(buf) + b_contig_data(buf, 0) == b_wrap(buf))
					goto recv;
				/* Truncated frame read but room still left, subscribe to retry later. */
				break;
			}

			b_del(buf, frm_ret);
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
