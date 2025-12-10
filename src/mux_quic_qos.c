#include <haproxy/mux_quic_qos.h>

#include <stdio.h>

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/connection.h>
#include <haproxy/mux_quic.h>
#include <haproxy/qmux_trace.h>
#include <haproxy/quic_fctl.h>
#include <haproxy/quic_frame.h>
#include <haproxy/trace.h>

int qcc_qos_recv(struct qcc *qcc)
{
	struct connection *conn = qcc->conn;
	struct quic_frame frm;
	const unsigned char *pos, *end;
	int ret;

	TRACE_ENTER(QMUX_EV_QCC_RECV, qcc->conn);

	chunk_reset(&trash);
	ret = conn->xprt->rcv_buf(conn, conn->xprt_ctx, &trash, trash.size, NULL, 0, 0);
	BUG_ON(ret < 0);

	if (ret) {
		b_add(&trash, ret);

		pos = (unsigned char *)b_head(&trash);
		end = (unsigned char *)b_tail(&trash);
		ret = qc_parse_frm(&frm, NULL, &pos, end, NULL);
		BUG_ON(!ret);

		if (frm.type == QUIC_FT_QS_TP) {
			struct qf_qs_tp *qs_tp_frm = &frm.qs_tp;
			fprintf(stderr, "got qs_transport_parameters frame\n");
			fprintf(stderr, "  max_idle_timeout=%llu\n", (ullong)qs_tp_frm->tps.max_idle_timeout);
			fprintf(stderr, "  initial_max_data=%llu\n", (ullong)qs_tp_frm->tps.initial_max_data);
			qfctl_set_max(&qcc->tx.fc, qs_tp_frm->tps.initial_max_data, NULL, NULL);
			fprintf(stderr, "  initial_max_stream_data_bidi_local=%llu\n", (ullong)qs_tp_frm->tps.initial_max_stream_data_bidi_local);
			qcc->rfctl.msd_bidi_l = qs_tp_frm->tps.initial_max_stream_data_bidi_local;
			fprintf(stderr, "  initial_max_stream_data_bidi_remote=%llu\n", (ullong)qs_tp_frm->tps.initial_max_stream_data_bidi_remote);
			qcc->rfctl.msd_bidi_r = qs_tp_frm->tps.initial_max_stream_data_bidi_remote;
			fprintf(stderr, "  initial_max_stream_data_uni=%llu\n", (ullong)qs_tp_frm->tps.initial_max_stream_data_uni);
			qcc->rfctl.msd_uni_l = qs_tp_frm->tps.initial_max_stream_data_uni;
			fprintf(stderr, "  initial_max_streams_bidi=%llu\n", (ullong)qs_tp_frm->tps.initial_max_streams_bidi);
			fprintf(stderr, "  initial_max_streams_uni=%llu\n", (ullong)qs_tp_frm->tps.initial_max_streams_uni);
		}
		else if (frm.type >= QUIC_FT_STREAM_8 &&
		         frm.type <= QUIC_FT_STREAM_F) {
			struct qf_stream *strm_frm = &frm.stream;

		        qcc_recv(qcc, strm_frm->id, strm_frm->len, strm_frm->offset,
		                 (frm.type & QUIC_STREAM_FRAME_TYPE_FIN_BIT), (char *)strm_frm->data);
		}
		else if (frm.type == QUIC_FT_RESET_STREAM) {
			struct qf_reset_stream *rst_frm = &frm.reset_stream;
			qcc_recv_reset_stream(qcc, rst_frm->id, rst_frm->app_error_code, rst_frm->final_size);
		}
		else {
			ABORT_NOW();
		}

	}
	else {
		BUG_ON(!trash.size);
		if (!conn_xprt_read0_pending(qcc->conn)) {
			conn->xprt->subscribe(conn, conn->xprt_ctx, SUB_RETRY_RECV,
			                      &qcc->wait_event);
		}
	}

	TRACE_LEAVE(QMUX_EV_QCC_RECV, qcc->conn);
	return ret;

 err:
	return -1;
}
