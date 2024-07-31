#ifndef _HAPROXY_QMUX_TRACE_H
#define _HAPROXY_QMUX_TRACE_H

#ifdef USE_QUIC

#include <haproxy/api-t.h>
#include <haproxy/buf.h>
#include <haproxy/trace.h>

struct qcc;
struct qcs;

extern struct trace_source trace_qmux;
#define TRACE_SOURCE    &trace_qmux

static const struct trace_event qmux_trace_events[] = {
#define           QMUX_EV_QCC_NEW       (1ULL << 0)
	{ .mask = QMUX_EV_QCC_NEW ,     .name = "qcc_new",     .desc = "new QUIC connection" },
#define           QMUX_EV_QCC_RECV      (1ULL << 1)
	{ .mask = QMUX_EV_QCC_RECV,     .name = "qcc_recv",     .desc = "Rx on QUIC connection" },
#define           QMUX_EV_QCC_SEND      (1ULL << 2)
	{ .mask = QMUX_EV_QCC_SEND,     .name = "qcc_send",     .desc = "Tx on QUIC connection" },
#define           QMUX_EV_QCC_WAKE      (1ULL << 3)
	{ .mask = QMUX_EV_QCC_WAKE,     .name = "qcc_wake",     .desc = "QUIC connection woken up" },
#define           QMUX_EV_QCC_END       (1ULL << 4)
	{ .mask = QMUX_EV_QCC_END,      .name = "qcc_end",      .desc = "QUIC connection terminated" },
#define           QMUX_EV_QCC_NQCS      (1ULL << 5)
	{ .mask = QMUX_EV_QCC_NQCS,     .name = "qcc_no_qcs",   .desc = "QUIC stream not found" },
#define           QMUX_EV_QCS_NEW       (1ULL << 6)
	{ .mask = QMUX_EV_QCS_NEW,      .name = "qcs_new",      .desc = "new QUIC stream" },
#define           QMUX_EV_QCS_RECV      (1ULL << 7)
	{ .mask = QMUX_EV_QCS_RECV,     .name = "qcs_recv",     .desc = "Rx on QUIC stream" },
#define           QMUX_EV_QCS_SEND      (1ULL << 8)
	{ .mask = QMUX_EV_QCS_SEND,     .name = "qcs_send",     .desc = "Tx on QUIC stream" },
#define           QMUX_EV_QCS_END       (1ULL << 9)
	{ .mask = QMUX_EV_QCS_END,      .name = "qcs_end",      .desc = "QUIC stream terminated" },
#define           QMUX_EV_STRM_RECV     (1ULL << 10)
	{ .mask = QMUX_EV_STRM_RECV,    .name = "strm_recv",    .desc = "receiving data for stream" },
#define           QMUX_EV_STRM_SEND     (1ULL << 11)
	{ .mask = QMUX_EV_STRM_SEND,    .name = "strm_send",    .desc = "sending data for stream" },
#define           QMUX_EV_STRM_WAKE     (1ULL << 12)
	{ .mask = QMUX_EV_STRM_WAKE,    .name = "strm_wake",    .desc = "stream woken up" },
#define           QMUX_EV_STRM_SHUT     (1ULL << 13)
	{ .mask = QMUX_EV_STRM_SHUT,    .name = "strm_shut",    .desc = "stream shutdown" },
#define           QMUX_EV_STRM_END      (1ULL << 14)
	{ .mask = QMUX_EV_STRM_END,     .name = "strm_end",     .desc = "detaching app-layer stream" },
#define           QMUX_EV_SEND_FRM      (1ULL << 15)
	{ .mask = QMUX_EV_SEND_FRM,     .name = "send_frm",     .desc = "sending QUIC frame" },
/* special event dedicated to qcs_xfer_data */
#define           QMUX_EV_QCS_XFER_DATA  (1ULL << 16)
	{ .mask = QMUX_EV_QCS_XFER_DATA,  .name = "qcs_xfer_data", .desc = "qcs_xfer_data" },
/* special event dedicated to qcs_build_stream_frm */
#define           QMUX_EV_QCS_BUILD_STRM (1ULL << 17)
	{ .mask = QMUX_EV_QCS_BUILD_STRM, .name = "qcs_build_stream_frm", .desc = "qcs_build_stream_frm" },
#define           QMUX_EV_PROTO_ERR     (1ULL << 18)
	{ .mask = QMUX_EV_PROTO_ERR,    .name = "proto_err",    .desc = "protocol error" },
#define           QMUX_EV_QCC_ERR       (1ULL << 19)
	{ .mask = QMUX_EV_QCC_ERR,      .name = "qcc_err",      .desc = "connection on error" },
	{ }
};

/* custom arg for QMUX_EV_QCS_XFER_DATA */
struct qcs_xfer_data_trace_arg {
	size_t prep;
	int xfer;
};

/* custom arg for QMUX_EV_QCS_BUILD_STRM */
struct qcs_build_stream_trace_arg {
	size_t len;
	char fin;
	uint64_t offset;
};

void qmux_dump_qcc_info(struct buffer *msg, const struct qcc *qcc);
void qmux_dump_qcs_info(struct buffer *msg, const struct qcs *qcs);

#endif /* USE_QUIC */

#endif /* _HAPROXY_QMUX_TRACE_H */
