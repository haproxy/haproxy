/*
 * HTTP/3 protocol processing
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

#include <import/ist.h>

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/h3.h>
#include <haproxy/h3_stats.h>
#include <haproxy/http.h>
#include <haproxy/http-hdr-t.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/intops.h>
#include <haproxy/istbuf.h>
#include <haproxy/mux_quic.h>
#include <haproxy/pool.h>
#include <haproxy/qmux_http.h>
#include <haproxy/qpack-dec.h>
#include <haproxy/qpack-enc.h>
#include <haproxy/quic_enc.h>
#include <haproxy/quic_fctl.h>
#include <haproxy/quic_frame.h>
#include <haproxy/stats-t.h>
#include <haproxy/tools.h>
#include <haproxy/trace.h>

/* trace source and events */
static void h3_trace(enum trace_level level, uint64_t mask,
                     const struct trace_source *src,
                     const struct ist where, const struct ist func,
                     const void *a1, const void *a2, const void *a3, const void *a4);

static const struct trace_event h3_trace_events[] = {
#define           H3_EV_RX_FRAME      (1ULL <<  0)
	{ .mask = H3_EV_RX_FRAME,     .name = "rx_frame",    .desc = "receipt of any H3 frame" },
#define           H3_EV_RX_DATA       (1ULL <<  1)
	{ .mask = H3_EV_RX_DATA,      .name = "rx_data",     .desc = "receipt of H3 DATA frame" },
#define           H3_EV_RX_HDR        (1ULL <<  2)
	{ .mask = H3_EV_RX_HDR,       .name = "rx_hdr",      .desc = "receipt of H3 HEADERS frame" },
#define           H3_EV_RX_SETTINGS   (1ULL <<  3)
	{ .mask = H3_EV_RX_SETTINGS,  .name = "rx_settings", .desc = "receipt of H3 SETTINGS frame" },
#define           H3_EV_TX_FRAME      (1ULL <<  4)
	{ .mask = H3_EV_TX_FRAME,     .name = "tx_frame",    .desc = "transmission of any H3 frame" },
#define           H3_EV_TX_DATA       (1ULL <<  5)
	{ .mask = H3_EV_TX_DATA,      .name = "tx_data",     .desc = "transmission of H3 DATA frame" },
#define           H3_EV_TX_HDR        (1ULL <<  6)
	{ .mask = H3_EV_TX_HDR,       .name = "tx_hdr",      .desc = "transmission of H3 HEADERS frame" },
#define           H3_EV_TX_SETTINGS   (1ULL <<  7)
	{ .mask = H3_EV_TX_SETTINGS,  .name = "tx_settings", .desc = "transmission of H3 SETTINGS frame" },
#define           H3_EV_H3S_NEW       (1ULL <<  8)
	{ .mask = H3_EV_H3S_NEW,      .name = "h3s_new",     .desc = "new H3 stream" },
#define           H3_EV_H3S_END       (1ULL <<  9)
	{ .mask = H3_EV_H3S_END,      .name = "h3s_end",     .desc = "H3 stream terminated" },
#define           H3_EV_H3C_NEW       (1ULL << 10)
	{ .mask = H3_EV_H3C_NEW,      .name = "h3c_new",     .desc = "new H3 connection" },
#define           H3_EV_H3C_END       (1ULL << 11)
	{ .mask = H3_EV_H3C_END,      .name = "h3c_end",     .desc = "H3 connection terminated" },
#define           H3_EV_STRM_SEND     (1ULL << 12)
	{ .mask = H3_EV_STRM_SEND,    .name = "strm_send",   .desc = "sending data for stream" },
	{ }
};

static const struct name_desc h3_trace_lockon_args[4] = {
	/* arg1 */ { /* already used by the connection */ },
	/* arg2 */ { .name="qcs", .desc="QUIC stream" },
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct name_desc h3_trace_decoding[] = {
#define H3_VERB_CLEAN    1
	{ .name="clean",    .desc="only user-friendly stuff, generally suitable for level \"user\"" },
#define H3_VERB_MINIMAL  2
	{ .name="minimal",  .desc="report only qcc/qcs state and flags, no real decoding" },
	{ /* end */ }
};

struct trace_source trace_h3 = {
	.name = IST("h3"),
	.desc = "HTTP/3 transcoder",
	.arg_def = TRC_ARG1_CONN,  /* TRACE()'s first argument is always a connection */
	.default_cb = h3_trace,
	.known_events = h3_trace_events,
	.lockon_args = h3_trace_lockon_args,
	.decoding = h3_trace_decoding,
	.report_events = ~0,  /* report everything by default */
};

#define TRACE_SOURCE    &trace_h3
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

#if defined(DEBUG_H3)
#define h3_debug_printf fprintf
#define h3_debug_hexdump debug_hexdump
#else
#define h3_debug_printf(...) do { } while (0)
#define h3_debug_hexdump(...) do { } while (0)
#endif

#define H3_CF_SETTINGS_SENT     0x00000001  /* SETTINGS frame already sent on local control stream */
#define H3_CF_SETTINGS_RECV     0x00000002  /* SETTINGS frame already received on remote control stream */
#define H3_CF_UNI_CTRL_SET      0x00000004  /* Remote H3 Control stream opened */
#define H3_CF_UNI_QPACK_DEC_SET 0x00000008  /* Remote QPACK decoder stream opened */
#define H3_CF_UNI_QPACK_ENC_SET 0x00000010  /* Remote QPACK encoder stream opened */
#define H3_CF_GOAWAY_SENT       0x00000020  /* GOAWAY sent on local control stream */

/* Default settings */
static uint64_t h3_settings_qpack_max_table_capacity = 0;
static uint64_t h3_settings_qpack_blocked_streams = 4096;
static uint64_t h3_settings_max_field_section_size = QUIC_VARINT_8_BYTE_MAX; /* Unlimited */

struct h3c {
	struct qcc *qcc;
	struct qcs *ctrl_strm; /* Control stream */
	int err;
	uint32_t flags;

	/* Settings */
	uint64_t qpack_max_table_capacity;
	uint64_t qpack_blocked_streams;
	uint64_t max_field_section_size;

	uint64_t id_goaway; /* stream ID used for a GOAWAY frame */

	struct buffer_wait buf_wait; /* wait list for buffer allocations */
	/* Stats counters */
	struct h3_counters *prx_counters;
};

DECLARE_STATIC_POOL(pool_head_h3c, "h3c", sizeof(struct h3c));

#define H3_SF_UNI_INIT  0x00000001  /* stream type not parsed for unidirectional stream */
#define H3_SF_UNI_NO_H3 0x00000002  /* unidirectional stream does not carry H3 frames */
#define H3_SF_HAVE_CLEN 0x00000004  /* content-length header is present */

struct h3s {
	struct h3c *h3c;

	enum h3s_t type;
	enum h3s_st_req st_req; /* only used for request streams */
	uint64_t demux_frame_len;
	uint64_t demux_frame_type;

	unsigned long long body_len; /* known request body length from content-length header if present */
	unsigned long long data_len; /* total length of all parsed DATA */

	int flags;
	int err; /* used for stream reset */
};

DECLARE_STATIC_POOL(pool_head_h3s, "h3s", sizeof(struct h3s));

/* Initialize an uni-stream <qcs> by reading its type from <b>.
 *
 * Returns the count of consumed bytes or a negative error code.
 */
static ssize_t h3_init_uni_stream(struct h3c *h3c, struct qcs *qcs,
                                  struct buffer *b)
{
	/* decode unidirectional stream type */
	struct h3s *h3s = qcs->ctx;
	uint64_t type;
	size_t len = 0, ret;

	TRACE_ENTER(H3_EV_H3S_NEW, qcs->qcc->conn, qcs);

	/* Function reserved to uni streams. Must be called only once per stream instance. */
	BUG_ON(!quic_stream_is_uni(qcs->id) || h3s->flags & H3_SF_UNI_INIT);

	ret = b_quic_dec_int(&type, b, &len);
	if (!ret) {
		/* not enough data to decode uni stream type, retry later */
		TRACE_DATA("cannot decode uni stream type due to incomplete data", H3_EV_H3S_NEW, qcs->qcc->conn, qcs);
		goto out;
	}

	switch (type) {
	case H3_UNI_S_T_CTRL:
		if (h3c->flags & H3_CF_UNI_CTRL_SET) {
			TRACE_ERROR("duplicated control stream", H3_EV_H3S_NEW, qcs->qcc->conn, qcs);
			qcc_set_error(qcs->qcc, H3_ERR_STREAM_CREATION_ERROR, 1);
			qcc_report_glitch(qcs->qcc, 1);
			goto err;
		}
		h3c->flags |= H3_CF_UNI_CTRL_SET;
		h3s->type = H3S_T_CTRL;
		break;

	case H3_UNI_S_T_PUSH:
		/* TODO not supported for the moment */
		h3s->type = H3S_T_PUSH;
		break;

	case H3_UNI_S_T_QPACK_DEC:
		if (h3c->flags & H3_CF_UNI_QPACK_DEC_SET) {
			TRACE_ERROR("duplicated qpack decoder stream", H3_EV_H3S_NEW, qcs->qcc->conn, qcs);
			qcc_set_error(qcs->qcc, H3_ERR_STREAM_CREATION_ERROR, 1);
			qcc_report_glitch(qcs->qcc, 1);
			goto err;
		}
		h3c->flags |= H3_CF_UNI_QPACK_DEC_SET;
		h3s->type = H3S_T_QPACK_DEC;
		h3s->flags |= H3_SF_UNI_NO_H3;
		break;

	case H3_UNI_S_T_QPACK_ENC:
		if (h3c->flags & H3_CF_UNI_QPACK_ENC_SET) {
			TRACE_ERROR("duplicated qpack encoder stream", H3_EV_H3S_NEW, qcs->qcc->conn, qcs);
			qcc_set_error(qcs->qcc, H3_ERR_STREAM_CREATION_ERROR, 1);
			qcc_report_glitch(qcs->qcc, 1);
			goto err;
		}
		h3c->flags |= H3_CF_UNI_QPACK_ENC_SET;
		h3s->type = H3S_T_QPACK_ENC;
		h3s->flags |= H3_SF_UNI_NO_H3;
		break;

	default:
		/* draft-ietf-quic-http34 9. Extensions to HTTP/3
		 *
		 * Implementations MUST [...] abort reading on unidirectional
		 * streams that have unknown or unsupported types.
		 */
		TRACE_STATE("abort reading on unknown uni stream type", H3_EV_H3S_NEW, qcs->qcc->conn, qcs);
		qcc_abort_stream_read(qcs);
		goto err;
	}

	h3s->flags |= H3_SF_UNI_INIT;

 out:
	TRACE_LEAVE(H3_EV_H3S_NEW, qcs->qcc->conn, qcs);
	return len;

 err:
	TRACE_DEVEL("leaving on error", H3_EV_H3S_NEW, qcs->qcc->conn, qcs);
	return -1;
}

/* Parse a buffer <b> for a <qcs> uni-stream which does not contains H3 frames.
 * This may be used for QPACK encoder/decoder streams for example. <fin> is set
 * if this is the last frame of the stream.
 *
 * Returns the number of consumed bytes or a negative error code.
 */
static ssize_t h3_parse_uni_stream_no_h3(struct qcs *qcs, struct buffer *b, int fin)
{
	struct h3s *h3s = qcs->ctx;

	/* Function reserved to non-HTTP/3 unidirectional streams. */
	BUG_ON(!quic_stream_is_uni(qcs->id) || !(h3s->flags & H3_SF_UNI_NO_H3));

	switch (h3s->type) {
	case H3S_T_QPACK_DEC:
		if (qpack_decode_dec(b, fin, qcs))
			return -1;
		break;
	case H3S_T_QPACK_ENC:
		if (qpack_decode_enc(b, fin, qcs))
			return -1;
		break;
	case H3S_T_UNKNOWN:
	default:
		/* Unknown stream should be flagged with QC_SF_READ_ABORTED. */
		ABORT_NOW();
	}

	/* TODO adjust return code */
	return 0;
}

/* Decode a H3 frame header from <rxbuf> buffer. The frame type is stored in
 * <ftype> and length in <flen>.
 *
 * Returns the size of the H3 frame header. Note that the input buffer is not
 * consumed.
 */
static inline size_t h3_decode_frm_header(uint64_t *ftype, uint64_t *flen,
                                          struct buffer *b)
{
	size_t hlen;

	hlen = 0;
	if (!b_quic_dec_int(ftype, b, &hlen) ||
	    !b_quic_dec_int(flen, b, &hlen)) {
		return 0;
	}

	return hlen;
}

/* Check if H3 frame of type <ftype> is valid when received on stream <qcs>.
 *
 * Returns 0 if frame valid, otherwise HTTP/3 error code.
 */
static int h3_check_frame_valid(struct h3c *h3c, struct qcs *qcs, uint64_t ftype)
{
	struct h3s *h3s = qcs->ctx;
	int ret = 0;

	/* Stream type must be known to ensure frame is valid for this stream. */
	BUG_ON(h3s->type == H3S_T_UNKNOWN);

	switch (ftype) {
	case H3_FT_DATA:
		/* cf H3_FT_HEADERS case. */
		if (h3s->type == H3S_T_CTRL ||
		    (h3s->st_req != H3S_ST_REQ_HEADERS && h3s->st_req != H3S_ST_REQ_DATA)) {
			ret = H3_ERR_FRAME_UNEXPECTED;
		}

		break;

	case H3_FT_HEADERS:
		/* RFC 9114 4.1. HTTP Message Framing
		 *
		 *
		 * An HTTP message (request or response) consists of:
		 * 1. the header section, including message control data, sent as a
		 *    single HEADERS frame,
		 * 2. optionally, the content, if present, sent as a series of DATA
		 *    frames, and
		 * 3. optionally, the trailer section, if present, sent as a single
		 *    HEADERS frame.
		 *
		 * [...]
		 *
		 *  Receipt of an invalid sequence of frames MUST be treated as a
		 *  connection error of type H3_FRAME_UNEXPECTED. In particular, a DATA
		 *  frame before any HEADERS frame, or a HEADERS or DATA frame after the
		 *  trailing HEADERS frame, is considered invalid. Other frame types,
		 *  especially unknown frame types, might be permitted subject to their
		 *  own rules; see Section 9.
		 */
		if (h3s->type == H3S_T_CTRL || h3s->st_req == H3S_ST_REQ_TRAILERS)
			ret = H3_ERR_FRAME_UNEXPECTED;
		break;

	case H3_FT_CANCEL_PUSH:
	case H3_FT_GOAWAY:
	case H3_FT_MAX_PUSH_ID:
		/* RFC 9114 7.2.3. CANCEL_PUSH
		 *
		 * A CANCEL_PUSH frame is sent on the control stream. Receiving a
		 * CANCEL_PUSH frame on a stream other than the control stream MUST be
		 * treated as a connection error of type H3_FRAME_UNEXPECTED.
		 */

		/* RFC 9114 7.2.6. GOAWAY
		 *
		 * A client MUST treat a GOAWAY frame on a stream other than the
		 * control stream as a connection error of type H3_FRAME_UNEXPECTED.
		 */

		/* RFC 9114 7.2.7. MAX_PUSH_ID
		 *
		 * The MAX_PUSH_ID frame is always sent on the control stream. Receipt
		 * of a MAX_PUSH_ID frame on any other stream MUST be treated as a
		 * connection error of type H3_FRAME_UNEXPECTED.
		 */

		if (h3s->type != H3S_T_CTRL)
			ret = H3_ERR_FRAME_UNEXPECTED;
		else if (!(h3c->flags & H3_CF_SETTINGS_RECV))
			ret = H3_ERR_MISSING_SETTINGS;
		break;

	case H3_FT_SETTINGS:
		/* RFC 9114 7.2.4. SETTINGS
		 *
		 * A SETTINGS frame MUST be sent as the first frame of
		 * each control stream (see Section 6.2.1) by each peer, and it MUST NOT
		 * be sent subsequently. If an endpoint receives a second SETTINGS frame
		 * on the control stream, the endpoint MUST respond with a connection
		 * error of type H3_FRAME_UNEXPECTED.
		 *
		 * SETTINGS frames MUST NOT be sent on any stream other than the control
		 * stream. If an endpoint receives a SETTINGS frame on a different
		 * stream, the endpoint MUST respond with a connection error of type
		 * H3_FRAME_UNEXPECTED.
		 */
		if (h3s->type != H3S_T_CTRL || h3c->flags & H3_CF_SETTINGS_RECV)
			ret = H3_ERR_FRAME_UNEXPECTED;
		break;

	case H3_FT_PUSH_PROMISE:
		/* RFC 9114 7.2.5. PUSH_PROMISE
		 *
		 * A client MUST NOT send a PUSH_PROMISE frame. A server MUST treat the
		 * receipt of a PUSH_PROMISE frame as a connection error of type
		 * H3_FRAME_UNEXPECTED.
		 */

		/* TODO server-side only. */
		ret = H3_ERR_FRAME_UNEXPECTED;
		break;

	default:
		/* RFC 9114 9. Extensions to HTTP/3
		 *
		 * Implementations MUST ignore unknown or unsupported values in all
		 * extensible protocol elements. [...]
		 * However, where a known frame type is required to be in a
		 * specific location, such as the SETTINGS frame as the first frame of
		 * the control stream (see Section 6.2.1), an unknown frame type does
		 * not satisfy that requirement and SHOULD be treated as an error.
		 */
		if (h3s->type == H3S_T_CTRL && !(h3c->flags & H3_CF_SETTINGS_RECV))
			ret = H3_ERR_MISSING_SETTINGS;
		break;
	}

	return ret;
}

/* Check from stream <qcs> that length of all DATA frames does not exceed with
 * a previously parsed content-length header. <fin> must be set for the last
 * data of the stream so that length of DATA frames must be equal to the
 * content-length.
 *
 * This must only be called for a stream with H3_SF_HAVE_CLEN flag.
 *
 * Return 0 on valid else non-zero.
 */
static int h3_check_body_size(struct qcs *qcs, int fin)
{
	struct h3s *h3s = qcs->ctx;
	int ret = 0;
	TRACE_ENTER(H3_EV_RX_FRAME, qcs->qcc->conn, qcs);

	/* Reserved for streams with a previously parsed content-length header. */
	BUG_ON(!(h3s->flags & H3_SF_HAVE_CLEN));

	/* RFC 9114 4.1.2. Malformed Requests and Responses
	 *
	 * A request or response that is defined as having content when it
	 * contains a Content-Length header field (Section 8.6 of [HTTP]) is
	 * malformed if the value of the Content-Length header field does not
	 * equal the sum of the DATA frame lengths received.
	 *
	 * TODO for backend support
	 * A response that is
	 * defined as never having content, even when a Content-Length is
	 * present, can have a non-zero Content-Length header field even though
	 * no content is included in DATA frames.
	 */
	if (h3s->data_len > h3s->body_len ||
	    (fin && h3s->data_len < h3s->body_len)) {
		TRACE_ERROR("Content-length does not match DATA frame size", H3_EV_RX_FRAME|H3_EV_RX_DATA, qcs->qcc->conn, qcs);
		h3s->err = H3_ERR_MESSAGE_ERROR;
		qcc_report_glitch(qcs->qcc, 1);
		ret = -1;
	}

	TRACE_LEAVE(H3_EV_RX_FRAME, qcs->qcc->conn, qcs);
	return ret;
}

/* Set <auth> authority header to the new value <value> for <qcs> stream. This
 * ensures that value is conformant to the specification. If <auth> is a
 * non-null length string, it ensures that <value> is identical to it.
 *
 * Returns 0 on success else non-zero.
 */
static int h3_set_authority(struct qcs *qcs, struct ist *auth, const struct ist value)
{
	/* RFC 9114 4.3.1. Request Pseudo-Header Fields
	 *
	 * If the :scheme pseudo-header field identifies a scheme that has a
	 * mandatory authority component (including "http" and "https"), the
	 * request MUST contain either an :authority pseudo-header field or a
	 * Host header field. If these fields are present, they MUST NOT be
	 * empty. If both fields are present, they MUST contain the same value.
	 */

	/* Check that if a previous value is set the new value is identical. */
	if (isttest(*auth) && !isteq(*auth, value)) {
		TRACE_ERROR("difference between :authority and host headers", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
		return 1;
	}

	/* Check that value is not empty. */
	if (!istlen(value)) {
		TRACE_ERROR("empty :authority/host header", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
		return 1;
	}

	*auth = value;
	return 0;
}

/* Parse from buffer <buf> a H3 HEADERS frame of length <len>. Data are copied
 * in a local HTX buffer and transfer to the stream connector layer. <fin> must be
 * set if this is the last data to transfer from this stream.
 *
 * Returns the number of consumed bytes or a negative error code. On error
 * either the connection should be closed or the stream reset using codes
 * provided in h3c.err / h3s.err.
 */
static ssize_t h3_headers_to_htx(struct qcs *qcs, const struct buffer *buf,
                                 uint64_t len, char fin)
{
	struct h3s *h3s = qcs->ctx;
	struct h3c *h3c = h3s->h3c;
	struct buffer htx_buf = BUF_NULL;
	struct buffer *tmp = get_trash_chunk();
	struct htx *htx = NULL;
	struct htx_sl *sl;
	struct http_hdr list[global.tune.max_http_hdr * 2];
	unsigned int flags = HTX_SL_F_NONE;
	struct ist meth = IST_NULL, path = IST_NULL;
	struct ist scheme = IST_NULL, authority = IST_NULL;
	int hdr_idx, ret;
	int cookie = -1, last_cookie = -1, i;
	const char *ctl;
	int relaxed = !!(h3c->qcc->proxy->options2 & PR_O2_REQBUG_OK);
	int qpack_err;

	/* RFC 9114 4.1.2. Malformed Requests and Responses
	 *
	 * A malformed request or response is one that is an otherwise valid
	 * sequence of frames but is invalid due to:
	 * - the presence of prohibited fields or pseudo-header fields,
	 * - the absence of mandatory pseudo-header fields,
	 * - invalid values for pseudo-header fields,
	 * - pseudo-header fields after fields,
	 * - an invalid sequence of HTTP messages,
	 * - the inclusion of uppercase field names, or
	 * - the inclusion of invalid characters in field names or values.
	 *
	 * [...]
	 *
	 * Intermediaries that process HTTP requests or responses (i.e., any
	 * intermediary not acting as a tunnel) MUST NOT forward a malformed
	 * request or response. Malformed requests or responses that are
	 * detected MUST be treated as a stream error of type H3_MESSAGE_ERROR.
	 */

	TRACE_ENTER(H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);

	/* TODO support trailer parsing in this function */

	/* TODO support buffer wrapping */
	BUG_ON(b_head(buf) + len >= b_wrap(buf));
	ret = qpack_decode_fs((const unsigned char *)b_head(buf), len, tmp,
	                    list, sizeof(list) / sizeof(list[0]));
	if (ret < 0) {
		TRACE_ERROR("QPACK decoding error", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
		if ((qpack_err = qpack_err_decode(ret)) >= 0) {
			h3c->err = qpack_err;
			qcc_report_glitch(qcs->qcc, 1);
		}
		len = -1;
		goto out;
	}

	if (!b_alloc(&htx_buf, DB_SE_RX)) {
		TRACE_ERROR("HTX buffer alloc failure", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
		len = -1;
		goto out;
	}
	BUG_ON(!b_size(&htx_buf)); /* TODO */
	htx = htx_from_buf(&htx_buf);

	/* first treat pseudo-header to build the start line */
	hdr_idx = 0;
	while (1) {
		/* RFC 9114 4.3. HTTP Control Data
		 *
		 * Endpoints MUST treat a request or response that contains
		 * undefined or invalid pseudo-header fields as malformed.
		 *
		 * All pseudo-header fields MUST appear in the header section before
		 * regular header fields. Any request or response that contains a
		 * pseudo-header field that appears in a header section after a regular
		 * header field MUST be treated as malformed.
		 */

		/* Stop at first non pseudo-header. */
		if (!istmatch(list[hdr_idx].n, ist(":")))
			break;

		/* RFC 9114 10.3 Intermediary-Encapsulation Attacks
		 *
		 * While most values that can be encoded will not alter field
		 * parsing, carriage return (ASCII 0x0d), line feed (ASCII 0x0a),
		 * and the null character (ASCII 0x00) might be exploited by an
		 * attacker if they are translated verbatim. Any request or
		 * response that contains a character not permitted in a field
		 * value MUST be treated as malformed
		 */

		/* look for forbidden control characters in the pseudo-header value */
		ctl = ist_find_ctl(list[hdr_idx].v);
		if (unlikely(ctl) && http_header_has_forbidden_char(list[hdr_idx].v, ctl)) {
			TRACE_ERROR("control character present in pseudo-header value", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
			h3s->err = H3_ERR_MESSAGE_ERROR;
			qcc_report_glitch(h3c->qcc, 1);
			len = -1;
			goto out;
		}

		/* pseudo-header. Malformed name with uppercase character or
		 * invalid token will be rejected in the else clause.
		 */
		if (isteq(list[hdr_idx].n, ist(":method"))) {
			if (isttest(meth)) {
				TRACE_ERROR("duplicated method pseudo-header", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
				h3s->err = H3_ERR_MESSAGE_ERROR;
				qcc_report_glitch(h3c->qcc, 1);
				len = -1;
				goto out;
			}

			if (!istlen(list[hdr_idx].v) || http_method_has_forbidden_char(list[hdr_idx].v)) {
				TRACE_ERROR("invalid method pseudo-header", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
				h3s->err = H3_ERR_MESSAGE_ERROR;
				qcc_report_glitch(h3c->qcc, 1);
				len = -1;
				goto out;
			}

			meth = list[hdr_idx].v;
		}
		else if (isteq(list[hdr_idx].n, ist(":path"))) {
			if (isttest(path)) {
				TRACE_ERROR("duplicated path pseudo-header", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
				h3s->err = H3_ERR_MESSAGE_ERROR;
				qcc_report_glitch(h3c->qcc, 1);
				len = -1;
				goto out;
			}

			if (!relaxed) {
				/* we need to reject any control chars or '#' from the path,
				 * unless option accept-unsafe-violations-in-http-request is set.
				 */
				ctl = ist_find_range(list[hdr_idx].v, 0, '#');
				if (unlikely(ctl) && http_path_has_forbidden_char(list[hdr_idx].v, ctl)) {
					TRACE_ERROR("forbidden character in ':path' pseudo-header", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
					h3s->err = H3_ERR_MESSAGE_ERROR;
					qcc_report_glitch(h3c->qcc, 1);
					len = -1;
					goto out;
				}
			}

			path = list[hdr_idx].v;
		}
		else if (isteq(list[hdr_idx].n, ist(":scheme"))) {
			if (isttest(scheme)) {
				/* duplicated pseudo-header */
				TRACE_ERROR("duplicated scheme pseudo-header", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
				h3s->err = H3_ERR_MESSAGE_ERROR;
				qcc_report_glitch(h3c->qcc, 1);
				len = -1;
				goto out;
			}

			if (!http_validate_scheme(list[hdr_idx].v)) {
				TRACE_ERROR("invalid scheme pseudo-header", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
				h3s->err = H3_ERR_MESSAGE_ERROR;
				qcc_report_glitch(h3c->qcc, 1);
				len = -1;
				goto out;
			}

			scheme = list[hdr_idx].v;
		}
		else if (isteq(list[hdr_idx].n, ist(":authority"))) {
			if (isttest(authority)) {
				TRACE_ERROR("duplicated authority pseudo-header", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
				h3s->err = H3_ERR_MESSAGE_ERROR;
				qcc_report_glitch(h3c->qcc, 1);
				len = -1;
				goto out;
			}

			if (h3_set_authority(qcs, &authority, list[hdr_idx].v)) {
				h3s->err = H3_ERR_MESSAGE_ERROR;
				qcc_report_glitch(h3c->qcc, 1);
				len = -1;
				goto out;
			}
		}
		else {
			TRACE_ERROR("unknown pseudo-header", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
			h3s->err = H3_ERR_MESSAGE_ERROR;
			qcc_report_glitch(h3c->qcc, 1);
			len = -1;
			goto out;
		}

		++hdr_idx;
	}

	if (!istmatch(meth, ist("CONNECT"))) {
		/* RFC 9114 4.3.1. Request Pseudo-Header Fields
		 *
		 * All HTTP/3 requests MUST include exactly one value for the :method,
		 * :scheme, and :path pseudo-header fields, unless the request is a
		 * CONNECT request; see Section 4.4.
		 */
		if (!isttest(meth) || !isttest(scheme) || !isttest(path)) {
			TRACE_ERROR("missing mandatory pseudo-header", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
			h3s->err = H3_ERR_MESSAGE_ERROR;
			qcc_report_glitch(h3c->qcc, 1);
			len = -1;
			goto out;
		}
	}

	flags |= HTX_SL_F_VER_11;
	flags |= HTX_SL_F_XFER_LEN;

	sl = htx_add_stline(htx, HTX_BLK_REQ_SL, flags, meth, path, ist("HTTP/3.0"));
	if (!sl) {
		len = -1;
		goto out;
	}

	if (fin)
		sl->flags |= HTX_SL_F_BODYLESS;

	sl->info.req.meth = find_http_meth(meth.ptr, meth.len);

	if (isttest(authority)) {
		if (!htx_add_header(htx, ist("host"), authority)) {
			len = -1;
			goto out;
		}
	}

	/* now treat standard headers */
	while (1) {
		if (isteq(list[hdr_idx].n, ist("")))
			break;

		if (istmatch(list[hdr_idx].n, ist(":"))) {
			TRACE_ERROR("pseudo-header field after fields", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
			h3s->err = H3_ERR_MESSAGE_ERROR;
			qcc_report_glitch(h3c->qcc, 1);
			len = -1;
			goto out;
		}

		for (i = 0; i < list[hdr_idx].n.len; ++i) {
			const char c = list[hdr_idx].n.ptr[i];
			if ((uint8_t)(c - 'A') < 'Z' - 'A' || !HTTP_IS_TOKEN(c)) {
				TRACE_ERROR("invalid characters in field name", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
				h3s->err = H3_ERR_MESSAGE_ERROR;
				qcc_report_glitch(h3c->qcc, 1);
				len = -1;
				goto out;
			}
		}


		/* RFC 9114 10.3 Intermediary-Encapsulation Attacks
		 *
		 * While most values that can be encoded will not alter field
		 * parsing, carriage return (ASCII 0x0d), line feed (ASCII 0x0a),
		 * and the null character (ASCII 0x00) might be exploited by an
		 * attacker if they are translated verbatim. Any request or
		 * response that contains a character not permitted in a field
		 * value MUST be treated as malformed
		 */

		/* look for forbidden control characters in the header value */
		ctl = ist_find_ctl(list[hdr_idx].v);
		if (unlikely(ctl) && http_header_has_forbidden_char(list[hdr_idx].v, ctl)) {
			TRACE_ERROR("control character present in header value", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
			h3s->err = H3_ERR_MESSAGE_ERROR;
			qcc_report_glitch(h3c->qcc, 1);
			len = -1;
			goto out;
		}

		if (isteq(list[hdr_idx].n, ist("host"))) {
			if (h3_set_authority(qcs, &authority, list[hdr_idx].v)) {
				h3s->err = H3_ERR_MESSAGE_ERROR;
				qcc_report_glitch(h3c->qcc, 1);
				len = -1;
				goto out;
			}
		}
		else if (isteq(list[hdr_idx].n, ist("cookie"))) {
			http_cookie_register(list, hdr_idx, &cookie, &last_cookie);
			++hdr_idx;
			continue;
		}
		else if (isteq(list[hdr_idx].n, ist("content-length"))) {
			ret = http_parse_cont_len_header(&list[hdr_idx].v,
			                                 &h3s->body_len,
			                                 h3s->flags & H3_SF_HAVE_CLEN);
			if (ret < 0) {
				TRACE_ERROR("invalid content-length", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
				h3s->err = H3_ERR_MESSAGE_ERROR;
				qcc_report_glitch(h3c->qcc, 1);
				len = -1;
				goto out;
			}
			else if (!ret) {
				/* Skip duplicated value. */
				++hdr_idx;
				continue;
			}

			h3s->flags |= H3_SF_HAVE_CLEN;
			sl->flags |= HTX_SL_F_CLEN;
			/* This will fail if current frame is the last one and
			 * content-length is not null.
			 */
			if (h3_check_body_size(qcs, fin)) {
				len = -1;
				goto out;
			}
		}
		else if (isteq(list[hdr_idx].n, ist("connection")) ||
		         isteq(list[hdr_idx].n, ist("proxy-connection")) ||
		         isteq(list[hdr_idx].n, ist("keep-alive")) ||
		         isteq(list[hdr_idx].n, ist("transfer-encoding"))) {
			/* RFC 9114 4.2. HTTP Fields
		         *
		         * HTTP/3 does not use the Connection header field to indicate
		         * connection-specific fields; in this protocol, connection-
		         * specific metadata is conveyed by other means. An endpoint
		         * MUST NOT generate an HTTP/3 field section containing
		         * connection-specific fields; any message containing
		         * connection-specific fields MUST be treated as malformed.
		         */
			TRACE_ERROR("invalid connection header", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
			h3s->err = H3_ERR_MESSAGE_ERROR;
			qcc_report_glitch(h3c->qcc, 1);
			len = -1;
			goto out;
		}
		else if (isteq(list[hdr_idx].n, ist("te")) &&
		         !isteq(list[hdr_idx].v, ist("trailers"))) {
			/* RFC 9114 4.2. HTTP Fields
			 *
			 * The only exception to this is the TE header field, which MAY
			 * be present in an HTTP/3 request header; when it is, it MUST
			 * NOT contain any value other than "trailers".
			 */
			TRACE_ERROR("invalid te header", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
			h3s->err = H3_ERR_MESSAGE_ERROR;
			qcc_report_glitch(h3c->qcc, 1);
			len = -1;
			goto out;
		}

		if (!htx_add_header(htx, list[hdr_idx].n, list[hdr_idx].v)) {
			len = -1;
			goto out;
		}
		++hdr_idx;
	}

	/* RFC 9114 4.3.1. Request Pseudo-Header Fields
	 *
	 * If the :scheme pseudo-header field identifies a scheme that has a
	 * mandatory authority component (including "http" and "https"), the
	 * request MUST contain either an :authority pseudo-header field or a
	 * Host header field.
	 */
	if (!isttest(authority)) {
		TRACE_ERROR("missing mandatory pseudo-header", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
		h3s->err = H3_ERR_MESSAGE_ERROR;
		qcc_report_glitch(h3c->qcc, 1);
		len = -1;
		goto out;
	}

	if (cookie >= 0) {
		if (http_cookie_merge(htx, list, cookie)) {
			len = -1;
			goto out;
		}
	}

	/* Check the number of blocks agains "tune.http.maxhdr" value before adding EOH block */
	if (htx_nbblks(htx) > global.tune.max_http_hdr) {
		len = -1;
		goto out;
	}

	if (!htx_add_endof(htx, HTX_BLK_EOH)) {
		len = -1;
		goto out;
	}

	if (fin)
		htx->flags |= HTX_FL_EOM;

	htx_to_buf(htx, &htx_buf);
	htx = NULL;

	if (qcs_attach_sc(qcs, &htx_buf, fin)) {
		len = -1;
		goto out;
	}

	/* RFC 9114 5.2. Connection Shutdown
	 *
	 * The GOAWAY frame contains an identifier that
	 * indicates to the receiver the range of requests or pushes that were
	 * or might be processed in this connection.  The server sends a client-
	 * initiated bidirectional stream ID; the client sends a push ID.
	 * Requests or pushes with the indicated identifier or greater are
	 * rejected (Section 4.1.1) by the sender of the GOAWAY.  This
	 * identifier MAY be zero if no requests or pushes were processed.
	 */
	if (qcs->id >= h3c->id_goaway)
		h3c->id_goaway = qcs->id + 4;

 out:
	/* HTX may be non NULL if error before previous htx_to_buf(). */
	if (htx)
		htx_to_buf(htx, &htx_buf);

	/* Buffer is transferred to the stream connector and set to NULL except
	 * on stream creation error or QCS already fully closed.
	 */
	if (b_size(&htx_buf)) {
		b_free(&htx_buf);
		offer_buffers(NULL, 1);
	}

	TRACE_LEAVE(H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
	return len;
}

/* Parse from buffer <buf> a H3 HEADERS frame of length <len> used as trailers.
 * Data are copied in a local HTX buffer and transfer to the stream connector
 * layer. <fin> must be set if this is the last data to transfer from this
 * stream.
 *
 * Returns the number of consumed bytes or a negative error code. On error
 * either the connection should be closed or the stream reset using codes
 * provided in h3c.err / h3s.err.
 */
static ssize_t h3_trailers_to_htx(struct qcs *qcs, const struct buffer *buf,
                                  uint64_t len, char fin)
{
	struct h3s *h3s = qcs->ctx;
	struct h3c *h3c = h3s->h3c;
	struct buffer *tmp = get_trash_chunk();
	struct buffer *appbuf = NULL;
	struct htx *htx = NULL;
	struct htx_sl *sl;
	struct http_hdr list[global.tune.max_http_hdr * 2];
	int hdr_idx, ret;
	const char *ctl;
	int qpack_err;
	int i;

	TRACE_ENTER(H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);

	/* TODO support buffer wrapping */
	BUG_ON(b_head(buf) + len >= b_wrap(buf));
	ret = qpack_decode_fs((const unsigned char *)b_head(buf), len, tmp,
	                    list, sizeof(list) / sizeof(list[0]));
	if (ret < 0) {
		TRACE_ERROR("QPACK decoding error", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
		if ((qpack_err = qpack_err_decode(ret)) >= 0) {
			h3c->err = qpack_err;
			qcc_report_glitch(qcs->qcc, 1);
		}
		len = -1;
		goto out;
	}

	if (!(appbuf = qcc_get_stream_rxbuf(qcs))) {
		TRACE_ERROR("HTX buffer alloc failure", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
		len = -1;
		goto out;
	}
	BUG_ON(!b_size(appbuf)); /* TODO */
	htx = htx_from_buf(appbuf);

	if (!h3s->data_len) {
		/* Notify that no body is present. This can only happens if
		 * there is H3 HEADERS as trailers without or empty H3 DATA
		 * frame. So this is probably not realistice ?
		 *
		 * TODO if sl is NULL because already consumed there is no way
		 * to notify about missing body.
		 */
		sl = http_get_stline(htx);
		if (sl)
			sl->flags |= HTX_SL_F_BODYLESS;
		else
			TRACE_ERROR("cannot notify missing body after trailers", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
	}

	hdr_idx = 0;
	while (1) {
		if (isteq(list[hdr_idx].n, ist("")))
			break;

		/* RFC 9114 4.3. HTTP Control Data
		 *
		 * Pseudo-header
		 * fields MUST NOT appear in trailer sections.
		 */
		if (istmatch(list[hdr_idx].n, ist(":"))) {
			TRACE_ERROR("pseudo-header field in trailers", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
			h3s->err = H3_ERR_MESSAGE_ERROR;
			qcc_report_glitch(h3c->qcc, 1);
			len = -1;
			goto out;
		}

		for (i = 0; i < list[hdr_idx].n.len; ++i) {
			const char c = list[hdr_idx].n.ptr[i];
			if ((uint8_t)(c - 'A') < 'Z' - 'A' || !HTTP_IS_TOKEN(c)) {
				TRACE_ERROR("invalid characters in field name", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
				h3s->err = H3_ERR_MESSAGE_ERROR;
				qcc_report_glitch(h3c->qcc, 1);
				len = -1;
				goto out;
			}
		}

		/* forbidden HTTP/3 headers, cf h3_headers_to_htx() */
		if (isteq(list[hdr_idx].n, ist("host")) ||
		    isteq(list[hdr_idx].n, ist("content-length")) ||
		    isteq(list[hdr_idx].n, ist("connection")) ||
		    isteq(list[hdr_idx].n, ist("proxy-connection")) ||
		    isteq(list[hdr_idx].n, ist("keep-alive")) ||
		    isteq(list[hdr_idx].n, ist("te")) ||
		    isteq(list[hdr_idx].n, ist("transfer-encoding"))) {
			TRACE_ERROR("forbidden HTTP/3 headers", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
			h3s->err = H3_ERR_MESSAGE_ERROR;
			qcc_report_glitch(h3c->qcc, 1);
			len = -1;
			goto out;
		}

		/* RFC 9114 10.3 Intermediary-Encapsulation Attacks
		 *
		 * While most values that can be encoded will not alter field
		 * parsing, carriage return (ASCII 0x0d), line feed (ASCII 0x0a),
		 * and the null character (ASCII 0x00) might be exploited by an
		 * attacker if they are translated verbatim. Any request or
		 * response that contains a character not permitted in a field
		 * value MUST be treated as malformed
		 */

		/* look for forbidden control characters in the trailer value */
		ctl = ist_find_ctl(list[hdr_idx].v);
		if (unlikely(ctl) && http_header_has_forbidden_char(list[hdr_idx].v, ctl)) {
			TRACE_ERROR("control character present in trailer value", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
			h3s->err = H3_ERR_MESSAGE_ERROR;
			qcc_report_glitch(h3c->qcc, 1);
			len = -1;
			goto out;
		}

		if (!htx_add_trailer(htx, list[hdr_idx].n, list[hdr_idx].v)) {
			TRACE_ERROR("cannot add trailer", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
			len = -1;
			goto out;
		}

		++hdr_idx;
	}

	/* Check the number of blocks agains "tune.http.maxhdr" value before adding EOT block */
	if (htx_nbblks(htx) > global.tune.max_http_hdr) {
		len = -1;
		goto out;
	}

	if (!htx_add_endof(htx, HTX_BLK_EOT)) {
		TRACE_ERROR("cannot add trailer", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
		len = -1;
		goto out;
	}

	if (fin)
		htx->flags |= HTX_FL_EOM;

 out:
	/* HTX may be non NULL if error before previous htx_to_buf(). */
	if (appbuf)
		htx_to_buf(htx, appbuf);

	TRACE_LEAVE(H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
	return len;
}

/* Copy from buffer <buf> a H3 DATA frame of length <len> in QUIC stream <qcs>
 * HTX buffer. <fin> must be set if this is the last data to transfer from this
 * stream.
 *
 * Returns the number of consumed bytes or a negative error code.
 */
static ssize_t h3_data_to_htx(struct qcs *qcs, const struct buffer *buf,
                              uint64_t len, char fin)
{
	struct buffer *appbuf;
	struct htx *htx = NULL;
	size_t htx_sent = 0;
	int htx_space;
	char *head;

	TRACE_ENTER(H3_EV_RX_FRAME|H3_EV_RX_DATA, qcs->qcc->conn, qcs);

	if (!(appbuf = qcc_get_stream_rxbuf(qcs))) {
		TRACE_ERROR("data buffer alloc failure", H3_EV_RX_FRAME|H3_EV_RX_DATA, qcs->qcc->conn, qcs);
		goto err;
	}

	htx = htx_from_buf(appbuf);

	if (len > b_data(buf)) {
		len = b_data(buf);
		fin = 0;
	}

	head = b_head(buf);
 retry:
	htx_space = htx_free_data_space(htx);
	if (!htx_space) {
		qcs->flags |= QC_SF_DEM_FULL;
		goto out;
	}

	if (len > htx_space) {
		len = htx_space;
		fin = 0;
	}

	if (head + len > b_wrap(buf)) {
		size_t contig = b_wrap(buf) - head;
		htx_sent = htx_add_data(htx, ist2(b_head(buf), contig));
		if (htx_sent < contig) {
			qcs->flags |= QC_SF_DEM_FULL;
			goto out;
		}

		len -= contig;
		head = b_orig(buf);
		goto retry;
	}

	htx_sent += htx_add_data(htx, ist2(head, len));
	if (htx_sent < len) {
		qcs->flags |= QC_SF_DEM_FULL;
		goto out;
	}

	if (fin && len == htx_sent)
		htx->flags |= HTX_FL_EOM;

 out:
	if (appbuf)
		htx_to_buf(htx, appbuf);

	TRACE_LEAVE(H3_EV_RX_FRAME|H3_EV_RX_DATA, qcs->qcc->conn, qcs);
	return htx_sent;

 err:
	TRACE_DEVEL("leaving on error", H3_EV_RX_FRAME|H3_EV_RX_DATA, qcs->qcc->conn, qcs);
	return -1;
}

/* Parse a SETTINGS frame of length <len> of payload <buf>.
 *
 * Returns the number of consumed bytes or a negative error code.
 */
static ssize_t h3_parse_settings_frm(struct h3c *h3c, const struct buffer *buf,
                                     size_t len)
{
	struct buffer b;
	uint64_t id, value;
	size_t ret = 0;
	long mask = 0;   /* used to detect duplicated settings identifier */

	TRACE_ENTER(H3_EV_RX_FRAME|H3_EV_RX_SETTINGS, h3c->qcc->conn);

	/* Work on a copy of <buf>. */
	b = b_make(b_orig(buf), b_size(buf), b_head_ofs(buf), len);

	while (b_data(&b)) {
		if (!b_quic_dec_int(&id, &b, &ret) || !b_quic_dec_int(&value, &b, &ret)) {
			h3c->err = H3_ERR_FRAME_ERROR;
			qcc_report_glitch(h3c->qcc, 1);
			return -1;
		}

		h3_debug_printf(stderr, "%s id: %llu value: %llu\n",
		                __func__, (unsigned long long)id, (unsigned long long)value);

		/* draft-ietf-quic-http34 7.2.4. SETTINGS
		 *
		 * The same setting identifier MUST NOT occur more than once in the
		 * SETTINGS frame.  A receiver MAY treat the presence of duplicate
		 * setting identifiers as a connection error of type H3_SETTINGS_ERROR.
		 */

		/* Ignore duplicate check for ID too big used for GREASE. */
		if (id < sizeof(mask)) {
			if (ha_bit_test(id, &mask)) {
				h3c->err = H3_ERR_SETTINGS_ERROR;
				qcc_report_glitch(h3c->qcc, 1);
				return -1;
			}
			ha_bit_set(id, &mask);
		}

		switch (id) {
		case H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY:
			h3c->qpack_max_table_capacity = value;
			break;
		case H3_SETTINGS_MAX_FIELD_SECTION_SIZE:
			h3c->max_field_section_size = value;
			break;
		case H3_SETTINGS_QPACK_BLOCKED_STREAMS:
			h3c->qpack_blocked_streams = value;
			break;

		case H3_SETTINGS_RESERVED_0:
		case H3_SETTINGS_RESERVED_2:
		case H3_SETTINGS_RESERVED_3:
		case H3_SETTINGS_RESERVED_4:
		case H3_SETTINGS_RESERVED_5:
			/* draft-ietf-quic-http34 7.2.4.1. Defined SETTINGS Parameters
			 *
			 * Setting identifiers which were defined in [HTTP2] where there is no
			 * corresponding HTTP/3 setting have also been reserved
			 * (Section 11.2.2).  These reserved settings MUST NOT be sent, and
			 * their receipt MUST be treated as a connection error of type
			 * H3_SETTINGS_ERROR.
			 */
			h3c->err = H3_ERR_SETTINGS_ERROR;
			qcc_report_glitch(h3c->qcc, 1);
			return -1;
		default:
			/* MUST be ignored */
			break;
		}
	}

	TRACE_LEAVE(H3_EV_RX_FRAME|H3_EV_RX_SETTINGS, h3c->qcc->conn);
	return ret;
}

/* Transcode HTTP/3 payload received in buffer <b> to HTX data for stream
 * <qcs>. If <fin> is set, it indicates that no more data will arrive after.
 *
 * Returns 0 on success else non-zero.
 */
static ssize_t h3_rcv_buf(struct qcs *qcs, struct buffer *b, int fin)
{
	struct h3s *h3s = qcs->ctx;
	struct h3c *h3c = h3s->h3c;
	ssize_t total = 0, ret = 0;

	TRACE_ENTER(H3_EV_RX_FRAME, qcs->qcc->conn, qcs);

	if (quic_stream_is_uni(qcs->id) && !(h3s->flags & H3_SF_UNI_INIT)) {
		ret = h3_init_uni_stream(h3c, qcs, b);
		if (ret < 0) {
			TRACE_ERROR("cannot initialize uni stream", H3_EV_RX_FRAME, qcs->qcc->conn, qcs);
			goto err;
		}
		else if (!ret) {
			/* not enough data to initialize uni stream, retry later */
			goto done;
		}

		total += ret;
	}

	if (quic_stream_is_uni(qcs->id) && (h3s->flags & H3_SF_UNI_NO_H3)) {
		/* For non-h3 STREAM, parse it and return immediately. */
		if ((ret = h3_parse_uni_stream_no_h3(qcs, b, fin)) < 0) {
			TRACE_ERROR("error when parsing non-HTTP3 uni stream", H3_EV_RX_FRAME, qcs->qcc->conn, qcs);
			goto err;
		}

		total += ret;
		goto done;
	}

	/* RFC 9114 6.2.1. Control Streams
	 *
	 * The sender MUST NOT close the control stream, and the receiver MUST NOT
	 * request that the sender close the control stream.  If either control
	 * stream is closed at any point, this MUST be treated as a connection
	 * error of type H3_CLOSED_CRITICAL_STREAM.
	 */
	if (h3s->type == H3S_T_CTRL && fin) {
		TRACE_ERROR("control stream closed by remote peer", H3_EV_RX_FRAME, qcs->qcc->conn, qcs);
		qcc_set_error(qcs->qcc, H3_ERR_CLOSED_CRITICAL_STREAM, 1);
		qcc_report_glitch(qcs->qcc, 1);
		goto err;
	}

	if (!b_data(b) && fin && quic_stream_is_bidi(qcs->id)) {
		struct buffer *appbuf;
		struct htx *htx;
		int eom;

		TRACE_PROTO("received FIN without data", H3_EV_RX_FRAME, qcs->qcc->conn, qcs);
		if (!(appbuf = qcc_get_stream_rxbuf(qcs))) {
			TRACE_ERROR("data buffer alloc failure", H3_EV_RX_FRAME, qcs->qcc->conn, qcs);
			qcc_set_error(qcs->qcc, H3_ERR_INTERNAL_ERROR, 1);
			goto err;
		}

		htx = htx_from_buf(appbuf);
		eom = htx_set_eom(htx);
		htx_to_buf(htx, appbuf);
		if (!eom) {
			TRACE_ERROR("cannot set EOM", H3_EV_RX_FRAME, qcs->qcc->conn, qcs);
			qcc_set_error(qcs->qcc, H3_ERR_INTERNAL_ERROR, 1);
			goto err;
		}

		goto done;
	}

	while (b_data(b) && !(qcs->flags & QC_SF_DEM_FULL) && ret >= 0) {
		uint64_t ftype, flen;
		char last_stream_frame = 0;

		if (!h3s->demux_frame_len) {
			/* Switch to a new frame. */
			size_t hlen = h3_decode_frm_header(&ftype, &flen, b);
			if (!hlen) {
				TRACE_PROTO("pause parsing on incomplete frame header", H3_EV_RX_FRAME, qcs->qcc->conn, qcs);
				break;
			}

			h3s->demux_frame_type = ftype;
			h3s->demux_frame_len = flen;
			total += hlen;
			TRACE_PROTO("parsing a new frame", H3_EV_RX_FRAME, qcs->qcc->conn, qcs);

			/* Check that content-length is not exceeded on a new DATA frame. */
			if (ftype == H3_FT_DATA) {
				h3s->data_len += flen;
				if (h3s->flags & H3_SF_HAVE_CLEN && h3_check_body_size(qcs, (fin && flen == b_data(b))))
					break;
			}

			if ((ret = h3_check_frame_valid(h3c, qcs, ftype))) {
				TRACE_ERROR("received an invalid frame", H3_EV_RX_FRAME, qcs->qcc->conn, qcs);
				qcc_set_error(qcs->qcc, ret, 1);
				qcc_report_glitch(qcs->qcc, 1);
				goto err;
			}

			if (!b_data(b))
				break;
		}

		flen = h3s->demux_frame_len;
		ftype = h3s->demux_frame_type;

		/* Do not demux incomplete frames except H3 DATA which can be
		 * fragmented in multiple HTX blocks.
		 */
		if (flen > b_data(b) && ftype != H3_FT_DATA) {
			/* Reject frames bigger than bufsize.
			 *
			 * TODO HEADERS should in complement be limited with H3
			 * SETTINGS_MAX_FIELD_SECTION_SIZE parameter to prevent
			 * excessive decompressed size.
			 */
			if (flen > QC_S_RX_BUF_SZ) {
				TRACE_ERROR("received a too big frame", H3_EV_RX_FRAME, qcs->qcc->conn, qcs);
				qcc_set_error(qcs->qcc, H3_ERR_EXCESSIVE_LOAD, 1);
				qcc_report_glitch(qcs->qcc, 1);
				goto err;
			}
			break;
		}

		last_stream_frame = (fin && flen == b_data(b));

		/* Check content-length equality with DATA frames length on the last frame. */
		if (last_stream_frame && h3s->flags & H3_SF_HAVE_CLEN && h3_check_body_size(qcs, last_stream_frame))
			break;

		h3_inc_frame_type_cnt(h3c->prx_counters, ftype);
		switch (ftype) {
		case H3_FT_DATA:
			ret = h3_data_to_htx(qcs, b, flen, last_stream_frame);
			h3s->st_req = H3S_ST_REQ_DATA;
			break;
		case H3_FT_HEADERS:
			if (h3s->st_req == H3S_ST_REQ_BEFORE) {
				ret = h3_headers_to_htx(qcs, b, flen, last_stream_frame);
				h3s->st_req = H3S_ST_REQ_HEADERS;
			}
			else {
				ret = h3_trailers_to_htx(qcs, b, flen, last_stream_frame);
				h3s->st_req = H3S_ST_REQ_TRAILERS;
			}
			break;
		case H3_FT_CANCEL_PUSH:
		case H3_FT_PUSH_PROMISE:
		case H3_FT_MAX_PUSH_ID:
		case H3_FT_GOAWAY:
			/* Not supported */
			ret = flen;
			break;
		case H3_FT_SETTINGS:
			ret = h3_parse_settings_frm(qcs->qcc->ctx, b, flen);
			if (ret < 0) {
				TRACE_ERROR("error on SETTINGS parsing", H3_EV_RX_FRAME, qcs->qcc->conn, qcs);
				qcc_set_error(qcs->qcc, h3c->err, 1);
				goto err;
			}
			h3c->flags |= H3_CF_SETTINGS_RECV;
			break;
		default:
			/* draft-ietf-quic-http34 9. Extensions to HTTP/3
			 *
			 * Implementations MUST discard frames [...] that have unknown
			 * or unsupported types.
			 */
			ret = flen;
			break;
		}

		if (ret > 0) {
			BUG_ON(h3s->demux_frame_len < ret);
			h3s->demux_frame_len -= ret;
			b_del(b, ret);
			total += ret;
		}
	}

	/* Reset demux frame type for traces. */
	if (!h3s->demux_frame_len)
		h3s->demux_frame_type = H3_FT_UNINIT;

	/* Interrupt decoding on stream/connection error detected. */
	if (h3s->err) {
		qcc_abort_stream_read(qcs);
		qcc_reset_stream(qcs, h3s->err);
		return b_data(b);
	}
	else if (h3c->err) {
		qcc_set_error(qcs->qcc, h3c->err, 1);
		return b_data(b);
	}
	else if (unlikely(ret < 0)) {
		qcc_set_error(qcs->qcc, H3_ERR_INTERNAL_ERROR, 1);
		goto err;
	}

	/* TODO may be useful to wakeup the MUX if blocked due to full buffer.
	 * However, currently, io-cb of MUX does not handle Rx.
	 */

 done:
	TRACE_LEAVE(H3_EV_RX_FRAME, qcs->qcc->conn, qcs);
	return total;

 err:
	TRACE_DEVEL("leaving on error", H3_EV_RX_FRAME, qcs->qcc->conn, qcs);
	return -1;
}

/* Function used to emit stream data from <qcs> control uni-stream.
 *
 * On success return the number of sent bytes. A negative code is used on
 * error.
 */
static int h3_control_send(struct qcs *qcs, void *ctx)
{
	int err;
	int ret;
	struct h3c *h3c = ctx;
	unsigned char data[(2 + 3) * 2 * QUIC_VARINT_MAX_SIZE]; /* enough for 3 settings */
	struct buffer pos, *res;
	size_t frm_len;

	TRACE_ENTER(H3_EV_TX_FRAME|H3_EV_TX_SETTINGS, qcs->qcc->conn, qcs);

	BUG_ON_HOT(h3c->flags & H3_CF_SETTINGS_SENT);

	ret = 0;
	pos = b_make((char *)data, sizeof(data), 0, 0);

	frm_len = quic_int_getsize(H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY) +
		quic_int_getsize(h3_settings_qpack_max_table_capacity) +
		quic_int_getsize(H3_SETTINGS_QPACK_BLOCKED_STREAMS) +
		quic_int_getsize(h3_settings_qpack_blocked_streams);
	if (h3_settings_max_field_section_size) {
		frm_len += quic_int_getsize(H3_SETTINGS_MAX_FIELD_SECTION_SIZE) +
		quic_int_getsize(h3_settings_max_field_section_size);
	}

	b_quic_enc_int(&pos, H3_UNI_S_T_CTRL, 0);
	/* Build a SETTINGS frame */
	b_quic_enc_int(&pos, H3_FT_SETTINGS, 0);
	b_quic_enc_int(&pos, frm_len, 0);
	b_quic_enc_int(&pos, H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0);
	b_quic_enc_int(&pos, h3_settings_qpack_max_table_capacity, 0);
	b_quic_enc_int(&pos, H3_SETTINGS_QPACK_BLOCKED_STREAMS, 0);
	b_quic_enc_int(&pos, h3_settings_qpack_blocked_streams, 0);
	if (h3_settings_max_field_section_size) {
		b_quic_enc_int(&pos, H3_SETTINGS_MAX_FIELD_SECTION_SIZE, 0);
		b_quic_enc_int(&pos, h3_settings_max_field_section_size, 0);
	}

	if (qfctl_sblocked(&qcs->tx.fc) || qfctl_sblocked(&qcs->qcc->tx.fc)) {
		TRACE_ERROR("not enough initial credit for control stream", H3_EV_TX_FRAME|H3_EV_TX_SETTINGS, qcs->qcc->conn, qcs);
		goto err;
	}

	if (!(res = qcc_get_stream_txbuf(qcs, &err, 0))) {
		/* Only memory failure can cause buf alloc error for control stream due to qcs_send_metadata() usage. */
		TRACE_ERROR("cannot allocate Tx buffer", H3_EV_TX_FRAME|H3_EV_TX_SETTINGS, qcs->qcc->conn, qcs);
		goto err;
	}

	if (b_room(res) < b_data(&pos)) {
		// TODO the mux should be put in blocked state, with
		// the stream in state waiting for settings to be sent
		ABORT_NOW();
	}

	ret = b_force_xfer(res, &pos, b_data(&pos));
	if (ret > 0) {
		/* Register qcs for sending before other streams. */
		qcc_send_stream(qcs, 1, ret);
		h3c->flags |= H3_CF_SETTINGS_SENT;
	}

	TRACE_LEAVE(H3_EV_TX_FRAME|H3_EV_TX_SETTINGS, qcs->qcc->conn, qcs);
	return ret;

 err:
	TRACE_DEVEL("leaving on error", H3_EV_TX_FRAME|H3_EV_TX_SETTINGS, qcs->qcc->conn, qcs);
	return -1;
}

static int h3_resp_headers_send(struct qcs *qcs, struct htx *htx)
{
	int err;
	struct buffer outbuf;
	struct buffer headers_buf = BUF_NULL;
	struct buffer *res;
	struct http_hdr list[global.tune.max_http_hdr * 2];
	struct htx_sl *sl;
	struct htx_blk *blk;
	enum htx_blk_type type;
	int frame_length_size;  /* size in bytes of frame length varint field */
	int smallbuf = 1;
	int ret = 0;
	int hdr;
	int status = 0;

	TRACE_ENTER(H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);

	sl = NULL;
	hdr = 0;
	for (blk = htx_get_head_blk(htx); blk; blk = htx_get_next_blk(htx, blk)) {
		type = htx_get_blk_type(blk);

		if (type == HTX_BLK_UNUSED)
			continue;

		if (type == HTX_BLK_EOH)
			break;

		if (type == HTX_BLK_RES_SL) {
			/* start-line -> HEADERS h3 frame */
			BUG_ON(sl);
			sl = htx_get_blk_ptr(htx, blk);
			/* TODO should be on h3 layer */
			status = sl->info.res.status;
		}
		else if (type == HTX_BLK_HDR) {
			if (unlikely(hdr >= sizeof(list) / sizeof(list[0]) - 1)) {
				TRACE_ERROR("too many headers", H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
				goto err;
			}
			list[hdr].n = htx_get_blk_name(htx, blk);
			list[hdr].v = htx_get_blk_value(htx, blk);
			hdr++;
		}
		else {
			/* Unhandled HTX block type. */
			ABORT_NOW();
			goto err;
		}
	}

	BUG_ON(!sl);

	list[hdr].n = ist("");

 retry:
	res = smallbuf ? qcc_get_stream_txbuf(qcs, &err, 1) :
	                 qcc_realloc_stream_txbuf(qcs);
	if (!res) {
		if (err) {
			TRACE_ERROR("cannot allocate Tx buffer", H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
			goto err;
		}

		TRACE_STATE("buf window full", H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
		goto end;
	}

	/* Buffer allocated just now : must be enough for frame type + length as a max varint size */
	BUG_ON(b_room(res) < 5);

	b_reset(&outbuf);
	outbuf = b_make(b_tail(res), b_contig_space(res), 0, 0);
	/* Start the headers after frame type + length */
	headers_buf = b_make(b_head(res) + 5, b_size(res) - 5, 0, 0);

	TRACE_DATA("encoding HEADERS frame", H3_EV_TX_FRAME|H3_EV_TX_HDR,
	           qcs->qcc->conn, qcs);
	if (qpack_encode_field_section_line(&headers_buf))
		goto err_full;
	if (qpack_encode_int_status(&headers_buf, status)) {
		/* TODO handle invalid status code VS no buf space left */
		TRACE_ERROR("error during status code encoding", H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
		goto err_full;
	}

	for (hdr = 0; hdr < sizeof(list) / sizeof(list[0]); ++hdr) {
		if (isteq(list[hdr].n, ist("")))
			break;

		/* RFC 9114 4.2. HTTP Fields
		 *
		 * An intermediary transforming an HTTP/1.x message to HTTP/3
		 * MUST remove connection-specific header fields as discussed in
		 * Section 7.6.1 of [HTTP], or their messages will be treated by
		 * other HTTP/3 endpoints as malformed.
		 */
		if (isteq(list[hdr].n, ist("connection")) ||
		    isteq(list[hdr].n, ist("proxy-connection")) ||
		    isteq(list[hdr].n, ist("keep-alive")) ||
		    isteq(list[hdr].n, ist("transfer-encoding"))) {
			continue;
		}
		else if (isteq(list[hdr].n, ist("te"))) {
			/* "te" may only be sent with "trailers" if this value
			 * is present, otherwise it must be deleted.
			 */
			const struct ist v = istist(list[hdr].v, ist("trailers"));
			if (!isttest(v) || (v.len > 8 && v.ptr[8] != ','))
				continue;
			list[hdr].v = ist("trailers");
		}

		if (qpack_encode_header(&headers_buf, list[hdr].n, list[hdr].v))
			goto err_full;
	}

	/* Now that all headers are encoded, we are certain that res buffer is
	 * big enough
	 */
	frame_length_size = quic_int_getsize(b_data(&headers_buf));
	res->head += 4 - frame_length_size;
	b_putchr(res, 0x01); /* h3 HEADERS frame type */
	b_quic_enc_int(res, b_data(&headers_buf), 0);
	b_add(res, b_data(&headers_buf));

	ret = 0;
	blk = htx_get_head_blk(htx);
	while (blk) {
		type = htx_get_blk_type(blk);
		ret += htx_get_blksz(blk);
		blk = htx_remove_blk(htx, blk);
		if (type == HTX_BLK_EOH)
			break;
	}

 end:
	TRACE_LEAVE(H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
	return ret;

 err_full:
	if (smallbuf) {
		TRACE_DEVEL("retry with a full buffer", H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
		smallbuf = 0;
		goto retry;
	}
 err:
	TRACE_DEVEL("leaving on error", H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
	return -1;
}

/* Convert a series of HTX trailer blocks from <htx> buffer into <qcs> buffer
 * as a H3 HEADERS frame. H3 forbidden trailers are skipped. HTX trailer blocks
 * are removed from <htx> until EOT is found and itself removed.
 *
 * If only a EOT HTX block is present without trailer, no H3 frame is produced.
 * Caller is responsible to emit an empty QUIC STREAM frame to signal the end
 * of the stream.
 *
 * Returns the size of HTX blocks removed. A negative error code is returned in
 * case of a fatal error which should caused a connection closure.
 */
static int h3_resp_trailers_send(struct qcs *qcs, struct htx *htx)
{
	int err;
	struct buffer headers_buf = BUF_NULL;
	struct buffer *res;
	struct http_hdr list[global.tune.max_http_hdr];
	struct htx_blk *blk;
	enum htx_blk_type type;
	char *tail;
	int ret = 0;
	int hdr;

	TRACE_ENTER(H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);

	hdr = 0;
	for (blk = htx_get_head_blk(htx); blk; blk = htx_get_next_blk(htx, blk)) {
		type = htx_get_blk_type(blk);

		if (type == HTX_BLK_UNUSED)
			continue;

		if (type == HTX_BLK_EOT)
			break;

		if (type == HTX_BLK_TLR) {
			if (unlikely(hdr >= sizeof(list) / sizeof(list[0]) - 1)) {
				TRACE_ERROR("too many headers", H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
				goto err;
			}
			list[hdr].n = htx_get_blk_name(htx, blk);
			list[hdr].v = htx_get_blk_value(htx, blk);
			hdr++;
		}
		else {
			TRACE_ERROR("unexpected HTX block", H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
			goto err;
		}
	}

	if (!hdr) {
		/* No headers encoded here so no need to generate a H3 HEADERS
		 * frame. Mux will send an empty QUIC STREAM frame with FIN.
		 */
		TRACE_DATA("skipping trailer", H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);

		/* Truncate UNUSED / EOT HTX blocks. */
		blk = htx_get_head_blk(htx);
		while (blk) {
			type = htx_get_blk_type(blk);
			ret += htx_get_blksz(blk);
			blk = htx_remove_blk(htx, blk);
			if (type == HTX_BLK_EOT)
				break;
		}
		goto end;
	}

	list[hdr].n = ist("");

 start:
	if (!(res = qcc_get_stream_txbuf(qcs, &err, 0))) {
		if (err) {
			TRACE_ERROR("cannot allocate Tx buffer", H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
			goto err;
		}

		TRACE_STATE("buf window full", H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
		goto end;
	}

	/* At least 9 bytes to store frame type + length as a varint max size */
	if (b_room(res) < 9) {
		TRACE_STATE("not enough room for trailers frame", H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
		if (qcc_release_stream_txbuf(qcs))
			goto end;

		/* Buffer released, restart processing. */
		goto start;
	}

	/* Force buffer realignment as size required to encode headers is unknown. */
	if (b_space_wraps(res))
		b_slow_realign(res, trash.area, b_data(res));
	/* Start the headers after frame type + length */
	headers_buf = b_make(b_peek(res, b_data(res) + 9), b_contig_space(res) - 9, 0, 0);

	if (qpack_encode_field_section_line(&headers_buf)) {
		TRACE_STATE("not enough room for trailers section line", H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
		if (qcc_release_stream_txbuf(qcs))
			goto end;

		/* Buffer released, restart processing. */
		goto start;
	}

	tail = b_tail(&headers_buf);
	for (hdr = 0; hdr < sizeof(list) / sizeof(list[0]); ++hdr) {
		if (isteq(list[hdr].n, ist("")))
			break;

		/* forbidden HTTP/3 headers, cf h3_resp_headers_send() */
		if (isteq(list[hdr].n, ist("host")) ||
		    isteq(list[hdr].n, ist("content-length")) ||
		    isteq(list[hdr].n, ist("connection")) ||
		    isteq(list[hdr].n, ist("proxy-connection")) ||
		    isteq(list[hdr].n, ist("keep-alive")) ||
		    isteq(list[hdr].n, ist("te")) ||
		    isteq(list[hdr].n, ist("transfer-encoding"))) {
			continue;
		}

		if (qpack_encode_header(&headers_buf, list[hdr].n, list[hdr].v)) {
			TRACE_STATE("not enough room for all trailers", H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
			if (qcc_release_stream_txbuf(qcs))
				goto end;

			/* Buffer released, restart processing. */
			goto start;
		}
	}

	/* Check that at least one header was encoded in buffer. */
	if (b_tail(&headers_buf) == tail) {
		/* No headers encoded here so no need to generate a H3 HEADERS
		 * frame. Mux will send an empty QUIC STREAM frame with FIN.
		 */
		TRACE_DATA("skipping trailer", H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
	}
	else {
		/* Now that all headers are encoded, we are certain that res
		 * buffer is big enough.
		 */
		TRACE_DATA("encoding TRAILERS frame", H3_EV_TX_FRAME|H3_EV_TX_HDR,
			   qcs->qcc->conn, qcs);
		b_putchr(res, 0x01); /* h3 HEADERS frame type */
		b_quic_enc_int(res, b_data(&headers_buf), 8);
		b_add(res, b_data(&headers_buf));
	}

	/* Encoding success, truncate HTX blocks until EOT. */
	blk = htx_get_head_blk(htx);
	while (blk) {
		type = htx_get_blk_type(blk);
		ret += htx_get_blksz(blk);
		blk = htx_remove_blk(htx, blk);
		if (type == HTX_BLK_EOT)
			break;
	}

 end:
	TRACE_LEAVE(H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
	return ret;

 err:
	TRACE_DEVEL("leaving on error", H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
	return -1;
}

/* Convert a series of HTX data blocks from <htx> buffer of size <count> into
 * HTTP/3 frames encoded into <qcs> Tx buffer. The caller must also specify the
 * underlying HTX area via <buf> as this will be used if zero-copy can be
 * performed.
 *
 * Returns the total bytes of encoded HTTP/3 payload. This corresponds to the
 * total bytes of HTX block removed. A negative error code is returned in case
 * of a fatal error which should caused a connection closure.
 */
static int h3_resp_data_send(struct qcs *qcs, struct htx *htx,
                             struct buffer *buf, size_t count)
{
	int err;
	struct buffer outbuf;
	struct buffer *res;
	size_t total = 0;
	int bsize, fsize, hsize;
	struct htx_blk *blk;
	enum htx_blk_type type;

	TRACE_ENTER(H3_EV_TX_FRAME|H3_EV_TX_DATA, qcs->qcc->conn, qcs);

 new_frame:
	if (!count || htx_is_empty(htx))
		goto end;

	blk = htx_get_head_blk(htx);
	type = htx_get_blk_type(blk);
	fsize = bsize = htx_get_blksz(blk);

	/* h3 DATA headers : 1-byte frame type + varint frame length */
	hsize = 1 + QUIC_VARINT_MAX_SIZE;

	if (type != HTX_BLK_DATA)
		goto end;

	if (!(res = qcc_get_stream_txbuf(qcs, &err, 0))) {
		if (err) {
			TRACE_ERROR("cannot allocate Tx buffer", H3_EV_TX_FRAME|H3_EV_TX_DATA, qcs->qcc->conn, qcs);
			goto err;
		}

		TRACE_STATE("buf window full", H3_EV_TX_FRAME|H3_EV_TX_HDR, qcs->qcc->conn, qcs);
		goto end;
	}

	/* If HTX contains only one DATA block, try to exchange it with MUX
	 * buffer to perform zero-copy. This is only achievable if MUX buffer
	 * is currently empty.
	 */
	if (unlikely(fsize == count &&
	             !b_data(res) &&
	             htx_nbblks(htx) == 1 && type == HTX_BLK_DATA)) {
		void *old_area = res->area;

		TRACE_DATA("perform zero-copy DATA transfer",
		           H3_EV_TX_FRAME|H3_EV_TX_DATA, qcs->qcc->conn, qcs);

		/* remap MUX buffer to HTX area, keep an offset for H3 header. */
		*res = b_make(buf->area, buf->size,
		              sizeof(struct htx) + blk->addr - hsize, 0);

		/* write H3 header frame before old HTX block. */
		b_putchr(res, 0x00); /* h3 frame type = DATA */
		b_quic_enc_int(res, fsize, QUIC_VARINT_MAX_SIZE); /* h3 frame length */
		b_add(res, fsize);

		/* assign old MUX area to HTX buffer. */
		buf->area = old_area;
		buf->data = buf->head = 0;
		total += fsize;

		goto end;
	}

	if (fsize > count)
		fsize = count;

	while (1) {
		b_reset(&outbuf);
		outbuf = b_make(b_tail(res), b_contig_space(res), 0, 0);
		if (b_size(&outbuf) > hsize || !b_space_wraps(res))
			break;
		if (qcc_realign_stream_txbuf(qcs, res))
			break;
	}

	/* Not enough room for headers and at least one data byte, try to
	 * release the current buffer and allocate a new one. If not possible,
	 * stconn layer will subscribe on SEND.
	 */
	if (b_size(&outbuf) <= hsize) {
		TRACE_STATE("not enough room for data frame", H3_EV_TX_FRAME|H3_EV_TX_DATA, qcs->qcc->conn, qcs);
		if (qcc_release_stream_txbuf(qcs))
			goto end;

		/* Buffer released, restart processing. */
		goto new_frame;
	}

	if (b_size(&outbuf) < hsize + fsize)
		fsize = b_size(&outbuf) - hsize;
	BUG_ON(fsize <= 0);

	TRACE_DATA("encoding DATA frame", H3_EV_TX_FRAME|H3_EV_TX_DATA,
	           qcs->qcc->conn, qcs);
	b_putchr(&outbuf, 0x00);        /* h3 frame type = DATA */
	b_quic_enc_int(&outbuf, fsize, 0); /* h3 frame length */

	b_putblk(&outbuf, htx_get_blk_ptr(htx, blk), fsize);
	total += fsize;
	count -= fsize;

	if (fsize == bsize)
		htx_remove_blk(htx, blk);
	else
		htx_cut_data_blk(htx, blk, fsize);

	/* commit the buffer */
	b_add(res, b_data(&outbuf));
	goto new_frame;

 end:
	TRACE_LEAVE(H3_EV_TX_FRAME|H3_EV_TX_DATA, qcs->qcc->conn, qcs);
	return total;

 err:
	BUG_ON(total); /* Must return HTX removed size if at least on frame encoded. */
	TRACE_DEVEL("leaving on error", H3_EV_TX_FRAME|H3_EV_TX_DATA, qcs->qcc->conn, qcs);
	return -1;
}

static size_t h3_snd_buf(struct qcs *qcs, struct buffer *buf, size_t count)
{
	size_t total = 0;
	enum htx_blk_type btype;
	struct htx *htx;
	struct htx_blk *blk;
	uint32_t bsize;
	int32_t idx;
	int ret = 0;

	TRACE_ENTER(H3_EV_STRM_SEND, qcs->qcc->conn, qcs);

	htx = htx_from_buf(buf);

	while (count && !htx_is_empty(htx) && qcc_stream_can_send(qcs) && ret >= 0) {
		idx = htx_get_head(htx);
		blk = htx_get_blk(htx, idx);
		btype = htx_get_blk_type(blk);
		bsize = htx_get_blksz(blk);

		/* Not implemented : QUIC on backend side */
		BUG_ON(btype == HTX_BLK_REQ_SL);

		switch (btype) {
		case HTX_BLK_RES_SL:
			/* start-line -> HEADERS h3 frame */
			ret = h3_resp_headers_send(qcs, htx);
			if (ret > 0) {
				total += ret;
				count -= ret;
				if (ret < bsize)
					goto out;
			}
			break;

		case HTX_BLK_DATA:
			ret = h3_resp_data_send(qcs, htx, buf, count);
			if (ret > 0) {
				/* Reload HTX. This is necessary if 0-copy was performed. */
				htx = htx_from_buf(buf);

				total += ret;
				count -= ret;
				if (ret < bsize)
					goto out;
			}
			break;

		case HTX_BLK_TLR:
		case HTX_BLK_EOT:
			ret = h3_resp_trailers_send(qcs, htx);
			if (ret > 0) {
				total += ret;
				count -= ret;
				if (ret < bsize)
					goto out;
			}
			break;

		default:
			htx_remove_blk(htx, blk);
			total += bsize;
			count -= bsize;
			break;
		}
	}

	/* Interrupt sending on fatal error. */
	if (unlikely(ret < 0)) {
		qcc_set_error(qcs->qcc, H3_ERR_INTERNAL_ERROR, 1);
		goto out;
	}

	/* RFC 9114 4.1. HTTP Message Framing
	 *
	 * A server can send a complete response prior to the client sending an
	 * entire request if the response does not depend on any portion of the
	 * request that has not been sent and received. When the server does not
	 * need to receive the remainder of the request, it MAY abort reading
	 * the request stream, send a complete response, and cleanly close the
	 * sending part of the stream. The error code H3_NO_ERROR SHOULD be used
	 * when requesting that the client stop sending on the request stream.
	 * Clients MUST NOT discard complete responses as a result of having
	 * their request terminated abruptly, though clients can always discard
	 * responses at their discretion for other reasons. If the server sends
	 * a partial or complete response but does not abort reading the
	 * request, clients SHOULD continue sending the content of the request
	 * and close the stream normally.
	 */
	if (unlikely((htx->flags & HTX_FL_EOM) && htx_is_empty(htx)) &&
	             !qcs_is_close_remote(qcs)) {
	        /* Generate a STOP_SENDING if full response transferred before
	         * receiving the full request.
	         */
	        qcs->err = H3_ERR_NO_ERROR;
	        qcc_abort_stream_read(qcs);
	}

 out:
	htx_to_buf(htx, buf);

	TRACE_LEAVE(H3_EV_STRM_SEND, qcs->qcc->conn, qcs);
	return total;
}

static size_t h3_nego_ff(struct qcs *qcs, size_t count)
{
	int err;
	struct buffer *res;
	int hsize;
	size_t sz, ret = 0;

	TRACE_ENTER(H3_EV_STRM_SEND, qcs->qcc->conn, qcs);

 start:
	if (!(res = qcc_get_stream_txbuf(qcs, &err, 0))) {
		if (err) {
			qcs->sd->iobuf.flags |= IOBUF_FL_NO_FF;
			goto end;
		}

		qcs->sd->iobuf.flags |= IOBUF_FL_FF_BLOCKED;
		goto end;
	}

	/* h3 DATA headers : 1-byte frame type + varint frame length */
	hsize = 1 + QUIC_VARINT_MAX_SIZE;
	while (1) {
		if (b_contig_space(res) >= hsize || !b_space_wraps(res))
			break;
		if (qcc_realign_stream_txbuf(qcs, res))
			break;
	}

	/* Not enough room for headers and at least one data byte, block the
	 * stream. It is expected that the stream connector layer will subscribe
	 * on SEND.
	 */
	if (b_contig_space(res) <= hsize) {
		if (qcc_release_stream_txbuf(qcs)) {
			qcs->sd->iobuf.flags |= IOBUF_FL_FF_BLOCKED;
			goto end;
		}

		/* Buffer released, restart processing. */
		goto start;
	}

	/* Cannot forward more than available room in output buffer */
	sz = b_contig_space(res) - hsize;
	if (count > sz)
		count = sz;

	qcs->sd->iobuf.buf = res;
	qcs->sd->iobuf.offset = hsize;
	qcs->sd->iobuf.data = 0;

	ret = count;
  end:
	TRACE_LEAVE(H3_EV_STRM_SEND, qcs->qcc->conn, qcs);
	return ret;
}

/* Finalize encoding of a HTTP/3 data frame after zero-copy for <qcs> stream.
 * No frame is encoded if <qcs> iobuf indicates that no data were transferred.
 *
 * Return the payload size of the H3 data frame or 0 if no frame encoded.
 */
static size_t h3_done_ff(struct qcs *qcs)
{
	size_t total = 0;
	TRACE_ENTER(H3_EV_STRM_SEND, qcs->qcc->conn, qcs);

	h3_debug_printf(stderr, "%s\n", __func__);

	if (qcs->sd->iobuf.data) {
		TRACE_DATA("encoding DATA frame (fast forward)",
		           H3_EV_TX_FRAME|H3_EV_TX_DATA, qcs->qcc->conn, qcs);

		b_sub(qcs->sd->iobuf.buf, qcs->sd->iobuf.data);
		b_putchr(qcs->sd->iobuf.buf, 0x00); /* h3 frame type = DATA */
		b_quic_enc_int(qcs->sd->iobuf.buf, qcs->sd->iobuf.data, QUIC_VARINT_MAX_SIZE); /* h3 frame length */
		b_add(qcs->sd->iobuf.buf, qcs->sd->iobuf.data);

		total = qcs->sd->iobuf.offset + qcs->sd->iobuf.data;
	}

	TRACE_LEAVE(H3_EV_STRM_SEND, qcs->qcc->conn, qcs);
	return total;
}

/* Notify about a closure on <qcs> stream requested by the remote peer.
 *
 * Stream channel <side> is explained relative to our endpoint : WR for
 * STOP_SENDING or RD for RESET_STREAM reception. Callback decode_qcs() is used
 * instead for closure performed using a STREAM frame with FIN bit.
 *
 * The main objective of this function is to check if closure is valid
 * according to HTTP/3 specification.
 *
 * Returns 0 on success else non-zero. A CONNECTION_CLOSE is generated on
 * error.
 */
static int h3_close(struct qcs *qcs, enum qcc_app_ops_close_side side)
{
	struct h3s *h3s = qcs->ctx;
	struct h3c *h3c = h3s->h3c;;

	/* RFC 9114 6.2.1. Control Streams
	 *
	 * The sender
	 * MUST NOT close the control stream, and the receiver MUST NOT
	 * request that the sender close the control stream.  If either
	 * control stream is closed at any point, this MUST be treated
	 * as a connection error of type H3_CLOSED_CRITICAL_STREAM.
	 */
	if (qcs == h3c->ctrl_strm || h3s->type == H3S_T_CTRL) {
		TRACE_ERROR("closure detected on control stream", H3_EV_H3S_END, qcs->qcc->conn, qcs);
		qcc_set_error(qcs->qcc, H3_ERR_CLOSED_CRITICAL_STREAM, 1);
		qcc_report_glitch(qcs->qcc, 1);
		return 1;
	}

	return 0;
}

/* Allocates HTTP/3 stream context relative to <qcs>. If the operation cannot
 * be performed, an error is returned and <qcs> context is unchanged.
 *
 * Returns 0 on success else non-zero.
 */
static int h3_attach(struct qcs *qcs, void *conn_ctx)
{
	struct h3c *h3c = conn_ctx;
	struct h3s *h3s = NULL;

	TRACE_ENTER(H3_EV_H3S_NEW, qcs->qcc->conn, qcs);

	h3s = pool_alloc(pool_head_h3s);
	if (!h3s) {
		TRACE_ERROR("h3s allocation failure", H3_EV_H3S_NEW, qcs->qcc->conn, qcs);
		goto err;
	}

	qcs->ctx = h3s;
	h3s->h3c = conn_ctx;

	h3s->demux_frame_len = 0;
	h3s->demux_frame_type = H3_FT_UNINIT;
	h3s->body_len = 0;
	h3s->data_len = 0;
	h3s->flags = 0;
	h3s->err = 0;

	if (quic_stream_is_bidi(qcs->id)) {
		h3s->type = H3S_T_REQ;
		h3s->st_req = H3S_ST_REQ_BEFORE;
		qcs_wait_http_req(qcs);
	}
	else {
		/* stream type must be decoded for unidirectional streams */
		h3s->type = H3S_T_UNKNOWN;
	}

	/* RFC 9114 5.2. Connection Shutdown
	 *
	 * Upon sending
	 * a GOAWAY frame, the endpoint SHOULD explicitly cancel (see
	 * Sections 4.1.1 and 7.2.3) any requests or pushes that have
	 * identifiers greater than or equal to the one indicated, in
	 * order to clean up transport state for the affected streams.
	 * The endpoint SHOULD continue to do so as more requests or
	 * pushes arrive.
	 */
	if (h3c->flags & H3_CF_GOAWAY_SENT && qcs->id >= h3c->id_goaway &&
	    quic_stream_is_bidi(qcs->id)) {
		TRACE_STATE("close stream outside of goaway range", H3_EV_H3S_NEW, qcs->qcc->conn, qcs);
		qcc_abort_stream_read(qcs);
		qcc_reset_stream(qcs, H3_ERR_REQUEST_REJECTED);
	}

	/* TODO support push uni-stream rejection. */

	TRACE_LEAVE(H3_EV_H3S_NEW, qcs->qcc->conn, qcs);
	return 0;

 err:
	TRACE_DEVEL("leaving in error", H3_EV_H3S_NEW, qcs->qcc->conn, qcs);
	return 1;
}

static void h3_detach(struct qcs *qcs)
{
	struct h3s *h3s = qcs->ctx;

	TRACE_ENTER(H3_EV_H3S_END, qcs->qcc->conn, qcs);

	pool_free(pool_head_h3s, h3s);
	qcs->ctx = NULL;

	TRACE_LEAVE(H3_EV_H3S_END, qcs->qcc->conn, qcs);
}

/* Generate a GOAWAY frame for <h3c> connection on the control stream.
 *
 * Returns 0 on success else non-zero.
 */
static int h3_send_goaway(struct h3c *h3c)
{
	int err;
	struct qcs *qcs = h3c->ctrl_strm;
	struct buffer pos, *res;
	unsigned char data[3 * QUIC_VARINT_MAX_SIZE];
	size_t frm_len = quic_int_getsize(h3c->id_goaway);
	size_t xfer;

	TRACE_ENTER(H3_EV_H3C_END, h3c->qcc->conn);

	if (!qcs) {
		TRACE_ERROR("control stream not initialized", H3_EV_H3C_END, h3c->qcc->conn);
		goto err;
	}

	pos = b_make((char *)data, sizeof(data), 0, 0);

	b_quic_enc_int(&pos, H3_FT_GOAWAY, 0);
	b_quic_enc_int(&pos, frm_len, 0);
	b_quic_enc_int(&pos, h3c->id_goaway, 0);

	res = qcc_get_stream_txbuf(qcs, &err, 0);
	if (!res || b_room(res) < b_data(&pos) ||
	    qfctl_sblocked(&qcs->tx.fc) || qfctl_sblocked(&h3c->qcc->tx.fc)) {
		/* Do not try forcefully to emit GOAWAY if no buffer available or not enough space left. */
		TRACE_ERROR("cannot send GOAWAY", H3_EV_H3C_END, h3c->qcc->conn, qcs);
		goto err;
	}

	xfer = b_force_xfer(res, &pos, b_data(&pos));
	qcc_send_stream(qcs, 1, xfer);

	h3c->flags |= H3_CF_GOAWAY_SENT;
	TRACE_LEAVE(H3_EV_H3C_END, h3c->qcc->conn);
	return 0;

 err:
	/* Consider GOAWAY as sent even if not really the case. This will
	 * block future stream opening using H3_REQUEST_REJECTED reset.
	 */
	h3c->flags |= H3_CF_GOAWAY_SENT;
	TRACE_DEVEL("leaving in error", H3_EV_H3C_END, h3c->qcc->conn);
	return 1;
}

/* Initialize the HTTP/3 context for <qcc> mux.
 * Return 1 if succeeded, 0 if not.
 */
static int h3_init(struct qcc *qcc)
{
	struct h3c *h3c;
	const struct listener *li = __objt_listener(qcc->conn->target);

	TRACE_ENTER(H3_EV_H3C_NEW, qcc->conn);

	h3c = pool_alloc(pool_head_h3c);
	if (!h3c) {
		TRACE_ERROR("cannot allocate h3c", H3_EV_H3C_NEW, qcc->conn);
		goto fail_no_h3;
	}

	h3c->qcc = qcc;
	h3c->ctrl_strm = NULL;
	h3c->err = 0;
	h3c->flags = 0;
	h3c->id_goaway = 0;

	qcc->ctx = h3c;
	h3c->prx_counters =
		EXTRA_COUNTERS_GET(li->bind_conf->frontend->extra_counters_fe,
		                   &h3_stats_module);
	LIST_INIT(&h3c->buf_wait.list);

	TRACE_LEAVE(H3_EV_H3C_NEW, qcc->conn);
	return 1;

 fail_no_h3:
	qcc_set_error(qcc, H3_ERR_INTERNAL_ERROR, 1);
	TRACE_DEVEL("leaving on error", H3_EV_H3C_NEW, qcc->conn);
	return 0;
}

/* Initialize H3 control stream and prepare SETTINGS emission.
 *
 * Returns 0 on success else non-zero.
 */
static int h3_finalize(void *ctx)
{
	struct h3c *h3c = ctx;
	struct qcc *qcc = h3c->qcc;
	struct qcs *qcs;

	TRACE_ENTER(H3_EV_H3C_NEW, qcc->conn);

	qcs = qcc_init_stream_local(qcc, 0);
	if (!qcs) {
		/* Error must be set by qcc_init_stream_local(). */
		BUG_ON(!(qcc->flags & QC_CF_ERRL));
		TRACE_ERROR("cannot init control stream", H3_EV_H3C_NEW, qcc->conn);
		goto err;
	}

	qcs_send_metadata(qcs);
	h3c->ctrl_strm = qcs;

	if (h3_control_send(qcs, h3c) < 0) {
		qcc_set_error(qcc, H3_ERR_INTERNAL_ERROR, 1);
		goto err;
	}

	TRACE_LEAVE(H3_EV_H3C_NEW, qcc->conn);
	return 0;

 err:
	TRACE_DEVEL("leaving on error", H3_EV_H3C_NEW, qcc->conn);
	return 1;
}

/* Send a HTTP/3 GOAWAY followed by a CONNECTION_CLOSE_APP. */
static void h3_shutdown(void *ctx)
{
	struct h3c *h3c = ctx;

	TRACE_ENTER(H3_EV_H3C_END, h3c->qcc->conn);

	/* RFC 9114 5.2. Connection Shutdown
	 *
	 * Even when a connection is not idle, either endpoint can decide to
	 * stop using the connection and initiate a graceful connection close.
	 * Endpoints initiate the graceful shutdown of an HTTP/3 connection by
	 * sending a GOAWAY frame.
	 */
	h3_send_goaway(h3c);

	/* RFC 9114 5.2. Connection Shutdown
	 *
	 * An endpoint that completes a
	 * graceful shutdown SHOULD use the H3_NO_ERROR error code when closing
	 * the connection.
	 */
	h3c->qcc->err = quic_err_app(H3_ERR_NO_ERROR);

	TRACE_LEAVE(H3_EV_H3C_END, h3c->qcc->conn);
}

static void h3_release(void *ctx)
{
	struct h3c *h3c = ctx;
	pool_free(pool_head_h3c, h3c);
}

/* Increment the h3 error code counters for <error_code> value */
static void h3_stats_inc_err_cnt(void *ctx, int err_code)
{
	struct h3c *h3c = ctx;

	h3_inc_err_cnt(h3c->prx_counters, err_code);
}

static void h3_report_susp(void *ctx)
{
	struct h3c *h3c = ctx;
	h3c->qcc->err = quic_err_app(H3_ERR_EXCESSIVE_LOAD);
}

static inline const char *h3_ft_str(uint64_t type)
{
	switch (type) {
	case H3_FT_DATA:         return "DATA";
	case H3_FT_HEADERS:      return "HEADERS";
	case H3_FT_SETTINGS:     return "SETTINGS";
	case H3_FT_PUSH_PROMISE: return "PUSH_PROMISE";
	case H3_FT_MAX_PUSH_ID:  return "MAX_PUSH_ID";
	case H3_FT_CANCEL_PUSH:  return "CANCEL_PUSH";
	case H3_FT_GOAWAY:       return "GOAWAY";
	default:                 return "_UNKNOWN_";
	}
}

/* h3 trace handler */
static void h3_trace(enum trace_level level, uint64_t mask,
                     const struct trace_source *src,
                     const struct ist where, const struct ist func,
                     const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct connection *conn = a1;
	const struct qcc *qcc   = conn ? conn->ctx : NULL;
	const struct qcs *qcs   = a2;
	const struct h3s *h3s   = qcs ? qcs->ctx : NULL;

	if (!qcc)
		return;

	if (src->verbosity > H3_VERB_CLEAN) {
		chunk_appendf(&trace_buf, " : qcc=%p(F)", qcc);
		if (qcc->conn->handle.qc)
			chunk_appendf(&trace_buf, " qc=%p", qcc->conn->handle.qc);

		if (qcs)
			chunk_appendf(&trace_buf, " qcs=%p(%llu)", qcs, (ull)qcs->id);

		if (h3s && h3s->demux_frame_type != H3_FT_UNINIT) {
			chunk_appendf(&trace_buf, " h3s.dem=%s/%llu",
			              h3_ft_str(h3s->demux_frame_type), (ull)h3s->demux_frame_len);
		}
	}
}

/* HTTP/3 application layer operations */
const struct qcc_app_ops h3_ops = {
	.init        = h3_init,
	.finalize    = h3_finalize,
	.attach      = h3_attach,
	.rcv_buf     = h3_rcv_buf,
	.snd_buf     = h3_snd_buf,
	.nego_ff     = h3_nego_ff,
	.done_ff     = h3_done_ff,
	.close       = h3_close,
	.detach      = h3_detach,
	.shutdown    = h3_shutdown,
	.inc_err_cnt = h3_stats_inc_err_cnt,
	.report_susp = h3_report_susp,
	.release     = h3_release,
};
