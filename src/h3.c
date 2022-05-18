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

#include <haproxy/buf.h>
#include <haproxy/connection.h>
#include <haproxy/conn_stream.h>
#include <haproxy/dynbuf.h>
#include <haproxy/h3.h>
#include <haproxy/http.h>
#include <haproxy/htx.h>
#include <haproxy/intops.h>
#include <haproxy/istbuf.h>
#include <haproxy/mux_quic.h>
#include <haproxy/ncbuf.h>
#include <haproxy/pool.h>
#include <haproxy/qpack-dec.h>
#include <haproxy/qpack-enc.h>
#include <haproxy/quic_enc.h>
#include <haproxy/tools.h>
#include <haproxy/xprt_quic.h>

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

/* Default settings */
static uint64_t h3_settings_qpack_max_table_capacity = 0;
static uint64_t h3_settings_qpack_blocked_streams = 4096;
static uint64_t h3_settings_max_field_section_size = QUIC_VARINT_8_BYTE_MAX; /* Unlimited */

struct h3c {
	struct qcc *qcc;
	enum h3_err err;
	uint32_t flags;

	/* Settings */
	uint64_t qpack_max_table_capacity;
	uint64_t qpack_blocked_streams;
	uint64_t max_field_section_size;

	struct buffer_wait buf_wait; /* wait list for buffer allocations */
};

DECLARE_STATIC_POOL(pool_head_h3c, "h3c", sizeof(struct h3c));

#define H3_SF_UNI_INIT  0x00000001  /* stream type not parsed for unidirectional stream */
#define H3_SF_UNI_NO_H3 0x00000002  /* unidirectional stream does not carry H3 frames */

struct h3s {
	enum h3s_t type;
	int demux_frame_len;
	int demux_frame_type;

	int flags;
};

DECLARE_STATIC_POOL(pool_head_h3s, "h3s", sizeof(struct h3s));

/* Simple function to duplicate a buffer */
static inline struct buffer h3_b_dup(const struct ncbuf *b)
{
	return b_make(ncb_orig(b), b->size, b->head, ncb_data(b, 0));
}

/* Initialize an uni-stream <qcs> by reading its type from <rxbuf>.
 *
 * Returns 0 on success else non-zero.
 */
static int h3_init_uni_stream(struct h3c *h3c, struct qcs *qcs,
                              struct ncbuf *rxbuf)
{
	/* decode unidirectional stream type */
	struct h3s *h3s = qcs->ctx;
	struct buffer b;
	uint64_t type;
	size_t len = 0, ret;

	BUG_ON_HOT(!quic_stream_is_uni(qcs->id) ||
	           h3s->flags & H3_SF_UNI_INIT);

	b = h3_b_dup(rxbuf);
	ret = b_quic_dec_int(&type, &b, &len);
	if (!ret) {
		ABORT_NOW();
	}

	switch (type) {
	case H3_UNI_S_T_CTRL:
		if (h3c->flags & H3_CF_UNI_CTRL_SET) {
			qcc_emit_cc_app(qcs->qcc, H3_STREAM_CREATION_ERROR);
			return 1;
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
			qcc_emit_cc_app(qcs->qcc, H3_STREAM_CREATION_ERROR);
			return 1;
		}
		h3c->flags |= H3_CF_UNI_QPACK_DEC_SET;
		h3s->type = H3S_T_QPACK_DEC;
		h3s->flags |= H3_SF_UNI_NO_H3;
		break;

	case H3_UNI_S_T_QPACK_ENC:
		if (h3c->flags & H3_CF_UNI_QPACK_ENC_SET) {
			qcc_emit_cc_app(qcs->qcc, H3_STREAM_CREATION_ERROR);
			return 1;
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
		qcs->flags |= QC_SF_READ_ABORTED;
		return 1;
	};

	h3s->flags |= H3_SF_UNI_INIT;
	qcs_consume(qcs, len);

	return 0;
}

/* Parse an uni-stream <qcs> from <rxbuf> which does not contains H3 frames.
 * This may be used for QPACK encoder/decoder streams for example.
 *
 * Returns 0 on success else non-zero.
 */
static int h3_parse_uni_stream_no_h3(struct qcs *qcs, struct ncbuf *rxbuf)
{
	struct h3s *h3s = qcs->ctx;

	BUG_ON_HOT(!quic_stream_is_uni(qcs->id) ||
	           !(h3s->flags & H3_SF_UNI_NO_H3));

	switch (h3s->type) {
	case H3S_T_QPACK_DEC:
		if (!qpack_decode_dec(qcs, NULL))
			return 1;
		break;
	case H3S_T_QPACK_ENC:
		if (!qpack_decode_enc(qcs, NULL))
			return 1;
		break;
	case H3S_T_UNKNOWN:
	default:
		/* Unknown stream should be flagged with QC_SF_READ_ABORTED. */
		ABORT_NOW();
	}

	return 0;
}

/* Decode a h3 frame header made of two QUIC varints from <b> buffer.
 * Returns the number of bytes consumed if there was enough data in <b>, 0 if not.
 * Note that this function update <b> buffer to reflect the number of bytes consumed
 * to decode the h3 frame header.
 */
static inline size_t h3_decode_frm_header(uint64_t *ftype, uint64_t *flen,
                                          struct buffer *b)
{
	size_t hlen;

	hlen = 0;
	if (!b_quic_dec_int(ftype, b, &hlen) || !b_quic_dec_int(flen, b, &hlen))
		return 0;

	return hlen;
}

/* Check if H3 frame of type <ftype> is valid when received on stream <qcs>.
 *
 * Returns a boolean. If false, a connection error H3_FRAME_UNEXPECTED should
 * be reported.
 */
static int h3_is_frame_valid(struct h3c *h3c, struct qcs *qcs, uint64_t ftype)
{
	struct h3s *h3s = qcs->ctx;
	const uint64_t id = qcs->id;

	BUG_ON_HOT(h3s->type == H3S_T_UNKNOWN);

	switch (ftype) {
	case H3_FT_DATA:
	case H3_FT_HEADERS:
		return h3s->type != H3S_T_CTRL;

	case H3_FT_CANCEL_PUSH:
	case H3_FT_GOAWAY:
	case H3_FT_MAX_PUSH_ID:
		/* Only allowed for control stream. First frame of control
		 * stream MUST be SETTINGS.
		 */
		return h3s->type == H3S_T_CTRL &&
		       (h3c->flags & H3_CF_SETTINGS_RECV);

	case H3_FT_SETTINGS:
		/* draft-ietf-quic-http34 7.2.4. SETTINGS
		 *
		 * If an endpoint receives a second SETTINGS frame on the control
		 * stream, the endpoint MUST respond with a connection error of type
		 * H3_FRAME_UNEXPECTED.
		 */
		return h3s->type == H3S_T_CTRL &&
		       !(h3c->flags & H3_CF_SETTINGS_RECV);

	case H3_FT_PUSH_PROMISE:
		return h3s->type != H3S_T_CTRL &&
		       (id & QCS_ID_SRV_INTIATOR_BIT);

	default:
		/* draft-ietf-quic-http34 9. Extensions to HTTP/3
		 *
		 * Implementations MUST discard frames [...] that have unknown
		 * or unsupported types.
		 */
		return h3s->type != H3S_T_CTRL || (h3c->flags & H3_CF_SETTINGS_RECV);
	}
}

/* Parse from buffer <buf> a H3 HEADERS frame of length <len>. Data are copied
 * in a local HTX buffer and transfer to the stream connector layer. <fin> must be
 * set if this is the last data to transfer from this stream.
 *
 * Returns the number of bytes handled or a negative error code.
 */
static int h3_headers_to_htx(struct qcs *qcs, struct ncbuf *buf, uint64_t len,
                             char fin)
{
	struct buffer htx_buf = BUF_NULL;
	struct buffer *tmp = get_trash_chunk();
	struct htx *htx = NULL;
	struct htx_sl *sl;
	struct http_hdr list[global.tune.max_http_hdr];
	unsigned int flags = HTX_SL_F_NONE;
	struct ist meth = IST_NULL, path = IST_NULL;
	//struct ist scheme = IST_NULL, authority = IST_NULL;
	struct ist authority = IST_NULL;
	int hdr_idx;

	/* TODO support buffer wrapping */
	BUG_ON(ncb_head(buf) + len >= ncb_wrap(buf));
	if (qpack_decode_fs((const unsigned char *)ncb_head(buf), len, tmp, list) < 0)
		return -1;

	qc_get_buf(qcs, &htx_buf);
	BUG_ON(!b_size(&htx_buf));
	htx = htx_from_buf(&htx_buf);

	/* first treat pseudo-header to build the start line */
	hdr_idx = 0;
	while (1) {
		if (isteq(list[hdr_idx].n, ist("")))
			break;

		if (istmatch(list[hdr_idx].n, ist(":"))) {
			/* pseudo-header */
			if (isteq(list[hdr_idx].n, ist(":method")))
				meth = list[hdr_idx].v;
			else if (isteq(list[hdr_idx].n, ist(":path")))
				path = list[hdr_idx].v;
			//else if (isteq(list[hdr_idx].n, ist(":scheme")))
			//	scheme = list[hdr_idx].v;
			else if (isteq(list[hdr_idx].n, ist(":authority")))
				authority = list[hdr_idx].v;
		}

		++hdr_idx;
	}

	flags |= HTX_SL_F_VER_11;
	flags |= HTX_SL_F_XFER_LEN;

	sl = htx_add_stline(htx, HTX_BLK_REQ_SL, flags, meth, path, ist("HTTP/3.0"));
	if (!sl)
		return -1;

	if (fin)
		sl->flags |= HTX_SL_F_BODYLESS;

	sl->info.req.meth = find_http_meth(meth.ptr, meth.len);
	BUG_ON(sl->info.req.meth == HTTP_METH_OTHER);

	if (isttest(authority))
		htx_add_header(htx, ist("host"), authority);

	/* now treat standard headers */
	hdr_idx = 0;
	while (1) {
		if (isteq(list[hdr_idx].n, ist("")))
			break;

		if (!istmatch(list[hdr_idx].n, ist(":")))
			htx_add_header(htx, list[hdr_idx].n, list[hdr_idx].v);

		++hdr_idx;
	}

	htx_add_endof(htx, HTX_BLK_EOH);
	htx_to_buf(htx, &htx_buf);

	if (fin)
		htx->flags |= HTX_FL_EOM;

	if (!qc_attach_cs(qcs, &htx_buf))
		return -1;

	/* buffer is transferred to the stream connector and set to NULL
	 * except on stream creation error.
	 */
	b_free(&htx_buf);
	offer_buffers(NULL, 1);

	return len;
}

/* Copy from buffer <buf> a H3 DATA frame of length <len> in QUIC stream <qcs>
 * HTX buffer. <fin> must be set if this is the last data to transfer from this
 * stream.
 *
 * Returns the number of bytes handled or a negative error code.
 */
static int h3_data_to_htx(struct qcs *qcs, struct ncbuf *buf, uint64_t len,
                          char fin)
{
	struct buffer *appbuf;
	struct htx *htx = NULL;
	size_t htx_sent = 0;
	int htx_space;
	char *head;

	appbuf = qc_get_buf(qcs, &qcs->rx.app_buf);
	BUG_ON(!appbuf);
	htx = htx_from_buf(appbuf);

	if (len > ncb_data(buf, 0)) {
		len = ncb_data(buf, 0);
		fin = 0;
	}

	head = ncb_head(buf);
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

	if (head + len > ncb_wrap(buf)) {
		size_t contig = ncb_wrap(buf) - head;
		htx_sent = htx_add_data(htx, ist2(ncb_head(buf), contig));
		if (htx_sent < contig) {
			qcs->flags |= QC_SF_DEM_FULL;
			goto out;
		}

		len -= contig;
		head = ncb_orig(buf);
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
	htx_to_buf(htx, appbuf);
	return htx_sent;
}

/* Parse a SETTINGS frame of length <len> of payload <rxbuf>.
 *
 * Returns the number of bytes handled or a negative error code.
 */
static size_t h3_parse_settings_frm(struct h3c *h3c, const struct ncbuf *rxbuf,
                                    size_t len)
{
	struct buffer b;
	uint64_t id, value;
	size_t ret = 0;
	long mask = 0;   /* used to detect duplicated settings identifier */

	b = h3_b_dup(rxbuf);
	b_set_data(&b, len);

	while (b_data(&b)) {
		if (!b_quic_dec_int(&id, &b, &ret) || !b_quic_dec_int(&value, &b, &ret)) {
			h3c->err = H3_FRAME_ERROR;
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
				h3c->err = H3_SETTINGS_ERROR;
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
			h3c->err = H3_SETTINGS_ERROR;
			return -1;
		default:
			/* MUST be ignored */
			break;
		}
	}

	return ret;
}

/* Decode <qcs> remotely initiated bidi-stream. <fin> must be set to indicate
 * that we received the last data of the stream.
 *
 * Returns 0 on success else non-zero.
 */
static int h3_decode_qcs(struct qcs *qcs, int fin, void *ctx)
{
	struct ncbuf *rxbuf = &qcs->rx.ncbuf;
	struct h3c *h3c = ctx;
	struct h3s *h3s = qcs->ctx;
	ssize_t ret;

	h3_debug_printf(stderr, "%s: STREAM ID: %lu\n", __func__, qcs->id);
	if (!ncb_data(rxbuf, 0))
		return 0;

	if (quic_stream_is_uni(qcs->id) && !(h3s->flags & H3_SF_UNI_INIT)) {
		if (h3_init_uni_stream(h3c, qcs, rxbuf))
			return 1;
	}

	if (quic_stream_is_uni(qcs->id) && (h3s->flags & H3_SF_UNI_NO_H3)) {
		/* For non-h3 STREAM, parse it and return immediately. */
		if (h3_parse_uni_stream_no_h3(qcs, rxbuf))
			return 1;
		return 0;
	}

	while (ncb_data(rxbuf, 0) && !(qcs->flags & QC_SF_DEM_FULL)) {
		uint64_t ftype, flen;
		struct buffer b;
		char last_stream_frame = 0;

		/* Work on a copy of <rxbuf> */
		b = h3_b_dup(rxbuf);
		if (!h3s->demux_frame_len) {
			size_t hlen = h3_decode_frm_header(&ftype, &flen, &b);
			if (!hlen)
				break;

			h3_debug_printf(stderr, "%s: ftype: %lu, flen: %lu\n",
			                __func__, ftype, flen);

			h3s->demux_frame_type = ftype;
			h3s->demux_frame_len = flen;
			qcs_consume(qcs, hlen);
		}

		flen = h3s->demux_frame_len;
		ftype = h3s->demux_frame_type;

		if (!h3_is_frame_valid(h3c, qcs, ftype)) {
			qcc_emit_cc_app(qcs->qcc, H3_FRAME_UNEXPECTED);
			return 1;
		}

		/* Do not demux incomplete frames except H3 DATA which can be
		 * fragmented in multiple HTX blocks.
		 */
		if (flen > b_data(&b) && ftype != H3_FT_DATA) {
			/* Reject frames bigger than bufsize.
			 *
			 * TODO HEADERS should in complement be limited with H3
			 * SETTINGS_MAX_FIELD_SECTION_SIZE parameter to prevent
			 * excessive decompressed size.
			 */
			if (flen > ncb_size(rxbuf)) {
				qcc_emit_cc_app(qcs->qcc, H3_EXCESSIVE_LOAD);
				return 1;
			}
			break;
		}

		last_stream_frame = (fin && flen == ncb_total_data(rxbuf));

		switch (ftype) {
		case H3_FT_DATA:
			ret = h3_data_to_htx(qcs, rxbuf, flen, last_stream_frame);
			/* TODO handle error reporting. Stream closure required. */
			if (ret < 0) { ABORT_NOW(); }
			break;
		case H3_FT_HEADERS:
			ret = h3_headers_to_htx(qcs, rxbuf, flen, last_stream_frame);
			/* TODO handle error reporting. Stream closure required. */
			if (ret < 0) { ABORT_NOW(); }
			break;
		case H3_FT_CANCEL_PUSH:
		case H3_FT_PUSH_PROMISE:
		case H3_FT_MAX_PUSH_ID:
		case H3_FT_GOAWAY:
			/* Not supported */
			ret = flen;
			break;
		case H3_FT_SETTINGS:
			ret = h3_parse_settings_frm(qcs->qcc->ctx, rxbuf, flen);
			if (ret < 0) {
				qcc_emit_cc_app(qcs->qcc, h3c->err);
				return 1;
			}
			h3c->flags |= H3_CF_SETTINGS_RECV;
			break;
		default:
			/* draft-ietf-quic-http34 9. Extensions to HTTP/3
			 *
			 * Implementations MUST discard frames [...] that have unknown
			 * or unsupported types.
			 */
			h3_debug_printf(stderr, "ignore unknown frame type 0x%lx\n", ftype);
			ret = flen;
			break;
		}

		if (ret) {
			BUG_ON(h3s->demux_frame_len < ret);
			h3s->demux_frame_len -= ret;
			qcs_consume(qcs, ret);
		}
	}

	/* TODO may be useful to wakeup the MUX if blocked due to full buffer.
	 * However, currently, io-cb of MUX does not handle Rx.
	 */

	return 0;
}

/* Returns buffer for data sending.
 * May be NULL if the allocation failed.
 */
static struct buffer *mux_get_buf(struct qcs *qcs)
{
	if (!b_size(&qcs->tx.buf))
		b_alloc(&qcs->tx.buf);

	return &qcs->tx.buf;
}

/* Function used to emit stream data from <qcs> control uni-stream */
static int h3_control_send(struct qcs *qcs, void *ctx)
{
	int ret;
	struct h3c *h3c = ctx;
	unsigned char data[(2 + 3) * 2 * QUIC_VARINT_MAX_SIZE]; /* enough for 3 settings */
	struct buffer pos, *res;
	size_t frm_len;

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

	b_quic_enc_int(&pos, H3_UNI_S_T_CTRL);
	/* Build a SETTINGS frame */
	b_quic_enc_int(&pos, H3_FT_SETTINGS);
	b_quic_enc_int(&pos, frm_len);
	b_quic_enc_int(&pos, H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY);
	b_quic_enc_int(&pos, h3_settings_qpack_max_table_capacity);
	b_quic_enc_int(&pos, H3_SETTINGS_QPACK_BLOCKED_STREAMS);
	b_quic_enc_int(&pos, h3_settings_qpack_blocked_streams);
	if (h3_settings_max_field_section_size) {
		b_quic_enc_int(&pos, H3_SETTINGS_MAX_FIELD_SECTION_SIZE);
		b_quic_enc_int(&pos, h3_settings_max_field_section_size);
	}

	res = mux_get_buf(qcs);
	if (b_room(res) < b_data(&pos)) {
		// TODO the mux should be put in blocked state, with
		// the stream in state waiting for settings to be sent
		ABORT_NOW();
	}

	ret = b_force_xfer(res, &pos, b_data(&pos));
	if (ret > 0) {
		h3c->flags |= H3_CF_SETTINGS_SENT;
		if (!(qcs->qcc->wait_event.events & SUB_RETRY_SEND))
			tasklet_wakeup(qcs->qcc->wait_event.tasklet);
	}

	return ret;
}

static int h3_resp_headers_send(struct qcs *qcs, struct htx *htx)
{
	struct buffer outbuf;
	struct buffer headers_buf = BUF_NULL;
	struct buffer *res;
	struct http_hdr list[global.tune.max_http_hdr];
	struct htx_sl *sl;
	struct htx_blk *blk;
	enum htx_blk_type type;
	int frame_length_size;  /* size in bytes of frame length varint field */
	int ret = 0;
	int hdr;
	int status = 0;

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
			list[hdr].n = htx_get_blk_name(htx, blk);
			list[hdr].v = htx_get_blk_value(htx, blk);
			hdr++;
		}
		else {
			ABORT_NOW();
			goto err;
		}
	}

	BUG_ON(!sl);

	list[hdr].n = ist("");

	res = mux_get_buf(qcs);

	/* At least 5 bytes to store frame type + length as a varint max size */
	if (b_room(res) < 5)
		ABORT_NOW();

	b_reset(&outbuf);
	outbuf = b_make(b_tail(res), b_contig_space(res), 0, 0);
	/* Start the headers after frame type + length */
	headers_buf = b_make(b_head(res) + 5, b_size(res) - 5, 0, 0);

	if (qpack_encode_field_section_line(&headers_buf))
		ABORT_NOW();
	if (qpack_encode_int_status(&headers_buf, status))
		ABORT_NOW();

	for (hdr = 0; hdr < sizeof(list) / sizeof(list[0]); ++hdr) {
		if (isteq(list[hdr].n, ist("")))
			break;

		/* draft-ietf-quic-http34 4.1. HTTP Message Exchanges
		 * Transfer codings (see Section 6.1 of [HTTP11]) are not
		 * defined for HTTP/3; the Transfer-Encoding header field MUST
		 * NOT be used.
		 */
		if (isteq(list[hdr].n, ist("transfer-encoding")))
			continue;

		if (qpack_encode_header(&headers_buf, list[hdr].n, list[hdr].v))
			ABORT_NOW();
	}

	/* Now that all headers are encoded, we are certain that res buffer is
	 * big enough
	 */
	frame_length_size = quic_int_getsize(b_data(&headers_buf));
	res->head += 4 - frame_length_size;
	b_putchr(res, 0x01); /* h3 HEADERS frame type */
	if (!b_quic_enc_int(res, b_data(&headers_buf)))
		ABORT_NOW();
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

	return ret;

 err:
	return 0;
}

/* Returns the total of bytes sent. */
static int h3_resp_data_send(struct qcs *qcs, struct buffer *buf, size_t count)
{
	struct buffer outbuf;
	struct buffer *res;
	size_t total = 0;
	struct htx *htx;
	int bsize, fsize, hsize;
	struct htx_blk *blk;
	enum htx_blk_type type;

	htx = htx_from_buf(buf);

 new_frame:
	if (!count || htx_is_empty(htx))
		goto end;

	blk = htx_get_head_blk(htx);
	type = htx_get_blk_type(blk);
	fsize = bsize = htx_get_blksz(blk);

	if (type != HTX_BLK_DATA)
		goto end;

	res = mux_get_buf(qcs);

	if (fsize > count)
		fsize = count;

	/* h3 DATA headers : 1-byte frame type + varint frame length */
	hsize = 1 + QUIC_VARINT_MAX_SIZE;

	while (1) {
		b_reset(&outbuf);
		outbuf = b_make(b_tail(res), b_contig_space(res), 0, 0);
		if (b_size(&outbuf) > hsize || !b_space_wraps(res))
			break;
		b_slow_realign(res, trash.area, b_data(res));
	}

	/* Not enough room for headers and at least one data byte, block the
	 * stream. It is expected that the stream connector layer will subscribe
	 * on SEND.
	 */
	if (b_size(&outbuf) <= hsize) {
		qcs->flags |= QC_SF_BLK_MROOM;
		goto end;
	}

	if (b_size(&outbuf) < hsize + fsize)
		fsize = b_size(&outbuf) - hsize;
	BUG_ON(fsize <= 0);

	b_putchr(&outbuf, 0x00);        /* h3 frame type = DATA */
	b_quic_enc_int(&outbuf, fsize); /* h3 frame length */

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
	return total;
}

size_t h3_snd_buf(struct stconn *cs, struct buffer *buf, size_t count, int flags)
{
	size_t total = 0;
	struct qcs *qcs = __sc_mux_strm(cs);
	struct htx *htx;
	enum htx_blk_type btype;
	struct htx_blk *blk;
	uint32_t bsize;
	int32_t idx;
	int ret;

	h3_debug_printf(stderr, "%s\n", __func__);

	htx = htx_from_buf(buf);

	while (count && !htx_is_empty(htx) && !(qcs->flags & QC_SF_BLK_MROOM)) {
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
			ret = h3_resp_data_send(qcs, buf, count);
			if (ret > 0) {
				htx = htx_from_buf(buf);
				total += ret;
				count -= ret;
				if (ret < bsize)
					goto out;
			}
			break;

		case HTX_BLK_TLR:
		case HTX_BLK_EOT:
			/* TODO trailers */

		default:
			htx_remove_blk(htx, blk);
			total += bsize;
			count -= bsize;
			break;
		}
	}

	if ((htx->flags & HTX_FL_EOM) && htx_is_empty(htx))
		qcs->flags |= QC_SF_FIN_STREAM;

 out:
	if (total) {
		if (!(qcs->qcc->wait_event.events & SUB_RETRY_SEND))
			tasklet_wakeup(qcs->qcc->wait_event.tasklet);
	}

	return total;
}

static int h3_attach(struct qcs *qcs)
{
	struct h3s *h3s;

	h3s = pool_alloc(pool_head_h3s);
	if (!h3s)
		return 1;

	qcs->ctx = h3s;
	h3s->demux_frame_len = 0;
	h3s->demux_frame_type = 0;
	h3s->flags = 0;

	if (quic_stream_is_bidi(qcs->id)) {
		h3s->type = H3S_T_REQ;
	}
	else {
		/* stream type must be decoded for unidirectional streams */
		h3s->type = H3S_T_UNKNOWN;
	}

	return 0;
}

static void h3_detach(struct qcs *qcs)
{
	struct h3s *h3s = qcs->ctx;
	pool_free(pool_head_h3s, h3s);
	qcs->ctx = NULL;
}

static int h3_finalize(void *ctx)
{
	struct h3c *h3c = ctx;
	struct qcs *qcs;

	qcs = qcs_new(h3c->qcc, 0x3, QCS_SRV_UNI);
	if (!qcs)
		return 0;

	h3_control_send(qcs, h3c);

	return 1;
}

/* Initialize the HTTP/3 context for <qcc> mux.
 * Return 1 if succeeded, 0 if not.
 */
static int h3_init(struct qcc *qcc)
{
	struct h3c *h3c;

	h3c = pool_alloc(pool_head_h3c);
	if (!h3c)
		goto fail_no_h3;

	h3c->qcc = qcc;
	h3c->err = H3_NO_ERROR;
	h3c->flags = 0;

	qcc->ctx = h3c;
	LIST_INIT(&h3c->buf_wait.list);

	return 1;

 fail_no_h3:
	return 0;
}

static void h3_release(void *ctx)
{
	struct h3c *h3c = ctx;
	pool_free(pool_head_h3c, h3c);
}

/* Check if the H3 connection can still be considered as active.
 *
 * Return true if active else false.
 */
static int h3_is_active(const struct qcc *qcc, void *ctx)
{
	if (qcc->strms[QCS_CLT_BIDI].nb_streams)
		return 1;

	return 0;
}

/* HTTP/3 application layer operations */
const struct qcc_app_ops h3_ops = {
	.init        = h3_init,
	.attach      = h3_attach,
	.decode_qcs  = h3_decode_qcs,
	.snd_buf     = h3_snd_buf,
	.detach      = h3_detach,
	.finalize    = h3_finalize,
	.is_active   = h3_is_active,
	.release     = h3_release,
};
