/*
 * Copyright 2019 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <string.h>

#include <import/eb64tree.h>
#include <haproxy/buf-t.h>
#include <haproxy/chunk.h>
#include <haproxy/pool.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_enc.h>
#include <haproxy/quic_frame.h>
#include <haproxy/quic_rx-t.h>
#include <haproxy/quic_tp-t.h>
#include <haproxy/quic_trace.h>
#include <haproxy/quic_tx.h>
#include <haproxy/trace.h>

DECLARE_POOL(pool_head_quic_frame, "quic_frame", sizeof(struct quic_frame));
DECLARE_POOL(pool_head_qf_crypto, "qf_crypto", sizeof(struct qf_crypto));

const char *quic_frame_type_string(enum quic_frame_type ft)
{
	switch (ft) {
	case QUIC_FT_PADDING:
		return "PADDING";
	case QUIC_FT_PING:
		return "PING";
	case QUIC_FT_ACK:
		return "ACK";
	case QUIC_FT_ACK_ECN:
		return "ACK_ECN";
	case QUIC_FT_RESET_STREAM:
		return "RESET_STREAM";
	case QUIC_FT_STOP_SENDING:
		return "STOP_SENDING";
	case QUIC_FT_CRYPTO:
		return "CRYPTO";
	case QUIC_FT_NEW_TOKEN:
		return "NEW_TOKEN";

	case QUIC_FT_STREAM_8:
		return "STREAM_8";
	case QUIC_FT_STREAM_9:
		return "STREAM_9";
	case QUIC_FT_STREAM_A:
		return "STREAM_A";
	case QUIC_FT_STREAM_B:
		return "STREAM_B";
	case QUIC_FT_STREAM_C:
		return "STREAM_C";
	case QUIC_FT_STREAM_D:
		return "STREAM_D";
	case QUIC_FT_STREAM_E:
		return "STREAM_E";
	case QUIC_FT_STREAM_F:
		return "STREAM_F";

	case QUIC_FT_MAX_DATA:
		return "MAX_DATA";
	case QUIC_FT_MAX_STREAM_DATA:
		return "MAX_STREAM_DATA";
	case QUIC_FT_MAX_STREAMS_BIDI:
		return "MAX_STREAMS_BIDI";
	case QUIC_FT_MAX_STREAMS_UNI:
		return "MAX_STREAMS_UNI";
	case QUIC_FT_DATA_BLOCKED:
		return "DATA_BLOCKED";
	case QUIC_FT_STREAM_DATA_BLOCKED:
		return "STREAM_DATA_BLOCKED";
	case QUIC_FT_STREAMS_BLOCKED_BIDI:
		return "STREAMS_BLOCKED_BIDI";
	case QUIC_FT_STREAMS_BLOCKED_UNI:
		return "STREAMS_BLOCKED_UNI";
	case QUIC_FT_NEW_CONNECTION_ID:
		return "NEW_CONNECTION_ID";
	case QUIC_FT_RETIRE_CONNECTION_ID:
		return "RETIRE_CONNECTION_ID";
	case QUIC_FT_PATH_CHALLENGE:
		return "PATH_CHALLENGE";
	case QUIC_FT_PATH_RESPONSE:
		return "PATH_RESPONSE";
	case QUIC_FT_CONNECTION_CLOSE:
		return "CONNECTION_CLOSE";
	case QUIC_FT_CONNECTION_CLOSE_APP:
		return "CONNECTION_CLOSE_APP";
	case QUIC_FT_HANDSHAKE_DONE:
		return "HANDSHAKE_DONE";
	default:
		return "UNKNOWN";
	}
}

static void chunk_cc_phrase_appendf(struct buffer *buf,
                                    const unsigned char *phr, size_t phrlen)
{
	chunk_appendf(buf, " reason_phrase: '");
	while (phrlen--)
		chunk_appendf(buf, "%c", *phr++);
	chunk_appendf(buf, "'");
}

/* Add traces to <buf> depending on <frm> frame type. */
void chunk_frm_appendf(struct buffer *buf, const struct quic_frame *frm)
{
	chunk_appendf(buf, " %s", quic_frame_type_string(frm->type));
	switch (frm->type) {
	case QUIC_FT_CRYPTO:
	{
		const struct qf_crypto *crypto_frm = &frm->crypto;
		chunk_appendf(buf, " cfoff=%llu cflen=%llu",
		              (ull)crypto_frm->offset, (ull)crypto_frm->len);
		break;
	}
	case QUIC_FT_RESET_STREAM:
	{
		const struct qf_reset_stream *rs_frm = &frm->reset_stream;
		chunk_appendf(buf, " id=%llu app_error_code=%llu final_size=%llu",
		              (ull)rs_frm->id, (ull)rs_frm->app_error_code, (ull)rs_frm->final_size);
		break;
	}
	case QUIC_FT_STOP_SENDING:
	{
		const struct qf_stop_sending *ss_frm = &frm->stop_sending;
		chunk_appendf(&trace_buf, " id=%llu app_error_code=%llu",
		              (ull)ss_frm->id, (ull)ss_frm->app_error_code);
		break;
	}
	case QUIC_FT_STREAM_8 ... QUIC_FT_STREAM_F:
	{
		const struct qf_stream *strm_frm = &frm->stream;
		chunk_appendf(&trace_buf, " uni=%d fin=%d id=%llu off=%llu len=%llu",
		              !!(strm_frm->id & QUIC_STREAM_FRAME_ID_DIR_BIT),
		              !!(frm->type & QUIC_STREAM_FRAME_TYPE_FIN_BIT),
		              (ull)strm_frm->id, (ull)strm_frm->offset, (ull)strm_frm->len);
		break;
	}
	case QUIC_FT_MAX_DATA:
	{
		const struct qf_max_data *md_frm = &frm->max_data;
		chunk_appendf(&trace_buf, " max_data=%llu", (ull)md_frm->max_data);
		break;
	}
	case QUIC_FT_MAX_STREAM_DATA:
	{
		const struct qf_max_stream_data *msd_frm = &frm->max_stream_data;
		chunk_appendf(&trace_buf, " id=%llu max_stream_data=%llu",
		              (ull)msd_frm->id, (ull)msd_frm->max_stream_data);
		break;
	}
	case QUIC_FT_MAX_STREAMS_BIDI:
	{
		const struct qf_max_streams *ms_frm = &frm->max_streams_bidi;
		chunk_appendf(&trace_buf, " max_streams=%llu", (ull)ms_frm->max_streams);
		break;
	}
	case QUIC_FT_MAX_STREAMS_UNI:
	{
		const struct qf_max_streams *ms_frm = &frm->max_streams_uni;
		chunk_appendf(&trace_buf, " max_streams=%llu", (ull)ms_frm->max_streams);
		break;
	}
	case QUIC_FT_DATA_BLOCKED:
	{
		const struct qf_data_blocked *db_frm = &frm->data_blocked;
		chunk_appendf(&trace_buf, " limit=%llu", (ull)db_frm->limit);
		break;
	}
	case QUIC_FT_STREAM_DATA_BLOCKED:
	{
		const struct qf_stream_data_blocked *sdb_frm = &frm->stream_data_blocked;
		chunk_appendf(&trace_buf, " id=%llu limit=%llu",
		              (ull)sdb_frm->id, (ull)sdb_frm->limit);
		break;
	}
	case QUIC_FT_STREAMS_BLOCKED_BIDI:
	{
		const struct qf_streams_blocked *sb_frm = &frm->streams_blocked_bidi;
		chunk_appendf(&trace_buf, " limit=%llu", (ull)sb_frm->limit);
		break;
	}
	case QUIC_FT_STREAMS_BLOCKED_UNI:
	{
		const struct qf_streams_blocked *sb_frm = &frm->streams_blocked_uni;
		chunk_appendf(&trace_buf, " limit=%llu", (ull)sb_frm->limit);
		break;
	}
	case QUIC_FT_RETIRE_CONNECTION_ID:
	{
		const struct qf_retire_connection_id *rcid_frm = &frm->retire_connection_id;
		chunk_appendf(&trace_buf, " seq_num=%llu", (ull)rcid_frm->seq_num);
		break;
	}
	case QUIC_FT_CONNECTION_CLOSE:
	{
		const struct qf_connection_close *cc_frm = &frm->connection_close;
		size_t plen = QUIC_MIN((size_t)cc_frm->reason_phrase_len, sizeof cc_frm->reason_phrase);
		chunk_appendf(&trace_buf,
		              " error_code=%llu frame_type=%llu reason_phrase_len=%llu",
		              (ull)cc_frm->error_code, (ull)cc_frm->frame_type,
		              (ull)cc_frm->reason_phrase_len);
		if (plen)
			chunk_cc_phrase_appendf(&trace_buf, cc_frm->reason_phrase, plen);
		break;
	}
	case QUIC_FT_CONNECTION_CLOSE_APP:
	{
		const struct qf_connection_close_app *cc_frm = &frm->connection_close_app;
		size_t plen = QUIC_MIN((size_t)cc_frm->reason_phrase_len, sizeof cc_frm->reason_phrase);
		chunk_appendf(&trace_buf,
		              " error_code=%llu reason_phrase_len=%llu",
		              (ull)cc_frm->error_code, (ull)cc_frm->reason_phrase_len);
		if (plen)
			chunk_cc_phrase_appendf(&trace_buf, cc_frm->reason_phrase, plen);
		break;
	}
	}
}

/* Encode <frm> PADDING frame at <pos> buffer position, <end> being one byte past the end
 * of this buffer.
 * Returns 1 if succeeded (enough room in the buffer to encode the frame), 0 if not.
 */
static int quic_build_padding_frame(unsigned char **pos, const unsigned char *end,
                                    struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_padding *padding_frm = &frm->padding;

	if (end - *pos < padding_frm->len - 1)
		return 0;

	memset(*pos, 0, padding_frm->len - 1);
	*pos += padding_frm->len - 1;

	return 1;
}

/* Parse a PADDING frame at <pos> buffer position with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_padding_frame(struct quic_frame *frm, struct quic_conn *qc,
                                    const unsigned char **pos, const unsigned char *end)
{
	const unsigned char *beg;
	struct qf_padding *padding_frm = &frm->padding;

	beg = *pos;
	padding_frm->len = 1;
	while (*pos < end && !**pos)
		(*pos)++;
	padding_frm->len += *pos - beg;

	return 1;
}

/* Encode a ACK frame at <pos> buffer position.
 * Always succeeds.
 */
static int quic_build_ping_frame(unsigned char **pos, const unsigned char *end,
                                 struct quic_frame *frm, struct quic_conn *conn)
{
	/* No field */
	return 1;
}

/* Parse a PADDING frame from <pos> buffer position with <end> as end into <frm> frame.
 * Always succeeds.
 */
static int quic_parse_ping_frame(struct quic_frame *frm, struct quic_conn *qc,
                                 const unsigned char **pos, const unsigned char *end)
{
	/* No field */
	return 1;
}

/* Encode a ACK frame.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_ack_frame(unsigned char **pos, const unsigned char *end,
                                struct quic_frame *frm, struct quic_conn *qc)
{
	struct qf_tx_ack *ack_frm = &frm->tx_ack;
	struct eb64_node *ar, *prev_ar;
	struct quic_arng_node *ar_node, *prev_ar_node;

	ar = eb64_last(&ack_frm->arngs->root);
	ar_node = eb64_entry(ar, struct quic_arng_node, first);
	TRACE_PROTO("TX ack range", QUIC_EV_CONN_PRSAFRM,
	            qc,, &ar_node->last, &ar_node->first.key);
	if (!quic_enc_int(pos, end, ar_node->last) ||
	    !quic_enc_int(pos, end, ack_frm->ack_delay) ||
	    !quic_enc_int(pos, end, ack_frm->arngs->sz - 1) ||
	    !quic_enc_int(pos, end, ar_node->last - ar_node->first.key))
		return 0;

	while ((prev_ar = eb64_prev(ar))) {
		prev_ar_node = eb64_entry(prev_ar, struct quic_arng_node, first);
		TRACE_PROTO("TX ack range", QUIC_EV_CONN_PRSAFRM, qc,,
		            &prev_ar_node->last, &prev_ar_node->first.key);
		if (!quic_enc_int(pos, end, ar_node->first.key - prev_ar_node->last - 2) ||
		    !quic_enc_int(pos, end, prev_ar_node->last - prev_ar_node->first.key))
			return 0;

		ar = prev_ar;
		ar_node = eb64_entry(ar, struct quic_arng_node, first);
	}

	return 1;
}

/* Parse an ACK frame header at <pos> buffer position with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room at <pos> buffer position to parse this frame), 0 if not.
 */
static int quic_parse_ack_frame_header(struct quic_frame *frm, struct quic_conn *qc,
                                       const unsigned char **pos, const unsigned char *end)
{
	int ret;
	struct qf_ack *ack_frm = &frm->ack;

	ret = quic_dec_int(&ack_frm->largest_ack, pos, end);
	if (!ret)
		return 0;

	ret = quic_dec_int(&ack_frm->ack_delay, pos, end);
	if (!ret)
		return 0;

	ret = quic_dec_int(&ack_frm->ack_range_num, pos, end);
	if (!ret)
		return 0;

	ret = quic_dec_int(&ack_frm->first_ack_range, pos, end);
	if (!ret)
		return 0;

	return 1;
}

/* Encode a ACK_ECN frame.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_ack_ecn_frame(unsigned char **pos, const unsigned char *end,
                                    struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_ack *ack_frm = &frm->ack;

	return quic_enc_int(pos, end, ack_frm->largest_ack) &&
		quic_enc_int(pos, end, ack_frm->ack_delay) &&
		quic_enc_int(pos, end, ack_frm->first_ack_range) &&
		quic_enc_int(pos, end, ack_frm->ack_range_num);
}

/* Parse an ACK_ECN frame at <pos> buffer position with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough at <pos> buffer position to parse this frame), 0 if not.
 */
static int quic_parse_ack_ecn_frame(struct quic_frame *frm, struct quic_conn *qc,
                                    const unsigned char **pos, const unsigned char *end)
{
	struct qf_ack *ack_frm = &frm->ack;

	return quic_dec_int(&ack_frm->largest_ack, pos, end) &&
		quic_dec_int(&ack_frm->ack_delay, pos, end) &&
		quic_dec_int(&ack_frm->first_ack_range, pos, end) &&
		quic_dec_int(&ack_frm->ack_range_num, pos, end);
}

/* Encode a RESET_STREAM frame at <pos> buffer position.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_reset_stream_frame(unsigned char **pos, const unsigned char *end,
                                         struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_reset_stream *rs_frm = &frm->reset_stream;

	return quic_enc_int(pos, end, rs_frm->id) &&
		quic_enc_int(pos, end, rs_frm->app_error_code) &&
		quic_enc_int(pos, end, rs_frm->final_size);
}

/* Parse a RESET_STREAM frame at <pos> buffer position with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_reset_stream_frame(struct quic_frame *frm, struct quic_conn *qc,
                                         const unsigned char **pos, const unsigned char *end)
{
	struct qf_reset_stream *rs_frm = &frm->reset_stream;

	return quic_dec_int(&rs_frm->id, pos, end) &&
		quic_dec_int(&rs_frm->app_error_code, pos, end) &&
		quic_dec_int(&rs_frm->final_size, pos, end);
}

/* Encode a STOP_SENDING frame.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_stop_sending_frame(unsigned char **pos, const unsigned char *end,
                                         struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_stop_sending *ss_frm = &frm->stop_sending;

	return quic_enc_int(pos, end, ss_frm->id) &&
		quic_enc_int(pos, end, ss_frm->app_error_code);
}

/* Parse a STOP_SENDING frame at <pos> buffer position with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room at <pos> buffer position to parse this frame), 0 if not.
 */
static int quic_parse_stop_sending_frame(struct quic_frame *frm, struct quic_conn *qc,
                                         const unsigned char **pos, const unsigned char *end)
{
	struct qf_stop_sending *ss_frm = &frm->stop_sending;

	return quic_dec_int(&ss_frm->id, pos, end) &&
		quic_dec_int(&ss_frm->app_error_code, pos, end);
}

/* Encode a CRYPTO frame at <pos> buffer position.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_crypto_frame(unsigned char **pos, const unsigned char *end,
                                   struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_crypto *crypto_frm = &frm->crypto;
	const struct quic_enc_level *qel = crypto_frm->qel;
	size_t offset, len;

	if (!quic_enc_int(pos, end, crypto_frm->offset) ||
	    !quic_enc_int(pos, end, crypto_frm->len) || end - *pos < crypto_frm->len)
		return 0;

	len = crypto_frm->len;
	offset = crypto_frm->offset;
	while (len) {
		int idx;
		size_t to_copy;
		const unsigned char *data;

		idx = offset >> QUIC_CRYPTO_BUF_SHIFT;
		to_copy = qel->tx.crypto.bufs[idx]->sz - (offset & QUIC_CRYPTO_BUF_MASK);
		if (to_copy > len)
			to_copy = len;
		data = qel->tx.crypto.bufs[idx]->data + (offset & QUIC_CRYPTO_BUF_MASK);
		memcpy(*pos, data, to_copy);
		*pos += to_copy;
		offset += to_copy;
		len -= to_copy;
	}

	return 1;
}

/* Parse a CRYPTO frame from <pos> buffer position with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_crypto_frame(struct quic_frame *frm, struct quic_conn *qc,
                                   const unsigned char **pos, const unsigned char *end)
{
	struct qf_crypto *crypto_frm = &frm->crypto;

	if (!quic_dec_int(&crypto_frm->offset, pos, end) ||
	    !quic_dec_int(&crypto_frm->len, pos, end) || end - *pos < crypto_frm->len)
		return 0;

	crypto_frm->data = *pos;
	*pos += crypto_frm->len;

	return 1;
}

/* Server only function.
 * Encode a NEW_TOKEN frame at <pos> buffer position.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_new_token_frame(unsigned char **pos, const unsigned char *end,
                                      struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_new_token *new_token_frm = &frm->new_token;

	if (!quic_enc_int(pos, end, new_token_frm->len) || end - *pos < new_token_frm->len)
		return 0;

	memcpy(*pos, new_token_frm->data, new_token_frm->len);
	*pos += new_token_frm->len;

	return 1;
}

/* Client only function.
 * Parse a NEW_TOKEN frame at <pos> buffer position with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room at <pos> buffer position to parse this frame), 0 if not.
 */
static int quic_parse_new_token_frame(struct quic_frame *frm, struct quic_conn *qc,
                                      const unsigned char **pos, const unsigned char *end)
{
	struct qf_new_token *new_token_frm = &frm->new_token;

	if (!quic_dec_int(&new_token_frm->len, pos, end) || end - *pos < new_token_frm->len ||
	    sizeof(new_token_frm->data) < new_token_frm->len)
		return 0;

	memcpy(new_token_frm->data, *pos, new_token_frm->len);
	*pos += new_token_frm->len;

	return 1;
}

/* Encode a STREAM frame at <pos> buffer position.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_stream_frame(unsigned char **pos, const unsigned char *end,
                                   struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_stream *strm_frm = &frm->stream;
	const unsigned char *wrap;

	/* Caller must set OFF bit if and only if a non-null offset is used. */
	BUG_ON(!!(frm->type & QUIC_STREAM_FRAME_TYPE_OFF_BIT) !=
	       !!strm_frm->offset);

	if (!quic_enc_int(pos, end, strm_frm->id) ||
	    ((frm->type & QUIC_STREAM_FRAME_TYPE_OFF_BIT) && !quic_enc_int(pos, end, strm_frm->offset)) ||
	    ((frm->type & QUIC_STREAM_FRAME_TYPE_LEN_BIT) &&
	     (!quic_enc_int(pos, end, strm_frm->len) || end - *pos < strm_frm->len)))
		return 0;

	/* No need for data memcpy if no payload. */
	if (!strm_frm->len)
		return 1;

	wrap = (const unsigned char *)b_wrap(strm_frm->buf);
	if (strm_frm->data + strm_frm->len > wrap) {
		size_t to_copy = wrap - strm_frm->data;
		memcpy(*pos, strm_frm->data, to_copy);
		*pos += to_copy;

		to_copy = strm_frm->len - to_copy;
		memcpy(*pos, b_orig(strm_frm->buf), to_copy);
		*pos += to_copy;
	}
	else {
		memcpy(*pos, strm_frm->data, strm_frm->len);
		*pos += strm_frm->len;
	}

	return 1;
}

/* Parse a STREAM frame at <pos> buffer position with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room at <pos> buffer position to parse this frame), 0 if not.
 */
static int quic_parse_stream_frame(struct quic_frame *frm, struct quic_conn *qc,
                                   const unsigned char **pos, const unsigned char *end)
{
	struct qf_stream *strm_frm = &frm->stream;

	if (!quic_dec_int(&strm_frm->id, pos, end))
		return 0;

	/* Offset parsing */
	if (!(frm->type & QUIC_STREAM_FRAME_TYPE_OFF_BIT))
		strm_frm->offset = 0;
	else if (!quic_dec_int((uint64_t *)&strm_frm->offset, pos, end))
		return 0;

	/* Length parsing */
	if (!(frm->type & QUIC_STREAM_FRAME_TYPE_LEN_BIT)) {
		strm_frm->len = end - *pos;
	}
	else if (!quic_dec_int(&strm_frm->len, pos, end) || end - *pos < strm_frm->len)
		return 0;

	strm_frm->data = *pos;
	*pos += strm_frm->len;

	return 1;
}

/* Encode a MAX_DATA frame at <pos> buffer position.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_max_data_frame(unsigned char **pos, const unsigned char *end,
                                     struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_max_data *md_frm = &frm->max_data;

	return quic_enc_int(pos, end, md_frm->max_data);
}

/* Parse a MAX_DATA frame at <pos> buffer position with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_max_data_frame(struct quic_frame *frm, struct quic_conn *qc,
                                     const unsigned char **pos, const unsigned char *end)
{
	struct qf_max_data *md_frm = &frm->max_data;

	return quic_dec_int(&md_frm->max_data, pos, end);
}

/* Encode a MAX_STREAM_DATA frame at <pos> buffer position.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_max_stream_data_frame(unsigned char **pos, const unsigned char *end,
                                            struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_max_stream_data *msd_frm = &frm->max_stream_data;

	return quic_enc_int(pos, end, msd_frm->id) &&
		quic_enc_int(pos, end, msd_frm->max_stream_data);
}

/* Parse a MAX_STREAM_DATA frame at <pos> buffer position with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_max_stream_data_frame(struct quic_frame *frm, struct quic_conn *qc,
                                            const unsigned char **pos, const unsigned char *end)
{
	struct qf_max_stream_data *msd_frm = &frm->max_stream_data;

	return quic_dec_int(&msd_frm->id, pos, end) &&
		quic_dec_int(&msd_frm->max_stream_data, pos, end);
}

/* Encode a MAX_STREAMS frame for bidirectional streams at <buf> buffer position.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_max_streams_bidi_frame(unsigned char **pos, const unsigned char *end,
                                             struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_max_streams *ms_frm = &frm->max_streams_bidi;

	return quic_enc_int(pos, end, ms_frm->max_streams);
}

/* Parse a MAX_STREAMS frame for bidirectional streams at <pos> buffer position with <end>
 * as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_max_streams_bidi_frame(struct quic_frame *frm, struct quic_conn *qc,
                                             const unsigned char **pos, const unsigned char *end)
{
	struct qf_max_streams *ms_frm = &frm->max_streams_bidi;

	return quic_dec_int(&ms_frm->max_streams, pos, end);
}

/* Encode a MAX_STREAMS frame for unidirectional streams at <pos> buffer position.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_max_streams_uni_frame(unsigned char **pos, const unsigned char *end,
                                            struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_max_streams *ms_frm = &frm->max_streams_uni;

	return quic_enc_int(pos, end, ms_frm->max_streams);
}

/* Parse a MAX_STREAMS frame for undirectional streams at <pos> buffer position with <end>
 * as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_max_streams_uni_frame(struct quic_frame *frm, struct quic_conn *qc,
                                            const unsigned char **pos, const unsigned char *end)
{
	struct qf_max_streams *ms_frm = &frm->max_streams_uni;

	return quic_dec_int(&ms_frm->max_streams, pos, end);
}

/* Encode a DATA_BLOCKED frame at <pos> buffer position.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_data_blocked_frame(unsigned char **pos, const unsigned char *end,
                                         struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_data_blocked *db_frm = &frm->data_blocked;

	return quic_enc_int(pos, end, db_frm->limit);
}

/* Parse a DATA_BLOCKED frame at <pos> buffer position with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_data_blocked_frame(struct quic_frame *frm, struct quic_conn *qc,
                                         const unsigned char **pos, const unsigned char *end)
{
	struct qf_data_blocked *db_frm = &frm->data_blocked;

	return quic_dec_int(&db_frm->limit, pos, end);
}

/* Encode a STREAM_DATA_BLOCKED at <pos> buffer position.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_stream_data_blocked_frame(unsigned char **pos, const unsigned char *end,
                                                struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_stream_data_blocked *sdb_frm = &frm->stream_data_blocked;

	return quic_enc_int(pos, end, sdb_frm->id) &&
		quic_enc_int(pos, end, sdb_frm->limit);
}

/* Parse a STREAM_DATA_BLOCKED frame at <pos> buffer position with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_stream_data_blocked_frame(struct quic_frame *frm, struct quic_conn *qc,
                                                const unsigned char **pos, const unsigned char *end)
{
	struct qf_stream_data_blocked *sdb_frm = &frm->stream_data_blocked;

	return quic_dec_int(&sdb_frm->id, pos, end) &&
		quic_dec_int(&sdb_frm->limit, pos, end);
}

/* Encode a STREAMS_BLOCKED frame for bidirectional streams at <pos> buffer position.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_streams_blocked_bidi_frame(unsigned char **pos, const unsigned char *end,
                                                 struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_streams_blocked *sb_frm = &frm->streams_blocked_bidi;

	return quic_enc_int(pos, end, sb_frm->limit);
}

/* Parse a STREAMS_BLOCKED frame for bidirectional streams at <pos> buffer position with <end>
 * as end into <frm> frame.
 * Return 1 if succeeded (enough room at <pos> buffer position to parse this frame), 0 if not.
 */
static int quic_parse_streams_blocked_bidi_frame(struct quic_frame *frm, struct quic_conn *qc,
                                                 const unsigned char **pos, const unsigned char *end)
{
	struct qf_streams_blocked *sb_frm = &frm->streams_blocked_bidi;

	return quic_dec_int(&sb_frm->limit, pos, end);
}

/* Encode a STREAMS_BLOCKED frame for unidirectional streams at <pos> buffer position.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_streams_blocked_uni_frame(unsigned char **pos, const unsigned char *end,
                                                struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_streams_blocked *sb_frm = &frm->streams_blocked_uni;

	return quic_enc_int(pos, end, sb_frm->limit);
}

/* Parse a STREAMS_BLOCKED frame for unidirectional streams at <pos> buffer position with <end>
 * as end into <frm> frame.
 * Return 1 if succeeded (enough room at <pos> buffer position to parse this frame), 0 if not.
 */
static int quic_parse_streams_blocked_uni_frame(struct quic_frame *frm, struct quic_conn *qc,
                                                const unsigned char **pos, const unsigned char *end)
{
	struct qf_streams_blocked *sb_frm = &frm->streams_blocked_uni;

	return quic_dec_int(&sb_frm->limit, pos, end);
}

/* Encode a NEW_CONNECTION_ID frame at <pos> buffer position.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_new_connection_id_frame(unsigned char **pos, const unsigned char *end,
                                              struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_new_connection_id *ncid_frm = &frm->new_connection_id;

	if (!quic_enc_int(pos, end, ncid_frm->seq_num) ||
	    !quic_enc_int(pos, end, ncid_frm->retire_prior_to) ||
	    end - *pos < sizeof ncid_frm->cid.len + ncid_frm->cid.len + QUIC_STATELESS_RESET_TOKEN_LEN)
		return 0;

	*(*pos)++ = ncid_frm->cid.len;

	if (ncid_frm->cid.len) {
		memcpy(*pos, ncid_frm->cid.data, ncid_frm->cid.len);
		*pos += ncid_frm->cid.len;
	}
	memcpy(*pos, ncid_frm->stateless_reset_token, QUIC_STATELESS_RESET_TOKEN_LEN);
	*pos += QUIC_STATELESS_RESET_TOKEN_LEN;

	return 1;
}

/* Parse a NEW_CONNECTION_ID frame at <pos> buffer position with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_new_connection_id_frame(struct quic_frame *frm, struct quic_conn *qc,
                                              const unsigned char **pos, const unsigned char *end)
{
	struct qf_new_connection_id *ncid_frm = &frm->new_connection_id;

	if (!quic_dec_int(&ncid_frm->seq_num, pos, end) ||
	    !quic_dec_int(&ncid_frm->retire_prior_to, pos, end) || end <= *pos)
		return 0;

	ncid_frm->cid.len = *(*pos)++;
	if (end - *pos < ncid_frm->cid.len + QUIC_STATELESS_RESET_TOKEN_LEN)
		return 0;

	if (ncid_frm->cid.len) {
		ncid_frm->cid.data = *pos;
		*pos += ncid_frm->cid.len;
	}
	ncid_frm->stateless_reset_token = *pos;
	*pos += QUIC_STATELESS_RESET_TOKEN_LEN;

	return 1;
}

/* Encode a RETIRE_CONNECTION_ID frame at <pos> buffer position.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_retire_connection_id_frame(unsigned char **pos, const unsigned char *end,
                                                 struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_retire_connection_id *rcid_frm = &frm->retire_connection_id;

	return quic_enc_int(pos, end, rcid_frm->seq_num);
}

/* Parse a RETIRE_CONNECTION_ID frame at <pos> buffer position with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_retire_connection_id_frame(struct quic_frame *frm, struct quic_conn *qc,
                                                 const unsigned char **pos, const unsigned char *end)
{
	struct qf_retire_connection_id *rcid_frm = &frm->retire_connection_id;

	return quic_dec_int(&rcid_frm->seq_num, pos, end);
}

/* Encode a PATH_CHALLENGE frame at <pos> buffer position.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_path_challenge_frame(unsigned char **pos, const unsigned char *end,
                                           struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_path_challenge *pc_frm = &frm->path_challenge;

	if (end - *pos < sizeof pc_frm->data)
		return 0;

	memcpy(*pos, pc_frm->data, sizeof pc_frm->data);
	*pos += sizeof pc_frm->data;

	return 1;
}

/* Parse a PATH_CHALLENGE frame at <pos> buffer position with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room at <pos> buffer position to parse this frame), 0 if not.
 */
static int quic_parse_path_challenge_frame(struct quic_frame *frm, struct quic_conn *qc,
                                           const unsigned char **pos, const unsigned char *end)
{
	struct qf_path_challenge *pc_frm = &frm->path_challenge;

	if (end - *pos < sizeof pc_frm->data)
		return 0;

	memcpy(pc_frm->data, *pos, sizeof pc_frm->data);
	*pos += sizeof pc_frm->data;

	return 1;
}


/* Encode a PATH_RESPONSE frame at <pos> buffer position.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_path_response_frame(unsigned char **pos, const unsigned char *end,
                                          struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_path_challenge_response *pcr_frm = &frm->path_challenge_response;

	if (end - *pos < sizeof pcr_frm->data)
		return 0;

	memcpy(*pos, pcr_frm->data, sizeof pcr_frm->data);
	*pos += sizeof pcr_frm->data;

	return 1;
}

/* Parse a PATH_RESPONSE frame at <pos> buffer position with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room at <pos> buffer position to parse this frame), 0 if not.
 */
static int quic_parse_path_response_frame(struct quic_frame *frm, struct quic_conn *qc,
                                          const unsigned char **pos, const unsigned char *end)
{
	struct qf_path_challenge_response *pcr_frm = &frm->path_challenge_response;

	if (end - *pos < sizeof pcr_frm->data)
		return 0;

	memcpy(pcr_frm->data, *pos, sizeof pcr_frm->data);
	*pos += sizeof pcr_frm->data;

	return 1;
}

/* Encode a CONNECTION_CLOSE frame at QUIC layer at <pos> buffer position.
 * Note there exist two types of CONNECTION_CLOSE frame, one for the application layer
 * and another at QUIC layer.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_connection_close_frame(unsigned char **pos, const unsigned char *end,
                                             struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_connection_close *cc_frm = &frm->connection_close;

	if (!quic_enc_int(pos, end, cc_frm->error_code) ||
	    !quic_enc_int(pos, end, cc_frm->frame_type) ||
	    !quic_enc_int(pos, end, cc_frm->reason_phrase_len) ||
	    end - *pos < cc_frm->reason_phrase_len)
		return 0;

	memcpy(*pos, cc_frm->reason_phrase, cc_frm->reason_phrase_len);
	*pos += cc_frm->reason_phrase_len;

	return 1;
}

/* Parse a CONNECTION_CLOSE frame at QUIC layer at <pos> buffer position with <end> as end into <frm> frame.
 * Note there exist two types of CONNECTION_CLOSE frame, one for the application layer
 * and another at QUIC layer.
 * Return 1 if succeeded (enough room at <pos> buffer position to parse this frame), 0 if not.
 */
static int quic_parse_connection_close_frame(struct quic_frame *frm, struct quic_conn *qc,
                                             const unsigned char **pos, const unsigned char *end)
{
	size_t plen;
	struct qf_connection_close *cc_frm = &frm->connection_close;

	if (!quic_dec_int(&cc_frm->error_code, pos, end) ||
	    !quic_dec_int(&cc_frm->frame_type, pos, end) ||
	    !quic_dec_int(&cc_frm->reason_phrase_len, pos, end) ||
	    end - *pos < cc_frm->reason_phrase_len)
		return 0;

	plen = QUIC_MIN((size_t)cc_frm->reason_phrase_len, sizeof cc_frm->reason_phrase);
	memcpy(cc_frm->reason_phrase, *pos, plen);
	*pos += cc_frm->reason_phrase_len;

	return 1;
}

/* Encode a CONNECTION_CLOSE frame at application layer at <pos> buffer position.
 * Note there exist two types of CONNECTION_CLOSE frame, one for application layer
 * and another at QUIC layer.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 */
static int quic_build_connection_close_app_frame(unsigned char **pos, const unsigned char *end,
                                                 struct quic_frame *frm, struct quic_conn *conn)
{
	struct qf_connection_close_app *cc_frm = &frm->connection_close_app;

	if (!quic_enc_int(pos, end, cc_frm->error_code) ||
	    !quic_enc_int(pos, end, cc_frm->reason_phrase_len) ||
	    end - *pos < cc_frm->reason_phrase_len)
		return 0;

	memcpy(*pos, cc_frm->reason_phrase, cc_frm->reason_phrase_len);
	*pos += cc_frm->reason_phrase_len;

	return 1;
}

/* Parse a CONNECTION_CLOSE frame at QUIC layer at <pos> buffer position with <end> as end into <frm> frame.
 * Note there exist two types of CONNECTION_CLOSE frame, one for the application layer
 * and another at QUIC layer.
 * Return 1 if succeeded (enough room at <pos> buffer position to parse this frame), 0 if not.
 */
static int quic_parse_connection_close_app_frame(struct quic_frame *frm, struct quic_conn *qc,
                                                 const unsigned char **pos, const unsigned char *end)
{
	size_t plen;
	struct qf_connection_close_app *cc_frm = &frm->connection_close_app;

	if (!quic_dec_int(&cc_frm->error_code, pos, end) ||
	    !quic_dec_int(&cc_frm->reason_phrase_len, pos, end) ||
	    end - *pos < cc_frm->reason_phrase_len)
		return 0;

	plen = QUIC_MIN((size_t)cc_frm->reason_phrase_len, sizeof cc_frm->reason_phrase);
	memcpy(cc_frm->reason_phrase, *pos, plen);
	*pos += cc_frm->reason_phrase_len;

	return 1;
}

/* Encode a HANDSHAKE_DONE frame at <pos> buffer position.
 * Always succeeds.
 */
static int quic_build_handshake_done_frame(unsigned char **pos, const unsigned char *end,
                                           struct quic_frame *frm, struct quic_conn *conn)
{
	/* No field */
	return 1;
}

/* Parse a HANDSHAKE_DONE frame at QUIC layer at <pos> buffer position with <end> as end into <frm> frame.
 * Always succeed.
 */
static int quic_parse_handshake_done_frame(struct quic_frame *frm, struct quic_conn *qc,
                                           const unsigned char **pos, const unsigned char *end)
{
	/* No field */
	return 1;
}

struct quic_frame_builder {
	int (*func)(unsigned char **pos, const unsigned char *end,
                 struct quic_frame *frm, struct quic_conn *conn);
	uint32_t mask;
	unsigned char flags;
};

const struct quic_frame_builder quic_frame_builders[] = {
	[QUIC_FT_PADDING]              = { .func = quic_build_padding_frame,              .flags = QUIC_FL_TX_PACKET_PADDING,       .mask = QUIC_FT_PKT_TYPE_IH01_BITMASK, },
	[QUIC_FT_PING]                 = { .func = quic_build_ping_frame,                 .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE_IH01_BITMASK, },
	[QUIC_FT_ACK]                  = { .func = quic_build_ack_frame,                  .flags = 0,                               .mask = QUIC_FT_PKT_TYPE_IH_1_BITMASK, },
	[QUIC_FT_ACK_ECN]              = { .func = quic_build_ack_ecn_frame,              .flags = 0,                               .mask = QUIC_FT_PKT_TYPE_IH_1_BITMASK, },
	[QUIC_FT_RESET_STREAM]         = { .func = quic_build_reset_stream_frame,         .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STOP_SENDING]         = { .func = quic_build_stop_sending_frame,         .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_CRYPTO]               = { .func = quic_build_crypto_frame,               .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE_IH_1_BITMASK, },
	[QUIC_FT_NEW_TOKEN]            = { .func = quic_build_new_token_frame,            .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE____1_BITMASK, },
	[QUIC_FT_STREAM_8]             = { .func = quic_build_stream_frame,               .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAM_9]             = { .func = quic_build_stream_frame,               .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAM_A]             = { .func = quic_build_stream_frame,               .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAM_B]             = { .func = quic_build_stream_frame,               .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAM_C]             = { .func = quic_build_stream_frame,               .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAM_D]             = { .func = quic_build_stream_frame,               .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAM_E]             = { .func = quic_build_stream_frame,               .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAM_F]             = { .func = quic_build_stream_frame,               .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_MAX_DATA]             = { .func = quic_build_max_data_frame,             .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_MAX_STREAM_DATA]      = { .func = quic_build_max_stream_data_frame,      .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_MAX_STREAMS_BIDI]     = { .func = quic_build_max_streams_bidi_frame,     .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_MAX_STREAMS_UNI]      = { .func = quic_build_max_streams_uni_frame,      .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_DATA_BLOCKED]         = { .func = quic_build_data_blocked_frame,         .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAM_DATA_BLOCKED]  = { .func = quic_build_stream_data_blocked_frame,  .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAMS_BLOCKED_BIDI] = { .func = quic_build_streams_blocked_bidi_frame, .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAMS_BLOCKED_UNI]  = { .func = quic_build_streams_blocked_uni_frame,  .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_NEW_CONNECTION_ID]    = { .func = quic_build_new_connection_id_frame,    .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_RETIRE_CONNECTION_ID] = { .func = quic_build_retire_connection_id_frame, .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_PATH_CHALLENGE]       = { .func = quic_build_path_challenge_frame,       .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_PATH_RESPONSE]        = { .func = quic_build_path_response_frame,        .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_CONNECTION_CLOSE]     = { .func = quic_build_connection_close_frame,     .flags = 0,                               .mask = QUIC_FT_PKT_TYPE_IH01_BITMASK, },
	[QUIC_FT_CONNECTION_CLOSE_APP] = { .func = quic_build_connection_close_app_frame, .flags = 0,                               .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_HANDSHAKE_DONE]       = { .func = quic_build_handshake_done_frame,       .flags = QUIC_FL_TX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE____1_BITMASK, },
};

struct quic_frame_parser {
	int (*func)(struct quic_frame *frm, struct quic_conn *qc,
                const unsigned char **pos, const unsigned char *end);
	uint32_t mask;
	unsigned char flags;
};

const struct quic_frame_parser quic_frame_parsers[] = {
	[QUIC_FT_PADDING]              = { .func = quic_parse_padding_frame,              .flags = 0,                               .mask = QUIC_FT_PKT_TYPE_IH01_BITMASK, },
	[QUIC_FT_PING]                 = { .func = quic_parse_ping_frame,                 .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE_IH01_BITMASK, },
	[QUIC_FT_ACK]                  = { .func = quic_parse_ack_frame_header,           .flags = 0,                               .mask = QUIC_FT_PKT_TYPE_IH_1_BITMASK, },
	[QUIC_FT_ACK_ECN]              = { .func = quic_parse_ack_ecn_frame,              .flags = 0,                               .mask = QUIC_FT_PKT_TYPE_IH_1_BITMASK, },
	[QUIC_FT_RESET_STREAM]         = { .func = quic_parse_reset_stream_frame,         .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STOP_SENDING]         = { .func = quic_parse_stop_sending_frame,         .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_CRYPTO]               = { .func = quic_parse_crypto_frame,               .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE_IH_1_BITMASK, },
	[QUIC_FT_NEW_TOKEN]            = { .func = quic_parse_new_token_frame,            .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE____1_BITMASK, },
	[QUIC_FT_STREAM_8]             = { .func = quic_parse_stream_frame,               .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAM_9]             = { .func = quic_parse_stream_frame,               .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAM_A]             = { .func = quic_parse_stream_frame,               .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAM_B]             = { .func = quic_parse_stream_frame,               .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAM_C]             = { .func = quic_parse_stream_frame,               .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAM_D]             = { .func = quic_parse_stream_frame,               .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAM_E]             = { .func = quic_parse_stream_frame,               .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAM_F]             = { .func = quic_parse_stream_frame,               .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_MAX_DATA]             = { .func = quic_parse_max_data_frame,             .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_MAX_STREAM_DATA]      = { .func = quic_parse_max_stream_data_frame,      .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_MAX_STREAMS_BIDI]     = { .func = quic_parse_max_streams_bidi_frame,     .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_MAX_STREAMS_UNI]      = { .func = quic_parse_max_streams_uni_frame,      .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_DATA_BLOCKED]         = { .func = quic_parse_data_blocked_frame,         .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAM_DATA_BLOCKED]  = { .func = quic_parse_stream_data_blocked_frame,  .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAMS_BLOCKED_BIDI] = { .func = quic_parse_streams_blocked_bidi_frame, .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_STREAMS_BLOCKED_UNI]  = { .func = quic_parse_streams_blocked_uni_frame,  .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_NEW_CONNECTION_ID]    = { .func = quic_parse_new_connection_id_frame,    .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_RETIRE_CONNECTION_ID] = { .func = quic_parse_retire_connection_id_frame, .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_PATH_CHALLENGE]       = { .func = quic_parse_path_challenge_frame,       .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_PATH_RESPONSE]        = { .func = quic_parse_path_response_frame,        .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_CONNECTION_CLOSE]     = { .func = quic_parse_connection_close_frame,     .flags = 0,                               .mask = QUIC_FT_PKT_TYPE_IH01_BITMASK, },
	[QUIC_FT_CONNECTION_CLOSE_APP] = { .func = quic_parse_connection_close_app_frame, .flags = 0,                               .mask = QUIC_FT_PKT_TYPE___01_BITMASK, },
	[QUIC_FT_HANDSHAKE_DONE]       = { .func = quic_parse_handshake_done_frame,       .flags = QUIC_FL_RX_PACKET_ACK_ELICITING, .mask = QUIC_FT_PKT_TYPE____1_BITMASK, },
};

/* Decode a QUIC frame at <pos> buffer position into <frm> frame.
 * Returns 1 if succeeded (enough data at <pos> buffer position to parse the frame), 0 if not.
 */
int qc_parse_frm(struct quic_frame *frm, struct quic_rx_packet *pkt,
                 const unsigned char **pos, const unsigned char *end,
                 struct quic_conn *qc)
{
	int ret = 0;
	const struct quic_frame_parser *parser;

	TRACE_ENTER(QUIC_EV_CONN_PRSFRM, qc);
	if (end <= *pos) {
		TRACE_DEVEL("wrong frame", QUIC_EV_CONN_PRSFRM, qc);
		goto leave;
	}

	frm->type = *(*pos)++;
	if (frm->type >= QUIC_FT_MAX) {
		/* RFC 9000 12.4. Frames and Frame Types
		 *
		 * An endpoint MUST treat the receipt of a frame of unknown type as a
		 * connection error of type FRAME_ENCODING_ERROR.
		 */
		TRACE_DEVEL("wrong frame type", QUIC_EV_CONN_PRSFRM, qc, frm);
		quic_set_connection_close(qc, quic_err_transport(QC_ERR_FRAME_ENCODING_ERROR));
		goto leave;
	}

	parser = &quic_frame_parsers[frm->type];
	if (!(parser->mask & (1U << pkt->type))) {
		TRACE_DEVEL("unauthorized frame", QUIC_EV_CONN_PRSFRM, qc, frm);
		goto leave;
	}

	if (!parser->func(frm, qc, pos, end)) {
		TRACE_DEVEL("parsing error", QUIC_EV_CONN_PRSFRM, qc, frm);
		goto leave;
	}

	TRACE_PROTO("RX frm", QUIC_EV_CONN_PSTRM, qc, frm);

	pkt->flags |= parser->flags;

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PRSFRM, qc);
	return ret;
}

/* Encode <frm> QUIC frame at <pos> buffer position.
 * Returns 1 if succeeded (enough room at <pos> buffer position to encode the frame), 0 if not.
 * The buffer is updated to point to one byte past the end of the built frame
 * only if succeeded.
 */
int qc_build_frm(unsigned char **pos, const unsigned char *end,
                 struct quic_frame *frm, struct quic_tx_packet *pkt,
                 struct quic_conn *qc)
{
	int ret = 0;
	const struct quic_frame_builder *builder;
	unsigned char *p = *pos;

	TRACE_ENTER(QUIC_EV_CONN_BFRM, qc);
	builder = &quic_frame_builders[frm->type];
	if (!(builder->mask & (1U << pkt->type))) {
		/* XXX This it a bug to send an unauthorized frame with such a packet type XXX */
		TRACE_ERROR("unauthorized frame", QUIC_EV_CONN_BFRM, qc, frm);
		BUG_ON(!(builder->mask & (1U << pkt->type)));
	}

	if (end <= p) {
		TRACE_DEVEL("not enough room", QUIC_EV_CONN_BFRM, qc, frm);
		goto leave;
	}

	TRACE_PROTO("TX frm", QUIC_EV_CONN_BFRM, qc, frm);
	*p++ = frm->type;
	if (!quic_frame_builders[frm->type].func(&p, end, frm, qc)) {
		TRACE_ERROR("frame building error", QUIC_EV_CONN_BFRM, qc, frm);
		goto leave;
	}

	pkt->flags |= builder->flags;
	*pos = p;

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_BFRM, qc);
	return ret;
}

/* Detach all duplicated frames from <frm> reflist. */
void qc_frm_unref(struct quic_frame *frm, struct quic_conn *qc)
{
	struct quic_frame *f, *tmp;

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc, frm);

	list_for_each_entry_safe(f, tmp, &frm->reflist, ref) {
		f->origin = NULL;
		LIST_DEL_INIT(&f->ref);
		if (f->pkt) {
			TRACE_DEVEL("remove frame reference",
			            QUIC_EV_CONN_PRSAFRM, qc, f, &f->pkt->pn_node.key);
		}
		else {
			TRACE_DEVEL("remove frame reference for unsent frame",
			            QUIC_EV_CONN_PRSAFRM, qc, f);
		}
	}

	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
}

/* Free a <frm> quic_frame. Remove it from parent element if still attached. */
void qc_frm_free(struct quic_conn *qc, struct quic_frame **frm)
{

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc, *frm);
	/* Caller must ensure that no other frame points to <frm>. Use
	 * qc_frm_unref() to handle this properly.
	 */
	BUG_ON(!LIST_ISEMPTY(&((*frm)->reflist)));
	BUG_ON(LIST_INLIST(&((*frm)->ref)));

	/* TODO simplify frame deallocation. In some code paths, we must
	 * manually call this LIST_DEL_INIT before using
	 * quic_tx_packet_refdec() and freeing the frame.
	 */
	LIST_DEL_INIT(&((*frm)->list));

	pool_free(pool_head_quic_frame, *frm);
	*frm = NULL;
	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
}

/* Release <frm> frame and mark its copies as acknowledged */
void qc_release_frm(struct quic_conn *qc, struct quic_frame *frm)
{
	uint64_t pn;
	struct quic_frame *origin, *f, *tmp;

	/* <frm> will be detached from its Tx packet via origin->reflist loop
	 * implemented below. It is thus expected that its pkt field is not
	 * NULL or else it may free the frame too soon.
	 */
	BUG_ON(!frm->pkt);

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc, frm);

	/* Identify this frame: a frame copy or one of its copies */
	origin = frm->origin ? frm->origin : frm;
	/* Ensure the source of the copies is flagged as acked, <frm> being
	 * possibly a copy of <origin>
	 */
	origin->flags |= QUIC_FL_TX_FRAME_ACKED;
	/* Mark all the copy of <origin> as acknowledged. We must
	 * not release the packets (releasing the frames) at this time as
	 * they are possibly also to be acknowledged alongside the
	 * the current one.
	 */
	list_for_each_entry_safe(f, tmp, &origin->reflist, ref) {
		if (f->pkt) {
			f->flags |= QUIC_FL_TX_FRAME_ACKED;
			f->origin = NULL;
			LIST_DEL_INIT(&f->ref);
			pn = f->pkt->pn_node.key;
			TRACE_DEVEL("mark frame as acked from packet",
			            QUIC_EV_CONN_PRSAFRM, qc, f, &pn);
		}
		else {
			TRACE_DEVEL("freeing unsent frame",
			            QUIC_EV_CONN_PRSAFRM, qc, f);
			LIST_DEL_INIT(&f->ref);
			qc_frm_free(qc, &f);
		}
	}
	LIST_DEL_INIT(&frm->list);
	pn = frm->pkt->pn_node.key;
	quic_tx_packet_refdec(frm->pkt);
	TRACE_DEVEL("freeing frame from packet",
	            QUIC_EV_CONN_PRSAFRM, qc, frm, &pn);
	qc_frm_free(qc, &frm);

	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
}

