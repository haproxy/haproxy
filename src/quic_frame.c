/*
 * Copyright 2019 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <import/eb64tree.h>
#include <haproxy/quic_frame.h>
#include <haproxy/trace.h>
#include <haproxy/xprt_quic.h>

#define TRACE_SOURCE    &trace_quic

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
		return "ACK_ENC";
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
		const struct quic_crypto *cf = &frm->crypto;
		chunk_appendf(buf, " cfoff=%llu cflen=%llu",
		              (ull)cf->offset, (ull)cf->len);
		break;
	}
	case QUIC_FT_RESET_STREAM:
	{
		const struct quic_reset_stream *rs = &frm->reset_stream;
		chunk_appendf(buf, " id=%llu app_error_code=%llu final_size=%llu",
		              (ull)rs->id, (ull)rs->app_error_code, (ull)rs->final_size);
		break;
	}
	case QUIC_FT_STOP_SENDING:
	{
		const struct quic_stop_sending *s = &frm->stop_sending;
		chunk_appendf(&trace_buf, " id=%llu app_error_code=%llu",
		              (ull)s->id, (ull)s->app_error_code);
		break;
	}
	case QUIC_FT_STREAM_8 ... QUIC_FT_STREAM_F:
	{
		const struct quic_stream *s = &frm->stream;
		chunk_appendf(&trace_buf, " uni=%d fin=%d id=%llu off=%llu len=%llu",
		              !!(s->id & QUIC_STREAM_FRAME_ID_DIR_BIT),
		              !!(frm->type & QUIC_STREAM_FRAME_TYPE_FIN_BIT),
		              (ull)s->id, (ull)s->offset.key, (ull)s->len);
		break;
	}
	case QUIC_FT_MAX_DATA:
	{
		const struct quic_max_data *s = &frm->max_data;
		chunk_appendf(&trace_buf, " max_data=%llu", (ull)s->max_data);
		break;
	}
	case QUIC_FT_MAX_STREAM_DATA:
	{
		const struct quic_max_stream_data *s = &frm->max_stream_data;
		chunk_appendf(&trace_buf, " id=%llu max_stream_data=%llu",
		              (ull)s->id, (ull)s->max_stream_data);
		break;
	}
	case QUIC_FT_MAX_STREAMS_BIDI:
	{
		const struct quic_max_streams *s = &frm->max_streams_bidi;
		chunk_appendf(&trace_buf, " max_streams=%llu", (ull)s->max_streams);
		break;
	}
	case QUIC_FT_MAX_STREAMS_UNI:
	{
		const struct quic_max_streams *s = &frm->max_streams_uni;
		chunk_appendf(&trace_buf, " max_streams=%llu", (ull)s->max_streams);
		break;
	}
	case QUIC_FT_DATA_BLOCKED:
	{
		const struct quic_data_blocked *s = &frm->data_blocked;
		chunk_appendf(&trace_buf, " limit=%llu", (ull)s->limit);
		break;
	}
	case QUIC_FT_STREAM_DATA_BLOCKED:
	{
		const struct quic_stream_data_blocked *s = &frm->stream_data_blocked;
		chunk_appendf(&trace_buf, " id=%llu limit=%llu",
		              (ull)s->id, (ull)s->limit);
		break;
	}
	case QUIC_FT_STREAMS_BLOCKED_BIDI:
	{
		const struct quic_streams_blocked *s = &frm->streams_blocked_bidi;
		chunk_appendf(&trace_buf, " limit=%llu", (ull)s->limit);
		break;
	}
	case QUIC_FT_STREAMS_BLOCKED_UNI:
	{
		const struct quic_streams_blocked *s = &frm->streams_blocked_uni;
		chunk_appendf(&trace_buf, " limit=%llu", (ull)s->limit);
		break;
	}
	case QUIC_FT_RETIRE_CONNECTION_ID:
	{
		const struct quic_retire_connection_id *rci = &frm->retire_connection_id;
		chunk_appendf(&trace_buf, " seq_num=%llu", (ull)rci->seq_num);
		break;
	}
	case QUIC_FT_CONNECTION_CLOSE:
	{
		const struct quic_connection_close *cc = &frm->connection_close;
		size_t plen = QUIC_MIN(cc->reason_phrase_len, sizeof cc->reason_phrase);
		chunk_appendf(&trace_buf,
		              " error_code=%llu frame_type=%llu reason_phrase_len=%llu",
		              (ull)cc->error_code, (ull)cc->frame_type,
		              (ull)cc->reason_phrase_len);
		if (plen)
			chunk_cc_phrase_appendf(&trace_buf, cc->reason_phrase, plen);
		break;
	}
	case QUIC_FT_CONNECTION_CLOSE_APP:
	{
		const struct quic_connection_close_app *cc = &frm->connection_close_app;
		size_t plen = QUIC_MIN(cc->reason_phrase_len, sizeof cc->reason_phrase);
		chunk_appendf(&trace_buf,
		              " error_code=%llu reason_phrase_len=%llu",
		              (ull)cc->error_code, (ull)cc->reason_phrase_len);
		if (plen)
			chunk_cc_phrase_appendf(&trace_buf, cc->reason_phrase, plen);
		break;
	}
	}
}

/* Encode <frm> PADDING frame into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_padding_frame(unsigned char **buf, const unsigned char *end,
                                    struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_padding *padding = &frm->padding;

	if (end - *buf < padding->len - 1)
		return 0;

	memset(*buf, 0, padding->len - 1);
	*buf += padding->len - 1;

	return 1;
}

/* Parse a PADDING frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_padding_frame(struct quic_frame *frm, struct quic_conn *qc,
                                    const unsigned char **buf, const unsigned char *end)
{
	const unsigned char *beg;
	struct quic_padding *padding = &frm->padding;

	beg = *buf;
	padding->len = 1;
	while (*buf < end && !**buf)
		(*buf)++;
	padding->len += *buf - beg;

	return 1;
}

/* Encode a ACK frame into <buf> buffer.
 * Always succeeds.
 */
static int quic_build_ping_frame(unsigned char **buf, const unsigned char *end,
                                 struct quic_frame *frm, struct quic_conn *conn)
{
	/* No field */
	return 1;
}

/* Parse a PADDING frame from <buf> buffer with <end> as end into <frm> frame.
 * Always succeeds.
 */
static int quic_parse_ping_frame(struct quic_frame *frm, struct quic_conn *qc,
                                 const unsigned char **buf, const unsigned char *end)
{
	/* No field */
	return 1;
}

/* Encode a ACK frame.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_ack_frame(unsigned char **buf, const unsigned char *end,
                                struct quic_frame *frm, struct quic_conn *qc)
{
	struct quic_tx_ack *tx_ack = &frm->tx_ack;
	struct eb64_node *ar, *prev_ar;
	struct quic_arng_node *ar_node, *prev_ar_node;

	ar = eb64_last(&tx_ack->arngs->root);
	ar_node = eb64_entry(&ar->node, struct quic_arng_node, first);
	TRACE_PROTO("ack range", QUIC_EV_CONN_PRSAFRM,
	            qc,, &ar_node->last, &ar_node->first.key);
	if (!quic_enc_int(buf, end, ar_node->last) ||
	    !quic_enc_int(buf, end, tx_ack->ack_delay) ||
	    !quic_enc_int(buf, end, tx_ack->arngs->sz - 1) ||
	    !quic_enc_int(buf, end, ar_node->last - ar_node->first.key))
		return 0;

	while ((prev_ar = eb64_prev(ar))) {
		prev_ar_node = eb64_entry(&prev_ar->node, struct quic_arng_node, first);
		TRACE_PROTO("ack range", QUIC_EV_CONN_PRSAFRM, qc,,
		            &prev_ar_node->last, &prev_ar_node->first.key);
		if (!quic_enc_int(buf, end, ar_node->first.key - prev_ar_node->last - 2) ||
		    !quic_enc_int(buf, end, prev_ar_node->last - prev_ar_node->first.key))
			return 0;

		ar = prev_ar;
		ar_node = eb64_entry(&ar->node, struct quic_arng_node, first);
	}

	return 1;
}

/* Parse an ACK frame header from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_ack_frame_header(struct quic_frame *frm, struct quic_conn *qc,
                                       const unsigned char **buf, const unsigned char *end)
{
	int ret;
	struct quic_ack *ack = &frm->ack;

	ret = quic_dec_int(&ack->largest_ack, buf, end);
	if (!ret)
		return 0;

	ret = quic_dec_int(&ack->ack_delay, buf, end);
	if (!ret)
		return 0;

	ret = quic_dec_int(&ack->ack_range_num, buf, end);
	if (!ret)
		return 0;

	ret = quic_dec_int(&ack->first_ack_range, buf, end);
	if (!ret)
		return 0;

	return 1;
}

/* Encode a ACK_ECN frame.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_ack_ecn_frame(unsigned char **buf, const unsigned char *end,
                                    struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_ack *ack = &frm->ack;

	return quic_enc_int(buf, end, ack->largest_ack) &&
		quic_enc_int(buf, end, ack->ack_delay) &&
		quic_enc_int(buf, end, ack->first_ack_range) &&
		quic_enc_int(buf, end, ack->ack_range_num);
}

/* Parse an ACK_ECN frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_ack_ecn_frame(struct quic_frame *frm, struct quic_conn *qc,
                                    const unsigned char **buf, const unsigned char *end)
{
	struct quic_ack *ack = &frm->ack;

	return quic_dec_int(&ack->largest_ack, buf, end) &&
		quic_dec_int(&ack->ack_delay, buf, end) &&
		quic_dec_int(&ack->first_ack_range, buf, end) &&
		quic_dec_int(&ack->ack_range_num, buf, end);
}

/* Encode a RESET_STREAM frame into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_reset_stream_frame(unsigned char **buf, const unsigned char *end,
                                         struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_reset_stream *reset_stream = &frm->reset_stream;

	return quic_enc_int(buf, end, reset_stream->id) &&
		quic_enc_int(buf, end, reset_stream->app_error_code) &&
		quic_enc_int(buf, end, reset_stream->final_size);
}

/* Parse a RESET_STREAM frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_reset_stream_frame(struct quic_frame *frm, struct quic_conn *qc,
                                         const unsigned char **buf, const unsigned char *end)
{
	struct quic_reset_stream *reset_stream = &frm->reset_stream;

	return quic_dec_int(&reset_stream->id, buf, end) &&
		quic_dec_int(&reset_stream->app_error_code, buf, end) &&
		quic_dec_int(&reset_stream->final_size, buf, end);
}

/* Encode a STOP_SENDING frame.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_stop_sending_frame(unsigned char **buf, const unsigned char *end,
                                         struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_stop_sending *stop_sending = &frm->stop_sending;

	return quic_enc_int(buf, end, stop_sending->id) &&
		quic_enc_int(buf, end, stop_sending->app_error_code);
}

/* Parse a STOP_SENDING frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_stop_sending_frame(struct quic_frame *frm, struct quic_conn *qc,
                                         const unsigned char **buf, const unsigned char *end)
{
	struct quic_stop_sending *stop_sending = &frm->stop_sending;

	return quic_dec_int(&stop_sending->id, buf, end) &&
		quic_dec_int(&stop_sending->app_error_code, buf, end);
}

/* Encode a CRYPTO frame into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_crypto_frame(unsigned char **buf, const unsigned char *end,
                                   struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_crypto *crypto = &frm->crypto;
	const struct quic_enc_level *qel = crypto->qel;
	size_t offset, len;

	if (!quic_enc_int(buf, end, crypto->offset) ||
	    !quic_enc_int(buf, end, crypto->len) || end - *buf < crypto->len)
		return 0;

	len = crypto->len;
	offset = crypto->offset;
	while (len) {
		int idx;
		size_t to_copy;
		const unsigned char *data;

		idx = offset >> QUIC_CRYPTO_BUF_SHIFT;
		to_copy = qel->tx.crypto.bufs[idx]->sz - (offset & QUIC_CRYPTO_BUF_MASK);
		if (to_copy > len)
			to_copy = len;
		data = qel->tx.crypto.bufs[idx]->data + (offset & QUIC_CRYPTO_BUF_MASK);
		memcpy(*buf, data, to_copy);
		*buf += to_copy;
		offset += to_copy;
		len -= to_copy;
	}

	return 1;
}

/* Parse a CRYPTO frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_crypto_frame(struct quic_frame *frm, struct quic_conn *qc,
                                   const unsigned char **buf, const unsigned char *end)
{
	struct quic_crypto *crypto = &frm->crypto;

	if (!quic_dec_int(&crypto->offset, buf, end) ||
	    !quic_dec_int(&crypto->len, buf, end) || end - *buf < crypto->len)
		return 0;

	crypto->data = *buf;
	*buf += crypto->len;

	return 1;
}

/* Encode a NEW_TOKEN frame into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_new_token_frame(unsigned char **buf, const unsigned char *end,
                                      struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_new_token *new_token = &frm->new_token;

	if (!quic_enc_int(buf, end, new_token->len) || end - *buf < new_token->len)
		return 0;

	memcpy(*buf, new_token->data, new_token->len);

	return 1;
}

/* Parse a NEW_TOKEN frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_new_token_frame(struct quic_frame *frm, struct quic_conn *qc,
                                      const unsigned char **buf, const unsigned char *end)
{
	struct quic_new_token *new_token = &frm->new_token;

	if (!quic_dec_int(&new_token->len, buf, end) || end - *buf < new_token->len)
		return 0;

	new_token->data = *buf;
	*buf += new_token->len;

	return 1;
}

/* Encode a STREAM frame into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_stream_frame(unsigned char **buf, const unsigned char *end,
                                   struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_stream *stream = &frm->stream;
	size_t offset, block1, block2;
	struct buffer b;

	if (!quic_enc_int(buf, end, stream->id) ||
	    ((frm->type & QUIC_STREAM_FRAME_TYPE_OFF_BIT) && !quic_enc_int(buf, end, stream->offset.key)) ||
	    ((frm->type & QUIC_STREAM_FRAME_TYPE_LEN_BIT) &&
	     (!quic_enc_int(buf, end, stream->len) || end - *buf < stream->len)))
		return 0;

	/* Buffer copy */
	b = *stream->buf;
	offset = (frm->type & QUIC_STREAM_FRAME_TYPE_OFF_BIT) ?
		stream->offset.key & (b_size(stream->buf) - 1): 0;
	block1 = b_wrap(&b) - (b_orig(&b) + offset);
	if (block1 > stream->len)
		block1 = stream->len;
	block2 = stream->len - block1;
	memcpy(*buf, b_orig(&b) + offset, block1);
	*buf += block1;
	if (block2) {
		memcpy(*buf, b_orig(&b), block2);
		*buf += block2;
	}

	return 1;
}

/* Parse a STREAM frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_stream_frame(struct quic_frame *frm, struct quic_conn *qc,
                                   const unsigned char **buf, const unsigned char *end)
{
	struct quic_stream *stream = &frm->stream;

	if (!quic_dec_int(&stream->id, buf, end))
		return 0;

	/* Offset parsing */
	if (!(frm->type & QUIC_STREAM_FRAME_TYPE_OFF_BIT)) {
		stream->offset.key = 0;
	}
	else if (!quic_dec_int((uint64_t *)&stream->offset.key, buf, end))
		return 0;

	/* Length parsing */
	if (!(frm->type & QUIC_STREAM_FRAME_TYPE_LEN_BIT)) {
		stream->len = end - *buf;
	}
	else if (!quic_dec_int(&stream->len, buf, end) || end - *buf < stream->len)
		return 0;

	stream->fin = (frm->type & QUIC_STREAM_FRAME_TYPE_FIN_BIT);

	stream->data = *buf;
	*buf += stream->len;

	return 1;
}

/* Encode a MAX_DATA frame into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_max_data_frame(unsigned char **buf, const unsigned char *end,
                                     struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_max_data *max_data = &frm->max_data;

	return quic_enc_int(buf, end, max_data->max_data);
}

/* Parse a MAX_DATA frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_max_data_frame(struct quic_frame *frm, struct quic_conn *qc,
                                     const unsigned char **buf, const unsigned char *end)
{
	struct quic_max_data *max_data = &frm->max_data;

	return quic_dec_int(&max_data->max_data, buf, end);
}

/* Encode a MAX_STREAM_DATA frame into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_max_stream_data_frame(unsigned char **buf, const unsigned char *end,
                                            struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_max_stream_data *max_stream_data = &frm->max_stream_data;

	return quic_enc_int(buf, end, max_stream_data->id) &&
		quic_enc_int(buf, end, max_stream_data->max_stream_data);
}

/* Parse a MAX_STREAM_DATA frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_max_stream_data_frame(struct quic_frame *frm, struct quic_conn *qc,
                                            const unsigned char **buf, const unsigned char *end)
{
	struct quic_max_stream_data *max_stream_data = &frm->max_stream_data;

	return quic_dec_int(&max_stream_data->id, buf, end) &&
		quic_dec_int(&max_stream_data->max_stream_data, buf, end);
}

/* Encode a MAX_STREAMS frame for bidirectional streams into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_max_streams_bidi_frame(unsigned char **buf, const unsigned char *end,
                                             struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_max_streams *max_streams_bidi = &frm->max_streams_bidi;

	return quic_enc_int(buf, end, max_streams_bidi->max_streams);
}

/* Parse a MAX_STREAMS frame for bidirectional streams from <buf> buffer with <end>
 * as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_max_streams_bidi_frame(struct quic_frame *frm, struct quic_conn *qc,
                                             const unsigned char **buf, const unsigned char *end)
{
	struct quic_max_streams *max_streams_bidi = &frm->max_streams_bidi;

	return quic_dec_int(&max_streams_bidi->max_streams, buf, end);
}

/* Encode a MAX_STREAMS frame for unidirectional streams into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_max_streams_uni_frame(unsigned char **buf, const unsigned char *end,
                                            struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_max_streams *max_streams_uni = &frm->max_streams_uni;

	return quic_enc_int(buf, end, max_streams_uni->max_streams);
}

/* Parse a MAX_STREAMS frame for undirectional streams from <buf> buffer with <end>
 * as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_max_streams_uni_frame(struct quic_frame *frm, struct quic_conn *qc,
                                            const unsigned char **buf, const unsigned char *end)
{
	struct quic_max_streams *max_streams_uni = &frm->max_streams_uni;

	return quic_dec_int(&max_streams_uni->max_streams, buf, end);
}

/* Encode a DATA_BLOCKED frame into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_data_blocked_frame(unsigned char **buf, const unsigned char *end,
                                         struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_data_blocked *data_blocked = &frm->data_blocked;

	return quic_enc_int(buf, end, data_blocked->limit);
}

/* Parse a DATA_BLOCKED frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_data_blocked_frame(struct quic_frame *frm, struct quic_conn *qc,
                                         const unsigned char **buf, const unsigned char *end)
{
	struct quic_data_blocked *data_blocked = &frm->data_blocked;

	return quic_dec_int(&data_blocked->limit, buf, end);
}

/* Encode a STREAM_DATA_BLOCKED into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_stream_data_blocked_frame(unsigned char **buf, const unsigned char *end,
                                                struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_stream_data_blocked *stream_data_blocked = &frm->stream_data_blocked;

	return quic_enc_int(buf, end, stream_data_blocked->id) &&
		quic_enc_int(buf, end, stream_data_blocked->limit);
}

/* Parse a STREAM_DATA_BLOCKED frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_stream_data_blocked_frame(struct quic_frame *frm, struct quic_conn *qc,
                                                const unsigned char **buf, const unsigned char *end)
{
	struct quic_stream_data_blocked *stream_data_blocked = &frm->stream_data_blocked;

	return quic_dec_int(&stream_data_blocked->id, buf, end) &&
		quic_dec_int(&stream_data_blocked->limit, buf, end);
}

/* Encode a STREAMS_BLOCKED frame for bidirectional streams into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_streams_blocked_bidi_frame(unsigned char **buf, const unsigned char *end,
                                                 struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_streams_blocked *streams_blocked_bidi = &frm->streams_blocked_bidi;

	return quic_enc_int(buf, end, streams_blocked_bidi->limit);
}

/* Parse a STREAMS_BLOCKED frame for bidirectional streams from <buf> buffer with <end>
 * as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_streams_blocked_bidi_frame(struct quic_frame *frm, struct quic_conn *qc,
                                                 const unsigned char **buf, const unsigned char *end)
{
	struct quic_streams_blocked *streams_blocked_bidi = &frm->streams_blocked_bidi;

	return quic_dec_int(&streams_blocked_bidi->limit, buf, end);
}

/* Encode a STREAMS_BLOCKED frame for unidirectional streams into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_streams_blocked_uni_frame(unsigned char **buf, const unsigned char *end,
                                                struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_streams_blocked *streams_blocked_uni = &frm->streams_blocked_uni;

	return quic_enc_int(buf, end, streams_blocked_uni->limit);
}

/* Parse a STREAMS_BLOCKED frame for unidirectional streams from <buf> buffer with <end>
 * as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_streams_blocked_uni_frame(struct quic_frame *frm, struct quic_conn *qc,
                                                const unsigned char **buf, const unsigned char *end)
{
	struct quic_streams_blocked *streams_blocked_uni = &frm->streams_blocked_uni;

	return quic_dec_int(&streams_blocked_uni->limit, buf, end);
}

/* Encode a NEW_CONNECTION_ID frame into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_new_connection_id_frame(unsigned char **buf, const unsigned char *end,
                                              struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_new_connection_id *new_cid = &frm->new_connection_id;

	if (!quic_enc_int(buf, end, new_cid->seq_num) ||
	    !quic_enc_int(buf, end, new_cid->retire_prior_to) ||
	    end - *buf < sizeof new_cid->cid.len + new_cid->cid.len + QUIC_STATELESS_RESET_TOKEN_LEN)
		return 0;

	*(*buf)++ = new_cid->cid.len;

	if (new_cid->cid.len) {
		memcpy(*buf, new_cid->cid.data, new_cid->cid.len);
		*buf += new_cid->cid.len;
	}
	memcpy(*buf, new_cid->stateless_reset_token, QUIC_STATELESS_RESET_TOKEN_LEN);
	*buf += QUIC_STATELESS_RESET_TOKEN_LEN;

	return 1;
}

/* Parse a NEW_CONNECTION_ID frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_new_connection_id_frame(struct quic_frame *frm, struct quic_conn *qc,
                                              const unsigned char **buf, const unsigned char *end)
{
	struct quic_new_connection_id *new_cid = &frm->new_connection_id;

	if (!quic_dec_int(&new_cid->seq_num, buf, end) ||
	    !quic_dec_int(&new_cid->retire_prior_to, buf, end) || end <= *buf)
		return 0;

	new_cid->cid.len = *(*buf)++;
	if (end - *buf < new_cid->cid.len + QUIC_STATELESS_RESET_TOKEN_LEN)
		return 0;

	if (new_cid->cid.len) {
		new_cid->cid.data = *buf;
		*buf += new_cid->cid.len;
	}
	new_cid->stateless_reset_token = *buf;
	*buf += QUIC_STATELESS_RESET_TOKEN_LEN;

	return 1;
}

/* Encode a RETIRE_CONNECTION_ID frame into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_retire_connection_id_frame(unsigned char **buf, const unsigned char *end,
                                                 struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_retire_connection_id *retire_connection_id = &frm->retire_connection_id;

	return quic_enc_int(buf, end, retire_connection_id->seq_num);
}

/* Parse a RETIRE_CONNECTION_ID frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_retire_connection_id_frame(struct quic_frame *frm, struct quic_conn *qc,
                                                 const unsigned char **buf, const unsigned char *end)
{
	struct quic_retire_connection_id *retire_connection_id = &frm->retire_connection_id;

	return quic_dec_int(&retire_connection_id->seq_num, buf, end);
}

/* Encode a PATH_CHALLENGE frame into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_path_challenge_frame(unsigned char **buf, const unsigned char *end,
                                           struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_path_challenge *path_challenge = &frm->path_challenge;

	if (end - *buf < sizeof path_challenge->data)
		return 0;

	memcpy(*buf, path_challenge->data, sizeof path_challenge->data);
	*buf += sizeof path_challenge->data;

	return 1;
}

/* Parse a PATH_CHALLENGE frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_path_challenge_frame(struct quic_frame *frm, struct quic_conn *qc,
                                           const unsigned char **buf, const unsigned char *end)
{
	struct quic_path_challenge *path_challenge = &frm->path_challenge;

	if (end - *buf < sizeof path_challenge->data)
		return 0;

	memcpy(path_challenge->data, *buf, sizeof path_challenge->data);
	*buf += sizeof path_challenge->data;

	return 1;
}


/* Encode a PATH_RESPONSE frame into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_path_response_frame(unsigned char **buf, const unsigned char *end,
                                          struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_path_challenge_response *path_challenge_response = &frm->path_challenge_response;

	if (end - *buf < sizeof path_challenge_response->data)
		return 0;

	memcpy(*buf, path_challenge_response->data, sizeof path_challenge_response->data);
	*buf += sizeof path_challenge_response->data;

	return 1;
}

/* Parse a PATH_RESPONSE frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_path_response_frame(struct quic_frame *frm, struct quic_conn *qc,
                                          const unsigned char **buf, const unsigned char *end)
{
	struct quic_path_challenge_response *path_challenge_response = &frm->path_challenge_response;

	if (end - *buf < sizeof path_challenge_response->data)
		return 0;

	memcpy(path_challenge_response->data, *buf, sizeof path_challenge_response->data);
	*buf += sizeof path_challenge_response->data;

	return 1;
}

/* Encode a CONNECTION_CLOSE frame at QUIC layer into <buf> buffer.
 * Note there exist two types of CONNECTION_CLOSE frame, one for the application layer
 * and another at QUIC layer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_connection_close_frame(unsigned char **buf, const unsigned char *end,
                                             struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_connection_close *cc = &frm->connection_close;

	if (!quic_enc_int(buf, end, cc->error_code) ||
	    !quic_enc_int(buf, end, cc->frame_type) ||
	    !quic_enc_int(buf, end, cc->reason_phrase_len) ||
	    end - *buf < cc->reason_phrase_len)
		return 0;

	memcpy(*buf, cc->reason_phrase, cc->reason_phrase_len);
	*buf += cc->reason_phrase_len;

	return 1;
}

/* Parse a CONNECTION_CLOSE frame at QUIC layer from <buf> buffer with <end> as end into <frm> frame.
 * Note there exist two types of CONNECTION_CLOSE frame, one for the application layer
 * and another at QUIC layer.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_connection_close_frame(struct quic_frame *frm, struct quic_conn *qc,
                                             const unsigned char **buf, const unsigned char *end)
{
	size_t plen;
	struct quic_connection_close *cc = &frm->connection_close;

	if (!quic_dec_int(&cc->error_code, buf, end) ||
	    !quic_dec_int(&cc->frame_type, buf, end) ||
	    !quic_dec_int(&cc->reason_phrase_len, buf, end) ||
	    end - *buf < cc->reason_phrase_len)
		return 0;

	plen = QUIC_MIN(cc->reason_phrase_len, sizeof cc->reason_phrase);
	memcpy(cc->reason_phrase, *buf, plen);
	*buf += cc->reason_phrase_len;

	return 1;
}

/* Encode a CONNECTION_CLOSE frame at application layer into <buf> buffer.
 * Note there exist two types of CONNECTION_CLOSE frame, one for application layer
 * and another at QUIC layer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int quic_build_connection_close_app_frame(unsigned char **buf, const unsigned char *end,
                                                 struct quic_frame *frm, struct quic_conn *conn)
{
	struct quic_connection_close_app *cc = &frm->connection_close_app;

	if (!quic_enc_int(buf, end, cc->error_code) ||
	    !quic_enc_int(buf, end, cc->reason_phrase_len) ||
	    end - *buf < cc->reason_phrase_len)
		return 0;

	memcpy(*buf, cc->reason_phrase, cc->reason_phrase_len);
	*buf += cc->reason_phrase_len;

	return 1;
}

/* Parse a CONNECTION_CLOSE frame at QUIC layer from <buf> buffer with <end> as end into <frm> frame.
 * Note there exist two types of CONNECTION_CLOSE frame, one for the application layer
 * and another at QUIC layer.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int quic_parse_connection_close_app_frame(struct quic_frame *frm, struct quic_conn *qc,
                                                 const unsigned char **buf, const unsigned char *end)
{
	size_t plen;
	struct quic_connection_close_app *cc = &frm->connection_close_app;

	if (!quic_dec_int(&cc->error_code, buf, end) ||
	    !quic_dec_int(&cc->reason_phrase_len, buf, end) ||
	    end - *buf < cc->reason_phrase_len)
		return 0;

	plen = QUIC_MIN(cc->reason_phrase_len, sizeof cc->reason_phrase);
	memcpy(cc->reason_phrase, *buf, plen);
	*buf += cc->reason_phrase_len;

	return 1;
}

/* Encode a HANDSHAKE_DONE frame into <buf> buffer.
 * Always succeeds.
 */
static int quic_build_handshake_done_frame(unsigned char **buf, const unsigned char *end,
                                           struct quic_frame *frm, struct quic_conn *conn)
{
	/* No field */
	return 1;
}

/* Parse a HANDSHAKE_DONE frame at QUIC layer from <buf> buffer with <end> as end into <frm> frame.
 * Always succeed.
 */
static int quic_parse_handshake_done_frame(struct quic_frame *frm, struct quic_conn *qc,
                                           const unsigned char **buf, const unsigned char *end)
{
	/* No field */
	return 1;
}

struct quic_frame_builder {
	int (*func)(unsigned char **buf, const unsigned char *end,
                 struct quic_frame *frm, struct quic_conn *conn);
	unsigned char flags;
	unsigned char mask;
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
                const unsigned char **buf, const unsigned char *end);
	unsigned char flags;
	unsigned char mask;
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

/* Decode a QUIC frame from <buf> buffer into <frm> frame.
 * Returns 1 if succeeded (enough data to parse the frame), 0 if not.
 */
int qc_parse_frm(struct quic_frame *frm, struct quic_rx_packet *pkt,
                 const unsigned char **buf, const unsigned char *end,
                 struct quic_conn *qc)
{
	const struct quic_frame_parser *parser;

	if (end <= *buf) {
		TRACE_DEVEL("wrong frame", QUIC_EV_CONN_PRSFRM, qc);
		return 0;
	}

	frm->type = *(*buf)++;
	if (frm->type > QUIC_FT_MAX) {
		TRACE_DEVEL("wrong frame type", QUIC_EV_CONN_PRSFRM, qc, frm);
		return 0;
	}

	parser = &quic_frame_parsers[frm->type];
	if (!(parser->mask & (1 << pkt->type))) {
		TRACE_DEVEL("unauthorized frame", QUIC_EV_CONN_PRSFRM, qc, frm);
		return 0;
	}

	TRACE_PROTO("frame", QUIC_EV_CONN_PRSFRM, qc, frm);
	if (!parser->func(frm, qc, buf, end)) {
		TRACE_DEVEL("parsing error", QUIC_EV_CONN_PRSFRM, qc, frm);
		return 0;
	}

	pkt->flags |= parser->flags;

	return 1;
}

/* Encode <frm> QUIC frame into <buf> buffer.
 * Returns 1 if succeeded (enough room in <buf> to encode the frame), 0 if not.
 */
int qc_build_frm(unsigned char **buf, const unsigned char *end,
                 struct quic_frame *frm, struct quic_tx_packet *pkt,
                 struct quic_conn *qc)
{
	const struct quic_frame_builder *builder;

	builder = &quic_frame_builders[frm->type];
	if (!(builder->mask & (1 << pkt->type))) {
		/* XXX This it a bug to send an unauthorized frame with such a packet type XXX */
		TRACE_DEVEL("frame skipped", QUIC_EV_CONN_BFRM, qc, frm);
		BUG_ON(!(builder->mask & (1 << pkt->type)));
	}

	if (end <= *buf) {
		TRACE_DEVEL("not enough room", QUIC_EV_CONN_BFRM, qc, frm);
		return 0;
	}

	TRACE_PROTO("frame", QUIC_EV_CONN_BFRM, qc, frm);
	*(*buf)++ = frm->type;
	if (!quic_frame_builders[frm->type].func(buf, end, frm, qc)) {
		TRACE_DEVEL("frame building error", QUIC_EV_CONN_BFRM, qc, frm);
		return 0;
	}

	pkt->flags |= builder->flags;

	return 1;
}

