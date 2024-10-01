/*
 * include/haproxy/quic_frame.h
 * This file contains prototypes for QUIC frames.
 *
 * Copyright 2020 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
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

#ifndef _HAPROXY_QUIC_FRAME_H
#define _HAPROXY_QUIC_FRAME_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <import/eb64tree.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_enc.h>
#include <haproxy/quic_frame-t.h>
#include <haproxy/quic_rx-t.h>

const char *quic_frame_type_string(enum quic_frame_type ft);

int qc_build_frm(unsigned char **pos, const unsigned char *end,
                 struct quic_frame *frm, struct quic_tx_packet *pkt,
                 struct quic_conn *conn);

int qc_parse_frm(struct quic_frame *frm, struct quic_rx_packet *pkt,
                 const unsigned char **pos, const unsigned char *end,
                 struct quic_conn *conn);

void qc_release_frm(struct quic_conn *qc, struct quic_frame *frm);

/* Return the length of <frm> frame if succeeded, -1 if not (unknown frames
 * or which must not be transmitted again after having been lost (PING, PADDING).
 */
static inline size_t qc_frm_len(struct quic_frame *frm)
{
	size_t len = 0;

	switch (frm->type) {
	case QUIC_FT_ACK: {
		struct qf_tx_ack *tx_ack = &frm->tx_ack;
		struct eb64_node *ar, *prev_ar;
		struct quic_arng_node *ar_node, *prev_ar_node;

		ar = eb64_last(&tx_ack->arngs->root);
		ar_node = eb64_entry(ar, struct quic_arng_node, first);
		len += 1 + quic_int_getsize(ar_node->last);
		len += quic_int_getsize(tx_ack->ack_delay);
		len += quic_int_getsize(tx_ack->arngs->sz - 1);
		len += quic_int_getsize(ar_node->last - ar_node->first.key);

		while ((prev_ar = eb64_prev(ar))) {
			prev_ar_node = eb64_entry(prev_ar, struct quic_arng_node, first);
			len += quic_int_getsize(ar_node->first.key - prev_ar_node->last - 2);
			len += quic_int_getsize(prev_ar_node->last - prev_ar_node->first.key);
			ar = prev_ar;
			ar_node = eb64_entry(ar, struct quic_arng_node, first);
		}
		break;
	}
	case QUIC_FT_RESET_STREAM: {
		struct qf_reset_stream *f = &frm->reset_stream;
		len += 1 + quic_int_getsize(f->id) +
			quic_int_getsize(f->app_error_code) + quic_int_getsize(f->final_size);
		break;
	}
	case QUIC_FT_STOP_SENDING: {
		struct qf_stop_sending *f = &frm->stop_sending;
		len += 1 + quic_int_getsize(f->id) + quic_int_getsize(f->app_error_code);
		break;
	}
	case QUIC_FT_CRYPTO: {
		struct qf_crypto *f = &frm->crypto;
		len += 1 + quic_int_getsize(f->offset) + quic_int_getsize(f->len) + f->len;
		break;
	}
	case QUIC_FT_NEW_TOKEN: {
		struct qf_new_token *f = &frm->new_token;
		len += 1 + quic_int_getsize(f->len) + f->len;
		break;
	}
	case QUIC_FT_STREAM_8 ... QUIC_FT_STREAM_F: {
		struct qf_stream *f = &frm->stream;
		len += 1 + quic_int_getsize(f->id) +
			((frm->type & QUIC_STREAM_FRAME_TYPE_OFF_BIT) ? quic_int_getsize(f->offset) : 0) +
			((frm->type & QUIC_STREAM_FRAME_TYPE_LEN_BIT) ? quic_int_getsize(f->len) : 0) + f->len;
		break;
	}
	case QUIC_FT_MAX_DATA: {
		struct qf_max_data *f = &frm->max_data;
		len += 1 + quic_int_getsize(f->max_data);
		break;
	}
	case QUIC_FT_MAX_STREAM_DATA: {
		struct qf_max_stream_data *f = &frm->max_stream_data;
		len += 1 + quic_int_getsize(f->id) + quic_int_getsize(f->max_stream_data);
		break;
	}
	case QUIC_FT_MAX_STREAMS_BIDI: {
		struct qf_max_streams *f = &frm->max_streams_bidi;
		len += 1 + quic_int_getsize(f->max_streams);
		break;
	}
	case QUIC_FT_MAX_STREAMS_UNI: {
		struct qf_max_streams *f = &frm->max_streams_uni;
		len += 1 + quic_int_getsize(f->max_streams);
		break;
	}
	case QUIC_FT_DATA_BLOCKED: {
		struct qf_data_blocked *f = &frm->data_blocked;
		len += 1 + quic_int_getsize(f->limit);
		break;
	}
	case QUIC_FT_STREAM_DATA_BLOCKED: {
		struct qf_stream_data_blocked *f = &frm->stream_data_blocked;
		len += 1 + quic_int_getsize(f->id) + quic_int_getsize(f->limit);
		break;
	}
	case QUIC_FT_STREAMS_BLOCKED_BIDI: {
		struct qf_streams_blocked *f = &frm->streams_blocked_bidi;
		len += 1 + quic_int_getsize(f->limit);
		break;
	}
	case QUIC_FT_STREAMS_BLOCKED_UNI: {
		struct qf_streams_blocked *f = &frm->streams_blocked_uni;
		len += 1 + quic_int_getsize(f->limit);
		break;
	}
	case QUIC_FT_NEW_CONNECTION_ID: {
		struct qf_new_connection_id *f = &frm->new_connection_id;
		len += 1 + quic_int_getsize(f->seq_num) + quic_int_getsize(f->retire_prior_to) +
			quic_int_getsize(f->cid.len) + f->cid.len + QUIC_STATELESS_RESET_TOKEN_LEN;
		break;
	}
	case QUIC_FT_RETIRE_CONNECTION_ID: {
		struct qf_retire_connection_id *f = &frm->retire_connection_id;
		len += 1 + quic_int_getsize(f->seq_num);
		break;
	}
	case QUIC_FT_PATH_CHALLENGE: {
		struct qf_path_challenge *f = &frm->path_challenge;
		len += 1 + sizeof f->data;
		break;
	}
	case QUIC_FT_PATH_RESPONSE: {
		struct qf_path_challenge_response *f = &frm->path_challenge_response;
		len += 1 + sizeof f->data;
		break;
	}
	case QUIC_FT_CONNECTION_CLOSE: {
		struct qf_connection_close *f = &frm->connection_close;
		len += 1 + quic_int_getsize(f->error_code) + quic_int_getsize(f->frame_type) +
			quic_int_getsize(f->reason_phrase_len) + f->reason_phrase_len;
		break;
	}
	case QUIC_FT_CONNECTION_CLOSE_APP: {
		struct qf_connection_close *f = &frm->connection_close;
		len += 1 + quic_int_getsize(f->error_code) +
			quic_int_getsize(f->reason_phrase_len) + f->reason_phrase_len;
		break;
	}
	case QUIC_FT_HANDSHAKE_DONE: {
		len += 1;
		break;
	}
	default:
		return -1;
	}

	return len;
}

static inline struct quic_err quic_err_transport(uint64_t code)
{
	return (struct quic_err){ .code = code, .app = 0 };
}

static inline struct quic_err quic_err_tls(uint64_t tls_alert)
{
	const uint64_t code = QC_ERR_CRYPTO_ERROR|tls_alert;
	return (struct quic_err){ .code = code, .app = 0 };
}

static inline struct quic_err quic_err_app(uint64_t code)
{
	return (struct quic_err){ .code = code, .app = 1 };
}

/* Allocate a quic_frame with type <type>. Frame must be freed with
 * qc_frm_free().
 *
 * Returns the allocated frame or NULL on failure.
 */
static inline struct quic_frame *qc_frm_alloc(int type)
{
	struct quic_frame *frm = NULL;

	frm = pool_alloc(pool_head_quic_frame);
	if (!frm)
		return NULL;

	frm->type = type;

	LIST_INIT(&frm->list);
	LIST_INIT(&frm->reflist);
	LIST_INIT(&frm->ref);
	frm->pkt = NULL;
	frm->origin = NULL;
	frm->flags = 0;
	frm->loss_count = 0;

	return frm;
}

/* Allocate a quic_frame by duplicating <origin> frame. This will create a new
 * frame of the same type with the same content. Internal fields such as packet
 * owner and flags are however reset for the newly allocated frame except
 * for the loss counter. Frame must be freed with qc_frm_free().
 *
 * Returns the allocated frame or NULL on failure.
 */
static inline struct quic_frame *qc_frm_dup(struct quic_frame *origin)
{
	struct quic_frame *frm = NULL;

	frm = pool_alloc(pool_head_quic_frame);
	if (!frm)
		return NULL;

	*frm = *origin;

	/* Reinit all internal members except loss_count. */
	LIST_INIT(&frm->list);
	LIST_INIT(&frm->reflist);
	frm->pkt = NULL;
	frm->flags = 0;

	/* Attach <frm> to <origin>. */
	LIST_APPEND(&origin->reflist, &frm->ref);
	frm->origin = origin;

	return frm;
}

void qc_frm_free(struct quic_conn *qc, struct quic_frame **frm);
void qc_frm_unref(struct quic_frame *frm, struct quic_conn *qc);

/* Move forward <strm> STREAM frame by <data> bytes. */
static inline void qc_stream_frm_mv_fwd(struct quic_frame *frm, uint64_t data)
{
	struct qf_stream *strm_frm = &frm->stream;
	struct buffer cf_buf;

	/* Set offset bit if not already there. */
	strm_frm->offset += data;
	frm->type |= QUIC_STREAM_FRAME_TYPE_OFF_BIT;

	strm_frm->len -= data;
	cf_buf = b_make(b_orig(strm_frm->buf),
	                b_size(strm_frm->buf),
	                (char *)strm_frm->data - b_orig(strm_frm->buf), 0);
	strm_frm->data = (unsigned char *)b_peek(&cf_buf, data);
}

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_FRAME_H */
