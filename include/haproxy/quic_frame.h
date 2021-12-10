/*
 * include/haproxy/quic_frame.h
 * This file contains prototypes for QUIC frames.
 *
 * Copyright 2020 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
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

#include <haproxy/quic_enc.h>
#include <haproxy/quic_frame-t.h>
#include <haproxy/xprt_quic-t.h>

const char *quic_frame_type_string(enum quic_frame_type ft);

int qc_build_frm(unsigned char **buf, const unsigned char *end,
                 struct quic_frame *frm, struct quic_tx_packet *pkt,
                 struct quic_conn *conn);

int qc_parse_frm(struct quic_frame *frm, struct quic_rx_packet *pkt,
                 const unsigned char **buf, const unsigned char *end,
                 struct quic_conn *conn);

/* Return the length of <frm> frame if succeeded, -1 if not (unknown frames
 * or which must not be transmitted again after having been lost (PING, PADDING).
 */
static inline size_t qc_frm_len(struct quic_frame *frm)
{
	size_t len = 0;

	switch (frm->type) {
	case QUIC_FT_RESET_STREAM: {
		struct quic_reset_stream *f = &frm->reset_stream;
		len += 1 + quic_int_getsize(f->id) +
			quic_int_getsize(f->app_error_code) + quic_int_getsize(f->final_size);
		break;
	}
	case QUIC_FT_STOP_SENDING: {
		struct quic_stop_sending *f = &frm->stop_sending;
		len += 1 + quic_int_getsize(f->id) + quic_int_getsize(f->app_error_code);
		break;
	}
	case QUIC_FT_CRYPTO: {
		struct quic_crypto *f = &frm->crypto;
		len += 1 + quic_int_getsize(f->offset) + quic_int_getsize(f->len) + f->len;
		break;
	}
	case QUIC_FT_NEW_TOKEN: {
		struct quic_new_token *f = &frm->new_token;
		len += 1 + quic_int_getsize(f->len) + f->len;
		break;
	}
	case QUIC_FT_STREAM_8 ... QUIC_FT_STREAM_F: {
		struct quic_stream *f = &frm->stream;
		len += 1 + quic_int_getsize(f->id) +
			((frm->type & QUIC_STREAM_FRAME_TYPE_OFF_BIT) ? quic_int_getsize(f->offset.key) : 0) +
			((frm->type & QUIC_STREAM_FRAME_TYPE_LEN_BIT) ? quic_int_getsize(f->len) : 0) + f->len;
		break;
	}
	case QUIC_FT_MAX_DATA: {
		struct quic_max_data *f = &frm->max_data;
		len += 1 + quic_int_getsize(f->max_data);
		break;
	}
	case QUIC_FT_MAX_STREAM_DATA: {
		struct quic_max_stream_data *f = &frm->max_stream_data;
		len += 1 + quic_int_getsize(f->id) + quic_int_getsize(f->max_stream_data);
		break;
	}
	case QUIC_FT_MAX_STREAMS_BIDI: {
		struct quic_max_streams *f = &frm->max_streams_bidi;
		len += 1 + quic_int_getsize(f->max_streams);
		break;
	}
	case QUIC_FT_MAX_STREAMS_UNI: {
		struct quic_max_streams *f = &frm->max_streams_uni;
		len += 1 + quic_int_getsize(f->max_streams);
		break;
	}
	case QUIC_FT_DATA_BLOCKED: {
		struct quic_data_blocked *f = &frm->data_blocked;
		len += 1 + quic_int_getsize(f->limit);
		break;
	}
	case QUIC_FT_STREAM_DATA_BLOCKED: {
		struct quic_stream_data_blocked *f = &frm->stream_data_blocked;
		len += 1 + quic_int_getsize(f->id) + quic_int_getsize(f->limit);
		break;
	}
	case QUIC_FT_STREAMS_BLOCKED_BIDI: {
		struct quic_streams_blocked *f = &frm->streams_blocked_bidi;
		len += 1 + quic_int_getsize(f->limit);
		break;
	}
	case QUIC_FT_STREAMS_BLOCKED_UNI: {
		struct quic_streams_blocked *f = &frm->streams_blocked_uni;
		len += 1 + quic_int_getsize(f->limit);
		break;
	}
	case QUIC_FT_NEW_CONNECTION_ID: {
		struct quic_new_connection_id *f = &frm->new_connection_id;
		len += 1 + quic_int_getsize(f->seq_num) + quic_int_getsize(f->retire_prior_to) +
			quic_int_getsize(f->cid.len) + f->cid.len + QUIC_STATELESS_RESET_TOKEN_LEN;
		break;
	}
	case QUIC_FT_RETIRE_CONNECTION_ID: {
		struct quic_retire_connection_id *f = &frm->retire_connection_id;
		len += 1 + quic_int_getsize(f->seq_num);
		break;
	}
	case QUIC_FT_PATH_CHALLENGE: {
		struct quic_path_challenge *f = &frm->path_challenge;
		len += 1 + sizeof f->data;
		break;
	}
	case QUIC_FT_PATH_RESPONSE: {
		struct quic_path_challenge_response *f = &frm->path_challenge_response;
		len += 1 + sizeof f->data;
		break;
	}
	case QUIC_FT_CONNECTION_CLOSE: {
		struct quic_connection_close *f = &frm->connection_close;
		len += 1 + quic_int_getsize(f->error_code) + quic_int_getsize(f->frame_type) +
			quic_int_getsize(f->reason_phrase_len) + f->reason_phrase_len;
		break;
	}
	case QUIC_FT_CONNECTION_CLOSE_APP: {
		struct quic_connection_close *f = &frm->connection_close;
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

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_FRAME_H */
