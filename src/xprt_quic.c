/*
 * QUIC transport layer over SOCK_DGRAM sockets.
 *
 * Copyright 2020 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netinet/tcp.h>

#include <haproxy/buf-t.h>
#include <haproxy/compat.h>
#include <haproxy/api.h>
#include <haproxy/debug.h>
#include <haproxy/tools.h>
#include <haproxy/ticks.h>
#include <haproxy/time.h>

#include <haproxy/connection.h>
#include <haproxy/fd.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/global.h>
#include <haproxy/log.h>
#include <haproxy/pipe.h>
#include <haproxy/proxy.h>
#include <haproxy/quic_cc.h>
#include <haproxy/quic_frame.h>
#include <haproxy/quic_loss.h>
#include <haproxy/quic_tls.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/stream_interface.h>
#include <haproxy/task.h>
#include <haproxy/trace.h>
#include <haproxy/xprt_quic.h>

struct quic_transport_params quic_dflt_transport_params = {
	.max_packet_size    = QUIC_DFLT_MAX_PACKET_SIZE,
	.ack_delay_exponent = QUIC_DFLT_ACK_DELAY_COMPONENT,
	.max_ack_delay      = QUIC_DFLT_MAX_ACK_DELAY,
};

/* trace source and events */
static void quic_trace(enum trace_level level, uint64_t mask, \
                       const struct trace_source *src,
                       const struct ist where, const struct ist func,
                       const void *a1, const void *a2, const void *a3, const void *a4);

static const struct trace_event quic_trace_events[] = {
	{ .mask = QUIC_EV_CONN_NEW,      .name = "new_conn",         .desc = "new QUIC connection" },
	{ .mask = QUIC_EV_CONN_INIT,     .name = "new_conn_init",    .desc = "new QUIC connection initialization" },
	{ .mask = QUIC_EV_CONN_ISEC,     .name = "init_secs",        .desc = "initial secrets derivation" },
	{ .mask = QUIC_EV_CONN_RSEC,     .name = "read_secs",        .desc = "read secrets derivation" },
	{ .mask = QUIC_EV_CONN_WSEC,     .name = "write_secs",       .desc = "write secrets derivation" },
	{ .mask = QUIC_EV_CONN_LPKT,     .name = "lstnr_packet",     .desc = "new listener received packet" },
	{ .mask = QUIC_EV_CONN_SPKT,     .name = "srv_packet",       .desc = "new server received packet" },
	{ .mask = QUIC_EV_CONN_ENCPKT,   .name = "enc_hdshk_pkt",    .desc = "handhshake packet encryption" },
	{ .mask = QUIC_EV_CONN_HPKT,     .name = "hdshk_pkt",        .desc = "handhshake packet building" },
	{ .mask = QUIC_EV_CONN_PAPKT,    .name = "phdshk_apkt",      .desc = "post handhshake application packet preparation" },
	{ .mask = QUIC_EV_CONN_PAPKTS,   .name = "phdshk_apkts",     .desc = "post handhshake application packets preparation" },
	{ .mask = QUIC_EV_CONN_HDSHK,    .name = "hdshk",            .desc = "SSL handhshake processing" },
	{ .mask = QUIC_EV_CONN_RMHP,     .name = "rm_hp",            .desc = "Remove header protection" },
	{ .mask = QUIC_EV_CONN_PRSHPKT,  .name = "parse_hpkt",       .desc = "parse handshake packet" },
	{ .mask = QUIC_EV_CONN_PRSAPKT,  .name = "parse_apkt",       .desc = "parse application packet" },
	{ .mask = QUIC_EV_CONN_PRSFRM,   .name = "parse_frm",        .desc = "parse frame" },
	{ .mask = QUIC_EV_CONN_PRSAFRM,  .name = "parse_ack_frm",    .desc = "parse ACK frame" },
	{ .mask = QUIC_EV_CONN_BFRM,     .name = "build_frm",        .desc = "build frame" },
	{ .mask = QUIC_EV_CONN_PHPKTS,   .name = "phdshk_pkts",      .desc = "handhshake packets preparation" },
	{ .mask = QUIC_EV_CONN_TRMHP,    .name = "rm_hp_try",        .desc = "header protection removing try" },
	{ .mask = QUIC_EV_CONN_ELRMHP,   .name = "el_rm_hp",         .desc = "handshake enc. level header protection removing" },
	{ .mask = QUIC_EV_CONN_ELRXPKTS, .name = "el_treat_rx_pkts", .desc = "handshake enc. level rx packets treatment" },
	{ .mask = QUIC_EV_CONN_SSLDATA,  .name = "ssl_provide_data", .desc = "CRYPTO data provision to TLS stack" },
	{ .mask = QUIC_EV_CONN_RXCDATA,  .name = "el_treat_rx_cfrms",.desc = "enc. level RX CRYPTO frames processing"},
	{ .mask = QUIC_EV_CONN_ADDDATA,  .name = "add_hdshk_data",   .desc = "TLS stack ->add_handshake_data() call"},
	{ .mask = QUIC_EV_CONN_FFLIGHT,  .name = "flush_flight",     .desc = "TLS stack ->flush_flight() call"},
	{ .mask = QUIC_EV_CONN_SSLALERT, .name = "send_alert",       .desc = "TLS stack ->send_alert() call"},
	{ .mask = QUIC_EV_CONN_RTTUPDT,  .name = "rtt_updt",         .desc = "RTT sampling" },
	{ .mask = QUIC_EV_CONN_SPPKTS,   .name = "sppkts",           .desc = "send prepared packets" },
	{ .mask = QUIC_EV_CONN_PKTLOSS,  .name = "pktloss",          .desc = "detect packet loss" },
	{ .mask = QUIC_EV_CONN_STIMER,   .name = "stimer",           .desc = "set timer" },
	{ .mask = QUIC_EV_CONN_PTIMER,   .name = "ptimer",           .desc = "process timer" },
	{ .mask = QUIC_EV_CONN_SPTO,     .name = "spto",             .desc = "set PTO" },
	{ .mask = QUIC_EV_CONN_BCFRMS,   .name = "bcfrms",           .desc = "build CRYPTO data frames" },
	{ /* end */ }
};

static const struct name_desc quic_trace_lockon_args[4] = {
	/* arg1 */ { /* already used by the connection */ },
	/* arg2 */ { .name="quic", .desc="QUIC transport" },
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct name_desc quic_trace_decoding[] = {
#define QUIC_VERB_CLEAN    1
	{ .name="clean",    .desc="only user-friendly stuff, generally suitable for level \"user\"" },
	{ /* end */ }
};


struct trace_source trace_quic = {
	.name = IST("quic"),
	.desc = "QUIC xprt",
	.arg_def = TRC_ARG1_CONN,  /* TRACE()'s first argument is always a connection */
	.default_cb = quic_trace,
	.known_events = quic_trace_events,
	.lockon_args = quic_trace_lockon_args,
	.decoding = quic_trace_decoding,
	.report_events = ~0,  /* report everything by default */
};

#define TRACE_SOURCE    &trace_quic
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

static BIO_METHOD *ha_quic_meth;

/* QUIC xprt connection context. */
struct quic_conn_ctx {
	struct connection *conn;
	SSL *ssl;
	BIO *bio;
	int state;
	const struct xprt_ops *xprt;
	void *xprt_ctx;
	struct wait_event wait_event;
	struct wait_event *subs;
};

DECLARE_STATIC_POOL(pool_head_quic_conn_ctx,
                    "quic_conn_ctx_pool", sizeof(struct quic_conn_ctx));

DECLARE_STATIC_POOL(pool_head_quic_conn, "quic_conn", sizeof(struct quic_conn));

DECLARE_POOL(pool_head_quic_connection_id,
             "quic_connnection_id_pool", sizeof(struct quic_connection_id));

DECLARE_POOL(pool_head_quic_rx_packet, "quic_rx_packet_pool", sizeof(struct quic_rx_packet));

DECLARE_POOL(pool_head_quic_tx_packet, "quic_tx_packet_pool", sizeof(struct quic_tx_packet));

DECLARE_STATIC_POOL(pool_head_quic_rx_crypto_frm, "quic_rx_crypto_frm_pool", sizeof(struct quic_rx_crypto_frm));

DECLARE_POOL(pool_head_quic_tx_frm, "quic_tx_frm_pool", sizeof(struct quic_tx_frm));

DECLARE_STATIC_POOL(pool_head_quic_crypto_buf, "quic_crypto_buf_pool", sizeof(struct quic_crypto_buf));

DECLARE_STATIC_POOL(pool_head_quic_frame, "quic_frame_pool", sizeof(struct quic_frame));

DECLARE_STATIC_POOL(pool_head_quic_arng, "quic_arng_pool", sizeof(struct quic_arng_node));

static ssize_t qc_build_hdshk_pkt(struct q_buf *buf, struct quic_conn *qc, int pkt_type,
                                  struct quic_enc_level *qel);

int qc_prep_phdshk_pkts(struct quic_conn *qc);

/* Add traces to <buf> depending on <frm> TX frame type. */
static inline void chunk_tx_frm_appendf(struct buffer *buf,
                                        const struct quic_tx_frm *frm)
{
	switch (frm->type) {
	case QUIC_FT_CRYPTO:
		chunk_appendf(buf, " cfoff=%llu cflen=%llu",
		              (unsigned long long)frm->crypto.offset,
		              (unsigned long long)frm->crypto.len);
		break;
	default:
		chunk_appendf(buf, " %s", quic_frame_type_string(frm->type));
	}
}

/* Only for debug purpose */
struct enc_debug_info {
	unsigned char *payload;
	size_t payload_len;
	unsigned char *aad;
	size_t aad_len;
	uint64_t pn;
};

/* Initializes a enc_debug_info struct (only for debug purpose) */
static inline void enc_debug_info_init(struct enc_debug_info *edi,
                                       unsigned char *payload, size_t payload_len,
                                       unsigned char *aad, size_t aad_len, uint64_t pn)
{
	edi->payload = payload;
	edi->payload_len = payload_len;
	edi->aad = aad;
	edi->aad_len = aad_len;
	edi->pn = pn;
}

/* Trace callback for QUIC.
 * These traces always expect that arg1, if non-null, is of type connection.
 */
static void quic_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                       const struct ist where, const struct ist func,
                       const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct connection *conn = a1;

	if (conn) {
		struct quic_tls_secrets *secs;
		struct quic_conn *qc;

		qc = conn->qc;
		chunk_appendf(&trace_buf, " : conn@%p", conn);
		if ((mask & QUIC_EV_CONN_INIT) && qc) {
			chunk_appendf(&trace_buf, "\n  odcid");
			quic_cid_dump(&trace_buf, &qc->odcid);
			chunk_appendf(&trace_buf, "\n   dcid");
			quic_cid_dump(&trace_buf, &qc->dcid);
			chunk_appendf(&trace_buf, "\n   scid");
			quic_cid_dump(&trace_buf, &qc->scid);
		}

		if (mask & QUIC_EV_CONN_ADDDATA) {
			const enum ssl_encryption_level_t *level = a2;
			const size_t *len = a3;

			if (level) {
				enum quic_tls_enc_level lvl = ssl_to_quic_enc_level(*level);

				chunk_appendf(&trace_buf, " el=%c(%d)", quic_enc_level_char(lvl), lvl);
			}
			if (len)
				chunk_appendf(&trace_buf, " len=%llu", (unsigned long long)*len);
		}
		if ((mask & QUIC_EV_CONN_ISEC) && qc) {
			/* Initial read & write secrets. */
			enum quic_tls_enc_level level = QUIC_TLS_ENC_LEVEL_INITIAL;
			const unsigned char *rx_sec = a2;
			const unsigned char *tx_sec = a3;

			secs = &qc->els[level].tls_ctx.rx;
			if (secs->flags & QUIC_FL_TLS_SECRETS_SET) {
				chunk_appendf(&trace_buf, "\n  RX el=%c", quic_enc_level_char(level));
				if (rx_sec)
					quic_tls_secret_hexdump(&trace_buf, rx_sec, 32);
				quic_tls_keys_hexdump(&trace_buf, secs);
			}
			secs = &qc->els[level].tls_ctx.tx;
			if (secs->flags & QUIC_FL_TLS_SECRETS_SET) {
				chunk_appendf(&trace_buf, "\n  TX el=%c", quic_enc_level_char(level));
				if (tx_sec)
					quic_tls_secret_hexdump(&trace_buf, tx_sec, 32);
				quic_tls_keys_hexdump(&trace_buf, secs);
			}
		}
		if (mask & (QUIC_EV_CONN_RSEC|QUIC_EV_CONN_RWSEC)) {
			const enum ssl_encryption_level_t *level = a2;
			const unsigned char *secret = a3;
			const size_t *secret_len = a4;

			if (level) {
				enum quic_tls_enc_level lvl = ssl_to_quic_enc_level(*level);

				chunk_appendf(&trace_buf, "\n  RX el=%c", quic_enc_level_char(lvl));
				if (secret && secret_len)
					quic_tls_secret_hexdump(&trace_buf, secret, *secret_len);
				secs = &qc->els[lvl].tls_ctx.rx;
				if (secs->flags & QUIC_FL_TLS_SECRETS_SET)
					quic_tls_keys_hexdump(&trace_buf, secs);
			}
		}

		if (mask & (QUIC_EV_CONN_WSEC|QUIC_EV_CONN_RWSEC)) {
			const enum ssl_encryption_level_t *level = a2;
			const unsigned char *secret = a3;
			const size_t *secret_len = a4;

			if (level) {
				enum quic_tls_enc_level lvl = ssl_to_quic_enc_level(*level);

				chunk_appendf(&trace_buf, "\n  TX el=%c", quic_enc_level_char(lvl));
				if (secret && secret_len)
					quic_tls_secret_hexdump(&trace_buf, secret, *secret_len);
				secs = &qc->els[lvl].tls_ctx.tx;
				if (secs->flags & QUIC_FL_TLS_SECRETS_SET)
					quic_tls_keys_hexdump(&trace_buf, secs);
			}

		}

		if (mask & (QUIC_EV_CONN_HPKT|QUIC_EV_CONN_PAPKT)) {
			const struct quic_tx_packet *pkt = a2;
			const struct quic_enc_level *qel = a3;
			const ssize_t *room = a4;

			if (qel) {
				struct quic_pktns *pktns;

				pktns = qc->pktns;
				chunk_appendf(&trace_buf, " qel=%c cwnd=%llu ppif=%lld pif=%llu "
				              "if=%llu pp=%u pdg=%d",
				              quic_enc_level_char_from_qel(qel, qc),
				              (unsigned long long)qc->path->cwnd,
				              (unsigned long long)qc->path->prep_in_flight,
				              (unsigned long long)qc->path->in_flight,
				              (unsigned long long)pktns->tx.in_flight,
				              pktns->tx.pto_probe, qc->tx.nb_pto_dgrams);
			}
			if (pkt) {
				const struct quic_tx_frm *frm;
				chunk_appendf(&trace_buf, " pn=%llu cdlen=%u",
				              (unsigned long long)pkt->pn_node.key, pkt->cdata_len);
				list_for_each_entry(frm, &pkt->frms, list)
					chunk_tx_frm_appendf(&trace_buf, frm);
				chunk_appendf(&trace_buf, " tx.bytes=%llu", (unsigned long long)qc->tx.bytes);
			}

			if (room) {
				chunk_appendf(&trace_buf, " room=%lld", (long long)*room);
				chunk_appendf(&trace_buf, " dcid.len=%llu scid.len=%llu",
				              (unsigned long long)qc->dcid.len, (unsigned long long)qc->scid.len);
			}
		}

		if (mask & QUIC_EV_CONN_HDSHK) {
			const enum quic_handshake_state *state = a2;
			const int *err = a3;

			if (state)
				chunk_appendf(&trace_buf, " state=%s", quic_hdshk_state_str(*state));
			if (err)
				chunk_appendf(&trace_buf, " err=%s", ssl_error_str(*err));
		}

		if (mask & (QUIC_EV_CONN_TRMHP|QUIC_EV_CONN_ELRMHP|QUIC_EV_CONN_SPKT)) {
			const struct quic_rx_packet *pkt = a2;
			const unsigned long *pktlen = a3;
			const SSL *ssl = a4;

			if (pkt) {
				chunk_appendf(&trace_buf, " pkt@%p el=%c",
				              pkt, quic_packet_type_enc_level_char(pkt->type));
				if (pkt->pnl)
					chunk_appendf(&trace_buf, " pnl=%u pn=%llu", pkt->pnl,
					              (unsigned long long)pkt->pn);
				if (pkt->token_len)
					chunk_appendf(&trace_buf, " toklen=%llu",
					              (unsigned long long)pkt->token_len);
				if (pkt->aad_len)
					chunk_appendf(&trace_buf, " aadlen=%llu",
					              (unsigned long long)pkt->aad_len);
				chunk_appendf(&trace_buf, " flags=0x%x len=%llu",
				              pkt->flags, (unsigned long long)pkt->len);
			}
			if (pktlen)
				chunk_appendf(&trace_buf, " (%ld)", *pktlen);
			if (ssl) {
				enum ssl_encryption_level_t level = SSL_quic_read_level(ssl);
				chunk_appendf(&trace_buf, " el=%c",
				              quic_enc_level_char(ssl_to_quic_enc_level(level)));
			}
		}

		if (mask & (QUIC_EV_CONN_ELRXPKTS|QUIC_EV_CONN_PRSHPKT|QUIC_EV_CONN_SSLDATA)) {
			const struct quic_rx_packet *pkt = a2;
			const struct quic_rx_crypto_frm *cf = a3;
			const SSL *ssl = a4;

			if (pkt)
				chunk_appendf(&trace_buf, " pkt@%p el=%c pn=%llu", pkt,
				              quic_packet_type_enc_level_char(pkt->type),
				              (unsigned long long)pkt->pn);
			if (cf)
				chunk_appendf(&trace_buf, " cfoff=%llu cflen=%llu",
				              (unsigned long long)cf->offset_node.key,
				              (unsigned long long)cf->len);
			if (ssl) {
				enum ssl_encryption_level_t level = SSL_quic_read_level(ssl);
				chunk_appendf(&trace_buf, " el=%c",
				              quic_enc_level_char(ssl_to_quic_enc_level(level)));
			}
		}

		if (mask & (QUIC_EV_CONN_PRSFRM|QUIC_EV_CONN_BFRM)) {
			const struct quic_frame *frm = a2;

			if (frm)
				chunk_appendf(&trace_buf, " %s", quic_frame_type_string(frm->type));
		}

		if (mask & QUIC_EV_CONN_PHPKTS) {
			const struct quic_enc_level *qel = a2;

			if (qel) {
				struct quic_pktns *pktns;

				pktns = qc->pktns;
				chunk_appendf(&trace_buf,
				              " qel=%c ack?%d cwnd=%llu ppif=%lld pif=%llu if=%llu pp=%u pdg=%llu",
				              quic_enc_level_char_from_qel(qel, qc),
				              !!(pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED),
				              (unsigned long long)qc->path->cwnd,
				              (unsigned long long)qc->path->prep_in_flight,
				              (unsigned long long)qc->path->in_flight,
				              (unsigned long long)pktns->tx.in_flight, pktns->tx.pto_probe,
				              (unsigned long long)qc->tx.nb_pto_dgrams);
			}
		}

		if (mask & QUIC_EV_CONN_ENCPKT) {
			const struct enc_debug_info *edi = a2;

			if (edi)
				chunk_appendf(&trace_buf,
				              " payload=@%p payload_len=%llu"
				              " aad=@%p aad_len=%llu pn=%llu",
				              edi->payload, (unsigned long long)edi->payload_len,
				              edi->aad, (unsigned long long)edi->aad_len,
				              (unsigned long long)edi->pn);
		}

		if (mask & QUIC_EV_CONN_RMHP) {
			const struct quic_rx_packet *pkt = a2;

			if (pkt) {
				const int *ret = a3;

				chunk_appendf(&trace_buf, " pkt@%p", pkt);
				if (ret && *ret)
					chunk_appendf(&trace_buf, " pnl=%u pn=%llu",
					              pkt->pnl, (unsigned long long)pkt->pn);
			}
		}

		if (mask & QUIC_EV_CONN_PRSAFRM) {
			const struct quic_tx_frm *frm = a2;
			const unsigned long *val1 = a3;
			const unsigned long *val2 = a4;

			if (frm)
				chunk_tx_frm_appendf(&trace_buf, frm);
			if (val1)
				chunk_appendf(&trace_buf, " %lu", *val1);
			if (val2)
				chunk_appendf(&trace_buf, "..%lu", *val2);
		}

		if (mask & QUIC_EV_CONN_RTTUPDT) {
			const unsigned int *rtt_sample = a2;
			const unsigned int *ack_delay = a3;
			const struct quic_loss *ql = a4;

			if (rtt_sample)
				chunk_appendf(&trace_buf, " rtt_sample=%ums", *rtt_sample);
			if (ack_delay)
				chunk_appendf(&trace_buf, " ack_delay=%ums", *ack_delay);
			if (ql)
				chunk_appendf(&trace_buf,
				              " srtt=%ums rttvar=%ums min_rtt=%ums",
				              ql->srtt >> 3, ql->rtt_var >> 2, ql->rtt_min);
		}
		if (mask & QUIC_EV_CONN_CC) {
			const struct quic_cc_event *ev = a2;
			const struct quic_cc *cc = a3;

			if (a2)
				quic_cc_event_trace(&trace_buf, ev);
			if (a3)
				quic_cc_state_trace(&trace_buf, cc);
		}

		if (mask & QUIC_EV_CONN_PKTLOSS) {
			const struct quic_pktns *pktns = a2;
			const struct list *lost_pkts = a3;
			struct quic_conn *qc = conn->qc;

			if (pktns) {
				chunk_appendf(&trace_buf, " pktns=%s",
				              pktns == &qc->pktns[QUIC_TLS_PKTNS_INITIAL] ? "I" :
				              pktns == &qc->pktns[QUIC_TLS_PKTNS_01RTT] ? "01RTT": "H");
				if (pktns->tx.loss_time)
				              chunk_appendf(&trace_buf, " loss_time=%dms",
				                            TICKS_TO_MS(tick_remain(now_ms, pktns->tx.loss_time)));
			}
			if (lost_pkts && !LIST_ISEMPTY(lost_pkts)) {
				struct quic_tx_packet *pkt;

				chunk_appendf(&trace_buf, " lost_pkts:");
				list_for_each_entry(pkt, lost_pkts, list)
					chunk_appendf(&trace_buf, " %lu", (unsigned long)pkt->pn_node.key);
			}
		}

		if (mask & (QUIC_EV_CONN_STIMER|QUIC_EV_CONN_PTIMER|QUIC_EV_CONN_SPTO)) {
			struct quic_conn *qc = conn->qc;
			const struct quic_pktns *pktns = a2;
			const int *duration = a3;
			const uint64_t *ifae_pkts = a4;

			if (ifae_pkts)
				chunk_appendf(&trace_buf, " ifae_pkts=%llu",
				              (unsigned long long)*ifae_pkts);
			if (pktns) {
				chunk_appendf(&trace_buf, " pktns=%s pp=%d",
				              pktns == &qc->pktns[QUIC_TLS_PKTNS_INITIAL] ? "I" :
				              pktns == &qc->pktns[QUIC_TLS_PKTNS_01RTT] ? "01RTT": "H",
				              pktns->tx.pto_probe);
				if (mask & QUIC_EV_CONN_STIMER) {
					if (pktns->tx.loss_time)
						chunk_appendf(&trace_buf, " loss_time=%dms",
						              TICKS_TO_MS(pktns->tx.loss_time - now_ms));
				}
				if (mask & QUIC_EV_CONN_SPTO) {
					if (pktns->tx.time_of_last_eliciting)
						chunk_appendf(&trace_buf, " tole=%dms",
						              TICKS_TO_MS(pktns->tx.time_of_last_eliciting - now_ms));
					if (duration)
						chunk_appendf(&trace_buf, " dur=%dms", TICKS_TO_MS(*duration));
				}
			}

			if (!(mask & QUIC_EV_CONN_SPTO) && qc->timer_task) {
				chunk_appendf(&trace_buf,
				              " expire=%dms", TICKS_TO_MS(qc->timer - now_ms));
			}
		}

		if (mask & QUIC_EV_CONN_SPPKTS) {
			const struct quic_tx_packet *pkt = a2;

			chunk_appendf(&trace_buf, " cwnd=%llu ppif=%llu pif=%llu",
			             (unsigned long long)qc->path->cwnd,
			             (unsigned long long)qc->path->prep_in_flight,
			             (unsigned long long)qc->path->in_flight);
			if (pkt) {
				chunk_appendf(&trace_buf, " pn=%lu(%s) iflen=%llu cdlen=%llu",
				              (unsigned long)pkt->pn_node.key,
				              pkt->pktns == &qc->pktns[QUIC_TLS_PKTNS_INITIAL] ? "I" :
				              pkt->pktns == &qc->pktns[QUIC_TLS_PKTNS_01RTT] ? "01RTT": "H",
				              (unsigned long long)pkt->in_flight_len,
				              (unsigned long long)pkt->cdata_len);
			}
		}

		if (mask & QUIC_EV_CONN_SSLALERT) {
			const uint8_t *alert = a2;
			const enum ssl_encryption_level_t *level = a3;

			if (alert)
				chunk_appendf(&trace_buf, " alert=0x%02x", *alert);
			if (level)
				chunk_appendf(&trace_buf, " el=%c",
				              quic_enc_level_char(ssl_to_quic_enc_level(*level)));
		}

		if (mask & QUIC_EV_CONN_BCFRMS) {
			const size_t *sz1 = a2;
			const size_t *sz2 = a3;
			const size_t *sz3 = a4;

			if (sz1)
				chunk_appendf(&trace_buf, " %llu", (unsigned long long)*sz1);
			if (sz2)
				chunk_appendf(&trace_buf, " %llu", (unsigned long long)*sz2);
			if (sz3)
				chunk_appendf(&trace_buf, " %llu", (unsigned long long)*sz3);
		}

		if (mask & QUIC_EV_CONN_PSTRM) {
			const struct quic_frame *frm = a2;
			const struct quic_stream *s = &frm->stream;

			chunk_appendf(&trace_buf, " uni=%d fin=%d id=%llu off=%llu len=%llu",
			              !!(s->id & QUIC_STREAM_FRAME_ID_DIR_BIT),
			              !!(frm->type & QUIC_STREAM_FRAME_TYPE_FIN_BIT),
			              (unsigned long long)s->id,
			              (unsigned long long)s->offset,
			              (unsigned long long)s->len);
		}
	}
	if (mask & QUIC_EV_CONN_LPKT) {
		const struct quic_rx_packet *pkt = a2;

		if (conn)
			chunk_appendf(&trace_buf, " xprt_ctx@%p", conn->xprt_ctx);
		if (pkt)
			chunk_appendf(&trace_buf, " type=0x%02x %s",
			              pkt->type, qc_pkt_long(pkt) ? "long" : "short");
	}

}

/* Returns 1 if the peer has validated <qc> QUIC connection address, 0 if not. */
static inline int quic_peer_validated_addr(struct quic_conn_ctx *ctx)
{
	struct quic_conn *qc;

	qc = ctx->conn->qc;
	if (objt_server(qc->conn->target))
		return 1;

	if ((qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE].pktns->flags & QUIC_FL_PKTNS_ACK_RECEIVED) ||
	    (qc->els[QUIC_TLS_ENC_LEVEL_APP].pktns->flags & QUIC_FL_PKTNS_ACK_RECEIVED) ||
	    (ctx->state & QUIC_HS_ST_COMPLETE))
		return 1;

	return 0;
}

/* Set the timer attached to the QUIC connection with <ctx> as I/O handler and used for
 * both loss detection and PTO and schedule the task assiated to this timer if needed.
 */
static inline void qc_set_timer(struct quic_conn_ctx *ctx)
{
	struct quic_conn *qc;
	struct quic_pktns *pktns;
	unsigned int pto;

	TRACE_ENTER(QUIC_EV_CONN_STIMER, ctx->conn,
	            NULL, NULL, &ctx->conn->qc->path->ifae_pkts);
	qc = ctx->conn->qc;
	pktns = quic_loss_pktns(qc);
	if (tick_isset(pktns->tx.loss_time)) {
		qc->timer = pktns->tx.loss_time;
		goto out;
	}

	/* XXX TODO: anti-amplification: the timer must be
	 * cancelled for a server which reached the anti-amplification limit.
	 */

	if (!qc->path->ifae_pkts && quic_peer_validated_addr(ctx)) {
		TRACE_PROTO("timer cancellation", QUIC_EV_CONN_STIMER, ctx->conn);
		/* Timer cancellation. */
		qc->timer = TICK_ETERNITY;
		goto out;
	}

	pktns = quic_pto_pktns(qc, ctx->state & QUIC_HS_ST_COMPLETE, &pto);
	if (tick_isset(pto))
		qc->timer = pto;
 out:
	task_schedule(qc->timer_task, qc->timer);
	TRACE_LEAVE(QUIC_EV_CONN_STIMER, ctx->conn, pktns);
}

#ifndef OPENSSL_IS_BORINGSSL
int ha_quic_set_encryption_secrets(SSL *ssl, enum ssl_encryption_level_t level,
                                   const uint8_t *read_secret,
                                   const uint8_t *write_secret, size_t secret_len)
{
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);
	struct quic_tls_ctx *tls_ctx =
		&conn->qc->els[ssl_to_quic_enc_level(level)].tls_ctx;
	const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);

	TRACE_ENTER(QUIC_EV_CONN_RWSEC, conn);
	tls_ctx->rx.aead = tls_ctx->tx.aead = tls_aead(cipher);
	tls_ctx->rx.md   = tls_ctx->tx.md   = tls_md(cipher);
	tls_ctx->rx.hp   = tls_ctx->tx.hp   = tls_hp(cipher);

	if (!quic_tls_derive_keys(tls_ctx->rx.aead, tls_ctx->rx.hp, tls_ctx->rx.md,
	                          tls_ctx->rx.key, sizeof tls_ctx->rx.key,
	                          tls_ctx->rx.iv, sizeof tls_ctx->rx.iv,
	                          tls_ctx->rx.hp_key, sizeof tls_ctx->rx.hp_key,
	                          read_secret, secret_len)) {
		TRACE_DEVEL("RX key derivation failed", QUIC_EV_CONN_RWSEC, conn);
		return 0;
	}

	tls_ctx->rx.flags |= QUIC_FL_TLS_SECRETS_SET;
	if (!quic_tls_derive_keys(tls_ctx->tx.aead, tls_ctx->tx.hp, tls_ctx->tx.md,
	                          tls_ctx->tx.key, sizeof tls_ctx->tx.key,
	                          tls_ctx->tx.iv, sizeof tls_ctx->tx.iv,
	                          tls_ctx->tx.hp_key, sizeof tls_ctx->tx.hp_key,
	                          write_secret, secret_len)) {
		TRACE_DEVEL("TX key derivation failed", QUIC_EV_CONN_RWSEC, conn);
		return 0;
	}

	tls_ctx->tx.flags |= QUIC_FL_TLS_SECRETS_SET;
	if (objt_server(conn->target) && level == ssl_encryption_application) {
		const unsigned char *buf;
		size_t buflen;

		SSL_get_peer_quic_transport_params(ssl, &buf, &buflen);
		if (!buflen)
			return 0;

		if (!quic_transport_params_store(conn->qc, 1, buf, buf + buflen))
			return 0;
	}
	TRACE_LEAVE(QUIC_EV_CONN_RWSEC, conn, &level);

	return 1;
}
#else
/* ->set_read_secret callback to derive the RX secrets at <level> encryption
 * level.
 * Returns 1 if succeeded, 0 if not.
 */
int ha_set_rsec(SSL *ssl, enum ssl_encryption_level_t level,
                const SSL_CIPHER *cipher,
                const uint8_t *secret, size_t secret_len)
{
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);
	struct quic_tls_ctx *tls_ctx =
		&conn->qc->els[ssl_to_quic_enc_level(level)].tls_ctx;

	TRACE_ENTER(QUIC_EV_CONN_RSEC, conn);
	tls_ctx->rx.aead = tls_aead(cipher);
	tls_ctx->rx.md = tls_md(cipher);
	tls_ctx->rx.hp = tls_hp(cipher);

	if (!quic_tls_derive_keys(tls_ctx->rx.aead, tls_ctx->rx.hp, tls_ctx->rx.md,
	                          tls_ctx->rx.key, sizeof tls_ctx->rx.key,
	                          tls_ctx->rx.iv, sizeof tls_ctx->rx.iv,
	                          tls_ctx->rx.hp_key, sizeof tls_ctx->rx.hp_key,
	                          secret, secret_len)) {
		TRACE_DEVEL("RX key derivation failed", QUIC_EV_CONN_RSEC, conn);
		goto err;
	}

	if (objt_server(conn->target) && level == ssl_encryption_application) {
		const unsigned char *buf;
		size_t buflen;

		SSL_get_peer_quic_transport_params(ssl, &buf, &buflen);
		if (!buflen)
			goto err;

		if (!quic_transport_params_store(conn->qc, 1, buf, buf + buflen))
			goto err;
	}

	tls_ctx->rx.flags |= QUIC_FL_TLS_SECRETS_SET;
	TRACE_LEAVE(QUIC_EV_CONN_RSEC, conn, &level, secret, &secret_len);

	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_RSEC, conn);
	return 0;
}

/* ->set_write_secret callback to derive the TX secrets at <level>
 * encryption level.
 * Returns 1 if succeeded, 0 if not.
 */
int ha_set_wsec(SSL *ssl, enum ssl_encryption_level_t level,
                const SSL_CIPHER *cipher,
                const uint8_t *secret, size_t secret_len)
{
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);
	struct quic_tls_ctx *tls_ctx =
		&conn->qc->els[ssl_to_quic_enc_level(level)].tls_ctx;

	TRACE_ENTER(QUIC_EV_CONN_WSEC, conn);
	tls_ctx->tx.aead = tls_aead(cipher);
	tls_ctx->tx.md = tls_md(cipher);
	tls_ctx->tx.hp = tls_hp(cipher);

	if (!quic_tls_derive_keys(tls_ctx->tx.aead, tls_ctx->tx.hp, tls_ctx->tx.md,
	                          tls_ctx->tx.key, sizeof tls_ctx->tx.key,
	                          tls_ctx->tx.iv, sizeof tls_ctx->tx.iv,
	                          tls_ctx->tx.hp_key, sizeof tls_ctx->tx.hp_key,
	                          secret, secret_len)) {
		TRACE_DEVEL("TX key derivation failed", QUIC_EV_CONN_WSEC, conn);
		goto err;
	}

	tls_ctx->tx.flags |= QUIC_FL_TLS_SECRETS_SET;
	TRACE_LEAVE(QUIC_EV_CONN_WSEC, conn, &level, secret, &secret_len);

	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_WSEC, conn);
	return 0;
}
#endif

/* This function copies the CRYPTO data provided by the TLS stack found at <data>
 * with <len> as size in CRYPTO buffers dedicated to store the information about
 * outgoing CRYPTO frames so that to be able to replay the CRYPTO data streams.
 * It fails only if it could not managed to allocate enough CRYPTO buffers to
 * store all the data.
 * Note that CRYPTO data may exist at any encryption level except at 0-RTT.
 */
static int quic_crypto_data_cpy(struct quic_enc_level *qel,
                                const unsigned char *data, size_t len)
{
	struct quic_crypto_buf **qcb;
	/* The remaining byte to store in CRYPTO buffers. */
	size_t cf_offset, cf_len, *nb_buf;
	unsigned char *pos;

	nb_buf = &qel->tx.crypto.nb_buf;
	qcb = &qel->tx.crypto.bufs[*nb_buf - 1];
	cf_offset = (*nb_buf - 1) * QUIC_CRYPTO_BUF_SZ + (*qcb)->sz;
	cf_len = len;

	while (len) {
		size_t to_copy, room;

		pos = (*qcb)->data + (*qcb)->sz;
		room = QUIC_CRYPTO_BUF_SZ  - (*qcb)->sz;
		to_copy = len > room ? room : len;
		if (to_copy) {
			memcpy(pos, data, to_copy);
			/* Increment the total size of this CRYPTO buffers by <to_copy>. */
			qel->tx.crypto.sz += to_copy;
			(*qcb)->sz += to_copy;
			pos += to_copy;
			len -= to_copy;
			data += to_copy;
		}
		else {
			struct quic_crypto_buf **tmp;

			tmp = realloc(qel->tx.crypto.bufs,
			              (*nb_buf + 1) * sizeof *qel->tx.crypto.bufs);
			if (tmp) {
				qel->tx.crypto.bufs = tmp;
				qcb = &qel->tx.crypto.bufs[*nb_buf];
				*qcb = pool_alloc(pool_head_quic_crypto_buf);
				if (!*qcb)
					return 0;

				(*qcb)->sz = 0;
				++*nb_buf;
			}
			else {
				break;
			}
		}
	}

	/* Allocate a TX CRYPTO frame only if all the CRYPTO data
	 * have been buffered.
	 */
	if (!len) {
		struct quic_tx_frm *frm;

		frm = pool_alloc(pool_head_quic_tx_frm);
		if (!frm)
			return 0;

		frm->type = QUIC_FT_CRYPTO;
		frm->crypto.offset = cf_offset;
		frm->crypto.len = cf_len;
		LIST_ADDQ(&qel->pktns->tx.frms, &frm->list);
	}

	return len == 0;
}


/* ->add_handshake_data QUIC TLS callback used by the QUIC TLS stack when it
 * wants to provide the QUIC layer with CRYPTO data.
 * Returns 1 if succeeded, 0 if not.
 */
int ha_quic_add_handshake_data(SSL *ssl, enum ssl_encryption_level_t level,
                               const uint8_t *data, size_t len)
{
	struct connection *conn;
	enum quic_tls_enc_level tel;
	struct quic_enc_level *qel;

	conn = SSL_get_ex_data(ssl, ssl_app_data_index);
	TRACE_ENTER(QUIC_EV_CONN_ADDDATA, conn);
	tel = ssl_to_quic_enc_level(level);
	qel = &conn->qc->els[tel];

	if (tel == -1) {
		TRACE_PROTO("Wrong encryption level", QUIC_EV_CONN_ADDDATA, conn);
		goto err;
	}

	if (!quic_crypto_data_cpy(qel, data, len)) {
		TRACE_PROTO("Could not bufferize", QUIC_EV_CONN_ADDDATA, conn);
		goto err;
	}

	TRACE_PROTO("CRYPTO data buffered", QUIC_EV_CONN_ADDDATA,
	            conn, &level, &len);

	TRACE_LEAVE(QUIC_EV_CONN_ADDDATA, conn);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_ADDDATA, conn);
	return 0;
}

int ha_quic_flush_flight(SSL *ssl)
{
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);

	TRACE_ENTER(QUIC_EV_CONN_FFLIGHT, conn);
	TRACE_LEAVE(QUIC_EV_CONN_FFLIGHT, conn);

	return 1;
}

int ha_quic_send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert)
{
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);

	TRACE_DEVEL("SSL alert", QUIC_EV_CONN_SSLALERT, conn, &alert, &level);
	return 1;
}

/* QUIC TLS methods */
static SSL_QUIC_METHOD ha_quic_method = {
#ifdef OPENSSL_IS_BORINGSSL
	.set_read_secret        = ha_set_rsec,
	.set_write_secret       = ha_set_wsec,
#else
	.set_encryption_secrets = ha_quic_set_encryption_secrets,
#endif
	.add_handshake_data     = ha_quic_add_handshake_data,
	.flush_flight           = ha_quic_flush_flight,
	.send_alert             = ha_quic_send_alert,
};

/* Initialize the TLS context of a listener with <bind_conf> as configuration.
 * Returns an error count.
 */
int ssl_quic_initial_ctx(struct bind_conf *bind_conf)
{
	struct proxy *curproxy = bind_conf->frontend;
	struct ssl_bind_conf __maybe_unused *ssl_conf_cur;
	int cfgerr = 0;

#if 0
	/* XXX Did not manage to use this. */
	const char *ciphers =
		"TLS_AES_128_GCM_SHA256:"
		"TLS_AES_256_GCM_SHA384:"
		"TLS_CHACHA20_POLY1305_SHA256:"
		"TLS_AES_128_CCM_SHA256";
#endif
	const char *groups = "P-256:X25519:P-384:P-521";
	long options =
		(SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
		SSL_OP_SINGLE_ECDH_USE |
		SSL_OP_CIPHER_SERVER_PREFERENCE;
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(TLS_server_method());
	bind_conf->initial_ctx = ctx;

	SSL_CTX_set_options(ctx, options);
#if 0
	if (SSL_CTX_set_cipher_list(ctx, ciphers) != 1) {
		ha_alert("Proxy '%s': unable to set TLS 1.3 cipher list to '%s' "
		         "for bind '%s' at [%s:%d].\n",
		         curproxy->id, ciphers,
		         bind_conf->arg, bind_conf->file, bind_conf->line);
		cfgerr++;
	}
#endif

	if (SSL_CTX_set1_curves_list(ctx, groups) != 1) {
		ha_alert("Proxy '%s': unable to set TLS 1.3 curves list to '%s' "
		         "for bind '%s' at [%s:%d].\n",
		         curproxy->id, groups,
		         bind_conf->arg, bind_conf->file, bind_conf->line);
		cfgerr++;
	}

	SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_default_verify_paths(ctx);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
#ifdef OPENSSL_IS_BORINGSSL
	SSL_CTX_set_select_certificate_cb(ctx, ssl_sock_switchctx_cbk);
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_err_cbk);
#elif (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	if (bind_conf->ssl_conf.early_data) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_ANTI_REPLAY);
		SSL_CTX_set_max_early_data(ctx, global.tune.bufsize - global.tune.maxrewrite);
	}
	SSL_CTX_set_client_hello_cb(ctx, ssl_sock_switchctx_cbk, NULL);
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_err_cbk);
#else
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_cbk);
#endif
	SSL_CTX_set_tlsext_servername_arg(ctx, bind_conf);
#endif
	SSL_CTX_set_quic_method(ctx, &ha_quic_method);

	return cfgerr;
}

/* Decode an expected packet number from <truncated_on> its truncated value,
 * depending on <largest_pn> the largest received packet number, and <pn_nbits>
 * the number of bits used to encode this packet number (its length in bytes * 8).
 * See https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#packet-encoding
 */
static uint64_t decode_packet_number(uint64_t largest_pn,
                                     uint32_t truncated_pn, unsigned int pn_nbits)
{
	uint64_t expected_pn = largest_pn + 1;
	uint64_t pn_win = (uint64_t)1 << pn_nbits;
	uint64_t pn_hwin = pn_win / 2;
	uint64_t pn_mask = pn_win - 1;
	uint64_t candidate_pn;


	candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;
	/* Note that <pn_win> > <pn_hwin>. */
	if (candidate_pn < QUIC_MAX_PACKET_NUM - pn_win &&
	    candidate_pn + pn_hwin <= expected_pn)
		return candidate_pn + pn_win;

	if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win)
		return candidate_pn - pn_win;

	return candidate_pn;
}

/* Remove the header protection of <pkt> QUIC packet using <tls_ctx> as QUIC TLS
 * cryptographic context.
 * <largest_pn> is the largest received packet number and <pn> the address of
 * the packet number field for this packet with <byte0> address of its first byte.
 * <end> points to one byte past the end of this packet.
 * Returns 1 if succeeded, 0 if not.
 */
static int qc_do_rm_hp(struct quic_rx_packet *pkt, struct quic_tls_ctx *tls_ctx,
                       int64_t largest_pn, unsigned char *pn,
                       unsigned char *byte0, const unsigned char *end,
                       struct quic_conn_ctx *ctx)
{
	int ret, outlen, i, pnlen;
	uint64_t packet_number;
	uint32_t truncated_pn = 0;
	unsigned char mask[5] = {0};
	unsigned char *sample;
	EVP_CIPHER_CTX *cctx;
	unsigned char *hp_key;

	/* Check there is enough data in this packet. */
	if (end - pn < QUIC_PACKET_PN_MAXLEN + sizeof mask) {
		TRACE_DEVEL("too short packet", QUIC_EV_CONN_RMHP, ctx->conn, pkt);
		return 0;
	}

	cctx = EVP_CIPHER_CTX_new();
	if (!cctx) {
		TRACE_DEVEL("memory allocation failed", QUIC_EV_CONN_RMHP, ctx->conn, pkt);
		return 0;
	}

	ret = 0;
	sample = pn + QUIC_PACKET_PN_MAXLEN;

	hp_key = tls_ctx->rx.hp_key;
	if (!EVP_DecryptInit_ex(cctx, tls_ctx->rx.hp, NULL, hp_key, sample) ||
	    !EVP_DecryptUpdate(cctx, mask, &outlen, mask, sizeof mask) ||
	    !EVP_DecryptFinal_ex(cctx, mask, &outlen)) {
		TRACE_DEVEL("decryption failed", QUIC_EV_CONN_RMHP, ctx->conn, pkt);
	    goto out;
	}

	*byte0 ^= mask[0] & (*byte0 & QUIC_PACKET_LONG_HEADER_BIT ? 0xf : 0x1f);
	pnlen = (*byte0 & QUIC_PACKET_PNL_BITMASK) + 1;
	for (i = 0; i < pnlen; i++) {
		pn[i] ^= mask[i + 1];
		truncated_pn = (truncated_pn << 8) | pn[i];
	}

	packet_number = decode_packet_number(largest_pn, truncated_pn, pnlen * 8);
	/* Store remaining information for this unprotected header */
	pkt->pn = packet_number;
	pkt->pnl = pnlen;

	ret = 1;

 out:
	EVP_CIPHER_CTX_free(cctx);

	return ret;
}

/* Encrypt the payload of a QUIC packet with <pn> as number found at <payload>
 * address, with <payload_len> as payload length, <aad> as address of
 * the ADD and <aad_len> as AAD length depending on the <tls_ctx> QUIC TLS
 * context.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_packet_encrypt(unsigned char *payload, size_t payload_len,
                               unsigned char *aad, size_t aad_len, uint64_t pn,
                               struct quic_tls_ctx *tls_ctx, struct connection *conn)
{
	unsigned char iv[12];
	unsigned char *tx_iv = tls_ctx->tx.iv;
	size_t tx_iv_sz = sizeof tls_ctx->tx.iv;
	struct enc_debug_info edi;

	if (!quic_aead_iv_build(iv, sizeof iv, tx_iv, tx_iv_sz, pn)) {
		TRACE_DEVEL("AEAD IV building for encryption failed", QUIC_EV_CONN_HPKT, conn);
		goto err;
	}

	if (!quic_tls_encrypt(payload, payload_len, aad, aad_len,
	                      tls_ctx->tx.aead, tls_ctx->tx.key, iv)) {
		TRACE_DEVEL("QUIC packet encryption failed", QUIC_EV_CONN_HPKT, conn);
		goto err;
	}

	return 1;

 err:
	enc_debug_info_init(&edi, payload, payload_len, aad, aad_len, pn);
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_ENCPKT, conn, &edi);
	return 0;
}

/* Decrypt <pkt> QUIC packet with <tls_ctx> as QUIC TLS cryptographic context.
 * Returns 1 if succeeded, 0 if not.
 */
static int qc_pkt_decrypt(struct quic_rx_packet *pkt, struct quic_tls_ctx *tls_ctx)
{
	int ret;
	unsigned char iv[12];
	unsigned char *rx_iv = tls_ctx->rx.iv;
	size_t rx_iv_sz = sizeof tls_ctx->rx.iv;

	if (!quic_aead_iv_build(iv, sizeof iv, rx_iv, rx_iv_sz, pkt->pn))
		return 0;

	ret = quic_tls_decrypt(pkt->data + pkt->aad_len, pkt->len - pkt->aad_len,
	                       pkt->data, pkt->aad_len,
	                       tls_ctx->rx.aead, tls_ctx->rx.key, iv);
	if (!ret)
		return 0;

	/* Update the packet length (required to parse the frames). */
	pkt->len = pkt->aad_len + ret;

	return 1;
}

/* Treat <frm> frame whose packet it is attached to has just been acknowledged. */
static inline void qc_treat_acked_tx_frm(struct quic_tx_frm *frm,
                                         struct quic_conn_ctx *ctx)
{
	TRACE_PROTO("Removing frame", QUIC_EV_CONN_PRSAFRM, ctx->conn, frm);
	LIST_DEL(&frm->list);
	pool_free(pool_head_quic_tx_frm, frm);
}

/* Remove <largest> down to <smallest> node entries from <pkts> tree of TX packet,
 * deallocating them, and their TX frames.
 * Returns the last node reached to be used for the next range.
 * May be NULL if <largest> node could not be found.
 */
static inline struct eb64_node *qc_ackrng_pkts(struct eb_root *pkts, unsigned int *pkt_flags,
                                               struct list *newly_acked_pkts,
                                               struct eb64_node *largest_node,
                                               uint64_t largest, uint64_t smallest,
                                               struct quic_conn_ctx *ctx)
{
	struct eb64_node *node;
	struct quic_tx_packet *pkt;

	if (largest_node)
		node = largest_node;
	else {
		node = eb64_lookup(pkts, largest);
		while (!node && largest > smallest) {
			node = eb64_lookup(pkts, --largest);
		}
	}

	while (node && node->key >= smallest) {
		struct quic_tx_frm *frm, *frmbak;

		pkt = eb64_entry(&node->node, struct quic_tx_packet, pn_node);
		*pkt_flags |= pkt->flags;
		LIST_ADD(newly_acked_pkts, &pkt->list);
		TRACE_PROTO("Removing packet #", QUIC_EV_CONN_PRSAFRM, ctx->conn,, &pkt->pn_node.key);
		list_for_each_entry_safe(frm, frmbak, &pkt->frms, list)
			qc_treat_acked_tx_frm(frm, ctx);
		node = eb64_prev(node);
		eb64_delete(&pkt->pn_node);
	}

	return node;
}

/* Treat <frm> frame whose packet it is attached to has just been detected as non
 * acknowledged.
 */
static inline void qc_treat_nacked_tx_frm(struct quic_tx_frm *frm,
                                          struct quic_pktns *pktns,
                                          struct quic_conn_ctx *ctx)
{
	TRACE_PROTO("to resend frame", QUIC_EV_CONN_PRSAFRM, ctx->conn, frm);
	LIST_DEL(&frm->list);
	LIST_ADD(&pktns->tx.frms, &frm->list);
}


/* Free the TX packets of <pkts> list */
static inline void free_quic_tx_pkts(struct list *pkts)
{
	struct quic_tx_packet *pkt, *tmp;

	list_for_each_entry_safe(pkt, tmp, pkts, list) {
		LIST_DEL(&pkt->list);
		eb64_delete(&pkt->pn_node);
		pool_free(pool_head_quic_tx_packet, pkt);
	}
}

/* Send a packet loss event nofification to the congestion controller
 * attached to <qc> connection with <lost_bytes> the number of lost bytes,
 * <oldest_lost>, <newest_lost> the oldest lost packet and newest lost packet
 * at <now_us> current time.
 * Always succeeds.
 */
static inline void qc_cc_loss_event(struct quic_conn *qc,
                                    unsigned int lost_bytes,
                                    unsigned int newest_time_sent,
                                    unsigned int period,
                                    unsigned int now_us)
{
	struct quic_cc_event ev = {
		.type = QUIC_CC_EVT_LOSS,
		.loss.now_ms           = now_ms,
		.loss.max_ack_delay    = qc->max_ack_delay,
		.loss.lost_bytes       = lost_bytes,
		.loss.newest_time_sent = newest_time_sent,
		.loss.period           = period,
	};

	quic_cc_event(&qc->path->cc, &ev);
}

/* Send a packet ack event nofication for each newly acked packet of
 * <newly_acked_pkts> list and free them.
 * Always succeeds.
 */
static inline void qc_treat_newly_acked_pkts(struct quic_conn_ctx *ctx,
                                             struct list *newly_acked_pkts)
{
	struct quic_conn *qc = ctx->conn->qc;
	struct quic_tx_packet *pkt, *tmp;
	struct quic_cc_event ev = { .type = QUIC_CC_EVT_ACK, };

	list_for_each_entry_safe(pkt, tmp, newly_acked_pkts, list) {
		pkt->pktns->tx.in_flight -= pkt->in_flight_len;
		qc->path->prep_in_flight -= pkt->in_flight_len;
		if (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING)
			qc->path->ifae_pkts--;
		ev.ack.acked = pkt->in_flight_len;
		ev.ack.time_sent = pkt->time_sent;
		quic_cc_event(&qc->path->cc, &ev);
		LIST_DEL(&pkt->list);
		eb64_delete(&pkt->pn_node);
		pool_free(pool_head_quic_tx_packet, pkt);
	}

}

/* Handle <pkts> list of lost packets detected at <now_us> handling
 * their TX frames.
 * Send a packet loss event to the congestion controller if
 * in flight packet have been lost.
 * Also frees the packet in <pkts> list.
 * Never fails.
 */
static inline void qc_release_lost_pkts(struct quic_pktns *pktns,
                                        struct quic_conn_ctx *ctx,
                                        struct list *pkts,
                                        uint64_t now_us)
{
	struct quic_conn *qc = ctx->conn->qc;
	struct quic_tx_packet *pkt, *tmp, *oldest_lost, *newest_lost;
	struct quic_tx_frm *frm, *frmbak;
	uint64_t lost_bytes;

	lost_bytes = 0;
	oldest_lost = newest_lost = NULL;
	list_for_each_entry_safe(pkt, tmp, pkts, list) {
		lost_bytes += pkt->in_flight_len;
		pkt->pktns->tx.in_flight -= pkt->in_flight_len;
		qc->path->prep_in_flight -= pkt->in_flight_len;
		if (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING)
			qc->path->ifae_pkts--;
		/* Treat the frames of this lost packet. */
		list_for_each_entry_safe(frm, frmbak, &pkt->frms, list)
			qc_treat_nacked_tx_frm(frm, pktns, ctx);
		LIST_DEL(&pkt->list);
		if (!oldest_lost) {
			oldest_lost = newest_lost = pkt;
		}
		else {
			if (newest_lost != oldest_lost)
				pool_free(pool_head_quic_tx_packet, newest_lost);
			newest_lost = pkt;
		}
	}

	if (lost_bytes) {
		/* Sent a packet loss event to the congestion controller. */
		qc_cc_loss_event(ctx->conn->qc, lost_bytes, newest_lost->time_sent,
		                 newest_lost->time_sent - oldest_lost->time_sent, now_us);
		pool_free(pool_head_quic_tx_packet, oldest_lost);
		if (newest_lost != oldest_lost)
			pool_free(pool_head_quic_tx_packet, newest_lost);
	}
}

/* Look for packet loss from sent packets for <qel> encryption level of a
 * connection with <ctx> as I/O handler context. If remove is true, remove them from
 * their tree if deemed as lost or set the <loss_time> value the packet number
 * space if any not deemed lost.
 * Should be called after having received an ACK frame with newly acknowledged
 * packets or when the the loss detection timer has expired.
 * Always succeeds.
 */
static void qc_packet_loss_lookup(struct quic_pktns *pktns,
                                  struct quic_conn *qc,
                                  struct list *lost_pkts)
{
	struct eb_root *pkts;
	struct eb64_node *node;
	struct quic_loss *ql;
	unsigned int loss_delay;

	TRACE_ENTER(QUIC_EV_CONN_PKTLOSS, qc->conn, pktns);
	pkts = &pktns->tx.pkts;
	pktns->tx.loss_time = TICK_ETERNITY;
	if (eb_is_empty(pkts))
		goto out;

	ql = &qc->path->loss;
	loss_delay = QUIC_MAX(ql->latest_rtt, ql->srtt >> 3);
	loss_delay += loss_delay >> 3;
	loss_delay = QUIC_MAX(loss_delay, MS_TO_TICKS(QUIC_TIMER_GRANULARITY));

	node = eb64_first(pkts);
	while (node) {
		struct quic_tx_packet *pkt;
		int64_t largest_acked_pn;
		unsigned int loss_time_limit, time_sent;

		pkt = eb64_entry(&node->node, struct quic_tx_packet, pn_node);
		largest_acked_pn = pktns->tx.largest_acked_pn;
		node = eb64_next(node);
		if ((int64_t)pkt->pn_node.key > largest_acked_pn)
			break;

		time_sent = pkt->time_sent;
		loss_time_limit = tick_add(time_sent, loss_delay);
		if (tick_is_le(time_sent, now_ms) ||
			(int64_t)largest_acked_pn >= pkt->pn_node.key + QUIC_LOSS_PACKET_THRESHOLD) {
			eb64_delete(&pkt->pn_node);
			LIST_ADDQ(lost_pkts, &pkt->list);
		}
		else {
			pktns->tx.loss_time = tick_first(pktns->tx.loss_time, loss_time_limit);
		}
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_PKTLOSS, qc->conn, pktns, lost_pkts);
}

/* Parse ACK frame into <frm> from a buffer at <buf> address with <end> being at
 * one byte past the end of this buffer. Also update <rtt_sample> if needed, i.e.
 * if the largest acked packet was newly acked and if there was at least one newly
 * acked ack-eliciting packet.
 * Return 1, if succeeded, 0 if not.
 */
static inline int qc_parse_ack_frm(struct quic_frame *frm, struct quic_conn_ctx *ctx,
                                   struct quic_enc_level *qel,
                                   unsigned int *rtt_sample,
                                   const unsigned char **pos, const unsigned char *end)
{
	struct quic_ack *ack = &frm->ack;
	uint64_t smallest, largest;
	struct eb_root *pkts;
	struct eb64_node *largest_node;
	unsigned int time_sent, pkt_flags;
	struct list newly_acked_pkts = LIST_HEAD_INIT(newly_acked_pkts);
	struct list lost_pkts = LIST_HEAD_INIT(lost_pkts);

	if (ack->largest_ack > qel->pktns->tx.next_pn) {
		TRACE_DEVEL("ACK for not sent packet", QUIC_EV_CONN_PRSAFRM,
		            ctx->conn,, &ack->largest_ack);
		goto err;
	}

	if (ack->first_ack_range > ack->largest_ack) {
		TRACE_DEVEL("too big first ACK range", QUIC_EV_CONN_PRSAFRM,
		            ctx->conn,, &ack->first_ack_range);
		goto err;
	}

	largest = ack->largest_ack;
	smallest = largest - ack->first_ack_range;
	pkts = &qel->pktns->tx.pkts;
	pkt_flags = 0;
	largest_node = NULL;
	time_sent = 0;

	if ((int64_t)ack->largest_ack > qel->pktns->tx.largest_acked_pn) {
		largest_node = eb64_lookup(pkts, largest);
		if (!largest_node) {
			TRACE_DEVEL("Largest acked packet not found",
			            QUIC_EV_CONN_PRSAFRM, ctx->conn);
			goto err;
		}

		time_sent = eb64_entry(&largest_node->node,
		                       struct quic_tx_packet, pn_node)->time_sent;
	}

	TRACE_PROTO("ack range", QUIC_EV_CONN_PRSAFRM,
	            ctx->conn,, &largest, &smallest);
	do {
		uint64_t gap, ack_range;

		qc_ackrng_pkts(pkts, &pkt_flags, &newly_acked_pkts,
		               largest_node, largest, smallest, ctx);
		if (!ack->ack_range_num--)
			break;

		if (!quic_dec_int(&gap, pos, end))
			goto err;

		if (smallest < gap + 2) {
			TRACE_DEVEL("wrong gap value", QUIC_EV_CONN_PRSAFRM,
			            ctx->conn,, &gap, &smallest);
			goto err;
		}

		largest = smallest - gap - 2;
		if (!quic_dec_int(&ack_range, pos, end))
			goto err;

		if (largest < ack_range) {
			TRACE_DEVEL("wrong ack range value", QUIC_EV_CONN_PRSAFRM,
			            ctx->conn,, &largest, &ack_range);
			goto err;
		}

		/* Do not use this node anymore. */
		largest_node = NULL;
		/* Next range */
		smallest = largest - ack_range;

		TRACE_PROTO("ack range", QUIC_EV_CONN_PRSAFRM,
		            ctx->conn,, &largest, &smallest);
	} while (1);

	/* Flag this packet number space as having received an ACK. */
	qel->pktns->flags |= QUIC_FL_PKTNS_ACK_RECEIVED;

	if (time_sent && (pkt_flags & QUIC_FL_TX_PACKET_ACK_ELICITING)) {
		*rtt_sample = tick_remain(time_sent, now_ms);
		qel->pktns->tx.largest_acked_pn = ack->largest_ack;
	}

	if (!LIST_ISEMPTY(&newly_acked_pkts)) {
		if (!eb_is_empty(&qel->pktns->tx.pkts)) {
			qc_packet_loss_lookup(qel->pktns, ctx->conn->qc, &lost_pkts);
			if (!LIST_ISEMPTY(&lost_pkts))
				qc_release_lost_pkts(qel->pktns, ctx, &lost_pkts, now_ms);
		}
		qc_treat_newly_acked_pkts(ctx, &newly_acked_pkts);
		if (quic_peer_validated_addr(ctx))
			ctx->conn->qc->path->loss.pto_count = 0;
		qc_set_timer(ctx);
	}


	return 1;

 err:
	free_quic_tx_pkts(&newly_acked_pkts);
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_PRSAFRM, ctx->conn);
	return 0;
}

/* Provide CRYPTO data to the TLS stack found at <data> with <len> as length
 * from <qel> encryption level with <ctx> as QUIC connection context.
 * Remaining parameter are there for debugging purposes.
 * Return 1 if succeeded, 0 if not.
 */
static inline int qc_provide_cdata(struct quic_enc_level *el,
                                   struct quic_conn_ctx *ctx,
                                   const unsigned char *data, size_t len,
                                   struct quic_rx_packet *pkt,
                                   struct quic_rx_crypto_frm *cf)
{
	int ssl_err;

	TRACE_ENTER(QUIC_EV_CONN_SSLDATA, ctx->conn);
	ssl_err = SSL_ERROR_NONE;
	if (SSL_provide_quic_data(ctx->ssl, el->level, data, len) != 1) {
		TRACE_PROTO("SSL_provide_quic_data() error",
		            QUIC_EV_CONN_SSLDATA, ctx->conn, pkt, cf, ctx->ssl);
		goto err;
	}

	el->rx.crypto.offset += len;
	TRACE_PROTO("in order CRYPTO data",
	            QUIC_EV_CONN_SSLDATA, ctx->conn,, cf, ctx->ssl);

	if (ctx->state < QUIC_HS_ST_COMPLETE) {
		ssl_err = SSL_do_handshake(ctx->ssl);
		if (ssl_err != 1) {
			ssl_err = SSL_get_error(ctx->ssl, ssl_err);
			if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
				TRACE_PROTO("SSL handshake",
				            QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state, &ssl_err);
				goto out;
			}

			TRACE_DEVEL("SSL handshake error",
			            QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state, &ssl_err);
			goto err;
		}

		TRACE_PROTO("SSL handshake OK", QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state);
		if (objt_listener(ctx->conn->target))
			ctx->state = QUIC_HS_ST_CONFIRMED;
		else
			ctx->state = QUIC_HS_ST_COMPLETE;
	} else {
		ssl_err = SSL_process_quic_post_handshake(ctx->ssl);
		if (ssl_err != 1) {
			ssl_err = SSL_get_error(ctx->ssl, ssl_err);
			if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
				TRACE_DEVEL("SSL post handshake",
				            QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state, &ssl_err);
				goto out;
			}

			TRACE_DEVEL("SSL post handshake error",
			            QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state, &ssl_err);
			goto err;
		}

		TRACE_PROTO("SSL post handshake succeeded",
		            QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state);
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_SSLDATA, ctx->conn);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_SSLDATA, ctx->conn);
	return 0;
}

/* Parse all the frames of <pkt> QUIC packet for QUIC connection with <ctx>
 * as I/O handler context and <qel> as encryption level.
 * Returns 1 if succeeded, 0 if failed.
 */
static int qc_parse_pkt_frms(struct quic_rx_packet *pkt, struct quic_conn_ctx *ctx,
                             struct quic_enc_level *qel)
{
	struct quic_frame frm;
	const unsigned char *pos, *end;
	struct quic_conn *conn = ctx->conn->qc;

	TRACE_ENTER(QUIC_EV_CONN_PRSHPKT, ctx->conn);
	/* Skip the AAD */
	pos = pkt->data + pkt->aad_len;
	end = pkt->data + pkt->len;

	while (pos < end) {
		if (!qc_parse_frm(&frm, pkt, &pos, end, conn))
			goto err;

		switch (frm.type) {
		case QUIC_FT_PADDING:
			if (pos != end) {
				TRACE_DEVEL("wrong frame", QUIC_EV_CONN_PRSHPKT, ctx->conn, pkt);
				goto err;
			}
			break;
		case QUIC_FT_PING:
			break;
		case QUIC_FT_ACK:
		{
			unsigned int rtt_sample;

			rtt_sample = 0;
			if (!qc_parse_ack_frm(&frm, ctx, qel, &rtt_sample, &pos, end))
				goto err;

			if (rtt_sample) {
				unsigned int ack_delay;

				ack_delay = !quic_application_pktns(qel->pktns, conn) ? 0 :
					MS_TO_TICKS(QUIC_MIN(quic_ack_delay_ms(&frm.ack, conn), conn->max_ack_delay));
				quic_loss_srtt_update(&conn->path->loss, rtt_sample, ack_delay, conn);
			}
			tasklet_wakeup(ctx->wait_event.tasklet);
			break;
		}
		case QUIC_FT_CRYPTO:
			if (frm.crypto.offset != qel->rx.crypto.offset) {
				struct quic_rx_crypto_frm *cf;

				cf = pool_alloc(pool_head_quic_rx_crypto_frm);
				if (!cf) {
					TRACE_DEVEL("CRYPTO frame allocation failed",
					            QUIC_EV_CONN_PRSHPKT, ctx->conn);
					goto err;
				}

				cf->offset_node.key = frm.crypto.offset;
				cf->len = frm.crypto.len;
				cf->data = frm.crypto.data;
				cf->pkt = pkt;
				eb64_insert(&qel->rx.crypto.frms, &cf->offset_node);
				quic_rx_packet_refinc(pkt);
			}
			else {
				/* XXX TO DO: <cf> is used only for the traces. */
				struct quic_rx_crypto_frm cf = { };

				cf.offset_node.key = frm.crypto.offset;
				cf.len = frm.crypto.len;
				if (!qc_provide_cdata(qel, ctx,
				                      frm.crypto.data, frm.crypto.len,
				                      pkt, &cf))
					goto err;
			}
			break;
		case QUIC_FT_STREAM_8:
		case QUIC_FT_STREAM_9:
		case QUIC_FT_STREAM_A:
		case QUIC_FT_STREAM_B:
		case QUIC_FT_STREAM_C:
		case QUIC_FT_STREAM_D:
		case QUIC_FT_STREAM_E:
		case QUIC_FT_STREAM_F:
		{
			struct quic_stream *stream = &frm.stream;

			TRACE_PROTO("STREAM frame", QUIC_EV_CONN_PSTRM, ctx->conn, &frm);
			if (objt_listener(ctx->conn->target)) {
				if (stream->id & QUIC_STREAM_FRAME_ID_INITIATOR_BIT)
					goto err;
			} else if (!(stream->id & QUIC_STREAM_FRAME_ID_INITIATOR_BIT))
				goto err;
			break;
		}
		case QUIC_FT_NEW_CONNECTION_ID:
			break;
		case QUIC_FT_CONNECTION_CLOSE:
		case QUIC_FT_CONNECTION_CLOSE_APP:
			break;
		case QUIC_FT_HANDSHAKE_DONE:
			if (objt_listener(ctx->conn->target))
				goto err;

			ctx->state = QUIC_HS_ST_CONFIRMED;
			break;
		default:
			goto err;
		}
	}

	/* The server must switch from INITIAL to HANDSHAKE handshake state when it
	 * has successfully parse a Handshake packet. The Initial encryption must also
	 * be discarded.
	 */
	if (ctx->state == QUIC_HS_ST_SERVER_INITIAL &&
	    pkt->type == QUIC_PACKET_TYPE_HANDSHAKE) {
		quic_tls_discard_keys(&conn->els[QUIC_TLS_ENC_LEVEL_INITIAL]);
		quic_pktns_discard(conn->els[QUIC_TLS_ENC_LEVEL_INITIAL].pktns, conn);
		qc_set_timer(ctx);
		ctx->state = QUIC_HS_ST_SERVER_HANDSHAKE;
	}

	TRACE_LEAVE(QUIC_EV_CONN_PRSHPKT, ctx->conn);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_PRSHPKT, ctx->conn);
	return 0;
}

/* Prepare as much as possible handshake packets for the QUIC connection
 * with <ctx> as I/O handler context.
 * Returns 1 if succeeded, or 0 if something wrong happened.
 */
static int qc_prep_hdshk_pkts(struct quic_conn_ctx *ctx)
{
	struct quic_conn *qc;
	enum quic_tls_enc_level tel, next_tel;
	struct quic_enc_level *qel;
	struct q_buf *wbuf;
	/* A boolean to flag <wbuf> as reusable, even if not empty. */
	int reuse_wbuf;

	TRACE_ENTER(QUIC_EV_CONN_PHPKTS, ctx->conn);
	qc = ctx->conn->qc;
	if (!quic_get_tls_enc_levels(&tel, &next_tel, ctx->state)) {
		TRACE_DEVEL("unknown enc. levels",
		            QUIC_EV_CONN_PHPKTS, ctx->conn);
		goto err;
	}

	reuse_wbuf = 0;
	wbuf = q_wbuf(qc);
	qel = &qc->els[tel];
	/* When entering this function, the writter buffer must be empty.
	 * Most of the time it points to the reader buffer.
	 */
	while ((q_buf_empty(wbuf) || reuse_wbuf)) {
		ssize_t ret;
		enum quic_pkt_type pkt_type;

		TRACE_POINT(QUIC_EV_CONN_PHPKTS, ctx->conn, qel);
		/* Do not build any more packet f the TX secrets are not available or
		 * f there is nothing to send, i.e. if no ACK are required
		 * and if there is no more packets to send upon PTO expiration
		 * and if there is no more CRYPTO data available or in flight
		 * congestion control limit is reached for prepared data
		 */
		if (!(qel->tls_ctx.tx.flags & QUIC_FL_TLS_SECRETS_SET) ||
		    (!(qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) &&
		    !qc->tx.nb_pto_dgrams &&
		    (LIST_ISEMPTY(&qel->pktns->tx.frms) ||
		     qc->path->prep_in_flight >= qc->path->cwnd))) {
			TRACE_DEVEL("nothing more to do", QUIC_EV_CONN_PHPKTS, ctx->conn);
			/* Consume the buffer if we were supposed to reuse it. */
			if (reuse_wbuf)
					wbuf = q_next_wbuf(qc);
			break;
		}

		pkt_type = quic_tls_level_pkt_type(tel);
		ret = qc_build_hdshk_pkt(wbuf, qc, pkt_type, qel);
		switch (ret) {
		case -2:
			goto err;
		case -1:
			if (!reuse_wbuf)
				goto out;

			/* Not enough room in <wbuf>. */
			wbuf = q_next_wbuf(qc);
			reuse_wbuf = 0;
			continue;
		case 0:
			goto out;
		default:
			reuse_wbuf = 0;
			/* Discard the Initial encryption keys as soon as
			 * a handshake packet could be built.
			 */
			if (ctx->state == QUIC_HS_ST_CLIENT_INITIAL &&
			    pkt_type == QUIC_PACKET_TYPE_HANDSHAKE) {
				quic_tls_discard_keys(&qc->els[QUIC_TLS_ENC_LEVEL_INITIAL]);
				quic_pktns_discard(qc->els[QUIC_TLS_ENC_LEVEL_INITIAL].pktns, qc);
				qc_set_timer(ctx);
				ctx->state = QUIC_HS_ST_CLIENT_HANDSHAKE;
			}
			/* Special case for Initial packets: when they have all
			 * been sent, select the next level.
			 */
			if ((LIST_ISEMPTY(&qel->pktns->tx.frms) || qc->els[next_tel].pktns->tx.in_flight) &&
			    tel == QUIC_TLS_ENC_LEVEL_INITIAL) {
				tel = next_tel;
				qel = &qc->els[tel];
				if (LIST_ISEMPTY(&qel->pktns->tx.frms)) {
					/* If there is no more data for the next level, let's
					 * consume a buffer. This is the case for a client
					 * which sends only one Initial packet, then wait
					 * for additional CRYPTO data from the server to enter the
					 * next level.
					 */
					wbuf = q_next_wbuf(qc);
				}
				else {
					/* Let's try to reuse this buffer. */
					reuse_wbuf = 1;
				}
			}
			else {
				wbuf = q_next_wbuf(qc);
			}
		}
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_PHPKTS, ctx->conn);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_PHPKTS, ctx->conn);
	return 0;
}

/* Send the QUIC packets which have been prepared for QUIC connections
 * with <ctx> as I/O handler context.
 */
int qc_send_ppkts(struct quic_conn_ctx *ctx)
{
	struct quic_conn *qc;
	struct buffer tmpbuf = { };
	struct q_buf *rbuf;

	qc = ctx->conn->qc;
	for (rbuf = q_rbuf(qc); !q_buf_empty(rbuf) ; rbuf = q_next_rbuf(qc)) {
		struct quic_tx_packet *p, *q;
		unsigned int time_sent;

		tmpbuf.area = (char *)rbuf->area;
		tmpbuf.size = tmpbuf.data = rbuf->data;
		TRACE_PROTO("to send", QUIC_EV_CONN_SPPKTS, ctx->conn);
	    if (ctx->xprt->snd_buf(qc->conn, qc->conn->xprt_ctx,
	                           &tmpbuf, tmpbuf.data, 0) <= 0)
		    break;

		qc->tx.bytes += tmpbuf.data;
		time_sent = now_ms;
		/* Reset this buffer to make it available for the next packet to prepare. */
		q_buf_reset(rbuf);
		/* Remove from <rbuf> the packets which have just been sent. */
		list_for_each_entry_safe(p, q, &rbuf->pkts, list) {
			p->time_sent = time_sent;
			if (p->flags & QUIC_FL_TX_PACKET_ACK_ELICITING) {
				p->pktns->tx.time_of_last_eliciting = time_sent;
				qc->path->ifae_pkts++;
			}
			qc->path->in_flight += p->in_flight_len;
			p->pktns->tx.in_flight += p->in_flight_len;
			if (p->in_flight_len)
				qc_set_timer(ctx);
			TRACE_PROTO("sent pkt", QUIC_EV_CONN_SPPKTS, ctx->conn, p);
			LIST_DEL(&p->list);
		}
	}

	return 1;
}

/* Build all the frames which must be sent just after the handshake have succeeded.
 * This is essentially NEW_CONNECTION_ID frames. A QUIC server must also send
 * a HANDSHAKE_DONE frame.
 * Return 1 if succeeded, 0 if not.
 */
static int quic_build_post_handshake_frames(struct quic_conn *conn)
{
	int i;
	struct quic_frame *frm;

	/* Only servers must send a HANDSHAKE_DONE frame. */
	if (!objt_server(conn->conn->target)) {
		frm = pool_alloc(pool_head_quic_frame);
		if (!frm)
			return 0;

		frm->type = QUIC_FT_HANDSHAKE_DONE;
		LIST_ADDQ(&conn->tx.frms_to_send, &frm->list);
	}

	for (i = 1; i < conn->rx_tps.active_connection_id_limit; i++) {
		struct quic_connection_id *cid;

		frm = pool_alloc(pool_head_quic_frame);
		cid = new_quic_cid(&conn->cids, i);
		if (!frm || !cid)
			goto err;

		quic_connection_id_to_frm_cpy(frm, cid);
		LIST_ADDQ(&conn->tx.frms_to_send, &frm->list);
	}

    return 1;

 err:
	free_quic_conn_cids(conn);
	return 0;
}

/* Deallocate <l> list of ACK ranges. */
void free_quic_arngs(struct quic_arngs *arngs)
{
	struct eb64_node *n;
	struct quic_arng_node *ar;

	n = eb64_first(&arngs->root);
	while (n) {
		struct eb64_node *next;

		ar = eb64_entry(&n->node, struct quic_arng_node, first);
		next = eb64_next(n);
		eb64_delete(n);
		free(ar);
		n = next;
	}
}

/* Return the gap value between <p> and <q> ACK ranges where <q> follows <p> in
 * descending order.
 */
static inline size_t sack_gap(struct quic_arng_node *p,
                              struct quic_arng_node *q)
{
	return p->first.key - q->last - 2;
}


/* Remove the last elements of <ack_ranges> list of ack range updating its
 * encoded size until it goes below <limit>.
 * Returns 1 if succeeded, 0 if not (no more element to remove).
 */
static int quic_rm_last_ack_ranges(struct quic_arngs *arngs, size_t limit)
{
	struct eb64_node *last, *prev;

	last = eb64_last(&arngs->root);
	while (last && arngs->enc_sz > limit) {
		struct quic_arng_node *last_node, *prev_node;

		prev = eb64_prev(last);
		if (!prev)
			return 0;

		last_node = eb64_entry(&last->node, struct quic_arng_node, first);
		prev_node = eb64_entry(&prev->node, struct quic_arng_node, first);
		arngs->enc_sz -= quic_int_getsize(last_node->last - last_node->first.key);
		arngs->enc_sz -= quic_int_getsize(sack_gap(prev_node, last_node));
		arngs->enc_sz -= quic_decint_size_diff(arngs->sz);
		--arngs->sz;
		eb64_delete(last);
		pool_free(pool_head_quic_arng, last);
		last = prev;
	}

	return 1;
}

/* Set the encoded size of <arngs> QUIC ack ranges. */
static void quic_arngs_set_enc_sz(struct quic_arngs *arngs)
{
	struct eb64_node *node, *next;
	struct quic_arng_node *ar, *ar_next;

	node = eb64_last(&arngs->root);
	if (!node)
		return;

	ar = eb64_entry(&node->node, struct quic_arng_node, first);
	arngs->enc_sz = quic_int_getsize(ar->last) +
		quic_int_getsize(ar->last - ar->first.key) + quic_int_getsize(arngs->sz - 1);

	while ((next = eb64_prev(node))) {
		ar_next = eb64_entry(&next->node, struct quic_arng_node, first);
		arngs->enc_sz += quic_int_getsize(sack_gap(ar, ar_next)) +
			quic_int_getsize(ar_next->last - ar_next->first.key);
		node = next;
		ar = eb64_entry(&node->node, struct quic_arng_node, first);
	}
}

/* Insert in <root> ebtree <node> node with <ar> as range value.
 * Returns the ebtree node which has been inserted.
 */
static inline
struct eb64_node *quic_insert_new_range(struct eb_root *root,
                                        struct quic_arng_node *node,
                                        struct quic_arng *ar)
{
	node->first.key = ar->first;
	node->last = ar->last;
	return eb64_insert(root, &node->first);
}

/* Update <arngs> tree of ACK ranges with <ar> as new ACK range value.
 * Note that this function computes the number of bytes required to encode
 * this tree of ACK ranges in descending order.
 *
 *    Descending order
 *    ------------->
 *                range1                  range2
 *    ..........|--------|..............|--------|
 *              ^        ^              ^        ^
 *              |        |              |        |
 *            last1     first1        last2    first2
 *    ..........+--------+--------------+--------+......
 *                 diff1       gap12       diff2
 *
 * To encode the previous list of ranges we must encode integers as follows in
 * descending order:
 *          enc(last2),enc(diff2),enc(gap12),enc(diff1)
 *  with diff1 = last1 - first1
 *       diff2 = last2 - first2
 *       gap12 = first1 - last2 - 2 (>= 0)
 *
 */
int quic_update_ack_ranges_list(struct quic_arngs *arngs,
                                struct quic_arng *ar)
{
	struct eb64_node *le;
	struct quic_arng_node *new_node;
	struct eb64_node *new;

	new = NULL;
	if (eb_is_empty(&arngs->root)) {
		/* First range insertion. */
		new_node = pool_alloc(pool_head_quic_arng);
		if (!new_node)
			return 0;

		quic_insert_new_range(&arngs->root, new_node, ar);
		/* Increment the size of these ranges. */
		arngs->sz++;
		goto out;
	}

	le = eb64_lookup_le(&arngs->root, ar->first);
	if (!le) {
		/* New insertion */
		new_node = pool_alloc(pool_head_quic_arng);
		if (!new_node)
			return 0;

		new = quic_insert_new_range(&arngs->root, new_node, ar);
		/* Increment the size of these ranges. */
		arngs->sz++;
	}
	else {
		struct quic_arng_node *le_ar =
			eb64_entry(&le->node, struct quic_arng_node, first);

		/* Already existing range */
		if (le_ar->first.key <= ar->first && le_ar->last >= ar->last)
			return 1;

		if (le_ar->last + 1 >= ar->first) {
			le_ar->last = ar->last;
			new = le;
			new_node = le_ar;
		}
		else {
			/* New insertion */
			new_node = pool_alloc(pool_head_quic_arng);
			if (!new_node)
				return 0;

			new = quic_insert_new_range(&arngs->root, new_node, ar);
			/* Increment the size of these ranges. */
			arngs->sz++;
		}
	}

	/* Verify that the new inserted node does not overlap the nodes
	 * which follow it.
	 */
	if (new) {
		uint64_t new_node_last;
		struct eb64_node *next;
		struct quic_arng_node *next_node;

		new_node_last = new_node->last;
		while ((next = eb64_next(new))) {
			next_node =
				eb64_entry(&next->node, struct quic_arng_node, first);
			if (new_node_last + 1 < next_node->first.key)
				break;

			if (next_node->last > new_node->last)
				new_node->last = next_node->last;
			eb64_delete(next);
			free(next_node);
			/* Decrement the size of these ranges. */
			arngs->sz--;
		}
	}

	quic_arngs_set_enc_sz(arngs);

 out:
	return 1;
}
/* Remove the header protection of packets at <el> encryption level.
 * Always succeeds.
 */
static inline void qc_rm_hp_pkts(struct quic_enc_level *el, struct quic_conn_ctx *ctx)
{
	struct quic_tls_ctx *tls_ctx;
	struct quic_rx_packet *pqpkt, *qqpkt;
	struct quic_enc_level *app_qel;

	TRACE_ENTER(QUIC_EV_CONN_ELRMHP, ctx->conn);
	app_qel = &ctx->conn->qc->els[QUIC_TLS_ENC_LEVEL_APP];
	/* A server must not process incoming 1-RTT packets before the handshake is complete. */
	if (el == app_qel && objt_listener(ctx->conn->target) && ctx->state < QUIC_HS_ST_COMPLETE) {
		TRACE_PROTO("hp not removed (handshake not completed)",
		            QUIC_EV_CONN_ELRMHP, ctx->conn);
		goto out;
	}
	tls_ctx = &el->tls_ctx;
	list_for_each_entry_safe(pqpkt, qqpkt, &el->rx.pqpkts, list) {
		if (!qc_do_rm_hp(pqpkt, tls_ctx, el->pktns->rx.largest_pn,
		                 pqpkt->data + pqpkt->pn_offset,
		                 pqpkt->data, pqpkt->data + pqpkt->len, ctx)) {
			TRACE_PROTO("hp removing error", QUIC_EV_CONN_ELRMHP, ctx->conn);
			/* XXX TO DO XXX */
		}
		else {
			/* The AAD includes the packet number field */
			pqpkt->aad_len = pqpkt->pn_offset + pqpkt->pnl;
			/* Store the packet into the tree of packets to decrypt. */
			pqpkt->pn_node.key = pqpkt->pn;
			quic_rx_packet_eb64_insert(&el->rx.pkts, &pqpkt->pn_node);
			TRACE_PROTO("hp removed", QUIC_EV_CONN_ELRMHP, ctx->conn, pqpkt);
		}
		quic_rx_packet_list_del(pqpkt);
	}

  out:
	TRACE_LEAVE(QUIC_EV_CONN_ELRMHP, ctx->conn);
}

/* Process all the CRYPTO frame at <el> encryption level.
 * Return 1 if succeeded, 0 if not.
 */
static inline int qc_treat_rx_crypto_frms(struct quic_enc_level *el,
                                          struct quic_conn_ctx *ctx)
{
	struct eb64_node *node;

	TRACE_ENTER(QUIC_EV_CONN_RXCDATA, ctx->conn);
	node = eb64_first(&el->rx.crypto.frms);
	while (node) {
		struct quic_rx_crypto_frm *cf;

		cf = eb64_entry(&node->node, struct quic_rx_crypto_frm, offset_node);
		if (cf->offset_node.key != el->rx.crypto.offset)
			break;

		if (!qc_provide_cdata(el, ctx, cf->data, cf->len, cf->pkt, cf))
			goto err;

		node = eb64_next(node);
		quic_rx_packet_refdec(cf->pkt);
		eb64_delete(&cf->offset_node);
		pool_free(pool_head_quic_rx_crypto_frm, cf);
	}

	TRACE_LEAVE(QUIC_EV_CONN_RXCDATA, ctx->conn);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_RXCDATA, ctx->conn);
	return 0;
}

/* Process all the packets at <el> encryption level.
 * Return 1 if succeeded, 0 if not.
 */
int qc_treat_rx_pkts(struct quic_enc_level *el, struct quic_conn_ctx *ctx)
{
	struct quic_tls_ctx *tls_ctx;
	struct eb64_node *node;

	TRACE_ENTER(QUIC_EV_CONN_ELRXPKTS, ctx->conn);
	tls_ctx = &el->tls_ctx;
	node = eb64_first(&el->rx.pkts);
	while (node) {
		struct quic_rx_packet *pkt;

		pkt = eb64_entry(&node->node, struct quic_rx_packet, pn_node);
		if (!qc_pkt_decrypt(pkt, tls_ctx)) {
			/* Drop the packet */
			TRACE_PROTO("packet decryption failed -> dropped",
			            QUIC_EV_CONN_ELRXPKTS, ctx->conn, pkt);
		}
		else {
			int drop;

			drop = 0;
			if (!qc_parse_pkt_frms(pkt, ctx, el))
				drop = 1;

			if (drop) {
				/* Drop the packet */
				TRACE_PROTO("packet parsing failed -> dropped",
				            QUIC_EV_CONN_ELRXPKTS, ctx->conn, pkt);
			}
			else {
				struct quic_arng ar = { .first = pkt->pn, .last = pkt->pn };

				if (pkt->flags & QUIC_FL_RX_PACKET_ACK_ELICITING) {
					el->pktns->rx.nb_ack_eliciting++;
					if (!(el->pktns->rx.nb_ack_eliciting & 1))
						el->pktns->flags |= QUIC_FL_PKTNS_ACK_REQUIRED;
				}

				/* Update the largest packet number. */
				if (pkt->pn > el->pktns->rx.largest_pn)
					el->pktns->rx.largest_pn = pkt->pn;

				/* Update the list of ranges to acknowledge. */
				if (!quic_update_ack_ranges_list(&el->pktns->rx.arngs, &ar)) {
					TRACE_DEVEL("Could not update ack range list",
					            QUIC_EV_CONN_ELRXPKTS, ctx->conn);
					node = eb64_next(node);
					quic_rx_packet_eb64_delete(&pkt->pn_node);
					free_quic_rx_packet(pkt);
					goto err;
				}

			}
		}
		node = eb64_next(node);
		quic_rx_packet_eb64_delete(&pkt->pn_node);
		free_quic_rx_packet(pkt);
	}

	if (!qc_treat_rx_crypto_frms(el, ctx))
		goto err;

	TRACE_LEAVE(QUIC_EV_CONN_ELRXPKTS, ctx->conn);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_ELRXPKTS, ctx->conn);
	return 0;
}

/* Called during handshakes to parse and build Initial and Handshake packets for QUIC
 * connections with <ctx> as I/O handler context.
 * Returns 1 if succeeded, 0 if not.
 */
int qc_do_hdshk(struct quic_conn_ctx *ctx)
{
	int ssl_err;
	struct quic_conn *quic_conn;
	enum quic_tls_enc_level tel, next_tel;
	struct quic_enc_level *qel, *next_qel;
	struct quic_tls_ctx *tls_ctx;

	TRACE_ENTER(QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state);

	ssl_err = SSL_ERROR_NONE;
	quic_conn = ctx->conn->qc;
	if (!quic_get_tls_enc_levels(&tel, &next_tel, ctx->state))
		goto err;

	qel = &quic_conn->els[tel];
	next_qel = &quic_conn->els[next_tel];

 next_level:
	tls_ctx = &qel->tls_ctx;

	/* If the header protection key for this level has been derived,
	 * remove the packet header protections.
	 */
	if (!LIST_ISEMPTY(&qel->rx.pqpkts) &&
	    (tls_ctx->rx.flags & QUIC_FL_TLS_SECRETS_SET))
		qc_rm_hp_pkts(qel, ctx);

	if (!eb_is_empty(&qel->rx.pkts) &&
		!qc_treat_rx_pkts(qel, ctx))
		goto err;

	if (!qc_prep_hdshk_pkts(ctx))
		goto err;

	if (!qc_send_ppkts(ctx))
		goto err;

	/* Check if there is something to do for the next level.
	 */
	if ((next_qel->tls_ctx.rx.flags & QUIC_FL_TLS_SECRETS_SET) &&
	    (!LIST_ISEMPTY(&next_qel->rx.pqpkts) || !eb_is_empty(&next_qel->rx.pkts))) {
		qel = next_qel;
		goto next_level;
	}

	/* If the handshake has not been completed -> out! */
	if (ctx->state < QUIC_HS_ST_COMPLETE)
		goto out;

	/* Discard the Handshake keys. */
	quic_tls_discard_keys(&quic_conn->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE]);
	quic_pktns_discard(quic_conn->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE].pktns, quic_conn);
	qc_set_timer(ctx);
	if (!quic_build_post_handshake_frames(quic_conn) ||
	    !qc_prep_phdshk_pkts(quic_conn) ||
	    !qc_send_ppkts(ctx))
		goto err;

 out:
	TRACE_LEAVE(QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state, &ssl_err);
	return 0;
}

/* Allocate a new QUIC connection and return it if succeeded, NULL if not. */
struct quic_conn *new_quic_conn(uint32_t version)
{
	struct quic_conn *quic_conn;

	quic_conn = pool_alloc(pool_head_quic_conn);
	if (quic_conn) {
		memset(quic_conn, 0, sizeof *quic_conn);
		quic_conn->version = version;
	}

	return quic_conn;
}

/* Uninitialize <qel> QUIC encryption level. Never fails. */
static void quic_conn_enc_level_uninit(struct quic_enc_level *qel)
{
	int i;

	for (i = 0; i < qel->tx.crypto.nb_buf; i++) {
		if (qel->tx.crypto.bufs[i]) {
			pool_free(pool_head_quic_crypto_buf, qel->tx.crypto.bufs[i]);
			qel->tx.crypto.bufs[i] = NULL;
		}
	}
	free(qel->tx.crypto.bufs);
	qel->tx.crypto.bufs = NULL;
}

/* Initialize QUIC TLS encryption level with <level<> as level for <qc> QUIC
 * connection allocating everything needed.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_conn_enc_level_init(struct quic_conn *qc,
                                    enum quic_tls_enc_level level)
{
	struct quic_enc_level *qel;

	qel = &qc->els[level];
	qel->level = quic_to_ssl_enc_level(level);
	qel->tls_ctx.rx.aead = qel->tls_ctx.tx.aead = NULL;
	qel->tls_ctx.rx.md   = qel->tls_ctx.tx.md = NULL;
	qel->tls_ctx.rx.hp   = qel->tls_ctx.tx.hp = NULL;
	qel->tls_ctx.rx.flags = 0;
	qel->tls_ctx.tx.flags = 0;

	qel->rx.pkts = EB_ROOT;
	LIST_INIT(&qel->rx.pqpkts);

	/* Allocate only one buffer. */
	qel->tx.crypto.bufs = malloc(sizeof *qel->tx.crypto.bufs);
	if (!qel->tx.crypto.bufs)
		goto err;

	qel->tx.crypto.bufs[0] = pool_alloc(pool_head_quic_crypto_buf);
	if (!qel->tx.crypto.bufs[0])
		goto err;

	qel->tx.crypto.bufs[0]->sz = 0;
	qel->tx.crypto.nb_buf = 1;

	qel->tx.crypto.sz = 0;
	qel->tx.crypto.offset = 0;

	return 1;

 err:
	free(qel->tx.crypto.bufs);
	qel->tx.crypto.bufs = NULL;
	return 0;
}

/* Release the memory allocated for <buf> array of buffers, with <nb> as size.
 * Never fails.
 */
static inline void free_quic_conn_tx_bufs(struct q_buf **bufs, size_t nb)
{
	struct q_buf **p;

	if (!bufs)
		return;

	p = bufs;
	while (--nb) {
		if (!*p) {
			p++;
			continue;
		}
		free((*p)->area);
		(*p)->area = NULL;
		free(*p);
		*p = NULL;
		p++;
	}
	free(bufs);
}

/* Allocate an array or <nb> buffers of <sz> bytes each.
 * Return this array if succeeded, NULL if failed.
 */
static inline struct q_buf **quic_conn_tx_bufs_alloc(size_t nb, size_t sz)
{
	int i;
	struct q_buf **bufs, **p;

	bufs = calloc(nb, sizeof *bufs);
	if (!bufs)
		return NULL;

	i = 0;
	p = bufs;
	while (i++ < nb) {
		*p = calloc(1, sizeof **p);
		if (!*p)
			goto err;

		(*p)->area = malloc(sz);
		if (!(*p)->area)
		    goto err;

		(*p)->pos = (*p)->area;
		(*p)->end = (*p)->area + sz;
		(*p)->data = 0;
		LIST_INIT(&(*p)->pkts);
		p++;
	}

	return bufs;

 err:
	free_quic_conn_tx_bufs(bufs, nb);
	return NULL;
}

/* Release all the memory allocated for <conn> QUIC connection. */
static void quic_conn_free(struct quic_conn *conn)
{
	int i;

	free_quic_conn_cids(conn);
	for (i = 0; i < QUIC_TLS_ENC_LEVEL_MAX; i++)
		quic_conn_enc_level_uninit(&conn->els[i]);
	free_quic_conn_tx_bufs(conn->tx.bufs, conn->tx.nb_buf);
	if (conn->timer_task)
		task_destroy(conn->timer_task);
	pool_free(pool_head_quic_conn, conn);
}

/* Callback called upon loss detection and PTO timer expirations. */
static struct task *process_timer(struct task *task, void *ctx, unsigned short state)
{
	struct quic_conn_ctx *conn_ctx;
	struct quic_conn *qc;
	struct quic_pktns *pktns;


	conn_ctx = task->context;
	qc = conn_ctx->conn->qc;
	TRACE_ENTER(QUIC_EV_CONN_PTIMER, conn_ctx->conn,
	            NULL, NULL, &qc->path->ifae_pkts);
	task->expire = TICK_ETERNITY;
	pktns = quic_loss_pktns(qc);
	if (tick_isset(pktns->tx.loss_time)) {
		struct list lost_pkts = LIST_HEAD_INIT(lost_pkts);

		qc_packet_loss_lookup(pktns, qc, &lost_pkts);
		if (!LIST_ISEMPTY(&lost_pkts))
			qc_release_lost_pkts(pktns, ctx, &lost_pkts, now_ms);
		qc_set_timer(conn_ctx);
		goto out;
	}

	if (qc->path->in_flight) {
		pktns = quic_pto_pktns(qc, conn_ctx->state >= QUIC_HS_ST_COMPLETE, NULL);
		pktns->tx.pto_probe = 1;
	}
	else if (objt_server(qc->conn->target) && conn_ctx->state <= QUIC_HS_ST_COMPLETE) {
		struct quic_enc_level *iel = &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL];
		struct quic_enc_level *hel = &qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE];

		if (hel->tls_ctx.rx.flags == QUIC_FL_TLS_SECRETS_SET)
			hel->pktns->tx.pto_probe = 1;
		if (iel->tls_ctx.rx.flags == QUIC_FL_TLS_SECRETS_SET)
			iel->pktns->tx.pto_probe = 1;
	}
	qc->tx.nb_pto_dgrams = QUIC_MAX_NB_PTO_DGRAMS;
	tasklet_wakeup(conn_ctx->wait_event.tasklet);
	qc->path->loss.pto_count++;

 out:
	TRACE_LEAVE(QUIC_EV_CONN_PTIMER, conn_ctx->conn, pktns);

	return task;
}

/* Initialize <conn> QUIC connection with <quic_initial_clients> as root of QUIC
 * connections used to identify the first Initial packets of client connecting
 * to listeners. This parameter must be NULL for QUIC connections attached
 * to listeners. <dcid> is the destination connection ID with <dcid_len> as length.
 * <scid> is the source connection ID with <scid_len> as length.
 * Returns 1 if succeeded, 0 if not.
 */
int qc_new_conn_init(struct quic_conn *qc, int ipv4,
                     struct eb_root *quic_initial_clients,
                     struct eb_root *quic_clients,
                     unsigned char *dcid, size_t dcid_len,
                     unsigned char *scid, size_t scid_len)
{
	int i;
	/* Initial CID. */
	struct quic_connection_id *icid;

	TRACE_ENTER(QUIC_EV_CONN_INIT, qc->conn);
	qc->cids = EB_ROOT;
	/* QUIC Server (or listener). */
	if (objt_listener(qc->conn->target)) {
		/* Copy the initial DCID. */
		qc->odcid.len = dcid_len;
		if (qc->odcid.len)
			memcpy(qc->odcid.data, dcid, dcid_len);

		/* Copy the SCID as our DCID for this connection. */
		if (scid_len)
			memcpy(qc->dcid.data, scid, scid_len);
		qc->dcid.len = scid_len;
	}
	/* QUIC Client (outgoing connection to servers) */
	else {
		if (dcid_len)
			memcpy(qc->dcid.data, dcid, dcid_len);
		qc->dcid.len = dcid_len;
	}

	/* Initialize the output buffer */
	qc->obuf.pos = qc->obuf.data;

	icid = new_quic_cid(&qc->cids, 0);
	if (!icid)
		return 0;

	/* Select our SCID which is the first CID with 0 as sequence number. */
	qc->scid = icid->cid;

	/* Insert the DCID the QUIC client has chosen (only for listeners) */
	if (objt_listener(qc->conn->target))
		ebmb_insert(quic_initial_clients, &qc->odcid_node, qc->odcid.len);

	/* Insert our SCID, the connection ID for the QUIC client. */
	ebmb_insert(quic_clients, &qc->scid_node, qc->scid.len);

	/* Packet number spaces initialization. */
	for (i = 0; i < QUIC_TLS_PKTNS_MAX; i++)
		quic_pktns_init(&qc->pktns[i]);
	/* QUIC encryption level context initialization. */
	for (i = 0; i < QUIC_TLS_ENC_LEVEL_MAX; i++) {
		if (!quic_conn_enc_level_init(qc, i))
			goto err;
		/* Initialize the packet number space. */
		qc->els[i].pktns = &qc->pktns[quic_tls_pktns(i)];
	}

	/* TX part. */
	LIST_INIT(&qc->tx.frms_to_send);
	qc->tx.bufs = quic_conn_tx_bufs_alloc(QUIC_CONN_TX_BUFS_NB, QUIC_CONN_TX_BUF_SZ);
	if (!qc->tx.bufs)
		goto err;

	qc->tx.nb_buf = QUIC_CONN_TX_BUFS_NB;
	qc->tx.wbuf = qc->tx.rbuf = 0;
	qc->tx.bytes = 0;
	qc->tx.nb_pto_dgrams = 0;
	/* RX part. */
	qc->rx.bytes = 0;

	/* XXX TO DO: Only one path at this time. */
	qc->path = &qc->paths[0];
	quic_path_init(qc->path, ipv4, default_quic_cc_algo, qc);

	TRACE_LEAVE(QUIC_EV_CONN_INIT, qc->conn);

	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_INIT, qc->conn);
	quic_conn_free(qc);
	return 0;
}

/* Initialize the timer task of <qc> QUIC connection.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_conn_init_timer(struct quic_conn *qc)
{
	qc->timer_task = task_new(MAX_THREADS_MASK);
	if (!qc->timer_task)
		return 0;

	qc->timer = TICK_ETERNITY;
	qc->timer_task->process = process_timer;
	qc->timer_task->context = qc->conn->xprt_ctx;

	return 1;
}

/* Parse into <pkt> a long header located at <*buf> buffer, <end> begin a pointer to the end
 * past one byte of this buffer.
 */
static inline int quic_packet_read_long_header(unsigned char **buf, const unsigned char *end,
                                               struct quic_rx_packet *pkt)
{
	unsigned char dcid_len, scid_len;

	/* Version */
	if (!quic_read_uint32(&pkt->version, (const unsigned char **)buf, end))
		return 0;

	if (!pkt->version) { /* XXX TO DO XXX Version negotiation packet */ };

	/* Destination Connection ID Length */
	dcid_len = *(*buf)++;
	/* We want to be sure we can read <dcid_len> bytes and one more for <scid_len> value */
	if (dcid_len > QUIC_CID_MAXLEN || end - *buf < dcid_len + 1)
		/* XXX MUST BE DROPPED */
		return 0;

	if (dcid_len) {
		/* Check that the length of this received DCID matches the CID lengths
		 * of our implementation for non Initials packets only.
		 */
		if (pkt->type != QUIC_PACKET_TYPE_INITIAL && dcid_len != QUIC_CID_LEN)
			return 0;

		memcpy(pkt->dcid.data, *buf, dcid_len);
	}

	pkt->dcid.len = dcid_len;
	*buf += dcid_len;

	/* Source Connection ID Length */
	scid_len = *(*buf)++;
	if (scid_len > QUIC_CID_MAXLEN || end - *buf < scid_len)
		/* XXX MUST BE DROPPED */
		return 0;

	if (scid_len)
		memcpy(pkt->scid.data, *buf, scid_len);
	pkt->scid.len = scid_len;
	*buf += scid_len;

	return 1;
}

/* Try to remove the header protecttion of <pkt> QUIC packet attached to <conn>
 * QUIC connection with <buf> as packet number field address, <end> a pointer to one
 * byte past the end of the buffer containing this packet and <beg> the address of
 * the packet first byte.
 * If succeeded, this function updates <*buf> to point to the next packet in the buffer.
 * Returns 1 if succeeded, 0 if not.
 */
static inline int qc_try_rm_hp(struct quic_rx_packet *pkt,
                               unsigned char **buf, unsigned char *beg,
                               const unsigned char *end,
                               struct quic_conn_ctx *ctx)
{
	unsigned char *pn = NULL; /* Packet number field */
	enum quic_tls_enc_level tel;
	struct quic_enc_level *qel;
	/* Only for traces. */
	struct quic_rx_packet *qpkt_trace;

	qpkt_trace = NULL;
	TRACE_ENTER(QUIC_EV_CONN_TRMHP, ctx->conn);
	/* The packet number is here. This is also the start minus
	 * QUIC_PACKET_PN_MAXLEN of the sample used to add/remove the header
	 * protection.
	 */
	pn = *buf;
	tel = quic_packet_type_enc_level(pkt->type);
	if (tel == QUIC_TLS_ENC_LEVEL_NONE) {
		TRACE_DEVEL("Wrong enc. level", QUIC_EV_CONN_TRMHP, ctx->conn);
		goto err;
	}

	qel = &ctx->conn->qc->els[tel];

	if (qel->tls_ctx.rx.flags & QUIC_FL_TLS_SECRETS_DCD) {
		TRACE_DEVEL("Discarded keys", QUIC_EV_CONN_TRMHP, ctx->conn);
		goto err;
	}

	if ((qel->tls_ctx.rx.flags & QUIC_FL_TLS_SECRETS_SET) &&
	    (tel != QUIC_TLS_ENC_LEVEL_APP || ctx->state >= QUIC_HS_ST_COMPLETE)) {
		 /* Note that the following function enables us to unprotect the packet
		 * number and its length subsequently used to decrypt the entire
		 * packets.
		 */
		if (!qc_do_rm_hp(pkt, &qel->tls_ctx,
		                 qel->pktns->rx.largest_pn, pn, beg, end, ctx)) {
			TRACE_PROTO("hp error", QUIC_EV_CONN_TRMHP, ctx->conn);
			goto err;
		}

		/* The AAD includes the packet number field found at <pn>. */
		pkt->aad_len = pn - beg + pkt->pnl;
		qpkt_trace = pkt;
		/* Store the packet */
		pkt->pn_node.key = pkt->pn;
		quic_rx_packet_eb64_insert(&qel->rx.pkts, &pkt->pn_node);
	}
	else {
		TRACE_PROTO("hp not removed", QUIC_EV_CONN_TRMHP, ctx->conn, pkt);
		pkt->pn_offset = pn - beg;
		quic_rx_packet_list_addq(&qel->rx.pqpkts, pkt);
	}

	memcpy(pkt->data, beg, pkt->len);
	/* Updtate the offset of <*buf> for the next QUIC packet. */
	*buf = beg + pkt->len;

	TRACE_LEAVE(QUIC_EV_CONN_TRMHP, ctx->conn, qpkt_trace);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_TRMHP, ctx->conn, qpkt_trace);
	return 0;
}

/* Parse the header form from <byte0> first byte of <pkt> pacekt to set type.
 * Also set <*long_header> to 1 if this form is long, 0 if not.
 */
static inline void qc_parse_hd_form(struct quic_rx_packet *pkt,
                                    unsigned char byte0, int *long_header)
{
	if (byte0 & QUIC_PACKET_LONG_HEADER_BIT) {
		pkt->type =
			(byte0 >> QUIC_PACKET_TYPE_SHIFT) & QUIC_PACKET_TYPE_BITMASK;
		*long_header = 1;
	}
	else {
		pkt->type = QUIC_PACKET_TYPE_SHORT;
		*long_header = 0;
	}
}

static ssize_t qc_srv_pkt_rcv(unsigned char **buf, const unsigned char *end,
                              struct quic_rx_packet *pkt,
                              struct quic_dgram_ctx *dgram_ctx,
                              struct sockaddr_storage *saddr)
{
	unsigned char *beg;
	uint64_t len;
	struct quic_conn *qc;
	struct eb_root *cids;
	struct ebmb_node *node;
	struct connection *srv_conn;
	struct quic_conn_ctx *conn_ctx;
	int long_header;

	qc = NULL;
	TRACE_ENTER(QUIC_EV_CONN_SPKT);
	if (end <= *buf)
		goto err;

	/* Fixed bit */
	if (!(**buf & QUIC_PACKET_FIXED_BIT))
		/* XXX TO BE DISCARDED */
		goto err;

	srv_conn = dgram_ctx->owner;
	beg = *buf;
	/* Header form */
	qc_parse_hd_form(pkt, *(*buf)++, &long_header);
	if (long_header) {
		size_t cid_lookup_len;

		if (!quic_packet_read_long_header(buf, end, pkt))
			goto err;

		/* For Initial packets, and for servers (QUIC clients connections),
		 * there is no Initial connection IDs storage.
		 */
		if (pkt->type == QUIC_PACKET_TYPE_INITIAL) {
			cids = &((struct server *)__objt_server(srv_conn->target))->cids;
			cid_lookup_len = pkt->dcid.len;
		}
		else {
			cids = &((struct server *)__objt_server(srv_conn->target))->cids;
			cid_lookup_len = QUIC_CID_LEN;
		}

		node = ebmb_lookup(cids, pkt->dcid.data, cid_lookup_len);
		if (!node)
			goto err;

		qc = ebmb_entry(node, struct quic_conn, scid_node);

		if (pkt->type == QUIC_PACKET_TYPE_INITIAL) {
			qc->dcid.len = pkt->scid.len;
			if (pkt->scid.len)
				memcpy(qc->dcid.data, pkt->scid.data, pkt->scid.len);
		}

		if (pkt->type == QUIC_PACKET_TYPE_INITIAL) {
			uint64_t token_len;

			if (!quic_dec_int(&token_len, (const unsigned char **)buf, end) || end - *buf < token_len)
				goto err;

			/* XXX TO DO XXX 0 value means "the token is not present".
			 * A server which sends an Initial packet must not set the token.
			 * So, a client which receives an Initial packet with a token
			 * MUST discard the packet or generate a connection error with
			 * PROTOCOL_VIOLATION as type.
			 * The token must be provided in a Retry packet or NEW_TOKEN frame.
			 */
			pkt->token_len = token_len;
		}
	}
	else {
		/* XXX TO DO: Short header XXX */
		if (end - *buf < QUIC_CID_LEN)
			goto err;

		cids = &((struct server *)__objt_server(srv_conn->target))->cids;
		node = ebmb_lookup(cids, *buf, QUIC_CID_LEN);
		if (!node)
			goto err;

		qc = ebmb_entry(node, struct quic_conn, scid_node);
		*buf += QUIC_CID_LEN;
	}
	/* Store the DCID used for this packet to check the packet which
	 * come in this UDP datagram match with it.
	 */
	if (!dgram_ctx->dcid_node)
		dgram_ctx->dcid_node = node;
	/* Only packets packets with long headers and not RETRY or VERSION as type
	 * have a length field.
	 */
	if (long_header && pkt->type != QUIC_PACKET_TYPE_RETRY && pkt->version) {
		if (!quic_dec_int(&len, (const unsigned char **)buf, end) || end - *buf < len)
			goto err;

		pkt->len = len;
	}
	else if (!long_header) {
		/* A short packet is the last one of an UDP datagram. */
		pkt->len = end - *buf;
	}

	conn_ctx = qc->conn->xprt_ctx;

	/* Increase the total length of this packet by the header length. */
	pkt->len += *buf - beg;
	/* Do not check the DCID node before the length. */
	if (dgram_ctx->dcid_node != node) {
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_SPKT, qc->conn);
		goto err;
	}

	if (pkt->len > sizeof pkt->data) {
		TRACE_PROTO("Too big packet", QUIC_EV_CONN_SPKT, qc->conn, pkt, &pkt->len);
		goto err;
	}

	if (!qc_try_rm_hp(pkt, buf, beg, end, conn_ctx))
		goto err;

	/* Wake the tasklet of the QUIC connection packet handler. */
	if (conn_ctx)
		tasklet_wakeup(conn_ctx->wait_event.tasklet);

	TRACE_LEAVE(QUIC_EV_CONN_SPKT, qc->conn);

	return pkt->len;

 err:
	TRACE_DEVEL("Leaing in error", QUIC_EV_CONN_SPKT, qc ? qc->conn : NULL);
	return -1;
}

static ssize_t qc_lstnr_pkt_rcv(unsigned char **buf, const unsigned char *end,
                                struct quic_rx_packet *pkt,
                                struct quic_dgram_ctx *dgram_ctx,
                                struct sockaddr_storage *saddr)
{
	unsigned char *beg;
	uint64_t len;
	struct quic_conn *qc;
	struct eb_root *cids;
	struct ebmb_node *node;
	struct listener *l;
	struct quic_conn_ctx *conn_ctx;
	int long_header = 0;

	qc = NULL;
	TRACE_ENTER(QUIC_EV_CONN_LPKT);
	if (end <= *buf)
		goto err;

	/* Fixed bit */
	if (!(**buf & QUIC_PACKET_FIXED_BIT)) {
		/* XXX TO BE DISCARDED */
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
		goto err;
	}

	l = dgram_ctx->owner;
	beg = *buf;
	/* Header form */
	qc_parse_hd_form(pkt, *(*buf)++, &long_header);
	if (long_header) {
		unsigned char dcid_len;

		if (!quic_packet_read_long_header(buf, end, pkt)) {
			TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
			goto err;
		}

		dcid_len = pkt->dcid.len;
		/* For Initial packets, and for servers (QUIC clients connections),
		 * there is no Initial connection IDs storage.
		 */
		if (pkt->type == QUIC_PACKET_TYPE_INITIAL) {
			/* DCIDs of first packets coming from clients may have the same values.
			 * Let's distinguish them concatenating the socket addresses to the DCIDs.
			 */
			quic_cid_saddr_cat(&pkt->dcid, saddr);
			cids = &l->rx.odcids;
		}
		else {
			if (pkt->dcid.len != QUIC_CID_LEN) {
				TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
				goto err;
			}

			cids = &l->rx.cids;
		}

		node = ebmb_lookup(cids, pkt->dcid.data, pkt->dcid.len);
		if (!node && pkt->type == QUIC_PACKET_TYPE_INITIAL && dcid_len == QUIC_CID_LEN &&
		    cids == &l->rx.odcids) {
			/* Switch to the definitive tree ->cids containing the final CIDs. */
			node = ebmb_lookup(&l->rx.cids, pkt->dcid.data, dcid_len);
			if (node) {
				/* If found, signal this with NULL as special value for <cids>. */
				pkt->dcid.len = dcid_len;
				cids = NULL;
			}
		}

		if (!node) {
			if (pkt->type != QUIC_PACKET_TYPE_INITIAL) {
				TRACE_PROTO("Non Initiial packet", QUIC_EV_CONN_LPKT);
				goto err;
			}

			qc = new_quic_conn(pkt->version);
			if (!qc) {
				TRACE_PROTO("Non allocated new connection", QUIC_EV_CONN_LPKT);
				goto err;
			}

			pkt->qc = qc;
			pkt->saddr = *saddr;
			/* Note that here, odcid_len equals to pkt->dcid.len minus the length
			 * of <saddr>.
			 */
			pkt->odcid_len = dcid_len;
			/* Enqueue this packet. */
			LIST_ADDQ(&l->rx.qpkts, &pkt->rx_list);
			/* Try to accept a new connection. */
			listener_accept(l);
			if (!qc->conn) {
				TRACE_PROTO("Non accepted connection", QUIC_EV_CONN_LPKT, qc->conn);
				goto err;
			}

			if (!quic_conn_init_timer(qc)) {
				TRACE_PROTO("Non initialized timer", QUIC_EV_CONN_LPKT, qc->conn);
				goto err;
			}

			/* This is the DCID node sent in this packet by the client. */
			node = &qc->odcid_node;
			conn_ctx = qc->conn->xprt_ctx;
			SSL_set_quic_transport_params(conn_ctx->ssl,
			                              qc->enc_params, qc->enc_params_len);
		}
		else {
			if (pkt->type == QUIC_PACKET_TYPE_INITIAL && cids == &l->rx.odcids)
				qc = ebmb_entry(node, struct quic_conn, odcid_node);
			else
				qc = ebmb_entry(node, struct quic_conn, scid_node);
		}

		if (pkt->type == QUIC_PACKET_TYPE_INITIAL) {
			uint64_t token_len;
			struct quic_tls_ctx *ctx =
				&qc->els[QUIC_TLS_ENC_LEVEL_INITIAL].tls_ctx;

			if (!quic_dec_int(&token_len, (const unsigned char **)buf, end) ||
			    end - *buf < token_len) {
				TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT, qc->conn);
				goto err;
			}

			/* XXX TO DO XXX 0 value means "the token is not present".
			 * A server which sends an Initial packet must not set the token.
			 * So, a client which receives an Initial packet with a token
			 * MUST discard the packet or generate a connection error with
			 * PROTOCOL_VIOLATION as type.
			 * The token must be provided in a Retry packet or NEW_TOKEN frame.
			 */
			pkt->token_len = token_len;
			/* NOTE: the socket address has been concatenated to the destination ID
			 * chosen by the client for Initial packets.
			 */
			if (!ctx->rx.hp && !qc_new_isecs(qc->conn, pkt->dcid.data,
			                                 pkt->odcid_len, 1)) {
				TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT, qc->conn);
				goto err;
			}
		}
	}
	else {
		if (end - *buf < QUIC_CID_LEN) {
			TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
			goto err;
		}

		cids = &l->rx.cids;
		node = ebmb_lookup(cids, *buf, QUIC_CID_LEN);
		if (!node) {
			TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
			goto err;
		}

		qc = ebmb_entry(node, struct quic_conn, scid_node);
		*buf += QUIC_CID_LEN;
	}

	/* Store the DCID used for this packet to check the packet which
	 * come in this UDP datagram match with it.
	 */
	if (!dgram_ctx->dcid_node) {
		dgram_ctx->dcid_node = node;
		dgram_ctx->qc = qc;
	}

	/* Only packets packets with long headers and not RETRY or VERSION as type
	 * have a length field.
	 */
	if (long_header && pkt->type != QUIC_PACKET_TYPE_RETRY && pkt->version) {
		if (!quic_dec_int(&len, (const unsigned char **)buf, end) ||
		    end - *buf < len) {
			TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT, qc->conn);
			goto err;
		}

		pkt->len = len;
	}
	else if (!long_header) {
		/* A short packet is the last one of an UDP datagram. */
		pkt->len = end - *buf;
	}

	/* Update the state if needed. */
	conn_ctx = qc->conn->xprt_ctx;

	/* Increase the total length of this packet by the header length. */
	pkt->len += *buf - beg;
	/* Do not check the DCID node before the length. */
	if (dgram_ctx->dcid_node != node) {
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT, qc->conn);
		goto err;
	}

	if (pkt->len > sizeof pkt->data) {
		TRACE_PROTO("Too big packet", QUIC_EV_CONN_LPKT, qc->conn, pkt, &pkt->len);
		goto err;
	}

	if (!qc_try_rm_hp(pkt, buf, beg, end, conn_ctx)) {
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT, qc->conn);
		goto err;
	}

	/* Wake the tasklet of the QUIC connection packet handler. */
	if (conn_ctx)
		tasklet_wakeup(conn_ctx->wait_event.tasklet);
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc->conn, pkt);

	return pkt->len;

 err:
	TRACE_DEVEL("Leaving in error", QUIC_EV_CONN_LPKT,
	            qc ? qc->conn : NULL, pkt);
	return -1;
}

/* This function builds into <buf> buffer a QUIC long packet header whose size may be computed
 * in advance. This is the reponsability of the caller to check there is enough room in this
 * buffer to build a long header.
 * Returns 0 if <type> QUIC packet type is not supported by long header, or 1 if succeeded.
 */
static int quic_build_packet_long_header(unsigned char **buf, const unsigned char *end,
                                         int type, size_t pn_len, struct quic_conn *conn)
{
	if (type > QUIC_PACKET_TYPE_RETRY)
		return 0;

	/* #0 byte flags */
	*(*buf)++ = QUIC_PACKET_FIXED_BIT | QUIC_PACKET_LONG_HEADER_BIT |
		(type << QUIC_PACKET_TYPE_SHIFT) | (pn_len - 1);
	/* Version */
	quic_write_uint32(buf, end, conn->version);
	*(*buf)++ = conn->dcid.len;
	/* Destination connection ID */
	if (conn->dcid.len) {
		memcpy(*buf, conn->dcid.data, conn->dcid.len);
		*buf += conn->dcid.len;
	}
	/* Source connection ID */
	*(*buf)++ = conn->scid.len;
	if (conn->scid.len) {
		memcpy(*buf, conn->scid.data, conn->scid.len);
		*buf += conn->scid.len;
	}

	return 1;
}

/* This function builds into <buf> buffer a QUIC long packet header whose size may be computed
 * in advance. This is the reponsability of the caller to check there is enough room in this
 * buffer to build a long header.
 * Returns 0 if <type> QUIC packet type is not supported by long header, or 1 if succeeded.
 */
static int quic_build_packet_short_header(unsigned char **buf, const unsigned char *end,
                                          size_t pn_len, struct quic_conn *conn)
{
	/* #0 byte flags */
	*(*buf)++ = QUIC_PACKET_FIXED_BIT | (pn_len - 1);
	/* Destination connection ID */
	if (conn->dcid.len) {
		memcpy(*buf, conn->dcid.data, conn->dcid.len);
		*buf += conn->dcid.len;
	}

	return 1;
}

/* Apply QUIC header protection to the packet with <buf> as first byte address,
 * <pn> as address of the Packet number field, <pnlen> being this field length
 * with <aead> as AEAD cipher and <key> as secret key.
 * Returns 1 if succeeded or 0 if failed.
 */
static int quic_apply_header_protection(unsigned char *buf, unsigned char *pn, size_t pnlen,
                                        const EVP_CIPHER *aead, const unsigned char *key)
{
	int i, ret, outlen;
	EVP_CIPHER_CTX *ctx;
	/* We need an IV of at least 5 bytes: one byte for bytes #0
	 * and at most 4 bytes for the packet number
	 */
	unsigned char mask[5] = {0};

	ret = 0;
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;

	if (!EVP_EncryptInit_ex(ctx, aead, NULL, key, pn + QUIC_PACKET_PN_MAXLEN) ||
	    !EVP_EncryptUpdate(ctx, mask, &outlen, mask, sizeof mask) ||
	    !EVP_EncryptFinal_ex(ctx, mask, &outlen))
		goto out;

	*buf ^= mask[0] & (*buf & QUIC_PACKET_LONG_HEADER_BIT ? 0xf : 0x1f);
	for (i = 0; i < pnlen; i++)
		pn[i] ^= mask[i + 1];

	ret = 1;

 out:
	EVP_CIPHER_CTX_free(ctx);

	return ret;
}

/* Reduce the encoded size of <ack_frm> ACK frame removing the last
 * ACK ranges if needed to a value below <limit> in bytes.
 * Return 1 if succeeded, 0 if not.
 */
static int quic_ack_frm_reduce_sz(struct quic_frame *ack_frm, size_t limit)
{
	size_t room, ack_delay_sz;

	ack_delay_sz = quic_int_getsize(ack_frm->tx_ack.ack_delay);
	/* A frame is made of 1 byte for the frame type. */
	room = limit - ack_delay_sz - 1;
	if (!quic_rm_last_ack_ranges(ack_frm->tx_ack.arngs, room))
		return 0;

	return 1 + ack_delay_sz + ack_frm->tx_ack.arngs->enc_sz;
}

/* Prepare as most as possible CRYPTO frames from prebuilt CRYPTO frames for <qel>
 * encryption level to be encoded in a buffer with <room> as available room,
 * and <*len> the packet Length field initialized with the number of bytes already present
 * in this buffer which must be taken into an account for the Length packet field value.
 * <headlen> is the number of bytes already present in this packet before building
 * CRYPTO frames.
 * This is the responsibility of the caller to check that <*len> < <room> as this is
 * the responsibility to check that <headlen> < quic_path_prep_data(conn->path).
 * Update consequently <*len> to reflect the size of these CRYPTO frames built
 * by this function. Also attach these CRYPTO frames to <pkt> QUIC packet.
 * Return 1 if succeeded, 0 if not.
 */
static inline int qc_build_cfrms(struct quic_tx_packet *pkt,
                                 size_t room, size_t *len, size_t headlen,
                                 struct quic_enc_level *qel,
                                 struct quic_conn *conn)
{
	int ret;
	struct quic_tx_frm *cf, *cfbak;

	ret = 0;
	/* If we are not probing we must take into an account the congestion
	 * control window.
	 */
	if (!conn->tx.nb_pto_dgrams)
		room = QUIC_MIN(room, quic_path_prep_data(conn->path) - headlen);
	TRACE_PROTO("************** CRYPTO frames build (headlen)",
	            QUIC_EV_CONN_BCFRMS, conn->conn, &headlen);
	list_for_each_entry_safe(cf, cfbak, &qel->pktns->tx.frms, list) {
		/* header length, data length, frame length. */
		size_t hlen, dlen, cflen;

		TRACE_PROTO("          New CRYPTO frame build (room, len)",
		            QUIC_EV_CONN_BCFRMS, conn->conn, &room, len);
		if (!room)
			break;

		/* Compute the length of this CRYPTO frame header */
		hlen = 1 + quic_int_getsize(cf->crypto.offset);
		/* Compute the data length of this CRyPTO frame. */
		dlen = max_stream_data_size(room, *len + hlen, cf->crypto.len);
		TRACE_PROTO(" CRYPTO data length (hlen, crypto.len, dlen)",
		            QUIC_EV_CONN_BCFRMS, conn->conn, &hlen, &cf->crypto.len, &dlen);
		if (!dlen)
			break;

		pkt->cdata_len += dlen;
		/* CRYPTO frame length. */
		cflen = hlen + quic_int_getsize(dlen) + dlen;
		TRACE_PROTO("                 CRYPTO frame length (cflen)",
		            QUIC_EV_CONN_BCFRMS, conn->conn, &cflen);
		/* Add the CRYPTO data length and its encoded length to the packet
		 * length and the length of this length.
		 */
		*len += cflen;
		room -= cflen;
		if (dlen == cf->crypto.len) {
			/* <cf> CRYPTO data have been consumed. */
			LIST_DEL(&cf->list);
			LIST_ADDQ(&pkt->frms, &cf->list);
		}
		else {
			struct quic_tx_frm *new_cf;

			new_cf = pool_alloc(pool_head_quic_tx_frm);
			if (!new_cf) {
				TRACE_PROTO("No memory for new crypto frame", QUIC_EV_CONN_BCFRMS, conn->conn);
				return 0;
			}

			new_cf->type = QUIC_FT_CRYPTO;
			new_cf->crypto.len = dlen;
			new_cf->crypto.offset = cf->crypto.offset;
			LIST_ADDQ(&pkt->frms, &new_cf->list);
			/* Consume <dlen> bytes of the current frame. */
			cf->crypto.len -= dlen;
			cf->crypto.offset += dlen;
		}
		ret = 1;
	}

	return ret;
}

/* This function builds a clear handshake packet used during a QUIC TLS handshakes
 * into <wbuf> the current <wbuf> for <conn> QUIC connection with <qel> as QUIC
 * TLS encryption level for outgoing packets filling it with as much as CRYPTO
 * data as possible from <offset> offset in the CRYPTO data stream. Note that
 * this offset value is updated by the length of the CRYPTO frame used to embed
 * the CRYPTO data if this packet and only if the packet is successfully built.
 * The trailing QUIC_TLS_TAG_LEN bytes of this packet are not built. But they are
 * reserved so that to be sure there is enough room to build this AEAD TAG after
 * having successfully returned from this function and to be sure the position
 * pointer of <wbuf> may be safely incremented by QUIC_TLS_TAG_LEN. After having
 * returned from this function, <wbuf> position will point one past the last
 * byte of the payload with the confidence there is at least QUIC_TLS_TAG_LEN bytes
 * available packet to encrypt this packet.
 * This function also update the value of <buf_pn> pointer to point to the packet
 * number field in this packet. <pn_len> will also have the packet number
 * length as value.
 *
 * Return the length of the packet if succeeded minus QUIC_TLS_TAG_LEN, or -1 if
 * failed (not enough room in <wbuf> to build this packet plus QUIC_TLS_TAG_LEN
 * bytes), -2 if there are too much CRYPTO data in flight to build a packet.
 */
static ssize_t qc_do_build_hdshk_pkt(struct q_buf *wbuf,
                                     struct quic_tx_packet *pkt, int pkt_type,
                                     int64_t pn, size_t *pn_len,
                                     unsigned char **buf_pn,
                                     struct quic_enc_level *qel,
                                     struct quic_conn *conn)
{
	unsigned char *beg, *pos;
	const unsigned char *end;
	size_t len, len_frms, token_fields_len, padding_len;
	struct quic_frame frm = { .type = QUIC_FT_CRYPTO, };
	struct quic_frame ack_frm = { .type = QUIC_FT_ACK, };
	struct quic_crypto *crypto = &frm.crypto;
	size_t ack_frm_len;
	int64_t largest_acked_pn;
	int add_ping_frm;

	/* Length field value with CRYPTO frames if present. */
	len_frms = 0;
	beg = pos = q_buf_getpos(wbuf);
	end = q_buf_end(wbuf);
	/* When not probing and not acking, reduce the size of this buffer to respect
	 * the congestion controller window.
	 */
	if (!conn->tx.nb_pto_dgrams && !(qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED)) {
		size_t path_room;

		path_room = quic_path_prep_data(conn->path);
		if (end - beg > path_room)
			end = beg + path_room;
	}

	/* For a server, the token field of an Initial packet is empty. */
	token_fields_len = pkt_type == QUIC_PACKET_TYPE_INITIAL ? 1 : 0;

	/* Check there is enough room to build the header followed by a token. */
	if (end - pos < QUIC_LONG_PACKET_MINLEN + conn->dcid.len +
	    conn->scid.len + token_fields_len + QUIC_TLS_TAG_LEN) {
		ssize_t room = end - pos;
		TRACE_PROTO("Not enough room", QUIC_EV_CONN_HPKT,
		            conn->conn, NULL, NULL, &room);
		goto err;
	}

	/* Reserve enough room at the end of the packet for the AEAD TAG. */
	end -= QUIC_TLS_TAG_LEN;
	largest_acked_pn = qel->pktns->tx.largest_acked_pn;
	/* packet number length */
	*pn_len = quic_packet_number_length(pn, largest_acked_pn);

	quic_build_packet_long_header(&pos, end, pkt_type, *pn_len, conn);

	/* Encode the token length (0) for an Initial packet. */
	if (pkt_type == QUIC_PACKET_TYPE_INITIAL)
		*pos++ = 0;

	/* Build an ACK frame if required. */
	ack_frm_len = 0;
	if ((qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) &&
	    !eb_is_empty(&qel->pktns->rx.arngs.root)) {
		ack_frm.tx_ack.ack_delay = 0;
		ack_frm.tx_ack.arngs = &qel->pktns->rx.arngs;
		ack_frm_len = quic_ack_frm_reduce_sz(&ack_frm, end - pos);
		if (!ack_frm_len) {
			ssize_t room = end - pos;
			TRACE_PROTO("Not enough room", QUIC_EV_CONN_HPKT,
			            conn->conn, NULL, NULL, &room);
			goto err;
		}

		qel->pktns->flags &= ~QUIC_FL_PKTNS_ACK_REQUIRED;
	}

	/* Length field value without the CRYPTO frames data length. */
	len = ack_frm_len + *pn_len;
	if (!LIST_ISEMPTY(&qel->pktns->tx.frms)) {
		ssize_t room = end - pos;

		len_frms = len + QUIC_TLS_TAG_LEN;
		if (!qc_build_cfrms(pkt, end - pos, &len_frms, pos - beg, qel, conn)) {
			TRACE_PROTO("Not enough room", QUIC_EV_CONN_HPKT,
						conn->conn, NULL, NULL, &room);
			goto err;
		}
	}

	add_ping_frm = 0;
	padding_len = 0;
	if (objt_server(conn->conn->target) &&
	    pkt_type == QUIC_PACKET_TYPE_INITIAL &&
	    len < QUIC_INITIAL_PACKET_MINLEN) {
		len += padding_len = QUIC_INITIAL_PACKET_MINLEN - len;
	}
	else if (LIST_ISEMPTY(&pkt->frms)) {
		if (qel->pktns->tx.pto_probe) {
			/* If we cannot send a CRYPTO frame, we send a PING frame. */
			add_ping_frm = 1;
			len += 1;
		}
		/* If there is no frame at all to follow, add at least a PADDING frame. */
		if (!ack_frm_len)
			len += padding_len = QUIC_PACKET_PN_MAXLEN - *pn_len;
	}

	/* Length (of the remaining data). Must not fail because, the buffer size
	 * has been checked above. Note that we have reserved QUIC_TLS_TAG_LEN bytes
	 * for the encryption TAG. It must be taken into an account for the length
	 * of this packet.
	 */
	if (len_frms)
		len = len_frms;
	else
		len += QUIC_TLS_TAG_LEN;
	quic_enc_int(&pos, end, len);

	/* Packet number field address. */
	*buf_pn = pos;

	/* Packet number encoding. */
	quic_packet_number_encode(&pos, end, pn, *pn_len);

	if (ack_frm_len && !qc_build_frm(&pos, end, &ack_frm, pkt, conn)) {
		ssize_t room = end - pos;
		TRACE_PROTO("Not enough room", QUIC_EV_CONN_HPKT,
		            conn->conn, NULL, NULL, &room);
		goto err;
	}

	/* Crypto frame */
	if (!LIST_ISEMPTY(&pkt->frms)) {
		struct quic_tx_frm *cf;

		list_for_each_entry(cf, &pkt->frms, list) {
			crypto->offset = cf->crypto.offset;
			crypto->len = cf->crypto.len;
			crypto->qel = qel;
			if (!qc_build_frm(&pos, end, &frm, pkt, conn)) {
				ssize_t room = end - pos;
				TRACE_PROTO("Not enough room", QUIC_EV_CONN_HPKT,
							conn->conn, NULL, NULL, &room);
				goto err;
			}
		}
	}

	/* Build a PING frame if needed. */
	if (add_ping_frm) {
		frm.type = QUIC_FT_PING;
		if (!qc_build_frm(&pos, end, &frm, pkt, conn)) {
			ssize_t room = end - pos;
			TRACE_PROTO("Not enough room", QUIC_EV_CONN_HPKT,
			            conn->conn, NULL, NULL, &room);
			goto err;
		}
	}

	/* Build a PADDING frame if needed. */
	if (padding_len) {
		frm.type = QUIC_FT_PADDING;
		frm.padding.len = padding_len;
		if (!qc_build_frm(&pos, end, &frm, pkt, conn)) {
			ssize_t room = end - pos;
			TRACE_PROTO("Not enough room", QUIC_EV_CONN_HPKT,
			            conn->conn, NULL, NULL, &room);
			goto err;
		}
	}

	/* Always reset this variable as this function has no idea
	 * if it was set. It is handle by the loss detection timer.
	 */
	qel->pktns->tx.pto_probe = 0;

 out:
	return pos - beg;

 err:
	return -1;
}

static inline void quic_tx_packet_init(struct quic_tx_packet *pkt)
{
	pkt->cdata_len = 0;
	pkt->in_flight_len = 0;
	LIST_INIT(&pkt->frms);
}

/* Free <pkt> TX packet which has not already attached to any tree. */
static inline void free_quic_tx_packet(struct quic_tx_packet *pkt)
{
	struct quic_tx_frm *frm, *frmbak;

	list_for_each_entry_safe(frm, frmbak, &pkt->frms, list) {
		LIST_DEL(&frm->list);
		pool_free(pool_head_quic_tx_frm, frm);
	}
	pool_free(pool_head_quic_tx_packet, pkt);
}

/* Build a handshake packet into <buf> packet buffer with <pkt_type> as packet
 * type for <qc> QUIC connection from CRYPTO data stream at <*offset> offset to
 * be encrypted at <qel> encryption level.
 * Return -2 if the packet could not be encrypted for any reason, -1 if there was
 * not enough room in <buf> to build the packet, or the size of the built packet
 * if succeeded (may be zero if there is too much crypto data in flight to build the packet).
 */
static ssize_t qc_build_hdshk_pkt(struct q_buf *buf, struct quic_conn *qc, int pkt_type,
                                  struct quic_enc_level *qel)
{
	/* The pointer to the packet number field. */
	unsigned char *buf_pn;
	unsigned char *beg, *end, *payload;
	int64_t pn;
	size_t pn_len, payload_len, aad_len;
	ssize_t pkt_len;
	struct quic_tls_ctx *tls_ctx;
	struct quic_tx_packet *pkt;

	TRACE_ENTER(QUIC_EV_CONN_HPKT, qc->conn, NULL, qel);
	pkt = pool_alloc(pool_head_quic_tx_packet);
	if (!pkt) {
		TRACE_DEVEL("Not enough memory for a new packet", QUIC_EV_CONN_HPKT, qc->conn);
		return -2;
	}

	quic_tx_packet_init(pkt);
	beg = q_buf_getpos(buf);
	pn_len = 0;
	buf_pn = NULL;
	pn = qel->pktns->tx.next_pn + 1;
	pkt_len = qc_do_build_hdshk_pkt(buf, pkt, pkt_type, pn, &pn_len, &buf_pn, qel, qc);
	if (pkt_len <= 0) {
		free_quic_tx_packet(pkt);
		return pkt_len;
	}

	end = beg + pkt_len;
	payload = buf_pn + pn_len;
	payload_len = end - payload;
	aad_len = payload - beg;

	tls_ctx = &qel->tls_ctx;
	if (!quic_packet_encrypt(payload, payload_len, beg, aad_len, pn, tls_ctx, qc->conn))
		goto err;

	end += QUIC_TLS_TAG_LEN;
	pkt_len += QUIC_TLS_TAG_LEN;
	if (!quic_apply_header_protection(beg, buf_pn, pn_len,
	                                  tls_ctx->tx.hp, tls_ctx->tx.hp_key)) {
		TRACE_DEVEL("Could not apply the header protection", QUIC_EV_CONN_HPKT, qc->conn);
		goto err;
	}

	/* Now that a correct packet is built, let us set the position pointer of
	 * <buf> buffer for the next packet.
	 */
	q_buf_setpos(buf, end);
	/* Consume a packet number. */
	++qel->pktns->tx.next_pn;
	/* Attach the built packet to its tree. */
	pkt->pn_node.key = qel->pktns->tx.next_pn;
	/* Set the packet in fligth length for in flight packet only. */
	if (pkt->flags & QUIC_FL_TX_PACKET_IN_FLIGHT) {
		pkt->in_flight_len = pkt_len;
		qc->path->prep_in_flight += pkt_len;
	}
	pkt->pktns = qel->pktns;
	eb64_insert(&qel->pktns->tx.pkts, &pkt->pn_node);
	/* Increment the number of bytes in <buf> buffer by the length of this packet. */
	buf->data += pkt_len;
	/* Attach this packet to <buf>. */
	LIST_ADDQ(&buf->pkts, &pkt->list);
	TRACE_LEAVE(QUIC_EV_CONN_HPKT, qc->conn, pkt);

	return pkt_len;

 err:
	free_quic_tx_packet(pkt);
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_HPKT, qc->conn);
	return -2;
}

/* Prepare a clear post handhskake packet for <conn> QUIC connection.
 * Return the length of this packet if succeeded, -1 <wbuf> was full.
 */
static ssize_t qc_do_build_phdshk_apkt(struct q_buf *wbuf,
                                       struct quic_tx_packet *pkt,
                                       int64_t pn, size_t *pn_len,
                                       unsigned char **buf_pn, struct quic_enc_level *qel,
                                       struct quic_conn *conn)
{
	const unsigned char *beg, *end;
	unsigned char *pos;
	struct quic_frame *frm, *sfrm;
	struct quic_frame ack_frm = { .type = QUIC_FT_ACK, };
	size_t fake_len, ack_frm_len;
	int64_t largest_acked_pn;

	TRACE_ENTER(QUIC_EV_CONN_PAPKT, conn->conn);
	beg = pos = q_buf_getpos(wbuf);
	end = q_buf_end(wbuf);
	/* When not probing and not acking, reduce the size of this buffer to respect
	 * the congestion controller window.
	 */
	if (!conn->tx.nb_pto_dgrams && !(qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED)) {
		size_t path_room;

		path_room = quic_path_prep_data(conn->path);
		if (end - beg > path_room)
			end = beg + path_room;
	}
	largest_acked_pn = qel->pktns->tx.largest_acked_pn;
	/* Packet number length */
	*pn_len = quic_packet_number_length(pn, largest_acked_pn);
	/* Check there is enough room to build this packet (without payload). */
	if (end - pos < QUIC_SHORT_PACKET_MINLEN + sizeof_quic_cid(&conn->dcid) +
	    *pn_len + QUIC_TLS_TAG_LEN) {
		ssize_t room = end - pos;
		TRACE_PROTO("Not enough room", QUIC_EV_CONN_PAPKT,
		            conn->conn, NULL, NULL, &room);
		goto err;
	}

	/* Reserve enough room at the end of the packet for the AEAD TAG. */
	end -= QUIC_TLS_TAG_LEN;
	quic_build_packet_short_header(&pos, end, *pn_len, conn);
	/* Packet number field. */
	*buf_pn = pos;
	/* Packet number encoding. */
	quic_packet_number_encode(&pos, end, pn, *pn_len);

	/* Build an ACK frame if required. */
	ack_frm_len = 0;
	if ((qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) &&
	    !eb_is_empty(&qel->pktns->rx.arngs.root)) {
		ack_frm.tx_ack.ack_delay = 0;
		ack_frm.tx_ack.arngs = &qel->pktns->rx.arngs;
		ack_frm_len = quic_ack_frm_reduce_sz(&ack_frm, end - pos);
		if (!ack_frm_len)
			goto err;

		qel->pktns->flags &= ~QUIC_FL_PKTNS_ACK_REQUIRED;
	}

	if (ack_frm_len && !qc_build_frm(&pos, end, &ack_frm, pkt, conn)) {
		ssize_t room = end - pos;
		TRACE_PROTO("Not enough room", QUIC_EV_CONN_PAPKT,
		            conn->conn, NULL, NULL, &room);
		goto err;
	}

	fake_len = ack_frm_len;
	if (!LIST_ISEMPTY(&qel->pktns->tx.frms) &&
	    !qc_build_cfrms(pkt, end - pos, &fake_len, pos - beg, qel, conn)) {
		ssize_t room = end - pos;
		TRACE_PROTO("some CRYPTO frames could not be built",
		            QUIC_EV_CONN_PAPKT, conn->conn, NULL, NULL, &room);
		goto err;
	}

	/* Crypto frame */
	if (!LIST_ISEMPTY(&pkt->frms)) {
		struct quic_frame frm = { .type = QUIC_FT_CRYPTO, };
		struct quic_crypto *crypto = &frm.crypto;
		struct quic_tx_frm *cf;

		list_for_each_entry(cf, &pkt->frms, list) {
			crypto->offset = cf->crypto.offset;
			crypto->len = cf->crypto.len;
			crypto->qel = qel;
			if (!qc_build_frm(&pos, end, &frm, pkt, conn)) {
				ssize_t room = end - pos;
				TRACE_PROTO("Not enough room", QUIC_EV_CONN_PAPKT,
				            conn->conn, NULL, NULL, &room);
				goto err;
			}
		}
	}

	/* Encode a maximum of frames. */
	list_for_each_entry_safe(frm, sfrm, &conn->tx.frms_to_send, list) {
		unsigned char *ppos;

		ppos = pos;
		if (!qc_build_frm(&ppos, end, frm, pkt, conn)) {
			TRACE_DEVEL("Frames not built", QUIC_EV_CONN_PAPKT, conn->conn);
			break;
		}

		LIST_DEL(&frm->list);
		LIST_ADDQ(&pkt->frms, &frm->list);
		pos = ppos;
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_PAPKT, conn->conn);
	return pos - beg;

 err:
	TRACE_DEVEL("leaving in error (buffer full)", QUIC_EV_CONN_PAPKT, conn->conn);
	return -1;
}

/* Prepare a post handhskake packet at Application encryption level for <conn>
 * QUIC connection.
 * Return the length of this packet if succeeded, -1 if <wbuf> was full,
 * -2 in case of major error (encryption failure).
 */
static ssize_t qc_build_phdshk_apkt(struct q_buf *wbuf, struct quic_conn *qc)
{
	/* A pointer to the packet number field in <buf> */
	unsigned char *buf_pn;
	unsigned char *beg, *end, *payload;
	int64_t pn;
	size_t pn_len, aad_len, payload_len;
	ssize_t pkt_len;
	struct quic_tls_ctx *tls_ctx;
	struct quic_enc_level *qel;
	struct quic_tx_packet *pkt;

	TRACE_ENTER(QUIC_EV_CONN_PAPKT, qc->conn);
	pkt = pool_alloc(pool_head_quic_tx_packet);
	if (!pkt) {
		TRACE_DEVEL("Not enough memory for a new packet", QUIC_EV_CONN_PAPKT, qc->conn);
		return -2;
	}

	quic_tx_packet_init(pkt);
	beg = q_buf_getpos(wbuf);
	qel = &qc->els[QUIC_TLS_ENC_LEVEL_APP];
	pn_len = 0;
	buf_pn = NULL;
	pn = qel->pktns->tx.next_pn + 1;
	pkt_len = qc_do_build_phdshk_apkt(wbuf, pkt, pn, &pn_len, &buf_pn, qel, qc);
	if (pkt_len <= 0) {
		free_quic_tx_packet(pkt);
		return pkt_len;
	}

	end = beg + pkt_len;
	payload = buf_pn + pn_len;
	payload_len = end - payload;
	aad_len = payload - beg;

	tls_ctx = &qel->tls_ctx;
	if (!quic_packet_encrypt(payload, payload_len, beg, aad_len, pn, tls_ctx, qc->conn))
		goto err;

	end += QUIC_TLS_TAG_LEN;
	pkt_len += QUIC_TLS_TAG_LEN;
	if (!quic_apply_header_protection(beg, buf_pn, pn_len,
	                                  tls_ctx->tx.hp, tls_ctx->tx.hp_key))
		goto err;

	q_buf_setpos(wbuf, end);
	/* Consume a packet number. */
	++qel->pktns->tx.next_pn;
	/* Attach the built packet to its tree. */
	pkt->pn_node.key = qel->pktns->tx.next_pn;
	eb64_insert(&qel->pktns->tx.pkts, &pkt->pn_node);
	/* Set the packet in fligth length for in flight packet only. */
	if (pkt->flags & QUIC_FL_TX_PACKET_IN_FLIGHT) {
		pkt->in_flight_len = pkt_len;
		qc->path->prep_in_flight += pkt_len;
	}
	pkt->pktns = qel->pktns;
	/* Increment the number of bytes in <buf> buffer by the length of this packet. */
	wbuf->data += pkt_len;
	/* Attach this packet to <buf>. */
	LIST_ADDQ(&wbuf->pkts, &pkt->list);

	TRACE_LEAVE(QUIC_EV_CONN_PAPKT, qc->conn, pkt);

	return pkt_len;

 err:
	free_quic_tx_packet(pkt);
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_PAPKT, qc->conn);
	return -2;
}

/* Prepare a maximum of QUIC Application level packets from <ctx> QUIC
 * connection I/O handler context.
 * Returns 1 if succeeded, 0 if not.
 */
int qc_prep_phdshk_pkts(struct quic_conn *qc)
{
	struct q_buf *wbuf;
	struct quic_enc_level *qel;

	TRACE_ENTER(QUIC_EV_CONN_PAPKTS, qc->conn);
	wbuf = q_wbuf(qc);
	qel = &qc->els[QUIC_TLS_ENC_LEVEL_APP];
	while (q_buf_empty(wbuf)) {
		ssize_t ret;

		if (!(qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) &&
		    (LIST_ISEMPTY(&qel->pktns->tx.frms) ||
		     qc->path->prep_in_flight >= qc->path->cwnd)) {
			TRACE_DEVEL("nothing more to do",
			            QUIC_EV_CONN_PAPKTS, qc->conn);
			break;
		}

		ret = qc_build_phdshk_apkt(wbuf, qc);
		switch (ret) {
		case -1:
			/* Not enough room left in <wbuf>. */
			wbuf = q_next_wbuf(qc);
			continue;
		case -2:
			return 0;
		default:
			/* XXX TO CHECK: consume a buffer. */
			wbuf = q_next_wbuf(qc);
			continue;
		}
	}
	TRACE_LEAVE(QUIC_EV_CONN_PAPKTS, qc->conn);

	return 1;
}

/* QUIC connection packet handler task. */
static struct task *quic_conn_io_cb(struct task *t, void *context, unsigned short state)
{
	struct quic_conn_ctx *ctx = context;

	if (ctx->state < QUIC_HS_ST_COMPLETE) {
		qc_do_hdshk(ctx);
	}
	else {
		struct quic_conn *qc = ctx->conn->qc;

		/* XXX TO DO: may fail!!! XXX */
		qc_treat_rx_pkts(&qc->els[QUIC_TLS_ENC_LEVEL_APP], ctx);
		qc_prep_phdshk_pkts(qc);
		qc_send_ppkts(ctx);
	}

	return NULL;
}

/* Receive up to <count> bytes from connection <conn>'s socket and store them
 * into buffer <buf>. Only one call to recv() is performed, unless the
 * buffer wraps, in which case a second call may be performed. The connection's
 * flags are updated with whatever special event is detected (error, read0,
 * empty). The caller is responsible for taking care of those events and
 * avoiding the call if inappropriate. The function does not call the
 * connection's polling update function, so the caller is responsible for this.
 * errno is cleared before starting so that the caller knows that if it spots an
 * error without errno, it's pending and can be retrieved via getsockopt(SO_ERROR).
 */
static size_t quic_conn_to_buf(struct connection *conn, void *xprt_ctx, struct buffer *buf, size_t count, int flags)
{
	ssize_t ret;
	size_t try, done = 0;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!fd_recv_ready(conn->handle.fd))
		return 0;

	conn->flags &= ~CO_FL_WAIT_ROOM;
	errno = 0;

	if (unlikely(!(fdtab[conn->handle.fd].ev & FD_POLL_IN))) {
		/* stop here if we reached the end of data */
		if ((fdtab[conn->handle.fd].ev & (FD_POLL_ERR|FD_POLL_HUP)) == FD_POLL_HUP)
			goto read0;

		/* report error on POLL_ERR before connection establishment */
		if ((fdtab[conn->handle.fd].ev & FD_POLL_ERR) && (conn->flags & CO_FL_WAIT_L4_CONN)) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			goto leave;
		}
	}

	/* read the largest possible block. For this, we perform only one call
	 * to recv() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again. A new attempt is made on
	 * EINTR too.
	 */
	while (count > 0) {
		try = b_contig_space(buf);
		if (!try)
			break;

		if (try > count)
			try = count;

		ret = recvfrom(conn->handle.fd, b_tail(buf), try, 0, NULL, 0);

		if (ret > 0) {
			b_add(buf, ret);
			done += ret;
			if (ret < try) {
				/* unfortunately, on level-triggered events, POLL_HUP
				 * is generally delivered AFTER the system buffer is
				 * empty, unless the poller supports POLL_RDHUP. If
				 * we know this is the case, we don't try to read more
				 * as we know there's no more available. Similarly, if
				 * there's no problem with lingering we don't even try
				 * to read an unlikely close from the client since we'll
				 * close first anyway.
				 */
				if (fdtab[conn->handle.fd].ev & FD_POLL_HUP)
					goto read0;

				if ((!fdtab[conn->handle.fd].linger_risk) ||
				    (cur_poller.flags & HAP_POLL_F_RDHUP)) {
					break;
				}
			}
			count -= ret;
		}
		else if (ret == 0) {
			goto read0;
		}
		else if (errno == EAGAIN || errno == ENOTCONN) {
			fd_cant_recv(conn->handle.fd);
			break;
		}
		else if (errno != EINTR) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			break;
		}
	}

	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && done)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;

 leave:
	return done;

 read0:
	conn_sock_read0(conn);
	conn->flags &= ~CO_FL_WAIT_L4_CONN;

	/* Now a final check for a possible asynchronous low-level error
	 * report. This can happen when a connection receives a reset
	 * after a shutdown, both POLL_HUP and POLL_ERR are queued, and
	 * we might have come from there by just checking POLL_HUP instead
	 * of recv()'s return value 0, so we have no way to tell there was
	 * an error without checking.
	 */
	if (unlikely(fdtab[conn->handle.fd].ev & FD_POLL_ERR))
		conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
	goto leave;
}


/* Send up to <count> pending bytes from buffer <buf> to connection <conn>'s
 * socket. <flags> may contain some CO_SFL_* flags to hint the system about
 * other pending data for example, but this flag is ignored at the moment.
 * Only one call to send() is performed, unless the buffer wraps, in which case
 * a second call may be performed. The connection's flags are updated with
 * whatever special event is detected (error, empty). The caller is responsible
 * for taking care of those events and avoiding the call if inappropriate. The
 * function does not call the connection's polling update function, so the caller
 * is responsible for this. It's up to the caller to update the buffer's contents
 * based on the return value.
 */
static size_t quic_conn_from_buf(struct connection *conn, void *xprt_ctx, const struct buffer *buf, size_t count, int flags)
{
	ssize_t ret;
	size_t try, done;
	int send_flag;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!fd_send_ready(conn->handle.fd))
		return 0;

	done = 0;
	/* send the largest possible block. For this we perform only one call
	 * to send() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again.
	 */
	while (count) {
		try = b_contig_data(buf, done);
		if (try > count)
			try = count;

		send_flag = MSG_DONTWAIT | MSG_NOSIGNAL;
		if (try < count || flags & CO_SFL_MSG_MORE)
			send_flag |= MSG_MORE;

		ret = sendto(conn->handle.fd, b_peek(buf, done), try, send_flag,
		             (struct sockaddr *)conn->dst, get_addr_len(conn->dst));
		if (ret > 0) {
			count -= ret;
			done += ret;

			/* A send succeeded, so we can consider ourself connected */
			conn->flags |= CO_FL_WAIT_L4L6;
			/* if the system buffer is full, don't insist */
			if (ret < try)
				break;
		}
		else if (ret == 0 || errno == EAGAIN || errno == ENOTCONN || errno == EINPROGRESS) {
			/* nothing written, we need to poll for write first */
			fd_cant_send(conn->handle.fd);
			break;
		}
		else if (errno != EINTR) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			break;
		}
	}
	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && done)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;

	if (done > 0) {
		/* we count the total bytes sent, and the send rate for 32-byte
		 * blocks. The reason for the latter is that freq_ctr are
		 * limited to 4GB and that it's not enough per second.
		 */
		_HA_ATOMIC_ADD(&global.out_bytes, done);
		update_freq_ctr(&global.out_32bps, (done + 16) / 32);
	}
	return done;
}

/* Initialize a QUIC connection (quic_conn struct) to be attached to <conn>
 * connection with <xprt_ctx> as address of the xprt context.
 * Returns 1 if succeeded, 0 if not.
 */
static int qc_conn_init(struct connection *conn, void **xprt_ctx)
{
	struct quic_conn_ctx *ctx;

	TRACE_ENTER(QUIC_EV_CONN_NEW, conn);

	if (*xprt_ctx)
		goto out;

	if (!conn_ctrl_ready(conn))
		goto out;

	ctx = pool_alloc(pool_head_quic_conn_ctx);
	if (!ctx) {
		conn->err_code = CO_ER_SYS_MEMLIM;
		goto err;
	}

	ctx->wait_event.tasklet = tasklet_new();
	if (!ctx->wait_event.tasklet) {
		conn->err_code = CO_ER_SYS_MEMLIM;
		goto err;
	}

	ctx->wait_event.tasklet->process = quic_conn_io_cb;
	ctx->wait_event.tasklet->context = ctx;
	ctx->wait_event.events = 0;
	ctx->conn = conn;
	ctx->subs = NULL;
	ctx->xprt_ctx = NULL;

	ctx->xprt = xprt_get(XPRT_QUIC);
	if (objt_server(conn->target)) {
		/* Server */
		struct server *srv = __objt_server(conn->target);
		unsigned char dcid[QUIC_CID_LEN];
		struct quic_conn *quic_conn;
		int ssl_err, ipv4;

		ssl_err = SSL_ERROR_NONE;
		if (RAND_bytes(dcid, sizeof dcid) != 1)
			goto err;

		conn->qc = new_quic_conn(QUIC_PROTOCOL_VERSION_DRAFT_28);
		if (!conn->qc)
			goto err;

		quic_conn = conn->qc;
		quic_conn->conn = conn;
		ipv4 = conn->dst->ss_family == AF_INET;
		if (!qc_new_conn_init(quic_conn, ipv4, NULL, &srv->cids,
		                      dcid, sizeof dcid, NULL, 0))
			goto err;

		if (!qc_new_isecs(conn, dcid, sizeof dcid, 0))
			goto err;

		ctx->state = QUIC_HS_ST_CLIENT_INITIAL;
		if (ssl_bio_and_sess_init(conn, srv->ssl_ctx.ctx,
		                          &ctx->ssl, &ctx->bio, ha_quic_meth, ctx) == -1) 
			goto err;

		quic_conn->params = srv->quic_params;
		/* Copy the initial source connection ID. */
		quic_cid_cpy(&quic_conn->params.initial_source_connection_id, &quic_conn->scid);
		quic_conn->enc_params_len =
			quic_transport_params_encode(quic_conn->enc_params,
			                             quic_conn->enc_params + sizeof quic_conn->enc_params,
			                             &quic_conn->params, 0);
		if (!quic_conn->enc_params_len)
			goto err;

		SSL_set_quic_transport_params(ctx->ssl, quic_conn->enc_params, quic_conn->enc_params_len);
		SSL_set_connect_state(ctx->ssl);
		ssl_err = SSL_do_handshake(ctx->ssl);
		if (ssl_err != 1) {
			ssl_err = SSL_get_error(ctx->ssl, ssl_err);
			if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
				TRACE_PROTO("SSL handshake",
				            QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state, &ssl_err);
			}
			else {
				TRACE_DEVEL("SSL handshake error",
				            QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state, &ssl_err);
				goto err;
			}
		}
	}
	else if (objt_listener(conn->target)) {
		/* Listener */
		struct bind_conf *bc = __objt_listener(conn->target)->bind_conf;

		ctx->state = QUIC_HS_ST_SERVER_INITIAL;

		if (ssl_bio_and_sess_init(conn, bc->initial_ctx,
		                          &ctx->ssl, &ctx->bio, ha_quic_meth, ctx) == -1)
			goto err;

		SSL_set_accept_state(ctx->ssl);
	}

	*xprt_ctx = ctx;

	/* Leave init state and start handshake */
	conn->flags |= CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN;
	/* Start the handshake */
	tasklet_wakeup(ctx->wait_event.tasklet);

 out:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, conn);

	return 0;

 err:
	if (ctx->wait_event.tasklet)
		tasklet_free(ctx->wait_event.tasklet);
	pool_free(pool_head_quic_conn_ctx, ctx);
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_NEW, conn);
	return -1;
}

/* transport-layer operations for QUIC connections. */
static struct xprt_ops ssl_quic = {
	.snd_buf  = quic_conn_from_buf,
	.rcv_buf  = quic_conn_to_buf,
	.init     = qc_conn_init,
	.prepare_bind_conf = ssl_sock_prepare_bind_conf,
	.destroy_bind_conf = ssl_sock_destroy_bind_conf,
	.name     = "QUIC",
};

__attribute__((constructor))
static void __quic_conn_init(void)
{
	ha_quic_meth = BIO_meth_new(0x666, "ha QUIC methods");
	xprt_register(XPRT_QUIC, &ssl_quic);
}

__attribute__((destructor))
static void __quic_conn_deinit(void)
{
	BIO_meth_free(ha_quic_meth);
}

/* Read all the QUIC packets found in <buf> with <len> as length (typically a UDP
 * datagram), <ctx> being the QUIC I/O handler context, from QUIC connections,
 * calling <func> function;
 * Return the number of bytes read if succeeded, -1 if not.
 */
static ssize_t quic_dgram_read(char *buf, size_t len, void *owner,
                               struct sockaddr_storage *saddr, qpkt_read_func *func)
{
	unsigned char *pos;
	const unsigned char *end;
	struct quic_dgram_ctx dgram_ctx = {
		.dcid_node = NULL,
		.owner = owner,
	};

	pos = (unsigned char *)buf;
	end = pos + len;

	do {
		int ret;
		struct quic_rx_packet *pkt;

		pkt = pool_alloc(pool_head_quic_rx_packet);
		if (!pkt)
			goto err;

		memset(pkt, 0, sizeof(*pkt));
		quic_rx_packet_refinc(pkt);
		ret = func(&pos, end, pkt, &dgram_ctx, saddr);
		if (ret == -1) {
			size_t pkt_len;

			pkt_len = pkt->len;
			free_quic_rx_packet(pkt);
			/* If the packet length could not be found, we cannot continue. */
			if (!pkt_len)
				break;
		}
	} while (pos < end);

	/* Increasing the received bytes counter by the UDP datagram length
	 * if this datagram could be associated to a connection.
	 */
	if (dgram_ctx.qc)
		dgram_ctx.qc->rx.bytes += len;

	return pos - (unsigned char *)buf;

 err:
	return -1;
}

ssize_t quic_lstnr_dgram_read(char *buf, size_t len, void *owner,
                              struct sockaddr_storage *saddr)
{
	return quic_dgram_read(buf, len, owner, saddr, qc_lstnr_pkt_rcv);
}

ssize_t quic_srv_dgram_read(char *buf, size_t len, void *owner,
                            struct sockaddr_storage *saddr)
{
	return quic_dgram_read(buf, len, owner, saddr, qc_srv_pkt_rcv);
}

/* QUIC I/O handler for connection to local listeners or remove servers
 * depending on <listener> boolean value, with <fd> as socket file
 * descriptor and <ctx> as context.
 */
static size_t quic_conn_handler(int fd, void *ctx, qpkt_read_func *func)
{
	ssize_t ret;
	size_t done = 0;
	struct buffer *buf = get_trash_chunk();
	/* Source address */
	struct sockaddr_storage saddr = {0};
	socklen_t saddrlen = sizeof saddr;

	if (!fd_recv_ready(fd))
		return 0;

	do {
		ret = recvfrom(fd, buf->area, buf->size, 0,
		               (struct sockaddr *)&saddr, &saddrlen);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				fd_cant_recv(fd);
			goto out;
		}
	} while (0);

	done = buf->data = ret;
	quic_dgram_read(buf->area, buf->data, ctx, &saddr, func);

 out:
	return done;
}

/* QUIC I/O handler for connections to local listeners with <fd> as socket
 * file descriptor.
 */
void quic_fd_handler(int fd)
{
	if (fdtab[fd].ev & FD_POLL_IN)
		quic_conn_handler(fd, fdtab[fd].owner, &qc_lstnr_pkt_rcv);
}

/* QUIC I/O handler for connections to remote servers with <fd> as socket
 * file descriptor.
 */
void quic_conn_fd_handler(int fd)
{
	if (fdtab[fd].ev & FD_POLL_IN)
		quic_conn_handler(fd, fdtab[fd].owner, &qc_srv_pkt_rcv);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
