/*
 * QUIC protocol implementation. Lower layer with internal features implemented
 * here such as QUIC encryption, idle timeout, acknowledgement and
 * retransmission.
 *
 * Copyright 2020 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/quic_conn.h>

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netinet/tcp.h>

#include <import/ebmbtree.h>

#include <haproxy/buf-t.h>
#include <haproxy/compat.h>
#include <haproxy/api.h>
#include <haproxy/debug.h>
#include <haproxy/tools.h>
#include <haproxy/ticks.h>

#include <haproxy/applet-t.h>
#include <haproxy/cli.h>
#include <haproxy/connection.h>
#include <haproxy/fd.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/global.h>
#include <haproxy/h3.h>
#include <haproxy/hq_interop.h>
#include <haproxy/log.h>
#include <haproxy/mux_quic.h>
#include <haproxy/ncbuf.h>
#include <haproxy/pipe.h>
#include <haproxy/proxy.h>
#include <haproxy/quic_cc.h>
#include <haproxy/quic_frame.h>
#include <haproxy/quic_enc.h>
#include <haproxy/quic_loss.h>
#include <haproxy/quic_sock.h>
#include <haproxy/quic_stats.h>
#include <haproxy/quic_stream.h>
#include <haproxy/quic_tp.h>
#include <haproxy/cbuf.h>
#include <haproxy/proto_quic.h>
#include <haproxy/quic_tls.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/task.h>
#include <haproxy/thread.h>
#include <haproxy/trace.h>

/* incremented by each "show quic". */
static unsigned int qc_epoch = 0;

/* list of supported QUIC versions by this implementation */
const struct quic_version quic_versions[] = {
	{
		.num              = QUIC_PROTOCOL_VERSION_DRAFT_29,
		.initial_salt     = initial_salt_draft_29,
		.initial_salt_len = sizeof initial_salt_draft_29,
		.key_label        = (const unsigned char *)QUIC_HKDF_KEY_LABEL_V1,
		.key_label_len    = sizeof(QUIC_HKDF_KEY_LABEL_V1) - 1,
		.iv_label         = (const unsigned char *)QUIC_HKDF_IV_LABEL_V1,
		.iv_label_len     = sizeof(QUIC_HKDF_IV_LABEL_V1) - 1,
		.hp_label         = (const unsigned char *)QUIC_HKDF_HP_LABEL_V1,
		.hp_label_len     = sizeof(QUIC_HKDF_HP_LABEL_V1) - 1,
		.ku_label         = (const unsigned char *)QUIC_HKDF_KU_LABEL_V1,
		.ku_label_len     = sizeof(QUIC_HKDF_KU_LABEL_V1) - 1,
		.retry_tag_key    = (const unsigned char *)QUIC_TLS_RETRY_KEY_DRAFT,
		.retry_tag_nonce  = (const unsigned char *)QUIC_TLS_RETRY_NONCE_DRAFT,
	},
	{
		.num              = QUIC_PROTOCOL_VERSION_1,
		.initial_salt     = initial_salt_v1,
		.initial_salt_len = sizeof initial_salt_v1,
		.key_label        = (const unsigned char *)QUIC_HKDF_KEY_LABEL_V1,
		.key_label_len    = sizeof(QUIC_HKDF_KEY_LABEL_V1) - 1,
		.iv_label         = (const unsigned char *)QUIC_HKDF_IV_LABEL_V1,
		.iv_label_len     = sizeof(QUIC_HKDF_IV_LABEL_V1) - 1,
		.hp_label         = (const unsigned char *)QUIC_HKDF_HP_LABEL_V1,
		.hp_label_len     = sizeof(QUIC_HKDF_HP_LABEL_V1) - 1,
		.ku_label         = (const unsigned char *)QUIC_HKDF_KU_LABEL_V1,
		.ku_label_len     = sizeof(QUIC_HKDF_KU_LABEL_V1) - 1,
		.retry_tag_key    = (const unsigned char *)QUIC_TLS_RETRY_KEY_V1,
		.retry_tag_nonce  = (const unsigned char *)QUIC_TLS_RETRY_NONCE_V1,
	},
	{
		.num              = QUIC_PROTOCOL_VERSION_2,
		.initial_salt     = initial_salt_v2,
		.initial_salt_len = sizeof initial_salt_v2,
		.key_label        = (const unsigned char *)QUIC_HKDF_KEY_LABEL_V2,
		.key_label_len    = sizeof(QUIC_HKDF_KEY_LABEL_V2) - 1,
		.iv_label         = (const unsigned char *)QUIC_HKDF_IV_LABEL_V2,
		.iv_label_len     = sizeof(QUIC_HKDF_IV_LABEL_V2) - 1,
		.hp_label         = (const unsigned char *)QUIC_HKDF_HP_LABEL_V2,
		.hp_label_len     = sizeof(QUIC_HKDF_HP_LABEL_V2) - 1,
		.ku_label         = (const unsigned char *)QUIC_HKDF_KU_LABEL_V2,
		.ku_label_len     = sizeof(QUIC_HKDF_KU_LABEL_V2) - 1,
		.retry_tag_key    = (const unsigned char *)QUIC_TLS_RETRY_KEY_V2,
		.retry_tag_nonce  = (const unsigned char *)QUIC_TLS_RETRY_NONCE_V2,
	},
};

/* The total number of supported versions */
const size_t quic_versions_nb = sizeof quic_versions / sizeof *quic_versions;
/* Listener only preferred version */
const struct quic_version *preferred_version;

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
	{ .mask = QUIC_EV_CONN_TXPKT,    .name = "tx_pkt",           .desc = "TX packet" },
	{ .mask = QUIC_EV_CONN_PAPKT,    .name = "phdshk_apkt",      .desc = "post handhshake application packet preparation" },
	{ .mask = QUIC_EV_CONN_PAPKTS,   .name = "phdshk_apkts",     .desc = "post handhshake application packets preparation" },
	{ .mask = QUIC_EV_CONN_IO_CB,    .name = "qc_io_cb",         .desc = "QUIC conn. I/O processing" },
	{ .mask = QUIC_EV_CONN_RMHP,     .name = "rm_hp",            .desc = "Remove header protection" },
	{ .mask = QUIC_EV_CONN_PRSHPKT,  .name = "parse_hpkt",       .desc = "parse handshake packet" },
	{ .mask = QUIC_EV_CONN_PRSAPKT,  .name = "parse_apkt",       .desc = "parse application packet" },
	{ .mask = QUIC_EV_CONN_PRSFRM,   .name = "parse_frm",        .desc = "parse frame" },
	{ .mask = QUIC_EV_CONN_PRSAFRM,  .name = "parse_ack_frm",    .desc = "parse ACK frame" },
	{ .mask = QUIC_EV_CONN_BFRM,     .name = "build_frm",        .desc = "build frame" },
	{ .mask = QUIC_EV_CONN_PHPKTS,   .name = "phdshk_pkts",      .desc = "handhshake packets preparation" },
	{ .mask = QUIC_EV_CONN_TRMHP,    .name = "rm_hp_try",        .desc = "header protection removing try" },
	{ .mask = QUIC_EV_CONN_ELRMHP,   .name = "el_rm_hp",         .desc = "handshake enc. level header protection removing" },
	{ .mask = QUIC_EV_CONN_RXPKT,    .name = "rx_pkt",           .desc = "RX packet" },
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
	{ .mask = QUIC_EV_CONN_XPRTSEND, .name = "xprt_send",        .desc = "sending XRPT subscription" },
	{ .mask = QUIC_EV_CONN_XPRTRECV, .name = "xprt_recv",        .desc = "receiving XRPT subscription" },
	{ .mask = QUIC_EV_CONN_FREED,    .name = "conn_freed",       .desc = "releasing conn. memory" },
	{ .mask = QUIC_EV_CONN_CLOSE,    .name = "conn_close",       .desc = "closing conn." },
	{ .mask = QUIC_EV_CONN_ACKSTRM,  .name = "ack_strm",         .desc = "STREAM ack."},
	{ .mask = QUIC_EV_CONN_FRMLIST,  .name = "frm_list",         .desc = "frame list"},
	{ .mask = QUIC_EV_STATELESS_RST, .name = "stateless_reset",  .desc = "stateless reset sent"},
	{ .mask = QUIC_EV_TRANSP_PARAMS, .name = "transport_params", .desc = "transport parameters"},
	{ .mask = QUIC_EV_CONN_IDLE_TIMER, .name = "idle_timer",     .desc = "idle timer task"},
	{ .mask = QUIC_EV_CONN_SUB,      .name = "xprt_sub",         .desc = "RX/TX subcription or unsubscription to QUIC xprt"},
	{ .mask = QUIC_EV_CONN_RCV,      .name = "conn_recv",        .desc = "RX on connection" },
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
	.arg_def = TRC_ARG1_QCON,  /* TRACE()'s first argument is always a quic_conn */
	.default_cb = quic_trace,
	.known_events = quic_trace_events,
	.lockon_args = quic_trace_lockon_args,
	.decoding = quic_trace_decoding,
	.report_events = ~0,  /* report everything by default */
};

#define TRACE_SOURCE    &trace_quic
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

static BIO_METHOD *ha_quic_meth;

DECLARE_POOL(pool_head_quic_tx_ring, "quic_tx_ring", QUIC_TX_RING_BUFSZ);
DECLARE_POOL(pool_head_quic_conn_rxbuf, "quic_conn_rxbuf", QUIC_CONN_RX_BUFSZ);
DECLARE_STATIC_POOL(pool_head_quic_conn_ctx,
                    "quic_conn_ctx", sizeof(struct ssl_sock_ctx));
DECLARE_STATIC_POOL(pool_head_quic_conn, "quic_conn", sizeof(struct quic_conn));
DECLARE_POOL(pool_head_quic_connection_id,
             "quic_connnection_id", sizeof(struct quic_connection_id));
DECLARE_POOL(pool_head_quic_dgram, "quic_dgram", sizeof(struct quic_dgram));
DECLARE_POOL(pool_head_quic_rx_packet, "quic_rx_packet", sizeof(struct quic_rx_packet));
DECLARE_POOL(pool_head_quic_tx_packet, "quic_tx_packet", sizeof(struct quic_tx_packet));
DECLARE_STATIC_POOL(pool_head_quic_rx_crypto_frm, "quic_rx_crypto_frm", sizeof(struct quic_rx_crypto_frm));
DECLARE_STATIC_POOL(pool_head_quic_crypto_buf, "quic_crypto_buf", sizeof(struct quic_crypto_buf));
DECLARE_STATIC_POOL(pool_head_quic_cstream, "quic_cstream", sizeof(struct quic_cstream));
DECLARE_POOL(pool_head_quic_frame, "quic_frame", sizeof(struct quic_frame));
DECLARE_STATIC_POOL(pool_head_quic_arng, "quic_arng", sizeof(struct quic_arng_node));

static struct quic_tx_packet *qc_build_pkt(unsigned char **pos, const unsigned char *buf_end,
                                           struct quic_enc_level *qel, struct quic_tls_ctx *ctx,
                                           struct list *frms, struct quic_conn *qc,
                                           const struct quic_version *ver, size_t dglen, int pkt_type,
                                           int force_ack, int padding, int probe, int cc, int *err);
struct task *quic_conn_app_io_cb(struct task *t, void *context, unsigned int state);
static void qc_idle_timer_do_rearm(struct quic_conn *qc);
static void qc_idle_timer_rearm(struct quic_conn *qc, int read);
static int qc_conn_alloc_ssl_ctx(struct quic_conn *qc);
static int quic_conn_init_timer(struct quic_conn *qc);
static int quic_conn_init_idle_timer_task(struct quic_conn *qc);

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
	const struct quic_conn *qc = a1;

	if (qc) {
		const struct quic_tls_ctx *tls_ctx;

		chunk_appendf(&trace_buf, " : qc@%p", qc);
		if (mask & QUIC_EV_CONN_INIT) {
			chunk_appendf(&trace_buf, "\n  odcid");
			quic_cid_dump(&trace_buf, &qc->odcid);
			chunk_appendf(&trace_buf, "\n   dcid");
			quic_cid_dump(&trace_buf, &qc->dcid);
			chunk_appendf(&trace_buf, "\n   scid");
			quic_cid_dump(&trace_buf, &qc->scid);
		}

		if (mask & QUIC_EV_TRANSP_PARAMS) {
			const struct quic_transport_params *p = a2;

			if (p)
				quic_transport_params_dump(&trace_buf, qc, p);
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

			tls_ctx = &qc->els[level].tls_ctx;
			chunk_appendf(&trace_buf, "\n  RX el=%c", quic_enc_level_char(level));
			if (rx_sec)
				quic_tls_secret_hexdump(&trace_buf, rx_sec, 32);
			quic_tls_keys_hexdump(&trace_buf, &tls_ctx->rx);
			chunk_appendf(&trace_buf, "\n  TX el=%c", quic_enc_level_char(level));
			if (tx_sec)
				quic_tls_secret_hexdump(&trace_buf, tx_sec, 32);
			quic_tls_keys_hexdump(&trace_buf, &tls_ctx->tx);
		}
		if (mask & (QUIC_EV_CONN_RSEC|QUIC_EV_CONN_RWSEC)) {
			const enum ssl_encryption_level_t *level = a2;

			if (level) {
				enum quic_tls_enc_level lvl = ssl_to_quic_enc_level(*level);

				chunk_appendf(&trace_buf, "\n  RX el=%c", quic_enc_level_char(lvl));
				if (quic_tls_has_rx_sec(&qc->els[lvl])) {
					tls_ctx = &qc->els[lvl].tls_ctx;
					quic_tls_keys_hexdump(&trace_buf, &tls_ctx->rx);
				}
				else
					chunk_appendf(&trace_buf, " (none)");
			}
		}

		if (mask & (QUIC_EV_CONN_WSEC|QUIC_EV_CONN_RWSEC)) {
			const enum ssl_encryption_level_t *level = a2;

			if (level) {
				enum quic_tls_enc_level lvl = ssl_to_quic_enc_level(*level);

				chunk_appendf(&trace_buf, "\n  TX el=%c", quic_enc_level_char(lvl));
				if (quic_tls_has_tx_sec(&qc->els[lvl])) {
					tls_ctx = &qc->els[lvl].tls_ctx;
					quic_tls_keys_hexdump(&trace_buf, &tls_ctx->tx);
				}
				else
					chunk_appendf(&trace_buf, " (none)");
			}

		}

		if (mask & QUIC_EV_CONN_FRMLIST) {
			const struct list *l = a2;

			if (l) {
				const struct quic_frame *frm;
				list_for_each_entry(frm, l, list) {
					chunk_appendf(&trace_buf, " frm@%p", frm);
					chunk_frm_appendf(&trace_buf, frm);
				}
			}
		}

		if (mask & (QUIC_EV_CONN_TXPKT|QUIC_EV_CONN_PAPKT)) {
			const struct quic_tx_packet *pkt = a2;
			const struct quic_enc_level *qel = a3;
			const ssize_t *room = a4;

			if (qel) {
				const struct quic_pktns *pktns = qel->pktns;
				chunk_appendf(&trace_buf, " qel=%c pto_count=%d cwnd=%llu ppif=%lld pif=%llu "
				              "if=%llu pp=%u",
				              quic_enc_level_char_from_qel(qel, qc),
				              qc->path->loss.pto_count,
				              (unsigned long long)qc->path->cwnd,
				              (unsigned long long)qc->path->prep_in_flight,
				              (unsigned long long)qc->path->in_flight,
				              (unsigned long long)pktns->tx.in_flight,
				              pktns->tx.pto_probe);
			}
			if (pkt) {
				const struct quic_frame *frm;
				if (pkt->pn_node.key != (uint64_t)-1)
					chunk_appendf(&trace_buf, " pn=%llu",(ull)pkt->pn_node.key);
				list_for_each_entry(frm, &pkt->frms, list) {
					chunk_appendf(&trace_buf, " frm@%p", frm);
					chunk_frm_appendf(&trace_buf, frm);
				}
			}

			if (room) {
				chunk_appendf(&trace_buf, " room=%lld", (long long)*room);
				chunk_appendf(&trace_buf, " dcid.len=%llu scid.len=%llu",
				              (unsigned long long)qc->dcid.len, (unsigned long long)qc->scid.len);
			}
		}

		if (mask & QUIC_EV_CONN_IO_CB) {
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
				chunk_appendf(&trace_buf, " pkt@%p", pkt);
				if (pkt->type == QUIC_PACKET_TYPE_SHORT && pkt->data)
					chunk_appendf(&trace_buf, " kp=%d",
					              !!(*pkt->data & QUIC_PACKET_KEY_PHASE_BIT));
				chunk_appendf(&trace_buf, " el=%c",
				              quic_packet_type_enc_level_char(pkt->type));
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

		if (mask & (QUIC_EV_CONN_RXPKT|QUIC_EV_CONN_PRSHPKT|QUIC_EV_CONN_SSLDATA)) {
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
				chunk_appendf(&trace_buf, " rel=%c",
				              quic_enc_level_char(ssl_to_quic_enc_level(level)));
			}

			if (qc->err.code)
				chunk_appendf(&trace_buf, " err_code=0x%llx", (ull)qc->err.code);
		}

		if (mask & (QUIC_EV_CONN_PRSFRM|QUIC_EV_CONN_BFRM)) {
			const struct quic_frame *frm = a2;

			if (frm)
				chunk_appendf(&trace_buf, " %s", quic_frame_type_string(frm->type));
		}

		if (mask & QUIC_EV_CONN_PHPKTS) {
			const struct quic_enc_level *qel = a2;

			if (qel) {
				const struct quic_pktns *pktns = qel->pktns;
				chunk_appendf(&trace_buf,
				              " qel=%c state=%s ack?%d pto_count=%d cwnd=%llu ppif=%lld pif=%llu if=%llu pp=%u off=%llu",
				              quic_enc_level_char_from_qel(qel, qc),
				              quic_hdshk_state_str(qc->state),
				              !!(qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED),
				              qc->path->loss.pto_count,
				              (unsigned long long)qc->path->cwnd,
				              (unsigned long long)qc->path->prep_in_flight,
				              (unsigned long long)qc->path->in_flight,
				              (unsigned long long)pktns->tx.in_flight,
				              pktns->tx.pto_probe,
				              qel->cstream ? (unsigned long long)qel->cstream->rx.offset : 0);
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
			const struct quic_frame *frm = a2;
			const unsigned long *val1 = a3;
			const unsigned long *val2 = a4;

			if (frm) {
				chunk_appendf(&trace_buf, " frm@%p", frm);
				chunk_frm_appendf(&trace_buf, frm);
			}
			if (val1)
				chunk_appendf(&trace_buf, " %lu", *val1);
			if (val2)
				chunk_appendf(&trace_buf, "..%lu", *val2);
		}

		if (mask & QUIC_EV_CONN_ACKSTRM) {
			const struct quic_stream *s = a2;
			const struct qc_stream_desc *stream = a3;

			if (s)
				chunk_appendf(&trace_buf, " off=%llu len=%llu", (ull)s->offset.key, (ull)s->len);
			if (stream)
				chunk_appendf(&trace_buf, " ack_offset=%llu", (ull)stream->ack_offset);
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
				if (mask & (QUIC_EV_CONN_STIMER|QUIC_EV_CONN_SPTO)) {
					if (pktns->tx.in_flight)
						chunk_appendf(&trace_buf, " if=%llu", (ull)pktns->tx.in_flight);
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

			if (!(mask & (QUIC_EV_CONN_SPTO|QUIC_EV_CONN_PTIMER)) && qc->timer_task) {
				chunk_appendf(&trace_buf,
				              " expire=%dms", TICKS_TO_MS(qc->timer - now_ms));
			}
		}

		if (mask & QUIC_EV_CONN_SPPKTS) {
			const struct quic_tx_packet *pkt = a2;

			chunk_appendf(&trace_buf, " pto_count=%d cwnd=%llu ppif=%llu pif=%llu",
			              qc->path->loss.pto_count,
			             (unsigned long long)qc->path->cwnd,
			             (unsigned long long)qc->path->prep_in_flight,
			             (unsigned long long)qc->path->in_flight);
			if (pkt) {
				const struct quic_frame *frm;
				chunk_appendf(&trace_buf, " pn=%lu(%s) iflen=%llu",
				              (unsigned long)pkt->pn_node.key,
				              pkt->pktns == &qc->pktns[QUIC_TLS_PKTNS_INITIAL] ? "I" :
				              pkt->pktns == &qc->pktns[QUIC_TLS_PKTNS_01RTT] ? "01RTT": "H",
				              (unsigned long long)pkt->in_flight_len);
				chunk_appendf(&trace_buf, " rx.bytes=%llu tx.bytes=%llu",
				              (unsigned long long)qc->rx.bytes,
				              (unsigned long long)qc->tx.bytes);
				list_for_each_entry(frm, &pkt->frms, list) {
					chunk_appendf(&trace_buf, " frm@%p", frm);
					chunk_frm_appendf(&trace_buf, frm);
				}

				if (pkt->type == QUIC_PACKET_TYPE_INITIAL) {
					chunk_appendf(&trace_buf, " with scid");
					quic_cid_dump(&trace_buf, &qc->scid);
				}
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

			if (frm) {
				chunk_appendf(&trace_buf, " frm@%p", frm);
				chunk_frm_appendf(&trace_buf, frm);
			}
		}

		if (mask & QUIC_EV_CONN_ELEVELSEL) {
			const enum quic_handshake_state *state = a2;
			const enum quic_tls_enc_level *level = a3;
			const enum quic_tls_enc_level *next_level = a4;

			if (state)
				chunk_appendf(&trace_buf, " state=%s", quic_hdshk_state_str(qc->state));
			if (level)
				chunk_appendf(&trace_buf, " level=%c", quic_enc_level_char(*level));
			if (next_level)
				chunk_appendf(&trace_buf, " next_level=%c", quic_enc_level_char(*next_level));

		}

		if (mask & QUIC_EV_CONN_RCV) {
			const struct quic_dgram *dgram = a2;

			if (dgram)
				chunk_appendf(&trace_buf, " dgram.len=%zu", dgram->len);
		}
	}
	if (mask & QUIC_EV_CONN_LPKT) {
		const struct quic_rx_packet *pkt = a2;
		const uint64_t *len = a3;
		const struct quic_version *ver = a4;

		if (pkt) {
			chunk_appendf(&trace_buf, " pkt@%p type=0x%02x %s",
			              pkt, pkt->type, qc_pkt_long(pkt) ? "long" : "short");
			if (pkt->pn_node.key != (uint64_t)-1)
				chunk_appendf(&trace_buf, " pn=%llu", pkt->pn_node.key);
		}

		if (len)
			chunk_appendf(&trace_buf, " len=%llu", (ull)*len);

		if (ver)
			chunk_appendf(&trace_buf, " ver=0x%08x", ver->num);
	}

	if (mask & QUIC_EV_STATELESS_RST) {
		const struct quic_cid *cid = a2;

		if (cid)
			quic_cid_dump(&trace_buf, cid);
	}

}

/* Returns 1 if the peer has validated <qc> QUIC connection address, 0 if not. */
static inline int quic_peer_validated_addr(struct quic_conn *qc)
{
	struct quic_pktns *hdshk_pktns, *app_pktns;

	if (!qc_is_listener(qc))
		return 1;

	hdshk_pktns = qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE].pktns;
	app_pktns = qc->els[QUIC_TLS_ENC_LEVEL_APP].pktns;
	if ((hdshk_pktns->flags & QUIC_FL_PKTNS_PKT_RECEIVED) ||
	    (app_pktns->flags & QUIC_FL_PKTNS_PKT_RECEIVED) ||
	    qc->state >= QUIC_HS_ST_COMPLETE)
		return 1;

	return 0;
}

/* To be called to kill a connection as soon as possible (without sending any packet). */
void qc_kill_conn(struct quic_conn *qc)
{
	TRACE_ENTER(QUIC_EV_CONN_KILL, qc);
	qc->flags |= QUIC_FL_CONN_TO_KILL;
	task_wakeup(qc->idle_timer_task, TASK_WOKEN_OTHER);
	TRACE_LEAVE(QUIC_EV_CONN_KILL, qc);
}

/* Set the timer attached to the QUIC connection with <ctx> as I/O handler and used for
 * both loss detection and PTO and schedule the task assiated to this timer if needed.
 */
static inline void qc_set_timer(struct quic_conn *qc)
{
	struct quic_pktns *pktns;
	unsigned int pto;
	int handshake_confirmed;

	TRACE_ENTER(QUIC_EV_CONN_STIMER, qc,
	            NULL, NULL, &qc->path->ifae_pkts);

	pktns = NULL;
	if (!qc->timer_task) {
		TRACE_PROTO("already released timer task", QUIC_EV_CONN_STIMER, qc);
		goto leave;
	}

	pktns = quic_loss_pktns(qc);
	if (tick_isset(pktns->tx.loss_time)) {
		qc->timer = pktns->tx.loss_time;
		goto out;
	}

	/* anti-amplification: the timer must be
	 * cancelled for a server which reached the anti-amplification limit.
	 */
	if (!quic_peer_validated_addr(qc) &&
	    (qc->flags & QUIC_FL_CONN_ANTI_AMPLIFICATION_REACHED)) {
		TRACE_PROTO("anti-amplification reached", QUIC_EV_CONN_STIMER, qc);
		qc->timer = TICK_ETERNITY;
		goto out;
	}

	if (!qc->path->ifae_pkts && quic_peer_validated_addr(qc)) {
		TRACE_PROTO("timer cancellation", QUIC_EV_CONN_STIMER, qc);
		/* Timer cancellation. */
		qc->timer = TICK_ETERNITY;
		goto out;
	}

	handshake_confirmed = qc->state >= QUIC_HS_ST_CONFIRMED;
	pktns = quic_pto_pktns(qc, handshake_confirmed, &pto);
	if (tick_isset(pto))
		qc->timer = pto;
 out:
	if (qc->timer == TICK_ETERNITY) {
		qc->timer_task->expire = TICK_ETERNITY;
	}
	else  if (tick_is_expired(qc->timer, now_ms)) {
		TRACE_DEVEL("wakeup asap timer task", QUIC_EV_CONN_STIMER, qc);
		task_wakeup(qc->timer_task, TASK_WOKEN_MSG);
	}
	else {
		TRACE_DEVEL("timer task scheduling", QUIC_EV_CONN_STIMER, qc);
		task_schedule(qc->timer_task, qc->timer);
	}
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_STIMER, qc, pktns);
}

/* Derive new keys and ivs required for Key Update feature for <qc> QUIC
 * connection.
 * Return 1 if succeeded, 0 if not.
 */
static int quic_tls_key_update(struct quic_conn *qc)
{
	struct quic_tls_ctx *tls_ctx = &qc->els[QUIC_TLS_ENC_LEVEL_APP].tls_ctx;
	struct quic_tls_secrets *rx, *tx;
	struct quic_tls_kp *nxt_rx = &qc->ku.nxt_rx;
	struct quic_tls_kp *nxt_tx = &qc->ku.nxt_tx;
	const struct quic_version *ver =
		qc->negotiated_version ? qc->negotiated_version : qc->original_version;
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_RWSEC, qc);

	tls_ctx = &qc->els[QUIC_TLS_ENC_LEVEL_APP].tls_ctx;
	rx = &tls_ctx->rx;
	tx = &tls_ctx->tx;
	nxt_rx = &qc->ku.nxt_rx;
	nxt_tx = &qc->ku.nxt_tx;

	/* Prepare new RX secrets */
	if (!quic_tls_sec_update(rx->md, ver, nxt_rx->secret, nxt_rx->secretlen,
	                         rx->secret, rx->secretlen)) {
		TRACE_ERROR("New RX secret update failed", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	if (!quic_tls_derive_keys(rx->aead, NULL, rx->md, ver,
	                          nxt_rx->key, nxt_rx->keylen,
	                          nxt_rx->iv, nxt_rx->ivlen, NULL, 0,
	                          nxt_rx->secret, nxt_rx->secretlen)) {
		TRACE_ERROR("New RX key derivation failed", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	/* Prepare new TX secrets */
	if (!quic_tls_sec_update(tx->md, ver, nxt_tx->secret, nxt_tx->secretlen,
	                         tx->secret, tx->secretlen)) {
		TRACE_ERROR("New TX secret update failed", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	if (!quic_tls_derive_keys(tx->aead, NULL, tx->md, ver,
	                          nxt_tx->key, nxt_tx->keylen,
	                          nxt_tx->iv, nxt_tx->ivlen, NULL, 0,
	                          nxt_tx->secret, nxt_tx->secretlen)) {
		TRACE_ERROR("New TX key derivation failed", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	if (nxt_rx->ctx) {
		EVP_CIPHER_CTX_free(nxt_rx->ctx);
		nxt_rx->ctx = NULL;
	}

	if (!quic_tls_rx_ctx_init(&nxt_rx->ctx, tls_ctx->rx.aead, nxt_rx->key)) {
		TRACE_ERROR("could not initial RX TLS cipher context", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	if (nxt_tx->ctx) {
		EVP_CIPHER_CTX_free(nxt_tx->ctx);
		nxt_tx->ctx = NULL;
	}

	if (!quic_tls_rx_ctx_init(&nxt_tx->ctx, tls_ctx->tx.aead, nxt_tx->key)) {
		TRACE_ERROR("could not initial RX TLS cipher context", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_RWSEC, qc);
	return ret;
}

/* Rotate the Key Update information for <qc> QUIC connection.
 * Must be used after having updated them.
 * Always succeeds.
 */
static void quic_tls_rotate_keys(struct quic_conn *qc)
{
	struct quic_tls_ctx *tls_ctx = &qc->els[QUIC_TLS_ENC_LEVEL_APP].tls_ctx;
	unsigned char *curr_secret, *curr_iv, *curr_key;
	EVP_CIPHER_CTX *curr_ctx;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT, qc);

	/* Rotate the RX secrets */
	curr_ctx = tls_ctx->rx.ctx;
	curr_secret = tls_ctx->rx.secret;
	curr_iv = tls_ctx->rx.iv;
	curr_key = tls_ctx->rx.key;

	tls_ctx->rx.ctx     = qc->ku.nxt_rx.ctx;
	tls_ctx->rx.secret  = qc->ku.nxt_rx.secret;
	tls_ctx->rx.iv      = qc->ku.nxt_rx.iv;
	tls_ctx->rx.key     = qc->ku.nxt_rx.key;

	qc->ku.nxt_rx.ctx    = qc->ku.prv_rx.ctx;
	qc->ku.nxt_rx.secret = qc->ku.prv_rx.secret;
	qc->ku.nxt_rx.iv     = qc->ku.prv_rx.iv;
	qc->ku.nxt_rx.key    = qc->ku.prv_rx.key;

	qc->ku.prv_rx.ctx    = curr_ctx;
	qc->ku.prv_rx.secret = curr_secret;
	qc->ku.prv_rx.iv     = curr_iv;
	qc->ku.prv_rx.key    = curr_key;
	qc->ku.prv_rx.pn     = tls_ctx->rx.pn;

	/* Update the TX secrets */
	curr_ctx = tls_ctx->tx.ctx;
	curr_secret = tls_ctx->tx.secret;
	curr_iv = tls_ctx->tx.iv;
	curr_key = tls_ctx->tx.key;

	tls_ctx->tx.ctx    = qc->ku.nxt_tx.ctx;
	tls_ctx->tx.secret = qc->ku.nxt_tx.secret;
	tls_ctx->tx.iv     = qc->ku.nxt_tx.iv;
	tls_ctx->tx.key    = qc->ku.nxt_tx.key;

	qc->ku.nxt_tx.ctx    = curr_ctx;
	qc->ku.nxt_tx.secret = curr_secret;
	qc->ku.nxt_tx.iv     = curr_iv;
	qc->ku.nxt_tx.key    = curr_key;

	TRACE_LEAVE(QUIC_EV_CONN_RXPKT, qc);
}

/* returns 0 on error, 1 on success */
int ha_quic_set_encryption_secrets(SSL *ssl, enum ssl_encryption_level_t level,
                                   const uint8_t *read_secret,
                                   const uint8_t *write_secret, size_t secret_len)
{
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);
	struct quic_tls_ctx *tls_ctx = &qc->els[ssl_to_quic_enc_level(level)].tls_ctx;
	const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
	struct quic_tls_secrets *rx = NULL, *tx = NULL;
	const struct quic_version *ver =
		qc->negotiated_version ? qc->negotiated_version : qc->original_version;
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_RWSEC, qc);
	BUG_ON(secret_len > QUIC_TLS_SECRET_LEN);

	if (qc->flags & QUIC_FL_CONN_TO_KILL) {
		TRACE_PROTO("connection to be killed", QUIC_EV_CONN_ADDDATA, qc);
		goto out;
	}

	if (qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE) {
		TRACE_PROTO("CC required", QUIC_EV_CONN_RWSEC, qc);
		goto out;
	}

	if (!read_secret)
		goto write;

	rx = &tls_ctx->rx;
	if (!quic_tls_secrets_keys_alloc(rx)) {
		TRACE_ERROR("RX keys allocation failed", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	rx->aead = tls_aead(cipher);
	rx->md   = tls_md(cipher);
	rx->hp   = tls_hp(cipher);

	if (!quic_tls_derive_keys(rx->aead, rx->hp, rx->md, ver, rx->key, rx->keylen,
	                          rx->iv, rx->ivlen, rx->hp_key, sizeof rx->hp_key,
	                          read_secret, secret_len)) {
		TRACE_ERROR("TX key derivation failed", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	if (!quic_tls_rx_ctx_init(&rx->ctx, rx->aead, rx->key)) {
		TRACE_ERROR("could not initial RX TLS cipher context", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	if (!quic_tls_dec_aes_ctx_init(&rx->hp_ctx, rx->hp, rx->hp_key)) {
		TRACE_ERROR("could not initial RX TLS cipher context for HP", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	/* Enqueue this connection asap if we could derive O-RTT secrets as
	 * listener. Note that a listener derives only RX secrets for this
	 * level.
	 */
	if (qc_is_listener(qc) && level == ssl_encryption_early_data) {
		TRACE_DEVEL("pushing connection into accept queue", QUIC_EV_CONN_RWSEC, qc);
		quic_accept_push_qc(qc);
	}

write:

	if (!write_secret)
		goto out;

	tx = &tls_ctx->tx;
	if (!quic_tls_secrets_keys_alloc(tx)) {
		TRACE_ERROR("TX keys allocation failed", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	tx->aead = tls_aead(cipher);
	tx->md   = tls_md(cipher);
	tx->hp   = tls_hp(cipher);

	if (!quic_tls_derive_keys(tx->aead, tx->hp, tx->md, ver, tx->key, tx->keylen,
	                          tx->iv, tx->ivlen, tx->hp_key, sizeof tx->hp_key,
	                          write_secret, secret_len)) {
		TRACE_ERROR("TX key derivation failed", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	if (!quic_tls_tx_ctx_init(&tx->ctx, tx->aead, tx->key)) {
		TRACE_ERROR("could not initial RX TLS cipher context", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	if (!quic_tls_enc_aes_ctx_init(&tx->hp_ctx, tx->hp, tx->hp_key)) {
		TRACE_ERROR("could not initial TX TLS cipher context for HP", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	if (level == ssl_encryption_handshake && qc_is_listener(qc)) {
		qc->enc_params_len =
			quic_transport_params_encode(qc->enc_params,
			                             qc->enc_params + sizeof qc->enc_params,
			                             &qc->rx.params, ver, 1);
		if (!qc->enc_params_len) {
			TRACE_ERROR("quic_transport_params_encode() failed", QUIC_EV_CONN_RWSEC);
			goto leave;
		}

		if (!SSL_set_quic_transport_params(qc->xprt_ctx->ssl, qc->enc_params, qc->enc_params_len)) {
			TRACE_ERROR("SSL_set_quic_transport_params() failed", QUIC_EV_CONN_RWSEC);
			goto leave;
		}
	}

	if (level == ssl_encryption_application) {
		struct quic_tls_kp *prv_rx = &qc->ku.prv_rx;
		struct quic_tls_kp *nxt_rx = &qc->ku.nxt_rx;
		struct quic_tls_kp *nxt_tx = &qc->ku.nxt_tx;

		if (rx) {
			if (!(rx->secret = pool_alloc(pool_head_quic_tls_secret))) {
				TRACE_ERROR("Could not allocate RX Application secrete keys", QUIC_EV_CONN_RWSEC, qc);
				goto leave;
			}

			memcpy(rx->secret, read_secret, secret_len);
			rx->secretlen = secret_len;
		}

		if (tx) {
			if (!(tx->secret = pool_alloc(pool_head_quic_tls_secret))) {
				TRACE_ERROR("Could not allocate TX Application secrete keys", QUIC_EV_CONN_RWSEC, qc);
				goto leave;
			}

			memcpy(tx->secret, write_secret, secret_len);
			tx->secretlen = secret_len;
		}

		/* Initialize all the secret keys lengths */
		prv_rx->secretlen = nxt_rx->secretlen = nxt_tx->secretlen = secret_len;
	}

 out:
	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_RWSEC, qc, &level);
	return ret;
}

/* This function copies the CRYPTO data provided by the TLS stack found at <data>
 * with <len> as size in CRYPTO buffers dedicated to store the information about
 * outgoing CRYPTO frames so that to be able to replay the CRYPTO data streams.
 * It fails (returns 0) only if it could not managed to allocate enough CRYPTO
 * buffers to store all the data.
 * Note that CRYPTO data may exist at any encryption level except at 0-RTT.
 */
static int quic_crypto_data_cpy(struct quic_conn *qc, struct quic_enc_level *qel,
                                const unsigned char *data, size_t len)
{
	struct quic_crypto_buf **qcb;
	/* The remaining byte to store in CRYPTO buffers. */
	size_t cf_offset, cf_len, *nb_buf;
	unsigned char *pos;
	int ret = 0;

	nb_buf = &qel->tx.crypto.nb_buf;
	qcb = &qel->tx.crypto.bufs[*nb_buf - 1];
	cf_offset = (*nb_buf - 1) * QUIC_CRYPTO_BUF_SZ + (*qcb)->sz;
	cf_len = len;

	TRACE_ENTER(QUIC_EV_CONN_ADDDATA, qc);

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
			len -= to_copy;
			data += to_copy;
		}
		else {
			struct quic_crypto_buf **tmp;

			// FIXME: realloc!
			tmp = realloc(qel->tx.crypto.bufs,
			              (*nb_buf + 1) * sizeof *qel->tx.crypto.bufs);
			if (tmp) {
				qel->tx.crypto.bufs = tmp;
				qcb = &qel->tx.crypto.bufs[*nb_buf];
				*qcb = pool_alloc(pool_head_quic_crypto_buf);
				if (!*qcb) {
					TRACE_ERROR("Could not allocate crypto buf", QUIC_EV_CONN_ADDDATA, qc);
					goto leave;
				}

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
		struct quic_frame *frm;
		struct quic_frame *found = NULL;

		/* There is at most one CRYPTO frame in this packet number
		 * space. Let's look for it.
		 */
		list_for_each_entry(frm, &qel->pktns->tx.frms, list) {
			if (frm->type != QUIC_FT_CRYPTO)
				continue;

			/* Found */
			found = frm;
			break;
		}

		if (found) {
			found->crypto.len += cf_len;
		}
		else {
			frm = qc_frm_alloc(QUIC_FT_CRYPTO);
			if (!frm) {
				TRACE_ERROR("Could not allocate quic frame", QUIC_EV_CONN_ADDDATA, qc);
				goto leave;
			}

			frm->crypto.offset = cf_offset;
			frm->crypto.len = cf_len;
			frm->crypto.qel = qel;
			LIST_APPEND(&qel->pktns->tx.frms, &frm->list);
		}
	}
	ret = len == 0;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_ADDDATA, qc);
	return ret;
}

/* Prepare the emission of CONNECTION_CLOSE with error <err>. All send/receive
 * activity for <qc> will be interrupted.
 */
void quic_set_connection_close(struct quic_conn *qc, const struct quic_err err)
{
	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);
	if (qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE)
		goto leave;

	TRACE_STATE("setting immediate close", QUIC_EV_CONN_CLOSE, qc);
	qc->flags |= QUIC_FL_CONN_IMMEDIATE_CLOSE;
	qc->err.code = err.code;
	qc->err.app  = err.app;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);
}

/* Set <alert> TLS alert as QUIC CRYPTO_ERROR error */
void quic_set_tls_alert(struct quic_conn *qc, int alert)
{
	TRACE_ENTER(QUIC_EV_CONN_SSLALERT, qc);

	if (!(qc->flags & QUIC_FL_CONN_HALF_OPEN_CNT_DECREMENTED)) {
		qc->flags |= QUIC_FL_CONN_HALF_OPEN_CNT_DECREMENTED;
		TRACE_DEVEL("dec half open counter", QUIC_EV_CONN_SSLALERT, qc);
		HA_ATOMIC_DEC(&qc->prx_counters->half_open_conn);
	}
	quic_set_connection_close(qc, quic_err_tls(alert));
	qc->flags |= QUIC_FL_CONN_TLS_ALERT;
	TRACE_STATE("Alert set", QUIC_EV_CONN_SSLALERT, qc);

	TRACE_LEAVE(QUIC_EV_CONN_SSLALERT, qc);
}

/* Set the application for <qc> QUIC connection.
 * Return 1 if succeeded, 0 if not.
 */
int quic_set_app_ops(struct quic_conn *qc, const unsigned char *alpn, size_t alpn_len)
{
	if (alpn_len >= 2 && memcmp(alpn, "h3", 2) == 0)
		qc->app_ops = &h3_ops;
	else if (alpn_len >= 10 && memcmp(alpn, "hq-interop", 10) == 0)
		qc->app_ops = &hq_interop_ops;
	else
		return 0;

	return 1;
}

/* ->add_handshake_data QUIC TLS callback used by the QUIC TLS stack when it
 * wants to provide the QUIC layer with CRYPTO data.
 * Returns 1 if succeeded, 0 if not.
 */
int ha_quic_add_handshake_data(SSL *ssl, enum ssl_encryption_level_t level,
                               const uint8_t *data, size_t len)
{
	struct quic_conn *qc;
	enum quic_tls_enc_level tel;
	struct quic_enc_level *qel;
	int ret = 0;

	qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);
	TRACE_ENTER(QUIC_EV_CONN_ADDDATA, qc);

	if (qc->flags & QUIC_FL_CONN_TO_KILL) {
		TRACE_PROTO("connection to be killed", QUIC_EV_CONN_ADDDATA, qc);
		goto out;
	}

	if (qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE) {
		TRACE_PROTO("CC required", QUIC_EV_CONN_ADDDATA, qc);
		goto out;
	}

	tel = ssl_to_quic_enc_level(level);
	if (tel == -1) {
		TRACE_ERROR("Wrong encryption level", QUIC_EV_CONN_ADDDATA, qc);
		goto leave;
	}

	qel = &qc->els[tel];
	if (!quic_crypto_data_cpy(qc, qel, data, len)) {
		TRACE_ERROR("Could not bufferize", QUIC_EV_CONN_ADDDATA, qc);
		goto leave;
	}

	TRACE_DEVEL("CRYPTO data buffered", QUIC_EV_CONN_ADDDATA,
	            qc, &level, &len);
 out:
	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_ADDDATA, qc);
	return ret;
}

int ha_quic_flush_flight(SSL *ssl)
{
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);

	TRACE_ENTER(QUIC_EV_CONN_FFLIGHT, qc);
	TRACE_LEAVE(QUIC_EV_CONN_FFLIGHT, qc);

	return 1;
}

int ha_quic_send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert)
{
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);

	TRACE_ENTER(QUIC_EV_CONN_SSLALERT, qc);

	TRACE_PROTO("Received TLS alert", QUIC_EV_CONN_SSLALERT, qc, &alert, &level);

	quic_set_tls_alert(qc, alert);
	TRACE_LEAVE(QUIC_EV_CONN_SSLALERT, qc);
	return 1;
}

/* QUIC TLS methods */
static SSL_QUIC_METHOD ha_quic_method = {
	.set_encryption_secrets = ha_quic_set_encryption_secrets,
	.add_handshake_data     = ha_quic_add_handshake_data,
	.flush_flight           = ha_quic_flush_flight,
	.send_alert             = ha_quic_send_alert,
};

/* Initialize the TLS context of a listener with <bind_conf> as configuration.
 * Returns an error count.
 */
int ssl_quic_initial_ctx(struct bind_conf *bind_conf)
{
	struct ssl_bind_conf __maybe_unused *ssl_conf_cur;
	int cfgerr = 0;

	long options =
		(SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
		SSL_OP_SINGLE_ECDH_USE |
		SSL_OP_CIPHER_SERVER_PREFERENCE;
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(TLS_server_method());
	bind_conf->initial_ctx = ctx;

	SSL_CTX_set_options(ctx, options);
	SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
# if defined(HAVE_SSL_CLIENT_HELLO_CB)
#  if defined(SSL_OP_NO_ANTI_REPLAY)
	if (bind_conf->ssl_conf.early_data) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_ANTI_REPLAY);
		SSL_CTX_set_max_early_data(ctx, 0xffffffff);
	}
#  endif /* !SSL_OP_NO_ANTI_REPLAY */
	SSL_CTX_set_client_hello_cb(ctx, ssl_sock_switchctx_cbk, NULL);
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_err_cbk);
# else /* ! HAVE_SSL_CLIENT_HELLO_CB */
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_cbk);
# endif
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
static int qc_do_rm_hp(struct quic_conn *qc,
                       struct quic_rx_packet *pkt, struct quic_tls_ctx *tls_ctx,
                       int64_t largest_pn, unsigned char *pn, unsigned char *byte0)
{
	int ret, i, pnlen;
	uint64_t packet_number;
	uint32_t truncated_pn = 0;
	unsigned char mask[5] = {0};
	unsigned char *sample;
	EVP_CIPHER_CTX *cctx = NULL;

	TRACE_ENTER(QUIC_EV_CONN_RMHP, qc);

	ret = 0;

	/* Check there is enough data in this packet. */
	if (pkt->len - (pn - byte0) < QUIC_PACKET_PN_MAXLEN + sizeof mask) {
		TRACE_PROTO("too short packet", QUIC_EV_CONN_RMHP, qc, pkt);
		goto leave;
	}

	cctx = EVP_CIPHER_CTX_new();
	if (!cctx) {
		TRACE_ERROR("memory allocation failed", QUIC_EV_CONN_RMHP, qc, pkt);
		goto leave;
	}

	sample = pn + QUIC_PACKET_PN_MAXLEN;

	if (!quic_tls_aes_decrypt(mask, sample, sizeof mask, tls_ctx->rx.hp_ctx)) {
		TRACE_ERROR("HP removing failed", QUIC_EV_CONN_RMHP, qc, pkt);
		goto leave;
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
 leave:
	if (cctx)
		EVP_CIPHER_CTX_free(cctx);
	TRACE_LEAVE(QUIC_EV_CONN_RMHP, qc);
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
                               struct quic_tls_ctx *tls_ctx, struct quic_conn *qc)
{
	int ret = 0;
	unsigned char iv[QUIC_TLS_IV_LEN];
	unsigned char *tx_iv = tls_ctx->tx.iv;
	size_t tx_iv_sz = tls_ctx->tx.ivlen;
	struct enc_debug_info edi;

	TRACE_ENTER(QUIC_EV_CONN_ENCPKT, qc);

	if (!quic_aead_iv_build(iv, sizeof iv, tx_iv, tx_iv_sz, pn)) {
		TRACE_ERROR("AEAD IV building for encryption failed", QUIC_EV_CONN_ENCPKT, qc);
		goto err;
	}

	if (!quic_tls_encrypt(payload, payload_len, aad, aad_len,
	                      tls_ctx->tx.ctx, tls_ctx->tx.aead, tls_ctx->tx.key, iv)) {
		TRACE_ERROR("QUIC packet encryption failed", QUIC_EV_CONN_ENCPKT, qc);
		goto err;
	}

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_ENCPKT, qc);
	return ret;

 err:
	enc_debug_info_init(&edi, payload, payload_len, aad, aad_len, pn);
	goto leave;
}

/* Decrypt <pkt> packet using encryption level <qel> for <qc> connection.
 * Decryption is done in place in packet buffer.
 *
 * Returns 1 on success else 0.
 */
static int qc_pkt_decrypt(struct quic_conn *qc, struct quic_enc_level *qel,
                          struct quic_rx_packet *pkt)
{
	int ret, kp_changed;
	unsigned char iv[QUIC_TLS_IV_LEN];
	struct quic_tls_ctx *tls_ctx = &qel->tls_ctx;
	EVP_CIPHER_CTX *rx_ctx = tls_ctx->rx.ctx;
	unsigned char *rx_iv = tls_ctx->rx.iv;
	size_t rx_iv_sz = tls_ctx->rx.ivlen;
	unsigned char *rx_key = tls_ctx->rx.key;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT, qc);

	ret = 0;
	kp_changed = 0;

	if (pkt->type == QUIC_PACKET_TYPE_SHORT) {
		/* The two tested bits are not at the same position,
		 * this is why they are first both inversed.
		 */
		if (!(*pkt->data & QUIC_PACKET_KEY_PHASE_BIT) ^ !(tls_ctx->flags & QUIC_FL_TLS_KP_BIT_SET)) {
			if (pkt->pn < tls_ctx->rx.pn) {
				/* The lowest packet number of a previous key phase
				 * cannot be null if it really stores previous key phase
				 * secrets.
				 */
				// TODO: check if BUG_ON() more suitable
				if (!qc->ku.prv_rx.pn) {
					TRACE_ERROR("null previous packet number", QUIC_EV_CONN_RXPKT, qc);
					goto leave;
				}

				rx_ctx = qc->ku.prv_rx.ctx;
				rx_iv  = qc->ku.prv_rx.iv;
				rx_key = qc->ku.prv_rx.key;
			}
			else if (pkt->pn > qel->pktns->rx.largest_pn) {
				/* Next key phase */
				kp_changed = 1;
				rx_ctx = qc->ku.nxt_rx.ctx;
				rx_iv  = qc->ku.nxt_rx.iv;
				rx_key = qc->ku.nxt_rx.key;
			}
		}
	}

	if (!quic_aead_iv_build(iv, sizeof iv, rx_iv, rx_iv_sz, pkt->pn)) {
		TRACE_ERROR("quic_aead_iv_build() failed", QUIC_EV_CONN_RXPKT, qc);
		goto leave;
	}

	ret = quic_tls_decrypt(pkt->data + pkt->aad_len, pkt->len - pkt->aad_len,
	                       pkt->data, pkt->aad_len,
	                       rx_ctx, tls_ctx->rx.aead, rx_key, iv);
	if (!ret) {
		TRACE_ERROR("quic_tls_decrypt() failed", QUIC_EV_CONN_RXPKT, qc);
		goto leave;
	}

	/* Update the keys only if the packet decryption succeeded. */
	if (kp_changed) {
		quic_tls_rotate_keys(qc);
		/* Toggle the Key Phase bit */
		tls_ctx->flags ^= QUIC_FL_TLS_KP_BIT_SET;
		/* Store the lowest packet number received for the current key phase */
		tls_ctx->rx.pn = pkt->pn;
		/* Prepare the next key update */
		if (!quic_tls_key_update(qc)) {
			TRACE_ERROR("quic_tls_key_update() failed", QUIC_EV_CONN_RXPKT, qc);
			goto leave;
		}
	}

	/* Update the packet length (required to parse the frames). */
	pkt->len -= QUIC_TLS_TAG_LEN;
	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_RXPKT, qc);
	return ret;
}


/* Release <frm> frame and mark its copies as acknowledged */
void qc_release_frm(struct quic_conn *qc, struct quic_frame *frm)
{
	uint64_t pn;
	struct quic_frame *origin, *f, *tmp;

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);

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
			qc_frm_free(&f);
		}
	}
	LIST_DEL_INIT(&frm->list);
	pn = frm->pkt->pn_node.key;
	quic_tx_packet_refdec(frm->pkt);
	TRACE_DEVEL("freeing frame from packet",
	            QUIC_EV_CONN_PRSAFRM, qc, frm, &pn);
	qc_frm_free(&frm);

	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
}

/* Schedule a CONNECTION_CLOSE emission on <qc> if the MUX has been released
 * and all STREAM data are acknowledged. The MUX is responsible to have set
 * <qc.err> before as it is reused for the CONNECTION_CLOSE frame.
 *
 * TODO this should also be called on lost packet detection
 */
void qc_check_close_on_released_mux(struct quic_conn *qc)
{
	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);

	if (qc->mux_state == QC_MUX_RELEASED && eb_is_empty(&qc->streams_by_id)) {
		/* Reuse errcode which should have been previously set by the MUX on release. */
		quic_set_connection_close(qc, qc->err);
		tasklet_wakeup(qc->wait_event.tasklet);
	}

	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);
}

/* Remove from <stream> the acknowledged frames.
 *
 * Returns 1 if at least one frame was removed else 0.
 */
static int quic_stream_try_to_consume(struct quic_conn *qc,
                                      struct qc_stream_desc *stream)
{
	int ret;
	struct eb64_node *frm_node;

	TRACE_ENTER(QUIC_EV_CONN_ACKSTRM, qc);

	ret = 0;
	frm_node = eb64_first(&stream->acked_frms);
	while (frm_node) {
		struct quic_stream *strm;
		struct quic_frame *frm;
		size_t offset, len;

		strm = eb64_entry(frm_node, struct quic_stream, offset);
		offset = strm->offset.key;
		len = strm->len;

		if (offset > stream->ack_offset)
			break;

		if (qc_stream_desc_ack(&stream, offset, len)) {
			/* cf. next comment : frame may be freed at this stage. */
			TRACE_DEVEL("stream consumed", QUIC_EV_CONN_ACKSTRM,
			            qc, stream ? strm : NULL, stream);
			ret = 1;
		}

		/* If stream is NULL after qc_stream_desc_ack(), it means frame
		 * has been freed. with the stream frames tree. Nothing to do
		 * anymore in here.
		 */
		if (!stream) {
			qc_check_close_on_released_mux(qc);
			ret = 1;
			goto leave;
		}

		frm_node = eb64_next(frm_node);
		eb64_delete(&strm->offset);

		frm = container_of(strm, struct quic_frame, stream);
		qc_release_frm(qc, frm);
	}

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_ACKSTRM, qc);
	return ret;
}

/* Treat <frm> frame whose packet it is attached to has just been acknowledged. */
static inline void qc_treat_acked_tx_frm(struct quic_conn *qc,
                                         struct quic_frame *frm)
{
	int stream_acked;

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc, frm);

	stream_acked = 0;
	switch (frm->type) {
	case QUIC_FT_STREAM_8 ... QUIC_FT_STREAM_F:
	{
		struct quic_stream *strm_frm = &frm->stream;
		struct eb64_node *node = NULL;
		struct qc_stream_desc *stream = NULL;
		const size_t offset = strm_frm->offset.key;
		const size_t len = strm_frm->len;

		/* do not use strm_frm->stream as the qc_stream_desc instance
		 * might be freed at this stage. Use the id to do a proper
		 * lookup.
		 *
		 * TODO if lookup operation impact on the perf is noticeable,
		 * implement a refcount on qc_stream_desc instances.
		 */
		node = eb64_lookup(&qc->streams_by_id, strm_frm->id);
		if (!node) {
			TRACE_DEVEL("acked stream for released stream", QUIC_EV_CONN_ACKSTRM, qc, strm_frm);
			qc_release_frm(qc, frm);
			/* early return */
			goto leave;
		}
		stream = eb64_entry(node, struct qc_stream_desc, by_id);

		TRACE_DEVEL("acked stream", QUIC_EV_CONN_ACKSTRM, qc, strm_frm, stream);
		if (offset <= stream->ack_offset) {
			if (qc_stream_desc_ack(&stream, offset, len)) {
				stream_acked = 1;
				TRACE_DEVEL("stream consumed", QUIC_EV_CONN_ACKSTRM,
				            qc, strm_frm, stream);
			}

			if (!stream) {
				/* no need to continue if stream freed. */
				TRACE_DEVEL("stream released and freed", QUIC_EV_CONN_ACKSTRM, qc);
				qc_release_frm(qc, frm);
				qc_check_close_on_released_mux(qc);
				break;
			}

			TRACE_DEVEL("stream consumed", QUIC_EV_CONN_ACKSTRM,
			            qc, strm_frm, stream);
			qc_release_frm(qc, frm);
		}
		else {
			eb64_insert(&stream->acked_frms, &strm_frm->offset);
		}

		stream_acked |= quic_stream_try_to_consume(qc, stream);
	}
	break;
	default:
		qc_release_frm(qc, frm);
	}

	if (stream_acked) {
		if (qc->subs && qc->subs->events & SUB_RETRY_SEND) {
			tasklet_wakeup(qc->subs->tasklet);
			qc->subs->events &= ~SUB_RETRY_SEND;
			if (!qc->subs->events)
				qc->subs = NULL;
		}
	}
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
}

/* Remove <largest> down to <smallest> node entries from <pkts> tree of TX packet,
 * deallocating them, and their TX frames.
 * Returns the last node reached to be used for the next range.
 * May be NULL if <largest> node could not be found.
 */
static inline struct eb64_node *qc_ackrng_pkts(struct quic_conn *qc,
                                               struct eb_root *pkts,
                                               unsigned int *pkt_flags,
                                               struct list *newly_acked_pkts,
                                               struct eb64_node *largest_node,
                                               uint64_t largest, uint64_t smallest)
{
	struct eb64_node *node;
	struct quic_tx_packet *pkt;

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);

	node = largest_node ? largest_node : eb64_lookup_le(pkts, largest);
	while (node && node->key >= smallest) {
		struct quic_frame *frm, *frmbak;

		pkt = eb64_entry(node, struct quic_tx_packet, pn_node);
		*pkt_flags |= pkt->flags;
		LIST_INSERT(newly_acked_pkts, &pkt->list);
		TRACE_DEVEL("Removing packet #", QUIC_EV_CONN_PRSAFRM, qc, NULL, &pkt->pn_node.key);
		list_for_each_entry_safe(frm, frmbak, &pkt->frms, list)
			qc_treat_acked_tx_frm(qc, frm);
		/* If there are others packet in the same datagram <pkt> is attached to,
		 * detach the previous one and the next one from <pkt>.
		 */
		quic_tx_packet_dgram_detach(pkt);
		node = eb64_prev(node);
		eb64_delete(&pkt->pn_node);
	}

	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
	return node;
}

/* Remove all frames from <pkt_frm_list> and reinsert them in the same order
 * they have been sent into <pktns_frm_list>. The loss counter of each frame is
 * incremented and checked if it does not exceed retransmission limit.
 *
 * Returns 1 on success, 0 if a frame loss limit is exceeded. A
 * CONNECTION_CLOSE is scheduled in this case.
 */
static inline int qc_requeue_nacked_pkt_tx_frms(struct quic_conn *qc,
                                                struct quic_tx_packet *pkt,
                                                struct list *pktns_frm_list)
{
	struct quic_frame *frm, *frmbak;
	struct list tmp = LIST_HEAD_INIT(tmp);
	struct list *pkt_frm_list = &pkt->frms;
	uint64_t pn = pkt->pn_node.key;
	int close = 0;

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);

	list_for_each_entry_safe(frm, frmbak, pkt_frm_list, list) {
		/* First remove this frame from the packet it was attached to */
		LIST_DEL_INIT(&frm->list);
		quic_tx_packet_refdec(pkt);
		/* At this time, this frame is not freed but removed from its packet */
		frm->pkt = NULL;
		/* Remove any reference to this frame */
		qc_frm_unref(frm, qc);
		switch (frm->type) {
		case QUIC_FT_STREAM_8 ... QUIC_FT_STREAM_F:
		{
			struct quic_stream *strm_frm = &frm->stream;
			struct eb64_node *node = NULL;
			struct qc_stream_desc *stream_desc;

			node = eb64_lookup(&qc->streams_by_id, strm_frm->id);
			if (!node) {
				TRACE_DEVEL("released stream", QUIC_EV_CONN_PRSAFRM, qc, frm);
				TRACE_DEVEL("freeing frame from packet", QUIC_EV_CONN_PRSAFRM,
				            qc, frm, &pn);
				qc_frm_free(&frm);
				continue;
			}

			stream_desc = eb64_entry(node, struct qc_stream_desc, by_id);
			/* Do not resend this frame if in the "already acked range" */
			if (strm_frm->offset.key + strm_frm->len <= stream_desc->ack_offset) {
				TRACE_DEVEL("ignored frame in already acked range",
				            QUIC_EV_CONN_PRSAFRM, qc, frm);
				qc_frm_free(&frm);
				continue;
			}
			else if (strm_frm->offset.key < stream_desc->ack_offset) {
				strm_frm->offset.key = stream_desc->ack_offset;
				TRACE_DEVEL("updated partially acked frame",
				            QUIC_EV_CONN_PRSAFRM, qc, frm);
			}
			break;
		}

		default:
			break;
		}

		/* Do not resend probing packet with old data */
		if (pkt->flags & QUIC_FL_TX_PACKET_PROBE_WITH_OLD_DATA) {
			TRACE_DEVEL("ignored frame with old data from packet", QUIC_EV_CONN_PRSAFRM,
				    qc, frm, &pn);
			if (frm->origin)
				LIST_DEL_INIT(&frm->ref);
			qc_frm_free(&frm);
			continue;
		}

		if (frm->flags & QUIC_FL_TX_FRAME_ACKED) {
			TRACE_DEVEL("already acked frame", QUIC_EV_CONN_PRSAFRM, qc, frm);
			TRACE_DEVEL("freeing frame from packet", QUIC_EV_CONN_PRSAFRM,
			            qc, frm, &pn);
			qc_frm_free(&frm);
		}
		else {
			if (++frm->loss_count >= global.tune.quic_max_frame_loss) {
				TRACE_ERROR("retransmission limit reached, closing the connection", QUIC_EV_CONN_PRSAFRM, qc);
				quic_set_connection_close(qc, quic_err_transport(QC_ERR_INTERNAL_ERROR));
				close = 1;
			}

			if (QUIC_FT_STREAM_8 <= frm->type && frm->type <= QUIC_FT_STREAM_F) {
				/* Mark this STREAM frame as lost. A look up their stream descriptor
				 * will be performed to check the stream is not consumed or released.
				 */
				frm->flags |= QUIC_FL_TX_FRAME_LOST;
			}
			LIST_APPEND(&tmp, &frm->list);
			TRACE_DEVEL("frame requeued", QUIC_EV_CONN_PRSAFRM, qc, frm);
		}
	}

	LIST_SPLICE(pktns_frm_list, &tmp);

 end:
	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
	return !close;
}

/* Free <pkt> TX packet and its attached frames.
 * This is the responsibility of the caller to remove this packet of
 * any data structure it was possibly attached to.
 */
static inline void free_quic_tx_packet(struct quic_conn *qc,
                                       struct quic_tx_packet *pkt)
{
	struct quic_frame *frm, *frmbak;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	if (!pkt)
		goto leave;

	list_for_each_entry_safe(frm, frmbak, &pkt->frms, list)
		qc_frm_free(&frm);
	pool_free(pool_head_quic_tx_packet, pkt);

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
}

/* Free the TX packets of <pkts> list */
static inline void free_quic_tx_pkts(struct quic_conn *qc, struct list *pkts)
{
	struct quic_tx_packet *pkt, *tmp;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	list_for_each_entry_safe(pkt, tmp, pkts, list) {
		LIST_DELETE(&pkt->list);
		eb64_delete(&pkt->pn_node);
		free_quic_tx_packet(qc, pkt);
	}

	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
}

/* Remove already sent ranges of acknowledged packet numbers from
 * <pktns> packet number space tree below <largest_acked_pn> possibly
 * updating the range which contains <largest_acked_pn>.
 * Never fails.
 */
static void qc_treat_ack_of_ack(struct quic_conn *qc,
                                struct quic_pktns *pktns,
                                int64_t largest_acked_pn)
{
	struct eb64_node *ar, *next_ar;
	struct quic_arngs *arngs = &pktns->rx.arngs;

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);

	ar = eb64_first(&arngs->root);
	while (ar) {
		struct quic_arng_node *ar_node;

		next_ar = eb64_next(ar);
		ar_node = eb64_entry(ar, struct quic_arng_node, first);

		if ((int64_t)ar_node->first.key > largest_acked_pn) {
			TRACE_DEVEL("first.key > largest", QUIC_EV_CONN_PRSAFRM, qc);
			break;
		}

		if (largest_acked_pn < ar_node->last) {
			eb64_delete(ar);
			ar_node->first.key = largest_acked_pn + 1;
			eb64_insert(&arngs->root, ar);
			break;
		}

		eb64_delete(ar);
		pool_free(pool_head_quic_arng, ar_node);
		arngs->sz--;
		ar = next_ar;
	}

	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
}

/* Send a packet ack event nofication for each newly acked packet of
 * <newly_acked_pkts> list and free them.
 * Always succeeds.
 */
static inline void qc_treat_newly_acked_pkts(struct quic_conn *qc,
                                             struct list *newly_acked_pkts)
{
	struct quic_tx_packet *pkt, *tmp;
	struct quic_cc_event ev = { .type = QUIC_CC_EVT_ACK, };

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);

	list_for_each_entry_safe(pkt, tmp, newly_acked_pkts, list) {
		pkt->pktns->tx.in_flight -= pkt->in_flight_len;
		qc->path->prep_in_flight -= pkt->in_flight_len;
		qc->path->in_flight -= pkt->in_flight_len;
		if (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING)
			qc->path->ifae_pkts--;
		/* If this packet contained an ACK frame, proceed to the
		 * acknowledging of range of acks from the largest acknowledged
		 * packet number which was sent in an ACK frame by this packet.
		 */
		if (pkt->largest_acked_pn != -1)
			qc_treat_ack_of_ack(qc, pkt->pktns, pkt->largest_acked_pn);
		ev.ack.acked = pkt->in_flight_len;
		ev.ack.time_sent = pkt->time_sent;
		quic_cc_event(&qc->path->cc, &ev);
		LIST_DELETE(&pkt->list);
		eb64_delete(&pkt->pn_node);
		quic_tx_packet_refdec(pkt);
	}

	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);

}

/* Release all the frames attached to <pktns> packet number space */
static inline void qc_release_pktns_frms(struct quic_conn *qc,
                                         struct quic_pktns *pktns)
{
	struct quic_frame *frm, *frmbak;

	TRACE_ENTER(QUIC_EV_CONN_PHPKTS, qc);

	list_for_each_entry_safe(frm, frmbak, &pktns->tx.frms, list)
		qc_frm_free(&frm);

	TRACE_LEAVE(QUIC_EV_CONN_PHPKTS, qc);
}

/* Handle <pkts> list of lost packets detected at <now_us> handling their TX
 * frames. Send a packet loss event to the congestion controller if in flight
 * packet have been lost. Also frees the packet in <pkts> list.
 *
 * Returns 1 on success else 0 if loss limit has been exceeded. A
 * CONNECTION_CLOSE was prepared to close the connection ASAP.
 */
static inline int qc_release_lost_pkts(struct quic_conn *qc,
                                       struct quic_pktns *pktns,
                                       struct list *pkts,
                                       uint64_t now_us)
{
	struct quic_tx_packet *pkt, *tmp, *oldest_lost, *newest_lost;
	int close = 0;

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);

	if (LIST_ISEMPTY(pkts))
		goto leave;

	oldest_lost = newest_lost = NULL;
	list_for_each_entry_safe(pkt, tmp, pkts, list) {
		struct list tmp = LIST_HEAD_INIT(tmp);

		pkt->pktns->tx.in_flight -= pkt->in_flight_len;
		qc->path->prep_in_flight -= pkt->in_flight_len;
		qc->path->in_flight -= pkt->in_flight_len;
		if (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING)
			qc->path->ifae_pkts--;
		/* Treat the frames of this lost packet. */
		if (!qc_requeue_nacked_pkt_tx_frms(qc, pkt, &pktns->tx.frms))
			close = 1;
		LIST_DELETE(&pkt->list);
		if (!oldest_lost) {
			oldest_lost = newest_lost = pkt;
		}
		else {
			if (newest_lost != oldest_lost)
				quic_tx_packet_refdec(newest_lost);
			newest_lost = pkt;
		}
	}

	if (!close) {
		if (newest_lost) {
			/* Sent a congestion event to the controller */
			struct quic_cc_event ev = { };

			ev.type = QUIC_CC_EVT_LOSS;
			ev.loss.time_sent = newest_lost->time_sent;

			quic_cc_event(&qc->path->cc, &ev);
		}

		/* If an RTT have been already sampled, <rtt_min> has been set.
		 * We must check if we are experiencing a persistent congestion.
		 * If this is the case, the congestion controller must re-enter
		 * slow start state.
		 */
		if (qc->path->loss.rtt_min && newest_lost != oldest_lost) {
			unsigned int period = newest_lost->time_sent - oldest_lost->time_sent;

			if (quic_loss_persistent_congestion(&qc->path->loss, period,
							    now_ms, qc->max_ack_delay))
				qc->path->cc.algo->slow_start(&qc->path->cc);
		}
	}

	/* <oldest_lost> cannot be NULL at this stage because we have ensured
	 * that <pkts> list is not empty. Without this, GCC 12.2.0 reports a
	 * possible overflow on a 0 byte region with O2 optimization.
	 */
	ALREADY_CHECKED(oldest_lost);
	quic_tx_packet_refdec(oldest_lost);
	if (newest_lost != oldest_lost)
		quic_tx_packet_refdec(newest_lost);

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
	return !close;
}

/* Parse ACK frame into <frm> from a buffer at <buf> address with <end> being at
 * one byte past the end of this buffer. Also update <rtt_sample> if needed, i.e.
 * if the largest acked packet was newly acked and if there was at least one newly
 * acked ack-eliciting packet.
 * Return 1, if succeeded, 0 if not.
 */
static inline int qc_parse_ack_frm(struct quic_conn *qc,
                                   struct quic_frame *frm,
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
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);

	if (ack->largest_ack > qel->pktns->tx.next_pn) {
		TRACE_DEVEL("ACK for not sent packet", QUIC_EV_CONN_PRSAFRM,
		            qc, NULL, &ack->largest_ack);
		goto err;
	}

	if (ack->first_ack_range > ack->largest_ack) {
		TRACE_DEVEL("too big first ACK range", QUIC_EV_CONN_PRSAFRM,
		            qc, NULL, &ack->first_ack_range);
		goto err;
	}

	largest = ack->largest_ack;
	smallest = largest - ack->first_ack_range;
	pkts = &qel->pktns->tx.pkts;
	pkt_flags = 0;
	largest_node = NULL;
	time_sent = 0;

	if ((int64_t)ack->largest_ack > qel->pktns->rx.largest_acked_pn) {
		largest_node = eb64_lookup(pkts, largest);
		if (!largest_node) {
			TRACE_DEVEL("Largest acked packet not found",
			            QUIC_EV_CONN_PRSAFRM, qc);
		}
		else {
			time_sent = eb64_entry(largest_node,
			                       struct quic_tx_packet, pn_node)->time_sent;
		}
	}

	TRACE_PROTO("rcvd ack range", QUIC_EV_CONN_PRSAFRM,
	            qc, NULL, &largest, &smallest);
	do {
		uint64_t gap, ack_range;

		qc_ackrng_pkts(qc, pkts, &pkt_flags, &newly_acked_pkts,
		               largest_node, largest, smallest);
		if (!ack->ack_range_num--)
			break;

		if (!quic_dec_int(&gap, pos, end)) {
			TRACE_ERROR("quic_dec_int(gap) failed", QUIC_EV_CONN_PRSAFRM, qc);
			goto err;
		}

		if (smallest < gap + 2) {
			TRACE_DEVEL("wrong gap value", QUIC_EV_CONN_PRSAFRM,
			            qc, NULL, &gap, &smallest);
			goto err;
		}

		largest = smallest - gap - 2;
		if (!quic_dec_int(&ack_range, pos, end)) {
			TRACE_ERROR("quic_dec_int(ack_range) failed", QUIC_EV_CONN_PRSAFRM, qc);
			goto err;
		}

		if (largest < ack_range) {
			TRACE_DEVEL("wrong ack range value", QUIC_EV_CONN_PRSAFRM,
			            qc, NULL, &largest, &ack_range);
			goto err;
		}

		/* Do not use this node anymore. */
		largest_node = NULL;
		/* Next range */
		smallest = largest - ack_range;

		TRACE_PROTO("rcvd next ack range", QUIC_EV_CONN_PRSAFRM,
		            qc, NULL, &largest, &smallest);
	} while (1);

	if (time_sent && (pkt_flags & QUIC_FL_TX_PACKET_ACK_ELICITING)) {
		*rtt_sample = tick_remain(time_sent, now_ms);
		qel->pktns->rx.largest_acked_pn = ack->largest_ack;
	}

	if (!LIST_ISEMPTY(&newly_acked_pkts)) {
		if (!eb_is_empty(&qel->pktns->tx.pkts)) {
			qc_packet_loss_lookup(qel->pktns, qc, &lost_pkts);
			if (!qc_release_lost_pkts(qc, qel->pktns, &lost_pkts, now_ms))
				goto leave;
		}
		qc_treat_newly_acked_pkts(qc, &newly_acked_pkts);
		if (quic_peer_validated_addr(qc))
			qc->path->loss.pto_count = 0;
		qc_set_timer(qc);
	}

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
	return ret;

 err:
	free_quic_tx_pkts(qc, &newly_acked_pkts);
	goto leave;
}

/* This function gives the detail of the SSL error. It is used only
 * if the debug mode and the verbose mode are activated. It dump all
 * the SSL error until the stack was empty.
 */
static forceinline void qc_ssl_dump_errors(struct connection *conn)
{
	if (unlikely(global.mode & MODE_DEBUG)) {
		while (1) {
			const char *func = NULL;
			unsigned long ret;

			ERR_peek_error_func(&func);
			ret = ERR_get_error();
			if (!ret)
				return;

			fprintf(stderr, "conn. @%p OpenSSL error[0x%lx] %s: %s\n", conn, ret,
			        func, ERR_reason_error_string(ret));
		}
	}
}

int ssl_sock_get_alpn(const struct connection *conn, void *xprt_ctx,
                      const char **str, int *len);

/* Finalize <qc> QUIC connection:
 * - initialize the Initial QUIC TLS context for negotiated version,
 * - derive the secrets for this context,
 * - set them into the TLS stack,
 *
 * MUST be called after having received the remote transport parameters which
 * are parsed when the TLS callback for the ClientHello message is called upon
 * SSL_do_handshake() calls, not necessarily at the first time as this TLS
 * message may be splitted between packets
 * Return 1 if succeeded, 0 if not.
 */
static int qc_conn_finalize(struct quic_conn *qc, int server)
{
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_NEW, qc);

	if (qc->flags & QUIC_FL_CONN_FINALIZED)
		goto finalized;

	if (qc->negotiated_version &&
	    !qc_new_isecs(qc, &qc->negotiated_ictx, qc->negotiated_version,
	                  qc->odcid.data, qc->odcid.len, server))
		goto out;

	/* This connection is functional (ready to send/receive) */
	qc->flags |= QUIC_FL_CONN_FINALIZED;

 finalized:
	ret = 1;
 out:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);
	return ret;
}

/* Provide CRYPTO data to the TLS stack found at <data> with <len> as length
 * from <qel> encryption level with <ctx> as QUIC connection context.
 * Remaining parameter are there for debugging purposes.
 * Return 1 if succeeded, 0 if not.
 */
static inline int qc_provide_cdata(struct quic_enc_level *el,
                                   struct ssl_sock_ctx *ctx,
                                   const unsigned char *data, size_t len,
                                   struct quic_rx_packet *pkt,
                                   struct quic_rx_crypto_frm *cf)
{
#ifdef DEBUG_STRICT
	enum ncb_ret ncb_ret;
#endif
	int ssl_err, state;
	struct quic_conn *qc;
	int ret = 0;
	struct ncbuf *ncbuf = &el->cstream->rx.ncbuf;

	ssl_err = SSL_ERROR_NONE;
	qc = ctx->qc;

	TRACE_ENTER(QUIC_EV_CONN_SSLDATA, qc);

	if (SSL_provide_quic_data(ctx->ssl, el->level, data, len) != 1) {
		TRACE_ERROR("SSL_provide_quic_data() error",
		            QUIC_EV_CONN_SSLDATA, qc, pkt, cf, ctx->ssl);
		goto leave;
	}

	TRACE_PROTO("in order CRYPTO data",
	            QUIC_EV_CONN_SSLDATA, qc, NULL, cf, ctx->ssl);

	state = qc->state;
	if (state < QUIC_HS_ST_COMPLETE) {
		ssl_err = SSL_do_handshake(ctx->ssl);

		if (qc->flags & QUIC_FL_CONN_TO_KILL) {
			TRACE_DEVEL("connection to be killed", QUIC_EV_CONN_IO_CB, qc);
			goto leave;
		}

		/* Finalize the connection as soon as possible if the peer transport parameters
		 * have been received. This may be useful to send packets even if this
		 * handshake fails.
		 */
		if ((qc->flags & QUIC_FL_CONN_TX_TP_RECEIVED) && !qc_conn_finalize(qc, 1)) {
			TRACE_ERROR("connection finalization failed", QUIC_EV_CONN_IO_CB, qc, &state);
			goto leave;
		}

		if (ssl_err != 1) {
			ssl_err = SSL_get_error(ctx->ssl, ssl_err);
			if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
				TRACE_PROTO("SSL handshake in progress",
				            QUIC_EV_CONN_IO_CB, qc, &state, &ssl_err);
				goto out;
			}

			/* TODO: Should close the connection asap */
			if (!(qc->flags & QUIC_FL_CONN_HALF_OPEN_CNT_DECREMENTED)) {
				qc->flags |= QUIC_FL_CONN_HALF_OPEN_CNT_DECREMENTED;
				HA_ATOMIC_DEC(&qc->prx_counters->half_open_conn);
				HA_ATOMIC_INC(&qc->prx_counters->hdshk_fail);
			}
			TRACE_ERROR("SSL handshake error", QUIC_EV_CONN_IO_CB, qc, &state, &ssl_err);
			qc_ssl_dump_errors(ctx->conn);
			ERR_clear_error();
			goto leave;
		}

		TRACE_PROTO("SSL handshake OK", QUIC_EV_CONN_IO_CB, qc, &state);

		/* Check the alpn could be negotiated */
		if (!qc->app_ops) {
			TRACE_ERROR("No negotiated ALPN", QUIC_EV_CONN_IO_CB, qc, &state);
			quic_set_tls_alert(qc, SSL_AD_NO_APPLICATION_PROTOCOL);
			goto leave;
		}

		if (!(qc->flags & QUIC_FL_CONN_HALF_OPEN_CNT_DECREMENTED)) {
			TRACE_DEVEL("dec half open counter", QUIC_EV_CONN_IO_CB, qc, &state);
			qc->flags |= QUIC_FL_CONN_HALF_OPEN_CNT_DECREMENTED;
			HA_ATOMIC_DEC(&qc->prx_counters->half_open_conn);
		}
		/* I/O callback switch */
		qc->wait_event.tasklet->process = quic_conn_app_io_cb;
		if (qc_is_listener(ctx->qc)) {
			qc->state = QUIC_HS_ST_CONFIRMED;
			/* The connection is ready to be accepted. */
			quic_accept_push_qc(qc);
		}
		else {
			qc->state = QUIC_HS_ST_COMPLETE;
		}

		/* Prepare the next key update */
		if (!quic_tls_key_update(qc)) {
			TRACE_ERROR("quic_tls_key_update() failed", QUIC_EV_CONN_IO_CB, qc);
			goto leave;
		}
	} else {
		ssl_err = SSL_process_quic_post_handshake(ctx->ssl);
		if (ssl_err != 1) {
			ssl_err = SSL_get_error(ctx->ssl, ssl_err);
			if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
				TRACE_PROTO("SSL post handshake in progress",
				            QUIC_EV_CONN_IO_CB, qc, &state, &ssl_err);
				goto out;
			}

			TRACE_ERROR("SSL post handshake error",
			            QUIC_EV_CONN_IO_CB, qc, &state, &ssl_err);
			goto leave;
		}

		TRACE_STATE("SSL post handshake succeeded", QUIC_EV_CONN_IO_CB, qc, &state);
	}

 out:
	ret = 1;
 leave:
	/* The CRYPTO data are consumed even in case of an error to release
	 * the memory asap.
	 */
	if (!ncb_is_null(ncbuf)) {
#ifdef DEBUG_STRICT
		ncb_ret = ncb_advance(ncbuf, len);
		/* ncb_advance() must always succeed. This is guaranteed as
		 * this is only done inside a data block. If false, this will
		 * lead to handshake failure with quic_enc_level offset shifted
		 * from buffer data.
		 */
		BUG_ON(ncb_ret != NCB_RET_OK);
#else
		ncb_advance(ncbuf, len);
#endif
	}

	TRACE_LEAVE(QUIC_EV_CONN_SSLDATA, qc);
	return ret;
}

/* Parse a STREAM frame <strm_frm> received in <pkt> packet for <qc>
 * connection. <fin> is true if FIN bit is set on frame type.
 *
 * Return 1 on success. On error, 0 is returned. In this case, the packet
 * containing the frame must not be acknowledged.
 */
static inline int qc_handle_strm_frm(struct quic_rx_packet *pkt,
                                     struct quic_stream *strm_frm,
                                     struct quic_conn *qc, char fin)
{
	int ret;

	/* RFC9000 13.1.  Packet Processing
	 *
	 * A packet MUST NOT be acknowledged until packet protection has been
	 * successfully removed and all frames contained in the packet have
	 * been processed. For STREAM frames, this means the data has been
	 * enqueued in preparation to be received by the application protocol,
	 * but it does not require that data be delivered and consumed.
	 */
	TRACE_ENTER(QUIC_EV_CONN_PRSFRM, qc);

	ret = qcc_recv(qc->qcc, strm_frm->id, strm_frm->len,
	               strm_frm->offset.key, fin, (char *)strm_frm->data);

	/* frame rejected - packet must not be acknowledeged */
	TRACE_LEAVE(QUIC_EV_CONN_PRSFRM, qc);
	return !ret;
}

/* Duplicate all frames from <pkt_frm_list> list into <out_frm_list> list
 * for <qc> QUIC connection.
 * This is a best effort function which never fails even if no memory could be
 * allocated to duplicate these frames.
 */
static void qc_dup_pkt_frms(struct quic_conn *qc,
                            struct list *pkt_frm_list, struct list *out_frm_list)
{
	struct quic_frame *frm, *frmbak;
	struct list tmp = LIST_HEAD_INIT(tmp);

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);

	list_for_each_entry_safe(frm, frmbak, pkt_frm_list, list) {
		struct quic_frame *dup_frm, *origin;

		switch (frm->type) {
		case QUIC_FT_STREAM_8 ... QUIC_FT_STREAM_F:
		{
			struct quic_stream *strm_frm = &frm->stream;
			struct eb64_node *node = NULL;
			struct qc_stream_desc *stream_desc;

			node = eb64_lookup(&qc->streams_by_id, strm_frm->id);
			if (!node) {
				TRACE_DEVEL("ignored frame for a released stream", QUIC_EV_CONN_PRSAFRM, qc, frm);
				continue;
			}

			stream_desc = eb64_entry(node, struct qc_stream_desc, by_id);
			/* Do not resend this frame if in the "already acked range" */
			if (strm_frm->offset.key + strm_frm->len <= stream_desc->ack_offset) {
				TRACE_DEVEL("ignored frame in already acked range",
				            QUIC_EV_CONN_PRSAFRM, qc, frm);
				continue;
			}
			else if (strm_frm->offset.key < stream_desc->ack_offset) {
				strm_frm->offset.key = stream_desc->ack_offset;
				TRACE_DEVEL("updated partially acked frame",
				            QUIC_EV_CONN_PRSAFRM, qc, frm);
			}
			break;
		}

		default:
			break;
		}

		/* If <frm> is already a copy of another frame, we must take
		 * its original frame as source for the copy.
		 */
		origin = frm->origin ? frm->origin : frm;
		dup_frm = qc_frm_dup(origin);
		if (!dup_frm) {
			TRACE_ERROR("could not duplicate frame", QUIC_EV_CONN_PRSAFRM, qc, frm);
			break;
		}

		TRACE_DEVEL("built probing frame", QUIC_EV_CONN_PRSAFRM, qc, origin);
		if (origin->pkt) {
			TRACE_DEVEL("duplicated from packet", QUIC_EV_CONN_PRSAFRM,
			            qc, NULL, &origin->pkt->pn_node.key);
		}
		else {
			/* <origin> is a frame which was sent from a packet detected as lost. */
			TRACE_DEVEL("duplicated from lost packet", QUIC_EV_CONN_PRSAFRM, qc);
		}

		LIST_APPEND(&tmp, &dup_frm->list);
	}

	LIST_SPLICE(out_frm_list, &tmp);

	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
}

/* Prepare a fast retransmission from <qel> encryption level */
static void qc_prep_fast_retrans(struct quic_conn *qc,
                                 struct quic_enc_level *qel,
                                 struct list *frms1, struct list *frms2)
{
	struct eb_root *pkts = &qel->pktns->tx.pkts;
	struct list *frms = frms1;
	struct eb64_node *node;
	struct quic_tx_packet *pkt;

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);

	BUG_ON(frms1 == frms2);

	pkt = NULL;
	node = eb64_first(pkts);
 start:
	while (node) {
		pkt = eb64_entry(node, struct quic_tx_packet, pn_node);
		node = eb64_next(node);
		/* Skip the empty and coalesced packets */
		TRACE_PRINTF(TRACE_LEVEL_DEVELOPER, QUIC_EV_CONN_SPPKTS, qc, 0, 0, 0,
		             "--> pn=%llu (%d %d)", (ull)pkt->pn_node.key,
		             LIST_ISEMPTY(&pkt->frms), !!(pkt->flags & QUIC_FL_TX_PACKET_COALESCED));
		if (!LIST_ISEMPTY(&pkt->frms))
			break;
	}

	if (!pkt)
		goto leave;

	/* When building a packet from another one, the field which may increase the
	 * packet size is the packet number. And the maximum increase is 4 bytes.
	 */
	if (!quic_peer_validated_addr(qc) && qc_is_listener(qc) &&
	    pkt->len + 4 > 3 * qc->rx.bytes - qc->tx.prep_bytes) {
		TRACE_PROTO("anti-amplification limit would be reached", QUIC_EV_CONN_SPPKTS, qc, pkt);
		goto leave;
	}

	TRACE_DEVEL("duplicating packet", QUIC_EV_CONN_SPPKTS, qc, pkt);
	qc_dup_pkt_frms(qc, &pkt->frms, frms);
	if (frms == frms1 && frms2) {
		frms = frms2;
		goto start;
	}
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_SPPKTS, qc);
}

/* Prepare a fast retransmission during a handshake after a client
 * has resent Initial packets. According to the RFC a server may retransmit
 * Initial packets send them coalescing with others (Handshake here).
 * (Listener only function).
 */
static void qc_prep_hdshk_fast_retrans(struct quic_conn *qc,
                                       struct list *ifrms, struct list *hfrms)
{
	struct list itmp = LIST_HEAD_INIT(itmp);
	struct list htmp = LIST_HEAD_INIT(htmp);

	struct quic_enc_level *iqel = &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL];
	struct quic_enc_level *hqel = &qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE];
	struct quic_enc_level *qel = iqel;
	struct eb_root *pkts;
	struct eb64_node *node;
	struct quic_tx_packet *pkt;
	struct list *tmp = &itmp;

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);
 start:
	pkt = NULL;
	pkts = &qel->pktns->tx.pkts;
	node = eb64_first(pkts);
	/* Skip the empty packet (they have already been retransmitted) */
	while (node) {
		pkt = eb64_entry(node, struct quic_tx_packet, pn_node);
		TRACE_PRINTF(TRACE_LEVEL_DEVELOPER, QUIC_EV_CONN_SPPKTS, qc, 0, 0, 0,
		             "--> pn=%llu (%d %d)", (ull)pkt->pn_node.key,
		             LIST_ISEMPTY(&pkt->frms), !!(pkt->flags & QUIC_FL_TX_PACKET_COALESCED));
		if (!LIST_ISEMPTY(&pkt->frms) && !(pkt->flags & QUIC_FL_TX_PACKET_COALESCED))
			break;
		node = eb64_next(node);
	}

	if (!pkt)
		goto end;

	/* When building a packet from another one, the field which may increase the
	 * packet size is the packet number. And the maximum increase is 4 bytes.
	 */
	if (!quic_peer_validated_addr(qc) && qc_is_listener(qc) &&
	    pkt->len + 4 > 3 * qc->rx.bytes - qc->tx.prep_bytes) {
		TRACE_PROTO("anti-amplification limit would be reached", QUIC_EV_CONN_PRSAFRM, qc);
		goto end;
	}

	qel->pktns->tx.pto_probe += 1;

	/* No risk to loop here, #packet per datagram is bounded */
 requeue:
	TRACE_DEVEL("duplicating packet", QUIC_EV_CONN_PRSAFRM, qc, NULL, &pkt->pn_node.key);
	qc_dup_pkt_frms(qc, &pkt->frms, tmp);
	if (qel == iqel) {
		if (pkt->next && pkt->next->type == QUIC_PACKET_TYPE_HANDSHAKE) {
			pkt = pkt->next;
			tmp = &htmp;
			hqel->pktns->tx.pto_probe += 1;
			TRACE_DEVEL("looping for next packet", QUIC_EV_CONN_PRSAFRM, qc);
			goto requeue;
		}
	}

 end:
	LIST_SPLICE(ifrms, &itmp);
	LIST_SPLICE(hfrms, &htmp);

	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
}

static void qc_cc_err_count_inc(struct quic_conn *qc, struct quic_frame *frm)
{
	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);

	if (frm->type == QUIC_FT_CONNECTION_CLOSE)
		quic_stats_transp_err_count_inc(qc->prx_counters, frm->connection_close.error_code);
	else if (frm->type == QUIC_FT_CONNECTION_CLOSE_APP) {
		if (qc->mux_state != QC_MUX_READY || !qc->qcc->app_ops->inc_err_cnt)
			goto out;

		qc->qcc->app_ops->inc_err_cnt(qc->qcc->ctx, frm->connection_close_app.error_code);
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);
}

/* Cancel a request on connection <qc> for stream id <id>. This is useful when
 * the client opens a new stream but the MUX has already been released. A
 * STOP_SENDING + RESET_STREAM frames are prepared for emission.
 *
 * TODO this function is closely related to H3. Its place should be in H3 layer
 * instead of quic-conn but this requires an architecture adjustment.
 *
 * Returns 1 on sucess else 0.
 */
static int qc_h3_request_reject(struct quic_conn *qc, uint64_t id)
{
	int ret = 0;
	struct quic_frame *ss, *rs;
	struct quic_enc_level *qel = &qc->els[QUIC_TLS_ENC_LEVEL_APP];
	const uint64_t app_error_code = H3_REQUEST_REJECTED;

	TRACE_ENTER(QUIC_EV_CONN_PRSHPKT, qc);

	/* Do not emit rejection for unknown unidirectional stream as it is
	 * forbidden to close some of them (H3 control stream and QPACK
	 * encoder/decoder streams).
	 */
	if (quic_stream_is_uni(id)) {
		ret = 1;
		goto out;
	}

	ss = qc_frm_alloc(QUIC_FT_STOP_SENDING);
	if (!ss) {
		TRACE_ERROR("failed to allocate quic_frame", QUIC_EV_CONN_PRSHPKT, qc);
		goto out;
	}

	ss->stop_sending.id = id;
	ss->stop_sending.app_error_code = app_error_code;

	rs = qc_frm_alloc(QUIC_FT_RESET_STREAM);
	if (!rs) {
		TRACE_ERROR("failed to allocate quic_frame", QUIC_EV_CONN_PRSHPKT, qc);
		qc_frm_free(&ss);
		goto out;
	}

	rs->reset_stream.id = id;
	rs->reset_stream.app_error_code = app_error_code;
	rs->reset_stream.final_size = 0;

	LIST_APPEND(&qel->pktns->tx.frms, &ss->list);
	LIST_APPEND(&qel->pktns->tx.frms, &rs->list);
	ret = 1;
 out:
	TRACE_LEAVE(QUIC_EV_CONN_PRSHPKT, qc);
	return ret;
}

/* Release the underlying memory use by <ncbuf> non-contiguous buffer */
static void quic_free_ncbuf(struct ncbuf *ncbuf)
{
	struct buffer buf;

	if (ncb_is_null(ncbuf))
		return;

	buf = b_make(ncbuf->area, ncbuf->size, 0, 0);
	b_free(&buf);
	offer_buffers(NULL, 1);

	*ncbuf = NCBUF_NULL;
}

/* Allocate the underlying required memory for <ncbuf> non-contiguous buffer */
static struct ncbuf *quic_get_ncbuf(struct ncbuf *ncbuf)
{
	struct buffer buf = BUF_NULL;

	if (!ncb_is_null(ncbuf))
		return ncbuf;

	b_alloc(&buf);
	BUG_ON(b_is_null(&buf));

	*ncbuf = ncb_make(buf.area, buf.size, 0);
	ncb_init(ncbuf, 0);

	return ncbuf;
}

/* Parse <frm> CRYPTO frame coming with <pkt> packet at <qel> <qc> connectionn.
 * Returns 1 if succeeded, 0 if not. Also set <*fast_retrans> to 1 if the
 * speed up handshake completion may be run after having received duplicated
 * CRYPTO data.
 */
static int qc_handle_crypto_frm(struct quic_conn *qc,
                                struct quic_crypto *frm, struct quic_rx_packet *pkt,
                                struct quic_enc_level *qel, int *fast_retrans)
{
	int ret = 0;
	enum ncb_ret ncb_ret;
	/* XXX TO DO: <cfdebug> is used only for the traces. */
	struct quic_rx_crypto_frm cfdebug = {
		.offset_node.key = frm->offset,
		.len = frm->len,
	};
	struct quic_cstream *cstream = qel->cstream;
	struct ncbuf *ncbuf = &qel->cstream->rx.ncbuf;

	TRACE_ENTER(QUIC_EV_CONN_PRSHPKT, qc);
	if (unlikely(qel->tls_ctx.flags & QUIC_FL_TLS_SECRETS_DCD)) {
		TRACE_PROTO("CRYPTO data discarded",
					QUIC_EV_CONN_RXPKT, qc, pkt, &cfdebug);
		goto done;
	}

	if (unlikely(frm->offset < cstream->rx.offset)) {
		size_t diff;

		if (frm->offset + frm->len <= cstream->rx.offset) {
			/* Nothing to do */
			TRACE_PROTO("Already received CRYPTO data",
						QUIC_EV_CONN_RXPKT, qc, pkt, &cfdebug);
			if (qc_is_listener(qc) && qel == &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL] &&
				!(qc->flags & QUIC_FL_CONN_HANDSHAKE_SPEED_UP))
				*fast_retrans = 1;
			goto done;
		}

		TRACE_PROTO("Partially already received CRYPTO data",
		            QUIC_EV_CONN_RXPKT, qc, pkt, &cfdebug);

		diff = cstream->rx.offset - frm->offset;
		frm->len -= diff;
		frm->data += diff;
		frm->offset = cstream->rx.offset;
	}

	if (frm->offset == cstream->rx.offset && ncb_is_empty(ncbuf)) {
		if (!qc_provide_cdata(qel, qc->xprt_ctx, frm->data, frm->len,
		                      pkt, &cfdebug)) {
			// trace already emitted by function above
			goto leave;
		}

		cstream->rx.offset += frm->len;
		TRACE_DEVEL("increment crypto level offset", QUIC_EV_CONN_PHPKTS, qc, qel);
		goto done;
	}

	if (!quic_get_ncbuf(ncbuf) ||
	    ncb_is_null(ncbuf)) {
		TRACE_ERROR("CRYPTO ncbuf allocation failed", QUIC_EV_CONN_PRSHPKT, qc);
		goto leave;
	}

	/* frm->offset > cstream-trx.offset */
	ncb_ret = ncb_add(ncbuf, frm->offset - cstream->rx.offset,
	                  (const char *)frm->data, frm->len, NCB_ADD_COMPARE);
	if (ncb_ret != NCB_RET_OK) {
		if (ncb_ret == NCB_RET_DATA_REJ) {
			TRACE_ERROR("overlapping data rejected", QUIC_EV_CONN_PRSHPKT, qc);
			quic_set_connection_close(qc, quic_err_transport(QC_ERR_PROTOCOL_VIOLATION));
		}
		else if (ncb_ret == NCB_RET_GAP_SIZE) {
			TRACE_ERROR("cannot bufferize frame due to gap size limit",
			            QUIC_EV_CONN_PRSHPKT, qc);
		}
		goto leave;
	}

 done:
	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PRSHPKT, qc);
	return ret;
}

/* Parse all the frames of <pkt> QUIC packet for QUIC connection <qc> and <qel>
 * as encryption level.
 * Returns 1 if succeeded, 0 if failed.
 */
static int qc_parse_pkt_frms(struct quic_conn *qc, struct quic_rx_packet *pkt,
                             struct quic_enc_level *qel)
{
	struct quic_frame frm;
	const unsigned char *pos, *end;
	int fast_retrans = 0, ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_PRSHPKT, qc);
	/* Skip the AAD */
	pos = pkt->data + pkt->aad_len;
	end = pkt->data + pkt->len;

	while (pos < end) {
		if (!qc_parse_frm(&frm, pkt, &pos, end, qc)) {
			// trace already emitted by function above
			goto leave;
		}

		TRACE_PROTO("RX frame", QUIC_EV_CONN_PSTRM, qc, &frm);
		switch (frm.type) {
		case QUIC_FT_PADDING:
			break;
		case QUIC_FT_PING:
			break;
		case QUIC_FT_ACK:
		{
			unsigned int rtt_sample;

			rtt_sample = 0;
			if (!qc_parse_ack_frm(qc, &frm, qel, &rtt_sample, &pos, end)) {
				// trace already emitted by function above
				goto leave;
			}

			if (rtt_sample) {
				unsigned int ack_delay;

				ack_delay = !quic_application_pktns(qel->pktns, qc) ? 0 :
					qc->state >= QUIC_HS_ST_CONFIRMED ?
					MS_TO_TICKS(QUIC_MIN(quic_ack_delay_ms(&frm.ack, qc), qc->max_ack_delay)) :
					MS_TO_TICKS(quic_ack_delay_ms(&frm.ack, qc));
				quic_loss_srtt_update(&qc->path->loss, rtt_sample, ack_delay, qc);
			}
			break;
		}
		case QUIC_FT_RESET_STREAM:
			if (qc->mux_state == QC_MUX_READY) {
				struct quic_reset_stream *rs = &frm.reset_stream;
				qcc_recv_reset_stream(qc->qcc, rs->id, rs->app_error_code, rs->final_size);
			}
			break;
		case QUIC_FT_STOP_SENDING:
		{
			struct quic_stop_sending *stop_sending = &frm.stop_sending;
			if (qc->mux_state == QC_MUX_READY) {
				if (qcc_recv_stop_sending(qc->qcc, stop_sending->id,
				                          stop_sending->app_error_code)) {
					TRACE_ERROR("qcc_recv_stop_sending() failed", QUIC_EV_CONN_PRSHPKT, qc);
					goto leave;
				}
			}
			break;
		}
		case QUIC_FT_CRYPTO:
			if (!qc_handle_crypto_frm(qc, &frm.crypto, pkt, qel, &fast_retrans))
				goto leave;
			break;
		case QUIC_FT_STREAM_8 ... QUIC_FT_STREAM_F:
		{
			struct quic_stream *stream = &frm.stream;
			unsigned nb_streams = qc->rx.strms[qcs_id_type(stream->id)].nb_streams;
			const char fin = frm.type & QUIC_STREAM_FRAME_TYPE_FIN_BIT;

			/* The upper layer may not be allocated. */
			if (qc->mux_state != QC_MUX_READY) {
				if ((stream->id >> QCS_ID_TYPE_SHIFT) < nb_streams) {
					TRACE_DATA("Already closed stream", QUIC_EV_CONN_PRSHPKT, qc);
					break;
				}
				else {
					TRACE_DEVEL("No mux for new stream", QUIC_EV_CONN_PRSHPKT, qc);
					if (qc->app_ops == &h3_ops) {
						if (!qc_h3_request_reject(qc, stream->id)) {
							TRACE_ERROR("error on request rejection", QUIC_EV_CONN_PRSHPKT, qc);
							/* This packet will not be acknowledged */
							goto leave;
						}
					}
					else {
						/* This packet will not be acknowledged */
						goto leave;
					}
				}
			}

			if (!qc_handle_strm_frm(pkt, stream, qc, fin)) {
				TRACE_ERROR("qc_handle_strm_frm() failed", QUIC_EV_CONN_PRSHPKT, qc);
				goto leave;
			}

			break;
		}
		case QUIC_FT_MAX_DATA:
			if (qc->mux_state == QC_MUX_READY) {
				struct quic_max_data *data = &frm.max_data;
				qcc_recv_max_data(qc->qcc, data->max_data);
			}
			break;
		case QUIC_FT_MAX_STREAM_DATA:
			if (qc->mux_state == QC_MUX_READY) {
				struct quic_max_stream_data *data = &frm.max_stream_data;
				if (qcc_recv_max_stream_data(qc->qcc, data->id,
				                              data->max_stream_data)) {
					TRACE_ERROR("qcc_recv_max_stream_data() failed", QUIC_EV_CONN_PRSHPKT, qc);
					goto leave;
				}
			}
			break;
		case QUIC_FT_MAX_STREAMS_BIDI:
		case QUIC_FT_MAX_STREAMS_UNI:
			break;
		case QUIC_FT_DATA_BLOCKED:
			HA_ATOMIC_INC(&qc->prx_counters->data_blocked);
			break;
		case QUIC_FT_STREAM_DATA_BLOCKED:
			HA_ATOMIC_INC(&qc->prx_counters->stream_data_blocked);
			break;
		case QUIC_FT_STREAMS_BLOCKED_BIDI:
			HA_ATOMIC_INC(&qc->prx_counters->streams_data_blocked_bidi);
			break;
		case QUIC_FT_STREAMS_BLOCKED_UNI:
			HA_ATOMIC_INC(&qc->prx_counters->streams_data_blocked_uni);
			break;
		case QUIC_FT_NEW_CONNECTION_ID:
		case QUIC_FT_RETIRE_CONNECTION_ID:
			/* XXX TO DO XXX */
			break;
		case QUIC_FT_CONNECTION_CLOSE:
		case QUIC_FT_CONNECTION_CLOSE_APP:
			/* Increment the error counters */
			qc_cc_err_count_inc(qc, &frm);
			if (!(qc->flags & QUIC_FL_CONN_DRAINING)) {
				if (!(qc->flags & QUIC_FL_CONN_HALF_OPEN_CNT_DECREMENTED)) {
					qc->flags |= QUIC_FL_CONN_HALF_OPEN_CNT_DECREMENTED;
					HA_ATOMIC_DEC(&qc->prx_counters->half_open_conn);
				}
				TRACE_STATE("Entering draining state", QUIC_EV_CONN_PRSHPKT, qc);
				/* RFC 9000 10.2. Immediate Close:
				 * The closing and draining connection states exist to ensure
				 * that connections close cleanly and that delayed or reordered
				 * packets are properly discarded. These states SHOULD persist
				 * for at least three times the current PTO interval...
				 *
				 * Rearm the idle timeout only one time when entering draining
				 * state.
				 */
				qc->flags |= QUIC_FL_CONN_DRAINING|QUIC_FL_CONN_IMMEDIATE_CLOSE;
				qc_idle_timer_do_rearm(qc);
				qc_notify_close(qc);
			}
			break;
		case QUIC_FT_HANDSHAKE_DONE:
			if (qc_is_listener(qc)) {
				TRACE_ERROR("non accepted QUIC_FT_HANDSHAKE_DONE frame",
				            QUIC_EV_CONN_PRSHPKT, qc);
				goto leave;
			}

			qc->state = QUIC_HS_ST_CONFIRMED;
			break;
		default:
			TRACE_ERROR("unknosw frame type", QUIC_EV_CONN_PRSHPKT, qc);
			goto leave;
		}
	}

	/* Flag this packet number space as having received a packet. */
	qel->pktns->flags |= QUIC_FL_PKTNS_PKT_RECEIVED;

	if (fast_retrans) {
		struct quic_enc_level *iqel = &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL];
		struct quic_enc_level *hqel = &qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE];

		TRACE_PROTO("speeding up handshake completion", QUIC_EV_CONN_PRSHPKT, qc);
		qc_prep_hdshk_fast_retrans(qc, &iqel->pktns->tx.frms, &hqel->pktns->tx.frms);
		qc->flags |= QUIC_FL_CONN_HANDSHAKE_SPEED_UP;
	}

	/* The server must switch from INITIAL to HANDSHAKE handshake state when it
	 * has successfully parse a Handshake packet. The Initial encryption must also
	 * be discarded.
	 */
	if (pkt->type == QUIC_PACKET_TYPE_HANDSHAKE && qc_is_listener(qc)) {
	    if (qc->state >= QUIC_HS_ST_SERVER_INITIAL) {
			if (!(qc->els[QUIC_TLS_ENC_LEVEL_INITIAL].tls_ctx.flags &
			      QUIC_FL_TLS_SECRETS_DCD)) {
				quic_tls_discard_keys(&qc->els[QUIC_TLS_ENC_LEVEL_INITIAL]);
				TRACE_PROTO("discarding Initial pktns", QUIC_EV_CONN_PRSHPKT, qc);
				quic_pktns_discard(qc->els[QUIC_TLS_ENC_LEVEL_INITIAL].pktns, qc);
				qc_set_timer(qc);
				qc_el_rx_pkts_del(&qc->els[QUIC_TLS_ENC_LEVEL_INITIAL]);
				qc_release_pktns_frms(qc, qc->els[QUIC_TLS_ENC_LEVEL_INITIAL].pktns);
			}
		    if (qc->state < QUIC_HS_ST_SERVER_HANDSHAKE)
			    qc->state = QUIC_HS_ST_SERVER_HANDSHAKE;
	    }
	}

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PRSHPKT, qc);
	return ret;
}


/* Allocate Tx buffer from <qc> quic-conn if needed.
 *
 * Returns allocated buffer or NULL on error.
 */
static struct buffer *qc_txb_alloc(struct quic_conn *qc)
{
	struct buffer *buf = &qc->tx.buf;
	if (!b_alloc(buf))
		return NULL;

	return buf;
}

/* Free Tx buffer from <qc> if it is empty. */
static void qc_txb_release(struct quic_conn *qc)
{
	struct buffer *buf = &qc->tx.buf;

	/* For the moment sending function is responsible to purge the buffer
	 * entirely. It may change in the future but this requires to be able
	 * to reuse old data.
	 * For the momemt we do not care to leave data in the buffer for
	 * a connection which is supposed to be killed asap.
	 */
	BUG_ON_HOT(buf && b_data(buf));

	if (!b_data(buf)) {
		b_free(buf);
		offer_buffers(NULL, 1);
	}
}

/* Commit a datagram payload written into <buf> of length <length>. <first_pkt>
 * must contains the address of the first packet stored in the payload.
 *
 * Caller is responsible that there is enough space in the buffer.
 */
static void qc_txb_store(struct buffer *buf, uint16_t length,
                         struct quic_tx_packet *first_pkt)
{
	const size_t hdlen = sizeof(uint16_t) + sizeof(void *);
	BUG_ON_HOT(b_contig_space(buf) < hdlen); /* this must not happen */

	write_u16(b_tail(buf), length);
	write_ptr(b_tail(buf) + sizeof(length), first_pkt);
	b_add(buf, hdlen + length);
}

/* Returns 1 if a packet may be built for <qc> from <qel> encryption level
 * with <frms> as ack-eliciting frame list to send, 0 if not.
 * <cc> must equal to 1 if an immediate close was asked, 0 if not.
 * <probe> must equalt to 1 if a probing packet is required, 0 if not.
 * <force_ack> may be set to 1 if you want to force an ack.
 */
static int qc_may_build_pkt(struct quic_conn *qc, struct list *frms,
                            struct quic_enc_level *qel, int cc, int probe, int force_ack)
{
	unsigned int must_ack = force_ack ||
		(LIST_ISEMPTY(frms) && (qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED));

	/* Do not build any more packet if the TX secrets are not available or
	 * if there is nothing to send, i.e. if no CONNECTION_CLOSE or ACK are required
	 * and if there is no more packets to send upon PTO expiration
	 * and if there is no more ack-eliciting frames to send or in flight
	 * congestion control limit is reached for prepared data
	 */
	if (!quic_tls_has_tx_sec(qel) ||
	    (!cc && !probe && !must_ack &&
	     (LIST_ISEMPTY(frms) || qc->path->prep_in_flight >= qc->path->cwnd))) {
		return 0;
	}

	return 1;
}

/* Prepare as much as possible QUIC packets for sending from prebuilt frames
 * <frms>. Each packet is stored in a distinct datagram written to <buf>.
 *
 * Each datagram is prepended by a two fields header : the datagram length and
 * the address of the packet contained in the datagram.
 *
 * Returns the number of bytes prepared in packets if succeeded (may be 0), or
 * -1 if something wrong happened.
 */
static int qc_prep_app_pkts(struct quic_conn *qc, struct buffer *buf,
                            struct list *frms)
{
	int ret = -1;
	struct quic_enc_level *qel;
	unsigned char *end, *pos;
	struct quic_tx_packet *pkt;
	size_t total;
	/* Each datagram is prepended with its length followed by the address
	 * of the first packet in the datagram.
	 */
	const size_t dg_headlen = sizeof(uint16_t) + sizeof(pkt);

	TRACE_ENTER(QUIC_EV_CONN_PHPKTS, qc);

	qel = &qc->els[QUIC_TLS_ENC_LEVEL_APP];
	total = 0;
	pos = (unsigned char *)b_tail(buf);
	while (b_contig_space(buf) >= (int)qc->path->mtu + dg_headlen) {
		int err, probe, cc;

		TRACE_POINT(QUIC_EV_CONN_PHPKTS, qc, qel);
		probe = 0;
		cc =  qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE;
		/* We do not probe if an immediate close was asked */
		if (!cc)
			probe = qel->pktns->tx.pto_probe;

		if (!qc_may_build_pkt(qc, frms, qel, cc, probe, 0))
			break;

		/* Leave room for the datagram header */
		pos += dg_headlen;
		if (!quic_peer_validated_addr(qc) && qc_is_listener(qc)) {
			end = pos + QUIC_MIN((uint64_t)qc->path->mtu, 3 * qc->rx.bytes - qc->tx.prep_bytes);
		}
		else {
			end = pos + qc->path->mtu;
		}

		pkt = qc_build_pkt(&pos, end, qel, &qel->tls_ctx, frms, qc, NULL, 0,
		                   QUIC_PACKET_TYPE_SHORT, 0, 0, probe, cc, &err);
		switch (err) {
		case -2:
			// trace already emitted by function above
			goto leave;
		case -1:
			/* As we provide qc_build_pkt() with an enough big buffer to fulfill an
			 * MTU, we are here because of the congestion control window. There is
			 * no need to try to reuse this buffer.
			 */
			TRACE_DEVEL("could not prepare anymore packet", QUIC_EV_CONN_PHPKTS, qc);
			goto out;
		default:
			break;
		}

		/* This is to please to GCC. We cannot have (err >= 0 && !pkt) */
		BUG_ON(!pkt);

		if (qc->flags & QUIC_FL_CONN_RETRANS_OLD_DATA)
			pkt->flags |= QUIC_FL_TX_PACKET_PROBE_WITH_OLD_DATA;

		total += pkt->len;

		/* Write datagram header. */
		qc_txb_store(buf, pkt->len, pkt);
	}

 out:
	ret = total;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PHPKTS, qc);
	return ret;
}

/* Prepare as much as possible QUIC packets for sending from prebuilt frames
 * <frms>. Several packets can be regrouped in a single datagram. The result is
 * written into <buf>.
 *
 * Each datagram is prepended by a two fields header : the datagram length and
 * the address of first packet in the datagram.
 *
 * Returns the number of bytes prepared in packets if succeeded (may be 0), or
 * -1 if something wrong happened.
 */
static int qc_prep_pkts(struct quic_conn *qc, struct buffer *buf,
                        enum quic_tls_enc_level tel, struct list *tel_frms,
                        enum quic_tls_enc_level next_tel, struct list *next_tel_frms)
{
	struct quic_enc_level *qel;
	unsigned char *end, *pos;
	struct quic_tx_packet *first_pkt, *cur_pkt, *prv_pkt;
	/* length of datagrams */
	uint16_t dglen;
	size_t total;
	int ret = -1, padding;
	/* Each datagram is prepended with its length followed by the address
	 * of the first packet in the datagram.
	 */
	const size_t dg_headlen = sizeof(uint16_t) + sizeof(first_pkt);
	struct list *frms;

	TRACE_ENTER(QUIC_EV_CONN_PHPKTS, qc);

	/* Currently qc_prep_pkts() does not handle buffer wrapping so the
	 * caller must ensure that buf is reset.
	 */
	BUG_ON_HOT(buf->head || buf->data);

	total = 0;
	qel = &qc->els[tel];
	frms = tel_frms;
	dglen = 0;
	padding = 0;
	pos = (unsigned char *)b_head(buf);
	first_pkt = prv_pkt = NULL;
	while (b_contig_space(buf) >= (int)qc->path->mtu + dg_headlen || prv_pkt) {
		int err, probe, cc;
		enum quic_pkt_type pkt_type;
		struct quic_tls_ctx *tls_ctx;
		const struct quic_version *ver;
		int force_ack = (qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) &&
			(qel == &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL] ||
			 qel == &qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE]);

		TRACE_POINT(QUIC_EV_CONN_PHPKTS, qc, qel);
		probe = 0;
		cc =  qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE;
		/* We do not probe if an immediate close was asked */
		if (!cc)
			probe = qel->pktns->tx.pto_probe;

		if (!qc_may_build_pkt(qc, frms, qel, cc, probe, force_ack)) {
			if (prv_pkt)
				qc_txb_store(buf, dglen, first_pkt);
			/* Let's select the next encryption level */
			if (tel != next_tel && next_tel != QUIC_TLS_ENC_LEVEL_NONE) {
				tel = next_tel;
				frms = next_tel_frms;
				qel = &qc->els[tel];
				/* Build a new datagram */
				prv_pkt = NULL;
				TRACE_DEVEL("next encryption level selected", QUIC_EV_CONN_PHPKTS, qc);
				continue;
			}
			break;
		}

		pkt_type = quic_tls_level_pkt_type(tel);
		if (!prv_pkt) {
			/* Leave room for the datagram header */
			pos += dg_headlen;
			if (!quic_peer_validated_addr(qc) && qc_is_listener(qc)) {
				end = pos + QUIC_MIN((uint64_t)qc->path->mtu, 3 * qc->rx.bytes - qc->tx.prep_bytes);
			}
			else {
				end = pos + qc->path->mtu;
			}
		}

		if (qc->negotiated_version) {
			ver = qc->negotiated_version;
			if (qel == &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL])
				tls_ctx = &qc->negotiated_ictx;
			else
				tls_ctx = &qel->tls_ctx;
		}
		else {
			ver = qc->original_version;
			tls_ctx = &qel->tls_ctx;
		}

		cur_pkt = qc_build_pkt(&pos, end, qel, tls_ctx, frms,
		                       qc, ver, dglen, pkt_type,
		                       force_ack, padding, probe, cc, &err);
		switch (err) {
		case -2:
			// trace already emitted by function above
			goto leave;
		case -1:
			/* If there was already a correct packet present, set the
			 * current datagram as prepared into <cbuf>.
			 */
			if (prv_pkt)
				qc_txb_store(buf, dglen, first_pkt);
			TRACE_DEVEL("could not prepare anymore packet", QUIC_EV_CONN_PHPKTS, qc);
			goto out;
		default:
			break;
		}

		/* This is to please to GCC. We cannot have (err >= 0 && !cur_pkt) */
		BUG_ON(!cur_pkt);

		if (qc->flags & QUIC_FL_CONN_RETRANS_OLD_DATA)
			cur_pkt->flags |= QUIC_FL_TX_PACKET_PROBE_WITH_OLD_DATA;

		total += cur_pkt->len;
		/* keep trace of the first packet in the datagram */
		if (!first_pkt)
			first_pkt = cur_pkt;
		/* Attach the current one to the previous one and vice versa */
		if (prv_pkt) {
			prv_pkt->next = cur_pkt;
			cur_pkt->prev = prv_pkt;
			cur_pkt->flags |= QUIC_FL_TX_PACKET_COALESCED;
		}
		/* Let's say we have to build a new dgram */
		prv_pkt = NULL;
		dglen += cur_pkt->len;
		/* Client: discard the Initial encryption keys as soon as
		 * a handshake packet could be built.
		 */
		if (qc->state == QUIC_HS_ST_CLIENT_INITIAL &&
		    pkt_type == QUIC_PACKET_TYPE_HANDSHAKE) {
			quic_tls_discard_keys(&qc->els[QUIC_TLS_ENC_LEVEL_INITIAL]);
			TRACE_PROTO("discarding Initial pktns", QUIC_EV_CONN_PHPKTS, qc);
			quic_pktns_discard(qc->els[QUIC_TLS_ENC_LEVEL_INITIAL].pktns, qc);
			qc_set_timer(qc);
			qc_el_rx_pkts_del(&qc->els[QUIC_TLS_ENC_LEVEL_INITIAL]);
			qc_release_pktns_frms(qc, qc->els[QUIC_TLS_ENC_LEVEL_INITIAL].pktns);
			qc->state = QUIC_HS_ST_CLIENT_HANDSHAKE;
		}
		/* If the data for the current encryption level have all been sent,
		 * select the next level.
		 */
		if ((tel == QUIC_TLS_ENC_LEVEL_INITIAL || tel == QUIC_TLS_ENC_LEVEL_HANDSHAKE) &&
		    next_tel != QUIC_TLS_ENC_LEVEL_NONE && (LIST_ISEMPTY(frms) && !qel->pktns->tx.pto_probe)) {
			/* If QUIC_TLS_ENC_LEVEL_HANDSHAKE was already reached let's try QUIC_TLS_ENC_LEVEL_APP */
			if (tel == QUIC_TLS_ENC_LEVEL_HANDSHAKE && next_tel == tel)
				next_tel = QUIC_TLS_ENC_LEVEL_APP;
			tel = next_tel;
			if (tel == QUIC_TLS_ENC_LEVEL_APP)
				frms = &qc->els[tel].pktns->tx.frms;
			else
				frms = next_tel_frms;
			qel = &qc->els[tel];
			if (!LIST_ISEMPTY(frms)) {
				/* If there is data for the next level, do not
				 * consume a datagram.
				 */
				prv_pkt = cur_pkt;
			}
		}

		/* If we have to build a new datagram, set the current datagram as
		 * prepared into <cbuf>.
		 */
		if (!prv_pkt) {
			qc_txb_store(buf, dglen, first_pkt);
			first_pkt = NULL;
			dglen = 0;
			padding = 0;
		}
		else if (prv_pkt->type == QUIC_TLS_ENC_LEVEL_INITIAL &&
		         (!qc_is_listener(qc) ||
		         prv_pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING)) {
			padding = 1;
		}
	}

 out:
	ret = total;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PHPKTS, qc);
	return ret;
}

/* Send datagrams stored in <buf>.
 *
 * This function returns 1 for success. Even if sendto() syscall failed,
 * buffer is drained and packets are considered as emitted and this function returns 1
 * There is a unique exception when sendto() fails with ECONNREFUSED as errno,
 * this function returns 0.
 * QUIC loss detection mechanism is used as a back door way to retry sending.
 */
int qc_send_ppkts(struct buffer *buf, struct ssl_sock_ctx *ctx)
{
	int ret = 0;
	struct quic_conn *qc;
	char skip_sendto = 0;

	qc = ctx->qc;
	TRACE_ENTER(QUIC_EV_CONN_SPPKTS, qc);
	while (b_contig_data(buf, 0)) {
		unsigned char *pos;
		struct buffer tmpbuf = { };
		struct quic_tx_packet *first_pkt, *pkt, *next_pkt;
		uint16_t dglen;
		size_t headlen = sizeof dglen + sizeof first_pkt;
		unsigned int time_sent;

		pos = (unsigned char *)b_head(buf);
		dglen = read_u16(pos);
		BUG_ON_HOT(!dglen); /* this should not happen */

		pos += sizeof dglen;
		first_pkt = read_ptr(pos);
		pos += sizeof first_pkt;
		tmpbuf.area = (char *)pos;
		tmpbuf.size = tmpbuf.data = dglen;

		TRACE_DATA("send dgram", QUIC_EV_CONN_SPPKTS, qc);
		/* If sendto is on error just skip the call to it for the rest
		 * of the loop but continue to purge the buffer. Data will be
		 * transmitted when QUIC packets are detected as lost on our
		 * side.
		 *
		 * TODO use fd-monitoring to detect when send operation can be
		 * retry. This should improve the bandwidth without relying on
		 * retransmission timer. However, it requires a major rework on
		 * quic-conn fd management.
		 */
		if (!skip_sendto) {
			int syscall_errno;

			syscall_errno = 0;
			if (qc_snd_buf(qc, &tmpbuf, tmpbuf.data, 0, &syscall_errno)) {
				if (syscall_errno == ECONNREFUSED) {
					/* Let's kill this connection asap. */
					TRACE_PROTO("UDP port unreachable", QUIC_EV_CONN_SPPKTS, qc);
					qc_kill_conn(qc);
					b_del(buf, buf->data);
					goto leave;
				}

				skip_sendto = 1;
				TRACE_ERROR("sendto error, simulate sending for the rest of data", QUIC_EV_CONN_SPPKTS, qc);
			}
		}

		b_del(buf, dglen + headlen);
		qc->tx.bytes += tmpbuf.data;
		time_sent = now_ms;

		for (pkt = first_pkt; pkt; pkt = next_pkt) {
			pkt->time_sent = time_sent;
			if (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING) {
				pkt->pktns->tx.time_of_last_eliciting = time_sent;
				qc->path->ifae_pkts++;
				if (qc->flags & QUIC_FL_CONN_IDLE_TIMER_RESTARTED_AFTER_READ)
					qc_idle_timer_rearm(qc, 0);
			}
			if (!(qc->flags & QUIC_FL_CONN_CLOSING) &&
			    (pkt->flags & QUIC_FL_TX_PACKET_CC)) {
				qc->flags |= QUIC_FL_CONN_CLOSING;
				qc_notify_close(qc);

				/* RFC 9000 10.2. Immediate Close:
				 * The closing and draining connection states exist to ensure
				 * that connections close cleanly and that delayed or reordered
				 * packets are properly discarded. These states SHOULD persist
				 * for at least three times the current PTO interval...
				 *
				 * Rearm the idle timeout only one time when entering closing
				 * state.
				 */
				qc_idle_timer_do_rearm(qc);
				if (qc->timer_task) {
					task_destroy(qc->timer_task);
					qc->timer_task = NULL;
				}
			}
			qc->path->in_flight += pkt->in_flight_len;
			pkt->pktns->tx.in_flight += pkt->in_flight_len;
			if (pkt->in_flight_len)
				qc_set_timer(qc);
			TRACE_DATA("sent pkt", QUIC_EV_CONN_SPPKTS, qc, pkt);
			next_pkt = pkt->next;
			quic_tx_packet_refinc(pkt);
			eb64_insert(&pkt->pktns->tx.pkts, &pkt->pn_node);
		}
	}

	ret = 1;
leave:
	TRACE_LEAVE(QUIC_EV_CONN_SPPKTS, qc);

	return ret;
}

/* Copy into <buf> buffer a stateless reset token depending on the
 * <salt> salt input. This is the cluster secret which will be derived
 * as HKDF input secret to generate this token.
 * Return 1 if succeeded, 0 if not.
 */
static int quic_stateless_reset_token_cpy(struct quic_conn *qc,
                                          unsigned char *buf, size_t len,
                                          const unsigned char *salt, size_t saltlen)
{
	/* Input secret */
	const unsigned char *key = (const unsigned char *)global.cluster_secret;
	size_t keylen = strlen(global.cluster_secret);
	/* Info */
	const unsigned char label[] = "stateless token";
	size_t labellen = sizeof label - 1;
	int ret;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	ret = quic_hkdf_extract_and_expand(EVP_sha256(), buf, len,
	                                    key, keylen, salt, saltlen, label, labellen);
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return ret;
}

/* Initialize the stateless reset token attached to <cid> connection ID.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_stateless_reset_token_init(struct quic_conn *qc,
                                           struct quic_connection_id *quic_cid)
{
	int ret;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	if (global.cluster_secret) {
		/* Output secret */
		unsigned char *token = quic_cid->stateless_reset_token;
		size_t tokenlen = sizeof quic_cid->stateless_reset_token;
		/* Salt */
		const unsigned char *cid = quic_cid->cid.data;
		size_t cidlen = quic_cid->cid.len;

		ret = quic_stateless_reset_token_cpy(qc, token, tokenlen, cid, cidlen);
	}
	else {
		/* TODO: RAND_bytes() should be replaced */
		ret = RAND_bytes(quic_cid->stateless_reset_token,
		                 sizeof quic_cid->stateless_reset_token) == 1;
	}

	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return ret;
}

/* Allocate a new CID with <seq_num> as sequence number and attach it to <root>
 * ebtree.
 *
 * The CID is randomly generated in part with the result altered to be
 * associated with the current thread ID. This means this function must only
 * be called by the quic_conn thread.
 *
 * Returns the new CID if succeeded, NULL if not.
 */
static struct quic_connection_id *new_quic_cid(struct eb_root *root,
                                               struct quic_conn *qc,
                                               int seq_num)
{
	struct quic_connection_id *cid;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	cid = pool_alloc(pool_head_quic_connection_id);
	if (!cid) {
		TRACE_ERROR("cid allocation failed", QUIC_EV_CONN_TXPKT, qc);
		goto err;
	}

	cid->cid.len = QUIC_HAP_CID_LEN;
	/* TODO: RAND_bytes() should be replaced */
	if (RAND_bytes(cid->cid.data, cid->cid.len) != 1) {
		TRACE_ERROR("RAND_bytes() failed", QUIC_EV_CONN_TXPKT, qc);
		goto err;
	}

	quic_pin_cid_to_tid(cid->cid.data, tid);
	if (quic_stateless_reset_token_init(qc, cid) != 1) {
		TRACE_ERROR("quic_stateless_reset_token_init() failed", QUIC_EV_CONN_TXPKT, qc);
		goto err;
	}

	cid->qc = qc;

	cid->seq_num.key = seq_num;
	cid->retire_prior_to = 0;
	/* insert the allocated CID in the quic_conn tree */
	eb64_insert(root, &cid->seq_num);

	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return cid;

 err:
	pool_free(pool_head_quic_connection_id, cid);
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return NULL;
}

/* Build all the frames which must be sent just after the handshake have succeeded.
 * This is essentially NEW_CONNECTION_ID frames. A QUIC server must also send
 * a HANDSHAKE_DONE frame.
 * Return 1 if succeeded, 0 if not.
 */
static int quic_build_post_handshake_frames(struct quic_conn *qc)
{
	int ret = 0, i, first, max;
	struct quic_enc_level *qel;
	struct quic_frame *frm, *frmbak;
	struct list frm_list = LIST_HEAD_INIT(frm_list);
	struct eb64_node *node;

	TRACE_ENTER(QUIC_EV_CONN_IO_CB, qc);

	qel = &qc->els[QUIC_TLS_ENC_LEVEL_APP];
	/* Only servers must send a HANDSHAKE_DONE frame. */
	if (qc_is_listener(qc)) {
		frm = qc_frm_alloc(QUIC_FT_HANDSHAKE_DONE);
		if (!frm) {
			TRACE_ERROR("frame allocation error", QUIC_EV_CONN_IO_CB, qc);
			goto leave;
		}

		LIST_APPEND(&frm_list, &frm->list);
	}

	/* Initialize <max> connection IDs minus one: there is
	 * already one connection ID used for the current connection.
	 */
	first = 1;
	max = qc->tx.params.active_connection_id_limit;

	/* TODO: check limit */
	for (i = first; i < max; i++) {
		struct quic_connection_id *cid;

		frm = qc_frm_alloc(QUIC_FT_NEW_CONNECTION_ID);
		if (!frm) {
			TRACE_ERROR("frame allocation error", QUIC_EV_CONN_IO_CB, qc);
			goto err;
		}

		cid = new_quic_cid(&qc->cids, qc, i);
		if (!cid) {
			qc_frm_free(&frm);
			TRACE_ERROR("CID allocation error", QUIC_EV_CONN_IO_CB, qc);
			goto err;
		}

		/* insert the allocated CID in the receiver datagram handler tree */
		ebmb_insert(&quic_dghdlrs[tid].cids, &cid->node, cid->cid.len);

		quic_connection_id_to_frm_cpy(frm, cid);
		LIST_APPEND(&frm_list, &frm->list);
	}

	LIST_SPLICE(&qel->pktns->tx.frms, &frm_list);
	qc->flags |= QUIC_FL_CONN_POST_HANDSHAKE_FRAMES_BUILT;

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_IO_CB, qc);
	return ret;

 err:
	/* free the frames */
	list_for_each_entry_safe(frm, frmbak, &frm_list, list)
		qc_frm_free(&frm);

	node = eb64_lookup_ge(&qc->cids, first);
	while (node) {
		struct quic_connection_id *cid;

		cid = eb64_entry(node, struct quic_connection_id, seq_num);
		if (cid->seq_num.key >= max)
			break;

		node = eb64_next(node);
		ebmb_delete(&cid->node);
		eb64_delete(&cid->seq_num);
		pool_free(pool_head_quic_connection_id, cid);
	}
	goto leave;
}

/* Deallocate <l> list of ACK ranges. */
void quic_free_arngs(struct quic_conn *qc, struct quic_arngs *arngs)
{
	struct eb64_node *n;
	struct quic_arng_node *ar;

	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);

	n = eb64_first(&arngs->root);
	while (n) {
		struct eb64_node *next;

		ar = eb64_entry(n, struct quic_arng_node, first);
		next = eb64_next(n);
		eb64_delete(n);
		pool_free(pool_head_quic_arng, ar);
		n = next;
	}

	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);
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
static int quic_rm_last_ack_ranges(struct quic_conn *qc,
                                   struct quic_arngs *arngs, size_t limit)
{
	int ret = 0;
	struct eb64_node *last, *prev;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	last = eb64_last(&arngs->root);
	while (last && arngs->enc_sz > limit) {
		struct quic_arng_node *last_node, *prev_node;

		prev = eb64_prev(last);
		if (!prev) {
			TRACE_DEVEL("<last> not found", QUIC_EV_CONN_TXPKT, qc);
			goto out;
		}

		last_node = eb64_entry(last, struct quic_arng_node, first);
		prev_node = eb64_entry(prev, struct quic_arng_node, first);
		arngs->enc_sz -= quic_int_getsize(last_node->last - last_node->first.key);
		arngs->enc_sz -= quic_int_getsize(sack_gap(prev_node, last_node));
		arngs->enc_sz -= quic_decint_size_diff(arngs->sz);
		--arngs->sz;
		eb64_delete(last);
		pool_free(pool_head_quic_arng, last);
		last = prev;
	}

	ret = 1;
 out:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return ret;
}

/* Set the encoded size of <arngs> QUIC ack ranges. */
static void quic_arngs_set_enc_sz(struct quic_conn *qc, struct quic_arngs *arngs)
{
	struct eb64_node *node, *next;
	struct quic_arng_node *ar, *ar_next;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	node = eb64_last(&arngs->root);
	if (!node)
		goto leave;

	ar = eb64_entry(node, struct quic_arng_node, first);
	arngs->enc_sz = quic_int_getsize(ar->last) +
		quic_int_getsize(ar->last - ar->first.key) + quic_int_getsize(arngs->sz - 1);

	while ((next = eb64_prev(node))) {
		ar_next = eb64_entry(next, struct quic_arng_node, first);
		arngs->enc_sz += quic_int_getsize(sack_gap(ar, ar_next)) +
			quic_int_getsize(ar_next->last - ar_next->first.key);
		node = next;
		ar = eb64_entry(node, struct quic_arng_node, first);
	}

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
}

/* Insert <ar> ack range into <argns> tree of ack ranges.
 * Returns the ack range node which has been inserted if succeeded, NULL if not.
 */
static inline
struct quic_arng_node *quic_insert_new_range(struct quic_conn *qc,
                                             struct quic_arngs *arngs,
                                             struct quic_arng *ar)
{
	struct quic_arng_node *new_ar;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT, qc);

	new_ar = pool_alloc(pool_head_quic_arng);
	if (!new_ar) {
		TRACE_ERROR("ack range allocation failed", QUIC_EV_CONN_RXPKT, qc);
		goto leave;
	}

	new_ar->first.key = ar->first;
	new_ar->last = ar->last;
	eb64_insert(&arngs->root, &new_ar->first);
	arngs->sz++;

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_RXPKT, qc);
	return new_ar;
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

returns 0 on error

 */
int quic_update_ack_ranges_list(struct quic_conn *qc,
                                struct quic_arngs *arngs,
                                struct quic_arng *ar)
{
	int ret = 0;
	struct eb64_node *le;
	struct quic_arng_node *new_node;
	struct eb64_node *new;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT, qc);

	new = NULL;
	if (eb_is_empty(&arngs->root)) {
		new_node = quic_insert_new_range(qc, arngs, ar);
		if (new_node)
			ret = 1;

		goto leave;
	}

	le = eb64_lookup_le(&arngs->root, ar->first);
	if (!le) {
		new_node = quic_insert_new_range(qc, arngs, ar);
		if (!new_node)
			goto leave;

		new = &new_node->first;
	}
	else {
		struct quic_arng_node *le_ar =
			eb64_entry(le, struct quic_arng_node, first);

		/* Already existing range */
		if (le_ar->last >= ar->last) {
			ret = 1;
		}
		else if (le_ar->last + 1 >= ar->first) {
			le_ar->last = ar->last;
			new = le;
			new_node = le_ar;
		}
		else {
			new_node = quic_insert_new_range(qc, arngs, ar);
			if (!new_node)
				goto leave;

			new = &new_node->first;
		}
	}

	/* Verify that the new inserted node does not overlap the nodes
	 * which follow it.
	 */
	if (new) {
		struct eb64_node *next;
		struct quic_arng_node *next_node;

		while ((next = eb64_next(new))) {
			next_node =
				eb64_entry(next, struct quic_arng_node, first);
			if (new_node->last + 1 < next_node->first.key)
				break;

			if (next_node->last > new_node->last)
				new_node->last = next_node->last;
			eb64_delete(next);
			pool_free(pool_head_quic_arng, next_node);
			/* Decrement the size of these ranges. */
			arngs->sz--;
		}
	}

	ret = 1;
 leave:
	quic_arngs_set_enc_sz(qc, arngs);
	TRACE_LEAVE(QUIC_EV_CONN_RXPKT, qc);
	return ret;
}
/* Remove the header protection of packets at <el> encryption level.
 * Always succeeds.
 */
static inline void qc_rm_hp_pkts(struct quic_conn *qc, struct quic_enc_level *el)
{
	struct quic_tls_ctx *tls_ctx;
	struct quic_rx_packet *pqpkt, *pkttmp;
	struct quic_enc_level *app_qel;

	TRACE_ENTER(QUIC_EV_CONN_ELRMHP, qc);
	app_qel = &qc->els[QUIC_TLS_ENC_LEVEL_APP];
	/* A server must not process incoming 1-RTT packets before the handshake is complete. */
	if (el == app_qel && qc_is_listener(qc) && qc->state < QUIC_HS_ST_COMPLETE) {
		TRACE_DEVEL("hp not removed (handshake not completed)",
		            QUIC_EV_CONN_ELRMHP, qc);
		goto out;
	}
	tls_ctx = &el->tls_ctx;
	list_for_each_entry_safe(pqpkt, pkttmp, &el->rx.pqpkts, list) {
		if (!qc_do_rm_hp(qc, pqpkt, tls_ctx, el->pktns->rx.largest_pn,
		                 pqpkt->data + pqpkt->pn_offset, pqpkt->data)) {
			TRACE_ERROR("hp removing error", QUIC_EV_CONN_ELRMHP, qc);
		}
		else {
			/* The AAD includes the packet number field */
			pqpkt->aad_len = pqpkt->pn_offset + pqpkt->pnl;
			/* Store the packet into the tree of packets to decrypt. */
			pqpkt->pn_node.key = pqpkt->pn;
			eb64_insert(&el->rx.pkts, &pqpkt->pn_node);
			quic_rx_packet_refinc(pqpkt);
			TRACE_DEVEL("hp removed", QUIC_EV_CONN_ELRMHP, qc, pqpkt);
		}
		LIST_DELETE(&pqpkt->list);
		quic_rx_packet_refdec(pqpkt);
	}

  out:
	TRACE_LEAVE(QUIC_EV_CONN_ELRMHP, qc);
}

/* Process all the CRYPTO frame at <el> encryption level. This is the
 * responsibility of the called to ensure there exists a CRYPTO data
 * stream for this level.
 * Return 1 if succeeded, 0 if not.
 */
static inline int qc_treat_rx_crypto_frms(struct quic_conn *qc,
                                          struct quic_enc_level *el,
                                          struct ssl_sock_ctx *ctx)
{
	int ret = 0;
	struct ncbuf *ncbuf;
	struct quic_cstream *cstream = el->cstream;
	ncb_sz_t data;

	TRACE_ENTER(QUIC_EV_CONN_PHPKTS, qc, el);

	BUG_ON(!cstream);
	ncbuf = &cstream->rx.ncbuf;
	if (ncb_is_null(ncbuf))
		goto done;

	/* TODO not working if buffer is wrapping */
	while ((data = ncb_data(ncbuf, 0))) {
		const unsigned char *cdata = (const unsigned char *)ncb_head(ncbuf);

		if (!qc_provide_cdata(el, ctx, cdata, data, NULL, NULL))
			goto leave;

		cstream->rx.offset += data;
		TRACE_DEVEL("buffered crypto data were provided to TLS stack",
		            QUIC_EV_CONN_PHPKTS, qc, el);
	}

 done:
	ret = 1;
 leave:
	if (!ncb_is_null(ncbuf) && ncb_is_empty(ncbuf)) {
		TRACE_DEVEL("freeing crypto buf", QUIC_EV_CONN_PHPKTS, qc, el);
		quic_free_ncbuf(ncbuf);
	}
	TRACE_LEAVE(QUIC_EV_CONN_PHPKTS, qc);
	return ret;
}

/* Process all the packets at <el> and <next_el> encryption level.
 * This is the caller responsibility to check that <cur_el> is different of <next_el>
 * as pointer value.
 * Return 1 if succeeded, 0 if not.
 */
int qc_treat_rx_pkts(struct quic_conn *qc, struct quic_enc_level *cur_el,
                     struct quic_enc_level *next_el, int force_ack)
{
	int ret = 0;
	struct eb64_node *node;
	int64_t largest_pn = -1;
	unsigned int largest_pn_time_received = 0;
	struct quic_enc_level *qel = cur_el;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT, qc);
	qel = cur_el;
 next_tel:
	if (!qel)
		goto out;

	node = eb64_first(&qel->rx.pkts);
	while (node) {
		struct quic_rx_packet *pkt;

		pkt = eb64_entry(node, struct quic_rx_packet, pn_node);
		TRACE_DATA("new packet", QUIC_EV_CONN_RXPKT,
		            qc, pkt, NULL, qc->xprt_ctx->ssl);
		if (!qc_pkt_decrypt(qc, qel, pkt)) {
			/* Drop the packet */
			TRACE_ERROR("packet decryption failed -> dropped",
			            QUIC_EV_CONN_RXPKT, qc, pkt);
		}
		else {
			if (!qc_parse_pkt_frms(qc, pkt, qel)) {
				/* Drop the packet */
				TRACE_ERROR("packet parsing failed -> dropped",
				            QUIC_EV_CONN_RXPKT, qc, pkt);
				HA_ATOMIC_INC(&qc->prx_counters->dropped_parsing);
			}
			else {
				struct quic_arng ar = { .first = pkt->pn, .last = pkt->pn };

				if (pkt->flags & QUIC_FL_RX_PACKET_ACK_ELICITING || force_ack) {
					qel->pktns->flags |= QUIC_FL_PKTNS_ACK_REQUIRED;
					qel->pktns->rx.nb_aepkts_since_last_ack++;
					qc_idle_timer_rearm(qc, 1);
				}
				if (pkt->pn > largest_pn) {
					largest_pn = pkt->pn;
					largest_pn_time_received = pkt->time_received;
				}
				/* Update the list of ranges to acknowledge. */
				if (!quic_update_ack_ranges_list(qc, &qel->pktns->rx.arngs, &ar))
					TRACE_ERROR("Could not update ack range list",
					            QUIC_EV_CONN_RXPKT, qc);
			}
		}
		node = eb64_next(node);
		eb64_delete(&pkt->pn_node);
		quic_rx_packet_refdec(pkt);
	}

	if (largest_pn != -1 && largest_pn > qel->pktns->rx.largest_pn) {
		/* Update the largest packet number. */
		qel->pktns->rx.largest_pn = largest_pn;
		/* Update the largest acknowledged packet timestamps */
		qel->pktns->rx.largest_time_received = largest_pn_time_received;
		qel->pktns->flags |= QUIC_FL_PKTNS_NEW_LARGEST_PN;
	}

	if (qel->cstream && !qc_treat_rx_crypto_frms(qc, qel, qc->xprt_ctx)) {
		// trace already emitted by function above
		goto leave;
	}

	if (qel == cur_el) {
		BUG_ON(qel == next_el);
		qel = next_el;
		largest_pn = -1;
		goto next_tel;
	}

 out:
	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_RXPKT, qc);
	return ret;
}

/* Check if it's possible to remove header protection for packets related to
 * encryption level <qel>. If <qel> is NULL, assume it's false.
 *
 * Return true if the operation is possible else false.
 */
static int qc_qel_may_rm_hp(struct quic_conn *qc, struct quic_enc_level *qel)
{
	int ret = 0;
	enum quic_tls_enc_level tel;

	TRACE_ENTER(QUIC_EV_CONN_TRMHP, qc);

	if (!qel)
		goto cant_rm_hp;

	tel = ssl_to_quic_enc_level(qel->level);

	/* check if tls secrets are available */
	if (qel->tls_ctx.flags & QUIC_FL_TLS_SECRETS_DCD) {
		TRACE_DEVEL("Discarded keys", QUIC_EV_CONN_TRMHP, qc);
		goto cant_rm_hp;
	}

	if (!quic_tls_has_rx_sec(qel)) {
		TRACE_DEVEL("non available secrets", QUIC_EV_CONN_TRMHP, qc);
		goto cant_rm_hp;
	}

	if (tel == QUIC_TLS_ENC_LEVEL_APP && qc->state < QUIC_HS_ST_COMPLETE) {
		TRACE_DEVEL("handshake not complete", QUIC_EV_CONN_TRMHP, qc);
		goto cant_rm_hp;
	}

	/* check if the connection layer is ready before using app level */
	if ((tel == QUIC_TLS_ENC_LEVEL_APP || tel == QUIC_TLS_ENC_LEVEL_EARLY_DATA) &&
	    qc->mux_state == QC_MUX_NULL) {
		TRACE_DEVEL("connection layer not ready", QUIC_EV_CONN_TRMHP, qc);
		goto cant_rm_hp;
	}

	ret = 1;
 cant_rm_hp:
	TRACE_LEAVE(QUIC_EV_CONN_TRMHP, qc);
	return ret;
}

/* Try to send application frames from list <frms> on connection <qc>.
 *
 * Use qc_send_app_probing wrapper when probing with old data.
 *
 * Returns 1 on success. Some data might not have been sent due to congestion,
 * in this case they are left in <frms> input list. The caller may subscribe on
 * quic-conn to retry later.
 *
 * Returns 0 on critical error.
 * TODO review and classify more distinctly transient from definitive errors to
 * allow callers to properly handle it.
 */
static int qc_send_app_pkts(struct quic_conn *qc, struct list *frms)
{
	int status = 0;
	struct buffer *buf;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	buf = qc_txb_alloc(qc);
	if (!buf) {
		TRACE_ERROR("buffer allocation failed", QUIC_EV_CONN_TXPKT, qc);
		goto leave;
	}

	/* Prepare and send packets until we could not further prepare packets. */
	while (1) {
		int ret;
		/* Currently buf cannot be non-empty at this stage. Even if a
		 * previous sendto() has failed it is emptied to simulate
		 * packet emission and rely on QUIC lost detection to try to
		 * emit it.
		 */
		BUG_ON_HOT(b_data(buf));
		b_reset(buf);

		ret = qc_prep_app_pkts(qc, buf, frms);
		if (ret == -1)
			goto err;
		else if (ret == 0)
			goto out;

		if (!qc_send_ppkts(buf, qc->xprt_ctx))
			goto err;
	}

 out:
	status = 1;
	qc_txb_release(qc);
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return status;

 err:
	qc_txb_release(qc);
	goto leave;
}

/* Try to send application frames from list <frms> on connection <qc>. Use this
 * function when probing is required.
 *
 * Returns the result from qc_send_app_pkts function.
 */
static forceinline int qc_send_app_probing(struct quic_conn *qc,
                                           struct list *frms)
{
	int ret;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	TRACE_STATE("preparing old data (probing)", QUIC_EV_CONN_TXPKT, qc);
	qc->flags |= QUIC_FL_CONN_RETRANS_OLD_DATA;
	ret = qc_send_app_pkts(qc, frms);
	qc->flags &= ~QUIC_FL_CONN_RETRANS_OLD_DATA;

	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return ret;
}

/* Try to send application frames from list <frms> on connection <qc>. This
 * function is provided for MUX upper layer usage only.
 *
 * Returns the result from qc_send_app_pkts function.
 */
int qc_send_mux(struct quic_conn *qc, struct list *frms)
{
	int ret;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);
	BUG_ON(qc->mux_state != QC_MUX_READY); /* Only MUX can uses this function so it must be ready. */

	TRACE_STATE("preparing data (from MUX)", QUIC_EV_CONN_TXPKT, qc);
	qc->flags |= QUIC_FL_CONN_TX_MUX_CONTEXT;
	ret = qc_send_app_pkts(qc, frms);
	qc->flags &= ~QUIC_FL_CONN_TX_MUX_CONTEXT;

	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return ret;
}

/* Sends handshake packets from up to two encryption levels <tel> and <next_te>
 * with <tel_frms> and <next_tel_frms> as frame list respectively for <qc>
 * QUIC connection. <old_data> is used as boolean to send data already sent but
 * not already acknowledged (in flight).
 * Returns 1 if succeeded, 0 if not.
 */
int qc_send_hdshk_pkts(struct quic_conn *qc, int old_data,
                       enum quic_tls_enc_level tel, struct list *tel_frms,
                       enum quic_tls_enc_level next_tel, struct list *next_tel_frms)
{
	int ret, status = 0;
	struct buffer *buf = qc_txb_alloc(qc);

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	if (!buf) {
		TRACE_ERROR("buffer allocation failed", QUIC_EV_CONN_TXPKT, qc);
		goto leave;
	}

	/* Currently buf cannot be non-empty at this stage. Even if a previous
	 * sendto() has failed it is emptied to simulate packet emission and
	 * rely on QUIC lost detection to try to emit it.
	 */
	BUG_ON_HOT(b_data(buf));
	b_reset(buf);

	if (old_data) {
		TRACE_STATE("old data for probing asked", QUIC_EV_CONN_TXPKT, qc);
		qc->flags |= QUIC_FL_CONN_RETRANS_OLD_DATA;
	}

	ret = qc_prep_pkts(qc, buf, tel, tel_frms, next_tel, next_tel_frms);
	if (ret == -1)
		goto out;
	else if (ret == 0)
		goto skip_send;

	if (!qc_send_ppkts(buf, qc->xprt_ctx))
		goto out;

 skip_send:
	status = 1;
 out:
	TRACE_STATE("no more need old data for probing", QUIC_EV_CONN_TXPKT, qc);
	qc->flags &= ~QUIC_FL_CONN_RETRANS_OLD_DATA;
	qc_txb_release(qc);
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return status;
}

/* Retransmit up to two datagrams depending on packet number space.
 * Return 0 when failed, 0 if not.
 */
static int qc_dgrams_retransmit(struct quic_conn *qc)
{
	int ret = 0;
	struct quic_enc_level *iqel = &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL];
	struct quic_enc_level *hqel = &qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE];
	struct quic_enc_level *aqel = &qc->els[QUIC_TLS_ENC_LEVEL_APP];

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	if (iqel->pktns->flags & QUIC_FL_PKTNS_PROBE_NEEDED) {
		int i;

		for (i = 0; i < QUIC_MAX_NB_PTO_DGRAMS; i++) {
			struct list ifrms = LIST_HEAD_INIT(ifrms);
			struct list hfrms = LIST_HEAD_INIT(hfrms);

			qc_prep_hdshk_fast_retrans(qc, &ifrms, &hfrms);
			TRACE_DEVEL("Avail. ack eliciting frames", QUIC_EV_CONN_FRMLIST, qc, &ifrms);
			TRACE_DEVEL("Avail. ack eliciting frames", QUIC_EV_CONN_FRMLIST, qc, &hfrms);
			if (!LIST_ISEMPTY(&ifrms)) {
				iqel->pktns->tx.pto_probe = 1;
				if (!LIST_ISEMPTY(&hfrms))
					hqel->pktns->tx.pto_probe = 1;
				if (!qc_send_hdshk_pkts(qc, 1, QUIC_TLS_ENC_LEVEL_INITIAL, &ifrms,
				                        QUIC_TLS_ENC_LEVEL_HANDSHAKE, &hfrms))
					goto leave;
				/* Put back unsent frames in their packet number spaces */
				LIST_SPLICE(&iqel->pktns->tx.frms, &ifrms);
				LIST_SPLICE(&hqel->pktns->tx.frms, &hfrms);
			}
		}
		TRACE_STATE("no more need to probe Initial packet number space",
					QUIC_EV_CONN_TXPKT, qc);
		iqel->pktns->flags &= ~QUIC_FL_PKTNS_PROBE_NEEDED;
		hqel->pktns->flags &= ~QUIC_FL_PKTNS_PROBE_NEEDED;
	}
	else {
		int i;

		if (hqel->pktns->flags & QUIC_FL_PKTNS_PROBE_NEEDED) {
			hqel->pktns->tx.pto_probe = 0;
			for (i = 0; i < QUIC_MAX_NB_PTO_DGRAMS; i++) {
				struct list frms1 = LIST_HEAD_INIT(frms1);

				qc_prep_fast_retrans(qc, hqel, &frms1, NULL);
				TRACE_DEVEL("Avail. ack eliciting frames", QUIC_EV_CONN_FRMLIST, qc, &frms1);
				if (!LIST_ISEMPTY(&frms1)) {
					hqel->pktns->tx.pto_probe = 1;
					if (!qc_send_hdshk_pkts(qc, 1, QUIC_TLS_ENC_LEVEL_HANDSHAKE, &frms1,
					                        QUIC_TLS_ENC_LEVEL_NONE, NULL))
						goto leave;

					/* Put back unsent frames into their packet number spaces */
					LIST_SPLICE(&hqel->pktns->tx.frms, &frms1);
				}
			}
			TRACE_STATE("no more need to probe Handshake packet number space",
			            QUIC_EV_CONN_TXPKT, qc);
			hqel->pktns->flags &= ~QUIC_FL_PKTNS_PROBE_NEEDED;
		}
		else if (aqel->pktns->flags & QUIC_FL_PKTNS_PROBE_NEEDED) {
			struct list frms2 = LIST_HEAD_INIT(frms2);
			struct list frms1 = LIST_HEAD_INIT(frms1);

			aqel->pktns->tx.pto_probe = 0;
			qc_prep_fast_retrans(qc, aqel, &frms1, &frms2);
			TRACE_PROTO("Avail. ack eliciting frames", QUIC_EV_CONN_FRMLIST, qc, &frms1);
			TRACE_PROTO("Avail. ack eliciting frames", QUIC_EV_CONN_FRMLIST, qc, &frms2);
			if (!LIST_ISEMPTY(&frms1)) {
				aqel->pktns->tx.pto_probe = 1;
				if (!qc_send_app_probing(qc, &frms1))
					goto leave;

				/* Put back unsent frames into their packet number spaces */
				LIST_SPLICE(&aqel->pktns->tx.frms, &frms1);
			}
			if (!LIST_ISEMPTY(&frms2)) {
				aqel->pktns->tx.pto_probe = 1;
				if (!qc_send_app_probing(qc, &frms2))
					goto leave;
				/* Put back unsent frames into their packet number spaces */
				LIST_SPLICE(&aqel->pktns->tx.frms, &frms2);
			}
			TRACE_STATE("no more need to probe 01RTT packet number space",
			            QUIC_EV_CONN_TXPKT, qc);
			aqel->pktns->flags &= ~QUIC_FL_PKTNS_PROBE_NEEDED;
		}
	}

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return ret;
}

/* QUIC connection packet handler task (post handshake) */
struct task *quic_conn_app_io_cb(struct task *t, void *context, unsigned int state)
{
	struct quic_conn *qc = context;
	struct quic_enc_level *qel;

	qel = &qc->els[QUIC_TLS_ENC_LEVEL_APP];

	TRACE_ENTER(QUIC_EV_CONN_IO_CB, qc);
	TRACE_STATE("connection handshake state", QUIC_EV_CONN_IO_CB, qc, &qc->state);

	if (qc_test_fd(qc))
		qc_rcv_buf(qc);

	/* Retranmissions */
	if (qc->flags & QUIC_FL_CONN_RETRANS_NEEDED) {
		TRACE_STATE("retransmission needed", QUIC_EV_CONN_IO_CB, qc);
		qc->flags &= ~QUIC_FL_CONN_RETRANS_NEEDED;
		if (!qc_dgrams_retransmit(qc))
			goto out;
	}

	if (!LIST_ISEMPTY(&qel->rx.pqpkts) && qc_qel_may_rm_hp(qc, qel))
		qc_rm_hp_pkts(qc, qel);

	if (!qc_treat_rx_pkts(qc, qel, NULL, 0)) {
		TRACE_DEVEL("qc_treat_rx_pkts() failed", QUIC_EV_CONN_IO_CB, qc);
		goto out;
	}

	if (qc->flags & QUIC_FL_CONN_TO_KILL) {
		TRACE_DEVEL("connection to be killed", QUIC_EV_CONN_IO_CB, qc);
		goto out;
	}

	if ((qc->flags & QUIC_FL_CONN_DRAINING) &&
	    !(qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE)) {
		TRACE_STATE("draining connection (must not send packets)", QUIC_EV_CONN_IO_CB, qc);
		goto out;
	}

	/* XXX TODO: how to limit the list frames to send */
	if (!qc_send_app_pkts(qc, &qel->pktns->tx.frms)) {
		TRACE_DEVEL("qc_send_app_pkts() failed", QUIC_EV_CONN_IO_CB, qc);
		goto out;
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_IO_CB, qc);
	return t;
}

/* Returns a boolean if <qc> needs to emit frames for <qel> encryption level. */
static int qc_need_sending(struct quic_conn *qc, struct quic_enc_level *qel)
{
	return (qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE) ||
	       (qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) ||
	       qel->pktns->tx.pto_probe ||
	       !LIST_ISEMPTY(&qel->pktns->tx.frms);
}

/* QUIC connection packet handler task. */
struct task *quic_conn_io_cb(struct task *t, void *context, unsigned int state)
{
	int ret, ssl_err;
	struct quic_conn *qc = context;
	enum quic_tls_enc_level tel, next_tel;
	struct quic_enc_level *qel, *next_qel;
	/* Early-data encryption level */
	struct quic_enc_level *eqel;
	struct buffer *buf = NULL;
	int st, force_ack, zero_rtt;

	TRACE_ENTER(QUIC_EV_CONN_IO_CB, qc);
	eqel = &qc->els[QUIC_TLS_ENC_LEVEL_EARLY_DATA];
	st = qc->state;
	TRACE_PROTO("connection state", QUIC_EV_CONN_IO_CB, qc, &st);

	/* Retranmissions */
	if (qc->flags & QUIC_FL_CONN_RETRANS_NEEDED) {
		TRACE_DEVEL("retransmission needed", QUIC_EV_CONN_PHPKTS, qc);
		qc->flags &= ~QUIC_FL_CONN_RETRANS_NEEDED;
		if (!qc_dgrams_retransmit(qc))
			goto out;
	}

	ssl_err = SSL_ERROR_NONE;
	zero_rtt = st < QUIC_HS_ST_COMPLETE &&
		quic_tls_has_rx_sec(eqel) &&
		(!LIST_ISEMPTY(&eqel->rx.pqpkts) || qc_el_rx_pkts(eqel));

	if (qc_test_fd(qc))
		qc_rcv_buf(qc);

	if (st >= QUIC_HS_ST_COMPLETE &&
	    qc_el_rx_pkts(&qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE])) {
		TRACE_DEVEL("remaining Handshake packets", QUIC_EV_CONN_PHPKTS, qc);
		/* There may be remaining Handshake packets to treat and acknowledge. */
		tel = QUIC_TLS_ENC_LEVEL_HANDSHAKE;
		next_tel = QUIC_TLS_ENC_LEVEL_APP;
	}
	else if (!quic_get_tls_enc_levels(&tel, &next_tel, qc, st, zero_rtt))
		goto out;

	qel = &qc->els[tel];
	next_qel = next_tel == QUIC_TLS_ENC_LEVEL_NONE ? NULL : &qc->els[next_tel];

 next_level:
	/* Treat packets waiting for header packet protection decryption */
	if (!LIST_ISEMPTY(&qel->rx.pqpkts) && qc_qel_may_rm_hp(qc, qel))
		qc_rm_hp_pkts(qc, qel);

	force_ack = qel == &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL] ||
		qel == &qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE];
	if (!qc_treat_rx_pkts(qc, qel, next_qel, force_ack))
		goto out;

	if (qc->flags & QUIC_FL_CONN_TO_KILL) {
		TRACE_DEVEL("connection to be killed", QUIC_EV_CONN_PHPKTS, qc);
		goto out;
	}

	if ((qc->flags & QUIC_FL_CONN_DRAINING) &&
	    !(qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE))
		goto out;

	zero_rtt = st < QUIC_HS_ST_COMPLETE &&
		quic_tls_has_rx_sec(eqel) &&
		(!LIST_ISEMPTY(&eqel->rx.pqpkts) || qc_el_rx_pkts(eqel));
	if (next_qel && next_qel == eqel && zero_rtt) {
		TRACE_DEVEL("select 0RTT as next encryption level",
					QUIC_EV_CONN_PHPKTS, qc);
		qel = next_qel;
		next_qel = NULL;
		goto next_level;
	}

	st = qc->state;
	if (st >= QUIC_HS_ST_COMPLETE) {
		if (!(qc->flags & QUIC_FL_CONN_POST_HANDSHAKE_FRAMES_BUILT) &&
		    !quic_build_post_handshake_frames(qc))
			goto out;

		if (!(qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE].tls_ctx.flags &
		           QUIC_FL_TLS_SECRETS_DCD)) {
			/* Discard the Handshake keys. */
			quic_tls_discard_keys(&qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE]);
			TRACE_PROTO("discarding Handshake pktns", QUIC_EV_CONN_PHPKTS, qc);
			quic_pktns_discard(qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE].pktns, qc);
			qc_set_timer(qc);
			qc_el_rx_pkts_del(&qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE]);
			qc_release_pktns_frms(qc, qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE].pktns);
		}

		if (qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE].pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) {
			/* There may be remaining handshake to build (acks) */
			st = QUIC_HS_ST_SERVER_HANDSHAKE;
		}
	}

	/* A listener does not send any O-RTT packet. O-RTT packet number space must not
	 * be considered.
	 */
	if (!quic_get_tls_enc_levels(&tel, &next_tel, qc, st, 0))
		goto out;

	if (!qc_need_sending(qc, qel) &&
	    (!next_qel || !qc_need_sending(qc, next_qel))) {
		goto skip_send;
	}

	buf = qc_txb_alloc(qc);
	if (!buf)
		goto out;

	/* Currently buf cannot be non-empty at this stage. Even if a previous
	 * sendto() has failed it is emptied to simulate packet emission and
	 * rely on QUIC lost detection to try to emit it.
	 */
	BUG_ON_HOT(b_data(buf));
	b_reset(buf);

	ret = qc_prep_pkts(qc, buf, tel, &qc->els[tel].pktns->tx.frms,
	                   next_tel, &qc->els[next_tel].pktns->tx.frms);
	if (ret == -1)
		goto out;
	else if (ret == 0)
		goto skip_send;

	if (!qc_send_ppkts(buf, qc->xprt_ctx))
		goto out;

 skip_send:
	/* Check if there is something to do for the next level.
	 */
	if (next_qel && next_qel != qel &&
	    quic_tls_has_rx_sec(next_qel) &&
	    (!LIST_ISEMPTY(&next_qel->rx.pqpkts) || qc_el_rx_pkts(next_qel))) {
		qel = next_qel;
		next_qel = NULL;
		goto next_level;
	}

 out:
	qc_txb_release(qc);
	TRACE_LEAVE(QUIC_EV_CONN_IO_CB, qc, &st, &ssl_err);
	return t;
}

/* Release the memory allocated for <cs> CRYPTO stream */
void quic_cstream_free(struct quic_cstream *cs)
{
	if (!cs) {
		/* This is the case for ORTT encryption level */
		return;
	}

	quic_free_ncbuf(&cs->rx.ncbuf);

	qc_stream_desc_release(cs->desc);
	pool_free(pool_head_quic_cstream, cs);
}

/* Allocate a new QUIC stream for <qc>.
 * Return it if succeeded, NULL if not.
 */
struct quic_cstream *quic_cstream_new(struct quic_conn *qc)
{
	struct quic_cstream *cs, *ret_cs = NULL;

	TRACE_ENTER(QUIC_EV_CONN_LPKT, qc);
	cs = pool_alloc(pool_head_quic_cstream);
	if (!cs) {
		TRACE_ERROR("crypto stream allocation failed", QUIC_EV_CONN_INIT, qc);
		goto leave;
	}

	cs->rx.offset = 0;
	cs->rx.ncbuf = NCBUF_NULL;
	cs->rx.offset = 0;

	cs->tx.offset = 0;
	cs->tx.sent_offset = 0;
	cs->tx.buf = BUF_NULL;
	cs->desc = qc_stream_desc_new((uint64_t)-1, -1, cs, qc);
	if (!cs->desc) {
		TRACE_ERROR("crypto stream allocation failed", QUIC_EV_CONN_INIT, qc);
		goto err;
	}

	ret_cs = cs;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc);
	return ret_cs;

 err:
	pool_free(pool_head_quic_cstream, cs);
	goto leave;
}

/* Uninitialize <qel> QUIC encryption level. Never fails. */
static void quic_conn_enc_level_uninit(struct quic_conn *qc, struct quic_enc_level *qel)
{
	int i;

	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);

	for (i = 0; i < qel->tx.crypto.nb_buf; i++) {
		if (qel->tx.crypto.bufs[i]) {
			pool_free(pool_head_quic_crypto_buf, qel->tx.crypto.bufs[i]);
			qel->tx.crypto.bufs[i] = NULL;
		}
	}
	ha_free(&qel->tx.crypto.bufs);
	quic_cstream_free(qel->cstream);

	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);
}

/* Initialize QUIC TLS encryption level with <level<> as level for <qc> QUIC
 * connection allocating everything needed.
 *
 * Returns 1 if succeeded, 0 if not. On error the caller is responsible to use
 * quic_conn_enc_level_uninit() to cleanup partially allocated content.
 */
static int quic_conn_enc_level_init(struct quic_conn *qc,
                                    enum quic_tls_enc_level level)
{
	int ret = 0;
	struct quic_enc_level *qel;

	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);

	qel = &qc->els[level];
	qel->level = quic_to_ssl_enc_level(level);
	qel->tls_ctx.rx.aead = qel->tls_ctx.tx.aead = NULL;
	qel->tls_ctx.rx.md   = qel->tls_ctx.tx.md = NULL;
	qel->tls_ctx.rx.hp   = qel->tls_ctx.tx.hp = NULL;
	qel->tls_ctx.flags = 0;

	qel->rx.pkts = EB_ROOT;
	LIST_INIT(&qel->rx.pqpkts);

	/* Allocate only one buffer. */
	/* TODO: use a pool */
	qel->tx.crypto.bufs = malloc(sizeof *qel->tx.crypto.bufs);
	if (!qel->tx.crypto.bufs)
		goto leave;

	qel->tx.crypto.bufs[0] = pool_alloc(pool_head_quic_crypto_buf);
	if (!qel->tx.crypto.bufs[0])
		goto leave;

	qel->tx.crypto.bufs[0]->sz = 0;
	qel->tx.crypto.nb_buf = 1;

	qel->tx.crypto.sz = 0;
	qel->tx.crypto.offset = 0;
	/* No CRYPTO data for early data TLS encryption level */
	if (level == QUIC_TLS_ENC_LEVEL_EARLY_DATA)
		qel->cstream = NULL;
	else {
		qel->cstream = quic_cstream_new(qc);
		if (!qel->cstream)
			goto leave;
	}

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);
	return ret;
}

/* Return 1 if <qc> connection may probe the Initial packet number space, 0 if not.
 * This is not the case if the remote peer address is not validated and if
 * it cannot send at least QUIC_INITIAL_PACKET_MINLEN bytes.
 */
static int qc_may_probe_ipktns(struct quic_conn *qc)
{
	return quic_peer_validated_addr(qc) ||
	       (int)(3 * qc->rx.bytes - qc->tx.prep_bytes) >= QUIC_INITIAL_PACKET_MINLEN;
}

/* Callback called upon loss detection and PTO timer expirations. */
struct task *qc_process_timer(struct task *task, void *ctx, unsigned int state)
{
	struct quic_conn *qc = ctx;
	struct quic_pktns *pktns;

	TRACE_ENTER(QUIC_EV_CONN_PTIMER, qc,
	            NULL, NULL, &qc->path->ifae_pkts);
	task->expire = TICK_ETERNITY;
	pktns = quic_loss_pktns(qc);
	if (tick_isset(pktns->tx.loss_time)) {
		struct list lost_pkts = LIST_HEAD_INIT(lost_pkts);

		qc_packet_loss_lookup(pktns, qc, &lost_pkts);
		if (!LIST_ISEMPTY(&lost_pkts))
		    tasklet_wakeup(qc->wait_event.tasklet);
		if (qc_release_lost_pkts(qc, pktns, &lost_pkts, now_ms))
			qc_set_timer(qc);
		goto out;
	}

	if (qc->path->in_flight) {
		pktns = quic_pto_pktns(qc, qc->state >= QUIC_HS_ST_CONFIRMED, NULL);
		if (qc->subs && qc->subs->events & SUB_RETRY_SEND) {
			pktns->tx.pto_probe = QUIC_MAX_NB_PTO_DGRAMS;
			tasklet_wakeup(qc->subs->tasklet);
			qc->subs->events &= ~SUB_RETRY_SEND;
			if (!qc->subs->events)
				qc->subs = NULL;
		}
		else {
			if (pktns == &qc->pktns[QUIC_TLS_PKTNS_INITIAL]) {
				if (qc_may_probe_ipktns(qc)) {
					qc->flags |= QUIC_FL_CONN_RETRANS_NEEDED;
					pktns->flags |= QUIC_FL_PKTNS_PROBE_NEEDED;
					TRACE_STATE("needs to probe Initial packet number space", QUIC_EV_CONN_TXPKT, qc);
				}
				else {
					TRACE_STATE("Cannot probe Initial packet number space", QUIC_EV_CONN_TXPKT, qc);
				}
				if (qc->pktns[QUIC_TLS_PKTNS_HANDSHAKE].tx.in_flight) {
					qc->flags |= QUIC_FL_CONN_RETRANS_NEEDED;
					qc->pktns[QUIC_TLS_PKTNS_HANDSHAKE].flags |= QUIC_FL_PKTNS_PROBE_NEEDED;
					TRACE_STATE("needs to probe Handshake packet number space", QUIC_EV_CONN_TXPKT, qc);
				}
			}
			else if (pktns == &qc->pktns[QUIC_TLS_PKTNS_HANDSHAKE]) {
				TRACE_STATE("needs to probe Handshake packet number space", QUIC_EV_CONN_TXPKT, qc);
				qc->flags |= QUIC_FL_CONN_RETRANS_NEEDED;
				pktns->flags |= QUIC_FL_PKTNS_PROBE_NEEDED;
				if (qc->pktns[QUIC_TLS_PKTNS_INITIAL].tx.in_flight) {
					if (qc_may_probe_ipktns(qc)) {
						qc->pktns[QUIC_TLS_PKTNS_INITIAL].flags |= QUIC_FL_PKTNS_PROBE_NEEDED;
						TRACE_STATE("needs to probe Initial packet number space", QUIC_EV_CONN_TXPKT, qc);
					}
					else {
						TRACE_STATE("Cannot probe Initial packet number space", QUIC_EV_CONN_TXPKT, qc);
					}
				}
			}
			else if (pktns == &qc->pktns[QUIC_TLS_PKTNS_01RTT]) {
				TRACE_STATE("needs to probe 01RTT packet number space", QUIC_EV_CONN_TXPKT, qc);
				qc->flags |= QUIC_FL_CONN_RETRANS_NEEDED;
				pktns->flags |= QUIC_FL_PKTNS_PROBE_NEEDED;
			}
		}
	}
	else if (!qc_is_listener(qc) && qc->state <= QUIC_HS_ST_COMPLETE) {
		struct quic_enc_level *iel = &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL];
		struct quic_enc_level *hel = &qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE];

		if (quic_tls_has_tx_sec(hel))
			hel->pktns->tx.pto_probe = 1;
		if (quic_tls_has_tx_sec(iel))
			iel->pktns->tx.pto_probe = 1;
	}

	tasklet_wakeup(qc->wait_event.tasklet);
	qc->path->loss.pto_count++;

 out:
	TRACE_LEAVE(QUIC_EV_CONN_PTIMER, qc, pktns);

	return task;
}

/* Parse the Retry token from buffer <token> with <end> a pointer to
 * one byte past the end of this buffer. This will extract the ODCID
 * which will be stored into <odcid>
 *
 * Returns 0 on success else non-zero.
 */
static int parse_retry_token(struct quic_conn *qc,
                             const unsigned char *token, const unsigned char *end,
                             struct quic_cid *odcid)
{
	int ret = 0;
	uint64_t odcid_len;
	uint32_t timestamp;

	TRACE_ENTER(QUIC_EV_CONN_LPKT, qc);

	if (!quic_dec_int(&odcid_len, &token, end)) {
		TRACE_ERROR("quic_dec_int() error", QUIC_EV_CONN_LPKT, qc);
		goto leave;
	}

	/* RFC 9000 7.2. Negotiating Connection IDs:
	 * When an Initial packet is sent by a client that has not previously
	 * received an Initial or Retry packet from the server, the client
	 * populates the Destination Connection ID field with an unpredictable
	 * value. This Destination Connection ID MUST be at least 8 bytes in length.
	 */
	if (odcid_len < QUIC_ODCID_MINLEN || odcid_len > QUIC_CID_MAXLEN) {
		TRACE_ERROR("wrong ODCID length", QUIC_EV_CONN_LPKT, qc);
		goto leave;
	}

	if (end - token < odcid_len + sizeof timestamp) {
		TRACE_ERROR("too long ODCID length", QUIC_EV_CONN_LPKT, qc);
		goto leave;
	}

	timestamp = ntohl(read_u32(token + odcid_len));
	if (timestamp + MS_TO_TICKS(QUIC_RETRY_DURATION_MS) <= now_ms) {
		TRACE_ERROR("token has expired", QUIC_EV_CONN_LPKT, qc);
		goto leave;
	}

	ret = 1;
	memcpy(odcid->data, token, odcid_len);
	odcid->len = odcid_len;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc);
	return !ret;
}

/* Allocate a new QUIC connection with <version> as QUIC version. <ipv4>
 * boolean is set to 1 for IPv4 connection, 0 for IPv6. <server> is set to 1
 * for QUIC servers (or haproxy listeners).
 * <dcid> is the destination connection ID, <scid> is the source connection ID,
 * <token> the token found to be used for this connection with <token_len> as
 * length. Endpoints addresses are specified via <local_addr> and <peer_addr>.
 * Returns the connection if succeeded, NULL if not.
 */
static struct quic_conn *qc_new_conn(const struct quic_version *qv, int ipv4,
                                     struct quic_cid *dcid, struct quic_cid *scid,
                                     const struct quic_cid *token_odcid,
                                     struct sockaddr_storage *local_addr,
                                     struct sockaddr_storage *peer_addr,
                                     int server, int token, void *owner)
{
	int i;
	struct quic_conn *qc;
	/* Initial CID. */
	struct quic_connection_id *icid;
	char *buf_area = NULL;
	struct listener *l = NULL;
	struct quic_cc_algo *cc_algo = NULL;
	struct quic_tls_ctx *ictx;
	TRACE_ENTER(QUIC_EV_CONN_INIT);
	/* TODO replace pool_zalloc by pool_alloc(). This requires special care
	 * to properly initialized internal quic_conn members to safely use
	 * quic_conn_release() on alloc failure.
	 */
	qc = pool_zalloc(pool_head_quic_conn);
	if (!qc) {
		TRACE_ERROR("Could not allocate a new connection", QUIC_EV_CONN_INIT);
		goto err;
	}

	/* Initialize in priority qc members required for a safe dealloc. */

	/* required to use MTLIST_IN_LIST */
	MT_LIST_INIT(&qc->accept_list);

	LIST_INIT(&qc->rx.pkt_list);

	qc_init_fd(qc);

	LIST_INIT(&qc->back_refs);

	/* Now proceeds to allocation of qc members. */

	buf_area = pool_alloc(pool_head_quic_conn_rxbuf);
	if (!buf_area) {
		TRACE_ERROR("Could not allocate a new RX buffer", QUIC_EV_CONN_INIT, qc);
		goto err;
	}

	qc->cids = EB_ROOT;
	/* QUIC Server (or listener). */
	if (server) {
		struct proxy *prx;

		l = owner;
		prx = l->bind_conf->frontend;
		cc_algo = l->bind_conf->quic_cc_algo;

		qc->prx_counters = EXTRA_COUNTERS_GET(prx->extra_counters_fe,
		                                      &quic_stats_module);
		qc->flags |= QUIC_FL_CONN_LISTENER;
		qc->state = QUIC_HS_ST_SERVER_INITIAL;
		/* Copy the initial DCID with the address. */
		qc->odcid.len = dcid->len;
		qc->odcid.addrlen = dcid->addrlen;
		memcpy(qc->odcid.data, dcid->data, dcid->len + dcid->addrlen);

		/* copy the packet SCID to reuse it as DCID for sending */
		if (scid->len)
			memcpy(qc->dcid.data, scid->data, scid->len);
		qc->dcid.len = scid->len;
		qc->tx.buf = BUF_NULL;
		qc->li = l;
	}
	/* QUIC Client (outgoing connection to servers) */
	else {
		qc->state = QUIC_HS_ST_CLIENT_INITIAL;
		if (dcid->len)
			memcpy(qc->dcid.data, dcid->data, dcid->len);
		qc->dcid.len = dcid->len;
	}
	qc->mux_state = QC_MUX_NULL;
	qc->err = quic_err_transport(QC_ERR_NO_ERROR);

	icid = new_quic_cid(&qc->cids, qc, 0);
	if (!icid) {
		TRACE_ERROR("Could not allocate a new connection ID", QUIC_EV_CONN_INIT, qc);
		goto err;
	}

	if ((global.tune.options & GTUNE_QUIC_SOCK_PER_CONN) &&
	    is_addr(local_addr)) {
		TRACE_USER("Allocate a socket for QUIC connection", QUIC_EV_CONN_INIT, qc);
		qc_alloc_fd(qc, local_addr, peer_addr);

		/* haproxy soft-stop is supported only for QUIC connections
		 * with their owned socket.
		 */
		if (qc_test_fd(qc))
			_HA_ATOMIC_INC(&jobs);
	}

	/* insert the allocated CID in the receiver datagram handler tree */
	if (server)
		ebmb_insert(&quic_dghdlrs[tid].cids, &icid->node, icid->cid.len);

	/* Select our SCID which is the first CID with 0 as sequence number. */
	qc->scid = icid->cid;

	/* Packet number spaces initialization. */
	for (i = 0; i < QUIC_TLS_PKTNS_MAX; i++)
		quic_pktns_init(&qc->pktns[i]);
	/* QUIC encryption level context initialization. */
	for (i = 0; i < QUIC_TLS_ENC_LEVEL_MAX; i++) {
		if (!quic_conn_enc_level_init(qc, i)) {
			TRACE_ERROR("Could not initialize an encryption level", QUIC_EV_CONN_INIT, qc);
			goto err;
		}
		/* Initialize the packet number space. */
		qc->els[i].pktns = &qc->pktns[quic_tls_pktns(i)];
	}

	qc->original_version = qv;
	qc->tps_tls_ext = (qc->original_version->num & 0xff000000) == 0xff000000 ?
		TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS_DRAFT:
		TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS;
	/* TX part. */
	LIST_INIT(&qc->tx.frms_to_send);
	qc->tx.nb_buf = QUIC_CONN_TX_BUFS_NB;
	qc->tx.wbuf = qc->tx.rbuf = 0;
	qc->tx.bytes = 0;
	qc->tx.buf = BUF_NULL;
	/* RX part. */
	qc->rx.bytes = 0;
	qc->rx.buf = b_make(buf_area, QUIC_CONN_RX_BUFSZ, 0, 0);
	for (i = 0; i < QCS_MAX_TYPES; i++)
		qc->rx.strms[i].nb_streams = 0;

	qc->nb_pkt_for_cc = 1;
	qc->nb_pkt_since_cc = 0;

	if (!quic_tls_ku_init(qc)) {
		TRACE_ERROR("Key update initialization failed", QUIC_EV_CONN_INIT, qc);
		goto err;
	}

	/* XXX TO DO: Only one path at this time. */
	qc->path = &qc->paths[0];
	quic_path_init(qc->path, ipv4, cc_algo ? cc_algo : default_quic_cc_algo, qc);

	qc->streams_by_id = EB_ROOT_UNIQUE;
	qc->stream_buf_count = 0;
	memcpy(&qc->local_addr, local_addr, sizeof(qc->local_addr));
	memcpy(&qc->peer_addr, peer_addr, sizeof qc->peer_addr);

	if (server && !qc_lstnr_params_init(qc, &l->bind_conf->quic_params,
	                                    icid->stateless_reset_token,
	                                    dcid->data, dcid->len,
	                                    qc->scid.data, qc->scid.len, token_odcid))
		goto err;

	qc->wait_event.tasklet = tasklet_new();
	if (!qc->wait_event.tasklet) {
		TRACE_ERROR("tasklet_new() failed", QUIC_EV_CONN_TXPKT);
		goto err;
	}
	qc->wait_event.tasklet->process = quic_conn_io_cb;
	qc->wait_event.tasklet->context = qc;
	qc->wait_event.events = 0;
	/* Set tasklet tid based on the SCID selected by us for this
	 * connection. The upper layer will also be binded on the same thread.
	 */
	qc->tid = quic_get_cid_tid(qc->scid.data, &l->rx);
	qc->wait_event.tasklet->tid = qc->tid;
	qc->subs = NULL;

	if (qc_conn_alloc_ssl_ctx(qc) ||
	    !quic_conn_init_timer(qc) ||
	    !quic_conn_init_idle_timer_task(qc))
		goto err;

	ictx = &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL].tls_ctx;
	if (!qc_new_isecs(qc, ictx,qc->original_version, dcid->data, dcid->len, 1))
		goto err;

	LIST_APPEND(&th_ctx->quic_conns, &qc->el_th_ctx);
	qc->qc_epoch = HA_ATOMIC_LOAD(&qc_epoch);

	TRACE_LEAVE(QUIC_EV_CONN_INIT, qc);

	return qc;

 err:
	pool_free(pool_head_quic_conn_rxbuf, buf_area);
	if (qc) {
		qc->rx.buf.area = NULL;
		quic_conn_release(qc);
	}
	TRACE_LEAVE(QUIC_EV_CONN_INIT);
	return NULL;
}

/* Release the quic_conn <qc>. The connection is removed from the CIDs tree.
 * The connection tasklet is killed.
 *
 * This function must only be called by the thread responsible of the quic_conn
 * tasklet.
 */
void quic_conn_release(struct quic_conn *qc)
{
	int i;
	struct ssl_sock_ctx *conn_ctx;
	struct eb64_node *node;
	struct quic_tls_ctx *app_tls_ctx;
	struct quic_rx_packet *pkt, *pktback;
	struct bref *bref, *back;

	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);

	/* We must not free the quic-conn if the MUX is still allocated. */
	BUG_ON(qc->mux_state == QC_MUX_READY);

	if (qc_test_fd(qc))
		_HA_ATOMIC_DEC(&jobs);

	/* Close quic-conn socket fd. */
	qc_release_fd(qc, 0);

	/* in the unlikely (but possible) case the connection was just added to
	 * the accept_list we must delete it from there.
	 */
	MT_LIST_DELETE(&qc->accept_list);

	/* free remaining stream descriptors */
	node = eb64_first(&qc->streams_by_id);
	while (node) {
		struct qc_stream_desc *stream;

		stream = eb64_entry(node, struct qc_stream_desc, by_id);
		node = eb64_next(node);

		/* all streams attached to the quic-conn are released, so
		 * qc_stream_desc_free will liberate the stream instance.
		 */
		BUG_ON(!stream->release);
		qc_stream_desc_free(stream, 1);
	}

	/* Purge Rx packet list. */
	list_for_each_entry_safe(pkt, pktback, &qc->rx.pkt_list, qc_rx_pkt_list) {
		LIST_DELETE(&pkt->qc_rx_pkt_list);
		pool_free(pool_head_quic_rx_packet, pkt);
	}

	if (qc->idle_timer_task) {
		task_destroy(qc->idle_timer_task);
		qc->idle_timer_task = NULL;
	}

	if (qc->timer_task) {
		task_destroy(qc->timer_task);
		qc->timer_task = NULL;
	}

	if (qc->wait_event.tasklet)
		tasklet_free(qc->wait_event.tasklet);

	/* remove the connection from receiver cids trees */
	ebmb_delete(&qc->odcid_node);
	ebmb_delete(&qc->scid_node);
	free_quic_conn_cids(qc);

	conn_ctx = qc->xprt_ctx;
	if (conn_ctx) {
		SSL_free(conn_ctx->ssl);
		pool_free(pool_head_quic_conn_ctx, conn_ctx);
	}

	quic_tls_ku_free(qc);
	for (i = 0; i < QUIC_TLS_ENC_LEVEL_MAX; i++) {
		quic_tls_ctx_secs_free(&qc->els[i].tls_ctx);
		quic_conn_enc_level_uninit(qc, &qc->els[i]);
	}
	quic_tls_ctx_secs_free(&qc->negotiated_ictx);

	app_tls_ctx = &qc->els[QUIC_TLS_ENC_LEVEL_APP].tls_ctx;
	pool_free(pool_head_quic_tls_secret, app_tls_ctx->rx.secret);
	pool_free(pool_head_quic_tls_secret, app_tls_ctx->tx.secret);

	for (i = 0; i < QUIC_TLS_PKTNS_MAX; i++) {
		quic_pktns_tx_pkts_release(&qc->pktns[i], qc);
		quic_free_arngs(qc, &qc->pktns[i].rx.arngs);
	}

	/* Detach CLI context watchers currently dumping this connection.
	 * Reattach them to the next quic_conn instance.
	 */
	list_for_each_entry_safe(bref, back, &qc->back_refs, users) {
		/* Remove watcher from this quic_conn instance. */
		LIST_DEL_INIT(&bref->users);

		/* Attach it to next instance unless it was the last list element. */
		if (qc->el_th_ctx.n != &th_ctx->quic_conns) {
			struct quic_conn *next = LIST_NEXT(&qc->el_th_ctx,
			                                   struct quic_conn *,
			                                   el_th_ctx);
			LIST_APPEND(&next->back_refs, &bref->users);
		}
		bref->ref = qc->el_th_ctx.n;
		__ha_barrier_store();
	}
	/* Remove quic_conn from global ha_thread_ctx list. */
	LIST_DELETE(&qc->el_th_ctx);

	pool_free(pool_head_quic_conn_rxbuf, qc->rx.buf.area);
	pool_free(pool_head_quic_conn, qc);

	TRACE_PROTO("QUIC conn. freed", QUIC_EV_CONN_FREED, qc);

	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);
}

/* Initialize the timer task of <qc> QUIC connection.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_conn_init_timer(struct quic_conn *qc)
{
	int ret = 0;
	/* Attach this task to the same thread ID used for the connection */
	TRACE_ENTER(QUIC_EV_CONN_NEW, qc);

	qc->timer_task = task_new_on(qc->tid);
	if (!qc->timer_task) {
		TRACE_ERROR("timer task allocation failed", QUIC_EV_CONN_NEW, qc);
		goto leave;
	}

	qc->timer = TICK_ETERNITY;
	qc->timer_task->process = qc_process_timer;
	qc->timer_task->context = qc;

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);
	return ret;
}

/* Rearm the idle timer for <qc> QUIC connection. */
static void qc_idle_timer_do_rearm(struct quic_conn *qc)
{
	unsigned int expire;

	if (stopping && qc->flags & (QUIC_FL_CONN_CLOSING|QUIC_FL_CONN_DRAINING)) {
		TRACE_STATE("executing idle timer immediately on stopping", QUIC_EV_CONN_IDLE_TIMER, qc);
		task_wakeup(qc->idle_timer_task, TASK_WOKEN_MSG);
	}
	else {
		expire = QUIC_MAX(3 * quic_pto(qc), qc->max_idle_timeout);
		qc->idle_timer_task->expire = tick_add(now_ms, MS_TO_TICKS(expire));
		task_queue(qc->idle_timer_task);
	}
}

/* Rearm the idle timer for <qc> QUIC connection depending on <read> boolean
 * which is set to 1 when receiving a packet , and 0 when sending packet
 */
static void qc_idle_timer_rearm(struct quic_conn *qc, int read)
{
	TRACE_ENTER(QUIC_EV_CONN_IDLE_TIMER, qc);

	if (read) {
		qc->flags |= QUIC_FL_CONN_IDLE_TIMER_RESTARTED_AFTER_READ;
	}
	else {
		qc->flags &= ~QUIC_FL_CONN_IDLE_TIMER_RESTARTED_AFTER_READ;
	}
	qc_idle_timer_do_rearm(qc);

	TRACE_LEAVE(QUIC_EV_CONN_IDLE_TIMER, qc);
}

/* The task handling the idle timeout */
struct task *qc_idle_timer_task(struct task *t, void *ctx, unsigned int state)
{
	struct quic_conn *qc = ctx;
	struct quic_counters *prx_counters = qc->prx_counters;
	unsigned int qc_flags = qc->flags;

	TRACE_ENTER(QUIC_EV_CONN_IDLE_TIMER, qc);

	/* Notify the MUX before settings QUIC_FL_CONN_EXP_TIMER or the MUX
	 * might free the quic-conn too early via quic_close().
	 */
	qc_notify_close(qc);

	/* If the MUX is still alive, keep the quic-conn. The MUX is
	 * responsible to call quic_close to release it.
	 */
	qc->flags |= QUIC_FL_CONN_EXP_TIMER;
	if (qc->mux_state != QC_MUX_READY)
		quic_conn_release(qc);

	/* TODO if the quic-conn cannot be freed because of the MUX, we may at
	 * least clean some parts of it such as the tasklet.
	 */

	if (!(qc_flags & QUIC_FL_CONN_HALF_OPEN_CNT_DECREMENTED)) {
		qc_flags |= QUIC_FL_CONN_HALF_OPEN_CNT_DECREMENTED;
		TRACE_DEVEL("dec half open counter", QUIC_EV_CONN_SSLALERT, qc);
		HA_ATOMIC_DEC(&prx_counters->half_open_conn);
	}

	TRACE_LEAVE(QUIC_EV_CONN_IDLE_TIMER, qc);
	return NULL;
}

/* Initialize the idle timeout task for <qc>.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_conn_init_idle_timer_task(struct quic_conn *qc)
{
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_NEW, qc);

	qc->idle_timer_task = task_new_here();
	if (!qc->idle_timer_task) {
		TRACE_ERROR("Idle timer task allocation failed", QUIC_EV_CONN_NEW, qc);
		goto leave;
	}

	qc->idle_timer_task->process = qc_idle_timer_task;
	qc->idle_timer_task->context = qc;
	qc_idle_timer_rearm(qc, 1);
	task_queue(qc->idle_timer_task);

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);
	return ret;
}

/* Parse into <pkt> a long header located at <*buf> buffer, <end> begin a pointer to the end
 * past one byte of this buffer.
 */
static inline int quic_packet_read_long_header(unsigned char **buf, const unsigned char *end,
                                               struct quic_rx_packet *pkt)
{
	int ret = 0;
	unsigned char dcid_len, scid_len;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT);

	if (end == *buf) {
		TRACE_ERROR("buffer data consumed",  QUIC_EV_CONN_RXPKT);
		goto leave;
	}

	/* Destination Connection ID Length */
	dcid_len = *(*buf)++;
	/* We want to be sure we can read <dcid_len> bytes and one more for <scid_len> value */
	if (dcid_len > QUIC_CID_MAXLEN || end - *buf < dcid_len + 1) {
		TRACE_ERROR("too long DCID",  QUIC_EV_CONN_RXPKT);
		goto leave;
	}

	if (dcid_len) {
		/* Check that the length of this received DCID matches the CID lengths
		 * of our implementation for non Initials packets only.
		 */
		if (pkt->type != QUIC_PACKET_TYPE_INITIAL &&
		    pkt->type != QUIC_PACKET_TYPE_0RTT &&
		    dcid_len != QUIC_HAP_CID_LEN) {
			TRACE_ERROR("wrong DCID length", QUIC_EV_CONN_RXPKT);
			goto leave;
		}

		memcpy(pkt->dcid.data, *buf, dcid_len);
	}

	pkt->dcid.len = dcid_len;
	*buf += dcid_len;

	/* Source Connection ID Length */
	scid_len = *(*buf)++;
	if (scid_len > QUIC_CID_MAXLEN || end - *buf < scid_len) {
		TRACE_ERROR("too long SCID",  QUIC_EV_CONN_RXPKT);
		goto leave;
	}

	if (scid_len)
		memcpy(pkt->scid.data, *buf, scid_len);
	pkt->scid.len = scid_len;
	*buf += scid_len;

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_RXPKT);
	return ret;
}

/* Insert <pkt> RX packet in its <qel> RX packets tree */
static void qc_pkt_insert(struct quic_conn *qc,
                          struct quic_rx_packet *pkt, struct quic_enc_level *qel)
{
	TRACE_ENTER(QUIC_EV_CONN_RXPKT, qc);

	pkt->pn_node.key = pkt->pn;
	quic_rx_packet_refinc(pkt);
	eb64_insert(&qel->rx.pkts, &pkt->pn_node);

	TRACE_LEAVE(QUIC_EV_CONN_RXPKT, qc);
}

/* Try to remove the header protection of <pkt> QUIC packet with <beg> the
 * address of the packet first byte, using the keys from encryption level <el>.
 *
 * If header protection has been successfully removed, packet data are copied
 * into <qc> Rx buffer. If <el> secrets are not yet available, the copy is also
 * proceeded, and the packet is inserted into <qc> protected packets tree. In
 * both cases, packet can now be considered handled by the <qc> connection.
 *
 * If header protection cannot be removed due to <el> secrets already
 * discarded, no operation is conducted.
 *
 * Returns 1 on success : packet data is now handled by the connection. On
 * error 0 is returned : packet should be dropped by the caller.
 */
static inline int qc_try_rm_hp(struct quic_conn *qc,
                               struct quic_rx_packet *pkt,
                               unsigned char *beg,
                               struct quic_enc_level **el)
{
	int ret = 0;
	unsigned char *pn = NULL; /* Packet number field */
	enum quic_tls_enc_level tel;
	struct quic_enc_level *qel;
	/* Only for traces. */
	struct quic_rx_packet *qpkt_trace;

	qpkt_trace = NULL;
	TRACE_ENTER(QUIC_EV_CONN_TRMHP, qc);
	BUG_ON(!pkt->pn_offset);

	/* The packet number is here. This is also the start minus
	 * QUIC_PACKET_PN_MAXLEN of the sample used to add/remove the header
	 * protection.
	 */
	pn = beg + pkt->pn_offset;

	tel = quic_packet_type_enc_level(pkt->type);
	qel = &qc->els[tel];

	if (qc_qel_may_rm_hp(qc, qel)) {
		 /* Note that the following function enables us to unprotect the packet
		 * number and its length subsequently used to decrypt the entire
		 * packets.
		 */
		if (!qc_do_rm_hp(qc, pkt, &qel->tls_ctx,
		                 qel->pktns->rx.largest_pn, pn, beg)) {
			TRACE_PROTO("hp error", QUIC_EV_CONN_TRMHP, qc);
			goto out;
		}

		/* The AAD includes the packet number field. */
		pkt->aad_len = pkt->pn_offset + pkt->pnl;
		if (pkt->len - pkt->aad_len < QUIC_TLS_TAG_LEN) {
			TRACE_PROTO("Too short packet", QUIC_EV_CONN_TRMHP, qc);
			goto out;
		}

		qpkt_trace = pkt;
	}
	else {
		if (qel->tls_ctx.flags & QUIC_FL_TLS_SECRETS_DCD) {
			/* If the packet number space has been discarded, this packet
			 * will be not parsed.
			 */
			TRACE_PROTO("Discarded pktns", QUIC_EV_CONN_TRMHP, qc, pkt);
			goto out;
		}

		TRACE_PROTO("hp not removed", QUIC_EV_CONN_TRMHP, qc, pkt);
		LIST_APPEND(&qel->rx.pqpkts, &pkt->list);
		quic_rx_packet_refinc(pkt);
	}

	*el = qel;
	/* No reference counter incrementation here!!! */
	LIST_APPEND(&qc->rx.pkt_list, &pkt->qc_rx_pkt_list);
	memcpy(b_tail(&qc->rx.buf), beg, pkt->len);
	pkt->data = (unsigned char *)b_tail(&qc->rx.buf);
	b_add(&qc->rx.buf, pkt->len);
	
	ret = 1;
 out:
	TRACE_LEAVE(QUIC_EV_CONN_TRMHP, qc, qpkt_trace);
	return ret;
}

/* Parse the header form from <byte0> first byte of <pkt> packet to set its type.
 * Also set <*long_header> to 1 if this form is long, 0 if not and the version
 * of this packet into <*version>.
 */
static inline int qc_parse_hd_form(struct quic_rx_packet *pkt,
                                   unsigned char **buf, const unsigned char *end,
                                   int *long_header, uint32_t *version)
{
	int ret = 0;
	const unsigned char byte0 = **buf;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT);

	(*buf)++;
	if (byte0 & QUIC_PACKET_LONG_HEADER_BIT) {
		unsigned char type =
			(byte0 >> QUIC_PACKET_TYPE_SHIFT) & QUIC_PACKET_TYPE_BITMASK;

		*long_header = 1;
		/* Version */
		if (!quic_read_uint32(version, (const unsigned char **)buf, end)) {
			TRACE_ERROR("could not read the packet version", QUIC_EV_CONN_RXPKT);
			goto out;
		}

		if (*version != QUIC_PROTOCOL_VERSION_2) {
			pkt->type = type;
		}
		else {
			switch (type) {
			case 0:
				pkt->type = QUIC_PACKET_TYPE_RETRY;
				break;
			case 1:
				pkt->type = QUIC_PACKET_TYPE_INITIAL;
				break;
			case 2:
				pkt->type = QUIC_PACKET_TYPE_0RTT;
				break;
			case 3:
				pkt->type = QUIC_PACKET_TYPE_HANDSHAKE;
				break;
			}
		}
	}
	else {
		pkt->type = QUIC_PACKET_TYPE_SHORT;
		*long_header = 0;
	}

	ret = 1;
 out:
	TRACE_LEAVE(QUIC_EV_CONN_RXPKT);
	return ret;
}

/* Return the QUIC version (quic_version struct) with <version> as version number
 * if supported or NULL if not.
 */
static inline const struct quic_version *qc_supported_version(uint32_t version)
{
	int i;

	for (i = 0; i < quic_versions_nb; i++)
		if (quic_versions[i].num == version)
			return &quic_versions[i];

	return NULL;
}

/*
 * Send a Version Negotiation packet on response to <pkt> on socket <fd> to
 * address <addr>.
 * Implementation of RFC9000 6. Version Negotiation
 *
 * TODO implement a rate-limiting sending of Version Negotiation packets
 *
 * Returns 0 on success else non-zero
 */
static int send_version_negotiation(int fd, struct sockaddr_storage *addr,
                                    struct quic_rx_packet *pkt)
{
	char buf[256];
	int ret = 0, i = 0, j;
	uint32_t version;
	const socklen_t addrlen = get_addr_len(addr);

	TRACE_ENTER(QUIC_EV_CONN_TXPKT);
	/*
	 * header form
	 * long header, fixed bit to 0 for Version Negotiation
	 */
	/* TODO: RAND_bytes() should be replaced? */
	if (RAND_bytes((unsigned char *)buf, 1) != 1) {
		TRACE_ERROR("RAND_bytes() error", QUIC_EV_CONN_TXPKT);
		goto out;
	}

	buf[i++] |= '\x80';
	/* null version for Version Negotiation */
	buf[i++] = '\x00';
	buf[i++] = '\x00';
	buf[i++] = '\x00';
	buf[i++] = '\x00';

	/* source connection id */
	buf[i++] = pkt->scid.len;
	memcpy(&buf[i], pkt->scid.data, pkt->scid.len);
	i += pkt->scid.len;

	/* destination connection id */
	buf[i++] = pkt->dcid.len;
	memcpy(&buf[i], pkt->dcid.data, pkt->dcid.len);
	i += pkt->dcid.len;

	/* supported version */
	for (j = 0; j < quic_versions_nb; j++) {
		version = htonl(quic_versions[j].num);
		memcpy(&buf[i], &version, sizeof(version));
		i += sizeof(version);
	}

	if (sendto(fd, buf, i, 0, (struct sockaddr *)addr, addrlen) < 0)
		goto out;

	ret = 1;
 out:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT);
	return !ret;
}

/* Send a stateless reset packet depending on <pkt> RX packet information
 * from <fd> UDP socket to <dst>
 * Return 1 if succeeded, 0 if not.
 */
static int send_stateless_reset(struct listener *l, struct sockaddr_storage *dstaddr,
                                struct quic_rx_packet *rxpkt)
{
	int ret = 0, pktlen, rndlen;
	unsigned char pkt[64];
	const socklen_t addrlen = get_addr_len(dstaddr);
	struct proxy *prx;
	struct quic_counters *prx_counters;

	TRACE_ENTER(QUIC_EV_STATELESS_RST);

	prx = l->bind_conf->frontend;
	prx_counters = EXTRA_COUNTERS_GET(prx->extra_counters_fe, &quic_stats_module);
	/* 10.3 Stateless Reset (https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3)
	 * The resulting minimum size of 21 bytes does not guarantee that a Stateless
	 * Reset is difficult to distinguish from other packets if the recipient requires
	 * the use of a connection ID. To achieve that end, the endpoint SHOULD ensure
	 * that all packets it sends are at least 22 bytes longer than the minimum
	 * connection ID length that it requests the peer to include in its packets,
	 * adding PADDING frames as necessary. This ensures that any Stateless Reset
	 * sent by the peer is indistinguishable from a valid packet sent to the endpoint.
	 * An endpoint that sends a Stateless Reset in response to a packet that is
	 * 43 bytes or shorter SHOULD send a Stateless Reset that is one byte shorter
	 * than the packet it responds to.
	 */

	/* Note that we build at most a 42 bytes QUIC packet to mimic a short packet */
	pktlen = rxpkt->len <= 43 ? rxpkt->len - 1 : 0;
	pktlen = QUIC_MAX(QUIC_STATELESS_RESET_PACKET_MINLEN, pktlen);
	rndlen = pktlen - QUIC_STATELESS_RESET_TOKEN_LEN;

	/* Put a header of random bytes */
	/* TODO: RAND_bytes() should be replaced */
	if (RAND_bytes(pkt, rndlen) != 1) {
		TRACE_ERROR("RAND_bytes() failed", QUIC_EV_STATELESS_RST);
		goto leave;
	}

	/* Clear the most significant bit, and set the second one */
	*pkt = (*pkt & ~0x80) | 0x40;
	if (!quic_stateless_reset_token_cpy(NULL, pkt + rndlen, QUIC_STATELESS_RESET_TOKEN_LEN,
	                                    rxpkt->dcid.data, rxpkt->dcid.len))
		goto leave;

	if (sendto(l->rx.fd, pkt, pktlen, 0, (struct sockaddr *)dstaddr, addrlen) < 0)
		goto leave;

    ret = 1;
	HA_ATOMIC_INC(&prx_counters->stateless_reset_sent);
	TRACE_PROTO("stateless reset sent", QUIC_EV_STATELESS_RST, NULL, &rxpkt->dcid);
 leave:
	TRACE_LEAVE(QUIC_EV_STATELESS_RST);
	return ret;
}

/* QUIC server only function.
 * Add AAD to <add> buffer from <cid> connection ID and <addr> socket address.
 * This is the responsibility of the caller to check <aad> size is big enough
 * to contain these data.
 * Return the number of bytes copied to <aad>.
 */
static int quic_generate_retry_token_aad(unsigned char *aad,
                                         uint32_t version,
                                         const struct quic_cid *cid,
                                         const struct sockaddr_storage *addr)
{
	unsigned char *p;

	p = aad;
	memcpy(p, &version, sizeof version);
	p += sizeof version;
	p += quic_saddr_cpy(p, addr);
	memcpy(p, cid->data, cid->len);
	p += cid->len;

	return p - aad;
}

/* QUIC server only function.
 * Generate the token to be used in Retry packets. The token is written to
 * <buf> with <len> as length. <odcid> is the original destination connection
 * ID and <dcid> is our side destination connection ID (or client source
 * connection ID).
 * Returns the length of the encoded token or 0 on error.
 */
static int quic_generate_retry_token(unsigned char *buf, size_t len,
                                     const uint32_t version,
                                     const struct quic_cid *odcid,
                                     const struct quic_cid *dcid,
                                     struct sockaddr_storage *addr)
{
	int ret = 0;
	unsigned char *p;
	unsigned char aad[sizeof(uint32_t) + sizeof(in_port_t) +
	                  sizeof(struct in6_addr) + QUIC_CID_MAXLEN];
	size_t aadlen;
	unsigned char salt[QUIC_RETRY_TOKEN_SALTLEN];
	unsigned char key[QUIC_TLS_KEY_LEN];
	unsigned char iv[QUIC_TLS_IV_LEN];
	const unsigned char *sec = (const unsigned char *)global.cluster_secret;
	size_t seclen = strlen(global.cluster_secret);
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *aead = EVP_aes_128_gcm();
	uint32_t timestamp = now_ms;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT);

	/* We copy the odcid into the token, prefixed by its one byte
	 * length, the format token byte. It is followed by an AEAD TAG, and finally
	 * the random bytes used to derive the secret to encrypt the token.
	 */
	if (1 + dcid->len + 1 + QUIC_TLS_TAG_LEN + sizeof salt > len)
		goto err;

	aadlen = quic_generate_retry_token_aad(aad, version, dcid, addr);
	/* TODO: RAND_bytes() should be replaced */
	if (RAND_bytes(salt, sizeof salt) != 1) {
		TRACE_ERROR("RAND_bytes()", QUIC_EV_CONN_TXPKT);
		goto err;
	}

	if (!quic_tls_derive_retry_token_secret(EVP_sha256(), key, sizeof key, iv, sizeof iv,
	                                        salt, sizeof salt, sec, seclen)) {
		TRACE_ERROR("quic_tls_derive_retry_token_secret() failed", QUIC_EV_CONN_TXPKT);
		goto err;
	}

	if (!quic_tls_tx_ctx_init(&ctx, aead, key)) {
		TRACE_ERROR("quic_tls_tx_ctx_init() failed", QUIC_EV_CONN_TXPKT);
		goto err;
	}

	/* Token build */
	p = buf;
	*p++ = QUIC_TOKEN_FMT_RETRY,
	*p++ = odcid->len;
	memcpy(p, odcid->data, odcid->len);
	p += odcid->len;
	write_u32(p, htonl(timestamp));
	p += sizeof timestamp;

	/* Do not encrypt the QUIC_TOKEN_FMT_RETRY byte */
	if (!quic_tls_encrypt(buf + 1, p - buf - 1, aad, aadlen, ctx, aead, key, iv)) {
		TRACE_ERROR("quic_tls_encrypt() failed", QUIC_EV_CONN_TXPKT);
		goto err;
	}

	p += QUIC_TLS_TAG_LEN;
	memcpy(p, salt, sizeof salt);
	p += sizeof salt;
	EVP_CIPHER_CTX_free(ctx);

	ret = p - buf;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT);
	return ret;

 err:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	goto leave;
}

/* QUIC server only function.
 *
 * Check the validity of the Retry token from Initial packet <pkt>. <dgram> is
 * the UDP datagram containing <pkt> and <l> is the listener instance on which
 * it was received. If the token is valid, the ODCID of <qc> QUIC connection
 * will be put into <odcid>. <qc> is used to retrieve the QUIC version needed
 * to validate the token but it can be NULL : in this case the version will be
 * retrieved from the packet.
 *
 * Return 1 if succeeded, 0 if not.
 */

static int quic_retry_token_check(struct quic_rx_packet *pkt,
                                  struct quic_dgram *dgram,
                                  struct listener *l,
                                  struct quic_conn *qc,
                                  struct quic_cid *odcid)
{
	struct proxy *prx;
	struct quic_counters *prx_counters;
	int ret = 0;
	unsigned char *token = pkt->token;
	const uint64_t tokenlen = pkt->token_len;
	unsigned char buf[128];
	unsigned char aad[sizeof(uint32_t) + sizeof(in_port_t) +
	                  sizeof(struct in6_addr) + QUIC_CID_MAXLEN];
	size_t aadlen;
	const unsigned char *salt;
	unsigned char key[QUIC_TLS_KEY_LEN];
	unsigned char iv[QUIC_TLS_IV_LEN];
	const unsigned char *sec = (const unsigned char *)global.cluster_secret;
	size_t seclen = strlen(global.cluster_secret);
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *aead = EVP_aes_128_gcm();
	const struct quic_version *qv = qc ? qc->original_version :
	                                     pkt->version;

	TRACE_ENTER(QUIC_EV_CONN_LPKT, qc);

	/* The caller must ensure this. */
	BUG_ON(!global.cluster_secret || !pkt->token_len);

	prx = l->bind_conf->frontend;
	prx_counters = EXTRA_COUNTERS_GET(prx->extra_counters_fe, &quic_stats_module);

	if (*pkt->token != QUIC_TOKEN_FMT_RETRY) {
		/* TODO: New token check */
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT, qc, NULL, NULL, pkt->version);
		goto leave;
	}

	if (sizeof buf < tokenlen) {
		TRACE_ERROR("too short buffer", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	aadlen = quic_generate_retry_token_aad(aad, qv->num, &pkt->scid, &dgram->saddr);
	salt = token + tokenlen - QUIC_RETRY_TOKEN_SALTLEN;
	if (!quic_tls_derive_retry_token_secret(EVP_sha256(), key, sizeof key, iv, sizeof iv,
	                                        salt, QUIC_RETRY_TOKEN_SALTLEN, sec, seclen)) {
		TRACE_ERROR("Could not derive retry secret", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	if (!quic_tls_rx_ctx_init(&ctx, aead, key)) {
		TRACE_ERROR("quic_tls_rx_ctx_init() failed", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	/* Do not decrypt the QUIC_TOKEN_FMT_RETRY byte */
	if (!quic_tls_decrypt2(buf, token + 1, tokenlen - QUIC_RETRY_TOKEN_SALTLEN - 1, aad, aadlen,
	                       ctx, aead, key, iv)) {
		TRACE_ERROR("Could not decrypt retry token", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	if (parse_retry_token(qc, buf, buf + tokenlen - QUIC_RETRY_TOKEN_SALTLEN - 1, odcid)) {
		TRACE_ERROR("Error during Initial token parsing", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	EVP_CIPHER_CTX_free(ctx);

	ret = 1;
	HA_ATOMIC_INC(&prx_counters->retry_validated);

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc);
	return ret;

 err:
	HA_ATOMIC_INC(&prx_counters->retry_error);
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	goto leave;
}

/* Generate a Retry packet and send it on <fd> socket to <addr> in response to
 * the Initial <pkt> packet.
 *
 * Returns 0 on success else non-zero.
 */
static int send_retry(int fd, struct sockaddr_storage *addr,
                      struct quic_rx_packet *pkt, const struct quic_version *qv)
{
	int ret = 0;
	unsigned char buf[128];
	int i = 0, token_len;
	const socklen_t addrlen = get_addr_len(addr);
	struct quic_cid scid;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT);

	/* long header + fixed bit + packet type QUIC_PACKET_TYPE_RETRY */
	buf[i++] = (QUIC_PACKET_LONG_HEADER_BIT | QUIC_PACKET_FIXED_BIT) |
		(quic_pkt_type(QUIC_PACKET_TYPE_RETRY, qv->num) << QUIC_PACKET_TYPE_SHIFT);
	/* version */
	buf[i++] = *((unsigned char *)&qv->num + 3);
	buf[i++] = *((unsigned char *)&qv->num + 2);
	buf[i++] = *((unsigned char *)&qv->num + 1);
	buf[i++] = *(unsigned char *)&qv->num;

	/* Use the SCID from <pkt> for Retry DCID. */
	buf[i++] = pkt->scid.len;
	memcpy(&buf[i], pkt->scid.data, pkt->scid.len);
	i += pkt->scid.len;

	/* Generate a new CID to be used as SCID for the Retry packet. */
	scid.len = QUIC_HAP_CID_LEN;
	/* TODO: RAND_bytes() should be replaced */
	if (RAND_bytes(scid.data, scid.len) != 1) {
		TRACE_ERROR("RAND_bytes() failed", QUIC_EV_CONN_TXPKT);
		goto out;
	}

	buf[i++] = scid.len;
	memcpy(&buf[i], scid.data, scid.len);
	i += scid.len;

	/* token */
	if (!(token_len = quic_generate_retry_token(&buf[i], sizeof(buf) - i, qv->num,
	                                            &pkt->dcid, &pkt->scid, addr))) {
		TRACE_ERROR("quic_generate_retry_token() failed", QUIC_EV_CONN_TXPKT);
		goto out;
	}

	i += token_len;

	/* token integrity tag */
	if ((&buf[i] - buf < QUIC_TLS_TAG_LEN) ||
	    !quic_tls_generate_retry_integrity_tag(pkt->dcid.data,
	                                           pkt->dcid.len, buf, i, qv)) {
		TRACE_ERROR("quic_tls_generate_retry_integrity_tag() failed", QUIC_EV_CONN_TXPKT);
		goto out;
	}

	i += QUIC_TLS_TAG_LEN;

	if (sendto(fd, buf, i, 0, (struct sockaddr *)addr, addrlen) < 0) {
		TRACE_ERROR("quic_tls_generate_retry_integrity_tag() failed", QUIC_EV_CONN_TXPKT);
		goto out;
	}

	ret = 1;
 out:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT);
	return !ret;
}

/* Retrieve a quic_conn instance from the <pkt> DCID field. If the packet is of
 * type INITIAL, the ODCID tree is first used. In this case, <saddr> is
 * concatenated to the <pkt> DCID field.
 *
 * Returns the instance or NULL if not found.
 */
static struct quic_conn *retrieve_qc_conn_from_cid(struct quic_rx_packet *pkt,
                                                   struct listener *l,
                                                   struct sockaddr_storage *saddr)
{
	struct quic_conn *qc = NULL;
	struct ebmb_node *node;
	struct quic_connection_id *id;
	/* set if the quic_conn is found in the second DCID tree */

	TRACE_ENTER(QUIC_EV_CONN_RXPKT);

	/* Look first into ODCIDs tree for INITIAL/0-RTT packets. */
	if (pkt->type == QUIC_PACKET_TYPE_INITIAL ||
	    pkt->type == QUIC_PACKET_TYPE_0RTT) {
		/* DCIDs of first packets coming from multiple clients may have
		 * the same values. Let's distinguish them by concatenating the
		 * socket addresses.
		 */
		quic_cid_saddr_cat(&pkt->dcid, saddr);
		node = ebmb_lookup(&quic_dghdlrs[tid].odcids, pkt->dcid.data,
		                   pkt->dcid.len + pkt->dcid.addrlen);
		if (node) {
			qc = ebmb_entry(node, struct quic_conn, odcid_node);
			goto end;
		}
	}

	/* Look into DCIDs tree for non-INITIAL/0-RTT packets. This may be used
	 * also for INITIAL/0-RTT non-first packets with the final DCID in
	 * used.
	 */
	node = ebmb_lookup(&quic_dghdlrs[tid].cids, pkt->dcid.data, pkt->dcid.len);
	if (!node)
		goto end;

	id = ebmb_entry(node, struct quic_connection_id, node);
	qc = id->qc;

	/* If found in DCIDs tree, remove the quic_conn from the ODCIDs tree.
	 * If already done, this is a noop.
	 */
	if (qc)
		ebmb_delete(&qc->odcid_node);

 end:
	TRACE_LEAVE(QUIC_EV_CONN_RXPKT, qc);
	return qc;
}

/* Try to allocate the <*ssl> SSL session object for <qc> QUIC connection
 * with <ssl_ctx> as SSL context inherited settings. Also set the transport
 * parameters of this session.
 * This is the responsibility of the caller to check the validity of all the
 * pointers passed as parameter to this function.
 * Return 0 if succeeded, -1 if not. If failed, sets the ->err_code member of <qc->conn> to
 * CO_ER_SSL_NO_MEM.
 */
static int qc_ssl_sess_init(struct quic_conn *qc, SSL_CTX *ssl_ctx, SSL **ssl,
                            unsigned char *params, size_t params_len)
{
	int retry, ret = -1;

	TRACE_ENTER(QUIC_EV_CONN_NEW, qc);

	retry = 1;
 retry:
	*ssl = SSL_new(ssl_ctx);
	if (!*ssl) {
		if (!retry--)
			goto err;

		pool_gc(NULL);
		goto retry;
	}

	if (!SSL_set_quic_method(*ssl, &ha_quic_method) ||
	    !SSL_set_ex_data(*ssl, ssl_qc_app_data_index, qc)) {
		SSL_free(*ssl);
		*ssl = NULL;
		if (!retry--)
			goto err;

		pool_gc(NULL);
		goto retry;
	}

	ret = 0;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);
	return ret;

 err:
	qc->conn->err_code = CO_ER_SSL_NO_MEM;
	goto leave;
}

/* Allocate the ssl_sock_ctx from connection <qc>. This creates the tasklet
 * used to process <qc> received packets. The allocated context is stored in
 * <qc.xprt_ctx>.
 *
 * Returns 0 on success else non-zero.
 */
static int qc_conn_alloc_ssl_ctx(struct quic_conn *qc)
{
	int ret = 0;
	struct bind_conf *bc = qc->li->bind_conf;
	struct ssl_sock_ctx *ctx = NULL;

	TRACE_ENTER(QUIC_EV_CONN_NEW, qc);

	ctx = pool_zalloc(pool_head_quic_conn_ctx);
	if (!ctx) {
		TRACE_ERROR("SSL context allocation failed", QUIC_EV_CONN_TXPKT);
		goto err;
	}

	ctx->subs = NULL;
	ctx->xprt_ctx = NULL;
	ctx->qc = qc;

	if (qc_is_listener(qc)) {
		if (qc_ssl_sess_init(qc, bc->initial_ctx, &ctx->ssl,
		                     qc->enc_params, qc->enc_params_len) == -1) {
		        goto err;
		}
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
		/* Enabling 0-RTT */
		if (bc->ssl_conf.early_data)
			SSL_set_quic_early_data_enabled(ctx->ssl, 1);
#endif

		SSL_set_accept_state(ctx->ssl);
	}

	ctx->xprt = xprt_get(XPRT_QUIC);

	/* Store the allocated context in <qc>. */
	qc->xprt_ctx = ctx;

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);
	return !ret;

 err:
	pool_free(pool_head_quic_conn_ctx, ctx);
	goto leave;
}

/* Check that all the bytes between <buf> included and <end> address
 * excluded are null. This is the responsibility of the caller to
 * check that there is at least one byte between <buf> end <end>.
 * Return 1 if this all the bytes are null, 0 if not.
 */
static inline int quic_padding_check(const unsigned char *buf,
                                     const unsigned char *end)
{
	while (buf < end && !*buf)
		buf++;

	return buf == end;
}

/* Find the associated connection to the packet <pkt> or create a new one if
 * this is an Initial packet. <dgram> is the datagram containing the packet and
 * <l> is the listener instance on which it was received.
 *
 * Returns the quic-conn instance or NULL.
 */
static struct quic_conn *quic_rx_pkt_retrieve_conn(struct quic_rx_packet *pkt,
                                                   struct quic_dgram *dgram,
                                                   struct listener *l)
{
	struct quic_cid token_odcid = { .len = 0 };
	struct quic_conn *qc = NULL;
	struct proxy *prx;
	struct quic_counters *prx_counters;

	TRACE_ENTER(QUIC_EV_CONN_LPKT);

	prx = l->bind_conf->frontend;
	prx_counters = EXTRA_COUNTERS_GET(prx->extra_counters_fe, &quic_stats_module);

	qc = retrieve_qc_conn_from_cid(pkt, l, &dgram->saddr);

	if (pkt->type == QUIC_PACKET_TYPE_INITIAL) {
		BUG_ON(!pkt->version); /* This must not happen. */

		if (global.cluster_secret && pkt->token_len) {
			if (!quic_retry_token_check(pkt, dgram, l, qc, &token_odcid))
				goto err;
		}

		if (!qc) {
			int ipv4;

			if (global.cluster_secret && !pkt->token_len && !(l->bind_conf->options & BC_O_QUIC_FORCE_RETRY) &&
			    HA_ATOMIC_LOAD(&prx_counters->half_open_conn) >= global.tune.quic_retry_threshold) {
				TRACE_PROTO("Initial without token, sending retry",
				            QUIC_EV_CONN_LPKT, NULL, NULL, NULL, pkt->version);
				if (send_retry(l->rx.fd, &dgram->saddr, pkt, pkt->version)) {
					TRACE_ERROR("Error during Retry generation",
					            QUIC_EV_CONN_LPKT, NULL, NULL, NULL, pkt->version);
					goto out;
				}

				HA_ATOMIC_INC(&prx_counters->retry_sent);
				goto out;
			}

			/* RFC 9000 7.2. Negotiating Connection IDs:
			 * When an Initial packet is sent by a client that has not previously
			 * received an Initial or Retry packet from the server, the client
			 * populates the Destination Connection ID field with an unpredictable
			 * value. This Destination Connection ID MUST be at least 8 bytes in length.
			 */
			if (pkt->dcid.len < QUIC_ODCID_MINLEN) {
				TRACE_PROTO("dropped packet",
				            QUIC_EV_CONN_LPKT, NULL, NULL, NULL, pkt->version);
				goto err;
			}

			pkt->saddr = dgram->saddr;
			ipv4 = dgram->saddr.ss_family == AF_INET;

			qc = qc_new_conn(pkt->version, ipv4, &pkt->dcid, &pkt->scid, &token_odcid,
			                 &dgram->daddr, &pkt->saddr, 1,
			                 !!pkt->token_len, l);
			if (qc == NULL)
				goto err;

			HA_ATOMIC_INC(&prx_counters->half_open_conn);
			/* Insert the DCID the QUIC client has chosen (only for listeners) */
			ebmb_insert(&quic_dghdlrs[tid].odcids, &qc->odcid_node,
			            qc->odcid.len + qc->odcid.addrlen);
		}
	}
	else if (!qc) {
		TRACE_PROTO("No connection on a non Initial packet", QUIC_EV_CONN_LPKT, NULL, NULL, NULL, pkt->version);
		if (global.cluster_secret && !send_stateless_reset(l, &dgram->saddr, pkt))
			TRACE_ERROR("stateless reset not sent", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc);
	return qc;

 err:
	HA_ATOMIC_INC(&prx_counters->dropped_pkt);
	TRACE_LEAVE(QUIC_EV_CONN_LPKT);
	return NULL;
}

/* Parse a QUIC packet starting at <buf>. Data won't be read after <end> even
 * if the packet is incomplete. This function will populate fields of <pkt>
 * instance, most notably its length. <dgram> is the UDP datagram which
 * contains the parsed packet. <l> is the listener instance on which it was
 * received.
 *
 * Returns 0 on success else non-zero. Packet length is guaranteed to be set to
 * the real packet value or to cover all data between <buf> and <end> : this is
 * useful to reject a whole datagram.
 */
static int quic_rx_pkt_parse(struct quic_rx_packet *pkt,
                             unsigned char *buf, const unsigned char *end,
                             struct quic_dgram *dgram, struct listener *l)
{
	const unsigned char *beg = buf;
	struct proxy *prx;
	struct quic_counters *prx_counters;
	int long_header = 0;
	uint32_t version = 0;
	const struct quic_version *qv = NULL;

	TRACE_ENTER(QUIC_EV_CONN_LPKT);

	prx = l->bind_conf->frontend;
	prx_counters = EXTRA_COUNTERS_GET(prx->extra_counters_fe, &quic_stats_module);
	/* This ist only to please to traces and distinguish the
	 * packet with parsed packet number from others.
	 */
	pkt->pn_node.key = (uint64_t)-1;
	if (end <= buf) {
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
		goto drop;
	}

	/* Fixed bit */
	if (!(*buf & QUIC_PACKET_FIXED_BIT)) {
		if (!(pkt->flags & QUIC_FL_RX_PACKET_DGRAM_FIRST) &&
		    quic_padding_check(buf, end)) {
			/* Some browsers may pad the remaining datagram space with null bytes.
			 * That is what we called add padding out of QUIC packets. Such
			 * datagrams must be considered as valid. But we can only consume
			 * the remaining space.
			 */
			pkt->len = end - buf;
			goto drop_silent;
		}

		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
		goto drop;
	}

	/* Header form */
	if (!qc_parse_hd_form(pkt, &buf, end, &long_header, &version)) {
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
		goto drop;
	}

	if (long_header) {
		uint64_t len;

		TRACE_PROTO("long header packet received", QUIC_EV_CONN_LPKT);
		if (!quic_packet_read_long_header(&buf, end, pkt)) {
			TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
			goto drop;
		}

		/* When multiple QUIC packets are coalesced on the same UDP datagram,
		 * they must have the same DCID.
		 */
		if (!(pkt->flags & QUIC_FL_RX_PACKET_DGRAM_FIRST) &&
		    (pkt->dcid.len != dgram->dcid_len ||
		     memcmp(dgram->dcid, pkt->dcid.data, pkt->dcid.len))) {
			TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
			goto drop;
		}

		/* Retry of Version Negotiation packets are only sent by servers */
		if (pkt->type == QUIC_PACKET_TYPE_RETRY || !version) {
			TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
			goto drop;
		}

		/* RFC9000 6. Version Negotiation */
		qv = qc_supported_version(version);
		if (!qv) {
			 /* unsupported version, send Negotiation packet */
			if (send_version_negotiation(l->rx.fd, &dgram->saddr, pkt)) {
				TRACE_ERROR("VN packet not sent", QUIC_EV_CONN_LPKT);
				goto drop_silent;
			}

			TRACE_PROTO("VN packet sent", QUIC_EV_CONN_LPKT);
			goto drop_silent;
		}
		pkt->version = qv;

		/* For Initial packets, and for servers (QUIC clients connections),
		 * there is no Initial connection IDs storage.
		 */
		if (pkt->type == QUIC_PACKET_TYPE_INITIAL) {
			uint64_t token_len;

			if (!quic_dec_int(&token_len, (const unsigned char **)&buf, end) ||
				end - buf < token_len) {
				TRACE_PROTO("Packet dropped",
				            QUIC_EV_CONN_LPKT, NULL, NULL, NULL, qv);
				goto drop;
			}

			/* TODO Retry should be automatically activated if
			 * suspect network usage is detected.
			 */
			if (global.cluster_secret && !token_len) {
				if (l->bind_conf->options & BC_O_QUIC_FORCE_RETRY) {
					TRACE_PROTO("Initial without token, sending retry",
					            QUIC_EV_CONN_LPKT, NULL, NULL, NULL, qv);
					if (send_retry(l->rx.fd, &dgram->saddr, pkt, qv)) {
						TRACE_PROTO("Error during Retry generation",
						            QUIC_EV_CONN_LPKT, NULL, NULL, NULL, qv);
						goto drop_silent;
					}

					HA_ATOMIC_INC(&prx_counters->retry_sent);
					goto drop_silent;
				}
			}
			else if (!global.cluster_secret && token_len) {
				/* Impossible case: a token was received without configured
				 * cluster secret.
				 */
				TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT,
				            NULL, NULL, NULL, qv);
				goto drop;
			}

			pkt->token = buf;
			pkt->token_len = token_len;
			buf += pkt->token_len;
		}
		else if (pkt->type != QUIC_PACKET_TYPE_0RTT) {
			if (pkt->dcid.len != QUIC_HAP_CID_LEN) {
				TRACE_PROTO("Packet dropped",
				            QUIC_EV_CONN_LPKT, NULL, NULL, NULL, qv);
				goto drop;
			}
		}

		if (!quic_dec_int(&len, (const unsigned char **)&buf, end) ||
			end - buf < len) {
			TRACE_PROTO("Packet dropped",
			            QUIC_EV_CONN_LPKT, NULL, NULL, NULL, qv);
			goto drop;
		}

		/* Packet Number is stored here. Packet Length totalizes the
		 * rest of the content.
		 */
		pkt->pn_offset = buf - beg;
		pkt->len = pkt->pn_offset + len;

		/* RFC 9000. Initial Datagram Size
		 *
		 * A server MUST discard an Initial packet that is carried in a UDP datagram
		 * with a payload that is smaller than the smallest allowed maximum datagram
		 * size of 1200 bytes.
		 */
		if (pkt->type == QUIC_PACKET_TYPE_INITIAL &&
		    dgram->len < QUIC_INITIAL_PACKET_MINLEN) {
			TRACE_PROTO("Too short datagram with an Initial packet", QUIC_EV_CONN_LPKT);
			HA_ATOMIC_INC(&prx_counters->too_short_initial_dgram);
			goto drop;
		}

		/* Interrupt parsing after packet length retrieval : this
		 * ensures that only the packet is dropped but not the whole
		 * datagram.
		 */
		if (pkt->type == QUIC_PACKET_TYPE_0RTT && !l->bind_conf->ssl_conf.early_data) {
			TRACE_PROTO("0-RTT packet not supported", QUIC_EV_CONN_LPKT);
			goto drop;
		}
	}
	else {
		TRACE_PROTO("short header packet received", QUIC_EV_CONN_LPKT);
		if (end - buf < QUIC_HAP_CID_LEN) {
			TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
			goto drop;
		}

		memcpy(pkt->dcid.data, buf, QUIC_HAP_CID_LEN);
		pkt->dcid.len = QUIC_HAP_CID_LEN;

		/* When multiple QUIC packets are coalesced on the same UDP datagram,
		 * they must have the same DCID.
		 */
		if (!(pkt->flags & QUIC_FL_RX_PACKET_DGRAM_FIRST) &&
		    (pkt->dcid.len != dgram->dcid_len ||
		     memcmp(dgram->dcid, pkt->dcid.data, pkt->dcid.len))) {
			TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
			goto drop;
		}

		buf += QUIC_HAP_CID_LEN;

		pkt->pn_offset = buf - beg;
		/* A short packet is the last one of a UDP datagram. */
		pkt->len = end - beg;
	}

	TRACE_LEAVE(QUIC_EV_CONN_LPKT, NULL, pkt, NULL, qv);
	return 0;

 drop:
	HA_ATOMIC_INC(&prx_counters->dropped_pkt);
 drop_silent:
	if (!pkt->len)
		pkt->len = end - beg;
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, NULL, pkt, NULL, qv);
	return -1;
}

/* Check if received packet <pkt> should be drop due to <qc> already in closing
 * state. This can be true if a CONNECTION_CLOSE has already been emitted for
 * this connection.
 *
 * Returns false if connection is not in closing state else true. The caller
 * should drop the whole datagram in the last case to not mess up <qc>
 * CONNECTION_CLOSE rate limit counter.
 */
static int qc_rx_check_closing(struct quic_conn *qc,
                               struct quic_rx_packet *pkt)
{
	if (!(qc->flags & QUIC_FL_CONN_CLOSING))
		return 0;

	TRACE_STATE("Closing state connection", QUIC_EV_CONN_LPKT, qc, NULL, NULL, pkt->version);

	/* Check if CONNECTION_CLOSE rate reemission is reached. */
	if (++qc->nb_pkt_since_cc >= qc->nb_pkt_for_cc) {
		qc->flags |= QUIC_FL_CONN_IMMEDIATE_CLOSE;
		qc->nb_pkt_for_cc++;
		qc->nb_pkt_since_cc = 0;
	}

	return 1;
}

/* React to a connection migration initiated on <qc> by a client with the new
 * path addresses <peer_addr>/<local_addr>.
 *
 * Returns 0 on success else non-zero.
 */
static int qc_handle_conn_migration(struct quic_conn *qc,
                                    const struct sockaddr_storage *peer_addr,
                                    const struct sockaddr_storage *local_addr)
{
	TRACE_ENTER(QUIC_EV_CONN_LPKT, qc);

	/* RFC 9000. Connection Migration
	 *
	 * If the peer sent the disable_active_migration transport parameter,
	 * an endpoint also MUST NOT send packets (including probing packets;
	 * see Section 9.1) from a different local address to the address the peer
	 * used during the handshake, unless the endpoint has acted on a
	 * preferred_address transport parameter from the peer.
	 */
	if (qc->li->bind_conf->quic_params.disable_active_migration) {
		TRACE_ERROR("Active migration was disabled, datagram dropped", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	/* RFC 9000 9. Connection Migration
	 *
	 * The design of QUIC relies on endpoints retaining a stable address for
	 * the duration of the handshake.  An endpoint MUST NOT initiate
	 * connection migration before the handshake is confirmed, as defined in
	 * Section 4.1.2 of [QUIC-TLS].
	 */
	if (qc->state < QUIC_HS_ST_COMPLETE) {
		TRACE_STATE("Connection migration during handshake rejected", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	/* RFC 9000 9. Connection Migration
	 *
	 * TODO
	 * An endpoint MUST
	 * perform path validation (Section 8.2) if it detects any change to a
	 * peer's address, unless it has previously validated that address.
	 */

	/* Update quic-conn owned socket if in used.
	 * TODO try to reuse it instead of closing and opening a new one.
	 */
	if (qc_test_fd(qc)) {
		/* TODO try to reuse socket instead of closing it and opening a new one. */
		TRACE_STATE("Connection migration detected, allocate a new connection socket", QUIC_EV_CONN_LPKT, qc);
		qc_release_fd(qc, 1);
		/* TODO need to adjust <jobs> on socket allocation failure. */
		qc_alloc_fd(qc, local_addr, peer_addr);
	}

	qc->local_addr = *local_addr;
	qc->peer_addr = *peer_addr;
	HA_ATOMIC_INC(&qc->prx_counters->conn_migration_done);

	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc);
	return 0;

 err:
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc);
	return 1;
}

/* Release the memory for the RX packets which are no more referenced
 * and consume their payloads which have been copied to the RX buffer
 * for the connection.
 * Always succeeds.
 */
static inline void quic_rx_pkts_del(struct quic_conn *qc)
{
	struct quic_rx_packet *pkt, *pktback;

	list_for_each_entry_safe(pkt, pktback, &qc->rx.pkt_list, qc_rx_pkt_list) {
		TRACE_PRINTF(TRACE_LEVEL_DEVELOPER, QUIC_EV_CONN_LPKT, qc, 0, 0, 0,
		             "pkt #%lld(type=%d,len=%llu,rawlen=%llu,refcnt=%u) (diff: %zd)",
		             (long long)pkt->pn_node.key,
		             pkt->type, (ull)pkt->len, (ull)pkt->raw_len, pkt->refcnt,
		             (unsigned char *)b_head(&qc->rx.buf) - pkt->data);
		if (pkt->data != (unsigned char *)b_head(&qc->rx.buf)) {
			size_t cdata;

			cdata = b_contig_data(&qc->rx.buf, 0);
			TRACE_PRINTF(TRACE_LEVEL_DEVELOPER, QUIC_EV_CONN_LPKT, qc, 0, 0, 0,
			             "cdata=%llu *b_head()=0x%x", (ull)cdata, *b_head(&qc->rx.buf));
			if (cdata && !*b_head(&qc->rx.buf)) {
				/* Consume the remaining data */
				b_del(&qc->rx.buf, cdata);
			}
			break;
		}

		if (pkt->refcnt)
			break;

		b_del(&qc->rx.buf, pkt->raw_len);
		LIST_DELETE(&pkt->qc_rx_pkt_list);
		pool_free(pool_head_quic_rx_packet, pkt);
	}

	/* In frequent cases the buffer will be emptied at this stage. */
	b_realign_if_empty(&qc->rx.buf);
}

/* Handle a parsed packet <pkt> by the connection <qc>. Data will be copied
 * into <qc> receive buffer after header protection removal procedure.
 *
 * <dgram> must be set to the datagram which contains the QUIC packet. <beg>
 * must point to packet buffer first byte.
 *
 * <tasklist_head> may be non-NULL when the caller treat several datagrams for
 * different quic-conn. In this case, each quic-conn tasklet will be appended
 * to it in order to be woken up after the current task.
 *
 * The caller can safely removed the packet data. If packet refcount was not
 * incremented by this function, it means that the connection did not handled
 * it and it should be freed by the caller.
 */
static void qc_rx_pkt_handle(struct quic_conn *qc, struct quic_rx_packet *pkt,
                             struct quic_dgram *dgram, unsigned char *beg,
                             struct list **tasklist_head)
{
	const struct quic_version *qv = pkt->version;
	struct quic_enc_level *qel = NULL;
	size_t b_cspace;
	int io_cb_wakeup = 0;

	TRACE_ENTER(QUIC_EV_CONN_LPKT, qc, pkt, NULL, qv);

	if (pkt->flags & QUIC_FL_RX_PACKET_DGRAM_FIRST &&
	    !quic_peer_validated_addr(qc) &&
	    qc->flags & QUIC_FL_CONN_ANTI_AMPLIFICATION_REACHED) {
		TRACE_PROTO("PTO timer must be armed after anti-amplication was reached",
					QUIC_EV_CONN_LPKT, qc, NULL, NULL, qv);
		/* Reset the anti-amplification bit. It will be set again
		 * when sending the next packet if reached again.
		 */
		qc->flags &= ~QUIC_FL_CONN_ANTI_AMPLIFICATION_REACHED;
		io_cb_wakeup = 1;
	}

	if (qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE) {
		TRACE_PROTO("Connection error",
		            QUIC_EV_CONN_LPKT, qc, NULL, NULL, qv);
		goto out;
	}

	pkt->raw_len = pkt->len;
	quic_rx_pkts_del(qc);
	b_cspace = b_contig_space(&qc->rx.buf);
	if (b_cspace < pkt->len) {
		TRACE_PRINTF(TRACE_LEVEL_DEVELOPER, QUIC_EV_CONN_LPKT, qc, 0, 0, 0,
		             "bspace=%llu pkt->len=%llu", (ull)b_cspace, (ull)pkt->len);
		/* Do not consume buf if space not at the end. */
		if (b_tail(&qc->rx.buf) + b_cspace < b_wrap(&qc->rx.buf)) {
			TRACE_PROTO("Packet dropped",
			            QUIC_EV_CONN_LPKT, qc, NULL, NULL, qv);
			HA_ATOMIC_INC(&qc->prx_counters->dropped_pkt_bufoverrun);
			goto drop_silent;
		}

		/* Let us consume the remaining contiguous space. */
		if (b_cspace) {
			b_putchr(&qc->rx.buf, 0x00);
			b_cspace--;
		}
		b_add(&qc->rx.buf, b_cspace);
		if (b_contig_space(&qc->rx.buf) < pkt->len) {
			TRACE_PROTO("Too big packet",
			            QUIC_EV_CONN_LPKT, qc, pkt, &pkt->len, qv);
			HA_ATOMIC_INC(&qc->prx_counters->dropped_pkt_bufoverrun);
			goto drop_silent;
		}
	}

	if (!qc_try_rm_hp(qc, pkt, beg, &qel)) {
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT, qc, NULL, NULL, qv);
		goto drop;
	}

	TRACE_DATA("New packet", QUIC_EV_CONN_LPKT, qc, pkt, NULL, qv);
	if (pkt->aad_len)
		qc_pkt_insert(qc, pkt, qel);
 out:
	*tasklist_head = tasklet_wakeup_after(*tasklist_head,
	                                      qc->wait_event.tasklet);

 drop_silent:
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc ? qc : NULL, pkt, NULL, qv);
	return;

 drop:
	HA_ATOMIC_INC(&qc->prx_counters->dropped_pkt);
	if (io_cb_wakeup) {
		TRACE_DEVEL("needs to wakeup the timer task after the amplification limit was reached",
		            QUIC_EV_CONN_LPKT, qc);
		qc_set_timer(qc);
		if (qc->timer_task && tick_isset(qc->timer) && tick_is_lt(qc->timer, now_ms))
			task_wakeup(qc->timer_task, TASK_WOKEN_MSG);
	}

	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc ? qc : NULL, pkt, NULL, qv);
}

/* This function builds into <buf> buffer a QUIC long packet header.
 * Return 1 if enough room to build this header, 0 if not.
 */
static int quic_build_packet_long_header(unsigned char **buf, const unsigned char *end,
                                         int type, size_t pn_len,
                                         struct quic_conn *qc, const struct quic_version *ver)
{
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_LPKT, qc);

	if (end - *buf < sizeof ver->num + qc->dcid.len + qc->scid.len + 3) {
		TRACE_DEVEL("not enough room", QUIC_EV_CONN_LPKT, qc);
		goto leave;
	}

	type = quic_pkt_type(type, ver->num);
	/* #0 byte flags */
	*(*buf)++ = QUIC_PACKET_FIXED_BIT | QUIC_PACKET_LONG_HEADER_BIT |
		(type << QUIC_PACKET_TYPE_SHIFT) | (pn_len - 1);
	/* Version */
	quic_write_uint32(buf, end, ver->num);
	*(*buf)++ = qc->dcid.len;
	/* Destination connection ID */
	if (qc->dcid.len) {
		memcpy(*buf, qc->dcid.data, qc->dcid.len);
		*buf += qc->dcid.len;
	}
	/* Source connection ID */
	*(*buf)++ = qc->scid.len;
	if (qc->scid.len) {
		memcpy(*buf, qc->scid.data, qc->scid.len);
		*buf += qc->scid.len;
	}

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc);
	return ret;
}

/* This function builds into <buf> buffer a QUIC short packet header.
 * Return 1 if enough room to build this header, 0 if not.
 */
static int quic_build_packet_short_header(unsigned char **buf, const unsigned char *end,
                                          size_t pn_len, struct quic_conn *qc,
                                          unsigned char tls_flags)
{
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	if (end - *buf < 1 + qc->dcid.len) {
		TRACE_DEVEL("not enough room", QUIC_EV_CONN_LPKT, qc);
		goto leave;
	}

	/* #0 byte flags */
	*(*buf)++ = QUIC_PACKET_FIXED_BIT |
		((tls_flags & QUIC_FL_TLS_KP_BIT_SET) ? QUIC_PACKET_KEY_PHASE_BIT : 0) | (pn_len - 1);
	/* Destination connection ID */
	if (qc->dcid.len) {
		memcpy(*buf, qc->dcid.data, qc->dcid.len);
		*buf += qc->dcid.len;
	}

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return ret;
}

/* Apply QUIC header protection to the packet with <buf> as first byte address,
 * <pn> as address of the Packet number field, <pnlen> being this field length
 * with <aead> as AEAD cipher and <key> as secret key.
 * Returns 1 if succeeded or 0 if failed.
 */
static int quic_apply_header_protection(struct quic_conn *qc, unsigned char *buf,
                                        unsigned char *pn, size_t pnlen,
                                        struct quic_tls_ctx *tls_ctx)

{
	int i, ret = 0;
	/* We need an IV of at least 5 bytes: one byte for bytes #0
	 * and at most 4 bytes for the packet number
	 */
	unsigned char mask[5] = {0};
	EVP_CIPHER_CTX *aes_ctx = tls_ctx->tx.hp_ctx;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	if (!quic_tls_aes_encrypt(mask, pn + QUIC_PACKET_PN_MAXLEN, sizeof mask, aes_ctx)) {
		TRACE_ERROR("could not apply header protection", QUIC_EV_CONN_TXPKT, qc);
		goto out;
	}

	*buf ^= mask[0] & (*buf & QUIC_PACKET_LONG_HEADER_BIT ? 0xf : 0x1f);
	for (i = 0; i < pnlen; i++)
		pn[i] ^= mask[i + 1];

	ret = 1;
 out:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return ret;
}

/* Reduce the encoded size of <ack_frm> ACK frame removing the last
 * ACK ranges if needed to a value below <limit> in bytes.
 * Return 1 if succeeded, 0 if not.
 */
static int quic_ack_frm_reduce_sz(struct quic_conn *qc,
                                  struct quic_frame *ack_frm, size_t limit)
{
	size_t room, ack_delay_sz;
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	ack_delay_sz = quic_int_getsize(ack_frm->tx_ack.ack_delay);
	/* A frame is made of 1 byte for the frame type. */
	room = limit - ack_delay_sz - 1;
	if (!quic_rm_last_ack_ranges(qc, ack_frm->tx_ack.arngs, room))
		goto leave;

	ret = 1 + ack_delay_sz + ack_frm->tx_ack.arngs->enc_sz;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return ret;
}

/* Prepare into <outlist> as most as possible ack-eliciting frame from their
 * <inlist> prebuilt frames for <qel> encryption level to be encoded in a buffer
 * with <room> as available room, and <*len> the packet Length field initialized
 * with the number of bytes already present in this buffer which must be taken
 * into an account for the Length packet field value. <headlen> is the number of
 * bytes already present in this packet before building frames.
 *
 * Update consequently <*len> to reflect the size of these frames built
 * by this function. Also attach these frames to <l> frame list.
 * Return 1 if at least one ack-eleciting frame could be built, 0 if not.
 */
static inline int qc_build_frms(struct list *outlist, struct list *inlist,
                                size_t room, size_t *len, size_t headlen,
                                struct quic_enc_level *qel,
                                struct quic_conn *qc)
{
	int ret;
	struct quic_frame *cf, *cfbak;

	TRACE_ENTER(QUIC_EV_CONN_BCFRMS, qc);

	ret = 0;
	if (*len > room)
		goto leave;

	/* If we are not probing we must take into an account the congestion
	 * control window.
	 */
	if (!qel->pktns->tx.pto_probe) {
		size_t remain = quic_path_prep_data(qc->path);

		if (headlen > remain)
			goto leave;

		room = QUIC_MIN(room, remain - headlen);
	}

	TRACE_PROTO("************** frames build (headlen)",
	            QUIC_EV_CONN_BCFRMS, qc, &headlen);

	/* NOTE: switch/case block inside a loop, a successful status must be
	 * returned by this function only if at least one frame could be built
	 * in the switch/case block.
	 */
	list_for_each_entry_safe(cf, cfbak, inlist, list) {
		/* header length, data length, frame length. */
		size_t hlen, dlen, dlen_sz, avail_room, flen;

		if (!room)
			break;

		switch (cf->type) {
		case QUIC_FT_CRYPTO:
			TRACE_DEVEL("          New CRYPTO frame build (room, len)",
			            QUIC_EV_CONN_BCFRMS, qc, &room, len);
			/* Compute the length of this CRYPTO frame header */
			hlen = 1 + quic_int_getsize(cf->crypto.offset);
			/* Compute the data length of this CRyPTO frame. */
			dlen = max_stream_data_size(room, *len + hlen, cf->crypto.len);
			TRACE_DEVEL(" CRYPTO data length (hlen, crypto.len, dlen)",
			            QUIC_EV_CONN_BCFRMS, qc, &hlen, &cf->crypto.len, &dlen);
			if (!dlen)
				continue;

			/* CRYPTO frame length. */
			flen = hlen + quic_int_getsize(dlen) + dlen;
			TRACE_DEVEL("                 CRYPTO frame length (flen)",
			            QUIC_EV_CONN_BCFRMS, qc, &flen);
			/* Add the CRYPTO data length and its encoded length to the packet
			 * length and the length of this length.
			 */
			*len += flen;
			room -= flen;
			if (dlen == cf->crypto.len) {
				/* <cf> CRYPTO data have been consumed. */
				LIST_DEL_INIT(&cf->list);
				LIST_APPEND(outlist, &cf->list);
			}
			else {
				struct quic_frame *new_cf;

				new_cf = qc_frm_alloc(QUIC_FT_CRYPTO);
				if (!new_cf) {
					TRACE_ERROR("No memory for new crypto frame", QUIC_EV_CONN_BCFRMS, qc);
					continue;
				}

				new_cf->crypto.len = dlen;
				new_cf->crypto.offset = cf->crypto.offset;
				new_cf->crypto.qel = qel;
				TRACE_DEVEL("split frame", QUIC_EV_CONN_PRSAFRM, qc, new_cf);
				if (cf->origin) {
					TRACE_DEVEL("duplicated frame", QUIC_EV_CONN_PRSAFRM, qc);
					/* This <cf> frame was duplicated */
					LIST_APPEND(&cf->origin->reflist, &new_cf->ref);
					new_cf->origin = cf->origin;
					/* Detach the remaining CRYPTO frame from its original frame */
					LIST_DEL_INIT(&cf->ref);
					cf->origin = NULL;
				}
				LIST_APPEND(outlist, &new_cf->list);
				/* Consume <dlen> bytes of the current frame. */
				cf->crypto.len -= dlen;
				cf->crypto.offset += dlen;
			}
			break;

		case QUIC_FT_STREAM_8 ... QUIC_FT_STREAM_F:
			if (cf->flags & QUIC_FL_TX_FRAME_LOST) {
				struct eb64_node *node = NULL;
				struct qc_stream_desc *stream_desc = NULL;
				struct quic_stream *strm = &cf->stream;

				/* As this frame has been already lost, ensure the stream is always
				 * available or the range of this frame is not consumed before
				 * resending it.
				 */
				node = eb64_lookup(&qc->streams_by_id, strm->id);
				if (!node) {
					TRACE_DEVEL("released stream", QUIC_EV_CONN_PRSAFRM, qc, cf);
					qc_frm_free(&cf);
					continue;
				}

				stream_desc = eb64_entry(node, struct qc_stream_desc, by_id);
				if (strm->offset.key + strm->len <= stream_desc->ack_offset) {
					TRACE_DEVEL("ignored frame frame in already acked range",
					            QUIC_EV_CONN_PRSAFRM, qc, cf);
					qc_frm_free(&cf);
					continue;
				}
				else if (strm->offset.key < stream_desc->ack_offset) {
					strm->offset.key = stream_desc->ack_offset;
					TRACE_DEVEL("updated partially acked frame",
					            QUIC_EV_CONN_PRSAFRM, qc, cf);
				}
			}
			/* Note that these frames are accepted in short packets only without
			 * "Length" packet field. Here, <*len> is used only to compute the
			 * sum of the lengths of the already built frames for this packet.
			 *
			 * Compute the length of this STREAM frame "header" made a all the field
			 * excepting the variable ones. Note that +1 is for the type of this frame.
			 */
			hlen = 1 + quic_int_getsize(cf->stream.id) +
				((cf->type & QUIC_STREAM_FRAME_TYPE_OFF_BIT) ? quic_int_getsize(cf->stream.offset.key) : 0);
			/* Compute the data length of this STREAM frame. */
			avail_room = room - hlen - *len;
			if ((ssize_t)avail_room <= 0)
				continue;

			TRACE_DEVEL("          New STREAM frame build (room, len)",
			            QUIC_EV_CONN_BCFRMS, qc, &room, len);

			/* hlen contains STREAM id and offset. Ensure there is
			 * enough room for length field.
			 */
			if (cf->type & QUIC_STREAM_FRAME_TYPE_LEN_BIT) {
				dlen = QUIC_MIN((uint64_t)max_available_room(avail_room, &dlen_sz),
				                cf->stream.len);
				dlen_sz = quic_int_getsize(dlen);
				flen = hlen + dlen_sz + dlen;
			}
			else {
				dlen = QUIC_MIN((uint64_t)avail_room, cf->stream.len);
				flen = hlen + dlen;
			}

			if (cf->stream.len && !dlen) {
				/* Only a small gap is left on buffer, not
				 * enough to encode the STREAM data length.
				 */
				continue;
			}

			TRACE_DEVEL(" STREAM data length (hlen, stream.len, dlen)",
			            QUIC_EV_CONN_BCFRMS, qc, &hlen, &cf->stream.len, &dlen);
			TRACE_DEVEL("                 STREAM frame length (flen)",
			            QUIC_EV_CONN_BCFRMS, qc, &flen);
			/* Add the STREAM data length and its encoded length to the packet
			 * length and the length of this length.
			 */
			*len += flen;
			room -= flen;
			if (dlen == cf->stream.len) {
				/* <cf> STREAM data have been consumed. */
				LIST_DEL_INIT(&cf->list);
				LIST_APPEND(outlist, &cf->list);

				/* Do not notify MUX on retransmission. */
				if (qc->flags & QUIC_FL_CONN_TX_MUX_CONTEXT) {
					qcc_streams_sent_done(cf->stream.stream->ctx,
					                      cf->stream.len,
					                      cf->stream.offset.key);
				}
			}
			else {
				struct quic_frame *new_cf;
				struct buffer cf_buf;

				new_cf = qc_frm_alloc(cf->type);
				if (!new_cf) {
					TRACE_ERROR("No memory for new STREAM frame", QUIC_EV_CONN_BCFRMS, qc);
					continue;
				}

				new_cf->stream.stream = cf->stream.stream;
				new_cf->stream.buf = cf->stream.buf;
				new_cf->stream.id = cf->stream.id;
				new_cf->stream.offset = cf->stream.offset;
				new_cf->stream.len = dlen;
				new_cf->type |= QUIC_STREAM_FRAME_TYPE_LEN_BIT;
				/* FIN bit reset */
				new_cf->type &= ~QUIC_STREAM_FRAME_TYPE_FIN_BIT;
				new_cf->stream.data = cf->stream.data;
				TRACE_DEVEL("split frame", QUIC_EV_CONN_PRSAFRM, qc, new_cf);
				if (cf->origin) {
					TRACE_DEVEL("duplicated frame", QUIC_EV_CONN_PRSAFRM, qc);
					/* This <cf> frame was duplicated */
					LIST_APPEND(&cf->origin->reflist, &new_cf->ref);
					new_cf->origin = cf->origin;
					/* Detach this STREAM frame from its origin */
					LIST_DEL_INIT(&cf->ref);
					cf->origin = NULL;
				}
				LIST_APPEND(outlist, &new_cf->list);
				cf->type |= QUIC_STREAM_FRAME_TYPE_OFF_BIT;
				/* Consume <dlen> bytes of the current frame. */
				cf_buf = b_make(b_orig(cf->stream.buf),
				                b_size(cf->stream.buf),
				                (char *)cf->stream.data - b_orig(cf->stream.buf), 0);
				cf->stream.len -= dlen;
				cf->stream.offset.key += dlen;
				cf->stream.data = (unsigned char *)b_peek(&cf_buf, dlen);

				/* Do not notify MUX on retransmission. */
				if (qc->flags & QUIC_FL_CONN_TX_MUX_CONTEXT) {
					qcc_streams_sent_done(new_cf->stream.stream->ctx,
					                      new_cf->stream.len,
					                      new_cf->stream.offset.key);
				}
			}

			/* TODO the MUX is notified about the frame sending via
			 * previous qcc_streams_sent_done call. However, the
			 * sending can fail later, for example if the sendto
			 * system call returns an error. As the MUX has been
			 * notified, the transport layer is responsible to
			 * bufferize and resent the announced data later.
			 */

			break;

		default:
			flen = qc_frm_len(cf);
			BUG_ON(!flen);
			if (flen > room)
				continue;

			*len += flen;
			room -= flen;
			LIST_DEL_INIT(&cf->list);
			LIST_APPEND(outlist, &cf->list);
			break;
		}

		/* Successful status as soon as a frame could be built */
		ret = 1;
	}

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_BCFRMS, qc);
	return ret;
}

/* Generate a CONNECTION_CLOSE frame for <qc> on <qel> encryption level. <out>
 * is used as return parameter and should be zero'ed by the caller.
 */
static void qc_build_cc_frm(struct quic_conn *qc, struct quic_enc_level *qel,
                            struct quic_frame *out)
{
	/* TODO improve CONNECTION_CLOSE on Initial/Handshake encryption levels
	 *
	 * A CONNECTION_CLOSE frame should be sent in several packets with
	 * different encryption levels depending on the client context. This is
	 * to ensure that the client can decrypt it. See RFC 9000 10.2.3 for
	 * more details on how to implement it.
	 */
	TRACE_ENTER(QUIC_EV_CONN_BFRM, qc);


	if (qc->err.app) {
		if (unlikely(qel == &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL] ||
		             qel == &qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE])) {
			/* RFC 9000 10.2.3.  Immediate Close during the Handshake
			 *
			 * Sending a CONNECTION_CLOSE of type 0x1d in an Initial or Handshake
			 * packet could expose application state or be used to alter application
			 * state.  A CONNECTION_CLOSE of type 0x1d MUST be replaced by a
			 * CONNECTION_CLOSE of type 0x1c when sending the frame in Initial or
			 * Handshake packets.  Otherwise, information about the application
			 * state might be revealed.  Endpoints MUST clear the value of the
			 * Reason Phrase field and SHOULD use the APPLICATION_ERROR code when
			 * converting to a CONNECTION_CLOSE of type 0x1c.
			 */
			out->type = QUIC_FT_CONNECTION_CLOSE;
			out->connection_close.error_code = QC_ERR_APPLICATION_ERROR;
			out->connection_close.reason_phrase_len = 0;
		}
		else {
			out->type = QUIC_FT_CONNECTION_CLOSE_APP;
			out->connection_close.error_code = qc->err.code;
		}
	}
	else {
		out->type = QUIC_FT_CONNECTION_CLOSE;
		out->connection_close.error_code = qc->err.code;
	}
	TRACE_LEAVE(QUIC_EV_CONN_BFRM, qc);

}

/* This function builds a clear packet from <pkt> information (its type)
 * into a buffer with <pos> as position pointer and <qel> as QUIC TLS encryption
 * level for <conn> QUIC connection and <qel> as QUIC TLS encryption level,
 * filling the buffer with as much frames as possible from <frms> list of
 * prebuilt frames.
 * The trailing QUIC_TLS_TAG_LEN bytes of this packet are not built. But they are
 * reserved so that to ensure there is enough room to build this AEAD TAG after
 * having returned from this function.
 * This function also updates the value of <buf_pn> pointer to point to the packet
 * number field in this packet. <pn_len> will also have the packet number
 * length as value.
 *
 * Return 1 if succeeded (enough room to buile this packet), O if not.
 */
static int qc_do_build_pkt(unsigned char *pos, const unsigned char *end,
                           size_t dglen, struct quic_tx_packet *pkt,
                           int64_t pn, size_t *pn_len, unsigned char **buf_pn,
                           int force_ack, int padding, int cc, int probe,
                           struct quic_enc_level *qel, struct quic_conn *qc,
                           const struct quic_version *ver, struct list *frms)
{
	unsigned char *beg, *payload;
	size_t len, len_sz, len_frms, padding_len;
	struct quic_frame frm = { .type = QUIC_FT_CRYPTO, };
	struct quic_frame ack_frm = { .type = QUIC_FT_ACK, };
	struct quic_frame cc_frm = { };
	size_t ack_frm_len, head_len;
	int64_t rx_largest_acked_pn;
	int add_ping_frm;
	struct list frm_list = LIST_HEAD_INIT(frm_list);
	struct quic_frame *cf;
	int must_ack, ret = 0;
	int nb_aepkts_since_last_ack;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	/* Length field value with CRYPTO frames if present. */
	len_frms = 0;
	beg = pos;
	/* When not probing, and no immediate close is required, reduce the size of this
	 * buffer to respect the congestion controller window.
	 * This size will be limited if we have ack-eliciting frames to send from <frms>.
	 */
	if (!probe && !LIST_ISEMPTY(frms) && !cc) {
		size_t path_room;

		path_room = quic_path_prep_data(qc->path);
		if (end - beg > path_room)
			end = beg + path_room;
	}

	/* Ensure there is enough room for the TLS encryption tag and a zero token
	 * length field if any.
	 */
	if (end - pos < QUIC_TLS_TAG_LEN +
	    (pkt->type == QUIC_PACKET_TYPE_INITIAL ? 1 : 0))
		goto no_room;

	end -= QUIC_TLS_TAG_LEN;
	rx_largest_acked_pn = qel->pktns->rx.largest_acked_pn;
	/* packet number length */
	*pn_len = quic_packet_number_length(pn, rx_largest_acked_pn);
	/* Build the header */
	if ((pkt->type == QUIC_PACKET_TYPE_SHORT &&
	    !quic_build_packet_short_header(&pos, end, *pn_len, qc, qel->tls_ctx.flags)) ||
	    (pkt->type != QUIC_PACKET_TYPE_SHORT &&
		!quic_build_packet_long_header(&pos, end, pkt->type, *pn_len, qc, ver)))
		goto no_room;

	/* Encode the token length (0) for an Initial packet. */
	if (pkt->type == QUIC_PACKET_TYPE_INITIAL)
		*pos++ = 0;
	head_len = pos - beg;
	/* Build an ACK frame if required. */
	ack_frm_len = 0;
	nb_aepkts_since_last_ack = qel->pktns->rx.nb_aepkts_since_last_ack;
	must_ack = !qel->pktns->tx.pto_probe &&
		(force_ack || ((qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) &&
		 (LIST_ISEMPTY(frms) || nb_aepkts_since_last_ack >= QUIC_MAX_RX_AEPKTS_SINCE_LAST_ACK)));
	if (must_ack) {
	    struct quic_arngs *arngs = &qel->pktns->rx.arngs;
	    BUG_ON(eb_is_empty(&qel->pktns->rx.arngs.root));
		ack_frm.tx_ack.arngs = arngs;
		if (qel->pktns->flags & QUIC_FL_PKTNS_NEW_LARGEST_PN) {
			qel->pktns->tx.ack_delay =
				quic_compute_ack_delay_us(qel->pktns->rx.largest_time_received, qc);
			qel->pktns->flags &= ~QUIC_FL_PKTNS_NEW_LARGEST_PN;
		}
		ack_frm.tx_ack.ack_delay = qel->pktns->tx.ack_delay;
		/* XXX BE CAREFUL XXX : here we reserved at least one byte for the
		 * smallest frame (PING) and <*pn_len> more for the packet number. Note
		 * that from here, we do not know if we will have to send a PING frame.
		 * This will be decided after having computed the ack-eliciting frames
		 * to be added to this packet.
		 */
		ack_frm_len = quic_ack_frm_reduce_sz(qc, &ack_frm, end - 1 - *pn_len - pos);
		if (!ack_frm_len)
			goto no_room;
	}

	/* Length field value without the ack-eliciting frames. */
	len = ack_frm_len + *pn_len;
	len_frms = 0;
	if (!cc && !LIST_ISEMPTY(frms)) {
		ssize_t room = end - pos;

		TRACE_DEVEL("Avail. ack eliciting frames", QUIC_EV_CONN_FRMLIST, qc, frms);
		/* Initialize the length of the frames built below to <len>.
		 * If any frame could be successfully built by qc_build_frms(),
		 * we will have len_frms > len.
		 */
		len_frms = len;
		if (!qc_build_frms(&frm_list, frms,
		                   end - pos, &len_frms, pos - beg, qel, qc)) {
			TRACE_DEVEL("Not enough room", QUIC_EV_CONN_TXPKT,
			            qc, NULL, NULL, &room);
			if (!ack_frm_len && !qel->pktns->tx.pto_probe)
				goto no_room;
		}
	}

	/* Length (of the remaining data). Must not fail because, the buffer size
	 * has been checked above. Note that we have reserved QUIC_TLS_TAG_LEN bytes
	 * for the encryption tag. It must be taken into an account for the length
	 * of this packet.
	 */
	if (len_frms)
		len = len_frms + QUIC_TLS_TAG_LEN;
	else
		len += QUIC_TLS_TAG_LEN;
	/* CONNECTION_CLOSE frame */
	if (cc) {
		qc_build_cc_frm(qc, qel, &cc_frm);
		len += qc_frm_len(&cc_frm);
	}
	add_ping_frm = 0;
	padding_len = 0;
	len_sz = quic_int_getsize(len);
	/* Add this packet size to <dglen> */
	dglen += head_len + len_sz + len;
	if (padding && dglen < QUIC_INITIAL_PACKET_MINLEN) {
		/* This is a maximum padding size */
		padding_len = QUIC_INITIAL_PACKET_MINLEN - dglen;
		/* The length field value is of this packet is <len> + <padding_len>
		 * the size of which may be greater than the initial computed size
		 * <len_sz>. So, let's deduce the difference between these to packet
		 * sizes from <padding_len>.
		 */
		padding_len -= quic_int_getsize(len + padding_len) - len_sz;
		len += padding_len;
	}
	else if (len_frms && len_frms < QUIC_PACKET_PN_MAXLEN) {
		len += padding_len = QUIC_PACKET_PN_MAXLEN - len_frms;
	}
	else if (LIST_ISEMPTY(&frm_list)) {
		if (qel->pktns->tx.pto_probe) {
			/* If we cannot send a frame, we send a PING frame. */
			add_ping_frm = 1;
			len += 1;
		}
		/* If there is no frame at all to follow, add at least a PADDING frame. */
		if (!ack_frm_len && !cc)
			len += padding_len = QUIC_PACKET_PN_MAXLEN - *pn_len;
	}

	if (pkt->type != QUIC_PACKET_TYPE_SHORT && !quic_enc_int(&pos, end, len))
		goto no_room;

	/* Packet number field address. */
	*buf_pn = pos;

	/* Packet number encoding. */
	if (!quic_packet_number_encode(&pos, end, pn, *pn_len))
		goto no_room;

	/* payload building (ack-eliciting or not frames) */
	payload = pos;
	if (ack_frm_len) {
		if (!qc_build_frm(&pos, end, &ack_frm, pkt, qc))
			goto no_room;

		pkt->largest_acked_pn = quic_pktns_get_largest_acked_pn(qel->pktns);
		pkt->flags |= QUIC_FL_TX_PACKET_ACK;
	}

	/* Ack-eliciting frames */
	if (!LIST_ISEMPTY(&frm_list)) {
		struct quic_frame *tmp_cf;
		list_for_each_entry_safe(cf, tmp_cf, &frm_list, list) {
			if (!qc_build_frm(&pos, end, cf, pkt, qc)) {
				ssize_t room = end - pos;
				TRACE_DEVEL("Not enough room", QUIC_EV_CONN_TXPKT,
				            qc, NULL, NULL, &room);
				/* Note that <cf> was added from <frms> to <frm_list> list by
				 * qc_build_frms().
				 */
				LIST_DEL_INIT(&cf->list);
				LIST_INSERT(frms, &cf->list);
				continue;
			}

			quic_tx_packet_refinc(pkt);
			cf->pkt = pkt;
		}
	}

	/* Build a PING frame if needed. */
	if (add_ping_frm) {
		frm.type = QUIC_FT_PING;
		if (!qc_build_frm(&pos, end, &frm, pkt, qc))
			goto no_room;
	}

	/* Build a CONNECTION_CLOSE frame if needed. */
	if (cc) {
		if (!qc_build_frm(&pos, end, &cc_frm, pkt, qc))
			goto no_room;

		pkt->flags |= QUIC_FL_TX_PACKET_CC;
	}

	/* Build a PADDING frame if needed. */
	if (padding_len) {
		frm.type = QUIC_FT_PADDING;
		frm.padding.len = padding_len;
		if (!qc_build_frm(&pos, end, &frm, pkt, qc))
			goto no_room;
	}

	if (pos == payload) {
		/* No payload was built because of congestion control */
		TRACE_DEVEL("limited by congestion control", QUIC_EV_CONN_TXPKT, qc);
		goto no_room;
	}

	/* If this packet is ack-eliciting and we are probing let's
	 * decrement the PTO probe counter.
	 */
	if (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING &&
	    qel->pktns->tx.pto_probe)
		qel->pktns->tx.pto_probe--;

	pkt->len = pos - beg;
	LIST_SPLICE(&pkt->frms, &frm_list);

	ret = 1;
	TRACE_DEVEL("Packet ack-eliciting frames", QUIC_EV_CONN_TXPKT, qc, pkt);
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return ret;

 no_room:
	/* Replace the pre-built frames which could not be add to this packet */
	LIST_SPLICE(frms, &frm_list);
	TRACE_DEVEL("Remaining ack-eliciting frames", QUIC_EV_CONN_FRMLIST, qc, frms);
	goto leave;
}

static inline void quic_tx_packet_init(struct quic_tx_packet *pkt, int type)
{
	pkt->type = type;
	pkt->len = 0;
	pkt->in_flight_len = 0;
	pkt->pn_node.key = (uint64_t)-1;
	LIST_INIT(&pkt->frms);
	pkt->time_sent = TICK_ETERNITY;
	pkt->next = NULL;
	pkt->prev = NULL;
	pkt->largest_acked_pn = -1;
	pkt->flags = 0;
	pkt->refcnt = 0;
}

/* Build a packet into <buf> packet buffer with <pkt_type> as packet
 * type for <qc> QUIC connection from <qel> encryption level from <frms> list
 * of prebuilt frames.
 *
 * Return -2 if the packet could not be allocated or encrypted for any reason,
 * -1 if there was not enough room to build a packet.
 * XXX NOTE XXX
 * If you provide provide qc_build_pkt() with a big enough buffer to build a packet as big as
 * possible (to fill an MTU), the unique reason why this function may fail is the congestion
 * control window limitation.
 */
static struct quic_tx_packet *qc_build_pkt(unsigned char **pos,
                                           const unsigned char *buf_end,
                                           struct quic_enc_level *qel,
                                           struct quic_tls_ctx *tls_ctx, struct list *frms,
                                           struct quic_conn *qc, const struct quic_version *ver,
                                           size_t dglen, int pkt_type, int force_ack,
                                           int padding, int probe, int cc, int *err)
{
	struct quic_tx_packet *ret_pkt = NULL;
	/* The pointer to the packet number field. */
	unsigned char *buf_pn;
	unsigned char *beg, *end, *payload;
	int64_t pn;
	size_t pn_len, payload_len, aad_len;
	struct quic_tx_packet *pkt;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc, NULL, qel);
	*err = 0;
	pkt = pool_alloc(pool_head_quic_tx_packet);
	if (!pkt) {
		TRACE_DEVEL("Not enough memory for a new packet", QUIC_EV_CONN_TXPKT, qc);
		*err = -2;
		goto err;
	}

	quic_tx_packet_init(pkt, pkt_type);
	beg = *pos;
	pn_len = 0;
	buf_pn = NULL;

	pn = qel->pktns->tx.next_pn + 1;
	if (!qc_do_build_pkt(*pos, buf_end, dglen, pkt, pn, &pn_len, &buf_pn,
	                     force_ack, padding, cc, probe, qel, qc, ver, frms)) {
		// trace already emitted by function above
		*err = -1;
		goto err;
	}

	end = beg + pkt->len;
	payload = buf_pn + pn_len;
	payload_len = end - payload;
	aad_len = payload - beg;

	if (!quic_packet_encrypt(payload, payload_len, beg, aad_len, pn, tls_ctx, qc)) {
		// trace already emitted by function above
		*err = -2;
		goto err;
	}

	end += QUIC_TLS_TAG_LEN;
	pkt->len += QUIC_TLS_TAG_LEN;
	if (!quic_apply_header_protection(qc, beg, buf_pn, pn_len, tls_ctx)) {
		// trace already emitted by function above
		*err = -2;
		goto err;
	}

	/* Consume a packet number */
	qel->pktns->tx.next_pn++;
	qc->tx.prep_bytes += pkt->len;
	if (qc->tx.prep_bytes >= 3 * qc->rx.bytes && !quic_peer_validated_addr(qc)) {
		qc->flags |= QUIC_FL_CONN_ANTI_AMPLIFICATION_REACHED;
		TRACE_PROTO("anti-amplification limit reached", QUIC_EV_CONN_TXPKT, qc);
	}
	/* Now that a correct packet is built, let us consume <*pos> buffer. */
	*pos = end;
	/* Attach the built packet to its tree. */
	pkt->pn_node.key = pn;
	/* Set the packet in fligth length for in flight packet only. */
	if (pkt->flags & QUIC_FL_TX_PACKET_IN_FLIGHT) {
		pkt->in_flight_len = pkt->len;
		qc->path->prep_in_flight += pkt->len;
	}
	/* Always reset this flags */
	qc->flags &= ~QUIC_FL_CONN_IMMEDIATE_CLOSE;
	if (pkt->flags & QUIC_FL_TX_PACKET_ACK) {
		qel->pktns->flags &= ~QUIC_FL_PKTNS_ACK_REQUIRED;
		qel->pktns->rx.nb_aepkts_since_last_ack = 0;
	}

	pkt->pktns = qel->pktns;

	ret_pkt = pkt;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc, ret_pkt);
	return ret_pkt;

 err:
	/* TODO: what about the frames which have been built
	 * for this packet.
	 */
	free_quic_tx_packet(qc, pkt);
	goto leave;
}


static void __quic_conn_init(void)
{
	ha_quic_meth = BIO_meth_new(0x666, "ha QUIC methods");
}
INITCALL0(STG_REGISTER, __quic_conn_init);

static void __quic_conn_deinit(void)
{
	BIO_meth_free(ha_quic_meth);
}
REGISTER_POST_DEINIT(__quic_conn_deinit);

/* Handle a new <dgram> received. Parse each QUIC packets and copied their
 * content to a quic-conn instance. The datagram content can be released after
 * this function.
 *
 * If datagram has been received on a quic-conn owned FD, <from_qc> must be set
 * to the connection instance. <li> is the attached listener. The caller is
 * responsible to ensure that the first packet is destined to this connection
 * by comparing CIDs.
 *
 * If datagram has been received on a receiver FD, <from_qc> will be NULL. This
 * function will thus retrieve the connection from the CID tree or allocate a
 * new one if possible. <li> is the listener attached to the receiver.
 *
 * Returns 0 on success else non-zero. If an error happens, some packets from
 * the datagram may not have been parsed.
 */
int quic_dgram_parse(struct quic_dgram *dgram, struct quic_conn *from_qc,
                     struct listener *li)
{
	struct quic_rx_packet *pkt;
	struct quic_conn *qc = NULL;
	unsigned char *pos, *end;
	struct list *tasklist_head = NULL;

	TRACE_ENTER(QUIC_EV_CONN_LPKT);

	pos = dgram->buf;
	end = pos + dgram->len;
	do {
		/* TODO replace zalloc -> alloc. */
		pkt = pool_zalloc(pool_head_quic_rx_packet);
		if (!pkt) {
			TRACE_ERROR("RX packet allocation failed", QUIC_EV_CONN_LPKT);
			goto err;
		}

		pkt->version = NULL;
		pkt->pn_offset = 0;

		/* Set flag if pkt is the first one in dgram. */
		if (pos == dgram->buf)
			pkt->flags |= QUIC_FL_RX_PACKET_DGRAM_FIRST;

		LIST_INIT(&pkt->qc_rx_pkt_list);
		pkt->time_received = now_ms;
		quic_rx_packet_refinc(pkt);
		if (quic_rx_pkt_parse(pkt, pos, end, dgram, li))
			goto next;

		/* Search quic-conn instance for first packet of the datagram.
		 * quic_rx_packet_parse() is responsible to discard packets
		 * with different DCID as the first one in the same datagram.
		 */
		if (!qc) {
			qc = from_qc ? from_qc : quic_rx_pkt_retrieve_conn(pkt, dgram, li);
			/* qc is NULL if receiving a non Initial packet for an
			 * unknown connection.
			 */
			if (!qc) {
				/* Skip the entire datagram. */
				pkt->len = end - pos;
				goto next;
			}

			dgram->qc = qc;
		}

		if (qc_rx_check_closing(qc, pkt)) {
			/* Skip the entire datagram. */
			pkt->len = end - pos;
			goto next;
		}

		/* Detect QUIC connection migration. */
		if (ipcmp(&qc->peer_addr, &dgram->saddr, 1)) {
			if (qc_handle_conn_migration(qc, &dgram->saddr, &dgram->daddr)) {
				/* Skip the entire datagram. */
				TRACE_ERROR("error during connection migration, datagram dropped", QUIC_EV_CONN_LPKT, qc);
				pkt->len = end - pos;
				goto next;
			}
		}

		qc_rx_pkt_handle(qc, pkt, dgram, pos, &tasklist_head);

 next:
		pos += pkt->len;
		quic_rx_packet_refdec(pkt);

		/* Free rejected packets */
		if (!pkt->refcnt) {
			BUG_ON(LIST_INLIST(&pkt->qc_rx_pkt_list));
			pool_free(pool_head_quic_rx_packet, pkt);
		}
	} while (pos < end);

	/* Increasing the received bytes counter by the UDP datagram length
	 * if this datagram could be associated to a connection.
	 */
	if (dgram->qc)
		dgram->qc->rx.bytes += dgram->len;

	/* This must never happen. */
	BUG_ON(pos > end);
	BUG_ON(pos < end || pos > dgram->buf + dgram->len);
	/* Mark this datagram as consumed */
	HA_ATOMIC_STORE(&dgram->buf, NULL);

	TRACE_LEAVE(QUIC_EV_CONN_LPKT);
	return 0;

 err:
	TRACE_LEAVE(QUIC_EV_CONN_LPKT);
	return -1;
}

/* Check if connection ID <dcid> of length <dcid_len> belongs to <qc> local
 * CIDs. This can be used to determine if a datagram is addressed to the right
 * connection instance.
 *
 * Returns a boolean value.
 */
int qc_check_dcid(struct quic_conn *qc, unsigned char *dcid, size_t dcid_len)
{
	struct ebmb_node *node;
	struct quic_connection_id *id;

	/* For ODCID, address is concatenated to it after qc.odcid.len so this
	 * comparison is safe.
	 */
	if ((qc->scid.len == dcid_len &&
	     memcmp(qc->scid.data, dcid, dcid_len) == 0) ||
	    (qc->odcid.len == dcid_len &&
	     memcmp(qc->odcid.data, dcid, dcid_len) == 0)) {
		return 1;
	}

	node = ebmb_lookup(&quic_dghdlrs[tid].cids, dcid, dcid_len);
	if (node) {
		id = ebmb_entry(node, struct quic_connection_id, node);
		if (qc == id->qc)
			return 1;
	}

	return 0;
}

/* Retrieve the DCID from a QUIC datagram or packet with <buf> as first octet.
 * Returns 1 if succeeded, 0 if not.
 */
int quic_get_dgram_dcid(unsigned char *buf, const unsigned char *end,
                        unsigned char **dcid, size_t *dcid_len)
{
	int ret = 0, long_header;
	size_t minlen, skip;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT);

	if (!(*buf & QUIC_PACKET_FIXED_BIT)) {
		TRACE_PROTO("fixed bit not set", QUIC_EV_CONN_RXPKT);
		goto err;
	}

	long_header = *buf & QUIC_PACKET_LONG_HEADER_BIT;
	minlen = long_header ? QUIC_LONG_PACKET_MINLEN :
		QUIC_SHORT_PACKET_MINLEN + QUIC_HAP_CID_LEN + QUIC_TLS_TAG_LEN;
	skip = long_header ? QUIC_LONG_PACKET_DCID_OFF : QUIC_SHORT_PACKET_DCID_OFF;
	if (end - buf < minlen)
		goto err;

	buf += skip;
	*dcid_len = long_header ? *buf++ : QUIC_HAP_CID_LEN;
	if (*dcid_len > QUIC_CID_MAXLEN || end - buf <= *dcid_len)
		goto err;

	*dcid = buf;

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_RXPKT);
	return ret;

 err:
	TRACE_PROTO("wrong datagram", QUIC_EV_CONN_RXPKT);
	goto leave;
}

/* Notify the MUX layer if alive about an imminent close of <qc>. */
void qc_notify_close(struct quic_conn *qc)
{
	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);

	if (qc->flags & QUIC_FL_CONN_NOTIFY_CLOSE)
		goto leave;

	qc->flags |= QUIC_FL_CONN_NOTIFY_CLOSE;
	/* wake up the MUX */
	if (qc->mux_state == QC_MUX_READY && qc->conn->mux->wake) {
		TRACE_STATE("connection closure notidfied to mux",
		            QUIC_FL_CONN_NOTIFY_CLOSE, qc);
		qc->conn->mux->wake(qc->conn);
	}
	else
		TRACE_STATE("connection closure not notidfied to mux",
		            QUIC_FL_CONN_NOTIFY_CLOSE, qc);
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);
}


/* appctx context used by "show quic" command */
struct show_quic_ctx {
	unsigned int epoch;
	struct bref bref; /* back-reference to the quic-conn being dumped */
	unsigned int thr;
	int flags;
};

#define QC_CLI_FL_SHOW_ALL 0x1 /* show closing/draining connections */

static int cli_parse_show_quic(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_quic_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	ctx->epoch = _HA_ATOMIC_FETCH_ADD(&qc_epoch, 1);
	ctx->thr = 0;
	ctx->flags = 0;

	if (*args[2] && strcmp(args[2], "all") == 0)
		ctx->flags |= QC_CLI_FL_SHOW_ALL;

	LIST_INIT(&ctx->bref.users);

	return 0;
}

static int cli_io_handler_dump_quic(struct appctx *appctx)
{
	struct show_quic_ctx *ctx = appctx->svcctx;
	struct stconn *sc = appctx_sc(appctx);
	struct quic_conn *qc;
	struct quic_enc_level *qel;
	struct eb64_node *node;
	struct qc_stream_desc *stream;
	char bufaddr[INET6_ADDRSTRLEN], bufport[6];
	int expire;
	unsigned char cid_len;

	thread_isolate();

	if (ctx->thr >= global.nbthread)
		goto done;

	if (unlikely(sc_ic(sc)->flags & CF_SHUTW)) {
		/* If we're forced to shut down, we might have to remove our
		 * reference to the last stream being dumped.
		 */
		if (!LIST_ISEMPTY(&ctx->bref.users))
			LIST_DEL_INIT(&ctx->bref.users);
		goto done;
	}

	chunk_reset(&trash);

	if (!LIST_ISEMPTY(&ctx->bref.users)) {
		/* Remove show_quic_ctx from previous quic_conn instance. */
		LIST_DEL_INIT(&ctx->bref.users);
	}
	else if (!ctx->bref.ref) {
		/* First invocation. */
		ctx->bref.ref = ha_thread_ctx[ctx->thr].quic_conns.n;
	}

	while (1) {
		int done = 0;
		int i;

		if (ctx->bref.ref == &ha_thread_ctx[ctx->thr].quic_conns) {
			done = 1;
		}
		else {
			qc = LIST_ELEM(ctx->bref.ref, struct quic_conn *, el_th_ctx);
			if ((int)(qc->qc_epoch - ctx->epoch) > 0)
				done = 1;
		}

		if (done) {
			++ctx->thr;
			if (ctx->thr >= global.nbthread)
				break;
			ctx->bref.ref = ha_thread_ctx[ctx->thr].quic_conns.n;
			continue;
		}

		if (!(ctx->flags & QC_CLI_FL_SHOW_ALL) &&
		    qc->flags & (QUIC_FL_CONN_CLOSING|QUIC_FL_CONN_DRAINING)) {
			ctx->bref.ref = qc->el_th_ctx.n;
			continue;
		}

		/* CIDs */
		chunk_appendf(&trash, "* %p[%02u]: scid=", qc, qc->tid);
		for (cid_len = 0; cid_len < qc->scid.len; ++cid_len)
			chunk_appendf(&trash, "%02x", qc->scid.data[cid_len]);
		while (cid_len++ < 20)
			chunk_appendf(&trash, "..");

		chunk_appendf(&trash, " dcid=");
		for (cid_len = 0; cid_len < qc->dcid.len; ++cid_len)
			chunk_appendf(&trash, "%02x", qc->dcid.data[cid_len]);
		while (cid_len++ < 20)
			chunk_appendf(&trash, "..");

		chunk_appendf(&trash, "\n");

		/* Connection state */
		if (qc->flags & QUIC_FL_CONN_CLOSING)
			chunk_appendf(&trash, "  st=closing          ");
		else if (qc->flags & QUIC_FL_CONN_DRAINING)
			chunk_appendf(&trash, "  st=draining         ");
		else if (qc->state < QUIC_HS_ST_CONFIRMED)
			chunk_appendf(&trash, "  st=handshake        ");
		else
			chunk_appendf(&trash, "  st=opened           ");

		if (qc->mux_state == QC_MUX_NULL)
			chunk_appendf(&trash, "mux=null                                      ");
		else if (qc->mux_state == QC_MUX_READY)
			chunk_appendf(&trash, "mux=ready                                     ");
		else
			chunk_appendf(&trash, "mux=released                                  ");

		expire = qc->idle_timer_task->expire;
		chunk_appendf(&trash, "expire=%02ds ",
		              expire > now_ms ? (expire - now_ms) / 1000 : 0);

		chunk_appendf(&trash, "\n");

		/* Socket */
		chunk_appendf(&trash, "  fd=%d", qc->fd);
		if (qc->local_addr.ss_family == AF_INET ||
		    qc->local_addr.ss_family == AF_INET6) {
			addr_to_str(&qc->local_addr, bufaddr, sizeof(bufaddr));
			port_to_str(&qc->local_addr, bufport, sizeof(bufport));
			chunk_appendf(&trash, "               from=%s:%s", bufaddr, bufport);

			addr_to_str(&qc->peer_addr, bufaddr, sizeof(bufaddr));
			port_to_str(&qc->peer_addr, bufport, sizeof(bufport));
			chunk_appendf(&trash, " to=%s:%s", bufaddr, bufport);
		}

		chunk_appendf(&trash, "\n");

		/* Encryption levels */
		qel = &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL];
		chunk_appendf(&trash, "  [initl]             rx.ackrng=%-6zu tx.inflight=%-6zu",
		              qel->pktns->rx.arngs.sz, qel->pktns->tx.in_flight);
		qel = &qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE];
		chunk_appendf(&trash, "           [hndshk] rx.ackrng=%-6zu tx.inflight=%-6zu\n",
		              qel->pktns->rx.arngs.sz, qel->pktns->tx.in_flight);
		qel = &qc->els[QUIC_TLS_ENC_LEVEL_EARLY_DATA];
		chunk_appendf(&trash, "  [0-rtt]             rx.ackrng=%-6zu tx.inflight=%-6zu",
		              qel->pktns->rx.arngs.sz, qel->pktns->tx.in_flight);
		qel = &qc->els[QUIC_TLS_ENC_LEVEL_APP];
		chunk_appendf(&trash, "           [1-rtt]  rx.ackrng=%-6zu tx.inflight=%-6zu",
		              qel->pktns->rx.arngs.sz, qel->pktns->tx.in_flight);

		chunk_appendf(&trash, "\n");

		/* Streams */
		node = eb64_first(&qc->streams_by_id);
		i = 0;
		while (node) {
			stream = eb64_entry(node, struct qc_stream_desc, by_id);
			node = eb64_next(node);

			chunk_appendf(&trash, "  | stream=%-8llu", (unsigned long long)stream->by_id.key);
			chunk_appendf(&trash, " off=%-8llu ack=%-8llu",
			              (unsigned long long)stream->buf_offset,
			              (unsigned long long)stream->ack_offset);

			if (!(++i % 3)) {
				chunk_appendf(&trash, "\n");
				i = 0;
			}
		}

		chunk_appendf(&trash, "\n");

		if (applet_putchk(appctx, &trash) == -1) {
			/* Register show_quic_ctx to quic_conn instance. */
			LIST_APPEND(&qc->back_refs, &ctx->bref.users);
			goto full;
		}

		ctx->bref.ref = qc->el_th_ctx.n;
	}

 done:
	thread_release();
	return 1;

 full:
	thread_release();
	return 0;
}

static void cli_release_show_quic(struct appctx *appctx)
{
	struct show_quic_ctx *ctx = appctx->svcctx;

	if (ctx->thr < global.nbthread) {
		thread_isolate();
		if (!LIST_ISEMPTY(&ctx->bref.users))
			LIST_DEL_INIT(&ctx->bref.users);
		thread_release();
	}
}

static struct cli_kw_list cli_kws = {{ }, {
	{ { "show", "quic", NULL }, "show quic : display quic connections status", cli_parse_show_quic, cli_io_handler_dump_quic, cli_release_show_quic },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

static void init_quic()
{
	int thr;

	for (thr = 0; thr < MAX_THREADS; ++thr)
		LIST_INIT(&ha_thread_ctx[thr].quic_conns);
}
INITCALL0(STG_INIT, init_quic);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
