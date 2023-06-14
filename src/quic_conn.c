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
#include <haproxy/xxhash.h>

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
/* RFC 8999 5.4. Version
 * A Version field with a
 * value of 0x00000000 is reserved for version negotiation
 */
const struct quic_version quic_version_VN_reserved = { .num = 0, };

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
	{ .mask = QUIC_EV_CONN_SET_AFFINITY, .name = "conn_set_affinity", .desc = "set connection thread affinity" },
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
             "quic_connection_id", sizeof(struct quic_connection_id));
DECLARE_POOL(pool_head_quic_dgram, "quic_dgram", sizeof(struct quic_dgram));
DECLARE_POOL(pool_head_quic_rx_packet, "quic_rx_packet", sizeof(struct quic_rx_packet));
DECLARE_POOL(pool_head_quic_tx_packet, "quic_tx_packet", sizeof(struct quic_tx_packet));
DECLARE_STATIC_POOL(pool_head_quic_rx_crypto_frm, "quic_rx_crypto_frm", sizeof(struct quic_rx_crypto_frm));
DECLARE_STATIC_POOL(pool_head_quic_crypto_buf, "quic_crypto_buf", sizeof(struct quic_crypto_buf));
DECLARE_STATIC_POOL(pool_head_quic_cstream, "quic_cstream", sizeof(struct quic_cstream));
DECLARE_POOL(pool_head_quic_frame, "quic_frame", sizeof(struct quic_frame));
DECLARE_STATIC_POOL(pool_head_quic_arng, "quic_arng", sizeof(struct quic_arng_node));

static struct quic_connection_id *new_quic_cid(struct eb_root *root,
                                               struct quic_conn *qc,
                                               const struct quic_cid *odcid,
                                               const struct sockaddr_storage *saddr);
static struct quic_tx_packet *qc_build_pkt(unsigned char **pos, const unsigned char *buf_end,
                                           struct quic_enc_level *qel, struct quic_tls_ctx *ctx,
                                           struct list *frms, struct quic_conn *qc,
                                           const struct quic_version *ver, size_t dglen, int pkt_type,
                                           int must_ack, int padding, int probe, int cc, int *err);
struct task *quic_conn_app_io_cb(struct task *t, void *context, unsigned int state);
static void qc_idle_timer_do_rearm(struct quic_conn *qc, int arm_ack);
static void qc_idle_timer_rearm(struct quic_conn *qc, int read, int arm_ack);
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

/* Used only for QUIC TLS key phase traces */
struct quic_kp_trace {
	const unsigned char *rx_sec;
	size_t rx_seclen;
	const struct quic_tls_kp *rx;
	const unsigned char *tx_sec;
	size_t tx_seclen;
	const struct quic_tls_kp *tx;
};

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

		chunk_appendf(&trace_buf, " : qc@%p flags=0x%x", qc, qc->flags);
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

		if ((mask & QUIC_EV_CONN_KP) && qc) {
			/* Initial read & write secrets. */
			const struct quic_kp_trace *kp = a2;

			if (kp) {
				if (kp->rx) {
					chunk_appendf(&trace_buf, "\n  RX kp");
					if (kp->rx_sec)
						quic_tls_secret_hexdump(&trace_buf, kp->rx_sec, kp->rx_seclen);
					quic_tls_kp_keys_hexdump(&trace_buf, kp->rx);
				}
				if (kp->tx) {
					chunk_appendf(&trace_buf, "\n  TX kp");
					if (kp->tx_sec)
						quic_tls_secret_hexdump(&trace_buf, kp->tx_sec, kp->tx_seclen);
					quic_tls_kp_keys_hexdump(&trace_buf, kp->tx);
				}
			}
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
				chunk_appendf(&trace_buf, " qel=%c flags=0x%x pto_count=%d cwnd=%llu ppif=%lld pif=%llu "
				              "if=%llu pp=%u",
				              quic_enc_level_char_from_qel(qel, qc),
				              qel->pktns->flags,
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
			const struct list *l = a3;

			if (qel) {
				const struct quic_pktns *pktns = qel->pktns;
				chunk_appendf(&trace_buf,
				              " qel=%c flags=0x%x state=%s ack?%d pto_count=%d cwnd=%llu ppif=%lld pif=%llu if=%llu pp=%u off=%llu",
				              quic_enc_level_char_from_qel(qel, qc),
				              qel->pktns->flags,
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

			if (l) {
				const struct quic_frame *frm;
				list_for_each_entry(frm, l, list) {
					chunk_appendf(&trace_buf, " frm@%p", frm);
					chunk_frm_appendf(&trace_buf, frm);
				}
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
			const struct qf_stream *strm_frm = a2;
			const struct qc_stream_desc *stream = a3;

			if (strm_frm)
				chunk_appendf(&trace_buf, " off=%llu len=%llu", (ull)strm_frm->offset.key, (ull)strm_frm->len);
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
				if (pkt->flags & QUIC_FL_TX_PACKET_ACK)
				    chunk_appendf(&trace_buf, " ack");
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

			if (frm)
				chunk_frm_appendf(&trace_buf, frm);
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

		if (mask & QUIC_EV_CONN_IDLE_TIMER) {
			if (tick_isset(qc->ack_expire))
				chunk_appendf(&trace_buf, " ack_expire=%ums",
				              TICKS_TO_MS(tick_remain(now_ms, qc->ack_expire)));
			if (tick_isset(qc->idle_expire))
				chunk_appendf(&trace_buf, " idle_expire=%ums",
				              TICKS_TO_MS(tick_remain(now_ms, qc->idle_expire)));
			if (qc->idle_timer_task && tick_isset(qc->idle_timer_task->expire))
				chunk_appendf(&trace_buf, " expire=%ums",
				              TICKS_TO_MS(tick_remain(now_ms, qc->idle_timer_task->expire)));
		}
	}

	if (mask & QUIC_EV_CONN_RCV) {
		int i;
		const struct quic_dgram *dgram = a2;
		char bufaddr[INET6_ADDRSTRLEN], bufport[6];

		if (qc) {
			addr_to_str(&qc->peer_addr, bufaddr, sizeof(bufaddr));
			port_to_str(&qc->peer_addr, bufport, sizeof(bufport));
			chunk_appendf(&trace_buf, " peer_addr=%s:%s ", bufaddr, bufport);
		}

		if (dgram) {
			chunk_appendf(&trace_buf, " dgram.len=%zu", dgram->len);
			/* Socket */
			if (dgram->saddr.ss_family == AF_INET ||
				dgram->saddr.ss_family == AF_INET6) {
				addr_to_str(&dgram->saddr, bufaddr, sizeof(bufaddr));
				port_to_str(&dgram->saddr, bufport, sizeof(bufport));
				chunk_appendf(&trace_buf, "saddr=%s:%s ", bufaddr, bufport);

				addr_to_str(&dgram->daddr, bufaddr, sizeof(bufaddr));
				port_to_str(&dgram->daddr, bufport, sizeof(bufport));
				chunk_appendf(&trace_buf, "daddr=%s:%s ", bufaddr, bufport);
			}
			/* DCID */
			for (i = 0; i < dgram->dcid_len; ++i)
				chunk_appendf(&trace_buf, "%02x", dgram->dcid[i]);

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
	TRACE_PROTO("killing the connection", QUIC_EV_CONN_KILL, qc);
	qc->flags |= QUIC_FL_CONN_TO_KILL;
	task_wakeup(qc->idle_timer_task, TASK_WOKEN_OTHER);

	qc_notify_err(qc);

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

	TRACE_ENTER(QUIC_EV_CONN_STIMER, qc);
	TRACE_PROTO("set timer", QUIC_EV_CONN_STIMER, qc, NULL, NULL, &qc->path->ifae_pkts);

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
	TRACE_PROTO("set timer", QUIC_EV_CONN_STIMER, qc, pktns);
	TRACE_LEAVE(QUIC_EV_CONN_STIMER, qc);
}

/* Derive new keys and ivs required for Key Update feature for <qc> QUIC
 * connection.
 * Return 1 if succeeded, 0 if not.
 */
static int quic_tls_key_update(struct quic_conn *qc)
{
	struct quic_tls_ctx *tls_ctx = &qc->els[QUIC_TLS_ENC_LEVEL_APP].tls_ctx;
	struct quic_tls_secrets *rx = &tls_ctx->rx;
	struct quic_tls_secrets *tx = &tls_ctx->tx;
	/* Used only for the traces */
	struct quic_kp_trace kp_trace = {
		.rx_sec = rx->secret,
		.rx_seclen = rx->secretlen,
		.tx_sec = tx->secret,
		.tx_seclen = tx->secretlen,
	};
	/* The next key phase secrets to be derived */
	struct quic_tls_kp *nxt_rx = &qc->ku.nxt_rx;
	struct quic_tls_kp *nxt_tx = &qc->ku.nxt_tx;
	const struct quic_version *ver =
		qc->negotiated_version ? qc->negotiated_version : qc->original_version;
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_KP, qc);

	nxt_rx = &qc->ku.nxt_rx;
	nxt_tx = &qc->ku.nxt_tx;

	TRACE_PRINTF(TRACE_LEVEL_DEVELOPER, QUIC_EV_CONN_SPPKTS, qc, 0, 0, 0,
	             "nxt_rx->secretlen=%llu rx->secretlen=%llu",
	             (ull)nxt_rx->secretlen, (ull)rx->secretlen);
	/* Prepare new RX secrets */
	if (!quic_tls_sec_update(rx->md, ver, nxt_rx->secret, nxt_rx->secretlen,
	                         rx->secret, rx->secretlen)) {
		TRACE_ERROR("New RX secret update failed", QUIC_EV_CONN_KP, qc);
		goto leave;
	}

	if (!quic_tls_derive_keys(rx->aead, NULL, rx->md, ver,
	                          nxt_rx->key, nxt_rx->keylen,
	                          nxt_rx->iv, nxt_rx->ivlen, NULL, 0,
	                          nxt_rx->secret, nxt_rx->secretlen)) {
		TRACE_ERROR("New RX key derivation failed", QUIC_EV_CONN_KP, qc);
		goto leave;
	}

	kp_trace.rx = nxt_rx;
	/* Prepare new TX secrets */
	if (!quic_tls_sec_update(tx->md, ver, nxt_tx->secret, nxt_tx->secretlen,
	                         tx->secret, tx->secretlen)) {
		TRACE_ERROR("New TX secret update failed", QUIC_EV_CONN_KP, qc);
		goto leave;
	}

	if (!quic_tls_derive_keys(tx->aead, NULL, tx->md, ver,
	                          nxt_tx->key, nxt_tx->keylen,
	                          nxt_tx->iv, nxt_tx->ivlen, NULL, 0,
	                          nxt_tx->secret, nxt_tx->secretlen)) {
		TRACE_ERROR("New TX key derivation failed", QUIC_EV_CONN_KP, qc);
		goto leave;
	}

	kp_trace.tx = nxt_tx;
	if (nxt_rx->ctx) {
		EVP_CIPHER_CTX_free(nxt_rx->ctx);
		nxt_rx->ctx = NULL;
	}

	if (!quic_tls_rx_ctx_init(&nxt_rx->ctx, tls_ctx->rx.aead, nxt_rx->key)) {
		TRACE_ERROR("could not initialize RX TLS cipher context", QUIC_EV_CONN_KP, qc);
		goto leave;
	}

	if (nxt_tx->ctx) {
		EVP_CIPHER_CTX_free(nxt_tx->ctx);
		nxt_tx->ctx = NULL;
	}

	if (!quic_tls_tx_ctx_init(&nxt_tx->ctx, tls_ctx->tx.aead, nxt_tx->key)) {
		TRACE_ERROR("could not initialize TX TLS cipher context", QUIC_EV_CONN_KP, qc);
		goto leave;
	}

	ret = 1;
 leave:
	TRACE_PROTO("key update", QUIC_EV_CONN_KP, qc, &kp_trace);
	TRACE_LEAVE(QUIC_EV_CONN_KP, qc);
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

	TRACE_ENTER(QUIC_EV_CONN_RMHP, qc);

	ret = 0;

	/* Check there is enough data in this packet. */
	if (pkt->len - (pn - byte0) < QUIC_PACKET_PN_MAXLEN + sizeof mask) {
		TRACE_PROTO("too short packet", QUIC_EV_CONN_RMHP, qc, pkt);
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
	TRACE_LEAVE(QUIC_EV_CONN_RMHP, qc);
	return ret;
}

/* Encrypt the payload of a QUIC packet with <pn> as number found at <payload>
 * address, with <payload_len> as payload length, <aad> as address of
 * the ADD and <aad_len> as AAD length depending on the <tls_ctx> QUIC TLS
 * context.
 *
 * TODO no error is expected as encryption is done in place but encryption
 * manual is unclear. <fail> will be set to true if an error is detected.
 */
static void quic_packet_encrypt(unsigned char *payload, size_t payload_len,
                                unsigned char *aad, size_t aad_len, uint64_t pn,
                                struct quic_tls_ctx *tls_ctx, struct quic_conn *qc,
                                int *fail)
{
	unsigned char iv[QUIC_TLS_IV_LEN];
	unsigned char *tx_iv = tls_ctx->tx.iv;
	size_t tx_iv_sz = tls_ctx->tx.ivlen;
	struct enc_debug_info edi;

	TRACE_ENTER(QUIC_EV_CONN_ENCPKT, qc);
	*fail = 0;

	quic_aead_iv_build(iv, sizeof iv, tx_iv, tx_iv_sz, pn);

	if (!quic_tls_encrypt(payload, payload_len, aad, aad_len,
	                      tls_ctx->tx.ctx, tls_ctx->tx.aead, tls_ctx->tx.key, iv)) {
		TRACE_ERROR("QUIC packet encryption failed", QUIC_EV_CONN_ENCPKT, qc);
		*fail = 1;
		enc_debug_info_init(&edi, payload, payload_len, aad, aad_len, pn);
	}

	TRACE_LEAVE(QUIC_EV_CONN_ENCPKT, qc);
}

/* Select the correct TLS cipher context to used to decipher <pkt> packet
 * attached to <qc> connection from <qel> encryption level.
 */
static inline struct quic_tls_ctx *qc_select_tls_ctx(struct quic_conn *qc,
                                                     struct quic_enc_level *qel,
                                                     struct quic_rx_packet *pkt)
{
	return pkt->type != QUIC_PACKET_TYPE_INITIAL ? &qel->tls_ctx :
		pkt->version == qc->negotiated_version ? &qc->negotiated_ictx : &qel->tls_ctx;
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
	struct quic_tls_ctx *tls_ctx = qc_select_tls_ctx(qc, qel, pkt);
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
				TRACE_PROTO("Key phase changed", QUIC_EV_CONN_RXPKT, qc);
				kp_changed = 1;
				rx_ctx = qc->ku.nxt_rx.ctx;
				rx_iv  = qc->ku.nxt_rx.iv;
				rx_key = qc->ku.nxt_rx.key;
			}
		}
	}

	quic_aead_iv_build(iv, sizeof iv, rx_iv, rx_iv_sz, pkt->pn);

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
		struct qf_stream *strm_frm;
		struct quic_frame *frm;
		size_t offset, len;

		strm_frm = eb64_entry(frm_node, struct qf_stream, offset);
		offset = strm_frm->offset.key;
		len = strm_frm->len;

		if (offset > stream->ack_offset)
			break;

		if (qc_stream_desc_ack(&stream, offset, len)) {
			/* cf. next comment : frame may be freed at this stage. */
			TRACE_DEVEL("stream consumed", QUIC_EV_CONN_ACKSTRM,
			            qc, stream ? strm_frm : NULL, stream);
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
		eb64_delete(&strm_frm->offset);

		frm = container_of(strm_frm, struct quic_frame, stream);
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
	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);
	TRACE_PROTO("RX ack TX frm", QUIC_EV_CONN_PRSAFRM, qc, frm);

	switch (frm->type) {
	case QUIC_FT_STREAM_8 ... QUIC_FT_STREAM_F:
	{
		struct qf_stream *strm_frm = &frm->stream;
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

		quic_stream_try_to_consume(qc, stream);
	}
	break;
	default:
		qc_release_frm(qc, frm);
	}

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
}

/* Remove <largest> down to <smallest> node entries from <pkts> tree of TX packet,
 * deallocating them, and their TX frames.
 * May be NULL if <largest> node could not be found.
 */
static inline void qc_ackrng_pkts(struct quic_conn *qc,
                                  struct eb_root *pkts,
                                  unsigned int *pkt_flags,
                                  struct list *newly_acked_pkts,
                                  struct eb64_node *largest_node,
                                  uint64_t largest, uint64_t smallest)
{
	struct eb64_node *node;
	struct quic_tx_packet *pkt;

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);

	node = eb64_lookup_ge(pkts, smallest);
	if (!node)
		goto leave;

	largest_node = largest_node ? largest_node : eb64_lookup_le(pkts, largest);
	if (!largest_node)
		goto leave;

	while (node && node->key <= largest_node->key) {
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
		node = eb64_next(node);
		eb64_delete(&pkt->pn_node);
	}

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
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
			struct qf_stream *strm_frm = &frm->stream;
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
				uint64_t diff = stream_desc->ack_offset - strm_frm->offset.key;

				qc_stream_frm_mv_fwd(frm, diff);
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
				qc_notify_err(qc);
				close = 1;
			}

			LIST_APPEND(pktns_frm_list, &frm->list);
			TRACE_DEVEL("frame requeued", QUIC_EV_CONN_PRSAFRM, qc, frm);
		}
	}

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

		/* Do not empty the tree: the first ACK range contains the
		 * largest acknowledged packet number.
		 */
		if (arngs->sz == 1)
			break;

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
	struct qf_ack *ack_frm = &frm->ack;
	uint64_t smallest, largest;
	struct eb_root *pkts;
	struct eb64_node *largest_node;
	unsigned int time_sent, pkt_flags;
	struct list newly_acked_pkts = LIST_HEAD_INIT(newly_acked_pkts);
	struct list lost_pkts = LIST_HEAD_INIT(lost_pkts);
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);

	if (ack_frm->largest_ack > qel->pktns->tx.next_pn) {
		TRACE_DEVEL("ACK for not sent packet", QUIC_EV_CONN_PRSAFRM,
		            qc, NULL, &ack_frm->largest_ack);
		goto err;
	}

	if (ack_frm->first_ack_range > ack_frm->largest_ack) {
		TRACE_DEVEL("too big first ACK range", QUIC_EV_CONN_PRSAFRM,
		            qc, NULL, &ack_frm->first_ack_range);
		goto err;
	}

	largest = ack_frm->largest_ack;
	smallest = largest - ack_frm->first_ack_range;
	pkts = &qel->pktns->tx.pkts;
	pkt_flags = 0;
	largest_node = NULL;
	time_sent = 0;

	if ((int64_t)ack_frm->largest_ack > qel->pktns->rx.largest_acked_pn) {
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

	TRACE_PROTO("RX ack range", QUIC_EV_CONN_PRSAFRM,
	            qc, NULL, &largest, &smallest);
	do {
		uint64_t gap, ack_range;

		qc_ackrng_pkts(qc, pkts, &pkt_flags, &newly_acked_pkts,
		               largest_node, largest, smallest);
		if (!ack_frm->ack_range_num--)
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

		TRACE_PROTO("RX next ack range", QUIC_EV_CONN_PRSAFRM,
		            qc, NULL, &largest, &smallest);
	} while (1);

	if (time_sent && (pkt_flags & QUIC_FL_TX_PACKET_ACK_ELICITING)) {
		*rtt_sample = tick_remain(time_sent, now_ms);
		qel->pktns->rx.largest_acked_pn = ack_frm->largest_ack;
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
		qc_notify_send(qc);
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
 * message may be split between packets
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
			qc->flags |= QUIC_FL_CONN_NEED_POST_HANDSHAKE_FRMS;
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
                                     struct qf_stream *strm_frm,
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

		if (frm->flags & QUIC_FL_TX_FRAME_ACKED) {
			TRACE_DEVEL("already acknowledged frame", QUIC_EV_CONN_PRSAFRM, qc, frm);
			continue;
		}

		switch (frm->type) {
		case QUIC_FT_STREAM_8 ... QUIC_FT_STREAM_F:
		{
			struct qf_stream *strm_frm = &frm->stream;
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
				uint64_t diff = stream_desc->ack_offset - strm_frm->offset.key;

				qc_stream_frm_mv_fwd(frm, diff);
				TRACE_DEVEL("updated partially acked frame",
				            QUIC_EV_CONN_PRSAFRM, qc, frm);
			}

			strm_frm->dup = 1;
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

/* Boolean function which return 1 if <pkt> TX packet is only made of
 * already acknowledged frame.
 */
static inline int qc_pkt_with_only_acked_frms(struct quic_tx_packet *pkt)
{
	struct quic_frame *frm;

	list_for_each_entry(frm, &pkt->frms, list)
		if (!(frm->flags & QUIC_FL_TX_FRAME_ACKED))
			return 0;

	return 1;
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

	TRACE_ENTER(QUIC_EV_CONN_SPPKTS, qc);

	BUG_ON(frms1 == frms2);

	pkt = NULL;
	node = eb64_first(pkts);
 start:
	while (node) {
		struct quic_tx_packet *p;

		p = eb64_entry(node, struct quic_tx_packet, pn_node);
		node = eb64_next(node);
		/* Skip the empty and coalesced packets */
		TRACE_PRINTF(TRACE_LEVEL_PROTO, QUIC_EV_CONN_SPPKTS, qc, 0, 0, 0,
		             "--> pn=%llu (%d %d %d)", (ull)p->pn_node.key,
		             LIST_ISEMPTY(&p->frms), !!(p->flags & QUIC_FL_TX_PACKET_COALESCED),
		             qc_pkt_with_only_acked_frms(p));
		if (!LIST_ISEMPTY(&p->frms) && !qc_pkt_with_only_acked_frms(p)) {
			pkt = p;
			break;
		}
	}

	if (!pkt)
		goto leave;

	/* When building a packet from another one, the field which may increase the
	 * packet size is the packet number. And the maximum increase is 4 bytes.
	 */
	if (!quic_peer_validated_addr(qc) && qc_is_listener(qc) &&
	    pkt->len + 4 > 3 * qc->rx.bytes - qc->tx.prep_bytes) {
		qc->flags |= QUIC_FL_CONN_ANTI_AMPLIFICATION_REACHED;
		TRACE_PROTO("anti-amplification limit would be reached", QUIC_EV_CONN_SPPKTS, qc, pkt);
		goto leave;
	}

	TRACE_PROTO("duplicating packet", QUIC_EV_CONN_SPPKTS, qc, pkt);
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

	TRACE_ENTER(QUIC_EV_CONN_SPPKTS, qc);
 start:
	pkt = NULL;
	pkts = &qel->pktns->tx.pkts;
	node = eb64_first(pkts);
	/* Skip the empty packet (they have already been retransmitted) */
	while (node) {
		struct quic_tx_packet *p;

		p = eb64_entry(node, struct quic_tx_packet, pn_node);
		TRACE_PRINTF(TRACE_LEVEL_PROTO, QUIC_EV_CONN_SPPKTS, qc, 0, 0, 0,
		             "--> pn=%llu (%d %d)", (ull)p->pn_node.key,
		             LIST_ISEMPTY(&p->frms), !!(p->flags & QUIC_FL_TX_PACKET_COALESCED));
		if (!LIST_ISEMPTY(&p->frms) && !(p->flags & QUIC_FL_TX_PACKET_COALESCED) &&
		    !qc_pkt_with_only_acked_frms(p)) {
			pkt = p;
			break;
		}

		node = eb64_next(node);
	}

	if (!pkt)
		goto end;

	/* When building a packet from another one, the field which may increase the
	 * packet size is the packet number. And the maximum increase is 4 bytes.
	 */
	if (!quic_peer_validated_addr(qc) && qc_is_listener(qc)) {
		size_t dglen = pkt->len + 4;

		dglen += pkt->next ? pkt->next->len + 4 : 0;
		if (dglen > 3 * qc->rx.bytes - qc->tx.prep_bytes) {
			qc->flags |= QUIC_FL_CONN_ANTI_AMPLIFICATION_REACHED;
			TRACE_PROTO("anti-amplification limit would be reached", QUIC_EV_CONN_SPPKTS, qc, pkt);
			if (pkt->next)
				TRACE_PROTO("anti-amplification limit would be reached", QUIC_EV_CONN_SPPKTS, qc, pkt->next);
			goto end;
		}
	}

	qel->pktns->tx.pto_probe += 1;

	/* No risk to loop here, #packet per datagram is bounded */
 requeue:
	TRACE_PROTO("duplicating packet", QUIC_EV_CONN_PRSAFRM, qc, NULL, &pkt->pn_node.key);
	qc_dup_pkt_frms(qc, &pkt->frms, tmp);
	if (qel == iqel) {
		if (pkt->next && pkt->next->type == QUIC_PACKET_TYPE_HANDSHAKE) {
			pkt = pkt->next;
			tmp = &htmp;
			hqel->pktns->tx.pto_probe += 1;
			TRACE_DEVEL("looping for next packet", QUIC_EV_CONN_SPPKTS, qc);
			goto requeue;
		}
	}

 end:
	LIST_SPLICE(ifrms, &itmp);
	LIST_SPLICE(hfrms, &htmp);

	TRACE_LEAVE(QUIC_EV_CONN_SPPKTS, qc);
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
 * Returns 1 on success else 0.
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
                                struct qf_crypto *crypto_frm, struct quic_rx_packet *pkt,
                                struct quic_enc_level *qel, int *fast_retrans)
{
	int ret = 0;
	enum ncb_ret ncb_ret;
	/* XXX TO DO: <cfdebug> is used only for the traces. */
	struct quic_rx_crypto_frm cfdebug = {
		.offset_node.key = crypto_frm->offset,
		.len = crypto_frm->len,
	};
	struct quic_cstream *cstream = qel->cstream;
	struct ncbuf *ncbuf = &qel->cstream->rx.ncbuf;

	TRACE_ENTER(QUIC_EV_CONN_PRSHPKT, qc);
	if (unlikely(qel->tls_ctx.flags & QUIC_FL_TLS_SECRETS_DCD)) {
		TRACE_PROTO("CRYPTO data discarded",
					QUIC_EV_CONN_RXPKT, qc, pkt, &cfdebug);
		goto done;
	}

	if (unlikely(crypto_frm->offset < cstream->rx.offset)) {
		size_t diff;

		if (crypto_frm->offset + crypto_frm->len <= cstream->rx.offset) {
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

		diff = cstream->rx.offset - crypto_frm->offset;
		crypto_frm->len -= diff;
		crypto_frm->data += diff;
		crypto_frm->offset = cstream->rx.offset;
	}

	if (crypto_frm->offset == cstream->rx.offset && ncb_is_empty(ncbuf)) {
		if (!qc_provide_cdata(qel, qc->xprt_ctx, crypto_frm->data, crypto_frm->len,
		                      pkt, &cfdebug)) {
			// trace already emitted by function above
			goto leave;
		}

		cstream->rx.offset += crypto_frm->len;
		TRACE_DEVEL("increment crypto level offset", QUIC_EV_CONN_PHPKTS, qc, qel);
		goto done;
	}

	if (!quic_get_ncbuf(ncbuf) ||
	    ncb_is_null(ncbuf)) {
		TRACE_ERROR("CRYPTO ncbuf allocation failed", QUIC_EV_CONN_PRSHPKT, qc);
		goto leave;
	}

	/* crypto_frm->offset > cstream-trx.offset */
	ncb_ret = ncb_add(ncbuf, crypto_frm->offset - cstream->rx.offset,
	                  (const char *)crypto_frm->data, crypto_frm->len, NCB_ADD_COMPARE);
	if (ncb_ret != NCB_RET_OK) {
		if (ncb_ret == NCB_RET_DATA_REJ) {
			TRACE_ERROR("overlapping data rejected", QUIC_EV_CONN_PRSHPKT, qc);
			quic_set_connection_close(qc, quic_err_transport(QC_ERR_PROTOCOL_VIOLATION));
			qc_notify_err(qc);
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

/* Build a NEW_CONNECTION_ID frame for <conn_id> CID of <qc> connection.
 *
 * Returns 1 on success else 0.
 */
static int qc_build_new_connection_id_frm(struct quic_conn *qc,
                                          struct quic_connection_id *conn_id)
{
	int ret = 0;
	struct quic_frame *frm;
	struct quic_enc_level *qel;

	TRACE_ENTER(QUIC_EV_CONN_PRSHPKT, qc);

	qel = &qc->els[QUIC_TLS_ENC_LEVEL_APP];
	frm = qc_frm_alloc(QUIC_FT_NEW_CONNECTION_ID);
	if (!frm) {
		TRACE_ERROR("frame allocation error", QUIC_EV_CONN_IO_CB, qc);
		goto leave;
	}

	quic_connection_id_to_frm_cpy(frm, conn_id);
	LIST_APPEND(&qel->pktns->tx.frms, &frm->list);
	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PRSHPKT, qc);
	return ret;
}


/* Handle RETIRE_CONNECTION_ID frame from <frm> frame.
 * Return 1 if succeeded, 0 if not. If succeeded, also set <to_retire>
 * to the CID to be retired if not already retired.
 */
static int qc_handle_retire_connection_id_frm(struct quic_conn *qc,
                                              struct quic_frame *frm,
                                              struct quic_cid *dcid,
                                              struct quic_connection_id **to_retire)
{
	int ret = 0;
	struct qf_retire_connection_id *rcid_frm = &frm->retire_connection_id;
	struct eb64_node *node;
	struct quic_connection_id *conn_id;

	TRACE_ENTER(QUIC_EV_CONN_PRSHPKT, qc);

	/* RFC 9000 19.16. RETIRE_CONNECTION_ID Frames:
	 * Receipt of a RETIRE_CONNECTION_ID frame containing a sequence number greater
	 * than any previously sent to the peer MUST be treated as a connection error
	 * of type PROTOCOL_VIOLATION.
	 */
	if (rcid_frm->seq_num >= qc->next_cid_seq_num) {
		TRACE_PROTO("CID seq. number too big", QUIC_EV_CONN_PSTRM, qc, frm);
		goto protocol_violation;
	}

	/* RFC 9000 19.16. RETIRE_CONNECTION_ID Frames:
	 * The sequence number specified in a RETIRE_CONNECTION_ID frame MUST NOT refer to
	 * the Destination Connection ID field of the packet in which the frame is contained.
	 * The peer MAY treat this as a connection error of type PROTOCOL_VIOLATION.
	 */
	node = eb64_lookup(&qc->cids, rcid_frm->seq_num);
	if (!node) {
		TRACE_PROTO("CID already retired", QUIC_EV_CONN_PSTRM, qc, frm);
		goto out;
	}

	conn_id = eb64_entry(node, struct quic_connection_id, seq_num);
	/* Note that the length of <dcid> has already been checked. It must match the
	 * length of the CIDs which have been provided to the peer.
	 */
	if (!memcmp(dcid->data, conn_id->cid.data, QUIC_HAP_CID_LEN)) {
		TRACE_PROTO("cannot retire the current CID", QUIC_EV_CONN_PSTRM, qc, frm);
		goto protocol_violation;
	}

	*to_retire = conn_id;
 out:
	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PRSHPKT, qc);
	return ret;
 protocol_violation:
	quic_set_connection_close(qc, quic_err_transport(QC_ERR_PROTOCOL_VIOLATION));
	qc_notify_err(qc);
	goto leave;
}

/* Remove a <qc> quic-conn from its ha_thread_ctx list. If <closing> is true,
 * it will immediately be reinserted in the ha_thread_ctx quic_conns_clo list.
 */
static void qc_detach_th_ctx_list(struct quic_conn *qc, int closing)
{
	struct bref *bref, *back;

	/* Detach CLI context watchers currently dumping this connection.
	 * Reattach them to the next quic_conn instance.
	 */
	list_for_each_entry_safe(bref, back, &qc->back_refs, users) {
		/* Remove watcher from this quic_conn instance. */
		LIST_DEL_INIT(&bref->users);

		/* Attach it to next instance unless it was the last list element. */
		if (qc->el_th_ctx.n != &th_ctx->quic_conns &&
		    qc->el_th_ctx.n != &th_ctx->quic_conns_clo) {
			struct quic_conn *next = LIST_NEXT(&qc->el_th_ctx,
			                                   struct quic_conn *,
			                                   el_th_ctx);
			LIST_APPEND(&next->back_refs, &bref->users);
		}
		bref->ref = qc->el_th_ctx.n;
		__ha_barrier_store();
	}

	/* Remove quic_conn from global ha_thread_ctx list. */
	LIST_DEL_INIT(&qc->el_th_ctx);

	if (closing)
		LIST_APPEND(&th_ctx->quic_conns_clo, &qc->el_th_ctx);
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

		switch (frm.type) {
		case QUIC_FT_PADDING:
			break;
		case QUIC_FT_PING:
			break;
		case QUIC_FT_ACK:
		{
			unsigned int rtt_sample;

			rtt_sample = UINT_MAX;
			if (!qc_parse_ack_frm(qc, &frm, qel, &rtt_sample, &pos, end)) {
				// trace already emitted by function above
				goto leave;
			}

			if (rtt_sample != UINT_MAX) {
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
				struct qf_reset_stream *rs_frm = &frm.reset_stream;
				qcc_recv_reset_stream(qc->qcc, rs_frm->id, rs_frm->app_error_code, rs_frm->final_size);
			}
			break;
		case QUIC_FT_STOP_SENDING:
		{
			struct qf_stop_sending *ss_frm = &frm.stop_sending;
			if (qc->mux_state == QC_MUX_READY) {
				if (qcc_recv_stop_sending(qc->qcc, ss_frm->id,
				                          ss_frm->app_error_code)) {
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
			struct qf_stream *strm_frm = &frm.stream;
			unsigned nb_streams = qc->rx.strms[qcs_id_type(strm_frm->id)].nb_streams;
			const char fin = frm.type & QUIC_STREAM_FRAME_TYPE_FIN_BIT;

			/* The upper layer may not be allocated. */
			if (qc->mux_state != QC_MUX_READY) {
				if ((strm_frm->id >> QCS_ID_TYPE_SHIFT) < nb_streams) {
					TRACE_DATA("Already closed stream", QUIC_EV_CONN_PRSHPKT, qc);
				}
				else {
					TRACE_DEVEL("No mux for new stream", QUIC_EV_CONN_PRSHPKT, qc);
					if (qc->app_ops == &h3_ops) {
						if (!qc_h3_request_reject(qc, strm_frm->id)) {
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

				break;
			}

			if (!qc_handle_strm_frm(pkt, strm_frm, qc, fin)) {
				TRACE_ERROR("qc_handle_strm_frm() failed", QUIC_EV_CONN_PRSHPKT, qc);
				goto leave;
			}

			break;
		}
		case QUIC_FT_MAX_DATA:
			if (qc->mux_state == QC_MUX_READY) {
				struct qf_max_data *md_frm = &frm.max_data;
				qcc_recv_max_data(qc->qcc, md_frm->max_data);
			}
			break;
		case QUIC_FT_MAX_STREAM_DATA:
			if (qc->mux_state == QC_MUX_READY) {
				struct qf_max_stream_data *msd_frm = &frm.max_stream_data;
				if (qcc_recv_max_stream_data(qc->qcc, msd_frm->id,
				                              msd_frm->max_stream_data)) {
					TRACE_ERROR("qcc_recv_max_stream_data() failed", QUIC_EV_CONN_PRSHPKT, qc);
					goto leave;
				}
			}
			break;
		case QUIC_FT_MAX_STREAMS_BIDI:
		case QUIC_FT_MAX_STREAMS_UNI:
			break;
		case QUIC_FT_DATA_BLOCKED:
			qc->cntrs.data_blocked++;
			break;
		case QUIC_FT_STREAM_DATA_BLOCKED:
			qc->cntrs.stream_data_blocked++;
			break;
		case QUIC_FT_STREAMS_BLOCKED_BIDI:
			qc->cntrs.streams_blocked_bidi++;
			break;
		case QUIC_FT_STREAMS_BLOCKED_UNI:
			qc->cntrs.streams_blocked_uni++;
			break;
		case QUIC_FT_NEW_CONNECTION_ID:
			/* XXX TO DO XXX */
			break;
		case QUIC_FT_RETIRE_CONNECTION_ID:
		{
			struct quic_connection_id *conn_id = NULL;

			if (!qc_handle_retire_connection_id_frm(qc, &frm, &pkt->dcid, &conn_id))
				goto leave;

			if (!conn_id)
				break;

			ebmb_delete(&conn_id->node);
			eb64_delete(&conn_id->seq_num);
			pool_free(pool_head_quic_connection_id, conn_id);
			TRACE_PROTO("CID retired", QUIC_EV_CONN_PSTRM, qc);

			conn_id = new_quic_cid(&qc->cids, qc, NULL, NULL);
			if (!conn_id) {
				TRACE_ERROR("CID allocation error", QUIC_EV_CONN_IO_CB, qc);
			}
			else {
				quic_cid_insert(conn_id);
				qc_build_new_connection_id_frm(qc, conn_id);
			}
			break;
		}
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
				qc_detach_th_ctx_list(qc, 1);
				qc_idle_timer_do_rearm(qc, 0);
				qc_notify_err(qc);
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
 * Also set <*must_ack> to inform the caller if an acknowledgement should be sent.
 */
static int qc_may_build_pkt(struct quic_conn *qc, struct list *frms,
                            struct quic_enc_level *qel, int cc, int probe,
                            int *must_ack)
{
	int force_ack =
		qel == &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL] ||
		qel == &qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE];
	int nb_aepkts_since_last_ack = qel->pktns->rx.nb_aepkts_since_last_ack;

	/* An acknowledgement must be sent if this has been forced by the caller,
	 * typically during the handshake when the packets must be acknowledged as
	 * soon as possible. This is also the case when the ack delay timer has been
	 * triggered, or at least every QUIC_MAX_RX_AEPKTS_SINCE_LAST_ACK packets.
	 */
	*must_ack = (qc->flags & QUIC_FL_CONN_ACK_TIMER_FIRED) ||
		((qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) &&
		 (force_ack || nb_aepkts_since_last_ack >= QUIC_MAX_RX_AEPKTS_SINCE_LAST_ACK));

	/* Do not build any more packet if the TX secrets are not available or
	 * if there is nothing to send, i.e. if no CONNECTION_CLOSE or ACK are required
	 * and if there is no more packets to send upon PTO expiration
	 * and if there is no more ack-eliciting frames to send or in flight
	 * congestion control limit is reached for prepared data
	 */
	if (!quic_tls_has_tx_sec(qel) ||
	    (!cc && !probe && !*must_ack &&
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
		int err, probe, cc, must_ack;

		TRACE_PROTO("TX prep app pkts", QUIC_EV_CONN_PHPKTS, qc, qel, frms);
		probe = 0;
		cc =  qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE;
		/* We do not probe if an immediate close was asked */
		if (!cc)
			probe = qel->pktns->tx.pto_probe;

		if (!qc_may_build_pkt(qc, frms, qel, cc, probe, &must_ack))
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
		                   QUIC_PACKET_TYPE_SHORT, must_ack, 0, probe, cc, &err);
		switch (err) {
		case -2:
			// trace already emitted by function above
			goto leave;
		case -1:
			/* As we provide qc_build_pkt() with an enough big buffer to fulfill an
			 * MTU, we are here because of the congestion control window. There is
			 * no need to try to reuse this buffer.
			 */
			TRACE_PROTO("could not prepare anymore packet", QUIC_EV_CONN_PHPKTS, qc, qel);
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
		int err, probe, cc, must_ack;
		enum quic_pkt_type pkt_type;
		struct quic_tls_ctx *tls_ctx;
		const struct quic_version *ver;

		TRACE_PROTO("TX prep pkts", QUIC_EV_CONN_PHPKTS, qc, qel);
		probe = 0;
		cc =  qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE;
		/* We do not probe if an immediate close was asked */
		if (!cc)
			probe = qel->pktns->tx.pto_probe;

		if (!qc_may_build_pkt(qc, frms, qel, cc, probe, &must_ack)) {
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

		/* RFC 9000 14.1 Initial datagram size
		 * a server MUST expand the payload of all UDP datagrams carrying ack-eliciting
		 * Initial packets to at least the smallest allowed maximum datagram size of
		 * 1200 bytes.
		 *
		 * Ensure that no ack-eliciting packets are sent into too small datagrams
		 */
		if (pkt_type == QUIC_PACKET_TYPE_INITIAL && !LIST_ISEMPTY(tel_frms)) {
			if (end - pos < QUIC_INITIAL_PACKET_MINLEN) {
				TRACE_PROTO("No more enough room to build an Initial packet",
				            QUIC_EV_CONN_PHPKTS, qc);
				goto out;
			}

			/* Pad this Initial packet if there is no ack-eliciting frames to send from
			 * the next packet number space.
			 */
			if (!next_tel_frms || LIST_ISEMPTY(next_tel_frms))
				padding = 1;
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
		                       must_ack, padding, probe, cc, &err);
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
			TRACE_PROTO("could not prepare anymore packet", QUIC_EV_CONN_PHPKTS, qc, qel);
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
		    next_tel != QUIC_TLS_ENC_LEVEL_NONE && (LIST_ISEMPTY(frms))) {
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

/* Free all frames in <l> list. In addition also remove all these frames
 * from the original ones if they are the results of duplications.
 */
static inline void qc_free_frm_list(struct list *l)
{
	struct quic_frame *frm, *frmbak;

	list_for_each_entry_safe(frm, frmbak, l, list) {
		LIST_DEL_INIT(&frm->ref);
		qc_frm_free(&frm);
	}
}

/* Free <pkt> TX packet and all the packets coalesced to it. */
static inline void qc_free_tx_coalesced_pkts(struct quic_tx_packet *p)
{
	struct quic_tx_packet *pkt, *nxt_pkt;

	for (pkt = p; pkt; pkt = nxt_pkt) {
		qc_free_frm_list(&pkt->frms);
		nxt_pkt = pkt->next;
		pool_free(pool_head_quic_tx_packet, pkt);
	}
}

/* Purge <buf> TX buffer from its prepare packets. */
static void qc_purge_tx_buf(struct buffer *buf)
{
	while (b_contig_data(buf, 0)) {
		uint16_t dglen;
		struct quic_tx_packet *pkt;
		size_t headlen = sizeof dglen + sizeof pkt;

		dglen = read_u16(b_head(buf));
		pkt = read_ptr(b_head(buf) + sizeof dglen);
		qc_free_tx_coalesced_pkts(pkt);
		b_del(buf, dglen + headlen);
	}

	BUG_ON(b_data(buf));
}

/* Send datagrams stored in <buf>.
 *
 * This function returns 1 for success. On error, there is several behavior
 * depending on underlying sendto() error :
 * - for an unrecoverable error, 0 is returned and connection is killed.
 * - a transient error is handled differently if connection has its owned
 *   socket. If this is the case, 0 is returned and socket is subscribed on the
 *   poller. The other case is assimilated to a success case with 1 returned.
 *   Remaining data are purged from the buffer and will eventually be detected
 *   as lost which gives the opportunity to retry sending.
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

		TRACE_PROTO("TX dgram", QUIC_EV_CONN_SPPKTS, qc);
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
			int ret = qc_snd_buf(qc, &tmpbuf, tmpbuf.data, 0);
			if (ret < 0) {
				TRACE_ERROR("sendto fatal error", QUIC_EV_CONN_SPPKTS, qc, first_pkt);
				qc_kill_conn(qc);
				qc_free_tx_coalesced_pkts(first_pkt);
				b_del(buf, dglen + headlen);
				qc_purge_tx_buf(buf);
				goto leave;
			}
			else if (!ret) {
				/* Connection owned socket : poller will wake us up when transient error is cleared. */
				if (qc_test_fd(qc)) {
					TRACE_ERROR("sendto error, subscribe to poller", QUIC_EV_CONN_SPPKTS, qc);
					goto leave;
				}

				/* No connection owned-socket : rely on retransmission to retry sending. */
				skip_sendto = 1;
				TRACE_ERROR("sendto error, simulate sending for the rest of data", QUIC_EV_CONN_SPPKTS, qc);
			}
		}

		b_del(buf, dglen + headlen);
		qc->tx.bytes += tmpbuf.data;
		time_sent = now_ms;

		for (pkt = first_pkt; pkt; pkt = next_pkt) {
			/* RFC 9000 14.1 Initial datagram size
			 * a server MUST expand the payload of all UDP datagrams carrying ack-eliciting
			 * Initial packets to at least the smallest allowed maximum datagram size of
			 * 1200 bytes.
			 */
			qc->cntrs.sent_pkt++;
			BUG_ON_HOT(pkt->type == QUIC_PACKET_TYPE_INITIAL &&
			           (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING) &&
			           dglen < QUIC_INITIAL_PACKET_MINLEN);

			pkt->time_sent = time_sent;
			if (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING) {
				pkt->pktns->tx.time_of_last_eliciting = time_sent;
				qc->path->ifae_pkts++;
				if (qc->flags & QUIC_FL_CONN_IDLE_TIMER_RESTARTED_AFTER_READ)
					qc_idle_timer_rearm(qc, 0, 0);
			}
			if (!(qc->flags & QUIC_FL_CONN_CLOSING) &&
			    (pkt->flags & QUIC_FL_TX_PACKET_CC)) {
				qc->flags |= QUIC_FL_CONN_CLOSING;
				qc_detach_th_ctx_list(qc, 1);

				/* RFC 9000 10.2. Immediate Close:
				 * The closing and draining connection states exist to ensure
				 * that connections close cleanly and that delayed or reordered
				 * packets are properly discarded. These states SHOULD persist
				 * for at least three times the current PTO interval...
				 *
				 * Rearm the idle timeout only one time when entering closing
				 * state.
				 */
				qc_idle_timer_do_rearm(qc, 0);
				if (qc->timer_task) {
					task_destroy(qc->timer_task);
					qc->timer_task = NULL;
				}
			}
			qc->path->in_flight += pkt->in_flight_len;
			pkt->pktns->tx.in_flight += pkt->in_flight_len;
			if (pkt->in_flight_len)
				qc_set_timer(qc);
			TRACE_PROTO("TX pkt", QUIC_EV_CONN_SPPKTS, qc, pkt);
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

/* Copy at <pos> position a stateless reset token depending on the
 * <salt> salt input. This is the cluster secret which will be derived
 * as HKDF input secret to generate this token.
 * Return 1 if succeeded, 0 if not.
 */
static int quic_stateless_reset_token_cpy(unsigned char *pos, size_t len,
                                          const unsigned char *salt, size_t saltlen)
{
	/* Input secret */
	const unsigned char *key = (const unsigned char *)global.cluster_secret;
	size_t keylen = strlen(global.cluster_secret);
	/* Info */
	const unsigned char label[] = "stateless token";
	size_t labellen = sizeof label - 1;
	int ret;

	ret = quic_hkdf_extract_and_expand(EVP_sha256(), pos, len,
	                                    key, keylen, salt, saltlen, label, labellen);
	return ret;
}

/* Initialize the stateless reset token attached to <conn_id> connection ID.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_stateless_reset_token_init(struct quic_connection_id *conn_id)
{
	int ret;

	if (global.cluster_secret) {
		/* Output secret */
		unsigned char *token = conn_id->stateless_reset_token;
		size_t tokenlen = sizeof conn_id->stateless_reset_token;
		/* Salt */
		const unsigned char *cid = conn_id->cid.data;
		size_t cidlen = conn_id->cid.len;

		ret = quic_stateless_reset_token_cpy(token, tokenlen, cid, cidlen);
	}
	else {
		/* TODO: RAND_bytes() should be replaced */
		ret = RAND_bytes(conn_id->stateless_reset_token,
		                 sizeof conn_id->stateless_reset_token) == 1;
	}

	return ret;
}

/* Generate a CID directly derived from <orig> CID and <addr> address.
 *
 * Returns the derived CID.
 */
struct quic_cid quic_derive_cid(const struct quic_cid *orig,
                                const struct sockaddr_storage *addr)
{
	struct quic_cid cid;
	const struct sockaddr_in *in;
	const struct sockaddr_in6 *in6;
	char *pos = trash.area;
	size_t idx = 0;
	uint64_t hash;
	int i;

	/* Prepare buffer for hash using original CID first. */
	memcpy(pos, orig->data, orig->len);
	idx += orig->len;

	/* Concatenate client address. */
	switch (addr->ss_family) {
	case AF_INET:
		in = (struct sockaddr_in *)addr;

		memcpy(&pos[idx], &in->sin_addr, sizeof(in->sin_addr));
		idx += sizeof(in->sin_addr);
		memcpy(&pos[idx], &in->sin_port, sizeof(in->sin_port));
		idx += sizeof(in->sin_port);
		break;

	case AF_INET6:
		in6 = (struct sockaddr_in6 *)addr;

		memcpy(&pos[idx], &in6->sin6_addr, sizeof(in6->sin6_addr));
		idx += sizeof(in6->sin6_addr);
		memcpy(&pos[idx], &in6->sin6_port, sizeof(in6->sin6_port));
		idx += sizeof(in6->sin6_port);
		break;

	default:
		/* TODO to implement */
		ABORT_NOW();
	}

	/* Avoid similar values between multiple haproxy process. */
	memcpy(&pos[idx], boot_seed, sizeof(boot_seed));
	idx += sizeof(boot_seed);

	/* Hash the final buffer content. */
	hash = XXH64(pos, idx, 0);

	for (i = 0; i < sizeof(hash); ++i)
		cid.data[i] = hash >> ((sizeof(hash) * 7) - (8 * i));
	cid.len = sizeof(hash);

	return cid;
}

/* Retrieve the thread ID associated to QUIC connection ID <cid> of length
 * <cid_len>. CID may be not found on the CID tree because it is an ODCID. In
 * this case, it will derived using client address <cli_addr> as hash
 * parameter. However, this is done only if <pos> points to an INITIAL or 0RTT
 * packet of length <len>.
 *
 * Returns the thread ID or a negative error code.
 */
int quic_get_cid_tid(const unsigned char *cid, size_t cid_len,
                     const struct sockaddr_storage *cli_addr,
                     unsigned char *pos, size_t len)
{
	struct quic_cid_tree *tree;
	struct quic_connection_id *conn_id;
	struct ebmb_node *node;

	tree = &quic_cid_trees[_quic_cid_tree_idx(cid)];
	HA_RWLOCK_RDLOCK(QC_CID_LOCK, &tree->lock);
	node = ebmb_lookup(&tree->root, cid, cid_len);
	HA_RWLOCK_RDUNLOCK(QC_CID_LOCK, &tree->lock);

	if (!node) {
		struct quic_cid orig, derive_cid;
		struct quic_rx_packet pkt;

		if (!qc_parse_hd_form(&pkt, &pos, pos + len))
			goto not_found;

		if (pkt.type != QUIC_PACKET_TYPE_INITIAL &&
		    pkt.type != QUIC_PACKET_TYPE_0RTT) {
			goto not_found;
		}

		memcpy(orig.data, cid, cid_len);
		orig.len = cid_len;
		derive_cid = quic_derive_cid(&orig, cli_addr);

		tree = &quic_cid_trees[quic_cid_tree_idx(&derive_cid)];
		HA_RWLOCK_RDLOCK(QC_CID_LOCK, &tree->lock);
		node = ebmb_lookup(&tree->root, cid, cid_len);
		HA_RWLOCK_RDUNLOCK(QC_CID_LOCK, &tree->lock);
	}

	if (!node)
		goto not_found;

	conn_id = ebmb_entry(node, struct quic_connection_id, node);
	return HA_ATOMIC_LOAD(&conn_id->tid);

 not_found:
	return -1;
}

/* Allocate a new CID and attach it to <root> ebtree.
 *
 * If <orig> and <addr> params are non null, the new CID value is directly
 * derived from them. Else a random value is generated. The CID is then marked
 * with the current thread ID.
 *
 * Returns the new CID if succeeded, NULL if not.
 */
static struct quic_connection_id *new_quic_cid(struct eb_root *root,
                                               struct quic_conn *qc,
                                               const struct quic_cid *orig,
                                               const struct sockaddr_storage *addr)
{
	struct quic_connection_id *conn_id;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	/* Caller must set either none or both values. */
	BUG_ON(!!orig != !!addr);

	conn_id = pool_alloc(pool_head_quic_connection_id);
	if (!conn_id) {
		TRACE_ERROR("cid allocation failed", QUIC_EV_CONN_TXPKT, qc);
		goto err;
	}

	conn_id->cid.len = QUIC_HAP_CID_LEN;

	if (!orig) {
		/* TODO: RAND_bytes() should be replaced */
		if (RAND_bytes(conn_id->cid.data, conn_id->cid.len) != 1) {
			TRACE_ERROR("RAND_bytes() failed", QUIC_EV_CONN_TXPKT, qc);
			goto err;
		}
	}
	else {
		/* Derive the new CID value from original CID. */
		conn_id->cid = quic_derive_cid(orig, addr);
	}

	if (quic_stateless_reset_token_init(conn_id) != 1) {
		TRACE_ERROR("quic_stateless_reset_token_init() failed", QUIC_EV_CONN_TXPKT, qc);
		goto err;
	}

	conn_id->qc = qc;
	HA_ATOMIC_STORE(&conn_id->tid, tid);

	conn_id->seq_num.key = qc ? qc->next_cid_seq_num++ : 0;
	conn_id->retire_prior_to = 0;
	/* insert the allocated CID in the quic_conn tree */
	if (root)
		eb64_insert(root, &conn_id->seq_num);

	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return conn_id;

 err:
	pool_free(pool_head_quic_connection_id, conn_id);
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
	int ret = 0, max;
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
	 * already one connection ID used for the current connection. Also limit
	 * the number of connection IDs sent to the peer to 4 (3 from this function
	 * plus 1 for the current connection.
	 * Note that active_connection_id_limit >= 2: this has been already checked
	 * when receiving this parameter.
	 */
	max = QUIC_MIN(qc->tx.params.active_connection_id_limit - 1, (uint64_t)3);
	while (max--) {
		struct quic_connection_id *conn_id;

		frm = qc_frm_alloc(QUIC_FT_NEW_CONNECTION_ID);
		if (!frm) {
			TRACE_ERROR("frame allocation error", QUIC_EV_CONN_IO_CB, qc);
			goto err;
		}

		conn_id = new_quic_cid(&qc->cids, qc, NULL, NULL);
		if (!conn_id) {
			qc_frm_free(&frm);
			TRACE_ERROR("CID allocation error", QUIC_EV_CONN_IO_CB, qc);
			goto err;
		}

		/* TODO To prevent CID tree locking, all CIDs created here
		 * could be allocated at the same time as the first one.
		 */
		quic_cid_insert(conn_id);

		quic_connection_id_to_frm_cpy(frm, conn_id);
		LIST_APPEND(&frm_list, &frm->list);
	}

	LIST_SPLICE(&qel->pktns->tx.frms, &frm_list);
	qc->flags &= ~QUIC_FL_CONN_NEED_POST_HANDSHAKE_FRMS;

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_IO_CB, qc);
	return ret;

 err:
	/* free the frames */
	list_for_each_entry_safe(frm, frmbak, &frm_list, list)
		qc_frm_free(&frm);

	/* The first CID sequence number value used to allocated CIDs by this function is 1,
	 * 0 being the sequence number of the CID for this connection.
	 */
	node = eb64_lookup_ge(&qc->cids, 1);
	while (node) {
		struct quic_connection_id *conn_id;

		conn_id = eb64_entry(node, struct quic_connection_id, seq_num);
		if (conn_id->seq_num.key >= max)
			break;

		node = eb64_next(node);
		quic_cid_delete(conn_id);

		eb64_delete(&conn_id->seq_num);
		pool_free(pool_head_quic_connection_id, conn_id);
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

	if (arngs->sz >= QUIC_MAX_ACK_RANGES) {
		struct eb64_node *last;

		last = eb64_last(&arngs->root);
		BUG_ON(last == NULL);
		eb64_delete(last);
		pool_free(pool_head_quic_arng, last);
		arngs->sz--;
	}

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

/* Detect the value of the spin bit to be used. */
static inline void qc_handle_spin_bit(struct quic_conn *qc, struct quic_rx_packet *pkt,
                                      struct quic_enc_level *qel)
{
	uint64_t largest_pn = qel->pktns->rx.largest_pn;

	if (qel != &qc->els[QUIC_TLS_ENC_LEVEL_APP] || largest_pn == -1 ||
	    pkt->pn <= largest_pn)
		return;

	if (qc_is_listener(qc)) {
		if (pkt->flags & QUIC_FL_RX_PACKET_SPIN_BIT)
			qc->flags |= QUIC_FL_CONN_SPIN_BIT;
		else
			qc->flags &= ~QUIC_FL_CONN_SPIN_BIT;
	}
	else {
		if (pkt->flags & QUIC_FL_RX_PACKET_SPIN_BIT)
			qc->flags &= ~QUIC_FL_CONN_SPIN_BIT;
		else
			qc->flags |= QUIC_FL_CONN_SPIN_BIT;
	}
}

/* Remove the header protection of packets at <el> encryption level.
 * Always succeeds.
 */
static inline void qc_rm_hp_pkts(struct quic_conn *qc, struct quic_enc_level *el)
{
	struct quic_rx_packet *pqpkt, *pkttmp;
	struct quic_enc_level *app_qel;

	TRACE_ENTER(QUIC_EV_CONN_ELRMHP, qc);
	app_qel = &qc->els[QUIC_TLS_ENC_LEVEL_APP];
	/* A server must not process incoming 1-RTT packets before the handshake is complete. */
	if (el == app_qel && qc_is_listener(qc) && qc->state < QUIC_HS_ST_COMPLETE) {
		TRACE_PROTO("RX hp not removed (handshake not completed)",
		            QUIC_EV_CONN_ELRMHP, qc);
		goto out;
	}

	list_for_each_entry_safe(pqpkt, pkttmp, &el->rx.pqpkts, list) {
		struct quic_tls_ctx *tls_ctx;

		tls_ctx = qc_select_tls_ctx(qc, el, pqpkt);
		if (!qc_do_rm_hp(qc, pqpkt, tls_ctx, el->pktns->rx.largest_pn,
		                 pqpkt->data + pqpkt->pn_offset, pqpkt->data)) {
			TRACE_ERROR("RX hp removing error", QUIC_EV_CONN_ELRMHP, qc);
		}
		else {
			qc_handle_spin_bit(qc, pqpkt, el);
			/* The AAD includes the packet number field */
			pqpkt->aad_len = pqpkt->pn_offset + pqpkt->pnl;
			/* Store the packet into the tree of packets to decrypt. */
			pqpkt->pn_node.key = pqpkt->pn;
			eb64_insert(&el->rx.pkts, &pqpkt->pn_node);
			quic_rx_packet_refinc(pqpkt);
			TRACE_PROTO("RX hp removed", QUIC_EV_CONN_ELRMHP, qc, pqpkt);
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

	TRACE_ENTER(QUIC_EV_CONN_PHPKTS, qc);

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
                     struct quic_enc_level *next_el)
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
				qc->cntrs.dropped_parsing++;
			}
			else {
				struct quic_arng ar = { .first = pkt->pn, .last = pkt->pn };

				if (pkt->flags & QUIC_FL_RX_PACKET_ACK_ELICITING) {
					int arm_ack_timer =
						qc->state >= QUIC_HS_ST_COMPLETE &&
						qel->pktns == &qc->pktns[QUIC_TLS_PKTNS_01RTT];

					qel->pktns->flags |= QUIC_FL_PKTNS_ACK_REQUIRED;
					qel->pktns->rx.nb_aepkts_since_last_ack++;
					qc_idle_timer_rearm(qc, 1, arm_ack_timer);
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
		TRACE_PROTO("Discarded keys", QUIC_EV_CONN_TRMHP, qc);
		goto cant_rm_hp;
	}

	if (!quic_tls_has_rx_sec(qel)) {
		TRACE_PROTO("non available secrets", QUIC_EV_CONN_TRMHP, qc);
		goto cant_rm_hp;
	}

	if (tel == QUIC_TLS_ENC_LEVEL_APP && qc->state < QUIC_HS_ST_COMPLETE) {
		TRACE_PROTO("handshake not complete", QUIC_EV_CONN_TRMHP, qc);
		goto cant_rm_hp;
	}

	/* check if the connection layer is ready before using app level */
	if ((tel == QUIC_TLS_ENC_LEVEL_APP || tel == QUIC_TLS_ENC_LEVEL_EARLY_DATA) &&
	    qc->mux_state == QC_MUX_NULL) {
		TRACE_PROTO("connection layer not ready", QUIC_EV_CONN_TRMHP, qc);
		goto cant_rm_hp;
	}

	ret = 1;
 cant_rm_hp:
	TRACE_LEAVE(QUIC_EV_CONN_TRMHP, qc);
	return ret;
}

/* Flush txbuf for <qc> connection. This must be called prior to a packet
 * preparation when txbuf contains older data. A send will be conducted for
 * these data.
 *
 * Returns 1 on success : buffer is empty and can be use for packet
 * preparation. On error 0 is returned.
 */
static int qc_purge_txbuf(struct quic_conn *qc, struct buffer *buf)
{
	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	/* This operation can only be conducted if txbuf is not empty. This
	 * case only happens for connection with their owned socket due to an
	 * older transient sendto() error.
	 */
	BUG_ON(!qc_test_fd(qc));

	if (b_data(buf) && !qc_send_ppkts(buf, qc->xprt_ctx)) {
		if (qc->flags & QUIC_FL_CONN_TO_KILL)
			qc_txb_release(qc);
		TRACE_DEVEL("leaving in error", QUIC_EV_CONN_TXPKT, qc);
		return 0;
	}

	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return 1;
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
	int status = 0, ret;
	struct buffer *buf;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	buf = qc_txb_alloc(qc);
	if (!buf) {
		TRACE_ERROR("buffer allocation failed", QUIC_EV_CONN_TXPKT, qc);
		goto err;
	}

	if (b_data(buf) && !qc_purge_txbuf(qc, buf))
		goto err;

	/* Prepare and send packets until we could not further prepare packets. */
	do {
		/* Currently buf cannot be non-empty at this stage. Even if a
		 * previous sendto() has failed it is emptied to simulate
		 * packet emission and rely on QUIC lost detection to try to
		 * emit it.
		 */
		BUG_ON_HOT(b_data(buf));
		b_reset(buf);

		ret = qc_prep_app_pkts(qc, buf, frms);

		if (b_data(buf) && !qc_send_ppkts(buf, qc->xprt_ctx)) {
			if (qc->flags & QUIC_FL_CONN_TO_KILL)
				qc_txb_release(qc);
			goto err;
		}
	} while (ret > 0);

	qc_txb_release(qc);
	if (ret < 0)
		goto err;

	status = 1;
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return status;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_TXPKT, qc);
	return 0;
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

	TRACE_PROTO("preparing old data (probing)", QUIC_EV_CONN_FRMLIST, qc, frms);
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

	if (qc->conn->flags & CO_FL_SOCK_WR_SH) {
		qc->conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH;
		TRACE_DEVEL("connection on error", QUIC_EV_CONN_TXPKT, qc);
		return 0;
	}

	/* Try to send post handshake frames first unless on 0-RTT. */
	if ((qc->flags & QUIC_FL_CONN_NEED_POST_HANDSHAKE_FRMS) &&
	    qc->state >= QUIC_HS_ST_COMPLETE) {
		struct quic_enc_level *qel = &qc->els[QUIC_TLS_ENC_LEVEL_APP];
		quic_build_post_handshake_frames(qc);
		qc_send_app_pkts(qc, &qel->pktns->tx.frms);
	}

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

	if (b_data(buf) && !qc_purge_txbuf(qc, buf))
		goto out;

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
	if (ret == -1) {
		qc_txb_release(qc);
		goto out;
	}

	if (ret && !qc_send_ppkts(buf, qc->xprt_ctx)) {
		if (qc->flags & QUIC_FL_CONN_TO_KILL)
			qc_txb_release(qc);
		goto out;
	}

	qc_txb_release(qc);
	status = 1;

 out:
	TRACE_STATE("no more need old data for probing", QUIC_EV_CONN_TXPKT, qc);
	qc->flags &= ~QUIC_FL_CONN_RETRANS_OLD_DATA;
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
			else {
				if (!(qc->flags & QUIC_FL_CONN_ANTI_AMPLIFICATION_REACHED)) {
					iqel->pktns->tx.pto_probe = 1;
					if (!qc_send_hdshk_pkts(qc, 0, QUIC_TLS_ENC_LEVEL_INITIAL, &ifrms,
					                        QUIC_TLS_ENC_LEVEL_NONE, NULL))
						goto leave;
				}
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
				if (!qc_send_app_probing(qc, &frms1)) {
					qc_free_frm_list(&frms2);
					goto leave;
				}

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

	TRACE_ENTER(QUIC_EV_CONN_IO_CB, qc);

	qel = &qc->els[QUIC_TLS_ENC_LEVEL_APP];
	TRACE_STATE("connection handshake state", QUIC_EV_CONN_IO_CB, qc, &qc->state);

	if (qc_test_fd(qc))
		qc_rcv_buf(qc);

	/* Prepare post-handshake frames
	 * - after connection is instantiated (accept is done)
	 * - handshake state is completed (may not be the case here in 0-RTT)
	 */
	if ((qc->flags & QUIC_FL_CONN_NEED_POST_HANDSHAKE_FRMS) && qc->conn &&
	    qc->state >= QUIC_HS_ST_COMPLETE) {
		quic_build_post_handshake_frames(qc);
	}

	/* Retranmissions */
	if (qc->flags & QUIC_FL_CONN_RETRANS_NEEDED) {
		TRACE_STATE("retransmission needed", QUIC_EV_CONN_IO_CB, qc);
		qc->flags &= ~QUIC_FL_CONN_RETRANS_NEEDED;
		if (!qc_dgrams_retransmit(qc))
			goto out;
	}

	if (!LIST_ISEMPTY(&qel->rx.pqpkts) && qc_qel_may_rm_hp(qc, qel))
		qc_rm_hp_pkts(qc, qel);

	if (!qc_treat_rx_pkts(qc, qel, NULL)) {
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
	int st, zero_rtt;

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

	if (!qc_treat_rx_pkts(qc, qel, next_qel))
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

	if (b_data(buf) && !qc_purge_txbuf(qc, buf))
		goto skip_send;

	/* Currently buf cannot be non-empty at this stage. Even if a previous
	 * sendto() has failed it is emptied to simulate packet emission and
	 * rely on QUIC lost detection to try to emit it.
	 */
	BUG_ON_HOT(b_data(buf));
	b_reset(buf);

	ret = qc_prep_pkts(qc, buf, tel, &qc->els[tel].pktns->tx.frms,
	                   next_tel, &qc->els[next_tel].pktns->tx.frms);
	if (ret == -1) {
		qc_txb_release(qc);
		goto out;
	}

	if (ret && !qc_send_ppkts(buf, qc->xprt_ctx)) {
		if (qc->flags & QUIC_FL_CONN_TO_KILL)
			qc_txb_release(qc);
		goto out;
	}

	qc_txb_release(qc);

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
	TRACE_PROTO("ssl error", QUIC_EV_CONN_IO_CB, qc, &st, &ssl_err);
	TRACE_LEAVE(QUIC_EV_CONN_IO_CB, qc);
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

	TRACE_ENTER(QUIC_EV_CONN_PTIMER, qc);
	TRACE_PROTO("process timer", QUIC_EV_CONN_PTIMER, qc,
	            NULL, NULL, &qc->path->ifae_pkts);

	task->expire = TICK_ETERNITY;
	pktns = quic_loss_pktns(qc);

	if (qc->flags & (QUIC_FL_CONN_DRAINING|QUIC_FL_CONN_TO_KILL)) {
		TRACE_PROTO("cancelled action (draining state)", QUIC_EV_CONN_PTIMER, qc);
		task = NULL;
		goto out;
	}

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
		if (!pktns->tx.in_flight) {
			TRACE_PROTO("No in flight packets to probe with", QUIC_EV_CONN_TXPKT, qc);
			goto out;
		}

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
			pktns->tx.pto_probe = QUIC_MAX_NB_PTO_DGRAMS;
			/* Wake up upper layer if waiting to send new data. */
			if (!qc_notify_send(qc)) {
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
	TRACE_PROTO("process timer", QUIC_EV_CONN_PTIMER, qc, pktns);
	TRACE_LEAVE(QUIC_EV_CONN_PTIMER, qc);

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
	if (tick_is_expired(tick_add(timestamp, MS_TO_TICKS(QUIC_RETRY_DURATION_MS)), now_ms)) {
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
                                     struct quic_connection_id *conn_id,
                                     struct sockaddr_storage *local_addr,
                                     struct sockaddr_storage *peer_addr,
                                     int server, int token, void *owner)
{
	int i;
	struct quic_conn *qc;
	/* Initial CID. */
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
	LIST_INIT(&qc->el_th_ctx);

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
		/* Copy the client original DCID. */
		qc->odcid.len = dcid->len;
		memcpy(qc->odcid.data, dcid->data, dcid->len);

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

	conn_id->qc = qc;
	eb64_insert(&qc->cids, &conn_id->seq_num);
	/* Initialize the next CID sequence number to be used for this connection. */
	qc->next_cid_seq_num = 1;

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

	/* Select our SCID which is the first CID with 0 as sequence number. */
	qc->scid = conn_id->cid;

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
	                                    conn_id->stateless_reset_token,
	                                    dcid->data, dcid->len,
	                                    qc->scid.data, qc->scid.len, token_odcid))
		goto err;

	/* Initialize the idle timeout of the connection at the "max_idle_timeout"
	 * value from local transport parameters.
	 */
	qc->max_idle_timeout = qc->rx.params.max_idle_timeout;
	qc->wait_event.tasklet = tasklet_new();
	if (!qc->wait_event.tasklet) {
		TRACE_ERROR("tasklet_new() failed", QUIC_EV_CONN_TXPKT);
		goto err;
	}
	qc->wait_event.tasklet->process = quic_conn_io_cb;
	qc->wait_event.tasklet->context = qc;
	qc->wait_event.events = 0;
	qc->subs = NULL;

	if (qc_conn_alloc_ssl_ctx(qc) ||
	    !quic_conn_init_timer(qc) ||
	    !quic_conn_init_idle_timer_task(qc))
		goto err;

	ictx = &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL].tls_ctx;
	if (!qc_new_isecs(qc, ictx,qc->original_version, dcid->data, dcid->len, 1))
		goto err;

	/* Counters initialization */
	memset(&qc->cntrs, 0, sizeof qc->cntrs);

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

/* Update the proxy counters of <qc> QUIC connection from its counters */
static inline void quic_conn_prx_cntrs_update(struct quic_conn *qc)
{
	if (!qc->prx_counters)
		return;

	HA_ATOMIC_ADD(&qc->prx_counters->dropped_pkt, qc->cntrs.dropped_pkt);
	HA_ATOMIC_ADD(&qc->prx_counters->dropped_pkt_bufoverrun, qc->cntrs.dropped_pkt_bufoverrun);
	HA_ATOMIC_ADD(&qc->prx_counters->dropped_parsing, qc->cntrs.dropped_parsing);
	HA_ATOMIC_ADD(&qc->prx_counters->socket_full, qc->cntrs.socket_full);
	HA_ATOMIC_ADD(&qc->prx_counters->sendto_err, qc->cntrs.sendto_err);
	HA_ATOMIC_ADD(&qc->prx_counters->sendto_err_unknown, qc->cntrs.sendto_err_unknown);
	HA_ATOMIC_ADD(&qc->prx_counters->sent_pkt, qc->cntrs.sent_pkt);
	HA_ATOMIC_ADD(&qc->prx_counters->lost_pkt, qc->path->loss.nb_lost_pkt);
	HA_ATOMIC_ADD(&qc->prx_counters->conn_migration_done, qc->cntrs.conn_migration_done);
	/* Stream related counters */
	HA_ATOMIC_ADD(&qc->prx_counters->data_blocked, qc->cntrs.data_blocked);
	HA_ATOMIC_ADD(&qc->prx_counters->stream_data_blocked, qc->cntrs.stream_data_blocked);
	HA_ATOMIC_ADD(&qc->prx_counters->streams_blocked_bidi, qc->cntrs.streams_blocked_bidi);
	HA_ATOMIC_ADD(&qc->prx_counters->streams_blocked_uni, qc->cntrs.streams_blocked_uni);
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

	tasklet_free(qc->wait_event.tasklet);

	/* remove the connection from receiver cids trees */
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

	qc_detach_th_ctx_list(qc, 0);

	quic_conn_prx_cntrs_update(qc);
	pool_free(pool_head_quic_conn_rxbuf, qc->rx.buf.area);
	pool_free(pool_head_quic_conn, qc);
	qc = NULL;

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

	qc->timer_task = task_new_here();
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

/* Rearm the idle timer or the ack timer (if not already armde) for <qc> QUIC
 * connection. */
static void qc_idle_timer_do_rearm(struct quic_conn *qc, int arm_ack)
{
	unsigned int expire;

	if (stopping && qc->flags & (QUIC_FL_CONN_CLOSING|QUIC_FL_CONN_DRAINING)) {
		TRACE_PROTO("executing idle timer immediately on stopping", QUIC_EV_CONN_IDLE_TIMER, qc);
		qc->ack_expire = TICK_ETERNITY;
		task_wakeup(qc->idle_timer_task, TASK_WOKEN_MSG);
	}
	else {
		expire = QUIC_MAX(3 * quic_pto(qc), qc->max_idle_timeout);
		qc->idle_expire = tick_add(now_ms, MS_TO_TICKS(expire));
		if (arm_ack) {
			/* Arm the ack timer only if not already armed. */
			if (!tick_isset(qc->ack_expire)) {
				qc->ack_expire = tick_add(now_ms, MS_TO_TICKS(QUIC_ACK_DELAY));
				qc->idle_timer_task->expire = qc->ack_expire;
				task_queue(qc->idle_timer_task);
				TRACE_PROTO("ack timer armed", QUIC_EV_CONN_IDLE_TIMER, qc);
			}
		}
		else {
			qc->idle_timer_task->expire = tick_first(qc->ack_expire, qc->idle_expire);
			task_queue(qc->idle_timer_task);
			TRACE_PROTO("idle timer armed", QUIC_EV_CONN_IDLE_TIMER, qc);
		}
	}
}

/* Rearm the idle timer or ack timer for <qc> QUIC connection depending on <read>
 * and <arm_ack> booleans. The former is set to 1 when receiving a packet ,
 * and 0 when sending packet. <arm_ack> is set to 1 if this is the ack timer
 * which must be rearmed.
 */
static void qc_idle_timer_rearm(struct quic_conn *qc, int read, int arm_ack)
{
	TRACE_ENTER(QUIC_EV_CONN_IDLE_TIMER, qc);

	if (read) {
		qc->flags |= QUIC_FL_CONN_IDLE_TIMER_RESTARTED_AFTER_READ;
	}
	else {
		qc->flags &= ~QUIC_FL_CONN_IDLE_TIMER_RESTARTED_AFTER_READ;
	}
	qc_idle_timer_do_rearm(qc, arm_ack);

	TRACE_LEAVE(QUIC_EV_CONN_IDLE_TIMER, qc);
}

/* The task handling the idle timeout */
struct task *qc_idle_timer_task(struct task *t, void *ctx, unsigned int state)
{
	struct quic_conn *qc = ctx;
	struct quic_counters *prx_counters = qc->prx_counters;
	unsigned int qc_flags = qc->flags;

	TRACE_ENTER(QUIC_EV_CONN_IDLE_TIMER, qc);

	if ((state & TASK_WOKEN_ANY) == TASK_WOKEN_TIMER && !tick_is_expired(t->expire, now_ms))
		goto requeue;

	if (tick_is_expired(qc->ack_expire, now_ms)) {
		TRACE_PROTO("ack timer expired", QUIC_EV_CONN_IDLE_TIMER, qc);
		qc->ack_expire = TICK_ETERNITY;
		/* Note that ->idle_expire is always set. */
		t->expire = qc->idle_expire;
		/* Do not wakeup the I/O handler in DRAINING state or if the
		 * connection must be killed as soon as possible.
		 */
		if (!(qc->flags & (QUIC_FL_CONN_DRAINING|QUIC_FL_CONN_TO_KILL))) {
			qc->flags |= QUIC_FL_CONN_ACK_TIMER_FIRED;
			tasklet_wakeup(qc->wait_event.tasklet);
		}

		goto requeue;
	}

	TRACE_PROTO("idle timer task running", QUIC_EV_CONN_IDLE_TIMER, qc);
	/* Notify the MUX before settings QUIC_FL_CONN_EXP_TIMER or the MUX
	 * might free the quic-conn too early via quic_close().
	 */
	qc_notify_err(qc);

	/* If the MUX is still alive, keep the quic-conn. The MUX is
	 * responsible to call quic_close to release it.
	 */
	qc->flags |= QUIC_FL_CONN_EXP_TIMER;
	if (qc->mux_state != QC_MUX_READY) {
		quic_conn_release(qc);
		qc = NULL;
	}

	/* TODO if the quic-conn cannot be freed because of the MUX, we may at
	 * least clean some parts of it such as the tasklet.
	 */

	if (!(qc_flags & QUIC_FL_CONN_HALF_OPEN_CNT_DECREMENTED)) {
		qc_flags |= QUIC_FL_CONN_HALF_OPEN_CNT_DECREMENTED;
		TRACE_DEVEL("dec half open counter", QUIC_EV_CONN_IDLE_TIMER, qc);
		HA_ATOMIC_DEC(&prx_counters->half_open_conn);
	}

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_IDLE_TIMER, qc);
	return NULL;

 requeue:
	TRACE_LEAVE(QUIC_EV_CONN_IDLE_TIMER, qc);
	return t;
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
	qc->ack_expire = TICK_ETERNITY;
	qc_idle_timer_rearm(qc, 1, 0);
	task_queue(qc->idle_timer_task);

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);
	return ret;
}

/* Parse into <pkt> a long header located at <*pos> position, <end> begin a pointer to the end
 * past one byte of this buffer.
 */
static inline int quic_packet_read_long_header(unsigned char **pos, const unsigned char *end,
                                               struct quic_rx_packet *pkt)
{
	int ret = 0;
	unsigned char dcid_len, scid_len;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT);

	if (end == *pos) {
		TRACE_ERROR("buffer data consumed",  QUIC_EV_CONN_RXPKT);
		goto leave;
	}

	/* Destination Connection ID Length */
	dcid_len = *(*pos)++;
	/* We want to be sure we can read <dcid_len> bytes and one more for <scid_len> value */
	if (dcid_len > QUIC_CID_MAXLEN || end - *pos < dcid_len + 1) {
		TRACE_ERROR("too long DCID",  QUIC_EV_CONN_RXPKT);
		goto leave;
	}

	if (dcid_len) {
		/* Check that the length of this received DCID matches the CID lengths
		 * of our implementation for non Initials packets only.
		 */
		if (pkt->version && pkt->version->num &&
		    pkt->type != QUIC_PACKET_TYPE_INITIAL &&
		    pkt->type != QUIC_PACKET_TYPE_0RTT &&
		    dcid_len != QUIC_HAP_CID_LEN) {
			TRACE_ERROR("wrong DCID length", QUIC_EV_CONN_RXPKT);
			goto leave;
		}

		memcpy(pkt->dcid.data, *pos, dcid_len);
	}

	pkt->dcid.len = dcid_len;
	*pos += dcid_len;

	/* Source Connection ID Length */
	scid_len = *(*pos)++;
	if (scid_len > QUIC_CID_MAXLEN || end - *pos < scid_len) {
		TRACE_ERROR("too long SCID",  QUIC_EV_CONN_RXPKT);
		goto leave;
	}

	if (scid_len)
		memcpy(pkt->scid.data, *pos, scid_len);
	pkt->scid.len = scid_len;
	*pos += scid_len;

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
		struct quic_tls_ctx *tls_ctx = qc_select_tls_ctx(qc, qel, pkt);

		 /* Note that the following function enables us to unprotect the packet
		 * number and its length subsequently used to decrypt the entire
		 * packets.
		 */
		if (!qc_do_rm_hp(qc, pkt, tls_ctx,
		                 qel->pktns->rx.largest_pn, pn, beg)) {
			TRACE_PROTO("hp error", QUIC_EV_CONN_TRMHP, qc);
			goto out;
		}

		qc_handle_spin_bit(qc, pkt, qel);
		/* The AAD includes the packet number field. */
		pkt->aad_len = pkt->pn_offset + pkt->pnl;
		if (pkt->len - pkt->aad_len < QUIC_TLS_TAG_LEN) {
			TRACE_PROTO("Too short packet", QUIC_EV_CONN_TRMHP, qc);
			goto out;
		}

		TRACE_PROTO("RX hp removed", QUIC_EV_CONN_TRMHP, qc, pkt);
	}
	else {
		if (qel->tls_ctx.flags & QUIC_FL_TLS_SECRETS_DCD) {
			/* If the packet number space has been discarded, this packet
			 * will be not parsed.
			 */
			TRACE_PROTO("Discarded pktns", QUIC_EV_CONN_TRMHP, qc, pkt);
			goto out;
		}

		TRACE_PROTO("RX hp not removed", QUIC_EV_CONN_TRMHP, qc, pkt);
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
	TRACE_LEAVE(QUIC_EV_CONN_TRMHP, qc);
	return ret;
}

/* Return the QUIC version (quic_version struct) with <version> as version number
 * if supported or NULL if not.
 */
static inline const struct quic_version *qc_supported_version(uint32_t version)
{
	int i;

	if (unlikely(!version))
		return &quic_version_VN_reserved;

	for (i = 0; i < quic_versions_nb; i++)
		if (quic_versions[i].num == version)
			return &quic_versions[i];

	return NULL;
}

/* Parse a QUIC packet header starting at <pos> position without exceeding <end>.
 * Version and type are stored in <pkt> packet instance. Type is set to unknown
 * on two occasions : for unsupported version, in this case version field is
 * set to NULL; for Version Negotiation packet with version number set to 0.
 *
 * Returns 1 on success else 0.
 */
int qc_parse_hd_form(struct quic_rx_packet *pkt,
                     unsigned char **pos, const unsigned char *end)
{
	uint32_t version;
	int ret = 0;
	const unsigned char byte0 = **pos;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT);
	pkt->version = NULL;
	pkt->type = QUIC_PACKET_TYPE_UNKNOWN;

	(*pos)++;
	if (byte0 & QUIC_PACKET_LONG_HEADER_BIT) {
		unsigned char type =
			(byte0 >> QUIC_PACKET_TYPE_SHIFT) & QUIC_PACKET_TYPE_BITMASK;

		/* Version */
		if (!quic_read_uint32(&version, (const unsigned char **)pos, end)) {
			TRACE_ERROR("could not read the packet version", QUIC_EV_CONN_RXPKT);
			goto out;
		}

		pkt->version = qc_supported_version(version);
		if (version && pkt->version) {
			if (version != QUIC_PROTOCOL_VERSION_2) {
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
	}
	else {
		if (byte0 & QUIC_PACKET_SPIN_BIT)
			pkt->flags |= QUIC_FL_RX_PACKET_SPIN_BIT;
		pkt->type = QUIC_PACKET_TYPE_SHORT;
	}

	ret = 1;
 out:
	TRACE_LEAVE(QUIC_EV_CONN_RXPKT);
	return ret;
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
	if (!quic_stateless_reset_token_cpy(pkt + rndlen, QUIC_STATELESS_RESET_TOKEN_LEN,
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
 * <token> with <len> as length. <odcid> is the original destination connection
 * ID and <dcid> is our side destination connection ID (or client source
 * connection ID).
 * Returns the length of the encoded token or 0 on error.
 */
static int quic_generate_retry_token(unsigned char *token, size_t len,
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

	/* The token is made of the token format byte, the ODCID prefixed by its one byte
	 * length, the creation timestamp, an AEAD TAG, and finally
	 * the random bytes used to derive the secret to encrypt the token.
	 */
	if (1 + odcid->len + 1 + sizeof(timestamp) + QUIC_TLS_TAG_LEN + QUIC_RETRY_TOKEN_SALTLEN > len)
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
	p = token;
	*p++ = QUIC_TOKEN_FMT_RETRY,
	*p++ = odcid->len;
	memcpy(p, odcid->data, odcid->len);
	p += odcid->len;
	write_u32(p, htonl(timestamp));
	p += sizeof timestamp;

	/* Do not encrypt the QUIC_TOKEN_FMT_RETRY byte */
	if (!quic_tls_encrypt(token + 1, p - token - 1, aad, aadlen, ctx, aead, key, iv)) {
		TRACE_ERROR("quic_tls_encrypt() failed", QUIC_EV_CONN_TXPKT);
		goto err;
	}

	p += QUIC_TLS_TAG_LEN;
	memcpy(p, salt, sizeof salt);
	p += sizeof salt;
	EVP_CIPHER_CTX_free(ctx);

	ret = p - token;
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

	/* The token is made of the token format byte, the ODCID prefixed by its one byte
	 * length, the creation timestamp, an AEAD TAG, and finally
	 * the random bytes used to derive the secret to encrypt the token.
	 */
	if (tokenlen < 2 + QUIC_ODCID_MINLEN + sizeof(uint32_t) + QUIC_TLS_TAG_LEN + QUIC_RETRY_TOKEN_SALTLEN ||
	    tokenlen > 2 + QUIC_CID_MAXLEN + sizeof(uint32_t) + QUIC_TLS_TAG_LEN + QUIC_RETRY_TOKEN_SALTLEN) {
		TRACE_ERROR("invalid token length", QUIC_EV_CONN_LPKT, qc);
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

	/* The token is prefixed by a one-byte length format which is not ciphered. */
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

/* Retrieve a quic_conn instance from the <pkt> DCID field. If the packet is an
 * INITIAL or 0RTT type, we may have to use client address <saddr> if an ODCID
 * is used.
 *
 * Returns the instance or NULL if not found.
 */
static struct quic_conn *retrieve_qc_conn_from_cid(struct quic_rx_packet *pkt,
                                                   struct listener *l,
                                                   struct sockaddr_storage *saddr,
                                                   int *new_tid)
{
	struct quic_conn *qc = NULL;
	struct ebmb_node *node;
	struct quic_connection_id *conn_id;
	struct quic_cid_tree *tree;
	uint conn_id_tid;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT);
	*new_tid = -1;

	/* First look into DCID tree. */
	tree = &quic_cid_trees[_quic_cid_tree_idx(pkt->dcid.data)];
	HA_RWLOCK_RDLOCK(QC_CID_LOCK, &tree->lock);
	node = ebmb_lookup(&tree->root, pkt->dcid.data, pkt->dcid.len);

	/* If not found on an Initial/0-RTT packet, it could be because an
	 * ODCID is reused by the client. Calculate the derived CID value to
	 * retrieve it from the DCID tree.
	 */
	if (!node && (pkt->type == QUIC_PACKET_TYPE_INITIAL ||
	     pkt->type == QUIC_PACKET_TYPE_0RTT)) {
		const struct quic_cid derive_cid = quic_derive_cid(&pkt->dcid, saddr);

		HA_RWLOCK_RDUNLOCK(QC_CID_LOCK, &tree->lock);

		tree = &quic_cid_trees[quic_cid_tree_idx(&derive_cid)];
		HA_RWLOCK_RDLOCK(QC_CID_LOCK, &tree->lock);
		node = ebmb_lookup(&tree->root, derive_cid.data, derive_cid.len);
	}

	if (!node)
		goto end;

	conn_id = ebmb_entry(node, struct quic_connection_id, node);
	conn_id_tid = HA_ATOMIC_LOAD(&conn_id->tid);
	if (conn_id_tid != tid) {
		*new_tid = conn_id_tid;
		goto end;
	}
	qc = conn_id->qc;

 end:
	HA_RWLOCK_RDUNLOCK(QC_CID_LOCK, &tree->lock);
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
			goto leave;

		pool_gc(NULL);
		goto retry;
	}

	if (!SSL_set_quic_method(*ssl, &ha_quic_method) ||
	    !SSL_set_ex_data(*ssl, ssl_qc_app_data_index, qc)) {
		SSL_free(*ssl);
		*ssl = NULL;
		if (!retry--)
			goto leave;

		pool_gc(NULL);
		goto retry;
	}

	ret = 0;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);
	return ret;
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

/* Check that all the bytes between <pos> included and <end> address
 * excluded are null. This is the responsibility of the caller to
 * check that there is at least one byte between <pos> end <end>.
 * Return 1 if this all the bytes are null, 0 if not.
 */
static inline int quic_padding_check(const unsigned char *pos,
                                     const unsigned char *end)
{
	while (pos < end && !*pos)
		pos++;

	return pos == end;
}

/* Find the associated connection to the packet <pkt> or create a new one if
 * this is an Initial packet. <dgram> is the datagram containing the packet and
 * <l> is the listener instance on which it was received.
 *
 * By default, <new_tid> is set to -1. However, if thread affinity has been
 * chanbed, it will be set to its new thread ID.
 *
 * Returns the quic-conn instance or NULL if not found or thread affinity
 * changed.
 */
static struct quic_conn *quic_rx_pkt_retrieve_conn(struct quic_rx_packet *pkt,
                                                   struct quic_dgram *dgram,
                                                   struct listener *l,
                                                   int *new_tid)
{
	struct quic_cid token_odcid = { .len = 0 };
	struct quic_conn *qc = NULL;
	struct proxy *prx;
	struct quic_counters *prx_counters;

	TRACE_ENTER(QUIC_EV_CONN_LPKT);

	*new_tid = -1;

	prx = l->bind_conf->frontend;
	prx_counters = EXTRA_COUNTERS_GET(prx->extra_counters_fe, &quic_stats_module);

	qc = retrieve_qc_conn_from_cid(pkt, l, &dgram->saddr, new_tid);

	/* If connection already created or rebinded on another thread. */
	if (!qc && *new_tid != -1 && tid != *new_tid)
		goto out;

	if (pkt->type == QUIC_PACKET_TYPE_INITIAL) {
		BUG_ON(!pkt->version); /* This must not happen. */

		if (global.cluster_secret && pkt->token_len) {
			if (!quic_retry_token_check(pkt, dgram, l, qc, &token_odcid))
				goto err;
		}

		if (!qc) {
			struct quic_cid_tree *tree;
			struct ebmb_node *node;
			struct quic_connection_id *conn_id;
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

			/* Generate the first connection CID. This is derived from the client
			 * ODCID and address. This allows to retrieve the connection from the
			 * ODCID without storing it in the CID tree. This is an interesting
			 * optimization as the client is expected to stop using its ODCID in
			 * favor of our generated value.
			 */
			conn_id = new_quic_cid(NULL, NULL, &pkt->dcid, &pkt->saddr);
			if (!conn_id)
				goto err;

			tree = &quic_cid_trees[quic_cid_tree_idx(&conn_id->cid)];
			HA_RWLOCK_WRLOCK(QC_CID_LOCK, &tree->lock);
			node = ebmb_insert(&tree->root, &conn_id->node, conn_id->cid.len);
			if (node != &conn_id->node) {
				pool_free(pool_head_quic_connection_id, conn_id);

				conn_id = ebmb_entry(node, struct quic_connection_id, node);
				*new_tid = HA_ATOMIC_LOAD(&conn_id->tid);
			}
			HA_RWLOCK_WRUNLOCK(QC_CID_LOCK, &tree->lock);

			if (*new_tid != -1)
				goto out;

			qc = qc_new_conn(pkt->version, ipv4, &pkt->dcid, &pkt->scid, &token_odcid,
			                 conn_id, &dgram->daddr, &pkt->saddr, 1,
			                 !!pkt->token_len, l);
			if (qc == NULL)
				goto err;

			HA_ATOMIC_INC(&prx_counters->half_open_conn);
		}
	}
	else if (!qc) {
		TRACE_PROTO("RX non Initial pkt without connection", QUIC_EV_CONN_LPKT, NULL, NULL, NULL, pkt->version);
		if (global.cluster_secret && !send_stateless_reset(l, &dgram->saddr, pkt))
			TRACE_ERROR("stateless reset not sent", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc);
	return qc;

 err:
	if (qc)
		qc->cntrs.dropped_pkt++;
	else
		HA_ATOMIC_INC(&prx_counters->dropped_pkt);
	TRACE_LEAVE(QUIC_EV_CONN_LPKT);
	return NULL;
}

/* Parse a QUIC packet starting at <pos>. Data won't be read after <end> even
 * if the packet is incomplete. This function will populate fields of <pkt>
 * instance, most notably its length. <dgram> is the UDP datagram which
 * contains the parsed packet. <l> is the listener instance on which it was
 * received.
 *
 * Returns 0 on success else non-zero. Packet length is guaranteed to be set to
 * the real packet value or to cover all data between <pos> and <end> : this is
 * useful to reject a whole datagram.
 */
static int quic_rx_pkt_parse(struct quic_rx_packet *pkt,
                             unsigned char *pos, const unsigned char *end,
                             struct quic_dgram *dgram, struct listener *l)
{
	const unsigned char *beg = pos;
	struct proxy *prx;
	struct quic_counters *prx_counters;

	TRACE_ENTER(QUIC_EV_CONN_LPKT);

	prx = l->bind_conf->frontend;
	prx_counters = EXTRA_COUNTERS_GET(prx->extra_counters_fe, &quic_stats_module);
	/* This ist only to please to traces and distinguish the
	 * packet with parsed packet number from others.
	 */
	pkt->pn_node.key = (uint64_t)-1;
	if (end <= pos) {
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
		goto drop;
	}

	/* Fixed bit */
	if (!(*pos & QUIC_PACKET_FIXED_BIT)) {
		if (!(pkt->flags & QUIC_FL_RX_PACKET_DGRAM_FIRST) &&
		    quic_padding_check(pos, end)) {
			/* Some browsers may pad the remaining datagram space with null bytes.
			 * That is what we called add padding out of QUIC packets. Such
			 * datagrams must be considered as valid. But we can only consume
			 * the remaining space.
			 */
			pkt->len = end - pos;
			goto drop_silent;
		}

		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
		goto drop;
	}

	/* Header form */
	if (!qc_parse_hd_form(pkt, &pos, end)) {
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
		goto drop;
	}

	if (pkt->type != QUIC_PACKET_TYPE_SHORT) {
		uint64_t len;
		TRACE_PROTO("long header packet received", QUIC_EV_CONN_LPKT);

		if (!quic_packet_read_long_header(&pos, end, pkt)) {
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
		if (pkt->type == QUIC_PACKET_TYPE_RETRY ||
		    (pkt->version && !pkt->version->num)) {
			TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
			goto drop;
		}

		/* RFC9000 6. Version Negotiation */
		if (!pkt->version) {
			 /* unsupported version, send Negotiation packet */
			if (send_version_negotiation(l->rx.fd, &dgram->saddr, pkt)) {
				TRACE_ERROR("VN packet not sent", QUIC_EV_CONN_LPKT);
				goto drop_silent;
			}

			TRACE_PROTO("VN packet sent", QUIC_EV_CONN_LPKT);
			goto drop_silent;
		}

		/* For Initial packets, and for servers (QUIC clients connections),
		 * there is no Initial connection IDs storage.
		 */
		if (pkt->type == QUIC_PACKET_TYPE_INITIAL) {
			uint64_t token_len;

			if (!quic_dec_int(&token_len, (const unsigned char **)&pos, end) ||
				end - pos < token_len) {
				TRACE_PROTO("Packet dropped",
				            QUIC_EV_CONN_LPKT, NULL, NULL, NULL, pkt->version);
				goto drop;
			}

			/* TODO Retry should be automatically activated if
			 * suspect network usage is detected.
			 */
			if (global.cluster_secret && !token_len) {
				if (l->bind_conf->options & BC_O_QUIC_FORCE_RETRY) {
					TRACE_PROTO("Initial without token, sending retry",
					            QUIC_EV_CONN_LPKT, NULL, NULL, NULL, pkt->version);
					if (send_retry(l->rx.fd, &dgram->saddr, pkt, pkt->version)) {
						TRACE_PROTO("Error during Retry generation",
						            QUIC_EV_CONN_LPKT, NULL, NULL, NULL, pkt->version);
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
				            NULL, NULL, NULL, pkt->version);
				goto drop;
			}

			pkt->token = pos;
			pkt->token_len = token_len;
			pos += pkt->token_len;
		}
		else if (pkt->type != QUIC_PACKET_TYPE_0RTT) {
			if (pkt->dcid.len != QUIC_HAP_CID_LEN) {
				TRACE_PROTO("Packet dropped",
				            QUIC_EV_CONN_LPKT, NULL, NULL, NULL, pkt->version);
				goto drop;
			}
		}

		if (!quic_dec_int(&len, (const unsigned char **)&pos, end) ||
			end - pos < len) {
			TRACE_PROTO("Packet dropped",
			            QUIC_EV_CONN_LPKT, NULL, NULL, NULL, pkt->version);
			goto drop;
		}

		/* Packet Number is stored here. Packet Length totalizes the
		 * rest of the content.
		 */
		pkt->pn_offset = pos - beg;
		pkt->len = pkt->pn_offset + len;

		/* RFC 9000. Initial Datagram Size
		 *
		 * A server MUST discard an Initial packet that is carried in a UDP datagram
		 * with a payload that is smaller than the smallest allowed maximum datagram
		 * size of 1200 bytes.
		 */
		if (pkt->type == QUIC_PACKET_TYPE_INITIAL &&
		    dgram->len < QUIC_INITIAL_PACKET_MINLEN) {
			TRACE_PROTO("RX too short datagram with an Initial packet", QUIC_EV_CONN_LPKT);
			HA_ATOMIC_INC(&prx_counters->too_short_initial_dgram);
			goto drop;
		}

		/* Interrupt parsing after packet length retrieval : this
		 * ensures that only the packet is dropped but not the whole
		 * datagram.
		 */
		if (pkt->type == QUIC_PACKET_TYPE_0RTT && !l->bind_conf->ssl_conf.early_data) {
			TRACE_PROTO("RX 0-RTT packet not supported", QUIC_EV_CONN_LPKT);
			goto drop;
		}
	}
	else {
		TRACE_PROTO("RX short header packet", QUIC_EV_CONN_LPKT);
		if (end - pos < QUIC_HAP_CID_LEN) {
			TRACE_PROTO("RX pkt dropped", QUIC_EV_CONN_LPKT);
			goto drop;
		}

		memcpy(pkt->dcid.data, pos, QUIC_HAP_CID_LEN);
		pkt->dcid.len = QUIC_HAP_CID_LEN;

		/* When multiple QUIC packets are coalesced on the same UDP datagram,
		 * they must have the same DCID.
		 */
		if (!(pkt->flags & QUIC_FL_RX_PACKET_DGRAM_FIRST) &&
		    (pkt->dcid.len != dgram->dcid_len ||
		     memcmp(dgram->dcid, pkt->dcid.data, pkt->dcid.len))) {
			TRACE_PROTO("RX pkt dropped", QUIC_EV_CONN_LPKT);
			goto drop;
		}

		pos += QUIC_HAP_CID_LEN;

		pkt->pn_offset = pos - beg;
		/* A short packet is the last one of a UDP datagram. */
		pkt->len = end - beg;
	}

	TRACE_PROTO("RX pkt parsed", QUIC_EV_CONN_LPKT, NULL, pkt, NULL, pkt->version);
	TRACE_LEAVE(QUIC_EV_CONN_LPKT);
	return 0;

 drop:
	HA_ATOMIC_INC(&prx_counters->dropped_pkt);
 drop_silent:
	if (!pkt->len)
		pkt->len = end - beg;
	TRACE_PROTO("RX pkt parsing failed", QUIC_EV_CONN_LPKT, NULL, pkt, NULL, pkt->version);
	TRACE_LEAVE(QUIC_EV_CONN_LPKT);
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
	qc->cntrs.conn_migration_done++;

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

	TRACE_ENTER(QUIC_EV_CONN_LPKT, qc);
	TRACE_PROTO("RX pkt", QUIC_EV_CONN_LPKT, qc, pkt, NULL, qv);

	if (pkt->flags & QUIC_FL_RX_PACKET_DGRAM_FIRST &&
	    qc->flags & QUIC_FL_CONN_ANTI_AMPLIFICATION_REACHED) {
		TRACE_PROTO("PTO timer must be armed after anti-amplication was reached",
					QUIC_EV_CONN_LPKT, qc, NULL, NULL, qv);
		TRACE_DEVEL("needs to wakeup the timer task after the amplification limit was reached",
		            QUIC_EV_CONN_LPKT, qc);
		/* Reset the anti-amplification bit. It will be set again
		 * when sending the next packet if reached again.
		 */
		qc->flags &= ~QUIC_FL_CONN_ANTI_AMPLIFICATION_REACHED;
		qc_set_timer(qc);
		if (qc->timer_task && tick_isset(qc->timer) && tick_is_lt(qc->timer, now_ms))
			task_wakeup(qc->timer_task, TASK_WOKEN_MSG);
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
			qc->cntrs.dropped_pkt_bufoverrun++;
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
			qc->cntrs.dropped_pkt_bufoverrun++;
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
	TRACE_PROTO("RX pkt", QUIC_EV_CONN_LPKT, qc ? qc : NULL, pkt, NULL, qv);
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc ? qc : NULL);
	return;

 drop:
	qc->cntrs.dropped_pkt++;
	TRACE_PROTO("packet drop", QUIC_EV_CONN_LPKT, qc, pkt, NULL, qv);
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc);
}

/* This function builds into a buffer at <pos> position a QUIC long packet header,
 * <end> being one byte past the end of this buffer.
 * Return 1 if enough room to build this header, 0 if not.
 */
static int quic_build_packet_long_header(unsigned char **pos, const unsigned char *end,
                                         int type, size_t pn_len,
                                         struct quic_conn *qc, const struct quic_version *ver)
{
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_LPKT, qc);

	if (end - *pos < sizeof ver->num + qc->dcid.len + qc->scid.len + 3) {
		TRACE_DEVEL("not enough room", QUIC_EV_CONN_LPKT, qc);
		goto leave;
	}

	type = quic_pkt_type(type, ver->num);
	/* #0 byte flags */
	*(*pos)++ = QUIC_PACKET_FIXED_BIT | QUIC_PACKET_LONG_HEADER_BIT |
		(type << QUIC_PACKET_TYPE_SHIFT) | (pn_len - 1);
	/* Version */
	quic_write_uint32(pos, end, ver->num);
	*(*pos)++ = qc->dcid.len;
	/* Destination connection ID */
	if (qc->dcid.len) {
		memcpy(*pos, qc->dcid.data, qc->dcid.len);
		*pos += qc->dcid.len;
	}
	/* Source connection ID */
	*(*pos)++ = qc->scid.len;
	if (qc->scid.len) {
		memcpy(*pos, qc->scid.data, qc->scid.len);
		*pos += qc->scid.len;
	}

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc);
	return ret;
}

/* This function builds into a buffer at <pos> position a QUIC short packet header,
 * <end> being one byte past the end of this buffer.
 * Return 1 if enough room to build this header, 0 if not.
 */
static int quic_build_packet_short_header(unsigned char **pos, const unsigned char *end,
                                          size_t pn_len, struct quic_conn *qc,
                                          unsigned char tls_flags)
{
	int ret = 0;
	unsigned char spin_bit =
		(qc->flags & QUIC_FL_CONN_SPIN_BIT) ? QUIC_PACKET_SPIN_BIT : 0;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	if (end - *pos < 1 + qc->dcid.len) {
		TRACE_DEVEL("not enough room", QUIC_EV_CONN_LPKT, qc);
		goto leave;
	}

	/* #0 byte flags */
	*(*pos)++ = QUIC_PACKET_FIXED_BIT | spin_bit |
		((tls_flags & QUIC_FL_TLS_KP_BIT_SET) ? QUIC_PACKET_KEY_PHASE_BIT : 0) | (pn_len - 1);
	/* Destination connection ID */
	if (qc->dcid.len) {
		memcpy(*pos, qc->dcid.data, qc->dcid.len);
		*pos += qc->dcid.len;
	}

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return ret;
}

/* Apply QUIC header protection to the packet with <pos> as first byte address,
 * <pn> as address of the Packet number field, <pnlen> being this field length
 * with <aead> as AEAD cipher and <key> as secret key.
 *
 * TODO no error is expected as encryption is done in place but encryption
 * manual is unclear. <fail> will be set to true if an error is detected.
 */
void quic_apply_header_protection(struct quic_conn *qc, unsigned char *pos,
                                        unsigned char *pn, size_t pnlen,
                                        struct quic_tls_ctx *tls_ctx, int *fail)

{
	int i;
	/* We need an IV of at least 5 bytes: one byte for bytes #0
	 * and at most 4 bytes for the packet number
	 */
	unsigned char mask[5] = {0};
	EVP_CIPHER_CTX *aes_ctx = tls_ctx->tx.hp_ctx;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	*fail = 0;

	if (!quic_tls_aes_encrypt(mask, pn + QUIC_PACKET_PN_MAXLEN, sizeof mask, aes_ctx)) {
		TRACE_ERROR("could not apply header protection", QUIC_EV_CONN_TXPKT, qc);
		*fail = 1;
		goto out;
	}

	*pos ^= mask[0] & (*pos & QUIC_PACKET_LONG_HEADER_BIT ? 0xf : 0x1f);
	for (i = 0; i < pnlen; i++)
		pn[i] ^= mask[i + 1];

 out:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
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

	TRACE_PROTO("TX frms build (headlen)",
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
			if (cf->stream.dup) {
				struct eb64_node *node = NULL;
				struct qc_stream_desc *stream_desc = NULL;
				struct qf_stream *strm_frm = &cf->stream;

				/* As this frame has been already lost, ensure the stream is always
				 * available or the range of this frame is not consumed before
				 * resending it.
				 */
				node = eb64_lookup(&qc->streams_by_id, strm_frm->id);
				if (!node) {
					TRACE_DEVEL("released stream", QUIC_EV_CONN_PRSAFRM, qc, cf);
					qc_frm_free(&cf);
					continue;
				}

				stream_desc = eb64_entry(node, struct qc_stream_desc, by_id);
				if (strm_frm->offset.key + strm_frm->len <= stream_desc->ack_offset) {
					TRACE_DEVEL("ignored frame frame in already acked range",
					            QUIC_EV_CONN_PRSAFRM, qc, cf);
					qc_frm_free(&cf);
					continue;
				}
				else if (strm_frm->offset.key < stream_desc->ack_offset) {
					uint64_t diff = stream_desc->ack_offset - strm_frm->offset.key;

					qc_stream_frm_mv_fwd(cf, diff);
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
				new_cf->stream.dup = cf->stream.dup;
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
                           int must_ack, int padding, int cc, int probe,
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
	int ret = 0;

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
	if (pkt->type == QUIC_PACKET_TYPE_INITIAL) {
		if (end <= pos)
			goto no_room;

		*pos++ = 0;
	}

	head_len = pos - beg;
	/* Build an ACK frame if required. */
	ack_frm_len = 0;
	/* Do not ack and probe at the same time. */
	if ((must_ack || (qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED)) && !qel->pktns->tx.pto_probe) {
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
		if (end - pos <= 1 + *pn_len)
			goto no_room;

		ack_frm_len = qc_frm_len(&ack_frm);
		if (ack_frm_len > end - 1 - *pn_len - pos)
			goto no_room;
	}

	/* Length field value without the ack-eliciting frames. */
	len = ack_frm_len + *pn_len;
	len_frms = 0;
	if (!cc && !LIST_ISEMPTY(frms)) {
		ssize_t room = end - pos;

		TRACE_PROTO("Avail. ack eliciting frames", QUIC_EV_CONN_FRMLIST, qc, frms);
		/* Initialize the length of the frames built below to <len>.
		 * If any frame could be successfully built by qc_build_frms(),
		 * we will have len_frms > len.
		 */
		len_frms = len;
		if (!qc_build_frms(&frm_list, frms,
		                   end - pos, &len_frms, pos - beg, qel, qc)) {
			TRACE_PROTO("Not enough room", QUIC_EV_CONN_TXPKT,
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
	/* Note that <padding> is true only when building an Handshake packet
	 * coalesced to an Initial packet.
	 */
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
			dglen += 1;
			/* Note that only we are in the case where this Initial packet
			 * is not coalesced to an Handshake packet. We must directly
			 * pad the datragram.
			 */
			if (pkt->type == QUIC_PACKET_TYPE_INITIAL) {
				if (dglen < QUIC_INITIAL_PACKET_MINLEN) {
					padding_len = QUIC_INITIAL_PACKET_MINLEN - dglen;
					padding_len -= quic_int_getsize(len + padding_len) - len_sz;
					len += padding_len;
				}
			}
			else {
				/* Note that +1 is for the PING frame */
				if (*pn_len + 1 < QUIC_PACKET_PN_MAXLEN)
					len += padding_len = QUIC_PACKET_PN_MAXLEN - *pn_len - 1;
			}
		}
		else {
			/* If there is no frame at all to follow, add at least a PADDING frame. */
			if (!ack_frm_len && !cc)
				len += padding_len = QUIC_PACKET_PN_MAXLEN - *pn_len;
		}
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
				TRACE_PROTO("Not enough room", QUIC_EV_CONN_TXPKT,
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
		TRACE_PROTO("limited by congestion control", QUIC_EV_CONN_TXPKT, qc);
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
	TRACE_PROTO("Packet ack-eliciting frames", QUIC_EV_CONN_TXPKT, qc, pkt);
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return ret;

 no_room:
	/* Replace the pre-built frames which could not be add to this packet */
	LIST_SPLICE(frms, &frm_list);
	TRACE_PROTO("Remaining ack-eliciting frames", QUIC_EV_CONN_FRMLIST, qc, frms);
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

/* Build a packet into a buffer at <pos> position, <end> pointing to one byte past
 * the end of this buffer, with <pkt_type> as packet type for <qc> QUIC connection
 * at <qel> encryption level with <frms> list of prebuilt frames.
 *
 * Return -2 if the packet could not be allocated or encrypted for any reason,
 * -1 if there was not enough room to build a packet.
 * XXX NOTE XXX
 * If you provide provide qc_build_pkt() with a big enough buffer to build a packet as big as
 * possible (to fill an MTU), the unique reason why this function may fail is the congestion
 * control window limitation.
 */
static struct quic_tx_packet *qc_build_pkt(unsigned char **pos,
                                           const unsigned char *end,
                                           struct quic_enc_level *qel,
                                           struct quic_tls_ctx *tls_ctx, struct list *frms,
                                           struct quic_conn *qc, const struct quic_version *ver,
                                           size_t dglen, int pkt_type, int must_ack,
                                           int padding, int probe, int cc, int *err)
{
	struct quic_tx_packet *ret_pkt = NULL;
	/* The pointer to the packet number field. */
	unsigned char *buf_pn;
	unsigned char *first_byte, *last_byte, *payload;
	int64_t pn;
	size_t pn_len, payload_len, aad_len;
	struct quic_tx_packet *pkt;
	int encrypt_failure = 0;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);
	TRACE_PROTO("TX pkt build", QUIC_EV_CONN_TXPKT, qc, NULL, qel);
	*err = 0;
	pkt = pool_alloc(pool_head_quic_tx_packet);
	if (!pkt) {
		TRACE_DEVEL("Not enough memory for a new packet", QUIC_EV_CONN_TXPKT, qc);
		*err = -2;
		goto err;
	}

	quic_tx_packet_init(pkt, pkt_type);
	first_byte = *pos;
	pn_len = 0;
	buf_pn = NULL;

	pn = qel->pktns->tx.next_pn + 1;
	if (!qc_do_build_pkt(*pos, end, dglen, pkt, pn, &pn_len, &buf_pn,
	                     must_ack, padding, cc, probe, qel, qc, ver, frms)) {
		// trace already emitted by function above
		*err = -1;
		goto err;
	}

	last_byte = first_byte + pkt->len;
	payload = buf_pn + pn_len;
	payload_len = last_byte - payload;
	aad_len = payload - first_byte;

	quic_packet_encrypt(payload, payload_len, first_byte, aad_len, pn, tls_ctx, qc, &encrypt_failure);
	if (encrypt_failure) {
		/* TODO Unrecoverable failure, unencrypted data should be returned to the caller. */
		WARN_ON("quic_packet_encrypt failure");
		*err = -2;
		goto err;
	}

	last_byte += QUIC_TLS_TAG_LEN;
	pkt->len += QUIC_TLS_TAG_LEN;
	quic_apply_header_protection(qc, first_byte, buf_pn, pn_len, tls_ctx, &encrypt_failure);
	if (encrypt_failure) {
		/* TODO Unrecoverable failure, unencrypted data should be returned to the caller. */
		WARN_ON("quic_apply_header_protection failure");
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
	*pos = last_byte;
	/* Attach the built packet to its tree. */
	pkt->pn_node.key = pn;
	/* Set the packet in fligth length for in flight packet only. */
	if (pkt->flags & QUIC_FL_TX_PACKET_IN_FLIGHT) {
		pkt->in_flight_len = pkt->len;
		qc->path->prep_in_flight += pkt->len;
	}
	/* Always reset this flag */
	qc->flags &= ~QUIC_FL_CONN_IMMEDIATE_CLOSE;
	if (pkt->flags & QUIC_FL_TX_PACKET_ACK) {
		qel->pktns->flags &= ~QUIC_FL_PKTNS_ACK_REQUIRED;
		qel->pktns->rx.nb_aepkts_since_last_ack = 0;
		qc->flags &= ~QUIC_FL_CONN_ACK_TIMER_FIRED;
		if (tick_isset(qc->ack_expire)) {
		    qc->ack_expire = TICK_ETERNITY;
		    qc->idle_timer_task->expire = qc->idle_expire;
		    task_queue(qc->idle_timer_task);
		    TRACE_PROTO("ack timer cancelled", QUIC_EV_CONN_IDLE_TIMER, qc);
		}
	}

	pkt->pktns = qel->pktns;

	ret_pkt = pkt;
 leave:
	TRACE_PROTO("TX pkt built", QUIC_EV_CONN_TXPKT, qc, ret_pkt);
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
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
			int new_tid = -1;

			qc = from_qc ? from_qc : quic_rx_pkt_retrieve_conn(pkt, dgram, li, &new_tid);
			/* qc is NULL if receiving a non Initial packet for an
			 * unknown connection or on connection affinity rebind.
			 */
			if (!qc) {
				if (new_tid >= 0) {
					MT_LIST_APPEND(&quic_dghdlrs[new_tid].dgrams,
					               &dgram->handler_list);
					tasklet_wakeup(quic_dghdlrs[new_tid].task);
					goto out;
				}

				/* Skip the entire datagram. */
				pkt->len = end - pos;
				goto next;
			}

			dgram->qc = qc;
		}

		if (qc->flags & QUIC_FL_CONN_AFFINITY_CHANGED)
			qc_finalize_affinity_rebind(qc);

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

 out:
	TRACE_LEAVE(QUIC_EV_CONN_LPKT);
	return 0;

 err:
	/* Mark this datagram as consumed as maybe at least some packets were parsed. */
	HA_ATOMIC_STORE(&dgram->buf, NULL);
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
	const uchar idx = _quic_cid_tree_idx(dcid);
	struct quic_connection_id *conn_id;
	struct ebmb_node *node = NULL;
	struct quic_cid_tree *tree = &quic_cid_trees[idx];

	/* Test against our default CID or client ODCID. */
	if ((qc->scid.len == dcid_len &&
	     memcmp(qc->scid.data, dcid, dcid_len) == 0) ||
	    (qc->odcid.len == dcid_len &&
	     memcmp(qc->odcid.data, dcid, dcid_len) == 0)) {
		return 1;
	}

	/* Test against our other CIDs. This can happen if the client has
	 * decided to switch to a new one.
	 *
	 * TODO to avoid locking, loop through qc.cids as an alternative.
	 *
	 * TODO set it to our default CID to avoid this operation next time.
	 */
	HA_RWLOCK_RDLOCK(QC_CID_LOCK, &tree->lock);
	node = ebmb_lookup(&tree->root, dcid, dcid_len);
	HA_RWLOCK_RDUNLOCK(QC_CID_LOCK, &tree->lock);

	if (node) {
		conn_id = ebmb_entry(node, struct quic_connection_id, node);
		if (qc == conn_id->qc)
			return 1;
	}

	return 0;
}

/* Retrieve the DCID from a QUIC datagram or packet at <pos> position,
 * <end> being at one byte past the end of this datagram.
 * Returns 1 if succeeded, 0 if not.
 */
int quic_get_dgram_dcid(unsigned char *pos, const unsigned char *end,
                        unsigned char **dcid, size_t *dcid_len)
{
	int ret = 0, long_header;
	size_t minlen, skip;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT);

	if (!(*pos & QUIC_PACKET_FIXED_BIT)) {
		TRACE_PROTO("fixed bit not set", QUIC_EV_CONN_RXPKT);
		goto err;
	}

	long_header = *pos & QUIC_PACKET_LONG_HEADER_BIT;
	minlen = long_header ? QUIC_LONG_PACKET_MINLEN :
		QUIC_SHORT_PACKET_MINLEN + QUIC_HAP_CID_LEN + QUIC_TLS_TAG_LEN;
	skip = long_header ? QUIC_LONG_PACKET_DCID_OFF : QUIC_SHORT_PACKET_DCID_OFF;
	if (end - pos < minlen)
		goto err;

	pos += skip;
	*dcid_len = long_header ? *pos++ : QUIC_HAP_CID_LEN;
	if (*dcid_len > QUIC_CID_MAXLEN || end - pos <= *dcid_len)
		goto err;

	*dcid = pos;

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_RXPKT);
	return ret;

 err:
	TRACE_PROTO("wrong datagram", QUIC_EV_CONN_RXPKT);
	goto leave;
}

/* Notify upper layer of a fatal error which forces to close the connection. */
void qc_notify_err(struct quic_conn *qc)
{
	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);

	if (qc->mux_state == QC_MUX_READY) {
		TRACE_STATE("error notified to mux", QUIC_EV_CONN_CLOSE, qc);

		/* Mark socket as closed. */
		qc->conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;

		/* TODO quic-conn layer must stay active until MUX is released.
		 * Thus, we have to wake up directly to ensure upper stream
		 * layer will be notified of the error. If a proper separation
		 * is made between MUX and quic-conn layer, wake up could be
		 * conducted only with qc.subs.
		 */
		tasklet_wakeup(qc->qcc->wait_event.tasklet);
	}

	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);
}

/* Wake-up upper layer for sending if all conditions are met :
 * - room in congestion window or probe packet to sent
 * - socket FD ready to sent or listener socket used
 *
 * Returns 1 if upper layer has been woken up else 0.
 */
int qc_notify_send(struct quic_conn *qc)
{
	const struct quic_pktns *pktns = &qc->pktns[QUIC_TLS_PKTNS_01RTT];

	if (qc->subs && qc->subs->events & SUB_RETRY_SEND) {
		/* RFC 9002 7.5. Probe Timeout
		 *
		 * Probe packets MUST NOT be blocked by the congestion controller.
		 */
		if ((quic_path_prep_data(qc->path) || pktns->tx.pto_probe) &&
		    (!qc_test_fd(qc) || !fd_send_active(qc->fd))) {
			tasklet_wakeup(qc->subs->tasklet);
			qc->subs->events &= ~SUB_RETRY_SEND;
			if (!qc->subs->events)
				qc->subs = NULL;

			return 1;
		}
	}

	return 0;
}

/* Move a <qc> QUIC connection and its resources from the current thread to the
 * new one <new_tid> optionally in association with <new_li> (since it may need
 * to change when migrating to a thread from a different group, otherwise leave
 * it NULL). After this call, the connection cannot be dereferenced anymore on
 * the current thread.
 *
 * Returns 0 on success else non-zero.
 */
int qc_set_tid_affinity(struct quic_conn *qc, uint new_tid, struct listener *new_li)
{
	struct task *t1 = NULL, *t2 = NULL;
	struct tasklet *t3 = NULL;

	struct quic_connection_id *conn_id;
	struct eb64_node *node;

	TRACE_ENTER(QUIC_EV_CONN_SET_AFFINITY, qc);

	/* Pre-allocate all required resources. This ensures we do not left a
	 * connection with only some of its field rebinded.
	 */
	if (((t1 = task_new_on(new_tid)) == NULL) ||
	    (qc->timer_task && (t2 = task_new_on(new_tid)) == NULL) ||
	    (t3 = tasklet_new()) == NULL) {
		goto err;
	}

	/* Reinit idle timer task. */
	task_kill(qc->idle_timer_task);
	t1->expire = qc->idle_timer_task->expire;
	qc->idle_timer_task = t1;
	qc->idle_timer_task->process = qc_idle_timer_task;
	qc->idle_timer_task->context = qc;

	/* Reinit timer task if allocated. */
	if (qc->timer_task) {
		task_kill(qc->timer_task);
		qc->timer_task = t2;
		qc->timer_task->process = qc_process_timer;
		qc->timer_task->context = qc;
	}

	/* Reinit IO tasklet. */
	if (qc->wait_event.tasklet->state & TASK_IN_LIST)
		qc->flags |= QUIC_FL_CONN_IO_TO_REQUEUE;
	tasklet_kill(qc->wait_event.tasklet);
	/* In most cases quic_conn_app_io_cb is used but for 0-RTT quic_conn_io_cb can be still activated. */
	t3->process = qc->wait_event.tasklet->process;
	qc->wait_event.tasklet = t3;
	qc->wait_event.tasklet->tid = new_tid;
	qc->wait_event.tasklet->context = qc;
	qc->wait_event.events = 0;

	/* Rebind the connection FD. */
	if (qc_test_fd(qc)) {
		/* Reading is reactivated by the new thread. */
		fd_migrate_on(qc->fd, new_tid);
	}

	/* Remove conn from per-thread list instance. It will be hidden from
	 * "show quic" until rebinding is completed.
	 */
	qc_detach_th_ctx_list(qc, 0);

	node = eb64_first(&qc->cids);
	BUG_ON(!node || eb64_next(node)); /* One and only one CID must be present before affinity rebind. */
	conn_id = eb64_entry(node, struct quic_connection_id, seq_num);

	/* At this point no connection was accounted for yet on this
	 * listener so it's OK to just swap the pointer.
	 */
	if (new_li && new_li != qc->li)
		qc->li = new_li;

	/* Rebinding is considered done when CID points to the new thread. No
	 * access should be done to quic-conn instance after it.
	 */
	qc->flags |= QUIC_FL_CONN_AFFINITY_CHANGED;
	HA_ATOMIC_STORE(&conn_id->tid, new_tid);
	qc = NULL;

	TRACE_LEAVE(QUIC_EV_CONN_SET_AFFINITY, NULL);
	return 0;

 err:
	task_destroy(t1);
	task_destroy(t2);
	tasklet_free(t3);

	TRACE_DEVEL("leaving on error", QUIC_EV_CONN_SET_AFFINITY, qc);
	return 1;
}

/* Must be called after qc_set_tid_affinity() on the new thread. */
void qc_finalize_affinity_rebind(struct quic_conn *qc)
{
	TRACE_ENTER(QUIC_EV_CONN_SET_AFFINITY, qc);

	/* This function must not be called twice after an affinity rebind. */
	BUG_ON(!(qc->flags & QUIC_FL_CONN_AFFINITY_CHANGED));
	qc->flags &= ~QUIC_FL_CONN_AFFINITY_CHANGED;

	/* A connection must not pass to closing state until affinity rebind
	 * is completed. Else quic_handle_stopping() may miss it during process
	 * stopping cleanup.
	 */
	BUG_ON(qc->flags & (QUIC_FL_CONN_CLOSING|QUIC_FL_CONN_DRAINING));

	/* Reinsert connection in ha_thread_ctx global list. */
	LIST_APPEND(&th_ctx->quic_conns, &qc->el_th_ctx);
	qc->qc_epoch = HA_ATOMIC_LOAD(&qc_epoch);

	/* Reactivate FD polling if connection socket is active. */
	qc_want_recv(qc);

	/* Reactivate timer task if needed. */
	qc_set_timer(qc);

	/* Idle timer task is always active. */
	task_queue(qc->idle_timer_task);

	/* Reactivate IO tasklet if needed. */
	if (qc->flags & QUIC_FL_CONN_IO_TO_REQUEUE) {
		tasklet_wakeup(qc->wait_event.tasklet);
		qc->flags &= ~QUIC_FL_CONN_IO_TO_REQUEUE;
	}

	TRACE_LEAVE(QUIC_EV_CONN_SET_AFFINITY, qc);
}

enum quic_dump_format {
	QUIC_DUMP_FMT_ONELINE,
	QUIC_DUMP_FMT_FULL,
};

/* appctx context used by "show quic" command */
struct show_quic_ctx {
	unsigned int epoch;
	struct bref bref; /* back-reference to the quic-conn being dumped */
	unsigned int thr;
	int flags;
	enum quic_dump_format format;
};

#define QC_CLI_FL_SHOW_ALL 0x1 /* show closing/draining connections */

static int cli_parse_show_quic(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_quic_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	int argc = 2;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	ctx->epoch = _HA_ATOMIC_FETCH_ADD(&qc_epoch, 1);
	ctx->thr = 0;
	ctx->flags = 0;
	ctx->format = QUIC_DUMP_FMT_ONELINE;

	if (strcmp(args[argc], "oneline") == 0) {
		/* format already used as default value */
		++argc;
	}
	else if (strcmp(args[argc], "full") == 0) {
		ctx->format = QUIC_DUMP_FMT_FULL;
		++argc;
	}

	while (*args[argc]) {
		if (strcmp(args[argc], "all") == 0)
			ctx->flags |= QC_CLI_FL_SHOW_ALL;

		++argc;
	}

	LIST_INIT(&ctx->bref.users);

	return 0;
}

/* Dump for "show quic" with "oneline" format. */
static void dump_quic_oneline(struct show_quic_ctx *ctx, struct quic_conn *qc)
{
	char bufaddr[INET6_ADDRSTRLEN], bufport[6];
	int ret;
	unsigned char cid_len;

	ret = chunk_appendf(&trash, "%p[%02u]/%-.12s ", qc, ctx->thr,
	                    qc->li->bind_conf->frontend->id);
	chunk_appendf(&trash, "%*s", 36 - ret, " "); /* align output */

	/* State */
	if (qc->flags & QUIC_FL_CONN_CLOSING)
		chunk_appendf(&trash, "CLOSE   ");
	else if (qc->flags & QUIC_FL_CONN_DRAINING)
		chunk_appendf(&trash, "DRAIN   ");
	else if (qc->state < QUIC_HS_ST_COMPLETE)
		chunk_appendf(&trash, "HDSHK   ");
	else
		chunk_appendf(&trash, "ESTAB   ");

	/* Bytes in flight / Lost packets */
	chunk_appendf(&trash, "%9llu %6llu %6llu   ",
	              (ullong)qc->path->in_flight,
	              (ullong)qc->path->ifae_pkts,
	              (ullong)qc->path->loss.nb_lost_pkt);

	/* Socket */
	if (qc->local_addr.ss_family == AF_INET ||
	    qc->local_addr.ss_family == AF_INET6) {
		addr_to_str(&qc->local_addr, bufaddr, sizeof(bufaddr));
		port_to_str(&qc->local_addr, bufport, sizeof(bufport));
		chunk_appendf(&trash, "%15s:%-5s   ", bufaddr, bufport);

		addr_to_str(&qc->peer_addr, bufaddr, sizeof(bufaddr));
		port_to_str(&qc->peer_addr, bufport, sizeof(bufport));
		chunk_appendf(&trash, "%15s:%-5s ", bufaddr, bufport);

	}

	/* CIDs */
	for (cid_len = 0; cid_len < qc->scid.len; ++cid_len)
		chunk_appendf(&trash, "%02x", qc->scid.data[cid_len]);

	chunk_appendf(&trash, " ");
	for (cid_len = 0; cid_len < qc->dcid.len; ++cid_len)
		chunk_appendf(&trash, "%02x", qc->dcid.data[cid_len]);

	chunk_appendf(&trash, "\n");
}

/* Dump for "show quic" with "full" format. */
static void dump_quic_full(struct show_quic_ctx *ctx, struct quic_conn *qc)
{
	struct quic_pktns *pktns;
	struct eb64_node *node;
	struct qc_stream_desc *stream;
	char bufaddr[INET6_ADDRSTRLEN], bufport[6];
	int expire, i, addnl;
	unsigned char cid_len;

	addnl = 0;
	/* CIDs */
	chunk_appendf(&trash, "* %p[%02u]: scid=", qc, ctx->thr);
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

	chunk_appendf(&trash, "  loc. TPs:");
	quic_transport_params_dump(&trash, qc, &qc->rx.params);
	chunk_appendf(&trash, "\n");
	chunk_appendf(&trash, "  rem. TPs:");
	quic_transport_params_dump(&trash, qc, &qc->tx.params);
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

	expire = qc->idle_expire;
	chunk_appendf(&trash, "expire=%02ds ",
	              TICKS_TO_MS(tick_remain(now_ms, expire)) / 1000);

	chunk_appendf(&trash, "\n");

	/* Socket */
	chunk_appendf(&trash, "  fd=%d", qc->fd);
	if (qc->local_addr.ss_family == AF_INET ||
	    qc->local_addr.ss_family == AF_INET6) {
		addr_to_str(&qc->local_addr, bufaddr, sizeof(bufaddr));
		port_to_str(&qc->local_addr, bufport, sizeof(bufport));
		chunk_appendf(&trash, "               local_addr=%s:%s", bufaddr, bufport);

		addr_to_str(&qc->peer_addr, bufaddr, sizeof(bufaddr));
		port_to_str(&qc->peer_addr, bufport, sizeof(bufport));
		chunk_appendf(&trash, " foreign_addr=%s:%s", bufaddr, bufport);
	}

	chunk_appendf(&trash, "\n");

	/* Packet number spaces information */
	pktns = &qc->pktns[QUIC_TLS_PKTNS_INITIAL];
	chunk_appendf(&trash, "  [initl]             rx.ackrng=%-6zu tx.inflight=%-6zu",
	              pktns->rx.arngs.sz, pktns->tx.in_flight);
	pktns = &qc->pktns[QUIC_TLS_PKTNS_HANDSHAKE];
	chunk_appendf(&trash, "           [hndshk] rx.ackrng=%-6zu tx.inflight=%-6zu\n",
	              pktns->rx.arngs.sz, pktns->tx.in_flight);
	pktns = &qc->pktns[QUIC_TLS_PKTNS_01RTT];
	chunk_appendf(&trash, "  [01rtt]             rx.ackrng=%-6zu tx.inflight=%-6zu\n",
	              pktns->rx.arngs.sz, pktns->tx.in_flight);

	chunk_appendf(&trash, "  srtt=%-4u rttvar=%-4u rttmin=%-4u ptoc=%-4u cwnd=%-6llu"
	                      " mcwnd=%-6llu sentpkts=%-6llu lostpkts=%-6llu\n",
	              qc->path->loss.srtt >> 3, qc->path->loss.rtt_var >> 2,
	              qc->path->loss.rtt_min, qc->path->loss.pto_count, (ullong)qc->path->cwnd,
	              (ullong)qc->path->mcwnd, (ullong)qc->cntrs.sent_pkt, (ullong)qc->path->loss.nb_lost_pkt);

	if (qc->cntrs.dropped_pkt) {
		chunk_appendf(&trash, " droppkts=%-6llu", qc->cntrs.dropped_pkt);
		addnl = 1;
	}
	if (qc->cntrs.dropped_pkt_bufoverrun) {
		chunk_appendf(&trash, " dropbuff=%-6llu", qc->cntrs.dropped_pkt_bufoverrun);
		addnl = 1;
	}
	if (qc->cntrs.dropped_parsing) {
		chunk_appendf(&trash, " droppars=%-6llu", qc->cntrs.dropped_parsing);
		addnl = 1;
	}
	if (qc->cntrs.socket_full) {
		chunk_appendf(&trash, " sockfull=%-6llu", qc->cntrs.socket_full);
		addnl = 1;
	}
	if (qc->cntrs.sendto_err) {
		chunk_appendf(&trash, " sendtoerr=%-6llu", qc->cntrs.sendto_err);
		addnl = 1;
	}
	if (qc->cntrs.sendto_err_unknown) {
		chunk_appendf(&trash, " sendtounknerr=%-6llu", qc->cntrs.sendto_err);
		addnl = 1;
	}
	if (qc->cntrs.conn_migration_done) {
		chunk_appendf(&trash, " migrdone=%-6llu", qc->cntrs.conn_migration_done);
		addnl = 1;
	}
	if (qc->cntrs.data_blocked) {
		chunk_appendf(&trash, " datablocked=%-6llu", qc->cntrs.data_blocked);
		addnl = 1;
	}
	if (qc->cntrs.stream_data_blocked) {
		chunk_appendf(&trash, " sdatablocked=%-6llu", qc->cntrs.stream_data_blocked);
		addnl = 1;
	}
	if (qc->cntrs.streams_blocked_bidi) {
		chunk_appendf(&trash, " sblockebidi=%-6llu", qc->cntrs.streams_blocked_bidi);
		addnl = 1;
	}
	if (qc->cntrs.streams_blocked_uni) {
		chunk_appendf(&trash, " sblockeduni=%-6llu", qc->cntrs.streams_blocked_uni);
		addnl = 1;
	}
	if (addnl)
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
}

static int cli_io_handler_dump_quic(struct appctx *appctx)
{
	struct show_quic_ctx *ctx = appctx->svcctx;
	struct stconn *sc = appctx_sc(appctx);
	struct quic_conn *qc;

	thread_isolate();

	if (ctx->thr >= global.nbthread)
		goto done;

	/* FIXME: Don't watch the other side !*/
	if (unlikely(sc_opposite(sc)->flags & SC_FL_SHUT_DONE)) {
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

		/* Print legend for oneline format. */
		if (ctx->format == QUIC_DUMP_FMT_ONELINE) {
			chunk_appendf(&trash, "# conn/frontend                     state   "
				      "in_flight infl_p lost_p         "
				      "Local Address           Foreign Address      "
				      "local & remote CIDs\n");
			applet_putchk(appctx, &trash);
		}
	}

	while (1) {
		int done = 0;

		if (ctx->bref.ref == &ha_thread_ctx[ctx->thr].quic_conns) {
			/* If closing connections requested through "all", move
			 * to quic_conns_clo list after browsing quic_conns.
			 * Else move directly to the next quic_conns thread.
			 */
			if (ctx->flags & QC_CLI_FL_SHOW_ALL) {
				ctx->bref.ref = ha_thread_ctx[ctx->thr].quic_conns_clo.n;
				continue;
			}

			done = 1;
		}
		else if (ctx->bref.ref == &ha_thread_ctx[ctx->thr].quic_conns_clo) {
			/* Closing list entirely browsed, go to next quic_conns
			 * thread.
			 */
			done = 1;
		}
		else {
			/* Retrieve next element of the current list. */
			qc = LIST_ELEM(ctx->bref.ref, struct quic_conn *, el_th_ctx);
			if ((int)(qc->qc_epoch - ctx->epoch) > 0)
				done = 1;
		}

		if (done) {
			++ctx->thr;
			if (ctx->thr >= global.nbthread)
				break;
			/* Switch to next thread quic_conns list. */
			ctx->bref.ref = ha_thread_ctx[ctx->thr].quic_conns.n;
			continue;
		}

		switch (ctx->format) {
		case QUIC_DUMP_FMT_FULL:
			dump_quic_full(ctx, qc);
			break;
		case QUIC_DUMP_FMT_ONELINE:
			dump_quic_oneline(ctx, qc);
			break;
		}

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
	{ { "show", "quic", NULL }, "show quic [oneline|full] [all]          : display quic connections status", cli_parse_show_quic, cli_io_handler_dump_quic, cli_release_show_quic },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

static void init_quic()
{
	int thr;

	for (thr = 0; thr < MAX_THREADS; ++thr) {
		LIST_INIT(&ha_thread_ctx[thr].quic_conns);
		LIST_INIT(&ha_thread_ctx[thr].quic_conns_clo);
	}
}
INITCALL0(STG_INIT, init_quic);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
