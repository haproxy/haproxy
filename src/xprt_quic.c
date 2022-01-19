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

#include <import/ebmbtree.h>

#include <haproxy/buf-t.h>
#include <haproxy/compat.h>
#include <haproxy/api.h>
#include <haproxy/debug.h>
#include <haproxy/tools.h>
#include <haproxy/ticks.h>

#include <haproxy/connection.h>
#include <haproxy/fd.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/global.h>
#include <haproxy/h3.h>
#include <haproxy/hq_interop.h>
#include <haproxy/log.h>
#include <haproxy/mux_quic.h>
#include <haproxy/pipe.h>
#include <haproxy/proxy.h>
#include <haproxy/quic_cc.h>
#include <haproxy/quic_frame.h>
#include <haproxy/quic_loss.h>
#include <haproxy/quic_sock.h>
#include <haproxy/cbuf.h>
#include <haproxy/quic_tls.h>
#include <haproxy/sink.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/stream_interface.h>
#include <haproxy/task.h>
#include <haproxy/trace.h>
#include <haproxy/xprt_quic.h>

/* list of supported QUIC versions by this implementation */
static int quic_supported_version[] = {
	0x00000001,
	0xff00001d, /* draft-29 */

	/* placeholder, do not add entry after this */
	0x0
};

/* This is the values of some QUIC transport parameters when absent.
 * Should be used to initialize any transport parameters (local or remote)
 * before updating them with customized values.
 */
struct quic_transport_params quic_dflt_transport_params = {
	.max_udp_payload_size = QUIC_PACKET_MAXLEN,
	.ack_delay_exponent   = QUIC_DFLT_ACK_DELAY_COMPONENT,
	.max_ack_delay        = QUIC_DFLT_MAX_ACK_DELAY,
	.active_connection_id_limit = QUIC_ACTIVE_CONNECTION_ID_LIMIT,
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
	{ .mask = QUIC_EV_CONN_XPRTSEND, .name = "xprt_send",        .desc = "sending XRPT subscription" },
	{ .mask = QUIC_EV_CONN_XPRTRECV, .name = "xprt_recv",        .desc = "receiving XRPT subscription" },
	{ .mask = QUIC_EV_CONN_FREED,    .name = "conn_freed",       .desc = "releasing conn. memory" },
	{ .mask = QUIC_EV_CONN_CLOSE,    .name = "conn_close",       .desc = "closing conn." },
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

DECLARE_POOL(pool_head_quic_tx_ring, "quic_tx_ring_pool", QUIC_TX_RING_BUFSZ);
DECLARE_POOL(pool_head_quic_rxbuf, "quic_rxbuf_pool", QUIC_RX_BUFSZ);
DECLARE_POOL(pool_head_quic_conn_rxbuf, "quic_conn_rxbuf", QUIC_CONN_RX_BUFSZ);
DECLARE_STATIC_POOL(pool_head_quic_conn_ctx,
                    "quic_conn_ctx_pool", sizeof(struct ssl_sock_ctx));
DECLARE_STATIC_POOL(pool_head_quic_conn, "quic_conn", sizeof(struct quic_conn));
DECLARE_POOL(pool_head_quic_connection_id,
             "quic_connnection_id_pool", sizeof(struct quic_connection_id));
DECLARE_POOL(pool_head_quic_rx_packet, "quic_rx_packet_pool", sizeof(struct quic_rx_packet));
DECLARE_POOL(pool_head_quic_tx_packet, "quic_tx_packet_pool", sizeof(struct quic_tx_packet));
DECLARE_STATIC_POOL(pool_head_quic_rx_crypto_frm, "quic_rx_crypto_frm_pool", sizeof(struct quic_rx_crypto_frm));
DECLARE_POOL(pool_head_quic_rx_strm_frm, "quic_rx_strm_frm", sizeof(struct quic_rx_strm_frm));
DECLARE_STATIC_POOL(pool_head_quic_crypto_buf, "quic_crypto_buf_pool", sizeof(struct quic_crypto_buf));
DECLARE_POOL(pool_head_quic_frame, "quic_frame_pool", sizeof(struct quic_frame));
DECLARE_STATIC_POOL(pool_head_quic_arng, "quic_arng_pool", sizeof(struct quic_arng_node));

static struct quic_tx_packet *qc_build_pkt(unsigned char **pos, const unsigned char *buf_end,
                                           struct quic_enc_level *qel,
                                           struct quic_conn *qc, size_t dglen, int pkt_type,
                                           int padding, int ack, int probe, int cc, int *err);

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
		const struct quic_tls_secrets *secs;

		chunk_appendf(&trace_buf, " : qc@%p", qc);
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
				const struct quic_pktns *pktns = qc->pktns;
				chunk_appendf(&trace_buf, " qel=%c cwnd=%llu ppif=%lld pif=%llu "
				              "if=%llu pp=%u",
				              quic_enc_level_char_from_qel(qel, qc),
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
				list_for_each_entry(frm, &pkt->frms, list)
					chunk_frm_appendf(&trace_buf, frm);
				chunk_appendf(&trace_buf, " rx.bytes=%llu tx.bytes=%llu",
				              (unsigned long long)qc->rx.bytes,
				              (unsigned long long)qc->tx.bytes);
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
				chunk_appendf(&trace_buf, " rel=%c",
				              quic_enc_level_char(ssl_to_quic_enc_level(level)));
			}

			if (qc->err_code)
				chunk_appendf(&trace_buf, " err_code=0x%llx", (ull)qc->err_code);
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
				              " qel=%c state=%s ack?%d cwnd=%llu ppif=%lld pif=%llu if=%llu pp=%u",
				              quic_enc_level_char_from_qel(qel, qc),
				              quic_hdshk_state_str(HA_ATOMIC_LOAD(&qc->state)),
				              !!(HA_ATOMIC_LOAD(&qel->pktns->flags) & QUIC_FL_PKTNS_ACK_REQUIRED),
				              (unsigned long long)qc->path->cwnd,
				              (unsigned long long)qc->path->prep_in_flight,
				              (unsigned long long)qc->path->in_flight,
				              (unsigned long long)pktns->tx.in_flight,
				              pktns->tx.pto_probe);
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

			if (frm)
				chunk_frm_appendf(&trace_buf, frm);
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
				chunk_appendf(&trace_buf, " pn=%lu(%s) iflen=%llu",
				              (unsigned long)pkt->pn_node.key,
				              pkt->pktns == &qc->pktns[QUIC_TLS_PKTNS_INITIAL] ? "I" :
				              pkt->pktns == &qc->pktns[QUIC_TLS_PKTNS_01RTT] ? "01RTT": "H",
				              (unsigned long long)pkt->in_flight_len);
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
	}
	if (mask & QUIC_EV_CONN_LPKT) {
		const struct quic_rx_packet *pkt = a2;
		const uint64_t *len = a3;

		if (pkt) {
			chunk_appendf(&trace_buf, " pkt@%p type=0x%02x %s",
			              pkt, pkt->type, qc_pkt_long(pkt) ? "long" : "short");
			if (pkt->pn_node.key != (uint64_t)-1)
				chunk_appendf(&trace_buf, " pn=%llu", pkt->pn_node.key);
		}

		if (len)
			chunk_appendf(&trace_buf, " len=%llu", (ull)*len);
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
	if ((HA_ATOMIC_LOAD(&hdshk_pktns->flags) & QUIC_FL_PKTNS_ACK_RECEIVED) ||
	    (HA_ATOMIC_LOAD(&app_pktns->flags) & QUIC_FL_PKTNS_ACK_RECEIVED) ||
	    HA_ATOMIC_LOAD(&qc->state) >= QUIC_HS_ST_COMPLETE)
		return 1;

	return 0;
}

/* Set the timer attached to the QUIC connection with <ctx> as I/O handler and used for
 * both loss detection and PTO and schedule the task assiated to this timer if needed.
 */
static inline void qc_set_timer(struct quic_conn *qc)
{
	struct quic_pktns *pktns;
	unsigned int pto;
	int handshake_complete;

	TRACE_ENTER(QUIC_EV_CONN_STIMER, qc,
	            NULL, NULL, &qc->path->ifae_pkts);

	pktns = quic_loss_pktns(qc);
	if (tick_isset(pktns->tx.loss_time)) {
		qc->timer = pktns->tx.loss_time;
		goto out;
	}

	/* anti-amplification: the timer must be
	 * cancelled for a server which reached the anti-amplification limit.
	 */
	if (!quic_peer_validated_addr(qc) &&
	    (HA_ATOMIC_LOAD(&qc->flags) & QUIC_FL_CONN_ANTI_AMPLIFICATION_REACHED)) {
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

	handshake_complete = HA_ATOMIC_LOAD(&qc->state) >= QUIC_HS_ST_COMPLETE;
	pktns = quic_pto_pktns(qc, handshake_complete, &pto);
	if (tick_isset(pto))
		qc->timer = pto;
 out:
	if (qc->timer_task && qc->timer != TICK_ETERNITY)
		task_schedule(qc->timer_task, qc->timer);
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

	tls_ctx = &qc->els[QUIC_TLS_ENC_LEVEL_APP].tls_ctx;
	rx = &tls_ctx->rx;
	tx = &tls_ctx->tx;
	nxt_rx = &qc->ku.nxt_rx;
	nxt_tx = &qc->ku.nxt_tx;

	/* Prepare new RX secrets */
	if (!quic_tls_sec_update(rx->md, nxt_rx->secret, nxt_rx->secretlen,
	                         rx->secret, rx->secretlen)) {
		TRACE_DEVEL("New RX secret update failed", QUIC_EV_CONN_RWSEC, qc);
		return 0;
	}

	if (!quic_tls_derive_keys(rx->aead, NULL, rx->md,
	                          nxt_rx->key, nxt_rx->keylen,
	                          nxt_rx->iv, nxt_rx->ivlen, NULL, 0,
	                          nxt_rx->secret, nxt_rx->secretlen)) {
		TRACE_DEVEL("New RX key derivation failed", QUIC_EV_CONN_RWSEC, qc);
		return 0;
	}

	/* Prepare new TX secrets */
	if (!quic_tls_sec_update(tx->md, nxt_tx->secret, nxt_tx->secretlen,
	                         tx->secret, tx->secretlen)) {
		TRACE_DEVEL("New TX secret update failed", QUIC_EV_CONN_RWSEC, qc);
		return 0;
	}

	if (!quic_tls_derive_keys(tx->aead, NULL, tx->md,
	                          nxt_tx->key, nxt_tx->keylen,
	                          nxt_tx->iv, nxt_tx->ivlen, NULL, 0,
	                          nxt_tx->secret, nxt_tx->secretlen)) {
		TRACE_DEVEL("New TX key derivation failed", QUIC_EV_CONN_RWSEC, qc);
		return 0;
	}

	return 1;
}

/* Rotate the Key Update information for <qc> QUIC connection.
 * Must be used after having updated them.
 * Always succeeds.
 */
static void quic_tls_rotate_keys(struct quic_conn *qc)
{
	struct quic_tls_ctx *tls_ctx = &qc->els[QUIC_TLS_ENC_LEVEL_APP].tls_ctx;
	unsigned char *curr_secret, *curr_iv, *curr_key;

	/* Rotate the RX secrets */
	curr_secret = tls_ctx->rx.secret;
	curr_iv = tls_ctx->rx.iv;
	curr_key = tls_ctx->rx.key;

	tls_ctx->rx.secret  = qc->ku.nxt_rx.secret;
	tls_ctx->rx.iv      = qc->ku.nxt_rx.iv;
	tls_ctx->rx.key     = qc->ku.nxt_rx.key;

	qc->ku.nxt_rx.secret = qc->ku.prv_rx.secret;
	qc->ku.nxt_rx.iv     = qc->ku.prv_rx.iv;
	qc->ku.nxt_rx.key    = qc->ku.prv_rx.key;

	qc->ku.prv_rx.secret = curr_secret;
	qc->ku.prv_rx.iv     = curr_iv;
	qc->ku.prv_rx.key    = curr_key;
	qc->ku.prv_rx.pn     = tls_ctx->rx.pn;

	/* Update the TX secrets */
	curr_secret = tls_ctx->tx.secret;
	curr_iv = tls_ctx->tx.iv;
	curr_key = tls_ctx->tx.key;

	tls_ctx->tx.secret = qc->ku.nxt_tx.secret;
	tls_ctx->tx.iv     = qc->ku.nxt_tx.iv;
	tls_ctx->tx.key    = qc->ku.nxt_tx.key;

	qc->ku.nxt_tx.secret = curr_secret;
	qc->ku.nxt_tx.iv     = curr_iv;
	qc->ku.nxt_tx.key    = curr_key;
}

#ifndef OPENSSL_IS_BORINGSSL
int ha_quic_set_encryption_secrets(SSL *ssl, enum ssl_encryption_level_t level,
                                   const uint8_t *read_secret,
                                   const uint8_t *write_secret, size_t secret_len)
{
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);
	struct quic_tls_ctx *tls_ctx = &qc->els[ssl_to_quic_enc_level(level)].tls_ctx;
	const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
	struct quic_tls_secrets *rx, *tx;

	TRACE_ENTER(QUIC_EV_CONN_RWSEC, qc);
	BUG_ON(secret_len > QUIC_TLS_SECRET_LEN);
	if (HA_ATOMIC_LOAD(&qc->flags) & QUIC_FL_CONN_IMMEDIATE_CLOSE) {
		TRACE_PROTO("CC required", QUIC_EV_CONN_RWSEC, qc);
		goto out;
	}

	if (!quic_tls_ctx_keys_alloc(tls_ctx)) {
		TRACE_DEVEL("keys allocation failed", QUIC_EV_CONN_RWSEC, qc);
		goto err;
	}

	rx = &tls_ctx->rx;
	tx = &tls_ctx->tx;

	rx->aead = tx->aead = tls_aead(cipher);
	rx->md   = tx->md   = tls_md(cipher);
	rx->hp   = tx->hp   = tls_hp(cipher);

	if (!quic_tls_derive_keys(rx->aead, rx->hp, rx->md, rx->key, rx->keylen,
	                          rx->iv, rx->ivlen, rx->hp_key, sizeof rx->hp_key,
	                          read_secret, secret_len)) {
		TRACE_DEVEL("RX key derivation failed", QUIC_EV_CONN_RWSEC, qc);
		goto err;
	}

	rx->flags |= QUIC_FL_TLS_SECRETS_SET;

	if (!write_secret)
		goto tp;

	if (!quic_tls_derive_keys(tx->aead, tx->hp, tx->md, tx->key, tx->keylen,
	                          tx->iv, tx->ivlen, tx->hp_key, sizeof tx->hp_key,
	                          write_secret, secret_len)) {
		TRACE_DEVEL("TX key derivation failed", QUIC_EV_CONN_RWSEC, qc);
		goto err;
	}

	tx->flags |= QUIC_FL_TLS_SECRETS_SET;
 tp:
	if (!qc_is_listener(qc) && level == ssl_encryption_application) {
		const unsigned char *buf;
		size_t buflen;

		SSL_get_peer_quic_transport_params(ssl, &buf, &buflen);
		if (!buflen)
			goto err;

		if (!quic_transport_params_store(qc, 1, buf, buf + buflen))
			goto err;
	}

	if (level == ssl_encryption_application) {
		struct quic_tls_kp *prv_rx = &qc->ku.prv_rx;
		struct quic_tls_kp *nxt_rx = &qc->ku.nxt_rx;
		struct quic_tls_kp *nxt_tx = &qc->ku.nxt_tx;

		if (!(rx->secret = pool_alloc(pool_head_quic_tls_secret)) ||
		    !(tx->secret = pool_alloc(pool_head_quic_tls_secret))) {
			TRACE_DEVEL("Could not allocate secrete keys", QUIC_EV_CONN_RWSEC, qc);
			goto err;
		}

		memcpy(rx->secret, read_secret, secret_len);
		rx->secretlen = secret_len;
		memcpy(tx->secret, write_secret, secret_len);
		tx->secretlen = secret_len;
		/* Initialize all the secret keys lengths */
		prv_rx->secretlen = nxt_rx->secretlen = nxt_tx->secretlen = secret_len;
		/* Prepare the next key update */
		if (!quic_tls_key_update(qc))
			goto err;
	}
 out:
	TRACE_LEAVE(QUIC_EV_CONN_RWSEC, qc, &level);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_RWSEC, qc);
	return 0;
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
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);
	struct quic_tls_ctx *tls_ctx =
		&qc->els[ssl_to_quic_enc_level(level)].tls_ctx;

	TRACE_ENTER(QUIC_EV_CONN_RSEC, qc);
	if (HA_ATOMIC_LOAD(&qc->flags) & QUIC_FL_CONN_IMMEDIATE_CLOSE) {
		TRACE_PROTO("CC required", QUIC_EV_CONN_RSEC, qc);
		goto out;
	}

	tls_ctx->rx.aead = tls_aead(cipher);
	tls_ctx->rx.md = tls_md(cipher);
	tls_ctx->rx.hp = tls_hp(cipher);

	if (!(ctx->rx.key = pool_alloc(pool_head_quic_tls_key)))
		goto err;

	if (!quic_tls_derive_keys(tls_ctx->rx.aead, tls_ctx->rx.hp, tls_ctx->rx.md,
	                          tls_ctx->rx.key, tls_ctx->rx.keylen,
	                          tls_ctx->rx.iv, tls_ctx->rx.ivlen,
	                          tls_ctx->rx.hp_key, sizeof tls_ctx->rx.hp_key,
	                          secret, secret_len)) {
		TRACE_DEVEL("RX key derivation failed", QUIC_EV_CONN_RSEC, qc);
		goto err;
	}

	if (!qc_is_listener(qc) && level == ssl_encryption_application) {
		const unsigned char *buf;
		size_t buflen;

		SSL_get_peer_quic_transport_params(ssl, &buf, &buflen);
		if (!buflen)
			goto err;

		if (!quic_transport_params_store(qc, 1, buf, buf + buflen))
			goto err;
	}

	tls_ctx->rx.flags |= QUIC_FL_TLS_SECRETS_SET;
 out:
	TRACE_LEAVE(QUIC_EV_CONN_RSEC, qc, &level, secret, &secret_len);

	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_RSEC, qc);
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
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);
	struct quic_tls_ctx *tls_ctx = &qc->els[ssl_to_quic_enc_level(level)].tls_ctx;

	TRACE_ENTER(QUIC_EV_CONN_WSEC, qc);
	if (HA_ATOMIC_LOAD(&qc->flags) & QUIC_FL_CONN_IMMEDIATE_CLOSE) {
		TRACE_PROTO("CC required", QUIC_EV_CONN_WSEC, qc);
		goto out;
	}

	if (!(ctx->tx.key = pool_alloc(pool_head_quic_tls_key)))
		goto err;

	tls_ctx->tx.aead = tls_aead(cipher);
	tls_ctx->tx.md = tls_md(cipher);
	tls_ctx->tx.hp = tls_hp(cipher);

	if (!quic_tls_derive_keys(tls_ctx->tx.aead, tls_ctx->tx.hp, tls_ctx->tx.md,
	                          tls_ctx->tx.key, tls_ctx->tx.keylen,
	                          tls_ctx->tx.iv, tls_ctx->tx.ivlen,
	                          tls_ctx->tx.hp_key, sizeof tls_ctx->tx.hp_key,
	                          secret, secret_len)) {
		TRACE_DEVEL("TX key derivation failed", QUIC_EV_CONN_WSEC, qc);
		goto err;
	}

	tls_ctx->tx.flags |= QUIC_FL_TLS_SECRETS_SET;
	TRACE_LEAVE(QUIC_EV_CONN_WSEC, qc, &level, secret, &secret_len);
 out:
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_WSEC, qc);
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
			frm = pool_alloc(pool_head_quic_frame);
			if (!frm)
				return 0;

			frm->type = QUIC_FT_CRYPTO;
			frm->crypto.offset = cf_offset;
			frm->crypto.len = cf_len;
			frm->crypto.qel = qel;
			LIST_APPEND(&qel->pktns->tx.frms, &frm->list);
		}
	}

	return len == 0;
}


/* Set <alert> TLS alert as QUIC CRYPTO_ERROR error */
void quic_set_tls_alert(struct quic_conn *qc, int alert)
{
	HA_ATOMIC_STORE(&qc->err_code, QC_ERR_CRYPTO_ERROR | alert);
	HA_ATOMIC_OR(&qc->flags, QUIC_FL_CONN_IMMEDIATE_CLOSE);
	TRACE_PROTO("Alert set", QUIC_EV_CONN_SSLDATA, qc);
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

	qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);
	TRACE_ENTER(QUIC_EV_CONN_ADDDATA, qc);
	if (HA_ATOMIC_LOAD(&qc->flags) & QUIC_FL_CONN_IMMEDIATE_CLOSE) {
		TRACE_PROTO("CC required", QUIC_EV_CONN_ADDDATA, qc);
		goto out;
	}

	tel = ssl_to_quic_enc_level(level);
	qel = &qc->els[tel];

	if (tel == -1) {
		TRACE_PROTO("Wrong encryption level", QUIC_EV_CONN_ADDDATA, qc);
		goto err;
	}

	if (!quic_crypto_data_cpy(qel, data, len)) {
		TRACE_PROTO("Could not bufferize", QUIC_EV_CONN_ADDDATA, qc);
		goto err;
	}

	TRACE_PROTO("CRYPTO data buffered", QUIC_EV_CONN_ADDDATA,
	            qc, &level, &len);

 out:
	TRACE_LEAVE(QUIC_EV_CONN_ADDDATA, qc);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_ADDDATA, qc);
	return 0;
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

	TRACE_DEVEL("SSL alert", QUIC_EV_CONN_SSLALERT, qc, &alert, &level);
	quic_set_tls_alert(qc, alert);
	HA_ATOMIC_STORE(&qc->flags, QUIC_FL_CONN_IMMEDIATE_CLOSE);
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
	const char *groups = "X25519:P-256:P-384:P-521";
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
		SSL_CTX_set_max_early_data(ctx, 0xffffffff);
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
static int qc_do_rm_hp(struct quic_conn *qc,
                       struct quic_rx_packet *pkt, struct quic_tls_ctx *tls_ctx,
                       int64_t largest_pn, unsigned char *pn,
                       unsigned char *byte0, const unsigned char *end)
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
		TRACE_DEVEL("too short packet", QUIC_EV_CONN_RMHP, qc, pkt);
		return 0;
	}

	cctx = EVP_CIPHER_CTX_new();
	if (!cctx) {
		TRACE_DEVEL("memory allocation failed", QUIC_EV_CONN_RMHP, qc, pkt);
		return 0;
	}

	ret = 0;
	sample = pn + QUIC_PACKET_PN_MAXLEN;

	hp_key = tls_ctx->rx.hp_key;
	if (!EVP_DecryptInit_ex(cctx, tls_ctx->rx.hp, NULL, hp_key, sample) ||
	    !EVP_DecryptUpdate(cctx, mask, &outlen, mask, sizeof mask) ||
	    !EVP_DecryptFinal_ex(cctx, mask, &outlen)) {
		TRACE_DEVEL("decryption failed", QUIC_EV_CONN_RMHP, qc, pkt);
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
                               struct quic_tls_ctx *tls_ctx, struct quic_conn *qc)
{
	unsigned char iv[12];
	unsigned char *tx_iv = tls_ctx->tx.iv;
	size_t tx_iv_sz = tls_ctx->tx.ivlen;
	struct enc_debug_info edi;

	if (!quic_aead_iv_build(iv, sizeof iv, tx_iv, tx_iv_sz, pn)) {
		TRACE_DEVEL("AEAD IV building for encryption failed", QUIC_EV_CONN_HPKT, qc);
		goto err;
	}

	if (!quic_tls_encrypt(payload, payload_len, aad, aad_len,
	                      tls_ctx->tx.aead, tls_ctx->tx.key, iv)) {
		TRACE_DEVEL("QUIC packet encryption failed", QUIC_EV_CONN_HPKT, qc);
		goto err;
	}

	return 1;

 err:
	enc_debug_info_init(&edi, payload, payload_len, aad, aad_len, pn);
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_ENCPKT, qc, &edi);
	return 0;
}

/* Decrypt <pkt> QUIC packet with <tls_ctx> as QUIC TLS cryptographic context.
 * Returns 1 if succeeded, 0 if not.
 */
static int qc_pkt_decrypt(struct quic_rx_packet *pkt, struct quic_enc_level *qel)
{
	int ret, kp_changed;
	unsigned char iv[12];
	struct quic_tls_ctx *tls_ctx = &qel->tls_ctx;
	unsigned char *rx_iv = tls_ctx->rx.iv;
	size_t rx_iv_sz = tls_ctx->rx.ivlen;
	unsigned char *rx_key = tls_ctx->rx.key;

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
				if (!pkt->qc->ku.prv_rx.pn)
					return 0;

				rx_iv = pkt->qc->ku.prv_rx.iv;
				rx_key = pkt->qc->ku.prv_rx.key;
			}
			else if (pkt->pn > qel->pktns->rx.largest_pn) {
				/* Next key phase */
				kp_changed = 1;
				rx_iv = pkt->qc->ku.nxt_rx.iv;
				rx_key = pkt->qc->ku.nxt_rx.key;
			}
		}
	}

	if (!quic_aead_iv_build(iv, sizeof iv, rx_iv, rx_iv_sz, pkt->pn))
		return 0;

	ret = quic_tls_decrypt(pkt->data + pkt->aad_len, pkt->len - pkt->aad_len,
	                       pkt->data, pkt->aad_len,
	                       tls_ctx->rx.aead, rx_key, iv);
	if (!ret)
		return 0;

	/* Update the keys only if the packet decryption succeeded. */
	if (kp_changed) {
		quic_tls_rotate_keys(pkt->qc);
		/* Toggle the Key Phase bit */
		tls_ctx->flags ^= QUIC_FL_TLS_KP_BIT_SET;
		/* Store the lowest packet number received for the current key phase */
		tls_ctx->rx.pn = pkt->pn;
		/* Prepare the next key update */
		if (!quic_tls_key_update(pkt->qc))
		    return 0;
	}

	/* Update the packet length (required to parse the frames). */
	pkt->len = pkt->aad_len + ret;

	return 1;
}

/* Remove from <qcs> stream the acknowledged frames.
 * Never fails.
 */
static int qcs_try_to_consume(struct qcs *qcs)
{
	int ret;
	struct eb64_node *frm_node;

	ret = 0;
	frm_node = eb64_first(&qcs->tx.acked_frms);
	while (frm_node) {
		struct quic_stream *strm;

		strm = eb64_entry(&frm_node->node, struct quic_stream, offset);
		if (strm->offset.key != qcs->tx.ack_offset)
			break;

		b_del(strm->buf, strm->len);
		qcs->tx.ack_offset += strm->len;
		frm_node = eb64_next(frm_node);
		eb64_delete(&strm->offset);
		ret = 1;
	}

	return ret;
}

/* Treat <frm> frame whose packet it is attached to has just been acknowledged. */
static inline void qc_treat_acked_tx_frm(struct quic_conn *qc,
                                         struct quic_frame *frm)
{
	int stream_acked;

	TRACE_PROTO("Removing frame", QUIC_EV_CONN_PRSAFRM, qc, frm);
	stream_acked = 0;
	switch (frm->type) {
	case QUIC_FT_STREAM_8 ... QUIC_FT_STREAM_F:
	{
		struct qcs *qcs = frm->stream.qcs;
		struct quic_stream *strm = &frm->stream;

		if (qcs->tx.ack_offset == strm->offset.key) {
			b_del(strm->buf, strm->len);
			qcs->tx.ack_offset += strm->len;
			LIST_DELETE(&frm->list);
			pool_free(pool_head_quic_frame, frm);
			stream_acked = 1;
		}
		else {
			eb64_insert(&qcs->tx.acked_frms, &strm->offset);
		}
		stream_acked |= qcs_try_to_consume(qcs);
	}
	break;
	default:
		LIST_DELETE(&frm->list);
		pool_free(pool_head_quic_frame, frm);
	}

	if (stream_acked) {
		struct qcc *qcc = qc->qcc;

		if (qcc->subs && qcc->subs->events & SUB_RETRY_SEND) {
			tasklet_wakeup(qcc->subs->tasklet);
			qcc->subs->events &= ~SUB_RETRY_SEND;
			if (!qcc->subs->events)
				qcc->subs = NULL;
		}
	}
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

	if (largest_node)
		node = largest_node;
	else {
		node = eb64_lookup(pkts, largest);
		while (!node && largest > smallest) {
			node = eb64_lookup(pkts, --largest);
		}
	}

	while (node && node->key >= smallest) {
		struct quic_frame *frm, *frmbak;

		pkt = eb64_entry(&node->node, struct quic_tx_packet, pn_node);
		*pkt_flags |= pkt->flags;
		LIST_INSERT(newly_acked_pkts, &pkt->list);
		TRACE_PROTO("Removing packet #", QUIC_EV_CONN_PRSAFRM, qc, NULL, &pkt->pn_node.key);
		list_for_each_entry_safe(frm, frmbak, &pkt->frms, list)
			qc_treat_acked_tx_frm(qc, frm);
		node = eb64_prev(node);
		eb64_delete(&pkt->pn_node);
	}

	return node;
}

/* Remove all frames from <pkt_frm_list> and reinsert them in the
 * same order they have been sent into <pktns_frm_list>.
 */
static inline void qc_requeue_nacked_pkt_tx_frms(struct quic_conn *qc,
                                                 struct list *pkt_frm_list,
                                                 struct list *pktns_frm_list)
{
	struct quic_frame *frm, *frmbak;
	struct list tmp = LIST_HEAD_INIT(tmp);

	list_for_each_entry_safe(frm, frmbak, pkt_frm_list, list) {
		LIST_DELETE(&frm->list);
		TRACE_PROTO("to resend frame", QUIC_EV_CONN_PRSAFRM, qc, frm);
		LIST_APPEND(&tmp, &frm->list);
	}

	LIST_SPLICE(pktns_frm_list, &tmp);
}

/* Free the TX packets of <pkts> list */
static inline void free_quic_tx_pkts(struct list *pkts)
{
	struct quic_tx_packet *pkt, *tmp;

	list_for_each_entry_safe(pkt, tmp, pkts, list) {
		LIST_DELETE(&pkt->list);
		eb64_delete(&pkt->pn_node);
		quic_tx_packet_refdec(pkt);
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
static inline void qc_treat_newly_acked_pkts(struct quic_conn *qc,
                                             struct list *newly_acked_pkts)
{
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
		LIST_DELETE(&pkt->list);
		eb64_delete(&pkt->pn_node);
		quic_tx_packet_refdec(pkt);
	}

}

/* Release all the frames attached to <pktns> packet number space */
static inline void qc_release_pktns_frms(struct quic_pktns *pktns)
{
	struct quic_frame *frm, *frmbak;

	list_for_each_entry_safe(frm, frmbak, &pktns->tx.frms, list) {
		LIST_DELETE(&frm->list);
		pool_free(pool_head_quic_frame, frm);
	}
}

/* Handle <pkts> list of lost packets detected at <now_us> handling
 * their TX frames.
 * Send a packet loss event to the congestion controller if
 * in flight packet have been lost.
 * Also frees the packet in <pkts> list.
 * Never fails.
 */
static inline void qc_release_lost_pkts(struct quic_conn *qc,
                                        struct quic_pktns *pktns,
                                        struct list *pkts,
                                        uint64_t now_us)
{
	struct quic_tx_packet *pkt, *tmp, *oldest_lost, *newest_lost;
	uint64_t lost_bytes;

	lost_bytes = 0;
	oldest_lost = newest_lost = NULL;
	list_for_each_entry_safe(pkt, tmp, pkts, list) {
		struct list tmp = LIST_HEAD_INIT(tmp);

		lost_bytes += pkt->in_flight_len;
		pkt->pktns->tx.in_flight -= pkt->in_flight_len;
		qc->path->prep_in_flight -= pkt->in_flight_len;
		if (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING)
			qc->path->ifae_pkts--;
		/* Treat the frames of this lost packet. */
		qc_requeue_nacked_pkt_tx_frms(qc, &pkt->frms, &pktns->tx.frms);
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

	if (lost_bytes) {
		/* Sent a packet loss event to the congestion controller. */
		qc_cc_loss_event(qc, lost_bytes, newest_lost->time_sent,
		                 newest_lost->time_sent - oldest_lost->time_sent, now_us);
		quic_tx_packet_refdec(oldest_lost);
		if (newest_lost != oldest_lost)
			quic_tx_packet_refdec(newest_lost);
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

	TRACE_ENTER(QUIC_EV_CONN_PKTLOSS, qc, pktns);
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
		largest_acked_pn = HA_ATOMIC_LOAD(&pktns->tx.largest_acked_pn);
		node = eb64_next(node);
		if ((int64_t)pkt->pn_node.key > largest_acked_pn)
			break;

		time_sent = pkt->time_sent;
		loss_time_limit = tick_add(time_sent, loss_delay);
		if (tick_is_le(time_sent, now_ms) ||
			(int64_t)largest_acked_pn >= pkt->pn_node.key + QUIC_LOSS_PACKET_THRESHOLD) {
			eb64_delete(&pkt->pn_node);
			LIST_APPEND(lost_pkts, &pkt->list);
		}
		else {
			if (tick_isset(pktns->tx.loss_time))
				pktns->tx.loss_time = tick_first(pktns->tx.loss_time, loss_time_limit);
			else
				pktns->tx.loss_time = loss_time_limit;
		}
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_PKTLOSS, qc, pktns, lost_pkts);
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

	if ((int64_t)ack->largest_ack > HA_ATOMIC_LOAD(&qel->pktns->tx.largest_acked_pn)) {
		largest_node = eb64_lookup(pkts, largest);
		if (!largest_node) {
			TRACE_DEVEL("Largest acked packet not found",
			            QUIC_EV_CONN_PRSAFRM, qc);
		}
		else {
			time_sent = eb64_entry(&largest_node->node,
			                       struct quic_tx_packet, pn_node)->time_sent;
		}
	}

	TRACE_PROTO("ack range", QUIC_EV_CONN_PRSAFRM,
	            qc, NULL, &largest, &smallest);
	do {
		uint64_t gap, ack_range;

		qc_ackrng_pkts(qc, pkts, &pkt_flags, &newly_acked_pkts,
		               largest_node, largest, smallest);
		if (!ack->ack_range_num--)
			break;

		if (!quic_dec_int(&gap, pos, end))
			goto err;

		if (smallest < gap + 2) {
			TRACE_DEVEL("wrong gap value", QUIC_EV_CONN_PRSAFRM,
			            qc, NULL, &gap, &smallest);
			goto err;
		}

		largest = smallest - gap - 2;
		if (!quic_dec_int(&ack_range, pos, end))
			goto err;

		if (largest < ack_range) {
			TRACE_DEVEL("wrong ack range value", QUIC_EV_CONN_PRSAFRM,
			            qc, NULL, &largest, &ack_range);
			goto err;
		}

		/* Do not use this node anymore. */
		largest_node = NULL;
		/* Next range */
		smallest = largest - ack_range;

		TRACE_PROTO("ack range", QUIC_EV_CONN_PRSAFRM,
		            qc, NULL, &largest, &smallest);
	} while (1);

	/* Flag this packet number space as having received an ACK. */
	HA_ATOMIC_OR(&qel->pktns->flags, QUIC_FL_PKTNS_ACK_RECEIVED);

	if (time_sent && (pkt_flags & QUIC_FL_TX_PACKET_ACK_ELICITING)) {
		*rtt_sample = tick_remain(time_sent, now_ms);
		HA_ATOMIC_STORE(&qel->pktns->tx.largest_acked_pn, ack->largest_ack);
	}

	if (!LIST_ISEMPTY(&newly_acked_pkts)) {
		if (!eb_is_empty(&qel->pktns->tx.pkts)) {
			qc_packet_loss_lookup(qel->pktns, qc, &lost_pkts);
			if (!LIST_ISEMPTY(&lost_pkts))
				qc_release_lost_pkts(qc, qel->pktns, &lost_pkts, now_ms);
		}
		qc_treat_newly_acked_pkts(qc, &newly_acked_pkts);
		if (quic_peer_validated_addr(qc))
			qc->path->loss.pto_count = 0;
		qc_set_timer(qc);
	}


	return 1;

 err:
	free_quic_tx_pkts(&newly_acked_pkts);
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_PRSAFRM, qc);
	return 0;
}

/* This function gives the detail of the SSL error. It is used only
 * if the debug mode and the verbose mode are activated. It dump all
 * the SSL error until the stack was empty.
 */
static forceinline void qc_ssl_dump_errors(struct connection *conn)
{
	if (unlikely(global.mode & MODE_DEBUG)) {
		while (1) {
			unsigned long ret;

			ret = ERR_get_error();
			if (!ret)
				return;

			fprintf(stderr, "conn. @%p OpenSSL error[0x%lx] %s: %s\n", conn, ret,
			        ERR_func_error_string(ret), ERR_reason_error_string(ret));
		}
	}
}

int ssl_sock_get_alpn(const struct connection *conn, void *xprt_ctx,
                      const char **str, int *len);

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
	int ssl_err, state;
	struct quic_conn *qc;

	ssl_err = SSL_ERROR_NONE;
	qc = ctx->qc;

	TRACE_ENTER(QUIC_EV_CONN_SSLDATA, qc);

	if (SSL_provide_quic_data(ctx->ssl, el->level, data, len) != 1) {
		TRACE_PROTO("SSL_provide_quic_data() error",
		            QUIC_EV_CONN_SSLDATA, qc, pkt, cf, ctx->ssl);
		goto err;
	}

	el->rx.crypto.offset += len;
	TRACE_PROTO("in order CRYPTO data",
	            QUIC_EV_CONN_SSLDATA, qc, NULL, cf, ctx->ssl);

	state = HA_ATOMIC_LOAD(&qc->state);
	if (state < QUIC_HS_ST_COMPLETE) {
		ssl_err = SSL_do_handshake(ctx->ssl);
		if (ssl_err != 1) {
			ssl_err = SSL_get_error(ctx->ssl, ssl_err);
			if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
				TRACE_PROTO("SSL handshake",
				            QUIC_EV_CONN_HDSHK, qc, &state, &ssl_err);
				goto out;
			}

			TRACE_DEVEL("SSL handshake error",
			            QUIC_EV_CONN_HDSHK, qc, &state, &ssl_err);
			qc_ssl_dump_errors(ctx->conn);
			ERR_clear_error();
			goto err;
		}

		TRACE_PROTO("SSL handshake OK", QUIC_EV_CONN_HDSHK, qc, &state);
		if (qc_is_listener(ctx->qc)) {
			HA_ATOMIC_STORE(&qc->state, QUIC_HS_ST_CONFIRMED);
			/* The connection is ready to be accepted. */
			quic_accept_push_qc(qc);
		}
		else {
			HA_ATOMIC_STORE(&qc->state, QUIC_HS_ST_COMPLETE);
		}
	} else {
		ssl_err = SSL_process_quic_post_handshake(ctx->ssl);
		if (ssl_err != 1) {
			ssl_err = SSL_get_error(ctx->ssl, ssl_err);
			if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
				TRACE_DEVEL("SSL post handshake",
				            QUIC_EV_CONN_HDSHK, qc, &state, &ssl_err);
				goto out;
			}

			TRACE_DEVEL("SSL post handshake error",
			            QUIC_EV_CONN_HDSHK, qc, &state, &ssl_err);
			goto err;
		}

		TRACE_PROTO("SSL post handshake succeeded",
		            QUIC_EV_CONN_HDSHK, qc, &state);
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_SSLDATA, qc);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_SSLDATA, qc);
	return 0;
}

/* Allocate a new STREAM RX frame from <stream_fm> STREAM frame attached to
 * <pkt> RX packet.
 * Return it if succeeded, NULL if not.
 */
static inline
struct quic_rx_strm_frm *new_quic_rx_strm_frm(struct quic_stream *stream_frm,
                                              struct quic_rx_packet *pkt)
{
	struct quic_rx_strm_frm *frm;

	frm = pool_alloc(pool_head_quic_rx_strm_frm);
	if (frm) {
		frm->offset_node.key = stream_frm->offset.key;
		frm->len = stream_frm->len;
		frm->data = stream_frm->data;
		frm->pkt = pkt;
	}

	return frm;
}

/* Copy as most as possible STREAM data from <strm_frm> into <strm> stream.
 * Also update <strm_frm> frame to reflect the data which have been consumed.
 */
static size_t qc_strm_cpy(struct buffer *buf, struct quic_stream *strm_frm)
{
	size_t ret;

	ret = 0;
	while (strm_frm->len) {
		size_t try;

		try = b_contig_space(buf);
		if (!try)
			break;

		if (try > strm_frm->len)
			try = strm_frm->len;
		memcpy(b_tail(buf), strm_frm->data, try);
		strm_frm->len -= try;
		strm_frm->offset.key += try;
		b_add(buf, try);
		ret += try;
	}

	return ret;
}

/* Copy as most as possible STREAM data from <strm_frm> into <buf> buffer.
 * Also update <strm_frm> frame to reflect the data which have been consumed.
 */
static size_t qc_rx_strm_frm_cpy(struct buffer *buf,
                                 struct quic_rx_strm_frm *strm_frm)
{
	size_t ret;

	ret = 0;
	while (strm_frm->len) {
		size_t try;

		try = b_contig_space(buf);
		if (!try)
			break;

		if (try > strm_frm->len)
			try = strm_frm->len;
		memcpy(b_tail(buf), strm_frm->data, try);
		strm_frm->len -= try;
		strm_frm->offset_node.key += try;
		b_add(buf, try);
		ret += try;
	}

	return ret;
}

/* Process as much as possible RX STREAM frames received for <qcs> */
static size_t qc_treat_rx_strm_frms(struct qcs *qcs)
{
	int total;
	struct eb64_node *frm_node;

	total = 0;
	frm_node = eb64_first(&qcs->rx.frms);
	while (frm_node) {
		int ret;
		struct quic_rx_strm_frm *frm;

		frm = eb64_entry(&frm_node->node, struct quic_rx_strm_frm, offset_node);
		if (frm->offset_node.key != qcs->rx.offset)
			break;

		ret = qc_rx_strm_frm_cpy(&qcs->rx.buf, frm);
		qcs->rx.offset += ret;
		total += ret;
		if (frm->len) {
			/* If there is remaining data in this frame
			 * this is because the destination buffer is full.
			 */
			break;
		}

		frm_node = eb64_next(frm_node);
		quic_rx_packet_refdec(frm->pkt);
		eb64_delete(&frm->offset_node);
		pool_free(pool_head_quic_rx_strm_frm, frm);
	}

	return total;
}

/* Handle <strm_frm> bidirectional STREAM frame. Depending on its ID, several
 * streams may be open. The data are copied to the stream RX buffer if possible.
 * If not, the STREAM frame is stored to be treated again later.
 * We rely on the flow control so that not to store too much STREAM frames.
 * Return 1 if succeeded, 0 if not.
 */
static int qc_handle_bidi_strm_frm(struct quic_rx_packet *pkt,
                                   struct quic_stream *strm_frm,
                                   struct quic_conn *qc)
{
	int total;
	struct qcs *strm;
	struct eb64_node *strm_node;
	struct quic_rx_strm_frm *frm;

	strm_node = qcc_get_qcs(qc->qcc, strm_frm->id);
	if (!strm_node) {
		TRACE_PROTO("Stream not found", QUIC_EV_CONN_PSTRM, qc);
		return 0;
	}

	strm = eb64_entry(&strm_node->node, struct qcs, by_id);
	if (strm_frm->offset.key < strm->rx.offset) {
		size_t diff;

		if (strm_frm->offset.key + strm_frm->len <= strm->rx.offset) {
			TRACE_PROTO("Already received STREAM data",
			            QUIC_EV_CONN_PSTRM, qc);
			goto out;
		}

		TRACE_PROTO("Partially already received STREAM data", QUIC_EV_CONN_PSTRM, qc);
		diff = strm->rx.offset - strm_frm->offset.key;
		strm_frm->offset.key = strm->rx.offset;
		strm_frm->len -= diff;
		strm_frm->data += diff;
	}

	total = 0;
	if (strm_frm->offset.key == strm->rx.offset) {
		int ret;

		if (!qc_get_buf(strm, &strm->rx.buf)) {
		    goto store_frm;
		}

		ret = qc_strm_cpy(&strm->rx.buf, strm_frm);
		total += ret;
		strm->rx.offset += ret;
	}

	total += qc_treat_rx_strm_frms(strm);
	if (total && qc->qcc->app_ops->decode_qcs(strm, strm_frm->fin, qc->qcc->ctx) < 0) {
		TRACE_PROTO("Decoding error", QUIC_EV_CONN_PSTRM, qc);
		return 0;
	}

	if (!strm_frm->len)
		goto out;

 store_frm:
	frm = new_quic_rx_strm_frm(strm_frm, pkt);
	if (!frm) {
		TRACE_PROTO("Could not alloc RX STREAM frame",
					QUIC_EV_CONN_PSTRM, qc);
		return 0;
	}

	eb64_insert(&strm->rx.frms, &frm->offset_node);
	quic_rx_packet_refinc(pkt);

 out:
	return 1;
}

/* Handle <strm_frm> unidirectional STREAM frame. Depending on its ID, several
 * streams may be open. The data are copied to the stream RX buffer if possible.
 * If not, the STREAM frame is stored to be treated again later.
 * We rely on the flow control so that not to store too much STREAM frames.
 * Return 1 if succeeded, 0 if not.
 */
static int qc_handle_uni_strm_frm(struct quic_rx_packet *pkt,
                                  struct quic_stream *strm_frm,
                                  struct quic_conn *qc)
{
	struct qcs *strm;
	struct eb64_node *strm_node;
	struct quic_rx_strm_frm *frm;
	size_t strm_frm_len;

	strm_node = qcc_get_qcs(qc->qcc, strm_frm->id);
	if (!strm_node) {
		TRACE_PROTO("Stream not found", QUIC_EV_CONN_PSTRM, qc);
		return 0;
	}

	strm = eb64_entry(&strm_node->node, struct qcs, by_id);
	if (strm_frm->offset.key < strm->rx.offset) {
		size_t diff;

		if (strm_frm->offset.key + strm_frm->len <= strm->rx.offset) {
			TRACE_PROTO("Already received STREAM data",
			            QUIC_EV_CONN_PSTRM, qc);
			goto out;
		}

		TRACE_PROTO("Partially already received STREAM data", QUIC_EV_CONN_PSTRM, qc);
		diff = strm->rx.offset - strm_frm->offset.key;
		strm_frm->offset.key = strm->rx.offset;
		strm_frm->len -= diff;
		strm_frm->data += diff;
	}

	strm_frm_len = strm_frm->len;
	if (strm_frm->offset.key == strm->rx.offset) {
		int ret;

		if (!qc_get_buf(strm, &strm->rx.buf))
		    goto store_frm;

		/* qc_strm_cpy() will modify the offset, depending on the number
		 * of bytes copied.
		 */
		ret = qc_strm_cpy(&strm->rx.buf, strm_frm);
		/* Inform the application of the arrival of this new stream */
		if (!strm->rx.offset && !qc->qcc->app_ops->attach_ruqs(strm, qc->qcc->ctx)) {
			TRACE_PROTO("Could not set an uni-stream", QUIC_EV_CONN_PSTRM, qc);
			return 0;
		}

		if (ret)
			qcs_notify_recv(strm);

		strm_frm->offset.key += ret;
	}
	/* Take this frame into an account for the stream flow control */
	strm->rx.offset += strm_frm_len;
	/* It all the data were provided to the application, there is no need to
	 * store any more information for it.
	 */
	if (!strm_frm->len)
		goto out;

 store_frm:
	frm = new_quic_rx_strm_frm(strm_frm, pkt);
	if (!frm) {
		TRACE_PROTO("Could not alloc RX STREAM frame",
		            QUIC_EV_CONN_PSTRM, qc);
		return 0;
	}

	eb64_insert(&strm->rx.frms, &frm->offset_node);
	quic_rx_packet_refinc(pkt);

 out:
	return 1;
}

static inline int qc_handle_strm_frm(struct quic_rx_packet *pkt,
                                     struct quic_stream *strm_frm,
                                     struct quic_conn *qc)
{
	if (strm_frm->id & QCS_ID_DIR_BIT)
		return qc_handle_uni_strm_frm(pkt, strm_frm, qc);
	else
		return qc_handle_bidi_strm_frm(pkt, strm_frm, qc);
}

/* Prepare a fast retransmission from <qel> encryption level */
static void qc_prep_fast_retrans(struct quic_enc_level *qel,
                                 struct quic_conn *qc)
{
	struct eb_root *pkts = &qel->pktns->tx.pkts;
	struct eb64_node *node;
	struct quic_tx_packet *pkt;

	pkt = NULL;
	pkts = &qel->pktns->tx.pkts;
	node = eb64_first(pkts);
	/* Skip the empty packet (they have already been retransmitted) */
	while (node) {
		pkt = eb64_entry(&node->node, struct quic_tx_packet, pn_node);
		if (!LIST_ISEMPTY(&pkt->frms))
			break;
		node = eb64_next(node);
	}

	if (!pkt)
		return;

	qc_requeue_nacked_pkt_tx_frms(qc, &pkt->frms, &qel->pktns->tx.frms);
}

/* Prepare a fast retransmission during handshake after a client
 * has resent Initial packets. According to the RFC a server may retransmit
 * up to two datagrams of Initial packets if did not receive all Initial packets
 * and resend them coalescing with others (Handshake here).
 * (Listener only).
 */
static void qc_prep_hdshk_fast_retrans(struct quic_conn *qc)
{
	struct list itmp = LIST_HEAD_INIT(itmp);
	struct list htmp = LIST_HEAD_INIT(htmp);
	struct quic_frame *frm, *frmbak;

	struct quic_enc_level *iqel = &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL];
	struct quic_enc_level *hqel = &qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE];
	struct quic_enc_level *qel = iqel;
	struct eb_root *pkts;
	struct eb64_node *node;
	struct quic_tx_packet *pkt;
	struct list *tmp = &itmp;

 start:
	pkt = NULL;
	pkts = &qel->pktns->tx.pkts;
	node = eb64_first(pkts);
	/* Skip the empty packet (they have already been retransmitted) */
	while (node) {
		pkt = eb64_entry(&node->node, struct quic_tx_packet, pn_node);
		if (!LIST_ISEMPTY(&pkt->frms))
			break;
		node = eb64_next(node);
	}

	if (!pkt)
		goto end;

	qel->pktns->tx.pto_probe += 1;
 requeue:
	list_for_each_entry_safe(frm, frmbak, &pkt->frms, list) {
		TRACE_PROTO("to resend frame", QUIC_EV_CONN_PRSAFRM, qc, frm);
		LIST_DELETE(&frm->list);
		LIST_APPEND(tmp, &frm->list);
	}

	if (qel == iqel) {
		if (pkt->next && pkt->next->type == QUIC_PACKET_TYPE_HANDSHAKE) {
			pkt = pkt->next;
			tmp = &htmp;
			hqel->pktns->tx.pto_probe += 1;
			goto requeue;
		}

		qel = hqel;
		tmp = &htmp;
		goto start;
	}

 end:
	LIST_SPLICE(&iqel->pktns->tx.frms, &itmp);
	LIST_SPLICE(&hqel->pktns->tx.frms, &htmp);
}

/* Parse all the frames of <pkt> QUIC packet for QUIC connection with <ctx>
 * as I/O handler context and <qel> as encryption level.
 * Returns 1 if succeeded, 0 if failed.
 */
static int qc_parse_pkt_frms(struct quic_rx_packet *pkt, struct ssl_sock_ctx *ctx,
                             struct quic_enc_level *qel)
{
	struct quic_frame frm;
	const unsigned char *pos, *end;
	struct quic_conn *qc = ctx->qc;
	int fast_retrans = 0;

	TRACE_ENTER(QUIC_EV_CONN_PRSHPKT, qc);
	/* Skip the AAD */
	pos = pkt->data + pkt->aad_len;
	end = pkt->data + pkt->len;

	while (pos < end) {
		if (!qc_parse_frm(&frm, pkt, &pos, end, qc))
			goto err;

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
			if (!qc_parse_ack_frm(qc, &frm, qel, &rtt_sample, &pos, end))
				goto err;

			if (rtt_sample) {
				unsigned int ack_delay;

				ack_delay = !quic_application_pktns(qel->pktns, qc) ? 0 :
					HA_ATOMIC_LOAD(&qc->state) >= QUIC_HS_ST_CONFIRMED ?
					MS_TO_TICKS(QUIC_MIN(quic_ack_delay_ms(&frm.ack, qc), qc->max_ack_delay)) :
					MS_TO_TICKS(quic_ack_delay_ms(&frm.ack, qc));
				quic_loss_srtt_update(&qc->path->loss, rtt_sample, ack_delay, qc);
			}
			break;
		}
		case QUIC_FT_STOP_SENDING:
			break;
		case QUIC_FT_CRYPTO:
		{
			struct quic_rx_crypto_frm *cf;

			if (unlikely(qel->tls_ctx.rx.flags & QUIC_FL_TLS_SECRETS_DCD)) {
				/* XXX TO DO: <cfdebug> is used only for the traces. */
				struct quic_rx_crypto_frm cfdebug = { };

				cfdebug.offset_node.key = frm.crypto.offset;
				cfdebug.len = frm.crypto.len;
				TRACE_PROTO("CRYPTO data discarded",
				            QUIC_EV_CONN_ELRXPKTS, qc, pkt, &cfdebug);
				break;
			}

			if (unlikely(frm.crypto.offset < qel->rx.crypto.offset)) {
				if (frm.crypto.offset + frm.crypto.len <= qel->rx.crypto.offset) {
					/* XXX TO DO: <cfdebug> is used only for the traces. */
					struct quic_rx_crypto_frm cfdebug = { };

					cfdebug.offset_node.key = frm.crypto.offset;
					cfdebug.len = frm.crypto.len;
					/* Nothing to do */
					TRACE_PROTO("Already received CRYPTO data",
					            QUIC_EV_CONN_ELRXPKTS, qc, pkt, &cfdebug);
					if (qc_is_listener(ctx->qc) &&
					    qel == &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL])
						fast_retrans = 1;
					break;
				}
				else {
					size_t diff = qel->rx.crypto.offset - frm.crypto.offset;
					/* XXX TO DO: <cfdebug> is used only for the traces. */
					struct quic_rx_crypto_frm cfdebug = { };

					cfdebug.offset_node.key = frm.crypto.offset;
					cfdebug.len = frm.crypto.len;
					TRACE_PROTO("Partially already received CRYPTO data",
					            QUIC_EV_CONN_ELRXPKTS, qc, pkt, &cfdebug);
					frm.crypto.len -= diff;
					frm.crypto.data += diff;
					frm.crypto.offset = qel->rx.crypto.offset;
				}
			}

			if (frm.crypto.offset == qel->rx.crypto.offset) {
				/* XXX TO DO: <cf> is used only for the traces. */
				struct quic_rx_crypto_frm cfdebug = { };

				cfdebug.offset_node.key = frm.crypto.offset;
				cfdebug.len = frm.crypto.len;
				if (!qc_provide_cdata(qel, ctx,
				                      frm.crypto.data, frm.crypto.len,
				                      pkt, &cfdebug))
					goto err;

				break;
			}

			/* frm.crypto.offset > qel->rx.crypto.offset */
			cf = pool_alloc(pool_head_quic_rx_crypto_frm);
			if (!cf) {
				TRACE_DEVEL("CRYPTO frame allocation failed",
				            QUIC_EV_CONN_PRSHPKT, qc);
				goto err;
			}

			cf->offset_node.key = frm.crypto.offset;
			cf->len = frm.crypto.len;
			cf->data = frm.crypto.data;
			cf->pkt = pkt;
			eb64_insert(&qel->rx.crypto.frms, &cf->offset_node);
			quic_rx_packet_refinc(pkt);
			break;
		}
		case QUIC_FT_STREAM_8 ... QUIC_FT_STREAM_F:
		{
			struct quic_stream *stream = &frm.stream;

			if (qc_is_listener(ctx->qc)) {
				if (stream->id & QUIC_STREAM_FRAME_ID_INITIATOR_BIT)
					goto err;
			} else if (!(stream->id & QUIC_STREAM_FRAME_ID_INITIATOR_BIT))
				goto err;

			if (!qc_handle_strm_frm(pkt, stream, qc))
				goto err;

			break;
		}
		case QUIC_FT_MAX_DATA:
		case QUIC_FT_MAX_STREAM_DATA:
		case QUIC_FT_MAX_STREAMS_BIDI:
		case QUIC_FT_MAX_STREAMS_UNI:
		case QUIC_FT_DATA_BLOCKED:
		case QUIC_FT_STREAM_DATA_BLOCKED:
		case QUIC_FT_STREAMS_BLOCKED_BIDI:
		case QUIC_FT_STREAMS_BLOCKED_UNI:
			break;
		case QUIC_FT_NEW_CONNECTION_ID:
		case QUIC_FT_RETIRE_CONNECTION_ID:
			/* XXX TO DO XXX */
			break;
		case QUIC_FT_CONNECTION_CLOSE:
		case QUIC_FT_CONNECTION_CLOSE_APP:
			/* warn the mux to close the connection */
			qc->qcc->flags |= QC_CF_CC_RECV;
			tasklet_wakeup(qc->qcc->wait_event.tasklet);
			break;
		case QUIC_FT_HANDSHAKE_DONE:
			if (qc_is_listener(ctx->qc))
				goto err;

			HA_ATOMIC_STORE(&qc->state, QUIC_HS_ST_CONFIRMED);
			break;
		default:
			goto err;
		}
	}

	if (fast_retrans)
		qc_prep_hdshk_fast_retrans(qc);

	/* The server must switch from INITIAL to HANDSHAKE handshake state when it
	 * has successfully parse a Handshake packet. The Initial encryption must also
	 * be discarded.
	 */
	if (pkt->type == QUIC_PACKET_TYPE_HANDSHAKE && qc_is_listener(ctx->qc)) {
	    int state = HA_ATOMIC_LOAD(&qc->state);

	    if (state >= QUIC_HS_ST_SERVER_INITIAL) {
		    quic_tls_discard_keys(&qc->els[QUIC_TLS_ENC_LEVEL_INITIAL]);
		    TRACE_PROTO("discarding Initial pktns", QUIC_EV_CONN_PRSHPKT, qc);
		    quic_pktns_discard(qc->els[QUIC_TLS_ENC_LEVEL_INITIAL].pktns, qc);
		    qc_set_timer(ctx->qc);
		    qc_el_rx_pkts_del(&qc->els[QUIC_TLS_ENC_LEVEL_INITIAL]);
		    qc_release_pktns_frms(qc->els[QUIC_TLS_ENC_LEVEL_INITIAL].pktns);
		    if (state < QUIC_HS_ST_SERVER_HANDSHAKE)
			    HA_ATOMIC_STORE(&qc->state, QUIC_HS_ST_SERVER_HANDSHAKE);
	    }
	}

	TRACE_LEAVE(QUIC_EV_CONN_PRSHPKT, qc);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_PRSHPKT, qc);
	return 0;
}

/* Write <dglen> datagram length and <pkt> first packet address into <cbuf> ring
 * buffer. This is the responsibility of the caller to check there is enough
 * room in <cbuf>. Also increase the <cbuf> write index consequently.
 * This function must be called only after having built a correct datagram.
 * Always succeeds.
 */
static inline void qc_set_dg(struct cbuf *cbuf,
                             uint16_t dglen, struct quic_tx_packet *pkt)
{
	write_u16(cb_wr(cbuf), dglen);
	write_ptr(cb_wr(cbuf) + sizeof dglen, pkt);
	cb_add(cbuf, dglen + sizeof dglen + sizeof pkt);
}

/* Prepare as much as possible packets into <qr> ring buffer for
 * the QUIC connection with <ctx> as I/O handler context, possibly concatenating
 * several packets in the same datagram. A header made of two fields is added
 * to each datagram: the datagram length followed by the address of the first
 * packet in this datagram.
 * Returns 1 if succeeded, or 0 if something wrong happened.
 */
static int qc_prep_pkts(struct quic_conn *qc, struct qring *qr,
                        enum quic_tls_enc_level tel,
                        enum quic_tls_enc_level next_tel)
{
	struct quic_enc_level *qel;
	struct cbuf *cbuf;
	unsigned char *end_buf, *end, *pos, *spos;
	struct quic_tx_packet *first_pkt, *cur_pkt, *prv_pkt;
	/* length of datagrams */
	uint16_t dglen;
	size_t total;
	int padding;
	/* Each datagram is prepended with its length followed by the
	 * address of the first packet in the datagram.
	 */
	size_t dg_headlen = sizeof dglen + sizeof first_pkt;

	TRACE_ENTER(QUIC_EV_CONN_PHPKTS, qc);

	total = 0;
 start:
	dglen = 0;
	padding = 0;
	qel = &qc->els[tel];
	cbuf = qr->cbuf;
	spos = pos = cb_wr(cbuf);
	/* Leave at least <dglen> bytes at the end of this buffer
	 * to ensure there is enough room to mark the end of prepared
	 * contiguous data with a zero length.
	 */
	end_buf = pos + cb_contig_space(cbuf) - sizeof dglen;
	first_pkt = prv_pkt = NULL;
	while (end_buf - pos >= (int)qc->path->mtu + dg_headlen || prv_pkt) {
		int err, probe, ack, cc;
		enum quic_pkt_type pkt_type;

		TRACE_POINT(QUIC_EV_CONN_PHPKTS, qc, qel);
		probe = ack = 0;
		cc =  HA_ATOMIC_LOAD(&qc->flags) & QUIC_FL_CONN_IMMEDIATE_CLOSE;
		if (!cc) {
			probe = qel->pktns->tx.pto_probe;
			ack = HA_ATOMIC_BTR(&qel->pktns->flags, QUIC_FL_PKTNS_ACK_REQUIRED_BIT);
		}
		/* Do not build any more packet if the TX secrets are not available or
		 * if there is nothing to send, i.e. if no CONNECTION_CLOSE or ACK are required
		 * and if there is no more packets to send upon PTO expiration
		 * and if there is no more CRYPTO data available or in flight
		 * congestion control limit is reached for prepared data
		 */
		if (!(qel->tls_ctx.tx.flags & QUIC_FL_TLS_SECRETS_SET) ||
		    (!cc && !ack && !probe &&
		     (LIST_ISEMPTY(&qel->pktns->tx.frms) ||
		      qc->path->prep_in_flight >= qc->path->cwnd))) {
			TRACE_DEVEL("nothing more to do", QUIC_EV_CONN_PHPKTS, qc);
			/* Set the current datagram as prepared into <cbuf> if
			 * the was already a correct packet which was previously written.
			 */
			if (prv_pkt)
				qc_set_dg(cbuf, dglen, first_pkt);
			/* Let's select the next encryption level */
			if (tel != next_tel && next_tel != QUIC_TLS_ENC_LEVEL_NONE) {
				tel = next_tel;
				qel = &qc->els[tel];
				/* Build a new datagram */
				prv_pkt = NULL;
				continue;
			}
			break;
		}

		pkt_type = quic_tls_level_pkt_type(tel);
		if (!prv_pkt) {
			/* Leave room for the datagram header */
			pos += dg_headlen;
			if (!quic_peer_validated_addr(qc) && qc_is_listener(qc)) {
				end = pos + QUIC_MIN(qc->path->mtu, 3 * qc->rx.bytes - qc->tx.prep_bytes);
			}
			else {
				end = pos + qc->path->mtu;
			}
		}

		cur_pkt = qc_build_pkt(&pos, end, qel, qc, dglen, padding,
		                       pkt_type, ack, probe, cc, &err);
		/* Restore the PTO dgrams counter if a packet could not be built */
		if (err < 0) {
			if (ack)
				HA_ATOMIC_BTS(&qel->pktns->flags, QUIC_FL_PKTNS_ACK_REQUIRED_BIT);
		}
		switch (err) {
		case -2:
			goto err;
		case -1:
			/* If there was already a correct packet present, set the
			 * current datagram as prepared into <cbuf>.
			 */
			if (prv_pkt) {
				qc_set_dg(cbuf, dglen, first_pkt);
				goto stop_build;
			}
			goto out;
		default:
			break;
		}

		/* This is to please to GCC. We cannot have (err >= 0 && !cur_pkt) */
		if (!cur_pkt)
			goto err;

		total += cur_pkt->len;
		/* keep trace of the first packet in the datagram */
		if (!first_pkt)
			first_pkt = cur_pkt;
		/* Attach the current one to the previous one */
		if (prv_pkt)
			prv_pkt->next = cur_pkt;
		/* Let's say we have to build a new dgram */
		prv_pkt = NULL;
		dglen += cur_pkt->len;
		/* Client: discard the Initial encryption keys as soon as
		 * a handshake packet could be built.
		 */
		if (HA_ATOMIC_LOAD(&qc->state) == QUIC_HS_ST_CLIENT_INITIAL &&
		    pkt_type == QUIC_PACKET_TYPE_HANDSHAKE) {
			quic_tls_discard_keys(&qc->els[QUIC_TLS_ENC_LEVEL_INITIAL]);
			TRACE_PROTO("discarding Initial pktns", QUIC_EV_CONN_PHPKTS, qc);
			quic_pktns_discard(qc->els[QUIC_TLS_ENC_LEVEL_INITIAL].pktns, qc);
			qc_set_timer(qc);
			qc_el_rx_pkts_del(&qc->els[QUIC_TLS_ENC_LEVEL_INITIAL]);
			qc_release_pktns_frms(qc->els[QUIC_TLS_ENC_LEVEL_INITIAL].pktns);
			HA_ATOMIC_STORE(&qc->state, QUIC_HS_ST_CLIENT_HANDSHAKE);
		}
		/* If the data for the current encryption level have all been sent,
		 * select the next level.
		 */
		if ((tel == QUIC_TLS_ENC_LEVEL_INITIAL || tel == QUIC_TLS_ENC_LEVEL_HANDSHAKE) &&
		    (LIST_ISEMPTY(&qel->pktns->tx.frms))) {
			/* If QUIC_TLS_ENC_LEVEL_HANDSHAKE was already reached let's try QUIC_TLS_ENC_LEVEL_APP */
			if (tel == QUIC_TLS_ENC_LEVEL_HANDSHAKE && next_tel == tel)
				next_tel = QUIC_TLS_ENC_LEVEL_APP;
			tel = next_tel;
			qel = &qc->els[tel];
			if (!LIST_ISEMPTY(&qel->pktns->tx.frms)) {
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
			qc_set_dg(cbuf, dglen, first_pkt);
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

 stop_build:
	/* Reset <wr> writer index if in front of <rd> index */
	if (end_buf - pos < (int)qc->path->mtu + dg_headlen) {
		int rd = HA_ATOMIC_LOAD(&cbuf->rd);

		TRACE_DEVEL("buffer full", QUIC_EV_CONN_PHPKTS, qc);
		if (cb_contig_space(cbuf) >= sizeof(uint16_t)) {
			if ((pos != spos && cbuf->wr > rd) || (pos == spos && rd <= cbuf->wr)) {
				/* Mark the end of contiguous data for the reader */
				write_u16(cb_wr(cbuf), 0);
				cb_add(cbuf, sizeof(uint16_t));
			}
		}

	    if (rd && rd <= cbuf->wr) {
			cb_wr_reset(cbuf);
			/* Let's try to reuse this buffer */
			goto start;
		}
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_PHPKTS, qc);
	return total;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_PHPKTS, qc);
	return -1;
}

/* Send the QUIC packets which have been prepared for QUIC connections
 * from <qr> ring buffer with <ctx> as I/O handler context.
 */
int qc_send_ppkts(struct qring *qr, struct ssl_sock_ctx *ctx)
{
	struct quic_conn *qc;
	struct cbuf *cbuf;

	qc = ctx->qc;
	cbuf = qr->cbuf;
	while (cb_contig_data(cbuf)) {
		unsigned char *pos;
		struct buffer tmpbuf = { };
		struct quic_tx_packet *first_pkt, *pkt, *next_pkt;
		uint16_t dglen;
		size_t headlen = sizeof dglen + sizeof first_pkt;
		unsigned int time_sent;

		pos = cb_rd(cbuf);
		dglen = read_u16(pos);
		/* End of prepared datagrams.
		 * Reset the reader index only if in front of the writer index.
		 */
		if (!dglen) {
			int wr = HA_ATOMIC_LOAD(&cbuf->wr);

			if (wr && wr < cbuf->rd) {
				cb_rd_reset(cbuf);
				continue;
			}
			break;
		}

		pos += sizeof dglen;
		first_pkt = read_ptr(pos);
		pos += sizeof first_pkt;
		tmpbuf.area = (char *)pos;
		tmpbuf.size = tmpbuf.data = dglen;

		TRACE_PROTO("to send", QUIC_EV_CONN_SPPKTS, qc);
		for (pkt = first_pkt; pkt; pkt = pkt->next)
			quic_tx_packet_refinc(pkt);
		if (ctx->xprt->snd_buf(NULL, qc->xprt_ctx,
		                       &tmpbuf, tmpbuf.data, 0) <= 0) {
			for (pkt = first_pkt; pkt; pkt = pkt->next)
				quic_tx_packet_refdec(pkt);
			break;
		}

		cb_del(cbuf, dglen + headlen);
		qc->tx.bytes += tmpbuf.data;
		time_sent = now_ms;

		for (pkt = first_pkt; pkt; pkt = next_pkt) {
			pkt->time_sent = time_sent;
			if (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING) {
				pkt->pktns->tx.time_of_last_eliciting = time_sent;
				qc->path->ifae_pkts++;
			}
			qc->path->in_flight += pkt->in_flight_len;
			pkt->pktns->tx.in_flight += pkt->in_flight_len;
			if (pkt->in_flight_len)
				qc_set_timer(qc);
			TRACE_PROTO("sent pkt", QUIC_EV_CONN_SPPKTS, qc, pkt);
			next_pkt = pkt->next;
			eb64_insert(&pkt->pktns->tx.pkts, &pkt->pn_node);
			quic_tx_packet_refdec(pkt);
		}
	}

	return 1;
}

/* Build all the frames which must be sent just after the handshake have succeeded.
 * This is essentially NEW_CONNECTION_ID frames. A QUIC server must also send
 * a HANDSHAKE_DONE frame.
 * Return 1 if succeeded, 0 if not.
 */
static int quic_build_post_handshake_frames(struct quic_conn *qc)
{
	int i;
	struct quic_enc_level *qel;
	struct quic_frame *frm;

	qel = &qc->els[QUIC_TLS_ENC_LEVEL_APP];
	/* Only servers must send a HANDSHAKE_DONE frame. */
	if (qc_is_listener(qc)) {
		frm = pool_alloc(pool_head_quic_frame);
		if (!frm)
			return 0;

		frm->type = QUIC_FT_HANDSHAKE_DONE;
		LIST_APPEND(&qel->pktns->tx.frms, &frm->list);
	}

	for (i = 1; i < qc->tx.params.active_connection_id_limit; i++) {
		struct quic_connection_id *cid;
		struct listener *l = qc->li;

		frm = pool_alloc(pool_head_quic_frame);
		if (!frm)
			goto err;

		cid = new_quic_cid(&qc->cids, qc, i);
		if (!cid)
			goto err;

		/* insert the allocated CID in the receiver tree */
		HA_RWLOCK_WRLOCK(QUIC_LOCK, &l->rx.cids_lock);
		ebmb_insert(&l->rx.cids, &cid->node, cid->cid.len);
		HA_RWLOCK_WRUNLOCK(QUIC_LOCK, &l->rx.cids_lock);

		quic_connection_id_to_frm_cpy(frm, cid);
		LIST_APPEND(&qel->pktns->tx.frms, &frm->list);
	}
	HA_ATOMIC_OR(&qc->flags, QUIC_FL_POST_HANDSHAKE_FRAMES_BUILT);

    return 1;

 err:
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

/* Insert <ar> ack range into <argns> tree of ack ranges.
 * Returns the ack range node which has been inserted if succeeded, NULL if not.
 */
static inline
struct quic_arng_node *quic_insert_new_range(struct quic_arngs *arngs,
                                             struct quic_arng *ar)
{
	struct quic_arng_node *new_ar;

	new_ar = pool_alloc(pool_head_quic_arng);
	if (new_ar) {
		new_ar->first.key = ar->first;
		new_ar->last = ar->last;
		eb64_insert(&arngs->root, &new_ar->first);
		arngs->sz++;
	}

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
 */
int quic_update_ack_ranges_list(struct quic_arngs *arngs,
                                struct quic_arng *ar)
{
	struct eb64_node *le;
	struct quic_arng_node *new_node;
	struct eb64_node *new;

	new = NULL;
	if (eb_is_empty(&arngs->root)) {
		new_node = quic_insert_new_range(arngs, ar);
		if (!new_node)
			return 0;

		goto out;
	}

	le = eb64_lookup_le(&arngs->root, ar->first);
	if (!le) {
		new_node = quic_insert_new_range(arngs, ar);
		if (!new_node)
			return 0;

		new = &new_node->first;
	}
	else {
		struct quic_arng_node *le_ar =
			eb64_entry(&le->node, struct quic_arng_node, first);

		/* Already existing range */
		if (le_ar->last >= ar->last)
			return 1;

		if (le_ar->last + 1 >= ar->first) {
			le_ar->last = ar->last;
			new = le;
			new_node = le_ar;
		}
		else {
			new_node = quic_insert_new_range(arngs, ar);
			if (!new_node)
				return 0;

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
				eb64_entry(&next->node, struct quic_arng_node, first);
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

 out:
	quic_arngs_set_enc_sz(arngs);

	return 1;
}
/* Remove the header protection of packets at <el> encryption level.
 * Always succeeds.
 */
static inline void qc_rm_hp_pkts(struct quic_conn *qc, struct quic_enc_level *el)
{
	struct quic_tls_ctx *tls_ctx;
	struct quic_rx_packet *pqpkt;
	struct mt_list *pkttmp1, pkttmp2;
	struct quic_enc_level *app_qel;

	TRACE_ENTER(QUIC_EV_CONN_ELRMHP, qc);
	app_qel = &qc->els[QUIC_TLS_ENC_LEVEL_APP];
	/* A server must not process incoming 1-RTT packets before the handshake is complete. */
	if (el == app_qel && qc_is_listener(qc) &&
	    HA_ATOMIC_LOAD(&qc->state) < QUIC_HS_ST_COMPLETE) {
		TRACE_PROTO("hp not removed (handshake not completed)",
		            QUIC_EV_CONN_ELRMHP, qc);
		goto out;
	}
	tls_ctx = &el->tls_ctx;
	mt_list_for_each_entry_safe(pqpkt, &el->rx.pqpkts, list, pkttmp1, pkttmp2) {
		if (!qc_do_rm_hp(qc, pqpkt, tls_ctx, el->pktns->rx.largest_pn,
		                 pqpkt->data + pqpkt->pn_offset,
		                 pqpkt->data, pqpkt->data + pqpkt->len)) {
			TRACE_PROTO("hp removing error", QUIC_EV_CONN_ELRMHP, qc);
			/* XXX TO DO XXX */
		}
		else {
			/* The AAD includes the packet number field */
			pqpkt->aad_len = pqpkt->pn_offset + pqpkt->pnl;
			/* Store the packet into the tree of packets to decrypt. */
			pqpkt->pn_node.key = pqpkt->pn;
			HA_RWLOCK_WRLOCK(QUIC_LOCK, &el->rx.pkts_rwlock);
			eb64_insert(&el->rx.pkts, &pqpkt->pn_node);
			quic_rx_packet_refinc(pqpkt);
			HA_RWLOCK_WRUNLOCK(QUIC_LOCK, &el->rx.pkts_rwlock);
			TRACE_PROTO("hp removed", QUIC_EV_CONN_ELRMHP, qc, pqpkt);
		}
		MT_LIST_DELETE_SAFE(pkttmp1);
		quic_rx_packet_refdec(pqpkt);
	}

  out:
	TRACE_LEAVE(QUIC_EV_CONN_ELRMHP, qc);
}

/* Process all the CRYPTO frame at <el> encryption level.
 * Return 1 if succeeded, 0 if not.
 */
static inline int qc_treat_rx_crypto_frms(struct quic_enc_level *el,
                                          struct ssl_sock_ctx *ctx)
{
	struct eb64_node *node;

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
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_RXCDATA, ctx->qc);
	return 0;
}

/* Process all the packets at <el> and <next_el> encryption level.
 * This is the caller responsibility to check that <cur_el> is different of <next_el>
 * as pointer value.
 * Return 1 if succeeded, 0 if not.
 */
int qc_treat_rx_pkts(struct quic_enc_level *cur_el, struct quic_enc_level *next_el,
                     struct ssl_sock_ctx *ctx, int force_ack)
{
	struct eb64_node *node;
	int64_t largest_pn = -1;
	struct quic_conn *qc = ctx->qc;
	struct quic_enc_level *qel = cur_el;

	TRACE_ENTER(QUIC_EV_CONN_ELRXPKTS, ctx->qc);
	qel = cur_el;
 next_tel:
	if (!qel)
		goto out;

	HA_RWLOCK_WRLOCK(QUIC_LOCK, &qel->rx.pkts_rwlock);
	node = eb64_first(&qel->rx.pkts);
	while (node) {
		struct quic_rx_packet *pkt;

		pkt = eb64_entry(&node->node, struct quic_rx_packet, pn_node);
		TRACE_PROTO("new packet", QUIC_EV_CONN_ELRXPKTS,
		            ctx->qc, pkt, NULL, ctx->ssl);
		if (!qc_pkt_decrypt(pkt, qel)) {
			/* Drop the packet */
			TRACE_PROTO("packet decryption failed -> dropped",
			            QUIC_EV_CONN_ELRXPKTS, ctx->qc, pkt);
		}
		else {
			if (!qc_parse_pkt_frms(pkt, ctx, qel)) {
				/* Drop the packet */
				TRACE_PROTO("packet parsing failed -> dropped",
				            QUIC_EV_CONN_ELRXPKTS, ctx->qc, pkt);
			}
			else {
				struct quic_arng ar = { .first = pkt->pn, .last = pkt->pn };

				if (pkt->flags & QUIC_FL_RX_PACKET_ACK_ELICITING &&
				    (!(HA_ATOMIC_ADD_FETCH(&qc->rx.nb_ack_eliciting, 1) & 1) || force_ack))
					HA_ATOMIC_BTS(&qel->pktns->flags, QUIC_FL_PKTNS_ACK_REQUIRED_BIT);
				if (pkt->pn > largest_pn)
					largest_pn = pkt->pn;
				/* Update the list of ranges to acknowledge. */
				if (!quic_update_ack_ranges_list(&qel->pktns->rx.arngs, &ar))
					TRACE_DEVEL("Could not update ack range list",
					            QUIC_EV_CONN_ELRXPKTS, ctx->qc);
			}
		}
		node = eb64_next(node);
		eb64_delete(&pkt->pn_node);
		quic_rx_packet_refdec(pkt);
	}
	HA_RWLOCK_WRUNLOCK(QUIC_LOCK, &qel->rx.pkts_rwlock);

	/* Update the largest packet number. */
	if (largest_pn != -1)
		HA_ATOMIC_UPDATE_MAX(&qel->pktns->rx.largest_pn, largest_pn);
	if (!qc_treat_rx_crypto_frms(qel, ctx))
		goto err;

	if (qel == cur_el) {
		BUG_ON(qel == next_el);
		qel = next_el;
		goto next_tel;
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_ELRXPKTS, ctx->qc);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_ELRXPKTS, ctx->qc);
	return 0;
}

/* Check if it's possible to remove header protection for packets related to
 * encryption level <qel>. If <qel> is NULL, assume it's false.
 *
 * Return true if the operation is possible else false.
 */
static int qc_qel_may_rm_hp(struct quic_conn *qc, struct quic_enc_level *qel)
{
	enum quic_tls_enc_level tel;

	if (!qel)
		return 0;

	tel = ssl_to_quic_enc_level(qel->level);

	/* check if tls secrets are available */
	if (qel->tls_ctx.rx.flags & QUIC_FL_TLS_SECRETS_DCD)
		TRACE_DEVEL("Discarded keys", QUIC_EV_CONN_TRMHP, qc);

	if (!(qel->tls_ctx.rx.flags & QUIC_FL_TLS_SECRETS_SET))
		return 0;

	/* check if the connection layer is ready before using app level */
	if (tel == QUIC_TLS_ENC_LEVEL_APP && qc->mux_state != QC_MUX_READY)
		return 0;

	return 1;
}

/* QUIC connection packet handler task. */
struct task *quic_conn_io_cb(struct task *t, void *context, unsigned int state)
{
	int ret, ssl_err;
	struct ssl_sock_ctx *ctx;
	struct quic_conn *qc;
	enum quic_tls_enc_level tel, next_tel;
	struct quic_enc_level *qel, *next_qel;
	struct qring *qr; // Tx ring
	int st, force_ack, zero_rtt;

	ctx = context;
	qc = ctx->qc;
	TRACE_ENTER(QUIC_EV_CONN_HDSHK, qc);
	qr = NULL;
	st = HA_ATOMIC_LOAD(&qc->state);
	TRACE_PROTO("state", QUIC_EV_CONN_HDSHK, qc, &st);
	if (HA_ATOMIC_LOAD(&qc->flags) & QUIC_FL_CONN_IO_CB_WAKEUP) {
		HA_ATOMIC_BTR(&qc->flags, QUIC_FL_CONN_IO_CB_WAKEUP_BIT);
		/* The I/O handler has been woken up by the dgram listener
		 * after the anti-amplification was reached.
		 */
		qc_set_timer(qc);
		if (tick_isset(qc->timer) && tick_is_lt(qc->timer, now_ms))
			task_wakeup(qc->timer_task, TASK_WOKEN_MSG);
	}
	ssl_err = SSL_ERROR_NONE;
	zero_rtt = st < QUIC_HS_ST_COMPLETE &&
		(!MT_LIST_ISEMPTY(&qc->els[QUIC_TLS_ENC_LEVEL_EARLY_DATA].rx.pqpkts) ||
		qc_el_rx_pkts(&qc->els[QUIC_TLS_ENC_LEVEL_EARLY_DATA]));
 start:
	if (st >= QUIC_HS_ST_COMPLETE &&
	    qc_el_rx_pkts(&qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE])) {
		TRACE_PROTO("remaining Handshake packets", QUIC_EV_CONN_PHPKTS, qc);
		/* There may be remaining Handshake packets to treat and acknowledge. */
		tel = QUIC_TLS_ENC_LEVEL_HANDSHAKE;
		next_tel = QUIC_TLS_ENC_LEVEL_APP;
	}
	else if (!quic_get_tls_enc_levels(&tel, &next_tel, st, zero_rtt))
		goto err;

	qel = &qc->els[tel];
	next_qel = next_tel == QUIC_TLS_ENC_LEVEL_NONE ? NULL : &qc->els[next_tel];

 next_level:
	/* Treat packets waiting for header packet protection decryption */
	if (!MT_LIST_ISEMPTY(&qel->rx.pqpkts) && qc_qel_may_rm_hp(qc, qel))
		qc_rm_hp_pkts(qc, qel);

	force_ack = qel == &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL] ||
		qel == &qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE];
	if (!qc_treat_rx_pkts(qel, next_qel, ctx, force_ack))
		goto err;

	if (zero_rtt && next_qel && !MT_LIST_ISEMPTY(&next_qel->rx.pqpkts) &&
	    (next_qel->tls_ctx.rx.flags & QUIC_FL_TLS_SECRETS_SET)) {
		qel = next_qel;
		next_qel = NULL;
		goto next_level;
	}

	st = HA_ATOMIC_LOAD(&qc->state);
	if (st >= QUIC_HS_ST_COMPLETE) {
		if (!(HA_ATOMIC_LOAD(&qc->flags) & QUIC_FL_POST_HANDSHAKE_FRAMES_BUILT) &&
		    !quic_build_post_handshake_frames(qc))
			goto err;

		if (!(qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE].tls_ctx.rx.flags &
		           QUIC_FL_TLS_SECRETS_DCD)) {
			/* Discard the Handshake keys. */
			quic_tls_discard_keys(&qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE]);
			TRACE_PROTO("discarding Handshake pktns", QUIC_EV_CONN_PHPKTS, qc);
			quic_pktns_discard(qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE].pktns, qc);
			qc_set_timer(qc);
			qc_el_rx_pkts_del(&qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE]);
			qc_release_pktns_frms(qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE].pktns);
		}

		if (qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE].pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) {
			/* There may be remaining handshake to build (acks) */
			st = QUIC_HS_ST_SERVER_HANDSHAKE;
		}
	}

	if (!qr)
		qr = MT_LIST_POP(qc->tx.qring_list, typeof(qr), mt_list);
	/* A listener does not send any O-RTT packet. O-RTT packet number space must not
	 * be considered.
	 */
	if (!quic_get_tls_enc_levels(&tel, &next_tel, st, 0))
		goto err;
	ret = qc_prep_pkts(qc, qr, tel, next_tel);
	if (ret == -1)
		goto err;
	else if (ret == 0)
		goto skip_send;

	if (!qc_send_ppkts(qr, ctx))
		goto err;

 skip_send:
	/* Check if there is something to do for the next level.
	 */
	if (next_qel && next_qel != qel &&
	    (next_qel->tls_ctx.rx.flags & QUIC_FL_TLS_SECRETS_SET) &&
	    (!MT_LIST_ISEMPTY(&next_qel->rx.pqpkts) || qc_el_rx_pkts(next_qel))) {
		qel = next_qel;
		next_qel = NULL;
		goto next_level;
	}

	MT_LIST_APPEND(qc->tx.qring_list, &qr->mt_list);
	TRACE_LEAVE(QUIC_EV_CONN_HDSHK, qc, &st);
	return t;

 err:
	if (qr)
		MT_LIST_APPEND(qc->tx.qring_list, &qr->mt_list);
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_HDSHK, qc, &st, &ssl_err);
	return t;
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
	ha_free(&qel->tx.crypto.bufs);
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
	qel->tls_ctx.flags = 0;

	qel->rx.pkts = EB_ROOT;
	HA_RWLOCK_INIT(&qel->rx.pkts_rwlock);
	MT_LIST_INIT(&qel->rx.pqpkts);
	qel->rx.crypto.offset = 0;
	qel->rx.crypto.frms = EB_ROOT_UNIQUE;

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
	ha_free(&qel->tx.crypto.bufs);
	return 0;
}

/* Increment the <qc> refcount.
 *
 * This operation must be conducted when manipulating the quic_conn outside of
 * the connection pinned thread. These threads can only retrieve the connection
 * in the CID tree, so this function must be conducted under the CID lock.
 */
static inline void quic_conn_take(struct quic_conn *qc)
{
	HA_ATOMIC_INC(&qc->refcount);
}

/* Decrement the <qc> refcount. If the refcount is zero *BEFORE* the
 * subtraction, the quic_conn is freed.
 */
static void quic_conn_drop(struct quic_conn *qc)
{
	struct ssl_sock_ctx *conn_ctx;
	int i;

	if (!qc)
		return;

	if (HA_ATOMIC_FETCH_SUB(&qc->refcount, 1))
		return;

	conn_ctx = HA_ATOMIC_LOAD(&qc->xprt_ctx);
	if (conn_ctx) {
		SSL_free(conn_ctx->ssl);
		pool_free(pool_head_quic_conn_ctx, conn_ctx);
	}

	for (i = 0; i < QUIC_TLS_ENC_LEVEL_MAX; i++)
		quic_conn_enc_level_uninit(&qc->els[i]);

	pool_free(pool_head_quic_conn_rxbuf, qc->rx.buf.area);
	pool_free(pool_head_quic_conn, qc);
	TRACE_PROTO("QUIC conn. freed", QUIC_EV_CONN_FREED, qc);
}

/* Release the quic_conn <qc>. It will decrement its refcount so that the
 * connection will be freed once all threads have finished to work with it. The
 * connection is removed from the CIDs tree and thus cannot be found by other
 * threads after it. The connection tasklet is killed.
 *
 * Do not use <qc> after it as it may be freed. This function must only be
 * called by the thread responsible of the quic_conn tasklet.
 */
static void quic_conn_release(struct quic_conn *qc)
{
	struct ssl_sock_ctx *conn_ctx;

	/* remove the connection from receiver cids trees */
	HA_RWLOCK_WRLOCK(QUIC_LOCK, &qc->li->rx.cids_lock);
	ebmb_delete(&qc->odcid_node);
	ebmb_delete(&qc->scid_node);
	free_quic_conn_cids(qc);
	HA_RWLOCK_WRUNLOCK(QUIC_LOCK, &qc->li->rx.cids_lock);

	/* Kill the tasklet. Do not use tasklet_free as this is not thread safe
	 * as other threads may call tasklet_wakeup after this.
	 */
	conn_ctx = HA_ATOMIC_LOAD(&qc->xprt_ctx);
	if (conn_ctx)
		tasklet_kill(conn_ctx->wait_event.tasklet);

	quic_conn_drop(qc);
}

void quic_close(struct connection *conn, void *xprt_ctx)
{
	struct ssl_sock_ctx *conn_ctx = xprt_ctx;
	struct quic_conn *qc = conn_ctx->qc;

	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);
	/* This task must be deleted by the connection-pinned thread. */
	if (qc->timer_task) {
		task_destroy(qc->timer_task);
		qc->timer_task = NULL;
	}

	/* Next application data can be dropped. */
	qc->mux_state = QC_MUX_RELEASED;

	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);

	/* TODO for now release the quic_conn on notification by the upper
	 * layer. It could be useful to delay it if there is remaining data to
	 * send or data to be acked.
	 */
	quic_conn_release(qc);
}

/* Callback called upon loss detection and PTO timer expirations. */
static struct task *process_timer(struct task *task, void *ctx, unsigned int state)
{
	struct ssl_sock_ctx *conn_ctx;
	struct quic_conn *qc;
	struct quic_pktns *pktns;
	int i, st;

	conn_ctx = task->context;
	qc = conn_ctx->qc;
	TRACE_ENTER(QUIC_EV_CONN_PTIMER, qc,
	            NULL, NULL, &qc->path->ifae_pkts);
	task->expire = TICK_ETERNITY;
	pktns = quic_loss_pktns(qc);
	if (tick_isset(pktns->tx.loss_time)) {
		struct list lost_pkts = LIST_HEAD_INIT(lost_pkts);

		qc_packet_loss_lookup(pktns, qc, &lost_pkts);
		if (!LIST_ISEMPTY(&lost_pkts))
			qc_release_lost_pkts(qc, pktns, &lost_pkts, now_ms);
		qc_set_timer(qc);
		goto out;
	}

	st = HA_ATOMIC_LOAD(&qc->state);
	if (qc->path->in_flight) {
		pktns = quic_pto_pktns(qc, st >= QUIC_HS_ST_COMPLETE, NULL);
		if (pktns == &qc->pktns[QUIC_TLS_PKTNS_INITIAL]) {
			pktns->tx.pto_probe = 1;
			if (qc->pktns[QUIC_TLS_PKTNS_HANDSHAKE].tx.in_flight)
				qc->pktns[QUIC_TLS_PKTNS_HANDSHAKE].tx.pto_probe = 1;
		}
		else {
			pktns->tx.pto_probe = 2;
		}
	}
	else if (!qc_is_listener(qc) && st <= QUIC_HS_ST_COMPLETE) {
		struct quic_enc_level *iel = &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL];
		struct quic_enc_level *hel = &qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE];

		if (hel->tls_ctx.rx.flags == QUIC_FL_TLS_SECRETS_SET)
			hel->pktns->tx.pto_probe = 1;
		if (iel->tls_ctx.rx.flags == QUIC_FL_TLS_SECRETS_SET)
			iel->pktns->tx.pto_probe = 1;
	}

	for (i = QUIC_TLS_ENC_LEVEL_INITIAL; i < QUIC_TLS_ENC_LEVEL_MAX; i++) {
		int j;

		if (i == QUIC_TLS_ENC_LEVEL_APP && !quic_peer_validated_addr(qc))
		    continue;

		for (j = 0; j < qc->els[i].pktns->tx.pto_probe; j++)
			qc_prep_fast_retrans(&qc->els[i], qc);
	}

	tasklet_wakeup(conn_ctx->wait_event.tasklet);
	qc->path->loss.pto_count++;

 out:
	TRACE_LEAVE(QUIC_EV_CONN_PTIMER, qc, pktns);

	return task;
}

/* Initialize <conn> QUIC connection with <quic_initial_clients> as root of QUIC
 * connections used to identify the first Initial packets of client connecting
 * to listeners. This parameter must be NULL for QUIC connections attached
 * to listeners. <dcid> is the destination connection ID with <dcid_len> as length.
 * <scid> is the source connection ID with <scid_len> as length.
 * Returns 1 if succeeded, 0 if not.
 */
static struct quic_conn *qc_new_conn(unsigned int version, int ipv4,
                                    unsigned char *dcid, size_t dcid_len, size_t dcid_addr_len,
                                    unsigned char *scid, size_t scid_len, int server, void *owner)
{
	int i;
	struct quic_conn *qc;
	/* Initial CID. */
	struct quic_connection_id *icid;
	char *buf_area;
	struct listener *l = NULL;

	TRACE_ENTER(QUIC_EV_CONN_INIT);
	qc = pool_zalloc(pool_head_quic_conn);
	if (!qc) {
		TRACE_PROTO("Could not allocate a new connection", QUIC_EV_CONN_INIT);
		goto err;
	}

	HA_ATOMIC_STORE(&qc->refcount, 0);

	buf_area = pool_alloc(pool_head_quic_conn_rxbuf);
	if (!buf_area) {
		TRACE_PROTO("Could not allocate a new RX buffer", QUIC_EV_CONN_INIT, qc);
		goto err;
	}

	qc->cids = EB_ROOT;
	/* QUIC Server (or listener). */
	if (server) {
		l = owner;

		qc->flags |= QUIC_FL_CONN_LISTENER;
		HA_ATOMIC_STORE(&qc->state, QUIC_HS_ST_SERVER_INITIAL);
		/* Copy the initial DCID with the address. */
		qc->odcid.len = dcid_len;
		qc->odcid.addrlen = dcid_addr_len;
		memcpy(qc->odcid.data, dcid, dcid_len + dcid_addr_len);

		/* copy the packet SCID to reuse it as DCID for sending */
		if (scid_len)
			memcpy(qc->dcid.data, scid, scid_len);
		qc->dcid.len = scid_len;
		qc->tx.qring_list = &l->rx.tx_qring_list;
		qc->li = l;
	}
	/* QUIC Client (outgoing connection to servers) */
	else {
		HA_ATOMIC_STORE(&qc->state, QUIC_HS_ST_CLIENT_INITIAL);
		if (dcid_len)
			memcpy(qc->dcid.data, dcid, dcid_len);
		qc->dcid.len = dcid_len;
	}
	qc->mux_state = QC_MUX_NULL;

	/* Initialize the output buffer */
	qc->obuf.pos = qc->obuf.data;

	icid = new_quic_cid(&qc->cids, qc, 0);
	if (!icid) {
		TRACE_PROTO("Could not allocate a new connection ID", QUIC_EV_CONN_INIT, qc);
		goto err;
	}

	/* insert the allocated CID in the receiver tree */
	if (server) {
		HA_RWLOCK_WRLOCK(QUIC_LOCK, &l->rx.cids_lock);
		ebmb_insert(&l->rx.cids, &icid->node, icid->cid.len);
		HA_RWLOCK_WRUNLOCK(QUIC_LOCK, &l->rx.cids_lock);
	}

	/* Select our SCID which is the first CID with 0 as sequence number. */
	qc->scid = icid->cid;

	/* Packet number spaces initialization. */
	for (i = 0; i < QUIC_TLS_PKTNS_MAX; i++)
		quic_pktns_init(&qc->pktns[i]);
	/* QUIC encryption level context initialization. */
	for (i = 0; i < QUIC_TLS_ENC_LEVEL_MAX; i++) {
		if (!quic_conn_enc_level_init(qc, i)) {
			TRACE_PROTO("Could not initialize an encryption level", QUIC_EV_CONN_INIT, qc);
			goto err;
		}
		/* Initialize the packet number space. */
		qc->els[i].pktns = &qc->pktns[quic_tls_pktns(i)];
	}

	qc->version = version;
	qc->tps_tls_ext = qc->version & 0xff000000 ?
		TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS_DRAFT:
		TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS;
	/* TX part. */
	LIST_INIT(&qc->tx.frms_to_send);
	qc->tx.nb_buf = QUIC_CONN_TX_BUFS_NB;
	qc->tx.wbuf = qc->tx.rbuf = 0;
	qc->tx.bytes = 0;
	/* RX part. */
	qc->rx.bytes = 0;
	qc->rx.nb_ack_eliciting = 0;
	qc->rx.buf = b_make(buf_area, QUIC_CONN_RX_BUFSZ, 0, 0);
	HA_RWLOCK_INIT(&qc->rx.buf_rwlock);
	LIST_INIT(&qc->rx.pkt_list);
	if (!quic_tls_ku_init(qc)) {
		TRACE_PROTO("Key update initialization failed", QUIC_EV_CONN_INIT, qc);
		goto err;
	}

	/* XXX TO DO: Only one path at this time. */
	qc->path = &qc->paths[0];
	quic_path_init(qc->path, ipv4, default_quic_cc_algo, qc);

	/* required to use MTLIST_IN_LIST */
	MT_LIST_INIT(&qc->accept_list);

	TRACE_LEAVE(QUIC_EV_CONN_INIT, qc);

	return qc;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_INIT, qc ? qc : NULL);
	quic_conn_drop(qc);
	return NULL;
}

/* Initialize the timer task of <qc> QUIC connection.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_conn_init_timer(struct quic_conn *qc)
{
	/* Attach this task to the same thread ID used for the connection */
	qc->timer_task = task_new(1UL << qc->tid);
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
		if (pkt->type != QUIC_PACKET_TYPE_INITIAL &&
		    pkt->type != QUIC_PACKET_TYPE_0RTT &&
		    dcid_len != QUIC_HAP_CID_LEN)
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

/* Insert <pkt> RX packet in its <qel> RX packets tree */
static void qc_pkt_insert(struct quic_rx_packet *pkt, struct quic_enc_level *qel)
{
	pkt->pn_node.key = pkt->pn;
	quic_rx_packet_refinc(pkt);
	HA_RWLOCK_WRLOCK(QUIC_LOCK, &qel->rx.pkts_rwlock);
	eb64_insert(&qel->rx.pkts, &pkt->pn_node);
	HA_RWLOCK_WRUNLOCK(QUIC_LOCK, &qel->rx.pkts_rwlock);
}

/* Try to remove the header protection of <pkt> QUIC packet attached to <qc>
 * QUIC connection with <buf> as packet number field address, <end> a pointer to one
 * byte past the end of the buffer containing this packet and <beg> the address of
 * the packet first byte.
 * If succeeded, this function updates <*buf> to point to the next packet in the buffer.
 * Returns 1 if succeeded, 0 if not.
 */
static inline int qc_try_rm_hp(struct quic_conn *qc,
                               struct quic_rx_packet *pkt,
                               unsigned char *buf, unsigned char *beg,
                               const unsigned char *end,
                               struct quic_enc_level **el)
{
	unsigned char *pn = NULL; /* Packet number field */
	enum quic_tls_enc_level tel;
	struct quic_enc_level *qel;
	/* Only for traces. */
	struct quic_rx_packet *qpkt_trace;

	qpkt_trace = NULL;
	TRACE_ENTER(QUIC_EV_CONN_TRMHP, qc);
	/* The packet number is here. This is also the start minus
	 * QUIC_PACKET_PN_MAXLEN of the sample used to add/remove the header
	 * protection.
	 */
	pn = buf;

	tel = quic_packet_type_enc_level(pkt->type);
	qel = &qc->els[tel];

	if (qc_qel_may_rm_hp(qc, qel)) {
		 /* Note that the following function enables us to unprotect the packet
		 * number and its length subsequently used to decrypt the entire
		 * packets.
		 */
		if (!qc_do_rm_hp(qc, pkt, &qel->tls_ctx,
		                 qel->pktns->rx.largest_pn, pn, beg, end)) {
			TRACE_PROTO("hp error", QUIC_EV_CONN_TRMHP, qc);
			goto err;
		}

		/* The AAD includes the packet number field found at <pn>. */
		pkt->aad_len = pn - beg + pkt->pnl;
		qpkt_trace = pkt;
	}
	else if (qel) {
		if (qel->tls_ctx.rx.flags & QUIC_FL_TLS_SECRETS_DCD) {
			/* If the packet number space has been discarded, this packet
			 * will be not parsed.
			 */
			TRACE_PROTO("Discarded pktns", QUIC_EV_CONN_TRMHP, qc, pkt);
			goto out;
		}

		TRACE_PROTO("hp not removed", QUIC_EV_CONN_TRMHP, qc, pkt);
		pkt->pn_offset = pn - beg;
		MT_LIST_APPEND(&qel->rx.pqpkts, &pkt->list);
		quic_rx_packet_refinc(pkt);
	}
	else {
		TRACE_PROTO("Unknown packet type", QUIC_EV_CONN_TRMHP, qc);
		goto err;
	}

	*el = qel;
	/* No reference counter incrementation here!!! */
	LIST_APPEND(&qc->rx.pkt_list, &pkt->qc_rx_pkt_list);
	memcpy(b_tail(&qc->rx.buf), beg, pkt->len);
	pkt->data = (unsigned char *)b_tail(&qc->rx.buf);
	b_add(&qc->rx.buf, pkt->len);
 out:
	TRACE_LEAVE(QUIC_EV_CONN_TRMHP, qc, qpkt_trace);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_TRMHP, qc, qpkt_trace);
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

/*
 * Check if the QUIC version in packet <pkt> is supported. Returns a boolean.
 */
static inline int qc_pkt_is_supported_version(struct quic_rx_packet *pkt)
{
	int j = 0, version;

	do {
		version = quic_supported_version[j];
		if (version == pkt->version)
			return 1;

		version = quic_supported_version[++j];
	} while(version);

	return 0;
}

__attribute__((unused))
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
	struct ssl_sock_ctx *conn_ctx;
	int long_header;
	size_t b_cspace;
	struct quic_enc_level *qel;

	qc = NULL;
	qel = NULL;
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

		/* unsupported QUIC version */
		if (!qc_pkt_is_supported_version(pkt)) {
			TRACE_PROTO("Null QUIC version, packet dropped", QUIC_EV_CONN_LPKT);
			goto err;
		}

		/* For Initial packets, and for servers (QUIC clients connections),
		 * there is no Initial connection IDs storage.
		 */
		if (pkt->type == QUIC_PACKET_TYPE_INITIAL) {
			cids = &((struct server *)__objt_server(srv_conn->target))->cids;
			cid_lookup_len = pkt->dcid.len;
		}
		else {
			cids = &((struct server *)__objt_server(srv_conn->target))->cids;
			cid_lookup_len = QUIC_HAP_CID_LEN;
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
		if (end - *buf < QUIC_HAP_CID_LEN)
			goto err;

		cids = &((struct server *)__objt_server(srv_conn->target))->cids;
		node = ebmb_lookup(cids, *buf, QUIC_HAP_CID_LEN);
		if (!node)
			goto err;

		qc = ebmb_entry(node, struct quic_conn, scid_node);
		*buf += QUIC_HAP_CID_LEN;
	}

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

	/* When multiple QUIC packets are coalesced on the same UDP datagram,
	 * they must have the same DCID.
	 *
	 * This check must be done after the final update to pkt.len to
	 * properly drop the packet on failure.
	 */
	if (!dgram_ctx->dcid.len) {
		memcpy(dgram_ctx->dcid.data, pkt->dcid.data, pkt->dcid.len);
	}
	else if (memcmp(dgram_ctx->dcid.data, pkt->dcid.data, pkt->dcid.len)) {
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_SPKT, qc);
		goto err;
	}
	dgram_ctx->qc = qc;

	HA_RWLOCK_WRLOCK(QUIC_LOCK, &qc->rx.buf_rwlock);
	b_cspace = b_contig_space(&qc->rx.buf);
	if (b_cspace < pkt->len) {
		/* Let us consume the remaining contiguous space. */
		b_add(&qc->rx.buf, b_cspace);
		if (b_contig_space(&qc->rx.buf) < pkt->len) {
			HA_RWLOCK_WRUNLOCK(QUIC_LOCK, &qc->rx.buf_rwlock);
			TRACE_PROTO("Too big packet", QUIC_EV_CONN_SPKT, qc, pkt, &pkt->len);
			goto err;
		}
	}

	if (!qc_try_rm_hp(qc, pkt, *buf, beg, end, &qel)) {
		HA_RWLOCK_WRUNLOCK(QUIC_LOCK, &qc->rx.buf_rwlock);
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_SPKT, qc);
		goto err;
	}

	HA_RWLOCK_WRUNLOCK(QUIC_LOCK, &qc->rx.buf_rwlock);
	if (pkt->aad_len)
		qc_pkt_insert(pkt, qel);
	/* Wake the tasklet of the QUIC connection packet handler. */
	if (conn_ctx)
		tasklet_wakeup(conn_ctx->wait_event.tasklet);

	TRACE_LEAVE(QUIC_EV_CONN_SPKT, qc);

	return pkt->len;

 err:
	TRACE_DEVEL("Leaing in error", QUIC_EV_CONN_SPKT, qc ? qc : NULL);
	return -1;
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
	int i = 0, j, version;
	const socklen_t addrlen = get_addr_len(addr);

	/*
	 * header form
	 * long header, fixed bit to 0 for Version Negotiation
	 */
	if (RAND_bytes((unsigned char *)buf, 1) != 1)
		return 1;

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
	j = 0;
	do {
		version = htonl(quic_supported_version[j]);
		memcpy(&buf[i], &version, sizeof(version));
		i += sizeof(version);

		version = quic_supported_version[++j];
	} while (version);

	if (sendto(fd, buf, i, 0, (struct sockaddr *)addr, addrlen) < 0)
		return 1;

	return 0;
}

/* Generate the token to be used in Retry packets. The token is written to
 * <buf> which is expected to be <len> bytes.
 *
 * Various parameters are expected to be encoded in the token. For now, only
 * the DCID from <pkt> is stored. This is useful to implement a stateless Retry
 * as this CID must be repeated by the server in the transport parameters.
 *
 * TODO add the client address to validate the token origin.
 *
 * Returns the length of the encoded token or 0 on error.
 */
static int generate_retry_token(unsigned char *buf, unsigned char len,
                                struct quic_rx_packet *pkt)
{
	const size_t token_len = 1 + pkt->dcid.len;
	unsigned char i = 0;

	if (token_len > len)
		return 0;

	buf[i++] = pkt->dcid.len;
	memcpy(&buf[i], pkt->dcid.data, pkt->dcid.len);
	i += pkt->dcid.len;

	return i;
}

/* Generate a Retry packet and send it on <fd> socket to <addr> in response to
 * the Initial <pkt> packet.
 *
 * Returns 0 on success else non-zero.
 */
static int send_retry(int fd, struct sockaddr_storage *addr,
                      struct quic_rx_packet *pkt)
{
	unsigned char buf[128];
	int i = 0, token_len;
	const socklen_t addrlen = get_addr_len(addr);
	struct quic_cid scid;

	/* long header + fixed bit + packet type 0x3 */
	buf[i++] = 0xf0;
	/* version */
	buf[i++] = 0x00;
	buf[i++] = 0x00;
	buf[i++] = 0x00;
	buf[i++] = 0x01;

	/* Use the SCID from <pkt> for Retry DCID. */
	buf[i++] = pkt->scid.len;
	memcpy(&buf[i], pkt->scid.data, pkt->scid.len);
	i += pkt->scid.len;

	/* Generate a new CID to be used as SCID for the Retry packet. */
	scid.len = QUIC_HAP_CID_LEN;
	if (RAND_bytes(scid.data, scid.len) != 1)
		return 1;

	buf[i++] = scid.len;
	memcpy(&buf[i], scid.data, scid.len);
	i += scid.len;

	/* token */
	if (!(token_len = generate_retry_token(&buf[i], &buf[i] - buf, pkt)))
		return 1;
	i += token_len;

	/* token integrity tag */
	if ((&buf[i] - buf < QUIC_TLS_TAG_LEN) ||
	    !quic_tls_generate_retry_integrity_tag(pkt->dcid.data,
	                                           pkt->dcid.len, buf, i)) {
		return 1;
	}

	i += QUIC_TLS_TAG_LEN;

	if (sendto(fd, buf, i, 0, (struct sockaddr *)addr, addrlen) < 0)
		return 1;

	return 0;
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
	int found_in_dcid = 0;

	HA_RWLOCK_RDLOCK(QUIC_LOCK, &l->rx.cids_lock);

	/* Look first into ODCIDs tree for INITIAL/0-RTT packets. */
	if (pkt->type == QUIC_PACKET_TYPE_INITIAL ||
	    pkt->type == QUIC_PACKET_TYPE_0RTT) {
		/* DCIDs of first packets coming from multiple clients may have
		 * the same values. Let's distinguish them by concatenating the
		 * socket addresses.
		 */
		quic_cid_saddr_cat(&pkt->dcid, saddr);
		node = ebmb_lookup(&l->rx.odcids, pkt->dcid.data,
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
	node = ebmb_lookup(&l->rx.cids, pkt->dcid.data, pkt->dcid.len);
	if (!node)
		goto end;

	id = ebmb_entry(node, struct quic_connection_id, node);
	qc = id->qc;
	found_in_dcid = 1;

 end:
	if (qc)
		quic_conn_take(qc);
	HA_RWLOCK_RDUNLOCK(QUIC_LOCK, &l->rx.cids_lock);

	/* If found in DCIDs tree, remove the quic_conn from the ODCIDs tree.
	 * If already done, this is a noop.
	 *
	 * node.leaf_p is first checked to avoid unnecessary locking.
	 */
	if (qc && found_in_dcid && qc->odcid_node.node.leaf_p) {
		HA_RWLOCK_WRLOCK(QUIC_LOCK, &l->rx.cids_lock);
		ebmb_delete(&qc->odcid_node);
		HA_RWLOCK_WRUNLOCK(QUIC_LOCK, &l->rx.cids_lock);
	}

	return qc;
}

/* Parse the Retry token from buffer <token> whose size is <token_len>. This
 * will extract the parameters stored in the token : <odcid>.
 *
 * Returns 0 on success else non-zero.
 */
static int parse_retry_token(const unsigned char *token, uint64_t token_len,
                             struct quic_cid *odcid)
{
	uint64_t odcid_len;

	if (!quic_dec_int(&odcid_len, &token, token + token_len))
		return 1;

	memcpy(odcid->data, token, odcid_len);
	odcid->len = odcid_len;

	return 0;
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
	int retry;

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
	    !SSL_set_ex_data(*ssl, ssl_qc_app_data_index, qc) ||
	    !SSL_set_quic_transport_params(*ssl, qc->enc_params, qc->enc_params_len)) {
			goto err;

		SSL_free(*ssl);
		*ssl = NULL;
		if (!retry--)
			goto err;

		pool_gc(NULL);
		goto retry;
	}

	return 0;

 err:
	qc->conn->err_code = CO_ER_SSL_NO_MEM;
	return -1;
}

/* Allocate the ssl_sock_ctx from connection <qc>. This creates the tasklet
 * used to process <qc> received packets. The allocated context is stored in
 * <qc.xprt_ctx>.
 *
 * Returns 0 on success else non-zero.
 */
int qc_conn_alloc_ssl_ctx(struct quic_conn *qc)
{
	struct bind_conf *bc = qc->li->bind_conf;
	struct ssl_sock_ctx *ctx = NULL;

	ctx = pool_zalloc(pool_head_quic_conn_ctx);
	if (!ctx)
		goto err;

	ctx->wait_event.tasklet = tasklet_new();
	if (!ctx->wait_event.tasklet)
		goto err;

	ctx->wait_event.tasklet->process = quic_conn_io_cb;
	ctx->wait_event.tasklet->context = ctx;
	ctx->wait_event.events = 0;
	ctx->subs = NULL;
	ctx->xprt_ctx = NULL;
	ctx->qc = qc;

	/* Set tasklet tid based on the SCID selected by us for this
	 * connection. The upper layer will also be binded on the same thread.
	 */
	qc->tid = ctx->wait_event.tasklet->tid = quic_get_cid_tid(&qc->scid);

	if (qc_is_listener(qc)) {
		if (qc_ssl_sess_init(qc, bc->initial_ctx, &ctx->ssl,
		                     qc->enc_params, qc->enc_params_len) == -1) {
		        goto err;
		}

		/* Enabling 0-RTT */
		if (bc->ssl_conf.early_data)
			SSL_set_quic_early_data_enabled(ctx->ssl, 1);

		SSL_set_accept_state(ctx->ssl);
	}

	ctx->xprt = xprt_get(XPRT_QUIC);

	/* Store the allocated context in <qc>. */
	HA_ATOMIC_STORE(&qc->xprt_ctx, ctx);

	return 0;

 err:
	if (ctx && ctx->wait_event.tasklet)
		tasklet_free(ctx->wait_event.tasklet);
	pool_free(pool_head_quic_conn_ctx, ctx);

	return 1;
}

static ssize_t qc_lstnr_pkt_rcv(unsigned char *buf, const unsigned char *end,
                                struct quic_rx_packet *pkt,
                                struct quic_dgram_ctx *dgram_ctx,
                                struct sockaddr_storage *saddr)
{
	unsigned char *beg, *payload;
	struct quic_conn *qc, *qc_to_purge = NULL;
	struct listener *l;
	struct ssl_sock_ctx *conn_ctx;
	int long_header = 0, io_cb_wakeup = 0;
	size_t b_cspace;
	struct quic_enc_level *qel;

	beg = buf;
	qc = NULL;
	conn_ctx = NULL;
	qel = NULL;
	TRACE_ENTER(QUIC_EV_CONN_LPKT);
	/* This ist only to please to traces and distinguish the
	 * packet with parsed packet number from others.
	 */
	pkt->pn_node.key = (uint64_t)-1;
	if (end <= buf)
		goto err;

	/* Fixed bit */
	if (!(*buf & QUIC_PACKET_FIXED_BIT)) {
		/* XXX TO BE DISCARDED */
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
		goto err;
	}

	l = dgram_ctx->owner;
	/* Header form */
	qc_parse_hd_form(pkt, *buf++, &long_header);
	if (long_header) {
		uint64_t len;

		if (!quic_packet_read_long_header(&buf, end, pkt)) {
			TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
			goto err;
		}

		/* Retry of Version Negotiation packets are only sent by servers */
		if (pkt->type == QUIC_PACKET_TYPE_RETRY || !pkt->version) {
			TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
			goto err;
		}

		/* RFC9000 6. Version Negotiation */
		if (!qc_pkt_is_supported_version(pkt)) {
			 /* unsupported version, send Negotiation packet */
			if (send_version_negotiation(l->rx.fd, saddr, pkt)) {
				TRACE_PROTO("Error on Version Negotiation sending", QUIC_EV_CONN_LPKT);
				goto err;
			}

			TRACE_PROTO("Unsupported QUIC version, send Version Negotiation packet", QUIC_EV_CONN_LPKT);
			goto err;
		}

		/* For Initial packets, and for servers (QUIC clients connections),
		 * there is no Initial connection IDs storage.
		 */
		if (pkt->type == QUIC_PACKET_TYPE_INITIAL) {
			uint64_t token_len;

			if (!quic_dec_int(&token_len, (const unsigned char **)&buf, end) ||
				end - buf < token_len) {
				TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
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

			/* TODO Retry should be automatically activated if
			 * suspect network usage is detected.
			 */
			if (!token_len && l->bind_conf->quic_force_retry) {
				TRACE_PROTO("Initial without token, sending retry", QUIC_EV_CONN_LPKT);
				if (send_retry(l->rx.fd, saddr, pkt)) {
					TRACE_PROTO("Error during Retry generation", QUIC_EV_CONN_LPKT);
					goto err;
				}

				goto err;
			}
			else {
				pkt->token = buf;
				buf += pkt->token_len;
			}
		}
		else if (pkt->type != QUIC_PACKET_TYPE_0RTT) {
			if (pkt->dcid.len != QUIC_HAP_CID_LEN) {
				TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
				goto err;
			}
		}

		if (!quic_dec_int(&len, (const unsigned char **)&buf, end) ||
			end - buf < len) {
			TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
			goto err;
		}

		payload = buf;
		pkt->len = len + payload - beg;

		qc = retrieve_qc_conn_from_cid(pkt, l, saddr);
		if (!qc) {
			int ipv4;
			struct quic_cid *odcid;
			struct ebmb_node *n = NULL;
			const unsigned char *salt = initial_salt_v1;
			size_t salt_len = sizeof initial_salt_v1;

			if (pkt->type != QUIC_PACKET_TYPE_INITIAL) {
				TRACE_PROTO("Non Initial packet", QUIC_EV_CONN_LPKT);
				goto err;
			}

			pkt->saddr = *saddr;
			ipv4 = saddr->ss_family == AF_INET;
			qc = qc_new_conn(pkt->version, ipv4,
			                 pkt->dcid.data, pkt->dcid.len, pkt->dcid.addrlen,
			                 pkt->scid.data, pkt->scid.len, 1, l);
			if (qc == NULL)
				goto err;

			memcpy(&qc->peer_addr, &pkt->saddr, sizeof(pkt->saddr));

			odcid = &qc->rx.params.original_destination_connection_id;
			/* Copy the transport parameters. */
			qc->rx.params = l->bind_conf->quic_params;

			/* Copy original_destination_connection_id transport parameter. */
			if (pkt->token_len) {
				if (parse_retry_token(pkt->token, pkt->token_len, odcid)) {
					TRACE_PROTO("Error during Initial token parsing", QUIC_EV_CONN_LPKT, qc);
					goto err;
				}
				/* Copy retry_source_connection_id transport parameter. */
				quic_cid_cpy(&qc->rx.params.retry_source_connection_id,
				             &pkt->dcid);
			}
			else {
				memcpy(odcid->data, &pkt->dcid.data, pkt->dcid.len);
				odcid->len = pkt->dcid.len;
			}

			/* Copy the initial source connection ID. */
			quic_cid_cpy(&qc->rx.params.initial_source_connection_id, &qc->scid);
			qc->enc_params_len =
				quic_transport_params_encode(qc->enc_params,
				                             qc->enc_params + sizeof qc->enc_params,
				                             &qc->rx.params, 1);
			if (!qc->enc_params_len)
				goto err;

			if (qc_conn_alloc_ssl_ctx(qc))
				goto err;

			/* NOTE: the socket address has been concatenated to the destination ID
			 * chosen by the client for Initial packets.
			 */
			if (pkt->version == QUIC_PROTOCOL_VERSION_DRAFT_29) {
				salt = initial_salt_draft_29;
				salt_len = sizeof initial_salt_draft_29;
			}
			if (!qc_new_isecs(qc, salt, salt_len,
			                  pkt->dcid.data, pkt->dcid.len, 1)) {
				TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT, qc);
				goto err;
			}

			HA_RWLOCK_WRLOCK(QUIC_LOCK, &l->rx.cids_lock);
			/* Insert the DCID the QUIC client has chosen (only for listeners) */
			n = ebmb_insert(&l->rx.odcids, &qc->odcid_node,
			                qc->odcid.len + qc->odcid.addrlen);

			/* If the insertion failed, it means that another
			 * thread has already allocated a QUIC connection for
			 * the same CID. Liberate our allocated connection.
			 */
			if (unlikely(n != &qc->odcid_node)) {
				qc_to_purge = qc;

				qc = ebmb_entry(n, struct quic_conn, odcid_node);
				pkt->qc = qc;
			}

			quic_conn_take(qc);
			HA_RWLOCK_WRUNLOCK(QUIC_LOCK, &l->rx.cids_lock);

			if (likely(!qc_to_purge)) {
				/* Enqueue this packet. */
				pkt->qc = qc;
			}
			else {
				quic_conn_drop(qc_to_purge);
			}
		}
		else {
			pkt->qc = qc;
		}
	}
	else {
		if (end - buf < QUIC_HAP_CID_LEN) {
			TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT);
			goto err;
		}

		memcpy(pkt->dcid.data, buf, QUIC_HAP_CID_LEN);
		pkt->dcid.len = QUIC_HAP_CID_LEN;
		buf += QUIC_HAP_CID_LEN;

		/* A short packet is the last one of a UDP datagram. */
		payload = buf;
		pkt->len = end - beg;

		qc = retrieve_qc_conn_from_cid(pkt, l, saddr);
		if (!qc) {
			size_t pktlen = end - buf;
			TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT, NULL, pkt, &pktlen);
			goto err;
		}

		pkt->qc = qc;
	}


	/* When multiple QUIC packets are coalesced on the same UDP datagram,
	 * they must have the same DCID.
	 *
	 * This check must be done after the final update to pkt.len to
	 * properly drop the packet on failure.
	 */
	if (!dgram_ctx->dcid.len) {
		memcpy(dgram_ctx->dcid.data, pkt->dcid.data, pkt->dcid.len);
		if (!quic_peer_validated_addr(qc) &&
		    HA_ATOMIC_LOAD(&qc->flags) & QUIC_FL_CONN_ANTI_AMPLIFICATION_REACHED) {
			TRACE_PROTO("PTO timer must be armed after anti-amplication was reached",
			            QUIC_EV_CONN_LPKT, qc);
			/* Reset the anti-amplification bit. It will be set again
			 * when sending the next packet if reached again.
			 */
			HA_ATOMIC_BTR(&qc->flags, QUIC_FL_CONN_ANTI_AMPLIFICATION_REACHED_BIT);
			HA_ATOMIC_OR(&qc->flags, QUIC_FL_CONN_IO_CB_WAKEUP_BIT);
			io_cb_wakeup = 1;
		}
	}
	else if (memcmp(dgram_ctx->dcid.data, pkt->dcid.data, pkt->dcid.len)) {
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}
	dgram_ctx->qc = qc;


	if (HA_ATOMIC_LOAD(&qc->err_code)) {
		TRACE_PROTO("Connection error", QUIC_EV_CONN_LPKT, qc);
		goto out;
	}

	pkt->raw_len = pkt->len;
	HA_RWLOCK_WRLOCK(QUIC_LOCK, &qc->rx.buf_rwlock);
	quic_rx_pkts_del(qc);
	b_cspace = b_contig_space(&qc->rx.buf);
	if (b_cspace < pkt->len) {
		/* Let us consume the remaining contiguous space. */
		if (b_cspace) {
			b_putchr(&qc->rx.buf, 0x00);
			b_cspace--;
		}
		b_add(&qc->rx.buf, b_cspace);
		if (b_contig_space(&qc->rx.buf) < pkt->len) {
			HA_RWLOCK_WRUNLOCK(QUIC_LOCK, &qc->rx.buf_rwlock);
			TRACE_PROTO("Too big packet", QUIC_EV_CONN_LPKT, qc, pkt, &pkt->len);
			qc_list_all_rx_pkts(qc);
			goto err;
		}
	}

	if (!qc_try_rm_hp(qc, pkt, payload, beg, end, &qel)) {
		HA_RWLOCK_WRUNLOCK(QUIC_LOCK, &qc->rx.buf_rwlock);
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	HA_RWLOCK_WRUNLOCK(QUIC_LOCK, &qc->rx.buf_rwlock);
	TRACE_PROTO("New packet", QUIC_EV_CONN_LPKT, qc, pkt);
	if (pkt->aad_len)
		qc_pkt_insert(pkt, qel);
 out:
	/* Wake up the connection packet handler task from here only if all
	 * the contexts have been initialized, especially the mux context
	 * conn_ctx->conn->ctx. Note that this is ->start xprt callback which
	 * will start it if these contexts for the connection are not already
	 * initialized.
	 */
	conn_ctx = HA_ATOMIC_LOAD(&qc->xprt_ctx);
	if (conn_ctx)
		tasklet_wakeup(conn_ctx->wait_event.tasklet);

	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc ? qc : NULL, pkt);

	if (qc)
		quic_conn_drop(qc);

	return pkt->len;

 err:
	/* Wakeup the I/O handler callback if the PTO timer must be armed.
	 * This cannot be done by this thread.
	 */
	if (io_cb_wakeup) {
		conn_ctx = HA_ATOMIC_LOAD(&qc->xprt_ctx);
		if (conn_ctx && conn_ctx->wait_event.tasklet)
			tasklet_wakeup(conn_ctx->wait_event.tasklet);
	}
	/* If length not found, consume the entire datagram */
	if (!pkt->len)
		pkt->len = end - beg;
	TRACE_DEVEL("Leaving in error", QUIC_EV_CONN_LPKT,
	            qc ? qc : NULL, pkt);

	if (qc)
		quic_conn_drop(qc);

	return -1;
}

/* This function builds into <buf> buffer a QUIC long packet header.
 * Return 1 if enough room to build this header, 0 if not.
 */
static int quic_build_packet_long_header(unsigned char **buf, const unsigned char *end,
                                         int type, size_t pn_len, struct quic_conn *conn)
{
	if (end - *buf < sizeof conn->version + conn->dcid.len + conn->scid.len + 3)
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

/* This function builds into <buf> buffer a QUIC short packet header.
 * Return 1 if enough room to build this header, 0 if not.
 */
static int quic_build_packet_short_header(unsigned char **buf, const unsigned char *end,
                                          size_t pn_len, struct quic_conn *conn,
                                          unsigned char tls_flags)
{
	if (end - *buf < 1 + conn->dcid.len)
		return 0;

	/* #0 byte flags */
	*(*buf)++ = QUIC_PACKET_FIXED_BIT |
		((tls_flags & QUIC_FL_TLS_KP_BIT_SET) ? QUIC_PACKET_KEY_PHASE_BIT : 0) | (pn_len - 1);
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

/* Prepare as most as possible CRYPTO or STREAM frames from their prebuilt frames
 * for <qel> encryption level to be encoded in a buffer with <room> as available room,
 * and <*len> the packet Length field initialized with the number of bytes already present
 * in this buffer which must be taken into an account for the Length packet field value.
 * <headlen> is the number of bytes already present in this packet before building frames.
 *
 * Update consequently <*len> to reflect the size of these frames built
 * by this function. Also attach these frames to <l> frame list.
 * Return 1 if succeeded, 0 if not.
 */
static inline int qc_build_frms(struct list *l,
                                size_t room, size_t *len, size_t headlen,
                                struct quic_enc_level *qel,
                                struct quic_conn *qc)
{
	int ret;
	struct quic_frame *cf, *cfbak;

	ret = 0;
	if (*len > room)
		return 0;

	/* If we are not probing we must take into an account the congestion
	 * control window.
	 */
	if (!qel->pktns->tx.pto_probe) {
		size_t remain = quic_path_prep_data(qc->path);

		if (headlen > remain)
			return 0;

		room = QUIC_MIN(room, remain - headlen);
	}

	TRACE_PROTO("************** frames build (headlen)",
	            QUIC_EV_CONN_BCFRMS, qc, &headlen);
	list_for_each_entry_safe(cf, cfbak, &qel->pktns->tx.frms, list) {
		/* header length, data length, frame length. */
		size_t hlen, dlen, dlen_sz, avail_room, flen;

		if (!room)
			break;

		switch (cf->type) {
		case QUIC_FT_CRYPTO:
			TRACE_PROTO("          New CRYPTO frame build (room, len)",
			            QUIC_EV_CONN_BCFRMS, qc, &room, len);
			/* Compute the length of this CRYPTO frame header */
			hlen = 1 + quic_int_getsize(cf->crypto.offset);
			/* Compute the data length of this CRyPTO frame. */
			dlen = max_stream_data_size(room, *len + hlen, cf->crypto.len);
			TRACE_PROTO(" CRYPTO data length (hlen, crypto.len, dlen)",
			            QUIC_EV_CONN_BCFRMS, qc, &hlen, &cf->crypto.len, &dlen);
			if (!dlen)
				break;

			/* CRYPTO frame length. */
			flen = hlen + quic_int_getsize(dlen) + dlen;
			TRACE_PROTO("                 CRYPTO frame length (flen)",
			            QUIC_EV_CONN_BCFRMS, qc, &flen);
			/* Add the CRYPTO data length and its encoded length to the packet
			 * length and the length of this length.
			 */
			*len += flen;
			room -= flen;
			if (dlen == cf->crypto.len) {
				/* <cf> CRYPTO data have been consumed. */
				LIST_DELETE(&cf->list);
				LIST_APPEND(l, &cf->list);
			}
			else {
				struct quic_frame *new_cf;

				new_cf = pool_alloc(pool_head_quic_frame);
				if (!new_cf) {
					TRACE_PROTO("No memory for new crypto frame", QUIC_EV_CONN_BCFRMS, qc);
					return 0;
				}

				new_cf->type = QUIC_FT_CRYPTO;
				new_cf->crypto.len = dlen;
				new_cf->crypto.offset = cf->crypto.offset;
				new_cf->crypto.qel = qel;
				LIST_APPEND(l, &new_cf->list);
				/* Consume <dlen> bytes of the current frame. */
				cf->crypto.len -= dlen;
				cf->crypto.offset += dlen;
			}
			break;

		case QUIC_FT_STREAM_8 ... QUIC_FT_STREAM_F:
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
				break;

			TRACE_PROTO("          New STREAM frame build (room, len)",
			            QUIC_EV_CONN_BCFRMS, qc, &room, len);
			if (cf->type & QUIC_STREAM_FRAME_TYPE_LEN_BIT) {
				dlen = max_available_room(avail_room, &dlen_sz);
				if (dlen > cf->stream.len) {
					dlen = cf->stream.len;
				}
				dlen_sz = quic_int_getsize(dlen);
				flen = hlen + dlen_sz + dlen;
			}
			else {
				dlen = QUIC_MIN(avail_room, cf->stream.len);
				flen = hlen + dlen;
			}
			TRACE_PROTO(" STREAM data length (hlen, stream.len, dlen)",
			            QUIC_EV_CONN_BCFRMS, qc, &hlen, &cf->stream.len, &dlen);
			TRACE_PROTO("                 STREAM frame length (flen)",
			            QUIC_EV_CONN_BCFRMS, qc, &flen);
			/* Add the STREAM data length and its encoded length to the packet
			 * length and the length of this length.
			 */
			*len += flen;
			room -= flen;
			if (dlen == cf->stream.len) {
				/* <cf> STREAM data have been consumed. */
				LIST_DELETE(&cf->list);
				LIST_APPEND(l, &cf->list);
			}
			else {
				struct quic_frame *new_cf;

				new_cf = pool_zalloc(pool_head_quic_frame);
				if (!new_cf) {
					TRACE_PROTO("No memory for new STREAM frame", QUIC_EV_CONN_BCFRMS, qc);
					return 0;
				}

				new_cf->type = cf->type;
				new_cf->stream.qcs = cf->stream.qcs;
				new_cf->stream.buf = cf->stream.buf;
				new_cf->stream.id = cf->stream.id;
				if (cf->type & QUIC_STREAM_FRAME_TYPE_OFF_BIT)
					new_cf->stream.offset = cf->stream.offset;
				new_cf->stream.len = dlen;
				new_cf->type |= QUIC_STREAM_FRAME_TYPE_LEN_BIT;
				/* FIN bit reset */
				new_cf->type &= ~QUIC_STREAM_FRAME_TYPE_FIN_BIT;
				new_cf->stream.data = cf->stream.data;
				LIST_APPEND(l, &new_cf->list);
				cf->type |= QUIC_STREAM_FRAME_TYPE_OFF_BIT;
				/* Consume <dlen> bytes of the current frame. */
				cf->stream.len -= dlen;
				cf->stream.offset.key += dlen;
				cf->stream.data += dlen;
			}
			break;

		default:
			flen = qc_frm_len(cf);
			BUG_ON(!flen);
			if (flen > room)
				continue;

			*len += flen;
			room -= flen;
			LIST_DELETE(&cf->list);
			LIST_APPEND(l, &cf->list);
			break;
		}
		ret = 1;
	}

	return ret;
}

/* This function builds a clear packet from <pkt> information (its type)
 * into a buffer with <pos> as position pointer and <qel> as QUIC TLS encryption
 * level for <conn> QUIC connection and <qel> as QUIC TLS encryption level,
 * filling the buffer with as much frames as possible.
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
                           int ack, int padding, int cc, int probe,
                           struct quic_enc_level *qel, struct quic_conn *qc)
{
	unsigned char *beg;
	size_t len, len_sz, len_frms, padding_len;
	struct quic_frame frm = { .type = QUIC_FT_CRYPTO, };
	struct quic_frame ack_frm = { .type = QUIC_FT_ACK, };
	struct quic_frame cc_frm = { . type = QUIC_FT_CONNECTION_CLOSE, };
	size_t ack_frm_len, head_len;
	int64_t largest_acked_pn;
	int add_ping_frm;
	struct list frm_list = LIST_HEAD_INIT(frm_list);

	/* Length field value with CRYPTO frames if present. */
	len_frms = 0;
	beg = pos;
	/* When not probing and not acking, and no immediate close is required,
	 * reduce the size of this buffer to respect
	 * the congestion controller window. So, we do not limit the size of this
	 * packet if we have an ACK frame to send because an ACK frame is not
	 * ack-eliciting. This size will be limited if we have ack-eliciting
	 * frames to send from qel->pktns->tx.frms.
	 */
	if (!probe && !ack && !cc) {
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
	largest_acked_pn = HA_ATOMIC_LOAD(&qel->pktns->tx.largest_acked_pn);
	/* packet number length */
	*pn_len = quic_packet_number_length(pn, largest_acked_pn);
	/* Build the header */
	if ((pkt->type == QUIC_PACKET_TYPE_SHORT &&
	    !quic_build_packet_short_header(&pos, end, *pn_len, qc, qel->tls_ctx.flags)) ||
	    (pkt->type != QUIC_PACKET_TYPE_SHORT &&
		!quic_build_packet_long_header(&pos, end, pkt->type, *pn_len, qc)))
		goto no_room;

	/* XXX FIXME XXX Encode the token length (0) for an Initial packet. */
	if (pkt->type == QUIC_PACKET_TYPE_INITIAL)
		*pos++ = 0;
	head_len = pos - beg;
	/* Build an ACK frame if required. */
	ack_frm_len = 0;
	if (!cc && ack && !eb_is_empty(&qel->pktns->rx.arngs.root)) {
		ack_frm.tx_ack.ack_delay = 0;
		ack_frm.tx_ack.arngs = &qel->pktns->rx.arngs;
		/* XXX BE CAREFUL XXX : here we reserved at least one byte for the
		 * smallest frame (PING) and <*pn_len> more for the packet number. Note
		 * that from here, we do not know if we will have to send a PING frame.
		 * This will be decided after having computed the ack-eliciting frames
		 * to be added to this packet.
		 */
		ack_frm_len = quic_ack_frm_reduce_sz(&ack_frm, end - 1 - *pn_len - pos);
		if (!ack_frm_len)
			goto no_room;
	}

	/* Length field value without the ack-eliciting frames. */
	len = ack_frm_len + *pn_len;
	len_frms = 0;
	if (!cc && !LIST_ISEMPTY(&qel->pktns->tx.frms)) {
		ssize_t room = end - pos;

		/* Initialize the length of the frames built below to <len>.
		 * If any frame could be successfully built by qc_build_frms(),
		 * we will have len_frms > len.
		 */
		len_frms = len;
		if (!qc_build_frms(&frm_list, end - pos, &len_frms, pos - beg, qel, qc)) {
			TRACE_PROTO("Not enough room", QUIC_EV_CONN_HPKT,
			            qc, NULL, NULL, &room);
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
		struct quic_connection_close *cc = &cc_frm.connection_close;

		cc->error_code = qc->err_code;
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
	else if (LIST_ISEMPTY(&frm_list) || len_frms == len) {
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

	if (ack_frm_len && !qc_build_frm(&pos, end, &ack_frm, pkt, qc))
		goto no_room;

	/* Ack-eliciting frames */
	if (!LIST_ISEMPTY(&frm_list)) {
		struct quic_frame *cf;

		list_for_each_entry(cf, &frm_list, list) {
			if (!qc_build_frm(&pos, end, cf, pkt, qc)) {
				ssize_t room = end - pos;
				TRACE_PROTO("Not enough room", QUIC_EV_CONN_HPKT,
				            qc, NULL, NULL, &room);
				break;
			}
		}
	}

	/* Build a PING frame if needed. */
	if (add_ping_frm) {
		frm.type = QUIC_FT_PING;
		if (!qc_build_frm(&pos, end, &frm, pkt, qc))
			goto no_room;
	}

	/* Build a CONNECTION_CLOSE frame if needed. */
	if (cc && !qc_build_frm(&pos, end, &cc_frm, pkt, qc))
		goto no_room;

	/* Build a PADDING frame if needed. */
	if (padding_len) {
		frm.type = QUIC_FT_PADDING;
		frm.padding.len = padding_len;
		if (!qc_build_frm(&pos, end, &frm, pkt, qc))
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
	TRACE_PROTO("Ack eliciting frame", QUIC_EV_CONN_HPKT, qc, pkt);

	return 1;

 no_room:
	/* Replace the pre-built frames which could not be add to this packet */
	LIST_SPLICE(&qel->pktns->tx.frms, &frm_list);
	TRACE_PROTO("Not enough room", QUIC_EV_CONN_HPKT, qc);
	return 0;
}

static inline void quic_tx_packet_init(struct quic_tx_packet *pkt, int type)
{
	pkt->type = type;
	pkt->len = 0;
	pkt->in_flight_len = 0;
	pkt->pn_node.key = (uint64_t)-1;
	LIST_INIT(&pkt->frms);
	pkt->next = NULL;
	pkt->refcnt = 1;
}

/* Free <pkt> TX packet which has not already attached to any tree. */
static inline void free_quic_tx_packet(struct quic_tx_packet *pkt)
{
	struct quic_frame *frm, *frmbak;

	if (!pkt)
		return;

	list_for_each_entry_safe(frm, frmbak, &pkt->frms, list) {
		LIST_DELETE(&frm->list);
		pool_free(pool_head_quic_frame, frm);
	}
	quic_tx_packet_refdec(pkt);
}

/* Build a packet into <buf> packet buffer with <pkt_type> as packet
 * type for <qc> QUIC connection from <qel> encryption level.
 * Return -2 if the packet could not be allocated or encrypted for any reason,
 * -1 if there was not enough room to build a packet.
 */
static struct quic_tx_packet *qc_build_pkt(unsigned char **pos,
                                           const unsigned char *buf_end,
                                           struct quic_enc_level *qel,
                                           struct quic_conn *qc, size_t dglen, int padding,
                                           int pkt_type, int ack, int probe, int cc, int *err)
{
	/* The pointer to the packet number field. */
	unsigned char *buf_pn;
	unsigned char *beg, *end, *payload;
	int64_t pn;
	size_t pn_len, payload_len, aad_len;
	struct quic_tls_ctx *tls_ctx;
	struct quic_tx_packet *pkt;

	TRACE_ENTER(QUIC_EV_CONN_HPKT, qc, NULL, qel);
	*err = 0;
	pkt = pool_alloc(pool_head_quic_tx_packet);
	if (!pkt) {
		TRACE_DEVEL("Not enough memory for a new packet", QUIC_EV_CONN_HPKT, qc);
		*err = -2;
		goto err;
	}

	quic_tx_packet_init(pkt, pkt_type);
	beg = *pos;
	pn_len = 0;
	buf_pn = NULL;

	pn = qel->pktns->tx.next_pn + 1;
	if (!qc_do_build_pkt(*pos, buf_end, dglen, pkt, pn, &pn_len, &buf_pn,
	                     ack, padding, cc, probe, qel, qc)) {
		*err = -1;
		goto err;
	}

	end = beg + pkt->len;
	payload = buf_pn + pn_len;
	payload_len = end - payload;
	aad_len = payload - beg;

	tls_ctx = &qel->tls_ctx;
	if (!quic_packet_encrypt(payload, payload_len, beg, aad_len, pn, tls_ctx, qc)) {
		*err = -2;
		goto err;
	}

	end += QUIC_TLS_TAG_LEN;
	pkt->len += QUIC_TLS_TAG_LEN;
	if (!quic_apply_header_protection(beg, buf_pn, pn_len,
	                                  tls_ctx->tx.hp, tls_ctx->tx.hp_key)) {
		TRACE_DEVEL("Could not apply the header protection", QUIC_EV_CONN_HPKT, qc);
		*err = -2;
		goto err;
	}

	/* Consume a packet number */
	qel->pktns->tx.next_pn++;
	qc->tx.prep_bytes += pkt->len;
	if (qc->tx.prep_bytes >= 3 * qc->rx.bytes)
		HA_ATOMIC_OR(&qc->flags, QUIC_FL_CONN_ANTI_AMPLIFICATION_REACHED);
	/* Now that a correct packet is built, let us consume <*pos> buffer. */
	*pos = end;
	/* Attach the built packet to its tree. */
	pkt->pn_node.key = pn;
	/* Set the packet in fligth length for in flight packet only. */
	if (pkt->flags & QUIC_FL_TX_PACKET_IN_FLIGHT) {
		pkt->in_flight_len = pkt->len;
		qc->path->prep_in_flight += pkt->len;
	}
	pkt->pktns = qel->pktns;
	TRACE_LEAVE(QUIC_EV_CONN_HPKT, qc, pkt);

	return pkt;

 err:
	free_quic_tx_packet(pkt);
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_HPKT, qc);
	return NULL;
}

/* Copy up to <count> bytes from connection <conn> internal stream storage into buffer <buf>.
 * Return the number of bytes which have been copied.
 */
static size_t quic_conn_to_buf(struct connection *conn, void *xprt_ctx,
                               struct buffer *buf, size_t count, int flags)
{
	size_t try, done = 0;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!fd_recv_ready(conn->handle.fd))
		return 0;

	conn->flags &= ~CO_FL_WAIT_ROOM;

	/* read the largest possible block. For this, we perform only one call
	 * to recv() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again.
	 */
	while (count > 0) {
		try = b_contig_space(buf);
		if (!try)
			break;

		if (try > count)
			try = count;

		b_add(buf, try);
		done += try;
		count -= try;
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
	if (unlikely(fdtab[conn->handle.fd].state & FD_POLL_ERR))
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
	struct quic_conn *qc = ((struct ssl_sock_ctx *)xprt_ctx)->qc;

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

		ret = sendto(qc->li->rx.fd, b_peek(buf, done), try, send_flag,
		             (struct sockaddr *)&qc->peer_addr, get_addr_len(&qc->peer_addr));
		if (ret > 0) {
			count -= ret;
			done += ret;

			if (ret < try)
				break;
		}
		else if (ret == 0 || errno == EAGAIN || errno == ENOTCONN || errno == EINPROGRESS) {
			ABORT_NOW();
		}
		else if (errno != EINTR) {
			ABORT_NOW();
		}
	}

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

/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be a
 * combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0.
 */
static int quic_conn_subscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	struct qcc *qcc = conn->qc->qcc;

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(qcc->subs && qcc->subs != es);

	es->events |= event_type;
	qcc->subs = es;

	if (event_type & SUB_RETRY_RECV)
		TRACE_DEVEL("subscribe(recv)", QUIC_EV_CONN_XPRTRECV, conn->qc, qcc);

	if (event_type & SUB_RETRY_SEND)
		TRACE_DEVEL("subscribe(send)", QUIC_EV_CONN_XPRTSEND, conn->qc, qcc);

	return 0;
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int quic_conn_unsubscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	return conn_unsubscribe(conn, xprt_ctx, event_type, es);
}

/* Store in <xprt_ctx> the context attached to <conn>.
 * Returns always 0.
 */
static int qc_conn_init(struct connection *conn, void **xprt_ctx)
{
	struct quic_conn *qc = NULL;

	TRACE_ENTER(QUIC_EV_CONN_NEW, conn);

	/* do not store the context if already set */
	if (*xprt_ctx)
		goto out;

	HA_ATOMIC_STORE(xprt_ctx, conn->qc->xprt_ctx);

 out:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);

	return 0;
}

/* Start the QUIC transport layer */
static int qc_xprt_start(struct connection *conn, void *ctx)
{
	struct quic_conn *qc;
	struct ssl_sock_ctx *qctx = ctx;

	qc = conn->qc;
	if (!quic_conn_init_timer(qc)) {
		TRACE_PROTO("Non initialized timer", QUIC_EV_CONN_LPKT, qc);
		return 0;
	}

	quic_mux_transport_params_update(qc->qcc);
	if (qcc_install_app_ops(qc->qcc, qc->app_ops)) {
		TRACE_PROTO("Cannot install app layer", QUIC_EV_CONN_LPKT, qc);
		return 0;
	}

	/* mux-quic can now be considered ready. */
	qc->mux_state = QC_MUX_READY;

	tasklet_wakeup(qctx->wait_event.tasklet);
	return 1;
}

/* transport-layer operations for QUIC connections. */
static struct xprt_ops ssl_quic = {
	.close    = quic_close,
	.snd_buf  = quic_conn_from_buf,
	.rcv_buf  = quic_conn_to_buf,
	.subscribe = quic_conn_subscribe,
	.unsubscribe = quic_conn_unsubscribe,
	.init     = qc_conn_init,
	.start    = qc_xprt_start,
	.prepare_bind_conf = ssl_sock_prepare_bind_conf,
	.destroy_bind_conf = ssl_sock_destroy_bind_conf,
	.get_alpn = ssl_sock_get_alpn,
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

/* Read all the QUIC packets found in <buf> from QUIC connection with <owner>
 * as owner calling <func> function.
 * Return the number of bytes read if succeeded, -1 if not.
 */
static ssize_t quic_dgram_read(struct buffer *buf, size_t len, void *owner,
                               struct sockaddr_storage *saddr, qpkt_read_func *func)
{
	unsigned char *pos;
	const unsigned char *end;
	struct quic_dgram_ctx dgram_ctx = {
		.qc = NULL,
		.dcid.len = 0,
		.owner = owner,
	};

	pos = (unsigned char *)b_head(buf);
	end = pos + len;
	do {
		int ret;
		struct quic_rx_packet *pkt;

		pkt = pool_zalloc(pool_head_quic_rx_packet);
		if (!pkt)
			goto err;

		quic_rx_packet_refinc(pkt);
		ret = func(pos, end, pkt, &dgram_ctx, saddr);
		pos += pkt->len;
		quic_rx_packet_refdec(pkt);
		if (ret == -1)
			/* If the packet length could not be found, we cannot continue. */
			break;
	} while (pos < end);

	/* Increasing the received bytes counter by the UDP datagram length
	 * if this datagram could be associated to a connection.
	 */
	if (dgram_ctx.qc)
		dgram_ctx.qc->rx.bytes += len;

	return pos - (unsigned char *)b_head(buf);

 err:
	return -1;
}

ssize_t quic_lstnr_dgram_read(struct buffer *buf, size_t len, void *owner,
                              struct sockaddr_storage *saddr)
{
	return quic_dgram_read(buf, len, owner, saddr, qc_lstnr_pkt_rcv);
}

/* Function to automatically activate QUIC traces on stdout.
 * Activated via the compilation flag -DENABLE_QUIC_STDOUT_TRACES.
 * Main use for now is in the docker image for QUIC interop testing.
 */
static void quic_init_stdout_traces(void)
{
#ifdef ENABLE_QUIC_STDOUT_TRACES
	trace_quic.sink = sink_find("stdout");
	trace_quic.level = TRACE_LEVEL_DEVELOPER;
	trace_quic.state = TRACE_STATE_RUNNING;
#endif
}
INITCALL0(STG_INIT, quic_init_stdout_traces);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
