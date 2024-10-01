/*
 * QUIC traces
 *
 * Copyright 2000-2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <inttypes.h>

#include <haproxy/api-t.h>
#include <haproxy/chunk.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_ssl.h>
#include <haproxy/quic_tls.h>
#include <haproxy/quic_trace.h>
#include <haproxy/quic_tp.h>
#include <haproxy/trace.h>

static void quic_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
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
	{ .mask = QUIC_EV_CONN_SUB,      .name = "xprt_sub",         .desc = "RX/TX subscription or unsubscription to QUIC xprt"},
	{ .mask = QUIC_EV_CONN_RCV,      .name = "conn_recv",        .desc = "RX on connection" },
	{ .mask = QUIC_EV_CONN_BIND_TID, .name = "conn_bind_tid",    .desc = "change connection thread affinity" },
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

INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

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

		chunk_appendf(&trace_buf, " : qc@%p idle_timer_task@%p flags=0x%x",
		              qc, qc->idle_timer_task, qc->flags);
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
			const unsigned char *rx_sec = a2;
			const unsigned char *tx_sec = a3;

			tls_ctx = &qc->iel->tls_ctx;
			chunk_appendf(&trace_buf, "\n  RX el=I");
			if (rx_sec)
				quic_tls_secret_hexdump(&trace_buf, rx_sec, 32);
			quic_tls_keys_hexdump(&trace_buf, &tls_ctx->rx);
			chunk_appendf(&trace_buf, "\n  TX el=I");
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
				struct quic_enc_level *qel = qc_quic_enc_level(qc, lvl);

				chunk_appendf(&trace_buf, "\n  RX el=%c", quic_enc_level_char(lvl));
				if (quic_tls_has_rx_sec(qel))
					quic_tls_keys_hexdump(&trace_buf, &qel->tls_ctx.rx);
				else
					chunk_appendf(&trace_buf, " (none)");
			}
		}

		if (mask & (QUIC_EV_CONN_WSEC|QUIC_EV_CONN_RWSEC)) {
			const enum ssl_encryption_level_t *level = a2;

			if (level) {
				enum quic_tls_enc_level lvl = ssl_to_quic_enc_level(*level);
				struct quic_enc_level *qel = qc_quic_enc_level(qc, lvl);

				chunk_appendf(&trace_buf, "\n  TX el=%c", quic_enc_level_char(lvl));
				if (quic_tls_has_tx_sec(qel)) {
					quic_tls_keys_hexdump(&trace_buf, &qel->tls_ctx.tx);
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
			const int *ssl_err = a3;
			const SSL *ssl = a4;

			if (state)
				chunk_appendf(&trace_buf, " state=%s", quic_hdshk_state_str(*state));
			if (ssl_err)
				chunk_appendf(&trace_buf, "  ssl_err=%d", *ssl_err);
			if (ssl)
				chunk_appendf(&trace_buf, " early_data_status=%s",
				              quic_ssl_early_data_status_str(ssl));
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
				              " qel=%c flags=0x%x state=%s ack?%d pto_count=%d cwnd=%llu "
				              "ppif=%lld pif=%llu if=%llu pp=%u off=%llu",
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
				chunk_appendf(&trace_buf, " off=%llu len=%llu", (ull)strm_frm->offset, (ull)strm_frm->len);
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
				              ql->srtt, ql->rtt_var, ql->rtt_min);
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
				chunk_appendf(&trace_buf, " pktns=%c", quic_pktns_char(qc, pktns));
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
				chunk_appendf(&trace_buf, " pktns=%c pp=%d",
				              quic_pktns_char(qc, pktns),
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
				chunk_appendf(&trace_buf, " pn=%lu(%c) iflen=%llu",
				              (unsigned long)pkt->pn_node.key,
				              quic_pktns_char(qc, pkt->pktns),
				              (unsigned long long)pkt->in_flight_len);
				chunk_appendf(&trace_buf, " bytes.rx=%llu bytes.tx=%llu",
				              (unsigned long long)qc->bytes.rx,
				              (unsigned long long)qc->bytes.tx);
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

void quic_dump_qc_info(struct buffer *msg, const struct quic_conn *qc)
{
	chunk_appendf(msg, " qc.wnd=%llu/%llu", (ullong)qc->path->in_flight,
	                                        (ullong)qc->path->cwnd);
}
