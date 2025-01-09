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

#include <haproxy/quic_rx.h>

#include <haproxy/h3.h>
#include <haproxy/list.h>
#include <haproxy/ncbuf.h>
#include <haproxy/proto_quic.h>
#include <haproxy/quic_ack.h>
#include <haproxy/quic_cc_drs.h>
#include <haproxy/quic_cid.h>
#include <haproxy/quic_retransmit.h>
#include <haproxy/quic_retry.h>
#include <haproxy/quic_rules.h>
#include <haproxy/quic_sock.h>
#include <haproxy/quic_stream.h>
#include <haproxy/quic_ssl.h>
#include <haproxy/quic_tls.h>
#include <haproxy/quic_token.h>
#include <haproxy/quic_trace.h>
#include <haproxy/quic_tx.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/trace.h>

DECLARE_POOL(pool_head_quic_conn_rxbuf, "quic_conn_rxbuf", QUIC_CONN_RX_BUFSZ);
DECLARE_POOL(pool_head_quic_dgram, "quic_dgram", sizeof(struct quic_dgram));
DECLARE_POOL(pool_head_quic_rx_packet, "quic_rx_packet", sizeof(struct quic_rx_packet));

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

	if (!quic_tls_hp_decrypt(mask, sample, sizeof mask, tls_ctx->rx.hp_ctx, tls_ctx->rx.hp_key)) {
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
	struct quic_tls_ctx *tls_ctx =
		qc_select_tls_ctx(qc, qel, pkt->type, pkt->version);
	QUIC_AEAD_CTX *rx_ctx = tls_ctx->rx.ctx;
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

/* Handle <frm> frame whose packet it is attached to has just been acknowledged. The memory allocated
 * for this frame will be at least released in every cases.
 *
 * Returns 1 on sucess else 0.
 */
static int qc_handle_newly_acked_frm(struct quic_conn *qc, struct quic_frame *frm)
{
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);
	TRACE_PROTO("RX ack TX frm", QUIC_EV_CONN_PRSAFRM, qc, frm);

	switch (frm->type) {
	case QUIC_FT_STREAM_8 ... QUIC_FT_STREAM_F:
	{
		struct qf_stream *strm_frm = &frm->stream;
		struct eb64_node *node = NULL;
		struct qc_stream_desc *stream = NULL;
		int ack;

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
			/* return as success */
		}
		else {
			stream = eb64_entry(node, struct qc_stream_desc, by_id);

			ack = qc_stream_desc_ack(stream, strm_frm->offset,
			                         strm_frm->len,
			                         frm->type & QUIC_STREAM_FRAME_TYPE_FIN_BIT);
			if (!ack) {
				TRACE_DEVEL("stream consumed on ACK received",
				            QUIC_EV_CONN_ACKSTRM, qc, strm_frm, stream);

				if (qc_stream_desc_done(stream)) {
					/* no need to continue if stream freed. */
					TRACE_DEVEL("stream released and freed", QUIC_EV_CONN_ACKSTRM, qc);
					qc_check_close_on_released_mux(qc);
				}

				qc_release_frm(qc, frm);
			}
			else if (ack > 0) {
				TRACE_DEVEL("handled out-of-order stream ACK",
				            QUIC_EV_CONN_ACKSTRM, qc, strm_frm, stream);
				qc_release_frm(qc, frm);
			}
			else {
				/* Fatal error during qc_stream_desc_ack(). */
				goto leave;
			}
		}
	}
	break;
	default:
		qc_release_frm(qc, frm);
	}

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
	return ret;
}

/* Collect newly acknowledged TX packets from <pkts> ebtree into <newly_acked_pkts>
 * list depending on <largest> and <smallest> packet number of a range of acknowledged
 * packets announced in an ACK frame. <largest_node> may be provided to start
 * looking from this packet node.
 */
static void qc_newly_acked_pkts(struct quic_conn *qc, struct eb_root *pkts,
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
		pkt = eb64_entry(node, struct quic_tx_packet, pn_node);
		LIST_APPEND(newly_acked_pkts, &pkt->list);
		node = eb64_next(node);
		eb64_delete(&pkt->pn_node);
	}

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
}

/* Handle <newly_acked_pkts> list of newly acknowledged TX packets.
 *
 * Returns 1 on sucess else 0.
 */
static int qc_handle_newly_acked_pkts(struct quic_conn *qc,
                                      unsigned int *pkt_flags, struct list *newly_acked_pkts)
{
	struct quic_tx_packet *pkt, *tmp;
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);

	list_for_each_entry_safe(pkt, tmp, newly_acked_pkts, list) {
		struct quic_frame *frm, *frmbak;

		*pkt_flags |= pkt->flags;
		TRACE_DEVEL("Removing packet #", QUIC_EV_CONN_PRSAFRM, qc, NULL, &pkt->pn_node.key);
		list_for_each_entry_safe(frm, frmbak, &pkt->frms, list) {
			if (!qc_handle_newly_acked_frm(qc, frm))
				goto leave;
		}
		/* If there are others packet in the same datagram <pkt> is attached to,
		 * detach the previous one and the next one from <pkt>.
		 */
		quic_tx_packet_dgram_detach(pkt);
		eb64_delete(&pkt->pn_node);
	}

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
	return ret;
}

/* Handle all frames sent from <pkt> packet and reinsert them in the same order
 * they have been sent into <pktns_frm_list>. The loss counter of each frame is
 * incremented and checked if it does not exceed retransmission limit.
 *
 * Returns 1 on success, 0 if a frame loss limit is exceeded. A
 * CONNECTION_CLOSE is scheduled in this case.
 */
int qc_handle_frms_of_lost_pkt(struct quic_conn *qc,
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
			if (qc_stream_frm_is_acked(qc, frm)) {
				qc_frm_free(qc, &frm);
				continue;
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
			qc_frm_free(qc, &frm);
			continue;
		}

		if (frm->flags & QUIC_FL_TX_FRAME_ACKED) {
			TRACE_DEVEL("already acked frame", QUIC_EV_CONN_PRSAFRM, qc, frm);
			TRACE_DEVEL("freeing frame from packet", QUIC_EV_CONN_PRSAFRM,
			            qc, frm, &pn);
			qc_frm_free(qc, &frm);
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

/* Send a packet ack event nofication for each newly acked packet of
 * <newly_acked_pkts> list and free them.
 * Always succeeds.
 */
static void qc_notify_cc_of_newly_acked_pkts(struct quic_conn *qc,
                                             struct list *newly_acked_pkts,
                                             unsigned int bytes_lost,
                                             unsigned int rtt)
{
	struct quic_tx_packet *pkt, *tmp;
	struct quic_cc_event ev = { .type = QUIC_CC_EVT_ACK, };
	struct quic_cc_path *p = qc->path;
	struct quic_cc_drs *drs =
		p->cc.algo->get_drs ? p->cc.algo->get_drs(&p->cc) : NULL;
	unsigned int bytes_delivered = 0, pkt_delivered = 0;
	uint64_t time_ns = task_mono_time();

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);

	list_for_each_entry_safe(pkt, tmp, newly_acked_pkts, list) {
		pkt->pktns->tx.in_flight -= pkt->in_flight_len;
		p->prep_in_flight -= pkt->in_flight_len;
		if (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING)
			p->ifae_pkts--;
		/* If this packet contained an ACK frame, proceed to the
		 * acknowledging of range of acks from the largest acknowledged
		 * packet number which was sent in an ACK frame by this packet.
		 */
		if (pkt->largest_acked_pn != -1)
			qc_treat_ack_of_ack(qc, &pkt->pktns->rx.arngs, pkt->largest_acked_pn);
		bytes_delivered += pkt->len;
		pkt_delivered = pkt->rs.delivered;
		ev.ack.acked = pkt->in_flight_len;
		ev.ack.time_sent = pkt->time_sent_ms;
		ev.ack.pn = pkt->pn_node.key;
		/* Note that this event is not emitted for BBR. */
		quic_cc_event(&p->cc, &ev);
		p->in_flight -= pkt->in_flight_len;
		if (drs && (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING))
			quic_cc_drs_update_rate_sample(drs, pkt, time_ns);
		LIST_DEL_INIT(&pkt->list);
		quic_tx_packet_refdec(pkt);
	}

	if (drs) {
		quic_cc_drs_on_ack_recv(drs, p, pkt_delivered);
		drs->lost += bytes_lost;
	}
	if (p->cc.algo->on_ack_rcvd)
		p->cc.algo->on_ack_rcvd(&p->cc, bytes_delivered, pkt_delivered,
		                        rtt, bytes_lost, now_ms);

	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);

}

/* Parse ACK frame into <frm> from a buffer at <buf> address with <end> being at
 * one byte past the end of this buffer. Also update <rtt_sample> if needed, i.e.
 * if the largest acked packet was newly acked and if there was at least one newly
 * acked ack-eliciting packet.
 * Return 1, if succeeded, 0 if not.
 */
static int qc_parse_ack_frm(struct quic_conn *qc,
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
	int ret = 0, new_largest_acked_pn = 0;
	struct quic_tx_packet *pkt, *tmp;

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);

	pkts = &qel->pktns->tx.pkts;
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
			                       struct quic_tx_packet, pn_node)->time_sent_ms;
			new_largest_acked_pn = 1;
		}
	}

	TRACE_PROTO("RX ack range", QUIC_EV_CONN_PRSAFRM,
	            qc, NULL, &largest, &smallest);
	do {
		uint64_t gap, ack_range;

		qc_newly_acked_pkts(qc, pkts, &newly_acked_pkts,
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

	if (!LIST_ISEMPTY(&newly_acked_pkts)) {
		unsigned int bytes_lost = 0;

		if (!qc_handle_newly_acked_pkts(qc, &pkt_flags, &newly_acked_pkts))
			goto leave;

		if (new_largest_acked_pn && (pkt_flags & QUIC_FL_TX_PACKET_ACK_ELICITING)) {
			*rtt_sample = tick_remain(time_sent, now_ms);
			qel->pktns->rx.largest_acked_pn = ack_frm->largest_ack;
		}

		if (!eb_is_empty(&qel->pktns->tx.pkts)) {
			qc_packet_loss_lookup(qel->pktns, qc, &lost_pkts, &bytes_lost);
			if (!qc_release_lost_pkts(qc, qel->pktns, &lost_pkts, now_ms))
				goto leave;
		}

		qc_notify_cc_of_newly_acked_pkts(qc, &newly_acked_pkts,
		                                 bytes_lost, *rtt_sample);
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
	/* Move back these packets into their tree. */
	list_for_each_entry_safe(pkt, tmp, &newly_acked_pkts, list) {
		LIST_DEL_INIT(&pkt->list);
		eb64_insert(pkts, &pkt->pn_node);
	}
	goto leave;
}

/* Parse a STREAM frame <strm_frm> received in <pkt> packet for <qc>
 * connection. <fin> is true if FIN bit is set on frame type.
 *
 * Return 1 on success. On error, 0 is returned. In this case, the packet
 * containing the frame must not be acknowledged.
 */
static int qc_handle_strm_frm(struct quic_rx_packet *pkt,
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
	               strm_frm->offset, fin, (char *)strm_frm->data);

	/* frame rejected - packet must not be acknowledeged */
	TRACE_LEAVE(QUIC_EV_CONN_PRSFRM, qc);
	return !ret;
}

/* Parse <frm> CRYPTO frame coming with <pkt> packet at <qel> <qc> connection.
 *
 * Returns 0 on success or a negative error code. A positive value is used to
 * indicate that the current frame cannot be handled immediately, but it could
 * be solved by running a new packet parsing iteration.
 *
 * Also set <*fast_retrans> as output parameter to 1 if the speed up handshake
 * completion may be run after having received duplicated CRYPTO data.
 */
static enum quic_rx_ret_frm qc_handle_crypto_frm(struct quic_conn *qc,
                                                 struct qf_crypto *crypto_frm,
                                                 struct quic_rx_packet *pkt,
                                                 struct quic_enc_level *qel)
{
	enum ncb_ret ncb_ret;
	enum quic_rx_ret_frm ret = QUIC_RX_RET_FRM_DONE;
	/* XXX TO DO: <cfdebug> is used only for the traces. */
	struct quic_rx_crypto_frm cfdebug = {
		.offset_node.key = crypto_frm->offset,
		.len = crypto_frm->len,
	};
	struct quic_cstream *cstream = qel->cstream;
	struct ncbuf *ncbuf = &qel->cstream->rx.ncbuf;
	uint64_t off_rel;

	TRACE_ENTER(QUIC_EV_CONN_PRSHPKT, qc);

	if (unlikely(crypto_frm->offset < cstream->rx.offset)) {
		size_t diff;

		if (crypto_frm->offset + crypto_frm->len <= cstream->rx.offset) {
			/* Nothing to do */
			TRACE_PROTO("Already received CRYPTO data",
			            QUIC_EV_CONN_RXPKT, qc, pkt, &cfdebug);
			ret = QUIC_RX_RET_FRM_DUP;
			goto done;
		}

		TRACE_PROTO("Partially already received CRYPTO data",
		            QUIC_EV_CONN_RXPKT, qc, pkt, &cfdebug);

		diff = cstream->rx.offset - crypto_frm->offset;
		crypto_frm->len -= diff;
		crypto_frm->data += diff;
		crypto_frm->offset = cstream->rx.offset;
	}

	if (!quic_get_ncbuf(ncbuf) || ncb_is_null(ncbuf)) {
		TRACE_ERROR("CRYPTO ncbuf allocation failed", QUIC_EV_CONN_PRSHPKT, qc);
		goto err;
	}

	/* crypto_frm->offset > cstream-trx.offset */
	off_rel = crypto_frm->offset - cstream->rx.offset;

	/* RFC 9000 7.5. Cryptographic Message Buffering
	 *
	 * Being unable to buffer CRYPTO frames during the handshake can lead to
	 * a connection failure. If an endpoint's buffer is exceeded during the
	 * handshake, it can expand its buffer temporarily to complete the
	 * handshake. If an endpoint does not expand its buffer, it MUST close
	 * the connection with a CRYPTO_BUFFER_EXCEEDED error code.
	 */
	if (off_rel + crypto_frm->len > ncb_size(ncbuf)) {
		TRACE_ERROR("CRYPTO frame too large", QUIC_EV_CONN_PRSHPKT, qc);
		quic_set_connection_close(qc, quic_err_transport(QC_ERR_CRYPTO_BUFFER_EXCEEDED));
		goto err;
	}

	ncb_ret = ncb_add(ncbuf, off_rel, (const char *)crypto_frm->data,
	                  crypto_frm->len, NCB_ADD_COMPARE);
	if (ncb_ret != NCB_RET_OK) {
		if (ncb_ret == NCB_RET_DATA_REJ) {
			TRACE_ERROR("overlapping data rejected", QUIC_EV_CONN_PRSHPKT, qc);
			quic_set_connection_close(qc, quic_err_transport(QC_ERR_PROTOCOL_VIOLATION));
			qc_notify_err(qc);
			goto err;
		}
		else if (ncb_ret == NCB_RET_GAP_SIZE) {
			TRACE_DATA("cannot bufferize frame due to gap size limit",
			           QUIC_EV_CONN_PRSHPKT, qc);
			ret = QUIC_RX_RET_FRM_AGAIN;
			goto done;
		}
	}

	/* Reschedule with TASK_HEAVY if CRYPTO data ready for decoding. */
	if (ncb_data(ncbuf, 0)) {
		HA_ATOMIC_OR(&qc->wait_event.tasklet->state, TASK_HEAVY);
		tasklet_wakeup(qc->wait_event.tasklet);
	}

 done:
	TRACE_LEAVE(QUIC_EV_CONN_PRSHPKT, qc);
	return ret;

 err:
	TRACE_DEVEL("leaving on error", QUIC_EV_CONN_PRSHPKT, qc);
	return QUIC_RX_RET_FRM_FATAL;
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
	node = eb64_lookup(qc->cids, rcid_frm->seq_num);
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

/* Returns the <ack_delay> field value in milliseconds from <ack_frm> ACK frame for
 * <conn> QUIC connection. Note that the value of <ack_delay> coming from
 * ACK frame is in microseconds.
 */
static inline unsigned int quic_ack_delay_ms(struct qf_ack *ack_frm,
                                             struct quic_conn *conn)
{
	return (ack_frm->ack_delay << conn->tx.params.ack_delay_exponent) / 1000;
}

/* Parse all the frames of <pkt> QUIC packet for QUIC connection <qc> and <qel>
 * as encryption level.
 * Returns 1 if succeeded, 0 if failed.
 */
static int qc_parse_pkt_frms(struct quic_conn *qc, struct quic_rx_packet *pkt,
                             struct quic_enc_level *qel)
{
	struct list retry_frms = LIST_HEAD_INIT(retry_frms);
	struct quic_frame *frm = NULL, *frm_tmp;
	const unsigned char *pos, *end;
	enum quic_rx_ret_frm ret;
	int fast_retrans = 0;
	/* parsing may be rerun multiple times, but no more than <iter>. */
	int iter = 3, parsing_stage = 0;

	TRACE_ENTER(QUIC_EV_CONN_PRSHPKT, qc);
	/* Skip the AAD */
	pos = pkt->data + pkt->aad_len;
	end = pkt->data + pkt->len;

	/* Packet with no frame. */
	if (pos == end) {
		/* RFC9000 12.4. Frames and Frame Types
		 *
		 * The payload of a packet that contains frames MUST contain at least
		 * one frame, and MAY contain multiple frames and multiple frame types.
		 * An endpoint MUST treat receipt of a packet containing no frames as a
		 * connection error of type PROTOCOL_VIOLATION. Frames always fit within
		 * a single QUIC packet and cannot span multiple packets.
		 */
		quic_set_connection_close(qc, quic_err_transport(QC_ERR_PROTOCOL_VIOLATION));
		goto err;
	}

	while (pos < end) {
		if (!frm && !(frm = qc_frm_alloc(0))) {
			TRACE_ERROR("cannot allocate frame", QUIC_EV_CONN_PRSHPKT, qc);
			goto err;
		}

		if (!qc_parse_frm(frm, pkt, &pos, end, qc)) {
			// trace already emitted by function above
			goto err;
		}

		switch (frm->type) {
		case QUIC_FT_PADDING:
			break;
		case QUIC_FT_PING:
			break;
		case QUIC_FT_ACK:
		case QUIC_FT_ACK_ECN:
		{
			unsigned int rtt_sample;
			rtt_sample = UINT_MAX;

			if (!qc_parse_ack_frm(qc, frm, qel, &rtt_sample, &pos, end)) {
				// trace already emitted by function above
				goto err;
			}

			if (rtt_sample != UINT_MAX) {
				unsigned int ack_delay;

				ack_delay = !quic_application_pktns(qel->pktns, qc) ? 0 :
					qc->state >= QUIC_HS_ST_CONFIRMED ?
					MS_TO_TICKS(QUIC_MIN(quic_ack_delay_ms(&frm->ack, qc), qc->max_ack_delay)) :
					MS_TO_TICKS(quic_ack_delay_ms(&frm->ack, qc));
				quic_loss_srtt_update(&qc->path->loss, rtt_sample, ack_delay, qc);
			}
			break;
		}
		case QUIC_FT_RESET_STREAM:
			if (qc->mux_state == QC_MUX_READY) {
				struct qf_reset_stream *rs_frm = &frm->reset_stream;
				qcc_recv_reset_stream(qc->qcc, rs_frm->id, rs_frm->app_error_code, rs_frm->final_size);
			}
			break;
		case QUIC_FT_STOP_SENDING:
		{
			struct qf_stop_sending *ss_frm = &frm->stop_sending;
			if (qc->mux_state == QC_MUX_READY) {
				if (qcc_recv_stop_sending(qc->qcc, ss_frm->id,
				                          ss_frm->app_error_code)) {
					TRACE_ERROR("qcc_recv_stop_sending() failed", QUIC_EV_CONN_PRSHPKT, qc);
					goto err;
				}
			}
			break;
		}
		case QUIC_FT_CRYPTO:
			ret = qc_handle_crypto_frm(qc, &frm->crypto, pkt, qel);
			switch (ret) {
			case QUIC_RX_RET_FRM_FATAL:
				goto err;

			case QUIC_RX_RET_FRM_AGAIN:
				if (parsing_stage == 0) {
					TRACE_STATE("parsing stage set to 1 (AGAIN encountered)", QUIC_EV_CONN_PRSHPKT, qc);
					++parsing_stage;
				}
				/* Save frame in temp list to reparse it later. A new instance must be used for next packet frames. */
				LIST_APPEND(&retry_frms, &frm->list);
				frm = NULL;
				break;

			case QUIC_RX_RET_FRM_DUP:
				if (qc_is_listener(qc) && qel == qc->iel &&
				    !(qc->flags & QUIC_FL_CONN_HANDSHAKE_SPEED_UP)) {
					fast_retrans = 1;
				}
				break;

			case QUIC_RX_RET_FRM_DONE:
				if (parsing_stage == 1) {
					TRACE_STATE("parsing stage set to 2 (DONE after AGAIN)", QUIC_EV_CONN_PRSHPKT, qc);
					++parsing_stage;
				}
				break;
			}

			break;
		case QUIC_FT_NEW_TOKEN:
			if (qc_is_listener(qc)) {
				TRACE_ERROR("reject NEW_TOKEN frame emitted by client",
				            QUIC_EV_CONN_PRSHPKT, qc);

				/* RFC 9000 19.7. NEW_TOKEN Frames
				 * Clients MUST NOT send NEW_TOKEN frames. A server MUST treat receipt
				 * of a NEW_TOKEN frame as a connection error of type
				 * PROTOCOL_VIOLATION.
				 */
				quic_set_connection_close(qc, quic_err_transport(QC_ERR_PROTOCOL_VIOLATION));
				goto err;
			}
			else {
				/* TODO */
			}
			break;
		case QUIC_FT_STREAM_8 ... QUIC_FT_STREAM_F:
		{
			struct qf_stream *strm_frm = &frm->stream;
			unsigned nb_streams = qc->rx.strms[qcs_id_type(strm_frm->id)].nb_streams;
			const char fin = frm->type & QUIC_STREAM_FRAME_TYPE_FIN_BIT;

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
							goto err;
						}
					}
					else {
						/* This packet will not be acknowledged */
						goto err;
					}
				}

				break;
			}

			if (!qc_handle_strm_frm(pkt, strm_frm, qc, fin)) {
				TRACE_ERROR("qc_handle_strm_frm() failed", QUIC_EV_CONN_PRSHPKT, qc);
				goto err;
			}

			break;
		}
		case QUIC_FT_MAX_DATA:
			if (qc->mux_state == QC_MUX_READY) {
				struct qf_max_data *md_frm = &frm->max_data;
				qcc_recv_max_data(qc->qcc, md_frm->max_data);
			}
			break;
		case QUIC_FT_MAX_STREAM_DATA:
			if (qc->mux_state == QC_MUX_READY) {
				struct qf_max_stream_data *msd_frm = &frm->max_stream_data;
				if (qcc_recv_max_stream_data(qc->qcc, msd_frm->id,
				                              msd_frm->max_stream_data)) {
					TRACE_ERROR("qcc_recv_max_stream_data() failed", QUIC_EV_CONN_PRSHPKT, qc);
					goto err;
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

			if (!qc_handle_retire_connection_id_frm(qc, frm, &pkt->dcid, &conn_id))
				goto err;

			if (!conn_id)
				break;

			quic_cid_delete(conn_id);
			eb64_delete(&conn_id->seq_num);
			pool_free(pool_head_quic_connection_id, conn_id);
			TRACE_PROTO("CID retired", QUIC_EV_CONN_PSTRM, qc);

			conn_id = new_quic_cid(qc->cids, qc, NULL, NULL);
			if (!conn_id) {
				TRACE_ERROR("CID allocation error", QUIC_EV_CONN_IO_CB, qc);
			}
			else {
				_quic_cid_insert(conn_id);
				qc_build_new_connection_id_frm(qc, conn_id);
			}
			break;
		}
		case QUIC_FT_PATH_CHALLENGE:
		case QUIC_FT_PATH_RESPONSE:
			/* TODO */
			break;
		case QUIC_FT_CONNECTION_CLOSE:
		case QUIC_FT_CONNECTION_CLOSE_APP:
			/* Increment the error counters */
			quic_conn_closed_err_count_inc(qc, frm);
			if (!(qc->flags & QUIC_FL_CONN_DRAINING)) {
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

				/* RFC 9000 19.20. HANDSHAKE_DONE Frames
				 *
				 * A
				 * server MUST treat receipt of a HANDSHAKE_DONE frame as a connection
				 * error of type PROTOCOL_VIOLATION.
				 */
				quic_set_connection_close(qc, quic_err_transport(QC_ERR_PROTOCOL_VIOLATION));
				goto err;
			}

			qc->state = QUIC_HS_ST_CONFIRMED;
			break;
		default:
			/* Unknown frame type must be rejected by qc_parse_frm(). */
			ABORT_NOW();
		}
	}

	if (frm)
		qc_frm_free(qc, &frm);

	while (!LIST_ISEMPTY(&retry_frms)) {
		if (--iter <= 0) {
			TRACE_ERROR("interrupt parsing due to max iteration reached",
			            QUIC_EV_CONN_PRSHPKT, qc);
			goto err;
		}
		else if (parsing_stage <= 1) {
			TRACE_ERROR("interrupt parsing due to buffering blocked on gap size limit",
			            QUIC_EV_CONN_PRSHPKT, qc);
			goto err;
		}

		parsing_stage = 0;
		list_for_each_entry_safe(frm, frm_tmp, &retry_frms, list) {
			/* only CRYPTO frames may be reparsed for now */
			BUG_ON(frm->type != QUIC_FT_CRYPTO);
			ret = qc_handle_crypto_frm(qc, &frm->crypto, pkt, qel);
			switch (ret) {
			case QUIC_RX_RET_FRM_FATAL:
				goto err;

			case QUIC_RX_RET_FRM_AGAIN:
				if (parsing_stage == 0) {
					TRACE_STATE("parsing stage set to 1 (AGAIN encountered)", QUIC_EV_CONN_PRSHPKT, qc);
					++parsing_stage;
				}
				break;

			case QUIC_RX_RET_FRM_DONE:
				TRACE_PROTO("frame handled after a new parsing iteration",
				            QUIC_EV_CONN_PRSAFRM, qc, frm);
				if (parsing_stage == 1) {
					TRACE_STATE("parsing stage set to 2 (DONE after AGAIN)", QUIC_EV_CONN_PRSHPKT, qc);
					++parsing_stage;
				}
				__fallthrough;
			case QUIC_RX_RET_FRM_DUP:
				qc_frm_free(qc, &frm);
				break;
			}
		}

		/* Always reset <frm> as it may be dangling after
		 * list_for_each_entry_safe() usage. Especially necessary to
		 * prevent a crash if loop is interrupted on max iteration.
		 */
		frm = NULL;
	}

	/* Error should be returned if some frames cannot be parsed. */
	BUG_ON(!LIST_ISEMPTY(&retry_frms));

	if (fast_retrans && qc->iel && qc->hel) {
		struct quic_enc_level *iqel = qc->iel;
		struct quic_enc_level *hqel = qc->hel;

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
			if (qc->ipktns && !quic_tls_pktns_is_dcd(qc, qc->ipktns)) {
				/* Discard the handshake packet number space. */
				TRACE_PROTO("discarding Initial pktns", QUIC_EV_CONN_PRSHPKT, qc);
				quic_pktns_discard(qc->ipktns, qc);
				qc_set_timer(qc);
				qc_el_rx_pkts_del(qc->iel);
				qc_release_pktns_frms(qc, qc->ipktns);
			}
		    if (qc->state < QUIC_HS_ST_SERVER_HANDSHAKE)
			    qc->state = QUIC_HS_ST_SERVER_HANDSHAKE;
	    }
	}

	TRACE_LEAVE(QUIC_EV_CONN_PRSHPKT, qc);
	return 1;

 err:
	if (frm)
		qc_frm_free(qc, &frm);
	list_for_each_entry_safe(frm, frm_tmp, &retry_frms, list) {
		qc_frm_free(qc, &frm);
	}

	TRACE_DEVEL("leaving on error", QUIC_EV_CONN_PRSHPKT, qc);
	return 0;
}

/* Detect the value of the spin bit to be used. */
static inline void qc_handle_spin_bit(struct quic_conn *qc, struct quic_rx_packet *pkt,
                                      struct quic_enc_level *qel)
{
	uint64_t largest_pn = qel->pktns->rx.largest_pn;

	if (qel != qc->ael || largest_pn == -1 ||
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
static void qc_rm_hp_pkts(struct quic_conn *qc, struct quic_enc_level *el)
{
	struct quic_rx_packet *pqpkt, *pkttmp;

	TRACE_ENTER(QUIC_EV_CONN_ELRMHP, qc);
	/* A server must not process incoming 1-RTT packets before the handshake is complete. */
	if (el == qc->ael && qc_is_listener(qc) && qc->state < QUIC_HS_ST_COMPLETE) {
		TRACE_PROTO("RX hp not removed (handshake not completed)",
		            QUIC_EV_CONN_ELRMHP, qc);
		goto out;
	}

	list_for_each_entry_safe(pqpkt, pkttmp, &el->rx.pqpkts, list) {
		struct quic_tls_ctx *tls_ctx;

		tls_ctx = qc_select_tls_ctx(qc, el, pqpkt->type, pqpkt->version);
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
		LIST_DEL_INIT(&pqpkt->list);
		quic_rx_packet_refdec(pqpkt);
	}

  out:
	TRACE_LEAVE(QUIC_EV_CONN_ELRMHP, qc);
}

/* Check if it's possible to remove header protection for packets related to
 * encryption level <qel>. If <qel> is NULL, assume it's false.
 *
 * Return true if the operation is possible else false.
 */
static int qc_qel_may_rm_hp(struct quic_conn *qc, struct quic_enc_level *qel)
{
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_TRMHP, qc);

	if (!qel)
		goto cant_rm_hp;

	if (!quic_tls_has_rx_sec(qel)) {
		TRACE_PROTO("non available secrets", QUIC_EV_CONN_TRMHP, qc);
		goto cant_rm_hp;
	}

	if (qel == qc->ael && qc->state < QUIC_HS_ST_COMPLETE) {
		TRACE_PROTO("handshake not complete", QUIC_EV_CONN_TRMHP, qc);
		goto cant_rm_hp;
	}

	/* check if the connection layer is ready before using app level */
	if ((qel == qc->ael || qel == qc->eel) &&
	    qc->mux_state == QC_MUX_NULL) {
		TRACE_PROTO("connection layer not ready", QUIC_EV_CONN_TRMHP, qc);
		goto cant_rm_hp;
	}

	ret = 1;
 cant_rm_hp:
	TRACE_LEAVE(QUIC_EV_CONN_TRMHP, qc);
	return ret;
}

/* Process all the packets for all the encryption levels listed in <qc> QUIC connection.
 * Return 1 if succeeded, 0 if not.
 */
int qc_treat_rx_pkts(struct quic_conn *qc)
{
	int ret = 0;
	struct eb64_node *node;
	int64_t largest_pn = -1;
	unsigned int largest_pn_time_received = 0;
	struct quic_enc_level *qel, *qelbak;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT, qc);

	list_for_each_entry_safe(qel, qelbak, &qc->qel_list, list) {
		/* Treat packets waiting for header packet protection decryption */
		if (!LIST_ISEMPTY(&qel->rx.pqpkts) && qc_qel_may_rm_hp(qc, qel))
			qc_rm_hp_pkts(qc, qel);

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

					/* RFC 9000 8.1. Address Validation during Connection Establishment
					 *
					 * Connection establishment implicitly provides address validation for
					 * both endpoints. In particular, receipt of a packet protected with
					 * Handshake keys confirms that the peer successfully processed an
					 * Initial packet.
					 */
					if (qel == qc->hel &&
					    !(qc->flags & QUIC_FL_CONN_PEER_VALIDATED_ADDR)) {
						TRACE_STATE("validate peer address on handshake packet",
						            QUIC_EV_CONN_RXPKT, qc, pkt);
						qc->flags |= QUIC_FL_CONN_PEER_VALIDATED_ADDR;
						BUG_ON(!qc->prx_counters->half_open_conn);
						HA_ATOMIC_DEC(&qc->prx_counters->half_open_conn);
					}

					/* Update the list of ranges to acknowledge. */
					if (quic_update_ack_ranges_list(qc, &qel->pktns->rx.arngs, &ar)) {
						if (pkt->flags & QUIC_FL_RX_PACKET_ACK_ELICITING) {
							int arm_ack_timer =
								qc->state >= QUIC_HS_ST_COMPLETE &&
								qel->pktns == qc->apktns;

							qel->pktns->flags |= QUIC_FL_PKTNS_ACK_REQUIRED;
							qel->pktns->rx.nb_aepkts_since_last_ack++;
							qc_idle_timer_rearm(qc, 1, arm_ack_timer);
						}

						if (pkt->pn > largest_pn) {
							largest_pn = pkt->pn;
							largest_pn_time_received = pkt->time_received;
						}
					}
					else {
						TRACE_ERROR("Could not update ack range list",
						            QUIC_EV_CONN_RXPKT, qc);
					}
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

		/* Release the Initial encryption level and packet number space. */
		if ((qc->flags & QUIC_FL_CONN_IPKTNS_DCD) && qel == qc->iel) {
			qc_enc_level_free(qc, &qc->iel);
			quic_pktns_release(qc, &qc->ipktns);
		}

		largest_pn = -1;
	}

 out:
	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_RXPKT, qc);
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
static int qc_try_rm_hp(struct quic_conn *qc, struct quic_rx_packet *pkt,
                        unsigned char *beg, struct quic_enc_level **el)
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
	qel = qc_quic_enc_level(qc, tel);
	if (!qel) {
		struct quic_enc_level **qc_qel = qel_to_qel_addr(qc, tel);
		struct quic_pktns **qc_pktns = qel_to_quic_pktns(qc, tel);

		if (!qc_enc_level_alloc(qc, qc_pktns, qc_qel, quic_to_ssl_enc_level(tel))) {
			TRACE_PROTO("Could not allocated an encryption level", QUIC_EV_CONN_ADDDATA, qc);
			goto out;
		}

		qel = *qc_qel;
	}

	if (qc_qel_may_rm_hp(qc, qel)) {
		struct quic_tls_ctx *tls_ctx =
			qc_select_tls_ctx(qc, qel, pkt->type, pkt->version);

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

/* Return a 32-bits integer in <val> from QUIC packet with <buf> as address.
 * Makes <buf> point to the data after this 32-bits value if succeeded.
 * Note that these 32-bits integers are network bytes ordered.
 * Returns 0 if failed (not enough data in the buffer), 1 if succeeded.
 */
static inline int quic_read_uint32(uint32_t *val,
                                   const unsigned char **buf,
                                   const unsigned char *end)
{
	if (end - *buf < sizeof *val)
		return 0;

	*val = ntohl(read_u32(*buf));
	*buf += sizeof *val;

	return 1;
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

/* Validate the token, retry or not (provided by NEW_TOKEN) parsed into
 * <pkt> RX packet from <dgram> datagram.
 * Return 1 if succeded, 0 if not.
 */
static inline int quic_token_validate(struct quic_rx_packet *pkt,
                                      struct quic_dgram *dgram,
                                      struct listener *l, struct quic_conn *qc,
                                      struct quic_cid *odcid)
{
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_LPKT, qc);

	switch (*pkt->token) {
	case QUIC_TOKEN_FMT_RETRY:
		ret = quic_retry_token_check(pkt, dgram, l, qc, odcid);
		break;
	case QUIC_TOKEN_FMT_NEW:
		ret = quic_token_check(pkt, dgram, qc);
		if (!ret) {
			/* Fallback to a retry token in case of any error. */
			dgram->flags |= QUIC_DGRAM_FL_SEND_RETRY;
		}
		break;
	default:
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT, qc, NULL, NULL, pkt->version);
		break;
	}

	if (!ret)
		goto err;

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc);
	return ret;
 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_LPKT, qc);
	goto leave;
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

	qc = retrieve_qc_conn_from_cid(pkt, &dgram->saddr, new_tid);

	/* quic_conn must be set to NULL if bind on another thread. */
	BUG_ON_HOT(qc && *new_tid != -1);

	/* If connection already created or rebinded on another thread. */
	if (!qc && *new_tid != -1 && tid != *new_tid)
		goto out;

	if (pkt->type == QUIC_PACKET_TYPE_INITIAL) {
		BUG_ON(!pkt->version); /* This must not happen. */

		if (!qc) {
			struct quic_connection_id *conn_id;
			int ipv4;

			/* Reject INITIAL early if listener limits reached. */
			if (unlikely(HA_ATOMIC_LOAD(&l->rx.quic_curr_handshake) >=
			             quic_listener_max_handshake(l))) {
				TRACE_DATA("Drop INITIAL on max handshake",
				            QUIC_EV_CONN_LPKT, NULL, NULL, NULL, pkt->version);
				goto out;
			}

			if (unlikely(HA_ATOMIC_LOAD(&l->rx.quic_curr_accept) >=
			             quic_listener_max_accept(l))) {
				TRACE_DATA("Drop INITIAL on max accept",
				            QUIC_EV_CONN_LPKT, NULL, NULL, NULL, pkt->version);
				goto out;
			}

			if (pkt->token_len) {
				TRACE_PROTO("Initial with token", QUIC_EV_CONN_LPKT, NULL, NULL, NULL, pkt->version);
				/* Validate the token, retry or not only when connection is unknown. */
				if (!quic_token_validate(pkt, dgram, l, qc, &token_odcid)) {
					if (dgram->flags & QUIC_DGRAM_FL_SEND_RETRY) {
						if (send_retry(l->rx.fd, &dgram->saddr, pkt, pkt->version)) {
							TRACE_ERROR("Error during Retry generation",
							            QUIC_EV_CONN_LPKT, NULL, NULL, NULL, pkt->version);
						}
						else
							HA_ATOMIC_INC(&prx_counters->retry_sent);

						goto out;
					}

					goto err;
				}
			}
			else {
				TRACE_PROTO("Initial without token", QUIC_EV_CONN_LPKT, NULL, NULL, NULL, pkt->version);
			}

			if (!quic_init_exec_rules(l, dgram)) {
				TRACE_USER("drop datagram on quic-initial rules", QUIC_EV_CONN_LPKT, NULL, NULL, NULL, pkt->version);
				goto err;
			}

			/* No need to emit Retry if connection is refused. */
			if (!pkt->token_len && !(dgram->flags & QUIC_DGRAM_FL_REJECT)) {
				if ((l->bind_conf->options & BC_O_QUIC_FORCE_RETRY) ||
				    HA_ATOMIC_LOAD(&prx_counters->half_open_conn) >= global.tune.quic_retry_threshold ||
				    (dgram->flags & QUIC_DGRAM_FL_SEND_RETRY)) {

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

			qc = qc_new_conn(pkt->version, ipv4, &pkt->dcid, &pkt->scid, &token_odcid,
			                 conn_id, &dgram->daddr, &pkt->saddr, 1,
			                 !!pkt->token_len, l);
			if (qc == NULL) {
				pool_free(pool_head_quic_connection_id, conn_id);
				goto err;
			}

			/* Compute and store into the quic_conn the hash used to compute extra CIDs */
			if (quic_hash64_from_cid)
				qc->hash64 = quic_hash64_from_cid(conn_id->cid.data, conn_id->cid.len,
								  global.cluster_secret, sizeof(global.cluster_secret));

			if (quic_cid_insert(conn_id, new_tid)) {
				pool_free(pool_head_quic_connection_id, conn_id);
				quic_conn_release(qc);
				qc = NULL;
			}
			else {
				/* From here, <qc> is the correct connection for this <pkt> Initial
				 * packet. <conn_id> must be inserted in the CIDs tree for this
				 * connection.
				 */
				eb64_insert(qc->cids, &conn_id->seq_num);
				/* Initialize the next CID sequence number to be used for this connection. */
				qc->next_cid_seq_num = 1;

				if (dgram->flags & QUIC_DGRAM_FL_REJECT)
					quic_set_connection_close(qc, quic_err_transport(QC_ERR_CONNECTION_REFUSED));
			}

			if (*new_tid != -1)
				goto out;
		}
	}
	else if (!qc) {
		/* Stateless Reset sent even for Long header packets as haproxy
		 * emits stateless_reset_token in its TPs.
		 */
		TRACE_PROTO("RX non Initial pkt without connection", QUIC_EV_CONN_LPKT, NULL, NULL, NULL, pkt->version);
		if (!send_stateless_reset(l, &dgram->saddr, pkt))
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

/* Release the memory for the RX packets which are no more referenced
 * and consume their payloads which have been copied to the RX buffer
 * for the connection.
 * Always succeeds.
 */
static void quic_rx_pkts_del(struct quic_conn *qc)
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

	/* Drop asap packet whose packet number space is discarded. */
	if (quic_tls_pkt_type_pktns_dcd(qc, pkt->type)) {
		TRACE_PROTO("Discarded packet number space", QUIC_EV_CONN_TRMHP, qc);
		goto drop_silent;
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
	if (pkt->aad_len) {
		/* Insert this RX packet in its encryption level tree */
		pkt->pn_node.key = pkt->pn;
		quic_rx_packet_refinc(pkt);
		eb64_insert(&qel->rx.pkts, &pkt->pn_node);
	}
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
		pkt = pool_alloc(pool_head_quic_rx_packet);
		if (!pkt) {
			TRACE_ERROR("RX packet allocation failed", QUIC_EV_CONN_LPKT);
			goto err;
		}

		LIST_INIT(&pkt->qc_rx_pkt_list);
		pkt->version = NULL;
		pkt->type = QUIC_PACKET_TYPE_UNKNOWN;
		pkt->pn_offset = 0;
		pkt->len = 0;
		pkt->raw_len = 0;
		pkt->token = NULL;
		pkt->token_len = 0;
		pkt->aad_len = 0;
		pkt->data = NULL;
		pkt->pn_node.key = (uint64_t)-1;
		pkt->refcnt = 0;
		pkt->flags = 0;
		pkt->time_received = now_ms;

		/* Set flag if pkt is the first one in dgram. */
		if (pos == dgram->buf)
			pkt->flags |= QUIC_FL_RX_PACKET_DGRAM_FIRST;

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
					pool_free(pool_head_quic_rx_packet, pkt);
					goto out;
				}

				/* Skip the entire datagram. */
				pkt->len = end - pos;
				goto next;
			}

			dgram->qc = qc;
		}

		/* Ensure quic_conn access only occurs on its attached thread. */
		BUG_ON_HOT(((struct quic_connection_id *)
		               eb64_entry(eb64_first(qc->cids), struct quic_connection_id, seq_num))->tid != tid);

		/* Ensure thread connection migration is finalized ASAP. */
		if (qc->flags & QUIC_FL_CONN_TID_REBIND)
			qc_finalize_tid_rebind(qc);

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
		dgram->qc->bytes.rx += dgram->len;

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

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
