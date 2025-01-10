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

#include <haproxy/quic_tx.h>

#include <errno.h>

#include <haproxy/pool.h>
#include <haproxy/trace.h>
#include <haproxy/quic_cc_drs.h>
#include <haproxy/quic_cid.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_pacing.h>
#include <haproxy/quic_retransmit.h>
#include <haproxy/quic_retry.h>
#include <haproxy/quic_sock.h>
#include <haproxy/quic_stream.h>
#include <haproxy/quic_tls.h>
#include <haproxy/quic_trace.h>
#include <haproxy/ssl_sock-t.h>

DECLARE_POOL(pool_head_quic_tx_packet, "quic_tx_packet", sizeof(struct quic_tx_packet));
DECLARE_POOL(pool_head_quic_cc_buf, "quic_cc_buf", QUIC_MAX_CC_BUFSIZE);

static struct quic_tx_packet *qc_build_pkt(unsigned char **pos, const unsigned char *buf_end,
                                           struct quic_enc_level *qel, struct quic_tls_ctx *ctx,
                                           struct list *frms, struct quic_conn *qc,
                                           const struct quic_version *ver, size_t dglen, int pkt_type,
                                           int must_ack, int padding, int probe, int cc,
                                           enum qc_build_pkt_err *err);

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
	                      tls_ctx->tx.ctx, tls_ctx->tx.aead, iv)) {
		TRACE_ERROR("QUIC packet encryption failed", QUIC_EV_CONN_ENCPKT, qc);
		*fail = 1;
		enc_debug_info_init(&edi, payload, payload_len, aad, aad_len, pn);
	}

	TRACE_LEAVE(QUIC_EV_CONN_ENCPKT, qc);
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
		qc_frm_free(qc, &frm);
	pool_free(pool_head_quic_tx_packet, pkt);

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
}

/* Allocate Tx buffer from <qc> quic-conn if needed.
 *
 * Returns allocated buffer or NULL on error.
 */
struct buffer *qc_txb_alloc(struct quic_conn *qc)
{
	struct buffer *buf = &qc->tx.buf;
	if (!b_alloc(buf, DB_MUX_TX))
		return NULL;

	return buf;
}

/* Free Tx buffer from <qc> if it is empty. */
void qc_txb_release(struct quic_conn *qc)
{
	struct buffer *buf = &qc->tx.buf;

	/* For the moment sending function is responsible to purge the buffer
	 * entirely. It may change in the future but this requires to be able
	 * to reuse old data.
	 * For the moment we do not care to leave data in the buffer for
	 * a connection which is supposed to be killed asap.
	 */
	BUG_ON_HOT(buf && b_data(buf));

	if (!b_data(buf)) {
		b_free(buf);
		offer_buffers(NULL, 1);
	}
}

/* Return the TX buffer dedicated to the "connection close" datagram to be built
 * if an immediate close is required after having allocated it or directly
 * allocate a TX buffer if an immediate close is not required.
 */
struct buffer *qc_get_txb(struct quic_conn *qc)
{
	struct buffer *buf;

	if (qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE) {
		TRACE_PROTO("Immediate close required", QUIC_EV_CONN_PHPKTS, qc);
		buf = &qc->tx.cc_buf;
		if (b_is_null(buf)) {
			qc->tx.cc_buf_area = pool_alloc(pool_head_quic_cc_buf);
			if (!qc->tx.cc_buf_area)
				goto err;
		}

		/* In every case, initialize ->tx.cc_buf */
		qc->tx.cc_buf = b_make(qc->tx.cc_buf_area, QUIC_MAX_CC_BUFSIZE, 0, 0);
	}
	else {
		buf = qc_txb_alloc(qc);
		if (!buf)
			goto err;
	}

	return buf;
 err:
	return NULL;
}

/* Commit a datagram payload written into <buf> of length <length>. <first_pkt>
 * must contains the address of the first packet stored in the payload. When
 * GSO is used, several datagrams can be commited at once. In this case,
 * <length> must be the total length of all consecutive datagrams.
 *
 * Caller is responsible that there is enough space in the buffer.
 */
static void qc_txb_store(struct buffer *buf, uint16_t length,
                         struct quic_tx_packet *first_pkt)
{
	BUG_ON_HOT(b_contig_space(buf) < QUIC_DGRAM_HEADLEN); /* this must not happen */

	/* If first packet is INITIAL, ensure datagram is sufficiently padded. */
	BUG_ON(first_pkt->type == QUIC_PACKET_TYPE_INITIAL &&
	       (first_pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING) &&
	       length < QUIC_INITIAL_PACKET_MINLEN);

	write_u16(b_tail(buf), length);
	write_ptr(b_tail(buf) + sizeof(length), first_pkt);
	b_add(buf, QUIC_DGRAM_HEADLEN + length);
}

/* Reports if data are ready to be sent for <qel> encryption level on <qc>
 * connection.
 *
 * <frms> is the ack-eliciting frames list to send, if any. Other parameters
 * can be set individually for some special frame types : <cc> for immediate
 * close, <probe> to emit probing frames.
 *
 * This function will also set <must_ack> to inform the caller that an
 * acknowledgement should be sent.
 *
 * Returns true if data to emit else false.
 */
static int qc_may_build_pkt(struct quic_conn *qc, struct list *frms,
                            struct quic_enc_level *qel, int cc, int probe,
                            int *must_ack)
{
	int force_ack = qel == qc->iel || qel == qc->hel;
	int nb_aepkts_since_last_ack = qel->pktns->rx.nb_aepkts_since_last_ack;

	/* An acknowledgement must be sent if this has been forced by the caller,
	 * typically during the handshake when the packets must be acknowledged as
	 * soon as possible. This is also the case when the ack delay timer has been
	 * triggered, or at least every QUIC_MAX_RX_AEPKTS_SINCE_LAST_ACK packets.
	 */
	*must_ack = (qc->flags & QUIC_FL_CONN_ACK_TIMER_FIRED) ||
		((qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) &&
		 (force_ack || nb_aepkts_since_last_ack >= QUIC_MAX_RX_AEPKTS_SINCE_LAST_ACK));

	TRACE_PRINTF(TRACE_LEVEL_DEVELOPER, QUIC_EV_CONN_PHPKTS, qc, 0, 0, 0,
	             "%c has_sec=%d cc=%d probe=%d must_ack=%d frms=%d prep_in_fligh=%llu cwnd=%llu",
	             quic_enc_level_char_from_qel(qel, qc),
	             quic_tls_has_tx_sec(qel), cc, probe, *must_ack, LIST_ISEMPTY(frms),
	             (ullong)qc->path->prep_in_flight, (ullong)qc->path->cwnd);

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

/* Free all frames in <l> list. In addition also remove all these frames
 * from the original ones if they are the results of duplications.
 */
static inline void qc_free_frm_list(struct quic_conn *qc, struct list *l)
{
	struct quic_frame *frm, *frmbak;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	list_for_each_entry_safe(frm, frmbak, l, list) {
		LIST_DEL_INIT(&frm->ref);
		qc_frm_free(qc, &frm);
	}

	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
}

/* Free <pkt> TX packet and all the packets coalesced to it. */
static inline void qc_free_tx_coalesced_pkts(struct quic_conn *qc,
                                             struct quic_tx_packet *p)
{
	struct quic_tx_packet *pkt, *nxt_pkt;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	for (pkt = p; pkt; pkt = nxt_pkt) {
		qc_free_frm_list(qc, &pkt->frms);
		nxt_pkt = pkt->next;
		pool_free(pool_head_quic_tx_packet, pkt);
	}

	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
}

/* Purge <buf> TX buffer from its prepare packets. */
static void qc_purge_tx_buf(struct quic_conn *qc, struct buffer *buf)
{
	while (b_contig_data(buf, 0)) {
		uint16_t dglen;
		struct quic_tx_packet *pkt;

		dglen = read_u16(b_head(buf));
		pkt = read_ptr(b_head(buf) + sizeof(dglen));
		qc_free_tx_coalesced_pkts(qc, pkt);
		b_del(buf, dglen + QUIC_DGRAM_HEADLEN);
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
static int qc_send_ppkts(struct buffer *buf, struct ssl_sock_ctx *ctx)
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
		uint16_t dglen, gso = 0, gso_fallback = 0;
		uint64_t time_sent_ns;
		unsigned int time_sent_ms;

		pos = (unsigned char *)b_head(buf);
		dglen = read_u16(pos);
		BUG_ON_HOT(!dglen); /* this should not happen */

		/* If datagram bigger than MTU, several ones were encoded for GSO usage. */
		if (dglen > qc->path->mtu) {
			if (likely(!(HA_ATOMIC_LOAD(&qc->li->flags) & LI_F_UDP_GSO_NOTSUPP))) {
				TRACE_PROTO("send multiple datagrams with GSO", QUIC_EV_CONN_SPPKTS, qc);
				gso = qc->path->mtu;
			}
			else {
				TRACE_PROTO("use non-GSO fallback emission mode", QUIC_EV_CONN_SPPKTS, qc);
				gso_fallback = dglen;
				/* Only send a single datagram now that GSO is disabled. */
				dglen = qc->path->mtu;
			}
		}

		first_pkt = read_ptr(pos + sizeof(dglen));
		pos += QUIC_DGRAM_HEADLEN;
		tmpbuf.area = (char *)pos;
		tmpbuf.size = tmpbuf.data = dglen;

		TRACE_PROTO("TX dgram", QUIC_EV_CONN_SPPKTS, qc);
		if (!skip_sendto) {
			int ret = qc_snd_buf(qc, &tmpbuf, tmpbuf.data, 0, gso);
			if (ret < 0) {
				if (gso && ret == -EIO) {
					/* Disable permanently UDP GSO for this listener.
					 * Retry standard emission.
					 */
					TRACE_ERROR("mark listener UDP GSO as unsupported", QUIC_EV_CONN_SPPKTS, qc, first_pkt);
					HA_ATOMIC_OR(&qc->li->flags, LI_F_UDP_GSO_NOTSUPP);
					continue;
				}

				TRACE_ERROR("sendto fatal error", QUIC_EV_CONN_SPPKTS, qc, first_pkt);
				qc_kill_conn(qc);
				qc_free_tx_coalesced_pkts(qc, first_pkt);
				b_del(buf, dglen + QUIC_DGRAM_HEADLEN);
				qc_purge_tx_buf(qc, buf);
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
			else {
				qc->cntrs.sent_bytes += ret;
				if (gso && ret > gso)
					qc->cntrs.sent_bytes_gso += ret;
			}
		}

		b_del(buf, dglen + QUIC_DGRAM_HEADLEN);
		qc->bytes.tx += tmpbuf.data;
		time_sent_ms = now_ms;
		time_sent_ns = task_mono_time();

		for (pkt = first_pkt; pkt; pkt = next_pkt) {
			struct quic_cc *cc = &qc->path->cc;

			/* Packets built with GSO from consecutive datagrams
			 * are attached together but without COALESCED flag.
			 * Unlink them to treat them separately on ACK Rx.
			 */
			if (!(pkt->flags & QUIC_FL_TX_PACKET_COALESCED)) {
				if (pkt->prev) {
					pkt->prev->next = NULL;
					pkt->prev = NULL;
				}

				/* Packet from first dgram only were sent on non-GSO fallback. */
				if (gso_fallback) {
					BUG_ON_HOT(gso_fallback < dglen);
					gso_fallback -= dglen;

					/* Built a new datagram header. */
					buf->head -= QUIC_DGRAM_HEADLEN;
					b_add(buf, QUIC_DGRAM_HEADLEN);
					write_u16(b_head(buf), gso_fallback);
					write_ptr(b_head(buf) + sizeof(gso_fallback), pkt);
					break;
				}
			}

			qc->cntrs.sent_pkt++;

			pkt->time_sent_ns = time_sent_ns;
			pkt->time_sent_ms = time_sent_ms;
			if (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING) {
				pkt->pktns->tx.time_of_last_eliciting = time_sent_ms;
				qc->path->ifae_pkts++;
				if (qc->flags & QUIC_FL_CONN_IDLE_TIMER_RESTARTED_AFTER_READ)
					qc_idle_timer_rearm(qc, 0, 0);
				if (cc->algo->on_transmit)
					cc->algo->on_transmit(cc);
				if (cc->algo->drs_on_transmit)
					cc->algo->drs_on_transmit(cc, pkt);
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
			if ((global.tune.options & GTUNE_QUIC_CC_HYSTART) && pkt->pktns == qc->apktns)
				cc->algo->hystart_start_round(cc, pkt->pn_node.key);
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

/* Flush txbuf for <qc> connection. This must be called prior to a packet
 * preparation when txbuf contains older data. A send will be conducted for
 * these data.
 *
 * Returns 1 on success : buffer is empty and can be use for packet
 * preparation. On error 0 is returned.
 */
int qc_purge_txbuf(struct quic_conn *qc, struct buffer *buf)
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

/* Try to send application frames from list <frms> on connection <qc>. This
 * function is provided for MUX upper layer usage only.
 *
 * Returns the result from qc_send() function.
 */
enum quic_tx_err qc_send_mux(struct quic_conn *qc, struct list *frms,
                             struct quic_pacer *pacer)
{
	struct list send_list = LIST_HEAD_INIT(send_list);
	enum quic_tx_err ret = QUIC_TX_ERR_NONE;
	int max_dgram = 0, sent;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);
	BUG_ON(qc->mux_state != QC_MUX_READY); /* Only MUX can uses this function so it must be ready. */

	if (qc->conn->flags & CO_FL_SOCK_WR_SH) {
		qc->conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH;
		TRACE_DEVEL("connection on error", QUIC_EV_CONN_TXPKT, qc);
		return QUIC_TX_ERR_FATAL;
	}

	/* Try to send post handshake frames first unless on 0-RTT. */
	if ((qc->flags & QUIC_FL_CONN_NEED_POST_HANDSHAKE_FRMS) &&
	    qc->state >= QUIC_HS_ST_COMPLETE) {
		quic_build_post_handshake_frames(qc);
		qel_register_send(&send_list, qc->ael, &qc->ael->pktns->tx.frms);
		qc_send(qc, 0, &send_list, 0);
	}

	if (pacer) {
		max_dgram = pacer->credit;
		BUG_ON(max_dgram <= 0); /* pacer must specify a positive burst value. */
	}

	TRACE_STATE("preparing data (from MUX)", QUIC_EV_CONN_TXPKT, qc);
	qel_register_send(&send_list, qc->ael, frms);
	sent = qc_send(qc, 0, &send_list, max_dgram);

	if (pacer && qc->path->cc.algo->check_app_limited)
		qc->path->cc.algo->check_app_limited(&qc->path->cc, sent);

	if (sent <= 0) {
		ret = QUIC_TX_ERR_FATAL;
	}
	else if (pacer) {
		BUG_ON(sent > max_dgram); /* Must not exceed pacing limit. */
		if (max_dgram == sent && !LIST_ISEMPTY(frms))
			ret = QUIC_TX_ERR_PACING;
		quic_pacing_sent_done(pacer, sent);
	}

	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return ret;
}

/* Select <*tls_ctx> and <*ver> for the encryption level <qel> of <qc> QUIC
 * connection, depending on its state, especially the negotiated version.
 */
static inline void qc_select_tls_ver(struct quic_conn *qc,
                                     struct quic_enc_level *qel,
                                     struct quic_tls_ctx **tls_ctx,
                                     const struct quic_version **ver)
{
	if (qc->negotiated_version) {
		*ver = qc->negotiated_version;
		if (qel == qc->iel)
			*tls_ctx = qc->nictx;
		else
			*tls_ctx = &qel->tls_ctx;
	}
	else {
		*ver = qc->original_version;
		*tls_ctx = &qel->tls_ctx;
	}
}

/* Prepare one or several QUIC datagrams/packets for sending from <qels> list
 * of encryption levels. Several packets can be coalesced into a single
 * datagram. The result is written into <buf>.
 *
 * If <max_dgrams> is non null, it limits the number of prepared datagrams.
 * Useful to support pacing emission.
 *
 * Each datagram is prepended by a two fields header : the datagram length and
 * the address of first packet in the datagram.
 *
 * Returns the number of prepared datagrams on success which may be 0. On error
 * a negative error code is returned.
 */
static int qc_prep_pkts(struct quic_conn *qc, struct buffer *buf,
                         struct list *qels, int max_dgrams)
{
	int cc, padding;
	struct quic_tx_packet *first_pkt, *prv_pkt;
	unsigned char *end, *pos;
	uint32_t wrlen; /* may differ from dglen if GSO used */
	uint16_t dglen;
	int total = 0;
	struct quic_enc_level *qel, *tmp_qel;
	int dgram_cnt = 0;
	/* Restrict GSO emission to comply with sendmsg limitation. See QUIC_MAX_GSO_DGRAMS for more details. */
	uchar gso_dgram_cnt = 0;

	TRACE_ENTER(QUIC_EV_CONN_IO_CB, qc);
	/* Currently qc_prep_pkts() does not handle buffer wrapping so the
	 * caller must ensure that buf is reset.
	 */
	BUG_ON_HOT(buf->head || buf->data);

	cc =  qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE;
	padding = 0;
	first_pkt = prv_pkt = NULL;
	end = pos = (unsigned char *)b_head(buf);
	dglen = wrlen = 0;

	list_for_each_entry_safe(qel, tmp_qel, qels, el_send) {
		struct quic_tls_ctx *tls_ctx;
		const struct quic_version *ver;
		struct list *frms = qel->send_frms;
		struct quic_enc_level *next_qel;
		int probe, must_ack;

		if (qel == qc->eel) {
			/* Next encryption level */
			continue;
		}

		qc_select_tls_ver(qc, qel, &tls_ctx, &ver);

		/* Retrieve next QEL. Set it to NULL if on qels last element. */
		next_qel = LIST_NEXT(&qel->el_send, struct quic_enc_level *, el_send);
		if (&next_qel->el_send == qels)
			next_qel = NULL;
		/* We do not probe if an immediate close was asked */
		probe = !cc ? qel->pktns->tx.pto_probe : 0;

		/* Build packets for QEL until nothing to send (and no padding
		 * required anymore) while there is still room left in buffer.
		 */
		while (b_contig_space(buf) >= QUIC_DGRAM_HEADLEN &&
		       (qc_may_build_pkt(qc, frms, qel, cc, probe, &must_ack) ||
		        (padding && !next_qel))) {

			enum quic_pkt_type pkt_type;
			struct quic_tx_packet *cur_pkt;
			enum qc_build_pkt_err err;

			TRACE_PROTO("TX prep pkts", QUIC_EV_CONN_PHPKTS, qc, qel);

			/* Start to decrement <max_dgrams> after the first packet built. */
			if (!dglen && pos != (unsigned char *)b_head(buf)) {
				if (max_dgrams && !--max_dgrams) {
					BUG_ON(LIST_ISEMPTY(frms));
					TRACE_PROTO("reached max allowed built datagrams", QUIC_EV_CONN_PHPKTS, qc, qel);
					goto out;
				}
			}

			if (!first_pkt)
				pos += QUIC_DGRAM_HEADLEN;

			/* On starting a new datagram, calculate end max offset
			 * to stay under MTU limit.
			 */
			if (!dglen) {
				if (cc)
					end = pos + QUIC_MIN_CC_PKTSIZE;
				else if (!quic_peer_validated_addr(qc) && qc_is_listener(qc))
					end = pos + QUIC_MIN(qc->path->mtu, quic_may_send_bytes(qc));
				else
					end = pos + qc->path->mtu;

				/* Ensure end does not go beyond buffer */
				if (end > (unsigned char *)b_wrap(buf))
					end = (unsigned char *)b_wrap(buf);
			}

			/* RFC 9000 14.1 Initial datagram size
			 *
			 * Similarly, a server MUST expand the payload of all UDP
			 * datagrams carrying ack-eliciting Initial packets to at least the
			 * smallest allowed maximum datagram size of 1200 bytes.
			 */
			if (qel == qc->iel && (!LIST_ISEMPTY(frms) || probe)) {
				 /* Ensure that no ack-eliciting packets are sent into too small datagrams */
				if (end - pos < QUIC_INITIAL_PACKET_MINLEN) {
					TRACE_PROTO("No more enough room to build an Initial packet",
					            QUIC_EV_CONN_PHPKTS, qc);
					break;
				}

				/* padding will be set for last QEL, except when probing:
				 * to build a PING only non coalesced Initial datagram for
				 * instance when blocked by the anti-amplification limit,
				 * this datagram MUST be padded.
				 */
				padding = 1;
			}

			pkt_type = quic_enc_level_pkt_type(qc, qel);
			/* <paddding> parameter for qc_build_pkt() must not be set to 1 when
			 * building PING only Initial datagram (a datagram with an Initial
			 * packet inside containing only a PING frame as ack-eliciting
			 * frame). This is the case when both <probe> and LIST_EMPTY(<frms>)
			 * conditions are verified (see qc_do_build_pkt()).
			 */
			cur_pkt = qc_build_pkt(&pos, end, qel, tls_ctx, frms,
			                       qc, ver, dglen, pkt_type, must_ack,
			                       padding && !next_qel && (!probe || !LIST_ISEMPTY(frms)),
			                       probe, cc, &err);
			if (!cur_pkt) {
				switch (err) {
				case QC_BUILD_PKT_ERR_ALLOC:
					qc_purge_tx_buf(qc, buf);
					break;

				case QC_BUILD_PKT_ERR_ENCRYPT:
					// trace already emitted by function above
					break;

				case QC_BUILD_PKT_ERR_BUFROOM:
					/* If a first packet could be built, do not lose it,
					 * except if it is an too short Initial.
					 */
					if (first_pkt && (first_pkt->type != QUIC_PACKET_TYPE_INITIAL ||
					                  wrlen >= QUIC_INITIAL_PACKET_MINLEN)) {
						qc_txb_store(buf, wrlen, first_pkt);
					}
					TRACE_PROTO("could not prepare anymore packet", QUIC_EV_CONN_PHPKTS, qc, qel);
					break;

				default:
					ABORT_NOW(); /* error case not handled */
					break;
				}

				if (err == QC_BUILD_PKT_ERR_ALLOC || err == QC_BUILD_PKT_ERR_ENCRYPT)
					goto err;
				first_pkt = NULL;
				goto out;
			}


			if (qc->flags & QUIC_FL_CONN_RETRANS_OLD_DATA)
				cur_pkt->flags |= QUIC_FL_TX_PACKET_PROBE_WITH_OLD_DATA;

			/* keep trace of the first packet in the datagram */
			if (!first_pkt)
				first_pkt = cur_pkt;

			/* Attach the current one to the previous one and vice versa */
			if (prv_pkt) {
				prv_pkt->next = cur_pkt;
				cur_pkt->prev = prv_pkt;

				/* On GSO, do not flag consecutive packets from
				 * 2 different datagrams as coalesced. They
				 * will be unlinked on qc_send_ppkts().
				 */
				if (dglen)
					cur_pkt->flags |= QUIC_FL_TX_PACKET_COALESCED;
			}

			/* If <dglen> is NULL at this stage, it means the built
			 * packet is the first of a new datagram.
			 */
			if (!dglen)
				++dgram_cnt;

			total += cur_pkt->len;
			dglen += cur_pkt->len;
			wrlen += cur_pkt->len;

			/* Reset padding if datagram is big enough. */
			if (dglen >= QUIC_INITIAL_PACKET_MINLEN)
				padding = 0;
			BUG_ON(padding && !next_qel);

			/* Build only one datagram when an immediate close is required. */
			if (cc)
				goto out;

			/* Only one short packet by datagram when probing. */
			if (probe && qel == qc->ael)
				break;

			if (LIST_ISEMPTY(frms)) {
				/* Everything sent. Continue within the same datagram. */
				prv_pkt = cur_pkt;
			}
			else if (!(global.tune.options & GTUNE_QUIC_NO_UDP_GSO) &&
			         !(HA_ATOMIC_LOAD(&qc->li->flags) & LI_F_UDP_GSO_NOTSUPP) &&
			         dglen == qc->path->mtu &&
			         (char *)end < b_wrap(buf) &&
			         ++gso_dgram_cnt < QUIC_MAX_GSO_DGRAMS) {

				/* A datagram covering the full MTU has been
				 * built, use GSO to built next entry. Do not
				 * reserve extra space for datagram header.
				 */
				prv_pkt = cur_pkt;
				dglen = 0;

			}
			else {
				/* Finalize current datagram if not all frames sent. */
				qc_txb_store(buf, wrlen, first_pkt);
				first_pkt = NULL;
				wrlen = dglen = 0;
				padding = 0;
				prv_pkt = NULL;
				gso_dgram_cnt = 0;
			}

			/* qc_do_build_pkt() is responsible to decrement probe
			 * value. Required to break loop on qc_may_build_pkt().
			 */
			probe = qel->pktns->tx.pto_probe;
		}

		TRACE_DEVEL("next encryption level", QUIC_EV_CONN_PHPKTS, qc);
	}

 out:
	if (first_pkt)
		qc_txb_store(buf, wrlen, first_pkt);

	if (cc && total) {
		BUG_ON(buf != &qc->tx.cc_buf);
		BUG_ON(dglen != total);
		qc->tx.cc_dgram_len = dglen;
	}

	TRACE_LEAVE(QUIC_EV_CONN_PHPKTS, qc);
	return dgram_cnt;

 err:
	TRACE_DEVEL("leaving on error", QUIC_EV_CONN_PHPKTS, qc);
	return -1;
}

/* Encode frames and send them as packets for <qc> connection. Input frames are
 * specified via quic_enc_level <send_list> through their send_frms member. Set
 * <old_data> when reemitted duplicated data.
 *
 * If <max_dgrams> is non null, it limits the number of emitted datagrams.
 * Useful to support pacing emission.
 *
 * Note that <send_list> will always be emptied on function completion, both on
 * success and error.
 *
 * Returns the number of sent datagrams on success. It means either that all
 * input frames were sent or emission is interrupted due to pacing. Else a
 * negative error code is returned.
 */
int qc_send(struct quic_conn *qc, int old_data, struct list *send_list,
            int max_dgrams)
{
	struct quic_enc_level *qel, *tmp_qel;
	int prep = 0, ret = 0;
	struct buffer *buf;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	buf = qc_get_txb(qc);
	if (!buf) {
		TRACE_ERROR("buffer allocation failed", QUIC_EV_CONN_TXPKT, qc);
		ret = -1;
		goto out;
	}

	if (b_data(buf) && !qc_purge_txbuf(qc, buf)) {
		TRACE_ERROR("Could not purge TX buffer", QUIC_EV_CONN_TXPKT, qc);
		ret = -1;
		goto out;
	}

	if (old_data) {
		TRACE_STATE("old data for probing asked", QUIC_EV_CONN_TXPKT, qc);
		qc->flags |= QUIC_FL_CONN_RETRANS_OLD_DATA;
	}

	/* Prepare and send packets until we could not further prepare packets.
	 * Sending must be interrupted if a CONNECTION_CLOSE was already sent
	 * previously and is currently not needed.
	 */
	while (!LIST_ISEMPTY(send_list) &&
	       (!(qc->flags & (QUIC_FL_CONN_CLOSING|QUIC_FL_CONN_DRAINING)) ||
	        (qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE))) {

		/* Buffer must always be empty before qc_prep_pkts() usage.
		 * qc_send_ppkts() ensures it is cleared on success.
		 */
		BUG_ON_HOT(b_data(buf));
		b_reset(buf);

		prep = qc_prep_pkts(qc, buf, send_list, max_dgrams ? max_dgrams - ret : 0);
		BUG_ON(max_dgrams && prep > max_dgrams);

		if (b_data(buf) && !qc_send_ppkts(buf, qc->xprt_ctx)) {
			if (qc->flags & QUIC_FL_CONN_TO_KILL)
				qc_txb_release(qc);
			ret = -1;
			goto out;
		}

		if (prep <= 0) {
			/* TODO should this be considered error if prep<0 ? */
			TRACE_DEVEL("stopping on qc_prep_pkts() return", QUIC_EV_CONN_TXPKT, qc);
			break;
		}

		ret += prep;
		BUG_ON(max_dgrams && ret > max_dgrams);
		if (max_dgrams && ret == max_dgrams && !LIST_ISEMPTY(send_list)) {
			TRACE_DEVEL("stopping for artificial pacing", QUIC_EV_CONN_TXPKT, qc);
			break;
		}

		if ((qc->flags & QUIC_FL_CONN_DRAINING) &&
		    !(qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE)) {
			TRACE_DEVEL("draining connection", QUIC_EV_CONN_TXPKT, qc);
			break;
		}
	}

	qc_txb_release(qc);

 out:
	if (old_data) {
		TRACE_STATE("no more need old data for probing", QUIC_EV_CONN_TXPKT, qc);
		qc->flags &= ~QUIC_FL_CONN_RETRANS_OLD_DATA;
	}

	/* Always reset QEL sending list. */
	list_for_each_entry_safe(qel, tmp_qel, send_list, el_send) {
		LIST_DEL_INIT(&qel->el_send);
		qel->send_frms = NULL;
	}

	TRACE_DEVEL((ret > 0 ? "leaving" : "leaving in error"), QUIC_EV_CONN_TXPKT, qc);
	return ret;
}

/* Insert <qel> into <send_list> in preparation for sending. Set its send
 * frames list pointer to <frms>.
 */
void qel_register_send(struct list *send_list, struct quic_enc_level *qel,
                       struct list *frms)
{
	/* Ensure QEL is not already registered for sending. */
	BUG_ON(LIST_INLIST(&qel->el_send));

	LIST_APPEND(send_list, &qel->el_send);
	qel->send_frms = frms;
}

/* Returns true if <qel> should be registered for sending. This is the case if
 * frames are prepared, probing is set, <qc> ACK timer has fired or a
 * CONNECTION_CLOSE is required.
 */
int qel_need_sending(struct quic_enc_level *qel, struct quic_conn *qc)
{
	return !LIST_ISEMPTY(&qel->pktns->tx.frms) ||
	       qel->pktns->tx.pto_probe ||
	       (qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) ||
	       (qc->flags & (QUIC_FL_CONN_ACK_TIMER_FIRED|QUIC_FL_CONN_IMMEDIATE_CLOSE));
}

/* Retransmit up to two datagrams depending on packet number space.
 * Return 0 when failed, 0 if not.
 */
int qc_dgrams_retransmit(struct quic_conn *qc)
{
	int ret = 0;
	int sret;
	struct quic_pktns *ipktns = qc->ipktns;
	struct quic_pktns *hpktns = qc->hpktns;
	struct quic_pktns *apktns = qc->apktns;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	/* Note that if the Initial packet number space is not discarded,
	 * this is also the case for the Handshake packet number space.
	 */
	if (ipktns && (ipktns->flags & QUIC_FL_PKTNS_PROBE_NEEDED)) {
		int i;

		for (i = 0; i < QUIC_MAX_NB_PTO_DGRAMS; i++) {
			struct list send_list = LIST_HEAD_INIT(send_list);
			struct list ifrms = LIST_HEAD_INIT(ifrms);
			struct list hfrms = LIST_HEAD_INIT(hfrms);

			qc_prep_hdshk_fast_retrans(qc, &ifrms, &hfrms);
			TRACE_DEVEL("Avail. ack eliciting frames", QUIC_EV_CONN_FRMLIST, qc, &ifrms);
			TRACE_DEVEL("Avail. ack eliciting frames", QUIC_EV_CONN_FRMLIST, qc, &hfrms);
			if (!LIST_ISEMPTY(&ifrms)) {
				ipktns->tx.pto_probe = 1;
				if (!LIST_ISEMPTY(&hfrms))
					hpktns->tx.pto_probe = 1;

				qel_register_send(&send_list, qc->iel, &ifrms);
				if (qc->hel)
					qel_register_send(&send_list, qc->hel, &hfrms);

				sret = qc_send(qc, 1, &send_list, 0);
				qc_free_frm_list(qc, &ifrms);
				qc_free_frm_list(qc, &hfrms);
				if (sret < 0)
					goto leave;
			}
			else {
				/* No frame to send due to amplification limit
				 * or allocation failure. A PING frame will be
				 * emitted for probing.
				 */
				ipktns->tx.pto_probe = 1;
				qel_register_send(&send_list, qc->iel, &ifrms);
				sret = qc_send(qc, 0, &send_list, 0);
				qc_free_frm_list(qc, &ifrms);
				qc_free_frm_list(qc, &hfrms);
				if (sret < 0)
					goto leave;

				break;
			}
		}
		TRACE_STATE("no more need to probe Initial packet number space",
					QUIC_EV_CONN_TXPKT, qc);
		ipktns->flags &= ~QUIC_FL_PKTNS_PROBE_NEEDED;
		if (hpktns)
			hpktns->flags &= ~QUIC_FL_PKTNS_PROBE_NEEDED;
	}
	else {
		int i;

		if (hpktns && (hpktns->flags & QUIC_FL_PKTNS_PROBE_NEEDED)) {
			hpktns->tx.pto_probe = 0;
			for (i = 0; i < QUIC_MAX_NB_PTO_DGRAMS; i++) {
				struct list send_list = LIST_HEAD_INIT(send_list);
				struct list frms1 = LIST_HEAD_INIT(frms1);

				qc_prep_fast_retrans(qc, hpktns, &frms1, NULL);
				TRACE_DEVEL("Avail. ack eliciting frames", QUIC_EV_CONN_FRMLIST, qc, &frms1);
				if (!LIST_ISEMPTY(&frms1)) {
					hpktns->tx.pto_probe = 1;
					qel_register_send(&send_list, qc->hel, &frms1);
					sret = qc_send(qc, 1, &send_list, 0);
					qc_free_frm_list(qc, &frms1);
					if (sret < 0)
						goto leave;
				}
			}
			TRACE_STATE("no more need to probe Handshake packet number space",
			            QUIC_EV_CONN_TXPKT, qc);
			hpktns->flags &= ~QUIC_FL_PKTNS_PROBE_NEEDED;
		}
		else if (apktns && (apktns->flags & QUIC_FL_PKTNS_PROBE_NEEDED)) {
			struct list send_list = LIST_HEAD_INIT(send_list);
			struct list frms2 = LIST_HEAD_INIT(frms2);
			struct list frms1 = LIST_HEAD_INIT(frms1);

			apktns->tx.pto_probe = 0;
			qc_prep_fast_retrans(qc, apktns, &frms1, &frms2);
			TRACE_PROTO("Avail. ack eliciting frames", QUIC_EV_CONN_FRMLIST, qc, &frms1);
			TRACE_PROTO("Avail. ack eliciting frames", QUIC_EV_CONN_FRMLIST, qc, &frms2);

			if (!LIST_ISEMPTY(&frms1)) {
				apktns->tx.pto_probe = 1;
				qel_register_send(&send_list, qc->ael, &frms1);
				sret = qc_send(qc, 1, &send_list, 0);
				qc_free_frm_list(qc, &frms1);
				if (sret < 0) {
					qc_free_frm_list(qc, &frms2);
					goto leave;
				}
			}

			if (!LIST_ISEMPTY(&frms2)) {
				apktns->tx.pto_probe = 1;
				qel_register_send(&send_list, qc->ael, &frms2);
				sret = qc_send(qc, 1, &send_list, 0);
				qc_free_frm_list(qc, &frms2);
				if (sret < 0)
					goto leave;
			}
			TRACE_STATE("no more need to probe 01RTT packet number space",
			            QUIC_EV_CONN_TXPKT, qc);
			apktns->flags &= ~QUIC_FL_PKTNS_PROBE_NEEDED;
		}
	}

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
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
int send_version_negotiation(int fd, struct sockaddr_storage *addr,
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
int send_stateless_reset(struct listener *l, struct sockaddr_storage *dstaddr,
                         struct quic_rx_packet *rxpkt)
{
	int ret = 0, pktlen, rndlen;
	unsigned char pkt[64];
	const socklen_t addrlen = get_addr_len(dstaddr);
	struct proxy *prx;
	struct quic_counters *prx_counters;

	TRACE_ENTER(QUIC_EV_STATELESS_RST);

	/* RFC 9000 10.3. Stateless Reset
	 *
	 * Endpoints MUST discard packets that are too small to be valid QUIC
	 * packets. To give an example, with the set of AEAD functions defined
	 * in [QUIC-TLS], short header packets that are smaller than 21 bytes
	 * are never valid.
	 *
	 * [...]
	 *
	 * RFC 9000 10.3.3. Looping
	 *
	 * An endpoint MUST ensure that every Stateless Reset that it sends is
	 * smaller than the packet that triggered it, unless it maintains state
	 * sufficient to prevent looping. In the event of a loop, this results
	 * in packets eventually being too small to trigger a response.
	 */
	if (rxpkt->len <= QUIC_STATELESS_RESET_PACKET_MINLEN) {
		TRACE_DEVEL("rxpkt too short", QUIC_EV_STATELESS_RST);
		goto leave;
	}

	prx = l->bind_conf->frontend;
	prx_counters = EXTRA_COUNTERS_GET(prx->extra_counters_fe, &quic_stats_module);

	/* RFC 9000 10.3. Stateless Reset
	 *
	 * An endpoint that sends a Stateless Reset in response to a packet that is
	 * 43 bytes or shorter SHOULD send a Stateless Reset that is one byte shorter
	 * than the packet it responds to.
	 */
	pktlen = rxpkt->len <= 43 ? rxpkt->len - 1 :
	                            QUIC_STATELESS_RESET_PACKET_MINLEN;
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

/* Return the long packet type matching with <qv> version and <type> */
static inline int quic_pkt_type(int type, uint32_t version)
{
	if (version != QUIC_PROTOCOL_VERSION_2)
		return type;

	switch (type) {
	case QUIC_PACKET_TYPE_INITIAL:
		return 1;
	case QUIC_PACKET_TYPE_0RTT:
		return 2;
	case QUIC_PACKET_TYPE_HANDSHAKE:
		return 3;
	case QUIC_PACKET_TYPE_RETRY:
		return 0;
	}

	return -1;
}


/* Generate a Retry packet and send it on <fd> socket to <addr> in response to
 * the Initial <pkt> packet.
 *
 * Returns 0 on success else non-zero.
 */
int send_retry(int fd, struct sockaddr_storage *addr,
               struct quic_rx_packet *pkt, const struct quic_version *qv)
{
	int ret = 0;
	unsigned char buf[128];
	int i = 0, token_len;
	const socklen_t addrlen = get_addr_len(addr);
	struct quic_cid scid;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT);

	/* long header(1) | fixed bit(1) | packet type QUIC_PACKET_TYPE_RETRY(2) | unused random bits(4)*/
	buf[i++] = (QUIC_PACKET_LONG_HEADER_BIT | QUIC_PACKET_FIXED_BIT) |
		(quic_pkt_type(QUIC_PACKET_TYPE_RETRY, qv->num) << QUIC_PACKET_TYPE_SHIFT) |
		statistical_prng_range(16);
	/* version */
	write_n32(&buf[i], qv->num);
	i += sizeof(uint32_t);

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
	if ((sizeof(buf) - i < QUIC_TLS_TAG_LEN) ||
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

/* Write a 32-bits integer to a buffer with <buf> as address.
 * Make <buf> point to the data after this 32-buts value if succeeded.
 * Note that these 32-bits integers are networkg bytes ordered.
 * Returns 0 if failed (not enough room in the buffer), 1 if succeeded.
 */
static inline int quic_write_uint32(unsigned char **buf,
                                    const unsigned char *end, uint32_t val)
{
	if (end - *buf < sizeof val)
		return 0;

	write_u32(*buf, htonl(val));
	*buf += sizeof val;

	return 1;
}

/* Return the maximum number of bytes we must use to completely fill a
 * buffer with <sz> as size for a data field of bytes prefixed by its QUIC
 * variable-length (may be 0).
 * Also put in <*len_sz> the size of this QUIC variable-length.
 * So after returning from this function we have : <*len_sz> + <ret> <= <sz>
 * (<*len_sz> = { max(i), i + ret <= <sz> }) .
 */
static inline size_t max_available_room(size_t sz, size_t *len_sz)
{
	size_t sz_sz, ret;
	size_t diff;

	sz_sz = quic_int_getsize(sz);
	if (sz <= sz_sz)
		return 0;

	ret = sz - sz_sz;
	*len_sz = quic_int_getsize(ret);
	/* Difference between the two sizes. Note that <sz_sz> >= <*len_sz>. */
	diff = sz_sz - *len_sz;
	if (unlikely(diff > 0)) {
		/* Let's try to take into an account remaining bytes.
		 *
		 *                  <----------------> <sz_sz>
		 *  <--------------><-------->  +----> <max_int>
		 *       <ret>       <len_sz>   |
		 *  +---------------------------+-----------....
		 *  <--------------------------------> <sz>
		 */
		size_t max_int = quic_max_int(*len_sz);

		if (max_int + *len_sz <= sz)
			ret = max_int;
		else
			ret = sz - diff;
	}

	return ret;
}

/* This function computes the maximum data we can put into a buffer with <sz> as
 * size prefixed with a variable-length field "Length" whose value is the
 * remaining data length, already filled of <ilen> bytes which must be taken
 * into an account by "Length" field, and finally followed by the data we want
 * to put in this buffer prefixed again by a variable-length field.
 * <sz> is the size of the buffer to fill.
 * <ilen> the number of bytes already put after the "Length" field.
 * <dlen> the number of bytes we want to at most put in the buffer.
 * Also set <*dlen_sz> to the size of the data variable-length we want to put in
 * the buffer. This is typically this function which must be used to fill as
 * much as possible a QUIC packet made of only one CRYPTO or STREAM frames.
 * Returns this computed size if there is enough room in the buffer, 0 if not.
 */
static inline size_t max_stream_data_size(size_t sz, size_t ilen, size_t dlen)
{
	size_t ret, len_sz, dlen_sz;

	/*
	 * The length of variable-length QUIC integers are powers of two.
	 * Look for the first 3length" field value <len_sz> which match our need.
	 * As we must put <ilen> bytes in our buffer, the minimum value for
	 * <len_sz> is the number of bytes required to encode <ilen>.
	 */
	for (len_sz = quic_int_getsize(ilen);
	     len_sz <= QUIC_VARINT_MAX_SIZE;
	     len_sz <<= 1) {
		if (sz < len_sz + ilen)
			return 0;

		ret = max_available_room(sz - len_sz - ilen, &dlen_sz);
		if (!ret)
			return 0;

		/* Check that <*len_sz> matches <ret> value */
		if (len_sz + ilen + dlen_sz + ret <= quic_max_int(len_sz))
			return ret < dlen ? ret : dlen;
	}

	return 0;
}

/* Return the length in bytes of <pn> packet number depending on
 * <largest_acked_pn> the largest ackownledged packet number.
 */
static inline size_t quic_packet_number_length(int64_t pn,
                                               int64_t largest_acked_pn)
{
	int64_t max_nack_pkts;

	/* About packet number encoding, the RFC says:
	 * The sender MUST use a packet number size able to represent more than
	 * twice as large a range than the difference between the largest
	 * acknowledged packet and packet number being sent.
	 */
	max_nack_pkts = 2 * (pn - largest_acked_pn) + 1;
	if (max_nack_pkts > 0xffffff)
		return 4;
	if (max_nack_pkts > 0xffff)
		return 3;
	if (max_nack_pkts > 0xff)
		return 2;

	return 1;
}

/* Encode <pn> packet number with <pn_len> as length in byte into a buffer with
 * <buf> as current copy address and <end> as pointer to one past the end of
 * this buffer. This is the responsibility of the caller to check there is
 * enough room in the buffer to copy <pn_len> bytes.
 * Never fails.
 */
static inline int quic_packet_number_encode(unsigned char **buf,
                                            const unsigned char *end,
                                            uint64_t pn, size_t pn_len)
{
	if (end - *buf < pn_len)
		return 0;

	/* Encode the packet number. */
	switch (pn_len) {
	case 1:
		**buf = pn;
		break;
	case 2:
		write_n16(*buf, pn);
		break;
	case 3:
		(*buf)[0] = pn >> 16;
		(*buf)[1] = pn >> 8;
		(*buf)[2] = pn;
		break;
	case 4:
		write_n32(*buf, pn);
		break;
	}
	*buf += pn_len;

	return 1;
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
	EVP_CIPHER_CTX *hp_ctx = tls_ctx->tx.hp_ctx;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	*fail = 0;

	if (!quic_tls_hp_encrypt(mask, pn + QUIC_PACKET_PN_MAXLEN, sizeof mask, hp_ctx, tls_ctx->tx.hp_key)) {
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
static int qc_build_frms(struct list *outlist, struct list *inlist,
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
	room -= *len;

	/* If we are not probing we must take into an account the congestion
	 * control window.
	 */
	if (!qel->pktns->tx.pto_probe) {
		size_t remain = quic_cc_path_prep_data(qc->path);

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
			/* Compute the data length of this CRYPTO frame. */
			dlen = max_stream_data_size(room, hlen, cf->crypto.len);
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
				if (qc_stream_frm_is_acked(qc, cf)) {
					qc_frm_free(qc, &cf);
					continue;
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
				((cf->type & QUIC_STREAM_FRAME_TYPE_OFF_BIT) ? quic_int_getsize(cf->stream.offset) : 0);
			/* Compute the data length of this STREAM frame. */
			avail_room = room - hlen;
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

				qc_stream_desc_send(cf->stream.stream,
				                    cf->stream.offset,
				                    cf->stream.len);
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
				cf->stream.offset += dlen;
				cf->stream.data = (unsigned char *)b_peek(&cf_buf, dlen);

				qc_stream_desc_send(new_cf->stream.stream,
				                    new_cf->stream.offset,
				                    new_cf->stream.len);
			}

			/* TODO the MUX is notified about the frame sending via
			 * previous qc_stream_desc_send call. However, the
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
		if (unlikely(qel == qc->iel || qel == qc->hel)) {
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
			out->connection_close_app.error_code = qc->err.code;
			out->connection_close_app.reason_phrase_len = 0;
		}
	}
	else {
		out->type = QUIC_FT_CONNECTION_CLOSE;
		out->connection_close.error_code = qc->err.code;
		out->connection_close.reason_phrase_len = 0;
	}
	TRACE_LEAVE(QUIC_EV_CONN_BFRM, qc);

}

/* Returns the <ack_delay> field value in microsecond to be set in an ACK frame
 * depending on the time the packet with a new largest packet number was received.
 */
static inline uint64_t quic_compute_ack_delay_us(unsigned int time_received,
                                                 struct quic_conn *conn)
{
	return ((now_ms - time_received) * 1000) >> conn->tx.params.ack_delay_exponent;
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
 * NOTE: This function does not build all the possible combinations of packets
 * depending on its list of parameters. In most cases, <frms> frame list is
 * not empty. So, this function first tries to build this list of frames.
 * Then some padding is added to this packet if <padding> boolean is set true.
 * The unique case one wants to do that is when a first Initial packet was
 * previously built into the same datagram as the currently built one and when
 * this packet is supposed to pad the datagram, if needed, to build an at
 * least 1200 bytes long Initial datagram.
 * If <padding> is not true, if the packet is too short, the packet is also
 * padded. This is very often the case when no frames are provided by <frms>
 * and when probing with only a PING frame.
 * Finally, if <frms> was empty, if <probe> boolean is true this function builds
 * a PING only packet handling also the cases where it must be padded.
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
	struct quic_frame frm;
	struct quic_frame ack_frm;
	struct quic_frame cc_frm;
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

		path_room = quic_cc_path_prep_data(qc->path);
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
		ack_frm.type = QUIC_FT_ACK;
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
			if (padding) {
				len_frms = 0;
				goto comp_pkt_len;
			}

			if (qel->pktns->tx.pto_probe) {
				/* If a probing packet was asked and could not be built,
				 * this is not because there was not enough room, but due to
				 * its frames which were already acknowledeged.
				 * See qc_stream_frm_is_acked()) called by qc_build_frms().
				 * Note that qc_stream_frm_is_acked() logs a trace in this
				 * case mentionning some frames were already acknowledged.
				 *
				 * That said, the consequence must be the same: cancelling
				 * the packet build as if there was not enough room in the
				 * TX buffer.
				 */
				 qel->pktns->tx.pto_probe--;
				 goto no_room;
			}

			if (!ack_frm_len)
				goto no_room;
		}
	}

 comp_pkt_len:
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
	dglen += head_len + len;
	if (pkt->type != QUIC_PACKET_TYPE_SHORT)
		dglen += len_sz;

	if (padding && dglen < QUIC_INITIAL_PACKET_MINLEN) {
		padding_len = QUIC_INITIAL_PACKET_MINLEN - dglen;

		len += padding_len;
		/* Update size of packet length field with new PADDING data. */
		if (pkt->type != QUIC_PACKET_TYPE_SHORT) {
			size_t len_sz_diff = quic_int_getsize(len) - len_sz;
			if (len_sz_diff) {
				padding_len -= len_sz_diff;
				len_sz += len_sz_diff;
				dglen += len_sz_diff;
			}
		}
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

	BUG_ON(qel->pktns->tx.pto_probe &&
	       !(pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING));
	/* If this packet is ack-eliciting and we are probing let's
	 * decrement the PTO probe counter.
	 */
	if ((pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING) &&
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
	pkt->time_sent_ms = TICK_ETERNITY;
	pkt->time_sent_ns = 0;
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
 * Return built packet instance or NULL on error. <err> will be set to the
 * specific error encountered.
 */
static struct quic_tx_packet *qc_build_pkt(unsigned char **pos,
                                           const unsigned char *end,
                                           struct quic_enc_level *qel,
                                           struct quic_tls_ctx *tls_ctx, struct list *frms,
                                           struct quic_conn *qc, const struct quic_version *ver,
                                           size_t dglen, int pkt_type, int must_ack,
                                           int padding, int probe, int cc,
                                           enum qc_build_pkt_err *err)
{
	/* The pointer to the packet number field. */
	unsigned char *buf_pn;
	unsigned char *first_byte, *last_byte, *payload;
	int64_t pn;
	size_t pn_len, payload_len, aad_len;
	struct quic_tx_packet *pkt;
	int encrypt_failure = 0;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);
	TRACE_PROTO("TX pkt build", QUIC_EV_CONN_TXPKT, qc, NULL, qel);
	*err = QC_BUILD_PKT_ERR_NONE;
	pkt = pool_alloc(pool_head_quic_tx_packet);
	if (!pkt) {
		TRACE_DEVEL("Not enough memory for a new packet", QUIC_EV_CONN_TXPKT, qc);
		*err = QC_BUILD_PKT_ERR_ALLOC;
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
		*err = QC_BUILD_PKT_ERR_BUFROOM;
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
		*err = QC_BUILD_PKT_ERR_ENCRYPT;
		goto err;
	}

	last_byte += QUIC_TLS_TAG_LEN;
	pkt->len += QUIC_TLS_TAG_LEN;
	quic_apply_header_protection(qc, first_byte, buf_pn, pn_len, tls_ctx, &encrypt_failure);
	if (encrypt_failure) {
		/* TODO Unrecoverable failure, unencrypted data should be returned to the caller. */
		WARN_ON("quic_apply_header_protection failure");
		*err = QC_BUILD_PKT_ERR_ENCRYPT;
		goto err;
	}

	/* Consume a packet number */
	qel->pktns->tx.next_pn++;
	qc->bytes.prep += pkt->len;
	if (qc->bytes.prep >= 3 * qc->bytes.rx && !quic_peer_validated_addr(qc)) {
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

	TRACE_PROTO("TX pkt built", QUIC_EV_CONN_TXPKT, qc, pkt);
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return pkt;

 err:
	/* TODO What about the frames which have been built for this packet? */
	free_quic_tx_packet(qc, pkt);
	TRACE_DEVEL("leaving on error", QUIC_EV_CONN_TXPKT, qc);
	return NULL;
}
/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
