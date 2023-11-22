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

#include <haproxy/pool.h>
#include <haproxy/trace.h>
#include <haproxy/quic_sock.h>
#include <haproxy/quic_tls.h>
#include <haproxy/quic_trace.h>
#include <haproxy/ssl_sock-t.h>

DECLARE_POOL(pool_head_quic_tx_packet, "quic_tx_packet", sizeof(struct quic_tx_packet));
DECLARE_POOL(pool_head_quic_cc_buf, "quic_cc_buf", QUIC_MAX_CC_BUFSIZE);

static struct quic_tx_packet *qc_build_pkt(unsigned char **pos, const unsigned char *buf_end,
                                           struct quic_enc_level *qel, struct quic_tls_ctx *ctx,
                                           struct list *frms, struct quic_conn *qc,
                                           const struct quic_version *ver, size_t dglen, int pkt_type,
                                           int must_ack, int padding, int probe, int cc, int *err);

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
                                 struct quic_pktns *pktns,
                                 struct list *frms1, struct list *frms2)
{
	struct eb_root *pkts = &pktns->tx.pkts;
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
	    pkt->len + 4 > quic_may_send_bytes(qc)) {
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
void qc_prep_hdshk_fast_retrans(struct quic_conn *qc,
                                struct list *ifrms, struct list *hfrms)
{
	struct list itmp = LIST_HEAD_INIT(itmp);
	struct list htmp = LIST_HEAD_INIT(htmp);

	struct quic_enc_level *iqel = qc->iel;
	struct quic_enc_level *hqel = qc->hel;
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
		size_t may_send;

		may_send = quic_may_send_bytes(qc);
		dglen += pkt->next ? pkt->next->len + 4 : 0;
		if (dglen > may_send) {
			qc->flags |= QUIC_FL_CONN_ANTI_AMPLIFICATION_REACHED;
			TRACE_PROTO("anti-amplification limit would be reached", QUIC_EV_CONN_SPPKTS, qc, pkt);
			if (pkt->next)
				TRACE_PROTO("anti-amplification limit would be reached", QUIC_EV_CONN_SPPKTS, qc, pkt->next);
			if (qel == iqel && may_send >= QUIC_INITIAL_PACKET_MINLEN)
				TRACE_PROTO("will probe Initial packet number space", QUIC_EV_CONN_SPPKTS, qc);
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

/* Allocate Tx buffer from <qc> quic-conn if needed.
 *
 * Returns allocated buffer or NULL on error.
 */
struct buffer *qc_txb_alloc(struct quic_conn *qc)
{
	struct buffer *buf = &qc->tx.buf;
	if (!b_alloc(buf))
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
	 * For the momemt we do not care to leave data in the buffer for
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
	             "has_sec=%d cc=%d probe=%d must_ack=%d frms=%d prep_in_fligh=%llu cwnd=%llu",
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
	int ret = -1, cc;
	struct quic_enc_level *qel;
	unsigned char *end, *pos;
	struct quic_tx_packet *pkt;
	size_t total;

	TRACE_ENTER(QUIC_EV_CONN_PHPKTS, qc);

	qel = qc->ael;
	total = 0;
	pos = (unsigned char *)b_tail(buf);
	cc =  qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE;
	/* Each datagram is prepended with its length followed by the address
	 * of the first packet in the datagram (QUIC_DGRAM_HEADLEN).
	 */
	while ((!cc && b_contig_space(buf) >= (int)qc->path->mtu + QUIC_DGRAM_HEADLEN) ||
	        (cc && b_contig_space(buf) >= QUIC_MIN_CC_PKTSIZE + QUIC_DGRAM_HEADLEN)) {
		int err, probe, must_ack;

		TRACE_PROTO("TX prep app pkts", QUIC_EV_CONN_PHPKTS, qc, qel, frms);
		probe = 0;
		/* We do not probe if an immediate close was asked */
		if (!cc)
			probe = qel->pktns->tx.pto_probe;

		if (!qc_may_build_pkt(qc, frms, qel, cc, probe, &must_ack))
			break;

		/* Leave room for the datagram header */
		pos += QUIC_DGRAM_HEADLEN;
		if (cc) {
			end = pos + QUIC_MIN_CC_PKTSIZE;
		}
		else if (!quic_peer_validated_addr(qc) && qc_is_listener(qc)) {
			end = pos + QUIC_MIN(qc->path->mtu, quic_may_send_bytes(qc));
		}
		else {
			end = pos + qc->path->mtu;
		}

		pkt = qc_build_pkt(&pos, end, qel, &qel->tls_ctx, frms, qc, NULL, 0,
		                   QUIC_PACKET_TYPE_SHORT, must_ack, 0, probe, cc, &err);
		switch (err) {
		case -3:
			qc_purge_txbuf(qc, buf);
			goto leave;
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
		/* Build only one datagram when an immediate close is required. */
		if (cc)
			break;
	}

 out:
	if (total && cc) {
		BUG_ON(buf != &qc->tx.cc_buf);
		qc->tx.cc_dgram_len = total;
	}
	ret = total;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PHPKTS, qc);
	return ret;
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
		size_t headlen = sizeof dglen + sizeof pkt;

		dglen = read_u16(b_head(buf));
		pkt = read_ptr(b_head(buf) + sizeof dglen);
		qc_free_tx_coalesced_pkts(qc, pkt);
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
				qc_free_tx_coalesced_pkts(qc, first_pkt);
				b_del(buf, dglen + headlen);
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
		}

		b_del(buf, dglen + headlen);
		qc->bytes.tx += tmpbuf.data;
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

/* Build all the frames which must be sent just after the handshake have succeeded.
 * This is essentially NEW_CONNECTION_ID frames. A QUIC server must also send
 * a HANDSHAKE_DONE frame.
 * Return 1 if succeeded, 0 if not.
 */
int quic_build_post_handshake_frames(struct quic_conn *qc)
{
	int ret = 0, max;
	struct quic_enc_level *qel;
	struct quic_frame *frm, *frmbak;
	struct list frm_list = LIST_HEAD_INIT(frm_list);
	struct eb64_node *node;

	TRACE_ENTER(QUIC_EV_CONN_IO_CB, qc);

	qel = qc->ael;
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

		conn_id = new_quic_cid(qc->cids, qc, NULL, NULL);
		if (!conn_id) {
			qc_frm_free(qc, &frm);
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
		qc_frm_free(qc, &frm);

	/* The first CID sequence number value used to allocated CIDs by this function is 1,
	 * 0 being the sequence number of the CID for this connection.
	 */
	node = eb64_lookup_ge(qc->cids, 1);
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
int qc_send_app_pkts(struct quic_conn *qc, struct list *frms)
{
	int status = 0, ret;
	struct buffer *buf;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	buf = qc_get_txb(qc);
	if (!buf) {
		TRACE_ERROR("could not get a buffer", QUIC_EV_CONN_TXPKT, qc);
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
		quic_build_post_handshake_frames(qc);
		qc_send_app_pkts(qc, &qc->ael->pktns->tx.frms);
	}

	TRACE_STATE("preparing data (from MUX)", QUIC_EV_CONN_TXPKT, qc);
	qc->flags |= QUIC_FL_CONN_TX_MUX_CONTEXT;
	ret = qc_send_app_pkts(qc, frms);
	qc->flags &= ~QUIC_FL_CONN_TX_MUX_CONTEXT;

	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return ret;
}

/* Return the encryption level following the one which contains <el> list head
 * depending on <retrans> TX mode (retranmission or not).
 */
static inline struct quic_enc_level *qc_list_next_qel(struct list *el, int retrans)
{
	return !retrans ? LIST_NEXT(el, struct quic_enc_level *, list) :
                      LIST_NEXT(el, struct quic_enc_level *, retrans);
}

/* Return the encryption level following <qel> depending on <retrans> TX mode
 * (retranmission or not).
 */
static inline struct quic_enc_level *qc_next_qel(struct quic_enc_level *qel, int retrans)
{
	struct list *el = !retrans ? &qel->list : &qel->retrans;

	return qc_list_next_qel(el, retrans);
}

/* Return 1 if <qel> is at the head of its list, 0 if not. */
static inline int qc_qel_is_head(struct quic_enc_level *qel, struct list *l,
                                 int retrans)
{
	return !retrans ? &qel->list == l : &qel->retrans == l;
}

/* Select <*tls_ctx>, <*frms> and <*ver> for the encryption level <qel> of <qc> QUIC
 * connection, depending on its state, especially the negotiated version and if
 * retransmissions are required. If this the case <qels> is the list of encryption
 * levels to used, or NULL if no retransmissions are required.
 * Never fails.
 */
static inline void qc_select_tls_frms_ver(struct quic_conn *qc,
                                          struct quic_enc_level *qel,
                                          struct quic_tls_ctx **tls_ctx,
                                          struct list **frms,
                                          const struct quic_version **ver,
                                          struct list *qels)
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

	if (!qels)
		*frms = &qel->pktns->tx.frms;
	else
		*frms = qel->retrans_frms;
}

/* Prepare as much as possible QUIC datagrams/packets for sending from <qels>
 * list of encryption levels. Several packets can be coalesced into a single
 * datagram. The result is written into <buf>. Note that if <qels> is NULL,
 * the encryption levels which will be used are those currently allocated
 * and attached to the connection.
 *
 * Each datagram is prepended by a two fields header : the datagram length and
 * the address of first packet in the datagram.
 *
 * Returns the number of bytes prepared in datragrams/packets if succeeded
 * (may be 0), or -1 if something wrong happened.
 */
int qc_prep_hpkts(struct quic_conn *qc, struct buffer *buf, struct list *qels)
{
	int ret, cc, retrans, padding;
	struct quic_tx_packet *first_pkt, *prv_pkt;
	unsigned char *end, *pos;
	uint16_t dglen;
	size_t total;
	struct list *qel_list;
	struct quic_enc_level *qel;

	TRACE_ENTER(QUIC_EV_CONN_IO_CB, qc);
	/* Currently qc_prep_pkts() does not handle buffer wrapping so the
	 * caller must ensure that buf is reset.
	 */
	BUG_ON_HOT(buf->head || buf->data);

	ret = -1;
	cc =  qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE;
	retrans = !!qels;
	padding = 0;
	first_pkt = prv_pkt = NULL;
	end = pos = (unsigned char *)b_head(buf);
	dglen = 0;
	total = 0;

	qel_list = qels ? qels : &qc->qel_list;
	qel = qc_list_next_qel(qel_list, retrans);
	while (!qc_qel_is_head(qel, qel_list, retrans)) {
		struct quic_tls_ctx *tls_ctx;
		const struct quic_version *ver;
		struct list *frms, *next_frms;
		struct quic_enc_level *next_qel;

		if (qel == qc->eel) {
			/* Next encryption level */
			qel = qc_next_qel(qel, retrans);
			continue;
		}

		qc_select_tls_frms_ver(qc, qel, &tls_ctx, &frms, &ver, qels);

		next_qel = qc_next_qel(qel, retrans);
		next_frms = qc_qel_is_head(next_qel, qel_list, retrans) ? NULL :
			!qels ? &next_qel->pktns->tx.frms : next_qel->retrans_frms;

		/* Build as much as datagrams at <qel> encryption level.
		 * Each datagram is prepended with its length followed by the address
		 * of the first packet in the datagram (QUIC_DGRAM_HEADLEN).
		 */
		while ((!cc && b_contig_space(buf) >= (int)qc->path->mtu + QUIC_DGRAM_HEADLEN) ||
		        (cc && b_contig_space(buf) >= QUIC_MIN_CC_PKTSIZE + QUIC_DGRAM_HEADLEN) || prv_pkt) {
			int err, probe, must_ack;
			enum quic_pkt_type pkt_type;
			struct quic_tx_packet *cur_pkt;

			TRACE_PROTO("TX prep pkts", QUIC_EV_CONN_PHPKTS, qc, qel);
			probe = 0;
			/* We do not probe if an immediate close was asked */
			if (!cc)
				probe = qel->pktns->tx.pto_probe;

			if (!qc_may_build_pkt(qc, frms, qel, cc, probe, &must_ack)) {
				if (prv_pkt && qc_qel_is_head(next_qel, qel_list, retrans)) {
					qc_txb_store(buf, dglen, first_pkt);
					/* Build only one datagram when an immediate close is required. */
					if (cc)
						goto out;
				}

				TRACE_DEVEL("next encryption level", QUIC_EV_CONN_PHPKTS, qc);
				break;
			}

			if (!prv_pkt) {
				/* Leave room for the datagram header */
				pos += QUIC_DGRAM_HEADLEN;
				if (cc) {
					end = pos + QUIC_MIN_CC_PKTSIZE;
				}
				else if (!quic_peer_validated_addr(qc) && qc_is_listener(qc)) {
					end = pos + QUIC_MIN(qc->path->mtu, quic_may_send_bytes(qc));
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
			if (qel == qc->iel && !LIST_ISEMPTY(frms)) {
				if (end - pos < QUIC_INITIAL_PACKET_MINLEN) {
					TRACE_PROTO("No more enough room to build an Initial packet",
					            QUIC_EV_CONN_PHPKTS, qc);
					break;
				}

				/* Pad this Initial packet if there is no ack-eliciting frames to send from
				 * the next packet number space.
				 */
				if (!next_frms || LIST_ISEMPTY(next_frms))
					padding = 1;
			}

			pkt_type = quic_enc_level_pkt_type(qc, qel);
			cur_pkt = qc_build_pkt(&pos, end, qel, tls_ctx, frms,
			                       qc, ver, dglen, pkt_type,
			                       must_ack, padding, probe, cc, &err);
			switch (err) {
				case -3:
					qc_purge_tx_buf(qc, buf);
					goto leave;
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

			total += cur_pkt->len;
			dglen += cur_pkt->len;

			if (qc->flags & QUIC_FL_CONN_RETRANS_OLD_DATA)
				cur_pkt->flags |= QUIC_FL_TX_PACKET_PROBE_WITH_OLD_DATA;

			/* keep trace of the first packet in the datagram */
			if (!first_pkt)
				first_pkt = cur_pkt;

			/* Attach the current one to the previous one and vice versa */
			if (prv_pkt) {
				prv_pkt->next = cur_pkt;
				cur_pkt->prev = prv_pkt;
				cur_pkt->flags |= QUIC_FL_TX_PACKET_COALESCED;
			}

			/* If there is no more packet to build for this encryption level,
			 * select the next one <next_qel>, if any, to coalesce a packet in
			 * the same datagram, except if <qel> is the Application data
			 * encryption level which cannot be selected to do that.
			 */
			if (LIST_ISEMPTY(frms) && qel != qc->ael &&
			    !qc_qel_is_head(next_qel, qel_list, retrans)) {
				if (qel == qc->iel &&
				    (!qc_is_listener(qc) ||
				     cur_pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING))
					padding = 1;

				prv_pkt = cur_pkt;
				break;
			}
			else {
				qc_txb_store(buf, dglen, first_pkt);
				/* Build only one datagram when an immediate close is required. */
				if (cc)
					goto out;
				first_pkt = NULL;
				dglen = 0;
				padding = 0;
				prv_pkt = NULL;
			}
		}

		/* Next encryption level */
		qel = next_qel;
	}

 out:
	if (cc && total) {
		BUG_ON(buf != &qc->tx.cc_buf);
		BUG_ON(dglen != total);
		qc->tx.cc_dgram_len = dglen;
	}

	ret = total;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PHPKTS, qc);
	return ret;
}

/* Sends handshake packets from up to two encryption levels <tel> and <next_te>
 * with <tel_frms> and <next_tel_frms> as frame list respectively for <qc>
 * QUIC connection. <old_data> is used as boolean to send data already sent but
 * not already acknowledged (in flight).
 * Returns 1 if succeeded, 0 if not.
 */
int qc_send_hdshk_pkts(struct quic_conn *qc, int old_data,
                       struct quic_enc_level *qel1, struct quic_enc_level *qel2)
{
	int ret, status = 0;
	struct buffer *buf = qc_get_txb(qc);
	struct list qels = LIST_HEAD_INIT(qels);

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	if (!buf) {
		TRACE_ERROR("buffer allocation failed", QUIC_EV_CONN_TXPKT, qc);
		goto leave;
	}

	if (b_data(buf) && !qc_purge_txbuf(qc, buf)) {
		TRACE_ERROR("Could not purge TX buffer", QUIC_EV_CONN_TXPKT, qc);
		goto out;
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

	if (qel1) {
		BUG_ON(LIST_INLIST(&qel1->retrans));
		LIST_APPEND(&qels, &qel1->retrans);
	}

	if (qel2) {
		BUG_ON(LIST_INLIST(&qel2->retrans));
		LIST_APPEND(&qels, &qel2->retrans);
	}

	ret = qc_prep_hpkts(qc, buf, &qels);
	if (ret == -1) {
		qc_txb_release(qc);
		TRACE_ERROR("Could not build some packets", QUIC_EV_CONN_TXPKT, qc);
		goto out;
	}

	if (ret && !qc_send_ppkts(buf, qc->xprt_ctx)) {
		if (qc->flags & QUIC_FL_CONN_TO_KILL)
			qc_txb_release(qc);
		TRACE_ERROR("Could not send some packets", QUIC_EV_CONN_TXPKT, qc);
		goto out;
	}

	qc_txb_release(qc);
	status = 1;

 out:
	if (qel1) {
		LIST_DEL_INIT(&qel1->retrans);
		qel1->retrans_frms = NULL;
	}

	if (qel2) {
		LIST_DEL_INIT(&qel2->retrans);
		qel2->retrans_frms = NULL;
	}

	TRACE_STATE("no more need old data for probing", QUIC_EV_CONN_TXPKT, qc);
	qc->flags &= ~QUIC_FL_CONN_RETRANS_OLD_DATA;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return status;
}

/* Retransmit up to two datagrams depending on packet number space.
 * Return 0 when failed, 0 if not.
 */
int qc_dgrams_retransmit(struct quic_conn *qc)
{
	int ret = 0;
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
			struct list ifrms = LIST_HEAD_INIT(ifrms);
			struct list hfrms = LIST_HEAD_INIT(hfrms);
			struct list qels = LIST_HEAD_INIT(qels);

			qc_prep_hdshk_fast_retrans(qc, &ifrms, &hfrms);
			TRACE_DEVEL("Avail. ack eliciting frames", QUIC_EV_CONN_FRMLIST, qc, &ifrms);
			TRACE_DEVEL("Avail. ack eliciting frames", QUIC_EV_CONN_FRMLIST, qc, &hfrms);
			if (!LIST_ISEMPTY(&ifrms)) {
				ipktns->tx.pto_probe = 1;
				if (!LIST_ISEMPTY(&hfrms))
					hpktns->tx.pto_probe = 1;
				qc->iel->retrans_frms = &ifrms;
				if (qc->hel)
					qc->hel->retrans_frms = &hfrms;
				if (!qc_send_hdshk_pkts(qc, 1, qc->iel, qc->hel))
					goto leave;
				/* Put back unsent frames in their packet number spaces */
				LIST_SPLICE(&ipktns->tx.frms, &ifrms);
				if (hpktns)
					LIST_SPLICE(&hpktns->tx.frms, &hfrms);
			}
			else {
				/* We are in the case where the anti-amplification limit will be
				 * reached after having sent this datagram. There is no need to
				 * send more than one datagram.
				 */
				ipktns->tx.pto_probe = 1;
				qc->iel->retrans_frms = &ifrms;
				if (!qc_send_hdshk_pkts(qc, 0, qc->iel, NULL))
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
				struct list frms1 = LIST_HEAD_INIT(frms1);

				qc_prep_fast_retrans(qc, hpktns, &frms1, NULL);
				TRACE_DEVEL("Avail. ack eliciting frames", QUIC_EV_CONN_FRMLIST, qc, &frms1);
				if (!LIST_ISEMPTY(&frms1)) {
					hpktns->tx.pto_probe = 1;
					qc->hel->retrans_frms = &frms1;
					if (!qc_send_hdshk_pkts(qc, 1, qc->hel, NULL))
						goto leave;

					/* Put back unsent frames into their packet number spaces */
					LIST_SPLICE(&hpktns->tx.frms, &frms1);
				}
			}
			TRACE_STATE("no more need to probe Handshake packet number space",
			            QUIC_EV_CONN_TXPKT, qc);
			hpktns->flags &= ~QUIC_FL_PKTNS_PROBE_NEEDED;
		}
		else if (apktns && (apktns->flags & QUIC_FL_PKTNS_PROBE_NEEDED)) {
			struct list frms2 = LIST_HEAD_INIT(frms2);
			struct list frms1 = LIST_HEAD_INIT(frms1);

			apktns->tx.pto_probe = 0;
			qc_prep_fast_retrans(qc, apktns, &frms1, &frms2);
			TRACE_PROTO("Avail. ack eliciting frames", QUIC_EV_CONN_FRMLIST, qc, &frms1);
			TRACE_PROTO("Avail. ack eliciting frames", QUIC_EV_CONN_FRMLIST, qc, &frms2);
			if (!LIST_ISEMPTY(&frms1)) {
				apktns->tx.pto_probe = 1;
				if (!qc_send_app_probing(qc, &frms1)) {
					qc_free_frm_list(qc, &frms1);
					qc_free_frm_list(qc, &frms2);
					goto leave;
				}

				/* Put back unsent frames into their packet number spaces */
				LIST_SPLICE(&apktns->tx.frms, &frms1);
			}
			if (!LIST_ISEMPTY(&frms2)) {
				apktns->tx.pto_probe = 1;
				if (!qc_send_app_probing(qc, &frms2)) {
					qc_free_frm_list(qc, &frms2);
					goto leave;
				}
				/* Put back unsent frames into their packet number spaces */
				LIST_SPLICE(&apktns->tx.frms, &frms2);
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

/* Returns a boolean if <qc> needs to emit frames for <qel> encryption level. */
int qc_need_sending(struct quic_conn *qc, struct quic_enc_level *qel)
{
	return (qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE) ||
	       (qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) ||
	       qel->pktns->tx.pto_probe ||
	       !LIST_ISEMPTY(&qel->pktns->tx.frms);
}

/* Return 1 if <qc> connection may probe the Initial packet number space, 0 if not.
 * This is not the case if the remote peer address is not validated and if
 * it cannot send at least QUIC_INITIAL_PACKET_MINLEN bytes.
 */
int qc_may_probe_ipktns(struct quic_conn *qc)
{
	return quic_peer_validated_addr(qc) ||
		quic_may_send_bytes(qc) >= QUIC_INITIAL_PACKET_MINLEN;
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
int quic_generate_retry_token_aad(unsigned char *aad,
                                  uint32_t version,
                                  const struct quic_cid *cid,
                                  const struct sockaddr_storage *addr)
{
	unsigned char *p;

	p = aad;
	*(uint32_t *)p = htonl(version);
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
	const unsigned char *sec = global.cluster_secret;
	size_t seclen = sizeof global.cluster_secret;
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *aead = EVP_aes_128_gcm();
	uint32_t timestamp = (uint32_t)date.tv_sec;

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
	if (!quic_tls_encrypt(token + 1, p - token - 1, aad, aadlen, ctx, aead, iv)) {
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
					qc_frm_free(qc, &cf);
					continue;
				}

				stream_desc = eb64_entry(node, struct qc_stream_desc, by_id);
				if (strm_frm->offset.key + strm_frm->len <= stream_desc->ack_offset) {
					TRACE_DEVEL("ignored frame frame in already acked range",
					            QUIC_EV_CONN_PRSAFRM, qc, cf);
					qc_frm_free(qc, &cf);
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
			out->connection_close.error_code = qc->err.code;
			out->connection_close.reason_phrase_len = 0;
		}
	}
	else {
		out->type = QUIC_FT_CONNECTION_CLOSE;
		out->connection_close.error_code = qc->err.code;
		out->connection_close.reason_phrase_len = 0;
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

			if (!ack_frm_len && !qel->pktns->tx.pto_probe)
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
 * Return -3 if the packet could not be allocated, -2 if could not be encrypted for
 * any reason, -1 if there was not enough room to build a packet.
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
		*err = -3;
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

/* Wake-up upper layer for sending if all conditions are met :
 * - room in congestion window or probe packet to sent
 * - socket FD ready to sent or listener socket used
 *
 * Returns 1 if upper layer has been woken up else 0.
 */
int qc_notify_send(struct quic_conn *qc)
{
	const struct quic_pktns *pktns = qc->apktns;

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

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
