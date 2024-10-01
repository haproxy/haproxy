#include <import/eb64tree.h>

#include <haproxy/quic_conn.h>
#include <haproxy/quic_frame.h>
#include <haproxy/quic_retransmit.h>
#include <haproxy/quic_stream-t.h>
#include <haproxy/quic_trace.h>
#include <haproxy/quic_tx.h>
#include <haproxy/trace.h>

#define TRACE_SOURCE &trace_quic

/* Check if STREAM frame <f> content has already been acknowledged before
 * retransmitting it. If only a subset of <f> content is acknowledged, frame is
 * updated to only cover the unacked data.
 *
 * Returns true if frame content is fully acknowledged, false if partially or
 * not at all.
 */
int qc_stream_frm_is_acked(struct quic_conn *qc, struct quic_frame *f)
{
	const struct qf_stream *frm = &f->stream;
	const struct qc_stream_desc *s = frm->stream;
	const int frm_fin = f->type & QUIC_STREAM_FRAME_TYPE_FIN_BIT;

	if (!eb64_lookup(&qc->streams_by_id, frm->id)) {
		TRACE_DEVEL("STREAM frame already acked : stream released", QUIC_EV_CONN_PRSAFRM, qc, f);
		return 1;
	}

	/* Frame cannot advertise FIN for a smaller data range. */
	BUG_ON(frm_fin && frm->offset + frm->len < s->ack_offset);

	if (frm->offset + frm->len < s->ack_offset ||
	    (frm->offset + frm->len == s->ack_offset &&
	     (!frm_fin || !(s->flags & QC_SD_FL_WAIT_FOR_FIN)))) {
		TRACE_DEVEL("STREAM frame already acked : fully acked range", QUIC_EV_CONN_PRSAFRM, qc, f);
		return 1;
	}

	if (frm->offset < s->ack_offset &&
	    frm->offset + frm->len > s->ack_offset) {
		/* Data range partially acked, remove it from STREAM frame. */
		const uint64_t diff = s->ack_offset - frm->offset;
		TRACE_DEVEL("updated partially acked frame", QUIC_EV_CONN_PRSAFRM, qc, f);
		qc_stream_frm_mv_fwd(f, diff);
	}

	return 0;
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
			/* Do not resend this frame if in the "already acked range" */
			if (qc_stream_frm_is_acked(qc, frm))
				continue;

			frm->stream.dup = 1;
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
			            qc, dup_frm, &origin->pkt->pn_node.key);
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
void qc_prep_fast_retrans(struct quic_conn *qc,
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
			else
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
