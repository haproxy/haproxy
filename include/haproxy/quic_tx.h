/*
 * QUIC protocol definitions (TX side).
 *
 * Copyright (C) 2023
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

#ifndef _HAPROXY_QUIC_TX_H
#define _HAPROXY_QUIC_TX_H

#include <haproxy/buf-t.h>
#include <haproxy/list-t.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_tls-t.h>
#include <haproxy/quic_pacing-t.h>
#include <haproxy/quic_rx-t.h>
#include <haproxy/quic_tx-t.h>

struct buffer *qc_txb_alloc(struct quic_conn *qc);
void qc_txb_release(struct quic_conn *qc);
int qc_purge_txbuf(struct quic_conn *qc, struct buffer *buf);
struct buffer *qc_get_txb(struct quic_conn *qc);

enum quic_tx_err qc_send_mux(struct quic_conn *qc, struct list *frms,
                             struct quic_pacer *pacer);

void qel_register_send(struct list *send_list, struct quic_enc_level *qel,
                       struct list *frms);
int qel_need_sending(struct quic_enc_level *qel, struct quic_conn *qc);
int qc_send(struct quic_conn *qc, int old_data, struct list *send_list,
            int max_dgrams);

int qc_dgrams_retransmit(struct quic_conn *qc);
void qc_prep_hdshk_fast_retrans(struct quic_conn *qc,
                                struct list *ifrms, struct list *hfrms);
int send_retry(int fd, struct sockaddr_storage *addr,
               struct quic_rx_packet *pkt, const struct quic_version *qv);
int send_stateless_reset(struct listener *l, struct sockaddr_storage *dstaddr,
                         struct quic_rx_packet *rxpkt);
int send_version_negotiation(int fd, struct sockaddr_storage *addr,
                             struct quic_rx_packet *pkt);

/* The TX packets sent in the same datagram are linked to each others in
 * the order they are built. This function detach a packet from its successor
 * and predecessor in the same datagram.
 */
static inline void quic_tx_packet_dgram_detach(struct quic_tx_packet *pkt)
{
	if (pkt->prev)
		pkt->prev->next = pkt->next;
	if (pkt->next)
		pkt->next->prev = pkt->prev;
	pkt->prev = pkt->next = NULL;
}


/* Increment the reference counter of <pkt> */
static inline void quic_tx_packet_refinc(struct quic_tx_packet *pkt)
{
	pkt->refcnt++;
}

/* Decrement the reference counter of <pkt> */
static inline void quic_tx_packet_refdec(struct quic_tx_packet *pkt)
{
	BUG_ON(pkt->refcnt <= 0);
	if (--pkt->refcnt == 0) {
		BUG_ON(!LIST_ISEMPTY(&pkt->frms));
		/* If there are others packet in the same datagram <pkt> is attached to,
		 * detach the previous one and the next one from <pkt>.
		 */
		quic_tx_packet_dgram_detach(pkt);
		pool_free(pool_head_quic_tx_packet, pkt);
	}
}

/* Return the number of bytes which may be sent from <qc> connection when
 * it has not already been validated. Note that this is the responsibility
 * of the caller to check that the case with quic_peer_validated_addr().
 * This latter BUG_ON() if 3 * qc->rx.bytes < qc->tx.prep_bytes.
 */
static inline size_t quic_may_send_bytes(struct quic_conn *qc)
{
	return 3 * qc->bytes.rx - qc->bytes.prep;
}


#endif /* _HAPROXY_QUIC_TX_H */
