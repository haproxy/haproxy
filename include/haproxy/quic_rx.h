/*
 * QUIC protocol definitions (RX side).
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

#ifndef _HAPROXY_QUIC_RX_H
#define _HAPROXY_QUIC_RX_H

#include <haproxy/listener-t.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_rx-t.h>

int quic_dgram_parse(struct quic_dgram *dgram, struct quic_conn *from_qc,
                     struct listener *li);
int qc_treat_rx_pkts(struct quic_conn *qc);
int qc_parse_hd_form(struct quic_rx_packet *pkt,
                     unsigned char **pos, const unsigned char *end);
void quic_free_ncbuf(struct ncbuf *ncbuf);
int qc_release_lost_pkts(struct quic_conn *qc, struct quic_pktns *pktns,
                         struct list *pkts, uint64_t now_us);

#endif /* _HAPROXY_QUIC_RX_H */
