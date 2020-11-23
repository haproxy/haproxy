/*
 * include/haproxy/quic_frame.h
 * This file contains prototypes for QUIC frames.
 *
 * Copyright 2020 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
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

#ifndef _HAPROXY_QUIC_FRAME_H
#define _HAPROXY_QUIC_FRAME_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/quic_frame-t.h>
#include <haproxy/xprt_quic-t.h>

const char *quic_frame_type_string(enum quic_frame_type ft);

int qc_build_frm(unsigned char **buf, const unsigned char *end,
                 struct quic_frame *frm, struct quic_tx_packet *pkt,
                 struct quic_conn *conn);

int qc_parse_frm(struct quic_frame *frm, struct quic_rx_packet *pkt,
                 const unsigned char **buf, const unsigned char *end,
                 struct quic_conn *conn);

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_FRAME_H */
