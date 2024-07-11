/*
 * include/haproxy/quic_trace-t.h
 * Definitions for QUIC traces internal types, constants and flags.
 *
 * Copyright (C) 2023
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef _HAPROXY_QUIC_TRACE_T_H
#define _HAPROXY_QUIC_TRACE_T_H

#include <haproxy/quic_tls-t.h>
#include <haproxy/trace-t.h>

extern struct trace_source trace_quic;

/* Used only for QUIC TLS key phase traces */
struct quic_kp_trace {
	const unsigned char *rx_sec;
	size_t rx_seclen;
	const struct quic_tls_kp *rx;
	const unsigned char *tx_sec;
	size_t tx_seclen;
	const struct quic_tls_kp *tx;
};

/* Only for debug purpose */
struct enc_debug_info {
	unsigned char *payload;
	size_t payload_len;
	unsigned char *aad;
	size_t aad_len;
	uint64_t pn;
};

/* Structure to store enough information about the RX CRYPTO frames. */
struct quic_rx_crypto_frm {
	struct eb64_node offset_node;
	uint64_t len;
	const unsigned char *data;
	struct quic_rx_packet *pkt;
};

#define           QUIC_EV_CONN_NEW       (1ULL << 0)
#define           QUIC_EV_CONN_INIT      (1ULL << 1)
#define           QUIC_EV_CONN_ISEC      (1ULL << 2)
#define           QUIC_EV_CONN_RSEC      (1ULL << 3)
#define           QUIC_EV_CONN_WSEC      (1ULL << 4)
#define           QUIC_EV_CONN_RWSEC     (1ULL << 5)
#define           QUIC_EV_CONN_LPKT      (1ULL << 6)
#define           QUIC_EV_CONN_SPKT      (1ULL << 7)
#define           QUIC_EV_CONN_ENCPKT    (1ULL << 8)
#define           QUIC_EV_CONN_TXPKT     (1ULL << 9)
#define           QUIC_EV_CONN_PAPKT     (1ULL << 10)
#define           QUIC_EV_CONN_PAPKTS    (1ULL << 11)
#define           QUIC_EV_CONN_IO_CB     (1ULL << 12)
#define           QUIC_EV_CONN_RMHP      (1ULL << 13)
#define           QUIC_EV_CONN_PRSHPKT   (1ULL << 14)
#define           QUIC_EV_CONN_PRSAPKT   (1ULL << 15)
#define           QUIC_EV_CONN_PRSFRM    (1ULL << 16)
#define           QUIC_EV_CONN_PRSAFRM   (1ULL << 17)
#define           QUIC_EV_CONN_BFRM      (1ULL << 18)
#define           QUIC_EV_CONN_PHPKTS    (1ULL << 19)
#define           QUIC_EV_CONN_TRMHP     (1ULL << 20)
#define           QUIC_EV_CONN_ELRMHP    (1ULL << 21)
#define           QUIC_EV_CONN_RXPKT     (1ULL << 22)
#define           QUIC_EV_CONN_SSLDATA   (1ULL << 23)
#define           QUIC_EV_CONN_RXCDATA   (1ULL << 24)
#define           QUIC_EV_CONN_ADDDATA   (1ULL << 25)
#define           QUIC_EV_CONN_FFLIGHT   (1ULL << 26)
#define           QUIC_EV_CONN_SSLALERT  (1ULL << 27)
#define           QUIC_EV_CONN_PSTRM     (1ULL << 28)
#define           QUIC_EV_CONN_RTTUPDT   (1ULL << 29)
#define           QUIC_EV_CONN_CC        (1ULL << 30)
#define           QUIC_EV_CONN_SPPKTS    (1ULL << 31)
#define           QUIC_EV_CONN_PKTLOSS   (1ULL << 32)
#define           QUIC_EV_CONN_STIMER    (1ULL << 33)
#define           QUIC_EV_CONN_PTIMER    (1ULL << 34)
#define           QUIC_EV_CONN_SPTO      (1ULL << 35)
#define           QUIC_EV_CONN_BCFRMS    (1ULL << 36)
#define           QUIC_EV_CONN_XPRTSEND  (1ULL << 37)
#define           QUIC_EV_CONN_XPRTRECV  (1ULL << 38)
#define           QUIC_EV_CONN_FREED     (1ULL << 39)
#define           QUIC_EV_CONN_CLOSE     (1ULL << 40)
#define           QUIC_EV_CONN_ACKSTRM   (1ULL << 41)
#define           QUIC_EV_CONN_FRMLIST   (1ULL << 42)
#define           QUIC_EV_STATELESS_RST  (1ULL << 43)
#define           QUIC_EV_TRANSP_PARAMS  (1ULL << 44)
#define           QUIC_EV_CONN_IDLE_TIMER (1ULL << 45)
#define           QUIC_EV_CONN_SUB       (1ULL << 46)
#define           QUIC_EV_CONN_ELEVELSEL (1ULL << 47)
#define           QUIC_EV_CONN_RCV       (1ULL << 48)
#define           QUIC_EV_CONN_KILL      (1ULL << 49)
#define           QUIC_EV_CONN_KP        (1ULL << 50)
#define           QUIC_EV_CONN_SSL_COMPAT (1ULL << 51)
#define           QUIC_EV_CONN_BIND_TID  (1ULL << 52)

#endif /* _HAPROXY_QUIC_TRACE_T_H */
