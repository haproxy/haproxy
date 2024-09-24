/*
 * include/haproxy/quic_token.h
 * This file contains definition for QUIC tokens (provided by NEW_TOKEN).
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

#ifndef _PROTO_QUIC_TOKEN_H
#define _PROTO_QUIC_TOKEN_H

#include <haproxy/listener-t.h>
#include <haproxy/quic_rx-t.h>
#include <haproxy/quic_sock-t.h>
#include <haproxy/quic_tls-t.h>

#define QUIC_TOKEN_RAND_LEN 16
/* The size of QUIC token as provided by NEW_TOKEN frame in bytes:
 * one byte as format identifier, sizeof(uint32_t) bytes for the timestamp,
 * QUIC_TLS_TAG_LEN bytes for the AEAD TAG and QUIC_TOKEN_RAND_LEN bytes
 * for the random data part which are used to derive a token secret in
 * addition to the cluster secret (global.cluster_secret).
 */
#define QUIC_TOKEN_LEN (1 + sizeof(uint32_t) + QUIC_TLS_TAG_LEN + QUIC_TOKEN_RAND_LEN)

/* RFC 9001 4.6. 0-RTT
 * TLS13 sets a limit of seven days on the time between the original
 * connection and any attempt to use 0-RTT.
 */
#define QUIC_TOKEN_DURATION_SEC (7 * 24 * 3600) // 7 days in seconds

int quic_generate_token(unsigned char *token, size_t len,
                        struct sockaddr_storage *addr);
int quic_token_check(struct quic_rx_packet *pkt, struct quic_dgram *dgram,
                     struct quic_conn *qc);

#endif  /* _PROTO_QUIC_TOKEN_H */

