#ifndef _HAPROXY_QUIC_RETRY_H
#define _HAPROXY_QUIC_RETRY_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <inttypes.h>
#include <sys/socket.h>

#include <haproxy/quic_cid-t.h>
#include <haproxy/quic_rx-t.h>
#include <haproxy/quic_sock-t.h>

struct listener;

int quic_generate_retry_token(unsigned char *token, size_t len,
                              const uint32_t version,
                              const struct quic_cid *odcid,
                              const struct quic_cid *dcid,
                              struct sockaddr_storage *addr);
int parse_retry_token(struct quic_conn *qc,
                      const unsigned char *token, const unsigned char *end,
                      struct quic_cid *odcid);
int quic_retry_token_check(struct quic_rx_packet *pkt,
                           struct quic_dgram *dgram,
                           struct listener *l,
                           struct quic_conn *qc,
                           struct quic_cid *odcid);

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_RETRY_H */
