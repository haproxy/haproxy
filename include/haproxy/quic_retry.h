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

extern struct pool_head *pool_head_quic_retry_token;

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
int quic_retry_packet_check(struct quic_conn *qc, struct quic_rx_packet *pkt,
                            const unsigned char *beg, const unsigned char *end,
                            const unsigned char *pos, size_t *retry_token_len);

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_RETRY_H */
