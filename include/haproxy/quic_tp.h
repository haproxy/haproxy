#ifndef _HAPROXY_QUIC_TP_H
#define _HAPROXY_QUIC_TP_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/quic_tp-t.h>
#include <haproxy/xprt_quic-t.h>

void quic_transport_params_init(struct quic_transport_params *p, int server);
int quic_transport_params_encode(unsigned char *buf,
                                 const unsigned char *end,
                                 struct quic_transport_params *p,
                                 int server);

int quic_transport_params_store(struct quic_conn *conn, int server,
                                const unsigned char *buf,
                                const unsigned char *end);

int qc_lstnr_params_init(struct quic_conn *qc,
                         const struct quic_transport_params *listener_params,
                         const unsigned char *stateless_reset_token,
                         const unsigned char *dcid, size_t dcidlen,
                         const unsigned char *scid, size_t scidlen,
                         const unsigned char *odcid, size_t odcidlen, int token);
#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_TP_H */
