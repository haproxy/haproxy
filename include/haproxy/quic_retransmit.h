#ifndef _HAPROXY_QUIC_RETRANSMIT_H
#define _HAPROXY_QUIC_RETRANSMIT_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/list-t.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_tls-t.h>

struct quic_frame;

int qc_stream_frm_is_acked(struct quic_conn *qc, struct quic_frame *f);

void qc_prep_fast_retrans(struct quic_conn *qc,
                          struct quic_pktns *pktns,
                          struct list *frms1, struct list *frms2);
void qc_prep_hdshk_fast_retrans(struct quic_conn *qc,
                                struct list *ifrms, struct list *hfrms);

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_RETRANSMIT_H */
