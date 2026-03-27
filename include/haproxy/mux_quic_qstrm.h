#ifndef _HAPROXY_MUX_QUIC_QSTRM_H
#define _HAPROXY_MUX_QUIC_QSTRM_H

#include <haproxy/mux_quic.h>

int qcc_qstrm_recv(struct qcc *qcc);

int qcc_qstrm_send_frames(struct qcc *qcc, struct list *frms);

#endif /* _HAPROXY_MUX_QUIC_QSTRM_H */
