#ifndef _HAPROXY_MUX_QUIC_QOS_H
#define _HAPROXY_MUX_QUIC_QOS_H

#include <haproxy/mux_quic.h>

int qcc_qos_recv(struct qcc *qcc);

int qcc_qos_send_frames(struct qcc *qcc, struct list *frms, int stream);

int qcc_qos_send_tp(struct qcc *qcc);

#endif /* _HAPROXY_MUX_QUIC_QOS_H */
