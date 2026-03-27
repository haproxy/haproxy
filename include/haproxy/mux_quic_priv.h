#ifndef _HAPROXY_MUX_QUIC_PRIV_H
#define _HAPROXY_MUX_QUIC_PRIV_H

/* This header file should only be used by QUIC-MUX layer internally. */

#include <haproxy/mux_quic-t.h>

void qcs_idle_open(struct qcs *qcs);
void qcs_close_local(struct qcs *qcs);
int qcs_is_completed(struct qcs *qcs);

uint64_t qcs_prep_bytes(const struct qcs *qcs);

#endif /* _HAPROXY_MUX_QUIC_PRIV_H */
