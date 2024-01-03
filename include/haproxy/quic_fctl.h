#ifndef _HAPROXY_QUIC_FCTL_H
#define _HAPROXY_QUIC_FCTL_H

#include <haproxy/quic_fctl-t.h>

void qfctl_init(struct quic_fctl *fctl, uint64_t limit);

int qfctl_rblocked(const struct quic_fctl *fctl);
int qfctl_sblocked(const struct quic_fctl *fctl);

int qfctl_set_max(struct quic_fctl *fctl, uint64_t val,
                  int *unblock_soft, int *unblock_real);

int qfctl_rinc(struct quic_fctl *fctl, uint64_t diff);
int qfctl_sinc(struct quic_fctl *fctl, uint64_t diff);

uint64_t qfctl_rcap(const struct quic_fctl *fctl);

#endif /* _HAPROXY_QUIC_FCTL_H */
