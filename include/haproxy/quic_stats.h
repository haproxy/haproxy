#ifndef _HAPROXY_QUIC_STATS_H
#define _HAPROXY_QUIC_STATS_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/quic_stats-t.h>

void quic_stats_transp_err_count_inc(struct quic_counters *ctrs, int error_code);

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_STATS_H */
