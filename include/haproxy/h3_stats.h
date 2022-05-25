#ifndef _HAPROXY_H3_STATS_H
#define _HAPROXY_H3_STATS_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/h3_stats-t.h>

struct h3_counters;

void h3_inc_err_cnt(void *ctx, int error_code);
void h3_inc_frame_type_cnt(struct h3_counters *ctrs, int frm_type);

#endif /* USE_QUIC */
#endif /* _HAPROXY_H3_STATS_H */
