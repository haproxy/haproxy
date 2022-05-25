#ifndef _HAPROXY_H3_STATS_T_H
#define _HAPROXY_H3_STATS_T_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

extern struct stats_module h3_stats_module;

#endif /* USE_QUIC */
#endif /* _HAPROXY_H3_STATS_T_H */
