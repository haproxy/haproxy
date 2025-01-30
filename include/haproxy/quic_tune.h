#ifndef _HAPROXY_QUIC_TUNE_H
#define _HAPROXY_QUIC_TUNE_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/quic_tune-t.h>

extern struct quic_tune quic_tune;

#endif /* USE_QUIC */

#endif /* _HAPROXY_QUIC_TUNE_H */
