#ifndef _HAPROXY_QUIC_TUNE_T_H
#define _HAPROXY_QUIC_TUNE_T_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#define QUIC_TUNE_NO_PACING     0x00000001

struct quic_tune {
	uint options;
};

#endif /* USE_QUIC */

#endif /* _HAPROXY_QUIC_TUNE_T_H */
