#ifndef _HAPROXY_QUIC_TUNE_T_H
#define _HAPROXY_QUIC_TUNE_T_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#define QUIC_TUNE_FE_LISTEN_OFF    0x00000001

#define QUIC_TUNE_NO_PACING     0x00000001
#define QUIC_TUNE_NO_UDP_GSO    0x00000002
#define QUIC_TUNE_SOCK_PER_CONN 0x00000004
#define QUIC_TUNE_CC_HYSTART    0x00000008

struct quic_tune {
	struct {
		uint sec_glitches_threshold;
		uint opts;    /* QUIC_TUNE_FE_* options specific to FE side */
		uint fb_opts; /* QUIC_TUNE_FB_* options shared by both side */
	} fe;

	struct {
		uint sec_glitches_threshold;
		uint fb_opts; /* QUIC_TUNE_FB_* options shared by both side */
	} be;

	uint options;
};

#endif /* USE_QUIC */

#endif /* _HAPROXY_QUIC_TUNE_T_H */
