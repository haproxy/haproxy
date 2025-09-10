#ifndef _HAPROXY_QUIC_TUNE_T_H
#define _HAPROXY_QUIC_TUNE_T_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif


/* Default limit of loss detection on a single frame. If exceeded, connection is closed. */
#define QUIC_DFLT_CC_MAX_FRAME_LOSS       10
/* Default congestion window size. 480 kB, equivalent to the legacy value which was 30*bufsize */
#define QUIC_DFLT_CC_MAX_WIN_SIZE  491520
/* Default ratio value applied to a dynamic Packet reorder threshold. */
#define QUIC_DFLT_CC_REORDER_RATIO        50 /* in percent */
/* Default max-idle-timeout advertised via TP */
#define QUIC_DFLT_FE_MAX_IDLE_TIMEOUT   30000 /* milliseconds */
#define QUIC_DFLT_BE_MAX_IDLE_TIMEOUT   30000 /* milliseconds */
/* Default Retry threshold */
#define QUIC_DFLT_SEC_RETRY_THRESHOLD     100 /* in connection openings */


#define QUIC_TUNE_FE_LISTEN_OFF    0x00000001
#define QUIC_TUNE_FE_SOCK_PER_CONN 0x00000002

#define QUIC_TUNE_FB_TX_PACING  0x00000001
#define QUIC_TUNE_FB_TX_UDP_GSO 0x00000002
#define QUIC_TUNE_FB_CC_HYSTART 0x00000004

struct quic_tune {
	struct {
		uint cc_cubic_min_losses;
		uint cc_max_frame_loss;
		size_t cc_max_win_size;
		uint cc_reorder_ratio;
		uint max_idle_timeout;
		uint sec_glitches_threshold;
		uint sec_retry_threshold;
		uint opts;    /* QUIC_TUNE_FE_* options specific to FE side */
		uint fb_opts; /* QUIC_TUNE_FB_* options shared by both side */
	} fe;

	struct {
		uint cc_cubic_min_losses;
		uint cc_max_frame_loss;
		size_t cc_max_win_size;
		uint cc_reorder_ratio;
		uint max_idle_timeout;
		uint sec_glitches_threshold;
		uint fb_opts; /* QUIC_TUNE_FB_* options shared by both side */
	} be;

	uint64_t mem_tx_max;
};

#endif /* USE_QUIC */

#endif /* _HAPROXY_QUIC_TUNE_T_H */
