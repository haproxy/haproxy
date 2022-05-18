#ifndef _HAPROXY_QUIC_STATS_T_H
#define _HAPROXY_QUIC_STATS_T_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

extern struct stats_module quic_stats_module;

struct quic_counters {
	long long dropped_pkt;       /* total number of dropped packets */
	long long retry_sent;        /* total number of Retry sent */
	long long retry_validated;   /* total number of validated Retry tokens */
	long long retry_error;       /* total number of Retry token errors */
	long long conn_opening;      /* total number of connection openings */
	long long hdshk_fail;        /* total number of handshake failures */
	/* Streams related counters */
	long long data_blocked;              /* total number of times DATA_BLOCKED frame was received */
	long long stream_data_blocked;       /* total number of times STEAM_DATA_BLOCKED frame was received */
	long long streams_data_blocked_bidi; /* total number of times STREAMS_DATA_BLOCKED_BIDI frame was received */
	long long streams_data_blocked_uni;  /* total number of times STREAMS_DATA_BLOCKED_UNI frame was received */
};

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_STATS_T_H */
