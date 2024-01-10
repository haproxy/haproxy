#ifndef _HAPROXY_QUIC_TP_T_H
#define _HAPROXY_QUIC_TP_T_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define QUIC_STATELESS_RESET_TOKEN_LEN 16

/* Default QUIC connection transport parameters */
extern struct quic_transport_params quic_dflt_transport_params;

struct tp_cid {
	uint8_t len;
	uint8_t data[20];
};

struct tp_preferred_address {
	uint16_t ipv4_port;
	uint16_t ipv6_port;
	struct in_addr  ipv4_addr;
	struct in6_addr ipv6_addr;
	struct tp_cid cid;
	uint8_t stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];
};

struct tp_version_information {
	uint32_t chosen;
	const struct quic_version *negotiated_version;
};

/* Default values for the absent transport parameters */
#define QUIC_TP_DFLT_MAX_UDP_PAYLOAD_SIZE        65527 /* bytes */
#define QUIC_TP_DFLT_ACK_DELAY_COMPONENT             3 /* milliseconds */
#define QUIC_TP_DFLT_MAX_ACK_DELAY                  25 /* milliseconds */
#define QUIC_TP_DFLT_ACTIVE_CONNECTION_ID_LIMIT      2 /* number of connections */
/* These ones are our implementation default values when not set
 * by configuration
 */
#define QUIC_TP_DFLT_FRONT_MAX_IDLE_TIMEOUT      30000 /* milliseconds */
#define QUIC_TP_DFLT_FRONT_MAX_STREAMS_BIDI        100
#define QUIC_TP_DFLT_BACK_MAX_IDLE_TIMEOUT       30000 /* milliseconds */

/* Types of QUIC transport parameters */
#define QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID  0x00
#define QUIC_TP_MAX_IDLE_TIMEOUT                    0x01
#define QUIC_TP_STATELESS_RESET_TOKEN               0x02
#define QUIC_TP_MAX_UDP_PAYLOAD_SIZE                0x03
#define QUIC_TP_INITIAL_MAX_DATA                    0x04
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL  0x05
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE 0x06
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI         0x07
#define QUIC_TP_INITIAL_MAX_STREAMS_BIDI            0x08
#define QUIC_TP_INITIAL_MAX_STREAMS_UNI             0x09
#define QUIC_TP_ACK_DELAY_EXPONENT                  0x0a
#define QUIC_TP_MAX_ACK_DELAY                       0x0b
#define QUIC_TP_DISABLE_ACTIVE_MIGRATION            0x0c
#define QUIC_TP_PREFERRED_ADDRESS                   0x0d
#define QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT          0x0e
#define QUIC_TP_INITIAL_SOURCE_CONNECTION_ID        0x0f
#define QUIC_TP_RETRY_SOURCE_CONNECTION_ID          0x10
#define QUIC_TP_VERSION_INFORMATION                 0x11

/*
 * These defines are not for transport parameter type, but the maximum accepted value for
 * transport parameter types.
 */
#define QUIC_TP_ACK_DELAY_EXPONENT_LIMIT 20
#define QUIC_TP_MAX_ACK_DELAY_LIMIT      (1UL << 14)

/* The maximum length of encoded transport parameters for any QUIC peer. */
#define QUIC_TP_MAX_ENCLEN    128
/*
 * QUIC transport parameters.
 * Note that forbidden parameters sent by clients MUST generate TRANSPORT_PARAMETER_ERROR errors.
 */
struct quic_transport_params {
	uint64_t max_idle_timeout;
	uint64_t max_udp_payload_size;                 /* Default: 65527 bytes (max of UDP payload for IPv6) */
	uint64_t initial_max_data;
	uint64_t initial_max_stream_data_bidi_local;
	uint64_t initial_max_stream_data_bidi_remote;
	uint64_t initial_max_stream_data_uni;
	uint64_t initial_max_streams_bidi;
	uint64_t initial_max_streams_uni;
	uint64_t ack_delay_exponent;                   /* Default: 3, max: 20 */
	uint64_t max_ack_delay;                        /* Default: 3ms, max: 2^14ms*/
	uint64_t active_connection_id_limit;

	/* Booleans */
	uint8_t disable_active_migration;
	uint8_t with_stateless_reset_token;
	uint8_t with_preferred_address;
	uint8_t original_destination_connection_id_present;
	uint8_t initial_source_connection_id_present;

	uint8_t stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN]; /* Forbidden for clients */
	/*
	 * MUST be sent by servers.
	 * When received by clients, must be set to 1 if present.
	 */
	struct tp_cid original_destination_connection_id;            /* Forbidden for clients */
	/*
	 * MUST be sent by servers after Retry.
	 */
	struct tp_cid retry_source_connection_id;                    /* Forbidden for clients */
	/* MUST be present both for servers and clients. */
	struct tp_cid initial_source_connection_id;
	struct tp_preferred_address preferred_address;                    /* Forbidden for clients */
	struct tp_version_information version_information;
};

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_TP_T_H */
