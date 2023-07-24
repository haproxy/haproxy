/*
 * include/haproxy/quic_trace-t.h
 * Definitions for QUIC traces internal types, constants and flags.
 *
 * Copyright (C) 2023
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef _HAPROXY_QUIC_TRACE_T_H
#define _HAPROXY_QUIC_TRACE_T_H

#include <inttypes.h>
#include <stdlib.h>

#include <haproxy/quic_tls-t.h>

/* Used only for QUIC TLS key phase traces */
struct quic_kp_trace {
	const unsigned char *rx_sec;
	size_t rx_seclen;
	const struct quic_tls_kp *rx;
	const unsigned char *tx_sec;
	size_t tx_seclen;
	const struct quic_tls_kp *tx;
};

/* Only for debug purpose */
struct enc_debug_info {
	unsigned char *payload;
	size_t payload_len;
	unsigned char *aad;
	size_t aad_len;
	uint64_t pn;
};

#endif /* _HAPROXY_QUIC_TRACE_T_H */
