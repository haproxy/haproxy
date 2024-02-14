/*
 * include/haproxy/quic_ack-t.h
 * Definitions for QUIC acknowledgements internal types, constants and flags.
 *
 * Copyright (C) 2023
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */
#ifndef _HAPROXY_QUIC_ACK_T_H
#define _HAPROXY_QUIC_ACK_T_H

#include <inttypes.h>
#include <stddef.h>
#include <import/eb64tree.h>

/* The maximum number of ack ranges to be built in ACK frames */
#define QUIC_MAX_ACK_RANGES   32

/* Structure to maintain a set of ACK ranges to be used to build ACK frames. */
struct quic_arngs {
	/* ebtree of ACK ranges organized by their first value. */
	struct eb_root root;
	/* The number of ACK ranges is this tree */
	size_t sz;
	/* The number of bytes required to encode this ACK ranges lists. */
	size_t enc_sz;
};

/* Structure to hold a range of ACKs sent in ACK frames. */
struct quic_arng {
	int64_t first;
	int64_t last;
};

/* Structure to hold a range of ACKs to be store as a node in a tree of
 * ACK ranges.
 */
struct quic_arng_node {
	struct eb64_node first;
	uint64_t last;
};

#endif /* _HAPROXY_QUIC_ACK_T_H */
