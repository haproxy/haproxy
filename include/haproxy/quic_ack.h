/*
 * include/proto/quic_ack.h
 * This file provides definitions for QUIC acknowledgements.
 *
 * Copyright (C) 2023
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _HAPROXY_QUIC_ACK_H
#define _HAPROXY_QUIC_ACK_H

#include <inttypes.h>

struct quic_conn;
struct quic_arng;
struct quic_arngs;

void quic_free_arngs(struct quic_conn *qc, struct quic_arngs *arngs);
int quic_update_ack_ranges_list(struct quic_conn *qc,
                                struct quic_arngs *arngs,
                                struct quic_arng *ar);
void qc_treat_ack_of_ack(struct quic_conn *qc, struct quic_arngs *arngs,
                         int64_t largest_acked_pn);

#endif /* _HAPROXY_QUIC_ACK_H */
