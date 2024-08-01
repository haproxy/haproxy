/*
 * include/haproxy/quic_trace.h
 * This file contains QUIC traces definitions.
 *
 * Copyright (C) 2023
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef _HAPROXY_QUIC_TRACE_H
#define _HAPROXY_QUIC_TRACE_H

#include <haproxy/quic_trace-t.h>

#include <haproxy/buf-t.h>

struct quic_conn;

#define TRACE_SOURCE    &trace_quic

/* Initializes a enc_debug_info struct (only for debug purpose) */
static inline void enc_debug_info_init(struct enc_debug_info *edi,
                                       unsigned char *payload, size_t payload_len,
                                       unsigned char *aad, size_t aad_len, uint64_t pn)
{
	edi->payload = payload;
	edi->payload_len = payload_len;
	edi->aad = aad;
	edi->aad_len = aad_len;
	edi->pn = pn;
}

void quic_dump_qc_info(struct buffer *msg, const struct quic_conn *qc);

#endif /* _HAPROXY_QUIC_TRACE_H */
