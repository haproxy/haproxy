/*
 * include/haproxy/quic_ssl-t.h
 * Definitions for QUIC over TLS/SSL api types, constants and flags.
 *
 * Copyright (C) 2023
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef _HAPROXY_QUIC_SSL_T_H
#define _HAPROXY_QUIC_SSL_T_H

#include <haproxy/pool-t.h>

extern struct pool_head *pool_head_quic_ssl_sock_ctx;

#endif /* _HAPROXY_QUIC_SSL_T_H */
