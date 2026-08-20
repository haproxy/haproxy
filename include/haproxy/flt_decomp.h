/*
 * include/haproxy/flt_decomp.h
 * This file defines function prototypes for the decompression filters.
 *
 * Copyright 2026 HAProxy Technologies
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
#ifndef _HAPROXY_FLT_DECOMP_H
#define _HAPROXY_FLT_DECOMP_H

#include <haproxy/proxy-t.h>

int check_implicit_decomp_flt(struct proxy *proxy);

#endif // _HAPROXY_FLT_DECOMP_H
