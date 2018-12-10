/*
 * include/proto/flt_http_comp.h
 * This file defines function prototypes for the compression filter.
 *
 * Copyright (C) 2015 Qualys Inc., Christopher Faulet <cfaulet@qualys.com>
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
#ifndef _PROTO_FLT_HTTP_COMP_H
#define _PROTO_FLT_HTTP_COMP_H

#include <types/proxy.h>

int check_implicit_http_comp_flt(struct proxy *proxy);

#endif // _PROTO_FLT_HTTP_COMP_H
