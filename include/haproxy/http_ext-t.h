/*
 * include/haproxy/http_ext-t.h
 * Version-agnostic and implementation-agnostic HTTP extensions definitions
 *
 * Copyright 2022 HAProxy Technologies
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

#ifndef _HAPROXY_HTTPEXT_T_H
#define _HAPROXY_HTTPEXT_T_H

#include <arpa/inet.h>
#include <import/ist.h>
#include <haproxy/tools-t.h>

enum forwarded_header_attribute_type {
	FORWARDED_HEADER_UNK    = 0,
	FORWARDED_HEADER_OBFS   = 1,
	FORWARDED_HEADER_PORT   = 2,
	FORWARDED_HEADER_IP     = 3,
};

struct forwarded_header_nodename {
	union {
		struct sockaddr_storage ip;
		struct ist obfs;
	};
	enum forwarded_header_attribute_type type;
};

struct forwarded_header_nodeport {
	union {
		uint16_t port;
		struct ist obfs;
	};
	enum forwarded_header_attribute_type type;
};

struct forwarded_header_node {
	struct forwarded_header_nodename nodename;
	struct forwarded_header_nodeport nodeport;
	struct ist raw;
};

enum forwarded_header_proto {
	FORWARDED_HEADER_HTTP   = 1,
	FORWARDED_HEADER_HTTPS  = 2
};

struct forwarded_header_ctx {
	struct forwarded_header_node nfor;
	struct forwarded_header_node nby;
	struct ist host;
	enum forwarded_header_proto proto;
};

enum http_ext_7239_forby_mode {
	HTTP_7239_FORBY_ORIG   = 1,
	HTTP_7239_FORBY_SMP    = 2
};
struct http_ext_7239_forby {
	/* nn = nodename, np = nodeport */
	union {
		char                  *nn_expr_s;
		struct sample_expr    *nn_expr;
	};
	union {
		char                  *np_expr_s;
		struct sample_expr    *np_expr;
	};
	enum http_ext_7239_forby_mode nn_mode;
	enum http_ext_7239_forby_mode np_mode;
};

enum http_ext_7239_host_mode {
	HTTP_7239_HOST_ORIG = 1,
	HTTP_7239_HOST_SMP  = 2
};
struct http_ext_7239_host {
	union {
		char                 *expr_s;
		struct sample_expr   *expr;
	};
	enum http_ext_7239_host_mode mode;
};

struct http_ext_7239 {
	/* forwarded header parameters options */
	struct http_ext_7239_forby p_for;
	struct http_ext_7239_forby p_by;
	struct http_ext_7239_host  p_host;
	uint8_t                    p_proto;
	/* config error hints, used only during configuration parsing */
	char                       *c_file;
	int                        c_line;
	int                        c_mode; /* 0: parsed, 1: compiled */
};

enum forwarded_header_field {
	FORWARDED_HEADER_FOR    = 0x01,
	FORWARDED_HEADER_BY     = 0x02,
	FORWARDED_HEADER_HOST   = 0x04,
	FORWARDED_HEADER_PROTO  = 0x08,
	FORWARDED_HEADER_ALL	= FORWARDED_HEADER_FOR|FORWARDED_HEADER_BY|FORWARDED_HEADER_HOST|FORWARDED_HEADER_PROTO
};

enum http_ext_xff_mode {
	HTTP_XFF_IFNONE = 0, /* set if not already set */
	HTTP_XFF_ALWAYS = 1 /* always set x-forwarded-for */
};
struct http_ext_xff {
	struct ist      hdr_name;   /* header to use - default: "x-forwarded-for" */
	struct net_addr except_net; /* don't forward x-forward-for for this address. */
	uint8_t         mode;
};

struct http_ext_xot {
	struct ist      hdr_name;   /* header to use - default: "x-original-to" */
	struct net_addr except_net; /* don't forward x-original-to for this address. */
};

/* http_ext options */
struct http_ext {
	/* forwarded header (RFC 7239) */
	struct http_ext_7239       *fwd;
	/* x-forward-for:
	 *   conditionally insert x-forwarded-for with client address
	 */
	struct http_ext_xff        *xff;
	/* x-original-to:
	 *  insert x-original-to with destination address
	 */
	struct http_ext_xot        *xot;
};

#endif /* !_HAPROXY_HTTPEXT_T_H */
