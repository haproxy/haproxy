/*
 * include/common/fcgi.h
 * This file contains FastCGI protocol definitions.
 *
 * Copyright (C) 2019 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
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

#ifndef _COMMON_FCGI_H
#define _COMMON_FCGI_H

#include <inttypes.h>
#include <stdio.h>
#include <common/config.h>
#include <common/standard.h>
#include <common/buf.h>
#include <common/ist.h>

/* FCGI protocol version */
#define FCGI_VERSION    0x1

/* flags for FCGI_BEGIN_REQUEST records */
#define FCGI_KEEP_CONN  0x01

/* FCGI record's type */
enum fcgi_record_type {
	FCGI_BEGIN_REQUEST     =  1,
	FCGI_ABORT_REQUEST     =  2,
	FCGI_END_REQUEST       =  3,
	FCGI_PARAMS            =  4,
	FCGI_STDIN             =  5,
	FCGI_STDOUT            =  6,
	FCGI_STDERR            =  7,
	FCGI_DATA              =  8,
	FCGI_GET_VALUES        =  9,
	FCGI_GET_VALUES_RESULT = 10,
	FCGI_UNKNOWN_TYPE      = 11,
	FCGI_ENTRIES
} __attribute__((packed));


enum fcgi_role {
	FCGI_RESPONDER  = 1,
	FCGI_AUTHORIZER = 2, /* Unsupported */
	FCGI_FILTER     = 3, /* Unsupported */
} __attribute__((packed));

/* Protocol status */
enum fcgi_proto_status {
	FCGI_PS_REQUEST_COMPLETE = 0,
	FCGI_PS_CANT_MPX_CONN    = 1,
	FCGI_PS_OVERLOADED       = 2,
	FCGI_PS_UNKNOWN_ROLE     = 3,
	FCGI_PS_ENTRIES,
} __attribute__((packed));

struct fcgi_header {
	uint8_t  vsn;
	uint8_t  type;
	uint16_t id;
	uint16_t len;
	uint8_t  padding;
	uint8_t  rsv;
};

struct fcgi_param {
	struct ist n;
	struct ist v;
};

struct fcgi_begin_request {
	enum fcgi_role role;
	uint8_t flags;
};

struct fcgi_end_request {
	uint32_t status;
	uint8_t  errcode;
};

struct fcgi_unknown_type {
    uint8_t type;
};


static inline const char *fcgi_rt_str(int type)
{
        switch (type) {
        case FCGI_BEGIN_REQUEST     : return "BEGIN_REQUEST";
        case FCGI_ABORT_REQUEST     : return "ABORT_REQUEST";
        case FCGI_END_REQUEST       : return "END_REQUEST";
        case FCGI_PARAMS            : return "PARAMS";
        case FCGI_STDIN             : return "STDIN";
        case FCGI_STDOUT            : return "STDOUT";
        case FCGI_STDERR            : return "STDERR";
        case FCGI_DATA              : return "DATA";
        case FCGI_GET_VALUES        : return "GET_VALUES";
        case FCGI_GET_VALUES_RESULT : return "GET_VALUES_RESULT";
        case FCGI_UNKNOWN_TYPE      : return "UNKNOWN_TYPE";
        default                     : return "_UNKNOWN_";
        }
}


int    fcgi_encode_record_hdr(struct buffer *out, const struct fcgi_header *h);
size_t fcgi_decode_record_hdr(const struct buffer *in, size_t o, struct fcgi_header *h);

int    fcgi_encode_begin_request(struct buffer *out, const struct fcgi_begin_request *r);

int    fcgi_encode_param(struct buffer *out, const struct fcgi_param *p);
size_t fcgi_decode_param(const struct buffer *in, size_t o, struct fcgi_param *p);
size_t fcgi_aligned_decode_param(const struct buffer *in, size_t o, struct fcgi_param *p);

size_t fcgi_decode_end_request(const struct buffer *in, size_t o, struct fcgi_end_request *r);

#endif /* _COMMON_FCGI_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
