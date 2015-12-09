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

/* NOTE: This is a temporary header file. It will be removed when the
 * compression filter will added */

#include <common/buffer.h>
#include <types/stream.h>

int select_compression_request_header(struct stream *s, struct buffer *req);
int select_compression_response_header(struct stream *s, struct buffer *res);

int http_compression_buffer_init(struct stream *s, struct buffer *in, struct buffer *out);
int http_compression_buffer_add_data(struct stream *s, struct buffer *in, struct buffer *out);
int http_compression_buffer_end(struct stream *s, struct buffer **in, struct buffer **out, int end);


#endif /* _PROTO_FLT_HTTP_COMP_H */
