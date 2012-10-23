/*
 * include/proto/compression.h
 * This file defines function prototypes for compression.
 *
 * Copyright 2012 (C) Exceliance, David Du Colombier <dducolombier@exceliance.fr>
 *                                William Lallemand <wlallemand@exceliance.fr>
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

#ifndef _PROTO_COMP_H
#define _PROTO_COMP_H

#include <types/compression.h>

int comp_append_type(struct comp *comp, const char *type);
int comp_append_algo(struct comp *comp, const char *algo);

int http_emit_chunk_size(char *out, unsigned int chksz, int add_crlf);
int http_compression_buffer_init(struct session *s, struct buffer *in, struct buffer *out);
int http_compression_buffer_add_data(struct session *s, struct buffer *in, struct buffer *out);
int http_compression_buffer_end(struct session *s, struct buffer **in, struct buffer **out, int end);

int identity_init(void *v, int level);
int identity_add_data(void *v, const char *in_data, int in_len, char *out_data, int out_len);
int identity_flush(void *comp_ctx, struct buffer *out, int flag);
int identity_reset(void *comp_ctx);
int identity_end(void *comp_ctx);


#ifdef USE_ZLIB

int deflate_init(void *comp_ctx, int level);
int deflate_add_data(void *v, const char *in_data, int in_len, char *out_data, int out_len);
int deflate_flush(void *comp_ctx, struct buffer *out, int flag);
int deflate_reset(void *comp_ctx);
int deflate_end(void *comp_ctx);

int gzip_init(void *comp_ctx, int level);
int gzip_add_data(void *v, const char *in_data, int in_len, char *out_data, int out_len);
int gzip_flush(void *comp_ctx, struct buffer *out, int flag);
int gzip_reset(void *comp_ctx);
int gzip_end(void *comp_ctx);

#endif /* USE_ZLIB */

#endif /* _PROTO_COMP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
