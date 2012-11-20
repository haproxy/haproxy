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

extern unsigned int compress_min_idle;

int comp_append_type(struct comp *comp, const char *type);
int comp_append_algo(struct comp *comp, const char *algo);

int http_emit_chunk_size(char *out, unsigned int chksz, int add_crlf);
int http_compression_buffer_init(struct session *s, struct buffer *in, struct buffer *out);
int http_compression_buffer_add_data(struct session *s, struct buffer *in, struct buffer *out);
int http_compression_buffer_end(struct session *s, struct buffer **in, struct buffer **out, int end);

int identity_init(struct comp_ctx **comp_ctx, int level);
int identity_add_data(struct comp_ctx *comp_ctx, const char *in_data, int in_len, struct buffer *out);
int identity_flush(struct comp_ctx *comp_ctx, struct buffer *out, int flag);
int identity_reset(struct comp_ctx *comp_ctx);
int identity_end(struct comp_ctx **comp_ctx);



#ifdef USE_ZLIB
extern long zlib_used_memory;

int deflate_init(struct comp_ctx **comp_ctx, int level);
int deflate_add_data(struct comp_ctx *comp_ctx, const char *in_data, int in_len, struct buffer *out);
int deflate_flush(struct comp_ctx *comp_ctx, struct buffer *out, int flag);
int deflate_reset(struct comp_ctx *comp_ctx);
int deflate_end(struct comp_ctx **comp_ctx);

int gzip_init(struct comp_ctx **comp_ctx, int level);
#endif /* USE_ZLIB */

#endif /* _PROTO_COMP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
