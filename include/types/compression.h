/*
 * include/types/compression.h
 * This file defines everything related to compression.
 *
 * Copyright 2012 Exceliance, David Du Colombier <dducolombier@exceliance.fr>
                              William Lallemand <wlallemand@exceliance.fr>
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

#ifndef _TYPES_COMP_H
#define _TYPES_COMP_H

#ifdef USE_ZLIB

#include <zlib.h>

#endif /* USE_ZLIB */

struct comp {
	struct comp_algo *algos;
	struct comp_type *types;
	unsigned int offload;
};

struct comp_ctx {
#ifdef USE_ZLIB
	z_stream strm; /* zlib stream */
	void *zlib_deflate_state;
	void *zlib_window;
	void *zlib_prev;
	void *zlib_pending_buf;
	void *zlib_head;
#endif /* USE_ZLIB */
	int cur_lvl;
};

struct comp_algo {
	char *name;
	int name_len;
	int (*init)(struct comp_ctx **comp_ctx, int level);
	int (*add_data)(struct comp_ctx *comp_ctx, const char *in_data, int in_len, struct buffer *out);
	int (*flush)(struct comp_ctx *comp_ctx, struct buffer *out, int flag);
	int (*reset)(struct comp_ctx *comp_ctx);
	int (*end)(struct comp_ctx **comp_ctx);
	struct comp_algo *next;
};

struct comp_type {
	char *name;
	int name_len;
	struct comp_type *next;
};


#endif /* _TYPES_COMP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */

