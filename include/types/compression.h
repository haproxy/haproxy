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

#include <zlib.h>

struct comp {
	struct comp_algo *algos;
	struct comp_type *types;
};

struct comp_algo {
	char *name;
	int name_len;
	int (*init)(void *, int);
	int (*add_data)(void *v, const char *in_data, int in_len, char *out_data, int out_len);
	int (*flush)(void *v, struct buffer *out, int flag);
	int (*reset)(void *v);
	int (*end)(void *v);
	struct comp_algo *next;
};

union comp_ctx {
	z_stream strm; /* zlib */
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

