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

#ifdef USE_ZLIB
extern long zlib_used_memory;
#endif /* USE_ZLIB */

#endif /* _PROTO_COMP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
