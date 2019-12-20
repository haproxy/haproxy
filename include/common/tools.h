/*
 * include/common/tools.h
 * Trivial macros needed everywhere.
 *
 * Copyright (C) 2000-2011 Willy Tarreau - w@1wt.eu
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

#ifndef _COMMON_TOOLS_H
#define _COMMON_TOOLS_H

#include <sys/param.h>
#include <common/config.h>

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define SWAP(a, b) do { typeof(a) t; t = a; a = b; b = t; } while(0)

/* return an integer of type <ret> with only the highest bit set. <ret> may be
 * both a variable or a type.
 */
#define MID_RANGE(ret) ((typeof(ret))1 << (8*sizeof(ret) - 1))

/* return the largest possible integer of type <ret>, with all bits set */
#define MAX_RANGE(ret) (~(typeof(ret))0)

#endif /* _COMMON_TOOLS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
