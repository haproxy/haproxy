/*
  include/common/debug.h
  This files contains some macros to help debugging.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _COMMON_DEBUG_H
#define _COMMON_DEBUG_H

#include <common/config.h>

#ifdef DEBUG_FULL
#define DPRINTF(x...) fprintf(x)
#else
#define DPRINTF(x...)
#endif

#ifdef DEBUG_FSM
#define FSM_PRINTF(x...) fprintf(x)
#else
#define FSM_PRINTF(x...)
#endif

/* This abort is more efficient than abort() because it does not mangle the
 * stack and stops at the exact location we need.
 */
#define ABORT_NOW() (*(int*)0=0)

/* this one is provided for easy code tracing.
 * Usage: TRACE(strm||0, fmt, args...);
 *        TRACE(strm, "");
 */
#define TRACE(strm, fmt, args...) do {                            \
	fprintf(stderr,                                           \
		"%d.%06d [%s:%d %s] [strm %p(%x)] " fmt "\n",      \
		(int)now.tv_sec, (int)now.tv_usec,                \
		__FILE__, __LINE__, __FUNCTION__,                 \
		strm, strm?((struct stream *)strm)->uniq_id:~0U, \
		##args);                                           \
        } while (0)


#endif /* _COMMON_DEBUG_H */
