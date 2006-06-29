/*
  include/proto/polling.h
  Polling functions.

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

#ifndef _PROTO_POLLING_H
#define _PROTO_POLLING_H

#include <common/config.h>
#include <types/polling.h>

/*
 * Main select() loop.
 * does 3 actions :
 * 0 (POLL_LOOP_ACTION_INIT)  : initializes necessary private structures
 * 1 (POLL_LOOP_ACTION_RUN)   : runs the loop
 * 2 (POLL_LOOP_ACTION_CLEAN) : cleans up
 *
 * returns 0 if initialization failed, !0 otherwise.
 */
int select_loop(int action);

#if defined(ENABLE_POLL)
/*
 * Main poll() loop.
 * does 3 actions :
 * 0 (POLL_LOOP_ACTION_INIT)  : initializes necessary private structures
 * 1 (POLL_LOOP_ACTION_RUN)   : runs the loop
 * 2 (POLL_LOOP_ACTION_CLEAN) : cleans up
 *
 * returns 0 if initialization failed, !0 otherwise.
 */
int poll_loop(int action);
#endif

#if defined(ENABLE_EPOLL)
/*
 * Main epoll() loop.
 * does 3 actions :
 * 0 (POLL_LOOP_ACTION_INIT)  : initializes necessary private structures
 * 1 (POLL_LOOP_ACTION_RUN)   : runs the loop
 * 2 (POLL_LOOP_ACTION_CLEAN) : cleans up
 *
 * returns 0 if initialization failed, !0 otherwise.
 */
int epoll_loop(int action);
#endif


#endif /* _PROTO_POLLING_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
