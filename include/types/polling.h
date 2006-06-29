/*
  include/types/polling.h
  File descriptors and polling definitions.

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

#ifndef _TYPES_POLLING_H
#define _TYPES_POLLING_H

/* for fd_set */
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/config.h>

/* for POLL_* */
#if defined(ENABLE_POLL)
#include <sys/poll.h>
#endif

/* for EPOLL_* */
#if defined(ENABLE_EPOLL)
#if !defined(USE_MY_EPOLL)
#include <sys/epoll.h>
#else
#include <common/epoll.h>
#endif
#endif

/* possible actions for the *poll() loops */
#define POLL_LOOP_ACTION_INIT	0
#define POLL_LOOP_ACTION_RUN	1
#define POLL_LOOP_ACTION_CLEAN	2

/* poll mechanisms available */
#define POLL_USE_SELECT         (1<<0)
#define POLL_USE_POLL           (1<<1)
#define POLL_USE_EPOLL          (1<<2)

/* result of an I/O event */
#define	RES_SILENT	0	/* didn't happen */
#define RES_DATA	1	/* data were sent or received */
#define	RES_NULL	2	/* result is 0 (read == 0), or connect without need for writing */
#define RES_ERROR	3	/* result -1 or error on the socket (eg: connect()) */

/* fd states */
extern fd_set *StaticReadEvent, *StaticWriteEvent;
extern int cfg_polling_mechanism;       /* POLL_USE_{SELECT|POLL|EPOLL} */


#endif /* _TYPES_POLLING_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
