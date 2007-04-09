/*
  include/proto/fd.h
  File descriptors states.

  Copyright (C) 2000-2007 Willy Tarreau - w@1wt.eu
  
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

#ifndef _PROTO_FD_H
#define _PROTO_FD_H

#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/config.h>
#include <types/fd.h>

/* Deletes an FD from the fdsets, and recomputes the maxfd limit.
 * The file descriptor is also closed.
 */
void fd_delete(int fd);

/* registers all known pollers */
void register_pollers();

/* disable the specified poller */
void disable_poller(const char *poller_name);

/*
 * Initialize the pollers till the best one is found.
 * If none works, returns 0, otherwise 1.
 */
int init_pollers();

/*
 * Some pollers may lose their connection after a fork(). It may be necessary
 * to create initialize part of them again. Returns 0 in case of failure,
 * otherwise 1. The fork() function may be NULL if unused. In case of error,
 * the the current poller is destroyed and the caller is responsible for trying
 * another one by calling init_pollers() again.
 */
int fork_poller();

/*
 * Lists the known pollers on <out>.
 * Should be performed only before initialization.
 */
int list_pollers(FILE *out);

/*
 * Runs the polling loop
 */
void run_poller();

#define EV_FD_SET(fd, ev)    (cur_poller.set((fd), (ev)))
#define EV_FD_CLR(fd, ev)    (cur_poller.clr((fd), (ev)))
#define EV_FD_ISSET(fd, ev)  (cur_poller.is_set((fd), (ev)))
#define EV_FD_COND_S(fd, ev) (cur_poller.cond_s((fd), (ev)))
#define EV_FD_COND_C(fd, ev) (cur_poller.cond_c((fd), (ev)))
#define EV_FD_REM(fd)        (cur_poller.rem(fd))
#define EV_FD_CLO(fd)        (cur_poller.clo(fd))


/* recomputes the maxfd limit from the fd */
static inline void fd_insert(int fd)
{
	if (fd + 1 > maxfd)
		maxfd = fd + 1;
}


#endif /* _PROTO_FD_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
