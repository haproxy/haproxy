/*
  include/proto/fd.h
  File descriptors states.

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

#ifndef _PROTO_FD_H
#define _PROTO_FD_H

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/config.h>
#include <types/fd.h>

/* Deletes an FD from the fdsets, and recomputes the maxfd limit.
 * The file descriptor is also closed.
 */
void fd_delete(int fd);


/*
 * Benchmarks performed on a Pentium-M notebook show that using functions
 * instead of the usual macros improve the FD_* performance by about 80%,
 * and that marking them regparm(2) adds another 20%.
 */
#if defined(CONFIG_HAP_INLINE_FD_SET)

# define MY_FD_SET   FD_SET
# define MY_FD_CLR   FD_CLR
# define MY_FD_ISSET FD_ISSET

#else

# define MY_FD_SET   my_fd_set
# define MY_FD_CLR   my_fd_clr
# define MY_FD_ISSET my_fd_isset

void __attribute__((regparm(2))) my_fd_set(const int fd, fd_set *ev);
void __attribute__((regparm(2))) my_fd_clr(const int fd, fd_set *ev);
int __attribute__((regparm(2))) my_fd_isset(const int fd, const fd_set *ev);

#endif


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
