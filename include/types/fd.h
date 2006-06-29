/*
  include/fd.h
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

#ifndef _TYPES_FD_H
#define _TYPES_FD_H

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/config.h>
#include <types/task.h>

/* different possible states for the fd */
#define FD_STCLOSE	0
#define FD_STLISTEN	1
#define FD_STCONN	2
#define FD_STREADY	3
#define FD_STERROR	4


/* info about one given fd */
struct fdtab {
    int (*read)(int fd);	/* read function */
    int (*write)(int fd);	/* write function */
    struct task *owner;		/* the session (or proxy) associated with this fd */
    int state;			/* the state of this fd */
};

extern struct fdtab *fdtab;             /* array of all the file descriptors */
extern int maxfd;                       /* # of the highest fd + 1 */
extern int totalconn;                   /* total # of terminated sessions */
extern int actconn;                     /* # of active sessions */

#endif /* _TYPES_FD_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
