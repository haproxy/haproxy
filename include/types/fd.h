/*
  include/types/fd.h
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

#ifndef _TYPES_FD_H
#define _TYPES_FD_H

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/config.h>
#include <types/task.h>
#include <types/buffers.h>

/* different possible states for the fd */
#define FD_STCLOSE	0
#define FD_STLISTEN	1
#define FD_STCONN	2
#define FD_STREADY	3
#define FD_STERROR	4

enum {
	DIR_RD=0,
	DIR_WR=1,
	DIR_SIZE
};

/* info about one given fd */
struct fdtab {
	struct {
		int (*f)(int fd);            /* read/write function */
		struct buffer *b;            /* read/write buffer */
	} cb[DIR_SIZE];
	struct task *owner;             /* the session (or proxy) associated with this fd */
	int state;                      /* the state of this fd */
};

/*
 * Poller descriptors.
 *  - <name> is initialized by the poller's register() function, and should not
 *    be allocated, just linked to.
 *  - <pref> is initialized by the poller's register() function. It is set to 0
 *    by default, meaning the poller is disabled. init() should set it to 0 in
 *    case of failure. term() must set it to 0. A generic unoptimized select()
 *    poller should set it to 100.
 *  - <private> is initialized by the poller's init() function, and cleaned by
 *    the term() function.
 *  - cond_s() checks if fd was not set then sets it and returns 1. Otherwise
 *    it returns 0. It may be the same as set().
 *  - cond_c() checks if fd was set then clears it and returns 1. Otherwise
 *    it returns 0. It may be the same as clr().
 *  - clo() should be used to do indicate the poller that fd will be closed. It
 *    may be the same as rem() on some pollers.
 *  - poll() calls the poller, waiting at most wait_time ms.
 */
struct poller {
	void   *private;                                     /* any private data for the poller */
	REGPRM2 int  (*is_set)(const int fd, int dir);       /* check if <fd> is being polled for dir <dir> */
	REGPRM2 int     (*set)(const int fd, int dir);       /* set   polling on <fd> for <dir> */
	REGPRM2 int     (*clr)(const int fd, int dir);       /* clear polling on <fd> for <dir> */
	REGPRM2 int  (*cond_s)(const int fd, int dir);       /* set   polling on <fd> for <dir> if unset */
	REGPRM2 int  (*cond_c)(const int fd, int dir);       /* clear polling on <fd> for <dir> if set */
	REGPRM1 void    (*rem)(const int fd);                /* remove any polling on <fd> */
	REGPRM1 void    (*clo)(const int fd);                /* mark <fd> as closed */
    	REGPRM2 void   (*poll)(struct poller *p, int wait_time); /* the poller itself */
	REGPRM1 int    (*init)(struct poller *p);            /* poller initialization */
	REGPRM1 void   (*term)(struct poller *p);            /* termination of this poller */
	REGPRM1 int    (*test)(struct poller *p);            /* pre-init check of the poller */
	REGPRM1 int    (*fork)(struct poller *p);            /* post-fork re-opening */
	const char   *name;                                  /* poller name */
	int    pref;                                         /* try pollers with higher preference first */
};

extern struct poller cur_poller; /* the current poller */
extern int nbpollers;
#define MAX_POLLERS	10
extern struct poller pollers[MAX_POLLERS];   /* all registered pollers */

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
