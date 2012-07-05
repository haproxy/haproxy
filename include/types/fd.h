/*
 * include/types/fd.h
 * File descriptors states.
 *
 * Copyright (C) 2000-2009 Willy Tarreau - w@1wt.eu
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

#ifndef _TYPES_FD_H
#define _TYPES_FD_H

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/config.h>
#include <types/task.h>
#include <types/protocols.h>

/* different possible states for the fd */
#define FD_STLISTEN	1
#define FD_STCONN	2
#define FD_STREADY	3
#define FD_STERROR	4

enum {
	DIR_RD=0,
	DIR_WR=1,
	DIR_SIZE
};

/*
 * FD_POLL_IN remains set as long as some data is pending for read.
 * FD_POLL_OUT remains set as long as the fd accepts to write data.
 * FD_POLL_ERR and FD_POLL_ERR remain set forever (until processed).
 */
#define FD_POLL_IN	0x01
#define FD_POLL_PRI	0x02
#define FD_POLL_OUT	0x04
#define FD_POLL_ERR	0x08
#define FD_POLL_HUP	0x10

#define FD_POLL_DATA    (FD_POLL_IN  | FD_POLL_OUT)
#define FD_POLL_STICKY  (FD_POLL_ERR | FD_POLL_HUP)

/* bit values for fdtab[fd]->flags. Most of them are used to hold a value
 * consecutive to a behaviour change.
 */
#define FD_FL_TCP               0x0001       /* socket is TCP */
#define FD_FL_TCP_NODELAY       0x0002
#define FD_FL_TCP_NOLING        0x0004       /* lingering disabled */

/* info about one given fd */
struct fdtab {
	struct {
		int (*f)(int fd);            /* read/write function */
	} cb[DIR_SIZE];
	void *owner;                         /* the session (or proxy) associated with this fd, NULL if closed */
	struct {                             /* used by pollers which support speculative polling */
		unsigned char e;             /* read and write events status. 4 bits, may be merged into flags' lower bits */
		unsigned int s1;             /* Position in spec list+1. 0=not in list. */
	} spec;
	unsigned short flags;                /* various flags precising the exact status of this fd */
	unsigned char state;                 /* the state of this fd */
	unsigned char ev;                    /* event seen in return of poll() : FD_POLL_* */
};

/* less often used information */
struct fdinfo {
	struct port_range *port_range;       /* optional port range to bind to */
	int local_port;                      /* optional local port */
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
 *  - poll() calls the poller, expiring at <exp>
 */
struct poller {
	void   *private;                                     /* any private data for the poller */
	int  REGPRM2 (*is_set)(const int fd, int dir);       /* check if <fd> is being polled for dir <dir> */
	int  REGPRM2    (*set)(const int fd, int dir);       /* set   polling on <fd> for <dir> */
	int  REGPRM2    (*clr)(const int fd, int dir);       /* clear polling on <fd> for <dir> */
	int  REGPRM2 (*cond_s)(const int fd, int dir);       /* set   polling on <fd> for <dir> if unset */
	int  REGPRM2 (*cond_c)(const int fd, int dir);       /* clear polling on <fd> for <dir> if set */
	void REGPRM1    (*rem)(const int fd);                /* remove any polling on <fd> */
	void REGPRM1    (*clo)(const int fd);                /* mark <fd> as closed */
    	void REGPRM2   (*poll)(struct poller *p, int exp);   /* the poller itself */
	int  REGPRM1   (*init)(struct poller *p);            /* poller initialization */
	void REGPRM1   (*term)(struct poller *p);            /* termination of this poller */
	int  REGPRM1   (*test)(struct poller *p);            /* pre-init check of the poller */
	int  REGPRM1   (*fork)(struct poller *p);            /* post-fork re-opening */
	const char   *name;                                  /* poller name */
	int    pref;                                         /* try pollers with higher preference first */
};

extern struct poller cur_poller; /* the current poller */
extern int nbpollers;
#define MAX_POLLERS	10
extern struct poller pollers[MAX_POLLERS];   /* all registered pollers */

extern struct fdtab *fdtab;             /* array of all the file descriptors */
extern struct fdinfo *fdinfo;           /* less-often used infos for file descriptors */
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
