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

#include <common/config.h>
#include <types/port_range.h>

/* Direction for each FD event update */
enum {
	DIR_RD=0,
	DIR_WR=1,
};

/* Polling status flags returned in fdtab[].ev :
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

/* Event state for an FD in each direction, as found in the 4 lower bits of
 * fdtab[].spec_e, and in the 4 next bits.
 */
#define FD_EV_ACTIVE    1U
#define FD_EV_POLLED    4U
#define FD_EV_STATUS    (FD_EV_ACTIVE | FD_EV_POLLED)
#define FD_EV_STATUS_R  (FD_EV_STATUS)
#define FD_EV_STATUS_W  (FD_EV_STATUS << 1)

#define FD_EV_POLLED_R  (FD_EV_POLLED)
#define FD_EV_POLLED_W  (FD_EV_POLLED << 1)
#define FD_EV_POLLED_RW (FD_EV_POLLED_R | FD_EV_POLLED_W)

#define FD_EV_ACTIVE_R  (FD_EV_ACTIVE)
#define FD_EV_ACTIVE_W  (FD_EV_ACTIVE << 1)
#define FD_EV_ACTIVE_RW (FD_EV_ACTIVE_R | FD_EV_ACTIVE_W)

#define FD_EV_CURR_MASK 0x0FU
#define FD_EV_PREV_MASK 0xF0U

/* info about one given fd */
struct fdtab {
	int (*iocb)(int fd);                 /* I/O handler, returns FD_WAIT_* */
	void *owner;                         /* the connection or listener associated with this fd, NULL if closed */
	unsigned int  spec_p;                /* speculative polling: position in spec list+1. 0=not in list. */
	unsigned char spec_e;                /* speculative polling: read and write events status. 4 bits */
	unsigned char ev;                    /* event seen in return of poll() : FD_POLL_* */
	unsigned char new:1;                 /* 1 if this fd has just been created */
	unsigned char updated:1;             /* 1 if this fd is already in the update list */
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
 *  - clo() should be used to do indicate the poller that fd will be closed.
 *  - poll() calls the poller, expiring at <exp>
 */
struct poller {
	void   *private;                                     /* any private data for the poller */
	void REGPRM1   (*clo)(const int fd);                 /* mark <fd> as closed */
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
