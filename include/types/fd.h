/*
 * include/types/fd.h
 * File descriptors states - check src/fd.c for explanations.
 *
 * Copyright (C) 2000-2014 Willy Tarreau - w@1wt.eu
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
#include <common/hathreads.h>
#include <common/ist.h>
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

/* FD bits used for different polling states in each direction */
#define FD_EV_ACTIVE    1U
#define FD_EV_READY     2U
#define FD_EV_SHUT      4U
#define FD_EV_ERR       8U

/* bits positions for a few flags */
#define FD_EV_ACTIVE_R_BIT 0
#define FD_EV_READY_R_BIT  1
#define FD_EV_SHUT_R_BIT   2
#define FD_EV_ERR_R_BIT    3

#define FD_EV_ACTIVE_W_BIT 4
#define FD_EV_READY_W_BIT  5
#define FD_EV_SHUT_W_BIT   6
#define FD_EV_ERR_W_BIT    7

#define FD_EV_STATUS    (FD_EV_ACTIVE | FD_EV_READY | FD_EV_SHUT | FD_EV_ERR)
#define FD_EV_STATUS_R  (FD_EV_STATUS)
#define FD_EV_STATUS_W  (FD_EV_STATUS << 4)

#define FD_EV_ACTIVE_R  (FD_EV_ACTIVE)
#define FD_EV_ACTIVE_W  (FD_EV_ACTIVE << 4)
#define FD_EV_ACTIVE_RW (FD_EV_ACTIVE_R | FD_EV_ACTIVE_W)

#define FD_EV_READY_R   (FD_EV_READY)
#define FD_EV_READY_W   (FD_EV_READY << 4)
#define FD_EV_READY_RW  (FD_EV_READY_R | FD_EV_READY_W)

/* note that when FD_EV_SHUT is set, ACTIVE and READY are cleared */
#define FD_EV_SHUT_R    (FD_EV_SHUT)
#define FD_EV_SHUT_W    (FD_EV_SHUT << 4)
#define FD_EV_SHUT_RW   (FD_EV_SHUT_R | FD_EV_SHUT_W)

/* note that when FD_EV_ERR is set, SHUT is also set */
#define FD_EV_ERR_R     (FD_EV_ERR)
#define FD_EV_ERR_W     (FD_EV_ERR << 4)
#define FD_EV_ERR_RW    (FD_EV_ERR_R | FD_EV_ERR_W)


/* This is the value used to mark a file descriptor as dead. This value is
 * negative, this is important so that tests on fd < 0 properly match. It
 * also has the nice property of being highly negative but neither overflowing
 * nor changing sign on 32-bit machines when multiplied by sizeof(fdtab).
 * This ensures that any unexpected dereference of such an uninitialized
 * file descriptor will lead to so large a dereference that it will crash
 * the process at the exact location of the bug with a clean stack trace
 * instead of causing silent manipulation of other FDs. And it's readable
 * when found in a dump.
 */
#define DEAD_FD_MAGIC 0xFDDEADFD

/* fdlist_entry: entry used by the fd cache.
 *    >= 0 means we're in the cache and gives the FD of the next in the cache,
 *      -1 means we're in the cache and the last element,
 *      -2 means the entry is locked,
 *   <= -3 means not in the cache, and next element is -4-fd
 *
 * It must remain 8-aligned so that aligned CAS operations may be done on both
 * entries at once.
 */
struct fdlist_entry {
	int next;
	int prev;
} __attribute__ ((aligned(8)));

/* head of the fd cache */
struct fdlist {
	int first;
	int last;
} __attribute__ ((aligned(8)));

/* info about one given fd */
struct fdtab {
	__decl_hathreads(HA_SPINLOCK_T lock);
	unsigned long thread_mask;           /* mask of thread IDs authorized to process the task */
	unsigned long update_mask;           /* mask of thread IDs having an update for fd */
	struct fdlist_entry update;          /* Entry in the global update list */
	void (*iocb)(int fd);                /* I/O handler */
	void *owner;                         /* the connection or listener associated with this fd, NULL if closed */
	unsigned char state;                 /* FD state for read and write directions (2*3 bits) */
	unsigned char ev;                    /* event seen in return of poll() : FD_POLL_* */
	unsigned char linger_risk:1;         /* 1 if we must kill lingering before closing */
	unsigned char cloned:1;              /* 1 if a cloned socket, requires EPOLL_CTL_DEL on close */
	unsigned char initialized:1;         /* 1 if init phase was done on this fd (e.g. set non-blocking) */
}
#ifdef USE_THREAD
/* only align on cache lines when using threads; 32-bit small archs
 * can put everything in 32-bytes when threads are disabled.
 */
__attribute__((aligned(64)))
#endif
;

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
 *  - poll() calls the poller, expiring at <exp>, or immediately if <wake> is set
 *  - flags indicate what the poller supports (HAP_POLL_F_*)
 */

#define HAP_POLL_F_RDHUP 0x00000001                          /* the poller notifies of HUP with reads */

struct poller {
	void   *private;                                     /* any private data for the poller */
	void REGPRM1   (*clo)(const int fd);                 /* mark <fd> as closed */
	void REGPRM3   (*poll)(struct poller *p, int exp, int wake);  /* the poller itself */
	int  REGPRM1   (*init)(struct poller *p);            /* poller initialization */
	void REGPRM1   (*term)(struct poller *p);            /* termination of this poller */
	int  REGPRM1   (*test)(struct poller *p);            /* pre-init check of the poller */
	int  REGPRM1   (*fork)(struct poller *p);            /* post-fork re-opening */
	const char   *name;                                  /* poller name */
	unsigned int flags;                                  /* HAP_POLL_F_* */
	int    pref;                                         /* try pollers with higher preference first */
};

extern struct poller cur_poller; /* the current poller */
extern int nbpollers;
#define MAX_POLLERS	10
extern struct poller pollers[MAX_POLLERS];   /* all registered pollers */

extern struct fdtab *fdtab;             /* array of all the file descriptors */
extern struct fdinfo *fdinfo;           /* less-often used infos for file descriptors */
extern int totalconn;                   /* total # of terminated sessions */
extern int actconn;                     /* # of active sessions */

#endif /* _TYPES_FD_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
