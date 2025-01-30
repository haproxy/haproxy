/*
 * include/haproxy/fd-t.h
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

#ifndef _HAPROXY_FD_T_H
#define _HAPROXY_FD_T_H

#include <haproxy/api-t.h>
#include <haproxy/port_range-t.h>
#include <haproxy/show_flags-t.h>

/* Direction for each FD event update */
enum {
	DIR_RD=0,
	DIR_WR=1,
};


/* fdtab[].state is a composite state describing what is known about the FD.
 * For now, the following information are stored in it:
 *   - event configuration and status for each direction (R,W) split into
 *     active, ready, shutdown categories (FD_EV_*). These are known by their
 *     bit values as well so that test-and-set bit operations are possible.
 *
 *   - last known polling status (FD_POLL_*). For ease of troubleshooting,
 *     avoid visually mixing these ones with the other ones above. 3 of these
 *     flags are updated on each poll() report (FD_POLL_IN, FD_POLL_OUT,
 *     FD_POLL_PRI). FD_POLL_HUP and FD_POLL_ERR are "sticky" in that once they
 *     are reported, they will not be cleared until the FD is closed.
 */

/* bits positions for a few flags */
#define FD_EV_ACTIVE_R_BIT 0
#define FD_EV_READY_R_BIT  1
#define FD_EV_SHUT_R_BIT   2
/* unused: 3 */

#define FD_EV_ACTIVE_W_BIT 4
#define FD_EV_READY_W_BIT  5
#define FD_EV_SHUT_W_BIT   6
#define FD_EV_ERR_RW_BIT   7

#define FD_POLL_IN_BIT     8
#define FD_POLL_PRI_BIT    9
#define FD_POLL_OUT_BIT   10
#define FD_POLL_ERR_BIT   11
#define FD_POLL_HUP_BIT   12

/* info/config bits */
#define FD_LINGER_RISK_BIT 16  /* must kill lingering before closing */
#define FD_CLONED_BIT      17  /* cloned socket, requires EPOLL_CTL_DEL on close */
#define FD_INITIALIZED_BIT 18  /* init phase was done (e.g. output pipe set non-blocking) */
#define FD_ET_POSSIBLE_BIT 19  /* edge-triggered is possible on this FD */
#define FD_EXPORTED_BIT    20  /* FD is exported and must not be closed */
#define FD_EXCL_SYSCALL_BIT 21 /* a syscall claims exclusivity on this FD */
#define FD_DISOWN_BIT      22  /* this fd will be closed by some external code */
#define FD_MUST_CLOSE_BIT  23  /* this fd will be closed by some external code */


/* and flag values */
#define FD_EV_ACTIVE_R  (1U << FD_EV_ACTIVE_R_BIT)
#define FD_EV_ACTIVE_W  (1U << FD_EV_ACTIVE_W_BIT)
#define FD_EV_ACTIVE_RW (FD_EV_ACTIVE_R | FD_EV_ACTIVE_W)

#define FD_EV_READY_R   (1U << FD_EV_READY_R_BIT)
#define FD_EV_READY_W   (1U << FD_EV_READY_W_BIT)
#define FD_EV_READY_RW  (FD_EV_READY_R | FD_EV_READY_W)

/* note that when FD_EV_SHUT is set, ACTIVE and READY are cleared */
#define FD_EV_SHUT_R    (1U << FD_EV_SHUT_R_BIT)
#define FD_EV_SHUT_W    (1U << FD_EV_SHUT_W_BIT)
#define FD_EV_SHUT_RW   (FD_EV_SHUT_R | FD_EV_SHUT_W)

/* note that when FD_EV_ERR is set, SHUT is also set. Also, ERR is for both
 * directions at once (write error, socket dead, etc).
 */
#define FD_EV_ERR_RW    (1U << FD_EV_ERR_RW_BIT)

/* mask covering all use cases above */
#define FD_EV_ANY       (FD_EV_ACTIVE_RW | FD_EV_READY_RW | FD_EV_SHUT_RW | FD_EV_ERR_RW)

/* polling status */
#define FD_POLL_IN          (1U << FD_POLL_IN_BIT)
#define FD_POLL_PRI         (1U << FD_POLL_PRI_BIT)
#define FD_POLL_OUT         (1U << FD_POLL_OUT_BIT)
#define FD_POLL_ERR         (1U << FD_POLL_ERR_BIT)
#define FD_POLL_HUP         (1U << FD_POLL_HUP_BIT)
#define FD_POLL_UPDT_MASK   (FD_POLL_IN | FD_POLL_PRI | FD_POLL_OUT)
#define FD_POLL_ANY_MASK    (FD_POLL_IN | FD_POLL_PRI | FD_POLL_OUT | FD_POLL_ERR | FD_POLL_HUP)

/* information/configuration flags */
#define FD_LINGER_RISK      (1U << FD_LINGER_RISK_BIT)
#define FD_CLONED           (1U << FD_CLONED_BIT)
#define FD_INITIALIZED      (1U << FD_INITIALIZED_BIT)
#define FD_ET_POSSIBLE      (1U << FD_ET_POSSIBLE_BIT)
#define FD_EXPORTED         (1U << FD_EXPORTED_BIT)
#define FD_EXCL_SYSCALL     (1U << FD_EXCL_SYSCALL_BIT)
#define FD_DISOWN           (1U << FD_DISOWN_BIT)
#define FD_MUST_CLOSE       (1U << FD_MUST_CLOSE_BIT)

/* This function is used to report flags in debugging tools. Please reflect
 * below any single-bit flag addition above in the same order via the
 * __APPEND_FLAG macro. The new end of the buffer is returned.
 */
static forceinline char *fd_show_flags(char *buf, size_t len, const char *delim, uint flg)
{
#define _(f, ...) __APPEND_FLAG(buf, len, delim, flg, f, #f, __VA_ARGS__)
	/* prologue */
	_(0);
	/* flags */
	_(FD_EV_ACTIVE_R, _(FD_EV_ACTIVE_W, _(FD_EV_READY_R, _(FD_EV_READY_W,
	_(FD_EV_SHUT_R, _(FD_EV_SHUT_W, _(FD_EV_ERR_RW, _(FD_POLL_IN,
	_(FD_POLL_PRI, _(FD_POLL_OUT, _(FD_POLL_ERR, _(FD_POLL_HUP,
	_(FD_LINGER_RISK, _(FD_CLONED, _(FD_INITIALIZED, _(FD_ET_POSSIBLE,
	_(FD_EXPORTED, _(FD_EXCL_SYSCALL, _(FD_DISOWN)))))))))))))))))));
	/* epilogue */
	_(~0U);
	return buf;
#undef _
}

/* FD update status after fd_update_events() */
enum {
	FD_UPDT_DONE = 0,    // update done, nothing else to be done
	FD_UPDT_CLOSED,      // FD was closed
	FD_UPDT_MIGRATED,    // FD was migrated, ignore it now
};

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
} ALIGNED(8);

/* head of the fd cache, per-group */
struct fdlist {
	int first;
	int last;
} ALIGNED(64);

/* info about one given fd. Note: only align on cache lines when using threads;
 * 32-bit small archs can put everything in 32-bytes when threads are disabled.
 * refc_tgid is an atomic 32-bit composite value made of 16 higher bits
 * containing a refcount on tgid and the running_mask, and 16 lower bits
 * containing a thread group ID and a lock bit on the 16th. The tgid may only
 * be changed when refc is zero and running may only be checked/changed when
 * refc is held and shows the reader is alone. An FD with tgid zero belongs to
 * nobody.
 */
struct fdtab {
	unsigned long running_mask;          /* mask of thread IDs currently using the fd */
	unsigned long thread_mask;           /* mask of thread IDs authorized to process the fd */
	unsigned long update_mask;           /* mask of thread IDs having an update for fd */
	struct fdlist_entry update;          /* Entry in the global update list */
	void (*iocb)(int fd);                /* I/O handler */
	void *owner;                         /* the connection or listener associated with this fd, NULL if closed */
	unsigned int state;                  /* FD state for read and write directions (FD_EV_*) + FD_POLL_* */
	unsigned int refc_tgid;              /* refcounted tgid, updated atomically */
	/* the info below are mainly used for epoll debugging/strengthening.
	 * they're filling the rest of the cache line but may easily be dropped
	 * if the room is needed for more important stuff.
	 */
	unsigned int nb_takeover;            /* number of times this FD was taken over since inserted (used for debugging) */
	unsigned int generation;             /* number of times this FD was closed before (used for epoll strengthening) */
#ifdef DEBUG_FD
	unsigned int event_count;            /* number of events reported */
#endif
} THREAD_ALIGNED(64);

/* polled mask, one bit per thread and per direction for each FD */
struct polled_mask {
	unsigned long poll_recv;
	unsigned long poll_send;
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
 *  - poll() calls the poller, expiring at <exp>, or immediately if <wake> is set
 *  - flags indicate what the poller supports (HAP_POLL_F_*)
 */

#define HAP_POLL_F_RDHUP        0x00000001                   /* the poller notifies of HUP with reads */
#define HAP_POLL_F_ERRHUP       0x00000002                   /* the poller reports ERR and HUP */

struct poller {
	void   *private;                                     /* any private data for the poller */
	void   (*clo)(const int fd);                 /* mark <fd> as closed */
	void   (*poll)(struct poller *p, int exp, int wake);  /* the poller itself */
	int    (*init)(struct poller *p);            /* poller initialization */
	void   (*term)(struct poller *p);            /* termination of this poller */
	int    (*test)(struct poller *p);            /* pre-init check of the poller */
	int    (*fork)(struct poller *p);            /* post-fork re-opening */
	const char   *name;                                  /* poller name */
	unsigned int flags;                                  /* HAP_POLL_F_* */
	int    pref;                                         /* try pollers with higher preference first */
};

#endif /* _HAPROXY_FD_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
