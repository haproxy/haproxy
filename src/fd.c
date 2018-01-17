/*
 * File descriptors management functions.
 *
 * Copyright 2000-2014 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * This code implements an events cache for file descriptors. It remembers the
 * readiness of a file descriptor after a return from poll() and the fact that
 * an I/O attempt failed on EAGAIN. Events in the cache which are still marked
 * ready and active are processed just as if they were reported by poll().
 *
 * This serves multiple purposes. First, it significantly improves performance
 * by avoiding to subscribe to polling unless absolutely necessary, so most
 * events are processed without polling at all, especially send() which
 * benefits from the socket buffers. Second, it is the only way to support
 * edge-triggered pollers (eg: EPOLL_ET). And third, it enables I/O operations
 * that are backed by invisible buffers. For example, SSL is able to read a
 * whole socket buffer and not deliver it to the application buffer because
 * it's full. Unfortunately, it won't be reported by a poller anymore until
 * some new activity happens. The only way to call it again thus is to keep
 * this readiness information in the cache and to access it without polling
 * once the FD is enabled again.
 *
 * One interesting feature of the cache is that it maintains the principle
 * of speculative I/O introduced in haproxy 1.3 : the first time an event is
 * enabled, the FD is considered as ready so that the I/O attempt is performed
 * via the cache without polling. And the polling happens only when EAGAIN is
 * first met. This avoids polling for HTTP requests, especially when the
 * defer-accept mode is used. It also avoids polling for sending short data
 * such as requests to servers or short responses to clients.
 *
 * The cache consists in a list of active events and a list of updates.
 * Active events are events that are expected to come and that we must report
 * to the application until it asks to stop or asks to poll. Updates are new
 * requests for changing an FD state. Updates are the only way to create new
 * events. This is important because it means that the number of cached events
 * cannot increase between updates and will only grow one at a time while
 * processing updates. All updates must always be processed, though events
 * might be processed by small batches if required.
 *
 * There is no direct link between the FD and the updates list. There is only a
 * bit in the fdtab[] to indicate than a file descriptor is already present in
 * the updates list. Once an fd is present in the updates list, it will have to
 * be considered even if its changes are reverted in the middle or if the fd is
 * replaced.
 *
 * It is important to understand that as long as all expected events are
 * processed, they might starve the polled events, especially because polled
 * I/O starvation quickly induces more cached I/O. One solution to this
 * consists in only processing a part of the events at once, but one drawback
 * is that unhandled events will still wake the poller up. Using an edge-
 * triggered poller such as EPOLL_ET will solve this issue though.
 *
 * Since we do not want to scan all the FD list to find cached I/O events,
 * we store them in a list consisting in a linear array holding only the FD
 * indexes right now. Note that a closed FD cannot exist in the cache, because
 * it is closed by fd_delete() which in turn calls fd_release_cache_entry()
 * which always removes it from the list.
 *
 * The FD array has to hold a back reference to the cache. This reference is
 * always valid unless the FD is not in the cache and is not updated, in which
 * case the reference points to index 0.
 *
 * The event state for an FD, as found in fdtab[].state, is maintained for each
 * direction. The state field is built this way, with R bits in the low nibble
 * and W bits in the high nibble for ease of access and debugging :
 *
 *               7    6    5    4   3    2    1    0
 *             [ 0 | PW | RW | AW | 0 | PR | RR | AR ]
 *
 *                   A* = active     *R = read
 *                   P* = polled     *W = write
 *                   R* = ready
 *
 * An FD is marked "active" when there is a desire to use it.
 * An FD is marked "polled" when it is registered in the polling.
 * An FD is marked "ready" when it has not faced a new EAGAIN since last wake-up
 * (it is a cache of the last EAGAIN regardless of polling changes).
 *
 * We have 8 possible states for each direction based on these 3 flags :
 *
 *   +---+---+---+----------+---------------------------------------------+
 *   | P | R | A | State    | Description				  |
 *   +---+---+---+----------+---------------------------------------------+
 *   | 0 | 0 | 0 | DISABLED | No activity desired, not ready.		  |
 *   | 0 | 0 | 1 | MUSTPOLL | Activity desired via polling.		  |
 *   | 0 | 1 | 0 | STOPPED  | End of activity without polling.		  |
 *   | 0 | 1 | 1 | ACTIVE   | Activity desired without polling.		  |
 *   | 1 | 0 | 0 | ABORT    | Aborted poll(). Not frequently seen.	  |
 *   | 1 | 0 | 1 | POLLED   | FD is being polled.			  |
 *   | 1 | 1 | 0 | PAUSED   | FD was paused while ready (eg: buffer full) |
 *   | 1 | 1 | 1 | READY    | FD was marked ready by poll()		  |
 *   +---+---+---+----------+---------------------------------------------+
 *
 * The transitions are pretty simple :
 *   - fd_want_*() : set flag A
 *   - fd_stop_*() : clear flag A
 *   - fd_cant_*() : clear flag R (when facing EAGAIN)
 *   - fd_may_*()  : set flag R (upon return from poll())
 *   - sync()      : if (A) { if (!R) P := 1 } else { P := 0 }
 *
 * The PAUSED, ABORT and MUSTPOLL states are transient for level-trigerred
 * pollers and are fixed by the sync() which happens at the beginning of the
 * poller. For event-triggered pollers, only the MUSTPOLL state will be
 * transient and ABORT will lead to PAUSED. The ACTIVE state is the only stable
 * one which has P != A.
 *
 * The READY state is a bit special as activity on the FD might be notified
 * both by the poller or by the cache. But it is needed for some multi-layer
 * protocols (eg: SSL) where connection activity is not 100% linked to FD
 * activity. Also some pollers might prefer to implement it as ACTIVE if
 * enabling/disabling the FD is cheap. The READY and ACTIVE states are the
 * two states for which a cache entry is allocated.
 *
 * The state transitions look like the diagram below. Only the 4 right states
 * have polling enabled :
 *
 *          (POLLED=0)          (POLLED=1)
 *
 *          +----------+  sync  +-------+
 *          | DISABLED | <----- | ABORT |         (READY=0, ACTIVE=0)
 *          +----------+        +-------+
 *         clr |  ^           set |  ^
 *             |  |               |  |
 *             v  | set           v  | clr
 *          +----------+  sync  +--------+
 *          | MUSTPOLL | -----> | POLLED |        (READY=0, ACTIVE=1)
 *          +----------+        +--------+
 *                ^          poll |  ^
 *                |               |  |
 *                | EAGAIN        v  | EAGAIN
 *           +--------+         +-------+
 *           | ACTIVE |         | READY |         (READY=1, ACTIVE=1)
 *           +--------+         +-------+
 *         clr |  ^           set |  ^
 *             |  |               |  |
 *             v  | set           v  | clr
 *          +---------+   sync  +--------+
 *          | STOPPED | <------ | PAUSED |        (READY=1, ACTIVE=0)
 *          +---------+         +--------+
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <common/compat.h>
#include <common/config.h>

#include <types/global.h>

#include <proto/fd.h>
#include <proto/log.h>
#include <proto/port_range.h>

struct fdtab *fdtab = NULL;     /* array of all the file descriptors */
struct fdinfo *fdinfo = NULL;   /* less-often used infos for file descriptors */
int maxfd;                      /* # of the highest fd + 1 */
int totalconn;                  /* total # of terminated sessions */
int actconn;                    /* # of active sessions */

struct poller pollers[MAX_POLLERS];
struct poller cur_poller;
int nbpollers = 0;

unsigned int *fd_cache = NULL; // FD events cache
int fd_cache_num = 0;          // number of events in the cache
unsigned long fd_cache_mask = 0; // Mask of threads with events in the cache

THREAD_LOCAL int *fd_updt  = NULL;  // FD updates list
THREAD_LOCAL int  fd_nbupdt = 0;   // number of updates in the list

__decl_hathreads(HA_SPINLOCK_T fdtab_lock);       /* global lock to protect fdtab array */
__decl_hathreads(HA_RWLOCK_T   fdcache_lock);     /* global lock to protect fd_cache array */
__decl_hathreads(HA_SPINLOCK_T poll_lock);        /* global lock to protect poll info */

/* Deletes an FD from the fdsets, and recomputes the maxfd limit.
 * The file descriptor is also closed.
 */
static void fd_dodelete(int fd, int do_close)
{
	HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	if (fdtab[fd].linger_risk) {
		/* this is generally set when connecting to servers */
		setsockopt(fd, SOL_SOCKET, SO_LINGER,
			   (struct linger *) &nolinger, sizeof(struct linger));
	}
	if (cur_poller.clo)
		cur_poller.clo(fd);

	fd_release_cache_entry(fd);
	fdtab[fd].state = 0;

	port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
	fdinfo[fd].port_range = NULL;
	fdtab[fd].owner = NULL;
	fdtab[fd].update_mask &= ~tid_bit;
	fdtab[fd].new = 0;
	fdtab[fd].thread_mask = 0;
	if (do_close) {
		fdtab[fd].polled_mask = 0;
		close(fd);
	}
	HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);

	HA_SPIN_LOCK(FDTAB_LOCK, &fdtab_lock);
	while ((maxfd-1 >= 0) && !fdtab[maxfd-1].owner)
		maxfd--;
	HA_SPIN_UNLOCK(FDTAB_LOCK, &fdtab_lock);
}

/* Deletes an FD from the fdsets, and recomputes the maxfd limit.
 * The file descriptor is also closed.
 */
void fd_delete(int fd)
{
	fd_dodelete(fd, 1);
}

/* Deletes an FD from the fdsets, and recomputes the maxfd limit.
 * The file descriptor is kept open.
 */
void fd_remove(int fd)
{
	fd_dodelete(fd, 0);
}

/* Scan and process the cached events. This should be called right after
 * the poller. The loop may cause new entries to be created, for example
 * if a listener causes an accept() to initiate a new incoming connection
 * wanting to attempt an recv().
 */
void fd_process_cached_events()
{
	int fd, entry, e;

	HA_RWLOCK_RDLOCK(FDCACHE_LOCK, &fdcache_lock);
	fd_cache_mask &= ~tid_bit;
	for (entry = 0; entry < fd_cache_num; ) {
		fd = fd_cache[entry];

		if (!(fdtab[fd].thread_mask & tid_bit)) {
			activity[tid].fd_skip++;
			goto next;
		}

		fd_cache_mask |= tid_bit;
		if (HA_SPIN_TRYLOCK(FD_LOCK, &fdtab[fd].lock)) {
			activity[tid].fd_lock++;
			goto next;
		}

		HA_RWLOCK_RDUNLOCK(FDCACHE_LOCK, &fdcache_lock);

		e = fdtab[fd].state;
		fdtab[fd].ev &= FD_POLL_STICKY;

		if ((e & (FD_EV_READY_R | FD_EV_ACTIVE_R)) == (FD_EV_READY_R | FD_EV_ACTIVE_R))
			fdtab[fd].ev |= FD_POLL_IN;

		if ((e & (FD_EV_READY_W | FD_EV_ACTIVE_W)) == (FD_EV_READY_W | FD_EV_ACTIVE_W))
			fdtab[fd].ev |= FD_POLL_OUT;

		if (fdtab[fd].iocb && fdtab[fd].owner && fdtab[fd].ev) {
			HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
			fdtab[fd].iocb(fd);
		}
		else {
			fd_release_cache_entry(fd);
			HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
		}

		HA_RWLOCK_RDLOCK(FDCACHE_LOCK, &fdcache_lock);
		/* If the fd was removed from the cache, it has been
		 * replaced by the next one that we don't want to skip !
		 */
		if (entry < fd_cache_num && fd_cache[entry] != fd) {
			activity[tid].fd_del++;
			continue;
		}
	  next:
		entry++;
	}
	HA_RWLOCK_RDUNLOCK(FDCACHE_LOCK, &fdcache_lock);
}

/* disable the specified poller */
void disable_poller(const char *poller_name)
{
	int p;

	for (p = 0; p < nbpollers; p++)
		if (strcmp(pollers[p].name, poller_name) == 0)
			pollers[p].pref = 0;
}

/* Initialize the pollers per thread */
static int init_pollers_per_thread()
{
	if ((fd_updt = calloc(global.maxsock, sizeof(*fd_updt))) == NULL)
		return 0;
	return 1;
}

/* Deinitialize the pollers per thread */
static void deinit_pollers_per_thread()
{
	free(fd_updt);
	fd_updt = NULL;
}

/*
 * Initialize the pollers till the best one is found.
 * If none works, returns 0, otherwise 1.
 */
int init_pollers()
{
	int p;
	struct poller *bp;

	if ((fdtab = calloc(global.maxsock, sizeof(struct fdtab))) == NULL)
		goto fail_tab;

	if ((fdinfo = calloc(global.maxsock, sizeof(struct fdinfo))) == NULL)
		goto fail_info;

	if ((fd_cache = calloc(global.maxsock, sizeof(*fd_cache))) == NULL)
		goto fail_cache;

	hap_register_per_thread_init(init_pollers_per_thread);
	hap_register_per_thread_deinit(deinit_pollers_per_thread);

	for (p = 0; p < global.maxsock; p++)
		HA_SPIN_INIT(&fdtab[p].lock);

	HA_SPIN_INIT(&fdtab_lock);
	HA_RWLOCK_INIT(&fdcache_lock);
	HA_SPIN_INIT(&poll_lock);
	do {
		bp = NULL;
		for (p = 0; p < nbpollers; p++)
			if (!bp || (pollers[p].pref > bp->pref))
				bp = &pollers[p];

		if (!bp || bp->pref == 0)
			break;

		if (bp->init(bp)) {
			memcpy(&cur_poller, bp, sizeof(*bp));
			return 1;
		}
	} while (!bp || bp->pref == 0);
	return 0;

 fail_cache:
	free(fdinfo);
 fail_info:
	free(fdtab);
 fail_tab:
	return 0;
}

/*
 * Deinitialize the pollers.
 */
void deinit_pollers() {

	struct poller *bp;
	int p;

	for (p = 0; p < global.maxsock; p++)
		HA_SPIN_DESTROY(&fdtab[p].lock);

	for (p = 0; p < nbpollers; p++) {
		bp = &pollers[p];

		if (bp && bp->pref)
			bp->term(bp);
	}

	free(fd_cache); fd_cache = NULL;
	free(fdinfo);   fdinfo   = NULL;
	free(fdtab);    fdtab    = NULL;

	HA_SPIN_DESTROY(&fdtab_lock);
	HA_RWLOCK_DESTROY(&fdcache_lock);
	HA_SPIN_DESTROY(&poll_lock);
}

/*
 * Lists the known pollers on <out>.
 * Should be performed only before initialization.
 */
int list_pollers(FILE *out)
{
	int p;
	int last, next;
	int usable;
	struct poller *bp;

	fprintf(out, "Available polling systems :\n");

	usable = 0;
	bp = NULL;
	last = next = -1;
	while (1) {
		for (p = 0; p < nbpollers; p++) {
			if ((next < 0 || pollers[p].pref > next)
			    && (last < 0 || pollers[p].pref < last)) {
				next = pollers[p].pref;
				if (!bp || (pollers[p].pref > bp->pref))
					bp = &pollers[p];
			}
		}

		if (next == -1)
			break;

		for (p = 0; p < nbpollers; p++) {
			if (pollers[p].pref == next) {
				fprintf(out, " %10s : ", pollers[p].name);
				if (pollers[p].pref == 0)
					fprintf(out, "disabled, ");
				else
					fprintf(out, "pref=%3d, ", pollers[p].pref);
				if (pollers[p].test(&pollers[p])) {
					fprintf(out, " test result OK");
					if (next > 0)
						usable++;
				} else {
					fprintf(out, " test result FAILED");
					if (bp == &pollers[p])
						bp = NULL;
				}
				fprintf(out, "\n");
			}
		}
		last = next;
		next = -1;
	};
	fprintf(out, "Total: %d (%d usable), will use %s.\n", nbpollers, usable, bp ? bp->name : "none");
	return 0;
}

/*
 * Some pollers may lose their connection after a fork(). It may be necessary
 * to create initialize part of them again. Returns 0 in case of failure,
 * otherwise 1. The fork() function may be NULL if unused. In case of error,
 * the the current poller is destroyed and the caller is responsible for trying
 * another one by calling init_pollers() again.
 */
int fork_poller()
{
	int fd;
	for (fd = 0; fd <= maxfd; fd++) {
		if (fdtab[fd].owner) {
			fdtab[fd].cloned = 1;
		}
	}

	if (cur_poller.fork) {
		if (cur_poller.fork(&cur_poller))
			return 1;
		cur_poller.term(&cur_poller);
		return 0;
	}
	return 1;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
