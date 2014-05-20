/*
 * include/proto/fd.h
 * File descriptors states.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _PROTO_FD_H
#define _PROTO_FD_H

#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/config.h>
#include <types/fd.h>

/* public variables */
extern unsigned int *fd_cache;      // FD events cache
extern unsigned int *fd_updt;       // FD updates list
extern int fd_cache_num;            // number of events in the cache
extern int fd_nbupdt;               // number of updates in the list

/* Deletes an FD from the fdsets, and recomputes the maxfd limit.
 * The file descriptor is also closed.
 */
void fd_delete(int fd);

/* disable the specified poller */
void disable_poller(const char *poller_name);

/*
 * Initialize the pollers till the best one is found.
 * If none works, returns 0, otherwise 1.
 * The pollers register themselves just before main() is called.
 */
int init_pollers();

/*
 * Deinitialize the pollers.
 */
void deinit_pollers();

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

/* Scan and process the cached events. This should be called right after
 * the poller.
 */
void fd_process_cached_events();

/* Check the events attached to a file descriptor, update its cache
 * accordingly, and call the associated I/O callback. If new updates are
 * detected, the function tries to process them as well in order to save
 * wakeups after accept().
 */
void fd_process_polled_events(int fd);


/* Mark fd <fd> as updated and allocate an entry in the update list for this if
 * it was not already there. This can be done at any time.
 */
static inline void updt_fd(const int fd)
{
	if (fdtab[fd].updated)
		/* already scheduled for update */
		return;
	fdtab[fd].updated = 1;
	fd_updt[fd_nbupdt++] = fd;
}


/* Allocates a cache entry for a file descriptor if it does not yet have one.
 * This can be done at any time.
 */
static inline void fd_alloc_cache_entry(const int fd)
{
	if (fdtab[fd].cache)
		return;
	fd_cache_num++;
	fdtab[fd].cache = fd_cache_num;
	fd_cache[fd_cache_num-1] = fd;
}

/* Removes entry used by fd <fd> from the FD cache and replaces it with the
 * last one. The fdtab.cache is adjusted to match the back reference if needed.
 * If the fd has no entry assigned, return immediately.
 */
static inline void fd_release_cache_entry(int fd)
{
	unsigned int pos;

	pos = fdtab[fd].cache;
	if (!pos)
		return;
	fdtab[fd].cache = 0;
	fd_cache_num--;
	if (likely(pos <= fd_cache_num)) {
		/* was not the last entry */
		fd = fd_cache[fd_cache_num];
		fd_cache[pos - 1] = fd;
		fdtab[fd].cache = pos;
	}
}

/* Computes the new polled status based on the active and ready statuses, for
 * each direction. This is meant to be used by pollers while processing updates.
 */
static inline int fd_compute_new_polled_status(int state)
{
	if (state & FD_EV_ACTIVE_R) {
		if (!(state & FD_EV_READY_R))
			state |= FD_EV_POLLED_R;
	}
	else
		state &= ~FD_EV_POLLED_R;

	if (state & FD_EV_ACTIVE_W) {
		if (!(state & FD_EV_READY_W))
			state |= FD_EV_POLLED_W;
	}
	else
		state &= ~FD_EV_POLLED_W;

	return state;
}

/* Automatically allocates or releases a cache entry for fd <fd> depending on
 * its new state. This is meant to be used by pollers while processing updates.
 */
static inline void fd_alloc_or_release_cache_entry(int fd, int new_state)
{
	/* READY and ACTIVE states (the two with both flags set) require a cache entry */

	if (((new_state & (FD_EV_READY_R | FD_EV_ACTIVE_R)) == (FD_EV_READY_R | FD_EV_ACTIVE_R)) ||
	    ((new_state & (FD_EV_READY_W | FD_EV_ACTIVE_W)) == (FD_EV_READY_W | FD_EV_ACTIVE_W))) {
		fd_alloc_cache_entry(fd);
	}
	else {
		fd_release_cache_entry(fd);
	}
}

/*
 * returns the FD's recv state (FD_EV_*)
 */
static inline int fd_recv_state(const int fd)
{
	return ((unsigned)fdtab[fd].state >> (4 * DIR_RD)) & FD_EV_STATUS;
}

/*
 * returns true if the FD is active for recv
 */
static inline int fd_recv_active(const int fd)
{
	return (unsigned)fdtab[fd].state & FD_EV_ACTIVE_R;
}

/*
 * returns true if the FD is ready for recv
 */
static inline int fd_recv_ready(const int fd)
{
	return (unsigned)fdtab[fd].state & FD_EV_READY_R;
}

/*
 * returns true if the FD is polled for recv
 */
static inline int fd_recv_polled(const int fd)
{
	return (unsigned)fdtab[fd].state & FD_EV_POLLED_R;
}

/*
 * returns the FD's send state (FD_EV_*)
 */
static inline int fd_send_state(const int fd)
{
	return ((unsigned)fdtab[fd].state >> (4 * DIR_WR)) & FD_EV_STATUS;
}

/*
 * returns true if the FD is active for send
 */
static inline int fd_send_active(const int fd)
{
	return (unsigned)fdtab[fd].state & FD_EV_ACTIVE_W;
}

/*
 * returns true if the FD is ready for send
 */
static inline int fd_send_ready(const int fd)
{
	return (unsigned)fdtab[fd].state & FD_EV_READY_W;
}

/*
 * returns true if the FD is polled for send
 */
static inline int fd_send_polled(const int fd)
{
	return (unsigned)fdtab[fd].state & FD_EV_POLLED_W;
}

/* Disable processing recv events on fd <fd> */
static inline void fd_stop_recv(int fd)
{
	if (!((unsigned int)fdtab[fd].state & FD_EV_ACTIVE_R))
		return; /* already disabled */
	fdtab[fd].state &= ~FD_EV_ACTIVE_R;
	updt_fd(fd); /* need an update entry to change the state */
}

/* Disable processing send events on fd <fd> */
static inline void fd_stop_send(int fd)
{
	if (!((unsigned int)fdtab[fd].state & FD_EV_ACTIVE_W))
		return; /* already disabled */
	fdtab[fd].state &= ~FD_EV_ACTIVE_W;
	updt_fd(fd); /* need an update entry to change the state */
}

/* Disable processing of events on fd <fd> for both directions. */
static inline void fd_stop_both(int fd)
{
	if (!((unsigned int)fdtab[fd].state & FD_EV_ACTIVE_RW))
		return; /* already disabled */
	fdtab[fd].state &= ~FD_EV_ACTIVE_RW;
	updt_fd(fd); /* need an update entry to change the state */
}

/* Report that FD <fd> cannot receive anymore without polling (EAGAIN detected). */
static inline void fd_cant_recv(const int fd)
{
	if (!(((unsigned int)fdtab[fd].state) & FD_EV_READY_R))
		return; /* already marked as blocked */
	fdtab[fd].state &= ~FD_EV_READY_R;
	updt_fd(fd);
}

/* Report that FD <fd> can receive anymore without polling. */
static inline void fd_may_recv(const int fd)
{
	if (((unsigned int)fdtab[fd].state) & FD_EV_READY_R)
		return; /* already marked as blocked */
	fdtab[fd].state |= FD_EV_READY_R;
	updt_fd(fd);
}

/* Disable readiness when polled. This is useful to interrupt reading when it
 * is suspected that the end of data might have been reached (eg: short read).
 * This can only be done using level-triggered pollers, so if any edge-triggered
 * is ever implemented, a test will have to be added here.
 */
static inline void fd_done_recv(const int fd)
{
	if (fd_recv_polled(fd))
		fd_cant_recv(fd);
}

/* Report that FD <fd> cannot send anymore without polling (EAGAIN detected). */
static inline void fd_cant_send(const int fd)
{
	if (!(((unsigned int)fdtab[fd].state) & FD_EV_READY_W))
		return; /* already marked as blocked */
	fdtab[fd].state &= ~FD_EV_READY_W;
	updt_fd(fd);
}

/* Report that FD <fd> can send anymore without polling (EAGAIN detected). */
static inline void fd_may_send(const int fd)
{
	if (((unsigned int)fdtab[fd].state) & FD_EV_READY_W)
		return; /* already marked as blocked */
	fdtab[fd].state |= FD_EV_READY_W;
	updt_fd(fd);
}

/* Prepare FD <fd> to try to receive */
static inline void fd_want_recv(int fd)
{
	if (((unsigned int)fdtab[fd].state & FD_EV_ACTIVE_R))
		return; /* already enabled */
	fdtab[fd].state |= FD_EV_ACTIVE_R;
	updt_fd(fd); /* need an update entry to change the state */
}

/* Prepare FD <fd> to try to send */
static inline void fd_want_send(int fd)
{
	if (((unsigned int)fdtab[fd].state & FD_EV_ACTIVE_W))
		return; /* already enabled */
	fdtab[fd].state |= FD_EV_ACTIVE_W;
	updt_fd(fd); /* need an update entry to change the state */
}

/* Prepares <fd> for being polled */
static inline void fd_insert(int fd)
{
	fdtab[fd].ev = 0;
	fdtab[fd].new = 1;
	fdtab[fd].linger_risk = 0;
	fdtab[fd].cloned = 0;
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
