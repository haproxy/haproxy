/*
 * include/proto/fd.h
 * File descriptors states.
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
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
extern int fd_nbspec;          // number of speculative events in the list
extern int fd_nbupdt;          // number of updates in the list
extern unsigned int *fd_spec;  // speculative I/O list
extern unsigned int *fd_updt;  // FD updates list

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

/* Scan and process the speculative events. This should be called right after
 * the poller.
 */
void fd_process_spec_events();

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


/* allocate an entry for a speculative event. This can be done at any time. */
static inline void alloc_spec_entry(const int fd)
{
	if (fdtab[fd].spec_p)
		/* FD already in speculative I/O list */
		return;
	fd_nbspec++;
	fdtab[fd].spec_p = fd_nbspec;
	fd_spec[fd_nbspec-1] = fd;
}

/* Removes entry used by fd <fd> from the spec list and replaces it with the
 * last one. The fdtab.spec is adjusted to match the back reference if needed.
 * If the fd has no entry assigned, return immediately.
 */
static inline void release_spec_entry(int fd)
{
	unsigned int pos;

	pos = fdtab[fd].spec_p;
	if (!pos)
		return;
	fdtab[fd].spec_p = 0;
	fd_nbspec--;
	if (likely(pos <= fd_nbspec)) {
		/* was not the last entry */
		fd = fd_spec[fd_nbspec];
		fd_spec[pos - 1] = fd;
		fdtab[fd].spec_p = pos;
	}
}

/*
 * Returns non-zero if <fd> is already monitored for events in direction <dir>.
 */
static inline int fd_ev_is_set(const int fd, int dir)
{
	return ((unsigned)fdtab[fd].spec_e >> dir) & FD_EV_STATUS;
}

/* Disable processing of events on fd <fd> for direction <dir>. Note: this
 * function was optimized to be used with a constant for <dir>.
 */
static inline void fd_ev_clr(const int fd, int dir)
{
	unsigned int i = ((unsigned int)fdtab[fd].spec_e) & (FD_EV_STATUS << dir);
	if (i == 0)
		return; /* already disabled */
	fdtab[fd].spec_e ^= i;
	updt_fd(fd); /* need an update entry to change the state */
}

/* Enable polling for events on fd <fd> for direction <dir>. Note: this
 * function was optimized to be used with a constant for <dir>.
 */
static inline void fd_ev_wai(const int fd, int dir)
{
	unsigned int i = ((unsigned int)fdtab[fd].spec_e) & (FD_EV_STATUS << dir);
	if (i == (FD_EV_POLLED << dir))
		return; /* already in desired state */
	fdtab[fd].spec_e ^= i ^ (FD_EV_POLLED << dir);
	updt_fd(fd); /* need an update entry to change the state */
}

/* Enable processing of events on fd <fd> for direction <dir>. Note: this
 * function was optimized to be used with a constant for <dir>.
 */
static inline void fd_ev_set(int fd, int dir)
{
	unsigned int i = ((unsigned int)fdtab[fd].spec_e) & (FD_EV_STATUS << dir);

	/* note that we don't care about disabling the polled state when
	 * enabling the active state, since it brings no benefit but costs
	 * some syscalls.
	 */
	if (i & (FD_EV_ACTIVE << dir))
		return; /* already in desired state */
	fdtab[fd].spec_e |= (FD_EV_ACTIVE << dir);
	updt_fd(fd); /* need an update entry to change the state */
}

/* Disable processing of events on fd <fd> for both directions. */
static inline void fd_ev_rem(const int fd)
{
	unsigned int i = ((unsigned int)fdtab[fd].spec_e) & FD_EV_CURR_MASK;
	if (i == 0)
		return; /* already disabled */
	fdtab[fd].spec_e ^= i;
	updt_fd(fd); /* need an update entry to change the state */
}

/* event manipulation primitives for use by I/O callbacks */
static inline void fd_want_recv(int fd)
{
	return fd_ev_set(fd, DIR_RD);
}

static inline void fd_stop_recv(int fd)
{
	return fd_ev_clr(fd, DIR_RD);
}

static inline void fd_poll_recv(int fd)
{
	return fd_ev_wai(fd, DIR_RD);
}

static inline void fd_want_send(int fd)
{
	return fd_ev_set(fd, DIR_WR);
}

static inline void fd_stop_send(int fd)
{
	return fd_ev_clr(fd, DIR_WR);
}

static inline void fd_poll_send(int fd)
{
	return fd_ev_wai(fd, DIR_WR);
}

static inline void fd_stop_both(int fd)
{
	return fd_ev_rem(fd);
}

/* Prepares <fd> for being polled */
static inline void fd_insert(int fd)
{
	fdtab[fd].ev = 0;
	fdtab[fd].new = 1;
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
