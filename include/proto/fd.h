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
#include <common/ticks.h>
#include <common/time.h>
#include <types/fd.h>
#include <proto/activity.h>

/* public variables */

extern volatile struct fdlist fd_cache;
extern volatile struct fdlist fd_cache_local[MAX_THREADS];

extern volatile struct fdlist update_list;

extern unsigned long *polled_mask;

extern unsigned long fd_cache_mask; // Mask of threads with events in the cache

extern THREAD_LOCAL int *fd_updt;  // FD updates list
extern THREAD_LOCAL int fd_nbupdt; // number of updates in the list

extern int poller_wr_pipe[MAX_THREADS];

__decl_hathreads(extern HA_RWLOCK_T   __attribute__((aligned(64))) fdcache_lock);    /* global lock to protect fd_cache array */

/* Deletes an FD from the fdsets.
 * The file descriptor is also closed.
 */
void fd_delete(int fd);

/* Deletes an FD from the fdsets.
 * The file descriptor is kept open.
 */
void fd_remove(int fd);

/* disable the specified poller */
void disable_poller(const char *poller_name);

void poller_pipe_io_handler(int fd);

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

void fd_add_to_fd_list(volatile struct fdlist *list, int fd, int off);
void fd_rm_from_fd_list(volatile struct fdlist *list, int fd, int off);

/* Mark fd <fd> as updated for polling and allocate an entry in the update list
 * for this if it was not already there. This can be done at any time.
 */
static inline void updt_fd_polling(const int fd)
{
	if ((fdtab[fd].thread_mask & all_threads_mask) == tid_bit) {
		unsigned int oldupdt;

		/* note: we don't have a test-and-set yet in hathreads */

		if (HA_ATOMIC_BTS(&fdtab[fd].update_mask, tid))
			return;

		oldupdt = HA_ATOMIC_ADD(&fd_nbupdt, 1) - 1;
		fd_updt[oldupdt] = fd;
	} else {
		unsigned long update_mask = fdtab[fd].update_mask;
		do {
			if (update_mask == fdtab[fd].thread_mask)
				return;
		} while (!HA_ATOMIC_CAS(&fdtab[fd].update_mask, &update_mask,
		    fdtab[fd].thread_mask));
		fd_add_to_fd_list(&update_list, fd, offsetof(struct fdtab, update));
	}

}

/* Called from the poller to acknoledge we read an entry from the global
 * update list, to remove our bit from the update_mask, and remove it from
 * the list if we were the last one.
 */
static inline void done_update_polling(int fd)
{
	unsigned long update_mask;

	update_mask = HA_ATOMIC_AND(&fdtab[fd].update_mask, ~tid_bit);
	while ((update_mask & all_threads_mask)== 0) {
		/* If we were the last one that had to update that entry, remove it from the list */
		fd_rm_from_fd_list(&update_list, fd, offsetof(struct fdtab, update));
		if (update_list.first == fd)
			abort();
		update_mask = (volatile unsigned long)fdtab[fd].update_mask;
		if ((update_mask & all_threads_mask) != 0) {
			/* Maybe it's been re-updated in the meanwhile, and we
			 * wrongly removed it from the list, if so, re-add it
			 */
			fd_add_to_fd_list(&update_list, fd, offsetof(struct fdtab, update));
			update_mask = (volatile unsigned long)(fdtab[fd].update_mask);
			/* And then check again, just in case after all it
			 * should be removed, even if it's very unlikely, given
			 * the current thread wouldn't have been able to take
			 * care of it yet */
		} else
			break;

	}
}

/* Allocates a cache entry for a file descriptor if it does not yet have one.
 * This can be done at any time.
 */
static inline void fd_alloc_cache_entry(const int fd)
{
	HA_ATOMIC_OR(&fd_cache_mask, fdtab[fd].thread_mask);
	if (!(fdtab[fd].thread_mask & (fdtab[fd].thread_mask - 1)))
		fd_add_to_fd_list(&fd_cache_local[my_ffsl(fdtab[fd].thread_mask) - 1], fd,  offsetof(struct fdtab, cache));
	else
		fd_add_to_fd_list(&fd_cache, fd,  offsetof(struct fdtab, cache));
}

/* Removes entry used by fd <fd> from the FD cache and replaces it with the
 * last one.
 * If the fd has no entry assigned, return immediately.
 */
static inline void fd_release_cache_entry(const int fd)
{
	if (!(fdtab[fd].thread_mask & (fdtab[fd].thread_mask - 1)))
		fd_rm_from_fd_list(&fd_cache_local[my_ffsl(fdtab[fd].thread_mask) - 1], fd, offsetof(struct fdtab, cache));
	else
		fd_rm_from_fd_list(&fd_cache, fd, offsetof(struct fdtab, cache));
}

/* This function automatically enables/disables caching for an entry depending
 * on its state. It is only called on state changes.
 */
static inline void fd_update_cache(int fd)
{
	/* only READY and ACTIVE states (the two with both flags set) require a cache entry */
	if (((fdtab[fd].state & (FD_EV_READY_R | FD_EV_ACTIVE_R)) == (FD_EV_READY_R | FD_EV_ACTIVE_R)) ||
	    ((fdtab[fd].state & (FD_EV_READY_W | FD_EV_ACTIVE_W)) == (FD_EV_READY_W | FD_EV_ACTIVE_W))) {
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

/*
 * returns true if the FD is active for recv or send
 */
static inline int fd_active(const int fd)
{
	return (unsigned)fdtab[fd].state & FD_EV_ACTIVE_RW;
}

/* Disable processing recv events on fd <fd> */
static inline void fd_stop_recv(int fd)
{
	unsigned char old, new;

	old = fdtab[fd].state;
	do {
		if (!(old & FD_EV_ACTIVE_R))
			return;
		new = old & ~FD_EV_ACTIVE_R;
		new &= ~FD_EV_POLLED_R;
	} while (unlikely(!HA_ATOMIC_CAS(&fdtab[fd].state, &old, new)));

	if ((old ^ new) & FD_EV_POLLED_R)
		updt_fd_polling(fd);

	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	fd_update_cache(fd); /* need an update entry to change the state */
	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Disable processing send events on fd <fd> */
static inline void fd_stop_send(int fd)
{
	unsigned char old, new;

	old = fdtab[fd].state;
	do {
		if (!(old & FD_EV_ACTIVE_W))
			return;
		new = old & ~FD_EV_ACTIVE_W;
		new &= ~FD_EV_POLLED_W;
	} while (unlikely(!HA_ATOMIC_CAS(&fdtab[fd].state, &old, new)));

	if ((old ^ new) & FD_EV_POLLED_W)
		updt_fd_polling(fd);

	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	fd_update_cache(fd); /* need an update entry to change the state */
	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Disable processing of events on fd <fd> for both directions. */
static inline void fd_stop_both(int fd)
{
	unsigned char old, new;

	old = fdtab[fd].state;
	do {
		if (!(old & FD_EV_ACTIVE_RW))
			return;
		new = old & ~FD_EV_ACTIVE_RW;
		new &= ~FD_EV_POLLED_RW;
	} while (unlikely(!HA_ATOMIC_CAS(&fdtab[fd].state, &old, new)));

	if ((old ^ new) & FD_EV_POLLED_RW)
		updt_fd_polling(fd);

	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	fd_update_cache(fd); /* need an update entry to change the state */
	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Report that FD <fd> cannot receive anymore without polling (EAGAIN detected). */
static inline void fd_cant_recv(const int fd)
{
	unsigned char old, new;

	old = fdtab[fd].state;
	do {
		if (!(old & FD_EV_READY_R))
			return;
		new = old & ~FD_EV_READY_R;
		if (new & FD_EV_ACTIVE_R)
			new |= FD_EV_POLLED_R;
	} while (unlikely(!HA_ATOMIC_CAS(&fdtab[fd].state, &old, new)));

	if ((old ^ new) & FD_EV_POLLED_R)
		updt_fd_polling(fd);

	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	fd_update_cache(fd); /* need an update entry to change the state */
	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Report that FD <fd> can receive anymore without polling. */
static inline void fd_may_recv(const int fd)
{
	/* marking ready never changes polled status */
	HA_ATOMIC_OR(&fdtab[fd].state, FD_EV_READY_R);

	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	fd_update_cache(fd); /* need an update entry to change the state */
	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Disable readiness when polled. This is useful to interrupt reading when it
 * is suspected that the end of data might have been reached (eg: short read).
 * This can only be done using level-triggered pollers, so if any edge-triggered
 * is ever implemented, a test will have to be added here.
 */
static inline void fd_done_recv(const int fd)
{
	unsigned char old, new;

	old = fdtab[fd].state;
	do {
		if ((old & (FD_EV_POLLED_R|FD_EV_READY_R)) != (FD_EV_POLLED_R|FD_EV_READY_R))
			return;
		new = old & ~FD_EV_READY_R;
		if (new & FD_EV_ACTIVE_R)
			new |= FD_EV_POLLED_R;
	} while (unlikely(!HA_ATOMIC_CAS(&fdtab[fd].state, &old, new)));

	if ((old ^ new) & FD_EV_POLLED_R)
		updt_fd_polling(fd);

	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	fd_update_cache(fd); /* need an update entry to change the state */
	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Report that FD <fd> cannot send anymore without polling (EAGAIN detected). */
static inline void fd_cant_send(const int fd)
{
	unsigned char old, new;

	old = fdtab[fd].state;
	do {
		if (!(old & FD_EV_READY_W))
			return;
		new = old & ~FD_EV_READY_W;
		if (new & FD_EV_ACTIVE_W)
			new |= FD_EV_POLLED_W;
	} while (unlikely(!HA_ATOMIC_CAS(&fdtab[fd].state, &old, new)));

	if ((old ^ new) & FD_EV_POLLED_W)
		updt_fd_polling(fd);

	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	fd_update_cache(fd); /* need an update entry to change the state */
	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Report that FD <fd> can send anymore without polling (EAGAIN detected). */
static inline void fd_may_send(const int fd)
{
	/* marking ready never changes polled status */
	HA_ATOMIC_OR(&fdtab[fd].state, FD_EV_READY_W);

	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	fd_update_cache(fd); /* need an update entry to change the state */
	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Prepare FD <fd> to try to receive */
static inline void fd_want_recv(int fd)
{
	unsigned char old, new;

	old = fdtab[fd].state;
	do {
		if (old & FD_EV_ACTIVE_R)
			return;
		new = old | FD_EV_ACTIVE_R;
		if (!(new & FD_EV_READY_R))
			new |= FD_EV_POLLED_R;
	} while (unlikely(!HA_ATOMIC_CAS(&fdtab[fd].state, &old, new)));

	if ((old ^ new) & FD_EV_POLLED_R)
		updt_fd_polling(fd);

	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	fd_update_cache(fd); /* need an update entry to change the state */
	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Prepare FD <fd> to try to send */
static inline void fd_want_send(int fd)
{
	unsigned char old, new;

	old = fdtab[fd].state;
	do {
		if (old & FD_EV_ACTIVE_W)
			return;
		new = old | FD_EV_ACTIVE_W;
		if (!(new & FD_EV_READY_W))
			new |= FD_EV_POLLED_W;
	} while (unlikely(!HA_ATOMIC_CAS(&fdtab[fd].state, &old, new)));

	if ((old ^ new) & FD_EV_POLLED_W)
		updt_fd_polling(fd);

	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	fd_update_cache(fd); /* need an update entry to change the state */
	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Update events seen for FD <fd> and its state if needed. This should be called
 * by the poller to set FD_POLL_* flags. */
static inline void fd_update_events(int fd, int evts)
{
	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	fdtab[fd].ev &= FD_POLL_STICKY;
	fdtab[fd].ev |= evts;
	if (atleast2(fdtab[fd].thread_mask))
		HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);

	if (fdtab[fd].ev & (FD_POLL_IN | FD_POLL_HUP | FD_POLL_ERR))
		fd_may_recv(fd);

	if (fdtab[fd].ev & (FD_POLL_OUT | FD_POLL_ERR))
		fd_may_send(fd);
}

/* Prepares <fd> for being polled */
static inline void fd_insert(int fd, void *owner, void (*iocb)(int fd), unsigned long thread_mask)
{
	if (atleast2(thread_mask))
		HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	fdtab[fd].owner = owner;
	fdtab[fd].iocb = iocb;
	fdtab[fd].ev = 0;
	fdtab[fd].linger_risk = 0;
	fdtab[fd].cloned = 0;
	fdtab[fd].thread_mask = thread_mask;
	/* note: do not reset polled_mask here as it indicates which poller
	 * still knows this FD from a possible previous round.
	 */
	if (atleast2(thread_mask))
		HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Computes the bounded poll() timeout based on the next expiration timer <next>
 * by bounding it to MAX_DELAY_MS. <next> may equal TICK_ETERNITY. The pollers
 * just needs to call this function right before polling to get their timeout
 * value. Timeouts that are already expired (possibly due to a pending event)
 * are accounted for in activity.poll_exp.
 */
static inline int compute_poll_timeout(int next)
{
	int wait_time;

	if (!tick_isset(next))
		wait_time = MAX_DELAY_MS;
	else if (tick_is_expired(next, now_ms)) {
		activity[tid].poll_exp++;
		wait_time = 0;
	}
	else {
		wait_time = TICKS_TO_MS(tick_remain(now_ms, next)) + 1;
		if (wait_time > MAX_DELAY_MS)
			wait_time = MAX_DELAY_MS;
	}
	return wait_time;
}

/* These are replacements for FD_SET, FD_CLR, FD_ISSET, working on uints */
static inline void hap_fd_set(int fd, unsigned int *evts)
{
	HA_ATOMIC_OR(&evts[fd / (8*sizeof(*evts))], 1U << (fd & (8*sizeof(*evts) - 1)));
}

static inline void hap_fd_clr(int fd, unsigned int *evts)
{
	HA_ATOMIC_AND(&evts[fd / (8*sizeof(*evts))], ~(1U << (fd & (8*sizeof(*evts) - 1))));
}

static inline unsigned int hap_fd_isset(int fd, unsigned int *evts)
{
	return evts[fd / (8*sizeof(*evts))] & (1U << (fd & (8*sizeof(*evts) - 1)));
}

static inline void wake_thread(int tid)
{
	char c = 'c';

	shut_your_big_mouth_gcc(write(poller_wr_pipe[tid], &c, 1));
}


#endif /* _PROTO_FD_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
