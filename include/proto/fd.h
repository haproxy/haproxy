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

extern volatile struct fdlist fd_cache;
extern volatile struct fdlist fd_cache_local[MAX_THREADS];

extern unsigned long fd_cache_mask; // Mask of threads with events in the cache

extern THREAD_LOCAL int *fd_updt;  // FD updates list
extern THREAD_LOCAL int fd_nbupdt; // number of updates in the list

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

/* Mark fd <fd> as updated for polling and allocate an entry in the update list
 * for this if it was not already there. This can be done at any time.
 */
static inline void updt_fd_polling(const int fd)
{
	if (fdtab[fd].update_mask & tid_bit)
		/* already scheduled for update */
		return;
	fdtab[fd].update_mask |= tid_bit;
	fd_updt[fd_nbupdt++] = fd;
}

static inline void fd_add_to_fd_list(volatile struct fdlist *list, int fd)
{
	int next;
	int new;
	int old;
	int last;

redo_next:
	next = fdtab[fd].cache.next;
	/* Check that we're not already in the cache, and if not, lock us. */
	if (next >= -2)
		goto done;
	if (!HA_ATOMIC_CAS(&fdtab[fd].cache.next, &next, -2))
		goto redo_next;
	__ha_barrier_store();
redo_last:
	/* First, insert in the linked list */
	last = list->last;
	old = -1;
	new = fd;
	if (unlikely(last == -1)) {
		/* list is empty, try to add ourselves alone so that list->last=fd */

		fdtab[fd].cache.prev = last;

		/* Make sure the "prev" store is visible before we update the last entry */
		__ha_barrier_store();
		if (unlikely(!HA_ATOMIC_CAS(&list->last, &old, new)))
			    goto redo_last;

		/* list->first was necessary -1, we're guaranteed to be alone here */
		list->first = fd;

		/* since we're alone at the end of the list and still locked(-2),
		 * we know noone tried to add past us. Mark the end of list.
		 */
		fdtab[fd].cache.next = -1;
		goto done; /* We're done ! */
	} else {
		/* non-empty list, add past the tail */
		do {
			new = fd;
			old = -1;
			fdtab[fd].cache.prev = last;

			__ha_barrier_store();

			/* adding ourselves past the last element
			 * The CAS will only succeed if its next is -1,
			 * which means it's in the cache, and the last element.
			 */
			if (likely(HA_ATOMIC_CAS(&fdtab[last].cache.next, &old, new)))
				break;
			goto redo_last;
		} while (1);
	}
	/* Then, update the last entry */
redo_fd_cache:
	last = list->last;
	__ha_barrier_load();

	if (unlikely(!HA_ATOMIC_CAS(&list->last, &last, fd)))
		goto redo_fd_cache;
	__ha_barrier_store();
	fdtab[fd].cache.next = -1;
	__ha_barrier_store();
done:
	return;
}

/* Allocates a cache entry for a file descriptor if it does not yet have one.
 * This can be done at any time.
 */
static inline void fd_alloc_cache_entry(const int fd)
{
	if (!(fdtab[fd].thread_mask & (fdtab[fd].thread_mask - 1)))
		fd_add_to_fd_list(&fd_cache_local[my_ffsl(fdtab[fd].thread_mask) - 1], fd);
	else
		fd_add_to_fd_list(&fd_cache, fd);
 }

static inline void fd_rm_from_fd_list(volatile struct fdlist *list, int fd)
{
#if defined(HA_HAVE_CAS_DW) || defined(HA_CAS_IS_8B)
	volatile struct fdlist_entry cur_list, next_list;
#endif
	int old;
	int new = -2;
	int prev;
	int next;
	int last;

lock_self:
#if (defined(HA_CAS_IS_8B) || defined(HA_HAVE_CAS_DW))
	next_list.next = next_list.prev = -2;
	cur_list = fdtab[fd].cache;
	/* First, attempt to lock our own entries */
	do {
		/* The FD is not in the FD cache, give up */
		if (unlikely(cur_list.next <= -3))
			return;
		if (unlikely(cur_list.prev == -2 || cur_list.next == -2))
			goto lock_self;
	} while (
#ifdef HA_CAS_IS_8B
	    unlikely(!HA_ATOMIC_CAS(((void **)(void *)&fdtab[fd].cache.next), ((void **)(void *)&cur_list), (*(void **)(void *)&next_list))))
#else
	    unlikely(!__ha_cas_dw((void *)&fdtab[fd].cache.next, (void *)&cur_list, (void *)&next_list)))
#endif
	    ;
	next = cur_list.next;
	prev = cur_list.prev;

#else
lock_self_next:
	next = fdtab[fd].cache.next;
	if (next == -2)
		goto lock_self_next;
	if (next <= -3)
		goto done;
	if (unlikely(!HA_ATOMIC_CAS(&fdtab[fd].cache.next, &next, -2)))
		goto lock_self_next;
lock_self_prev:
	prev = fdtab[fd].cache.prev;
	if (prev == -2)
		goto lock_self_prev;
	if (unlikely(!HA_ATOMIC_CAS(&fdtab[fd].cache.prev, &prev, -2)))
		goto lock_self_prev;
#endif
	__ha_barrier_store();

	/* Now, lock the entries of our neighbours */
	if (likely(prev != -1)) {
redo_prev:
		old = fd;

		if (unlikely(!HA_ATOMIC_CAS(&fdtab[prev].cache.next, &old, new))) {
			if (unlikely(old == -2)) {
				/* Neighbour already locked, give up and
				 * retry again once he's done
				 */
				fdtab[fd].cache.prev = prev;
				__ha_barrier_store();
				fdtab[fd].cache.next = next;
				__ha_barrier_store();
				goto lock_self;
			}
			goto redo_prev;
		}
	}
	if (likely(next != -1)) {
redo_next:
		old = fd;
		if (unlikely(!HA_ATOMIC_CAS(&fdtab[next].cache.prev, &old, new))) {
			if (unlikely(old == -2)) {
				/* Neighbour already locked, give up and
				 * retry again once he's done
				 */
				if (prev != -1) {
					fdtab[prev].cache.next = fd;
					__ha_barrier_store();
				}
				fdtab[fd].cache.prev = prev;
				__ha_barrier_store();
				fdtab[fd].cache.next = next;
				__ha_barrier_store();
				goto lock_self;
			}
			goto redo_next;
		}
	}
	if (list->first == fd)
		list->first = next;
	__ha_barrier_store();
	last = list->last;
	while (unlikely(last == fd && (!HA_ATOMIC_CAS(&list->last, &last, prev))))
		__ha_compiler_barrier();
	/* Make sure we let other threads know we're no longer in cache,
	 * before releasing our neighbours.
	 */
	__ha_barrier_store();
	if (likely(prev != -1))
		fdtab[prev].cache.next = next;
	__ha_barrier_store();
	if (likely(next != -1))
		fdtab[next].cache.prev = prev;
	__ha_barrier_store();
	/* Ok, now we're out of the fd cache */
	fdtab[fd].cache.next = -(next + 4);
	__ha_barrier_store();
done:
	return;
}

/* Removes entry used by fd <fd> from the FD cache and replaces it with the
 * last one.
 * If the fd has no entry assigned, return immediately.
 */
static inline void fd_release_cache_entry(int fd)
{
	if (!(fdtab[fd].thread_mask & (fdtab[fd].thread_mask - 1)))
		fd_rm_from_fd_list(&fd_cache_local[my_ffsl(fdtab[fd].thread_mask) - 1], fd);
	else
		fd_rm_from_fd_list(&fd_cache, fd);
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

/* This function automatically enables/disables caching for an entry depending
 * on its state, and also possibly creates an update entry so that the poller
 * does its job as well. It is only called on state changes.
 */
static inline void fd_update_cache(int fd)
{
	/* 3 states for each direction require a polling update */
	if ((fdtab[fd].state & (FD_EV_POLLED_R |                 FD_EV_ACTIVE_R)) == FD_EV_POLLED_R ||
	    (fdtab[fd].state & (FD_EV_POLLED_R | FD_EV_READY_R | FD_EV_ACTIVE_R)) == FD_EV_ACTIVE_R ||
	    (fdtab[fd].state & (FD_EV_POLLED_W |                 FD_EV_ACTIVE_W)) == FD_EV_POLLED_W ||
	    (fdtab[fd].state & (FD_EV_POLLED_W | FD_EV_READY_W | FD_EV_ACTIVE_W)) == FD_EV_ACTIVE_W)
		updt_fd_polling(fd);

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
	HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	if (fd_recv_active(fd)) {
		fdtab[fd].state &= ~FD_EV_ACTIVE_R;
		fd_update_cache(fd); /* need an update entry to change the state */
	}
	HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Disable processing send events on fd <fd> */
static inline void fd_stop_send(int fd)
{
	HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	if (fd_send_active(fd)) {
		fdtab[fd].state &= ~FD_EV_ACTIVE_W;
		fd_update_cache(fd); /* need an update entry to change the state */
	}
	HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Disable processing of events on fd <fd> for both directions. */
static inline void fd_stop_both(int fd)
{
	HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	if (fd_active(fd)) {
		fdtab[fd].state &= ~FD_EV_ACTIVE_RW;
		fd_update_cache(fd); /* need an update entry to change the state */
	}
	HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Report that FD <fd> cannot receive anymore without polling (EAGAIN detected). */
static inline void fd_cant_recv(const int fd)
{
	HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	if (fd_recv_ready(fd)) {
		fdtab[fd].state &= ~FD_EV_READY_R;
		fd_update_cache(fd); /* need an update entry to change the state */
	}
	HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Report that FD <fd> can receive anymore without polling. */
static inline void fd_may_recv(const int fd)
{
	HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	if (!fd_recv_ready(fd)) {
		fdtab[fd].state |= FD_EV_READY_R;
		fd_update_cache(fd); /* need an update entry to change the state */
	}
	HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Disable readiness when polled. This is useful to interrupt reading when it
 * is suspected that the end of data might have been reached (eg: short read).
 * This can only be done using level-triggered pollers, so if any edge-triggered
 * is ever implemented, a test will have to be added here.
 */
static inline void fd_done_recv(const int fd)
{
	HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	if (fd_recv_polled(fd) && fd_recv_ready(fd)) {
		fdtab[fd].state &= ~FD_EV_READY_R;
		fd_update_cache(fd); /* need an update entry to change the state */
	}
	HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Report that FD <fd> cannot send anymore without polling (EAGAIN detected). */
static inline void fd_cant_send(const int fd)
{
	HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	if (fd_send_ready(fd)) {
		fdtab[fd].state &= ~FD_EV_READY_W;
		fd_update_cache(fd); /* need an update entry to change the state */
	}
	HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Report that FD <fd> can send anymore without polling (EAGAIN detected). */
static inline void fd_may_send(const int fd)
{
	HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	if (!fd_send_ready(fd)) {
		fdtab[fd].state |= FD_EV_READY_W;
		fd_update_cache(fd); /* need an update entry to change the state */
	}
	HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Prepare FD <fd> to try to receive */
static inline void fd_want_recv(int fd)
{
	HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	if (!fd_recv_active(fd)) {
		fdtab[fd].state |= FD_EV_ACTIVE_R;
		fd_update_cache(fd); /* need an update entry to change the state */
	}
	HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Prepare FD <fd> to try to send */
static inline void fd_want_send(int fd)
{
	HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	if (!fd_send_active(fd)) {
		fdtab[fd].state |= FD_EV_ACTIVE_W;
		fd_update_cache(fd); /* need an update entry to change the state */
	}
	HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
}

/* Update events seen for FD <fd> and its state if needed. This should be called
 * by the poller to set FD_POLL_* flags. */
static inline void fd_update_events(int fd, int evts)
{
	HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	fdtab[fd].ev &= FD_POLL_STICKY;
	fdtab[fd].ev |= evts;
	HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);

	if (fdtab[fd].ev & (FD_POLL_IN | FD_POLL_HUP | FD_POLL_ERR))
		fd_may_recv(fd);

	if (fdtab[fd].ev & (FD_POLL_OUT | FD_POLL_ERR))
		fd_may_send(fd);
}

/* Prepares <fd> for being polled */
static inline void fd_insert(int fd, void *owner, void (*iocb)(int fd), unsigned long thread_mask)
{
	HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
	fdtab[fd].owner = owner;
	fdtab[fd].iocb = iocb;
	fdtab[fd].ev = 0;
	fdtab[fd].update_mask &= ~tid_bit;
	fdtab[fd].linger_risk = 0;
	fdtab[fd].cloned = 0;
	fdtab[fd].thread_mask = thread_mask;
	/* note: do not reset polled_mask here as it indicates which poller
	 * still knows this FD from a possible previous round.
	 */
	HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);
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


#endif /* _PROTO_FD_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
