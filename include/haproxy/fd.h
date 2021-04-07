/*
 * include/haproxy/fd.h
 * File descriptors states - exported variables and functions
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_FD_H
#define _HAPROXY_FD_H

#include <sys/time.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <import/ist.h>
#include <haproxy/activity.h>
#include <haproxy/api.h>
#include <haproxy/fd-t.h>
#include <haproxy/global.h>
#include <haproxy/thread.h>
#include <haproxy/ticks.h>
#include <haproxy/time.h>

/* public variables */

extern struct poller cur_poller; /* the current poller */
extern int nbpollers;
extern struct poller pollers[MAX_POLLERS];   /* all registered pollers */
extern struct fdtab *fdtab;             /* array of all the file descriptors */
extern struct fdinfo *fdinfo;           /* less-often used infos for file descriptors */
extern int totalconn;                   /* total # of terminated sessions */
extern int actconn;                     /* # of active sessions */

extern volatile struct fdlist update_list;
extern struct polled_mask *polled_mask;

extern THREAD_LOCAL int *fd_updt;  // FD updates list
extern THREAD_LOCAL int fd_nbupdt; // number of updates in the list

extern int poller_wr_pipe[MAX_THREADS];

extern volatile int ha_used_fds; // Number of FDs we're currently using

/* Deletes an FD from the fdsets.
 * The file descriptor is also closed.
 */
void fd_delete(int fd);
void _fd_delete_orphan(int fd);

/*
 * Take over a FD belonging to another thread.
 * Returns 0 on success, and -1 on failure.
 */
int fd_takeover(int fd, void *expected_owner);

/* lock used by FD migration */
#ifndef HA_HAVE_CAS_DW
__decl_thread(extern HA_RWLOCK_T fd_mig_lock);
#endif

ssize_t fd_write_frag_line(int fd, size_t maxlen, const struct ist pfx[], size_t npfx, const struct ist msg[], size_t nmsg, int nl);

/* close all FDs starting from <start> */
void my_closefrom(int start);

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

void fd_add_to_fd_list(volatile struct fdlist *list, int fd, int off);
void fd_rm_from_fd_list(volatile struct fdlist *list, int fd, int off);
void updt_fd_polling(const int fd);

/* Called from the poller to acknowledge we read an entry from the global
 * update list, to remove our bit from the update_mask, and remove it from
 * the list if we were the last one.
 */
static inline void done_update_polling(int fd)
{
	unsigned long update_mask;

	update_mask = _HA_ATOMIC_AND_FETCH(&fdtab[fd].update_mask, ~tid_bit);
	while ((update_mask & all_threads_mask)== 0) {
		/* If we were the last one that had to update that entry, remove it from the list */
		fd_rm_from_fd_list(&update_list, fd, offsetof(struct fdtab, update));
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
 * returns true if the FD is active for recv or send
 */
static inline int fd_active(const int fd)
{
	return (unsigned)fdtab[fd].state & FD_EV_ACTIVE_RW;
}

/* Disable processing recv events on fd <fd> */
static inline void fd_stop_recv(int fd)
{
	if (!(fdtab[fd].state & FD_EV_ACTIVE_R) ||
	    !HA_ATOMIC_BTR(&fdtab[fd].state, FD_EV_ACTIVE_R_BIT))
		return;
}

/* Disable processing send events on fd <fd> */
static inline void fd_stop_send(int fd)
{
	if (!(fdtab[fd].state & FD_EV_ACTIVE_W) ||
	    !HA_ATOMIC_BTR(&fdtab[fd].state, FD_EV_ACTIVE_W_BIT))
		return;
}

/* Disable processing of events on fd <fd> for both directions. */
static inline void fd_stop_both(int fd)
{
	uint old, new;

	old = fdtab[fd].state;
	do {
		if (!(old & FD_EV_ACTIVE_RW))
			return;
		new = old & ~FD_EV_ACTIVE_RW;
	} while (unlikely(!_HA_ATOMIC_CAS(&fdtab[fd].state, &old, new)));
}

/* Report that FD <fd> cannot receive anymore without polling (EAGAIN detected). */
static inline void fd_cant_recv(const int fd)
{
	/* marking ready never changes polled status */
	if (!(fdtab[fd].state & FD_EV_READY_R) ||
	    !HA_ATOMIC_BTR(&fdtab[fd].state, FD_EV_READY_R_BIT))
		return;
}

/* Report that FD <fd> may receive again without polling. */
static inline void fd_may_recv(const int fd)
{
	/* marking ready never changes polled status */
	if ((fdtab[fd].state & FD_EV_READY_R) ||
	    HA_ATOMIC_BTS(&fdtab[fd].state, FD_EV_READY_R_BIT))
		return;
}

/* Report that FD <fd> may receive again without polling but only if its not
 * active yet. This is in order to speculatively try to enable I/Os when it's
 * highly likely that these will succeed, but without interfering with polling.
 */
static inline void fd_cond_recv(const int fd)
{
	if ((fdtab[fd].state & (FD_EV_ACTIVE_R|FD_EV_READY_R)) == 0)
		HA_ATOMIC_BTS(&fdtab[fd].state, FD_EV_READY_R_BIT);
}

/* Report that FD <fd> may send again without polling but only if its not
 * active yet. This is in order to speculatively try to enable I/Os when it's
 * highly likely that these will succeed, but without interfering with polling.
 */
static inline void fd_cond_send(const int fd)
{
	if ((fdtab[fd].state & (FD_EV_ACTIVE_W|FD_EV_READY_W)) == 0)
		HA_ATOMIC_BTS(&fdtab[fd].state, FD_EV_READY_W_BIT);
}

/* Report that FD <fd> may receive and send without polling. Used at FD
 * initialization.
 */
static inline void fd_may_both(const int fd)
{
	HA_ATOMIC_OR(&fdtab[fd].state, FD_EV_READY_RW);
}

/* Report that FD <fd> cannot send anymore without polling (EAGAIN detected). */
static inline void fd_cant_send(const int fd)
{
	/* removing ready never changes polled status */
	if (!(fdtab[fd].state & FD_EV_READY_W) ||
	    !HA_ATOMIC_BTR(&fdtab[fd].state, FD_EV_READY_W_BIT))
		return;
}

/* Report that FD <fd> may send again without polling (EAGAIN not detected). */
static inline void fd_may_send(const int fd)
{
	/* marking ready never changes polled status */
	if ((fdtab[fd].state & FD_EV_READY_W) ||
	    HA_ATOMIC_BTS(&fdtab[fd].state, FD_EV_READY_W_BIT))
		return;
}

/* Prepare FD <fd> to try to receive */
static inline void fd_want_recv(int fd)
{
	if ((fdtab[fd].state & FD_EV_ACTIVE_R) ||
	    HA_ATOMIC_BTS(&fdtab[fd].state, FD_EV_ACTIVE_R_BIT))
		return;
	updt_fd_polling(fd);
}

/* Prepare FD <fd> to try to receive, and only create update if fd_updt exists
 * (essentially for receivers during early boot).
 */
static inline void fd_want_recv_safe(int fd)
{
	if ((fdtab[fd].state & FD_EV_ACTIVE_R) ||
	    HA_ATOMIC_BTS(&fdtab[fd].state, FD_EV_ACTIVE_R_BIT))
		return;
	if (fd_updt)
		updt_fd_polling(fd);
}

/* Prepare FD <fd> to try to send */
static inline void fd_want_send(int fd)
{
	if ((fdtab[fd].state & FD_EV_ACTIVE_W) ||
	    HA_ATOMIC_BTS(&fdtab[fd].state, FD_EV_ACTIVE_W_BIT))
		return;
	updt_fd_polling(fd);
}

/* Set the fd as currently running on the current thread.
 * Returns 0 if all goes well, or -1 if we no longer own the fd, and should
 * do nothing with it.
 */
static inline int fd_set_running(int fd)
{
#ifndef HA_HAVE_CAS_DW
	HA_RWLOCK_RDLOCK(OTHER_LOCK, &fd_mig_lock);
	if (!(fdtab[fd].thread_mask & tid_bit)) {
		HA_RWLOCK_RDUNLOCK(OTHER_LOCK, &fd_mig_lock);
		return -1;
	}
	_HA_ATOMIC_OR(&fdtab[fd].running_mask, tid_bit);
	HA_RWLOCK_RDUNLOCK(OTHER_LOCK, &fd_mig_lock);
	return 0;
#else
	unsigned long old_masks[2];
	unsigned long new_masks[2];
	old_masks[0] = fdtab[fd].running_mask;
	old_masks[1] = fdtab[fd].thread_mask;
	do {
		if (!(old_masks[1] & tid_bit))
			return -1;
		new_masks[0] = fdtab[fd].running_mask | tid_bit;
		new_masks[1] = old_masks[1];

	} while (!(HA_ATOMIC_DWCAS(&fdtab[fd].running_mask, &old_masks, &new_masks)));
	return 0;
#endif
}

/* remove tid_bit from the fd's running mask and returns the bits that remain
 * after the atomic operation.
 */
static inline long fd_clr_running(int fd)
{
	return _HA_ATOMIC_AND_FETCH(&fdtab[fd].running_mask, ~tid_bit);
}

/* Update events seen for FD <fd> and its state if needed. This should be
 * called by the poller, passing FD_EV_*_{R,W,RW} in <evts>. FD_EV_ERR_*
 * doesn't need to also pass FD_EV_SHUT_*, it's implied. ERR and SHUT are
 * allowed to be reported regardless of R/W readiness.
 */
static inline void fd_update_events(int fd, uint evts)
{
	unsigned long locked = atleast2(fdtab[fd].thread_mask);
	uint old, new;
	uint new_flags, must_stop;

	new_flags =
	      ((evts & FD_EV_READY_R) ? FD_POLL_IN  : 0) |
	      ((evts & FD_EV_READY_W) ? FD_POLL_OUT : 0) |
	      ((evts & FD_EV_SHUT_R)  ? FD_POLL_HUP : 0) |
	      ((evts & FD_EV_ERR_RW)  ? FD_POLL_ERR : 0);

	/* SHUTW reported while FD was active for writes is an error */
	if ((fdtab[fd].state & FD_EV_ACTIVE_W) && (evts & FD_EV_SHUT_W))
		new_flags |= FD_POLL_ERR;

	/* compute the inactive events reported late that must be stopped */
	must_stop = 0;
	if (unlikely(!fd_active(fd))) {
		/* both sides stopped */
		must_stop = FD_POLL_IN | FD_POLL_OUT;
	}
	else if (unlikely(!fd_recv_active(fd) && (evts & (FD_EV_READY_R | FD_EV_SHUT_R | FD_EV_ERR_RW)))) {
		/* only send remains */
		must_stop = FD_POLL_IN;
	}
	else if (unlikely(!fd_send_active(fd) && (evts & (FD_EV_READY_W | FD_EV_SHUT_W | FD_EV_ERR_RW)))) {
		/* only recv remains */
		must_stop = FD_POLL_OUT;
	}

	old = fdtab[fd].state;
	new = (old & ~FD_POLL_UPDT_MASK) | new_flags;

	if (unlikely(locked)) {
		/* Locked FDs (those with more than 2 threads) are atomically updated */
		while (unlikely(new != old && !_HA_ATOMIC_CAS(&fdtab[fd].state, &old, new)))
			new = (old & ~FD_POLL_UPDT_MASK) | new_flags;
	} else {
		if (new != old)
			fdtab[fd].state = new;
	}

	if (fdtab[fd].state & (FD_POLL_IN | FD_POLL_HUP | FD_POLL_ERR))
		fd_may_recv(fd);

	if (fdtab[fd].state & (FD_POLL_OUT | FD_POLL_ERR))
		fd_may_send(fd);

	if (fdtab[fd].iocb && fd_active(fd)) {
		if (fd_set_running(fd) == -1)
			return;
		fdtab[fd].iocb(fd);
		if ((fdtab[fd].running_mask & tid_bit) &&
		    fd_clr_running(fd) == 0 && !fdtab[fd].thread_mask)
			_fd_delete_orphan(fd);
	}

	/* we had to stop this FD and it still must be stopped after the I/O
	 * cb's changes, so let's program an update for this.
	 */
	if (must_stop && !(fdtab[fd].update_mask & tid_bit)) {
		if (((must_stop & FD_POLL_IN)  && !fd_recv_active(fd)) ||
		    ((must_stop & FD_POLL_OUT) && !fd_send_active(fd)))
			if (!HA_ATOMIC_BTS(&fdtab[fd].update_mask, tid))
				fd_updt[fd_nbupdt++] = fd;
	}

	ti->flags &= ~TI_FL_STUCK; // this thread is still running
}

/* Prepares <fd> for being polled */
static inline void fd_insert(int fd, void *owner, void (*iocb)(int fd), unsigned long thread_mask)
{
	extern void sock_conn_iocb(int);

	fdtab[fd].owner = owner;
	fdtab[fd].iocb = iocb;
	fdtab[fd].state = 0;
#ifdef DEBUG_FD
	fdtab[fd].event_count = 0;
#endif

	/* conn_fd_handler should support edge-triggered FDs */
	if ((global.tune.options & GTUNE_FD_ET) && fdtab[fd].iocb == sock_conn_iocb)
		fdtab[fd].state |= FD_ET_POSSIBLE;

	fdtab[fd].thread_mask = thread_mask;
	/* note: do not reset polled_mask here as it indicates which poller
	 * still knows this FD from a possible previous round.
	 */

	/* the two directions are ready until proven otherwise */
	fd_may_both(fd);
	_HA_ATOMIC_INC(&ha_used_fds);
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
	_HA_ATOMIC_OR(&evts[fd / (8*sizeof(*evts))], 1U << (fd & (8*sizeof(*evts) - 1)));
}

static inline void hap_fd_clr(int fd, unsigned int *evts)
{
	_HA_ATOMIC_AND(&evts[fd / (8*sizeof(*evts))], ~(1U << (fd & (8*sizeof(*evts) - 1))));
}

static inline unsigned int hap_fd_isset(int fd, unsigned int *evts)
{
	return evts[fd / (8*sizeof(*evts))] & (1U << (fd & (8*sizeof(*evts) - 1)));
}

static inline void wake_thread(int tid)
{
	char c = 'c';

	DISGUISE(write(poller_wr_pipe[tid], &c, 1));
}


#endif /* _HAPROXY_FD_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
