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
#include <haproxy/api.h>
#include <haproxy/atomic.h>
#include <haproxy/fd-t.h>
#include <haproxy/global.h>
#include <haproxy/thread.h>

/* public variables */

extern struct poller cur_poller; /* the current poller */
extern int nbpollers;
extern struct poller pollers[MAX_POLLERS];   /* all registered pollers */
extern struct fdtab *fdtab;             /* array of all the file descriptors */
extern struct fdinfo *fdinfo;           /* less-often used infos for file descriptors */
extern int totalconn;                   /* total # of terminated sessions */
extern int actconn;                     /* # of active sessions */

extern volatile struct fdlist update_list[MAX_TGROUPS];
extern struct polled_mask *polled_mask;

extern THREAD_LOCAL int *fd_updt;  // FD updates list
extern THREAD_LOCAL int fd_nbupdt; // number of updates in the list
extern THREAD_LOCAL int fd_highest;// highest FD known by the current thread

extern int poller_wr_pipe[MAX_THREADS];

extern volatile int ha_used_fds; // Number of FDs we're currently using

/* Deletes an FD from the fdsets.
 * The file descriptor is also closed.
 */
void fd_delete(int fd);
void _fd_delete_orphan(int fd);

/* makes the new fd non-blocking and clears all other O_* flags;
 * this is meant to be used on new FDs. Returns -1 on failure.
 */
int fd_set_nonblock(int fd);

/* makes the fd close-on-exec; returns -1 on failure. */
int fd_set_cloexec(int fd);

/* Migrate a FD to a new thread <new_tid>. */
void fd_migrate_on(int fd, uint new_tid);

/*
 * Take over a FD belonging to another thread.
 * Returns 0 on success, and -1 on failure.
 */
int fd_takeover(int fd, void *expected_owner);

ssize_t fd_write_frag_line(int fd, size_t maxlen, const struct ist pfx[], size_t npfx, const struct ist msg[], size_t nmsg, int nl);

/* close all FDs starting from <start> */
void my_closefrom(int start);

int compute_poll_timeout(int next);
void fd_leaving_poll(int wait_time, int status);

/* disable the specified poller */
void disable_poller(const char *poller_name);

void poller_pipe_io_handler(int fd);

/*
 * Initialize the pollers till the best one is found.
 * If none works, returns 0, otherwise 1.
 * The pollers register themselves just before main() is called.
 */
int init_pollers(void);

/*
 * Deinitialize the pollers.
 */
void deinit_pollers(void);

/*
 * Some pollers may lose their connection after a fork(). It may be necessary
 * to create initialize part of them again. Returns 0 in case of failure,
 * otherwise 1. The fork() function may be NULL if unused. In case of error,
 * the the current poller is destroyed and the caller is responsible for trying
 * another one by calling init_pollers() again.
 */
int fork_poller(void);

/*
 * Lists the known pollers on <out>.
 * Should be performed only before initialization.
 */
int list_pollers(FILE *out);

/*
 * Runs the polling loop
 */
void run_poller();

void fd_add_to_fd_list(volatile struct fdlist *list, int fd);
void fd_rm_from_fd_list(volatile struct fdlist *list, int fd);
void updt_fd_polling(const int fd);
int fd_update_events(int fd, uint evts);
void fd_reregister_all(int tgrp, ulong mask);

/* Called from the poller to acknowledge we read an entry from the global
 * update list, to remove our bit from the update_mask, and remove it from
 * the list if we were the last one.
 */
static inline void done_update_polling(int fd)
{
	unsigned long update_mask;

	update_mask = _HA_ATOMIC_AND_FETCH(&fdtab[fd].update_mask, ~ti->ltid_bit);
	while ((update_mask & _HA_ATOMIC_LOAD(&tg->threads_enabled)) == 0) {
		/* If we were the last one that had to update that entry, remove it from the list */
		fd_rm_from_fd_list(&update_list[tgid - 1], fd);
		update_mask = _HA_ATOMIC_LOAD(&fdtab[fd].update_mask);
		if ((update_mask & _HA_ATOMIC_LOAD(&tg->threads_enabled)) != 0) {
			/* Maybe it's been re-updated in the meanwhile, and we
			 * wrongly removed it from the list, if so, re-add it
			 */
			fd_add_to_fd_list(&update_list[tgid - 1], fd);
			update_mask = _HA_ATOMIC_LOAD(&fdtab[fd].update_mask);
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

/* returns the tgid from an fd (masks the refcount) */
static forceinline int fd_tgid(int fd)
{
	return _HA_ATOMIC_LOAD(&fdtab[fd].refc_tgid) & 0xFFFF;
}

/* Release a tgid previously taken by fd_grab_tgid() */
static forceinline void fd_drop_tgid(int fd)
{
	HA_ATOMIC_SUB(&fdtab[fd].refc_tgid, 0x10000);
}

/* Unlock a tgid currently locked by fd_lock_tgid(). This will effectively
 * allow threads from the FD's tgid to check the masks and manipulate the FD.
 */
static forceinline void fd_unlock_tgid(int fd)
{
	HA_ATOMIC_AND(&fdtab[fd].refc_tgid, 0xffff7fffU);
}

/* Switch the FD's TGID to the new value with a refcount of 1 and the lock bit
 * set. It doesn't care about the current TGID, except that it will wait for
 * the FD not to be already switching and having its refcount cleared. After
 * the function returns, the caller is free to manipulate the masks, and it
 * must call fd_unlock_tgid() to drop the lock, allowing threads from the
 * designated group to use the FD. Finally a call to fd_drop_tgid() will be
 * needed to drop the reference.
 */
static inline void fd_lock_tgid(int fd, uint desired_tgid)
{
	uint old;

	BUG_ON(!desired_tgid);

	old = tgid;  // assume we start from the caller's tgid
	desired_tgid |= 0x18000; // refcount=1, lock bit=1.

	while (1) {
		old &= 0x7fff; // expect no lock and refcount==0
		if (_HA_ATOMIC_CAS(&fdtab[fd].refc_tgid, &old, desired_tgid))
			break;
		__ha_cpu_relax();
	}
}

/* Grab a reference to the FD's TGID, and return the tgid. Note that a TGID of
 * zero indicates the FD was closed, thus also fails (i.e. no need to drop it).
 * On non-zero (success), the caller must release it using fd_drop_tgid().
 */
static inline uint fd_take_tgid(int fd)
{
	uint old;

	old = _HA_ATOMIC_FETCH_ADD(&fdtab[fd].refc_tgid, 0x10000) & 0xffff;
	if (likely(old))
		return old;
	HA_ATOMIC_SUB(&fdtab[fd].refc_tgid, 0x10000);
	return 0;
}

/* Reset a tgid without affecting the refcount */
static forceinline void fd_reset_tgid(int fd)
{
	HA_ATOMIC_AND(&fdtab[fd].refc_tgid, 0xffff0000U);
}

/* Try to grab a reference to the FD's TGID, but only if it matches the
 * requested one (i.e. it succeeds with TGID refcnt held, or fails). Note that
 * a TGID of zero indicates the FD was closed, thus also fails. It returns
 * non-zero on success, in which case the caller must then release it using
 * fd_drop_tgid(), or zero on failure. The function is optimized for use
 * when it's likely that the tgid matches the desired one as it's by far
 * the most common.
 */
static inline uint fd_grab_tgid(int fd, uint desired_tgid)
{
	uint old;

	old = _HA_ATOMIC_FETCH_ADD(&fdtab[fd].refc_tgid, 0x10000) & 0xffff;
	if (likely(old == desired_tgid))
		return 1;
	HA_ATOMIC_SUB(&fdtab[fd].refc_tgid, 0x10000);
	return 0;
}

/* Set the FD's TGID to the new value with a refcount of 1, waiting for the
 * current refcount to become 0, to cover the rare possibly that a late
 * competing thread would be touching the tgid or the running mask in parallel.
 * The caller must call fd_drop_tgid() once done.
 */
static inline void fd_claim_tgid(int fd, uint desired_tgid)
{
	uint old;

	BUG_ON(!desired_tgid);

	desired_tgid += 0x10000; // refcount=1
	old = 0;                 // assume unused (most likely)
	while (1) {
		if (_HA_ATOMIC_CAS(&fdtab[fd].refc_tgid, &old, desired_tgid))
			break;
		__ha_cpu_relax();
		old &= 0x7fff;   // keep only the tgid and drop the lock
	}
}

/* atomically read the running mask if the tgid matches, or returns zero if it
 * does not match. This is meant for use in code paths where the bit is expected
 * to be present and will be sufficient to protect against a short-term group
 * migration (e.g. takss and return from iocb).
 */
static inline ulong fd_get_running(int fd, uint desired_tgid)
{
	ulong ret = 0;
	uint old;

	/* TODO: may also be checked using an atomic double-load from a DWCAS
	 * on compatible architectures, which wouldn't require to modify nor
	 * restore the original value.
	 */
	old = _HA_ATOMIC_ADD_FETCH(&fdtab[fd].refc_tgid, 0x10000);
	if (likely((old & 0xffff) == desired_tgid))
		ret = _HA_ATOMIC_LOAD(&fdtab[fd].running_mask);
	_HA_ATOMIC_SUB(&fdtab[fd].refc_tgid, 0x10000);
	return ret;
}

/* remove tid_bit from the fd's running mask and returns the value before the
 * atomic operation, so that the caller can know if it was present.
 */
static inline long fd_clr_running(int fd)
{
	return _HA_ATOMIC_FETCH_AND(&fdtab[fd].running_mask, ~ti->ltid_bit);
}

/* Prepares <fd> for being polled on all permitted threads of this group ID
 * (these will then be refined to only cover running ones).
*/
static inline void fd_insert(int fd, void *owner, void (*iocb)(int fd), int tgid, unsigned long thread_mask)
{
	extern void sock_conn_iocb(int);
	int newstate;

	/* conn_fd_handler should support edge-triggered FDs */
	newstate = 0;
	if ((global.tune.options & GTUNE_FD_ET) && iocb == sock_conn_iocb)
		newstate |= FD_ET_POSSIBLE;

	/* We must update fd_highest to reflect the highest known FD for this
	 * thread. It's important to note that it's not necessarily the highest
	 * FD the thread will see, it's the highest FD that was inserted by
	 * this thread or by the main thread. The purpose is essentially to
	 * let all threads know the highest known FD at boot, that will be
	 * cloned into each thread, in order to limit the work range for init
	 * functions such as fork_poller() and fd_reregister_all(). Keeping the
	 * value thread-local substantially limits the cost, since after a few
	 * thousand calls the value will just stop changing.
	 */
	if (unlikely(fd > fd_highest))
		fd_highest = fd;

	/* This must never happen and would definitely indicate a bug, in
	 * addition to overwriting some unexpected memory areas.
	 */
	BUG_ON(fd < 0);
	BUG_ON(fd >= global.maxsock);
	BUG_ON(fdtab[fd].owner != NULL);
	BUG_ON(fdtab[fd].state != 0);
	BUG_ON(tgid < 1 || tgid > MAX_TGROUPS);

	thread_mask &= tg->threads_enabled;
	BUG_ON(thread_mask == 0);

	fd_claim_tgid(fd, tgid);

	BUG_ON(fdtab[fd].running_mask);

	fdtab[fd].owner = owner;
	fdtab[fd].iocb = iocb;
	fdtab[fd].state = newstate;
	fdtab[fd].thread_mask = thread_mask;

	/* just for debugging: how many times taken over since last fd_insert() */
	fdtab[fd].nb_takeover = 0;

	fd_drop_tgid(fd);

#ifdef DEBUG_FD
	fdtab[fd].event_count = 0;
#endif

	/* note: do not reset polled_mask here as it indicates which poller
	 * still knows this FD from a possible previous round.
	 */

	/* the two directions are ready until proven otherwise */
	fd_may_both(fd);
	_HA_ATOMIC_INC(&ha_used_fds);
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

/* send a wake-up event to this thread, only if it's asleep and not notified yet */
static inline void wake_thread(int thr)
{
	struct thread_ctx *ctx = &ha_thread_ctx[thr];

	if ((_HA_ATOMIC_FETCH_OR(&ctx->flags, TH_FL_NOTIFIED) & (TH_FL_SLEEPING|TH_FL_NOTIFIED)) == TH_FL_SLEEPING) {
		char c = 'c';
		DISGUISE(write(poller_wr_pipe[thr], &c, 1));
	}
}


#endif /* _HAPROXY_FD_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
