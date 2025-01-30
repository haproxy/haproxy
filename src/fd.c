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
 * There is no direct link between the FD and the updates list. There is only a
 * bit in the fdtab[] to indicate than a file descriptor is already present in
 * the updates list. Once an fd is present in the updates list, it will have to
 * be considered even if its changes are reverted in the middle or if the fd is
 * replaced.
 *
 * The event state for an FD, as found in fdtab[].state, is maintained for each
 * direction. The state field is built this way, with R bits in the low nibble
 * and W bits in the high nibble for ease of access and debugging :
 *
 *               7    6    5    4   3    2    1    0
 *             [ 0 |  0 | RW | AW | 0 |  0 | RR | AR ]
 *
 *                   A* = active     *R = read
 *                   R* = ready      *W = write
 *
 * An FD is marked "active" when there is a desire to use it.
 * An FD is marked "ready" when it has not faced a new EAGAIN since last wake-up
 * (it is a cache of the last EAGAIN regardless of polling changes). Each poller
 * has its own "polled" state for the same fd, as stored in the polled_mask.
 *
 * We have 4 possible states for each direction based on these 2 flags :
 *
 *   +---+---+----------+---------------------------------------------+
 *   | R | A | State    | Description                                 |
 *   +---+---+----------+---------------------------------------------+
 *   | 0 | 0 | DISABLED | No activity desired, not ready.             |
 *   | 0 | 1 | ACTIVE   | Activity desired.                           |
 *   | 1 | 0 | STOPPED  | End of activity.                            |
 *   | 1 | 1 | READY    | Activity desired and reported.              |
 *   +---+---+----------+---------------------------------------------+
 *
 * The transitions are pretty simple :
 *   - fd_want_*() : set flag A
 *   - fd_stop_*() : clear flag A
 *   - fd_cant_*() : clear flag R (when facing EAGAIN)
 *   - fd_may_*()  : set flag R (upon return from poll())
 *
 * Each poller then computes its own polled state :
 *     if (A) { if (!R) P := 1 } else { P := 0 }
 *
 * The state transitions look like the diagram below.
 *
 *     may  +----------+
 *     ,----| DISABLED |    (READY=0, ACTIVE=0)
 *     |    +----------+
 *     |  want |  ^
 *     |       |  |
 *     |       v  | stop
 *     |    +----------+
 *     |    |  ACTIVE  |    (READY=0, ACTIVE=1)
 *     |    +----------+
 *     |       |  ^
 *     |  may  |  |
 *     |       v  | EAGAIN (can't)
 *     |     +--------+
 *     |     | READY  |     (READY=1, ACTIVE=1)
 *     |     +--------+
 *     |  stop |  ^
 *     |       |  |
 *     |       v  | want
 *     |    +---------+
 *     `--->| STOPPED |     (READY=1, ACTIVE=0)
 *          +---------+
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/uio.h>

#if defined(USE_POLL)
#include <poll.h>
#endif
#include <errno.h>

#include <haproxy/api.h>
#include <haproxy/activity.h>
#include <haproxy/cfgparse.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/log.h>
#include <haproxy/port_range.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>


struct fdtab *fdtab             __read_mostly = NULL;  /* array of all the file descriptors */
struct polled_mask *polled_mask __read_mostly = NULL;  /* Array for the polled_mask of each fd */
struct fdinfo *fdinfo           __read_mostly = NULL;  /* less-often used infos for file descriptors */
int totalconn;                  /* total # of terminated sessions */
int actconn;                    /* # of active sessions */

struct poller pollers[MAX_POLLERS] __read_mostly;
struct poller cur_poller           __read_mostly;
int nbpollers = 0;

volatile struct fdlist update_list[MAX_TGROUPS]; // Global update list

THREAD_LOCAL int *fd_updt  = NULL;  // FD updates list
THREAD_LOCAL int  fd_nbupdt = 0;   // number of updates in the list
THREAD_LOCAL int  fd_highest = -1; // highest FD known by the current thread
THREAD_LOCAL int poller_rd_pipe = -1; // Pipe to wake the thread
int poller_wr_pipe[MAX_THREADS] __read_mostly; // Pipe to wake the threads

volatile int ha_used_fds = 0; // Number of FD we're currently using
static struct fdtab *fdtab_addr;  /* address of the allocated area containing fdtab */

/* adds fd <fd> to fd list <list> if it was not yet in it */
void fd_add_to_fd_list(volatile struct fdlist *list, int fd)
{
	int next;
	int new;
	int old;
	int last;

redo_next:
	next = HA_ATOMIC_LOAD(&fdtab[fd].update.next);
	/* Check that we're not already in the cache, and if not, lock us. */
	if (next > -2)
		goto done;
	if (next == -2)
		goto redo_next;
	if (!_HA_ATOMIC_CAS(&fdtab[fd].update.next, &next, -2))
		goto redo_next;
	__ha_barrier_atomic_store();

	new = fd;
redo_last:
	/* First, insert in the linked list */
	last = list->last;
	old = -1;

	fdtab[fd].update.prev = -2;
	/* Make sure the "prev" store is visible before we update the last entry */
	__ha_barrier_store();

	if (unlikely(last == -1)) {
		/* list is empty, try to add ourselves alone so that list->last=fd */
		if (unlikely(!_HA_ATOMIC_CAS(&list->last, &old, new)))
			    goto redo_last;

		/* list->first was necessary -1, we're guaranteed to be alone here */
		list->first = fd;
	} else {
		/* adding ourselves past the last element
		 * The CAS will only succeed if its next is -1,
		 * which means it's in the cache, and the last element.
		 */
		if (unlikely(!_HA_ATOMIC_CAS(&fdtab[last].update.next, &old, new)))
			goto redo_last;

		/* Then, update the last entry */
		list->last = fd;
	}
	__ha_barrier_store();
	/* since we're alone at the end of the list and still locked(-2),
	 * we know no one tried to add past us. Mark the end of list.
	 */
	fdtab[fd].update.prev = last;
	fdtab[fd].update.next = -1;
	__ha_barrier_store();
done:
	return;
}

/* removes fd <fd> from fd list <list> */
void fd_rm_from_fd_list(volatile struct fdlist *list, int fd)
{
#if defined(HA_HAVE_CAS_DW) || defined(HA_CAS_IS_8B)
	volatile union {
		struct fdlist_entry ent;
		uint64_t u64;
		uint32_t u32[2];
	} cur_list, next_list;
#endif
	int old;
	int new = -2;
	int prev;
	int next;
	int last;
lock_self:
#if (defined(HA_CAS_IS_8B) || defined(HA_HAVE_CAS_DW))
	next_list.ent.next = next_list.ent.prev = -2;
	cur_list.ent = *(volatile typeof(fdtab->update)*)&fdtab[fd].update;
	/* First, attempt to lock our own entries */
	do {
		/* The FD is not in the FD cache, give up */
		if (unlikely(cur_list.ent.next <= -3))
			return;
		if (unlikely(cur_list.ent.prev == -2 || cur_list.ent.next == -2))
			goto lock_self;
	} while (
#ifdef HA_CAS_IS_8B
		 unlikely(!_HA_ATOMIC_CAS(((uint64_t *)&fdtab[fd].update), (uint64_t *)&cur_list.u64, next_list.u64))
#else
		 unlikely(!_HA_ATOMIC_DWCAS(((long *)&fdtab[fd].update), (uint32_t *)&cur_list.u32, (const uint32_t *)&next_list.u32))
#endif
	    );
	next = cur_list.ent.next;
	prev = cur_list.ent.prev;

#else
lock_self_next:
	next = HA_ATOMIC_LOAD(&fdtab[fd].update.next);
	if (next == -2)
		goto lock_self_next;
	if (next <= -3)
		goto done;
	if (unlikely(!_HA_ATOMIC_CAS(&fdtab[fd].update.next, &next, -2)))
		goto lock_self_next;
lock_self_prev:
	prev = HA_ATOMIC_LOAD(&fdtab[fd].update.prev);
	if (prev == -2)
		goto lock_self_prev;
	if (unlikely(!_HA_ATOMIC_CAS(&fdtab[fd].update.prev, &prev, -2)))
		goto lock_self_prev;
#endif
	__ha_barrier_atomic_store();

	/* Now, lock the entries of our neighbours */
	if (likely(prev != -1)) {
redo_prev:
		old = fd;

		if (unlikely(!_HA_ATOMIC_CAS(&fdtab[prev].update.next, &old, new))) {
			if (unlikely(old == -2)) {
				/* Neighbour already locked, give up and
				 * retry again once he's done
				 */
				fdtab[fd].update.prev = prev;
				__ha_barrier_store();
				fdtab[fd].update.next = next;
				__ha_barrier_store();
				goto lock_self;
			}
			goto redo_prev;
		}
	}
	if (likely(next != -1)) {
redo_next:
		old = fd;
		if (unlikely(!_HA_ATOMIC_CAS(&fdtab[next].update.prev, &old, new))) {
			if (unlikely(old == -2)) {
				/* Neighbour already locked, give up and
				 * retry again once he's done
				 */
				if (prev != -1) {
					fdtab[prev].update.next = fd;
					__ha_barrier_store();
				}
				fdtab[fd].update.prev = prev;
				__ha_barrier_store();
				fdtab[fd].update.next = next;
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
	while (unlikely(last == fd && (!_HA_ATOMIC_CAS(&list->last, &last, prev))))
		__ha_compiler_barrier();
	/* Make sure we let other threads know we're no longer in cache,
	 * before releasing our neighbours.
	 */
	__ha_barrier_store();
	if (likely(prev != -1))
		fdtab[prev].update.next = next;
	__ha_barrier_store();
	if (likely(next != -1))
		fdtab[next].update.prev = prev;
	__ha_barrier_store();
	/* Ok, now we're out of the fd cache */
	fdtab[fd].update.next = -(next + 4);
	__ha_barrier_store();
done:
	return;
}

/* deletes the FD once nobody uses it anymore, as detected by the caller by its
 * thread_mask being zero and its running mask turning to zero. There is no
 * protection against concurrent accesses, it's up to the caller to make sure
 * only the last thread will call it. If called under isolation, it is safe to
 * call this from another group than the FD's. This is only for internal use,
 * please use fd_delete() instead.
 */
void _fd_delete_orphan(int fd)
{
	int tgrp = fd_tgid(fd);
	uint fd_disown;

	fd_disown = fdtab[fd].state & FD_DISOWN;
	if (fdtab[fd].state & FD_LINGER_RISK) {
		/* this is generally set when connecting to servers */
		DISGUISE(setsockopt(fd, SOL_SOCKET, SO_LINGER,
			   (struct linger *) &nolinger, sizeof(struct linger)));
	}

	/* It's expected that a close() will result in the FD disappearing from
	 * pollers, but some pollers may have some internal bookkeeping to be
	 * done prior to the call (e.g. remove references from internal tables).
	 */
	if (cur_poller.clo)
		cur_poller.clo(fd);

	/* now we're about to reset some of this FD's fields. We don't want
	 * anyone to grab it anymore and we need to make sure those which could
	 * possibly have stumbled upon it right now are leaving before we
	 * proceed. This is done in two steps. First we reset the tgid so that
	 * fd_take_tgid() and fd_grab_tgid() fail, then we wait for existing
	 * ref counts to drop. Past this point we're alone dealing with the
	 * FD's thead/running/update/polled masks.
	 */
	fd_reset_tgid(fd);

	while (_HA_ATOMIC_LOAD(&fdtab[fd].refc_tgid) != 0) // refc==0 ?
		__ha_cpu_relax();

	/* we don't want this FD anymore in the global list */
	fd_rm_from_fd_list(&update_list[tgrp - 1], fd);

	/* no more updates on this FD are relevant anymore */
	HA_ATOMIC_STORE(&fdtab[fd].update_mask, 0);
	if (fd_nbupdt > 0 && fd_updt[fd_nbupdt - 1] == fd)
		fd_nbupdt--;

	port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
	polled_mask[fd].poll_recv = polled_mask[fd].poll_send = 0;

	fdtab[fd].state = 0;

#ifdef DEBUG_FD
	fdtab[fd].event_count = 0;
#endif
	fdinfo[fd].port_range = NULL;
	fdtab[fd].owner = NULL;

	/* perform the close() call last as it's what unlocks the instant reuse
	 * of this FD by any other thread.
	 */
	if (!fd_disown) {
		fdtab[fd].generation++;
		close(fd);
	}
	_HA_ATOMIC_DEC(&ha_used_fds);
}

/* Deletes an FD from the fdsets. The file descriptor is also closed, possibly
 * asynchronously. It is safe to call it from another thread from the same
 * group as the FD's or from a thread from a different group. However if called
 * from a thread from another group, there is an extra cost involved because
 * the operation is performed under thread isolation, so doing so must be
 * reserved for ultra-rare cases (e.g. stopping a listener).
 */
void fd_delete(int fd)
{
	/* This must never happen and would definitely indicate a bug, in
	 * addition to overwriting some unexpected memory areas.
	 */
	BUG_ON(fd < 0 || fd >= global.maxsock);

	/* NOTE: The master when going into reexec mode re-closes all FDs after
	 * they were already dispatched. But we know we didn't start the polling
	 * threads so we can still close them. The masks will probably not match
	 * however so we force the value and erase the refcount if any.
	 */
	if (unlikely(global.mode & MODE_STARTING))
		fdtab[fd].refc_tgid = ti->tgid;

	/* the tgid cannot change before a complete close so we should never
	 * face the situation where we try to close an fd that was reassigned.
	 * However there is one corner case where this happens, it's when an
	 * attempt to pause a listener fails (e.g. abns), leaving the listener
	 * in fault state and it is forcefully stopped. This needs to be done
	 * under isolation, and it's quite rare (i.e. once per such FD per
	 * process). Since we'll be isolated we can clear the thread mask and
	 * close the FD ourselves.
	 */
	if (unlikely(fd_tgid(fd) != ti->tgid)) {
		int must_isolate = !thread_isolated() && !(global.mode & MODE_STOPPING);

		if (must_isolate)
			thread_isolate();

		HA_ATOMIC_STORE(&fdtab[fd].thread_mask, 0);
		HA_ATOMIC_STORE(&fdtab[fd].running_mask, 0);
		_fd_delete_orphan(fd);

		if (must_isolate)
			thread_release();
		return;
	}

	/* we must postpone removal of an FD that may currently be in use
	 * by another thread. This can happen in the following two situations:
	 *   - after a takeover, the owning thread closes the connection but
	 *     the previous one just woke up from the poller and entered
	 *     the FD handler iocb. That thread holds an entry in running_mask
	 *     and requires removal protection.
	 *   - multiple threads are accepting connections on a listener, and
	 *     one of them (or even an separate one) decides to unbind the
	 *     listener under the listener's lock while other ones still hold
	 *     the running bit.
	 * In both situations the FD is marked as unused (thread_mask = 0) and
	 * will not take new bits in its running_mask so we have the guarantee
	 * that the last thread eliminating running_mask is the one allowed to
	 * safely delete the FD. Most of the time it will be the current thread.
	 * We still need to set and check the one-shot flag FD_MUST_CLOSE
	 * to take care of the rare cases where a thread wakes up on late I/O
	 * before the thread_mask is zero, and sets its bit in the running_mask
	 * just after the current thread finishes clearing its own bit, hence
	 * the two threads see themselves as last ones (which they really are).
	 */

	HA_ATOMIC_OR(&fdtab[fd].running_mask, ti->ltid_bit);
	HA_ATOMIC_OR(&fdtab[fd].state, FD_MUST_CLOSE);
	HA_ATOMIC_STORE(&fdtab[fd].thread_mask, 0);
	if (fd_clr_running(fd) == ti->ltid_bit) {
		if (HA_ATOMIC_BTR(&fdtab[fd].state, FD_MUST_CLOSE_BIT)) {
			_fd_delete_orphan(fd);
		}
	}
}

/* makes the new fd non-blocking and clears all other O_* flags; this is meant
 * to be used on new FDs. Returns -1 on failure. The result is disguised at the
 * end because some callers need to be able to ignore it regardless of the libc
 * attributes.
 */
int fd_set_nonblock(int fd)
{
	int ret = fcntl(fd, F_SETFL, O_NONBLOCK);

	return DISGUISE(ret);
}

/* sets the close-on-exec flag on fd; returns -1 on failure. The result is
 * disguised at the end because some callers need to be able to ignore it
 * regardless of the libc attributes.
 */
int fd_set_cloexec(int fd)
{
	int flags, ret;

	flags = fcntl(fd, F_GETFD);
	flags |= FD_CLOEXEC;
	ret = fcntl(fd, F_SETFD, flags);
	return DISGUISE(ret);
}

/* Migrate a FD to a new thread <new_tid>. It is explicitly permitted to
 * migrate to another thread group, the function takes the necessary locking
 * for this. It is even permitted to migrate from a foreign group to another,
 * but the calling thread must be certain that the FD is not about to close
 * when doing so, reason why it is highly recommended that only one of the
 * FD's owners performs this operation. The polling is completely disabled.
 * The operation never fails.
 */
void fd_migrate_on(int fd, uint new_tid)
{
	struct thread_info *new_ti = &ha_thread_info[new_tid];

	/* we must be alone to work on this idle FD. If not, it means that its
	 * poller is currently waking up and is about to use it, likely to
	 * close it on shut/error, but maybe also to process any unexpectedly
	 * pending data. It's also possible that the FD was closed and
	 * reassigned to another thread group, so let's be careful.
	 */
	fd_lock_tgid(fd, new_ti->tgid);

	/* now we have exclusive access to it. From now FD belongs to tid_bit
	 * for this tgid.
	 */
	HA_ATOMIC_STORE(&fdtab[fd].thread_mask, new_ti->ltid_bit);

	/* Make sure the FD doesn't have the active bit. It is possible that
	 * the fd is polled by the thread that used to own it, the new thread
	 * is supposed to call subscribe() later, to activate polling.
	 */
	fd_stop_both(fd);

	/* we're done with it. As soon as we unlock it, other threads from the
	 * target group can manipulate it. However it may only disappear once
	 * we drop the reference.
	 */
	fd_unlock_tgid(fd);
	fd_drop_tgid(fd);
}

/*
 * Take over a FD belonging to another thread.
 * unexpected_conn is the expected owner of the fd.
 * Returns 0 on success, and -1 on failure.
 */
int fd_takeover(int fd, void *expected_owner)
{
	unsigned long old;

	/* protect ourself against a delete then an insert for the same fd,
	 * if it happens, then the owner will no longer be the expected
	 * connection.
	 */
	if (fdtab[fd].owner != expected_owner)
		return -1;

	/* we must be alone to work on this idle FD. If not, it means that its
	 * poller is currently waking up and is about to use it, likely to
	 * close it on shut/error, but maybe also to process any unexpectedly
	 * pending data. It's also possible that the FD was closed and
	 * reassigned to another thread group, so let's be careful.
	 */
	if (unlikely(!fd_grab_tgid(fd, ti->tgid)))
		return -1;

	old = 0;
	if (!HA_ATOMIC_CAS(&fdtab[fd].running_mask, &old, ti->ltid_bit)) {
		fd_drop_tgid(fd);
		return -1;
	}

	/* success, from now on it's ours */
	HA_ATOMIC_STORE(&fdtab[fd].thread_mask, ti->ltid_bit);

	/* Make sure the FD doesn't have the active bit. It is possible that
	 * the fd is polled by the thread that used to own it, the new thread
	 * is supposed to call subscribe() later, to activate polling.
	 */
	fd_stop_recv(fd);

	/* essentially for debugging */
	fdtab[fd].nb_takeover++;

	/* we're done with it */
	HA_ATOMIC_AND(&fdtab[fd].running_mask, ~ti->ltid_bit);

	/* no more changes planned */
	fd_drop_tgid(fd);
	return 0;
}

void updt_fd_polling(const int fd)
{
	uint tgrp = fd_take_tgid(fd);

	/* closed ? may happen */
	if (!tgrp)
		return;

	if (unlikely(tgrp != tgid && tgrp <= MAX_TGROUPS)) {
		/* Hmmm delivered an update for another group... That may
		 * happen on suspend/resume of a listener for example when
		 * the FD was not even marked for running. Let's broadcast
		 * the update.
		 */
		unsigned long update_mask = fdtab[fd].update_mask;
		int thr;

		while (!_HA_ATOMIC_CAS(&fdtab[fd].update_mask, &update_mask,
		                       _HA_ATOMIC_LOAD(&ha_tgroup_info[tgrp - 1].threads_enabled)))
			__ha_cpu_relax();

		fd_add_to_fd_list(&update_list[tgrp - 1], fd);

		thr = one_among_mask(fdtab[fd].thread_mask & ha_tgroup_info[tgrp - 1].threads_enabled,
		                     statistical_prng_range(ha_tgroup_info[tgrp - 1].count));
		thr += ha_tgroup_info[tgrp - 1].base;
		wake_thread(thr);

		fd_drop_tgid(fd);
		return;
	}

	fd_drop_tgid(fd);

	if (tg->threads_enabled == 1UL || (fdtab[fd].thread_mask & tg->threads_enabled) == ti->ltid_bit) {
		if (HA_ATOMIC_BTS(&fdtab[fd].update_mask, ti->ltid))
			return;

		fd_updt[fd_nbupdt++] = fd;
	} else {
		unsigned long update_mask = fdtab[fd].update_mask;
		do {
			if (update_mask == fdtab[fd].thread_mask) // FIXME: this works only on thread-groups 1
				return;
		} while (!_HA_ATOMIC_CAS(&fdtab[fd].update_mask, &update_mask, fdtab[fd].thread_mask));

		fd_add_to_fd_list(&update_list[tgid - 1], fd);

		if (fd_active(fd) && !(fdtab[fd].thread_mask & ti->ltid_bit)) {
			/* we need to wake up another thread to handle it immediately, any will fit,
			 * so let's pick a random one so that it doesn't always end up on the same.
			 */
			int thr = one_among_mask(fdtab[fd].thread_mask & tg->threads_enabled,
			                         statistical_prng_range(tg->count));
			thr += tg->base;
			wake_thread(thr);
		}
	}
}

/* Update events seen for FD <fd> and its state if needed. This should be
 * called by the poller, passing FD_EV_*_{R,W,RW} in <evts>. FD_EV_ERR_*
 * doesn't need to also pass FD_EV_SHUT_*, it's implied. ERR and SHUT are
 * allowed to be reported regardless of R/W readiness. Returns one of
 * FD_UPDT_*.
 */
int fd_update_events(int fd, uint evts)
{
	unsigned long locked;
	uint old, new;
	uint new_flags, must_stop;
	ulong rmask, tmask;

	_HA_ATOMIC_AND(&th_ctx->flags, ~TH_FL_STUCK); // this thread is still running

	if (unlikely(!fd_grab_tgid(fd, ti->tgid))) {
		/* the FD changed to another tgid, we can't safely
		 * check it anymore. The bits in the masks are not
		 * ours anymore and we're not allowed to touch them.
		 * Ours have already been cleared and the FD was
		 * closed in between so we can safely leave now.
		 */
		activity[tid].poll_drop_fd++;
		return FD_UPDT_CLOSED;
	}

	/* Do not take running_mask if not strictly needed (will trigger a
	 * cosmetic BUG_ON() in fd_insert() anyway if done).
	 */
	tmask = _HA_ATOMIC_LOAD(&fdtab[fd].thread_mask);
	if (!(tmask & ti->ltid_bit))
		goto do_update;

	HA_ATOMIC_OR(&fdtab[fd].running_mask, ti->ltid_bit);

	/* From this point, our bit may possibly be in thread_mask, but it may
	 * still vanish, either because a takeover completed just before taking
	 * the bit above with the new owner deleting the FD, or because a
	 * takeover started just before taking the bit. In order to make sure a
	 * started takeover is complete, we need to verify that all bits of
	 * running_mask are present in thread_mask, since takeover first takes
	 * running then atomically replaces thread_mask. Once it's stable, if
	 * our bit remains there, no further takeover may happen because we
	 * hold running, but if our bit is not there it means we've lost the
	 * takeover race and have to decline touching the FD. Regarding the
	 * risk of deletion, our bit in running_mask prevents fd_delete() from
	 * finalizing the close, and the caller will leave the FD with a zero
	 * thread_mask and the FD_MUST_CLOSE flag set. It will then be our
	 * responsibility to close it.
	 */
	do {
		rmask = _HA_ATOMIC_LOAD(&fdtab[fd].running_mask);
		tmask = _HA_ATOMIC_LOAD(&fdtab[fd].thread_mask);
		rmask &= ~ti->ltid_bit;
	} while ((rmask & ~tmask) && (tmask & ti->ltid_bit));

	/* Now tmask is stable. Do nothing if the FD was taken over under us */

	if (!(tmask & ti->ltid_bit)) {
		/* a takeover has started */
		activity[tid].poll_skip_fd++;

		if (fd_clr_running(fd) == ti->ltid_bit)
			goto closed_or_migrated;

		goto do_update;
	}

	/* with running we're safe now, we can drop the reference */
	fd_drop_tgid(fd);

	locked = (tmask != ti->ltid_bit);

	/* OK now we are guaranteed that our thread_mask was present and
	 * that we're allowed to update the FD.
	 */

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

	if (new_flags & (FD_POLL_IN | FD_POLL_HUP | FD_POLL_ERR))
		new_flags |= FD_EV_READY_R;

	if (new_flags & (FD_POLL_OUT | FD_POLL_ERR))
		new_flags |= FD_EV_READY_W;

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

	if (fdtab[fd].iocb && fd_active(fd)) {
		fdtab[fd].iocb(fd);
	}

	/*
	 * We entered iocb with running set and with the valid tgid.
	 * Since then, this is what could have happened:
	 *   - another thread tried to close the FD (e.g. timeout task from
	 *     another one that owns it). We still have running set, but not
	 *     tmask. We must call fd_clr_running() then _fd_delete_orphan()
	 *     if we were the last one.
	 *
	 *   - the iocb tried to close the FD => bit no more present in running,
	 *     nothing to do. If it managed to close it, the poller's ->clo()
	 *     has already been called.
	 *
	 *   - after we closed, the FD was reassigned to another thread in
	 *     another group => running not present, tgid differs, nothing to
	 *     do because if it got reassigned it indicates it was already
	 *     closed.
	 *
	 * There's no risk of takeover of the valid FD here during this period.
	 * Also if we still have running, immediately after we release it, the
	 * events above might instantly happen due to another thread taking
	 * over.
	 *
	 * As such, the only cases where the FD is still relevant are:
	 *   - tgid still set and running still set (most common)
	 *   - tgid still valid but running cleared due to fd_delete(): we may
	 *     still need to stop polling otherwise we may keep it enabled
	 *     while waiting for other threads to close it.
	 * And given that we may need to program a tentative update in case we
	 * don't immediately close, it's easier to grab the tgid during the
	 * whole check.
	 */

	if (!fd_grab_tgid(fd, tgid))
		return FD_UPDT_CLOSED;

	tmask = _HA_ATOMIC_LOAD(&fdtab[fd].thread_mask);

	/* another thread might have attempted to close this FD in the mean
	 * time (e.g. timeout task) striking on a previous thread and closing.
	 * This is detected by us being the last owners of a running_mask bit,
	 * and the thread_mask being zero. At the moment we release the running
	 * bit, a takeover may also happen, so in practice we check for our loss
	 * of the thread_mask bitboth thread_mask and running_mask being 0 after
	 * we remove ourselves last. There is no risk the FD gets reassigned
	 * to a different group since it's not released until the real close()
	 * in _fd_delete_orphan().
	 */
	if (fd_clr_running(fd) == ti->ltid_bit && !(tmask & ti->ltid_bit))
		goto closed_or_migrated;

	/* we had to stop this FD and it still must be stopped after the I/O
	 * cb's changes, so let's program an update for this.
	 */
	if (must_stop && !(fdtab[fd].update_mask & ti->ltid_bit)) {
		if (((must_stop & FD_POLL_IN)  && !fd_recv_active(fd)) ||
		    ((must_stop & FD_POLL_OUT) && !fd_send_active(fd)))
			if (!HA_ATOMIC_BTS(&fdtab[fd].update_mask, ti->ltid))
				fd_updt[fd_nbupdt++] = fd;
	}

	fd_drop_tgid(fd);
	return FD_UPDT_DONE;

 closed_or_migrated:
	/* We only come here once we've last dropped running and the FD is
	 * not for us as per !(tmask & tid_bit). It may imply we're
	 * responsible for closing it. Otherwise it's just a migration.
	 */
	if (HA_ATOMIC_BTR(&fdtab[fd].state, FD_MUST_CLOSE_BIT)) {
		fd_drop_tgid(fd);
		_fd_delete_orphan(fd);
		return FD_UPDT_CLOSED;
	}

	/* So we were alone, no close bit, at best the FD was migrated, at
	 * worst it's in the process of being closed by another thread. We must
	 * be ultra-careful as it can be re-inserted by yet another thread as
	 * the result of socket() or accept(). Let's just tell the poller the
	 * FD was lost. If it was closed it was already removed and this will
	 * only cost an update for nothing.
	 */

 do_update:
	/* The FD is not closed but we don't want the poller to wake up for
	 * it anymore.
	 */
	if (!HA_ATOMIC_BTS(&fdtab[fd].update_mask, ti->ltid))
		fd_updt[fd_nbupdt++] = fd;

	fd_drop_tgid(fd);
	return FD_UPDT_MIGRATED;
}

/* This is used by pollers at boot time to re-register desired events for
 * all FDs after new pollers have been created. It doesn't do much, it checks
 * that their thread group matches the one in argument, and that the thread
 * mask matches at least one of the bits in the mask, and if so, marks the FD
 * as updated.
 */
void fd_reregister_all(int tgrp, ulong mask)
{
	int fd;

	for (fd = 0; fd < fd_highest; fd++) {
		if (!fdtab[fd].owner)
			continue;

		/* make sure we don't register other tgroups' FDs. We just
		 * avoid needlessly taking the lock if not needed.
		 */
		if (!(_HA_ATOMIC_LOAD(&fdtab[fd].thread_mask) & mask) ||
		    !fd_grab_tgid(fd, tgrp))
			continue;  // was not for us anyway

		if (_HA_ATOMIC_LOAD(&fdtab[fd].thread_mask) & mask)
			updt_fd_polling(fd);
		fd_drop_tgid(fd);
	}
}

/* Tries to send <npfx> parts from <prefix> followed by <nmsg> parts from <msg>
 * optionally followed by a newline if <nl> is non-null, to file descriptor
 * <fd>. The message is sent atomically using writev(). It may be truncated to
 * <maxlen> bytes if <maxlen> is non-null. There is no distinction between the
 * two lists, it's just a convenience to help the caller prepend some prefixes
 * when necessary. It takes the fd's lock to make sure no other thread will
 * write to the same fd in parallel. Returns the number of bytes sent, or <=0
 * on failure. A limit to 31 total non-empty segments is enforced. The caller
 * is responsible for taking care of making the fd non-blocking.
 */
ssize_t fd_write_frag_line(int fd, size_t maxlen, const struct ist pfx[], size_t npfx, const struct ist msg[], size_t nmsg, int nl)
{
	struct iovec iovec[32];
	size_t sent = 0;
	int vec = 0;
	int attempts = 0;

	if (!maxlen)
		maxlen = ~0;

	/* keep one char for a possible trailing '\n' in any case */
	maxlen--;

	/* make an iovec from the concatenation of all parts of the original
	 * message. Skip empty fields and truncate the whole message to maxlen,
	 * leaving one spare iovec for the '\n'.
	 */
	while (vec < (sizeof(iovec) / sizeof(iovec[0]) - 1)) {
		if (!npfx) {
			pfx = msg;
			npfx = nmsg;
			nmsg = 0;
			if (!npfx)
				break;
		}

		iovec[vec].iov_base = pfx->ptr;
		iovec[vec].iov_len  = MIN(maxlen, pfx->len);
		maxlen -= iovec[vec].iov_len;
		if (iovec[vec].iov_len)
			vec++;
		pfx++; npfx--;
	};

	if (nl) {
		iovec[vec].iov_base = "\n";
		iovec[vec].iov_len  = 1;
		vec++;
	}

	/* make sure we never interleave writes and we never block. This means
	 * we prefer to fail on collision than to block. But we don't want to
	 * lose too many logs so we just perform a few lock attempts then give
	 * up.
	 */

	while (HA_ATOMIC_BTS(&fdtab[fd].state, FD_EXCL_SYSCALL_BIT)) {
		if (++attempts >= 200) {
			/* so that the caller knows the message couldn't be delivered */
			sent = -1;
			errno = EAGAIN;
			goto leave;
		}
		ha_thread_relax();
	}

	if (unlikely(!(fdtab[fd].state & FD_INITIALIZED))) {
		HA_ATOMIC_OR(&fdtab[fd].state, FD_INITIALIZED);
		if (!isatty(fd))
			fd_set_nonblock(fd);
	}
	sent = writev(fd, iovec, vec);
	HA_ATOMIC_BTR(&fdtab[fd].state, FD_EXCL_SYSCALL_BIT);

 leave:
	/* sent > 0 if the message was delivered */
	return sent;
}

#if defined(USE_CLOSEFROM)
void my_closefrom(int start)
{
	closefrom(start);
}

#elif defined(USE_POLL)
/* This is a portable implementation of closefrom(). It closes all open file
 * descriptors starting at <start> and above. It relies on the fact that poll()
 * will return POLLNVAL for each invalid (hence close) file descriptor passed
 * in argument in order to skip them. It acts with batches of FDs and will
 * typically perform one poll() call per 1024 FDs so the overhead is low in
 * case all FDs have to be closed.
 */
void my_closefrom(int start)
{
	struct pollfd poll_events[1024];
	struct rlimit limit;
	int nbfds, fd, ret, idx;
	int step, next;

	if (getrlimit(RLIMIT_NOFILE, &limit) == 0)
		step = nbfds = limit.rlim_cur;
	else
		step = nbfds = 0;

	if (nbfds <= 0) {
		/* set safe limit */
		nbfds = 1024;
		step = 256;
	}

	if (step > sizeof(poll_events) / sizeof(poll_events[0]))
		step = sizeof(poll_events) / sizeof(poll_events[0]);

	while (start < nbfds) {
		next = (start / step + 1) * step;

		for (fd = start; fd < next && fd < nbfds; fd++) {
			poll_events[fd - start].fd = fd;
			poll_events[fd - start].events = 0;
		}

		do {
			ret = poll(poll_events, fd - start, 0);
			if (ret >= 0)
				break;
		} while (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ENOMEM);

		/* always check the whole range */
		ret = fd - start;

		for (idx = 0; idx < ret; idx++) {
			if (poll_events[idx].revents & POLLNVAL)
				continue; /* already closed */

			fd = poll_events[idx].fd;
			close(fd);
		}
		start = next;
	}
}

#else // defined(USE_POLL)

/* This is a portable implementation of closefrom(). It closes all open file
 * descriptors starting at <start> and above. This is a naive version for use
 * when the operating system provides no alternative.
 */
void my_closefrom(int start)
{
	struct rlimit limit;
	int nbfds;

	if (getrlimit(RLIMIT_NOFILE, &limit) == 0)
		nbfds = limit.rlim_cur;
	else
		nbfds = 0;

	if (nbfds <= 0)
		nbfds = 1024; /* safe limit */

	while (start < nbfds)
		close(start++);
}
#endif // defined(USE_POLL)


/* Computes the bounded poll() timeout based on the next expiration timer <next>
 * by bounding it to MAX_DELAY_MS. <next> may equal TICK_ETERNITY. The pollers
 * just needs to call this function right before polling to get their timeout
 * value. Timeouts that are already expired (possibly due to a pending event)
 * are accounted for in activity.poll_exp.
 */
int compute_poll_timeout(int next)
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

/* Handle the return of the poller, which consists in calculating the idle
 * time, saving a few clocks, marking the thread harmful again etc. All that
 * is some boring stuff that all pollers have to do anyway.
 */
void fd_leaving_poll(int wait_time, int status)
{
	clock_leaving_poll(wait_time, status);

	thread_harmless_end();
	thread_idle_end();

	_HA_ATOMIC_AND(&th_ctx->flags, ~TH_FL_SLEEPING);
}

/* disable the specified poller */
void disable_poller(const char *poller_name)
{
	int p;

	for (p = 0; p < nbpollers; p++)
		if (strcmp(pollers[p].name, poller_name) == 0)
			pollers[p].pref = 0;
}

void poller_pipe_io_handler(int fd)
{
	char buf[1024];
	/* Flush the pipe */
	while (read(fd, buf, sizeof(buf)) > 0);
	fd_cant_recv(fd);
}

/* allocate the per-thread fd_updt thus needs to be called early after
 * thread creation.
 */
static int alloc_pollers_per_thread()
{
	fd_updt = calloc(global.maxsock, sizeof(*fd_updt));
	vma_set_name_id(fd_updt, global.maxsock * sizeof(*fd_updt), "fd", "fd_updt", tid + 1);
	return fd_updt != NULL;
}

/* Initialize the pollers per thread.*/
static int init_pollers_per_thread()
{
	int mypipe[2];

	if (pipe(mypipe) < 0)
		return 0;

	poller_rd_pipe = mypipe[0];
	poller_wr_pipe[tid] = mypipe[1];
	fd_set_nonblock(poller_rd_pipe);
	fd_insert(poller_rd_pipe, poller_pipe_io_handler, poller_pipe_io_handler, tgid, ti->ltid_bit);
	fd_insert(poller_wr_pipe[tid], poller_pipe_io_handler, poller_pipe_io_handler, tgid, ti->ltid_bit);
	fd_want_recv(poller_rd_pipe);
	fd_stop_both(poller_wr_pipe[tid]);
	return 1;
}

/* Deinitialize the pollers per thread */
static void deinit_pollers_per_thread()
{
	/* rd and wr are init at the same place, but only rd is init to -1, so
	  we rely to rd to close.   */
	if (poller_rd_pipe > -1) {
		fd_delete(poller_rd_pipe);
		poller_rd_pipe = -1;
		fd_delete(poller_wr_pipe[tid]);
		poller_wr_pipe[tid] = -1;
	}
}

/* Release the pollers per thread, to be called late */
static void free_pollers_per_thread()
{
	fd_nbupdt = 0;
	ha_free(&fd_updt);
}

/*
 * Initialize the pollers till the best one is found.
 * If none works, returns 0, otherwise 1.
 */
int init_pollers()
{
	int p;
	struct poller *bp;

	if ((fdtab_addr = calloc(1, global.maxsock * sizeof(*fdtab) + 64)) == NULL) {
		ha_alert("Not enough memory to allocate %d entries for fdtab!\n", global.maxsock);
		goto fail_tab;
	}
	vma_set_name(fdtab_addr, global.maxsock * sizeof(*fdtab) + 64, "fd", "fdtab_addr");

	/* always provide an aligned fdtab */
	fdtab = (struct fdtab*)((((size_t)fdtab_addr) + 63) & -(size_t)64);

	if ((polled_mask = calloc(global.maxsock, sizeof(*polled_mask))) == NULL) {
		ha_alert("Not enough memory to allocate %d entries for polled_mask!\n", global.maxsock);
		goto fail_polledmask;
	}
	vma_set_name(polled_mask, global.maxsock * sizeof(*polled_mask), "fd", "polled_mask");

	if ((fdinfo = calloc(global.maxsock, sizeof(*fdinfo))) == NULL) {
		ha_alert("Not enough memory to allocate %d entries for fdinfo!\n", global.maxsock);
		goto fail_info;
	}
	vma_set_name(fdinfo, global.maxsock * sizeof(*fdinfo), "fd", "fdinfo");

	for (p = 0; p < MAX_TGROUPS; p++)
		update_list[p].first = update_list[p].last = -1;

	for (p = 0; p < global.maxsock; p++) {
		/* Mark the fd as out of the fd cache */
		fdtab[p].update.next = -3;
	}

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

	free(fdinfo);
 fail_info:
	free(polled_mask);
 fail_polledmask:
	free(fdtab_addr);
 fail_tab:
	return 0;
}

/*
 * Deinitialize the pollers.
 */
void deinit_pollers() {

	struct poller *bp;
	int p;

	for (p = 0; p < nbpollers; p++) {
		bp = &pollers[p];

		if (bp && bp->pref)
			bp->term(bp);
	}

	ha_free(&fdinfo);
	ha_free(&fdtab_addr);
	ha_free(&polled_mask);
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
	for (fd = 0; fd < fd_highest; fd++) {
		if (fdtab[fd].owner) {
			HA_ATOMIC_OR(&fdtab[fd].state, FD_CLONED);
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

/* config parser for global "tune.fd.edge-triggered", accepts "on" or "off" */
static int cfg_parse_tune_fd_edge_triggered(char **args, int section_type, struct proxy *curpx,
                                      const struct proxy *defpx, const char *file, int line,
                                      char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		global.tune.options |= GTUNE_FD_ET;
	else if (strcmp(args[1], "off") == 0)
		global.tune.options &= ~GTUNE_FD_ET;
	else {
		memprintf(err, "'%s' expects either 'on' or 'off' but got '%s'.", args[0], args[1]);
		return -1;
	}
	return 0;
}

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.fd.edge-triggered", cfg_parse_tune_fd_edge_triggered, KWF_EXPERIMENTAL },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

REGISTER_PER_THREAD_ALLOC(alloc_pollers_per_thread);
REGISTER_PER_THREAD_INIT(init_pollers_per_thread);
REGISTER_PER_THREAD_DEINIT(deinit_pollers_per_thread);
REGISTER_PER_THREAD_FREE(free_pollers_per_thread);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
