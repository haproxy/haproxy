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
 *     |       v  | EAGAIN (cant)
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
#include <errno.h>
#endif

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/port_range.h>
#include <haproxy/tools.h>


struct fdtab *fdtab = NULL;     /* array of all the file descriptors */
struct polled_mask *polled_mask = NULL; /* Array for the polled_mask of each fd */
struct fdinfo *fdinfo = NULL;   /* less-often used infos for file descriptors */
int totalconn;                  /* total # of terminated sessions */
int actconn;                    /* # of active sessions */

struct poller pollers[MAX_POLLERS];
struct poller cur_poller;
int nbpollers = 0;

volatile struct fdlist update_list; // Global update list

THREAD_LOCAL int *fd_updt  = NULL;  // FD updates list
THREAD_LOCAL int  fd_nbupdt = 0;   // number of updates in the list
THREAD_LOCAL int poller_rd_pipe = -1; // Pipe to wake the thread
int poller_wr_pipe[MAX_THREADS]; // Pipe to wake the threads

volatile int ha_used_fds = 0; // Number of FD we're currently using

#define _GET_NEXT(fd, off) ((volatile struct fdlist_entry *)(void *)((char *)(&fdtab[fd]) + off))->next
#define _GET_PREV(fd, off) ((volatile struct fdlist_entry *)(void *)((char *)(&fdtab[fd]) + off))->prev
/* adds fd <fd> to fd list <list> if it was not yet in it */
void fd_add_to_fd_list(volatile struct fdlist *list, int fd, int off)
{
	int next;
	int new;
	int old;
	int last;

redo_next:
	next = _GET_NEXT(fd, off);
	/* Check that we're not already in the cache, and if not, lock us. */
	if (next > -2)
		goto done;
	if (next == -2)
		goto redo_next;
	if (!_HA_ATOMIC_CAS(&_GET_NEXT(fd, off), &next, -2))
		goto redo_next;
	__ha_barrier_atomic_store();

	new = fd;
redo_last:
	/* First, insert in the linked list */
	last = list->last;
	old = -1;

	_GET_PREV(fd, off) = -2;
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
		if (unlikely(!_HA_ATOMIC_CAS(&_GET_NEXT(last, off), &old, new)))
			goto redo_last;

		/* Then, update the last entry */
		list->last = fd;
	}
	__ha_barrier_store();
	/* since we're alone at the end of the list and still locked(-2),
	 * we know no one tried to add past us. Mark the end of list.
	 */
	_GET_PREV(fd, off) = last;
	_GET_NEXT(fd, off) = -1;
	__ha_barrier_store();
done:
	return;
}

/* removes fd <fd> from fd list <list> */
void fd_rm_from_fd_list(volatile struct fdlist *list, int fd, int off)
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
	cur_list.ent = *(volatile struct fdlist_entry *)(((char *)&fdtab[fd]) + off);
	/* First, attempt to lock our own entries */
	do {
		/* The FD is not in the FD cache, give up */
		if (unlikely(cur_list.ent.next <= -3))
			return;
		if (unlikely(cur_list.ent.prev == -2 || cur_list.ent.next == -2))
			goto lock_self;
	} while (
#ifdef HA_CAS_IS_8B
		 unlikely(!_HA_ATOMIC_CAS(((uint64_t *)&_GET_NEXT(fd, off)), (uint64_t *)&cur_list.u64, next_list.u64))
#else
		 unlikely(!_HA_ATOMIC_DWCAS(((long *)&_GET_NEXT(fd, off)), (uint32_t *)&cur_list.u32, &next_list.u32))
#endif
	    );
	next = cur_list.ent.next;
	prev = cur_list.ent.prev;

#else
lock_self_next:
	next = _GET_NEXT(fd, off);
	if (next == -2)
		goto lock_self_next;
	if (next <= -3)
		goto done;
	if (unlikely(!_HA_ATOMIC_CAS(&_GET_NEXT(fd, off), &next, -2)))
		goto lock_self_next;
lock_self_prev:
	prev = _GET_PREV(fd, off);
	if (prev == -2)
		goto lock_self_prev;
	if (unlikely(!_HA_ATOMIC_CAS(&_GET_PREV(fd, off), &prev, -2)))
		goto lock_self_prev;
#endif
	__ha_barrier_atomic_store();

	/* Now, lock the entries of our neighbours */
	if (likely(prev != -1)) {
redo_prev:
		old = fd;

		if (unlikely(!_HA_ATOMIC_CAS(&_GET_NEXT(prev, off), &old, new))) {
			if (unlikely(old == -2)) {
				/* Neighbour already locked, give up and
				 * retry again once he's done
				 */
				_GET_PREV(fd, off) = prev;
				__ha_barrier_store();
				_GET_NEXT(fd, off) = next;
				__ha_barrier_store();
				goto lock_self;
			}
			goto redo_prev;
		}
	}
	if (likely(next != -1)) {
redo_next:
		old = fd;
		if (unlikely(!_HA_ATOMIC_CAS(&_GET_PREV(next, off), &old, new))) {
			if (unlikely(old == -2)) {
				/* Neighbour already locked, give up and
				 * retry again once he's done
				 */
				if (prev != -1) {
					_GET_NEXT(prev, off) = fd;
					__ha_barrier_store();
				}
				_GET_PREV(fd, off) = prev;
				__ha_barrier_store();
				_GET_NEXT(fd, off) = next;
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
		_GET_NEXT(prev, off) = next;
	__ha_barrier_store();
	if (likely(next != -1))
		_GET_PREV(next, off) = prev;
	__ha_barrier_store();
	/* Ok, now we're out of the fd cache */
	_GET_NEXT(fd, off) = -(next + 4);
	__ha_barrier_store();
done:
	return;
}

#undef _GET_NEXT
#undef _GET_PREV

/* Deletes an FD from the fdsets.
 * The file descriptor is also closed.
 */
void fd_delete(int fd)
{
	int locked = fdtab[fd].running_mask != tid_bit;

	/* We're just trying to protect against a concurrent fd_insert()
	 * here, not against fd_takeover(), because either we're called
	 * directly from the iocb(), and we're already locked, or we're
	 * called from the mux tasklet, but then the mux is responsible for
	 * making sure the tasklet does nothing, and the connection is never
	 * destroyed.
	 */
	if (locked)
		fd_set_running_excl(fd);

	if (fdtab[fd].linger_risk) {
		/* this is generally set when connecting to servers */
		DISGUISE(setsockopt(fd, SOL_SOCKET, SO_LINGER,
			   (struct linger *) &nolinger, sizeof(struct linger)));
	}
	if (cur_poller.clo)
		cur_poller.clo(fd);
	polled_mask[fd].poll_recv = polled_mask[fd].poll_send = 0;

	fdtab[fd].state = 0;

#ifdef DEBUG_FD
	fdtab[fd].event_count = 0;
#endif
	port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
	fdinfo[fd].port_range = NULL;
	fdtab[fd].owner = NULL;
	fdtab[fd].thread_mask = 0;
	fdtab[fd].exported = 0;
	close(fd);
	_HA_ATOMIC_SUB(&ha_used_fds, 1);
	if (locked)
		fd_clr_running(fd);
}

#ifndef HA_HAVE_CAS_DW
__decl_thread(__decl_rwlock(fd_mig_lock));
#endif

/*
 * Take over a FD belonging to another thread.
 * unexpected_conn is the expected owner of the fd.
 * Returns 0 on success, and -1 on failure.
 */
int fd_takeover(int fd, void *expected_owner)
{
	int ret = -1;

#ifndef HA_HAVE_CAS_DW
	if (_HA_ATOMIC_OR(&fdtab[fd].running_mask, tid_bit) == tid_bit) {
		HA_RWLOCK_WRLOCK(OTHER_LOCK, &fd_mig_lock);
		if (fdtab[fd].owner == expected_owner) {
			fdtab[fd].thread_mask = tid_bit;
			ret = 0;
		}
		HA_RWLOCK_WRUNLOCK(OTHER_LOCK, &fd_mig_lock);
	}
#else
	unsigned long old_masks[2];
	unsigned long new_masks[2];

	new_masks[0] = new_masks[1] = tid_bit;

	old_masks[0] = _HA_ATOMIC_OR(&fdtab[fd].running_mask, tid_bit);
	old_masks[1] = fdtab[fd].thread_mask;

	/* protect ourself against a delete then an insert for the same fd,
	 * if it happens, then the owner will no longer be the expected
	 * connection.
	 */
	if (fdtab[fd].owner == expected_owner) {
		while (old_masks[0] == tid_bit && old_masks[1]) {
			if (_HA_ATOMIC_DWCAS(&fdtab[fd].running_mask, &old_masks, &new_masks)) {
				ret = 0;
				break;
			}
		}
	}
#endif /* HW_HAVE_CAS_DW */

	_HA_ATOMIC_AND(&fdtab[fd].running_mask, ~tid_bit);

	/* Make sure the FD doesn't have the active bit. It is possible that
	 * the fd is polled by the thread that used to own it, the new thread
	 * is supposed to call subscribe() later, to activate polling.
	 */
	if (likely(ret == 0))
		fd_stop_recv(fd);
	return ret;
}

void updt_fd_polling(const int fd)
{
	if (all_threads_mask == 1UL || (fdtab[fd].thread_mask & all_threads_mask) == tid_bit) {
		if (HA_ATOMIC_BTS(&fdtab[fd].update_mask, tid))
			return;

		fd_updt[fd_nbupdt++] = fd;
	} else {
		unsigned long update_mask = fdtab[fd].update_mask;
		do {
			if (update_mask == fdtab[fd].thread_mask)
				return;
		} while (!_HA_ATOMIC_CAS(&fdtab[fd].update_mask, &update_mask, fdtab[fd].thread_mask));

		fd_add_to_fd_list(&update_list, fd, offsetof(struct fdtab, update));

		if (fd_active(fd) &&
		    !(fdtab[fd].thread_mask & tid_bit) &&
		    (fdtab[fd].thread_mask & ~tid_bit & all_threads_mask & ~sleeping_thread_mask) == 0) {
			/* we need to wake up one thread to handle it immediately */
			int thr = my_ffsl(fdtab[fd].thread_mask & ~tid_bit & all_threads_mask) - 1;

			_HA_ATOMIC_AND(&sleeping_thread_mask, ~(1UL << thr));
			wake_thread(thr);
		}
	}
}

__decl_spinlock(log_lock);
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
	size_t totlen = 0;
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
		totlen += iovec[vec].iov_len;
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

	while (HA_SPIN_TRYLOCK(OTHER_LOCK, &log_lock) != 0) {
		if (++attempts >= 200) {
			/* so that the caller knows the message couldn't be delivered */
			sent = -1;
			errno = EAGAIN;
			goto leave;
		}
		ha_thread_relax();
	}

	if (unlikely(!fdtab[fd].initialized)) {
		fdtab[fd].initialized = 1;
		if (!isatty(fd))
			fcntl(fd, F_SETFL, O_NONBLOCK);
	}
	sent = writev(fd, iovec, vec);
	HA_SPIN_UNLOCK(OTHER_LOCK, &log_lock);

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
		} while (errno == EAGAIN || errno == EINTR || errno == ENOMEM);

		if (ret)
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
	fcntl(poller_rd_pipe, F_SETFL, O_NONBLOCK);
	fd_insert(poller_rd_pipe, poller_pipe_io_handler, poller_pipe_io_handler,
	    tid_bit);
	fd_want_recv(poller_rd_pipe);
	return 1;
}

/* Deinitialize the pollers per thread */
static void deinit_pollers_per_thread()
{
	/* rd and wr are init at the same place, but only rd is init to -1, so
	  we rely to rd to close.   */
	if (poller_rd_pipe > -1) {
		close(poller_rd_pipe);
		poller_rd_pipe = -1;
		close(poller_wr_pipe[tid]);
		poller_wr_pipe[tid] = -1;
	}
}

/* Release the pollers per thread, to be called late */
static void free_pollers_per_thread()
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

	if ((fdtab = calloc(global.maxsock, sizeof(*fdtab))) == NULL) {
		ha_alert("Not enough memory to allocate %d entries for fdtab!\n", global.maxsock);
		goto fail_tab;
	}

	if ((polled_mask = calloc(global.maxsock, sizeof(*polled_mask))) == NULL) {
		ha_alert("Not enough memory to allocate %d entries for polled_mask!\n", global.maxsock);
		goto fail_polledmask;
	}

	if ((fdinfo = calloc(global.maxsock, sizeof(*fdinfo))) == NULL) {
		ha_alert("Not enough memory to allocate %d entries for fdinfo!\n", global.maxsock);
		goto fail_info;
	}

	update_list.first = update_list.last = -1;

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

	for (p = 0; p < nbpollers; p++) {
		bp = &pollers[p];

		if (bp && bp->pref)
			bp->term(bp);
	}

	free(fdinfo);   fdinfo   = NULL;
	free(fdtab);    fdtab    = NULL;
	free(polled_mask); polled_mask = NULL;
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
	for (fd = 0; fd < global.maxsock; fd++) {
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

/* config parser for global "tune.fd.edge-triggered", accepts "on" or "off" */
static int cfg_parse_tune_fd_edge_triggered(char **args, int section_type, struct proxy *curpx,
                                      struct proxy *defpx, const char *file, int line,
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
	{ CFG_GLOBAL, "tune.fd.edge-triggered", cfg_parse_tune_fd_edge_triggered },
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
