/*
 * FD polling functions for Speculative I/O combined with Linux epoll()
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 *
 * This code implements "speculative I/O" under Linux. The principle is to
 * try to perform expected I/O before registering the events in the poller.
 * Each time this succeeds, it saves an expensive epoll_ctl(). It generally
 * succeeds for all reads after an accept(), and for writes after a connect().
 * It also improves performance for streaming connections because even if only
 * one side is polled, the other one may react accordingly depending on the
 * level of the buffer.
 *
 * More importantly, it enables I/O operations that are backed by invisible
 * buffers. For example, SSL is able to read a whole socket buffer and not
 * deliver it to the application buffer because it's full. Unfortunately, it
 * won't be reported by epoll() anymore until some new activity happens. The
 * only way to call it again thus is to perform speculative I/O as soon as
 * reading on the FD is enabled again.
 *
 * The speculative I/O relies on a double list of expected events and updates.
 * Expected events are events that are expected to come and that we must report
 * to the application until it asks to stop or to poll. Updates are new requests
 * for changing an FD state. Updates are the only way to create new events. This
 * is important because it means that the number of speculative events cannot
 * increase between updates and will only grow one at a time while processing
 * updates. All updates must always be processed, though events might be
 * processed by small batches if required. The result is that there is no need
 * for preallocating room for spec events, updates evinced from the list always
 * release at least as much as necessary.
 *
 * In order to limit memory usage, events and updates share the same list (an
 * array to be exact). The lower part (0..nbevts) is used by events and the
 * higher part by updates. This way, an fd may be mapped to any entry (evt or
 * update) using a single index. Updates may be simply turned to events. When
 * events are deleted, the last event from the list must replace the deleted
 * event, and if there were updates past this event, one must be moved to take
 * its place. It still means that any file descriptor might be present in the
 * event or update list, so the list must be at least as large as the maximum
 * number of simultaneous file descriptors.
 *
 * It is important to understand that as long as all expected events are
 * processed, they might starve the polled events, especially because polled
 * I/O starvation quickly induces more speculative I/O. One solution to this
 * consists in only processing a part of the events at once, but one drawback
 * is that unhandled events will still wake epoll_wait() up. Using EPOLL_ET
 * will solve this issue though.
 *
 * A file descriptor has a distinct state for each direction. This state is a
 * combination of two bits :
 *  bit 0 = active Y/N : is set if the FD is active, which means that its
 *          handler will be called without prior polling ;
 *  bit 1 = polled Y/N : is set if the FD was subscribed to polling
 *
 * It is perfectly valid to have both bits set at a time, which generally means
 * that the FD was reported by polling, was marked active and not yet unpolled.
 * Such a state must not last long to avoid unneeded wakeups.
 *
 * The state of the FD as of last change is preserved in two other bits. These
 * ones are useful to save a significant amount of system calls during state
 * changes, because there is no need to call epoll_ctl() until we're about to
 * call epoll_wait().
 *
 * Since we do not want to scan all the FD list to find speculative I/O events,
 * we store them in a list consisting in a linear array holding only the FD
 * indexes right now. Note that a closed FD cannot exist in the spec list,
 * because it is closed by fd_delete() which in turn calls __fd_clo() which
 * always removes it from the list.
 *
 * For efficiency reasons, we will store the Read and Write bits interlaced to
 * form a 4-bit field, so that we can simply shift the value right by 0/1 and
 * get what we want :
 *    3  2  1  0
 *   Wp Rp Wa Ra
 *
 * The FD array has to hold a back reference to the speculative list. This
 * reference is always valid unless the FD if currently being polled and not
 * updated (in which case the reference points to index 0).
 *
 * We store the FD state in the 4 lower bits of fdtab[fd].spec_e, and save the
 * previous state upon changes in the 4 higher bits, so that changes are easy
 * to spot.
 */

#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/epoll.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>
#include <common/tools.h>

#include <types/global.h>

#include <proto/fd.h>
#include <proto/signal.h>
#include <proto/task.h>


#define FD_EV_ACTIVE    1U
#define FD_EV_POLLED    4U
#define FD_EV_STATUS    (FD_EV_ACTIVE | FD_EV_POLLED)
#define FD_EV_STATUS_R  (FD_EV_STATUS)
#define FD_EV_STATUS_W  (FD_EV_STATUS << 1)

#define FD_EV_POLLED_R  (FD_EV_POLLED)
#define FD_EV_POLLED_W  (FD_EV_POLLED << 1)
#define FD_EV_POLLED_RW (FD_EV_POLLED_R | FD_EV_POLLED_W)

#define FD_EV_ACTIVE_R  (FD_EV_ACTIVE)
#define FD_EV_ACTIVE_W  (FD_EV_ACTIVE << 1)
#define FD_EV_ACTIVE_RW (FD_EV_ACTIVE_R | FD_EV_ACTIVE_W)

#define FD_EV_CURR_MASK 0x0FU
#define FD_EV_PREV_MASK 0xF0U

/* This is the minimum number of events successfully processed in speculative
 * mode above which we agree to return without checking epoll() (1/2 times).
 */
#define MIN_RETURN_EVENTS	25

static int nbspec = 0;          // number of speculative events in the list
static int nbupdt = 0;          // number of updates in the list
static int absmaxevents = 0;    // absolute maximum amounts of polled events
static int in_poll_loop = 0;    // non-null if polled events are being processed

static unsigned int *spec_list = NULL;  // speculative I/O list
static unsigned int *updt_list = NULL;  // FD updates list

/* private data */
static struct epoll_event *epoll_events;
static int epoll_fd;

/* This structure may be used for any purpose. Warning! do not use it in
 * recursive functions !
 */
static struct epoll_event ev;


/* Mark fd <fd> as updated and allocate an entry in the update list for this if
 * it was not already there. This can be done at any time.
 */
REGPRM1 static inline void updt_fd(const int fd)
{
	if (fdtab[fd].updated)
		/* already scheduled for update */
		return;
	updt_list[nbupdt++] = fd;
	fdtab[fd].updated = 1;
}


/* allocate an entry for a speculative event. This can be done at any time. */
REGPRM1 static inline void alloc_spec_entry(const int fd)
{
	if (fdtab[fd].spec_p)
		/* FD already in speculative I/O list */
		return;
	spec_list[nbspec++] = fd;
	fdtab[fd].spec_p = nbspec;
}

/* Removes entry used by fd <fd> from the spec list and replaces it with the
 * last one. The fdtab.spec is adjusted to match the back reference if needed.
 * If the fd has no entry assigned, return immediately.
 */
REGPRM1 static void release_spec_entry(int fd)
{
	unsigned int pos;

	pos = fdtab[fd].spec_p;
	if (!pos)
		return;
	fdtab[fd].spec_p = 0;
	nbspec--;
	if (pos <= nbspec) {
		/* was not the last entry */
		fd = spec_list[nbspec];
		spec_list[pos - 1] = fd;
		fdtab[fd].spec_p = pos;
	}
}

/*
 * Returns non-zero if <fd> is already monitored for events in direction <dir>.
 */
REGPRM2 static int __fd_is_set(const int fd, int dir)
{
#if DEBUG_DEV
	if (!fdtab[fd].owner) {
		fprintf(stderr, "sepoll.fd_isset called on closed fd #%d.\n", fd);
		ABORT_NOW();
	}
#endif
	return ((unsigned)fdtab[fd].spec_e >> dir) & FD_EV_STATUS;
}

/*
 * Don't worry about the strange constructs in __fd_set/__fd_clr, they are
 * designed like this in order to reduce the number of jumps (verified).
 */
REGPRM2 static void __fd_wai(const int fd, int dir)
{
	unsigned int i;

#if DEBUG_DEV
	if (!fdtab[fd].owner) {
		fprintf(stderr, "sepoll.fd_wai called on closed fd #%d.\n", fd);
		ABORT_NOW();
	}
#endif
	i = ((unsigned)fdtab[fd].spec_e >> dir) & FD_EV_STATUS;

	if (i == FD_EV_POLLED)
		return; /* already in desired state */
	updt_fd(fd); /* need an update entry to change the state */
	fdtab[fd].spec_e ^= (i ^ (unsigned int)FD_EV_POLLED) << dir;
}

REGPRM2 static void __fd_set(const int fd, int dir)
{
	unsigned int i;

#if DEBUG_DEV
	if (!fdtab[fd].owner) {
		fprintf(stderr, "sepoll.fd_set called on closed fd #%d.\n", fd);
		ABORT_NOW();
	}
#endif
	i = ((unsigned)fdtab[fd].spec_e >> dir) & FD_EV_STATUS;

	/* note that we don't care about disabling the polled state when
	 * enabling the active state, since it brings no benefit but costs
	 * some syscalls.
	 */
	if (i & FD_EV_ACTIVE)
		return; /* already in desired state */
	updt_fd(fd); /* need an update entry to change the state */
	fdtab[fd].spec_e |= ((unsigned int)FD_EV_ACTIVE) << dir;
}

REGPRM2 static void __fd_clr(const int fd, int dir)
{
	unsigned int i;

#if DEBUG_DEV
	if (!fdtab[fd].owner) {
		fprintf(stderr, "sepoll.fd_clr called on closed fd #%d.\n", fd);
		ABORT_NOW();
	}
#endif
	i = ((unsigned)fdtab[fd].spec_e >> dir) & FD_EV_STATUS;

	if (i == 0)
		return /* already disabled */;
	updt_fd(fd); /* need an update entry to change the state */
	fdtab[fd].spec_e ^= i << dir;
}

/* normally unused */
REGPRM1 static void __fd_rem(int fd)
{
	__fd_clr(fd, DIR_RD);
	__fd_clr(fd, DIR_WR);
}

/*
 * On valid epoll() implementations, a call to close() automatically removes
 * the fds. This means that the FD will appear as previously unset.
 */
REGPRM1 static void __fd_clo(int fd)
{
	release_spec_entry(fd);
	fdtab[fd].spec_e &= ~(FD_EV_CURR_MASK | FD_EV_PREV_MASK);
}

/*
 * speculative epoll() poller
 */
REGPRM2 static void _do_poll(struct poller *p, int exp)
{
	int status, eo, en;
	int fd, opcode;
	int count;
	int spec_idx;
	int updt_idx;
	int wait_time;

	/* first, scan the update list to find changes */
	for (updt_idx = 0; updt_idx < nbupdt; updt_idx++) {
		fd = updt_list[updt_idx];
		en = fdtab[fd].spec_e & 15;  /* new events */
		eo = fdtab[fd].spec_e >> 4;  /* previous events */

		if (fdtab[fd].owner && (eo ^ en)) {
			if ((eo ^ en) & FD_EV_POLLED_RW) {
				/* poll status changed */
				if ((en & FD_EV_POLLED_RW) == 0) {
					/* fd removed from poll list */
					opcode = EPOLL_CTL_DEL;
				}
				else if ((eo & FD_EV_POLLED_RW) == 0) {
					/* new fd in the poll list */
					opcode = EPOLL_CTL_ADD;
				}
				else {
					/* fd status changed */
					opcode = EPOLL_CTL_MOD;
				}

				/* construct the epoll events based on new state */
				ev.events = 0;
				if (en & FD_EV_POLLED_R)
					ev.events |= EPOLLIN;

				if (en & FD_EV_POLLED_W)
					ev.events |= EPOLLOUT;

				ev.data.fd = fd;
				epoll_ctl(epoll_fd, opcode, fd, &ev);
			}

			fdtab[fd].spec_e = (en << 4) + en;  /* save new events */

			if (!(en & FD_EV_ACTIVE_RW)) {
				/* This fd doesn't use any active entry anymore, we can
				 * kill its entry.
				 */
				release_spec_entry(fd);
			}
			else if ((en & ~eo) & FD_EV_ACTIVE_RW) {
				/* we need a new spec entry now */
				alloc_spec_entry(fd);
			}

		}
		fdtab[fd].updated = 0;
		fdtab[fd].new = 0;
	}
	nbupdt = 0;

	/* compute the epoll_wait() timeout */

	if (nbspec || run_queue || signal_queue_len) {
		/* Maybe we still have events in the spec list, or there are
		 * some tasks left pending in the run_queue, so we must not
		 * wait in epoll() otherwise we would delay their delivery by
		 * the next timeout.
		 */
		wait_time = 0;
	}
	else {
		if (!exp)
			wait_time = MAX_DELAY_MS;
		else if (tick_is_expired(exp, now_ms))
			wait_time = 0;
		else {
			wait_time = TICKS_TO_MS(tick_remain(now_ms, exp)) + 1;
			if (wait_time > MAX_DELAY_MS)
				wait_time = MAX_DELAY_MS;
		}
	}

	/* now let's wait for polled events */

	fd = MIN(maxfd, global.tune.maxpollevents);
	gettimeofday(&before_poll, NULL);
	status = epoll_wait(epoll_fd, epoll_events, fd, wait_time);
	tv_update_date(wait_time, status);
	measure_idle();

	in_poll_loop = 1;

	/* process polled events */

	for (count = 0; count < status; count++) {
		int e = epoll_events[count].events;
		fd = epoll_events[count].data.fd;

		if (!fdtab[fd].owner)
			continue;

		/* it looks complicated but gcc can optimize it away when constants
		 * have same values.
		 */
		fdtab[fd].ev &= FD_POLL_STICKY;
		fdtab[fd].ev |=
			((e & EPOLLIN ) ? FD_POLL_IN  : 0) |
			((e & EPOLLPRI) ? FD_POLL_PRI : 0) |
			((e & EPOLLOUT) ? FD_POLL_OUT : 0) |
			((e & EPOLLERR) ? FD_POLL_ERR : 0) |
			((e & EPOLLHUP) ? FD_POLL_HUP : 0);

		if (fdtab[fd].iocb && fdtab[fd].owner && fdtab[fd].ev) {
			int new_updt, old_updt = nbupdt; /* Save number of updates to detect creation of new FDs. */

			/* Mark the events as speculative before processing
			 * them so that if nothing can be done we don't need
			 * to poll again.
			 */
			if (fdtab[fd].ev & (FD_POLL_IN|FD_POLL_HUP|FD_POLL_ERR))
				__fd_set(fd, DIR_RD);

			if (fdtab[fd].ev & (FD_POLL_OUT|FD_POLL_ERR))
				__fd_set(fd, DIR_WR);

			fdtab[fd].iocb(fd);

			/* One or more fd might have been created during the iocb().
			 * This mainly happens with new incoming connections that have
			 * just been accepted, so we'd like to process them immediately
			 * for better efficiency. Second benefit, if at the end the fds
			 * are disabled again, we can safely destroy their update entry
			 * to reduce the scope of later scans. This is the reason we
			 * scan the new entries backwards.
			 */

			for (new_updt = nbupdt; new_updt > old_updt; new_updt--) {
				fd = updt_list[new_updt - 1];
				if (!fdtab[fd].new)
					continue;

				fdtab[fd].new = 0;
				fdtab[fd].ev &= FD_POLL_STICKY;

				if ((fdtab[fd].spec_e & FD_EV_STATUS_R) == FD_EV_ACTIVE_R)
					fdtab[fd].ev |= FD_POLL_IN;

				if ((fdtab[fd].spec_e & FD_EV_STATUS_W) == FD_EV_ACTIVE_W)
					fdtab[fd].ev |= FD_POLL_OUT;

				if (fdtab[fd].ev && fdtab[fd].iocb && fdtab[fd].owner)
					fdtab[fd].iocb(fd);

				/* we can remove this update entry if it's the last one and is
				 * unused, otherwise we don't touch anything.
				 */
				if (new_updt == nbupdt && fdtab[fd].spec_e == 0) {
					fdtab[fd].updated = 0;
					nbupdt--;
				}
			}
		}
	}

	/* now process speculative events if any */

	for (spec_idx = 0; spec_idx < nbspec; ) {
		fd = spec_list[spec_idx];
		eo = fdtab[fd].spec_e;

		/*
		 * Process the speculative events.
		 *
		 * Principle: events which are marked FD_EV_ACTIVE are processed
		 * with their usual I/O callback. The callback may remove the
		 * events from the list or tag them for polling. Changes will be
		 * applied on next round.
		 */

		fdtab[fd].ev &= FD_POLL_STICKY;

		if ((eo & FD_EV_STATUS_R) == FD_EV_ACTIVE_R)
			fdtab[fd].ev |= FD_POLL_IN;

		if ((eo & FD_EV_STATUS_W) == FD_EV_ACTIVE_W)
			fdtab[fd].ev |= FD_POLL_OUT;

		if (fdtab[fd].iocb && fdtab[fd].owner && fdtab[fd].ev)
			fdtab[fd].iocb(fd);

		/* if the fd was removed from the spec list, it has been
		 * replaced by the next one that we don't want to skip !
		 */
		if (spec_idx < nbspec && spec_list[spec_idx] != fd)
			continue;

		spec_idx++;
	}

	in_poll_loop = 0;
	/* in the end, we have processed status + spec_processed FDs */
}

/*
 * Initialization of the speculative epoll() poller.
 * Returns 0 in case of failure, non-zero in case of success. If it fails, it
 * disables the poller by setting its pref to 0.
 */
REGPRM1 static int _do_init(struct poller *p)
{
	__label__ fail_spec, fail_ee, fail_fd;

	p->private = NULL;

	epoll_fd = epoll_create(global.maxsock + 1);
	if (epoll_fd < 0)
		goto fail_fd;

	/* See comments at the top of the file about this formula. */
	absmaxevents = MAX(global.tune.maxpollevents, global.maxsock);
	epoll_events = (struct epoll_event*)
		calloc(1, sizeof(struct epoll_event) * absmaxevents);

	if (epoll_events == NULL)
		goto fail_ee;

	if ((spec_list = (uint32_t *)calloc(1, sizeof(uint32_t) * global.maxsock)) == NULL)
		goto fail_spec;

	if ((updt_list = (uint32_t *)calloc(1, sizeof(uint32_t) * global.maxsock)) == NULL)
		goto fail_updt;

	return 1;

 fail_updt:
	free(spec_list);
 fail_spec:
	free(epoll_events);
 fail_ee:
	close(epoll_fd);
	epoll_fd = -1;
 fail_fd:
	p->pref = 0;
	return 0;
}

/*
 * Termination of the speculative epoll() poller.
 * Memory is released and the poller is marked as unselectable.
 */
REGPRM1 static void _do_term(struct poller *p)
{
	free(updt_list);
	free(spec_list);
	free(epoll_events);

	if (epoll_fd >= 0) {
		close(epoll_fd);
		epoll_fd = -1;
	}

	updt_list = NULL;
	spec_list = NULL;
	epoll_events = NULL;

	p->private = NULL;
	p->pref = 0;
}

/*
 * Check that the poller works.
 * Returns 1 if OK, otherwise 0.
 */
REGPRM1 static int _do_test(struct poller *p)
{
	int fd;

	fd = epoll_create(global.maxsock + 1);
	if (fd < 0)
		return 0;
	close(fd);
	return 1;
}

/*
 * Recreate the epoll file descriptor after a fork(). Returns 1 if OK,
 * otherwise 0. It will ensure that all processes will not share their
 * epoll_fd. Some side effects were encountered because of this, such
 * as epoll_wait() returning an FD which was previously deleted.
 */
REGPRM1 static int _do_fork(struct poller *p)
{
	if (epoll_fd >= 0)
		close(epoll_fd);
	epoll_fd = epoll_create(global.maxsock + 1);
	if (epoll_fd < 0)
		return 0;
	return 1;
}

/*
 * It is a constructor, which means that it will automatically be called before
 * main(). This is GCC-specific but it works at least since 2.95.
 * Special care must be taken so that it does not need any uninitialized data.
 */
__attribute__((constructor))
static void _do_register(void)
{
	struct poller *p;

	if (nbpollers >= MAX_POLLERS)
		return;

	epoll_fd = -1;
	p = &pollers[nbpollers++];

	p->name = "sepoll";
	p->pref = 400;
	p->private = NULL;

	p->test = _do_test;
	p->init = _do_init;
	p->term = _do_term;
	p->poll = _do_poll;
	p->fork = _do_fork;

	p->is_set  = __fd_is_set;
	p->set = __fd_set;
	p->wai = __fd_wai;
	p->clr = __fd_clr;
	p->rem = __fd_rem;
	p->clo = __fd_clo;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
