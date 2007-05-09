/*
 * FD polling functions for Speculative I/O combined with Linux epoll()
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/standard.h>
#include <common/time.h>

#include <types/fd.h>
#include <types/global.h>

#include <proto/fd.h>
#include <proto/task.h>

#if defined(USE_MY_EPOLL)
#include <common/epoll.h>
#include <errno.h>
#include <sys/syscall.h>
static _syscall1 (int, epoll_create, int, size);
static _syscall4 (int, epoll_ctl, int, epfd, int, op, int, fd, struct epoll_event *, event);
static _syscall4 (int, epoll_wait, int, epfd, struct epoll_event *, events, int, maxevents, int, timeout);
#else
#include <sys/epoll.h>
#endif

/*
 * We define 4 states for each direction of a file descriptor, which we store
 * as 2 bits :
 *
 *  00 = IDLE : we're not interested in this event
 *  01 = SPEC : perform speculative I/O on this FD
 *  10 = WAIT : really wait for an availability event on this FD (poll)
 *  11 = STOP : was marked WAIT, but disabled. It can switch back to WAIT if
 *              the application changes its mind, otherwise disable FD polling
 *              and switch back to IDLE.
 *
 * Since we do not want to scan all the FD list to find speculative I/O events,
 * we store them in a list consisting in a linear array holding only the FD
 * indexes right now.
 *
 * The STOP state requires the event to be present in the spec list so that
 * it can be detected and flushed upon next scan without having to scan the
 * whole FD list.
 *
 * This translates like this :
 *
 *   EVENT_IN_SPEC_LIST = 01
 *   EVENT_IN_POLL_LIST = 10
 *
 *   IDLE = 0
 *   SPEC = (EVENT_IN_SPEC_LIST)
 *   WAIT = (EVENT_IN_POLL_LIST)
 *   STOP = (EVENT_IN_SPEC_LIST|EVENT_IN_POLL_LIST)
 *
 * fd_is_set() just consists in checking that the status is 01 or 10.
 *
 * For efficiency reasons, we will store the Read and Write bits interlaced to
 * form a 4-bit field, so that we can simply shift the value right by 0/1 and
 * get what we want :
 *    3  2  1  0
 *   Wp Rp Ws Rs
 *
 * The FD array has to hold a back reference to the speculative list. This
 * reference is only valid if at least one of the directions is marked SPEC.
 *
 */

#define FD_EV_IN_SL	1
#define FD_EV_IN_PL	4

#define FD_EV_IDLE	0
#define FD_EV_SPEC	(FD_EV_IN_SL)
#define FD_EV_WAIT	(FD_EV_IN_PL)
#define FD_EV_STOP	(FD_EV_IN_SL|FD_EV_IN_PL)

/* Those match any of R or W for Spec list or Poll list */
#define FD_EV_RW_SL	(FD_EV_IN_SL | (FD_EV_IN_SL << 1))
#define FD_EV_RW_PL	(FD_EV_IN_PL | (FD_EV_IN_PL << 1))
#define FD_EV_MASK_DIR	(FD_EV_IN_SL|FD_EV_IN_PL)

#define FD_EV_IDLE_R	0
#define FD_EV_SPEC_R	(FD_EV_IN_SL)
#define FD_EV_WAIT_R	(FD_EV_IN_PL)
#define FD_EV_STOP_R	(FD_EV_IN_SL|FD_EV_IN_PL)
#define FD_EV_MASK_R	(FD_EV_IN_SL|FD_EV_IN_PL)

#define FD_EV_IDLE_W	(FD_EV_IDLE_R << 1)
#define FD_EV_SPEC_W	(FD_EV_SPEC_R << 1)
#define FD_EV_WAIT_W	(FD_EV_WAIT_R << 1)
#define FD_EV_STOP_W	(FD_EV_STOP_R << 1)
#define FD_EV_MASK_W	(FD_EV_MASK_R << 1)

#define FD_EV_MASK	(FD_EV_MASK_W | FD_EV_MASK_R)


/* descriptor of one FD.
 * FIXME: should be a bit field */
struct fd_status {
	unsigned int e:4;       // read and write events status.
	unsigned int s:28;      // Position in spec list. Should be last.
};

static int nbspec = 0;          // current size of the spec list

static struct fd_status *fd_list = NULL;	// list of FDs
static unsigned int *spec_list = NULL;	// speculative I/O list

/* private data */
static struct epoll_event *epoll_events;
static int epoll_fd;

/* This structure may be used for any purpose. Warning! do not use it in
 * recursive functions !
 */
static struct epoll_event ev;


REGPRM1 static void alloc_spec_entry(const int fd)
{
	if (fd_list[fd].e & FD_EV_RW_SL)
		return;
	fd_list[fd].s = nbspec;
	spec_list[nbspec++] = fd;
}

/* removes entry <pos> from the spec list and replaces it with the last one.
 * The fd_list is adjusted to match the back reference if needed.
 */
REGPRM1 static void delete_spec_entry(const int pos)
{
	int fd;

	nbspec--;
	if (pos == nbspec)
		return;

	/* we replace current FD by the highest one */
	fd = spec_list[nbspec];
	spec_list[pos] = fd;
	fd_list[fd].s = pos;
}

/*
 * Returns non-zero if <fd> is already monitored for events in direction <dir>.
 */
REGPRM2 static int __fd_is_set(const int fd, int dir)
{
	int ret;

	ret = ((unsigned)fd_list[fd].e >> dir) & FD_EV_MASK_DIR;
	return (ret == FD_EV_SPEC || ret == FD_EV_WAIT);
}

/*
 * Don't worry about the strange constructs in __fd_set/__fd_clr, they are
 * designed like this in order to reduce the number of jumps (verified).
 */
REGPRM2 static int __fd_set(const int fd, int dir)
{
	__label__ switch_state;
	unsigned int i;

	i = ((unsigned)fd_list[fd].e >> dir) & FD_EV_MASK_DIR;

	if (i == FD_EV_IDLE) {
		// switch to SPEC state and allocate a SPEC entry.
		alloc_spec_entry(fd);
	switch_state:
		fd_list[fd].e ^= (unsigned int)(FD_EV_IN_SL << dir);
		return 1;
	}
	else if (i == FD_EV_STOP) {
		// switch to WAIT state
		goto switch_state;
	}
	else
		return 0;
}

REGPRM2 static int __fd_clr(const int fd, int dir)
{
	__label__ switch_state;
	unsigned int i;

	i = ((unsigned)fd_list[fd].e >> dir) & FD_EV_MASK_DIR;

	if (i == FD_EV_SPEC) {
		// switch to IDLE state
		goto switch_state;
	}
	else if (likely(i == FD_EV_WAIT)) {
		// switch to STOP state
		/* We will create a queue entry for this one because we want to
		 * process it later in order to merge it with other events on
		 * the same FD.
		 */
		alloc_spec_entry(fd);
	switch_state:
		fd_list[fd].e ^= (unsigned int)(FD_EV_IN_SL << dir);
		return 1;
	}
	return 0;
}

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
	if (fd_list[fd].e & FD_EV_RW_SL)
		delete_spec_entry(fd_list[fd].s);
	fd_list[fd].e &= ~(FD_EV_MASK);
}

/*
 * operations to perform when reaching _do_poll() for some FDs in the spec
 * queue depending on their state. This is mainly used to cleanup some FDs
 * which are in STOP state. It is also used to compute EPOLL* flags when
 * switching from SPEC to WAIT.
 */
static struct ev_to_epoll {
	char op;        // epoll opcode to switch from spec to wait, 0 if none
	char m;         // inverted mask for existing events
	char ev;        // remaining epoll events after change
	char pad;
} ev_to_epoll[16] = {
	[FD_EV_IDLE_W | FD_EV_STOP_R] = { .op=EPOLL_CTL_DEL, .m=FD_EV_MASK_R },
	[FD_EV_SPEC_W | FD_EV_STOP_R] = { .op=EPOLL_CTL_DEL, .m=FD_EV_MASK_R },
	[FD_EV_STOP_W | FD_EV_IDLE_R] = { .op=EPOLL_CTL_DEL, .m=FD_EV_MASK_W },
	[FD_EV_STOP_W | FD_EV_SPEC_R] = { .op=EPOLL_CTL_DEL, .m=FD_EV_MASK_W },
	[FD_EV_WAIT_W | FD_EV_STOP_R] = { .op=EPOLL_CTL_MOD, .m=FD_EV_MASK_R, .ev=EPOLLOUT },
	[FD_EV_STOP_W | FD_EV_WAIT_R] = { .op=EPOLL_CTL_MOD, .m=FD_EV_MASK_W, .ev=EPOLLIN },
	[FD_EV_STOP_W | FD_EV_STOP_R] = { .op=EPOLL_CTL_DEL, .m=FD_EV_MASK_R|FD_EV_MASK_W },
	[FD_EV_SPEC_W | FD_EV_WAIT_R] = { .ev=EPOLLIN },
	[FD_EV_WAIT_W | FD_EV_SPEC_R] = { .ev=EPOLLOUT },
	[FD_EV_WAIT_W | FD_EV_WAIT_R] = { .ev=EPOLLIN|EPOLLOUT },
};

/*
 * speculative epoll() poller
 */
REGPRM2 static void _do_poll(struct poller *p, int wait_time)
{
	static unsigned int last_skipped;
	int status;
	int fd, opcode;
	int count;
	int spec_idx;


	/* Here we have two options :
	 * - either walk the list forwards and hope to atch more events
	 * - or walk it backwards to minimize the number of changes and
	 *   to make better use of the cache.
	 * Tests have shown that walking backwards improves perf by 0.2%.
	 */

	spec_idx = nbspec;
	while (likely(spec_idx > 0)) {
		spec_idx--;
		fd = spec_list[spec_idx];

		opcode = ev_to_epoll[fd_list[fd].e].op;
		if (opcode) {
			ev.data.fd = fd;
			ev.events  = ev_to_epoll[fd_list[fd].e].ev;
			fd_list[fd].e &= ~(unsigned int)ev_to_epoll[fd_list[fd].e].m;
			epoll_ctl(epoll_fd, opcode, fd, &ev);
		}

		if (!(fd_list[fd].e & FD_EV_RW_SL)) {
			// This one must be removed. Let's clear it now.
			delete_spec_entry(spec_idx);
			continue;
		}

		/* OK so now we do not have any event marked STOP anymore in
		 * the list. We can simply try to execute functions for the
		 * events we have found, and requeue them in case of EAGAIN.
		 */

		status = 0;
		fdtab[fd].ev = 0;

		if ((fd_list[fd].e & FD_EV_MASK_R) == FD_EV_SPEC_R) {
			if (fdtab[fd].state != FD_STCLOSE && fdtab[fd].state != FD_STERROR) {
				fdtab[fd].ev |= FD_POLL_IN;
				if (fdtab[fd].cb[DIR_RD].f(fd) == 0)
					status |= EPOLLIN;
			}
		}
		
		if ((fd_list[fd].e & FD_EV_MASK_W) == FD_EV_SPEC_W) {
			if (fdtab[fd].state != FD_STCLOSE && fdtab[fd].state != FD_STERROR) {
				fdtab[fd].ev |= FD_POLL_OUT;
				if (fdtab[fd].cb[DIR_WR].f(fd) == 0)
					status |= EPOLLOUT;
			}
		}

		if (status) {
			/* Some speculative accesses have failed, we must
			 * switch to the WAIT state.
			 */
			ev.events = status;
			ev.data.fd = fd;
			if (fd_list[fd].e & FD_EV_RW_PL) {
				// Event already in poll list
				ev.events |= ev_to_epoll[fd_list[fd].e].ev;
				opcode = EPOLL_CTL_MOD;
			} else {
				// Event not in poll list yet
				opcode = EPOLL_CTL_ADD;
			}
			epoll_ctl(epoll_fd, opcode, fd, &ev);

			if (status & EPOLLIN) {
				fd_list[fd].e &= ~FD_EV_MASK_R;
				fd_list[fd].e |= FD_EV_WAIT_R;
			}
			if (status & EPOLLOUT) {
				fd_list[fd].e &= ~FD_EV_MASK_W;
				fd_list[fd].e |= FD_EV_WAIT_W;
			}

			if ((fd_list[fd].e & FD_EV_MASK_R) != FD_EV_SPEC_R &&
			    (fd_list[fd].e & FD_EV_MASK_W) != FD_EV_SPEC_W) {
				delete_spec_entry(spec_idx);
				continue;
			}
		}
	}

	/* If some speculative events remain, we must not set the timeout in
	 * epoll_wait(). Also, if some speculative events remain, it means
	 * that some have been immediately processed, otherwise they would
	 * have been disabled.
	 */
	if (nbspec) {
		if (!last_skipped++) {
			/* Measures have shown a great performance increase if
			 * we call the epoll_wait() only the second time after
			 * speculative accesses have succeeded. This reduces
			 * the number of unsucessful calls to epoll_wait() by
			 * a factor of about 3, and the total number of calls
			 * by about 2.
			 */
			tv_now(&now);
			return;
		}
		wait_time = 0;
	}
	last_skipped = 0;

	/* now let's wait for events */
	status = epoll_wait(epoll_fd, epoll_events, maxfd, wait_time);
	tv_now(&now);

	for (count = 0; count < status; count++) {
		int e = epoll_events[count].events;
		fd = epoll_events[count].data.fd;

		/* it looks complicated but gcc can optimize it away when constants
		 * have same values.
		 */
		fdtab[fd].ev = 
			((e & EPOLLIN ) ? FD_POLL_IN  : 0) |
			((e & EPOLLPRI) ? FD_POLL_PRI : 0) |
			((e & EPOLLOUT) ? FD_POLL_OUT : 0) |
			((e & EPOLLERR) ? FD_POLL_ERR : 0) |
			((e & EPOLLHUP) ? FD_POLL_HUP : 0);
		
		if ((fd_list[fd].e & FD_EV_MASK_R) == FD_EV_WAIT_R) {
			if (fdtab[fd].state == FD_STCLOSE || fdtab[fd].state == FD_STERROR)
				continue;
			if (fdtab[fd].ev & (FD_POLL_RD|FD_POLL_HUP|FD_POLL_ERR))
				fdtab[fd].cb[DIR_RD].f(fd);
		}

		if ((fd_list[fd].e & FD_EV_MASK_W) == FD_EV_WAIT_W) {
			if (fdtab[fd].state == FD_STCLOSE || fdtab[fd].state == FD_STERROR)
				continue;
			if (fdtab[fd].ev & (FD_POLL_WR|FD_POLL_ERR))
				fdtab[fd].cb[DIR_WR].f(fd);
		}
	}
}

/*
 * Initialization of the speculative epoll() poller.
 * Returns 0 in case of failure, non-zero in case of success. If it fails, it
 * disables the poller by setting its pref to 0.
 */
REGPRM1 static int _do_init(struct poller *p)
{
	__label__ fail_fd_list, fail_spec, fail_ee, fail_fd;

	p->private = NULL;

	epoll_fd = epoll_create(global.maxsock + 1);
	if (epoll_fd < 0)
		goto fail_fd;

	epoll_events = (struct epoll_event*)
		calloc(1, sizeof(struct epoll_event) * global.maxsock);

	if (epoll_events == NULL)
		goto fail_ee;

	if ((spec_list = (uint32_t *)calloc(1, sizeof(uint32_t) * global.maxsock)) == NULL)
		goto fail_spec;

	fd_list = (struct fd_status *)calloc(1, sizeof(struct fd_status) * global.maxsock);
	if (fd_list == NULL)
		goto fail_fd_list;

	return 1;

 fail_fd_list:
	free(spec_list);
 fail_spec:
	free(epoll_events);
 fail_ee:
	close(epoll_fd);
	epoll_fd = 0;
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
	if (fd_list)
		free(fd_list);
	if (spec_list)
		free(spec_list);
	if (epoll_events)
		free(epoll_events);

	close(epoll_fd);
	epoll_fd = 0;

	fd_list = NULL;
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
	p = &pollers[nbpollers++];

	p->name = "sepoll";
	p->pref = 400;
	p->private = NULL;

	p->test = _do_test;
	p->init = _do_init;
	p->term = _do_term;
	p->poll = _do_poll;

	p->is_set  = __fd_is_set;
	p->cond_s = p->set = __fd_set;
	p->cond_c = p->clr = __fd_clr;
	p->rem = __fd_rem;
	p->clo = __fd_clo;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
