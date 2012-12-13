/*
 * FD polling functions for Linux epoll
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
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


static int absmaxevents = 0;    // absolute maximum amounts of polled events

/* private data */
static struct epoll_event *epoll_events;
static int epoll_fd;

/* This structure may be used for any purpose. Warning! do not use it in
 * recursive functions !
 */
static struct epoll_event ev;

/*
 * speculative epoll() poller
 */
REGPRM2 static void _do_poll(struct poller *p, int exp)
{
	int status, eo, en;
	int fd, opcode;
	int count;
	int updt_idx;
	int wait_time;

	/* first, scan the update list to find changes */
	for (updt_idx = 0; updt_idx < fd_nbupdt; updt_idx++) {
		fd = fd_updt[updt_idx];
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
	fd_nbupdt = 0;

	/* compute the epoll_wait() timeout */

	if (fd_nbspec || run_queue || signal_queue_len) {
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

	/* process polled events */

	for (count = 0; count < status; count++) {
		unsigned char n;
		unsigned char e = epoll_events[count].events;
		fd = epoll_events[count].data.fd;

		if (!fdtab[fd].owner)
			continue;

		/* it looks complicated but gcc can optimize it away when constants
		 * have same values... In fact it depends on gcc :-(
		 */
		fdtab[fd].ev &= FD_POLL_STICKY;
		if (EPOLLIN == FD_POLL_IN && EPOLLOUT == FD_POLL_OUT &&
		    EPOLLPRI == FD_POLL_PRI && EPOLLERR == FD_POLL_ERR &&
		    EPOLLHUP == FD_POLL_HUP) {
			n = e & (EPOLLIN|EPOLLOUT|EPOLLPRI|EPOLLERR|EPOLLHUP);
		}
		else {
			n =	((e & EPOLLIN ) ? FD_POLL_IN  : 0) |
				((e & EPOLLPRI) ? FD_POLL_PRI : 0) |
				((e & EPOLLOUT) ? FD_POLL_OUT : 0) |
				((e & EPOLLERR) ? FD_POLL_ERR : 0) |
				((e & EPOLLHUP) ? FD_POLL_HUP : 0);
		}

		if (!n)
			continue;

		fdtab[fd].ev |= n;

		if (fdtab[fd].iocb) {
			int new_updt, old_updt;

			/* Mark the events as speculative before processing
			 * them so that if nothing can be done we don't need
			 * to poll again.
			 */
			if (fdtab[fd].ev & FD_POLL_IN)
				fd_ev_set(fd, DIR_RD);

			if (fdtab[fd].ev & FD_POLL_OUT)
				fd_ev_set(fd, DIR_WR);

			if (fdtab[fd].spec_p) {
				/* This fd was already scheduled for being called as a speculative I/O */
				continue;
			}

			/* Save number of updates to detect creation of new FDs. */
			old_updt = fd_nbupdt;
			fdtab[fd].iocb(fd);

			/* One or more fd might have been created during the iocb().
			 * This mainly happens with new incoming connections that have
			 * just been accepted, so we'd like to process them immediately
			 * for better efficiency. Second benefit, if at the end the fds
			 * are disabled again, we can safely destroy their update entry
			 * to reduce the scope of later scans. This is the reason we
			 * scan the new entries backwards.
			 */

			for (new_updt = fd_nbupdt; new_updt > old_updt; new_updt--) {
				fd = fd_updt[new_updt - 1];
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
				if (new_updt == fd_nbupdt && fdtab[fd].spec_e == 0) {
					fdtab[fd].updated = 0;
					fd_nbupdt--;
				}
			}
		}
	}

	/* the caller will take care of speculative events */
}

/*
 * Initialization of the speculative epoll() poller.
 * Returns 0 in case of failure, non-zero in case of success. If it fails, it
 * disables the poller by setting its pref to 0.
 */
REGPRM1 static int _do_init(struct poller *p)
{
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

	return 1;

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
	free(epoll_events);

	if (epoll_fd >= 0) {
		close(epoll_fd);
		epoll_fd = -1;
	}

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

	p->name = "epoll";
	p->pref = 300;
	p->private = NULL;

	p->clo  = NULL;
	p->test = _do_test;
	p->init = _do_init;
	p->term = _do_term;
	p->poll = _do_poll;
	p->fork = _do_fork;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
