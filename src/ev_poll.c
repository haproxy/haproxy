/*
 * FD polling functions for generic poll()
 *
 * Copyright 2000-2014 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#define _GNU_SOURCE  // for POLLRDHUP on Linux

#include <unistd.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/types.h>

#include <haproxy/activity.h>
#include <haproxy/api.h>
#include <haproxy/clock.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/signal.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>


#ifndef POLLRDHUP
/* POLLRDHUP was defined late in libc, and it appeared in kernel 2.6.17 */
#define POLLRDHUP 0
#endif

static int maxfd;   /* # of the highest fd + 1 */
static unsigned int *fd_evts[2];

/* private data */
static THREAD_LOCAL int nbfd = 0;
static THREAD_LOCAL struct pollfd *poll_events = NULL;

static void __fd_clo(int fd)
{
	hap_fd_clr(fd, fd_evts[DIR_RD]);
	hap_fd_clr(fd, fd_evts[DIR_WR]);
}

static void _update_fd(int fd, int *max_add_fd)
{
	int en;
	ulong pr, ps;

	en = fdtab[fd].state;
	pr = _HA_ATOMIC_LOAD(&polled_mask[fd].poll_recv);
	ps = _HA_ATOMIC_LOAD(&polled_mask[fd].poll_send);

	/* we have a single state for all threads, which is why we
	 * don't check the tid_bit. First thread to see the update
	 * takes it for every other one.
	 */
	if (!(en & FD_EV_ACTIVE_RW)) {
		if (!(pr | ps)) {
			/* fd was not watched, it's still not */
			return;
		}
		/* fd totally removed from poll list */
		hap_fd_clr(fd, fd_evts[DIR_RD]);
		hap_fd_clr(fd, fd_evts[DIR_WR]);
		_HA_ATOMIC_AND(&polled_mask[fd].poll_recv, 0);
		_HA_ATOMIC_AND(&polled_mask[fd].poll_send, 0);
	}
	else {
		/* OK fd has to be monitored, it was either added or changed */
		if (!(en & FD_EV_ACTIVE_R)) {
			hap_fd_clr(fd, fd_evts[DIR_RD]);
			if (pr & ti->ltid_bit)
				_HA_ATOMIC_AND(&polled_mask[fd].poll_recv, ~ti->ltid_bit);
		} else {
			hap_fd_set(fd, fd_evts[DIR_RD]);
			if (!(pr & ti->ltid_bit))
				_HA_ATOMIC_OR(&polled_mask[fd].poll_recv, ti->ltid_bit);
		}

		if (!(en & FD_EV_ACTIVE_W)) {
			hap_fd_clr(fd, fd_evts[DIR_WR]);
			if (ps & ti->ltid_bit)
				_HA_ATOMIC_AND(&polled_mask[fd].poll_send, ~ti->ltid_bit);
		} else {
			hap_fd_set(fd, fd_evts[DIR_WR]);
			if (!(ps & ti->ltid_bit))
				_HA_ATOMIC_OR(&polled_mask[fd].poll_send, ti->ltid_bit);
		}

		if (fd > *max_add_fd)
			*max_add_fd = fd;
	}
}

/*
 * Poll() poller
 */
static void _do_poll(struct poller *p, int exp, int wake)
{
	int status;
	int fd;
	int wait_time;
	int updt_idx;
	int fds, count;
	int sr, sw;
	int old_maxfd, new_maxfd, max_add_fd;
	unsigned rn, wn; /* read new, write new */
	int old_fd;

	max_add_fd = -1;

	/* first, scan the update list to find changes */
	for (updt_idx = 0; updt_idx < fd_nbupdt; updt_idx++) {
		fd = fd_updt[updt_idx];

		_HA_ATOMIC_AND(&fdtab[fd].update_mask, ~ti->ltid_bit);
		if (!fdtab[fd].owner) {
			activity[tid].poll_drop_fd++;
			continue;
		}
		_update_fd(fd, &max_add_fd);
	}

	/* Now scan the global update list */
	for (old_fd = fd = update_list[tgid - 1].first; fd != -1; fd = fdtab[fd].update.next) {
		if (fd == -2) {
			fd = old_fd;
			continue;
		}
		else if (fd <= -3)
			fd = -fd -4;
		if (fd == -1)
			break;
		if (fdtab[fd].update_mask & ti->ltid_bit) {
			/* Cheat a bit, as the state is global to all pollers
			 * we don't need every thread to take care of the
			 * update.
			 */
			_HA_ATOMIC_AND(&fdtab[fd].update_mask, ~tg->threads_enabled);
			done_update_polling(fd);
		} else
			continue;
		if (!fdtab[fd].owner)
			continue;
		_update_fd(fd, &max_add_fd);
	}

	/* maybe we added at least one fd larger than maxfd */
	for (old_maxfd = maxfd; old_maxfd <= max_add_fd; ) {
		if (_HA_ATOMIC_CAS(&maxfd, &old_maxfd, max_add_fd + 1))
			break;
	}

	/* maxfd doesn't need to be precise but it needs to cover *all* active
	 * FDs. Thus we only shrink it if we have such an opportunity. The algo
	 * is simple : look for the previous used place, try to update maxfd to
	 * point to it, abort if maxfd changed in the mean time.
	 */
	old_maxfd = maxfd;
	do {
		new_maxfd = old_maxfd;
		while (new_maxfd - 1 >= 0 && !fdtab[new_maxfd - 1].owner)
			new_maxfd--;
		if (new_maxfd >= old_maxfd)
			break;
	} while (!_HA_ATOMIC_CAS(&maxfd, &old_maxfd, new_maxfd));

	thread_idle_now();
	thread_harmless_now();

	fd_nbupdt = 0;

	nbfd = 0;
	for (fds = 0; (fds * 8*sizeof(**fd_evts)) < maxfd; fds++) {
		rn = fd_evts[DIR_RD][fds];
		wn = fd_evts[DIR_WR][fds];

		if (!(rn|wn))
			continue;

		for (count = 0, fd = fds * 8*sizeof(**fd_evts); count < 8*sizeof(**fd_evts) && fd < maxfd; count++, fd++) {
			sr = (rn >> count) & 1;
			sw = (wn >> count) & 1;
			if ((sr|sw)) {
				if (!fdtab[fd].owner) {
					/* should normally not happen here except
					 * due to rare thread concurrency
					 */
					continue;
				}

				if (!(fdtab[fd].thread_mask & ti->ltid_bit)) {
					continue;
				}

				poll_events[nbfd].fd = fd;
				poll_events[nbfd].events = (sr ? (POLLIN | POLLRDHUP) : 0) | (sw ? POLLOUT : 0);
				nbfd++;
			}
		}
	}

	/* Now let's wait for polled events. */
	wait_time = wake ? 0 : compute_poll_timeout(exp);
	clock_entering_poll();
	status = poll(poll_events, nbfd, wait_time);
	clock_update_date(wait_time, status);

	fd_leaving_poll(wait_time, status);

	if (status > 0)
		activity[tid].poll_io++;

	for (count = 0; status > 0 && count < nbfd; count++) {
		unsigned int n;
		int e = poll_events[count].revents;

		fd = poll_events[count].fd;

		if ((e & POLLRDHUP) && !(cur_poller.flags & HAP_POLL_F_RDHUP))
			_HA_ATOMIC_OR(&cur_poller.flags, HAP_POLL_F_RDHUP);

#ifdef DEBUG_FD
		_HA_ATOMIC_INC(&fdtab[fd].event_count);
#endif
		if (!(e & ( POLLOUT | POLLIN | POLLERR | POLLHUP | POLLRDHUP )))
			continue;

		/* ok, we found one active fd */
		status--;

		n = ((e & POLLIN)    ? FD_EV_READY_R : 0) |
		    ((e & POLLOUT)   ? FD_EV_READY_W : 0) |
		    ((e & POLLRDHUP) ? FD_EV_SHUT_R  : 0) |
		    ((e & POLLHUP)   ? FD_EV_SHUT_RW : 0) |
		    ((e & POLLERR)   ? FD_EV_ERR_RW  : 0);

		fd_update_events(fd, n);
	}
}


static int init_poll_per_thread()
{
	poll_events = calloc(1, sizeof(struct pollfd) * global.maxsock);
	if (poll_events == NULL)
		return 0;
	vma_set_name_id(poll_events, sizeof(struct pollfd) * global.maxsock,
	                "ev_poll", "poll_events", tid + 1);
	return 1;
}

static void deinit_poll_per_thread()
{
	ha_free(&poll_events);
}

/*
 * Initialization of the poll() poller.
 * Returns 0 in case of failure, non-zero in case of success. If it fails, it
 * disables the poller by setting its pref to 0.
 */
static int _do_init(struct poller *p)
{
	__label__ fail_swevt, fail_srevt;
	int fd_evts_bytes;

	p->private = NULL;

	/* this old poller uses a process-wide FD list that cannot work with
	 * groups.
	 */
	if (global.nbtgroups > 1)
		goto fail_srevt;

	fd_evts_bytes = (global.maxsock + sizeof(**fd_evts) * 8 - 1) / (sizeof(**fd_evts) * 8) * sizeof(**fd_evts);

	if ((fd_evts[DIR_RD] = calloc(1, fd_evts_bytes)) == NULL)
		goto fail_srevt;
	vma_set_name(fd_evts[DIR_RD], fd_evts_bytes, "ev_poll", "fd_evts_rd");
	if ((fd_evts[DIR_WR] = calloc(1, fd_evts_bytes)) == NULL)
		goto fail_swevt;
	vma_set_name(fd_evts[DIR_WR], fd_evts_bytes, "ev_poll", "fd_evts_wr");

	hap_register_per_thread_init(init_poll_per_thread);
	hap_register_per_thread_deinit(deinit_poll_per_thread);

	return 1;

 fail_swevt:
	free(fd_evts[DIR_RD]);
 fail_srevt:
	p->pref = 0;
	return 0;
}

/*
 * Termination of the poll() poller.
 * Memory is released and the poller is marked as unselectable.
 */
static void _do_term(struct poller *p)
{
	free(fd_evts[DIR_WR]);
	free(fd_evts[DIR_RD]);
	p->private = NULL;
	p->pref = 0;
}

/*
 * Check that the poller works.
 * Returns 1 if OK, otherwise 0.
 */
static int _do_test(struct poller *p)
{
	return 1;
}

/*
 * Registers the poller.
 */
static void _do_register(void)
{
	struct poller *p;

	if (nbpollers >= MAX_POLLERS)
		return;
	p = &pollers[nbpollers++];

	p->name = "poll";
	p->pref = 200;
	p->flags = HAP_POLL_F_ERRHUP;
	p->private = NULL;

	p->clo  = __fd_clo;
	p->test = _do_test;
	p->init = _do_init;
	p->term = _do_term;
	p->poll = _do_poll;
}

INITCALL0(STG_REGISTER, _do_register);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
