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

#include <common/compat.h>
#include <common/config.h>
#include <common/hathreads.h>
#include <common/ticks.h>
#include <common/time.h>

#include <types/global.h>

#include <proto/activity.h>
#include <proto/fd.h>


#ifndef POLLRDHUP
/* POLLRDHUP was defined late in libc, and it appeared in kernel 2.6.17 */
#define POLLRDHUP 0
#endif

static int maxfd;   /* # of the highest fd + 1 */
static unsigned int *fd_evts[2];

/* private data */
static THREAD_LOCAL int nbfd = 0;
static THREAD_LOCAL struct pollfd *poll_events = NULL;

REGPRM1 static void __fd_clo(int fd)
{
	hap_fd_clr(fd, fd_evts[DIR_RD]);
	hap_fd_clr(fd, fd_evts[DIR_WR]);
}

static void _update_fd(int fd, int *max_add_fd)
{
	int en;

	en = fdtab[fd].state;

	/* we have a single state for all threads, which is why we
	 * don't check the tid_bit. First thread to see the update
	 * takes it for every other one.
	 */
	if (!(en & FD_EV_ACTIVE_RW)) {
		if (!(polled_mask[fd].poll_recv | polled_mask[fd].poll_send)) {
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
			if (polled_mask[fd].poll_recv & tid_bit)
				_HA_ATOMIC_AND(&polled_mask[fd].poll_recv, ~tid_bit);
		} else {
			hap_fd_set(fd, fd_evts[DIR_RD]);
			if (!(polled_mask[fd].poll_recv & tid_bit))
				_HA_ATOMIC_OR(&polled_mask[fd].poll_recv, tid_bit);
		}

		if (!(en & FD_EV_ACTIVE_W)) {
			hap_fd_clr(fd, fd_evts[DIR_WR]);
			if (polled_mask[fd].poll_send & tid_bit)
				_HA_ATOMIC_AND(&polled_mask[fd].poll_send, ~tid_bit);
		}else {
			hap_fd_set(fd, fd_evts[DIR_WR]);
			if (!(polled_mask[fd].poll_send & tid_bit))
				_HA_ATOMIC_OR(&polled_mask[fd].poll_send, tid_bit);
		}

		if (fd > *max_add_fd)
			*max_add_fd = fd;
	}
}

/*
 * Poll() poller
 */
REGPRM3 static void _do_poll(struct poller *p, int exp, int wake)
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

		_HA_ATOMIC_AND(&fdtab[fd].update_mask, ~tid_bit);
		if (!fdtab[fd].owner) {
			activity[tid].poll_drop++;
			continue;
		}
		_update_fd(fd, &max_add_fd);
	}

	/* Now scan the global update list */
	for (old_fd = fd = update_list.first; fd != -1; fd = fdtab[fd].update.next) {
		if (fd == -2) {
			fd = old_fd;
			continue;
		}
		else if (fd <= -3)
			fd = -fd -4;
		if (fd == -1)
			break;
		if (fdtab[fd].update_mask & tid_bit) {
			/* Cheat a bit, as the state is global to all pollers
			 * we don't need every thread ot take care of the
			 * update.
			 */
			_HA_ATOMIC_AND(&fdtab[fd].update_mask, ~all_threads_mask);
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

	thread_harmless_now();
	if (sleeping_thread_mask & tid_bit)
		_HA_ATOMIC_AND(&sleeping_thread_mask, ~tid_bit);

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

				if (!(fdtab[fd].thread_mask & tid_bit)) {
					activity[tid].poll_skip++;
					continue;
				}

				poll_events[nbfd].fd = fd;
				poll_events[nbfd].events = (sr ? (POLLIN | POLLRDHUP) : 0) | (sw ? POLLOUT : 0);
				nbfd++;
			}
		}
	}

	/* now let's wait for events */
	wait_time = wake ? 0 : compute_poll_timeout(exp);
	tv_entering_poll();
	activity_count_runtime();
	status = poll(poll_events, nbfd, wait_time);
	tv_update_date(wait_time, status);
	tv_leaving_poll(wait_time, status);

	thread_harmless_end();

	for (count = 0; status > 0 && count < nbfd; count++) {
		unsigned int n;
		int e = poll_events[count].revents;
		fd = poll_events[count].fd;

		if (!(e & ( POLLOUT | POLLIN | POLLERR | POLLHUP | POLLRDHUP )))
			continue;

		/* ok, we found one active fd */
		status--;

		if (!fdtab[fd].owner) {
			activity[tid].poll_dead++;
			continue;
		}

		n = ((e & POLLIN)    ? FD_EV_READY_R : 0) |
		    ((e & POLLOUT)   ? FD_EV_READY_W : 0) |
		    ((e & POLLRDHUP) ? FD_EV_SHUT_R  : 0) |
		    ((e & POLLHUP)   ? FD_EV_SHUT_RW : 0) |
		    ((e & POLLERR)   ? FD_EV_ERR_RW  : 0);

		if ((e & POLLRDHUP) && !(cur_poller.flags & HAP_POLL_F_RDHUP))
			_HA_ATOMIC_OR(&cur_poller.flags, HAP_POLL_F_RDHUP);

		fd_update_events(fd, n);
	}

}


static int init_poll_per_thread()
{
	poll_events = calloc(1, sizeof(struct pollfd) * global.maxsock);
	if (poll_events == NULL)
		return 0;
	return 1;
}

static void deinit_poll_per_thread()
{
	free(poll_events);
	poll_events = NULL;
}

/*
 * Initialization of the poll() poller.
 * Returns 0 in case of failure, non-zero in case of success. If it fails, it
 * disables the poller by setting its pref to 0.
 */
REGPRM1 static int _do_init(struct poller *p)
{
	__label__ fail_swevt, fail_srevt;
	int fd_evts_bytes;

	p->private = NULL;
	fd_evts_bytes = (global.maxsock + sizeof(**fd_evts) * 8 - 1) / (sizeof(**fd_evts) * 8) * sizeof(**fd_evts);

	if ((fd_evts[DIR_RD] = calloc(1, fd_evts_bytes)) == NULL)
		goto fail_srevt;
	if ((fd_evts[DIR_WR] = calloc(1, fd_evts_bytes)) == NULL)
		goto fail_swevt;

	hap_register_per_thread_init(init_poll_per_thread);
	hap_register_per_thread_deinit(deinit_poll_per_thread);

	return 1;

 fail_swevt:
	free(fd_evts[DIR_RD]);
 fail_srevt:
	free(poll_events);
	p->pref = 0;
	return 0;
}

/*
 * Termination of the poll() poller.
 * Memory is released and the poller is marked as unselectable.
 */
REGPRM1 static void _do_term(struct poller *p)
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
REGPRM1 static int _do_test(struct poller *p)
{
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

	p->name = "poll";
	p->pref = 200;
	p->flags = 0;
	p->private = NULL;

	p->clo  = __fd_clo;
	p->test = _do_test;
	p->init = _do_init;
	p->term = _do_term;
	p->poll = _do_poll;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
