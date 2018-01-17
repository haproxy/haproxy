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
#include <common/ticks.h>
#include <common/time.h>

#include <types/global.h>

#include <proto/fd.h>


#ifndef POLLRDHUP
/* POLLRDHUP was defined late in libc, and it appeared in kernel 2.6.17 */
#define POLLRDHUP 0
#endif

static unsigned int *fd_evts[2];

/* private data */
static THREAD_LOCAL int nbfd = 0;
static THREAD_LOCAL struct pollfd *poll_events = NULL;

static inline void hap_fd_set(int fd, unsigned int *evts)
{
	evts[fd / (8*sizeof(*evts))] |= 1U << (fd & (8*sizeof(*evts) - 1));
}

static inline void hap_fd_clr(int fd, unsigned int *evts)
{
	evts[fd / (8*sizeof(*evts))] &= ~(1U << (fd & (8*sizeof(*evts) - 1)));
}

REGPRM1 static void __fd_clo(int fd)
{
	HA_SPIN_LOCK(POLL_LOCK, &poll_lock);
	hap_fd_clr(fd, fd_evts[DIR_RD]);
	hap_fd_clr(fd, fd_evts[DIR_WR]);
	HA_SPIN_UNLOCK(POLL_LOCK, &poll_lock);
}

/*
 * Poll() poller
 */
REGPRM2 static void _do_poll(struct poller *p, int exp)
{
	int status;
	int fd;
	int wait_time;
	int updt_idx, en, eo;
	int fds, count;
	int sr, sw;
	unsigned rn, wn; /* read new, write new */

	/* first, scan the update list to find changes */
	for (updt_idx = 0; updt_idx < fd_nbupdt; updt_idx++) {
		fd = fd_updt[updt_idx];

		if (!fdtab[fd].owner)
			continue;

		HA_SPIN_LOCK(FD_LOCK, &fdtab[fd].lock);
		fdtab[fd].updated = 0;
		fdtab[fd].new = 0;

		eo = fdtab[fd].state;
		en = fd_compute_new_polled_status(eo);
		fdtab[fd].state = en;
		HA_SPIN_UNLOCK(FD_LOCK, &fdtab[fd].lock);

		if ((eo ^ en) & FD_EV_POLLED_RW) {
			/* poll status changed, update the lists */
			HA_SPIN_LOCK(POLL_LOCK, &poll_lock);
			if ((eo & ~en) & FD_EV_POLLED_R)
				hap_fd_clr(fd, fd_evts[DIR_RD]);
			else if ((en & ~eo) & FD_EV_POLLED_R)
				hap_fd_set(fd, fd_evts[DIR_RD]);

			if ((eo & ~en) & FD_EV_POLLED_W)
				hap_fd_clr(fd, fd_evts[DIR_WR]);
			else if ((en & ~eo) & FD_EV_POLLED_W)
				hap_fd_set(fd, fd_evts[DIR_WR]);
			HA_SPIN_UNLOCK(POLL_LOCK, &poll_lock);
		}
	}
	fd_nbupdt = 0;

	nbfd = 0;
	for (fds = 0; (fds * 8*sizeof(**fd_evts)) < maxfd; fds++) {
		rn = fd_evts[DIR_RD][fds];
		wn = fd_evts[DIR_WR][fds];

		if (!(rn|wn))
			continue;

		for (count = 0, fd = fds * 8*sizeof(**fd_evts); count < 8*sizeof(**fd_evts) && fd < maxfd; count++, fd++) {

			if (!fdtab[fd].owner || !(fdtab[fd].thread_mask & tid_bit))
				continue;

			sr = (rn >> count) & 1;
			sw = (wn >> count) & 1;
			if ((sr|sw)) {
				poll_events[nbfd].fd = fd;
				poll_events[nbfd].events = (sr ? (POLLIN | POLLRDHUP) : 0) | (sw ? POLLOUT : 0);
				nbfd++;
			}
		}
	}

	/* now let's wait for events */
	if (!exp)
		wait_time = MAX_DELAY_MS;
	else if (tick_is_expired(exp, now_ms))
		wait_time = 0;
	else {
		wait_time = TICKS_TO_MS(tick_remain(now_ms, exp)) + 1;
		if (wait_time > MAX_DELAY_MS)
			wait_time = MAX_DELAY_MS;
	}

	gettimeofday(&before_poll, NULL);
	status = poll(poll_events, nbfd, wait_time);
	tv_update_date(wait_time, status);
	measure_idle();

	for (count = 0; status > 0 && count < nbfd; count++) {
		unsigned int n;
		int e = poll_events[count].revents;
		fd = poll_events[count].fd;

		if (!(e & ( POLLOUT | POLLIN | POLLERR | POLLHUP | POLLRDHUP )))
			continue;

		/* ok, we found one active fd */
		status--;

		if (!fdtab[fd].owner)
			continue;

		/* it looks complicated but gcc can optimize it away when constants
		 * have same values... In fact it depends on gcc :-(
		 */
		if (POLLIN == FD_POLL_IN && POLLOUT == FD_POLL_OUT &&
		    POLLERR == FD_POLL_ERR && POLLHUP == FD_POLL_HUP) {
			n = e & (POLLIN|POLLOUT|POLLERR|POLLHUP);
		}
		else {
			n =     ((e & POLLIN ) ? FD_POLL_IN  : 0) |
				((e & POLLOUT) ? FD_POLL_OUT : 0) |
				((e & POLLERR) ? FD_POLL_ERR : 0) |
				((e & POLLHUP) ? FD_POLL_HUP : 0);
		}

		/* always remap RDHUP to HUP as they're used similarly */
		if (e & POLLRDHUP) {
			HA_ATOMIC_OR(&cur_poller.flags, HAP_POLL_F_RDHUP);
			n |= FD_POLL_HUP;
		}
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
