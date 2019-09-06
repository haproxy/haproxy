/*
 * FD polling functions for Linux epoll
 *
 * Copyright 2000-2014 Willy Tarreau <w@1wt.eu>
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
#include <common/hathreads.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>
#include <common/tools.h>

#include <types/global.h>

#include <proto/activity.h>
#include <proto/fd.h>
#include <proto/signal.h>


/* private data */
static THREAD_LOCAL struct epoll_event *epoll_events = NULL;
static int epoll_fd[MAX_THREADS]; // per-thread epoll_fd

/* This structure may be used for any purpose. Warning! do not use it in
 * recursive functions !
 */
static THREAD_LOCAL struct epoll_event ev;

#ifndef EPOLLRDHUP
/* EPOLLRDHUP was defined late in libc, and it appeared in kernel 2.6.17 */
#define EPOLLRDHUP 0x2000
#endif

/*
 * Immediately remove file descriptor from epoll set upon close.
 * Since we forked, some fds share inodes with the other process, and epoll may
 * send us events even though this process closed the fd (see man 7 epoll,
 * "Questions and answers", Q 6).
 */
REGPRM1 static void __fd_clo(int fd)
{
	if (unlikely(fdtab[fd].cloned)) {
		unsigned long m = polled_mask[fd].poll_recv | polled_mask[fd].poll_send;
		int i;

		for (i = global.nbthread - 1; i >= 0; i--)
			if (m & (1UL << i))
				epoll_ctl(epoll_fd[i], EPOLL_CTL_DEL, fd, &ev);
	}
}

static void _update_fd(int fd)
{
	int en, opcode;

	en = fdtab[fd].state;

	if ((polled_mask[fd].poll_send | polled_mask[fd].poll_recv) & tid_bit) {
		if (!(fdtab[fd].thread_mask & tid_bit) || !(en & FD_EV_ACTIVE_RW)) {
			/* fd removed from poll list */
			opcode = EPOLL_CTL_DEL;
			if (polled_mask[fd].poll_recv & tid_bit)
				_HA_ATOMIC_AND(&polled_mask[fd].poll_recv, ~tid_bit);
			if (polled_mask[fd].poll_send & tid_bit)
				_HA_ATOMIC_AND(&polled_mask[fd].poll_send, ~tid_bit);
		}
		else {
			if (((en & FD_EV_ACTIVE_R) != 0) ==
			    ((polled_mask[fd].poll_recv & tid_bit) != 0) &&
			    ((en & FD_EV_ACTIVE_W) != 0) ==
			    ((polled_mask[fd].poll_send & tid_bit) != 0))
				return;
			if (en & FD_EV_ACTIVE_R) {
				if (!(polled_mask[fd].poll_recv & tid_bit))
					_HA_ATOMIC_OR(&polled_mask[fd].poll_recv, tid_bit);
			} else {
				if (polled_mask[fd].poll_recv & tid_bit)
					_HA_ATOMIC_AND(&polled_mask[fd].poll_recv, ~tid_bit);
			}
			if (en & FD_EV_ACTIVE_W) {
				if (!(polled_mask[fd].poll_send & tid_bit))
					_HA_ATOMIC_OR(&polled_mask[fd].poll_send, tid_bit);
			} else {
				if (polled_mask[fd].poll_send & tid_bit)
					_HA_ATOMIC_AND(&polled_mask[fd].poll_send, ~tid_bit);
			}
			/* fd status changed */
			opcode = EPOLL_CTL_MOD;
		}
	}
	else if ((fdtab[fd].thread_mask & tid_bit) && (en & FD_EV_ACTIVE_RW)) {
		/* new fd in the poll list */
		opcode = EPOLL_CTL_ADD;
		if (en & FD_EV_ACTIVE_R)
			_HA_ATOMIC_OR(&polled_mask[fd].poll_recv, tid_bit);
		if (en & FD_EV_ACTIVE_W)
			_HA_ATOMIC_OR(&polled_mask[fd].poll_send, tid_bit);
	}
	else {
		return;
	}

	/* construct the epoll events based on new state */
	ev.events = 0;
	if (en & FD_EV_ACTIVE_R)
		ev.events |= EPOLLIN | EPOLLRDHUP;

	if (en & FD_EV_ACTIVE_W)
		ev.events |= EPOLLOUT;

	ev.data.fd = fd;
	epoll_ctl(epoll_fd[tid], opcode, fd, &ev);
}

/*
 * Linux epoll() poller
 */
REGPRM3 static void _do_poll(struct poller *p, int exp, int wake)
{
	int status;
	int fd;
	int count;
	int updt_idx;
	int wait_time;
	int old_fd;

	/* first, scan the update list to find polling changes */
	for (updt_idx = 0; updt_idx < fd_nbupdt; updt_idx++) {
		fd = fd_updt[updt_idx];

		_HA_ATOMIC_AND(&fdtab[fd].update_mask, ~tid_bit);
		if (!fdtab[fd].owner) {
			activity[tid].poll_drop++;
			continue;
		}

		_update_fd(fd);
	}
	fd_nbupdt = 0;
	/* Scan the global update list */
	for (old_fd = fd = update_list.first; fd != -1; fd = fdtab[fd].update.next) {
		if (fd == -2) {
			fd = old_fd;
			continue;
		}
		else if (fd <= -3)
			fd = -fd -4;
		if (fd == -1)
			break;
		if (fdtab[fd].update_mask & tid_bit)
			done_update_polling(fd);
		else
			continue;
		if (!fdtab[fd].owner)
			continue;
		_update_fd(fd);
	}

	thread_harmless_now();

	/* now let's wait for polled events */
	wait_time = wake ? 0 : compute_poll_timeout(exp);
	tv_entering_poll();
	activity_count_runtime();
	do {
		int timeout = (global.tune.options & GTUNE_BUSY_POLLING) ? 0 : wait_time;

		status = epoll_wait(epoll_fd[tid], epoll_events, global.tune.maxpollevents, timeout);
		tv_update_date(timeout, status);

		if (status)
			break;
		if (timeout || !wait_time)
			break;
		if (signal_queue_len || wake)
			break;
		if (tick_isset(exp) && tick_is_expired(exp, now_ms))
			break;
	} while (1);

	tv_leaving_poll(wait_time, status);

	thread_harmless_end();
	if (sleeping_thread_mask & tid_bit)
		_HA_ATOMIC_AND(&sleeping_thread_mask, ~tid_bit);

	/* process polled events */

	for (count = 0; count < status; count++) {
		unsigned int n;
		unsigned int e = epoll_events[count].events;
		fd = epoll_events[count].data.fd;

		if (!fdtab[fd].owner) {
			activity[tid].poll_dead++;
			continue;
		}

		if (!(fdtab[fd].thread_mask & tid_bit)) {
			/* FD has been migrated */
			activity[tid].poll_skip++;
			epoll_ctl(epoll_fd[tid], EPOLL_CTL_DEL, fd, &ev);
			_HA_ATOMIC_AND(&polled_mask[fd].poll_recv, ~tid_bit);
			_HA_ATOMIC_AND(&polled_mask[fd].poll_send, ~tid_bit);
			continue;
		}

		n = ((e & EPOLLIN)    ? FD_EV_READY_R : 0) |
		    ((e & EPOLLOUT)   ? FD_EV_READY_W : 0) |
		    ((e & EPOLLRDHUP) ? FD_EV_SHUT_R  : 0) |
		    ((e & EPOLLHUP)   ? FD_EV_SHUT_RW : 0) |
		    ((e & EPOLLERR)   ? FD_EV_ERR_RW  : 0);

		if ((e & EPOLLRDHUP) && !(cur_poller.flags & HAP_POLL_F_RDHUP))
			_HA_ATOMIC_OR(&cur_poller.flags, HAP_POLL_F_RDHUP);

		fd_update_events(fd, n);
	}
	/* the caller will take care of cached events */
}

static int init_epoll_per_thread()
{
	int fd;

	epoll_events = calloc(1, sizeof(struct epoll_event) * global.tune.maxpollevents);
	if (epoll_events == NULL)
		goto fail_alloc;

	if (MAX_THREADS > 1 && tid) {
		epoll_fd[tid] = epoll_create(global.maxsock + 1);
		if (epoll_fd[tid] < 0)
			goto fail_fd;
	}

	/* we may have to unregister some events initially registered on the
	 * original fd when it was alone, and/or to register events on the new
	 * fd for this thread. Let's just mark them as updated, the poller will
	 * do the rest.
	 */
	for (fd = 0; fd < global.maxsock; fd++)
		updt_fd_polling(fd);

	return 1;
 fail_fd:
	free(epoll_events);
 fail_alloc:
	return 0;
}

static void deinit_epoll_per_thread()
{
	if (MAX_THREADS > 1 && tid)
		close(epoll_fd[tid]);

	free(epoll_events);
	epoll_events = NULL;
}

/*
 * Initialization of the epoll() poller.
 * Returns 0 in case of failure, non-zero in case of success. If it fails, it
 * disables the poller by setting its pref to 0.
 */
REGPRM1 static int _do_init(struct poller *p)
{
	p->private = NULL;

	epoll_fd[tid] = epoll_create(global.maxsock + 1);
	if (epoll_fd[tid] < 0)
		goto fail_fd;

	hap_register_per_thread_init(init_epoll_per_thread);
	hap_register_per_thread_deinit(deinit_epoll_per_thread);

	return 1;

 fail_fd:
	p->pref = 0;
	return 0;
}

/*
 * Termination of the epoll() poller.
 * Memory is released and the poller is marked as unselectable.
 */
REGPRM1 static void _do_term(struct poller *p)
{
	if (epoll_fd[tid] >= 0) {
		close(epoll_fd[tid]);
		epoll_fd[tid] = -1;
	}

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
	if (epoll_fd[tid] >= 0)
		close(epoll_fd[tid]);
	epoll_fd[tid] = epoll_create(global.maxsock + 1);
	if (epoll_fd[tid] < 0)
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
	int i;

	if (nbpollers >= MAX_POLLERS)
		return;

	for (i = 0; i < MAX_THREADS; i++)
		epoll_fd[i] = -1;

	p = &pollers[nbpollers++];

	p->name = "epoll";
	p->pref = 300;
	p->flags = 0;
	p->private = NULL;

	p->clo  = __fd_clo;
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
