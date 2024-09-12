/*
 * FD polling functions for FreeBSD kqueue()
 *
 * Copyright 2000-2014 Willy Tarreau <w@1wt.eu>
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

#include <sys/event.h>
#include <sys/time.h>

#include <haproxy/activity.h>
#include <haproxy/api.h>
#include <haproxy/clock.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/signal.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>


/* private data */
static int kqueue_fd[MAX_THREADS] __read_mostly; // per-thread kqueue_fd
static THREAD_LOCAL struct kevent *kev = NULL;
static struct kevent *kev_out = NULL; // Trash buffer for kevent() to write the eventlist in

static int _update_fd(int fd, int start)
{
	int en;
	int changes = start;
	ulong pr, ps;

	en = fdtab[fd].state;
	pr = _HA_ATOMIC_LOAD(&polled_mask[fd].poll_recv);
	ps = _HA_ATOMIC_LOAD(&polled_mask[fd].poll_send);

	if (!(fdtab[fd].thread_mask & ti->ltid_bit) || !(en & FD_EV_ACTIVE_RW)) {
		if (!((pr | ps) & ti->ltid_bit)) {
			/* fd was not watched, it's still not */
			return changes;
		}
		/* fd totally removed from poll list */
		EV_SET(&kev[changes++], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
		EV_SET(&kev[changes++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
		if (pr & ti->ltid_bit)
			_HA_ATOMIC_AND(&polled_mask[fd].poll_recv, ~ti->ltid_bit);
		if (ps & ti->ltid_bit)
			_HA_ATOMIC_AND(&polled_mask[fd].poll_send, ~ti->ltid_bit);
	}
	else {
		/* OK fd has to be monitored, it was either added or changed */

		if (en & FD_EV_ACTIVE_R) {
			if (!(pr & ti->ltid_bit)) {
				EV_SET(&kev[changes++], fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
				_HA_ATOMIC_OR(&polled_mask[fd].poll_recv, ti->ltid_bit);
			}
		}
		else if (pr & ti->ltid_bit) {
			EV_SET(&kev[changes++], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
			HA_ATOMIC_AND(&polled_mask[fd].poll_recv, ~ti->ltid_bit);
		}

		if (en & FD_EV_ACTIVE_W) {
			if (!(ps & ti->ltid_bit)) {
				EV_SET(&kev[changes++], fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
				_HA_ATOMIC_OR(&polled_mask[fd].poll_send, ti->ltid_bit);
			}
		}
		else if (ps & ti->ltid_bit) {
			EV_SET(&kev[changes++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
			_HA_ATOMIC_AND(&polled_mask[fd].poll_send, ~ti->ltid_bit);
		}

	}
	return changes;
}

/*
 * kqueue() poller
 */
static void _do_poll(struct poller *p, int exp, int wake)
{
	int status;
	int count, fd, wait_time;
	struct timespec timeout_ts;
	int updt_idx;
	int changes = 0;
	int old_fd;

	timeout_ts.tv_sec  = 0;
	timeout_ts.tv_nsec = 0;
	/* first, scan the update list to find changes */
	for (updt_idx = 0; updt_idx < fd_nbupdt; updt_idx++) {
		fd = fd_updt[updt_idx];

		if (!fd_grab_tgid(fd, tgid)) {
			/* was reassigned */
			activity[tid].poll_drop_fd++;
			continue;
		}

		_HA_ATOMIC_AND(&fdtab[fd].update_mask, ~ti->ltid_bit);

		if (fdtab[fd].owner)
			changes = _update_fd(fd, changes);
		else
			activity[tid].poll_drop_fd++;

		fd_drop_tgid(fd);
	}
	/* Scan the global update list */
	for (old_fd = fd = update_list[tgid - 1].first; fd != -1; fd = fdtab[fd].update.next) {
		if (fd == -2) {
			fd = old_fd;
			continue;
		}
		else if (fd <= -3)
			fd = -fd -4;
		if (fd == -1)
			break;

		if (!fd_grab_tgid(fd, tgid)) {
			/* was reassigned */
			activity[tid].poll_drop_fd++;
			continue;
		}

		if (!(fdtab[fd].update_mask & ti->ltid_bit)) {
			fd_drop_tgid(fd);
			continue;
		}

		done_update_polling(fd);

		if (fdtab[fd].owner)
			changes = _update_fd(fd, changes);
		else
			activity[tid].poll_drop_fd++;

		fd_drop_tgid(fd);
	}

	thread_idle_now();
	thread_harmless_now();

	if (changes) {
#ifdef EV_RECEIPT
		kev[0].flags |= EV_RECEIPT;
#else
		/* If EV_RECEIPT isn't defined, just add an invalid entry,
		 * so that we get an error and kevent() stops before scanning
		 * the kqueue.
		 */
		EV_SET(&kev[changes++], -1, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
#endif
		kevent(kqueue_fd[tid], kev, changes, kev_out, changes, &timeout_ts);
	}
	fd_nbupdt = 0;

	/* Now let's wait for polled events. */
	wait_time = wake ? 0 : compute_poll_timeout(exp);
	fd = global.tune.maxpollevents;
	clock_entering_poll();

	do {
		int timeout = (global.tune.options & GTUNE_BUSY_POLLING) ? 0 : wait_time;

		timeout_ts.tv_sec  = (timeout / 1000);
		timeout_ts.tv_nsec = (timeout % 1000) * 1000000;

		status = kevent(kqueue_fd[tid], // int kq
		                NULL,      // const struct kevent *changelist
		                0,         // int nchanges
		                kev,       // struct kevent *eventlist
		                fd,        // int nevents
		                &timeout_ts); // const struct timespec *timeout
		clock_update_local_date(wait_time, (global.tune.options & GTUNE_BUSY_POLLING) ? 1 : status);

		if (status) {
			activity[tid].poll_io++;
			break;
		}
		if (timeout || !wait_time)
			break;
		if (tick_isset(exp) && tick_is_expired(exp, now_ms))
			break;
	} while (1);

	clock_update_global_date();
	fd_leaving_poll(wait_time, status);

	for (count = 0; count < status; count++) {
		unsigned int n = 0;

		fd = kev[count].ident;

#ifdef DEBUG_FD
		_HA_ATOMIC_INC(&fdtab[fd].event_count);
#endif
		if (kev[count].filter == EVFILT_READ) {
			if (kev[count].data || !(kev[count].flags & EV_EOF))
				n |= FD_EV_READY_R;
			if (kev[count].flags & EV_EOF)
				n |= FD_EV_SHUT_R;
		}
		else if (kev[count].filter == EVFILT_WRITE) {
			n |= FD_EV_READY_W;
			if (kev[count].flags & EV_EOF)
				n |= FD_EV_ERR_RW;
		}

		fd_update_events(fd, n);
	}
}


static int init_kqueue_per_thread()
{
	/* we can have up to two events per fd, so allocate enough to store
	 * 2*fd event, and an extra one, in case EV_RECEIPT isn't defined,
	 * so that we can add an invalid entry and get an error, to avoid
	 * scanning the kqueue uselessly.
	 */
	kev = calloc(1, sizeof(struct kevent) * (2 * global.maxsock + 1));
	if (kev == NULL)
		goto fail_alloc;

	if (MAX_THREADS > 1 && tid) {
		kqueue_fd[tid] = kqueue();
		if (kqueue_fd[tid] < 0)
			goto fail_fd;
	}

	/* we may have to unregister some events initially registered on the
	 * original fd when it was alone, and/or to register events on the new
	 * fd for this thread. Let's just mark them as updated, the poller will
	 * do the rest.
	 */
	fd_reregister_all(tgid, ti->ltid_bit);

	return 1;
 fail_fd:
	free(kev);
 fail_alloc:
	return 0;
}

static void deinit_kqueue_per_thread()
{
	if (MAX_THREADS > 1 && tid)
		close(kqueue_fd[tid]);

	ha_free(&kev);
}

/*
 * Initialization of the kqueue() poller.
 * Returns 0 in case of failure, non-zero in case of success. If it fails, it
 * disables the poller by setting its pref to 0.
 */
static int _do_init(struct poller *p)
{
	p->private = NULL;

	/* we can have up to two events per fd, so allocate enough to store
	 * 2*fd event, and an extra one, in case EV_RECEIPT isn't defined,
	 * so that we can add an invalid entry and get an error, to avoid
	 * scanning the kqueue uselessly.
	 */
	kev_out = calloc(1, sizeof(struct kevent) * (2 * global.maxsock + 1));
	if (!kev_out)
		goto fail_alloc;

	kqueue_fd[tid] = kqueue();
	if (kqueue_fd[tid] < 0)
		goto fail_fd;

	hap_register_per_thread_init(init_kqueue_per_thread);
	hap_register_per_thread_deinit(deinit_kqueue_per_thread);
	return 1;

 fail_fd:
	ha_free(&kev_out);
fail_alloc:
	p->pref = 0;
	return 0;
}

/*
 * Termination of the kqueue() poller.
 * Memory is released and the poller is marked as unselectable.
 */
static void _do_term(struct poller *p)
{
	if (kqueue_fd[tid] >= 0) {
		close(kqueue_fd[tid]);
		kqueue_fd[tid] = -1;
	}

	p->private = NULL;
	p->pref = 0;
	if (kev_out) {
		ha_free(&kev_out);
	}
}

/*
 * Check that the poller works.
 * Returns 1 if OK, otherwise 0.
 */
static int _do_test(struct poller *p)
{
	int fd;

	fd = kqueue();
	if (fd < 0)
		return 0;
	close(fd);
	return 1;
}

/*
 * Recreate the kqueue file descriptor after a fork(). Returns 1 if OK,
 * otherwise 0. Note that some pollers need to be reopened after a fork()
 * (such as kqueue), and some others may fail to do so in a chroot.
 */
static int _do_fork(struct poller *p)
{
	kqueue_fd[tid] = kqueue();
	if (kqueue_fd[tid] < 0)
		return 0;
	return 1;
}

/*
 * Registers the poller.
 */
static void _do_register(void)
{
	struct poller *p;
	int i;

	if (nbpollers >= MAX_POLLERS)
		return;

	for (i = 0; i < MAX_THREADS; i++)
		kqueue_fd[i] = -1;

	p = &pollers[nbpollers++];

	p->name = "kqueue";
	p->pref = 300;
	p->flags = HAP_POLL_F_RDHUP | HAP_POLL_F_ERRHUP;
	p->private = NULL;

	p->clo  = NULL;
	p->test = _do_test;
	p->init = _do_init;
	p->term = _do_term;
	p->poll = _do_poll;
	p->fork = _do_fork;
}

INITCALL0(STG_REGISTER, _do_register);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
