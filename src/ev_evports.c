/*
 * FD polling functions for SunOS event ports.
 *
 * Copyright 2018 Joyent, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#include <poll.h>
#include <port.h>
#include <errno.h>
#include <syslog.h>

#include <haproxy/activity.h>
#include <haproxy/api.h>
#include <haproxy/clock.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/signal.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>

/*
 * Private data:
 */
static int evports_fd[MAX_THREADS]; // per-thread evports_fd
static THREAD_LOCAL port_event_t *evports_evlist = NULL;
static THREAD_LOCAL int evports_evlist_max = 0;

/*
 * Convert the "state" member of "fdtab" into an event ports event mask.
 */
static inline int evports_state_to_events(int state)
{
	int events = 0;

	if (state & FD_EV_ACTIVE_W)
		events |= POLLOUT;
	if (state & FD_EV_ACTIVE_R)
		events |= POLLIN;

	return (events);
}

/*
 * Associate or dissociate this file descriptor with the event port, using the
 * specified event mask.
 */
static inline void evports_resync_fd(int fd, int events)
{
	if (events == 0)
		port_dissociate(evports_fd[tid], PORT_SOURCE_FD, fd);
	else
		port_associate(evports_fd[tid], PORT_SOURCE_FD, fd, events, NULL);
}

static void _update_fd(int fd)
{
	int en;
	int events;
	ulong pr, ps;

	en = fdtab[fd].state;
	pr = _HA_ATOMIC_LOAD(&polled_mask[fd].poll_recv);
	ps = _HA_ATOMIC_LOAD(&polled_mask[fd].poll_send);

	if (!(fdtab[fd].thread_mask & ti->ltid_bit) || !(en & FD_EV_ACTIVE_RW)) {
		if (!((pr | ps) & ti->ltid_bit)) {
			/* fd was not watched, it's still not */
			return;
		}
		/* fd totally removed from poll list */
		events = 0;
		if (pr & ti->ltid_bit)
			_HA_ATOMIC_AND(&polled_mask[fd].poll_recv, ~ti->ltid_bit);
		if (ps & ti->ltid_bit)
			_HA_ATOMIC_AND(&polled_mask[fd].poll_send, ~ti->ltid_bit);
	}
	else {
		/* OK fd has to be monitored, it was either added or changed */
		events = evports_state_to_events(en);
		if (en & FD_EV_ACTIVE_R) {
			if (!(pr & ti->ltid_bit))
				_HA_ATOMIC_OR(&polled_mask[fd].poll_recv, ti->ltid_bit);
		} else {
			if (pr & ti->ltid_bit)
				_HA_ATOMIC_AND(&polled_mask[fd].poll_recv, ~ti->ltid_bit);
		}
		if (en & FD_EV_ACTIVE_W) {
			if (!(ps & ti->ltid_bit))
				_HA_ATOMIC_OR(&polled_mask[fd].poll_send, ti->ltid_bit);
		} else {
			if (ps & ti->ltid_bit)
				_HA_ATOMIC_AND(&polled_mask[fd].poll_send, ~ti->ltid_bit);
		}

	}
	evports_resync_fd(fd, events);
}

/*
 * Event Ports poller.  This routine interacts with the file descriptor
 * management data structures and routines; see the large block comment in
 * "src/fd.c" for more information.
 */

static void _do_poll(struct poller *p, int exp, int wake)
{
	int i;
	int wait_time;
	struct timespec timeout_ts;
	unsigned int nevlist;
	int fd, old_fd;
	int status;

	/*
	 * Scan the list of file descriptors with an updated status:
	 */
	for (i = 0; i < fd_nbupdt; i++) {
		fd = fd_updt[i];

		if (!fd_grab_tgid(fd, tgid)) {
			/* was reassigned */
			activity[tid].poll_drop_fd++;
			continue;
		}

		_HA_ATOMIC_AND(&fdtab[fd].update_mask, ~ti->ltid_bit);

		if (fdtab[fd].owner)
			_update_fd(fd);
		else
			activity[tid].poll_drop_fd++;

		fd_drop_tgid(fd);
	}
	fd_nbupdt = 0;

	/* Scan the shared update list */
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
			_update_fd(fd);
		else
			activity[tid].poll_drop_fd++;

		fd_drop_tgid(fd);
	}

	thread_idle_now();
	thread_harmless_now();

	/* Now let's wait for polled events. */
	wait_time = wake ? 0 : compute_poll_timeout(exp);
	clock_entering_poll();

	do {
		int timeout = (global.tune.options & GTUNE_BUSY_POLLING) ? 0 : wait_time;
		int interrupted = 0;
		/* Note: normally we should probably expect to pass
		 * global.tune.maxpollevents here so as to process multiple
		 * events at once, but it appears unreliable in tests, even
		 * starting with value 2, and it seems basically nobody's
		 * using that anymore so it's probably not worth spending days
		 * investigating this poller more to improve its performance,
		 * let's switch back to 1. --WT
		 */
		nevlist = 1; /* desired number of events to be retrieved */
		timeout_ts.tv_sec  = (timeout / 1000);
		timeout_ts.tv_nsec = (timeout % 1000) * 1000000;

		status = port_getn(evports_fd[tid],
				   evports_evlist,
				   evports_evlist_max,
				   &nevlist, /* updated to the number of events retrieved */
				   &timeout_ts);

		/* Be careful, nevlist here is always updated by the syscall
		 * even on status == -1, so it must always be respected
		 * otherwise events are lost. Awkward API BTW, I wonder how
		 * they thought ENOSYS ought to be handled... -WT
		 */
		if (status != 0) {
			int e = errno;
			switch (e) {
			case ETIME:
				/*
				 * Though the manual page has not historically made it
				 * clear, port_getn() can return -1 with an errno of
				 * ETIME and still have returned some number of events.
				 */
				/* nevlist >= 0 */
				break;
			default:
				/* signal or anything else */
				interrupted = 1;
				break;
			}
		}
		clock_update_local_date(wait_time, (global.tune.options & GTUNE_BUSY_POLLING) ? 1 : nevlist);

		if (nevlist || interrupted)
			break;
		if (timeout || !wait_time)
			break;
		if (tick_isset(exp) && tick_is_expired(exp, now_ms))
			break;
	} while(1);

	clock_update_global_date();
	fd_leaving_poll(wait_time, nevlist);

	if (nevlist > 0)
		activity[tid].poll_io++;

	for (i = 0; i < nevlist; i++) {
		unsigned int n = 0;
		int events, rebind_events;
		int ret;

		fd = evports_evlist[i].portev_object;
		events = evports_evlist[i].portev_events;

#ifdef DEBUG_FD
		_HA_ATOMIC_INC(&fdtab[fd].event_count);
#endif
		/*
		 * By virtue of receiving an event for this file descriptor, it
		 * is no longer associated with the port in question.  Store
		 * the previous event mask so that we may reassociate after
		 * processing is complete.
		 */
		rebind_events = evports_state_to_events(fdtab[fd].state);
		/* rebind_events != 0 */

		/*
		 * Set bits based on the events we received from the port:
		 */
		n = ((events & POLLIN)  ? FD_EV_READY_R : 0) |
		    ((events & POLLOUT) ? FD_EV_READY_W : 0) |
		    ((events & POLLHUP) ? FD_EV_SHUT_RW : 0) |
		    ((events & POLLERR) ? FD_EV_ERR_RW  : 0);

		/*
		 * Call connection processing callbacks.  Note that it's
		 * possible for this processing to alter the required event
		 * port association; i.e., the "state" member of the "fdtab"
		 * entry.  If it changes, the fd will be placed on the updated
		 * list for processing the next time we are called.
		 */
		ret = fd_update_events(fd, n);

		/* polling will be on this instance if the FD was migrated */
		if (ret == FD_UPDT_MIGRATED)
			continue;

		/*
		 * This file descriptor was closed during the processing of
		 * polled events.  No need to reassociate.
		 */
		if (ret == FD_UPDT_CLOSED)
			continue;

		/*
		 * Reassociate with the port, using the same event mask as
		 * before.  This call will not result in a dissociation as we
		 * asserted that _some_ events needed to be rebound above.
		 *
		 * Reassociating with the same mask allows us to mimic the
		 * level-triggered behaviour of poll(2).  In the event that we
		 * are interested in the same events on the next turn of the
		 * loop, this represents no extra work.
		 *
		 * If this additional port_associate(3C) call becomes a
		 * performance problem, we would need to verify that we can
		 * correctly interact with the file descriptor cache and update
		 * list (see "src/fd.c") to avoid reassociating here, or to use
		 * a different events mask.
		 */
		evports_resync_fd(fd, rebind_events);
	}
}

static int init_evports_per_thread()
{
	evports_evlist_max = global.tune.maxpollevents;
	evports_evlist = calloc(evports_evlist_max, sizeof(*evports_evlist));
	if (evports_evlist == NULL) {
		goto fail_alloc;
	}

	if (MAX_THREADS > 1 && tid) {
		if ((evports_fd[tid] = port_create()) == -1) {
			goto fail_fd;
		}
	}

	/* we may have to unregister some events initially registered on the
	 * original fd when it was alone, and/or to register events on the new
	 * fd for this thread. Let's just mark them as updated, the poller will
	 * do the rest.
	 */
	fd_reregister_all(tgid, ti->ltid_bit);

	return 1;

 fail_fd:
	ha_free(&evports_evlist);
	evports_evlist_max = 0;
 fail_alloc:
	return 0;
}

static void deinit_evports_per_thread()
{
	if (MAX_THREADS > 1 && tid)
		close(evports_fd[tid]);

	ha_free(&evports_evlist);
	evports_evlist_max = 0;
}

/*
 * Initialisation of the event ports poller.
 * Returns 0 in case of failure, non-zero in case of success.
 */
static int _do_init(struct poller *p)
{
	p->private = NULL;

	if ((evports_fd[tid] = port_create()) == -1) {
		goto fail;
	}

	hap_register_per_thread_init(init_evports_per_thread);
	hap_register_per_thread_deinit(deinit_evports_per_thread);

	return 1;

fail:
	p->pref = 0;
	return 0;
}

/*
 * Termination of the event ports poller.
 * All resources are released and the poller is marked as inoperative.
 */
static void _do_term(struct poller *p)
{
	if (evports_fd[tid] != -1) {
		close(evports_fd[tid]);
		evports_fd[tid] = -1;
	}

	p->private = NULL;
	p->pref = 0;

	ha_free(&evports_evlist);
	evports_evlist_max = 0;
}

/*
 * Run-time check to make sure we can allocate the resources needed for
 * the poller to function correctly.
 * Returns 1 on success, otherwise 0.
 */
static int _do_test(struct poller *p)
{
	int fd;

	if ((fd = port_create()) == -1) {
		return 0;
	}

	close(fd);
	return 1;
}

/*
 * Close and recreate the event port after fork().  Returns 1 on success,
 * otherwise 0.  If this function fails, "_do_term()" must be called to
 * clean up the poller.
 */
static int _do_fork(struct poller *p)
{
	if (evports_fd[tid] != -1) {
		close(evports_fd[tid]);
	}

	if ((evports_fd[tid] = port_create()) == -1) {
		return 0;
	}

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
		evports_fd[i] = -1;

	p = &pollers[nbpollers++];

	p->name = "evports";
	p->pref = 300;
	p->flags = HAP_POLL_F_ERRHUP;
	p->private = NULL;

	p->clo  = NULL;
	p->test = _do_test;
	p->init = _do_init;
	p->term = _do_term;
	p->poll = _do_poll;
	p->fork = _do_fork;
}

INITCALL0(STG_REGISTER, _do_register);
