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
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/types.h>

#include <haproxy/activity.h>
#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/clock.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/signal.h>
#include <haproxy/ticks.h>
#include <haproxy/task.h>
#include <haproxy/tools.h>


/* private data */
static THREAD_LOCAL struct epoll_event *epoll_events = NULL;
static int epoll_fd[MAX_THREADS] __read_mostly; // per-thread epoll_fd
static uint epoll_mask = 0; // events to be masked and turned to EPOLLIN

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
static void __fd_clo(int fd)
{
	if (unlikely(fdtab[fd].state & FD_CLONED)) {
		unsigned long m = _HA_ATOMIC_LOAD(&polled_mask[fd].poll_recv) | _HA_ATOMIC_LOAD(&polled_mask[fd].poll_send);
		int tgrp = fd_tgid(fd);
		struct epoll_event ev;
		int i;

		if (!m)
			return;

		/* since FDs may only be shared per group and are only closed
		 * once entirely reset, it should never happen that we have to
		 * close an FD for another group, unless we're stopping from the
		 * wrong thread or during startup, which is what we're checking
		 * for. Regardless, it is not a problem to do so.
		 */
		if (unlikely(!(global.mode & MODE_STARTING))) {
			CHECK_IF(tgid != tgrp && !thread_isolated());
		}

		for (i = ha_tgroup_info[tgrp-1].base; i < ha_tgroup_info[tgrp-1].base + ha_tgroup_info[tgrp-1].count; i++)
			if (m & ha_thread_info[i].ltid_bit)
				epoll_ctl(epoll_fd[i], EPOLL_CTL_DEL, fd, &ev);
	}
}

static void _update_fd(int fd)
{
	int en, opcode;
	struct epoll_event ev = { };
	ulong pr, ps;

	en = fdtab[fd].state;
	pr = _HA_ATOMIC_LOAD(&polled_mask[fd].poll_recv);
	ps = _HA_ATOMIC_LOAD(&polled_mask[fd].poll_send);

	/* Try to force EPOLLET on FDs that support it */
	if (fdtab[fd].state & FD_ET_POSSIBLE) {
		/* already done ? */
		if (pr & ps & ti->ltid_bit)
			return;

		/* enable ET polling in both directions */
		_HA_ATOMIC_OR(&polled_mask[fd].poll_recv, ti->ltid_bit);
		_HA_ATOMIC_OR(&polled_mask[fd].poll_send, ti->ltid_bit);
		opcode = EPOLL_CTL_ADD;
		ev.events = EPOLLIN | EPOLLRDHUP | EPOLLOUT | EPOLLET;
		goto done;
	}

	/* if we're already polling or are going to poll for this FD and it's
	 * neither active nor ready, force it to be active so that we don't
	 * needlessly unsubscribe then re-subscribe it.
	 */
	if (!(en & (FD_EV_READY_R | FD_EV_SHUT_R | FD_EV_ERR_RW | FD_POLL_ERR)) &&
	    ((en & FD_EV_ACTIVE_W) || ((ps | pr) & ti->ltid_bit)))
		en |= FD_EV_ACTIVE_R;

	if ((ps | pr) & ti->ltid_bit) {
		if (!(fdtab[fd].thread_mask & ti->ltid_bit) || !(en & FD_EV_ACTIVE_RW)) {
			/* fd removed from poll list */
			opcode = EPOLL_CTL_DEL;
			if (pr & ti->ltid_bit)
				_HA_ATOMIC_AND(&polled_mask[fd].poll_recv, ~ti->ltid_bit);
			if (ps & ti->ltid_bit)
				_HA_ATOMIC_AND(&polled_mask[fd].poll_send, ~ti->ltid_bit);
		}
		else {
			if (((en & FD_EV_ACTIVE_R) != 0) == ((pr & ti->ltid_bit) != 0) &&
			    ((en & FD_EV_ACTIVE_W) != 0) == ((ps & ti->ltid_bit) != 0))
				return;
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
			/* fd status changed */
			opcode = EPOLL_CTL_MOD;
		}
	}
	else if ((fdtab[fd].thread_mask & ti->ltid_bit) && (en & FD_EV_ACTIVE_RW)) {
		/* new fd in the poll list */
		opcode = EPOLL_CTL_ADD;
		if (en & FD_EV_ACTIVE_R)
			_HA_ATOMIC_OR(&polled_mask[fd].poll_recv, ti->ltid_bit);
		if (en & FD_EV_ACTIVE_W)
			_HA_ATOMIC_OR(&polled_mask[fd].poll_send, ti->ltid_bit);
	}
	else {
		return;
	}

	/* construct the epoll events based on new state */
	if (en & FD_EV_ACTIVE_R)
		ev.events |= EPOLLIN | EPOLLRDHUP;

	if (en & FD_EV_ACTIVE_W)
		ev.events |= EPOLLOUT;

 done:
	ev.events &= ~epoll_mask;
	ev.data.u64 = ((u64)fdtab[fd].generation << 32) + fd;
	epoll_ctl(epoll_fd[tid], opcode, fd, &ev);
}

/*
 * Linux epoll() poller
 */
static void _do_poll(struct poller *p, int exp, int wake)
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

		status = epoll_wait(epoll_fd[tid], epoll_events, global.tune.maxpollevents, timeout);
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

	/* process polled events */

	for (count = 0; count < status; count++) {
		unsigned int n, e;
		uint64_t epoll_data;
		uint ev_gen, fd_gen;

		e = epoll_events[count].events;
		epoll_data = epoll_events[count].data.u64;

		/* epoll_data contains the fd's generation in the 32 upper bits
		 * and the fd in the 32 lower ones.
		 */
		fd = (uint32_t)epoll_data;
		ev_gen = epoll_data >> 32;
		fd_gen = _HA_ATOMIC_LOAD(&fdtab[fd].generation);

		if (unlikely(ev_gen != fd_gen)) {
			/* this is a stale report for an older instance of this FD,
			 * we must ignore it.
			 */

			if (_HA_ATOMIC_LOAD(&fdtab[fd].owner)) {
				ulong tmask = _HA_ATOMIC_LOAD(&fdtab[fd].thread_mask);
				if (!(tmask & ti->ltid_bit)) {
					/* thread has change. quite common, that's already handled
					 * by fd_update_events(), let's just report sensitivive
					 * events for statistics purposes.
					 */
					if (e & (EPOLLRDHUP|EPOLLHUP|EPOLLERR))
						COUNT_IF(1, "epoll report of HUP/ERR on a stale fd reopened on another thread (harmless)");
				} else {
					/* same thread but different generation, this smells bad,
					 * maybe that could be caused by crossed takeovers with a
					 * close() in between or something like this, but this is
					 * something fd_update_events() cannot detect. It still
					 * remains relatively safe for HUP because we consider it
					 * once we've read all pending data.
					 */
					if (e & EPOLLERR)
						COUNT_IF(1, "epoll report of ERR on a stale fd reopened on the same thread (suspicious)");
					else if (e & (EPOLLRDHUP|EPOLLHUP))
						COUNT_IF(1, "epoll report of HUP on a stale fd reopened on the same thread (suspicious)");
					else
						COUNT_IF(1, "epoll report of a harmless event on a stale fd reopened on the same thread (suspicious)");
				}
			} else if (ev_gen + 1 != fd_gen) {
				COUNT_IF(1, "epoll report of event on a closed recycled fd (rare)");
			} else {
				COUNT_IF(1, "epoll report of event on a just closed fd (harmless)");
			}
			continue;
		}

		if ((e & EPOLLRDHUP) && !(cur_poller.flags & HAP_POLL_F_RDHUP))
			_HA_ATOMIC_OR(&cur_poller.flags, HAP_POLL_F_RDHUP);

#ifdef DEBUG_FD
		_HA_ATOMIC_INC(&fdtab[fd].event_count);
#endif
		if (e & epoll_mask) {
			e |= EPOLLIN;
			e &= ~epoll_mask;
		}

		n = ((e & EPOLLIN)    ? FD_EV_READY_R : 0) |
		    ((e & EPOLLOUT)   ? FD_EV_READY_W : 0) |
		    ((e & EPOLLRDHUP) ? FD_EV_SHUT_R  : 0) |
		    ((e & EPOLLHUP)   ? FD_EV_SHUT_RW : 0) |
		    ((e & EPOLLERR)   ? FD_EV_ERR_RW  : 0);

		fd_update_events(fd, n);
	}
	/* the caller will take care of cached events */
}

static int init_epoll_per_thread()
{
	epoll_events = calloc(1, sizeof(struct epoll_event) * global.tune.maxpollevents);
	if (epoll_events == NULL)
		goto fail_alloc;
	vma_set_name_id(epoll_events, sizeof(struct epoll_event) * global.tune.maxpollevents,
	                "ev_epoll", "epoll_events", tid + 1);

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
	fd_reregister_all(tgid, ti->ltid_bit);

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

	ha_free(&epoll_events);
}

/*
 * Initialization of the epoll() poller.
 * Returns 0 in case of failure, non-zero in case of success. If it fails, it
 * disables the poller by setting its pref to 0.
 */
static int _do_init(struct poller *p)
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
static void _do_term(struct poller *p)
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
static int _do_test(struct poller *p)
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
static int _do_fork(struct poller *p)
{
	if (epoll_fd[tid] >= 0)
		close(epoll_fd[tid]);
	epoll_fd[tid] = epoll_create(global.maxsock + 1);
	if (epoll_fd[tid] < 0)
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
		epoll_fd[i] = -1;

	p = &pollers[nbpollers++];

	p->name = "epoll";
	p->pref = 300;
	p->flags = HAP_POLL_F_ERRHUP; // note: RDHUP might be dynamically added
	p->private = NULL;

	p->clo  = __fd_clo;
	p->test = _do_test;
	p->init = _do_init;
	p->term = _do_term;
	p->poll = _do_poll;
	p->fork = _do_fork;
}

/* config parser for global "tune.epoll.mask-events", accepts "err", "hup", "rdhup" */
static int cfg_parse_tune_epoll_mask_events(char **args, int section_type, struct proxy *curpx,
                                            const struct proxy *defpx, const char *file, int line,
                                            char **err)
{
	char *comma, *kw;

	if (too_many_args(1, args, err, NULL))
		return -1;

	epoll_mask = 0;
	for (kw = args[1]; kw && *kw; kw = comma) {
		comma = strchr(kw, ',');
		if (comma)
			*(comma++) = 0;

		if (strcmp(kw, "err") == 0)
			epoll_mask |= EPOLLERR;
		else if (strcmp(kw, "hup") == 0)
			epoll_mask |= EPOLLHUP;
		else if (strcmp(kw, "rdhup") == 0)
			epoll_mask |= EPOLLRDHUP;
		else {
			memprintf(err, "'%s' expects a comma-delimited list of 'err', 'hup' and 'rdhup' but got '%s'.", args[0], kw);
			return -1;
		}
	}
	return 0;
}

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.epoll.mask-events",   cfg_parse_tune_epoll_mask_events },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
INITCALL0(STG_REGISTER, _do_register);


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
