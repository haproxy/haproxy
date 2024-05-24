/*
 * FD polling functions for generic select()
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

#include <haproxy/activity.h>
#include <haproxy/api.h>
#include <haproxy/clock.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>


/* private data */
static int maxfd;   /* # of the highest fd + 1 */
static unsigned int *fd_evts[2];
static THREAD_LOCAL fd_set *tmp_evts[2];

/* Immediately remove the entry upon close() */
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
 * Select() poller
 */
static void _do_poll(struct poller *p, int exp, int wake)
{
	int status;
	int fd, i;
	struct timeval delta;
	int delta_ms;
	int fds;
	int updt_idx;
	char count;
	int readnotnull, writenotnull;
	int old_maxfd, new_maxfd, max_add_fd;
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

	/* let's restore fdset state */
	readnotnull = 0; writenotnull = 0;
	for (i = 0; i < (maxfd + FD_SETSIZE - 1)/(8*sizeof(int)); i++) {
		readnotnull |= (*(((int*)tmp_evts[DIR_RD])+i) = *(((int*)fd_evts[DIR_RD])+i)) != 0;
		writenotnull |= (*(((int*)tmp_evts[DIR_WR])+i) = *(((int*)fd_evts[DIR_WR])+i)) != 0;
	}

	/* now let's wait for events */
	delta_ms = wake ? 0 : compute_poll_timeout(exp);
	delta.tv_sec  = (delta_ms / 1000);
	delta.tv_usec = (delta_ms % 1000) * 1000;
	clock_entering_poll();
	status = select(maxfd,
			readnotnull ? tmp_evts[DIR_RD] : NULL,
			writenotnull ? tmp_evts[DIR_WR] : NULL,
			NULL,
			&delta);
	clock_update_date(delta_ms, status);
	fd_leaving_poll(delta_ms, status);

	if (status <= 0)
		return;

	activity[tid].poll_io++;

	for (fds = 0; (fds * BITS_PER_INT) < maxfd; fds++) {
		if ((((int *)(tmp_evts[DIR_RD]))[fds] | ((int *)(tmp_evts[DIR_WR]))[fds]) == 0)
			continue;

		for (count = BITS_PER_INT, fd = fds * BITS_PER_INT; count && fd < maxfd; count--, fd++) {
			unsigned int n = 0;

			if (FD_ISSET(fd, tmp_evts[DIR_RD]))
				n |= FD_EV_READY_R;

			if (FD_ISSET(fd, tmp_evts[DIR_WR]))
				n |= FD_EV_READY_W;

			if (!n)
				continue;

#ifdef DEBUG_FD
			_HA_ATOMIC_INC(&fdtab[fd].event_count);
#endif

			fd_update_events(fd, n);
		}
	}
}

static int init_select_per_thread()
{
	int fd_set_bytes;

	fd_set_bytes = sizeof(fd_set) * (global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE;
	tmp_evts[DIR_RD] = calloc(1, fd_set_bytes);
	if (tmp_evts[DIR_RD] == NULL)
		goto fail;
	vma_set_name_id(tmp_evts[DIR_RD], fd_set_bytes, "ev_select", "tmp_evts_rd", tid + 1);
	tmp_evts[DIR_WR] = calloc(1, fd_set_bytes);
	if (tmp_evts[DIR_WR] == NULL)
		goto fail;
	vma_set_name_id(tmp_evts[DIR_WR], fd_set_bytes, "ev_select", "tmp_evts_wr", tid + 1);
	return 1;
  fail:
	free(tmp_evts[DIR_RD]);
	free(tmp_evts[DIR_WR]);
	return 0;
}

static void deinit_select_per_thread()
{
	ha_free(&tmp_evts[DIR_WR]);
	ha_free(&tmp_evts[DIR_RD]);
}

/*
 * Initialization of the select() poller.
 * Returns 0 in case of failure, non-zero in case of success. If it fails, it
 * disables the poller by setting its pref to 0.
 */
static int _do_init(struct poller *p)
{
	int fd_set_bytes;

	p->private = NULL;

	/* this old poller uses a process-wide FD list that cannot work with
	 * groups.
	 */
	if (global.nbtgroups > 1)
		goto fail_srevt;

	if (global.maxsock > FD_SETSIZE)
		goto fail_srevt;

	fd_set_bytes = sizeof(fd_set) * (global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE;

	if ((fd_evts[DIR_RD] = calloc(1, fd_set_bytes)) == NULL)
		goto fail_srevt;
	vma_set_name(fd_evts[DIR_RD], fd_set_bytes, "ev_select", "fd_evts_rd");
	if ((fd_evts[DIR_WR] = calloc(1, fd_set_bytes)) == NULL)
		goto fail_swevt;
	vma_set_name(fd_evts[DIR_WR], fd_set_bytes, "ev_select", "fd_evts_wr");

	hap_register_per_thread_init(init_select_per_thread);
	hap_register_per_thread_deinit(deinit_select_per_thread);

	return 1;

 fail_swevt:
	free(fd_evts[DIR_RD]);
 fail_srevt:
	p->pref = 0;
	return 0;
}

/*
 * Termination of the select() poller.
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
	if (global.maxsock > FD_SETSIZE)
		return 0;

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

	p->name = "select";
	p->pref = 150;
	p->flags = 0;
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
