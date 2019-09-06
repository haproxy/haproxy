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

#include <common/compat.h>
#include <common/config.h>
#include <common/hathreads.h>
#include <common/ticks.h>
#include <common/time.h>

#include <types/global.h>

#include <proto/activity.h>
#include <proto/fd.h>


/* private data */
static int maxfd;   /* # of the highest fd + 1 */
static unsigned int *fd_evts[2];
static THREAD_LOCAL fd_set *tmp_evts[2];

/* Immediately remove the entry upon close() */
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
		} else {
			hap_fd_set(fd, fd_evts[DIR_WR]);
			if (!(polled_mask[fd].poll_send & tid_bit))
				_HA_ATOMIC_OR(&polled_mask[fd].poll_send, tid_bit);
		}

		if (fd > *max_add_fd)
			*max_add_fd = fd;
	}
}

/*
 * Select() poller
 */
REGPRM3 static void _do_poll(struct poller *p, int exp, int wake)
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
	tv_entering_poll();
	activity_count_runtime();
	status = select(maxfd,
			readnotnull ? tmp_evts[DIR_RD] : NULL,
			writenotnull ? tmp_evts[DIR_WR] : NULL,
			NULL,
			&delta);
	tv_update_date(delta_ms, status);
	tv_leaving_poll(delta_ms, status);

	thread_harmless_end();
	if (sleeping_thread_mask & tid_bit)
		_HA_ATOMIC_AND(&sleeping_thread_mask, ~tid_bit);

	if (status <= 0)
		return;

	for (fds = 0; (fds * BITS_PER_INT) < maxfd; fds++) {
		if ((((int *)(tmp_evts[DIR_RD]))[fds] | ((int *)(tmp_evts[DIR_WR]))[fds]) == 0)
			continue;

		for (count = BITS_PER_INT, fd = fds * BITS_PER_INT; count && fd < maxfd; count--, fd++) {
			unsigned int n = 0;

			if (!fdtab[fd].owner) {
				activity[tid].poll_dead++;
				continue;
			}

			if (!(fdtab[fd].thread_mask & tid_bit)) {
				activity[tid].poll_skip++;
				continue;
			}

			if (FD_ISSET(fd, tmp_evts[DIR_RD]))
				n |= FD_EV_READY_R;

			if (FD_ISSET(fd, tmp_evts[DIR_WR]))
				n |= FD_EV_READY_W;

			fd_update_events(fd, n);
		}
	}
}

static int init_select_per_thread()
{
	int fd_set_bytes;

	fd_set_bytes = sizeof(fd_set) * (global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE;
	if ((tmp_evts[DIR_RD] = (fd_set *)calloc(1, fd_set_bytes)) == NULL)
		goto fail;
	if ((tmp_evts[DIR_WR] = (fd_set *)calloc(1, fd_set_bytes)) == NULL)
		goto fail;
	return 1;
  fail:
	free(tmp_evts[DIR_RD]);
	free(tmp_evts[DIR_WR]);
	return 0;
}

static void deinit_select_per_thread()
{
	free(tmp_evts[DIR_WR]); tmp_evts[DIR_WR] = NULL;
	free(tmp_evts[DIR_RD]); tmp_evts[DIR_RD] = NULL;
}

/*
 * Initialization of the select() poller.
 * Returns 0 in case of failure, non-zero in case of success. If it fails, it
 * disables the poller by setting its pref to 0.
 */
REGPRM1 static int _do_init(struct poller *p)
{
	__label__ fail_swevt, fail_srevt, fail_revt;
	int fd_set_bytes;

	p->private = NULL;

	if (global.maxsock > FD_SETSIZE)
		goto fail_revt;

	fd_set_bytes = sizeof(fd_set) * (global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE;

	if ((fd_evts[DIR_RD] = calloc(1, fd_set_bytes)) == NULL)
		goto fail_srevt;
	if ((fd_evts[DIR_WR] = calloc(1, fd_set_bytes)) == NULL)
		goto fail_swevt;

	hap_register_per_thread_init(init_select_per_thread);
	hap_register_per_thread_deinit(deinit_select_per_thread);

	return 1;

 fail_swevt:
	free(fd_evts[DIR_RD]);
 fail_srevt:
	free(tmp_evts[DIR_WR]);
	free(tmp_evts[DIR_RD]);
 fail_revt:
	p->pref = 0;
	return 0;
}

/*
 * Termination of the select() poller.
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
	if (global.maxsock > FD_SETSIZE)
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


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
