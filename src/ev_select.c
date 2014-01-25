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
#include <common/ticks.h>
#include <common/time.h>

#include <types/global.h>

#include <proto/fd.h>
#include <proto/signal.h>
#include <proto/task.h>


static fd_set *fd_evts[2];
static fd_set *tmp_evts[2];

/* Immediately remove the entry upon close() */
REGPRM1 static void __fd_clo(int fd)
{
	FD_CLR(fd, fd_evts[DIR_RD]);
	FD_CLR(fd, fd_evts[DIR_WR]);
}

/*
 * Select() poller
 */
REGPRM2 static void _do_poll(struct poller *p, int exp)
{
	int status;
	int fd, i;
	struct timeval delta;
	int delta_ms;
	int readnotnull, writenotnull;
	int fds;
	int updt_idx, en, eo;
	char count;
		
	/* first, scan the update list to find changes */
	for (updt_idx = 0; updt_idx < fd_nbupdt; updt_idx++) {
		fd = fd_updt[updt_idx];
		fdtab[fd].updated = 0;
		fdtab[fd].new = 0;

		if (!fdtab[fd].owner)
			continue;

		eo = fdtab[fd].state;
		en = fd_compute_new_polled_status(eo);

		if ((eo ^ en) & FD_EV_POLLED_RW) {
			/* poll status changed, update the lists */
			fdtab[fd].state = en;

			if ((eo & ~en) & FD_EV_POLLED_R)
				FD_CLR(fd, fd_evts[DIR_RD]);
			else if ((en & ~eo) & FD_EV_POLLED_R)
				FD_SET(fd, fd_evts[DIR_RD]);

			if ((eo & ~en) & FD_EV_POLLED_W)
				FD_CLR(fd, fd_evts[DIR_WR]);
			else if ((en & ~eo) & FD_EV_POLLED_W)
				FD_SET(fd, fd_evts[DIR_WR]);
		}

		fd_alloc_or_release_cache_entry(fd, en);
	}
	fd_nbupdt = 0;

	delta_ms      = 0;
	delta.tv_sec  = 0;
	delta.tv_usec = 0;

	if (!fd_cache_num && !run_queue && !signal_queue_len) {
		if (!exp) {
			delta_ms      = MAX_DELAY_MS;
			delta.tv_sec  = (MAX_DELAY_MS / 1000);
			delta.tv_usec = (MAX_DELAY_MS % 1000) * 1000;
		}
		else if (!tick_is_expired(exp, now_ms)) {
			delta_ms = TICKS_TO_MS(tick_remain(now_ms, exp)) + SCHEDULER_RESOLUTION;
			if (delta_ms > MAX_DELAY_MS)
				delta_ms = MAX_DELAY_MS;
			delta.tv_sec  = (delta_ms / 1000);
			delta.tv_usec = (delta_ms % 1000) * 1000;
		}
	}

	/* let's restore fdset state */

	readnotnull = 0; writenotnull = 0;
	for (i = 0; i < (maxfd + FD_SETSIZE - 1)/(8*sizeof(int)); i++) {
		readnotnull |= (*(((int*)tmp_evts[DIR_RD])+i) = *(((int*)fd_evts[DIR_RD])+i)) != 0;
		writenotnull |= (*(((int*)tmp_evts[DIR_WR])+i) = *(((int*)fd_evts[DIR_WR])+i)) != 0;
	}

	//	/* just a verification code, needs to be removed for performance */
	//	for (i=0; i<maxfd; i++) {
	//	    if (FD_ISSET(i, tmp_evts[DIR_RD]) != FD_ISSET(i, fd_evts[DIR_RD]))
	//		abort();
	//	    if (FD_ISSET(i, tmp_evts[DIR_WR]) != FD_ISSET(i, fd_evts[DIR_WR]))
	//		abort();
	//	    
	//	}

	gettimeofday(&before_poll, NULL);
	status = select(maxfd,
			readnotnull ? tmp_evts[DIR_RD] : NULL,
			writenotnull ? tmp_evts[DIR_WR] : NULL,
			NULL,
			&delta);
      
	tv_update_date(delta_ms, status);
	measure_idle();

	if (status <= 0)
		return;

	for (fds = 0; (fds * BITS_PER_INT) < maxfd; fds++) {
		if ((((int *)(tmp_evts[DIR_RD]))[fds] | ((int *)(tmp_evts[DIR_WR]))[fds]) == 0)
			continue;

		for (count = BITS_PER_INT, fd = fds * BITS_PER_INT; count && fd < maxfd; count--, fd++) {
			/* if we specify read first, the accepts and zero reads will be
			 * seen first. Moreover, system buffers will be flushed faster.
			 */
			if (!fdtab[fd].owner)
				continue;

			fdtab[fd].ev &= FD_POLL_STICKY;
			if (FD_ISSET(fd, tmp_evts[DIR_RD]))
				fdtab[fd].ev |= FD_POLL_IN;

			if (FD_ISSET(fd, tmp_evts[DIR_WR]))
				fdtab[fd].ev |= FD_POLL_OUT;

			fd_process_polled_events(fd);
		}
	}
}

/*
 * Initialization of the select() poller.
 * Returns 0 in case of failure, non-zero in case of success. If it fails, it
 * disables the poller by setting its pref to 0.
 */
REGPRM1 static int _do_init(struct poller *p)
{
	__label__ fail_swevt, fail_srevt, fail_wevt, fail_revt;
	int fd_set_bytes;

	p->private = NULL;

	if (global.maxsock > FD_SETSIZE)
		goto fail_revt;

	fd_set_bytes = sizeof(fd_set) * (global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE;

	if ((tmp_evts[DIR_RD] = (fd_set *)calloc(1, fd_set_bytes)) == NULL)
		goto fail_revt;
		
	if ((tmp_evts[DIR_WR] = (fd_set *)calloc(1, fd_set_bytes)) == NULL)
		goto fail_wevt;

	if ((fd_evts[DIR_RD] = (fd_set *)calloc(1, fd_set_bytes)) == NULL)
		goto fail_srevt;

	if ((fd_evts[DIR_WR] = (fd_set *)calloc(1, fd_set_bytes)) == NULL)
		goto fail_swevt;

	return 1;

 fail_swevt:
	free(fd_evts[DIR_RD]);
 fail_srevt:
	free(tmp_evts[DIR_WR]);
 fail_wevt:
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
	free(tmp_evts[DIR_WR]);
	free(tmp_evts[DIR_RD]);
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
