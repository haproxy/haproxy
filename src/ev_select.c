/*
 * FD polling functions for generic select()
 *
 * Copyright 2000-2008 Willy Tarreau <w@1wt.eu>
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
#include <common/time.h>

#include <types/fd.h>
#include <types/global.h>

#include <proto/fd.h>
#include <proto/task.h>


static fd_set *fd_evts[2];
static fd_set *tmp_evts[2];


/*
 * Benchmarks performed on a Pentium-M notebook show that using functions
 * instead of the usual macros improve the FD_* performance by about 80%,
 * and that marking them regparm(2) adds another 20%.
 */
REGPRM2 static int __fd_is_set(const int fd, int dir)
{
	return FD_ISSET(fd, fd_evts[dir]);
}

REGPRM2 static int __fd_set(const int fd, int dir)
{
	FD_SET(fd, fd_evts[dir]);
	return 0;
}

REGPRM2 static int __fd_clr(const int fd, int dir)
{
	FD_CLR(fd, fd_evts[dir]);
	return 0;
}

REGPRM2 static int __fd_cond_s(const int fd, int dir)
{
	int ret;
	ret = !FD_ISSET(fd, fd_evts[dir]);
	if (ret)
		FD_SET(fd, fd_evts[dir]);
	return ret;
}

REGPRM2 static int __fd_cond_c(const int fd, int dir)
{
	int ret;
	ret = FD_ISSET(fd, fd_evts[dir]);
	if (ret)
		FD_CLR(fd, fd_evts[dir]);
	return ret;
}

REGPRM1 static void __fd_rem(int fd)
{
	FD_CLR(fd, fd_evts[DIR_RD]);
	FD_CLR(fd, fd_evts[DIR_WR]);
}

/*
 * Select() poller
 */
REGPRM2 static void _do_poll(struct poller *p, struct timeval *exp)
{
	const struct timeval max_delay = {
		.tv_sec  = MAX_DELAY_MS / 1000,
		.tv_usec = (MAX_DELAY_MS % 1000) * 1000
	};
	int status;
	int fd, i;
	struct timeval delta;
	int delta_ms;
	int readnotnull, writenotnull;
	int fds;
	char count;
		
	/* allow select to return immediately when needed */
	delta.tv_sec = delta.tv_usec = 0;
	delta_ms = 0;
	if (!run_queue) {
		if (!tv_isset(exp)) {
			delta = max_delay;
			delta_ms = MAX_DELAY_MS;
		}
		else if (tv_islt(&now, exp)) {
			tv_remain(&now, exp, &delta);
			/* To avoid eventual select loops due to timer precision */
			delta.tv_usec += SCHEDULER_RESOLUTION * 1000;
			if (delta.tv_usec >= 1000000) {
				delta.tv_usec -= 1000000;
				delta.tv_sec ++;
			}
			if (__tv_isge(&delta, &max_delay)) {
				delta = max_delay;
				delta_ms = MAX_DELAY_MS;
			} else {
				delta_ms = delta.tv_sec * 1000 + delta.tv_usec / 1000;
			}
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

	status = select(maxfd,
			readnotnull ? tmp_evts[DIR_RD] : NULL,
			writenotnull ? tmp_evts[DIR_WR] : NULL,
			NULL,
			&delta);
      
	tv_update_date(delta_ms, status);

	if (status <= 0)
		return;

	for (fds = 0; (fds << INTBITS) < maxfd; fds++) {
		if ((((int *)(tmp_evts[DIR_RD]))[fds] | ((int *)(tmp_evts[DIR_WR]))[fds]) == 0)
			continue;

		for (count = 1<<INTBITS, fd = fds << INTBITS; count && fd < maxfd; count--, fd++) {
			/* if we specify read first, the accepts and zero reads will be
			 * seen first. Moreover, system buffers will be flushed faster.
			 */
			if (FD_ISSET(fd, tmp_evts[DIR_RD])) {
				if (fdtab[fd].state == FD_STCLOSE)
					continue;
				fdtab[fd].cb[DIR_RD].f(fd);
			}

			if (FD_ISSET(fd, tmp_evts[DIR_WR])) {
				if (fdtab[fd].state == FD_STCLOSE)
					continue;
				fdtab[fd].cb[DIR_WR].f(fd);
			}
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
	if (fd_evts[DIR_WR])
		free(fd_evts[DIR_WR]);
	if (fd_evts[DIR_RD])
		free(fd_evts[DIR_RD]);
	if (tmp_evts[DIR_WR])
		free(tmp_evts[DIR_WR]);
	if (tmp_evts[DIR_RD])
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

	p->test = _do_test;
	p->init = _do_init;
	p->term = _do_term;
	p->poll = _do_poll;
	p->is_set = __fd_is_set;
	p->set = __fd_set;
	p->clr = __fd_clr;
	p->clo = p->rem = __fd_rem;
	p->cond_s = __fd_cond_s;
	p->cond_c = __fd_cond_c;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
