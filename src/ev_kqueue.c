/*
 * FD polling functions for FreeBSD kqueue()
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Note: not knowing much about kqueue, I had to rely on OpenBSD's detailed man
 * page and to check how it was implemented in lighttpd to understand it better.
 * But it is possible that I got things wrong.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#include <sys/event.h>
#include <sys/time.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/time.h>

#include <types/fd.h>
#include <types/global.h>

#include <proto/fd.h>
#include <proto/task.h>

/* private data */
static fd_set *fd_evts[2];
static int kqueue_fd;
static struct kevent *kev = NULL;

/* speeds up conversion of DIR_RD/DIR_WR to EVFILT* */
static const int dir2filt[2] = { EVFILT_READ, EVFILT_WRITE };

/* completes a change list for deletion */
REGPRM3 static int kqev_del(struct kevent *kev, const int fd, const int dir)
{
	if (FD_ISSET(fd, fd_evts[dir])) {
		FD_CLR(fd, fd_evts[dir]);
		EV_SET(kev, fd, dir2filt[dir], EV_DELETE, 0, 0, NULL);
		return 1;
	}
	return 0;
}

/*
 * Returns non-zero if direction <dir> is already set for <fd>.
 */
REGPRM2 static int __fd_isset(const int fd, int dir)
{
	return FD_ISSET(fd, fd_evts[dir]);
}

REGPRM2 static int __fd_set(const int fd, int dir)
{
	/* if the value was set, do nothing */
	if (FD_ISSET(fd, fd_evts[dir]))
		return 0;

	FD_SET(fd, fd_evts[dir]);
	EV_SET(kev, fd, dir2filt[dir], EV_ADD|EV_CLEAR, 0, 0, NULL);
	kevent(kqueue_fd, kev, 1, NULL, 0, NULL);
	return 1;
}

REGPRM2 static int __fd_clr(const int fd, int dir)
{
	/* if the value was not set, do nothing */
	//if (!FD_ISSET(fd, fd_evts[dir]))
	//	return 0;
	//
	//FD_CLR(fd, fd_evts[dir]);
	//EV_SET(&kev, fd, dir2filt[dir], EV_DELETE, 0, 0, NULL);
	//kevent(kqueue_fd, &kev, 1, NULL, 0, NULL);
	//return 1;
	if (!kqev_del(kev, fd, dir))
		return 0;
	kevent(kqueue_fd, kev, 1, NULL, 0, NULL);
	return 1;
}

REGPRM1 static void __fd_rem(int fd)
{
	int changes = 0;

	//if (FD_ISSET(fd, fd_evts[DIR_RD])) {
	//	FD_CLR(fd, fd_evts[DIR_RD]);
	//	EV_SET(&kev[changes], fd, dir2filt[DIR_RD], EV_DELETE, 0, 0, NULL);
	//	changes++;
	//}
	//if (FD_ISSET(fd, fd_evts[DIR_WR])) {
	//	FD_CLR(fd, fd_evts[DIR_WR]);
	//	EV_SET(&kev[changes], fd, dir2filt[DIR_WR], EV_DELETE, 0, 0, NULL);
	//	changes++;
	//}
	changes += kqev_del(&kev[changes], fd, DIR_RD);
	changes += kqev_del(&kev[changes], fd, DIR_WR);

	if (changes)
		kevent(kqueue_fd, kev, changes, NULL, 0, NULL);
}

/*
 * kqueue() poller
 */
REGPRM2 static void kqueue_poll(struct poller *p, int wait_time)
{
	int status;
	int count, fd;
	struct timespec timeout;

	timeout.tv_sec  =  wait_time / 1000;
	timeout.tv_nsec = (wait_time % 1000) * 1000000;

	status = kevent(kqueue_fd, // int kq
			NULL,      // const struct kevent *changelist
			0,         // int nchanges
			kev,       // struct kevent *eventlist
			maxfd,     // int nevents
			&timeout); // const struct timespec *timeout

	for (count = 0; count < status; count++) {
		fd = kev[count].ident;
		if (kev[count].filter ==  EVFILT_READ) {
			if (FD_ISSET(fd, fd_evts[DIR_RD])) {
				if (fdtab[fd].state == FD_STCLOSE)
					continue;
				fdtab[fd].cb[DIR_RD].f(fd);
			}
		} else if (kev[count].filter ==  EVFILT_WRITE) {
			if (FD_ISSET(fd, fd_evts[DIR_WR])) {
				if (fdtab[fd].state == FD_STCLOSE)
					continue;
				fdtab[fd].cb[DIR_WR].f(fd);
			}
		}
	}
}

/*
 * Initialization of the kqueue() poller.
 * Returns 0 in case of failure, non-zero in case of success. If it fails, it
 * disables the poller by setting its pref to 0.
 */
REGPRM1 static int kqueue_init(struct poller *p)
{
	__label__ fail_wevt, fail_revt, fail_fd;
	int fd_set_bytes;

	p->private = NULL;
	fd_set_bytes = sizeof(fd_set) * (global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE;

	kqueue_fd = kqueue();
	if (kqueue_fd < 0)
		goto fail_fd;

	kev = (struct kevent*)calloc(1, sizeof(struct kevent) * global.maxsock);

	if (kev == NULL)
		goto fail_kev;
		
	if ((fd_evts[DIR_RD] = (fd_set *)calloc(1, fd_set_bytes)) == NULL)
		goto fail_revt;

	if ((fd_evts[DIR_WR] = (fd_set *)calloc(1, fd_set_bytes)) == NULL)
		goto fail_wevt;

	return 1;

 fail_wevt:
	free(fd_evts[DIR_RD]);
 fail_revt:
	free(kev);
 fail_kev:
	close(kqueue_fd);
	kqueue_fd = 0;
 fail_fd:
	p->pref = 0;
	return 0;
}

/*
 * Termination of the kqueue() poller.
 * Memory is released and the poller is marked as unselectable.
 */
REGPRM1 static void kqueue_term(struct poller *p)
{
	if (fd_evts[DIR_WR])
		free(fd_evts[DIR_WR]);
	if (fd_evts[DIR_RD])
		free(fd_evts[DIR_RD]);
	if (kev)
		free(kev);
	close(kqueue_fd);
	kqueue_fd = 0;

	p->private = NULL;
	p->pref = 0;
}

/*
 * The only exported function. Returns 1.
 */
//int kqueue_native_register(struct poller *p)
int kqueue_register(struct poller *p)
{
	p->name = "kqueue";
	p->pref = 300;
	p->private = NULL;

	p->init = kqueue_init;
	p->term = kqueue_term;
	p->poll = kqueue_poll;

	p->isset  = __fd_isset;
	p->cond_s = p->set = __fd_set;
	p->cond_c = p->clr = __fd_clr;
	p->clo    = p->rem = __fd_rem;
	
	return 1;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
