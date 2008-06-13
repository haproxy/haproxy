/*
 * FD polling functions for linux epoll()
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
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
#include <common/standard.h>
#include <common/time.h>
#include <common/tools.h>

#include <types/fd.h>
#include <types/global.h>

#include <proto/fd.h>
#include <proto/task.h>

#if defined(USE_MY_EPOLL)
#include <common/epoll.h>
#include <errno.h>
#include <sys/syscall.h>
static _syscall1 (int, epoll_create, int, size);
static _syscall4 (int, epoll_ctl, int, epfd, int, op, int, fd, struct epoll_event *, event);
static _syscall4 (int, epoll_wait, int, epfd, struct epoll_event *, events, int, maxevents, int, timeout);
#else
#include <sys/epoll.h>
#endif

/* This is what we store in a list. It consists in old values and fds to detect changes. */
struct fd_chg {
	unsigned int prev:2;	// previous state mask. New one is in fd_evts.
	unsigned int fd:30;	// file descriptor
};

static int nbchanges = 0;		// number of changes pending
static struct fd_chg *chg_list = NULL;	// list of changes
static struct fd_chg **chg_ptr = NULL;	// per-fd changes

/* Each 32-bit word contains 2-bit descriptors of the latest state for 16 FDs :
 *   desc = (u32 >> (2*fd)) & 3
 *   desc = 0 : FD not set
 *          1 : WRITE not set, READ set
 *          2 : WRITE set, READ not set
 *          3 : WRITE set, READ set
 */

static uint32_t *fd_evts;

/* private data */
static struct epoll_event *epoll_events;
static int epoll_fd;

/* This structure may be used for any purpose. Warning! do not use it in
 * recursive functions !
 */
static struct epoll_event ev;

/* converts a direction to a single bitmask.
 *  0 => 1
 *  1 => 2
 */
#define DIR2MSK(dir) ((dir) + 1)

/* converts an FD to an fd_evts offset and to a bit shift */
#define FD2OFS(fd)   ((uint32_t)(fd) >> 4)
#define FD2BIT(fd)   (((uint32_t)(fd) & 0xF) << 1)
#define FD2MSK(fd)   (3 << FD2BIT(fd))

/*
 * Returns non-zero if direction <dir> is already set for <fd>.
 */
REGPRM2 static int __fd_is_set(const int fd, int dir)
{
	return (fd_evts[FD2OFS(fd)] >> FD2BIT(fd)) & DIR2MSK(dir);
}

/*
 * Adds, mods or deletes <fd> according to current status and to new desired
 * mask <dmask> :
 *
 *    0 = nothing
 *    1 = EPOLLIN
 *    2 = EPOLLOUT
 *    3 = EPOLLIN | EPOLLOUT
 *
 */
static int dmsk2event[4] = { 0, EPOLLIN, EPOLLOUT, EPOLLIN | EPOLLOUT };


REGPRM2 static void fd_flush_changes()
{
	uint32_t ofs;
	int opcode;
	int prev, next;
	int chg, fd;

	for (chg = 0; chg < nbchanges; chg++) {
		prev = chg_list[chg].prev;
		fd = chg_list[chg].fd;
		chg_ptr[fd] = NULL;

		ofs = FD2OFS(fd);
		next = (fd_evts[ofs] >> FD2BIT(fd)) & 3;

		if (prev == next)
			/* if the value was unchanged, do nothing */
			continue;

		ev.events = dmsk2event[next];
		ev.data.fd = fd;

		if (prev) {
			if (!next) {
				/* we want to delete it now */
				opcode = EPOLL_CTL_DEL;
			} else {
				/* we want to switch it */
				opcode = EPOLL_CTL_MOD;
			}
		} else {
			/* the FD did not exist, let's add it */
			opcode = EPOLL_CTL_ADD;
		}

		epoll_ctl(epoll_fd, opcode, fd, &ev);
	}
	nbchanges = 0;
}

REGPRM2 static void alloc_chg_list(const int fd, int old_evt)
{
	struct fd_chg *ptr;

	if (unlikely(chg_ptr[fd] != NULL))
		return;

#if LIMIT_NUMBER_OF_CHANGES
	if (nbchanges > 2)
		fd_flush_changes();
#endif

	ptr = &chg_list[nbchanges++];
	chg_ptr[fd] = ptr;
	ptr->fd = fd;
	ptr->prev = old_evt;
}

REGPRM2 static int __fd_set(const int fd, int dir)
{
	uint32_t ofs = FD2OFS(fd);
	uint32_t dmsk = DIR2MSK(dir);
	uint32_t old_evt;

	old_evt = fd_evts[ofs] >> FD2BIT(fd);
	old_evt &= 3;
	if (unlikely(old_evt & dmsk))
		return 0;

	alloc_chg_list(fd, old_evt);
	dmsk <<= FD2BIT(fd);
	fd_evts[ofs] |= dmsk;
	return 1;
}

REGPRM2 static int __fd_clr(const int fd, int dir)
{
	uint32_t ofs = FD2OFS(fd);
	uint32_t dmsk = DIR2MSK(dir);
	uint32_t old_evt;

	old_evt = fd_evts[ofs] >> FD2BIT(fd);
	old_evt &= 3;
	if (unlikely(!(old_evt & dmsk)))
		return 0;

	alloc_chg_list(fd, old_evt);
	dmsk <<= FD2BIT(fd);
	fd_evts[ofs] &= ~dmsk;
	return 1;
}

REGPRM1 static void __fd_rem(int fd)
{
	uint32_t ofs = FD2OFS(fd);

	if (unlikely(!((fd_evts[ofs] >> FD2BIT(fd)) & 3)))
		return;

	alloc_chg_list(fd, 0);
	fd_evts[ofs] &= ~FD2MSK(fd);
	return;
}

/*
 * On valid epoll() implementations, a call to close() automatically removes
 * the fds. This means that the FD will appear as previously unset.
 */
REGPRM1 static void __fd_clo(int fd)
{
	struct fd_chg *ptr;
	fd_evts[FD2OFS(fd)] &= ~FD2MSK(fd);
	ptr = chg_ptr[fd];
	if (ptr) {
		ptr->prev = 0;
		chg_ptr[fd] = NULL;
	}
	return;
}

/*
 * epoll() poller
 */
REGPRM2 static void _do_poll(struct poller *p, struct timeval *exp)
{
	int status;
	int fd;
	int count;
	int wait_time;

	if (likely(nbchanges))
		fd_flush_changes();

	/* now let's wait for events */
	if (run_queue)
		wait_time = 0;
	else if (tv_iseternity(exp))
		wait_time = -1;
	else if (tv_isge(&now, exp))
		wait_time = 0;
	else
		wait_time = __tv_ms_elapsed(&now, exp) + 1;

	fd = MIN(maxfd, global.tune.maxpollevents);
	status = epoll_wait(epoll_fd, epoll_events, fd, wait_time);
	tv_now(&now);

	for (count = 0; count < status; count++) {
		fd = epoll_events[count].data.fd;

		if ((fd_evts[FD2OFS(fd)] >> FD2BIT(fd)) & DIR2MSK(DIR_RD)) {
			if (fdtab[fd].state == FD_STCLOSE)
				continue;
			if (epoll_events[count].events & ( EPOLLIN | EPOLLERR | EPOLLHUP ))
				fdtab[fd].cb[DIR_RD].f(fd);
		}

		if ((fd_evts[FD2OFS(fd)] >> FD2BIT(fd)) & DIR2MSK(DIR_WR)) {
			if (fdtab[fd].state == FD_STCLOSE)
				continue;
			if (epoll_events[count].events & ( EPOLLOUT | EPOLLERR | EPOLLHUP ))
				fdtab[fd].cb[DIR_WR].f(fd);
		}
	}
}

/*
 * Initialization of the epoll() poller.
 * Returns 0 in case of failure, non-zero in case of success. If it fails, it
 * disables the poller by setting its pref to 0.
 */
REGPRM1 static int _do_init(struct poller *p)
{
	__label__ fail_chg_ptr, fail_chg_list, fail_fdevt, fail_ee, fail_fd;
	int fd_set_bytes;

	p->private = NULL;
	fd_set_bytes = 4 * (global.maxsock + 15) / 16;

	epoll_fd = epoll_create(global.maxsock + 1);
	if (epoll_fd < 0)
		goto fail_fd;

	epoll_events = (struct epoll_event*)
		calloc(1, sizeof(struct epoll_event) * global.tune.maxpollevents);

	if (epoll_events == NULL)
		goto fail_ee;

	if ((fd_evts = (uint32_t *)calloc(1, fd_set_bytes)) == NULL)
		goto fail_fdevt;

	chg_list = (struct fd_chg *)calloc(1, sizeof(struct fd_chg) * global.maxsock);
	if (chg_list == NULL)
		goto fail_chg_list;

	chg_ptr = (struct fd_chg **)calloc(1, sizeof(struct fd_chg*) * global.maxsock);
	if (chg_ptr == NULL)
		goto fail_chg_ptr;

	return 1;

 fail_chg_ptr:
	free(chg_list);
 fail_chg_list:
	free(fd_evts);
 fail_fdevt:
	free(epoll_events);
 fail_ee:
	close(epoll_fd);
	epoll_fd = 0;
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
	fd_flush_changes();

	if (chg_ptr)
		free(chg_ptr);
	if (chg_list)
		free(chg_list);
	if (fd_evts)
		free(fd_evts);
	if (epoll_events)
		free(epoll_events);

	close(epoll_fd);
	epoll_fd = 0;

	chg_ptr = NULL;
	chg_list = NULL;
	fd_evts = NULL;
	epoll_events = NULL;

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
	close(epoll_fd);
	epoll_fd = epoll_create(global.maxsock + 1);
	if (epoll_fd < 0)
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

	p->name = "epoll";
	p->pref = 300;
	p->private = NULL;

	p->test = _do_test;
	p->init = _do_init;
	p->term = _do_term;
	p->poll = _do_poll;
	p->fork = _do_fork;

	p->is_set  = __fd_is_set;
	p->cond_s = p->set = __fd_set;
	p->cond_c = p->clr = __fd_clr;
	p->rem = __fd_rem;
	p->clo = __fd_clo;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
