/*
 * File descriptors management functions.
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <common/compat.h>
#include <common/config.h>

#include <types/fd.h>
#include <types/global.h>

#include <proto/fd.h>

struct fdtab *fdtab = NULL;     /* array of all the file descriptors */
int maxfd;                      /* # of the highest fd + 1 */
int totalconn;                  /* total # of terminated sessions */
int actconn;                    /* # of active sessions */

int cfg_polling_mechanism = 0;  /* POLL_USE_{SELECT|POLL|EPOLL} */

struct poller pollers[MAX_POLLERS];
struct poller cur_poller;
int nbpollers = 0;


/*********************
 * generic functions
 *********************/

extern int select_register(struct poller *p);
#if defined(ENABLE_POLL)
extern int poll_register(struct poller *p);
#endif
#if defined(ENABLE_EPOLL)
extern int epoll_register(struct poller *p);
#endif
#if defined(ENABLE_KQUEUE)
extern int kqueue_register(struct poller *p);
#endif


/* Deletes an FD from the fdsets, and recomputes the maxfd limit.
 * The file descriptor is also closed.
 */
void fd_delete(int fd)
{
	EV_FD_CLO(fd);
	close(fd);
	fdtab[fd].state = FD_STCLOSE;

	while ((maxfd-1 >= 0) && (fdtab[maxfd-1].state == FD_STCLOSE))
		maxfd--;
}


/* registers all known pollers */
void register_pollers()
{
	if (select_register(&pollers[nbpollers]))
		nbpollers++;
#if defined(ENABLE_POLL)
	poll_register(&pollers[nbpollers]);
	nbpollers++;
#endif

#if defined(ENABLE_EPOLL)
	epoll_register(&pollers[nbpollers]);
	nbpollers++;
#endif

#if defined(ENABLE_KQUEUE)
	kqueue_register(&pollers[nbpollers]);
	nbpollers++;
#endif
}

/* disable the specified poller */
void disable_poller(const char *poller_name)
{
	int p;

	for (p = 0; p < nbpollers; p++)
		if (strcmp(pollers[p].name, poller_name) == 0)
			pollers[p].pref = 0;
}

/*
 * Initialize the pollers till the best one is found.
 * If none works, returns 0, otherwise 1.
 */
int init_pollers()
{
	int p;
	struct poller *bp;


	do {
		bp = NULL;
		for (p = 0; p < nbpollers; p++)
			if (!bp || (pollers[p].pref > bp->pref))
				bp = &pollers[p];

		if (!bp || bp->pref == 0)
			break;

		if (bp->init(bp)) {
			memcpy(&cur_poller, bp, sizeof(*bp));
			return 1;
		}
	} while (!bp || bp->pref == 0);
	return 0;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
