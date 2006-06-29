/*
 * File descriptors management functions.
 *
 * Copyright 2000-2006 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

/*
 * FIXME:
 * - we still use 'listeners' to check whether we want to stop or not.
 * - the various pollers should be moved to other external files, possibly
 *   dynamic libs.
 * - merge event_cli_read() and event_srv_read(). The difference is res_*,
 *   buffer (at the beginning) and timeouts (at the end).
 *   => event_tcp_read(). It may be called from event_accept().
 * - extract the connect code from event_srv_write()
 *   => event_tcp_connect(). It must then call event_write().
 * - merge the remaining event_cli_write() and event_srv_write()
 *   => single event_tcp_write(). Check buffer, fd_state, res*, and timeouts.
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

#include <proto/polling.h>
#include <proto/task.h>

struct fdtab *fdtab = NULL;     /* array of all the file descriptors */
int maxfd;                      /* # of the highest fd + 1 */
int totalconn;                  /* total # of terminated sessions */
int actconn;                    /* # of active sessions */

fd_set	*StaticReadEvent, *StaticWriteEvent;
int cfg_polling_mechanism = 0;  /* POLL_USE_{SELECT|POLL|EPOLL} */


/******************************
 * pollers
 ******************************/


/*
 * FIXME: this is dirty, but at the moment, there's no other solution to remove
 * the old FDs from outside the loop. Perhaps we should export a global 'poll'
 * structure with pointers to functions such as init_fd() and close_fd(), plus
 * a private structure with several pointers to places such as below.
 */

#if defined(ENABLE_EPOLL)
fd_set *PrevReadEvent = NULL, *PrevWriteEvent = NULL;

#if defined(USE_MY_EPOLL)
#include <errno.h>
#include <sys/syscall.h>
_syscall1 (int, epoll_create, int, size);
_syscall4 (int, epoll_ctl, int, epfd, int, op, int, fd, struct epoll_event *, event);
_syscall4 (int, epoll_wait, int, epfd, struct epoll_event *, events, int, maxevents, int, timeout);
#endif

/*
 * Main epoll() loop.
 * does 3 actions :
 * 0 (POLL_LOOP_ACTION_INIT)  : initializes necessary private structures
 * 1 (POLL_LOOP_ACTION_RUN)   : runs the loop
 * 2 (POLL_LOOP_ACTION_CLEAN) : cleans up
 *
 * returns 0 if initialization failed, !0 otherwise.
 */

int epoll_loop(int action)
{
	int next_time;
	int status;
	int fd;

	int fds, count;
	int pr, pw, sr, sw;
	unsigned rn, ro, wn, wo; /* read new, read old, write new, write old */
	struct epoll_event ev;

	/* private data */
	static struct epoll_event *epoll_events = NULL;
	static int epoll_fd;

	if (action == POLL_LOOP_ACTION_INIT) {
		epoll_fd = epoll_create(global.maxsock + 1);
		if (epoll_fd < 0)
			return 0;
		else {
			epoll_events = (struct epoll_event*)
				calloc(1, sizeof(struct epoll_event) * global.maxsock);
			PrevReadEvent = (fd_set *)
				calloc(1, sizeof(fd_set) * (global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE);
			PrevWriteEvent = (fd_set *)
				calloc(1, sizeof(fd_set) * (global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE);
		}
		return 1;
	}
	else if (action == POLL_LOOP_ACTION_CLEAN) {
		if (PrevWriteEvent) free(PrevWriteEvent);
		if (PrevReadEvent)  free(PrevReadEvent);
		if (epoll_events)   free(epoll_events);
		close(epoll_fd);
		epoll_fd = 0;
		return 1;
	}

	/* OK, it's POLL_LOOP_ACTION_RUN */

	tv_now(&now);

	while (1) {
		next_time = process_runnable_tasks();

		/* stop when there's no connection left and we don't allow them anymore */
		if (!actconn && listeners == 0)
			break;

		for (fds = 0; (fds << INTBITS) < maxfd; fds++) {
	  
			rn = ((int*)StaticReadEvent)[fds];  ro = ((int*)PrevReadEvent)[fds];
			wn = ((int*)StaticWriteEvent)[fds]; wo = ((int*)PrevWriteEvent)[fds];
	  
			if ((ro^rn) | (wo^wn)) {
				for (count = 0, fd = fds << INTBITS; count < (1<<INTBITS) && fd < maxfd; count++, fd++) {
#define FDSETS_ARE_INT_ALIGNED
#ifdef FDSETS_ARE_INT_ALIGNED

#define WE_REALLY_NOW_THAT_FDSETS_ARE_INTS
#ifdef WE_REALLY_NOW_THAT_FDSETS_ARE_INTS
					pr = (ro >> count) & 1;
					pw = (wo >> count) & 1;
					sr = (rn >> count) & 1;
					sw = (wn >> count) & 1;
#else
					pr = FD_ISSET(fd&((1<<INTBITS)-1), (typeof(fd_set*))&ro);
					pw = FD_ISSET(fd&((1<<INTBITS)-1), (typeof(fd_set*))&wo);
					sr = FD_ISSET(fd&((1<<INTBITS)-1), (typeof(fd_set*))&rn);
					sw = FD_ISSET(fd&((1<<INTBITS)-1), (typeof(fd_set*))&wn);
#endif
#else
					pr = FD_ISSET(fd, PrevReadEvent);
					pw = FD_ISSET(fd, PrevWriteEvent);
					sr = FD_ISSET(fd, StaticReadEvent);
					sw = FD_ISSET(fd, StaticWriteEvent);
#endif
					if (!((sr^pr) | (sw^pw)))
						continue;

					ev.events = (sr ? EPOLLIN : 0) | (sw ? EPOLLOUT : 0);
					ev.data.fd = fd;

#ifdef EPOLL_CTL_MOD_WORKAROUND
					/* I encountered a rarely reproducible problem with
					 * EPOLL_CTL_MOD where a modified FD (systematically
					 * the one in epoll_events[0], fd#7) would sometimes
					 * be set EPOLL_OUT while asked for a read ! This is
					 * with the 2.4 epoll patch. The workaround is to
					 * delete then recreate in case of modification.
					 * This is in 2.4 up to epoll-lt-0.21 but not in 2.6
					 * nor RHEL kernels.
					 */

					if ((pr | pw) && fdtab[fd].state != FD_STCLOSE)
						epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ev);

					if ((sr | sw))
						epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
#else
					if ((pr | pw)) {
						/* the file-descriptor already exists... */
						if ((sr | sw)) {
							/* ...and it will still exist */
							if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) < 0) {
								// perror("epoll_ctl(MOD)");
								// exit(1);
							}
						} else {
							/* ...and it will be removed */
							if (fdtab[fd].state != FD_STCLOSE &&
							    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ev) < 0) {
								// perror("epoll_ctl(DEL)");
								// exit(1);
							}
						}
					} else {
						/* the file-descriptor did not exist, let's add it */
						if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
							// perror("epoll_ctl(ADD)");
							//  exit(1);
						}
					}
#endif // EPOLL_CTL_MOD_WORKAROUND
				}
				((int*)PrevReadEvent)[fds] = rn;
				((int*)PrevWriteEvent)[fds] = wn;
			}		  
		}
      
		/* now let's wait for events */
		status = epoll_wait(epoll_fd, epoll_events, maxfd, next_time);
		tv_now(&now);

		for (count = 0; count < status; count++) {
			fd = epoll_events[count].data.fd;

			if (FD_ISSET(fd, StaticReadEvent)) {
				if (fdtab[fd].state == FD_STCLOSE)
					continue;
				if (epoll_events[count].events & ( EPOLLIN | EPOLLERR | EPOLLHUP ))
					fdtab[fd].read(fd);
			}

			if (FD_ISSET(fd, StaticWriteEvent)) {
				if (fdtab[fd].state == FD_STCLOSE)
					continue;
				if (epoll_events[count].events & ( EPOLLOUT | EPOLLERR | EPOLLHUP ))
					fdtab[fd].write(fd);
			}
		}
	}
	return 1;
}
#endif



#if defined(ENABLE_POLL)
/*
 * Main poll() loop.
 * does 3 actions :
 * 0 (POLL_LOOP_ACTION_INIT)  : initializes necessary private structures
 * 1 (POLL_LOOP_ACTION_RUN)   : runs the loop
 * 2 (POLL_LOOP_ACTION_CLEAN) : cleans up
 *
 * returns 0 if initialization failed, !0 otherwise.
 */

int poll_loop(int action)
{
	int next_time;
	int status;
	int fd, nbfd;

	int fds, count;
	int sr, sw;
	unsigned rn, wn; /* read new, write new */

	/* private data */
	static struct pollfd *poll_events = NULL;

	if (action == POLL_LOOP_ACTION_INIT) {
		poll_events = (struct pollfd*)
			calloc(1, sizeof(struct pollfd) * global.maxsock);
		return 1;
	}
	else if (action == POLL_LOOP_ACTION_CLEAN) {
		if (poll_events)
			free(poll_events);
		return 1;
	}

	/* OK, it's POLL_LOOP_ACTION_RUN */

	tv_now(&now);

	while (1) {
		next_time = process_runnable_tasks();

		/* stop when there's no connection left and we don't allow them anymore */
		if (!actconn && listeners == 0)
			break;

		nbfd = 0;
		for (fds = 0; (fds << INTBITS) < maxfd; fds++) {
	  
			rn = ((int*)StaticReadEvent)[fds];
			wn = ((int*)StaticWriteEvent)[fds];
	  
			if ((rn|wn)) {
				for (count = 0, fd = fds << INTBITS; count < (1<<INTBITS) && fd < maxfd; count++, fd++) {
#define FDSETS_ARE_INT_ALIGNED
#ifdef FDSETS_ARE_INT_ALIGNED

#define WE_REALLY_NOW_THAT_FDSETS_ARE_INTS
#ifdef WE_REALLY_NOW_THAT_FDSETS_ARE_INTS
					sr = (rn >> count) & 1;
					sw = (wn >> count) & 1;
#else
					sr = FD_ISSET(fd&((1<<INTBITS)-1), (typeof(fd_set*))&rn);
					sw = FD_ISSET(fd&((1<<INTBITS)-1), (typeof(fd_set*))&wn);
#endif
#else
					sr = FD_ISSET(fd, StaticReadEvent);
					sw = FD_ISSET(fd, StaticWriteEvent);
#endif
					if ((sr|sw)) {
						poll_events[nbfd].fd = fd;
						poll_events[nbfd].events = (sr ? POLLIN : 0) | (sw ? POLLOUT : 0);
						nbfd++;
					}
				}
			}		  
		}
      
		/* now let's wait for events */
		status = poll(poll_events, nbfd, next_time);
		tv_now(&now);

		for (count = 0; status > 0 && count < nbfd; count++) {
			fd = poll_events[count].fd;
	  
			if (!(poll_events[count].revents & ( POLLOUT | POLLIN | POLLERR | POLLHUP )))
				continue;

			/* ok, we found one active fd */
			status--;

			if (FD_ISSET(fd, StaticReadEvent)) {
				if (fdtab[fd].state == FD_STCLOSE)
					continue;
				if (poll_events[count].revents & ( POLLIN | POLLERR | POLLHUP ))
					fdtab[fd].read(fd);
			}
	  
			if (FD_ISSET(fd, StaticWriteEvent)) {
				if (fdtab[fd].state == FD_STCLOSE)
					continue;
				if (poll_events[count].revents & ( POLLOUT | POLLERR | POLLHUP ))
					fdtab[fd].write(fd);
			}
		}
	}
	return 1;
}
#endif



/*
 * Main select() loop.
 * does 3 actions :
 * 0 (POLL_LOOP_ACTION_INIT)  : initializes necessary private structures
 * 1 (POLL_LOOP_ACTION_RUN)   : runs the loop
 * 2 (POLL_LOOP_ACTION_CLEAN) : cleans up
 *
 * returns 0 if initialization failed, !0 otherwise.
 */


int select_loop(int action)
{
	int next_time;
	int status;
	int fd,i;
	struct timeval delta;
	int readnotnull, writenotnull;
	static fd_set	*ReadEvent = NULL, *WriteEvent = NULL;

	if (action == POLL_LOOP_ACTION_INIT) {
		ReadEvent = (fd_set *)
			calloc(1, sizeof(fd_set) * (global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE);
		WriteEvent = (fd_set *)
			calloc(1, sizeof(fd_set) * (global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE);
		return 1;
	}
	else if (action == POLL_LOOP_ACTION_CLEAN) {
		if (WriteEvent)       free(WriteEvent);
		if (ReadEvent)        free(ReadEvent);
		return 1;
	}

	/* OK, it's POLL_LOOP_ACTION_RUN */

	tv_now(&now);

	while (1) {
		next_time = process_runnable_tasks();

		/* stop when there's no connection left and we don't allow them anymore */
		if (!actconn && listeners == 0)
			break;

		if (next_time > 0) {  /* FIXME */
			/* Convert to timeval */
			/* to avoid eventual select loops due to timer precision */
			next_time += SCHEDULER_RESOLUTION;
			delta.tv_sec  = next_time / 1000; 
			delta.tv_usec = (next_time % 1000) * 1000;
		}
		else if (next_time == 0) { /* allow select to return immediately when needed */
			delta.tv_sec = delta.tv_usec = 0;
		}


		/* let's restore fdset state */

		readnotnull = 0; writenotnull = 0;
		for (i = 0; i < (maxfd + FD_SETSIZE - 1)/(8*sizeof(int)); i++) {
			readnotnull |= (*(((int*)ReadEvent)+i) = *(((int*)StaticReadEvent)+i)) != 0;
			writenotnull |= (*(((int*)WriteEvent)+i) = *(((int*)StaticWriteEvent)+i)) != 0;
		}

		//	/* just a verification code, needs to be removed for performance */
		//	for (i=0; i<maxfd; i++) {
		//	    if (FD_ISSET(i, ReadEvent) != FD_ISSET(i, StaticReadEvent))
		//		abort();
		//	    if (FD_ISSET(i, WriteEvent) != FD_ISSET(i, StaticWriteEvent))
		//		abort();
		//	    
		//	}

		status = select(maxfd,
				readnotnull ? ReadEvent : NULL,
				writenotnull ? WriteEvent : NULL,
				NULL,
				(next_time >= 0) ? &delta : NULL);
      
		/* this is an experiment on the separation of the select work */
		// status  = (readnotnull  ? select(maxfd, ReadEvent, NULL, NULL, (next_time >= 0) ? &delta : NULL) : 0);
		// status |= (writenotnull ? select(maxfd, NULL, WriteEvent, NULL, (next_time >= 0) ? &delta : NULL) : 0);
      
		tv_now(&now);

		if (status > 0) { /* must proceed with events */

			int fds;
			char count;
	  
			for (fds = 0; (fds << INTBITS) < maxfd; fds++)
				if ((((int *)(ReadEvent))[fds] | ((int *)(WriteEvent))[fds]) != 0)
					for (count = 1<<INTBITS, fd = fds << INTBITS; count && fd < maxfd; count--, fd++) {
		      
						/* if we specify read first, the accepts and zero reads will be
						 * seen first. Moreover, system buffers will be flushed faster.
						 */
						if (FD_ISSET(fd, ReadEvent)) {
							if (fdtab[fd].state == FD_STCLOSE)
								continue;
							fdtab[fd].read(fd);
						}

						if (FD_ISSET(fd, WriteEvent)) {
							if (fdtab[fd].state == FD_STCLOSE)
								continue;
							fdtab[fd].write(fd);
						}
					}
		}
		else {
			//	  fprintf(stderr,"select returned %d, maxfd=%d\n", status, maxfd);
		}
	}
	return 1;
}



/*********************
 * generic functions
 *********************/


/* Deletes an FD from the fdsets, and recomputes the maxfd limit.
 * The file descriptor is also closed.
 */
void fd_delete(int fd)
{
	FD_CLR(fd, StaticReadEvent);
	FD_CLR(fd, StaticWriteEvent);
#if defined(ENABLE_EPOLL)
	if (PrevReadEvent) {
		FD_CLR(fd, PrevReadEvent);
		FD_CLR(fd, PrevWriteEvent);
	}
#endif

	close(fd);
	fdtab[fd].state = FD_STCLOSE;

	while ((maxfd-1 >= 0) && (fdtab[maxfd-1].state == FD_STCLOSE))
		maxfd--;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
