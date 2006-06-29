/*
 * Proxy variables and functions.
 *
 * Copyright 2000-2006 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <common/defaults.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/time.h>

#include <types/global.h>
#include <types/polling.h>

#include <proto/client.h>
#include <proto/fd.h>
#include <proto/log.h>
#include <proto/proxy.h>


int listeners;	/* # of listeners */
struct proxy *proxy  = NULL;	/* list of all existing proxies */


/*
 * this function starts all the proxies. Its return value is composed from
 * ERR_NONE, ERR_RETRYABLE and ERR_FATAL. Retryable errors will only be printed
 * if <verbose> is not zero.
 */
int start_proxies(int verbose)
{
	struct proxy *curproxy;
	struct listener *listener;
	int err = ERR_NONE;
	int fd, pxerr;

	for (curproxy = proxy; curproxy != NULL; curproxy = curproxy->next) {
		if (curproxy->state != PR_STNEW)
			continue; /* already initialized */

		pxerr = 0;
		for (listener = curproxy->listen; listener != NULL; listener = listener->next) {
			if (listener->fd != -1)
				continue; /* already initialized */

			if ((fd = socket(listener->addr.ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1) {
				if (verbose)
					Alert("cannot create listening socket for proxy %s. Aborting.\n",
					      curproxy->id);
				err |= ERR_RETRYABLE;
				pxerr |= 1;
				continue;
			}
	
			if (fd >= global.maxsock) {
				Alert("socket(): not enough free sockets for proxy %s. Raise -n argument. Aborting.\n",
				      curproxy->id);
				close(fd);
				err |= ERR_FATAL;
				pxerr |= 1;
				break;
			}

			if ((fcntl(fd, F_SETFL, O_NONBLOCK) == -1) ||
			    (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
					(char *) &one, sizeof(one)) == -1)) {
				Alert("cannot make socket non-blocking for proxy %s. Aborting.\n",
				      curproxy->id);
				close(fd);
				err |= ERR_FATAL;
				pxerr |= 1;
				break;
			}

			if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one)) == -1) {
				Alert("cannot do so_reuseaddr for proxy %s. Continuing.\n",
				      curproxy->id);
			}
	
#ifdef SO_REUSEPORT
			/* OpenBSD supports this. As it's present in old libc versions of Linux,
			 * it might return an error that we will silently ignore.
			 */
			setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (char *) &one, sizeof(one));
#endif
			if (bind(fd,
				 (struct sockaddr *)&listener->addr,
				 listener->addr.ss_family == AF_INET6 ?
				 sizeof(struct sockaddr_in6) :
				 sizeof(struct sockaddr_in)) == -1) {
				if (verbose)
					Alert("cannot bind socket for proxy %s. Aborting.\n",
					      curproxy->id);
				close(fd);
				err |= ERR_RETRYABLE;
				pxerr |= 1;
				continue;
			}
	
			if (listen(fd, curproxy->maxconn) == -1) {
				if (verbose)
					Alert("cannot listen to socket for proxy %s. Aborting.\n",
					      curproxy->id);
				close(fd);
				err |= ERR_RETRYABLE;
				pxerr |= 1;
				continue;
			}
	
			/* the socket is ready */
			listener->fd = fd;

			/* the function for the accept() event */
			fdtab[fd].read  = &event_accept;
			fdtab[fd].write = NULL; /* never called */
			fdtab[fd].owner = (struct task *)curproxy; /* reference the proxy instead of a task */
			fdtab[fd].state = FD_STLISTEN;
			FD_SET(fd, StaticReadEvent);
			fd_insert(fd);
			listeners++;
		}

		if (!pxerr) {
			curproxy->state = PR_STRUN;
			send_log(curproxy, LOG_NOTICE, "Proxy %s started.\n", curproxy->id);
		}
	}

	return err;
}


/*
 * this function enables proxies when there are enough free sessions,
 * or stops them when the table is full. It is designed to be called from the
 * select_loop(). It returns the time left before next expiration event
 * during stop time, TIME_ETERNITY otherwise.
 */
int maintain_proxies(void)
{
	struct proxy *p;
	struct listener *l;
	int tleft; /* time left */

	p = proxy;
	tleft = TIME_ETERNITY; /* infinite time */

	/* if there are enough free sessions, we'll activate proxies */
	if (actconn < global.maxconn) {
		while (p) {
			if (p->nbconn < p->maxconn) {
				if (p->state == PR_STIDLE) {
					for (l = p->listen; l != NULL; l = l->next) {
						FD_SET(l->fd, StaticReadEvent);
					}
					p->state = PR_STRUN;
				}
			}
			else {
				if (p->state == PR_STRUN) {
					for (l = p->listen; l != NULL; l = l->next) {
						FD_CLR(l->fd, StaticReadEvent);
					}
					p->state = PR_STIDLE;
				}
			}
			p = p->next;
		}
	}
	else {  /* block all proxies */
		while (p) {
			if (p->state == PR_STRUN) {
				for (l = p->listen; l != NULL; l = l->next) {
					FD_CLR(l->fd, StaticReadEvent);
				}
				p->state = PR_STIDLE;
			}
			p = p->next;
		}
	}

	if (stopping) {
		p = proxy;
		while (p) {
			if (p->state != PR_STSTOPPED) {
				int t;
				t = tv_remain2(&now, &p->stop_time);
				if (t == 0) {
					Warning("Proxy %s stopped.\n", p->id);
					send_log(p, LOG_WARNING, "Proxy %s stopped.\n", p->id);

					for (l = p->listen; l != NULL; l = l->next) {
						fd_delete(l->fd);
						listeners--;
					}
					p->state = PR_STSTOPPED;
				}
				else {
					tleft = MINTIME(t, tleft);
				}
			}
			p = p->next;
		}
	}
	return tleft;
}


/*
 * this function disables health-check servers so that the process will quickly be ignored
 * by load balancers. Note that if a proxy was already in the PAUSED state, then its grace
 * time will not be used since it would already not listen anymore to the socket.
 */
void soft_stop(void)
{
	struct proxy *p;

	stopping = 1;
	p = proxy;
	tv_now(&now); /* else, the old time before select will be used */
	while (p) {
		if (p->state != PR_STSTOPPED) {
			Warning("Stopping proxy %s in %d ms.\n", p->id, p->grace);
			send_log(p, LOG_WARNING, "Stopping proxy %s in %d ms.\n", p->id, p->grace);
			tv_delayfrom(&p->stop_time, &now, p->grace);
		}
		p = p->next;
	}
}


/*
 * Linux unbinds the listen socket after a SHUT_RD, and ignores SHUT_WR.
 * Solaris refuses either shutdown().
 * OpenBSD ignores SHUT_RD but closes upon SHUT_WR and refuses to rebind.
 * So a common validation path involves SHUT_WR && listen && SHUT_RD.
 * If disabling at least one listener returns an error, then the proxy
 * state is set to PR_STERROR because we don't know how to resume from this.
 */
void pause_proxy(struct proxy *p)
{
	struct listener *l;
	for (l = p->listen; l != NULL; l = l->next) {
		if (shutdown(l->fd, SHUT_WR) == 0 &&
		    listen(l->fd, p->maxconn) == 0 &&
		    shutdown(l->fd, SHUT_RD) == 0) {
			FD_CLR(l->fd, StaticReadEvent);
			if (p->state != PR_STERROR)
				p->state = PR_STPAUSED;
		}
		else
			p->state = PR_STERROR;
	}
}

/*
 * This function temporarily disables listening so that another new instance
 * can start listening. It is designed to be called upon reception of a
 * SIGTTOU, after which either a SIGUSR1 can be sent to completely stop
 * the proxy, or a SIGTTIN can be sent to listen again.
 */
void pause_proxies(void)
{
	int err;
	struct proxy *p;

	err = 0;
	p = proxy;
	tv_now(&now); /* else, the old time before select will be used */
	while (p) {
		if (p->state != PR_STERROR &&
		    p->state != PR_STSTOPPED &&
		    p->state != PR_STPAUSED) {
			Warning("Pausing proxy %s.\n", p->id);
			send_log(p, LOG_WARNING, "Pausing proxy %s.\n", p->id);
			pause_proxy(p);
			if (p->state != PR_STPAUSED) {
				err |= 1;
				Warning("Proxy %s failed to enter pause mode.\n", p->id);
				send_log(p, LOG_WARNING, "Proxy %s failed to enter pause mode.\n", p->id);
			}
		}
		p = p->next;
	}
	if (err) {
		Warning("Some proxies refused to pause, performing soft stop now.\n");
		send_log(p, LOG_WARNING, "Some proxies refused to pause, performing soft stop now.\n");
		soft_stop();
	}
}


/*
 * This function reactivates listening. This can be used after a call to
 * sig_pause(), for example when a new instance has failed starting up.
 * It is designed to be called upon reception of a SIGTTIN.
 */
void listen_proxies(void)
{
	struct proxy *p;
	struct listener *l;

	p = proxy;
	tv_now(&now); /* else, the old time before select will be used */
	while (p) {
		if (p->state == PR_STPAUSED) {
			Warning("Enabling proxy %s.\n", p->id);
			send_log(p, LOG_WARNING, "Enabling proxy %s.\n", p->id);

			for (l = p->listen; l != NULL; l = l->next) {
				if (listen(l->fd, p->maxconn) == 0) {
					if (actconn < global.maxconn && p->nbconn < p->maxconn) {
						FD_SET(l->fd, StaticReadEvent);
						p->state = PR_STRUN;
					}
					else
						p->state = PR_STIDLE;
				} else {
					int port;

					if (l->addr.ss_family == AF_INET6)
						port = ntohs(((struct sockaddr_in6 *)(&l->addr))->sin6_port);
					else
						port = ntohs(((struct sockaddr_in *)(&l->addr))->sin_port);

					Warning("Port %d busy while trying to enable proxy %s.\n",
						port, p->id);
					send_log(p, LOG_WARNING, "Port %d busy while trying to enable proxy %s.\n",
						 port, p->id);
					/* Another port might have been enabled. Let's stop everything. */
					pause_proxy(p);
					break;
				}
			}
		}
		p = p->next;
	}
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
