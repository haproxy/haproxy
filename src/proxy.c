/*
 * Proxy variables and functions.
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <common/defaults.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/errors.h>
#include <common/memory.h>
#include <common/time.h>

#include <types/global.h>
#include <types/polling.h>

#include <proto/client.h>
#include <proto/backend.h>
#include <proto/fd.h>
#include <proto/log.h>
#include <proto/protocols.h>
#include <proto/proto_tcp.h>
#include <proto/proxy.h>


int listeners;	/* # of proxy listeners, set by cfgparse, unset by maintain_proxies */
struct proxy *proxy  = NULL;	/* list of all existing proxies */
int next_pxid = 1;		/* UUID assigned to next new proxy, 0 reserved */

/*
 * This function returns a string containing a name describing capabilities to
 * report comprehensible error messages. Specifically, it will return the words
 * "frontend", "backend", "ruleset" when appropriate, or "proxy" for all other
 * cases including the proxies declared in "listen" mode.
 */
const char *proxy_cap_str(int cap)
{
	if ((cap & PR_CAP_LISTEN) != PR_CAP_LISTEN) {
		if (cap & PR_CAP_FE)
			return "frontend";
		else if (cap & PR_CAP_BE)
			return "backend";
		else if (cap & PR_CAP_RS)
			return "ruleset";
	}
	return "proxy";
}

/*
 * This function returns a string containing the mode of the proxy in a format
 * suitable for error messages.
 */
const char *proxy_mode_str(int mode) {

	if (mode == PR_MODE_TCP)
		return "tcp";
	else if (mode == PR_MODE_HTTP)
		return "http";
	else if (mode == PR_MODE_HEALTH)
		return "health";
	else
		return "unknown";
}

/* This function parses a "timeout" statement in a proxy section. It returns
 * -1 if there is any error, 1 for a warning, otherwise zero. If it does not
 * return zero, it may write an error message into the <err> buffer, for at
 * most <errlen> bytes, trailing zero included. The trailing '\n' must not
 * be written. The function must be called with <args> pointing to the first
 * word after "timeout", with <proxy> pointing to the proxy being parsed, and
 * <defpx> to the default proxy or NULL. As a special case for compatibility
 * with older configs, it also accepts "{cli|srv|con}timeout" in args[0].
 */
int proxy_parse_timeout(const char **args, struct proxy *proxy,
			struct proxy *defpx, char *err, int errlen)
{
	unsigned timeout;
	int retval, cap;
	const char *res, *name;
	struct timeval *tv = NULL;
	struct timeval *td = NULL;

	retval = 0;
	name = args[0];
	if (!strcmp(args[0], "client") || !strcmp(args[0], "clitimeout")) {
		name = "client";
		tv = &proxy->timeout.client;
		td = &defpx->timeout.client;
		cap = PR_CAP_FE;
	} else if (!strcmp(args[0], "tarpit")) {
		tv = &proxy->timeout.tarpit;
		td = &defpx->timeout.tarpit;
		cap = PR_CAP_FE;
	} else if (!strcmp(args[0], "http-request")) {
		tv = &proxy->timeout.httpreq;
		td = &defpx->timeout.httpreq;
		cap = PR_CAP_FE;
	} else if (!strcmp(args[0], "server") || !strcmp(args[0], "srvtimeout")) {
		name = "server";
		tv = &proxy->timeout.server;
		td = &defpx->timeout.server;
		cap = PR_CAP_BE;
	} else if (!strcmp(args[0], "connect") || !strcmp(args[0], "contimeout")) {
		name = "connect";
		tv = &proxy->timeout.connect;
		td = &defpx->timeout.connect;
		cap = PR_CAP_BE;
	} else if (!strcmp(args[0], "appsession")) {
		tv = &proxy->timeout.appsession;
		td = &defpx->timeout.appsession;
		cap = PR_CAP_BE;
	} else if (!strcmp(args[0], "queue")) {
		tv = &proxy->timeout.queue;
		td = &defpx->timeout.queue;
		cap = PR_CAP_BE;
	} else {
		snprintf(err, errlen,
			 "timeout '%s': must be 'client', 'server', 'connect', "
			 "'appsession', 'queue', 'http-request' or 'tarpit'",
			 args[0]);
		return -1;
	}

	if (*args[1] == 0) {
		snprintf(err, errlen, "%s timeout expects an integer value (in milliseconds)", name);
		return -1;
	}

	res = parse_time_err(args[1], &timeout, TIME_UNIT_MS);
	if (res) {
		snprintf(err, errlen, "unexpected character '%c' in %s timeout", *err, name);
		return -1;
	}

	if (!(proxy->cap & cap)) {
		snprintf(err, errlen, "%s timeout will be ignored because %s '%s' has no %s capability",
			 name, proxy_type_str(proxy), proxy->id,
			 (cap & PR_CAP_BE) ? "backend" : "frontend");
		retval = 1;
	}
	else if (defpx && !__tv_iseq(tv, td)) {
		snprintf(err, errlen, "overwriting %s timeout which was already specified", name);
		retval = 1;
	}

	if (timeout)
		__tv_from_ms(tv, timeout);
	else
		tv_eternity(tv);

	return retval;
}

/*
 * This function finds a proxy with matching name, mode and with satisfying
 * capabilities. It also checks if there are more matching proxies with
 * requested name as this often leads into unexpected situations.
 */

struct proxy *findproxy(const char *name, int mode, int cap) {

	struct proxy *curproxy, *target=NULL;

	for (curproxy = proxy; curproxy; curproxy = curproxy->next) {
		if ((curproxy->cap & cap)!=cap || strcmp(curproxy->id, name))
			continue;

		if (curproxy->mode != mode) {
			Alert("Unable to use proxy '%s' with wrong mode, required: %s, has: %s.\n", 
				name, proxy_mode_str(mode), proxy_mode_str(curproxy->mode));
			Alert("You may want to use 'mode %s'.\n", proxy_mode_str(mode));
			return NULL;
		}

		if (!target) {
			target = curproxy;
			continue;
		}

		Alert("Refusing to use duplicated proxy '%s' with overlapping capabilities: %s/%s!\n",
			name, proxy_type_str(curproxy), proxy_type_str(target));

		return NULL;
	}

	return target;
}

/*
 * This function creates all proxy sockets. It should be done very early,
 * typically before privileges are dropped. The sockets will be registered
 * but not added to any fd_set, in order not to loose them across the fork().
 * The proxies also start in IDLE state, meaning that it will be
 * maintain_proxies that will finally complete their loading.
 *
 * Its return value is composed from ERR_NONE, ERR_RETRYABLE and ERR_FATAL.
 * Retryable errors will only be printed if <verbose> is not zero.
 */
int start_proxies(int verbose)
{
	struct proxy *curproxy;
	struct listener *listener;
	int lerr, err = ERR_NONE;
	int pxerr;
	char msg[100];

	for (curproxy = proxy; curproxy != NULL; curproxy = curproxy->next) {
		if (curproxy->state != PR_STNEW)
			continue; /* already initialized */

		pxerr = 0;
		for (listener = curproxy->listen; listener != NULL; listener = listener->next) {
			if (listener->state != LI_ASSIGNED)
				continue; /* already started */

			lerr = tcp_bind_listener(listener, msg, sizeof(msg));

			/* errors are reported if <verbose> is set or if they are fatal */
			if (verbose || (lerr & (ERR_FATAL | ERR_ABORT))) {
				if (lerr & ERR_ALERT)
					Alert("Starting %s %s: %s\n",
					      proxy_type_str(curproxy), curproxy->id, msg);
				else if (lerr & ERR_WARN)
					Warning("Starting %s %s: %s\n",
						proxy_type_str(curproxy), curproxy->id, msg);
			}

			err |= lerr;
			if (lerr & (ERR_ABORT | ERR_FATAL)) {
				pxerr |= 1;
				break;
			}
			else if (lerr & ERR_CODE) {
				pxerr |= 1;
				continue;
			}
		}

		if (!pxerr) {
			curproxy->state = PR_STIDLE;
			send_log(curproxy, LOG_NOTICE, "Proxy %s started.\n", curproxy->id);
		}

		if (err & ERR_ABORT)
			break;
	}

	return err;
}


/*
 * this function enables proxies when there are enough free sessions,
 * or stops them when the table is full. It is designed to be called from the
 * select_loop(). It returns the date of next expiration event during stop
 * time, ETERNITY otherwise.
 */
void maintain_proxies(struct timeval *next)
{
	struct proxy *p;
	struct listener *l;

	p = proxy;
	tv_eternity(next);

	/* if there are enough free sessions, we'll activate proxies */
	if (actconn < global.maxconn) {
		while (p) {
			if (p->feconn < p->maxconn) {
				if (p->state == PR_STIDLE) {
					for (l = p->listen; l != NULL; l = l->next)
						enable_listener(l);
					p->state = PR_STRUN;
				}
			}
			else {
				if (p->state == PR_STRUN) {
					for (l = p->listen; l != NULL; l = l->next)
						disable_listener(l);
					p->state = PR_STIDLE;
				}
			}
			p = p->next;
		}
	}
	else {  /* block all proxies */
		while (p) {
			if (p->state == PR_STRUN) {
				for (l = p->listen; l != NULL; l = l->next)
					disable_listener(l);
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
				t = tv_ms_remain2(&now, &p->stop_time);
				if (t == 0) {
					Warning("Proxy %s stopped.\n", p->id);
					send_log(p, LOG_WARNING, "Proxy %s stopped.\n", p->id);

					for (l = p->listen; l != NULL; l = l->next) {
						unbind_listener(l);
						if (l->state >= LI_ASSIGNED) {
							delete_listener(l);
							listeners--;
						}
					}
					p->state = PR_STSTOPPED;
					/* try to free more memory */
					pool_gc2();
				}
				else {
					tv_bound(next, &p->stop_time);
				}
			}
			p = p->next;
		}
	}
	return;
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
			tv_ms_add(&p->stop_time, &now, p->grace);
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
		    listen(l->fd, p->backlog ? p->backlog : p->maxconn) == 0 &&
		    shutdown(l->fd, SHUT_RD) == 0) {
			EV_FD_CLR(l->fd, DIR_RD);
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
				if (listen(l->fd, p->backlog ? p->backlog : p->maxconn) == 0) {
					if (actconn < global.maxconn && p->feconn < p->maxconn) {
						EV_FD_SET(l->fd, DIR_RD);
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
