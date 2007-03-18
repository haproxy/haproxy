/*
 * Backend variables and functions.
 *
 * Copyright 2000-2006 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/time.h>

#include <types/buffers.h>
#include <types/global.h>
#include <types/polling.h>
#include <types/proxy.h>
#include <types/server.h>
#include <types/session.h>

#include <proto/backend.h>
#include <proto/fd.h>
#include <proto/httperr.h>
#include <proto/log.h>
#include <proto/proto_http.h>
#include <proto/queue.h>
#include <proto/stream_sock.h>
#include <proto/task.h>

#ifdef CONFIG_HAP_CTTPROXY
#include <import/ip_tproxy.h>
#endif

#ifdef CONFIG_HAP_TCPSPLICE
#include <libtcpsplice.h>
#endif

/*
 * This function recounts the number of usable active and backup servers for
 * proxy <p>. These numbers are returned into the p->srv_act and p->srv_bck.
 * This function also recomputes the total active and backup weights.
 */
void recount_servers(struct proxy *px)
{
	struct server *srv;

	px->srv_act = 0; px->srv_bck = px->tot_wact = px->tot_wbck = 0;
	for (srv = px->srv; srv != NULL; srv = srv->next) {
		if (srv->state & SRV_RUNNING) {
			if (srv->state & SRV_BACKUP) {
				px->srv_bck++;
				px->tot_wbck += srv->eweight + 1;
			} else {
				px->srv_act++;
				px->tot_wact += srv->eweight + 1;
			}
		}
	}
}

/* This function recomputes the server map for proxy px. It
 * relies on px->tot_wact and px->tot_wbck, so it must be
 * called after recount_servers(). It also expects px->srv_map
 * to be initialized to the largest value needed.
 */
void recalc_server_map(struct proxy *px)
{
	int o, tot, flag;
	struct server *cur, *best;

	if (px->srv_act) {
		flag = SRV_RUNNING;
		tot  = px->tot_wact;
	} else if (px->srv_bck) {
		flag = SRV_RUNNING | SRV_BACKUP;
		if (px->options & PR_O_USE_ALL_BK)
			tot = px->tot_wbck;
		else
			tot = 1; /* the first server is enough */
	} else {
		px->srv_map_sz = 0;
		return;
	}

	/* this algorithm gives priority to the first server, which means that
	 * it will respect the declaration order for equivalent weights, and
	 * that whatever the weights, the first server called will always be
	 * the first declard. This is an important asumption for the backup
	 * case, where we want the first server only.
	 */
	for (cur = px->srv; cur; cur = cur->next)
		cur->wscore = 0;

	for (o = 0; o < tot; o++) {
		int max = 0;
		best = NULL;
		for (cur = px->srv; cur; cur = cur->next) {
			if ((cur->state & (SRV_RUNNING | SRV_BACKUP)) == flag) {
				int v;

				/* If we are forced to return only one server, we don't want to
				 * go further, because we would return the wrong one due to
				 * divide overflow.
				 */
				if (tot == 1) {
					best = cur;
					break;
				}

				cur->wscore += cur->eweight + 1;
				v = (cur->wscore + tot) / tot; /* result between 0 and 3 */
				if (best == NULL || v > max) {
					max = v;
					best = cur;
				}
			}
		}
		px->srv_map[o] = best;
		best->wscore -= tot;
	}
	px->srv_map_sz = tot;
}


/*
 * This function marks the session as 'assigned' in direct or dispatch modes,
 * or tries to assign one in balance mode, according to the algorithm. It does
 * nothing if the session had already been assigned a server.
 *
 * It may return :
 *   SRV_STATUS_OK       if everything is OK. s->srv will be valid.
 *   SRV_STATUS_NOSRV    if no server is available. s->srv = NULL.
 *   SRV_STATUS_FULL     if all servers are saturated. s->srv = NULL.
 *   SRV_STATUS_INTERNAL for other unrecoverable errors.
 *
 * Upon successful return, the session flag SN_ASSIGNED to indicate that it does
 * not need to be called anymore. This usually means that s->srv can be trusted
 * in balance and direct modes. This flag is not cleared, so it's to the caller
 * to clear it if required (eg: redispatch).
 *
 */

int assign_server(struct session *s)
{
#ifdef DEBUG_FULL
	fprintf(stderr,"assign_server : s=%p\n",s);
#endif

	if (s->pend_pos)
		return SRV_STATUS_INTERNAL;

	if (!(s->flags & SN_ASSIGNED)) {
		if (s->be->beprm->options & PR_O_BALANCE) {
			if (s->flags & SN_DIRECT) {
				s->flags |= SN_ASSIGNED;
				return SRV_STATUS_OK;
			}
			if (!s->be->beprm->srv_act && !s->be->beprm->srv_bck)
				return SRV_STATUS_NOSRV;

			if (s->be->beprm->options & PR_O_BALANCE_RR) {
				s->srv = get_server_rr_with_conns(s->be->beprm);
				if (!s->srv)
					return SRV_STATUS_FULL;
			}
			else if (s->be->beprm->options & PR_O_BALANCE_SH) {
				int len;
		
				if (s->cli_addr.ss_family == AF_INET)
					len = 4;
				else if (s->cli_addr.ss_family == AF_INET6)
					len = 16;
				else /* unknown IP family */
					return SRV_STATUS_INTERNAL;
		
				s->srv = get_server_sh(s->be->beprm,
						       (void *)&((struct sockaddr_in *)&s->cli_addr)->sin_addr,
						       len);
			}
			else /* unknown balancing algorithm */
				return SRV_STATUS_INTERNAL;
		}
		else if (!*(int *)&s->be->beprm->dispatch_addr.sin_addr &&
			 !(s->fe->options & PR_O_TRANSP)) {
			return SRV_STATUS_NOSRV;
		}
		s->flags |= SN_ASSIGNED;
	}
	return SRV_STATUS_OK;
}


/*
 * This function assigns a server address to a session, and sets SN_ADDR_SET.
 * The address is taken from the currently assigned server, or from the
 * dispatch or transparent address.
 *
 * It may return :
 *   SRV_STATUS_OK       if everything is OK.
 *   SRV_STATUS_INTERNAL for other unrecoverable errors.
 *
 * Upon successful return, the session flag SN_ADDR_SET is set. This flag is
 * not cleared, so it's to the caller to clear it if required.
 *
 */
int assign_server_address(struct session *s)
{
#ifdef DEBUG_FULL
	fprintf(stderr,"assign_server_address : s=%p\n",s);
#endif

	if ((s->flags & SN_DIRECT) || (s->be->beprm->options & PR_O_BALANCE)) {
		/* A server is necessarily known for this session */
		if (!(s->flags & SN_ASSIGNED))
			return SRV_STATUS_INTERNAL;

		s->srv_addr = s->srv->addr;

		/* if this server remaps proxied ports, we'll use
		 * the port the client connected to with an offset. */
		if (s->srv->state & SRV_MAPPORTS) {
			struct sockaddr_in sockname;
			socklen_t namelen = sizeof(sockname);

			if (!(s->fe->options & PR_O_TRANSP) ||
			    get_original_dst(s->cli_fd, (struct sockaddr_in *)&sockname, &namelen) == -1)
				getsockname(s->cli_fd, (struct sockaddr *)&sockname, &namelen);
			s->srv_addr.sin_port = htons(ntohs(s->srv_addr.sin_port) + ntohs(sockname.sin_port));
		}
	}
	else if (*(int *)&s->be->beprm->dispatch_addr.sin_addr) {
		/* connect to the defined dispatch addr */
		s->srv_addr = s->be->beprm->dispatch_addr;
	}
	else if (s->fe->options & PR_O_TRANSP) {
		/* in transparent mode, use the original dest addr if no dispatch specified */
		socklen_t salen = sizeof(s->srv_addr);

		if (get_original_dst(s->cli_fd, &s->srv_addr, &salen) == -1) {
			qfprintf(stderr, "Cannot get original server address.\n");
			return SRV_STATUS_INTERNAL;
		}
	}
	else {
		/* no server and no LB algorithm ! */
		return SRV_STATUS_INTERNAL;
	}

	s->flags |= SN_ADDR_SET;
	return SRV_STATUS_OK;
}


/* This function assigns a server to session <s> if required, and can add the
 * connection to either the assigned server's queue or to the proxy's queue.
 *
 * Returns :
 *
 *   SRV_STATUS_OK       if everything is OK.
 *   SRV_STATUS_NOSRV    if no server is available. s->srv = NULL.
 *   SRV_STATUS_QUEUED   if the connection has been queued.
 *   SRV_STATUS_FULL     if the server(s) is/are saturated and the
 *                       connection could not be queued.
 *   SRV_STATUS_INTERNAL for other unrecoverable errors.
 *
 */
int assign_server_and_queue(struct session *s)
{
	struct pendconn *p;
	int err;

	if (s->pend_pos)
		return SRV_STATUS_INTERNAL;

	if (s->flags & SN_ASSIGNED) {
		/* a server does not need to be assigned, perhaps because we're in
		 * direct mode, or in dispatch or transparent modes where the server
		 * is not needed.
		 */
		if (s->srv &&
		    s->srv->maxconn && s->srv->cur_sess >= srv_dynamic_maxconn(s->srv)) {
			p = pendconn_add(s);
			if (p)
				return SRV_STATUS_QUEUED;
			else
				return SRV_STATUS_FULL;
		}
		return SRV_STATUS_OK;
	}

	/* a server needs to be assigned */
	err = assign_server(s);
	switch (err) {
	case SRV_STATUS_OK:
		/* in balance mode, we might have servers with connection limits */
		if (s->srv &&
		    s->srv->maxconn && s->srv->cur_sess >= srv_dynamic_maxconn(s->srv)) {
			p = pendconn_add(s);
			if (p)
				return SRV_STATUS_QUEUED;
			else
				return SRV_STATUS_FULL;
		}
		return SRV_STATUS_OK;

	case SRV_STATUS_FULL:
		/* queue this session into the proxy's queue */
		p = pendconn_add(s);
		if (p)
			return SRV_STATUS_QUEUED;
		else
			return SRV_STATUS_FULL;

	case SRV_STATUS_NOSRV:
	case SRV_STATUS_INTERNAL:
		return err;
	default:
		return SRV_STATUS_INTERNAL;
	}
}


/*
 * This function initiates a connection to the server assigned to this session
 * (s->srv, s->srv_addr). It will assign a server if none is assigned yet.
 * It can return one of :
 *  - SN_ERR_NONE if everything's OK
 *  - SN_ERR_SRVTO if there are no more servers
 *  - SN_ERR_SRVCL if the connection was refused by the server
 *  - SN_ERR_PRXCOND if the connection has been limited by the proxy (maxconn)
 *  - SN_ERR_RESOURCE if a system resource is lacking (eg: fd limits, ports, ...)
 *  - SN_ERR_INTERNAL for any other purely internal errors
 * Additionnally, in the case of SN_ERR_RESOURCE, an emergency log will be emitted.
 */
int connect_server(struct session *s)
{
	int fd, err;

	if (!(s->flags & SN_ADDR_SET)) {
		err = assign_server_address(s);
		if (err != SRV_STATUS_OK)
			return SN_ERR_INTERNAL;
	}

	if ((fd = s->srv_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		qfprintf(stderr, "Cannot get a server socket.\n");

		if (errno == ENFILE)
			send_log(s->be->beprm, LOG_EMERG,
				 "Proxy %s reached system FD limit at %d. Please check system tunables.\n",
				 s->be->beprm->id, maxfd);
		else if (errno == EMFILE)
			send_log(s->be->beprm, LOG_EMERG,
				 "Proxy %s reached process FD limit at %d. Please check 'ulimit-n' and restart.\n",
				 s->be->beprm->id, maxfd);
		else if (errno == ENOBUFS || errno == ENOMEM)
			send_log(s->be->beprm, LOG_EMERG,
				 "Proxy %s reached system memory limit at %d sockets. Please check system tunables.\n",
				 s->be->beprm->id, maxfd);
		/* this is a resource error */
		return SN_ERR_RESOURCE;
	}
	
	if (fd >= global.maxsock) {
		/* do not log anything there, it's a normal condition when this option
		 * is used to serialize connections to a server !
		 */
		Alert("socket(): not enough free sockets. Raise -n argument. Giving up.\n");
		close(fd);
		return SN_ERR_PRXCOND; /* it is a configuration limit */
	}

#ifdef CONFIG_HAP_TCPSPLICE
	if ((s->fe->options & s->be->beprm->options) & PR_O_TCPSPLICE) {
		/* TCP splicing supported by both FE and BE */
		tcp_splice_initfd(s->cli_fd, fd);
	}
#endif

	if ((fcntl(fd, F_SETFL, O_NONBLOCK)==-1) ||
	    (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &one, sizeof(one)) == -1)) {
		qfprintf(stderr,"Cannot set client socket to non blocking mode.\n");
		close(fd);
		return SN_ERR_INTERNAL;
	}

	if (s->be->beprm->options & PR_O_TCP_SRV_KA)
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(one));

	/* allow specific binding :
	 * - server-specific at first
	 * - proxy-specific next
	 */
	if (s->srv != NULL && s->srv->state & SRV_BIND_SRC) {
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one));
		if (bind(fd, (struct sockaddr *)&s->srv->source_addr, sizeof(s->srv->source_addr)) == -1) {
			Alert("Cannot bind to source address before connect() for server %s/%s. Aborting.\n",
			      s->be->beprm->id, s->srv->id);
			close(fd);
			send_log(s->be->beprm, LOG_EMERG,
				 "Cannot bind to source address before connect() for server %s/%s.\n",
				 s->be->beprm->id, s->srv->id);
			return SN_ERR_RESOURCE;
		}
#ifdef CONFIG_HAP_CTTPROXY
		if (s->srv->state & SRV_TPROXY_MASK) {
			struct in_tproxy itp1, itp2;
			memset(&itp1, 0, sizeof(itp1));

			itp1.op = TPROXY_ASSIGN;
			switch (s->srv->state & SRV_TPROXY_MASK) {
			case SRV_TPROXY_ADDR:
				itp1.v.addr.faddr = s->srv->tproxy_addr.sin_addr;
				itp1.v.addr.fport = s->srv->tproxy_addr.sin_port;
				break;
			case SRV_TPROXY_CLI:
				itp1.v.addr.fport = ((struct sockaddr_in *)&s->cli_addr)->sin_port;
				/* fall through */
			case SRV_TPROXY_CIP:
				/* FIXME: what can we do if the client connects in IPv6 ? */
				itp1.v.addr.faddr = ((struct sockaddr_in *)&s->cli_addr)->sin_addr;
				break;
			}

			/* set connect flag on socket */
			itp2.op = TPROXY_FLAGS;
			itp2.v.flags = ITP_CONNECT | ITP_ONCE;

			if (setsockopt(fd, SOL_IP, IP_TPROXY, &itp1, sizeof(itp1)) == -1 ||
			    setsockopt(fd, SOL_IP, IP_TPROXY, &itp2, sizeof(itp2)) == -1) {
				Alert("Cannot bind to tproxy source address before connect() for server %s/%s. Aborting.\n",
				      s->be->beprm->id, s->srv->id);
				close(fd);
				send_log(s->be->beprm, LOG_EMERG,
					 "Cannot bind to tproxy source address before connect() for server %s/%s.\n",
					 s->be->beprm->id, s->srv->id);
				return SN_ERR_RESOURCE;
			}
		}
#endif
	}
	else if (s->be->beprm->options & PR_O_BIND_SRC) {
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one));
		if (bind(fd, (struct sockaddr *)&s->be->beprm->source_addr, sizeof(s->be->beprm->source_addr)) == -1) {
			Alert("Cannot bind to source address before connect() for proxy %s. Aborting.\n", s->be->beprm->id);
			close(fd);
			send_log(s->be->beprm, LOG_EMERG,
				 "Cannot bind to source address before connect() for server %s/%s.\n",
				 s->be->beprm->id, s->srv->id);
			return SN_ERR_RESOURCE;
		}
#ifdef CONFIG_HAP_CTTPROXY
		if (s->be->beprm->options & PR_O_TPXY_MASK) {
			struct in_tproxy itp1, itp2;
			memset(&itp1, 0, sizeof(itp1));

			itp1.op = TPROXY_ASSIGN;
			switch (s->be->beprm->options & PR_O_TPXY_MASK) {
			case PR_O_TPXY_ADDR:
				itp1.v.addr.faddr = s->srv->tproxy_addr.sin_addr;
				itp1.v.addr.fport = s->srv->tproxy_addr.sin_port;
				break;
			case PR_O_TPXY_CLI:
				itp1.v.addr.fport = ((struct sockaddr_in *)&s->cli_addr)->sin_port;
				/* fall through */
			case PR_O_TPXY_CIP:
				/* FIXME: what can we do if the client connects in IPv6 ? */
				itp1.v.addr.faddr = ((struct sockaddr_in *)&s->cli_addr)->sin_addr;
				break;
			}

			/* set connect flag on socket */
			itp2.op = TPROXY_FLAGS;
			itp2.v.flags = ITP_CONNECT | ITP_ONCE;

			if (setsockopt(fd, SOL_IP, IP_TPROXY, &itp1, sizeof(itp1)) == -1 ||
			    setsockopt(fd, SOL_IP, IP_TPROXY, &itp2, sizeof(itp2)) == -1) {
				Alert("Cannot bind to tproxy source address before connect() for proxy %s. Aborting.\n",
				      s->be->beprm->id);
				close(fd);
				send_log(s->be->beprm, LOG_EMERG,
					 "Cannot bind to tproxy source address before connect() for server %s/%s.\n",
					 s->be->beprm->id, s->srv->id);
				return SN_ERR_RESOURCE;
			}
		}
#endif
	}
	
	if ((connect(fd, (struct sockaddr *)&s->srv_addr, sizeof(s->srv_addr)) == -1) &&
	    (errno != EINPROGRESS) && (errno != EALREADY) && (errno != EISCONN)) {

		if (errno == EAGAIN || errno == EADDRINUSE) {
			char *msg;
			if (errno == EAGAIN) /* no free ports left, try again later */
				msg = "no free ports";
			else
				msg = "local address already in use";

			qfprintf(stderr,"Cannot connect: %s.\n",msg);
			close(fd);
			send_log(s->be->beprm, LOG_EMERG,
				 "Connect() failed for server %s/%s: %s.\n",
				 s->be->beprm->id, s->srv->id, msg);
			return SN_ERR_RESOURCE;
		} else if (errno == ETIMEDOUT) {
			//qfprintf(stderr,"Connect(): ETIMEDOUT");
			close(fd);
			return SN_ERR_SRVTO;
		} else {
			// (errno == ECONNREFUSED || errno == ENETUNREACH || errno == EACCES || errno == EPERM)
			//qfprintf(stderr,"Connect(): %d", errno);
			close(fd);
			return SN_ERR_SRVCL;
		}
	}

	fdtab[fd].owner = s->task;
	fdtab[fd].state = FD_STCONN; /* connection in progress */
	fdtab[fd].cb[DIR_RD].f = &stream_sock_read;
	fdtab[fd].cb[DIR_RD].b = s->rep;
	fdtab[fd].cb[DIR_WR].f = &stream_sock_write;
	fdtab[fd].cb[DIR_WR].b = s->req;
    
	MY_FD_SET(fd, StaticWriteEvent);  /* for connect status */
#if defined(DEBUG_FULL) && defined(ENABLE_EPOLL)
	if (PrevReadEvent) {
		assert(!(MY_FD_ISSET(fd, PrevReadEvent)));
		assert(!(MY_FD_ISSET(fd, PrevWriteEvent)));
	}
#endif
    
	fd_insert(fd);
	if (s->srv) {
		s->srv->cur_sess++;
		if (s->srv->cur_sess > s->srv->cur_sess_max)
			s->srv->cur_sess_max = s->srv->cur_sess;
	}

	if (s->be->beprm->contimeout)
		tv_delayfrom(&s->req->cex, &now, s->be->beprm->contimeout);
	else
		tv_eternity(&s->req->cex);
	return SN_ERR_NONE;  /* connection is OK */
}


/*
 * This function checks the retry count during the connect() job.
 * It updates the session's srv_state and retries, so that the caller knows
 * what it has to do. It uses the last connection error to set the log when
 * it expires. It returns 1 when it has expired, and 0 otherwise.
 */
int srv_count_retry_down(struct session *t, int conn_err)
{
	/* we are in front of a retryable error */
	t->conn_retries--;
	if (t->conn_retries < 0) {
		/* if not retryable anymore, let's abort */
		tv_eternity(&t->req->cex);
		srv_close_with_err(t, conn_err, SN_FINST_C,
				   503, error_message(t, HTTP_ERR_503));
		if (t->srv)
			t->srv->failed_conns++;
		t->be->beprm->failed_conns++;

		/* We used to have a free connection slot. Since we'll never use it,
		 * we have to inform the server that it may be used by another session.
		 */
		if (may_dequeue_tasks(t->srv, t->be->beprm))
			task_wakeup(&rq, t->srv->queue_mgt);
		return 1;
	}
	return 0;
}

    
/*
 * This function performs the retryable part of the connect() job.
 * It updates the session's srv_state and retries, so that the caller knows
 * what it has to do. It returns 1 when it breaks out of the loop, or 0 if
 * it needs to redispatch.
 */
int srv_retryable_connect(struct session *t)
{
	int conn_err;

	/* This loop ensures that we stop before the last retry in case of a
	 * redispatchable server.
	 */
	do {
		/* initiate a connection to the server */
		conn_err = connect_server(t);
		switch (conn_err) {
	
		case SN_ERR_NONE:
			//fprintf(stderr,"0: c=%d, s=%d\n", c, s);
			t->srv_state = SV_STCONN;
			return 1;
	    
		case SN_ERR_INTERNAL:
			tv_eternity(&t->req->cex);
			srv_close_with_err(t, SN_ERR_INTERNAL, SN_FINST_C,
					   500, error_message(t, HTTP_ERR_500));
			if (t->srv)
				t->srv->failed_conns++;
			t->be->beprm->failed_conns++;
			/* release other sessions waiting for this server */
			if (may_dequeue_tasks(t->srv, t->be->beprm))
				task_wakeup(&rq, t->srv->queue_mgt);
			return 1;
		}
		/* ensure that we have enough retries left */
		if (srv_count_retry_down(t, conn_err)) {
			return 1;
		}
	} while (t->srv == NULL || t->conn_retries > 0 || !(t->be->beprm->options & PR_O_REDISP));

	/* We're on our last chance, and the REDISP option was specified.
	 * We will ignore cookie and force to balance or use the dispatcher.
	 */
	/* let's try to offer this slot to anybody */
	if (may_dequeue_tasks(t->srv, t->be->beprm))
		task_wakeup(&rq, t->srv->queue_mgt);

	if (t->srv)
		t->srv->failed_conns++;
	t->be->beprm->failed_conns++;

	t->flags &= ~(SN_DIRECT | SN_ASSIGNED | SN_ADDR_SET);
	t->srv = NULL; /* it's left to the dispatcher to choose a server */
	http_flush_cookie_flags(&t->txn);
	return 0;
}

    
/* This function performs the "redispatch" part of a connection attempt. It
 * will assign a server if required, queue the connection if required, and
 * handle errors that might arise at this level. It can change the server
 * state. It will return 1 if it encounters an error, switches the server
 * state, or has to queue a connection. Otherwise, it will return 0 indicating
 * that the connection is ready to use.
 */

int srv_redispatch_connect(struct session *t)
{
	int conn_err;

	/* We know that we don't have any connection pending, so we will
	 * try to get a new one, and wait in this state if it's queued
	 */
	conn_err = assign_server_and_queue(t);
	switch (conn_err) {
	case SRV_STATUS_OK:
		break;

	case SRV_STATUS_NOSRV:
		/* note: it is guaranteed that t->srv == NULL here */
		tv_eternity(&t->req->cex);
		srv_close_with_err(t, SN_ERR_SRVTO, SN_FINST_C,
				   503, error_message(t, HTTP_ERR_503));
		if (t->srv)
			t->srv->failed_conns++;
		t->be->beprm->failed_conns++;

		return 1;

	case SRV_STATUS_QUEUED:
		/* FIXME-20060503 : we should use the queue timeout instead */
		if (t->be->beprm->contimeout)
			tv_delayfrom(&t->req->cex, &now, t->be->beprm->contimeout);
		else
			tv_eternity(&t->req->cex);
		t->srv_state = SV_STIDLE;
		/* do nothing else and do not wake any other session up */
		return 1;

	case SRV_STATUS_FULL:
	case SRV_STATUS_INTERNAL:
	default:
		tv_eternity(&t->req->cex);
		srv_close_with_err(t, SN_ERR_INTERNAL, SN_FINST_C,
				   500, error_message(t, HTTP_ERR_500));
		if (t->srv)
			t->srv->failed_conns++;
		t->be->beprm->failed_conns++;

		/* release other sessions waiting for this server */
		if (may_dequeue_tasks(t->srv, t->be->beprm))
			task_wakeup(&rq, t->srv->queue_mgt);
		return 1;
	}
	/* if we get here, it's because we got SRV_STATUS_OK, which also
	 * means that the connection has not been queued.
	 */
	return 0;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
