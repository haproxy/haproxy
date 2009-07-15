/*
 * Health-checks functions.
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
 * Copyright 2007-2008 Krzysztof Piotr Oledzki <ole@ans.pl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/time.h>

#include <types/global.h>

#include <proto/backend.h>
#include <proto/buffers.h>
#include <proto/fd.h>
#include <proto/log.h>
#include <proto/queue.h>
#include <proto/port_range.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/proxy.h>
#include <proto/server.h>
#include <proto/task.h>

/* sends a log message when a backend goes down, and also sets last
 * change date.
 */
static void set_backend_down(struct proxy *be)
{
	be->last_change = now.tv_sec;
	be->down_trans++;

	Alert("%s '%s' has no server available!\n", proxy_type_str(be), be->id);
	send_log(be, LOG_EMERG, "%s %s has no server available!\n", proxy_type_str(be), be->id);
}

/* Redistribute pending connections when a server goes down. The number of
 * connections redistributed is returned.
 */
static int redistribute_pending(struct server *s)
{
	struct pendconn *pc, *pc_bck, *pc_end;
	int xferred = 0;

	FOREACH_ITEM_SAFE(pc, pc_bck, &s->pendconns, pc_end, struct pendconn *, list) {
		struct session *sess = pc->sess;
		if (sess->be->options & PR_O_REDISP) {
			/* The REDISP option was specified. We will ignore
			 * cookie and force to balance or use the dispatcher.
			 */

			/* it's left to the dispatcher to choose a server */
			sess->flags &= ~(SN_DIRECT | SN_ASSIGNED | SN_ADDR_SET);

			pendconn_free(pc);
			task_wakeup(sess->task, TASK_WOKEN_RES);
			xferred++;
		}
	}
	return xferred;
}

/* Check for pending connections at the backend, and assign some of them to
 * the server coming up. The server's weight is checked before being assigned
 * connections it may not be able to handle. The total number of transferred
 * connections is returned.
 */
static int check_for_pending(struct server *s)
{
	int xferred;

	if (!s->eweight)
		return 0;

	for (xferred = 0; !s->maxconn || xferred < srv_dynamic_maxconn(s); xferred++) {
		struct session *sess;
		struct pendconn *p;

		p = pendconn_from_px(s->proxy);
		if (!p)
			break;
		p->sess->srv = s;
		sess = p->sess;
		pendconn_free(p);
		task_wakeup(sess->task, TASK_WOKEN_RES);
	}
	return xferred;
}

/* Sets server <s> down, notifies by all available means, recounts the
 * remaining servers on the proxy and transfers queued sessions whenever
 * possible to other servers. It automatically recomputes the number of
 * servers, but not the map.
 */
static void set_server_down(struct server *s)
{
	struct server *srv;
	struct chunk msg;
	int xferred;

	if (s->health == s->rise || s->tracked) {
		int srv_was_paused = s->state & SRV_GOINGDOWN;

		s->last_change = now.tv_sec;
		s->state &= ~(SRV_RUNNING | SRV_GOINGDOWN);
		s->proxy->lbprm.set_server_status_down(s);

		/* we might have sessions queued on this server and waiting for
		 * a connection. Those which are redispatchable will be queued
		 * to another server or to the proxy itself.
		 */
		xferred = redistribute_pending(s);

		msg.len = 0;
		msg.str = trash;

		chunk_printf(&msg, sizeof(trash),
			"%sServer %s/%s is DOWN", s->state & SRV_BACKUP ? "Backup " : "",
			s->proxy->id, s->id);

		if (s->tracked)
			chunk_printf(&msg, sizeof(trash), " via %s/%s",
				s->tracked->proxy->id, s->tracked->id);

		chunk_printf(&msg, sizeof(trash), ". %d active and %d backup servers left.%s"
			" %d sessions active, %d requeued, %d remaining in queue.\n",
			s->proxy->srv_act, s->proxy->srv_bck,
			(s->proxy->srv_bck && !s->proxy->srv_act) ? " Running on backup." : "",
			s->cur_sess, xferred, s->nbpend);

		Warning("%s", trash);

		/* we don't send an alert if the server was previously paused */
		if (srv_was_paused)
			send_log(s->proxy, LOG_NOTICE, "%s", trash);
		else
			send_log(s->proxy, LOG_ALERT, "%s", trash);

		if (s->proxy->srv_bck == 0 && s->proxy->srv_act == 0)
			set_backend_down(s->proxy);

		s->down_trans++;

		if (s->state & SRV_CHECKED)
			for(srv = s->tracknext; srv; srv = srv->tracknext)
				set_server_down(srv);
	}

	s->health = 0; /* failure */
}

static void set_server_up(struct server *s) {

	struct server *srv;
	struct chunk msg;
	int xferred;

	if (s->health == s->rise || s->tracked) {
		if (s->proxy->srv_bck == 0 && s->proxy->srv_act == 0) {
			if (s->proxy->last_change < now.tv_sec)		// ignore negative times
				s->proxy->down_time += now.tv_sec - s->proxy->last_change;
			s->proxy->last_change = now.tv_sec;
		}

		if (s->last_change < now.tv_sec)			// ignore negative times
			s->down_time += now.tv_sec - s->last_change;

		s->last_change = now.tv_sec;
		s->state |= SRV_RUNNING;

		if (s->slowstart > 0) {
			s->state |= SRV_WARMINGUP;
			if (s->proxy->lbprm.algo & BE_LB_PROP_DYN) {
				/* For dynamic algorithms, start at the first step of the weight,
				 * without multiplying by BE_WEIGHT_SCALE.
				 */
				s->eweight = s->uweight;
				if (s->proxy->lbprm.update_server_eweight)
					s->proxy->lbprm.update_server_eweight(s);
			}
		}
		s->proxy->lbprm.set_server_status_up(s);

		/* check if we can handle some connections queued at the proxy. We
		 * will take as many as we can handle.
		 */
		xferred = check_for_pending(s);

		msg.len = 0;
		msg.str = trash;

		chunk_printf(&msg, sizeof(trash),
			"%sServer %s/%s is UP", s->state & SRV_BACKUP ? "Backup " : "",
			s->proxy->id, s->id);

		if (s->tracked)
			chunk_printf(&msg, sizeof(trash), " via %s/%s",
				s->tracked->proxy->id, s->tracked->id);

		chunk_printf(&msg, sizeof(trash), ". %d active and %d backup servers online.%s"
			" %d sessions requeued, %d total in queue.\n",
			s->proxy->srv_act, s->proxy->srv_bck,
			(s->proxy->srv_bck && !s->proxy->srv_act) ? " Running on backup." : "",
			xferred, s->nbpend);

		Warning("%s", trash);
		send_log(s->proxy, LOG_NOTICE, "%s", trash);

		if (s->state & SRV_CHECKED)
			for(srv = s->tracknext; srv; srv = srv->tracknext)
				set_server_up(srv);
	}

	if (s->health >= s->rise)
		s->health = s->rise + s->fall - 1; /* OK now */

}

static void set_server_disabled(struct server *s) {

	struct server *srv;
	struct chunk msg;
	int xferred;

	s->state |= SRV_GOINGDOWN;
	s->proxy->lbprm.set_server_status_down(s);

	/* we might have sessions queued on this server and waiting for
	 * a connection. Those which are redispatchable will be queued
	 * to another server or to the proxy itself.
	 */
	xferred = redistribute_pending(s);

	msg.len = 0;
	msg.str = trash;

	chunk_printf(&msg, sizeof(trash),
		"Load-balancing on %sServer %s/%s is disabled",
		s->state & SRV_BACKUP ? "Backup " : "",
		s->proxy->id, s->id);

	if (s->tracked)
		chunk_printf(&msg, sizeof(trash), " via %s/%s",
			s->tracked->proxy->id, s->tracked->id);


	chunk_printf(&msg, sizeof(trash),". %d active and %d backup servers online.%s"
		" %d sessions requeued, %d total in queue.\n",
		s->proxy->srv_act, s->proxy->srv_bck,
		(s->proxy->srv_bck && !s->proxy->srv_act) ? " Running on backup." : "",
		xferred, s->nbpend);

	Warning("%s", trash);

	send_log(s->proxy, LOG_NOTICE, "%s", trash);

	if (!s->proxy->srv_bck && !s->proxy->srv_act)
		set_backend_down(s->proxy);

	if (s->state & SRV_CHECKED)
		for(srv = s->tracknext; srv; srv = srv->tracknext)
			set_server_disabled(srv);
}

static void set_server_enabled(struct server *s) {

	struct server *srv;
	struct chunk msg;
	int xferred;

	s->state &= ~SRV_GOINGDOWN;
	s->proxy->lbprm.set_server_status_up(s);

	/* check if we can handle some connections queued at the proxy. We
	 * will take as many as we can handle.
	 */
	xferred = check_for_pending(s);

	msg.len = 0;
	msg.str = trash;

	chunk_printf(&msg, sizeof(trash),
		"Load-balancing on %sServer %s/%s is enabled again",
		s->state & SRV_BACKUP ? "Backup " : "",
		s->proxy->id, s->id);

	if (s->tracked)
		chunk_printf(&msg, sizeof(trash), " via %s/%s",
			s->tracked->proxy->id, s->tracked->id);

	chunk_printf(&msg, sizeof(trash), ". %d active and %d backup servers online.%s"
		" %d sessions requeued, %d total in queue.\n",
		s->proxy->srv_act, s->proxy->srv_bck,
		(s->proxy->srv_bck && !s->proxy->srv_act) ? " Running on backup." : "",
		xferred, s->nbpend);

	Warning("%s", trash);
	send_log(s->proxy, LOG_NOTICE, "%s", trash);

	if (s->state & SRV_CHECKED)
		for(srv = s->tracknext; srv; srv = srv->tracknext)
			set_server_enabled(srv);
}

/*
 * This function is used only for server health-checks. It handles
 * the connection acknowledgement. If the proxy requires HTTP health-checks,
 * it sends the request. In other cases, it fills s->result with SRV_CHK_*.
 * The function itself returns 0 if it needs some polling before being called
 * again, otherwise 1.
 */
static int event_srv_chk_w(int fd)
{
	__label__ out_wakeup, out_nowake, out_poll, out_error;
	struct task *t = fdtab[fd].owner;
	struct server *s = t->context;

	//fprintf(stderr, "event_srv_chk_w, state=%ld\n", unlikely(fdtab[fd].state));
	if (unlikely(fdtab[fd].state == FD_STERROR || (fdtab[fd].ev & FD_POLL_ERR)))
		goto out_error;

	/* here, we know that the connection is established */

	if (!(s->result & SRV_CHK_ERROR)) {
		/* we don't want to mark 'UP' a server on which we detected an error earlier */
		if ((s->proxy->options & PR_O_HTTP_CHK) ||
		    (s->proxy->options & PR_O_SSL3_CHK) ||
		    (s->proxy->options & PR_O_SMTP_CHK)) {
			int ret;
			/* we want to check if this host replies to HTTP or SSLv3 requests
			 * so we'll send the request, and won't wake the checker up now.
			 */

			if (s->proxy->options & PR_O_SSL3_CHK) {
				/* SSL requires that we put Unix time in the request */
				int gmt_time = htonl(date.tv_sec);
				memcpy(s->proxy->check_req + 11, &gmt_time, 4);
			}

#ifndef MSG_NOSIGNAL
			ret = send(fd, s->proxy->check_req, s->proxy->check_len, MSG_DONTWAIT);
#else
			ret = send(fd, s->proxy->check_req, s->proxy->check_len, MSG_DONTWAIT | MSG_NOSIGNAL);
#endif
			if (ret == s->proxy->check_len) {
				/* we allow up to <timeout.check> if nonzero for a responce */
				if (s->proxy->timeout.check)
					t->expire = tick_add_ifset(now_ms, s->proxy->timeout.check);
				EV_FD_SET(fd, DIR_RD);   /* prepare for reading reply */
				goto out_nowake;
			}
			else if (ret == 0 || errno == EAGAIN)
				goto out_poll;
			else
				goto out_error;
		}
		else {
			/* We have no data to send to check the connection, and
			 * getsockopt() will not inform us whether the connection
			 * is still pending. So we'll reuse connect() to check the
			 * state of the socket. This has the advantage of givig us
			 * the following info :
			 *  - error
			 *  - connecting (EALREADY, EINPROGRESS)
			 *  - connected (EISCONN, 0)
			 */

			struct sockaddr_in sa;

			sa = (s->check_addr.sin_addr.s_addr) ? s->check_addr : s->addr;
			sa.sin_port = htons(s->check_port);

			if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0)
				errno = 0;

			if (errno == EALREADY || errno == EINPROGRESS)
				goto out_poll;

			if (errno && errno != EISCONN)
				goto out_error;

			/* good TCP connection is enough */
			s->result |= SRV_CHK_RUNNING;
			goto out_wakeup;
		}
	}
 out_wakeup:
	task_wakeup(t, TASK_WOKEN_IO);
 out_nowake:
	EV_FD_CLR(fd, DIR_WR);   /* nothing more to write */
	fdtab[fd].ev &= ~FD_POLL_OUT;
	return 1;
 out_poll:
	/* The connection is still pending. We'll have to poll it
	 * before attempting to go further. */
	fdtab[fd].ev &= ~FD_POLL_OUT;
	return 0;
 out_error:
	s->result |= SRV_CHK_ERROR;
	fdtab[fd].state = FD_STERROR;
	goto out_wakeup;
}


/*
 * This function is used only for server health-checks. It handles the server's
 * reply to an HTTP request or SSL HELLO. It sets s->result to SRV_CHK_RUNNING
 * if an HTTP server replies HTTP 2xx or 3xx (valid responses), if an SMTP
 * server returns 2xx, or if an SSL server returns at least 5 bytes in response
 * to an SSL HELLO (the principle is that this is enough to distinguish between
 * an SSL server and a pure TCP relay). All other cases will set s->result to
 * SRV_CHK_ERROR. The function returns 0 if it needs to be called again after
 * some polling, otherwise non-zero..
 */
static int event_srv_chk_r(int fd)
{
	__label__ out_wakeup;
	int len;
	struct task *t = fdtab[fd].owner;
	struct server *s = t->context;
	int skerr;
	socklen_t lskerr = sizeof(skerr);

	len = -1;

	if (unlikely((s->result & SRV_CHK_ERROR) ||
		     (fdtab[fd].state == FD_STERROR) ||
		     (fdtab[fd].ev & FD_POLL_ERR) ||
		     (getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr) == -1) ||
		     (skerr != 0))) {
		/* in case of TCP only, this tells us if the connection failed */
		s->result |= SRV_CHK_ERROR;
		goto out_wakeup;
	}

#ifndef MSG_NOSIGNAL
	len = recv(fd, trash, sizeof(trash), 0);
#else
	/* Warning! Linux returns EAGAIN on SO_ERROR if data are still available
	 * but the connection was closed on the remote end. Fortunately, recv still
	 * works correctly and we don't need to do the getsockopt() on linux.
	 */
	len = recv(fd, trash, sizeof(trash), MSG_NOSIGNAL);
#endif
	if (unlikely(len < 0 && errno == EAGAIN)) {
		/* we want some polling to happen first */
		fdtab[fd].ev &= ~FD_POLL_IN;
		return 0;
	}

	/* Note: the response will only be accepted if read at once */
	if (s->proxy->options & PR_O_HTTP_CHK) {
		/* Check if the server speaks HTTP 1.X */
		if ((len < strlen("HTTP/1.0 000\r")) ||
		    (memcmp(trash, "HTTP/1.", 7) != 0)) {
			s->result |= SRV_CHK_ERROR;
			goto out_wakeup;
		}

		/* check the reply : HTTP/1.X 2xx and 3xx are OK */
		if (trash[9] == '2' || trash[9] == '3')
			s->result |= SRV_CHK_RUNNING;
		else if ((s->proxy->options & PR_O_DISABLE404) &&
			 (s->state & SRV_RUNNING) &&
			 (memcmp(&trash[9], "404", 3) == 0)) {
			/* 404 may be accepted as "stopping" only if the server was up */
			s->result |= SRV_CHK_RUNNING | SRV_CHK_DISABLE;
		}
		else
			s->result |= SRV_CHK_ERROR;
	}
	else if (s->proxy->options & PR_O_SSL3_CHK) {
		/* Check for SSLv3 alert or handshake */
		if ((len >= 5) && (trash[0] == 0x15 || trash[0] == 0x16))
			s->result |= SRV_CHK_RUNNING;
		else
			s->result |= SRV_CHK_ERROR;
	}
	else if (s->proxy->options & PR_O_SMTP_CHK) {
		/* Check for SMTP code 2xx (should be 250) */
		if ((len >= 3) && (trash[0] == '2'))
			s->result |= SRV_CHK_RUNNING;
		else
			s->result |= SRV_CHK_ERROR;
	}
	else {
		/* other checks are valid if the connection succeeded anyway */
		s->result |= SRV_CHK_RUNNING;
	}

 out_wakeup:
	if (s->result & SRV_CHK_ERROR)
		fdtab[fd].state = FD_STERROR;

	EV_FD_CLR(fd, DIR_RD);
	task_wakeup(t, TASK_WOKEN_IO);
	fdtab[fd].ev &= ~FD_POLL_IN;
	return 1;
}

/*
 * manages a server health-check. Returns
 * the time the task accepts to wait, or TIME_ETERNITY for infinity.
 */
struct task *process_chk(struct task *t)
{
	int attempts = 0;
	struct server *s = t->context;
	struct sockaddr_in sa;
	int fd;
	int rv;

	//fprintf(stderr, "process_chk: task=%p\n", t);

 new_chk:
	if (attempts++ > 0) {
		/* we always fail to create a server, let's stop insisting... */
		while (tick_is_expired(t->expire, now_ms))
			t->expire = tick_add(t->expire, MS_TO_TICKS(s->inter));
		return t;
	}
	fd = s->curfd;
	if (fd < 0) {   /* no check currently running */
		//fprintf(stderr, "process_chk: 2\n");
		if (!tick_is_expired(t->expire, now_ms)) /* woke up too early */
			return t;

		/* we don't send any health-checks when the proxy is stopped or when
		 * the server should not be checked.
		 */
		if (!(s->state & SRV_CHECKED) || s->proxy->state == PR_STSTOPPED) {
			while (tick_is_expired(t->expire, now_ms))
				t->expire = tick_add(t->expire, MS_TO_TICKS(s->inter));
			return t;
		}

		/* we'll initiate a new check */
		s->result = SRV_CHK_UNKNOWN; /* no result yet */
		if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != -1) {
			if ((fd < global.maxsock) &&
			    (fcntl(fd, F_SETFL, O_NONBLOCK) != -1) &&
			    (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &one, sizeof(one)) != -1)) {
				//fprintf(stderr, "process_chk: 3\n");

				if (s->proxy->options & PR_O_TCP_NOLING) {
					/* We don't want to useless data */
					setsockopt(fd, SOL_SOCKET, SO_LINGER, (struct linger *) &nolinger, sizeof(struct linger));
				}
				
				if (s->check_addr.sin_addr.s_addr)
					/* we'll connect to the check addr specified on the server */
					sa = s->check_addr;
				else
					/* we'll connect to the addr on the server */
					sa = s->addr;

				/* we'll connect to the check port on the server */
				sa.sin_port = htons(s->check_port);

				/* allow specific binding :
				 * - server-specific at first
				 * - proxy-specific next
				 */
				if (s->state & SRV_BIND_SRC) {
					struct sockaddr_in *remote = NULL;
					int ret, flags = 0;

#if defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_LINUX_TPROXY)
					if ((s->state & SRV_TPROXY_MASK) == SRV_TPROXY_ADDR) {
						remote = (struct sockaddr_in *)&s->tproxy_addr;
						flags  = 3;
					}
#endif
#ifdef SO_BINDTODEVICE
					/* Note: this might fail if not CAP_NET_RAW */
					if (s->iface_name)
						setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
							   s->iface_name, s->iface_len + 1);
#endif
					if (s->sport_range) {
						int bind_attempts = 10; /* should be more than enough to find a spare port */
						struct sockaddr_in src;

						ret = 1;
						src = s->source_addr;

						do {
							/* note: in case of retry, we may have to release a previously
							 * allocated port, hence this loop's construct.
							 */
							port_range_release_port(fdtab[fd].port_range, fdtab[fd].local_port);
							fdtab[fd].port_range = NULL;

							if (!bind_attempts)
								break;
							bind_attempts--;

							fdtab[fd].local_port = port_range_alloc_port(s->sport_range);
							if (!fdtab[fd].local_port)
								break;

							fdtab[fd].port_range = s->sport_range;
							src.sin_port = htons(fdtab[fd].local_port);

							ret = tcpv4_bind_socket(fd, flags, &src, remote);
						} while (ret != 0); /* binding NOK */
					}
					else {
						ret = tcpv4_bind_socket(fd, flags, &s->source_addr, remote);
					}

					if (ret) {
						s->result |= SRV_CHK_ERROR;
						switch (ret) {
						case 1:
							Alert("Cannot bind to source address before connect() for server %s/%s. Aborting.\n",
							      s->proxy->id, s->id);
							break;
						case 2:
							Alert("Cannot bind to tproxy source address before connect() for server %s/%s. Aborting.\n",
							      s->proxy->id, s->id);
							break;
						}
					}
				}
				else if (s->proxy->options & PR_O_BIND_SRC) {
					struct sockaddr_in *remote = NULL;
					int ret, flags = 0;

#if defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_LINUX_TPROXY)
					if ((s->proxy->options & PR_O_TPXY_MASK) == PR_O_TPXY_ADDR) {
						remote = (struct sockaddr_in *)&s->proxy->tproxy_addr;
						flags  = 3;
					}
#endif
#ifdef SO_BINDTODEVICE
					/* Note: this might fail if not CAP_NET_RAW */
					if (s->proxy->iface_name)
						setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
							   s->proxy->iface_name, s->proxy->iface_len + 1);
#endif
					ret = tcpv4_bind_socket(fd, flags, &s->proxy->source_addr, remote);
					if (ret) {
						s->result |= SRV_CHK_ERROR;
						switch (ret) {
						case 1:
							Alert("Cannot bind to source address before connect() for %s '%s'. Aborting.\n",
							      proxy_type_str(s->proxy), s->proxy->id);
							break;
						case 2:
							Alert("Cannot bind to tproxy source address before connect() for %s '%s'. Aborting.\n",
							      proxy_type_str(s->proxy), s->proxy->id);
							break;
						}
					}
				}

				if (s->result == SRV_CHK_UNKNOWN) {
#ifdef TCP_QUICKACK
					/* disabling tcp quick ack now allows
					 * the request to leave the machine with
					 * the first ACK.
					 */
					if (s->proxy->options2 & PR_O2_SMARTCON)
						setsockopt(fd, SOL_TCP, TCP_QUICKACK, (char *) &zero, sizeof(zero));
#endif
					if ((connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != -1) || (errno == EINPROGRESS)) {
						/* OK, connection in progress or established */
			
						//fprintf(stderr, "process_chk: 4\n");
			
						s->curfd = fd; /* that's how we know a test is in progress ;-) */
						fd_insert(fd);
						fdtab[fd].owner = t;
						fdtab[fd].cb[DIR_RD].f = &event_srv_chk_r;
						fdtab[fd].cb[DIR_RD].b = NULL;
						fdtab[fd].cb[DIR_WR].f = &event_srv_chk_w;
						fdtab[fd].cb[DIR_WR].b = NULL;
						fdtab[fd].peeraddr = (struct sockaddr *)&sa;
						fdtab[fd].peerlen = sizeof(sa);
						fdtab[fd].state = FD_STCONN; /* connection in progress */
						fdtab[fd].flags = FD_FL_TCP | FD_FL_TCP_NODELAY;
						EV_FD_SET(fd, DIR_WR);  /* for connect status */
#ifdef DEBUG_FULL
						assert (!EV_FD_ISSET(fd, DIR_RD));
#endif
						//fprintf(stderr, "process_chk: 4+, %lu\n", __tv_to_ms(&s->proxy->timeout.connect));
						/* we allow up to min(inter, timeout.connect) for a connection
						 * to establish but only when timeout.check is set
						 * as it may be to short for a full check otherwise
						 */
						t->expire = tick_add(now_ms, MS_TO_TICKS(s->inter));

						if (s->proxy->timeout.check && s->proxy->timeout.connect) {
							int t_con = tick_add(now_ms, s->proxy->timeout.connect);
							t->expire = tick_first(t->expire, t_con);
						}
						return t;
					}
					else if (errno != EALREADY && errno != EISCONN && errno != EAGAIN) {
						s->result |= SRV_CHK_ERROR;    /* a real error */
					}
				}
			}
			port_range_release_port(fdtab[fd].port_range, fdtab[fd].local_port);
			fdtab[fd].port_range = NULL;
			close(fd); /* socket creation error */
		}

		if (s->result == SRV_CHK_UNKNOWN) { /* nothing done */
			//fprintf(stderr, "process_chk: 6\n");
			while (tick_is_expired(t->expire, now_ms))
				t->expire = tick_add(t->expire, MS_TO_TICKS(s->inter));
			goto new_chk; /* may be we should initialize a new check */
		}

		/* here, we have seen a failure */
		if (s->health > s->rise) {
			s->health--; /* still good */
			s->failed_checks++;
		}
		else
			set_server_down(s);

		//fprintf(stderr, "process_chk: 7, %lu\n", __tv_to_ms(&s->proxy->timeout.connect));
		/* we allow up to min(inter, timeout.connect) for a connection
		 * to establish but only when timeout.check is set
		 * as it may be to short for a full check otherwise
		 */
		while (tick_is_expired(t->expire, now_ms)) {
			int t_con;

			t_con = tick_add(t->expire, s->proxy->timeout.connect);
			t->expire = tick_add(t->expire, MS_TO_TICKS(s->inter));

			if (s->proxy->timeout.check)
				t->expire = tick_first(t->expire, t_con);
		}
		goto new_chk;
	}
	else {
		//fprintf(stderr, "process_chk: 8\n");
		/* there was a test running */
		if ((s->result & (SRV_CHK_ERROR|SRV_CHK_RUNNING)) == SRV_CHK_RUNNING) { /* good server detected */
			//fprintf(stderr, "process_chk: 9\n");

			if (s->state & SRV_WARMINGUP) {
				if (now.tv_sec < s->last_change || now.tv_sec >= s->last_change + s->slowstart) {
					s->state &= ~SRV_WARMINGUP;
					if (s->proxy->lbprm.algo & BE_LB_PROP_DYN)
						s->eweight = s->uweight * BE_WEIGHT_SCALE;
					if (s->proxy->lbprm.update_server_eweight)
						s->proxy->lbprm.update_server_eweight(s);
				}
				else if (s->proxy->lbprm.algo & BE_LB_PROP_DYN) {
					/* for dynamic algorithms, let's update the weight */
					s->eweight = (BE_WEIGHT_SCALE * (now.tv_sec - s->last_change) +
						      s->slowstart - 1) / s->slowstart;
					s->eweight *= s->uweight;
					if (s->proxy->lbprm.update_server_eweight)
						s->proxy->lbprm.update_server_eweight(s);
				}
				/* probably that we can refill this server with a bit more connections */
				check_for_pending(s);
			}

			/* we may have to add/remove this server from the LB group */
			if ((s->state & SRV_RUNNING) && (s->proxy->options & PR_O_DISABLE404)) {
				if ((s->state & SRV_GOINGDOWN) &&
				    ((s->result & (SRV_CHK_RUNNING|SRV_CHK_DISABLE)) == SRV_CHK_RUNNING))
					set_server_enabled(s);
				else if (!(s->state & SRV_GOINGDOWN) &&
					 ((s->result & (SRV_CHK_RUNNING | SRV_CHK_DISABLE)) ==
					  (SRV_CHK_RUNNING | SRV_CHK_DISABLE)))
					set_server_disabled(s);
			}

			if (s->health < s->rise + s->fall - 1) {
				s->health++; /* was bad, stays for a while */

				set_server_up(s);
			}
			s->curfd = -1; /* no check running anymore */
			fd_delete(fd);

			rv = 0;
			if (global.spread_checks > 0) {
				rv = srv_getinter(s) * global.spread_checks / 100;
				rv -= (int) (2 * rv * (rand() / (RAND_MAX + 1.0)));
				//fprintf(stderr, "process_chk(%p): (%d+/-%d%%) random=%d\n", s, srv_getinter(s), global.spread_checks, rv);
			}
			t->expire = tick_add(now_ms, MS_TO_TICKS(srv_getinter(s) + rv));
			goto new_chk;
		}
		else if ((s->result & SRV_CHK_ERROR) || tick_is_expired(t->expire, now_ms)) {
			//fprintf(stderr, "process_chk: 10\n");
			/* failure or timeout detected */
			if (s->health > s->rise) {
				s->health--; /* still good */
				s->failed_checks++;
			}
			else
				set_server_down(s);
			s->curfd = -1;
			fd_delete(fd);

			rv = 0;
			if (global.spread_checks > 0) {
				rv = srv_getinter(s) * global.spread_checks / 100;
				rv -= (int) (2 * rv * (rand() / (RAND_MAX + 1.0)));
				//fprintf(stderr, "process_chk(%p): (%d+/-%d%%) random=%d\n", s, srv_getinter(s), global.spread_checks, rv);
			}
			t->expire = tick_add(now_ms, MS_TO_TICKS(srv_getinter(s) + rv));
			goto new_chk;
		}
		/* if result is unknown and there's no timeout, we have to wait again */
	}
	//fprintf(stderr, "process_chk: 11\n");
	s->result = SRV_CHK_UNKNOWN;
	return t;
}

/*
 * Start health-check.
 * Returns 0 if OK, -1 if error, and prints the error in this case.
 */
int start_checks() {

	struct proxy *px;
	struct server *s;
	struct task *t;
	int nbchk=0, mininter=0, srvpos=0;

	/* 1- count the checkers to run simultaneously.
	 * We also determine the minimum interval among all of those which
	 * have an interval larger than SRV_CHK_INTER_THRES. This interval
	 * will be used to spread their start-up date. Those which have
	 * a shorter interval will start independantly and will not dictate
	 * too short an interval for all others.
	 */
	for (px = proxy; px; px = px->next) {
		for (s = px->srv; s; s = s->next) {
			if (!(s->state & SRV_CHECKED))
				continue;

			if ((srv_getinter(s) >= SRV_CHK_INTER_THRES) &&
			    (!mininter || mininter > srv_getinter(s)))
				mininter = srv_getinter(s);

			nbchk++;
		}
	}

	if (!nbchk)
		return 0;

	srand((unsigned)time(NULL));

	/*
	 * 2- start them as far as possible from each others. For this, we will
	 * start them after their interval set to the min interval divided by
	 * the number of servers, weighted by the server's position in the list.
	 */
	for (px = proxy; px; px = px->next) {
		for (s = px->srv; s; s = s->next) {
			if (!(s->state & SRV_CHECKED))
				continue;

			if ((t = task_new()) == NULL) {
				Alert("Starting [%s:%s] check: out of memory.\n", px->id, s->id);
				return -1;
			}

			s->check = t;
			t->process = process_chk;
			t->context = s;

			/* check this every ms */
			t->expire = tick_add(now_ms,
					     MS_TO_TICKS(((mininter && mininter >= srv_getinter(s)) ?
							  mininter : srv_getinter(s)) * srvpos / nbchk));
			task_queue(t);

			srvpos++;
		}
	}
	return 0;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
