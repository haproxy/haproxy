/*
 * UNIX SOCK_STREAM protocol layer (uxst)
 *
 * Copyright 2000-2008 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/errors.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>
#include <common/version.h>

#include <types/global.h>

#include <proto/acl.h>
#include <proto/backend.h>
#include <proto/buffers.h>
#include <proto/dumpstats.h>
#include <proto/fd.h>
#include <proto/log.h>
#include <proto/protocols.h>
#include <proto/proto_uxst.h>
#include <proto/queue.h>
#include <proto/session.h>
#include <proto/stream_interface.h>
#include <proto/stream_sock.h>
#include <proto/task.h>

#ifndef MAXPATHLEN
#define MAXPATHLEN 128
#endif

static int uxst_bind_listeners(struct protocol *proto);
static int uxst_unbind_listeners(struct protocol *proto);

/* Note: must not be declared <const> as its list will be overwritten */
static struct protocol proto_unix = {
	.name = "unix_stream",
	.sock_domain = PF_UNIX,
	.sock_type = SOCK_STREAM,
	.sock_prot = 0,
	.sock_family = AF_UNIX,
	.sock_addrlen = sizeof(struct sockaddr_un),
	.l3_addrlen = sizeof(((struct sockaddr_un*)0)->sun_path),/* path len */
	.read = &stream_sock_read,
	.write = &stream_sock_write,
	.bind_all = uxst_bind_listeners,
	.unbind_all = uxst_unbind_listeners,
	.enable_all = enable_all_listeners,
	.disable_all = disable_all_listeners,
	.listeners = LIST_HEAD_INIT(proto_unix.listeners),
	.nb_listeners = 0,
};


/********************************
 * 1) low-level socket functions
 ********************************/


/* This function creates a named PF_UNIX stream socket at address <path>. Note
 * that the path cannot be NULL nor empty. <uid> and <gid> different of -1 will
 * be used to change the socket owner. If <mode> is not 0, it will be used to
 * restrict access to the socket. While it is known not to be portable on every
 * OS, it's still useful where it works.
 * It returns the assigned file descriptor, or -1 in the event of an error.
 */
static int create_uxst_socket(const char *path, uid_t uid, gid_t gid, mode_t mode)
{
	char tempname[MAXPATHLEN];
	char backname[MAXPATHLEN];
	struct sockaddr_un addr;

	int ret, sock;

	/* 1. create socket names */
	if (!path[0]) {
		Alert("Invalid name for a UNIX socket. Aborting.\n");
		goto err_return;
	}

	ret = snprintf(tempname, MAXPATHLEN, "%s.%d.tmp", path, pid);
	if (ret < 0 || ret >= MAXPATHLEN) {
		Alert("name too long for UNIX socket. Aborting.\n");
		goto err_return;
	}

	ret = snprintf(backname, MAXPATHLEN, "%s.%d.bak", path, pid);
	if (ret < 0 || ret >= MAXPATHLEN) {
		Alert("name too long for UNIX socket. Aborting.\n");
		goto err_return;
	}

	/* 2. clean existing orphaned entries */
	if (unlink(tempname) < 0 && errno != ENOENT) {
		Alert("error when trying to unlink previous UNIX socket. Aborting.\n");
		goto err_return;
	}

	if (unlink(backname) < 0 && errno != ENOENT) {
		Alert("error when trying to unlink previous UNIX socket. Aborting.\n");
		goto err_return;
	}

	/* 3. backup existing socket */
	if (link(path, backname) < 0 && errno != ENOENT) {
		Alert("error when trying to preserve previous UNIX socket. Aborting.\n");
		goto err_return;
	}

	/* 4. prepare new socket */
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, tempname, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		Alert("cannot create socket for UNIX listener. Aborting.\n");
		goto err_unlink_back;
	}

	if (sock >= global.maxsock) {
		Alert("socket(): not enough free sockets for UNIX listener. Raise -n argument. Aborting.\n");
		goto err_unlink_temp;
	}

	if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
		Alert("cannot make UNIX socket non-blocking. Aborting.\n");
		goto err_unlink_temp;
	}

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		/* note that bind() creates the socket <tempname> on the file system */
		Alert("cannot bind socket for UNIX listener. Aborting.\n");
		goto err_unlink_temp;
	}

	if (((uid != -1 || gid != -1) && (chown(tempname, uid, gid) == -1)) ||
	    (mode != 0 && chmod(tempname, mode) == -1)) {
		Alert("cannot change UNIX socket ownership. Aborting.\n");
		goto err_unlink_temp;
	}

	if (listen(sock, 0) < 0) {
		Alert("cannot listen to socket for UNIX listener. Aborting.\n");
		goto err_unlink_temp;
	}

	/* 5. install.
	 * Point of no return: we are ready, we'll switch the sockets. We don't
	 * fear loosing the socket <path> because we have a copy of it in
	 * backname.
	 */
	if (rename(tempname, path) < 0) {
		Alert("cannot switch final and temporary sockets for UNIX listener. Aborting.\n");
		goto err_rename;
	}

	/* 6. cleanup */
	unlink(backname); /* no need to keep this one either */

	return sock;

 err_rename:
	ret = rename(backname, path);
	if (ret < 0 && errno == ENOENT)
		unlink(path);
 err_unlink_temp:
	unlink(tempname);
	close(sock);
 err_unlink_back:
	unlink(backname);
 err_return:
	return -1;
}

/* Tries to destroy the UNIX stream socket <path>. The socket must not be used
 * anymore. It practises best effort, and no error is returned.
 */
static void destroy_uxst_socket(const char *path)
{
	struct sockaddr_un addr;
	int sock, ret;

	/* We might have been chrooted, so we may not be able to access the
	 * socket. In order to avoid bothering the other end, we connect with a
	 * wrong protocol, namely SOCK_DGRAM. The return code from connect()
	 * is enough to know if the socket is still live or not. If it's live
	 * in mode SOCK_STREAM, we get EPROTOTYPE or anything else but not
	 * ECONNREFUSED. In this case, we do not touch it because it's used
	 * by some other process.
	 */
	sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0)
		return;

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
	ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0 && errno == ECONNREFUSED) {
		/* Connect failed: the socket still exists but is not used
		 * anymore. Let's remove this socket now.
		 */
		unlink(path);
	}
	close(sock);
}


/********************************
 * 2) listener-oriented functions
 ********************************/


/* This function creates the UNIX socket associated to the listener. It changes
 * the state from ASSIGNED to LISTEN. The socket is NOT enabled for polling.
 * The return value is composed from ERR_NONE, ERR_RETRYABLE and ERR_FATAL.
 */
static int uxst_bind_listener(struct listener *listener)
{
	int fd;

	if (listener->state != LI_ASSIGNED)
		return ERR_NONE; /* already bound */

	fd = create_uxst_socket(((struct sockaddr_un *)&listener->addr)->sun_path,
				listener->perm.ux.uid,
				listener->perm.ux.gid,
				listener->perm.ux.mode);
	if (fd == -1)
		return ERR_FATAL;

	/* the socket is now listening */
	listener->fd = fd;
	listener->state = LI_LISTEN;

	/* the function for the accept() event */
	fd_insert(fd);
	fdtab[fd].cb[DIR_RD].f = listener->accept;
	fdtab[fd].cb[DIR_WR].f = NULL; /* never called */
	fdtab[fd].cb[DIR_RD].b = fdtab[fd].cb[DIR_WR].b = NULL;
	fdtab[fd].owner = listener; /* reference the listener instead of a task */
	fdtab[fd].state = FD_STLISTEN;
	fdtab[fd].peeraddr = NULL;
	fdtab[fd].peerlen = 0;
	fdtab[fd].listener = NULL;
	return ERR_NONE;
}

/* This function closes the UNIX sockets for the specified listener.
 * The listener enters the LI_ASSIGNED state. It always returns ERR_NONE.
 */
static int uxst_unbind_listener(struct listener *listener)
{
	if (listener->state == LI_READY)
		EV_FD_CLR(listener->fd, DIR_RD);

	if (listener->state >= LI_LISTEN) {
		fd_delete(listener->fd);
		listener->state = LI_ASSIGNED;
		destroy_uxst_socket(((struct sockaddr_un *)&listener->addr)->sun_path);
	}
	return ERR_NONE;
}

/* Add a listener to the list of unix stream listeners. The listener's state
 * is automatically updated from LI_INIT to LI_ASSIGNED. The number of
 * listeners is updated. This is the function to use to add a new listener.
 */
void uxst_add_listener(struct listener *listener)
{
	if (listener->state != LI_INIT)
		return;
	listener->state = LI_ASSIGNED;
	listener->proto = &proto_unix;
	LIST_ADDQ(&proto_unix.listeners, &listener->proto_list);
	proto_unix.nb_listeners++;
}

/********************************
 * 3) protocol-oriented functions
 ********************************/


/* This function creates all UNIX sockets bound to the protocol entry <proto>.
 * It is intended to be used as the protocol's bind_all() function.
 * The sockets will be registered but not added to any fd_set, in order not to
 * loose them across the fork(). A call to uxst_enable_listeners() is needed
 * to complete initialization.
 *
 * The return value is composed from ERR_NONE, ERR_RETRYABLE and ERR_FATAL.
 */
static int uxst_bind_listeners(struct protocol *proto)
{
	struct listener *listener;
	int err = ERR_NONE;

	list_for_each_entry(listener, &proto->listeners, proto_list) {
		err |= uxst_bind_listener(listener);
		if (err != ERR_NONE)
			continue;
	}
	return err;
}


/* This function stops all listening UNIX sockets bound to the protocol
 * <proto>. It does not detaches them from the protocol.
 * It always returns ERR_NONE.
 */
static int uxst_unbind_listeners(struct protocol *proto)
{
	struct listener *listener;

	list_for_each_entry(listener, &proto->listeners, proto_list)
		uxst_unbind_listener(listener);
	return ERR_NONE;
}


/********************************
 * 4) high-level functions
 ********************************/


/*
 * This function is called on a read event from a listen socket, corresponding
 * to an accept. It tries to accept as many connections as possible.
 * It returns 0. Since we use UNIX sockets on the local system for monitoring
 * purposes and other related things, we do not need to output as many messages
 * as with TCP which can fall under attack.
 */
int uxst_event_accept(int fd) {
	struct listener *l = fdtab[fd].owner;
	struct session *s;
	struct task *t;
	int cfd;
	int max_accept;

	if (global.nbproc > 1)
		max_accept = 8; /* let other processes catch some connections too */
	else
		max_accept = -1;

	while (max_accept--) {
		struct sockaddr_storage addr;
		socklen_t laddr = sizeof(addr);

		if ((cfd = accept(fd, (struct sockaddr *)&addr, &laddr)) == -1) {
			switch (errno) {
			case EAGAIN:
			case EINTR:
			case ECONNABORTED:
				return 0;	    /* nothing more to accept */
			case ENFILE:
				/* Process reached system FD limit. Check system tunables. */
				return 0;
			case EMFILE:
				/* Process reached process FD limit. Check 'ulimit-n'. */
				return 0;
			case ENOBUFS:
			case ENOMEM:
				/* Process reached system memory limit. Check system tunables. */
				return 0;
			default:
				return 0;
			}
		}

		if (l->nbconn >= l->maxconn) {
			/* too many connections, we shoot this one and return.
			 * FIXME: it would be better to simply switch the listener's
			 * state to LI_FULL and disable the FD. We could re-enable
			 * it upon fd_delete(), but this requires all protocols to
			 * be switched.
			 */
			goto out_close;
		}

		if ((s = pool_alloc2(pool2_session)) == NULL) {
			Alert("out of memory in uxst_event_accept().\n");
			goto out_close;
		}

		LIST_ADDQ(&sessions, &s->list);

		s->flags = 0;
		s->term_trace = 0;

		if ((t = pool_alloc2(pool2_task)) == NULL) {
			Alert("out of memory in uxst_event_accept().\n");
			goto out_free_session;
		}

		s->cli_addr = addr;

		/* FIXME: should be checked earlier */
		if (cfd >= global.maxsock) {
			Alert("accept(): not enough free sockets. Raise -n argument. Giving up.\n");
			goto out_free_task;
		}

		if (fcntl(cfd, F_SETFL, O_NONBLOCK) == -1) {
			Alert("accept(): cannot set the socket in non blocking mode. Giving up\n");
			goto out_free_task;
		}

		task_init(t);
		t->process = l->handler;
		t->context = s;
		t->nice = -64;  /* we want to boost priority for local stats */

		s->task = t;
		s->fe = NULL;
		s->be = NULL;

		s->cli_state = CL_STDATA;
		s->ana_state = 0;
		s->req = s->rep = NULL; /* will be allocated later */

		s->si[0].state = s->si[0].prev_state = SI_ST_EST;
		s->si[0].err_type = SI_ET_NONE;
		s->si[0].err_loc = NULL;
		s->si[0].owner = t;
		s->si[0].shutr = stream_sock_shutr;
		s->si[0].shutw = stream_sock_shutw;
		s->si[0].fd = cfd;
		s->si[0].flags = SI_FL_NONE;
		s->si[0].exp = TICK_ETERNITY;
		s->cli_fd = cfd;

		s->si[1].state = s->si[1].prev_state = SI_ST_INI;
		s->si[1].err_type = SI_ET_NONE;
		s->si[1].err_loc = NULL;
		s->si[1].owner = t;
		s->si[1].shutr = stream_sock_shutr;
		s->si[1].shutw = stream_sock_shutw;
		s->si[1].exp = TICK_ETERNITY;
		s->si[1].fd = -1; /* just to help with debugging */
		s->si[1].flags = SI_FL_NONE;

		s->srv = s->prev_srv = s->srv_conn = NULL;
		s->pend_pos = NULL;

		memset(&s->logs, 0, sizeof(s->logs));
		memset(&s->txn, 0, sizeof(s->txn));

		s->data_state = DATA_ST_INIT;
		s->data_source = DATA_SRC_NONE;
		s->uniq_id = totalconn;

		if ((s->req = pool_alloc2(pool2_buffer)) == NULL)
			goto out_free_task;

		buffer_init(s->req);
		s->req->prod = &s->si[0];
		s->req->cons = &s->si[1];
		s->si[0].ib = s->si[1].ob = s->req;
		s->req->flags |= BF_READ_ATTACHED; /* the producer is already connected */

		s->req->analysers = l->analysers;

		s->req->wto = TICK_ETERNITY;
		s->req->cto = TICK_ETERNITY;
		s->req->rto = TICK_ETERNITY;

		if ((s->rep = pool_alloc2(pool2_buffer)) == NULL)
			goto out_free_req;

		buffer_init(s->rep);

		s->rep->prod = &s->si[1];
		s->rep->cons = &s->si[0];
		s->si[0].ob = s->si[1].ib = s->rep;

		s->rep->rto = TICK_ETERNITY;
		s->rep->cto = TICK_ETERNITY;
		s->rep->wto = TICK_ETERNITY;

		s->req->rex = TICK_ETERNITY;
		s->req->wex = TICK_ETERNITY;
		s->req->analyse_exp = TICK_ETERNITY;
		s->rep->rex = TICK_ETERNITY;
		s->rep->wex = TICK_ETERNITY;
		s->rep->analyse_exp = TICK_ETERNITY;

		t->expire = TICK_ETERNITY;

		if (l->timeout) {
			s->req->rto = *l->timeout;
			s->rep->wto = *l->timeout;
		}

		fd_insert(cfd);
		fdtab[cfd].owner = &s->si[0];
		fdtab[cfd].listener = l;
		fdtab[cfd].state = FD_STREADY;
		fdtab[cfd].cb[DIR_RD].f = l->proto->read;
		fdtab[cfd].cb[DIR_RD].b = s->req;
		fdtab[cfd].cb[DIR_WR].f = l->proto->write;
		fdtab[cfd].cb[DIR_WR].b = s->rep;
		fdtab[cfd].peeraddr = (struct sockaddr *)&s->cli_addr;
		fdtab[cfd].peerlen = sizeof(s->cli_addr);

		EV_FD_SET(cfd, DIR_RD);

		task_wakeup(t, TASK_WOKEN_INIT);

		l->nbconn++; /* warning! right now, it's up to the handler to decrease this */
		if (l->nbconn >= l->maxconn) {
			EV_FD_CLR(l->fd, DIR_RD);
			l->state = LI_FULL;
		}
		actconn++;
		totalconn++;
	}
	return 0;

 out_free_req:
	pool_free2(pool2_buffer, s->req);
 out_free_task:
	pool_free2(pool2_task, t);
 out_free_session:
	LIST_DEL(&s->list);
	pool_free2(pool2_session, s);
 out_close:
	close(cfd);
	return 0;
}

/* Parses the request line in <cmd> and possibly starts dumping stats on
 * s->rep with the hijack bit set. Returns 1 if OK, 0 in case of any error.
 * The line is modified after parsing.
 */
int unix_sock_parse_request(struct session *s, char *line)
{
	char *args[MAX_UXST_ARGS + 1];
	int arg;

	while (isspace((unsigned char)*line))
		line++;

	arg = 0;
	args[arg] = line;

	while (*line && arg < MAX_UXST_ARGS) {
		if (isspace((unsigned char)*line)) {
			*line++ = '\0';

			while (isspace((unsigned char)*line))
				line++;

			args[++arg] = line;
			continue;
		}

		line++;
	}

	while (++arg <= MAX_UXST_ARGS)
		args[arg] = line;

	if (strcmp(args[0], "show") == 0) {
		if (strcmp(args[1], "stat") == 0) {
			if (*args[2] && *args[3] && *args[4]) {
				s->data_ctx.stats.flags |= STAT_BOUND;
				s->data_ctx.stats.iid	= atoi(args[2]);
				s->data_ctx.stats.type	= atoi(args[3]);
				s->data_ctx.stats.sid	= atoi(args[4]);
			}

			s->data_ctx.stats.flags |= STAT_SHOW_STAT;
			s->data_ctx.stats.flags |= STAT_FMT_CSV;
			s->ana_state = STATS_ST_REP;
			buffer_start_hijack(s->rep);
			stats_dump_raw_to_buffer(s, s->rep);
		}
		else if (strcmp(args[1], "info") == 0) {
			s->data_ctx.stats.flags |= STAT_SHOW_INFO;
			s->data_ctx.stats.flags |= STAT_FMT_CSV;
			s->ana_state = STATS_ST_REP;
			buffer_start_hijack(s->rep);
			stats_dump_raw_to_buffer(s, s->rep);
		}
		else { /* neither "stat" nor "info" */
			return 0;
		}
	}
	else { /* not "show" */
		return 0;
	}
	return 1;
}

/* Processes the stats interpreter on the statistics socket.
 * In order to ease the transition, we simply simulate the server status
 * for now. It only knows states STATS_ST_INIT, STATS_ST_REQ, STATS_ST_REP, and
 * STATS_ST_CLOSE. It removes the AN_REQ_UNIX_STATS bit from req->analysers
 * once done. It always returns 0.
 */
int uxst_req_analyser_stats(struct session *s, struct buffer *req)
{
	char *line, *p;

	switch (s->ana_state) {
	case STATS_ST_INIT:
		/* Stats output not initialized yet */
		memset(&s->data_ctx.stats, 0, sizeof(s->data_ctx.stats));
		s->data_source = DATA_SRC_STATS;
		s->ana_state = STATS_ST_REQ;
		/* fall through */

	case STATS_ST_REQ:
		/* Now, stats are initialized, hijack is not set, and
		 * we are waiting for a complete request line.
		 */

		line = s->req->data;
		p = memchr(line, '\n', s->req->l);

		if (p) {
			*p = '\0';
			if (!unix_sock_parse_request(s, line)) {
				/* invalid request */
				buffer_shutw_now(s->req);
				s->ana_state = 0;
				req->analysers = 0;
				return 0;
			}
		}

		/* processing a valid or incomplete request */
		if ((req->flags & BF_FULL)                    || /* invalid request */
		    (req->flags & BF_READ_ERROR)              || /* input error */
		    (req->flags & BF_READ_TIMEOUT)            || /* read timeout */
		    tick_is_expired(req->analyse_exp, now_ms) || /* request timeout */
		    (req->flags & BF_SHUTR)) {                   /* input closed */
			buffer_shutw_now(s->req);
			s->ana_state = 0;
			req->analysers = 0;
			return 0;
		}

		/* don't forward nor abort */
		buffer_write_dis(req);
		return 0;

	case STATS_ST_REP:
		/* do nothing while response is being processed */
		buffer_write_dis(s->req);
		return 0;

	case STATS_ST_CLOSE:
		/* end of dump */
		s->req->analysers &= ~AN_REQ_UNIX_STATS;
		s->ana_state = 0;
		break;
	}
	return 0;
}


/* This function is the unix-stream equivalent of the global process_session().
 * It is currently limited to unix-stream processing on control sockets such as
 * stats, and has no server-side. The two functions should be merged into one
 * once client and server sides are better delimited. Note that the server-side
 * still exists but remains in SI_ST_INI state forever, so that any call is a
 * NOP.
 */
void uxst_process_session(struct task *t, int *next)
{
	struct session *s = t->context;
	struct listener *listener;
	int resync;
	unsigned int rqf_last, rpf_last;

	/* 1a: Check for low level timeouts if needed. We just set a flag on
	 * stream interfaces when their timeouts have expired.
	 */
	if (unlikely(t->state & TASK_WOKEN_TIMER)) {
		stream_int_check_timeouts(&s->si[0]);
		buffer_check_timeouts(s->req);
		buffer_check_timeouts(s->rep);
	}

	/* copy req/rep flags so that we can detect shutdowns */
	rqf_last = s->req->flags;
	rpf_last = s->rep->flags;

	/* 1b: check for low-level errors reported at the stream interface. */
	if (unlikely(s->si[0].flags & SI_FL_ERR)) {
		if (s->si[0].state == SI_ST_EST || s->si[0].state == SI_ST_DIS) {
			s->si[0].shutr(&s->si[0]);
			s->si[0].shutw(&s->si[0]);
			stream_int_report_error(&s->si[0]);
		}
	}

	/* check buffer timeouts, and close the corresponding stream interfaces
	 * for future reads or writes. Note: this will also concern upper layers
	 * but we do not touch any other flag. We must be careful and correctly
	 * detect state changes when calling them.
	 */
	if (unlikely(s->req->flags & (BF_READ_TIMEOUT|BF_WRITE_TIMEOUT))) {
		if (s->req->flags & BF_READ_TIMEOUT)
			s->req->prod->shutr(s->req->prod);
		if (s->req->flags & BF_WRITE_TIMEOUT)
			s->req->cons->shutw(s->req->cons);
	}

	if (unlikely(s->rep->flags & (BF_READ_TIMEOUT|BF_WRITE_TIMEOUT))) {
		if (s->rep->flags & BF_READ_TIMEOUT)
			s->rep->prod->shutr(s->rep->prod);
		if (s->rep->flags & BF_WRITE_TIMEOUT)
			s->rep->cons->shutw(s->rep->cons);
	}

	/* Check for connection closure */

 resync_stream_interface:

	/* nothing special to be done on client side */
	if (unlikely(s->req->prod->state == SI_ST_DIS))
		s->req->prod->state = SI_ST_CLO;

	/*
	 * Note: of the transient states (REQ, CER, DIS), only REQ may remain
	 * at this point.
	 */

	/**** Process layer 7 below ****/

	resync = 0;

	/* Analyse request */
	if ((s->req->flags & BF_MASK_ANALYSER) ||
	    (s->req->flags ^ rqf_last) & BF_MASK_STATIC) {
		unsigned int flags = s->req->flags;

		if (s->req->prod->state >= SI_ST_EST) {
			/* it's up to the analysers to reset write_ena */
			buffer_write_ena(s->req);

			/* We will call all analysers for which a bit is set in
			 * s->req->analysers, following the bit order from LSB
			 * to MSB. The analysers must remove themselves from
			 * the list when not needed. This while() loop is in
			 * fact a cleaner if().
			 */
			while (s->req->analysers) {
				if (s->req->analysers & AN_REQ_UNIX_STATS)
					if (!uxst_req_analyser_stats(s, s->req))
						break;

				/* Just make sure that nobody set a wrong flag causing an endless loop */
				s->req->analysers &= AN_REQ_UNIX_STATS;

				/* we don't want to loop anyway */
				break;
			}
		}
		s->req->flags &= BF_CLEAR_READ & BF_CLEAR_WRITE & BF_CLEAR_TIMEOUT;
		flags &= BF_CLEAR_READ & BF_CLEAR_WRITE & BF_CLEAR_TIMEOUT;
		if (s->req->flags != flags)
			resync = 1;
	}

	/* reflect what the L7 analysers have seen last */
	rqf_last = s->req->flags;

	/*
	 * Now forward all shutdown requests between both sides of the buffer
	 */

	/* first, let's check if the request buffer needs to shutdown(write) */
	if (unlikely((s->req->flags & (BF_SHUTW|BF_SHUTW_NOW|BF_EMPTY|BF_HIJACK|BF_WRITE_ENA|BF_SHUTR)) ==
		     (BF_EMPTY|BF_WRITE_ENA|BF_SHUTR)))
		buffer_shutw_now(s->req);

	/* shutdown(write) pending */
	if (unlikely((s->req->flags & (BF_SHUTW|BF_SHUTW_NOW)) == BF_SHUTW_NOW))
		s->req->cons->shutw(s->req->cons);

	/* shutdown(write) done on server side, we must stop the client too */
	if (unlikely((s->req->flags & (BF_SHUTW|BF_SHUTR|BF_SHUTR_NOW)) == BF_SHUTW &&
		     !s->req->analysers))
		buffer_shutr_now(s->req);

	/* shutdown(read) pending */
	if (unlikely((s->req->flags & (BF_SHUTR|BF_SHUTR_NOW)) == BF_SHUTR_NOW))
		s->req->prod->shutr(s->req->prod);

	/*
	 * Here we want to check if we need to resync or not.
	 */
	if ((s->req->flags ^ rqf_last) & BF_MASK_STATIC)
		resync = 1;

	s->req->flags &= BF_CLEAR_READ & BF_CLEAR_WRITE & BF_CLEAR_TIMEOUT;

	/* according to benchmarks, it makes sense to resync now */
	if (resync)
		goto resync_stream_interface;


	/* Analyse response */

	buffer_write_ena(s->rep);
	if (unlikely(s->rep->flags & BF_HIJACK)) {
		/* In inject mode, we wake up everytime something has
		 * happened on the write side of the buffer.
		 */
		unsigned int flags = s->rep->flags;

		if ((s->rep->flags & (BF_WRITE_PARTIAL|BF_WRITE_ERROR|BF_SHUTW)) &&
		    !(s->rep->flags & BF_FULL)) {
			/* it is the only hijacker right now */
			stats_dump_raw_to_buffer(s, s->rep);
		}
		s->rep->flags &= BF_CLEAR_READ & BF_CLEAR_WRITE & BF_CLEAR_TIMEOUT;
		flags &= BF_CLEAR_READ & BF_CLEAR_WRITE & BF_CLEAR_TIMEOUT;
		if (s->rep->flags != flags)
			resync = 1;
	}
	else if ((s->rep->flags & BF_MASK_ANALYSER) ||
		 (s->rep->flags ^ rpf_last) & BF_MASK_STATIC) {
		unsigned int flags = s->rep->flags;

		if (s->rep->prod->state >= SI_ST_EST) {
			/* it's up to the analysers to reset write_ena */
			buffer_write_ena(s->rep);
		}
		s->rep->flags &= BF_CLEAR_READ & BF_CLEAR_WRITE & BF_CLEAR_TIMEOUT;
		flags &= BF_CLEAR_READ & BF_CLEAR_WRITE & BF_CLEAR_TIMEOUT;
		if (s->rep->flags != flags)
			resync = 1;
	}

	/* reflect what the L7 analysers have seen last */
	rpf_last = s->rep->flags;

	/*
	 * Now forward all shutdown requests between both sides of the buffer
	 */

	/*
	 * FIXME: this is probably where we should produce error responses.
	 */

	/* first, let's check if the request buffer needs to shutdown(write) */
	if (unlikely((s->rep->flags & (BF_SHUTW|BF_SHUTW_NOW|BF_EMPTY|BF_HIJACK|BF_WRITE_ENA|BF_SHUTR)) ==
		     (BF_EMPTY|BF_WRITE_ENA|BF_SHUTR)))
		buffer_shutw_now(s->rep);

	/* shutdown(write) pending */
	if (unlikely((s->rep->flags & (BF_SHUTW|BF_SHUTW_NOW)) == BF_SHUTW_NOW))
		s->rep->cons->shutw(s->rep->cons);

	/* shutdown(write) done on the client side, we must stop the server too */
	if (unlikely((s->rep->flags & (BF_SHUTW|BF_SHUTR|BF_SHUTR_NOW)) == BF_SHUTW))
		buffer_shutr_now(s->rep);

	/* shutdown(read) pending */
	if (unlikely((s->rep->flags & (BF_SHUTR|BF_SHUTR_NOW)) == BF_SHUTR_NOW))
		s->rep->prod->shutr(s->rep->prod);

	/*
	 * Here we want to check if we need to resync or not.
	 */
	if ((s->rep->flags ^ rpf_last) & BF_MASK_STATIC)
		resync = 1;

	s->rep->flags &= BF_CLEAR_READ & BF_CLEAR_WRITE & BF_CLEAR_TIMEOUT;

	if (resync)
		goto resync_stream_interface;

	if (likely(s->rep->cons->state != SI_ST_CLO)) {
		if (s->rep->cons->state == SI_ST_EST)
			stream_sock_data_finish(s->rep->cons);

		s->req->flags &= BF_CLEAR_READ & BF_CLEAR_WRITE & BF_CLEAR_TIMEOUT;
		s->rep->flags &= BF_CLEAR_READ & BF_CLEAR_WRITE & BF_CLEAR_TIMEOUT;
		s->si[0].prev_state = s->si[0].state;
		s->si[0].flags = SI_FL_NONE;

		/* Trick: if a request is being waiting for the server to respond,
		 * and if we know the server can timeout, we don't want the timeout
		 * to expire on the client side first, but we're still interested
		 * in passing data from the client to the server (eg: POST). Thus,
		 * we can cancel the client's request timeout if the server's
		 * request timeout is set and the server has not yet sent a response.
		 */

		if ((s->rep->flags & (BF_WRITE_ENA|BF_SHUTR)) == 0 &&
		    (tick_isset(s->req->wex) || tick_isset(s->rep->rex)))
			s->req->rex = TICK_ETERNITY;

		t->expire = tick_first(tick_first(s->req->rex, s->req->wex),
				       tick_first(s->rep->rex, s->rep->wex));
		if (s->req->analysers)
			t->expire = tick_first(t->expire, s->req->analyse_exp);

		if (s->si[0].exp)
			t->expire = tick_first(t->expire, s->si[0].exp);

		/* restore t to its place in the task list */
		task_queue(t);

		*next = t->expire;
		return; /* nothing more to do */
	}

	actconn--;
	listener = fdtab[s->cli_fd].listener;
	if (listener) {
		listener->nbconn--;
		if (listener->state == LI_FULL &&
		    listener->nbconn < listener->maxconn) {
			/* we should reactivate the listener */
			EV_FD_SET(listener->fd, DIR_RD);
			listener->state = LI_READY;
		}
	}

	/* the task MUST not be in the run queue anymore */
	task_delete(t);
	session_free(s);
	task_free(t);
	*next = TICK_ETERNITY;
}

__attribute__((constructor))
static void __uxst_protocol_init(void)
{
	protocol_register(&proto_unix);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
