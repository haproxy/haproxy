/*
 * UNIX SOCK_STREAM protocol layer (uxst)
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
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
		Alert("Invalid empty name for a UNIX socket. Aborting.\n");
		goto err_return;
	}

	ret = snprintf(tempname, MAXPATHLEN, "%s.%d.tmp", path, pid);
	if (ret < 0 || ret >= MAXPATHLEN) {
		Alert("name too long for UNIX socket (%s). Aborting.\n", path);
		goto err_return;
	}

	ret = snprintf(backname, MAXPATHLEN, "%s.%d.bak", path, pid);
	if (ret < 0 || ret >= MAXPATHLEN) {
		Alert("name too long for UNIX socket (%s). Aborting.\n", path);
		goto err_return;
	}

	/* 2. clean existing orphaned entries */
	if (unlink(tempname) < 0 && errno != ENOENT) {
		Alert("error when trying to unlink previous UNIX socket (%s). Aborting.\n", path);
		goto err_return;
	}

	if (unlink(backname) < 0 && errno != ENOENT) {
		Alert("error when trying to unlink previous UNIX socket (%s). Aborting.\n", path);
		goto err_return;
	}

	/* 3. backup existing socket */
	if (link(path, backname) < 0 && errno != ENOENT) {
		Alert("error when trying to preserve previous UNIX socket (%s). Aborting.\n", path);
		goto err_return;
	}

	/* 4. prepare new socket */
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, tempname, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		Alert("cannot create socket for UNIX listener (%s). Aborting.\n", path);
		goto err_unlink_back;
	}

	if (sock >= global.maxsock) {
		Alert("socket(): not enough free sockets for UNIX listener (%s). Raise -n argument. Aborting.\n", path);
		goto err_unlink_temp;
	}

	if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
		Alert("cannot make UNIX socket non-blocking. Aborting.\n");
		goto err_unlink_temp;
	}

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		/* note that bind() creates the socket <tempname> on the file system */
		Alert("cannot bind socket for UNIX listener (%s). Aborting.\n", path);
		goto err_unlink_temp;
	}

	if (((uid != -1 || gid != -1) && (chown(tempname, uid, gid) == -1)) ||
	    (mode != 0 && chmod(tempname, mode) == -1)) {
		Alert("cannot change UNIX socket ownership (%s). Aborting.\n", path);
		goto err_unlink_temp;
	}

	if (listen(sock, 0) < 0) {
		Alert("cannot listen to socket for UNIX listener (%s). Aborting.\n", path);
		goto err_unlink_temp;
	}

	/* 5. install.
	 * Point of no return: we are ready, we'll switch the sockets. We don't
	 * fear loosing the socket <path> because we have a copy of it in
	 * backname.
	 */
	if (rename(tempname, path) < 0) {
		Alert("cannot switch final and temporary sockets for UNIX listener (%s). Aborting.\n", path);
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
	fdinfo[fd].peeraddr = NULL;
	fdinfo[fd].peerlen = 0;
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

		if (l->nbconn >= l->maxconn || actconn >= global.maxconn) {
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
		LIST_INIT(&s->back_refs);

		s->flags = 0;
		s->term_trace = 0;

		if ((t = task_new()) == NULL) {
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
			Alert("accept(): cannot set the socket in non blocking mode. Giving up.\n");
			goto out_free_task;
		}

		t->process = l->handler;
		t->context = s;
		t->nice = l->nice;

		s->task = t;
		s->listener = l;
		s->fe = s->be = l->private;

		s->req = s->rep = NULL; /* will be allocated later */

		s->si[0].state = s->si[0].prev_state = SI_ST_EST;
		s->si[0].err_type = SI_ET_NONE;
		s->si[0].err_loc = NULL;
		s->si[0].owner = t;
		s->si[0].update = stream_sock_data_finish;
		s->si[0].shutr = stream_sock_shutr;
		s->si[0].shutw = stream_sock_shutw;
		s->si[0].chk_rcv = stream_sock_chk_rcv;
		s->si[0].chk_snd = stream_sock_chk_snd;
		s->si[0].connect = NULL;
		s->si[0].iohandler = NULL;
		s->si[0].fd = cfd;
		s->si[0].flags = SI_FL_NONE;
		if (s->fe->options2 & PR_O2_INDEPSTR)
			s->si[0].flags |= SI_FL_INDEP_STR;
		s->si[0].exp = TICK_ETERNITY;

		s->si[1].state = s->si[1].prev_state = SI_ST_INI;
		s->si[1].err_type = SI_ET_NONE;
		s->si[1].err_loc = NULL;
		s->si[1].owner = t;
		s->si[1].exp = TICK_ETERNITY;
		s->si[1].fd = -1; /* just to help with debugging */
		s->si[1].flags = SI_FL_NONE;
		if (s->be->options2 & PR_O2_INDEPSTR)
			s->si[1].flags |= SI_FL_INDEP_STR;

		stream_int_register_handler(&s->si[1], stats_io_handler);
		s->si[1].private = s;
		s->si[1].st1 = 0;
		s->si[1].st0 = STAT_CLI_INIT;

		s->srv = s->prev_srv = s->srv_conn = NULL;
		s->pend_pos = NULL;

		s->store_count = 0;

		memset(&s->logs, 0, sizeof(s->logs));
		memset(&s->txn, 0, sizeof(s->txn));

		s->logs.accept_date = date; /* user-visible date for logging */
		s->logs.tv_accept = now;  /* corrected date for internal use */

		s->data_state = DATA_ST_INIT;
		s->data_source = DATA_SRC_NONE;
		s->uniq_id = totalconn;

		if ((s->req = pool_alloc2(pool2_buffer)) == NULL)
			goto out_free_task;

		s->req->size = global.tune.bufsize;
		buffer_init(s->req);
		s->req->prod = &s->si[0];
		s->req->cons = &s->si[1];
		s->si[0].ib = s->si[1].ob = s->req;
		s->req->flags |= BF_READ_ATTACHED; /* the producer is already connected */
		s->req->flags |= BF_READ_DONTWAIT; /* we plan to read small requests */

		s->req->analysers = l->analysers;

		s->req->wto = TICK_ETERNITY;
		s->req->cto = TICK_ETERNITY;
		s->req->rto = TICK_ETERNITY;

		if ((s->rep = pool_alloc2(pool2_buffer)) == NULL)
			goto out_free_req;

		s->rep->size = global.tune.bufsize;
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
		fdtab[cfd].state = FD_STREADY;
		fdtab[cfd].cb[DIR_RD].f = l->proto->read;
		fdtab[cfd].cb[DIR_RD].b = s->req;
		fdtab[cfd].cb[DIR_WR].f = l->proto->write;
		fdtab[cfd].cb[DIR_WR].b = s->rep;
		fdinfo[cfd].peeraddr = (struct sockaddr *)&s->cli_addr;
		fdinfo[cfd].peerlen = sizeof(s->cli_addr);

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
	task_free(t);
 out_free_session:
	LIST_DEL(&s->list);
	pool_free2(pool2_session, s);
 out_close:
	close(cfd);
	return 0;
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
