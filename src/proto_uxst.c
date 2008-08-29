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
#include <proto/senddata.h>
#include <proto/session.h>
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
	fdtab[fd].owner = (struct task *)listener; /* reference the listener instead of a task */
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
	struct listener *l = (struct listener *)fdtab[fd].owner;
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
			close(cfd);
			return 0;
		}

		if ((s = pool_alloc2(pool2_session)) == NULL) {
			Alert("out of memory in uxst_event_accept().\n");
			close(cfd);
			return 0;
		}

		s->flags = 0;
		s->term_trace = 0;

		if ((t = pool_alloc2(pool2_task)) == NULL) {
			Alert("out of memory in uxst_event_accept().\n");
			close(cfd);
			pool_free2(pool2_session, s);
			return 0;
		}

		s->cli_addr = addr;

		/* FIXME: should be checked earlier */
		if (cfd >= global.maxsock) {
			Alert("accept(): not enough free sockets. Raise -n argument. Giving up.\n");
			close(cfd);
			pool_free2(pool2_task, t);
			pool_free2(pool2_session, s);
			return 0;
		}

		if (fcntl(cfd, F_SETFL, O_NONBLOCK) == -1) {
			Alert("accept(): cannot set the socket in non blocking mode. Giving up\n");
			close(cfd);
			pool_free2(pool2_task, t);
			pool_free2(pool2_session, s);
			return 0;
		}

		task_init(t);
		t->process = l->handler;
		t->context = s;
		t->nice = -64;  /* we want to boost priority for local stats */

		s->task = t;
		s->fe = NULL;
		s->be = NULL;

		s->cli_state = CL_STDATA;
		s->srv_state = SV_STIDLE;
		s->req = s->rep = NULL; /* will be allocated later */

		s->cli_fd = cfd;
		s->srv = NULL;
		s->pend_pos = NULL;

		memset(&s->logs, 0, sizeof(s->logs));
		memset(&s->txn, 0, sizeof(s->txn));

		s->data_state = DATA_ST_INIT;
		s->data_source = DATA_SRC_NONE;
		s->uniq_id = totalconn;

		if ((s->req = pool_alloc2(pool2_buffer)) == NULL) { /* no memory */
			close(cfd); /* nothing can be done for this fd without memory */
			pool_free2(pool2_task, t);
			pool_free2(pool2_session, s);
			return 0;
		}

		if ((s->rep = pool_alloc2(pool2_buffer)) == NULL) { /* no memory */
			pool_free2(pool2_buffer, s->req);
			close(cfd); /* nothing can be done for this fd without memory */
			pool_free2(pool2_task, t);
			pool_free2(pool2_session, s);
			return 0;
		}

		buffer_init(s->req);
		buffer_init(s->rep);

		fd_insert(cfd);
		fdtab[cfd].owner = t;
		fdtab[cfd].listener = l;
		fdtab[cfd].state = FD_STREADY;
		fdtab[cfd].cb[DIR_RD].f = l->proto->read;
		fdtab[cfd].cb[DIR_RD].b = s->req;
		fdtab[cfd].cb[DIR_WR].f = l->proto->write;
		fdtab[cfd].cb[DIR_WR].b = s->rep;
		fdtab[cfd].peeraddr = (struct sockaddr *)&s->cli_addr;
		fdtab[cfd].peerlen = sizeof(s->cli_addr);

		s->req->rex = TICK_ETERNITY;
		s->req->wex = TICK_ETERNITY;
		s->req->analyse_exp = TICK_ETERNITY;
		s->rep->rex = TICK_ETERNITY;
		s->rep->wex = TICK_ETERNITY;
		s->rep->analyse_exp = TICK_ETERNITY;

		s->req->wto = TICK_ETERNITY;
		s->req->cto = TICK_ETERNITY;
		s->req->rto = TICK_ETERNITY;
		s->rep->rto = TICK_ETERNITY;
		s->rep->cto = TICK_ETERNITY;
		s->rep->wto = TICK_ETERNITY;

		if (l->timeout)
			s->req->rto = *l->timeout;

		if (l->timeout)
			s->rep->wto = *l->timeout;

		t->expire = TICK_ETERNITY;
		if (l->timeout && *l->timeout) {
			EV_FD_SET(cfd, DIR_RD);
			s->req->rex = tick_add(now_ms, s->req->rto);
			t->expire = s->req->rex;
		}

		task_wakeup(t, TASK_WOKEN_INIT);

		l->nbconn++; /* warning! right now, it's up to the handler to decrease this */
		if (l->nbconn >= l->maxconn) {
			EV_FD_CLR(l->fd, DIR_RD);
			l->state = LI_FULL;
		}
		actconn++;
		totalconn++;

		//fprintf(stderr, "accepting from %p => %d conn, %d total, task=%p, cfd=%d, maxfd=%d\n", p, actconn, totalconn, t, cfd, maxfd);
	} /* end of while (p->feconn < p->maxconn) */
	//fprintf(stderr,"fct %s:%d\n", __FUNCTION__, __LINE__);
	return 0;
}

/*
 * manages the client FSM and its socket. It returns 1 if a state has changed
 * (and a resync may be needed), otherwise 0.
 */
static int process_uxst_cli(struct session *t)
{
	int s = t->srv_state;
	int c = t->cli_state;
	struct buffer *req = t->req;
	struct buffer *rep = t->rep;
	//fprintf(stderr,"fct %s:%d\n", __FUNCTION__, __LINE__);
	if (c == CL_STDATA) {
		/* FIXME: this error handling is partly buggy because we always report
		 * a 'DATA' phase while we don't know if the server was in IDLE, CONN
		 * or HEADER phase. BTW, it's not logical to expire the client while
		 * we're waiting for the server to connect.
		 */
		/* read or write error */
		if (rep->flags & BF_WRITE_ERROR || req->flags & BF_READ_ERROR) {
			buffer_shutr(req);
			buffer_shutw(rep);
			fd_delete(t->cli_fd);
			t->cli_state = CL_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_CLICL;
			if (!(t->flags & SN_FINST_MASK)) {
				if (t->pend_pos)
					t->flags |= SN_FINST_Q;
				else if (s == SV_STCONN)
					t->flags |= SN_FINST_C;
				else
					t->flags |= SN_FINST_D;
			}
			return 1;
		}
		/* last read, or end of server write */
		else if (req->flags & BF_READ_NULL || s == SV_STSHUTW || s == SV_STCLOSE) {
			EV_FD_CLR(t->cli_fd, DIR_RD);
			buffer_shutr(req);
			t->cli_state = CL_STSHUTR;
			return 1;
		}	
		/* last server read and buffer empty */
		else if ((s == SV_STSHUTR || s == SV_STCLOSE) && (rep->flags & BF_EMPTY)) {
			EV_FD_CLR(t->cli_fd, DIR_WR);
			buffer_shutw(rep);
			shutdown(t->cli_fd, SHUT_WR);
			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			EV_FD_SET(t->cli_fd, DIR_RD);
			req->rex = tick_add_ifset(now_ms, req->rto);
			t->cli_state = CL_STSHUTW;
			//fprintf(stderr,"%p:%s(%d), c=%d, s=%d\n", t, __FUNCTION__, __LINE__, t->cli_state, t->cli_state);
			return 1;
		}
		/* read timeout */
		else if (tick_is_expired(req->rex, now_ms)) {
			EV_FD_CLR(t->cli_fd, DIR_RD);
			buffer_shutr(req);
			t->cli_state = CL_STSHUTR;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_CLITO;
			if (!(t->flags & SN_FINST_MASK)) {
				if (t->pend_pos)
					t->flags |= SN_FINST_Q;
				else if (s == SV_STCONN)
					t->flags |= SN_FINST_C;
				else
					t->flags |= SN_FINST_D;
			}
			return 1;
		}	
		/* write timeout */
		else if (tick_is_expired(rep->wex, now_ms)) {
			EV_FD_CLR(t->cli_fd, DIR_WR);
			buffer_shutw(rep);
			shutdown(t->cli_fd, SHUT_WR);
			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			EV_FD_SET(t->cli_fd, DIR_RD);
			req->rex = tick_add_ifset(now_ms, req->rto);

			t->cli_state = CL_STSHUTW;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_CLITO;
			if (!(t->flags & SN_FINST_MASK)) {
				if (t->pend_pos)
					t->flags |= SN_FINST_Q;
				else if (s == SV_STCONN)
					t->flags |= SN_FINST_C;
				else
					t->flags |= SN_FINST_D;
			}
			return 1;
		}

		if (req->flags & BF_FULL) {
			/* no room to read more data */
			if (EV_FD_COND_C(t->cli_fd, DIR_RD)) {
				/* stop reading until we get some space */
				req->rex = TICK_ETERNITY;
			}
		} else {
			/* there's still some space in the buffer */
			if (EV_FD_COND_S(t->cli_fd, DIR_RD)) {
				if (!req->rto ||
				    (t->srv_state < SV_STDATA && req->wto))
					/* If the client has no timeout, or if the server not ready yet, and we
					 * know for sure that it can expire, then it's cleaner to disable the
					 * timeout on the client side so that too low values cannot make the
					 * sessions abort too early.
					 */
					req->rex = TICK_ETERNITY;
				else
					req->rex = tick_add(now_ms, req->rto);
			}
		}

		if ((rep->flags & BF_EMPTY) ||
		    ((s < SV_STDATA) /* FIXME: this may be optimized && (rep->w == rep->h)*/)) {
			if (EV_FD_COND_C(t->cli_fd, DIR_WR)) {
				/* stop writing */
				rep->wex = TICK_ETERNITY;
			}
		} else {
			/* buffer not empty */
			if (EV_FD_COND_S(t->cli_fd, DIR_WR)) {
				/* restart writing */
				rep->wex = tick_add_ifset(now_ms, rep->wto);
				if (rep->wex) {
					/* FIXME: to prevent the client from expiring read timeouts during writes,
					 * we refresh it. */
					req->rex = rep->wex;
				}
			}
		}
		return 0; /* other cases change nothing */
	}
	else if (c == CL_STSHUTR) {
		if (rep->flags & BF_WRITE_ERROR) {
			buffer_shutw(rep);
			fd_delete(t->cli_fd);
			t->cli_state = CL_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_CLICL;
			if (!(t->flags & SN_FINST_MASK)) {
				if (t->pend_pos)
					t->flags |= SN_FINST_Q;
				else if (s == SV_STCONN)
					t->flags |= SN_FINST_C;
				else
					t->flags |= SN_FINST_D;
			}
			return 1;
		}
		else if ((s == SV_STSHUTR || s == SV_STCLOSE) && (rep->flags & BF_EMPTY)) {
			buffer_shutw(rep);
			fd_delete(t->cli_fd);
			t->cli_state = CL_STCLOSE;
			return 1;
		}
		else if (tick_is_expired(rep->wex, now_ms)) {
			buffer_shutw(rep);
			fd_delete(t->cli_fd);
			t->cli_state = CL_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_CLITO;
			if (!(t->flags & SN_FINST_MASK)) {
				if (t->pend_pos)
					t->flags |= SN_FINST_Q;
				else if (s == SV_STCONN)
					t->flags |= SN_FINST_C;
				else
					t->flags |= SN_FINST_D;
			}
			return 1;
		}

		if (rep->flags & BF_EMPTY) {
			if (EV_FD_COND_C(t->cli_fd, DIR_WR)) {
				/* stop writing */
				rep->wex = TICK_ETERNITY;
			}
		} else {
			/* buffer not empty */
			if (EV_FD_COND_S(t->cli_fd, DIR_WR)) {
				/* restart writing */
				rep->wex = tick_add_ifset(now_ms, rep->wto);
			}
		}
		return 0;
	}
	else if (c == CL_STSHUTW) {
		if (req->flags & BF_READ_ERROR) {
			buffer_shutr(req);
			fd_delete(t->cli_fd);
			t->cli_state = CL_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_CLICL;
			if (!(t->flags & SN_FINST_MASK)) {
				if (t->pend_pos)
					t->flags |= SN_FINST_Q;
				else if (s == SV_STCONN)
					t->flags |= SN_FINST_C;
				else
					t->flags |= SN_FINST_D;
			}
			return 1;
		}
		else if (req->flags & BF_READ_NULL || s == SV_STSHUTW || s == SV_STCLOSE) {
			buffer_shutr(req);
			fd_delete(t->cli_fd);
			t->cli_state = CL_STCLOSE;
			return 1;
		}
		else if (tick_is_expired(req->rex, now_ms)) {
			buffer_shutr(req);
			fd_delete(t->cli_fd);
			t->cli_state = CL_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_CLITO;
			if (!(t->flags & SN_FINST_MASK)) {
				if (t->pend_pos)
					t->flags |= SN_FINST_Q;
				else if (s == SV_STCONN)
					t->flags |= SN_FINST_C;
				else
					t->flags |= SN_FINST_D;
			}
			return 1;
		}
		else if (req->flags & BF_FULL) {
			/* no room to read more data */

			/* FIXME-20050705: is it possible for a client to maintain a session
			 * after the timeout by sending more data after it receives a close ?
			 */

			if (EV_FD_COND_C(t->cli_fd, DIR_RD)) {
				/* stop reading until we get some space */
				req->rex = TICK_ETERNITY;
			}
		} else {
			/* there's still some space in the buffer */
			if (EV_FD_COND_S(t->cli_fd, DIR_RD)) {
				req->rex = tick_add_ifset(now_ms, req->rto);
			}
		}
		return 0;
	}
	else { /* CL_STCLOSE: nothing to do */
		if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
			int len;
			len = sprintf(trash, "%08x:%s.clicls[%04x:%04x]\n", t->uniq_id, t->be?t->be->id:"",
				      (unsigned short)t->cli_fd, (unsigned short)t->req->cons->fd);
			write(1, trash, len);
		}
		return 0;
	}
	return 0;
}

#if 0
	/* FIXME! This part has not been completely converted yet, and it may
	 * still be very specific to TCPv4 ! Also, it relies on some parameters
	 * such as conn_retries which are not set upon accept().
	 */
/*
 * Manages the server FSM and its socket. It returns 1 if a state has changed
 * (and a resync may be needed), otherwise 0.
 */
static int process_uxst_srv(struct session *t)
{
	int s = t->srv_state;
	int c = t->cli_state;
	struct buffer *req = t->req;
	struct buffer *rep = t->rep;
	int conn_err;

	if (s == SV_STIDLE) {
		if (c == CL_STCLOSE || c == CL_STSHUTW ||
			 (c == CL_STSHUTR &&
			  (t->req->flags & BF_EMPTY || t->be->options & PR_O_ABRT_CLOSE))) { /* give up */
			tv_eternity(&req->cex);
			if (t->pend_pos)
				t->logs.t_queue = tv_ms_elapsed(&t->logs.tv_accept, &now);
			srv_close_with_err(t, SN_ERR_CLICL, t->pend_pos ? SN_FINST_Q : SN_FINST_C);
			return 1;
		}
		else {
			/* FIXME: reimplement the TARPIT check here */

			/* Right now, we will need to create a connection to the server.
			 * We might already have tried, and got a connection pending, in
			 * which case we will not do anything till it's pending. It's up
			 * to any other session to release it and wake us up again.
			 */
			if (t->pend_pos) {
				if (!tv_isle(&req->cex, &now))
					return 0;
				else {
					/* we've been waiting too long here */
					tv_eternity(&req->cex);
					t->logs.t_queue = tv_ms_elapsed(&t->logs.tv_accept, &now);
					srv_close_with_err(t, SN_ERR_SRVTO, SN_FINST_Q);
					if (t->srv)
						t->srv->failed_conns++;
					if (t->fe)
						t->fe->failed_conns++;
					return 1;
				}
			}

			do {
				/* first, get a connection */
				if (srv_redispatch_connect(t))
					return t->srv_state != SV_STIDLE;

				/* try to (re-)connect to the server, and fail if we expire the
				 * number of retries.
				 */
				if (srv_retryable_connect(t)) {
					t->logs.t_queue = tv_ms_elapsed(&t->logs.tv_accept, &now);
					return t->srv_state != SV_STIDLE;
				}
			} while (1);
		}
	}
	else if (s == SV_STCONN) { /* connection in progress */
		if (c == CL_STCLOSE || c == CL_STSHUTW ||
		    (c == CL_STSHUTR &&
		     ((t->req->flags & BF_EMPTY && !(req->flags & BF_WRITE_ACTIVITY)) ||
		      t->be->options & PR_O_ABRT_CLOSE))) { /* give up */
			tv_eternity(&req->cex);
			fd_delete(t->srv_fd);
			if (t->srv)
				t->srv->cur_sess--;

			srv_close_with_err(t, SN_ERR_CLICL, SN_FINST_C);
			return 1;
		}
		if (!(req->flags & BF_WRITE_ACTIVITY) && !tv_isle(&req->cex, &now)) {
			//fprintf(stderr,"1: c=%d, s=%d, now=%d.%06d, exp=%d.%06d\n", c, s, now.tv_sec, now.tv_usec, req->cex.tv_sec, req->cex.tv_usec);
			return 0; /* nothing changed */
		}
		else if (!(req->flags & BF_WRITE_ACTIVITY) || (req->flags & BF_WRITE_ERROR)) {
			/* timeout, asynchronous connect error or first write error */
			//fprintf(stderr,"2: c=%d, s=%d\n", c, s);

			fd_delete(t->srv_fd);
			if (t->srv)
				t->srv->cur_sess--;

			if (!(req->flags & BF_WRITE_ACTIVITY))
				conn_err = SN_ERR_SRVTO; // it was a connect timeout.
			else
				conn_err = SN_ERR_SRVCL; // it was an asynchronous connect error.

			/* ensure that we have enough retries left */
			if (srv_count_retry_down(t, conn_err))
				return 1;

			if (t->srv && t->conn_retries == 0 && t->be->options & PR_O_REDISP) {
				/* We're on our last chance, and the REDISP option was specified.
				 * We will ignore cookie and force to balance or use the dispatcher.
				 */
				/* let's try to offer this slot to anybody */
				if (may_dequeue_tasks(t->srv, t->be))
					process_srv_queue(t->srv);

				if (t->srv)
					t->srv->failed_conns++;
				t->be->failed_conns++;

				t->flags &= ~(SN_DIRECT | SN_ASSIGNED | SN_ADDR_SET);
				t->srv = NULL; /* it's left to the dispatcher to choose a server */

				/* first, get a connection */
				if (srv_redispatch_connect(t))
					return t->srv_state != SV_STIDLE;
			}

			do {
				/* Now we will try to either reconnect to the same server or
				 * connect to another server. If the connection gets queued
				 * because all servers are saturated, then we will go back to
				 * the SV_STIDLE state.
				 */
				if (srv_retryable_connect(t)) {
					t->logs.t_queue = tv_ms_elapsed(&t->logs.tv_accept, &now);
					return t->srv_state != SV_STCONN;
				}

				/* we need to redispatch the connection to another server */
				if (srv_redispatch_connect(t))
					return t->srv_state != SV_STCONN;
			} while (1);
		}
		else { /* no error or write 0 */
			t->logs.t_connect = tv_ms_elapsed(&t->logs.tv_accept, &now);

			//fprintf(stderr,"3: c=%d, s=%d\n", c, s);
			if (req->flags & BF_EMPTY) /* nothing to write */ {
				EV_FD_CLR(t->srv_fd, DIR_WR);
				tv_eternity(&req->wex);
			} else  /* need the right to write */ {
				EV_FD_SET(t->srv_fd, DIR_WR);
				if (tv_add_ifset(&req->wex, &now, &req->wto)) {
					/* FIXME: to prevent the server from expiring read timeouts during writes,
					 * we refresh it. */
					rep->rex = req->wex;
				}
				else
					tv_eternity(&req->wex);
			}

			EV_FD_SET(t->srv_fd, DIR_RD);
			if (!tv_add_ifset(&rep->rex, &now, &rep->rto))
				tv_eternity(&rep->rex);
		
			t->srv_state = SV_STDATA;
			if (t->srv)
				t->srv->cum_sess++;
			buffer_set_rlim(rep, BUFSIZE); /* no rewrite needed */

			/* if the user wants to log as soon as possible, without counting
			   bytes from the server, then this is the right moment. */
			if (t->fe && t->fe->to_log && !(t->logs.logwait & LW_BYTES)) {
				t->logs.t_close = t->logs.t_connect; /* to get a valid end date */
				//uxst_sess_log(t);
			}
			tv_eternity(&req->cex);
			return 1;
		}
	}
	else if (s == SV_STDATA) {
		/* read or write error */
		if (req->flags & BF_WRITE_ERROR || rep->flags & BF_READ_ERROR) {
			buffer_shutr(rep);
			buffer_shutw(req);
			fd_delete(t->srv_fd);
			if (t->srv) {
				t->srv->cur_sess--;
				t->srv->failed_resp++;
			}
			t->be->failed_resp++;
			t->srv_state = SV_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVCL;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_D;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be))
				process_srv_queue(t->srv);

			return 1;
		}
		/* last read, or end of client write */
		else if (rep->flags & BF_READ_NULL || c == CL_STSHUTW || c == CL_STCLOSE) {
			EV_FD_CLR(t->srv_fd, DIR_RD);
			buffer_shutr(rep);
			t->srv_state = SV_STSHUTR;
			//fprintf(stderr,"%p:%s(%d), c=%d, s=%d\n", t, __FUNCTION__, __LINE__, t->cli_state, t->cli_state);
			return 1;
		}
		/* end of client read and no more data to send */
		else if ((c == CL_STSHUTR || c == CL_STCLOSE) && (req->flags & BF_EMPTY)) {
			EV_FD_CLR(t->srv_fd, DIR_WR);
			buffer_shutw(req);
			shutdown(t->srv_fd, SHUT_WR);
			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			EV_FD_SET(t->srv_fd, DIR_RD);
			tv_add_ifset(&rep->rex, &now, &rep->rto);

			t->srv_state = SV_STSHUTW;
			return 1;
		}
		/* read timeout */
		else if (tv_isle(&rep->rex, &now)) {
			EV_FD_CLR(t->srv_fd, DIR_RD);
			buffer_shutr(rep);
			t->srv_state = SV_STSHUTR;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVTO;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_D;
			return 1;
		}	
		/* write timeout */
		else if (tv_isle(&req->wex, &now)) {
			EV_FD_CLR(t->srv_fd, DIR_WR);
			buffer_shutw(req);
			shutdown(t->srv_fd, SHUT_WR);
			/* We must ensure that the read part is still alive when switching
			 * to shutw */
			EV_FD_SET(t->srv_fd, DIR_RD);
			tv_add_ifset(&rep->rex, &now, &rep->rto);
			t->srv_state = SV_STSHUTW;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVTO;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_D;
			return 1;
		}

		/* recompute request time-outs */
		if (req->flags & BF_EMPTY) {
			if (EV_FD_COND_C(t->srv_fd, DIR_WR)) {
				/* stop writing */
				tv_eternity(&req->wex);
			}
		}
		else { /* buffer not empty, there are still data to be transferred */
			if (EV_FD_COND_S(t->srv_fd, DIR_WR)) {
				/* restart writing */
				if (tv_add_ifset(&req->wex, &now, &req->wto)) {
					/* FIXME: to prevent the server from expiring read timeouts during writes,
					 * we refresh it. */
					rep->rex = req->wex;
				}
				else
					tv_eternity(&req->wex);
			}
		}

		/* recompute response time-outs */
		if (rep->l == BUFSIZE) { /* no room to read more data */
			if (EV_FD_COND_C(t->srv_fd, DIR_RD)) {
				tv_eternity(&rep->rex);
			}
		}
		else {
			if (EV_FD_COND_S(t->srv_fd, DIR_RD)) {
				if (!tv_add_ifset(&rep->rex, &now, &rep->rto))
					tv_eternity(&rep->rex);
			}
		}

		return 0; /* other cases change nothing */
	}
	else if (s == SV_STSHUTR) {
		if (req->flags & BF_WRITE_ERROR) {
			//EV_FD_CLR(t->srv_fd, DIR_WR);
			buffer_shutw(req);
			fd_delete(t->srv_fd);
			if (t->srv) {
				t->srv->cur_sess--;
				t->srv->failed_resp++;
			}
			t->be->failed_resp++;
			//close(t->srv_fd);
			t->srv_state = SV_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVCL;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_D;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be))
				process_srv_queue(t->srv);

			return 1;
		}
		else if ((c == CL_STSHUTR || c == CL_STCLOSE) && (req->flags & BF_EMPTY)) {
			//EV_FD_CLR(t->srv_fd, DIR_WR);
			buffer_shutw(req);
			fd_delete(t->srv_fd);
			if (t->srv)
				t->srv->cur_sess--;
			//close(t->srv_fd);
			t->srv_state = SV_STCLOSE;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be))
				process_srv_queue(t->srv);

			return 1;
		}
		else if (tv_isle(&req->wex, &now)) {
			//EV_FD_CLR(t->srv_fd, DIR_WR);
			buffer_shutw(req);
			fd_delete(t->srv_fd);
			if (t->srv)
				t->srv->cur_sess--;
			//close(t->srv_fd);
			t->srv_state = SV_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVTO;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_D;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be))
				process_srv_queue(t->srv);

			return 1;
		}
		else if (req->flags & BF_EMPTY) {
			if (EV_FD_COND_C(t->srv_fd, DIR_WR)) {
				/* stop writing */
				tv_eternity(&req->wex);
			}
		}
		else { /* buffer not empty */
			if (EV_FD_COND_S(t->srv_fd, DIR_WR)) {
				/* restart writing */
				if (!tv_add_ifset(&req->wex, &now, &req->wto))
					tv_eternity(&req->wex);
			}
		}
		return 0;
	}
	else if (s == SV_STSHUTW) {
		if (rep->flags & BF_READ_ERROR) {
			//EV_FD_CLR(t->srv_fd, DIR_RD);
			buffer_shutr(rep);
			fd_delete(t->srv_fd);
			if (t->srv) {
				t->srv->cur_sess--;
				t->srv->failed_resp++;
			}
			t->be->failed_resp++;
			//close(t->srv_fd);
			t->srv_state = SV_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVCL;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_D;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be))
				process_srv_queue(t->srv);

			return 1;
		}
		else if (rep->flags & BF_READ_NULL || c == CL_STSHUTW || c == CL_STCLOSE) {
			//EV_FD_CLR(t->srv_fd, DIR_RD);
			buffer_shutr(rep);
			fd_delete(t->srv_fd);
			if (t->srv)
				t->srv->cur_sess--;
			//close(t->srv_fd);
			t->srv_state = SV_STCLOSE;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be))
				process_srv_queue(t->srv);

			return 1;
		}
		else if (tv_isle(&rep->rex, &now)) {
			//EV_FD_CLR(t->srv_fd, DIR_RD);
			buffer_shutr(rep);
			fd_delete(t->srv_fd);
			if (t->srv)
				t->srv->cur_sess--;
			//close(t->srv_fd);
			t->srv_state = SV_STCLOSE;
			if (!(t->flags & SN_ERR_MASK))
				t->flags |= SN_ERR_SRVTO;
			if (!(t->flags & SN_FINST_MASK))
				t->flags |= SN_FINST_D;
			/* We used to have a free connection slot. Since we'll never use it,
			 * we have to inform the server that it may be used by another session.
			 */
			if (may_dequeue_tasks(t->srv, t->be))
				process_srv_queue(t->srv);

			return 1;
		}
		else if (rep->l == BUFSIZE) { /* no room to read more data */
			if (EV_FD_COND_C(t->srv_fd, DIR_RD)) {
				tv_eternity(&rep->rex);
			}
		}
		else {
			if (EV_FD_COND_S(t->srv_fd, DIR_RD)) {
				if (!tv_add_ifset(&rep->rex, &now, &rep->rto))
					tv_eternity(&rep->rex);
			}
		}
		return 0;
	}
	else { /* SV_STCLOSE : nothing to do */
		if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
			int len;
			len = sprintf(trash, "%08x:%s.srvcls[%04x:%04x]\n",
				      t->uniq_id, t->be->id, (unsigned short)t->cli_fd, (unsigned short)t->srv_fd);
			write(1, trash, len);
		}
		return 0;
	}
	return 0;
}

/* Processes the client and server jobs of a session task, then
 * puts it back to the wait queue in a clean state, or
 * cleans up its resources if it must be deleted. Returns
 * the time the task accepts to wait, or TIME_ETERNITY for
 * infinity.
 */
void process_uxst_session(struct task *t, int *next)
{
	struct session *s = t->context;
	int fsm_resync = 0;

	do {
		fsm_resync = 0;
		fsm_resync |= process_uxst_cli(s);
		if (s->srv_state == SV_STIDLE) {
			if (s->cli_state == CL_STCLOSE || s->cli_state == CL_STSHUTW) {
				s->srv_state = SV_STCLOSE;
				fsm_resync |= 1;
				continue;
			}
			if (s->cli_state == CL_STSHUTR ||
			    (s->req->flags & BF_FULL)) {
				if (s->req->flags & BF_EMPTY) {
					s->srv_state = SV_STCLOSE;
					fsm_resync |= 1;
					continue;
				}
				/* OK we have some remaining data to process */
				/* Just as an exercice, we copy the req into the resp,
				 * and flush the req.
				 */
				memcpy(s->rep->data, s->req->data, sizeof(s->rep->data));
				s->rep->l = s->req->l;
				buffer_set_rlim(s->rep, BUFSIZE);
				s->rep->w = s->rep->data;
				s->rep->lr = s->rep->r = s->rep->data + s->rep->l;

				s->req->l = 0;
				s->srv_state = SV_STCLOSE;

				fsm_resync |= 1;
				continue;
			}
		}
	} while (fsm_resync);

	if (likely(s->cli_state != CL_STCLOSE || s->srv_state != SV_STCLOSE)) {

		if ((s->fe->options & PR_O_CONTSTATS) && (s->flags & SN_BE_ASSIGNED))
			session_process_counters(s);

		s->req->flags &= BF_CLEAR_READ & BF_CLEAR_WRITE;
		s->rep->flags &= BF_CLEAR_READ & BF_CLEAR_WRITE;

		t->expire = s->req->rex;
		tv_min(&t->expire, &s->req->rex, &s->req->wex);
		tv_bound(&t->expire, &s->req->cex);
		tv_bound(&t->expire, &s->rep->rex);
		tv_bound(&t->expire, &s->rep->wex);

		/* restore t to its place in the task list */
		task_queue(t);

		*next = t->expire;
		return; /* nothing more to do */
	}

	if (s->fe)
		s->fe->feconn--;
	if (s->be && (s->flags & SN_BE_ASSIGNED))
		s->be->beconn--;
	actconn--;
    
	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)))) {
		int len;
		len = sprintf(trash, "%08x:%s.closed[%04x:%04x]\n",
			      s->uniq_id, s->be->id,
			      (unsigned short)s->cli_fd, (unsigned short)s->srv_fd);
		write(1, trash, len);
	}

	s->logs.t_close = tv_ms_elapsed(&s->logs.tv_accept, &now);
	session_process_counters(s);

	/* let's do a final log if we need it */
	if (s->logs.logwait && 
	    !(s->flags & SN_MONITOR) &&
	    (s->req->total || !(s->fe && s->fe->options & PR_O_NULLNOLOG))) {
		//uxst_sess_log(s);
	}

	/* the task MUST not be in the run queue anymore */
	task_delete(t);
	session_free(s);
	task_free(t);
	tv_eternity(next);
}
#endif /* not converted */


/* Processes data exchanges on the statistics socket. The client processing
 * is called and the task is put back in the wait queue or it is cleared.
 * In order to ease the transition, we simply simulate the server status
 * for now. It only knows states SV_STIDLE, SV_STCONN, SV_STDATA, and
 * SV_STCLOSE. Returns in <next> the task's expiration date.
 */
void process_uxst_stats(struct task *t, int *next)
{
	struct session *s = t->context;
	struct listener *listener;
	int fsm_resync = 0;
	int last_rep_l;

	do {
		char *args[MAX_UXST_ARGS + 1];
		char *line, *p;
		int arg;

		fsm_resync = process_uxst_cli(s);

		if (s->cli_state == CL_STCLOSE || s->cli_state == CL_STSHUTW) {
			s->srv_state = SV_STCLOSE;
			break;
		}

		switch (s->srv_state) {
		case SV_STIDLE:
			/* stats output not initialized yet */
			memset(&s->data_ctx.stats, 0, sizeof(s->data_ctx.stats));
			s->data_source = DATA_SRC_STATS;
			s->srv_state = SV_STCONN;
			fsm_resync |= 1;
			break;

		case SV_STCONN: /* should be changed to SV_STHEADERS or something more obvious */
			/* stats initialized, but waiting for the command */
			line = s->req->data;
			p = memchr(line, '\n', s->req->l);

			if (!p)
				continue;

			*p = '\0';

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

			if (!strcmp(args[0], "show")) {
				if (!strcmp(args[1], "stat")) {
					if (*args[2] && *args[3] && *args[4]) {
						s->data_ctx.stats.flags |= STAT_BOUND;
						s->data_ctx.stats.iid	= atoi(args[2]);
						s->data_ctx.stats.type	= atoi(args[3]);
						s->data_ctx.stats.sid	= atoi(args[4]);
					}

					s->data_ctx.stats.flags |= STAT_SHOW_STAT;
					s->data_ctx.stats.flags |= STAT_FMT_CSV;
					s->srv_state = SV_STDATA;
					fsm_resync |= 1;
					continue;
				}

				if (!strcmp(args[1], "info")) {
					s->data_ctx.stats.flags |= STAT_SHOW_INFO;
					s->data_ctx.stats.flags |= STAT_FMT_CSV;
					s->srv_state = SV_STDATA;
					fsm_resync |= 1;
					continue;
				}
			}

			s->srv_state = SV_STCLOSE;
			fsm_resync |= 1;
			continue;

		case SV_STDATA:
			/* OK we have to process the request. Since it is possible
			 * that we get there with the client output paused, we
			 * will simply check that we have really sent some data
			 * and wake the client up if needed.
			 */
			last_rep_l = s->rep->l;
			if (stats_dump_raw(s, NULL) != 0) {
				s->srv_state = SV_STCLOSE;
				fsm_resync |= 1;
			}
			if (s->rep->l != last_rep_l)
				fsm_resync |= 1;
			break;
		}
	} while (fsm_resync);

	if (likely(s->cli_state != CL_STCLOSE || s->srv_state != SV_STCLOSE)) {
		s->req->flags &= BF_CLEAR_READ & BF_CLEAR_WRITE;
		s->rep->flags &= BF_CLEAR_READ & BF_CLEAR_WRITE;

		t->expire = tick_first(tick_first(s->req->rex, s->req->wex),
				       tick_first(s->rep->rex, s->rep->wex));

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
