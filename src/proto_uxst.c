/*
 * UNIX SOCK_STREAM protocol layer (uxst)
 *
 * Copyright 2000-2010 Willy Tarreau <w@1wt.eu>
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

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/errors.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/time.h>
#include <common/version.h>

#include <types/global.h>

#include <proto/fd.h>
#include <proto/log.h>
#include <proto/protocols.h>
#include <proto/proto_uxst.h>
#include <proto/stream_sock.h>
#include <proto/task.h>

static int uxst_bind_listener(struct listener *listener, char *errmsg, int errlen);
static int uxst_bind_listeners(struct protocol *proto, char *errmsg, int errlen);
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
	.accept = &stream_sock_accept,
	.read = &stream_sock_read,
	.write = &stream_sock_write,
	.bind = uxst_bind_listener,
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
static int create_uxst_socket(const char *path, uid_t uid, gid_t gid, mode_t mode, char *errmsg, int errlen)
{
	char tempname[MAXPATHLEN];
	char backname[MAXPATHLEN];
	struct sockaddr_un addr;

	int ret, sock;

	/* 1. create socket names */
	if (!path[0]) {
		if (errmsg && errlen)
			snprintf(errmsg, errlen, "Invalid empty name for a UNIX socket");
		goto err_return;
	}

	ret = snprintf(tempname, MAXPATHLEN, "%s.%d.tmp", path, pid);
	if (ret < 0 || ret >= MAXPATHLEN) {
		if (errmsg && errlen)
			snprintf(errmsg, errlen, "name too long for UNIX socket (%s)", path);
		goto err_return;
	}

	ret = snprintf(backname, MAXPATHLEN, "%s.%d.bak", path, pid);
	if (ret < 0 || ret >= MAXPATHLEN) {
		if (errmsg && errlen)
			snprintf(errmsg, errlen, "name too long for UNIX socket (%s)", path);
		goto err_return;
	}

	/* 2. clean existing orphaned entries */
	if (unlink(tempname) < 0 && errno != ENOENT) {
		if (errmsg && errlen)
			snprintf(errmsg, errlen, "error when trying to unlink previous UNIX socket (%s)", path);
		goto err_return;
	}

	if (unlink(backname) < 0 && errno != ENOENT) {
		if (errmsg && errlen)
			snprintf(errmsg, errlen, "error when trying to unlink previous UNIX socket (%s)", path);
		goto err_return;
	}

	/* 3. backup existing socket */
	if (link(path, backname) < 0 && errno != ENOENT) {
		if (errmsg && errlen)
			snprintf(errmsg, errlen, "error when trying to preserve previous UNIX socket (%s)", path);
		goto err_return;
	}

	/* 4. prepare new socket */
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, tempname, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		if (errmsg && errlen)
			snprintf(errmsg, errlen, "cannot create socket for UNIX listener (%s)", path);
		goto err_unlink_back;
	}

	if (sock >= global.maxsock) {
		if (errmsg && errlen)
			snprintf(errmsg, errlen, "socket(): not enough free sockets for UNIX listener (%s). Raise -n argument", path);
		goto err_unlink_temp;
	}

	if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
		if (errmsg && errlen)
			snprintf(errmsg, errlen, "cannot make UNIX socket non-blocking");
		goto err_unlink_temp;
	}

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		/* note that bind() creates the socket <tempname> on the file system */
		if (errmsg && errlen)
			snprintf(errmsg, errlen, "cannot bind socket for UNIX listener (%s)", path);
		goto err_unlink_temp;
	}

	if (((uid != -1 || gid != -1) && (chown(tempname, uid, gid) == -1)) ||
	    (mode != 0 && chmod(tempname, mode) == -1)) {
		if (errmsg && errlen)
			snprintf(errmsg, errlen, "cannot change UNIX socket ownership (%s)", path);
		goto err_unlink_temp;
	}

	if (listen(sock, 0) < 0) {
		if (errmsg && errlen)
			snprintf(errmsg, errlen, "cannot listen to socket for UNIX listener (%s)", path);
		goto err_unlink_temp;
	}

	/* 5. install.
	 * Point of no return: we are ready, we'll switch the sockets. We don't
	 * fear loosing the socket <path> because we have a copy of it in
	 * backname.
	 */
	if (rename(tempname, path) < 0) {
		if (errmsg && errlen)
			snprintf(errmsg, errlen, "cannot switch final and temporary sockets for UNIX listener (%s)", path);
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
static int uxst_bind_listener(struct listener *listener, char *errmsg, int errlen)
{
	int fd;

        /* ensure we never return garbage */
        if (errmsg && errlen)
                *errmsg = 0;

	if (listener->state != LI_ASSIGNED)
		return ERR_NONE; /* already bound */

	fd = create_uxst_socket(((struct sockaddr_un *)&listener->addr)->sun_path,
				listener->perm.ux.uid,
				listener->perm.ux.gid,
				listener->perm.ux.mode, errmsg, errlen);
	if (fd == -1) {
		return ERR_FATAL | ERR_ALERT;
	}
	/* the socket is now listening */
	listener->fd = fd;
	listener->state = LI_LISTEN;

	/* the function for the accept() event */
	fd_insert(fd);
	fdtab[fd].cb[DIR_RD].f = listener->proto->accept;
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
static int uxst_bind_listeners(struct protocol *proto, char *errmsg, int errlen)
{
	struct listener *listener;
	int err = ERR_NONE;

	list_for_each_entry(listener, &proto->listeners, proto_list) {
		err |= uxst_bind_listener(listener, errmsg, errlen);
		if (err & ERR_ABORT)
			break;
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
