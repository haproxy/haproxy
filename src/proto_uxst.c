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
#include <pwd.h>
#include <grp.h>
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
#include <proto/listener.h>
#include <proto/log.h>
#include <proto/protocol.h>
#include <proto/proto_uxst.h>
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
	.accept = &listener_accept,
	.bind = uxst_bind_listener,
	.bind_all = uxst_bind_listeners,
	.unbind_all = uxst_unbind_listeners,
	.enable_all = enable_all_listeners,
	.disable_all = disable_all_listeners,
	.get_src = uxst_get_src,
	.get_dst = uxst_get_dst,
	.listeners = LIST_HEAD_INIT(proto_unix.listeners),
	.nb_listeners = 0,
};

/********************************
 * 1) low-level socket functions
 ********************************/

/*
 * Retrieves the source address for the socket <fd>, with <dir> indicating
 * if we're a listener (=0) or an initiator (!=0). It returns 0 in case of
 * success, -1 in case of error. The socket's source address is stored in
 * <sa> for <salen> bytes.
 */
int uxst_get_src(int fd, struct sockaddr *sa, socklen_t salen, int dir)
{
	if (dir)
		return getsockname(fd, sa, &salen);
	else
		return getpeername(fd, sa, &salen);
}


/*
 * Retrieves the original destination address for the socket <fd>, with <dir>
 * indicating if we're a listener (=0) or an initiator (!=0). It returns 0 in
 * case of success, -1 in case of error. The socket's source address is stored
 * in <sa> for <salen> bytes.
 */
int uxst_get_dst(int fd, struct sockaddr *sa, socklen_t salen, int dir)
{
	if (dir)
		return getpeername(fd, sa, &salen);
	else
		return getsockname(fd, sa, &salen);
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


/* This function creates a UNIX socket associated to the listener. It changes
 * the state from ASSIGNED to LISTEN. The socket is NOT enabled for polling.
 * The return value is composed from ERR_NONE, ERR_RETRYABLE and ERR_FATAL.
 */
static int uxst_bind_listener(struct listener *listener, char *errmsg, int errlen)
{
	int fd;
	char tempname[MAXPATHLEN];
	char backname[MAXPATHLEN];
	struct sockaddr_un addr;
	const char *msg = NULL;
	const char *path;

	int ret;

	/* ensure we never return garbage */
	if (errmsg && errlen)
		*errmsg = 0;

	if (listener->state != LI_ASSIGNED)
		return ERR_NONE; /* already bound */
		
	path = ((struct sockaddr_un *)&listener->addr)->sun_path;

	/* 1. create socket names */
	if (!path[0]) {
		msg = "Invalid empty name for a UNIX socket";
		goto err_return;
	}

	ret = snprintf(tempname, MAXPATHLEN, "%s.%d.tmp", path, pid);
	if (ret < 0 || ret >= MAXPATHLEN) {
		msg = "name too long for UNIX socket";
		goto err_return;
	}

	ret = snprintf(backname, MAXPATHLEN, "%s.%d.bak", path, pid);
	if (ret < 0 || ret >= MAXPATHLEN) {
		msg = "name too long for UNIX socket";
		goto err_return;
	}

	/* 2. clean existing orphaned entries */
	if (unlink(tempname) < 0 && errno != ENOENT) {
		msg = "error when trying to unlink previous UNIX socket";
		goto err_return;
	}

	if (unlink(backname) < 0 && errno != ENOENT) {
		msg = "error when trying to unlink previous UNIX socket";
		goto err_return;
	}

	/* 3. backup existing socket */
	if (link(path, backname) < 0 && errno != ENOENT) {
		msg = "error when trying to preserve previous UNIX socket";
		goto err_return;
	}

	/* 4. prepare new socket */
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, tempname, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		msg = "cannot create UNIX socket";
		goto err_unlink_back;
	}

	if (fd >= global.maxsock) {
		msg = "socket(): not enough free sockets, raise -n argument";
		goto err_unlink_temp;
	}
	
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		msg = "cannot make UNIX socket non-blocking";
		goto err_unlink_temp;
	}
	
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		/* note that bind() creates the socket <tempname> on the file system */
		msg = "cannot bind UNIX socket";
		goto err_unlink_temp;
	}

	/* <uid> and <gid> different of -1 will be used to change the socket owner.
	 * If <mode> is not 0, it will be used to restrict access to the socket.
	 * While it is known not to be portable on every OS, it's still useful
	 * where it works.
	 */
	if (((listener->perm.ux.uid != -1 || listener->perm.ux.gid != -1) &&
	     (chown(tempname, listener->perm.ux.uid, listener->perm.ux.gid) == -1)) ||
	    (listener->perm.ux.mode != 0 && chmod(tempname, listener->perm.ux.mode) == -1)) {
		msg = "cannot change UNIX socket ownership";
		goto err_unlink_temp;
	}

	if (listen(fd, listener->backlog ? listener->backlog : listener->maxconn) < 0) {
		msg = "cannot listen to UNIX socket";
		goto err_unlink_temp;
	}

	/* 5. install.
	 * Point of no return: we are ready, we'll switch the sockets. We don't
	 * fear loosing the socket <path> because we have a copy of it in
	 * backname.
	 */
	if (rename(tempname, path) < 0) {
		msg = "cannot switch final and temporary UNIX sockets";
		goto err_rename;
	}

	/* 6. cleanup */
	unlink(backname); /* no need to keep this one either */

	/* the socket is now listening */
	listener->fd = fd;
	listener->state = LI_LISTEN;

	/* the function for the accept() event */
	fd_insert(fd);
	fdtab[fd].iocb = listener->proto->accept;
	fdtab[fd].owner = listener; /* reference the listener instead of a task */
	return ERR_NONE;
 err_rename:
	ret = rename(backname, path);
	if (ret < 0 && errno == ENOENT)
		unlink(path);
 err_unlink_temp:
	unlink(tempname);
	close(fd);
 err_unlink_back:
	unlink(backname);
 err_return:
	if (msg && errlen)
		snprintf(errmsg, errlen, "%s [%s]", msg, path);
	return ERR_FATAL | ERR_ALERT;
}

/* This function closes the UNIX sockets for the specified listener.
 * The listener enters the LI_ASSIGNED state. It always returns ERR_NONE.
 */
static int uxst_unbind_listener(struct listener *listener)
{
	if (listener->state > LI_ASSIGNED) {
		unbind_listener(listener);
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

/* parse the "mode" bind keyword */
static int bind_parse_mode(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;
	int val;

	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing mode (octal integer expected)", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	val = strtol(args[cur_arg + 1], NULL, 8);

	list_for_each_entry(l, &conf->listeners, by_bind) {
		if (l->addr.ss_family == AF_UNIX)
			l->perm.ux.mode = val;
	}

	return 0;
}

/* parse the "gid" bind keyword */
static int bind_parse_gid(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;
	int val;

	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing value", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	val = atol(args[cur_arg + 1]);
	list_for_each_entry(l, &conf->listeners, by_bind) {
		if (l->addr.ss_family == AF_UNIX)
			l->perm.ux.gid = val;
	}

	return 0;
}

/* parse the "group" bind keyword */
static int bind_parse_group(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;
	struct group *group;

	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing group name", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	group = getgrnam(args[cur_arg + 1]);
	if (!group) {
		if (err)
			memprintf(err, "'%s' : unknown group name '%s'", args[cur_arg], args[cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}

	list_for_each_entry(l, &conf->listeners, by_bind) {
		if (l->addr.ss_family == AF_UNIX)
			l->perm.ux.gid = group->gr_gid;
	}

	return 0;
}

/* parse the "uid" bind keyword */
static int bind_parse_uid(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;
	int val;

	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing value", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	val = atol(args[cur_arg + 1]);
	list_for_each_entry(l, &conf->listeners, by_bind) {
		if (l->addr.ss_family == AF_UNIX)
			l->perm.ux.uid = val;
	}

	return 0;
}

/* parse the "user" bind keyword */
static int bind_parse_user(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;
	struct passwd *user;

	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing user name", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	user = getpwnam(args[cur_arg + 1]);
	if (!user) {
		if (err)
			memprintf(err, "'%s' : unknown user name '%s'", args[cur_arg], args[cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}

	list_for_each_entry(l, &conf->listeners, by_bind) {
		if (l->addr.ss_family == AF_UNIX)
			l->perm.ux.uid = user->pw_uid;
	}

	return 0;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 */
static struct bind_kw_list bind_kws = { "UNIX", { }, {
	{ "gid",   bind_parse_gid,   1 },      /* set the socket's gid */
	{ "group", bind_parse_group, 1 },      /* set the socket's gid from the group name */
	{ "mode",  bind_parse_mode,  1 },      /* set the socket's mode (eg: 0644)*/
	{ "uid",   bind_parse_uid,   1 },      /* set the socket's uid */
	{ "user",  bind_parse_user,  1 },      /* set the socket's uid from the user name */
	{ NULL, NULL, 0 },
}};

/********************************
 * 4) high-level functions
 ********************************/

__attribute__((constructor))
static void __uxst_protocol_init(void)
{
	protocol_register(&proto_unix);
	bind_register_keywords(&bind_kws);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
