/*
 * SOCK_UNIX socket management
 *
 * Copyright 2000-2020 Willy Tarreau <w@1wt.eu>
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
#include <string.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <haproxy/api.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/listener.h>
#include <haproxy/receiver-t.h>
#include <haproxy/namespace.h>
#include <haproxy/sock.h>
#include <haproxy/sock_unix.h>
#include <haproxy/tools.h>


struct proto_fam proto_fam_unix = {
	.name = "unix",
	.sock_domain = PF_UNIX,
	.sock_family = AF_UNIX,
	.sock_addrlen = sizeof(struct sockaddr_un),
	.l3_addrlen = sizeof(((struct sockaddr_un*)0)->sun_path),
	.addrcmp = sock_unix_addrcmp,
	.bind = sock_unix_bind_receiver,
	.get_src = sock_get_src,
	.get_dst = sock_get_dst,
};

/* PLEASE NOTE for functions below:
 *
 * The address family SHOULD always be checked. In some cases a function will
 * be used in a situation where the address family is guaranteed (e.g. protocol
 * definitions), so the test may be avoided. This special case must then be
 * mentioned in the comment before the function definition.
 */


/* Compares two AF_UNIX sockaddr addresses. Returns 0 if they match or non-zero
 * if they do not match. It also supports ABNS socket addresses (those starting
 * with \0). For regular UNIX sockets however, this does explicitly support
 * matching names ending exactly with .XXXXX.tmp which are newly bound sockets
 * about to be replaced; this suffix is then ignored. Note that our UNIX socket
 * paths are always zero-terminated.
 */
int sock_unix_addrcmp(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
	const struct sockaddr_un *au = (const struct sockaddr_un *)a;
	const struct sockaddr_un *bu = (const struct sockaddr_un *)b;
	int idx, dot, idx2;

	if (a->ss_family != b->ss_family)
		return -1;

	if (a->ss_family != AF_UNIX)
		return -1;

	if (au->sun_path[0] != bu->sun_path[0])
		return -1;

	if (au->sun_path[0] == 0)
		return memcmp(au->sun_path, bu->sun_path, sizeof(au->sun_path));

	idx = 1; dot = 0;
	while (au->sun_path[idx] == bu->sun_path[idx]) {
		if (au->sun_path[idx] == 0)
			return 0;
		if (au->sun_path[idx] == '.')
			dot = idx;
		idx++;
	}

	/* Now we have a difference. It's OK if they are within or after a
	 * sequence of digits following a dot, and are followed by ".tmp".
	 */
	if (!dot)
		return -1;

	/* First, check in path "a" */
	if (au->sun_path[idx] != 0) {
		for (idx2 = dot + 1; idx2 && isdigit((unsigned char)au->sun_path[idx2]);)
			idx2++;
		if (strcmp(au->sun_path + idx2, ".tmp") != 0)
			return -1;
	}

	/* Then check in path "b" */
	if (bu->sun_path[idx] != 0) {
		for (idx2 = dot + 1; idx2 && isdigit((unsigned char)bu->sun_path[idx2]); idx2++)
			;
		if (strcmp(bu->sun_path + idx2, ".tmp") != 0)
			return -1;
	}

	/* OK that's a match */
	return 0;
}

/* Binds receiver <rx>, and assigns rx->iocb and rx->owner as the callback and
 * context, respectively, with ->bind_thread as the thread mask. Returns an
 * error code made of ERR_* bits on failure or ERR_NONE on success. On failure,
 * an error message may be passed into <errmsg>.
 */
int sock_unix_bind_receiver(struct receiver *rx, char **errmsg)
{
	char tempname[MAXPATHLEN];
	char backname[MAXPATHLEN];
	struct sockaddr_un addr;
	const char *path;
	int maxpathlen;
	int fd, err, ext, ret;

	/* ensure we never return garbage */
	if (errmsg)
		*errmsg = 0;

	err = ERR_NONE;

	if (rx->flags & RX_F_BOUND)
		return ERR_NONE;

	/* if no FD was assigned yet, we'll have to either find a compatible
	 * one or create a new one.
	 */
	if (rx->fd == -1)
		rx->fd = sock_find_compatible_fd(rx);

	path = ((struct sockaddr_un *)&rx->addr)->sun_path;
	maxpathlen = MIN(MAXPATHLEN, sizeof(addr.sun_path));

	/* if the listener already has an fd assigned, then we were offered the
	 * fd by an external process (most likely the parent), and we don't want
	 * to create a new socket. However we still want to set a few flags on
	 * the socket.
	 */
	fd = rx->fd;
	ext = (fd >= 0);
	if (ext)
		goto fd_ready;

	if (path[0]) {
		ret = snprintf(tempname, maxpathlen, "%s.%d.tmp", path, pid);
		if (ret < 0 || ret >= sizeof(addr.sun_path)) {
			err |= ERR_FATAL | ERR_ALERT;
			memprintf(errmsg, "name too long for UNIX socket (limit usually 97)");
			goto bind_return;
		}

		ret = snprintf(backname, maxpathlen, "%s.%d.bak", path, pid);
		if (ret < 0 || ret >= maxpathlen) {
			err |= ERR_FATAL | ERR_ALERT;
			memprintf(errmsg, "name too long for UNIX socket (limit usually 97)");
			goto bind_return;
		}

		/* 2. clean existing orphaned entries */
		if (unlink(tempname) < 0 && errno != ENOENT) {
			err |= ERR_FATAL | ERR_ALERT;
			memprintf(errmsg, "error when trying to unlink previous UNIX socket (%s)", strerror(errno));
			goto bind_return;
		}

		if (unlink(backname) < 0 && errno != ENOENT) {
			err |= ERR_FATAL | ERR_ALERT;
			memprintf(errmsg, "error when trying to unlink previous UNIX socket (%s)", strerror(errno));
			goto bind_return;
		}

		/* 3. backup existing socket */
		if (link(path, backname) < 0 && errno != ENOENT) {
			err |= ERR_FATAL | ERR_ALERT;
			memprintf(errmsg, "error when trying to preserve previous UNIX socket (%s)", strerror(errno));
			goto bind_return;
		}

		/* Note: this test is redundant with the snprintf one above and
		 * will never trigger, it's just added as the only way to shut
		 * gcc's painfully dumb warning about possibly truncated output
		 * during strncpy(). Don't move it above or smart gcc will not
		 * see it!
		 */
		if (strlen(tempname) >= sizeof(addr.sun_path)) {
			err |= ERR_FATAL | ERR_ALERT;
			memprintf(errmsg, "name too long for UNIX socket (limit usually 97)");
			goto bind_return;
		}

		strncpy(addr.sun_path, tempname, sizeof(addr.sun_path) - 1);
		addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
	}
	else {
		/* first char is zero, it's an abstract socket whose address
		 * is defined by all the bytes past this zero.
		 */
		memcpy(addr.sun_path, path, sizeof(addr.sun_path));
	}
	addr.sun_family = AF_UNIX;

	/* WT: shouldn't we use my_socketat(rx->netns) here instead ? */
	fd = socket(rx->proto->fam->sock_domain, rx->proto->sock_type, rx->proto->sock_prot);
	if (fd < 0) {
		err |= ERR_FATAL | ERR_ALERT;
		memprintf(errmsg, "cannot create receiving socket (%s)", strerror(errno));
		goto bind_return;
	}

 fd_ready:
	if (fd >= global.maxsock) {
		err |= ERR_FATAL | ERR_ABORT | ERR_ALERT;
		memprintf(errmsg, "not enough free sockets (raise '-n' parameter)");
		goto bind_close_return;
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		err |= ERR_FATAL | ERR_ALERT;
		memprintf(errmsg, "cannot make socket non-blocking");
		goto bind_close_return;
	}

	if (!ext && bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		/* note that bind() creates the socket <tempname> on the file system */
		if (errno == EADDRINUSE) {
			/* the old process might still own it, let's retry */
			err |= ERR_RETRYABLE | ERR_ALERT;
			memprintf(errmsg, "cannot bind UNIX socket (already in use)");
			goto bind_close_return;
		}
		else {
			err |= ERR_FATAL | ERR_ALERT;
			memprintf(errmsg, "cannot bind UNIX socket (%s)", strerror(errno));
			goto bind_close_return;
		}
	}

	/* <uid> and <gid> different of -1 will be used to change the socket owner.
	 * If <mode> is not 0, it will be used to restrict access to the socket.
	 * While it is known not to be portable on every OS, it's still useful
	 * where it works. We also don't change permissions on abstract sockets.
	 */
	if (!ext && path[0] &&
	    (((rx->settings->ux.uid != -1 || rx->settings->ux.gid != -1) &&
	      (chown(tempname, rx->settings->ux.uid, rx->settings->ux.gid) == -1)) ||
	     (rx->settings->ux.mode != 0 && chmod(tempname, rx->settings->ux.mode) == -1))) {
		err |= ERR_FATAL | ERR_ALERT;
		memprintf(errmsg, "cannot change UNIX socket ownership (%s)", strerror(errno));
		goto err_unlink_temp;
	}

	/* Point of no return: we are ready, we'll switch the sockets. We don't
	 * fear losing the socket <path> because we have a copy of it in
	 * backname. Abstract sockets are not renamed.
	 */
	if (!ext && path[0] && rename(tempname, path) < 0) {
		err |= ERR_FATAL | ERR_ALERT;
		memprintf(errmsg, "cannot switch final and temporary UNIX sockets (%s)", strerror(errno));
		goto err_rename;
	}

	/* Cleanup: only unlink if we didn't inherit the fd from the parent */
	if (!ext && path[0])
		unlink(backname);

	rx->fd = fd;
	rx->flags |= RX_F_BOUND;

	fd_insert(fd, rx->owner, rx->iocb, thread_mask(rx->settings->bind_thread) & all_threads_mask);

	/* for now, all regularly bound TCP listeners are exportable */
	if (!(rx->flags & RX_F_INHERITED))
		HA_ATOMIC_OR(&fdtab[fd].state, FD_EXPORTED);

	return err;

 err_rename:
	ret = rename(backname, path);
	if (ret < 0 && errno == ENOENT)
		unlink(path);
 err_unlink_temp:
	if (!ext && path[0])
		unlink(tempname);
	close(fd);
 err_unlink_back:
	if (!ext && path[0])
		unlink(backname);
 bind_return:
	if (errmsg && *errmsg) {
		if (!ext)
			memprintf(errmsg, "%s [%s]", *errmsg, path);
		else
			memprintf(errmsg, "%s [fd %d]", *errmsg, fd);
	}
	return err;

 bind_close_return:
	close(fd);
	goto bind_return;
}
