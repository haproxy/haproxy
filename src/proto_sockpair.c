/*
 * Socket Pair protocol layer (sockpair)
 *
 * Copyright HAProxy Technologies - William Lallemand <wlallemand@haproxy.com>
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
#include <common/initcall.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/time.h>
#include <common/version.h>

#include <types/global.h>

#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/listener.h>
#include <proto/log.h>
#include <proto/protocol.h>
#include <proto/task.h>

static void sockpair_add_listener(struct listener *listener, int port);
static int sockpair_bind_listener(struct listener *listener, char *errmsg, int errlen);
static int sockpair_bind_listeners(struct protocol *proto, char *errmsg, int errlen);
static int sockpair_connect_server(struct connection *conn, int flags);

/* Note: must not be declared <const> as its list will be overwritten */
static struct protocol proto_sockpair = {
	.name = "sockpair",
	.sock_domain = AF_CUST_SOCKPAIR,
	.sock_type = SOCK_STREAM,
	.sock_prot = 0,
	.sock_family = AF_UNIX,
	.sock_addrlen = sizeof(struct sockaddr_un),
	.l3_addrlen = sizeof(((struct sockaddr_un*)0)->sun_path),/* path len */
	.accept = &listener_accept,
	.connect = &sockpair_connect_server,
	.bind = sockpair_bind_listener,
	.bind_all = sockpair_bind_listeners,
	.unbind_all = NULL,
	.enable_all = enable_all_listeners,
	.disable_all = disable_all_listeners,
	.get_src = NULL,
	.get_dst = NULL,
	.pause = NULL,
	.add = sockpair_add_listener,
	.listeners = LIST_HEAD_INIT(proto_sockpair.listeners),
	.nb_listeners = 0,
};

INITCALL1(STG_REGISTER, protocol_register, &proto_sockpair);

/* Add <listener> to the list of sockpair listeners (port is ignored). The
 * listener's state is automatically updated from LI_INIT to LI_ASSIGNED.
 * The number of listeners for the protocol is updated.
 *
 * Must be called with proto_lock held.
 *
 */
static void sockpair_add_listener(struct listener *listener, int port)
{
	if (listener->state != LI_INIT)
		return;
	listener->state = LI_ASSIGNED;
	listener->proto = &proto_sockpair;
	LIST_ADDQ(&proto_sockpair.listeners, &listener->proto_list);
	proto_sockpair.nb_listeners++;
}

/* This function creates all UNIX sockets bound to the protocol entry <proto>.
 * It is intended to be used as the protocol's bind_all() function.
 * The sockets will be registered but not added to any fd_set, in order not to
 * loose them across the fork(). A call to uxst_enable_listeners() is needed
 * to complete initialization.
 *
 * Must be called with proto_lock held.
 *
 * The return value is composed from ERR_NONE, ERR_RETRYABLE and ERR_FATAL.
 */
static int sockpair_bind_listeners(struct protocol *proto, char *errmsg, int errlen)
{
	struct listener *listener;
	int err = ERR_NONE;

	list_for_each_entry(listener, &proto->listeners, proto_list) {
		err |= sockpair_bind_listener(listener, errmsg, errlen);
		if (err & ERR_ABORT)
			break;
	}
	return err;
}

/* This function changes the state from ASSIGNED to LISTEN. The socket is NOT
 * enabled for polling.  The return value is composed from ERR_NONE,
 * ERR_RETRYABLE and ERR_FATAL. It may return a warning or an error message in
 * <errmsg> if the message is at most <errlen> bytes long (including '\0').
 * Note that <errmsg> may be NULL if <errlen> is also zero.
 */
static int sockpair_bind_listener(struct listener *listener, char *errmsg, int errlen)
{
	int fd = listener->fd;
	int err;
	const char *msg = NULL;

	err = ERR_NONE;

	/* ensure we never return garbage */
	if (errlen)
		*errmsg = 0;

	if (listener->state != LI_ASSIGNED)
		return ERR_NONE; /* already bound */

	if (listener->fd == -1) {
		err |= ERR_FATAL | ERR_ALERT;
		msg = "sockpair can be only used with inherited FDs";
		goto err_return;
	}

	if (fd >= global.maxsock) {
		err |= ERR_FATAL | ERR_ALERT;
		msg = "socket(): not enough free sockets, raise -n argument";
		goto err_return;
	}
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		err |= ERR_FATAL | ERR_ALERT;
		msg = "cannot make sockpair non-blocking";
		goto err_return;
	}

	listener->state = LI_LISTEN;

	fd_insert(fd, listener, listener->proto->accept,
	          thread_mask(listener->bind_conf->bind_thread) & all_threads_mask);

	return err;

 err_return:
	if (msg && errlen)
		snprintf(errmsg, errlen, "%s [fd %d]", msg, fd);
	return err;
}

/*
 * Send FD over a unix socket
 *
 * <send_fd> is the FD to send
 * <fd> is the fd of the unix socket to use for the transfer
 *
 * The iobuf variable could be use in the future to enhance the protocol.
 */
int send_fd_uxst(int fd, int send_fd)
{
	char iobuf[2];
	struct iovec iov;
	struct msghdr msghdr;

	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	char buf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg = (void *)buf;

	int *fdptr;

	iov.iov_base = iobuf;
	iov.iov_len = sizeof(iobuf);

	memset(&msghdr, 0, sizeof(msghdr));
	msghdr.msg_iov = &iov;
	msghdr.msg_iovlen = 1;

	/* Now send the fds */
	msghdr.msg_control = cmsgbuf;
	msghdr.msg_controllen = CMSG_SPACE(sizeof(int));

	cmsg = CMSG_FIRSTHDR(&msghdr);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;

	fdptr = (int *)CMSG_DATA(cmsg);
	memcpy(fdptr, &send_fd, sizeof(send_fd));

	if (sendmsg(fd, &msghdr, 0) != sizeof(iobuf)) {
		ha_warning("Failed to transfer socket\n");
		return 1;
	}

	return 0;
}

/*
 *
 * This function works like uxst_connect_server but instead of creating a
 * socket and establishing a connection, it creates a pair of connected
 * sockets, and send one of them through the destination FD. The destination FD
 * is stored in conn->dst->sin_addr.s_addr during configuration parsing.
 *
 * conn->target may point either to a valid server or to a backend, depending
 * on conn->target. Only OBJ_TYPE_PROXY and OBJ_TYPE_SERVER are supported. The
 * <data> parameter is a boolean indicating whether there are data waiting for
 * being sent or not, in order to adjust data write polling and on some
 * platforms. The <delack> argument is ignored.
 *
 * Note that a pending send_proxy message accounts for data.
 *
 * It can return one of :
 *  - SF_ERR_NONE if everything's OK
 *  - SF_ERR_SRVTO if there are no more servers
 *  - SF_ERR_SRVCL if the connection was refused by the server
 *  - SF_ERR_PRXCOND if the connection has been limited by the proxy (maxconn)
 *  - SF_ERR_RESOURCE if a system resource is lacking (eg: fd limits, ports, ...)
 *  - SF_ERR_INTERNAL for any other purely internal errors
 * Additionally, in the case of SF_ERR_RESOURCE, an emergency log will be emitted.
 *
 * The connection's fd is inserted only when SF_ERR_NONE is returned, otherwise
 * it's invalid and the caller has nothing to do.
 */
static int sockpair_connect_server(struct connection *conn, int flags)
{
	int sv[2], fd, dst_fd = -1;

	/* the FD is stored in the sockaddr struct */
	dst_fd = ((struct sockaddr_in *)conn->dst)->sin_addr.s_addr;

	if (obj_type(conn->target) != OBJ_TYPE_PROXY &&
	    obj_type(conn->target) != OBJ_TYPE_SERVER) {
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_INTERNAL;
	}

	if (socketpair(PF_UNIX, SOCK_STREAM, 0, sv) == -1) {
		ha_alert("socketpair(): Cannot create socketpair. Giving up.\n");
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_RESOURCE;
	}

	fd = conn->handle.fd = sv[1];

	if (fd >= global.maxsock) {
		/* do not log anything there, it's a normal condition when this option
		 * is used to serialize connections to a server !
		 */
		ha_alert("socket(): not enough free sockets. Raise -n argument. Giving up.\n");
		close(sv[0]);
		close(sv[1]);
		conn->err_code = CO_ER_CONF_FDLIM;
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_PRXCOND; /* it is a configuration limit */
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		qfprintf(stderr,"Cannot set client socket to non blocking mode.\n");
		close(sv[0]);
		close(sv[1]);
		conn->err_code = CO_ER_SOCK_ERR;
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_INTERNAL;
	}

	if (master == 1 && (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)) {
		ha_alert("Cannot set CLOEXEC on client socket.\n");
		close(sv[0]);
		close(sv[1]);
		conn->err_code = CO_ER_SOCK_ERR;
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_INTERNAL;
	}

	/* if a send_proxy is there, there are data */
	if (conn->send_proxy_ofs)
		flags |= CONNECT_HAS_DATA;

	if (global.tune.server_sndbuf)
                setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &global.tune.server_sndbuf, sizeof(global.tune.server_sndbuf));

	if (global.tune.server_rcvbuf)
                setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &global.tune.server_rcvbuf, sizeof(global.tune.server_rcvbuf));

	/* The new socket is sent on the other side, it should be retrieved and
	 * considered as an 'accept' socket on the server side */
	if (send_fd_uxst(dst_fd, sv[0]) == -1) {
		close(sv[0]);
		close(sv[1]);
		conn->err_code = CO_ER_SOCK_ERR;
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_INTERNAL;
	}

	close(sv[0]); /* we don't need this side anymore */

	conn->flags &= ~CO_FL_WAIT_L4_CONN;

	conn->flags |= CO_FL_ADDR_TO_SET;

	/* Prepare to send a few handshakes related to the on-wire protocol. */
	if (conn->send_proxy_ofs)
		conn->flags |= CO_FL_SEND_PROXY;

	conn_ctrl_init(conn);       /* registers the FD */
	fdtab[fd].linger_risk = 0;  /* no need to disable lingering */

	if (conn_xprt_init(conn) < 0) {
		conn_full_close(conn);
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_RESOURCE;
	}

	conn_xprt_want_send(conn);  /* for connect status, proxy protocol or SSL */
	return SF_ERR_NONE;  /* connection is OK */
}


/*
 * Receives a file descriptor transferred from a unix socket.
 *
 * Return -1 or a socket fd;
 *
 * The iobuf variable could be used in the future to enhance the protocol.
 */
int recv_fd_uxst(int sock)
{
	struct msghdr msghdr;
	struct iovec iov;
	char iobuf[2];

	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	char buf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg = (void *)buf;


	int recv_fd = -1;
	int ret = -1;

	memset(&msghdr, 0, sizeof(msghdr));

	iov.iov_base = iobuf;
	iov.iov_len = sizeof(iobuf);

	msghdr.msg_iov = &iov;
	msghdr.msg_iovlen = 1;

	msghdr.msg_control = cmsgbuf;
	msghdr.msg_controllen = CMSG_SPACE(sizeof(int));

	iov.iov_len = sizeof(iobuf);
	iov.iov_base = iobuf;

	while (1) {
		ret = recvmsg(sock, &msghdr, 0);
		if (ret == -1 && errno == EINTR)
			continue;
		else
			break;
	}

	if (ret == -1)
		return ret;

	cmsg = CMSG_FIRSTHDR(&msghdr);
	if (cmsg && cmsg->cmsg_level == SOL_SOCKET &&
	    cmsg->cmsg_type == SCM_RIGHTS) {
		size_t totlen = cmsg->cmsg_len -
			CMSG_LEN(0);
		memcpy(&recv_fd, CMSG_DATA(cmsg), totlen);
	}
	return recv_fd;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
