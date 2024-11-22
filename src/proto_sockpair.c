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

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/global.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/protocol.h>
#include <haproxy/proto_sockpair.h>
#include <haproxy/sock.h>
#include <haproxy/tools.h>
#include <haproxy/version.h>


static int sockpair_bind_listener(struct listener *listener, char *errmsg, int errlen);
static void sockpair_enable_listener(struct listener *listener);
static void sockpair_disable_listener(struct listener *listener);
static int sockpair_connect_server(struct connection *conn, int flags);
static int sockpair_accepting_conn(const struct receiver *rx);
struct connection *sockpair_accept_conn(struct listener *l, int *status);

struct proto_fam proto_fam_sockpair = {
	.name = "sockpair",
	.sock_domain = AF_UNIX,
	.sock_family = AF_CUST_SOCKPAIR,
	.real_family = AF_CUST_SOCKPAIR,
	.sock_addrlen = sizeof(struct sockaddr_un),
	.l3_addrlen = sizeof(((struct sockaddr_un*)0)->sun_path),
	.addrcmp = NULL,
	.bind = sockpair_bind_receiver,
	.get_src = NULL,
	.get_dst = NULL,
};

/* Note: must not be declared <const> as its list will be overwritten */
struct protocol proto_sockpair = {
	.name           = "sockpair",

	/* connection layer */
	.xprt_type      = PROTO_TYPE_STREAM,
	.listen         = sockpair_bind_listener,
	.enable         = sockpair_enable_listener,
	.disable        = sockpair_disable_listener,
	.add            = default_add_listener,
	.unbind         = default_unbind_listener,
	.accept_conn    = sockpair_accept_conn,
	.ctrl_init      = sock_conn_ctrl_init,
	.ctrl_close     = sock_conn_ctrl_close,
	.connect        = sockpair_connect_server,
	.drain          = sock_drain,
	.check_events   = sock_check_events,
	.ignore_events  = sock_ignore_events,

	/* binding layer */
	/* Note: suspend/resume not supported */

	/* address family */
	.fam            = &proto_fam_sockpair,

	/* socket layer */
	.proto_type     = PROTO_TYPE_STREAM,
	.sock_type      = SOCK_STREAM,
	.sock_prot      = 0,
	.rx_enable      = sock_enable,
	.rx_disable     = sock_disable,
	.rx_unbind      = sock_unbind,
	.rx_listening   = sockpair_accepting_conn,
	.default_iocb   = sock_accept_iocb,
};

INITCALL1(STG_REGISTER, protocol_register, &proto_sockpair);

/* Enable receipt of incoming connections for listener <l>. The receiver must
 * still be valid.
 */
static void sockpair_enable_listener(struct listener *l)
{
	fd_want_recv_safe(l->rx.fd);
}

/* Disable receipt of incoming connections for listener <l>. The receiver must
 * still be valid.
 */
static void sockpair_disable_listener(struct listener *l)
{
	fd_stop_recv(l->rx.fd);
}

/* Binds receiver <rx>, and assigns rx->iocb and rx->owner as the callback
 * and context, respectively, with ->bind_thread as the thread mask. Returns an
 * error code made of ERR_* bits on failure or ERR_NONE on success. On failure,
 * an error message may be passed into <errmsg>. Note that the binding address
 * is only an FD to receive the incoming FDs on. Thus by definition there is no
 * real "bind" operation, this only completes the receiver. Such FDs are not
 * inherited upon reload.
 */
int sockpair_bind_receiver(struct receiver *rx, char **errmsg)
{
	int err;

	/* ensure we never return garbage */
	if (errmsg)
		*errmsg = 0;

	err = ERR_NONE;

	if (rx->flags & RX_F_BOUND)
		return ERR_NONE;

	if (rx->flags & RX_F_MUST_DUP) {
		/* this is a secondary receiver that is an exact copy of a
		 * reference which must already be bound (or has failed).
		 * We'll try to dup() the other one's FD and take it. We
		 * try hard not to reconfigure the socket since it's shared.
		 */
		BUG_ON(!rx->shard_info);
		if (!(rx->shard_info->ref->flags & RX_F_BOUND)) {
			/* it's assumed that the first one has already reported
			 * the error, let's not spam with another one, and do
			 * not set ERR_ALERT.
			 */
			err |= ERR_RETRYABLE;
			goto bind_ret_err;
		}
		/* taking the other one's FD will result in it being marked
		 * extern and being dup()ed. Let's mark the receiver as
		 * inherited so that it properly bypasses all second-stage
		 * setup and avoids being passed to new processes.
		 */
		rx->flags |= RX_F_INHERITED;
		rx->fd = rx->shard_info->ref->fd;
	}

	if (rx->fd == -1) {
		err |= ERR_FATAL | ERR_ALERT;
		memprintf(errmsg, "sockpair may be only used with inherited FDs");
		goto bind_return;
	}

	if (rx->fd >= global.maxsock) {
		err |= ERR_FATAL | ERR_ABORT | ERR_ALERT;
		memprintf(errmsg, "not enough free sockets (raise '-n' parameter)");
		goto bind_close_return;
	}

	if (fd_set_nonblock(rx->fd) == -1) {
		err |= ERR_FATAL | ERR_ALERT;
		memprintf(errmsg, "cannot make socket non-blocking");
		goto bind_close_return;
	}

	rx->flags |= RX_F_BOUND;

	fd_insert(rx->fd, rx->owner, rx->iocb, rx->bind_tgroup, rx->bind_thread);
	return err;

 bind_return:
	if (errmsg && *errmsg)
		memprintf(errmsg, "%s for [fd %d]", *errmsg, rx->fd);

 bind_ret_err:
	return err;

 bind_close_return:
	close(rx->fd);
	goto bind_return;
}

/* This function changes the state from ASSIGNED to LISTEN. The socket is NOT
 * enabled for polling.  The return value is composed from ERR_NONE,
 * ERR_RETRYABLE and ERR_FATAL. It may return a warning or an error message in
 * <errmsg> if the message is at most <errlen> bytes long (including '\0').
 * Note that <errmsg> may be NULL if <errlen> is also zero.
 */
static int sockpair_bind_listener(struct listener *listener, char *errmsg, int errlen)
{
	int err;
	char *msg = NULL;

	err = ERR_NONE;

	/* ensure we never return garbage */
	if (errlen)
		*errmsg = 0;

	if (listener->state != LI_ASSIGNED)
		return ERR_NONE; /* already bound */

	if (!(listener->rx.flags & RX_F_BOUND)) {
		msg = "receiving socket not bound";
		goto err_return;
	}

	listener_set_state(listener, LI_LISTEN);
	return err;

 err_return:
	if (msg && errlen)
		snprintf(errmsg, errlen, "%s [fd %d]", msg, listener->rx.fd);
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
	char iobuf[2] = {0};
	struct iovec iov;
	struct msghdr msghdr;

	char cmsgbuf[CMSG_SPACE(sizeof(int))] = {0};
	char buf[CMSG_SPACE(sizeof(int))] = {0};
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
		return -1;
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

	BUG_ON(!conn->dst);

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

	if (fd_set_nonblock(fd) == -1) {
		qfprintf(stderr,"Cannot set client socket to non blocking mode.\n");
		close(sv[0]);
		close(sv[1]);
		conn->err_code = CO_ER_SOCK_ERR;
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_INTERNAL;
	}

	if (master == 1 && fd_set_cloexec(fd) == -1) {
		ha_alert("Cannot set CLOEXEC on client socket.\n");
		close(sv[0]);
		close(sv[1]);
		conn->err_code = CO_ER_SOCK_ERR;
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_INTERNAL;
	}

	if (global.tune.server_sndbuf)
                setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &global.tune.server_sndbuf, sizeof(global.tune.server_sndbuf));

	if (global.tune.server_rcvbuf)
                setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &global.tune.server_rcvbuf, sizeof(global.tune.server_rcvbuf));

	/* The new socket is sent on the other side, it should be retrieved and
	 * considered as an 'accept' socket on the server side */
	if (send_fd_uxst(dst_fd, sv[0]) == -1) {
		ha_alert("socketpair: Cannot transfer the fd %d over sockpair@%d. Giving up.\n", sv[0], dst_fd);
		close(sv[0]);
		close(sv[1]);
		conn->err_code = CO_ER_SOCK_ERR;
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_INTERNAL;
	}

	close(sv[0]); /* we don't need this side anymore */

	conn->flags &= ~CO_FL_WAIT_L4_CONN;

	/* Prepare to send a few handshakes related to the on-wire protocol. */
	if (conn->send_proxy_ofs)
		conn->flags |= CO_FL_SEND_PROXY;

	conn_ctrl_init(conn);       /* registers the FD */
	HA_ATOMIC_AND(&fdtab[fd].state, ~FD_LINGER_RISK);  /* no need to disable lingering */

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

/* Tests if the receiver supports accepting connections. Returns positive on
 * success, 0 if not possible, negative if the socket is non-recoverable. In
 * practice zero is never returned since we don't support suspending sockets.
 * The real test consists in verifying we have a connected SOCK_STREAM of
 * family AF_UNIX.
 */
static int sockpair_accepting_conn(const struct receiver *rx)
{
	struct sockaddr sa;
	socklen_t len;
	int val;

	len = sizeof(val);
	if (getsockopt(rx->fd, SOL_SOCKET, SO_TYPE, &val, &len) == -1)
		return -1;

	if (val != SOCK_STREAM)
		return -1;

	len = sizeof(sa);
	if (getsockname(rx->fd, &sa, &len) != 0)
		return -1;

	if (sa.sa_family != AF_UNIX)
		return -1;

	len = sizeof(val);
	if (getsockopt(rx->fd, SOL_SOCKET, SO_ACCEPTCONN, &val, &len) == -1)
		return -1;

	/* Note: cannot be a listening socket, must be established */
	if (val)
		return -1;

	return 1;
}

/* Accept an incoming connection from listener <l>, and return it, as well as
 * a CO_AC_* status code into <status> if not null. Null is returned on error.
 * <l> must be a valid listener with a valid frontend.
 */
struct connection *sockpair_accept_conn(struct listener *l, int *status)
{
	struct proxy *p = l->bind_conf->frontend;
	struct connection *conn = NULL;
	int ret;
	int cfd;

	if ((cfd = recv_fd_uxst(l->rx.fd)) != -1)
		fd_set_nonblock(cfd);

	if (likely(cfd != -1)) {
		/* Perfect, the connection was accepted */
		conn = conn_new(&l->obj_type);
		if (!conn)
			goto fail_conn;

		if (!sockaddr_alloc(&conn->src, NULL, 0))
			goto fail_addr;

		/* just like with UNIX sockets, only the family is filled */
		conn->src->ss_family = AF_UNIX;
		conn->handle.fd = cfd;
		ret = CO_AC_DONE;
		goto done;
	}

	switch (errno) {
#if defined(EWOULDBLOCK) && defined(EAGAIN) && EWOULDBLOCK != EAGAIN
	case EWOULDBLOCK:
#endif
	case EAGAIN:
		ret = CO_AC_DONE; /* nothing more to accept */
		if (fdtab[l->rx.fd].state & (FD_POLL_HUP|FD_POLL_ERR)) {
			/* the listening socket might have been disabled in a shared
			 * process and we're a collateral victim. We'll just pause for
			 * a while in case it comes back. In the mean time, we need to
			 * clear this sticky flag.
			 */
			_HA_ATOMIC_AND(&fdtab[l->rx.fd].state, ~(FD_POLL_HUP|FD_POLL_ERR));
			ret = CO_AC_PAUSE;
		}
		fd_cant_recv(l->rx.fd);
		break;

	case EINVAL:
		/* might be trying to accept on a shut fd (eg: soft stop) */
		ret = CO_AC_PAUSE;
		break;

	case EINTR:
	case ECONNABORTED:
		ret = CO_AC_RETRY;
		break;

	case ENFILE:
		if (p)
			send_log(p, LOG_EMERG,
			         "Proxy %s reached system FD limit (maxsock=%d). Please check system tunables.\n",
			         p->id, global.maxsock);
		ret = CO_AC_PAUSE;
		break;

	case EMFILE:
		if (p)
			send_log(p, LOG_EMERG,
			         "Proxy %s reached process FD limit (maxsock=%d). Please check 'ulimit-n' and restart.\n",
			         p->id, global.maxsock);
		ret = CO_AC_PAUSE;
		break;

	case ENOBUFS:
	case ENOMEM:
		if (p)
			send_log(p, LOG_EMERG,
			         "Proxy %s reached system memory limit (maxsock=%d). Please check system tunables.\n",
			         p->id, global.maxsock);
		ret = CO_AC_PAUSE;
		break;

	default:
		/* unexpected result, let's give up and let other tasks run */
		ret = CO_AC_YIELD;
	}
 done:
	if (status)
		*status = ret;
	return conn;

 fail_addr:
	conn_free(conn);
	conn = NULL;
 fail_conn:
	ret = CO_AC_PAUSE;
	goto done;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
