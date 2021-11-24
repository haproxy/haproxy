/*
 * Generic code for native (BSD-compatible) sockets
 *
 * Copyright 2000-2020 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <net/if.h>

#include <haproxy/api.h>
#include <haproxy/activity.h>
#include <haproxy/connection.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/namespace.h>
#include <haproxy/proto_sockpair.h>
#include <haproxy/sock.h>
#include <haproxy/sock_inet.h>
#include <haproxy/tools.h>

/* the list of remaining sockets transferred from an older process */
struct xfer_sock_list *xfer_sock_list = NULL;


/* Accept an incoming connection from listener <l>, and return it, as well as
 * a CO_AC_* status code into <status> if not null. Null is returned on error.
 * <l> must be a valid listener with a valid frontend.
 */
struct connection *sock_accept_conn(struct listener *l, int *status)
{
#ifdef USE_ACCEPT4
	static int accept4_broken;
#endif
	struct proxy *p = l->bind_conf->frontend;
	struct connection *conn = NULL;
	struct sockaddr_storage *addr = NULL;
	socklen_t laddr;
	int ret;
	int cfd;

	if (!sockaddr_alloc(&addr, NULL, 0))
		goto fail_addr;

	/* accept() will mark all accepted FDs O_NONBLOCK and the ones accepted
	 * in the master process as FD_CLOEXEC. It's not done for workers
	 * because 1) workers are not supposed to execute anything so there's
	 * no reason for uselessly slowing down everything, and 2) that would
	 * prevent us from implementing fd passing in the future.
	 */
#ifdef USE_ACCEPT4
	laddr = sizeof(*conn->src);

	/* only call accept4() if it's known to be safe, otherwise fallback to
	 * the legacy accept() + fcntl().
	 */
	if (unlikely(accept4_broken) ||
	    (((cfd = accept4(l->rx.fd, (struct sockaddr*)addr, &laddr,
	                     SOCK_NONBLOCK | (master ? SOCK_CLOEXEC : 0))) == -1) &&
	     (errno == ENOSYS || errno == EINVAL || errno == EBADF) &&
	     ((accept4_broken = 1))))
#endif
	{
		laddr = sizeof(*conn->src);
		if ((cfd = accept(l->rx.fd, (struct sockaddr*)addr, &laddr)) != -1) {
			fcntl(cfd, F_SETFL, O_NONBLOCK);
			if (master)
				fcntl(cfd, F_SETFD, FD_CLOEXEC);
		}
	}

	if (likely(cfd != -1)) {
		/* Perfect, the connection was accepted */
		conn = conn_new(&l->obj_type);
		if (!conn)
			goto fail_conn;

		conn->src = addr;
		conn->handle.fd = cfd;
		conn->flags |= CO_FL_ADDR_FROM_SET;
		ret = CO_AC_DONE;
		goto done;
	}

	/* error conditions below */
	sockaddr_free(&addr);

	switch (errno) {
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

 fail_conn:
	sockaddr_free(&addr);
	/* The accept call already succeeded by the time we try to allocate the connection,
	 * we need to close it in case of failure. */
	close(cfd);
 fail_addr:
	ret = CO_AC_PAUSE;
	goto done;
}

/* Create a socket to connect to the server in conn->dst (which MUST be valid),
 * using the configured namespace if needed, or the one passed by the proxy
 * protocol if required to do so. It ultimately calls socket() or socketat()
 * and returns the FD or error code.
 */
int sock_create_server_socket(struct connection *conn)
{
	const struct netns_entry *ns = NULL;

#ifdef USE_NS
	if (objt_server(conn->target)) {
		if (__objt_server(conn->target)->flags & SRV_F_USE_NS_FROM_PP)
			ns = conn->proxy_netns;
		else
			ns = __objt_server(conn->target)->netns;
	}
#endif
	return my_socketat(ns, conn->dst->ss_family, SOCK_STREAM, 0);
}

/* Enables receiving on receiver <rx> once already bound. */
void sock_enable(struct receiver *rx)
{
        if (rx->flags & RX_F_BOUND)
		fd_want_recv_safe(rx->fd);
}

/* Disables receiving on receiver <rx> once already bound. */
void sock_disable(struct receiver *rx)
{
        if (rx->flags & RX_F_BOUND)
		fd_stop_recv(rx->fd);
}

/* stops, unbinds and possibly closes the FD associated with receiver rx */
void sock_unbind(struct receiver *rx)
{
	/* There are a number of situations where we prefer to keep the FD and
	 * not to close it (unless we're stopping, of course):
	 *   - worker process unbinding from a worker's FD with socket transfer enabled => keep
	 *   - master process unbinding from a master's inherited FD => keep
	 *   - master process unbinding from a master's FD => close
	 *   - master process unbinding from a worker's inherited FD => keep
	 *   - master process unbinding from a worker's FD => close
	 *   - worker process unbinding from a master's FD => close
	 *   - worker process unbinding from a worker's FD => close
	 */
	if (rx->flags & RX_F_BOUND)
		rx->proto->rx_disable(rx);

	if (!stopping && !master &&
	    !(rx->flags & RX_F_MWORKER) &&
	    (global.tune.options & GTUNE_SOCKET_TRANSFER))
		return;

	if (!stopping && master &&
	    rx->flags & RX_F_INHERITED)
		return;

	rx->flags &= ~RX_F_BOUND;
	if (rx->fd != -1)
		fd_delete(rx->fd);
	rx->fd = -1;
}

/*
 * Retrieves the source address for the socket <fd>, with <dir> indicating
 * if we're a listener (=0) or an initiator (!=0). It returns 0 in case of
 * success, -1 in case of error. The socket's source address is stored in
 * <sa> for <salen> bytes.
 */
int sock_get_src(int fd, struct sockaddr *sa, socklen_t salen, int dir)
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
int sock_get_dst(int fd, struct sockaddr *sa, socklen_t salen, int dir)
{
	if (dir)
		return getpeername(fd, sa, &salen);
	else
		return getsockname(fd, sa, &salen);
}

/* Try to retrieve exported sockets from worker at CLI <unixsocket>. These
 * ones will be placed into the xfer_sock_list for later use by function
 * sock_find_compatible_fd(). Returns 0 on success, -1 on failure.
 */
int sock_get_old_sockets(const char *unixsocket)
{
	char *cmsgbuf = NULL, *tmpbuf = NULL;
	int *tmpfd = NULL;
	struct sockaddr_un addr;
	struct cmsghdr *cmsg;
	struct msghdr msghdr;
	struct iovec iov;
	struct xfer_sock_list *xfer_sock = NULL;
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	int sock = -1;
	int ret = -1;
	int ret2 = -1;
	int fd_nb;
	int got_fd = 0;
	int cur_fd = 0;
	size_t maxoff = 0, curoff = 0;

	if (strncmp("sockpair@", unixsocket, strlen("sockpair@")) == 0) {
		/* sockpair for master-worker usage */
		int sv[2];
		int dst_fd;

		dst_fd = strtoll(unixsocket + strlen("sockpair@"), NULL, 0);

		if (socketpair(PF_UNIX, SOCK_STREAM, 0, sv) == -1) {
			ha_warning("socketpair(): Cannot create socketpair. Giving up.\n");
		}

		if (send_fd_uxst(dst_fd, sv[0]) == -1) {
			ha_alert("socketpair: cannot transfer socket.\n");
			close(sv[0]);
			close(sv[1]);
			goto out;
		}

		close(sv[0]); /* we don't need this side anymore */
		sock = sv[1];

	} else {
		/* Unix socket */

		sock = socket(PF_UNIX, SOCK_STREAM, 0);
		if (sock < 0) {
			ha_warning("Failed to connect to the old process socket '%s'\n", unixsocket);
			goto out;
		}

		strncpy(addr.sun_path, unixsocket, sizeof(addr.sun_path) - 1);
		addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
		addr.sun_family = PF_UNIX;

		ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
		if (ret < 0) {
			ha_warning("Failed to connect to the old process socket '%s'\n", unixsocket);
			goto out;
		}

	}
	memset(&msghdr, 0, sizeof(msghdr));
	cmsgbuf = malloc(CMSG_SPACE(sizeof(int)) * MAX_SEND_FD);
	if (!cmsgbuf) {
		ha_warning("Failed to allocate memory to send sockets\n");
		goto out;
	}

	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *)&tv, sizeof(tv));
	iov.iov_base = &fd_nb;
	iov.iov_len = sizeof(fd_nb);
	msghdr.msg_iov = &iov;
	msghdr.msg_iovlen = 1;

	if (send(sock, "_getsocks\n", strlen("_getsocks\n"), 0) != strlen("_getsocks\n")) {
		ha_warning("Failed to get the number of sockets to be transferred !\n");
		goto out;
	}

	/* First, get the number of file descriptors to be received */
	if (recvmsg(sock, &msghdr, MSG_WAITALL) != sizeof(fd_nb)) {
		ha_warning("Failed to get the number of sockets to be transferred !\n");
		goto out;
	}

	if (fd_nb == 0) {
		ret2 = 0;
		goto out;
	}

	tmpbuf = malloc(fd_nb * (1 + MAXPATHLEN + 1 + IFNAMSIZ + sizeof(int)));
	if (tmpbuf == NULL) {
		ha_warning("Failed to allocate memory while receiving sockets\n");
		goto out;
	}

	tmpfd = malloc(fd_nb * sizeof(int));
	if (tmpfd == NULL) {
		ha_warning("Failed to allocate memory while receiving sockets\n");
		goto out;
	}

	msghdr.msg_control = cmsgbuf;
	msghdr.msg_controllen = CMSG_SPACE(sizeof(int)) * MAX_SEND_FD;
	iov.iov_len = MAX_SEND_FD * (1 + MAXPATHLEN + 1 + IFNAMSIZ + sizeof(int));

	do {
		int ret3;

		iov.iov_base = tmpbuf + curoff;

		ret = recvmsg(sock, &msghdr, 0);

		if (ret == -1 && errno == EINTR)
			continue;

		if (ret <= 0)
			break;

		/* Send an ack to let the sender know we got the sockets
		 * and it can send some more
		 */
		do {
			ret3 = send(sock, &got_fd, sizeof(got_fd), 0);
		} while (ret3 == -1 && errno == EINTR);

		for (cmsg = CMSG_FIRSTHDR(&msghdr); cmsg != NULL; cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
			if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
				size_t totlen = cmsg->cmsg_len - CMSG_LEN(0);

				if (totlen / sizeof(int) + got_fd > fd_nb) {
					ha_warning("Got to many sockets !\n");
					goto out;
				}

				/*
				 * Be paranoid and use memcpy() to avoid any
				 * potential alignment issue.
				 */
				memcpy(&tmpfd[got_fd], CMSG_DATA(cmsg), totlen);
				got_fd += totlen / sizeof(int);
			}
		}
		curoff += ret;
	} while (got_fd < fd_nb);

	if (got_fd != fd_nb) {
		ha_warning("We didn't get the expected number of sockets (expecting %d got %d)\n",
			   fd_nb, got_fd);
		goto out;
	}

	maxoff = curoff;
	curoff = 0;

	for (cur_fd = 0; cur_fd < got_fd; cur_fd++) {
		int fd = tmpfd[cur_fd];
		socklen_t socklen;
		int val;
		int len;

		xfer_sock = calloc(1, sizeof(*xfer_sock));
		if (!xfer_sock) {
			ha_warning("Failed to allocate memory in get_old_sockets() !\n");
			break;
		}
		xfer_sock->fd = -1;

		socklen = sizeof(xfer_sock->addr);
		if (getsockname(fd, (struct sockaddr *)&xfer_sock->addr, &socklen) != 0) {
			ha_warning("Failed to get socket address\n");
			ha_free(&xfer_sock);
			continue;
		}

		if (curoff >= maxoff) {
			ha_warning("Inconsistency while transferring sockets\n");
			goto out;
		}

		len = tmpbuf[curoff++];
		if (len > 0) {
			/* We have a namespace */
			if (curoff + len > maxoff) {
				ha_warning("Inconsistency while transferring sockets\n");
				goto out;
			}
			xfer_sock->namespace = malloc(len + 1);
			if (!xfer_sock->namespace) {
				ha_warning("Failed to allocate memory while transferring sockets\n");
				goto out;
			}
			memcpy(xfer_sock->namespace, &tmpbuf[curoff], len);
			xfer_sock->namespace[len] = 0;
			xfer_sock->ns_namelen = len;
			curoff += len;
		}

		if (curoff >= maxoff) {
			ha_warning("Inconsistency while transferring sockets\n");
			goto out;
		}

		len = tmpbuf[curoff++];
		if (len > 0) {
			/* We have an interface */
			if (curoff + len > maxoff) {
				ha_warning("Inconsistency while transferring sockets\n");
				goto out;
			}
			xfer_sock->iface = malloc(len + 1);
			if (!xfer_sock->iface) {
				ha_warning("Failed to allocate memory while transferring sockets\n");
				goto out;
			}
			memcpy(xfer_sock->iface, &tmpbuf[curoff], len);
			xfer_sock->iface[len] = 0;
			xfer_sock->if_namelen = len;
			curoff += len;
		}

		if (curoff + sizeof(int) > maxoff) {
			ha_warning("Inconsistency while transferring sockets\n");
			goto out;
		}

		/* we used to have 32 bits of listener options here but we don't
		 * use them anymore.
		 */
		curoff += sizeof(int);

		/* determine the foreign status directly from the socket itself */
		if (sock_inet_is_foreign(fd, xfer_sock->addr.ss_family))
			xfer_sock->options |= SOCK_XFER_OPT_FOREIGN;

		socklen = sizeof(val);
		if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &val, &socklen) == 0 && val == SOCK_DGRAM)
			xfer_sock->options |= SOCK_XFER_OPT_DGRAM;

#if defined(IPV6_V6ONLY)
		/* keep only the v6only flag depending on what's currently
		 * active on the socket, and always drop the v4v6 one.
		 */
		socklen = sizeof(val);
		if (xfer_sock->addr.ss_family == AF_INET6 &&
		    getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, &socklen) == 0 && val > 0)
			xfer_sock->options |= SOCK_XFER_OPT_V6ONLY;
#endif

		xfer_sock->fd = fd;
		if (xfer_sock_list)
			xfer_sock_list->prev = xfer_sock;
		xfer_sock->next = xfer_sock_list;
		xfer_sock->prev = NULL;
		xfer_sock_list = xfer_sock;
		xfer_sock = NULL;
	}

	ret2 = 0;
out:
	/* If we failed midway make sure to close the remaining
	 * file descriptors
	 */
	if (tmpfd != NULL && cur_fd < got_fd) {
		for (; cur_fd < got_fd; cur_fd++) {
			close(tmpfd[cur_fd]);
		}
	}

	free(tmpbuf);
	free(tmpfd);
	free(cmsgbuf);

	if (sock != -1)
		close(sock);

	if (xfer_sock) {
		free(xfer_sock->namespace);
		free(xfer_sock->iface);
		if (xfer_sock->fd != -1)
			close(xfer_sock->fd);
		free(xfer_sock);
	}
	return (ret2);
}

/* When binding the receivers, check if a socket has been sent to us by the
 * previous process that we could reuse, instead of creating a new one. Note
 * that some address family-specific options are checked on the listener and
 * on the socket. Typically for AF_INET and AF_INET6, we check for transparent
 * mode, and for AF_INET6 we also check for "v4v6" or "v6only". The reused
 * socket is automatically removed from the list so that it's not proposed
 * anymore.
 */
int sock_find_compatible_fd(const struct receiver *rx)
{
	struct xfer_sock_list *xfer_sock = xfer_sock_list;
	int options = 0;
	int if_namelen = 0;
	int ns_namelen = 0;
	int ret = -1;

	if (!rx->proto->fam->addrcmp)
		return -1;

	if (rx->proto->proto_type == PROTO_TYPE_DGRAM)
		options |= SOCK_XFER_OPT_DGRAM;

	if (rx->settings->options & RX_O_FOREIGN)
		options |= SOCK_XFER_OPT_FOREIGN;

	if (rx->addr.ss_family == AF_INET6) {
		/* Prepare to match the v6only option against what we really want. Note
		 * that sadly the two options are not exclusive to each other and that
		 * v6only is stronger than v4v6.
		 */
		if ((rx->settings->options & RX_O_V6ONLY) ||
		    (sock_inet6_v6only_default && !(rx->settings->options & RX_O_V4V6)))
			options |= SOCK_XFER_OPT_V6ONLY;
	}

	if (rx->settings->interface)
		if_namelen = strlen(rx->settings->interface);
#ifdef USE_NS
	if (rx->settings->netns)
		ns_namelen = rx->settings->netns->name_len;
#endif

	while (xfer_sock) {
		if ((options == xfer_sock->options) &&
		    (if_namelen == xfer_sock->if_namelen) &&
		    (ns_namelen == xfer_sock->ns_namelen) &&
		    (!if_namelen || strcmp(rx->settings->interface, xfer_sock->iface) == 0) &&
#ifdef USE_NS
		    (!ns_namelen || strcmp(rx->settings->netns->node.key, xfer_sock->namespace) == 0) &&
#endif
		    rx->proto->fam->addrcmp(&xfer_sock->addr, &rx->addr) == 0)
			break;
		xfer_sock = xfer_sock->next;
	}

	if (xfer_sock != NULL) {
		ret = xfer_sock->fd;
		if (xfer_sock == xfer_sock_list)
			xfer_sock_list = xfer_sock->next;
		if (xfer_sock->prev)
			xfer_sock->prev->next = xfer_sock->next;
		if (xfer_sock->next)
			xfer_sock->next->prev = xfer_sock->prev;
		free(xfer_sock->iface);
		free(xfer_sock->namespace);
		free(xfer_sock);
	}
	return ret;
}

/* Tests if the receiver supports accepting connections. Returns positive on
 * success, 0 if not possible, negative if the socket is non-recoverable. The
 * rationale behind this is that inherited FDs may be broken and that shared
 * FDs might have been paused by another process.
 */
int sock_accepting_conn(const struct receiver *rx)
{
	int opt_val = 0;
	socklen_t opt_len = sizeof(opt_val);

	if (getsockopt(rx->fd, SOL_SOCKET, SO_ACCEPTCONN, &opt_val, &opt_len) == -1)
		return -1;

	return opt_val;
}

/* This is the FD handler IO callback for stream sockets configured for
 * accepting incoming connections. It's a pass-through to listener_accept()
 * which will iterate over the listener protocol's accept_conn() function.
 * The FD's owner must be a listener.
 */
void sock_accept_iocb(int fd)
{
	struct listener *l = fdtab[fd].owner;

	if (!l)
		return;

	BUG_ON(!!master != !!(l->rx.flags & RX_F_MWORKER));
	listener_accept(l);
}

/* This completes the initialization of connection <conn> by inserting its FD
 * into the fdtab, associating it with the regular connection handler. It will
 * be bound to the current thread only. This call cannot fail.
 */
void sock_conn_ctrl_init(struct connection *conn)
{
	fd_insert(conn->handle.fd, conn, sock_conn_iocb, tid_bit);
}

/* This completes the release of connection <conn> by removing its FD from the
 * fdtab and deleting it. The connection must not use the FD anymore past this
 * point. The FD may be modified in the connection.
 */
void sock_conn_ctrl_close(struct connection *conn)
{
	fd_delete(conn->handle.fd);
	conn->handle.fd = DEAD_FD_MAGIC;
}

/* This is the callback which is set when a connection establishment is pending
 * and we have nothing to send. It may update the FD polling status to indicate
 * !READY. It returns 0 if it fails in a fatal way or needs to poll to go
 * further, otherwise it returns non-zero and removes the CO_FL_WAIT_L4_CONN
 * flag from the connection's flags. In case of error, it sets CO_FL_ERROR and
 * leaves the error code in errno.
 */
int sock_conn_check(struct connection *conn)
{
	struct sockaddr_storage *addr;
	int fd = conn->handle.fd;

	if (conn->flags & CO_FL_ERROR)
		return 0;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!(conn->flags & CO_FL_WAIT_L4_CONN))
		return 1; /* strange we were called while ready */

	if (!fd_send_ready(fd) && !(fdtab[fd].state & (FD_POLL_ERR|FD_POLL_HUP)))
		return 0;

	/* Here we have 2 cases :
	 *  - modern pollers, able to report ERR/HUP. If these ones return any
	 *    of these flags then it's likely a failure, otherwise it possibly
	 *    is a success (i.e. there may have been data received just before
	 *    the error was reported).
	 *  - select, which doesn't report these and with which it's always
	 *    necessary either to try connect() again or to check for SO_ERROR.
	 * In order to simplify everything, we double-check using connect() as
	 * soon as we meet either of these delicate situations. Note that
	 * SO_ERROR would clear the error after reporting it!
	 */
	if (cur_poller.flags & HAP_POLL_F_ERRHUP) {
		/* modern poller, able to report ERR/HUP */
		if ((fdtab[fd].state & (FD_POLL_IN|FD_POLL_ERR|FD_POLL_HUP)) == FD_POLL_IN)
			goto done;
		if ((fdtab[fd].state & (FD_POLL_OUT|FD_POLL_ERR|FD_POLL_HUP)) == FD_POLL_OUT)
			goto done;
		if (!(fdtab[fd].state & (FD_POLL_ERR|FD_POLL_HUP)))
			goto wait;
		/* error present, fall through common error check path */
	}

	/* Use connect() to check the state of the socket. This has the double
	 * advantage of *not* clearing the error (so that health checks can
	 * still use getsockopt(SO_ERROR)) and giving us the following info :
	 *  - error
	 *  - connecting (EALREADY, EINPROGRESS)
	 *  - connected (EISCONN, 0)
	 */
	addr = conn->dst;
	if ((conn->flags & CO_FL_SOCKS4) && obj_type(conn->target) == OBJ_TYPE_SERVER)
		addr = &objt_server(conn->target)->socks4_addr;

	if (connect(fd, (const struct sockaddr *)addr, get_addr_len(addr)) == -1) {
		if (errno == EALREADY || errno == EINPROGRESS)
			goto wait;

		if (errno && errno != EISCONN)
			goto out_error;
	}

 done:
	/* The FD is ready now, we'll mark the connection as complete and
	 * forward the event to the transport layer which will notify the
	 * data layer.
	 */
	conn->flags &= ~CO_FL_WAIT_L4_CONN;
	fd_may_send(fd);
	fd_cond_recv(fd);
	errno = 0; // make health checks happy
	return 1;

 out_error:
	/* Write error on the file descriptor. Report it to the connection
	 * and disable polling on this FD.
	 */
	conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
	HA_ATOMIC_AND(&fdtab[fd].state, ~FD_LINGER_RISK);
	fd_stop_both(fd);
	return 0;

 wait:
	fd_cant_send(fd);
	fd_want_send(fd);
	return 0;
}

/* I/O callback for fd-based connections. It calls the read/write handlers
 * provided by the connection's sock_ops, which must be valid.
 */
void sock_conn_iocb(int fd)
{
	struct connection *conn = fdtab[fd].owner;
	unsigned int flags;
	int need_wake = 0;

	if (unlikely(!conn)) {
		activity[tid].conn_dead++;
		return;
	}

	flags = conn->flags & ~CO_FL_ERROR; /* ensure to call the wake handler upon error */

	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) &&
	    ((fd_send_ready(fd) && fd_send_active(fd)) ||
	     (fd_recv_ready(fd) && fd_recv_active(fd)))) {
		/* Still waiting for a connection to establish and nothing was
		 * attempted yet to probe the connection. this will clear the
		 * CO_FL_WAIT_L4_CONN flag on success.
		 */
		if (!sock_conn_check(conn))
			goto leave;
		need_wake = 1;
	}

	if (fd_send_ready(fd) && fd_send_active(fd)) {
		/* force reporting of activity by clearing the previous flags :
		 * we'll have at least ERROR or CONNECTED at the end of an I/O,
		 * both of which will be detected below.
		 */
		flags = 0;
		if (conn->subs && conn->subs->events & SUB_RETRY_SEND) {
			need_wake = 0; // wake will be called after this I/O
			tasklet_wakeup(conn->subs->tasklet);
			conn->subs->events &= ~SUB_RETRY_SEND;
			if (!conn->subs->events)
				conn->subs = NULL;
		}
		fd_stop_send(fd);
	}

	/* The data transfer starts here and stops on error and handshakes. Note
	 * that we must absolutely test conn->xprt at each step in case it suddenly
	 * changes due to a quick unexpected close().
	 */
	if (fd_recv_ready(fd) && fd_recv_active(fd)) {
		/* force reporting of activity by clearing the previous flags :
		 * we'll have at least ERROR or CONNECTED at the end of an I/O,
		 * both of which will be detected below.
		 */
		flags = 0;
		if (conn->subs && conn->subs->events & SUB_RETRY_RECV) {
			need_wake = 0; // wake will be called after this I/O
			tasklet_wakeup(conn->subs->tasklet);
			conn->subs->events &= ~SUB_RETRY_RECV;
			if (!conn->subs->events)
				conn->subs = NULL;
		}
		fd_stop_recv(fd);
	}

 leave:
	/* we may have to finish to install a mux or to wake it up based on
	 * what was just done above. It may kill the connection so we have to
	 * be prpared not to use it anymore.
	 */
	if (conn_notify_mux(conn, flags, need_wake) < 0)
		return;

	/* commit polling changes in case of error.
	 * WT: it seems that the last case where this could still be relevant
	 * is if a mux wake function above report a connection error but does
	 * not stop polling. Shouldn't we enforce this into the mux instead of
	 * having to deal with this ?
	 */
	if (unlikely(conn->flags & CO_FL_ERROR)) {
		if (conn_ctrl_ready(conn))
			fd_stop_both(fd);
	}
}

/* Drains possibly pending incoming data on the file descriptor attached to the
 * connection. This is used to know whether we need to disable lingering on
 * close. Returns non-zero if it is safe to close without disabling lingering,
 * otherwise zero.
 */
int sock_drain(struct connection *conn)
{
	int turns = 2;
	int fd = conn->handle.fd;
	int len;

	if (fdtab[fd].state & (FD_POLL_ERR|FD_POLL_HUP))
		goto shut;

	if (!(conn->flags & CO_FL_WANT_DRAIN) && !fd_recv_ready(fd))
		return 0;

	/* no drain function defined, use the generic one */

	while (turns) {
#ifdef MSG_TRUNC_CLEARS_INPUT
		len = recv(fd, NULL, INT_MAX, MSG_DONTWAIT | MSG_NOSIGNAL | MSG_TRUNC);
		if (len == -1 && errno == EFAULT)
#endif
			len = recv(fd, trash.area, trash.size, MSG_DONTWAIT | MSG_NOSIGNAL);

		if (len == 0)
			goto shut;

		if (len < 0) {
			if (errno == EAGAIN) {
				/* connection not closed yet */
				fd_cant_recv(fd);
				break;
			}
			if (errno == EINTR)  /* oops, try again */
				continue;
			/* other errors indicate a dead connection, fine. */
			goto shut;
		}
		/* OK we read some data, let's try again once */
		turns--;
	}

	/* some data are still present, give up */
	return 0;

 shut:
	/* we're certain the connection was shut down */
	HA_ATOMIC_AND(&fdtab[fd].state, ~FD_LINGER_RISK);
	return 1;
}

/* Checks the connection's FD for readiness of events <event_type>, which may
 * only be a combination of SUB_RETRY_RECV and SUB_RETRY_SEND. Those which are
 * ready are returned. The ones that are not ready are enabled. The caller is
 * expected to do what is needed to handle ready events and to deal with
 * subsequent wakeups caused by the requested events' readiness.
 */
int sock_check_events(struct connection *conn, int event_type)
{
	int ret = 0;

	if (event_type & SUB_RETRY_RECV) {
		if (fd_recv_ready(conn->handle.fd))
			ret |= SUB_RETRY_RECV;
		else
			fd_want_recv(conn->handle.fd);
	}

	if (event_type & SUB_RETRY_SEND) {
		if (fd_send_ready(conn->handle.fd))
			ret |= SUB_RETRY_SEND;
		else
			fd_want_send(conn->handle.fd);
	}

	return ret;
}

/* Ignore readiness events from connection's FD for events of types <event_type>
 * which may only be a combination of SUB_RETRY_RECV and SUB_RETRY_SEND.
 */
void sock_ignore_events(struct connection *conn, int event_type)
{
	if (event_type & SUB_RETRY_RECV)
		fd_stop_recv(conn->handle.fd);

	if (event_type & SUB_RETRY_SEND)
		fd_stop_send(conn->handle.fd);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
