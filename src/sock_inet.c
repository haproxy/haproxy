/*
 * AF_INET/AF_INET6 socket management
 *
 * Copyright 2000-2020 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/tcp.h>
#include <netinet/in.h>

#include <haproxy/api.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/namespace.h>
#include <haproxy/receiver-t.h>
#include <haproxy/sock.h>
#include <haproxy/sock_inet.h>
#include <haproxy/tools.h>

struct proto_fam proto_fam_inet4 = {
	.name = "inet4",
	.sock_domain = PF_INET,
	.sock_family = AF_INET,
	.sock_addrlen = sizeof(struct sockaddr_in),
	.l3_addrlen = 32/8,
	.addrcmp = sock_inet4_addrcmp,
	.bind = sock_inet_bind_receiver,
	.get_src = sock_get_src,
	.get_dst = sock_inet_get_dst,
	.set_port = sock_inet_set_port,
};

struct proto_fam proto_fam_inet6 = {
	.name = "inet6",
	.sock_domain = PF_INET6,
	.sock_family = AF_INET6,
	.sock_addrlen = sizeof(struct sockaddr_in6),
	.l3_addrlen = 128/8,
	.addrcmp = sock_inet6_addrcmp,
	.bind = sock_inet_bind_receiver,
	.get_src = sock_get_src,
	.get_dst = sock_get_dst,
	.set_port = sock_inet_set_port,
};

/* PLEASE NOTE for function below:
 *   - sock_inet4_* is solely for AF_INET (IPv4)
 *   - sock_inet6_* is solely for AF_INET6 (IPv6)
 *   - sock_inet_*  is for either
 *
 * The address family SHOULD always be checked. In some cases a function will
 * be used in a situation where the address family is guaranteed (e.g. protocol
 * definitions), so the test may be avoided. This special case must then be
 * mentioned in the comment before the function definition.
 */

/* determine if the operating system uses IPV6_V6ONLY by default. 0=no, 1=yes.
 * It also remains if IPv6 is not enabled/configured.
 */
int sock_inet6_v6only_default = 0;

/* Default TCPv4/TCPv6 MSS settings. -1=unknown. */
int sock_inet_tcp_maxseg_default = -1;
int sock_inet6_tcp_maxseg_default = -1;

/* Compares two AF_INET sockaddr addresses. Returns 0 if they match or non-zero
 * if they do not match.
 */
int sock_inet4_addrcmp(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
	const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
	const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;

	if (a->ss_family != b->ss_family)
		return -1;

	if (a->ss_family != AF_INET)
		return -1;

	if (a4->sin_port != b4->sin_port)
		return -1;

	return memcmp(&a4->sin_addr, &b4->sin_addr, sizeof(a4->sin_addr));
}

/* Compares two AF_INET6 sockaddr addresses. Returns 0 if they match or
 * non-zero if they do not match.
 */
int sock_inet6_addrcmp(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
	const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
	const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;

	if (a->ss_family != b->ss_family)
		return -1;

	if (a->ss_family != AF_INET6)
		return -1;

	if (a6->sin6_port != b6->sin6_port)
		return -1;

	return memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr));
}

/* Sets the port <port> on IPv4 or IPv6 address <addr>. The address family is
 * determined from the sockaddr_storage's address family. Nothing is done for
 * other families.
 */
void sock_inet_set_port(struct sockaddr_storage *addr, int port)
{
	if (addr->ss_family == AF_INET)
		((struct sockaddr_in *)addr)->sin_port = htons(port);
	else if (addr->ss_family == AF_INET6)
		((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
}

/*
 * Retrieves the original destination address for the socket <fd> which must be
 * of family AF_INET (not AF_INET6), with <dir> indicating if we're a listener
 * (=0) or an initiator (!=0). In the case of a listener, if the original
 * destination address was translated, the original address is retrieved. It
 * returns 0 in case of success, -1 in case of error. The socket's source
 * address is stored in <sa> for <salen> bytes.
 */
int sock_inet_get_dst(int fd, struct sockaddr *sa, socklen_t salen, int dir)
{
	if (dir)
		return getpeername(fd, sa, &salen);
	else {
		int ret = getsockname(fd, sa, &salen);

		if (ret < 0)
			return ret;

#if defined(USE_TPROXY) && defined(SO_ORIGINAL_DST)
		/* For TPROXY and Netfilter's NAT, we can retrieve the original
		 * IPv4 address before DNAT/REDIRECT. We must not do that with
		 * other families because v6-mapped IPv4 addresses are still
		 * reported as v4.
		 */
		if (getsockopt(fd, IPPROTO_IP, SO_ORIGINAL_DST, sa, &salen) == 0)
			return 0;
#endif
		return ret;
	}
}

/* Returns true if the passed FD corresponds to a socket bound with RX_O_FOREIGN
 * according to the various supported socket options. The socket's address family
 * must be passed in <family>.
 */
int sock_inet_is_foreign(int fd, sa_family_t family)
{
	int val __maybe_unused;
	socklen_t len __maybe_unused;

	switch (family) {
	case AF_INET:
#if defined(IP_TRANSPARENT)
		val = 0; len = sizeof(val);
		if (getsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, &val, &len) == 0 && val)
			return 1;
#endif
#if defined(IP_FREEBIND)
		val = 0; len = sizeof(val);
		if (getsockopt(fd, IPPROTO_IP, IP_FREEBIND, &val, &len) == 0 && val)
			return 1;
#endif
#if defined(IP_BINDANY)
		val = 0; len = sizeof(val);
		if (getsockopt(fd, IPPROTO_IP, IP_BINDANY, &val, &len) == 0 && val)
			return 1;
#endif
#if defined(SO_BINDANY)
		val = 0; len = sizeof(val);
		if (getsockopt(fd, SOL_SOCKET, SO_BINDANY, &val, &len) == 0 && val)
			return 1;
#endif
		break;

	case AF_INET6:
#if defined(IPV6_TRANSPARENT)
		val = 0; len = sizeof(val);
		if (getsockopt(fd, IPPROTO_IPV6, IPV6_TRANSPARENT, &val, &len) == 0 && val)
			return 1;
#endif
#if defined(IP_FREEBIND)
		val = 0; len = sizeof(val);
		if (getsockopt(fd, IPPROTO_IP, IP_FREEBIND, &val, &len) == 0 && val)
			return 1;
#endif
#if defined(IPV6_BINDANY)
		val = 0; len = sizeof(val);
		if (getsockopt(fd, IPPROTO_IPV6, IPV6_BINDANY, &val, &len) == 0 && val)
			return 1;
#endif
#if defined(SO_BINDANY)
		val = 0; len = sizeof(val);
		if (getsockopt(fd, SOL_SOCKET, SO_BINDANY, &val, &len) == 0 && val)
			return 1;
#endif
		break;
	}
	return 0;
}

/* Attempt all known socket options to prepare an AF_INET4 socket to be bound
 * to a foreign address. The socket must already exist and must not be bound.
 * 1 is returned on success, 0 on failure. The caller must check the address
 * family before calling this function.
 */
int sock_inet4_make_foreign(int fd)
{
	return
#if defined(IP_TRANSPARENT)
		setsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, &one, sizeof(one)) == 0 ||
#endif
#if defined(IP_FREEBIND)
		setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one)) == 0 ||
#endif
#if defined(IP_BINDANY)
		setsockopt(fd, IPPROTO_IP, IP_BINDANY, &one, sizeof(one)) == 0 ||
#endif
#if defined(SO_BINDANY)
		setsockopt(fd, SOL_SOCKET, SO_BINDANY, &one, sizeof(one)) == 0 ||
#endif
		0;
}

/* Attempt all known socket options to prepare an AF_INET6 socket to be bound
 * to a foreign address. The socket must already exist and must not be bound.
 * 1 is returned on success, 0 on failure. The caller must check the address
 * family before calling this function.
 */
int sock_inet6_make_foreign(int fd)
{
	return
#if defined(IPV6_TRANSPARENT)
		setsockopt(fd, IPPROTO_IPV6, IPV6_TRANSPARENT, &one, sizeof(one)) == 0 ||
#endif
#if defined(IP_FREEBIND)
		setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one)) == 0 ||
#endif
#if defined(IPV6_BINDANY)
		setsockopt(fd, IPPROTO_IPV6, IPV6_BINDANY, &one, sizeof(one)) == 0 ||
#endif
#if defined(SO_BINDANY)
		setsockopt(fd, SOL_SOCKET, SO_BINDANY, &one, sizeof(one)) == 0 ||
#endif
		0;
}

/* Binds receiver <rx>, and assigns rx->iocb and rx->owner as the callback and
 * context, respectively. Returns and error code made of ERR_* bits on failure
 * or ERR_NONE on success. On failure, an error message may be passed into
 * <errmsg>.
 */
int sock_inet_bind_receiver(struct receiver *rx, char **errmsg)
{
	int fd, err, ext;
	/* copy listener addr because sometimes we need to switch family */
	struct sockaddr_storage addr_inet = rx->addr;

	/* force to classic sock family, not AF_CUST_* */
	addr_inet.ss_family = rx->proto->fam->sock_family;

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

	/* if the receiver now has an fd assigned, then we were offered the fd
	 * by an external process (most likely the parent), and we don't want
	 * to create a new socket. However we still want to set a few flags on
	 * the socket.
	 */
	fd = rx->fd;
	ext = (fd >= 0);

	if (!ext) {
		fd = my_socketat(rx->settings->netns, rx->proto->fam->sock_domain,
		                 rx->proto->sock_type, rx->proto->sock_prot);
		if (fd == -1) {
			err |= ERR_RETRYABLE | ERR_ALERT;
			memprintf(errmsg, "cannot create receiving socket (%s)", strerror(errno));
			goto bind_return;
		}
	}

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

	if (!ext && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1) {
		/* not fatal but should be reported */
		memprintf(errmsg, "cannot do so_reuseaddr");
		err |= ERR_ALERT;
	}

#ifdef SO_REUSEPORT
	/* OpenBSD and Linux 3.9 support this. As it's present in old libc versions of
	 * Linux, it might return an error that we will silently ignore.
	 */
	if (!ext && (global.tune.options & GTUNE_USE_REUSEPORT))
		setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif

	if (!ext && (rx->settings->options & RX_O_FOREIGN)) {
		switch (addr_inet.ss_family) {
		case AF_INET:
			if (!sock_inet4_make_foreign(fd)) {
				memprintf(errmsg, "cannot make receiving socket transparent");
				err |= ERR_ALERT;
			}
		break;
		case AF_INET6:
			if (!sock_inet6_make_foreign(fd)) {
				memprintf(errmsg, "cannot make receiving socket transparent");
				err |= ERR_ALERT;
			}
		break;
		}
	}

#ifdef SO_BINDTODEVICE
	/* Note: this might fail if not CAP_NET_RAW */
	if (!ext && rx->settings->interface) {
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
		               rx->settings->interface,
		               strlen(rx->settings->interface) + 1) == -1) {
			memprintf(errmsg, "cannot bind receiver to device (%s)", strerror(errno));
			err |= ERR_WARN;
		}
	}
#endif

#if defined(IPV6_V6ONLY)
	if (addr_inet.ss_family == AF_INET6 && !ext) {
		/* Prepare to match the v6only option against what we really want. Note
		 * that sadly the two options are not exclusive to each other and that
		 * v6only is stronger than v4v6.
		 */
		if ((rx->settings->options & RX_O_V6ONLY) ||
		    (sock_inet6_v6only_default && !(rx->settings->options & RX_O_V4V6)))
			setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
		else
			setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
	}
#endif

	if (!ext && bind(fd, (struct sockaddr *)&addr_inet, rx->proto->fam->sock_addrlen) == -1) {
		err |= ERR_RETRYABLE | ERR_ALERT;
		memprintf(errmsg, "cannot bind socket (%s)", strerror(errno));
		goto bind_close_return;
	}

	rx->fd = fd;
	rx->flags |= RX_F_BOUND;

	fd_insert(fd, rx->owner, rx->iocb, thread_mask(rx->settings->bind_thread) & all_threads_mask);

	/* for now, all regularly bound TCP listeners are exportable */
	if (!(rx->flags & RX_F_INHERITED))
		HA_ATOMIC_OR(&fdtab[fd].state, FD_EXPORTED);

 bind_return:
	if (errmsg && *errmsg) {
		char pn[INET6_ADDRSTRLEN];

		addr_to_str(&addr_inet, pn, sizeof(pn));
		memprintf(errmsg, "%s [%s:%d]", *errmsg, pn, get_host_port(&addr_inet));
	}
	return err;

 bind_close_return:
	close(fd);
	goto bind_return;
}

static void sock_inet_prepare()
{
	int fd, val;
	socklen_t len;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd >= 0) {
#ifdef TCP_MAXSEG
		/* retrieve the OS' default mss for TCPv4 */
		len = sizeof(val);
		if (getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &val, &len) == 0)
			sock_inet_tcp_maxseg_default = val;
#endif
		close(fd);
	}

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd >= 0) {
#if defined(IPV6_V6ONLY)
		/* retrieve the OS' bindv6only value */
		len = sizeof(val);
		if (getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, &len) == 0 && val > 0)
			sock_inet6_v6only_default = 1;
#endif

#ifdef TCP_MAXSEG
		/* retrieve the OS' default mss for TCPv6 */
		len = sizeof(val);
		if (getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &val, &len) == 0)
			sock_inet6_tcp_maxseg_default = val;
#endif
		close(fd);
	}
}

INITCALL0(STG_PREPARE, sock_inet_prepare);


REGISTER_BUILD_OPTS("Built with transparent proxy support using:"
#if defined(IP_TRANSPARENT)
		    " IP_TRANSPARENT"
#endif
#if defined(IPV6_TRANSPARENT)
		    " IPV6_TRANSPARENT"
#endif
#if defined(IP_FREEBIND)
		    " IP_FREEBIND"
#endif
#if defined(IP_BINDANY)
		    " IP_BINDANY"
#endif
#if defined(IPV6_BINDANY)
		    " IPV6_BINDANY"
#endif
#if defined(SO_BINDANY)
		    " SO_BINDANY"
#endif
		    "");
