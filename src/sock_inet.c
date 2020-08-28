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

#include <string.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/tcp.h>
#include <netinet/in.h>

#include <haproxy/api.h>
#include <haproxy/sock_inet.h>
#include <haproxy/tools.h>


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
		if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, sa, &salen) == 0)
			return 0;
#endif
		return ret;
	}
}

/* Returns true if the passed FD corresponds to a socket bound with LI_O_FOREIGN
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
		if (getsockopt(fd, SOL_IP, IP_TRANSPARENT, &val, &len) == 0 && val)
			return 1;
#endif
#if defined(IP_FREEBIND)
		val = 0; len = sizeof(val);
		if (getsockopt(fd, SOL_IP, IP_FREEBIND, &val, &len) == 0 && val)
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
#if defined(IPV6_TRANSPARENT) && defined(SOL_IPV6)
		val = 0; len = sizeof(val);
		if (getsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &val, &len) == 0 && val)
			return 1;
#endif
#if defined(IP_FREEBIND)
		val = 0; len = sizeof(val);
		if (getsockopt(fd, SOL_IP, IP_FREEBIND, &val, &len) == 0 && val)
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
