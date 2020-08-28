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
