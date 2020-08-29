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
#include <string.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <haproxy/api.h>
#include <haproxy/listener.h>
#include <haproxy/namespace.h>
#include <haproxy/sock_unix.h>
#include <haproxy/tools.h>


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
