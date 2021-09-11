/*
 * Dynamic server cookie calculator
 *
 * Copyright 2021 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <arpa/inet.h>

#include <haproxy/xxhash.h>

__attribute__((noreturn)) void die(int code, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	exit(code);
}

int main(int argc, char **argv)
{
	size_t key_len;
	int addr_len;
	char *buf;
	int port;

	if (argc < 4)
		die(1, "Usage: %s <key> <ip> <port>\n", argv[0]);

	key_len = strlen(argv[1]);
	buf = realloc(strdup(argv[1]), key_len + 16 + 4);
	if (!buf)
		die(2, "Not enough memory\n");

	if (inet_pton(AF_INET, argv[2], buf + key_len) > 0)
		addr_len = 4;
	else if (inet_pton(AF_INET6, argv[2], buf + key_len) > 0)
		addr_len = 16;
	else
		die(3, "Cannot parse address <%s> as IPv4/IPv6\n", argv[2]);

	port = htonl(atoi(argv[3]));
	memcpy(buf + key_len + addr_len, &port, 4);
	printf("%016llx\n", (long long)XXH64(buf, key_len + addr_len + 4, 0));
	return 0;
}
