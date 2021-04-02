/*
 * network range to IP+mask converter
 *
 * Copyright 2011-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program reads lines starting by two IP addresses and outputs them with
 * the two IP addresses replaced by a netmask covering the range between these
 * IPs (inclusive). When multiple ranges are needed, as many lines are emitted.
 * The IP addresses may be delimited by spaces, tabs or commas. Quotes are
 * stripped, and lines beginning with a sharp character ('#') are ignored. The
 * IP addresses may be either in the dotted format or represented as a 32-bit
 * integer value in network byte order.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXLINE 1024

/* returns a string version of an IPv4 address in host order */
static const char *get_ipv4_addr(unsigned int addr)
{
	struct in_addr a;

	a.s_addr = ntohl(addr);
	return inet_ntoa(a);
}

/* print all networks present between address <low> and address <high> in
 * cidr format, followed by <eol>.
 */
static void convert_range(unsigned int low, unsigned int high, const char *eol, const char *pfx)
{
	int bit;

	if (low == high) {
		/* single value */
		printf("%s%s%s%s\n", pfx?pfx:"", pfx?" ":"", get_ipv4_addr(low), eol);
		return;
	}
	else if (low > high) {
		int swap = low;
		low = high;
		high = swap;
	}

	if (low == high + 1) {
		/* full range */
		printf("%s%s0.0.0.0/0%s\n", pfx?pfx:"", pfx?" ":"", eol);
		return;
	}
	//printf("low=%08x high=%08x\n", low, high);

	bit = 0;
	while (bit < 32 && low + (1 << bit) - 1 <= high) {
		/* enlarge mask */
		if (low & (1 << bit)) {
			/* can't aggregate anymore, dump and retry from the same bit */
			printf("%s%s%s/%d%s\n", pfx?pfx:"", pfx?" ":"", get_ipv4_addr(low), 32-bit, eol);
			low += (1 << bit);
		}
		else {
			/* try to enlarge the mask as much as possible first */
			bit++;
			//printf("  ++bit=%d\n", bit);
		}
	}
	//printf("stopped 1 at low=%08x, bit=%d\n", low, bit);

	bit = 31;
	while (bit >= 0 && high - low + 1 != 0) {
		/* shrink mask */
		if ((high - low + 1) & (1 << bit)) {
			/* large bit accepted, dump and go on from the same bit */
			//printf("max: %08x/%d\n", low, 32-bit);
			printf("%s%s%s/%d%s\n", pfx?pfx:"", pfx?" ":"", get_ipv4_addr(low), 32-bit, eol);
			low += (1 << bit);
		}
		else {
			bit--;
			//printf("  --bit=%d, low=%08x\n", bit, low);
		}
	}
	//printf("stopped at low=%08x\n", low);
}

static void usage(const char *argv0)
{
	fprintf(stderr,
	        "Usage: %s [<addr> ...] < iplist.csv\n"
	        "\n"
	        "This program reads lines starting by two IP addresses and outputs them with\n"
	        "the two IP addresses replaced by a netmask covering the range between these\n"
	        "IPs (inclusive). When multiple ranges are needed, as many lines are emitted.\n"
	        "The IP addresses may be delimited by spaces, tabs or commas. Quotes are\n"
	        "stripped, and lines beginning with a sharp character ('#') are ignored. The\n"
	        "IP addresses may be either in the dotted format or represented as a 32-bit\n"
	        "integer value in network byte order.\n"
		"\n"
		"For each optional <addr> specified, only the network it belongs to is returned,\n"
		"prefixed with the <addr> value.\n"
		"\n", argv0);
}

int main(int argc, char **argv)
{
	char line[MAXLINE];
	int l, lnum;
	char *lb, *le, *hb, *he, *err;
	struct in_addr src_addr, dst_addr;
	unsigned int sa, da, ta;

	if (argc > 1 && *argv[1] == '-') {
		usage(argv[0]);
		exit(1);
	}

	lnum = 0;
	while (fgets(line, sizeof(line), stdin) != NULL) {
		l = strlen(line);
		if (l && line[l - 1] == '\n')
			line[--l] = '\0';

		lnum++;
		/* look for the first field which must be the low address of a range,
		 * in dotted IPv4 format or as an integer. spaces and commas are
		 * considered as delimiters, quotes are removed.
		 */
		for (lb = line; *lb == ' ' || *lb == '\t' || *lb == ',' || *lb == '"'; lb++);
		if (!*lb || *lb == '#')
			continue;
		for (le = lb + 1; *le != ' ' && *le != '\t' && *le != ',' && *le != '"' && *le; le++);
		if (!*le)
			continue;
		/* we have the low address between lb(included) and le(excluded) */
		*(le++) = 0;

		for (hb = le; *hb == ' ' || *hb == '\t' || *hb == ',' || *hb == '"'; hb++);
		if (!*hb || *hb == '#')
			continue;
		for (he = hb + 1; *he != ' ' && *he != '\t' && *he != ',' && *he != '"' && *he; he++);
		if (!*he)
			continue;
		/* we have the high address between hb(included) and he(excluded) */
		*(he++) = 0;

		/* we want to remove a possible ending quote and a possible comma,
		 * not more.
		 */
		while (*he == '"')
			*(he++) = ' ';
		while (*he == ',' || *he == ' ' || *he == '\t')
			*(he++) = ' ';

		/* if the trailing string is not empty, prefix it with a space */
		if (*(he-1) == ' ')
			he--;

		if (inet_pton(AF_INET, lb, &src_addr) <= 0) {
			/* parsing failed, retry with a plain numeric IP */
			src_addr.s_addr = ntohl(strtoul(lb, &err, 10));
			if (err && *err) {
				fprintf(stderr, "Failed to parse source address <%s> at line %d, skipping line\n", lb, lnum);
				continue;
			}
		}

		if (inet_pton(AF_INET, hb, &dst_addr) <= 0) {
			/* parsing failed, retry with a plain numeric IP */
			dst_addr.s_addr = ntohl(strtoul(hb, &err, 10));
			if (err && *err) {
				fprintf(stderr, "Failed to parse destination address <%s> at line %d, skipping line\n", hb, lnum);
				continue;
			}
		}

		sa = htonl(src_addr.s_addr);
		da = htonl(dst_addr.s_addr);
		if (argc > 1) {
			for (l = 1; l < argc; l++) {
				if (inet_pton(AF_INET, argv[l], &dst_addr) <= 0)
					continue;
				ta = htonl(dst_addr.s_addr);
				if ((sa <= ta && ta <= da) || (da <= ta && ta <= sa))
					convert_range(sa, da, he, argv[l]);
			}
		}
		else {
			convert_range(sa, da, he, NULL);
		}
	}
	exit(0);
}
