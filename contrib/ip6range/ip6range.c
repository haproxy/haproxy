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

static inline void in6_bswap(struct in6_addr *a)
{
	a->in6_u.u6_addr32[0] = ntohl(a->in6_u.u6_addr32[0]);
	a->in6_u.u6_addr32[1] = ntohl(a->in6_u.u6_addr32[1]);
	a->in6_u.u6_addr32[2] = ntohl(a->in6_u.u6_addr32[2]);
	a->in6_u.u6_addr32[3] = ntohl(a->in6_u.u6_addr32[3]);
}

/* returns a string version of an IPv6 address in host order */
static const char *get_ipv6_addr(struct in6_addr *addr)
{
	struct in6_addr a;
	static char out[INET6_ADDRSTRLEN + 1];

	memcpy(&a, addr, sizeof(struct in6_addr));
	in6_bswap(&a);
	return inet_ntop(AF_INET6, &a, out, INET6_ADDRSTRLEN + 1);
}

static const char *get_addr(struct in6_addr *addr)
{
	static char out[50];
	snprintf(out, 50, "%08x:%08x:%08x:%08x",
	         addr->in6_u.u6_addr32[0],
	         addr->in6_u.u6_addr32[1],
	         addr->in6_u.u6_addr32[2],
	         addr->in6_u.u6_addr32[3]);
	return out;
}

/* a <= b */
static inline int a_le_b(struct in6_addr *a, struct in6_addr *b)
{
	if (a->in6_u.u6_addr32[0] < b->in6_u.u6_addr32[0]) return 1;
	if (a->in6_u.u6_addr32[0] > b->in6_u.u6_addr32[0]) return 0;
	if (a->in6_u.u6_addr32[1] < b->in6_u.u6_addr32[1]) return 1;
	if (a->in6_u.u6_addr32[1] > b->in6_u.u6_addr32[1]) return 0;
	if (a->in6_u.u6_addr32[2] < b->in6_u.u6_addr32[2]) return 1;
	if (a->in6_u.u6_addr32[2] > b->in6_u.u6_addr32[2]) return 0;
	if (a->in6_u.u6_addr32[3] < b->in6_u.u6_addr32[3]) return 1;
	if (a->in6_u.u6_addr32[3] > b->in6_u.u6_addr32[3]) return 0;
	return 1;
}

/* a == b */
static inline int a_eq_b(struct in6_addr *a, struct in6_addr *b)
{
	if (a->in6_u.u6_addr32[0] != b->in6_u.u6_addr32[0]) return 0;
	if (a->in6_u.u6_addr32[1] != b->in6_u.u6_addr32[1]) return 0;
	if (a->in6_u.u6_addr32[2] != b->in6_u.u6_addr32[2]) return 0;
	if (a->in6_u.u6_addr32[3] != b->in6_u.u6_addr32[3]) return 0;
	return 1;
}

/* a > b */
static inline int a_gt_b(struct in6_addr *a, struct in6_addr *b)
{
	if (a->in6_u.u6_addr32[0] > b->in6_u.u6_addr32[0]) return 1;
	if (a->in6_u.u6_addr32[0] < b->in6_u.u6_addr32[0]) return 0;
	if (a->in6_u.u6_addr32[1] > b->in6_u.u6_addr32[1]) return 1;
	if (a->in6_u.u6_addr32[1] < b->in6_u.u6_addr32[1]) return 0;
	if (a->in6_u.u6_addr32[2] > b->in6_u.u6_addr32[2]) return 1;
	if (a->in6_u.u6_addr32[2] < b->in6_u.u6_addr32[2]) return 0;
	if (a->in6_u.u6_addr32[3] > b->in6_u.u6_addr32[3]) return 1;
	if (a->in6_u.u6_addr32[3] < b->in6_u.u6_addr32[3]) return 0;
	return 0;
}

/* ( 1 << m ) - 1 -> r */
static inline struct in6_addr *hmask(unsigned int b, struct in6_addr *r)
{

	if (b < 32) {
		r->in6_u.u6_addr32[3] = (1 << b) - 1;
		r->in6_u.u6_addr32[2] = 0;
		r->in6_u.u6_addr32[1] = 0;
		r->in6_u.u6_addr32[0] = 0;
	}
	else if (b < 64) {
		r->in6_u.u6_addr32[3] = 0xffffffff;
		r->in6_u.u6_addr32[2] = (1 << (b - 32)) - 1;
		r->in6_u.u6_addr32[1] = 0;
		r->in6_u.u6_addr32[0] = 0;
	}
	else if (b < 96) {
		r->in6_u.u6_addr32[3] = 0xffffffff;
		r->in6_u.u6_addr32[2] = 0xffffffff;
		r->in6_u.u6_addr32[1] = (1 << (b - 64)) - 1;
		r->in6_u.u6_addr32[0] = 0;
	}
	else if (b < 128) {
		r->in6_u.u6_addr32[3] = 0xffffffff;
		r->in6_u.u6_addr32[2] = 0xffffffff;
		r->in6_u.u6_addr32[1] = 0xffffffff;
		r->in6_u.u6_addr32[0] = (1 << (b - 96)) - 1;
	}
	else {
		r->in6_u.u6_addr32[3] = 0xffffffff;
		r->in6_u.u6_addr32[2] = 0xffffffff;
		r->in6_u.u6_addr32[1] = 0xffffffff;
		r->in6_u.u6_addr32[0] = 0xffffffff;
	}
	return r;
}

/* 1 << b -> r */
static inline struct in6_addr *one_ls_b(unsigned int b, struct in6_addr *r)
{
	if (b < 32) {
		r->in6_u.u6_addr32[3] = 1 << b;
		r->in6_u.u6_addr32[2] = 0;
		r->in6_u.u6_addr32[1] = 0;
		r->in6_u.u6_addr32[0] = 0;
	}
	else if (b < 64) {
		r->in6_u.u6_addr32[3] = 0;
		r->in6_u.u6_addr32[2] = 1 << (b - 32);
		r->in6_u.u6_addr32[1] = 0;
		r->in6_u.u6_addr32[0] = 0;
	}
	else if (b < 96) {
		r->in6_u.u6_addr32[3] = 0;
		r->in6_u.u6_addr32[2] = 0;
		r->in6_u.u6_addr32[1] = 1 << (b - 64);
		r->in6_u.u6_addr32[0] = 0;
	}
	else if (b < 128) {
		r->in6_u.u6_addr32[3] = 0;
		r->in6_u.u6_addr32[2] = 0;
		r->in6_u.u6_addr32[1] = 0;
		r->in6_u.u6_addr32[0] = 1 << (b - 96);
	}
	else {
		r->in6_u.u6_addr32[3] = 0;
		r->in6_u.u6_addr32[2] = 0;
		r->in6_u.u6_addr32[1] = 0;
		r->in6_u.u6_addr32[0] = 0;
	}
	return r;
}

/* a + b -> r */
static inline struct in6_addr *a_plus_b(struct in6_addr *a, struct in6_addr *b, struct in6_addr *r)
{
	unsigned long long int c = 0;
	int i;

	for (i=3; i>=0; i--) {
		c = (unsigned long long int)a->in6_u.u6_addr32[i] +
		    (unsigned long long int)b->in6_u.u6_addr32[i] + c;
		r->in6_u.u6_addr32[i] = c;
		c >>= 32;
	}

	return r;
}

/* a - b -> r */
static inline struct in6_addr *a_minus_b(struct in6_addr *a, struct in6_addr *b, struct in6_addr *r)
{
	signed long long int c = 0;
	signed long long int d;
	int i;

	/* Check sign. Return 0xff..ff (-1) if the result is less than 0. */
	if (a_gt_b(b, a)) {
		r->in6_u.u6_addr32[3] = 0xffffffff;
		r->in6_u.u6_addr32[2] = 0xffffffff;
		r->in6_u.u6_addr32[1] = 0xffffffff;
		r->in6_u.u6_addr32[0] = 0xffffffff;
		return r;
	}

	for (i=3; i>=0; i--) {
		d = (unsigned long long int)b->in6_u.u6_addr32[i] + c;
		c = (unsigned long long int)a->in6_u.u6_addr32[i];
		if (c < d)
			c += 0x100000000ULL;
		c -= d;
		r->in6_u.u6_addr32[i] = c;
		c >>= 32;
	}

	return r;
}

/* a & b -> r */
static inline struct in6_addr *a_and_b(struct in6_addr *a, struct in6_addr *b, struct in6_addr *r)
{
	r->in6_u.u6_addr32[0] = a->in6_u.u6_addr32[0] & b->in6_u.u6_addr32[0];
	r->in6_u.u6_addr32[1] = a->in6_u.u6_addr32[1] & b->in6_u.u6_addr32[1];
	r->in6_u.u6_addr32[2] = a->in6_u.u6_addr32[2] & b->in6_u.u6_addr32[2];
	r->in6_u.u6_addr32[3] = a->in6_u.u6_addr32[3] & b->in6_u.u6_addr32[3];
	return r;
}

/* a != 0 */
int is_set(struct in6_addr *a)
{
	return a->in6_u.u6_addr32[0] ||
	       a->in6_u.u6_addr32[1] ||
	       a->in6_u.u6_addr32[2] ||
	       a->in6_u.u6_addr32[3];
}

/* 1 */
static struct in6_addr one = { .in6_u.u6_addr32 = {0, 0, 0, 1} };

/* print all networks present between address <low> and address <high> in
 * cidr format, followed by <eol>.
 */
static void convert_range(struct in6_addr *low, struct in6_addr *high, const char *eol, const char *pfx)
{
	int bit;
	struct in6_addr r0;
	struct in6_addr r1;

	if (a_eq_b(low, high)) {
		/* single value */
		printf("%s%s%s%s\n", pfx?pfx:"", pfx?" ":"", get_ipv6_addr(low), eol);
		return;
	}
	else if (a_gt_b(low, high)) {
		struct in6_addr *swap = low;
		low = high;
		high = swap;
	}

	if (a_eq_b(low, a_plus_b(high, &one, &r0))) {
		/* full range */
		printf("%s%s::/0%s\n", pfx?pfx:"", pfx?" ":"", eol);
		return;
	}
	//printf("low=%08x high=%08x\n", low, high);

	bit = 0;
	while (bit < 128 && a_le_b(a_plus_b(low, hmask(bit, &r0), &r0), high)) {

		/* enlarge mask */
		if (is_set(a_and_b(low, one_ls_b(bit, &r0), &r0))) {
			/* can't aggregate anymore, dump and retry from the same bit */
			printf("%s%s%s/%d%s\n", pfx?pfx:"", pfx?" ":"", get_ipv6_addr(low), 128-bit, eol);
			a_plus_b(low, one_ls_b(bit, &r0), low);
		}
		else {
			/* try to enlarge the mask as much as possible first */
			bit++;
			//printf("  ++bit=%d\n", bit);
		}
	}
	//printf("stopped 1 at low=%08x, bit=%d\n", low, bit);

	bit = 127;
	while (bit >= 0 && is_set(a_plus_b(a_minus_b(high, low, &r0), &one, &r0))) {

		/* shrink mask */
		if (is_set(a_and_b(a_plus_b(a_minus_b(high, low, &r0), &one, &r0), one_ls_b(bit, &r1), &r1))) {
			/* large bit accepted, dump and go on from the same bit */
			//printf("max: %08x/%d\n", low, 32-bit);
			printf("%s%s%s/%d%s\n", pfx?pfx:"", pfx?" ":"", get_ipv6_addr(low), 128-bit, eol);
			a_plus_b(low, one_ls_b(bit, &r0), low);
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

main(int argc, char **argv)
{
	char line[MAXLINE];
	int l, lnum;
	char *lb, *le, *hb, *he, *err;
	struct in6_addr sa, da, ta;

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

		if (inet_pton(AF_INET6, lb, &sa) <= 0) {
			fprintf(stderr, "Failed to parse source address <%s> at line %d, skipping line\n", lb, lnum);
			continue;
		}

		if (inet_pton(AF_INET6, hb, &da) <= 0) {
			fprintf(stderr, "Failed to parse destination address <%s> at line %d, skipping line\n", hb, lnum);
			continue;
		}

		in6_bswap(&sa);
		in6_bswap(&da);

		if (argc > 1) {
			for (l = 1; l < argc; l++) {
				if (inet_pton(AF_INET6, argv[l], &da) <= 0)
					continue;
				in6_bswap(&ta);
				if ((a_le_b(&sa, &ta) && a_le_b(&ta, &da)) || (a_le_b(&da, &ta) && a_le_b(&ta, &sa)))
					convert_range(&sa, &da, he, argv[l]);
			}
		}
		else {
			convert_range(&sa, &da, he, NULL);
		}
	}
}
