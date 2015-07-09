/*
 * include/types/arg.h
 * This file contains structure declarations for generaic argument parsing.
 *
 * Copyright 2012 Willy Tarreau <w@1wt.eu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _TYPES_ARG_H
#define _TYPES_ARG_H

#include <sys/socket.h>
#include <netinet/in.h>

#include <common/chunk.h>
#include <common/mini-clist.h>

#include <types/vars.h>

/* encoding of each arg type : up to 31 types are supported */
#define ARGT_BITS      5
#define ARGT_NBTYPES   (1 << ARGT_BITS)
#define ARGT_MASK      (ARGT_NBTYPES - 1)

/* encoding of the arg count : up to 5 args are possible. 4 bits are left
 * unused at the top.
 */
#define ARGM_MASK      ((1 << ARGM_BITS) - 1)
#define ARGM_BITS      3
#define ARGM_NBARGS    (32 - ARGM_BITS) / sizeof(int)

enum {
	ARGT_STOP = 0, /* end of the arg list */
	ARGT_UINT,     /* unsigned integer, which is a positive integer without any sign */
	ARGT_SINT,     /* signed integer, the sign (+/-) was explicit. Falls back to UINT if no sign. */
	ARGT_STR,      /* string */
	ARGT_IPV4,     /* an IPv4 address */
	ARGT_MSK4,     /* an IPv4 address mask (integer or dotted), stored as ARGT_IPV4 */
	ARGT_IPV6,     /* an IPv6 address */
	ARGT_MSK6,     /* an IPv6 address mask (integer or dotted), stored as ARGT_IPV4 */
	ARGT_TIME,     /* a delay in ms by default, stored as ARGT_UINT */
	ARGT_SIZE,     /* a size in bytes by default, stored as ARGT_UINT */
	ARGT_FE,       /* a pointer to a frontend only */
	ARGT_BE,       /* a pointer to a backend only */
	ARGT_TAB,      /* a pointer to a stick table */
	ARGT_SRV,      /* a pointer to a server */
	ARGT_USR,      /* a pointer to a user list */
	ARGT_MAP,      /* a pointer to a map descriptor */
	ARGT_REG,      /* a pointer to a regex */
	ARGT_VAR,      /* contains a variable description. */
};

/* context where arguments are used, in order to help error reporting */
enum {
	ARGC_ACL = 0,  /* ACL */
	ARGC_STK,      /* sticking rule */
	ARGC_TRK,      /* tracking rule */
	ARGC_LOG,      /* log-format */
	ARGC_HRQ,      /* http-request */
	ARGC_HRS,      /* http-response */
	ARGC_UIF,      /* unique-id-format */
	ARGC_RDR,      /* redirect */
	ARGC_CAP,      /* capture rule */
	ARGC_SRV,      /* server line */
};

/* flags used when compiling and executing regex */
#define ARGF_REG_ICASE 1
#define ARGF_REG_GLOB  2

/* some types that are externally defined */
struct proxy;
struct server;
struct userlist;
struct my_regex;

union arg_data {
	unsigned int uint; /* used for uint, time, size */
	int sint;
	struct chunk str;
	struct in_addr ipv4;
	struct in6_addr ipv6;
	struct proxy *prx; /* used for fe, be, tables */
	struct server *srv;
	struct userlist *usr;
	struct map_descriptor *map;
	struct my_regex *reg;
	struct var_desc var;
};

struct arg {
	unsigned char type;       /* argument type, ARGT_* */
	unsigned char unresolved; /* argument contains a string in <str> that must be resolved and freed */
	unsigned char type_flags; /* type-specific extra flags (eg: case sensitivity for regex), ARGF_* */
	union arg_data data;      /* argument data */
};

/* arg lists are used to store information about arguments that could not be
 * resolved when parsing the configuration. The head is an arg_list which
 * serves as a template to create new entries. Nothing here is allocated,
 * so plain copies are OK.
 */
struct arg_list {
	struct list list;         /* chaining with other arg_list, or list head */
	struct arg *arg;          /* pointer to the arg, NULL on list head */
	int arg_pos;              /* argument position */
	int ctx;                  /* context where the arg is used (ARGC_*) */
	const char *kw;           /* keyword making use of these args */
	const char *conv;         /* conv keyword when in conv, otherwise NULL */
	const char *file;         /* file name where the args are referenced */
	int line;                 /* line number where the args are referenced */
};

#endif /* _TYPES_ARG_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
