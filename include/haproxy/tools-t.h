/*
 * include/haproxy/tools-t.h
 * This files contains some general purpose macros and structures.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_TOOLS_T_H
#define _HAPROXY_TOOLS_T_H

#include <netinet/in.h>
#include <import/cebtree.h>

/* size used for max length of decimal representation of long long int. */
#define NB_LLMAX_STR (sizeof("-9223372036854775807")-1)

/* number of itoa_str entries */
#define NB_ITOA_STR	16

/* maximum quoted string length (truncated above) */
#define QSTR_SIZE 200
#define NB_QSTR 10

/* returns 1 only if only zero or one bit is set in X, which means that X is a
 * power of 2, and 0 otherwise */
#define POWEROF2(x) (((x) & ((x)-1)) == 0)

/* return an integer of type <ret> with only the highest bit set. <ret> may be
 * both a variable or a type.
 */
#define MID_RANGE(ret) ((typeof(ret))1 << (8*sizeof(ret) - 1))

/* return the largest possible integer of type <ret>, with all bits set */
#define MAX_RANGE(ret) (~(typeof(ret))0)

/* DEFVAL() returns either the second argument as-is, or <def> if absent. This
 * is for use in macros arguments.
 */
#define DEFVAL(_def,...) _FIRST_ARG(NULL, ##__VA_ARGS__, (_def))

/* DEFNULL() returns either the argument as-is, or NULL if absent. This is for
 * use in macros arguments.
 */
#define DEFNULL(...) DEFVAL(NULL, ##__VA_ARGS__)

/* DEFZERO() returns either the argument as-is, or 0 if absent. This is for
 * use in macros arguments.
 */
#define DEFZERO(...) DEFVAL(0, ##__VA_ARGS__)

#define _FIRST_ARG(a, b, ...) b

/* options flags for parse_line() */
#define PARSE_OPT_SHARP         0x00000001      // '#' ends the line
#define PARSE_OPT_BKSLASH       0x00000002      // '\' escapes chars
#define PARSE_OPT_SQUOTE        0x00000004      // "'" encloses a string
#define PARSE_OPT_DQUOTE        0x00000008      // '"' encloses a string
#define PARSE_OPT_ENV           0x00000010      // '$' is followed by environment variables
#define PARSE_OPT_INPLACE       0x00000020      // parse and tokenize in-place (src == dst)
#define PARSE_OPT_WORD_EXPAND   0x00000040      // '[*]' suffix to expand an environment variable as several individual arguments

/* return error flags from parse_line() */
#define PARSE_ERR_TOOLARGE      0x00000001      // result is too large for initial outlen
#define PARSE_ERR_TOOMANY       0x00000002      // more words than initial nbargs
#define PARSE_ERR_QUOTE         0x00000004      // unmatched quote (offending one at errptr)
#define PARSE_ERR_BRACE         0x00000008      // unmatched brace (offending one at errptr)
#define PARSE_ERR_HEX           0x00000010      // unparsable hex sequence (at errptr)
#define PARSE_ERR_VARNAME       0x00000020      // invalid variable name (at errptr)
#define PARSE_ERR_OVERLAP       0x00000040      // output overlaps with input, need to allocate
#define PARSE_ERR_WRONG_EXPAND  0x00000080      // unparsable word expansion sequence

/* special return values for the time parser (parse_time_err()) */
#define PARSE_TIME_UNDER ((char *)1)
#define PARSE_TIME_OVER  ((char *)2)

/* unit flags to pass to parse_time_err() */
#define TIME_UNIT_US   0x0000
#define TIME_UNIT_MS   0x0001
#define TIME_UNIT_S    0x0002
#define TIME_UNIT_MIN  0x0003
#define TIME_UNIT_HOUR 0x0004
#define TIME_UNIT_DAY  0x0005
#define TIME_UNIT_MASK 0x0007

#define SEC 1
#define MINUTE (60 * SEC)
#define HOUR (60 * MINUTE)
#define DAY (24 * HOUR)

/* Address parsing options for use with str2sa_range() */
#define PA_O_RESOLVE            0x00000001   /* do resolve the FQDN to an IP address */
#define PA_O_PORT_OK            0x00000002   /* ports are supported */
#define PA_O_PORT_MAND          0x00000004   /* ports are mandatory */
#define PA_O_PORT_RANGE         0x00000008   /* port ranges are supported */
#define PA_O_PORT_OFS           0x00000010   /* port offsets are supported */
#define PA_O_SOCKET_FD          0x00000020   /* inherited socket FDs are supported */
#define PA_O_RAW_FD             0x00000040   /* inherited raw FDs are supported (pipes, ttys, ...) */
#define PA_O_DGRAM              0x00000080   /* the address can be used for a datagram socket (in or out) */
#define PA_O_STREAM             0x00000100   /* the address can be used for streams (in or out) */
#define PA_O_XPRT               0x00000200   /* transport protocols may be specified */
#define PA_O_CONNECT            0x00000400   /* the protocol must have a ->connect method */
#define PA_O_DEFAULT_DGRAM      0x00000800   /* by default, this address will be used for a datagram socket */

/* UTF-8 decoder status */
#define UTF8_CODE_OK       0x00
#define UTF8_CODE_OVERLONG 0x10
#define UTF8_CODE_INVRANGE 0x20
#define UTF8_CODE_BADSEQ   0x40

/* HAP_STRING() makes a string from a literal while HAP_XSTRING() first
 * evaluates the argument and is suited to pass macros.
 *
 * They allow macros like PCRE_MAJOR to be defined without quotes, which
 * is convenient for applications that want to test its value.
 */
#define HAP_STRING(...) #__VA_ARGS__
#define HAP_XSTRING(...) HAP_STRING(__VA_ARGS__)

/* operators to compare values. They're ordered that way so that the lowest bit
 * serves as a negation for the test and contains all tests that are not equal.
 */
enum {
	STD_OP_LE = 0, STD_OP_GT = 1,
	STD_OP_EQ = 2, STD_OP_NE = 3,
	STD_OP_GE = 4, STD_OP_LT = 5,
};

enum http_scheme {
	SCH_HTTP,
	SCH_HTTPS,
};

/* output format used by url2sa() */
struct split_url {
	enum http_scheme scheme;
	const char *host;
	int host_len;
};

/* generic structure associating a name and a value, for use in arrays */
struct name_desc {
	const char *name;
	const char *desc;
};

struct net_addr {
	int family; /* AF_INET or AF_INET6 if defined, AF_UNSET if undefined */
	union {
		struct {
			struct in_addr ip;
			struct in_addr mask;
		} v4;
		struct {
			struct in6_addr ip;
			struct in6_addr mask;
		} v6;
	} addr;
};

/* holds socket and xprt types for a given address */
struct net_addr_type {
	int proto_type; // socket layer
	int xprt_type;  // transport layer
};

/* To easily pass context to cbor encode functions
 */
struct cbor_encode_ctx {
	/* function pointer that cbor encode functions will use to encode a
	 * single byte.
	 *
	 * The function needs to return the position of the last written byte
	 * on success and NULL on failure. The function cannot write past <stop>
	 */
	char *(*e_fct_byte)(struct cbor_encode_ctx *ctx,
	                    char *start, char *stop, uint8_t byte);

	/* to provide some user-context to the encode_fct_* funcs */
	void *e_fct_ctx;
};

/* An indexed file name node, to be used at various places where a config file
 * location is expected. These elements live forever and are only released on
 * deinit. The goal is to use them in place of a regular "char* file" in many
 * structures so that they can remain referenced without being strduped nor
 * refcounted. Refcounts might appear in the future. The root is file_names in
 * tools.c.
 */
struct file_name_node {
	struct ceb_node node; /* indexing node */
	char name[VAR_ARRAY]; /* storage, used with cebus_*() */
};

#endif /* _HAPROXY_TOOLS_T_H */
