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

/* DEFNULL() returns either the argument as-is, or NULL if absent. This is for
 * use in macros arguments.
 */
#define DEFNULL(...) _FIRST_ARG(NULL, ##__VA_ARGS__, NULL)
#define _FIRST_ARG(a, b, ...) b

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

#endif /* _HAPROXY_TOOLS_T_H */
