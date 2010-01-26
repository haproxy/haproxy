/*
 * include/types/pattern.h
 * Macros, variables and structures for patterns management.
 *
 * Copyright (C) 2009-2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
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

#ifndef _TYPES_PATTERN_H
#define _TYPES_PATTERN_H

#include <types/buffers.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* pattern in and out types */
enum {
	PATTERN_TYPE_IP      = 0,  /* ipv4 type */
	PATTERN_TYPE_INTEGER = 1,  /* unsigned 32bits integer type */
	PATTERN_TYPE_STRING  = 2,  /* char string type */
	PATTERN_TYPES
};

/* pattern fetch direction */
#define PATTERN_FETCH_REQ	1
#define PATTERN_FETCH_RTR	2

/* pattern result data */
union pattern_data {
	struct in_addr ip; /* used for ipv4 type */
	uint32_t integer;  /* used for unsigned 32bits integer type */
	struct chunk str;  /* used for char string type */
};

/* pattern result */
struct pattern {
	int type;                 /* current type of data */
	union pattern_data data;  /* data */
};

/* pattern conversion */
struct pattern_conv {
	const char *kw;                           /* configuration keyword  */
	int (*process)(const void *arg_p,
	               int arg_i,
	               union pattern_data *data); /* process function */
	unsigned int in_type;                     /* input needed pattern type */
	unsigned int out_type;                    /* output pattern type */
	int (*parse_args)(const char *arg_str,
			  void **arg_p,
			  int *arg_i);            /* argument parser. Can be NULL. */
};

/* pattern conversion expression */
struct pattern_conv_expr {
	struct list list;                         /* member of a pattern expression */
	struct pattern_conv *conv;                /* pattern conversion */
	void *arg_p;                              /* pointer arg, most often a string argument */
	int arg_i;                                /* int arg, most often the argument's length */
};

/* pattern fetch */
struct pattern_fetch {
	const char *kw;                           /* configuration keyword */
	int (*process)(struct proxy *px,
	               struct session *l4,
	               void *l7,
	               int dir, const char *arg,
	               int arg_len,
	               union pattern_data *data); /* fetch processing function */
	unsigned long out_type;                   /* output pattern type */
	int dir;                                  /* usable directions */
};

/* pattern expression */
struct pattern_expr {
	struct list list;                         /* member of list of pattern, currently not used */
	struct pattern_fetch *fetch;              /* pattern fetch */
	char *arg;                                /* configured keyword argument */
	int arg_len;                              /* configured keyword argument length */
	struct list conv_exprs;                   /* list of conversion expression to apply */
};

/* pattern fetch keywords list */
struct pattern_fetch_kw_list {
	struct list list;                         /* head of pattern fetch keyword list */
	struct pattern_fetch kw[VAR_ARRAY];       /* array of pattern fetches */
};

/* pattern conversion keywords list */
struct pattern_conv_kw_list {
	struct list list;                         /* head of pattern conversion keyword list */
	struct pattern_conv kw[VAR_ARRAY];        /* array of pattern ions */
};

#endif /* _TYPES_PATTERN_H */
