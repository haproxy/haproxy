/*
 * include/proto/arg.h
 * This file contains functions and macros declarations for generic argument parsing.
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

#ifndef _PROTO_ARG_H
#define _PROTO_ARG_H

#include <types/arg.h>

/* Some macros used to build some arg list. We can declare various argument
 * combinations from 0 to 7 args using a single 32-bit integer. The first
 * argument of these macros is always the mandatory number of arguments, and
 * remaining ones are optional args. Note: ARGM() may also be used to return
 * the number of mandatory arguments in a mask.
 */
#define ARGM(m) \
	(m & ARGM_MASK)

#define ARG1(m, t1) \
	(ARGM(m) + (ARGT_##t1 << (ARGM_BITS)))

#define ARG2(m, t1, t2) \
	(ARG1(m, t1) + (ARGT_##t2 << (ARGM_BITS + ARGT_BITS)))

#define ARG3(m, t1, t2, t3) \
	(ARG2(m, t1, t2) + (ARGT_##t3 << (ARGM_BITS + ARGT_BITS * 2)))

#define ARG4(m, t1, t2, t3, t4) \
	(ARG3(m, t1, t2, t3) + (ARGT_##t4 << (ARGM_BITS + ARGT_BITS * 3)))

#define ARG5(m, t1, t2, t3, t4, t5) \
	(ARG4(m, t1, t2, t3, t4) + (ARGT_##t5 << (ARGM_BITS + ARGT_BITS * 4)))

/* Mapping between argument number and literal description. */
extern const char *arg_type_names[];

/* This dummy arg list may be used by default when no arg is found, it helps
 * parsers by removing pointer checks.
 */
extern struct arg empty_arg_list[ARGM_NBARGS];

struct arg_list *arg_list_clone(const struct arg_list *orig);
struct arg_list *arg_list_add(struct arg_list *orig, struct arg *arg, int pos);
int make_arg_list(const char *in, int len, unsigned int mask, struct arg **argp,
                  char **err_msg, const char **err_ptr, int *err_arg,
                  struct arg_list *al);

#endif /* _PROTO_ARG_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
