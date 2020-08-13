/*
 * include/haproxy/regex-t.h
 * Types and macros definitions for regular expressions
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

#ifndef _HAPROXY_REGEX_T_H
#define _HAPROXY_REGEX_T_H

#include <stdlib.h>
#include <string.h>

#include <haproxy/api.h>

#ifdef USE_PCRE
#include <pcre.h>
#include <pcreposix.h>

/* For pre-8.20 PCRE compatibility */
#ifndef PCRE_STUDY_JIT_COMPILE
#define PCRE_STUDY_JIT_COMPILE 0
#endif

#elif USE_PCRE2
#include <pcre2.h>
#include <pcre2posix.h>

#else /* no PCRE, nor PCRE2 */
#include <regex.h>
#endif

struct my_regex {
#ifdef USE_PCRE
	pcre *reg;
	pcre_extra *extra;
#ifdef USE_PCRE_JIT
#ifndef PCRE_CONFIG_JIT
#error "The PCRE lib doesn't support JIT. Change your lib, or remove the option USE_PCRE_JIT."
#endif
#endif
#elif USE_PCRE2
	int(*mfn)(const pcre2_code *, PCRE2_SPTR, PCRE2_SIZE, PCRE2_SIZE, uint32_t, pcre2_match_data *, pcre2_match_context *);
	pcre2_code *reg;
#else /* no PCRE */
	regex_t regex;
#endif
};

struct hdr_exp {
    struct hdr_exp *next;
    struct my_regex *preg;		/* expression to look for */
    const char *replace;		/* expression to set instead */
    void *cond;				/* a possible condition or NULL */
};

#endif /* _HAPROXY_REGEX_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
