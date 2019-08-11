/*
 * include/types/fcgi-app.h
 * This file defines everything related to FCGI applications.
 *
 * Copyright (C) 2019 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
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

#ifndef _TYPES_HTTP_FCGI_H
#define _TYPES_HTTP_FCGI_H

#include <common/config.h>
#include <common/ist.h>
#include <common/fcgi.h>
#include <common/mini-clist.h>
#include <common/regex.h>

#include <ebistree.h>

#include <types/acl.h>
#include <types/filters.h>

#define FCGI_APP_FL_KEEP_CONN     0x00000001 /* Keep the connection alive */
#define FCGI_APP_FL_GET_VALUES    0x00000002 /* Retrieve FCGI variables on connection establishment */
#define FCGI_APP_FL_MPXS_CONNS    0x00000004 /* FCGI APP supports connection multiplexing */


enum fcgi_rule_type {
	FCGI_RULE_SET_PARAM = 0,
	FCGI_RULE_UNSET_PARAM,
	FCGI_RULE_PASS_HDR,
	FCGI_RULE_HIDE_HDR,
};

/* Used during configuration parsing only and converted into fcgi_rule when
 * filter is created.
 */
struct fcgi_rule_conf {
	enum fcgi_rule_type type;
	char *name;
	char *value;
	struct acl_cond *cond; /* acl condition to set/unset the param */
	struct list list;
};

/* parameter rule evaluated during request analyzis */
struct fcgi_rule {
	enum fcgi_rule_type type;
	struct ist name;       /* name of the parameter/header */
	struct list value;     /* log-format compatible expression, may be empty */
	struct acl_cond *cond; /* acl condition to set the param */
	struct list list;
};

/* parameter rule to set/unset a param at the end of the analyzis */
struct fcgi_param_rule {
	struct ist name;
	struct list *value; /* if empty , unset the parameter */
	struct ebpt_node node;
};

/* header rule to pass/hide a header at the end of the analyzis */
struct fcgi_hdr_rule {
	struct ist name;
	int pass; /* 1 to pass the header, 0 Otherwise */
	struct ebpt_node node;
};

struct fcgi_app {
	char              *name;          /* name to identify this set of params */
	struct ist         docroot;       /* FCGI docroot */
	struct ist         index;         /* filename to append to URI ending by a '/' */
	struct my_regex   *pathinfo_re;   /* Regex to use to split scriptname and path-info */
	unsigned int       flags;         /* FCGI_APP_FL_* */
	struct list        logsrvs;       /* log servers */
	unsigned int       maxreqs;       /* maximum number of concurrent requests */

	struct list acls;                 /* list of acls declared for this application */

	struct {
		char *file;               /* file where the section appears */
		int   line;               /* line where the section appears */
		struct list rules;        /* list of rules used during config parsing */
		struct arg_list args;     /* sample arg list that need to be resolved */
	} conf;                           /* config information */
	struct fcgi_app *next;            /* used to chain fcgi-app */
};

/* FCGI config attached to backend proxies */
struct fcgi_flt_conf {
	char *name;                  /* fcgi-app name used during config parsing */
	struct fcgi_app *app;        /* configuration of the fcgi application */

	struct list param_rules;     /* list of set/unset rules */
	struct list hdr_rules;       /* list of pass/add rules  */
};

/* FCGI context attached to streames */
struct fcgi_flt_ctx {
	struct filter *filter;
	struct fcgi_app *app;
};

#endif /* _TYPES_HTTP_FCGI_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
