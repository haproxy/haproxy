/*
 * include/haproxy/cli-t.h
 * This file provides structures and types for CLI.
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

#ifndef _HAPROXY_CLI_T_H
#define _HAPROXY_CLI_T_H

#include <haproxy/applet-t.h>

/* Access level for a stats socket (appctx->cli_level) */
#define ACCESS_LVL_NONE     0x0000
#define ACCESS_LVL_USER     0x0001
#define ACCESS_LVL_OPER     0x0002
#define ACCESS_LVL_ADMIN    0x0003
#define ACCESS_LVL_MASK     0x0003

#define ACCESS_FD_LISTENERS 0x0004  /* expose listeners FDs on stats socket */
#define ACCESS_MASTER       0x0008  /* works with the master (and every other processes) */
#define ACCESS_MASTER_ONLY  0x0010  /* only works with the master */
#define ACCESS_EXPERT       0x0020  /* access to dangerous commands reserved to experts */
#define ACCESS_EXPERIMENTAL 0x0040

/* flags for appctx->st1 */
#define APPCTX_CLI_ST1_PROMPT  (1 << 0)
#define APPCTX_CLI_ST1_PAYLOAD (1 << 1)
#define APPCTX_CLI_ST1_NOLF    (1 << 2)

#define CLI_PREFIX_KW_NB 5
#define CLI_MAX_MATCHES 5
#define CLI_MAX_HELP_ENTRIES 1024

/* CLI states */
enum {
	CLI_ST_INIT = 0,   /* initial state, must leave to zero ! */
	CLI_ST_END,        /* final state, let's close */
	CLI_ST_GETREQ,     /* wait for a request */
	CLI_ST_OUTPUT,     /* all states after this one are responses */
	CLI_ST_PROMPT,     /* display the prompt (first output, same code) */
	CLI_ST_PRINT,      /* display const message in cli->msg */
	CLI_ST_PRINT_ERR,  /* display const error in cli->msg */
	CLI_ST_PRINT_DYN,  /* display dynamic message in cli->err. After the display, free the pointer */
	CLI_ST_PRINT_FREE, /* display dynamic error in cli->err. After the display, free the pointer */
	CLI_ST_CALLBACK,   /* custom callback pointer */
};

/* CLI severity output formats */
enum {
	CLI_SEVERITY_UNDEFINED = 0, /* undefined severity format */
	CLI_SEVERITY_NONE,          /* no severity information prepended */
	CLI_SEVERITY_NUMBER,        /* prepend informational cli messages with a severity as number */
	CLI_SEVERITY_STRING,        /* prepend informational cli messages with a severity as string */
};


struct cli_kw {
	const char *str_kw[CLI_PREFIX_KW_NB]; /* keywords ended by NULL, limited to CLI_PREFIX_KW_NB
				 separated keywords combination */
	const char *usage;   /* usage message */
	int (*parse)(char **args, char *payload, struct appctx *appctx, void *private);
	int (*io_handler)(struct appctx *appctx);
	void (*io_release)(struct appctx *appctx);
	void *private;
	int level; /* this is the level needed to show the keyword usage and to use it */
};

struct cli_kw_list {
	struct list list;
	struct cli_kw kw[VAR_ARRAY];
};

#endif /* _HAPROXY_CLI_T_H */
