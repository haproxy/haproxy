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
#define ACCESS_MCLI_DEBUG   0x0080 /* allow the master CLI to use any command without the flag ACCESS_MASTER */
#define ACCESS_MCLI_SEVERITY_NB  0x0100 /* 'set severity-output number' on master CLI */
#define ACCESS_MCLI_SEVERITY_STR 0x0200 /* 'set severity-output string' on master CLI */

/* flags for appctx->st1 */
#define APPCTX_CLI_ST1_PROMPT  (1 << 0)
#define APPCTX_CLI_ST1_PAYLOAD (1 << 1)
#define APPCTX_CLI_ST1_NOLF    (1 << 2)
#define APPCTX_CLI_ST1_TIMED   (1 << 3)
#define APPCTX_CLI_ST1_LASTCMD (1 << 4)

#define CLI_PREFIX_KW_NB 5
#define CLI_MAX_MATCHES 5
#define CLI_MAX_HELP_ENTRIES 1024

/* CLI states */
enum {
	CLI_ST_INIT = 0,   /* initial state, must leave to zero ! */
	CLI_ST_END,        /* final state, let's close */
	CLI_ST_GETREQ,     /* wait for a request */
	CLI_ST_PARSEREQ,   /* parse a request */
	CLI_ST_OUTPUT,     /* all states after this one are responses */
	CLI_ST_PROMPT,     /* display the prompt (first output, same code) */
	CLI_ST_PRINT,      /* display const message in cli->msg */
	CLI_ST_PRINT_ERR,  /* display const error in cli->msg */
	CLI_ST_PRINT_DYN,  /* display dynamic message in cli->err. After the display, free the pointer */
	CLI_ST_PRINT_DYNERR, /* display dynamic error in cli->err. After the display, free the pointer */
	CLI_ST_PRINT_UMSG, /* display usermsgs_ctx buffer. After the display, usermsgs_ctx is reset. */
	CLI_ST_PRINT_UMSGERR, /* display usermsgs_ctx buffer as error. After the display, usermsgs_ctx is reset. */
	CLI_ST_CALLBACK,   /* custom callback pointer */
};

/* CLI severity output formats */
enum {
	CLI_SEVERITY_UNDEFINED = 0, /* undefined severity format */
	CLI_SEVERITY_NONE,          /* no severity information prepended */
	CLI_SEVERITY_NUMBER,        /* prepend informational cli messages with a severity as number */
	CLI_SEVERITY_STRING,        /* prepend informational cli messages with a severity as string */
};

/* CLI context for printing command responses. */
struct cli_print_ctx {
	const char *msg;        /* pointer to a persistent message to be returned in CLI_ST_PRINT state */
	char *err;              /* pointer to a 'must free' message to be returned in CLI_ST_PRINT_DYN state */
	int severity;           /* severity of the message to be returned according to (syslog) rfc5424 */
};

/* context for the "wait" command that's used to wait for some time on a
 * condition. We store the start date and the expiration date. The error
 * value is set by the I/O handler to be printed by the release handler at
 * the end.
 */
enum cli_wait_err {
	CLI_WAIT_ERR_DONE,       // condition satisfied
	CLI_WAIT_ERR_INTR,       // interrupted
	CLI_WAIT_ERR_EXP,        // finished on wait expiration
	CLI_WAIT_ERR_FAIL,       // finished early (unrecoverable)
};

enum cli_wait_cond {
	CLI_WAIT_COND_NONE,      // no condition to wait on
	CLI_WAIT_COND_SRV_UNUSED,// wait for server to become unused
};

struct cli_wait_ctx {
	uint start, deadline;    // both are in ticks.
	enum cli_wait_cond cond; // CLI_WAIT_COND_*
	enum cli_wait_err error; // CLI_WAIT_ERR_*
	char *args[4];           // up to 4 args taken at parse time, all strduped
	const char *msg;         // static error message for failures if not NULL
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
