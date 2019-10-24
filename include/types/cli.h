/*
 * include/types/cli.h
 * This file provides structures and types for CLI.
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

#ifndef _TYPES_CLI_H
#define _TYPES_CLI_H

#include <common/mini-clist.h>
#include <types/applet.h>

/* Access level for a stats socket */
#define ACCESS_LVL_NONE     0
#define ACCESS_LVL_USER     1
#define ACCESS_LVL_OPER     2
#define ACCESS_LVL_ADMIN    3
#define ACCESS_LVL_MASK     0x3

#define ACCESS_FD_LISTENERS 0x4  /* expose listeners FDs on stats socket */
#define ACCESS_MASTER       0x8  /* works with the master (and every other processes) */
#define ACCESS_MASTER_ONLY  0x10 /* only works with the worker */

#define ACCESS_EXPERT       0x20 /* access to dangerous commands reserved to experts */

struct cli_kw {
	const char *str_kw[5];   /* keywords ended by NULL, limited to 5
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


#endif /* _TYPES_CLI_H */
