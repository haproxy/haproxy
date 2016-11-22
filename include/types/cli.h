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

struct cli_kw {
	const char *str_kw[5];   /* keywords ended by NULL, limited to 5
				 separated keywords combination */
	const char *usage;   /* usage message */
	int (*parse)(char **args, struct appctx *appctx, void *private);
	int (*io_handler)(struct appctx *appctx);
	void (*io_release)(struct appctx *appctx);
	void *private;
};

struct cli_kw_list {
	struct list list;
	struct cli_kw kw[VAR_ARRAY];
};

/* stats socket states */
enum {
	STAT_CLI_INIT = 0,   /* initial state, must leave to zero ! */
	STAT_CLI_END,        /* final state, let's close */
	STAT_CLI_GETREQ,     /* wait for a request */
	STAT_CLI_OUTPUT,     /* all states after this one are responses */
	STAT_CLI_PROMPT,     /* display the prompt (first output, same code) */
	STAT_CLI_PRINT,      /* display message in cli->msg */
	STAT_CLI_PRINT_FREE, /* display message in cli->msg. After the display, free the pointer */
	STAT_CLI_O_CUSTOM,   /* custom callback pointer */
};


#endif /* _TYPES_CLI_H */
