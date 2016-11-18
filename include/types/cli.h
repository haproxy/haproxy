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

/* Show Info fields for CLI output. For any field added here, please add the text
 * representation in the info_field_names array below. Please only append at the end,
 * before the INF_TOTAL_FIELDS entry, and never insert anything in the middle
 * nor at the beginning.
 */
enum info_field {
	INF_NAME,
	INF_VERSION,
	INF_RELEASE_DATE,
	INF_NBPROC,
	INF_PROCESS_NUM,
	INF_PID,
	INF_UPTIME,
	INF_UPTIME_SEC,
	INF_MEMMAX_MB,
	INF_POOL_ALLOC_MB,
	INF_POOL_USED_MB,
	INF_POOL_FAILED,
	INF_ULIMIT_N,
	INF_MAXSOCK,
	INF_MAXCONN,
	INF_HARD_MAXCONN,
	INF_CURR_CONN,
	INF_CUM_CONN,
	INF_CUM_REQ,
	INF_MAX_SSL_CONNS,
	INF_CURR_SSL_CONNS,
	INF_CUM_SSL_CONNS,
	INF_MAXPIPES,
	INF_PIPES_USED,
	INF_PIPES_FREE,
	INF_CONN_RATE,
	INF_CONN_RATE_LIMIT,
	INF_MAX_CONN_RATE,
	INF_SESS_RATE,
	INF_SESS_RATE_LIMIT,
	INF_MAX_SESS_RATE,
	INF_SSL_RATE,
	INF_SSL_RATE_LIMIT,
	INF_MAX_SSL_RATE,
	INF_SSL_FRONTEND_KEY_RATE,
	INF_SSL_FRONTEND_MAX_KEY_RATE,
	INF_SSL_FRONTEND_SESSION_REUSE_PCT,
	INF_SSL_BACKEND_KEY_RATE,
	INF_SSL_BACKEND_MAX_KEY_RATE,
	INF_SSL_CACHE_LOOKUPS,
	INF_SSL_CACHE_MISSES,
	INF_COMPRESS_BPS_IN,
	INF_COMPRESS_BPS_OUT,
	INF_COMPRESS_BPS_RATE_LIM,
	INF_ZLIB_MEM_USAGE,
	INF_MAX_ZLIB_MEM_USAGE,
	INF_TASKS,
	INF_RUN_QUEUE,
	INF_IDLE_PCT,
	INF_NODE,
	INF_DESCRIPTION,

	/* must always be the last one */
	INF_TOTAL_FIELDS
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
	STAT_CLI_O_INFO,     /* dump info */
	STAT_CLI_O_SESS,     /* dump streams */
	STAT_CLI_O_ERR,      /* dump errors */
	STAT_CLI_O_TAB,      /* dump tables */
	STAT_CLI_O_CLR,      /* clear tables */
	STAT_CLI_O_SET,      /* set entries in tables */
	STAT_CLI_O_STAT,     /* dump stats */
	STAT_CLI_O_POOLS,    /* dump memory pools */
	STAT_CLI_O_SERVERS_STATE, /* dump server state and changing information */
	STAT_CLI_O_BACKEND,  /* dump backend list */
	STAT_CLI_O_ENV,      /* dump environment */
	STAT_CLI_O_CUSTOM,   /* custom callback pointer */
};


#endif /* _TYPES_CLI_H */
