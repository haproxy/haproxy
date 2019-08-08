/*
 * include/proto/cli.h
 * This file contains definitions of some primitives to dedicated to
 * statistics output.
 *
 * Copyright (C) 2000-2011 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_CLI_H
#define _PROTO_CLI_H

#include <types/applet.h>
#include <types/channel.h>
#include <types/cli.h>
#include <types/global.h>
#include <types/stream.h>


void cli_register_kw(struct cli_kw_list *kw_list);

int cli_has_level(struct appctx *appctx, int level);

int cli_parse_default(char **args, char *payload, struct appctx *appctx, void *private);

/* mworker proxy functions */

int mworker_cli_proxy_create();
int mworker_cli_proxy_new_listener(char *line);
int mworker_cli_sockpair_new(struct mworker_proc *mworker_proc, int proc);
void mworker_cli_proxy_stop();

/* proxy mode cli functions */

/* analyzers */
int pcli_wait_for_request(struct stream *s, struct channel *req, int an_bit);
int pcli_wait_for_response(struct stream *s, struct channel *rep, int an_bit);

/* updates the CLI's context to log <msg> at <severity> and returns 1. This is
 * for use in CLI parsers to deal with quick response messages.
 */
static inline int cli_msg(struct appctx *appctx, int severity, const char *msg)
{
	appctx->ctx.cli.severity = severity;
	appctx->ctx.cli.msg = msg;
	appctx->st0 = CLI_ST_PRINT;
	return 1;
}

/* updates the CLI's context to log error message <err> and returns 1. The
 * message will be logged at level LOG_ERR. This is for use in CLI parsers to
 * deal with quick response messages.
 */
static inline int cli_err(struct appctx *appctx, const char *err)
{
	appctx->ctx.cli.msg = err;
	appctx->st0 = CLI_ST_PRINT_ERR;
	return 1;
}

/* updates the CLI's context to log <msg> at <severity> and returns 1. The
 * message must have been dynamically allocated and will be freed. This is
 * for use in CLI parsers to deal with quick response messages.
 */
static inline int cli_dynmsg(struct appctx *appctx, int severity, char *msg)
{
	appctx->ctx.cli.severity = severity;
	appctx->ctx.cli.err = msg;
	appctx->st0 = CLI_ST_PRINT_DYN;
	return 1;
}

/* updates the CLI's context to log error message <err> and returns 1. The
 * message must have been dynamically allocated and will be freed. The message
 * will be logged at level LOG_ERR. This is for use in CLI parsers to deal with
 * quick response messages.
 */
static inline int cli_dynerr(struct appctx *appctx, char *err)
{
	appctx->ctx.cli.err = err;
	appctx->st0 = CLI_ST_PRINT_FREE;
	return 1;
}


#endif /* _PROTO_CLI_H */

