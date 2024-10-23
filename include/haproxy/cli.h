/*
 * include/haproxy/cli.h
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

#ifndef _HAPROXY_CLI_H
#define _HAPROXY_CLI_H

#include <haproxy/applet.h>
#include <haproxy/channel-t.h>
#include <haproxy/cli-t.h>
#include <haproxy/global.h>
#include <haproxy/mworker-t.h>
#include <haproxy/stream-t.h>


void cli_register_kw(struct cli_kw_list *kw_list);
struct cli_kw* cli_find_kw_exact(char **args);
void cli_list_keywords(void);

int cli_has_level(struct appctx *appctx, int level);

int cli_parse_default(char **args, char *payload, struct appctx *appctx, void *private);

/* mworker proxy functions */
int mworker_cli_create_master_proxy(char **errmsg);
int mworker_cli_attach_server(char **errmsg);
struct bind_conf *mworker_cli_master_proxy_new_listener(char *line);
int mworker_cli_global_proxy_new_listener(struct mworker_proc *proc);
void mworker_cli_proxy_stop(void);

extern struct bind_conf *mcli_reload_bind_conf;

/* proxy mode cli functions */

/* analyzers */
int pcli_wait_for_request(struct stream *s, struct channel *req, int an_bit);
int pcli_wait_for_response(struct stream *s, struct channel *rep, int an_bit);

/* updates the CLI's context to log <msg> at <severity> and returns 1. This is
 * for use in CLI parsers to deal with quick response messages.
 */
static inline int cli_msg(struct appctx *appctx, int severity, const char *msg)
{
	struct cli_print_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	ctx->severity = severity;
	ctx->msg = msg;
	appctx->st0 = CLI_ST_PRINT;
	return 1;
}

/* updates the CLI's context to log error message <err> and returns 1. The
 * message will be logged at level LOG_ERR. This is for use in CLI parsers to
 * deal with quick response messages.
 */
static inline int cli_err(struct appctx *appctx, const char *err)
{
	struct cli_print_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	ctx->msg = err;
	appctx->st0 = CLI_ST_PRINT_ERR;
	return 1;
}

/* updates the CLI's context to log <msg> at <severity> and returns 1. The
 * message must have been dynamically allocated and will be freed. This is
 * for use in CLI parsers to deal with quick response messages.
 */
static inline int cli_dynmsg(struct appctx *appctx, int severity, char *msg)
{
	struct cli_print_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	ctx->severity = severity;
	ctx->err = msg;
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
	struct cli_print_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	ctx->err = err;
	appctx->st0 = CLI_ST_PRINT_DYNERR;
	return 1;
}

/* updates the CLI's context to log messages stored in thread-local
 * usermsgs_ctx at <severity> level. usermsgs_ctx will be reset when done.
 * This is for use in CLI parsers to deal with quick response messages.
 *
 * Always returns 1.
 */
static inline int cli_umsg(struct appctx *appctx, int severity)
{
	struct cli_print_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	ctx->severity = severity;
	appctx->st0 = CLI_ST_PRINT_UMSG;
	return 1;
}

/* updates the CLI's context to log messages stored in thread-local
 * usermsgs_ctx using error level. usermsgs_ctx will be reset when done.
 * This is for use in CLI parsers to deal with quick response messages.
 *
 * Always returns 1.
 */
static inline int cli_umsgerr(struct appctx *appctx)
{
	appctx->st0 = CLI_ST_PRINT_UMSGERR;
	return 1;
}

#endif /* _HAPROXY_CLI_H */
