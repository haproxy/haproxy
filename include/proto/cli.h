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

/* mworker proxy functions */

int mworker_cli_proxy_create();
int mworker_cli_proxy_new_listener(char *line);
int mworker_cli_sockpair_new(struct mworker_proc *mworker_proc, int proc);
void mworker_cli_proxy_stop();

/* proxy mode cli functions */

/* analyzers */
int pcli_wait_for_request(struct stream *s, struct channel *req, int an_bit);
int pcli_wait_for_response(struct stream *s, struct channel *rep, int an_bit);


#endif /* _PROTO_CLI_H */

