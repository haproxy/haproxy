/*
 * include/proto/tcp_rules.h
 * This file contains "tcp" rules definitions
 *
 * Copyright (C) 2000-2016 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_TCP_RULES_H
#define _PROTO_TCP_RULES_H

#include <common/config.h>
#include <types/action.h>
#include <types/task.h>
#include <proto/stick_table.h>

int tcp_inspect_request(struct stream *s, struct channel *req, int an_bit);
int tcp_inspect_response(struct stream *s, struct channel *rep, int an_bit);
int tcp_exec_l4_rules(struct session *sess);
int tcp_exec_l5_rules(struct session *sess);

void tcp_req_conn_keywords_register(struct action_kw_list *kw_list);
void tcp_req_sess_keywords_register(struct action_kw_list *kw_list);
void tcp_req_cont_keywords_register(struct action_kw_list *kw_list);
void tcp_res_cont_keywords_register(struct action_kw_list *kw_list);

#endif /* _PROTO_TCP_RULES_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
