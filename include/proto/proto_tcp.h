/*
 * include/proto/proto_tcp.h
 * This file contains TCP socket protocol definitions.
 *
 * Copyright (C) 2000-2013 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_PROTO_TCP_H
#define _PROTO_PROTO_TCP_H

#include <common/config.h>
#include <types/action.h>
#include <types/task.h>
#include <proto/stick_table.h>

int tcp_bind_socket(int fd, int flags, struct sockaddr_storage *local, struct sockaddr_storage *remote);
void tcpv4_add_listener(struct listener *listener);
void tcpv6_add_listener(struct listener *listener);
int tcp_pause_listener(struct listener *l);
int tcp_connect_server(struct connection *conn, int data, int delack);
int tcp_connect_probe(struct connection *conn);
int tcp_get_src(int fd, struct sockaddr *sa, socklen_t salen, int dir);
int tcp_get_dst(int fd, struct sockaddr *sa, socklen_t salen, int dir);
int tcp_drain(int fd);
int tcp_inspect_request(struct stream *s, struct channel *req, int an_bit);
int tcp_inspect_response(struct stream *s, struct channel *rep, int an_bit);
int tcp_exec_req_rules(struct session *sess);

/* TCP keywords. */
void tcp_req_conn_keywords_register(struct action_kw_list *kw_list);
void tcp_req_cont_keywords_register(struct action_kw_list *kw_list);
void tcp_res_cont_keywords_register(struct action_kw_list *kw_list);

/* Export some samples. */
int smp_fetch_src(const struct arg *args, struct sample *smp, const char *kw, void *private);


/* for a tcp-request action ACT_TCP_TRK_*, return a tracking index starting at
 * zero for SC0. Unknown actions also return zero.
 */
static inline int tcp_trk_idx(int trk_action)
{
	return trk_action - ACT_ACTION_TRK_SC0;
}

#endif /* _PROTO_PROTO_TCP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
