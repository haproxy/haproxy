/*
 * include/proto/backend.h
 * Functions prototypes for the backend.
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_BACKEND_H
#define _PROTO_BACKEND_H

#include <common/config.h>

#include <types/backend.h>
#include <types/proxy.h>
#include <types/server.h>
#include <types/session.h>

int assign_server(struct session *s);
int assign_server_address(struct session *s);
int assign_server_and_queue(struct session *s);
int connect_server(struct session *s);
int srv_redispatch_connect(struct session *t);
const char *backend_lb_algo_str(int algo);
int backend_parse_balance(const char **args, char **err, struct proxy *curproxy);
int tcp_persist_rdp_cookie(struct session *s, struct buffer *req, int an_bit);

int be_downtime(struct proxy *px);
void recount_servers(struct proxy *px);
void update_backend_weight(struct proxy *px);
struct server *get_server_sh(struct proxy *px, const char *addr, int len);
struct server *get_server_uh(struct proxy *px, char *uri, int uri_len);

/* This function returns non-zero if a server with the given weight and state
 * is usable for LB, otherwise zero.
 */
static inline int srv_is_usable(int state, int weight)
{
	if (!weight)
		return 0;
	if (state & (SRV_GOINGDOWN | SRV_MAINTAIN))
		return 0;
	if (!(state & SRV_RUNNING))
		return 0;
	return 1;
}

#endif /* _PROTO_BACKEND_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
