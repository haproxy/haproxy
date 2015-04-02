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
#include <common/time.h>

#include <types/backend.h>
#include <types/proxy.h>
#include <types/server.h>
#include <types/stream.h>

int assign_server(struct stream *s);
int assign_server_address(struct stream *s);
int assign_server_and_queue(struct stream *s);
int connect_server(struct stream *s);
int srv_redispatch_connect(struct stream *t);
const char *backend_lb_algo_str(int algo);
int backend_parse_balance(const char **args, char **err, struct proxy *curproxy);
int tcp_persist_rdp_cookie(struct stream *s, struct channel *req, int an_bit);

int be_downtime(struct proxy *px);
void recount_servers(struct proxy *px);
void update_backend_weight(struct proxy *px);
struct server *get_server_sh(struct proxy *px, const char *addr, int len);
struct server *get_server_uh(struct proxy *px, char *uri, int uri_len);
int be_lastsession(const struct proxy *be);

/* set the time of last session on the backend */
static void inline be_set_sess_last(struct proxy *be)
{
	be->be_counters.last_sess = now.tv_sec;
}

/* This function returns non-zero if the designated server is usable for LB
 * according to its current weight and current state. Otherwise it returns 0.
 */
static inline int srv_is_usable(const struct server *srv)
{
	enum srv_state state = srv->state;

	if (!srv->eweight)
		return 0;
	if (srv->admin & SRV_ADMF_MAINT)
		return 0;
	if (srv->admin & SRV_ADMF_DRAIN)
		return 0;
	switch (state) {
	case SRV_ST_STARTING:
	case SRV_ST_RUNNING:
		return 1;
	case SRV_ST_STOPPING:
	case SRV_ST_STOPPED:
		return 0;
	}
	return 0;
}

/* This function returns non-zero if the designated server was usable for LB
 * according to its current weight and previous state. Otherwise it returns 0.
 */
static inline int srv_was_usable(const struct server *srv)
{
	enum srv_state state = srv->prev_state;

	if (!srv->prev_eweight)
		return 0;
	if (srv->prev_admin & SRV_ADMF_MAINT)
		return 0;
	if (srv->prev_admin & SRV_ADMF_DRAIN)
		return 0;
	switch (state) {
	case SRV_ST_STARTING:
	case SRV_ST_RUNNING:
		return 1;
	case SRV_ST_STOPPING:
	case SRV_ST_STOPPED:
		return 0;
	}
	return 0;
}

/* This function commits the current server state and weight onto the previous
 * ones in order to detect future changes.
 */
static inline void srv_lb_commit_status(struct server *srv)
{
	srv->prev_state = srv->state;
	srv->prev_admin = srv->admin;
	srv->prev_eweight = srv->eweight;
}

/* This function returns true when a server has experienced a change since last
 * commit on its state or weight, otherwise zero.
 */
static inline int srv_lb_status_changed(const struct server *srv)
{
	return (srv->state != srv->prev_state ||
		srv->admin != srv->prev_admin ||
		srv->eweight != srv->prev_eweight);
}

/* sends a log message when a backend goes down, and also sets last
 * change date.
 */
void set_backend_down(struct proxy *be);

#endif /* _PROTO_BACKEND_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
