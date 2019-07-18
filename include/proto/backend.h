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
int be_lastsession(const struct proxy *be);

/* Returns number of usable servers in backend */
static inline int be_usable_srv(struct proxy *be)
{
        if (be->state == PR_STSTOPPED)
                return 0;
        else if (be->srv_act)
                return be->srv_act;
        else if (be->lbprm.fbck)
                return 1;
        else
                return be->srv_bck;
}

/* set the time of last session on the backend */
static inline void be_set_sess_last(struct proxy *be)
{
	be->be_counters.last_sess = now.tv_sec;
}

/* This function returns non-zero if the designated server will be
 * usable for LB according to pending weight and state.
 * Otherwise it returns 0.
 */
static inline int srv_willbe_usable(const struct server *srv)
{
	enum srv_state state = srv->next_state;

	if (!srv->next_eweight)
		return 0;
	if (srv->next_admin & SRV_ADMF_MAINT)
		return 0;
	if (srv->next_admin & SRV_ADMF_DRAIN)
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
 * according to its current weight and state. Otherwise it returns 0.
 */
static inline int srv_currently_usable(const struct server *srv)
{
	enum srv_state state = srv->cur_state;

	if (!srv->cur_eweight)
		return 0;
	if (srv->cur_admin & SRV_ADMF_MAINT)
		return 0;
	if (srv->cur_admin & SRV_ADMF_DRAIN)
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

/* This function commits the next server state and weight onto the current
 * ones in order to detect future changes. The server's lock is expected to
 * be held when calling this function.
 */
static inline void srv_lb_commit_status(struct server *srv)
{
	srv->cur_state = srv->next_state;
	srv->cur_admin = srv->next_admin;
	srv->cur_eweight = srv->next_eweight;
}

/* This function returns true when a server has experienced a change since last
 * commit on its state or weight, otherwise zero.
 */
static inline int srv_lb_status_changed(const struct server *srv)
{
	return (srv->next_state != srv->cur_state ||
		srv->next_admin != srv->cur_admin ||
		srv->next_eweight != srv->cur_eweight);
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
