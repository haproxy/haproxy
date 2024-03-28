/*
 * sticky load-balancing
 *
 * Copyright 2024 HAProxy Technologies
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <haproxy/api.h>
#include <haproxy/backend.h>
#include <haproxy/lb_ss.h>
#include <haproxy/server-t.h>

/* this function updates the stick server according to server <srv>'s new state.
 *
 * The server's lock must be held. The lbprm's lock will be used.
 */
static void ss_set_server_status_down(struct server *srv)
{
	struct proxy *p = srv->proxy;

	if (!srv_lb_status_changed(srv))
		return;

	if (srv_willbe_usable(srv))
		goto out_update_state;

	HA_RWLOCK_WRLOCK(LBPRM_LOCK, &p->lbprm.lock);

	if (!srv_currently_usable(srv))
		/* server was already down */
		goto out_update_backend;

	if (srv->flags & SRV_F_BACKUP) {
		p->lbprm.tot_wbck -= srv->cur_eweight;
		p->srv_bck--;
	} else {
		p->lbprm.tot_wact -= srv->cur_eweight;
		p->srv_act--;
	}
	if (srv == p->lbprm.ss.srv) {
		/* sticked server is down, elect a new server
		 * that we will be sticking on.
		 */
		recalc_server_ss(p);
	}

 out_update_backend:
	/* check/update tot_used, tot_weight */
	update_backend_weight(p);
	HA_RWLOCK_WRUNLOCK(LBPRM_LOCK, &p->lbprm.lock);

 out_update_state:
	srv_lb_commit_status(srv);
}

/* This function updates the stick server according to server <srv>'s new state.
 *
 * The server's lock must be held. The lbprm's lock will be used.
 */
static void ss_set_server_status_up(struct server *srv)
{
	struct proxy *p = srv->proxy;

	if (!srv_lb_status_changed(srv))
		return;

	if (!srv_willbe_usable(srv))
		goto out_update_state;

	HA_RWLOCK_WRLOCK(LBPRM_LOCK, &p->lbprm.lock);

	if (srv_currently_usable(srv))
		/* server was already up */
		goto out_update_backend;

	if (srv->flags & SRV_F_BACKUP) {
		p->lbprm.tot_wbck += srv->next_eweight;
		p->srv_bck++;
	} else {
		p->lbprm.tot_wact += srv->next_eweight;
		p->srv_act++;
	}
	if (!p->lbprm.ss.srv ||
	    ((p->lbprm.ss.srv->flags & SRV_F_BACKUP) && !(srv->flags & SRV_F_BACKUP))) {
		/* we didn't have a server or were sticking on a backup server,
		 * but now we have an active server, let's switch to it
		 */
		p->lbprm.ss.srv = srv;
	}

 out_update_backend:
	/* check/update tot_used, tot_weight */
	update_backend_weight(p);
	HA_RWLOCK_WRUNLOCK(LBPRM_LOCK, &p->lbprm.lock);

 out_update_state:
	srv_lb_commit_status(srv);
}

/* This function elects a new stick server for proxy px.
 *
 * The lbprm's lock must be held.
 */
void recalc_server_ss(struct proxy *px)
{
	struct server *cur, *first;
	int flag;

	if (!px->lbprm.tot_used)
		return; /* no server */

	/* here we *know* that we have some servers */
	if (px->srv_act)
		flag = 0;
	else
		flag = SRV_F_BACKUP;

	first = NULL;

	for (cur = px->srv; cur; cur = cur->next) {
		if ((cur->flags & SRV_F_BACKUP) == flag &&
		    srv_willbe_usable(cur)) {
			first = cur;
			break;
		}
	}
	px->lbprm.ss.srv = first;
}

/* This function is responsible for preparing sticky LB algorithm.
 * It should be called only once per proxy, at config time.
 */
void init_server_ss(struct proxy *p)
{
	struct server *srv;

	p->lbprm.set_server_status_up   = ss_set_server_status_up;
	p->lbprm.set_server_status_down = ss_set_server_status_down;
	p->lbprm.update_server_eweight = NULL;

	if (!p->srv)
		return;

	for (srv = p->srv; srv; srv = srv->next) {
		srv->next_eweight = 1; /* ignore weights, all servers have the same weight */
		srv_lb_commit_status(srv);
	}

	/* recounts servers and their weights */
	recount_servers(p);
	update_backend_weight(p);
	recalc_server_ss(p);
}

/*
 * This function returns the server that we're sticking on. If any server
 * is found, it will be returned. If no valid server is found, NULL is
 * returned.
 *
 * The lbprm's lock will be used.
 */
struct server *ss_get_server(struct proxy *px)
{
	struct server *srv = NULL;

	HA_RWLOCK_RDLOCK(LBPRM_LOCK, &px->lbprm.lock);
	srv = px->lbprm.ss.srv;
	HA_RWLOCK_RDUNLOCK(LBPRM_LOCK, &px->lbprm.lock);
	return srv;
}
