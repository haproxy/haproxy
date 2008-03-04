/*
  include/proto/backend.h
  Functions prototypes for the backend.

  Copyright (C) 2000-2007 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _PROTO_BACKEND_H
#define _PROTO_BACKEND_H

#include <common/config.h>

#include <types/backend.h>
#include <types/session.h>

#include <proto/queue.h>

int assign_server(struct session *s);
int assign_server_address(struct session *s);
int assign_server_and_queue(struct session *s);
int connect_server(struct session *s);
int srv_count_retry_down(struct session *t, int conn_err);
int srv_retryable_connect(struct session *t);
int srv_redispatch_connect(struct session *t);
int backend_parse_balance(const char **args, char *err,
			  int errlen, struct proxy *curproxy);

void recalc_server_map(struct proxy *px);
int be_downtime(struct proxy *px);
void init_server_map(struct proxy *p);
void fwrr_init_server_groups(struct proxy *p);

/*
 * This function tries to find a running server with free connection slots for
 * the proxy <px> following the round-robin method.
 * If any server is found, it will be returned and px->lbprm.map.rr_idx will be updated
 * to point to the next server. If no valid server is found, NULL is returned.
 */
static inline struct server *get_server_rr_with_conns(struct proxy *px, struct server *srvtoavoid)
{
	int newidx, avoididx;
	struct server *srv, *avoided;

	if (px->lbprm.tot_weight == 0)
		return NULL;

	if (px->lbprm.map.state & PR_MAP_RECALC)
		recalc_server_map(px);

	if (px->lbprm.map.rr_idx < 0 || px->lbprm.map.rr_idx >= px->lbprm.tot_weight)
		px->lbprm.map.rr_idx = 0;
	newidx = px->lbprm.map.rr_idx;

	avoided = NULL;
	avoididx = 0; /* shut a gcc warning */
	do {
		srv = px->lbprm.map.srv[newidx++];
		if (!srv->maxconn || srv->cur_sess < srv_dynamic_maxconn(srv)) {
			/* make sure it is not the server we are try to exclude... */
			if (srv != srvtoavoid) {
				px->lbprm.map.rr_idx = newidx;
				return srv;
			}

			avoided = srv;	/* ...but remember that is was selected yet avoided */
			avoididx = newidx;
		}
		if (newidx == px->lbprm.tot_weight)
			newidx = 0;
	} while (newidx != px->lbprm.map.rr_idx);

	if (avoided)
		px->lbprm.map.rr_idx = avoididx;

	/* return NULL or srvtoavoid if found */
	return avoided;
}


/*
 * This function tries to find a running server for the proxy <px> following
 * the round-robin method.
 * If any server is found, it will be returned and px->lbprm.map.rr_idx will be updated
 * to point to the next server. If no valid server is found, NULL is returned.
 */
static inline struct server *get_server_rr(struct proxy *px)
{
	if (px->lbprm.tot_weight == 0)
		return NULL;

	if (px->lbprm.map.state & PR_MAP_RECALC)
		recalc_server_map(px);

	if (px->lbprm.map.rr_idx < 0 || px->lbprm.map.rr_idx >= px->lbprm.tot_weight)
		px->lbprm.map.rr_idx = 0;
	return px->lbprm.map.srv[px->lbprm.map.rr_idx++];
}


/*
 * This function tries to find a running server for the proxy <px> following
 * the source hash method. Depending on the number of active/backup servers,
 * it will either look for active servers, or for backup servers.
 * If any server is found, it will be returned. If no valid server is found,
 * NULL is returned.
 */
static inline struct server *get_server_sh(struct proxy *px,
					   const char *addr, int len)
{
	unsigned int h, l;

	if (px->lbprm.tot_weight == 0)
		return NULL;

	if (px->lbprm.map.state & PR_MAP_RECALC)
		recalc_server_map(px);

	l = h = 0;

	/* note: we won't hash if there's only one server left */
	if (px->lbprm.tot_used > 1) {
		while ((l + sizeof (int)) <= len) {
			h ^= ntohl(*(unsigned int *)(&addr[l]));
			l += sizeof (int);
		}
		h %= px->lbprm.tot_weight;
	}
	return px->lbprm.map.srv[h];
}

/* 
 * This function tries to find a running server for the proxy <px> following
 * the URI hash method. In order to optimize cache hits, the hash computation
 * ends at the question mark. Depending on the number of active/backup servers,
 * it will either look for active servers, or for backup servers.
 * If any server is found, it will be returned. If no valid server is found,
 * NULL is returned.
 *
 * This code was contributed by Guillaume Dallaire, who also selected this hash
 * algorithm out of a tens because it gave him the best results.
 *
 */
static inline struct server *get_server_uh(struct proxy *px, char *uri, int uri_len)
{
	unsigned long hash = 0;
	int c;

	if (px->lbprm.tot_weight == 0)
		return NULL;

	if (px->lbprm.map.state & PR_MAP_RECALC)
		recalc_server_map(px);

	while (uri_len--) {
		c = *uri++;
		if (c == '?')
			break;
		hash = c + (hash << 6) + (hash << 16) - hash;
	}

	return px->lbprm.map.srv[hash % px->lbprm.tot_weight];
}


#endif /* _PROTO_BACKEND_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
