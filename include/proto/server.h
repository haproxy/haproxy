/*
 * include/proto/server.h
 * This file defines everything related to servers.
 *
 * Copyright (C) 2000-2009 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_SERVER_H
#define _PROTO_SERVER_H

#include <unistd.h>

#include <common/config.h>
#include <types/proxy.h>
#include <types/queue.h>
#include <types/server.h>

#include <proto/queue.h>
#include <proto/freq_ctr.h>

int srv_downtime(const struct server *s);
int srv_getinter(const struct check *check);

/* increase the number of cumulated connections on the designated server */
static void inline srv_inc_sess_ctr(struct server *s)
{
	s->counters.cum_sess++;
	update_freq_ctr(&s->sess_per_sec, 1);
	if (s->sess_per_sec.curr_ctr > s->counters.sps_max)
		s->counters.sps_max = s->sess_per_sec.curr_ctr;
}

#endif /* _PROTO_SERVER_H */

/*
 * Registers the server keyword list <kwl> as a list of valid keywords for next
 * parsing sessions.
 */
void srv_register_keywords(struct srv_kw_list *kwl);

/* Return a pointer to the server keyword <kw>, or NULL if not found. */
struct srv_kw *srv_find_kw(const char *kw);

/* Dumps all registered "server" keywords to the <out> string pointer. */
void srv_dump_kws(char **out);

/* Recomputes the server's eweight based on its state, uweight, the current time,
 * and the proxy's algorihtm. To be used after updating sv->uweight. The warmup
 * state is automatically disabled if the time is elapsed.
 */
void server_recalc_eweight(struct server *sv);

/* returns the current server throttle rate between 0 and 100% */
static inline unsigned int server_throttle_rate(struct server *sv)
{
	struct proxy *px = sv->proxy;

	/* when uweight is 0, we're in soft-stop so that cannot be a slowstart,
	 * thus the throttle is 100%.
	 */
	if (!sv->uweight)
		return 100;

	return (100U * px->lbprm.wmult * sv->eweight + px->lbprm.wdiv - 1) / (px->lbprm.wdiv * sv->uweight);
}

/*
 * Parses weight_str and configures sv accordingly.
 * Returns NULL on success, error message string otherwise.
 */
const char *server_parse_weight_change_request(struct server *sv,
					       const char *weight_str);

/*
 * Update the server's drain state to reflect its user-weight.  This is not
 * done immediately to allow a discrepancy between the server's user-weight
 * and drains state to control logging of changes in the drain state.
 */
static inline void set_server_drain_state(struct server *s)
{
	if (!s->uweight)
		s->state |= SRV_DRAIN;
	else
		s->state &= ~SRV_DRAIN;
}
/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
