/*
 * include/proto/proxy.h
 * This file defines function prototypes for proxy management.
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

#ifndef _PROTO_PROXY_H
#define _PROTO_PROXY_H

#include <common/config.h>
#include <common/ticks.h>
#include <common/time.h>
#include <types/proxy.h>
#include <proto/freq_ctr.h>

int start_proxies(int verbose);
void maintain_proxies(int *next);
void soft_stop(void);
void pause_proxy(struct proxy *p);
void stop_proxy(struct proxy *p);
void pause_proxies(void);
void listen_proxies(void);
int  session_set_backend(struct session *s, struct proxy *be);

const char *proxy_cap_str(int cap);
const char *proxy_mode_str(int mode);
struct proxy *findproxy_mode(const char *name, int mode, int cap);
struct proxy *findproxy(const char *name, int cap);
struct server *findserver(const struct proxy *px, const char *name);
int proxy_cfg_ensure_no_http(struct proxy *curproxy);
int get_backend_server(const char *bk_name, const char *sv_name,
		       struct proxy **bk, struct server **sv);

/*
 * This function returns a string containing the type of the proxy in a format
 * suitable for error messages, from its capabilities.
 */
static inline const char *proxy_type_str(struct proxy *proxy)
{
	return proxy_cap_str(proxy->cap);
}

/* this function initializes all timeouts for proxy p */
static inline void proxy_reset_timeouts(struct proxy *proxy)
{
	proxy->timeout.client = TICK_ETERNITY;
	proxy->timeout.tarpit = TICK_ETERNITY;
	proxy->timeout.queue = TICK_ETERNITY;
	proxy->timeout.connect = TICK_ETERNITY;
	proxy->timeout.server = TICK_ETERNITY;
	proxy->timeout.appsession = TICK_ETERNITY;
	proxy->timeout.httpreq = TICK_ETERNITY;
	proxy->timeout.check = TICK_ETERNITY;
}

/* increase the number of cumulated connections received on the designated frontend */
static void inline proxy_inc_fe_conn_ctr(struct listener *l, struct proxy *fe)
{
	fe->counters.cum_feconn++;
	if (l->counters)
		l->counters->cum_conn++;

	update_freq_ctr(&fe->fe_conn_per_sec, 1);
	if (fe->fe_conn_per_sec.curr_ctr > fe->counters.fe_cps_max)
		fe->counters.fe_cps_max = fe->fe_conn_per_sec.curr_ctr;
}

/* increase the number of cumulated connections accepted by the designated frontend */
static void inline proxy_inc_fe_sess_ctr(struct listener *l, struct proxy *fe)
{
	fe->counters.cum_fesess++;
	if (l->counters)
		l->counters->cum_sess++;
	update_freq_ctr(&fe->fe_sess_per_sec, 1);
	if (fe->fe_sess_per_sec.curr_ctr > fe->counters.fe_sps_max)
		fe->counters.fe_sps_max = fe->fe_sess_per_sec.curr_ctr;
}

/* increase the number of cumulated connections on the designated backend */
static void inline proxy_inc_be_ctr(struct proxy *be)
{
	be->counters.cum_beconn++;
	update_freq_ctr(&be->be_sess_per_sec, 1);
	if (be->be_sess_per_sec.curr_ctr > be->counters.be_sps_max)
		be->counters.be_sps_max = be->be_sess_per_sec.curr_ctr;
}

/* increase the number of cumulated requests on the designated frontend */
static void inline proxy_inc_fe_req_ctr(struct proxy *fe)
{
	fe->counters.cum_fe_req++;
	update_freq_ctr(&fe->fe_req_per_sec, 1);
	if (fe->fe_req_per_sec.curr_ctr > fe->counters.fe_rps_max)
		fe->counters.fe_rps_max = fe->fe_req_per_sec.curr_ctr;
}

#endif /* _PROTO_PROXY_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
