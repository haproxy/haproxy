/*
 * include/proto/proxy.h
 * This file defines function prototypes for proxy management.
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

#ifndef _PROTO_PROXY_H
#define _PROTO_PROXY_H

#include <common/config.h>
#include <common/ticks.h>
#include <common/time.h>
#include <types/applet.h>
#include <types/global.h>
#include <types/proxy.h>
#include <types/listener.h>
#include <proto/freq_ctr.h>

extern struct proxy *proxies_list;
extern struct eb_root used_proxy_id;	/* list of proxy IDs in use */
extern unsigned int error_snapshot_id;  /* global ID assigned to each error then incremented */
extern struct eb_root proxy_by_name;    /* tree of proxies sorted by name */

extern const struct cfg_opt cfg_opts[];
extern const struct cfg_opt cfg_opts2[];

int start_proxies(int verbose);
struct task *manage_proxy(struct task *t, void *context, unsigned short state);
void soft_stop(void);
int pause_proxy(struct proxy *p);
int resume_proxy(struct proxy *p);
void stop_proxy(struct proxy *p);
void zombify_proxy(struct proxy *p);
void pause_proxies(void);
void resume_proxies(void);
int  stream_set_backend(struct stream *s, struct proxy *be);

const char *proxy_cap_str(int cap);
const char *proxy_mode_str(int mode);
void proxy_store_name(struct proxy *px);
struct proxy *proxy_find_by_id(int id, int cap, int table);
struct proxy *proxy_find_by_name(const char *name, int cap, int table);
struct proxy *proxy_find_best_match(int cap, const char *name, int id, int *diff);
struct server *findserver(const struct proxy *px, const char *name);
int proxy_cfg_ensure_no_http(struct proxy *curproxy);
void init_new_proxy(struct proxy *p);
int get_backend_server(const char *bk_name, const char *sv_name,
		       struct proxy **bk, struct server **sv);
void proxy_capture_error(struct proxy *proxy, int is_back,
			 struct proxy *other_end, enum obj_type *target,
			 const struct session *sess,
			 const struct buffer *buf, long buf_ofs,
			 unsigned int buf_out, unsigned int err_pos,
			 const union error_snapshot_ctx *ctx,
			 void (*show)(struct buffer *, const struct error_snapshot *));
void proxy_adjust_all_maxconn();
struct proxy *cli_find_frontend(struct appctx *appctx, const char *arg);
struct proxy *cli_find_frontend(struct appctx *appctx, const char *arg);

/*
 * This function returns a string containing the type of the proxy in a format
 * suitable for error messages, from its capabilities.
 */
static inline const char *proxy_type_str(struct proxy *proxy)
{
	return proxy_cap_str(proxy->cap);
}

/* Find the frontend having name <name>. The name may also start with a '#' to
 * reference a numeric id. NULL is returned if not found.
 */
static inline struct proxy *proxy_fe_by_name(const char *name)
{
	return proxy_find_by_name(name, PR_CAP_FE, 0);
}

/* Find the backend having name <name>. The name may also start with a '#' to
 * reference a numeric id. NULL is returned if not found.
 */
static inline struct proxy *proxy_be_by_name(const char *name)
{
	return proxy_find_by_name(name, PR_CAP_BE, 0);
}

/* this function initializes all timeouts for proxy p */
static inline void proxy_reset_timeouts(struct proxy *proxy)
{
	proxy->timeout.client = TICK_ETERNITY;
	proxy->timeout.tarpit = TICK_ETERNITY;
	proxy->timeout.queue = TICK_ETERNITY;
	proxy->timeout.connect = TICK_ETERNITY;
	proxy->timeout.server = TICK_ETERNITY;
	proxy->timeout.httpreq = TICK_ETERNITY;
	proxy->timeout.check = TICK_ETERNITY;
	proxy->timeout.tunnel = TICK_ETERNITY;
}

/* increase the number of cumulated connections received on the designated frontend */
static inline void proxy_inc_fe_conn_ctr(struct listener *l, struct proxy *fe)
{
	_HA_ATOMIC_ADD(&fe->fe_counters.cum_conn, 1);
	if (l->counters)
		_HA_ATOMIC_ADD(&l->counters->cum_conn, 1);
	HA_ATOMIC_UPDATE_MAX(&fe->fe_counters.cps_max,
			     update_freq_ctr(&fe->fe_conn_per_sec, 1));
}

/* increase the number of cumulated connections accepted by the designated frontend */
static inline void proxy_inc_fe_sess_ctr(struct listener *l, struct proxy *fe)
{

	_HA_ATOMIC_ADD(&fe->fe_counters.cum_sess, 1);
	if (l->counters)
		_HA_ATOMIC_ADD(&l->counters->cum_sess, 1);
	HA_ATOMIC_UPDATE_MAX(&fe->fe_counters.sps_max,
			     update_freq_ctr(&fe->fe_sess_per_sec, 1));
}

/* increase the number of cumulated connections on the designated backend */
static inline void proxy_inc_be_ctr(struct proxy *be)
{
	_HA_ATOMIC_ADD(&be->be_counters.cum_conn, 1);
	HA_ATOMIC_UPDATE_MAX(&be->be_counters.sps_max,
			     update_freq_ctr(&be->be_sess_per_sec, 1));
}

/* increase the number of cumulated requests on the designated frontend */
static inline void proxy_inc_fe_req_ctr(struct proxy *fe)
{
	_HA_ATOMIC_ADD(&fe->fe_counters.p.http.cum_req, 1);
	HA_ATOMIC_UPDATE_MAX(&fe->fe_counters.p.http.rps_max,
			     update_freq_ctr(&fe->fe_req_per_sec, 1));
}

/* Returns non-zero if the proxy is configured to retry a request if we got that status, 0 overwise */
static inline int l7_status_match(struct proxy *p, int status)
{
	/* Just return 0 if no retry was configured for any status */
	if (!(p->retry_type & PR_RE_STATUS_MASK))
		return 0;

	switch (status) {
	case 404:
		return (p->retry_type & PR_RE_404);
	case 408:
		return (p->retry_type & PR_RE_408);
	case 425:
		return (p->retry_type & PR_RE_425);
	case 500:
		return (p->retry_type & PR_RE_500);
	case 501:
		return (p->retry_type & PR_RE_501);
	case 502:
		return (p->retry_type & PR_RE_502);
	case 503:
		return (p->retry_type & PR_RE_503);
	case 504:
		return (p->retry_type & PR_RE_504);
	default:
		break;
	}
	return 0;
}

/* Return 1 if <p> proxy is in <list> list of proxies which are also stick-tables,
 * 0 if not.
 */
static inline int in_proxies_list(struct proxy *list, struct proxy *proxy)
{
	struct proxy *p;

	for (p = list; p; p = p->next_stkt_ref)
		if (proxy == p)
			return 1;

	return 0;
}

#endif /* _PROTO_PROXY_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
