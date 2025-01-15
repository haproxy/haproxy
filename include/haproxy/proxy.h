/*
 * include/haproxy/proxy.h
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

#ifndef _HAPROXY_PROXY_H
#define _HAPROXY_PROXY_H

#include <haproxy/api.h>
#include <haproxy/applet-t.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/list.h>
#include <haproxy/listener-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/server-t.h>
#include <haproxy/ticks.h>
#include <haproxy/thread.h>

extern struct proxy *proxies_list;
extern struct eb_root used_proxy_id;	/* list of proxy IDs in use */
extern unsigned int error_snapshot_id;  /* global ID assigned to each error then incremented */
extern struct eb_root proxy_by_name;    /* tree of proxies sorted by name */

extern const struct cfg_opt cfg_opts[];
extern const struct cfg_opt cfg_opts2[];

struct task *manage_proxy(struct task *t, void *context, unsigned int state);
void proxy_cond_pause(struct proxy *p);
void proxy_cond_resume(struct proxy *p);
void proxy_cond_disable(struct proxy *p);
void soft_stop(void);
int pause_proxy(struct proxy *p);
int resume_proxy(struct proxy *p);
void stop_proxy(struct proxy *p);
int  stream_set_backend(struct stream *s, struct proxy *be);

void free_proxy(struct proxy *p);
const char *proxy_cap_str(int cap);
const char *proxy_mode_str(int mode);
const char *proxy_find_best_option(const char *word, const char **extra);
void proxy_store_name(struct proxy *px);
struct proxy *proxy_find_by_id(int id, int cap, int table);
struct proxy *proxy_find_by_name(const char *name, int cap, int table);
struct proxy *proxy_find_best_match(int cap, const char *name, int id, int *diff);
struct server *findserver(const struct proxy *px, const char *name);
int proxy_cfg_ensure_no_http(struct proxy *curproxy);
int proxy_cfg_ensure_no_log(struct proxy *curproxy);
void init_new_proxy(struct proxy *p);
void proxy_preset_defaults(struct proxy *defproxy);
void proxy_free_defaults(struct proxy *defproxy);
void proxy_destroy_defaults(struct proxy *px);
void proxy_destroy_all_unref_defaults(void);
void proxy_ref_defaults(struct proxy *px, struct proxy *defpx);
void proxy_unref_defaults(struct proxy *px);
void proxy_unref_or_destroy_defaults(struct proxy *px);
struct proxy *alloc_new_proxy(const char *name, unsigned int cap,
                              char **errmsg);
struct proxy *parse_new_proxy(const char *name, unsigned int cap,
                              const char *file, int linenum,
                              const struct proxy *defproxy);
void proxy_capture_error(struct proxy *proxy, int is_back,
			 struct proxy *other_end, enum obj_type *target,
			 const struct session *sess,
			 const struct buffer *buf, long buf_ofs,
			 unsigned int buf_out, unsigned int err_pos,
			 const union error_snapshot_ctx *ctx,
			 void (*show)(struct buffer *, const struct error_snapshot *));
void proxy_adjust_all_maxconn(void);
struct proxy *cli_find_frontend(struct appctx *appctx, const char *arg);
struct proxy *cli_find_frontend(struct appctx *appctx, const char *arg);
int resolve_stick_rule(struct proxy *curproxy, struct sticking_rule *mrule);
void free_stick_rules(struct list *rules);
void free_server_rules(struct list *srules);
int proxy_init_per_thr(struct proxy *px);

/*
 * This function returns a string containing the type of the proxy in a format
 * suitable for error messages, from its capabilities.
 */
static inline const char *proxy_type_str(struct proxy *proxy)
{
	if (proxy->mode == PR_MODE_PEERS)
		return "peers section";
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
	_HA_ATOMIC_INC(&fe->fe_counters.cum_conn);
	if (l && l->counters)
		_HA_ATOMIC_INC(&l->counters->cum_conn);
	HA_ATOMIC_UPDATE_MAX(&fe->fe_counters.cps_max,
	                     update_freq_ctr(&fe->fe_counters.conn_per_sec, 1));
}

/* increase the number of cumulated connections accepted by the designated frontend */
static inline void proxy_inc_fe_sess_ctr(struct listener *l, struct proxy *fe)
{

	_HA_ATOMIC_INC(&fe->fe_counters.cum_sess);
	if (l && l->counters)
		_HA_ATOMIC_INC(&l->counters->cum_sess);
	HA_ATOMIC_UPDATE_MAX(&fe->fe_counters.sps_max,
			     update_freq_ctr(&fe->fe_counters.sess_per_sec, 1));
}

/* increase the number of cumulated HTTP sessions on the designated frontend.
 * <http_ver> must be the HTTP version for such requests.
 */
static inline void proxy_inc_fe_cum_sess_ver_ctr(struct listener *l, struct proxy *fe,
                                                 unsigned int http_ver)
{
	if (http_ver == 0 ||
	    http_ver > sizeof(fe->fe_counters.cum_sess_ver) / sizeof(*fe->fe_counters.cum_sess_ver))
	    return;

	_HA_ATOMIC_INC(&fe->fe_counters.cum_sess_ver[http_ver - 1]);
	if (l && l->counters)
		_HA_ATOMIC_INC(&l->counters->cum_sess_ver[http_ver - 1]);
}

/* increase the number of cumulated streams on the designated backend */
static inline void proxy_inc_be_ctr(struct proxy *be)
{
	_HA_ATOMIC_INC(&be->be_counters.cum_sess);
	HA_ATOMIC_UPDATE_MAX(&be->be_counters.sps_max,
			     update_freq_ctr(&be->be_counters.sess_per_sec, 1));
}

/* increase the number of cumulated requests on the designated frontend.
 * <http_ver> must be the HTTP version for HTTP request. 0 may be provided
 * for others requests.
 */
static inline void proxy_inc_fe_req_ctr(struct listener *l, struct proxy *fe,
                                        unsigned int http_ver)
{
	if (http_ver >= sizeof(fe->fe_counters.p.http.cum_req) / sizeof(*fe->fe_counters.p.http.cum_req))
	    return;

	_HA_ATOMIC_INC(&fe->fe_counters.p.http.cum_req[http_ver]);
	if (l && l->counters)
		_HA_ATOMIC_INC(&l->counters->p.http.cum_req[http_ver]);
	HA_ATOMIC_UPDATE_MAX(&fe->fe_counters.p.http.rps_max,
	                     update_freq_ctr(&fe->fe_counters.req_per_sec, 1));
}

/* Returns non-zero if the proxy is configured to retry a request if we got that status, 0 otherwise */
static inline int l7_status_match(struct proxy *p, int status)
{
	/* Just return 0 if no retry was configured for any status */
	if (!(p->retry_type & PR_RE_STATUS_MASK))
		return 0;

	switch (status) {
	case 401:
		return (p->retry_type & PR_RE_401);
	case 403:
		return (p->retry_type & PR_RE_403);
	case 404:
		return (p->retry_type & PR_RE_404);
	case 408:
		return (p->retry_type & PR_RE_408);
	case 421:
		return (p->retry_type & PR_RE_421);
	case 425:
		return (p->retry_type & PR_RE_425);
	case 429:
		return (p->retry_type & PR_RE_429);
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

/* Add <bytes> to the global total bytes sent and adjust the send rate. Set
 * <splice> if this was sent usigin splicing.
 */
static inline void increment_send_rate(uint64_t bytes, int splice)
{
	/* We count the total bytes sent, and the send rate for 32-byte blocks.
	 * The reason for the latter is that freq_ctr are limited to 4GB and
	 * that it's not enough per second.
	 */

	if (splice)
		_HA_ATOMIC_ADD(&th_ctx->spliced_out_bytes, bytes);
	_HA_ATOMIC_ADD(&th_ctx->out_bytes, bytes);
	update_freq_ctr(&th_ctx->out_32bps, (bytes + 16) / 32);
}

#endif /* _HAPROXY_PROXY_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
