/*
 * include/haproxy/check.h
 * Functions prototypes for the checks.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_CHECKS_H
#define _HAPROXY_CHECKS_H

#include <haproxy/action-t.h>
#include <haproxy/check-t.h>
#include <haproxy/list-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/server-t.h>

extern struct action_kw_list tcp_check_keywords;
extern struct pool_head *pool_head_tcpcheck_rule;

const char *get_check_status_description(short check_status);
const char *get_check_status_info(short check_status);
void __health_adjust(struct server *s, short status);
struct task *process_chk(struct task *t, void *context, unsigned short state);

const char *init_check(struct check *check, int type);
void free_check(struct check *check);
void free_tcpcheck(struct tcpcheck_rule *rule, int in_pool);

void deinit_proxy_tcpcheck(struct proxy *px);
int dup_tcpcheck_vars(struct list *dst, struct list *src);
void free_tcpcheck_vars(struct list *vars);
int add_tcpcheck_expect_str(struct tcpcheck_rules *rules, const char *str);
int add_tcpcheck_send_strs(struct tcpcheck_rules *rules, const char * const *strs);

/* Declared here, but the definitions are in flt_spoe.c */
int spoe_prepare_healthcheck_request(char **req, int *len);
int spoe_handle_healthcheck_response(char *frame, size_t size, char *err, int errlen);

int proxy_parse_tcp_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
			      const char *file, int line);
int proxy_parse_redis_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
				const char *file, int line);
int proxy_parse_ssl_hello_chk_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
				  const char *file, int line);
int proxy_parse_smtpchk_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
			const char *file, int line);
int proxy_parse_pgsql_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
				const char *file, int line);
int proxy_parse_mysql_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
			    const char *file, int line);
int proxy_parse_ldap_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
			       const char *file, int line);
int proxy_parse_spop_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
			       const char *file, int line);
int proxy_parse_httpchk_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
			    const char *file, int line);
int proxy_parse_external_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
				   const char *file, int line);

int set_srv_agent_send(struct server *srv, const char *send);

/* Use this one only. This inline version only ensures that we don't
 * call the function when the observe mode is disabled.
 */
static inline void health_adjust(struct server *s, short status)
{
	HA_SPIN_LOCK(SERVER_LOCK, &s->lock);
	/* return now if observing nor health check is not enabled */
	if (!s->observe || !s->check.task) {
		HA_SPIN_UNLOCK(SERVER_LOCK, &s->lock);
		return;
	}

	__health_adjust(s, status);
	HA_SPIN_UNLOCK(SERVER_LOCK, &s->lock);
}

static inline void tcp_check_keywords_register(struct action_kw_list *kw_list)
{
	LIST_ADDQ(&tcp_check_keywords.list, &kw_list->list);
}

#endif /* _HAPROXY_CHECKS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
