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

#include <haproxy/check-t.h>
#include <haproxy/list-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/server-t.h>

extern struct data_cb check_conn_cb;
extern struct proxy checks_fe;

const char *get_check_status_description(short check_status);
const char *get_check_status_info(short check_status);
int httpchk_build_status_header(struct server *s, struct buffer *buf);
void __health_adjust(struct server *s, short status);
void set_server_check_status(struct check *check, short status, const char *desc);
void chk_report_conn_err(struct check *check, int errno_bck, int expired);
struct task *process_chk(struct task *t, void *context, unsigned short state);

const char *init_check(struct check *check, int type);
void free_check(struct check *check);

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

#endif /* _HAPROXY_CHECKS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
