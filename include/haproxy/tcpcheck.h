/*
 * include/haproxy/tcpcheck.h
 * Functions prototypes for the TCP checks.
 *
 * Copyright 2000-2009,2020 Willy Tarreau <w@1wt.eu>
 * Copyright 2007-2010 Krzysztof Piotr Oledzki <ole@ans.pl>
 * Copyright 2013 Baptiste Assmann <bedis9@gmail.com>
 * Copyright 2020 Gaetan Rivet <grive@u256.net>
 * Copyright 2020 Christopher Faulet <cfaulet@haproxy.com>
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

#ifndef _HAPROXY_TCPCHECK_H
#define _HAPROXY_TCPCHECK_H

#include <haproxy/action.h>
#include <haproxy/check-t.h>
#include <haproxy/pool-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/tcpcheck-t.h>

extern struct action_kw_list tcp_check_keywords;
extern struct pool_head *pool_head_tcpcheck_rule;

int tcpcheck_get_step_id(const struct check *check, const struct tcpcheck_rule *rule);
struct tcpcheck_rule *get_first_tcpcheck_rule(const struct tcpcheck_rules *rules);

struct tcpcheck_ruleset *create_tcpcheck_ruleset(const char *name);
struct tcpcheck_ruleset *find_tcpcheck_ruleset(const char *name);
void free_tcpcheck_ruleset(struct tcpcheck_ruleset *rs);

void free_tcpcheck(struct tcpcheck_rule *rule, int in_pool);
void deinit_proxy_tcpcheck(struct proxy *px);

struct tcpcheck_var *create_tcpcheck_var(const struct ist name);
void free_tcpcheck_var(struct tcpcheck_var *var);
int dup_tcpcheck_vars(struct list *dst, const struct list *src);
void free_tcpcheck_vars(struct list *vars);

int add_tcpcheck_expect_str(struct tcpcheck_rules *rules, const char *str);
int add_tcpcheck_send_strs(struct tcpcheck_rules *rules, const char * const *strs);
int tcpcheck_add_http_rule(struct tcpcheck_rule *chk, struct tcpcheck_rules *rules, char **errmsg);

void free_tcpcheck_http_hdr(struct tcpcheck_http_hdr *hdr);

enum tcpcheck_eval_ret tcpcheck_mysql_expect_iniths(struct check *check, struct tcpcheck_rule *rule, int last_read);
enum tcpcheck_eval_ret tcpcheck_mysql_expect_ok(struct check *check, struct tcpcheck_rule *rule, int last_read);
enum tcpcheck_eval_ret tcpcheck_ldap_expect_bindrsp(struct check *check, struct tcpcheck_rule *rule, int last_read);
enum tcpcheck_eval_ret tcpcheck_spop_expect_agenthello(struct check *check, struct tcpcheck_rule *rule, int last_read);
enum tcpcheck_eval_ret tcpcheck_agent_expect_reply(struct check *check, struct tcpcheck_rule *rule, int last_read);
enum tcpcheck_eval_ret tcpcheck_eval_connect(struct check *check, struct tcpcheck_rule *rule);
enum tcpcheck_eval_ret tcpcheck_eval_send(struct check *check, struct tcpcheck_rule *rule);
enum tcpcheck_eval_ret tcpcheck_eval_recv(struct check *check, struct tcpcheck_rule *rule);
enum tcpcheck_eval_ret tcpcheck_eval_expect_http(struct check *check, struct tcpcheck_rule *rule, int last_read);
enum tcpcheck_eval_ret tcpcheck_eval_expect(struct check *check, struct tcpcheck_rule *rule, int last_read);
enum tcpcheck_eval_ret tcpcheck_eval_action_kw(struct check *check, struct tcpcheck_rule *rule);
int tcpcheck_main(struct check *check);
struct tcpcheck_rule *parse_tcpcheck_action(char **args, int cur_arg, struct proxy *px,
                                            struct list *rules, struct action_kw *kw,
                                            const char *file, int line, char **errmsg);
struct tcpcheck_rule *parse_tcpcheck_connect(char **args, int cur_arg, struct proxy *px, struct list *rules,
                                             const char *file, int line, char **errmsg);
struct tcpcheck_rule *parse_tcpcheck_send(char **args, int cur_arg, struct proxy *px, struct list *rules,
                                          const char *file, int line, char **errmsg);
struct tcpcheck_rule *parse_tcpcheck_send_http(char **args, int cur_arg, struct proxy *px, struct list *rules,
                                               const char *file, int line, char **errmsg);
struct tcpcheck_rule *parse_tcpcheck_comment(char **args, int cur_arg, struct proxy *px, struct list *rules,
                                             const char *file, int line, char **errmsg);
struct tcpcheck_rule *parse_tcpcheck_expect(char **args, int cur_arg, struct proxy *px,
                                            struct list *rules, unsigned int proto,
                                            const char *file, int line, char **errmsg);

int proxy_parse_tcpcheck(char **args, int section, struct proxy *curpx,
                         const struct proxy *defpx, const char *file, int line,
                         char **errmsg);

int proxy_parse_tcp_check_opt(char **args, int cur_arg, struct proxy *curpx, const struct proxy *defpx,
			      const char *file, int line);
int proxy_parse_redis_check_opt(char **args, int cur_arg, struct proxy *curpx, const struct proxy *defpx,
				const char *file, int line);
int proxy_parse_ssl_hello_chk_opt(char **args, int cur_arg, struct proxy *curpx, const struct proxy *defpx,
				  const char *file, int line);
int proxy_parse_smtpchk_opt(char **args, int cur_arg, struct proxy *curpx, const struct proxy *defpx,
			const char *file, int line);
int proxy_parse_pgsql_check_opt(char **args, int cur_arg, struct proxy *curpx, const struct proxy *defpx,
				const char *file, int line);
int proxy_parse_mysql_check_opt(char **args, int cur_arg, struct proxy *curpx, const struct proxy *defpx,
			    const char *file, int line);
int proxy_parse_ldap_check_opt(char **args, int cur_arg, struct proxy *curpx, const struct proxy *defpx,
			       const char *file, int line);
int proxy_parse_spop_check_opt(char **args, int cur_arg, struct proxy *curpx, const struct proxy *defpx,
			       const char *file, int line);
int proxy_parse_httpchk_opt(char **args, int cur_arg, struct proxy *curpx, const struct proxy *defpx,
			    const char *file, int line);

void tcp_check_keywords_register(struct action_kw_list *kw_list);

/* Return the struct action_kw associated to a keyword */
static inline struct action_kw *action_kw_tcp_check_lookup(const char *kw)
{
	return action_lookup(&tcp_check_keywords.list, kw);
}

static inline void action_kw_tcp_check_build_list(struct buffer *chk)
{
	action_build_list(&tcp_check_keywords.list, chk);
}

/*
 * Map tcpcheck rules type (TCPCHK_RULES_*) to equivalent proto_proxy_mode (PROTO_MODE_*)
 */
static inline int tcpchk_rules_type_to_proto_mode(int tcpchk_rules_type)
{
	int mode;

	mode = (((tcpchk_rules_type & TCPCHK_RULES_PROTO_CHK) == TCPCHK_RULES_HTTP_CHK) ? PROTO_MODE_HTTP :
		(((tcpchk_rules_type & TCPCHK_RULES_PROTO_CHK) == TCPCHK_RULES_SPOP_CHK) ? PROTO_MODE_SPOP :
		 PROTO_MODE_TCP));

	return mode;
}

#endif /* _HAPROXY_TCPCHECK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
