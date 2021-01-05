/*
 * Health-checks functions.
 *
 * Copyright 2000-2009,2020 Willy Tarreau <w@1wt.eu>
 * Copyright 2007-2010 Krzysztof Piotr Oledzki <ole@ans.pl>
 * Copyright 2013 Baptiste Assmann <bedis9@gmail.com>
 * Copyright 2020 Gaetan Rivet <grive@u256.net>
 * Copyright 2020 Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <haproxy/action.h>
#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/check.h>
#include <haproxy/chunk.h>
#include <haproxy/connection.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/h1.h>
#include <haproxy/http.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/istbuf.h>
#include <haproxy/list.h>
#include <haproxy/log.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy-t.h>
#include <haproxy/regex.h>
#include <haproxy/sample.h>
#include <haproxy/server.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/task.h>
#include <haproxy/tcpcheck.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <haproxy/vars.h>


/* Global tree to share all tcp-checks */
struct eb_root shared_tcpchecks = EB_ROOT;


DECLARE_POOL(pool_head_tcpcheck_rule, "tcpcheck_rule", sizeof(struct tcpcheck_rule));

/**************************************************************************/
/*************** Init/deinit tcp-check rules and ruleset ******************/
/**************************************************************************/
/* Releases memory allocated for a log-format string */
static void free_tcpcheck_fmt(struct list *fmt)
{
	struct logformat_node *lf, *lfb;

	list_for_each_entry_safe(lf, lfb, fmt, list) {
		LIST_DEL(&lf->list);
		release_sample_expr(lf->expr);
		free(lf->arg);
		free(lf);
	}
}

/* Releases memory allocated for an HTTP header used in a tcp-check send rule */
void free_tcpcheck_http_hdr(struct tcpcheck_http_hdr *hdr)
{
	if (!hdr)
		return;

	free_tcpcheck_fmt(&hdr->value);
	istfree(&hdr->name);
	free(hdr);
}

/* Releases memory allocated for an HTTP header list used in a tcp-check send
 * rule
 */
static void free_tcpcheck_http_hdrs(struct list *hdrs)
{
	struct tcpcheck_http_hdr *hdr, *bhdr;

	list_for_each_entry_safe(hdr, bhdr, hdrs, list) {
		LIST_DEL(&hdr->list);
		free_tcpcheck_http_hdr(hdr);
	}
}

/* Releases memory allocated for a tcp-check. If in_pool is set, it means the
 * tcp-check was allocated using a memory pool (it is used to instantiate email
 * alerts).
 */
void free_tcpcheck(struct tcpcheck_rule *rule, int in_pool)
{
	if (!rule)
		return;

	free(rule->comment);
	switch (rule->action) {
	case TCPCHK_ACT_SEND:
		switch (rule->send.type) {
		case TCPCHK_SEND_STRING:
		case TCPCHK_SEND_BINARY:
			istfree(&rule->send.data);
			break;
		case TCPCHK_SEND_STRING_LF:
		case TCPCHK_SEND_BINARY_LF:
			free_tcpcheck_fmt(&rule->send.fmt);
			break;
		case TCPCHK_SEND_HTTP:
			free(rule->send.http.meth.str.area);
			if (!(rule->send.http.flags & TCPCHK_SND_HTTP_FL_URI_FMT))
				istfree(&rule->send.http.uri);
			else
				free_tcpcheck_fmt(&rule->send.http.uri_fmt);
			istfree(&rule->send.http.vsn);
			free_tcpcheck_http_hdrs(&rule->send.http.hdrs);
			if (!(rule->send.http.flags & TCPCHK_SND_HTTP_FL_BODY_FMT))
				istfree(&rule->send.http.body);
			else
				free_tcpcheck_fmt(&rule->send.http.body_fmt);
			break;
		case TCPCHK_SEND_UNDEF:
			break;
		}
		break;
	case TCPCHK_ACT_EXPECT:
		free_tcpcheck_fmt(&rule->expect.onerror_fmt);
		free_tcpcheck_fmt(&rule->expect.onsuccess_fmt);
		release_sample_expr(rule->expect.status_expr);
		switch (rule->expect.type) {
		case TCPCHK_EXPECT_HTTP_STATUS:
			free(rule->expect.codes.codes);
			break;
		case TCPCHK_EXPECT_STRING:
		case TCPCHK_EXPECT_BINARY:
		case TCPCHK_EXPECT_HTTP_BODY:
			istfree(&rule->expect.data);
			break;
		case TCPCHK_EXPECT_STRING_REGEX:
		case TCPCHK_EXPECT_BINARY_REGEX:
		case TCPCHK_EXPECT_HTTP_STATUS_REGEX:
		case TCPCHK_EXPECT_HTTP_BODY_REGEX:
			regex_free(rule->expect.regex);
			break;
		case TCPCHK_EXPECT_STRING_LF:
		case TCPCHK_EXPECT_BINARY_LF:
		case TCPCHK_EXPECT_HTTP_BODY_LF:
			free_tcpcheck_fmt(&rule->expect.fmt);
			break;
		case TCPCHK_EXPECT_HTTP_HEADER:
			if (rule->expect.flags & TCPCHK_EXPT_FL_HTTP_HNAME_REG)
				regex_free(rule->expect.hdr.name_re);
			else if (rule->expect.flags & TCPCHK_EXPT_FL_HTTP_HNAME_FMT)
				free_tcpcheck_fmt(&rule->expect.hdr.name_fmt);
			else
				istfree(&rule->expect.hdr.name);

			if (rule->expect.flags & TCPCHK_EXPT_FL_HTTP_HVAL_REG)
				regex_free(rule->expect.hdr.value_re);
			else if (rule->expect.flags & TCPCHK_EXPT_FL_HTTP_HVAL_FMT)
				free_tcpcheck_fmt(&rule->expect.hdr.value_fmt);
			else if (!(rule->expect.flags & TCPCHK_EXPT_FL_HTTP_HVAL_NONE))
				istfree(&rule->expect.hdr.value);
			break;
		case TCPCHK_EXPECT_CUSTOM:
		case TCPCHK_EXPECT_UNDEF:
			break;
		}
		break;
	case TCPCHK_ACT_CONNECT:
		free(rule->connect.sni);
		free(rule->connect.alpn);
		release_sample_expr(rule->connect.port_expr);
		break;
	case TCPCHK_ACT_COMMENT:
		break;
	case TCPCHK_ACT_ACTION_KW:
		free(rule->action_kw.rule);
		break;
	}

	if (in_pool)
		pool_free(pool_head_tcpcheck_rule, rule);
	else
		free(rule);
}

/* Creates a tcp-check variable used in preset variables before executing a
 * tcp-check ruleset.
 */
struct tcpcheck_var *create_tcpcheck_var(const struct ist name)
{
	struct tcpcheck_var *var = NULL;

	var = calloc(1, sizeof(*var));
	if (var == NULL)
		return NULL;

	var->name = istdup(name);
	if (!isttest(var->name)) {
		free(var);
		return NULL;
	}

	LIST_INIT(&var->list);
	return var;
}

/* Releases memory allocated for a preset tcp-check variable */
void free_tcpcheck_var(struct tcpcheck_var *var)
{
	if (!var)
		return;

	istfree(&var->name);
	if (var->data.type == SMP_T_STR || var->data.type == SMP_T_BIN)
		free(var->data.u.str.area);
	else if (var->data.type == SMP_T_METH && var->data.u.meth.meth == HTTP_METH_OTHER)
		free(var->data.u.meth.str.area);
	free(var);
}

/* Releases a list of preset tcp-check variables */
void free_tcpcheck_vars(struct list *vars)
{
	struct tcpcheck_var *var, *back;

	list_for_each_entry_safe(var, back, vars, list) {
		LIST_DEL(&var->list);
		free_tcpcheck_var(var);
	}
}

/* Duplicate a list of preset tcp-check variables */
int dup_tcpcheck_vars(struct list *dst, struct list *src)
{
	struct tcpcheck_var *var, *new = NULL;

	list_for_each_entry(var, src, list) {
		new = create_tcpcheck_var(var->name);
		if (!new)
			goto error;
		new->data.type = var->data.type;
		if (var->data.type == SMP_T_STR || var->data.type == SMP_T_BIN) {
			if (chunk_dup(&new->data.u.str, &var->data.u.str) == NULL)
				goto error;
			if (var->data.type == SMP_T_STR)
				new->data.u.str.area[new->data.u.str.data] = 0;
		}
		else if (var->data.type == SMP_T_METH && var->data.u.meth.meth == HTTP_METH_OTHER) {
			if (chunk_dup(&new->data.u.str, &var->data.u.str) == NULL)
				goto error;
			new->data.u.str.area[new->data.u.str.data] = 0;
			new->data.u.meth.meth = var->data.u.meth.meth;
		}
		else
			new->data.u = var->data.u;
		LIST_ADDQ(dst, &new->list);
	}
	return 1;

 error:
	free(new);
	return 0;
}

/* Looks for a shared tcp-check ruleset given its name. */
struct tcpcheck_ruleset *find_tcpcheck_ruleset(const char *name)
{
	struct tcpcheck_ruleset *rs;
	struct ebpt_node *node;

	node = ebis_lookup_len(&shared_tcpchecks, name, strlen(name));
	if (node) {
		rs = container_of(node, typeof(*rs), node);
		return rs;
	}
	return NULL;
}

/* Creates a new shared tcp-check ruleset and insert it in shared_tcpchecks
 * tree.
 */
struct tcpcheck_ruleset *create_tcpcheck_ruleset(const char *name)
{
	struct tcpcheck_ruleset *rs;

	rs = calloc(1, sizeof(*rs));
	if (rs == NULL)
		return NULL;

	rs->node.key = strdup(name);
	if (rs->node.key == NULL) {
		free(rs);
		return NULL;
	}

	LIST_INIT(&rs->rules);
	ebis_insert(&shared_tcpchecks, &rs->node);
	return rs;
}

/* Releases memory allocated by a tcp-check ruleset. */
void free_tcpcheck_ruleset(struct tcpcheck_ruleset *rs)
{
	struct tcpcheck_rule *r, *rb;

	if (!rs)
		return;

	ebpt_delete(&rs->node);
	free(rs->node.key);
	list_for_each_entry_safe(r, rb, &rs->rules, list) {
		LIST_DEL(&r->list);
		free_tcpcheck(r, 0);
	}
	free(rs);
}


/**************************************************************************/
/**************** Everything about tcp-checks execution *******************/
/**************************************************************************/
/* Returns the id of a step in a tcp-check ruleset */
int tcpcheck_get_step_id(struct check *check, struct tcpcheck_rule *rule)
{
	if (!rule)
		rule = check->current_step;

	/* no last started step => first step */
	if (!rule)
		return 1;

	/* last step is the first implicit connect */
	if (rule->index == 0 &&
	    rule->action == TCPCHK_ACT_CONNECT &&
	    (rule->connect.options & TCPCHK_OPT_IMPLICIT))
		return 0;

	return rule->index + 1;
}

/* Returns the first non COMMENT/ACTION_KW tcp-check rule from list <list> or
 * NULL if none was found.
 */
struct tcpcheck_rule *get_first_tcpcheck_rule(struct tcpcheck_rules *rules)
{
	struct tcpcheck_rule *r;

	list_for_each_entry(r, rules->list, list) {
		if (r->action != TCPCHK_ACT_COMMENT && r->action != TCPCHK_ACT_ACTION_KW)
			return r;
	}
	return NULL;
}

/* Returns the last non COMMENT/ACTION_KW tcp-check rule from list <list> or
 * NULL if none was found.
 */
static struct tcpcheck_rule *get_last_tcpcheck_rule(struct tcpcheck_rules *rules)
{
	struct tcpcheck_rule *r;

	list_for_each_entry_rev(r, rules->list, list) {
		if (r->action != TCPCHK_ACT_COMMENT && r->action != TCPCHK_ACT_ACTION_KW)
			return r;
	}
	return NULL;
}

/* Returns the non COMMENT/ACTION_KW tcp-check rule from list <list> following
 * <start> or NULL if non was found. If <start> is NULL, it relies on
 * get_first_tcpcheck_rule().
 */
static struct tcpcheck_rule *get_next_tcpcheck_rule(struct tcpcheck_rules *rules, struct tcpcheck_rule *start)
{
	struct tcpcheck_rule *r;

	if (!start)
		return get_first_tcpcheck_rule(rules);

	r = LIST_NEXT(&start->list, typeof(r), list);
	list_for_each_entry_from(r, rules->list, list) {
		if (r->action != TCPCHK_ACT_COMMENT && r->action != TCPCHK_ACT_ACTION_KW)
			return r;
	}
	return NULL;
}


/* Creates info message when a tcp-check healthcheck fails on an expect rule */
static void tcpcheck_expect_onerror_message(struct buffer *msg, struct check *check, struct tcpcheck_rule *rule,
					    int match, struct ist info)
{
	struct sample *smp;

	/* Follows these step to produce the info message:
	 *     1. if info field is already provided, copy it
	 *     2. if the expect rule provides an onerror log-format string,
	 *        use it to produce the message
	 *     3. the expect rule is part of a protocol check (http, redis, mysql...), do nothing
	 *     4. Otherwise produce the generic tcp-check info message
	 */
	if (istlen(info)) {
		chunk_strncat(msg, istptr(info), istlen(info));
		goto comment;
	}
	else if (!LIST_ISEMPTY(&rule->expect.onerror_fmt)) {
		msg->data += sess_build_logline(check->sess, NULL, b_tail(msg), b_room(msg), &rule->expect.onerror_fmt);
		goto comment;
	}

       if (check->type == PR_O2_TCPCHK_CHK &&
	   (check->tcpcheck_rules->flags & TCPCHK_RULES_PROTO_CHK) != TCPCHK_RULES_TCP_CHK)
	       goto comment;

	chunk_strcat(msg, (match ? "TCPCHK matched unwanted content" : "TCPCHK did not match content"));
	switch (rule->expect.type) {
	case TCPCHK_EXPECT_HTTP_STATUS:
		chunk_appendf(msg, "(status codes) at step %d", tcpcheck_get_step_id(check, rule));
		break;
	case TCPCHK_EXPECT_STRING:
	case TCPCHK_EXPECT_HTTP_BODY:
		chunk_appendf(msg, " '%.*s' at step %d", (unsigned int)istlen(rule->expect.data), istptr(rule->expect.data),
			      tcpcheck_get_step_id(check, rule));
		break;
	case TCPCHK_EXPECT_BINARY:
		chunk_appendf(msg, " (binary) at step %d", tcpcheck_get_step_id(check, rule));
		break;
	case TCPCHK_EXPECT_STRING_REGEX:
	case TCPCHK_EXPECT_HTTP_STATUS_REGEX:
	case TCPCHK_EXPECT_HTTP_BODY_REGEX:
		chunk_appendf(msg, " (regex) at step %d", tcpcheck_get_step_id(check, rule));
		break;
	case TCPCHK_EXPECT_BINARY_REGEX:
		chunk_appendf(msg, " (binary regex) at step %d", tcpcheck_get_step_id(check, rule));
		break;
	case TCPCHK_EXPECT_STRING_LF:
	case TCPCHK_EXPECT_HTTP_BODY_LF:
		chunk_appendf(msg, " (log-format string) at step %d", tcpcheck_get_step_id(check, rule));
		break;
	case TCPCHK_EXPECT_BINARY_LF:
		chunk_appendf(msg, " (log-format binary) at step %d", tcpcheck_get_step_id(check, rule));
		break;
	case TCPCHK_EXPECT_CUSTOM:
		chunk_appendf(msg, " (custom function) at step %d", tcpcheck_get_step_id(check, rule));
		break;
	case TCPCHK_EXPECT_HTTP_HEADER:
		chunk_appendf(msg, " (header pattern) at step %d", tcpcheck_get_step_id(check, rule));
	case TCPCHK_EXPECT_UNDEF:
		/* Should never happen. */
		return;
	}

  comment:
	/* If the failing expect rule provides a comment, it is concatenated to
	 * the info message.
	 */
	if (rule->comment) {
		chunk_strcat(msg, " comment: ");
		chunk_strcat(msg, rule->comment);
	}

	/* Finally, the check status code is set if the failing expect rule
	 * defines a status expression.
	 */
	if (rule->expect.status_expr) {
		smp = sample_fetch_as_type(check->proxy, check->sess, NULL, SMP_OPT_DIR_RES | SMP_OPT_FINAL,
					   rule->expect.status_expr, SMP_T_STR);

		if (smp && sample_casts[smp->data.type][SMP_T_SINT] &&
                    sample_casts[smp->data.type][SMP_T_SINT](smp))
			check->code = smp->data.u.sint;
	}

	*(b_tail(msg)) = '\0';
}

/* Creates info message when a tcp-check healthcheck succeeds on an expect rule */
static void tcpcheck_expect_onsuccess_message(struct buffer *msg, struct check *check, struct tcpcheck_rule *rule,
					      struct ist info)
{
	struct sample *smp;

	/* Follows these step to produce the info message:
	 *     1. if info field is already provided, copy it
	 *     2. if the expect rule provides an onsucces log-format string,
	 *        use it to produce the message
	 *     3. the expect rule is part of a protocol check (http, redis, mysql...), do nothing
	 *     4. Otherwise produce the generic tcp-check info message
	 */
	if (istlen(info))
		chunk_strncat(msg, istptr(info), istlen(info));
	if (!LIST_ISEMPTY(&rule->expect.onsuccess_fmt))
		msg->data += sess_build_logline(check->sess, NULL, b_tail(msg), b_room(msg),
						&rule->expect.onsuccess_fmt);
	else if (check->type == PR_O2_TCPCHK_CHK &&
		 (check->tcpcheck_rules->flags & TCPCHK_RULES_PROTO_CHK) == TCPCHK_RULES_TCP_CHK)
		chunk_strcat(msg, "(tcp-check)");

	/* Finally, the check status code is set if the expect rule defines a
	 * status expression.
	 */
	if (rule->expect.status_expr) {
		smp = sample_fetch_as_type(check->proxy, check->sess, NULL, SMP_OPT_DIR_RES | SMP_OPT_FINAL,
					   rule->expect.status_expr, SMP_T_STR);

		if (smp && sample_casts[smp->data.type][SMP_T_SINT] &&
                    sample_casts[smp->data.type][SMP_T_SINT](smp))
			check->code = smp->data.u.sint;
	}

	*(b_tail(msg)) = '\0';
}

/* Internal functions to parse and validate a MySQL packet in the context of an
 * expect rule. It start to parse the input buffer at the offset <offset>. If
 * <last_read> is set, no more data are expected.
 */
static enum tcpcheck_eval_ret tcpcheck_mysql_expect_packet(struct check *check, struct tcpcheck_rule *rule,
							   unsigned int offset, int last_read)
{
	enum tcpcheck_eval_ret ret = TCPCHK_EVAL_CONTINUE;
	enum healthcheck_status status;
	struct buffer *msg = NULL;
	struct ist desc = IST_NULL;
	unsigned int err = 0, plen = 0;


	/* 3 Bytes for the packet length and 1 byte for the sequence id */
	if (b_data(&check->bi) < offset+4) {
		if (!last_read)
			goto wait_more_data;

		/* invalid length or truncated response */
		status = HCHK_STATUS_L7RSP;
		goto error;
	}

	plen = ((unsigned char) *b_peek(&check->bi, offset)) +
		(((unsigned char) *(b_peek(&check->bi, offset+1))) << 8) +
		(((unsigned char) *(b_peek(&check->bi, offset+2))) << 16);

	if (b_data(&check->bi) < offset+plen+4) {
		if (!last_read)
			goto wait_more_data;

		/* invalid length or truncated response */
		status = HCHK_STATUS_L7RSP;
		goto error;
	}

	if (*b_peek(&check->bi, offset+4) == '\xff') {
		/* MySQL Error packet always begin with field_count = 0xff */
		status = HCHK_STATUS_L7STS;
		err = ((unsigned char) *b_peek(&check->bi, offset+5)) +
			(((unsigned char) *(b_peek(&check->bi, offset+6))) << 8);
		desc = ist2(b_peek(&check->bi, offset+7), b_data(&check->bi) - offset - 7);
		goto error;
	}

	if (get_next_tcpcheck_rule(check->tcpcheck_rules, rule) != NULL) {
		/* Not the last rule, continue */
		goto out;
	}

	/* We set the MySQL Version in description for information purpose
	 * FIXME : it can be cool to use MySQL Version for other purpose,
	 * like mark as down old MySQL server.
	 */
	status = ((rule->expect.ok_status != HCHK_STATUS_UNKNOWN) ? rule->expect.ok_status : HCHK_STATUS_L7OKD);
	set_server_check_status(check, status, b_peek(&check->bi, 5));

  out:
	free_trash_chunk(msg);
	return ret;

  error:
	ret = TCPCHK_EVAL_STOP;
	check->code = err;
	msg = alloc_trash_chunk();
	if (msg)
		tcpcheck_expect_onerror_message(msg, check, rule, 0, desc);
	set_server_check_status(check, status, (msg ? b_head(msg) : NULL));
	goto out;

  wait_more_data:
	ret = TCPCHK_EVAL_WAIT;
	goto out;
}

/* Custom tcp-check expect function to parse and validate the MySQL initial
 * handshake packet. Returns TCPCHK_EVAL_WAIT to wait for more data,
 * TCPCHK_EVAL_CONTINUE to evaluate the next rule or TCPCHK_EVAL_STOP if an
 * error occurred.
 */
enum tcpcheck_eval_ret tcpcheck_mysql_expect_iniths(struct check *check, struct tcpcheck_rule *rule, int last_read)
{
	return tcpcheck_mysql_expect_packet(check, rule, 0, last_read);
}

/* Custom tcp-check expect function to parse and validate the MySQL OK packet
 * following the initial handshake. Returns TCPCHK_EVAL_WAIT to wait for more
 * data, TCPCHK_EVAL_CONTINUE to evaluate the next rule or TCPCHK_EVAL_STOP if
 * an error occurred.
 */
enum tcpcheck_eval_ret tcpcheck_mysql_expect_ok(struct check *check, struct tcpcheck_rule *rule, int last_read)
{
	unsigned int hslen = 0;

	hslen = 4 + ((unsigned char) *b_head(&check->bi)) +
		(((unsigned char) *(b_peek(&check->bi, 1))) << 8) +
		(((unsigned char) *(b_peek(&check->bi, 2))) << 16);

	return tcpcheck_mysql_expect_packet(check, rule, hslen, last_read);
}

/* Custom tcp-check expect function to parse and validate the LDAP bind response
 * package packet. Returns TCPCHK_EVAL_WAIT to wait for more data,
 * TCPCHK_EVAL_CONTINUE to evaluate the next rule or TCPCHK_EVAL_STOP if an
 * error occurred.
 */
enum tcpcheck_eval_ret tcpcheck_ldap_expect_bindrsp(struct check *check, struct tcpcheck_rule *rule, int last_read)
{
	enum tcpcheck_eval_ret ret = TCPCHK_EVAL_CONTINUE;
	enum healthcheck_status status;
	struct buffer *msg = NULL;
	struct ist desc = IST_NULL;
	unsigned short msglen = 0;

	/* Check if the server speaks LDAP (ASN.1/BER)
	 * http://en.wikipedia.org/wiki/Basic_Encoding_Rules
	 * http://tools.ietf.org/html/rfc4511
	 */
	/* size of LDAPMessage */
	msglen = (*(b_head(&check->bi) + 1) & 0x80) ? (*(b_head(&check->bi) + 1) & 0x7f) : 0;

	/* http://tools.ietf.org/html/rfc4511#section-4.2.2
	 *   messageID: 0x02 0x01 0x01: INTEGER 1
	 *   protocolOp: 0x61: bindResponse
	 */
	if ((msglen > 2) || (memcmp(b_head(&check->bi) + 2 + msglen, "\x02\x01\x01\x61", 4) != 0)) {
		status = HCHK_STATUS_L7RSP;
		desc = ist("Not LDAPv3 protocol");
		goto error;
	}

	/* size of bindResponse */
	msglen += (*(b_head(&check->bi) + msglen + 6) & 0x80) ? (*(b_head(&check->bi) + msglen + 6) & 0x7f) : 0;

	/* http://tools.ietf.org/html/rfc4511#section-4.1.9
	 *   ldapResult: 0x0a 0x01: ENUMERATION
	 */
	if ((msglen > 4) || (memcmp(b_head(&check->bi) + 7 + msglen, "\x0a\x01", 2) != 0)) {
		status = HCHK_STATUS_L7RSP;
		desc = ist("Not LDAPv3 protocol");
		goto error;
	}

	/* http://tools.ietf.org/html/rfc4511#section-4.1.9
	 *   resultCode
	 */
	check->code = *(b_head(&check->bi) + msglen + 9);
	if (check->code) {
		status = HCHK_STATUS_L7STS;
		desc = ist("See RFC: http://tools.ietf.org/html/rfc4511#section-4.1.9");
		goto error;
	}

	status = ((rule->expect.ok_status != HCHK_STATUS_UNKNOWN) ? rule->expect.ok_status : HCHK_STATUS_L7OKD);
	set_server_check_status(check, status, "Success");

  out:
	free_trash_chunk(msg);
	return ret;

  error:
	ret = TCPCHK_EVAL_STOP;
	msg = alloc_trash_chunk();
	if (msg)
		tcpcheck_expect_onerror_message(msg, check, rule, 0, desc);
	set_server_check_status(check, status, (msg ? b_head(msg) : NULL));
	goto out;
}

/* Custom tcp-check expect function to parse and validate the SPOP hello agent
 * frame. Returns TCPCHK_EVAL_WAIT to wait for more data, TCPCHK_EVAL_CONTINUE
 * to evaluate the next rule or TCPCHK_EVAL_STOP if an error occurred.
 */
enum tcpcheck_eval_ret tcpcheck_spop_expect_agenthello(struct check *check, struct tcpcheck_rule *rule, int last_read)
{
	enum tcpcheck_eval_ret ret = TCPCHK_EVAL_CONTINUE;
	enum healthcheck_status status;
	struct buffer *msg = NULL;
	struct ist desc = IST_NULL;
	unsigned int framesz;


	memcpy(&framesz, b_head(&check->bi), 4);
	framesz = ntohl(framesz);

	if (!last_read && b_data(&check->bi) < (4+framesz))
		goto wait_more_data;

	memset(b_orig(&trash), 0, b_size(&trash));
	if (spoe_handle_healthcheck_response(b_peek(&check->bi, 4), framesz, b_orig(&trash), HCHK_DESC_LEN) == -1) {
		status = HCHK_STATUS_L7RSP;
		desc = ist2(b_orig(&trash), strlen(b_orig(&trash)));
		goto error;
	}

	status = ((rule->expect.ok_status != HCHK_STATUS_UNKNOWN) ? rule->expect.ok_status : HCHK_STATUS_L7OKD);
	set_server_check_status(check, status, "SPOA server is ok");

  out:
	free_trash_chunk(msg);
	return ret;

  error:
	ret = TCPCHK_EVAL_STOP;
	msg = alloc_trash_chunk();
	if (msg)
		tcpcheck_expect_onerror_message(msg, check, rule, 0, desc);
	set_server_check_status(check, status, (msg ? b_head(msg) : NULL));
	goto out;

  wait_more_data:
	ret = TCPCHK_EVAL_WAIT;
	goto out;
}

/* Custom tcp-check expect function to parse and validate the agent-check
 * reply. Returns TCPCHK_EVAL_WAIT to wait for more data, TCPCHK_EVAL_CONTINUE
 * to evaluate the next rule or TCPCHK_EVAL_STOP if an error occurred.
 */
enum tcpcheck_eval_ret tcpcheck_agent_expect_reply(struct check *check, struct tcpcheck_rule *rule, int last_read)
{
	enum tcpcheck_eval_ret ret = TCPCHK_EVAL_STOP;
	enum healthcheck_status status = HCHK_STATUS_CHECKED;
	const char *hs = NULL; /* health status      */
	const char *as = NULL; /* admin status */
	const char *ps = NULL; /* performance status */
	const char *cs = NULL; /* maxconn */
	const char *err = NULL; /* first error to report */
	const char *wrn = NULL; /* first warning to report */
	char *cmd, *p;

	/* We're getting an agent check response. The agent could
	 * have been disabled in the mean time with a long check
	 * still pending. It is important that we ignore the whole
	 * response.
	 */
	if (!(check->state & CHK_ST_ENABLED))
		goto out;

	/* The agent supports strings made of a single line ended by the
	 * first CR ('\r') or LF ('\n'). This line is composed of words
	 * delimited by spaces (' '), tabs ('\t'), or commas (','). The
	 * line may optionally contained a description of a state change
	 * after a sharp ('#'), which is only considered if a health state
	 * is announced.
	 *
	 * Words may be composed of :
	 *   - a numeric weight suffixed by the percent character ('%').
	 *   - a health status among "up", "down", "stopped", and "fail".
	 *   - an admin status among "ready", "drain", "maint".
	 *
	 * These words may appear in any order. If multiple words of the
	 * same category appear, the last one wins.
	 */

	p = b_head(&check->bi);
	while (*p && *p != '\n' && *p != '\r')
		p++;

	if (!*p) {
		if (!last_read)
			goto wait_more_data;

		/* at least inform the admin that the agent is mis-behaving */
		set_server_check_status(check, check->status, "Ignoring incomplete line from agent");
		goto out;
	}

	*p = 0;
	cmd = b_head(&check->bi);

	while (*cmd) {
		/* look for next word */
		if (*cmd == ' ' || *cmd == '\t' || *cmd == ',') {
			cmd++;
			continue;
		}

		if (*cmd == '#') {
			/* this is the beginning of a health status description,
			 * skip the sharp and blanks.
			 */
			cmd++;
			while (*cmd == '\t' || *cmd == ' ')
				cmd++;
			break;
		}

		/* find the end of the word so that we have a null-terminated
		 * word between <cmd> and <p>.
		 */
		p = cmd + 1;
		while (*p && *p != '\t' && *p != ' ' && *p != '\n' && *p != ',')
			p++;
		if (*p)
			*p++ = 0;

		/* first, health statuses */
		if (strcasecmp(cmd, "up") == 0) {
			check->server->check.health = check->server->check.rise + check->server->check.fall - 1;
			status = HCHK_STATUS_L7OKD;
			hs = cmd;
		}
		else if (strcasecmp(cmd, "down") == 0) {
			check->server->check.health = 0;
			status = HCHK_STATUS_L7STS;
			hs = cmd;
		}
		else if (strcasecmp(cmd, "stopped") == 0) {
			check->server->check.health = 0;
			status = HCHK_STATUS_L7STS;
			hs = cmd;
		}
		else if (strcasecmp(cmd, "fail") == 0) {
			check->server->check.health = 0;
			status = HCHK_STATUS_L7STS;
			hs = cmd;
		}
		/* admin statuses */
		else if (strcasecmp(cmd, "ready") == 0) {
			as = cmd;
		}
		else if (strcasecmp(cmd, "drain") == 0) {
			as = cmd;
		}
		else if (strcasecmp(cmd, "maint") == 0) {
			as = cmd;
		}
		/* try to parse a weight here and keep the last one */
		else if (isdigit((unsigned char)*cmd) && strchr(cmd, '%') != NULL) {
			ps = cmd;
		}
		/* try to parse a maxconn here */
		else if (strncasecmp(cmd, "maxconn:", strlen("maxconn:")) == 0) {
			cs = cmd;
		}
		else {
			/* keep a copy of the first error */
			if (!err)
				err = cmd;
		}
		/* skip to next word */
		cmd = p;
	}
	/* here, cmd points either to \0 or to the beginning of a
	 * description. Skip possible leading spaces.
	 */
	while (*cmd == ' ' || *cmd == '\n')
		cmd++;

	/* First, update the admin status so that we avoid sending other
	 * possibly useless warnings and can also update the health if
	 * present after going back up.
	 */
	if (as) {
		if (strcasecmp(as, "drain") == 0)
			srv_adm_set_drain(check->server);
		else if (strcasecmp(as, "maint") == 0)
			srv_adm_set_maint(check->server);
		else
			srv_adm_set_ready(check->server);
	}

	/* now change weights */
	if (ps) {
		const char *msg;

		msg = server_parse_weight_change_request(check->server, ps);
		if (!wrn || !*wrn)
			wrn = msg;
	}

	if (cs) {
		const char *msg;

		cs += strlen("maxconn:");

		msg = server_parse_maxconn_change_request(check->server, cs);
		if (!wrn || !*wrn)
			wrn = msg;
	}

	/* and finally health status */
	if (hs) {
		/* We'll report some of the warnings and errors we have
		 * here. Down reports are critical, we leave them untouched.
		 * Lack of report, or report of 'UP' leaves the room for
		 * ERR first, then WARN.
		 */
		const char *msg = cmd;
		struct buffer *t;

		if (!*msg || status == HCHK_STATUS_L7OKD) {
			if (err && *err)
				msg = err;
			else if (wrn && *wrn)
				msg = wrn;
		}

		t = get_trash_chunk();
		chunk_printf(t, "via agent : %s%s%s%s",
			     hs, *msg ? " (" : "",
			     msg, *msg ? ")" : "");
		set_server_check_status(check, status, t->area);
	}
	else if (err && *err) {
		/* No status change but we'd like to report something odd.
		 * Just report the current state and copy the message.
		 */
		chunk_printf(&trash, "agent reports an error : %s", err);
		set_server_check_status(check, status/*check->status*/, trash.area);
	}
	else if (wrn && *wrn) {
		/* No status change but we'd like to report something odd.
		 * Just report the current state and copy the message.
		 */
		chunk_printf(&trash, "agent warns : %s", wrn);
		set_server_check_status(check, status/*check->status*/, trash.area);
	}
	else
		set_server_check_status(check, status, NULL);

  out:
	return ret;

  wait_more_data:
	ret = TCPCHK_EVAL_WAIT;
	goto out;
}

/* Evaluates a TCPCHK_ACT_CONNECT rule. Returns TCPCHK_EVAL_WAIT to wait the
 * connection establishment, TCPCHK_EVAL_CONTINUE to evaluate the next rule or
 * TCPCHK_EVAL_STOP if an error occurred.
 */
enum tcpcheck_eval_ret tcpcheck_eval_connect(struct check *check, struct tcpcheck_rule *rule)
{
	enum tcpcheck_eval_ret ret = TCPCHK_EVAL_CONTINUE;
	struct tcpcheck_connect *connect = &rule->connect;
	struct proxy *proxy = check->proxy;
	struct server *s = check->server;
	struct task *t = check->task;
	struct conn_stream *cs = check->cs;
	struct connection *conn = cs_conn(cs);
	struct protocol *proto;
	struct xprt_ops *xprt;
	struct tcpcheck_rule *next;
	int status, port;

	next = get_next_tcpcheck_rule(check->tcpcheck_rules, rule);

	/* current connection already created, check if it is established or not */
	if (conn) {
		if (conn->flags & CO_FL_WAIT_XPRT) {
			/* We are still waiting for the connection establishment */
			if (next && next->action == TCPCHK_ACT_SEND) {
				if (!(check->wait_list.events & SUB_RETRY_SEND))
					conn->mux->subscribe(cs, SUB_RETRY_SEND, &check->wait_list);
				ret = TCPCHK_EVAL_WAIT;
			}
			else
				ret = tcpcheck_eval_recv(check, rule);
		}
		goto out;
	}

	/* Note: here check->cs = cs = conn = NULL */

	/* Always release input and output buffer when a new connect is evaluated */
	check_release_buf(check, &check->bi);
	check_release_buf(check, &check->bo);

	/* No connection, prepare a new one */
	cs = cs_new(NULL, (s ? &s->obj_type : &proxy->obj_type));
	if (!cs) {
		chunk_printf(&trash, "TCPCHK error allocating connection at step %d",
			     tcpcheck_get_step_id(check, rule));
		if (rule->comment)
			chunk_appendf(&trash, " comment: '%s'", rule->comment);
		set_server_check_status(check, HCHK_STATUS_SOCKERR, trash.area);
		ret = TCPCHK_EVAL_STOP;
		goto out;
	}

	tasklet_set_tid(check->wait_list.tasklet, tid);

	check->cs = cs;
	conn = cs->conn;
	conn_set_owner(conn, check->sess, NULL);

	/* Maybe there were an older connection we were waiting on */
	check->wait_list.events = 0;

	/* no client address */
	if (!sockaddr_alloc(&conn->dst, NULL, 0)) {
		status = SF_ERR_RESOURCE;
		goto fail_check;
	}

	/* connect to the connect rule addr if specified, otherwise the check
	 * addr if specified on the server. otherwise, use the server addr (it
	 * MUST exist at this step).
	 */
	*conn->dst = (is_addr(&connect->addr)
		      ? connect->addr
		      : (is_addr(&check->addr) ? check->addr : s->addr));
	proto = protocol_by_family(conn->dst->ss_family);

	port = 0;
	if (!port && connect->port)
		port = connect->port;
	if (!port && connect->port_expr) {
		struct sample *smp;

		smp = sample_fetch_as_type(check->proxy, check->sess, NULL,
					   SMP_OPT_DIR_REQ | SMP_OPT_FINAL,
					   connect->port_expr, SMP_T_SINT);
		if (smp)
			port = smp->data.u.sint;
	}
	if (!port && is_inet_addr(&connect->addr))
		port = get_host_port(&connect->addr);
	if (!port && check->port)
		port = check->port;
	if (!port && is_inet_addr(&check->addr))
		port = get_host_port(&check->addr);
	if (!port) {
		/* The server MUST exist here */
		port = s->svc_port;
	}
	set_host_port(conn->dst, port);

	xprt = ((connect->options & TCPCHK_OPT_SSL)
		? xprt_get(XPRT_SSL)
		: ((connect->options & TCPCHK_OPT_DEFAULT_CONNECT) ? check->xprt : xprt_get(XPRT_RAW)));

	conn_prepare(conn, proto, xprt);
	cs_attach(cs, check, &check_conn_cb);

	if ((connect->options & TCPCHK_OPT_SOCKS4) && s && (s->flags & SRV_F_SOCKS4_PROXY)) {
		conn->send_proxy_ofs = 1;
		conn->flags |= CO_FL_SOCKS4;
	}
	else if ((connect->options & TCPCHK_OPT_DEFAULT_CONNECT) && s && s->check.via_socks4 && (s->flags & SRV_F_SOCKS4_PROXY)) {
		conn->send_proxy_ofs = 1;
		conn->flags |= CO_FL_SOCKS4;
	}

	if (connect->options & TCPCHK_OPT_SEND_PROXY) {
		conn->send_proxy_ofs = 1;
		conn->flags |= CO_FL_SEND_PROXY;
	}
	else if ((connect->options & TCPCHK_OPT_DEFAULT_CONNECT) && s && s->check.send_proxy && !(check->state & CHK_ST_AGENT)) {
		conn->send_proxy_ofs = 1;
		conn->flags |= CO_FL_SEND_PROXY;
	}

	status = SF_ERR_INTERNAL;
	if (proto && proto->connect) {
		int flags = 0;

		if (check->tcpcheck_rules->flags & TCPCHK_RULES_PROTO_CHK)
			flags |= CONNECT_HAS_DATA;
		if (!next || next->action != TCPCHK_ACT_EXPECT)
			flags |= CONNECT_DELACK_ALWAYS;
		status = proto->connect(conn, flags);
	}

	if (status != SF_ERR_NONE)
		goto fail_check;

	conn_set_private(conn);
	conn->ctx = cs;

#ifdef USE_OPENSSL
	if (connect->sni)
		ssl_sock_set_servername(conn, connect->sni);
	else if ((connect->options & TCPCHK_OPT_DEFAULT_CONNECT) && s && s->check.sni)
		ssl_sock_set_servername(conn, s->check.sni);

	if (connect->alpn)
		ssl_sock_set_alpn(conn, (unsigned char *)connect->alpn, connect->alpn_len);
	else if ((connect->options & TCPCHK_OPT_DEFAULT_CONNECT) && s && s->check.alpn_str)
		ssl_sock_set_alpn(conn, (unsigned char *)s->check.alpn_str, s->check.alpn_len);
#endif

	if (conn_ctrl_ready(conn) && (connect->options & TCPCHK_OPT_LINGER)) {
		/* Some servers don't like reset on close */
		fdtab[cs->conn->handle.fd].linger_risk = 0;
	}

	if (conn_ctrl_ready(conn) && (conn->flags & (CO_FL_SEND_PROXY | CO_FL_SOCKS4))) {
		if (xprt_add_hs(conn) < 0)
			status = SF_ERR_RESOURCE;
	}

	/* The mux may be initialized now if there isn't server attached to the
	 * check (email alerts) or if there is a mux proto specified or if there
	 * is no alpn.
	 */
	if (!s || ((connect->options & TCPCHK_OPT_DEFAULT_CONNECT) && check->mux_proto) ||
	    connect->mux_proto || (!connect->alpn && !check->alpn_str)) {
		const struct mux_ops *mux_ops;

		if (connect->mux_proto)
			mux_ops = connect->mux_proto->mux;
		else if ((connect->options & TCPCHK_OPT_DEFAULT_CONNECT) && check->mux_proto)
			mux_ops = check->mux_proto->mux;
		else {
			int mode = ((check->tcpcheck_rules->flags & TCPCHK_RULES_PROTO_CHK) == TCPCHK_RULES_HTTP_CHK
				    ? PROTO_MODE_HTTP
				    : PROTO_MODE_TCP);

			mux_ops = conn_get_best_mux(conn, IST_NULL, PROTO_SIDE_BE, mode);
		}
		if (mux_ops && conn_install_mux(conn, mux_ops, cs, proxy, check->sess) < 0) {
			status = SF_ERR_INTERNAL;
			goto fail_check;
		}
	}

  fail_check:
	/* It can return one of :
	 *  - SF_ERR_NONE if everything's OK
	 *  - SF_ERR_SRVTO if there are no more servers
	 *  - SF_ERR_SRVCL if the connection was refused by the server
	 *  - SF_ERR_PRXCOND if the connection has been limited by the proxy (maxconn)
	 *  - SF_ERR_RESOURCE if a system resource is lacking (eg: fd limits, ports, ...)
	 *  - SF_ERR_INTERNAL for any other purely internal errors
	 * Additionally, in the case of SF_ERR_RESOURCE, an emergency log will be emitted.
	 * Note that we try to prevent the network stack from sending the ACK during the
	 * connect() when a pure TCP check is used (without PROXY protocol).
	 */
	switch (status) {
	case SF_ERR_NONE:
		/* we allow up to min(inter, timeout.connect) for a connection
		 * to establish but only when timeout.check is set as it may be
		 * to short for a full check otherwise
		 */
		t->expire = tick_add(now_ms, MS_TO_TICKS(check->inter));

		if (proxy->timeout.check && proxy->timeout.connect) {
			int t_con = tick_add(now_ms, proxy->timeout.connect);
			t->expire = tick_first(t->expire, t_con);
		}
		break;
	case SF_ERR_SRVTO: /* ETIMEDOUT */
	case SF_ERR_SRVCL: /* ECONNREFUSED, ENETUNREACH, ... */
	case SF_ERR_PRXCOND:
	case SF_ERR_RESOURCE:
	case SF_ERR_INTERNAL:
		chk_report_conn_err(check, errno, 0);
		ret = TCPCHK_EVAL_STOP;
		goto out;
	}

	/* don't do anything until the connection is established */
	if (conn->flags & CO_FL_WAIT_XPRT) {
		if (conn->mux) {
			if (next && next->action == TCPCHK_ACT_SEND)
				conn->mux->subscribe(cs, SUB_RETRY_SEND, &check->wait_list);
			else
				conn->mux->subscribe(cs, SUB_RETRY_RECV, &check->wait_list);
		}
		ret = TCPCHK_EVAL_WAIT;
		goto out;
	}

  out:
	if (conn && check->result == CHK_RES_FAILED)
		conn->flags |= CO_FL_ERROR;

	if (ret == TCPCHK_EVAL_CONTINUE && check->proxy->timeout.check)
		check->task->expire = tick_add_ifset(now_ms, check->proxy->timeout.check);

	return ret;
}

/* Evaluates a TCPCHK_ACT_SEND rule. Returns TCPCHK_EVAL_WAIT if outgoing data
 * were not fully sent, TCPCHK_EVAL_CONTINUE to evaluate the next rule or
 * TCPCHK_EVAL_STOP if an error occurred.
 */
enum tcpcheck_eval_ret tcpcheck_eval_send(struct check *check, struct tcpcheck_rule *rule)
{
	enum tcpcheck_eval_ret ret = TCPCHK_EVAL_CONTINUE;
	struct tcpcheck_send *send = &rule->send;
	struct conn_stream *cs = check->cs;
	struct connection *conn = cs_conn(cs);
	struct buffer *tmp = NULL;
	struct htx *htx = NULL;
	int connection_hdr = 0;

	if (check->state & CHK_ST_OUT_ALLOC) {
		ret = TCPCHK_EVAL_WAIT;
		goto out;
	}

	if (!check_get_buf(check, &check->bo)) {
		check->state |= CHK_ST_OUT_ALLOC;
		ret = TCPCHK_EVAL_WAIT;
		goto out;
	}

	/* Data already pending in the output buffer, send them now */
	if (b_data(&check->bo))
		goto do_send;

	/* Always release input buffer when a new send is evaluated */
	check_release_buf(check, &check->bi);

	switch (send->type) {
	case TCPCHK_SEND_STRING:
	case TCPCHK_SEND_BINARY:
		if (istlen(send->data) >= b_size(&check->bo)) {
			chunk_printf(&trash, "tcp-check send : string too large (%u) for buffer size (%u) at step %d",
				     (unsigned int)istlen(send->data), (unsigned int)b_size(&check->bo),
				     tcpcheck_get_step_id(check, rule));
			set_server_check_status(check, HCHK_STATUS_L7RSP, trash.area);
			ret = TCPCHK_EVAL_STOP;
			goto out;
		}
		b_putist(&check->bo, send->data);
		break;
	case TCPCHK_SEND_STRING_LF:
		check->bo.data = sess_build_logline(check->sess, NULL, b_orig(&check->bo), b_size(&check->bo), &rule->send.fmt);
		if (!b_data(&check->bo))
			goto out;
		break;
	case TCPCHK_SEND_BINARY_LF: {
		int len = b_size(&check->bo);

		tmp = alloc_trash_chunk();
		if (!tmp)
			goto error_lf;
		tmp->data = sess_build_logline(check->sess, NULL, b_orig(tmp), b_size(tmp), &rule->send.fmt);
		if (!b_data(tmp))
			goto out;
		tmp->area[tmp->data] = '\0';
		if (parse_binary(b_orig(tmp),  &check->bo.area, &len, NULL) == 0)
			goto error_lf;
		check->bo.data = len;
		break;
	}
	case TCPCHK_SEND_HTTP: {
		struct htx_sl *sl;
		struct ist meth, uri, vsn, clen, body;
		unsigned int slflags = 0;

		tmp = alloc_trash_chunk();
		if (!tmp)
			goto error_htx;

		meth = ((send->http.meth.meth == HTTP_METH_OTHER)
			? ist2(send->http.meth.str.area, send->http.meth.str.data)
			: http_known_methods[send->http.meth.meth]);
		if (send->http.flags & TCPCHK_SND_HTTP_FL_URI_FMT) {
			tmp->data = sess_build_logline(check->sess, NULL, b_orig(tmp), b_size(tmp), &send->http.uri_fmt);
			uri = (b_data(tmp) ? ist2(b_orig(tmp), b_data(tmp)) : ist("/"));
		}
		else
			uri = (isttest(send->http.uri) ? send->http.uri : ist("/"));
		vsn = (isttest(send->http.vsn) ? send->http.vsn : ist("HTTP/1.0"));

		if ((istlen(vsn) == 6 && *(vsn.ptr+5) == '2') ||
		    (istlen(vsn) == 8 && (*(vsn.ptr+5) > '1' || (*(vsn.ptr+5) == '1' && *(vsn.ptr+7) >= '1'))))
			slflags |= HTX_SL_F_VER_11;
		slflags |= (HTX_SL_F_XFER_LEN|HTX_SL_F_CLEN);
		if (!isttest(send->http.body))
			slflags |= HTX_SL_F_BODYLESS;

		htx = htx_from_buf(&check->bo);
		sl = htx_add_stline(htx, HTX_BLK_REQ_SL, slflags, meth, uri, vsn);
		if (!sl)
			goto error_htx;
		sl->info.req.meth = send->http.meth.meth;
		if (!http_update_host(htx, sl, uri))
			goto error_htx;

		if (!LIST_ISEMPTY(&send->http.hdrs)) {
			struct tcpcheck_http_hdr *hdr;
			struct ist hdr_value;

			list_for_each_entry(hdr, &send->http.hdrs, list) {
				chunk_reset(tmp);
                                tmp->data = sess_build_logline(check->sess, NULL, b_orig(tmp), b_size(tmp), &hdr->value);
				if (!b_data(tmp))
					continue;
				hdr_value = ist2(b_orig(tmp), b_data(tmp));
				if (!htx_add_header(htx, hdr->name, hdr_value))
					goto error_htx;
				if ((sl->flags & HTX_SL_F_HAS_AUTHORITY) && isteqi(hdr->name, ist("host"))) {
					if (!http_update_authority(htx, sl, hdr_value))
						goto error_htx;
				}
				if (isteqi(hdr->name, ist("connection")))
					connection_hdr = 1;
			}

		}
		if (check->proxy->options2 & PR_O2_CHK_SNDST) {
			chunk_reset(tmp);
			httpchk_build_status_header(check->server, tmp);
			if (!htx_add_header(htx, ist("X-Haproxy-Server-State"), ist2(b_orig(tmp), b_data(tmp))))
				goto error_htx;
		}


		if (send->http.flags & TCPCHK_SND_HTTP_FL_BODY_FMT) {
			chunk_reset(tmp);
			tmp->data = sess_build_logline(check->sess, NULL, b_orig(tmp), b_size(tmp), &send->http.body_fmt);
			body = ist2(b_orig(tmp), b_data(tmp));
		}
		else
			body = send->http.body;
		clen = ist((!istlen(body) ? "0" : ultoa(istlen(body))));

		if ((!connection_hdr && !htx_add_header(htx, ist("Connection"), ist("close"))) ||
		    !htx_add_header(htx, ist("Content-length"), clen))
			goto error_htx;


		if (!htx_add_endof(htx, HTX_BLK_EOH) ||
		    (istlen(body) && !htx_add_data_atonce(htx, body)))
			goto error_htx;

		htx->flags |= HTX_FL_EOI; /* no more data are expected. Only EOM remains to add now */
		if (!htx_add_endof(htx, HTX_BLK_EOM))
			goto error_htx;

		htx_to_buf(htx, &check->bo);
		break;
	}
	case TCPCHK_SEND_UNDEF:
		/* Should never happen. */
		ret = TCPCHK_EVAL_STOP;
		goto out;
	};

  do_send:
	if (conn->mux->snd_buf(cs, &check->bo,
			       (IS_HTX_CONN(conn) ? (htxbuf(&check->bo))->data: b_data(&check->bo)), 0) <= 0) {
		if ((conn->flags & CO_FL_ERROR) || (cs->flags & CS_FL_ERROR)) {
			ret = TCPCHK_EVAL_STOP;
			goto out;
		}
	}
	if ((IS_HTX_CONN(conn) && !htx_is_empty(htxbuf(&check->bo))) || b_data(&check->bo)) {
		cs->conn->mux->subscribe(cs, SUB_RETRY_SEND, &check->wait_list);
		ret = TCPCHK_EVAL_WAIT;
		goto out;
	}

  out:
	free_trash_chunk(tmp);
	if (!b_data(&check->bo) || ret == TCPCHK_EVAL_STOP)
		check_release_buf(check, &check->bo);
	return ret;

  error_htx:
	if (htx) {
		htx_reset(htx);
		htx_to_buf(htx, &check->bo);
	}
	chunk_printf(&trash, "tcp-check send : failed to build HTTP request at step %d",
		     tcpcheck_get_step_id(check, rule));
	set_server_check_status(check, HCHK_STATUS_L7RSP, trash.area);
	ret = TCPCHK_EVAL_STOP;
	goto out;

  error_lf:
	chunk_printf(&trash, "tcp-check send : failed to build log-format string at step %d",
		     tcpcheck_get_step_id(check, rule));
	set_server_check_status(check, HCHK_STATUS_L7RSP, trash.area);
	ret = TCPCHK_EVAL_STOP;
	goto out;

}

/* Try to receive data before evaluating a tcp-check expect rule. Returns
 * TCPCHK_EVAL_WAIT if it is already subscribed on receive events or if nothing
 * was received, TCPCHK_EVAL_CONTINUE to evaluate the expect rule or
 * TCPCHK_EVAL_STOP if an error occurred.
 */
enum tcpcheck_eval_ret tcpcheck_eval_recv(struct check *check, struct tcpcheck_rule *rule)
{
	struct conn_stream *cs = check->cs;
	struct connection *conn = cs_conn(cs);
	enum tcpcheck_eval_ret ret = TCPCHK_EVAL_CONTINUE;
	size_t max, read, cur_read = 0;
	int is_empty;
	int read_poll = MAX_READ_POLL_LOOPS;

	if (check->wait_list.events & SUB_RETRY_RECV)
		goto wait_more_data;

	if (cs->flags & CS_FL_EOS)
		goto end_recv;

	if (check->state & CHK_ST_IN_ALLOC)
		goto wait_more_data;

	if (!check_get_buf(check, &check->bi)) {
		check->state |= CHK_ST_IN_ALLOC;
		goto wait_more_data;
	}

	/* errors on the connection and the conn-stream were already checked */

	/* prepare to detect if the mux needs more room */
	cs->flags &= ~CS_FL_WANT_ROOM;

	while ((cs->flags & CS_FL_RCV_MORE) ||
	       (!(conn->flags & CO_FL_ERROR) && !(cs->flags & (CS_FL_ERROR|CS_FL_EOS)))) {
		max = (IS_HTX_CS(cs) ?  htx_free_space(htxbuf(&check->bi)) : b_room(&check->bi));
		read = conn->mux->rcv_buf(cs, &check->bi, max, 0);
		cur_read += read;
		if (!read ||
		    (cs->flags & CS_FL_WANT_ROOM) ||
		    (--read_poll <= 0) ||
		    (read < max && read >= global.tune.recv_enough))
			break;
	}

  end_recv:
	is_empty = (IS_HTX_CS(cs) ? htx_is_empty(htxbuf(&check->bi)) : !b_data(&check->bi));
	if (is_empty && ((conn->flags & CO_FL_ERROR) || (cs->flags & CS_FL_ERROR))) {
		/* Report network errors only if we got no other data. Otherwise
		 * we'll let the upper layers decide whether the response is OK
		 * or not. It is very common that an RST sent by the server is
		 * reported as an error just after the last data chunk.
		 */
		goto stop;
	}
	if (!cur_read) {
		if (!(cs->flags & (CS_FL_WANT_ROOM|CS_FL_ERROR|CS_FL_EOS))) {
			conn->mux->subscribe(cs, SUB_RETRY_RECV, &check->wait_list);
			goto wait_more_data;
		}
		if (is_empty) {
			int status;

			chunk_printf(&trash, "TCPCHK got an empty response at step %d",
				     tcpcheck_get_step_id(check, rule));
			if (rule->comment)
				chunk_appendf(&trash, " comment: '%s'", rule->comment);

			status = ((rule->expect.err_status != HCHK_STATUS_UNKNOWN) ? rule->expect.err_status : HCHK_STATUS_L7RSP);
			set_server_check_status(check, status, trash.area);
			goto stop;
		}
	}

  out:
	if (!b_data(&check->bi) || ret == TCPCHK_EVAL_STOP)
		check_release_buf(check, &check->bi);
	return ret;

  stop:
	ret = TCPCHK_EVAL_STOP;
	goto out;

  wait_more_data:
	ret = TCPCHK_EVAL_WAIT;
	goto out;
}

/* Evaluates an HTTP TCPCHK_ACT_EXPECT rule. If <last_read> is set , no more data
 * are expected. Returns TCPCHK_EVAL_WAIT to wait for more data,
 * TCPCHK_EVAL_CONTINUE to evaluate the next rule or TCPCHK_EVAL_STOP if an
 * error occurred.
 */
enum tcpcheck_eval_ret tcpcheck_eval_expect_http(struct check *check, struct tcpcheck_rule *rule, int last_read)
{
	struct htx *htx = htxbuf(&check->bi);
	struct htx_sl *sl;
	struct htx_blk *blk;
	enum tcpcheck_eval_ret ret = TCPCHK_EVAL_CONTINUE;
	struct tcpcheck_expect *expect = &rule->expect;
	struct buffer *msg = NULL, *tmp = NULL, *nbuf = NULL, *vbuf = NULL;
	enum healthcheck_status status = HCHK_STATUS_L7RSP;
	struct ist desc = IST_NULL;
	int i, match, inverse;

	last_read |= (!htx_free_data_space(htx) || (htx_get_tail_type(htx) == HTX_BLK_EOM));

	if (htx->flags & HTX_FL_PARSING_ERROR) {
		status = HCHK_STATUS_L7RSP;
		goto error;
	}

	if (htx_is_empty(htx)) {
		if (last_read) {
			status = HCHK_STATUS_L7RSP;
			goto error;
		}
		goto wait_more_data;
	}

	sl = http_get_stline(htx);
	check->code = sl->info.res.status;

	if (check->server &&
	    (check->server->proxy->options & PR_O_DISABLE404) &&
	    (check->server->next_state != SRV_ST_STOPPED) &&
	    (check->code == 404)) {
		/* 404 may be accepted as "stopping" only if the server was up */
		goto out;
	}

	inverse = !!(expect->flags & TCPCHK_EXPT_FL_INV);
	/* Make GCC happy ; initialize match to a failure state. */
	match = inverse;
	status = expect->err_status;

	switch (expect->type) {
	case TCPCHK_EXPECT_HTTP_STATUS:
		match = 0;
		for (i = 0; i < expect->codes.num; i++) {
			if (sl->info.res.status >= expect->codes.codes[i][0] &&
			    sl->info.res.status <= expect->codes.codes[i][1]) {
				match = 1;
				break;
			}
		}

		/* Set status and description in case of error */
		status = ((status != HCHK_STATUS_UNKNOWN) ? status : HCHK_STATUS_L7STS);
		if (LIST_ISEMPTY(&expect->onerror_fmt))
			desc = htx_sl_res_reason(sl);
		break;
	case TCPCHK_EXPECT_HTTP_STATUS_REGEX:
		match = regex_exec2(expect->regex, HTX_SL_RES_CPTR(sl), HTX_SL_RES_CLEN(sl));

		/* Set status and description in case of error */
		status = ((status != HCHK_STATUS_UNKNOWN) ? status : HCHK_STATUS_L7STS);
		if (LIST_ISEMPTY(&expect->onerror_fmt))
			desc = htx_sl_res_reason(sl);
		break;

	case TCPCHK_EXPECT_HTTP_HEADER: {
		struct http_hdr_ctx ctx;
		struct ist npat, vpat, value;
		int full = (expect->flags & (TCPCHK_EXPT_FL_HTTP_HVAL_NONE|TCPCHK_EXPT_FL_HTTP_HVAL_FULL));

		if (expect->flags & TCPCHK_EXPT_FL_HTTP_HNAME_FMT) {
			nbuf = alloc_trash_chunk();
			if (!nbuf) {
				status = HCHK_STATUS_L7RSP;
				desc = ist("Failed to allocate buffer to eval log-format string");
				goto error;
			}
			nbuf->data = sess_build_logline(check->sess, NULL, b_orig(nbuf), b_size(nbuf), &expect->hdr.name_fmt);
			if (!b_data(nbuf)) {
				status = HCHK_STATUS_L7RSP;
				desc = ist("log-format string evaluated to an empty string");
				goto error;
			}
			npat = ist2(b_orig(nbuf), b_data(nbuf));
		}
		else if (!(expect->flags & TCPCHK_EXPT_FL_HTTP_HNAME_REG))
			npat = expect->hdr.name;

		if (expect->flags & TCPCHK_EXPT_FL_HTTP_HVAL_FMT) {
			vbuf = alloc_trash_chunk();
			if (!vbuf) {
				status = HCHK_STATUS_L7RSP;
				desc = ist("Failed to allocate buffer to eval log-format string");
				goto error;
			}
			vbuf->data = sess_build_logline(check->sess, NULL, b_orig(vbuf), b_size(vbuf), &expect->hdr.value_fmt);
			if (!b_data(vbuf)) {
				status = HCHK_STATUS_L7RSP;
				desc = ist("log-format string evaluated to an empty string");
				goto error;
			}
			vpat = ist2(b_orig(vbuf), b_data(vbuf));
		}
		else if (!(expect->flags & TCPCHK_EXPT_FL_HTTP_HVAL_REG))
			vpat = expect->hdr.value;

		match = 0;
		ctx.blk = NULL;
		while (1) {
			switch (expect->flags & TCPCHK_EXPT_FL_HTTP_HNAME_TYPE) {
			case TCPCHK_EXPT_FL_HTTP_HNAME_STR:
				if (!http_find_str_header(htx, npat, &ctx, full))
					goto end_of_match;
				break;
			case TCPCHK_EXPT_FL_HTTP_HNAME_BEG:
				if (!http_find_pfx_header(htx, npat, &ctx, full))
					goto end_of_match;
				break;
			case TCPCHK_EXPT_FL_HTTP_HNAME_END:
				if (!http_find_sfx_header(htx, npat, &ctx, full))
					goto end_of_match;
				break;
			case TCPCHK_EXPT_FL_HTTP_HNAME_SUB:
				if (!http_find_sub_header(htx, npat, &ctx, full))
					goto end_of_match;
				break;
			case TCPCHK_EXPT_FL_HTTP_HNAME_REG:
				if (!http_match_header(htx, expect->hdr.name_re, &ctx, full))
					goto end_of_match;
				break;
			default:
				/* should never happen */
				goto end_of_match;
			}

			/* A header has matched the name pattern, let's test its
			 * value now (always defined from there). If there is no
			 * value pattern, it is a good match.
			 */

			if (expect->flags & TCPCHK_EXPT_FL_HTTP_HVAL_NONE) {
				match = 1;
				goto end_of_match;
			}

			value = ctx.value;
			switch (expect->flags & TCPCHK_EXPT_FL_HTTP_HVAL_TYPE) {
			case TCPCHK_EXPT_FL_HTTP_HVAL_STR:
				if (isteq(value, vpat)) {
					match = 1;
					goto end_of_match;
				}
				break;
			case TCPCHK_EXPT_FL_HTTP_HVAL_BEG:
				if (istlen(value) < istlen(vpat))
					break;
				value = ist2(istptr(value), istlen(vpat));
				if (isteq(value, vpat)) {
					match = 1;
					goto end_of_match;
				}
				break;
			case TCPCHK_EXPT_FL_HTTP_HVAL_END:
				if (istlen(value) < istlen(vpat))
					break;
				value = ist2(istptr(value) + istlen(value) - istlen(vpat), istlen(vpat));
				if (isteq(value, vpat)) {
					match = 1;
					goto end_of_match;
				}
				break;
			case TCPCHK_EXPT_FL_HTTP_HVAL_SUB:
				if (isttest(istist(value, vpat))) {
					match = 1;
					goto end_of_match;
				}
				break;
			case TCPCHK_EXPT_FL_HTTP_HVAL_REG:
				if (regex_exec2(expect->hdr.value_re, istptr(value), istlen(value))) {
					match = 1;
					goto end_of_match;
				}
				break;
			}
		}

	  end_of_match:
		status = ((status != HCHK_STATUS_UNKNOWN) ? status : HCHK_STATUS_L7STS);
		if (LIST_ISEMPTY(&expect->onerror_fmt))
			desc = htx_sl_res_reason(sl);
		break;
	}

	case TCPCHK_EXPECT_HTTP_BODY:
	case TCPCHK_EXPECT_HTTP_BODY_REGEX:
	case TCPCHK_EXPECT_HTTP_BODY_LF:
		match = 0;
		chunk_reset(&trash);
		for (blk = htx_get_head_blk(htx); blk; blk = htx_get_next_blk(htx, blk)) {
			enum htx_blk_type type = htx_get_blk_type(blk);

			if (type == HTX_BLK_EOM || type == HTX_BLK_TLR || type == HTX_BLK_EOT)
				break;
			if (type == HTX_BLK_DATA) {
				if (!chunk_istcat(&trash, htx_get_blk_value(htx, blk)))
					break;
			}
		}

		if (!b_data(&trash)) {
			if (!last_read)
				goto wait_more_data;
			status = ((status != HCHK_STATUS_UNKNOWN) ? status : HCHK_STATUS_L7RSP);
			if (LIST_ISEMPTY(&expect->onerror_fmt))
				desc = ist("HTTP content check could not find a response body");
			goto error;
		}

		if (expect->type == TCPCHK_EXPECT_HTTP_BODY_LF) {
			tmp = alloc_trash_chunk();
			if (!tmp) {
				status = HCHK_STATUS_L7RSP;
				desc = ist("Failed to allocate buffer to eval log-format string");
				goto error;
			}
			tmp->data = sess_build_logline(check->sess, NULL, b_orig(tmp), b_size(tmp), &expect->fmt);
			if (!b_data(tmp)) {
				status = HCHK_STATUS_L7RSP;
				desc = ist("log-format string evaluated to an empty string");
				goto error;
			}
		}

		if (!last_read &&
		    ((expect->type == TCPCHK_EXPECT_HTTP_BODY && b_data(&trash) < istlen(expect->data)) ||
		     ((expect->type == TCPCHK_EXPECT_HTTP_BODY_LF && b_data(&trash) < b_data(tmp))) ||
		     (expect->min_recv > 0 && b_data(&trash) < expect->min_recv))) {
			ret = TCPCHK_EVAL_WAIT;
			goto out;
		}

		if (expect->type ==TCPCHK_EXPECT_HTTP_BODY)
			match = my_memmem(b_orig(&trash), b_data(&trash), istptr(expect->data), istlen(expect->data)) != NULL;
		else if (expect->type ==TCPCHK_EXPECT_HTTP_BODY_LF)
			match = my_memmem(b_orig(&trash), b_data(&trash), b_orig(tmp), b_data(tmp)) != NULL;
		else
			match = regex_exec2(expect->regex, b_orig(&trash), b_data(&trash));

		/* Wait for more data on mismatch only if no minimum is defined (-1),
		 * otherwise the absence of match is already conclusive.
		 */
		if (!match && !last_read && (expect->min_recv == -1)) {
			ret = TCPCHK_EVAL_WAIT;
			goto out;
		}

		/* Set status and description in case of error */
		status = ((status != HCHK_STATUS_UNKNOWN) ? status : HCHK_STATUS_L7RSP);
		if (LIST_ISEMPTY(&expect->onerror_fmt))
			desc = (inverse
				? ist("HTTP check matched unwanted content")
				: ist("HTTP content check did not match"));
		break;


	default:
		/* should never happen */
		status = ((status != HCHK_STATUS_UNKNOWN) ? status : HCHK_STATUS_L7RSP);
		goto error;
	}

	if (!(match ^ inverse))
		goto error;

  out:
	free_trash_chunk(tmp);
	free_trash_chunk(nbuf);
	free_trash_chunk(vbuf);
	free_trash_chunk(msg);
	return ret;

  error:
	ret = TCPCHK_EVAL_STOP;
	msg = alloc_trash_chunk();
	if (msg)
		tcpcheck_expect_onerror_message(msg, check, rule, 0, desc);
	set_server_check_status(check, status, (msg ? b_head(msg) : NULL));
	goto out;

  wait_more_data:
	ret = TCPCHK_EVAL_WAIT;
	goto out;
}

/* Evaluates a TCP TCPCHK_ACT_EXPECT rule. Returns TCPCHK_EVAL_WAIT to wait for
 * more data, TCPCHK_EVAL_CONTINUE to evaluate the next rule or TCPCHK_EVAL_STOP
 * if an error occurred.
 */
enum tcpcheck_eval_ret tcpcheck_eval_expect(struct check *check, struct tcpcheck_rule *rule, int last_read)
{
	enum tcpcheck_eval_ret ret = TCPCHK_EVAL_CONTINUE;
	struct tcpcheck_expect *expect = &rule->expect;
	struct buffer *msg = NULL, *tmp = NULL;
	struct ist desc = IST_NULL;
	enum healthcheck_status status;
	int match, inverse;

	last_read |= b_full(&check->bi);

	/* The current expect might need more data than the previous one, check again
	 * that the minimum amount data required to match is respected.
	 */
	if (!last_read) {
		if ((expect->type == TCPCHK_EXPECT_STRING || expect->type == TCPCHK_EXPECT_BINARY) &&
		    (b_data(&check->bi) < istlen(expect->data))) {
			ret = TCPCHK_EVAL_WAIT;
			goto out;
		}
		if (expect->min_recv > 0 && (b_data(&check->bi) < expect->min_recv)) {
			ret = TCPCHK_EVAL_WAIT;
			goto out;
		}
	}

	inverse = !!(expect->flags & TCPCHK_EXPT_FL_INV);
	/* Make GCC happy ; initialize match to a failure state. */
	match = inverse;
	status = ((expect->err_status != HCHK_STATUS_UNKNOWN) ? expect->err_status : HCHK_STATUS_L7RSP);

	switch (expect->type) {
	case TCPCHK_EXPECT_STRING:
	case TCPCHK_EXPECT_BINARY:
		match = my_memmem(b_head(&check->bi), b_data(&check->bi), istptr(expect->data), istlen(expect->data)) != NULL;
		break;
	case TCPCHK_EXPECT_STRING_REGEX:
		match = regex_exec2(expect->regex, b_head(&check->bi), MIN(b_data(&check->bi), b_size(&check->bi)-1));
		break;

	case TCPCHK_EXPECT_BINARY_REGEX:
		chunk_reset(&trash);
		dump_binary(&trash, b_head(&check->bi), b_data(&check->bi));
		match = regex_exec2(expect->regex, b_head(&trash), MIN(b_data(&trash), b_size(&trash)-1));
		break;

	case TCPCHK_EXPECT_STRING_LF:
	case TCPCHK_EXPECT_BINARY_LF:
		match = 0;
		tmp = alloc_trash_chunk();
		if (!tmp) {
			status = HCHK_STATUS_L7RSP;
			desc = ist("Failed to allocate buffer to eval format string");
			goto error;
		}
		tmp->data = sess_build_logline(check->sess, NULL, b_orig(tmp), b_size(tmp), &expect->fmt);
		if (!b_data(tmp)) {
			status = HCHK_STATUS_L7RSP;
			desc = ist("log-format string evaluated to an empty string");
			goto error;
		}
		if (expect->type == TCPCHK_EXPECT_BINARY_LF) {
			int len = tmp->data;
			if (parse_binary(b_orig(tmp),  &tmp->area, &len, NULL) == 0) {
				status = HCHK_STATUS_L7RSP;
				desc = ist("Failed to parse hexastring resulting of eval of a log-format string");
				goto error;
			}
			tmp->data = len;
		}
		if (b_data(&check->bi) < tmp->data) {
			if (!last_read) {
				ret = TCPCHK_EVAL_WAIT;
				goto out;
			}
			break;
		}
		match = my_memmem(b_head(&check->bi), b_data(&check->bi), b_orig(tmp), b_data(tmp)) != NULL;
		break;

	case TCPCHK_EXPECT_CUSTOM:
		if (expect->custom)
			ret = expect->custom(check, rule, last_read);
		goto out;
	default:
		/* Should never happen. */
		ret = TCPCHK_EVAL_STOP;
		goto out;
	}


	/* Wait for more data on mismatch only if no minimum is defined (-1),
	 * otherwise the absence of match is already conclusive.
	 */
	if (!match && !last_read && (expect->min_recv == -1)) {
		ret = TCPCHK_EVAL_WAIT;
		goto out;
	}

	/* Result as expected, next rule. */
	if (match ^ inverse)
		goto out;

  error:
	/* From this point on, we matched something we did not want, this is an error state. */
	ret = TCPCHK_EVAL_STOP;
	msg = alloc_trash_chunk();
	if (msg)
		tcpcheck_expect_onerror_message(msg, check, rule, match, desc);
	set_server_check_status(check, status, (msg ? b_head(msg) : NULL));
	free_trash_chunk(msg);

  out:
	free_trash_chunk(tmp);
	return ret;
}

/* Evaluates a TCPCHK_ACT_ACTION_KW rule. Returns TCPCHK_EVAL_CONTINUE to
 * evaluate the next rule or TCPCHK_EVAL_STOP if an error occurred. It never
 * waits.
 */
enum tcpcheck_eval_ret tcpcheck_eval_action_kw(struct check *check, struct tcpcheck_rule *rule)
{
	enum tcpcheck_eval_ret ret = TCPCHK_EVAL_CONTINUE;
	struct act_rule *act_rule;
	enum act_return act_ret;

	act_rule =rule->action_kw.rule;
	act_ret = act_rule->action_ptr(act_rule, check->proxy, check->sess, NULL, 0);
	if (act_ret != ACT_RET_CONT) {
		chunk_printf(&trash, "TCPCHK ACTION unexpected result at step %d\n",
			     tcpcheck_get_step_id(check, rule));
		set_server_check_status(check, HCHK_STATUS_L7RSP, trash.area);
		ret = TCPCHK_EVAL_STOP;
	}

	return ret;
}

/* Executes a tcp-check ruleset. Note that this is called both from the
 * connection's wake() callback and from the check scheduling task.  It returns
 * 0 on normal cases, or <0 if a close() has happened on an existing connection,
 * presenting the risk of an fd replacement.
 *
 * Please do NOT place any return statement in this function and only leave
 * via the out_end_tcpcheck label after setting retcode.
 */
int tcpcheck_main(struct check *check)
{
	struct tcpcheck_rule *rule;
	struct conn_stream *cs = check->cs;
	struct connection *conn = cs_conn(cs);
	int must_read = 1, last_read = 0;
	int retcode = 0;
	enum tcpcheck_eval_ret eval_ret;

	/* here, we know that the check is complete or that it failed */
	if (check->result != CHK_RES_UNKNOWN)
		goto out;

	/* Note: the conn-stream and the connection may only be undefined before
	 * the first rule evaluation (it is always a connect rule) or when the
	 * conn-stream allocation failed on a connect rule, during cs allocation.
	 */

	/* 1- check for connection error, if any */
	if ((conn && conn->flags & CO_FL_ERROR) || (cs && cs->flags & CS_FL_ERROR))
		goto out_end_tcpcheck;

	/* 2- check if a rule must be resume. It happens if check->current_step
	 *    is defined. */
	else if (check->current_step)
		rule = check->current_step;

	/* 3- It is the first evaluation. We must create a session and preset
	 *    tcp-check variables */
        else {
		struct tcpcheck_var *var;

		/* First evaluation, create a session */
		check->sess = session_new(&checks_fe, NULL, &check->obj_type);
		if (!check->sess) {
			chunk_printf(&trash, "TCPCHK error allocating check session");
			set_server_check_status(check, HCHK_STATUS_SOCKERR, trash.area);
			goto out_end_tcpcheck;
		}
		vars_init(&check->vars, SCOPE_CHECK);
		rule = LIST_NEXT(check->tcpcheck_rules->list, typeof(rule), list);

		/* Preset tcp-check variables */
		list_for_each_entry(var, &check->tcpcheck_rules->preset_vars, list) {
			struct sample smp;

			memset(&smp, 0, sizeof(smp));
			smp_set_owner(&smp, check->proxy, check->sess, NULL, SMP_OPT_FINAL);
			smp.data = var->data;
			vars_set_by_name_ifexist(istptr(var->name), istlen(var->name), &smp);
		}
	}

	/* Now evaluate the tcp-check rules */

	list_for_each_entry_from(rule, check->tcpcheck_rules->list, list) {
		check->code = 0;
		switch (rule->action) {
		case TCPCHK_ACT_CONNECT:
			/* release the previous connection (from a previous connect rule) */
			if (cs && check->current_step != rule) {
				cs_close(cs);
				if (check->wait_list.events)
					cs->conn->mux->unsubscribe(cs, check->wait_list.events, &check->wait_list);

				/* We may have been scheduled to run, and the I/O handler
				 * expects to have a cs, so remove the tasklet
				 */
				tasklet_remove_from_tasklet_list(check->wait_list.tasklet);
				cs_destroy(cs);
				cs = NULL;
				conn = NULL;
				check->cs = NULL;
				retcode = -1; /* do not reuse the fd in the caller! */
			}

			check->current_step = rule;
			eval_ret = tcpcheck_eval_connect(check, rule);

			/* Refresh conn-stream and connection */
			cs = check->cs;
			conn = cs_conn(cs);
			last_read = 0;
			must_read = ((cs && IS_HTX_CS(cs)) ? htx_is_empty(htxbuf(&check->bi)) : !b_data(&check->bi));
			break;
		case TCPCHK_ACT_SEND:
			check->current_step = rule;
			eval_ret = tcpcheck_eval_send(check, rule);
			must_read = 1;
			break;
		case TCPCHK_ACT_EXPECT:
			check->current_step = rule;
			if (must_read) {
				eval_ret = tcpcheck_eval_recv(check, rule);
				if (eval_ret == TCPCHK_EVAL_STOP)
					goto out_end_tcpcheck;
				else if (eval_ret == TCPCHK_EVAL_WAIT)
					goto out;
				last_read = ((conn->flags & CO_FL_ERROR) || (cs->flags & (CS_FL_ERROR|CS_FL_EOS)));
				must_read = 0;
			}

			eval_ret = ((check->tcpcheck_rules->flags & TCPCHK_RULES_PROTO_CHK) == TCPCHK_RULES_HTTP_CHK
				    ? tcpcheck_eval_expect_http(check, rule, last_read)
				    : tcpcheck_eval_expect(check, rule, last_read));

			if (eval_ret == TCPCHK_EVAL_WAIT) {
				check->current_step = rule->expect.head;
				if (!(check->wait_list.events & SUB_RETRY_RECV))
					conn->mux->subscribe(cs, SUB_RETRY_RECV, &check->wait_list);
			}
			break;
		case TCPCHK_ACT_ACTION_KW:
			/* Don't update the current step */
			eval_ret = tcpcheck_eval_action_kw(check, rule);
			break;
		default:
			/* Otherwise, just go to the next one and don't update
			 * the current step
			 */
			eval_ret = TCPCHK_EVAL_CONTINUE;
			break;
		}

		switch (eval_ret) {
		case TCPCHK_EVAL_CONTINUE:
			break;
		case TCPCHK_EVAL_WAIT:
			goto out;
		case TCPCHK_EVAL_STOP:
			goto out_end_tcpcheck;
		}
	}

	/* All rules was evaluated */
	if (check->current_step) {
		rule = check->current_step;

		if (rule->action == TCPCHK_ACT_EXPECT) {
			struct buffer *msg;
			enum healthcheck_status status;

			if (check->server &&
			    (check->server->proxy->options & PR_O_DISABLE404) &&
			    (check->server->next_state != SRV_ST_STOPPED) &&
			    (check->code == 404)) {
				set_server_check_status(check, HCHK_STATUS_L7OKCD, NULL);
				goto out_end_tcpcheck;
			}

			msg = alloc_trash_chunk();
			if (msg)
				tcpcheck_expect_onsuccess_message(msg, check, rule, IST_NULL);
			status = ((rule->expect.ok_status != HCHK_STATUS_UNKNOWN) ? rule->expect.ok_status : HCHK_STATUS_L7OKD);
			set_server_check_status(check, status, (msg ? b_head(msg) : "(tcp-check)"));
			free_trash_chunk(msg);
		}
		else if (rule->action == TCPCHK_ACT_CONNECT) {
			const char *msg = ((rule->connect.options & TCPCHK_OPT_IMPLICIT) ? NULL : "(tcp-check)");
			enum healthcheck_status status = HCHK_STATUS_L4OK;
#ifdef USE_OPENSSL
			if (ssl_sock_is_ssl(conn))
				status = HCHK_STATUS_L6OK;
#endif
			set_server_check_status(check, status, msg);
		}
		else
			set_server_check_status(check, HCHK_STATUS_L7OKD, "(tcp-check)");
	}
	else
		set_server_check_status(check, HCHK_STATUS_L7OKD, "(tcp-check)");

  out_end_tcpcheck:
	if ((conn && conn->flags & CO_FL_ERROR) || (cs && cs->flags & CS_FL_ERROR))
		chk_report_conn_err(check, errno, 0);

	/* the tcpcheck is finished, release in/out buffer now */
	check_release_buf(check, &check->bi);
	check_release_buf(check, &check->bo);

  out:
	return retcode;
}


/**************************************************************************/
/******************* Internals to parse tcp-check rules *******************/
/**************************************************************************/
struct action_kw_list tcp_check_keywords = {
	.list = LIST_HEAD_INIT(tcp_check_keywords.list),
};

/* Creates a tcp-check rule resulting from parsing a custom keyword. NULL is
 * returned on error.
 */
struct tcpcheck_rule *parse_tcpcheck_action(char **args, int cur_arg, struct proxy *px,
                                            struct list *rules, struct action_kw *kw,
                                            const char *file, int line, char **errmsg)
{
	struct tcpcheck_rule *chk = NULL;
	struct act_rule *actrule = NULL;

	actrule = calloc(1, sizeof(*actrule));
	if (!actrule) {
		memprintf(errmsg, "out of memory");
		goto error;
	}
	actrule->kw = kw;
	actrule->from = ACT_F_TCP_CHK;

	cur_arg++;
	if (kw->parse((const char **)args, &cur_arg, px, actrule, errmsg) == ACT_RET_PRS_ERR) {
		memprintf(errmsg, "'%s' : %s", kw->kw, *errmsg);
		goto error;
	}

	chk = calloc(1, sizeof(*chk));
	if (!chk) {
		memprintf(errmsg, "out of memory");
		goto error;
	}
	chk->action = TCPCHK_ACT_ACTION_KW;
	chk->action_kw.rule = actrule;
	return chk;

  error:
	free(actrule);
	return NULL;
}

/* Parses and creates a tcp-check connect or an http-check connect rule. NULL is
 * returned on error.
 */
struct tcpcheck_rule *parse_tcpcheck_connect(char **args, int cur_arg, struct proxy *px, struct list *rules,
                                             const char *file, int line, char **errmsg)
{
	struct tcpcheck_rule *chk = NULL;
	struct sockaddr_storage *sk = NULL;
	char *comment = NULL, *sni = NULL, *alpn = NULL;
	struct sample_expr *port_expr = NULL;
	const struct mux_proto_list *mux_proto = NULL;
	unsigned short conn_opts = 0;
	long port = 0;
	int alpn_len = 0;

	list_for_each_entry(chk, rules, list) {
		if (chk->action == TCPCHK_ACT_CONNECT)
			break;
		if (chk->action == TCPCHK_ACT_COMMENT ||
		    chk->action == TCPCHK_ACT_ACTION_KW ||
		    (chk->action == TCPCHK_ACT_SEND && (chk->send.http.flags & TCPCHK_SND_HTTP_FROM_OPT)))
			continue;

		memprintf(errmsg, "first step MUST also be a 'connect', "
			  "optionally preceded by a 'set-var', an 'unset-var' or a 'comment', "
			  "when there is a 'connect' step in the tcp-check ruleset");
		goto error;
	}

	cur_arg++;
	while (*(args[cur_arg])) {
		if (strcmp(args[cur_arg], "default") == 0)
			conn_opts |= TCPCHK_OPT_DEFAULT_CONNECT;
		else if (strcmp(args[cur_arg], "addr") == 0) {
			int port1, port2;

			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects <ipv4|ipv6> as argument.", args[cur_arg]);
				goto error;
			}

			sk = str2sa_range(args[cur_arg+1], NULL, &port1, &port2, NULL, NULL,
			                  errmsg, NULL, NULL, PA_O_RESOLVE | PA_O_PORT_OK | PA_O_STREAM | PA_O_CONNECT);
			if (!sk) {
				memprintf(errmsg, "'%s' : %s.", args[cur_arg], *errmsg);
				goto error;
			}

			cur_arg++;
		}
		else if (strcmp(args[cur_arg], "port") == 0) {
			const char *p, *end;

			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a port number or a sample expression as argument.", args[cur_arg]);
				goto error;
			}
			cur_arg++;

			port = 0;
			release_sample_expr(port_expr);
			p = args[cur_arg]; end = p + strlen(p);
			port = read_uint(&p, end);
			if (p != end) {
				int idx = 0;

				px->conf.args.ctx = ARGC_SRV;
				port_expr = sample_parse_expr((char *[]){args[cur_arg], NULL}, &idx,
							      file, line, errmsg, &px->conf.args, NULL);

				if (!port_expr) {
					memprintf(errmsg, "error detected while parsing port expression : %s", *errmsg);
					goto error;
				}
				if (!(port_expr->fetch->val & SMP_VAL_BE_CHK_RUL)) {
					memprintf(errmsg, "error detected while parsing port expression : "
						  " fetch method '%s' extracts information from '%s', "
						  "none of which is available here.\n",
						  args[cur_arg], sample_src_names(port_expr->fetch->use));
					goto error;
				}
				px->http_needed |= !!(port_expr->fetch->use & SMP_USE_HTTP_ANY);
			}
			else if (port > 65535 || port < 1) {
				memprintf(errmsg, "expects a valid TCP port (from range 1 to 65535) or a sample expression, got %s.",
					  args[cur_arg]);
				goto error;
			}
		}
		else if (strcmp(args[cur_arg], "proto") == 0) {
			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a MUX protocol as argument.", args[cur_arg]);
				goto error;
			}
			mux_proto = get_mux_proto(ist2(args[cur_arg+1], strlen(args[cur_arg+1])));
			if (!mux_proto) {
				memprintf(errmsg, "'%s' : unknown MUX protocol '%s'.", args[cur_arg], args[cur_arg+1]);
				goto error;
			}

			if (strcmp(args[0], "tcp-check") == 0 && mux_proto->mode != PROTO_MODE_TCP) {
				memprintf(errmsg, "'%s' : invalid MUX protocol '%s' for tcp-check", args[cur_arg], args[cur_arg+1]);
				goto error;
			}
			else if (strcmp(args[0], "http-check") == 0 && mux_proto->mode != PROTO_MODE_HTTP) {
				memprintf(errmsg, "'%s' : invalid MUX protocol '%s' for http-check", args[cur_arg], args[cur_arg+1]);
				goto error;
			}

			cur_arg++;
		}
		else if (strcmp(args[cur_arg], "comment") == 0) {
			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a string as argument.", args[cur_arg]);
				goto error;
			}
			cur_arg++;
			free(comment);
			comment = strdup(args[cur_arg]);
			if (!comment) {
				memprintf(errmsg, "out of memory");
				goto error;
			}
		}
		else if (strcmp(args[cur_arg], "send-proxy") == 0)
			conn_opts |= TCPCHK_OPT_SEND_PROXY;
		else if (strcmp(args[cur_arg], "via-socks4") == 0)
			conn_opts |= TCPCHK_OPT_SOCKS4;
		else if (strcmp(args[cur_arg], "linger") == 0)
			conn_opts |= TCPCHK_OPT_LINGER;
#ifdef USE_OPENSSL
		else if (strcmp(args[cur_arg], "ssl") == 0) {
			px->options |= PR_O_TCPCHK_SSL;
			conn_opts |= TCPCHK_OPT_SSL;
		}
		else if (strcmp(args[cur_arg], "sni") == 0) {
			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a string as argument.", args[cur_arg]);
				goto error;
			}
			cur_arg++;
			free(sni);
			sni = strdup(args[cur_arg]);
			if (!sni) {
				memprintf(errmsg, "out of memory");
				goto error;
			}
		}
		else if (strcmp(args[cur_arg], "alpn") == 0) {
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
			free(alpn);
			if (ssl_sock_parse_alpn(args[cur_arg + 1], &alpn, &alpn_len, errmsg)) {
				memprintf(errmsg, "'%s' : %s", args[cur_arg], *errmsg);
				goto error;
			}
			cur_arg++;
#else
			memprintf(errmsg, "'%s' : library does not support TLS ALPN extension.", args[cur_arg]);
			goto error;
#endif
		}
#endif /* USE_OPENSSL */

		else {
			memprintf(errmsg, "expects 'comment', 'port', 'addr', 'send-proxy'"
#ifdef USE_OPENSSL
				  ", 'ssl', 'sni', 'alpn'"
#endif /* USE_OPENSSL */
				  " or 'via-socks4', 'linger', 'default' but got '%s' as argument.",
				  args[cur_arg]);
			goto error;
		}
		cur_arg++;
	}

	chk = calloc(1, sizeof(*chk));
	if (!chk) {
		memprintf(errmsg, "out of memory");
		goto error;
	}
	chk->action  = TCPCHK_ACT_CONNECT;
	chk->comment = comment;
	chk->connect.port    = port;
	chk->connect.options = conn_opts;
	chk->connect.sni     = sni;
	chk->connect.alpn    = alpn;
	chk->connect.alpn_len= alpn_len;
	chk->connect.port_expr= port_expr;
	chk->connect.mux_proto= mux_proto;
	if (sk)
		chk->connect.addr = *sk;
	return chk;

  error:
	free(alpn);
	free(sni);
	free(comment);
	release_sample_expr(port_expr);
	return NULL;
}

/* Parses and creates a tcp-check send rule. NULL is returned on error */
struct tcpcheck_rule *parse_tcpcheck_send(char **args, int cur_arg, struct proxy *px, struct list *rules,
                                          const char *file, int line, char **errmsg)
{
	struct tcpcheck_rule *chk = NULL;
	char *comment = NULL, *data = NULL;
	enum tcpcheck_send_type type = TCPCHK_SEND_UNDEF;

	if (strcmp(args[cur_arg], "send-binary-lf") == 0)
		type = TCPCHK_SEND_BINARY_LF;
	else if (strcmp(args[cur_arg], "send-binary") == 0)
		type = TCPCHK_SEND_BINARY;
	else if (strcmp(args[cur_arg], "send-lf") == 0)
		type = TCPCHK_SEND_STRING_LF;
	else if (strcmp(args[cur_arg], "send") == 0)
		type = TCPCHK_SEND_STRING;

	if (!*(args[cur_arg+1])) {
		memprintf(errmsg, "'%s' expects a %s as argument",
			  (type == TCPCHK_SEND_BINARY ? "binary string": "string"), args[cur_arg]);
		goto error;
	}

	data = args[cur_arg+1];

	cur_arg += 2;
	while (*(args[cur_arg])) {
		if (strcmp(args[cur_arg], "comment") == 0) {
			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a string as argument.", args[cur_arg]);
				goto error;
			}
			cur_arg++;
			free(comment);
			comment = strdup(args[cur_arg]);
			if (!comment) {
				memprintf(errmsg, "out of memory");
				goto error;
			}
		}
		else {
			memprintf(errmsg, "expects 'comment' but got '%s' as argument.",
				  args[cur_arg]);
			goto error;
		}
		cur_arg++;
	}

	chk = calloc(1, sizeof(*chk));
	if (!chk) {
		memprintf(errmsg, "out of memory");
		goto error;
	}
	chk->action      = TCPCHK_ACT_SEND;
	chk->comment     = comment;
	chk->send.type   = type;

	switch (chk->send.type) {
	case TCPCHK_SEND_STRING:
		chk->send.data = ist2(strdup(data), strlen(data));
		if (!isttest(chk->send.data)) {
			memprintf(errmsg, "out of memory");
			goto error;
		}
		break;
	case TCPCHK_SEND_BINARY: {
		int len = chk->send.data.len;
		if (parse_binary(data, &chk->send.data.ptr, &len, errmsg) == 0) {
			memprintf(errmsg, "'%s' invalid binary string (%s).\n", data, *errmsg);
			goto error;
		}
		chk->send.data.len = len;
		break;
	}
	case TCPCHK_SEND_STRING_LF:
	case TCPCHK_SEND_BINARY_LF:
		LIST_INIT(&chk->send.fmt);
		px->conf.args.ctx = ARGC_SRV;
		if (!parse_logformat_string(data, px, &chk->send.fmt, 0, SMP_VAL_BE_CHK_RUL, errmsg)) {
			memprintf(errmsg, "'%s' invalid log-format string (%s).\n", data, *errmsg);
			goto error;
		}
		break;
	case TCPCHK_SEND_HTTP:
	case TCPCHK_SEND_UNDEF:
		goto error;
	}

	return chk;

  error:
	free(chk);
	free(comment);
	return NULL;
}

/* Parses and creates a http-check send rule. NULL is returned on error */
struct tcpcheck_rule *parse_tcpcheck_send_http(char **args, int cur_arg, struct proxy *px, struct list *rules,
                                               const char *file, int line, char **errmsg)
{
	struct tcpcheck_rule *chk = NULL;
	struct tcpcheck_http_hdr *hdr = NULL;
        struct http_hdr hdrs[global.tune.max_http_hdr];
	char *meth = NULL, *uri = NULL, *vsn = NULL;
	char *body = NULL, *comment = NULL;
	unsigned int flags = 0;
	int i = 0, host_hdr = -1;

	cur_arg++;
	while (*(args[cur_arg])) {
		if (strcmp(args[cur_arg], "meth") == 0) {
			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a string as argument.", args[cur_arg]);
				goto error;
			}
			cur_arg++;
			meth = args[cur_arg];
		}
		else if (strcmp(args[cur_arg], "uri") == 0 || strcmp(args[cur_arg], "uri-lf") == 0) {
			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a string as argument.", args[cur_arg]);
				goto error;
			}
			flags &= ~TCPCHK_SND_HTTP_FL_URI_FMT;
			if (strcmp(args[cur_arg], "uri-lf") == 0)
				flags |= TCPCHK_SND_HTTP_FL_URI_FMT;
			cur_arg++;
			uri = args[cur_arg];
		}
		else if (strcmp(args[cur_arg], "ver") == 0) {
			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a string as argument.", args[cur_arg]);
				goto error;
			}
			cur_arg++;
			vsn = args[cur_arg];
		}
                else if (strcmp(args[cur_arg], "hdr") == 0) {
			if (!*args[cur_arg+1] || !*args[cur_arg+2]) {
				memprintf(errmsg, "'%s' expects <name> and <value> as arguments", args[cur_arg]);
				goto error;
			}

			if (strcasecmp(args[cur_arg+1], "host") == 0) {
				if (host_hdr >= 0) {
					memprintf(errmsg, "'%s' header already defined (previous value is '%s')",
						  args[cur_arg+1], istptr(hdrs[host_hdr].v));
					goto error;
				}
				host_hdr = i;
			}
			else if (strcasecmp(args[cur_arg+1], "content-length") == 0 ||
				 strcasecmp(args[cur_arg+1], "transfer-encoding") == 0)
				goto skip_hdr;

			hdrs[i].n = ist2(args[cur_arg+1], strlen(args[cur_arg+1]));
			hdrs[i].v = ist2(args[cur_arg+2], strlen(args[cur_arg+2]));
			i++;
		  skip_hdr:
			cur_arg += 2;
		}
		else if (strcmp(args[cur_arg], "body") == 0 || strcmp(args[cur_arg], "body-lf") == 0) {
			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a string as argument.", args[cur_arg]);
				goto error;
			}
			flags &= ~TCPCHK_SND_HTTP_FL_BODY_FMT;
			if (strcmp(args[cur_arg], "body-lf") == 0)
				flags |= TCPCHK_SND_HTTP_FL_BODY_FMT;
			cur_arg++;
			body = args[cur_arg];
		}
		else if (strcmp(args[cur_arg], "comment") == 0) {
			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a string as argument.", args[cur_arg]);
				goto error;
			}
			cur_arg++;
			free(comment);
			comment = strdup(args[cur_arg]);
			if (!comment) {
				memprintf(errmsg, "out of memory");
				goto error;
			}
		}
		else {
			memprintf(errmsg, "expects 'comment', 'meth', 'uri', 'uri-lf', 'ver', 'hdr', 'body' or 'body-lf'"
				  " but got '%s' as argument.", args[cur_arg]);
			goto error;
		}
		cur_arg++;
	}

	hdrs[i].n = hdrs[i].v = IST_NULL;

	chk = calloc(1, sizeof(*chk));
	if (!chk) {
		memprintf(errmsg, "out of memory");
		goto error;
	}
	chk->action    = TCPCHK_ACT_SEND;
	chk->comment   = comment; comment = NULL;
	chk->send.type = TCPCHK_SEND_HTTP;
	chk->send.http.flags = flags;
	LIST_INIT(&chk->send.http.hdrs);

	if (meth) {
		chk->send.http.meth.meth = find_http_meth(meth, strlen(meth));
		chk->send.http.meth.str.area = strdup(meth);
		chk->send.http.meth.str.data = strlen(meth);
		if (!chk->send.http.meth.str.area) {
			memprintf(errmsg, "out of memory");
			goto error;
		}
	}
	if (uri) {
		if (chk->send.http.flags & TCPCHK_SND_HTTP_FL_URI_FMT) {
			LIST_INIT(&chk->send.http.uri_fmt);
			px->conf.args.ctx = ARGC_SRV;
			if (!parse_logformat_string(uri, px, &chk->send.http.uri_fmt, 0, SMP_VAL_BE_CHK_RUL, errmsg)) {
				memprintf(errmsg, "'%s' invalid log-format string (%s).\n", uri, *errmsg);
				goto error;
			}
		}
		else {
			chk->send.http.uri = ist2(strdup(uri), strlen(uri));
			if (!isttest(chk->send.http.uri)) {
				memprintf(errmsg, "out of memory");
				goto error;
			}
		}
	}
	if (vsn) {
		chk->send.http.vsn = ist2(strdup(vsn), strlen(vsn));
		if (!isttest(chk->send.http.vsn)) {
			memprintf(errmsg, "out of memory");
			goto error;
		}
	}
	for (i = 0; istlen(hdrs[i].n); i++) {
		hdr = calloc(1, sizeof(*hdr));
		if (!hdr) {
			memprintf(errmsg, "out of memory");
			goto error;
		}
		LIST_INIT(&hdr->value);
		hdr->name = istdup(hdrs[i].n);
		if (!isttest(hdr->name)) {
			memprintf(errmsg, "out of memory");
			goto error;
		}

		ist0(hdrs[i].v);
		if (!parse_logformat_string(istptr(hdrs[i].v), px, &hdr->value, 0, SMP_VAL_BE_CHK_RUL, errmsg))
			goto error;
		LIST_ADDQ(&chk->send.http.hdrs, &hdr->list);
		hdr = NULL;
	}

	if (body) {
		if (chk->send.http.flags & TCPCHK_SND_HTTP_FL_BODY_FMT) {
			LIST_INIT(&chk->send.http.body_fmt);
			px->conf.args.ctx = ARGC_SRV;
			if (!parse_logformat_string(body, px, &chk->send.http.body_fmt, 0, SMP_VAL_BE_CHK_RUL, errmsg)) {
				memprintf(errmsg, "'%s' invalid log-format string (%s).\n", body, *errmsg);
				goto error;
			}
		}
		else {
			chk->send.http.body = ist2(strdup(body), strlen(body));
			if (!isttest(chk->send.http.body)) {
				memprintf(errmsg, "out of memory");
				goto error;
			}
		}
	}

	return chk;

  error:
	free_tcpcheck_http_hdr(hdr);
	free_tcpcheck(chk, 0);
	free(comment);
	return NULL;
}

/* Parses and creates a http-check comment rule. NULL is returned on error */
struct tcpcheck_rule *parse_tcpcheck_comment(char **args, int cur_arg, struct proxy *px, struct list *rules,
                                             const char *file, int line, char **errmsg)
{
	struct tcpcheck_rule *chk = NULL;
	char *comment = NULL;

	if (!*(args[cur_arg+1])) {
		memprintf(errmsg, "expects a string as argument");
		goto error;
	}
	cur_arg++;
	comment = strdup(args[cur_arg]);
	if (!comment) {
		memprintf(errmsg, "out of memory");
		goto error;
	}

	chk = calloc(1, sizeof(*chk));
	if (!chk) {
		memprintf(errmsg, "out of memory");
		goto error;
	}
	chk->action  = TCPCHK_ACT_COMMENT;
	chk->comment = comment;
	return chk;

  error:
	free(comment);
	return NULL;
}

/* Parses and creates a tcp-check or an http-check expect rule. NULL is returned
 * on error. <proto> is set to the right protocol flags (covered by the
 * TCPCHK_RULES_PROTO_CHK mask).
 */
struct tcpcheck_rule *parse_tcpcheck_expect(char **args, int cur_arg, struct proxy *px,
                                            struct list *rules, unsigned int proto,
                                            const char *file, int line, char **errmsg)
{
	struct tcpcheck_rule *prev_check, *chk = NULL;
	struct sample_expr *status_expr = NULL;
	char *on_success_msg, *on_error_msg, *comment, *pattern, *npat, *vpat;
	enum tcpcheck_expect_type type = TCPCHK_EXPECT_UNDEF;
	enum healthcheck_status ok_st = HCHK_STATUS_UNKNOWN;
	enum healthcheck_status err_st = HCHK_STATUS_UNKNOWN;
	enum healthcheck_status tout_st = HCHK_STATUS_UNKNOWN;
	unsigned int flags = 0;
	long min_recv = -1;
	int inverse = 0;

	on_success_msg = on_error_msg = comment = pattern = npat = vpat = NULL;
	if (!*(args[cur_arg+1])) {
		memprintf(errmsg, "expects at least a matching pattern as arguments");
		goto error;
	}

	cur_arg++;
	while (*(args[cur_arg])) {
		int in_pattern = 0;

	  rescan:
		if (strcmp(args[cur_arg], "min-recv") == 0) {
			if (in_pattern) {
				memprintf(errmsg, "[!] not supported with '%s'", args[cur_arg]);
				goto error;
			}
			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a integer as argument", args[cur_arg]);
				goto error;
			}
			/* Use an signed integer here because of bufsize */
			cur_arg++;
			min_recv = atol(args[cur_arg]);
			if (min_recv < -1 || min_recv > INT_MAX) {
				memprintf(errmsg, "'%s' expects -1 or an integer from 0 to INT_MAX" , args[cur_arg-1]);
				goto error;
			}
		}
		else if (*(args[cur_arg]) == '!') {
			in_pattern = 1;
			while (*(args[cur_arg]) == '!') {
				inverse = !inverse;
				args[cur_arg]++;
			}
			if (!*(args[cur_arg]))
				cur_arg++;
			goto rescan;
		}
		else if (strcmp(args[cur_arg], "string") == 0 || strcmp(args[cur_arg], "rstring") == 0) {
			if (type != TCPCHK_EXPECT_UNDEF) {
				memprintf(errmsg, "only on pattern expected");
				goto error;
			}
			if (proto != TCPCHK_RULES_HTTP_CHK)
				type = ((*(args[cur_arg]) == 's') ? TCPCHK_EXPECT_STRING : TCPCHK_EXPECT_STRING_REGEX);
			else
				type = ((*(args[cur_arg]) == 's') ? TCPCHK_EXPECT_HTTP_BODY : TCPCHK_EXPECT_HTTP_BODY_REGEX);

			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a <pattern> as argument", args[cur_arg]);
				goto error;
			}
			cur_arg++;
			pattern = args[cur_arg];
		}
		else if (strcmp(args[cur_arg], "binary") == 0 || strcmp(args[cur_arg], "rbinary") == 0) {
			if (proto == TCPCHK_RULES_HTTP_CHK)
				goto bad_http_kw;
			if (type != TCPCHK_EXPECT_UNDEF) {
				memprintf(errmsg, "only on pattern expected");
				goto error;
			}
			type = ((*(args[cur_arg]) == 'b') ?  TCPCHK_EXPECT_BINARY : TCPCHK_EXPECT_BINARY_REGEX);

			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a <pattern> as argument", args[cur_arg]);
				goto error;
			}
			cur_arg++;
			pattern = args[cur_arg];
		}
		else if (strcmp(args[cur_arg], "string-lf") == 0 || strcmp(args[cur_arg], "binary-lf") == 0) {
			if (type != TCPCHK_EXPECT_UNDEF) {
				memprintf(errmsg, "only on pattern expected");
				goto error;
			}
			if (proto != TCPCHK_RULES_HTTP_CHK)
				type = ((*(args[cur_arg]) == 's') ? TCPCHK_EXPECT_STRING_LF : TCPCHK_EXPECT_BINARY_LF);
			else {
				if (*(args[cur_arg]) != 's')
					goto bad_http_kw;
				type = TCPCHK_EXPECT_HTTP_BODY_LF;
			}

			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a <pattern> as argument", args[cur_arg]);
				goto error;
			}
			cur_arg++;
			pattern = args[cur_arg];
		}
		else if (strcmp(args[cur_arg], "status") == 0 || strcmp(args[cur_arg], "rstatus") == 0) {
			if (proto != TCPCHK_RULES_HTTP_CHK)
				goto bad_tcp_kw;
			if (type != TCPCHK_EXPECT_UNDEF) {
				memprintf(errmsg, "only on pattern expected");
				goto error;
			}
			type = ((*(args[cur_arg]) == 's') ? TCPCHK_EXPECT_HTTP_STATUS : TCPCHK_EXPECT_HTTP_STATUS_REGEX);

			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a <pattern> as argument", args[cur_arg]);
				goto error;
			}
			cur_arg++;
			pattern = args[cur_arg];
		}
		else if (strcmp(args[cur_arg], "custom") == 0) {
			if (in_pattern) {
				memprintf(errmsg, "[!] not supported with '%s'", args[cur_arg]);
				goto error;
			}
			if (type != TCPCHK_EXPECT_UNDEF) {
				memprintf(errmsg, "only on pattern expected");
				goto error;
			}
			type = TCPCHK_EXPECT_CUSTOM;
		}
		else if (strcmp(args[cur_arg], "hdr") == 0 || strcmp(args[cur_arg], "fhdr") == 0) {
			int orig_arg = cur_arg;

			if (proto != TCPCHK_RULES_HTTP_CHK)
				goto bad_tcp_kw;
			if (type != TCPCHK_EXPECT_UNDEF) {
				memprintf(errmsg, "only on pattern expected");
				goto error;
			}
			type = TCPCHK_EXPECT_HTTP_HEADER;

			if (strcmp(args[cur_arg], "fhdr") == 0)
				flags |= TCPCHK_EXPT_FL_HTTP_HVAL_FULL;

			/* Parse the name pattern, mandatory */
			if (!*(args[cur_arg+1]) || !*(args[cur_arg+2]) ||
			    (strcmp(args[cur_arg+1], "name") != 0 && strcmp(args[cur_arg+1], "name-lf") != 0)) {
				memprintf(errmsg, "'%s' expects at the name keyword as first argument followed by a pattern",
					  args[orig_arg]);
				goto error;
			}

			if (strcmp(args[cur_arg+1], "name-lf") == 0)
				flags |= TCPCHK_EXPT_FL_HTTP_HNAME_FMT;

			cur_arg += 2;
			if (strcmp(args[cur_arg], "-m") == 0) {
				if  (!*(args[cur_arg+1])) {
					memprintf(errmsg, "'%s' : '%s' expects at a matching pattern ('str', 'beg', 'end', 'sub' or 'reg')",
						  args[orig_arg], args[cur_arg]);
					goto error;
				}
				if (strcmp(args[cur_arg+1], "str") == 0)
					flags |= TCPCHK_EXPT_FL_HTTP_HNAME_STR;
				else if (strcmp(args[cur_arg+1], "beg") == 0)
					flags |= TCPCHK_EXPT_FL_HTTP_HNAME_BEG;
				else if (strcmp(args[cur_arg+1], "end") == 0)
					flags |= TCPCHK_EXPT_FL_HTTP_HNAME_END;
				else if (strcmp(args[cur_arg+1], "sub") == 0)
					flags |= TCPCHK_EXPT_FL_HTTP_HNAME_SUB;
				else if (strcmp(args[cur_arg+1], "reg") == 0) {
					if (flags & TCPCHK_EXPT_FL_HTTP_HNAME_FMT) {
						memprintf(errmsg, "'%s': log-format string is not supported with a regex matching method",
							  args[orig_arg]);
						goto error;
					}
					flags |= TCPCHK_EXPT_FL_HTTP_HNAME_REG;
				}
				else {
					memprintf(errmsg, "'%s' : '%s' only supports 'str', 'beg', 'end', 'sub' or 'reg' (got '%s')",
						  args[orig_arg], args[cur_arg], args[cur_arg+1]);
					goto error;
				}
				cur_arg += 2;
			}
			else
				flags |= TCPCHK_EXPT_FL_HTTP_HNAME_STR;
			npat = args[cur_arg];

			if (!*(args[cur_arg+1]) ||
			    (strcmp(args[cur_arg+1], "value") != 0 && strcmp(args[cur_arg+1], "value-lf") != 0)) {
				flags |= TCPCHK_EXPT_FL_HTTP_HVAL_NONE;
				goto next;
			}
			if (strcmp(args[cur_arg+1], "value-lf") == 0)
				flags |= TCPCHK_EXPT_FL_HTTP_HVAL_FMT;

			/* Parse the value pattern, optional */
			if (strcmp(args[cur_arg+2], "-m") == 0) {
				cur_arg += 2;
				if  (!*(args[cur_arg+1])) {
					memprintf(errmsg, "'%s' : '%s' expects at a matching pattern ('str', 'beg', 'end', 'sub' or 'reg')",
						  args[orig_arg], args[cur_arg]);
					goto error;
				}
				if (strcmp(args[cur_arg+1], "str") == 0)
					flags |= TCPCHK_EXPT_FL_HTTP_HVAL_STR;
				else if (strcmp(args[cur_arg+1], "beg") == 0)
					flags |= TCPCHK_EXPT_FL_HTTP_HVAL_BEG;
				else if (strcmp(args[cur_arg+1], "end") == 0)
					flags |= TCPCHK_EXPT_FL_HTTP_HVAL_END;
				else if (strcmp(args[cur_arg+1], "sub") == 0)
					flags |= TCPCHK_EXPT_FL_HTTP_HVAL_SUB;
				else if (strcmp(args[cur_arg+1], "reg") == 0) {
					if (flags & TCPCHK_EXPT_FL_HTTP_HVAL_FMT) {
						memprintf(errmsg, "'%s': log-format string is not supported with a regex matching method",
							  args[orig_arg]);
						goto error;
					}
					flags |= TCPCHK_EXPT_FL_HTTP_HVAL_REG;
				}
				else {
					memprintf(errmsg, "'%s' : '%s' only supports 'str', 'beg', 'end', 'sub' or 'reg' (got '%s')",
						  args[orig_arg], args[cur_arg], args[cur_arg+1]);
					goto error;
				}
			}
			else
				flags |= TCPCHK_EXPT_FL_HTTP_HVAL_STR;

			if (!*(args[cur_arg+2])) {
				memprintf(errmsg, "'%s' expect a pattern with the value keyword", args[orig_arg]);
				goto error;
			}
			vpat = args[cur_arg+2];
			cur_arg += 2;
		}
		else if (strcmp(args[cur_arg], "comment") == 0) {
			if (in_pattern) {
				memprintf(errmsg, "[!] not supported with '%s'", args[cur_arg]);
				goto error;
			}
			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a string as argument", args[cur_arg]);
				goto error;
			}
			cur_arg++;
			free(comment);
			comment = strdup(args[cur_arg]);
			if (!comment) {
				memprintf(errmsg, "out of memory");
				goto error;
			}
		}
		else if (strcmp(args[cur_arg], "on-success") == 0) {
			if (in_pattern) {
				memprintf(errmsg, "[!] not supported with '%s'", args[cur_arg]);
				goto error;
			}
			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a string as argument", args[cur_arg]);
				goto error;
			}
			cur_arg++;
			on_success_msg = args[cur_arg];
		}
		else if (strcmp(args[cur_arg], "on-error") == 0) {
			if (in_pattern) {
				memprintf(errmsg, "[!] not supported with '%s'", args[cur_arg]);
				goto error;
			}
			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a string as argument", args[cur_arg]);
				goto error;
			}
			cur_arg++;
			on_error_msg = args[cur_arg];
		}
		else if (strcmp(args[cur_arg], "ok-status") == 0) {
			if (in_pattern) {
				memprintf(errmsg, "[!] not supported with '%s'", args[cur_arg]);
				goto error;
			}
			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a string as argument", args[cur_arg]);
				goto error;
			}
			if (strcasecmp(args[cur_arg+1], "L7OK") == 0)
				ok_st = HCHK_STATUS_L7OKD;
			else if (strcasecmp(args[cur_arg+1], "L7OKC") == 0)
				ok_st = HCHK_STATUS_L7OKCD;
			else if (strcasecmp(args[cur_arg+1], "L6OK") == 0)
				ok_st = HCHK_STATUS_L6OK;
			else if (strcasecmp(args[cur_arg+1], "L4OK") == 0)
				ok_st = HCHK_STATUS_L4OK;
			else  {
				memprintf(errmsg, "'%s' only supports 'L4OK', 'L6OK', 'L7OK' or 'L7OKC' status (got '%s').",
					  args[cur_arg], args[cur_arg+1]);
				goto error;
			}
			cur_arg++;
		}
		else if (strcmp(args[cur_arg], "error-status") == 0) {
			if (in_pattern) {
				memprintf(errmsg, "[!] not supported with '%s'", args[cur_arg]);
				goto error;
			}
			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a string as argument", args[cur_arg]);
				goto error;
			}
			if (strcasecmp(args[cur_arg+1], "L7RSP") == 0)
				err_st = HCHK_STATUS_L7RSP;
			else if (strcasecmp(args[cur_arg+1], "L7STS") == 0)
				err_st = HCHK_STATUS_L7STS;
			else if (strcasecmp(args[cur_arg+1], "L7OKC") == 0)
				err_st = HCHK_STATUS_L7OKCD;
			else if (strcasecmp(args[cur_arg+1], "L6RSP") == 0)
				err_st = HCHK_STATUS_L6RSP;
			else if (strcasecmp(args[cur_arg+1], "L4CON") == 0)
				err_st = HCHK_STATUS_L4CON;
			else  {
				memprintf(errmsg, "'%s' only supports 'L4CON', 'L6RSP', 'L7RSP' or 'L7STS' status (got '%s').",
					  args[cur_arg], args[cur_arg+1]);
				goto error;
			}
			cur_arg++;
		}
		else if (strcmp(args[cur_arg], "status-code") == 0) {
			int idx = 0;

			if (in_pattern) {
				memprintf(errmsg, "[!] not supported with '%s'", args[cur_arg]);
				goto error;
			}
			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects an expression as argument", args[cur_arg]);
				goto error;
			}

			cur_arg++;
			release_sample_expr(status_expr);
			px->conf.args.ctx = ARGC_SRV;
			status_expr = sample_parse_expr((char *[]){args[cur_arg], NULL}, &idx,
							file, line, errmsg, &px->conf.args, NULL);
			if (!status_expr) {
				memprintf(errmsg, "error detected while parsing status-code expression : %s", *errmsg);
				goto error;
			}
			if (!(status_expr->fetch->val & SMP_VAL_BE_CHK_RUL)) {
				memprintf(errmsg, "error detected while parsing status-code expression : "
					  " fetch method '%s' extracts information from '%s', "
					  "none of which is available here.\n",
					  args[cur_arg], sample_src_names(status_expr->fetch->use));
					goto error;
			}
			px->http_needed |= !!(status_expr->fetch->use & SMP_USE_HTTP_ANY);
		}
		else if (strcmp(args[cur_arg], "tout-status") == 0) {
			if (in_pattern) {
				memprintf(errmsg, "[!] not supported with '%s'", args[cur_arg]);
				goto error;
			}
			if (!*(args[cur_arg+1])) {
				memprintf(errmsg, "'%s' expects a string as argument", args[cur_arg]);
				goto error;
			}
			if (strcasecmp(args[cur_arg+1], "L7TOUT") == 0)
				tout_st = HCHK_STATUS_L7TOUT;
			else if (strcasecmp(args[cur_arg+1], "L6TOUT") == 0)
				tout_st = HCHK_STATUS_L6TOUT;
			else if (strcasecmp(args[cur_arg+1], "L4TOUT") == 0)
				tout_st = HCHK_STATUS_L4TOUT;
			else  {
				memprintf(errmsg, "'%s' only supports 'L4TOUT', 'L6TOUT' or 'L7TOUT' status (got '%s').",
					  args[cur_arg], args[cur_arg+1]);
				goto error;
			}
			cur_arg++;
		}
		else {
			if (proto == TCPCHK_RULES_HTTP_CHK) {
			  bad_http_kw:
				memprintf(errmsg, "'only supports min-recv, [!]string', '[!]rstring', '[!]string-lf', '[!]status', "
					  "'[!]rstatus', [!]hdr, [!]fhdr or comment but got '%s' as argument.", args[cur_arg]);
			}
			else {
			  bad_tcp_kw:
				memprintf(errmsg, "'only supports min-recv, '[!]binary', '[!]string', '[!]rstring', '[!]string-lf'"
					  "'[!]rbinary', '[!]binary-lf' or comment but got '%s' as argument.", args[cur_arg]);
			}
			goto error;
		}
	  next:
		cur_arg++;
	}

	chk = calloc(1, sizeof(*chk));
	if (!chk) {
		memprintf(errmsg, "out of memory");
		goto error;
	}
	chk->action  = TCPCHK_ACT_EXPECT;
	LIST_INIT(&chk->expect.onerror_fmt);
	LIST_INIT(&chk->expect.onsuccess_fmt);
	chk->comment = comment; comment = NULL;
	chk->expect.type = type;
	chk->expect.min_recv = min_recv;
	chk->expect.flags = flags | (inverse ? TCPCHK_EXPT_FL_INV : 0);
	chk->expect.ok_status = ok_st;
	chk->expect.err_status = err_st;
	chk->expect.tout_status = tout_st;
	chk->expect.status_expr = status_expr; status_expr = NULL;

	if (on_success_msg) {
		px->conf.args.ctx = ARGC_SRV;
		if (!parse_logformat_string(on_success_msg, px, &chk->expect.onsuccess_fmt, 0, SMP_VAL_BE_CHK_RUL, errmsg)) {
			memprintf(errmsg, "'%s' invalid log-format string (%s).\n", on_success_msg, *errmsg);
			goto error;
		}
	}
	if (on_error_msg) {
		px->conf.args.ctx = ARGC_SRV;
		if (!parse_logformat_string(on_error_msg, px, &chk->expect.onerror_fmt, 0, SMP_VAL_BE_CHK_RUL, errmsg)) {
			memprintf(errmsg, "'%s' invalid log-format string (%s).\n", on_error_msg, *errmsg);
			goto error;
		}
	}

	switch (chk->expect.type) {
	case TCPCHK_EXPECT_HTTP_STATUS: {
		const char *p = pattern;
		unsigned int c1,c2;

		chk->expect.codes.codes = NULL;
		chk->expect.codes.num   = 0;
		while (1) {
			c1 = c2 = read_uint(&p, pattern + strlen(pattern));
			if (*p == '-') {
				p++;
				c2 = read_uint(&p, pattern + strlen(pattern));
			}
			if (c1 > c2) {
				memprintf(errmsg, "invalid range of status codes '%s'", pattern);
				goto error;
			}

			chk->expect.codes.num++;
			chk->expect.codes.codes = my_realloc2(chk->expect.codes.codes,
							      chk->expect.codes.num * sizeof(*chk->expect.codes.codes));
			if (!chk->expect.codes.codes) {
				memprintf(errmsg, "out of memory");
				goto error;
			}
			chk->expect.codes.codes[chk->expect.codes.num-1][0] = c1;
			chk->expect.codes.codes[chk->expect.codes.num-1][1] = c2;

			if (*p == '\0')
				break;
			if (*p != ',') {
				memprintf(errmsg, "invalid character '%c' in the list of status codes", *p);
				goto error;
			}
			p++;
		}
		break;
	}
	case TCPCHK_EXPECT_STRING:
	case TCPCHK_EXPECT_HTTP_BODY:
		chk->expect.data = ist2(strdup(pattern), strlen(pattern));
		if (!isttest(chk->expect.data)) {
			memprintf(errmsg, "out of memory");
			goto error;
		}
		break;
	case TCPCHK_EXPECT_BINARY: {
		int len = chk->expect.data.len;

		if (parse_binary(pattern, &chk->expect.data.ptr, &len, errmsg) == 0) {
			memprintf(errmsg, "invalid binary string (%s)", *errmsg);
			goto error;
		}
		chk->expect.data.len = len;
		break;
	}
	case TCPCHK_EXPECT_STRING_REGEX:
	case TCPCHK_EXPECT_BINARY_REGEX:
	case TCPCHK_EXPECT_HTTP_STATUS_REGEX:
	case TCPCHK_EXPECT_HTTP_BODY_REGEX:
		chk->expect.regex = regex_comp(pattern, 1, 0, errmsg);
		if (!chk->expect.regex)
			goto error;
		break;

	case TCPCHK_EXPECT_STRING_LF:
	case TCPCHK_EXPECT_BINARY_LF:
	case TCPCHK_EXPECT_HTTP_BODY_LF:
		LIST_INIT(&chk->expect.fmt);
		px->conf.args.ctx = ARGC_SRV;
		if (!parse_logformat_string(pattern, px, &chk->expect.fmt, 0, SMP_VAL_BE_CHK_RUL, errmsg)) {
			memprintf(errmsg, "'%s' invalid log-format string (%s).\n", pattern, *errmsg);
			goto error;
		}
		break;

	case TCPCHK_EXPECT_HTTP_HEADER:
		if (!npat) {
			memprintf(errmsg, "unexpected error, undefined header name pattern");
			goto error;
		}
		if (chk->expect.flags & TCPCHK_EXPT_FL_HTTP_HNAME_REG) {
			chk->expect.hdr.name_re = regex_comp(npat, 0, 0, errmsg);
			if (!chk->expect.hdr.name_re)
				goto error;
		}
		else if (chk->expect.flags & TCPCHK_EXPT_FL_HTTP_HNAME_FMT) {
			px->conf.args.ctx = ARGC_SRV;
			LIST_INIT(&chk->expect.hdr.name_fmt);
			if (!parse_logformat_string(npat, px, &chk->expect.hdr.name_fmt, 0, SMP_VAL_BE_CHK_RUL, errmsg)) {
				memprintf(errmsg, "'%s' invalid log-format string (%s).\n", npat, *errmsg);
				goto error;
			}
		}
		else {
			chk->expect.hdr.name = ist2(strdup(npat), strlen(npat));
			if (!isttest(chk->expect.hdr.name)) {
				memprintf(errmsg, "out of memory");
				goto error;
			}
		}

		if (chk->expect.flags & TCPCHK_EXPT_FL_HTTP_HVAL_NONE) {
			chk->expect.hdr.value = IST_NULL;
			break;
		}

		if (!vpat) {
			memprintf(errmsg, "unexpected error, undefined header value pattern");
			goto error;
		}
		else if (chk->expect.flags & TCPCHK_EXPT_FL_HTTP_HVAL_REG) {
			chk->expect.hdr.value_re = regex_comp(vpat, 1, 0, errmsg);
			if (!chk->expect.hdr.value_re)
				goto error;
		}
		else if (chk->expect.flags & TCPCHK_EXPT_FL_HTTP_HVAL_FMT) {
			px->conf.args.ctx = ARGC_SRV;
			LIST_INIT(&chk->expect.hdr.value_fmt);
			if (!parse_logformat_string(vpat, px, &chk->expect.hdr.value_fmt, 0, SMP_VAL_BE_CHK_RUL, errmsg)) {
				memprintf(errmsg, "'%s' invalid log-format string (%s).\n", npat, *errmsg);
				goto error;
			}
		}
		else {
			chk->expect.hdr.value = ist2(strdup(vpat), strlen(vpat));
			if (!isttest(chk->expect.hdr.value)) {
				memprintf(errmsg, "out of memory");
				goto error;
			}
		}

		break;
	case TCPCHK_EXPECT_CUSTOM:
		chk->expect.custom = NULL; /* Must be defined by the caller ! */
		break;
	case TCPCHK_EXPECT_UNDEF:
		memprintf(errmsg, "pattern not found");
		goto error;
	}

	/* All tcp-check expect points back to the first inverse expect rule in
	 * a chain of one or more expect rule, potentially itself.
	 */
	chk->expect.head = chk;
	list_for_each_entry_rev(prev_check, rules, list) {
		if (prev_check->action == TCPCHK_ACT_EXPECT) {
			if (prev_check->expect.flags & TCPCHK_EXPT_FL_INV)
				chk->expect.head = prev_check;
			continue;
		}
		if (prev_check->action != TCPCHK_ACT_COMMENT && prev_check->action != TCPCHK_ACT_ACTION_KW)
			break;
	}
	return chk;

  error:
	free_tcpcheck(chk, 0);
	free(comment);
	release_sample_expr(status_expr);
	return NULL;
}

/* Overwrites fields of the old http send rule with those of the new one. When
 * replaced, old values are freed and replaced by the new ones. New values are
 * not copied but transferred. At the end <new> should be empty and can be
 * safely released. This function never fails.
 */
void tcpcheck_overwrite_send_http_rule(struct tcpcheck_rule *old, struct tcpcheck_rule *new)
{
	struct logformat_node *lf, *lfb;
	struct tcpcheck_http_hdr *hdr, *bhdr;


	if (new->send.http.meth.str.area) {
		free(old->send.http.meth.str.area);
		old->send.http.meth.meth = new->send.http.meth.meth;
		old->send.http.meth.str.area = new->send.http.meth.str.area;
		old->send.http.meth.str.data = new->send.http.meth.str.data;
		new->send.http.meth.str = BUF_NULL;
	}

	if (!(new->send.http.flags & TCPCHK_SND_HTTP_FL_URI_FMT) && isttest(new->send.http.uri)) {
		if (!(old->send.http.flags & TCPCHK_SND_HTTP_FL_URI_FMT))
			istfree(&old->send.http.uri);
		else
			free_tcpcheck_fmt(&old->send.http.uri_fmt);
		old->send.http.flags &= ~TCPCHK_SND_HTTP_FL_URI_FMT;
		old->send.http.uri = new->send.http.uri;
		new->send.http.uri = IST_NULL;
	}
	else if ((new->send.http.flags & TCPCHK_SND_HTTP_FL_URI_FMT) && !LIST_ISEMPTY(&new->send.http.uri_fmt)) {
		if (!(old->send.http.flags & TCPCHK_SND_HTTP_FL_URI_FMT))
			istfree(&old->send.http.uri);
		else
			free_tcpcheck_fmt(&old->send.http.uri_fmt);
		old->send.http.flags |= TCPCHK_SND_HTTP_FL_URI_FMT;
		LIST_INIT(&old->send.http.uri_fmt);
		list_for_each_entry_safe(lf, lfb, &new->send.http.uri_fmt, list) {
			LIST_DEL(&lf->list);
			LIST_ADDQ(&old->send.http.uri_fmt, &lf->list);
		}
	}

	if (isttest(new->send.http.vsn)) {
		istfree(&old->send.http.vsn);
		old->send.http.vsn = new->send.http.vsn;
		new->send.http.vsn = IST_NULL;
	}

	free_tcpcheck_http_hdrs(&old->send.http.hdrs);
	list_for_each_entry_safe(hdr, bhdr, &new->send.http.hdrs, list) {
		LIST_DEL(&hdr->list);
		LIST_ADDQ(&old->send.http.hdrs, &hdr->list);
	}

	if (!(new->send.http.flags & TCPCHK_SND_HTTP_FL_BODY_FMT) && isttest(new->send.http.body)) {
		if (!(old->send.http.flags & TCPCHK_SND_HTTP_FL_BODY_FMT))
			istfree(&old->send.http.body);
		else
			free_tcpcheck_fmt(&old->send.http.body_fmt);
		old->send.http.flags &= ~TCPCHK_SND_HTTP_FL_BODY_FMT;
		old->send.http.body = new->send.http.body;
		new->send.http.body = IST_NULL;
	}
	else if ((new->send.http.flags & TCPCHK_SND_HTTP_FL_BODY_FMT) && !LIST_ISEMPTY(&new->send.http.body_fmt)) {
		if (!(old->send.http.flags & TCPCHK_SND_HTTP_FL_BODY_FMT))
			istfree(&old->send.http.body);
		else
			free_tcpcheck_fmt(&old->send.http.body_fmt);
		old->send.http.flags |= TCPCHK_SND_HTTP_FL_BODY_FMT;
		LIST_INIT(&old->send.http.body_fmt);
		list_for_each_entry_safe(lf, lfb, &new->send.http.body_fmt, list) {
			LIST_DEL(&lf->list);
			LIST_ADDQ(&old->send.http.body_fmt, &lf->list);
		}
	}
}

/* Internal function used to add an http-check rule in a list during the config
 * parsing step. Depending on its type, and the previously inserted rules, a
 * specific action may be performed or an error may be reported. This functions
 * returns 1 on success and 0 on error and <errmsg> is filled with the error
 * message.
 */
int tcpcheck_add_http_rule(struct tcpcheck_rule *chk, struct tcpcheck_rules *rules, char **errmsg)
{
	struct tcpcheck_rule *r;

	/* the implicit send rule coming from an "option httpchk" line must be
	 * merged with the first explici http-check send rule, if
	 * any. Depending on the declaration order some tests are required.
	 *
	 * Some tests are also required for other kinds of http-check rules to be
	 * sure the ruleset remains valid.
	 */

	if (chk->action == TCPCHK_ACT_SEND && (chk->send.http.flags & TCPCHK_SND_HTTP_FROM_OPT)) {
		/* Tries to add an implicit http-check send rule from an "option httpchk" line.
		 * First, the first rule is retrieved, skipping the first CONNECT, if any, and
		 * following tests are performed :
		 *
		 *  1- If there is no such rule or if it is not a send rule, the implicit send
		 *     rule is pushed in front of the ruleset
		 *
		 *  2- If it is another implicit send rule, it is replaced with the new one.
		 *
		 *  3- Otherwise, it means it is an explicit send rule. In this case we merge
		 *     both, overwriting the old send rule (the explicit one) with info of the
		 *     new send rule (the implicit one).
		 */
		r = get_first_tcpcheck_rule(rules);
		if (r && r->action == TCPCHK_ACT_CONNECT)
			r = get_next_tcpcheck_rule(rules, r);
		if (!r || r->action != TCPCHK_ACT_SEND)
			LIST_ADD(rules->list, &chk->list);
		else if (r->send.http.flags & TCPCHK_SND_HTTP_FROM_OPT) {
			LIST_DEL(&r->list);
			free_tcpcheck(r, 0);
			LIST_ADD(rules->list, &chk->list);
		}
		else {
			tcpcheck_overwrite_send_http_rule(r, chk);
			free_tcpcheck(chk, 0);
		}
	}
	else {
		/* Tries to add an explicit http-check rule. First of all we check the typefo the
		 * last inserted rule to be sure it is valid. Then for send rule, we try to merge it
		 * with an existing implicit send rule, if any. At the end, if there is no error,
		 * the rule is appended to the list.
		 */

		r = get_last_tcpcheck_rule(rules);
		if (!r || (r->action == TCPCHK_ACT_SEND && (r->send.http.flags & TCPCHK_SND_HTTP_FROM_OPT)))
			/* no error */;
		else if (r->action != TCPCHK_ACT_CONNECT && chk->action == TCPCHK_ACT_SEND) {
			memprintf(errmsg, "unable to add http-check send rule at step %d (missing connect rule).",
				  chk->index+1);
			return 0;
		}
		else if (r->action != TCPCHK_ACT_SEND && r->action != TCPCHK_ACT_EXPECT && chk->action == TCPCHK_ACT_EXPECT) {
			memprintf(errmsg, "unable to add http-check expect rule at step %d (missing send rule).",
				  chk->index+1);
			return 0;
		}
		else if (r->action != TCPCHK_ACT_EXPECT && chk->action == TCPCHK_ACT_CONNECT) {
			memprintf(errmsg, "unable to add http-check connect rule at step %d (missing expect rule).",
				  chk->index+1);
			return 0;
		}

		if (chk->action == TCPCHK_ACT_SEND) {
			r = get_first_tcpcheck_rule(rules);
			if (r && r->action == TCPCHK_ACT_SEND && (r->send.http.flags & TCPCHK_SND_HTTP_FROM_OPT)) {
				tcpcheck_overwrite_send_http_rule(r, chk);
				free_tcpcheck(chk, 0);
				LIST_DEL(&r->list);
				r->send.http.flags &= ~TCPCHK_SND_HTTP_FROM_OPT;
				chk = r;
			}
		}
		LIST_ADDQ(rules->list, &chk->list);
	}
	return 1;
}

/* Check tcp-check health-check configuration for the proxy <px>. */
static int check_proxy_tcpcheck(struct proxy *px)
{
	struct tcpcheck_rule *chk, *back;
	char *comment = NULL, *errmsg = NULL;
	enum tcpcheck_rule_type prev_action = TCPCHK_ACT_COMMENT;
	int ret = ERR_NONE;

	if (!(px->cap & PR_CAP_BE) || (px->options2 & PR_O2_CHK_ANY) != PR_O2_TCPCHK_CHK) {
		deinit_proxy_tcpcheck(px);
		goto out;
	}

	free(px->check_command);
	free(px->check_path);
	px->check_command = px->check_path = NULL;

	if (!px->tcpcheck_rules.list) {
		ha_alert("config : proxy '%s' : tcp-check configured but no ruleset defined.\n", px->id);
		ret |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	/* HTTP ruleset only :  */
	if ((px->tcpcheck_rules.flags & TCPCHK_RULES_PROTO_CHK) == TCPCHK_RULES_HTTP_CHK) {
		struct tcpcheck_rule *next;

		/* move remaining implicit send rule from "option httpchk" line to the right place.
		 * If such rule exists, it must be the first one. In this case, the rule is moved
		 * after the first connect rule, if any. Otherwise, nothing is done.
		 */
		chk = get_first_tcpcheck_rule(&px->tcpcheck_rules);
		if (chk && chk->action == TCPCHK_ACT_SEND && (chk->send.http.flags & TCPCHK_SND_HTTP_FROM_OPT)) {
			next = get_next_tcpcheck_rule(&px->tcpcheck_rules, chk);
			if (next && next->action == TCPCHK_ACT_CONNECT) {
				LIST_DEL(&chk->list);
				LIST_ADD(&next->list, &chk->list);
				chk->index = next->index;
			}
		}

		/* add implicit expect rule if the last one is a send. It is inherited from previous
		 * versions where the http expect rule was optional. Now it is possible to chained
		 * send/expect rules but the last expect may still be implicit.
		 */
		chk = get_last_tcpcheck_rule(&px->tcpcheck_rules);
		if (chk && chk->action == TCPCHK_ACT_SEND) {
			next = parse_tcpcheck_expect((char *[]){"http-check", "expect", "status", "200-399", ""},
						     1, px, px->tcpcheck_rules.list, TCPCHK_RULES_HTTP_CHK,
						     px->conf.file, px->conf.line, &errmsg);
			if (!next) {
				ha_alert("config : proxy '%s': unable to add implicit http-check expect rule "
					 "(%s).\n", px->id, errmsg);
				free(errmsg);
				ret |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			LIST_ADDQ(px->tcpcheck_rules.list, &next->list);
			next->index = chk->index;
		}
	}

	/* For all ruleset: */

	/* If there is no connect rule preceding all send / expect rules, an
	 * implicit one is inserted before all others.
	 */
	chk = get_first_tcpcheck_rule(&px->tcpcheck_rules);
	if (!chk || chk->action != TCPCHK_ACT_CONNECT) {
		chk = calloc(1, sizeof(*chk));
		if (!chk) {
			ha_alert("config : proxy '%s': unable to add implicit tcp-check connect rule "
				 "(out of memory).\n", px->id);
			ret |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		chk->action = TCPCHK_ACT_CONNECT;
		chk->connect.options = (TCPCHK_OPT_DEFAULT_CONNECT|TCPCHK_OPT_IMPLICIT);
		LIST_ADD(px->tcpcheck_rules.list, &chk->list);
	}

	/* Remove all comment rules. To do so, when a such rule is found, the
	 * comment is assigned to the following rule(s).
	 */
	list_for_each_entry_safe(chk, back, px->tcpcheck_rules.list, list) {
		if (chk->action != prev_action && prev_action != TCPCHK_ACT_COMMENT) {
			free(comment);
			comment = NULL;
		}

		prev_action = chk->action;
		switch (chk->action) {
		case TCPCHK_ACT_COMMENT:
			free(comment);
			comment = chk->comment;
			LIST_DEL(&chk->list);
			free(chk);
			break;
		case TCPCHK_ACT_CONNECT:
			if (!chk->comment && comment)
				chk->comment = strdup(comment);
			/* fall through */
		case TCPCHK_ACT_ACTION_KW:
			free(comment);
			comment = NULL;
			break;
		case TCPCHK_ACT_SEND:
		case TCPCHK_ACT_EXPECT:
			if (!chk->comment && comment)
				chk->comment = strdup(comment);
			break;
		}
	}
	free(comment);
	comment = NULL;

  out:
	return ret;
}

void deinit_proxy_tcpcheck(struct proxy *px)
{
	free_tcpcheck_vars(&px->tcpcheck_rules.preset_vars);
	px->tcpcheck_rules.flags = 0;
	px->tcpcheck_rules.list  = NULL;
}

static void deinit_tcpchecks()
{
	struct tcpcheck_ruleset *rs;
	struct tcpcheck_rule *r, *rb;
	struct ebpt_node *node, *next;

	node = ebpt_first(&shared_tcpchecks);
	while (node) {
		next = ebpt_next(node);
		ebpt_delete(node);
		free(node->key);
		rs = container_of(node, typeof(*rs), node);
		list_for_each_entry_safe(r, rb, &rs->rules, list) {
			LIST_DEL(&r->list);
			free_tcpcheck(r, 0);
		}
		free(rs);
		node = next;
	}
}

int add_tcpcheck_expect_str(struct tcpcheck_rules *rules, const char *str)
{
	struct tcpcheck_rule *tcpcheck, *prev_check;
	struct tcpcheck_expect *expect;

	if ((tcpcheck = pool_alloc(pool_head_tcpcheck_rule)) == NULL)
		return 0;
	memset(tcpcheck, 0, sizeof(*tcpcheck));
	tcpcheck->action = TCPCHK_ACT_EXPECT;

	expect = &tcpcheck->expect;
	expect->type = TCPCHK_EXPECT_STRING;
	LIST_INIT(&expect->onerror_fmt);
	LIST_INIT(&expect->onsuccess_fmt);
	expect->ok_status = HCHK_STATUS_L7OKD;
	expect->err_status = HCHK_STATUS_L7RSP;
	expect->tout_status = HCHK_STATUS_L7TOUT;
	expect->data = ist2(strdup(str), strlen(str));
	if (!isttest(expect->data)) {
		pool_free(pool_head_tcpcheck_rule, tcpcheck);
		return 0;
	}

	/* All tcp-check expect points back to the first inverse expect rule
	 * in a chain of one or more expect rule, potentially itself.
	 */
	tcpcheck->expect.head = tcpcheck;
	list_for_each_entry_rev(prev_check, rules->list, list) {
		if (prev_check->action == TCPCHK_ACT_EXPECT) {
			if (prev_check->expect.flags & TCPCHK_EXPT_FL_INV)
				tcpcheck->expect.head = prev_check;
			continue;
		}
		if (prev_check->action != TCPCHK_ACT_COMMENT && prev_check->action != TCPCHK_ACT_ACTION_KW)
			break;
	}
	LIST_ADDQ(rules->list, &tcpcheck->list);
	return 1;
}

int add_tcpcheck_send_strs(struct tcpcheck_rules *rules, const char * const *strs)
{
	struct tcpcheck_rule *tcpcheck;
	struct tcpcheck_send *send;
	const char *in;
	char *dst;
	int i;

	if ((tcpcheck = pool_alloc(pool_head_tcpcheck_rule)) == NULL)
		return 0;
	memset(tcpcheck, 0, sizeof(*tcpcheck));
	tcpcheck->action       = TCPCHK_ACT_SEND;

	send = &tcpcheck->send;
	send->type = TCPCHK_SEND_STRING;

	for (i = 0; strs[i]; i++)
		send->data.len += strlen(strs[i]);

	send->data.ptr = malloc(istlen(send->data) + 1);
	if (!isttest(send->data)) {
		pool_free(pool_head_tcpcheck_rule, tcpcheck);
		return 0;
	}

	dst = istptr(send->data);
	for (i = 0; strs[i]; i++)
		for (in = strs[i]; (*dst = *in++); dst++);
	*dst = 0;

	LIST_ADDQ(rules->list, &tcpcheck->list);
	return 1;
}

/* Parses the "tcp-check" proxy keyword */
static int proxy_parse_tcpcheck(char **args, int section, struct proxy *curpx,
				struct proxy *defpx, const char *file, int line,
				char **errmsg)
{
	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rule *chk = NULL;
	int index, cur_arg, ret = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[0], NULL))
		ret = 1;

	/* Deduce the ruleset name from the proxy info */
	chunk_printf(&trash, "*tcp-check-%s_%s-%d",
		     ((curpx == defpx) ? "defaults" : curpx->id),
		     curpx->conf.file, curpx->conf.line);

	rs = find_tcpcheck_ruleset(b_orig(&trash));
	if (rs == NULL) {
		rs = create_tcpcheck_ruleset(b_orig(&trash));
		if (rs == NULL) {
			memprintf(errmsg, "out of memory.\n");
			goto error;
		}
	}

	index = 0;
	if (!LIST_ISEMPTY(&rs->rules)) {
		chk = LIST_PREV(&rs->rules, typeof(chk), list);
		index = chk->index + 1;
	}

	cur_arg = 1;
	if (strcmp(args[cur_arg], "connect") == 0)
		chk = parse_tcpcheck_connect(args, cur_arg, curpx, &rs->rules, file, line, errmsg);
	else if (strcmp(args[cur_arg], "send") == 0 || strcmp(args[cur_arg], "send-binary") == 0 ||
		 strcmp(args[cur_arg], "send-lf") == 0 || strcmp(args[cur_arg], "send-binary-lf") == 0)
		chk = parse_tcpcheck_send(args, cur_arg, curpx, &rs->rules, file, line, errmsg);
	else if (strcmp(args[cur_arg], "expect") == 0)
		chk = parse_tcpcheck_expect(args, cur_arg, curpx, &rs->rules, 0, file, line, errmsg);
	else if (strcmp(args[cur_arg], "comment") == 0)
		chk = parse_tcpcheck_comment(args, cur_arg, curpx, &rs->rules, file, line, errmsg);
	else {
		struct action_kw *kw = action_kw_tcp_check_lookup(args[cur_arg]);

		if (!kw) {
			action_kw_tcp_check_build_list(&trash);
			memprintf(errmsg, "'%s' only supports 'comment', 'connect', 'send', 'send-binary', 'expect'"
				  "%s%s. but got '%s'",
				  args[0], (*trash.area ? ", " : ""), trash.area, args[1]);
			goto error;
		}
		chk = parse_tcpcheck_action(args, cur_arg, curpx, &rs->rules, kw, file, line, errmsg);
	}

	if (!chk) {
		memprintf(errmsg, "'%s %s' : %s.", args[0], args[1], *errmsg);
		goto error;
	}
	ret = (ret || (*errmsg != NULL)); /* Handle warning */

	/* No error: add the tcp-check rule in the list */
	chk->index = index;
	LIST_ADDQ(&rs->rules, &chk->list);

	if ((curpx->options2 & PR_O2_CHK_ANY) == PR_O2_TCPCHK_CHK &&
	    (curpx->tcpcheck_rules.flags & TCPCHK_RULES_PROTO_CHK) == TCPCHK_RULES_TCP_CHK) {
		/* Use this ruleset if the proxy already has tcp-check enabled */
		curpx->tcpcheck_rules.list = &rs->rules;
		curpx->tcpcheck_rules.flags &= ~TCPCHK_RULES_UNUSED_TCP_RS;
	}
	else {
		/* mark this ruleset as unused for now */
		curpx->tcpcheck_rules.flags |= TCPCHK_RULES_UNUSED_TCP_RS;
	}

	return ret;

  error:
	free_tcpcheck(chk, 0);
	free_tcpcheck_ruleset(rs);
	return -1;
}

/* Parses the "http-check" proxy keyword */
static int proxy_parse_httpcheck(char **args, int section, struct proxy *curpx,
				 struct proxy *defpx, const char *file, int line,
				 char **errmsg)
{
	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rule *chk = NULL;
	int index, cur_arg, ret = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[0], NULL))
		ret = 1;

	cur_arg = 1;
	if (strcmp(args[cur_arg], "disable-on-404") == 0) {
		/* enable a graceful server shutdown on an HTTP 404 response */
		curpx->options |= PR_O_DISABLE404;
		if (too_many_args(1, args, errmsg, NULL))
			goto error;
		goto out;
	}
	else if (strcmp(args[cur_arg], "send-state") == 0) {
		/* enable emission of the apparent state of a server in HTTP checks */
		curpx->options2 |= PR_O2_CHK_SNDST;
		if (too_many_args(1, args, errmsg, NULL))
			goto error;
		goto out;
	}

	/* Deduce the ruleset name from the proxy info */
	chunk_printf(&trash, "*http-check-%s_%s-%d",
		     ((curpx == defpx) ? "defaults" : curpx->id),
		     curpx->conf.file, curpx->conf.line);

	rs = find_tcpcheck_ruleset(b_orig(&trash));
	if (rs == NULL) {
		rs = create_tcpcheck_ruleset(b_orig(&trash));
		if (rs == NULL) {
			memprintf(errmsg, "out of memory.\n");
			goto error;
		}
	}

	index = 0;
	if (!LIST_ISEMPTY(&rs->rules)) {
		chk = LIST_PREV(&rs->rules, typeof(chk), list);
		if (chk->action != TCPCHK_ACT_SEND || !(chk->send.http.flags & TCPCHK_SND_HTTP_FROM_OPT))
			index = chk->index + 1;
	}

	if (strcmp(args[cur_arg], "connect") == 0)
		chk = parse_tcpcheck_connect(args, cur_arg, curpx, &rs->rules, file, line, errmsg);
	else if (strcmp(args[cur_arg], "send") == 0)
		chk = parse_tcpcheck_send_http(args, cur_arg, curpx, &rs->rules, file, line, errmsg);
	else if (strcmp(args[cur_arg], "expect") == 0)
		chk = parse_tcpcheck_expect(args, cur_arg, curpx, &rs->rules, TCPCHK_RULES_HTTP_CHK,
					    file, line, errmsg);
	else if (strcmp(args[cur_arg], "comment") == 0)
		chk = parse_tcpcheck_comment(args, cur_arg, curpx, &rs->rules, file, line, errmsg);
	else {
		struct action_kw *kw = action_kw_tcp_check_lookup(args[cur_arg]);

		if (!kw) {
			action_kw_tcp_check_build_list(&trash);
			memprintf(errmsg, "'%s' only supports 'disable-on-404', 'send-state', 'comment', 'connect',"
				  " 'send', 'expect'%s%s. but got '%s'",
				  args[0], (*trash.area ? ", " : ""), trash.area, args[1]);
			goto error;
		}
		chk = parse_tcpcheck_action(args, cur_arg, curpx, &rs->rules, kw, file, line, errmsg);
	}

	if (!chk) {
		memprintf(errmsg, "'%s %s' : %s.", args[0], args[1], *errmsg);
		goto error;
	}
	ret = (*errmsg != NULL); /* Handle warning */

	chk->index = index;
	if ((curpx->options2 & PR_O2_CHK_ANY) == PR_O2_TCPCHK_CHK &&
	    (curpx->tcpcheck_rules.flags & TCPCHK_RULES_PROTO_CHK) == TCPCHK_RULES_HTTP_CHK) {
		/* Use this ruleset if the proxy already has http-check enabled */
		curpx->tcpcheck_rules.list = &rs->rules;
		curpx->tcpcheck_rules.flags &= ~TCPCHK_RULES_UNUSED_HTTP_RS;
		if (!tcpcheck_add_http_rule(chk, &curpx->tcpcheck_rules, errmsg)) {
			memprintf(errmsg, "'%s %s' : %s.", args[0], args[1], *errmsg);
			curpx->tcpcheck_rules.list = NULL;
			goto error;
		}
	}
	else {
		/* mark this ruleset as unused for now */
		curpx->tcpcheck_rules.flags |= TCPCHK_RULES_UNUSED_HTTP_RS;
		LIST_ADDQ(&rs->rules, &chk->list);
	}

  out:
	return ret;

  error:
	free_tcpcheck(chk, 0);
	free_tcpcheck_ruleset(rs);
	return -1;
}

/* Parses the "option redis-check" proxy keyword */
int proxy_parse_redis_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
				const char *file, int line)
{
	static char *redis_req = "*1\r\n$4\r\nPING\r\n";
	static char *redis_res = "+PONG\r\n";

	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	struct tcpcheck_rule *chk;
	char *errmsg = NULL;
	int err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(0, 1, file, line, args, &err_code))
		goto out;

	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	free_tcpcheck_vars(&rules->preset_vars);
	rules->list  = NULL;
	rules->flags = 0;

	rs = find_tcpcheck_ruleset("*redis-check");
	if (rs)
		goto ruleset_found;

	rs = create_tcpcheck_ruleset("*redis-check");
	if (rs == NULL) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}

	chk = parse_tcpcheck_send((char *[]){"tcp-check", "send", redis_req, ""},
				  1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 0;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "string", redis_res,
				               "error-status", "L7STS",
				               "on-error", "%[res.payload(0,0),cut_crlf]",
				               "on-success", "Redis server is ok",
				               ""},
				    1, curpx, &rs->rules, TCPCHK_RULES_REDIS_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 1;
	LIST_ADDQ(&rs->rules, &chk->list);

  ruleset_found:
	rules->list = &rs->rules;
	rules->flags &= ~(TCPCHK_RULES_PROTO_CHK|TCPCHK_RULES_UNUSED_RS);
	rules->flags |= TCPCHK_RULES_REDIS_CHK;

  out:
	free(errmsg);
	return err_code;

  error:
	free_tcpcheck_ruleset(rs);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}


/* Parses the "option ssl-hello-chk" proxy keyword */
int proxy_parse_ssl_hello_chk_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
				  const char *file, int line)
{
	/* This is the SSLv3 CLIENT HELLO packet used in conjunction with the
	 * ssl-hello-chk option to ensure that the remote server speaks SSL.
	 *
	 * Check RFC 2246 (TLSv1.0) sections A.3 and A.4 for details.
	 */
	static char sslv3_client_hello[] = {
		"16"                        /* ContentType         : 0x16 = Handshake          */
		"0300"                      /* ProtocolVersion     : 0x0300 = SSLv3            */
		"0079"                      /* ContentLength       : 0x79 bytes after this one */
		"01"                        /* HanshakeType        : 0x01 = CLIENT HELLO       */
		"000075"                    /* HandshakeLength     : 0x75 bytes after this one */
		"0300"                      /* Hello Version       : 0x0300 = v3               */
		"%[date(),htonl,hex]"       /* Unix GMT Time (s)   : filled with <now> (@0x0B) */
		"%[str(HAPROXYSSLCHK\nHAPROXYSSLCHK\n),hex]" /* Random   : must be exactly 28 bytes  */
		"00"                        /* Session ID length   : empty (no session ID)     */
		"004E"                      /* Cipher Suite Length : 78 bytes after this one   */
		"0001" "0002" "0003" "0004" /* 39 most common ciphers :  */
		"0005" "0006" "0007" "0008" /* 0x01...0x1B, 0x2F...0x3A  */
		"0009" "000A" "000B" "000C" /* This covers RSA/DH,       */
		"000D" "000E" "000F" "0010" /* various bit lengths,      */
		"0011" "0012" "0013" "0014" /* SHA1/MD5, DES/3DES/AES... */
		"0015" "0016" "0017" "0018"
		"0019" "001A" "001B" "002F"
		"0030" "0031" "0032" "0033"
		"0034" "0035" "0036" "0037"
		"0038" "0039" "003A"
		"01"                       /* Compression Length  : 0x01 = 1 byte for types   */
		"00"                       /* Compression Type    : 0x00 = NULL compression   */
	};

	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	struct tcpcheck_rule *chk;
	char *errmsg = NULL;
	int err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(0, 1, file, line, args, &err_code))
		goto out;

	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	free_tcpcheck_vars(&rules->preset_vars);
	rules->list  = NULL;
	rules->flags = 0;

	rs = find_tcpcheck_ruleset("*ssl-hello-check");
	if (rs)
		goto ruleset_found;

	rs = create_tcpcheck_ruleset("*ssl-hello-check");
	if (rs == NULL) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}

	chk = parse_tcpcheck_send((char *[]){"tcp-check", "send-binary-lf", sslv3_client_hello, ""},
				  1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 0;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "rbinary", "^1[56]",
				                "min-recv", "5", "ok-status", "L6OK",
				                "error-status", "L6RSP", "tout-status", "L6TOUT",
				                ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_SSL3_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 1;
	LIST_ADDQ(&rs->rules, &chk->list);

  ruleset_found:
	rules->list = &rs->rules;
	rules->flags &= ~(TCPCHK_RULES_PROTO_CHK|TCPCHK_RULES_UNUSED_RS);
	rules->flags |= TCPCHK_RULES_SSL3_CHK;

  out:
	free(errmsg);
	return err_code;

  error:
	free_tcpcheck_ruleset(rs);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

/* Parses the "option smtpchk" proxy keyword */
int proxy_parse_smtpchk_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
			    const char *file, int line)
{
	static char *smtp_req = "%[var(check.smtp_cmd)]\r\n";

	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	struct tcpcheck_rule *chk;
	struct tcpcheck_var *var = NULL;
	char *cmd = NULL, *errmsg = NULL;
	int err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(2, 1, file, line, args, &err_code))
		goto out;

	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	free_tcpcheck_vars(&rules->preset_vars);
	rules->list  = NULL;
	rules->flags = 0;

	cur_arg += 2;
	if (*args[cur_arg] && *args[cur_arg+1] &&
	    (strcmp(args[cur_arg], "EHLO") == 0 || strcmp(args[cur_arg], "HELO") == 0)) {
		/* <EHLO|HELO> + space (1) + <host> + null byte (1) */
		cmd = calloc(strlen(args[cur_arg]) + 1 + strlen(args[cur_arg+1]) + 1, sizeof(*cmd));
		if (cmd)
			sprintf(cmd, "%s %s", args[cur_arg], args[cur_arg+1]);
	}
	else {
		/* this just hits the default for now, but you could potentially expand it to allow for other stuff
		   though, it's unlikely you'd want to send anything other than an EHLO or HELO */
		cmd = strdup("HELO localhost");
	}

	var = create_tcpcheck_var(ist("check.smtp_cmd"));
	if (cmd == NULL || var == NULL) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}
	var->data.type = SMP_T_STR;
	var->data.u.str.area = cmd;
	var->data.u.str.data = strlen(cmd);
	LIST_INIT(&var->list);
	LIST_ADDQ(&rules->preset_vars, &var->list);
	cmd = NULL;
	var = NULL;

	rs = find_tcpcheck_ruleset("*smtp-check");
	if (rs)
		goto ruleset_found;

	rs = create_tcpcheck_ruleset("*smtp-check");
	if (rs == NULL) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}

	chk = parse_tcpcheck_connect((char *[]){"tcp-check", "connect", "default", "linger", ""},
				     1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 0;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "rstring", "^[0-9]{3}[ \r]",
				               "min-recv", "4",
				               "error-status", "L7RSP",
				               "on-error", "%[res.payload(0,0),cut_crlf]",
				               ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_SMTP_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 1;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "rstring", "^2[0-9]{2}[ \r]",
				               "min-recv", "4",
				               "error-status", "L7STS",
				               "on-error", "%[res.payload(4,0),ltrim(' '),cut_crlf]",
				               "status-code", "res.payload(0,3)",
				               ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_SMTP_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 2;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_send((char *[]){"tcp-check", "send-lf", smtp_req, ""},
				  1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 3;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "rstring", "^2[0-9]{2}[- \r]",
				               "min-recv", "4",
				               "error-status", "L7STS",
				               "on-error", "%[res.payload(4,0),ltrim(' '),cut_crlf]",
				               "on-success", "%[res.payload(4,0),ltrim(' '),cut_crlf]",
				               "status-code", "res.payload(0,3)",
				               ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_SMTP_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 4;
	LIST_ADDQ(&rs->rules, &chk->list);

  ruleset_found:
	rules->list = &rs->rules;
	rules->flags &= ~(TCPCHK_RULES_PROTO_CHK|TCPCHK_RULES_UNUSED_RS);
	rules->flags |= TCPCHK_RULES_SMTP_CHK;

  out:
	free(errmsg);
	return err_code;

  error:
	free(cmd);
	free(var);
	free_tcpcheck_vars(&rules->preset_vars);
	free_tcpcheck_ruleset(rs);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

/* Parses the "option pgsql-check" proxy keyword */
int proxy_parse_pgsql_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
				const char *file, int line)
{
	static char pgsql_req[] = {
		"%[var(check.plen),htonl,hex]" /* The packet length*/
		"00030000"                     /* the version 3.0 */
		"7573657200"                   /* "user" key */
		"%[var(check.username),hex]00" /* the username */
		"00"
	};

	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	struct tcpcheck_rule *chk;
	struct tcpcheck_var *var = NULL;
	char *user = NULL, *errmsg = NULL;
	size_t packetlen = 0;
	int err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(2, 1, file, line, args, &err_code))
		goto out;

	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	free_tcpcheck_vars(&rules->preset_vars);
	rules->list  = NULL;
	rules->flags = 0;

	cur_arg += 2;
	if (!*args[cur_arg] || !*args[cur_arg+1]) {
		ha_alert("parsing [%s:%d] : '%s %s' expects 'user <username>' as argument.\n",
			 file, line, args[0], args[1]);
		goto error;
	}
	if (strcmp(args[cur_arg], "user") == 0) {
		packetlen = 15 + strlen(args[cur_arg+1]);
		user = strdup(args[cur_arg+1]);

		var = create_tcpcheck_var(ist("check.username"));
		if (user == NULL || var == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
			goto error;
		}
		var->data.type = SMP_T_STR;
		var->data.u.str.area = user;
		var->data.u.str.data = strlen(user);
		LIST_INIT(&var->list);
		LIST_ADDQ(&rules->preset_vars, &var->list);
		user = NULL;
		var = NULL;

		var = create_tcpcheck_var(ist("check.plen"));
		if (var == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
			goto error;
		}
		var->data.type = SMP_T_SINT;
		var->data.u.sint = packetlen;
		LIST_INIT(&var->list);
		LIST_ADDQ(&rules->preset_vars, &var->list);
		var = NULL;
	}
	else {
		ha_alert("parsing [%s:%d] : '%s %s' only supports optional values: 'user'.\n",
			 file, line, args[0], args[1]);
		goto error;
	}

	rs = find_tcpcheck_ruleset("*pgsql-check");
	if (rs)
		goto ruleset_found;

	rs = create_tcpcheck_ruleset("*pgsql-check");
	if (rs == NULL) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}

	chk = parse_tcpcheck_connect((char *[]){"tcp-check", "connect", "default", "linger", ""},
				     1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 0;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_send((char *[]){"tcp-check", "send-binary-lf", pgsql_req, ""},
				  1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 1;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "!rstring", "^E",
				               "min-recv", "5",
				               "error-status", "L7RSP",
				               "on-error", "%[res.payload(6,0)]",
				               ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_PGSQL_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 2;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "rbinary", "^52000000(08|0A|0C)000000(00|02|03|04|05|06)",
				               "min-recv", "9",
				               "error-status", "L7STS",
				               "on-success", "PostgreSQL server is ok",
				               "on-error",   "PostgreSQL unknown error",
				               ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_PGSQL_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 3;
	LIST_ADDQ(&rs->rules, &chk->list);

  ruleset_found:
	rules->list = &rs->rules;
	rules->flags &= ~(TCPCHK_RULES_PROTO_CHK|TCPCHK_RULES_UNUSED_RS);
	rules->flags |= TCPCHK_RULES_PGSQL_CHK;

  out:
	free(errmsg);
	return err_code;

  error:
	free(user);
	free(var);
	free_tcpcheck_vars(&rules->preset_vars);
	free_tcpcheck_ruleset(rs);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}


/* Parses the "option mysql-check" proxy keyword */
int proxy_parse_mysql_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
				const char *file, int line)
{
	/* This is an example of a MySQL >=4.0 client Authentication packet kindly provided by Cyril Bonte.
	 * const char mysql40_client_auth_pkt[] = {
	 * 	"\x0e\x00\x00"	// packet length
	 * 	"\x01"		// packet number
	 * 	"\x00\x00"	// client capabilities
	 * 	"\x00\x00\x01"	// max packet
	 * 	"haproxy\x00"	// username (null terminated string)
	 * 	"\x00"		// filler (always 0x00)
	 * 	"\x01\x00\x00"	// packet length
	 * 	"\x00"		// packet number
	 * 	"\x01"		// COM_QUIT command
	 * };
	 */
	static char mysql40_rsname[] = "*mysql40-check";
	static char mysql40_req[] = {
		"%[var(check.header),hex]"     /* 3 bytes for the packet length and 1 byte for the sequence ID */
		"0080"                         /* client capabilities */
		"000001"                       /* max packet */
		"%[var(check.username),hex]00" /* the username */
		"00"                           /* filler (always 0x00) */
		"010000"                       /* packet length*/
		"00"                           /* sequence ID */
		"01"                           /* COM_QUIT command */
	};

	/* This is an example of a MySQL >=4.1  client Authentication packet provided by Nenad Merdanovic.
	 * const char mysql41_client_auth_pkt[] = {
	 * 	"\x0e\x00\x00\"		// packet length
	 * 	"\x01"			// packet number
	 * 	"\x00\x00\x00\x00"	// client capabilities
	 * 	"\x00\x00\x00\x01"	// max packet
	 *	"\x21"			// character set (UTF-8)
	 *	char[23]		// All zeroes
	 * 	"haproxy\x00"		// username (null terminated string)
	 * 	"\x00"			// filler (always 0x00)
	 * 	"\x01\x00\x00"		// packet length
	 * 	"\x00"			// packet number
	 * 	"\x01"			// COM_QUIT command
	 * };
	 */
	static char mysql41_rsname[] = "*mysql41-check";
	static char mysql41_req[] = {
		"%[var(check.header),hex]"     /* 3 bytes for the packet length and 1 byte for the sequence ID */
		"00820000"                     /* client capabilities */
		"00800001"                     /* max packet */
		"21"                           /* character set (UTF-8) */
		"000000000000000000000000"     /* 23 bytes, al zeroes */
		"0000000000000000000000"
		"%[var(check.username),hex]00" /* the username */
		"00"                           /* filler (always 0x00) */
		"010000"                       /* packet length*/
		"00"                           /* sequence ID */
		"01"                           /* COM_QUIT command */
	};

	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	struct tcpcheck_rule *chk;
	struct tcpcheck_var *var = NULL;
	char *mysql_rsname = "*mysql-check";
	char *mysql_req = NULL, *hdr = NULL, *user = NULL, *errmsg = NULL;
	int index = 0, err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(3, 1, file, line, args, &err_code))
		goto out;

	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	free_tcpcheck_vars(&rules->preset_vars);
	rules->list  = NULL;
	rules->flags = 0;

	cur_arg += 2;
	if (*args[cur_arg]) {
		int packetlen, userlen;

		if (strcmp(args[cur_arg], "user") != 0) {
			ha_alert("parsing [%s:%d] : '%s %s' only supports optional values: 'user' (got '%s').\n",
				 file, line, args[0], args[1], args[cur_arg]);
			goto error;
		}

		if (*(args[cur_arg+1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s %s %s' expects <username> as argument.\n",
				 file, line, args[0], args[1], args[cur_arg]);
			goto error;
		}

		hdr     = calloc(4, sizeof(*hdr));
		user    = strdup(args[cur_arg+1]);
		userlen = strlen(args[cur_arg+1]);

		if (hdr == NULL || user == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
			goto error;
		}

		if (!*args[cur_arg+2] || strcmp(args[cur_arg+2], "post-41") == 0) {
			packetlen = userlen + 7 + 27;
			mysql_req = mysql41_req;
			mysql_rsname  = mysql41_rsname;
		}
		else if (strcmp(args[cur_arg+2], "pre-41") == 0) {
			packetlen = userlen + 7;
			mysql_req = mysql40_req;
			mysql_rsname  = mysql40_rsname;
		}
		else  {
			ha_alert("parsing [%s:%d] : keyword '%s' only supports 'post-41' and 'pre-41' (got '%s').\n",
				 file, line, args[cur_arg], args[cur_arg+2]);
			goto error;
		}

		hdr[0] = (unsigned char)(packetlen & 0xff);
		hdr[1] = (unsigned char)((packetlen >> 8) & 0xff);
		hdr[2] = (unsigned char)((packetlen >> 16) & 0xff);
		hdr[3] = 1;

		var = create_tcpcheck_var(ist("check.header"));
		if (var == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
			goto error;
		}
		var->data.type = SMP_T_STR;
		var->data.u.str.area = hdr;
		var->data.u.str.data = 4;
		LIST_INIT(&var->list);
		LIST_ADDQ(&rules->preset_vars, &var->list);
		hdr = NULL;
		var = NULL;

		var = create_tcpcheck_var(ist("check.username"));
		if (var == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
			goto error;
		}
		var->data.type = SMP_T_STR;
		var->data.u.str.area = user;
		var->data.u.str.data = strlen(user);
		LIST_INIT(&var->list);
		LIST_ADDQ(&rules->preset_vars, &var->list);
		user = NULL;
		var = NULL;
	}

	rs = find_tcpcheck_ruleset(mysql_rsname);
	if (rs)
		goto ruleset_found;

	rs = create_tcpcheck_ruleset(mysql_rsname);
	if (rs == NULL) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}

	chk = parse_tcpcheck_connect((char *[]){"tcp-check", "connect", "default", "linger", ""},
				     1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = index++;
	LIST_ADDQ(&rs->rules, &chk->list);

	if (mysql_req) {
		chk = parse_tcpcheck_send((char *[]){"tcp-check", "send-binary-lf", mysql_req, ""},
					  1, curpx, &rs->rules, file, line, &errmsg);
		if (!chk) {
			ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
			goto error;
		}
		chk->index = index++;
		LIST_ADDQ(&rs->rules, &chk->list);
	}

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "custom", ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_MYSQL_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->expect.custom = tcpcheck_mysql_expect_iniths;
	chk->index = index++;
	LIST_ADDQ(&rs->rules, &chk->list);

	if (mysql_req) {
		chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "custom", ""},
					    1, curpx, &rs->rules, TCPCHK_RULES_MYSQL_CHK, file, line, &errmsg);
		if (!chk) {
			ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
			goto error;
		}
		chk->expect.custom = tcpcheck_mysql_expect_ok;
		chk->index = index++;
		LIST_ADDQ(&rs->rules, &chk->list);
	}

  ruleset_found:
	rules->list = &rs->rules;
	rules->flags &= ~(TCPCHK_RULES_PROTO_CHK|TCPCHK_RULES_UNUSED_RS);
	rules->flags |= TCPCHK_RULES_MYSQL_CHK;

  out:
	free(errmsg);
	return err_code;

  error:
	free(hdr);
	free(user);
	free(var);
	free_tcpcheck_vars(&rules->preset_vars);
	free_tcpcheck_ruleset(rs);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

int proxy_parse_ldap_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
			       const char *file, int line)
{
	static char *ldap_req = "300C020101600702010304008000";

	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	struct tcpcheck_rule *chk;
	char *errmsg = NULL;
	int err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(0, 1, file, line, args, &err_code))
		goto out;

	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	free_tcpcheck_vars(&rules->preset_vars);
	rules->list  = NULL;
	rules->flags = 0;

	rs = find_tcpcheck_ruleset("*ldap-check");
	if (rs)
		goto ruleset_found;

	rs = create_tcpcheck_ruleset("*ldap-check");
	if (rs == NULL) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}

	chk = parse_tcpcheck_send((char *[]){"tcp-check", "send-binary", ldap_req, ""},
				  1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 0;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "rbinary", "^30",
				               "min-recv", "14",
				               "on-error", "Not LDAPv3 protocol",
				               ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_LDAP_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 1;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "custom", ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_LDAP_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->expect.custom = tcpcheck_ldap_expect_bindrsp;
	chk->index = 2;
	LIST_ADDQ(&rs->rules, &chk->list);

  ruleset_found:
	rules->list = &rs->rules;
	rules->flags &= ~(TCPCHK_RULES_PROTO_CHK|TCPCHK_RULES_UNUSED_RS);
	rules->flags |= TCPCHK_RULES_LDAP_CHK;

  out:
	free(errmsg);
	return err_code;

  error:
	free_tcpcheck_ruleset(rs);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

int proxy_parse_spop_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
			       const char *file, int line)
{
	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	struct tcpcheck_rule *chk;
	char *spop_req = NULL;
	char *errmsg = NULL;
	int spop_len = 0, err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(0, 1, file, line, args, &err_code))
		goto out;

	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	free_tcpcheck_vars(&rules->preset_vars);
	rules->list  = NULL;
	rules->flags = 0;


	rs = find_tcpcheck_ruleset("*spop-check");
	if (rs)
		goto ruleset_found;

	rs = create_tcpcheck_ruleset("*spop-check");
	if (rs == NULL) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}

	if (spoe_prepare_healthcheck_request(&spop_req, &spop_len) == -1) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}
	chunk_reset(&trash);
	dump_binary(&trash, spop_req, spop_len);
	trash.area[trash.data] = '\0';

	chk = parse_tcpcheck_send((char *[]){"tcp-check", "send-binary", b_head(&trash), ""},
				  1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 0;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "custom", "min-recv", "4", ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_SPOP_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->expect.custom = tcpcheck_spop_expect_agenthello;
	chk->index = 1;
	LIST_ADDQ(&rs->rules, &chk->list);

  ruleset_found:
	rules->list = &rs->rules;
	rules->flags &= ~(TCPCHK_RULES_PROTO_CHK|TCPCHK_RULES_UNUSED_RS);
	rules->flags |= TCPCHK_RULES_SPOP_CHK;

  out:
	free(spop_req);
	free(errmsg);
	return err_code;

  error:
	free_tcpcheck_ruleset(rs);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}


static struct tcpcheck_rule *proxy_parse_httpchk_req(char **args, int cur_arg, struct proxy *px, char **errmsg)
{
	struct tcpcheck_rule *chk = NULL;
	struct tcpcheck_http_hdr *hdr = NULL;
	char *meth = NULL, *uri = NULL, *vsn = NULL;
	char *hdrs, *body;

	hdrs = (*args[cur_arg+2] ? strstr(args[cur_arg+2], "\r\n") : NULL);
	body = (*args[cur_arg+2] ? strstr(args[cur_arg+2], "\r\n\r\n") : NULL);
	if (hdrs == body)
		hdrs = NULL;
	if (hdrs) {
		*hdrs = '\0';
		hdrs +=2;
	}
	if (body) {
		*body = '\0';
		body += 4;
	}
	if (hdrs || body) {
		memprintf(errmsg, "hiding headers or body at the end of the version string is deprecated."
			  " Please, consider to use 'http-check send' directive instead.");
	}

	chk = calloc(1, sizeof(*chk));
	if (!chk) {
		memprintf(errmsg, "out of memory");
		goto error;
	}
	chk->action    = TCPCHK_ACT_SEND;
	chk->send.type = TCPCHK_SEND_HTTP;
	chk->send.http.flags |= TCPCHK_SND_HTTP_FROM_OPT;
	chk->send.http.meth.meth = HTTP_METH_OPTIONS;
	LIST_INIT(&chk->send.http.hdrs);

	/* Copy the method, uri and version */
	if (*args[cur_arg]) {
		if (!*args[cur_arg+1])
			uri = args[cur_arg];
		else
			meth = args[cur_arg];
	}
	if (*args[cur_arg+1])
		uri = args[cur_arg+1];
	if (*args[cur_arg+2])
		vsn = args[cur_arg+2];

	if (meth) {
		chk->send.http.meth.meth = find_http_meth(meth, strlen(meth));
		chk->send.http.meth.str.area = strdup(meth);
		chk->send.http.meth.str.data = strlen(meth);
		if (!chk->send.http.meth.str.area) {
			memprintf(errmsg, "out of memory");
			goto error;
		}
	}
	if (uri) {
		chk->send.http.uri = ist2(strdup(uri), strlen(uri));
		if (!isttest(chk->send.http.uri)) {
			memprintf(errmsg, "out of memory");
			goto error;
		}
	}
	if (vsn) {
		chk->send.http.vsn = ist2(strdup(vsn), strlen(vsn));
		if (!isttest(chk->send.http.vsn)) {
			memprintf(errmsg, "out of memory");
			goto error;
		}
	}

	/* Copy the header */
	if (hdrs) {
		struct http_hdr tmp_hdrs[global.tune.max_http_hdr];
		struct h1m h1m;
		int i, ret;

		/* Build and parse the request */
		chunk_printf(&trash, "%s\r\n\r\n", hdrs);

		h1m.flags = H1_MF_HDRS_ONLY;
		ret = h1_headers_to_hdr_list(b_orig(&trash), b_tail(&trash),
					     tmp_hdrs, sizeof(tmp_hdrs)/sizeof(tmp_hdrs[0]),
					     &h1m, NULL);
		if (ret <= 0) {
			memprintf(errmsg, "unable to parse the request '%s'.", b_orig(&trash));
			goto error;
		}

		for (i = 0; istlen(tmp_hdrs[i].n); i++) {
			hdr = calloc(1, sizeof(*hdr));
			if (!hdr) {
				memprintf(errmsg, "out of memory");
				goto error;
			}
			LIST_INIT(&hdr->value);
			hdr->name = istdup(tmp_hdrs[i].n);
			if (!hdr->name.ptr) {
				memprintf(errmsg, "out of memory");
				goto error;
			}

			ist0(tmp_hdrs[i].v);
			if (!parse_logformat_string(istptr(tmp_hdrs[i].v), px, &hdr->value, 0, SMP_VAL_BE_CHK_RUL, errmsg))
				goto error;
			LIST_ADDQ(&chk->send.http.hdrs, &hdr->list);
		}
	}

	/* Copy the body */
	if (body) {
		chk->send.http.body = ist2(strdup(body), strlen(body));
		if (!isttest(chk->send.http.body)) {
			memprintf(errmsg, "out of memory");
			goto error;
		}
	}

	return chk;

  error:
	free_tcpcheck_http_hdr(hdr);
	free_tcpcheck(chk, 0);
	return NULL;
}

/* Parses the "option httpchck" proxy keyword */
int proxy_parse_httpchk_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
			    const char *file, int line)
{
	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	struct tcpcheck_rule *chk;
	char *errmsg = NULL;
	int err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(3, 1, file, line, args, &err_code))
		goto out;

	chk = proxy_parse_httpchk_req(args, cur_arg+2, curpx, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : '%s %s' : %s.\n", file, line, args[0], args[1], errmsg);
		goto error;
	}
	if (errmsg) {
		ha_warning("parsing [%s:%d]: '%s %s' : %s\n", file, line, args[0], args[1], errmsg);
		err_code |= ERR_WARN;
		free(errmsg);
		errmsg = NULL;
	}

  no_request:
	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	free_tcpcheck_vars(&rules->preset_vars);
	rules->list = NULL;
	rules->flags |= TCPCHK_SND_HTTP_FROM_OPT;

	/* Deduce the ruleset name from the proxy info */
	chunk_printf(&trash, "*http-check-%s_%s-%d",
		     ((curpx == defpx) ? "defaults" : curpx->id),
		     curpx->conf.file, curpx->conf.line);

	rs = find_tcpcheck_ruleset(b_orig(&trash));
	if (rs == NULL) {
		rs = create_tcpcheck_ruleset(b_orig(&trash));
		if (rs == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
			goto error;
		}
	}

	rules->list = &rs->rules;
	rules->flags &= ~(TCPCHK_RULES_PROTO_CHK|TCPCHK_RULES_UNUSED_RS);
	rules->flags |= TCPCHK_RULES_HTTP_CHK;
	if (!tcpcheck_add_http_rule(chk, rules, &errmsg)) {
		ha_alert("parsing [%s:%d] : '%s %s' : %s.\n", file, line, args[0], args[1], errmsg);
		rules->list = NULL;
		goto error;
	}

  out:
	free(errmsg);
	return err_code;

  error:
	free_tcpcheck_ruleset(rs);
	free_tcpcheck(chk, 0);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

/* Parses the "option tcp-check" proxy keyword */
int proxy_parse_tcp_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
			      const char *file, int line)
{
	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	int err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(0, 1, file, line, args, &err_code))
		goto out;

	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	if ((rules->flags & TCPCHK_RULES_PROTO_CHK) == TCPCHK_RULES_TCP_CHK) {
		/* If a tcp-check rulesset is already set, do nothing */
		if (rules->list)
			goto out;

		/* If a tcp-check ruleset is waiting to be used for the current proxy,
		 * get it.
		 */
		if (rules->flags & TCPCHK_RULES_UNUSED_TCP_RS)
			goto curpx_ruleset;

		/* Otherwise, try to get the tcp-check ruleset of the default proxy */
		chunk_printf(&trash, "*tcp-check-defaults_%s-%d", defpx->conf.file, defpx->conf.line);
		rs = find_tcpcheck_ruleset(b_orig(&trash));
		if (rs)
			goto ruleset_found;
	}

  curpx_ruleset:
	/* Deduce the ruleset name from the proxy info */
	chunk_printf(&trash, "*tcp-check-%s_%s-%d",
		     ((curpx == defpx) ? "defaults" : curpx->id),
		     curpx->conf.file, curpx->conf.line);

	rs = find_tcpcheck_ruleset(b_orig(&trash));
	if (rs == NULL) {
		rs = create_tcpcheck_ruleset(b_orig(&trash));
		if (rs == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
			goto error;
		}
	}

  ruleset_found:
	free_tcpcheck_vars(&rules->preset_vars);
	rules->list = &rs->rules;
	rules->flags &= ~(TCPCHK_RULES_PROTO_CHK|TCPCHK_RULES_UNUSED_RS);
	rules->flags |= TCPCHK_RULES_TCP_CHK;

  out:
	return err_code;

  error:
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

static struct cfg_kw_list cfg_kws = {ILH, {
        { CFG_LISTEN, "http-check",     proxy_parse_httpcheck },
        { CFG_LISTEN, "tcp-check",      proxy_parse_tcpcheck },
        { 0, NULL, NULL },
}};

REGISTER_POST_PROXY_CHECK(check_proxy_tcpcheck);
REGISTER_PROXY_DEINIT(deinit_proxy_tcpcheck);
REGISTER_POST_DEINIT(deinit_tcpchecks);
INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
