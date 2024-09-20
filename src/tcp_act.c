/*
 * AF_INET/AF_INET6 SOCK_STREAM protocol layer (tcp)
 *
 * Copyright 2000-2013 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/tcp.h>
#include <netinet/in.h>

#include <haproxy/action.h>
#include <haproxy/api.h>
#include <haproxy/arg.h>
#include <haproxy/channel.h>
#include <haproxy/connection.h>
#include <haproxy/global.h>
#include <haproxy/http_rules.h>
#include <haproxy/log.h>
#include <haproxy/proto_tcp.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/sc_strm.h>
#include <haproxy/server.h>
#include <haproxy/session.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/tools.h>

static enum act_return tcp_action_attach_srv(struct act_rule *rule, struct proxy *px,
                                             struct session *sess, struct stream *s, int flags)
{
	struct server *srv = rule->arg.attach_srv.srv;
	struct sample *name_smp;
	struct connection *conn = objt_conn(sess->origin);
	if (!conn)
		return ACT_RET_ABRT;

	conn_set_reverse(conn, &srv->obj_type);

	if (rule->arg.attach_srv.name) {
		name_smp = sample_fetch_as_type(sess->fe, sess, s,
		                                SMP_OPT_DIR_REQ | SMP_OPT_FINAL,
		                                rule->arg.attach_srv.name, SMP_T_STR);
		/* TODO strdup du buffer du sample */
		if (name_smp) {
			struct buffer *buf = &name_smp->data.u.str;
			char *area = malloc(b_data(buf));

			if (!area)
				return ACT_RET_ERR;

			conn->reverse.name = b_make(area, b_data(buf), 0, 0);
			b_ncat(&conn->reverse.name, buf, b_data(buf));
		}
	}

	return ACT_RET_CONT;
}

/* tries to extract integer value from rule's argument:
 *  if expr is set, computes expr and sets the result into <value>
 *  else, it's already a numerical value, use it as-is.
 *
 * Returns 1 on success and 0 on failure.
 */
static int extract_int_from_rule(struct act_rule *rule,
                                 struct proxy *px, struct session *sess, struct stream *s,
                                 int *value)
{
	struct sample *smp;

	if (!rule->arg.expr_int.expr) {
		*value = rule->arg.expr_int.value;
		return 1;
	}
	smp = sample_fetch_as_type(px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->arg.expr_int.expr, SMP_T_SINT);
	if (!smp)
		return 0;
	*value = smp->data.u.sint;
	return 1;
}

/*
 * Execute the "set-src" action. May be called from {tcp,http}request.
 * It only changes the address and tries to preserve the original port. If the
 * previous family was neither AF_INET nor AF_INET6, the port is set to zero.
 */
static enum act_return tcp_action_req_set_src(struct act_rule *rule, struct proxy *px,
                                              struct session *sess, struct stream *s, int flags)
{
	struct connection *cli_conn;
	struct sockaddr_storage *src;
	struct sample *smp;

	switch (rule->from) {
	case ACT_F_TCP_REQ_CON:
		cli_conn = objt_conn(sess->origin);
		if (!cli_conn || !conn_get_src(cli_conn))
			goto end;
		src = cli_conn->src;
		break;

	case ACT_F_TCP_REQ_SES:
		if (!sess_get_src(sess))
			goto end;
		src = sess->src;
		break;

	case ACT_F_TCP_REQ_CNT:
	case ACT_F_HTTP_REQ:
		if (!sc_get_src(s->scf))
			goto end;
		src = s->scf->src;
		break;

	default:
		goto end;
	}

	smp = sample_fetch_as_type(px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->arg.expr, SMP_T_ADDR);
	if (smp) {
		int port = get_net_port(src);

		if (smp->data.type == SMP_T_IPV4) {
			((struct sockaddr_in *)src)->sin_family = AF_INET;
			((struct sockaddr_in *)src)->sin_addr.s_addr = smp->data.u.ipv4.s_addr;
			((struct sockaddr_in *)src)->sin_port = port;
		} else if (smp->data.type == SMP_T_IPV6) {
			((struct sockaddr_in6 *)src)->sin6_family = AF_INET6;
			memcpy(&((struct sockaddr_in6 *)src)->sin6_addr, &smp->data.u.ipv6, sizeof(struct in6_addr));
			((struct sockaddr_in6 *)src)->sin6_port = port;
		}
	}

  end:
	return ACT_RET_CONT;
}

/*
 * Execute the "set-dst" action. May be called from {tcp,http}request.
 * It only changes the address and tries to preserve the original port. If the
 * previous family was neither AF_INET nor AF_INET6, the port is set to zero.
 */
static enum act_return tcp_action_req_set_dst(struct act_rule *rule, struct proxy *px,
                                              struct session *sess, struct stream *s, int flags)
{
	struct connection *cli_conn;
	struct sockaddr_storage *dst;
	struct sample *smp;

	switch (rule->from) {
	case ACT_F_TCP_REQ_CON:
		cli_conn = objt_conn(sess->origin);
		if (!cli_conn || !conn_get_dst(cli_conn))
			goto end;
		dst = cli_conn->dst;
		break;

	case ACT_F_TCP_REQ_SES:
		if (!sess_get_dst(sess))
			goto end;
		dst = sess->dst;
		break;

	case ACT_F_TCP_REQ_CNT:
	case ACT_F_HTTP_REQ:
		if (!sc_get_dst(s->scf))
			goto end;
		dst = s->scf->dst;
		break;

	default:
		goto end;
	}

	smp = sample_fetch_as_type(px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->arg.expr, SMP_T_ADDR);
	if (smp) {
		int port = get_net_port(dst);

		if (smp->data.type == SMP_T_IPV4) {
			((struct sockaddr_in *)dst)->sin_family = AF_INET;
			((struct sockaddr_in *)dst)->sin_addr.s_addr = smp->data.u.ipv4.s_addr;
			((struct sockaddr_in *)dst)->sin_port = port;
		} else if (smp->data.type == SMP_T_IPV6) {
			((struct sockaddr_in6 *)dst)->sin6_family = AF_INET6;
			memcpy(&((struct sockaddr_in6 *)dst)->sin6_addr, &smp->data.u.ipv6, sizeof(struct in6_addr));
			((struct sockaddr_in6 *)dst)->sin6_port = port;
		}
	}

  end:
	return ACT_RET_CONT;
}

/*
 * Execute the "set-src-port" action. May be called from {tcp,http}request.
 * We must test the sin_family before setting the port. If the address family
 * is neither AF_INET nor AF_INET6, the address is forced to AF_INET "0.0.0.0"
 * and the port is assigned.
 */
static enum act_return tcp_action_req_set_src_port(struct act_rule *rule, struct proxy *px,
                                                   struct session *sess, struct stream *s, int flags)
{
	struct connection *cli_conn;
	struct sockaddr_storage *src;
	struct sample *smp;

	switch (rule->from) {
	case ACT_F_TCP_REQ_CON:
		cli_conn = objt_conn(sess->origin);
		if (!cli_conn || !conn_get_src(cli_conn))
			goto end;
		src = cli_conn->src;
		break;

	case ACT_F_TCP_REQ_SES:
		if (!sess_get_src(sess))
			goto end;
		src = sess->src;
		break;

	case ACT_F_TCP_REQ_CNT:
	case ACT_F_HTTP_REQ:
		if (!sc_get_src(s->scf))
			goto end;
		src = s->scf->src;
		break;

	default:
		goto end;
	}

	smp = sample_fetch_as_type(px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->arg.expr, SMP_T_SINT);
	if (smp) {
		if (src->ss_family == AF_INET6) {
			((struct sockaddr_in6 *)src)->sin6_port = htons(smp->data.u.sint);
		} else {
			if (src->ss_family != AF_INET) {
				src->ss_family = AF_INET;
				((struct sockaddr_in *)src)->sin_addr.s_addr = 0;
			}
			((struct sockaddr_in *)src)->sin_port = htons(smp->data.u.sint);
		}
	}

  end:
	return ACT_RET_CONT;
}

/*
 * Execute the "set-dst-port" action. May be called from {tcp,http}request.
 * We must test the sin_family before setting the port. If the address family
 * is neither AF_INET nor AF_INET6, the address is forced to AF_INET "0.0.0.0"
 * and the port is assigned.
 */
static enum act_return tcp_action_req_set_dst_port(struct act_rule *rule, struct proxy *px,
                                                   struct session *sess, struct stream *s, int flags)
{
	struct connection *cli_conn;
	struct sockaddr_storage *dst;
	struct sample *smp;

	switch (rule->from) {
	case ACT_F_TCP_REQ_CON:
		cli_conn = objt_conn(sess->origin);
		if (!cli_conn || !conn_get_dst(cli_conn))
			goto end;
		dst = cli_conn->dst;
		break;

	case ACT_F_TCP_REQ_SES:
		if (!sess_get_dst(sess))
			goto end;
		dst = sess->dst;
		break;

	case ACT_F_TCP_REQ_CNT:
	case ACT_F_HTTP_REQ:
		if (!sc_get_dst(s->scf))
			goto end;
		dst = s->scf->dst;
		break;

	default:
		goto end;
	}

	smp = sample_fetch_as_type(px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->arg.expr, SMP_T_SINT);
	if (smp) {
		if (dst->ss_family == AF_INET6) {
			((struct sockaddr_in6 *)dst)->sin6_port = htons(smp->data.u.sint);
		} else {
			if (dst->ss_family != AF_INET) {
				dst->ss_family = AF_INET;
				((struct sockaddr_in *)dst)->sin_addr.s_addr = 0;
			}
			((struct sockaddr_in *)dst)->sin_port = htons(smp->data.u.sint);
		}
	}

  end:
	return ACT_RET_CONT;
}

/* Executes the "silent-drop" action. May be called from {tcp,http}{request,response}.
 * If rule->arg.act.p[0] is 0, TCP_REPAIR is tried first, with a fallback to
 * sending a RST with TTL 1 towards the client. If it is [1-255], we will skip
 * TCP_REPAIR and prepare the socket to send a RST with the requested TTL when
 * the connection is killed by channel_abort().
 */
static enum act_return tcp_exec_action_silent_drop(struct act_rule *rule, struct proxy *px,
                                                   struct session *sess, struct stream *strm, int flags)
{
	struct connection *conn = objt_conn(sess->origin);
	unsigned int ttl __maybe_unused = (uintptr_t)rule->arg.act.p[0];
	char tcp_repair_enabled __maybe_unused;

	if (ttl == 0) {
		tcp_repair_enabled = 1;
		ttl = 1;
	} else {
		tcp_repair_enabled = 0;
	}

	if (!conn)
		goto out;

	if (!conn_ctrl_ready(conn))
		goto out;

#ifdef TCP_QUICKACK
	/* drain is needed only to send the quick ACK */
	conn_ctrl_drain(conn);

	/* re-enable quickack if it was disabled to ack all data and avoid
	 * retransmits from the client that might trigger a real reset.
	 */
	setsockopt(conn->handle.fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
#endif
	/* lingering must absolutely be disabled so that we don't send a
	 * shutdown(), this is critical to the TCP_REPAIR trick. When no stream
	 * is present, returning with ERR will cause lingering to be disabled.
	 */
	if (strm)
		strm->scf->flags |= SC_FL_NOLINGER;

	if (conn->flags & CO_FL_FDLESS)
		goto out;

	/* We're on the client-facing side, we must force to disable lingering to
	 * ensure we will use an RST exclusively and kill any pending data.
	 */
	HA_ATOMIC_OR(&fdtab[conn->handle.fd].state, FD_LINGER_RISK);

#ifdef TCP_REPAIR
	/* try to put socket in repair mode if sending a RST was not requested by
	 * config. this often fails due to missing permissions (CAP_NET_ADMIN capability)
	 */
	if (tcp_repair_enabled && (setsockopt(conn->handle.fd, IPPROTO_TCP, TCP_REPAIR, &one, sizeof(one)) == 0)) {
		/* socket will be quiet now */
		goto out;
	}
#endif

	/* Either TCP_REPAIR is not defined, it failed (eg: permissions), or was
	 * not executed because a RST with a specific TTL was requested to be sent.
	 * Set the TTL of the client connection before the connection is killed
	 * by channel_abort and a RST packet will be emitted by the TCP/IP stack.
	 */
#ifdef IP_TTL
	if (conn->src && conn->src->ss_family == AF_INET)
		setsockopt(conn->handle.fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
#endif
#ifdef IPV6_UNICAST_HOPS
	if (conn->src && conn->src->ss_family == AF_INET6)
		setsockopt(conn->handle.fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
#endif
 out:
	/* kill the stream if any */
	if (strm) {
		stream_abort(strm);
		strm->req.analysers &= AN_REQ_FLT_END;
		strm->res.analysers &= AN_RES_FLT_END;
		if (strm->flags & SF_BE_ASSIGNED)
			_HA_ATOMIC_INC(&strm->be->be_counters.denied_req);
		if (!(strm->flags & SF_ERR_MASK))
			strm->flags |= SF_ERR_PRXCOND;
		if (!(strm->flags & SF_FINST_MASK))
			strm->flags |= SF_FINST_R;
	}

	_HA_ATOMIC_INC(&sess->fe->fe_counters.denied_req);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->denied_req);

	return ACT_RET_ABRT;
}


#if defined(SO_MARK) || defined(SO_USER_COOKIE) || defined(SO_RTABLE)
static enum act_return tcp_action_set_fc_mark(struct act_rule *rule, struct proxy *px,
                                              struct session *sess, struct stream *s, int flags)
{
	unsigned int mark;

	if (extract_int_from_rule(rule, px, sess, s, (int *)&mark))
		conn_set_mark(objt_conn(sess->origin), mark);
	return ACT_RET_CONT;
}
static enum act_return tcp_action_set_bc_mark(struct act_rule *rule, struct proxy *px,
                                              struct session *sess, struct stream *s, int flags)
{
	struct connection __maybe_unused *conn = (s && s->scb) ? sc_conn(s->scb) : NULL;
	unsigned int mark;

	BUG_ON(!s || conn);
	if (extract_int_from_rule(rule, px, sess, s, (int *)&mark)) {
		/* connection does not exist yet, ensure it will be applied
		 * before connection is used by saving it within the stream
		 */
		s->bc_mark = mark;
		s->flags |= SF_BC_MARK;
	}
	return ACT_RET_CONT;
}
#endif

#ifdef IP_TOS
static enum act_return tcp_action_set_fc_tos(struct act_rule *rule, struct proxy *px,
                                             struct session *sess, struct stream *s, int flags)
{
	int tos;

	if (extract_int_from_rule(rule, px, sess, s, &tos))
		conn_set_tos(objt_conn(sess->origin), tos);
	return ACT_RET_CONT;
}
static enum act_return tcp_action_set_bc_tos(struct act_rule *rule, struct proxy *px,
                                             struct session *sess, struct stream *s, int flags)
{
	struct connection __maybe_unused *conn = (s && s->scb) ? sc_conn(s->scb) : NULL;
	int tos;

	BUG_ON(!s || conn);
	if (extract_int_from_rule(rule, px, sess, s, &tos)) {
		/* connection does not exist yet, ensure it will be applied
		 * before connection is used by saving it within the stream
		 */
		s->bc_tos = tos;
		s->flags |= SF_BC_TOS;
	}
	return ACT_RET_CONT;
}
#endif

/*
 * Release the sample expr when releasing attach-srv action
 */
static void release_attach_srv_action(struct act_rule *rule)
{
	ha_free(&rule->arg.attach_srv.srvname);
	release_sample_expr(rule->arg.attach_srv.name);
}

/*
 * Release the sample expr when releasing a set src/dst action
 */
static void release_set_src_dst_action(struct act_rule *rule)
{
	release_sample_expr(rule->arg.expr);
}

static int tcp_check_attach_srv(struct act_rule *rule, struct proxy *px, char **err)
{
	struct proxy *be = NULL;
	struct server *srv = NULL;
	char *name = rule->arg.attach_srv.srvname;
	struct ist be_name, sv_name;

	if (px->mode != PR_MODE_HTTP) {
		memprintf(err, "attach-srv rule requires HTTP proxy mode");
		return 0;
	}

	sv_name = ist(name);
	be_name = istsplit(&sv_name, '/');
	if (!istlen(sv_name)) {
		memprintf(err, "attach-srv rule: invalid server name '%s'", name);
		return 0;
	}

	if (!(be = proxy_be_by_name(ist0(be_name)))) {
		memprintf(err, "attach-srv rule: no such backend '%s/%s'", ist0(be_name), ist0(sv_name));
		return 0;
	}
	if (!(srv = server_find_by_name(be, ist0(sv_name)))) {
		memprintf(err, "attach-srv rule: no such server '%s/%s'", ist0(be_name), ist0(sv_name));
		return 0;
	}

	if (rule->arg.attach_srv.name) {
		if (!srv->pool_conn_name) {
			memprintf(err, "attach-srv rule has a name argument while server '%s/%s' does not use pool-conn-name; either reconfigure the server or remove the name argument from this attach-srv rule", ist0(be_name), ist0(sv_name));
			return 0;
		}
	} else {
		if (srv->pool_conn_name) {
			memprintf(err, "attach-srv rule has no name argument while server '%s/%s' uses pool-conn-name; either add a name argument to the attach-srv rule or reconfigure the server", ist0(be_name), ist0(sv_name));
			return 0;
		}
	}

	rule->arg.attach_srv.srv = srv;

	return 1;
}

static enum act_parse_ret tcp_parse_attach_srv(const char **args, int *cur_arg, struct proxy *px,
                                               struct act_rule *rule, char **err)
{
	char *srvname;
	struct sample_expr *expr;

	/* TODO duplicated code from check_kw_experimental() */
	if (!experimental_directives_allowed) {
		memprintf(err, "parsing [%s:%d] : '%s' action is experimental, must be allowed via a global 'expose-experimental-directives'",
		          px->conf.args.file, px->conf.args.line, args[2]);
		return ACT_RET_PRS_ERR;
	}
	mark_tainted(TAINTED_CONFIG_EXP_KW_DECLARED);

	rule->action      = ACT_CUSTOM;
	rule->action_ptr  = tcp_action_attach_srv;
	rule->release_ptr = release_attach_srv_action;
	rule->check_ptr   = tcp_check_attach_srv;
	rule->arg.attach_srv.srvname = NULL;
	rule->arg.attach_srv.name = NULL;

	srvname = my_strndup(args[*cur_arg], strlen(args[*cur_arg]));
	if (!srvname)
		goto err;
	rule->arg.attach_srv.srvname = srvname;

	++(*cur_arg);

	if (strcmp(args[*cur_arg], "name") == 0) {
		if (!*args[*cur_arg + 1]) {
			memprintf(err, "missing name value");
			return ACT_RET_PRS_ERR;
		}
		++(*cur_arg);

		expr = sample_parse_expr((char **)args, cur_arg, px->conf.args.file, px->conf.args.line,
		                         err, &px->conf.args, NULL);
		if (!expr)
			return ACT_RET_PRS_ERR;

		rule->arg.attach_srv.name = expr;
		rule->release_ptr = release_attach_srv_action;
	}

	return ACT_RET_PRS_OK;

 err:
	ha_free(&rule->arg.attach_srv.srvname);
	release_sample_expr(rule->arg.attach_srv.name);
	return ACT_RET_PRS_ERR;
}

/* parse "set-{src,dst}[-port]" action */
static enum act_parse_ret tcp_parse_set_src_dst(const char **args, int *orig_arg, struct proxy *px,
                                                struct act_rule *rule, char **err)
{
	int cur_arg;
	struct sample_expr *expr;
	unsigned int where;

	cur_arg = *orig_arg;
	expr = sample_parse_expr((char **)args, &cur_arg, px->conf.args.file, px->conf.args.line, err, &px->conf.args, NULL);
	if (!expr)
		return ACT_RET_PRS_ERR;

	where = 0;
	if (px->cap & PR_CAP_FE)
		where |= SMP_VAL_FE_HRQ_HDR;
	if (px->cap & PR_CAP_BE)
		where |= SMP_VAL_BE_HRQ_HDR;

	if (!(expr->fetch->val & where)) {
		memprintf(err,
			  "fetch method '%s' extracts information from '%s', none of which is available here",
			  args[cur_arg-1], sample_src_names(expr->fetch->use));
		free(expr);
		return ACT_RET_PRS_ERR;
	}
	rule->arg.expr = expr;
	rule->action = ACT_CUSTOM;

	if (strcmp(args[*orig_arg - 1], "set-src") == 0) {
		rule->action_ptr = tcp_action_req_set_src;
	} else if (strcmp(args[*orig_arg - 1], "set-src-port") == 0) {
		rule->action_ptr = tcp_action_req_set_src_port;
	} else if (strcmp(args[*orig_arg - 1], "set-dst") == 0) {
		rule->action_ptr = tcp_action_req_set_dst;
	} else if (strcmp(args[*orig_arg - 1], "set-dst-port") == 0) {
		rule->action_ptr = tcp_action_req_set_dst_port;
	} else {
		return ACT_RET_PRS_ERR;
	}

	rule->release_ptr = release_set_src_dst_action;
	(*orig_arg)++;

	return ACT_RET_PRS_OK;
}


/* Parse a "set-mark" action. It takes the MARK value as argument. It returns
 * ACT_RET_PRS_OK on success, ACT_RET_PRS_ERR on error.
 */
static enum act_parse_ret tcp_parse_set_mark(const char **args, int *orig_arg, struct proxy *px,
                                             struct act_rule *rule, char **err)
{
#if defined(SO_MARK) || defined(SO_USER_COOKIE) || defined(SO_RTABLE)
	struct sample_expr *expr;
	char *endp;
	unsigned int where;
	int cur_arg = *orig_arg;

	if (!*args[*orig_arg]) {
		memprintf(err, "expects an argument");
		return ACT_RET_PRS_ERR;
	}

	/* value may be either an unsigned integer or an expression */
	rule->arg.expr_int.expr = NULL;
	rule->arg.expr_int.value = strtoul(args[*orig_arg], &endp, 0);
	if (*endp == '\0') {
		/* valid unsigned integer */
		(*orig_arg)++;
	}
	else {
		/* invalid unsigned integer, fallback to expr */
		expr = sample_parse_expr((char **)args, orig_arg, px->conf.args.file, px->conf.args.line, err, &px->conf.args, NULL);
		if (!expr)
			return ACT_RET_PRS_ERR;

		where = 0;
		if (px->cap & PR_CAP_FE)
			where |= SMP_VAL_FE_HRQ_HDR;
		if (px->cap & PR_CAP_BE)
			where |= SMP_VAL_BE_HRQ_HDR;

		if (!(expr->fetch->val & where)) {
			memprintf(err,
				  "fetch method '%s' extracts information from '%s', none of which is available here",
				  args[cur_arg-1], sample_src_names(expr->fetch->use));
			free(expr);
			return ACT_RET_PRS_ERR;
		}
		rule->arg.expr_int.expr = expr;
	}

	/* Register processing function. */
	if (strcmp("set-bc-mark", args[cur_arg - 1]) == 0)
		rule->action_ptr = tcp_action_set_bc_mark;
	else
		rule->action_ptr = tcp_action_set_fc_mark; // fc mark
	rule->action = ACT_CUSTOM;
	rule->release_ptr = release_expr_int_action;
	global.last_checks |= LSTCHK_NETADM;
	return ACT_RET_PRS_OK;
#else
	memprintf(err, "not supported on this platform (SO_MARK|SO_USER_COOKIE|SO_RTABLE undefined)");
	return ACT_RET_PRS_ERR;
#endif
}


/* Parse a "set-tos" action. It takes the TOS value as argument. It returns
 * ACT_RET_PRS_OK on success, ACT_RET_PRS_ERR on error.
 */
static enum act_parse_ret tcp_parse_set_tos(const char **args, int *orig_arg, struct proxy *px,
                                            struct act_rule *rule, char **err)
{
#ifdef IP_TOS
	struct sample_expr *expr;
	char *endp;
	unsigned int where;
	int cur_arg = *orig_arg;

	if (!*args[*orig_arg]) {
		memprintf(err, "expects an argument");
		return ACT_RET_PRS_ERR;
	}

	/* value may be either an integer or an expression */
	rule->arg.expr_int.expr = NULL;
	rule->arg.expr_int.value = strtol(args[*orig_arg], &endp, 0);
	if (*endp == '\0') {
		/* valid integer */
		(*orig_arg)++;
	}
	else {
		/* invalid unsigned integer, fallback to expr */
		expr = sample_parse_expr((char **)args, orig_arg, px->conf.args.file, px->conf.args.line, err, &px->conf.args, NULL);
		if (!expr)
			return ACT_RET_PRS_ERR;

		where = 0;
		if (px->cap & PR_CAP_FE)
			where |= SMP_VAL_FE_HRQ_HDR;
		if (px->cap & PR_CAP_BE)
			where |= SMP_VAL_BE_HRQ_HDR;

		if (!(expr->fetch->val & where)) {
			memprintf(err,
				  "fetch method '%s' extracts information from '%s', none of which is available here",
				  args[cur_arg-1], sample_src_names(expr->fetch->use));
			free(expr);
			return ACT_RET_PRS_ERR;
		}
		rule->arg.expr_int.expr = expr;
	}

	/* Register processing function. */
	if (strcmp("set-bc-tos", args[cur_arg - 1]) == 0)
		rule->action_ptr = tcp_action_set_bc_tos;
	else
		rule->action_ptr = tcp_action_set_fc_tos; // fc tos
	rule->action = ACT_CUSTOM;
	rule->release_ptr = release_expr_int_action;
	return ACT_RET_PRS_OK;
#else
	memprintf(err, "not supported on this platform (IP_TOS undefined)");
	return ACT_RET_PRS_ERR;
#endif
}

/* Parse a "silent-drop" action. It may take 2 optional arguments to define a
 * "rst-ttl" parameter. It returns ACT_RET_PRS_OK on success, ACT_RET_PRS_ERR
 * on error.
 */
static enum act_parse_ret tcp_parse_silent_drop(const char **args, int *cur_arg, struct proxy *px,
                                                struct act_rule *rule, char **err)
{
	unsigned int rst_ttl  = 0;
	char *endp;

	rule->action     = ACT_CUSTOM;
	rule->action_ptr = tcp_exec_action_silent_drop;

	if (strcmp(args[*cur_arg], "rst-ttl") == 0) {
		if (!*args[*cur_arg + 1]) {
			memprintf(err, "missing rst-ttl value\n");
			return ACT_RET_PRS_ERR;
		}

		rst_ttl = (unsigned int)strtoul(args[*cur_arg + 1], &endp, 0);

		if (endp && *endp != '\0') {
			memprintf(err, "invalid character starting at '%s' (value 1-255 expected)\n",
					endp);
			return ACT_RET_PRS_ERR;
		}
		if ((rst_ttl == 0) || (rst_ttl > 255) ) {
			memprintf(err, "valid rst-ttl values are [1-255]\n");
			return ACT_RET_PRS_ERR;
		}

		*cur_arg += 2;
	}

	rule->arg.act.p[0] = (void *)(uintptr_t)rst_ttl;
	return ACT_RET_PRS_OK;
}

static enum log_orig_id do_log_tcp_req_conn;
static enum log_orig_id do_log_tcp_req_sess;
static enum log_orig_id do_log_tcp_req_cont;
static enum log_orig_id do_log_tcp_res_cont;

static void init_do_log(void)
{
	do_log_tcp_req_conn = log_orig_register("tcp-req-conn");
	BUG_ON(do_log_tcp_req_conn == LOG_ORIG_UNSPEC);
	do_log_tcp_req_sess = log_orig_register("tcp-req-sess");
	BUG_ON(do_log_tcp_req_sess == LOG_ORIG_UNSPEC);
	do_log_tcp_req_cont = log_orig_register("tcp-req-cont");
	BUG_ON(do_log_tcp_req_cont == LOG_ORIG_UNSPEC);
	do_log_tcp_res_cont = log_orig_register("tcp-res-cont");
	BUG_ON(do_log_tcp_res_cont == LOG_ORIG_UNSPEC);
}

INITCALL0(STG_PREPARE, init_do_log);

static enum act_parse_ret tcp_req_conn_parse_do_log(const char **args, int *orig_arg, struct proxy *px,
                                                    struct act_rule *rule, char **err)
{
	return do_log_parse_act(do_log_tcp_req_conn, args, orig_arg, px, rule, err);
}

static enum act_parse_ret tcp_req_sess_parse_do_log(const char **args, int *orig_arg, struct proxy *px,
                                                    struct act_rule *rule, char **err)
{
	return do_log_parse_act(do_log_tcp_req_sess, args, orig_arg, px, rule, err);
}

static enum act_parse_ret tcp_req_cont_parse_do_log(const char **args, int *orig_arg, struct proxy *px,
                                                    struct act_rule *rule, char **err)
{
	return do_log_parse_act(do_log_tcp_req_cont, args, orig_arg, px, rule, err);
}

static enum act_parse_ret tcp_res_cont_parse_do_log(const char **args, int *orig_arg, struct proxy *px,
                                                    struct act_rule *rule, char **err)
{
	return do_log_parse_act(do_log_tcp_res_cont, args, orig_arg, px, rule, err);
}

static struct action_kw_list tcp_req_conn_actions = {ILH, {
	{ "do-log"      , tcp_req_conn_parse_do_log },
	{ "set-dst"     , tcp_parse_set_src_dst },
	{ "set-dst-port", tcp_parse_set_src_dst },
	{ "set-fc-mark",  tcp_parse_set_mark    },
	{ "set-fc-tos",   tcp_parse_set_tos     },
	{ "set-mark",     tcp_parse_set_mark    }, // DEPRECATED, see set-fc-mark
	{ "set-src",      tcp_parse_set_src_dst },
	{ "set-src-port", tcp_parse_set_src_dst },
	{ "set-tos",      tcp_parse_set_tos     }, // DEPRECATED, see set-fc-tos
	{ "silent-drop",  tcp_parse_silent_drop },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_conn_keywords_register, &tcp_req_conn_actions);

static struct action_kw_list tcp_req_sess_actions = {ILH, {
	{ "attach-srv"  , tcp_parse_attach_srv  },
	{ "do-log",       tcp_req_sess_parse_do_log },
	{ "set-dst"     , tcp_parse_set_src_dst },
	{ "set-dst-port", tcp_parse_set_src_dst },
	{ "set-fc-mark",  tcp_parse_set_mark    },
	{ "set-fc-tos",   tcp_parse_set_tos     },
	{ "set-mark",     tcp_parse_set_mark    }, // DEPRECATED, see set-fc-mark
	{ "set-src",      tcp_parse_set_src_dst },
	{ "set-src-port", tcp_parse_set_src_dst },
	{ "set-tos",      tcp_parse_set_tos     }, // DEPRECATED, see set-fc-tos
	{ "silent-drop",  tcp_parse_silent_drop },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_sess_keywords_register, &tcp_req_sess_actions);

static struct action_kw_list tcp_req_cont_actions = {ILH, {
	{ "do-log",       tcp_req_cont_parse_do_log },
	{ "set-bc-mark",  tcp_parse_set_mark    },
	{ "set-bc-tos",   tcp_parse_set_tos     },
	{ "set-dst"     , tcp_parse_set_src_dst },
	{ "set-dst-port", tcp_parse_set_src_dst },
	{ "set-fc-mark",  tcp_parse_set_mark    },
	{ "set-fc-tos",   tcp_parse_set_tos     },
	{ "set-mark",     tcp_parse_set_mark    }, // DEPRECATED, see set-fc-mark
	{ "set-src",      tcp_parse_set_src_dst },
	{ "set-src-port", tcp_parse_set_src_dst },
	{ "set-tos",      tcp_parse_set_tos     }, // DEPRECATED, see set-fc-tos
	{ "silent-drop",  tcp_parse_silent_drop },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_cont_keywords_register, &tcp_req_cont_actions);

static struct action_kw_list tcp_res_cont_actions = {ILH, {
	{ "do-log",      tcp_res_cont_parse_do_log },
	{ "set-fc-mark", tcp_parse_set_mark    },
	{ "set-fc-tos",  tcp_parse_set_tos     },
	{ "set-mark",    tcp_parse_set_mark    }, // DEPRECATED, see set-fc-mark
	{ "set-tos",     tcp_parse_set_tos     }, // DEPRECATED, see set-fc-tos
	{ "silent-drop", tcp_parse_silent_drop },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_res_cont_keywords_register, &tcp_res_cont_actions);

static struct action_kw_list http_req_actions = {ILH, {
	{ "set-bc-mark",  tcp_parse_set_mark    },
	{ "set-bc-tos",   tcp_parse_set_tos     },
	{ "set-dst",      tcp_parse_set_src_dst },
	{ "set-dst-port", tcp_parse_set_src_dst },
	{ "set-fc-mark",  tcp_parse_set_mark    },
	{ "set-fc-tos",   tcp_parse_set_tos     },
	{ "set-mark",     tcp_parse_set_mark    }, // DEPRECATED, see set-fc-mark
	{ "set-src",      tcp_parse_set_src_dst },
	{ "set-src-port", tcp_parse_set_src_dst },
	{ "set-tos",      tcp_parse_set_tos     }, // DEPRECATED, see set-fc-tos
	{ "silent-drop",  tcp_parse_silent_drop },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_req_keywords_register, &http_req_actions);

static struct action_kw_list http_res_actions = {ILH, {
	{ "set-fc-mark", tcp_parse_set_mark    },
	{ "set-fc-tos",  tcp_parse_set_tos     },
	{ "set-mark",    tcp_parse_set_mark    }, // DEPRECATED, see set-fc-mark
	{ "set-tos",     tcp_parse_set_tos     }, // DEPRECATED, see set-fc-tos
	{ "silent-drop", tcp_parse_silent_drop },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_res_keywords_register, &http_res_actions);


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
