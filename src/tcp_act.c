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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/tcp.h>
#include <netinet/in.h>

#include <haproxy/action-t.h>
#include <haproxy/api.h>
#include <haproxy/arg.h>
#include <haproxy/channel.h>
#include <haproxy/connection.h>
#include <haproxy/cs_utils.h>
#include <haproxy/global.h>
#include <haproxy/http_rules.h>
#include <haproxy/proto_tcp.h>
#include <haproxy/proxy-t.h>
#include <haproxy/sample.h>
#include <haproxy/session.h>
#include <haproxy/stream_interface.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/tools.h>

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
		if (!cs_get_src(s->csf))
			goto end;
		src = s->csf->src;
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
		if (!cs_get_dst(s->csf))
			goto end;
		dst = s->csf->dst;
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
		if (!cs_get_src(s->csf))
			goto end;
		src = s->csf->src;
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
		if (!cs_get_dst(s->csf))
			goto end;
		dst = s->csf->dst;
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

/* Executes the "silent-drop" action. May be called from {tcp,http}{request,response} */
static enum act_return tcp_exec_action_silent_drop(struct act_rule *rule, struct proxy *px,
                                                   struct session *sess, struct stream *strm, int flags)
{
	struct connection *conn = objt_conn(sess->origin);

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
		strm->csf->si->flags |= SI_FL_NOLINGER;

	if (conn->flags & CO_FL_FDLESS)
		goto out;

	/* We're on the client-facing side, we must force to disable lingering to
	 * ensure we will use an RST exclusively and kill any pending data.
	 */
	HA_ATOMIC_OR(&fdtab[conn->handle.fd].state, FD_LINGER_RISK);

#ifdef TCP_REPAIR
	if (setsockopt(conn->handle.fd, IPPROTO_TCP, TCP_REPAIR, &one, sizeof(one)) == 0) {
		/* socket will be quiet now */
		goto out;
	}
#endif
	/* either TCP_REPAIR is not defined or it failed (eg: permissions).
	 * Let's fall back on the TTL trick, though it only works for routed
	 * network and has no effect on local net.
	 */
#ifdef IP_TTL
	if (conn->src && conn->src->ss_family == AF_INET)
		setsockopt(conn->handle.fd, IPPROTO_IP, IP_TTL, &one, sizeof(one));
#endif
#ifdef IPV6_UNICAST_HOPS
	if (conn->src && conn->src->ss_family == AF_INET6)
		setsockopt(conn->handle.fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &one, sizeof(one));
#endif
 out:
	/* kill the stream if any */
	if (strm) {
		channel_abort(&strm->req);
		channel_abort(&strm->res);
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
static enum act_return tcp_action_set_mark(struct act_rule *rule, struct proxy *px,
					   struct session *sess, struct stream *s, int flags)
{
	conn_set_mark(objt_conn(sess->origin), (uintptr_t)rule->arg.act.p[0]);
	return ACT_RET_CONT;
}
#endif

#ifdef IP_TOS
static enum act_return tcp_action_set_tos(struct act_rule *rule, struct proxy *px,
					  struct session *sess, struct stream *s, int flags)
{
	conn_set_tos(objt_conn(sess->origin), (uintptr_t)rule->arg.act.p[0]);
	return ACT_RET_CONT;
}
#endif

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

	(*orig_arg)++;

	return ACT_RET_PRS_OK;
}


/* Parse a "set-mark" action. It takes the MARK value as argument. It returns
 * ACT_RET_PRS_OK on success, ACT_RET_PRS_ERR on error.
 */
static enum act_parse_ret tcp_parse_set_mark(const char **args, int *cur_arg, struct proxy *px,
					     struct act_rule *rule, char **err)
{
#if defined(SO_MARK) || defined(SO_USER_COOKIE) || defined(SO_RTABLE)
	char *endp;
	unsigned int mark;

	if (!*args[*cur_arg]) {
		memprintf(err, "expects exactly 1 argument (integer/hex value)");
		return ACT_RET_PRS_ERR;
	}
	mark = strtoul(args[*cur_arg], &endp, 0);
	if (endp && *endp != '\0') {
		memprintf(err, "invalid character starting at '%s' (integer/hex value expected)", endp);
		return ACT_RET_PRS_ERR;
	}

	(*cur_arg)++;

	/* Register processing function. */
	rule->action_ptr = tcp_action_set_mark;
	rule->action = ACT_CUSTOM;
	rule->arg.act.p[0] = (void *)(uintptr_t)mark;
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
static enum act_parse_ret tcp_parse_set_tos(const char **args, int *cur_arg, struct proxy *px,
					     struct act_rule *rule, char **err)
{
#ifdef IP_TOS
	char *endp;
	int tos;

	if (!*args[*cur_arg]) {
		memprintf(err, "expects exactly 1 argument (integer/hex value)");
		return ACT_RET_PRS_ERR;
	}
	tos = strtol(args[*cur_arg], &endp, 0);
	if (endp && *endp != '\0') {
		memprintf(err, "invalid character starting at '%s' (integer/hex value expected)", endp);
		return ACT_RET_PRS_ERR;
	}

	(*cur_arg)++;

	/* Register processing function. */
	rule->action_ptr = tcp_action_set_tos;
	rule->action = ACT_CUSTOM;
	rule->arg.act.p[0] = (void *)(uintptr_t)tos;
	return ACT_RET_PRS_OK;
#else
	memprintf(err, "not supported on this platform (IP_TOS undefined)");
	return ACT_RET_PRS_ERR;
#endif
}


/* Parse a "silent-drop" action. It takes no argument. It returns ACT_RET_PRS_OK on
 * success, ACT_RET_PRS_ERR on error.
 */
static enum act_parse_ret tcp_parse_silent_drop(const char **args, int *orig_arg, struct proxy *px,
                                                struct act_rule *rule, char **err)
{
	rule->action     = ACT_CUSTOM;
	rule->action_ptr = tcp_exec_action_silent_drop;
	return ACT_RET_PRS_OK;
}


static struct action_kw_list tcp_req_conn_actions = {ILH, {
	{ "set-dst"     , tcp_parse_set_src_dst },
	{ "set-dst-port", tcp_parse_set_src_dst },
	{ "set-mark",     tcp_parse_set_mark    },
	{ "set-src",      tcp_parse_set_src_dst },
	{ "set-src-port", tcp_parse_set_src_dst },
	{ "set-tos",      tcp_parse_set_tos     },
	{ "silent-drop",  tcp_parse_silent_drop },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_conn_keywords_register, &tcp_req_conn_actions);

static struct action_kw_list tcp_req_sess_actions = {ILH, {
	{ "set-dst"     , tcp_parse_set_src_dst },
	{ "set-dst-port", tcp_parse_set_src_dst },
	{ "set-mark",     tcp_parse_set_mark    },
	{ "set-src",      tcp_parse_set_src_dst },
	{ "set-src-port", tcp_parse_set_src_dst },
	{ "set-tos",      tcp_parse_set_tos     },
	{ "silent-drop",  tcp_parse_silent_drop },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_sess_keywords_register, &tcp_req_sess_actions);

static struct action_kw_list tcp_req_cont_actions = {ILH, {
	{ "set-src",      tcp_parse_set_src_dst },
	{ "set-src-port", tcp_parse_set_src_dst },
	{ "set-dst"     , tcp_parse_set_src_dst },
	{ "set-dst-port", tcp_parse_set_src_dst },
	{ "set-mark",     tcp_parse_set_mark    },
	{ "set-tos",      tcp_parse_set_tos     },
	{ "silent-drop",  tcp_parse_silent_drop },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_cont_keywords_register, &tcp_req_cont_actions);

static struct action_kw_list tcp_res_cont_actions = {ILH, {
	{ "set-mark",     tcp_parse_set_mark   },
	{ "set-tos",      tcp_parse_set_tos     },
	{ "silent-drop", tcp_parse_silent_drop },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_res_cont_keywords_register, &tcp_res_cont_actions);

static struct action_kw_list http_req_actions = {ILH, {
	{ "set-dst",      tcp_parse_set_src_dst },
	{ "set-dst-port", tcp_parse_set_src_dst },
	{ "set-mark",     tcp_parse_set_mark    },
	{ "set-src",      tcp_parse_set_src_dst },
	{ "set-src-port", tcp_parse_set_src_dst },
	{ "set-tos",      tcp_parse_set_tos     },
	{ "silent-drop",  tcp_parse_silent_drop },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_req_keywords_register, &http_req_actions);

static struct action_kw_list http_res_actions = {ILH, {
	{ "set-mark",    tcp_parse_set_mark    },
	{ "set-tos",     tcp_parse_set_tos    },
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
