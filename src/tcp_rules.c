/*
 * "tcp" rules processing
 *
 * Copyright 2000-2016 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */
#include <haproxy/acl.h>
#include <haproxy/action.h>
#include <haproxy/api.h>
#include <haproxy/arg-t.h>
#include <haproxy/capture-t.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/connection.h>
#include <haproxy/global.h>
#include <haproxy/list.h>
#include <haproxy/log.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/stick_table.h>
#include <haproxy/stream-t.h>
#include <haproxy/stream_interface.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/ticks.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <haproxy/trace.h>


#define TRACE_SOURCE &trace_strm

/* List head of all known action keywords for "tcp-request connection" */
struct list tcp_req_conn_keywords = LIST_HEAD_INIT(tcp_req_conn_keywords);
struct list tcp_req_sess_keywords = LIST_HEAD_INIT(tcp_req_sess_keywords);
struct list tcp_req_cont_keywords = LIST_HEAD_INIT(tcp_req_cont_keywords);
struct list tcp_res_cont_keywords = LIST_HEAD_INIT(tcp_res_cont_keywords);

/*
 * Register keywords.
 */
void tcp_req_conn_keywords_register(struct action_kw_list *kw_list)
{
	LIST_ADDQ(&tcp_req_conn_keywords, &kw_list->list);
}

void tcp_req_sess_keywords_register(struct action_kw_list *kw_list)
{
	LIST_ADDQ(&tcp_req_sess_keywords, &kw_list->list);
}

void tcp_req_cont_keywords_register(struct action_kw_list *kw_list)
{
	LIST_ADDQ(&tcp_req_cont_keywords, &kw_list->list);
}

void tcp_res_cont_keywords_register(struct action_kw_list *kw_list)
{
	LIST_ADDQ(&tcp_res_cont_keywords, &kw_list->list);
}

/*
 * Return the struct tcp_req_action_kw associated to a keyword.
 */
struct action_kw *tcp_req_conn_action(const char *kw)
{
	return action_lookup(&tcp_req_conn_keywords, kw);
}

struct action_kw *tcp_req_sess_action(const char *kw)
{
	return action_lookup(&tcp_req_sess_keywords, kw);
}

struct action_kw *tcp_req_cont_action(const char *kw)
{
	return action_lookup(&tcp_req_cont_keywords, kw);
}

struct action_kw *tcp_res_cont_action(const char *kw)
{
	return action_lookup(&tcp_res_cont_keywords, kw);
}

/* This function performs the TCP request analysis on the current request. It
 * returns 1 if the processing can continue on next analysers, or zero if it
 * needs more data, encounters an error, or wants to immediately abort the
 * request. It relies on buffers flags, and updates s->req->analysers. The
 * function may be called for frontend rules and backend rules. It only relies
 * on the backend pointer so this works for both cases.
 */
int tcp_inspect_request(struct stream *s, struct channel *req, int an_bit)
{
	struct session *sess = s->sess;
	struct act_rule *rule;
	int partial;
	int act_opts = 0;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_TCP_ANA, s);

	/* We don't know whether we have enough data, so must proceed
	 * this way :
	 * - iterate through all rules in their declaration order
	 * - if one rule returns MISS, it means the inspect delay is
	 *   not over yet, then return immediately, otherwise consider
	 *   it as a non-match.
	 * - if one rule returns OK, then return OK
	 * - if one rule returns KO, then return KO
	 */

	if ((req->flags & CF_SHUTR) || channel_full(req, global.tune.maxrewrite) ||
	    !s->be->tcp_req.inspect_delay || tick_is_expired(s->rules_exp, now_ms))
		partial = SMP_OPT_FINAL;
	else
		partial = 0;

	/* If "the current_rule_list" match the executed rule list, we are in
	 * resume condition. If a resume is needed it is always in the action
	 * and never in the ACL or converters. In this case, we initialise the
	 * current rule, and go to the action execution point.
	 */
	if (s->current_rule) {
		rule = s->current_rule;
		s->current_rule = NULL;
		if (s->current_rule_list == &s->be->tcp_req.inspect_rules)
			goto resume_execution;
	}
	s->current_rule_list = &s->be->tcp_req.inspect_rules;

	list_for_each_entry(rule, &s->be->tcp_req.inspect_rules, list) {
		enum acl_test_res ret = ACL_TEST_PASS;

		if (rule->cond) {
			ret = acl_exec_cond(rule->cond, s->be, sess, s, SMP_OPT_DIR_REQ | partial);
			if (ret == ACL_TEST_MISS)
				goto missing_data;

			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			act_opts |= ACT_OPT_FIRST;
resume_execution:

			/* Always call the action function if defined */
			if (rule->action_ptr) {
				if (partial & SMP_OPT_FINAL)
					act_opts |= ACT_OPT_FINAL;

				switch (rule->action_ptr(rule, s->be, s->sess, s, act_opts)) {
					case ACT_RET_CONT:
						break;
					case ACT_RET_STOP:
					case ACT_RET_DONE:
						goto end;
					case ACT_RET_YIELD:
						s->current_rule = rule;
						if (partial & SMP_OPT_FINAL) {
							send_log(s->be, LOG_WARNING,
								 "Internal error: yield not allowed if the inspect-delay expired "
								 "for the tcp-request content actions.");
							goto internal;
						}
						goto missing_data;
					case ACT_RET_DENY:
						goto deny;
					case ACT_RET_ABRT:
						goto abort;
					case ACT_RET_ERR:
						goto internal;
					case ACT_RET_INV:
						goto invalid;
				}
				continue; /* eval the next rule */
			}

			/* If not action function defined, check for known actions */
			if (rule->action == ACT_ACTION_ALLOW) {
				goto end;
			}
			else if (rule->action == ACT_ACTION_DENY) {
				goto deny;
			}
		}
	}

 end:
	/* if we get there, it means we have no rule which matches, or
	 * we have an explicit accept, so we apply the default accept.
	 */
	req->analysers &= ~an_bit;
	req->analyse_exp = s->rules_exp = TICK_ETERNITY;
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_TCP_ANA, s);
	return 1;

 missing_data:
	channel_dont_connect(req);
	/* just set the request timeout once at the beginning of the request */
	if (!tick_isset(s->rules_exp) && s->be->tcp_req.inspect_delay)
		s->rules_exp = tick_add(now_ms, s->be->tcp_req.inspect_delay);
	req->analyse_exp = tick_first((tick_is_expired(req->analyse_exp, now_ms) ? 0 : req->analyse_exp), s->rules_exp);
	DBG_TRACE_DEVEL("waiting for more data", STRM_EV_STRM_ANA|STRM_EV_TCP_ANA, s);
	return 0;

 deny:
	_HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_req, 1);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_ADD(&sess->listener->counters->denied_req, 1);
	goto reject;

 internal:
	_HA_ATOMIC_ADD(&sess->fe->fe_counters.internal_errors, 1);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_ADD(&sess->listener->counters->internal_errors, 1);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_INTERNAL;
	goto reject;

 invalid:
	_HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

 reject:
	si_must_kill_conn(chn_prod(req));
	channel_abort(req);
	channel_abort(&s->res);

 abort:
	req->analysers &= AN_REQ_FLT_END;

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;
	DBG_TRACE_DEVEL("leaving on error|deny|abort", STRM_EV_STRM_ANA|STRM_EV_TCP_ANA|STRM_EV_TCP_ERR, s);
	return 0;
}

/* This function performs the TCP response analysis on the current response. It
 * returns 1 if the processing can continue on next analysers, or zero if it
 * needs more data, encounters an error, or wants to immediately abort the
 * response. It relies on buffers flags, and updates s->rep->analysers. The
 * function may be called for backend rules.
 */
int tcp_inspect_response(struct stream *s, struct channel *rep, int an_bit)
{
	struct session *sess = s->sess;
	struct act_rule *rule;
	int partial;
	int act_opts = 0;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_TCP_ANA, s);

	/* We don't know whether we have enough data, so must proceed
	 * this way :
	 * - iterate through all rules in their declaration order
	 * - if one rule returns MISS, it means the inspect delay is
	 *   not over yet, then return immediately, otherwise consider
	 *   it as a non-match.
	 * - if one rule returns OK, then return OK
	 * - if one rule returns KO, then return KO
	 */
	if ((rep->flags & CF_SHUTR) || channel_full(rep, global.tune.maxrewrite) ||
	    !s->be->tcp_rep.inspect_delay || tick_is_expired(s->rules_exp, now_ms))
		partial = SMP_OPT_FINAL;
	else
		partial = 0;

	/* If "the current_rule_list" match the executed rule list, we are in
	 * resume condition. If a resume is needed it is always in the action
	 * and never in the ACL or converters. In this case, we initialise the
	 * current rule, and go to the action execution point.
	 */
	if (s->current_rule) {
		rule = s->current_rule;
		s->current_rule = NULL;
		if (s->current_rule_list == &s->be->tcp_rep.inspect_rules)
			goto resume_execution;
	}
	s->current_rule_list = &s->be->tcp_rep.inspect_rules;
	s->rules_exp = TICK_ETERNITY;

	list_for_each_entry(rule, &s->be->tcp_rep.inspect_rules, list) {
		enum acl_test_res ret = ACL_TEST_PASS;

		if (rule->cond) {
			ret = acl_exec_cond(rule->cond, s->be, sess, s, SMP_OPT_DIR_RES | partial);
			if (ret == ACL_TEST_MISS)
				goto missing_data;

			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			act_opts |= ACT_OPT_FIRST;
resume_execution:
			/* Always call the action function if defined */
			if (rule->action_ptr) {
				if (partial & SMP_OPT_FINAL)
					act_opts |= ACT_OPT_FINAL;

				switch (rule->action_ptr(rule, s->be, s->sess, s, act_opts)) {
					case ACT_RET_CONT:
						break;
					case ACT_RET_STOP:
					case ACT_RET_DONE:
						goto end;
					case ACT_RET_YIELD:
						s->current_rule = rule;
						if (partial & SMP_OPT_FINAL) {
							send_log(s->be, LOG_WARNING,
								 "Internal error: yield not allowed if the inspect-delay expired "
								 "for the tcp-response content actions.");
							goto internal;
						}
						channel_dont_close(rep);
						goto missing_data;
					case ACT_RET_DENY:
						goto deny;
					case ACT_RET_ABRT:
						goto abort;
					case ACT_RET_ERR:
						goto internal;
					case ACT_RET_INV:
						goto invalid;
				}
				continue; /* eval the next rule */
			}

			/* If not action function defined, check for known actions */
			if (rule->action == ACT_ACTION_ALLOW) {
				goto end;
			}
			else if (rule->action == ACT_ACTION_DENY) {
				goto deny;
			}
			else if (rule->action == ACT_TCP_CLOSE) {
				chn_prod(rep)->flags |= SI_FL_NOLINGER | SI_FL_NOHALF;
				si_must_kill_conn(chn_prod(rep));
				si_shutr(chn_prod(rep));
				si_shutw(chn_prod(rep));
				goto end;
			}
		}
	}

 end:
	/* if we get there, it means we have no rule which matches, or
	 * we have an explicit accept, so we apply the default accept.
	 */
	rep->analysers &= ~an_bit;
	rep->analyse_exp = s->rules_exp = TICK_ETERNITY;
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_TCP_ANA, s);
	return 1;

 missing_data:
	/* just set the analyser timeout once at the beginning of the response */
	if (!tick_isset(s->rules_exp) && s->be->tcp_rep.inspect_delay)
		s->rules_exp = tick_add(now_ms, s->be->tcp_rep.inspect_delay);
	rep->analyse_exp = tick_first((tick_is_expired(rep->analyse_exp, now_ms) ? 0 : rep->analyse_exp), s->rules_exp);
	DBG_TRACE_DEVEL("waiting for more data", STRM_EV_STRM_ANA|STRM_EV_TCP_ANA, s);
	return 0;

  deny:
	_HA_ATOMIC_ADD(&s->sess->fe->fe_counters.denied_resp, 1);
	_HA_ATOMIC_ADD(&s->be->be_counters.denied_resp, 1);
	if (s->sess->listener->counters)
		_HA_ATOMIC_ADD(&s->sess->listener->counters->denied_resp, 1);
	if (objt_server(s->target))
		_HA_ATOMIC_ADD(&__objt_server(s->target)->counters.denied_resp, 1);
	goto reject;

 internal:
	_HA_ATOMIC_ADD(&s->sess->fe->fe_counters.internal_errors, 1);
	_HA_ATOMIC_ADD(&s->be->be_counters.internal_errors, 1);
	if (s->sess->listener->counters)
		_HA_ATOMIC_ADD(&s->sess->listener->counters->internal_errors, 1);
	if (objt_server(s->target))
		_HA_ATOMIC_ADD(&__objt_server(s->target)->counters.internal_errors, 1);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_INTERNAL;
	goto reject;

 invalid:
	_HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
	if (objt_server(s->target))
		_HA_ATOMIC_ADD(&__objt_server(s->target)->counters.failed_resp, 1);

 reject:
	si_must_kill_conn(chn_prod(rep));
	channel_abort(rep);
	channel_abort(&s->req);

  abort:
	rep->analysers &= AN_RES_FLT_END;

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_D;
	DBG_TRACE_DEVEL("leaving on error", STRM_EV_STRM_ANA|STRM_EV_TCP_ANA|STRM_EV_TCP_ERR, s);
	return 0;
}


/* This function performs the TCP layer4 analysis on the current request. It
 * returns 0 if a reject rule matches, otherwise 1 if either an accept rule
 * matches or if no more rule matches. It can only use rules which don't need
 * any data. This only works on connection-based client-facing stream interfaces.
 */
int tcp_exec_l4_rules(struct session *sess)
{
	struct act_rule *rule;
	struct connection *conn = objt_conn(sess->origin);
	int result = 1;
	enum acl_test_res ret;

	if (!conn)
		return result;

	list_for_each_entry(rule, &sess->fe->tcp_req.l4_rules, list) {
		ret = ACL_TEST_PASS;

		if (rule->cond) {
			ret = acl_exec_cond(rule->cond, sess->fe, sess, NULL, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			/* Always call the action function if defined */
			if (rule->action_ptr) {
				switch (rule->action_ptr(rule, sess->fe, sess, NULL, ACT_OPT_FINAL | ACT_OPT_FIRST)) {
					case ACT_RET_YIELD:
						/* yield is not allowed at this point. If this return code is
						 * used it is a bug, so I prefer to abort the process.
						 */
						send_log(sess->fe, LOG_WARNING,
							 "Internal error: yield not allowed with tcp-request connection actions.");
						/* fall through */
					case ACT_RET_STOP:
					case ACT_RET_DONE:
						goto end;
					case ACT_RET_CONT:
						break;
					case ACT_RET_DENY:
					case ACT_RET_ABRT:
					case ACT_RET_ERR:
					case ACT_RET_INV:
						result = 0;
						goto end;
				}
				continue; /* eval the next rule */
			}

			/* If not action function defined, check for known actions */
			if (rule->action == ACT_ACTION_ALLOW) {
				goto end;
			}
			else if (rule->action == ACT_ACTION_DENY) {
				_HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_conn, 1);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_ADD(&sess->listener->counters->denied_conn, 1);

				result = 0;
				goto end;
			}
			else if (rule->action == ACT_TCP_EXPECT_PX) {
				if (!(conn->flags & CO_FL_HANDSHAKE)) {
					if (xprt_add_hs(conn) < 0) {
						result = 0;
						goto end;
					}
				}
				conn->flags |= CO_FL_ACCEPT_PROXY;
			}
			else if (rule->action == ACT_TCP_EXPECT_CIP) {
				if (!(conn->flags & CO_FL_HANDSHAKE)) {
					if (xprt_add_hs(conn) < 0) {
						result = 0;
						goto end;
					}
				}
				conn->flags |= CO_FL_ACCEPT_CIP;
			}
		}
	}
 end:
	return result;
}

/* This function performs the TCP layer5 analysis on the current request. It
 * returns 0 if a reject rule matches, otherwise 1 if either an accept rule
 * matches or if no more rule matches. It can only use rules which don't need
 * any data. This only works on session-based client-facing stream interfaces.
 * An example of valid use case is to track a stick-counter on the source
 * address extracted from the proxy protocol.
 */
int tcp_exec_l5_rules(struct session *sess)
{
	struct act_rule *rule;
	int result = 1;
	enum acl_test_res ret;

	list_for_each_entry(rule, &sess->fe->tcp_req.l5_rules, list) {
		ret = ACL_TEST_PASS;

		if (rule->cond) {
			ret = acl_exec_cond(rule->cond, sess->fe, sess, NULL, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			/* Always call the action function if defined */
			if (rule->action_ptr) {
				switch (rule->action_ptr(rule, sess->fe, sess, NULL, ACT_OPT_FINAL | ACT_OPT_FIRST)) {
					case ACT_RET_YIELD:
						/* yield is not allowed at this point. If this return code is
						 * used it is a bug, so I prefer to abort the process.
						 */
						send_log(sess->fe, LOG_WARNING,
							 "Internal error: yield not allowed with tcp-request session actions.");
						/* fall through */
					case ACT_RET_STOP:
					case ACT_RET_DONE:
						goto end;
					case ACT_RET_CONT:
						break;
					case ACT_RET_DENY:
					case ACT_RET_ABRT:
					case ACT_RET_ERR:
					case ACT_RET_INV:
						result = 0;
						goto end;
				}
				continue; /* eval the next rule */
			}

			/* If not action function defined, check for known actions */
			if (rule->action == ACT_ACTION_ALLOW) {
				goto end;
			}
			else if (rule->action == ACT_ACTION_DENY) {
				_HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_sess, 1);
				if (sess->listener && sess->listener->counters)
					_HA_ATOMIC_ADD(&sess->listener->counters->denied_sess, 1);

				result = 0;
				goto end;
			}
		}
	}
  end:
	return result;
}

/* Parse a tcp-response rule. Return a negative value in case of failure */
static int tcp_parse_response_rule(char **args, int arg, int section_type,
                                   struct proxy *curpx, struct proxy *defpx,
                                   struct act_rule *rule, char **err,
                                   unsigned int where,
                                   const char *file, int line)
{
	if (curpx == defpx || !(curpx->cap & PR_CAP_BE)) {
		memprintf(err, "%s %s is only allowed in 'backend' sections",
		          args[0], args[1]);
		return -1;
	}

	if (strcmp(args[arg], "accept") == 0) {
		arg++;
		rule->action = ACT_ACTION_ALLOW;
		rule->flags |= ACT_FLAG_FINAL;
	}
	else if (strcmp(args[arg], "reject") == 0) {
		arg++;
		rule->action = ACT_ACTION_DENY;
		rule->flags |= ACT_FLAG_FINAL;
	}
	else if (strcmp(args[arg], "close") == 0) {
		arg++;
		rule->action = ACT_TCP_CLOSE;
		rule->flags |= ACT_FLAG_FINAL;
	}
	else {
		struct action_kw *kw;
		kw = tcp_res_cont_action(args[arg]);
		if (kw) {
			arg++;
			rule->kw = kw;
			if (kw->parse((const char **)args, &arg, curpx, rule, err) == ACT_RET_PRS_ERR)
				return -1;
		} else {
			action_build_list(&tcp_res_cont_keywords, &trash);
			memprintf(err,
			          "'%s %s' expects 'accept', 'close', 'reject', %s in %s '%s' (got '%s')",
			          args[0], args[1], trash.area,
			          proxy_type_str(curpx), curpx->id, args[arg]);
			return -1;
		}
	}

	if (strcmp(args[arg], "if") == 0 || strcmp(args[arg], "unless") == 0) {
		if ((rule->cond = build_acl_cond(file, line, &curpx->acl, curpx, (const char **)args+arg, err)) == NULL) {
			memprintf(err,
			          "'%s %s %s' : error detected in %s '%s' while parsing '%s' condition : %s",
			          args[0], args[1], args[2], proxy_type_str(curpx), curpx->id, args[arg], *err);
			return -1;
		}
	}
	else if (*args[arg]) {
		memprintf(err,
			 "'%s %s %s' only accepts 'if' or 'unless', in %s '%s' (got '%s')",
			 args[0], args[1], args[2], proxy_type_str(curpx), curpx->id, args[arg]);
		return -1;
	}
	return 0;
}


/* This function executes a track-sc* actions. On success, it returns
 * ACT_RET_CONT. If it must yield, it return ACT_RET_YIELD. Otherwsize
 * ACT_RET_ERR is returned.
 */
static enum act_return tcp_action_track_sc(struct act_rule *rule, struct proxy *px,
					    struct session *sess, struct stream *s, int flags)
{
	struct stksess *ts;
	struct stktable *t;
	struct stktable_key *key;
	struct sample smp;
	int opt;

	opt = SMP_OPT_DIR_REQ;
	if (flags & ACT_FLAG_FINAL)
		opt |= SMP_OPT_FINAL;

	t = rule->arg.trk_ctr.table.t;
	if (rule->from == ACT_F_TCP_REQ_CNT) { /* L7 rules: use the stream */
		if (stkctr_entry(&s->stkctr[rule->action]))
			goto end;

		key = stktable_fetch_key(t, s->be, sess, s, opt, rule->arg.trk_ctr.expr, &smp);

		if ((smp.flags & SMP_F_MAY_CHANGE) && !(flags & ACT_FLAG_FINAL))
			return ACT_RET_YIELD; /* key might appear later */

		if (key && (ts = stktable_get_entry(t, key))) {
			stream_track_stkctr(&s->stkctr[rule->action], t, ts);
			stkctr_set_flags(&s->stkctr[rule->action], STKCTR_TRACK_CONTENT);
			if (sess->fe != s->be)
				stkctr_set_flags(&s->stkctr[rule->action], STKCTR_TRACK_BACKEND);
		}
	}
	else {  /* L4/L5 rules: use the session */
		if (stkctr_entry(&sess->stkctr[rule->action]))
			goto end;

		key = stktable_fetch_key(t, sess->fe, sess, NULL, opt, rule->arg.trk_ctr.expr, NULL);
		if (key && (ts = stktable_get_entry(t, key)))
			stream_track_stkctr(&sess->stkctr[rule->action], t, ts);
	}

  end:
	return ACT_RET_CONT;
}

/* This function executes a capture actions. It executes a fetch expression,
 * turns the result into a string and puts it in a capture slot. On success, it
 * returns ACT_RET_CONT. If it must yield, it return ACT_RET_YIELD. Otherwsize
 * ACT_RET_ERR is returned.
 */
static enum act_return tcp_action_capture(struct act_rule *rule, struct proxy *px,
					  struct session *sess, struct stream *s, int flags)
{
	struct sample *key;
	struct cap_hdr *h = rule->arg.cap.hdr;
	char **cap = s->req_cap;
	int len, opt;

	opt = ((rule->from == ACT_F_TCP_REQ_CNT) ? SMP_OPT_DIR_REQ : SMP_OPT_DIR_RES);
	if (flags & ACT_FLAG_FINAL)
		opt |= SMP_OPT_FINAL;

	key = sample_fetch_as_type(s->be, sess, s, opt, rule->arg.cap.expr, SMP_T_STR);
	if (!key)
		goto end;

	if ((key->flags & SMP_F_MAY_CHANGE) && !(flags & ACT_FLAG_FINAL))
		return ACT_RET_YIELD; /* key might appear later */

	if (cap[h->index] == NULL) {
		cap[h->index] = pool_alloc(h->pool);
		if (cap[h->index] == NULL) /* no more capture memory, ignore error */
			goto end;
	}

	len = key->data.u.str.data;
	if (len > h->len)
		len = h->len;

	memcpy(cap[h->index], key->data.u.str.area, len);
	cap[h->index][len] = 0;

  end:
	return ACT_RET_CONT;
}

static void release_tcp_capture(struct act_rule * rule)
{
	release_sample_expr(rule->arg.cap.expr);
}


static void release_tcp_track_sc(struct act_rule * rule)
{
	release_sample_expr(rule->arg.trk_ctr.expr);
}

/* Parse a tcp-request rule. Return a negative value in case of failure */
static int tcp_parse_request_rule(char **args, int arg, int section_type,
                                  struct proxy *curpx, struct proxy *defpx,
                                  struct act_rule *rule, char **err,
                                  unsigned int where, const char *file, int line)
{
	if (curpx == defpx) {
		memprintf(err, "%s %s is not allowed in 'defaults' sections",
		          args[0], args[1]);
		return -1;
	}

	if (strcmp(args[arg], "accept") == 0) {
		arg++;
		rule->action = ACT_ACTION_ALLOW;
		rule->flags |= ACT_FLAG_FINAL;
	}
	else if (strcmp(args[arg], "reject") == 0) {
		arg++;
		rule->action = ACT_ACTION_DENY;
		rule->flags |= ACT_FLAG_FINAL;
	}
	else if (strcmp(args[arg], "capture") == 0) {
		struct sample_expr *expr;
		struct cap_hdr *hdr;
		int kw = arg;
		int len = 0;

		if (!(curpx->cap & PR_CAP_FE)) {
			memprintf(err,
			          "'%s %s %s' : proxy '%s' has no frontend capability",
			          args[0], args[1], args[kw], curpx->id);
			return -1;
		}

		if (!(where & SMP_VAL_FE_REQ_CNT)) {
			memprintf(err,
				  "'%s %s' is not allowed in '%s %s' rules in %s '%s'",
				  args[arg], args[arg+1], args[0], args[1], proxy_type_str(curpx), curpx->id);
			return -1;
		}

		arg++;

		curpx->conf.args.ctx = ARGC_CAP;
		expr = sample_parse_expr(args, &arg, file, line, err, &curpx->conf.args, NULL);
		if (!expr) {
			memprintf(err,
			          "'%s %s %s' : %s",
			          args[0], args[1], args[kw], *err);
			return -1;
		}

		if (!(expr->fetch->val & where)) {
			memprintf(err,
			          "'%s %s %s' : fetch method '%s' extracts information from '%s', none of which is available here",
			          args[0], args[1], args[kw], args[arg-1], sample_src_names(expr->fetch->use));
			release_sample_expr(expr);
			return -1;
		}

		if (strcmp(args[arg], "len") == 0) {
			arg++;
			if (!args[arg]) {
				memprintf(err,
					  "'%s %s %s' : missing length value",
					  args[0], args[1], args[kw]);
				release_sample_expr(expr);
				return -1;
			}
			/* we copy the table name for now, it will be resolved later */
			len = atoi(args[arg]);
			if (len <= 0) {
				memprintf(err,
					  "'%s %s %s' : length must be > 0",
					  args[0], args[1], args[kw]);
				release_sample_expr(expr);
				return -1;
			}
			arg++;
		}

		if (!len) {
			memprintf(err,
				  "'%s %s %s' : a positive 'len' argument is mandatory",
				  args[0], args[1], args[kw]);
			free(expr);
			return -1;
		}

		hdr = calloc(1, sizeof(*hdr));
		hdr->next = curpx->req_cap;
		hdr->name = NULL; /* not a header capture */
		hdr->namelen = 0;
		hdr->len = len;
		hdr->pool = create_pool("caphdr", hdr->len + 1, MEM_F_SHARED);
		hdr->index = curpx->nb_req_cap++;

		curpx->req_cap = hdr;
		curpx->to_log |= LW_REQHDR;

		/* check if we need to allocate an http_txn struct for HTTP parsing */
		curpx->http_needed |= !!(expr->fetch->use & SMP_USE_HTTP_ANY);

		rule->arg.cap.expr = expr;
		rule->arg.cap.hdr = hdr;
		rule->action = ACT_CUSTOM;
		rule->action_ptr = tcp_action_capture;
		rule->check_ptr = check_capture;
		rule->release_ptr  = release_tcp_capture;
	}
	else if (strncmp(args[arg], "track-sc", 8) == 0) {
		struct sample_expr *expr;
		int kw = arg;
		unsigned int tsc_num;
		const char *tsc_num_str;

		arg++;

		tsc_num_str = &args[kw][8];
		if (cfg_parse_track_sc_num(&tsc_num, tsc_num_str, tsc_num_str + strlen(tsc_num_str), err) == -1) {
			memprintf(err, "'%s %s %s' : %s", args[0], args[1], args[kw], *err);
			return -1;
		}

		curpx->conf.args.ctx = ARGC_TRK;
		expr = sample_parse_expr(args, &arg, file, line, err, &curpx->conf.args, NULL);
		if (!expr) {
			memprintf(err,
			          "'%s %s %s' : %s",
			          args[0], args[1], args[kw], *err);
			return -1;
		}

		if (!(expr->fetch->val & where)) {
			memprintf(err,
			          "'%s %s %s' : fetch method '%s' extracts information from '%s', none of which is available here",
			          args[0], args[1], args[kw], args[arg-1], sample_src_names(expr->fetch->use));
			release_sample_expr(expr);
			return -1;
		}

		/* check if we need to allocate an http_txn struct for HTTP parsing */
		curpx->http_needed |= !!(expr->fetch->use & SMP_USE_HTTP_ANY);

		if (strcmp(args[arg], "table") == 0) {
			arg++;
			if (!args[arg]) {
				memprintf(err,
					  "'%s %s %s' : missing table name",
					  args[0], args[1], args[kw]);
				release_sample_expr(expr);
				return -1;
			}
			/* we copy the table name for now, it will be resolved later */
			rule->arg.trk_ctr.table.n = strdup(args[arg]);
			arg++;
		}
		rule->action = tsc_num;
		rule->arg.trk_ctr.expr = expr;
		rule->action_ptr = tcp_action_track_sc;
		rule->check_ptr = check_trk_action;
		rule->release_ptr  = release_tcp_track_sc;
	}
	else if (strcmp(args[arg], "expect-proxy") == 0) {
		if (strcmp(args[arg+1], "layer4") != 0) {
			memprintf(err,
				  "'%s %s %s' only supports 'layer4' in %s '%s' (got '%s')",
				  args[0], args[1], args[arg], proxy_type_str(curpx), curpx->id, args[arg+1]);
			return -1;
		}

		if (!(where & SMP_VAL_FE_CON_ACC)) {
			memprintf(err,
				  "'%s %s' is not allowed in '%s %s' rules in %s '%s'",
				  args[arg], args[arg+1], args[0], args[1], proxy_type_str(curpx), curpx->id);
			return -1;
		}

		arg += 2;
		rule->action = ACT_TCP_EXPECT_PX;
	}
	else if (strcmp(args[arg], "expect-netscaler-cip") == 0) {
		if (strcmp(args[arg+1], "layer4") != 0) {
			memprintf(err,
				  "'%s %s %s' only supports 'layer4' in %s '%s' (got '%s')",
				  args[0], args[1], args[arg], proxy_type_str(curpx), curpx->id, args[arg+1]);
			return -1;
		}

		if (!(where & SMP_VAL_FE_CON_ACC)) {
			memprintf(err,
				  "'%s %s' is not allowed in '%s %s' rules in %s '%s'",
				  args[arg], args[arg+1], args[0], args[1], proxy_type_str(curpx), curpx->id);
			return -1;
		}

		arg += 2;
		rule->action = ACT_TCP_EXPECT_CIP;
	}
	else {
		struct action_kw *kw;
		if (where & SMP_VAL_FE_CON_ACC) {
			/* L4 */
			kw = tcp_req_conn_action(args[arg]);
			rule->kw = kw;
		} else if (where & SMP_VAL_FE_SES_ACC) {
			/* L5 */
			kw = tcp_req_sess_action(args[arg]);
			rule->kw = kw;
		} else {
			/* L6 */
			kw = tcp_req_cont_action(args[arg]);
			rule->kw = kw;
		}
		if (kw) {
			arg++;
			if (kw->parse((const char **)args, &arg, curpx, rule, err) == ACT_RET_PRS_ERR)
				return -1;
		} else {
			if (where & SMP_VAL_FE_CON_ACC)
				action_build_list(&tcp_req_conn_keywords, &trash);
			else if (where & SMP_VAL_FE_SES_ACC)
				action_build_list(&tcp_req_sess_keywords, &trash);
			else
				action_build_list(&tcp_req_cont_keywords, &trash);
			memprintf(err,
			          "'%s %s' expects 'accept', 'reject', 'track-sc0' ... 'track-sc%d', %s "
			          "in %s '%s' (got '%s').\n",
			          args[0], args[1], MAX_SESS_STKCTR-1,
			          trash.area, proxy_type_str(curpx),
			          curpx->id, args[arg]);
			return -1;
		}
	}

	if (strcmp(args[arg], "if") == 0 || strcmp(args[arg], "unless") == 0) {
		if ((rule->cond = build_acl_cond(file, line, &curpx->acl, curpx, (const char **)args+arg, err)) == NULL) {
			memprintf(err,
			          "'%s %s %s' : error detected in %s '%s' while parsing '%s' condition : %s",
			          args[0], args[1], args[2], proxy_type_str(curpx), curpx->id, args[arg], *err);
			return -1;
		}
	}
	else if (*args[arg]) {
		memprintf(err,
			 "'%s %s %s' only accepts 'if' or 'unless', in %s '%s' (got '%s')",
			 args[0], args[1], args[2], proxy_type_str(curpx), curpx->id, args[arg]);
		return -1;
	}
	return 0;
}

/* This function should be called to parse a line starting with the "tcp-response"
 * keyword.
 */
static int tcp_parse_tcp_rep(char **args, int section_type, struct proxy *curpx,
                             struct proxy *defpx, const char *file, int line,
                             char **err)
{
	const char *ptr = NULL;
	unsigned int val;
	int warn = 0;
	int arg;
	struct act_rule *rule;
	unsigned int where;
	const struct acl *acl;
	const char *kw;

	if (!*args[1]) {
		memprintf(err, "missing argument for '%s' in %s '%s'",
		          args[0], proxy_type_str(curpx), curpx->id);
		return -1;
	}

	if (strcmp(args[1], "inspect-delay") == 0) {
		if (curpx == defpx || !(curpx->cap & PR_CAP_BE)) {
			memprintf(err, "%s %s is only allowed in 'backend' sections",
			          args[0], args[1]);
			return -1;
		}

		if (!*args[2] || (ptr = parse_time_err(args[2], &val, TIME_UNIT_MS))) {
			memprintf(err,
			          "'%s %s' expects a positive delay in milliseconds, in %s '%s'",
			          args[0], args[1], proxy_type_str(curpx), curpx->id);

			if (ptr == PARSE_TIME_OVER)
				memprintf(err, "%s (timer overflow in '%s', maximum value is 2147483647 ms or ~24.8 days)", *err, args[2]);
			else if (ptr == PARSE_TIME_UNDER)
				memprintf(err, "%s (timer underflow in '%s', minimum non-null value is 1 ms)", *err, args[2]);
			else if (ptr)
				memprintf(err, "%s (unexpected character '%c')", *err, *ptr);
			return -1;
		}

		if (curpx->tcp_rep.inspect_delay) {
			memprintf(err, "ignoring %s %s (was already defined) in %s '%s'",
			          args[0], args[1], proxy_type_str(curpx), curpx->id);
			return 1;
		}
		curpx->tcp_rep.inspect_delay = val;
		return 0;
	}

	rule = calloc(1, sizeof(*rule));
	LIST_INIT(&rule->list);
	arg = 1;
	where = 0;

	if (strcmp(args[1], "content") == 0) {
		arg++;

		if (curpx->cap & PR_CAP_FE)
			where |= SMP_VAL_FE_RES_CNT;
		if (curpx->cap & PR_CAP_BE)
			where |= SMP_VAL_BE_RES_CNT;
		rule->from = ACT_F_TCP_RES_CNT;
		if (tcp_parse_response_rule(args, arg, section_type, curpx, defpx, rule, err, where, file, line) < 0)
			goto error;

		acl = rule->cond ? acl_cond_conflicts(rule->cond, where) : NULL;
		if (acl) {
			if (acl->name && *acl->name)
				memprintf(err,
					  "acl '%s' will never match in '%s %s' because it only involves keywords that are incompatible with '%s'",
					  acl->name, args[0], args[1], sample_ckp_names(where));
			else
				memprintf(err,
					  "anonymous acl will never match in '%s %s' because it uses keyword '%s' which is incompatible with '%s'",
					  args[0], args[1],
					  LIST_ELEM(acl->expr.n, struct acl_expr *, list)->kw,
					  sample_ckp_names(where));

			warn++;
		}
		else if (rule->cond && acl_cond_kw_conflicts(rule->cond, where, &acl, &kw)) {
			if (acl->name && *acl->name)
				memprintf(err,
					  "acl '%s' involves keyword '%s' which is incompatible with '%s'",
					  acl->name, kw, sample_ckp_names(where));
			else
				memprintf(err,
					  "anonymous acl involves keyword '%s' which is incompatible with '%s'",
					  kw, sample_ckp_names(where));
			warn++;
		}

		LIST_ADDQ(&curpx->tcp_rep.inspect_rules, &rule->list);
	}
	else {
		memprintf(err,
		          "'%s' expects 'inspect-delay' or 'content' in %s '%s' (got '%s')",
		          args[0], proxy_type_str(curpx), curpx->id, args[1]);
		goto error;
	}

	return warn;
 error:
	free(rule);
	return -1;
}


/* This function should be called to parse a line starting with the "tcp-request"
 * keyword.
 */
static int tcp_parse_tcp_req(char **args, int section_type, struct proxy *curpx,
                             struct proxy *defpx, const char *file, int line,
                             char **err)
{
	const char *ptr = NULL;
	unsigned int val;
	int warn = 0;
	int arg;
	struct act_rule *rule;
	unsigned int where;
	const struct acl *acl;
	const char *kw;

	if (!*args[1]) {
		if (curpx == defpx)
			memprintf(err, "missing argument for '%s' in defaults section", args[0]);
		else
			memprintf(err, "missing argument for '%s' in %s '%s'",
			          args[0], proxy_type_str(curpx), curpx->id);
		return -1;
	}

	if (strcmp(args[1], "inspect-delay") == 0) {
		if (curpx == defpx) {
			memprintf(err, "%s %s is not allowed in 'defaults' sections",
			          args[0], args[1]);
			return -1;
		}

		if (!*args[2] || (ptr = parse_time_err(args[2], &val, TIME_UNIT_MS))) {
			memprintf(err,
			          "'%s %s' expects a positive delay in milliseconds, in %s '%s'",
			          args[0], args[1], proxy_type_str(curpx), curpx->id);

			if (ptr == PARSE_TIME_OVER)
				memprintf(err, "%s (timer overflow in '%s', maximum value is 2147483647 ms or ~24.8 days)", *err, args[2]);
			else if (ptr == PARSE_TIME_UNDER)
				memprintf(err, "%s (timer underflow in '%s', minimum non-null value is 1 ms)", *err, args[2]);
			else if (ptr)
				memprintf(err, "%s (unexpected character '%c')", *err, *ptr);
			return -1;
		}

		if (curpx->tcp_req.inspect_delay) {
			memprintf(err, "ignoring %s %s (was already defined) in %s '%s'",
			          args[0], args[1], proxy_type_str(curpx), curpx->id);
			return 1;
		}
		curpx->tcp_req.inspect_delay = val;
		return 0;
	}

	rule = calloc(1, sizeof(*rule));
	LIST_INIT(&rule->list);
	arg = 1;
	where = 0;

	if (strcmp(args[1], "content") == 0) {
		arg++;

		if (curpx->cap & PR_CAP_FE)
			where |= SMP_VAL_FE_REQ_CNT;
		if (curpx->cap & PR_CAP_BE)
			where |= SMP_VAL_BE_REQ_CNT;
		rule->from = ACT_F_TCP_REQ_CNT;
		if (tcp_parse_request_rule(args, arg, section_type, curpx, defpx, rule, err, where, file, line) < 0)
			goto error;

		acl = rule->cond ? acl_cond_conflicts(rule->cond, where) : NULL;
		if (acl) {
			if (acl->name && *acl->name)
				memprintf(err,
					  "acl '%s' will never match in '%s %s' because it only involves keywords that are incompatible with '%s'",
					  acl->name, args[0], args[1], sample_ckp_names(where));
			else
				memprintf(err,
					  "anonymous acl will never match in '%s %s' because it uses keyword '%s' which is incompatible with '%s'",
					  args[0], args[1],
					  LIST_ELEM(acl->expr.n, struct acl_expr *, list)->kw,
					  sample_ckp_names(where));

			warn++;
		}
		else if (rule->cond && acl_cond_kw_conflicts(rule->cond, where, &acl, &kw)) {
			if (acl->name && *acl->name)
				memprintf(err,
					  "acl '%s' involves keyword '%s' which is incompatible with '%s'",
					  acl->name, kw, sample_ckp_names(where));
			else
				memprintf(err,
					  "anonymous acl involves keyword '%s' which is incompatible with '%s'",
					  kw, sample_ckp_names(where));
			warn++;
		}

		/* the following function directly emits the warning */
		warnif_misplaced_tcp_cont(curpx, file, line, args[0]);
		LIST_ADDQ(&curpx->tcp_req.inspect_rules, &rule->list);
	}
	else if (strcmp(args[1], "connection") == 0) {
		arg++;

		if (!(curpx->cap & PR_CAP_FE)) {
			memprintf(err, "%s %s is not allowed because %s %s is not a frontend",
			          args[0], args[1], proxy_type_str(curpx), curpx->id);
			goto error;
		}

		where |= SMP_VAL_FE_CON_ACC;
		rule->from = ACT_F_TCP_REQ_CON;
		if (tcp_parse_request_rule(args, arg, section_type, curpx, defpx, rule, err, where, file, line) < 0)
			goto error;

		acl = rule->cond ? acl_cond_conflicts(rule->cond, where) : NULL;
		if (acl) {
			if (acl->name && *acl->name)
				memprintf(err,
					  "acl '%s' will never match in '%s %s' because it only involves keywords that are incompatible with '%s'",
					  acl->name, args[0], args[1], sample_ckp_names(where));
			else
				memprintf(err,
					  "anonymous acl will never match in '%s %s' because it uses keyword '%s' which is incompatible with '%s'",
					  args[0], args[1],
					  LIST_ELEM(acl->expr.n, struct acl_expr *, list)->kw,
					  sample_ckp_names(where));

			warn++;
		}
		else if (rule->cond && acl_cond_kw_conflicts(rule->cond, where, &acl, &kw)) {
			if (acl->name && *acl->name)
				memprintf(err,
					  "acl '%s' involves keyword '%s' which is incompatible with '%s'",
					  acl->name, kw, sample_ckp_names(where));
			else
				memprintf(err,
					  "anonymous acl involves keyword '%s' which is incompatible with '%s'",
					  kw, sample_ckp_names(where));
			warn++;
		}

		/* the following function directly emits the warning */
		warnif_misplaced_tcp_conn(curpx, file, line, args[0]);
		LIST_ADDQ(&curpx->tcp_req.l4_rules, &rule->list);
	}
	else if (strcmp(args[1], "session") == 0) {
		arg++;

		if (!(curpx->cap & PR_CAP_FE)) {
			memprintf(err, "%s %s is not allowed because %s %s is not a frontend",
			          args[0], args[1], proxy_type_str(curpx), curpx->id);
			goto error;
		}

		where |= SMP_VAL_FE_SES_ACC;
		rule->from = ACT_F_TCP_REQ_SES;
		if (tcp_parse_request_rule(args, arg, section_type, curpx, defpx, rule, err, where, file, line) < 0)
			goto error;

		acl = rule->cond ? acl_cond_conflicts(rule->cond, where) : NULL;
		if (acl) {
			if (acl->name && *acl->name)
				memprintf(err,
					  "acl '%s' will never match in '%s %s' because it only involves keywords that are incompatible with '%s'",
					  acl->name, args[0], args[1], sample_ckp_names(where));
			else
				memprintf(err,
					  "anonymous acl will never match in '%s %s' because it uses keyword '%s' which is incompatible with '%s'",
					  args[0], args[1],
					  LIST_ELEM(acl->expr.n, struct acl_expr *, list)->kw,
					  sample_ckp_names(where));
			warn++;
		}
		else if (rule->cond && acl_cond_kw_conflicts(rule->cond, where, &acl, &kw)) {
			if (acl->name && *acl->name)
				memprintf(err,
					  "acl '%s' involves keyword '%s' which is incompatible with '%s'",
					  acl->name, kw, sample_ckp_names(where));
			else
				memprintf(err,
					  "anonymous acl involves keyword '%s' which is incompatible with '%s'",
					  kw, sample_ckp_names(where));
			warn++;
		}

		/* the following function directly emits the warning */
		warnif_misplaced_tcp_sess(curpx, file, line, args[0]);
		LIST_ADDQ(&curpx->tcp_req.l5_rules, &rule->list);
	}
	else {
		if (curpx == defpx)
			memprintf(err,
			          "'%s' expects 'inspect-delay', 'connection', or 'content' in defaults section (got '%s')",
			          args[0], args[1]);
		else
			memprintf(err,
			          "'%s' expects 'inspect-delay', 'connection', or 'content' in %s '%s' (got '%s')",
			          args[0], proxy_type_str(curpx), curpx->id, args[1]);
		goto error;
	}

	return warn;
 error:
	free(rule);
	return -1;
}

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_LISTEN, "tcp-request",  tcp_parse_tcp_req },
	{ CFG_LISTEN, "tcp-response", tcp_parse_tcp_rep },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
