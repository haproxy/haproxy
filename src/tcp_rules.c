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
#include <haproxy/sc_strm.h>
#include <haproxy/stconn.h>
#include <haproxy/stick_table.h>
#include <haproxy/stream-t.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/ticks.h>
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
	LIST_APPEND(&tcp_req_conn_keywords, &kw_list->list);
}

void tcp_req_sess_keywords_register(struct action_kw_list *kw_list)
{
	LIST_APPEND(&tcp_req_sess_keywords, &kw_list->list);
}

void tcp_req_cont_keywords_register(struct action_kw_list *kw_list)
{
	LIST_APPEND(&tcp_req_cont_keywords, &kw_list->list);
}

void tcp_res_cont_keywords_register(struct action_kw_list *kw_list)
{
	LIST_APPEND(&tcp_res_cont_keywords, &kw_list->list);
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
	struct list *def_rules, *rules;
	struct session *sess = s->sess;
	struct act_rule *rule;
	int partial;
	int act_opts = 0;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_TCP_ANA, s);

	def_rules = ((s->be->defpx &&
	              (sess->fe->mode == PR_MODE_TCP || sess->fe->mode == PR_MODE_HTTP) &&
	              (an_bit == AN_REQ_INSPECT_FE || s->be->defpx != sess->fe->defpx)) ? &s->be->defpx->tcp_req.inspect_rules : NULL);
	rules = &s->be->tcp_req.inspect_rules;

	/* We don't know whether we have enough data, so must proceed
	 * this way :
	 * - iterate through all rules in their declaration order
	 * - if one rule returns MISS, it means the inspect delay is
	 *   not over yet, then return immediately, otherwise consider
	 *   it as a non-match.
	 * - if one rule returns OK, then return OK
	 * - if one rule returns KO, then return KO
	 */

	if ((s->scf->flags & (SC_FL_EOS|SC_FL_ABRT_DONE)) || channel_full(req, global.tune.maxrewrite) ||
	    sc_waiting_room(s->scf) ||
	    !s->be->tcp_req.inspect_delay || tick_is_expired(s->rules_exp, now_ms)) {
		partial = SMP_OPT_FINAL;
		/* Action may yield while the inspect_delay is not expired and there is no read error */
		if ((s->scf->flags & SC_FL_ERROR) || !s->be->tcp_req.inspect_delay || tick_is_expired(s->rules_exp, now_ms))
			act_opts |= ACT_OPT_FINAL;
	}
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
		if (!(req->flags & SC_FL_ERROR) && !(req->flags & (CF_READ_TIMEOUT|CF_WRITE_TIMEOUT))) {
			s->waiting_entity.type = STRM_ENTITY_NONE;
			s->waiting_entity.ptr = NULL;
		}
		if ((def_rules && s->current_rule_list == def_rules) || s->current_rule_list == rules)
			goto resume_execution;
	}
	s->current_rule_list = ((!def_rules || s->current_rule_list == def_rules) ? rules : def_rules);

  restart:
	list_for_each_entry(rule, s->current_rule_list, list) {
		enum acl_test_res ret = ACL_TEST_PASS;

		if (rule->cond) {
			ret = acl_exec_cond(rule->cond, s->be, sess, s, SMP_OPT_DIR_REQ | partial);
			if (ret == ACL_TEST_MISS)
				goto missing_data;

			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;

			if (!ret)
				continue;
		}

		act_opts |= ACT_OPT_FIRST;
resume_execution:
		/* Always call the action function if defined */
		if (rule->action_ptr) {
			switch (rule->action_ptr(rule, s->be, s->sess, s, act_opts)) {
				case ACT_RET_CONT:
					break;
				case ACT_RET_STOP:
				case ACT_RET_DONE:
					s->last_entity.type = STRM_ENTITY_RULE;
					s->last_entity.ptr  = rule;
					goto end;
				case ACT_RET_YIELD:
					s->current_rule = rule;
					if (act_opts & ACT_OPT_FINAL) {
						send_log(s->be, LOG_WARNING,
							 "Internal error: yield not allowed if the inspect-delay expired "
							 "for the tcp-request content actions.");
						s->last_entity.type = STRM_ENTITY_RULE;
						s->last_entity.ptr  = rule;
						goto internal;
					}
					s->waiting_entity.type = STRM_ENTITY_RULE;
					s->waiting_entity.ptr  = rule;
					goto missing_data;
				case ACT_RET_DENY:
					s->last_entity.type = STRM_ENTITY_RULE;
					s->last_entity.ptr  = rule;
					goto deny;
				case ACT_RET_ABRT:
					stream_report_term_evt(s->scf, strm_tevt_type_intercepted);
					s->last_entity.type = STRM_ENTITY_RULE;
					s->last_entity.ptr  = rule;
					goto abort;
				case ACT_RET_ERR:
					s->last_entity.type = STRM_ENTITY_RULE;
					s->last_entity.ptr  = rule;
					goto internal;
				case ACT_RET_INV:
					s->last_entity.type = STRM_ENTITY_RULE;
					s->last_entity.ptr  = rule;
					goto invalid;
			}
			continue; /* eval the next rule */
		}

		/* If not action function defined, check for known actions */
		if (rule->action == ACT_ACTION_ALLOW) {
			s->last_entity.type = STRM_ENTITY_RULE;
			s->last_entity.ptr  = rule;
			goto end;
		}
		else if (rule->action == ACT_ACTION_DENY) {
			s->last_entity.type = STRM_ENTITY_RULE;
			s->last_entity.ptr  = rule;
			goto deny;
		}
	}

	if (def_rules && s->current_rule_list == def_rules) {
		s->current_rule_list = rules;
		goto restart;
	}

 end:
	/* if we get there, it means we have no rule which matches, or
	 * we have an explicit accept, so we apply the default accept.
	 */
	req->analysers &= ~an_bit;
	s->current_rule = s->current_rule_list = NULL;
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
	_HA_ATOMIC_INC(&sess->fe->fe_counters.denied_req);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->denied_req);
	stream_report_term_evt(s->scf, strm_tevt_type_intercepted);
	goto reject;

 internal:
	_HA_ATOMIC_INC(&sess->fe->fe_counters.internal_errors);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->internal_errors);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_INTERNAL;
	stream_report_term_evt(s->scf, strm_tevt_type_internal_err);
	goto reject;

 invalid:
	_HA_ATOMIC_INC(&sess->fe->fe_counters.failed_req);
	if (sess->listener && sess->listener->counters)
		_HA_ATOMIC_INC(&sess->listener->counters->failed_req);
	stream_report_term_evt(s->scf, strm_tevt_type_proto_err);

 reject:
	sc_must_kill_conn(s->scf);
	stream_abort(s);

 abort:
	// XXX: All errors are handled as intercepted here !
	req->analysers &= AN_REQ_FLT_END;
	s->current_rule = s->current_rule_list = NULL;
	req->analyse_exp = s->rules_exp = TICK_ETERNITY;

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
	struct list *def_rules, *rules;
	struct session *sess = s->sess;
	struct act_rule *rule;
	int partial;
	int act_opts = 0;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_TCP_ANA, s);

	def_rules = (s->be->defpx && (s->be->mode == PR_MODE_TCP || s->be->mode == PR_MODE_HTTP) ? &s->be->defpx->tcp_rep.inspect_rules : NULL);
	rules = &s->be->tcp_rep.inspect_rules;

	/* We don't know whether we have enough data, so must proceed
	 * this way :
	 * - iterate through all rules in their declaration order
	 * - if one rule returns MISS, it means the inspect delay is
	 *   not over yet, then return immediately, otherwise consider
	 *   it as a non-match.
	 * - if one rule returns OK, then return OK
	 * - if one rule returns KO, then return KO
	 */
	if ((s->scb->flags & (SC_FL_EOS|SC_FL_ABRT_DONE)) || channel_full(rep, global.tune.maxrewrite) ||
	    sc_waiting_room(s->scb) ||
	    !s->be->tcp_rep.inspect_delay || tick_is_expired(s->rules_exp, now_ms)) {
		partial = SMP_OPT_FINAL;
		/* Action may yield while the inspect_delay is not expired and there is no read error */
		if ((s->scb->flags & SC_FL_ERROR) || !s->be->tcp_rep.inspect_delay || tick_is_expired(s->rules_exp, now_ms))
			act_opts |= ACT_OPT_FINAL;
	}
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
		if (!(rep->flags & SC_FL_ERROR) && !(rep->flags & (CF_READ_TIMEOUT|CF_WRITE_TIMEOUT))) {
			s->waiting_entity.type = STRM_ENTITY_NONE;
			s->waiting_entity.ptr = NULL;
		}
		if ((def_rules && s->current_rule_list == def_rules) || s->current_rule_list == rules)
			goto resume_execution;
	}
	s->current_rule_list = ((!def_rules || s->current_rule_list == def_rules) ? rules : def_rules);

  restart:
	list_for_each_entry(rule, s->current_rule_list, list) {
		enum acl_test_res ret = ACL_TEST_PASS;

		if (rule->cond) {
			ret = acl_exec_cond(rule->cond, s->be, sess, s, SMP_OPT_DIR_RES | partial);
			if (ret == ACL_TEST_MISS)
				goto missing_data;

			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
			if (!ret)
				continue;
		}

		act_opts |= ACT_OPT_FIRST;
resume_execution:

		/* Always call the action function if defined */
		if (rule->action_ptr) {
			switch (rule->action_ptr(rule, s->be, s->sess, s, act_opts)) {
				case ACT_RET_CONT:
					break;
				case ACT_RET_STOP:
				case ACT_RET_DONE:
					s->last_entity.type = STRM_ENTITY_RULE;
					s->last_entity.ptr  = rule;
					goto end;
				case ACT_RET_YIELD:
					s->current_rule = rule;
					if (act_opts & ACT_OPT_FINAL) {
						send_log(s->be, LOG_WARNING,
							 "Internal error: yield not allowed if the inspect-delay expired "
							 "for the tcp-response content actions.");
						s->last_entity.type = STRM_ENTITY_RULE;
						s->last_entity.ptr  = rule;
						goto internal;
					}
					s->waiting_entity.type = STRM_ENTITY_RULE;
					s->waiting_entity.ptr  = rule;
					channel_dont_close(rep);
					goto missing_data;
				case ACT_RET_DENY:
					s->last_entity.type = STRM_ENTITY_RULE;
					s->last_entity.ptr  = rule;
					goto deny;
				case ACT_RET_ABRT:
					stream_report_term_evt(s->scb, strm_tevt_type_intercepted);
					s->last_entity.type = STRM_ENTITY_RULE;
					s->last_entity.ptr  = rule;
					goto abort;
				case ACT_RET_ERR:
					s->last_entity.type = STRM_ENTITY_RULE;
					s->last_entity.ptr  = rule;
					goto internal;
				case ACT_RET_INV:
					s->last_entity.type = STRM_ENTITY_RULE;
					s->last_entity.ptr  = rule;
					goto invalid;
			}
			continue; /* eval the next rule */
		}

		/* If not action function defined, check for known actions */
		if (rule->action == ACT_ACTION_ALLOW) {
			s->last_entity.type = STRM_ENTITY_RULE;
			s->last_entity.ptr  = rule;
			goto end;
		}
		else if (rule->action == ACT_ACTION_DENY) {
			s->last_entity.type = STRM_ENTITY_RULE;
			s->last_entity.ptr  = rule;
			goto deny;
		}
		else if (rule->action == ACT_TCP_CLOSE) {
			s->scb->flags |= SC_FL_NOLINGER | SC_FL_NOHALF;
			sc_must_kill_conn(s->scb);
			sc_abort(s->scb);
			sc_shutdown(s->scb);
			s->last_entity.type = STRM_ENTITY_RULE;
			s->last_entity.ptr  = rule;
			goto end;
		}
	}

	if (def_rules && s->current_rule_list == def_rules) {
		s->current_rule_list = rules;
		goto restart;
	}

 end:
	/* if we get there, it means we have no rule which matches, or
	 * we have an explicit accept, so we apply the default accept.
	 */
	rep->analysers &= ~an_bit;
	s->current_rule = s->current_rule_list = NULL;
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
	_HA_ATOMIC_INC(&s->sess->fe->fe_counters.denied_resp);
	_HA_ATOMIC_INC(&s->be->be_counters.denied_resp);
	if (s->sess->listener && s->sess->listener->counters)
		_HA_ATOMIC_INC(&s->sess->listener->counters->denied_resp);
	if (objt_server(s->target))
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.denied_resp);
	stream_report_term_evt(s->scb, strm_tevt_type_intercepted);
	goto reject;

 internal:
	_HA_ATOMIC_INC(&s->sess->fe->fe_counters.internal_errors);
	_HA_ATOMIC_INC(&s->be->be_counters.internal_errors);
	if (s->sess->listener && s->sess->listener->counters)
		_HA_ATOMIC_INC(&s->sess->listener->counters->internal_errors);
	if (objt_server(s->target))
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.internal_errors);
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_INTERNAL;
	stream_report_term_evt(s->scf, strm_tevt_type_internal_err);
	goto reject;

 invalid:
	_HA_ATOMIC_INC(&s->be->be_counters.failed_resp);
	if (objt_server(s->target))
		_HA_ATOMIC_INC(&__objt_server(s->target)->counters.failed_resp);
	stream_report_term_evt(s->scf, strm_tevt_type_proto_err);

 reject:
	sc_must_kill_conn(s->scb);
	stream_abort(s);

  abort:
	rep->analysers &= AN_RES_FLT_END;
	s->current_rule = s->current_rule_list = NULL;
	rep->analyse_exp = s->rules_exp = TICK_ETERNITY;

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
 * any data. This only works on connection-based client-facing stream connectors.
 */
int tcp_exec_l4_rules(struct session *sess)
{
	struct proxy *px = sess->fe;
	struct act_rule *rule;
	struct connection *conn = objt_conn(sess->origin);
	int result = 1;

	if (!conn)
		return result;

	if  (sess->fe->defpx && (sess->fe->mode == PR_MODE_TCP || sess->fe->mode == PR_MODE_HTTP))
		px = sess->fe->defpx;

  restart:
	list_for_each_entry(rule, &px->tcp_req.l4_rules, list) {

		if (!acl_match_cond(rule->cond, sess->fe, sess, NULL, SMP_OPT_DIR_REQ|SMP_OPT_FINAL))
			continue;

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
			_HA_ATOMIC_INC(&sess->fe->fe_counters.denied_conn);
			if (sess->listener && sess->listener->counters)
				_HA_ATOMIC_INC(&sess->listener->counters->denied_conn);

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

	if (px != sess->fe) {
		px = sess->fe;
		goto restart;
	}
 end:
	if (!result)
		conn_report_term_evt(conn, tevt_loc_fd, fd_tevt_type_intercepted);
	return result;
}

/* This function performs the TCP layer5 analysis on the current request. It
 * returns 0 if a reject rule matches, otherwise 1 if either an accept rule
 * matches or if no more rule matches. It can only use rules which don't need
 * any data. This only works on session-based client-facing stream connectors.
 * An example of valid use case is to track a stick-counter on the source
 * address extracted from the proxy protocol.
 */
int tcp_exec_l5_rules(struct session *sess)
{
	struct proxy *px = sess->fe;
	struct act_rule *rule;
	int result = 1;

	if  (sess->fe->defpx && (sess->fe->mode == PR_MODE_TCP || sess->fe->mode == PR_MODE_HTTP))
		px = sess->fe->defpx;

  restart:
	list_for_each_entry(rule, &px->tcp_req.l5_rules, list) {
		if (!acl_match_cond(rule->cond, sess->fe, sess, NULL, SMP_OPT_DIR_REQ|SMP_OPT_FINAL))
			continue;

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
			_HA_ATOMIC_INC(&sess->fe->fe_counters.denied_sess);
			if (sess->listener && sess->listener->counters)
				_HA_ATOMIC_INC(&sess->listener->counters->denied_sess);

			result = 0;
			goto end;
		}
	}

	if (px != sess->fe) {
		px = sess->fe;
		goto restart;
	}
  end:
	return result;
}

/* Parse a tcp-response rule. Return a negative value in case of failure */
static int tcp_parse_response_rule(char **args, int arg, int section_type,
                                   struct proxy *curpx, const struct proxy *defpx,
                                   struct act_rule *rule, char **err,
                                   unsigned int where,
                                   const char *file, int line)
{
	if ((curpx == defpx && strlen(defpx->id) == 0) || !(curpx->cap & PR_CAP_BE)) {
		memprintf(err, "%s %s is only allowed in 'backend' sections or 'defaults' section with a name",
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
			const char *extra[] = { "accept", "reject", "close", NULL };
			const char *best = action_suggest(args[arg], &tcp_res_cont_keywords, extra);

			action_build_list(&tcp_res_cont_keywords, &trash);
			memprintf(err,
			          "'%s %s' expects 'accept', 'close', 'reject', %s in %s '%s' (got '%s').%s%s%s",
			          args[0], args[1], trash.area,
			          proxy_type_str(curpx), curpx->id, args[arg],
			          best ? " Did you mean '" : "",
			          best ? best : "",
			          best ? "' maybe ?" : "");
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
                                  struct proxy *curpx, const struct proxy *defpx,
                                  struct act_rule *rule, char **err,
                                  unsigned int where, const char *file, int line)
{
	if (curpx == defpx && strlen(defpx->id) == 0) {
		memprintf(err, "%s %s is not allowed in anonymous 'defaults' sections",
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
		if (!hdr) {
			memprintf(err, "parsing [%s:%d] : out of memory", file, line);
			release_sample_expr(expr);
			return -1;
		}
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
			const char *extra[] = { "accept", "reject", "capture", "track-sc", "expect-proxy", "expect-netscaler-cip", NULL };
			const char *best = NULL;


			if (where & SMP_VAL_FE_CON_ACC) {
				action_build_list(&tcp_req_conn_keywords, &trash);
				best = action_suggest(args[arg], &tcp_req_conn_keywords, extra);
			}
			else if (where & SMP_VAL_FE_SES_ACC) {
				action_build_list(&tcp_req_sess_keywords, &trash);
				best = action_suggest(args[arg], &tcp_req_sess_keywords, extra);
			}
			else {
				action_build_list(&tcp_req_cont_keywords, &trash);
				best = action_suggest(args[arg], &tcp_req_cont_keywords, extra);
			}

			memprintf(err,
			          "'%s %s' expects 'accept', 'reject', 'capture', 'expect-proxy', 'expect-netscaler-cip', 'track-sc0' ... 'track-sc%d', %s "
			          "in %s '%s' (got '%s').%s%s%s\n",
			          args[0], args[1], global.tune.nb_stk_ctr-1,
			          trash.area, proxy_type_str(curpx),
			          curpx->id, args[arg],
			          best ? " Did you mean '" : "",
			          best ? best : "",
			          best ? "' maybe ?" : "");
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
                             const struct proxy *defpx, const char *file, int line,
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
		if ((curpx == defpx && strlen(defpx->id) == 0) || !(curpx->cap & PR_CAP_BE)) {
			memprintf(err, "%s %s is only allowed in 'backend' sections or 'defaults' section with a name",
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

	rule = new_act_rule(ACT_F_TCP_RES_CNT, file, line);
	if (!rule) {
		memprintf(err, "parsing [%s:%d] : out of memory", file, line);
		return -1;
	}
	LIST_INIT(&rule->list);
	arg = 1;
	where = 0;

	if (strcmp(args[1], "content") == 0) {
		arg++;

		if (curpx->cap & PR_CAP_FE)
			where |= SMP_VAL_FE_RES_CNT;
		if (curpx->cap & PR_CAP_BE)
			where |= SMP_VAL_BE_RES_CNT;
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

		/* the following function directly emits the warning */
		warnif_misplaced_tcp_res_cont(curpx, file, line, args[0], args[1]);
		LIST_APPEND(&curpx->tcp_rep.inspect_rules, &rule->list);
	}
	else {
		memprintf(err,
		          "'%s' expects 'inspect-delay' or 'content' in %s '%s' (got '%s')",
		          args[0], proxy_type_str(curpx), curpx->id, args[1]);
		goto error;
	}

	return warn;
 error:
	free_act_rule(rule);
	return -1;
}


/* This function should be called to parse a line starting with the "tcp-request"
 * keyword.
 */
static int tcp_parse_tcp_req(char **args, int section_type, struct proxy *curpx,
                             const struct proxy *defpx, const char *file, int line,
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
		if (curpx == defpx && strlen(defpx->id) == 0) {
			memprintf(err, "%s %s is not allowed in anonymous 'defaults' sections",
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

	rule = new_act_rule(0, file, line);
	if (!rule) {
		memprintf(err, "parsing [%s:%d] : out of memory", file, line);
		return -1;
	}
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
		warnif_misplaced_tcp_req_cont(curpx, file, line, args[0], args[1]);
		LIST_APPEND(&curpx->tcp_req.inspect_rules, &rule->list);
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
		warnif_misplaced_tcp_req_conn(curpx, file, line, args[0], args[1]);
		LIST_APPEND(&curpx->tcp_req.l4_rules, &rule->list);
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
		warnif_misplaced_tcp_req_sess(curpx, file, line, args[0], args[1]);
		LIST_APPEND(&curpx->tcp_req.l5_rules, &rule->list);
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
	free_act_rule(rule);
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
