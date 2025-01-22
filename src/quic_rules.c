#include <haproxy/quic_rules.h>

#include <haproxy/acl.h>
#include <haproxy/action.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/obj_type.h>
#include <haproxy/proxy-t.h>
#include <haproxy/quic_sock-t.h>
#include <haproxy/sample-t.h>
#include <haproxy/session-t.h>

/* Execute registered quic-initial rules on proxy owning <li> listener after
 * <dgram> reception.
 */
int quic_init_exec_rules(struct listener *li, struct quic_dgram *dgram)
{
	static THREAD_LOCAL struct session rule_sess;
	struct act_rule *rule;
	struct proxy *px;
	int result = 1;

	px = li->bind_conf->frontend;

	/* Initialize session elements specific to the current datagram. All
	 * others members are set to 0 thanks to static storage class.
	 */
	rule_sess.fe = px;
	rule_sess.listener = li;
	rule_sess.src = &dgram->saddr;
	rule_sess.dst = &dgram->daddr;
	rule_sess.origin = &dgram->obj_type;

	list_for_each_entry(rule, &px->quic_init_rules, list) {
		if (!acl_match_cond(rule->cond, px, &rule_sess, NULL, SMP_OPT_DIR_REQ|SMP_OPT_FINAL))
			continue;

		if (rule->action_ptr) {
			switch (rule->action_ptr(rule, px, &rule_sess, NULL, 0)) {
			case ACT_RET_CONT:
				break;
			case ACT_RET_DONE:
			case ACT_RET_STOP:
				goto end;
			case ACT_RET_ABRT:
			case ACT_RET_DENY:
			case ACT_RET_ERR:
			case ACT_RET_INV:
				result = 0;
				goto end;
			default:
				ABORT_NOW("not implemented");
			}
		}
		else if (rule->action == ACT_ACTION_ALLOW) {
			goto end;
		}
		else if (rule->action == ACT_ACTION_DENY) {
			result = 0;
			goto end;
		}
	}

 end:
	return result;
}

static enum act_parse_ret parse_accept(const char **args, int *orig_arg,
                                       struct proxy *px,
                                       struct act_rule *rule, char **err)
{
	rule->action = ACT_ACTION_ALLOW;
	rule->flags |= ACT_FLAG_FINAL;
	return ACT_RET_PRS_OK;
}

static enum act_parse_ret parse_dgram_drop(const char **args, int *orig_arg,
                                           struct proxy *px,
                                           struct act_rule *rule, char **err)
{
	rule->action = ACT_ACTION_DENY;
	rule->flags |= ACT_FLAG_FINAL;
	return ACT_RET_PRS_OK;
}

static enum log_orig_id do_log_quic_init;

static void init_do_log(void)
{
	do_log_quic_init = log_orig_register("quic-init");
	BUG_ON(do_log_quic_init == LOG_ORIG_UNSPEC);
}

INITCALL0(STG_PREPARE, init_do_log);

static enum act_parse_ret parse_do_log(const char **args, int *orig_arg,
                                       struct proxy *px,
                                       struct act_rule *rule, char **err)
{
	return do_log_parse_act(do_log_quic_init, args, orig_arg, px, rule, err);
}

static enum act_return quic_init_action_reject(struct act_rule *rule, struct proxy *px,
                                               struct session *sess, struct stream *s, int flags)
{
	struct quic_dgram *dgram = __objt_dgram(sess->origin);
	dgram->flags |= QUIC_DGRAM_FL_REJECT;
	return ACT_RET_DONE;
}

static enum act_return quic_init_action_send_retry(struct act_rule *rule, struct proxy *px,
                                                   struct session *sess, struct stream *s, int flags)
{
	struct quic_dgram *dgram = __objt_dgram(sess->origin);
	dgram->flags |= QUIC_DGRAM_FL_SEND_RETRY;
	return ACT_RET_DONE;
}

static enum act_parse_ret parse_reject(const char **args, int *orig_arg,
                                       struct proxy *px,
                                       struct act_rule *rule, char **err)
{
	rule->action     = ACT_CUSTOM;
	rule->action_ptr = quic_init_action_reject;
	return ACT_RET_PRS_OK;
}

static enum act_parse_ret parse_send_retry(const char **args, int *orig_arg,
                                           struct proxy *px,
                                           struct act_rule *rule, char **err)
{
	rule->action     = ACT_CUSTOM;
	rule->action_ptr = quic_init_action_send_retry;
	return ACT_RET_PRS_OK;
}

/* List head of all known action keywords for "quic-initial" */
struct action_kw_list quic_init_actions_list = {
       .list = LIST_HEAD_INIT(quic_init_actions_list.list)
};

void quic_init_actions_register(struct action_kw_list *kw_list)
{
	LIST_APPEND(&quic_init_actions_list.list, &kw_list->list);
}

/* Return the struct quic-initial action associated to a keyword. */
struct action_kw *action_quic_init_custom(const char *kw)
{
	return action_lookup(&quic_init_actions_list.list, kw);
}

static struct action_kw_list quic_init_actions = { ILH, {
		{ "accept",           parse_accept,            0 },
		{ "dgram-drop",       parse_dgram_drop,        0 },
		{ "do-log",           parse_do_log,            0 },
		{ "reject",           parse_reject,            0 },
		{ "send-retry",       parse_send_retry,        0 },
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, quic_init_actions_register, &quic_init_actions);
