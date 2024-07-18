#include <haproxy/quic_rules.h>

#include <haproxy/acl.h>
#include <haproxy/action.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/proxy-t.h>
#include <haproxy/sample-t.h>

/* Execute registered quic-initial rules on proxy owning <li> listener. */
int quic_init_exec_rules(struct listener *li)
{
	struct act_rule *rule;
	enum acl_test_res ret;
	struct proxy *px;
	int result = 1;

	px = li->bind_conf->frontend;

	list_for_each_entry(rule, &px->quic_init_rules, list) {
		ret = ACL_TEST_PASS;

		if (rule->cond) {
			ret = acl_exec_cond(rule->cond, px, NULL, NULL, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			if (rule->action_ptr) {
				switch (rule->action_ptr(rule, px, NULL, NULL, 0)) {
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
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, quic_init_actions_register, &quic_init_actions);
