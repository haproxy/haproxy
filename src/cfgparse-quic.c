#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#include <haproxy/acl.h>
#include <haproxy/action.h>
#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/listener.h>
#include <haproxy/proxy.h>
#include <haproxy/quic_cc.h>
#include <haproxy/quic_rules.h>
#include <haproxy/quic_tune.h>
#include <haproxy/tools.h>

#define QUIC_CC_NEWRENO_STR "newreno"
#define QUIC_CC_CUBIC_STR   "cubic"
#define QUIC_CC_BBR_STR     "bbr"
#define QUIC_CC_NO_CC_STR   "nocc"

struct quic_tune quic_tune;

static int bind_parse_quic_force_retry(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->options |= BC_O_QUIC_FORCE_RETRY;
	return 0;
}

/* Parse <value> as a window size integer argument to keyword <kw>. By
 * default, value is explained as bytes. Suffixes 'k', 'm' and 'g' are valid as
 * multipliers. <end_opt> will point to the next unparsed character.
 *
 * Return the parsed window size or 0 on error.
 */
static unsigned long parse_window_size(const char *kw, char *value,
                                       char **end_opt, char **err)
{
	unsigned long size;

	errno = 0;
	size = strtoul(value, end_opt, 0);
	if (*end_opt == value || errno != 0) {
		memprintf(err, "'%s' : could not parse congestion window value", kw);
		goto fail;
	}

	if (**end_opt == 'k') {
		size <<= 10;
		(*end_opt)++;
	}
	else if (**end_opt == 'm') {
		size <<= 20;
		(*end_opt)++;
	}
	else if (**end_opt == 'g') {
		size <<= 30;
		(*end_opt)++;
	}

	if (size < 10240 || size > (4UL << 30)) {
		memprintf(err, "'%s' : should be between 10k and 4g", kw);
		goto fail;
	}

	return size;

 fail:
	return 0;
}

/* parse "quic-cc-algo" bind keyword */
static int bind_parse_quic_cc_algo(char **args, int cur_arg, struct proxy *px,
                                   struct bind_conf *conf, char **err)
{
	struct quic_cc_algo *cc_algo = NULL;
	const char *algo = NULL;
	struct ist algo_ist, arg_ist;
	char *arg;

	cc_algo = calloc(1, sizeof(struct quic_cc_algo));
	if (!cc_algo) {
		memprintf(err, "'%s' : out of memory", args[cur_arg]);
		goto fail;
	}

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing control congestion algorithm", args[cur_arg]);
		goto fail;
	}

	arg = args[cur_arg + 1];
	arg_ist = ist(args[cur_arg + 1]);
	algo_ist = istsplit(&arg_ist, '(');
	if (isteq(algo_ist, ist(QUIC_CC_NEWRENO_STR))) {
		/* newreno */
		algo = QUIC_CC_NEWRENO_STR;
		*cc_algo = quic_cc_algo_nr;
		arg += strlen(QUIC_CC_NEWRENO_STR);
	}
	else if (isteq(algo_ist, ist(QUIC_CC_CUBIC_STR))) {
		/* cubic */
		algo = QUIC_CC_CUBIC_STR;
		*cc_algo = quic_cc_algo_cubic;
		arg += strlen(QUIC_CC_CUBIC_STR);
	}
	else if (isteq(algo_ist, ist(QUIC_CC_BBR_STR))) {
		/* bbr */
		algo = QUIC_CC_BBR_STR;
		*cc_algo = quic_cc_algo_bbr;
		arg += strlen(QUIC_CC_BBR_STR);
	}
	else if (isteq(algo_ist, ist(QUIC_CC_NO_CC_STR))) {
		/* nocc */
		if (!experimental_directives_allowed) {
			ha_alert("'%s' algo is experimental, must be allowed via a global "
			         "'expose-experimental-directives'\n", arg);
			goto fail;
		}

		algo = QUIC_CC_NO_CC_STR;
		*cc_algo = quic_cc_algo_nocc;
		arg += strlen(QUIC_CC_NO_CC_STR);
	}
	else {
		memprintf(err, "'%s' : unknown control congestion algorithm", args[cur_arg + 1]);
		goto fail;
	}

	if (*arg++ == '(') {
		char *end_opt;

		if (*arg == ')')
			goto out;

		if (*arg != ',') {
			unsigned long cwnd = parse_window_size(args[cur_arg], arg, &end_opt, err);
			if (!cwnd)
				goto fail;

			conf->max_cwnd = cwnd;

			if (*end_opt == ')') {
				goto out;
			}
			else if (*end_opt != ',') {
				memprintf(err, "'%s' : cannot parse max-window argument for '%s' algorithm", args[cur_arg], algo);
				goto fail;
			}
			arg = end_opt;
		}

		if (*++arg != ')') {
			memprintf(err, "'%s' : too many argument for '%s' algorithm", args[cur_arg], algo);
			goto fail;
		}
	}

 out:
	conf->quic_cc_algo = cc_algo;
	return 0;

 fail:
	free(cc_algo);
	return ERR_ALERT | ERR_FATAL;
}

static int bind_parse_quic_socket(char **args, int cur_arg, struct proxy *px,
                                  struct bind_conf *conf, char **err)
{
	char *arg;
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing argument, use either connection or listener.", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	arg = args[cur_arg + 1];
	if (strcmp(arg, "connection") == 0) {
		conf->quic_mode = QUIC_SOCK_MODE_CONN;
	}
	else if (strcmp(arg, "listener") == 0) {
		conf->quic_mode = QUIC_SOCK_MODE_LSTNR;
	}
	else {
		memprintf(err, "'%s' : unknown argument, use either connection or listener.", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

static struct bind_kw_list bind_kws = { "QUIC", { }, {
	{ "quic-force-retry", bind_parse_quic_force_retry, 0 },
	{ "quic-cc-algo", bind_parse_quic_cc_algo, 1 },
	{ "quic-socket", bind_parse_quic_socket, 1 },
	{ NULL, NULL, 0 },
}};

INITCALL1(STG_REGISTER, bind_register_keywords, &bind_kws);

/* parse "tune.quic.socket-owner", accepts "listener" or "connection" */
static int cfg_parse_quic_tune_socket_owner(char **args, int section_type,
                                            struct proxy *curpx,
                                            const struct proxy *defpx,
                                            const char *file, int line, char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "connection") == 0) {
		global.tune.options |= GTUNE_QUIC_SOCK_PER_CONN;
	}
	else if (strcmp(args[1], "listener") == 0) {
		global.tune.options &= ~GTUNE_QUIC_SOCK_PER_CONN;
	}
	else {
		memprintf(err, "'%s' expects either 'listener' or 'connection' but got '%s'.", args[0], args[1]);
		return -1;
	}

	return 0;
}

/* Must be used to parse tune.quic.* setting which requires a time
 * as value.
 * Return -1 on alert, or 0 if succeeded.
 */
static int cfg_parse_quic_time(char **args, int section_type,
                               struct proxy *curpx,
                               const struct proxy *defpx,
                               const char *file, int line, char **err)
{
	unsigned int time;
	const char *res, *name, *value;
	int prefix_len = strlen("tune.quic.");

	if (too_many_args(1, args, err, NULL))
		return -1;

	name = args[0];
	value = args[1];
	res = parse_time_err(value, &time, TIME_UNIT_MS);
	if (res == PARSE_TIME_OVER) {
		memprintf(err, "timer overflow in argument '%s' to '%s' "
		          "(maximum value is 2147483647 ms or ~24.8 days)", value, name);
		return -1;
	}
	else if (res == PARSE_TIME_UNDER) {
		memprintf(err, "timer underflow in argument '%s' to '%s' "
		          "(minimum non-null value is 1 ms)", value, name);
		return -1;
	}
	else if (res) {
		memprintf(err, "unexpected character '%c' in '%s'", *res, name);
		return -1;
	}

	if (strcmp(name + prefix_len, "frontend.max-idle-timeout") == 0)
		global.tune.quic_frontend_max_idle_timeout = time;
	else if (strcmp(name + prefix_len, "backend.max-idle-timeout") == 0)
		global.tune.quic_backend_max_idle_timeout = time;
	else {
		memprintf(err, "'%s' keyword not unhandled (please report this bug).", args[0]);
		return -1;
	}

	return 0;
}

/* Parse any tune.quic.* setting with strictly positive integer values.
 *
 * Returns 0 on success, >0 on warning, <0 on fatal error.
 */
static int cfg_parse_quic_tune_setting(char **args, int section_type,
                                       struct proxy *curpx,
                                       const struct proxy *defpx,
                                       const char *file, int line, char **err)
{
	unsigned int arg = 0;
	int prefix_len = strlen("tune.quic.");
	const char *suffix;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) != 0)
		arg = atoi(args[1]);

	if (arg < 1) {
		memprintf(err, "'%s' expects a positive integer.", args[0]);
		return -1;
	}

	suffix = args[0] + prefix_len;
	if (strcmp(suffix, "cc.cubic.min-losses") == 0)
		global.tune.quic_cubic_loss_tol = arg - 1;
	else if (strcmp(suffix, "frontend.conn-tx-buffers.limit") == 0) {
		memprintf(err, "'%s' keyword is now obsolote and has no effect. "
		               "Use 'tune.quic.frontend.default-max-window-size' to limit Tx buffer allocation per connection.", args[0]);
		return 1;
	}
	else if (strcmp(suffix, "frontend.glitches-threshold") == 0)
		global.tune.quic_frontend_glitches_threshold = arg;
	else if (strcmp(suffix, "frontend.max-streams-bidi") == 0)
		global.tune.quic_frontend_max_streams_bidi = arg;
	else if (strcmp(suffix, "frontend.default-max-window-size") == 0) {
		unsigned long cwnd;
		char *end_opt;

		cwnd = parse_window_size(args[0], args[1], &end_opt, err);
		if (!cwnd)
			return -1;
		if (*end_opt != '\0') {
			memprintf(err, "'%s' : expects an integer value with an optional suffix 'k', 'm' or 'g'", args[0]);
			return -1;
		}

		global.tune.quic_frontend_max_window_size = cwnd;
	}
	else if (strcmp(suffix, "max-frame-loss") == 0)
		global.tune.quic_max_frame_loss = arg;
	else if (strcmp(suffix, "reorder-ratio") == 0) {
		if (arg > 100) {
			memprintf(err, "'%s' expects an integer argument between 0 and 100.", args[0]);
			return -1;
		}

		global.tune.quic_reorder_ratio = arg;
	}
	else if (strcmp(suffix, "retry-threshold") == 0)
		global.tune.quic_retry_threshold = arg;
	else {
		memprintf(err, "'%s' keyword not unhandled (please report this bug).", args[0]);
		return -1;
	}

	return 0;
}

static int cfg_parse_quic_tune_setting0(char **args, int section_type,
                                        struct proxy *curpx,
                                        const struct proxy *defpx,
                                        const char *file, int line, char **err)
{
	int prefix_len = strlen("tune.quic.");
	const char *suffix;

	if (too_many_args(0, args, err, NULL))
		return -1;

	suffix = args[0] + prefix_len;
	if (strcmp(suffix, "disable-tx-pacing") == 0) {
		quic_tune.options |= QUIC_TUNE_NO_PACING;
	}
	else if (strcmp(suffix, "disable-udp-gso") == 0) {
		global.tune.options |= GTUNE_QUIC_NO_UDP_GSO;
	}
	else {
		memprintf(err, "'%s' keyword unhandled (please report this bug).", args[0]);
		return -1;
	}

	return 0;
}

/* config parser for global "tune.quic.* {on|off}" */
static int cfg_parse_quic_tune_on_off(char **args, int section_type, struct proxy *curpx,
                                      const struct proxy *defpx, const char *file, int line,
                                      char **err)
{
	int on;
	int prefix_len = strlen("tune.quic.");
	const char *suffix;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		on = 1;
	else if (strcmp(args[1], "off") == 0)
		on = 0;
	else {
		memprintf(err, "'%s' expects 'on' or 'off'.", args[0]);
		return -1;
	}

	suffix = args[0] + prefix_len;
	if (strcmp(suffix, "zero-copy-fwd-send") == 0 ) {
		if (on)
			global.tune.no_zero_copy_fwd &= ~NO_ZERO_COPY_FWD_QUIC_SND;
		else
			global.tune.no_zero_copy_fwd |= NO_ZERO_COPY_FWD_QUIC_SND;
	}
	else if (strcmp(suffix, "cc-hystart") == 0) {
		if (on)
			global.tune.options |= GTUNE_QUIC_CC_HYSTART;
		else
			global.tune.options &= ~GTUNE_QUIC_CC_HYSTART;
	}

	return 0;
}

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.quic.socket-owner", cfg_parse_quic_tune_socket_owner },
	{ CFG_GLOBAL, "tune.quic.cc-hystart", cfg_parse_quic_tune_on_off },
	{ CFG_GLOBAL, "tune.quic.cc.cubic.min-losses", cfg_parse_quic_tune_setting },
	{ CFG_GLOBAL, "tune.quic.frontend.conn-tx-buffers.limit", cfg_parse_quic_tune_setting },
	{ CFG_GLOBAL, "tune.quic.frontend.glitches-threshold", cfg_parse_quic_tune_setting },
	{ CFG_GLOBAL, "tune.quic.frontend.max-streams-bidi", cfg_parse_quic_tune_setting },
	{ CFG_GLOBAL, "tune.quic.frontend.max-idle-timeout", cfg_parse_quic_time },
	{ CFG_GLOBAL, "tune.quic.frontend.default-max-window-size", cfg_parse_quic_tune_setting },
	{ CFG_GLOBAL, "tune.quic.max-frame-loss", cfg_parse_quic_tune_setting },
	{ CFG_GLOBAL, "tune.quic.reorder-ratio", cfg_parse_quic_tune_setting },
	{ CFG_GLOBAL, "tune.quic.retry-threshold", cfg_parse_quic_tune_setting },
	{ CFG_GLOBAL, "tune.quic.disable-tx-pacing", cfg_parse_quic_tune_setting0 },
	{ CFG_GLOBAL, "tune.quic.disable-udp-gso", cfg_parse_quic_tune_setting0 },
	{ CFG_GLOBAL, "tune.quic.zero-copy-fwd-send", cfg_parse_quic_tune_on_off },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

static int quic_parse_quic_initial(char **args, int section_type, struct proxy *curpx,
                                   const struct proxy *defpx, const char *file, int line,
                                   char **err)
{
	const struct acl *acl;
	struct act_rule *rule;
	struct action_kw *kw;
	const char *acl_kw;
	unsigned int where;
	int warn = 0;
	int arg = 1;

	where = SMP_VAL_FE_CON_ACC;

	if (curpx == defpx && strlen(defpx->id) == 0) {
		memprintf(err, "%s is not allowed in anonymous 'defaults' sections",
			  args[0]);
		return -1;
	}

	if (!(curpx->cap & PR_CAP_FE)) {
		memprintf(err, "'%s' : proxy '%s' has no frontend capability",
		          args[0], curpx->id);
		return -1;
	}

	if (!(curpx->mode & PR_MODE_HTTP)) {
		memprintf(err, "'%s' : proxy '%s' does not used HTTP mode",
		          args[0], curpx->id);
		return -1;
	}

	rule = new_act_rule(0, file, line);
	if (!rule) {
		memprintf(err, "parsing [%s:%d] : out of memory", file, line);
		return -1;
	}

	LIST_INIT(&rule->list);
	rule->from = ACT_F_QUIC_INIT;

	kw = action_quic_init_custom(args[1]);
	if (kw) {
		rule->kw = kw;
		arg++;

		if (kw->parse((const char **)args, &arg, curpx, rule, err) == ACT_RET_PRS_ERR)
			goto err;
	}
	else {
		const char *best = action_suggest(args[1], &quic_init_actions_list.list, NULL);

		action_build_list(&quic_init_actions_list.list, &trash);
		memprintf(err, "'quic-initial' expects %s, but got '%s'%s.%s%s%s",
		          trash.area,
		          args[1], *args[1] ? "" : " (missing argument)",
		          best ? " Did you mean '" : "",
		          best ? best : "",
		          best ? "' maybe ?" : "");
		goto err;
	}

	if (strcmp(args[arg], "if") == 0 || strcmp(args[arg], "unless") == 0) {
		if ((rule->cond = build_acl_cond(file, line, &curpx->acl, curpx, (const char **)args+arg, err)) == NULL) {
			memprintf(err,
			          "'%s %s %s' : error detected in %s '%s' while parsing '%s' condition : %s",
			          args[0], args[1], args[2], proxy_type_str(curpx), curpx->id, args[arg], *err);
			goto err;
		}
	}
	else if (*args[arg]) {
		memprintf(err,
			 "'%s %s %s' only accepts 'if' or 'unless', in %s '%s' (got '%s')",
			 args[0], args[1], args[2], proxy_type_str(curpx), curpx->id, args[arg]);
		goto err;
	}

	acl = rule->cond ? acl_cond_conflicts(rule->cond, where) : NULL;
	if (acl) {
		if (acl->name && *acl->name)
			memprintf(err,
				  "acl '%s' will never match in '%s' because it only involves keywords that are incompatible with '%s'",
				  acl->name, args[0], sample_ckp_names(where));
		else
			memprintf(err,
				  "anonymous acl will never match in '%s' because it uses keyword '%s' which is incompatible with '%s'",
				  args[0],
				  LIST_ELEM(acl->expr.n, struct acl_expr *, list)->kw,
				  sample_ckp_names(where));

		warn++;
	}
	else if (rule->cond && acl_cond_kw_conflicts(rule->cond, where, &acl, &acl_kw)) {
		if (acl->name && *acl->name)
			memprintf(err,
				  "acl '%s' involves keyword '%s' which is incompatible with '%s'",
				  acl->name, acl_kw, sample_ckp_names(where));
		else
			memprintf(err,
				  "anonymous acl involves keyword '%s' which is incompatible with '%s'",
				  acl_kw, sample_ckp_names(where));
		warn++;
	}

	/* the following function directly emits the warning */
	warnif_misplaced_quic_init(curpx, file, line, args[0], NULL);

	LIST_APPEND(&curpx->quic_init_rules, &rule->list);

	return warn;

 err:
	free_act_rule(rule);
	return -1;
}

static struct cfg_kw_list cfg_kws_li = {ILH, {
	{ CFG_LISTEN, "quic-initial",  quic_parse_quic_initial },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws_li);
