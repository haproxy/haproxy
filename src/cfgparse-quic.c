#include <string.h>

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/listener.h>
#include <haproxy/proxy-t.h>
#include <haproxy/quic_cc-t.h>
#include <haproxy/tools.h>

static int bind_parse_quic_force_retry(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->options |= BC_O_QUIC_FORCE_RETRY;
	return 0;
}

/* parse "quic-cc-algo" bind keyword */
static int bind_parse_quic_cc_algo(char **args, int cur_arg, struct proxy *px,
                                   struct bind_conf *conf, char **err)
{
	struct quic_cc_algo *cc_algo;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing control congestion algorithm", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(args[cur_arg + 1], "newreno") == 0)
	    cc_algo = &quic_cc_algo_nr;
	else if (strcmp(args[cur_arg + 1], "cubic") == 0)
	    cc_algo = &quic_cc_algo_cubic;
	else {
		memprintf(err, "'%s' : unknown control congestion algorithm", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	conf->quic_cc_algo = cc_algo;
	return 0;
}

static struct bind_kw_list bind_kws = { "QUIC", { }, {
	{ "quic-force-retry", bind_parse_quic_force_retry, 0 },
	{ "quic-cc-algo", bind_parse_quic_cc_algo, 1 },
	{ NULL, NULL, 0 },
}};

INITCALL1(STG_REGISTER, bind_register_keywords, &bind_kws);

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
 * Return -1 on alert, or 0 if succeeded.
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
	if (strcmp(suffix, "frontend.conn-tx-buffers.limit") == 0)
		global.tune.quic_streams_buf = arg;
	else if (strcmp(suffix, "frontend.max-streams-bidi") == 0)
		global.tune.quic_frontend_max_streams_bidi = arg;
	else if (strcmp(suffix, "retry-threshold") == 0)
		global.tune.quic_retry_threshold = arg;
	else {
		memprintf(err, "'%s' keyword not unhandled (please report this bug).", args[0]);
		return -1;
	}

	return 0;
}

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.quic.backend.max-idle-timeou", cfg_parse_quic_time },
	{ CFG_GLOBAL, "tune.quic.frontend.conn-tx-buffers.limit", cfg_parse_quic_tune_setting },
	{ CFG_GLOBAL, "tune.quic.frontend.max-streams-bidi", cfg_parse_quic_tune_setting },
	{ CFG_GLOBAL, "tune.quic.frontend.max-idle-timeout", cfg_parse_quic_time },
	{ CFG_GLOBAL, "tune.quic.retry-threshold", cfg_parse_quic_tune_setting },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
