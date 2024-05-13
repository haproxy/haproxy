#include <errno.h>
#include <string.h>

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/listener.h>
#include <haproxy/proxy-t.h>
#include <haproxy/quic_cc-t.h>
#include <haproxy/tools.h>

#define QUIC_CC_NEWRENO_STR "newreno"
#define QUIC_CC_CUBIC_STR   "cubic"
#define QUIC_CC_NO_CC_STR   "nocc"

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
	const char *algo = NULL;
	char *arg;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing control congestion algorithm", args[cur_arg]);
		goto fail;
	}

	arg = args[cur_arg + 1];
	if (strncmp(arg, QUIC_CC_NEWRENO_STR, strlen(QUIC_CC_NEWRENO_STR)) == 0) {
		/* newreno */
		algo = QUIC_CC_NEWRENO_STR;
		cc_algo = &quic_cc_algo_nr;
		arg += strlen(QUIC_CC_NEWRENO_STR);
	}
	else if (strncmp(arg, QUIC_CC_CUBIC_STR, strlen(QUIC_CC_CUBIC_STR)) == 0) {
		/* cubic */
		algo = QUIC_CC_CUBIC_STR;
		cc_algo = &quic_cc_algo_cubic;
		arg += strlen(QUIC_CC_CUBIC_STR);
	}
	else if (strncmp(arg, QUIC_CC_NO_CC_STR, strlen(QUIC_CC_NO_CC_STR)) == 0) {
		/* nocc */
		if (!experimental_directives_allowed) {
			ha_alert("'%s' algo is experimental, must be allowed via a global "
			         "'expose-experimental-directives'\n", arg);
			goto fail;
		}

		algo = QUIC_CC_NO_CC_STR;
		cc_algo = &quic_cc_algo_nocc;
		arg += strlen(QUIC_CC_NO_CC_STR);
	}
	else {
		memprintf(err, "'%s' : unknown control congestion algorithm", args[cur_arg + 1]);
		goto fail;
	}

	if (*arg++ == '(') {
		unsigned long cwnd;
		char *end_opt;

		errno = 0;
		cwnd = strtoul(arg, &end_opt, 0);
		if (end_opt == arg || errno != 0) {
			memprintf(err, "'%s' : could not parse congestion window value", args[cur_arg + 1]);
			goto fail;
		}

		if (*end_opt == 'k') {
			cwnd <<= 10;
			end_opt++;
		}
		else if (*end_opt == 'm') {
			cwnd <<= 20;
			end_opt++;
		}
		else if (*end_opt == 'g') {
			cwnd <<= 30;
			end_opt++;
		}

		if (*end_opt != ')') {
			memprintf(err, "'%s' : expects %s(<max window>)", args[cur_arg + 1], algo);
			goto fail;
		}

		if (cwnd < 10240 || cwnd > (4UL << 30)) {
			memprintf(err, "'%s' : should be greater than 10k and smaller than 4g", args[cur_arg + 1]);
			goto fail;
		}

		conf->max_cwnd = cwnd;
	}

	conf->quic_cc_algo = cc_algo;
	return 0;

 fail:
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
	else if (strcmp(suffix, "frontend.glitches-threshold") == 0)
		global.tune.quic_frontend_glitches_threshold = arg;
	else if (strcmp(suffix, "frontend.max-streams-bidi") == 0)
		global.tune.quic_frontend_max_streams_bidi = arg;
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
	{ CFG_GLOBAL, "tune.quic.backend.max-idle-timeou", cfg_parse_quic_time },
	{ CFG_GLOBAL, "tune.quic.cc-hystart", cfg_parse_quic_tune_on_off },
	{ CFG_GLOBAL, "tune.quic.frontend.conn-tx-buffers.limit", cfg_parse_quic_tune_setting },
	{ CFG_GLOBAL, "tune.quic.frontend.glitches-threshold", cfg_parse_quic_tune_setting },
	{ CFG_GLOBAL, "tune.quic.frontend.max-streams-bidi", cfg_parse_quic_tune_setting },
	{ CFG_GLOBAL, "tune.quic.frontend.max-idle-timeout", cfg_parse_quic_time },
	{ CFG_GLOBAL, "tune.quic.max-frame-loss", cfg_parse_quic_tune_setting },
	{ CFG_GLOBAL, "tune.quic.reorder-ratio", cfg_parse_quic_tune_setting },
	{ CFG_GLOBAL, "tune.quic.retry-threshold", cfg_parse_quic_tune_setting },
	{ CFG_GLOBAL, "tune.quic.zero-copy-fwd-send", cfg_parse_quic_tune_on_off },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
