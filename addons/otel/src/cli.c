/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../include/include.h"


/***
 * NAME
 *   flt_otel_cli_set_msg - CLI response message setter
 *
 * SYNOPSIS
 *   static int flt_otel_cli_set_msg(struct appctx *appctx, char *err, char *msg)
 *
 * ARGUMENTS
 *   appctx - CLI application context
 *   err    - error message string (or NULL)
 *   msg    - informational message string (or NULL)
 *
 * DESCRIPTION
 *   Sets the CLI response message and state for the given <appctx>.  If <err>
 *   is non-NULL, it is passed to cli_dynerr() and <msg> is freed; otherwise
 *   <msg> is passed to cli_dynmsg() at LOG_INFO severity.  When neither message
 *   is available, the function returns 0 without changing state.
 *
 * RETURN VALUE
 *   Returns 1 when a message was set, or 0 when both pointers were NULL.
 */
static int flt_otel_cli_set_msg(struct appctx *appctx, char *err, char *msg)
{
	OTELC_FUNC("%p, %p, %p", appctx, err, msg);

	if ((appctx == NULL) || ((err == NULL) && (msg == NULL)))
		OTELC_RETURN_INT(0);

	if (err != NULL) {
		OTELC_DBG(INFO, "err(%d): \"%s\"", appctx->st0, err);

		OTELC_SFREE(msg);
		OTELC_RETURN_INT(cli_dynerr(appctx, err));
	}

	OTELC_DBG(INFO, "msg(%d): \"%s\"", appctx->st0, msg);

	OTELC_RETURN_INT(cli_dynmsg(appctx, LOG_INFO, msg));
}


#ifdef DEBUG_OTEL

/***
 * NAME
 *   flt_otel_cli_parse_debug - CLI debug level handler
 *
 * SYNOPSIS
 *   static int flt_otel_cli_parse_debug(char **args, char *payload, struct appctx *appctx, void *private)
 *
 * ARGUMENTS
 *   args    - CLI command arguments array
 *   payload - CLI command payload string
 *   appctx  - CLI application context
 *   private - unused private data pointer
 *
 * DESCRIPTION
 *   Handles the "otel debug [level]" CLI command.  When a level argument is
 *   provided in <args[2]>, parses it as an integer in the range
 *   [0, OTELC_DBG_LEVEL_MASK] and atomically stores it as the global debug
 *   level.  Setting a level requires admin access level.  When no argument is
 *   given, reports the current debug level.  The response message includes the
 *   debug level in both decimal and hexadecimal format.
 *
 * RETURN VALUE
 *   Returns 1, or 0 on memory allocation failure.
 */
static int flt_otel_cli_parse_debug(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *err = NULL, *msg = NULL;

	OTELC_FUNC("%p, \"%s\", %p, %p", args, OTELC_STR_ARG(payload), appctx, private);

	FLT_OTEL_ARGS_DUMP();

	if (FLT_OTEL_ARG_ISVALID(2)) {
		int64_t value;

		if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
			OTELC_RETURN_INT(1);

		if (flt_otel_strtoll(args[2], &value, 0, OTELC_DBG_LEVEL_MASK, &err)) {
			_HA_ATOMIC_STORE(&otelc_dbg_level, (int)value);

			(void)memprintf(&msg, FLT_OTEL_CLI_CMD " : debug level set to %d (0x%04x)", (int)value, (int)value);
		}
	} else {
		int value = _HA_ATOMIC_LOAD(&otelc_dbg_level);

		(void)memprintf(&msg, FLT_OTEL_CLI_CMD " : current debug level is %d (0x%04x)", value, value);
	}

	OTELC_RETURN_INT(flt_otel_cli_set_msg(appctx, err, msg));
}

#endif /* DEBUG_OTEL */


/***
 * NAME
 *   flt_otel_cli_parse_disabled - CLI enable/disable handler
 *
 * SYNOPSIS
 *   static int flt_otel_cli_parse_disabled(char **args, char *payload, struct appctx *appctx, void *private)
 *
 * ARGUMENTS
 *   args    - CLI command arguments array
 *   payload - CLI command payload string
 *   appctx  - CLI application context
 *   private - boolean flag cast to pointer (1 = disable, 0 = enable)
 *
 * DESCRIPTION
 *   Handles the "otel enable" and "otel disable" CLI commands.  The <private>
 *   parameter determines the action: a value of 1 disables the filter, 0
 *   enables it.  Requires admin access level.  The flag_disabled field is
 *   atomically updated for all OTel filter instances across all proxies.
 *
 * RETURN VALUE
 *   Returns 1, or 0 if no OTel filter instances are configured or on memory
 *   allocation failure.
 */
static int flt_otel_cli_parse_disabled(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *msg = NULL;
	bool  value = (uintptr_t)private;

	OTELC_FUNC("%p, \"%s\", %p, %p", args, OTELC_STR_ARG(payload), appctx, private);

	FLT_OTEL_ARGS_DUMP();

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		OTELC_RETURN_INT(1);

	FLT_OTEL_PROXIES_LIST_START() {
		_HA_ATOMIC_STORE(&(conf->instr->flag_disabled), value);

		(void)memprintf(&msg, "%s%s" FLT_OTEL_CLI_CMD " : filter %sabled", FLT_OTEL_CLI_MSG_CAT(msg), value ? "dis" : "en");
	} FLT_OTEL_PROXIES_LIST_END();

	OTELC_RETURN_INT(flt_otel_cli_set_msg(appctx, NULL, msg));
}


/***
 * NAME
 *   flt_otel_cli_parse_option - CLI error mode handler
 *
 * SYNOPSIS
 *   static int flt_otel_cli_parse_option(char **args, char *payload, struct appctx *appctx, void *private)
 *
 * ARGUMENTS
 *   args    - CLI command arguments array
 *   payload - CLI command payload string
 *   appctx  - CLI application context
 *   private - boolean flag cast to pointer (1 = hard-errors, 0 = soft-errors)
 *
 * DESCRIPTION
 *   Handles the "otel hard-errors" and "otel soft-errors" CLI commands.  The
 *   <private> parameter determines the error mode: a value of 1 enables
 *   hard-error mode (filter failure aborts the stream), 0 enables soft-error
 *   mode (failures are silently ignored).  Requires admin access level.  The
 *   flag_harderr field is atomically updated for all OTel filter instances
 *   across all proxies.
 *
 * RETURN VALUE
 *   Returns 1, or 0 if no OTel filter instances are configured or on memory
 *   allocation failure.
 */
static int flt_otel_cli_parse_option(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *msg = NULL;
	bool  value = (uintptr_t)private;

	OTELC_FUNC("%p, \"%s\", %p, %p", args, OTELC_STR_ARG(payload), appctx, private);

	FLT_OTEL_ARGS_DUMP();

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		OTELC_RETURN_INT(1);

	FLT_OTEL_PROXIES_LIST_START() {
		_HA_ATOMIC_STORE(&(conf->instr->flag_harderr), value);

		(void)memprintf(&msg, "%s%s" FLT_OTEL_CLI_CMD " : filter set %s-errors", FLT_OTEL_CLI_MSG_CAT(msg), value ? "hard" : "soft");
	} FLT_OTEL_PROXIES_LIST_END();

	OTELC_RETURN_INT(flt_otel_cli_set_msg(appctx, NULL, msg));
}


/***
 * NAME
 *   flt_otel_cli_parse_logging - CLI logging state handler
 *
 * SYNOPSIS
 *   static int flt_otel_cli_parse_logging(char **args, char *payload, struct appctx *appctx, void *private)
 *
 * ARGUMENTS
 *   args    - CLI command arguments array
 *   payload - CLI command payload string
 *   appctx  - CLI application context
 *   private - unused private data pointer
 *
 * DESCRIPTION
 *   Handles the "otel logging [state]" CLI command.  When a state argument is
 *   provided in <args[2]>, it is matched against "off", "on", or "nolognorm"
 *   and the logging field is atomically updated for all OTel filter instances.
 *   Setting a value requires admin access level.  When no argument is given,
 *   reports the current logging state for all instances.  Invalid values
 *   produce an error with the accepted options listed.
 *
 * RETURN VALUE
 *   Returns 1, or 0 if no OTel filter instances are configured (and no error
 *   occurred) or on memory allocation failure.
 */
static int flt_otel_cli_parse_logging(char **args, char *payload, struct appctx *appctx, void *private)
{
	char    *err = NULL, *msg = NULL;
	bool     flag_set = false;
	uint8_t  value;

	OTELC_FUNC("%p, \"%s\", %p, %p", args, OTELC_STR_ARG(payload), appctx, private);

	FLT_OTEL_ARGS_DUMP();

	if (FLT_OTEL_ARG_ISVALID(2)) {
		if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
			OTELC_RETURN_INT(1);

		if (strcasecmp(args[2], FLT_OTEL_CLI_LOGGING_OFF) == 0) {
			flag_set = true;
			value    = FLT_OTEL_LOGGING_OFF;
		}
		else if (strcasecmp(args[2], FLT_OTEL_CLI_LOGGING_ON) == 0) {
			flag_set = true;
			value    = FLT_OTEL_LOGGING_ON;
		}
		else if (strcasecmp(args[2], FLT_OTEL_CLI_LOGGING_NOLOGNORM) == 0) {
			flag_set = true;
			value    = FLT_OTEL_LOGGING_ON | FLT_OTEL_LOGGING_NOLOGNORM;
		}
		else {
			(void)memprintf(&err, "'%s' : invalid value, use <" FLT_OTEL_CLI_LOGGING_OFF " | " FLT_OTEL_CLI_LOGGING_ON " | " FLT_OTEL_CLI_LOGGING_NOLOGNORM ">", args[2]);
		}

		if (flag_set) {
			FLT_OTEL_PROXIES_LIST_START() {
				_HA_ATOMIC_STORE(&(conf->instr->logging), value);

				(void)memprintf(&msg, "%s%s" FLT_OTEL_CLI_CMD " : logging is %s", FLT_OTEL_CLI_MSG_CAT(msg), FLT_OTEL_CLI_LOGGING_STATE(value));
			} FLT_OTEL_PROXIES_LIST_END();
		}
	} else {
		FLT_OTEL_PROXIES_LIST_START() {
			value = _HA_ATOMIC_LOAD(&(conf->instr->logging));

			(void)memprintf(&msg, "%s%s" FLT_OTEL_CLI_CMD " : logging is currently %s", FLT_OTEL_CLI_MSG_CAT(msg), FLT_OTEL_CLI_LOGGING_STATE(value));
		} FLT_OTEL_PROXIES_LIST_END();
	}

	OTELC_RETURN_INT(flt_otel_cli_set_msg(appctx, err, msg));
}


/***
 * NAME
 *   flt_otel_cli_parse_rate - CLI rate limit handler
 *
 * SYNOPSIS
 *   static int flt_otel_cli_parse_rate(char **args, char *payload, struct appctx *appctx, void *private)
 *
 * ARGUMENTS
 *   args    - CLI command arguments array
 *   payload - CLI command payload string
 *   appctx  - CLI application context
 *   private - unused private data pointer
 *
 * DESCRIPTION
 *   Handles the "otel rate [value]" CLI command.  When a value argument is
 *   provided in <args[2]>, it is parsed as a floating-point number in the
 *   range [0.0, 100.0], converted to a fixed-point uint32_t representation,
 *   and atomically stored as the rate limit for all OTel filter instances.
 *   Setting a value requires admin access level.  When no argument is given,
 *   reports the current rate limit percentage for all instances.
 *
 * RETURN VALUE
 *   Returns 1, or 0 if no OTel filter instances are configured (and no error
 *   occurred) or on memory allocation failure.
 */
static int flt_otel_cli_parse_rate(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *err = NULL, *msg = NULL;

	OTELC_FUNC("%p, \"%s\", %p, %p", args, OTELC_STR_ARG(payload), appctx, private);

	FLT_OTEL_ARGS_DUMP();

	if (FLT_OTEL_ARG_ISVALID(2)) {
		double value;

		if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
			OTELC_RETURN_INT(1);

		if (flt_otel_strtod(args[2], &value, 0.0, 100.0, &err)) {
			FLT_OTEL_PROXIES_LIST_START() {
				_HA_ATOMIC_STORE(&(conf->instr->rate_limit), FLT_OTEL_FLOAT_U32(value));

				(void)memprintf(&msg, "%s%s" FLT_OTEL_CLI_CMD " : rate limit set to %.2f", FLT_OTEL_CLI_MSG_CAT(msg), value);
			} FLT_OTEL_PROXIES_LIST_END();
		}
	} else {
		FLT_OTEL_PROXIES_LIST_START() {
			uint32_t value = _HA_ATOMIC_LOAD(&(conf->instr->rate_limit));

			(void)memprintf(&msg, "%s%s" FLT_OTEL_CLI_CMD " : current rate limit is %.2f", FLT_OTEL_CLI_MSG_CAT(msg), FLT_OTEL_U32_FLOAT(value));
		} FLT_OTEL_PROXIES_LIST_END();
	}

	OTELC_RETURN_INT(flt_otel_cli_set_msg(appctx, err, msg));
}


/***
 * NAME
 *   flt_otel_cli_parse_status - CLI status display handler
 *
 * SYNOPSIS
 *   static int flt_otel_cli_parse_status(char **args, char *payload, struct appctx *appctx, void *private)
 *
 * ARGUMENTS
 *   args    - CLI command arguments array
 *   payload - CLI command payload string
 *   appctx  - CLI application context
 *   private - unused private data pointer
 *
 * DESCRIPTION
 *   Handles the "otel status" CLI command.  Builds a formatted status report
 *   for all OTel filter instances across all proxies.  The report includes
 *   the library version, proxy name, configuration file path, group and scope
 *   counts, disable counts, instrumentation ID, tracer state, rate limit, error
 *   mode, disabled state, logging state, and analyzer bits.  When DEBUG_OTEL is
 *   enabled, the current debug level is also included.
 *
 * RETURN VALUE
 *   Returns 1, or 0 on memory allocation failure.
 */
static int flt_otel_cli_parse_status(char **args, char *payload, struct appctx *appctx, void *private)
{
	const char *nl = "";
	char       *msg = NULL;

	OTELC_FUNC("%p, \"%s\", %p, %p", args, OTELC_STR_ARG(payload), appctx, private);

	FLT_OTEL_ARGS_DUMP();
	flt_otel_filters_dump();

	(void)memprintf(&msg, " " FLT_OTEL_OPT_NAME " filter status\n" FLT_OTEL_STR_DASH_78 "\n");
	(void)memprintf(&msg, "%s   library:       C++ " OTELCPP_VERSION ", C wrapper %s\n", msg, otelc_version());
#ifdef DEBUG_OTEL
	(void)memprintf(&msg, "%s   debug level:   0x%02hhx\n", msg, otelc_dbg_level);
#endif
	(void)memprintf(&msg, "%s   dropped count: %" PRId64 "/%" PRId64 " %" PRIu64 "\n", msg, otelc_processor_dropped_count(0), otelc_processor_dropped_count(1), _HA_ATOMIC_LOAD(&flt_otel_drop_cnt));

	FLT_OTEL_PROXIES_LIST_START() {
		struct flt_otel_conf_group *grp;
		struct flt_otel_conf_scope *scp;
		int                         n_groups = 0, n_scopes = 0;

		list_for_each_entry(grp, &(conf->groups), list)
			n_groups++;
		list_for_each_entry(scp, &(conf->scopes), list)
			n_scopes++;

		(void)memprintf(&msg, "%s\n%s   proxy %s, filter %s\n", msg, nl, px->id, conf->id);
		(void)memprintf(&msg, "%s     configuration: %s\n", msg, conf->cfg_file);
		(void)memprintf(&msg, "%s     groups/scopes: %d/%d\n\n", msg, n_groups, n_scopes);
		(void)memprintf(&msg, "%s       instrumentation %s\n", msg, conf->instr->id);
		(void)memprintf(&msg, "%s       configuration: %s\n", msg, conf->instr->config);
		(void)memprintf(&msg, "%s       tracer:        %s\n", msg, (conf->instr->tracer != NULL) ? "active" : "not initialized");
		(void)memprintf(&msg, "%s       rate limit:    %.2f %%\n", msg, FLT_OTEL_U32_FLOAT(_HA_ATOMIC_LOAD(&(conf->instr->rate_limit))));
		(void)memprintf(&msg, "%s       hard errors:   %s\n", msg, FLT_OTEL_STR_FLAG_YN(_HA_ATOMIC_LOAD(&(conf->instr->flag_harderr))));
		(void)memprintf(&msg, "%s       disabled:      %s\n", msg, FLT_OTEL_STR_FLAG_YN(_HA_ATOMIC_LOAD(&(conf->instr->flag_disabled))));
		(void)memprintf(&msg, "%s       logging:       %s\n", msg, FLT_OTEL_CLI_LOGGING_STATE(_HA_ATOMIC_LOAD(&(conf->instr->logging))));
		(void)memprintf(&msg, "%s       analyzers:     %08x", msg, conf->instr->analyzers);
#ifdef FLT_OTEL_USE_COUNTERS
		(void)memprintf(&msg, "%s\n\n     counters\n", msg);
		(void)memprintf(&msg, "%s       attached: %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n", msg, conf->cnt.attached[0], conf->cnt.attached[1], conf->cnt.attached[2], conf->cnt.attached[3]);
		(void)memprintf(&msg, "%s       disabled: %" PRIu64 " %" PRIu64, msg, conf->cnt.disabled[0], conf->cnt.disabled[1]);
#endif

		nl = "\n";
	} FLT_OTEL_PROXIES_LIST_END();

	OTELC_RETURN_INT(flt_otel_cli_set_msg(appctx, NULL, msg));
}


/* CLI command table for the OTel filter. */
static struct cli_kw_list cli_kws = { { }, {
#ifdef DEBUG_OTEL
	{ { FLT_OTEL_CLI_CMD, "debug", NULL }, FLT_OTEL_CLI_CMD " debug [level]                  : set the OTEL filter debug level (default: get current debug level)", flt_otel_cli_parse_debug, NULL, NULL, NULL, ACCESS_LVL_ADMIN },
#endif
	{ { FLT_OTEL_CLI_CMD, "disable", NULL }, FLT_OTEL_CLI_CMD " disable                        : disable the OTEL filter", flt_otel_cli_parse_disabled, NULL, NULL, (void *)1, ACCESS_LVL_ADMIN },
	{ { FLT_OTEL_CLI_CMD, "enable", NULL }, FLT_OTEL_CLI_CMD " enable                         : enable the OTEL filter", flt_otel_cli_parse_disabled, NULL, NULL, (void *)0, ACCESS_LVL_ADMIN },
	{ { FLT_OTEL_CLI_CMD, "soft-errors", NULL }, FLT_OTEL_CLI_CMD " soft-errors                    : disable hard-errors mode", flt_otel_cli_parse_option, NULL, NULL, (void *)0, ACCESS_LVL_ADMIN },
	{ { FLT_OTEL_CLI_CMD, "hard-errors", NULL }, FLT_OTEL_CLI_CMD " hard-errors                    : enable hard-errors mode", flt_otel_cli_parse_option, NULL, NULL, (void *)1, ACCESS_LVL_ADMIN },
	{ { FLT_OTEL_CLI_CMD, "logging",  NULL }, FLT_OTEL_CLI_CMD " logging [state]                : set logging state (default: get current logging state)", flt_otel_cli_parse_logging, NULL, NULL, NULL, ACCESS_LVL_ADMIN },
	{ { FLT_OTEL_CLI_CMD, "rate", NULL }, FLT_OTEL_CLI_CMD " rate [value]                   : set the rate limit (default: get current rate value)", flt_otel_cli_parse_rate, NULL, NULL, NULL, ACCESS_LVL_ADMIN },
	{ { FLT_OTEL_CLI_CMD, "status", NULL }, FLT_OTEL_CLI_CMD " status                         : show the OTEL filter status", flt_otel_cli_parse_status, NULL, NULL, NULL, 0 },
	{ /* END */ }
}};


/***
 * NAME
 *   flt_otel_cli_init - CLI keyword registration
 *
 * SYNOPSIS
 *   void flt_otel_cli_init(void)
 *
 * ARGUMENTS
 *   This function takes no arguments.
 *
 * DESCRIPTION
 *   Registers the OTel filter CLI keywords with the HAProxy CLI subsystem.
 *   The keywords include commands for enable/disable, error mode, logging,
 *   rate limit, status display, and (when DEBUG_OTEL is defined) debug level
 *   management.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_cli_init(void)
{
	OTELC_FUNC("");

	/* Register CLI keywords. */
	cli_register_kw(&cli_kws);

	OTELC_RETURN();
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
