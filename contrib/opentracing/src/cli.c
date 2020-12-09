/***
 * Copyright 2020 HAProxy Technologies
 *
 * This file is part of the HAProxy OpenTracing filter.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include "include.h"


/***
 * NAME
 *   flt_ot_cli_set_msg -
 *
 * ARGUMENTS
 *   appctx    -
 *   err       -
 *   msg       -
 *   cli_state -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void cmn_cli_set_msg(struct appctx *appctx, char *err, char *msg, int cli_state)
{
	FLT_OT_FUNC("%p, %p, %p, %d", appctx, err, msg, cli_state);

	if ((appctx == NULL) || ((err == NULL) && (msg == NULL)))
		FLT_OT_RETURN();

	appctx->ctx.cli.err = (err == NULL) ? msg : err;
	appctx->st0         = (appctx->ctx.cli.err == NULL) ? CLI_ST_PROMPT : cli_state;

	FLT_OT_DBG(1, "err(%d): \"%s\"", appctx->st0, appctx->ctx.cli.err);

	FLT_OT_RETURN();
}


#ifdef DEBUG_OT

/***
 * NAME
 *   flt_ot_cli_parse_debug -
 *
 * ARGUMENTS
 *   args    -
 *   payload -
 *   appctx  -
 *   private -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static int flt_ot_cli_parse_debug(char **args, char *payload, struct appctx *appctx, void *private)
{
	char    *err = NULL, *msg = NULL;
	uint8_t  value;
	int      retval = 0;

	FLT_OT_FUNC("%p, \"%s\", %p, %p", args, payload, appctx, private);

	FLT_OT_ARGS_DUMP();

	if (FLT_OT_ARG_ISVALID(2)) {
		value = flt_ot_strtoll(args[2], 0, 255, &err);
		if (err == NULL) {
			_HA_ATOMIC_STORE(&(flt_ot_debug.level), value);

			(void)memprintf(&msg, FLT_OT_CLI_CMD " : debug level set to %hhu", value);
		} else {
			retval = 1;
		}
	} else {
		value = _HA_ATOMIC_LOAD(&(flt_ot_debug.level));

		(void)memprintf(&msg, FLT_OT_CLI_CMD " : current debug level is %hhu", value);
	}

	cmn_cli_set_msg(appctx, err, msg, CLI_ST_PRINT_FREE);

	FLT_OT_RETURN(retval);
}

#endif /* DEBUG_OT */


/***
 * NAME
 *   flt_ot_cli_parse_disabled -
 *
 * ARGUMENTS
 *   args    -
 *   payload -
 *   appctx  -
 *   private -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static int flt_ot_cli_parse_disabled(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *msg = NULL;
	bool  value = (uintptr_t)private;
	int   retval = 0;

	FLT_OT_FUNC("%p, \"%s\", %p, %p", args, payload, appctx, private);

	FLT_OT_ARGS_DUMP();

	FLT_OT_PROXIES_LIST_START() {
		_HA_ATOMIC_STORE(&(conf->tracer->flag_disabled), value);

		(void)memprintf(&msg, "%s%s" FLT_OT_CLI_CMD " : filter %sabled", FLT_OT_CLI_MSG_CAT(msg), value ? "dis" : "en");
	} FLT_OT_PROXIES_LIST_END();

	cmn_cli_set_msg(appctx, NULL, msg, CLI_ST_PRINT_FREE);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_cli_parse_option -
 *
 * ARGUMENTS
 *   args    -
 *   payload -
 *   appctx  -
 *   private -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static int flt_ot_cli_parse_option(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *msg = NULL;
	bool  value = (uintptr_t)private;
	int   retval = 0;

	FLT_OT_FUNC("%p, \"%s\", %p, %p", args, payload, appctx, private);

	FLT_OT_ARGS_DUMP();

	FLT_OT_PROXIES_LIST_START() {
		_HA_ATOMIC_STORE(&(conf->tracer->flag_harderr), value);

		(void)memprintf(&msg, "%s%s" FLT_OT_CLI_CMD " : filter set %s-errors", FLT_OT_CLI_MSG_CAT(msg), value ? "hard" : "soft");
	} FLT_OT_PROXIES_LIST_END();

	cmn_cli_set_msg(appctx, NULL, msg, CLI_ST_PRINT_FREE);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_cli_parse_logging -
 *
 * ARGUMENTS
 *   args    -
 *   payload -
 *   appctx  -
 *   private -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static int flt_ot_cli_parse_logging(char **args, char *payload, struct appctx *appctx, void *private)
{
	char    *err = NULL, *msg = NULL;
	uint8_t  value;
	int      retval = 0;

	FLT_OT_FUNC("%p, \"%s\", %p, %p", args, payload, appctx, private);

	FLT_OT_ARGS_DUMP();

	if (FLT_OT_ARG_ISVALID(2)) {
		if (strcasecmp(args[2], FLT_OT_CLI_LOGGING_OFF) == 0) {
			value = FLT_OT_LOGGING_OFF;
		}
		else if (strcasecmp(args[2], FLT_OT_CLI_LOGGING_ON) == 0) {
			value = FLT_OT_LOGGING_ON;
		}
		else if (strcasecmp(args[2], FLT_OT_CLI_LOGGING_NOLOGNORM) == 0) {
			value = FLT_OT_LOGGING_ON | FLT_OT_LOGGING_NOLOGNORM;
		}
		else {
			(void)memprintf(&err, "'%s' : invalid value, use <" FLT_OT_CLI_LOGGING_OFF " | " FLT_OT_CLI_LOGGING_ON " | " FLT_OT_CLI_LOGGING_NOLOGNORM ">", args[2]);

			retval = 1;
		}

		if (retval == 0) {
			FLT_OT_PROXIES_LIST_START() {
				_HA_ATOMIC_STORE(&(conf->tracer->logging), value);

				(void)memprintf(&msg, "%s%s" FLT_OT_CLI_CMD " : logging is %s", FLT_OT_CLI_MSG_CAT(msg), FLT_OT_CLI_LOGGING_STATE(value));
			} FLT_OT_PROXIES_LIST_END();
		}
	} else {
		FLT_OT_PROXIES_LIST_START() {
			value = _HA_ATOMIC_LOAD(&(conf->tracer->logging));

			(void)memprintf(&msg, "%s%s" FLT_OT_CLI_CMD " : logging is currently %s", FLT_OT_CLI_MSG_CAT(msg), FLT_OT_CLI_LOGGING_STATE(value));
		} FLT_OT_PROXIES_LIST_END();
	}

	cmn_cli_set_msg(appctx, err, msg, CLI_ST_PRINT_FREE);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_cli_parse_rate -
 *
 * ARGUMENTS
 *   args    -
 *   payload -
 *   appctx  -
 *   private -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static int flt_ot_cli_parse_rate(char **args, char *payload, struct appctx *appctx, void *private)
{
	char     *err = NULL, *msg = NULL;
	uint32_t  value;
	int       retval = 0;

	FLT_OT_FUNC("%p, \"%s\", %p, %p", args, payload, appctx, private);

	FLT_OT_ARGS_DUMP();

	if (FLT_OT_ARG_ISVALID(2)) {
		value = FLT_OT_FLOAT_U32(flt_ot_strtod(args[2], 0.0, FLT_OT_RATE_LIMIT_MAX, &err), FLT_OT_RATE_LIMIT_MAX);
		if (err == NULL) {
			FLT_OT_PROXIES_LIST_START() {
				_HA_ATOMIC_STORE(&(conf->tracer->rate_limit), value);

				(void)memprintf(&msg, "%s%s" FLT_OT_CLI_CMD " : rate limit set to %.2f", FLT_OT_CLI_MSG_CAT(msg), FLT_OT_U32_FLOAT(value, FLT_OT_RATE_LIMIT_MAX));
			} FLT_OT_PROXIES_LIST_END();
		} else {
			retval = 1;
		}
	} else {
		FLT_OT_PROXIES_LIST_START() {
			value = _HA_ATOMIC_LOAD(&(conf->tracer->rate_limit));

			(void)memprintf(&msg, "%s%s" FLT_OT_CLI_CMD " : current rate limit is %.2f", FLT_OT_CLI_MSG_CAT(msg), FLT_OT_U32_FLOAT(value, FLT_OT_RATE_LIMIT_MAX));
		} FLT_OT_PROXIES_LIST_END();
	}

	cmn_cli_set_msg(appctx, err, msg, CLI_ST_PRINT_FREE);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_cli_parse_status -
 *
 * ARGUMENTS
 *   args    -
 *   payload -
 *   appctx  -
 *   private -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static int flt_ot_cli_parse_status(char **args, char *payload, struct appctx *appctx, void *private)
{
	const char *nl = "";
	char       *msg = NULL;
	int         retval = 0;

	FLT_OT_FUNC("%p, \"%s\", %p, %p", args, payload, appctx, private);

	FLT_OT_ARGS_DUMP();
	flt_ot_filters_dump();

	(void)memprintf(&msg, " " FLT_OT_OPT_NAME " filter status\n" FLT_OT_STR_DASH_78);
#ifdef DEBUG_OT
	(void)memprintf(&msg, "%s\n   debug level: 0x%02hhx\n", msg, flt_ot_debug.level);
#endif

	FLT_OT_PROXIES_LIST_START() {
		(void)memprintf(&msg, "%s\n%s   filter %s\n", msg, nl, conf->id);
		(void)memprintf(&msg, "%s     configuration: %s\n", msg, conf->cfg_file);
		(void)memprintf(&msg, "%s     disable count: %" PRIu64 " %" PRIu64 "\n\n", msg, conf->cnt.disabled[0], conf->cnt.disabled[1]);
		(void)memprintf(&msg, "%s     tracer %s\n", msg, conf->tracer->id);
		(void)memprintf(&msg, "%s       configuration: %s\n", msg, conf->tracer->config);
		(void)memprintf(&msg, "%s       plugin:        %s\n", msg, conf->tracer->plugin);
		(void)memprintf(&msg, "%s       rate limit:    %.2f %%\n", msg, FLT_OT_U32_FLOAT(conf->tracer->rate_limit, FLT_OT_RATE_LIMIT_MAX));
		(void)memprintf(&msg, "%s       hard errors:   %s\n", msg, FLT_OT_STR_FLAG_YN(conf->tracer->flag_harderr));
		(void)memprintf(&msg, "%s       disabled:      %s\n", msg, FLT_OT_STR_FLAG_YN(conf->tracer->flag_disabled));
		(void)memprintf(&msg, "%s       logging:       %s\n", msg, FLT_OT_CLI_LOGGING_STATE(conf->tracer->logging));
		(void)memprintf(&msg, "%s       analyzers:     %08x", msg, conf->tracer->analyzers);

		nl = "\n";
	} FLT_OT_PROXIES_LIST_END();

	cmn_cli_set_msg(appctx, NULL, msg, CLI_ST_PRINT_FREE);

	FLT_OT_RETURN(retval);
}


static struct cli_kw_list cli_kws = { { }, {
#ifdef DEBUG_OT
	{ { FLT_OT_CLI_CMD, "debug", NULL }, FLT_OT_CLI_CMD " debug [level]   : set the OT filter debug level (default: get current debug level)", flt_ot_cli_parse_debug, NULL, NULL, NULL, 0 },
#endif
	{ { FLT_OT_CLI_CMD, "disable", NULL }, FLT_OT_CLI_CMD " disable         : disable the OT filter", flt_ot_cli_parse_disabled, NULL, NULL, (void *)1, 0 },
	{ { FLT_OT_CLI_CMD, "enable", NULL }, FLT_OT_CLI_CMD " enable          : enable the OT filter", flt_ot_cli_parse_disabled, NULL, NULL, (void *)0, 0 },
	{ { FLT_OT_CLI_CMD, "soft-errors", NULL }, FLT_OT_CLI_CMD " soft-errors     : turning off hard-errors mode", flt_ot_cli_parse_option, NULL, NULL, (void *)0, 0 },
	{ { FLT_OT_CLI_CMD, "hard-errors", NULL }, FLT_OT_CLI_CMD " hard-errors     : enabling hard-errors mode", flt_ot_cli_parse_option, NULL, NULL, (void *)1, 0 },
	{ { FLT_OT_CLI_CMD, "logging",  NULL }, FLT_OT_CLI_CMD " logging [state] : set logging state (default: get current logging state)", flt_ot_cli_parse_logging, NULL, NULL, NULL, 0 },
	{ { FLT_OT_CLI_CMD, "rate", NULL }, FLT_OT_CLI_CMD " rate [value]    : set the rate limit (default: get current rate value)", flt_ot_cli_parse_rate, NULL, NULL, NULL, 0 },
	{ { FLT_OT_CLI_CMD, "status", NULL }, FLT_OT_CLI_CMD " status          : show the OT filter status", flt_ot_cli_parse_status, NULL, NULL, NULL, 0 },
	{ /* END */ }
}};


/***
 * NAME
 *   flt_ot_cli_init -
 *
 * ARGUMENTS
 *   This function takes no arguments.
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_cli_init(void)
{
	FLT_OT_FUNC("");

	/* Register CLI keywords. */
	cli_register_kw(&cli_kws);

	FLT_OT_RETURN();
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
