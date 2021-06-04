#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#include <haproxy/api.h>
#include <haproxy/applet-t.h>
#include <haproxy/cli.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/ring.h>
#include <haproxy/tools.h>
#include <haproxy/version.h>

/* A global buffer used to store all startup alerts/warnings. It will then be
 * retrieve on the CLI. */
static struct ring *startup_logs = NULL;

/* Generic function to display messages prefixed by a label */
static void print_message(const char *label, const char *fmt, va_list argp)
{
	char *head, *msg;
	char prefix[11]; // '[' + 8 chars + ']' + 0.

	*prefix = '[';
	strncpy(prefix + 1, label, sizeof(prefix) - 2);
	msg = prefix + strlen(prefix);
	*msg++ = ']';
	while (msg < prefix + sizeof(prefix) - 1)
		*msg++ = ' ';
	*msg = 0;

	head = msg = NULL;
	memprintf(&head, "%s (%u) : ", prefix, (uint)getpid());
	memvprintf(&msg, fmt, argp);

	if (global.mode & MODE_STARTING) {
		if (unlikely(!startup_logs))
			startup_logs = ring_new(STARTUP_LOG_SIZE);

		if (likely(startup_logs)) {
			struct ist m[2];

			m[0] = ist(head);
			m[1] = ist(msg);
			/* trim the trailing '\n' */
			if (m[1].len > 0 && m[1].ptr[m[1].len - 1] == '\n')
				m[1].len--;
			ring_write(startup_logs, ~0, 0, 0, m, 2);
		}
	}

	fprintf(stderr, "%s%s", head, msg);
	fflush(stderr);

	free(head);
	free(msg);
}

/*
 * Displays the message on stderr with the date and pid. Overrides the quiet
 * mode during startup.
 */
void ha_alert(const char *fmt, ...)
{
	va_list argp;

	if (!(global.mode & MODE_QUIET) || (global.mode & (MODE_VERBOSE | MODE_STARTING))) {
		if (!(warned & WARN_EXEC_PATH)) {
			const char *path = get_exec_path();

			warned |= WARN_EXEC_PATH;
			ha_notice("haproxy version is %s\n", haproxy_version);
			if (path)
				ha_notice("path to executable is %s\n", path);
		}
		va_start(argp, fmt);
		print_message("ALERT", fmt, argp);
		va_end(argp);
	}
}

/*
 * Displays the message on stderr with the date and pid.
 */
void ha_warning(const char *fmt, ...)
{
	va_list argp;

	warned |= WARN_ANY;

	if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) {
		va_start(argp, fmt);
		print_message("WARNING", fmt, argp);
		va_end(argp);
	}
}

/*
 * Variant of _ha_diag_warning with va_list.
 * Use it only if MODE_DIAG has been previously checked.
 */
void _ha_vdiag_warning(const char *fmt, va_list argp)
{
	print_message("DIAG", fmt, argp);
}

/*
 * Output a diagnostic warning.
 * Use it only if MODE_DIAG has been previously checked.
 */
void _ha_diag_warning(const char *fmt, ...)
{
	va_list argp;

	va_start(argp, fmt);
	_ha_vdiag_warning(fmt, argp);
	va_end(argp);
}

/*
 * Output a diagnostic warning. Do nothing of MODE_DIAG is not on.
 */
void ha_diag_warning(const char *fmt, ...)
{
	va_list argp;

	if (global.mode & MODE_DIAG) {
		va_start(argp, fmt);
		_ha_vdiag_warning(fmt, argp);
		va_end(argp);
	}
}

/*
 * Displays the message on stderr with the date and pid.
 */
void ha_notice(const char *fmt, ...)
{
	va_list argp;

	if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) {
		va_start(argp, fmt);
		print_message("NOTICE", fmt, argp);
		va_end(argp);
	}
}

/*
 * Displays the message on <out> only if quiet mode is not set.
 */
void qfprintf(FILE *out, const char *fmt, ...)
{
	va_list argp;

	if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) {
		va_start(argp, fmt);
		vfprintf(out, fmt, argp);
		fflush(out);
		va_end(argp);
	}
}


/* parse the "show startup-logs" command, returns 1 if a message is returned, otherwise zero */
static int cli_parse_show_startup_logs(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	if (!startup_logs)
		return cli_msg(appctx, LOG_INFO, "\n"); // nothing to print

	return ring_attach_cli(startup_logs, appctx);
}

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "startup-logs",  NULL }, "show startup-logs                       : report logs emitted during HAProxy startup", cli_parse_show_startup_logs, NULL, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);


static void deinit_errors_buffers()
{
	ring_free(_HA_ATOMIC_XCHG(&startup_logs, NULL));
}

REGISTER_PER_THREAD_FREE(deinit_errors_buffers);
