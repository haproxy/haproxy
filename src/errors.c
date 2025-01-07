#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include <haproxy/api.h>
#include <haproxy/applet-t.h>
#include <haproxy/buf.h>
#include <haproxy/cli.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/obj_type.h>
#include <haproxy/ring.h>
#include <haproxy/tools.h>
#include <haproxy/version.h>

/* A global buffer used to store all startup alerts/warnings. It will then be
 * retrieve on the CLI. */
struct ring *startup_logs = NULL;
uint tot_warnings = 0;
static struct ring *shm_startup_logs = NULL;

/* A thread local buffer used to store all alerts/warnings. It can be used to
 * retrieve them for CLI commands after startup.
 */
#define USER_MESSAGES_BUFSIZE 1024
static THREAD_LOCAL struct buffer usermsgs_buf = BUF_NULL;

/* A thread local context used for stderr output via ha_alert/warning/notice/diag.
 */
#define USERMSGS_CTX_BUFSIZE   PATH_MAX
static THREAD_LOCAL struct usermsgs_ctx usermsgs_ctx = { .str = BUF_NULL, };

/*
 * At process start (step_init_1) opens shm and allocates the ring area for the
 * startup logs into it. In master-worker mode master and worker share the same
 * ring until the moment, when worker sends READY state to master. This is done
 * in order to show worker's init logs in master CLI as the output of the
 * 'reload' command. After sending its READY status to master, worker must use
 * its copy of the shm, not the shm itself.
 */
static struct ring *startup_logs_init_shm()
{
	struct ring *r = NULL;
	char *area = NULL;

	area = mmap(NULL, STARTUP_LOG_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (area == MAP_FAILED || area == NULL)
		goto error;

        r = ring_make_from_area(area, STARTUP_LOG_SIZE, 1);
	if (r == NULL)
		goto error;

	shm_startup_logs = r; /* save the ptr so we can unmap later */

	return r;
error:
	if (area != MAP_FAILED && area != NULL)
		munmap(area, STARTUP_LOG_SIZE);

	return r;
}

void startup_logs_init()
{
	startup_logs = startup_logs_init_shm();
	if (startup_logs)
		vma_set_name(ring_allocated_area(startup_logs),
		             ring_allocated_size(startup_logs),
		             "errors", "startup_logs");
}

/* free the startup logs, unmap if it was an shm */
void startup_logs_free(struct ring *r)
{
	if (r == shm_startup_logs)
		munmap(ring_allocated_area(r), STARTUP_LOG_SIZE);
	ring_free(r);
	startup_logs = NULL;
}

/* duplicate a startup logs which was previously allocated in a shm */
struct ring *startup_logs_dup(struct ring *src)
{
	struct ring *dst = NULL;

	/* must use the size of the previous buffer */
	dst = ring_new(ring_allocated_size(src));
	if (!dst)
		goto error;

	ring_dup(dst, src, ring_size(src));
error:
	return dst;
}

/* Put msg in usermsgs_buf.
 *
 * The message should not be terminated by a newline because this function
 * manually insert it.
 *
 * If there is not enough room in the buffer, the message is silently discarded.
 * Do not forget to frequently clear the buffer.
 */
static void usermsgs_put(const struct ist *msg)
{
	/* Allocate the buffer if not already done. */
	if (unlikely(b_is_null(&usermsgs_buf))) {
		usermsgs_buf.area = malloc(USER_MESSAGES_BUFSIZE * sizeof(char));
		if (usermsgs_buf.area)
			usermsgs_buf.size = USER_MESSAGES_BUFSIZE;
	}

	if (likely(!b_is_null(&usermsgs_buf))) {
		if (b_room(&usermsgs_buf) >= msg->len + 2) {
			/* Insert the message + newline. */
			b_putblk(&usermsgs_buf, msg->ptr, msg->len);
			b_putchr(&usermsgs_buf, '\n');
			/* Insert NUL outside of the buffer. */
			*b_tail(&usermsgs_buf) = '\0';
		}
	}
}

/* Clear the user messages log buffer.
 *
 * <prefix> will set the local-thread context appended to every output
 * following this call. It can be NULL if not necessary.
 */
void usermsgs_clr(const char *prefix)
{
	if (likely(!b_is_null(&usermsgs_buf))) {
		b_reset(&usermsgs_buf);
		usermsgs_buf.area[0] = '\0';
	}

	usermsgs_ctx.prefix = prefix;
}

/* Check if the user messages buffer is empty. */
int usermsgs_empty(void)
{
	return !!(b_is_null(&usermsgs_buf) || !b_data(&usermsgs_buf));
}

/* Return the messages log buffer content. */
const char *usermsgs_str(void)
{
	if (unlikely(b_is_null(&usermsgs_buf)))
		return "";

	return b_head(&usermsgs_buf);
}

/* Set thread-local context infos to prefix forthcoming stderr output during
 * configuration parsing.
 *
 * <file> and <line> specify the location of the parsed configuration.
 *
 * <obj> can be of various types. If not NULL, the string prefix generated will
 * depend on its type.
 */
void set_usermsgs_ctx(const char *file, int line, enum obj_type *obj)
{
	usermsgs_ctx.file = file;
	usermsgs_ctx.line = line;
	usermsgs_ctx.obj = obj;
}

/* Set thread-local context infos to prefix forthcoming stderr output. It will
 * be set as a complement to possibly already defined file/line.
 *
 * <obj> can be of various types. If not NULL, the string prefix generated will
 * depend on its type.
 */
void register_parsing_obj(enum obj_type *obj)
{
	usermsgs_ctx.obj = obj;
}

/* Reset thread-local context infos for stderr output. */
void reset_usermsgs_ctx(void)
{
	usermsgs_ctx.file = NULL;
	usermsgs_ctx.line = 0;
	usermsgs_ctx.obj = NULL;
}

static void generate_usermsgs_ctx_str(void)
{
	struct usermsgs_ctx *ctx = &usermsgs_ctx;
	void *area;
	int ret;

	if (unlikely(b_is_null(&ctx->str))) {
		area = calloc(USERMSGS_CTX_BUFSIZE, sizeof(*area));
		if (area)
			ctx->str = b_make(area, USERMSGS_CTX_BUFSIZE, 0, 0);
	}

	if (likely(!b_is_null(&ctx->str))) {
		b_reset(&ctx->str);

		if (ctx->prefix) {
			ret = snprintf(b_tail(&ctx->str), b_room(&ctx->str),
			               "%s : ", ctx->prefix);
			b_add(&ctx->str, MIN(ret, b_room(&ctx->str)));
		}

		if (ctx->file) {
			ret = snprintf(b_tail(&ctx->str), b_room(&ctx->str),
			               "[%s:%d] : ", ctx->file, ctx->line);
			b_add(&ctx->str, MIN(ret, b_room(&ctx->str)));
		}

		switch (obj_type(ctx->obj)) {
		case OBJ_TYPE_SERVER:
			ret = snprintf(b_tail(&ctx->str), b_room(&ctx->str),
			               "'server %s/%s' : ",
			               __objt_server(ctx->obj)->proxy->id,
			               __objt_server(ctx->obj)->id);
			b_add(&ctx->str, MIN(ret, b_room(&ctx->str)));
			break;

		case OBJ_TYPE_NONE:
		default:
			break;
		}

		if (!b_data(&ctx->str))
			snprintf(b_tail(&ctx->str), b_room(&ctx->str), "%s", "");
	}
}

/* Generic function to display messages prefixed by a label */
static void print_message(int use_usermsgs_ctx, const char *label, const char *fmt, va_list argp)
{
	struct ist msg_ist = IST_NULL;
	char *head, *parsing_str, *msg;
	char prefix[11]; // '[' + 8 chars + ']' + 0.

	*prefix = '[';
	strncpy(prefix + 1, label, sizeof(prefix) - 2);
	msg = prefix + strlen(prefix);
	*msg++ = ']';
	while (msg < prefix + sizeof(prefix) - 1)
		*msg++ = ' ';
	*msg = 0;

	head = parsing_str = msg = NULL;
	memprintf(&head, "%s (%u) : ", prefix, (uint)getpid());
	memvprintf(&msg, fmt, argp);

	/* trim the trailing '\n' */
	msg_ist = ist(msg);
	if (msg_ist.len > 0 && msg_ist.ptr[msg_ist.len - 1] == '\n')
		msg_ist.len--;

	if (use_usermsgs_ctx) {
		generate_usermsgs_ctx_str();
		parsing_str = b_head(&usermsgs_ctx.str);
		reset_usermsgs_ctx();
	}
	else {
		parsing_str = "";
	}

	if (global.mode & MODE_STARTING) {
		if (likely(startup_logs)) {
			struct ist m[3];

			m[0] = ist(head);
			m[1] = ist(parsing_str);
			m[2] = msg_ist;

			ring_write(startup_logs, ~0, 0, 0, m, 3);
		} else
			usermsgs_put(&msg_ist);
	}
	else {
		usermsgs_put(&msg_ist);
	}
	if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) {
		fprintf(stderr, "%s%s%s", head, parsing_str, msg);
		fflush(stderr);
	}

	free(head);
	free(msg);
}

static void print_message_args(int use_usermsgs_ctx, const char *label, const char *fmt, ...)
{
	va_list argp;
	va_start(argp, fmt);
	print_message(use_usermsgs_ctx, label, fmt, argp);
	va_end(argp);
}

/*
 * Display a notice with the happroxy version and executable path when the
 * first message is emitted in starting mode.
 */
static void warn_exec_path()
{
	if (!(warned & WARN_EXEC_PATH) && (global.mode & MODE_STARTING)) {
		const char *path = get_exec_path();

		warned |= WARN_EXEC_PATH;
		print_message_args(0, "NOTICE", "haproxy version is %s\n", haproxy_version);
		if (path)
			print_message_args(0, "NOTICE", "path to executable is %s\n", path);
	}
}

/*
 * Displays the message on stderr with the pid.
 */
void ha_alert(const char *fmt, ...)
{
	va_list argp;

	warn_exec_path();
	va_start(argp, fmt);
	print_message(1, "ALERT", fmt, argp);
	va_end(argp);
}

/*
 * Displays the message on stderr with the pid.
 */
void ha_warning(const char *fmt, ...)
{
	va_list argp;

	warned |= WARN_ANY;
	HA_ATOMIC_INC(&tot_warnings);

	warn_exec_path();
	va_start(argp, fmt);
	print_message(1, "WARNING", fmt, argp);
	va_end(argp);
}

/*
 * Variant of _ha_diag_warning with va_list.
 * Use it only if MODE_DIAG has been previously checked.
 */
void _ha_vdiag_warning(const char *fmt, va_list argp)
{
	warned |= WARN_ANY;
	HA_ATOMIC_INC(&tot_warnings);

	warn_exec_path();
	print_message(1, "DIAG", fmt, argp);
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
 * Displays the message on stderr with the pid.
 */
void ha_notice(const char *fmt, ...)
{
	va_list argp;

	va_start(argp, fmt);
	print_message(1, "NOTICE", fmt, argp);
	va_end(argp);
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

	return ring_attach_cli(startup_logs, appctx, 0);
}

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "startup-logs",  NULL }, "show startup-logs                       : report logs emitted during HAProxy startup", cli_parse_show_startup_logs, NULL, NULL, NULL, ACCESS_MASTER },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);


static void deinit_errors_buffers()
{
	ring_free(_HA_ATOMIC_XCHG(&startup_logs, NULL));
	ha_free(&usermsgs_buf.area);
	ha_free(&usermsgs_ctx.str.area);
}

/* errors might be used in threads and even before forking, thus 2 deinit */
REGISTER_PER_THREAD_FREE(deinit_errors_buffers);
REGISTER_POST_DEINIT(deinit_errors_buffers);
