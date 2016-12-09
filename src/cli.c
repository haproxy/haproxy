/*
 * Functions dedicated to statistics output and the stats socket
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 * Copyright 2007-2009 Krzysztof Piotr Oledzki <ole@ans.pl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <common/cfgparse.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>
#include <common/uri_auth.h>
#include <common/version.h>
#include <common/base64.h>

#include <types/applet.h>
#include <types/cli.h>
#include <types/global.h>
#include <types/dns.h>
#include <types/stats.h>

#include <proto/backend.h>
#include <proto/channel.h>
#include <proto/checks.h>
#include <proto/compression.h>
#include <proto/stats.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/frontend.h>
#include <proto/log.h>
#include <proto/pattern.h>
#include <proto/pipe.h>
#include <proto/listener.h>
#include <proto/map.h>
#include <proto/proto_uxst.h>
#include <proto/proxy.h>
#include <proto/sample.h>
#include <proto/session.h>
#include <proto/stream.h>
#include <proto/server.h>
#include <proto/raw_sock.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

static struct applet cli_applet;

static const char stats_sock_usage_msg[] =
	"Unknown command. Please enter one of the following commands only :\n"
	"  help           : this message\n"
	"  prompt         : toggle interactive mode with prompt\n"
	"  quit           : disconnect\n"
	"";

static const char stats_permission_denied_msg[] =
	"Permission denied\n"
	"";


static char *dynamic_usage_msg = NULL;

/* List head of cli keywords */
static struct cli_kw_list cli_keywords = {
	.list = LIST_HEAD_INIT(cli_keywords.list)
};

extern const char *stat_status_codes[];

char *cli_gen_usage_msg()
{
	struct cli_kw_list *kw_list;
	struct cli_kw *kw;
	struct chunk *tmp = get_trash_chunk();
	struct chunk out;

	free(dynamic_usage_msg);
	dynamic_usage_msg = NULL;

	if (LIST_ISEMPTY(&cli_keywords.list))
		return NULL;

	chunk_reset(tmp);
	chunk_strcat(tmp, stats_sock_usage_msg);
	list_for_each_entry(kw_list, &cli_keywords.list, list) {
		kw = &kw_list->kw[0];
		while (kw->usage) {
			chunk_appendf(tmp, "  %s\n", kw->usage);
			kw++;
		}
	}
	chunk_init(&out, NULL, 0);
	chunk_dup(&out, tmp);
	dynamic_usage_msg = out.str;
	return dynamic_usage_msg;
}

struct cli_kw* cli_find_kw(char **args)
{
	struct cli_kw_list *kw_list;
	struct cli_kw *kw;/* current cli_kw */
	char **tmp_args;
	const char **tmp_str_kw;
	int found = 0;

	if (LIST_ISEMPTY(&cli_keywords.list))
		return NULL;

	list_for_each_entry(kw_list, &cli_keywords.list, list) {
		kw = &kw_list->kw[0];
		while (*kw->str_kw) {
			tmp_args = args;
			tmp_str_kw = kw->str_kw;
			while (*tmp_str_kw) {
				if (strcmp(*tmp_str_kw, *tmp_args) == 0) {
					found = 1;
				} else {
					found = 0;
					break;
				}
				tmp_args++;
				tmp_str_kw++;
			}
			if (found)
				return (kw);
			kw++;
		}
	}
	return NULL;
}

void cli_register_kw(struct cli_kw_list *kw_list)
{
	LIST_ADDQ(&cli_keywords.list, &kw_list->list);
}


/* allocate a new stats frontend named <name>, and return it
 * (or NULL in case of lack of memory).
 */
static struct proxy *alloc_stats_fe(const char *name, const char *file, int line)
{
	struct proxy *fe;

	fe = calloc(1, sizeof(*fe));
	if (!fe)
		return NULL;

	init_new_proxy(fe);
	fe->next = proxy;
	proxy = fe;
	fe->last_change = now.tv_sec;
	fe->id = strdup("GLOBAL");
	fe->cap = PR_CAP_FE;
	fe->maxconn = 10;                 /* default to 10 concurrent connections */
	fe->timeout.client = MS_TO_TICKS(10000); /* default timeout of 10 seconds */
	fe->conf.file = strdup(file);
	fe->conf.line = line;
	fe->accept = frontend_accept;
	fe->default_target = &cli_applet.obj_type;

	/* the stats frontend is the only one able to assign ID #0 */
	fe->conf.id.key = fe->uuid = 0;
	eb32_insert(&used_proxy_id, &fe->conf.id);
	return fe;
}

/* This function parses a "stats" statement in the "global" section. It returns
 * -1 if there is any error, otherwise zero. If it returns -1, it will write an
 * error message into the <err> buffer which will be preallocated. The trailing
 * '\n' must not be written. The function must be called with <args> pointing to
 * the first word after "stats".
 */
static int stats_parse_global(char **args, int section_type, struct proxy *curpx,
                              struct proxy *defpx, const char *file, int line,
                              char **err)
{
	struct bind_conf *bind_conf;
	struct listener *l;

	if (!strcmp(args[1], "socket")) {
		int cur_arg;

		if (*args[2] == 0) {
			memprintf(err, "'%s %s' in global section expects an address or a path to a UNIX socket", args[0], args[1]);
			return -1;
		}

		if (!global.stats_fe) {
			if ((global.stats_fe = alloc_stats_fe("GLOBAL", file, line)) == NULL) {
				memprintf(err, "'%s %s' : out of memory trying to allocate a frontend", args[0], args[1]);
				return -1;
			}
		}

		bind_conf = bind_conf_alloc(&global.stats_fe->conf.bind, file, line, args[2]);
		bind_conf->level = ACCESS_LVL_OPER; /* default access level */

		if (!str2listener(args[2], global.stats_fe, bind_conf, file, line, err)) {
			memprintf(err, "parsing [%s:%d] : '%s %s' : %s\n",
			          file, line, args[0], args[1], err && *err ? *err : "error");
			return -1;
		}

		cur_arg = 3;
		while (*args[cur_arg]) {
			static int bind_dumped;
			struct bind_kw *kw;

			kw = bind_find_kw(args[cur_arg]);
			if (kw) {
				if (!kw->parse) {
					memprintf(err, "'%s %s' : '%s' option is not implemented in this version (check build options).",
						  args[0], args[1], args[cur_arg]);
					return -1;
				}

				if (kw->parse(args, cur_arg, global.stats_fe, bind_conf, err) != 0) {
					if (err && *err)
						memprintf(err, "'%s %s' : '%s'", args[0], args[1], *err);
					else
						memprintf(err, "'%s %s' : error encountered while processing '%s'",
						          args[0], args[1], args[cur_arg]);
					return -1;
				}

				cur_arg += 1 + kw->skip;
				continue;
			}

			if (!bind_dumped) {
				bind_dump_kws(err);
				indent_msg(err, 4);
				bind_dumped = 1;
			}

			memprintf(err, "'%s %s' : unknown keyword '%s'.%s%s",
			          args[0], args[1], args[cur_arg],
			          err && *err ? " Registered keywords :" : "", err && *err ? *err : "");
			return -1;
		}

		list_for_each_entry(l, &bind_conf->listeners, by_bind) {
			l->maxconn = global.stats_fe->maxconn;
			l->backlog = global.stats_fe->backlog;
			l->accept = session_accept_fd;
			l->handler = process_stream;
			l->default_target = global.stats_fe->default_target;
			l->options |= LI_O_UNLIMITED; /* don't make the peers subject to global limits */
			l->nice = -64;  /* we want to boost priority for local stats */
			global.maxsock += l->maxconn;
		}
	}
	else if (!strcmp(args[1], "timeout")) {
		unsigned timeout;
		const char *res = parse_time_err(args[2], &timeout, TIME_UNIT_MS);

		if (res) {
			memprintf(err, "'%s %s' : unexpected character '%c'", args[0], args[1], *res);
			return -1;
		}

		if (!timeout) {
			memprintf(err, "'%s %s' expects a positive value", args[0], args[1]);
			return -1;
		}
		if (!global.stats_fe) {
			if ((global.stats_fe = alloc_stats_fe("GLOBAL", file, line)) == NULL) {
				memprintf(err, "'%s %s' : out of memory trying to allocate a frontend", args[0], args[1]);
				return -1;
			}
		}
		global.stats_fe->timeout.client = MS_TO_TICKS(timeout);
	}
	else if (!strcmp(args[1], "maxconn")) {
		int maxconn = atol(args[2]);

		if (maxconn <= 0) {
			memprintf(err, "'%s %s' expects a positive value", args[0], args[1]);
			return -1;
		}

		if (!global.stats_fe) {
			if ((global.stats_fe = alloc_stats_fe("GLOBAL", file, line)) == NULL) {
				memprintf(err, "'%s %s' : out of memory trying to allocate a frontend", args[0], args[1]);
				return -1;
			}
		}
		global.stats_fe->maxconn = maxconn;
	}
	else if (!strcmp(args[1], "bind-process")) {  /* enable the socket only on some processes */
		int cur_arg = 2;
		unsigned long set = 0;

		if (!global.stats_fe) {
			if ((global.stats_fe = alloc_stats_fe("GLOBAL", file, line)) == NULL) {
				memprintf(err, "'%s %s' : out of memory trying to allocate a frontend", args[0], args[1]);
				return -1;
			}
		}

		while (*args[cur_arg]) {
			unsigned int low, high;

			if (strcmp(args[cur_arg], "all") == 0) {
				set = 0;
				break;
			}
			else if (strcmp(args[cur_arg], "odd") == 0) {
				set |= ~0UL/3UL; /* 0x555....555 */
			}
			else if (strcmp(args[cur_arg], "even") == 0) {
				set |= (~0UL/3UL) << 1; /* 0xAAA...AAA */
			}
			else if (isdigit((int)*args[cur_arg])) {
				char *dash = strchr(args[cur_arg], '-');

				low = high = str2uic(args[cur_arg]);
				if (dash)
					high = str2uic(dash + 1);

				if (high < low) {
					unsigned int swap = low;
					low = high;
					high = swap;
				}

				if (low < 1 || high > LONGBITS) {
					memprintf(err, "'%s %s' supports process numbers from 1 to %d.\n",
					          args[0], args[1], LONGBITS);
					return -1;
				}
				while (low <= high)
					set |= 1UL << (low++ - 1);
			}
			else {
				memprintf(err,
				          "'%s %s' expects 'all', 'odd', 'even', or a list of process ranges with numbers from 1 to %d.\n",
				          args[0], args[1], LONGBITS);
				return -1;
			}
			cur_arg++;
		}
		global.stats_fe->bind_proc = set;
	}
	else {
		memprintf(err, "'%s' only supports 'socket', 'maxconn', 'bind-process' and 'timeout' (got '%s')", args[0], args[1]);
		return -1;
	}
	return 0;
}

/* Verifies that the CLI at least has a level at least as high as <level>
 * (typically ACCESS_LVL_ADMIN). Returns 1 if OK, otherwise 0. In case of
 * failure, an error message is prepared and the appctx's state is adjusted
 * to print it so that a return 1 is enough to abort any processing.
 */
int cli_has_level(struct appctx *appctx, int level)
{
	struct stream_interface *si = appctx->owner;
	struct stream *s = si_strm(si);

	if (strm_li(s)->bind_conf->level < level) {
		appctx->ctx.cli.msg = stats_permission_denied_msg;
		appctx->st0 = CLI_ST_PRINT;
		return 0;
	}
	return 1;
}


/* Processes the CLI interpreter on the stats socket. This function is called
 * from the CLI's IO handler running in an appctx context. The function returns 1
 * if the request was understood, otherwise zero. It is called with appctx->st0
 * set to CLI_ST_GETREQ and presets ->st2 to 0 so that parsers don't have to do
 * it. It will possilbly leave st0 to CLI_ST_CALLBACK if the keyword needs to
 * have its own I/O handler called again. Most of the time, parsers will only
 * set st0 to CLI_ST_PRINT and put their message to be displayed into cli.msg.
 */
static int cli_parse_request(struct appctx *appctx, char *line)
{
	char *args[MAX_STATS_ARGS + 1];
	struct cli_kw *kw;
	int arg;
	int i, j;

	while (isspace((unsigned char)*line))
		line++;

	arg = 0;
	args[arg] = line;

	while (*line && arg < MAX_STATS_ARGS) {
		if (*line == '\\') {
			line++;
			if (*line == '\0')
				break;
		}
		else if (isspace((unsigned char)*line)) {
			*line++ = '\0';

			while (isspace((unsigned char)*line))
				line++;

			args[++arg] = line;
			continue;
		}

		line++;
	}

	while (++arg <= MAX_STATS_ARGS)
		args[arg] = line;

	/* unescape '\' */
	arg = 0;
	while (*args[arg] != '\0') {
		j = 0;
		for (i=0; args[arg][i] != '\0'; i++) {
			if (args[arg][i] == '\\') {
				if (args[arg][i+1] == '\\')
					i++;
				else
					continue;
			}
			args[arg][j] = args[arg][i];
			j++;
		}
		args[arg][j] = '\0';
		arg++;
	}

	appctx->ctx.stats.scope_str = 0;
	appctx->ctx.stats.scope_len = 0;
	appctx->ctx.stats.flags = 0;
	appctx->st2 = 0;

	kw = cli_find_kw(args);
	if (!kw || !kw->parse)
		return 0;

	appctx->io_handler = kw->io_handler;
	if (kw->parse(args, appctx, kw->private) == 0 && appctx->io_handler) {
		appctx->st0 = CLI_ST_CALLBACK;
		appctx->io_release = kw->io_release;
	}
	return 1;
}

/* This I/O handler runs as an applet embedded in a stream interface. It is
 * used to processes I/O from/to the stats unix socket. The system relies on a
 * state machine handling requests and various responses. We read a request,
 * then we process it and send the response, and we possibly display a prompt.
 * Then we can read again. The state is stored in appctx->st0 and is one of the
 * CLI_ST_* constants. appctx->st1 is used to indicate whether prompt is enabled
 * or not.
 */
static void cli_io_handler(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct channel *req = si_oc(si);
	struct channel *res = si_ic(si);
	int reql;
	int len;

	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		goto out;

	/* Check if the input buffer is avalaible. */
	if (res->buf->size == 0) {
		si_applet_cant_put(si);
		goto out;
	}

	while (1) {
		if (appctx->st0 == CLI_ST_INIT) {
			/* Stats output not initialized yet */
			memset(&appctx->ctx.stats, 0, sizeof(appctx->ctx.stats));
			appctx->st0 = CLI_ST_GETREQ;
		}
		else if (appctx->st0 == CLI_ST_END) {
			/* Let's close for real now. We just close the request
			 * side, the conditions below will complete if needed.
			 */
			si_shutw(si);
			break;
		}
		else if (appctx->st0 == CLI_ST_GETREQ) {
			/* ensure we have some output room left in the event we
			 * would want to return some info right after parsing.
			 */
			if (buffer_almost_full(si_ib(si))) {
				si_applet_cant_put(si);
				break;
			}

			reql = bo_getline(si_oc(si), trash.str, trash.size);
			if (reql <= 0) { /* closed or EOL not found */
				if (reql == 0)
					break;
				appctx->st0 = CLI_ST_END;
				continue;
			}

			/* seek for a possible unescaped semi-colon. If we find
			 * one, we replace it with an LF and skip only this part.
			 */
			for (len = 0; len < reql; len++) {
				if (trash.str[len] == '\\') {
					len++;
					continue;
				}
				if (trash.str[len] == ';') {
					trash.str[len] = '\n';
					reql = len + 1;
					break;
				}
			}

			/* now it is time to check that we have a full line,
			 * remove the trailing \n and possibly \r, then cut the
			 * line.
			 */
			len = reql - 1;
			if (trash.str[len] != '\n') {
				appctx->st0 = CLI_ST_END;
				continue;
			}

			if (len && trash.str[len-1] == '\r')
				len--;

			trash.str[len] = '\0';

			appctx->st0 = CLI_ST_PROMPT;
			if (len) {
				if (strcmp(trash.str, "quit") == 0) {
					appctx->st0 = CLI_ST_END;
					continue;
				}
				else if (strcmp(trash.str, "prompt") == 0)
					appctx->st1 = !appctx->st1;
				else if (strcmp(trash.str, "help") == 0 ||
					 !cli_parse_request(appctx, trash.str)) {
					cli_gen_usage_msg();
					if (dynamic_usage_msg)
						appctx->ctx.cli.msg = dynamic_usage_msg;
					else
						appctx->ctx.cli.msg = stats_sock_usage_msg;
					appctx->st0 = CLI_ST_PRINT;
				}
				/* NB: stats_sock_parse_request() may have put
				 * another CLI_ST_O_* into appctx->st0.
				 */
			}
			else if (!appctx->st1) {
				/* if prompt is disabled, print help on empty lines,
				 * so that the user at least knows how to enable
				 * prompt and find help.
				 */
				cli_gen_usage_msg();
				if (dynamic_usage_msg)
					appctx->ctx.cli.msg = dynamic_usage_msg;
				else
					appctx->ctx.cli.msg = stats_sock_usage_msg;
				appctx->st0 = CLI_ST_PRINT;
			}

			/* re-adjust req buffer */
			bo_skip(si_oc(si), reql);
			req->flags |= CF_READ_DONTWAIT; /* we plan to read small requests */
		}
		else {	/* output functions */
			switch (appctx->st0) {
			case CLI_ST_PROMPT:
				break;
			case CLI_ST_PRINT:
				if (bi_putstr(si_ic(si), appctx->ctx.cli.msg) != -1)
					appctx->st0 = CLI_ST_PROMPT;
				else
					si_applet_cant_put(si);
				break;
			case CLI_ST_PRINT_FREE:
				if (bi_putstr(si_ic(si), appctx->ctx.cli.err) != -1) {
					free(appctx->ctx.cli.err);
					appctx->st0 = CLI_ST_PROMPT;
				}
				else
					si_applet_cant_put(si);
				break;
			case CLI_ST_CALLBACK: /* use custom pointer */
				if (appctx->io_handler)
					if (appctx->io_handler(appctx)) {
						appctx->st0 = CLI_ST_PROMPT;
						if (appctx->io_release) {
							appctx->io_release(appctx);
							appctx->io_release = NULL;
						}
					}
				break;
			default: /* abnormal state */
				si->flags |= SI_FL_ERR;
				break;
			}

			/* The post-command prompt is either LF alone or LF + '> ' in interactive mode */
			if (appctx->st0 == CLI_ST_PROMPT) {
				if (bi_putstr(si_ic(si), appctx->st1 ? "\n> " : "\n") != -1)
					appctx->st0 = CLI_ST_GETREQ;
				else
					si_applet_cant_put(si);
			}

			/* If the output functions are still there, it means they require more room. */
			if (appctx->st0 >= CLI_ST_OUTPUT)
				break;

			/* Now we close the output if one of the writers did so,
			 * or if we're not in interactive mode and the request
			 * buffer is empty. This still allows pipelined requests
			 * to be sent in non-interactive mode.
			 */
			if ((res->flags & (CF_SHUTW|CF_SHUTW_NOW)) || (!appctx->st1 && !req->buf->o)) {
				appctx->st0 = CLI_ST_END;
				continue;
			}

			/* switch state back to GETREQ to read next requests */
			appctx->st0 = CLI_ST_GETREQ;
		}
	}

	if ((res->flags & CF_SHUTR) && (si->state == SI_ST_EST)) {
		DPRINTF(stderr, "%s@%d: si to buf closed. req=%08x, res=%08x, st=%d\n",
			__FUNCTION__, __LINE__, req->flags, res->flags, si->state);
		/* Other side has closed, let's abort if we have no more processing to do
		 * and nothing more to consume. This is comparable to a broken pipe, so
		 * we forward the close to the request side so that it flows upstream to
		 * the client.
		 */
		si_shutw(si);
	}

	if ((req->flags & CF_SHUTW) && (si->state == SI_ST_EST) && (appctx->st0 < CLI_ST_OUTPUT)) {
		DPRINTF(stderr, "%s@%d: buf to si closed. req=%08x, res=%08x, st=%d\n",
			__FUNCTION__, __LINE__, req->flags, res->flags, si->state);
		/* We have no more processing to do, and nothing more to send, and
		 * the client side has closed. So we'll forward this state downstream
		 * on the response buffer.
		 */
		si_shutr(si);
		res->flags |= CF_READ_NULL;
	}

 out:
	DPRINTF(stderr, "%s@%d: st=%d, rqf=%x, rpf=%x, rqh=%d, rqs=%d, rh=%d, rs=%d\n",
		__FUNCTION__, __LINE__,
		si->state, req->flags, res->flags, req->buf->i, req->buf->o, res->buf->i, res->buf->o);
}

/* This is called when the stream interface is closed. For instance, upon an
 * external abort, we won't call the i/o handler anymore so we may need to
 * remove back references to the stream currently being dumped.
 */
static void cli_release_handler(struct appctx *appctx)
{
	if (appctx->io_release) {
		appctx->io_release(appctx);
		appctx->io_release = NULL;
	}
	else if (appctx->st0 == CLI_ST_PRINT_FREE) {
		free(appctx->ctx.cli.err);
		appctx->ctx.cli.err = NULL;
	}
}

/* This function dumps all environmnent variables to the buffer. It returns 0
 * if the output buffer is full and it needs to be called again, otherwise
 * non-zero. Dumps only one entry if st2 == STAT_ST_END.
 */
static int cli_io_handler_show_env(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		return 1;

	chunk_reset(&trash);

	/* we have two inner loops here, one for the proxy, the other one for
	 * the buffer.
	 */
	while (*appctx->ctx.env.var) {
		chunk_printf(&trash, "%s\n", *appctx->ctx.env.var);

		if (bi_putchk(si_ic(si), &trash) == -1) {
			si_applet_cant_put(si);
			return 0;
		}
		if (appctx->st2 == STAT_ST_END)
			break;
		appctx->ctx.env.var++;
	}

	/* dump complete */
	return 1;
}

/* parse a "show env" CLI request. Returns 0 if it needs to continue, 1 if it
 * wants to stop here.
 */
static int cli_parse_show_env(char **args, struct appctx *appctx, void *private)
{
	extern char **environ;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	appctx->ctx.env.var = environ;

	if (*args[2]) {
		int len = strlen(args[2]);

		for (; *appctx->ctx.env.var; appctx->ctx.env.var++) {
			if (strncmp(*appctx->ctx.env.var, args[2], len) == 0 &&
			    (*appctx->ctx.env.var)[len] == '=')
				break;
		}
		if (!*appctx->ctx.env.var) {
			appctx->ctx.cli.msg = "Variable not found\n";
			appctx->st0 = CLI_ST_PRINT;
			return 1;
		}
		appctx->st2 = STAT_ST_END;
	}
	return 0;
}

/* parse a "set timeout" CLI request. It always returns 1. */
static int cli_parse_set_timeout(char **args, struct appctx *appctx, void *private)
{
	struct stream_interface *si = appctx->owner;
	struct stream *s = si_strm(si);

	if (strcmp(args[2], "cli") == 0) {
		unsigned timeout;
		const char *res;

		if (!*args[3]) {
			appctx->ctx.cli.msg = "Expects an integer value.\n";
			appctx->st0 = CLI_ST_PRINT;
			return 1;
		}

		res = parse_time_err(args[3], &timeout, TIME_UNIT_S);
		if (res || timeout < 1) {
			appctx->ctx.cli.msg = "Invalid timeout value.\n";
			appctx->st0 = CLI_ST_PRINT;
			return 1;
		}

		s->req.rto = s->res.wto = 1 + MS_TO_TICKS(timeout*1000);
		task_wakeup(s->task, TASK_WOKEN_MSG); // recompute timeouts
		return 1;
	}
	else {
		appctx->ctx.cli.msg = "'set timeout' only supports 'cli'.\n";
		appctx->st0 = CLI_ST_PRINT;
		return 1;
	}
}

/* parse a "set maxconn global" command. It always returns 1. */
static int cli_parse_set_maxconn_global(char **args, struct appctx *appctx, void *private)
{
	int v;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3]) {
		appctx->ctx.cli.msg = "Expects an integer value.\n";
		appctx->st0 = CLI_ST_PRINT;
		return 1;
	}

	v = atoi(args[3]);
	if (v > global.hardmaxconn) {
		appctx->ctx.cli.msg = "Value out of range.\n";
		appctx->st0 = CLI_ST_PRINT;
		return 1;
	}

	/* check for unlimited values */
	if (v <= 0)
		v = global.hardmaxconn;

	global.maxconn = v;

	/* Dequeues all of the listeners waiting for a resource */
	if (!LIST_ISEMPTY(&global_listener_queue))
		dequeue_all_listeners(&global_listener_queue);

	return 1;
}

/* parse a "set rate-limit" command. It always returns 1. */
static int cli_parse_set_ratelimit(char **args, struct appctx *appctx, void *private)
{
	int v;
	int *res;
	int mul = 1;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (strcmp(args[2], "connections") == 0 && strcmp(args[3], "global") == 0)
		res = &global.cps_lim;
	else if (strcmp(args[2], "sessions") == 0 && strcmp(args[3], "global") == 0)
		res = &global.sps_lim;
#ifdef USE_OPENSSL
	else if (strcmp(args[2], "ssl-sessions") == 0 && strcmp(args[3], "global") == 0)
		res = &global.ssl_lim;
#endif
	else if (strcmp(args[2], "http-compression") == 0 && strcmp(args[3], "global") == 0) {
		res = &global.comp_rate_lim;
		mul = 1024;
	}
	else {
		appctx->ctx.cli.msg =
			"'set rate-limit' only supports :\n"
			"   - 'connections global' to set the per-process maximum connection rate\n"
			"   - 'sessions global' to set the per-process maximum session rate\n"
#ifdef USE_OPENSSL
			"   - 'ssl-session global' to set the per-process maximum SSL session rate\n"
#endif
			"   - 'http-compression global' to set the per-process maximum compression speed in kB/s\n";
		appctx->st0 = CLI_ST_PRINT;
		return 1;
	}

	if (!*args[4]) {
		appctx->ctx.cli.msg = "Expects an integer value.\n";
		appctx->st0 = CLI_ST_PRINT;
		return 1;
	}

	v = atoi(args[4]);
	if (v < 0) {
		appctx->ctx.cli.msg = "Value out of range.\n";
		appctx->st0 = CLI_ST_PRINT;
		return 1;
	}

	*res = v * mul;

	/* Dequeues all of the listeners waiting for a resource */
	if (!LIST_ISEMPTY(&global_listener_queue))
		dequeue_all_listeners(&global_listener_queue);

	return 1;
}

/* parse the "level" argument on the bind lines */
static int bind_parse_level(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing level", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (!strcmp(args[cur_arg+1], "user"))
		conf->level = ACCESS_LVL_USER;
	else if (!strcmp(args[cur_arg+1], "operator"))
		conf->level = ACCESS_LVL_OPER;
	else if (!strcmp(args[cur_arg+1], "admin"))
		conf->level = ACCESS_LVL_ADMIN;
	else {
		memprintf(err, "'%s' only supports 'user', 'operator', and 'admin' (got '%s')",
			  args[cur_arg], args[cur_arg+1]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

static struct applet cli_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<CLI>", /* used for logging */
	.fct = cli_io_handler,
	.release = cli_release_handler,
};

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "set", "maxconn", "global",  NULL }, "set maxconn global : change the per-process maxconn setting", cli_parse_set_maxconn_global, NULL },
	{ { "set", "rate-limit", NULL }, "set rate-limit : change a rate limiting value", cli_parse_set_ratelimit, NULL },
	{ { "set", "timeout",  NULL }, "set timeout    : change a timeout setting", cli_parse_set_timeout, NULL, NULL },
	{ { "show", "env",  NULL }, "show env [var] : dump environment variables known to the process", cli_parse_show_env, cli_io_handler_show_env, NULL },
	{{},}
}};

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "stats", stats_parse_global },
	{ 0, NULL, NULL },
}};

static struct bind_kw_list bind_kws = { "STAT", { }, {
	{ "level",    bind_parse_level,    1 }, /* set the unix socket admin level */
	{ NULL, NULL, 0 },
}};

__attribute__((constructor))
static void __dumpstats_module_init(void)
{
	cfg_register_keywords(&cfg_kws);
	cli_register_kw(&cli_kws);
	bind_register_keywords(&bind_kws);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
