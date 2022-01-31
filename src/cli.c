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

#include <net/if.h>

#include <haproxy/activity.h>
#include <haproxy/api.h>
#include <haproxy/applet-t.h>
#include <haproxy/base64.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/check.h>
#include <haproxy/cli.h>
#include <haproxy/compression.h>
#include <haproxy/dns-t.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/frontend.h>
#include <haproxy/global.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/mworker.h>
#include <haproxy/mworker-t.h>
#include <haproxy/pattern-t.h>
#include <haproxy/peers.h>
#include <haproxy/pipe.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/sample-t.h>
#include <haproxy/server.h>
#include <haproxy/session.h>
#include <haproxy/sock.h>
#include <haproxy/stats-t.h>
#include <haproxy/stream.h>
#include <haproxy/stream_interface.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <haproxy/version.h>

#define PAYLOAD_PATTERN "<<"

static struct applet cli_applet;
static struct applet mcli_applet;

static const char cli_permission_denied_msg[] =
	"Permission denied\n"
	"";


static THREAD_LOCAL char *dynamic_usage_msg = NULL;

/* List head of cli keywords */
static struct cli_kw_list cli_keywords = {
	.list = LIST_HEAD_INIT(cli_keywords.list)
};

extern const char *stat_status_codes[];

struct proxy *mworker_proxy; /* CLI proxy of the master */

static int cmp_kw_entries(const void *a, const void *b)
{
	const struct cli_kw *l = *(const struct cli_kw **)a;
	const struct cli_kw *r = *(const struct cli_kw **)b;

	return strcmp(l->usage ? l->usage : "", r->usage ? r->usage : "");
}

/* This will show the help message and list the commands supported at the
 * current level that match all of the first words of <args> if args is not
 * NULL, or all args if none matches or if args is null.
 */
static char *cli_gen_usage_msg(struct appctx *appctx, char * const *args)
{
	struct cli_kw *entries[CLI_MAX_HELP_ENTRIES];
	struct cli_kw_list *kw_list;
	struct cli_kw *kw;
	struct buffer *tmp = get_trash_chunk();
	struct buffer out;
	struct { struct cli_kw *kw; int dist; } matches[CLI_MAX_MATCHES], swp;
	int idx;
	int ishelp = 0;
	int length = 0;
	int help_entries = 0;

	ha_free(&dynamic_usage_msg);

	if (args && *args && strcmp(*args, "help") == 0) {
		args++;
		ishelp = 1;
	}

	/* first, let's measure the longest match */
	list_for_each_entry(kw_list, &cli_keywords.list, list) {
		for (kw = &kw_list->kw[0]; kw->str_kw[0]; kw++) {
			if (kw->level & ~appctx->cli_level & (ACCESS_MASTER_ONLY|ACCESS_EXPERT|ACCESS_EXPERIMENTAL))
				continue;
			if ((appctx->cli_level & ~kw->level & (ACCESS_MASTER_ONLY|ACCESS_MASTER)) ==
			    (ACCESS_MASTER_ONLY|ACCESS_MASTER))
				continue;

			/* OK this command is visible */
			for (idx = 0; idx < CLI_PREFIX_KW_NB; idx++) {
				if (!kw->str_kw[idx])
					break; // end of keyword
				if (!args || !args[idx] || !*args[idx])
					break; // end of command line
				if (strcmp(kw->str_kw[idx], args[idx]) != 0)
					break;
				if (idx + 1 > length)
					length = idx + 1;
			}
		}
	}

	/* now <length> equals the number of exactly matching words */
	chunk_reset(tmp);
	if (ishelp) // this is the help message.
		chunk_strcat(tmp, "The following commands are valid at this level:\n");
	else if (!length && (!args || !*args || !**args)) // no match
		chunk_strcat(tmp, "Unknown command. Please enter one of the following commands only:\n");
	else // partial match
		chunk_strcat(tmp, "Unknown command, but maybe one of the following ones is a better match:\n");

	for (idx = 0; idx < CLI_MAX_MATCHES; idx++) {
		matches[idx].kw = NULL;
		matches[idx].dist = INT_MAX;
	}

	/* In case of partial match we'll look for the best matching entries
	 * starting from position <length>
	 */
	if (args && args[length] && *args[length]) {
		list_for_each_entry(kw_list, &cli_keywords.list, list) {
			for (kw = &kw_list->kw[0]; kw->str_kw[0]; kw++) {
				if (kw->level & ~appctx->cli_level & (ACCESS_MASTER_ONLY|ACCESS_EXPERT|ACCESS_EXPERIMENTAL))
					continue;
				if ((appctx->cli_level & ~kw->level & (ACCESS_MASTER_ONLY|ACCESS_MASTER)) ==
				    (ACCESS_MASTER_ONLY|ACCESS_MASTER))
					continue;

				for (idx = 0; idx < length; idx++) {
					if (!kw->str_kw[idx])
						break; // end of keyword
					if (!args || !args[idx] || !*args[idx])
						break; // end of command line
					if (strcmp(kw->str_kw[idx], args[idx]) != 0)
						break;
				}

				/* extra non-matching words are fuzzy-matched */
				if (kw->usage && idx == length && args[idx] && *args[idx]) {
					uint8_t word_sig[1024];
					uint8_t list_sig[1024];
					int dist = 0;
					int totlen = 0;
					int i;

					/* this one matches, let's compute the distance between the two
					 * on the remaining words. For this we're computing the signature
					 * of everything that remains and the cumulated length of the
					 * strings.
					 */
					memset(word_sig, 0, sizeof(word_sig));
					for (i = idx; i < CLI_PREFIX_KW_NB && args[i] && *args[i]; i++) {
						update_word_fingerprint(word_sig, args[i]);
						totlen += strlen(args[i]);
					}

					memset(list_sig, 0, sizeof(list_sig));
					for (i = idx; i < CLI_PREFIX_KW_NB && kw->str_kw[i]; i++) {
						update_word_fingerprint(list_sig, kw->str_kw[i]);
						totlen += strlen(kw->str_kw[i]);
					}

					dist = word_fingerprint_distance(word_sig, list_sig);

					/* insert this one at its place if relevant, in order to keep only
					 * the best matches.
					 */
					swp.kw = kw; swp.dist = dist;
					if (dist < 5*totlen/2 && dist < matches[CLI_MAX_MATCHES-1].dist) {
						matches[CLI_MAX_MATCHES-1] = swp;
						for (idx = CLI_MAX_MATCHES - 1; --idx >= 0;) {
							if (matches[idx+1].dist >= matches[idx].dist)
								break;
							matches[idx+1] = matches[idx];
							matches[idx] = swp;
						}
					}
				}
			}
		}
	}

	if (matches[0].kw) {
		/* we have fuzzy matches, let's propose them */
		for (idx = 0; idx < CLI_MAX_MATCHES; idx++) {
			kw = matches[idx].kw;
			if (!kw)
				break;

			/* stop the dump if some words look very unlikely candidates */
			if (matches[idx].dist > 5*matches[0].dist/2)
				break;

			if (help_entries < CLI_MAX_HELP_ENTRIES)
				entries[help_entries++] = kw;
		}
	}

	list_for_each_entry(kw_list, &cli_keywords.list, list) {
		/* no full dump if we've already found nice candidates */
		if (matches[0].kw)
			break;

		for (kw = &kw_list->kw[0]; kw->str_kw[0]; kw++) {

			/* in a worker or normal process, don't display master-only commands
			 * nor expert/experimental mode commands if not in this mode.
			 */
			if (kw->level & ~appctx->cli_level & (ACCESS_MASTER_ONLY|ACCESS_EXPERT|ACCESS_EXPERIMENTAL))
				continue;

			/* in master don't display commands that have neither the master bit
			 * nor the master-only bit.
			 */
			if ((appctx->cli_level & ~kw->level & (ACCESS_MASTER_ONLY|ACCESS_MASTER)) ==
			    (ACCESS_MASTER_ONLY|ACCESS_MASTER))
				continue;

			for (idx = 0; idx < length; idx++) {
				if (!kw->str_kw[idx])
					break; // end of keyword
				if (!args || !args[idx] || !*args[idx])
					break; // end of command line
				if (strcmp(kw->str_kw[idx], args[idx]) != 0)
					break;
			}

			if (kw->usage && idx == length && help_entries < CLI_MAX_HELP_ENTRIES)
				entries[help_entries++] = kw;
		}
	}

	qsort(entries, help_entries, sizeof(*entries), cmp_kw_entries);

	for (idx = 0; idx < help_entries; idx++)
		chunk_appendf(tmp, "  %s\n", entries[idx]->usage);

	/* always show the prompt/help/quit commands */
	chunk_strcat(tmp,
	             "  help [<command>]                        : list matching or all commands\n"
	             "  prompt                                  : toggle interactive mode with prompt\n"
	             "  quit                                    : disconnect\n");

	chunk_init(&out, NULL, 0);
	chunk_dup(&out, tmp);
	dynamic_usage_msg = out.area;

	appctx->ctx.cli.severity = LOG_INFO;
	appctx->ctx.cli.msg = dynamic_usage_msg;
	appctx->st0 = CLI_ST_PRINT;

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

struct cli_kw* cli_find_kw_exact(char **args)
{
	struct cli_kw_list *kw_list;
	int found = 0;
	int i;
	int j;

	if (LIST_ISEMPTY(&cli_keywords.list))
		return NULL;

	list_for_each_entry(kw_list, &cli_keywords.list, list) {
		for (i = 0; kw_list->kw[i].str_kw[0]; i++) {
			found = 1;
			for (j = 0; j < CLI_PREFIX_KW_NB; j++) {
				if (args[j] == NULL && kw_list->kw[i].str_kw[j] == NULL) {
					break;
				}
				if (args[j] == NULL || kw_list->kw[i].str_kw[j] == NULL) {
					found = 0;
					break;
				}
				if (strcmp(args[j], kw_list->kw[i].str_kw[j]) != 0) {
					found = 0;
					break;
				}
			}
			if (found)
				return &kw_list->kw[i];
		}
	}
	return NULL;
}

void cli_register_kw(struct cli_kw_list *kw_list)
{
	LIST_APPEND(&cli_keywords.list, &kw_list->list);
}


/* allocate a new stats frontend named <name>, and return it
 * (or NULL in case of lack of memory).
 */
static struct proxy *cli_alloc_fe(const char *name, const char *file, int line)
{
	struct proxy *fe;

	fe = calloc(1, sizeof(*fe));
	if (!fe)
		return NULL;

	init_new_proxy(fe);
	fe->next = proxies_list;
	proxies_list = fe;
	fe->last_change = now.tv_sec;
	fe->id = strdup("GLOBAL");
	fe->cap = PR_CAP_FE|PR_CAP_INT;
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
static int cli_parse_global(char **args, int section_type, struct proxy *curpx,
                            const struct proxy *defpx, const char *file, int line,
                            char **err)
{
	struct bind_conf *bind_conf;
	struct listener *l;

	if (strcmp(args[1], "socket") == 0) {
		int cur_arg;

		if (*args[2] == 0) {
			memprintf(err, "'%s %s' in global section expects an address or a path to a UNIX socket", args[0], args[1]);
			return -1;
		}

		if (!global.cli_fe) {
			if ((global.cli_fe = cli_alloc_fe("GLOBAL", file, line)) == NULL) {
				memprintf(err, "'%s %s' : out of memory trying to allocate a frontend", args[0], args[1]);
				return -1;
			}
		}

		bind_conf = bind_conf_alloc(global.cli_fe, file, line, args[2], xprt_get(XPRT_RAW));
		if (!bind_conf) {
			memprintf(err, "'%s %s' : out of memory trying to allocate a bind_conf", args[0], args[1]);
			return -1;
		}
		bind_conf->level &= ~ACCESS_LVL_MASK;
		bind_conf->level |= ACCESS_LVL_OPER; /* default access level */

		if (!str2listener(args[2], global.cli_fe, bind_conf, file, line, err)) {
			memprintf(err, "parsing [%s:%d] : '%s %s' : %s\n",
			          file, line, args[0], args[1], err && *err ? *err : "error");
			return -1;
		}

		cur_arg = 3;
		while (*args[cur_arg]) {
			struct bind_kw *kw;
			const char *best;
			int code;

			kw = bind_find_kw(args[cur_arg]);
			if (kw) {
				if (!kw->parse) {
					memprintf(err, "'%s %s' : '%s' option is not implemented in this version (check build options).",
						  args[0], args[1], args[cur_arg]);
					return -1;
				}

				code = kw->parse(args, cur_arg, global.cli_fe, bind_conf, err);

				/* FIXME: this is ugly, we don't have a way to collect warnings,
				 * yet some important bind keywords may report warnings that we
				 * must display.
				 */
				if (((code & (ERR_WARN|ERR_FATAL|ERR_ALERT)) == ERR_WARN) && err && *err) {
					indent_msg(err, 2);
					ha_warning("parsing [%s:%d] : '%s %s' : %s\n", file, line, args[0], args[1], *err);
					ha_free(err);
				}

				if (code & ~ERR_WARN) {
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

			best = bind_find_best_kw(args[cur_arg]);
			if (best)
				memprintf(err, "'%s %s' : unknown keyword '%s'. Did you mean '%s' maybe ?",
				          args[0], args[1], args[cur_arg], best);
			else
				memprintf(err, "'%s %s' : unknown keyword '%s'.",
				          args[0], args[1], args[cur_arg]);
			return -1;
		}

		list_for_each_entry(l, &bind_conf->listeners, by_bind) {
			l->accept = session_accept_fd;
			l->default_target = global.cli_fe->default_target;
			l->options |= LI_O_UNLIMITED; /* don't make the peers subject to global limits */
			l->nice = -64;  /* we want to boost priority for local stats */
			global.maxsock++; /* for the listening socket */
		}
	}
	else if (strcmp(args[1], "timeout") == 0) {
		unsigned timeout;
		const char *res = parse_time_err(args[2], &timeout, TIME_UNIT_MS);

		if (res == PARSE_TIME_OVER) {
			memprintf(err, "timer overflow in argument '%s' to '%s %s' (maximum value is 2147483647 ms or ~24.8 days)",
				 args[2], args[0], args[1]);
			return -1;
		}
		else if (res == PARSE_TIME_UNDER) {
			memprintf(err, "timer underflow in argument '%s' to '%s %s' (minimum non-null value is 1 ms)",
				 args[2], args[0], args[1]);
			return -1;
		}
		else if (res) {
			memprintf(err, "'%s %s' : unexpected character '%c'", args[0], args[1], *res);
			return -1;
		}

		if (!timeout) {
			memprintf(err, "'%s %s' expects a positive value", args[0], args[1]);
			return -1;
		}
		if (!global.cli_fe) {
			if ((global.cli_fe = cli_alloc_fe("GLOBAL", file, line)) == NULL) {
				memprintf(err, "'%s %s' : out of memory trying to allocate a frontend", args[0], args[1]);
				return -1;
			}
		}
		global.cli_fe->timeout.client = MS_TO_TICKS(timeout);
	}
	else if (strcmp(args[1], "maxconn") == 0) {
		int maxconn = atol(args[2]);

		if (maxconn <= 0) {
			memprintf(err, "'%s %s' expects a positive value", args[0], args[1]);
			return -1;
		}

		if (!global.cli_fe) {
			if ((global.cli_fe = cli_alloc_fe("GLOBAL", file, line)) == NULL) {
				memprintf(err, "'%s %s' : out of memory trying to allocate a frontend", args[0], args[1]);
				return -1;
			}
		}
		global.cli_fe->maxconn = maxconn;
	}
	else if (strcmp(args[1], "bind-process") == 0) {  /* enable the socket only on some processes */
		int cur_arg = 2;
		unsigned long set = 0;

		if (!global.cli_fe) {
			if ((global.cli_fe = cli_alloc_fe("GLOBAL", file, line)) == NULL) {
				memprintf(err, "'%s %s' : out of memory trying to allocate a frontend", args[0], args[1]);
				return -1;
			}
		}

		while (*args[cur_arg]) {
			if (strcmp(args[cur_arg], "all") == 0) {
				set = 0;
				break;
			}
			if (parse_process_number(args[cur_arg], &set, 1, NULL, err)) {
				memprintf(err, "'%s %s' : %s", args[0], args[1], *err);
				return -1;
			}
			cur_arg++;
		}
	}
	else {
		memprintf(err, "'%s' only supports 'socket', 'maxconn', 'bind-process' and 'timeout' (got '%s')", args[0], args[1]);
		return -1;
	}
	return 0;
}

/*
 * This function exports the bound addresses of a <frontend> in the environment
 * variable <varname>. Those addresses are separated by semicolons and prefixed
 * with their type (abns@, unix@, sockpair@ etc)
 * Return -1 upon error, 0 otherwise
 */
int listeners_setenv(struct proxy *frontend, const char *varname)
{
	struct buffer *trash = get_trash_chunk();
	struct bind_conf *bind_conf;

	if (frontend) {
		list_for_each_entry(bind_conf, &frontend->conf.bind, by_fe) {
			struct listener *l;

			list_for_each_entry(l, &bind_conf->listeners, by_bind) {
				char addr[46];
				char port[6];

				/* separate listener by semicolons */
				if (trash->data)
					chunk_appendf(trash, ";");

				if (l->rx.addr.ss_family == AF_UNIX) {
					const struct sockaddr_un *un;

					un = (struct sockaddr_un *)&l->rx.addr;
					if (un->sun_path[0] == '\0') {
						chunk_appendf(trash, "abns@%s", un->sun_path+1);
					} else {
						chunk_appendf(trash, "unix@%s", un->sun_path);
					}
				} else if (l->rx.addr.ss_family == AF_INET) {
					addr_to_str(&l->rx.addr, addr, sizeof(addr));
					port_to_str(&l->rx.addr, port, sizeof(port));
					chunk_appendf(trash, "ipv4@%s:%s", addr, port);
				} else if (l->rx.addr.ss_family == AF_INET6) {
					addr_to_str(&l->rx.addr, addr, sizeof(addr));
					port_to_str(&l->rx.addr, port, sizeof(port));
					chunk_appendf(trash, "ipv6@[%s]:%s", addr, port);
				} else if (l->rx.addr.ss_family == AF_CUST_SOCKPAIR) {
					chunk_appendf(trash, "sockpair@%d", ((struct sockaddr_in *)&l->rx.addr)->sin_addr.s_addr);
				}
			}
		}
		trash->area[trash->data++] = '\0';
		if (setenv(varname, trash->area, 1) < 0)
			return -1;
	}

	return 0;
}

int cli_socket_setenv()
{
	if (listeners_setenv(global.cli_fe, "HAPROXY_CLI") < 0)
		return -1;
	if (listeners_setenv(mworker_proxy, "HAPROXY_MASTER_CLI") < 0)
		return -1;

	return 0;
}

REGISTER_CONFIG_POSTPARSER("cli", cli_socket_setenv);

/* Verifies that the CLI at least has a level at least as high as <level>
 * (typically ACCESS_LVL_ADMIN). Returns 1 if OK, otherwise 0. In case of
 * failure, an error message is prepared and the appctx's state is adjusted
 * to print it so that a return 1 is enough to abort any processing.
 */
int cli_has_level(struct appctx *appctx, int level)
{

	if ((appctx->cli_level & ACCESS_LVL_MASK) < level) {
		cli_err(appctx, cli_permission_denied_msg);
		return 0;
	}
	return 1;
}

/* same as cli_has_level but for the CLI proxy and without error message */
int pcli_has_level(struct stream *s, int level)
{
	if ((s->pcli_flags & ACCESS_LVL_MASK) < level) {
		return 0;
	}
	return 1;
}

/* Returns severity_output for the current session if set, or default for the socket */
static int cli_get_severity_output(struct appctx *appctx)
{
	if (appctx->cli_severity_output)
		return appctx->cli_severity_output;
	return strm_li(si_strm(appctx->owner))->bind_conf->severity_output;
}

/* Processes the CLI interpreter on the stats socket. This function is called
 * from the CLI's IO handler running in an appctx context. The function returns
 * 1 if the request was understood, otherwise zero (in which case an error
 * message will be displayed). It is called with appctx->st0
 * set to CLI_ST_GETREQ and presets ->st2 to 0 so that parsers don't have to do
 * it. It will possilbly leave st0 to CLI_ST_CALLBACK if the keyword needs to
 * have its own I/O handler called again. Most of the time, parsers will only
 * set st0 to CLI_ST_PRINT and put their message to be displayed into cli.msg.
 * If a keyword parser is NULL and an I/O handler is declared, the I/O handler
 * will automatically be used.
 */
static int cli_parse_request(struct appctx *appctx)
{
	char *args[MAX_CLI_ARGS + 1], *p, *end, *payload = NULL;
	int i = 0;
	struct cli_kw *kw;

	appctx->st2 = 0;
	memset(&appctx->ctx.cli, 0, sizeof(appctx->ctx.cli));

	p = appctx->chunk->area;
	end = p + appctx->chunk->data;

	/*
	 * Get pointers on words.
	 * One extra slot is reserved to store a pointer on a null byte.
	 */
	while (i < MAX_CLI_ARGS && p < end) {
		int j, k;

		/* skip leading spaces/tabs */
		p += strspn(p, " \t");
		if (!*p)
			break;

		if (strcmp(p, PAYLOAD_PATTERN) == 0) {
			/* payload pattern recognized here, this is not an arg anymore,
			 * the payload starts at the first byte that follows the zero
			 * after the pattern.
			 */
			payload = p + strlen(PAYLOAD_PATTERN) + 1;
			break;
		}

		args[i] = p;
		while (1) {
			p += strcspn(p, " \t\\");
			/* escaped chars using backlashes (\) */
			if (*p == '\\') {
				if (!*++p)
					break;
				if (!*++p)
					break;
			} else {
				break;
			}
		}
		*p++ = 0;

		/* unescape backslashes (\) */
		for (j = 0, k = 0; args[i][k]; k++) {
			if (args[i][k] == '\\') {
				if (args[i][k + 1] == '\\')
					k++;
				else
					continue;
			}
			args[i][j] = args[i][k];
			j++;
		}
		args[i][j] = 0;

		i++;
	}
	/* fill unused slots */
	p = appctx->chunk->area + appctx->chunk->data;
	for (; i < MAX_CLI_ARGS + 1; i++)
		args[i] = p;

	kw = cli_find_kw(args);
	if (!kw ||
	    (kw->level & ~appctx->cli_level & ACCESS_MASTER_ONLY) ||
	    (appctx->cli_level & ~kw->level & (ACCESS_MASTER_ONLY|ACCESS_MASTER)) == (ACCESS_MASTER_ONLY|ACCESS_MASTER)) {
		/* keyword not found in this mode */
		cli_gen_usage_msg(appctx, args);
		return 0;
	}

	/* don't handle expert mode commands if not in this mode. */
	if (kw->level & ~appctx->cli_level & ACCESS_EXPERT) {
		cli_err(appctx, "This command is restricted to expert mode only.\n");
		return 0;
	}

	if (kw->level & ~appctx->cli_level & ACCESS_EXPERIMENTAL) {
		cli_err(appctx, "This command is restricted to experimental mode only.\n");
		return 0;
	}

	if (kw->level == ACCESS_EXPERT)
		mark_tainted(TAINTED_CLI_EXPERT_MODE);
	else if (kw->level == ACCESS_EXPERIMENTAL)
		mark_tainted(TAINTED_CLI_EXPERIMENTAL_MODE);

	appctx->io_handler = kw->io_handler;
	appctx->io_release = kw->io_release;

	if (kw->parse && kw->parse(args, payload, appctx, kw->private) != 0)
		goto fail;

	/* kw->parse could set its own io_handler or io_release handler */
	if (!appctx->io_handler)
		goto fail;

	appctx->st0 = CLI_ST_CALLBACK;
	return 1;
fail:
	appctx->io_handler = NULL;
	appctx->io_release = NULL;
	return 1;
}

/* prepends then outputs the argument msg with a syslog-type severity depending on severity_output value */
static int cli_output_msg(struct channel *chn, const char *msg, int severity, int severity_output)
{
	struct buffer *tmp;

	if (likely(severity_output == CLI_SEVERITY_NONE))
		return ci_putblk(chn, msg, strlen(msg));

	tmp = get_trash_chunk();
	chunk_reset(tmp);

	if (severity < 0 || severity > 7) {
		ha_warning("socket command feedback with invalid severity %d", severity);
		chunk_printf(tmp, "[%d]: ", severity);
	}
	else {
		switch (severity_output) {
			case CLI_SEVERITY_NUMBER:
				chunk_printf(tmp, "[%d]: ", severity);
				break;
			case CLI_SEVERITY_STRING:
				chunk_printf(tmp, "[%s]: ", log_levels[severity]);
				break;
			default:
				ha_warning("Unrecognized severity output %d", severity_output);
		}
	}
	chunk_appendf(tmp, "%s", msg);

	return ci_putblk(chn, tmp->area, strlen(tmp->area));
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
	struct bind_conf *bind_conf = strm_li(si_strm(si))->bind_conf;
	int reql;
	int len;

	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		goto out;

	/* Check if the input buffer is available. */
	if (res->buf.size == 0) {
		/* buf.size==0 means we failed to get a buffer and were
		 * already subscribed to a wait list to get a buffer.
		 */
		goto out;
	}

	while (1) {
		if (appctx->st0 == CLI_ST_INIT) {
			/* Stats output not initialized yet */
			memset(&appctx->ctx.stats, 0, sizeof(appctx->ctx.stats));
			/* reset severity to default at init */
			appctx->cli_severity_output = bind_conf->severity_output;
			appctx->st0 = CLI_ST_GETREQ;
			appctx->cli_level = bind_conf->level;
		}
		else if (appctx->st0 == CLI_ST_END) {
			/* Let's close for real now. We just close the request
			 * side, the conditions below will complete if needed.
			 */
			si_shutw(si);
			free_trash_chunk(appctx->chunk);
			appctx->chunk = NULL;
			break;
		}
		else if (appctx->st0 == CLI_ST_GETREQ) {
			char *str;

			/* use a trash chunk to store received data */
			if (!appctx->chunk) {
				appctx->chunk = alloc_trash_chunk();
				if (!appctx->chunk) {
					appctx->st0 = CLI_ST_END;
					continue;
				}
			}

			str = appctx->chunk->area + appctx->chunk->data;

			/* ensure we have some output room left in the event we
			 * would want to return some info right after parsing.
			 */
			if (buffer_almost_full(si_ib(si))) {
				si_rx_room_blk(si);
				break;
			}

			/* payload doesn't take escapes nor does it end on semi-colons, so
			 * we use the regular getline. Normal mode however must stop on
			 * LFs and semi-colons that are not prefixed by a backslash. Note
			 * that we reserve one byte at the end to insert a trailing nul byte.
			 */

			if (appctx->st1 & APPCTX_CLI_ST1_PAYLOAD)
				reql = co_getline(si_oc(si), str,
				                  appctx->chunk->size - appctx->chunk->data - 1);
			else
				reql = co_getdelim(si_oc(si), str,
				                   appctx->chunk->size - appctx->chunk->data - 1,
				                   "\n;", '\\');

			if (reql <= 0) { /* closed or EOL not found */
				if (reql == 0)
					break;
				appctx->st0 = CLI_ST_END;
				continue;
			}

			if (!(appctx->st1 & APPCTX_CLI_ST1_PAYLOAD)) {
				/* seek for a possible unescaped semi-colon. If we find
				 * one, we replace it with an LF and skip only this part.
				 */
				for (len = 0; len < reql; len++) {
					if (str[len] == '\\') {
						len++;
						continue;
					}
					if (str[len] == ';') {
						str[len] = '\n';
						reql = len + 1;
						break;
					}
				}
			}

			/* now it is time to check that we have a full line,
			 * remove the trailing \n and possibly \r, then cut the
			 * line.
			 */
			len = reql - 1;
			if (str[len] != '\n') {
				appctx->st0 = CLI_ST_END;
				continue;
			}

			if (len && str[len-1] == '\r')
				len--;

			str[len] = '\0';
			appctx->chunk->data += len;

			if (appctx->st1 & APPCTX_CLI_ST1_PAYLOAD) {
				appctx->chunk->area[appctx->chunk->data] = '\n';
				appctx->chunk->area[appctx->chunk->data + 1] = 0;
				appctx->chunk->data++;
			}

			appctx->st0 = CLI_ST_PROMPT;

			if (appctx->st1 & APPCTX_CLI_ST1_PAYLOAD) {
				/* empty line */
				if (!len) {
					/* remove the last two \n */
					appctx->chunk->data -= 2;
					appctx->chunk->area[appctx->chunk->data] = 0;
					cli_parse_request(appctx);
					chunk_reset(appctx->chunk);
					/* NB: cli_sock_parse_request() may have put
					 * another CLI_ST_O_* into appctx->st0.
					 */

					appctx->st1 &= ~APPCTX_CLI_ST1_PAYLOAD;
				}
			}
			else {
				/*
				 * Look for the "payload start" pattern at the end of a line
				 * Its location is not remembered here, this is just to switch
				 * to a gathering mode.
				 */
				if (strcmp(appctx->chunk->area + appctx->chunk->data - strlen(PAYLOAD_PATTERN), PAYLOAD_PATTERN) == 0) {
					appctx->st1 |= APPCTX_CLI_ST1_PAYLOAD;
					appctx->chunk->data++; // keep the trailing \0 after '<<'
				}
				else {
					/* no payload, the command is complete: parse the request */
					cli_parse_request(appctx);
					chunk_reset(appctx->chunk);
				}
			}

			/* re-adjust req buffer */
			co_skip(si_oc(si), reql);
			req->flags |= CF_READ_DONTWAIT; /* we plan to read small requests */
		}
		else {	/* output functions */
			const char *msg;
			int sev;

			switch (appctx->st0) {
			case CLI_ST_PROMPT:
				break;
			case CLI_ST_PRINT:       /* print const message in msg */
			case CLI_ST_PRINT_ERR:   /* print const error in msg */
			case CLI_ST_PRINT_DYN:   /* print dyn message in msg, free */
			case CLI_ST_PRINT_FREE:  /* print dyn error in err, free */
				if (appctx->st0 == CLI_ST_PRINT || appctx->st0 == CLI_ST_PRINT_ERR) {
					sev = appctx->st0 == CLI_ST_PRINT_ERR ?
						LOG_ERR : appctx->ctx.cli.severity;
					msg = appctx->ctx.cli.msg;
				}
				else if (appctx->st0 == CLI_ST_PRINT_DYN || appctx->st0 == CLI_ST_PRINT_FREE) {
					sev = appctx->st0 == CLI_ST_PRINT_FREE ?
						LOG_ERR : appctx->ctx.cli.severity;
					msg = appctx->ctx.cli.err;
					if (!msg) {
						sev = LOG_ERR;
						msg = "Out of memory.\n";
					}
				}
				else {
					sev = LOG_ERR;
					msg = "Internal error.\n";
				}

				if (cli_output_msg(res, msg, sev, cli_get_severity_output(appctx)) != -1) {
					if (appctx->st0 == CLI_ST_PRINT_FREE ||
					    appctx->st0 == CLI_ST_PRINT_DYN) {
						ha_free(&appctx->ctx.cli.err);
					}
					appctx->st0 = CLI_ST_PROMPT;
				}
				else
					si_rx_room_blk(si);
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
				const char *prompt = "";

				if (appctx->st1 & APPCTX_CLI_ST1_PROMPT) {
					/*
					 * when entering a payload with interactive mode, change the prompt
					 * to emphasize that more data can still be sent
					 */
					if (appctx->chunk->data && appctx->st1 & APPCTX_CLI_ST1_PAYLOAD)
						prompt = "+ ";
					else
						prompt = "\n> ";
				}
				else {
					if (!(appctx->st1 & (APPCTX_CLI_ST1_PAYLOAD|APPCTX_CLI_ST1_NOLF)))
						prompt = "\n";
				}

				if (ci_putstr(si_ic(si), prompt) != -1)
					appctx->st0 = CLI_ST_GETREQ;
				else
					si_rx_room_blk(si);
			}

			/* If the output functions are still there, it means they require more room. */
			if (appctx->st0 >= CLI_ST_OUTPUT)
				break;

			/* Now we close the output if one of the writers did so,
			 * or if we're not in interactive mode and the request
			 * buffer is empty. This still allows pipelined requests
			 * to be sent in non-interactive mode.
			 */
			if (((res->flags & (CF_SHUTW|CF_SHUTW_NOW))) ||
			   (!(appctx->st1 & APPCTX_CLI_ST1_PROMPT) && !co_data(req) && (!(appctx->st1 & APPCTX_CLI_ST1_PAYLOAD)))) {
				appctx->st0 = CLI_ST_END;
				continue;
			}

			/* switch state back to GETREQ to read next requests */
			appctx->st0 = CLI_ST_GETREQ;
			/* reactivate the \n at the end of the response for the next command */
			appctx->st1 &= ~APPCTX_CLI_ST1_NOLF;

			/* this forces us to yield between pipelined commands and
			 * avoid extremely long latencies (e.g. "del map" etc). In
			 * addition this increases the likelihood that the stream
			 * refills the buffer with new bytes in non-interactive
			 * mode, avoiding to close on apparently empty commands.
			 */
			if (co_data(si_oc(si))) {
				appctx_wakeup(appctx);
				goto out;
			}
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
	DPRINTF(stderr, "%s@%d: st=%d, rqf=%x, rpf=%x, rqh=%lu, rqs=%lu, rh=%lu, rs=%lu\n",
		__FUNCTION__, __LINE__,
		si->state, req->flags, res->flags, ci_data(req), co_data(req), ci_data(res), co_data(res));
}

/* This is called when the stream interface is closed. For instance, upon an
 * external abort, we won't call the i/o handler anymore so we may need to
 * remove back references to the stream currently being dumped.
 */
static void cli_release_handler(struct appctx *appctx)
{
	free_trash_chunk(appctx->chunk);
	appctx->chunk = NULL;

	if (appctx->io_release) {
		appctx->io_release(appctx);
		appctx->io_release = NULL;
	}
	else if (appctx->st0 == CLI_ST_PRINT_FREE || appctx->st0 == CLI_ST_PRINT_DYN) {
		ha_free(&appctx->ctx.cli.err);
	}
}

/* This function dumps all environmnent variables to the buffer. It returns 0
 * if the output buffer is full and it needs to be called again, otherwise
 * non-zero. Dumps only one entry if st2 == STAT_ST_END. It uses cli.p0 as the
 * pointer to the current variable.
 */
static int cli_io_handler_show_env(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	char **var = appctx->ctx.cli.p0;

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		return 1;

	chunk_reset(&trash);

	/* we have two inner loops here, one for the proxy, the other one for
	 * the buffer.
	 */
	while (*var) {
		chunk_printf(&trash, "%s\n", *var);

		if (ci_putchk(si_ic(si), &trash) == -1) {
			si_rx_room_blk(si);
			return 0;
		}
		if (appctx->st2 == STAT_ST_END)
			break;
		var++;
		appctx->ctx.cli.p0 = var;
	}

	/* dump complete */
	return 1;
}

/* This function dumps all file descriptors states (or the requested one) to
 * the buffer. It returns 0 if the output buffer is full and it needs to be
 * called again, otherwise non-zero. Dumps only one entry if st2 == STAT_ST_END.
 * It uses cli.i0 as the fd number to restart from.
 */
static int cli_io_handler_show_fd(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	int fd = appctx->ctx.cli.i0;
	int ret = 1;

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		goto end;

	chunk_reset(&trash);

	/* isolate the threads once per round. We're limited to a buffer worth
	 * of output anyway, it cannot last very long.
	 */
	thread_isolate();

	/* we have two inner loops here, one for the proxy, the other one for
	 * the buffer.
	 */
	while (fd >= 0 && fd < global.maxsock) {
		struct fdtab fdt;
		const struct listener *li = NULL;
		const struct server *sv = NULL;
		const struct proxy *px = NULL;
		const struct connection *conn = NULL;
		const struct mux_ops *mux = NULL;
		const struct xprt_ops *xprt = NULL;
		const void *ctx = NULL;
		const void *xprt_ctx = NULL;
		uint32_t conn_flags = 0;
		int is_back = 0;
		int suspicious = 0;

		fdt = fdtab[fd];

		/* When DEBUG_FD is set, we also report closed FDs that have a
		 * non-null event count to detect stuck ones.
		 */
		if (!fdt.owner) {
#ifdef DEBUG_FD
			if (!fdt.event_count)
#endif
				goto skip; // closed
		}
		else if (fdt.iocb == sock_conn_iocb) {
			conn = (const struct connection *)fdt.owner;
			conn_flags = conn->flags;
			mux        = conn->mux;
			ctx        = conn->ctx;
			xprt       = conn->xprt;
			xprt_ctx   = conn->xprt_ctx;
			li         = objt_listener(conn->target);
			sv         = objt_server(conn->target);
			px         = objt_proxy(conn->target);
			is_back    = conn_is_back(conn);
			if (atleast2(fdt.thread_mask))
				suspicious = 1;
			if (conn->handle.fd != fd)
				suspicious = 1;
		}
		else if (fdt.iocb == sock_accept_iocb)
			li = fdt.owner;

		if (!fdt.thread_mask)
			suspicious = 1;

		chunk_printf(&trash,
			     "  %5d : st=0x%06x(%c%c %c%c%c%c%c W:%c%c%c R:%c%c%c) tmask=0x%lx umask=0x%lx owner=%p iocb=%p(",
			     fd,
			     fdt.state,
			     (fdt.state & FD_CLONED) ? 'C' : 'c',
			     (fdt.state & FD_LINGER_RISK) ? 'L' : 'l',
			     (fdt.state & FD_POLL_HUP) ? 'H' : 'h',
			     (fdt.state & FD_POLL_ERR) ? 'E' : 'e',
			     (fdt.state & FD_POLL_OUT) ? 'O' : 'o',
			     (fdt.state & FD_POLL_PRI) ? 'P' : 'p',
			     (fdt.state & FD_POLL_IN)  ? 'I' : 'i',
			     (fdt.state & FD_EV_SHUT_W) ? 'S' : 's',
			     (fdt.state & FD_EV_READY_W)  ? 'R' : 'r',
			     (fdt.state & FD_EV_ACTIVE_W) ? 'A' : 'a',
			     (fdt.state & FD_EV_SHUT_R) ? 'S' : 's',
			     (fdt.state & FD_EV_READY_R)  ? 'R' : 'r',
			     (fdt.state & FD_EV_ACTIVE_R) ? 'A' : 'a',
			     fdt.thread_mask, fdt.update_mask,
			     fdt.owner,
			     fdt.iocb);
		resolve_sym_name(&trash, NULL, fdt.iocb);

		if (!fdt.owner) {
			chunk_appendf(&trash, ")");
		}
		else if (fdt.iocb == sock_conn_iocb) {
			chunk_appendf(&trash, ") back=%d cflg=0x%08x", is_back, conn_flags);

			if (conn->handle.fd != fd) {
				chunk_appendf(&trash, " fd=%d(BOGUS)", conn->handle.fd);
				suspicious = 1;
			} else {
				struct sockaddr_storage sa;
				socklen_t salen;

				salen = sizeof(sa);
				if (getsockname(fd, (struct sockaddr *)&sa, &salen) != -1) {
					if (sa.ss_family == AF_INET)
						chunk_appendf(&trash, " fam=ipv4 lport=%d", ntohs(((const struct sockaddr_in *)&sa)->sin_port));
					else if (sa.ss_family == AF_INET6)
						chunk_appendf(&trash, " fam=ipv6 lport=%d", ntohs(((const struct sockaddr_in6 *)&sa)->sin6_port));
					else if (sa.ss_family == AF_UNIX)
						chunk_appendf(&trash, " fam=unix");
				}

				salen = sizeof(sa);
				if (getpeername(fd, (struct sockaddr *)&sa, &salen) != -1) {
					if (sa.ss_family == AF_INET)
						chunk_appendf(&trash, " rport=%d", ntohs(((const struct sockaddr_in *)&sa)->sin_port));
					else if (sa.ss_family == AF_INET6)
						chunk_appendf(&trash, " rport=%d", ntohs(((const struct sockaddr_in6 *)&sa)->sin6_port));
				}
			}

			if (px)
				chunk_appendf(&trash, " px=%s", px->id);
			else if (sv)
				chunk_appendf(&trash, " sv=%s/%s", sv->proxy->id, sv->id);
			else if (li)
				chunk_appendf(&trash, " fe=%s", li->bind_conf->frontend->id);

			if (mux) {
				chunk_appendf(&trash, " mux=%s ctx=%p", mux->name, ctx);
				if (!ctx)
					suspicious = 1;
				if (mux->show_fd)
					suspicious |= mux->show_fd(&trash, fdt.owner);
			}
			else
				chunk_appendf(&trash, " nomux");

			chunk_appendf(&trash, " xprt=%s", xprt ? xprt->name : "");
			if (xprt) {
				if (xprt_ctx || xprt->show_fd)
					chunk_appendf(&trash, " xprt_ctx=%p", xprt_ctx);
				if (xprt->show_fd)
					suspicious |= xprt->show_fd(&trash, conn, xprt_ctx);
			}
		}
		else if (fdt.iocb == sock_accept_iocb) {
			struct sockaddr_storage sa;
			socklen_t salen;

			chunk_appendf(&trash, ") l.st=%s fe=%s",
			              listener_state_str(li),
			              li->bind_conf->frontend->id);

			salen = sizeof(sa);
			if (getsockname(fd, (struct sockaddr *)&sa, &salen) != -1) {
				if (sa.ss_family == AF_INET)
					chunk_appendf(&trash, " fam=ipv4 lport=%d", ntohs(((const struct sockaddr_in *)&sa)->sin_port));
				else if (sa.ss_family == AF_INET6)
					chunk_appendf(&trash, " fam=ipv6 lport=%d", ntohs(((const struct sockaddr_in6 *)&sa)->sin6_port));
				else if (sa.ss_family == AF_UNIX)
					chunk_appendf(&trash, " fam=unix");
			}
		}
		else
			chunk_appendf(&trash, ")");

#ifdef DEBUG_FD
		chunk_appendf(&trash, " evcnt=%u", fdtab[fd].event_count);
		if (fdtab[fd].event_count >= 1000000)
			suspicious = 1;
#endif
		chunk_appendf(&trash, "%s\n", suspicious ? " !" : "");

		if (ci_putchk(si_ic(si), &trash) == -1) {
			si_rx_room_blk(si);
			appctx->ctx.cli.i0 = fd;
			ret = 0;
			break;
		}
	skip:
		if (appctx->st2 == STAT_ST_END)
			break;

		fd++;
	}

 end:
	/* dump complete */

	thread_release();
	return ret;
}

/* This function dumps some activity counters used by developers and support to
 * rule out some hypothesis during bug reports. It returns 0 if the output
 * buffer is full and it needs to be called again, otherwise non-zero. It dumps
 * everything at once in the buffer and is not designed to do it in multiple
 * passes.
 */
static int cli_io_handler_show_activity(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	int thr;

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		return 1;

	chunk_reset(&trash);

#undef SHOW_TOT
#define SHOW_TOT(t, x)							\
	do {								\
		unsigned int _v[MAX_THREADS];				\
		unsigned int _tot;					\
		const unsigned int _nbt = global.nbthread;		\
		_tot = t = 0;						\
		do {							\
			_tot += _v[t] = (x);				\
		} while (++t < _nbt);					\
		if (_nbt == 1) {					\
			chunk_appendf(&trash, " %u\n", _tot);		\
			break;						\
		}							\
		chunk_appendf(&trash, " %u [", _tot);			\
		for (t = 0; t < _nbt; t++)				\
			chunk_appendf(&trash, " %u", _v[t]);		\
		chunk_appendf(&trash, " ]\n");				\
	} while (0)

#undef SHOW_AVG
#define SHOW_AVG(t, x)							\
	do {								\
		unsigned int _v[MAX_THREADS];				\
		unsigned int _tot;					\
		const unsigned int _nbt = global.nbthread;		\
		_tot = t = 0;						\
		do {							\
			_tot += _v[t] = (x);				\
		} while (++t < _nbt);					\
		if (_nbt == 1) {					\
			chunk_appendf(&trash, " %u\n", _tot);		\
			break;						\
		}							\
		chunk_appendf(&trash, " %u [", (_tot + _nbt/2) / _nbt); \
		for (t = 0; t < _nbt; t++)				\
			chunk_appendf(&trash, " %u", _v[t]);		\
		chunk_appendf(&trash, " ]\n");				\
	} while (0)

	chunk_appendf(&trash, "thread_id: %u (%u..%u)\n", tid + 1, 1, global.nbthread);
	chunk_appendf(&trash, "date_now: %lu.%06lu\n", (long)now.tv_sec, (long)now.tv_usec);
	chunk_appendf(&trash, "ctxsw:");        SHOW_TOT(thr, activity[thr].ctxsw);
	chunk_appendf(&trash, "tasksw:");       SHOW_TOT(thr, activity[thr].tasksw);
	chunk_appendf(&trash, "empty_rq:");     SHOW_TOT(thr, activity[thr].empty_rq);
	chunk_appendf(&trash, "long_rq:");      SHOW_TOT(thr, activity[thr].long_rq);
	chunk_appendf(&trash, "loops:");        SHOW_TOT(thr, activity[thr].loops);
	chunk_appendf(&trash, "wake_tasks:");   SHOW_TOT(thr, activity[thr].wake_tasks);
	chunk_appendf(&trash, "wake_signal:");  SHOW_TOT(thr, activity[thr].wake_signal);
	chunk_appendf(&trash, "poll_io:");      SHOW_TOT(thr, activity[thr].poll_io);
	chunk_appendf(&trash, "poll_exp:");     SHOW_TOT(thr, activity[thr].poll_exp);
	chunk_appendf(&trash, "poll_drop_fd:"); SHOW_TOT(thr, activity[thr].poll_drop_fd);
	chunk_appendf(&trash, "poll_skip_fd:"); SHOW_TOT(thr, activity[thr].poll_skip_fd);
	chunk_appendf(&trash, "conn_dead:");    SHOW_TOT(thr, activity[thr].conn_dead);
	chunk_appendf(&trash, "stream_calls:"); SHOW_TOT(thr, activity[thr].stream_calls);
	chunk_appendf(&trash, "pool_fail:");    SHOW_TOT(thr, activity[thr].pool_fail);
	chunk_appendf(&trash, "buf_wait:");     SHOW_TOT(thr, activity[thr].buf_wait);
	chunk_appendf(&trash, "cpust_ms_tot:"); SHOW_TOT(thr, activity[thr].cpust_total / 2);
	chunk_appendf(&trash, "cpust_ms_1s:");  SHOW_TOT(thr, read_freq_ctr(&activity[thr].cpust_1s) / 2);
	chunk_appendf(&trash, "cpust_ms_15s:"); SHOW_TOT(thr, read_freq_ctr_period(&activity[thr].cpust_15s, 15000) / 2);
	chunk_appendf(&trash, "avg_loop_us:");  SHOW_AVG(thr, swrate_avg(activity[thr].avg_loop_us, TIME_STATS_SAMPLES));
	chunk_appendf(&trash, "accepted:");     SHOW_TOT(thr, activity[thr].accepted);
	chunk_appendf(&trash, "accq_pushed:");  SHOW_TOT(thr, activity[thr].accq_pushed);
	chunk_appendf(&trash, "accq_full:");    SHOW_TOT(thr, activity[thr].accq_full);
#ifdef USE_THREAD
	chunk_appendf(&trash, "accq_ring:");    SHOW_TOT(thr, (accept_queue_rings[thr].tail - accept_queue_rings[thr].head + ACCEPT_QUEUE_SIZE) % ACCEPT_QUEUE_SIZE);
	chunk_appendf(&trash, "fd_takeover:");  SHOW_TOT(thr, activity[thr].fd_takeover);
#endif

#if defined(DEBUG_DEV)
	/* keep these ones at the end */
	chunk_appendf(&trash, "ctr0:");         SHOW_TOT(thr, activity[thr].ctr0);
	chunk_appendf(&trash, "ctr1:");         SHOW_TOT(thr, activity[thr].ctr1);
	chunk_appendf(&trash, "ctr2:");         SHOW_TOT(thr, activity[thr].ctr2);
#endif

	if (ci_putchk(si_ic(si), &trash) == -1) {
		chunk_reset(&trash);
		chunk_printf(&trash, "[output too large, cannot dump]\n");
		si_rx_room_blk(si);
	}

#undef SHOW_AVG
#undef SHOW_TOT
	/* dump complete */
	return 1;
}

/*
 * CLI IO handler for `show cli sockets`.
 * Uses ctx.cli.p0 to store the restart pointer.
 */
static int cli_io_handler_show_cli_sock(struct appctx *appctx)
{
	struct bind_conf *bind_conf;
	struct stream_interface *si = appctx->owner;

	chunk_reset(&trash);

	switch (appctx->st2) {
		case STAT_ST_INIT:
			chunk_printf(&trash, "# socket lvl processes\n");
			if (ci_putchk(si_ic(si), &trash) == -1) {
				si_rx_room_blk(si);
				return 0;
			}
			appctx->st2 = STAT_ST_LIST;
			/* fall through */

		case STAT_ST_LIST:
			if (global.cli_fe) {
				list_for_each_entry(bind_conf, &global.cli_fe->conf.bind, by_fe) {
					struct listener *l;

					/*
					 * get the latest dumped node in appctx->ctx.cli.p0
					 * if the current node is the first of the list
					 */

					if (appctx->ctx.cli.p0  &&
					    &bind_conf->by_fe == (&global.cli_fe->conf.bind)->n) {
						/* change the current node to the latest dumped and continue the loop */
						bind_conf = LIST_ELEM(appctx->ctx.cli.p0, typeof(bind_conf), by_fe);
						continue;
					}

					list_for_each_entry(l, &bind_conf->listeners, by_bind) {

						char addr[46];
						char port[6];

						if (l->rx.addr.ss_family == AF_UNIX) {
							const struct sockaddr_un *un;

							un = (struct sockaddr_un *)&l->rx.addr;
							if (un->sun_path[0] == '\0') {
								chunk_appendf(&trash, "abns@%s ", un->sun_path+1);
							} else {
								chunk_appendf(&trash, "unix@%s ", un->sun_path);
							}
						} else if (l->rx.addr.ss_family == AF_INET) {
							addr_to_str(&l->rx.addr, addr, sizeof(addr));
							port_to_str(&l->rx.addr, port, sizeof(port));
							chunk_appendf(&trash, "ipv4@%s:%s ", addr, port);
						} else if (l->rx.addr.ss_family == AF_INET6) {
							addr_to_str(&l->rx.addr, addr, sizeof(addr));
							port_to_str(&l->rx.addr, port, sizeof(port));
							chunk_appendf(&trash, "ipv6@[%s]:%s ", addr, port);
						} else if (l->rx.addr.ss_family == AF_CUST_SOCKPAIR) {
							chunk_appendf(&trash, "sockpair@%d ", ((struct sockaddr_in *)&l->rx.addr)->sin_addr.s_addr);
						} else
							chunk_appendf(&trash, "unknown ");

						if ((bind_conf->level & ACCESS_LVL_MASK) == ACCESS_LVL_ADMIN)
							chunk_appendf(&trash, "admin ");
						else if ((bind_conf->level & ACCESS_LVL_MASK) == ACCESS_LVL_OPER)
							chunk_appendf(&trash, "operator ");
						else if ((bind_conf->level & ACCESS_LVL_MASK) == ACCESS_LVL_USER)
							chunk_appendf(&trash, "user ");
						else
							chunk_appendf(&trash, "  ");

						chunk_appendf(&trash, "all\n");

						if (ci_putchk(si_ic(si), &trash) == -1) {
							si_rx_room_blk(si);
							return 0;
						}
					}
					appctx->ctx.cli.p0 = &bind_conf->by_fe; /* store the latest list node dumped */
				}
			}
			/* fall through */
		default:
			appctx->st2 = STAT_ST_FIN;
			return 1;
	}
}


/* parse a "show env" CLI request. Returns 0 if it needs to continue, 1 if it
 * wants to stop here. It puts the variable to be dumped into cli.p0 if a single
 * variable is requested otherwise puts environ there.
 */
static int cli_parse_show_env(char **args, char *payload, struct appctx *appctx, void *private)
{
	extern char **environ;
	char **var;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	var = environ;

	if (*args[2]) {
		int len = strlen(args[2]);

		for (; *var; var++) {
			if (strncmp(*var, args[2], len) == 0 &&
			    (*var)[len] == '=')
				break;
		}
		if (!*var)
			return cli_err(appctx, "Variable not found\n");

		appctx->st2 = STAT_ST_END;
	}
	appctx->ctx.cli.p0 = var;
	return 0;
}

/* parse a "show fd" CLI request. Returns 0 if it needs to continue, 1 if it
 * wants to stop here. It puts the FD number into cli.i0 if a specific FD is
 * requested and sets st2 to STAT_ST_END, otherwise leaves 0 in i0.
 */
static int cli_parse_show_fd(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	appctx->ctx.cli.i0 = 0;

	if (*args[2]) {
		appctx->ctx.cli.i0 = atoi(args[2]);
		appctx->st2 = STAT_ST_END;
	}
	return 0;
}

/* parse a "set timeout" CLI request. It always returns 1. */
static int cli_parse_set_timeout(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct stream_interface *si = appctx->owner;
	struct stream *s = si_strm(si);

	if (strcmp(args[2], "cli") == 0) {
		unsigned timeout;
		const char *res;

		if (!*args[3])
			return cli_err(appctx, "Expects an integer value.\n");

		res = parse_time_err(args[3], &timeout, TIME_UNIT_S);
		if (res || timeout < 1)
			return cli_err(appctx, "Invalid timeout value.\n");

		s->req.rto = s->res.wto = 1 + MS_TO_TICKS(timeout*1000);
		task_wakeup(s->task, TASK_WOKEN_MSG); // recompute timeouts
		return 1;
	}

	return cli_err(appctx, "'set timeout' only supports 'cli'.\n");
}

/* parse a "set maxconn global" command. It always returns 1. */
static int cli_parse_set_maxconn_global(char **args, char *payload, struct appctx *appctx, void *private)
{
	int v;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "Expects an integer value.\n");

	v = atoi(args[3]);
	if (v > global.hardmaxconn)
		return cli_err(appctx, "Value out of range.\n");

	/* check for unlimited values */
	if (v <= 0)
		v = global.hardmaxconn;

	global.maxconn = v;

	/* Dequeues all of the listeners waiting for a resource */
	dequeue_all_listeners();

	return 1;
}

static int set_severity_output(int *target, char *argument)
{
	if (strcmp(argument, "none") == 0) {
		*target = CLI_SEVERITY_NONE;
		return 1;
	}
	else if (strcmp(argument, "number") == 0) {
		*target = CLI_SEVERITY_NUMBER;
		return 1;
	}
	else if (strcmp(argument, "string") == 0) {
		*target = CLI_SEVERITY_STRING;
		return 1;
	}
	return 0;
}

/* parse a "set severity-output" command. */
static int cli_parse_set_severity_output(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (*args[2] && set_severity_output(&appctx->cli_severity_output, args[2]))
		return 0;

	return cli_err(appctx, "one of 'none', 'number', 'string' is a required argument\n");
}


/* show the level of the current CLI session */
static int cli_parse_show_lvl(char **args, char *payload, struct appctx *appctx, void *private)
{
	if ((appctx->cli_level & ACCESS_LVL_MASK) == ACCESS_LVL_ADMIN)
		return cli_msg(appctx, LOG_INFO, "admin\n");
	else if ((appctx->cli_level & ACCESS_LVL_MASK) == ACCESS_LVL_OPER)
		return cli_msg(appctx, LOG_INFO, "operator\n");
	else if ((appctx->cli_level & ACCESS_LVL_MASK) == ACCESS_LVL_USER)
		return cli_msg(appctx, LOG_INFO, "user\n");
	else
		return cli_msg(appctx, LOG_INFO, "unknown\n");
}

/* parse and set the CLI level dynamically */
static int cli_parse_set_lvl(char **args, char *payload, struct appctx *appctx, void *private)
{
	/* this will ask the applet to not output a \n after the command */
	if (strcmp(args[1], "-") == 0)
	    appctx->st1 |= APPCTX_CLI_ST1_NOLF;

	if (strcmp(args[0], "operator") == 0) {
		if (!cli_has_level(appctx, ACCESS_LVL_OPER)) {
			return 1;
		}
		appctx->cli_level &= ~ACCESS_LVL_MASK;
		appctx->cli_level |= ACCESS_LVL_OPER;

	} else if (strcmp(args[0], "user") == 0) {
		if (!cli_has_level(appctx, ACCESS_LVL_USER)) {
			return 1;
		}
		appctx->cli_level &= ~ACCESS_LVL_MASK;
		appctx->cli_level |= ACCESS_LVL_USER;
	}
	appctx->cli_level &= ~(ACCESS_EXPERT|ACCESS_EXPERIMENTAL);
	return 1;
}


/* parse and set the CLI expert/experimental-mode dynamically */
static int cli_parse_expert_experimental_mode(char **args, char *payload, struct appctx *appctx, void *private)
{
	int level;
	char *level_str;
	char *output = NULL;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (strcmp(args[0], "expert-mode") == 0) {
		level = ACCESS_EXPERT;
		level_str = "expert-mode";
	}
	else if (strcmp(args[0], "experimental-mode") == 0) {
		level = ACCESS_EXPERIMENTAL;
		level_str = "experimental-mode";
	}
	else {
		return 1;
	}

	if (!*args[1]) {
		memprintf(&output, "%s is %s\n", level_str,
		          (appctx->cli_level & level) ? "ON" : "OFF");
		return cli_dynmsg(appctx, LOG_INFO, output);
	}

	appctx->cli_level &= ~level;
	if (strcmp(args[1], "on") == 0)
		appctx->cli_level |= level;
	return 1;
}

/* shows HAProxy version */
static int cli_parse_show_version(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *msg = NULL;

	return cli_dynmsg(appctx, LOG_INFO, memprintf(&msg, "%s\n", haproxy_version));
}

int cli_parse_default(char **args, char *payload, struct appctx *appctx, void *private)
{
	return 0;
}

/* parse a "set rate-limit" command. It always returns 1. */
static int cli_parse_set_ratelimit(char **args, char *payload, struct appctx *appctx, void *private)
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
		return cli_err(appctx,
			"'set rate-limit' only supports :\n"
			"   - 'connections global' to set the per-process maximum connection rate\n"
			"   - 'sessions global' to set the per-process maximum session rate\n"
#ifdef USE_OPENSSL
			"   - 'ssl-sessions global' to set the per-process maximum SSL session rate\n"
#endif
			"   - 'http-compression global' to set the per-process maximum compression speed in kB/s\n");
	}

	if (!*args[4])
		return cli_err(appctx, "Expects an integer value.\n");

	v = atoi(args[4]);
	if (v < 0)
		return cli_err(appctx, "Value out of range.\n");

	*res = v * mul;

	/* Dequeues all of the listeners waiting for a resource */
	dequeue_all_listeners();

	return 1;
}

/* parse the "expose-fd" argument on the bind lines */
static int bind_parse_expose_fd(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing fd type", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (strcmp(args[cur_arg + 1], "listeners") == 0) {
		conf->level |= ACCESS_FD_LISTENERS;
	} else {
		memprintf(err, "'%s' only supports 'listeners' (got '%s')",
			  args[cur_arg], args[cur_arg+1]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* parse the "level" argument on the bind lines */
static int bind_parse_level(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing level", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(args[cur_arg + 1], "user") == 0) {
		conf->level &= ~ACCESS_LVL_MASK;
		conf->level |= ACCESS_LVL_USER;
	} else if (strcmp(args[cur_arg + 1], "operator") == 0) {
		conf->level &= ~ACCESS_LVL_MASK;
		conf->level |= ACCESS_LVL_OPER;
	} else if (strcmp(args[cur_arg + 1], "admin") == 0) {
		conf->level &= ~ACCESS_LVL_MASK;
		conf->level |= ACCESS_LVL_ADMIN;
	} else {
		memprintf(err, "'%s' only supports 'user', 'operator', and 'admin' (got '%s')",
			  args[cur_arg], args[cur_arg+1]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

static int bind_parse_severity_output(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing severity format", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (set_severity_output(&conf->severity_output, args[cur_arg+1]))
		return 0;
	else {
		memprintf(err, "'%s' only supports 'none', 'number', and 'string' (got '%s')",
				args[cur_arg], args[cur_arg+1]);
		return ERR_ALERT | ERR_FATAL;
	}
}

/* Send all the bound sockets, always returns 1 */
static int _getsocks(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *cmsgbuf = NULL;
	unsigned char *tmpbuf = NULL;
	struct cmsghdr *cmsg;
	struct stream_interface *si = appctx->owner;
	struct stream *s = si_strm(si);
	struct connection *remote = cs_conn(objt_cs(si_opposite(si)->end));
	struct msghdr msghdr;
	struct iovec iov;
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	const char *ns_name, *if_name;
	unsigned char ns_nlen, if_nlen;
	int nb_queued;
	int cur_fd = 0;
	int *tmpfd;
	int tot_fd_nb = 0;
	int fd = -1;
	int curoff = 0;
	int old_fcntl = -1;
	int ret;

	if (!remote) {
		ha_warning("Only works on real connections\n");
		goto out;
	}

	fd = remote->handle.fd;

	/* Temporary set the FD in blocking mode, that will make our life easier */
	old_fcntl = fcntl(fd, F_GETFL);
	if (old_fcntl < 0) {
		ha_warning("Couldn't get the flags for the unix socket\n");
		goto out;
	}
	cmsgbuf = malloc(CMSG_SPACE(sizeof(int) * MAX_SEND_FD));
	if (!cmsgbuf) {
		ha_warning("Failed to allocate memory to send sockets\n");
		goto out;
	}
	if (fcntl(fd, F_SETFL, old_fcntl &~ O_NONBLOCK) == -1) {
		ha_warning("Cannot make the unix socket blocking\n");
		goto out;
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (void *)&tv, sizeof(tv));
	iov.iov_base = &tot_fd_nb;
	iov.iov_len = sizeof(tot_fd_nb);
	if (!(strm_li(s)->bind_conf->level & ACCESS_FD_LISTENERS))
		goto out;
	memset(&msghdr, 0, sizeof(msghdr));
	/*
	 * First, calculates the total number of FD, so that we can let
	 * the caller know how much it should expect.
	 */
	for (cur_fd = 0;cur_fd < global.maxsock; cur_fd++)
		tot_fd_nb += !!(fdtab[cur_fd].state & FD_EXPORTED);

	if (tot_fd_nb == 0)
		goto out;

	/* First send the total number of file descriptors, so that the
	 * receiving end knows what to expect.
	 */
	msghdr.msg_iov = &iov;
	msghdr.msg_iovlen = 1;
	ret = sendmsg(fd, &msghdr, 0);
	if (ret != sizeof(tot_fd_nb)) {
		ha_warning("Failed to send the number of sockets to send\n");
		goto out;
	}

	/* Now send the fds */
	msghdr.msg_control = cmsgbuf;
	msghdr.msg_controllen = CMSG_SPACE(sizeof(int) * MAX_SEND_FD);
	cmsg = CMSG_FIRSTHDR(&msghdr);
	cmsg->cmsg_len = CMSG_LEN(MAX_SEND_FD * sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	tmpfd = (int *)CMSG_DATA(cmsg);

	/* For each socket, e message is sent, containing the following :
	 *  Size of the namespace name (or 0 if none), as an unsigned char.
	 *  The namespace name, if any
	 *  Size of the interface name (or 0 if none), as an unsigned char
	 *  The interface name, if any
	 *  32 bits of zeroes (used to be listener options).
	 */
	/* We will send sockets MAX_SEND_FD per MAX_SEND_FD, allocate a
	 * buffer big enough to store the socket information.
	 */
	tmpbuf = malloc(MAX_SEND_FD * (1 + MAXPATHLEN + 1 + IFNAMSIZ + sizeof(int)));
	if (tmpbuf == NULL) {
		ha_warning("Failed to allocate memory to transfer socket information\n");
		goto out;
	}

	nb_queued = 0;
	iov.iov_base = tmpbuf;
	for (cur_fd = 0; cur_fd < global.maxsock; cur_fd++) {
		if (!(fdtab[cur_fd].state & FD_EXPORTED))
			continue;

		ns_name = if_name = "";
		ns_nlen = if_nlen = 0;

		/* for now we can only retrieve namespaces and interfaces from
		 * pure listeners.
		 */
		if (fdtab[cur_fd].iocb == sock_accept_iocb) {
			const struct listener *l = fdtab[cur_fd].owner;

			if (l->rx.settings->interface) {
				if_name = l->rx.settings->interface;
				if_nlen = strlen(if_name);
			}

#ifdef USE_NS
			if (l->rx.settings->netns) {
				ns_name = l->rx.settings->netns->node.key;
				ns_nlen = l->rx.settings->netns->name_len;
			}
#endif
		}

		/* put the FD into the CMSG_DATA */
		tmpfd[nb_queued++] = cur_fd;

		/* first block is <ns_name_len> <ns_name> */
		tmpbuf[curoff++] = ns_nlen;
		if (ns_nlen)
			memcpy(tmpbuf + curoff, ns_name, ns_nlen);
		curoff += ns_nlen;

		/* second block is <if_name_len> <if_name> */
		tmpbuf[curoff++] = if_nlen;
		if (if_nlen)
			memcpy(tmpbuf + curoff, if_name, if_nlen);
		curoff += if_nlen;

		/* we used to send the listener options here before 2.3 */
		memset(tmpbuf + curoff, 0, sizeof(int));
		curoff += sizeof(int);

		/* there's a limit to how many FDs may be sent at once */
		if (nb_queued == MAX_SEND_FD) {
			iov.iov_len = curoff;
			if (sendmsg(fd, &msghdr, 0) != curoff) {
				ha_warning("Failed to transfer sockets\n");
				return -1;
			}

			/* Wait for an ack */
			do {
				ret = recv(fd, &tot_fd_nb, sizeof(tot_fd_nb), 0);
			} while (ret == -1 && errno == EINTR);

			if (ret <= 0) {
				ha_warning("Unexpected error while transferring sockets\n");
				return -1;
			}
			curoff = 0;
			nb_queued = 0;
		}
	}

	/* flush pending stuff */
	if (nb_queued) {
		iov.iov_len = curoff;
		cmsg->cmsg_len = CMSG_LEN(nb_queued * sizeof(int));
		msghdr.msg_controllen = CMSG_SPACE(nb_queued * sizeof(int));
		if (sendmsg(fd, &msghdr, 0) != curoff) {
			ha_warning("Failed to transfer sockets\n");
			goto out;
		}
	}

out:
	if (fd >= 0 && old_fcntl >= 0 && fcntl(fd, F_SETFL, old_fcntl) == -1) {
		ha_warning("Cannot make the unix socket non-blocking\n");
		goto out;
	}
	appctx->st0 = CLI_ST_END;
	free(cmsgbuf);
	free(tmpbuf);
	return 1;
}

static int cli_parse_simple(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (*args[0] == 'h')
		/* help */
		cli_gen_usage_msg(appctx, args);
	else if (*args[0] == 'p')
		/* prompt */
		appctx->st1 ^= APPCTX_CLI_ST1_PROMPT;
	else if (*args[0] == 'q')
		/* quit */
		appctx->st0 = CLI_ST_END;

	return 1;
}

void pcli_write_prompt(struct stream *s)
{
	struct buffer *msg = get_trash_chunk();
	struct channel *oc = si_oc(&s->si[0]);

	if (!(s->pcli_flags & PCLI_F_PROMPT))
		return;

	if (s->pcli_flags & PCLI_F_PAYLOAD) {
		chunk_appendf(msg, "+ ");
	} else {
		if (s->pcli_next_pid == 0)
			chunk_appendf(msg, "master%s> ",
			              (proc_self->failedreloads > 0) ? "[ReloadFailed]" : "");
		else
			chunk_appendf(msg, "%d> ", s->pcli_next_pid);
	}
	co_inject(oc, msg->area, msg->data);
}


/* The pcli_* functions are used for the CLI proxy in the master */

void pcli_reply_and_close(struct stream *s, const char *msg)
{
	struct buffer *buf = get_trash_chunk();

	chunk_initstr(buf, msg);
	si_retnclose(&s->si[0], buf);
}

static enum obj_type *pcli_pid_to_server(int proc_pid)
{
	struct mworker_proc *child;

	/* return the  mCLI applet of the master */
	if (proc_pid == 0)
		return &mcli_applet.obj_type;

	list_for_each_entry(child, &proc_list, list) {
		if (child->pid == proc_pid){
			return &child->srv->obj_type;
		}
	}
	return NULL;
}

/* Take a CLI prefix in argument (eg: @!1234 @master @1)
 *  Return:
 *     0: master
 *   > 0: pid of a worker
 *   < 0: didn't find a worker
 */
static int pcli_prefix_to_pid(const char *prefix)
{
	int proc_pid;
	struct mworker_proc *child;
	char *errtol = NULL;

	if (*prefix != '@') /* not a prefix, should not happen */
		return -1;

	prefix++;
	if (!*prefix)    /* sent @ alone, return the master */
		return 0;

	if (strcmp("master", prefix) == 0) {
		return 0;
	} else if (*prefix == '!') {
		prefix++;
		if (!*prefix)
			return -1;

		proc_pid = strtol(prefix, &errtol, 10);
		if (*errtol != '\0')
			return -1;
		list_for_each_entry(child, &proc_list, list) {
			if (!(child->options & PROC_O_TYPE_WORKER))
				continue;
			if (child->pid == proc_pid){
				return child->pid;
			}
		}
	} else {
		struct mworker_proc *chosen = NULL;
		/* this is a relative pid */

		proc_pid = strtol(prefix, &errtol, 10);
		if (*errtol != '\0')
			return -1;

		if (proc_pid == 0) /* return the master */
			return 0;

		/* chose the right process, the current one is the one with the
		 least number of reloads */
		list_for_each_entry(child, &proc_list, list) {
			if (!(child->options & PROC_O_TYPE_WORKER))
				continue;
			if (child->reloads == 0)
				return child->pid;
			else if (chosen == NULL || child->reloads < chosen->reloads)
				chosen = child;
		}
		if (chosen)
			return chosen->pid;
	}
	return -1;
}

/* Return::
 *  >= 0 : number of words to escape
 *  = -1 : error
 */

int pcli_find_and_exec_kw(struct stream *s, char **args, int argl, char **errmsg, int *next_pid)
{
	if (argl < 1)
		return 0;

	/* there is a prefix */
	if (args[0][0] == '@') {
		int target_pid = pcli_prefix_to_pid(args[0]);

		if (target_pid == -1) {
			memprintf(errmsg, "Can't find the target PID matching the prefix '%s'\n", args[0]);
			return -1;
		}

		/* if the prefix is alone, define a default target */
		if (argl == 1)
			s->pcli_next_pid = target_pid;
		else
			*next_pid = target_pid;
		return 1;
	} else if (strcmp("prompt", args[0]) == 0) {
		s->pcli_flags ^= PCLI_F_PROMPT;
		return argl; /* return the number of elements in the array */

	} else if (strcmp("quit", args[0]) == 0) {
		channel_shutr_now(&s->req);
		channel_shutw_now(&s->res);
		return argl; /* return the number of elements in the array */
	} else if (strcmp(args[0], "operator") == 0) {
		if (!pcli_has_level(s, ACCESS_LVL_OPER)) {
			memprintf(errmsg, "Permission denied!\n");
			return -1;
		}
		s->pcli_flags &= ~ACCESS_LVL_MASK;
		s->pcli_flags |= ACCESS_LVL_OPER;
		return argl;

	} else if (strcmp(args[0], "user") == 0) {
		if (!pcli_has_level(s, ACCESS_LVL_USER)) {
			memprintf(errmsg, "Permission denied!\n");
			return -1;
		}
		s->pcli_flags &= ~ACCESS_LVL_MASK;
		s->pcli_flags |= ACCESS_LVL_USER;
		return argl;
	}

	return 0;
}

/*
 * Parse the CLI request:
 *  - It does basically the same as the cli_io_handler, but as a proxy
 *  - It can exec a command and strip non forwardable commands
 *
 *  Return:
 *  - the number of characters to forward or
 *  - 1 if there is an error or not enough data
 */
int pcli_parse_request(struct stream *s, struct channel *req, char **errmsg, int *next_pid)
{
	char *str;
	char *end;
	char *args[MAX_CLI_ARGS + 1]; /* +1 for storing a NULL */
	int argl; /* number of args */
	char *p;
	char *trim = NULL;
	char *payload = NULL;
	int wtrim = 0; /* number of words to trim */
	int reql = 0;
	int ret;
	int i = 0;

	/* we cannot deal with a wrapping buffer, so let's take care of this
	 * first.
	 */
	if (b_head(&req->buf) + b_data(&req->buf) > b_wrap(&req->buf))
		b_slow_realign(&req->buf, trash.area, co_data(req));

	str = (char *)ci_head(req);
	end = (char *)ci_stop(req);

	p = str;

	if (!(s->pcli_flags & PCLI_F_PAYLOAD)) {

		/* Looks for the end of one command */
		while (p+reql < end) {
			/* handle escaping */
			if (p[reql] == '\\') {
				reql+=2;
				continue;
			}
			if (p[reql] == ';' || p[reql] == '\n') {
				/* found the end of the command */
				p[reql] = '\n';
				reql++;
				break;
			}
			reql++;
		}
	} else {
		while (p+reql < end) {
			if (p[reql] == '\n') {
				/* found the end of the line */
				reql++;
				break;
			}
			reql++;
		}
	}

	/* set end to first byte after the end of the command */
	end = p + reql;

	/* there is no end to this command, need more to parse ! */
	if (!reql || *(end-1) != '\n') {
		return -1;
	}

	if (s->pcli_flags & PCLI_F_PAYLOAD) {
		if (reql == 1) /* last line of the payload */
			s->pcli_flags &= ~PCLI_F_PAYLOAD;
		return reql;
	}

	*(end-1) = '\0';

	/* splits the command in words */
	while (i < MAX_CLI_ARGS && p < end) {
		/* skip leading spaces/tabs */
		p += strspn(p, " \t");
		if (!*p)
			break;

		args[i] = p;
		while (1) {
			p += strcspn(p, " \t\\");
			/* escaped chars using backlashes (\) */
			if (*p == '\\') {
				if (!*++p)
					break;
				if (!*++p)
					break;
			} else {
				break;
			}
		}
		*p++ = 0;
		i++;
	}

	argl = i;

	for (; i < MAX_CLI_ARGS + 1; i++)
		args[i] = NULL;

	wtrim = pcli_find_and_exec_kw(s, args, argl, errmsg, next_pid);

	/* End of words are ending by \0, we need to replace the \0s by spaces
1	   before forwarding them */
	p = str;
	while (p < end-1) {
		if (*p == '\0')
			*p = ' ';
		p++;
	}

	payload = strstr(str, PAYLOAD_PATTERN);
	if ((end - 1) == (payload + strlen(PAYLOAD_PATTERN))) {
		/* if the payload pattern is at the end */
		s->pcli_flags |= PCLI_F_PAYLOAD;
	}

	*(end-1) = '\n';

	if (wtrim > 0) {
		trim = &args[wtrim][0];
		if (trim == NULL) /* if this was the last word in the table */
			trim = end;

		b_del(&req->buf, trim - str);

		ret = end - trim;
	} else if (wtrim < 0) {
		/* parsing error */
		return -1;
	} else {
		/* the whole string */
		ret = end - str;
	}

	if (ret > 1) {
		if (pcli_has_level(s, ACCESS_LVL_ADMIN)) {
			goto end;
		} else if (pcli_has_level(s, ACCESS_LVL_OPER)) {
			ci_insert_line2(req, 0, "operator -", strlen("operator -"));
			ret += strlen("operator -") + 2;
		} else if (pcli_has_level(s, ACCESS_LVL_USER)) {
			ci_insert_line2(req, 0, "user -", strlen("user -"));
			ret += strlen("user -") + 2;
		}
	}
end:

	return ret;
}

int pcli_wait_for_request(struct stream *s, struct channel *req, int an_bit)
{
	int next_pid = -1;
	int to_forward;
	char *errmsg = NULL;

	/* Don't read the next command if still processing the response of the
	 * current one. Just wait. At this stage, errors should be handled by
	 * the response analyzer.
	 */
	if (s->res.analysers & AN_RES_WAIT_CLI)
		return 0;

	if ((s->pcli_flags & ACCESS_LVL_MASK) == ACCESS_LVL_NONE)
		s->pcli_flags |= strm_li(s)->bind_conf->level & ACCESS_LVL_MASK;

read_again:
	/* if the channel is closed for read, we won't receive any more data
	   from the client, but we don't want to forward this close to the
	   server */
	channel_dont_close(req);

	/* We don't know yet to which server we will connect */
	channel_dont_connect(req);

	req->flags |= CF_READ_DONTWAIT;

	/* need more data */
	if (!ci_data(req))
		goto missing_data;

	/* If there is data available for analysis, log the end of the idle time. */
	if (c_data(req) && s->logs.t_idle == -1)
		s->logs.t_idle = tv_ms_elapsed(&s->logs.tv_accept, &now) - s->logs.t_handshake;

	to_forward = pcli_parse_request(s, req, &errmsg, &next_pid);
	if (to_forward > 0) {
		int target_pid;
		/* enough data */

		/* forward only 1 command */
		channel_forward(req, to_forward);

		if (!(s->pcli_flags & PCLI_F_PAYLOAD)) {
			/* we send only 1 command per request, and we write close after it */
			channel_shutw_now(req);
		} else {
			pcli_write_prompt(s);
		}

		s->res.flags |= CF_WAKE_ONCE; /* need to be called again */
		s->res.analysers |= AN_RES_WAIT_CLI;

		if (!(s->flags & SF_ASSIGNED)) {
			if (next_pid > -1)
				target_pid = next_pid;
			else
				target_pid = s->pcli_next_pid;
			/* we can connect now */
			s->target = pcli_pid_to_server(target_pid);

			if (!s->target)
				goto server_disconnect;

			s->flags |= (SF_DIRECT | SF_ASSIGNED);
			channel_auto_connect(req);
		}

	} else if (to_forward == 0) {
		/* we trimmed things but we might have other commands to consume */
		pcli_write_prompt(s);
		goto read_again;
	} else if (to_forward == -1) {
                if (errmsg) {
                        /* there was an error during the parsing */
                        pcli_reply_and_close(s, errmsg);
                        s->req.analysers &= ~AN_REQ_WAIT_CLI;
                        return 0;
                }
                goto missing_data;
	}

	return 0;

send_help:
	b_reset(&req->buf);
	b_putblk(&req->buf, "help\n", 5);
	goto read_again;

missing_data:
        if (req->flags & CF_SHUTR) {
                /* There is no more request or a only a partial one and we
                 * receive a close from the client, we can leave */
                channel_shutw_now(&s->res);
                s->req.analysers &= ~AN_REQ_WAIT_CLI;
                return 1;
        }
        else if (channel_full(req, global.tune.maxrewrite)) {
                /* buffer is full and we didn't catch the end of a command */
                goto send_help;
        }
        return 0;

server_disconnect:
	pcli_reply_and_close(s, "Can't connect to the target CLI!\n");
	return 0;
}

int pcli_wait_for_response(struct stream *s, struct channel *rep, int an_bit)
{
	struct proxy *fe = strm_fe(s);
	struct proxy *be = s->be;

	if (rep->flags & CF_READ_ERROR) {
		pcli_reply_and_close(s, "Can't connect to the target CLI!\n");
		s->req.analysers &= ~AN_REQ_WAIT_CLI;
		s->res.analysers &= ~AN_RES_WAIT_CLI;
		return 0;
	}
	rep->flags |= CF_READ_DONTWAIT; /* try to get back here ASAP */
	rep->flags |= CF_NEVER_WAIT;

	/* don't forward the close */
	channel_dont_close(&s->res);
	channel_dont_close(&s->req);

	if (s->pcli_flags & PCLI_F_PAYLOAD) {
		s->res.analysers &= ~AN_RES_WAIT_CLI;
		s->req.flags |= CF_WAKE_ONCE; /* need to be called again if there is some command left in the request */
		return 0;
	}

	/* forward the data */
	if (ci_data(rep)) {
		c_adv(rep, ci_data(rep));
		return 0;
	}

	if ((rep->flags & (CF_SHUTR|CF_READ_NULL))) {
		/* stream cleanup */

		pcli_write_prompt(s);

		s->si[1].flags |= SI_FL_NOLINGER | SI_FL_NOHALF;
		si_shutr(&s->si[1]);
		si_shutw(&s->si[1]);

		/*
		 * starting from there this the same code as
		 * http_end_txn_clean_session().
		 *
		 * It allows to do frontend keepalive while reconnecting to a
		 * new server for each request.
		 */

		if (s->flags & SF_BE_ASSIGNED) {
			HA_ATOMIC_DEC(&be->beconn);
			if (unlikely(s->srv_conn))
				sess_change_server(s, NULL);
		}

		s->logs.t_close = tv_ms_elapsed(&s->logs.tv_accept, &now);
		stream_process_counters(s);

		/* don't count other requests' data */
		s->logs.bytes_in  -= ci_data(&s->req);
		s->logs.bytes_out -= ci_data(&s->res);

		/* we may need to know the position in the queue */
		pendconn_free(s);

		/* let's do a final log if we need it */
		if (!LIST_ISEMPTY(&fe->logformat) && s->logs.logwait &&
		    !(s->flags & SF_MONITOR) &&
		    (!(fe->options & PR_O_NULLNOLOG) || s->req.total)) {
			s->do_log(s);
		}

		/* stop tracking content-based counters */
		stream_stop_content_counters(s);
		stream_update_time_stats(s);

		s->logs.accept_date = date; /* user-visible date for logging */
		s->logs.tv_accept = now;  /* corrected date for internal use */
		s->logs.t_handshake = 0; /* There are no handshake in keep alive connection. */
		s->logs.t_idle = -1;
		tv_zero(&s->logs.tv_request);
		s->logs.t_queue = -1;
		s->logs.t_connect = -1;
		s->logs.t_data = -1;
		s->logs.t_close = 0;
		s->logs.prx_queue_pos = 0;  /* we get the number of pending conns before us */
		s->logs.srv_queue_pos = 0; /* we will get this number soon */

		s->logs.bytes_in = s->req.total = ci_data(&s->req);
		s->logs.bytes_out = s->res.total = ci_data(&s->res);

		stream_del_srv_conn(s);
		if (objt_server(s->target)) {
			if (s->flags & SF_CURR_SESS) {
				s->flags &= ~SF_CURR_SESS;
				HA_ATOMIC_DEC(&__objt_server(s->target)->cur_sess);
			}
			if (may_dequeue_tasks(__objt_server(s->target), be))
				process_srv_queue(__objt_server(s->target));
		}

		s->target = NULL;

		/* only release our endpoint if we don't intend to reuse the
		 * connection.
		 */
		if (!si_conn_ready(&s->si[1])) {
			si_release_endpoint(&s->si[1]);
			s->srv_conn = NULL;
		}

		sockaddr_free(&s->si[1].dst);

		s->si[1].state     = s->si[1].prev_state = SI_ST_INI;
		s->si[1].err_type  = SI_ET_NONE;
		s->si[1].conn_retries = 0;  /* used for logging too */
		s->si[1].exp       = TICK_ETERNITY;
		s->si[1].flags    &= SI_FL_ISBACK | SI_FL_DONT_WAKE; /* we're in the context of process_stream */
		s->req.flags &= ~(CF_SHUTW|CF_SHUTW_NOW|CF_AUTO_CONNECT|CF_WRITE_ERROR|CF_STREAMER|CF_STREAMER_FAST|CF_NEVER_WAIT|CF_WROTE_DATA);
		s->res.flags &= ~(CF_SHUTR|CF_SHUTR_NOW|CF_READ_ATTACHED|CF_READ_ERROR|CF_READ_NOEXP|CF_STREAMER|CF_STREAMER_FAST|CF_WRITE_PARTIAL|CF_NEVER_WAIT|CF_WROTE_DATA|CF_READ_NULL);
		s->flags &= ~(SF_DIRECT|SF_ASSIGNED|SF_ADDR_SET|SF_BE_ASSIGNED|SF_FORCE_PRST|SF_IGNORE_PRST);
		s->flags &= ~(SF_CURR_SESS|SF_REDIRECTABLE|SF_SRV_REUSED);
		s->flags &= ~(SF_ERR_MASK|SF_FINST_MASK|SF_REDISP);
		/* reinitialise the current rule list pointer to NULL. We are sure that
		 * any rulelist match the NULL pointer.
		 */
		s->current_rule_list = NULL;

		s->be = strm_fe(s);
		s->logs.logwait = strm_fe(s)->to_log;
		s->logs.level = 0;
		stream_del_srv_conn(s);
		s->target = NULL;
		/* re-init store persistence */
		s->store_count = 0;
		s->uniq_id = global.req_count++;

		s->req.flags |= CF_READ_DONTWAIT; /* one read is usually enough */

		s->req.flags |= CF_WAKE_ONCE; /* need to be called again if there is some command left in the request */

		s->res.analysers &= ~AN_RES_WAIT_CLI;

		/* We must trim any excess data from the response buffer, because we
		 * may have blocked an invalid response from a server that we don't
		 * want to accidentally forward once we disable the analysers, nor do
		 * we want those data to come along with next response. A typical
		 * example of such data would be from a buggy server responding to
		 * a HEAD with some data, or sending more than the advertised
		 * content-length.
		 */
		if (unlikely(ci_data(&s->res)))
			b_set_data(&s->res.buf, co_data(&s->res));

		/* Now we can realign the response buffer */
		c_realign_if_empty(&s->res);

		s->req.rto = strm_fe(s)->timeout.client;
		s->req.wto = TICK_ETERNITY;

		s->res.rto = TICK_ETERNITY;
		s->res.wto = strm_fe(s)->timeout.client;

		s->req.rex = TICK_ETERNITY;
		s->req.wex = TICK_ETERNITY;
		s->req.analyse_exp = TICK_ETERNITY;
		s->res.rex = TICK_ETERNITY;
		s->res.wex = TICK_ETERNITY;
		s->res.analyse_exp = TICK_ETERNITY;
		s->si[1].hcto = TICK_ETERNITY;

		/* we're removing the analysers, we MUST re-enable events detection.
		 * We don't enable close on the response channel since it's either
		 * already closed, or in keep-alive with an idle connection handler.
		 */
		channel_auto_read(&s->req);
		channel_auto_close(&s->req);
		channel_auto_read(&s->res);


		return 1;
	}
	return 0;
}

/*
 * The mworker functions are used to initialize the CLI in the master process
 */

 /*
 * Stop the mworker proxy
 */
void mworker_cli_proxy_stop()
{
	if (mworker_proxy)
		stop_proxy(mworker_proxy);
}

/*
 * Create the mworker CLI proxy
 */
int mworker_cli_proxy_create()
{
	struct mworker_proc *child;
	char *msg = NULL;
	char *errmsg = NULL;

	mworker_proxy = alloc_new_proxy("MASTER", PR_CAP_LISTEN|PR_CAP_INT, &errmsg);
	if (!mworker_proxy)
		goto error_proxy;

	mworker_proxy->mode = PR_MODE_CLI;
	mworker_proxy->maxconn = 10;                 /* default to 10 concurrent connections */
	mworker_proxy->timeout.client = 0; /* no timeout */
	mworker_proxy->conf.file = strdup("MASTER");
	mworker_proxy->conf.line = 0;
	mworker_proxy->accept = frontend_accept;
	mworker_proxy-> lbprm.algo = BE_LB_ALGO_NONE;

	/* Does not init the default target the CLI applet, but must be done in
	 * the request parsing code */
	mworker_proxy->default_target = NULL;

	/* create all servers using the mworker_proc list */
	list_for_each_entry(child, &proc_list, list) {
		struct server *newsrv = NULL;
		struct sockaddr_storage *sk;
		int port1, port2, port;
		struct protocol *proto;

		/* only the workers support the master CLI */
		if (!(child->options & PROC_O_TYPE_WORKER))
			continue;

		newsrv = new_server(mworker_proxy);
		if (!newsrv)
			goto error;

		/* we don't know the new pid yet */
		if (child->pid == -1)
			memprintf(&msg, "cur-%d", 1);
		else
			memprintf(&msg, "old-%d", child->pid);

		newsrv->next = mworker_proxy->srv;
		mworker_proxy->srv = newsrv;
		newsrv->conf.file = strdup(msg);
		newsrv->id = strdup(msg);
		newsrv->conf.line = 0;

		memprintf(&msg, "sockpair@%d", child->ipc_fd[0]);
		if ((sk = str2sa_range(msg, &port, &port1, &port2, NULL, &proto,
		                       &errmsg, NULL, NULL, PA_O_STREAM)) == 0) {
			goto error;
		}
		ha_free(&msg);

		if (!proto->connect) {
			goto error;
		}

		/* no port specified */
		newsrv->flags |= SRV_F_MAPPORTS;
		newsrv->addr = *sk;
		/* don't let the server participate to load balancing */
		newsrv->iweight = 0;
		newsrv->uweight = 0;
		srv_lb_commit_status(newsrv);

		child->srv = newsrv;
	}

	mworker_proxy->next = proxies_list;
	proxies_list = mworker_proxy;

	return 0;

error:

	list_for_each_entry(child, &proc_list, list) {
		free((char *)child->srv->conf.file); /* cast because of const char *  */
		free(child->srv->id);
		ha_free(&child->srv);
	}
	free_proxy(mworker_proxy);
	free(msg);

error_proxy:
	ha_alert("%s\n", errmsg);
	free(errmsg);

	return -1;
}

/*
 * Create a new listener for the master CLI proxy
 */
int mworker_cli_proxy_new_listener(char *line)
{
	struct bind_conf *bind_conf;
	struct listener *l;
	char *err = NULL;
	char *args[MAX_LINE_ARGS + 1];
	int arg;
	int cur_arg;

	arg = 1;
	args[0] = line;

	/* args is a bind configuration with spaces replaced by commas */
	while (*line && arg < MAX_LINE_ARGS) {

		if (*line == ',') {
			*line++ = '\0';
			while (*line == ',')
				line++;
			args[arg++] = line;
		}
		line++;
	}

	args[arg] = "\0";

	bind_conf = bind_conf_alloc(mworker_proxy, "master-socket", 0, "", xprt_get(XPRT_RAW));
	if (!bind_conf)
		goto err;

	bind_conf->level &= ~ACCESS_LVL_MASK;
	bind_conf->level |= ACCESS_LVL_ADMIN;
	bind_conf->level |= ACCESS_MASTER | ACCESS_MASTER_ONLY;

	if (!str2listener(args[0], mworker_proxy, bind_conf, "master-socket", 0, &err)) {
		ha_alert("Cannot create the listener of the master CLI\n");
		goto err;
	}

	cur_arg = 1;

	while (*args[cur_arg]) {
			struct bind_kw *kw;
			const char *best;

			kw = bind_find_kw(args[cur_arg]);
			if (kw) {
				if (!kw->parse) {
					memprintf(&err, "'%s %s' : '%s' option is not implemented in this version (check build options).",
						  args[0], args[1], args[cur_arg]);
					goto err;
				}

				if (kw->parse(args, cur_arg, global.cli_fe, bind_conf, &err) != 0) {
					if (err)
						memprintf(&err, "'%s %s' : '%s'", args[0], args[1], err);
					else
						memprintf(&err, "'%s %s' : error encountered while processing '%s'",
						          args[0], args[1], args[cur_arg]);
					goto err;
				}

				cur_arg += 1 + kw->skip;
				continue;
			}

			best = bind_find_best_kw(args[cur_arg]);
			if (best)
				memprintf(&err, "'%s %s' : unknown keyword '%s'. Did you mean '%s' maybe ?",
				          args[0], args[1], args[cur_arg], best);
			else
				memprintf(&err, "'%s %s' : unknown keyword '%s'.",
				          args[0], args[1], args[cur_arg]);
			goto err;
	}


	list_for_each_entry(l, &bind_conf->listeners, by_bind) {
		l->accept = session_accept_fd;
		l->default_target = mworker_proxy->default_target;
		/* don't make the peers subject to global limits and don't close it in the master */
		l->options  |= LI_O_UNLIMITED;
		l->rx.flags |= RX_F_MWORKER; /* we are keeping this FD in the master */
		l->nice = -64;  /* we want to boost priority for local stats */
		global.maxsock++; /* for the listening socket */
	}
	global.maxsock += mworker_proxy->maxconn;

	return 0;

err:
	ha_alert("%s\n", err);
	free(err);
	free(bind_conf);
	return -1;

}

/*
 * Create a new CLI socket using a socketpair for a worker process
 * <mworker_proc> is the process structure, and <proc> is the process number
 */
int mworker_cli_sockpair_new(struct mworker_proc *mworker_proc, int proc)
{
	struct bind_conf *bind_conf;
	struct listener *l;
	char *path = NULL;
	char *err = NULL;

	/* master pipe to ensure the master is still alive  */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, mworker_proc->ipc_fd) < 0) {
		ha_alert("Cannot create worker socketpair.\n");
		return -1;
	}

	/* XXX: we might want to use a separate frontend at some point */
	if (!global.cli_fe) {
		if ((global.cli_fe = cli_alloc_fe("GLOBAL", "master-socket", 0)) == NULL) {
			ha_alert("out of memory trying to allocate the stats frontend");
			goto error;
		}
	}

	bind_conf = bind_conf_alloc(global.cli_fe, "master-socket", 0, "", xprt_get(XPRT_RAW));
	if (!bind_conf)
		goto error;

	bind_conf->level &= ~ACCESS_LVL_MASK;
	bind_conf->level |= ACCESS_LVL_ADMIN; /* TODO: need to lower the rights with a CLI keyword*/
	bind_conf->level |= ACCESS_FD_LISTENERS;

	if (!memprintf(&path, "sockpair@%d", mworker_proc->ipc_fd[1])) {
		ha_alert("Cannot allocate listener.\n");
		goto error;
	}

	if (!str2listener(path, global.cli_fe, bind_conf, "master-socket", 0, &err)) {
		free(path);
		ha_alert("Cannot create a CLI sockpair listener for process #%d\n", proc);
		goto error;
	}
	ha_free(&path);

	list_for_each_entry(l, &bind_conf->listeners, by_bind) {
		l->accept = session_accept_fd;
		l->default_target = global.cli_fe->default_target;
		l->options |= (LI_O_UNLIMITED | LI_O_NOSTOP);
		HA_ATOMIC_INC(&unstoppable_jobs);
		/* it's a sockpair but we don't want to keep the fd in the master */
		l->rx.flags &= ~RX_F_INHERITED;
		l->nice = -64;  /* we want to boost priority for local stats */
		global.maxsock++; /* for the listening socket */
	}

	return 0;

error:
	close(mworker_proc->ipc_fd[0]);
	close(mworker_proc->ipc_fd[1]);
	free(err);

	return -1;
}

static struct applet cli_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<CLI>", /* used for logging */
	.fct = cli_io_handler,
	.release = cli_release_handler,
};

/* master CLI */
static struct applet mcli_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<MCLI>", /* used for logging */
	.fct = cli_io_handler,
	.release = cli_release_handler,
};

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "help", NULL },                      NULL,                                                                                                cli_parse_simple, NULL, NULL, NULL, ACCESS_MASTER },
	{ { "prompt", NULL },                    NULL,                                                                                                cli_parse_simple, NULL, NULL, NULL, ACCESS_MASTER },
	{ { "quit", NULL },                      NULL,                                                                                                cli_parse_simple, NULL, NULL, NULL, ACCESS_MASTER },
	{ { "_getsocks", NULL },                 NULL,                                                                                                _getsocks, NULL },
	{ { "expert-mode", NULL },               NULL,                                                                                                cli_parse_expert_experimental_mode, NULL }, // not listed
	{ { "experimental-mode", NULL },         NULL,                                                                                                cli_parse_expert_experimental_mode, NULL }, // not listed
	{ { "set", "maxconn", "global",  NULL }, "set maxconn global <value>              : change the per-process maxconn setting",                  cli_parse_set_maxconn_global, NULL },
	{ { "set", "rate-limit", NULL },         "set rate-limit <setting> <value>        : change a rate limiting value",                            cli_parse_set_ratelimit, NULL },
	{ { "set", "severity-output",  NULL },   "set severity-output [none|number|string]: set presence of severity level in feedback information",  cli_parse_set_severity_output, NULL, NULL },
	{ { "set", "timeout",  NULL },           "set timeout [cli] <delay>               : change a timeout setting",                                cli_parse_set_timeout, NULL, NULL },
	{ { "show", "env",  NULL },              "show env [var]                          : dump environment variables known to the process",         cli_parse_show_env, cli_io_handler_show_env, NULL },
	{ { "show", "cli", "sockets",  NULL },   "show cli sockets                        : dump list of cli sockets",                                cli_parse_default, cli_io_handler_show_cli_sock, NULL, NULL, ACCESS_MASTER },
	{ { "show", "cli", "level", NULL },      "show cli level                          : display the level of the current CLI session",            cli_parse_show_lvl, NULL, NULL, NULL, ACCESS_MASTER},
	{ { "show", "fd", NULL },                "show fd [num]                           : dump list of file descriptors in use or a specific one",  cli_parse_show_fd, cli_io_handler_show_fd, NULL },
	{ { "show", "activity", NULL },          "show activity                           : show per-thread activity stats (for support/developers)", cli_parse_default, cli_io_handler_show_activity, NULL },
	{ { "show", "version", NULL },           "show version                            : show version of the current process",                     cli_parse_show_version, NULL, NULL, NULL, ACCESS_MASTER },
	{ { "operator", NULL },                  "operator                                : lower the level of the current CLI session to operator",  cli_parse_set_lvl, NULL, NULL, NULL, ACCESS_MASTER},
	{ { "user", NULL },                      "user                                    : lower the level of the current CLI session to user",      cli_parse_set_lvl, NULL, NULL, NULL, ACCESS_MASTER},
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "stats", cli_parse_global },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

static struct bind_kw_list bind_kws = { "STAT", { }, {
	{ "level",     bind_parse_level,    1 }, /* set the unix socket admin level */
	{ "expose-fd", bind_parse_expose_fd, 1 }, /* set the unix socket expose fd rights */
	{ "severity-output", bind_parse_severity_output, 1 }, /* set the severity output format */
	{ NULL, NULL, 0 },
}};

INITCALL1(STG_REGISTER, bind_register_keywords, &bind_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
