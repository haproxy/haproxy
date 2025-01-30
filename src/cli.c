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

#include <haproxy/api.h>
#include <haproxy/applet.h>
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
#include <haproxy/quic_sock.h>
#include <haproxy/sample-t.h>
#include <haproxy/sc_strm.h>
#include <haproxy/server.h>
#include <haproxy/session.h>
#include <haproxy/sock.h>
#include <haproxy/stats-t.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/systemd.h>
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
struct bind_conf *mcli_reload_bind_conf;

/* CLI context for the "show env" command */
struct show_env_ctx {
	char **var;      /* first variable to show */
	int show_one;    /* stop after showing the first one */
};

/* CLI context for the "show fd" command */
/* flags for show_fd_ctx->show_mask */
#define CLI_SHOWFD_F_PI  0x00000001   /* pipes             */
#define CLI_SHOWFD_F_LI  0x00000002   /* listeners         */
#define CLI_SHOWFD_F_FE  0x00000004   /* frontend conns    */
#define CLI_SHOWFD_F_SV  0x00000010   /* server-only conns */
#define CLI_SHOWFD_F_PX  0x00000020   /* proxy-only conns  */
#define CLI_SHOWFD_F_BE  0x00000030   /* backend: srv+px   */
#define CLI_SHOWFD_F_CO  0x00000034   /* conn: be+fe       */
#define CLI_SHOWFD_F_ANY 0x0000003f   /* any type          */

struct show_fd_ctx {
	int fd;          /* first FD to show */
	int show_one;    /* stop after showing one FD */
	uint show_mask;  /* CLI_SHOWFD_F_xxx */
};

/* CLI context for the "show cli sockets" command */
struct show_sock_ctx {
	struct bind_conf *bind_conf;
	struct listener *listener;
};

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
			if (!(appctx->cli_level & ACCESS_MCLI_DEBUG) &&
			    (appctx->cli_level & ~kw->level & (ACCESS_MASTER_ONLY|ACCESS_MASTER)) ==
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
	else {
		chunk_strcat(tmp, "Unknown command: '");
		if (args && *args)
			chunk_strcat(tmp, *args);
		chunk_strcat(tmp, "'");

		if (!length && (!args || !*args || !**args)) // no match
			chunk_strcat(tmp, ". Please enter one of the following commands only:\n");
		else // partial match
			chunk_strcat(tmp, ", but maybe one of the following ones is a better match:\n");
	}

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
				if (!(appctx->cli_level & ACCESS_MCLI_DEBUG) &&
				    ((appctx->cli_level & ~kw->level & (ACCESS_MASTER_ONLY|ACCESS_MASTER)) ==
				    (ACCESS_MASTER_ONLY|ACCESS_MASTER)))
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

			/* in master, if the CLI don't have the
			 * ACCESS_MCLI_DEBUG don't display commands that have
			 * neither the master bit nor the master-only bit.
			 */
			if (!(appctx->cli_level & ACCESS_MCLI_DEBUG) &&
			    ((appctx->cli_level & ~kw->level & (ACCESS_MASTER_ONLY|ACCESS_MASTER)) ==
			    (ACCESS_MASTER_ONLY|ACCESS_MASTER)))
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
	             "  prompt [timed]                          : toggle interactive mode with prompt\n"
	             "  quit                                    : disconnect\n");

	chunk_init(&out, NULL, 0);
	chunk_dup(&out, tmp);
	dynamic_usage_msg = out.area;

	cli_msg(appctx, LOG_INFO, dynamic_usage_msg);
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

/* list all known keywords on stdout, one per line */
void cli_list_keywords(void)
{
	struct cli_kw_list *kw_list;
	struct cli_kw *kwp, *kwn, *kw;
	int idx;

	for (kwn = kwp = NULL;; kwp = kwn) {
		list_for_each_entry(kw_list, &cli_keywords.list, list) {
			/* note: we sort based on the usage message when available,
			 * otherwise we fall back to the first keyword.
			 */
			for (kw = &kw_list->kw[0]; kw->str_kw[0]; kw++) {
				if (strordered(kwp ? kwp->usage ? kwp->usage : kwp->str_kw[0] : NULL,
					       kw->usage ? kw->usage : kw->str_kw[0],
					       kwn != kwp ? kwn->usage ? kwn->usage : kwn->str_kw[0] : NULL))
					kwn = kw;
			}
		}

		if (kwn == kwp)
			break;

		for (idx = 0; kwn->str_kw[idx]; idx++) {
			printf("%s ", kwn->str_kw[idx]);
		}
		if (kwn->level & (ACCESS_MASTER_ONLY|ACCESS_MASTER))
			printf("[MASTER] ");
		if (!(kwn->level & ACCESS_MASTER_ONLY))
			printf("[WORKER] ");
		if (kwn->level & ACCESS_EXPERT)
			printf("[EXPERT] ");
		if (kwn->level & ACCESS_EXPERIMENTAL)
			printf("[EXPERIM] ");
		printf("\n");
	}
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
	fe->fe_counters.last_change = ns_to_sec(now_ns);
	fe->id = strdup("GLOBAL");
	fe->cap = PR_CAP_FE|PR_CAP_INT;
	fe->maxconn = 10;                 /* default to 10 concurrent connections */
	fe->timeout.client = MS_TO_TICKS(10000); /* default timeout of 10 seconds */
	fe->conf.file = copy_file_name(file);
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

		bind_conf->accept = session_accept_fd;
		bind_conf->nice = -64;  /* we want to boost priority for local stats */
		bind_conf->options |= BC_O_UNLIMITED; /* don't make the peers subject to global limits */

		list_for_each_entry(l, &bind_conf->listeners, by_bind) {
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
	else if (strcmp(args[1], "bind-process") == 0) {
		memprintf(err, "'%s %s' is not supported anymore.", args[0], args[1]);
		return -1;
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

				if (l->rx.addr.ss_family == AF_UNIX ||
				    l->rx.addr.ss_family == AF_CUST_ABNS ||
				    l->rx.addr.ss_family == AF_CUST_ABNSZ) {
					const struct sockaddr_un *un;

					un = (struct sockaddr_un *)&l->rx.addr;
					if (l->rx.addr.ss_family == AF_CUST_ABNS ||
					    l->rx.addr.ss_family == AF_CUST_ABNSZ) {
						chunk_appendf(trash, "%sabns@%s", (trash->data ? ";" : ""), un->sun_path+1);
					} else {
						chunk_appendf(trash, "%sunix@%s", (trash->data ? ";" : ""), un->sun_path);
					}
				} else if (l->rx.addr.ss_family == AF_INET) {
					addr_to_str(&l->rx.addr, addr, sizeof(addr));
					port_to_str(&l->rx.addr, port, sizeof(port));
					chunk_appendf(trash, "%sipv4@%s:%s", (trash->data ? ";" : ""), addr, port);
				} else if (l->rx.addr.ss_family == AF_INET6) {
					addr_to_str(&l->rx.addr, addr, sizeof(addr));
					port_to_str(&l->rx.addr, port, sizeof(port));
					chunk_appendf(trash, "%sipv6@[%s]:%s", (trash->data ? ";" : ""), addr, port);
				}
				/* AF_CUST_SOCKPAIR is explicitly skipped, we don't want to show reload and shared
				 * master CLI sockpairs in HAPROXY_CLI and HAPROXY_MASTER_CLI
				 */
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
	return strm_li(appctx_strm(appctx))->bind_conf->severity_output;
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

	p = b_head(&appctx->inbuf);
	end = b_tail(&appctx->inbuf);
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

		/* first check if the '<<' is present, but this is not enough
		 * because we don't know if this is the end of the string */
		if (strncmp(p, PAYLOAD_PATTERN, strlen(PAYLOAD_PATTERN)) == 0) {
			int pat_len = strlen(appctx->cli_payload_pat);

			/* then if the customized pattern is empty, check if the next character is '\0' */
			if (pat_len == 0 && p[strlen(PAYLOAD_PATTERN)] == '\0') {
				payload = p + strlen(PAYLOAD_PATTERN) + 1;
				break;
			}

			/* else if we found the customized pattern at the end of the string */
			if (strcmp(p + strlen(PAYLOAD_PATTERN), appctx->cli_payload_pat) == 0) {
				payload = p + strlen(PAYLOAD_PATTERN) + pat_len + 1;
				break;
			}
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
	p = b_tail(&appctx->inbuf);
	for (; i < MAX_CLI_ARGS + 1; i++)
		args[i] = p;

	if (!**args)
		return 0;

	kw = cli_find_kw(args);
	if (!kw ||
	    (kw->level & ~appctx->cli_level & ACCESS_MASTER_ONLY) ||
	    (!(appctx->cli_level & ACCESS_MCLI_DEBUG) &&
	     (appctx->cli_level & ~kw->level & (ACCESS_MASTER_ONLY|ACCESS_MASTER)) == (ACCESS_MASTER_ONLY|ACCESS_MASTER))) {
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
static int cli_output_msg(struct appctx *appctx, const char *msg, int severity, int severity_output)
{
	struct buffer *tmp;
	struct ist imsg;

	tmp = get_trash_chunk();
	chunk_reset(tmp);

	if (likely(severity_output == CLI_SEVERITY_NONE))
		goto send_it;

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
 send_it:
	/* the vast majority of messages have their trailing LF but a few are
	 * still missing it, and very rare ones might even have two. For this
	 * reason, we'll first delete the trailing LFs if present, then
	 * systematically append one.
	 */
	for (imsg = ist(msg); imsg.len > 0 && imsg.ptr[imsg.len - 1] == '\n'; imsg.len--)
		;

	chunk_istcat(tmp, imsg);
	chunk_istcat(tmp, ist("\n"));

	return applet_putchk(appctx, tmp);
}

int cli_init(struct appctx *appctx)
{
	struct stconn *sc = appctx_sc(appctx);
	struct bind_conf *bind_conf = strm_li(__sc_strm(sc))->bind_conf;

	appctx->cli_severity_output = bind_conf->severity_output;
	applet_reset_svcctx(appctx);
	appctx->st0 = CLI_ST_GETREQ;
	appctx->cli_level = bind_conf->level;

	/* Wakeup the applet ASAP. */
        applet_need_more_data(appctx);
        return 0;

}

size_t cli_snd_buf(struct appctx *appctx, struct buffer *buf, size_t count, unsigned flags)
{
	char *str;
	size_t len, ret = 0;
	int lf = 0;

	if (appctx->st0 == CLI_ST_INIT)
		cli_init(appctx);
	else if (appctx->st0 != CLI_ST_GETREQ)
		goto end;

        if (b_space_wraps(&appctx->inbuf))
                b_slow_realign(&appctx->inbuf, trash.area, b_data(&appctx->inbuf));

	while (1) {
		/* payload doesn't take escapes nor does it end on semi-colons,
		 * so we use the regular getline. Normal mode however must stop
		 * on LFs and semi-colons that are not prefixed by a backslash.
		 * Note we reserve one byte at the end to insert a trailing nul
		 * byte.
		 */
		str = b_tail(&appctx->inbuf);
		if (!(appctx->st1 & APPCTX_CLI_ST1_PAYLOAD))
			len = b_getdelim(buf, ret, count, str, b_room(&appctx->inbuf) - 1, "\n;", '\\');
		else
			len = b_getline(buf, ret, count, str, b_room(&appctx->inbuf) - 1);

		if (!len) {
			if (!b_room(buf) || (count > b_room(&appctx->inbuf) - 1)) {
				cli_err(appctx, "The command is too big for the buffer size. Please change tune.bufsize in the configuration to use a bigger command.\n");
				applet_set_error(appctx);
				b_reset(&appctx->inbuf);
			}
			else if (flags & CO_SFL_LAST_DATA) {
				applet_set_eos(appctx);
				applet_set_error(appctx);
				b_reset(&appctx->inbuf);
			}
			break;
		}

		ret += len;
		count -= len;

		if (str[len-1] == '\n')
			lf = 1;
		len--;

		if (appctx->st1 & APPCTX_CLI_ST1_PAYLOAD) {
			str[len+1] = '\0';
			b_add(&appctx->inbuf, len+1);
		}
		else  {
			/* Remove the trailing \r, if any and add a null byte at the
			 * end. For normal mode, the trailing \n is removed, but we
			 * conserve \r\n or \n sequences for payload mode.
			 */
			if (len && str[len-1] == '\r')
				len--;
			str[len] = '\0';
			b_add(&appctx->inbuf, len);
		}

		if (appctx->st1 & APPCTX_CLI_ST1_PAYLOAD) {
			/* look for a pattern */
			if (len == strlen(appctx->cli_payload_pat)) {
				/* here use 'len' because str still contains the \n */
				if (strncmp(str, appctx->cli_payload_pat, len) == 0) {
					/* remove the last two \n */
					b_sub(&appctx->inbuf, strlen(appctx->cli_payload_pat) + 2);
					*b_tail(&appctx->inbuf) = '\0';
					appctx->st1 &= ~APPCTX_CLI_ST1_PAYLOAD;
					if (!(appctx->st1 & APPCTX_CLI_ST1_PROMPT) && lf)
						appctx->st1 |= APPCTX_CLI_ST1_LASTCMD;
				}
			}
		}
		else {
			char *last_arg;

			/*
			 * Look for the "payload start" pattern at the end of a
			 * line Its location is not remembered here, this is
			 * just to switch to a gathering mode.
			 *
			 * The pattern must start by << followed by 0 to 7
			 * characters, and finished by the end of the command
			 * (\n or ;).
			 */

			/* look for the first space starting by the end of the line */
			for (last_arg = b_tail(&appctx->inbuf); last_arg != b_head(&appctx->inbuf); last_arg--) {
				if (*last_arg == ' ' || *last_arg == '\t') {
					last_arg++;
					break;
				}
			}

			if (strncmp(last_arg, PAYLOAD_PATTERN, strlen(PAYLOAD_PATTERN)) == 0) {
				ssize_t pat_len = strlen(last_arg + strlen(PAYLOAD_PATTERN));

				/* A customized pattern can't be more than 7 characters
				 * if it's more, don't make it a payload
				 */
				if (pat_len < sizeof(appctx->cli_payload_pat)) {
					appctx->st1 |= APPCTX_CLI_ST1_PAYLOAD;
					/* copy the customized pattern, don't store the << */
					strncpy(appctx->cli_payload_pat, last_arg + strlen(PAYLOAD_PATTERN), sizeof(appctx->cli_payload_pat)-1);
					appctx->cli_payload_pat[sizeof(appctx->cli_payload_pat)-1] = '\0';
					b_add(&appctx->inbuf, 1); // keep the trailing \0 after the pattern
				}
			}
			else {
				if (!(appctx->st1 & APPCTX_CLI_ST1_PROMPT) && lf)
					appctx->st1 |= APPCTX_CLI_ST1_LASTCMD;
			}
		}

		if (!(appctx->st1 & APPCTX_CLI_ST1_PAYLOAD) || (appctx->st1 & APPCTX_CLI_ST1_PROMPT)) {
			appctx->st0 = CLI_ST_PARSEREQ;
			break;
		}
	}
	b_del(buf, ret);

  end:
	return ret;
}

/* This I/O handler runs as an applet embedded in a stream connector. It is
 * used to processes I/O from/to the stats unix socket. The system relies on a
 * state machine handling requests and various responses. We read a request,
 * then we process it and send the response, and we possibly display a prompt.
 * Then we can read again. The state is stored in appctx->st0 and is one of the
 * CLI_ST_* constants. appctx->st1 is used to indicate whether prompt is enabled
 * or not.
 */
static void cli_io_handler(struct appctx *appctx)
{
	if (applet_fl_test(appctx, APPCTX_FL_OUTBLK_ALLOC|APPCTX_FL_OUTBLK_FULL))
		goto out;

	if (!appctx_get_buf(appctx, &appctx->outbuf)) {
		goto out;
	}

	if (unlikely(applet_fl_test(appctx, APPCTX_FL_EOS|APPCTX_FL_ERROR))) {
		appctx->st0 = CLI_ST_END;
		goto out;
	}

	while (1) {
		if (appctx->st0 == CLI_ST_INIT) {
			/* reset severity to default at init */
			cli_init(appctx);
		}
		else if (appctx->st0 == CLI_ST_END) {
			applet_set_eos(appctx);
			break;
		}
		else if (appctx->st0 == CLI_ST_GETREQ) {
			/* Now we close the output if we're not in interactive
			 * mode and the request buffer is empty. This still
			 * allows pipelined requests to be sent in
			 * non-interactive mode.
			 */
			if (se_fl_test(appctx->sedesc, SE_FL_SHW)) {
				appctx->st0 = CLI_ST_END;
				continue;
			}
			break;
		}
		else if (appctx->st0 == CLI_ST_PARSEREQ) {
			/* ensure we have some output room left in the event we
			 * would want to return some info right after parsing.
			 */
			if (buffer_almost_full(&appctx->outbuf)) {
				applet_fl_set(appctx, APPCTX_FL_OUTBLK_FULL);
				break;
			}

			appctx->t->expire = TICK_ETERNITY;
			appctx->st0 = CLI_ST_PROMPT;

			if (!(appctx->st1 & APPCTX_CLI_ST1_PAYLOAD)) {
				cli_parse_request(appctx);
				b_reset(&appctx->inbuf);
			}
		}
		else {	/* output functions */
			struct cli_print_ctx *ctx;
			const char *msg;
			int sev;
		cli_output:
			switch (appctx->st0) {
			case CLI_ST_PROMPT:
				break;
			case CLI_ST_PRINT:       /* print const message in msg */
			case CLI_ST_PRINT_ERR:   /* print const error in msg */
			case CLI_ST_PRINT_DYN:   /* print dyn message in msg, free */
			case CLI_ST_PRINT_DYNERR: /* print dyn error in err, free */
			case CLI_ST_PRINT_UMSG:  /* print usermsgs_ctx and reset it */
			case CLI_ST_PRINT_UMSGERR: /* print usermsgs_ctx as error and reset it */
				/* the message is in the svcctx */
				ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
				if (appctx->st0 == CLI_ST_PRINT || appctx->st0 == CLI_ST_PRINT_ERR) {
					sev = appctx->st0 == CLI_ST_PRINT_ERR ?
						LOG_ERR : ctx->severity;
					msg = ctx->msg;
				}
				else if (appctx->st0 == CLI_ST_PRINT_DYN || appctx->st0 == CLI_ST_PRINT_DYNERR) {
					sev = appctx->st0 == CLI_ST_PRINT_DYNERR ?
						LOG_ERR : ctx->severity;
					msg = ctx->err;
					if (!msg) {
						sev = LOG_ERR;
						msg = "Out of memory.\n";
					}
				}
				else if (appctx->st0 == CLI_ST_PRINT_UMSG ||
				         appctx->st0 == CLI_ST_PRINT_UMSGERR) {
					sev = appctx->st0 == CLI_ST_PRINT_UMSGERR ?
					        LOG_ERR : ctx->severity;
					msg = usermsgs_str();
				}
				else {
					sev = LOG_ERR;
					msg = "Internal error.\n";
				}

				if (cli_output_msg(appctx, msg, sev, cli_get_severity_output(appctx)) != -1) {
					if (appctx->st0 == CLI_ST_PRINT_DYN ||
					    appctx->st0 == CLI_ST_PRINT_DYNERR) {
						ha_free(&ctx->err);
					}
					else if (appctx->st0 == CLI_ST_PRINT_UMSG ||
					         appctx->st0 == CLI_ST_PRINT_UMSGERR) {
						usermsgs_clr(NULL);
					}
					appctx->t->expire = TICK_ETERNITY;
					appctx->st0 = CLI_ST_PROMPT;
				}
				if (applet_fl_test(appctx, APPCTX_FL_ERR_PENDING)) {
					appctx->st0 = CLI_ST_END;
					continue;
				}

				break;

			case CLI_ST_CALLBACK: /* use custom pointer */
				if (appctx->io_handler)
					if (appctx->io_handler(appctx)) {
						appctx->t->expire = TICK_ETERNITY;
						appctx->st0 = CLI_ST_PROMPT;
						if (appctx->io_release) {
							appctx->io_release(appctx);
							appctx->io_release = NULL;
							/* some release handlers might have
							 * pending output to print.
							 */
							continue;
						}
					}
				break;
			default: /* abnormal state */
				se_fl_set(appctx->sedesc, SE_FL_ERROR);
				break;
			}

			/* The post-command prompt is either LF alone or LF + '> ' in interactive mode */
			if (appctx->st0 == CLI_ST_PROMPT) {
				char prompt_buf[20];
				const char *prompt = "";

				if (appctx->st1 & APPCTX_CLI_ST1_PROMPT) {
					/*
					 * when entering a payload with interactive mode, change the prompt
					 * to emphasize that more data can still be sent
					 */
					if (b_data(&appctx->inbuf) && appctx->st1 & APPCTX_CLI_ST1_PAYLOAD)
						prompt = "+ ";
					else if (appctx->st1 & APPCTX_CLI_ST1_TIMED) {
						uint up = ns_to_sec(now_ns - start_time_ns);
						snprintf(prompt_buf, sizeof(prompt_buf),
							 "\n[%u:%02u:%02u:%02u]> ",
							 (up / 86400), (up / 3600) % 24, (up / 60) % 60, up % 60);
						prompt = prompt_buf;
					}
					else
						prompt = "\n> ";
				}
				else {
					if (!(appctx->st1 & (APPCTX_CLI_ST1_PAYLOAD|APPCTX_CLI_ST1_NOLF)))
						prompt = "\n";
				}

				if (applet_putstr(appctx, prompt) != -1) {
					applet_reset_svcctx(appctx);
					appctx->st0 = CLI_ST_GETREQ;
				}
			}

			/* If the output functions are still there, it means they require more room. */
			if (appctx->st0 >= CLI_ST_OUTPUT) {
				applet_wont_consume(appctx);
				break;
			}

			/* Now we close the output if we're not in interactive
			 * mode and the request buffer is empty. This still
			 * allows pipelined requests to be sent in
			 * non-interactive mode.
			 */
			if ((appctx->st1 & (APPCTX_CLI_ST1_PROMPT|APPCTX_CLI_ST1_PAYLOAD|APPCTX_CLI_ST1_LASTCMD)) == APPCTX_CLI_ST1_LASTCMD) {
				applet_set_eoi(appctx);
				appctx->st0 = CLI_ST_END;
				continue;
			}

			/* switch state back to GETREQ to read next requests */
			applet_reset_svcctx(appctx);
			appctx->st0 = CLI_ST_GETREQ;
			applet_will_consume(appctx);
			applet_expect_data(appctx);

			/* reactivate the \n at the end of the response for the next command */
			appctx->st1 &= ~APPCTX_CLI_ST1_NOLF;

			/* this forces us to yield between pipelined commands and
			 * avoid extremely long latencies (e.g. "del map" etc). In
			 * addition this increases the likelihood that the stream
			 * refills the buffer with new bytes in non-interactive
			 * mode, avoiding to close on apparently empty commands.
			 */
			break;
		}
	}

 out:
	if (appctx->st0 == CLI_ST_END) {
		/* eat the whole request */
		b_reset(&appctx->inbuf);
		applet_fl_clr(appctx, APPCTX_FL_INBLK_FULL);
	}
	return;
}

/* This is called when the stream connector is closed. For instance, upon an
 * external abort, we won't call the i/o handler anymore so we may need to
 * remove back references to the stream currently being dumped.
 */
static void cli_release_handler(struct appctx *appctx)
{
	if (appctx->io_release) {
		appctx->io_release(appctx);
		appctx->io_release = NULL;
	}
	else if (appctx->st0 == CLI_ST_PRINT_DYN || appctx->st0 == CLI_ST_PRINT_DYNERR) {
		struct cli_print_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

		ha_free(&ctx->err);
	}
	else if (appctx->st0 == CLI_ST_PRINT_UMSG || appctx->st0 == CLI_ST_PRINT_UMSGERR) {
		usermsgs_clr(NULL);
	}
}

/* This function dumps all environmnent variables to the buffer. It returns 0
 * if the output buffer is full and it needs to be called again, otherwise
 * non-zero. It takes its context from the show_env_ctx in svcctx, and will
 * start from ->var and dump only one variable if ->show_one is set.
 */
static int cli_io_handler_show_env(struct appctx *appctx)
{
	struct show_env_ctx *ctx = appctx->svcctx;
	char **var = ctx->var;

	chunk_reset(&trash);

	/* we have two inner loops here, one for the proxy, the other one for
	 * the buffer.
	 */
	while (*var) {
		chunk_printf(&trash, "%s\n", *var);

		if (applet_putchk(appctx, &trash) == -1)
			return 0;

		if (ctx->show_one)
			break;
		var++;
		ctx->var = var;
	}

	/* dump complete */
	return 1;
}

/* This function dumps all file descriptors states (or the requested one) to
 * the buffer. It returns 0 if the output buffer is full and it needs to be
 * called again, otherwise non-zero. It takes its context from the show_fd_ctx
 * in svcctx, only dumps one entry if ->show_one is non-zero, and (re)starts
 * from ->fd.
 */
static int cli_io_handler_show_fd(struct appctx *appctx)
{
	struct show_fd_ctx *fdctx = appctx->svcctx;
	uint match = fdctx->show_mask;
	int fd = fdctx->fd;
	int ret = 1;

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
		const struct quic_conn *qc = NULL;
		uint32_t conn_flags = 0;
		uint8_t conn_err = 0;
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
			conn_err   = conn->err_code;
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
#if defined(USE_QUIC)
		else if (fdt.iocb == quic_conn_sock_fd_iocb) {
			qc = fdtab[fd].owner;
			li = qc ? qc->li : NULL;
			xprt_ctx   = qc ? qc->xprt_ctx : NULL;
			conn = qc ? qc->conn : NULL;
			xprt = conn ? conn->xprt : NULL; // in fact it's &ssl_quic
			mux = conn ? conn->mux : NULL;
			/* quic_conns don't always have a connection but they
			 * always have an xprt_ctx.
			 */
		}
		else if (fdt.iocb == quic_lstnr_sock_fd_iocb) {
			li = objt_listener(fdtab[fd].owner);
		}
#endif
		else if (fdt.iocb == sock_accept_iocb)
			li = fdt.owner;

		if (!(((conn || xprt_ctx) &&
		       ((match & CLI_SHOWFD_F_SV && sv) ||
			(match & CLI_SHOWFD_F_PX && px) ||
			(match & CLI_SHOWFD_F_FE && li))) ||
		      (!conn &&
		       ((match & CLI_SHOWFD_F_LI && li) ||
			(match & CLI_SHOWFD_F_PI && !li /* only pipes match this */))))) {
			/* not a desired type */
			goto skip;
		}

		if (!fdt.thread_mask)
			suspicious = 1;

		chunk_printf(&trash,
			     "  %5d : st=0x%06x(%c%c %c%c%c%c%c W:%c%c%c R:%c%c%c) ref=%#x gid=%d tmask=0x%lx umask=0x%lx prmsk=0x%lx pwmsk=0x%lx owner=%p gen=%u tkov=%u iocb=%p(",
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
			     (fdt.refc_tgid >> 4) & 0xffff,
			     (fdt.refc_tgid) & 0xffff,
			     fdt.thread_mask, fdt.update_mask,
			     polled_mask[fd].poll_recv,
			     polled_mask[fd].poll_send,
			     fdt.owner,
			     fdt.generation,
			     fdt.nb_takeover,
			     fdt.iocb);
		resolve_sym_name(&trash, NULL, fdt.iocb);

		if (!fdt.owner) {
			chunk_appendf(&trash, ")");
		}
		else if (conn) {
			chunk_appendf(&trash, ") back=%d cflg=0x%08x cerr=%d", is_back, conn_flags, conn_err);

			if (!(conn->flags & CO_FL_FDLESS) && conn->handle.fd != fd) {
				chunk_appendf(&trash, " fd=%d(BOGUS)", conn->handle.fd);
				suspicious = 1;
			} else if ((conn->flags & CO_FL_FDLESS) && (qc != conn->handle.qc)) {
				chunk_appendf(&trash, " qc=%p(BOGUS)", conn->handle.qc);
				suspicious = 1;
			} else {
				struct sockaddr_storage sa;
				socklen_t salen;

				salen = sizeof(sa);
				if (getsockname(fd, (struct sockaddr *)&sa, &salen) != -1) {
					/* only real address families in .ss_family (as provided by getsockname) */
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
				if (!ctx && !qc)
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
		else if (li && !xprt_ctx) {
			struct sockaddr_storage sa;
			socklen_t salen;

			chunk_appendf(&trash, ") l.st=%s fe=%s",
			              listener_state_str(li),
			              li->bind_conf->frontend->id);

			salen = sizeof(sa);
			if (getsockname(fd, (struct sockaddr *)&sa, &salen) != -1) {
				/* only real address families in .ss_family (as provided by getsockname) */
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

		if (applet_putchk(appctx, &trash) == -1) {
			fdctx->fd = fd;
			ret = 0;
			break;
		}
	skip:
		if (fdctx->show_one)
			break;

		fd++;
	}

 end:
	/* dump complete */

	thread_release();
	return ret;
}

/*
 * CLI IO handler for `show cli sockets`.
 * Uses the svcctx as a show_sock_ctx to store/retrieve the bind_conf and the
 * listener pointers.
 */
static int cli_io_handler_show_cli_sock(struct appctx *appctx)
{
	struct show_sock_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	struct bind_conf *bind_conf = ctx->bind_conf;

	if (!global.cli_fe)
		goto done;

	chunk_reset(&trash);

	if (!bind_conf) {
		/* first call */
		if (applet_putstr(appctx, "# socket lvl processes\n") == -1)
			goto full;
		bind_conf = LIST_ELEM(global.cli_fe->conf.bind.n, typeof(bind_conf), by_fe);
	}

	list_for_each_entry_from(bind_conf, &global.cli_fe->conf.bind, by_fe) {
		struct listener *l = ctx->listener;

		if (!l)
			l = LIST_ELEM(bind_conf->listeners.n, typeof(l), by_bind);

		list_for_each_entry_from(l, &bind_conf->listeners, by_bind) {
			char addr[46];
			char port[6];

			if (l->rx.addr.ss_family == AF_UNIX ||
			    l->rx.addr.ss_family == AF_CUST_ABNS ||
			    l->rx.addr.ss_family == AF_CUST_ABNSZ) {
				const struct sockaddr_un *un;

				un = (struct sockaddr_un *)&l->rx.addr;
				if (l->rx.addr.ss_family == AF_CUST_ABNS ||
				    l->rx.addr.ss_family == AF_CUST_ABNSZ) {
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

			if (applet_putchk(appctx, &trash) == -1) {
				ctx->bind_conf = bind_conf;
				ctx->listener  = l;
				goto full;
			}
		}
	}
 done:
	return 1;
 full:
	return 0;
}


/* parse a "show env" CLI request. Returns 0 if it needs to continue, 1 if it
 * wants to stop here. It reserves a show_env_ctx where it puts the variable to
 * be dumped as well as a flag if a single variable is requested, otherwise puts
 * environ there.
 */
static int cli_parse_show_env(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_env_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
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

		ctx->show_one = 1;
	}
	ctx->var = var;
	return 0;
}

/* parse a "show fd" CLI request. Returns 0 if it needs to continue, 1 if it
 * wants to stop here. It sets a show_fd_ctx context where, if a specific fd is
 * requested, it puts the FD number into ->fd and sets ->show_one to 1.
 */
static int cli_parse_show_fd(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_fd_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	const char *c;
	int arg;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	arg = 2;

	/* when starting with an inversion we preset every flag */
	if (*args[arg] == '!' || *args[arg] == '-')
		ctx->show_mask = CLI_SHOWFD_F_ANY;

	while (*args[arg] && !isdigit((uchar)*args[arg])) {
		uint flag = 0, inv = 0;
		c = args[arg];
		while (*c) {
			switch (*c) {
			case '!': inv = !inv; break;
			case '-': inv = !inv; break;
			case 'p': flag = CLI_SHOWFD_F_PI;  break;
			case 'l': flag = CLI_SHOWFD_F_LI;  break;
			case 'c': flag = CLI_SHOWFD_F_CO; break;
			case 'f': flag = CLI_SHOWFD_F_FE;  break;
			case 'b': flag = CLI_SHOWFD_F_BE; break;
			case 's': flag = CLI_SHOWFD_F_SV;  break;
			case 'd': flag = CLI_SHOWFD_F_PX;  break;
			default: return cli_err(appctx, "Invalid FD type\n");
			}
			c++;
			if (!inv)
				ctx->show_mask |= flag;
			else
				ctx->show_mask &= ~flag;
		}
		arg++;
	}

	/* default mask is to show everything */
	if (!ctx->show_mask)
		ctx->show_mask = CLI_SHOWFD_F_ANY;

	if (*args[arg]) {
		ctx->fd = atoi(args[2]);
		ctx->show_one = 1;
	}

	return 0;
}

/* parse a "set timeout" CLI request. It always returns 1. */
static int cli_parse_set_timeout(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct stream *s = appctx_strm(appctx);

	if (strcmp(args[2], "cli") == 0) {
		unsigned timeout;
		const char *res;

		if (!*args[3])
			return cli_err(appctx, "Expects an integer value.\n");

		res = parse_time_err(args[3], &timeout, TIME_UNIT_S);
		if (res || timeout < 1)
			return cli_err(appctx, "Invalid timeout value.\n");

		s->scf->ioto = 1 + MS_TO_TICKS(timeout*1000);
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
	/* this will ask the applet to not output a \n after the command */
	if (strcmp(args[3], "-") == 0)
		appctx->st1 |= APPCTX_CLI_ST1_NOLF;

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

	/* this will ask the applet to not output a \n after the command */
	if (*args[1] && *args[2] && strcmp(args[2], "-") == 0)
		appctx->st1 |= APPCTX_CLI_ST1_NOLF;

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
	else if (strcmp(args[0], "mcli-debug-mode") == 0) {
		level = ACCESS_MCLI_DEBUG;
		level_str = "mcli-debug-mode";
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

/* enable or disable the anonymized mode, it returns 1 when it works or displays an error message if it doesn't. */
static int cli_parse_set_anon(char **args, char *payload, struct appctx *appctx, void *private)
{
	uint32_t tmp;
	long long key;

	if (strcmp(args[2], "on") == 0) {

		if (*args[3]) {
			key = atoll(args[3]);
			if (key < 1 || key > UINT_MAX)
				return cli_err(appctx, "Value out of range (1 to 4294967295 expected).\n");
			appctx->cli_anon_key = key;
		}
		else {
			tmp = HA_ATOMIC_LOAD(&global.anon_key);
			if (tmp != 0)
				appctx->cli_anon_key = tmp;
			else
				appctx->cli_anon_key = ha_random32();
		}
	}
	else if (strcmp(args[2], "off") == 0) {

		if (*args[3]) {
			return cli_err(appctx, "Key can't be added while disabling anonymized mode\n");
		}
		else {
			appctx->cli_anon_key = 0;
		}
	}
	else {
		return cli_err(appctx,
			"'set anon' only supports :\n"
                        "   - 'on' [key] to enable the anonymized mode\n"
                        "   - 'off' to disable the anonymized mode");
	}
	return 1;
}

/* This function set the global anonyzing key, restricted to level 'admin' */
static int cli_parse_set_global_key(char **args, char *payload, struct appctx *appctx, void *private)
{
	long long key;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return cli_err(appctx, "Permission denied\n");
	if (!*args[2])
                return cli_err(appctx, "Expects an integer value.\n");

	key = atoll(args[2]);
	if (key < 0 || key > UINT_MAX)
		return cli_err(appctx, "Value out of range (0 to 4294967295 expected).\n");

	HA_ATOMIC_STORE(&global.anon_key, key);
	return 1;
}

/* shows the anonymized mode state to everyone, and the key except for users, it always returns 1. */
static int cli_parse_show_anon(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *msg = NULL;
	char *anon_mode = NULL;
	uint32_t c_key = appctx->cli_anon_key;

	if (!c_key)
		anon_mode = "Anonymized mode disabled";
	else
		anon_mode = "Anonymized mode enabled";

	if ( !((appctx->cli_level & ACCESS_LVL_MASK) < ACCESS_LVL_OPER) && c_key != 0) {
		cli_dynmsg(appctx, LOG_INFO, memprintf(&msg, "%s\nKey : %u\n", anon_mode, c_key));
	}
	else {
		cli_dynmsg(appctx, LOG_INFO, memprintf(&msg, "%s\n", anon_mode));
	}

	return 1;
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

/* Parse a "wait <time>" command.
 * It uses a "cli_wait_ctx" struct for its context.
 * Returns 0 if the server deletion has been successfully scheduled, 1 on failure.
 */
static int cli_parse_wait(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct cli_wait_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	uint wait_ms;
	const char *err;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[1])
		return cli_err(appctx, "Expects a duration in milliseconds.\n");

	err = parse_time_err(args[1], &wait_ms, TIME_UNIT_MS);
	if (err || wait_ms < 1) {
		/* in case -h is passed as the first option, continue to the next test */
		if (strcmp(args[1], "-h") == 0)
			args--;
		else
			return cli_err(appctx, "Invalid duration.\n");
	}

	if (strcmp(args[2], "srv-removable") == 0) {
		struct ist be_name, sv_name;

		if (!*args[3])
			return cli_err(appctx, "Missing server name (<backend>/<server>).\n");

		sv_name = ist(args[3]);
		be_name = istsplit(&sv_name, '/');
		if (!istlen(sv_name))
			return cli_err(appctx, "Require 'backend/server'.\n");

		be_name = istdup(be_name);
		sv_name = istdup(sv_name);
		if (!isttest(be_name) || !isttest(sv_name)) {
			free(istptr(be_name));
			free(istptr(sv_name));
			return cli_err(appctx, "Out of memory trying to clone the server name.\n");
		}

		ctx->args[0] = ist0(be_name);
		ctx->args[1] = ist0(sv_name);
		ctx->cond = CLI_WAIT_COND_SRV_UNUSED;
	}
	else if (*args[2]) {
		/* show the command's help either upon request (-h) or error */
		err = "Usage: wait {-h|<duration>} [condition [args...]]\n"
			"  - '-h' displays this help\n"
			"  - <duration> is the maximum wait time, optionally suffixed by the unit among\n"
			"    'us', 'ms', 's', 'm', 'h', and 'd'. ; the default unit is milliseconds.\n"
			"  - <condition> indicates what to wait for, no longer than the specified\n"
			"    duration. Supported conditions are:\n"
			"    - <none> : by default, just sleep for the specified duration.\n"
			"    - srv-removable <px>/<sv> : wait for this server to become removable.\n"
			"";

		if (strcmp(args[2], "-h") == 0)
			return cli_msg(appctx, LOG_INFO, err);
		else
			return cli_err(appctx, err);
	}

	ctx->start = now_ms;
	ctx->deadline = tick_add(now_ms, wait_ms);

	/* proceed with the I/O handler */
	return 0;
}

/* Execute a "wait" condition. The delay is exponentially incremented between
 * now_ms and ctx->deadline in powers of 1.5 and with a bound set to 10% of the
 * programmed wait time, so that in a few wakeups we can later check a condition
 * with reasonable accuracy. Shutdowns and other errors are handled as well and
 * terminate the operation, but not new inputs so that it remains possible to
 * chain other commands after it. Returns 0 if not finished, 1 if finished.
 */
static int cli_io_handler_wait(struct appctx *appctx)
{
	struct cli_wait_ctx *ctx = appctx->svcctx;
	uint total, elapsed, left, wait;
	int ret;

	/* note: upon first invocation, the timeout is not set */
	if (tick_isset(appctx->t->expire) &&
	    !tick_is_expired(appctx->t->expire, now_ms))
		goto wait;

	/* here we should evaluate our waiting conditions, if any */

	if (ctx->cond == CLI_WAIT_COND_SRV_UNUSED) {
		/* check if the server in args[0]/args[1] can be released now */
		thread_isolate();
		ret = srv_check_for_deletion(ctx->args[0], ctx->args[1], NULL, NULL, NULL);
		thread_release();

		if (ret < 0) {
			/* unrecoverable failure */
			ctx->error = CLI_WAIT_ERR_FAIL;
			return 1;
		} else if (ret > 0) {
			/* immediate success */
			ctx->error = CLI_WAIT_ERR_DONE;
			return 1;
		}
		/* let's check the timer */
	}

	/* and here we recalculate the new wait time or abort */
	left  = tick_remain(now_ms, ctx->deadline);
	if (!left) {
		/* let the release handler know we've expired. When there is no
		 * wait condition, it's a simple sleep so we declare we're done.
		 */
		if (ctx->cond == CLI_WAIT_COND_NONE)
			ctx->error = CLI_WAIT_ERR_DONE;
		else
			ctx->error = CLI_WAIT_ERR_EXP;
		return 1;
	}

	total = tick_remain(ctx->start, ctx->deadline);
	elapsed = total - left;
	wait = elapsed / 2 + 1;
	if (wait > left)
		wait = left;
	else if (wait > total / 10)
		wait = total / 10;

	appctx->t->expire = tick_add(now_ms, wait);

 wait:
	/* Stop waiting upon close/abort/error */
	if (unlikely(se_fl_test(appctx->sedesc, SE_FL_SHW)) && !b_data(&appctx->inbuf)) {
		ctx->error = CLI_WAIT_ERR_INTR;
		return 1;
	}

	return 0;
}


/* release structs allocated by "delete server" */
static void cli_release_wait(struct appctx *appctx)
{
	struct cli_wait_ctx *ctx = appctx->svcctx;
	const char *msg;
	int i;

	switch (ctx->error) {
	case CLI_WAIT_ERR_EXP:      msg = "Wait delay expired.\n"; break;
	case CLI_WAIT_ERR_INTR:     msg = "Interrupted.\n"; break;
	case CLI_WAIT_ERR_FAIL:     msg = ctx->msg ? ctx->msg : "Failed.\n"; break;
	default:                    msg = "Done.\n"; break;
	}

	for (i = 0; i < sizeof(ctx->args) / sizeof(ctx->args[0]); i++)
		ha_free(&ctx->args[i]);

	if (ctx->error == CLI_WAIT_ERR_DONE)
		cli_msg(appctx, LOG_INFO, msg);
	else
		cli_err(appctx, msg);
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
	static int already_sent = 0;
	char *cmsgbuf = NULL;
	unsigned char *tmpbuf = NULL;
	struct cmsghdr *cmsg;
	struct stconn *sc = appctx_sc(appctx);
	struct stream *s = __sc_strm(sc);
	struct connection *remote = sc_conn(sc_opposite(sc));
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

	if (tot_fd_nb == 0) {
		if (already_sent)
			ha_warning("_getsocks: attempt to get sockets but they were already sent and closed in this process!\n");
		goto out;
	}

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

	already_sent = 1;

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
	se_fl_set(appctx->sedesc, SE_FL_EOI);
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
		if (strcmp(args[1], "timed") == 0) {
			appctx->st1 |= APPCTX_CLI_ST1_PROMPT;
			appctx->st1 ^= APPCTX_CLI_ST1_TIMED;
		}
		else
			appctx->st1 ^= APPCTX_CLI_ST1_PROMPT;
	else if (*args[0] == 'q') {
		/* quit */
		se_fl_set(appctx->sedesc, SE_FL_EOI);
		appctx->st0 = CLI_ST_END;
	}

	return 1;
}

static int cli_parse_echo(char **args, char *payload, struct appctx *appctx, void *private)
{
	int i = 1; /* starts after 'echo' */

	chunk_reset(&trash);

	while (*args[i]) {
		/* add a space if there was a word before */
		if (i == 1)
			chunk_printf(&trash, "%s", args[i]);
		else
			chunk_appendf(&trash, " %s", args[i]);
		i++;
	}
	chunk_appendf(&trash, "\n");

	cli_msg(appctx, LOG_INFO, trash.area);

	return 1;
}

static int _send_status(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct listener *mproxy_li;
	struct mworker_proc *proc;
	char *msg = "READY\n";
	int pid;

	BUG_ON((strcmp(args[0], "_send_status") != 0),
		"Triggered in _send_status by unsupported command name.\n");

	pid = atoi(args[2]);

	list_for_each_entry(proc, &proc_list, list) {
		/* update status of the new worker */
		if (proc->pid == pid) {
			proc->options &= ~PROC_O_INIT;
			mproxy_li = fdtab[proc->ipc_fd[0]].owner;
			stop_listener(mproxy_li, 0, 0, 0);
		}
		/* send TERM to workers, which have exceeded max_reloads counter */
		if (max_reloads != -1) {
			if ((proc->options & PROC_O_TYPE_WORKER) &&
				(proc->options & PROC_O_LEAVING) &&
				(proc->reloads > max_reloads) && (proc->pid > 0)) {
				kill(proc->pid, SIGTERM);
			}

		}
	}

	/* At this point we are sure, that newly forked worker is started,
	 * so we can write our PID in a pidfile, if provided. Master doesn't
	 * perform chroot.
	 */
	if (global.pidfile != NULL) {
		if (handle_pidfile() < 0) {
			ha_alert("Fatal error(s) found, exiting.\n");
			exit(1);
		}
	}

	/* either send USR1/TERM to old master, case when we launched as -W -D ... -sf $(cat pidfile),
	 * or send USR1/TERM to old worker processes.
	 */
	if (nb_oldpids > 0) {
		nb_oldpids = tell_old_pids(oldpids_sig);
	}

	if (daemon_fd[1] != -1) {
		if (write(daemon_fd[1], msg, strlen(msg)) < 0) {
			ha_alert("[%s.main()] Failed to write into pipe with parent process: %s\n", progname, strerror(errno));
			exit(1);
		}
		close(daemon_fd[1]);
		daemon_fd[1] = -1;
	}

	load_status = 1;
	ha_notice("Loading success.\n");

	if (global.tune.options & GTUNE_USE_SYSTEMD)
		sd_notifyf(0, "READY=1\nMAINPID=%lu\nSTATUS=Ready.\n", (unsigned long)getpid());

	/* master and worker have successfully started, now we can set quiet mode
	 * if MODE_DAEMON
	 */
	if ((!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) &&
		(global.mode & MODE_DAEMON)) {
		/* detach from the tty, this is required to properly daemonize. */
		if ((getenv("HAPROXY_MWORKER_REEXEC") == NULL))
			stdio_quiet(-1);
		global.mode &= ~MODE_VERBOSE;
		global.mode |= MODE_QUIET; /* ensure that we won't say anything from now */
	}

	return 1;
}

void pcli_write_prompt(struct stream *s)
{
	struct buffer *msg = get_trash_chunk();
	struct channel *oc = sc_oc(s->scf);

	if (!(s->pcli_flags & PCLI_F_PROMPT))
		return;

	if (s->pcli_flags & PCLI_F_PAYLOAD) {
		chunk_appendf(msg, "+ ");
	} else {
		if (s->pcli_next_pid == 0) {
			/* master's prompt */
			if (s->pcli_flags & PCLI_F_TIMED) {
				uint up = ns_to_sec(now_ns - start_time_ns);
				chunk_appendf(msg, "[%u:%02u:%02u:%02u] ",
				         (up / 86400), (up / 3600) % 24, (up / 60) % 60, up % 60);
			}

			chunk_appendf(msg, "master%s",
			              (proc_self->failedreloads > 0) ? "[ReloadFailed]" : "");
		}
		else {
			/* worker's prompt */
			if (s->pcli_flags & PCLI_F_TIMED) {
				const struct mworker_proc *tmp, *proc;
				uint up;

				/* set proc to the worker corresponding to pcli_next_pid or NULL */
				proc = NULL;
				list_for_each_entry(tmp, &proc_list, list) {
					if (!(tmp->options & PROC_O_TYPE_WORKER))
						continue;
					if (tmp->pid == s->pcli_next_pid) {
						proc = tmp;
						break;
					}
				}

				if (!proc)
					chunk_appendf(msg, "[gone] ");
				else {
					up = date.tv_sec - proc->timestamp;
					if ((int)up < 0) /* must never be negative because of clock drift */
						up = 0;
					chunk_appendf(msg, "[%u:%02u:%02u:%02u] ",
						      (up / 86400), (up / 3600) % 24, (up / 60) % 60, up % 60);
				}
			}
			chunk_appendf(msg, "%d", s->pcli_next_pid);
		}

		if (s->pcli_flags & (ACCESS_EXPERIMENTAL|ACCESS_EXPERT|ACCESS_MCLI_DEBUG)) {
			chunk_appendf(msg, "(");

			if (s->pcli_flags & ACCESS_EXPERIMENTAL)
				chunk_appendf(msg, "x");

			if (s->pcli_flags & ACCESS_EXPERT)
				chunk_appendf(msg, "e");

			if (s->pcli_flags & ACCESS_MCLI_DEBUG)
				chunk_appendf(msg, "d");

			chunk_appendf(msg, ")");
		}

		chunk_appendf(msg, "> ");


	}
	co_inject(oc, msg->area, msg->data);
}

/* The pcli_* functions are used for the CLI proxy in the master */


/* flush the input buffer and output an error */
void pcli_error(struct stream *s, const char *msg)
{
	struct buffer *buf = get_trash_chunk();
	struct channel *oc = &s->res;
	struct channel *ic = &s->req;

	chunk_initstr(buf, msg);

	if (likely(buf && buf->data))
		co_inject(oc, buf->area, buf->data);

	channel_erase(ic);

}

/* flush the input buffer, output the error and close */
void pcli_reply_and_close(struct stream *s, const char *msg)
{
	struct buffer *buf = get_trash_chunk();

	chunk_initstr(buf, msg);
	stream_retnclose(s, buf);
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

		if (proc_pid != 1) /* only the "@1" relative PID is supported */
			return -1;

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

/*
 * pcli_find_and_exec_kw() parses a command for the master CLI.  It looks for a
 * prefix or a command that is handled directly by the proxy and never sent to
 * a worker.
 *
 * Return:
 *  >= 0 : number of words that were parsed and need to be skipped
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
		if (argl >= 2 && strcmp(args[1], "timed") == 0) {
			s->pcli_flags |= PCLI_F_PROMPT;
			s->pcli_flags ^= PCLI_F_TIMED;
		}
		else
			s->pcli_flags ^= PCLI_F_PROMPT;
		return argl; /* return the number of elements in the array */
	} else if (strcmp("quit", args[0]) == 0) {
		sc_schedule_abort(s->scf);
		sc_schedule_shutdown(s->scf);
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

	} else if (strcmp(args[0], "expert-mode") == 0) {
		if (!pcli_has_level(s, ACCESS_LVL_ADMIN)) {
			memprintf(errmsg, "Permission denied!\n");
			return -1;
		}

		s->pcli_flags &= ~ACCESS_EXPERT;
		if ((argl > 1) && (strcmp(args[1], "on") == 0))
			s->pcli_flags |= ACCESS_EXPERT;
		return argl;

	} else if (strcmp(args[0], "experimental-mode") == 0) {
		if (!pcli_has_level(s, ACCESS_LVL_ADMIN)) {
			memprintf(errmsg, "Permission denied!\n");
			return -1;
		}
		s->pcli_flags &= ~ACCESS_EXPERIMENTAL;
		if ((argl > 1) && (strcmp(args[1], "on") == 0))
			s->pcli_flags |= ACCESS_EXPERIMENTAL;
		return argl;
	} else if (strcmp(args[0], "mcli-debug-mode") == 0) {
		if (!pcli_has_level(s, ACCESS_LVL_ADMIN)) {
			memprintf(errmsg, "Permission denied!\n");
			return -1;
		}
		s->pcli_flags &= ~ACCESS_MCLI_DEBUG;
		if ((argl > 1) && (strcmp(args[1], "on") == 0))
			s->pcli_flags |= ACCESS_MCLI_DEBUG;
		return argl;
	} else if (strcmp(args[0], "set") == 0) {
		if ((argl > 1) && (strcmp(args[1], "severity-output") == 0)) {
			if ((argl > 2) &&strcmp(args[2], "none") == 0) {
				s->pcli_flags &= ~(ACCESS_MCLI_SEVERITY_NB|ACCESS_MCLI_SEVERITY_STR);
			} else if ((argl > 2) && strcmp(args[2], "string") == 0) {
				s->pcli_flags |= ACCESS_MCLI_SEVERITY_STR;
			} else if ((argl > 2) && strcmp(args[2], "number") == 0) {
				s->pcli_flags |= ACCESS_MCLI_SEVERITY_NB;
			} else {
				memprintf(errmsg, "one of 'none', 'number', 'string' is a required argument\n");
				return -1;
			}
			/* only skip argl if we have "set severity-output" not only "set" */
			return argl;
		}
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
		ret = -1;
		goto end;
	}

	/* in payload mode, skip the whole parsing/exec and just look for a pattern */
	if (s->pcli_flags & PCLI_F_PAYLOAD) {
		if (reql-1 == strlen(s->pcli_payload_pat)) {
			/* the custom pattern len can be 0 (empty line)  */
			if (strncmp(str, s->pcli_payload_pat, strlen(s->pcli_payload_pat)) == 0) {
				s->pcli_flags &= ~PCLI_F_PAYLOAD;
			}
		}
		ret = reql;
		goto end;
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

	/* first look for '<<' at the beginning of the last argument */
	if (argl && strncmp(args[argl-1], PAYLOAD_PATTERN, strlen(PAYLOAD_PATTERN)) == 0) {
		size_t pat_len = strlen(args[argl-1] + strlen(PAYLOAD_PATTERN));

		/*
		 * A customized pattern can't be more than 7 characters
		 * if it's more, don't make it a payload
		 */
		if (pat_len < sizeof(s->pcli_payload_pat)) {
			s->pcli_flags |= PCLI_F_PAYLOAD;
			/* copy the customized pattern, don't store the << */
			strncpy(s->pcli_payload_pat, args[argl-1] + strlen(PAYLOAD_PATTERN), sizeof(s->pcli_payload_pat)-1);
			s->pcli_payload_pat[sizeof(s->pcli_payload_pat)-1] = '\0';
		}
	}

	for (; i < MAX_CLI_ARGS + 1; i++)
		args[i] = NULL;

	wtrim = pcli_find_and_exec_kw(s, args, argl, errmsg, next_pid);

	/* End of words are ending by \0, we need to replace the \0s by spaces
	   before forwarding them */
	p = str;
	while (p < end-1) {
		if (*p == '\0')
			*p = ' ';
		p++;
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
		ret = -1;
		goto end;
	} else {
		/* the whole string */
		ret = end - str;
	}

	if (ret > 1) {

		/* the mcli-debug-mode is only sent to the applet of the master */
		if ((s->pcli_flags & ACCESS_MCLI_DEBUG) && *next_pid <= 0) {
			const char *cmd = "mcli-debug-mode on -;";
			ci_insert(req, 0, cmd, strlen(cmd));
			ret += strlen(cmd);
		}
		if (s->pcli_flags & ACCESS_EXPERIMENTAL) {
			const char *cmd = "experimental-mode on -;";
			ci_insert(req, 0, cmd, strlen(cmd));
			ret += strlen(cmd);
		}
		if (s->pcli_flags & ACCESS_EXPERT) {
			const char *cmd = "expert-mode on -;";
			ci_insert(req, 0, cmd, strlen(cmd));
			ret += strlen(cmd);
		}
		if (s->pcli_flags & ACCESS_MCLI_SEVERITY_STR) {
			const char *cmd = "set severity-output string -;";
			ci_insert(req, 0, cmd, strlen(cmd));
			ret += strlen(cmd);
		}
		if (s->pcli_flags & ACCESS_MCLI_SEVERITY_NB) {
			const char *cmd = "set severity-output number -;";
			ci_insert(req, 0, cmd, strlen(cmd));
			ret += strlen(cmd);
		}

		if (pcli_has_level(s, ACCESS_LVL_ADMIN)) {
			goto end;
		} else if (pcli_has_level(s, ACCESS_LVL_OPER)) {
			const char *cmd = "operator -;";
			ci_insert(req, 0, cmd, strlen(cmd));
			ret += strlen(cmd);
		} else if (pcli_has_level(s, ACCESS_LVL_USER)) {
			const char *cmd = "user -;";
			ci_insert(req, 0, cmd, strlen(cmd));
			ret += strlen(cmd);
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

	/* stream that comes from the reload listener only responses the reload
	 * status and quits */
	if (!(s->pcli_flags & PCLI_F_RELOAD)
	    && strm_li(s)->bind_conf == mcli_reload_bind_conf)
		goto send_status;


read_again:
	/* if the channel is closed for read, we won't receive any more data
	   from the client, but we don't want to forward this close to the
	   server */
	channel_dont_close(req);

	/* We don't know yet to which server we will connect */
	channel_dont_connect(req);

	s->scf->flags |= SC_FL_RCV_ONCE;

	/* need more data */
	if (!ci_data(req))
		goto missing_data;

	/* If there is data available for analysis, log the end of the idle time. */
	if (c_data(req) && s->logs.t_idle == -1)
		s->logs.t_idle = ns_to_ms(now_ns - s->logs.accept_ts) - s->logs.t_handshake;

	to_forward = pcli_parse_request(s, req, &errmsg, &next_pid);
	if (to_forward > 0) {
		int target_pid;
		/* enough data */

		/* forward only 1 command */
		channel_forward(req, to_forward);

		if (!(s->pcli_flags & PCLI_F_PAYLOAD)) {
			/* we send only 1 command per request, and we write close after it */
			sc_schedule_shutdown(s->scb);
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
                if (!errmsg) /* no error means missing data */
			goto missing_data;

		/* there was an error during the parsing */
		pcli_error(s, errmsg);
		pcli_write_prompt(s);
	}

	return 0;

send_help:
	b_reset(&req->buf);
	b_putblk(&req->buf, "help\n", 5);
	goto read_again;

send_status:
	s->pcli_flags |= PCLI_F_RELOAD;
	/* don't use ci_putblk here because SHUT_DONE could have been sent */
	b_reset(&req->buf);
	b_putblk(&req->buf, "_loadstatus;quit\n", 17);
	goto read_again;

missing_data:
        if (s->scf->flags & (SC_FL_ABRT_DONE|SC_FL_EOS)) {
                /* There is no more request or a only a partial one and we
                 * receive a close from the client, we can leave */
		sc_schedule_shutdown(s->scf);
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

	if ((s->scb->flags & SC_FL_ERROR) || (rep->flags & (CF_READ_TIMEOUT|CF_WRITE_TIMEOUT)) ||
	    ((s->scf->flags & SC_FL_SHUT_DONE) && (rep->to_forward || co_data(rep)))) {
		pcli_reply_and_close(s, "Can't connect to the target CLI!\n");
		s->req.analysers &= ~AN_REQ_WAIT_CLI;
		s->res.analysers &= ~AN_RES_WAIT_CLI;
		return 0;
	}
	s->scb->flags |= SC_FL_RCV_ONCE; /* try to get back here ASAP */
	s->scf->flags |= SC_FL_SND_NEVERWAIT;

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

	if (s->scb->flags & (SC_FL_ABRT_DONE|SC_FL_EOS)) {
		uint8_t do_log = 0;

		/* stream cleanup */

		pcli_write_prompt(s);

		s->scb->flags |= SC_FL_NOLINGER | SC_FL_NOHALF;
		sc_abort(s->scb);
		sc_shutdown(s->scb);

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

		s->logs.t_close = ns_to_ms(now_ns - s->logs.accept_ts);
		stream_process_counters(s);

		/* don't count other requests' data */
		s->logs.bytes_in  -= ci_data(&s->req);
		s->logs.bytes_out -= ci_data(&s->res);

		/* we may need to know the position in the queue */
		pendconn_free(s);

		/* let's do a final log if we need it */
		if (fe->to_log == LW_LOGSTEPS) {
			if (log_orig_proxy(LOG_ORIG_TXN_CLOSE, fe))
				do_log = 1;
		}
		else if (!lf_expr_isempty(&fe->logformat) && s->logs.logwait)
			do_log = 1;

		if (do_log &&
		    !(s->flags & SF_MONITOR) &&
		    (!(fe->options & PR_O_NULLNOLOG) || s->req.total)) {
			s->do_log(s, log_orig(LOG_ORIG_TXN_CLOSE, LOG_ORIG_FL_NONE));
		}

		/* stop tracking content-based counters */
		stream_stop_content_counters(s);
		stream_update_time_stats(s);

		s->logs.accept_date = date; /* user-visible date for logging */
		s->logs.accept_ts = now_ns;  /* corrected date for internal use */
		s->logs.t_handshake = 0; /* There are no handshake in keep alive connection. */
		s->logs.t_idle = -1;
		s->logs.request_ts = 0;
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

		/* Always release our endpoint */
		s->srv_conn = NULL;
		if (sc_reset_endp(s->scb) < 0) {
			if (!s->conn_err_type)
				s->conn_err_type = STRM_ET_CONN_OTHER;
			if (s->srv_error)
				s->srv_error(s, s->scb);
			return 1;
		}
		se_fl_clr(s->scb->sedesc, ~SE_FL_DETACHED);

		sockaddr_free(&s->scb->dst);

		sc_set_state(s->scb, SC_ST_INI);
		s->scb->flags &= ~(SC_FL_ERROR|SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED);
		s->scb->flags &= SC_FL_ISBACK | SC_FL_DONT_WAKE; /* we're in the context of process_stream */

		s->req.flags &= ~(CF_AUTO_CONNECT|CF_STREAMER|CF_STREAMER_FAST|CF_WROTE_DATA);
		s->res.flags &= ~(CF_STREAMER|CF_STREAMER_FAST|CF_WRITE_EVENT|CF_WROTE_DATA|CF_READ_EVENT);
		s->flags &= ~(SF_DIRECT|SF_ASSIGNED|SF_BE_ASSIGNED|SF_FORCE_PRST|SF_IGNORE_PRST);
		s->flags &= ~(SF_CURR_SESS|SF_REDIRECTABLE|SF_SRV_REUSED);
		s->flags &= ~(SF_ERR_MASK|SF_FINST_MASK|SF_REDISP);
		s->conn_retries = 0;  /* used for logging too */
		s->conn_exp = TICK_ETERNITY;
		s->conn_err_type = STRM_ET_NONE;
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
		s->uniq_id = _HA_ATOMIC_FETCH_ADD(&global.req_count, 1);

		s->scf->flags &= ~(SC_FL_EOI|SC_FL_EOS|SC_FL_ERROR|SC_FL_ABRT_DONE|SC_FL_ABRT_WANTED);
		s->scf->flags &= ~SC_FL_SND_NEVERWAIT;
		s->scf->flags |= SC_FL_RCV_ONCE; /* one read is usually enough */

		se_have_more_data(s->scf->sedesc);

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

		s->scf->ioto = strm_fe(s)->timeout.client;
		s->scb->ioto = TICK_ETERNITY;

		s->req.analyse_exp = TICK_ETERNITY;
		s->res.analyse_exp = TICK_ETERNITY;

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
 * Create the MASTER proxy
 */
int mworker_cli_create_master_proxy(char **errmsg)
{
	mworker_proxy = alloc_new_proxy("MASTER", PR_CAP_LISTEN|PR_CAP_INT, errmsg);
	if (!mworker_proxy) {
		return -1;
	}

	mworker_proxy->mode = PR_MODE_CLI;
	/* default to 10 concurrent connections */
	mworker_proxy->maxconn = 10;
	/* no timeout */
	mworker_proxy->timeout.client = 0;
	mworker_proxy->conf.file = strdup("MASTER");
	mworker_proxy->conf.line = 0;
	mworker_proxy->accept = frontend_accept;
	mworker_proxy->lbprm.algo = BE_LB_ALGO_NONE;

	/* Does not init the default target the CLI applet, but must be done in
	 * the request parsing code */
	mworker_proxy->default_target = NULL;
	mworker_proxy->next = proxies_list;
	proxies_list = mworker_proxy;

	return 0;
}

/*
 * Attach servers to ipc_fd[0] of all presented in proc_list workers. Master and
 * worker share MCLI sockpair (ipc_fd[0] and ipc_fd[1]). Servers are attached to
 * ipc_fd[0], which is always opened at master side. ipc_fd[0] of worker, started
 * before the reload, is inherited in master after the reload (execvp).
 */
int mworker_cli_attach_server(char **errmsg)
{
	char *msg = NULL;
	struct mworker_proc *child;

	BUG_ON((mworker_proxy == NULL), "Triggered in mworker_cli_attach_server(), "
		"mworker_proxy must be created before this call.\n");

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

		if (child->options & PROC_O_INIT)
			memprintf(&msg, "cur-%d", 1);
		else
			memprintf(&msg, "old-%d", child->pid);

		newsrv->next = mworker_proxy->srv;
		mworker_proxy->srv = newsrv;
		newsrv->conf.file = strdup(msg);
		newsrv->id = strdup(msg);
		newsrv->conf.line = 0;

		memprintf(&msg, "sockpair@%d", child->ipc_fd[0]);
		if ((sk = str2sa_range(msg, &port, &port1, &port2, NULL, &proto, NULL,
		                       errmsg, NULL, NULL, NULL, PA_O_STREAM)) == 0) {
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

	return 0;

error:

	list_for_each_entry(child, &proc_list, list) {
		free((char *)child->srv->conf.file); /* cast because of const char *  */
		free(child->srv->id);
		ha_free(&child->srv);
	}
	free(msg);

	return -1;
}

/*
 * Create a new listener for the master CLI proxy
 */
struct bind_conf *mworker_cli_master_proxy_new_listener(char *line)
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


	bind_conf->accept = session_accept_fd;
	bind_conf->nice = -64;  /* we want to boost priority for local stats */
	bind_conf->options |= BC_O_UNLIMITED; /* don't make the peers subject to global limits */

	/* Pin master CLI on the first thread of the first group only */
	thread_set_pin_grp1(&bind_conf->thread_set, 1);

	list_for_each_entry(l, &bind_conf->listeners, by_bind) {
		l->rx.flags |= RX_F_MWORKER; /* we are keeping this FD in the master */
		global.maxsock++; /* for the listening socket */
	}
	global.maxsock += mworker_proxy->maxconn;

	return bind_conf;

err:
	ha_alert("%s\n", err);
	free(err);
	free(bind_conf);
	return NULL;

}

/*
 * Creates a "master-socket" bind conf and a listener. Assigns
 * this new listener to the one "end" of the given process <proc> sockpair in
 * order to have a new master CLI listening socket for this process.
 */
int mworker_cli_global_proxy_new_listener(struct mworker_proc *proc)
{
	struct bind_conf *bind_conf;
	struct listener *l;
	char *path = NULL;
	char *err = NULL;

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

	if (!memprintf(&path, "sockpair@%d", proc->ipc_fd[1])) {
		ha_alert("Cannot allocate listener.\n");
		goto error;
	}

	if (!str2listener(path, global.cli_fe, bind_conf, "master-socket", 0, &err)) {
		free(path);
		ha_alert("Cannot create a CLI sockpair listener.\n");
		goto error;
	}
	ha_free(&path);

	bind_conf->accept = session_accept_fd;
	bind_conf->nice = -64;  /* we want to boost priority for local stats */
	bind_conf->options |= BC_O_UNLIMITED | BC_O_NOSTOP;

	/* Pin master CLI on the first thread of the first group only */
	thread_set_pin_grp1(&bind_conf->thread_set, 1);

	list_for_each_entry(l, &bind_conf->listeners, by_bind) {
		HA_ATOMIC_INC(&unstoppable_jobs);
		/* it's a sockpair but we don't want to keep the fd in the master */
		l->rx.flags &= ~RX_F_INHERITED;
		global.maxsock++; /* for the listening socket */
	}

	return 0;

error:
	close(proc->ipc_fd[1]);
	free(err);

	return -1;
}

static struct applet cli_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<CLI>", /* used for logging */
	.fct = cli_io_handler,
	.rcv_buf = appctx_raw_rcv_buf,
	.snd_buf = cli_snd_buf,
	.release = cli_release_handler,
};

/* master CLI */
static struct applet mcli_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<MCLI>", /* used for logging */
	.fct = cli_io_handler,
	.rcv_buf = appctx_raw_rcv_buf,
	.snd_buf = cli_snd_buf,
	.release = cli_release_handler,
};

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "help", NULL },                      NULL,                                                                                                cli_parse_simple, NULL, NULL, NULL, ACCESS_MASTER },
	{ { "echo", NULL },                      "echo <text>                             : print text to the output",                                cli_parse_echo,   NULL, NULL, NULL, ACCESS_MASTER },
	{ { "prompt", NULL },                    NULL,                                                                                                cli_parse_simple, NULL, NULL, NULL, ACCESS_MASTER },
	{ { "quit", NULL },                      NULL,                                                                                                cli_parse_simple, NULL, NULL, NULL, ACCESS_MASTER },
	{ { "_getsocks", NULL },                 NULL,                                                                                                _getsocks, NULL },
	{ { "expert-mode", NULL },               NULL,                                                                                                cli_parse_expert_experimental_mode, NULL, NULL, NULL, ACCESS_MASTER }, // not listed
	{ { "experimental-mode", NULL },         NULL,                                                                                                cli_parse_expert_experimental_mode, NULL, NULL, NULL, ACCESS_MASTER }, // not listed
	{ { "mcli-debug-mode", NULL },         NULL,                                                                                                  cli_parse_expert_experimental_mode, NULL, NULL, NULL, ACCESS_MASTER_ONLY }, // not listed
	{ { "set", "anon", "on" },               "set anon on [value]                     : activate the anonymized mode",                            cli_parse_set_anon, NULL, NULL },
	{ { "set", "anon", "off" },              "set anon off                            : deactivate the anonymized mode",                          cli_parse_set_anon, NULL, NULL },
	{ { "set", "anon", "global-key", NULL }, "set anon global-key <value>             : change the global anonymizing key",                       cli_parse_set_global_key, NULL, NULL },
	{ { "set", "maxconn", "global",  NULL }, "set maxconn global <value>              : change the per-process maxconn setting",                  cli_parse_set_maxconn_global, NULL },
	{ { "set", "rate-limit", NULL },         "set rate-limit <setting> <value>        : change a rate limiting value",                            cli_parse_set_ratelimit, NULL },
	{ { "set", "severity-output",  NULL },   "set severity-output [none|number|string]: set presence of severity level in feedback information",  cli_parse_set_severity_output, NULL, NULL },
	{ { "set", "timeout",  NULL },           "set timeout [cli] <delay>               : change a timeout setting",                                cli_parse_set_timeout, NULL, NULL },
	{ { "show", "anon", NULL },              "show anon                               : display the current state of anonymized mode",            cli_parse_show_anon, NULL },
	{ { "show", "env",  NULL },              "show env [var]                          : dump environment variables known to the process",         cli_parse_show_env, cli_io_handler_show_env, NULL, NULL, ACCESS_MASTER },
	{ { "show", "cli", "sockets",  NULL },   "show cli sockets                        : dump list of cli sockets",                                cli_parse_default, cli_io_handler_show_cli_sock, NULL, NULL, ACCESS_MASTER },
	{ { "show", "cli", "level", NULL },      "show cli level                          : display the level of the current CLI session",            cli_parse_show_lvl, NULL, NULL, NULL, ACCESS_MASTER},
	{ { "show", "fd", NULL },                "show fd [-!plcfbsd]* [num]              : dump list of file descriptors in use or a specific one",  cli_parse_show_fd, cli_io_handler_show_fd, NULL },
	{ { "show", "version", NULL },           "show version                            : show version of the current process",                     cli_parse_show_version, NULL, NULL, NULL, ACCESS_MASTER },
	{ { "operator", NULL },                  "operator                                : lower the level of the current CLI session to operator",  cli_parse_set_lvl, NULL, NULL, NULL, ACCESS_MASTER},
	{ { "user", NULL },                      "user                                    : lower the level of the current CLI session to user",      cli_parse_set_lvl, NULL, NULL, NULL, ACCESS_MASTER},
	{ { "wait", NULL },                      "wait {-h|<delay_ms>} cond [args...]     : wait the specified delay or condition (-h to see list)",  cli_parse_wait, cli_io_handler_wait, cli_release_wait, NULL },
	{ { "_send_status", NULL },              NULL,  											      _send_status, NULL, NULL, NULL, ACCESS_MASTER_ONLY },
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
