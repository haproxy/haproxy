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
#include <proto/proto_http.h>
#include <proto/proto_uxst.h>
#include <proto/proxy.h>
#include <proto/sample.h>
#include <proto/session.h>
#include <proto/stream.h>
#include <proto/server.h>
#include <proto/raw_sock.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

#ifdef USE_OPENSSL
#include <proto/ssl_sock.h>
#include <types/ssl_sock.h>
#endif

/* These are the field names for each INF_* field position. Please pay attention
 * to always use the exact same name except that the strings for new names must
 * be lower case or CamelCase while the enum entries must be upper case.
 */
const char *info_field_names[INF_TOTAL_FIELDS] = {
	[INF_NAME]                           = "Name",
	[INF_VERSION]                        = "Version",
	[INF_RELEASE_DATE]                   = "Release_date",
	[INF_NBPROC]                         = "Nbproc",
	[INF_PROCESS_NUM]                    = "Process_num",
	[INF_PID]                            = "Pid",
	[INF_UPTIME]                         = "Uptime",
	[INF_UPTIME_SEC]                     = "Uptime_sec",
	[INF_MEMMAX_MB]                      = "Memmax_MB",
	[INF_POOL_ALLOC_MB]                  = "PoolAlloc_MB",
	[INF_POOL_USED_MB]                   = "PoolUsed_MB",
	[INF_POOL_FAILED]                    = "PoolFailed",
	[INF_ULIMIT_N]                       = "Ulimit-n",
	[INF_MAXSOCK]                        = "Maxsock",
	[INF_MAXCONN]                        = "Maxconn",
	[INF_HARD_MAXCONN]                   = "Hard_maxconn",
	[INF_CURR_CONN]                      = "CurrConns",
	[INF_CUM_CONN]                       = "CumConns",
	[INF_CUM_REQ]                        = "CumReq",
	[INF_MAX_SSL_CONNS]                  = "MaxSslConns",
	[INF_CURR_SSL_CONNS]                 = "CurrSslConns",
	[INF_CUM_SSL_CONNS]                  = "CumSslConns",
	[INF_MAXPIPES]                       = "Maxpipes",
	[INF_PIPES_USED]                     = "PipesUsed",
	[INF_PIPES_FREE]                     = "PipesFree",
	[INF_CONN_RATE]                      = "ConnRate",
	[INF_CONN_RATE_LIMIT]                = "ConnRateLimit",
	[INF_MAX_CONN_RATE]                  = "MaxConnRate",
	[INF_SESS_RATE]                      = "SessRate",
	[INF_SESS_RATE_LIMIT]                = "SessRateLimit",
	[INF_MAX_SESS_RATE]                  = "MaxSessRate",
	[INF_SSL_RATE]                       = "SslRate",
	[INF_SSL_RATE_LIMIT]                 = "SslRateLimit",
	[INF_MAX_SSL_RATE]                   = "MaxSslRate",
	[INF_SSL_FRONTEND_KEY_RATE]          = "SslFrontendKeyRate",
	[INF_SSL_FRONTEND_MAX_KEY_RATE]      = "SslFrontendMaxKeyRate",
	[INF_SSL_FRONTEND_SESSION_REUSE_PCT] = "SslFrontendSessionReuse_pct",
	[INF_SSL_BACKEND_KEY_RATE]           = "SslBackendKeyRate",
	[INF_SSL_BACKEND_MAX_KEY_RATE]       = "SslBackendMaxKeyRate",
	[INF_SSL_CACHE_LOOKUPS]              = "SslCacheLookups",
	[INF_SSL_CACHE_MISSES]               = "SslCacheMisses",
	[INF_COMPRESS_BPS_IN]                = "CompressBpsIn",
	[INF_COMPRESS_BPS_OUT]               = "CompressBpsOut",
	[INF_COMPRESS_BPS_RATE_LIM]          = "CompressBpsRateLim",
	[INF_ZLIB_MEM_USAGE]                 = "ZlibMemUsage",
	[INF_MAX_ZLIB_MEM_USAGE]             = "MaxZlibMemUsage",
	[INF_TASKS]                          = "Tasks",
	[INF_RUN_QUEUE]                      = "Run_queue",
	[INF_IDLE_PCT]                       = "Idle_pct",
	[INF_NODE]                           = "node",
	[INF_DESCRIPTION]                    = "description",
};

/* one line of stats */
static struct field info[INF_TOTAL_FIELDS];

static int stats_dump_backend_to_buffer(struct stream_interface *si);
static int stats_dump_env_to_buffer(struct stream_interface *si);
static int stats_dump_info_to_buffer(struct stream_interface *si);
static int stats_dump_errors_to_buffer(struct stream_interface *si);
static int stats_table_request(struct stream_interface *si, int show);


static struct applet cli_applet;

static const char stats_sock_usage_msg[] =
	"Unknown command. Please enter one of the following commands only :\n"
	"  clear counters : clear max statistics counters (add 'all' for all counters)\n"
	"  clear table    : remove an entry from a table\n"
	"  help           : this message\n"
	"  prompt         : toggle interactive mode with prompt\n"
	"  quit           : disconnect\n"
	"  show backend   : list backends in the current running config\n"
	"  show env [var] : dump environment variables known to the process\n"
	"  show info      : report information about the running process\n"
	"  show stat      : report counters for each proxy and server\n"
	"  show errors    : report last request and response errors for each proxy\n"
	"  show table [id]: report table usage stats or dump this table's contents\n"
	"  get weight     : report a server's current weight\n"
	"  set weight     : change a server's weight\n"
	"  set table [id] : update or create a table entry's data\n"
	"  set timeout    : change a timeout setting\n"
	"  set maxconn    : change a maxconn setting\n"
	"  set rate-limit : change a rate limiting value\n"
	"  disable        : put a server or frontend in maintenance mode\n"
	"  enable         : re-enable a server or frontend which is in maintenance mode\n"
	"  shutdown       : kill a session or a frontend (eg:to release listening ports)\n"
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
		appctx->st0 = STAT_CLI_PRINT;
		return 0;
	}
	return 1;
}


/* print a string of text buffer to <out>. The format is :
 * Non-printable chars \t, \n, \r and \e are * encoded in C format.
 * Other non-printable chars are encoded "\xHH". Space, '\', and '=' are also escaped.
 * Print stopped if null char or <bsize> is reached, or if no more place in the chunk.
 */
static int dump_text(struct chunk *out, const char *buf, int bsize)
{
	unsigned char c;
	int ptr = 0;

	while (buf[ptr] && ptr < bsize) {
		c = buf[ptr];
		if (isprint(c) && isascii(c) && c != '\\' && c != ' ' && c != '=') {
			if (out->len > out->size - 1)
				break;
			out->str[out->len++] = c;
		}
		else if (c == '\t' || c == '\n' || c == '\r' || c == '\e' || c == '\\' || c == ' ' || c == '=') {
			if (out->len > out->size - 2)
				break;
			out->str[out->len++] = '\\';
			switch (c) {
			case ' ': c = ' '; break;
			case '\t': c = 't'; break;
			case '\n': c = 'n'; break;
			case '\r': c = 'r'; break;
			case '\e': c = 'e'; break;
			case '\\': c = '\\'; break;
			case '=': c = '='; break;
			}
			out->str[out->len++] = c;
		}
		else {
			if (out->len > out->size - 4)
				break;
			out->str[out->len++] = '\\';
			out->str[out->len++] = 'x';
			out->str[out->len++] = hextab[(c >> 4) & 0xF];
			out->str[out->len++] = hextab[c & 0xF];
		}
		ptr++;
	}

	return ptr;
}

/* print a buffer in hexa.
 * Print stopped if <bsize> is reached, or if no more place in the chunk.
 */
static int dump_binary(struct chunk *out, const char *buf, int bsize)
{
	unsigned char c;
	int ptr = 0;

	while (ptr < bsize) {
		c = buf[ptr];

		if (out->len > out->size - 2)
			break;
		out->str[out->len++] = hextab[(c >> 4) & 0xF];
		out->str[out->len++] = hextab[c & 0xF];

		ptr++;
	}
	return ptr;
}

/* Dump the status of a table to a stream interface's
 * read buffer. It returns 0 if the output buffer is full
 * and needs to be called again, otherwise non-zero.
 */
static int stats_dump_table_head_to_buffer(struct chunk *msg, struct stream_interface *si,
					   struct proxy *proxy, struct proxy *target)
{
	struct stream *s = si_strm(si);

	chunk_appendf(msg, "# table: %s, type: %s, size:%d, used:%d\n",
		     proxy->id, stktable_types[proxy->table.type].kw, proxy->table.size, proxy->table.current);

	/* any other information should be dumped here */

	if (target && strm_li(s)->bind_conf->level < ACCESS_LVL_OPER)
		chunk_appendf(msg, "# contents not dumped due to insufficient privileges\n");

	if (bi_putchk(si_ic(si), msg) == -1) {
		si_applet_cant_put(si);
		return 0;
	}

	return 1;
}

/* Dump the a table entry to a stream interface's
 * read buffer. It returns 0 if the output buffer is full
 * and needs to be called again, otherwise non-zero.
 */
static int stats_dump_table_entry_to_buffer(struct chunk *msg, struct stream_interface *si,
					    struct proxy *proxy, struct stksess *entry)
{
	int dt;

	chunk_appendf(msg, "%p:", entry);

	if (proxy->table.type == SMP_T_IPV4) {
		char addr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, (const void *)&entry->key.key, addr, sizeof(addr));
		chunk_appendf(msg, " key=%s", addr);
	}
	else if (proxy->table.type == SMP_T_IPV6) {
		char addr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, (const void *)&entry->key.key, addr, sizeof(addr));
		chunk_appendf(msg, " key=%s", addr);
	}
	else if (proxy->table.type == SMP_T_SINT) {
		chunk_appendf(msg, " key=%u", *(unsigned int *)entry->key.key);
	}
	else if (proxy->table.type == SMP_T_STR) {
		chunk_appendf(msg, " key=");
		dump_text(msg, (const char *)entry->key.key, proxy->table.key_size);
	}
	else {
		chunk_appendf(msg, " key=");
		dump_binary(msg, (const char *)entry->key.key, proxy->table.key_size);
	}

	chunk_appendf(msg, " use=%d exp=%d", entry->ref_cnt - 1, tick_remain(now_ms, entry->expire));

	for (dt = 0; dt < STKTABLE_DATA_TYPES; dt++) {
		void *ptr;

		if (proxy->table.data_ofs[dt] == 0)
			continue;
		if (stktable_data_types[dt].arg_type == ARG_T_DELAY)
			chunk_appendf(msg, " %s(%d)=", stktable_data_types[dt].name, proxy->table.data_arg[dt].u);
		else
			chunk_appendf(msg, " %s=", stktable_data_types[dt].name);

		ptr = stktable_data_ptr(&proxy->table, entry, dt);
		switch (stktable_data_types[dt].std_type) {
		case STD_T_SINT:
			chunk_appendf(msg, "%d", stktable_data_cast(ptr, std_t_sint));
			break;
		case STD_T_UINT:
			chunk_appendf(msg, "%u", stktable_data_cast(ptr, std_t_uint));
			break;
		case STD_T_ULL:
			chunk_appendf(msg, "%lld", stktable_data_cast(ptr, std_t_ull));
			break;
		case STD_T_FRQP:
			chunk_appendf(msg, "%d",
				     read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
							  proxy->table.data_arg[dt].u));
			break;
		}
	}
	chunk_appendf(msg, "\n");

	if (bi_putchk(si_ic(si), msg) == -1) {
		si_applet_cant_put(si);
		return 0;
	}

	return 1;
}

static void stats_sock_table_key_request(struct stream_interface *si, char **args, int action)
{
	struct stream *s = si_strm(si);
	struct appctx *appctx = __objt_appctx(si->end);
	struct proxy *px = appctx->ctx.table.target;
	struct stksess *ts;
	uint32_t uint32_key;
	unsigned char ip6_key[sizeof(struct in6_addr)];
	long long value;
	int data_type;
	int cur_arg;
	void *ptr;
	struct freq_ctr_period *frqp;

	appctx->st0 = STAT_CLI_OUTPUT;

	if (!*args[4]) {
		appctx->ctx.cli.msg = "Key value expected\n";
		appctx->st0 = STAT_CLI_PRINT;
		return;
	}

	switch (px->table.type) {
	case SMP_T_IPV4:
		uint32_key = htonl(inetaddr_host(args[4]));
		static_table_key->key = &uint32_key;
		break;
	case SMP_T_IPV6:
		inet_pton(AF_INET6, args[4], ip6_key);
		static_table_key->key = &ip6_key;
		break;
	case SMP_T_SINT:
		{
			char *endptr;
			unsigned long val;
			errno = 0;
			val = strtoul(args[4], &endptr, 10);
			if ((errno == ERANGE && val == ULONG_MAX) ||
			    (errno != 0 && val == 0) || endptr == args[4] ||
			    val > 0xffffffff) {
				appctx->ctx.cli.msg = "Invalid key\n";
				appctx->st0 = STAT_CLI_PRINT;
				return;
			}
			uint32_key = (uint32_t) val;
			static_table_key->key = &uint32_key;
			break;
		}
		break;
	case SMP_T_STR:
		static_table_key->key = args[4];
		static_table_key->key_len = strlen(args[4]);
		break;
	default:
		switch (action) {
		case STAT_CLI_O_TAB:
			appctx->ctx.cli.msg = "Showing keys from tables of type other than ip, ipv6, string and integer is not supported\n";
			break;
		case STAT_CLI_O_CLR:
			appctx->ctx.cli.msg = "Removing keys from ip tables of type other than ip, ipv6, string and integer is not supported\n";
			break;
		default:
			appctx->ctx.cli.msg = "Unknown action\n";
			break;
		}
		appctx->st0 = STAT_CLI_PRINT;
		return;
	}

	/* check permissions */
	if (strm_li(s)->bind_conf->level < ACCESS_LVL_OPER) {
		appctx->ctx.cli.msg = stats_permission_denied_msg;
		appctx->st0 = STAT_CLI_PRINT;
		return;
	}

	ts = stktable_lookup_key(&px->table, static_table_key);

	switch (action) {
	case STAT_CLI_O_TAB:
		if (!ts)
			return;
		chunk_reset(&trash);
		if (!stats_dump_table_head_to_buffer(&trash, si, px, px))
			return;
		stats_dump_table_entry_to_buffer(&trash, si, px, ts);
		return;

	case STAT_CLI_O_CLR:
		if (!ts)
			return;
		if (ts->ref_cnt) {
			/* don't delete an entry which is currently referenced */
			appctx->ctx.cli.msg = "Entry currently in use, cannot remove\n";
			appctx->st0 = STAT_CLI_PRINT;
			return;
		}
		stksess_kill(&px->table, ts);
		break;

	case STAT_CLI_O_SET:
		if (ts)
			stktable_touch(&px->table, ts, 1);
		else {
			ts = stksess_new(&px->table, static_table_key);
			if (!ts) {
				/* don't delete an entry which is currently referenced */
				appctx->ctx.cli.msg = "Unable to allocate a new entry\n";
				appctx->st0 = STAT_CLI_PRINT;
				return;
			}
			stktable_store(&px->table, ts, 1);
		}

		for (cur_arg = 5; *args[cur_arg]; cur_arg += 2) {
			if (strncmp(args[cur_arg], "data.", 5) != 0) {
				appctx->ctx.cli.msg = "\"data.<type>\" followed by a value expected\n";
				appctx->st0 = STAT_CLI_PRINT;
				return;
			}

			data_type = stktable_get_data_type(args[cur_arg] + 5);
			if (data_type < 0) {
				appctx->ctx.cli.msg = "Unknown data type\n";
				appctx->st0 = STAT_CLI_PRINT;
				return;
			}

			if (!px->table.data_ofs[data_type]) {
				appctx->ctx.cli.msg = "Data type not stored in this table\n";
				appctx->st0 = STAT_CLI_PRINT;
				return;
			}

			if (!*args[cur_arg+1] || strl2llrc(args[cur_arg+1], strlen(args[cur_arg+1]), &value) != 0) {
				appctx->ctx.cli.msg = "Require a valid integer value to store\n";
				appctx->st0 = STAT_CLI_PRINT;
				return;
			}

			ptr = stktable_data_ptr(&px->table, ts, data_type);

			switch (stktable_data_types[data_type].std_type) {
			case STD_T_SINT:
				stktable_data_cast(ptr, std_t_sint) = value;
				break;
			case STD_T_UINT:
				stktable_data_cast(ptr, std_t_uint) = value;
				break;
			case STD_T_ULL:
				stktable_data_cast(ptr, std_t_ull) = value;
				break;
			case STD_T_FRQP:
				/* We set both the current and previous values. That way
				 * the reported frequency is stable during all the period
				 * then slowly fades out. This allows external tools to
				 * push measures without having to update them too often.
				 */
				frqp = &stktable_data_cast(ptr, std_t_frqp);
				frqp->curr_tick = now_ms;
				frqp->prev_ctr = 0;
				frqp->curr_ctr = value;
				break;
			}
		}
		break;

	default:
		appctx->ctx.cli.msg = "Unknown action\n";
		appctx->st0 = STAT_CLI_PRINT;
		break;
	}
}

static void stats_sock_table_data_request(struct stream_interface *si, char **args, int action)
{
	struct appctx *appctx = __objt_appctx(si->end);

	if (action != STAT_CLI_O_TAB && action != STAT_CLI_O_CLR) {
		appctx->ctx.cli.msg = "content-based lookup is only supported with the \"show\" and \"clear\" actions";
		appctx->st0 = STAT_CLI_PRINT;
		return;
	}

	/* condition on stored data value */
	appctx->ctx.table.data_type = stktable_get_data_type(args[3] + 5);
	if (appctx->ctx.table.data_type < 0) {
		appctx->ctx.cli.msg = "Unknown data type\n";
		appctx->st0 = STAT_CLI_PRINT;
		return;
	}

	if (!((struct proxy *)appctx->ctx.table.target)->table.data_ofs[appctx->ctx.table.data_type]) {
		appctx->ctx.cli.msg = "Data type not stored in this table\n";
		appctx->st0 = STAT_CLI_PRINT;
		return;
	}

	appctx->ctx.table.data_op = get_std_op(args[4]);
	if (appctx->ctx.table.data_op < 0) {
		appctx->ctx.cli.msg = "Require and operator among \"eq\", \"ne\", \"le\", \"ge\", \"lt\", \"gt\"\n";
		appctx->st0 = STAT_CLI_PRINT;
		return;
	}

	if (!*args[5] || strl2llrc(args[5], strlen(args[5]), &appctx->ctx.table.value) != 0) {
		appctx->ctx.cli.msg = "Require a valid integer value to compare against\n";
		appctx->st0 = STAT_CLI_PRINT;
		return;
	}
}

static void stats_sock_table_request(struct stream_interface *si, char **args, int action)
{
	struct appctx *appctx = __objt_appctx(si->end);

	appctx->ctx.table.data_type = -1;
	appctx->st2 = STAT_ST_INIT;
	appctx->ctx.table.target = NULL;
	appctx->ctx.table.proxy = NULL;
	appctx->ctx.table.entry = NULL;
	appctx->st0 = action;

	if (*args[2]) {
		appctx->ctx.table.target = proxy_tbl_by_name(args[2]);
		if (!appctx->ctx.table.target) {
			appctx->ctx.cli.msg = "No such table\n";
			appctx->st0 = STAT_CLI_PRINT;
			return;
		}
	}
	else {
		if (action != STAT_CLI_O_TAB)
			goto err_args;
		return;
	}

	if (strcmp(args[3], "key") == 0)
		stats_sock_table_key_request(si, args, action);
	else if (strncmp(args[3], "data.", 5) == 0)
		stats_sock_table_data_request(si, args, action);
	else if (*args[3])
		goto err_args;

	return;

err_args:
	switch (action) {
	case STAT_CLI_O_TAB:
		appctx->ctx.cli.msg = "Optional argument only supports \"data.<store_data_type>\" <operator> <value> and key <key>\n";
		break;
	case STAT_CLI_O_CLR:
		appctx->ctx.cli.msg = "Required arguments: <table> \"data.<store_data_type>\" <operator> <value> or <table> key <key>\n";
		break;
	default:
		appctx->ctx.cli.msg = "Unknown action\n";
		break;
	}
	appctx->st0 = STAT_CLI_PRINT;
}

/* Expects to find a frontend named <arg> and returns it, otherwise displays various
 * adequate error messages and returns NULL. This function also expects the stream
 * level to be admin.
 */
static struct proxy *expect_frontend_admin(struct stream *s, struct stream_interface *si, const char *arg)
{
	struct appctx *appctx = __objt_appctx(si->end);
	struct proxy *px;

	if (strm_li(s)->bind_conf->level < ACCESS_LVL_ADMIN) {
		appctx->ctx.cli.msg = stats_permission_denied_msg;
		appctx->st0 = STAT_CLI_PRINT;
		return NULL;
	}

	if (!*arg) {
		appctx->ctx.cli.msg = "A frontend name is expected.\n";
		appctx->st0 = STAT_CLI_PRINT;
		return NULL;
	}

	px = proxy_fe_by_name(arg);
	if (!px) {
		appctx->ctx.cli.msg = "No such frontend.\n";
		appctx->st0 = STAT_CLI_PRINT;
		return NULL;
	}
	return px;
}

/* Expects to find a backend and a server in <arg> under the form <backend>/<server>,
 * and returns the pointer to the server. Otherwise, display adequate error messages
 * and returns NULL. This function also expects the stream level to be admin. Note:
 * the <arg> is modified to remove the '/'.
 */
struct server *expect_server_admin(struct stream *s, struct stream_interface *si, char *arg)
{
	struct appctx *appctx = __objt_appctx(si->end);
	struct proxy *px;
	struct server *sv;
	char *line;

	if (strm_li(s)->bind_conf->level < ACCESS_LVL_ADMIN) {
		appctx->ctx.cli.msg = stats_permission_denied_msg;
		appctx->st0 = STAT_CLI_PRINT;
		return NULL;
	}

	/* split "backend/server" and make <line> point to server */
	for (line = arg; *line; line++)
		if (*line == '/') {
			*line++ = '\0';
			break;
		}

	if (!*line || !*arg) {
		appctx->ctx.cli.msg = "Require 'backend/server'.\n";
		appctx->st0 = STAT_CLI_PRINT;
		return NULL;
	}

	if (!get_backend_server(arg, line, &px, &sv)) {
		appctx->ctx.cli.msg = px ? "No such server.\n" : "No such backend.\n";
		appctx->st0 = STAT_CLI_PRINT;
		return NULL;
	}

	if (px->state == PR_STSTOPPED) {
		appctx->ctx.cli.msg = "Proxy is disabled.\n";
		appctx->st0 = STAT_CLI_PRINT;
		return NULL;
	}

	return sv;
}

/* Processes the stats interpreter on the statistics socket. This function is
 * called from an applet running in a stream interface. The function returns 1
 * if the request was understood, otherwise zero. It sets appctx->st0 to a value
 * designating the function which will have to process the request, which can
 * also be the print function to display the return message set into cli.msg.
 */
static int stats_sock_parse_request(struct stream_interface *si, char *line)
{
	struct stream *s = si_strm(si);
	struct appctx *appctx = __objt_appctx(si->end);
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

	/* remove \ */
	arg = 0;
	while (*args[arg] != '\0') {
		j = 0;
		for (i=0; args[arg][i] != '\0'; i++) {
			if (args[arg][i] == '\\')
				continue;
			args[arg][j] = args[arg][i];
			j++;
		}
		args[arg][j] = '\0';
		arg++;
	}

	appctx->ctx.stats.scope_str = 0;
	appctx->ctx.stats.scope_len = 0;
	appctx->ctx.stats.flags = 0;
	if ((kw = cli_find_kw(args))) {
		if (kw->parse) {
			if (kw->parse(args, appctx, kw->private) == 0 && kw->io_handler) {
				appctx->st0 = STAT_CLI_O_CUSTOM;
				appctx->io_handler = kw->io_handler;
				appctx->io_release = kw->io_release;
			}
		}
	} else if (strcmp(args[0], "show") == 0) {
		if (strcmp(args[1], "backend") == 0) {
			appctx->ctx.be.px = NULL;
			appctx->st2 = STAT_ST_INIT;
			appctx->st0 = STAT_CLI_O_BACKEND;
		}
		else if (strcmp(args[1], "env") == 0) {
			extern char **environ;

			if (strm_li(s)->bind_conf->level < ACCESS_LVL_OPER) {
				appctx->ctx.cli.msg = stats_permission_denied_msg;
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}
			appctx->ctx.env.var = environ;
			appctx->st2 = STAT_ST_INIT;
			appctx->st0 = STAT_CLI_O_ENV; // stats_dump_env_to_buffer

			if (*args[2]) {
				int len = strlen(args[2]);

				for (; *appctx->ctx.env.var; appctx->ctx.env.var++) {
					if (strncmp(*appctx->ctx.env.var, args[2], len) == 0 &&
					    (*appctx->ctx.env.var)[len] == '=')
						break;
				}
				if (!*appctx->ctx.env.var) {
					appctx->ctx.cli.msg = "Variable not found\n";
					appctx->st0 = STAT_CLI_PRINT;
					return 1;
				}
				appctx->st2 = STAT_ST_END;
			}
		}
		else if (strcmp(args[1], "stat") == 0) {
			if (*args[2] && *args[3] && *args[4]) {
				appctx->ctx.stats.flags |= STAT_BOUND;
				appctx->ctx.stats.iid = atoi(args[2]);
				appctx->ctx.stats.type = atoi(args[3]);
				appctx->ctx.stats.sid = atoi(args[4]);
				if (strcmp(args[5], "typed") == 0)
					appctx->ctx.stats.flags |= STAT_FMT_TYPED;
			}
			else if (strcmp(args[2], "typed") == 0)
				appctx->ctx.stats.flags |= STAT_FMT_TYPED;

			appctx->st2 = STAT_ST_INIT;
			appctx->st0 = STAT_CLI_O_STAT; // stats_dump_stat_to_buffer
		}
		else if (strcmp(args[1], "info") == 0) {
			if (strcmp(args[2], "typed") == 0)
				appctx->ctx.stats.flags |= STAT_FMT_TYPED;
			appctx->st2 = STAT_ST_INIT;
			appctx->st0 = STAT_CLI_O_INFO; // stats_dump_info_to_buffer
		}
		else if (strcmp(args[1], "errors") == 0) {
			if (strm_li(s)->bind_conf->level < ACCESS_LVL_OPER) {
				appctx->ctx.cli.msg = stats_permission_denied_msg;
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}
			if (*args[2])
				appctx->ctx.errors.iid	= atoi(args[2]);
			else
				appctx->ctx.errors.iid	= -1;
			appctx->ctx.errors.px = NULL;
			appctx->st2 = STAT_ST_INIT;
			appctx->st0 = STAT_CLI_O_ERR; // stats_dump_errors_to_buffer
		}
		else if (strcmp(args[1], "table") == 0) {
			stats_sock_table_request(si, args, STAT_CLI_O_TAB);
		}
		else { /* neither "stat" nor "info" nor "sess" nor "errors" nor "table" */
			return 0;
		}
	}
	else if (strcmp(args[0], "clear") == 0) {
		if (strcmp(args[1], "counters") == 0) {
			struct proxy *px;
			struct server *sv;
			struct listener *li;
			int clrall = 0;

			if (strcmp(args[2], "all") == 0)
				clrall = 1;

			/* check permissions */
			if (strm_li(s)->bind_conf->level < ACCESS_LVL_OPER ||
			    (clrall && strm_li(s)->bind_conf->level < ACCESS_LVL_ADMIN)) {
				appctx->ctx.cli.msg = stats_permission_denied_msg;
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}

			for (px = proxy; px; px = px->next) {
				if (clrall) {
					memset(&px->be_counters, 0, sizeof(px->be_counters));
					memset(&px->fe_counters, 0, sizeof(px->fe_counters));
				}
				else {
					px->be_counters.conn_max = 0;
					px->be_counters.p.http.rps_max = 0;
					px->be_counters.sps_max = 0;
					px->be_counters.cps_max = 0;
					px->be_counters.nbpend_max = 0;

					px->fe_counters.conn_max = 0;
					px->fe_counters.p.http.rps_max = 0;
					px->fe_counters.sps_max = 0;
					px->fe_counters.cps_max = 0;
					px->fe_counters.nbpend_max = 0;
				}

				for (sv = px->srv; sv; sv = sv->next)
					if (clrall)
						memset(&sv->counters, 0, sizeof(sv->counters));
					else {
						sv->counters.cur_sess_max = 0;
						sv->counters.nbpend_max = 0;
						sv->counters.sps_max = 0;
					}

				list_for_each_entry(li, &px->conf.listeners, by_fe)
					if (li->counters) {
						if (clrall)
							memset(li->counters, 0, sizeof(*li->counters));
						else
							li->counters->conn_max = 0;
					}
			}

			global.cps_max = 0;
			global.sps_max = 0;
			return 1;
		}
		else if (strcmp(args[1], "table") == 0) {
			stats_sock_table_request(si, args, STAT_CLI_O_CLR);
			/* end of processing */
			return 1;
		}
		else {
			/* unknown "clear" argument */
			return 0;
		}
	}
	else if (strcmp(args[0], "get") == 0) {
		if (strcmp(args[1], "weight") == 0) {
			struct proxy *px;
			struct server *sv;

			/* split "backend/server" and make <line> point to server */
			for (line = args[2]; *line; line++)
				if (*line == '/') {
					*line++ = '\0';
					break;
				}

			if (!*line) {
				appctx->ctx.cli.msg = "Require 'backend/server'.\n";
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (!get_backend_server(args[2], line, &px, &sv)) {
				appctx->ctx.cli.msg = px ? "No such server.\n" : "No such backend.\n";
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}

			/* return server's effective weight at the moment */
			snprintf(trash.str, trash.size, "%d (initial %d)\n", sv->uweight, sv->iweight);
			if (bi_putstr(si_ic(si), trash.str) == -1)
				si_applet_cant_put(si);

			return 1;
		}
		else { /* not "get weight" */
			return 0;
		}
	}
	else if (strcmp(args[0], "set") == 0) {
		if (strcmp(args[1], "weight") == 0) {
			struct server *sv;
			const char *warning;

			sv = expect_server_admin(s, si, args[2]);
			if (!sv)
				return 1;

			warning = server_parse_weight_change_request(sv, args[3]);
			if (warning) {
				appctx->ctx.cli.msg = warning;
				appctx->st0 = STAT_CLI_PRINT;
			}
			return 1;
		}
		else if (strcmp(args[1], "timeout") == 0) {
			if (strcmp(args[2], "cli") == 0) {
				unsigned timeout;
				const char *res;

				if (!*args[3]) {
					appctx->ctx.cli.msg = "Expects an integer value.\n";
					appctx->st0 = STAT_CLI_PRINT;
					return 1;
				}

				res = parse_time_err(args[3], &timeout, TIME_UNIT_S);
				if (res || timeout < 1) {
					appctx->ctx.cli.msg = "Invalid timeout value.\n";
					appctx->st0 = STAT_CLI_PRINT;
					return 1;
				}

				s->req.rto = s->res.wto = 1 + MS_TO_TICKS(timeout*1000);
				task_wakeup(s->task, TASK_WOKEN_MSG); // recompute timeouts
				return 1;
			}
			else {
				appctx->ctx.cli.msg = "'set timeout' only supports 'cli'.\n";
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}
		}
		else if (strcmp(args[1], "maxconn") == 0) {
			if (strcmp(args[2], "frontend") == 0) {
				struct proxy *px;
				struct listener *l;
				int v;

				px = expect_frontend_admin(s, si, args[3]);
				if (!px)
					return 1;

				if (!*args[4]) {
					appctx->ctx.cli.msg = "Integer value expected.\n";
					appctx->st0 = STAT_CLI_PRINT;
					return 1;
				}

				v = atoi(args[4]);
				if (v < 0) {
					appctx->ctx.cli.msg = "Value out of range.\n";
					appctx->st0 = STAT_CLI_PRINT;
					return 1;
				}

				/* OK, the value is fine, so we assign it to the proxy and to all of
				 * its listeners. The blocked ones will be dequeued.
				 */
				px->maxconn = v;
				list_for_each_entry(l, &px->conf.listeners, by_fe) {
					l->maxconn = v;
					if (l->state == LI_FULL)
						resume_listener(l);
				}

				if (px->maxconn > px->feconn && !LIST_ISEMPTY(&px->listener_queue))
					dequeue_all_listeners(&px->listener_queue);

				return 1;
			}
			else if (strcmp(args[2], "server") == 0) {
				struct server *sv;
				const char *warning;

				sv = expect_server_admin(s, si, args[3]);
				if (!sv)
					return 1;

				warning = server_parse_maxconn_change_request(sv, args[4]);
				if (warning) {
					appctx->ctx.cli.msg = warning;
					appctx->st0 = STAT_CLI_PRINT;
				}

				return 1;
			}
			else if (strcmp(args[2], "global") == 0) {
				int v;

				if (strm_li(s)->bind_conf->level < ACCESS_LVL_ADMIN) {
					appctx->ctx.cli.msg = stats_permission_denied_msg;
					appctx->st0 = STAT_CLI_PRINT;
					return 1;
				}

				if (!*args[3]) {
					appctx->ctx.cli.msg = "Expects an integer value.\n";
					appctx->st0 = STAT_CLI_PRINT;
					return 1;
				}

				v = atoi(args[3]);
				if (v > global.hardmaxconn) {
					appctx->ctx.cli.msg = "Value out of range.\n";
					appctx->st0 = STAT_CLI_PRINT;
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
			else {
				appctx->ctx.cli.msg = "'set maxconn' only supports 'frontend', 'server', and 'global'.\n";
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}
		}
		else if (strcmp(args[1], "rate-limit") == 0) {
			if (strcmp(args[2], "connections") == 0) {
				if (strcmp(args[3], "global") == 0) {
					int v;

					if (strm_li(s)->bind_conf->level < ACCESS_LVL_ADMIN) {
						appctx->ctx.cli.msg = stats_permission_denied_msg;
						appctx->st0 = STAT_CLI_PRINT;
						return 1;
					}

					if (!*args[4]) {
						appctx->ctx.cli.msg = "Expects an integer value.\n";
						appctx->st0 = STAT_CLI_PRINT;
						return 1;
					}

					v = atoi(args[4]);
					if (v < 0) {
						appctx->ctx.cli.msg = "Value out of range.\n";
						appctx->st0 = STAT_CLI_PRINT;
						return 1;
					}

					global.cps_lim = v;

					/* Dequeues all of the listeners waiting for a resource */
					if (!LIST_ISEMPTY(&global_listener_queue))
						dequeue_all_listeners(&global_listener_queue);

					return 1;
				}
				else {
					appctx->ctx.cli.msg = "'set rate-limit connections' only supports 'global'.\n";
					appctx->st0 = STAT_CLI_PRINT;
					return 1;
				}
			}
			else if (strcmp(args[2], "sessions") == 0) {
				if (strcmp(args[3], "global") == 0) {
					int v;

					if (strm_li(s)->bind_conf->level < ACCESS_LVL_ADMIN) {
						appctx->ctx.cli.msg = stats_permission_denied_msg;
						appctx->st0 = STAT_CLI_PRINT;
						return 1;
					}

					if (!*args[4]) {
						appctx->ctx.cli.msg = "Expects an integer value.\n";
						appctx->st0 = STAT_CLI_PRINT;
						return 1;
					}

					v = atoi(args[4]);
					if (v < 0) {
						appctx->ctx.cli.msg = "Value out of range.\n";
						appctx->st0 = STAT_CLI_PRINT;
						return 1;
					}

					global.sps_lim = v;

					/* Dequeues all of the listeners waiting for a resource */
					if (!LIST_ISEMPTY(&global_listener_queue))
						dequeue_all_listeners(&global_listener_queue);

					return 1;
				}
				else {
					appctx->ctx.cli.msg = "'set rate-limit sessions' only supports 'global'.\n";
					appctx->st0 = STAT_CLI_PRINT;
					return 1;
				}
			}
#ifdef USE_OPENSSL
			else if (strcmp(args[2], "ssl-sessions") == 0) {
				if (strcmp(args[3], "global") == 0) {
					int v;

					if (strm_li(s)->bind_conf->level < ACCESS_LVL_ADMIN) {
						appctx->ctx.cli.msg = stats_permission_denied_msg;
						appctx->st0 = STAT_CLI_PRINT;
						return 1;
					}

					if (!*args[4]) {
						appctx->ctx.cli.msg = "Expects an integer value.\n";
						appctx->st0 = STAT_CLI_PRINT;
						return 1;
					}

					v = atoi(args[4]);
					if (v < 0) {
						appctx->ctx.cli.msg = "Value out of range.\n";
						appctx->st0 = STAT_CLI_PRINT;
						return 1;
					}

					global.ssl_lim = v;

					/* Dequeues all of the listeners waiting for a resource */
					if (!LIST_ISEMPTY(&global_listener_queue))
						dequeue_all_listeners(&global_listener_queue);

					return 1;
				}
				else {
					appctx->ctx.cli.msg = "'set rate-limit ssl-sessions' only supports 'global'.\n";
					appctx->st0 = STAT_CLI_PRINT;
					return 1;
				}
			}
#endif
			else if (strcmp(args[2], "http-compression") == 0) {
				if (strcmp(args[3], "global") == 0) {
					int v;

					if (strm_li(s)->bind_conf->level < ACCESS_LVL_ADMIN) {
						appctx->ctx.cli.msg = stats_permission_denied_msg;
						appctx->st0 = STAT_CLI_PRINT;
						return 1;
					}

					if (!*args[4]) {
						appctx->ctx.cli.msg = "Expects a maximum input byte rate in kB/s.\n";
						appctx->st0 = STAT_CLI_PRINT;
						return 1;
					}

					v = atoi(args[4]);
					global.comp_rate_lim = v * 1024; /* Kilo to bytes. */
				}
				else {
					appctx->ctx.cli.msg = "'set rate-limit http-compression' only supports 'global'.\n";
					appctx->st0 = STAT_CLI_PRINT;
					return 1;
				}
			}
			else {
				appctx->ctx.cli.msg = "'set rate-limit' supports 'connections', 'sessions', 'ssl-sessions', and 'http-compression'.\n";
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}
		}
		else if (strcmp(args[1], "table") == 0) {
			stats_sock_table_request(si, args, STAT_CLI_O_SET);
		} else { /* unknown "set" parameter */
			return 0;
		}
	}
	else if (strcmp(args[0], "enable") == 0) {
		if (strcmp(args[1], "agent") == 0) {
			struct server *sv;

			sv = expect_server_admin(s, si, args[2]);
			if (!sv)
				return 1;

			if (!(sv->agent.state & CHK_ST_CONFIGURED)) {
				appctx->ctx.cli.msg = "Agent was not configured on this server, cannot enable.\n";
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}

			sv->agent.state |= CHK_ST_ENABLED;
			return 1;
		}
		else if (strcmp(args[1], "health") == 0) {
			struct server *sv;

			sv = expect_server_admin(s, si, args[2]);
			if (!sv)
				return 1;

			if (!(sv->check.state & CHK_ST_CONFIGURED)) {
				appctx->ctx.cli.msg = "Health checks are not configured on this server, cannot enable.\n";
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}

			sv->check.state |= CHK_ST_ENABLED;
			return 1;
		}
		else if (strcmp(args[1], "server") == 0) {
			struct server *sv;

			sv = expect_server_admin(s, si, args[2]);
			if (!sv)
				return 1;

			srv_adm_set_ready(sv);
			return 1;
		}
		else if (strcmp(args[1], "frontend") == 0) {
			struct proxy *px;

			px = expect_frontend_admin(s, si, args[2]);
			if (!px)
				return 1;

			if (px->state == PR_STSTOPPED) {
				appctx->ctx.cli.msg = "Frontend was previously shut down, cannot enable.\n";
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (px->state != PR_STPAUSED) {
				appctx->ctx.cli.msg = "Frontend is already enabled.\n";
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (!resume_proxy(px)) {
				appctx->ctx.cli.msg = "Failed to resume frontend, check logs for precise cause (port conflict?).\n";
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}
			return 1;
		}
		else { /* unknown "enable" parameter */
			appctx->ctx.cli.msg = "'enable' only supports 'agent', 'frontend', 'health', and 'server'.\n";
			appctx->st0 = STAT_CLI_PRINT;
			return 1;
		}
	}
	else if (strcmp(args[0], "disable") == 0) {
		if (strcmp(args[1], "agent") == 0) {
			struct server *sv;

			sv = expect_server_admin(s, si, args[2]);
			if (!sv)
				return 1;

			sv->agent.state &= ~CHK_ST_ENABLED;
			return 1;
		}
		else if (strcmp(args[1], "health") == 0) {
			struct server *sv;

			sv = expect_server_admin(s, si, args[2]);
			if (!sv)
				return 1;

			sv->check.state &= ~CHK_ST_ENABLED;
			return 1;
		}
		else if (strcmp(args[1], "server") == 0) {
			struct server *sv;

			sv = expect_server_admin(s, si, args[2]);
			if (!sv)
				return 1;

			srv_adm_set_maint(sv);
			return 1;
		}
		else if (strcmp(args[1], "frontend") == 0) {
			struct proxy *px;

			px = expect_frontend_admin(s, si, args[2]);
			if (!px)
				return 1;

			if (px->state == PR_STSTOPPED) {
				appctx->ctx.cli.msg = "Frontend was previously shut down, cannot disable.\n";
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (px->state == PR_STPAUSED) {
				appctx->ctx.cli.msg = "Frontend is already disabled.\n";
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (!pause_proxy(px)) {
				appctx->ctx.cli.msg = "Failed to pause frontend, check logs for precise cause.\n";
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}
			return 1;
		}
		else { /* unknown "disable" parameter */
			appctx->ctx.cli.msg = "'disable' only supports 'agent', 'frontend', 'health', and 'server'.\n";
			appctx->st0 = STAT_CLI_PRINT;
			return 1;
		}
	}
	else if (strcmp(args[0], "shutdown") == 0) {
		if (strcmp(args[1], "frontend") == 0) {
			struct proxy *px;

			px = expect_frontend_admin(s, si, args[2]);
			if (!px)
				return 1;

			if (px->state == PR_STSTOPPED) {
				appctx->ctx.cli.msg = "Frontend was already shut down.\n";
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}

			Warning("Proxy %s stopped (FE: %lld conns, BE: %lld conns).\n",
				px->id, px->fe_counters.cum_conn, px->be_counters.cum_conn);
			send_log(px, LOG_WARNING, "Proxy %s stopped (FE: %lld conns, BE: %lld conns).\n",
				 px->id, px->fe_counters.cum_conn, px->be_counters.cum_conn);
			stop_proxy(px);
			return 1;
		}
		else if (strcmp(args[1], "session") == 0) {
			struct stream *sess, *ptr;

			if (strm_li(s)->bind_conf->level < ACCESS_LVL_ADMIN) {
				appctx->ctx.cli.msg = stats_permission_denied_msg;
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (!*args[2]) {
				appctx->ctx.cli.msg = "Session pointer expected (use 'show sess').\n";
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}

			ptr = (void *)strtoul(args[2], NULL, 0);

			/* first, look for the requested stream in the stream table */
			list_for_each_entry(sess, &streams, list) {
				if (sess == ptr)
					break;
			}

			/* do we have the stream ? */
			if (sess != ptr) {
				appctx->ctx.cli.msg = "No such session (use 'show sess').\n";
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}

			stream_shutdown(sess, SF_ERR_KILLED);
			return 1;
		}
		else if (strcmp(args[1], "sessions") == 0) {
			if (strcmp(args[2], "server") == 0) {
				struct server *sv;
				struct stream *sess, *sess_bck;

				sv = expect_server_admin(s, si, args[3]);
				if (!sv)
					return 1;

				/* kill all the stream that are on this server */
				list_for_each_entry_safe(sess, sess_bck, &sv->actconns, by_srv)
					if (sess->srv_conn == sv)
						stream_shutdown(sess, SF_ERR_KILLED);

				return 1;
			}
			else {
				appctx->ctx.cli.msg = "'shutdown sessions' only supports 'server'.\n";
				appctx->st0 = STAT_CLI_PRINT;
				return 1;
			}
		}
		else { /* unknown "disable" parameter */
			appctx->ctx.cli.msg = "'shutdown' only supports 'frontend', 'session' and 'sessions'.\n";
			appctx->st0 = STAT_CLI_PRINT;
			return 1;
		}
	}
	else { /* not "show" nor "clear" nor "get" nor "set" nor "enable" nor "disable" */
		return 0;
	}
	return 1;
}

/* This I/O handler runs as an applet embedded in a stream interface. It is
 * used to processes I/O from/to the stats unix socket. The system relies on a
 * state machine handling requests and various responses. We read a request,
 * then we process it and send the response, and we possibly display a prompt.
 * Then we can read again. The state is stored in appctx->st0 and is one of the
 * STAT_CLI_* constants. appctx->st1 is used to indicate whether prompt is enabled
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

	while (1) {
		if (appctx->st0 == STAT_CLI_INIT) {
			/* Stats output not initialized yet */
			memset(&appctx->ctx.stats, 0, sizeof(appctx->ctx.stats));
			appctx->st0 = STAT_CLI_GETREQ;
		}
		else if (appctx->st0 == STAT_CLI_END) {
			/* Let's close for real now. We just close the request
			 * side, the conditions below will complete if needed.
			 */
			si_shutw(si);
			break;
		}
		else if (appctx->st0 == STAT_CLI_GETREQ) {
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
				appctx->st0 = STAT_CLI_END;
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
				appctx->st0 = STAT_CLI_END;
				continue;
			}

			if (len && trash.str[len-1] == '\r')
				len--;

			trash.str[len] = '\0';

			appctx->st0 = STAT_CLI_PROMPT;
			if (len) {
				if (strcmp(trash.str, "quit") == 0) {
					appctx->st0 = STAT_CLI_END;
					continue;
				}
				else if (strcmp(trash.str, "prompt") == 0)
					appctx->st1 = !appctx->st1;
				else if (strcmp(trash.str, "help") == 0 ||
					 !stats_sock_parse_request(si, trash.str)) {
					cli_gen_usage_msg();
					if (dynamic_usage_msg)
						appctx->ctx.cli.msg = dynamic_usage_msg;
					else
						appctx->ctx.cli.msg = stats_sock_usage_msg;
					appctx->st0 = STAT_CLI_PRINT;
				}
				/* NB: stats_sock_parse_request() may have put
				 * another STAT_CLI_O_* into appctx->st0.
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
				appctx->st0 = STAT_CLI_PRINT;
			}

			/* re-adjust req buffer */
			bo_skip(si_oc(si), reql);
			req->flags |= CF_READ_DONTWAIT; /* we plan to read small requests */
		}
		else {	/* output functions */
			switch (appctx->st0) {
			case STAT_CLI_PROMPT:
				break;
			case STAT_CLI_PRINT:
				if (bi_putstr(si_ic(si), appctx->ctx.cli.msg) != -1)
					appctx->st0 = STAT_CLI_PROMPT;
				else
					si_applet_cant_put(si);
				break;
			case STAT_CLI_PRINT_FREE:
				if (bi_putstr(si_ic(si), appctx->ctx.cli.err) != -1) {
					free(appctx->ctx.cli.err);
					appctx->st0 = STAT_CLI_PROMPT;
				}
				else
					si_applet_cant_put(si);
				break;
			case STAT_CLI_O_BACKEND:
				if (stats_dump_backend_to_buffer(si))
					appctx->st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_INFO:
				if (stats_dump_info_to_buffer(si))
					appctx->st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_STAT:
				if (stats_dump_stat_to_buffer(si, NULL))
					appctx->st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_ERR:	/* errors dump */
				if (stats_dump_errors_to_buffer(si))
					appctx->st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_TAB:
			case STAT_CLI_O_CLR:
				if (stats_table_request(si, appctx->st0))
					appctx->st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_ENV:	/* environment dump */
				if (stats_dump_env_to_buffer(si))
					appctx->st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_CUSTOM: /* use custom pointer */
				if (appctx->io_handler)
					if (appctx->io_handler(appctx)) {
						appctx->st0 = STAT_CLI_PROMPT;
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
			if (appctx->st0 == STAT_CLI_PROMPT) {
				if (bi_putstr(si_ic(si), appctx->st1 ? "\n> " : "\n") != -1)
					appctx->st0 = STAT_CLI_GETREQ;
				else
					si_applet_cant_put(si);
			}

			/* If the output functions are still there, it means they require more room. */
			if (appctx->st0 >= STAT_CLI_OUTPUT)
				break;

			/* Now we close the output if one of the writers did so,
			 * or if we're not in interactive mode and the request
			 * buffer is empty. This still allows pipelined requests
			 * to be sent in non-interactive mode.
			 */
			if ((res->flags & (CF_SHUTW|CF_SHUTW_NOW)) || (!appctx->st1 && !req->buf->o)) {
				appctx->st0 = STAT_CLI_END;
				continue;
			}

			/* switch state back to GETREQ to read next requests */
			appctx->st0 = STAT_CLI_GETREQ;
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

	if ((req->flags & CF_SHUTW) && (si->state == SI_ST_EST) && (appctx->st0 < STAT_CLI_OUTPUT)) {
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

/* Dump all fields from <info> into <out> using the "show info" format (name: value) */
static int stats_dump_info_fields(struct chunk *out, const struct field *info)
{
	int field;

	for (field = 0; field < INF_TOTAL_FIELDS; field++) {
		if (!field_format(info, field))
			continue;

		if (!chunk_appendf(out, "%s: ", info_field_names[field]))
			return 0;
		if (!stats_emit_raw_data_field(out, &info[field]))
			return 0;
		if (!chunk_strcat(out, "\n"))
			return 0;
	}
	return 1;
}

/* Dump all fields from <info> into <out> using the "show info typed" format */
static int stats_dump_typed_info_fields(struct chunk *out, const struct field *info)
{
	int field;

	for (field = 0; field < INF_TOTAL_FIELDS; field++) {
		if (!field_format(info, field))
			continue;

		if (!chunk_appendf(out, "%d.%s.%u:", field, info_field_names[field], info[INF_PROCESS_NUM].u.u32))
			return 0;
		if (!stats_emit_field_tags(out, &info[field], ':'))
			return 0;
		if (!stats_emit_typed_data_field(out, &info[field]))
			return 0;
		if (!chunk_strcat(out, "\n"))
			return 0;
	}
	return 1;
}

/* Fill <info> with HAProxy global info. <info> is preallocated
 * array of length <len>. The length of the aray must be
 * INF_TOTAL_FIELDS. If this length is less then this value, the
 * function returns 0, otherwise, it returns 1.
 */
int stats_fill_info(struct field *info, int len)
{
	unsigned int up = (now.tv_sec - start_date.tv_sec);
	struct chunk *out = get_trash_chunk();

#ifdef USE_OPENSSL
	int ssl_sess_rate = read_freq_ctr(&global.ssl_per_sec);
	int ssl_key_rate = read_freq_ctr(&global.ssl_fe_keys_per_sec);
	int ssl_reuse = 0;

	if (ssl_key_rate < ssl_sess_rate) {
		/* count the ssl reuse ratio and avoid overflows in both directions */
		ssl_reuse = 100 - (100 * ssl_key_rate + (ssl_sess_rate - 1) / 2) / ssl_sess_rate;
	}
#endif

	if (len < INF_TOTAL_FIELDS)
		return 0;

	chunk_reset(out);
	memset(info, 0, sizeof(*info) * len);

	info[INF_NAME]                           = mkf_str(FO_PRODUCT|FN_OUTPUT|FS_SERVICE, PRODUCT_NAME);
	info[INF_VERSION]                        = mkf_str(FO_PRODUCT|FN_OUTPUT|FS_SERVICE, HAPROXY_VERSION);
	info[INF_RELEASE_DATE]                   = mkf_str(FO_PRODUCT|FN_OUTPUT|FS_SERVICE, HAPROXY_DATE);

	info[INF_NBPROC]                         = mkf_u32(FO_CONFIG|FS_SERVICE, global.nbproc);
	info[INF_PROCESS_NUM]                    = mkf_u32(FO_KEY, relative_pid);
	info[INF_PID]                            = mkf_u32(FO_STATUS, pid);

	info[INF_UPTIME]                         = mkf_str(FN_DURATION, chunk_newstr(out));
	chunk_appendf(out, "%ud %uh%02um%02us", up / 86400, (up % 86400) / 3600, (up % 3600) / 60, (up % 60));

	info[INF_UPTIME_SEC]                     = mkf_u32(FN_DURATION, up);
	info[INF_MEMMAX_MB]                      = mkf_u32(FO_CONFIG|FN_LIMIT, global.rlimit_memmax);
	info[INF_POOL_ALLOC_MB]                  = mkf_u32(0, (unsigned)(pool_total_allocated() / 1048576L));
	info[INF_POOL_USED_MB]                   = mkf_u32(0, (unsigned)(pool_total_used() / 1048576L));
	info[INF_POOL_FAILED]                    = mkf_u32(FN_COUNTER, pool_total_failures());
	info[INF_ULIMIT_N]                       = mkf_u32(FO_CONFIG|FN_LIMIT, global.rlimit_nofile);
	info[INF_MAXSOCK]                        = mkf_u32(FO_CONFIG|FN_LIMIT, global.maxsock);
	info[INF_MAXCONN]                        = mkf_u32(FO_CONFIG|FN_LIMIT, global.maxconn);
	info[INF_HARD_MAXCONN]                   = mkf_u32(FO_CONFIG|FN_LIMIT, global.hardmaxconn);
	info[INF_CURR_CONN]                      = mkf_u32(0, actconn);
	info[INF_CUM_CONN]                       = mkf_u32(FN_COUNTER, totalconn);
	info[INF_CUM_REQ]                        = mkf_u32(FN_COUNTER, global.req_count);
#ifdef USE_OPENSSL
	info[INF_MAX_SSL_CONNS]                  = mkf_u32(FN_MAX, global.maxsslconn);
	info[INF_CURR_SSL_CONNS]                 = mkf_u32(0, sslconns);
	info[INF_CUM_SSL_CONNS]                  = mkf_u32(FN_COUNTER, totalsslconns);
#endif
	info[INF_MAXPIPES]                       = mkf_u32(FO_CONFIG|FN_LIMIT, global.maxpipes);
	info[INF_PIPES_USED]                     = mkf_u32(0, pipes_used);
	info[INF_PIPES_FREE]                     = mkf_u32(0, pipes_free);
	info[INF_CONN_RATE]                      = mkf_u32(FN_RATE, read_freq_ctr(&global.conn_per_sec));
	info[INF_CONN_RATE_LIMIT]                = mkf_u32(FO_CONFIG|FN_LIMIT, global.cps_lim);
	info[INF_MAX_CONN_RATE]                  = mkf_u32(FN_MAX, global.cps_max);
	info[INF_SESS_RATE]                      = mkf_u32(FN_RATE, read_freq_ctr(&global.sess_per_sec));
	info[INF_SESS_RATE_LIMIT]                = mkf_u32(FO_CONFIG|FN_LIMIT, global.sps_lim);
	info[INF_MAX_SESS_RATE]                  = mkf_u32(FN_RATE, global.sps_max);

#ifdef USE_OPENSSL
	info[INF_SSL_RATE]                       = mkf_u32(FN_RATE, ssl_sess_rate);
	info[INF_SSL_RATE_LIMIT]                 = mkf_u32(FO_CONFIG|FN_LIMIT, global.ssl_lim);
	info[INF_MAX_SSL_RATE]                   = mkf_u32(FN_MAX, global.ssl_max);
	info[INF_SSL_FRONTEND_KEY_RATE]          = mkf_u32(0, ssl_key_rate);
	info[INF_SSL_FRONTEND_MAX_KEY_RATE]      = mkf_u32(FN_MAX, global.ssl_fe_keys_max);
	info[INF_SSL_FRONTEND_SESSION_REUSE_PCT] = mkf_u32(0, ssl_reuse);
	info[INF_SSL_BACKEND_KEY_RATE]           = mkf_u32(FN_RATE, read_freq_ctr(&global.ssl_be_keys_per_sec));
	info[INF_SSL_BACKEND_MAX_KEY_RATE]       = mkf_u32(FN_MAX, global.ssl_be_keys_max);
	info[INF_SSL_CACHE_LOOKUPS]              = mkf_u32(FN_COUNTER, global.shctx_lookups);
	info[INF_SSL_CACHE_MISSES]               = mkf_u32(FN_COUNTER, global.shctx_misses);
#endif
	info[INF_COMPRESS_BPS_IN]                = mkf_u32(FN_RATE, read_freq_ctr(&global.comp_bps_in));
	info[INF_COMPRESS_BPS_OUT]               = mkf_u32(FN_RATE, read_freq_ctr(&global.comp_bps_out));
	info[INF_COMPRESS_BPS_RATE_LIM]          = mkf_u32(FO_CONFIG|FN_LIMIT, global.comp_rate_lim);
#ifdef USE_ZLIB
	info[INF_ZLIB_MEM_USAGE]                 = mkf_u32(0, zlib_used_memory);
	info[INF_MAX_ZLIB_MEM_USAGE]             = mkf_u32(FO_CONFIG|FN_LIMIT, global.maxzlibmem);
#endif
	info[INF_TASKS]                          = mkf_u32(0, nb_tasks_cur);
	info[INF_RUN_QUEUE]                      = mkf_u32(0, run_queue_cur);
	info[INF_IDLE_PCT]                       = mkf_u32(FN_AVG, idle_pct);
	info[INF_NODE]                           = mkf_str(FO_CONFIG|FN_OUTPUT|FS_SERVICE, global.node);
	if (global.desc)
		info[INF_DESCRIPTION]            = mkf_str(FO_CONFIG|FN_OUTPUT|FS_SERVICE, global.desc);

	return 1;
}

/* This function dumps information onto the stream interface's read buffer.
 * It returns 0 as long as it does not complete, non-zero upon completion.
 * No state is used.
 */
static int stats_dump_info_to_buffer(struct stream_interface *si)
{
	struct appctx *appctx = __objt_appctx(si->end);

	if (!stats_fill_info(info, INF_TOTAL_FIELDS))
		return 0;

	chunk_reset(&trash);

	if (appctx->ctx.stats.flags & STAT_FMT_TYPED)
		stats_dump_typed_info_fields(&trash, info);
	else
		stats_dump_info_fields(&trash, info);

	if (bi_putchk(si_ic(si), &trash) == -1) {
		si_applet_cant_put(si);
		return 0;
	}

	return 1;
}

/* Parses backend list and simply report backend names */
static int stats_dump_backend_to_buffer(struct stream_interface *si)
{
	struct appctx *appctx = __objt_appctx(si->end);
	extern struct proxy *proxy;
	struct proxy *curproxy;

	chunk_reset(&trash);

	if (!appctx->ctx.be.px) {
		chunk_printf(&trash, "# name\n");
		if (bi_putchk(si_ic(si), &trash) == -1) {
			si_applet_cant_put(si);
			return 0;
		}
		appctx->ctx.be.px = proxy;
	}

	for (; appctx->ctx.be.px != NULL; appctx->ctx.be.px = curproxy->next) {
		curproxy = appctx->ctx.be.px;

		/* looking for backends only */
		if (!(curproxy->cap & PR_CAP_BE))
			continue;

		/* we don't want to list a backend which is bound to this process */
		if (curproxy->bind_proc && !(curproxy->bind_proc & (1UL << (relative_pid - 1))))
			continue;

		chunk_appendf(&trash, "%s\n", curproxy->id);
		if (bi_putchk(si_ic(si), &trash) == -1) {
			si_applet_cant_put(si);
			return 0;
		}
	}

	return 1;
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
	else if ((appctx->st0 == STAT_CLI_O_TAB || appctx->st0 == STAT_CLI_O_CLR) &&
		 appctx->st2 == STAT_ST_LIST) {
		appctx->ctx.table.entry->ref_cnt--;
		stksess_kill_if_expired(&appctx->ctx.table.proxy->table, appctx->ctx.table.entry);
	}
	else if (appctx->st0 == STAT_CLI_PRINT_FREE) {
		free(appctx->ctx.cli.err);
		appctx->ctx.cli.err = NULL;
	}
}

/* This function is used to either dump tables states (when action is set
 * to STAT_CLI_O_TAB) or clear tables (when action is STAT_CLI_O_CLR).
 * It returns 0 if the output buffer is full and it needs to be called
 * again, otherwise non-zero.
 */
static int stats_table_request(struct stream_interface *si, int action)
{
	struct appctx *appctx = __objt_appctx(si->end);
	struct stream *s = si_strm(si);
	struct ebmb_node *eb;
	int dt;
	int skip_entry;
	int show = action == STAT_CLI_O_TAB;

	/*
	 * We have 3 possible states in appctx->st2 :
	 *   - STAT_ST_INIT : the first call
	 *   - STAT_ST_INFO : the proxy pointer points to the next table to
	 *     dump, the entry pointer is NULL ;
	 *   - STAT_ST_LIST : the proxy pointer points to the current table
	 *     and the entry pointer points to the next entry to be dumped,
	 *     and the refcount on the next entry is held ;
	 *   - STAT_ST_END : nothing left to dump, the buffer may contain some
	 *     data though.
	 */

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW))) {
		/* in case of abort, remove any refcount we might have set on an entry */
		if (appctx->st2 == STAT_ST_LIST) {
			appctx->ctx.table.entry->ref_cnt--;
			stksess_kill_if_expired(&appctx->ctx.table.proxy->table, appctx->ctx.table.entry);
		}
		return 1;
	}

	chunk_reset(&trash);

	while (appctx->st2 != STAT_ST_FIN) {
		switch (appctx->st2) {
		case STAT_ST_INIT:
			appctx->ctx.table.proxy = appctx->ctx.table.target;
			if (!appctx->ctx.table.proxy)
				appctx->ctx.table.proxy = proxy;

			appctx->ctx.table.entry = NULL;
			appctx->st2 = STAT_ST_INFO;
			break;

		case STAT_ST_INFO:
			if (!appctx->ctx.table.proxy ||
			    (appctx->ctx.table.target &&
			     appctx->ctx.table.proxy != appctx->ctx.table.target)) {
				appctx->st2 = STAT_ST_END;
				break;
			}

			if (appctx->ctx.table.proxy->table.size) {
				if (show && !stats_dump_table_head_to_buffer(&trash, si, appctx->ctx.table.proxy,
									     appctx->ctx.table.target))
					return 0;

				if (appctx->ctx.table.target &&
				    strm_li(s)->bind_conf->level >= ACCESS_LVL_OPER) {
					/* dump entries only if table explicitly requested */
					eb = ebmb_first(&appctx->ctx.table.proxy->table.keys);
					if (eb) {
						appctx->ctx.table.entry = ebmb_entry(eb, struct stksess, key);
						appctx->ctx.table.entry->ref_cnt++;
						appctx->st2 = STAT_ST_LIST;
						break;
					}
				}
			}
			appctx->ctx.table.proxy = appctx->ctx.table.proxy->next;
			break;

		case STAT_ST_LIST:
			skip_entry = 0;

			if (appctx->ctx.table.data_type >= 0) {
				/* we're filtering on some data contents */
				void *ptr;
				long long data;

				dt = appctx->ctx.table.data_type;
				ptr = stktable_data_ptr(&appctx->ctx.table.proxy->table,
							appctx->ctx.table.entry,
							dt);

				data = 0;
				switch (stktable_data_types[dt].std_type) {
				case STD_T_SINT:
					data = stktable_data_cast(ptr, std_t_sint);
					break;
				case STD_T_UINT:
					data = stktable_data_cast(ptr, std_t_uint);
					break;
				case STD_T_ULL:
					data = stktable_data_cast(ptr, std_t_ull);
					break;
				case STD_T_FRQP:
					data = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
								    appctx->ctx.table.proxy->table.data_arg[dt].u);
					break;
				}

				/* skip the entry if the data does not match the test and the value */
				if ((data < appctx->ctx.table.value &&
				     (appctx->ctx.table.data_op == STD_OP_EQ ||
				      appctx->ctx.table.data_op == STD_OP_GT ||
				      appctx->ctx.table.data_op == STD_OP_GE)) ||
				    (data == appctx->ctx.table.value &&
				     (appctx->ctx.table.data_op == STD_OP_NE ||
				      appctx->ctx.table.data_op == STD_OP_GT ||
				      appctx->ctx.table.data_op == STD_OP_LT)) ||
				    (data > appctx->ctx.table.value &&
				     (appctx->ctx.table.data_op == STD_OP_EQ ||
				      appctx->ctx.table.data_op == STD_OP_LT ||
				      appctx->ctx.table.data_op == STD_OP_LE)))
					skip_entry = 1;
			}

			if (show && !skip_entry &&
			    !stats_dump_table_entry_to_buffer(&trash, si, appctx->ctx.table.proxy,
							      appctx->ctx.table.entry))
			    return 0;

			appctx->ctx.table.entry->ref_cnt--;

			eb = ebmb_next(&appctx->ctx.table.entry->key);
			if (eb) {
				struct stksess *old = appctx->ctx.table.entry;
				appctx->ctx.table.entry = ebmb_entry(eb, struct stksess, key);
				if (show)
					stksess_kill_if_expired(&appctx->ctx.table.proxy->table, old);
				else if (!skip_entry && !appctx->ctx.table.entry->ref_cnt)
					stksess_kill(&appctx->ctx.table.proxy->table, old);
				appctx->ctx.table.entry->ref_cnt++;
				break;
			}


			if (show)
				stksess_kill_if_expired(&appctx->ctx.table.proxy->table, appctx->ctx.table.entry);
			else if (!skip_entry && !appctx->ctx.table.entry->ref_cnt)
				stksess_kill(&appctx->ctx.table.proxy->table, appctx->ctx.table.entry);

			appctx->ctx.table.proxy = appctx->ctx.table.proxy->next;
			appctx->st2 = STAT_ST_INFO;
			break;

		case STAT_ST_END:
			appctx->st2 = STAT_ST_FIN;
			break;
		}
	}
	return 1;
}

/* print a line of text buffer (limited to 70 bytes) to <out>. The format is :
 * <2 spaces> <offset=5 digits> <space or plus> <space> <70 chars max> <\n>
 * which is 60 chars per line. Non-printable chars \t, \n, \r and \e are
 * encoded in C format. Other non-printable chars are encoded "\xHH". Original
 * lines are respected within the limit of 70 output chars. Lines that are
 * continuation of a previous truncated line begin with "+" instead of " "
 * after the offset. The new pointer is returned.
 */
static int dump_text_line(struct chunk *out, const char *buf, int bsize, int len,
			  int *line, int ptr)
{
	int end;
	unsigned char c;

	end = out->len + 80;
	if (end > out->size)
		return ptr;

	chunk_appendf(out, "  %05d%c ", ptr, (ptr == *line) ? ' ' : '+');

	while (ptr < len && ptr < bsize) {
		c = buf[ptr];
		if (isprint(c) && isascii(c) && c != '\\') {
			if (out->len > end - 2)
				break;
			out->str[out->len++] = c;
		} else if (c == '\t' || c == '\n' || c == '\r' || c == '\e' || c == '\\') {
			if (out->len > end - 3)
				break;
			out->str[out->len++] = '\\';
			switch (c) {
			case '\t': c = 't'; break;
			case '\n': c = 'n'; break;
			case '\r': c = 'r'; break;
			case '\e': c = 'e'; break;
			case '\\': c = '\\'; break;
			}
			out->str[out->len++] = c;
		} else {
			if (out->len > end - 5)
				break;
			out->str[out->len++] = '\\';
			out->str[out->len++] = 'x';
			out->str[out->len++] = hextab[(c >> 4) & 0xF];
			out->str[out->len++] = hextab[c & 0xF];
		}
		if (buf[ptr++] == '\n') {
			/* we had a line break, let's return now */
			out->str[out->len++] = '\n';
			*line = ptr;
			return ptr;
		}
	}
	/* we have an incomplete line, we return it as-is */
	out->str[out->len++] = '\n';
	return ptr;
}

/* This function dumps all captured errors onto the stream interface's
 * read buffer. It returns 0 if the output buffer is full and it needs
 * to be called again, otherwise non-zero.
 */
static int stats_dump_errors_to_buffer(struct stream_interface *si)
{
	struct appctx *appctx = __objt_appctx(si->end);
	extern const char *monthname[12];

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		return 1;

	chunk_reset(&trash);

	if (!appctx->ctx.errors.px) {
		/* the function had not been called yet, let's prepare the
		 * buffer for a response.
		 */
		struct tm tm;

		get_localtime(date.tv_sec, &tm);
		chunk_appendf(&trash, "Total events captured on [%02d/%s/%04d:%02d:%02d:%02d.%03d] : %u\n",
			     tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
			     tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(date.tv_usec/1000),
			     error_snapshot_id);

		if (bi_putchk(si_ic(si), &trash) == -1) {
			/* Socket buffer full. Let's try again later from the same point */
			si_applet_cant_put(si);
			return 0;
		}

		appctx->ctx.errors.px = proxy;
		appctx->ctx.errors.buf = 0;
		appctx->ctx.errors.bol = 0;
		appctx->ctx.errors.ptr = -1;
	}

	/* we have two inner loops here, one for the proxy, the other one for
	 * the buffer.
	 */
	while (appctx->ctx.errors.px) {
		struct error_snapshot *es;

		if (appctx->ctx.errors.buf == 0)
			es = &appctx->ctx.errors.px->invalid_req;
		else
			es = &appctx->ctx.errors.px->invalid_rep;

		if (!es->when.tv_sec)
			goto next;

		if (appctx->ctx.errors.iid >= 0 &&
		    appctx->ctx.errors.px->uuid != appctx->ctx.errors.iid &&
		    es->oe->uuid != appctx->ctx.errors.iid)
			goto next;

		if (appctx->ctx.errors.ptr < 0) {
			/* just print headers now */

			char pn[INET6_ADDRSTRLEN];
			struct tm tm;
			int port;

			get_localtime(es->when.tv_sec, &tm);
			chunk_appendf(&trash, " \n[%02d/%s/%04d:%02d:%02d:%02d.%03d]",
				     tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
				     tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(es->when.tv_usec/1000));

			switch (addr_to_str(&es->src, pn, sizeof(pn))) {
			case AF_INET:
			case AF_INET6:
				port = get_host_port(&es->src);
				break;
			default:
				port = 0;
			}

			switch (appctx->ctx.errors.buf) {
			case 0:
				chunk_appendf(&trash,
					     " frontend %s (#%d): invalid request\n"
					     "  backend %s (#%d)",
					     appctx->ctx.errors.px->id, appctx->ctx.errors.px->uuid,
					     (es->oe->cap & PR_CAP_BE) ? es->oe->id : "<NONE>",
					     (es->oe->cap & PR_CAP_BE) ? es->oe->uuid : -1);
				break;
			case 1:
				chunk_appendf(&trash,
					     " backend %s (#%d): invalid response\n"
					     "  frontend %s (#%d)",
					     appctx->ctx.errors.px->id, appctx->ctx.errors.px->uuid,
					     es->oe->id, es->oe->uuid);
				break;
			}

			chunk_appendf(&trash,
				     ", server %s (#%d), event #%u\n"
				     "  src %s:%d, session #%d, session flags 0x%08x\n"
				     "  HTTP msg state %d, msg flags 0x%08x, tx flags 0x%08x\n"
				     "  HTTP chunk len %lld bytes, HTTP body len %lld bytes\n"
				     "  buffer flags 0x%08x, out %d bytes, total %lld bytes\n"
				     "  pending %d bytes, wrapping at %d, error at position %d:\n \n",
				     es->srv ? es->srv->id : "<NONE>", es->srv ? es->srv->puid : -1,
				     es->ev_id,
				     pn, port, es->sid, es->s_flags,
				     es->state, es->m_flags, es->t_flags,
				     es->m_clen, es->m_blen,
				     es->b_flags, es->b_out, es->b_tot,
				     es->len, es->b_wrap, es->pos);

			if (bi_putchk(si_ic(si), &trash) == -1) {
				/* Socket buffer full. Let's try again later from the same point */
				si_applet_cant_put(si);
				return 0;
			}
			appctx->ctx.errors.ptr = 0;
			appctx->ctx.errors.sid = es->sid;
		}

		if (appctx->ctx.errors.sid != es->sid) {
			/* the snapshot changed while we were dumping it */
			chunk_appendf(&trash,
				     "  WARNING! update detected on this snapshot, dump interrupted. Please re-check!\n");
			if (bi_putchk(si_ic(si), &trash) == -1) {
				si_applet_cant_put(si);
				return 0;
			}
			goto next;
		}

		/* OK, ptr >= 0, so we have to dump the current line */
		while (es->buf && appctx->ctx.errors.ptr < es->len && appctx->ctx.errors.ptr < global.tune.bufsize) {
			int newptr;
			int newline;

			newline = appctx->ctx.errors.bol;
			newptr = dump_text_line(&trash, es->buf, global.tune.bufsize, es->len, &newline, appctx->ctx.errors.ptr);
			if (newptr == appctx->ctx.errors.ptr)
				return 0;

			if (bi_putchk(si_ic(si), &trash) == -1) {
				/* Socket buffer full. Let's try again later from the same point */
				si_applet_cant_put(si);
				return 0;
			}
			appctx->ctx.errors.ptr = newptr;
			appctx->ctx.errors.bol = newline;
		};
	next:
		appctx->ctx.errors.bol = 0;
		appctx->ctx.errors.ptr = -1;
		appctx->ctx.errors.buf++;
		if (appctx->ctx.errors.buf > 1) {
			appctx->ctx.errors.buf = 0;
			appctx->ctx.errors.px = appctx->ctx.errors.px->next;
		}
	}

	/* dump complete */
	return 1;
}

/* This function dumps all environmnent variables to the buffer. It returns 0
 * if the output buffer is full and it needs to be called again, otherwise
 * non-zero. Dumps only one entry if st2 == STAT_ST_END.
 */
static int stats_dump_env_to_buffer(struct stream_interface *si)
{
	struct appctx *appctx = __objt_appctx(si->end);

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
	bind_register_keywords(&bind_kws);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
