/*
 * Functions dedicated to statistics output and the stats socket
 *
 * Copyright 2000-2010 Willy Tarreau <w@1wt.eu>
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
#include <stdbool.h>
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

#include <types/global.h>

#include <proto/backend.h>
#include <proto/buffers.h>
#include <proto/checks.h>
#include <proto/dumpstats.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/log.h>
#include <proto/pipe.h>
#include <proto/proto_uxst.h>
#include <proto/proxy.h>
#include <proto/session.h>
#include <proto/server.h>
#include <proto/stream_interface.h>
#include <proto/stream_sock.h>
#include <proto/task.h>

static int stats_dump_raw_to_buffer(struct stream_interface *si);
static int stats_dump_full_sess_to_buffer(struct stream_interface *si);
static int stats_dump_sess_to_buffer(struct stream_interface *si);
static int stats_dump_errors_to_buffer(struct stream_interface *si);
static int stats_dump_table_to_buffer(struct stream_interface *si);
static int stats_dump_proxy(struct stream_interface *si, struct proxy *px, struct uri_auth *uri);
static int stats_dump_http(struct stream_interface *si, struct uri_auth *uri);

static struct si_applet cli_applet;

static const char stats_sock_usage_msg[] =
	"Unknown command. Please enter one of the following commands only :\n"
	"  clear counters : clear max statistics counters (add 'all' for all counters)\n"
	"  clear table    : remove an entry from a table\n"
	"  help           : this message\n"
	"  prompt         : toggle interactive mode with prompt\n"
	"  quit           : disconnect\n"
	"  show info      : report information about the running process\n"
	"  show stat      : report counters for each proxy and server\n"
	"  show errors    : report last request and response errors for each proxy\n"
	"  show sess [id] : report the list of current sessions or dump this session\n"
	"  show table [id]: report table usage stats or dump this table's contents\n"
	"  get weight     : report a server's current weight\n"
	"  set weight     : change a server's weight\n"
	"  set timeout    : change a timeout setting\n"
	"  disable server : set a server in maintenance mode\n"
	"  enable server  : re-enable a server that was previously in maintenance mode\n"
	"";

static const char stats_permission_denied_msg[] =
	"Permission denied\n"
	"";

/* data transmission states for the stats responses */
enum {
	STAT_ST_INIT = 0,
	STAT_ST_HEAD,
	STAT_ST_INFO,
	STAT_ST_LIST,
	STAT_ST_END,
	STAT_ST_FIN,
};

/* data transmission states for the stats responses inside a proxy */
enum {
	STAT_PX_ST_INIT = 0,
	STAT_PX_ST_TH,
	STAT_PX_ST_FE,
	STAT_PX_ST_LI,
	STAT_PX_ST_SV,
	STAT_PX_ST_BE,
	STAT_PX_ST_END,
	STAT_PX_ST_FIN,
};

/* This function is called from the session-level accept() in order to instanciate
 * a new stats socket. It returns a positive value upon success, 0 if the connection
 * needs to be closed and ignored, or a negative value upon critical failure.
 */
static int stats_accept(struct session *s)
{
	/* we have a dedicated I/O handler for the stats */
	stream_int_register_handler(&s->si[1], &cli_applet);
	copy_target(&s->target, &s->si[1].target); // for logging only
	s->si[1].applet.private = s;
	s->si[1].applet.st1 = 0;
	s->si[1].applet.st0 = STAT_CLI_INIT;

	tv_zero(&s->logs.tv_request);
	s->logs.t_queue = 0;
	s->logs.t_connect = 0;
	s->logs.t_data = 0;
	s->logs.t_close = 0;
	s->logs.bytes_in = s->logs.bytes_out = 0;
	s->logs.prx_queue_size = 0;  /* we get the number of pending conns before us */
	s->logs.srv_queue_size = 0; /* we will get this number soon */

	s->req->flags |= BF_READ_DONTWAIT; /* we plan to read small requests */

	if (s->listener->timeout) {
		s->req->rto = *s->listener->timeout;
		s->rep->wto = *s->listener->timeout;
	}
	return 1;
}

/* allocate a new stats frontend named <name>, and return it
 * (or NULL in case of lack of memory).
 */
static struct proxy *alloc_stats_fe(const char *name)
{
	struct proxy *fe;

	fe = (struct proxy *)calloc(1, sizeof(struct proxy));
	if (!fe)
		return NULL;

	LIST_INIT(&fe->pendconns);
	LIST_INIT(&fe->acl);
	LIST_INIT(&fe->block_cond);
	LIST_INIT(&fe->redirect_rules);
	LIST_INIT(&fe->mon_fail_cond);
	LIST_INIT(&fe->switching_rules);
	LIST_INIT(&fe->tcp_req.inspect_rules);

	/* Timeouts are defined as -1, so we cannot use the zeroed area
	 * as a default value.
	 */
	proxy_reset_timeouts(fe);

	fe->last_change = now.tv_sec;
	fe->id = strdup("GLOBAL");
	fe->cap = PR_CAP_FE;
	return fe;
}

/* This function parses a "stats" statement in the "global" section. It returns
 * -1 if there is any error, otherwise zero. If it returns -1, it may write an
 * error message into ther <err> buffer, for at most <errlen> bytes, trailing
 * zero included. The trailing '\n' must not be written. The function must be
 * called with <args> pointing to the first word after "stats".
 */
static int stats_parse_global(char **args, int section_type, struct proxy *curpx,
			      struct proxy *defpx, char *err, int errlen)
{
	args++;
	if (!strcmp(args[0], "socket")) {
		struct sockaddr_un *su;
		int cur_arg;

		if (*args[1] == 0) {
			snprintf(err, errlen, "'stats socket' in global section expects a path to a UNIX socket");
			return -1;
		}

		if (global.stats_sock.state != LI_NEW) {
			snprintf(err, errlen, "'stats socket' already specified in global section");
			return -1;
		}

		su = str2sun(args[1]);
		if (!su) {
			snprintf(err, errlen, "'stats socket' path would require truncation");
			return -1;
		}
		memcpy(&global.stats_sock.addr, su, sizeof(struct sockaddr_un)); // guaranteed to fit

		if (!global.stats_fe) {
			if ((global.stats_fe = alloc_stats_fe("GLOBAL")) == NULL) {
				snprintf(err, errlen, "out of memory");
				return -1;
			}
			global.stats_fe->timeout.client = MS_TO_TICKS(10000); /* default timeout of 10 seconds */
		}

		global.stats_sock.state = LI_INIT;
		global.stats_sock.options = LI_O_NONE;
		global.stats_sock.accept = session_accept;
		global.stats_fe->accept = stats_accept;
		global.stats_sock.handler = process_session;
		global.stats_sock.analysers = 0;
		global.stats_sock.nice = -64;  /* we want to boost priority for local stats */
		global.stats_sock.frontend = global.stats_fe;
		global.stats_sock.perm.ux.level = ACCESS_LVL_OPER; /* default access level */
		global.stats_fe->maxconn = global.stats_sock.maxconn;
		global.stats_sock.timeout = &global.stats_fe->timeout.client;

		global.stats_sock.next  = global.stats_fe->listen;
		global.stats_fe->listen = &global.stats_sock;

		cur_arg = 2;
		while (*args[cur_arg]) {
			if (!strcmp(args[cur_arg], "uid")) {
				global.stats_sock.perm.ux.uid = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "gid")) {
				global.stats_sock.perm.ux.gid = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "mode")) {
				global.stats_sock.perm.ux.mode = strtol(args[cur_arg + 1], NULL, 8);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "user")) {
				struct passwd *user;
				user = getpwnam(args[cur_arg + 1]);
				if (!user) {
					snprintf(err, errlen, "unknown user '%s' in 'global' section ('stats user')",
						 args[cur_arg + 1]);
					return -1;
				}
				global.stats_sock.perm.ux.uid = user->pw_uid;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "group")) {
				struct group *group;
				group = getgrnam(args[cur_arg + 1]);
				if (!group) {
					snprintf(err, errlen, "unknown group '%s' in 'global' section ('stats group')",
						 args[cur_arg + 1]);
					return -1;
				}
				global.stats_sock.perm.ux.gid = group->gr_gid;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "level")) {
				if (!strcmp(args[cur_arg+1], "user"))
					global.stats_sock.perm.ux.level = ACCESS_LVL_USER;
				else if (!strcmp(args[cur_arg+1], "operator"))
					global.stats_sock.perm.ux.level = ACCESS_LVL_OPER;
				else if (!strcmp(args[cur_arg+1], "admin"))
					global.stats_sock.perm.ux.level = ACCESS_LVL_ADMIN;
				else {
					snprintf(err, errlen, "'stats socket level' only supports 'user', 'operator', and 'admin'");
					return -1;
				}
				cur_arg += 2;
			}
			else {
				snprintf(err, errlen, "'stats socket' only supports 'user', 'uid', 'group', 'gid', 'level', and 'mode'");
				return -1;
			}
		}

		uxst_add_listener(&global.stats_sock);
		global.maxsock++;
	}
	else if (!strcmp(args[0], "timeout")) {
		unsigned timeout;
		const char *res = parse_time_err(args[1], &timeout, TIME_UNIT_MS);

		if (res) {
			snprintf(err, errlen, "unexpected character '%c' in 'stats timeout' in 'global' section", *res);
			return -1;
		}

		if (!timeout) {
			snprintf(err, errlen, "a positive value is expected for 'stats timeout' in 'global section'");
			return -1;
		}
		if (!global.stats_fe) {
			if ((global.stats_fe = alloc_stats_fe("GLOBAL")) == NULL) {
				snprintf(err, errlen, "out of memory");
				return -1;
			}
		}
		global.stats_fe->timeout.client = MS_TO_TICKS(timeout);
	}
	else if (!strcmp(args[0], "maxconn")) {
		int maxconn = atol(args[1]);

		if (maxconn <= 0) {
			snprintf(err, errlen, "a positive value is expected for 'stats maxconn' in 'global section'");
			return -1;
		}
		global.maxsock -= global.stats_sock.maxconn;
		global.stats_sock.maxconn = maxconn;
		global.maxsock += global.stats_sock.maxconn;
		if (global.stats_fe)
			global.stats_fe->maxconn = global.stats_sock.maxconn;
	}
	else {
		snprintf(err, errlen, "'stats' only supports 'socket', 'maxconn' and 'timeout' in 'global' section");
		return -1;
	}
	return 0;
}

static int print_csv_header(struct chunk *msg)
{
	return chunk_printf(msg,
			    "# pxname,svname,"
			    "qcur,qmax,"
			    "scur,smax,slim,stot,"
			    "bin,bout,"
			    "dreq,dresp,"
			    "ereq,econ,eresp,"
			    "wretr,wredis,"
			    "status,weight,act,bck,"
			    "chkfail,chkdown,lastchg,downtime,qlimit,"
			    "pid,iid,sid,throttle,lbtot,tracked,type,"
			    "rate,rate_lim,rate_max,"
			    "check_status,check_code,check_duration,"
			    "hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,"
			    "req_rate,req_rate_max,req_tot,"
			    "cli_abrt,srv_abrt,"
			    "\n");
}

/* print a string of text buffer to <out>. The format is :
 * Non-printable chars \t, \n, \r and \e are * encoded in C format.
 * Other non-printable chars are encoded "\xHH". Space and '\' are also escaped.
 * Print stopped if null char or <bsize> is reached, or if no more place in the chunk.
 */
static int dump_text(struct chunk *out, const char *buf, int bsize)
{
	unsigned char c;
	int ptr = 0;

	while (buf[ptr] && ptr < bsize) {
		c = buf[ptr];
		if (isprint(c) && isascii(c) && c != '\\' && c != ' ') {
			if (out->len > out->size - 1)
				break;
			out->str[out->len++] = c;
		}
		else if (c == '\t' || c == '\n' || c == '\r' || c == '\e' || c == '\\' || c == ' ') {
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
	struct session *s = si->applet.private;

	chunk_printf(msg, "# table: %s, type: %s, size:%d, used:%d\n",
		     proxy->id, stktable_types[proxy->table.type].kw, proxy->table.size, proxy->table.current);

	/* any other information should be dumped here */

	if (target && s->listener->perm.ux.level < ACCESS_LVL_OPER)
		chunk_printf(msg, "# contents not dumped due to insufficient privileges\n");

	if (buffer_feed_chunk(si->ib, msg) >= 0)
		return 0;

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

	chunk_printf(msg, "%p:", entry);

	if (proxy->table.type == STKTABLE_TYPE_IP) {
		char addr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, (const void *)&entry->key.key, addr, sizeof(addr));
		chunk_printf(msg, " key=%s", addr);
	}
	else if (proxy->table.type == STKTABLE_TYPE_IPV6) {
		char addr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, (const void *)&entry->key.key, addr, sizeof(addr));
		chunk_printf(msg, " key=%s", addr);
	}
	else if (proxy->table.type == STKTABLE_TYPE_INTEGER) {
		chunk_printf(msg, " key=%u", *(unsigned int *)entry->key.key);
	}
	else if (proxy->table.type == STKTABLE_TYPE_STRING) {
		chunk_printf(msg, " key=");
		dump_text(msg, (const char *)entry->key.key, proxy->table.key_size);
	}
	else {
		chunk_printf(msg, " key=");
		dump_binary(msg, (const char *)entry->key.key, proxy->table.key_size);
	}

	chunk_printf(msg, " use=%d exp=%d", entry->ref_cnt - 1, tick_remain(now_ms, entry->expire));

	for (dt = 0; dt < STKTABLE_DATA_TYPES; dt++) {
		void *ptr;

		if (proxy->table.data_ofs[dt] == 0)
			continue;
		if (stktable_data_types[dt].arg_type == ARG_T_DELAY)
			chunk_printf(msg, " %s(%d)=", stktable_data_types[dt].name, proxy->table.data_arg[dt].u);
		else
			chunk_printf(msg, " %s=", stktable_data_types[dt].name);

		ptr = stktable_data_ptr(&proxy->table, entry, dt);
		switch (stktable_data_types[dt].std_type) {
		case STD_T_SINT:
			chunk_printf(msg, "%d", stktable_data_cast(ptr, std_t_sint));
			break;
		case STD_T_UINT:
			chunk_printf(msg, "%u", stktable_data_cast(ptr, std_t_uint));
			break;
		case STD_T_ULL:
			chunk_printf(msg, "%lld", stktable_data_cast(ptr, std_t_ull));
			break;
		case STD_T_FRQP:
			chunk_printf(msg, "%d",
				     read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
							  proxy->table.data_arg[dt].u));
			break;
		}
	}
	chunk_printf(msg, "\n");

	if (buffer_feed_chunk(si->ib, msg) >= 0)
		return 0;

	return 1;
}

static void stats_sock_table_key_request(struct stream_interface *si, char **args, bool show)
{
	struct session *s = si->applet.private;
	struct proxy *px = si->applet.ctx.table.target;
	struct stksess *ts;
	unsigned int ip_key;

	si->applet.st0 = STAT_CLI_OUTPUT;

	if (!*args[4]) {
		si->applet.ctx.cli.msg = "Key value expected\n";
		si->applet.st0 = STAT_CLI_PRINT;
		return;
	}

	if (px->table.type == STKTABLE_TYPE_IP) {
		ip_key = htonl(inetaddr_host(args[4]));
		static_table_key.key = (void *)&ip_key;
	}
	else {
		if (show)
			si->applet.ctx.cli.msg = "Showing keys from non-ip tables is not supported\n";
		else
			si->applet.ctx.cli.msg = "Removing keys from non-ip tables is not supported\n";
		si->applet.st0 = STAT_CLI_PRINT;
		return;
	}

	/* check permissions */
	if (s->listener->perm.ux.level < ACCESS_LVL_OPER) {
		si->applet.ctx.cli.msg = stats_permission_denied_msg;
		si->applet.st0 = STAT_CLI_PRINT;
		return;
	}

	ts = stktable_lookup_key(&px->table, &static_table_key);
	if (!ts)
		return;

	if (show) {
		struct chunk msg;
		chunk_init(&msg, trash, sizeof(trash));
		if (!stats_dump_table_head_to_buffer(&msg, si, px, px))
			return;
		stats_dump_table_entry_to_buffer(&msg, si, px, ts);
		return;
	}

	if (ts->ref_cnt) {
		/* don't delete an entry which is currently referenced */
		si->applet.ctx.cli.msg = "Entry currently in use, cannot remove\n";
		si->applet.st0 = STAT_CLI_PRINT;
		return;
	}

	stksess_kill(&px->table, ts);
}

static void stats_sock_table_data_request(struct stream_interface *si, char **args)
{
	/* condition on stored data value */
	si->applet.ctx.table.data_type = stktable_get_data_type(args[3] + 5);
	if (si->applet.ctx.table.data_type < 0) {
		si->applet.ctx.cli.msg = "Unknown data type\n";
		si->applet.st0 = STAT_CLI_PRINT;
		return;
	}

	if (!((struct proxy *)si->applet.ctx.table.target)->table.data_ofs[si->applet.ctx.table.data_type]) {
		si->applet.ctx.cli.msg = "Data type not stored in this table\n";
		si->applet.st0 = STAT_CLI_PRINT;
		return;
	}

	si->applet.ctx.table.data_op = get_std_op(args[4]);
	if (si->applet.ctx.table.data_op < 0) {
		si->applet.ctx.cli.msg = "Require and operator among \"eq\", \"ne\", \"le\", \"ge\", \"lt\", \"gt\"\n";
		si->applet.st0 = STAT_CLI_PRINT;
		return;
	}

	if (!*args[5] || strl2llrc(args[5], strlen(args[5]), &si->applet.ctx.table.value) != 0) {
		si->applet.ctx.cli.msg = "Require a valid integer value to compare against\n";
		si->applet.st0 = STAT_CLI_PRINT;
		return;
	}
}

static void stats_sock_table_request(struct stream_interface *si, char **args, bool show)
{
	si->applet.ctx.table.data_type = -1;
	si->applet.state = STAT_ST_INIT;
	si->applet.ctx.table.proxy = NULL;
	si->applet.ctx.table.entry = NULL;
	si->applet.st0 = STAT_CLI_O_TAB; // stats_dump_table_to_buffer

	if (*args[2]) {
		si->applet.ctx.table.target = find_stktable(args[2]);
		if (!si->applet.ctx.table.target) {
			si->applet.ctx.cli.msg = "No such table\n";
			si->applet.st0 = STAT_CLI_PRINT;
			return;
		}
	}
	else {
		if (!show)
			goto err_args;
		return;
	}

	if (strcmp(args[3], "key") == 0)
		stats_sock_table_key_request(si, args, show);
	else if (show && strncmp(args[3], "data.", 5) == 0)
		stats_sock_table_data_request(si, args);
	else if (!show || *args[3])
		goto err_args;

	return;

err_args:
	if (show)
		si->applet.ctx.cli.msg = "Optional argument only supports \"data.<store_data_type>\" <operator> <value> and key <key>\n";
	else
		si->applet.ctx.cli.msg = "Required arguments: <table> key <key>\n";
	si->applet.st0 = STAT_CLI_PRINT;
}

/* Processes the stats interpreter on the statistics socket. This function is
 * called from an applet running in a stream interface. The function returns 1
 * if the request was understood, otherwise zero. It sets si->applet.st0 to a value
 * designating the function which will have to process the request, which can
 * also be the print function to display the return message set into cli.msg.
 */
static int stats_sock_parse_request(struct stream_interface *si, char *line)
{
	struct session *s = si->applet.private;
	char *args[MAX_STATS_ARGS + 1];
	int arg;

	while (isspace((unsigned char)*line))
		line++;

	arg = 0;
	args[arg] = line;

	while (*line && arg < MAX_STATS_ARGS) {
		if (isspace((unsigned char)*line)) {
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

	si->applet.ctx.stats.flags = 0;
	if (strcmp(args[0], "show") == 0) {
		if (strcmp(args[1], "stat") == 0) {
			if (*args[2] && *args[3] && *args[4]) {
				si->applet.ctx.stats.flags |= STAT_BOUND;
				si->applet.ctx.stats.iid = atoi(args[2]);
				si->applet.ctx.stats.type = atoi(args[3]);
				si->applet.ctx.stats.sid = atoi(args[4]);
			}

			si->applet.ctx.stats.flags |= STAT_SHOW_STAT;
			si->applet.ctx.stats.flags |= STAT_FMT_CSV;
			si->applet.state = STAT_ST_INIT;
			si->applet.st0 = STAT_CLI_O_INFO; // stats_dump_raw_to_buffer
		}
		else if (strcmp(args[1], "info") == 0) {
			si->applet.ctx.stats.flags |= STAT_SHOW_INFO;
			si->applet.ctx.stats.flags |= STAT_FMT_CSV;
			si->applet.state = STAT_ST_INIT;
			si->applet.st0 = STAT_CLI_O_INFO; // stats_dump_raw_to_buffer
		}
		else if (strcmp(args[1], "sess") == 0) {
			si->applet.state = STAT_ST_INIT;
			if (s->listener->perm.ux.level < ACCESS_LVL_OPER) {
				si->applet.ctx.cli.msg = stats_permission_denied_msg;
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}
			if (*args[2])
				si->applet.ctx.sess.target = (void *)strtoul(args[2], NULL, 0);
			else
				si->applet.ctx.sess.target = NULL;
			si->applet.ctx.sess.section = 0; /* start with session status */
			si->applet.ctx.sess.pos = 0;
			si->applet.st0 = STAT_CLI_O_SESS; // stats_dump_sess_to_buffer
		}
		else if (strcmp(args[1], "errors") == 0) {
			if (s->listener->perm.ux.level < ACCESS_LVL_OPER) {
				si->applet.ctx.cli.msg = stats_permission_denied_msg;
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}
			if (*args[2])
				si->applet.ctx.errors.iid	= atoi(args[2]);
			else
				si->applet.ctx.errors.iid	= -1;
			si->applet.ctx.errors.px = NULL;
			si->applet.state = STAT_ST_INIT;
			si->applet.st0 = STAT_CLI_O_ERR; // stats_dump_errors_to_buffer
		}
		else if (strcmp(args[1], "table") == 0) {
			stats_sock_table_request(si, args, true);
		}
		else { /* neither "stat" nor "info" nor "sess" nor "errors" no "table" */
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
			if (s->listener->perm.ux.level < ACCESS_LVL_OPER ||
			    (clrall && s->listener->perm.ux.level < ACCESS_LVL_ADMIN)) {
				si->applet.ctx.cli.msg = stats_permission_denied_msg;
				si->applet.st0 = STAT_CLI_PRINT;
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

				for (li = px->listen; li; li = li->next)
					if (li->counters) {
						if (clrall)
							memset(li->counters, 0, sizeof(*li->counters));
						else
							li->counters->conn_max = 0;
					}
			}

			return 1;
		}
		else if (strcmp(args[1], "table") == 0) {
			stats_sock_table_request(si, args, false);
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
				si->applet.ctx.cli.msg = "Require 'backend/server'.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (!get_backend_server(args[2], line, &px, &sv)) {
				si->applet.ctx.cli.msg = px ? "No such server.\n" : "No such backend.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			/* return server's effective weight at the moment */
			snprintf(trash, sizeof(trash), "%d (initial %d)\n", sv->uweight, sv->iweight);
			buffer_feed(si->ib, trash);
			return 1;
		}
		else { /* not "get weight" */
			return 0;
		}
	}
	else if (strcmp(args[0], "set") == 0) {
		if (strcmp(args[1], "weight") == 0) {
			struct proxy *px;
			struct server *sv;
			int w;

			if (s->listener->perm.ux.level < ACCESS_LVL_ADMIN) {
				si->applet.ctx.cli.msg = stats_permission_denied_msg;
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			/* split "backend/server" and make <line> point to server */
			for (line = args[2]; *line; line++)
				if (*line == '/') {
					*line++ = '\0';
					break;
				}

			if (!*line || !*args[3]) {
				si->applet.ctx.cli.msg = "Require 'backend/server' and 'weight' or 'weight%'.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (!get_backend_server(args[2], line, &px, &sv)) {
				si->applet.ctx.cli.msg = px ? "No such server.\n" : "No such backend.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (px->state == PR_STSTOPPED) {
				si->applet.ctx.cli.msg = "Proxy is disabled.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			/* if the weight is terminated with '%', it is set relative to
			 * the initial weight, otherwise it is absolute.
			 */
			w = atoi(args[3]);
			if (strchr(args[3], '%') != NULL) {
				if (w < 0 || w > 100) {
					si->applet.ctx.cli.msg = "Relative weight can only be set between 0 and 100% inclusive.\n";
					si->applet.st0 = STAT_CLI_PRINT;
					return 1;
				}
				w = sv->iweight * w / 100;
			}
			else {
				if (w < 0 || w > 256) {
					si->applet.ctx.cli.msg = "Absolute weight can only be between 0 and 256 inclusive.\n";
					si->applet.st0 = STAT_CLI_PRINT;
					return 1;
				}
			}

			if (w && w != sv->iweight && !(px->lbprm.algo & BE_LB_PROP_DYN)) {
				si->applet.ctx.cli.msg = "Backend is using a static LB algorithm and only accepts weights '0%' and '100%'.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			sv->uweight = w;

			if (px->lbprm.algo & BE_LB_PROP_DYN) {
			/* we must take care of not pushing the server to full throttle during slow starts */
				if ((sv->state & SRV_WARMINGUP) && (px->lbprm.algo & BE_LB_PROP_DYN))
					sv->eweight = (BE_WEIGHT_SCALE * (now.tv_sec - sv->last_change) + sv->slowstart - 1) / sv->slowstart;
				else
					sv->eweight = BE_WEIGHT_SCALE;
				sv->eweight *= sv->uweight;
			} else {
				sv->eweight = sv->uweight;
			}

			/* static LB algorithms are a bit harder to update */
			if (px->lbprm.update_server_eweight)
				px->lbprm.update_server_eweight(sv);
			else if (sv->eweight)
				px->lbprm.set_server_status_up(sv);
			else
				px->lbprm.set_server_status_down(sv);

			return 1;
		}
		else if (strcmp(args[1], "timeout") == 0) {
			if (strcmp(args[2], "cli") == 0) {
				unsigned timeout;
				const char *res;

				if (!*args[3]) {
					si->applet.ctx.cli.msg = "Expects an integer value.\n";
					si->applet.st0 = STAT_CLI_PRINT;
					return 1;
				}

				res = parse_time_err(args[3], &timeout, TIME_UNIT_S);
				if (res || timeout < 1) {
					si->applet.ctx.cli.msg = "Invalid timeout value.\n";
					si->applet.st0 = STAT_CLI_PRINT;
					return 1;
				}

				s->req->rto = s->rep->wto = 1 + MS_TO_TICKS(timeout*1000);
				return 1;
			}
			else {
				si->applet.ctx.cli.msg = "'set timeout' only supports 'cli'.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}
		}
		else { /* unknown "set" parameter */
			return 0;
		}
	}
	else if (strcmp(args[0], "enable") == 0) {
		if (strcmp(args[1], "server") == 0) {
			struct proxy *px;
			struct server *sv;

			if (s->listener->perm.ux.level < ACCESS_LVL_ADMIN) {
				si->applet.ctx.cli.msg = stats_permission_denied_msg;
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			/* split "backend/server" and make <line> point to server */
			for (line = args[2]; *line; line++)
				if (*line == '/') {
					*line++ = '\0';
					break;
				}

			if (!*line || !*args[2]) {
				si->applet.ctx.cli.msg = "Require 'backend/server'.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (!get_backend_server(args[2], line, &px, &sv)) {
				si->applet.ctx.cli.msg = px ? "No such server.\n" : "No such backend.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (px->state == PR_STSTOPPED) {
				si->applet.ctx.cli.msg = "Proxy is disabled.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (sv->state & SRV_MAINTAIN) {
				/* The server is really in maintenance, we can change the server state */
				if (sv->tracked) {
					/* If this server tracks the status of another one,
					* we must restore the good status.
					*/
					if (sv->tracked->state & SRV_RUNNING) {
						set_server_up(sv);
						sv->health = sv->rise;	/* up, but will fall down at first failure */
					} else {
						sv->state &= ~SRV_MAINTAIN;
						set_server_down(sv);
					}
				} else {
					set_server_up(sv);
					sv->health = sv->rise;	/* up, but will fall down at first failure */
				}
			}

			return 1;
		}
		else { /* unknown "enable" parameter */
			return 0;
		}
	}
	else if (strcmp(args[0], "disable") == 0) {
		if (strcmp(args[1], "server") == 0) {
			struct proxy *px;
			struct server *sv;

			if (s->listener->perm.ux.level < ACCESS_LVL_ADMIN) {
				si->applet.ctx.cli.msg = stats_permission_denied_msg;
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			/* split "backend/server" and make <line> point to server */
			for (line = args[2]; *line; line++)
				if (*line == '/') {
					*line++ = '\0';
					break;
				}

			if (!*line || !*args[2]) {
				si->applet.ctx.cli.msg = "Require 'backend/server'.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (!get_backend_server(args[2], line, &px, &sv)) {
				si->applet.ctx.cli.msg = px ? "No such server.\n" : "No such backend.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (px->state == PR_STSTOPPED) {
				si->applet.ctx.cli.msg = "Proxy is disabled.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (! (sv->state & SRV_MAINTAIN)) {
				/* Not already in maintenance, we can change the server state */
				sv->state |= SRV_MAINTAIN;
				set_server_down(sv);
			}

			return 1;
		}
		else { /* unknown "disable" parameter */
			return 0;
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
 * Then we can read again. The state is stored in si->applet.st0 and is one of the
 * STAT_CLI_* constants. si->applet.st1 is used to indicate whether prompt is enabled
 * or not.
 */
static void cli_io_handler(struct stream_interface *si)
{
	struct buffer *req = si->ob;
	struct buffer *res = si->ib;
	int reql;
	int len;

	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		goto out;

	while (1) {
		if (si->applet.st0 == STAT_CLI_INIT) {
			/* Stats output not initialized yet */
			memset(&si->applet.ctx.stats, 0, sizeof(si->applet.ctx.stats));
			si->applet.st0 = STAT_CLI_GETREQ;
		}
		else if (si->applet.st0 == STAT_CLI_END) {
			/* Let's close for real now. We just close the request
			 * side, the conditions below will complete if needed.
			 */
			si->shutw(si);
			break;
		}
		else if (si->applet.st0 == STAT_CLI_GETREQ) {
			/* ensure we have some output room left in the event we
			 * would want to return some info right after parsing.
			 */
			if (buffer_almost_full(si->ib))
				break;

			reql = buffer_get_line(si->ob, trash, sizeof(trash));
			if (reql <= 0) { /* closed or EOL not found */
				if (reql == 0)
					break;
				si->applet.st0 = STAT_CLI_END;
				continue;
			}

			/* seek for a possible semi-colon. If we find one, we
			 * replace it with an LF and skip only this part.
			 */
			for (len = 0; len < reql; len++)
				if (trash[len] == ';') {
					trash[len] = '\n';
					reql = len + 1;
					break;
				}

			/* now it is time to check that we have a full line,
			 * remove the trailing \n and possibly \r, then cut the
			 * line.
			 */
			len = reql - 1;
			if (trash[len] != '\n') {
				si->applet.st0 = STAT_CLI_END;
				continue;
			}

			if (len && trash[len-1] == '\r')
				len--;

			trash[len] = '\0';

			si->applet.st0 = STAT_CLI_PROMPT;
			if (len) {
				if (strcmp(trash, "quit") == 0) {
					si->applet.st0 = STAT_CLI_END;
					continue;
				}
				else if (strcmp(trash, "prompt") == 0)
					si->applet.st1 = !si->applet.st1;
				else if (strcmp(trash, "help") == 0 ||
					 !stats_sock_parse_request(si, trash)) {
					si->applet.ctx.cli.msg = stats_sock_usage_msg;
					si->applet.st0 = STAT_CLI_PRINT;
				}
				/* NB: stats_sock_parse_request() may have put
				 * another STAT_CLI_O_* into si->applet.st0.
				 */
			}
			else if (!si->applet.st1) {
				/* if prompt is disabled, print help on empty lines,
				 * so that the user at least knows how to enable
				 * prompt and find help.
				 */
				si->applet.ctx.cli.msg = stats_sock_usage_msg;
				si->applet.st0 = STAT_CLI_PRINT;
			}

			/* re-adjust req buffer */
			buffer_skip(si->ob, reql);
			req->flags |= BF_READ_DONTWAIT; /* we plan to read small requests */
		}
		else {	/* output functions: first check if the output buffer is closed then abort */
			if (res->flags & (BF_SHUTR_NOW|BF_SHUTR)) {
				si->applet.st0 = STAT_CLI_END;
				continue;
			}

			switch (si->applet.st0) {
			case STAT_CLI_PRINT:
				if (buffer_feed(si->ib, si->applet.ctx.cli.msg) < 0)
					si->applet.st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_INFO:
				if (stats_dump_raw_to_buffer(si))
					si->applet.st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_SESS:
				if (stats_dump_sess_to_buffer(si))
					si->applet.st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_ERR:	/* errors dump */
				if (stats_dump_errors_to_buffer(si))
					si->applet.st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_TAB:
				if (stats_dump_table_to_buffer(si))
					si->applet.st0 = STAT_CLI_PROMPT;
				break;
			default: /* abnormal state */
				si->applet.st0 = STAT_CLI_PROMPT;
				break;
			}

			/* The post-command prompt is either LF alone or LF + '> ' in interactive mode */
			if (si->applet.st0 == STAT_CLI_PROMPT) {
				if (buffer_feed(si->ib, si->applet.st1 ? "\n> " : "\n") < 0)
					si->applet.st0 = STAT_CLI_GETREQ;
			}

			/* If the output functions are still there, it means they require more room. */
			if (si->applet.st0 >= STAT_CLI_OUTPUT)
				break;

			/* Now we close the output if one of the writers did so,
			 * or if we're not in interactive mode and the request
			 * buffer is empty. This still allows pipelined requests
			 * to be sent in non-interactive mode.
			 */
			if ((res->flags & (BF_SHUTW|BF_SHUTW_NOW)) || (!si->applet.st1 && !req->send_max)) {
				si->applet.st0 = STAT_CLI_END;
				continue;
			}

			/* switch state back to GETREQ to read next requests */
			si->applet.st0 = STAT_CLI_GETREQ;
		}
	}

	if ((res->flags & BF_SHUTR) && (si->state == SI_ST_EST) && (si->applet.st0 != STAT_CLI_GETREQ)) {
		DPRINTF(stderr, "%s@%d: si to buf closed. req=%08x, res=%08x, st=%d\n",
			__FUNCTION__, __LINE__, req->flags, res->flags, si->state);
		/* Other size has closed, let's abort if we have no more processing to do
		 * and nothing more to consume. This is comparable to a broken pipe, so
		 * we forward the close to the request side so that it flows upstream to
		 * the client.
		 */
		si->shutw(si);
	}

	if ((req->flags & BF_SHUTW) && (si->state == SI_ST_EST) && (si->applet.st0 < STAT_CLI_OUTPUT)) {
		DPRINTF(stderr, "%s@%d: buf to si closed. req=%08x, res=%08x, st=%d\n",
			__FUNCTION__, __LINE__, req->flags, res->flags, si->state);
		/* We have no more processing to do, and nothing more to send, and
		 * the client side has closed. So we'll forward this state downstream
		 * on the response buffer.
		 */
		si->shutr(si);
		res->flags |= BF_READ_NULL;
	}

	/* update all other flags and resync with the other side */
	si->update(si);

	/* we don't want to expire timeouts while we're processing requests */
	si->ib->rex = TICK_ETERNITY;
	si->ob->wex = TICK_ETERNITY;

 out:
	DPRINTF(stderr, "%s@%d: st=%d, rqf=%x, rpf=%x, rql=%d, rqs=%d, rl=%d, rs=%d\n",
		__FUNCTION__, __LINE__,
		si->state, req->flags, res->flags, req->l, req->send_max, res->l, res->send_max);

	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO)) {
		/* check that we have released everything then unregister */
		stream_int_unregister_handler(si);
	}
}

/* This function dumps statistics onto the stream interface's read buffer.
 * The data_ctx must have been zeroed first, and the flags properly set.
 * It returns 0 as long as it does not complete, non-zero upon completion.
 * Some states are not used but it makes the code more similar to other
 * functions which handle stats too.
 */
static int stats_dump_raw_to_buffer(struct stream_interface *si)
{
	struct proxy *px;
	struct chunk msg;
	unsigned int up;

	chunk_init(&msg, trash, sizeof(trash));

	switch (si->applet.state) {
	case STAT_ST_INIT:
		/* the function had not been called yet */
		si->applet.state = STAT_ST_HEAD;
		/* fall through */

	case STAT_ST_HEAD:
		if (si->applet.ctx.stats.flags & STAT_SHOW_STAT) {
			print_csv_header(&msg);
			if (buffer_feed_chunk(si->ib, &msg) >= 0)
				return 0;
		}

		si->applet.state = STAT_ST_INFO;
		/* fall through */

	case STAT_ST_INFO:
		up = (now.tv_sec - start_date.tv_sec);
		if (si->applet.ctx.stats.flags & STAT_SHOW_INFO) {
			chunk_printf(&msg,
				     "Name: " PRODUCT_NAME "\n"
				     "Version: " HAPROXY_VERSION "\n"
				     "Release_date: " HAPROXY_DATE "\n"
				     "Nbproc: %d\n"
				     "Process_num: %d\n"
				     "Pid: %d\n"
				     "Uptime: %dd %dh%02dm%02ds\n"
				     "Uptime_sec: %d\n"
				     "Memmax_MB: %d\n"
				     "Ulimit-n: %d\n"
				     "Maxsock: %d\n"
				     "Maxconn: %d\n"
				     "Maxpipes: %d\n"
				     "CurrConns: %d\n"
				     "PipesUsed: %d\n"
				     "PipesFree: %d\n"
				     "Tasks: %d\n"
				     "Run_queue: %d\n"
				     "node: %s\n"
				     "description: %s\n"
				     "",
				     global.nbproc,
				     relative_pid,
				     pid,
				     up / 86400, (up % 86400) / 3600, (up % 3600) / 60, (up % 60),
				     up,
				     global.rlimit_memmax,
				     global.rlimit_nofile,
				     global.maxsock, global.maxconn, global.maxpipes,
				     actconn, pipes_used, pipes_free,
				     nb_tasks_cur, run_queue_cur,
				     global.node, global.desc?global.desc:""
				     );
			if (buffer_feed_chunk(si->ib, &msg) >= 0)
				return 0;
		}

		si->applet.ctx.stats.px = proxy;
		si->applet.ctx.stats.px_st = STAT_PX_ST_INIT;
		si->applet.ctx.stats.sv = NULL;
		si->applet.state = STAT_ST_LIST;
		/* fall through */

	case STAT_ST_LIST:
		/* dump proxies */
		if (si->applet.ctx.stats.flags & STAT_SHOW_STAT) {
			while (si->applet.ctx.stats.px) {
				px = si->applet.ctx.stats.px;
				/* skip the disabled proxies and non-networked ones */
				if (px->state != PR_STSTOPPED &&
				    (px->cap & (PR_CAP_FE | PR_CAP_BE))) {
					if (stats_dump_proxy(si, px, NULL) == 0)
						return 0;
				}

				si->applet.ctx.stats.px = px->next;
				si->applet.ctx.stats.px_st = STAT_PX_ST_INIT;
			}
			/* here, we just have reached the last proxy */
		}

		si->applet.state = STAT_ST_END;
		/* fall through */

	case STAT_ST_END:
		si->applet.state = STAT_ST_FIN;
		/* fall through */

	case STAT_ST_FIN:
		return 1;

	default:
		/* unknown state ! */
		si->applet.state = STAT_ST_FIN;
		return 1;
	}
}


/* We don't want to land on the posted stats page because a refresh will
 * repost the data.  We don't want this to happen on accident so we redirect
 * the browse to the stats page with a GET.
 */
static int stats_http_redir(struct stream_interface *si, struct uri_auth *uri)
{
	struct session *s = si->applet.private;
	struct chunk msg;

	chunk_init(&msg, trash, sizeof(trash));

	switch (si->applet.state) {
	case STAT_ST_INIT:
		chunk_printf(&msg,
			"HTTP/1.0 303 See Other\r\n"
			"Cache-Control: no-cache\r\n"
			"Content-Type: text/plain\r\n"
			"Connection: close\r\n"
			"Location: %s;st=%s",
			uri->uri_prefix, si->applet.ctx.stats.st_code);
		chunk_printf(&msg, "\r\n\r\n");

		if (buffer_feed_chunk(si->ib, &msg) >= 0)
			return 0;

		s->txn.status = 303;

		if (!(s->flags & SN_ERR_MASK))  // this is not really an error but it is
			s->flags |= SN_ERR_PRXCOND; // to mark that it comes from the proxy
		if (!(s->flags & SN_FINST_MASK))
			s->flags |= SN_FINST_R;

		si->applet.state = STAT_ST_FIN;
		return 1;
	}
	return 1;
}


/* This I/O handler runs as an applet embedded in a stream interface. It is
 * used to send HTTP stats over a TCP socket. The mechanism is very simple.
 * si->applet.st0 becomes non-zero once the transfer is finished. The handler
 * automatically unregisters itself once transfer is complete.
 */
static void http_stats_io_handler(struct stream_interface *si)
{
	struct session *s = si->applet.private;
	struct buffer *req = si->ob;
	struct buffer *res = si->ib;

	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		goto out;

	/* check that the output is not closed */
	if (res->flags & (BF_SHUTW|BF_SHUTW_NOW))
		si->applet.st0 = 1;

	if (!si->applet.st0) {
		if (s->txn.meth == HTTP_METH_POST) {
			if (stats_http_redir(si, s->be->uri_auth)) {
				si->applet.st0 = 1;
				si->shutw(si);
			}
		} else {
			if (stats_dump_http(si, s->be->uri_auth)) {
				si->applet.st0 = 1;
				si->shutw(si);
			}
		}
	}

	if ((res->flags & BF_SHUTR) && (si->state == SI_ST_EST))
		si->shutw(si);

	if ((req->flags & BF_SHUTW) && (si->state == SI_ST_EST) && si->applet.st0) {
		si->shutr(si);
		res->flags |= BF_READ_NULL;
	}

	/* update all other flags and resync with the other side */
	si->update(si);

	/* we don't want to expire timeouts while we're processing requests */
	si->ib->rex = TICK_ETERNITY;
	si->ob->wex = TICK_ETERNITY;

 out:
	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO)) {
		/* check that we have released everything then unregister */
		stream_int_unregister_handler(si);
	}
}


/* This function dumps statistics in HTTP format onto the stream interface's
 * read buffer. The data_ctx must have been zeroed first, and the flags
 * properly set. It returns 0 if it had to stop writing data and an I/O is
 * needed, 1 if the dump is finished and the session must be closed, or -1
 * in case of any error.
 */
static int stats_dump_http(struct stream_interface *si, struct uri_auth *uri)
{
	struct session *s = si->applet.private;
	struct buffer *rep = si->ib;
	struct proxy *px;
	struct chunk msg;
	unsigned int up;

	chunk_init(&msg, trash, sizeof(trash));

	switch (si->applet.state) {
	case STAT_ST_INIT:
		chunk_printf(&msg,
			     "HTTP/1.0 200 OK\r\n"
			     "Cache-Control: no-cache\r\n"
			     "Connection: close\r\n"
			     "Content-Type: %s\r\n",
			     (si->applet.ctx.stats.flags & STAT_FMT_CSV) ? "text/plain" : "text/html");

		if (uri->refresh > 0 && !(si->applet.ctx.stats.flags & STAT_NO_REFRESH))
			chunk_printf(&msg, "Refresh: %d\r\n",
				     uri->refresh);

		chunk_printf(&msg, "\r\n");

		s->txn.status = 200;
		if (buffer_feed_chunk(rep, &msg) >= 0)
			return 0;

		if (!(s->flags & SN_ERR_MASK))  // this is not really an error but it is
			s->flags |= SN_ERR_PRXCOND; // to mark that it comes from the proxy
		if (!(s->flags & SN_FINST_MASK))
			s->flags |= SN_FINST_R;

		if (s->txn.meth == HTTP_METH_HEAD) {
			/* that's all we return in case of HEAD request */
			si->applet.state = STAT_ST_FIN;
			return 1;
		}

		si->applet.state = STAT_ST_HEAD; /* let's start producing data */
		/* fall through */

	case STAT_ST_HEAD:
		if (!(si->applet.ctx.stats.flags & STAT_FMT_CSV)) {
			/* WARNING! This must fit in the first buffer !!! */
			chunk_printf(&msg,
			     "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\n"
			     "\"http://www.w3.org/TR/html4/loose.dtd\">\n"
			     "<html><head><title>Statistics Report for " PRODUCT_NAME "%s%s</title>\n"
			     "<meta http-equiv=\"content-type\" content=\"text/html; charset=iso-8859-1\">\n"
			     "<style type=\"text/css\"><!--\n"
			     "body {"
			     " font-family: arial, helvetica, sans-serif;"
			     " font-size: 12px;"
			     " font-weight: normal;"
			     " color: black;"
			     " background: white;"
			     "}\n"
			     "th,td {"
			     " font-size: 10px;"
			     "}\n"
			     "h1 {"
			     " font-size: x-large;"
			     " margin-bottom: 0.5em;"
			     "}\n"
			     "h2 {"
			     " font-family: helvetica, arial;"
			     " font-size: x-large;"
			     " font-weight: bold;"
			     " font-style: italic;"
			     " color: #6020a0;"
			     " margin-top: 0em;"
			     " margin-bottom: 0em;"
			     "}\n"
			     "h3 {"
			     " font-family: helvetica, arial;"
			     " font-size: 16px;"
			     " font-weight: bold;"
			     " color: #b00040;"
			     " background: #e8e8d0;"
			     " margin-top: 0em;"
			     " margin-bottom: 0em;"
			     "}\n"
			     "li {"
			     " margin-top: 0.25em;"
			     " margin-right: 2em;"
			     "}\n"
			     ".hr {margin-top: 0.25em;"
			     " border-color: black;"
			     " border-bottom-style: solid;"
			     "}\n"
			     ".titre	{background: #20D0D0;color: #000000; font-weight: bold; text-align: center;}\n"
			     ".total	{background: #20D0D0;color: #ffff80;}\n"
			     ".frontend	{background: #e8e8d0;}\n"
			     ".socket	{background: #d0d0d0;}\n"
			     ".backend	{background: #e8e8d0;}\n"
			     ".active0	{background: #ff9090;}\n"
			     ".active1	{background: #ffd020;}\n"
			     ".active2	{background: #ffffa0;}\n"
			     ".active3	{background: #c0ffc0;}\n"
			     ".active4	{background: #ffffa0;}\n"  /* NOLB state shows same as going down */
			     ".active5	{background: #a0e0a0;}\n"  /* NOLB state shows darker than up */
			     ".active6	{background: #e0e0e0;}\n"
			     ".backup0	{background: #ff9090;}\n"
			     ".backup1	{background: #ff80ff;}\n"
			     ".backup2	{background: #c060ff;}\n"
			     ".backup3	{background: #b0d0ff;}\n"
			     ".backup4	{background: #c060ff;}\n"  /* NOLB state shows same as going down */
			     ".backup5	{background: #90b0e0;}\n"  /* NOLB state shows same as going down */
			     ".backup6	{background: #e0e0e0;}\n"
			     ".maintain	{background: #c07820;}\n"
			     ".rls      {letter-spacing: 0.2em; margin-right: 1px;}\n" /* right letter spacing (used for grouping digits) */
			     "\n"
			     "a.px:link {color: #ffff40; text-decoration: none;}"
			     "a.px:visited {color: #ffff40; text-decoration: none;}"
			     "a.px:hover {color: #ffffff; text-decoration: none;}"
			     "a.lfsb:link {color: #000000; text-decoration: none;}"
			     "a.lfsb:visited {color: #000000; text-decoration: none;}"
			     "a.lfsb:hover {color: #505050; text-decoration: none;}"
			     "\n"
			     "table.tbl { border-collapse: collapse; border-style: none;}\n"
			     "table.tbl td { text-align: right; border-width: 1px 1px 1px 1px; border-style: solid solid solid solid; padding: 2px 3px; border-color: gray; white-space: nowrap;}\n"
			     "table.tbl td.ac { text-align: center;}\n"
			     "table.tbl th { border-width: 1px; border-style: solid solid solid solid; border-color: gray;}\n"
			     "table.tbl th.pxname { background: #b00040; color: #ffff40; font-weight: bold; border-style: solid solid none solid; padding: 2px 3px; white-space: nowrap;}\n"
			     "table.tbl th.empty { border-style: none; empty-cells: hide; background: white;}\n"
			     "table.tbl th.desc { background: white; border-style: solid solid none solid; text-align: left; padding: 2px 3px;}\n"
			     "\n"
			     "table.lgd { border-collapse: collapse; border-width: 1px; border-style: none none none solid; border-color: black;}\n"
			     "table.lgd td { border-width: 1px; border-style: solid solid solid solid; border-color: gray; padding: 2px;}\n"
			     "table.lgd td.noborder { border-style: none; padding: 2px; white-space: nowrap;}\n"
			     "u {text-decoration:none; border-bottom: 1px dotted black;}\n"
			     "-->\n"
			     "</style></head>\n",
			     (uri->flags&ST_SHNODE) ? " on " : "",
			     (uri->flags&ST_SHNODE) ? (uri->node ? uri->node : global.node) : ""
			     );
		} else {
			print_csv_header(&msg);
		}
		if (buffer_feed_chunk(rep, &msg) >= 0)
			return 0;

		si->applet.state = STAT_ST_INFO;
		/* fall through */

	case STAT_ST_INFO:
		up = (now.tv_sec - start_date.tv_sec);

		/* WARNING! this has to fit the first packet too.
			 * We are around 3.5 kB, add adding entries will
			 * become tricky if we want to support 4kB buffers !
			 */
		if (!(si->applet.ctx.stats.flags & STAT_FMT_CSV)) {
			chunk_printf(&msg,
			     "<body><h1><a href=\"" PRODUCT_URL "\" style=\"text-decoration: none;\">"
			     PRODUCT_NAME "%s</a></h1>\n"
			     "<h2>Statistics Report for pid %d%s%s%s%s</h2>\n"
			     "<hr width=\"100%%\" class=\"hr\">\n"
			     "<h3>&gt; General process information</h3>\n"
			     "<table border=0><tr><td align=\"left\" nowrap width=\"1%%\">\n"
			     "<p><b>pid = </b> %d (process #%d, nbproc = %d)<br>\n"
			     "<b>uptime = </b> %dd %dh%02dm%02ds<br>\n"
			     "<b>system limits:</b> memmax = %s%s; ulimit-n = %d<br>\n"
			     "<b>maxsock = </b> %d; <b>maxconn = </b> %d; <b>maxpipes = </b> %d<br>\n"
			     "current conns = %d; current pipes = %d/%d<br>\n"
			     "Running tasks: %d/%d<br>\n"
			     "</td><td align=\"center\" nowrap>\n"
			     "<table class=\"lgd\"><tr>\n"
			     "<td class=\"active3\">&nbsp;</td><td class=\"noborder\">active UP </td>"
			     "<td class=\"backup3\">&nbsp;</td><td class=\"noborder\">backup UP </td>"
			     "</tr><tr>\n"
			     "<td class=\"active2\"></td><td class=\"noborder\">active UP, going down </td>"
			     "<td class=\"backup2\"></td><td class=\"noborder\">backup UP, going down </td>"
			     "</tr><tr>\n"
			     "<td class=\"active1\"></td><td class=\"noborder\">active DOWN, going up </td>"
			     "<td class=\"backup1\"></td><td class=\"noborder\">backup DOWN, going up </td>"
			     "</tr><tr>\n"
			     "<td class=\"active0\"></td><td class=\"noborder\">active or backup DOWN &nbsp;</td>"
			     "<td class=\"active6\"></td><td class=\"noborder\">not checked </td>"
			     "</tr><tr>\n"
			     "<td class=\"maintain\"></td><td class=\"noborder\" colspan=\"3\">active or backup DOWN for maintenance (MAINT) &nbsp;</td>"
			     "</tr></table>\n"
			     "Note: UP with load-balancing disabled is reported as \"NOLB\"."
			     "</td>"
			     "<td align=\"left\" valign=\"top\" nowrap width=\"1%%\">"
			     "<b>Display option:</b><ul style=\"margin-top: 0.25em;\">"
			     "",
			     (uri->flags&ST_HIDEVER)?"":(STATS_VERSION_STRING),
			     pid, (uri->flags&ST_SHNODE) ? " on " : "", (uri->flags&ST_SHNODE) ? (uri->node ? uri->node : global.node) : "",
			     (uri->flags&ST_SHDESC)? ": " : "", (uri->flags&ST_SHDESC) ? (uri->desc ? uri->desc : global.desc) : "",
			     pid, relative_pid, global.nbproc,
			     up / 86400, (up % 86400) / 3600,
			     (up % 3600) / 60, (up % 60),
			     global.rlimit_memmax ? ultoa(global.rlimit_memmax) : "unlimited",
			     global.rlimit_memmax ? " MB" : "",
			     global.rlimit_nofile,
			     global.maxsock, global.maxconn, global.maxpipes,
			     actconn, pipes_used, pipes_used+pipes_free,
			     run_queue_cur, nb_tasks_cur
			     );

			if (si->applet.ctx.stats.flags & STAT_HIDE_DOWN)
				chunk_printf(&msg,
				     "<li><a href=\"%s%s%s\">Show all servers</a><br>\n",
				     uri->uri_prefix,
				     "",
				     (si->applet.ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "");
			else
				chunk_printf(&msg,
				     "<li><a href=\"%s%s%s\">Hide 'DOWN' servers</a><br>\n",
				     uri->uri_prefix,
				     ";up",
				     (si->applet.ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "");

			if (uri->refresh > 0) {
				if (si->applet.ctx.stats.flags & STAT_NO_REFRESH)
					chunk_printf(&msg,
					     "<li><a href=\"%s%s%s\">Enable refresh</a><br>\n",
					     uri->uri_prefix,
					     (si->applet.ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
					     "");
				else
					chunk_printf(&msg,
					     "<li><a href=\"%s%s%s\">Disable refresh</a><br>\n",
					     uri->uri_prefix,
					     (si->applet.ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
					     ";norefresh");
			}

			chunk_printf(&msg,
			     "<li><a href=\"%s%s%s\">Refresh now</a><br>\n",
			     uri->uri_prefix,
			     (si->applet.ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
			     (si->applet.ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "");

			chunk_printf(&msg,
			     "<li><a href=\"%s;csv%s\">CSV export</a><br>\n",
			     uri->uri_prefix,
			     (uri->refresh > 0) ? ";norefresh" : "");

			chunk_printf(&msg,
			     "</ul></td>"
			     "<td align=\"left\" valign=\"top\" nowrap width=\"1%%\">"
			     "<b>External ressources:</b><ul style=\"margin-top: 0.25em;\">\n"
			     "<li><a href=\"" PRODUCT_URL "\">Primary site</a><br>\n"
			     "<li><a href=\"" PRODUCT_URL_UPD "\">Updates (v" PRODUCT_BRANCH ")</a><br>\n"
			     "<li><a href=\"" PRODUCT_URL_DOC "\">Online manual</a><br>\n"
			     "</ul>"
			     "</td>"
			     "</tr></table>\n"
			     ""
			     );

			if (si->applet.ctx.stats.st_code) {
				if (strcmp(si->applet.ctx.stats.st_code, STAT_STATUS_DONE) == 0) {
					chunk_printf(&msg,
						     "<p><div class=active3>"
						     "<a class=lfsb href=\"%s\" title=\"Remove this message\">[X]</a> "
						     "Action processed successfully."
						     "</div>\n", uri->uri_prefix);
				}
				else if (strcmp(si->applet.ctx.stats.st_code, STAT_STATUS_NONE) == 0) {
					chunk_printf(&msg,
						     "<p><div class=active2>"
						     "<a class=lfsb href=\"%s\" title=\"Remove this message\">[X]</a> "
						     "Nothing has changed."
						     "</div>\n", uri->uri_prefix);
				}
				else if (strcmp(si->applet.ctx.stats.st_code, STAT_STATUS_EXCD) == 0) {
					chunk_printf(&msg,
						     "<p><div class=active0>"
						     "<a class=lfsb href=\"%s\" title=\"Remove this message\">[X]</a> "
						     "<b>Action not processed : the buffer couldn't store all the data.<br>"
						     "You should retry with less servers at a time.</b>"
						     "</div>\n", uri->uri_prefix);
				}
				else if (strcmp(si->applet.ctx.stats.st_code, STAT_STATUS_DENY) == 0) {
					chunk_printf(&msg,
						     "<p><div class=active0>"
						     "<a class=lfsb href=\"%s\" title=\"Remove this message\">[X]</a> "
						     "<b>Action denied.</b>"
						     "</div>\n", uri->uri_prefix);
				}
				else {
					chunk_printf(&msg,
						     "<p><div class=active6>"
						     "<a class=lfsb href=\"%s\" title=\"Remove this message\">[X]</a> "
						     "Unexpected result."
						     "</div>\n", uri->uri_prefix);
				}
				chunk_printf(&msg,"<p>\n");
			}

			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		}

		si->applet.ctx.stats.px = proxy;
		si->applet.ctx.stats.px_st = STAT_PX_ST_INIT;
		si->applet.state = STAT_ST_LIST;
		/* fall through */

	case STAT_ST_LIST:
		/* dump proxies */
		while (si->applet.ctx.stats.px) {
			if (buffer_almost_full(rep))
				return 0;
			px = si->applet.ctx.stats.px;
			/* skip the disabled proxies and non-networked ones */
			if (px->state != PR_STSTOPPED && (px->cap & (PR_CAP_FE | PR_CAP_BE)))
				if (stats_dump_proxy(si, px, uri) == 0)
					return 0;

			si->applet.ctx.stats.px = px->next;
			si->applet.ctx.stats.px_st = STAT_PX_ST_INIT;
		}
		/* here, we just have reached the last proxy */

		si->applet.state = STAT_ST_END;
		/* fall through */

	case STAT_ST_END:
		if (!(si->applet.ctx.stats.flags & STAT_FMT_CSV)) {
			chunk_printf(&msg, "</body></html>\n");
			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		}

		si->applet.state = STAT_ST_FIN;
		/* fall through */

	case STAT_ST_FIN:
		return 1;

	default:
		/* unknown state ! */
		si->applet.state = STAT_ST_FIN;
		return -1;
	}
}


/*
 * Dumps statistics for a proxy.
 * Returns 0 if it had to stop dumping data because of lack of buffer space,
 * ot non-zero if everything completed.
 */
static int stats_dump_proxy(struct stream_interface *si, struct proxy *px, struct uri_auth *uri)
{
	struct session *s = si->applet.private;
	struct buffer *rep = si->ib;
	struct server *sv, *svs;	/* server and server-state, server-state=server or server->tracked */
	struct listener *l;
	struct chunk msg;

	chunk_init(&msg, trash, sizeof(trash));

	switch (si->applet.ctx.stats.px_st) {
	case STAT_PX_ST_INIT:
		/* we are on a new proxy */

		if (uri && uri->scope) {
			/* we have a limited scope, we have to check the proxy name */
			struct stat_scope *scope;
			int len;

			len = strlen(px->id);
			scope = uri->scope;

			while (scope) {
				/* match exact proxy name */
				if (scope->px_len == len && !memcmp(px->id, scope->px_id, len))
					break;

				/* match '.' which means 'self' proxy */
				if (!strcmp(scope->px_id, ".") && px == s->be)
					break;
				scope = scope->next;
			}

			/* proxy name not found : don't dump anything */
			if (scope == NULL)
				return 1;
		}

		if ((si->applet.ctx.stats.flags & STAT_BOUND) && (si->applet.ctx.stats.iid != -1) &&
			(px->uuid != si->applet.ctx.stats.iid))
			return 1;

		si->applet.ctx.stats.px_st = STAT_PX_ST_TH;
		/* fall through */

	case STAT_PX_ST_TH:
		if (!(si->applet.ctx.stats.flags & STAT_FMT_CSV)) {
			if (px->cap & PR_CAP_BE && px->srv && (si->applet.ctx.stats.flags & STAT_ADMIN)) {
				/* A form to enable/disable this proxy servers */
				chunk_printf(&msg,
					"<form action=\"%s\" method=\"post\">",
					uri->uri_prefix);
			}

			/* print a new table */
			chunk_printf(&msg,
				     "<table class=\"tbl\" width=\"100%%\">\n"
				     "<tr class=\"titre\">"
				     "<th class=\"pxname\" width=\"10%%\"");

			if (uri->flags&ST_SHLGNDS) {
				/* cap, mode, id */
				chunk_printf(&msg, " title=\"cap: %s, mode: %s, id: %d",
					proxy_cap_str(px->cap), proxy_mode_str(px->mode),
					px->uuid);

				chunk_printf(&msg, "\"");
			}

			chunk_printf(&msg,
				     ">%s<a name=\"%s\"></a>"
				     "<a class=px href=\"#%s\">%s</a>%s</th>"
				     "<th class=\"%s\" width=\"90%%\">%s</th>"
				     "</tr>\n"
				     "</table>\n"
				     "<table class=\"tbl\" width=\"100%%\">\n"
				     "<tr class=\"titre\">",
				     (uri->flags & ST_SHLGNDS)?"<u>":"",
				     px->id, px->id, px->id,
				     (uri->flags & ST_SHLGNDS)?"</u>":"",
				     px->desc ? "desc" : "empty", px->desc ? px->desc : "");

			if (px->cap & PR_CAP_BE && px->srv && (si->applet.ctx.stats.flags & STAT_ADMIN)) {
				 /* Column heading for Enable or Disable server */
				chunk_printf(&msg, "<th rowspan=2 width=1></th>");
			}

			chunk_printf(&msg,
				     "<th rowspan=2></th>"
				     "<th colspan=3>Queue</th>"
				     "<th colspan=3>Session rate</th><th colspan=5>Sessions</th>"
				     "<th colspan=2>Bytes</th><th colspan=2>Denied</th>"
				     "<th colspan=3>Errors</th><th colspan=2>Warnings</th>"
				     "<th colspan=9>Server</th>"
				     "</tr>\n"
				     "<tr class=\"titre\">"
				     "<th>Cur</th><th>Max</th><th>Limit</th>"
				     "<th>Cur</th><th>Max</th><th>Limit</th><th>Cur</th><th>Max</th>"
				     "<th>Limit</th><th>Total</th><th>LbTot</th><th>In</th><th>Out</th>"
				     "<th>Req</th><th>Resp</th><th>Req</th><th>Conn</th>"
				     "<th>Resp</th><th>Retr</th><th>Redis</th>"
				     "<th>Status</th><th>LastChk</th><th>Wght</th><th>Act</th>"
				     "<th>Bck</th><th>Chk</th><th>Dwn</th><th>Dwntme</th>"
				     "<th>Thrtle</th>\n"
				     "</tr>");

			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		}

		si->applet.ctx.stats.px_st = STAT_PX_ST_FE;
		/* fall through */

	case STAT_PX_ST_FE:
		/* print the frontend */
		if ((px->cap & PR_CAP_FE) &&
		    (!(si->applet.ctx.stats.flags & STAT_BOUND) || (si->applet.ctx.stats.type & (1 << STATS_TYPE_FE)))) {
			if (!(si->applet.ctx.stats.flags & STAT_FMT_CSV)) {
				chunk_printf(&msg,
				     /* name, queue */
				     "<tr class=\"frontend\">");

				if (px->cap & PR_CAP_BE && px->srv && (si->applet.ctx.stats.flags & STAT_ADMIN)) {
					/* Column sub-heading for Enable or Disable server */
					chunk_printf(&msg, "<td></td>");
				}

				chunk_printf(&msg,
				     "<td class=ac>"
				     "<a name=\"%s/Frontend\"></a>"
				     "<a class=lfsb href=\"#%s/Frontend\">Frontend</a></td>"
				     "<td colspan=3></td>"
				     "",
				     px->id, px->id);

				if (px->mode == PR_MODE_HTTP) {
					chunk_printf(&msg,
						     /* sessions rate : current, max, limit */
						     "<td title=\"Cur: %u req/s\"><u>%s</u></td><td title=\"Max: %u req/s\"><u>%s</u></td><td>%s</td>"
						     "",
						     read_freq_ctr(&px->fe_req_per_sec),
						     U2H0(read_freq_ctr(&px->fe_sess_per_sec)),
						     px->fe_counters.p.http.rps_max,
						     U2H1(px->fe_counters.sps_max),
						     LIM2A2(px->fe_sps_lim, "-"));
				} else {
					chunk_printf(&msg,
						     /* sessions rate : current, max, limit */
						     "<td>%s</td><td>%s</td><td>%s</td>"
						     "",
						     U2H0(read_freq_ctr(&px->fe_sess_per_sec)),
						     U2H1(px->fe_counters.sps_max), LIM2A2(px->fe_sps_lim, "-"));
				}

				chunk_printf(&msg,
				     /* sessions: current, max, limit */
				     "<td>%s</td><td>%s</td><td>%s</td>"
				     "<td"
				     "",
				     U2H3(px->feconn), U2H4(px->fe_counters.conn_max), U2H5(px->maxconn));

				/* http response (via td title): 1xx, 2xx, 3xx, 4xx, 5xx, other */
				if (px->mode == PR_MODE_HTTP) {
					int i;

					chunk_printf(&msg, " title=\"%lld requests:", px->fe_counters.p.http.cum_req);

					for (i = 1; i < 6; i++)
						chunk_printf(&msg, " %dxx=%lld,", i, px->fe_counters.p.http.rsp[i]);

					chunk_printf(&msg, " other=%lld\"", px->fe_counters.p.http.rsp[0]);
				}

				chunk_printf(&msg,
				     /* sessions: total, lbtot */
				     ">%s%s%s</td><td></td>"
				     /* bytes : in, out */
				     "<td>%s</td><td>%s</td>"
				     "",
				     (px->mode == PR_MODE_HTTP)?"<u>":"",
				     U2H6(px->fe_counters.cum_sess),
				     (px->mode == PR_MODE_HTTP)?"</u>":"",
				     U2H7(px->fe_counters.bytes_in), U2H8(px->fe_counters.bytes_out));

				chunk_printf(&msg,
				     /* denied: req, resp */
				     "<td>%s</td><td>%s</td>"
				     /* errors : request, connect, response */
				     "<td>%s</td><td></td><td></td>"
				     /* warnings: retries, redispatches */
				     "<td></td><td></td>"
				     /* server status : reflect frontend status */
				     "<td class=ac>%s</td>"
				     /* rest of server: nothing */
				     "<td class=ac colspan=8></td></tr>"
				     "",
				     U2H0(px->fe_counters.denied_req), U2H1(px->fe_counters.denied_resp),
				     U2H2(px->fe_counters.failed_req),
				     px->state == PR_STRUN ? "OPEN" :
				     px->state == PR_STIDLE ? "FULL" : "STOP");
			} else {
				chunk_printf(&msg,
				     /* pxid, name, queue cur, queue max, */
				     "%s,FRONTEND,,,"
				     /* sessions : current, max, limit, total */
				     "%d,%d,%d,%lld,"
				     /* bytes : in, out */
				     "%lld,%lld,"
				     /* denied: req, resp */
				     "%lld,%lld,"
				     /* errors : request, connect, response */
				     "%lld,,,"
				     /* warnings: retries, redispatches */
				     ",,"
				     /* server status : reflect frontend status */
				     "%s,"
				     /* rest of server: nothing */
				     ",,,,,,,,"
				     /* pid, iid, sid, throttle, lbtot, tracked, type */
				     "%d,%d,0,,,,%d,"
				     /* rate, rate_lim, rate_max */
				     "%u,%u,%u,"
				     /* check_status, check_code, check_duration */
				     ",,,",
				     px->id,
				     px->feconn, px->fe_counters.conn_max, px->maxconn, px->fe_counters.cum_sess,
				     px->fe_counters.bytes_in, px->fe_counters.bytes_out,
				     px->fe_counters.denied_req, px->fe_counters.denied_resp,
				     px->fe_counters.failed_req,
				     px->state == PR_STRUN ? "OPEN" :
				     px->state == PR_STIDLE ? "FULL" : "STOP",
				     relative_pid, px->uuid, STATS_TYPE_FE,
				     read_freq_ctr(&px->fe_sess_per_sec),
				     px->fe_sps_lim, px->fe_counters.sps_max);

				/* http response: 1xx, 2xx, 3xx, 4xx, 5xx, other */
				if (px->mode == PR_MODE_HTTP) {
					int i;

					for (i=1; i<6; i++)
						chunk_printf(&msg, "%lld,", px->fe_counters.p.http.rsp[i]);

					chunk_printf(&msg, "%lld,", px->fe_counters.p.http.rsp[0]);
				} else {
					chunk_printf(&msg, ",,,,,,");
				}

				/* failed health analyses */
				chunk_printf(&msg, ",");

				/* requests : req_rate, req_rate_max, req_tot, */
				chunk_printf(&msg, "%u,%u,%lld,",
					     read_freq_ctr(&px->fe_req_per_sec),
					     px->fe_counters.p.http.rps_max, px->fe_counters.p.http.cum_req);

				/* errors: cli_aborts, srv_aborts */
				chunk_printf(&msg, ",,");

				/* finish with EOL */
				chunk_printf(&msg, "\n");
			}

			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		}

		si->applet.ctx.stats.l = px->listen; /* may be NULL */
		si->applet.ctx.stats.px_st = STAT_PX_ST_LI;
		/* fall through */

	case STAT_PX_ST_LI:
		/* stats.l has been initialized above */
		for (; si->applet.ctx.stats.l != NULL; si->applet.ctx.stats.l = l->next) {
			if (buffer_almost_full(rep))
				return 0;

			l = si->applet.ctx.stats.l;
			if (!l->counters)
				continue;

			if (si->applet.ctx.stats.flags & STAT_BOUND) {
				if (!(si->applet.ctx.stats.type & (1 << STATS_TYPE_SO)))
					break;

				if (si->applet.ctx.stats.sid != -1 && l->luid != si->applet.ctx.stats.sid)
					continue;
			}

			if (!(si->applet.ctx.stats.flags & STAT_FMT_CSV)) {
				chunk_printf(&msg, "<tr class=socket>");
				if (px->cap & PR_CAP_BE && px->srv && (si->applet.ctx.stats.flags & STAT_ADMIN)) {
					 /* Column sub-heading for Enable or Disable server */
					chunk_printf(&msg, "<td></td>");
				}
				chunk_printf(&msg, "<td class=ac");

					if (uri->flags&ST_SHLGNDS) {
						char str[INET6_ADDRSTRLEN], *fmt = NULL;
						int port;

						chunk_printf(&msg, " title=\"IP: ");

						port = (l->addr.ss_family == AF_INET6)
							? ntohs(((struct sockaddr_in6 *)(&l->addr))->sin6_port)
							: ntohs(((struct sockaddr_in *)(&l->addr))->sin_port);

						if (l->addr.ss_family == AF_INET) {
							if (inet_ntop(AF_INET,
							    (const void *)&((struct sockaddr_in *)&l->addr)->sin_addr,
							    str, sizeof(str)))
								fmt = "%s:%d";
						} else {
							if (inet_ntop(AF_INET6,
							    (const void *)&((struct sockaddr_in6 *)(&l->addr))->sin6_addr,
							    str, sizeof(str)))
								fmt = "[%s]:%d";
						}

						if (fmt)
							chunk_printf(&msg, fmt, str, port);
						else
							chunk_printf(&msg, "(%s)", strerror(errno));

						/* id */
						chunk_printf(&msg, ", id: %d", l->luid);

						chunk_printf(&msg, "\"");
					}

				chunk_printf(&msg,
				     /* name, queue */
				     ">%s<a name=\"%s/+%s\"></a>"
				     "<a class=lfsb href=\"#%s/+%s\">%s</a></td><td colspan=3>%s</td>"
				     /* sessions rate: current, max, limit */
				     "<td colspan=3>&nbsp;</td>"
				     /* sessions: current, max, limit, total, lbtot */
				     "<td>%s</td><td>%s</td><td>%s</td>"
				     "<td>%s</td><td>&nbsp;</td>"
				     /* bytes: in, out */
				     "<td>%s</td><td>%s</td>"
				     "",
				     (uri->flags & ST_SHLGNDS)?"<u>":"",
				     px->id, l->name, px->id, l->name, l->name,
				     (uri->flags & ST_SHLGNDS)?"</u>":"",
				     U2H3(l->nbconn), U2H4(l->counters->conn_max), U2H5(l->maxconn),
				     U2H6(l->counters->cum_conn), U2H7(l->counters->bytes_in), U2H8(l->counters->bytes_out));

				chunk_printf(&msg,
				     /* denied: req, resp */
				     "<td>%s</td><td>%s</td>"
				     /* errors: request, connect, response */
				     "<td>%s</td><td></td><td></td>"
				     /* warnings: retries, redispatches */
				     "<td></td><td></td>"
				     /* server status: reflect listener status */
				     "<td class=ac>%s</td>"
				     /* rest of server: nothing */
				     "<td class=ac colspan=8></td></tr>"
				     "",
				     U2H0(l->counters->denied_req), U2H1(l->counters->denied_resp),
				     U2H2(l->counters->failed_req),
				     (l->nbconn < l->maxconn) ? "OPEN" : "FULL");
			} else {
				chunk_printf(&msg,
				     /* pxid, name, queue cur, queue max, */
				     "%s,%s,,,"
				     /* sessions: current, max, limit, total */
				     "%d,%d,%d,%lld,"
				     /* bytes: in, out */
				     "%lld,%lld,"
				     /* denied: req, resp */
				     "%lld,%lld,"
				     /* errors: request, connect, response */
				     "%lld,,,"
				     /* warnings: retries, redispatches */
				     ",,"
				     /* server status: reflect listener status */
				     "%s,"
				     /* rest of server: nothing */
				     ",,,,,,,,"
				     /* pid, iid, sid, throttle, lbtot, tracked, type */
				     "%d,%d,%d,,,,%d,"
				     /* rate, rate_lim, rate_max */
				     ",,,"
				     /* check_status, check_code, check_duration */
				     ",,,"
				     /* http response: 1xx, 2xx, 3xx, 4xx, 5xx, other */
				     ",,,,,,"
				     /* failed health analyses */
				     ","
				     /* requests : req_rate, req_rate_max, req_tot, */
				     ",,,"
				     /* errors: cli_aborts, srv_aborts */
				     ",,"
				     "\n",
				     px->id, l->name,
				     l->nbconn, l->counters->conn_max,
				     l->maxconn, l->counters->cum_conn,
				     l->counters->bytes_in, l->counters->bytes_out,
				     l->counters->denied_req, l->counters->denied_resp,
				     l->counters->failed_req,
				     (l->nbconn < l->maxconn) ? "OPEN" : "FULL",
				     relative_pid, px->uuid, l->luid, STATS_TYPE_SO);
			}

			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		}

		si->applet.ctx.stats.sv = px->srv; /* may be NULL */
		si->applet.ctx.stats.px_st = STAT_PX_ST_SV;
		/* fall through */

	case STAT_PX_ST_SV:
		/* stats.sv has been initialized above */
		for (; si->applet.ctx.stats.sv != NULL; si->applet.ctx.stats.sv = sv->next) {
			int sv_state; /* 0=DOWN, 1=going up, 2=going down, 3=UP, 4,5=NOLB, 6=unchecked */

			if (buffer_almost_full(rep))
				return 0;

			sv = si->applet.ctx.stats.sv;

			if (si->applet.ctx.stats.flags & STAT_BOUND) {
				if (!(si->applet.ctx.stats.type & (1 << STATS_TYPE_SV)))
					break;

				if (si->applet.ctx.stats.sid != -1 && sv->puid != si->applet.ctx.stats.sid)
					continue;
			}

			if (sv->tracked)
				svs = sv->tracked;
			else
				svs = sv;

			/* FIXME: produce some small strings for "UP/DOWN x/y &#xxxx;" */
			if (!(svs->state & SRV_CHECKED))
				sv_state = 6;
			else if (svs->state & SRV_RUNNING) {
				if (svs->health == svs->rise + svs->fall - 1)
					sv_state = 3; /* UP */
				else
					sv_state = 2; /* going down */

				if (svs->state & SRV_GOINGDOWN)
					sv_state += 2;
			}
			else
				if (svs->health)
					sv_state = 1; /* going up */
				else
					sv_state = 0; /* DOWN */

			if (((sv_state == 0) || (sv->state & SRV_MAINTAIN)) && (si->applet.ctx.stats.flags & STAT_HIDE_DOWN)) {
				/* do not report servers which are DOWN */
				si->applet.ctx.stats.sv = sv->next;
				continue;
			}

			if (!(si->applet.ctx.stats.flags & STAT_FMT_CSV)) {
				static char *srv_hlt_st[7] = { "DOWN", "DN %d/%d &uarr;",
							       "UP %d/%d &darr;", "UP",
							       "NOLB %d/%d &darr;", "NOLB",
							       "<i>no check</i>" };
				if ((sv->state & SRV_MAINTAIN) || (svs->state & SRV_MAINTAIN)) {
					chunk_printf(&msg,
					    /* name */
					    "<tr class=\"maintain\">"
					);
				}
				else {
					chunk_printf(&msg,
					    /* name */
					    "<tr class=\"%s%d\">",
					    (sv->state & SRV_BACKUP) ? "backup" : "active", sv_state);
				}

				if (px->cap & PR_CAP_BE && px->srv && (si->applet.ctx.stats.flags & STAT_ADMIN)) {
					chunk_printf(&msg,
						"<td><input type=\"checkbox\" name=\"s\" value=\"%s\"></td>",
						sv->id);
				}

				chunk_printf(&msg, "<td class=ac");

				if (uri->flags&ST_SHLGNDS) {
					char str[INET6_ADDRSTRLEN];

					chunk_printf(&msg, " title=\"IP: ");

					/* IP */
					switch (sv->addr.ss_family) {
					case AF_INET:
						if (inet_ntop(AF_INET, (const void *)&((struct sockaddr_in *)&sv->addr)->sin_addr, str, sizeof(str)))
							chunk_printf(&msg, "%s:%d", str, htons(((struct sockaddr_in *)&sv->addr)->sin_port));
						else
							chunk_printf(&msg, "(%s)", strerror(errno));
						break;
					case AF_INET6:
						if (inet_ntop(AF_INET6, (const void *)&((struct sockaddr_in6 *)&sv->addr)->sin6_addr, str, sizeof(str)))
							chunk_printf(&msg, "%s:%d", str, htons(((struct sockaddr_in6 *)&sv->addr)->sin6_port));
						else
							chunk_printf(&msg, "(%s)", strerror(errno));
						break;
					}

					/* id */
					chunk_printf(&msg, ", id: %d", sv->puid);

					/* cookie */
					if (sv->cookie) {
						struct chunk src;

						chunk_printf(&msg, ", cookie: '");

						chunk_initlen(&src, sv->cookie, 0, strlen(sv->cookie));
						chunk_htmlencode(&msg, &src);

						chunk_printf(&msg, "'");
					}

					chunk_printf(&msg, "\"");
				}

				chunk_printf(&msg,
				     ">%s<a name=\"%s/%s\"></a>"
				     "<a class=lfsb href=\"#%s/%s\">%s</a>%s</td>"
				     /* queue : current, max, limit */
				     "<td>%s</td><td>%s</td><td>%s</td>"
				     /* sessions rate : current, max, limit */
				     "<td>%s</td><td>%s</td><td></td>"
				     /* sessions: current, max, limit */
				     "<td>%s</td><td>%s</td><td>%s</td>"
				     "<td"
				     "",
				     (uri->flags & ST_SHLGNDS)?"<u>":"",
				     px->id, sv->id, px->id, sv->id, sv->id,
				     (uri->flags & ST_SHLGNDS)?"</u>":"",
				     U2H0(sv->nbpend), U2H1(sv->counters.nbpend_max), LIM2A2(sv->maxqueue, "-"),
				     U2H3(read_freq_ctr(&sv->sess_per_sec)), U2H4(sv->counters.sps_max),
				     U2H5(sv->cur_sess), U2H6(sv->counters.cur_sess_max), LIM2A7(sv->maxconn, "-"));

				/* http response (via td title): 1xx, 2xx, 3xx, 4xx, 5xx, other */
				if (px->mode == PR_MODE_HTTP) {
					int i;

					chunk_printf(&msg, " title=\"rsp codes:");

					for (i = 1; i < 6; i++)
						chunk_printf(&msg, " %dxx=%lld,", i, sv->counters.p.http.rsp[i]);

					chunk_printf(&msg, " other=%lld\"", sv->counters.p.http.rsp[0]);
				}

				chunk_printf(&msg,
				     /* sessions: total, lbtot */
				     ">%s%s%s</td><td>%s</td>",
				     (px->mode == PR_MODE_HTTP)?"<u>":"",
				     U2H0(sv->counters.cum_sess),
				     (px->mode == PR_MODE_HTTP)?"</u>":"",
				     U2H1(sv->counters.cum_lbconn));

				chunk_printf(&msg,
				     /* bytes : in, out */
				     "<td>%s</td><td>%s</td>"
				     /* denied: req, resp */
				     "<td></td><td>%s</td>"
				     /* errors : request, connect */
				     "<td></td><td>%s</td>"
				     /* errors : response */
				     "<td title=\"Connection resets during transfers: %lld client, %lld server\"><u>%s</u></td>"
				     /* warnings: retries, redispatches */
				     "<td>%lld</td><td>%lld</td>"
				     "",
				     U2H0(sv->counters.bytes_in), U2H1(sv->counters.bytes_out),
				     U2H2(sv->counters.failed_secu),
				     U2H3(sv->counters.failed_conns),
				     sv->counters.cli_aborts,
				     sv->counters.srv_aborts,
				     U2H6(sv->counters.failed_resp),
				     sv->counters.retries, sv->counters.redispatches);

				/* status, lest check */
				chunk_printf(&msg, "<td class=ac>");

				if (sv->state & SRV_MAINTAIN) {
					chunk_printf(&msg, "%s ",
						human_time(now.tv_sec - sv->last_change, 1));
					chunk_printf(&msg, "MAINT");
				}
				else if (svs != sv && svs->state & SRV_MAINTAIN) {
					chunk_printf(&msg, "%s ",
						human_time(now.tv_sec - svs->last_change, 1));
					chunk_printf(&msg, "MAINT(via)");
				}
				else if (svs->state & SRV_CHECKED) {
					chunk_printf(&msg, "%s ",
						human_time(now.tv_sec - svs->last_change, 1));

					chunk_printf(&msg,
					     srv_hlt_st[sv_state],
					     (svs->state & SRV_RUNNING) ? (svs->health - svs->rise + 1) : (svs->health),
					     (svs->state & SRV_RUNNING) ? (svs->fall) : (svs->rise));
				}

				if (sv->state & SRV_CHECKED) {
					chunk_printf(&msg, "</td><td class=ac title=\"%s",
						get_check_status_description(sv->check_status));

					if (*sv->check_desc) {
						struct chunk src;

						chunk_printf(&msg, ": ");

						chunk_initlen(&src, sv->check_desc, 0, strlen(sv->check_desc));
						chunk_htmlencode(&msg, &src);
					}

					chunk_printf(&msg, "\"><u> %s%s",
						tv_iszero(&sv->check_start)?"":"* ",
						get_check_status_info(sv->check_status));

					if (sv->check_status >= HCHK_STATUS_L57DATA)
						chunk_printf(&msg, "/%d", sv->check_code);

					if (sv->check_status >= HCHK_STATUS_CHECKED && sv->check_duration >= 0)
					chunk_printf(&msg, " in %lums</u>", sv->check_duration);
				} else
					chunk_printf(&msg, "</td><td>");

				chunk_printf(&msg,
				     /* weight */
				     "</td><td class=ac>%d</td>"
				     /* act, bck */
				     "<td class=ac>%s</td><td class=ac>%s</td>"
				     "",
				     (sv->eweight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv,
				     (sv->state & SRV_BACKUP) ? "-" : "Y",
				     (sv->state & SRV_BACKUP) ? "Y" : "-");

				/* check failures: unique, fatal, down time */
				if (sv->state & SRV_CHECKED) {
					chunk_printf(&msg, "<td title=\"Failed Health Checks%s\"><u>%lld",
					     svs->observe?"/Health Analyses":"", svs->counters.failed_checks);

					if (svs->observe)
						chunk_printf(&msg, "/%lld", svs->counters.failed_hana);

					chunk_printf(&msg,
					     "</u></td>"
					     "<td>%lld</td><td>%s</td>"
					     "",
					     svs->counters.down_trans, human_time(srv_downtime(sv), 1));
				} else if (sv != svs)
					chunk_printf(&msg,
					     "<td class=ac colspan=3><a class=lfsb href=\"#%s/%s\">via %s/%s<a></td>",
							svs->proxy->id, svs->id, svs->proxy->id, svs->id);
				else
					chunk_printf(&msg,
					     "<td colspan=3></td>");

				/* throttle */
				if ((sv->state & SRV_WARMINGUP) &&
				    now.tv_sec < sv->last_change + sv->slowstart &&
				    now.tv_sec >= sv->last_change) {
					unsigned int ratio;
					ratio = MAX(1, 100 * (now.tv_sec - sv->last_change) / sv->slowstart);
					chunk_printf(&msg,
						     "<td class=ac>%d %%</td></tr>\n", ratio);
				} else {
					chunk_printf(&msg,
						     "<td class=ac>-</td></tr>\n");
				}
			} else {
				static char *srv_hlt_st[7] = { "DOWN,", "DOWN %d/%d,",
							       "UP %d/%d,", "UP,",
							       "NOLB %d/%d,", "NOLB,",
							       "no check," };
				chunk_printf(&msg,
				     /* pxid, name */
				     "%s,%s,"
				     /* queue : current, max */
				     "%d,%d,"
				     /* sessions : current, max, limit, total */
				     "%d,%d,%s,%lld,"
				     /* bytes : in, out */
				     "%lld,%lld,"
				     /* denied: req, resp */
				     ",%lld,"
				     /* errors : request, connect, response */
				     ",%lld,%lld,"
				     /* warnings: retries, redispatches */
				     "%lld,%lld,"
				     "",
				     px->id, sv->id,
				     sv->nbpend, sv->counters.nbpend_max,
				     sv->cur_sess, sv->counters.cur_sess_max, LIM2A0(sv->maxconn, ""), sv->counters.cum_sess,
				     sv->counters.bytes_in, sv->counters.bytes_out,
				     sv->counters.failed_secu,
				     sv->counters.failed_conns, sv->counters.failed_resp,
				     sv->counters.retries, sv->counters.redispatches);

				/* status */
				if (sv->state & SRV_MAINTAIN) {
					chunk_printf(&msg, "MAINT,");
				}
				else if (svs != sv && svs->state & SRV_MAINTAIN) {
					chunk_printf(&msg, "MAINT(via),");
				}
				else {
					chunk_printf(&msg,
					    srv_hlt_st[sv_state],
					    (svs->state & SRV_RUNNING) ? (svs->health - svs->rise + 1) : (svs->health),
					    (svs->state & SRV_RUNNING) ? (svs->fall) : (svs->rise));
				}

				chunk_printf(&msg,
				     /* weight, active, backup */
				     "%d,%d,%d,"
				     "",
				     (sv->eweight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv,
				     (sv->state & SRV_BACKUP) ? 0 : 1,
				     (sv->state & SRV_BACKUP) ? 1 : 0);

				/* check failures: unique, fatal; last change, total downtime */
				if (sv->state & SRV_CHECKED)
					chunk_printf(&msg,
					     "%lld,%lld,%d,%d,",
					     sv->counters.failed_checks, sv->counters.down_trans,
					     (int)(now.tv_sec - sv->last_change), srv_downtime(sv));
				else
					chunk_printf(&msg,
					     ",,,,");

				/* queue limit, pid, iid, sid, */
				chunk_printf(&msg,
				     "%s,"
				     "%d,%d,%d,",
				     LIM2A0(sv->maxqueue, ""),
				     relative_pid, px->uuid, sv->puid);

				/* throttle */
				if ((sv->state & SRV_WARMINGUP) &&
				    now.tv_sec < sv->last_change + sv->slowstart &&
				    now.tv_sec >= sv->last_change) {
					unsigned int ratio;
					ratio = MAX(1, 100 * (now.tv_sec - sv->last_change) / sv->slowstart);
					chunk_printf(&msg, "%d", ratio);
				}

				/* sessions: lbtot */
				chunk_printf(&msg, ",%lld,", sv->counters.cum_lbconn);

				/* tracked */
				if (sv->tracked)
					chunk_printf(&msg, "%s/%s,",
						sv->tracked->proxy->id, sv->tracked->id);
				else
					chunk_printf(&msg, ",");

				/* type */
				chunk_printf(&msg, "%d,", STATS_TYPE_SV);

				/* rate */
				chunk_printf(&msg, "%u,,%u,",
					     read_freq_ctr(&sv->sess_per_sec),
					     sv->counters.sps_max);

				if (sv->state & SRV_CHECKED) {
					/* check_status */
					chunk_printf(&msg, "%s,", get_check_status_info(sv->check_status));

					/* check_code */
					if (sv->check_status >= HCHK_STATUS_L57DATA)
						chunk_printf(&msg, "%u,", sv->check_code);
					else
						chunk_printf(&msg, ",");

					/* check_duration */
					if (sv->check_status >= HCHK_STATUS_CHECKED)
						chunk_printf(&msg, "%lu,", sv->check_duration);
					else
						chunk_printf(&msg, ",");

				} else {
					chunk_printf(&msg, ",,,");
				}

				/* http response: 1xx, 2xx, 3xx, 4xx, 5xx, other */
				if (px->mode == PR_MODE_HTTP) {
					int i;

					for (i=1; i<6; i++)
						chunk_printf(&msg, "%lld,", sv->counters.p.http.rsp[i]);

					chunk_printf(&msg, "%lld,", sv->counters.p.http.rsp[0]);
				} else {
					chunk_printf(&msg, ",,,,,,");
				}

				/* failed health analyses */
				chunk_printf(&msg, "%lld,",  sv->counters.failed_hana);

				/* requests : req_rate, req_rate_max, req_tot, */
				chunk_printf(&msg, ",,,");

				/* errors: cli_aborts, srv_aborts */
				chunk_printf(&msg, "%lld,%lld,",
					     sv->counters.cli_aborts, sv->counters.srv_aborts);

				/* finish with EOL */
				chunk_printf(&msg, "\n");
			}
			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		} /* for sv */

		si->applet.ctx.stats.px_st = STAT_PX_ST_BE;
		/* fall through */

	case STAT_PX_ST_BE:
		/* print the backend */
		if ((px->cap & PR_CAP_BE) &&
		    (!(si->applet.ctx.stats.flags & STAT_BOUND) || (si->applet.ctx.stats.type & (1 << STATS_TYPE_BE)))) {
			if (!(si->applet.ctx.stats.flags & STAT_FMT_CSV)) {
				chunk_printf(&msg, "<tr class=\"backend\">");
				if (px->cap & PR_CAP_BE && px->srv && (si->applet.ctx.stats.flags & STAT_ADMIN)) {
					/* Column sub-heading for Enable or Disable server */
					chunk_printf(&msg, "<td></td>");
				}
				chunk_printf(&msg, "<td class=ac");

				if (uri->flags&ST_SHLGNDS) {
					/* balancing */
					 chunk_printf(&msg, " title=\"balancing: %s",
						 backend_lb_algo_str(px->lbprm.algo & BE_LB_ALGO));

					/* cookie */
					if (px->cookie_name) {
						struct chunk src;

						chunk_printf(&msg, ", cookie: '");

						chunk_initlen(&src, px->cookie_name, 0, strlen(px->cookie_name));
						chunk_htmlencode(&msg, &src);

						chunk_printf(&msg, "'");
					}

					chunk_printf(&msg, "\"");

				}

				chunk_printf(&msg,
				     /* name */
				     ">%s<a name=\"%s/Backend\"></a>"
				     "<a class=lfsb href=\"#%s/Backend\">Backend</a>%s</td>"
				     /* queue : current, max */
				     "<td>%s</td><td>%s</td><td></td>"
				     /* sessions rate : current, max, limit */
				     "<td>%s</td><td>%s</td><td></td>"
				     "",
				     (uri->flags & ST_SHLGNDS)?"<u>":"",
				     px->id, px->id,
				     (uri->flags & ST_SHLGNDS)?"</u>":"",
				     U2H0(px->nbpend) /* or px->totpend ? */, U2H1(px->be_counters.nbpend_max),
				     U2H2(read_freq_ctr(&px->be_sess_per_sec)), U2H3(px->be_counters.sps_max));

				chunk_printf(&msg,
				     /* sessions: current, max, limit */
				     "<td>%s</td><td>%s</td><td>%s</td>"
				     "<td"
				     "",
				     U2H2(px->beconn), U2H3(px->be_counters.conn_max), U2H4(px->fullconn));

				/* http response (via td title): 1xx, 2xx, 3xx, 4xx, 5xx, other */
				if (px->mode == PR_MODE_HTTP) {
					int i;

					chunk_printf(&msg, " title=\"rsp codes:");

					for (i = 1; i < 6; i++)
						chunk_printf(&msg, " %dxx=%lld", i, px->be_counters.p.http.rsp[i]);

					chunk_printf(&msg, " other=%lld\"", px->be_counters.p.http.rsp[0]);
				}

				chunk_printf(&msg,
				     /* sessions: total, lbtot */
				     ">%s%s%s</td><td>%s</td>"
				     /* bytes: in, out */
				     "<td>%s</td><td>%s</td>"
				     "",
				     (px->mode == PR_MODE_HTTP)?"<u>":"",
				     U2H6(px->be_counters.cum_conn),
				     (px->mode == PR_MODE_HTTP)?"</u>":"",
				     U2H7(px->be_counters.cum_lbconn),
				     U2H8(px->be_counters.bytes_in), U2H9(px->be_counters.bytes_out));

				chunk_printf(&msg,
				     /* denied: req, resp */
				     "<td>%s</td><td>%s</td>"
				     /* errors : request, connect */
				     "<td></td><td>%s</td>"
				     /* errors : response */
				     "<td title=\"Connection resets during transfers: %lld client, %lld server\"><u>%s</u></td>"
				     /* warnings: retries, redispatches */
				     "<td>%lld</td><td>%lld</td>"
				     /* backend status: reflect backend status (up/down): we display UP
				      * if the backend has known working servers or if it has no server at
				      * all (eg: for stats). Then we display the total weight, number of
				      * active and backups. */
				     "<td class=ac>%s %s</td><td class=ac>&nbsp;</td><td class=ac>%d</td>"
				     "<td class=ac>%d</td><td class=ac>%d</td>"
				     "",
				     U2H0(px->be_counters.denied_req), U2H1(px->be_counters.denied_resp),
				     U2H2(px->be_counters.failed_conns),
				     px->be_counters.cli_aborts,
				     px->be_counters.srv_aborts,
				     U2H5(px->be_counters.failed_resp),
				     px->be_counters.retries, px->be_counters.redispatches,
				     human_time(now.tv_sec - px->last_change, 1),
				     (px->lbprm.tot_weight > 0 || !px->srv) ? "UP" :
					     "<font color=\"red\"><b>DOWN</b></font>",
				     (px->lbprm.tot_weight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv,
				     px->srv_act, px->srv_bck);

				chunk_printf(&msg,
				     /* rest of backend: nothing, down transitions, total downtime, throttle */
				     "<td class=ac>&nbsp;</td><td>%d</td>"
				     "<td>%s</td>"
				     "<td></td>"
				     "</tr>",
				     px->down_trans,
				     px->srv?human_time(be_downtime(px), 1):"&nbsp;");
			} else {
				chunk_printf(&msg,
				     /* pxid, name */
				     "%s,BACKEND,"
				     /* queue : current, max */
				     "%d,%d,"
				     /* sessions : current, max, limit, total */
				     "%d,%d,%d,%lld,"
				     /* bytes : in, out */
				     "%lld,%lld,"
				     /* denied: req, resp */
				     "%lld,%lld,"
				     /* errors : request, connect, response */
				     ",%lld,%lld,"
				     /* warnings: retries, redispatches */
				     "%lld,%lld,"
				     /* backend status: reflect backend status (up/down): we display UP
				      * if the backend has known working servers or if it has no server at
				      * all (eg: for stats). Then we display the total weight, number of
				      * active and backups. */
				     "%s,"
				     "%d,%d,%d,"
				     /* rest of backend: nothing, down transitions, last change, total downtime */
				     ",%d,%d,%d,,"
				     /* pid, iid, sid, throttle, lbtot, tracked, type */
				     "%d,%d,0,,%lld,,%d,"
				     /* rate, rate_lim, rate_max, */
				     "%u,,%u,"
				     /* check_status, check_code, check_duration */
				     ",,,",
				     px->id,
				     px->nbpend /* or px->totpend ? */, px->be_counters.nbpend_max,
				     px->beconn, px->be_counters.conn_max, px->fullconn, px->be_counters.cum_conn,
				     px->be_counters.bytes_in, px->be_counters.bytes_out,
				     px->be_counters.denied_req, px->be_counters.denied_resp,
				     px->be_counters.failed_conns, px->be_counters.failed_resp,
				     px->be_counters.retries, px->be_counters.redispatches,
				     (px->lbprm.tot_weight > 0 || !px->srv) ? "UP" : "DOWN",
				     (px->lbprm.tot_weight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv,
				     px->srv_act, px->srv_bck,
				     px->down_trans, (int)(now.tv_sec - px->last_change),
				     px->srv?be_downtime(px):0,
				     relative_pid, px->uuid,
				     px->be_counters.cum_lbconn, STATS_TYPE_BE,
				     read_freq_ctr(&px->be_sess_per_sec),
				     px->be_counters.sps_max);

				/* http response: 1xx, 2xx, 3xx, 4xx, 5xx, other */
				if (px->mode == PR_MODE_HTTP) {
					int i;

					for (i=1; i<6; i++)
						chunk_printf(&msg, "%lld,", px->be_counters.p.http.rsp[i]);

					chunk_printf(&msg, "%lld,", px->be_counters.p.http.rsp[0]);
				} else {
					chunk_printf(&msg, ",,,,,,");
				}

				/* failed health analyses */
				chunk_printf(&msg, ",");

				/* requests : req_rate, req_rate_max, req_tot, */
				chunk_printf(&msg, ",,,");

				/* errors: cli_aborts, srv_aborts */
				chunk_printf(&msg, "%lld,%lld,",
					     px->be_counters.cli_aborts, px->be_counters.srv_aborts);

				/* finish with EOL */
				chunk_printf(&msg, "\n");

			}
			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		}

		si->applet.ctx.stats.px_st = STAT_PX_ST_END;
		/* fall through */

	case STAT_PX_ST_END:
		if (!(si->applet.ctx.stats.flags & STAT_FMT_CSV)) {
			chunk_printf(&msg, "</table>");

			if (px->cap & PR_CAP_BE && px->srv && (si->applet.ctx.stats.flags & STAT_ADMIN)) {
				/* close the form used to enable/disable this proxy servers */
				chunk_printf(&msg,
					"Choose the action to perform on the checked servers : "
					"<select name=action>"
					"<option value=\"\"></option>"
					"<option value=\"disable\">Disable</option>"
					"<option value=\"enable\">Enable</option>"
					"</select>"
					"<input type=\"hidden\" name=\"b\" value=\"%s\">"
					"&nbsp;<input type=\"submit\" value=\"Apply\">"
					"</form>",
					px->id);
			}

			chunk_printf(&msg, "<p>\n");

			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		}

		si->applet.ctx.stats.px_st = STAT_PX_ST_FIN;
		/* fall through */

	case STAT_PX_ST_FIN:
		return 1;

	default:
		/* unknown state, we should put an abort() here ! */
		return 1;
	}
}

/* This function dumps a complete session state onto the stream intreface's
 * read buffer. The data_ctx must have been zeroed first, and the flags
 * properly set. The session has to be set in data_ctx.sess.target. It returns
 * 0 if the output buffer is full and it needs to be called again, otherwise
 * non-zero. It is designed to be called from stats_dump_sess_to_buffer() below.
 */
static int stats_dump_full_sess_to_buffer(struct stream_interface *si)
{
	struct tm tm;
	struct chunk msg;
	struct session *sess;
	extern const char *monthname[12];
	char pn[INET6_ADDRSTRLEN];

	chunk_init(&msg, trash, sizeof(trash));
	sess = si->applet.ctx.sess.target;

	if (si->applet.ctx.sess.section > 0 && si->applet.ctx.sess.uid != sess->uniq_id) {
		/* session changed, no need to go any further */
		chunk_printf(&msg, "  *** session terminated while we were watching it ***\n");
		if (buffer_feed_chunk(si->ib, &msg) >= 0)
			return 0;
		si->applet.ctx.sess.target = NULL;
		si->applet.ctx.sess.uid = 0;
		return 1;
	}

	switch (si->applet.ctx.sess.section) {
	case 0: /* main status of the session */
		si->applet.ctx.sess.uid = sess->uniq_id;
		si->applet.ctx.sess.section = 1;
		/* fall through */

	case 1:
		chunk_printf(&msg,
			     "%p: id=%u, proto=%s",
			     sess,
			     sess->uniq_id,
			     sess->listener->proto->name);

		switch (sess->listener->proto->sock_family) {
		case AF_INET:
			inet_ntop(AF_INET,
				  (const void *)&((struct sockaddr_in *)&sess->si[0].addr.c.from)->sin_addr,
				  pn, sizeof(pn));

			chunk_printf(&msg,
				     " source=%s:%d\n",
				     pn,
				     ntohs(((struct sockaddr_in *)&sess->si[0].addr.c.from)->sin_port));
			break;
		case AF_INET6:
			inet_ntop(AF_INET6,
				  (const void *)&((struct sockaddr_in6 *)(&sess->si[0].addr.c.from))->sin6_addr,
				  pn, sizeof(pn));

			chunk_printf(&msg,
				     " source=%s:%d\n",
				     pn,
				     ntohs(((struct sockaddr_in6 *)&sess->si[0].addr.c.from)->sin6_port));
			break;
		case AF_UNIX:
			chunk_printf(&msg,
				     " source=unix:%d\n", sess->listener->luid);
			break;
		default:
			/* no more information to print right now */
			chunk_printf(&msg, "\n");
			break;
		}

		chunk_printf(&msg,
			     "  flags=0x%x, conn_retries=%d, srv_conn=%p, pend_pos=%p\n",
			     sess->flags, sess->si[1].conn_retries, sess->srv_conn, sess->pend_pos);

		chunk_printf(&msg,
			     "  frontend=%s (id=%u mode=%s), listener=%s (id=%u)\n",
			     sess->fe->id, sess->fe->uuid, sess->fe->mode ? "http" : "tcp",
			     sess->listener ? sess->listener->name ? sess->listener->name : "?" : "?",
			     sess->listener ? sess->listener->luid : 0);

		chunk_printf(&msg,
			     "  backend=%s (id=%u mode=%s) server=%s (id=%u)\n",
			     sess->be->id, sess->be->uuid, sess->be->mode ? "http" : "tcp",
			     target_srv(&sess->target) ? target_srv(&sess->target)->id : "<none>",
			     target_srv(&sess->target) ? target_srv(&sess->target)->puid : 0);

		chunk_printf(&msg,
			     "  task=%p (state=0x%02x nice=%d calls=%d exp=%s%s)\n",
			     sess->task,
			     sess->task->state,
			     sess->task->nice, sess->task->calls,
			     sess->task->expire ?
			             tick_is_expired(sess->task->expire, now_ms) ? "<PAST>" :
			                     human_time(TICKS_TO_MS(sess->task->expire - now_ms),
			                     TICKS_TO_MS(1000)) : "<NEVER>",
			     task_in_rq(sess->task) ? ", running" : "");

		get_localtime(sess->logs.accept_date.tv_sec, &tm);
		chunk_printf(&msg,
			     "  task created [%02d/%s/%04d:%02d:%02d:%02d.%06d] (age=%s)\n",
			     tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
			     tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(sess->logs.accept_date.tv_usec),
			     human_time(now.tv_sec - sess->logs.accept_date.tv_sec, 1));

		chunk_printf(&msg,
			     "  si[0]=%p (state=%d flags=0x%02x fd=%d exp=%s, et=0x%03x)\n",
			     &sess->si[0],
			     sess->si[0].state,
			     sess->si[0].flags,
			     sess->si[0].fd,
			     sess->si[0].exp ?
			             tick_is_expired(sess->si[0].exp, now_ms) ? "<PAST>" :
			                     human_time(TICKS_TO_MS(sess->si[0].exp - now_ms),
			                     TICKS_TO_MS(1000)) : "<NEVER>",
			     sess->si[0].err_type);

		chunk_printf(&msg,
			     "  si[1]=%p (state=%d flags=0x%02x fd=%d exp=%s, et=0x%03x)\n",
			     &sess->si[1],
			     sess->si[1].state,
			     sess->si[1].flags,
			     sess->si[1].fd,
			     sess->si[1].exp ?
			             tick_is_expired(sess->si[1].exp, now_ms) ? "<PAST>" :
			                     human_time(TICKS_TO_MS(sess->si[1].exp - now_ms),
			                     TICKS_TO_MS(1000)) : "<NEVER>",
			     sess->si[1].err_type);

		chunk_printf(&msg,
			     "  txn=%p (flags=0x%x meth=%d status=%d req.st=%d rsp.st=%d)\n",
			     &sess->txn, sess->txn.flags, sess->txn.meth, sess->txn.status,
			     sess->txn.req.msg_state, sess->txn.rsp.msg_state);


		chunk_printf(&msg,
			     "  req=%p (f=0x%06x an=0x%x l=%d sndmx=%d pipe=%d fwd=%d)\n"
			     "      an_exp=%s",
			     sess->req,
			     sess->req->flags, sess->req->analysers,
			     sess->req->l, sess->req->send_max,
			     sess->req->pipe ? sess->req->pipe->data : 0,
			     sess->req->to_forward,
			     sess->req->analyse_exp ?
			     human_time(TICKS_TO_MS(sess->req->analyse_exp - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>");

		chunk_printf(&msg,
			     " rex=%s",
			     sess->req->rex ?
			     human_time(TICKS_TO_MS(sess->req->rex - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>");

		chunk_printf(&msg,
			     " wex=%s\n"
			     "      data=%p r=%d w=%d lr=%d total=%lld\n",
			     sess->req->wex ?
			     human_time(TICKS_TO_MS(sess->req->wex - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>",
			     sess->req->data,
			     (int)(sess->req->r - sess->req->data),
			     (int)(sess->req->w - sess->req->data),
			     (int)(sess->req->lr - sess->req->data),
			     sess->req->total);

		chunk_printf(&msg,
			     "  res=%p (f=0x%06x an=0x%x l=%d sndmx=%d pipe=%d fwd=%d)\n"
			     "      an_exp=%s",
			     sess->rep,
			     sess->rep->flags, sess->rep->analysers,
			     sess->rep->l, sess->rep->send_max,
			     sess->rep->pipe ? sess->rep->pipe->data : 0,
			     sess->rep->to_forward,
			     sess->rep->analyse_exp ?
			     human_time(TICKS_TO_MS(sess->rep->analyse_exp - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>");

		chunk_printf(&msg,
			     " rex=%s",
			     sess->rep->rex ?
			     human_time(TICKS_TO_MS(sess->rep->rex - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>");

		chunk_printf(&msg,
			     " wex=%s\n"
			     "      data=%p r=%d w=%d lr=%d total=%lld\n",
			     sess->rep->wex ?
			     human_time(TICKS_TO_MS(sess->rep->wex - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>",
			     sess->rep->data,
			     (int)(sess->rep->r - sess->rep->data),
			     (int)(sess->rep->w - sess->rep->data),
			     (int)(sess->rep->lr - sess->rep->data),
			     sess->rep->total);

		if (buffer_feed_chunk(si->ib, &msg) >= 0)
			return 0;

		/* use other states to dump the contents */
	}
	/* end of dump */
	si->applet.ctx.sess.uid = 0;
	return 1;
}

/* This function dumps all sessions' states onto the stream intreface's
 * read buffer. The data_ctx must have been zeroed first, and the flags
 * properly set. It returns 0 if the output buffer is full and it needs
 * to be called again, otherwise non-zero. It is designed to be called
 * from stats_dump_sess_to_buffer() below.
 */
static int stats_dump_sess_to_buffer(struct stream_interface *si)
{
	struct chunk msg;

	if (unlikely(si->ib->flags & (BF_WRITE_ERROR|BF_SHUTW))) {
		/* If we're forced to shut down, we might have to remove our
		 * reference to the last session being dumped.
		 */
		if (si->applet.state == STAT_ST_LIST) {
			if (!LIST_ISEMPTY(&si->applet.ctx.sess.bref.users)) {
				LIST_DEL(&si->applet.ctx.sess.bref.users);
				LIST_INIT(&si->applet.ctx.sess.bref.users);
			}
		}
		return 1;
	}

	chunk_init(&msg, trash, sizeof(trash));

	switch (si->applet.state) {
	case STAT_ST_INIT:
		/* the function had not been called yet, let's prepare the
		 * buffer for a response. We initialize the current session
		 * pointer to the first in the global list. When a target
		 * session is being destroyed, it is responsible for updating
		 * this pointer. We know we have reached the end when this
		 * pointer points back to the head of the sessions list.
		 */
		LIST_INIT(&si->applet.ctx.sess.bref.users);
		si->applet.ctx.sess.bref.ref = sessions.n;
		si->applet.state = STAT_ST_LIST;
		/* fall through */

	case STAT_ST_LIST:
		/* first, let's detach the back-ref from a possible previous session */
		if (!LIST_ISEMPTY(&si->applet.ctx.sess.bref.users)) {
			LIST_DEL(&si->applet.ctx.sess.bref.users);
			LIST_INIT(&si->applet.ctx.sess.bref.users);
		}

		/* and start from where we stopped */
		while (si->applet.ctx.sess.bref.ref != &sessions) {
			char pn[INET6_ADDRSTRLEN];
			struct session *curr_sess;

			curr_sess = LIST_ELEM(si->applet.ctx.sess.bref.ref, struct session *, list);

			if (si->applet.ctx.sess.target) {
				if (si->applet.ctx.sess.target != curr_sess)
					goto next_sess;

				LIST_ADDQ(&curr_sess->back_refs, &si->applet.ctx.sess.bref.users);
				/* call the proper dump() function and return if we're missing space */
				if (!stats_dump_full_sess_to_buffer(si))
					return 0;

				/* session dump complete */
				LIST_DEL(&si->applet.ctx.sess.bref.users);
				LIST_INIT(&si->applet.ctx.sess.bref.users);
				si->applet.ctx.sess.target = NULL;
				break;
			}

			chunk_printf(&msg,
				     "%p: proto=%s",
				     curr_sess,
				     curr_sess->listener->proto->name);

			switch (curr_sess->listener->proto->sock_family) {
			case AF_INET:
				inet_ntop(AF_INET,
					  (const void *)&((struct sockaddr_in *)&curr_sess->si[0].addr.c.from)->sin_addr,
					  pn, sizeof(pn));

				chunk_printf(&msg,
					     " src=%s:%d fe=%s be=%s srv=%s",
					     pn,
					     ntohs(((struct sockaddr_in *)&curr_sess->si[0].addr.c.from)->sin_port),
					     curr_sess->fe->id,
					     curr_sess->be->id,
					     target_srv(&curr_sess->target) ? target_srv(&curr_sess->target)->id : "<none>"
					     );
				break;
			case AF_INET6:
				inet_ntop(AF_INET6,
					  (const void *)&((struct sockaddr_in6 *)(&curr_sess->si[0].addr.c.from))->sin6_addr,
					  pn, sizeof(pn));

				chunk_printf(&msg,
					     " src=%s:%d fe=%s be=%s srv=%s",
					     pn,
					     ntohs(((struct sockaddr_in6 *)&curr_sess->si[0].addr.c.from)->sin6_port),
					     curr_sess->fe->id,
					     curr_sess->be->id,
					     target_srv(&curr_sess->target) ? target_srv(&curr_sess->target)->id : "<none>"
					     );

				break;
			case AF_UNIX:
				chunk_printf(&msg,
					     " src=unix:%d fe=%s be=%s srv=%s",
					     curr_sess->listener->luid,
					     curr_sess->fe->id,
					     curr_sess->be->id,
					     target_srv(&curr_sess->target) ? target_srv(&curr_sess->target)->id : "<none>"
					     );
				break;
			}

			chunk_printf(&msg,
				     " ts=%02x age=%s calls=%d",
				     curr_sess->task->state,
				     human_time(now.tv_sec - curr_sess->logs.tv_accept.tv_sec, 1),
				     curr_sess->task->calls);

			chunk_printf(&msg,
				     " rq[f=%06xh,l=%d,an=%02xh,rx=%s",
				     curr_sess->req->flags,
				     curr_sess->req->l,
				     curr_sess->req->analysers,
				     curr_sess->req->rex ?
				     human_time(TICKS_TO_MS(curr_sess->req->rex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg,
				     ",wx=%s",
				     curr_sess->req->wex ?
				     human_time(TICKS_TO_MS(curr_sess->req->wex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg,
				     ",ax=%s]",
				     curr_sess->req->analyse_exp ?
				     human_time(TICKS_TO_MS(curr_sess->req->analyse_exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg,
				     " rp[f=%06xh,l=%d,an=%02xh,rx=%s",
				     curr_sess->rep->flags,
				     curr_sess->rep->l,
				     curr_sess->rep->analysers,
				     curr_sess->rep->rex ?
				     human_time(TICKS_TO_MS(curr_sess->rep->rex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg,
				     ",wx=%s",
				     curr_sess->rep->wex ?
				     human_time(TICKS_TO_MS(curr_sess->rep->wex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg,
				     ",ax=%s]",
				     curr_sess->rep->analyse_exp ?
				     human_time(TICKS_TO_MS(curr_sess->rep->analyse_exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg,
				     " s0=[%d,%1xh,fd=%d,ex=%s]",
				     curr_sess->si[0].state,
				     curr_sess->si[0].flags,
				     curr_sess->si[0].fd,
				     curr_sess->si[0].exp ?
				     human_time(TICKS_TO_MS(curr_sess->si[0].exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg,
				     " s1=[%d,%1xh,fd=%d,ex=%s]",
				     curr_sess->si[1].state,
				     curr_sess->si[1].flags,
				     curr_sess->si[1].fd,
				     curr_sess->si[1].exp ?
				     human_time(TICKS_TO_MS(curr_sess->si[1].exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg,
				     " exp=%s",
				     curr_sess->task->expire ?
				     human_time(TICKS_TO_MS(curr_sess->task->expire - now_ms),
						TICKS_TO_MS(1000)) : "");
			if (task_in_rq(curr_sess->task))
				chunk_printf(&msg, " run(nice=%d)", curr_sess->task->nice);

			chunk_printf(&msg, "\n");

			if (buffer_feed_chunk(si->ib, &msg) >= 0) {
				/* let's try again later from this session. We add ourselves into
				 * this session's users so that it can remove us upon termination.
				 */
				LIST_ADDQ(&curr_sess->back_refs, &si->applet.ctx.sess.bref.users);
				return 0;
			}

		next_sess:
			si->applet.ctx.sess.bref.ref = curr_sess->list.n;
		}

		if (si->applet.ctx.sess.target) {
			/* specified session not found */
			if (si->applet.ctx.sess.section > 0)
				chunk_printf(&msg, "  *** session terminated while we were watching it ***\n");
			else
				chunk_printf(&msg, "Session not found.\n");

			if (buffer_feed_chunk(si->ib, &msg) >= 0)
				return 0;

			si->applet.ctx.sess.target = NULL;
			si->applet.ctx.sess.uid = 0;
			return 1;
		}

		si->applet.state = STAT_ST_FIN;
		/* fall through */

	default:
		si->applet.state = STAT_ST_FIN;
		return 1;
	}
}

/* This function dumps all tables' states onto the stream intreface's
 * read buffer. The data_ctx must have been zeroed first, and the flags
 * properly set. It returns 0 if the output buffer is full and it needs
 * to be called again, otherwise non-zero.
 */
static int stats_dump_table_to_buffer(struct stream_interface *si)
{
	struct session *s = si->applet.private;
	struct chunk msg;
	struct ebmb_node *eb;
	int dt;

	/*
	 * We have 3 possible states in si->applet.state :
	 *   - STAT_ST_INIT : the first call
	 *   - STAT_ST_INFO : the proxy pointer points to the next table to
	 *     dump, the entry pointer is NULL ;
	 *   - STAT_ST_LIST : the proxy pointer points to the current table
	 *     and the entry pointer points to the next entry to be dumped,
	 *     and the refcount on the next entry is held ;
	 *   - STAT_ST_END : nothing left to dump, the buffer may contain some
	 *     data though.
	 */

	if (unlikely(si->ib->flags & (BF_WRITE_ERROR|BF_SHUTW))) {
		/* in case of abort, remove any refcount we might have set on an entry */
		if (si->applet.state == STAT_ST_LIST) {
			si->applet.ctx.table.entry->ref_cnt--;
			stksess_kill_if_expired(&si->applet.ctx.table.proxy->table, si->applet.ctx.table.entry);
		}
		return 1;
	}

	chunk_init(&msg, trash, sizeof(trash));

	while (si->applet.state != STAT_ST_FIN) {
		switch (si->applet.state) {
		case STAT_ST_INIT:
			si->applet.ctx.table.proxy = si->applet.ctx.table.target;
			if (!si->applet.ctx.table.proxy)
				si->applet.ctx.table.proxy = proxy;

			si->applet.ctx.table.entry = NULL;
			si->applet.state = STAT_ST_INFO;
			break;

		case STAT_ST_INFO:
			if (!si->applet.ctx.table.proxy ||
			    (si->applet.ctx.table.target &&
			     si->applet.ctx.table.proxy != si->applet.ctx.table.target)) {
				si->applet.state = STAT_ST_END;
				break;
			}

			if (si->applet.ctx.table.proxy->table.size) {
				if (!stats_dump_table_head_to_buffer(&msg, si, si->applet.ctx.table.proxy,
								     si->applet.ctx.table.target))
					return 0;

				if (si->applet.ctx.table.target &&
				    s->listener->perm.ux.level >= ACCESS_LVL_OPER) {
					/* dump entries only if table explicitly requested */
					eb = ebmb_first(&si->applet.ctx.table.proxy->table.keys);
					if (eb) {
						si->applet.ctx.table.entry = ebmb_entry(eb, struct stksess, key);
						si->applet.ctx.table.entry->ref_cnt++;
						si->applet.state = STAT_ST_LIST;
						break;
					}
				}
			}
			si->applet.ctx.table.proxy = si->applet.ctx.table.proxy->next;
			break;

		case STAT_ST_LIST:
			if (si->applet.ctx.table.data_type >= 0) {
				/* we're filtering on some data contents */
				void *ptr;
				long long data;

				dt = si->applet.ctx.table.data_type;
				ptr = stktable_data_ptr(&si->applet.ctx.table.proxy->table,
							si->applet.ctx.table.entry,
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
								    si->applet.ctx.table.proxy->table.data_arg[dt].u);
					break;
				}

				/* skip the entry if the data does not match the test and the value */
				if ((data < si->applet.ctx.table.value &&
				     (si->applet.ctx.table.data_op == STD_OP_EQ ||
				      si->applet.ctx.table.data_op == STD_OP_GT ||
				      si->applet.ctx.table.data_op == STD_OP_GE)) ||
				    (data == si->applet.ctx.table.value &&
				     (si->applet.ctx.table.data_op == STD_OP_NE ||
				      si->applet.ctx.table.data_op == STD_OP_GT ||
				      si->applet.ctx.table.data_op == STD_OP_LT)) ||
				    (data > si->applet.ctx.table.value &&
				     (si->applet.ctx.table.data_op == STD_OP_EQ ||
				      si->applet.ctx.table.data_op == STD_OP_LT ||
				      si->applet.ctx.table.data_op == STD_OP_LE)))
					goto skip_entry;
			}

			if (!stats_dump_table_entry_to_buffer(&msg, si, si->applet.ctx.table.proxy,
							      si->applet.ctx.table.entry))
			    return 0;

		skip_entry:
			si->applet.ctx.table.entry->ref_cnt--;

			eb = ebmb_next(&si->applet.ctx.table.entry->key);
			if (eb) {
				struct stksess *old = si->applet.ctx.table.entry;
				si->applet.ctx.table.entry = ebmb_entry(eb, struct stksess, key);
				stksess_kill_if_expired(&si->applet.ctx.table.proxy->table, old);
				si->applet.ctx.table.entry->ref_cnt++;
				break;
			}

			stksess_kill_if_expired(&si->applet.ctx.table.proxy->table, si->applet.ctx.table.entry);
			si->applet.ctx.table.proxy = si->applet.ctx.table.proxy->next;
			si->applet.state = STAT_ST_INFO;
			break;

		case STAT_ST_END:
			si->applet.state = STAT_ST_FIN;
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

	chunk_printf(out, "  %05d%c ", ptr, (ptr == *line) ? ' ' : '+');

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

/* This function dumps all captured errors onto the stream intreface's
 * read buffer. The data_ctx must have been zeroed first, and the flags
 * properly set. It returns 0 if the output buffer is full and it needs
 * to be called again, otherwise non-zero.
 */
static int stats_dump_errors_to_buffer(struct stream_interface *si)
{
	extern const char *monthname[12];
	struct chunk msg;

	if (unlikely(si->ib->flags & (BF_WRITE_ERROR|BF_SHUTW)))
		return 1;

	chunk_init(&msg, trash, sizeof(trash));

	if (!si->applet.ctx.errors.px) {
		/* the function had not been called yet, let's prepare the
		 * buffer for a response.
		 */
		struct tm tm;

		get_localtime(date.tv_sec, &tm);
		chunk_printf(&msg, "Total events captured on [%02d/%s/%04d:%02d:%02d:%02d.%03d] : %u\n",
			     tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
			     tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(date.tv_usec/1000),
			     error_snapshot_id);

		if (buffer_feed_chunk(si->ib, &msg) >= 0) {
			/* Socket buffer full. Let's try again later from the same point */
			return 0;
		}

		si->applet.ctx.errors.px = proxy;
		si->applet.ctx.errors.buf = 0;
		si->applet.ctx.errors.bol = 0;
		si->applet.ctx.errors.ptr = -1;
	}

	/* we have two inner loops here, one for the proxy, the other one for
	 * the buffer.
	 */
	while (si->applet.ctx.errors.px) {
		struct error_snapshot *es;

		if (si->applet.ctx.errors.buf == 0)
			es = &si->applet.ctx.errors.px->invalid_req;
		else
			es = &si->applet.ctx.errors.px->invalid_rep;

		if (!es->when.tv_sec)
			goto next;

		if (si->applet.ctx.errors.iid >= 0 &&
		    si->applet.ctx.errors.px->uuid != si->applet.ctx.errors.iid &&
		    es->oe->uuid != si->applet.ctx.errors.iid)
			goto next;

		if (si->applet.ctx.errors.ptr < 0) {
			/* just print headers now */

			char pn[INET6_ADDRSTRLEN];
			struct tm tm;

			get_localtime(es->when.tv_sec, &tm);
			chunk_printf(&msg, " \n[%02d/%s/%04d:%02d:%02d:%02d.%03d]",
				     tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
				     tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(es->when.tv_usec/1000));


			if (es->src.ss_family == AF_INET)
				inet_ntop(AF_INET,
					  (const void *)&((struct sockaddr_in *)&es->src)->sin_addr,
					  pn, sizeof(pn));
			else
				inet_ntop(AF_INET6,
					  (const void *)&((struct sockaddr_in6 *)(&es->src))->sin6_addr,
					  pn, sizeof(pn));

			switch (si->applet.ctx.errors.buf) {
			case 0:
				chunk_printf(&msg,
					     " frontend %s (#%d): invalid request\n"
					     "  src %s, session #%d, backend %s (#%d), server %s (#%d)\n"
					     "  HTTP internal state %d, buffer flags 0x%08x, event #%u\n"
					     "  request length %d bytes, error at position %d:\n \n",
					     si->applet.ctx.errors.px->id, si->applet.ctx.errors.px->uuid,
					     pn, es->sid, (es->oe->cap & PR_CAP_BE) ? es->oe->id : "<NONE>",
					     (es->oe->cap & PR_CAP_BE) ? es->oe->uuid : -1,
					     es->srv ? es->srv->id : "<NONE>",
					     es->srv ? es->srv->puid : -1,
					     es->state, es->flags, es->ev_id,
					     es->len, es->pos);
				break;
			case 1:
				chunk_printf(&msg,
					     " backend %s (#%d) : invalid response\n"
					     "  src %s, session #%d, frontend %s (#%d), server %s (#%d)\n"
					     "  HTTP internal state %d, buffer flags 0x%08x, event #%u\n"
					     "  response length %d bytes, error at position %d:\n \n",
					     si->applet.ctx.errors.px->id, si->applet.ctx.errors.px->uuid,
					     pn, es->sid, es->oe->id, es->oe->uuid,
					     es->srv ? es->srv->id : "<NONE>",
					     es->srv ? es->srv->puid : -1,
					     es->state, es->flags, es->ev_id,
					     es->len, es->pos);
				break;
			}

			if (buffer_feed_chunk(si->ib, &msg) >= 0) {
				/* Socket buffer full. Let's try again later from the same point */
				return 0;
			}
			si->applet.ctx.errors.ptr = 0;
			si->applet.ctx.errors.sid = es->sid;
		}

		if (si->applet.ctx.errors.sid != es->sid) {
			/* the snapshot changed while we were dumping it */
			chunk_printf(&msg,
				     "  WARNING! update detected on this snapshot, dump interrupted. Please re-check!\n");
			if (buffer_feed_chunk(si->ib, &msg) >= 0)
				return 0;
			goto next;
		}

		/* OK, ptr >= 0, so we have to dump the current line */
		while (si->applet.ctx.errors.ptr < es->len && si->applet.ctx.errors.ptr < sizeof(es->buf)) {
			int newptr;
			int newline;

			newline = si->applet.ctx.errors.bol;
			newptr = dump_text_line(&msg, es->buf, sizeof(es->buf), es->len, &newline, si->applet.ctx.errors.ptr);
			if (newptr == si->applet.ctx.errors.ptr)
				return 0;

			if (buffer_feed_chunk(si->ib, &msg) >= 0) {
				/* Socket buffer full. Let's try again later from the same point */
				return 0;
			}
			si->applet.ctx.errors.ptr = newptr;
			si->applet.ctx.errors.bol = newline;
		};
	next:
		si->applet.ctx.errors.bol = 0;
		si->applet.ctx.errors.ptr = -1;
		si->applet.ctx.errors.buf++;
		if (si->applet.ctx.errors.buf > 1) {
			si->applet.ctx.errors.buf = 0;
			si->applet.ctx.errors.px = si->applet.ctx.errors.px->next;
		}
	}

	/* dump complete */
	return 1;
}

struct si_applet http_stats_applet = {
	.name = "<STATS>", /* used for logging */
	.fct = http_stats_io_handler,
};

static struct si_applet cli_applet = {
	.name = "<CLI>", /* used for logging */
	.fct = cli_io_handler,
};

static struct cfg_kw_list cfg_kws = {{ },{
	{ CFG_GLOBAL, "stats", stats_parse_global },
	{ 0, NULL, NULL },
}};

__attribute__((constructor))
static void __dumpstats_module_init(void)
{
	cfg_register_keywords(&cfg_kws);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
