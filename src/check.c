/*
 * Health-checks functions.
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
 * Copyright 2007-2009 Krzysztof Piotr Oledzki <ole@ans.pl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <haproxy/action.h>
#include <haproxy/api.h>
#include <haproxy/arg.h>
#include <haproxy/cfgparse.h>
#include <haproxy/check.h>
#include <haproxy/chunk.h>
#include <haproxy/dgram.h>
#include <haproxy/dynbuf.h>
#include <haproxy/extcheck.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/h1.h>
#include <haproxy/http.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/istbuf.h>
#include <haproxy/list.h>
#include <haproxy/log.h>
#include <haproxy/mailers.h>
#include <haproxy/port_range.h>
#include <haproxy/proto_tcp.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/queue.h>
#include <haproxy/regex.h>
#include <haproxy/resolvers.h>
#include <haproxy/sample.h>
#include <haproxy/server.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/stats-t.h>
#include <haproxy/task.h>
#include <haproxy/tcpcheck.h>
#include <haproxy/thread.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <haproxy/trace.h>
#include <haproxy/vars.h>

/* trace source and events */
static void check_trace(enum trace_level level, uint64_t mask,
			const struct trace_source *src,
			const struct ist where, const struct ist func,
			const void *a1, const void *a2, const void *a3, const void *a4);

/* The event representation is split like this :
 *   check  - check
 *
 * CHECK_EV_* macros are defined in <haproxy/check.h>
 */
static const struct trace_event check_trace_events[] = {
	{ .mask = CHK_EV_TASK_WAKE,   .name = "task_wake",        .desc = "Check task woken up" },
	{ .mask = CHK_EV_HCHK_START,  .name = "hchck_start",      .desc = "Health-check started" },
	{ .mask = CHK_EV_HCHK_WAKE,   .name = "hchck_wake",       .desc = "Health-check woken up" },
	{ .mask = CHK_EV_HCHK_RUN,    .name = "hchck_run",        .desc = "Health-check running" },
	{ .mask = CHK_EV_HCHK_END,    .name = "hchck_end",        .desc = "Health-check terminated" },
	{ .mask = CHK_EV_HCHK_SUCC,   .name = "hchck_succ",       .desc = "Health-check success" },
	{ .mask = CHK_EV_HCHK_ERR,    .name = "hchck_err",        .desc = "Health-check failure" },

	{ .mask = CHK_EV_TCPCHK_EVAL, .name = "tcp_check_eval",   .desc = "tcp-check rules evaluation" },
	{ .mask = CHK_EV_TCPCHK_ERR,  .name = "tcp_check_err",    .desc = "tcp-check evaluation error" },
	{ .mask = CHK_EV_TCPCHK_CONN, .name = "tcp_check_conn",   .desc = "tcp-check connection rule" },
	{ .mask = CHK_EV_TCPCHK_SND,  .name = "tcp_check_send",   .desc = "tcp-check send rule" },
	{ .mask = CHK_EV_TCPCHK_EXP,  .name = "tcp_check_expect", .desc = "tcp-check expect rule" },
	{ .mask = CHK_EV_TCPCHK_ACT,  .name = "tcp_check_action", .desc = "tcp-check action rule" },

	{ .mask = CHK_EV_RX_DATA,     .name = "rx_data",          .desc = "receipt of data" },
	{ .mask = CHK_EV_RX_BLK,      .name = "rx_blk",           .desc = "receipt blocked" },
	{ .mask = CHK_EV_RX_ERR,      .name = "rx_err",           .desc = "receipt error" },

	{ .mask = CHK_EV_TX_DATA,     .name = "tx_data",          .desc = "transmission of data" },
	{ .mask = CHK_EV_TX_BLK,      .name = "tx_blk",           .desc = "transmission blocked" },
	{ .mask = CHK_EV_TX_ERR,      .name = "tx_err",           .desc = "transmission error" },

	{}
};

static const struct name_desc check_trace_lockon_args[4] = {
	/* arg1 */ { /* already used by the check */ },
	/* arg2 */ { },
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct name_desc check_trace_decoding[] = {
#define CHK_VERB_CLEAN    1
	{ .name="clean",    .desc="only user-friendly stuff, generally suitable for level \"user\"" },
#define CHK_VERB_MINIMAL  2
	{ .name="minimal",  .desc="report info on streams and connectors" },
#define CHK_VERB_SIMPLE   3
	{ .name="simple",   .desc="add info on request and response channels" },
#define CHK_VERB_ADVANCED 4
	{ .name="advanced", .desc="add info on channel's buffer for data and developer levels only" },
#define CHK_VERB_COMPLETE 5
	{ .name="complete", .desc="add info on channel's buffer" },
	{ /* end */ }
};

struct trace_source trace_check = {
	.name = IST("check"),
	.desc = "Health-check",
	.arg_def = TRC_ARG1_CHK,  // TRACE()'s first argument is always a stream
	.default_cb = check_trace,
	.known_events = check_trace_events,
	.lockon_args = check_trace_lockon_args,
	.decoding = check_trace_decoding,
	.report_events = ~0,  // report everything by default
};

#define TRACE_SOURCE &trace_check
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);


/* Dummy frontend used to create all checks sessions. */
struct proxy checks_fe;


static inline void check_trace_buf(const struct buffer *buf, size_t ofs, size_t len)
{
	size_t block1, block2;
	int line, ptr, newptr;

	block1 = b_contig_data(buf, ofs);
	block2 = 0;
	if (block1 > len)
		block1 = len;
	block2 = len - block1;

	ofs = b_peek_ofs(buf, ofs);

	line = 0;
	ptr = ofs;
	while (ptr < ofs + block1) {
		newptr = dump_text_line(&trace_buf, b_orig(buf), b_size(buf), ofs + block1, &line, ptr);
		if (newptr == ptr)
			break;
		ptr = newptr;
	}

	line = ptr = 0;
	while (ptr < block2) {
		newptr = dump_text_line(&trace_buf, b_orig(buf), b_size(buf), block2, &line, ptr);
		if (newptr == ptr)
			break;
		ptr = newptr;
	}
}

/* trace source and events */
static void check_trace(enum trace_level level, uint64_t mask,
			const struct trace_source *src,
			const struct ist where, const struct ist func,
			const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct check *check = a1;
	const struct server *srv = (check ? check->server : NULL);
	const size_t        *val = a4;
	const char *res;

	if (!check || src->verbosity < CHK_VERB_CLEAN)
		return;

	if (srv) {
		chunk_appendf(&trace_buf, " : [%c] SRV=%s",
			      ((check->type == PR_O2_EXT_CHK) ? 'E' : (check->state & CHK_ST_AGENT ? 'A' : 'H')),
			      srv->id);

		chunk_appendf(&trace_buf, " status=%d/%d %s",
			      (check->health >= check->rise) ? check->health - check->rise + 1 : check->health,
			      (check->health >= check->rise) ? check->fall : check->rise,
			      (check->health >= check->rise) ? (srv->uweight ? "UP" : "DRAIN") : "DOWN");
	}
	else
		chunk_appendf(&trace_buf, " : [EMAIL]");

	switch (check->result) {
	case CHK_RES_NEUTRAL: res = "-";     break;
	case CHK_RES_FAILED:   res = "FAIL"; break;
	case CHK_RES_PASSED:   res = "PASS"; break;
	case CHK_RES_CONDPASS: res = "COND"; break;
	default:               res = "UNK";  break;
	}

	if (src->verbosity == CHK_VERB_CLEAN)
		return;

	chunk_appendf(&trace_buf, " - last=%s(%d)/%s(%d)",
		      get_check_status_info(check->status), check->status,
		      res, check->result);

	/* Display the value to the 4th argument (level > STATE) */
	if (src->level > TRACE_LEVEL_STATE && val)
		chunk_appendf(&trace_buf, " - VAL=%lu", (long)*val);

	chunk_appendf(&trace_buf, " check=%p(0x%08x)", check, check->state);

	if (src->verbosity == CHK_VERB_MINIMAL)
		return;


	if (check->sc) {
		struct connection *conn = sc_conn(check->sc);

		chunk_appendf(&trace_buf, " - conn=%p(0x%08x)", conn, conn ? conn->flags : 0);
		chunk_appendf(&trace_buf, " sc=%p(0x%08x)", check->sc, check->sc->flags);
	}

	if (mask & CHK_EV_TCPCHK) {
		const char *type;

		switch (check->tcpcheck_rules->flags & TCPCHK_RULES_PROTO_CHK) {
			case TCPCHK_RULES_PGSQL_CHK: type = "PGSQL"; break;
			case TCPCHK_RULES_REDIS_CHK: type = "REDIS"; break;
			case TCPCHK_RULES_SMTP_CHK:  type = "SMTP";  break;
			case TCPCHK_RULES_HTTP_CHK:  type = "HTTP";  break;
			case TCPCHK_RULES_MYSQL_CHK: type = "MYSQL"; break;
			case TCPCHK_RULES_LDAP_CHK:  type = "LDAP";  break;
			case TCPCHK_RULES_SSL3_CHK:  type = "SSL3";  break;
			case TCPCHK_RULES_AGENT_CHK: type = "AGENT"; break;
			case TCPCHK_RULES_SPOP_CHK:  type = "SPOP";  break;
			case TCPCHK_RULES_TCP_CHK:   type = "TCP";   break;
			default:                     type = "???"; break;
		}
		if (check->current_step)
			chunk_appendf(&trace_buf, " - tcp-check=(%s,%d)", type, tcpcheck_get_step_id(check, NULL));
		else
			chunk_appendf(&trace_buf, " - tcp-check=(%s,-)", type);
	}

	/* Display bi and bo buffer info (level > USER & verbosity > SIMPLE) */
	if (src->level > TRACE_LEVEL_USER) {
		const struct buffer *buf = NULL;

		chunk_appendf(&trace_buf, " bi=%u@%p+%u/%u",
			      (unsigned int)b_data(&check->bi), b_orig(&check->bi),
			      (unsigned int)b_head_ofs(&check->bi), (unsigned int)b_size(&check->bi));
		chunk_appendf(&trace_buf, " bo=%u@%p+%u/%u",
			      (unsigned int)b_data(&check->bo), b_orig(&check->bo),
			      (unsigned int)b_head_ofs(&check->bo), (unsigned int)b_size(&check->bo));

		if (src->verbosity >= CHK_VERB_ADVANCED && (mask & (CHK_EV_RX)))
			buf = (b_is_null(&check->bi) ? NULL : &check->bi);
		else if (src->verbosity >= CHK_VERB_ADVANCED && (mask & (CHK_EV_TX)))
			buf = (b_is_null(&check->bo) ? NULL : &check->bo);

		if (buf) {
			if ((check->tcpcheck_rules->flags & TCPCHK_RULES_PROTO_CHK) == TCPCHK_RULES_HTTP_CHK) {
				int full = (src->verbosity == CHK_VERB_COMPLETE);

				chunk_memcat(&trace_buf, "\n\t", 2);
				htx_dump(&trace_buf, htxbuf(buf), full);
			}
			else {
				int max = ((src->verbosity == CHK_VERB_COMPLETE) ? 1024 : 256);

				chunk_memcat(&trace_buf, "\n", 1);
				if (b_data(buf) > max) {
					check_trace_buf(buf, 0, max);
					chunk_memcat(&trace_buf, "  ...\n", 6);
				}
				else
					check_trace_buf(buf, 0, b_data(buf));
			}

		}
	}

}


/**************************************************************************/
/************************ Handle check results ****************************/
/**************************************************************************/
struct check_status {
	short result;			/* one of SRV_CHK_* */
	char *info;			/* human readable short info */
	char *desc;			/* long description */
};

struct analyze_status {
	char *desc;				/* description */
	unsigned char lr[HANA_OBS_SIZE];	/* result for l4/l7: 0 = ignore, 1 - error, 2 - OK */
};

static const struct check_status check_statuses[HCHK_STATUS_SIZE] = {
	[HCHK_STATUS_UNKNOWN]	= { CHK_RES_UNKNOWN,  "UNK",     "Unknown" },
	[HCHK_STATUS_INI]	= { CHK_RES_UNKNOWN,  "INI",     "Initializing" },
	[HCHK_STATUS_START]	= { /* SPECIAL STATUS*/ },

	/* Below we have finished checks */
	[HCHK_STATUS_CHECKED]	= { CHK_RES_NEUTRAL,  "CHECKED", "No status change" },
	[HCHK_STATUS_HANA]	= { CHK_RES_FAILED,   "HANA",    "Health analyze" },

	[HCHK_STATUS_SOCKERR]	= { CHK_RES_FAILED,   "SOCKERR", "Socket error" },

	[HCHK_STATUS_L4OK]	= { CHK_RES_PASSED,   "L4OK",    "Layer4 check passed" },
	[HCHK_STATUS_L4TOUT]	= { CHK_RES_FAILED,   "L4TOUT",  "Layer4 timeout" },
	[HCHK_STATUS_L4CON]	= { CHK_RES_FAILED,   "L4CON",   "Layer4 connection problem" },

	[HCHK_STATUS_L6OK]	= { CHK_RES_PASSED,   "L6OK",    "Layer6 check passed" },
	[HCHK_STATUS_L6TOUT]	= { CHK_RES_FAILED,   "L6TOUT",  "Layer6 timeout" },
	[HCHK_STATUS_L6RSP]	= { CHK_RES_FAILED,   "L6RSP",   "Layer6 invalid response" },

	[HCHK_STATUS_L7TOUT]	= { CHK_RES_FAILED,   "L7TOUT",  "Layer7 timeout" },
	[HCHK_STATUS_L7RSP]	= { CHK_RES_FAILED,   "L7RSP",   "Layer7 invalid response" },

	[HCHK_STATUS_L57DATA]	= { /* DUMMY STATUS */ },

	[HCHK_STATUS_L7OKD]	= { CHK_RES_PASSED,   "L7OK",    "Layer7 check passed" },
	[HCHK_STATUS_L7OKCD]	= { CHK_RES_CONDPASS, "L7OKC",   "Layer7 check conditionally passed" },
	[HCHK_STATUS_L7STS]	= { CHK_RES_FAILED,   "L7STS",   "Layer7 wrong status" },

	[HCHK_STATUS_PROCERR]	= { CHK_RES_FAILED,   "PROCERR",  "External check error" },
	[HCHK_STATUS_PROCTOUT]	= { CHK_RES_FAILED,   "PROCTOUT", "External check timeout" },
	[HCHK_STATUS_PROCOK]	= { CHK_RES_PASSED,   "PROCOK",   "External check passed" },
};

static const struct analyze_status analyze_statuses[HANA_STATUS_SIZE] = {		/* 0: ignore, 1: error, 2: OK */
	[HANA_STATUS_UNKNOWN]		= { "Unknown",                         { 0, 0 }},

	[HANA_STATUS_L4_OK]		= { "L4 successful connection",        { 2, 0 }},
	[HANA_STATUS_L4_ERR]		= { "L4 unsuccessful connection",      { 1, 1 }},

	[HANA_STATUS_HTTP_OK]		= { "Correct http response",           { 0, 2 }},
	[HANA_STATUS_HTTP_STS]		= { "Wrong http response",             { 0, 1 }},
	[HANA_STATUS_HTTP_HDRRSP]	= { "Invalid http response (headers)", { 0, 1 }},
	[HANA_STATUS_HTTP_RSP]		= { "Invalid http response",           { 0, 1 }},

	[HANA_STATUS_HTTP_READ_ERROR]	= { "Read error (http)",               { 0, 1 }},
	[HANA_STATUS_HTTP_READ_TIMEOUT]	= { "Read timeout (http)",             { 0, 1 }},
	[HANA_STATUS_HTTP_BROKEN_PIPE]	= { "Close from server (http)",        { 0, 1 }},
};

/* checks if <err> is a real error for errno or one that can be ignored, and
 * return 0 for these ones or <err> for real ones.
 */
static inline int unclean_errno(int err)
{
	if (err == EAGAIN || err == EWOULDBLOCK || err == EINPROGRESS ||
	    err == EISCONN || err == EALREADY)
		return 0;
	return err;
}

/* Converts check_status code to result code */
short get_check_status_result(short check_status)
{
	if (check_status < HCHK_STATUS_SIZE)
		return check_statuses[check_status].result;
	else
		return check_statuses[HCHK_STATUS_UNKNOWN].result;
}

/* Converts check_status code to description */
const char *get_check_status_description(short check_status) {

	const char *desc;

	if (check_status < HCHK_STATUS_SIZE)
		desc = check_statuses[check_status].desc;
	else
		desc = NULL;

	if (desc && *desc)
		return desc;
	else
		return check_statuses[HCHK_STATUS_UNKNOWN].desc;
}

/* Converts check_status code to short info */
const char *get_check_status_info(short check_status)
{
	const char *info;

	if (check_status < HCHK_STATUS_SIZE)
		info = check_statuses[check_status].info;
	else
		info = NULL;

	if (info && *info)
		return info;
	else
		return check_statuses[HCHK_STATUS_UNKNOWN].info;
}

/* Convert analyze_status to description */
const char *get_analyze_status(short analyze_status) {

	const char *desc;

	if (analyze_status < HANA_STATUS_SIZE)
		desc = analyze_statuses[analyze_status].desc;
	else
		desc = NULL;

	if (desc && *desc)
		return desc;
	else
		return analyze_statuses[HANA_STATUS_UNKNOWN].desc;
}

/* append check info to buffer msg */
void check_append_info(struct buffer *msg, struct check *check)
{
	if (!check)
		return;
	chunk_appendf(msg, ", reason: %s", get_check_status_description(check->status));

	if (check->status >= HCHK_STATUS_L57DATA)
		chunk_appendf(msg, ", code: %d", check->code);

	if (check->desc[0]) {
		struct buffer src;

		chunk_appendf(msg, ", info: \"");

		chunk_initlen(&src, check->desc, 0, strlen(check->desc));
		chunk_asciiencode(msg, &src, '"');

		chunk_appendf(msg, "\"");
	}

	if (check->duration >= 0)
		chunk_appendf(msg, ", check duration: %ldms", check->duration);
}

/* Sets check->status, update check->duration and fill check->result with an
 * adequate CHK_RES_* value. The new check->health is computed based on the
 * result.
 *
 * Shows information in logs about failed health check if server is UP or
 * succeeded health checks if server is DOWN.
 */
void set_server_check_status(struct check *check, short status, const char *desc)
{
	struct server *s = check->server;
	short prev_status = check->status;
	int report = (status != prev_status) ? 1 : 0;

	TRACE_POINT(CHK_EV_HCHK_RUN, check);

	if (status == HCHK_STATUS_START) {
		check->result = CHK_RES_UNKNOWN;	/* no result yet */
		check->desc[0] = '\0';
		check->start = now_ns;
		return;
	}

	if (!check->status)
		return;

	if (desc && *desc) {
		strncpy(check->desc, desc, HCHK_DESC_LEN-1);
		check->desc[HCHK_DESC_LEN-1] = '\0';
	} else
		check->desc[0] = '\0';

	check->status = status;
	if (check_statuses[status].result)
		check->result = check_statuses[status].result;

	if (status == HCHK_STATUS_HANA)
		check->duration = -1;
	else if (check->start) {
		/* set_server_check_status() may be called more than once */
		check->duration = ns_to_ms(now_ns - check->start);
		check->start = 0;
	}

	/* no change is expected if no state change occurred */
	if (check->result == CHK_RES_NEUTRAL)
		return;

	/* If the check was really just sending a mail, it won't have an
	 * associated server, so we're done now.
	 */
	if (!s)
	    return;

	switch (check->result) {
	case CHK_RES_FAILED:
		/* Failure to connect to the agent as a secondary check should not
		 * cause the server to be marked down.
		 */
		if ((!(check->state & CHK_ST_AGENT) ||
		    (check->status >= HCHK_STATUS_L57DATA)) &&
		    (check->health > 0)) {
			_HA_ATOMIC_INC(&s->counters.failed_checks);
			report = 1;
			check->health--;
			if (check->health < check->rise)
				check->health = 0;
		}
		break;

	case CHK_RES_PASSED:
	case CHK_RES_CONDPASS:
		if (check->health < check->rise + check->fall - 1) {
			report = 1;
			check->health++;

			if (check->health >= check->rise)
				check->health = check->rise + check->fall - 1; /* OK now */
		}

		/* clear consecutive_errors if observing is enabled */
		if (s->onerror)
			HA_ATOMIC_STORE(&s->consecutive_errors, 0);
		break;

	default:
		break;
	}

	if (report)
		srv_event_hdl_publish_check(s, check);

	if (s->proxy->options2 & PR_O2_LOGHCHKS && report) {
		chunk_printf(&trash,
		             "%s check for %sserver %s/%s %s%s",
			     (check->state & CHK_ST_AGENT) ? "Agent" : "Health",
		             s->flags & SRV_F_BACKUP ? "backup " : "",
		             s->proxy->id, s->id,
		             (check->result == CHK_RES_CONDPASS) ? "conditionally ":"",
		             (check->result >= CHK_RES_PASSED)   ? "succeeded" : "failed");

		check_append_info(&trash, check);

		chunk_appendf(&trash, ", status: %d/%d %s",
		             (check->health >= check->rise) ? check->health - check->rise + 1 : check->health,
		             (check->health >= check->rise) ? check->fall : check->rise,
			     (check->health >= check->rise) ? (s->uweight ? "UP" : "DRAIN") : "DOWN");

		ha_warning("%s.\n", trash.area);
		send_log(s->proxy, LOG_NOTICE, "%s.\n", trash.area);
		send_email_alert(s, LOG_INFO, "%s", trash.area);
	}
}

static inline enum srv_op_st_chg_cause check_notify_cause(struct check *check)
{
	struct server *s = check->server;

	/* We only report a cause for the check if we did not do so previously */
	if (!s->track && !(s->proxy->options2 & PR_O2_LOGHCHKS))
		return (check->state & CHK_ST_AGENT) ? SRV_OP_STCHGC_AGENT : SRV_OP_STCHGC_HEALTH;
	return SRV_OP_STCHGC_NONE;
}

/* Marks the check <check>'s server down if the current check is already failed
 * and the server is not down yet nor in maintenance.
 */
void check_notify_failure(struct check *check)
{
	struct server *s = check->server;

	/* The agent secondary check should only cause a server to be marked
	 * as down if check->status is HCHK_STATUS_L7STS, which indicates
	 * that the agent returned "fail", "stopped" or "down".
	 * The implication here is that failure to connect to the agent
	 * as a secondary check should not cause the server to be marked
	 * down. */
	if ((check->state & CHK_ST_AGENT) && check->status != HCHK_STATUS_L7STS)
		return;

	if (check->health > 0)
		return;

	TRACE_STATE("health-check failed, set server DOWN", CHK_EV_HCHK_END|CHK_EV_HCHK_ERR, check);
	srv_set_stopped(s, check_notify_cause(check));
}

/* Marks the check <check> as valid and tries to set its server up, provided
 * it isn't in maintenance, it is not tracking a down server and other checks
 * comply. The rule is simple : by default, a server is up, unless any of the
 * following conditions is true :
 *   - health check failed (check->health < rise)
 *   - agent check failed (agent->health < rise)
 *   - the server tracks a down server (track && track->state == STOPPED)
 * Note that if the server has a slowstart, it will switch to STARTING instead
 * of RUNNING. Also, only the health checks support the nolb mode, so the
 * agent's success may not take the server out of this mode.
 */
void check_notify_success(struct check *check)
{
	struct server *s = check->server;

	if (s->next_admin & SRV_ADMF_MAINT)
		return;

	if (s->track && s->track->next_state == SRV_ST_STOPPED)
		return;

	if ((s->check.state & CHK_ST_ENABLED) && (s->check.health < s->check.rise))
		return;

	if ((s->agent.state & CHK_ST_ENABLED) && (s->agent.health < s->agent.rise))
		return;

	if ((check->state & CHK_ST_AGENT) && s->next_state == SRV_ST_STOPPING)
		return;

	TRACE_STATE("health-check succeeded, set server RUNNING", CHK_EV_HCHK_END|CHK_EV_HCHK_SUCC, check);
	srv_set_running(s, check_notify_cause(check));
}

/* Marks the check <check> as valid and tries to set its server into stopping mode
 * if it was running or starting, and provided it isn't in maintenance and other
 * checks comply. The conditions for the server to be marked in stopping mode are
 * the same as for it to be turned up. Also, only the health checks support the
 * nolb mode.
 */
void check_notify_stopping(struct check *check)
{
	struct server *s = check->server;

	if (s->next_admin & SRV_ADMF_MAINT)
		return;

	if (check->state & CHK_ST_AGENT)
		return;

	if (s->track && s->track->next_state == SRV_ST_STOPPED)
		return;

	if ((s->check.state & CHK_ST_ENABLED) && (s->check.health < s->check.rise))
		return;

	if ((s->agent.state & CHK_ST_ENABLED) && (s->agent.health < s->agent.rise))
		return;

	TRACE_STATE("health-check condionnaly succeeded, set server STOPPING", CHK_EV_HCHK_END|CHK_EV_HCHK_SUCC, check);
	srv_set_stopping(s, check_notify_cause(check));
}

/* note: use health_adjust() only, which first checks that the observe mode is
 * enabled. This will take the server lock if needed.
 */
void __health_adjust(struct server *s, short status)
{
	int failed;

	if (s->observe >= HANA_OBS_SIZE)
		return;

	if (status >= HANA_STATUS_SIZE || !analyze_statuses[status].desc)
		return;

	switch (analyze_statuses[status].lr[s->observe - 1]) {
		case 1:
			failed = 1;
			break;

		case 2:
			failed = 0;
			break;

		default:
			return;
	}

	if (!failed) {
		/* good: clear consecutive_errors */
		HA_ATOMIC_STORE(&s->consecutive_errors, 0);
		return;
	}

	if (HA_ATOMIC_ADD_FETCH(&s->consecutive_errors, 1) < s->consecutive_errors_limit)
		return;

	chunk_printf(&trash, "Detected %d consecutive errors, last one was: %s",
	             HA_ATOMIC_LOAD(&s->consecutive_errors), get_analyze_status(status));

	HA_SPIN_LOCK(SERVER_LOCK, &s->lock);

	/* force fastinter for upcoming check
	 * (does nothing if fastinter is not enabled)
	 */
	s->check.state |= CHK_ST_FASTINTER;

	switch (s->onerror) {
		case HANA_ONERR_FASTINTER:
		/* force fastinter - nothing to do here as all modes force it */
			break;

		case HANA_ONERR_SUDDTH:
		/* simulate a pre-fatal failed health check */
			if (s->check.health > s->check.rise)
				s->check.health = s->check.rise + 1;

			__fallthrough;

		case HANA_ONERR_FAILCHK:
		/* simulate a failed health check */
			set_server_check_status(&s->check, HCHK_STATUS_HANA,
						trash.area);
			check_notify_failure(&s->check);
			break;

		case HANA_ONERR_MARKDWN:
		/* mark server down */
			s->check.health = s->check.rise;
			set_server_check_status(&s->check, HCHK_STATUS_HANA,
						trash.area);
			check_notify_failure(&s->check);
			break;

		default:
			/* write a warning? */
			break;
	}

	HA_SPIN_UNLOCK(SERVER_LOCK, &s->lock);

	HA_ATOMIC_STORE(&s->consecutive_errors, 0);
	_HA_ATOMIC_INC(&s->counters.failed_hana);

	if (s->check.fastinter) {
		/* timer might need to be advanced, it might also already be
		 * running in another thread. Let's just wake the task up, it
		 * will automatically adjust its timer.
		 */
		task_wakeup(s->check.task, TASK_WOKEN_MSG);
	}
}

/* Checks the connection. If an error has already been reported or the socket is
 * closed, keep errno intact as it is supposed to contain the valid error code.
 * If no error is reported, check the socket's error queue using getsockopt().
 * Warning, this must be done only once when returning from poll, and never
 * after an I/O error was attempted, otherwise the error queue might contain
 * inconsistent errors. If an error is detected, the CO_FL_ERROR is set on the
 * socket. Returns non-zero if an error was reported, zero if everything is
 * clean (including a properly closed socket).
 */
static int retrieve_errno_from_socket(struct connection *conn)
{
	int skerr;
	socklen_t lskerr = sizeof(skerr);

	if (conn->flags & CO_FL_ERROR && (unclean_errno(errno) || !conn->ctrl))
		return 1;

	if (!conn_ctrl_ready(conn))
		return 0;

	BUG_ON(conn->flags & CO_FL_FDLESS);

	if (getsockopt(conn->handle.fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr) == 0)
		errno = skerr;

	errno = unclean_errno(errno);

	if (!errno) {
		/* we could not retrieve an error, that does not mean there is
		 * none. Just don't change anything and only report the prior
		 * error if any.
		 */
		if (conn->flags & CO_FL_ERROR)
			return 1;
		else
			return 0;
	}

	conn->flags |= CO_FL_ERROR | CO_FL_SOCK_WR_SH | CO_FL_SOCK_RD_SH;
	return 1;
}

/* Tries to collect as much information as possible on the connection status,
 * and adjust the server status accordingly. It may make use of <errno_bck>
 * if non-null when the caller is absolutely certain of its validity (eg:
 * checked just after a syscall). If the caller doesn't have a valid errno,
 * it can pass zero, and retrieve_errno_from_socket() will be called to try
 * to extract errno from the socket. If no error is reported, it will consider
 * the <expired> flag. This is intended to be used when a connection error was
 * reported in conn->flags or when a timeout was reported in <expired>. The
 * function takes care of not updating a server status which was already set.
 * All situations where at least one of <expired> or CO_FL_ERROR are set
 * produce a status.
 */
void chk_report_conn_err(struct check *check, int errno_bck, int expired)
{
	struct stconn *sc = check->sc;
	struct connection *conn = sc_conn(sc);
	const char *err_msg;
	struct buffer *chk;
	int step;

	if (check->result != CHK_RES_UNKNOWN) {
		return;
	}

	errno = unclean_errno(errno_bck);
	if (conn && errno)
		retrieve_errno_from_socket(conn);

	if (conn && !(conn->flags & CO_FL_ERROR) && !sc_ep_test(sc, SE_FL_ERROR) && !expired)
		return;

	TRACE_ENTER(CHK_EV_HCHK_END|CHK_EV_HCHK_ERR, check, 0, 0, (size_t[]){expired});

	/* we'll try to build a meaningful error message depending on the
	 * context of the error possibly present in conn->err_code, and the
	 * socket error possibly collected above. This is useful to know the
	 * exact step of the L6 layer (eg: SSL handshake).
	 */
	chk = get_trash_chunk();

	if (check->type == PR_O2_TCPCHK_CHK &&
	    (check->tcpcheck_rules->flags & TCPCHK_RULES_PROTO_CHK) == TCPCHK_RULES_TCP_CHK) {
		step = tcpcheck_get_step_id(check, NULL);
		if (!step) {
			TRACE_DEVEL("initial connection failure", CHK_EV_HCHK_END|CHK_EV_HCHK_ERR, check);
			chunk_printf(chk, " at initial connection step of tcp-check");
		}
		else {
			chunk_printf(chk, " at step %d of tcp-check", step);
			/* we were looking for a string */
			if (check->current_step && check->current_step->action == TCPCHK_ACT_CONNECT) {
				if (check->current_step->connect.port)
					chunk_appendf(chk, " (connect port %d)" ,check->current_step->connect.port);
				else
					chunk_appendf(chk, " (connect)");
				TRACE_DEVEL("connection failure", CHK_EV_HCHK_END|CHK_EV_HCHK_ERR, check);
			}
			else if (check->current_step && check->current_step->action == TCPCHK_ACT_EXPECT) {
				struct tcpcheck_expect *expect = &check->current_step->expect;

				switch (expect->type) {
				case TCPCHK_EXPECT_STRING:
					chunk_appendf(chk, " (expect string '%.*s')", (unsigned int)istlen(expect->data), istptr(expect->data));
					break;
				case TCPCHK_EXPECT_BINARY:
					chunk_appendf(chk, " (expect binary '");
					dump_binary(chk, istptr(expect->data), (int)istlen(expect->data));
					chunk_appendf(chk, "')");
					break;
				case TCPCHK_EXPECT_STRING_REGEX:
					chunk_appendf(chk, " (expect regex)");
					break;
				case TCPCHK_EXPECT_BINARY_REGEX:
					chunk_appendf(chk, " (expect binary regex)");
					break;
				case TCPCHK_EXPECT_STRING_LF:
					chunk_appendf(chk, " (expect log-format string)");
					break;
				case TCPCHK_EXPECT_BINARY_LF:
					chunk_appendf(chk, " (expect log-format binary)");
					break;
				case TCPCHK_EXPECT_HTTP_STATUS:
					chunk_appendf(chk, " (expect HTTP status codes)");
					break;
				case TCPCHK_EXPECT_HTTP_STATUS_REGEX:
					chunk_appendf(chk, " (expect HTTP status regex)");
					break;
				case TCPCHK_EXPECT_HTTP_HEADER:
					chunk_appendf(chk, " (expect HTTP header pattern)");
					break;
				case TCPCHK_EXPECT_HTTP_BODY:
					chunk_appendf(chk, " (expect HTTP body content '%.*s')", (unsigned int)istlen(expect->data), istptr(expect->data));
					break;
				case TCPCHK_EXPECT_HTTP_BODY_REGEX:
					chunk_appendf(chk, " (expect HTTP body regex)");
					break;
				case TCPCHK_EXPECT_HTTP_BODY_LF:
					chunk_appendf(chk, " (expect log-format HTTP body)");
					break;
				case TCPCHK_EXPECT_CUSTOM:
					chunk_appendf(chk, " (expect custom function)");
					break;
				case TCPCHK_EXPECT_UNDEF:
					chunk_appendf(chk, " (undefined expect!)");
					break;
				}
				TRACE_DEVEL("expect rule failed", CHK_EV_HCHK_END|CHK_EV_HCHK_ERR, check);
			}
			else if (check->current_step && check->current_step->action == TCPCHK_ACT_SEND) {
				chunk_appendf(chk, " (send)");
				TRACE_DEVEL("send rule failed", CHK_EV_HCHK_END|CHK_EV_HCHK_ERR, check);
			}

			if (check->current_step && check->current_step->comment)
				chunk_appendf(chk, " comment: '%s'", check->current_step->comment);
		}
	}

	if (conn && conn->err_code) {
		if (unclean_errno(errno))
			chunk_printf(&trash, "%s (%s)%s", conn_err_code_str(conn), strerror(errno),
				     chk->area);
		else
			chunk_printf(&trash, "%s%s", conn_err_code_str(conn),
				     chk->area);
		err_msg = trash.area;
	}
	else {
		if (unclean_errno(errno)) {
			chunk_printf(&trash, "%s%s", strerror(errno),
				     chk->area);
			err_msg = trash.area;
		}
		else {
			err_msg = chk->area;
		}
	}

	if (check->state & CHK_ST_PORT_MISS) {
		/* NOTE: this is reported after <fall> tries */
		set_server_check_status(check, HCHK_STATUS_SOCKERR, err_msg);
	}

	if (!conn || !conn->ctrl) {
		/* error before any connection attempt (connection allocation error or no control layer) */
		set_server_check_status(check, HCHK_STATUS_SOCKERR, err_msg);
	}
	else if (conn->flags & CO_FL_WAIT_L4_CONN) {
		/* L4 not established (yet) */
		if (conn->flags & CO_FL_ERROR || sc_ep_test(sc, SE_FL_ERROR))
			set_server_check_status(check, HCHK_STATUS_L4CON, err_msg);
		else if (expired)
			set_server_check_status(check, HCHK_STATUS_L4TOUT, err_msg);

		/*
		 * might be due to a server IP change.
		 * Let's trigger a DNS resolution if none are currently running.
		 */
		if (check->server)
			resolv_trigger_resolution(check->server->resolv_requester);

	}
	else if (conn->flags & CO_FL_WAIT_L6_CONN) {
		/* L6 not established (yet) */
		if (conn->flags & CO_FL_ERROR || sc_ep_test(sc, SE_FL_ERROR))
			set_server_check_status(check, HCHK_STATUS_L6RSP, err_msg);
		else if (expired)
			set_server_check_status(check, HCHK_STATUS_L6TOUT, err_msg);
	}
	else if (conn->flags & CO_FL_ERROR || sc_ep_test(sc, SE_FL_ERROR)) {
		/* I/O error after connection was established and before we could diagnose */
		set_server_check_status(check, HCHK_STATUS_SOCKERR, err_msg);
	}
	else if (expired) {
		enum healthcheck_status tout = HCHK_STATUS_L7TOUT;

		/* connection established but expired check */
		if (check->current_step && check->current_step->action == TCPCHK_ACT_EXPECT &&
		    check->current_step->expect.tout_status != HCHK_STATUS_UNKNOWN)
			tout = check->current_step->expect.tout_status;
		set_server_check_status(check, tout, err_msg);
	}

	TRACE_LEAVE(CHK_EV_HCHK_END|CHK_EV_HCHK_ERR, check);
	return;
}


/* Builds the server state header used by HTTP health-checks */
int httpchk_build_status_header(struct server *s, struct buffer *buf)
{
	int sv_state;
	int ratio;
	char addr[46];
	char port[6];
	const char *srv_hlt_st[7] = { "DOWN", "DOWN %d/%d",
				      "UP %d/%d", "UP",
				      "NOLB %d/%d", "NOLB",
				      "no check" };

	if (!(s->check.state & CHK_ST_ENABLED))
		sv_state = 6;
	else if (s->cur_state != SRV_ST_STOPPED) {
		if (s->check.health == s->check.rise + s->check.fall - 1)
			sv_state = 3; /* UP */
		else
			sv_state = 2; /* going down */

		if (s->cur_state == SRV_ST_STOPPING)
			sv_state += 2;
	} else {
		if (s->check.health)
			sv_state = 1; /* going up */
		else
			sv_state = 0; /* DOWN */
	}

	chunk_appendf(buf, srv_hlt_st[sv_state],
		      (s->cur_state != SRV_ST_STOPPED) ? (s->check.health - s->check.rise + 1) : (s->check.health),
		      (s->cur_state != SRV_ST_STOPPED) ? (s->check.fall) : (s->check.rise));

	addr_to_str(&s->addr, addr, sizeof(addr));
	if (s->addr.ss_family == AF_INET || s->addr.ss_family == AF_INET6)
		snprintf(port, sizeof(port), "%u", s->svc_port);
	else
		*port = 0;

	chunk_appendf(buf, "; address=%s; port=%s; name=%s/%s; node=%s; weight=%d/%d; scur=%d/%d; qcur=%d",
		      addr, port, s->proxy->id, s->id,
		      global.node,
		      (s->cur_eweight * s->proxy->lbprm.wmult + s->proxy->lbprm.wdiv - 1) / s->proxy->lbprm.wdiv,
		      (s->proxy->lbprm.tot_weight * s->proxy->lbprm.wmult + s->proxy->lbprm.wdiv - 1) / s->proxy->lbprm.wdiv,
		      s->cur_sess, s->proxy->beconn - s->proxy->queueslength,
		      s->queueslength);

	if ((s->cur_state == SRV_ST_STARTING) &&
	    ns_to_sec(now_ns) < s->counters.last_change + s->slowstart &&
	    ns_to_sec(now_ns) >= s->counters.last_change) {
		ratio = MAX(1, 100 * (ns_to_sec(now_ns) - s->counters.last_change) / s->slowstart);
		chunk_appendf(buf, "; throttle=%d%%", ratio);
	}

	return b_data(buf);
}

/**************************************************************************/
/***************** Health-checks based on connections *********************/
/**************************************************************************/
/* This function is used only for server health-checks. It handles connection
 * status updates including errors. If necessary, it wakes the check task up.
 * It returns 0 on normal cases, <0 if at least one close() has happened on the
 * connection (eg: reconnect). It relies on tcpcheck_main().
 */
int wake_srv_chk(struct stconn *sc)
{
	struct connection *conn;
	struct check *check = __sc_check(sc);
	struct email_alertq *q = container_of(check, typeof(*q), check);
	int ret = 0;

	TRACE_ENTER(CHK_EV_HCHK_WAKE, check);
	if (check->result != CHK_RES_UNKNOWN)
		goto end;

	if (check->server)
		HA_SPIN_LOCK(SERVER_LOCK, &check->server->lock);
	else
		HA_SPIN_LOCK(EMAIL_ALERTS_LOCK, &q->lock);

	/* we may have to make progress on the TCP checks */
	ret = tcpcheck_main(check);

	sc = check->sc;
	conn = sc_conn(sc);

	if (unlikely(!conn || conn->flags & CO_FL_ERROR || sc_ep_test(sc, SE_FL_ERROR))) {
		/* We may get error reports bypassing the I/O handlers, typically
		 * the case when sending a pure TCP check which fails, then the I/O
		 * handlers above are not called. This is completely handled by the
		 * main processing task so let's simply wake it up. If we get here,
		 * we expect errno to still be valid.
		 */
		TRACE_ERROR("report connection error", CHK_EV_HCHK_WAKE|CHK_EV_HCHK_END|CHK_EV_HCHK_ERR, check);
		chk_report_conn_err(check, errno, 0);
		task_wakeup(check->task, TASK_WOKEN_IO);
	}

	if (check->result != CHK_RES_UNKNOWN || ret == -1) {
		/* Check complete or aborted. Wake the check task up to be sure
		 * the result is handled ASAP. */
		ret = -1;
		task_wakeup(check->task, TASK_WOKEN_IO);
	}

	if (check->server)
		HA_SPIN_UNLOCK(SERVER_LOCK, &check->server->lock);
	else
		HA_SPIN_UNLOCK(EMAIL_ALERTS_LOCK, &q->lock);

  end:
	TRACE_LEAVE(CHK_EV_HCHK_WAKE, check);
	return ret;
}

/* This function checks if any I/O is wanted, and if so, attempts to do so */
struct task *srv_chk_io_cb(struct task *t, void *ctx, unsigned int state)
{
	struct stconn *sc = ctx;

	wake_srv_chk(sc);
	return NULL;
}

/* returns <0, 0, >0 if check thread 1 is respectively less loaded than,
 * equally as, or more loaded than thread 2. This is made to decide on
 * migrations so a margin is applied in either direction. For ease of
 * remembering the direction, consider this returns load1 - load2.
 */
static inline int check_thread_cmp_load(int thr1, int thr2)
{
	uint t1_load = _HA_ATOMIC_LOAD(&ha_thread_ctx[thr1].rq_total);
	uint t1_act  = _HA_ATOMIC_LOAD(&ha_thread_ctx[thr1].active_checks);
	uint t2_load = _HA_ATOMIC_LOAD(&ha_thread_ctx[thr2].rq_total);
	uint t2_act  = _HA_ATOMIC_LOAD(&ha_thread_ctx[thr2].active_checks);

	/* twice as more active checks is a significant difference */
	if (t1_act * 2 < t2_act)
		return -1;

	if (t2_act * 2 < t1_act)
		return 1;

	/* twice as more rqload with more checks is also a significant
	 * difference.
	 */
	if (t1_act <= t2_act && t1_load * 2 < t2_load)
		return -1;

	if (t2_act <= t1_act && t2_load * 2 < t1_load)
		return 1;

	/* otherwise they're roughly equal */
	return 0;
}

/* returns <0, 0, >0 if check thread 1's active checks count is respectively
 * higher than, equal, or lower than thread 2's. This is made to decide on
 * forced migrations upon overload, so only a very little margin is applied
 * here (~1%). For ease of remembering the direction, consider this returns
 * active1 - active2.
 */
static inline int check_thread_cmp_active(int thr1, int thr2)
{
	uint t1_act  = _HA_ATOMIC_LOAD(&ha_thread_ctx[thr1].active_checks);
	uint t2_act  = _HA_ATOMIC_LOAD(&ha_thread_ctx[thr2].active_checks);

	if (t1_act * 128 >= t2_act * 129)
		return 1;
	if (t2_act * 128 >= t1_act * 129)
		return -1;
	return 0;
}


/* manages a server health-check that uses a connection. Returns
 * the time the task accepts to wait, or TIME_ETERNITY for infinity.
 *
 * Please do NOT place any return statement in this function and only leave
 * via the out_unlock label.
 */
struct task *process_chk_conn(struct task *t, void *context, unsigned int state)
{
	struct check *check = context;
	struct proxy *proxy = check->proxy;
	struct stconn *sc;
	struct connection *conn;
	int rv;
	int expired = tick_is_expired(t->expire, now_ms);

	TRACE_ENTER(CHK_EV_TASK_WAKE, check);

	if (check->state & CHK_ST_SLEEPING) {
		/* This check just restarted. It's still time to verify if
		 * we're on an overloaded thread or if a more suitable one is
		 * available. This helps spread the load over the available
		 * threads, without migrating too often. For this we'll check
		 * our load, and pick a random thread, check if it has less
		 * than half of the current thread's load, and if so we'll
		 * bounce the task there. It's possible because it's not yet
		 * tied to the current thread. The other thread will not bounce
		 * the task again because we're setting CHK_ST_READY indicating
		 * a migration.
		 */
		uint run_checks = _HA_ATOMIC_LOAD(&th_ctx->running_checks);
		uint my_load = HA_ATOMIC_LOAD(&th_ctx->rq_total);
		uint attempts = MIN(global.nbthread, 3);

		if (check->state & CHK_ST_READY) {
			/* check was migrated, active already counted */
			activity[tid].check_adopted++;
		}
		else {
			/* first wakeup, let's check if another thread is less loaded
			 * than this one in order to smooth the load. If the current
			 * thread is not yet overloaded, we attempt an opportunistic
			 * migration to another thread that is not full and that is
			 * significantly less loaded. And if the current thread is
			 * already overloaded, we attempt a forced migration to a
			 * thread with less active checks. We try at most 3 random
			 * other thread.
			 */
			while (attempts-- > 0 &&
			       (!LIST_ISEMPTY(&th_ctx->queued_checks) || my_load >= 3) &&
			       _HA_ATOMIC_LOAD(&th_ctx->active_checks) >= 3) {
				uint new_tid  = statistical_prng_range(global.nbthread);

				if (new_tid == tid)
					continue;

				ALREADY_CHECKED(new_tid);

				if (check_thread_cmp_active(tid, new_tid) > 0 &&
				    (run_checks >= global.tune.max_checks_per_thread ||
				     check_thread_cmp_load(tid, new_tid) > 0)) {
					/* Found one. Let's migrate the task over there. We have to
					 * remove it from the WQ first and kill its expire time
					 * otherwise the scheduler will reinsert it and trigger a
					 * BUG_ON() as we're not allowed to call task_queue() for a
					 * foreign thread. The recipient will restore the expiration.
					 */
					check->state |= CHK_ST_READY;
					HA_ATOMIC_INC(&ha_thread_ctx[new_tid].active_checks);
					task_unlink_wq(t);
					t->expire = TICK_ETERNITY;
					task_set_thread(t, new_tid);
					task_wakeup(t, TASK_WOKEN_MSG);
					TRACE_LEAVE(CHK_EV_TASK_WAKE, check);
					return t;
				}
			}
			/* check just woke up, count it as active */
			_HA_ATOMIC_INC(&th_ctx->active_checks);
		}

		/* OK we're keeping it so this check is ours now */
		task_set_thread(t, tid);
		check->state &= ~CHK_ST_SLEEPING;

		/* if we just woke up and the thread is full of running, or
		 * already has others waiting, we might have to wait in queue
		 * (for health checks only). This means !SLEEPING && !READY.
		 */
		if (check->server &&
		    (!LIST_ISEMPTY(&th_ctx->queued_checks) ||
		     (global.tune.max_checks_per_thread &&
		      _HA_ATOMIC_LOAD(&th_ctx->running_checks) >= global.tune.max_checks_per_thread))) {
			TRACE_DEVEL("health-check queued", CHK_EV_TASK_WAKE, check);
			t->expire = TICK_ETERNITY;
			LIST_APPEND(&th_ctx->queued_checks, &check->check_queue);

			/* reset fastinter flag (if set) so that srv_getinter()
			 * only returns fastinter if server health is degraded
			 */
			check->state &= ~CHK_ST_FASTINTER;
			goto out_leave;
		}

		/* OK let's run, now we cannot roll back anymore */
		check->state |= CHK_ST_READY;
		activity[tid].check_started++;
		_HA_ATOMIC_INC(&th_ctx->running_checks);
	}

	/* at this point, CHK_ST_SLEEPING = 0 and CHK_ST_READY = 1*/

	if (check->server)
		HA_SPIN_LOCK(SERVER_LOCK, &check->server->lock);

	if (!(check->state & (CHK_ST_INPROGRESS|CHK_ST_IN_ALLOC|CHK_ST_OUT_ALLOC))) {
		/* This task might have bounced from another overloaded thread, it
		 * needs an expiration timer that was supposed to be now, but that
		 * was erased during the bounce.
		 */
		if (!tick_isset(t->expire)) {
			t->expire = tick_add(now_ms, 0);
			expired = 0;
		}
	}

	if (unlikely(check->state & CHK_ST_PURGE)) {
		TRACE_STATE("health-check state to purge", CHK_EV_TASK_WAKE, check);
	}
	else if (!(check->state & (CHK_ST_INPROGRESS))) {
		/* no check currently running, but we might have been woken up
		 * before the timer's expiration to update it according to a
		 * new state (e.g. fastinter), in which case we'll reprogram
		 * the new timer.
		 */
		if (!tick_is_expired(t->expire, now_ms)) { /* woke up too early */
			if (check->server) {
				int new_exp = tick_add(now_ms, MS_TO_TICKS(srv_getinter(check)));

				if (tick_is_expired(new_exp, t->expire)) {
					TRACE_STATE("health-check was advanced", CHK_EV_TASK_WAKE, check);
					goto update_timer;
				}
			}

			TRACE_STATE("health-check wake up too early", CHK_EV_TASK_WAKE, check);
			goto out_unlock;
		}

		/* we don't send any health-checks when the proxy is
		 * stopped, the server should not be checked or the check
		 * is disabled.
		 */
		if (((check->state & (CHK_ST_ENABLED | CHK_ST_PAUSED)) != CHK_ST_ENABLED) ||
		    (proxy->flags & (PR_FL_DISABLED|PR_FL_STOPPED))) {
			TRACE_STATE("health-check paused or disabled", CHK_EV_TASK_WAKE, check);
			goto reschedule;
		}

		/* we'll initiate a new check */
		set_server_check_status(check, HCHK_STATUS_START, NULL);

		check->state |= CHK_ST_INPROGRESS;
		TRACE_STATE("init new health-check", CHK_EV_TASK_WAKE|CHK_EV_HCHK_START, check);

		check->current_step = NULL;

		check->sc = sc_new_from_check(check, SC_FL_NONE);
		if (!check->sc) {
			set_server_check_status(check, HCHK_STATUS_SOCKERR, NULL);
			goto end;
		}
		tcpcheck_main(check);
		expired = 0;
	}

	/* there was a test running.
	 * First, let's check whether there was an uncaught error,
	 * which can happen on connect timeout or error.
	 */
	if (check->result == CHK_RES_UNKNOWN && likely(!(check->state & CHK_ST_PURGE))) {
		sc = check->sc;
		conn = sc_conn(sc);

		/* Here the connection must be defined. Otherwise the
		 * error would have already been detected
		 */
		if ((conn && ((conn->flags & CO_FL_ERROR) || sc_ep_test(sc, SE_FL_ERROR))) || expired) {
			TRACE_ERROR("report connection error", CHK_EV_TASK_WAKE|CHK_EV_HCHK_END|CHK_EV_HCHK_ERR, check);
			chk_report_conn_err(check, 0, expired);
		}
		else {
			if (check->state & CHK_ST_CLOSE_CONN) {
				TRACE_DEVEL("closing current connection", CHK_EV_TASK_WAKE|CHK_EV_HCHK_RUN, check);
				check->state &= ~CHK_ST_CLOSE_CONN;
				if (!sc_reset_endp(check->sc)) {
					/* error will be handled by tcpcheck_main().
					 * On success, remove all flags except SE_FL_DETACHED
					 */
					sc_ep_clr(check->sc, ~SE_FL_DETACHED);
				}
				tcpcheck_main(check);
			}
			if (check->result == CHK_RES_UNKNOWN) {
				TRACE_DEVEL("health-check not expired", CHK_EV_TASK_WAKE|CHK_EV_HCHK_RUN, check);
				goto out_unlock; /* timeout not reached, wait again */
			}
		}
	}

	/* check complete or aborted */
	TRACE_STATE("health-check complete or aborted", CHK_EV_TASK_WAKE|CHK_EV_HCHK_END, check);

	/* check->sc may be NULL when the healthcheck is purged */
	check->current_step = NULL;
	sc = check->sc;
	conn = (sc ? sc_conn(sc) : NULL);

	if (conn && conn->xprt) {
		/* The check was aborted and the connection was not yet closed.
		 * This can happen upon timeout, or when an external event such
		 * as a failed response coupled with "observe layer7" caused the
		 * server state to be suddenly changed.
		 */
		se_shutdown(sc->sedesc, SE_SHR_DRAIN|SE_SHW_SILENT);
	}

	if (sc) {
		sc_destroy(sc);
		check->sc = NULL;
	}

	if (check->sess != NULL) {
		vars_prune(&check->vars, check->sess, NULL);
		session_free(check->sess);
		check->sess = NULL;
	}

  end:
	if (check->server && likely(!(check->state & CHK_ST_PURGE))) {
		if (check->result == CHK_RES_FAILED) {
			/* a failure or timeout detected */
			TRACE_DEVEL("report failure", CHK_EV_TASK_WAKE|CHK_EV_HCHK_END|CHK_EV_HCHK_ERR, check);
			check_notify_failure(check);
		}
		else if (check->result == CHK_RES_CONDPASS) {
			/* check is OK but asks for stopping mode */
			TRACE_DEVEL("report conditional success", CHK_EV_TASK_WAKE|CHK_EV_HCHK_END|CHK_EV_HCHK_SUCC, check);
			check_notify_stopping(check);
		}
		else if (check->result == CHK_RES_PASSED) {
			/* a success was detected */
			TRACE_DEVEL("report success", CHK_EV_TASK_WAKE|CHK_EV_HCHK_END|CHK_EV_HCHK_SUCC, check);
			check_notify_success(check);
		}
	}

	b_dequeue(&check->buf_wait);

	check_release_buf(check, &check->bi);
	check_release_buf(check, &check->bo);
	_HA_ATOMIC_DEC(&th_ctx->running_checks);
	_HA_ATOMIC_DEC(&th_ctx->active_checks);
	check->state &= ~(CHK_ST_INPROGRESS|CHK_ST_IN_ALLOC|CHK_ST_OUT_ALLOC);
	check->state &= ~CHK_ST_READY;
	check->state |= CHK_ST_SLEEPING;

 update_timer:
	/* when going to sleep, we need to check if other checks are waiting
	 * for a slot. If so we pick them out of the queue and wake them up.
	 */
	if (check->server && (check->state & CHK_ST_SLEEPING)) {
		if (!LIST_ISEMPTY(&th_ctx->queued_checks) &&
		    _HA_ATOMIC_LOAD(&th_ctx->running_checks) < global.tune.max_checks_per_thread) {
			struct check *next_chk = LIST_ELEM(th_ctx->queued_checks.n, struct check *, check_queue);

			/* wake up pending task */
			LIST_DEL_INIT(&next_chk->check_queue);

			activity[tid].check_started++;
			_HA_ATOMIC_INC(&th_ctx->running_checks);
			next_chk->state |= CHK_ST_READY;
			/* now running */
			task_wakeup(next_chk->task, TASK_WOKEN_RES);
		}
	}

	if (check->server) {
		rv = 0;
		if (global.spread_checks > 0) {
			rv = srv_getinter(check) * global.spread_checks / 100;
			rv -= (int) (2 * rv * (statistical_prng() / 4294967295.0));
		}
		t->expire = tick_add(now_ms, MS_TO_TICKS(srv_getinter(check) + rv));
		/* reset fastinter flag (if set) so that srv_getinter()
		 * only returns fastinter if server health is degraded
		 */
		check->state &= ~CHK_ST_FASTINTER;
	}

 reschedule:
	if (proxy->flags & (PR_FL_DISABLED|PR_FL_STOPPED))
		t->expire = TICK_ETERNITY;
	else {
		while (tick_is_expired(t->expire, now_ms))
			t->expire = tick_add(t->expire, MS_TO_TICKS(check->inter));
	}

 out_unlock:
	if (check->server)
		HA_SPIN_UNLOCK(SERVER_LOCK, &check->server->lock);

 out_leave:
	TRACE_LEAVE(CHK_EV_TASK_WAKE, check);

	/* Free the check if set to PURGE. After this, the check instance may be
	 * freed via the srv_drop invocation, so it must not be accessed after
	 * this point.
	 */
	if (unlikely(check->state & CHK_ST_PURGE)) {
		free_check(check);
		if (check->server)
			srv_drop(check->server);

		t = NULL;
	}

	return t;
}


/**************************************************************************/
/************************** Init/deinit checks ****************************/
/**************************************************************************/
/*
 * Tries to grab a buffer and to re-enables processing on check <target>. The
 * check flags are used to figure what buffer was requested. It returns 1 if the
 * allocation succeeds, in which case the I/O tasklet is woken up, or 0 if it's
 * impossible to wake up and we prefer to be woken up later.
 */
int check_buf_available(void *target)
{
	struct check *check = target;

	BUG_ON(!check->sc);

	if ((check->state & CHK_ST_IN_ALLOC) && b_alloc(&check->bi, DB_CHANNEL)) {
		TRACE_STATE("unblocking check, input buffer allocated", CHK_EV_TCPCHK_EXP|CHK_EV_RX_BLK, check);
		check->state &= ~CHK_ST_IN_ALLOC;
		tasklet_wakeup(check->sc->wait_event.tasklet);
		return 1;
	}
	if ((check->state & CHK_ST_OUT_ALLOC) && b_alloc(&check->bo, DB_CHANNEL)) {
		TRACE_STATE("unblocking check, output buffer allocated", CHK_EV_TCPCHK_SND|CHK_EV_TX_BLK, check);
		check->state &= ~CHK_ST_OUT_ALLOC;
		tasklet_wakeup(check->sc->wait_event.tasklet);
		return 1;
	}

	return 0;
}

/*
 * Allocate a buffer. If it fails, it adds the check in buffer wait queue.
 */
struct buffer *check_get_buf(struct check *check, struct buffer *bptr)
{
	struct buffer *buf = NULL;

	if (likely(!LIST_INLIST(&check->buf_wait.list)) &&
	    unlikely((buf = b_alloc(bptr, DB_CHANNEL)) == NULL)) {
		b_queue(DB_CHANNEL, &check->buf_wait, check, check_buf_available);
	}
	return buf;
}

/*
 * Release a buffer, if any, and try to wake up entities waiting in the buffer
 * wait queue.
 */
void check_release_buf(struct check *check, struct buffer *bptr)
{
	if (bptr->size) {
		b_free(bptr);
		offer_buffers(check->buf_wait.target, 1);
	}
}

const char *init_check(struct check *check, int type)
{
	check->type = type;

	check->bi = BUF_NULL;
	check->bo = BUF_NULL;
	LIST_INIT(&check->buf_wait.list);
	LIST_INIT(&check->check_queue);
	return NULL;
}

/* Liberates the resources allocated for a check.
 *
 * This function must only be run by the thread owning the check.
 */
void free_check(struct check *check)
{
	/* For agent-check, free the rules / vars from the server. This is not
	 * done for health-check : the proxy is the owner of the rules / vars
	 * in this case.
	 */
	if (check->state & CHK_ST_AGENT) {
		free_tcpcheck_vars(&check->tcpcheck_rules->preset_vars);
		ha_free(&check->tcpcheck_rules);
	}

	task_destroy(check->task);

	check_release_buf(check, &check->bi);
	check_release_buf(check, &check->bo);
	if (check->sc) {
		sc_destroy(check->sc);
		check->sc = NULL;
	}
}

/* This function must be used in order to free a started check. The check will
 * be scheduled for a next execution in order to properly close and free all
 * check elements.
 *
 * Non thread-safe.
 */
void check_purge(struct check *check)
{
	check->state |= CHK_ST_PURGE;
	task_wakeup(check->task, TASK_WOKEN_OTHER);
}

/* manages a server health-check. Returns the time the task accepts to wait, or
 * TIME_ETERNITY for infinity.
 */
struct task *process_chk(struct task *t, void *context, unsigned int state)
{
	struct check *check = context;

	if (check->type == PR_O2_EXT_CHK)
		return process_chk_proc(t, context, state);
	return process_chk_conn(t, context, state);

}


int start_check_task(struct check *check, int mininter,
			    int nbcheck, int srvpos)
{
	struct task *t;

	/* task for the check. Process-based checks exclusively run on thread 1. */
	if (check->type == PR_O2_EXT_CHK)
		t = task_new_on(0);
	else
		t = task_new_anywhere();

	if (!t)
		goto fail_alloc_task;

	check->task = t;
	t->process = process_chk;
	t->context = check;

	if (mininter < srv_getinter(check))
		mininter = srv_getinter(check);

	if (global.spread_checks > 0) {
		int rnd;

		rnd  = srv_getinter(check) * global.spread_checks / 100;
		rnd -= (int) (2 * rnd * (ha_random32() / 4294967295.0));
		mininter += rnd;
	}

	if (global.max_spread_checks && mininter > global.max_spread_checks)
		mininter = global.max_spread_checks;

	/* check this every ms */
	t->expire = tick_add(now_ms, MS_TO_TICKS(mininter * srvpos / nbcheck));
	check->start = now_ns;
	task_queue(t);

	return 1;

  fail_alloc_task:
	ha_alert("Starting [%s:%s] check: out of memory.\n",
		 check->server->proxy->id, check->server->id);
	return 0;
}

/*
 * Start health-check.
 * Returns 0 if OK, ERR_FATAL on error, and prints the error in this case.
 */
static int start_checks()
{

	struct proxy *px;
	struct server *s;
	int nbcheck=0, mininter=0, srvpos=0;

	/* 0- init the dummy frontend used to create all checks sessions */
	init_new_proxy(&checks_fe);
	checks_fe.id = strdup("CHECKS-FE");
	if (!checks_fe.id) {
		ha_alert("Out of memory creating the checks frontend.\n");
		return ERR_ALERT | ERR_FATAL;
	}
	checks_fe.cap = PR_CAP_FE | PR_CAP_BE;
        checks_fe.mode = PR_MODE_TCP;
	checks_fe.maxconn = 0;
	checks_fe.conn_retries = CONN_RETRIES;
	checks_fe.options2 |= PR_O2_INDEPSTR | PR_O2_SMARTCON | PR_O2_SMARTACC;
	checks_fe.timeout.client = TICK_ETERNITY;

	/* 1- count the checkers to run simultaneously.
	 * We also determine the minimum interval among all of those which
	 * have an interval larger than SRV_CHK_INTER_THRES. This interval
	 * will be used to spread their start-up date. Those which have
	 * a shorter interval will start independently and will not dictate
	 * too short an interval for all others.
	 */
	for (px = proxies_list; px; px = px->next) {
		for (s = px->srv; s; s = s->next) {
			if (s->check.state & CHK_ST_CONFIGURED) {
				nbcheck++;
				if ((srv_getinter(&s->check) >= SRV_CHK_INTER_THRES) &&
				    (!mininter || mininter > srv_getinter(&s->check)))
					mininter = srv_getinter(&s->check);
			}

			if (s->agent.state & CHK_ST_CONFIGURED) {
				nbcheck++;
				if ((srv_getinter(&s->agent) >= SRV_CHK_INTER_THRES) &&
				    (!mininter || mininter > srv_getinter(&s->agent)))
					mininter = srv_getinter(&s->agent);
			}
		}
	}

	if (!nbcheck)
		return ERR_NONE;

	srand((unsigned)time(NULL));

	/* 2- start them as far as possible from each other. For this, we will
	 * start them after their interval is set to the min interval divided
	 * by the number of servers, weighted by the server's position in the
	 * list.
	 */
	for (px = proxies_list; px; px = px->next) {
		if ((px->options2 & PR_O2_CHK_ANY) == PR_O2_EXT_CHK) {
			if (init_pid_list()) {
				ha_alert("Starting [%s] check: out of memory.\n", px->id);
				return ERR_ALERT | ERR_FATAL;
			}
		}

		for (s = px->srv; s; s = s->next) {
			/* A task for the main check */
			if (s->check.state & CHK_ST_CONFIGURED) {
				if (s->check.type == PR_O2_EXT_CHK) {
					if (!prepare_external_check(&s->check))
						return ERR_ALERT | ERR_FATAL;
				}
				if (!start_check_task(&s->check, mininter, nbcheck, srvpos))
					return ERR_ALERT | ERR_FATAL;
				srvpos++;
			}

			/* A task for a auxiliary agent check */
			if (s->agent.state & CHK_ST_CONFIGURED) {
				if (!start_check_task(&s->agent, mininter, nbcheck, srvpos)) {
					return ERR_ALERT | ERR_FATAL;
				}
				srvpos++;
			}
		}
	}
	return ERR_NONE;
}


/*
 * Return value:
 *   the port to be used for the health check
 *   0 in case no port could be found for the check
 */
static int srv_check_healthcheck_port(struct check *chk)
{
	int i = 0;
	struct server *srv = NULL;

	srv = chk->server;

	/* by default, we use the health check port configured */
	if (chk->port > 0)
		return chk->port;

	/* try to get the port from check_core.addr if check.port not set */
	i = get_host_port(&chk->addr);
	if (i > 0)
		return i;

	/* try to get the port from server address */
	/* prevent MAPPORTS from working at this point, since checks could
	 * not be performed in such case (MAPPORTS impose a relative ports
	 * based on live traffic)
	 */
	if (srv->flags & SRV_F_MAPPORTS)
		return 0;

	i = srv->svc_port; /* by default */
	if (i > 0)
		return i;

	return 0;
}

/* Initializes an health-check attached to the server <srv>. Non-zero is returned
 * if an error occurred.
 */
int init_srv_check(struct server *srv)
{
	const char *err;
	struct tcpcheck_rule *r;
	int ret = ERR_NONE;
	int check_type;

	if (!srv->do_check || !(srv->proxy->cap & PR_CAP_BE))
		goto out;

	check_type = srv->check.tcpcheck_rules->flags & TCPCHK_RULES_PROTO_CHK;

	if (!(srv->flags & SRV_F_DYNAMIC)) {
		/* If neither a port nor an addr was specified and no check
		 * transport layer is forced, then the transport layer used by
		 * the checks is the same as for the production traffic.
		 * Otherwise we use raw_sock by default, unless one is
		 * specified.
		 */
		if (!srv->check.port && !is_addr(&srv->check.addr)) {
			if (!srv->check.use_ssl && srv->use_ssl != -1) {
				srv->check.use_ssl = srv->use_ssl;
				srv->check.xprt    = srv->xprt;
			}
			else if (srv->check.use_ssl == 1)
				srv->check.xprt = xprt_get(XPRT_SSL);
			srv->check.send_proxy |= (srv->pp_opts);
		}
		else if (srv->check.use_ssl == 1)
			srv->check.xprt = xprt_get(XPRT_SSL);
	}
	else {
		/* For dynamic servers, check-ssl and check-send-proxy must be
		 * explicitly defined even if the check port was not
		 * overridden.
		 */
		if (srv->check.use_ssl == 1)
			srv->check.xprt = xprt_get(XPRT_SSL);
	}

	/* Inherit the mux protocol from the server if not already defined for
	 * the check
	 */
	if (srv->mux_proto && !srv->check.mux_proto &&
	    ((srv->mux_proto->mode == PROTO_MODE_HTTP && check_type == TCPCHK_RULES_HTTP_CHK) ||
	     (srv->mux_proto->mode == PROTO_MODE_SPOP && check_type == TCPCHK_RULES_SPOP_CHK) ||
	     (srv->mux_proto->mode == PROTO_MODE_TCP && check_type != TCPCHK_RULES_HTTP_CHK))) {
		srv->check.mux_proto = srv->mux_proto;
	}
	/* test that check proto is valid if explicitly defined */
	else if (srv->check.mux_proto &&
	         ((srv->check.mux_proto->mode == PROTO_MODE_HTTP && check_type != TCPCHK_RULES_HTTP_CHK) ||
		  (srv->check.mux_proto->mode == PROTO_MODE_SPOP && check_type != TCPCHK_RULES_SPOP_CHK) ||
	          (srv->check.mux_proto->mode == PROTO_MODE_TCP && check_type == TCPCHK_RULES_HTTP_CHK))) {
		ha_alert("config: %s '%s': server '%s' uses an incompatible MUX protocol for the selected check type\n",
		         proxy_type_str(srv->proxy), srv->proxy->id, srv->id);
		ret |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	/* validate <srv> server health-check settings */

	/* We need at least a service port, a check port or the first tcp-check
	 * rule must be a 'connect' one when checking an IPv4/IPv6 server.
	 */
	if ((srv_check_healthcheck_port(&srv->check) != 0) ||
	    (!is_inet_addr(&srv->check.addr) && (is_addr(&srv->check.addr) || !is_inet_addr(&srv->addr))))
		goto init;

	if (!srv->proxy->tcpcheck_rules.list || LIST_ISEMPTY(srv->proxy->tcpcheck_rules.list)) {
		ha_alert("config: %s '%s': server '%s' has neither service port nor check port.\n",
			 proxy_type_str(srv->proxy), srv->proxy->id, srv->id);
		ret |= ERR_ALERT | ERR_ABORT;
		goto out;
	}

	/* search the first action (connect / send / expect) in the list */
	r = get_first_tcpcheck_rule(&srv->proxy->tcpcheck_rules);
	if (!r || (r->action != TCPCHK_ACT_CONNECT) || (!r->connect.port && !get_host_port(&r->connect.addr))) {
		ha_alert("config: %s '%s': server '%s' has neither service port nor check port "
			 "nor tcp_check rule 'connect' with port information.\n",
			 proxy_type_str(srv->proxy), srv->proxy->id, srv->id);
		ret |= ERR_ALERT | ERR_ABORT;
		goto out;
	}

	/* scan the tcp-check ruleset to ensure a port has been configured */
	list_for_each_entry(r, srv->proxy->tcpcheck_rules.list, list) {
		if ((r->action == TCPCHK_ACT_CONNECT) && (!r->connect.port && !get_host_port(&r->connect.addr))) {
			ha_alert("config: %s '%s': server '%s' has neither service port nor check port, "
				 "and a tcp_check rule 'connect' with no port information.\n",
				 proxy_type_str(srv->proxy), srv->proxy->id, srv->id);
			ret |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
	}

  init:
	err = init_check(&srv->check, srv->proxy->options2 & PR_O2_CHK_ANY);
	if (err) {
		ha_alert("config: %s '%s': unable to init check for server '%s' (%s).\n",
			 proxy_type_str(srv->proxy), srv->proxy->id, srv->id, err);
		ret |= ERR_ALERT | ERR_ABORT;
		goto out;
	}
	srv->check.state |= CHK_ST_CONFIGURED | CHK_ST_ENABLED | CHK_ST_SLEEPING;
	srv_take(srv);

	/* Only increment maxsock for servers from the configuration. Dynamic
	 * servers at the moment are not taken into account for the estimation
	 * of the resources limits.
	 */
	if (global.mode & MODE_STARTING)
		global.maxsock++;

  out:
	return ret;
}

/* Initializes an agent-check attached to the server <srv>. Non-zero is returned
 * if an error occurred.
 */
int init_srv_agent_check(struct server *srv)
{
	struct tcpcheck_rule *chk;
	const char *err;
	int ret = ERR_NONE;

	if (!srv->do_agent || !(srv->proxy->cap & PR_CAP_BE))
		goto out;

	/* If there is no connect rule preceding all send / expect rules, an
	 * implicit one is inserted before all others.
	 */
	chk = get_first_tcpcheck_rule(srv->agent.tcpcheck_rules);
	if (!chk || chk->action != TCPCHK_ACT_CONNECT) {
		chk = calloc(1, sizeof(*chk));
		if (!chk) {
			ha_alert("%s '%s': unable to add implicit tcp-check connect rule"
				 " to agent-check for server '%s' (out of memory).\n",
				 proxy_type_str(srv->proxy), srv->proxy->id, srv->id);
			ret |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		chk->action = TCPCHK_ACT_CONNECT;
		chk->connect.options = (TCPCHK_OPT_DEFAULT_CONNECT|TCPCHK_OPT_IMPLICIT);
		LIST_INSERT(srv->agent.tcpcheck_rules->list, &chk->list);
	}

	/* <chk> is always defined here and it is a CONNECT action. If there is
	 * a preset variable, it means there is an agent string defined and data
	 * will be sent after the connect.
	 */
	if (!LIST_ISEMPTY(&srv->agent.tcpcheck_rules->preset_vars))
		chk->connect.options |= TCPCHK_OPT_HAS_DATA;


	err = init_check(&srv->agent, PR_O2_TCPCHK_CHK);
	if (err) {
		ha_alert("config: %s '%s': unable to init agent-check for server '%s' (%s).\n",
			 proxy_type_str(srv->proxy), srv->proxy->id, srv->id, err);
		ret |= ERR_ALERT | ERR_ABORT;
		goto out;
	}

	if (!srv->agent.inter)
		srv->agent.inter = srv->check.inter;

	srv->agent.state |= CHK_ST_CONFIGURED | CHK_ST_ENABLED | CHK_ST_SLEEPING | CHK_ST_AGENT;
	srv_take(srv);

	/* Only increment maxsock for servers from the configuration. Dynamic
	 * servers at the moment are not taken into account for the estimation
	 * of the resources limits.
	 */
	if (global.mode & MODE_STARTING)
		global.maxsock++;

  out:
	return ret;
}

static void deinit_srv_check(struct server *srv)
{
	if (srv->check.state & CHK_ST_CONFIGURED) {
		free_check(&srv->check);
		/* it is safe to drop now since the main server reference is still held by the proxy */
		srv_drop(srv);
	}
	srv->check.state &= ~CHK_ST_CONFIGURED & ~CHK_ST_ENABLED;
	srv->do_check = 0;
}


static void deinit_srv_agent_check(struct server *srv)
{
	if (srv->agent.state & CHK_ST_CONFIGURED) {
		free_check(&srv->agent);
		/* it is safe to drop now since the main server reference is still held by the proxy */
		srv_drop(srv);
	}

	srv->agent.state &= ~CHK_ST_CONFIGURED & ~CHK_ST_ENABLED & ~CHK_ST_AGENT;
	srv->do_agent = 0;
}

REGISTER_POST_SERVER_CHECK(init_srv_check);
REGISTER_POST_SERVER_CHECK(init_srv_agent_check);
REGISTER_POST_CHECK(start_checks);

REGISTER_SERVER_DEINIT(deinit_srv_check);
REGISTER_SERVER_DEINIT(deinit_srv_agent_check);

/* perform minimal initializations */
static void init_checks()
{
	int i;

	for (i = 0; i < MAX_THREADS; i++)
		LIST_INIT(&ha_thread_ctx[i].queued_checks);
}

INITCALL0(STG_PREPARE, init_checks);

/**************************************************************************/
/************************** Check sample fetches **************************/
/**************************************************************************/

static struct sample_fetch_kw_list smp_kws = {ILH, {
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &smp_kws);


/**************************************************************************/
/************************ Check's parsing functions ***********************/
/**************************************************************************/
/* Parse the "addr" server keyword */
static int srv_parse_addr(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
			  char **errmsg)
{
	struct sockaddr_storage *sk;
	int port1, port2, err_code = 0;


	if (!*args[*cur_arg+1]) {
		memprintf(errmsg, "'%s' expects <ipv4|ipv6> as argument.", args[*cur_arg]);
		goto error;
	}

	sk = str2sa_range(args[*cur_arg+1], NULL, &port1, &port2, NULL, NULL, NULL, errmsg, NULL, NULL, NULL,
	                  PA_O_RESOLVE | PA_O_PORT_OK | PA_O_STREAM | PA_O_CONNECT);
	if (!sk) {
		memprintf(errmsg, "'%s' : %s", args[*cur_arg], *errmsg);
		goto error;
	}

	srv->check.addr = *sk;
	/* if agentaddr was never set, we can use addr */
	if (!(srv->flags & SRV_F_AGENTADDR))
		srv->agent.addr = *sk;

  out:
	return err_code;

 error:
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

/* Parse the "agent-addr" server keyword */
static int srv_parse_agent_addr(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
				char **errmsg)
{
	struct sockaddr_storage sk;
	int err_code = 0;

	if (!*(args[*cur_arg+1])) {
		memprintf(errmsg, "'%s' expects an address as argument.", args[*cur_arg]);
		goto error;
	}
	memset(&sk, 0, sizeof(sk));
	if (str2ip(args[*cur_arg + 1], &sk) == NULL) {
		memprintf(errmsg, "parsing agent-addr failed. Check if '%s' is correct address.", args[*cur_arg+1]);
		goto error;
	}
	set_srv_agent_addr(srv, &sk);

  out:
	return err_code;

  error:
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

/* Parse the "agent-check" server keyword */
static int srv_parse_agent_check(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
				 char **errmsg)
{
	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = srv->agent.tcpcheck_rules;
	struct tcpcheck_rule *chk;
	int err_code = 0;

	if (srv->do_agent)
		goto out;

	if (!(curpx->cap & PR_CAP_BE)) {
		memprintf(errmsg, "'%s' ignored because %s '%s' has no backend capability",
			  args[*cur_arg], proxy_type_str(curpx), curpx->id);
		return ERR_WARN;
	}

	if (!rules) {
		rules = calloc(1, sizeof(*rules));
		if (!rules) {
			memprintf(errmsg, "out of memory.");
			goto error;
		}
		LIST_INIT(&rules->preset_vars);
		srv->agent.tcpcheck_rules = rules;
	}
	rules->list  = NULL;
	rules->flags = 0;

	rs = find_tcpcheck_ruleset("*agent-check");
	if (rs)
		goto ruleset_found;

	rs = create_tcpcheck_ruleset("*agent-check");
	if (rs == NULL) {
		memprintf(errmsg, "out of memory.");
		goto error;
	}

	chk = parse_tcpcheck_send((char *[]){"tcp-check", "send-lf", "%[var(check.agent_string)]", ""},
				  1, curpx, &rs->rules, srv->conf.file, srv->conf.line, errmsg);
	if (!chk) {
		memprintf(errmsg, "'%s': %s", args[*cur_arg], *errmsg);
		goto error;
	}
	chk->index = 0;
	LIST_APPEND(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "custom", ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_AGENT_CHK,
				    srv->conf.file, srv->conf.line, errmsg);
	if (!chk) {
		memprintf(errmsg, "'%s': %s", args[*cur_arg], *errmsg);
		goto error;
	}
	chk->expect.custom = tcpcheck_agent_expect_reply;
	chk->index = 1;
	LIST_APPEND(&rs->rules, &chk->list);

  ruleset_found:
	rules->list = &rs->rules;
	rules->flags &= ~(TCPCHK_RULES_PROTO_CHK|TCPCHK_RULES_UNUSED_RS);
	rules->flags |= TCPCHK_RULES_AGENT_CHK;
	srv->do_agent = 1;

  out:
	return err_code;

  error:
	deinit_srv_agent_check(srv);
	free_tcpcheck_ruleset(rs);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

/* Parse the "agent-inter" server keyword */
static int srv_parse_agent_inter(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
				 char **errmsg)
{
	const char *err = NULL;
	unsigned int delay;
	int err_code = 0;

	if (!*(args[*cur_arg+1])) {
		memprintf(errmsg, "'%s' expects a delay as argument.", args[*cur_arg]);
		goto error;
	}

	err = parse_time_err(args[*cur_arg+1], &delay, TIME_UNIT_MS);
	if (err == PARSE_TIME_OVER) {
		memprintf(errmsg, "timer overflow in argument <%s> to <%s> of server %s, maximum value is 2147483647 ms (~24.8 days).",
			  args[*cur_arg+1], args[*cur_arg], srv->id);
		goto error;
	}
	else if (err == PARSE_TIME_UNDER) {
		memprintf(errmsg, "timer underflow in argument <%s> to <%s> of server %s, minimum non-null value is 1 ms.",
			  args[*cur_arg+1], args[*cur_arg], srv->id);
		goto error;
	}
	else if (err) {
		memprintf(errmsg, "unexpected character '%c' in 'agent-inter' argument of server %s.",
			  *err, srv->id);
		goto error;
	}
	if (delay <= 0) {
		memprintf(errmsg, "invalid value %d for argument '%s' of server %s.",
			  delay, args[*cur_arg], srv->id);
		goto error;
	}
	srv->agent.inter = delay;

	if (warn_if_lower(args[*cur_arg+1], 100)) {
		memprintf(errmsg, "'%s %u' in server '%s' is suspiciously small for a value in milliseconds. Please use an explicit unit ('%ums') if that was the intent",
		          args[*cur_arg], delay, srv->id, delay);
		err_code |= ERR_WARN;
	}

  out:
	return err_code;

  error:
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

/* Parse the "agent-port" server keyword */
static int srv_parse_agent_port(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
				char **errmsg)
{
	int err_code = 0;

	if (!*(args[*cur_arg+1])) {
		memprintf(errmsg, "'%s' expects a port number as argument.", args[*cur_arg]);
		goto error;
	}

	/* Only increment maxsock for servers from the configuration. Dynamic
	 * servers at the moment are not taken into account for the estimation
	 * of the resources limits.
	 */
	if (global.mode & MODE_STARTING)
		global.maxsock++;

	set_srv_agent_port(srv, atol(args[*cur_arg + 1]));

  out:
	return err_code;

  error:
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

int set_srv_agent_send(struct server *srv, const char *send)
{
	struct tcpcheck_rules *rules = srv->agent.tcpcheck_rules;
	struct tcpcheck_var *var = NULL;
	char *str;

	str = strdup(send);
	var = create_tcpcheck_var(ist("check.agent_string"));
	if (str == NULL || var == NULL)
		goto error;

	free_tcpcheck_vars(&rules->preset_vars);

	var->data.type = SMP_T_STR;
	var->data.u.str.area = str;
	var->data.u.str.data = strlen(str);
	LIST_INIT(&var->list);
	LIST_APPEND(&rules->preset_vars, &var->list);

	return 1;

  error:
	free(str);
	free(var);
	return 0;
}

/* Parse the "agent-send" server keyword */
static int srv_parse_agent_send(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
				char **errmsg)
{
	struct tcpcheck_rules *rules = srv->agent.tcpcheck_rules;
	int err_code = 0;

	if (!*(args[*cur_arg+1])) {
		memprintf(errmsg, "'%s' expects a string as argument.", args[*cur_arg]);
		goto error;
	}

	if (!rules) {
		rules = calloc(1, sizeof(*rules));
		if (!rules) {
			memprintf(errmsg, "out of memory.");
			goto error;
		}
		LIST_INIT(&rules->preset_vars);
		srv->agent.tcpcheck_rules = rules;
	}

	if (!set_srv_agent_send(srv, args[*cur_arg+1])) {
		memprintf(errmsg, "out of memory.");
		goto error;
	}

  out:
	return err_code;

  error:
	deinit_srv_agent_check(srv);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

/* Parse the "no-agent-send" server keyword */
static int srv_parse_no_agent_check(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
				    char **errmsg)
{
	deinit_srv_agent_check(srv);
	return 0;
}

/* Parse the "check" server keyword */
static int srv_parse_check(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
			   char **errmsg)
{
	if (!(curpx->cap & PR_CAP_BE)) {
		memprintf(errmsg, "'%s' ignored because %s '%s' has no backend capability",
			  args[*cur_arg], proxy_type_str(curpx), curpx->id);
		return ERR_WARN;
	}

	srv->do_check = 1;
	return 0;
}

/* Parse the "check-send-proxy" server keyword */
static int srv_parse_check_send_proxy(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
				      char **errmsg)
{
	srv->check.send_proxy = 1;
	return 0;
}

/* Parse the "check-via-socks4" server keyword */
static int srv_parse_check_via_socks4(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
				      char **errmsg)
{
	srv->check.via_socks4 = 1;
	return 0;
}

/* Parse the "no-check" server keyword */
static int srv_parse_no_check(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
			      char **errmsg)
{
	deinit_srv_check(srv);
	return 0;
}

/* Parse the "no-check-send-proxy" server keyword */
static int srv_parse_no_check_send_proxy(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
					 char **errmsg)
{
	srv->check.send_proxy = 0;
	return 0;
}

/* parse the "check-proto" server keyword */
static int srv_parse_check_proto(char **args, int *cur_arg,
				 struct proxy *px, struct server *newsrv, char **err)
{
	int err_code = 0;

	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing value", args[*cur_arg]);
		goto error;
	}
	newsrv->check.mux_proto = get_mux_proto(ist(args[*cur_arg + 1]));
	if (!newsrv->check.mux_proto) {
		memprintf(err, "'%s' :  unknown MUX protocol '%s'", args[*cur_arg], args[*cur_arg+1]);
		goto error;
	}

  out:
	return err_code;

  error:
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}


/* Parse the "rise" server keyword */
static int srv_parse_check_rise(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
				char **errmsg)
{
	int err_code = 0;

	if (!*args[*cur_arg + 1]) {
		memprintf(errmsg, "'%s' expects an integer argument.", args[*cur_arg]);
		goto error;
	}

	srv->check.rise = atol(args[*cur_arg+1]);
	if (srv->check.rise <= 0) {
		memprintf(errmsg, "'%s' has to be > 0.", args[*cur_arg]);
		goto error;
	}

	if (srv->check.health)
		srv->check.health = srv->check.rise;

  out:
	return err_code;

  error:
	deinit_srv_agent_check(srv);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

/* Parse the "fall" server keyword */
static int srv_parse_check_fall(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
				char **errmsg)
{
	int err_code = 0;

	if (!*args[*cur_arg + 1]) {
		memprintf(errmsg, "'%s' expects an integer argument.", args[*cur_arg]);
		goto error;
	}

	srv->check.fall = atol(args[*cur_arg+1]);
	if (srv->check.fall <= 0) {
		memprintf(errmsg, "'%s' has to be > 0.", args[*cur_arg]);
		goto error;
	}

  out:
	return err_code;

  error:
	deinit_srv_agent_check(srv);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

/* Parse the "inter" server keyword */
static int srv_parse_check_inter(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
				 char **errmsg)
{
	const char *err = NULL;
	unsigned int delay;
	int err_code = 0;

	if (!*(args[*cur_arg+1])) {
		memprintf(errmsg, "'%s' expects a delay as argument.", args[*cur_arg]);
		goto error;
	}

	err = parse_time_err(args[*cur_arg+1], &delay, TIME_UNIT_MS);
	if (err == PARSE_TIME_OVER) {
		memprintf(errmsg, "timer overflow in argument <%s> to <%s> of server %s, maximum value is 2147483647 ms (~24.8 days).",
			  args[*cur_arg+1], args[*cur_arg], srv->id);
		goto error;
	}
	else if (err == PARSE_TIME_UNDER) {
		memprintf(errmsg, "timer underflow in argument <%s> to <%s> of server %s, minimum non-null value is 1 ms.",
			  args[*cur_arg+1], args[*cur_arg], srv->id);
		goto error;
	}
	else if (err) {
		memprintf(errmsg, "unexpected character '%c' in 'agent-inter' argument of server %s.",
			  *err, srv->id);
		goto error;
	}
	if (delay <= 0) {
		memprintf(errmsg, "invalid value %d for argument '%s' of server %s.",
			  delay, args[*cur_arg], srv->id);
		goto error;
	}
	srv->check.inter = delay;

	if (warn_if_lower(args[*cur_arg+1], 100)) {
		memprintf(errmsg, "'%s %u' in server '%s' is suspiciously small for a value in milliseconds. Please use an explicit unit ('%ums') if that was the intent",
		          args[*cur_arg], delay, srv->id, delay);
		err_code |= ERR_WARN;
	}

  out:
	return err_code;

  error:
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}


/* Parse the "fastinter" server keyword */
static int srv_parse_check_fastinter(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
				     char **errmsg)
{
	const char *err = NULL;
	unsigned int delay;
	int err_code = 0;

	if (!*(args[*cur_arg+1])) {
		memprintf(errmsg, "'%s' expects a delay as argument.", args[*cur_arg]);
		goto error;
	}

	err = parse_time_err(args[*cur_arg+1], &delay, TIME_UNIT_MS);
	if (err == PARSE_TIME_OVER) {
		memprintf(errmsg, "timer overflow in argument <%s> to <%s> of server %s, maximum value is 2147483647 ms (~24.8 days).",
			  args[*cur_arg+1], args[*cur_arg], srv->id);
		goto error;
	}
	else if (err == PARSE_TIME_UNDER) {
		memprintf(errmsg, "timer underflow in argument <%s> to <%s> of server %s, minimum non-null value is 1 ms.",
			  args[*cur_arg+1], args[*cur_arg], srv->id);
		goto error;
	}
	else if (err) {
		memprintf(errmsg, "unexpected character '%c' in 'agent-inter' argument of server %s.",
			  *err, srv->id);
		goto error;
	}
	if (delay <= 0) {
		memprintf(errmsg, "invalid value %d for argument '%s' of server %s.",
			  delay, args[*cur_arg], srv->id);
		goto error;
	}
	srv->check.fastinter = delay;

	if (warn_if_lower(args[*cur_arg+1], 100)) {
		memprintf(errmsg, "'%s %u' in server '%s' is suspiciously small for a value in milliseconds. Please use an explicit unit ('%ums') if that was the intent",
		          args[*cur_arg], delay, srv->id, delay);
		err_code |= ERR_WARN;
	}

  out:
	return err_code;

  error:
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}


/* Parse the "downinter" server keyword */
static int srv_parse_check_downinter(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
				     char **errmsg)
{
	const char *err = NULL;
	unsigned int delay;
	int err_code = 0;

	if (!*(args[*cur_arg+1])) {
		memprintf(errmsg, "'%s' expects a delay as argument.", args[*cur_arg]);
		goto error;
	}

	err = parse_time_err(args[*cur_arg+1], &delay, TIME_UNIT_MS);
	if (err == PARSE_TIME_OVER) {
		memprintf(errmsg, "timer overflow in argument <%s> to <%s> of server %s, maximum value is 2147483647 ms (~24.8 days).",
			  args[*cur_arg+1], args[*cur_arg], srv->id);
		goto error;
	}
	else if (err == PARSE_TIME_UNDER) {
		memprintf(errmsg, "timer underflow in argument <%s> to <%s> of server %s, minimum non-null value is 1 ms.",
			  args[*cur_arg+1], args[*cur_arg], srv->id);
		goto error;
	}
	else if (err) {
		memprintf(errmsg, "unexpected character '%c' in 'agent-inter' argument of server %s.",
			  *err, srv->id);
		goto error;
	}
	if (delay <= 0) {
		memprintf(errmsg, "invalid value %d for argument '%s' of server %s.",
			  delay, args[*cur_arg], srv->id);
		goto error;
	}
	srv->check.downinter = delay;

	if (warn_if_lower(args[*cur_arg+1], 100)) {
		memprintf(errmsg, "'%s %u' in server '%s' is suspiciously small for a value in milliseconds. Please use an explicit unit ('%ums') if that was the intent",
		          args[*cur_arg], delay, srv->id, delay);
		err_code |= ERR_WARN;
	}

  out:
	return err_code;

  error:
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

/* Parse the "port" server keyword */
static int srv_parse_check_port(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
				char **errmsg)
{
	int err_code = 0;

	if (!*(args[*cur_arg+1])) {
		memprintf(errmsg, "'%s' expects a port number as argument.", args[*cur_arg]);
		goto error;
	}

	/* Only increment maxsock for servers from the configuration. Dynamic
	 * servers at the moment are not taken into account for the estimation
	 * of the resources limits.
	 */
	if (global.mode & MODE_STARTING)
		global.maxsock++;

	srv->check.port = atol(args[*cur_arg+1]);
	/* if agentport was never set, we can use port */
	if (!(srv->flags & SRV_F_AGENTPORT))
		srv->agent.port = srv->check.port;

  out:
	return err_code;

  error:
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

/* config parser for global "tune.max-checks-per-thread" */
static int check_parse_global_max_checks(char **args, int section_type, struct proxy *curpx,
                                       const struct proxy *defpx, const char *file, int line,
                                       char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;
	global.tune.max_checks_per_thread = atoi(args[1]);
	return 0;
}

/* register "global" section keywords */
static struct cfg_kw_list chk_cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.max-checks-per-thread", check_parse_global_max_checks },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &chk_cfg_kws);

/* register "server" line keywords */
static struct srv_kw_list srv_kws = { "CHK", { }, {
	{ "addr",                srv_parse_addr,                1,  1,  1 }, /* IP address to send health to or to probe from agent-check */
	{ "agent-addr",          srv_parse_agent_addr,          1,  1,  1 }, /* Enable an auxiliary agent check */
	{ "agent-check",         srv_parse_agent_check,         0,  1,  1 }, /* Enable agent checks */
	{ "agent-inter",         srv_parse_agent_inter,         1,  1,  1 }, /* Set the interval between two agent checks */
	{ "agent-port",          srv_parse_agent_port,          1,  1,  1 }, /* Set the TCP port used for agent checks. */
	{ "agent-send",          srv_parse_agent_send,          1,  1,  1 }, /* Set string to send to agent. */
	{ "check",               srv_parse_check,               0,  1,  1 }, /* Enable health checks */
	{ "check-proto",         srv_parse_check_proto,         1,  1,  1 }, /* Set the mux protocol for health checks  */
	{ "check-send-proxy",    srv_parse_check_send_proxy,    0,  1,  1 }, /* Enable PROXY protocol for health checks */
	{ "check-via-socks4",    srv_parse_check_via_socks4,    0,  1,  1 }, /* Enable socks4 proxy for health checks */
	{ "no-agent-check",      srv_parse_no_agent_check,      0,  1,  0 }, /* Do not enable any auxiliary agent check */
	{ "no-check",            srv_parse_no_check,            0,  1,  0 }, /* Disable health checks */
	{ "no-check-send-proxy", srv_parse_no_check_send_proxy, 0,  1,  0 }, /* Disable PROXY protocol for health checks */
	{ "rise",                srv_parse_check_rise,          1,  1,  1 }, /* Set rise value for health checks */
	{ "fall",                srv_parse_check_fall,          1,  1,  1 }, /* Set fall value for health checks */
	{ "inter",               srv_parse_check_inter,         1,  1,  1 }, /* Set inter value for health checks */
	{ "fastinter",           srv_parse_check_fastinter,     1,  1,  1 }, /* Set fastinter value for health checks */
	{ "downinter",           srv_parse_check_downinter,     1,  1,  1 }, /* Set downinter value for health checks */
	{ "port",                srv_parse_check_port,          1,  1,  1 }, /* Set the TCP port used for health checks. */
	{ NULL, NULL, 0 },
}};

INITCALL1(STG_REGISTER, srv_register_keywords, &srv_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
