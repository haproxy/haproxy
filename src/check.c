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
#include <fcntl.h>
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
#include <haproxy/dns.h>
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
#include <haproxy/sample.h>
#include <haproxy/server.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/stats-t.h>
#include <haproxy/stream_interface.h>
#include <haproxy/task.h>
#include <haproxy/tcpcheck.h>
#include <haproxy/thread.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <haproxy/vars.h>


static int wake_srv_chk(struct conn_stream *cs);
struct data_cb check_conn_cb = {
	.wake = wake_srv_chk,
	.name = "CHCK",
};


/* Dummy frontend used to create all checks sessions. */
struct proxy checks_fe;

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
	if (err == EAGAIN || err == EINPROGRESS ||
	    err == EISCONN || err == EALREADY)
		return 0;
	return err;
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
const char *get_check_status_info(short check_status) {

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
	int report = 0;

	if (status == HCHK_STATUS_START) {
		check->result = CHK_RES_UNKNOWN;	/* no result yet */
		check->desc[0] = '\0';
		check->start = now;
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
	else if (!tv_iszero(&check->start)) {
		/* set_server_check_status() may be called more than once */
		check->duration = tv_ms_elapsed(&check->start, &now);
		tv_zero(&check->start);
	}

	/* no change is expected if no state change occurred */
	if (check->result == CHK_RES_NEUTRAL)
		return;

	/* If the check was really just sending a mail, it won't have an
	 * associated server, so we're done now.
	 */
	if (!s)
	    return;
	report = 0;

	switch (check->result) {
	case CHK_RES_FAILED:
		/* Failure to connect to the agent as a secondary check should not
		 * cause the server to be marked down.
		 */
		if ((!(check->state & CHK_ST_AGENT) ||
		    (check->status >= HCHK_STATUS_L57DATA)) &&
		    (check->health > 0)) {
			_HA_ATOMIC_ADD(&s->counters.failed_checks, 1);
			report = 1;
			check->health--;
			if (check->health < check->rise)
				check->health = 0;
		}
		break;

	case CHK_RES_PASSED:
	case CHK_RES_CONDPASS:	/* "condpass" cannot make the first step but it OK after a "passed" */
		if ((check->health < check->rise + check->fall - 1) &&
		    (check->result == CHK_RES_PASSED || check->health > 0)) {
			report = 1;
			check->health++;

			if (check->health >= check->rise)
				check->health = check->rise + check->fall - 1; /* OK now */
		}

		/* clear consecutive_errors if observing is enabled */
		if (s->onerror)
			s->consecutive_errors = 0;
		break;

	default:
		break;
	}

	if (s->proxy->options2 & PR_O2_LOGHCHKS &&
	    (status != prev_status || report)) {
		chunk_printf(&trash,
		             "%s check for %sserver %s/%s %s%s",
			     (check->state & CHK_ST_AGENT) ? "Agent" : "Health",
		             s->flags & SRV_F_BACKUP ? "backup " : "",
		             s->proxy->id, s->id,
		             (check->result == CHK_RES_CONDPASS) ? "conditionally ":"",
		             (check->result >= CHK_RES_PASSED)   ? "succeeded" : "failed");

		srv_append_status(&trash, s, check, -1, 0);

		chunk_appendf(&trash, ", status: %d/%d %s",
		             (check->health >= check->rise) ? check->health - check->rise + 1 : check->health,
		             (check->health >= check->rise) ? check->fall : check->rise,
			     (check->health >= check->rise) ? (s->uweight ? "UP" : "DRAIN") : "DOWN");

		ha_warning("%s.\n", trash.area);
		send_log(s->proxy, LOG_NOTICE, "%s.\n", trash.area);
		send_email_alert(s, LOG_INFO, "%s", trash.area);
	}
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

	/* We only report a reason for the check if we did not do so previously */
	srv_set_stopped(s, NULL, (!s->track && !(s->proxy->options2 & PR_O2_LOGHCHKS)) ? check : NULL);
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

	srv_set_running(s, NULL, (!s->track && !(s->proxy->options2 & PR_O2_LOGHCHKS)) ? check : NULL);
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

	srv_set_stopping(s, NULL, (!s->track && !(s->proxy->options2 & PR_O2_LOGHCHKS)) ? check : NULL);
}

/* note: use health_adjust() only, which first checks that the observe mode is
 * enabled.
 */
void __health_adjust(struct server *s, short status)
{
	int failed;
	int expire;

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
		s->consecutive_errors = 0;
		return;
	}

	_HA_ATOMIC_ADD(&s->consecutive_errors, 1);

	if (s->consecutive_errors < s->consecutive_errors_limit)
		return;

	chunk_printf(&trash, "Detected %d consecutive errors, last one was: %s",
	             s->consecutive_errors, get_analyze_status(status));

	switch (s->onerror) {
		case HANA_ONERR_FASTINTER:
		/* force fastinter - nothing to do here as all modes force it */
			break;

		case HANA_ONERR_SUDDTH:
		/* simulate a pre-fatal failed health check */
			if (s->check.health > s->check.rise)
				s->check.health = s->check.rise + 1;

			/* no break - fall through */

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

	s->consecutive_errors = 0;
	_HA_ATOMIC_ADD(&s->counters.failed_hana, 1);

	if (s->check.fastinter) {
		expire = tick_add(now_ms, MS_TO_TICKS(s->check.fastinter));
		if (s->check.task->expire > expire) {
			s->check.task->expire = expire;
			/* requeue check task with new expire */
			task_queue(s->check.task);
		}
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
	struct conn_stream *cs = check->cs;
	struct connection *conn = cs_conn(cs);
	const char *err_msg;
	struct buffer *chk;
	int step;

	if (check->result != CHK_RES_UNKNOWN)
		return;

	errno = unclean_errno(errno_bck);
	if (conn && errno)
		retrieve_errno_from_socket(conn);

	if (conn && !(conn->flags & CO_FL_ERROR) &&
	    !(cs->flags & CS_FL_ERROR) && !expired)
		return;

	/* we'll try to build a meaningful error message depending on the
	 * context of the error possibly present in conn->err_code, and the
	 * socket error possibly collected above. This is useful to know the
	 * exact step of the L6 layer (eg: SSL handshake).
	 */
	chk = get_trash_chunk();

	if (check->type == PR_O2_TCPCHK_CHK &&
	    (check->tcpcheck_rules->flags & TCPCHK_RULES_PROTO_CHK) == TCPCHK_RULES_TCP_CHK) {
		step = tcpcheck_get_step_id(check, NULL);
		if (!step)
			chunk_printf(chk, " at initial connection step of tcp-check");
		else {
			chunk_printf(chk, " at step %d of tcp-check", step);
			/* we were looking for a string */
			if (check->current_step && check->current_step->action == TCPCHK_ACT_CONNECT) {
				if (check->current_step->connect.port)
					chunk_appendf(chk, " (connect port %d)" ,check->current_step->connect.port);
				else
					chunk_appendf(chk, " (connect)");
			}
			else if (check->current_step && check->current_step->action == TCPCHK_ACT_EXPECT) {
				struct tcpcheck_expect *expect = &check->current_step->expect;

				switch (expect->type) {
				case TCPCHK_EXPECT_STRING:
					chunk_appendf(chk, " (expect string '%.*s')", (unsigned int)istlen(expect->data), istptr(expect->data));
					break;
				case TCPCHK_EXPECT_BINARY:
					chunk_appendf(chk, " (expect binary '%.*s')", (unsigned int)istlen(expect->data), istptr(expect->data));
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
			}
			else if (check->current_step && check->current_step->action == TCPCHK_ACT_SEND) {
				chunk_appendf(chk, " (send)");
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
		chunk_printf(chk, "No port available for the TCP connection");
		set_server_check_status(check, HCHK_STATUS_SOCKERR, err_msg);
	}

	if (!conn) {
		/* connection allocation error before the connection was established */
		set_server_check_status(check, HCHK_STATUS_SOCKERR, err_msg);
	}
	else if (conn->flags & CO_FL_WAIT_L4_CONN) {
		/* L4 not established (yet) */
		if (conn->flags & CO_FL_ERROR || cs->flags & CS_FL_ERROR)
			set_server_check_status(check, HCHK_STATUS_L4CON, err_msg);
		else if (expired)
			set_server_check_status(check, HCHK_STATUS_L4TOUT, err_msg);

		/*
		 * might be due to a server IP change.
		 * Let's trigger a DNS resolution if none are currently running.
		 */
		if (check->server)
			dns_trigger_resolution(check->server->dns_requester);

	}
	else if (conn->flags & CO_FL_WAIT_L6_CONN) {
		/* L6 not established (yet) */
		if (conn->flags & CO_FL_ERROR || cs->flags & CS_FL_ERROR)
			set_server_check_status(check, HCHK_STATUS_L6RSP, err_msg);
		else if (expired)
			set_server_check_status(check, HCHK_STATUS_L6TOUT, err_msg);
	}
	else if (conn->flags & CO_FL_ERROR || cs->flags & CS_FL_ERROR) {
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
		      s->cur_sess, s->proxy->beconn - s->proxy->nbpend,
		      s->nbpend);

	if ((s->cur_state == SRV_ST_STARTING) &&
	    now.tv_sec < s->last_change + s->slowstart &&
	    now.tv_sec >= s->last_change) {
		ratio = MAX(1, 100 * (now.tv_sec - s->last_change) / s->slowstart);
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
static int wake_srv_chk(struct conn_stream *cs)
{
	struct connection *conn = cs->conn;
	struct check *check = cs->data;
	struct email_alertq *q = container_of(check, typeof(*q), check);
	int ret = 0;

	if (check->server)
		HA_SPIN_LOCK(SERVER_LOCK, &check->server->lock);
	else
		HA_SPIN_LOCK(EMAIL_ALERTS_LOCK, &q->lock);

	/* we may have to make progress on the TCP checks */
	ret = tcpcheck_main(check);

	cs = check->cs;
	conn = cs->conn;

	if (unlikely(conn->flags & CO_FL_ERROR || cs->flags & CS_FL_ERROR)) {
		/* We may get error reports bypassing the I/O handlers, typically
		 * the case when sending a pure TCP check which fails, then the I/O
		 * handlers above are not called. This is completely handled by the
		 * main processing task so let's simply wake it up. If we get here,
		 * we expect errno to still be valid.
		 */
		chk_report_conn_err(check, errno, 0);
		task_wakeup(check->task, TASK_WOKEN_IO);
	}

	if (check->result != CHK_RES_UNKNOWN) {
		/* Check complete or aborted. If connection not yet closed do it
		 * now and wake the check task up to be sure the result is
		 * handled ASAP. */
		conn_sock_drain(conn);
		cs_close(cs);
		ret = -1;
		/* We may have been scheduled to run, and the
		 * I/O handler expects to have a cs, so remove
		 * the tasklet
		 */
		tasklet_remove_from_tasklet_list(check->wait_list.tasklet);
		task_wakeup(check->task, TASK_WOKEN_IO);
	}

	if (check->server)
		HA_SPIN_UNLOCK(SERVER_LOCK, &check->server->lock);
	else
		HA_SPIN_UNLOCK(EMAIL_ALERTS_LOCK, &q->lock);

	/* if a connection got replaced, we must absolutely prevent the connection
	 * handler from touching its fd, and perform the FD polling updates ourselves
	 */
	if (ret < 0)
		conn_cond_update_polling(conn);

	return ret;
}

/* This function checks if any I/O is wanted, and if so, attempts to do so */
static struct task *event_srv_chk_io(struct task *t, void *ctx, unsigned short state)
{
	struct check *check = ctx;
	struct conn_stream *cs = check->cs;

	wake_srv_chk(cs);
	return NULL;
}

/* manages a server health-check that uses a connection. Returns
 * the time the task accepts to wait, or TIME_ETERNITY for infinity.
 *
 * Please do NOT place any return statement in this function and only leave
 * via the out_unlock label.
 */
static struct task *process_chk_conn(struct task *t, void *context, unsigned short state)
{
	struct check *check = context;
	struct proxy *proxy = check->proxy;
	struct conn_stream *cs = check->cs;
	struct connection *conn = cs_conn(cs);
	int rv;
	int expired = tick_is_expired(t->expire, now_ms);

	if (check->server)
		HA_SPIN_LOCK(SERVER_LOCK, &check->server->lock);
	if (!(check->state & CHK_ST_INPROGRESS)) {
		/* no check currently running */
		if (!expired) /* woke up too early */
			goto out_unlock;

		/* we don't send any health-checks when the proxy is
		 * stopped, the server should not be checked or the check
		 * is disabled.
		 */
		if (((check->state & (CHK_ST_ENABLED | CHK_ST_PAUSED)) != CHK_ST_ENABLED) ||
		    proxy->state == PR_STSTOPPED)
			goto reschedule;

		/* we'll initiate a new check */
		set_server_check_status(check, HCHK_STATUS_START, NULL);

		check->state |= CHK_ST_INPROGRESS;
		b_reset(&check->bi);
		b_reset(&check->bo);

		task_set_affinity(t, tid_bit);

		check->current_step = NULL;
		tcpcheck_main(check);
		goto out_unlock;
	}
	else {
		/* there was a test running.
		 * First, let's check whether there was an uncaught error,
		 * which can happen on connect timeout or error.
		 */
		if (check->result == CHK_RES_UNKNOWN) {
			if ((conn->flags & CO_FL_ERROR) || cs->flags & CS_FL_ERROR || expired) {
				chk_report_conn_err(check, 0, expired);
			}
			else
				goto out_unlock; /* timeout not reached, wait again */
		}

		/* check complete or aborted */

		check->current_step = NULL;

		if (conn && conn->xprt) {
			/* The check was aborted and the connection was not yet closed.
			 * This can happen upon timeout, or when an external event such
			 * as a failed response coupled with "observe layer7" caused the
			 * server state to be suddenly changed.
			 */
			conn_sock_drain(conn);
			cs_close(cs);
		}

		if (cs) {
			if (check->wait_list.events)
				cs->conn->mux->unsubscribe(cs, check->wait_list.events, &check->wait_list);
			/* We may have been scheduled to run, and the
			 * I/O handler expects to have a cs, so remove
			 * the tasklet
			 */
			tasklet_remove_from_tasklet_list(check->wait_list.tasklet);
			cs_destroy(cs);
			cs = check->cs = NULL;
			conn = NULL;
		}

		if (check->sess != NULL) {
			vars_prune(&check->vars, check->sess, NULL);
			session_free(check->sess);
			check->sess = NULL;
		}

		if (check->server) {
			if (check->result == CHK_RES_FAILED) {
				/* a failure or timeout detected */
				check_notify_failure(check);
			}
			else if (check->result == CHK_RES_CONDPASS) {
				/* check is OK but asks for stopping mode */
				check_notify_stopping(check);
			}
			else if (check->result == CHK_RES_PASSED) {
				/* a success was detected */
				check_notify_success(check);
			}
		}
		task_set_affinity(t, MAX_THREADS_MASK);
		check->state &= ~CHK_ST_INPROGRESS;

		if (check->server) {
			rv = 0;
			if (global.spread_checks > 0) {
				rv = srv_getinter(check) * global.spread_checks / 100;
				rv -= (int) (2 * rv * (ha_random32() / 4294967295.0));
			}
			t->expire = tick_add(now_ms, MS_TO_TICKS(srv_getinter(check) + rv));
		}
	}

 reschedule:
	while (tick_is_expired(t->expire, now_ms))
		t->expire = tick_add(t->expire, MS_TO_TICKS(check->inter));
 out_unlock:
	if (check->server)
		HA_SPIN_UNLOCK(SERVER_LOCK, &check->server->lock);
	return t;
}


/**************************************************************************/
/************************** Init/deinit checks ****************************/
/**************************************************************************/
const char *init_check(struct check *check, int type)
{
	check->type = type;

	b_reset(&check->bi); check->bi.size = global.tune.chksize;
	b_reset(&check->bo); check->bo.size = global.tune.chksize;

	check->bi.area = calloc(check->bi.size, sizeof(char));
	check->bo.area = calloc(check->bo.size, sizeof(char));

	if (!check->bi.area || !check->bo.area)
		return "out of memory while allocating check buffer";

	check->wait_list.tasklet = tasklet_new();
	if (!check->wait_list.tasklet)
		return "out of memory while allocating check tasklet";
	check->wait_list.events = 0;
	check->wait_list.tasklet->process = event_srv_chk_io;
	check->wait_list.tasklet->context = check;
	return NULL;
}

void free_check(struct check *check)
{
	task_destroy(check->task);
	if (check->wait_list.tasklet)
		tasklet_free(check->wait_list.tasklet);

	free(check->bi.area);
	free(check->bo.area);
	if (check->cs) {
		free(check->cs->conn);
		check->cs->conn = NULL;
		cs_free(check->cs);
		check->cs = NULL;
	}
}

/* manages a server health-check. Returns the time the task accepts to wait, or
 * TIME_ETERNITY for infinity.
 */
struct task *process_chk(struct task *t, void *context, unsigned short state)
{
	struct check *check = context;

	if (check->type == PR_O2_EXT_CHK)
		return process_chk_proc(t, context, state);
	return process_chk_conn(t, context, state);

}


static int start_check_task(struct check *check, int mininter,
			    int nbcheck, int srvpos)
{
	struct task *t;
	unsigned long thread_mask = MAX_THREADS_MASK;

	if (check->type == PR_O2_EXT_CHK)
		thread_mask = 1;

	/* task for the check */
	if ((t = task_new(thread_mask)) == NULL) {
		ha_alert("Starting [%s:%s] check: out of memory.\n",
			 check->server->proxy->id, check->server->id);
		return 0;
	}

	check->task = t;
	t->process = process_chk;
	t->context = check;

	if (mininter < srv_getinter(check))
		mininter = srv_getinter(check);

	if (global.max_spread_checks && mininter > global.max_spread_checks)
		mininter = global.max_spread_checks;

	/* check this every ms */
	t->expire = tick_add(now_ms, MS_TO_TICKS(mininter * srvpos / nbcheck));
	check->start = now;
	task_queue(t);

	return 1;
}

/* updates the server's weight during a warmup stage. Once the final weight is
 * reached, the task automatically stops. Note that any server status change
 * must have updated s->last_change accordingly.
 */
static struct task *server_warmup(struct task *t, void *context, unsigned short state)
{
	struct server *s = context;

	/* by default, plan on stopping the task */
	t->expire = TICK_ETERNITY;
	if ((s->next_admin & SRV_ADMF_MAINT) ||
	    (s->next_state != SRV_ST_STARTING))
		return t;

	HA_SPIN_LOCK(SERVER_LOCK, &s->lock);

	/* recalculate the weights and update the state */
	server_recalc_eweight(s, 1);

	/* probably that we can refill this server with a bit more connections */
	pendconn_grab_from_px(s);

	HA_SPIN_UNLOCK(SERVER_LOCK, &s->lock);

	/* get back there in 1 second or 1/20th of the slowstart interval,
	 * whichever is greater, resulting in small 5% steps.
	 */
	if (s->next_state == SRV_ST_STARTING)
		t->expire = tick_add(now_ms, MS_TO_TICKS(MAX(1000, s->slowstart / 20)));
	return t;
}

/*
 * Start health-check.
 * Returns 0 if OK, ERR_FATAL on error, and prints the error in this case.
 */
static int start_checks()
{

	struct proxy *px;
	struct server *s;
	struct task *t;
	int nbcheck=0, mininter=0, srvpos=0;

	/* 0- init the dummy frontend used to create all checks sessions */
	init_new_proxy(&checks_fe);
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
			if (s->slowstart) {
				if ((t = task_new(MAX_THREADS_MASK)) == NULL) {
					ha_alert("Starting [%s:%s] check: out of memory.\n", px->id, s->id);
					return ERR_ALERT | ERR_FATAL;
				}
				/* We need a warmup task that will be called when the server
				 * state switches from down to up.
				 */
				s->warmup = t;
				t->process = server_warmup;
				t->context = s;
				/* server can be in this state only because of */
				if (s->next_state == SRV_ST_STARTING)
					task_schedule(s->warmup, tick_add(now_ms, MS_TO_TICKS(MAX(1000, (now.tv_sec - s->last_change)) / 20)));
			}

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
		return 0;

	srand((unsigned)time(NULL));

	/*
	 * 2- start them as far as possible from each others. For this, we will
	 * start them after their interval set to the min interval divided by
	 * the number of servers, weighted by the server's position in the list.
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
	return 0;
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

	/* by default, we use the health check port ocnfigured */
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
static int init_srv_check(struct server *srv)
{
	const char *err;
	struct tcpcheck_rule *r;
	int ret = 0;

	if (!srv->do_check)
		goto out;


	/* If neither a port nor an addr was specified and no check transport
	 * layer is forced, then the transport layer used by the checks is the
	 * same as for the production traffic. Otherwise we use raw_sock by
	 * default, unless one is specified.
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

	/* Inherit the mux protocol from the server if not already defined for
	 * the check
	 */
	if (srv->mux_proto && !srv->check.mux_proto)
		srv->check.mux_proto = srv->mux_proto;

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
		if ((r->action == TCPCHK_ACT_CONNECT) && (!r->connect.port || !get_host_port(&r->connect.addr))) {
			ha_alert("config: %s '%s': server '%s' has neither service port nor check port, "
				 "and a tcp_check rule 'connect' with no port information.\n",
				 proxy_type_str(srv->proxy), srv->proxy->id, srv->id);
			ret |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
	}

  init:
	if (!(srv->proxy->options2 & PR_O2_CHK_ANY)) {
		struct tcpcheck_ruleset *rs = NULL;
		struct tcpcheck_rules *rules = &srv->proxy->tcpcheck_rules;
		//char *errmsg = NULL;

		srv->proxy->options2 &= ~PR_O2_CHK_ANY;
		srv->proxy->options2 |= PR_O2_TCPCHK_CHK;

		rs = find_tcpcheck_ruleset("*tcp-check");
		if (!rs) {
			rs = create_tcpcheck_ruleset("*tcp-check");
			if (rs == NULL) {
				ha_alert("config: %s '%s': out of memory.\n",
					 proxy_type_str(srv->proxy), srv->proxy->id);
				ret |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}

		free_tcpcheck_vars(&rules->preset_vars);
		rules->list = &rs->rules;
		rules->flags = 0;
	}

	err = init_check(&srv->check, srv->proxy->options2 & PR_O2_CHK_ANY);
	if (err) {
		ha_alert("config: %s '%s': unable to init check for server '%s' (%s).\n",
			 proxy_type_str(srv->proxy), srv->proxy->id, srv->id, err);
		ret |= ERR_ALERT | ERR_ABORT;
		goto out;
	}
	srv->check.state |= CHK_ST_CONFIGURED | CHK_ST_ENABLED;
	global.maxsock++;

  out:
	return ret;
}

/* Initializes an agent-check attached to the server <srv>. Non-zero is returned
 * if an error occurred.
 */
static int init_srv_agent_check(struct server *srv)
{
	struct tcpcheck_rule *chk;
	const char *err;
	int ret = 0;

	if (!srv->do_agent)
		goto out;

	/* If there is no connect rule preceding all send / expect rules, an
	 * implicit one is inserted before all others.
	 */
	chk = get_first_tcpcheck_rule(srv->agent.tcpcheck_rules);
	if (!chk || chk->action != TCPCHK_ACT_CONNECT) {
		chk = calloc(1, sizeof(*chk));
		if (!chk) {
			ha_alert("config : %s '%s': unable to add implicit tcp-check connect rule"
				 " to agent-check for server '%s' (out of memory).\n",
				 proxy_type_str(srv->proxy), srv->proxy->id, srv->id);
			ret |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		chk->action = TCPCHK_ACT_CONNECT;
		chk->connect.options = (TCPCHK_OPT_DEFAULT_CONNECT|TCPCHK_OPT_IMPLICIT);
		LIST_ADD(srv->agent.tcpcheck_rules->list, &chk->list);
	}


	err = init_check(&srv->agent, PR_O2_TCPCHK_CHK);
	if (err) {
		ha_alert("config: %s '%s': unable to init agent-check for server '%s' (%s).\n",
			 proxy_type_str(srv->proxy), srv->proxy->id, srv->id, err);
		ret |= ERR_ALERT | ERR_ABORT;
		goto out;
	}

	if (!srv->agent.inter)
		srv->agent.inter = srv->check.inter;

	srv->agent.state |= CHK_ST_CONFIGURED | CHK_ST_ENABLED | CHK_ST_AGENT;
	global.maxsock++;

  out:
	return ret;
}

static void deinit_srv_check(struct server *srv)
{
	if (srv->check.state & CHK_ST_CONFIGURED)
		free_check(&srv->check);
	srv->check.state &= ~CHK_ST_CONFIGURED & ~CHK_ST_ENABLED;
	srv->do_check = 0;
}


static void deinit_srv_agent_check(struct server *srv)
{
	if (srv->agent.tcpcheck_rules) {
		free_tcpcheck_vars(&srv->agent.tcpcheck_rules->preset_vars);
		free(srv->agent.tcpcheck_rules);
		srv->agent.tcpcheck_rules = NULL;
	}

	if (srv->agent.state & CHK_ST_CONFIGURED)
		free_check(&srv->agent);

	srv->agent.state &= ~CHK_ST_CONFIGURED & ~CHK_ST_ENABLED & ~CHK_ST_AGENT;
	srv->do_agent = 0;
}

REGISTER_POST_SERVER_CHECK(init_srv_check);
REGISTER_POST_SERVER_CHECK(init_srv_agent_check);
REGISTER_POST_CHECK(start_checks);

REGISTER_SERVER_DEINIT(deinit_srv_check);
REGISTER_SERVER_DEINIT(deinit_srv_agent_check);


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
/* Parses the "http-check" proxy keyword */
static int proxy_parse_httpcheck(char **args, int section, struct proxy *curpx,
				 struct proxy *defpx, const char *file, int line,
				 char **errmsg)
{
	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rule *chk = NULL;
	int index, cur_arg, ret = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[0], NULL))
		ret = 1;

	cur_arg = 1;
	if (strcmp(args[cur_arg], "disable-on-404") == 0) {
		/* enable a graceful server shutdown on an HTTP 404 response */
		curpx->options |= PR_O_DISABLE404;
		if (too_many_args(1, args, errmsg, NULL))
			goto error;
		goto out;
	}
	else if (strcmp(args[cur_arg], "send-state") == 0) {
		/* enable emission of the apparent state of a server in HTTP checks */
		curpx->options2 |= PR_O2_CHK_SNDST;
		if (too_many_args(1, args, errmsg, NULL))
			goto error;
		goto out;
	}

	/* Deduce the ruleset name from the proxy info */
	chunk_printf(&trash, "*http-check-%s_%s-%d",
		     ((curpx == defpx) ? "defaults" : curpx->id),
		     curpx->conf.file, curpx->conf.line);

	rs = find_tcpcheck_ruleset(b_orig(&trash));
	if (rs == NULL) {
		rs = create_tcpcheck_ruleset(b_orig(&trash));
		if (rs == NULL) {
			memprintf(errmsg, "out of memory.\n");
			goto error;
		}
	}

	index = 0;
	if (!LIST_ISEMPTY(&rs->rules)) {
		chk = LIST_PREV(&rs->rules, typeof(chk), list);
		if (chk->action != TCPCHK_ACT_SEND || !(chk->send.http.flags & TCPCHK_SND_HTTP_FROM_OPT))
			index = chk->index + 1;
	}

	if (strcmp(args[cur_arg], "connect") == 0)
		chk = parse_tcpcheck_connect(args, cur_arg, curpx, &rs->rules, file, line, errmsg);
	else if (strcmp(args[cur_arg], "send") == 0)
		chk = parse_tcpcheck_send_http(args, cur_arg, curpx, &rs->rules, file, line, errmsg);
	else if (strcmp(args[cur_arg], "expect") == 0)
		chk = parse_tcpcheck_expect(args, cur_arg, curpx, &rs->rules, TCPCHK_RULES_HTTP_CHK,
					    file, line, errmsg);
	else if (strcmp(args[cur_arg], "comment") == 0)
		chk = parse_tcpcheck_comment(args, cur_arg, curpx, &rs->rules, file, line, errmsg);
	else {
		struct action_kw *kw = action_kw_tcp_check_lookup(args[cur_arg]);

		if (!kw) {
			action_kw_tcp_check_build_list(&trash);
			memprintf(errmsg, "'%s' only supports 'disable-on-404', 'send-state', 'comment', 'connect',"
				  " 'send', 'expect'%s%s. but got '%s'",
				  args[0], (*trash.area ? ", " : ""), trash.area, args[1]);
			goto error;
		}
		chk = parse_tcpcheck_action(args, cur_arg, curpx, &rs->rules, kw, file, line, errmsg);
	}

	if (!chk) {
		memprintf(errmsg, "'%s %s' : %s.", args[0], args[1], *errmsg);
		goto error;
	}
	ret = (*errmsg != NULL); /* Handle warning */

	chk->index = index;
	if ((curpx->options2 & PR_O2_CHK_ANY) == PR_O2_TCPCHK_CHK &&
	    (curpx->tcpcheck_rules.flags & TCPCHK_RULES_PROTO_CHK) == TCPCHK_RULES_HTTP_CHK) {
		/* Use this ruleset if the proxy already has http-check enabled */
		curpx->tcpcheck_rules.list = &rs->rules;
		curpx->tcpcheck_rules.flags &= ~TCPCHK_RULES_UNUSED_HTTP_RS;
		if (!tcpcheck_add_http_rule(chk, &curpx->tcpcheck_rules, errmsg)) {
			memprintf(errmsg, "'%s %s' : %s.", args[0], args[1], *errmsg);
			curpx->tcpcheck_rules.list = NULL;
			goto error;
		}
	}
	else {
		/* mark this ruleset as unused for now */
		curpx->tcpcheck_rules.flags |= TCPCHK_RULES_UNUSED_HTTP_RS;
		LIST_ADDQ(&rs->rules, &chk->list);
	}

  out:
	return ret;

  error:
	free_tcpcheck(chk, 0);
	free_tcpcheck_ruleset(rs);
	return -1;
}

/* Parses the "option tcp-check" proxy keyword */
int proxy_parse_tcp_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
			      const char *file, int line)
{
	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	int err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(0, 1, file, line, args, &err_code))
		goto out;

	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	if ((rules->flags & TCPCHK_RULES_PROTO_CHK) == TCPCHK_RULES_TCP_CHK) {
		/* If a tcp-check rulesset is already set, do nothing */
		if (rules->list)
			goto out;

		/* If a tcp-check ruleset is waiting to be used for the current proxy,
		 * get it.
		 */
		if (rules->flags & TCPCHK_RULES_UNUSED_TCP_RS)
			goto curpx_ruleset;

		/* Otherwise, try to get the tcp-check ruleset of the default proxy */
		chunk_printf(&trash, "*tcp-check-defaults_%s-%d", defpx->conf.file, defpx->conf.line);
		rs = find_tcpcheck_ruleset(b_orig(&trash));
		if (rs)
			goto ruleset_found;
	}

  curpx_ruleset:
	/* Deduce the ruleset name from the proxy info */
	chunk_printf(&trash, "*tcp-check-%s_%s-%d",
		     ((curpx == defpx) ? "defaults" : curpx->id),
		     curpx->conf.file, curpx->conf.line);

	rs = find_tcpcheck_ruleset(b_orig(&trash));
	if (rs == NULL) {
		rs = create_tcpcheck_ruleset(b_orig(&trash));
		if (rs == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
			goto error;
		}
	}

  ruleset_found:
	free_tcpcheck_vars(&rules->preset_vars);
	rules->list = &rs->rules;
	rules->flags |= TCPCHK_RULES_TCP_CHK;

  out:
	return err_code;

  error:
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

/* Parses the "option redis-check" proxy keyword */
int proxy_parse_redis_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
				const char *file, int line)
{
	static char *redis_req = "*1\r\n$4\r\nPING\r\n";
	static char *redis_res = "+PONG\r\n";

	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	struct tcpcheck_rule *chk;
	char *errmsg = NULL;
	int err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(0, 1, file, line, args, &err_code))
		goto out;

	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	free_tcpcheck_vars(&rules->preset_vars);
	rules->list  = NULL;
	rules->flags = 0;

	rs = find_tcpcheck_ruleset("*redis-check");
	if (rs)
		goto ruleset_found;

	rs = create_tcpcheck_ruleset("*redis-check");
	if (rs == NULL) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}

	chk = parse_tcpcheck_send((char *[]){"tcp-check", "send", redis_req, ""},
				  1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 0;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "string", redis_res,
				               "error-status", "L7STS",
				               "on-error", "%[res.payload(0,0),cut_crlf]",
				               "on-success", "Redis server is ok",
				               ""},
				    1, curpx, &rs->rules, TCPCHK_RULES_REDIS_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 1;
	LIST_ADDQ(&rs->rules, &chk->list);

  ruleset_found:
	rules->list = &rs->rules;
	rules->flags |= TCPCHK_RULES_REDIS_CHK;

  out:
	free(errmsg);
	return err_code;

  error:
	free_tcpcheck_ruleset(rs);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}


/* Parses the "option ssl-hello-chk" proxy keyword */
int proxy_parse_ssl_hello_chk_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
				  const char *file, int line)
{
	/* This is the SSLv3 CLIENT HELLO packet used in conjunction with the
	 * ssl-hello-chk option to ensure that the remote server speaks SSL.
	 *
	 * Check RFC 2246 (TLSv1.0) sections A.3 and A.4 for details.
	 */
	static char sslv3_client_hello[] = {
		"16"                        /* ContentType         : 0x16 = Handshake          */
		"0300"                      /* ProtocolVersion     : 0x0300 = SSLv3            */
		"0079"                      /* ContentLength       : 0x79 bytes after this one */
		"01"                        /* HanshakeType        : 0x01 = CLIENT HELLO       */
		"000075"                    /* HandshakeLength     : 0x75 bytes after this one */
		"0300"                      /* Hello Version       : 0x0300 = v3               */
		"%[date(),htonl,hex]"       /* Unix GMT Time (s)   : filled with <now> (@0x0B) */
		"%[str(HAPROXYSSLCHK\nHAPROXYSSLCHK\n),hex]" /* Random   : must be exactly 28 bytes  */
		"00"                        /* Session ID length   : empty (no session ID)     */
		"004E"                      /* Cipher Suite Length : 78 bytes after this one   */
		"0001" "0002" "0003" "0004" /* 39 most common ciphers :  */
		"0005" "0006" "0007" "0008" /* 0x01...0x1B, 0x2F...0x3A  */
		"0009" "000A" "000B" "000C" /* This covers RSA/DH,       */
		"000D" "000E" "000F" "0010" /* various bit lengths,      */
		"0011" "0012" "0013" "0014" /* SHA1/MD5, DES/3DES/AES... */
		"0015" "0016" "0017" "0018"
		"0019" "001A" "001B" "002F"
		"0030" "0031" "0032" "0033"
		"0034" "0035" "0036" "0037"
		"0038" "0039" "003A"
		"01"                       /* Compression Length  : 0x01 = 1 byte for types   */
		"00"                       /* Compression Type    : 0x00 = NULL compression   */
	};

	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	struct tcpcheck_rule *chk;
	char *errmsg = NULL;
	int err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(0, 1, file, line, args, &err_code))
		goto out;

	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	free_tcpcheck_vars(&rules->preset_vars);
	rules->list  = NULL;
	rules->flags = 0;

	rs = find_tcpcheck_ruleset("*ssl-hello-check");
	if (rs)
		goto ruleset_found;

	rs = create_tcpcheck_ruleset("*ssl-hello-check");
	if (rs == NULL) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}

	chk = parse_tcpcheck_send((char *[]){"tcp-check", "send-binary-lf", sslv3_client_hello, ""},
				  1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 0;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "rbinary", "^1[56]",
				                "min-recv", "5", "ok-status", "L6OK",
				                "error-status", "L6RSP", "tout-status", "L6TOUT",
				                ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_SSL3_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 1;
	LIST_ADDQ(&rs->rules, &chk->list);

  ruleset_found:
	rules->list = &rs->rules;
	rules->flags |= TCPCHK_RULES_SSL3_CHK;

  out:
	free(errmsg);
	return err_code;

  error:
	free_tcpcheck_ruleset(rs);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

/* Parses the "option smtpchk" proxy keyword */
int proxy_parse_smtpchk_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
			    const char *file, int line)
{
	static char *smtp_req = "%[var(check.smtp_cmd)]\r\n";

	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	struct tcpcheck_rule *chk;
	struct tcpcheck_var *var = NULL;
	char *cmd = NULL, *errmsg = NULL;
	int err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(2, 1, file, line, args, &err_code))
		goto out;

	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	free_tcpcheck_vars(&rules->preset_vars);
	rules->list  = NULL;
	rules->flags = 0;

	cur_arg += 2;
	if (*args[cur_arg] && *args[cur_arg+1] &&
	    (strcmp(args[cur_arg], "EHLO") == 0 || strcmp(args[cur_arg], "HELO") == 0)) {
		cmd = calloc(strlen(args[cur_arg]) + strlen(args[cur_arg+1]) + 1, sizeof(*cmd));
		if (cmd)
			sprintf(cmd, "%s %s", args[cur_arg], args[cur_arg+1]);
	}
	else {
		/* this just hits the default for now, but you could potentially expand it to allow for other stuff
		   though, it's unlikely you'd want to send anything other than an EHLO or HELO */
		cmd = strdup("HELO localhost");
	}

	var = create_tcpcheck_var(ist("check.smtp_cmd"));
	if (cmd == NULL || var == NULL) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}
	var->data.type = SMP_T_STR;
	var->data.u.str.area = cmd;
	var->data.u.str.data = strlen(cmd);
	LIST_INIT(&var->list);
	LIST_ADDQ(&rules->preset_vars, &var->list);
	cmd = NULL;
	var = NULL;

	rs = find_tcpcheck_ruleset("*smtp-check");
	if (rs)
		goto ruleset_found;

	rs = create_tcpcheck_ruleset("*smtp-check");
	if (rs == NULL) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}

	chk = parse_tcpcheck_connect((char *[]){"tcp-check", "connect", "default", "linger", ""},
				     1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 0;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "rstring", "^[0-9]{3}[ \r]",
				               "min-recv", "4",
				               "error-status", "L7RSP",
				               "on-error", "%[res.payload(0,0),cut_crlf]",
				               ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_SMTP_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 1;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "rstring", "^2[0-9]{2}[ \r]",
				               "min-recv", "4",
				               "error-status", "L7STS",
				               "on-error", "%[res.payload(4,0),ltrim(' '),cut_crlf]",
				               "status-code", "res.payload(0,3)",
				               ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_SMTP_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 2;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_send((char *[]){"tcp-check", "send-lf", smtp_req, ""},
				  1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 3;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "rstring", "^2[0-9]{2}[- \r]",
				               "min-recv", "4",
				               "error-status", "L7STS",
				               "on-error", "%[res.payload(4,0),ltrim(' '),cut_crlf]",
				               "on-success", "%[res.payload(4,0),ltrim(' '),cut_crlf]",
				               "status-code", "res.payload(0,3)",
				               ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_SMTP_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 4;
	LIST_ADDQ(&rs->rules, &chk->list);

  ruleset_found:
	rules->list = &rs->rules;
	rules->flags |= TCPCHK_RULES_SMTP_CHK;

  out:
	free(errmsg);
	return err_code;

  error:
	free(cmd);
	free(var);
	free_tcpcheck_vars(&rules->preset_vars);
	free_tcpcheck_ruleset(rs);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

/* Parses the "option pgsql-check" proxy keyword */
int proxy_parse_pgsql_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
				const char *file, int line)
{
	static char pgsql_req[] = {
		"%[var(check.plen),htonl,hex]" /* The packet length*/
		"00030000"                     /* the version 3.0 */
		"7573657200"                   /* "user" key */
		"%[var(check.username),hex]00" /* the username */
		"00"
	};

	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	struct tcpcheck_rule *chk;
	struct tcpcheck_var *var = NULL;
	char *user = NULL, *errmsg = NULL;
	size_t packetlen = 0;
	int err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(2, 1, file, line, args, &err_code))
		goto out;

	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	free_tcpcheck_vars(&rules->preset_vars);
	rules->list  = NULL;
	rules->flags = 0;

	cur_arg += 2;
	if (!*args[cur_arg] || !*args[cur_arg+1]) {
		ha_alert("parsing [%s:%d] : '%s %s' expects 'user <username>' as argument.\n",
			 file, line, args[0], args[1]);
		goto error;
	}
	if (strcmp(args[cur_arg], "user") == 0) {
		packetlen = 15 + strlen(args[cur_arg+1]);
		user = strdup(args[cur_arg+1]);

		var = create_tcpcheck_var(ist("check.username"));
		if (user == NULL || var == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
			goto error;
		}
		var->data.type = SMP_T_STR;
		var->data.u.str.area = user;
		var->data.u.str.data = strlen(user);
		LIST_INIT(&var->list);
		LIST_ADDQ(&rules->preset_vars, &var->list);
		user = NULL;
		var = NULL;

		var = create_tcpcheck_var(ist("check.plen"));
		if (var == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
			goto error;
		}
		var->data.type = SMP_T_SINT;
		var->data.u.sint = packetlen;
		LIST_INIT(&var->list);
		LIST_ADDQ(&rules->preset_vars, &var->list);
		var = NULL;
	}
	else {
		ha_alert("parsing [%s:%d] : '%s %s' only supports optional values: 'user'.\n",
			 file, line, args[0], args[1]);
		goto error;
	}

	rs = find_tcpcheck_ruleset("*pgsql-check");
	if (rs)
		goto ruleset_found;

	rs = create_tcpcheck_ruleset("*pgsql-check");
	if (rs == NULL) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}

	chk = parse_tcpcheck_connect((char *[]){"tcp-check", "connect", "default", "linger", ""},
				     1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 0;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_send((char *[]){"tcp-check", "send-binary-lf", pgsql_req, ""},
				  1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 1;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "!rstring", "^E",
				               "min-recv", "5",
				               "error-status", "L7RSP",
				               "on-error", "%[res.payload(6,0)]",
				               ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_PGSQL_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 2;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "rbinary", "^52000000(08|0A|0C)000000(00|02|03|04|05|06)",
				               "min-recv", "9",
				               "error-status", "L7STS",
				               "on-success", "PostgreSQL server is ok",
				               "on-error",   "PostgreSQL unknown error",
				               ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_PGSQL_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 3;
	LIST_ADDQ(&rs->rules, &chk->list);

  ruleset_found:
	rules->list = &rs->rules;
	rules->flags |= TCPCHK_RULES_PGSQL_CHK;

  out:
	free(errmsg);
	return err_code;

  error:
	free(user);
	free(var);
	free_tcpcheck_vars(&rules->preset_vars);
	free_tcpcheck_ruleset(rs);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}


/* Parses the "option mysql-check" proxy keyword */
int proxy_parse_mysql_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
				const char *file, int line)
{
	/* This is an example of a MySQL >=4.0 client Authentication packet kindly provided by Cyril Bonte.
	 * const char mysql40_client_auth_pkt[] = {
	 * 	"\x0e\x00\x00"	// packet length
	 * 	"\x01"		// packet number
	 * 	"\x00\x00"	// client capabilities
	 * 	"\x00\x00\x01"	// max packet
	 * 	"haproxy\x00"	// username (null terminated string)
	 * 	"\x00"		// filler (always 0x00)
	 * 	"\x01\x00\x00"	// packet length
	 * 	"\x00"		// packet number
	 * 	"\x01"		// COM_QUIT command
	 * };
	 */
	static char mysql40_rsname[] = "*mysql40-check";
	static char mysql40_req[] = {
		"%[var(check.header),hex]"     /* 3 bytes for the packet length and 1 byte for the sequence ID */
		"0080"                         /* client capabilities */
		"000001"                       /* max packet */
		"%[var(check.username),hex]00" /* the username */
		"00"                           /* filler (always 0x00) */
		"010000"                       /* packet length*/
		"00"                           /* sequence ID */
		"01"                           /* COM_QUIT command */
	};

	/* This is an example of a MySQL >=4.1  client Authentication packet provided by Nenad Merdanovic.
	 * const char mysql41_client_auth_pkt[] = {
	 * 	"\x0e\x00\x00\"		// packet length
	 * 	"\x01"			// packet number
	 * 	"\x00\x00\x00\x00"	// client capabilities
	 * 	"\x00\x00\x00\x01"	// max packet
	 *	"\x21"			// character set (UTF-8)
	 *	char[23]		// All zeroes
	 * 	"haproxy\x00"		// username (null terminated string)
	 * 	"\x00"			// filler (always 0x00)
	 * 	"\x01\x00\x00"		// packet length
	 * 	"\x00"			// packet number
	 * 	"\x01"			// COM_QUIT command
	 * };
	 */
	static char mysql41_rsname[] = "*mysql41-check";
	static char mysql41_req[] = {
		"%[var(check.header),hex]"     /* 3 bytes for the packet length and 1 byte for the sequence ID */
		"00820000"                     /* client capabilities */
		"00800001"                     /* max packet */
		"21"                           /* character set (UTF-8) */
		"000000000000000000000000"     /* 23 bytes, al zeroes */
		"0000000000000000000000"
		"%[var(check.username),hex]00" /* the username */
		"00"                           /* filler (always 0x00) */
		"010000"                       /* packet length*/
		"00"                           /* sequence ID */
		"01"                           /* COM_QUIT command */
	};

	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	struct tcpcheck_rule *chk;
	struct tcpcheck_var *var = NULL;
	char *mysql_rsname = "*mysql-check";
	char *mysql_req = NULL, *hdr = NULL, *user = NULL, *errmsg = NULL;
	int index = 0, err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(3, 1, file, line, args, &err_code))
		goto out;

	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	free_tcpcheck_vars(&rules->preset_vars);
	rules->list  = NULL;
	rules->flags = 0;

	cur_arg += 2;
	if (*args[cur_arg]) {
		int packetlen, userlen;

		if (strcmp(args[cur_arg], "user") != 0) {
			ha_alert("parsing [%s:%d] : '%s %s' only supports optional values: 'user' (got '%s').\n",
				 file, line, args[0], args[1], args[cur_arg]);
			goto error;
		}

		if (*(args[cur_arg+1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s %s %s' expects <username> as argument.\n",
				 file, line, args[0], args[1], args[cur_arg]);
			goto error;
		}

		hdr     = calloc(4, sizeof(*hdr));
		user    = strdup(args[cur_arg+1]);
		userlen = strlen(args[cur_arg+1]);

		if (hdr == NULL || user == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
			goto error;
		}

		if (!*args[cur_arg+2] || strcmp(args[cur_arg+2], "post-41") == 0) {
			packetlen = userlen + 7 + 27;
			mysql_req = mysql41_req;
			mysql_rsname  = mysql41_rsname;
		}
		else if (strcmp(args[cur_arg+2], "pre-41") == 0) {
			packetlen = userlen + 7;
			mysql_req = mysql40_req;
			mysql_rsname  = mysql40_rsname;
		}
		else  {
			ha_alert("parsing [%s:%d] : keyword '%s' only supports 'post-41' and 'pre-41' (got '%s').\n",
				 file, line, args[cur_arg], args[cur_arg+2]);
			goto error;
		}

		hdr[0] = (unsigned char)(packetlen & 0xff);
		hdr[1] = (unsigned char)((packetlen >> 8) & 0xff);
		hdr[2] = (unsigned char)((packetlen >> 16) & 0xff);
		hdr[3] = 1;

		var = create_tcpcheck_var(ist("check.header"));
		if (var == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
			goto error;
		}
		var->data.type = SMP_T_STR;
		var->data.u.str.area = hdr;
		var->data.u.str.data = 4;
		LIST_INIT(&var->list);
		LIST_ADDQ(&rules->preset_vars, &var->list);
		hdr = NULL;
		var = NULL;

		var = create_tcpcheck_var(ist("check.username"));
		if (var == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
			goto error;
		}
		var->data.type = SMP_T_STR;
		var->data.u.str.area = user;
		var->data.u.str.data = strlen(user);
		LIST_INIT(&var->list);
		LIST_ADDQ(&rules->preset_vars, &var->list);
		user = NULL;
		var = NULL;
	}

	rs = find_tcpcheck_ruleset(mysql_rsname);
	if (rs)
		goto ruleset_found;

	rs = create_tcpcheck_ruleset(mysql_rsname);
	if (rs == NULL) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}

	chk = parse_tcpcheck_connect((char *[]){"tcp-check", "connect", "default", "linger", ""},
				     1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = index++;
	LIST_ADDQ(&rs->rules, &chk->list);

	if (mysql_req) {
		chk = parse_tcpcheck_send((char *[]){"tcp-check", "send-binary-lf", mysql_req, ""},
					  1, curpx, &rs->rules, file, line, &errmsg);
		if (!chk) {
			ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
			goto error;
		}
		chk->index = index++;
		LIST_ADDQ(&rs->rules, &chk->list);
	}

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "custom", ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_MYSQL_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->expect.custom = tcpcheck_mysql_expect_iniths;
	chk->index = index++;
	LIST_ADDQ(&rs->rules, &chk->list);

	if (mysql_req) {
		chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "custom", ""},
					    1, curpx, &rs->rules, TCPCHK_RULES_MYSQL_CHK, file, line, &errmsg);
		if (!chk) {
			ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
			goto error;
		}
		chk->expect.custom = tcpcheck_mysql_expect_ok;
		chk->index = index++;
		LIST_ADDQ(&rs->rules, &chk->list);
	}

  ruleset_found:
	rules->list = &rs->rules;
	rules->flags |= TCPCHK_RULES_MYSQL_CHK;

  out:
	free(errmsg);
	return err_code;

  error:
	free(hdr);
	free(user);
	free(var);
	free_tcpcheck_vars(&rules->preset_vars);
	free_tcpcheck_ruleset(rs);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

int proxy_parse_ldap_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
			       const char *file, int line)
{
	static char *ldap_req = "300C020101600702010304008000";

	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	struct tcpcheck_rule *chk;
	char *errmsg = NULL;
	int err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(0, 1, file, line, args, &err_code))
		goto out;

	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	free_tcpcheck_vars(&rules->preset_vars);
	rules->list  = NULL;
	rules->flags = 0;

	rs = find_tcpcheck_ruleset("*ldap-check");
	if (rs)
		goto ruleset_found;

	rs = create_tcpcheck_ruleset("*ldap-check");
	if (rs == NULL) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}

	chk = parse_tcpcheck_send((char *[]){"tcp-check", "send-binary", ldap_req, ""},
				  1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 0;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "rbinary", "^30",
				               "min-recv", "14",
				               "on-error", "Not LDAPv3 protocol",
				               ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_LDAP_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 1;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "custom", ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_LDAP_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->expect.custom = tcpcheck_ldap_expect_bindrsp;
	chk->index = 2;
	LIST_ADDQ(&rs->rules, &chk->list);

  ruleset_found:
	rules->list = &rs->rules;
	rules->flags |= TCPCHK_RULES_LDAP_CHK;

  out:
	free(errmsg);
	return err_code;

  error:
	free_tcpcheck_ruleset(rs);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

int proxy_parse_spop_check_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
			       const char *file, int line)
{
	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	struct tcpcheck_rule *chk;
	char *spop_req = NULL;
	char *errmsg = NULL;
	int spop_len = 0, err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(0, 1, file, line, args, &err_code))
		goto out;

	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	free_tcpcheck_vars(&rules->preset_vars);
	rules->list  = NULL;
	rules->flags = 0;


	rs = find_tcpcheck_ruleset("*spop-check");
	if (rs)
		goto ruleset_found;

	rs = create_tcpcheck_ruleset("*spop-check");
	if (rs == NULL) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}

	if (spoe_prepare_healthcheck_request(&spop_req, &spop_len) == -1) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
		goto error;
	}
	chunk_reset(&trash);
	dump_binary(&trash, spop_req, spop_len);
	trash.area[trash.data] = '\0';

	chk = parse_tcpcheck_send((char *[]){"tcp-check", "send-binary", b_head(&trash), ""},
				  1, curpx, &rs->rules, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->index = 0;
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "custom", "min-recv", "4", ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_SPOP_CHK, file, line, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : %s\n", file, line, errmsg);
		goto error;
	}
	chk->expect.custom = tcpcheck_spop_expect_agenthello;
	chk->index = 1;
	LIST_ADDQ(&rs->rules, &chk->list);

  ruleset_found:
	rules->list = &rs->rules;
	rules->flags |= TCPCHK_RULES_SPOP_CHK;

  out:
	free(spop_req);
	free(errmsg);
	return err_code;

  error:
	free_tcpcheck_ruleset(rs);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}


struct tcpcheck_rule *proxy_parse_httpchk_req(char **args, int cur_arg, struct proxy *px, char **errmsg)
{
	struct tcpcheck_rule *chk = NULL;
	struct tcpcheck_http_hdr *hdr = NULL;
	char *meth = NULL, *uri = NULL, *vsn = NULL;
	char *hdrs, *body;

	hdrs = (*args[cur_arg+2] ? strstr(args[cur_arg+2], "\r\n") : NULL);
	body = (*args[cur_arg+2] ? strstr(args[cur_arg+2], "\r\n\r\n") : NULL);
	if (hdrs == body)
		hdrs = NULL;
	if (hdrs) {
		*hdrs = '\0';
		hdrs +=2;
	}
	if (body) {
		*body = '\0';
		body += 4;
	}
	if (hdrs || body) {
		memprintf(errmsg, "hiding headers or body at the end of the version string is deprecated."
			  " Please, consider to use 'http-check send' directive instead.");
	}

	chk = calloc(1, sizeof(*chk));
	if (!chk) {
		memprintf(errmsg, "out of memory");
		goto error;
	}
	chk->action    = TCPCHK_ACT_SEND;
	chk->send.type = TCPCHK_SEND_HTTP;
	chk->send.http.flags |= TCPCHK_SND_HTTP_FROM_OPT;
	chk->send.http.meth.meth = HTTP_METH_OPTIONS;
	LIST_INIT(&chk->send.http.hdrs);

	/* Copy the method, uri and version */
	if (*args[cur_arg]) {
		if (!*args[cur_arg+1])
			uri = args[cur_arg];
		else
			meth = args[cur_arg];
	}
	if (*args[cur_arg+1])
		uri = args[cur_arg+1];
	if (*args[cur_arg+2])
		vsn = args[cur_arg+2];

	if (meth) {
		chk->send.http.meth.meth = find_http_meth(meth, strlen(meth));
		chk->send.http.meth.str.area = strdup(meth);
		chk->send.http.meth.str.data = strlen(meth);
		if (!chk->send.http.meth.str.area) {
			memprintf(errmsg, "out of memory");
			goto error;
		}
	}
	if (uri) {
		chk->send.http.uri = ist2(strdup(uri), strlen(uri));
		if (!isttest(chk->send.http.uri)) {
			memprintf(errmsg, "out of memory");
			goto error;
		}
	}
	if (vsn) {
		chk->send.http.vsn = ist2(strdup(vsn), strlen(vsn));
		if (!isttest(chk->send.http.vsn)) {
			memprintf(errmsg, "out of memory");
			goto error;
		}
	}

	/* Copy the header */
	if (hdrs) {
		struct http_hdr tmp_hdrs[global.tune.max_http_hdr];
		struct h1m h1m;
		int i, ret;

		/* Build and parse the request */
		chunk_printf(&trash, "%s\r\n\r\n", hdrs);

		h1m.flags = H1_MF_HDRS_ONLY;
		ret = h1_headers_to_hdr_list(b_orig(&trash), b_tail(&trash),
					     tmp_hdrs, sizeof(tmp_hdrs)/sizeof(tmp_hdrs[0]),
					     &h1m, NULL);
		if (ret <= 0) {
			memprintf(errmsg, "unable to parse the request '%s'.", b_orig(&trash));
			goto error;
		}

		for (i = 0; istlen(tmp_hdrs[i].n); i++) {
			hdr = calloc(1, sizeof(*hdr));
			if (!hdr) {
				memprintf(errmsg, "out of memory");
				goto error;
			}
			LIST_INIT(&hdr->value);
			hdr->name = istdup(tmp_hdrs[i].n);
			if (!hdr->name.ptr) {
				memprintf(errmsg, "out of memory");
				goto error;
			}

			ist0(tmp_hdrs[i].v);
			if (!parse_logformat_string(istptr(tmp_hdrs[i].v), px, &hdr->value, 0, SMP_VAL_BE_CHK_RUL, errmsg))
				goto error;
			LIST_ADDQ(&chk->send.http.hdrs, &hdr->list);
		}
	}

	/* Copy the body */
	if (body) {
		chk->send.http.body = ist2(strdup(body), strlen(body));
		if (!isttest(chk->send.http.body)) {
			memprintf(errmsg, "out of memory");
			goto error;
		}
	}

	return chk;

  error:
	free_tcpcheck_http_hdr(hdr);
	free_tcpcheck(chk, 0);
	return NULL;
}

int proxy_parse_httpchk_opt(char **args, int cur_arg, struct proxy *curpx, struct proxy *defpx,
			    const char *file, int line)
{
	struct tcpcheck_ruleset *rs = NULL;
	struct tcpcheck_rules *rules = &curpx->tcpcheck_rules;
	struct tcpcheck_rule *chk;
	char *errmsg = NULL;
	int err_code = 0;

	if (warnifnotcap(curpx, PR_CAP_BE, file, line, args[cur_arg+1], NULL))
		err_code |= ERR_WARN;

	if (alertif_too_many_args_idx(3, 1, file, line, args, &err_code))
		goto out;

	chk = proxy_parse_httpchk_req(args, cur_arg+2, curpx, &errmsg);
	if (!chk) {
		ha_alert("parsing [%s:%d] : '%s %s' : %s.\n", file, line, args[0], args[1], errmsg);
		goto error;
	}
	if (errmsg) {
		ha_warning("parsing [%s:%d]: '%s %s' : %s\n", file, line, args[0], args[1], errmsg);
		err_code |= ERR_WARN;
		free(errmsg);
		errmsg = NULL;
	}

  no_request:
	curpx->options2 &= ~PR_O2_CHK_ANY;
	curpx->options2 |= PR_O2_TCPCHK_CHK;

	free_tcpcheck_vars(&rules->preset_vars);
	rules->list = NULL;
	rules->flags |= TCPCHK_SND_HTTP_FROM_OPT;

	/* Deduce the ruleset name from the proxy info */
	chunk_printf(&trash, "*http-check-%s_%s-%d",
		     ((curpx == defpx) ? "defaults" : curpx->id),
		     curpx->conf.file, curpx->conf.line);

	rs = find_tcpcheck_ruleset(b_orig(&trash));
	if (rs == NULL) {
		rs = create_tcpcheck_ruleset(b_orig(&trash));
		if (rs == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, line);
			goto error;
		}
	}

	rules->list = &rs->rules;
	rules->flags |= TCPCHK_RULES_HTTP_CHK;
	if (!tcpcheck_add_http_rule(chk, rules, &errmsg)) {
		ha_alert("parsing [%s:%d] : '%s %s' : %s.\n", file, line, args[0], args[1], errmsg);
		rules->list = NULL;
		goto error;
	}

  out:
	free(errmsg);
	return err_code;

  error:
	free_tcpcheck_ruleset(rs);
	free_tcpcheck(chk, 0);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

/* Parse the "addr" server keyword */
static int srv_parse_addr(char **args, int *cur_arg, struct proxy *curpx, struct server *srv,
			  char **errmsg)
{
	struct sockaddr_storage *sk;
	struct protocol *proto;
	int port1, port2, err_code = 0;


	if (!*args[*cur_arg+1]) {
		memprintf(errmsg, "'%s' expects <ipv4|ipv6> as argument.", args[*cur_arg]);
		goto error;
	}

	sk = str2sa_range(args[*cur_arg+1], NULL, &port1, &port2, errmsg, NULL, NULL, 1);
	if (!sk) {
		memprintf(errmsg, "'%s' : %s", args[*cur_arg], *errmsg);
		goto error;
	}

	proto = protocol_by_family(sk->ss_family);
	if (!proto || !proto->connect) {
		memprintf(errmsg, "'%s %s' : connect() not supported for this address family.",
		          args[*cur_arg], args[*cur_arg+1]);
		goto error;
	}

	if (port1 != port2) {
		memprintf(errmsg, "'%s' : port ranges and offsets are not allowed in '%s'.",
		          args[*cur_arg], args[*cur_arg+1]);
		goto error;
	}

	srv->check.addr = srv->agent.addr = *sk;
	srv->flags |= SRV_F_CHECKADDR;
	srv->flags |= SRV_F_AGENTADDR;

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
	int err_code = 0;

	if (!*(args[*cur_arg+1])) {
		memprintf(errmsg, "'%s' expects an address as argument.", args[*cur_arg]);
		goto error;
	}
	if(str2ip(args[*cur_arg+1], &srv->agent.addr) == NULL) {
		memprintf(errmsg, "parsing agent-addr failed. Check if '%s' is correct address.", args[*cur_arg+1]);
		goto error;
	}

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
	LIST_ADDQ(&rs->rules, &chk->list);

	chk = parse_tcpcheck_expect((char *[]){"tcp-check", "expect", "custom", ""},
		                    1, curpx, &rs->rules, TCPCHK_RULES_AGENT_CHK,
				    srv->conf.file, srv->conf.line, errmsg);
	if (!chk) {
		memprintf(errmsg, "'%s': %s", args[*cur_arg], *errmsg);
		goto error;
	}
	chk->expect.custom = tcpcheck_agent_expect_reply;
	chk->index = 1;
	LIST_ADDQ(&rs->rules, &chk->list);

  ruleset_found:
	rules->list = &rs->rules;
	rules->flags |= TCPCHK_RULES_AGENT_CHK;
	srv->do_agent = 1;

  out:
	return 0;

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

	global.maxsock++;
	srv->agent.port = atol(args[*cur_arg+1]);

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
	LIST_ADDQ(&rules->preset_vars, &var->list);

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
	newsrv->check.mux_proto = get_mux_proto(ist2(args[*cur_arg + 1], strlen(args[*cur_arg + 1])));
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
	return 0;
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
	return 0;
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

	global.maxsock++;
	srv->check.port = atol(args[*cur_arg+1]);
	srv->flags |= SRV_F_CHECKPORT;

  out:
	return err_code;

  error:
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
}

static struct cfg_kw_list cfg_kws = {ILH, {
        { CFG_LISTEN, "http-check",     proxy_parse_httpcheck },
        { 0, NULL, NULL },
}};

static struct srv_kw_list srv_kws = { "CHK", { }, {
	{ "addr",                srv_parse_addr,                1,  1 }, /* IP address to send health to or to probe from agent-check */
	{ "agent-addr",          srv_parse_agent_addr,          1,  1 }, /* Enable an auxiliary agent check */
	{ "agent-check",         srv_parse_agent_check,         0,  1 }, /* Enable agent checks */
	{ "agent-inter",         srv_parse_agent_inter,         1,  1 }, /* Set the interval between two agent checks */
	{ "agent-port",          srv_parse_agent_port,          1,  1 }, /* Set the TCP port used for agent checks. */
	{ "agent-send",          srv_parse_agent_send,          1,  1 }, /* Set string to send to agent. */
	{ "check",               srv_parse_check,               0,  1 }, /* Enable health checks */
	{ "check-proto",         srv_parse_check_proto,         1,  1 }, /* Set the mux protocol for health checks  */
	{ "check-send-proxy",    srv_parse_check_send_proxy,    0,  1 }, /* Enable PROXY protocol for health checks */
	{ "check-via-socks4",    srv_parse_check_via_socks4,    0,  1 }, /* Enable socks4 proxy for health checks */
	{ "no-agent-check",      srv_parse_no_agent_check,      0,  1 }, /* Do not enable any auxiliary agent check */
	{ "no-check",            srv_parse_no_check,            0,  1 }, /* Disable health checks */
	{ "no-check-send-proxy", srv_parse_no_check_send_proxy, 0,  1 }, /* Disable PROXY protol for health checks */
	{ "rise",                srv_parse_check_rise,          1,  1 }, /* Set rise value for health checks */
	{ "fall",                srv_parse_check_fall,          1,  1 }, /* Set fall value for health checks */
	{ "inter",               srv_parse_check_inter,         1,  1 }, /* Set inter value for health checks */
	{ "fastinter",           srv_parse_check_fastinter,     1,  1 }, /* Set fastinter value for health checks */
	{ "downinter",           srv_parse_check_downinter,     1,  1 }, /* Set downinter value for health checks */
	{ "port",                srv_parse_check_port,          1,  1 }, /* Set the TCP port used for health checks. */
	{ NULL, NULL, 0 },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
INITCALL1(STG_REGISTER, srv_register_keywords, &srv_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
