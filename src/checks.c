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
#include <signal.h>
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

#include <common/chunk.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/time.h>
#include <common/hathreads.h>

#include <types/global.h>
#include <types/dns.h>
#include <types/stats.h>

#include <proto/backend.h>
#include <proto/checks.h>
#include <proto/stats.h>
#include <proto/fd.h>
#include <proto/log.h>
#include <proto/mux_pt.h>
#include <proto/queue.h>
#include <proto/port_range.h>
#include <proto/proto_tcp.h>
#include <proto/protocol.h>
#include <proto/proxy.h>
#include <proto/server.h>
#include <proto/signal.h>
#include <proto/stream_interface.h>
#include <proto/task.h>
#include <proto/log.h>
#include <proto/dns.h>
#include <proto/proto_udp.h>
#include <proto/ssl_sock.h>

static int httpchk_expect(struct server *s, int done);
static int tcpcheck_get_step_id(struct check *);
static char * tcpcheck_get_step_comment(struct check *, int);
static int tcpcheck_main(struct check *);
static void __event_srv_chk_w(struct conn_stream *cs);
static int wake_srv_chk(struct conn_stream *cs);
static void __event_srv_chk_r(struct conn_stream *cs);

DECLARE_STATIC_POOL(pool_head_email_alert,   "email_alert",   sizeof(struct email_alert));
DECLARE_STATIC_POOL(pool_head_tcpcheck_rule, "tcpcheck_rule", sizeof(struct tcpcheck_rule));


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

const struct extcheck_env extcheck_envs[EXTCHK_SIZE] = {
	[EXTCHK_PATH]                   = { "PATH",                   EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_PROXY_NAME]     = { "HAPROXY_PROXY_NAME",     EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_PROXY_ID]       = { "HAPROXY_PROXY_ID",       EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_PROXY_ADDR]     = { "HAPROXY_PROXY_ADDR",     EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_PROXY_PORT]     = { "HAPROXY_PROXY_PORT",     EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_SERVER_NAME]    = { "HAPROXY_SERVER_NAME",    EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_SERVER_ID]      = { "HAPROXY_SERVER_ID",      EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_SERVER_ADDR]    = { "HAPROXY_SERVER_ADDR",    EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_SERVER_PORT]    = { "HAPROXY_SERVER_PORT",    EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_SERVER_MAXCONN] = { "HAPROXY_SERVER_MAXCONN", EXTCHK_SIZE_EVAL_INIT },
	[EXTCHK_HAPROXY_SERVER_CURCONN] = { "HAPROXY_SERVER_CURCONN", EXTCHK_SIZE_ULONG },
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

/*
 * Convert check_status code to description
 */
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

/*
 * Convert check_status code to short info
 */
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

/*
 * Set check->status, update check->duration and fill check->result with
 * an adequate CHK_RES_* value. The new check->health is computed based
 * on the result.
 *
 * Show information in logs about failed health check if server is UP
 * or succeeded health checks if server is DOWN.
 */
static void set_server_check_status(struct check *check, short status, const char *desc)
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
static void check_notify_failure(struct check *check)
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
static void check_notify_success(struct check *check)
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
static void check_notify_stopping(struct check *check)
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

static int httpchk_build_status_header(struct server *s, char *buffer, int size)
{
	int sv_state;
	int ratio;
	int hlen = 0;
	char addr[46];
	char port[6];
	const char *srv_hlt_st[7] = { "DOWN", "DOWN %d/%d",
				      "UP %d/%d", "UP",
				      "NOLB %d/%d", "NOLB",
				      "no check" };

	memcpy(buffer + hlen, "X-Haproxy-Server-State: ", 24);
	hlen += 24;

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

	hlen += snprintf(buffer + hlen, size - hlen,
			     srv_hlt_st[sv_state],
			     (s->cur_state != SRV_ST_STOPPED) ? (s->check.health - s->check.rise + 1) : (s->check.health),
			     (s->cur_state != SRV_ST_STOPPED) ? (s->check.fall) : (s->check.rise));

	addr_to_str(&s->addr, addr, sizeof(addr));
	if (s->addr.ss_family == AF_INET || s->addr.ss_family == AF_INET6)
		snprintf(port, sizeof(port), "%u", s->svc_port);
	else
		*port = 0;

	hlen += snprintf(buffer + hlen,  size - hlen, "; address=%s; port=%s; name=%s/%s; node=%s; weight=%d/%d; scur=%d/%d; qcur=%d",
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
		hlen += snprintf(buffer + hlen, size - hlen, "; throttle=%d%%", ratio);
	}

	buffer[hlen++] = '\r';
	buffer[hlen++] = '\n';

	return hlen;
}

/* Check the connection. If an error has already been reported or the socket is
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

	if (conn->flags & CO_FL_ERROR && ((errno && errno != EAGAIN) || !conn->ctrl))
		return 1;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (getsockopt(conn->handle.fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr) == 0)
		errno = skerr;

	if (errno == EAGAIN)
		errno = 0;

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

/* Try to collect as much information as possible on the connection status,
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
static void chk_report_conn_err(struct check *check, int errno_bck, int expired)
{
	struct conn_stream *cs = check->cs;
	struct connection *conn = cs_conn(cs);
	const char *err_msg;
	struct buffer *chk;
	int step;
	char *comment;

	if (check->result != CHK_RES_UNKNOWN)
		return;

	errno = errno_bck;
	if (conn && (!errno || errno == EAGAIN))
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

	if (check->type == PR_O2_TCPCHK_CHK) {
		step = tcpcheck_get_step_id(check);
		if (!step)
			chunk_printf(chk, " at initial connection step of tcp-check");
		else {
			chunk_printf(chk, " at step %d of tcp-check", step);
			/* we were looking for a string */
			if (check->last_started_step && check->last_started_step->action == TCPCHK_ACT_CONNECT) {
				if (check->last_started_step->port)
					chunk_appendf(chk, " (connect port %d)" ,check->last_started_step->port);
				else
					chunk_appendf(chk, " (connect)");
			}
			else if (check->last_started_step && check->last_started_step->action == TCPCHK_ACT_EXPECT) {
				if (check->last_started_step->string)
					chunk_appendf(chk, " (expect string '%s')", check->last_started_step->string);
				else if (check->last_started_step->expect_regex)
					chunk_appendf(chk, " (expect regex)");
			}
			else if (check->last_started_step && check->last_started_step->action == TCPCHK_ACT_SEND) {
				chunk_appendf(chk, " (send)");
			}

			comment = tcpcheck_get_step_comment(check, step);
			if (comment)
				chunk_appendf(chk, " comment: '%s'", comment);
		}
	}

	if (conn && conn->err_code) {
		if (errno && errno != EAGAIN)
			chunk_printf(&trash, "%s (%s)%s", conn_err_code_str(conn), strerror(errno),
				     chk->area);
		else
			chunk_printf(&trash, "%s%s", conn_err_code_str(conn),
				     chk->area);
		err_msg = trash.area;
	}
	else {
		if (errno && errno != EAGAIN) {
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
	else if ((conn->flags & (CO_FL_CONNECTED|CO_FL_WAIT_L4_CONN)) == CO_FL_WAIT_L4_CONN) {
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
	else if ((conn->flags & (CO_FL_CONNECTED|CO_FL_WAIT_L6_CONN)) == CO_FL_WAIT_L6_CONN) {
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
		/* connection established but expired check */
		if (check->type == PR_O2_SSL3_CHK)
			set_server_check_status(check, HCHK_STATUS_L6TOUT, err_msg);
		else	/* HTTP, SMTP, ... */
			set_server_check_status(check, HCHK_STATUS_L7TOUT, err_msg);
	}

	return;
}

/* This function checks if any I/O is wanted, and if so, attempts to do so */
static struct task *event_srv_chk_io(struct task *t, void *ctx, unsigned short state)
{
	struct check *check = ctx;
	struct conn_stream *cs = check->cs;
	struct email_alertq *q = container_of(check, typeof(*q), check);
	int ret = 0;

	if (!(check->wait_list.events & SUB_RETRY_SEND))
		ret = wake_srv_chk(cs);
	if (ret == 0 && !(check->wait_list.events & SUB_RETRY_RECV)) {
		if (check->server)
			HA_SPIN_LOCK(SERVER_LOCK, &check->server->lock);
		else
			HA_SPIN_LOCK(EMAIL_ALERTS_LOCK, &q->lock);
		__event_srv_chk_r(cs);
		if (check->server)
			HA_SPIN_UNLOCK(SERVER_LOCK, &check->server->lock);
		else
			HA_SPIN_UNLOCK(EMAIL_ALERTS_LOCK, &q->lock);
	}
	return NULL;
}

/* same as above but protected by the server lock.
 *
 * Please do NOT place any return statement in this function and only leave
 * via the out label. NOTE THAT THIS FUNCTION DOESN'T LOCK, YOU PROBABLY WANT
 * TO USE event_srv_chk_w() instead.
 */
static void __event_srv_chk_w(struct conn_stream *cs)
{
	struct connection *conn = cs->conn;
	struct check *check = cs->data;
	struct server *s = check->server;
	struct task *t = check->task;

	if (unlikely(check->result == CHK_RES_FAILED))
		goto out_wakeup;

	if (conn->flags & CO_FL_HANDSHAKE) {
		if (!(conn->flags & CO_FL_ERROR))
			cs->conn->mux->subscribe(cs, SUB_RETRY_SEND, &check->wait_list);
		goto out;
	}

	if (retrieve_errno_from_socket(conn)) {
		chk_report_conn_err(check, errno, 0);
		goto out_wakeup;
	}

	if (conn->flags & CO_FL_SOCK_WR_SH) {
		/* if the output is closed, we can't do anything */
		conn->flags |= CO_FL_ERROR;
		chk_report_conn_err(check, 0, 0);
		goto out_wakeup;
	}

	/* here, we know that the connection is established. That's enough for
	 * a pure TCP check.
	 */
	if (!check->type)
		goto out_wakeup;

	/* wake() will take care of calling tcpcheck_main() */
	if (check->type == PR_O2_TCPCHK_CHK)
		goto out;

	if (b_data(&check->bo)) {
		cs->conn->mux->snd_buf(cs, &check->bo, b_data(&check->bo), 0);
		b_realign_if_empty(&check->bo);
		if (conn->flags & CO_FL_ERROR || cs->flags & CS_FL_ERROR) {
			chk_report_conn_err(check, errno, 0);
			goto out_wakeup;
		}
		if (b_data(&check->bo)) {
			conn->mux->subscribe(cs, SUB_RETRY_SEND, &check->wait_list);
			goto out;
		}
	}

	if (!b_data(&check->bo))
		conn_xprt_stop_send(conn);

	/* full request sent, we allow up to <timeout.check> if nonzero for a response */
	if (s->proxy->timeout.check) {
		t->expire = tick_add_ifset(now_ms, s->proxy->timeout.check);
		task_queue(t);
	}
	goto out;

 out_wakeup:
	task_wakeup(t, TASK_WOKEN_IO);
 out:
	return;
}

/*
 * This function is used only for server health-checks. It handles the server's
 * reply to an HTTP request, SSL HELLO or MySQL client Auth. It calls
 * set_server_check_status() to update check->status, check->duration
 * and check->result.

 * The set_server_check_status function is called with HCHK_STATUS_L7OKD if
 * an HTTP server replies HTTP 2xx or 3xx (valid responses), if an SMTP server
 * returns 2xx, HCHK_STATUS_L6OK if an SSL server returns at least 5 bytes in
 * response to an SSL HELLO (the principle is that this is enough to
 * distinguish between an SSL server and a pure TCP relay). All other cases will
 * call it with a proper error status like HCHK_STATUS_L7STS, HCHK_STATUS_L6RSP,
 * etc.
 *
 * Please do NOT place any return statement in this function and only leave
 * via the out label.
 *
 * This must be called with the server lock held.
 */
static void __event_srv_chk_r(struct conn_stream *cs)
{
	struct connection *conn = cs->conn;
	struct check *check = cs->data;
	struct server *s = check->server;
	struct task *t = check->task;
	char *desc;
	int done;
	unsigned short msglen;

	if (unlikely(check->result == CHK_RES_FAILED))
		goto out_wakeup;

	if (conn->flags & CO_FL_HANDSHAKE) {
		if (!(conn->flags & CO_FL_ERROR))
			cs->conn->mux->subscribe(cs, SUB_RETRY_RECV, &check->wait_list);
		goto out;
	}

	/* wake() will take care of calling tcpcheck_main() */
	if (check->type == PR_O2_TCPCHK_CHK)
		goto out;

	/* Warning! Linux returns EAGAIN on SO_ERROR if data are still available
	 * but the connection was closed on the remote end. Fortunately, recv still
	 * works correctly and we don't need to do the getsockopt() on linux.
	 */

	/* Set buffer to point to the end of the data already read, and check
	 * that there is free space remaining. If the buffer is full, proceed
	 * with running the checks without attempting another socket read.
	 */

	done = 0;

	cs->conn->mux->rcv_buf(cs, &check->bi, b_size(&check->bi), 0);
	if (conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH) || cs->flags & CS_FL_ERROR) {
		done = 1;
		if ((conn->flags & CO_FL_ERROR || cs->flags & CS_FL_ERROR) && !b_data(&check->bi)) {
			/* Report network errors only if we got no other data. Otherwise
			 * we'll let the upper layers decide whether the response is OK
			 * or not. It is very common that an RST sent by the server is
			 * reported as an error just after the last data chunk.
			 */
			chk_report_conn_err(check, errno, 0);
			goto out_wakeup;
		}
	}

	/* the rest of the code below expects the connection to be ready! */
	if (!(conn->flags & CO_FL_CONNECTED) && !done)
		goto wait_more_data;

	/* Intermediate or complete response received.
	 * Terminate string in b_head(&check->bi) buffer.
	 */
	if (b_data(&check->bi) < b_size(&check->bi))
		b_head(&check->bi)[b_data(&check->bi)] = '\0';
	else {
		b_head(&check->bi)[b_data(&check->bi) - 1] = '\0';
		done = 1; /* buffer full, don't wait for more data */
	}

	/* Run the checks... */
	switch (check->type) {
	case PR_O2_HTTP_CHK:
		if (!done && b_data(&check->bi) < strlen("HTTP/1.0 000\r"))
			goto wait_more_data;

		/* Check if the server speaks HTTP 1.X */
		if ((b_data(&check->bi) < strlen("HTTP/1.0 000\r")) ||
		    (memcmp(b_head(&check->bi), "HTTP/1.", 7) != 0 ||
		    (*(b_head(&check->bi) + 12) != ' ' && *(b_head(&check->bi) + 12) != '\r')) ||
		    !isdigit((unsigned char) *(b_head(&check->bi) + 9)) || !isdigit((unsigned char) *(b_head(&check->bi) + 10)) ||
		    !isdigit((unsigned char) *(b_head(&check->bi) + 11))) {
			cut_crlf(b_head(&check->bi));
			set_server_check_status(check, HCHK_STATUS_L7RSP, b_head(&check->bi));

			goto out_wakeup;
		}

		check->code = str2uic(b_head(&check->bi) + 9);
		desc = ltrim(b_head(&check->bi) + 12, ' ');

		if ((s->proxy->options & PR_O_DISABLE404) &&
			 (s->next_state != SRV_ST_STOPPED) && (check->code == 404)) {
			/* 404 may be accepted as "stopping" only if the server was up */
			cut_crlf(desc);
			set_server_check_status(check, HCHK_STATUS_L7OKCD, desc);
		}
		else if (s->proxy->options2 & PR_O2_EXP_TYPE) {
			/* Run content verification check... We know we have at least 13 chars */
			if (!httpchk_expect(s, done))
				goto wait_more_data;
		}
		/* check the reply : HTTP/1.X 2xx and 3xx are OK */
		else if (*(b_head(&check->bi) + 9) == '2' || *(b_head(&check->bi) + 9) == '3') {
			cut_crlf(desc);
			set_server_check_status(check,  HCHK_STATUS_L7OKD, desc);
		}
		else {
			cut_crlf(desc);
			set_server_check_status(check, HCHK_STATUS_L7STS, desc);
		}
		break;

	case PR_O2_SSL3_CHK:
		if (!done && b_data(&check->bi) < 5)
			goto wait_more_data;

		/* Check for SSLv3 alert or handshake */
		if ((b_data(&check->bi) >= 5) && (*b_head(&check->bi) == 0x15 || *b_head(&check->bi) == 0x16))
			set_server_check_status(check, HCHK_STATUS_L6OK, NULL);
		else
			set_server_check_status(check, HCHK_STATUS_L6RSP, NULL);
		break;

	case PR_O2_SMTP_CHK:
		if (!done && b_data(&check->bi) < strlen("000\r"))
			goto wait_more_data;

		/* do not reset when closing, servers don't like this */
		if (conn_ctrl_ready(cs->conn))
			fdtab[cs->conn->handle.fd].linger_risk = 0;

		/* Check if the server speaks SMTP */
		if ((b_data(&check->bi) < strlen("000\r")) ||
		    (*(b_head(&check->bi) + 3) != ' ' && *(b_head(&check->bi) + 3) != '\r') ||
		    !isdigit((unsigned char) *b_head(&check->bi)) || !isdigit((unsigned char) *(b_head(&check->bi) + 1)) ||
		    !isdigit((unsigned char) *(b_head(&check->bi) + 2))) {
			cut_crlf(b_head(&check->bi));
			set_server_check_status(check, HCHK_STATUS_L7RSP, b_head(&check->bi));
			goto out_wakeup;
		}

		check->code = str2uic(b_head(&check->bi));

		desc = ltrim(b_head(&check->bi) + 3, ' ');
		cut_crlf(desc);

		/* Check for SMTP code 2xx (should be 250) */
		if (*b_head(&check->bi) == '2')
			set_server_check_status(check, HCHK_STATUS_L7OKD, desc);
		else
			set_server_check_status(check, HCHK_STATUS_L7STS, desc);
		break;

	case PR_O2_LB_AGENT_CHK: {
		int status = HCHK_STATUS_CHECKED;
		const char *hs = NULL; /* health status      */
		const char *as = NULL; /* admin status */
		const char *ps = NULL; /* performance status */
		const char *cs = NULL; /* maxconn */
		const char *err = NULL; /* first error to report */
		const char *wrn = NULL; /* first warning to report */
		char *cmd, *p;

		/* We're getting an agent check response. The agent could
		 * have been disabled in the mean time with a long check
		 * still pending. It is important that we ignore the whole
		 * response.
		 */
		if (!(check->server->agent.state & CHK_ST_ENABLED))
			break;

		/* The agent supports strings made of a single line ended by the
		 * first CR ('\r') or LF ('\n'). This line is composed of words
		 * delimited by spaces (' '), tabs ('\t'), or commas (','). The
		 * line may optionally contained a description of a state change
		 * after a sharp ('#'), which is only considered if a health state
		 * is announced.
		 *
		 * Words may be composed of :
		 *   - a numeric weight suffixed by the percent character ('%').
		 *   - a health status among "up", "down", "stopped", and "fail".
		 *   - an admin status among "ready", "drain", "maint".
		 *
		 * These words may appear in any order. If multiple words of the
		 * same category appear, the last one wins.
		 */

		p = b_head(&check->bi);
		while (*p && *p != '\n' && *p != '\r')
			p++;

		if (!*p) {
			if (!done)
				goto wait_more_data;

			/* at least inform the admin that the agent is mis-behaving */
			set_server_check_status(check, check->status, "Ignoring incomplete line from agent");
			break;
		}

		*p = 0;
		cmd = b_head(&check->bi);

		while (*cmd) {
			/* look for next word */
			if (*cmd == ' ' || *cmd == '\t' || *cmd == ',') {
				cmd++;
				continue;
			}

			if (*cmd == '#') {
				/* this is the beginning of a health status description,
				 * skip the sharp and blanks.
				 */
				cmd++;
				while (*cmd == '\t' || *cmd == ' ')
					cmd++;
				break;
			}

			/* find the end of the word so that we have a null-terminated
			 * word between <cmd> and <p>.
			 */
			p = cmd + 1;
			while (*p && *p != '\t' && *p != ' ' && *p != '\n' && *p != ',')
				p++;
			if (*p)
				*p++ = 0;

			/* first, health statuses */
			if (strcasecmp(cmd, "up") == 0) {
				check->health = check->rise + check->fall - 1;
				status = HCHK_STATUS_L7OKD;
				hs = cmd;
			}
			else if (strcasecmp(cmd, "down") == 0) {
				check->health = 0;
				status = HCHK_STATUS_L7STS;
				hs = cmd;
			}
			else if (strcasecmp(cmd, "stopped") == 0) {
				check->health = 0;
				status = HCHK_STATUS_L7STS;
				hs = cmd;
			}
			else if (strcasecmp(cmd, "fail") == 0) {
				check->health = 0;
				status = HCHK_STATUS_L7STS;
				hs = cmd;
			}
			/* admin statuses */
			else if (strcasecmp(cmd, "ready") == 0) {
				as = cmd;
			}
			else if (strcasecmp(cmd, "drain") == 0) {
				as = cmd;
			}
			else if (strcasecmp(cmd, "maint") == 0) {
				as = cmd;
			}
			/* try to parse a weight here and keep the last one */
			else if (isdigit((unsigned char)*cmd) && strchr(cmd, '%') != NULL) {
				ps = cmd;
			}
			/* try to parse a maxconn here */
			else if (strncasecmp(cmd, "maxconn:", strlen("maxconn:")) == 0) {
				cs = cmd;
			}
			else {
				/* keep a copy of the first error */
				if (!err)
					err = cmd;
			}
			/* skip to next word */
			cmd = p;
		}
		/* here, cmd points either to \0 or to the beginning of a
		 * description. Skip possible leading spaces.
		 */
		while (*cmd == ' ' || *cmd == '\n')
			cmd++;

		/* First, update the admin status so that we avoid sending other
		 * possibly useless warnings and can also update the health if
		 * present after going back up.
		 */
		if (as) {
			if (strcasecmp(as, "drain") == 0)
				srv_adm_set_drain(check->server);
			else if (strcasecmp(as, "maint") == 0)
				srv_adm_set_maint(check->server);
			else
				srv_adm_set_ready(check->server);
		}

		/* now change weights */
		if (ps) {
			const char *msg;

			msg = server_parse_weight_change_request(s, ps);
			if (!wrn || !*wrn)
				wrn = msg;
		}

		if (cs) {
			const char *msg;

			cs += strlen("maxconn:");

			msg = server_parse_maxconn_change_request(s, cs);
			if (!wrn || !*wrn)
				wrn = msg;
		}

		/* and finally health status */
		if (hs) {
			/* We'll report some of the warnings and errors we have
			 * here. Down reports are critical, we leave them untouched.
			 * Lack of report, or report of 'UP' leaves the room for
			 * ERR first, then WARN.
			 */
			const char *msg = cmd;
			struct buffer *t;

			if (!*msg || status == HCHK_STATUS_L7OKD) {
				if (err && *err)
					msg = err;
				else if (wrn && *wrn)
					msg = wrn;
			}

			t = get_trash_chunk();
			chunk_printf(t, "via agent : %s%s%s%s",
				     hs, *msg ? " (" : "",
				     msg, *msg ? ")" : "");

			set_server_check_status(check, status, t->area);
		}
		else if (err && *err) {
			/* No status change but we'd like to report something odd.
			 * Just report the current state and copy the message.
			 */
			chunk_printf(&trash, "agent reports an error : %s", err);
			set_server_check_status(check, status/*check->status*/,
                                                trash.area);

		}
		else if (wrn && *wrn) {
			/* No status change but we'd like to report something odd.
			 * Just report the current state and copy the message.
			 */
			chunk_printf(&trash, "agent warns : %s", wrn);
			set_server_check_status(check, status/*check->status*/,
                                                trash.area);
		}
		else
			set_server_check_status(check, status, NULL);
		break;
	}

	case PR_O2_PGSQL_CHK:
		if (!done && b_data(&check->bi) < 9)
			goto wait_more_data;

		/* do not reset when closing, servers don't like this */
		if (conn_ctrl_ready(cs->conn))
			fdtab[cs->conn->handle.fd].linger_risk = 0;

		if (b_head(&check->bi)[0] == 'R') {
			set_server_check_status(check, HCHK_STATUS_L7OKD, "PostgreSQL server is ok");
		}
		else {
			if ((b_head(&check->bi)[0] == 'E') && (b_head(&check->bi)[5]!=0) && (b_head(&check->bi)[6]!=0))
				desc = &b_head(&check->bi)[6];
			else
				desc = "PostgreSQL unknown error";

			set_server_check_status(check, HCHK_STATUS_L7STS, desc);
		}
		break;

	case PR_O2_REDIS_CHK:
		if (!done && b_data(&check->bi) < 7)
			goto wait_more_data;

		if (strcmp(b_head(&check->bi), "+PONG\r\n") == 0) {
			set_server_check_status(check, HCHK_STATUS_L7OKD, "Redis server is ok");
		}
		else {
			set_server_check_status(check, HCHK_STATUS_L7STS, b_head(&check->bi));
		}
		break;

	case PR_O2_MYSQL_CHK:
		if (!done && b_data(&check->bi) < 5)
			goto wait_more_data;

		/* do not reset when closing, servers don't like this */
		if (conn_ctrl_ready(cs->conn))
			fdtab[cs->conn->handle.fd].linger_risk = 0;

		if (s->proxy->check_len == 0) { // old mode
			if (*(b_head(&check->bi) + 4) != '\xff') {
				/* We set the MySQL Version in description for information purpose
				 * FIXME : it can be cool to use MySQL Version for other purpose,
				 * like mark as down old MySQL server.
				 */
				if (b_data(&check->bi) > 51) {
					desc = ltrim(b_head(&check->bi) + 5, ' ');
					set_server_check_status(check, HCHK_STATUS_L7OKD, desc);
				}
				else {
					if (!done)
						goto wait_more_data;

					/* it seems we have a OK packet but without a valid length,
					 * it must be a protocol error
					 */
					set_server_check_status(check, HCHK_STATUS_L7RSP, b_head(&check->bi));
				}
			}
			else {
				/* An error message is attached in the Error packet */
				desc = ltrim(b_head(&check->bi) + 7, ' ');
				set_server_check_status(check, HCHK_STATUS_L7STS, desc);
			}
		} else {
			unsigned int first_packet_len = ((unsigned int) *b_head(&check->bi)) +
			                                (((unsigned int) *(b_head(&check->bi) + 1)) << 8) +
			                                (((unsigned int) *(b_head(&check->bi) + 2)) << 16);

			if (b_data(&check->bi) == first_packet_len + 4) {
				/* MySQL Error packet always begin with field_count = 0xff */
				if (*(b_head(&check->bi) + 4) != '\xff') {
					/* We have only one MySQL packet and it is a Handshake Initialization packet
					* but we need to have a second packet to know if it is alright
					*/
					if (!done && b_data(&check->bi) < first_packet_len + 5)
						goto wait_more_data;
				}
				else {
					/* We have only one packet and it is an Error packet,
					* an error message is attached, so we can display it
					*/
					desc = &b_head(&check->bi)[7];
					//ha_warning("onlyoneERR: %s\n", desc);
					set_server_check_status(check, HCHK_STATUS_L7STS, desc);
				}
			} else if (b_data(&check->bi) > first_packet_len + 4) {
				unsigned int second_packet_len = ((unsigned int) *(b_head(&check->bi) + first_packet_len + 4)) +
				                                 (((unsigned int) *(b_head(&check->bi) + first_packet_len + 5)) << 8) +
				                                 (((unsigned int) *(b_head(&check->bi) + first_packet_len + 6)) << 16);

				if (b_data(&check->bi) == first_packet_len + 4 + second_packet_len + 4 ) {
					/* We have 2 packets and that's good */
					/* Check if the second packet is a MySQL Error packet or not */
					if (*(b_head(&check->bi) + first_packet_len + 8) != '\xff') {
						/* No error packet */
						/* We set the MySQL Version in description for information purpose */
						desc = &b_head(&check->bi)[5];
						//ha_warning("2packetOK: %s\n", desc);
						set_server_check_status(check, HCHK_STATUS_L7OKD, desc);
					}
					else {
						/* An error message is attached in the Error packet
						* so we can display it ! :)
						*/
						desc = &b_head(&check->bi)[first_packet_len+11];
						//ha_warning("2packetERR: %s\n", desc);
						set_server_check_status(check, HCHK_STATUS_L7STS, desc);
					}
				}
			}
			else {
				if (!done)
					goto wait_more_data;

				/* it seems we have a Handshake Initialization packet but without a valid length,
				 * it must be a protocol error
				 */
				desc = &b_head(&check->bi)[5];
				//ha_warning("protoerr: %s\n", desc);
				set_server_check_status(check, HCHK_STATUS_L7RSP, desc);
			}
		}
		break;

	case PR_O2_LDAP_CHK:
		if (!done && b_data(&check->bi) < 14)
			goto wait_more_data;

		/* Check if the server speaks LDAP (ASN.1/BER)
		 * http://en.wikipedia.org/wiki/Basic_Encoding_Rules
		 * http://tools.ietf.org/html/rfc4511
		 */

		/* http://tools.ietf.org/html/rfc4511#section-4.1.1
		 *   LDAPMessage: 0x30: SEQUENCE
		 */
		if ((b_data(&check->bi) < 14) || (*(b_head(&check->bi)) != '\x30')) {
			set_server_check_status(check, HCHK_STATUS_L7RSP, "Not LDAPv3 protocol");
		}
		else {
			 /* size of LDAPMessage */
			msglen = (*(b_head(&check->bi) + 1) & 0x80) ? (*(b_head(&check->bi) + 1) & 0x7f) : 0;

			/* http://tools.ietf.org/html/rfc4511#section-4.2.2
			 *   messageID: 0x02 0x01 0x01: INTEGER 1
			 *   protocolOp: 0x61: bindResponse
			 */
			if ((msglen > 2) ||
			    (memcmp(b_head(&check->bi) + 2 + msglen, "\x02\x01\x01\x61", 4) != 0)) {
				set_server_check_status(check, HCHK_STATUS_L7RSP, "Not LDAPv3 protocol");
				goto out_wakeup;
			}

			/* size of bindResponse */
			msglen += (*(b_head(&check->bi) + msglen + 6) & 0x80) ? (*(b_head(&check->bi) + msglen + 6) & 0x7f) : 0;

			/* http://tools.ietf.org/html/rfc4511#section-4.1.9
			 *   ldapResult: 0x0a 0x01: ENUMERATION
			 */
			if ((msglen > 4) ||
			    (memcmp(b_head(&check->bi) + 7 + msglen, "\x0a\x01", 2) != 0)) {
				set_server_check_status(check, HCHK_STATUS_L7RSP, "Not LDAPv3 protocol");
				goto out_wakeup;
			}

			/* http://tools.ietf.org/html/rfc4511#section-4.1.9
			 *   resultCode
			 */
			check->code = *(b_head(&check->bi) + msglen + 9);
			if (check->code) {
				set_server_check_status(check, HCHK_STATUS_L7STS, "See RFC: http://tools.ietf.org/html/rfc4511#section-4.1.9");
			} else {
				set_server_check_status(check, HCHK_STATUS_L7OKD, "Success");
			}
		}
		break;

	case PR_O2_SPOP_CHK: {
		unsigned int framesz;
		char	     err[HCHK_DESC_LEN];

		if (!done && b_data(&check->bi) < 4)
			goto wait_more_data;

		memcpy(&framesz, b_head(&check->bi), 4);
		framesz = ntohl(framesz);

		if (!done && b_data(&check->bi) < (4+framesz))
		    goto wait_more_data;

		if (!spoe_handle_healthcheck_response(b_head(&check->bi)+4, framesz, err, HCHK_DESC_LEN-1))
			set_server_check_status(check, HCHK_STATUS_L7OKD, "SPOA server is ok");
		else
			set_server_check_status(check, HCHK_STATUS_L7STS, err);
		break;
	}

	default:
		/* good connection is enough for pure TCP check */
		if ((conn->flags & CO_FL_CONNECTED) && !check->type) {
			if (check->use_ssl)
				set_server_check_status(check, HCHK_STATUS_L6OK, NULL);
			else
				set_server_check_status(check, HCHK_STATUS_L4OK, NULL);
		}
		break;
	} /* switch */

 out_wakeup:
	/* collect possible new errors */
	if (conn->flags & CO_FL_ERROR || cs->flags & CS_FL_ERROR)
		chk_report_conn_err(check, 0, 0);

	/* Reset the check buffer... */
	*b_head(&check->bi) = '\0';
	b_reset(&check->bi);

	/* Close the connection... We still attempt to nicely close if,
	 * for instance, SSL needs to send a "close notify." Later, we perform
	 * a hard close and reset the connection if some data are pending,
	 * otherwise we end up with many TIME_WAITs and eat all the source port
	 * range quickly.  To avoid sending RSTs all the time, we first try to
	 * drain pending data.
	 */
	/* Call cs_shutr() first, to add the CO_FL_SOCK_RD_SH flag on the
	 * connection, to make sure cs_shutw() will not lead to a shutdown()
	 * that would provoke TIME_WAITs.
	 */
	cs_shutr(cs, CS_SHR_DRAIN);
	cs_shutw(cs, CS_SHW_NORMAL);

	/* OK, let's not stay here forever */
	if (check->result == CHK_RES_FAILED)
		conn->flags |= CO_FL_ERROR;

	task_wakeup(t, TASK_WOKEN_IO);
out:
	return;

 wait_more_data:
	cs->conn->mux->subscribe(cs, SUB_RETRY_RECV, &check->wait_list);
        goto out;
}

/*
 * This function is used only for server health-checks. It handles connection
 * status updates including errors. If necessary, it wakes the check task up.
 * It returns 0 on normal cases, <0 if at least one close() has happened on the
 * connection (eg: reconnect).
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
	if (check->type == PR_O2_TCPCHK_CHK) {
		ret = tcpcheck_main(check);
		cs = check->cs;
		conn = cs->conn;
	} else {
		if (!(check->wait_list.events & SUB_RETRY_SEND))
			__event_srv_chk_w(cs);
		if (!(check->wait_list.events & SUB_RETRY_RECV))
			__event_srv_chk_r(cs);
	}

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
	else if (!(conn->flags & CO_FL_HANDSHAKE) && !check->type) {
		/* we may get here if only a connection probe was required : we
		 * don't have any data to send nor anything expected in response,
		 * so the completion of the connection establishment is enough.
		 */
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

struct data_cb check_conn_cb = {
	.wake = wake_srv_chk,
	.name = "CHCK",
};

/*
 * updates the server's weight during a warmup stage. Once the final weight is
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

/* returns the first NON-COMMENT tcp-check rule from list <list> or NULL if
 * none was found.
 */
static struct tcpcheck_rule *get_first_tcpcheck_rule(struct list *list)
{
	struct tcpcheck_rule *r;

	list_for_each_entry(r, list, list) {
		if (r->action != TCPCHK_ACT_COMMENT)
			return r;
	}
	return NULL;
}

/*
 * establish a server health-check that makes use of a connection.
 *
 * It can return one of :
 *  - SF_ERR_NONE if everything's OK and tcpcheck_main() was not called
 *  - SF_ERR_UP if if everything's OK and tcpcheck_main() was called
 *  - SF_ERR_SRVTO if there are no more servers
 *  - SF_ERR_SRVCL if the connection was refused by the server
 *  - SF_ERR_PRXCOND if the connection has been limited by the proxy (maxconn)
 *  - SF_ERR_RESOURCE if a system resource is lacking (eg: fd limits, ports, ...)
 *  - SF_ERR_INTERNAL for any other purely internal errors
 *  - SF_ERR_CHK_PORT if no port could be found to run a health check on an AF_INET* socket
 * Additionally, in the case of SF_ERR_RESOURCE, an emergency log will be emitted.
 * Note that we try to prevent the network stack from sending the ACK during the
 * connect() when a pure TCP check is used (without PROXY protocol).
 */
static int connect_conn_chk(struct task *t)
{
	struct check *check = t->context;
	struct server *s = check->server;
	struct conn_stream *cs = check->cs;
	struct connection *conn = cs_conn(cs);
	struct protocol *proto;
	struct tcpcheck_rule *tcp_rule = NULL;
	int ret;
	int connflags = 0;

	/* we cannot have a connection here */
	if (conn)
		return SF_ERR_INTERNAL;

	/* tcpcheck send/expect initialisation */
	if (check->type == PR_O2_TCPCHK_CHK) {
		check->current_step = NULL;
		tcp_rule = get_first_tcpcheck_rule(check->tcpcheck_rules);
	}

	/* prepare the check buffer.
	 * This should not be used if check is the secondary agent check
	 * of a server as s->proxy->check_req will relate to the
	 * configuration of the primary check. Similarly, tcp-check uses
	 * its own strings.
	 */
	if (check->type && check->type != PR_O2_TCPCHK_CHK && !(check->state & CHK_ST_AGENT)) {
		b_putblk(&check->bo, s->proxy->check_req, s->proxy->check_len);

		/* we want to check if this host replies to HTTP or SSLv3 requests
		 * so we'll send the request, and won't wake the checker up now.
		 */
		if ((check->type) == PR_O2_SSL3_CHK) {
			/* SSL requires that we put Unix time in the request */
			int gmt_time = htonl(date.tv_sec);
			memcpy(b_head(&check->bo) + 11, &gmt_time, 4);
		}
		else if ((check->type) == PR_O2_HTTP_CHK) {
			if (s->proxy->options2 & PR_O2_CHK_SNDST)
				b_putblk(&check->bo, trash.area,
					 httpchk_build_status_header(s, trash.area, trash.size));
			/* prevent HTTP keep-alive when "http-check expect" is used */
			if (s->proxy->options2 & PR_O2_EXP_TYPE)
				b_putist(&check->bo, ist("Connection: close\r\n"));
			b_putist(&check->bo, ist("\r\n"));
			*b_tail(&check->bo) = '\0'; /* to make gdb output easier to read */
		}
	}

	if ((check->type & PR_O2_LB_AGENT_CHK) && check->send_string_len) {
		b_putblk(&check->bo, check->send_string, check->send_string_len);
	}

	/* for tcp-checks, the initial connection setup is handled separately as
	 * it may be sent to a specific port and not to the server's.
	 */
	if (tcp_rule && tcp_rule->action == TCPCHK_ACT_CONNECT) {
		tcpcheck_main(check);
		return SF_ERR_UP;
	}

	/* prepare a new connection */
	cs = check->cs = cs_new(NULL);
	if (!check->cs)
		return SF_ERR_RESOURCE;
	conn = cs->conn;
	/* Maybe there were an older connection we were waiting on */
	check->wait_list.events = 0;
	tasklet_set_tid(check->wait_list.tasklet, tid);


	if (!sockaddr_alloc(&conn->dst))
		return SF_ERR_RESOURCE;

	if (is_addr(&check->addr)) {
		/* we'll connect to the check addr specified on the server */
		*conn->dst = check->addr;
	}
	else {
		/* we'll connect to the addr on the server */
		*conn->dst = s->addr;
	}

	if (s->check.via_socks4 &&  (s->flags & SRV_F_SOCKS4_PROXY)) {
		conn->send_proxy_ofs = 1;
		conn->flags |= CO_FL_SOCKS4;
	}

	proto = protocol_by_family(conn->dst->ss_family);
	conn->target = &s->obj_type;

	if ((conn->dst->ss_family == AF_INET) || (conn->dst->ss_family == AF_INET6)) {
		int i = 0;

		i = srv_check_healthcheck_port(check);
		if (i == 0)
			return SF_ERR_CHK_PORT;

		set_host_port(conn->dst, i);
	}

	/* no client address */

	conn_prepare(conn, proto, check->xprt);
	if (conn_install_mux(conn, &mux_pt_ops, cs, s->proxy, NULL) < 0)
		return SF_ERR_RESOURCE;
	cs_attach(cs, check, &check_conn_cb);

	/* only plain tcp-check supports quick ACK */
	if (check->type != 0)
		connflags |= CONNECT_HAS_DATA;
	if ((check->type == 0 || check->type == PR_O2_TCPCHK_CHK) &&
	    (!tcp_rule || tcp_rule->action != TCPCHK_ACT_EXPECT))
		connflags |= CONNECT_DELACK_ALWAYS;

	ret = SF_ERR_INTERNAL;
	if (proto && proto->connect)
		ret = proto->connect(conn, connflags);


#ifdef USE_OPENSSL
	if (ret == SF_ERR_NONE) {
		if (s->check.sni)
			ssl_sock_set_servername(conn, s->check.sni);
		if (s->check.alpn_str)
			ssl_sock_set_alpn(conn, (unsigned char *)s->check.alpn_str,
			    s->check.alpn_len);
	}
#endif
	if (s->check.send_proxy && !(check->state & CHK_ST_AGENT)) {
		conn->send_proxy_ofs = 1;
		conn->flags |= CO_FL_SEND_PROXY;
		if (xprt_add_hs(conn) < 0)
			ret = SF_ERR_RESOURCE;
	}

	return ret;
}

static struct list pid_list = LIST_HEAD_INIT(pid_list);
static struct pool_head *pool_head_pid_list;
__decl_spinlock(pid_list_lock);

void block_sigchld(void)
{
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	assert(ha_sigmask(SIG_BLOCK, &set, NULL) == 0);
}

void unblock_sigchld(void)
{
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	assert(ha_sigmask(SIG_UNBLOCK, &set, NULL) == 0);
}

static struct pid_list *pid_list_add(pid_t pid, struct task *t)
{
	struct pid_list *elem;
	struct check *check = t->context;

	elem = pool_alloc(pool_head_pid_list);
	if (!elem)
		return NULL;
	elem->pid = pid;
	elem->t = t;
	elem->exited = 0;
	check->curpid = elem;
	LIST_INIT(&elem->list);

	HA_SPIN_LOCK(PID_LIST_LOCK, &pid_list_lock);
	LIST_ADD(&pid_list, &elem->list);
	HA_SPIN_UNLOCK(PID_LIST_LOCK, &pid_list_lock);

	return elem;
}

static void pid_list_del(struct pid_list *elem)
{
	struct check *check;

	if (!elem)
		return;

	HA_SPIN_LOCK(PID_LIST_LOCK, &pid_list_lock);
	LIST_DEL(&elem->list);
	HA_SPIN_UNLOCK(PID_LIST_LOCK, &pid_list_lock);

	if (!elem->exited)
		kill(elem->pid, SIGTERM);

	check = elem->t->context;
	check->curpid = NULL;
	pool_free(pool_head_pid_list, elem);
}

/* Called from inside SIGCHLD handler, SIGCHLD is blocked */
static void pid_list_expire(pid_t pid, int status)
{
	struct pid_list *elem;

	HA_SPIN_LOCK(PID_LIST_LOCK, &pid_list_lock);
	list_for_each_entry(elem, &pid_list, list) {
		if (elem->pid == pid) {
			elem->t->expire = now_ms;
			elem->status = status;
			elem->exited = 1;
			task_wakeup(elem->t, TASK_WOKEN_IO);
			break;
		}
	}
	HA_SPIN_UNLOCK(PID_LIST_LOCK, &pid_list_lock);
}

static void sigchld_handler(struct sig_handler *sh)
{
	pid_t pid;
	int status;

	while ((pid = waitpid(0, &status, WNOHANG)) > 0)
		pid_list_expire(pid, status);
}

static int init_pid_list(void)
{
	if (pool_head_pid_list != NULL)
		/* Nothing to do */
		return 0;

	if (!signal_register_fct(SIGCHLD, sigchld_handler, SIGCHLD)) {
		ha_alert("Failed to set signal handler for external health checks: %s. Aborting.\n",
			 strerror(errno));
		return 1;
	}

	pool_head_pid_list = create_pool("pid_list", sizeof(struct pid_list), MEM_F_SHARED);
	if (pool_head_pid_list == NULL) {
		ha_alert("Failed to allocate memory pool for external health checks: %s. Aborting.\n",
			 strerror(errno));
		return 1;
	}

	return 0;
}

/* helper macro to set an environment variable and jump to a specific label on failure. */
#define EXTCHK_SETENV(check, envidx, value, fail) { if (extchk_setenv(check, envidx, value)) goto fail; }

/*
 * helper function to allocate enough memory to store an environment variable.
 * It will also check that the environment variable is updatable, and silently
 * fail if not.
 */
static int extchk_setenv(struct check *check, int idx, const char *value)
{
	int len, ret;
	char *envname;
	int vmaxlen;

	if (idx < 0 || idx >= EXTCHK_SIZE) {
		ha_alert("Illegal environment variable index %d. Aborting.\n", idx);
		return 1;
	}

	envname = extcheck_envs[idx].name;
	vmaxlen = extcheck_envs[idx].vmaxlen;

	/* Check if the environment variable is already set, and silently reject
	 * the update if this one is not updatable. */
	if ((vmaxlen == EXTCHK_SIZE_EVAL_INIT) && (check->envp[idx]))
		return 0;

	/* Instead of sending NOT_USED, sending an empty value is preferable */
	if (strcmp(value, "NOT_USED") == 0) {
		value = "";
	}

	len = strlen(envname) + 1;
	if (vmaxlen == EXTCHK_SIZE_EVAL_INIT)
		len += strlen(value);
	else
		len += vmaxlen;

	if (!check->envp[idx])
		check->envp[idx] = malloc(len + 1);

	if (!check->envp[idx]) {
		ha_alert("Failed to allocate memory for the environment variable '%s'. Aborting.\n", envname);
		return 1;
	}
	ret = snprintf(check->envp[idx], len + 1, "%s=%s", envname, value);
	if (ret < 0) {
		ha_alert("Failed to store the environment variable '%s'. Reason : %s. Aborting.\n", envname, strerror(errno));
		return 1;
	}
	else if (ret > len) {
		ha_alert("Environment variable '%s' was truncated. Aborting.\n", envname);
		return 1;
	}
	return 0;
}

static int prepare_external_check(struct check *check)
{
	struct server *s = check->server;
	struct proxy *px = s->proxy;
	struct listener *listener = NULL, *l;
	int i;
	const char *path = px->check_path ? px->check_path : DEF_CHECK_PATH;
	char buf[256];

	list_for_each_entry(l, &px->conf.listeners, by_fe)
		/* Use the first INET, INET6 or UNIX listener */
		if (l->addr.ss_family == AF_INET ||
		    l->addr.ss_family == AF_INET6 ||
		    l->addr.ss_family == AF_UNIX) {
			listener = l;
			break;
		}

	check->curpid = NULL;
	check->envp = calloc((EXTCHK_SIZE + 1), sizeof(char *));
	if (!check->envp) {
		ha_alert("Failed to allocate memory for environment variables. Aborting\n");
		goto err;
	}

	check->argv = calloc(6, sizeof(char *));
	if (!check->argv) {
		ha_alert("Starting [%s:%s] check: out of memory.\n", px->id, s->id);
		goto err;
	}

	check->argv[0] = px->check_command;

	if (!listener) {
		check->argv[1] = strdup("NOT_USED");
		check->argv[2] = strdup("NOT_USED");
	}
	else if (listener->addr.ss_family == AF_INET ||
	    listener->addr.ss_family == AF_INET6) {
		addr_to_str(&listener->addr, buf, sizeof(buf));
		check->argv[1] = strdup(buf);
		port_to_str(&listener->addr, buf, sizeof(buf));
		check->argv[2] = strdup(buf);
	}
	else if (listener->addr.ss_family == AF_UNIX) {
		const struct sockaddr_un *un;

		un = (struct sockaddr_un *)&listener->addr;
		check->argv[1] = strdup(un->sun_path);
		check->argv[2] = strdup("NOT_USED");
	}
	else {
		ha_alert("Starting [%s:%s] check: unsupported address family.\n", px->id, s->id);
		goto err;
	}

	addr_to_str(&s->addr, buf, sizeof(buf));
	check->argv[3] = strdup(buf);

	if (s->addr.ss_family == AF_INET || s->addr.ss_family == AF_INET6)
		snprintf(buf, sizeof(buf), "%u", s->svc_port);
	else
		*buf = 0;
	check->argv[4] = strdup(buf);

	for (i = 0; i < 5; i++) {
		if (!check->argv[i]) {
			ha_alert("Starting [%s:%s] check: out of memory.\n", px->id, s->id);
			goto err;
		}
	}

	EXTCHK_SETENV(check, EXTCHK_PATH, path, err);
	/* Add proxy environment variables */
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_PROXY_NAME, px->id, err);
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_PROXY_ID, ultoa_r(px->uuid, buf, sizeof(buf)), err);
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_PROXY_ADDR, check->argv[1], err);
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_PROXY_PORT, check->argv[2], err);
	/* Add server environment variables */
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_SERVER_NAME, s->id, err);
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_SERVER_ID, ultoa_r(s->puid, buf, sizeof(buf)), err);
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_SERVER_ADDR, check->argv[3], err);
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_SERVER_PORT, check->argv[4], err);
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_SERVER_MAXCONN, ultoa_r(s->maxconn, buf, sizeof(buf)), err);
	EXTCHK_SETENV(check, EXTCHK_HAPROXY_SERVER_CURCONN, ultoa_r(s->cur_sess, buf, sizeof(buf)), err);

	/* Ensure that we don't leave any hole in check->envp */
	for (i = 0; i < EXTCHK_SIZE; i++)
		if (!check->envp[i])
			EXTCHK_SETENV(check, i, "", err);

	return 1;
err:
	if (check->envp) {
		for (i = 0; i < EXTCHK_SIZE; i++)
			free(check->envp[i]);
		free(check->envp);
		check->envp = NULL;
	}

	if (check->argv) {
		for (i = 1; i < 5; i++)
			free(check->argv[i]);
		free(check->argv);
		check->argv = NULL;
	}
	return 0;
}

/*
 * establish a server health-check that makes use of a process.
 *
 * It can return one of :
 *  - SF_ERR_NONE if everything's OK
 *  - SF_ERR_RESOURCE if a system resource is lacking (eg: fd limits, ports, ...)
 * Additionally, in the case of SF_ERR_RESOURCE, an emergency log will be emitted.
 *
 * Blocks and then unblocks SIGCHLD
 */
static int connect_proc_chk(struct task *t)
{
	char buf[256];
	struct check *check = t->context;
	struct server *s = check->server;
	struct proxy *px = s->proxy;
	int status;
	pid_t pid;

	status = SF_ERR_RESOURCE;

	block_sigchld();

	pid = fork();
	if (pid < 0) {
		ha_alert("Failed to fork process for external health check: %s. Aborting.\n",
			 strerror(errno));
		set_server_check_status(check, HCHK_STATUS_SOCKERR, strerror(errno));
		goto out;
	}
	if (pid == 0) {
		/* Child */
		extern char **environ;
		struct rlimit limit;
		int fd;

		/* close all FDs. Keep stdin/stdout/stderr in verbose mode */
		fd = (global.mode & (MODE_QUIET|MODE_VERBOSE)) == MODE_QUIET ? 0 : 3;

		my_closefrom(fd);

		/* restore the initial FD limits */
		limit.rlim_cur = rlim_fd_cur_at_boot;
		limit.rlim_max = rlim_fd_max_at_boot;
		if (setrlimit(RLIMIT_NOFILE, &limit) == -1) {
			getrlimit(RLIMIT_NOFILE, &limit);
			ha_warning("External check: failed to restore initial FD limits (cur=%u max=%u), using cur=%u max=%u\n",
				   rlim_fd_cur_at_boot, rlim_fd_max_at_boot,
				   (unsigned int)limit.rlim_cur, (unsigned int)limit.rlim_max);
		}

		environ = check->envp;
		extchk_setenv(check, EXTCHK_HAPROXY_SERVER_CURCONN, ultoa_r(s->cur_sess, buf, sizeof(buf)));
		haproxy_unblock_signals();
		execvp(px->check_command, check->argv);
		ha_alert("Failed to exec process for external health check: %s. Aborting.\n",
			 strerror(errno));
		exit(-1);
	}

	/* Parent */
	if (check->result == CHK_RES_UNKNOWN) {
		if (pid_list_add(pid, t) != NULL) {
			t->expire = tick_add(now_ms, MS_TO_TICKS(check->inter));

			if (px->timeout.check && px->timeout.connect) {
				int t_con = tick_add(now_ms, px->timeout.connect);
				t->expire = tick_first(t->expire, t_con);
			}
			status = SF_ERR_NONE;
			goto out;
		}
		else {
			set_server_check_status(check, HCHK_STATUS_SOCKERR, strerror(errno));
		}
		kill(pid, SIGTERM); /* process creation error */
	}
	else
		set_server_check_status(check, HCHK_STATUS_SOCKERR, strerror(errno));

out:
	unblock_sigchld();
	return status;
}

/*
 * manages a server health-check that uses an external process. Returns
 * the time the task accepts to wait, or TIME_ETERNITY for infinity.
 *
 * Please do NOT place any return statement in this function and only leave
 * via the out_unlock label.
 */
static struct task *process_chk_proc(struct task *t, void *context, unsigned short state)
{
	struct check *check = context;
	struct server *s = check->server;
	int rv;
	int ret;
	int expired = tick_is_expired(t->expire, now_ms);

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
		    s->proxy->state == PR_STSTOPPED)
			goto reschedule;

		/* we'll initiate a new check */
		set_server_check_status(check, HCHK_STATUS_START, NULL);

		check->state |= CHK_ST_INPROGRESS;

		ret = connect_proc_chk(t);
		if (ret == SF_ERR_NONE) {
			/* the process was forked, we allow up to min(inter,
			 * timeout.connect) for it to report its status, but
			 * only when timeout.check is set as it may be to short
			 * for a full check otherwise.
			 */
			t->expire = tick_add(now_ms, MS_TO_TICKS(check->inter));

			if (s->proxy->timeout.check && s->proxy->timeout.connect) {
				int t_con = tick_add(now_ms, s->proxy->timeout.connect);
				t->expire = tick_first(t->expire, t_con);
			}
			task_set_affinity(t, tid_bit);
			goto reschedule;
		}

		/* here, we failed to start the check */

		check->state &= ~CHK_ST_INPROGRESS;
		check_notify_failure(check);

		/* we allow up to min(inter, timeout.connect) for a connection
		 * to establish but only when timeout.check is set
		 * as it may be to short for a full check otherwise
		 */
		while (tick_is_expired(t->expire, now_ms)) {
			int t_con;

			t_con = tick_add(t->expire, s->proxy->timeout.connect);
			t->expire = tick_add(t->expire, MS_TO_TICKS(check->inter));

			if (s->proxy->timeout.check)
				t->expire = tick_first(t->expire, t_con);
		}
	}
	else {
		/* there was a test running.
		 * First, let's check whether there was an uncaught error,
		 * which can happen on connect timeout or error.
		 */
		if (check->result == CHK_RES_UNKNOWN) {
			/* good connection is enough for pure TCP check */
			struct pid_list *elem = check->curpid;
			int status = HCHK_STATUS_UNKNOWN;

			if (elem->exited) {
				status = elem->status; /* Save in case the process exits between use below */
				if (!WIFEXITED(status))
					check->code = -1;
				else
					check->code = WEXITSTATUS(status);
				if (!WIFEXITED(status) || WEXITSTATUS(status))
					status = HCHK_STATUS_PROCERR;
				else
					status = HCHK_STATUS_PROCOK;
			} else if (expired) {
				status = HCHK_STATUS_PROCTOUT;
				ha_warning("kill %d\n", (int)elem->pid);
				kill(elem->pid, SIGTERM);
			}
			set_server_check_status(check, status, NULL);
		}

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
		task_set_affinity(t, 1);
		check->state &= ~CHK_ST_INPROGRESS;

		pid_list_del(check->curpid);

		rv = 0;
		if (global.spread_checks > 0) {
			rv = srv_getinter(check) * global.spread_checks / 100;
			rv -= (int) (2 * rv * (rand() / (RAND_MAX + 1.0)));
		}
		t->expire = tick_add(now_ms, MS_TO_TICKS(srv_getinter(check) + rv));
	}

 reschedule:
	while (tick_is_expired(t->expire, now_ms))
		t->expire = tick_add(t->expire, MS_TO_TICKS(check->inter));

 out_unlock:
	HA_SPIN_UNLOCK(SERVER_LOCK, &check->server->lock);
	return t;
}

/*
 * manages a server health-check that uses a connection. Returns
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
	int ret;
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

		ret = connect_conn_chk(t);
		cs = check->cs;
		conn = cs_conn(cs);

		switch (ret) {
		case SF_ERR_UP:
			goto out_unlock;

		case SF_ERR_NONE:
			/* we allow up to min(inter, timeout.connect) for a connection
			 * to establish but only when timeout.check is set
			 * as it may be to short for a full check otherwise
			 */
			t->expire = tick_add(now_ms, MS_TO_TICKS(check->inter));

			if (proxy->timeout.check && proxy->timeout.connect) {
				int t_con = tick_add(now_ms, proxy->timeout.connect);
				t->expire = tick_first(t->expire, t_con);
			}

			if (check->type) {
				/* send the request if we have one. We avoid receiving
				 * if not connected, unless we didn't subscribe for
				 * sending since otherwise we won't be woken up.
				 */
				__event_srv_chk_w(cs);
				if (!(conn->flags & CO_FL_WAIT_L4_CONN) ||
				    !(check->wait_list.events & SUB_RETRY_SEND))
					__event_srv_chk_r(cs);
			}

			task_set_affinity(t, tid_bit);
			goto reschedule;

		case SF_ERR_SRVTO: /* ETIMEDOUT */
		case SF_ERR_SRVCL: /* ECONNREFUSED, ENETUNREACH, ... */
			if (conn)
				conn->flags |= CO_FL_ERROR;
			chk_report_conn_err(check, errno, 0);
			break;
		/* should share same code than cases below */
		case SF_ERR_CHK_PORT:
			check->state |= CHK_ST_PORT_MISS;
		case SF_ERR_PRXCOND:
		case SF_ERR_RESOURCE:
		case SF_ERR_INTERNAL:
			if (conn)
				conn->flags |= CO_FL_ERROR;
			chk_report_conn_err(check, conn ? 0 : ENOMEM, 0);
			break;
		}

		/* here, we have seen a synchronous error, no fd was allocated */
		if (cs) {
			if (check->wait_list.events)
				cs->conn->xprt->unsubscribe(cs->conn,
				                            cs->conn->xprt_ctx,
							    check->wait_list.events,
							    &check->wait_list);
			/* We may have been scheduled to run, and the
			 * I/O handler expects to have a cs, so remove
			 * the tasklet
			 */
			tasklet_remove_from_tasklet_list(check->wait_list.tasklet);
			cs_destroy(cs);
			cs = check->cs = NULL;
			conn = NULL;
		}

		check->state &= ~CHK_ST_INPROGRESS;
		check_notify_failure(check);

		/* we allow up to min(inter, timeout.connect) for a connection
		 * to establish but only when timeout.check is set
		 * as it may be to short for a full check otherwise
		 */
		while (tick_is_expired(t->expire, now_ms)) {
			int t_con;

			t_con = tick_add(t->expire, proxy->timeout.connect);
			t->expire = tick_add(t->expire, MS_TO_TICKS(check->inter));

			if (proxy->timeout.check)
				t->expire = tick_first(t->expire, t_con);
		}
	}
	else {
		/* there was a test running.
		 * First, let's check whether there was an uncaught error,
		 * which can happen on connect timeout or error.
		 */
		if (check->result == CHK_RES_UNKNOWN) {
			/* good connection is enough for pure TCP check */
			if ((conn->flags & CO_FL_CONNECTED) && !check->type) {
				if (check->use_ssl)
					set_server_check_status(check, HCHK_STATUS_L6OK, NULL);
				else
					set_server_check_status(check, HCHK_STATUS_L4OK, NULL);
			}
			else if ((conn->flags & CO_FL_ERROR) || cs->flags & CS_FL_ERROR || expired) {
				chk_report_conn_err(check, 0, expired);
			}
			else
				goto out_unlock; /* timeout not reached, wait again */
		}

		/* check complete or aborted */
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
				cs->conn->xprt->unsubscribe(cs->conn,
				    cs->conn->xprt_ctx,
				    check->wait_list.events,
				    &check->wait_list);
			/* We may have been scheduled to run, and the
			 * I/O handler expects to have a cs, so remove
			 * the tasklet
			 */
			tasklet_remove_from_tasklet_list(check->wait_list.tasklet);
			cs_destroy(cs);
			cs = check->cs = NULL;
			conn = NULL;
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
				rv -= (int) (2 * rv * (rand() / (RAND_MAX + 1.0)));
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

/*
 * manages a server health-check. Returns
 * the time the task accepts to wait, or TIME_ETERNITY for infinity.
 */
static struct task *process_chk(struct task *t, void *context, unsigned short state)
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
 * Perform content verification check on data in s->check.buffer buffer.
 * The buffer MUST be terminated by a null byte before calling this function.
 * Sets server status appropriately. The caller is responsible for ensuring
 * that the buffer contains at least 13 characters. If <done> is zero, we may
 * return 0 to indicate that data is required to decide of a match.
 */
static int httpchk_expect(struct server *s, int done)
{
	static THREAD_LOCAL char status_msg[] = "HTTP status check returned code <000>";
	char status_code[] = "000";
	char *contentptr;
	int crlf;
	int ret;

	switch (s->proxy->options2 & PR_O2_EXP_TYPE) {
	case PR_O2_EXP_STS:
	case PR_O2_EXP_RSTS:
		memcpy(status_code, b_head(&s->check.bi) + 9, 3);
		memcpy(status_msg + strlen(status_msg) - 4, b_head(&s->check.bi) + 9, 3);

		if ((s->proxy->options2 & PR_O2_EXP_TYPE) == PR_O2_EXP_STS)
			ret = strncmp(s->proxy->expect_str, status_code, 3) == 0;
		else
			ret = regex_exec(s->proxy->expect_regex, status_code);

		/* we necessarily have the response, so there are no partial failures */
		if (s->proxy->options2 & PR_O2_EXP_INV)
			ret = !ret;

		set_server_check_status(&s->check, ret ? HCHK_STATUS_L7OKD : HCHK_STATUS_L7STS, status_msg);
		break;

	case PR_O2_EXP_STR:
	case PR_O2_EXP_RSTR:
		/* very simple response parser: ignore CR and only count consecutive LFs,
		 * stop with contentptr pointing to first char after the double CRLF or
		 * to '\0' if crlf < 2.
		 */
		crlf = 0;
		for (contentptr = b_head(&s->check.bi); *contentptr; contentptr++) {
			if (crlf >= 2)
				break;
			if (*contentptr == '\r')
				continue;
			else if (*contentptr == '\n')
				crlf++;
			else
				crlf = 0;
		}

		/* Check that response contains a body... */
		if (crlf < 2) {
			if (!done)
				return 0;

			set_server_check_status(&s->check, HCHK_STATUS_L7RSP,
						"HTTP content check could not find a response body");
			return 1;
		}

		/* Check that response body is not empty... */
		if (*contentptr == '\0') {
			if (!done)
				return 0;

			set_server_check_status(&s->check, HCHK_STATUS_L7RSP,
						"HTTP content check found empty response body");
			return 1;
		}

		/* Check the response content against the supplied string
		 * or regex... */
		if ((s->proxy->options2 & PR_O2_EXP_TYPE) == PR_O2_EXP_STR)
			ret = strstr(contentptr, s->proxy->expect_str) != NULL;
		else
			ret = regex_exec(s->proxy->expect_regex, contentptr);

		/* if we don't match, we may need to wait more */
		if (!ret && !done)
			return 0;

		if (ret) {
			/* content matched */
			if (s->proxy->options2 & PR_O2_EXP_INV)
				set_server_check_status(&s->check, HCHK_STATUS_L7RSP,
							"HTTP check matched unwanted content");
			else
				set_server_check_status(&s->check, HCHK_STATUS_L7OKD,
							"HTTP content check matched");
		}
		else {
			if (s->proxy->options2 & PR_O2_EXP_INV)
				set_server_check_status(&s->check, HCHK_STATUS_L7OKD,
							"HTTP check did not match unwanted content");
			else
				set_server_check_status(&s->check, HCHK_STATUS_L7RSP,
							"HTTP content check did not match");
		}
		break;
	}
	return 1;
}

/*
 * return the id of a step in a send/expect session
 */
static int tcpcheck_get_step_id(struct check *check)
{
	struct tcpcheck_rule *cur = NULL, *next = NULL;
	int i = 0;

	/* not even started anything yet => step 0 = initial connect */
	if (!check->current_step)
		return 0;

	cur = check->last_started_step;

	/* no step => first step */
	if (cur == NULL)
		return 1;

	/* increment i until current step */
	list_for_each_entry(next, check->tcpcheck_rules, list) {
		if (next->list.p == &cur->list)
			break;
		++i;
	}

	return i;
}

/*
 * return the latest known comment before (including) the given stepid
 * returns NULL if no comment found
 */
static char * tcpcheck_get_step_comment(struct check *check, int stepid)
{
	struct tcpcheck_rule *cur = NULL;
	char *ret = NULL;
	int i = 0;

	/* not even started anything yet, return latest comment found before any action */
	if (!check->current_step) {
		list_for_each_entry(cur, check->tcpcheck_rules, list) {
			if (cur->action == TCPCHK_ACT_COMMENT)
				ret = cur->comment;
			else
				goto return_comment;
		}
	}

	i = 1;
	list_for_each_entry(cur, check->tcpcheck_rules, list) {
		if (cur->comment)
			ret = cur->comment;

		if (i >= stepid)
			goto return_comment;

		++i;
	}

 return_comment:
	return ret;
}

/* proceed with next steps for the TCP checks <check>. Note that this is called
 * both from the connection's wake() callback and from the check scheduling task.
 * It returns 0 on normal cases, or <0 if a close() has happened on an existing
 * connection, presenting the risk of an fd replacement.
 *
 * Please do NOT place any return statement in this function and only leave
 * via the out_end_tcpcheck label after setting retcode.
 */
static int tcpcheck_main(struct check *check)
{
	char *contentptr, *comment;
	struct tcpcheck_rule *next;
	int done = 0, ret = 0, step = 0;
	struct conn_stream *cs = check->cs;
	struct connection *conn = cs_conn(cs);
	struct server *s = check->server;
	struct proxy *proxy = check->proxy;
	struct task *t = check->task;
	struct list *head = check->tcpcheck_rules;
	int retcode = 0;

	/* here, we know that the check is complete or that it failed */
	if (check->result != CHK_RES_UNKNOWN)
		goto out_end_tcpcheck;

	/* We have 4 possibilities here :
	 *   1. we've not yet attempted step 1, and step 1 is a connect, so no
	 *      connection attempt was made yet ; conn==NULL;current_step==NULL.
	 *   2. we've not yet attempted step 1, and step 1 is a not connect or
	 *      does not exist (no rule), so a connection attempt was made
	 *      before coming here, conn!=NULL.
	 *   3. we're coming back after having started with step 1, so we may
	 *      be waiting for a connection attempt to complete. conn!=NULL.
	 *   4. the connection + handshake are complete. conn!=NULL.
	 *
	 * #2 and #3 are quite similar, we want both the connection and the
	 * handshake to complete before going any further. Thus we must always
	 * wait for a connection to complete unless we're before and existing
	 * step 1.
	 */

	/* find first rule and skip comments */
	next = LIST_NEXT(head, struct tcpcheck_rule *, list);
	while (&next->list != head && next->action == TCPCHK_ACT_COMMENT)
		next = LIST_NEXT(&next->list, struct tcpcheck_rule *, list);

	if ((check->current_step || &next->list == head) &&
	    (!(conn->flags & CO_FL_CONNECTED) || (conn->flags & CO_FL_HANDSHAKE))) {
		/* we allow up to min(inter, timeout.connect) for a connection
		 * to establish but only when timeout.check is set
		 * as it may be to short for a full check otherwise
		 */
		while (tick_is_expired(t->expire, now_ms)) {
			int t_con;

			t_con = tick_add(t->expire, proxy->timeout.connect);
			t->expire = tick_add(t->expire, MS_TO_TICKS(check->inter));

			if (proxy->timeout.check)
				t->expire = tick_first(t->expire, t_con);
		}
		goto out;
	}

	/* special case: option tcp-check with no rule, a connect is enough */
	if (&next->list == head) {
		set_server_check_status(check, HCHK_STATUS_L4OK, NULL);
		goto out_end_tcpcheck;
	}

	/* no step means first step initialisation */
	if (check->current_step == NULL) {
		check->last_started_step = NULL;
		b_reset(&check->bo);
		b_reset(&check->bi);
		check->current_step = next;
		t->expire = tick_add(now_ms, MS_TO_TICKS(check->inter));
		if (proxy->timeout.check)
			t->expire = tick_add_ifset(now_ms, proxy->timeout.check);
	}

	while (1) {
		/* We have to try to flush the output buffer before reading, at
		 * the end, or if we're about to send a string that does not fit
		 * in the remaining space. That explains why we break out of the
		 * loop after this control. If we have data, conn is valid.
		 */
		if (b_data(&check->bo) &&
		    (&check->current_step->list == head ||
		     check->current_step->action != TCPCHK_ACT_SEND ||
		     check->current_step->string_len >= b_room(&check->bo))) {
			int ret;

			ret = cs->conn->mux->snd_buf(cs, &check->bo, b_data(&check->bo), 0);
			b_realign_if_empty(&check->bo);

			if (ret <= 0) {
				if (conn->flags & CO_FL_ERROR || cs->flags & CS_FL_ERROR) {
					chk_report_conn_err(check, errno, 0);
					goto out_end_tcpcheck;
				}
				break;
			}
			if (b_data(&check->bo)) {
				cs->conn->mux->subscribe(cs, SUB_RETRY_SEND, &check->wait_list);
				goto out;
			}
		}

		if (&check->current_step->list == head)
			break;

		/* have 'next' point to the next rule or NULL if we're on the
		 * last one, connect() needs this.
		 */
		next = LIST_NEXT(&check->current_step->list, struct tcpcheck_rule *, list);

		/* bypass all comment rules */
		while (&next->list != head && next->action == TCPCHK_ACT_COMMENT)
			next = LIST_NEXT(&next->list, struct tcpcheck_rule *, list);

		/* NULL if we're on the last rule */
		if (&next->list == head)
			next = NULL;

		if (check->current_step->action == TCPCHK_ACT_CONNECT) {
			struct protocol *proto;
			struct xprt_ops *xprt;

			/* For a connect action we'll create a new connection.
			 * We may also have to kill a previous one. But we don't
			 * want to leave *without* a connection if we came here
			 * from the connection layer, hence with a connection.
			 * Thus we'll proceed in the following order :
			 *   1: close but not release previous connection
			 *   2: try to get a new connection
			 *   3: release and replace the old one on success
			 */
			if (check->cs) {
				cs_close(check->cs);
				retcode = -1; /* do not reuse the fd in the caller! */
			}

			/* mark the step as started */
			check->last_started_step = check->current_step;

			/* prepare new connection */
			cs = cs_new(NULL);
			if (!cs) {
				step = tcpcheck_get_step_id(check);
				chunk_printf(&trash, "TCPCHK error allocating connection at step %d", step);
				comment = tcpcheck_get_step_comment(check, step);
				if (comment)
					chunk_appendf(&trash, " comment: '%s'", comment);
				set_server_check_status(check, HCHK_STATUS_SOCKERR,
							trash.area);
				check->current_step = NULL;
				goto out;
			}

			if (check->cs) {
				if (check->wait_list.events)
					cs->conn->xprt->unsubscribe(cs->conn,
					                            cs->conn->xprt_ctx,
								    check->wait_list.events,
								    &check->wait_list);
				/* We may have been scheduled to run, and the
				 * I/O handler expects to have a cs, so remove
				 * the tasklet
				 */
				tasklet_remove_from_tasklet_list(check->wait_list.tasklet);
				cs_destroy(check->cs);
			}

			tasklet_set_tid(check->wait_list.tasklet, tid);

			check->cs = cs;
			conn = cs->conn;
			/* Maybe there were an older connection we were waiting on */
			check->wait_list.events = 0;
			conn->target = s ? &s->obj_type : &proxy->obj_type;

			/* no client address */

			if (!sockaddr_alloc(&conn->dst)) {
				ret = SF_ERR_RESOURCE;
				goto fail_check;
			}

			if (is_addr(&check->addr)) {
				/* we'll connect to the check addr specified on the server */
				*conn->dst = check->addr;
			}
			else {
				/* we'll connect to the addr on the server */
				*conn->dst = s->addr;
			}
			proto = protocol_by_family(conn->dst->ss_family);

			/* port */
			if (check->current_step->port)
				set_host_port(conn->dst, check->current_step->port);
			else if (check->port)
				set_host_port(conn->dst, check->port);
			else if (s->svc_port)
				set_host_port(conn->dst, s->svc_port);

			if (check->current_step->conn_opts & TCPCHK_OPT_SSL) {
				xprt = xprt_get(XPRT_SSL);
			}
			else {
				xprt = xprt_get(XPRT_RAW);
			}

			conn_prepare(conn, proto, xprt);

			if (conn_install_mux(conn, &mux_pt_ops, cs, proxy, NULL) < 0) {
				ret = SF_ERR_RESOURCE;
				goto fail_check;
			}

			cs_attach(cs, check, &check_conn_cb);

			ret = SF_ERR_INTERNAL;
			if (proto && proto->connect)
				ret = proto->connect(conn,
						     CONNECT_HAS_DATA /* I/O polling is always needed */ | (next && next->action == TCPCHK_ACT_EXPECT) ? 0 : CONNECT_DELACK_ALWAYS);
			if (check->current_step->conn_opts & TCPCHK_OPT_SEND_PROXY) {
				conn->send_proxy_ofs = 1;
				conn->flags |= CO_FL_SEND_PROXY;
				if (xprt_add_hs(conn) < 0)
					ret = SF_ERR_RESOURCE;
			}

			/* It can return one of :
			 *  - SF_ERR_NONE if everything's OK
			 *  - SF_ERR_SRVTO if there are no more servers
			 *  - SF_ERR_SRVCL if the connection was refused by the server
			 *  - SF_ERR_PRXCOND if the connection has been limited by the proxy (maxconn)
			 *  - SF_ERR_RESOURCE if a system resource is lacking (eg: fd limits, ports, ...)
			 *  - SF_ERR_INTERNAL for any other purely internal errors
			 * Additionally, in the case of SF_ERR_RESOURCE, an emergency log will be emitted.
			 * Note that we try to prevent the network stack from sending the ACK during the
			 * connect() when a pure TCP check is used (without PROXY protocol).
			 */
		fail_check:
			switch (ret) {
			case SF_ERR_NONE:
				/* we allow up to min(inter, timeout.connect) for a connection
				 * to establish but only when timeout.check is set
				 * as it may be to short for a full check otherwise
				 */
				t->expire = tick_add(now_ms, MS_TO_TICKS(check->inter));

				if (proxy->timeout.check && proxy->timeout.connect) {
					int t_con = tick_add(now_ms, proxy->timeout.connect);
					t->expire = tick_first(t->expire, t_con);
				}
				break;
			case SF_ERR_SRVTO: /* ETIMEDOUT */
			case SF_ERR_SRVCL: /* ECONNREFUSED, ENETUNREACH, ... */
				step = tcpcheck_get_step_id(check);
				chunk_printf(&trash, "TCPCHK error establishing connection at step %d: %s",
						step, strerror(errno));
				comment = tcpcheck_get_step_comment(check, step);
				if (comment)
					chunk_appendf(&trash, " comment: '%s'", comment);
				set_server_check_status(check, HCHK_STATUS_L4CON,
							trash.area);
				goto out_end_tcpcheck;
			case SF_ERR_PRXCOND:
			case SF_ERR_RESOURCE:
			case SF_ERR_INTERNAL:
				step = tcpcheck_get_step_id(check);
				chunk_printf(&trash, "TCPCHK error establishing connection at step %d", step);
				comment = tcpcheck_get_step_comment(check, step);
				if (comment)
					chunk_appendf(&trash, " comment: '%s'", comment);
				set_server_check_status(check, HCHK_STATUS_SOCKERR,
							trash.area);
				goto out_end_tcpcheck;
			}

			/* allow next rule */
			check->current_step = LIST_NEXT(&check->current_step->list, struct tcpcheck_rule *, list);

			/* bypass all comment rules */
			while (&check->current_step->list != head &&
				check->current_step->action == TCPCHK_ACT_COMMENT)
				check->current_step = LIST_NEXT(&check->current_step->list, struct tcpcheck_rule *, list);

			if (&check->current_step->list == head)
				break;

			/* don't do anything until the connection is established */
			if (!(conn->flags & CO_FL_CONNECTED))
				break;

		} /* end 'connect' */
		else if (check->current_step->action == TCPCHK_ACT_SEND) {
			/* mark the step as started */
			check->last_started_step = check->current_step;

			/* reset the read buffer */
			if (*b_head(&check->bi) != '\0') {
				*b_head(&check->bi) = '\0';
				b_reset(&check->bi);
			}

			if (conn->flags & CO_FL_SOCK_WR_SH) {
				conn->flags |= CO_FL_ERROR;
				chk_report_conn_err(check, 0, 0);
				goto out_end_tcpcheck;
			}

			if (check->current_step->string_len >= b_size(&check->bo)) {
				chunk_printf(&trash, "tcp-check send : string too large (%d) for buffer size (%u) at step %d",
					     check->current_step->string_len, (unsigned int)b_size(&check->bo),
					     tcpcheck_get_step_id(check));
				set_server_check_status(check, HCHK_STATUS_L7RSP,
							trash.area);
				goto out_end_tcpcheck;
			}

			/* do not try to send if there is no space */
			if (check->current_step->string_len >= b_room(&check->bo))
				continue;

			b_putblk(&check->bo, check->current_step->string, check->current_step->string_len);
			*b_tail(&check->bo) = '\0'; /* to make gdb output easier to read */

			/* go to next rule and try to send */
			check->current_step = LIST_NEXT(&check->current_step->list, struct tcpcheck_rule *, list);

			/* bypass all comment rules */
			while (&check->current_step->list != head &&
				check->current_step->action == TCPCHK_ACT_COMMENT)
				check->current_step = LIST_NEXT(&check->current_step->list, struct tcpcheck_rule *, list);

		} /* end 'send' */
		else if (check->current_step->action == TCPCHK_ACT_EXPECT) {
			if (unlikely(check->result == CHK_RES_FAILED))
				goto out_end_tcpcheck;

			/* If we already subscribed, then we tried to received
			 * and failed, so there's no point trying again.
			 */
			if (check->wait_list.events & SUB_RETRY_RECV)
				break;
			if (cs->conn->mux->rcv_buf(cs, &check->bi, b_size(&check->bi), 0) <= 0) {
				if (conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH) || cs->flags & CS_FL_ERROR) {
					done = 1;
					if ((conn->flags & CO_FL_ERROR || cs->flags & CS_FL_ERROR) && !b_data(&check->bi)) {
						/* Report network errors only if we got no other data. Otherwise
						 * we'll let the upper layers decide whether the response is OK
						 * or not. It is very common that an RST sent by the server is
						 * reported as an error just after the last data chunk.
						 */
						chk_report_conn_err(check, errno, 0);
						goto out_end_tcpcheck;
					}
				}
				else {
					conn->mux->subscribe(cs, SUB_RETRY_RECV, &check->wait_list);
					break;
				}
			}

			/* mark the step as started */
			check->last_started_step = check->current_step;


			/* Intermediate or complete response received.
			 * Terminate string in b_head(&check->bi) buffer.
			 */
			if (b_data(&check->bi) < b_size(&check->bi)) {
				b_head(&check->bi)[b_data(&check->bi)] = '\0';
			}
			else {
				b_head(&check->bi)[b_data(&check->bi) - 1] = '\0';
				done = 1; /* buffer full, don't wait for more data */
			}

			contentptr = b_head(&check->bi);

			/* Check that response body is not empty... */
			if (!b_data(&check->bi)) {
				if (!done)
					continue;

				/* empty response */
				step = tcpcheck_get_step_id(check);
				chunk_printf(&trash, "TCPCHK got an empty response at step %d", step);
				comment = tcpcheck_get_step_comment(check, step);
				if (comment)
					chunk_appendf(&trash, " comment: '%s'", comment);
				set_server_check_status(check, HCHK_STATUS_L7RSP,
							trash.area);

				goto out_end_tcpcheck;
			}

			if (!done && (check->current_step->string != NULL) && (b_data(&check->bi) < check->current_step->string_len) )
				continue; /* try to read more */

		tcpcheck_expect:
			if (check->current_step->string != NULL)
				ret = my_memmem(contentptr, b_data(&check->bi), check->current_step->string, check->current_step->string_len) != NULL;
			else if (check->current_step->expect_regex != NULL)
				ret = regex_exec(check->current_step->expect_regex, contentptr);

			if (!ret && !done)
				continue; /* try to read more */

			/* matched */
			step = tcpcheck_get_step_id(check);
			if (ret) {
				/* matched but we did not want to => ERROR */
				if (check->current_step->inverse) {
					/* we were looking for a string */
					if (check->current_step->string != NULL) {
						chunk_printf(&trash, "TCPCHK matched unwanted content '%s' at step %d",
						             check->current_step->string, step);
					}
					else {
					/* we were looking for a regex */
						chunk_printf(&trash, "TCPCHK matched unwanted content (regex) at step %d", step);
					}
					comment = tcpcheck_get_step_comment(check, step);
					if (comment)
						chunk_appendf(&trash, " comment: '%s'", comment);
					set_server_check_status(check, HCHK_STATUS_L7RSP,
								trash.area);
					goto out_end_tcpcheck;
				}
				/* matched and was supposed to => OK, next step */
				else {
					/* allow next rule */
					check->current_step = LIST_NEXT(&check->current_step->list, struct tcpcheck_rule *, list);

					/* bypass all comment rules */
					while (&check->current_step->list != head &&
					       check->current_step->action == TCPCHK_ACT_COMMENT)
						check->current_step = LIST_NEXT(&check->current_step->list, struct tcpcheck_rule *, list);

					if (&check->current_step->list == head)
						break;

					if (check->current_step->action == TCPCHK_ACT_EXPECT)
						goto tcpcheck_expect;
				}
			}
			else {
			/* not matched */
				/* not matched and was not supposed to => OK, next step */
				if (check->current_step->inverse) {
					/* allow next rule */
					check->current_step = LIST_NEXT(&check->current_step->list, struct tcpcheck_rule *, list);

					/* bypass all comment rules */
					while (&check->current_step->list != head &&
					       check->current_step->action == TCPCHK_ACT_COMMENT)
						check->current_step = LIST_NEXT(&check->current_step->list, struct tcpcheck_rule *, list);

					if (&check->current_step->list == head)
						break;

					if (check->current_step->action == TCPCHK_ACT_EXPECT)
						goto tcpcheck_expect;
				}
				/* not matched but was supposed to => ERROR */
				else {
					/* we were looking for a string */
					if (check->current_step->string != NULL) {
						chunk_printf(&trash, "TCPCHK did not match content '%s' at step %d",
						             check->current_step->string, step);
					}
					else {
					/* we were looking for a regex */
						chunk_printf(&trash, "TCPCHK did not match content (regex) at step %d",
								step);
					}
					comment = tcpcheck_get_step_comment(check, step);
					if (comment)
						chunk_appendf(&trash, " comment: '%s'", comment);
					set_server_check_status(check, HCHK_STATUS_L7RSP,
								trash.area);
					goto out_end_tcpcheck;
				}
			}
		} /* end expect */
	} /* end loop over double chained step list */

	/* don't do anything until the connection is established */
	if (!(conn->flags & CO_FL_CONNECTED)) {
		/* update expire time, should be done by process_chk */
		/* we allow up to min(inter, timeout.connect) for a connection
		 * to establish but only when timeout.check is set
		 * as it may be to short for a full check otherwise
		 */
		while (tick_is_expired(t->expire, now_ms)) {
			int t_con;

			t_con = tick_add(t->expire, proxy->timeout.connect);
			t->expire = tick_add(t->expire, MS_TO_TICKS(check->inter));

			if (proxy->timeout.check)
				t->expire = tick_first(t->expire, t_con);
		}
		goto out;
	}

	/* We're waiting for some I/O to complete, we've reached the end of the
	 * rules, or both. Do what we have to do, otherwise we're done.
	 */
	if (&check->current_step->list == head && !b_data(&check->bo)) {
		set_server_check_status(check, HCHK_STATUS_L7OKD, "(tcp-check)");
		goto out_end_tcpcheck;
	}

	if (&check->current_step->list != head &&
	    check->current_step->action == TCPCHK_ACT_EXPECT)
		__event_srv_chk_r(cs);
	goto out;

 out_end_tcpcheck:
	/* collect possible new errors */
	if ((conn && conn->flags & CO_FL_ERROR) || (cs && cs->flags & CS_FL_ERROR))
		chk_report_conn_err(check, 0, 0);

	/* cleanup before leaving */
	check->current_step = NULL;

	if (check->result == CHK_RES_FAILED)
		conn->flags |= CO_FL_ERROR;

 out:
	return retcode;
}

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
		return "out of memroy while allocating check tasklet";
	check->wait_list.events = 0;
	check->wait_list.tasklet->process = event_srv_chk_io;
	check->wait_list.tasklet->context = check;
	return NULL;
}

void free_check(struct check *check)
{
	free(check->bi.area);
	free(check->bo.area);
	if (check->cs) {
		free(check->cs->conn);
		check->cs->conn = NULL;
		cs_free(check->cs);
		check->cs = NULL;
	}
}

void email_alert_free(struct email_alert *alert)
{
	struct tcpcheck_rule *rule, *back;

	if (!alert)
		return;

	list_for_each_entry_safe(rule, back, &alert->tcpcheck_rules, list) {
		LIST_DEL(&rule->list);
		free(rule->comment);
		free(rule->string);
		regex_free(rule->expect_regex);
		pool_free(pool_head_tcpcheck_rule, rule);
	}
	pool_free(pool_head_email_alert, alert);
}

static struct task *process_email_alert(struct task *t, void *context, unsigned short state)
{
	struct check        *check = context;
	struct email_alertq *q;
	struct email_alert  *alert;

	q = container_of(check, typeof(*q), check);

	HA_SPIN_LOCK(EMAIL_ALERTS_LOCK, &q->lock);
	while (1) {
		if (!(check->state & CHK_ST_ENABLED)) {
			if (LIST_ISEMPTY(&q->email_alerts)) {
				/* All alerts processed, queue the task */
				t->expire = TICK_ETERNITY;
				task_queue(t);
				goto end;
			}

			alert = LIST_NEXT(&q->email_alerts, typeof(alert), list);
			LIST_DEL(&alert->list);
			t->expire             = now_ms;
			check->tcpcheck_rules = &alert->tcpcheck_rules;
			check->status         = HCHK_STATUS_INI;
			check->state         |= CHK_ST_ENABLED;
		}

		process_chk(t, context, state);
		if (check->state & CHK_ST_INPROGRESS)
			break;

		alert = container_of(check->tcpcheck_rules, typeof(*alert), tcpcheck_rules);
		email_alert_free(alert);
		check->tcpcheck_rules = NULL;
		check->server         = NULL;
		check->state         &= ~CHK_ST_ENABLED;
	}
  end:
	HA_SPIN_UNLOCK(EMAIL_ALERTS_LOCK, &q->lock);
	return t;
}

/* Initializes mailer alerts for the proxy <p> using <mls> parameters.
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is
 * filled.
 */
int init_email_alert(struct mailers *mls, struct proxy *p, char **err)
{
	struct mailer       *mailer;
	struct email_alertq *queues;
	const char          *err_str;
	int                  i = 0;

	if ((queues = calloc(mls->count, sizeof(*queues))) == NULL) {
		memprintf(err, "out of memory while allocating mailer alerts queues");
		goto fail_no_queue;
	}

	for (mailer = mls->mailer_list; mailer; i++, mailer = mailer->next) {
		struct email_alertq *q     = &queues[i];
		struct check        *check = &q->check;
		struct task         *t;

		LIST_INIT(&q->email_alerts);
		HA_SPIN_INIT(&q->lock);
		check->inter = mls->timeout.mail;
		check->rise = DEF_AGENT_RISETIME;
		check->proxy = p;
		check->fall = DEF_AGENT_FALLTIME;
		if ((err_str = init_check(check, PR_O2_TCPCHK_CHK))) {
			memprintf(err, "%s", err_str);
			goto error;
		}

		check->xprt = mailer->xprt;
		check->addr = mailer->addr;
		check->port = get_host_port(&mailer->addr);

		if ((t = task_new(MAX_THREADS_MASK)) == NULL) {
			memprintf(err, "out of memory while allocating mailer alerts task");
			goto error;
		}

		check->task = t;
		t->process = process_email_alert;
		t->context = check;

		/* check this in one ms */
		t->expire    = TICK_ETERNITY;
		check->start = now;
		task_queue(t);
	}

	mls->users++;
	free(p->email_alert.mailers.name);
	p->email_alert.mailers.m = mls;
	p->email_alert.queues    = queues;
	return 0;

  error:
	for (i = 0; i < mls->count; i++) {
		struct email_alertq *q     = &queues[i];
		struct check        *check = &q->check;

		task_destroy(check->task);
		free_check(check);
	}
	free(queues);
  fail_no_queue:
	return 1;
}


static int add_tcpcheck_expect_str(struct list *list, const char *str)
{
	struct tcpcheck_rule *tcpcheck;

	if ((tcpcheck = pool_alloc(pool_head_tcpcheck_rule)) == NULL)
		return 0;
	memset(tcpcheck, 0, sizeof(*tcpcheck));
	tcpcheck->action       = TCPCHK_ACT_EXPECT;
	tcpcheck->string       = strdup(str);
	tcpcheck->expect_regex = NULL;
	tcpcheck->comment      = NULL;
	if (!tcpcheck->string) {
		pool_free(pool_head_tcpcheck_rule, tcpcheck);
		return 0;
	}

	LIST_ADDQ(list, &tcpcheck->list);
	return 1;
}

static int add_tcpcheck_send_strs(struct list *list, const char * const *strs)
{
	struct tcpcheck_rule *tcpcheck;
	const char *in;
	char *dst;
	int i;

	if ((tcpcheck = pool_alloc(pool_head_tcpcheck_rule)) == NULL)
		return 0;
	memset(tcpcheck, 0, sizeof(*tcpcheck));
	tcpcheck->action       = TCPCHK_ACT_SEND;
	tcpcheck->expect_regex = NULL;
	tcpcheck->comment      = NULL;
	tcpcheck->string_len = 0;
	for (i = 0; strs[i]; i++)
		tcpcheck->string_len += strlen(strs[i]);

	tcpcheck->string = malloc(tcpcheck->string_len + 1);
	if (!tcpcheck->string) {
		pool_free(pool_head_tcpcheck_rule, tcpcheck);
		return 0;
	}

	dst = tcpcheck->string;
	for (i = 0; strs[i]; i++)
		for (in = strs[i]; (*dst = *in++); dst++);
	*dst = 0;

	LIST_ADDQ(list, &tcpcheck->list);
	return 1;
}

static int enqueue_one_email_alert(struct proxy *p, struct server *s,
				   struct email_alertq *q, const char *msg)
{
	struct email_alert   *alert;
	struct tcpcheck_rule *tcpcheck;
	struct check *check = &q->check;

	if ((alert = pool_alloc(pool_head_email_alert)) == NULL)
		goto error;
	LIST_INIT(&alert->list);
	LIST_INIT(&alert->tcpcheck_rules);
	alert->srv = s;

	if ((tcpcheck = pool_alloc(pool_head_tcpcheck_rule)) == NULL)
		goto error;
	memset(tcpcheck, 0, sizeof(*tcpcheck));
	tcpcheck->action       = TCPCHK_ACT_CONNECT;
	tcpcheck->comment      = NULL;
	tcpcheck->string       = NULL;
	tcpcheck->expect_regex = NULL;
	LIST_ADDQ(&alert->tcpcheck_rules, &tcpcheck->list);

	if (!add_tcpcheck_expect_str(&alert->tcpcheck_rules, "220 "))
		goto error;

	{
		const char * const strs[4] = { "EHLO ", p->email_alert.myhostname, "\r\n" };
		if (!add_tcpcheck_send_strs(&alert->tcpcheck_rules, strs))
			goto error;
	}

	if (!add_tcpcheck_expect_str(&alert->tcpcheck_rules, "250 "))
		goto error;

	{
		const char * const strs[4] = { "MAIL FROM:<", p->email_alert.from, ">\r\n" };
		if (!add_tcpcheck_send_strs(&alert->tcpcheck_rules, strs))
			goto error;
	}

	if (!add_tcpcheck_expect_str(&alert->tcpcheck_rules, "250 "))
		goto error;

	{
		const char * const strs[4] = { "RCPT TO:<", p->email_alert.to, ">\r\n" };
		if (!add_tcpcheck_send_strs(&alert->tcpcheck_rules, strs))
			goto error;
	}

	if (!add_tcpcheck_expect_str(&alert->tcpcheck_rules, "250 "))
		goto error;

	{
		const char * const strs[2] = { "DATA\r\n" };
		if (!add_tcpcheck_send_strs(&alert->tcpcheck_rules, strs))
			goto error;
	}

	if (!add_tcpcheck_expect_str(&alert->tcpcheck_rules, "354 "))
		goto error;

	{
		struct tm tm;
		char datestr[48];
		const char * const strs[18] = {
			"From: ", p->email_alert.from, "\r\n",
			"To: ", p->email_alert.to, "\r\n",
			"Date: ", datestr, "\r\n",
			"Subject: [HAproxy Alert] ", msg, "\r\n",
			"\r\n",
			msg, "\r\n",
			"\r\n",
			".\r\n",
			NULL
		};

		get_localtime(date.tv_sec, &tm);

		if (strftime(datestr, sizeof(datestr), "%a, %d %b %Y %T %z (%Z)", &tm) == 0) {
			goto error;
		}

		if (!add_tcpcheck_send_strs(&alert->tcpcheck_rules, strs))
			goto error;
	}

	if (!add_tcpcheck_expect_str(&alert->tcpcheck_rules, "250 "))
		goto error;

	{
		const char * const strs[2] = { "QUIT\r\n" };
		if (!add_tcpcheck_send_strs(&alert->tcpcheck_rules, strs))
			goto error;
	}

	if (!add_tcpcheck_expect_str(&alert->tcpcheck_rules, "221 "))
		goto error;

	HA_SPIN_LOCK(EMAIL_ALERTS_LOCK, &q->lock);
	task_wakeup(check->task, TASK_WOKEN_MSG);
	LIST_ADDQ(&q->email_alerts, &alert->list);
	HA_SPIN_UNLOCK(EMAIL_ALERTS_LOCK, &q->lock);
	return 1;

error:
	email_alert_free(alert);
	return 0;
}

static void enqueue_email_alert(struct proxy *p, struct server *s, const char *msg)
{
	int i;
	struct mailer *mailer;

	for (i = 0, mailer = p->email_alert.mailers.m->mailer_list;
	     i < p->email_alert.mailers.m->count; i++, mailer = mailer->next) {
		if (!enqueue_one_email_alert(p, s, &p->email_alert.queues[i], msg)) {
			ha_alert("Email alert [%s] could not be enqueued: out of memory\n", p->id);
			return;
		}
	}

	return;
}

/*
 * Send email alert if configured.
 */
void send_email_alert(struct server *s, int level, const char *format, ...)
{
	va_list argp;
	char buf[1024];
	int len;
	struct proxy *p = s->proxy;

	if (!p->email_alert.mailers.m || level > p->email_alert.level || format == NULL)
		return;

	va_start(argp, format);
	len = vsnprintf(buf, sizeof(buf), format, argp);
	va_end(argp);

	if (len < 0 || len >= sizeof(buf)) {
		ha_alert("Email alert [%s] could not format message\n", p->id);
		return;
	}

	enqueue_email_alert(p, s, buf);
}

/*
 * Return value:
 *   the port to be used for the health check
 *   0 in case no port could be found for the check
 */
int srv_check_healthcheck_port(struct check *chk)
{
	int i = 0;
	struct server *srv = NULL;

	srv = chk->server;

	/* If neither a port nor an addr was specified and no check transport
	 * layer is forced, then the transport layer used by the checks is the
	 * same as for the production traffic. Otherwise we use raw_sock by
	 * default, unless one is specified.
	 */
	if (!chk->port && !is_addr(&chk->addr)) {
		chk->use_ssl |= (srv->use_ssl || (srv->proxy->options & PR_O_TCPCHK_SSL));
		chk->send_proxy |= (srv->pp_opts);
	}

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

REGISTER_POST_CHECK(start_checks);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
