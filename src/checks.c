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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <common/chunk.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/time.h>

#include <types/global.h>

#include <proto/backend.h>
#include <proto/checks.h>
#include <proto/fd.h>
#include <proto/log.h>
#include <proto/queue.h>
#include <proto/port_range.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/proxy.h>
#include <proto/raw_sock.h>
#include <proto/server.h>
#include <proto/session.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

static int httpchk_expect(struct server *s, int done);

static const struct check_status check_statuses[HCHK_STATUS_SIZE] = {
	[HCHK_STATUS_UNKNOWN]	= { SRV_CHK_UNKNOWN,                   "UNK",     "Unknown" },
	[HCHK_STATUS_INI]	= { SRV_CHK_UNKNOWN,                   "INI",     "Initializing" },
	[HCHK_STATUS_START]	= { /* SPECIAL STATUS*/ },

	[HCHK_STATUS_HANA]	= { SRV_CHK_ERROR,                     "HANA",    "Health analyze" },

	[HCHK_STATUS_SOCKERR]	= { SRV_CHK_ERROR,                     "SOCKERR", "Socket error" },

	[HCHK_STATUS_L4OK]	= { SRV_CHK_RUNNING,                   "L4OK",    "Layer4 check passed" },
	[HCHK_STATUS_L4TOUT]	= { SRV_CHK_ERROR,                     "L4TOUT",  "Layer4 timeout" },
	[HCHK_STATUS_L4CON]	= { SRV_CHK_ERROR,                     "L4CON",   "Layer4 connection problem" },

	[HCHK_STATUS_L6OK]	= { SRV_CHK_RUNNING,                   "L6OK",    "Layer6 check passed" },
	[HCHK_STATUS_L6TOUT]	= { SRV_CHK_ERROR,                     "L6TOUT",  "Layer6 timeout" },
	[HCHK_STATUS_L6RSP]	= { SRV_CHK_ERROR,                     "L6RSP",   "Layer6 invalid response" },

	[HCHK_STATUS_L7TOUT]	= { SRV_CHK_ERROR,                     "L7TOUT",  "Layer7 timeout" },
	[HCHK_STATUS_L7RSP]	= { SRV_CHK_ERROR,                     "L7RSP",   "Layer7 invalid response" },

	[HCHK_STATUS_L57DATA]	= { /* DUMMY STATUS */ },

	[HCHK_STATUS_L7OKD]	= { SRV_CHK_RUNNING,                   "L7OK",    "Layer7 check passed" },
	[HCHK_STATUS_L7OKCD]	= { SRV_CHK_RUNNING | SRV_CHK_DISABLE, "L7OKC",   "Layer7 check conditionally passed" },
	[HCHK_STATUS_L7STS]	= { SRV_CHK_ERROR,                     "L7STS",   "Layer7 wrong status" },
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

#define SSP_O_HCHK	0x0002

static void server_status_printf(struct chunk *msg, struct server *s, unsigned options, int xferred) {

	if (s->track)
		chunk_printf(msg, " via %s/%s",
			s->track->proxy->id, s->track->id);

	if (options & SSP_O_HCHK) {
		chunk_printf(msg, ", reason: %s", get_check_status_description(s->check.status));

		if (s->check.status >= HCHK_STATUS_L57DATA)
			chunk_printf(msg, ", code: %d", s->check.code);

		if (*s->check.desc) {
			struct chunk src;

			chunk_printf(msg, ", info: \"");

			chunk_initlen(&src, s->check.desc, 0, strlen(s->check.desc));
			chunk_asciiencode(msg, &src, '"');

			chunk_printf(msg, "\"");
		}

		if (s->check.duration >= 0)
			chunk_printf(msg, ", check duration: %ldms", s->check.duration);
	}

	if (xferred >= 0) {
		if (!(s->state & SRV_RUNNING))
        	        chunk_printf(msg, ". %d active and %d backup servers left.%s"
				" %d sessions active, %d requeued, %d remaining in queue",
				s->proxy->srv_act, s->proxy->srv_bck,
				(s->proxy->srv_bck && !s->proxy->srv_act) ? " Running on backup." : "",
				s->cur_sess, xferred, s->nbpend);
		else 
			chunk_printf(msg, ". %d active and %d backup servers online.%s"
				" %d sessions requeued, %d total in queue",
				s->proxy->srv_act, s->proxy->srv_bck,
				(s->proxy->srv_bck && !s->proxy->srv_act) ? " Running on backup." : "",
				xferred, s->nbpend);
	}
}

/*
 * Set s->check.status, update s->check.duration and fill s->result with
 * an adequate SRV_CHK_* value.
 *
 * Show information in logs about failed health check if server is UP
 * or succeeded health checks if server is DOWN.
 */
static void set_server_check_status(struct server *s, short status, char *desc) {

	struct chunk msg;

	if (status == HCHK_STATUS_START) {
		s->result = SRV_CHK_UNKNOWN;	/* no result yet */
		s->check.desc[0] = '\0';
		s->check.start = now;
		return;
	}

	if (!s->check.status)
		return;

	if (desc && *desc) {
		strncpy(s->check.desc, desc, HCHK_DESC_LEN-1);
		s->check.desc[HCHK_DESC_LEN-1] = '\0';
	} else
		s->check.desc[0] = '\0';

	s->check.status = status;
	if (check_statuses[status].result)
		s->result = check_statuses[status].result;

	if (status == HCHK_STATUS_HANA)
		s->check.duration = -1;
	else if (!tv_iszero(&s->check.start)) {
		/* set_server_check_status() may be called more than once */
		s->check.duration = tv_ms_elapsed(&s->check.start, &now);
		tv_zero(&s->check.start);
	}

	if (s->proxy->options2 & PR_O2_LOGHCHKS &&
	(((s->health != 0) && (s->result & SRV_CHK_ERROR)) ||
	    ((s->health != s->rise + s->fall - 1) && (s->result & SRV_CHK_RUNNING)) ||
	    ((s->state & SRV_GOINGDOWN) && !(s->result & SRV_CHK_DISABLE)) ||
	    (!(s->state & SRV_GOINGDOWN) && (s->result & SRV_CHK_DISABLE)))) {

		int health, rise, fall, state;

		chunk_init(&msg, trash, trashlen);

		/* FIXME begin: calculate local version of the health/rise/fall/state */
		health = s->health;
		rise   = s->rise;
		fall   = s->fall;
		state  = s->state;

		if (s->result & SRV_CHK_ERROR) {
			if (health > rise) {
				health--; /* still good */
			} else {
				if (health == rise)
					state &= ~(SRV_RUNNING | SRV_GOINGDOWN);

				health = 0;
			}
		}

		if (s->result & SRV_CHK_RUNNING) {
			if (health < rise + fall - 1) {
				health++; /* was bad, stays for a while */

				if (health == rise)
					state |= SRV_RUNNING;

				if (health >= rise)
					health = rise + fall - 1; /* OK now */
			}

			/* clear consecutive_errors if observing is enabled */
			if (s->onerror)
				s->consecutive_errors = 0;
		}
		/* FIXME end: calculate local version of the health/rise/fall/state */

		chunk_printf(&msg,
			"Health check for %sserver %s/%s %s%s",
			s->state & SRV_BACKUP ? "backup " : "",
			s->proxy->id, s->id,
			(s->result & SRV_CHK_DISABLE)?"conditionally ":"",
			(s->result & SRV_CHK_RUNNING)?"succeeded":"failed");

		server_status_printf(&msg, s, SSP_O_HCHK, -1);

		chunk_printf(&msg, ", status: %d/%d %s",
			(state & SRV_RUNNING) ? (health - rise + 1) : (health),
			(state & SRV_RUNNING) ? (fall) : (rise),
			(state & SRV_RUNNING)?"UP":"DOWN");

		Warning("%s.\n", trash);
		send_log(s->proxy, LOG_NOTICE, "%s.\n", trash);
	}
}

/* sends a log message when a backend goes down, and also sets last
 * change date.
 */
static void set_backend_down(struct proxy *be)
{
	be->last_change = now.tv_sec;
	be->down_trans++;

	Alert("%s '%s' has no server available!\n", proxy_type_str(be), be->id);
	send_log(be, LOG_EMERG, "%s %s has no server available!\n", proxy_type_str(be), be->id);
}

/* Redistribute pending connections when a server goes down. The number of
 * connections redistributed is returned.
 */
static int redistribute_pending(struct server *s)
{
	struct pendconn *pc, *pc_bck, *pc_end;
	int xferred = 0;

	FOREACH_ITEM_SAFE(pc, pc_bck, &s->pendconns, pc_end, struct pendconn *, list) {
		struct session *sess = pc->sess;
		if ((sess->be->options & (PR_O_REDISP|PR_O_PERSIST)) == PR_O_REDISP &&
		    !(sess->flags & SN_FORCE_PRST)) {
			/* The REDISP option was specified. We will ignore
			 * cookie and force to balance or use the dispatcher.
			 */

			/* it's left to the dispatcher to choose a server */
			sess->flags &= ~(SN_DIRECT | SN_ASSIGNED | SN_ADDR_SET);

			pendconn_free(pc);
			task_wakeup(sess->task, TASK_WOKEN_RES);
			xferred++;
		}
	}
	return xferred;
}

/* Check for pending connections at the backend, and assign some of them to
 * the server coming up. The server's weight is checked before being assigned
 * connections it may not be able to handle. The total number of transferred
 * connections is returned.
 */
static int check_for_pending(struct server *s)
{
	int xferred;

	if (!s->eweight)
		return 0;

	for (xferred = 0; !s->maxconn || xferred < srv_dynamic_maxconn(s); xferred++) {
		struct session *sess;
		struct pendconn *p;

		p = pendconn_from_px(s->proxy);
		if (!p)
			break;
		set_target_server(&p->sess->target, s);
		sess = p->sess;
		pendconn_free(p);
		task_wakeup(sess->task, TASK_WOKEN_RES);
	}
	return xferred;
}

/* Shutdown all connections of a server. The caller must pass a termination
 * code in <why>, which must be one of SN_ERR_* indicating the reason for the
 * shutdown.
 */
static void shutdown_sessions(struct server *srv, int why)
{
	struct session *session, *session_bck;

	list_for_each_entry_safe(session, session_bck, &srv->actconns, by_srv)
		if (session->srv_conn == srv)
			session_shutdown(session, why);
}

/* Shutdown all connections of all backup servers of a proxy. The caller must
 * pass a termination code in <why>, which must be one of SN_ERR_* indicating
 * the reason for the shutdown.
 */
static void shutdown_backup_sessions(struct proxy *px, int why)
{
	struct server *srv;

	for (srv = px->srv; srv != NULL; srv = srv->next)
		if (srv->state & SRV_BACKUP)
			shutdown_sessions(srv, why);
}

/* Sets server <s> down, notifies by all available means, recounts the
 * remaining servers on the proxy and transfers queued sessions whenever
 * possible to other servers. It automatically recomputes the number of
 * servers, but not the map.
 */
void set_server_down(struct server *s)
{
	struct server *srv;
	struct chunk msg;
	int xferred;

	if (s->state & SRV_MAINTAIN) {
		s->health = s->rise;
	}

	if (s->health == s->rise || s->track) {
		int srv_was_paused = s->state & SRV_GOINGDOWN;
		int prev_srv_count = s->proxy->srv_bck + s->proxy->srv_act;

		s->last_change = now.tv_sec;
		s->state &= ~(SRV_RUNNING | SRV_GOINGDOWN);
		if (s->proxy->lbprm.set_server_status_down)
			s->proxy->lbprm.set_server_status_down(s);

		if (s->onmarkeddown & HANA_ONMARKEDDOWN_SHUTDOWNSESSIONS)
			shutdown_sessions(s, SN_ERR_DOWN);

		/* we might have sessions queued on this server and waiting for
		 * a connection. Those which are redispatchable will be queued
		 * to another server or to the proxy itself.
		 */
		xferred = redistribute_pending(s);

		chunk_init(&msg, trash, trashlen);

		if (s->state & SRV_MAINTAIN) {
			chunk_printf(&msg,
				"%sServer %s/%s is DOWN for maintenance", s->state & SRV_BACKUP ? "Backup " : "",
				s->proxy->id, s->id);
		} else {
			chunk_printf(&msg,
				"%sServer %s/%s is DOWN", s->state & SRV_BACKUP ? "Backup " : "",
				s->proxy->id, s->id);

			server_status_printf(&msg, s,
						((!s->track && !(s->proxy->options2 & PR_O2_LOGHCHKS))?SSP_O_HCHK:0),
						xferred);
		}
		Warning("%s.\n", trash);

		/* we don't send an alert if the server was previously paused */
		if (srv_was_paused)
			send_log(s->proxy, LOG_NOTICE, "%s.\n", trash);
		else
			send_log(s->proxy, LOG_ALERT, "%s.\n", trash);

		if (prev_srv_count && s->proxy->srv_bck == 0 && s->proxy->srv_act == 0)
			set_backend_down(s->proxy);

		s->counters.down_trans++;

		if (s->state & SRV_CHECKED)
			for(srv = s->tracknext; srv; srv = srv->tracknext)
				if (! (srv->state & SRV_MAINTAIN))
					/* Only notify tracking servers that are not already in maintenance. */
					set_server_down(srv);
	}

	s->health = 0; /* failure */
}

void set_server_up(struct server *s) {

	struct server *srv;
	struct chunk msg;
	int xferred;
	unsigned int old_state = s->state;

	if (s->state & SRV_MAINTAIN) {
		s->health = s->rise;
	}

	if (s->health == s->rise || s->track) {
		if (s->proxy->srv_bck == 0 && s->proxy->srv_act == 0) {
			if (s->proxy->last_change < now.tv_sec)		// ignore negative times
				s->proxy->down_time += now.tv_sec - s->proxy->last_change;
			s->proxy->last_change = now.tv_sec;
		}

		if (s->last_change < now.tv_sec)			// ignore negative times
			s->down_time += now.tv_sec - s->last_change;

		s->last_change = now.tv_sec;
		s->state |= SRV_RUNNING;
		s->state &= ~SRV_MAINTAIN;

		if (s->slowstart > 0) {
			s->state |= SRV_WARMINGUP;
			if (s->proxy->lbprm.algo & BE_LB_PROP_DYN) {
				/* For dynamic algorithms, start at the first step of the weight,
				 * without multiplying by BE_WEIGHT_SCALE.
				 */
				s->eweight = s->uweight;
				if (s->proxy->lbprm.update_server_eweight)
					s->proxy->lbprm.update_server_eweight(s);
			}
			task_schedule(s->warmup, tick_add(now_ms, MS_TO_TICKS(MAX(1000, s->slowstart / 20))));
		}
		if (s->proxy->lbprm.set_server_status_up)
			s->proxy->lbprm.set_server_status_up(s);

		/* If the server is set with "on-marked-up shutdown-backup-sessions",
		 * and it's not a backup server and its effective weight is > 0,
		 * then it can accept new connections, so we shut down all sessions
		 * on all backup servers.
		 */
		if ((s->onmarkedup & HANA_ONMARKEDUP_SHUTDOWNBACKUPSESSIONS) &&
		    !(s->state & SRV_BACKUP) && s->eweight)
			shutdown_backup_sessions(s->proxy, SN_ERR_UP);

		/* check if we can handle some connections queued at the proxy. We
		 * will take as many as we can handle.
		 */
		xferred = check_for_pending(s);

		chunk_init(&msg, trash, trashlen);

		if (old_state & SRV_MAINTAIN) {
			chunk_printf(&msg,
				"%sServer %s/%s is UP (leaving maintenance)", s->state & SRV_BACKUP ? "Backup " : "",
				s->proxy->id, s->id);
		} else {
			chunk_printf(&msg,
				"%sServer %s/%s is UP", s->state & SRV_BACKUP ? "Backup " : "",
				s->proxy->id, s->id);

			server_status_printf(&msg, s,
						((!s->track && !(s->proxy->options2 & PR_O2_LOGHCHKS))?SSP_O_HCHK:0),
						xferred);
		}

		Warning("%s.\n", trash);
		send_log(s->proxy, LOG_NOTICE, "%s.\n", trash);

		if (s->state & SRV_CHECKED)
			for(srv = s->tracknext; srv; srv = srv->tracknext)
				if (! (srv->state & SRV_MAINTAIN))
					/* Only notify tracking servers if they're not in maintenance. */
					set_server_up(srv);
	}

	if (s->health >= s->rise)
		s->health = s->rise + s->fall - 1; /* OK now */

}

static void set_server_disabled(struct server *s) {

	struct server *srv;
	struct chunk msg;
	int xferred;

	s->state |= SRV_GOINGDOWN;
	if (s->proxy->lbprm.set_server_status_down)
		s->proxy->lbprm.set_server_status_down(s);

	/* we might have sessions queued on this server and waiting for
	 * a connection. Those which are redispatchable will be queued
	 * to another server or to the proxy itself.
	 */
	xferred = redistribute_pending(s);

	chunk_init(&msg, trash, trashlen);

	chunk_printf(&msg,
		"Load-balancing on %sServer %s/%s is disabled",
		s->state & SRV_BACKUP ? "Backup " : "",
		s->proxy->id, s->id);

	server_status_printf(&msg, s,
				((!s->track && !(s->proxy->options2 & PR_O2_LOGHCHKS))?SSP_O_HCHK:0),
				xferred);

	Warning("%s.\n", trash);
	send_log(s->proxy, LOG_NOTICE, "%s.\n", trash);

	if (!s->proxy->srv_bck && !s->proxy->srv_act)
		set_backend_down(s->proxy);

	if (s->state & SRV_CHECKED)
		for(srv = s->tracknext; srv; srv = srv->tracknext)
			set_server_disabled(srv);
}

static void set_server_enabled(struct server *s) {

	struct server *srv;
	struct chunk msg;
	int xferred;

	s->state &= ~SRV_GOINGDOWN;
	if (s->proxy->lbprm.set_server_status_up)
		s->proxy->lbprm.set_server_status_up(s);

	/* check if we can handle some connections queued at the proxy. We
	 * will take as many as we can handle.
	 */
	xferred = check_for_pending(s);

	chunk_init(&msg, trash, trashlen);

	chunk_printf(&msg,
		"Load-balancing on %sServer %s/%s is enabled again",
		s->state & SRV_BACKUP ? "Backup " : "",
		s->proxy->id, s->id);

	server_status_printf(&msg, s,
				((!s->track && !(s->proxy->options2 & PR_O2_LOGHCHKS))?SSP_O_HCHK:0),
				xferred);

	Warning("%s.\n", trash);
	send_log(s->proxy, LOG_NOTICE, "%s.\n", trash);

	if (s->state & SRV_CHECKED)
		for(srv = s->tracknext; srv; srv = srv->tracknext)
			set_server_enabled(srv);
}

void health_adjust(struct server *s, short status) {

	int failed;
	int expire;

	/* return now if observing nor health check is not enabled */
	if (!s->observe || !s->check.task)
		return;

	if (s->observe >= HANA_OBS_SIZE)
		return;

	if (status >= HCHK_STATUS_SIZE || !analyze_statuses[status].desc)
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

	s->consecutive_errors++;

	if (s->consecutive_errors < s->consecutive_errors_limit)
		return;

	sprintf(trash, "Detected %d consecutive errors, last one was: %s",
		s->consecutive_errors, get_analyze_status(status));

	switch (s->onerror) {
		case HANA_ONERR_FASTINTER:
		/* force fastinter - nothing to do here as all modes force it */
			break;

		case HANA_ONERR_SUDDTH:
		/* simulate a pre-fatal failed health check */
			if (s->health > s->rise)
				s->health = s->rise + 1;

			/* no break - fall through */

		case HANA_ONERR_FAILCHK:
		/* simulate a failed health check */
			set_server_check_status(s, HCHK_STATUS_HANA, trash);

			if (s->health > s->rise) {
				s->health--; /* still good */
				s->counters.failed_checks++;
			}
			else
				set_server_down(s);

			break;

		case HANA_ONERR_MARKDWN:
		/* mark server down */
			s->health = s->rise;
			set_server_check_status(s, HCHK_STATUS_HANA, trash);
			set_server_down(s);

			break;

		default:
			/* write a warning? */
			break;
	}

	s->consecutive_errors = 0;
	s->counters.failed_hana++;

	if (s->fastinter) {
		expire = tick_add(now_ms, MS_TO_TICKS(s->fastinter));
		if (s->check.task->expire > expire)
			s->check.task->expire = expire;
	}
}

static int httpchk_build_status_header(struct server *s, char *buffer)
{
	int sv_state;
	int ratio;
	int hlen = 0;
	const char *srv_hlt_st[7] = { "DOWN", "DOWN %d/%d",
				      "UP %d/%d", "UP",
				      "NOLB %d/%d", "NOLB",
				      "no check" };

	memcpy(buffer + hlen, "X-Haproxy-Server-State: ", 24);
	hlen += 24;

	if (!(s->state & SRV_CHECKED))
		sv_state = 6; /* should obviously never happen */
	else if (s->state & SRV_RUNNING) {
		if (s->health == s->rise + s->fall - 1)
			sv_state = 3; /* UP */
		else
			sv_state = 2; /* going down */

		if (s->state & SRV_GOINGDOWN)
			sv_state += 2;
	} else {
		if (s->health)
			sv_state = 1; /* going up */
		else
			sv_state = 0; /* DOWN */
	}

	hlen += sprintf(buffer + hlen,
			     srv_hlt_st[sv_state],
			     (s->state & SRV_RUNNING) ? (s->health - s->rise + 1) : (s->health),
			     (s->state & SRV_RUNNING) ? (s->fall) : (s->rise));

	hlen += sprintf(buffer + hlen, "; name=%s/%s; node=%s; weight=%d/%d; scur=%d/%d; qcur=%d",
			     s->proxy->id, s->id,
			     global.node,
			     (s->eweight * s->proxy->lbprm.wmult + s->proxy->lbprm.wdiv - 1) / s->proxy->lbprm.wdiv,
			     (s->proxy->lbprm.tot_weight * s->proxy->lbprm.wmult + s->proxy->lbprm.wdiv - 1) / s->proxy->lbprm.wdiv,
			     s->cur_sess, s->proxy->beconn - s->proxy->nbpend,
			     s->nbpend);

	if ((s->state & SRV_WARMINGUP) &&
	    now.tv_sec < s->last_change + s->slowstart &&
	    now.tv_sec >= s->last_change) {
		ratio = MAX(1, 100 * (now.tv_sec - s->last_change) / s->slowstart);
		hlen += sprintf(buffer + hlen, "; throttle=%d%%", ratio);
	}

	buffer[hlen++] = '\r';
	buffer[hlen++] = '\n';

	return hlen;
}

/*
 * This function is used only for server health-checks. It handles
 * the connection acknowledgement. If the proxy requires L7 health-checks,
 * it sends the request. In other cases, it calls set_server_check_status()
 * to set s->check.status, s->check.duration and s->result.
 */
static void event_srv_chk_w(struct connection *conn)
{
	struct server *s = conn->owner;
	int fd = conn->t.sock.fd;
	struct task *t = s->check.task;

	if (conn->flags & (CO_FL_SOCK_WR_SH | CO_FL_DATA_WR_SH | CO_FL_WAIT_DATA | CO_FL_WAIT_WR))
		conn->flags |= CO_FL_ERROR;

	if (unlikely(conn->flags & CO_FL_ERROR)) {
		int skerr, err = errno;
		socklen_t lskerr = sizeof(skerr);

		if (!getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr) && skerr)
			err = skerr;

		set_server_check_status(s, HCHK_STATUS_L4CON, strerror(err));
		goto out_error;
	}

	if (conn->flags & CO_FL_HANDSHAKE)
		return;

	/* here, we know that the connection is established */
	if (!(s->result & SRV_CHK_ERROR)) {
		/* we don't want to mark 'UP' a server on which we detected an error earlier */
		if (s->check.bo->o) {
			int ret;

			ret = conn->xprt->snd_buf(conn, s->check.bo, MSG_DONTWAIT | MSG_NOSIGNAL);
			if (conn->flags & CO_FL_ERROR) {
				set_server_check_status(s, HCHK_STATUS_L4CON, strerror(errno));
				goto out_wakeup;
			}
		}

		if (!s->check.bo->o) {
			/* full request sent, we allow up to <timeout.check> if nonzero for a response */
			if (s->proxy->timeout.check) {
				t->expire = tick_add_ifset(now_ms, s->proxy->timeout.check);
				task_queue(t);
			}
			__conn_data_want_recv(conn);   /* prepare for reading reply */
			goto out_nowake;
		}
		goto out_poll;
	}
 out_wakeup:
	task_wakeup(t, TASK_WOKEN_IO);
 out_nowake:
	__conn_data_stop_send(conn);   /* nothing more to write */
	return;
 out_poll:
	__conn_data_poll_send(conn);
	return;
 out_error:
	conn->flags |= CO_FL_ERROR;
	goto out_wakeup;
}


/*
 * This function is used only for server health-checks. It handles the server's
 * reply to an HTTP request, SSL HELLO or MySQL client Auth. It calls
 * set_server_check_status() to update s->check.status, s->check.duration
 * and s->result.

 * The set_server_check_status function is called with HCHK_STATUS_L7OKD if
 * an HTTP server replies HTTP 2xx or 3xx (valid responses), if an SMTP server
 * returns 2xx, HCHK_STATUS_L6OK if an SSL server returns at least 5 bytes in
 * response to an SSL HELLO (the principle is that this is enough to
 * distinguish between an SSL server and a pure TCP relay). All other cases will
 * call it with a proper error status like HCHK_STATUS_L7STS, HCHK_STATUS_L6RSP,
 * etc.
 */
static void event_srv_chk_r(struct connection *conn)
{
	int len;
	struct server *s = conn->owner;
	struct task *t = s->check.task;
	char *desc;
	int done;
	unsigned short msglen;

	if (conn->flags & (CO_FL_SOCK_WR_SH | CO_FL_DATA_WR_SH | CO_FL_WAIT_DATA | CO_FL_WAIT_WR))
		conn->flags |= CO_FL_ERROR;

	if (unlikely((s->result & SRV_CHK_ERROR) || (conn->flags & CO_FL_ERROR))) {
		/* in case of TCP only, this tells us if the connection failed */
		if (!(s->result & SRV_CHK_ERROR))
			set_server_check_status(s, HCHK_STATUS_SOCKERR, NULL);

		goto out_wakeup;
	}

	if (conn->flags & CO_FL_HANDSHAKE)
		return;

	/* Warning! Linux returns EAGAIN on SO_ERROR if data are still available
	 * but the connection was closed on the remote end. Fortunately, recv still
	 * works correctly and we don't need to do the getsockopt() on linux.
	 */

	/* Set buffer to point to the end of the data already read, and check
	 * that there is free space remaining. If the buffer is full, proceed
	 * with running the checks without attempting another socket read.
	 */

	done = 0;

	len = conn->xprt->rcv_buf(conn, s->check.bi, s->check.bi->size);
	if (conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_DATA_RD_SH)) {
		done = 1;
		if ((conn->flags & CO_FL_ERROR) && !s->check.bi->i) {
			/* Report network errors only if we got no other data. Otherwise
			 * we'll let the upper layers decide whether the response is OK
			 * or not. It is very common that an RST sent by the server is
			 * reported as an error just after the last data chunk.
			 */
			if (!(s->result & SRV_CHK_ERROR))
				set_server_check_status(s, HCHK_STATUS_SOCKERR, NULL);
			goto out_wakeup;
		}
	}

	/* Intermediate or complete response received.
	 * Terminate string in check.bi->data buffer.
	 */
	if (s->check.bi->i < s->check.bi->size)
		s->check.bi->data[s->check.bi->i] = '\0';
	else {
		s->check.bi->data[s->check.bi->i - 1] = '\0';
		done = 1; /* buffer full, don't wait for more data */
	}

	/* Run the checks... */
	switch (s->proxy->options2 & PR_O2_CHK_ANY) {
	case PR_O2_HTTP_CHK:
		if (!done && s->check.bi->i < strlen("HTTP/1.0 000\r"))
			goto wait_more_data;

		/* Check if the server speaks HTTP 1.X */
		if ((s->check.bi->i < strlen("HTTP/1.0 000\r")) ||
		    (memcmp(s->check.bi->data, "HTTP/1.", 7) != 0 ||
		    (*(s->check.bi->data + 12) != ' ' && *(s->check.bi->data + 12) != '\r')) ||
		    !isdigit((unsigned char) *(s->check.bi->data + 9)) || !isdigit((unsigned char) *(s->check.bi->data + 10)) ||
		    !isdigit((unsigned char) *(s->check.bi->data + 11))) {
			cut_crlf(s->check.bi->data);
			set_server_check_status(s, HCHK_STATUS_L7RSP, s->check.bi->data);

			goto out_wakeup;
		}

		s->check.code = str2uic(s->check.bi->data + 9);
		desc = ltrim(s->check.bi->data + 12, ' ');
		
		if ((s->proxy->options & PR_O_DISABLE404) &&
			 (s->state & SRV_RUNNING) && (s->check.code == 404)) {
			/* 404 may be accepted as "stopping" only if the server was up */
			cut_crlf(desc);
			set_server_check_status(s, HCHK_STATUS_L7OKCD, desc);
		}
		else if (s->proxy->options2 & PR_O2_EXP_TYPE) {
			/* Run content verification check... We know we have at least 13 chars */
			if (!httpchk_expect(s, done))
				goto wait_more_data;
		}
		/* check the reply : HTTP/1.X 2xx and 3xx are OK */
		else if (*(s->check.bi->data + 9) == '2' || *(s->check.bi->data + 9) == '3') {
			cut_crlf(desc);
			set_server_check_status(s, HCHK_STATUS_L7OKD, desc);
		}
		else {
			cut_crlf(desc);
			set_server_check_status(s, HCHK_STATUS_L7STS, desc);
		}
		break;

	case PR_O2_SSL3_CHK:
		if (!done && s->check.bi->i < 5)
			goto wait_more_data;

		/* Check for SSLv3 alert or handshake */
		if ((s->check.bi->i >= 5) && (*s->check.bi->data == 0x15 || *s->check.bi->data == 0x16))
			set_server_check_status(s, HCHK_STATUS_L6OK, NULL);
		else
			set_server_check_status(s, HCHK_STATUS_L6RSP, NULL);
		break;

	case PR_O2_SMTP_CHK:
		if (!done && s->check.bi->i < strlen("000\r"))
			goto wait_more_data;

		/* Check if the server speaks SMTP */
		if ((s->check.bi->i < strlen("000\r")) ||
		    (*(s->check.bi->data + 3) != ' ' && *(s->check.bi->data + 3) != '\r') ||
		    !isdigit((unsigned char) *s->check.bi->data) || !isdigit((unsigned char) *(s->check.bi->data + 1)) ||
		    !isdigit((unsigned char) *(s->check.bi->data + 2))) {
			cut_crlf(s->check.bi->data);
			set_server_check_status(s, HCHK_STATUS_L7RSP, s->check.bi->data);

			goto out_wakeup;
		}

		s->check.code = str2uic(s->check.bi->data);

		desc = ltrim(s->check.bi->data + 3, ' ');
		cut_crlf(desc);

		/* Check for SMTP code 2xx (should be 250) */
		if (*s->check.bi->data == '2')
			set_server_check_status(s, HCHK_STATUS_L7OKD, desc);
		else
			set_server_check_status(s, HCHK_STATUS_L7STS, desc);
		break;

	case PR_O2_PGSQL_CHK:
		if (!done && s->check.bi->i < 9)
			goto wait_more_data;

		if (s->check.bi->data[0] == 'R') {
			set_server_check_status(s, HCHK_STATUS_L7OKD, "PostgreSQL server is ok");
		}
		else {
			if ((s->check.bi->data[0] == 'E') && (s->check.bi->data[5]!=0) && (s->check.bi->data[6]!=0))
				desc = &s->check.bi->data[6];
			else
				desc = "PostgreSQL unknown error";

			set_server_check_status(s, HCHK_STATUS_L7STS, desc);
		}
		break;

	case PR_O2_REDIS_CHK:
		if (!done && s->check.bi->i < 7)
			goto wait_more_data;

		if (strcmp(s->check.bi->data, "+PONG\r\n") == 0) {
			set_server_check_status(s, HCHK_STATUS_L7OKD, "Redis server is ok");
		}
		else {
			set_server_check_status(s, HCHK_STATUS_L7STS, s->check.bi->data);
		}
		break;

	case PR_O2_MYSQL_CHK:
		if (!done && s->check.bi->i < 5)
			goto wait_more_data;

		if (s->proxy->check_len == 0) { // old mode
			if (*(s->check.bi->data + 4) != '\xff') {
				/* We set the MySQL Version in description for information purpose
				 * FIXME : it can be cool to use MySQL Version for other purpose,
				 * like mark as down old MySQL server.
				 */
				if (s->check.bi->i > 51) {
					desc = ltrim(s->check.bi->data + 5, ' ');
					set_server_check_status(s, HCHK_STATUS_L7OKD, desc);
				}
				else {
					if (!done)
						goto wait_more_data;
					/* it seems we have a OK packet but without a valid length,
					 * it must be a protocol error
					 */
					set_server_check_status(s, HCHK_STATUS_L7RSP, s->check.bi->data);
				}
			}
			else {
				/* An error message is attached in the Error packet */
				desc = ltrim(s->check.bi->data + 7, ' ');
				set_server_check_status(s, HCHK_STATUS_L7STS, desc);
			}
		} else {
			unsigned int first_packet_len = ((unsigned int) *s->check.bi->data) +
			                                (((unsigned int) *(s->check.bi->data + 1)) << 8) +
			                                (((unsigned int) *(s->check.bi->data + 2)) << 16);

			if (s->check.bi->i == first_packet_len + 4) {
				/* MySQL Error packet always begin with field_count = 0xff */
				if (*(s->check.bi->data + 4) != '\xff') {
					/* We have only one MySQL packet and it is a Handshake Initialization packet
					* but we need to have a second packet to know if it is alright
					*/
					if (!done && s->check.bi->i < first_packet_len + 5)
						goto wait_more_data;
				}
				else {
					/* We have only one packet and it is an Error packet,
					* an error message is attached, so we can display it
					*/
					desc = &s->check.bi->data[7];
					//Warning("onlyoneERR: %s\n", desc);
					set_server_check_status(s, HCHK_STATUS_L7STS, desc);
				}
			} else if (s->check.bi->i > first_packet_len + 4) {
				unsigned int second_packet_len = ((unsigned int) *(s->check.bi->data + first_packet_len + 4)) +
				                                 (((unsigned int) *(s->check.bi->data + first_packet_len + 5)) << 8) +
				                                 (((unsigned int) *(s->check.bi->data + first_packet_len + 6)) << 16);

				if (s->check.bi->i == first_packet_len + 4 + second_packet_len + 4 ) {
					/* We have 2 packets and that's good */
					/* Check if the second packet is a MySQL Error packet or not */
					if (*(s->check.bi->data + first_packet_len + 8) != '\xff') {
						/* No error packet */
						/* We set the MySQL Version in description for information purpose */
						desc = &s->check.bi->data[5];
						//Warning("2packetOK: %s\n", desc);
						set_server_check_status(s, HCHK_STATUS_L7OKD, desc);
					}
					else {
						/* An error message is attached in the Error packet
						* so we can display it ! :)
						*/
						desc = &s->check.bi->data[first_packet_len+11];
						//Warning("2packetERR: %s\n", desc);
						set_server_check_status(s, HCHK_STATUS_L7STS, desc);
					}
				}
			}
			else {
				if (!done)
					goto wait_more_data;
				/* it seems we have a Handshake Initialization packet but without a valid length,
				 * it must be a protocol error
				 */
				desc = &s->check.bi->data[5];
				//Warning("protoerr: %s\n", desc);
				set_server_check_status(s, HCHK_STATUS_L7RSP, desc);
			}
		}
		break;

	case PR_O2_LDAP_CHK:
		if (!done && s->check.bi->i < 14)
			goto wait_more_data;

		/* Check if the server speaks LDAP (ASN.1/BER)
		 * http://en.wikipedia.org/wiki/Basic_Encoding_Rules
		 * http://tools.ietf.org/html/rfc4511
		 */

		/* http://tools.ietf.org/html/rfc4511#section-4.1.1
		 *   LDAPMessage: 0x30: SEQUENCE
		 */
		if ((s->check.bi->i < 14) || (*(s->check.bi->data) != '\x30')) {
			set_server_check_status(s, HCHK_STATUS_L7RSP, "Not LDAPv3 protocol");
		}
		else {
			 /* size of LDAPMessage */
			msglen = (*(s->check.bi->data + 1) & 0x80) ? (*(s->check.bi->data + 1) & 0x7f) : 0;

			/* http://tools.ietf.org/html/rfc4511#section-4.2.2
			 *   messageID: 0x02 0x01 0x01: INTEGER 1
			 *   protocolOp: 0x61: bindResponse
			 */
			if ((msglen > 2) ||
			    (memcmp(s->check.bi->data + 2 + msglen, "\x02\x01\x01\x61", 4) != 0)) {
				set_server_check_status(s, HCHK_STATUS_L7RSP, "Not LDAPv3 protocol");

				goto out_wakeup;
			}

			/* size of bindResponse */
			msglen += (*(s->check.bi->data + msglen + 6) & 0x80) ? (*(s->check.bi->data + msglen + 6) & 0x7f) : 0;

			/* http://tools.ietf.org/html/rfc4511#section-4.1.9
			 *   ldapResult: 0x0a 0x01: ENUMERATION
			 */
			if ((msglen > 4) ||
			    (memcmp(s->check.bi->data + 7 + msglen, "\x0a\x01", 2) != 0)) {
				set_server_check_status(s, HCHK_STATUS_L7RSP, "Not LDAPv3 protocol");

				goto out_wakeup;
			}

			/* http://tools.ietf.org/html/rfc4511#section-4.1.9
			 *   resultCode
			 */
			s->check.code = *(s->check.bi->data + msglen + 9);
			if (s->check.code) {
				set_server_check_status(s, HCHK_STATUS_L7STS, "See RFC: http://tools.ietf.org/html/rfc4511#section-4.1.9");
			} else {
				set_server_check_status(s, HCHK_STATUS_L7OKD, "Success");
			}
		}
		break;

	default:
		/* other checks are valid if the connection succeeded anyway */
		set_server_check_status(s, HCHK_STATUS_L4OK, NULL);
		break;
	} /* switch */

 out_wakeup:
	if (s->result & SRV_CHK_ERROR)
		conn->flags |= CO_FL_ERROR;

	/* Reset the check buffer... */
	*s->check.bi->data = '\0';
	s->check.bi->i = 0;

	/* Close the connection... */
	if (conn->xprt && conn->xprt->shutw)
		conn->xprt->shutw(conn, 0);
	if (!(conn->flags & (CO_FL_WAIT_L4_CONN|CO_FL_SOCK_WR_SH)))
		shutdown(conn->t.sock.fd, SHUT_RDWR);
	__conn_data_stop_recv(conn);
	task_wakeup(t, TASK_WOKEN_IO);
	return;

 wait_more_data:
	__conn_data_poll_recv(conn);
}

/*
 * This function is used only for server health-checks. It handles connection
 * status updates including errors. If necessary, it wakes the check task up.
 * It always returns 0.
 */
static int wake_srv_chk(struct connection *conn)
{
	struct server *s = conn->owner;

	if (unlikely(conn->flags & CO_FL_ERROR))
		task_wakeup(s->check.task, TASK_WOKEN_IO);

	return 0;
}

struct data_cb check_conn_cb = {
	.recv = event_srv_chk_r,
	.send = event_srv_chk_w,
	.wake = wake_srv_chk,
};

/*
 * updates the server's weight during a warmup stage. Once the final weight is
 * reached, the task automatically stops. Note that any server status change
 * must have updated s->last_change accordingly.
 */
static struct task *server_warmup(struct task *t)
{
	struct server *s = t->context;

	/* by default, plan on stopping the task */
	t->expire = TICK_ETERNITY;
	if ((s->state & (SRV_RUNNING|SRV_WARMINGUP|SRV_MAINTAIN)) != (SRV_RUNNING|SRV_WARMINGUP))
		return t;

	if (now.tv_sec < s->last_change || now.tv_sec >= s->last_change + s->slowstart) {
		/* go to full throttle if the slowstart interval is reached */
		s->state &= ~SRV_WARMINGUP;
		if (s->proxy->lbprm.algo & BE_LB_PROP_DYN)
			s->eweight = s->uweight * BE_WEIGHT_SCALE;
		if (s->proxy->lbprm.update_server_eweight)
			s->proxy->lbprm.update_server_eweight(s);
	}
	else if (s->proxy->lbprm.algo & BE_LB_PROP_DYN) {
		/* for dynamic algorithms, let's slowly update the weight */
		s->eweight = (BE_WEIGHT_SCALE * (now.tv_sec - s->last_change) +
			      s->slowstart - 1) / s->slowstart;
		s->eweight *= s->uweight;
		if (s->proxy->lbprm.update_server_eweight)
			s->proxy->lbprm.update_server_eweight(s);
	}
	/* Note that static algorithms are already running at full throttle */

	/* probably that we can refill this server with a bit more connections */
	check_for_pending(s);

	/* get back there in 1 second or 1/20th of the slowstart interval,
	 * whichever is greater, resulting in small 5% steps.
	 */
	if (s->state & SRV_WARMINGUP)
		t->expire = tick_add(now_ms, MS_TO_TICKS(MAX(1000, s->slowstart / 20)));
	return t;
}

/*
 * manages a server health-check. Returns
 * the time the task accepts to wait, or TIME_ETERNITY for infinity.
 */
static struct task *process_chk(struct task *t)
{
	int attempts = 0;
	struct server *s = t->context;
	struct connection *conn = s->check.conn;
	int fd;
	int rv;
	int ret;

 new_chk:
	if (attempts++ > 0) {
		/* we always fail to create a server, let's stop insisting... */
		while (tick_is_expired(t->expire, now_ms))
			t->expire = tick_add(t->expire, MS_TO_TICKS(s->inter));
		return t;
	}

	fd = conn->t.sock.fd;
	if (fd < 0) {   /* no check currently running */
		if (!tick_is_expired(t->expire, now_ms)) /* woke up too early */
			return t;

		/* we don't send any health-checks when the proxy is stopped or when
		 * the server should not be checked.
		 */
		if (!(s->state & SRV_CHECKED) || s->proxy->state == PR_STSTOPPED || (s->state & SRV_MAINTAIN)) {
			while (tick_is_expired(t->expire, now_ms))
				t->expire = tick_add(t->expire, MS_TO_TICKS(s->inter));
			return t;
		}

		/* we'll initiate a new check */
		set_server_check_status(s, HCHK_STATUS_START, NULL);

		s->check.bi->p = s->check.bi->data;
		s->check.bi->i = 0;
		s->check.bo->p = s->check.bo->data;
		s->check.bo->o = 0;

		/* prepare the check buffer */
		if (s->proxy->options2 & PR_O2_CHK_ANY) {
			bo_putblk(s->check.bo, s->proxy->check_req, s->proxy->check_len);

			/* we want to check if this host replies to HTTP or SSLv3 requests
			 * so we'll send the request, and won't wake the checker up now.
			 */
			if ((s->proxy->options2 & PR_O2_CHK_ANY) == PR_O2_SSL3_CHK) {
				/* SSL requires that we put Unix time in the request */
				int gmt_time = htonl(date.tv_sec);
				memcpy(s->check.bo->data + 11, &gmt_time, 4);
			}
			else if ((s->proxy->options2 & PR_O2_CHK_ANY) == PR_O2_HTTP_CHK) {
				if (s->proxy->options2 & PR_O2_CHK_SNDST)
					bo_putblk(s->check.bo, trash, httpchk_build_status_header(s, trash));
				bo_putstr(s->check.bo, "\r\n");
				*s->check.bo->p = '\0'; /* to make gdb output easier to read */
			}
		}

		/* prepare a new connection */
		set_target_server(&conn->target, s);
		conn_prepare(conn, &check_conn_cb, s->check.proto, s->check.xprt, s);

		if (is_addr(&s->check.addr))
			/* we'll connect to the check addr specified on the server */
			conn->addr.to = s->check.addr;
		else
			/* we'll connect to the addr on the server */
			conn->addr.to = s->addr;

		set_host_port(&conn->addr.to, s->check.port);

		/* It can return one of :
		 *  - SN_ERR_NONE if everything's OK
		 *  - SN_ERR_SRVTO if there are no more servers
		 *  - SN_ERR_SRVCL if the connection was refused by the server
		 *  - SN_ERR_PRXCOND if the connection has been limited by the proxy (maxconn)
		 *  - SN_ERR_RESOURCE if a system resource is lacking (eg: fd limits, ports, ...)
		 *  - SN_ERR_INTERNAL for any other purely internal errors
		 * Additionnally, in the case of SN_ERR_RESOURCE, an emergency log will be emitted.
		 */
		ret = s->check.proto->connect(conn, 1);
		conn->flags |= CO_FL_WAKE_DATA;
		if (s->check.send_proxy)
			conn->flags |= CO_FL_LOCAL_SPROXY;

		switch (ret) {
		case SN_ERR_NONE:
			break;
		case SN_ERR_SRVTO: /* ETIMEDOUT */
		case SN_ERR_SRVCL: /* ECONNREFUSED, ENETUNREACH, ... */
			set_server_check_status(s, HCHK_STATUS_L4CON, strerror(errno));
			break;
		case SN_ERR_PRXCOND:
		case SN_ERR_RESOURCE:
		case SN_ERR_INTERNAL:
			set_server_check_status(s, HCHK_STATUS_SOCKERR, NULL);
			break;
		}

		if (s->result == SRV_CHK_UNKNOWN) {
			/* connection attempt was started */

			/* we allow up to min(inter, timeout.connect) for a connection
			 * to establish but only when timeout.check is set
			 * as it may be to short for a full check otherwise
			 */
			t->expire = tick_add(now_ms, MS_TO_TICKS(s->inter));

			if (s->proxy->timeout.check && s->proxy->timeout.connect) {
				int t_con = tick_add(now_ms, s->proxy->timeout.connect);
				t->expire = tick_first(t->expire, t_con);
			}
			return t;
		}

		/* here, we have seen a failure */
		if (s->health > s->rise) {
			s->health--; /* still good */
			s->counters.failed_checks++;
		}
		else
			set_server_down(s);

		//fprintf(stderr, "process_chk: 7, %lu\n", __tv_to_ms(&s->proxy->timeout.connect));
		/* we allow up to min(inter, timeout.connect) for a connection
		 * to establish but only when timeout.check is set
		 * as it may be to short for a full check otherwise
		 */
		while (tick_is_expired(t->expire, now_ms)) {
			int t_con;

			t_con = tick_add(t->expire, s->proxy->timeout.connect);
			t->expire = tick_add(t->expire, MS_TO_TICKS(s->inter));

			if (s->proxy->timeout.check)
				t->expire = tick_first(t->expire, t_con);
		}
		goto new_chk;
	}
	else {
		/* there was a test running.
		 * First, let's check whether there was an uncaught error,
		 * which can happen on connect timeout or error.
		 */
		if (s->result == SRV_CHK_UNKNOWN) {
			if (conn->flags & CO_FL_CONNECTED) {
				/* good TCP connection is enough */
				if (s->check.use_ssl)
					set_server_check_status(s, HCHK_STATUS_L6OK, NULL);
				else
					set_server_check_status(s, HCHK_STATUS_L4OK, NULL);
			}
			else if (conn->flags & CO_FL_WAIT_L4_CONN) {
				/* L4 failed */
				if (conn->flags & CO_FL_ERROR)
					set_server_check_status(s, HCHK_STATUS_L4CON, NULL);
				else
					set_server_check_status(s, HCHK_STATUS_L4TOUT, NULL);
			}
			else if (conn->flags & CO_FL_WAIT_L6_CONN) {
				/* L6 failed */
				if (conn->flags & CO_FL_ERROR)
					set_server_check_status(s, HCHK_STATUS_L6RSP, NULL);
				else
					set_server_check_status(s, HCHK_STATUS_L6TOUT, NULL);
			}
		}

		if ((s->result & (SRV_CHK_ERROR|SRV_CHK_RUNNING)) == SRV_CHK_RUNNING) { /* good server detected */
			/* we may have to add/remove this server from the LB group */
			if ((s->state & SRV_RUNNING) && (s->proxy->options & PR_O_DISABLE404)) {
				if ((s->state & SRV_GOINGDOWN) &&
				    ((s->result & (SRV_CHK_RUNNING|SRV_CHK_DISABLE)) == SRV_CHK_RUNNING))
					set_server_enabled(s);
				else if (!(s->state & SRV_GOINGDOWN) &&
					 ((s->result & (SRV_CHK_RUNNING | SRV_CHK_DISABLE)) ==
					  (SRV_CHK_RUNNING | SRV_CHK_DISABLE)))
					set_server_disabled(s);
			}

			if (s->health < s->rise + s->fall - 1) {
				s->health++; /* was bad, stays for a while */

				set_server_up(s);
			}
			conn->t.sock.fd = -1; /* no check running anymore */
			conn_xprt_close(conn);
			if (conn->ctrl)
				fd_delete(fd);

			rv = 0;
			if (global.spread_checks > 0) {
				rv = srv_getinter(s) * global.spread_checks / 100;
				rv -= (int) (2 * rv * (rand() / (RAND_MAX + 1.0)));
			}
			t->expire = tick_add(now_ms, MS_TO_TICKS(srv_getinter(s) + rv));
			goto new_chk;
		}
		else if ((s->result & SRV_CHK_ERROR) || tick_is_expired(t->expire, now_ms)) {
			if (!(s->result & SRV_CHK_ERROR)) {
				if (conn->flags & CO_FL_WAIT_L4_CONN) {
					set_server_check_status(s, HCHK_STATUS_L4TOUT, NULL);
				} else {
					if ((s->proxy->options2 & PR_O2_CHK_ANY) == PR_O2_SSL3_CHK)
						set_server_check_status(s, HCHK_STATUS_L6TOUT, NULL);
					else	/* HTTP, SMTP */
						set_server_check_status(s, HCHK_STATUS_L7TOUT, NULL);
				}
			}

			/* failure or timeout detected */
			if (s->health > s->rise) {
				s->health--; /* still good */
				s->counters.failed_checks++;
			}
			else
				set_server_down(s);
			conn->t.sock.fd = -1;
			conn_xprt_close(conn);
			if (conn->ctrl)
				fd_delete(fd);

			rv = 0;
			if (global.spread_checks > 0) {
				rv = srv_getinter(s) * global.spread_checks / 100;
				rv -= (int) (2 * rv * (rand() / (RAND_MAX + 1.0)));
			}
			t->expire = tick_add(now_ms, MS_TO_TICKS(srv_getinter(s) + rv));
			goto new_chk;
		}
		/* if result is unknown and there's no timeout, we have to wait again */
	}
	s->result = SRV_CHK_UNKNOWN;
	return t;
}

/*
 * Start health-check.
 * Returns 0 if OK, -1 if error, and prints the error in this case.
 */
int start_checks() {

	struct proxy *px;
	struct server *s;
	struct task *t;
	int nbchk=0, mininter=0, srvpos=0;

	/* 1- count the checkers to run simultaneously.
	 * We also determine the minimum interval among all of those which
	 * have an interval larger than SRV_CHK_INTER_THRES. This interval
	 * will be used to spread their start-up date. Those which have
	 * a shorter interval will start independently and will not dictate
	 * too short an interval for all others.
	 */
	for (px = proxy; px; px = px->next) {
		for (s = px->srv; s; s = s->next) {
			if (!(s->state & SRV_CHECKED))
				continue;

			if ((srv_getinter(s) >= SRV_CHK_INTER_THRES) &&
			    (!mininter || mininter > srv_getinter(s)))
				mininter = srv_getinter(s);

			nbchk++;
		}
	}

	if (!nbchk)
		return 0;

	srand((unsigned)time(NULL));

	/*
	 * 2- start them as far as possible from each others. For this, we will
	 * start them after their interval set to the min interval divided by
	 * the number of servers, weighted by the server's position in the list.
	 */
	for (px = proxy; px; px = px->next) {
		for (s = px->srv; s; s = s->next) {
			if (s->slowstart) {
				if ((t = task_new()) == NULL) {
					Alert("Starting [%s:%s] check: out of memory.\n", px->id, s->id);
					return -1;
				}
				/* We need a warmup task that will be called when the server
				 * state switches from down to up.
				 */
				s->warmup = t;
				t->process = server_warmup;
				t->context = s;
				t->expire = TICK_ETERNITY;
			}

			if (!(s->state & SRV_CHECKED))
				continue;

			/* one task for the checks */
			if ((t = task_new()) == NULL) {
				Alert("Starting [%s:%s] check: out of memory.\n", px->id, s->id);
				return -1;
			}

			s->check.task = t;
			t->process = process_chk;
			t->context = s;

			/* check this every ms */
			t->expire = tick_add(now_ms,
					     MS_TO_TICKS(((mininter && mininter >= srv_getinter(s)) ?
							  mininter : srv_getinter(s)) * srvpos / nbchk));
			s->check.start = now;
			task_queue(t);

			srvpos++;
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
	static char status_msg[] = "HTTP status check returned code <000>";
	char status_code[] = "000";
	char *contentptr;
	int crlf;
	int ret;

	switch (s->proxy->options2 & PR_O2_EXP_TYPE) {
	case PR_O2_EXP_STS:
	case PR_O2_EXP_RSTS:
		memcpy(status_code, s->check.bi->data + 9, 3);
		memcpy(status_msg + strlen(status_msg) - 4, s->check.bi->data + 9, 3);

		if ((s->proxy->options2 & PR_O2_EXP_TYPE) == PR_O2_EXP_STS)
			ret = strncmp(s->proxy->expect_str, status_code, 3) == 0;
		else
			ret = regexec(s->proxy->expect_regex, status_code, MAX_MATCH, pmatch, 0) == 0;

		/* we necessarily have the response, so there are no partial failures */
		if (s->proxy->options2 & PR_O2_EXP_INV)
			ret = !ret;

		set_server_check_status(s, ret ? HCHK_STATUS_L7OKD : HCHK_STATUS_L7STS, status_msg);
		break;

	case PR_O2_EXP_STR:
	case PR_O2_EXP_RSTR:
		/* very simple response parser: ignore CR and only count consecutive LFs,
		 * stop with contentptr pointing to first char after the double CRLF or
		 * to '\0' if crlf < 2.
		 */
		crlf = 0;
		for (contentptr = s->check.bi->data; *contentptr; contentptr++) {
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

			set_server_check_status(s, HCHK_STATUS_L7RSP,
						"HTTP content check could not find a response body");
			return 1;
		}

		/* Check that response body is not empty... */
		if (*contentptr == '\0') {
			if (!done)
				return 0;

			set_server_check_status(s, HCHK_STATUS_L7RSP,
						"HTTP content check found empty response body");
			return 1;
		}

		/* Check the response content against the supplied string
		 * or regex... */
		if ((s->proxy->options2 & PR_O2_EXP_TYPE) == PR_O2_EXP_STR)
			ret = strstr(contentptr, s->proxy->expect_str) != NULL;
		else
			ret = regexec(s->proxy->expect_regex, contentptr, MAX_MATCH, pmatch, 0) == 0;

		/* if we don't match, we may need to wait more */
		if (!ret && !done)
			return 0;

		if (ret) {
			/* content matched */
			if (s->proxy->options2 & PR_O2_EXP_INV)
				set_server_check_status(s, HCHK_STATUS_L7RSP,
							"HTTP check matched unwanted content");
			else
				set_server_check_status(s, HCHK_STATUS_L7OKD,
							"HTTP content check matched");
		}
		else {
			if (s->proxy->options2 & PR_O2_EXP_INV)
				set_server_check_status(s, HCHK_STATUS_L7OKD,
							"HTTP check did not match unwanted content");
			else
				set_server_check_status(s, HCHK_STATUS_L7RSP,
							"HTTP content check did not match");
		}
		break;
	}
	return 1;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
