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

#include <common/compat.h>
#include <common/config.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/time.h>

#include <types/global.h>

#include <proto/backend.h>
#include <proto/checks.h>
#include <proto/buffers.h>
#include <proto/fd.h>
#include <proto/log.h>
#include <proto/queue.h>
#include <proto/port_range.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/proxy.h>
#include <proto/server.h>
#include <proto/task.h>

const struct check_status check_statuses[HCHK_STATUS_SIZE] = {
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

const struct analyze_status analyze_statuses[HANA_STATUS_SIZE] = {		/* 0: ignore, 1: error, 2: OK */
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

	if (s->tracked)
		chunk_printf(msg, " via %s/%s",
			s->tracked->proxy->id, s->tracked->id);

	if (options & SSP_O_HCHK) {
		chunk_printf(msg, ", reason: %s", get_check_status_description(s->check_status));

		if (s->check_status >= HCHK_STATUS_L57DATA)
			chunk_printf(msg, ", code: %d", s->check_code);

		if (*s->check_desc) {
			struct chunk src;

			chunk_printf(msg, ", info: \"");

			chunk_initlen(&src, s->check_desc, 0, strlen(s->check_desc));
			chunk_asciiencode(msg, &src, '"');

			chunk_printf(msg, "\"");
		}

		if (s->check_duration >= 0)
			chunk_printf(msg, ", check duration: %ldms", s->check_duration);
	}

	if (xferred > 0) {
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
 * Set s->check_status, update s->check_duration and fill s->result with
 * an adequate SRV_CHK_* value.
 *
 * Show information in logs about failed health check if server is UP
 * or succeeded health checks if server is DOWN.
 */
static void set_server_check_status(struct server *s, short status, char *desc) {

	struct chunk msg;

	if (status == HCHK_STATUS_START) {
		s->result = SRV_CHK_UNKNOWN;	/* no result yet */
		s->check_desc[0] = '\0';
		s->check_start = now;
		return;
	}

	if (!s->check_status)
		return;

	if (desc && *desc) {
		strncpy(s->check_desc, desc, HCHK_DESC_LEN-1);
		s->check_desc[HCHK_DESC_LEN-1] = '\0';
	} else
		s->check_desc[0] = '\0';

	s->check_status = status;
	if (check_statuses[status].result)
		s->result = check_statuses[status].result;

	if (status == HCHK_STATUS_HANA)
		s->check_duration = -1;
	else if (!tv_iszero(&s->check_start)) {
		/* set_server_check_status() may be called more than once */
		s->check_duration = tv_ms_elapsed(&s->check_start, &now);
		tv_zero(&s->check_start);
	}

	if (s->proxy->options2 & PR_O2_LOGHCHKS &&
	(((s->health != 0) && (s->result & SRV_CHK_ERROR)) ||
	    ((s->health != s->rise + s->fall - 1) && (s->result & SRV_CHK_RUNNING)) ||
	    ((s->state & SRV_GOINGDOWN) && !(s->result & SRV_CHK_DISABLE)) ||
	    (!(s->state & SRV_GOINGDOWN) && (s->result & SRV_CHK_DISABLE)))) {

		int health, rise, fall, state;

		chunk_init(&msg, trash, sizeof(trash));

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
		p->sess->srv = s;
		sess = p->sess;
		pendconn_free(p);
		task_wakeup(sess->task, TASK_WOKEN_RES);
	}
	return xferred;
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

	if (s->health == s->rise || s->tracked) {
		int srv_was_paused = s->state & SRV_GOINGDOWN;

		s->last_change = now.tv_sec;
		s->state &= ~(SRV_RUNNING | SRV_GOINGDOWN);
		s->proxy->lbprm.set_server_status_down(s);

		/* we might have sessions queued on this server and waiting for
		 * a connection. Those which are redispatchable will be queued
		 * to another server or to the proxy itself.
		 */
		xferred = redistribute_pending(s);

		chunk_init(&msg, trash, sizeof(trash));

		if (s->state & SRV_MAINTAIN) {
			chunk_printf(&msg,
				"%sServer %s/%s is DOWN for maintenance", s->state & SRV_BACKUP ? "Backup " : "",
				s->proxy->id, s->id);
		} else {
			chunk_printf(&msg,
				"%sServer %s/%s is DOWN", s->state & SRV_BACKUP ? "Backup " : "",
				s->proxy->id, s->id);

			server_status_printf(&msg, s,
						((!s->tracked && !(s->proxy->options2 & PR_O2_LOGHCHKS))?SSP_O_HCHK:0),
						xferred);
		}
		Warning("%s.\n", trash);

		/* we don't send an alert if the server was previously paused */
		if (srv_was_paused)
			send_log(s->proxy, LOG_NOTICE, "%s.\n", trash);
		else
			send_log(s->proxy, LOG_ALERT, "%s.\n", trash);

		if (s->proxy->srv_bck == 0 && s->proxy->srv_act == 0)
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

	if (s->state & SRV_MAINTAIN) {
		s->health = s->rise;
	}

	if (s->health == s->rise || s->tracked) {
		if (s->proxy->srv_bck == 0 && s->proxy->srv_act == 0) {
			if (s->proxy->last_change < now.tv_sec)		// ignore negative times
				s->proxy->down_time += now.tv_sec - s->proxy->last_change;
			s->proxy->last_change = now.tv_sec;
		}

		if (s->last_change < now.tv_sec)			// ignore negative times
			s->down_time += now.tv_sec - s->last_change;

		s->last_change = now.tv_sec;
		s->state |= SRV_RUNNING;

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
		}
		s->proxy->lbprm.set_server_status_up(s);

		/* check if we can handle some connections queued at the proxy. We
		 * will take as many as we can handle.
		 */
		xferred = check_for_pending(s);

		chunk_init(&msg, trash, sizeof(trash));

		if (s->state & SRV_MAINTAIN) {
			chunk_printf(&msg,
				"%sServer %s/%s is UP (leaving maintenance)", s->state & SRV_BACKUP ? "Backup " : "",
				s->proxy->id, s->id);
		} else {
			chunk_printf(&msg,
				"%sServer %s/%s is UP", s->state & SRV_BACKUP ? "Backup " : "",
				s->proxy->id, s->id);

			server_status_printf(&msg, s,
						((!s->tracked && !(s->proxy->options2 & PR_O2_LOGHCHKS))?SSP_O_HCHK:0),
						xferred);
		}

		Warning("%s.\n", trash);
		send_log(s->proxy, LOG_NOTICE, "%s.\n", trash);

		if (s->state & SRV_CHECKED)
			for(srv = s->tracknext; srv; srv = srv->tracknext)
				if (! (srv->state & SRV_MAINTAIN))
					/* Only notify tracking servers if they're not in maintenance. */
					set_server_up(srv);

		s->state &= ~SRV_MAINTAIN;
	}

	if (s->health >= s->rise)
		s->health = s->rise + s->fall - 1; /* OK now */

}

static void set_server_disabled(struct server *s) {

	struct server *srv;
	struct chunk msg;
	int xferred;

	s->state |= SRV_GOINGDOWN;
	s->proxy->lbprm.set_server_status_down(s);

	/* we might have sessions queued on this server and waiting for
	 * a connection. Those which are redispatchable will be queued
	 * to another server or to the proxy itself.
	 */
	xferred = redistribute_pending(s);

	chunk_init(&msg, trash, sizeof(trash));

	chunk_printf(&msg,
		"Load-balancing on %sServer %s/%s is disabled",
		s->state & SRV_BACKUP ? "Backup " : "",
		s->proxy->id, s->id);

	server_status_printf(&msg, s,
				((!s->tracked && !(s->proxy->options2 & PR_O2_LOGHCHKS))?SSP_O_HCHK:0),
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
	s->proxy->lbprm.set_server_status_up(s);

	/* check if we can handle some connections queued at the proxy. We
	 * will take as many as we can handle.
	 */
	xferred = check_for_pending(s);

	chunk_init(&msg, trash, sizeof(trash));

	chunk_printf(&msg,
		"Load-balancing on %sServer %s/%s is enabled again",
		s->state & SRV_BACKUP ? "Backup " : "",
		s->proxy->id, s->id);

	server_status_printf(&msg, s,
				((!s->tracked && !(s->proxy->options2 & PR_O2_LOGHCHKS))?SSP_O_HCHK:0),
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
	if (!s->observe || !s->check)
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
		if (s->check->expire > expire)
			s->check->expire = expire;
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
 * to set s->check_status, s->check_duration and s->result.
 * The function itself returns 0 if it needs some polling before being called
 * again, otherwise 1.
 */
static int event_srv_chk_w(int fd)
{
	__label__ out_wakeup, out_nowake, out_poll, out_error;
	struct task *t = fdtab[fd].owner;
	struct server *s = t->context;

	//fprintf(stderr, "event_srv_chk_w, state=%ld\n", unlikely(fdtab[fd].state));
	if (unlikely(fdtab[fd].state == FD_STERROR || (fdtab[fd].ev & FD_POLL_ERR))) {
		int skerr, err = errno;
		socklen_t lskerr = sizeof(skerr);

		if (!getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr) && skerr)
			err = skerr;

		set_server_check_status(s, HCHK_STATUS_L4CON, strerror(err));
		goto out_error;
	}

	/* here, we know that the connection is established */

	if (!(s->result & SRV_CHK_ERROR)) {
		/* we don't want to mark 'UP' a server on which we detected an error earlier */
		if ((s->proxy->options & PR_O_HTTP_CHK) ||
		    (s->proxy->options & PR_O_SSL3_CHK) ||
		    (s->proxy->options & PR_O_SMTP_CHK) ||
		    (s->proxy->options2 & PR_O2_MYSQL_CHK)) {
			int ret;
			const char *check_req = s->proxy->check_req;
			int check_len = s->proxy->check_len;

			/* we want to check if this host replies to HTTP or SSLv3 requests
			 * so we'll send the request, and won't wake the checker up now.
			 */

			if (s->proxy->options & PR_O_SSL3_CHK) {
				/* SSL requires that we put Unix time in the request */
				int gmt_time = htonl(date.tv_sec);
				memcpy(s->proxy->check_req + 11, &gmt_time, 4);
			}
			else if (s->proxy->options & PR_O_HTTP_CHK) {
				memcpy(trash, check_req, check_len);

				if (s->proxy->options2 & PR_O2_CHK_SNDST)
					check_len += httpchk_build_status_header(s, trash + check_len);

				trash[check_len++] = '\r';
				trash[check_len++] = '\n';
				trash[check_len] = '\0';
				check_req = trash;
			}

			ret = send(fd, check_req, check_len, MSG_DONTWAIT | MSG_NOSIGNAL);
			if (ret == check_len) {
				/* we allow up to <timeout.check> if nonzero for a responce */
				if (s->proxy->timeout.check)
					t->expire = tick_add_ifset(now_ms, s->proxy->timeout.check);
				EV_FD_SET(fd, DIR_RD);   /* prepare for reading reply */
				goto out_nowake;
			}
			else if (ret == 0 || errno == EAGAIN)
				goto out_poll;
			else {
				switch (errno) {
					case ECONNREFUSED:
					case ENETUNREACH:
						set_server_check_status(s, HCHK_STATUS_L4CON, strerror(errno));
						break;

					default:
						set_server_check_status(s, HCHK_STATUS_SOCKERR, strerror(errno));
				}

				goto out_error;
			}
		}
		else {
			/* We have no data to send to check the connection, and
			 * getsockopt() will not inform us whether the connection
			 * is still pending. So we'll reuse connect() to check the
			 * state of the socket. This has the advantage of givig us
			 * the following info :
			 *  - error
			 *  - connecting (EALREADY, EINPROGRESS)
			 *  - connected (EISCONN, 0)
			 */

			struct sockaddr_in sa;

			sa = (s->check_addr.sin_addr.s_addr) ? s->check_addr : s->addr;
			sa.sin_port = htons(s->check_port);

			if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0)
				errno = 0;

			if (errno == EALREADY || errno == EINPROGRESS)
				goto out_poll;

			if (errno && errno != EISCONN) {
				set_server_check_status(s, HCHK_STATUS_L4CON, strerror(errno));
				goto out_error;
			}

			/* good TCP connection is enough */
			set_server_check_status(s, HCHK_STATUS_L4OK, NULL);
			goto out_wakeup;
		}
	}
 out_wakeup:
	task_wakeup(t, TASK_WOKEN_IO);
 out_nowake:
	EV_FD_CLR(fd, DIR_WR);   /* nothing more to write */
	fdtab[fd].ev &= ~FD_POLL_OUT;
	return 1;
 out_poll:
	/* The connection is still pending. We'll have to poll it
	 * before attempting to go further. */
	fdtab[fd].ev &= ~FD_POLL_OUT;
	return 0;
 out_error:
	fdtab[fd].state = FD_STERROR;
	goto out_wakeup;
}


/*
 * This function is used only for server health-checks. It handles the server's
 * reply to an HTTP request or SSL HELLO. It calls set_server_check_status() to
 * update s->check_status, s->check_duration and s->result.

 * The set_server_check_status function is called with HCHK_STATUS_L7OKD if
 * an HTTP server replies HTTP 2xx or 3xx (valid responses), if an SMTP server
 * returns 2xx, HCHK_STATUS_L6OK if an SSL server returns at least 5 bytes in
 * response to an SSL HELLO (the principle is that this is enough to
 * distinguish between an SSL server and a pure TCP relay). All other cases will
 * call it with a proper error status like HCHK_STATUS_L7STS, HCHK_STATUS_L6RSP,
 * etc.
 *
 * The function returns 0 if it needs to be called again after some polling,
 * otherwise non-zero..
 */
static int event_srv_chk_r(int fd)
{
	__label__ out_wakeup;
	int len;
	struct task *t = fdtab[fd].owner;
	struct server *s = t->context;
	char *desc;

	len = -1;

	if (unlikely((s->result & SRV_CHK_ERROR) ||
		     (fdtab[fd].state == FD_STERROR) ||
		     (fdtab[fd].ev & FD_POLL_ERR))) {
		/* in case of TCP only, this tells us if the connection failed */
		if (!(s->result & SRV_CHK_ERROR))
			set_server_check_status(s, HCHK_STATUS_SOCKERR, NULL);

		goto out_wakeup;
	}

	/* Warning! Linux returns EAGAIN on SO_ERROR if data are still available
	 * but the connection was closed on the remote end. Fortunately, recv still
	 * works correctly and we don't need to do the getsockopt() on linux.
	 */
	len = recv(fd, trash, sizeof(trash), 0);
	if (unlikely(len < 0)) {
		if (errno == EAGAIN) {
			/* not ready, we want to poll first */
			fdtab[fd].ev &= ~FD_POLL_IN;
			return 0;
		}
		/* network error, report it */
		if (!(s->result & SRV_CHK_ERROR))
			set_server_check_status(s, HCHK_STATUS_SOCKERR, NULL);
		goto out_wakeup;
	}

	if (len < sizeof(trash))
		trash[len] = '\0';
	else
		trash[len-1] = '\0';

	/* Note: the response will only be accepted if read at once */
	if (s->proxy->options & PR_O_HTTP_CHK) {
		/* Check if the server speaks HTTP 1.X */
		if ((len < strlen("HTTP/1.0 000\r")) ||
		    (memcmp(trash, "HTTP/1.", 7) != 0 ||
		    (trash[12] != ' ' && trash[12] != '\r')) ||
		    !isdigit((unsigned char)trash[9]) || !isdigit((unsigned char)trash[10]) ||
		    !isdigit((unsigned char)trash[11])) {

			cut_crlf(trash);
			set_server_check_status(s, HCHK_STATUS_L7RSP, trash);

			goto out_wakeup;
		}

		s->check_code = str2uic(&trash[9]);

		desc = ltrim(&trash[12], ' ');
		cut_crlf(desc);

		/* check the reply : HTTP/1.X 2xx and 3xx are OK */
		if (trash[9] == '2' || trash[9] == '3')
			set_server_check_status(s, HCHK_STATUS_L7OKD, desc);
		else if ((s->proxy->options & PR_O_DISABLE404) &&
			 (s->state & SRV_RUNNING) &&
			 (s->check_code == 404))
		/* 404 may be accepted as "stopping" only if the server was up */
			set_server_check_status(s, HCHK_STATUS_L7OKCD, desc);
		else
			set_server_check_status(s, HCHK_STATUS_L7STS, desc);
	}
	else if (s->proxy->options & PR_O_SSL3_CHK) {
		/* Check for SSLv3 alert or handshake */
		if ((len >= 5) && (trash[0] == 0x15 || trash[0] == 0x16))
			set_server_check_status(s, HCHK_STATUS_L6OK, NULL);
		else
			set_server_check_status(s, HCHK_STATUS_L6RSP, NULL);
	}
	else if (s->proxy->options & PR_O_SMTP_CHK) {
		/* Check if the server speaks SMTP */
		if ((len < strlen("000\r")) ||
		    (trash[3] != ' ' && trash[3] != '\r') ||
		    !isdigit((unsigned char)trash[0]) || !isdigit((unsigned char)trash[1]) ||
		    !isdigit((unsigned char)trash[2])) {

			cut_crlf(trash);
			set_server_check_status(s, HCHK_STATUS_L7RSP, trash);

			goto out_wakeup;
		}

		s->check_code = str2uic(&trash[0]);

		desc = ltrim(&trash[3], ' ');
		cut_crlf(desc);

		/* Check for SMTP code 2xx (should be 250) */
		if (trash[0] == '2')
			set_server_check_status(s, HCHK_STATUS_L7OKD, desc);
		else
			set_server_check_status(s, HCHK_STATUS_L7STS, desc);
	}
	else if (s->proxy->options2 & PR_O2_MYSQL_CHK) {
		/* MySQL Error packet always begin with field_count = 0xff
		 * contrary to OK Packet who always begin whith 0x00 */
		if (trash[4] != '\xff') {
			/* We set the MySQL Version in description for information purpose
			 * FIXME : it can be cool to use MySQL Version for other purpose,
			 * like mark as down old MySQL server.
			 */
			if (len > 51) {
				desc = ltrim(&trash[5], ' ');
				set_server_check_status(s, HCHK_STATUS_L7OKD, desc);
			}
			else {
				/* it seems we have a OK packet but without a valid length,
				 * it must be a protocol error
				 */
				set_server_check_status(s, HCHK_STATUS_L7RSP, trash);
			}
		}
		else {
			/* An error message is attached in the Error packet,
			 * so we can display it ! :)
			 */
			desc = ltrim(&trash[7], ' ');
			set_server_check_status(s, HCHK_STATUS_L7STS, desc);
		}
	}
	else {
		/* other checks are valid if the connection succeeded anyway */
		set_server_check_status(s, HCHK_STATUS_L4OK, NULL);
	}

 out_wakeup:
	if (s->result & SRV_CHK_ERROR)
		fdtab[fd].state = FD_STERROR;

	EV_FD_CLR(fd, DIR_RD);
	task_wakeup(t, TASK_WOKEN_IO);
	fdtab[fd].ev &= ~FD_POLL_IN;
	return 1;
}

/*
 * manages a server health-check. Returns
 * the time the task accepts to wait, or TIME_ETERNITY for infinity.
 */
struct task *process_chk(struct task *t)
{
	int attempts = 0;
	struct server *s = t->context;
	struct sockaddr_in sa;
	int fd;
	int rv;

	//fprintf(stderr, "process_chk: task=%p\n", t);

 new_chk:
	if (attempts++ > 0) {
		/* we always fail to create a server, let's stop insisting... */
		while (tick_is_expired(t->expire, now_ms))
			t->expire = tick_add(t->expire, MS_TO_TICKS(s->inter));
		return t;
	}
	fd = s->curfd;
	if (fd < 0) {   /* no check currently running */
		//fprintf(stderr, "process_chk: 2\n");
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
		if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != -1) {
			if ((fd < global.maxsock) &&
			    (fcntl(fd, F_SETFL, O_NONBLOCK) != -1) &&
			    (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &one, sizeof(one)) != -1)) {
				//fprintf(stderr, "process_chk: 3\n");

				if (s->proxy->options & PR_O_TCP_NOLING) {
					/* We don't want to useless data */
					setsockopt(fd, SOL_SOCKET, SO_LINGER, (struct linger *) &nolinger, sizeof(struct linger));
				}
				
				if (s->check_addr.sin_addr.s_addr)
					/* we'll connect to the check addr specified on the server */
					sa = s->check_addr;
				else
					/* we'll connect to the addr on the server */
					sa = s->addr;

				/* we'll connect to the check port on the server */
				sa.sin_port = htons(s->check_port);

				/* allow specific binding :
				 * - server-specific at first
				 * - proxy-specific next
				 */
				if (s->state & SRV_BIND_SRC) {
					struct sockaddr_in *remote = NULL;
					int ret, flags = 0;

#if defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_LINUX_TPROXY)
					if ((s->state & SRV_TPROXY_MASK) == SRV_TPROXY_ADDR) {
						remote = (struct sockaddr_in *)&s->tproxy_addr;
						flags  = 3;
					}
#endif
#ifdef SO_BINDTODEVICE
					/* Note: this might fail if not CAP_NET_RAW */
					if (s->iface_name)
						setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
							   s->iface_name, s->iface_len + 1);
#endif
					if (s->sport_range) {
						int bind_attempts = 10; /* should be more than enough to find a spare port */
						struct sockaddr_in src;

						ret = 1;
						src = s->source_addr;

						do {
							/* note: in case of retry, we may have to release a previously
							 * allocated port, hence this loop's construct.
							 */
							port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
							fdinfo[fd].port_range = NULL;

							if (!bind_attempts)
								break;
							bind_attempts--;

							fdinfo[fd].local_port = port_range_alloc_port(s->sport_range);
							if (!fdinfo[fd].local_port)
								break;

							fdinfo[fd].port_range = s->sport_range;
							src.sin_port = htons(fdinfo[fd].local_port);

							ret = tcpv4_bind_socket(fd, flags, &src, remote);
						} while (ret != 0); /* binding NOK */
					}
					else {
						ret = tcpv4_bind_socket(fd, flags, &s->source_addr, remote);
					}

					if (ret) {
						set_server_check_status(s, HCHK_STATUS_SOCKERR, NULL);
						switch (ret) {
						case 1:
							Alert("Cannot bind to source address before connect() for server %s/%s. Aborting.\n",
							      s->proxy->id, s->id);
							break;
						case 2:
							Alert("Cannot bind to tproxy source address before connect() for server %s/%s. Aborting.\n",
							      s->proxy->id, s->id);
							break;
						}
					}
				}
				else if (s->proxy->options & PR_O_BIND_SRC) {
					struct sockaddr_in *remote = NULL;
					int ret, flags = 0;

#if defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_LINUX_TPROXY)
					if ((s->proxy->options & PR_O_TPXY_MASK) == PR_O_TPXY_ADDR) {
						remote = (struct sockaddr_in *)&s->proxy->tproxy_addr;
						flags  = 3;
					}
#endif
#ifdef SO_BINDTODEVICE
					/* Note: this might fail if not CAP_NET_RAW */
					if (s->proxy->iface_name)
						setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
							   s->proxy->iface_name, s->proxy->iface_len + 1);
#endif
					ret = tcpv4_bind_socket(fd, flags, &s->proxy->source_addr, remote);
					if (ret) {
						set_server_check_status(s, HCHK_STATUS_SOCKERR, NULL);
						switch (ret) {
						case 1:
							Alert("Cannot bind to source address before connect() for %s '%s'. Aborting.\n",
							      proxy_type_str(s->proxy), s->proxy->id);
							break;
						case 2:
							Alert("Cannot bind to tproxy source address before connect() for %s '%s'. Aborting.\n",
							      proxy_type_str(s->proxy), s->proxy->id);
							break;
						}
					}
				}

				if (s->result == SRV_CHK_UNKNOWN) {
#if defined(TCP_QUICKACK)
					/* disabling tcp quick ack now allows
					 * the request to leave the machine with
					 * the first ACK.
					 */
					if (s->proxy->options2 & PR_O2_SMARTCON)
						setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, (char *) &zero, sizeof(zero));
#endif
					if ((connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != -1) || (errno == EINPROGRESS)) {
						/* OK, connection in progress or established */
			
						//fprintf(stderr, "process_chk: 4\n");
			
						s->curfd = fd; /* that's how we know a test is in progress ;-) */
						fd_insert(fd);
						fdtab[fd].owner = t;
						fdtab[fd].cb[DIR_RD].f = &event_srv_chk_r;
						fdtab[fd].cb[DIR_RD].b = NULL;
						fdtab[fd].cb[DIR_WR].f = &event_srv_chk_w;
						fdtab[fd].cb[DIR_WR].b = NULL;
						fdinfo[fd].peeraddr = (struct sockaddr *)&sa;
						fdinfo[fd].peerlen = sizeof(sa);
						fdtab[fd].state = FD_STCONN; /* connection in progress */
						fdtab[fd].flags = FD_FL_TCP | FD_FL_TCP_NODELAY;
						EV_FD_SET(fd, DIR_WR);  /* for connect status */
#ifdef DEBUG_FULL
						assert (!EV_FD_ISSET(fd, DIR_RD));
#endif
						//fprintf(stderr, "process_chk: 4+, %lu\n", __tv_to_ms(&s->proxy->timeout.connect));
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
					else if (errno != EALREADY && errno != EISCONN && errno != EAGAIN) {
						/* a real error */

						switch (errno) {
							/* FIXME: is it possible to get ECONNREFUSED/ENETUNREACH with O_NONBLOCK? */
							case ECONNREFUSED:
							case ENETUNREACH:
								set_server_check_status(s, HCHK_STATUS_L4CON, strerror(errno));
								break;

							default:
								set_server_check_status(s, HCHK_STATUS_SOCKERR, strerror(errno));
						}
					}
				}
			}
			port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
			fdinfo[fd].port_range = NULL;
			close(fd); /* socket creation error */
		}

		if (s->result == SRV_CHK_UNKNOWN) { /* nothing done */
			//fprintf(stderr, "process_chk: 6\n");
			while (tick_is_expired(t->expire, now_ms))
				t->expire = tick_add(t->expire, MS_TO_TICKS(s->inter));
			goto new_chk; /* may be we should initialize a new check */
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
		//fprintf(stderr, "process_chk: 8\n");
		/* there was a test running */
		if ((s->result & (SRV_CHK_ERROR|SRV_CHK_RUNNING)) == SRV_CHK_RUNNING) { /* good server detected */
			//fprintf(stderr, "process_chk: 9\n");

			if (s->state & SRV_WARMINGUP) {
				if (now.tv_sec < s->last_change || now.tv_sec >= s->last_change + s->slowstart) {
					s->state &= ~SRV_WARMINGUP;
					if (s->proxy->lbprm.algo & BE_LB_PROP_DYN)
						s->eweight = s->uweight * BE_WEIGHT_SCALE;
					if (s->proxy->lbprm.update_server_eweight)
						s->proxy->lbprm.update_server_eweight(s);
				}
				else if (s->proxy->lbprm.algo & BE_LB_PROP_DYN) {
					/* for dynamic algorithms, let's update the weight */
					s->eweight = (BE_WEIGHT_SCALE * (now.tv_sec - s->last_change) +
						      s->slowstart - 1) / s->slowstart;
					s->eweight *= s->uweight;
					if (s->proxy->lbprm.update_server_eweight)
						s->proxy->lbprm.update_server_eweight(s);
				}
				/* probably that we can refill this server with a bit more connections */
				check_for_pending(s);
			}

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
			s->curfd = -1; /* no check running anymore */
			fd_delete(fd);

			rv = 0;
			if (global.spread_checks > 0) {
				rv = srv_getinter(s) * global.spread_checks / 100;
				rv -= (int) (2 * rv * (rand() / (RAND_MAX + 1.0)));
				//fprintf(stderr, "process_chk(%p): (%d+/-%d%%) random=%d\n", s, srv_getinter(s), global.spread_checks, rv);
			}
			t->expire = tick_add(now_ms, MS_TO_TICKS(srv_getinter(s) + rv));
			goto new_chk;
		}
		else if ((s->result & SRV_CHK_ERROR) || tick_is_expired(t->expire, now_ms)) {
			if (!(s->result & SRV_CHK_ERROR)) {
				if (!EV_FD_ISSET(fd, DIR_RD)) {
					set_server_check_status(s, HCHK_STATUS_L4TOUT, NULL);
				} else {
					if (s->proxy->options & PR_O_SSL3_CHK)
						set_server_check_status(s, HCHK_STATUS_L6TOUT, NULL);
					else	/* HTTP, SMTP */
						set_server_check_status(s, HCHK_STATUS_L7TOUT, NULL);
				}
			}

			//fprintf(stderr, "process_chk: 10\n");
			/* failure or timeout detected */
			if (s->health > s->rise) {
				s->health--; /* still good */
				s->counters.failed_checks++;
			}
			else
				set_server_down(s);
			s->curfd = -1;
			fd_delete(fd);

			rv = 0;
			if (global.spread_checks > 0) {
				rv = srv_getinter(s) * global.spread_checks / 100;
				rv -= (int) (2 * rv * (rand() / (RAND_MAX + 1.0)));
				//fprintf(stderr, "process_chk(%p): (%d+/-%d%%) random=%d\n", s, srv_getinter(s), global.spread_checks, rv);
			}
			t->expire = tick_add(now_ms, MS_TO_TICKS(srv_getinter(s) + rv));
			goto new_chk;
		}
		/* if result is unknown and there's no timeout, we have to wait again */
	}
	//fprintf(stderr, "process_chk: 11\n");
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
	 * a shorter interval will start independantly and will not dictate
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
			if (!(s->state & SRV_CHECKED))
				continue;

			if ((t = task_new()) == NULL) {
				Alert("Starting [%s:%s] check: out of memory.\n", px->id, s->id);
				return -1;
			}

			s->check = t;
			t->process = process_chk;
			t->context = s;

			/* check this every ms */
			t->expire = tick_add(now_ms,
					     MS_TO_TICKS(((mininter && mininter >= srv_getinter(s)) ?
							  mininter : srv_getinter(s)) * srvpos / nbchk));
			s->check_start = now;
			task_queue(t);

			srvpos++;
		}
	}
	return 0;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
