/*
 * Server management functions.
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 * Copyright 2007-2008 Krzysztof Piotr Oledzki <ole@ans.pl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>

#include <common/cfgparse.h>
#include <common/config.h>
#include <common/errors.h>
#include <common/namespace.h>
#include <common/time.h>

#include <types/global.h>
#include <types/dns.h>

#include <proto/checks.h>
#include <proto/port_range.h>
#include <proto/protocol.h>
#include <proto/queue.h>
#include <proto/raw_sock.h>
#include <proto/server.h>
#include <proto/stream.h>
#include <proto/task.h>
#include <proto/dns.h>


/* List head of all known server keywords */
static struct srv_kw_list srv_keywords = {
	.list = LIST_HEAD_INIT(srv_keywords.list)
};

int srv_downtime(const struct server *s)
{
	if ((s->state != SRV_ST_STOPPED) && s->last_change < now.tv_sec)		// ignore negative time
		return s->down_time;

	return now.tv_sec - s->last_change + s->down_time;
}

int srv_lastsession(const struct server *s)
{
	if (s->counters.last_sess)
		return now.tv_sec - s->counters.last_sess;

	return -1;
}

int srv_getinter(const struct check *check)
{
	const struct server *s = check->server;

	if ((check->state & CHK_ST_CONFIGURED) && (check->health == check->rise + check->fall - 1))
		return check->inter;

	if ((s->state == SRV_ST_STOPPED) && check->health == 0)
		return (check->downinter)?(check->downinter):(check->inter);

	return (check->fastinter)?(check->fastinter):(check->inter);
}

/*
 * Registers the server keyword list <kwl> as a list of valid keywords for next
 * parsing sessions.
 */
void srv_register_keywords(struct srv_kw_list *kwl)
{
	LIST_ADDQ(&srv_keywords.list, &kwl->list);
}

/* Return a pointer to the server keyword <kw>, or NULL if not found. If the
 * keyword is found with a NULL ->parse() function, then an attempt is made to
 * find one with a valid ->parse() function. This way it is possible to declare
 * platform-dependant, known keywords as NULL, then only declare them as valid
 * if some options are met. Note that if the requested keyword contains an
 * opening parenthesis, everything from this point is ignored.
 */
struct srv_kw *srv_find_kw(const char *kw)
{
	int index;
	const char *kwend;
	struct srv_kw_list *kwl;
	struct srv_kw *ret = NULL;

	kwend = strchr(kw, '(');
	if (!kwend)
		kwend = kw + strlen(kw);

	list_for_each_entry(kwl, &srv_keywords.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if ((strncmp(kwl->kw[index].kw, kw, kwend - kw) == 0) &&
			    kwl->kw[index].kw[kwend-kw] == 0) {
				if (kwl->kw[index].parse)
					return &kwl->kw[index]; /* found it !*/
				else
					ret = &kwl->kw[index];  /* may be OK */
			}
		}
	}
	return ret;
}

/* Dumps all registered "server" keywords to the <out> string pointer. The
 * unsupported keywords are only dumped if their supported form was not
 * found.
 */
void srv_dump_kws(char **out)
{
	struct srv_kw_list *kwl;
	int index;

	*out = NULL;
	list_for_each_entry(kwl, &srv_keywords.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if (kwl->kw[index].parse ||
			    srv_find_kw(kwl->kw[index].kw) == &kwl->kw[index]) {
				memprintf(out, "%s[%4s] %s%s%s%s\n", *out ? *out : "",
				          kwl->scope,
				          kwl->kw[index].kw,
				          kwl->kw[index].skip ? " <arg>" : "",
				          kwl->kw[index].default_ok ? " [dflt_ok]" : "",
				          kwl->kw[index].parse ? "" : " (not supported)");
			}
		}
	}
}

/* parse the "id" server keyword */
static int srv_parse_id(char **args, int *cur_arg, struct proxy *curproxy, struct server *newsrv, char **err)
{
	struct eb32_node *node;

	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : expects an integer argument", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	newsrv->puid = atol(args[*cur_arg + 1]);
	newsrv->conf.id.key = newsrv->puid;

	if (newsrv->puid <= 0) {
		memprintf(err, "'%s' : custom id has to be > 0", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	node = eb32_lookup(&curproxy->conf.used_server_id, newsrv->puid);
	if (node) {
		struct server *target = container_of(node, struct server, conf.id);
		memprintf(err, "'%s' : custom id %d already used at %s:%d ('server %s')",
		          args[*cur_arg], newsrv->puid, target->conf.file, target->conf.line,
		          target->id);
		return ERR_ALERT | ERR_FATAL;
	}

	eb32_insert(&curproxy->conf.used_server_id, &newsrv->conf.id);
	return 0;
}

/* Shutdown all connections of a server. The caller must pass a termination
 * code in <why>, which must be one of SF_ERR_* indicating the reason for the
 * shutdown.
 */
void srv_shutdown_streams(struct server *srv, int why)
{
	struct stream *stream, *stream_bck;

	list_for_each_entry_safe(stream, stream_bck, &srv->actconns, by_srv)
		if (stream->srv_conn == srv)
			stream_shutdown(stream, why);
}

/* Shutdown all connections of all backup servers of a proxy. The caller must
 * pass a termination code in <why>, which must be one of SF_ERR_* indicating
 * the reason for the shutdown.
 */
void srv_shutdown_backup_streams(struct proxy *px, int why)
{
	struct server *srv;

	for (srv = px->srv; srv != NULL; srv = srv->next)
		if (srv->flags & SRV_F_BACKUP)
			srv_shutdown_streams(srv, why);
}

/* Appends some information to a message string related to a server going UP or
 * DOWN.  If both <forced> and <reason> are null and the server tracks another
 * one, a "via" information will be provided to know where the status came from.
 * If <reason> is non-null, the entire string will be appended after a comma and
 * a space (eg: to report some information from the check that changed the state).
 * If <xferred> is non-negative, some information about requeued streams are
 * provided.
 */
void srv_append_status(struct chunk *msg, struct server *s, const char *reason, int xferred, int forced)
{
	if (reason)
		chunk_appendf(msg, ", %s", reason);
	else if (!forced && s->track)
		chunk_appendf(msg, " via %s/%s", s->track->proxy->id, s->track->id);

	if (xferred >= 0) {
		if (s->state == SRV_ST_STOPPED)
			chunk_appendf(msg, ". %d active and %d backup servers left.%s"
				" %d sessions active, %d requeued, %d remaining in queue",
				s->proxy->srv_act, s->proxy->srv_bck,
				(s->proxy->srv_bck && !s->proxy->srv_act) ? " Running on backup." : "",
				s->cur_sess, xferred, s->nbpend);
		else
			chunk_appendf(msg, ". %d active and %d backup servers online.%s"
				" %d sessions requeued, %d total in queue",
				s->proxy->srv_act, s->proxy->srv_bck,
				(s->proxy->srv_bck && !s->proxy->srv_act) ? " Running on backup." : "",
				xferred, s->nbpend);
	}
}

/* Marks server <s> down, regardless of its checks' statuses, notifies by all
 * available means, recounts the remaining servers on the proxy and transfers
 * queued streams whenever possible to other servers. It automatically
 * recomputes the number of servers, but not the map. Maintenance servers are
 * ignored. It reports <reason> if non-null as the reason for going down. Note
 * that it makes use of the trash to build the log strings, so <reason> must
 * not be placed there.
 */
void srv_set_stopped(struct server *s, const char *reason)
{
	struct server *srv;
	int prev_srv_count = s->proxy->srv_bck + s->proxy->srv_act;
	int srv_was_stopping = (s->state == SRV_ST_STOPPING);
	int log_level;
	int xferred;

	if ((s->admin & SRV_ADMF_MAINT) || s->state == SRV_ST_STOPPED)
		return;

	s->last_change = now.tv_sec;
	s->state = SRV_ST_STOPPED;
	if (s->proxy->lbprm.set_server_status_down)
		s->proxy->lbprm.set_server_status_down(s);

	if (s->onmarkeddown & HANA_ONMARKEDDOWN_SHUTDOWNSESSIONS)
		srv_shutdown_streams(s, SF_ERR_DOWN);

	/* we might have streams queued on this server and waiting for
	 * a connection. Those which are redispatchable will be queued
	 * to another server or to the proxy itself.
	 */
	xferred = pendconn_redistribute(s);

	chunk_printf(&trash,
	             "%sServer %s/%s is DOWN", s->flags & SRV_F_BACKUP ? "Backup " : "",
	             s->proxy->id, s->id);

	srv_append_status(&trash, s, reason, xferred, 0);
	Warning("%s.\n", trash.str);

	/* we don't send an alert if the server was previously paused */
	log_level = srv_was_stopping ? LOG_NOTICE : LOG_ALERT;
	send_log(s->proxy, log_level, "%s.\n", trash.str);
	send_email_alert(s, log_level, "%s", trash.str);

	if (prev_srv_count && s->proxy->srv_bck == 0 && s->proxy->srv_act == 0)
		set_backend_down(s->proxy);

	s->counters.down_trans++;

	for (srv = s->trackers; srv; srv = srv->tracknext)
		srv_set_stopped(srv, NULL);
}

/* Marks server <s> up regardless of its checks' statuses and provided it isn't
 * in maintenance. Notifies by all available means, recounts the remaining
 * servers on the proxy and tries to grab requests from the proxy. It
 * automatically recomputes the number of servers, but not the map. Maintenance
 * servers are ignored. It reports <reason> if non-null as the reason for going
 * up. Note that it makes use of the trash to build the log strings, so <reason>
 * must not be placed there.
 */
void srv_set_running(struct server *s, const char *reason)
{
	struct server *srv;
	int xferred;

	if (s->admin & SRV_ADMF_MAINT)
		return;

	if (s->state == SRV_ST_STARTING || s->state == SRV_ST_RUNNING)
		return;

	if (s->proxy->srv_bck == 0 && s->proxy->srv_act == 0) {
		if (s->proxy->last_change < now.tv_sec)		// ignore negative times
			s->proxy->down_time += now.tv_sec - s->proxy->last_change;
		s->proxy->last_change = now.tv_sec;
	}

	if (s->state == SRV_ST_STOPPED && s->last_change < now.tv_sec)	// ignore negative times
		s->down_time += now.tv_sec - s->last_change;

	s->last_change = now.tv_sec;

	s->state = SRV_ST_STARTING;
	if (s->slowstart > 0)
		task_schedule(s->warmup, tick_add(now_ms, MS_TO_TICKS(MAX(1000, s->slowstart / 20))));
	else
		s->state = SRV_ST_RUNNING;

	server_recalc_eweight(s);

	/* If the server is set with "on-marked-up shutdown-backup-sessions",
	 * and it's not a backup server and its effective weight is > 0,
	 * then it can accept new connections, so we shut down all streams
	 * on all backup servers.
	 */
	if ((s->onmarkedup & HANA_ONMARKEDUP_SHUTDOWNBACKUPSESSIONS) &&
	    !(s->flags & SRV_F_BACKUP) && s->eweight)
		srv_shutdown_backup_streams(s->proxy, SF_ERR_UP);

	/* check if we can handle some connections queued at the proxy. We
	 * will take as many as we can handle.
	 */
	xferred = pendconn_grab_from_px(s);

	chunk_printf(&trash,
	             "%sServer %s/%s is UP", s->flags & SRV_F_BACKUP ? "Backup " : "",
	             s->proxy->id, s->id);

	srv_append_status(&trash, s, reason, xferred, 0);
	Warning("%s.\n", trash.str);
	send_log(s->proxy, LOG_NOTICE, "%s.\n", trash.str);
	send_email_alert(s, LOG_NOTICE, "%s", trash.str);

	for (srv = s->trackers; srv; srv = srv->tracknext)
		srv_set_running(srv, NULL);
}

/* Marks server <s> stopping regardless of its checks' statuses and provided it
 * isn't in maintenance. Notifies by all available means, recounts the remaining
 * servers on the proxy and tries to grab requests from the proxy. It
 * automatically recomputes the number of servers, but not the map. Maintenance
 * servers are ignored. It reports <reason> if non-null as the reason for going
 * up. Note that it makes use of the trash to build the log strings, so <reason>
 * must not be placed there.
 */
void srv_set_stopping(struct server *s, const char *reason)
{
	struct server *srv;
	int xferred;

	if (s->admin & SRV_ADMF_MAINT)
		return;

	if (s->state == SRV_ST_STOPPING)
		return;

	s->last_change = now.tv_sec;
	s->state = SRV_ST_STOPPING;
	if (s->proxy->lbprm.set_server_status_down)
		s->proxy->lbprm.set_server_status_down(s);

	/* we might have streams queued on this server and waiting for
	 * a connection. Those which are redispatchable will be queued
	 * to another server or to the proxy itself.
	 */
	xferred = pendconn_redistribute(s);

	chunk_printf(&trash,
	             "%sServer %s/%s is stopping", s->flags & SRV_F_BACKUP ? "Backup " : "",
	             s->proxy->id, s->id);

	srv_append_status(&trash, s, reason, xferred, 0);

	Warning("%s.\n", trash.str);
	send_log(s->proxy, LOG_NOTICE, "%s.\n", trash.str);

	if (!s->proxy->srv_bck && !s->proxy->srv_act)
		set_backend_down(s->proxy);

	for (srv = s->trackers; srv; srv = srv->tracknext)
		srv_set_stopping(srv, NULL);
}

/* Enables admin flag <mode> (among SRV_ADMF_*) on server <s>. This is used to
 * enforce either maint mode or drain mode. It is not allowed to set more than
 * one flag at once. The equivalent "inherited" flag is propagated to all
 * tracking servers. Maintenance mode disables health checks (but not agent
 * checks). When either the flag is already set or no flag is passed, nothing
 * is done.
 */
void srv_set_admin_flag(struct server *s, enum srv_admin mode)
{
	struct check *check = &s->check;
	struct server *srv;
	int xferred;

	if (!mode)
		return;

	/* stop going down as soon as we meet a server already in the same state */
	if (s->admin & mode)
		return;

	s->admin |= mode;

	/* stop going down if the equivalent flag was already present (forced or inherited) */
	if (((mode & SRV_ADMF_MAINT) && (s->admin & ~mode & SRV_ADMF_MAINT)) ||
	    ((mode & SRV_ADMF_DRAIN) && (s->admin & ~mode & SRV_ADMF_DRAIN)))
		return;

	/* Maintenance must also disable health checks */
	if (mode & SRV_ADMF_MAINT) {
		if (s->check.state & CHK_ST_ENABLED) {
			s->check.state |= CHK_ST_PAUSED;
			check->health = 0;
		}

		if (s->state == SRV_ST_STOPPED) {	/* server was already down */
			chunk_printf(&trash,
			             "%sServer %s/%s was DOWN and now enters maintenance",
			             s->flags & SRV_F_BACKUP ? "Backup " : "", s->proxy->id, s->id);

			srv_append_status(&trash, s, NULL, -1, (mode & SRV_ADMF_FMAINT));

			Warning("%s.\n", trash.str);
			send_log(s->proxy, LOG_NOTICE, "%s.\n", trash.str);
		}
		else {	/* server was still running */
			int srv_was_stopping = (s->state == SRV_ST_STOPPING) || (s->admin & SRV_ADMF_DRAIN);
			int prev_srv_count = s->proxy->srv_bck + s->proxy->srv_act;

			check->health = 0; /* failure */
			s->last_change = now.tv_sec;
			s->state = SRV_ST_STOPPED;
			if (s->proxy->lbprm.set_server_status_down)
				s->proxy->lbprm.set_server_status_down(s);

			if (s->onmarkeddown & HANA_ONMARKEDDOWN_SHUTDOWNSESSIONS)
				srv_shutdown_streams(s, SF_ERR_DOWN);

			/* we might have streams queued on this server and waiting for
			 * a connection. Those which are redispatchable will be queued
			 * to another server or to the proxy itself.
			 */
			xferred = pendconn_redistribute(s);

			chunk_printf(&trash,
			             "%sServer %s/%s is going DOWN for maintenance",
			             s->flags & SRV_F_BACKUP ? "Backup " : "",
			             s->proxy->id, s->id);

			srv_append_status(&trash, s, NULL, xferred, (mode & SRV_ADMF_FMAINT));

			Warning("%s.\n", trash.str);
			send_log(s->proxy, srv_was_stopping ? LOG_NOTICE : LOG_ALERT, "%s.\n", trash.str);

			if (prev_srv_count && s->proxy->srv_bck == 0 && s->proxy->srv_act == 0)
				set_backend_down(s->proxy);

			s->counters.down_trans++;
		}
	}

	/* drain state is applied only if not yet in maint */
	if ((mode & SRV_ADMF_DRAIN) && !(s->admin & SRV_ADMF_MAINT))  {
		int prev_srv_count = s->proxy->srv_bck + s->proxy->srv_act;

		s->last_change = now.tv_sec;
		if (s->proxy->lbprm.set_server_status_down)
			s->proxy->lbprm.set_server_status_down(s);

		/* we might have streams queued on this server and waiting for
		 * a connection. Those which are redispatchable will be queued
		 * to another server or to the proxy itself.
		 */
		xferred = pendconn_redistribute(s);

		chunk_printf(&trash, "%sServer %s/%s enters drain state",
			     s->flags & SRV_F_BACKUP ? "Backup " : "", s->proxy->id, s->id);

		srv_append_status(&trash, s, NULL, xferred, (mode & SRV_ADMF_FDRAIN));

		Warning("%s.\n", trash.str);
		send_log(s->proxy, LOG_NOTICE, "%s.\n", trash.str);
		send_email_alert(s, LOG_NOTICE, "%s", trash.str);

		if (prev_srv_count && s->proxy->srv_bck == 0 && s->proxy->srv_act == 0)
			set_backend_down(s->proxy);
	}

	/* compute the inherited flag to propagate */
	if (mode & SRV_ADMF_MAINT)
		mode = SRV_ADMF_IMAINT;
	else if (mode & SRV_ADMF_DRAIN)
		mode = SRV_ADMF_IDRAIN;

	for (srv = s->trackers; srv; srv = srv->tracknext)
		srv_set_admin_flag(srv, mode);
}

/* Disables admin flag <mode> (among SRV_ADMF_*) on server <s>. This is used to
 * stop enforcing either maint mode or drain mode. It is not allowed to set more
 * than one flag at once. The equivalent "inherited" flag is propagated to all
 * tracking servers. Leaving maintenance mode re-enables health checks. When
 * either the flag is already cleared or no flag is passed, nothing is done.
 */
void srv_clr_admin_flag(struct server *s, enum srv_admin mode)
{
	struct check *check = &s->check;
	struct server *srv;
	int xferred = -1;

	if (!mode)
		return;

	/* stop going down as soon as we see the flag is not there anymore */
	if (!(s->admin & mode))
		return;

	s->admin &= ~mode;

	if (s->admin & SRV_ADMF_MAINT) {
		/* remaining in maintenance mode, let's inform precisely about the
		 * situation.
		 */
		if (mode & SRV_ADMF_FMAINT) {
			chunk_printf(&trash,
			             "%sServer %s/%s is leaving forced maintenance but remains in maintenance",
			             s->flags & SRV_F_BACKUP ? "Backup " : "",
			             s->proxy->id, s->id);

			if (s->track) /* normally it's mandatory here */
				chunk_appendf(&trash, " via %s/%s",
				              s->track->proxy->id, s->track->id);
			Warning("%s.\n", trash.str);
			send_log(s->proxy, LOG_NOTICE, "%s.\n", trash.str);
		}
		else if (mode & SRV_ADMF_IMAINT) {
			chunk_printf(&trash,
			             "%sServer %s/%s remains in forced maintenance",
			             s->flags & SRV_F_BACKUP ? "Backup " : "",
			             s->proxy->id, s->id);
			Warning("%s.\n", trash.str);
			send_log(s->proxy, LOG_NOTICE, "%s.\n", trash.str);
		}
		/* don't report anything when leaving drain mode and remaining in maintenance */
	}
	else if (mode & SRV_ADMF_MAINT) {
		/* OK here we're leaving maintenance, we have many things to check,
		 * because the server might possibly be coming back up depending on
		 * its state. In practice, leaving maintenance means that we should
		 * immediately turn to UP (more or less the slowstart) under the
		 * following conditions :
		 *   - server is neither checked nor tracked
		 *   - server tracks another server which is not checked
		 *   - server tracks another server which is already up
		 * Which sums up as something simpler :
		 * "either the tracking server is up or the server's checks are disabled
		 * or up". Otherwise we only re-enable health checks. There's a special
		 * case associated to the stopping state which can be inherited. Note
		 * that the server might still be in drain mode, which is naturally dealt
		 * with by the lower level functions.
		 */

		if (s->check.state & CHK_ST_ENABLED) {
			s->check.state &= ~CHK_ST_PAUSED;
			check->health = check->rise; /* start OK but check immediately */
		}

		if ((!s->track || s->track->state != SRV_ST_STOPPED) &&
		    (!(s->agent.state & CHK_ST_ENABLED) || (s->agent.health >= s->agent.rise)) &&
		    (!(s->check.state & CHK_ST_ENABLED) || (s->check.health >= s->check.rise))) {
			if (s->proxy->srv_bck == 0 && s->proxy->srv_act == 0) {
				if (s->proxy->last_change < now.tv_sec)		// ignore negative times
					s->proxy->down_time += now.tv_sec - s->proxy->last_change;
				s->proxy->last_change = now.tv_sec;
			}

			if (s->last_change < now.tv_sec)			// ignore negative times
				s->down_time += now.tv_sec - s->last_change;
			s->last_change = now.tv_sec;

			if (s->track && s->track->state == SRV_ST_STOPPING)
				s->state = SRV_ST_STOPPING;
			else {
				s->state = SRV_ST_STARTING;
				if (s->slowstart > 0)
					task_schedule(s->warmup, tick_add(now_ms, MS_TO_TICKS(MAX(1000, s->slowstart / 20))));
				else
					s->state = SRV_ST_RUNNING;
			}

			server_recalc_eweight(s);

			/* If the server is set with "on-marked-up shutdown-backup-sessions",
			 * and it's not a backup server and its effective weight is > 0,
			 * then it can accept new connections, so we shut down all streams
			 * on all backup servers.
			 */
			if ((s->onmarkedup & HANA_ONMARKEDUP_SHUTDOWNBACKUPSESSIONS) &&
			    !(s->flags & SRV_F_BACKUP) && s->eweight)
				srv_shutdown_backup_streams(s->proxy, SF_ERR_UP);

			/* check if we can handle some connections queued at the proxy. We
			 * will take as many as we can handle.
			 */
			xferred = pendconn_grab_from_px(s);
		}

		if (mode & SRV_ADMF_FMAINT) {
			chunk_printf(&trash,
				     "%sServer %s/%s is %s/%s (leaving forced maintenance)",
				     s->flags & SRV_F_BACKUP ? "Backup " : "",
				     s->proxy->id, s->id,
				     (s->state == SRV_ST_STOPPED) ? "DOWN" : "UP",
				     (s->admin & SRV_ADMF_DRAIN) ? "DRAIN" : "READY");
		}
		else {
			chunk_printf(&trash,
				     "%sServer %s/%s is %s/%s (leaving maintenance)",
				     s->flags & SRV_F_BACKUP ? "Backup " : "",
				     s->proxy->id, s->id,
				     (s->state == SRV_ST_STOPPED) ? "DOWN" : "UP",
				     (s->admin & SRV_ADMF_DRAIN) ? "DRAIN" : "READY");
			srv_append_status(&trash, s, NULL, xferred, 0);
		}
		Warning("%s.\n", trash.str);
		send_log(s->proxy, LOG_NOTICE, "%s.\n", trash.str);
	}
	else if ((mode & SRV_ADMF_DRAIN) && (s->admin & SRV_ADMF_DRAIN)) {
		/* remaining in drain mode after removing one of its flags */

		if (mode & SRV_ADMF_FDRAIN) {
			chunk_printf(&trash,
			             "%sServer %s/%s is leaving forced drain but remains in drain mode",
			             s->flags & SRV_F_BACKUP ? "Backup " : "",
			             s->proxy->id, s->id);

			if (s->track) /* normally it's mandatory here */
				chunk_appendf(&trash, " via %s/%s",
				              s->track->proxy->id, s->track->id);
		}
		else {
			chunk_printf(&trash,
			             "%sServer %s/%s remains in forced drain mode",
			             s->flags & SRV_F_BACKUP ? "Backup " : "",
			             s->proxy->id, s->id);
		}
		Warning("%s.\n", trash.str);
		send_log(s->proxy, LOG_NOTICE, "%s.\n", trash.str);
	}
	else if (mode & SRV_ADMF_DRAIN) {
		/* OK completely leaving drain mode */
		if (s->proxy->srv_bck == 0 && s->proxy->srv_act == 0) {
			if (s->proxy->last_change < now.tv_sec)		// ignore negative times
				s->proxy->down_time += now.tv_sec - s->proxy->last_change;
			s->proxy->last_change = now.tv_sec;
		}

		if (s->last_change < now.tv_sec)			// ignore negative times
			s->down_time += now.tv_sec - s->last_change;
		s->last_change = now.tv_sec;
		server_recalc_eweight(s);

		if (mode & SRV_ADMF_FDRAIN) {
			chunk_printf(&trash,
				     "%sServer %s/%s is %s (leaving forced drain)",
				     s->flags & SRV_F_BACKUP ? "Backup " : "",
				     s->proxy->id, s->id,
				     (s->state == SRV_ST_STOPPED) ? "DOWN" : "UP");
		}
		else {
			chunk_printf(&trash,
				     "%sServer %s/%s is %s (leaving drain)",
				     s->flags & SRV_F_BACKUP ? "Backup " : "",
				     s->proxy->id, s->id,
				     (s->state == SRV_ST_STOPPED) ? "DOWN" : "UP");
			if (s->track) /* normally it's mandatory here */
				chunk_appendf(&trash, " via %s/%s",
				              s->track->proxy->id, s->track->id);
		}
		Warning("%s.\n", trash.str);
		send_log(s->proxy, LOG_NOTICE, "%s.\n", trash.str);
	}

	/* stop going down if the equivalent flag is still present (forced or inherited) */
	if (((mode & SRV_ADMF_MAINT) && (s->admin & SRV_ADMF_MAINT)) ||
	    ((mode & SRV_ADMF_DRAIN) && (s->admin & SRV_ADMF_DRAIN)))
		return;

	if (mode & SRV_ADMF_MAINT)
		mode = SRV_ADMF_IMAINT;
	else if (mode & SRV_ADMF_DRAIN)
		mode = SRV_ADMF_IDRAIN;

	for (srv = s->trackers; srv; srv = srv->tracknext)
		srv_clr_admin_flag(srv, mode);
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 */
static struct srv_kw_list srv_kws = { "ALL", { }, {
	{ "id",           srv_parse_id,           1,  0 }, /* set id# of server */
	{ NULL, NULL, 0 },
}};

__attribute__((constructor))
static void __listener_init(void)
{
	srv_register_keywords(&srv_kws);
}

/* Recomputes the server's eweight based on its state, uweight, the current time,
 * and the proxy's algorihtm. To be used after updating sv->uweight. The warmup
 * state is automatically disabled if the time is elapsed.
 */
void server_recalc_eweight(struct server *sv)
{
	struct proxy *px = sv->proxy;
	unsigned w;

	if (now.tv_sec < sv->last_change || now.tv_sec >= sv->last_change + sv->slowstart) {
		/* go to full throttle if the slowstart interval is reached */
		if (sv->state == SRV_ST_STARTING)
			sv->state = SRV_ST_RUNNING;
	}

	/* We must take care of not pushing the server to full throttle during slow starts.
	 * It must also start immediately, at least at the minimal step when leaving maintenance.
	 */
	if ((sv->state == SRV_ST_STARTING) && (px->lbprm.algo & BE_LB_PROP_DYN))
		w = (px->lbprm.wdiv * (now.tv_sec - sv->last_change) + sv->slowstart) / sv->slowstart;
	else
		w = px->lbprm.wdiv;

	sv->eweight = (sv->uweight * w + px->lbprm.wmult - 1) / px->lbprm.wmult;

	/* now propagate the status change to any LB algorithms */
	if (px->lbprm.update_server_eweight)
		px->lbprm.update_server_eweight(sv);
	else if (srv_is_usable(sv)) {
		if (px->lbprm.set_server_status_up)
			px->lbprm.set_server_status_up(sv);
	}
	else {
		if (px->lbprm.set_server_status_down)
			px->lbprm.set_server_status_down(sv);
	}
}

/*
 * Parses weight_str and configures sv accordingly.
 * Returns NULL on success, error message string otherwise.
 */
const char *server_parse_weight_change_request(struct server *sv,
					       const char *weight_str)
{
	struct proxy *px;
	long int w;
	char *end;

	px = sv->proxy;

	/* if the weight is terminated with '%', it is set relative to
	 * the initial weight, otherwise it is absolute.
	 */
	if (!*weight_str)
		return "Require <weight> or <weight%>.\n";

	w = strtol(weight_str, &end, 10);
	if (end == weight_str)
		return "Empty weight string empty or preceded by garbage";
	else if (end[0] == '%' && end[1] == '\0') {
		if (w < 0)
			return "Relative weight must be positive.\n";
		/* Avoid integer overflow */
		if (w > 25600)
			w = 25600;
		w = sv->iweight * w / 100;
		if (w > 256)
			w = 256;
	}
	else if (w < 0 || w > 256)
		return "Absolute weight can only be between 0 and 256 inclusive.\n";
	else if (end[0] != '\0')
		return "Trailing garbage in weight string";

	if (w && w != sv->iweight && !(px->lbprm.algo & BE_LB_PROP_DYN))
		return "Backend is using a static LB algorithm and only accepts weights '0%' and '100%'.\n";

	sv->uweight = w;
	server_recalc_eweight(sv);

	return NULL;
}

/*
 * Parses <addr_str> and configures <sv> accordingly.
 * Returns:
 *  - error string on error
 *  - NULL on success
 */
const char *server_parse_addr_change_request(struct server *sv,
                                             const char *addr_str)
{
	unsigned char ip[INET6_ADDRSTRLEN];

	if (inet_pton(AF_INET6, addr_str, ip)) {
		update_server_addr(sv, ip, AF_INET6, "stats command\n");
		return NULL;
	}
	if (inet_pton(AF_INET, addr_str, ip)) {
		update_server_addr(sv, ip, AF_INET, "stats command\n");
		return NULL;
	}

	return "Could not understand IP address format.\n";
}

int parse_server(const char *file, int linenum, char **args, struct proxy *curproxy, struct proxy *defproxy)
{
	struct server *newsrv = NULL;
	const char *err;
	char *errmsg = NULL;
	int err_code = 0;
	unsigned val;

	if (!strcmp(args[0], "server") || !strcmp(args[0], "default-server")) {  /* server address */
		int cur_arg;
		short realport = 0;
		int do_agent = 0, do_check = 0, defsrv = (*args[0] == 'd');

		if (!defsrv && curproxy == defproxy) {
			Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, args[0], NULL))
			err_code |= ERR_ALERT | ERR_FATAL;

		if (!*args[2]) {
			Alert("parsing [%s:%d] : '%s' expects <name> and <addr>[:<port>] as arguments.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err && !defsrv) {
			Alert("parsing [%s:%d] : character '%c' is not permitted in server name '%s'.\n",
			      file, linenum, *err, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (!defsrv) {
			struct sockaddr_storage *sk;
			int port1, port2;
			struct protocol *proto;
			struct dns_resolution *curr_resolution;

			if ((newsrv = (struct server *)calloc(1, sizeof(struct server))) == NULL) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			/* the servers are linked backwards first */
			newsrv->next = curproxy->srv;
			curproxy->srv = newsrv;
			newsrv->proxy = curproxy;
			newsrv->conf.file = strdup(file);
			newsrv->conf.line = linenum;

			newsrv->obj_type = OBJ_TYPE_SERVER;
			LIST_INIT(&newsrv->actconns);
			LIST_INIT(&newsrv->pendconns);
			do_check = 0;
			do_agent = 0;
			newsrv->flags = 0;
			newsrv->admin = 0;
			newsrv->state = SRV_ST_RUNNING; /* early server setup */
			newsrv->last_change = now.tv_sec;
			newsrv->id = strdup(args[1]);

			/* several ways to check the port component :
			 *  - IP    => port=+0, relative (IPv4 only)
			 *  - IP:   => port=+0, relative
			 *  - IP:N  => port=N, absolute
			 *  - IP:+N => port=+N, relative
			 *  - IP:-N => port=-N, relative
			 */
			sk = str2sa_range(args[2], &port1, &port2, &errmsg, NULL);
			if (!sk) {
				Alert("parsing [%s:%d] : '%s %s' : %s\n", file, linenum, args[0], args[1], errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			proto = protocol_by_family(sk->ss_family);
			if (!proto || !proto->connect) {
				Alert("parsing [%s:%d] : '%s %s' : connect() not supported for this address family.\n",
				      file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (!port1 || !port2) {
				/* no port specified, +offset, -offset */
				newsrv->flags |= SRV_F_MAPPORTS;
			}
			else if (port1 != port2) {
				/* port range */
				Alert("parsing [%s:%d] : '%s %s' : port ranges are not allowed in '%s'\n",
				      file, linenum, args[0], args[1], args[2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			else {
				/* used by checks */
				realport = port1;
			}

			/* save hostname and create associated name resolution */
			switch (sk->ss_family) {
			case AF_INET: {
				/* remove the port if any */
				char *c;
				if ((c = rindex(args[2], ':')) != NULL) {
					newsrv->hostname = my_strndup(args[2], c - args[2]);
				}
				else {
					newsrv->hostname = strdup(args[2]);
				}
			}
				break;
			case AF_INET6:
				newsrv->hostname = strdup(args[2]);
				break;
			default:
				goto skip_name_resolution;
			}

			/* no name resolution if an IP has been provided */
			if (inet_pton(sk->ss_family, newsrv->hostname, trash.str) == 1)
				goto skip_name_resolution;

			if ((curr_resolution = calloc(1, sizeof(struct dns_resolution))) == NULL)
				goto skip_name_resolution;

			curr_resolution->hostname_dn_len = dns_str_to_dn_label_len(newsrv->hostname);
			if ((curr_resolution->hostname_dn = calloc(curr_resolution->hostname_dn_len + 1, sizeof(char))) == NULL)
				goto skip_name_resolution;
			if ((dns_str_to_dn_label(newsrv->hostname, curr_resolution->hostname_dn, curr_resolution->hostname_dn_len + 1)) == NULL) {
				Alert("parsing [%s:%d] : Invalid hostname '%s'\n",
				      file, linenum, args[2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			curr_resolution->requester = newsrv;
			curr_resolution->requester_cb = snr_resolution_cb;
			curr_resolution->requester_error_cb = snr_resolution_error_cb;
			curr_resolution->status = RSLV_STATUS_NONE;
			curr_resolution->step = RSLV_STEP_NONE;
			/* a first resolution has been done by the configuration parser */
			curr_resolution->last_resolution = now_ms;
			newsrv->resolution = curr_resolution;

 skip_name_resolution:
			newsrv->addr = *sk;
			newsrv->xprt  = newsrv->check.xprt = newsrv->agent.xprt = &raw_sock;

			if (!protocol_by_family(newsrv->addr.ss_family)) {
				Alert("parsing [%s:%d] : Unknown protocol family %d '%s'\n",
				      file, linenum, newsrv->addr.ss_family, args[2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			newsrv->check.use_ssl	= curproxy->defsrv.check.use_ssl;
			newsrv->check.port	= curproxy->defsrv.check.port;
			newsrv->check.inter	= curproxy->defsrv.check.inter;
			newsrv->check.fastinter	= curproxy->defsrv.check.fastinter;
			newsrv->check.downinter	= curproxy->defsrv.check.downinter;
			newsrv->agent.use_ssl	= curproxy->defsrv.agent.use_ssl;
			newsrv->agent.port	= curproxy->defsrv.agent.port;
			newsrv->agent.inter	= curproxy->defsrv.agent.inter;
			newsrv->agent.fastinter	= curproxy->defsrv.agent.fastinter;
			newsrv->agent.downinter	= curproxy->defsrv.agent.downinter;
			newsrv->maxqueue	= curproxy->defsrv.maxqueue;
			newsrv->minconn		= curproxy->defsrv.minconn;
			newsrv->maxconn		= curproxy->defsrv.maxconn;
			newsrv->slowstart	= curproxy->defsrv.slowstart;
			newsrv->onerror		= curproxy->defsrv.onerror;
			newsrv->onmarkeddown    = curproxy->defsrv.onmarkeddown;
			newsrv->onmarkedup      = curproxy->defsrv.onmarkedup;
			newsrv->consecutive_errors_limit
						= curproxy->defsrv.consecutive_errors_limit;
#ifdef OPENSSL
			newsrv->use_ssl		= curproxy->defsrv.use_ssl;
#endif
			newsrv->uweight = newsrv->iweight
						= curproxy->defsrv.iweight;

			newsrv->check.status	= HCHK_STATUS_INI;
			newsrv->check.rise	= curproxy->defsrv.check.rise;
			newsrv->check.fall	= curproxy->defsrv.check.fall;
			newsrv->check.health	= newsrv->check.rise;	/* up, but will fall down at first failure */
			newsrv->check.server	= newsrv;
			newsrv->check.tcpcheck_rules	= &curproxy->tcpcheck_rules;

			newsrv->agent.status	= HCHK_STATUS_INI;
			newsrv->agent.rise	= curproxy->defsrv.agent.rise;
			newsrv->agent.fall	= curproxy->defsrv.agent.fall;
			newsrv->agent.health	= newsrv->agent.rise;	/* up, but will fall down at first failure */
			newsrv->agent.server	= newsrv;
			newsrv->resolver_family_priority = curproxy->defsrv.resolver_family_priority;
			if (newsrv->resolver_family_priority == AF_UNSPEC)
				newsrv->resolver_family_priority = AF_INET6;

			cur_arg = 3;
		} else {
			newsrv = &curproxy->defsrv;
			cur_arg = 1;
			newsrv->resolver_family_priority = AF_INET6;
		}

		while (*args[cur_arg]) {
			if (!strcmp(args[cur_arg], "agent-check")) {
				global.maxsock++;
				do_agent = 1;
				cur_arg += 1;
			} else if (!strcmp(args[cur_arg], "agent-inter")) {
				const char *err = parse_time_err(args[cur_arg + 1], &val, TIME_UNIT_MS);
				if (err) {
					Alert("parsing [%s:%d] : unexpected character '%c' in 'agent-inter' argument of server %s.\n",
					      file, linenum, *err, newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if (val <= 0) {
					Alert("parsing [%s:%d]: invalid value %d for argument '%s' of server %s.\n",
					      file, linenum, val, args[cur_arg], newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				newsrv->agent.inter = val;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "agent-port")) {
				global.maxsock++;
				newsrv->agent.port = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "cookie")) {
				newsrv->cookie = strdup(args[cur_arg + 1]);
				newsrv->cklen = strlen(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "redir")) {
				newsrv->rdr_pfx = strdup(args[cur_arg + 1]);
				newsrv->rdr_len = strlen(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "resolvers")) {
				newsrv->resolvers_id = strdup(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "resolve-prefer")) {
				if (!strcmp(args[cur_arg + 1], "ipv4"))
					newsrv->resolver_family_priority = AF_INET;
				else if (!strcmp(args[cur_arg + 1], "ipv6"))
					newsrv->resolver_family_priority = AF_INET6;
				else {
					Alert("parsing [%s:%d]: '%s' expects either ipv4 or ipv6 as argument.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "rise")) {
				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d]: '%s' expects an integer argument.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				newsrv->check.rise = atol(args[cur_arg + 1]);
				if (newsrv->check.rise <= 0) {
					Alert("parsing [%s:%d]: '%s' has to be > 0.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (newsrv->check.health)
					newsrv->check.health = newsrv->check.rise;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "fall")) {
				newsrv->check.fall = atol(args[cur_arg + 1]);

				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d]: '%s' expects an integer argument.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (newsrv->check.fall <= 0) {
					Alert("parsing [%s:%d]: '%s' has to be > 0.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "inter")) {
				const char *err = parse_time_err(args[cur_arg + 1], &val, TIME_UNIT_MS);
				if (err) {
					Alert("parsing [%s:%d] : unexpected character '%c' in 'inter' argument of server %s.\n",
					      file, linenum, *err, newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if (val <= 0) {
					Alert("parsing [%s:%d]: invalid value %d for argument '%s' of server %s.\n",
					      file, linenum, val, args[cur_arg], newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				newsrv->check.inter = val;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "fastinter")) {
				const char *err = parse_time_err(args[cur_arg + 1], &val, TIME_UNIT_MS);
				if (err) {
					Alert("parsing [%s:%d]: unexpected character '%c' in 'fastinter' argument of server %s.\n",
					      file, linenum, *err, newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if (val <= 0) {
					Alert("parsing [%s:%d]: invalid value %d for argument '%s' of server %s.\n",
					      file, linenum, val, args[cur_arg], newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				newsrv->check.fastinter = val;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "downinter")) {
				const char *err = parse_time_err(args[cur_arg + 1], &val, TIME_UNIT_MS);
				if (err) {
					Alert("parsing [%s:%d]: unexpected character '%c' in 'downinter' argument of server %s.\n",
					      file, linenum, *err, newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if (val <= 0) {
					Alert("parsing [%s:%d]: invalid value %d for argument '%s' of server %s.\n",
					      file, linenum, val, args[cur_arg], newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				newsrv->check.downinter = val;
				cur_arg += 2;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "addr")) {
				struct sockaddr_storage *sk;
				int port1, port2;
				struct protocol *proto;

				sk = str2sa_range(args[cur_arg + 1], &port1, &port2, &errmsg, NULL);
				if (!sk) {
					Alert("parsing [%s:%d] : '%s' : %s\n",
					      file, linenum, args[cur_arg], errmsg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				proto = protocol_by_family(sk->ss_family);
				if (!proto || !proto->connect) {
					Alert("parsing [%s:%d] : '%s %s' : connect() not supported for this address family.\n",
					      file, linenum, args[cur_arg], args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				if (port1 != port2) {
					Alert("parsing [%s:%d] : '%s' : port ranges and offsets are not allowed in '%s'\n",
					      file, linenum, args[cur_arg], args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				newsrv->check.addr = newsrv->agent.addr = *sk;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "port")) {
				newsrv->check.port = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "backup")) {
				newsrv->flags |= SRV_F_BACKUP;
				cur_arg ++;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "non-stick")) {
				newsrv->flags |= SRV_F_NON_STICK;
				cur_arg ++;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "send-proxy")) {
				newsrv->pp_opts |= SRV_PP_V1;
				cur_arg ++;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "send-proxy-v2")) {
				newsrv->pp_opts |= SRV_PP_V2;
				cur_arg ++;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "check-send-proxy")) {
				newsrv->check.send_proxy = 1;
				cur_arg ++;
			}
			else if (!strcmp(args[cur_arg], "weight")) {
				int w;
				w = atol(args[cur_arg + 1]);
				if (w < 0 || w > SRV_UWGHT_MAX) {
					Alert("parsing [%s:%d] : weight of server %s is not within 0 and %d (%d).\n",
					      file, linenum, newsrv->id, SRV_UWGHT_MAX, w);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				newsrv->uweight = newsrv->iweight = w;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "minconn")) {
				newsrv->minconn = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "maxconn")) {
				newsrv->maxconn = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "maxqueue")) {
				newsrv->maxqueue = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "slowstart")) {
				/* slowstart is stored in seconds */
				const char *err = parse_time_err(args[cur_arg + 1], &val, TIME_UNIT_MS);
				if (err) {
					Alert("parsing [%s:%d] : unexpected character '%c' in 'slowstart' argument of server %s.\n",
					      file, linenum, *err, newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				newsrv->slowstart = (val + 999) / 1000;
				cur_arg += 2;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "track")) {

				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d]: 'track' expects [<proxy>/]<server> as argument.\n",
						file, linenum);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				newsrv->trackit = strdup(args[cur_arg + 1]);

				cur_arg += 2;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "check")) {
				global.maxsock++;
				do_check = 1;
				cur_arg += 1;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "disabled")) {
				newsrv->admin |= SRV_ADMF_FMAINT;
				newsrv->state = SRV_ST_STOPPED;
				newsrv->check.state |= CHK_ST_PAUSED;
				newsrv->check.health = 0;
				cur_arg += 1;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "observe")) {
				if (!strcmp(args[cur_arg + 1], "none"))
					newsrv->observe = HANA_OBS_NONE;
				else if (!strcmp(args[cur_arg + 1], "layer4"))
					newsrv->observe = HANA_OBS_LAYER4;
				else if (!strcmp(args[cur_arg + 1], "layer7")) {
					if (curproxy->mode != PR_MODE_HTTP) {
						Alert("parsing [%s:%d]: '%s' can only be used in http proxies.\n",
							file, linenum, args[cur_arg + 1]);
						err_code |= ERR_ALERT;
					}
					newsrv->observe = HANA_OBS_LAYER7;
				}
				else {
					Alert("parsing [%s:%d]: '%s' expects one of 'none', "
						"'layer4', 'layer7' but got '%s'\n",
						file, linenum, args[cur_arg], args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "on-error")) {
				if (!strcmp(args[cur_arg + 1], "fastinter"))
					newsrv->onerror = HANA_ONERR_FASTINTER;
				else if (!strcmp(args[cur_arg + 1], "fail-check"))
					newsrv->onerror = HANA_ONERR_FAILCHK;
				else if (!strcmp(args[cur_arg + 1], "sudden-death"))
					newsrv->onerror = HANA_ONERR_SUDDTH;
				else if (!strcmp(args[cur_arg + 1], "mark-down"))
					newsrv->onerror = HANA_ONERR_MARKDWN;
				else {
					Alert("parsing [%s:%d]: '%s' expects one of 'fastinter', "
						"'fail-check', 'sudden-death' or 'mark-down' but got '%s'\n",
						file, linenum, args[cur_arg], args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "on-marked-down")) {
				if (!strcmp(args[cur_arg + 1], "shutdown-sessions"))
					newsrv->onmarkeddown = HANA_ONMARKEDDOWN_SHUTDOWNSESSIONS;
				else {
					Alert("parsing [%s:%d]: '%s' expects 'shutdown-sessions' but got '%s'\n",
						file, linenum, args[cur_arg], args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "on-marked-up")) {
				if (!strcmp(args[cur_arg + 1], "shutdown-backup-sessions"))
					newsrv->onmarkedup = HANA_ONMARKEDUP_SHUTDOWNBACKUPSESSIONS;
				else {
					Alert("parsing [%s:%d]: '%s' expects 'shutdown-backup-sessions' but got '%s'\n",
						file, linenum, args[cur_arg], args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "error-limit")) {
				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d]: '%s' expects an integer argument.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				newsrv->consecutive_errors_limit = atoi(args[cur_arg + 1]);

				if (newsrv->consecutive_errors_limit <= 0) {
					Alert("parsing [%s:%d]: %s has to be > 0.\n",
						file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				cur_arg += 2;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "source")) {  /* address to which we bind when connecting */
				int port_low, port_high;
				struct sockaddr_storage *sk;
				struct protocol *proto;

				if (!*args[cur_arg + 1]) {
					Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>[-<port>]], and optionally '%s' <addr>, and '%s' <name> as argument.\n",
					      file, linenum, "source", "usesrc", "interface");
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				newsrv->conn_src.opts |= CO_SRC_BIND;
				sk = str2sa_range(args[cur_arg + 1], &port_low, &port_high, &errmsg, NULL);
				if (!sk) {
					Alert("parsing [%s:%d] : '%s %s' : %s\n",
					      file, linenum, args[cur_arg], args[cur_arg+1], errmsg);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				proto = protocol_by_family(sk->ss_family);
				if (!proto || !proto->connect) {
					Alert("parsing [%s:%d] : '%s %s' : connect() not supported for this address family.\n",
					      file, linenum, args[cur_arg], args[cur_arg+1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				newsrv->conn_src.source_addr = *sk;

				if (port_low != port_high) {
					int i;

					if (!port_low || !port_high) {
						Alert("parsing [%s:%d] : %s does not support port offsets (found '%s').\n",
						      file, linenum, args[cur_arg], args[cur_arg + 1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}

					if (port_low  <= 0 || port_low > 65535 ||
					    port_high <= 0 || port_high > 65535 ||
					    port_low > port_high) {
						Alert("parsing [%s:%d] : invalid source port range %d-%d.\n",
						      file, linenum, port_low, port_high);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					newsrv->conn_src.sport_range = port_range_alloc_range(port_high - port_low + 1);
					for (i = 0; i < newsrv->conn_src.sport_range->size; i++)
						newsrv->conn_src.sport_range->ports[i] = port_low + i;
				}

				cur_arg += 2;
				while (*(args[cur_arg])) {
					if (!strcmp(args[cur_arg], "usesrc")) {  /* address to use outside */
#if defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_TRANSPARENT)
#if !defined(CONFIG_HAP_TRANSPARENT)
						if (!is_inet_addr(&newsrv->conn_src.source_addr)) {
							Alert("parsing [%s:%d] : '%s' requires an explicit '%s' address.\n",
							      file, linenum, "usesrc", "source");
							err_code |= ERR_ALERT | ERR_FATAL;
							goto out;
						}
#endif
						if (!*args[cur_arg + 1]) {
							Alert("parsing [%s:%d] : '%s' expects <addr>[:<port>], 'client', 'clientip', or 'hdr_ip(name,#)' as argument.\n",
							      file, linenum, "usesrc");
							err_code |= ERR_ALERT | ERR_FATAL;
							goto out;
						}
						if (!strcmp(args[cur_arg + 1], "client")) {
							newsrv->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
							newsrv->conn_src.opts |= CO_SRC_TPROXY_CLI;
						} else if (!strcmp(args[cur_arg + 1], "clientip")) {
							newsrv->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
							newsrv->conn_src.opts |= CO_SRC_TPROXY_CIP;
						} else if (!strncmp(args[cur_arg + 1], "hdr_ip(", 7)) {
							char *name, *end;

							name = args[cur_arg+1] + 7;
							while (isspace(*name))
								name++;

							end = name;
							while (*end && !isspace(*end) && *end != ',' && *end != ')')
								end++;

							newsrv->conn_src.opts &= ~CO_SRC_TPROXY_MASK;
							newsrv->conn_src.opts |= CO_SRC_TPROXY_DYN;
							newsrv->conn_src.bind_hdr_name = calloc(1, end - name + 1);
							newsrv->conn_src.bind_hdr_len = end - name;
							memcpy(newsrv->conn_src.bind_hdr_name, name, end - name);
							newsrv->conn_src.bind_hdr_name[end-name] = '\0';
							newsrv->conn_src.bind_hdr_occ = -1;

							/* now look for an occurrence number */
							while (isspace(*end))
								end++;
							if (*end == ',') {
								end++;
								name = end;
								if (*end == '-')
									end++;
								while (isdigit((int)*end))
									end++;
								newsrv->conn_src.bind_hdr_occ = strl2ic(name, end-name);
							}

							if (newsrv->conn_src.bind_hdr_occ < -MAX_HDR_HISTORY) {
								Alert("parsing [%s:%d] : usesrc hdr_ip(name,num) does not support negative"
								      " occurrences values smaller than %d.\n",
								      file, linenum, MAX_HDR_HISTORY);
								err_code |= ERR_ALERT | ERR_FATAL;
								goto out;
							}
						} else {
							struct sockaddr_storage *sk;
							int port1, port2;

							sk = str2sa_range(args[cur_arg + 1], &port1, &port2, &errmsg, NULL);
							if (!sk) {
								Alert("parsing [%s:%d] : '%s %s' : %s\n",
								      file, linenum, args[cur_arg], args[cur_arg+1], errmsg);
								err_code |= ERR_ALERT | ERR_FATAL;
								goto out;
							}

							proto = protocol_by_family(sk->ss_family);
							if (!proto || !proto->connect) {
								Alert("parsing [%s:%d] : '%s %s' : connect() not supported for this address family.\n",
								      file, linenum, args[cur_arg], args[cur_arg+1]);
								err_code |= ERR_ALERT | ERR_FATAL;
								goto out;
							}

							if (port1 != port2) {
								Alert("parsing [%s:%d] : '%s' : port ranges and offsets are not allowed in '%s'\n",
								      file, linenum, args[cur_arg], args[cur_arg + 1]);
								err_code |= ERR_ALERT | ERR_FATAL;
								goto out;
							}
							newsrv->conn_src.tproxy_addr = *sk;
							newsrv->conn_src.opts |= CO_SRC_TPROXY_ADDR;
						}
						global.last_checks |= LSTCHK_NETADM;
#if !defined(CONFIG_HAP_TRANSPARENT)
						global.last_checks |= LSTCHK_CTTPROXY;
#endif
						cur_arg += 2;
						continue;
#else	/* no TPROXY support */
						Alert("parsing [%s:%d] : '%s' not allowed here because support for TPROXY was not compiled in.\n",
						      file, linenum, "usesrc");
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
#endif /* defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_TRANSPARENT) */
					} /* "usesrc" */

					if (!strcmp(args[cur_arg], "interface")) { /* specifically bind to this interface */
#ifdef SO_BINDTODEVICE
						if (!*args[cur_arg + 1]) {
							Alert("parsing [%s:%d] : '%s' : missing interface name.\n",
							      file, linenum, args[0]);
							err_code |= ERR_ALERT | ERR_FATAL;
							goto out;
						}
						free(newsrv->conn_src.iface_name);
						newsrv->conn_src.iface_name = strdup(args[cur_arg + 1]);
						newsrv->conn_src.iface_len  = strlen(newsrv->conn_src.iface_name);
						global.last_checks |= LSTCHK_NETADM;
#else
						Alert("parsing [%s:%d] : '%s' : '%s' option not implemented.\n",
						      file, linenum, args[0], args[cur_arg]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
#endif
						cur_arg += 2;
						continue;
					}
					/* this keyword in not an option of "source" */
					break;
				} /* while */
			}
			else if (!defsrv && !strcmp(args[cur_arg], "usesrc")) {  /* address to use outside: needs "source" first */
				Alert("parsing [%s:%d] : '%s' only allowed after a '%s' statement.\n",
				      file, linenum, "usesrc", "source");
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			else if (!defsrv && !strcmp(args[cur_arg], "namespace")) {
#ifdef CONFIG_HAP_NS
				char *arg = args[cur_arg + 1];
				if (!strcmp(arg, "*")) {
					newsrv->flags |= SRV_F_USE_NS_FROM_PP;
				} else {
					newsrv->netns = netns_store_lookup(arg, strlen(arg));

					if (newsrv->netns == NULL)
						newsrv->netns = netns_store_insert(arg);

					if (newsrv->netns == NULL) {
						Alert("Cannot open namespace '%s'.\n", args[cur_arg + 1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
				}
#else
				Alert("parsing [%s:%d] : '%s' : '%s' option not implemented.\n",
				      file, linenum, args[0], args[cur_arg]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
#endif
				cur_arg += 2;
			}
			else {
				static int srv_dumped;
				struct srv_kw *kw;
				char *err;

				kw = srv_find_kw(args[cur_arg]);
				if (kw) {
					char *err = NULL;
					int code;

					if (!kw->parse) {
						Alert("parsing [%s:%d] : '%s %s' : '%s' option is not implemented in this version (check build options).\n",
						      file, linenum, args[0], args[1], args[cur_arg]);
						cur_arg += 1 + kw->skip ;
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}

					if (defsrv && !kw->default_ok) {
						Alert("parsing [%s:%d] : '%s %s' : '%s' option is not accepted in default-server sections.\n",
						      file, linenum, args[0], args[1], args[cur_arg]);
						cur_arg += 1 + kw->skip ;
						err_code |= ERR_ALERT;
						continue;
					}

					code = kw->parse(args, &cur_arg, curproxy, newsrv, &err);
					err_code |= code;

					if (code) {
						if (err && *err) {
							indent_msg(&err, 2);
							Alert("parsing [%s:%d] : '%s %s' : %s\n", file, linenum, args[0], args[1], err);
						}
						else
							Alert("parsing [%s:%d] : '%s %s' : error encountered while processing '%s'.\n",
							      file, linenum, args[0], args[1], args[cur_arg]);
						if (code & ERR_FATAL) {
							free(err);
							cur_arg += 1 + kw->skip;
							goto out;
						}
					}
					free(err);
					cur_arg += 1 + kw->skip;
					continue;
				}

				err = NULL;
				if (!srv_dumped) {
					srv_dump_kws(&err);
					indent_msg(&err, 4);
					srv_dumped = 1;
				}

				Alert("parsing [%s:%d] : '%s %s' unknown keyword '%s'.%s%s\n",
				      file, linenum, args[0], args[1], args[cur_arg],
				      err ? " Registered keywords :" : "", err ? err : "");
				free(err);

				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}

		if (do_check) {
			const char *ret;

			if (newsrv->trackit) {
				Alert("parsing [%s:%d]: unable to enable checks and tracking at the same time!\n",
					file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			/* If neither a port nor an addr was specified and no check transport
			 * layer is forced, then the transport layer used by the checks is the
			 * same as for the production traffic. Otherwise we use raw_sock by
			 * default, unless one is specified.
			 */
			if (!newsrv->check.port && !is_addr(&newsrv->check.addr)) {
#ifdef USE_OPENSSL
				newsrv->check.use_ssl |= (newsrv->use_ssl || (newsrv->proxy->options & PR_O_TCPCHK_SSL));
#endif
				newsrv->check.send_proxy |= (newsrv->pp_opts);
			}
			/* try to get the port from check_core.addr if check.port not set */
			if (!newsrv->check.port)
				newsrv->check.port = get_host_port(&newsrv->check.addr);

			if (!newsrv->check.port)
				newsrv->check.port = realport; /* by default */

			if (!newsrv->check.port) {
				/* not yet valid, because no port was set on
				 * the server either. We'll check if we have
				 * a known port on the first listener.
				 */
				struct listener *l;

				list_for_each_entry(l, &curproxy->conf.listeners, by_fe) {
					newsrv->check.port = get_host_port(&l->addr);
					if (newsrv->check.port)
						break;
				}
			}
			/*
			 * We need at least a service port, a check port or the first tcp-check rule must
			 * be a 'connect' one when checking an IPv4/IPv6 server.
			 */
			if (!newsrv->check.port &&
			    (is_inet_addr(&newsrv->check.addr) ||
			     (!is_addr(&newsrv->check.addr) && is_inet_addr(&newsrv->addr)))) {
				struct tcpcheck_rule *n = NULL, *r = NULL;
				struct list *l;

				r = (struct tcpcheck_rule *)newsrv->proxy->tcpcheck_rules.n;
				if (!r) {
					Alert("parsing [%s:%d] : server %s has neither service port nor check port. Check has been disabled.\n",
					      file, linenum, newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				if ((r->action != TCPCHK_ACT_CONNECT) || !r->port) {
					Alert("parsing [%s:%d] : server %s has neither service port nor check port nor tcp_check rule 'connect' with port information. Check has been disabled.\n",
					      file, linenum, newsrv->id);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				else {
					/* scan the tcp-check ruleset to ensure a port has been configured */
					l = &newsrv->proxy->tcpcheck_rules;
					list_for_each_entry(n, l, list) {
						r = (struct tcpcheck_rule *)n->list.p;
						if ((r->action == TCPCHK_ACT_CONNECT) && (!r->port)) {
							Alert("parsing [%s:%d] : server %s has neither service port nor check port, and a tcp_check rule 'connect' with no port information. Check has been disabled.\n",
							      file, linenum, newsrv->id);
							err_code |= ERR_ALERT | ERR_FATAL;
							goto out;
						}
					}
				}
			}

			/* note: check type will be set during the config review phase */
			ret = init_check(&newsrv->check, 0);
			if (ret) {
				Alert("parsing [%s:%d] : %s.\n", file, linenum, ret);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			if (newsrv->resolution)
				newsrv->resolution->resolver_family_priority = newsrv->resolver_family_priority;

			newsrv->check.state |= CHK_ST_CONFIGURED | CHK_ST_ENABLED;
		}

		if (do_agent) {
			const char *ret;

			if (!newsrv->agent.port) {
				Alert("parsing [%s:%d] : server %s does not have agent port. Agent check has been disabled.\n",
				      file, linenum, newsrv->id);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (!newsrv->agent.inter)
				newsrv->agent.inter = newsrv->check.inter;

			ret = init_check(&newsrv->agent, PR_O2_LB_AGENT_CHK);
			if (ret) {
				Alert("parsing [%s:%d] : %s.\n", file, linenum, ret);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			newsrv->agent.state |= CHK_ST_CONFIGURED | CHK_ST_ENABLED | CHK_ST_AGENT;
		}

		if (!defsrv) {
			if (newsrv->flags & SRV_F_BACKUP)
				curproxy->srv_bck++;
			else
				curproxy->srv_act++;

			srv_lb_commit_status(newsrv);
		}
	}
	return 0;

 out:
	free(errmsg);
	return err_code;
}

/*
 * update a server's current IP address.
 * ip is a pointer to the new IP address, whose address family is ip_sin_family.
 * ip is in network format.
 * updater is a string which contains an information about the requester of the update.
 * updater is used if not NULL.
 *
 * A log line and a stderr warning message is generated based on server's backend options.
 */
int update_server_addr(struct server *s, void *ip, int ip_sin_family, char *updater)
{
	/* generates a log line and a warning on stderr */
	if (1) {
		/* book enough space for both IPv4 and IPv6 */
		char oldip[INET6_ADDRSTRLEN];
		char newip[INET6_ADDRSTRLEN];

		memset(oldip, '\0', INET6_ADDRSTRLEN);
		memset(newip, '\0', INET6_ADDRSTRLEN);

		/* copy old IP address in a string */
		switch (s->addr.ss_family) {
		case AF_INET:
			inet_ntop(s->addr.ss_family, &((struct sockaddr_in *)&s->addr)->sin_addr, oldip, INET_ADDRSTRLEN);
			break;
		case AF_INET6:
			inet_ntop(s->addr.ss_family, &((struct sockaddr_in6 *)&s->addr)->sin6_addr, oldip, INET6_ADDRSTRLEN);
			break;
		};

		/* copy new IP address in a string */
		switch (ip_sin_family) {
		case AF_INET:
			inet_ntop(ip_sin_family, ip, newip, INET_ADDRSTRLEN);
			break;
		case AF_INET6:
			inet_ntop(ip_sin_family, ip, newip, INET6_ADDRSTRLEN);
			break;
		};

		/* save log line into a buffer */
		chunk_printf(&trash, "%s/%s changed its IP from %s to %s by %s",
				s->proxy->id, s->id, oldip, newip, updater);

		/* write the buffer on stderr */
		Warning("%s.\n", trash.str);

		/* send a log */
		send_log(s->proxy, LOG_NOTICE, "%s.\n", trash.str);
	}

	/* save the new IP family */
	s->addr.ss_family = ip_sin_family;
	/* save the new IP address */
	switch (ip_sin_family) {
	case AF_INET:
		((struct sockaddr_in *)&s->addr)->sin_addr.s_addr = *(uint32_t *)ip;
		break;
	case AF_INET6:
		memcpy(((struct sockaddr_in6 *)&s->addr)->sin6_addr.s6_addr, ip, 16);
		break;
	};

	return 0;
}

/*
 * update server status based on result of name resolution
 * returns:
 *  0 if server status is updated
 *  1 if server status has not changed
 */
int snr_update_srv_status(struct server *s)
{
	struct dns_resolution *resolution = s->resolution;

	switch (resolution->status) {
		case RSLV_STATUS_NONE:
			/* status when HAProxy has just (re)started */
			trigger_resolution(s);
			break;

		default:
			break;
	}

	return 1;
}

/*
 * Server Name Resolution valid response callback
 * It expects:
 *  - <nameserver>: the name server which answered the valid response
 *  - <response>: buffer containing a valid DNS response
 *  - <response_len>: size of <response>
 * It performs the following actions:
 *  - ignore response if current ip found and server family not met
 *  - update with first new ip found if family is met and current IP is not found
 * returns:
 *  0 on error
 *  1 when no error or safe ignore
 */
int snr_resolution_cb(struct dns_resolution *resolution, struct dns_nameserver *nameserver, unsigned char *response, int response_len)
{
	struct server *s;
	void *serverip, *firstip;
	short server_sin_family, firstip_sin_family;
	unsigned char *response_end;
	int ret;
	struct chunk *chk = get_trash_chunk();

	/* initializing variables */
	response_end = response + response_len;	/* pointer to mark the end of the response */
	firstip = NULL;		/* pointer to the first valid response found */
				/* it will be used as the new IP if a change is required */
	firstip_sin_family = AF_UNSPEC;
	serverip = NULL;	/* current server IP address */

	/* shortcut to the server whose name is being resolved */
	s = (struct server *)resolution->requester;

	/* initializing server IP pointer */
	server_sin_family = s->addr.ss_family;
	switch (server_sin_family) {
		case AF_INET:
			serverip = &((struct sockaddr_in *)&s->addr)->sin_addr.s_addr;
			break;

		case AF_INET6:
			serverip = &((struct sockaddr_in6 *)&s->addr)->sin6_addr.s6_addr;
			break;

		default:
			goto invalid;
	}

	ret = dns_get_ip_from_response(response, response_end, resolution->hostname_dn, resolution->hostname_dn_len,
			serverip, server_sin_family, resolution->resolver_family_priority, &firstip,
			&firstip_sin_family);

	switch (ret) {
		case DNS_UPD_NO:
			if (resolution->status != RSLV_STATUS_VALID) {
				resolution->status = RSLV_STATUS_VALID;
				resolution->last_status_change = now_ms;
			}
			goto stop_resolution;

		case DNS_UPD_SRVIP_NOT_FOUND:
			goto save_ip;

		case DNS_UPD_CNAME:
			if (resolution->status != RSLV_STATUS_VALID) {
				resolution->status = RSLV_STATUS_VALID;
				resolution->last_status_change = now_ms;
			}
			goto invalid;

		default:
			goto invalid;

	}

 save_ip:
	nameserver->counters.update += 1;
	if (resolution->status != RSLV_STATUS_VALID) {
		resolution->status = RSLV_STATUS_VALID;
		resolution->last_status_change = now_ms;
	}

	/* save the first ip we found */
	chunk_printf(chk, "%s/%s", nameserver->resolvers->id, nameserver->id);
	update_server_addr(s, firstip, firstip_sin_family, (char *)chk->str);

 stop_resolution:
	/* update last resolution date and time */
	resolution->last_resolution = now_ms;
	/* reset current status flag */
	resolution->step = RSLV_STEP_NONE;
	/* reset values */
	dns_reset_resolution(resolution);

	LIST_DEL(&resolution->list);
	dns_update_resolvers_timeout(nameserver->resolvers);

	snr_update_srv_status(s);
	return 0;

 invalid:
	nameserver->counters.invalid += 1;
	if (resolution->nb_responses >= nameserver->resolvers->count_nameservers)
		goto stop_resolution;

	snr_update_srv_status(s);
	return 0;
}

/*
 * Server Name Resolution error management callback
 * returns:
 *  0 on error
 *  1 when no error or safe ignore
 */
int snr_resolution_error_cb(struct dns_resolution *resolution, int error_code)
{
	struct server *s;
	struct dns_resolvers *resolvers;

	/* shortcut to the server whose name is being resolved */
	s = (struct server *)resolution->requester;
	resolvers = resolution->resolvers;

	/* can be ignored if this is not the last response */
	if ((error_code != DNS_RESP_TIMEOUT) && (resolution->nb_responses < resolvers->count_nameservers)) {
		return 1;
	}

	switch (error_code) {
		case DNS_RESP_INVALID:
		case DNS_RESP_WRONG_NAME:
			if (resolution->status != RSLV_STATUS_INVALID) {
				resolution->status = RSLV_STATUS_INVALID;
				resolution->last_status_change = now_ms;
			}
			break;

		case DNS_RESP_ANCOUNT_ZERO:
		case DNS_RESP_ERROR:
			if (resolution->query_type == DNS_RTYPE_ANY) {
				/* let's change the query type */
				if (resolution->resolver_family_priority == AF_INET6)
					resolution->query_type = DNS_RTYPE_AAAA;
				else
					resolution->query_type = DNS_RTYPE_A;

				dns_send_query(resolution);

				/*
				 * move the resolution to the last element of the FIFO queue
				 * and update timeout wakeup based on the new first entry
				 */
				if (dns_check_resolution_queue(resolvers) > 1) {
					/* second resolution becomes first one */
					LIST_DEL(&resolvers->curr_resolution);
					/* ex first resolution goes to the end of the queue */
					LIST_ADDQ(&resolvers->curr_resolution, &resolution->list);
				}
				dns_update_resolvers_timeout(resolvers);
				goto leave;
			}
			else {
				if (resolution->status != RSLV_STATUS_OTHER) {
					resolution->status = RSLV_STATUS_OTHER;
					resolution->last_status_change = now_ms;
				}
			}
			break;

		case DNS_RESP_NX_DOMAIN:
			if (resolution->status != RSLV_STATUS_NX) {
				resolution->status = RSLV_STATUS_NX;
				resolution->last_status_change = now_ms;
			}
			break;

		case DNS_RESP_REFUSED:
			if (resolution->status != RSLV_STATUS_REFUSED) {
				resolution->status = RSLV_STATUS_REFUSED;
				resolution->last_status_change = now_ms;
			}
			break;

		case DNS_RESP_CNAME_ERROR:
			break;

		case DNS_RESP_TIMEOUT:
			if (resolution->status != RSLV_STATUS_TIMEOUT) {
				resolution->status = RSLV_STATUS_TIMEOUT;
				resolution->last_status_change = now_ms;
			}
			break;
	}

	/* update last resolution date and time */
	resolution->last_resolution = now_ms;
	/* reset current status flag */
	resolution->step = RSLV_STEP_NONE;
	/* reset values */
	dns_reset_resolution(resolution);

	LIST_DEL(&resolution->list);
	dns_update_resolvers_timeout(resolvers);

 leave:
	snr_update_srv_status(s);
	return 1;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
