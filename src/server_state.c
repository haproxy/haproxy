/*
 * Server-state management functions.
 *
 * Copyright (C) 2021 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>

#include <import/eb64tree.h>
#include <import/ebistree.h>

#include <haproxy/api.h>
#include <haproxy/backend.h>
#include <haproxy/cfgparse.h>
#include <haproxy/check.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/log.h>
#include <haproxy/port_range.h>
#include <haproxy/proxy.h>
#include <haproxy/resolvers.h>
#include <haproxy/server.h>
#include <haproxy/tools.h>
#include <haproxy/xxhash.h>


/* Update a server state using the parameters available in the params list.
 * The caller must provide a supported version
 * Grabs the server lock during operation.
 */
static void srv_state_srv_update(struct server *srv, int version, char **params)
{
	char *p;
	struct buffer *msg;
	const char *warning;

	/* fields since version 1
	 * and common to all other upcoming versions
	 */
	enum srv_state srv_op_state;
	enum srv_admin srv_admin_state;
	unsigned srv_uweight, srv_iweight;
	unsigned long srv_last_time_change;
	short srv_check_status;
	enum chk_result srv_check_result;
	int srv_check_health;
	int srv_check_state, srv_agent_state;
	int bk_f_forced_id;
	int srv_f_forced_id;
	int fqdn_changed;
	const char *fqdn;
	const char *port_st;
	unsigned int port_svc;
	char *srvrecord;
	char *addr;
	int partial_apply = 0;
#ifdef USE_OPENSSL
	int use_ssl;
#endif

	fqdn = NULL;
	port_svc = 0;
	msg = alloc_trash_chunk();
	if (!msg)
		goto end;

	HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);

	/* Only version 1 supported for now, don't check it. Fields are :
	 * srv_addr:             params[0]
	 * srv_op_state:         params[1]
	 * srv_admin_state:      params[2]
	 * srv_uweight:          params[3]
	 * srv_iweight:          params[4]
	 * srv_last_time_change: params[5]
	 * srv_check_status:     params[6]
	 * srv_check_result:     params[7]
	 * srv_check_health:     params[8]
	 * srv_check_state:      params[9]
	 * srv_agent_state:      params[10]
	 * bk_f_forced_id:       params[11]
	 * srv_f_forced_id:      params[12]
	 * srv_fqdn:             params[13]
	 * srv_port:             params[14]
	 * srvrecord:            params[15]
	 * srv_use_ssl:          params[16]
	 * srv_check_port:       params[17]
	 * srv_check_addr:       params[18]
	 * srv_agent_addr:       params[19]
	 * srv_agent_port:       params[20]
	 */

	/* validating srv_op_state */
	p = NULL;
	errno = 0;
	srv_op_state = strtol(params[1], &p, 10);
	if ((p == params[1]) || errno == EINVAL || errno == ERANGE ||
	    (srv_op_state != SRV_ST_STOPPED &&
	     srv_op_state != SRV_ST_STARTING &&
	     srv_op_state != SRV_ST_RUNNING &&
	     srv_op_state != SRV_ST_STOPPING)) {
		chunk_appendf(msg, ", invalid srv_op_state value '%s'", params[1]);
	}

	/* validating srv_admin_state */
	p = NULL;
	errno = 0;
	srv_admin_state = strtol(params[2], &p, 10);
	fqdn_changed = !!(srv_admin_state & SRV_ADMF_FQDN_CHANGED);

	/* inherited statuses will be recomputed later.
	 * Also disable SRV_ADMF_FQDN_CHANGED flag (set from stats socket fqdn).
	 */
	srv_admin_state &= ~SRV_ADMF_IDRAIN & ~SRV_ADMF_IMAINT & ~SRV_ADMF_RMAINT & ~SRV_ADMF_FQDN_CHANGED;

	if ((p == params[2]) || errno == EINVAL || errno == ERANGE ||
	    (srv_admin_state != 0 &&
	     srv_admin_state != SRV_ADMF_FMAINT &&
	     srv_admin_state != SRV_ADMF_CMAINT &&
	     srv_admin_state != (SRV_ADMF_CMAINT | SRV_ADMF_FMAINT) &&
	     srv_admin_state != (SRV_ADMF_CMAINT | SRV_ADMF_FDRAIN) &&
	     srv_admin_state != SRV_ADMF_FDRAIN)) {
		chunk_appendf(msg, ", invalid srv_admin_state value '%s'", params[2]);
	}

	/* validating srv_uweight */
	p = NULL;
	errno = 0;
	srv_uweight = strtol(params[3], &p, 10);
	if ((p == params[3]) || errno == EINVAL || errno == ERANGE || (srv_uweight > SRV_UWGHT_MAX))
		chunk_appendf(msg, ", invalid srv_uweight value '%s'", params[3]);

	/* validating srv_iweight */
	p = NULL;
	errno = 0;
	srv_iweight = strtol(params[4], &p, 10);
	if ((p == params[4]) || errno == EINVAL || errno == ERANGE || (srv_iweight > SRV_UWGHT_MAX))
		chunk_appendf(msg, ", invalid srv_iweight value '%s'", params[4]);

	/* validating srv_last_time_change */
	p = NULL;
	errno = 0;
	srv_last_time_change = strtol(params[5], &p, 10);
	if ((p == params[5]) || errno == EINVAL || errno == ERANGE)
		chunk_appendf(msg, ", invalid srv_last_time_change value '%s'", params[5]);

	/* validating srv_check_status */
	p = NULL;
	errno = 0;
	srv_check_status = strtol(params[6], &p, 10);
	if (p == params[6] || errno == EINVAL || errno == ERANGE ||
	    (srv_check_status >= HCHK_STATUS_SIZE))
		chunk_appendf(msg, ", invalid srv_check_status value '%s'", params[6]);

	/* validating srv_check_result */
	p = NULL;
	errno = 0;
	srv_check_result = strtol(params[7], &p, 10);
	if ((p == params[7]) || errno == EINVAL || errno == ERANGE ||
	    (srv_check_result != CHK_RES_UNKNOWN &&
	     srv_check_result != CHK_RES_NEUTRAL &&
	     srv_check_result != CHK_RES_FAILED &&
	     srv_check_result != CHK_RES_PASSED &&
	     srv_check_result != CHK_RES_CONDPASS)) {
		chunk_appendf(msg, ", invalid srv_check_result value '%s'", params[7]);
	}

	/* validating srv_check_health */
	p = NULL;
	errno = 0;
	srv_check_health = strtol(params[8], &p, 10);
	if (p == params[8] || errno == EINVAL || errno == ERANGE)
		chunk_appendf(msg, ", invalid srv_check_health value '%s'", params[8]);

	/* validating srv_check_state */
	p = NULL;
	errno = 0;
	srv_check_state = strtol(params[9], &p, 10);
	if (p == params[9] || errno == EINVAL || errno == ERANGE ||
	    (srv_check_state & ~(CHK_ST_INPROGRESS | CHK_ST_CONFIGURED | CHK_ST_ENABLED | CHK_ST_PAUSED | CHK_ST_AGENT)))
		chunk_appendf(msg, ", invalid srv_check_state value '%s'", params[9]);

	/* validating srv_agent_state */
	p = NULL;
	errno = 0;
	srv_agent_state = strtol(params[10], &p, 10);
	if (p == params[10] || errno == EINVAL || errno == ERANGE ||
	    (srv_agent_state & ~(CHK_ST_INPROGRESS | CHK_ST_CONFIGURED | CHK_ST_ENABLED | CHK_ST_PAUSED | CHK_ST_AGENT)))
		chunk_appendf(msg, ", invalid srv_agent_state value '%s'", params[10]);

	/* validating bk_f_forced_id */
	p = NULL;
	errno = 0;
	bk_f_forced_id = strtol(params[11], &p, 10);
	if (p == params[11] || errno == EINVAL || errno == ERANGE || !((bk_f_forced_id == 0) || (bk_f_forced_id == 1)))
		chunk_appendf(msg, ", invalid bk_f_forced_id value '%s'", params[11]);

	/* validating srv_f_forced_id */
	p = NULL;
	errno = 0;
	srv_f_forced_id = strtol(params[12], &p, 10);
	if (p == params[12] || errno == EINVAL || errno == ERANGE || !((srv_f_forced_id == 0) || (srv_f_forced_id == 1)))
		chunk_appendf(msg, ", invalid srv_f_forced_id value '%s'", params[12]);

	/* validating srv_fqdn */
	fqdn = params[13];
	if (fqdn && *fqdn == '-')
		fqdn = NULL;
	if (fqdn && (strlen(fqdn) > DNS_MAX_NAME_SIZE || invalid_domainchar(fqdn))) {
		chunk_appendf(msg, ", invalid srv_fqdn value '%s'", params[13]);
		fqdn = NULL;
	}

	port_st = params[14];
	if (port_st) {
		port_svc = strl2uic(port_st, strlen(port_st));
		if (port_svc > USHRT_MAX) {
			chunk_appendf(msg, ", invalid srv_port value '%s'", port_st);
			port_st = NULL;
		}
	}

	/* SRV record
	 * NOTE: in HAProxy, SRV records must start with an underscore '_'
	 */
	srvrecord = params[15];
	if (srvrecord && *srvrecord != '_')
		srvrecord = NULL;

	/* don't apply anything if one error has been detected */
	if (msg->data)
		goto out;
	partial_apply = 1;

	/* recover operational state and apply it to this server
	 * and all servers tracking this one */
	srv->check.health = srv_check_health;
	switch (srv_op_state) {
		case SRV_ST_STOPPED:
			srv->check.health = 0;
			srv_set_stopped(srv, SRV_OP_STCHGC_STATEFILE);
			break;
		case SRV_ST_STARTING:
			/* If rise == 1 there is no STARTING state, let's switch to
			 * RUNNING
			 */
			if (srv->check.rise == 1) {
				srv->check.health = srv->check.rise + srv->check.fall - 1;
				srv_set_running(srv, SRV_OP_STCHGC_NONE);
				break;
			}
			if (srv->check.health < 1 || srv->check.health >= srv->check.rise)
				srv->check.health = srv->check.rise - 1;
			srv->next_state = srv_op_state;
			break;
		case SRV_ST_STOPPING:
			/* If fall == 1 there is no STOPPING state, let's switch to
			 * STOPPED
			 */
			if (srv->check.fall == 1) {
				srv->check.health = 0;
				srv_set_stopped(srv, SRV_OP_STCHGC_STATEFILE);
				break;
			}
			if (srv->check.health < srv->check.rise ||
			    srv->check.health > srv->check.rise + srv->check.fall - 2)
				srv->check.health = srv->check.rise;
			srv_set_stopping(srv, SRV_OP_STCHGC_STATEFILE);
			break;
		case SRV_ST_RUNNING:
			srv->check.health = srv->check.rise + srv->check.fall - 1;
			srv_set_running(srv, SRV_OP_STCHGC_NONE);
			break;
	}

	/* When applying server state, the following rules apply:
	 * - in case of a configuration change, we apply the setting from the new
	 *   configuration, regardless of old running state
	 * - if no configuration change, we apply old running state only if old running
	 *   state is different from new configuration state
	 */
	/* configuration has changed */
	if ((srv_admin_state & SRV_ADMF_CMAINT) != (srv->next_admin & SRV_ADMF_CMAINT)) {
		if (srv->next_admin & SRV_ADMF_CMAINT)
			srv_adm_set_maint(srv);
		else
			srv_adm_set_ready(srv);
	}
	/* configuration is the same, let's compate old running state and new conf state */
	else {
		if (srv_admin_state & SRV_ADMF_FMAINT && !(srv->next_admin & SRV_ADMF_CMAINT))
			srv_adm_set_maint(srv);
		else if (!(srv_admin_state & SRV_ADMF_FMAINT) && (srv->next_admin & SRV_ADMF_CMAINT))
			srv_adm_set_ready(srv);
	}
	/* apply drain mode if server is currently enabled */
	if (!(srv->next_admin & SRV_ADMF_FMAINT) && (srv_admin_state & SRV_ADMF_FDRAIN)) {
		/* The SRV_ADMF_FDRAIN flag is inherited when srv->iweight is 0
		 * (srv->iweight is the weight set up in configuration).
		 * There are two possible reasons for FDRAIN to have been present :
		 *   - previous config weight was zero
		 *   - "set server b/s drain" was sent to the CLI
		 *
		 * In the first case, we simply want to drop this drain state
		 * if the new weight is not zero anymore, meaning the administrator
		 * has intentionally turned the weight back to a positive value to
		 * enable the server again after an operation. In the second case,
		 * the drain state was forced on the CLI regardless of the config's
		 * weight so we don't want a change to the config weight to lose this
		 * status. What this means is :
		 *   - if previous weight was 0 and new one is >0, drop the DRAIN state.
		 *   - if the previous weight was >0, keep it.
		 */
		if (srv_iweight > 0 || srv->iweight == 0)
			srv_adm_set_drain(srv);
	}

	srv->counters.last_change = ns_to_sec(now_ns) - srv_last_time_change;
	srv->check.status = srv_check_status;
	srv->check.result = srv_check_result;

	/* Only case we want to apply is removing ENABLED flag which could have been
	 * done by the "disable health" command over the stats socket
	 */
	if ((srv->check.state & CHK_ST_CONFIGURED) &&
	    (srv_check_state & CHK_ST_CONFIGURED) &&
	    !(srv_check_state & CHK_ST_ENABLED))
		srv->check.state &= ~CHK_ST_ENABLED;

	/* Only case we want to apply is removing ENABLED flag which could have been
	 * done by the "disable agent" command over the stats socket
	 */
	if ((srv->agent.state & CHK_ST_CONFIGURED) &&
	    (srv_agent_state & CHK_ST_CONFIGURED) &&
	    !(srv_agent_state & CHK_ST_ENABLED))
		srv->agent.state &= ~CHK_ST_ENABLED;

	/* We want to apply the previous 'running' weight (srv_uweight) only if there
	 * was no change in the configuration: both previous and new iweight are equals
	 *
	 * It means that a configuration file change has precedence over a unix socket change
	 * for server's weight
	 *
	 * by default, HAProxy applies the following weight when parsing the configuration
	 *    srv->uweight = srv->iweight
	 */
	if (srv_iweight == srv->iweight) {
		srv->uweight = srv_uweight;
	}
	server_recalc_eweight(srv, 1);

	/* load server IP address */
	if (strcmp(params[0], "-") != 0)
		srv->lastaddr = strdup(params[0]);

	if (fqdn && srv->hostname) {
		if (strcmp(srv->hostname, fqdn) == 0) {
			/* Here we reset the 'set from stats socket FQDN' flag
			 * to support such transitions:
			 * Let's say initial FQDN value is foo1 (in configuration file).
			 * - FQDN changed from stats socket, from foo1 to foo2 value,
			 * - FQDN changed again from file configuration (with the same previous value
			 set from stats socket, from foo1 to foo2 value),
			 * - reload for any other reason than a FQDN modification,
			 * the configuration file FQDN matches the fqdn server state file value.
			 * So we must reset the 'set from stats socket FQDN' flag to be consistent with
			 * any further FQDN modification.
			 */
			srv->next_admin &= ~SRV_ADMF_FQDN_CHANGED;
		}
		else {
			/* If the FDQN has been changed from stats socket,
			 * apply fqdn state file value (which is the value set
			 * from stats socket).
			 * Also ensure the runtime resolver will process this resolution.
			 */
			if (fqdn_changed) {
				srv_set_fqdn(srv, fqdn, 0);
				srv->flags &= ~SRV_F_NO_RESOLUTION;
				srv->next_admin |= SRV_ADMF_FQDN_CHANGED;
			}
		}
	}
	/* If all the conditions below are validated, this means
	 * we're evaluating a server managed by SRV resolution
	 */
	else if (fqdn && !srv->hostname && srvrecord) {
		int res;
		int i;
		char *tmp;

		/* we can't apply previous state if SRV record has changed */
		if (!srv->srvrq) {
			chunk_appendf(msg, ", no SRV resolution for server '%s'. Previous state not applied", srv->id);
			goto out;
		}
		if (strcmp(srv->srvrq->name, srvrecord) != 0) {
			chunk_appendf(msg, ", SRV record mismatch between configuration ('%s') and state file ('%s) for server '%s'. Previous state not applied", srv->srvrq->name, srvrecord, srv->id);
			goto out;
		}

		/* prepare DNS resolution for this server */
		res = srv_prepare_for_resolution(srv, fqdn);
		if (res == -1) {
			chunk_appendf(msg, ", can't allocate memory for DNS resolution for server '%s'", srv->id);
			goto out;
		}

		/* Remove from available list and insert in tree
		 * since this server has an hostname
		 */
		LIST_DEL_INIT(&srv->srv_rec_item);
		srv->host_dn.key = tmp = strdup(srv->hostname_dn);

		/* convert the key in lowercase because tree
		 * lookup is case sensitive but we don't care
		 */
		for (i = 0; tmp[i]; i++)
			tmp[i] = tolower((unsigned char)tmp[i]);

		/* insert in tree and set the srvrq expiration date */
		ebis_insert(&srv->srvrq->named_servers, &srv->host_dn);
		task_schedule(srv->srvrq_check, tick_add(now_ms, srv->srvrq->resolvers->timeout.resolve +
							 srv->srvrq->resolvers->resolve_retries *
							 srv->srvrq->resolvers->timeout.retry));

		/* Unset SRV_F_MAPPORTS for SRV records.
		 * SRV_F_MAPPORTS is unfortunately set by parse_server()
		 * because no ports are provided in the configuration file.
		 * This is because HAProxy will use the port found into the SRV record.
		 */
		srv->flags &= ~SRV_F_MAPPORTS;
	}

	if (port_st)
		srv->svc_port = port_svc;


	if (params[16]) {
#ifdef USE_OPENSSL
		use_ssl = strtol(params[16], &p, 10);

		/* configure ssl if connection has been initiated at startup */
		if (srv->ssl_ctx.ctx != NULL)
			srv_set_ssl(srv, use_ssl);
#endif
	}

	port_st = NULL;
	if (params[17] && strcmp(params[17], "0") != 0)
		port_st = params[17];
	addr = NULL;
	if (params[18] && strcmp(params[18], "-") != 0)
		addr = params[18];
	if (addr || port_st) {
		warning = srv_update_check_addr_port(srv, addr, port_st);
		if (warning) {
			chunk_appendf(msg, ", %s", warning);
			goto out;
		}
	}

	port_st = NULL;
	if (params[20] && strcmp(params[20], "0") != 0)
		port_st = params[20];
	addr = NULL;
	if (params[19] && strcmp(params[19], "-") != 0)
		addr = params[19];
	if (addr || port_st) {
		warning = srv_update_agent_addr_port(srv, addr, port_st);
		if (warning) {
			chunk_appendf(msg, ", %s", warning);
			goto out;
		}
	}

  out:
	HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	if (msg->data) {
		if (partial_apply == 1)
			ha_warning("server-state partially applied for server '%s/%s'%s\n",
				   srv->proxy->id, srv->id, msg->area);
		else
			ha_warning("server-state application failed for server '%s/%s'%s\n",
				   srv->proxy->id, srv->id, msg->area);
	}
  end:
	free_trash_chunk(msg);
}

/*
 * Loop on the proxy's servers and try to load its state from <st_tree> using
 * srv_state_srv_update(). The proxy name and the server name are concatenated
 * to form the key. If found the entry is removed from the tree.
 */
static void srv_state_px_update(const struct proxy *px, int vsn, struct eb_root *st_tree)
{
	struct server_state_line *st_line;
	struct eb64_node *node;
	struct server *srv;
	unsigned long key;

	for (srv = px->srv; srv; srv = srv->next) {
		chunk_printf(&trash, "%s %s", px->id, srv->id);
		key = XXH3(trash.area, trash.data, 0);
		node = eb64_lookup(st_tree, key);
		if (!node)
			continue; /* next server */
		st_line = eb64_entry(node, typeof(*st_line), node);
		srv_state_srv_update(srv, vsn, st_line->params+4);

		/* the node may be released now */
		eb64_delete(node);
		free(st_line->line);
		free(st_line);
	}
}

/*
 * read next line from file <f> and return the server state version if one found.
 * If file is empty, then -1 is returned
 * If no version is found, then 0 is returned
 * Note that this should be the first read on <f>
 */
static int srv_state_get_version(FILE *f) {
	char mybuf[SRV_STATE_LINE_MAXLEN];
	char *endptr;
	long int vsn;

	/* first character of first line of the file must contain the version of the export */
	if (fgets(mybuf, SRV_STATE_LINE_MAXLEN, f) == NULL)
		return -1;

	vsn = strtol(mybuf, &endptr, 10);
	if (endptr == mybuf || *endptr != '\n') {
		/* Empty or truncated line */
		return 0;
	}

	if (vsn < SRV_STATE_FILE_VERSION_MIN || vsn > SRV_STATE_FILE_VERSION_MAX) {
		/* Wrong version number */
		return 0;
	}

	return vsn;
}


/*
 * parses server state line stored in <buf> and supposedly in version <version>.
 * Set <params> accordingly on success. It returns 1 on success, 0 if the line
 * must be ignored and -1 on error.
 * The caller must provide a supported version
 */
static int srv_state_parse_line(char *buf, const int version, char **params)
{
	int buflen, arg, ret;
	char *cur;

	buflen = strlen(buf);
	cur = buf;
	ret = 1; /* be optimistic and pretend a success */

	/* we need at least one character and a non-truncated line */
	if (buflen == 0 || buf[buflen - 1] != '\n') {
		ret = -1;
		goto out;
	}

	/* skip blank characters at the beginning of the line */
	while (*cur == ' ' || *cur == '\t')
		++cur;

	/* ignore empty or commented lines */
	if (!*cur || *cur == '\n' || *cur == '#') {
		ret = 0;
		goto out;
	}

	/* Removes trailing '\n' to ease parsing */
	buf[buflen - 1] = '\0';

	/* we're now ready to move the line into <params> */
	memset(params, 0, SRV_STATE_FILE_MAX_FIELDS * sizeof(*params));
	arg = 0;
	while (*cur) {
		/* first of all, stop if there are too many fields */
		if (arg >= SRV_STATE_FILE_MAX_FIELDS)
			break;

		/* then skip leading spaces */
		while (*cur && (*cur == ' ' || *cur == '\t')) {
			++cur;
			if (!*cur)
				break;
		}

		/*
		 * idx:
		 *   be_id:                params[0]
		 *   be_name:              params[1]
		 *   srv_id:               params[2]
		 *   srv_name:             params[3]
		 * v1
		 *   srv_addr:             params[4]
		 *   srv_op_state:         params[5]
		 *   srv_admin_state:      params[6]
		 *   srv_uweight:          params[7]
		 *   srv_iweight:          params[8]
		 *   srv_last_time_change: params[9]
		 *   srv_check_status:     params[10]
		 *   srv_check_result:     params[11]
		 *   srv_check_health:     params[12]
		 *   srv_check_state:      params[13]
		 *   srv_agent_state:      params[14]
		 *   bk_f_forced_id:       params[15]
		 *   srv_f_forced_id:      params[16]
		 *   srv_fqdn:             params[17]
		 *   srv_port:             params[18]
		 *   srvrecord:            params[19]
		 *
		 *   srv_use_ssl:          params[20]  (optional field)
		 *   srv_check_port:       params[21]  (optional field)
		 *   srv_check_addr:       params[22]  (optional field)
		 *   srv_agent_addr:       params[23]  (optional field)
		 *   srv_agent_port:       params[24]  (optional field)
		 *
		 */
		params[arg++] = cur;

		/* look for the end of the current field */
		while (*cur && *cur != ' ' && *cur != '\t') {
			++cur;
			if (!*cur)
				break;
		}

		/* otherwise, cut the field and move to the next one */
		*cur++ = '\0';
	}

	/* if the number of fields does not match the version, then return an error */
	if (version == 1 &&
	    (arg < SRV_STATE_FILE_MIN_FIELDS_VERSION_1 ||
	     arg > SRV_STATE_FILE_MAX_FIELDS_VERSION_1))
		ret = -1;

  out:
	return ret;
}


/*
 * parses a server state line using srv_state_parse_line() and store the result
 * in <st_tree>. If an error occurred during the parsing, the line is
 * ignored. if <px> is defined, it is used to check the backend id/name against
 * the parsed params and to compute the key of the line.
 */
static int srv_state_parse_and_store_line(char *line, int vsn, struct eb_root *st_tree,
					  struct proxy *px)
{
	struct server_state_line *st_line;
	int ret = 0;

	/* store line in tree and duplicate the line */
	st_line = calloc(1, sizeof(*st_line));
	if (st_line == NULL)
		goto skip_line;
	st_line->line = strdup(line);
	if (st_line->line == NULL)
		goto skip_line;

	ret = srv_state_parse_line(st_line->line, vsn, st_line->params);
	if (ret <= 0)
		goto skip_line;

	/* Check backend name against params if <px> is defined */
	if (px) {
		int check_id = (atoi(st_line->params[0]) == px->uuid);
		int check_name = (strcmp(px->id, st_line->params[1]) == 0);
		int bk_f_forced_id = (atoi(st_line->params[15]) & PR_O_FORCED_ID);


		if (!check_id && !check_name) {
			/* backend does not match at all: skip the line */
			goto skip_line;
		}
		else if (!check_id) {
			/* Id mismatch: warn but continue */
			ha_warning("Proxy '%s': backend ID mismatch: from server state file: '%s', from running config '%d'\n",
				   px->id, st_line->params[0], px->uuid);
			send_log(px, LOG_NOTICE, "backend ID mismatch: from server state file: '%s', from running config '%d'\n",
				 st_line->params[0], px->uuid);
		}
		else if (!check_name) {
			/* Name mismatch: warn and skip the line, except if the backend id was forced
			 * in the previous configuration */
			ha_warning("Proxy '%s': backend name mismatch: from server state file: '%s', from running config '%s'\n",
				   px->id, st_line->params[1], px->id);
			send_log(px, LOG_NOTICE, "backend name mismatch: from server state file: '%s', from running config '%s'\n",
				 st_line->params[1], px->id);
			if (!bk_f_forced_id)
				goto skip_line;
		}
	}

	/*
	 * The key: "be_name srv_name"
	 *   if <px> is defined:  be_name == px->id
	 *   otherwise: be_name == params[1]
	 */
	chunk_printf(&trash, "%s %s", (px ? px->id : st_line->params[1]), st_line->params[3]);
	st_line->node.key = XXH3(trash.area, trash.data, 0);
	if (eb64_insert(st_tree, &st_line->node) != &st_line->node) {
		/* this is a duplicate key, probably a hand-crafted file, drop it! */
		goto skip_line;
	}

	return ret;

  skip_line:
	/* free up memory in case of error during the processing of the line */
	if (st_line) {
		free(st_line->line);
		free(st_line);
	}
	return ret;
}

/* Helper function to get the server-state file path.
 * If <filename> starts with a '/', it is considered as an absolute path. In
 * this case or if <global.server_state_base> is not set, <filename> only is
 * considered. Otherwise, the <global.server_state_base> is concatenated to
 * <filename> to produce the file path and copied to <dst_path>. in both cases,
 * the result must not exceeds <maxpathlen>.
 *
 * The len is returned on success or -1 if the path is too long. On error, the
 * caller must not rely on <dst_path>.
 */
static inline int srv_state_get_filepath(char *dst_path, int maxpathlen, const char *filename)
{
	char *sep;
	int len = 0;

	/* create the globalfilepath variable */
	if (*filename == '/' || !global.server_state_base) {
		/* absolute path or no base directory provided */
		len = strlcpy2(dst_path, filename, maxpathlen);
	}
	else {
		/* concat base directory and global server-state file */
		sep = (global.server_state_base[strlen(global.server_state_base)-1] != '/' ? "/":  "");
		len = snprintf(dst_path, maxpathlen, "%s%s%s", global.server_state_base, sep, filename);
	}
	return (len < maxpathlen ? len: -1);
}


/* This function parses all the proxies and only take care of the backends (since we're looking for server)
 * For each proxy, it does the following:
 *  - opens its server state file (either one or local one)
 *  - read whole file, line by line
 *  - analyse each line to check if it matches our current backend:
 *    - backend name matches
 *    - backend id matches if id is forced and name doesn't match
 *  - if the server pointed by the line is found, then state is applied
 *
 * If the running backend uuid or id differs from the state file, then HAProxy reports
 * a warning.
 *
 * Grabs the server's lock via srv_state_srv_update().
 */
void apply_server_state(void)
{
	/* tree where global state_file is loaded */
	struct eb_root global_state_tree = EB_ROOT_UNIQUE;
	struct proxy *curproxy;
	struct server_state_line *st_line;
	struct eb64_node *node, *next_node;
	FILE *f;
	char mybuf[SRV_STATE_LINE_MAXLEN];
	char file[MAXPATHLEN];
	int local_vsn, global_vsn, len, linenum;

	global_vsn = 0; /* no global file */
	if (!global.server_state_file)
		goto no_globalfile;
	len = srv_state_get_filepath(file, MAXPATHLEN, global.server_state_file);
	if (len == -1) {
		ha_warning("config: Can't load global server state file: file too long.\n");
		goto no_globalfile;
	}

	/* Load global server state in a tree */
	errno = 0;
	f = fopen(file, "r");
	if (!f) {
		if (errno == ENOENT)
			ha_notice("config: Can't open global server state file '%s': %s\n", file, strerror(errno));
		else
			ha_warning("config: Can't open global server state file '%s': %s\n", file, strerror(errno));
		goto no_globalfile;
	}

	global_vsn = srv_state_get_version(f);
	if (global_vsn < 1) {
		if (global_vsn == -1)
			ha_notice("config: Empty global server state file '%s'.\n",
				   file);
		if (global_vsn == 0)
			ha_warning("config: Can't get version of the global server state file '%s'.\n",
				   file);
		goto close_globalfile;
	}

	for (linenum = 1; fgets(mybuf, SRV_STATE_LINE_MAXLEN, f); linenum++) {
		int ret;

		ret = srv_state_parse_and_store_line(mybuf, global_vsn, &global_state_tree, NULL);
		if (ret == -1) {
			ha_warning("config: corrupted global server state file '%s' at line %d.\n",
				   file, linenum);
			global_vsn = 0;
			break;
		}
	}

  close_globalfile:
	fclose(f);

  no_globalfile:
	/* parse all proxies and load states form tree (global file) or from local file */
	for (curproxy = proxies_list; curproxy != NULL; curproxy = curproxy->next) {
		struct eb_root local_state_tree = EB_ROOT_UNIQUE;

		/* Must be an enabled backend with at least a server */
		if (!(curproxy->cap & PR_CAP_BE) || (curproxy->flags & (PR_FL_DISABLED|PR_FL_STOPPED)) || !curproxy->srv)
			continue; /* next proxy */

		/* Mode must be specified */
		BUG_ON(curproxy->load_server_state_from_file == PR_SRV_STATE_FILE_UNSPEC);

		/* No server-state file for this proxy */
		if (curproxy->load_server_state_from_file == PR_SRV_STATE_FILE_NONE)
			continue;  /* next proxy */

		if (curproxy->load_server_state_from_file == PR_SRV_STATE_FILE_GLOBAL) {
			/* when global file is used, we get data from the tree
			 * Note that in such case we don't check backend name neither uuid.
			 * Backend name can't be wrong since it's used as a key to retrieve the server state
			 * line from the tree.
			 */
			if (global_vsn)
				srv_state_px_update(curproxy, global_vsn, &global_state_tree);
			continue; /* next proxy */
		}

		/*
		 * Here we load a local server state-file
		 */

		/* create file variable */
		len = srv_state_get_filepath(file, MAXPATHLEN, curproxy->server_state_file_name);
		if (len == -1) {
			ha_warning("Proxy '%s': Can't load local server state file: file too long.\n", curproxy->id);
			continue; /* next proxy */
		}

		/* Load local server state in a tree */
		errno = 0;
		f = fopen(file, "r");
		if (!f) {
			if (errno == ENOENT)
				ha_notice("Proxy '%s': Can't open server state file '%s': %s.\n",
					   curproxy->id, file, strerror(errno));
			else
				ha_warning("Proxy '%s': Can't open server state file '%s': %s.\n",
					   curproxy->id, file, strerror(errno));
			continue; /* next proxy */
		}

		/* first character of first line of the file must contain the version of the export */
		local_vsn = srv_state_get_version(f);
		if (local_vsn < 1) {
			if (local_vsn == -1)
				ha_notice("Proxy '%s': Empty server state file '%s'.\n",
					   curproxy->id, file);
			if (local_vsn == 0)
				ha_warning("Proxy '%s': Can't get version of the server state file '%s'.\n",
					   curproxy->id, file);
			goto close_localfile;
		}

		/* First, parse lines of the local server-state file and store them in a eb-tree */
		for (linenum = 1; fgets(mybuf, SRV_STATE_LINE_MAXLEN, f); linenum++) {
			int ret;

			ret = srv_state_parse_and_store_line(mybuf, local_vsn, &local_state_tree, curproxy);
			if (ret == -1) {
				ha_warning("Proxy '%s': corrupted server state file '%s' at line %d.\n",
					   curproxy->id, file, linenum);
				local_vsn = 0;
				break;
			}
		}

		if (local_vsn)
			srv_state_px_update(curproxy, local_vsn, &local_state_tree);

		/* Remove unused server-state lines */
		node = eb64_first(&local_state_tree);
		while (node) {
			st_line = eb64_entry(node, typeof(*st_line), node);
			next_node = eb64_next(node);
			eb64_delete(node);

			if (local_vsn) {
				/* if no server found, then warn */
				ha_warning("Proxy '%s': can't find server '%s' in backend '%s'\n",
					   curproxy->id, st_line->params[3], curproxy->id);
				send_log(curproxy, LOG_NOTICE, "can't find server '%s' in backend '%s'\n",
					 st_line->params[3], curproxy->id);
			}

			free(st_line->line);
			free(st_line);
			node = next_node;
		}

	close_localfile:
		fclose(f);
	}

	node = eb64_first(&global_state_tree);
        while (node) {
                st_line = eb64_entry(node, typeof(*st_line), node);
                next_node = eb64_next(node);
                eb64_delete(node);
		free(st_line->line);
		free(st_line);
                node = next_node;
        }
}
