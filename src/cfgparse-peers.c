/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Configuration parser for peers section
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/peers.h>
#include <haproxy/proxy.h>
#include <haproxy/server.h>
#include <haproxy/stick_table.h>
#include <haproxy/tools.h>

/* Allocate and initialize the frontend of a "peers" section found in
 * file <file> at line <linenum> with <id> as ID.
 * Return 0 if succeeded, -1 if not.
 * Note that this function may be called from "default-server"
 * or "peer" lines.
 */
static int init_peers_frontend(const char *file, int linenum,
                               const char *id, struct peers *peers)
{
	struct proxy *p;
	char *errmsg = NULL;

	if (peers->peers_fe) {
		p = peers->peers_fe;
		goto out;
	}

	p = alloc_new_proxy(NULL, PR_CAP_FE | PR_CAP_BE, &errmsg);
	if (!p) {
		ha_alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
		ha_free(&errmsg);
		return -1;
	}

	peers_setup_frontend(p);
	p->parent = peers;
	/* Finally store this frontend. */
	peers->peers_fe = p;

 out:
	if (id && !p->id)
		p->id = strdup(id);
	drop_file_name(&p->conf.file);
	p->conf.args.file = p->conf.file = copy_file_name(file);
	if (linenum != -1)
		p->conf.args.line = p->conf.line = linenum;

	return 0;
}

/* Only change ->file, ->line and ->arg struct bind_conf member values
 * if already present.
 */
static struct bind_conf *bind_conf_uniq_alloc(struct proxy *p,
                                              const char *file, int line,
                                              const char *arg, struct xprt_ops *xprt)
{
	struct bind_conf *bind_conf;

	if (!LIST_ISEMPTY(&p->conf.bind)) {
		bind_conf = LIST_ELEM((&p->conf.bind)->n, typeof(bind_conf), by_fe);
		/*
		 * We keep bind_conf->file and bind_conf->line unchanged
		 * to make them available for error messages
		 */
		if (arg) {
			free(bind_conf->arg);
			bind_conf->arg = strdup(arg);
		}
	}
	else {
		bind_conf = bind_conf_alloc(p, file, line, arg, xprt);
	}

	return bind_conf;
}

/*
 * Allocate a new struct peer parsed at line <linenum> in file <file>
 * to be added to <peers>.
 * Returns the new allocated structure if succeeded, NULL if not.
 */
static struct peer *cfg_peers_add_peer(struct peers *peers,
                                       const char *file, int linenum,
                                       const char *id, int local)
{
	struct peer *p;

	p = calloc(1, sizeof *p);
	if (!p) {
		ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
		return NULL;
	}

	/* the peers are linked backwards first */
	peers->count++;
	p->peers = peers;
	p->next = peers->remote;
	peers->remote = p;
	p->conf.file = strdup(file);
	p->conf.line = linenum;
	p->last_change = ns_to_sec(now_ns);
	HA_SPIN_INIT(&p->lock);
	if (id)
		p->id = strdup(id);
	if (local) {
		p->local = 1;
		peers->local = p;
	}

	return p;
}

/*
 * Parse a line in a <peers> section.
 * Returns the error code, 0 if OK, or any combination of :
 *  - ERR_ABORT: must abort ASAP
 *  - ERR_FATAL: we can continue parsing but not start the service
 *  - ERR_WARN: a warning has been emitted
 *  - ERR_ALERT: an alert has been emitted
 * Only the two first ones can stop processing, the two others are just
 * indicators.
 */
int cfg_parse_peers(const char *file, int linenum, char **args, int kwm)
{
	static struct peers *curpeers = NULL;
	static struct sockaddr_storage *bind_addr = NULL;
	static int nb_shards = 0;
	struct peer *newpeer = NULL;
	const char *err;
	struct bind_conf *bind_conf;
	int err_code = 0;
	char *errmsg = NULL;
	static int bind_line, peer_line;

	if (strcmp(args[0], "bind") == 0 || strcmp(args[0], "default-bind") == 0) {
		int cur_arg;
		struct bind_conf *bind_conf;
		int ret;

		cur_arg = 1;

		if (init_peers_frontend(file, linenum, NULL, curpeers) != 0) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		bind_conf = bind_conf_uniq_alloc(curpeers->peers_fe, file, linenum,
		                                 args[1], xprt_get(XPRT_RAW));
		if (!bind_conf) {
			ha_alert("parsing [%s:%d] : '%s %s' : cannot allocate memory.\n", file, linenum, args[0], args[1]);
			err_code |= ERR_FATAL;
			goto out;
		}

		bind_conf->maxaccept = 1;
		bind_conf->accept = session_accept_fd;
		bind_conf->options |= BC_O_UNLIMITED; /* don't make the peers subject to global limits */

		if (*args[0] == 'b') {
			struct listener *l;

			if (peer_line) {
				ha_alert("parsing [%s:%d] : mixing \"peer\" and \"bind\" line is forbidden\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			if (!LIST_ISEMPTY(&bind_conf->listeners)) {
				ha_alert("parsing [%s:%d] : One listener per \"peers\" section is authorized but another is already configured at [%s:%d].\n", file, linenum, bind_conf->file, bind_conf->line);
				err_code |= ERR_FATAL;
			}

			if (!str2listener(args[1], curpeers->peers_fe, bind_conf, file, linenum, &errmsg)) {
				if (errmsg && *errmsg) {
					indent_msg(&errmsg, 2);
					ha_alert("parsing [%s:%d] : '%s %s' : %s\n", file, linenum, args[0], args[1], errmsg);
				}
				else
					ha_alert("parsing [%s:%d] : '%s %s' : error encountered while parsing listening address %s.\n",
							 file, linenum, args[0], args[1], args[1]);
				err_code |= ERR_FATAL;
				goto out;
			}

			/* Only one listener supported. Compare first listener
			 * against the last one. It must be the same one.
			 */
			if (bind_conf->listeners.n != bind_conf->listeners.p) {
				ha_alert("parsing [%s:%d] : Only one listener per \"peers\" section is authorized. Multiple listening addresses or port range are not supported.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			/*
			 * Newly allocated listener is at the end of the list
			 */
			l = LIST_ELEM(bind_conf->listeners.p, typeof(l), by_bind);
			bind_addr = &l->rx.addr;

			global.maxsock++; /* for the listening socket */

			bind_line = 1;
			if (cfg_peers->local) {
				/* Local peer already defined using "server" line has no
				 * address yet, we should update its server's addr:port
				 * settings
				 */
				newpeer = cfg_peers->local;
				BUG_ON(!newpeer->srv);
				newpeer->srv->addr = *bind_addr;
				newpeer->srv->svc_port = get_host_port(bind_addr);
			}
			else {
				/* This peer is local.
				 * Note that we do not set the peer ID. This latter is initialized
				 * when parsing "peer" or "server" line.
				 */
				newpeer = cfg_peers_add_peer(curpeers, file, linenum, NULL, 1);
				if (!newpeer) {
					err_code |= ERR_ALERT | ERR_ABORT;
					goto out;
				}
			}
			cur_arg++;
		}

		ret = bind_parse_args_list(bind_conf, args, cur_arg, cursection, file, linenum);
		err_code |= ret;
		if (ret != 0)
			goto out;
	}
	else if (strcmp(args[0], "default-server") == 0) {
		if (init_peers_frontend(file, -1, NULL, curpeers) != 0) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		err_code |= parse_server(file, linenum, args, curpeers->peers_fe, NULL,
		                         SRV_PARSE_DEFAULT_SERVER|SRV_PARSE_IN_PEER_SECTION|SRV_PARSE_INITIAL_RESOLVE);
	}
	else if (strcmp(args[0], "log") == 0) {
		if (init_peers_frontend(file, linenum, NULL, curpeers) != 0) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		if (!parse_logger(args, &curpeers->peers_fe->loggers, (kwm == KWM_NO), file, linenum, &errmsg)) {
			ha_alert("parsing [%s:%d] : %s : %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "peers") == 0) { /* new peers section */
		/* Initialize these static variables when entering a new "peers" section*/
		bind_line = peer_line = 0;
		bind_addr = NULL;
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : missing name for peers section.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
				 file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		for (curpeers = cfg_peers; curpeers != NULL; curpeers = curpeers->next) {
			/*
			 * If there are two proxies with the same name only following
			 * combinations are allowed:
			 */
			if (strcmp(curpeers->id, args[1]) == 0) {
				ha_alert("Parsing [%s:%d]: peers section '%s' has the same name as another peers section declared at %s:%d.\n",
					 file, linenum, args[1], curpeers->conf.file, curpeers->conf.line);
				err_code |= ERR_ALERT | ERR_FATAL;
			}
		}

		if ((curpeers = calloc(1, sizeof(*curpeers))) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		curpeers->next = cfg_peers;
		cfg_peers = curpeers;
		curpeers->conf.file = strdup(file);
		curpeers->conf.line = linenum;
		curpeers->last_change = ns_to_sec(now_ns);
		curpeers->id = strdup(args[1]);
		curpeers->disabled = 0;
	}
	else if (strcmp(args[0], "peer") == 0 ||
	         strcmp(args[0], "server") == 0) { /* peer or server definition */
		struct server *prev_srv;
		int local_peer, peer;
		int parse_addr = 0;

		peer = *args[0] == 'p';
		local_peer = strcmp(args[1], localpeer) == 0;
		/* The local peer may have already partially been parsed on a "bind" line. */
		if (*args[0] == 'p') {
			if (bind_line) {
				ha_alert("parsing [%s:%d] : mixing \"peer\" and \"bind\" line is forbidden\n", file, linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			peer_line = 1;
		}
		if (cfg_peers->local && !cfg_peers->local->id && local_peer) {
			/* The local peer has already been initialized on a "bind" line.
			 * Let's use it and store its ID.
			 */
			newpeer = cfg_peers->local;
			newpeer->id = strdup(localpeer);
		}
		else {
			if (local_peer && cfg_peers->local) {
				ha_alert("parsing [%s:%d] : '%s %s' : local peer name already referenced at %s:%d. %s\n",
				         file, linenum, args[0], args[1],
				 curpeers->peers_fe->conf.file, curpeers->peers_fe->conf.line, cfg_peers->local->id);
				err_code |= ERR_FATAL;
				goto out;
			}
			newpeer = cfg_peers_add_peer(curpeers, file, linenum, args[1], local_peer);
			if (!newpeer) {
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
		}

		/* Line number and peer ID are updated only if this peer is the local one. */
		if (init_peers_frontend(file,
		                        newpeer->local ? linenum: -1,
		                        newpeer->local ? newpeer->id : NULL,
		                        curpeers) != 0) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		/* This initializes curpeer->peers->peers_fe->srv.
		 * The server address is parsed only if we are parsing a "peer" line,
		 * or if we are parsing a "server" line and the current peer is not the local one.
		 */
		parse_addr = (peer || !local_peer) ? SRV_PARSE_PARSE_ADDR : 0;
		prev_srv = curpeers->peers_fe->srv;
		err_code |= parse_server(file, linenum, args, curpeers->peers_fe, NULL,
		                         SRV_PARSE_IN_PEER_SECTION|parse_addr|SRV_PARSE_INITIAL_RESOLVE);
		if (curpeers->peers_fe->srv == prev_srv) {
			/* parse_server didn't add a server:
			 * Remove the newly allocated peer.
			 */
			struct peer *p;

			/* while it is tolerated to have a "server" line without address, it isn't
			 * the case for a "peer" line
			 */
			if (peer) {
				ha_warning("parsing [%s:%d] : '%s %s' : ignoring invalid peer definition (missing address:port)\n",
				           file, linenum, args[0], args[1]);
				err_code |= ERR_WARN;
			}
			else {
				ha_diag_warning("parsing [%s:%d] : '%s %s' : ignoring server (not a local peer, valid address:port is expected)\n",
				                file, linenum, args[0], args[1]);
			}

			p = curpeers->remote;
			curpeers->remote = curpeers->remote->next;
			free(p->id);
			free(p);
			if (local_peer) {
				/* we only get there with incomplete "peer"
				 * line for local peer (missing address):
				 *
				 * reset curpeers and curpeers fields
				 * that are local peer related
				 */
				curpeers->local = NULL;
				ha_free(&curpeers->peers_fe->id);
			}
			goto out;
		}

		if (!parse_addr && bind_addr) {
			/* local peer declared using "server": has name but no
			 * address: we use the known "bind" line addr settings
			 * as implicit server's addr and port.
			 */
			curpeers->peers_fe->srv->addr = *bind_addr;
			curpeers->peers_fe->srv->svc_port = get_host_port(bind_addr);
		}

		if (nb_shards && curpeers->peers_fe->srv->shard > nb_shards) {
			ha_warning("parsing [%s:%d] : '%s %s' : %d peer shard greater value than %d shards value is ignored.\n",
			           file, linenum, args[0], args[1], curpeers->peers_fe->srv->shard, nb_shards);
			curpeers->peers_fe->srv->shard = 0;
			err_code |= ERR_WARN;
		}

		if (curpeers->peers_fe->srv->init_addr_methods || curpeers->peers_fe->srv->resolvers_id ||
		    curpeers->peers_fe->srv->do_check || curpeers->peers_fe->srv->do_agent) {
			ha_warning("parsing [%s:%d] : '%s %s' : init_addr, resolvers, check and agent are ignored for peers.\n", file, linenum, args[0], args[1]);
			err_code |= ERR_WARN;
		}

		HA_SPIN_INIT(&newpeer->lock);

		newpeer->srv = curpeers->peers_fe->srv;
		if (!newpeer->local)
			goto out;

		/* The lines above are reserved to "peer" lines. */
		if (*args[0] == 's')
			goto out;

		bind_conf = bind_conf_uniq_alloc(curpeers->peers_fe, file, linenum, args[2], xprt_get(XPRT_RAW));
		if (!bind_conf) {
			ha_alert("parsing [%s:%d] : '%s %s' : Cannot allocate memory.\n", file, linenum, args[0], args[1]);
			err_code |= ERR_FATAL;
			goto out;
		}

		bind_conf->maxaccept = 1;
		bind_conf->accept = session_accept_fd;
		bind_conf->options |= BC_O_UNLIMITED; /* don't make the peers subject to global limits */

		if (!LIST_ISEMPTY(&bind_conf->listeners)) {
			ha_alert("parsing [%s:%d] : One listener per \"peers\" section is authorized but another is already configured at [%s:%d].\n", file, linenum, bind_conf->file, bind_conf->line);
			err_code |= ERR_FATAL;
		}

		if (!str2listener(args[2], curpeers->peers_fe, bind_conf, file, linenum, &errmsg)) {
			if (errmsg && *errmsg) {
				indent_msg(&errmsg, 2);
				ha_alert("parsing [%s:%d] : '%s %s' : %s\n", file, linenum, args[0], args[1], errmsg);
			}
			else
				ha_alert("parsing [%s:%d] : '%s %s' : error encountered while parsing listening address %s.\n",
				         file, linenum, args[0], args[1], args[2]);
			err_code |= ERR_FATAL;
			goto out;
		}

		global.maxsock++; /* for the listening socket */
	}
	else if (strcmp(args[0], "shards") == 0) {
		char *endptr;

		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' : missing value\n", file, linenum, args[0]);
			err_code |= ERR_FATAL;
			goto out;
		}

		curpeers->nb_shards = strtol(args[1], &endptr, 10);
		if (*endptr != '\0') {
			ha_alert("parsing [%s:%d] : '%s' : expects an integer argument, found '%s'\n",
			         file, linenum, args[0], args[1]);
			err_code |= ERR_FATAL;
			goto out;
		}

		if (!curpeers->nb_shards) {
			ha_alert("parsing [%s:%d] : '%s' : expects a strictly positive integer argument\n",
			         file, linenum, args[0]);
			err_code |= ERR_FATAL;
			goto out;
		}

		nb_shards = curpeers->nb_shards;
	}
	else if (strcmp(args[0], "table") == 0) {
		struct stktable *t, *other;
		char *id;
		size_t prefix_len;

		/* Line number and peer ID are updated only if this peer is the local one. */
		if (init_peers_frontend(file, -1, NULL, curpeers) != 0) {
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		/* Build the stick-table name, concatenating the "peers" section name
		 * followed by a '/' character and the table name argument.
		 */
		chunk_reset(&trash);
		if (!chunk_strcpy(&trash, curpeers->id)) {
			ha_alert("parsing [%s:%d]: '%s %s' : stick-table name too long.\n",
			         file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		prefix_len = trash.data;
		if (!chunk_memcat(&trash, "/", 1) || !chunk_strcat(&trash, args[1])) {
			ha_alert("parsing [%s:%d]: '%s %s' : stick-table name too long.\n",
			         file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		t = calloc(1, sizeof *t);
		id = strdup(trash.area);
		if (!t || !id) {
			ha_alert("parsing [%s:%d]: '%s %s' : memory allocation failed\n",
			         file, linenum, args[0], args[1]);
			free(t);
			free(id);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		other = stktable_find_by_name(trash.area);
		if (other) {
			ha_alert("parsing [%s:%d] : stick-table name '%s' conflicts with table declared in %s '%s' at %s:%d.\n",
			         file, linenum, args[1],
			         other->proxy ? proxy_cap_str(other->proxy->cap) : "peers",
			         other->proxy ? other->id : other->peers.p->id,
			         other->conf.file, other->conf.line);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}


		err_code |= parse_stick_table(file, linenum, args, t, id, id + prefix_len, curpeers);
		if (err_code & ERR_FATAL) {
			free(t);
			free(id);
			goto out;
		}

		stktable_store_name(t);
		t->next = stktables_list;
		stktables_list = t;
	}
	else if (strcmp(args[0], "disabled") == 0) {  /* disables this peers section */
		curpeers->disabled |= PR_FL_DISABLED;
	}
	else if (strcmp(args[0], "enabled") == 0) {  /* enables this peers section (used to revert a disabled default) */
		curpeers->disabled = 0;
	}
	else if (*args[0] != 0) {
		struct peers_kw_list *pkwl;
		int index;
		int rc = -1;

		list_for_each_entry(pkwl, &peers_keywords.list, list) {
			for (index = 0; pkwl->kw[index].kw != NULL; index++) {
				if (strcmp(pkwl->kw[index].kw, args[0]) == 0) {
					rc = pkwl->kw[index].parse(args, curpeers, file, linenum, &errmsg);
					if (rc < 0) {
						ha_alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					else if (rc > 0) {
						ha_warning("parsing [%s:%d] : %s\n", file, linenum, errmsg);
						err_code |= ERR_WARN;
						goto out;
					}
					goto out;
				}
			}
		}

		ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], cursection);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

out:
	free(errmsg);
	return err_code;
}

REGISTER_CONFIG_SECTION("peers", cfg_parse_peers, NULL);
