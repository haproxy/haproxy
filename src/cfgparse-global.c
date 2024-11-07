#define _GNU_SOURCE  /* for cpu_set_t from haproxy/cpuset.h */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include <import/sha1.h>

#include <haproxy/buf.h>
#include <haproxy/cfgparse.h>
#ifdef USE_CPU_AFFINITY
#include <haproxy/cpuset.h>
#endif
#include <haproxy/compression.h>
#include <haproxy/global.h>
#include <haproxy/log.h>
#include <haproxy/peers.h>
#include <haproxy/protocol.h>
#include <haproxy/stress.h>
#include <haproxy/tools.h>

int cluster_secret_isset;

/* some keywords that are still being parsed using strcmp() and are not
 * registered anywhere. They are used as suggestions for mistyped words.
 */
static const char *common_kw_list[] = {
	"global", "busy-polling", "set-dumpable",
	"insecure-fork-wanted", "insecure-setuid-wanted", "nosplice",
	"nogetaddrinfo", "noreuseport", "uid", "gid",
	"external-check", "user", "group", "maxconn",
	"ssl-server-verify", "maxconnrate", "maxsessrate", "maxsslrate",
	"maxcomprate", "maxpipes", "maxzlibmem", "maxcompcpuusage", "ulimit-n",
	"description", "node", "unix-bind", "log",
	"log-send-hostname", "server-state-base", "server-state-file",
	"log-tag", "spread-checks", "max-spread-checks", "cpu-map",
	"strict-limits",
	"numa-cpu-mapping", "defaults", "listen", "frontend", "backend",
	"peers", "resolvers", "cluster-secret", "no-quic", "limited-quic",
	"stats-file",
	NULL /* must be last */
};

/*
 * parse a line in a <global> section. Returns the error code, 0 if OK, or
 * any combination of :
 *  - ERR_ABORT: must abort ASAP
 *  - ERR_FATAL: we can continue parsing but not start the service
 *  - ERR_WARN: a warning has been emitted
 *  - ERR_ALERT: an alert has been emitted
 * Only the two first ones can stop processing, the two others are just
 * indicators.
 */
int cfg_parse_global(const char *file, int linenum, char **args, int kwm)
{
	int err_code = 0;
	char *errmsg = NULL;

	if (strcmp(args[0], "global") == 0) {  /* new section */
		/* no option, nothing special to do */
		alertif_too_many_args(0, file, linenum, args, &err_code);
		goto out;
	}

	if (global.mode & MODE_DISCOVERY)
		goto discovery_kw;

	else if (strcmp(args[0], "limited-quic") == 0) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;

		global.tune.options |= GTUNE_LIMITED_QUIC;
	}
	else if (strcmp(args[0], "no-quic") == 0) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;

		global.tune.options |= GTUNE_NO_QUIC;
	}
	else if (strcmp(args[0], "busy-polling") == 0) { /* "no busy-polling" or "busy-polling" */
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		if (kwm == KWM_NO)
			global.tune.options &= ~GTUNE_BUSY_POLLING;
		else
			global.tune.options |=  GTUNE_BUSY_POLLING;
	}
	else if (strcmp(args[0], "set-dumpable") == 0) { /* "no set-dumpable" or "set-dumpable" */
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		if (kwm == KWM_NO)
			global.tune.options &= ~GTUNE_SET_DUMPABLE;
		else
			global.tune.options |=  GTUNE_SET_DUMPABLE;
	}
	else if (strcmp(args[0], "h2-workaround-bogus-websocket-clients") == 0) { /* "no h2-workaround-bogus-websocket-clients" or "h2-workaround-bogus-websocket-clients" */
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		if (kwm == KWM_NO)
			global.tune.options &= ~GTUNE_DISABLE_H2_WEBSOCKET;
		else
			global.tune.options |=  GTUNE_DISABLE_H2_WEBSOCKET;
	}
	else if (strcmp(args[0], "insecure-fork-wanted") == 0) { /* "no insecure-fork-wanted" or "insecure-fork-wanted" */
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		if (kwm == KWM_NO)
			global.tune.options &= ~GTUNE_INSECURE_FORK;
		else
			global.tune.options |=  GTUNE_INSECURE_FORK;
	}
	else if (strcmp(args[0], "insecure-setuid-wanted") == 0) { /* "no insecure-setuid-wanted" or "insecure-setuid-wanted" */
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		if (kwm == KWM_NO)
			global.tune.options &= ~GTUNE_INSECURE_SETUID;
		else
			global.tune.options |=  GTUNE_INSECURE_SETUID;
	}
	else if (strcmp(args[0], "nosplice") == 0) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.tune.options &= ~GTUNE_USE_SPLICE;
	}
	else if (strcmp(args[0], "nogetaddrinfo") == 0) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.tune.options &= ~GTUNE_USE_GAI;
	}
	else if (strcmp(args[0], "noreuseport") == 0) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		protocol_clrf_all(PROTO_F_REUSEPORT_SUPPORTED);
	}

	else if (strcmp(args[0], "cluster-secret") == 0) {
		blk_SHA_CTX sha1_ctx;
		unsigned char sha1_out[20];

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*args[1] == 0) {
			ha_alert("parsing [%s:%d] : expects an ASCII string argument.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (cluster_secret_isset) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}

		blk_SHA1_Init(&sha1_ctx);
		blk_SHA1_Update(&sha1_ctx, args[1], strlen(args[1]));
		blk_SHA1_Final(sha1_out, &sha1_ctx);
		BUG_ON(sizeof sha1_out < sizeof global.cluster_secret);
		memcpy(global.cluster_secret, sha1_out, sizeof global.cluster_secret);
		cluster_secret_isset = 1;
	}
	else if (strcmp(args[0], "uid") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.uid != 0) {
			ha_alert("parsing [%s:%d] : user/uid already specified. Continuing.\n", file, linenum);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (strl2irc(args[1], strlen(args[1]), &global.uid) != 0) {
			ha_warning("parsing [%s:%d] :  uid: string '%s' is not a number.\n   | You might want to use the 'user' parameter to use a system user name.\n", file, linenum, args[1]);
			err_code |= ERR_WARN;
			goto out;
		}

	}
	else if (strcmp(args[0], "gid") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.gid != 0) {
			ha_alert("parsing [%s:%d] : group/gid already specified. Continuing.\n", file, linenum);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (strl2irc(args[1], strlen(args[1]), &global.gid) != 0) {
			ha_warning("parsing [%s:%d] :  gid: string '%s' is not a number.\n   | You might want to use the 'group' parameter to use a system group name.\n", file, linenum, args[1]);
			err_code |= ERR_WARN;
			goto out;
		}
	}
	else if (strcmp(args[0], "external-check") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		global.external_check = 1;
		if (strcmp(args[1], "preserve-env") == 0) {
			global.external_check = 2;
		} else if (*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' only supports 'preserve-env' as an argument, found '%s'.\n", file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
	                goto out;
		}
	}
	/* user/group name handling */
	else if (strcmp(args[0], "user") == 0) {
		struct passwd *ha_user;
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.uid != 0) {
			ha_alert("parsing [%s:%d] : user/uid already specified. Continuing.\n", file, linenum);
			err_code |= ERR_ALERT;
			goto out;
		}
		errno = 0;
		ha_user = getpwnam(args[1]);
		if (ha_user != NULL) {
			global.uid = (int)ha_user->pw_uid;
		}
		else {
			ha_alert("parsing [%s:%d] : cannot find user id for '%s' (%d:%s)\n", file, linenum, args[1], errno, strerror(errno));
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}
	else if (strcmp(args[0], "group") == 0) {
		struct group *ha_group;
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.gid != 0) {
			ha_alert("parsing [%s:%d] : gid/group was already specified. Continuing.\n", file, linenum);
			err_code |= ERR_ALERT;
			goto out;
		}
		errno = 0;
		ha_group = getgrnam(args[1]);
		if (ha_group != NULL) {
			global.gid = (int)ha_group->gr_gid;
		}
		else {
			ha_alert("parsing [%s:%d] : cannot find group id for '%s' (%d:%s)\n", file, linenum, args[1], errno, strerror(errno));
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}
	/* end of user/group name handling*/
	else if (strcmp(args[0], "maxconn") == 0) {
		char *stop;

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.maxconn != 0) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.maxconn = strtol(args[1], &stop, 10);
		if (*stop != '\0') {
			ha_alert("parsing [%s:%d] : cannot parse '%s' value '%s', an integer is expected.\n", file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
#ifdef SYSTEM_MAXCONN
		if (global.maxconn > SYSTEM_MAXCONN && cfg_maxconn <= SYSTEM_MAXCONN) {
			ha_alert("parsing [%s:%d] : maxconn value %d too high for this system.\nLimiting to %d. Please use '-n' to force the value.\n", file, linenum, global.maxconn, SYSTEM_MAXCONN);
			global.maxconn = SYSTEM_MAXCONN;
			err_code |= ERR_ALERT;
		}
#endif /* SYSTEM_MAXCONN */
	}
	else if (strcmp(args[0], "ssl-server-verify") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (strcmp(args[1],"none") == 0)
			global.ssl_server_verify = SSL_SERVER_VERIFY_NONE;
		else if (strcmp(args[1],"required") == 0)
			global.ssl_server_verify = SSL_SERVER_VERIFY_REQUIRED;
		else {
			ha_alert("parsing [%s:%d] : '%s' expects 'none' or 'required' as argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
	                goto out;
		}
	}
	else if (strcmp(args[0], "maxconnrate") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.cps_lim != 0) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.cps_lim = atol(args[1]);
	}
	else if (strcmp(args[0], "maxsessrate") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.sps_lim != 0) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.sps_lim = atol(args[1]);
	}
	else if (strcmp(args[0], "maxsslrate") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.ssl_lim != 0) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.ssl_lim = atol(args[1]);
	}
	else if (strcmp(args[0], "maxcomprate") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument in kb/s.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.comp_rate_lim = atoi(args[1]) * 1024;
	}
	else if (strcmp(args[0], "maxpipes") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.maxpipes != 0) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.maxpipes = atol(args[1]);
	}
	else if (strcmp(args[0], "maxzlibmem") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.maxzlibmem = atol(args[1]) * 1024L * 1024L;
	}
	else if (strcmp(args[0], "maxcompcpuusage") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument between 0 and 100.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		compress_min_idle = 100 - atoi(args[1]);
		if (compress_min_idle > 100) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument between 0 and 100.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "fd-hard-limit") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.fd_hard_limit != 0) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.fd_hard_limit = atol(args[1]);
	}
	else if (strcmp(args[0], "ulimit-n") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.rlimit_nofile != 0) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.rlimit_nofile = atol(args[1]);
	}
	else if (strcmp(args[0], "description") == 0) {
		int i, len=0;
		char *d;

		if (!*args[1]) {
			ha_alert("parsing [%s:%d]: '%s' expects a string argument.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		for (i = 1; *args[i]; i++)
			len += strlen(args[i]) + 1;

		if (global.desc)
			free(global.desc);

		global.desc = d = calloc(1, len);

		d += snprintf(d, global.desc + len - d, "%s", args[1]);
		for (i = 2; *args[i]; i++)
			d += snprintf(d, global.desc + len - d, " %s", args[i]);
	}
	else if (strcmp(args[0], "node") == 0) {
		int i;
		char c;

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		for (i=0; args[1][i]; i++) {
			c = args[1][i];
			if (!isupper((unsigned char)c) && !islower((unsigned char)c) &&
			    !isdigit((unsigned char)c) && c != '_' && c != '-' && c != '.')
				break;
		}

		if (!i || args[1][i]) {
			ha_alert("parsing [%s:%d]: '%s' requires valid node name - non-empty string"
				 " with digits(0-9), letters(A-Z, a-z), dot(.), hyphen(-) or underscode(_).\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (global.node)
			free(global.node);

		global.node = strdup(args[1]);
	}
	else if (strcmp(args[0], "unix-bind") == 0) {
		int cur_arg = 1;
		while (*(args[cur_arg])) {
			if (strcmp(args[cur_arg], "prefix") == 0) {
				if (global.unix_bind.prefix != NULL) {
					ha_alert("parsing [%s:%d] : unix-bind '%s' already specified. Continuing.\n", file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT;
					cur_arg += 2;
					continue;
				}

				if (*(args[cur_arg+1]) == 0) {
		                        ha_alert("parsing [%s:%d] : unix_bind '%s' expects a path as an argument.\n", file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				global.unix_bind.prefix =  strdup(args[cur_arg+1]);
				cur_arg += 2;
				continue;
			}

			if (strcmp(args[cur_arg], "mode") == 0) {

				global.unix_bind.ux.mode = strtol(args[cur_arg + 1], NULL, 8);
                                cur_arg += 2;
				continue;
			}

			if (strcmp(args[cur_arg], "uid") == 0) {

				global.unix_bind.ux.uid = atol(args[cur_arg + 1 ]);
                                cur_arg += 2;
				continue;
                        }

			if (strcmp(args[cur_arg], "gid") == 0) {

				global.unix_bind.ux.gid = atol(args[cur_arg + 1 ]);
                                cur_arg += 2;
				continue;
                        }

			if (strcmp(args[cur_arg], "user") == 0) {
				struct passwd *user;

				user = getpwnam(args[cur_arg + 1]);
				if (!user) {
					ha_alert("parsing [%s:%d] : '%s' : '%s' unknown user.\n",
						 file, linenum, args[0], args[cur_arg + 1 ]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				global.unix_bind.ux.uid = user->pw_uid;
				cur_arg += 2;
				continue;
                        }

			if (strcmp(args[cur_arg], "group") == 0) {
				struct group *group;

				group = getgrnam(args[cur_arg + 1]);
				if (!group) {
					ha_alert("parsing [%s:%d] : '%s' : '%s' unknown group.\n",
						 file, linenum, args[0], args[cur_arg + 1 ]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				global.unix_bind.ux.gid = group->gr_gid;
				cur_arg += 2;
				continue;
			}

			ha_alert("parsing [%s:%d] : '%s' only supports the 'prefix', 'mode', 'uid', 'gid', 'user' and 'group' options.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
                }
	}
	else if (strcmp(args[0], "log") == 0) { /* "no log" or "log ..." */
		if (!parse_logger(args, &global.loggers, (kwm == KWM_NO), file, linenum, &errmsg)) {
			ha_alert("parsing [%s:%d] : %s : %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "log-send-hostname") == 0) { /* set the hostname in syslog header */
		char *name;

		if (global.log_send_hostname != NULL) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}

		if (*(args[1]))
			name = args[1];
		else
			name = hostname;

		free(global.log_send_hostname);
		global.log_send_hostname = strdup(name);
	}
	else if (strcmp(args[0], "server-state-base") == 0) { /* path base where HAProxy can find server state files */
		if (global.server_state_base != NULL) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}

		if (!*(args[1])) {
			ha_alert("parsing [%s:%d] : '%s' expects one argument: a directory path.\n", file, linenum, args[0]);
			err_code |= ERR_FATAL;
			goto out;
		}

		global.server_state_base = strdup(args[1]);
	}
	else if (strcmp(args[0], "server-state-file") == 0) { /* path to the file where HAProxy can load the server states */
		if (global.server_state_file != NULL) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}

		if (!*(args[1])) {
			ha_alert("parsing [%s:%d] : '%s' expect one argument: a file path.\n", file, linenum, args[0]);
			err_code |= ERR_FATAL;
			goto out;
		}

		global.server_state_file = strdup(args[1]);
	}
	else if (strcmp(args[0], "stats-file") == 0) { /* path to the file where HAProxy can load the server states */
		if (global.stats_file != NULL) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}

		if (!*(args[1])) {
			ha_alert("parsing [%s:%d] : '%s' expect one argument: a file path.\n", file, linenum, args[0]);
			err_code |= ERR_FATAL;
			goto out;
		}

		global.stats_file = strdup(args[1]);
	}
	else if (strcmp(args[0], "log-tag") == 0) {  /* tag to report to syslog */
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects a tag for use in syslog.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		chunk_destroy(&global.log_tag);
		chunk_initlen(&global.log_tag, strdup(args[1]), strlen(args[1]), strlen(args[1]));
		if (b_orig(&global.log_tag) == NULL) {
			chunk_destroy(&global.log_tag);
			ha_alert("parsing [%s:%d]: cannot allocate memory for '%s'.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "spread-checks") == 0) {  /* random time between checks (0-50) */
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.spread_checks != 0) {
			ha_alert("parsing [%s:%d]: spread-checks already specified. Continuing.\n", file, linenum);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d]: '%s' expects an integer argument (0..50).\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.spread_checks = atol(args[1]);
		if (global.spread_checks < 0 || global.spread_checks > 50) {
			ha_alert("parsing [%s:%d]: 'spread-checks' needs a positive value in range 0..50.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}
	else if (strcmp(args[0], "max-spread-checks") == 0) {  /* maximum time between first and last check */
		const char *err;
		unsigned int val;

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d]: '%s' expects an integer argument (0..50).\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err = parse_time_err(args[1], &val, TIME_UNIT_MS);
		if (err == PARSE_TIME_OVER) {
			ha_alert("parsing [%s:%d]: timer overflow in argument <%s> to <%s>, maximum value is 2147483647 ms (~24.8 days).\n",
			         file, linenum, args[1], args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
		else if (err == PARSE_TIME_UNDER) {
			ha_alert("parsing [%s:%d]: timer underflow in argument <%s> to <%s>, minimum non-null value is 1 ms.\n",
			         file, linenum, args[1], args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
		else if (err) {
			ha_alert("parsing [%s:%d]: unsupported character '%c' in '%s' (wants an integer delay).\n", file, linenum, *err, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
		global.max_spread_checks = val;
	}
	else if (strcmp(args[0], "cpu-map") == 0) {
		/* map a process list to a CPU set */
#ifdef USE_CPU_AFFINITY
		char *slash;
		unsigned long tgroup = 0, thread = 0;
		int g, j, n, autoinc;
		struct hap_cpuset cpus, cpus_copy;

		if (!*args[1] || !*args[2]) {
			ha_alert("parsing [%s:%d] : %s expects a thread group number "
				 " ('all', 'odd', 'even', a number from 1 to %d or a range), "
				 " followed by a list of CPU ranges with numbers from 0 to %d.\n",
				 file, linenum, args[0], LONGBITS, LONGBITS - 1);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if ((slash = strchr(args[1], '/')) != NULL)
			*slash = 0;

		/* note: we silently ignore thread group numbers over MAX_TGROUPS
		 * and threads over MAX_THREADS so as not to make configurations a
		 * pain to maintain.
		 */
		if (parse_process_number(args[1], &tgroup, LONGBITS, &autoinc, &errmsg)) {
			ha_alert("parsing [%s:%d] : %s : %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (slash) {
			if (parse_process_number(slash+1, &thread, LONGBITS, NULL, &errmsg)) {
				ha_alert("parsing [%s:%d] : %s : %s\n", file, linenum, args[0], errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			*slash = '/';
		} else
			thread = ~0UL; /* missing '/' = 'all' */

		/* from now on, thread cannot be NULL anymore */

		if (parse_cpu_set((const char **)args+2, &cpus, &errmsg)) {
			ha_alert("parsing [%s:%d] : %s : %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (autoinc &&
		    my_popcountl(tgroup) != ha_cpuset_count(&cpus) &&
		    my_popcountl(thread) != ha_cpuset_count(&cpus)) {
			ha_alert("parsing [%s:%d] : %s : TGROUP/THREAD range and CPU sets "
				 "must have the same size to be automatically bound\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		/* we now have to deal with 3 real cases :
		 *    cpu-map P-Q    => mapping for whole tgroups, numbers P to Q
		 *    cpu-map P-Q/1  => mapping of first thread of groups P to Q
		 *    cpu-map P/T-U  => mapping of threads T to U of tgroup P
		 */
		/* first tgroup, iterate on threads. E.g. cpu-map 1/1-4 0-3 */
		for (g = 0; g < MAX_TGROUPS; g++) {
			/* No mapping for this tgroup */
			if (!(tgroup & (1UL << g)))
				continue;

			ha_cpuset_assign(&cpus_copy, &cpus);

			/* a thread set is specified, apply the
			 * CPU set to these threads.
			 */
			for (j = n = 0; j < MAX_THREADS_PER_GROUP; j++) {
				/* No mapping for this thread */
				if (!(thread & (1UL << j)))
					continue;

				if (!autoinc)
					ha_cpuset_assign(&cpu_map[g].thread[j], &cpus);
				else {
					ha_cpuset_zero(&cpu_map[g].thread[j]);
					n = ha_cpuset_ffs(&cpus_copy) - 1;
					ha_cpuset_clr(&cpus_copy, n);
					ha_cpuset_set(&cpu_map[g].thread[j], n);
				}
			}
		}
#else
		ha_alert("parsing [%s:%d] : '%s' is not enabled, please check build options for USE_CPU_AFFINITY.\n",
			 file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
#endif /* ! USE_CPU_AFFINITY */
	}
	else if (strcmp(args[0], "quick-exit") == 0) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.tune.options |= GTUNE_QUICK_EXIT;
	}
	else if (strcmp(args[0], "strict-limits") == 0) { /* "no strict-limits" or "strict-limits" */
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		if (kwm == KWM_NO)
			global.tune.options &= ~GTUNE_STRICT_LIMITS;
	}
	else if (strcmp(args[0], "numa-cpu-mapping") == 0) {
		global.numa_cpu_mapping = (kwm == KWM_NO) ? 0 : 1;
	}
	else if (strcmp(args[0], "anonkey") == 0) {
		long long tmp = 0;

		if (*args[1] == 0) {
			ha_alert("parsing [%s:%d]: a key is expected after '%s'.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (HA_ATOMIC_LOAD(&global.anon_key) == 0) {
			tmp = atoll(args[1]);
			if (tmp < 0 || tmp > UINT_MAX) {
				ha_alert("parsing [%s:%d]: '%s' value must be within range %u-%u (was '%s').\n",
					 file, linenum, args[0], 0, UINT_MAX, args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			HA_ATOMIC_STORE(&global.anon_key, tmp);
		}
	}
	else {
		struct cfg_kw_list *kwl;
		const char *best;
		int index;
		int rc;
discovery_kw:
		list_for_each_entry(kwl, &cfg_keywords.list, list) {
			for (index = 0; kwl->kw[index].kw != NULL; index++) {
				if (kwl->kw[index].section != CFG_GLOBAL)
					continue;
				if (strcmp(kwl->kw[index].kw, args[0]) == 0) {

					/* in MODE_DISCOVERY we read only the keywords, which contains the appropiate flag */
					if ((global.mode & MODE_DISCOVERY) && ((kwl->kw[index].flags & KWF_DISCOVERY) == 0 ))
						goto out;

					if (check_kw_experimental(&kwl->kw[index], file, linenum, &errmsg)) {
						ha_alert("%s\n", errmsg);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}

					rc = kwl->kw[index].parse(args, CFG_GLOBAL, NULL, NULL, file, linenum, &errmsg);
					if (rc < 0) {
						ha_alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
						err_code |= ERR_ALERT | ERR_FATAL;
					}
					else if (rc > 0) {
						ha_warning("parsing [%s:%d] : %s\n", file, linenum, errmsg);
						err_code |= ERR_WARN;
					}
					goto out;
				}
			}
		}

		if (global.mode & MODE_DISCOVERY)
			goto out;

		best = cfg_find_best_match(args[0], &cfg_keywords.list, CFG_GLOBAL, common_kw_list);
		if (best)
			ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section; did you mean '%s' maybe ?\n", file, linenum, args[0], cursection, best);
		else
			ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], "global");
		err_code |= ERR_ALERT | ERR_FATAL;
	}

 out:
	free(errmsg);
	return err_code;
}

static int cfg_parse_prealloc_fd(char **args, int section_type, struct proxy *curpx,
                            const struct proxy *defpx, const char *file, int line,
                            char **err)
{
	if (too_many_args(0, args, err, NULL))
		return -1;

	global.prealloc_fd = 1;

	return 0;
}

/* Parser for harden.reject-privileged-ports.{tcp|quic}. */
static int cfg_parse_reject_privileged_ports(char **args, int section_type,
                                             struct proxy *curpx,
                                             const struct proxy *defpx,
                                             const char *file, int line, char **err)
{
	struct ist proto;
	char onoff;

	if (!*(args[1])) {
		memprintf(err, "'%s' expects either 'on' or 'off'.", args[0]);
		return -1;
	}

	proto = ist(args[0]);
	while (istlen(istfind(proto, '.')))
		proto = istadv(istfind(proto, '.'), 1);

	if (strcmp(args[1], "on") == 0) {
		onoff = 1;
	}
	else if (strcmp(args[1], "off") == 0) {
		onoff = 0;
	}
	else {
		memprintf(err, "'%s' expects either 'on' or 'off'.", args[0]);
		return -1;
	}

	if (istmatch(proto, ist("tcp"))) {
		if (!onoff)
			global.clt_privileged_ports |= HA_PROTO_TCP;
		else
			global.clt_privileged_ports &= ~HA_PROTO_TCP;
	}
	else if (istmatch(proto, ist("quic"))) {
		if (!onoff)
			global.clt_privileged_ports |= HA_PROTO_QUIC;
		else
			global.clt_privileged_ports &= ~HA_PROTO_QUIC;
	}
	else {
		memprintf(err, "invalid protocol for '%s'.", args[0]);
		return -1;
	}

	return 0;
}

/* Parser for master-worker mode */
static int cfg_parse_global_master_worker(char **args, int section_type,
					  struct proxy *curpx, const struct proxy *defpx,
					  const char *file, int line, char **err)
{
	if (!(global.mode & MODE_DISCOVERY))
		return 0;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*args[1]) {
		if (strcmp(args[1], "no-exit-on-failure") == 0)
			global.tune.options |= GTUNE_NOEXIT_ONFAILURE;
		else {
			memprintf(err, "'%s' only supports 'no-exit-on-failure' option",
				  args[0]);
			return -1;
		}
	}
	global.mode |= MODE_MWORKER;

	return 0;
}

/* Parser for other modes */
static int cfg_parse_global_mode(char **args, int section_type,
				 struct proxy *curpx, const struct proxy *defpx,
				 const char *file, int line, char **err)
{
	if (!(global.mode & MODE_DISCOVERY))
		return 0;

	if (too_many_args(0, args, err, NULL))
		return -1;

	if (strcmp(args[0], "daemon") == 0) {
		global.mode |= MODE_DAEMON;

	} else if (strcmp(args[0], "quiet") == 0) {
		global.mode |= MODE_QUIET;

	} else if (strcmp(args[0], "zero-warning") == 0) {
		global.mode |= MODE_ZERO_WARNING;

	} else {
		BUG_ON(1, "Triggered in cfg_parse_global_mode() by unsupported keyword.\n");
		return -1;
	}

	return 0;
}

/* Disable certain poller if set */
static int cfg_parse_global_disable_poller(char **args, int section_type,
					   struct proxy *curpx, const struct proxy *defpx,
					   const char *file, int line, char **err)
{
	if (!(global.mode & MODE_DISCOVERY))
		return 0;

	if (too_many_args(0, args, err, NULL))
		return -1;

	if (strcmp(args[0], "noepoll") == 0) {
		global.tune.options &= ~GTUNE_USE_EPOLL;

	} else if (strcmp(args[0], "nokqueue") == 0) {
		global.tune.options &= ~GTUNE_USE_KQUEUE;

	} else if (strcmp(args[0], "noevports") == 0) {
		global.tune.options &= ~GTUNE_USE_EVPORTS;

	} else if (strcmp(args[0], "nopoll") == 0) {
		global.tune.options &= ~GTUNE_USE_POLL;

	} else {
		BUG_ON(1, "Triggered in cfg_parse_global_disable_poller() by unsupported keyword.\n");
		return -1;
	}

	return 0;
}

static int cfg_parse_global_pidfile(char **args, int section_type,
				    struct proxy *curpx, const struct proxy *defpx,
				    const char *file, int line, char **err)
{
	if (!(global.mode & MODE_DISCOVERY))
		return 0;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[0], "pidfile") == 0) {
		if (global.pidfile != NULL) {
			memprintf(err, "'%s' already specified. Continuing.", args[0]);
			return 1;
		}
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects a file name as an argument.", args[0]);
			return -1;
		}
		global.pidfile = strdup(args[1]);
	} else {
		BUG_ON(1, "Triggered in cfg_parse_global_pidfile() by unsupported keyword.\n");
		return -1;
	}

	return 0;
}

static int cfg_parse_global_non_std_directives(char **args, int section_type,
					       struct proxy *curpx, const struct proxy *defpx,
					       const char *file, int line, char **err)
{

	if (too_many_args(0, args, err, NULL))
		return -1;

	if (strcmp(args[0], "expose-deprecated-directives") == 0) {
		deprecated_directives_allowed = 1;
	} else if (strcmp(args[0], "expose-experimental-directives") == 0) {
		experimental_directives_allowed = 1;
	} else {
		BUG_ON(1, "Triggered in cfg_parse_global_non_std_directives() by unsupported keyword.\n");
		return -1;
	}

	return 0;
}

static int cfg_parse_global_tune_opts(char **args, int section_type,
				      struct proxy *curpx, const struct proxy *defpx,
				      const char *file, int line, char **err)
{
	const char *res;

	if (too_many_args(1, args, err, NULL))
		return -1;


	if (strcmp(args[0], "tune.runqueue-depth") == 0) {
		if (global.tune.runqueue_depth != 0) {
			memprintf(err, "'%s' already specified. Continuing.", args[0]);
			return 1;
		}
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		global.tune.runqueue_depth = atol(args[1]);

		return 0;

	}
	else if (strcmp(args[0], "tune.maxpollevents") == 0) {
		if (global.tune.maxpollevents != 0) {
			memprintf(err, "'%s' already specified. Continuing.", args[0]);
			return 1;
		}
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		global.tune.maxpollevents = atol(args[1]);

		return 0;
	}
	else if (strcmp(args[0], "tune.maxaccept") == 0) {
		long max;

		if (global.tune.maxaccept != 0) {
			memprintf(err, "'%s' already specified. Continuing.", args[0]);
			return 1;
		}
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument", args[0]);
			return -1;
		}
		max = atol(args[1]);
		if (/*max < -1 || */max > INT_MAX) {
			memprintf(err, "'%s' expects -1 or an integer from 0 to INT_MAX.", args[0]);
			return -1;
		}
		global.tune.maxaccept = max;

		return 0;
	}
	else if (strcmp(args[0], "tune.recv_enough") == 0) {
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		res = parse_size_err(args[1], &global.tune.recv_enough);
		if (res != NULL)
			goto size_err;

		if (global.tune.recv_enough > INT_MAX) {
			memprintf(err, "'%s' expects a size in bytes from 0 to %d.", args[0], INT_MAX);
			return -1;
		}

		return 0;
	}
	else if (strcmp(args[0], "tune.bufsize") == 0) {
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument", args[0]);
			return -1;
		}
		res = parse_size_err(args[1], &global.tune.bufsize);
		if (res != NULL)
			goto size_err;

		if (global.tune.bufsize > INT_MAX - (int)(2 * sizeof(void *))) {
			memprintf(err, "'%s' expects a size in bytes from 0 to %d.",
				  args[0], INT_MAX - (int)(2 * sizeof(void *)));
			return -1;
		}

		/* round it up to support a two-pointer alignment at the end */
		global.tune.bufsize = (global.tune.bufsize + 2 * sizeof(void *) - 1) & -(2 * sizeof(void *));
		if (global.tune.bufsize <= 0) {
			memprintf(err, "'%s' expects a positive integer argument.", args[0]);
			return -1;
		}

		return 0;
	}
	else if (strcmp(args[0], "tune.maxrewrite") == 0) {
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		global.tune.maxrewrite = atol(args[1]);
		if (global.tune.maxrewrite < 0) {
			memprintf(err, "'%s' expects a positive integer argument.", args[0]);
			return -1;
		}

		return 0;
	}
	else if (strcmp(args[0], "tune.idletimer") == 0) {
		unsigned int idle;

		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects a timer value between 0 and 65535 ms.", args[0]);
			return -1;
		}

		res = parse_time_err(args[1], &idle, TIME_UNIT_MS);
		if (res == PARSE_TIME_OVER) {
			memprintf(err, "timer overflow in argument <%s> to <%s>, maximum value is 65535 ms.",
			         args[1], args[0]);
			return -1;
		}
		else if (res == PARSE_TIME_UNDER) {
			memprintf(err, "timer underflow in argument <%s> to <%s>, minimum non-null value is 1 ms.",
			         args[1], args[0]);
			return -1;
		}
		else if (res) {
			memprintf(err, "unexpected character '%c' in argument to <%s>.", *res, args[0]);
			return -1;
		}

		if (idle > 65535) {
			memprintf(err, "'%s' expects a timer value between 0 and 65535 ms.", args[0]);
			return -1;
		}
		global.tune.idle_timer = idle;

		return 0;
	}
	else if (strcmp(args[0], "tune.rcvbuf.client") == 0) {
		if (global.tune.client_rcvbuf != 0) {
			memprintf(err, "'%s' already specified. Continuing.", args[0]);
			return 1;
		}
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		res = parse_size_err(args[1], &global.tune.client_rcvbuf);
		if (res != NULL)
			goto size_err;

		return 0;
	}
	else if (strcmp(args[0], "tune.rcvbuf.server") == 0) {
		if (global.tune.server_rcvbuf != 0) {
			memprintf(err, "'%s' already specified. Continuing.", args[0]);
			return 1;
		}
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		res = parse_size_err(args[1], &global.tune.server_rcvbuf);
		if (res != NULL)
			goto size_err;

		return 0;
	}
	else if (strcmp(args[0], "tune.sndbuf.client") == 0) {
		if (global.tune.client_sndbuf != 0) {
			memprintf(err, "'%s' already specified. Continuing.", args[0]);
			return 1;
		}
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		res = parse_size_err(args[1], &global.tune.client_sndbuf);
		if (res != NULL)
			goto size_err;

		return 0;
	}
	else if (strcmp(args[0], "tune.sndbuf.server") == 0) {
		if (global.tune.server_sndbuf != 0) {
			memprintf(err, "'%s' already specified. Continuing.", args[0]);
			return 1;
		}
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		res = parse_size_err(args[1], &global.tune.server_sndbuf);
		if (res != NULL)
			goto size_err;

		return 0;
	}
	else if (strcmp(args[0], "tune.pipesize") == 0) {
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		res = parse_size_err(args[1], &global.tune.pipesize);
		if (res != NULL)
			goto size_err;

		return 0;
	}
	else if (strcmp(args[0], "tune.http.cookielen") == 0) {
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		global.tune.cookie_len = atol(args[1]) + 1;

		return 0;
	}
	else if (strcmp(args[0], "tune.http.logurilen") == 0) {
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		global.tune.requri_len = atol(args[1]) + 1;

		return 0;
	}
	else if (strcmp(args[0], "tune.http.maxhdr") == 0) {
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		global.tune.max_http_hdr = atoi(args[1]);
		if (global.tune.max_http_hdr < 1 || global.tune.max_http_hdr > 32767) {
			memprintf(err, "'%s' expects a numeric value between 1 and 32767", args[0]);
			return -1;
		}

		return 0;
	}
	else if (strcmp(args[0], "tune.comp.maxlevel") == 0) {
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects a numeric value between 1 and 9", args[0]);
			return -1;
		}
		global.tune.comp_maxlevel = atoi(args[1]);
		if (global.tune.comp_maxlevel < 1 || global.tune.comp_maxlevel > 9) {
			memprintf(err, "'%s' expects a numeric value between 1 and 9", args[0]);
			return -1;
		}

		return 0;
	}
	else if (strcmp(args[0], "tune.pattern.cache-size") == 0) {
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects a positive numeric value", args[0]);
			return -1;
		}
		global.tune.pattern_cache = atoi(args[1]);
		if (global.tune.pattern_cache < 0) {
			memprintf(err, "'%s' expects a positive numeric value", args[0]);
			return -1;
		}
	}
	else {
		BUG_ON(1, "Triggered in cfg_parse_global_tune_opts() by unsupported keyword.\n");
		return -1;
	}

	return 0;

 size_err:
	memprintf(err, "unexpected '%s' after size passed to '%s'", res, args[0]);
	return -1;

}

static int cfg_parse_global_tune_forward_opts(char **args, int section_type,
					      struct proxy *curpx, const struct proxy *defpx,
					      const char *file, int line, char **err)
{

	if (too_many_args(0, args, err, NULL))
		return -1;

	if (strcmp(args[0], "tune.disable-fast-forward") == 0) {
		if (!experimental_directives_allowed) {
			memprintf(err, "'%s' directive is experimental, must be allowed via a global 'expose-experimental-directives'",
				 args[0]);
			return -1;
		}
		mark_tainted(TAINTED_CONFIG_EXP_KW_DECLARED);
		global.tune.options &= ~GTUNE_USE_FAST_FWD;
	}
	else if (strcmp(args[0], "tune.disable-zero-copy-forwarding") == 0) {
		global.tune.no_zero_copy_fwd |= NO_ZERO_COPY_FWD;
	}
	else {
		BUG_ON(1, "Triggered in cfg_parse_global_tune_forward_opts() by unsupported keyword.\n");
		return -1;
	}

	return 0;

}

static int cfg_parse_global_unsupported_opts(char **args, int section_type,
					     struct proxy *curpx, const struct proxy *defpx,
					     const char *file, int line, char **err)
{
	if (strcmp(args[0], "nbproc") == 0) {
		memprintf(err, "nbproc is not supported any more since HAProxy 2.5. "
			  "Threads will automatically be used on multi-processor machines if available.");
	}
	else if (strcmp(args[0], "tune.chksize") == 0) {
		memprintf(err, "option '%s' is not supported any more (tune.bufsize is used instead).", args[0]);
	}
	else {
		BUG_ON(1, "Triggered in cfg_parse_global_unsupported_opts() by unsupported keyword.\n");
	}

	return -1;
}

static int cfg_parse_global_env_opts(char **args, int section_type,
				     struct proxy *curpx, const struct proxy *defpx,
				     const char *file, int line, char **err)
{

	if (strcmp(args[0], "setenv") == 0 || strcmp(args[0], "presetenv") == 0) {
		if (too_many_args(2, args, err, NULL))
			return -1;

		if (*(args[2]) == 0) {
			memprintf(err, "'%s' expects an env variable name and a value.\n.",
				  args[0]);
			return -1;
		}

		/* "setenv" overwrites, "presetenv" only sets if not yet set */
		if (setenv(args[1], args[2], (args[0][0] == 's')) != 0) {
			memprintf(err, "'%s' failed on variable '%s' : %s.\n",
				  args[0], args[1], strerror(errno));
			return -1;
		}
	}
	else if (strcmp(args[0], "unsetenv") == 0) {
		int arg;

		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects at least one variable name.\n", args[0]);
			return -1;
		}

		for (arg = 1; *args[arg]; arg++) {
			if (unsetenv(args[arg]) != 0) {
				memprintf(err, "'%s' failed on variable '%s' : %s.\n",
					  args[0], args[arg], strerror(errno));
				return -1;
			}
		}
	}
	else if (strcmp(args[0], "resetenv") == 0) {
		extern char **environ;
		char **env = environ;

		/* args contain variable names to keep, one per argument */
		while (*env) {
			int arg;

			/* look for current variable in among all those we want to keep */
			for (arg = 1; *args[arg]; arg++) {
				if (strncmp(*env, args[arg], strlen(args[arg])) == 0 &&
				    (*env)[strlen(args[arg])] == '=')
					break;
			}

			/* delete this variable */
			if (!*args[arg]) {
				char *delim = strchr(*env, '=');

				if (!delim || delim - *env >= trash.size) {
					memprintf(err, "'%s' failed to unset invalid variable '%s'.\n",
						  args[0], *env);
					return -1;
				}

				memcpy(trash.area, *env, delim - *env);
				trash.area[delim - *env] = 0;

				if (unsetenv(trash.area) != 0) {
					memprintf(err, "'%s' failed to unset variable '%s' : %s.\n",
						  args[0], *env, strerror(errno));
					return -1;
				}
			}
			else
				env++;
		}
	}
	else {
		BUG_ON(1, "Triggered in cfg_parse_global_env_opts() by unsupported keyword.\n");
		return -1;
	}

	return 0;
}

static int cfg_parse_global_parser_pause(char **args, int section_type,
                                         struct proxy *curpx, const struct proxy *defpx,
                                         const char *file, int line, char **err)
{
	unsigned int ms = 0;
	const char *res;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects a timer value between 0 and 65535 ms.", args[0]);
		return -1;
	}

	if (too_many_args(1, args, err, NULL))
		return -1;


	res = parse_time_err(args[1], &ms, TIME_UNIT_MS);
	if (res == PARSE_TIME_OVER) {
		memprintf(err, "timer overflow in argument <%s> to <%s>, maximum value is 65535 ms.",
				args[1], args[0]);
		return -1;
	}
	else if (res == PARSE_TIME_UNDER) {
		memprintf(err, "timer underflow in argument <%s> to <%s>, minimum non-null value is 1 ms.",
				args[1], args[0]);
		return -1;
	}
	else if (res) {
		memprintf(err, "unexpected character '%c' in argument to <%s>.", *res, args[0]);
		return -1;
	}

	if (ms > 65535) {
		memprintf(err, "'%s' expects a timer value between 0 and 65535 ms.", args[0]);
		return -1;
	}

	usleep(ms * 1000);

	return 0;
}

/* config parser for global "tune.renice.startup" and "tune.renice.runtime",
 * accepts -20 to +19 inclusive, stored as 80..119.
 */
static int cfg_parse_tune_renice(char **args, int section_type, struct proxy *curpx,
                                const struct proxy *defpx, const char *file, int line,
                                char **err)
{
	int prio;
	char *stop;

	if (too_many_args(1, args, err, NULL))
		return -1;

	prio = strtol(args[1], &stop, 10);
	if ((*stop != '\0') || (prio < -20 || prio > 19)) {
		memprintf(err, "'%s' only supports values between -20 and 19 inclusive (was given %s)", args[0], args[1]);
		return -1;
	}

	/* 'runtime' vs 'startup' */
	if (args[0][12] == 'r') {
		/* runtime is executed once parsing is done */

		global.tune.renice_runtime = prio + 100;
	} else if (args[0][12] == 's') {
		/* startup is executed during cfg parsing */

		global.tune.renice_startup = prio + 100;
		if (setpriority(PRIO_PROCESS, 0, prio) == -1)
			ha_warning("couldn't set the startup nice value to %d: %s\n", prio, strerror(errno));

		/* try to store the previous priority in the runtime priority */
		prio = getpriority(PRIO_PROCESS, 0);
		if (prio == -1) {
			ha_warning("couldn't get the runtime nice value: %s\n", strerror(errno));
		} else {
			/* if there wasn't a renice runtime option set */
			if (global.tune.renice_runtime == 0)
				global.tune.renice_runtime = prio + 100;
		}

	} else {
		BUG_ON(1, "Triggered in cfg_parse_tune_renice() by unsupported keyword.\n");
	}

	return 0;
}

static int cfg_parse_global_chroot(char **args, int section_type, struct proxy *curpx,
				   const struct proxy *defpx, const char *file, int line,
				   char **err)
{
	struct stat dir_stat;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (global.chroot != NULL) {
		memprintf(err, "'%s' is already specified. Continuing.\n", args[0]);
		return 1;
	}
	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects a directory as an argument.\n", args[0]);
		return -1;
	}
	global.chroot = strdup(args[1]);

	/* some additional test for chroot dir, warn messages might be
	 * handy to catch misconfiguration errors more quickly
	 */
	if (stat(args[1], &dir_stat) != 0) {
		if (errno == ENOENT)
			ha_diag_warning("parsing [%s:%d]: '%s': '%s': %s.\n",
					file, line, args[0], args[1], strerror(errno));
		else if (errno == EACCES)
			ha_diag_warning("parsing [%s:%d]: '%s': '%s': %s "
					"(process is need to be started with root priviledges to be able to chroot).\n",
					file, line, args[0], args[1], strerror(errno));
		else
			ha_diag_warning("parsing [%s:%d]: '%s': '%s': stat() is failed: %s.\n",
					file, line, args[0], args[1], strerror(errno));
	} else if ((dir_stat.st_mode & S_IFMT) != S_IFDIR) {
		ha_diag_warning("parsing [%s:%d]: '%s': '%s' is not a directory.\n",
				file, line, args[0], args[1]);
	}

	return 0;
}

static int cfg_parse_global_localpeer(char **args, int section_type, struct proxy *curpx,
				      const struct proxy *defpx, const char *file, int line,
				      char **err)
{
	if (!(global.mode & MODE_DISCOVERY))
		return 0;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects a name as an argument.\n", args[0]);
		return -1;
	}

	if (global.localpeer_cmdline != 0) {
		memprintf(err, "'%s' ignored since it is already set by using the '-L' "
			 "command line argument.\n", args[0]);
		return -1;
	}

	free(localpeer);
	localpeer = strdup(args[1]);
	if (localpeer == NULL) {
		memprintf(err, "cannot allocate memory for '%s'.\n", args[0]);
		return -1;
	}

	return 0;
}

static int cfg_parse_global_stress_level(char **args, int section_type, struct proxy *curpx,
                                         const struct proxy *defpx, const char *file, int line,
                                         char **err)
{
	char *stop;
	int level;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects a level as an argument.", args[0]);
		return -1;
	}

	level = strtol(args[1], &stop, 10);
	if ((*stop != '\0') || level < 0 || level > 9) {
		memprintf(err, "'%s' level must be between 0 and 9 inclusive.", args[0]);
		return -1;
	}

	mode_stress_level = level;

	return 0;
}

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "prealloc-fd", cfg_parse_prealloc_fd },
	{ CFG_GLOBAL, "force-cfg-parser-pause", cfg_parse_global_parser_pause, KWF_EXPERIMENTAL },
	{ CFG_GLOBAL, "harden.reject-privileged-ports.tcp",  cfg_parse_reject_privileged_ports },
	{ CFG_GLOBAL, "harden.reject-privileged-ports.quic", cfg_parse_reject_privileged_ports },
	{ CFG_GLOBAL, "master-worker", cfg_parse_global_master_worker, KWF_DISCOVERY },
	{ CFG_GLOBAL, "daemon", cfg_parse_global_mode, KWF_DISCOVERY } ,
	{ CFG_GLOBAL, "quiet", cfg_parse_global_mode, KWF_DISCOVERY },
	{ CFG_GLOBAL, "zero-warning", cfg_parse_global_mode, KWF_DISCOVERY },
	{ CFG_GLOBAL, "noepoll", cfg_parse_global_disable_poller, KWF_DISCOVERY },
	{ CFG_GLOBAL, "nokqueue", cfg_parse_global_disable_poller, KWF_DISCOVERY },
	{ CFG_GLOBAL, "noevports", cfg_parse_global_disable_poller, KWF_DISCOVERY },
	{ CFG_GLOBAL, "nopoll", cfg_parse_global_disable_poller, KWF_DISCOVERY },
	{ CFG_GLOBAL, "pidfile", cfg_parse_global_pidfile, KWF_DISCOVERY },
	{ CFG_GLOBAL, "expose-deprecated-directives", cfg_parse_global_non_std_directives, KWF_DISCOVERY },
	{ CFG_GLOBAL, "expose-experimental-directives", cfg_parse_global_non_std_directives },
	{ CFG_GLOBAL, "tune.runqueue-depth", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.maxpollevents", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.maxaccept", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.recv_enough", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.bufsize", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.maxrewrite", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.idletimer", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.renice.startup", cfg_parse_tune_renice },
	{ CFG_GLOBAL, "tune.renice.runtime", cfg_parse_tune_renice },
	{ CFG_GLOBAL, "tune.rcvbuf.client", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.rcvbuf.server", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.sndbuf.client", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.sndbuf.server", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.pipesize", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.http.cookielen", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.http.logurilen", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.http.maxhdr", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.comp.maxlevel", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.pattern.cache-size", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.disable-fast-forward", cfg_parse_global_tune_forward_opts },
	{ CFG_GLOBAL, "tune.disable-zero-copy-forwarding", cfg_parse_global_tune_forward_opts },
	{ CFG_GLOBAL, "tune.chksize", cfg_parse_global_unsupported_opts },
	{ CFG_GLOBAL, "nbproc", cfg_parse_global_unsupported_opts },
	{ CFG_GLOBAL, "setenv", cfg_parse_global_env_opts, KWF_DISCOVERY },
	{ CFG_GLOBAL, "unsetenv", cfg_parse_global_env_opts, KWF_DISCOVERY },
	{ CFG_GLOBAL, "resetenv", cfg_parse_global_env_opts, KWF_DISCOVERY },
	{ CFG_GLOBAL, "presetenv", cfg_parse_global_env_opts, KWF_DISCOVERY },
	{ CFG_GLOBAL, "chroot", cfg_parse_global_chroot },
	{ CFG_GLOBAL, "localpeer", cfg_parse_global_localpeer, KWF_DISCOVERY },
	{ CFG_GLOBAL, "stress-level", cfg_parse_global_stress_level },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
