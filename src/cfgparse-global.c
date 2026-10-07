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
#include <haproxy/guid.h>
#include <haproxy/log.h>
#include <haproxy/peers.h>
#include <haproxy/protocol.h>
#include <haproxy/stats-file.h>
#include <haproxy/stress.h>
#include <haproxy/sym.h>
#include <haproxy/tools.h>

int cluster_secret_isset;

/* some keywords that are still being parsed using strcmp() and are not
 * registered anywhere. They are used as suggestions for mistyped words.
 */
static const char *common_kw_list[] = {
	"global",
	"defaults", "listen", "frontend", "backend",
	"peers", "resolvers",
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

	else if (strcmp(args[0], "anonkey") == 0) {
		long long tmp = 0;

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
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

					/* in MODE_DISCOVERY we read only the keywords, which contains the appropriate flag */
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

	if (!*args[1]) {
		memprintf(err, "support for '%s' was removed in version 3.5. Use -W or -Ws in the startup script instead.\n", args[0]);
		return -1;
	}

	if (!(global.mode & (MODE_MWORKER | MODE_CHECK))) {
		memprintf(err, "'%s %s' is only supported in master-worker mode. Use -W or -Ws in the startup script.\n", args[0], args[1]);
		return -1;
	}

	if (*args[1]) {
		if (strcmp(args[1], "no-exit-on-failure") == 0)
			global.tune.options |= GTUNE_NOEXIT_ONFAILURE;
		else {
			memprintf(err, "'%s' only supports 'no-exit-on-failure' option",
				  args[0]);
			return -1;
		}
	}

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
		if (global.tune.options & GTUNE_USE_SYSTEMD) {
			ha_warning("'%s' is not compatible with -Ws (master-worker mode for systemd), ignoring.\n", args[0]);
		} else {
			global.mode |= MODE_DAEMON;
		}

	} else if (strcmp(args[0], "quiet") == 0) {
		global.mode |= MODE_QUIET;

	} else if (strcmp(args[0], "zero-warning") == 0) {
		global.mode |= MODE_ZERO_WARNING;

	} else {
		BUG_ON(1, "Triggered in cfg_parse_global_mode() by unsupported keyword.");
		return -1;
	}

	return 0;
}

static int cfg_parse_global_disable_ktls(char **args, int section_type,
					 struct proxy *curpx, const struct proxy *defpx,
					 const char *file, int line, char **err)
{
	if (!(global.mode & MODE_DISCOVERY))
                return 0;

	if (too_many_args(0, args, err, NULL))
		return -1;

	global.tune.options |= GTUNE_NO_KTLS;

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
		BUG_ON(1, "Triggered in cfg_parse_global_disable_poller() by unsupported keyword.");
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
		BUG_ON(1, "Triggered in cfg_parse_global_pidfile() by unsupported keyword.");
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
		BUG_ON(1, "Triggered in cfg_parse_global_non_std_directives() by unsupported keyword.");
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
		long max;

		if (global.tune.maxpollevents != 0) {
			memprintf(err, "'%s' already specified. Continuing.", args[0]);
			return 1;
		}
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		max = atol(args[1]);
		if (max > 1000000) {
			memprintf(err, "'%s' expects an integer value lower than or equal to 1000000.", args[0]);
			return -1;
		}
		global.tune.maxpollevents = max;
		return 0;
	}
	else if (strcmp(args[0], "tune.max-rules-at-once") == 0) {
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects a positive numeric value", args[0]);
			return -1;
		}
		global.tune.max_rules_at_once = atoi(args[1]);
		if (global.tune.max_rules_at_once < 0) {
			memprintf(err, "'%s' expects a positive numeric value", args[0]);
			return -1;
		}
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
	else if (strcmp(args[0], "tune.notsent-lowat.client") == 0) {
#if defined(TCP_NOTSENT_LOWAT)
		if (global.tune.client_notsent_lowat != 0) {
			memprintf(err, "'%s' already specified. Continuing.", args[0]);
			return 1;
		}
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		res = parse_size_err(args[1], &global.tune.client_notsent_lowat);
		if (res != NULL)
			goto size_err;

		return 0;
#else
		memprintf(err, "'%s' is not supported on this system.", args[0]);
		return -1;
#endif
	}
	else if (strcmp(args[0], "tune.notsent-lowat.server") == 0) {
#if defined(TCP_NOTSENT_LOWAT)
		if (global.tune.server_notsent_lowat != 0) {
			memprintf(err, "'%s' already specified. Continuing.", args[0]);
			return 1;
		}
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		res = parse_size_err(args[1], &global.tune.server_notsent_lowat);
		if (res != NULL)
			goto size_err;

		return 0;
#else
		memprintf(err, "'%s' is not supported on this system.", args[0]);
		return -1;
#endif
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
	else if (strcmp(args[0], "tune.defaults.purge") == 0) {
		if (args[1]) {
			struct ist arg = ist(args[1]);
			/* First check exclusive values "all" and "none". */
			if (isteq(arg, ist("all"))) {
				global.tune.options |= GTUNE_PURGE_DEFAULTS|GTUNE_PURGE_DEF_SRV;
			}
			else if (isteq(arg, ist("none"))) {
				global.tune.options &= ~(GTUNE_PURGE_DEFAULTS|GTUNE_PURGE_DEF_SRV);
			}
			else {
				/* Treat argument value as a comma separated list. */
				do {
					struct ist token = istsplit(&arg, ',');

					if (isteq(token, ist("proxies"))) {
						global.tune.options |= GTUNE_PURGE_DEFAULTS;
					}
					else if (isteq(token, ist("servers"))) {
						global.tune.options |= GTUNE_PURGE_DEF_SRV;
					}
					else if (isteq(token, ist("all")) ||
					         isteq(token, ist("none"))) {
						memprintf(err, "'%s' value '%s' is exclusive.", args[0], ist0(token));
						return -1;
					}
					else {
						memprintf(err, "'%s' unknown directive '%s'.", args[0], ist0(token));
						return -1;
					}
				} while (istlen(arg));
			}
		}
		else {
			/* default value if no argument : purge defaults proxies. */
			global.tune.options |= GTUNE_PURGE_DEFAULTS;
		}
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
	else if (strcmp(args[0], "tune.streams-elasticity") == 0) {
		char *stop;

		global.tune.streams_elasticity = strtol(args[1], &stop, 10);
		if (!*args[1] || *stop ||
		    (global.tune.streams_elasticity && global.tune.streams_elasticity < 100)) {
			memprintf(err, "'%s' expects 0 or a positive percentage value of 100 or above", args[0]);
			return -1;
		}
	}
	else if (strcmp(args[0], "tune.takeover-other-tg-connections") == 0) {
		ha_warning("parsing [%s:%d]: '%s' is deprecated and will be removed in version 3.7. Please use 'tune.idle-pool.shared\n", file, line, args[0]);
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects 'none', 'restricted', or 'full'", args[0]);
			return -1;
		}
		if (strcmp(args[1], "none") == 0)
			global.tune.tg_takeover = NO_THREADGROUP_TAKEOVER;
		else if (strcmp(args[1], "restricted") == 0)
			global.tune.tg_takeover = RESTRICTED_THREADGROUP_TAKEOVER;
		else if (strcmp(args[1], "full") == 0)
			global.tune.tg_takeover = FULL_THREADGROUP_TAKEOVER;
		else {
			memprintf(err, "'%s' expects 'none', 'restricted', or 'full', got '%s'", args[0], args[1]);
			return -1;
		}
	}
	else if (strcmp(args[0], "tune.glitches.kill.cpu-usage") == 0) {
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects a numeric value between 0 and 100", args[0]);
			return -1;
		}
		global.tune.glitch_kill_maxidle = 100 - atoi(args[1]);
		if (global.tune.glitch_kill_maxidle > 100) {
			memprintf(err, "'%s' expects a numeric value between 0 and 100", args[0]);
			return -1;
		}
		return 0;
	}
	else if (strcmp(args[0], "tune.fd.tables") == 0) {
#ifdef HA_HAVE_UNSHARE
		if (strcmp(args[1], "per-thread-group") == 0)
			global.tune.options |= GTUNE_NO_TG_FD_SHARING;
		else if (strcmp(args[1], "shared") == 0)
			global.tune.options &= ~GTUNE_NO_TG_FD_SHARING;
		else {
			memprintf(err, "'%s' expects 'shared' or 'per-thread-group', got '%s'", args[0], args[1]);
			return -1;
		}
		return 0;
#else
		memprintf(err, "'%s' is not supported on that platform", args[0]);
		return -1;
#endif
	}
	else {
		BUG_ON(1, "Triggered in cfg_parse_global_tune_opts() by unsupported keyword.");
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
		global.tune.options &= ~GTUNE_USE_FAST_FWD;
	}
	else if (strcmp(args[0], "tune.disable-zero-copy-forwarding") == 0) {
		global.tune.no_zero_copy_fwd |= NO_ZERO_COPY_FWD;
	}
	else {
		BUG_ON(1, "Triggered in cfg_parse_global_tune_forward_opts() by unsupported keyword.");
		return -1;
	}

	return 0;

}

/* Parser for tune options related to the symbol resolution used for
 * backtraces.
 */
static int cfg_parse_global_tune_debug_opts(char **args, int section_type,
					    struct proxy *curpx, const struct proxy *defpx,
					    const char *file, int line, char **err)
{
	if (strcmp(args[0], "tune.disable-elf-symbols") == 0) {
		if (too_many_args(0, args, err, NULL))
			return -1;
		global.tune.debug |= GDBG_NO_ELF_SYMS;
	}
	else if (strcmp(args[0], "tune.debug-file-directory") == 0) {
		if (too_many_args(1, args, err, NULL))
			return -1;
		if (!*args[1]) {
			memprintf(err, "'%s' expects a directory path.", args[0]);
			return -1;
		}
		if (sym_add_debug_dir(args[1]) < 0) {
			memprintf(err, "out of memory while adding '%s' for '%s'.", args[1], args[0]);
			return -1;
		}
	}
	else {
		BUG_ON(1, "Triggered in cfg_parse_global_tune_debug_opts() by unsupported keyword.");
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
		BUG_ON(1, "Triggered in cfg_parse_global_unsupported_opts() by unsupported keyword.");
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
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects environment variable name.\n.",
				  args[0]);
			return -1;
		}

		if (*(args[2]) == 0) {
			memprintf(err, "'%s' expects environment variable value for '%s'.\n.",
				  args[0], args[1]);
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
		BUG_ON(1, "Triggered in cfg_parse_global_env_opts() by unsupported keyword.");
		return -1;
	}

	return 0;
}

static int cfg_parse_global_shm_stats_file(char **args, int section_type,
				           struct proxy *curpx, const struct proxy *defpx,
				           const char *file, int line, char **err)
{
	if (global.shm_stats_file != NULL) {
		memprintf(err, "'%s' already specified.\n", args[0]);
		return -1;
	}

	if (!*(args[1])) {
		memprintf(err, "'%s' expect one argument: a file path.\n", args[0]);
		return -1;
	}

	global.shm_stats_file = strdup(args[1]);
	return 0;
}

static int cfg_parse_global_shm_stats_file_max_objects(char **args, int section_type,
				                       struct proxy *curpx, const struct proxy *defpx,
				                       const char *file, int line, char **err)
{
	if (shm_stats_file_max_objects != -1) {
		memprintf(err, "'%s' already specified.\n", args[0]);
		return -1;
	}

	if (!*(args[1])) {
		memprintf(err, "'%s' expect one argument: max objects number.\n", args[0]);
		return -1;
	}

	shm_stats_file_max_objects = atoi(args[1]);
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
		BUG_ON(1, "Triggered in cfg_parse_tune_renice() by unsupported keyword.");
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
					"(process is need to be started with root privileges to be able to chroot).\n",
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

/* Parses the "worker-id" keyword, which assigns a unique identifier to this
 * worker process. It is preset to a UUID v7 generated at boot (see
 * init_worker_id()). It is parsed only by the worker and the environment
 * variable is set on the fly so that its value is instantly known from next
 * directives making use of "$HAPROXY_WORKER_ID" (e.g. log-format).
 */
static int cfg_parse_global_worker_id(char **args, int section_type, struct proxy *curpx,
                                      const struct proxy *defpx, const char *file, int line,
                                      char **err)
{
	char *errmsg = NULL;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects an identifier as an argument.", args[0]);
		return -1;
	}

	if (!guid_is_valid_fmt(args[1], &errmsg)) {
		memprintf(err, "'%s': %s.", args[0], errmsg);
		free(errmsg);
		return -1;
	}

	if (setenv("HAPROXY_WORKER_ID", args[1], 1) != 0) {
		memprintf(err, "'%s' failed to set HAPROXY_WORKER_ID to '%s' : %s.\n",
			  args[0], args[1], strerror(errno));
		return -1;
	}

	ha_free(&global.worker_id);
	global.worker_id = strdup(args[1]);
	if (!global.worker_id) {
		memprintf(err, "cannot allocate memory for '%s'.", args[0]);
		return -1;
	}

	return 0;
}

/* Parses the global keywords which take no argument and only set or clear a
 * boolean, most often one of the GTUNE_* options. Some of them also support
 * the "no" modifier, which is checked via cfg_curr_kwm.
 */
static int cfg_parse_global_bool_opts(char **args, int section_type, struct proxy *curpx,
                                      const struct proxy *defpx, const char *file, int line,
                                      char **err)
{
	if (too_many_args(0, args, err, NULL))
		return -1;

	if (strcmp(args[0], "busy-polling") == 0) {
		if (cfg_curr_kwm == KWM_NO)
			global.tune.options &= ~GTUNE_BUSY_POLLING;
		else
			global.tune.options |=  GTUNE_BUSY_POLLING;
	}
	else if (strcmp(args[0], "h2-workaround-bogus-websocket-clients") == 0) {
		if (cfg_curr_kwm == KWM_NO)
			global.tune.options &= ~GTUNE_DISABLE_H2_WEBSOCKET;
		else
			global.tune.options |=  GTUNE_DISABLE_H2_WEBSOCKET;
	}
	else if (strcmp(args[0], "insecure-fork-wanted") == 0) {
		if (cfg_curr_kwm == KWM_NO)
			global.tune.options &= ~GTUNE_INSECURE_FORK;
		else
			global.tune.options |=  GTUNE_INSECURE_FORK;
	}
	else if (strcmp(args[0], "insecure-setuid-wanted") == 0) {
		if (cfg_curr_kwm == KWM_NO)
			global.tune.options &= ~GTUNE_INSECURE_SETUID;
		else
			global.tune.options |=  GTUNE_INSECURE_SETUID;
	}
	else if (strcmp(args[0], "limited-quic") == 0) {
		global.tune.options |= GTUNE_LIMITED_QUIC;
	}
	else if (strcmp(args[0], "nogetaddrinfo") == 0) {
		global.tune.options &= ~GTUNE_USE_GAI;
	}
	else if (strcmp(args[0], "noreuseport") == 0) {
		protocol_clrf_all(PROTO_F_REUSEPORT_SUPPORTED);
	}
	else if (strcmp(args[0], "nosplice") == 0) {
		global.tune.options &= ~GTUNE_USE_SPLICE;
	}
	else if (strcmp(args[0], "numa-cpu-mapping") == 0) {
		global.numa_cpu_mapping = (cfg_curr_kwm == KWM_NO) ? 0 : 1;
	}
	else if (strcmp(args[0], "quick-exit") == 0) {
		global.tune.options |= GTUNE_QUICK_EXIT;
	}
	else if (strcmp(args[0], "strict-limits") == 0) {
		if (cfg_curr_kwm == KWM_NO)
			global.tune.options &= ~GTUNE_STRICT_LIMITS;
	}
	else {
		BUG_ON(1, "unhandled keyword in cfg_parse_global_bool_opts().");
		return -1;
	}

	return 0;
}

/* Parses the "set-dumpable" keyword, which also supports the "no" modifier. */
static int cfg_parse_global_set_dumpable(char **args, int section_type, struct proxy *curpx,
                                         const struct proxy *defpx, const char *file, int line,
                                         char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (cfg_curr_kwm == KWM_NO) {
		global.tune.options &= ~GTUNE_SET_DUMPABLE;
		return 0;
	}

	if (!*args[1] || strcmp(args[1], "on") == 0)
		global.tune.options |= GTUNE_SET_DUMPABLE;
	else if (strcmp(args[1], "libs") == 0)
		global.tune.options |= GTUNE_SET_DUMPABLE | GTUNE_COLLECT_LIBS;
	else if (strcmp(args[1], "off") == 0)
		global.tune.options &= ~GTUNE_SET_DUMPABLE;
	else {
		memprintf(err, "'%s' only supports 'on' and 'off' as an argument, found '%s'.", args[0], args[1]);
		return -1;
	}

	return 0;
}

/* Parses the "uid", "gid", "user" and "group" keywords, which all end up
 * setting global.uid or global.gid, either from a number or from a system
 * user or group name.
 */
static int cfg_parse_global_uid_gid(char **args, int section_type, struct proxy *curpx,
                                    const struct proxy *defpx, const char *file, int line,
                                    char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[0], "uid") == 0) {
		if (global.uid >= 0) {
			ha_alert("parsing [%s:%d] : user/uid already specified. Continuing.\n", file, line);
			return 0;
		}
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		if (strl2irc(args[1], strlen(args[1]), &global.uid) != 0) {
			memprintf(err, "uid: string '%s' is not a number.\n"
				  "   | You might want to use the 'user' parameter to use a system user name.",
				  args[1]);
			return 1;
		}
	}
	else if (strcmp(args[0], "gid") == 0) {
		if (global.gid >= 0) {
			ha_alert("parsing [%s:%d] : group/gid already specified. Continuing.\n", file, line);
			return 0;
		}
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		if (strl2irc(args[1], strlen(args[1]), &global.gid) != 0) {
			memprintf(err, "gid: string '%s' is not a number.\n"
				  "   | You might want to use the 'group' parameter to use a system group name.",
				  args[1]);
			return 1;
		}
	}
	else if (strcmp(args[0], "user") == 0) {
		struct passwd *ha_user;

		if (global.uid >= 0) {
			ha_alert("parsing [%s:%d] : user/uid already specified. Continuing.\n", file, line);
			return 0;
		}

		if (build_is_static)
			ha_warning("parsing [%s:%d] : haproxy is built statically, the "
				   "libc might crash when resolving \"user %s\", "
				   "please use \"uid\" instead\n",
				   file, line, args[1]);

		errno = 0;
		ha_user = getpwnam(args[1]);
		if (!ha_user) {
			memprintf(err, "cannot find user id for '%s' (%d:%s)", args[1], errno, strerror(errno));
			return -1;
		}
		global.uid = (int)ha_user->pw_uid;
	}
	else if (strcmp(args[0], "group") == 0) {
		struct group *ha_group;

		if (global.gid >= 0) {
			ha_alert("parsing [%s:%d] : gid/group was already specified. Continuing.\n", file, line);
			return 0;
		}

		if (build_is_static)
			ha_warning("parsing [%s:%d] : haproxy is built statically, the "
				   "libc might crash when resolving \"group %s\", "
				   "please use \"gid\" instead\n",
				   file, line, args[1]);

		errno = 0;
		ha_group = getgrnam(args[1]);
		if (!ha_group) {
			memprintf(err, "cannot find group id for '%s' (%d:%s)", args[1], errno, strerror(errno));
			return -1;
		}
		global.gid = (int)ha_group->gr_gid;
	}
	else {
		BUG_ON(1, "unhandled keyword in cfg_parse_global_uid_gid().");
		return -1;
	}

	return 0;
}

/* Parses the "external-check" keyword. */
static int cfg_parse_global_external_check(char **args, int section_type, struct proxy *curpx,
                                           const struct proxy *defpx, const char *file, int line,
                                           char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	global.external_check = 1;
	if (strcmp(args[1], "preserve-env") == 0)
		global.external_check = 2;
	else if (*args[1]) {
		memprintf(err, "'%s' only supports 'preserve-env' as an argument, found '%s'.", args[0], args[1]);
		return -1;
	}

	return 0;
}

/* Parses the "cluster-secret" keyword. The secret is not stored as-is, only
 * its SHA1 digest is kept.
 */
static int cfg_parse_global_cluster_secret(char **args, int section_type, struct proxy *curpx,
                                           const struct proxy *defpx, const char *file, int line,
                                           char **err)
{
	blk_SHA_CTX sha1_ctx;
	unsigned char sha1_out[20];

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*args[1] == 0) {
		memprintf(err, "'%s' expects an ASCII string argument.", args[0]);
		return -1;
	}

	if (cluster_secret_isset) {
		ha_warning("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, line, args[0]);
		return 0;
	}

	blk_SHA1_Init(&sha1_ctx);
	blk_SHA1_Update(&sha1_ctx, args[1], strlen(args[1]));
	blk_SHA1_Final(sha1_out, &sha1_ctx);
	BUG_ON(sizeof sha1_out < sizeof global.cluster_secret);
	memcpy(global.cluster_secret, sha1_out, sizeof global.cluster_secret);
	cluster_secret_isset = 1;

	return 0;
}

/* Parses the global keywords which set one of the process-wide limits, such
 * as "maxconn" or "ulimit-n". They all take a single integer argument and may
 * only be specified once.
 */
static int cfg_parse_global_limits(char **args, int section_type, struct proxy *curpx,
                                   const struct proxy *defpx, const char *file, int line,
                                   char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[0], "maxconn") == 0) {
		char *stop;

		if (global.maxconn != 0)
			goto already_set;
		if (*(args[1]) == 0)
			goto expect_integer;

		global.maxconn = strtol(args[1], &stop, 10);
		if (*stop != '\0') {
			memprintf(err, "cannot parse '%s' value '%s', an integer is expected.", args[0], args[1]);
			return -1;
		}
#ifdef SYSTEM_MAXCONN
		if (global.maxconn > SYSTEM_MAXCONN && cfg_maxconn <= SYSTEM_MAXCONN) {
			ha_alert("parsing [%s:%d] : maxconn value %d too high for this system.\n"
				 "Limiting to %d. Please use '-n' to force the value.\n",
				 file, line, global.maxconn, SYSTEM_MAXCONN);
			global.maxconn = SYSTEM_MAXCONN;
		}
#endif /* SYSTEM_MAXCONN */
	}
	else if (strcmp(args[0], "maxconnrate") == 0) {
		if (global.cps_lim != 0)
			goto already_set;
		if (*(args[1]) == 0)
			goto expect_integer;
		global.cps_lim = atol(args[1]);
	}
	else if (strcmp(args[0], "maxsessrate") == 0) {
		if (global.sps_lim != 0)
			goto already_set;
		if (*(args[1]) == 0)
			goto expect_integer;
		global.sps_lim = atol(args[1]);
	}
	else if (strcmp(args[0], "maxsslrate") == 0) {
		if (global.ssl_lim != 0)
			goto already_set;
		if (*(args[1]) == 0)
			goto expect_integer;
		global.ssl_lim = atol(args[1]);
	}
	else if (strcmp(args[0], "maxpipes") == 0) {
		if (global.maxpipes != 0)
			goto already_set;
		if (*(args[1]) == 0)
			goto expect_integer;
		global.maxpipes = atol(args[1]);
	}
	else if (strcmp(args[0], "fd-hard-limit") == 0) {
		if (global.fd_hard_limit != 0)
			goto already_set;
		if (*(args[1]) == 0)
			goto expect_integer;
		global.fd_hard_limit = atol(args[1]);
	}
	else if (strcmp(args[0], "ulimit-n") == 0) {
		if (global.rlimit_nofile != 0)
			goto already_set;
		if (*(args[1]) == 0)
			goto expect_integer;
		global.rlimit_nofile = atol(args[1]);
	}
	else {
		BUG_ON(1, "unhandled keyword in cfg_parse_global_limits().");
		return -1;
	}

	return 0;

 already_set:
	ha_warning("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, line, args[0]);
	return 0;

 expect_integer:
	memprintf(err, "'%s' expects an integer argument.", args[0]);
	return -1;
}

/* Parses the global keywords which limit the resources dedicated to the
 * compression: "maxcomprate", "maxzlibmem" and "maxcompcpuusage".
 */
static int cfg_parse_global_comp_limits(char **args, int section_type, struct proxy *curpx,
                                        const struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[0], "maxcomprate") == 0) {
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument in kb/s.", args[0]);
			return -1;
		}
		global.comp_rate_lim = atoi(args[1]) * 1024;
	}
	else if (strcmp(args[0], "maxzlibmem") == 0) {
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument.", args[0]);
			return -1;
		}
		global.maxzlibmem = atol(args[1]) * 1024L * 1024L;
	}
	else if (strcmp(args[0], "maxcompcpuusage") == 0) {
		if (*(args[1]) == 0)
			goto expect_percent;

		compress_min_idle = 100 - atoi(args[1]);
		if (compress_min_idle > 100)
			goto expect_percent;
	}
	else {
		BUG_ON(1, "unhandled keyword in cfg_parse_global_comp_limits().");
		return -1;
	}

	return 0;

 expect_percent:
	memprintf(err, "'%s' expects an integer argument between 0 and 100.", args[0]);
	return -1;
}

/* Parses the "ssl-server-verify" keyword. */
static int cfg_parse_global_ssl_server_verify(char **args, int section_type, struct proxy *curpx,
                                              const struct proxy *defpx, const char *file, int line,
                                              char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects an integer argument.", args[0]);
		return -1;
	}

	if (strcmp(args[1], "none") == 0)
		global.ssl_server_verify = SSL_SERVER_VERIFY_NONE;
	else if (strcmp(args[1], "required") == 0)
		global.ssl_server_verify = SSL_SERVER_VERIFY_REQUIRED;
	else {
		memprintf(err, "'%s' expects 'none' or 'required' as argument.", args[0]);
		return -1;
	}

	return 0;
}

/* Parses the "node" and "description" keywords, which sets the name and
 * description for this node.
 */
static int cfg_parse_global_node_desc(char **args, int section_type, struct proxy *curpx,
                                      const struct proxy *defpx, const char *file, int line,
                                      char **err)
{
	if (strcmp(args[0], "description") == 0) {
		int i, len = 0;
		char *d;

		if (!*args[1]) {
			memprintf(err, "'%s' expects a string argument.", args[0]);
			return -1;
		}

		for (i = 1; *args[i]; i++)
			len += strlen(args[i]) + 1;

		d = calloc(1, len);
		if (!d) {
			memprintf(err, "cannot allocate memory for '%s'.", args[0]);
			return -1;
		}

		free(global.desc);
		global.desc = d;

		d += snprintf(d, global.desc + len - d, "%s", args[1]);
		for (i = 2; *args[i]; i++)
			d += snprintf(d, global.desc + len - d, " %s", args[i]);
	}
	else if (strcmp(args[0], "node") == 0) {
		char *node;
		int i;
		char c;

		if (too_many_args(1, args, err, NULL))
			return -1;

		for (i = 0; args[1][i]; i++) {
			c = args[1][i];
			if (!isupper((unsigned char)c) && !islower((unsigned char)c) &&
			    !isdigit((unsigned char)c) && c != '_' && c != '-' && c != '.')
				break;
		}

		if (!i || args[1][i]) {
			memprintf(err, "'%s' requires valid node name - non-empty string"
				  " with digits(0-9), letters(A-Z, a-z), dot(.), hyphen(-) or underscode(_).",
				  args[0]);
			return -1;
		}

		node = strdup(args[1]);
		if (!node) {
			memprintf(err, "cannot allocate memory for '%s'.", args[0]);
			return -1;
		}

		free(global.node);
		global.node = node;
	}
	else {
		BUG_ON(1, "unhandled keyword in cfg_parse_global_node_desc().");
		return -1;
	}

	return 0;
}

/* Parses the "unix-bind" keyword, which sets the default ownership and
 * permissions of the UNIX sockets, as well as an optional path prefix.
 */
static int cfg_parse_global_unix_bind(char **args, int section_type, struct proxy *curpx,
                                      const struct proxy *defpx, const char *file, int line,
                                      char **err)
{
	int cur_arg = 1;

	while (*(args[cur_arg])) {
		if (strcmp(args[cur_arg], "prefix") == 0) {
			char *prefix;

			if (global.unix_bind.prefix != NULL) {
				ha_warning("parsing [%s:%d] : unix-bind '%s' already specified. Continuing.\n",
					   file, line, args[cur_arg]);
				cur_arg += 2;
				continue;
			}

			if (*(args[cur_arg+1]) == 0) {
				memprintf(err, "unix_bind '%s' expects a path as an argument.", args[cur_arg]);
				return -1;
			}

			prefix = strdup(args[cur_arg+1]);
			if (!prefix) {
				memprintf(err, "cannot allocate memory for '%s %s'.", args[0], args[cur_arg]);
				return -1;
			}
			global.unix_bind.prefix = prefix;
			cur_arg += 2;
		}
		else if (strcmp(args[cur_arg], "mode") == 0) {
			global.unix_bind.ux.mode = strtol(args[cur_arg + 1], NULL, 8);
			cur_arg += 2;
		}
		else if (strcmp(args[cur_arg], "uid") == 0) {
			global.unix_bind.ux.uid = atol(args[cur_arg + 1]);
			cur_arg += 2;
		}
		else if (strcmp(args[cur_arg], "gid") == 0) {
			global.unix_bind.ux.gid = atol(args[cur_arg + 1]);
			cur_arg += 2;
		}
		else if (strcmp(args[cur_arg], "user") == 0) {
			struct passwd *user;

			user = getpwnam(args[cur_arg + 1]);
			if (!user) {
				memprintf(err, "'%s' : '%s' unknown user.", args[0], args[cur_arg + 1]);
				return -1;
			}

			global.unix_bind.ux.uid = user->pw_uid;
			cur_arg += 2;
		}
		else if (strcmp(args[cur_arg], "group") == 0) {
			struct group *group;

			group = getgrnam(args[cur_arg + 1]);
			if (!group) {
				memprintf(err, "'%s' : '%s' unknown group.", args[0], args[cur_arg + 1]);
				return -1;
			}

			global.unix_bind.ux.gid = group->gr_gid;
			cur_arg += 2;
		}
		else {
			memprintf(err, "'%s' only supports the 'prefix', 'mode', 'uid', 'gid', 'user' and 'group' options.",
				  args[0]);
			return -1;
		}
	}

	return 0;
}

/* Parses the log-related global keywords: "log", "log-send-hostname" and
 * "log-tag".
 */
static int cfg_parse_global_log_opts(char **args, int section_type, struct proxy *curpx,
                                     const struct proxy *defpx, const char *file, int line,
                                     char **err)
{
	if (strcmp(args[0], "log") == 0) { /* "no log" or "log ..." */
		char *errmsg = NULL;

		if (!parse_logger(args, &global.loggers, (cfg_curr_kwm == KWM_NO), file, line, &errmsg)) {
			memprintf(err, "%s : %s", args[0], errmsg);
			free(errmsg);
			return -1;
		}
	}
	else if (strcmp(args[0], "log-send-hostname") == 0) { /* set the hostname in syslog header */
		char *name;

		if (global.log_send_hostname != NULL) {
			ha_warning("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, line, args[0]);
			return 0;
		}

		if (*(args[1]))
			name = args[1];
		else
			name = hostname;

		name = strdup(name);
		if (!name) {
			memprintf(err, "cannot allocate memory for '%s'.", args[0]);
			return -1;
		}

		global.log_send_hostname = name;
	}
	else if (strcmp(args[0], "log-tag") == 0) {  /* tag to report to syslog */
		if (too_many_args(1, args, err, NULL))
			return -1;

		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects a tag for use in syslog.", args[0]);
			return -1;
		}

		chunk_destroy(&global.log_tag);
		chunk_initlen(&global.log_tag, strdup(args[1]), strlen(args[1]), strlen(args[1]));
		if (b_orig(&global.log_tag) == NULL) {
			chunk_destroy(&global.log_tag);
			memprintf(err, "cannot allocate memory for '%s'.", args[0]);
			return -1;
		}
	}
	else {
		BUG_ON(1, "unhandled keyword in cfg_parse_global_log_opts().");
		return -1;
	}

	return 0;
}

/* Parses the global keywords which designate a file or a directory used to
 * preload the state at boot: "server-state-base", "server-state-file" and
 * "stats-file".
 */
static int cfg_parse_global_state_files(char **args, int section_type, struct proxy *curpx,
                                        const struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	char **dst;
	char *path;

	if (strcmp(args[0], "server-state-base") == 0)
		dst = &global.server_state_base;
	else if (strcmp(args[0], "server-state-file") == 0)
		dst = &global.server_state_file;
	else if (strcmp(args[0], "stats-file") == 0)
		dst = &global.stats_file;
	else {
		BUG_ON(1, "unhandled keyword in cfg_parse_global_state_files().");
		return -1;
	}

	if (*dst) {
		ha_warning("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, line, args[0]);
		return 0;
	}

	if (!*(args[1])) {
		memprintf(err, "'%s' expects one argument: a %s path.", args[0],
			  (dst == &global.server_state_base) ? "directory" : "file");
		return -1;
	}

	path = strdup(args[1]);
	if (!path) {
		memprintf(err, "cannot allocate memory for '%s'.", args[0]);
		return -1;
	}

	*dst = path;
	return 0;
}

/* Parses the "spread-checks" and "max-spread-checks" keywords, which control
 * the spreading of the health checks over time.
 */
static int cfg_parse_global_spread_checks(char **args, int section_type, struct proxy *curpx,
                                          const struct proxy *defpx, const char *file, int line,
                                          char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[0], "spread-checks") == 0) {  /* random time between checks (0-50) */
		if (global.spread_checks != 0) {
			ha_warning("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, line, args[0]);
			return 0;
		}
		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument (0..50).", args[0]);
			return -1;
		}
		global.spread_checks = atol(args[1]);
		if (global.spread_checks < 0 || global.spread_checks > 50) {
			memprintf(err, "'%s' needs a positive value in range 0..50.", args[0]);
			return -1;
		}
	}
	else if (strcmp(args[0], "max-spread-checks") == 0) {  /* maximum time between first and last check */
		const char *res;
		unsigned int val;

		if (*(args[1]) == 0) {
			memprintf(err, "'%s' expects an integer argument (0..50).", args[0]);
			return -1;
		}

		res = parse_time_err(args[1], &val, TIME_UNIT_MS);
		if (res == PARSE_TIME_OVER) {
			memprintf(err, "timer overflow in argument <%s> to <%s>, maximum value is 2147483647 ms (~24.8 days).",
				  args[1], args[0]);
			return -1;
		}
		else if (res == PARSE_TIME_UNDER) {
			memprintf(err, "timer underflow in argument <%s> to <%s>, minimum non-null value is 1 ms.",
				  args[1], args[0]);
			return -1;
		}
		else if (res) {
			memprintf(err, "unsupported character '%c' in '%s' (wants an integer delay).", *res, args[0]);
			return -1;
		}
		global.max_spread_checks = val;
	}
	else {
		BUG_ON(1, "unhandled keyword in cfg_parse_global_spread_checks().");
		return -1;
	}

	return 0;
}

/* Parses the "cpu-map" keyword, which maps a thread group and/or thread range
 * to a CPU set.
 */
static int cfg_parse_global_cpu_map(char **args, int section_type, struct proxy *curpx,
                                    const struct proxy *defpx, const char *file, int line,
                                    char **err)
{
#ifdef USE_CPU_AFFINITY
	char *errmsg = NULL;
	char *slash;
	unsigned long tgroup = 0, thread = 0;
	int g, j, n, autoinc;
	struct hap_cpuset cpus, cpus_copy;

	if (!*args[1] || !*args[2]) {
		memprintf(err, "%s expects a thread group number "
			  " ('all', 'odd', 'even', a number from 1 to %d or a range), "
			  " followed by a list of CPU ranges with numbers from 0 to %d.",
			  args[0], LONGBITS, LONGBITS - 1);
		return -1;
	}

	if ((slash = strchr(args[1], '/')) != NULL)
		*slash = 0;

	/* note: we silently ignore thread group numbers over MAX_TGROUPS
	 * and threads over MAX_THREADS so as not to make configurations a
	 * pain to maintain.
	 */
	if (parse_process_number(args[1], &tgroup, LONGBITS, &autoinc, &errmsg) != 0)
		goto err_with_msg;

	if (slash) {
		if (parse_process_number(slash+1, &thread, LONGBITS, NULL, &errmsg) != 0)
			goto err_with_msg;

		*slash = '/';
	} else
		thread = ~0UL; /* missing '/' = 'all' */

	/* from now on, thread cannot be NULL anymore */

	if (parse_cpu_set((const char **)args+2, &cpus, &errmsg) != 0)
		goto err_with_msg;

	if (autoinc &&
	    my_popcountl(tgroup) != ha_cpuset_count(&cpus) &&
	    my_popcountl(thread) != ha_cpuset_count(&cpus)) {
		memprintf(err, "%s : TGROUP/THREAD range and CPU sets "
			  "must have the same size to be automatically bound", args[0]);
		return -1;
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

	return 0;

 err_with_msg:
	/* reports errmsg, frees it and returns a failure */
	memprintf(err, "%s : %s", args[0], errmsg);
	free(errmsg);
	return -1;
#else
	memprintf(err, "'%s' is not enabled, please check build options for USE_CPU_AFFINITY.", args[0]);
	return -1;
#endif /* ! USE_CPU_AFFINITY */
}

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "busy-polling", cfg_parse_global_bool_opts },
	{ CFG_GLOBAL, "chroot", cfg_parse_global_chroot },
	{ CFG_GLOBAL, "cluster-secret", cfg_parse_global_cluster_secret },
	{ CFG_GLOBAL, "cpu-map", cfg_parse_global_cpu_map },
	{ CFG_GLOBAL, "daemon", cfg_parse_global_mode, KWF_DISCOVERY } ,
	{ CFG_GLOBAL, "external-check", cfg_parse_global_external_check },
	{ CFG_GLOBAL, "description", cfg_parse_global_node_desc },
	{ CFG_GLOBAL, "expose-deprecated-directives", cfg_parse_global_non_std_directives, KWF_DISCOVERY },
	{ CFG_GLOBAL, "expose-experimental-directives", cfg_parse_global_non_std_directives },
	{ CFG_GLOBAL, "fd-hard-limit", cfg_parse_global_limits },
	{ CFG_GLOBAL, "force-cfg-parser-pause", cfg_parse_global_parser_pause, KWF_EXPERIMENTAL },
	{ CFG_GLOBAL, "h2-workaround-bogus-websocket-clients", cfg_parse_global_bool_opts },
	{ CFG_GLOBAL, "harden.reject-privileged-ports.quic", cfg_parse_reject_privileged_ports },
	{ CFG_GLOBAL, "harden.reject-privileged-ports.tcp",  cfg_parse_reject_privileged_ports },
	{ CFG_GLOBAL, "gid", cfg_parse_global_uid_gid },
	{ CFG_GLOBAL, "group", cfg_parse_global_uid_gid },
	{ CFG_GLOBAL, "insecure-fork-wanted", cfg_parse_global_bool_opts },
	{ CFG_GLOBAL, "insecure-setuid-wanted", cfg_parse_global_bool_opts },
	{ CFG_GLOBAL, "limited-quic", cfg_parse_global_bool_opts },
	{ CFG_GLOBAL, "log", cfg_parse_global_log_opts },
	{ CFG_GLOBAL, "log-send-hostname", cfg_parse_global_log_opts },
	{ CFG_GLOBAL, "log-tag", cfg_parse_global_log_opts },
	{ CFG_GLOBAL, "localpeer", cfg_parse_global_localpeer, KWF_DISCOVERY },
	{ CFG_GLOBAL, "master-worker", cfg_parse_global_master_worker, KWF_DISCOVERY },
	{ CFG_GLOBAL, "max-spread-checks", cfg_parse_global_spread_checks },
	{ CFG_GLOBAL, "maxconn", cfg_parse_global_limits },
	{ CFG_GLOBAL, "maxconnrate", cfg_parse_global_limits },
	{ CFG_GLOBAL, "maxcompcpuusage", cfg_parse_global_comp_limits },
	{ CFG_GLOBAL, "maxcomprate", cfg_parse_global_comp_limits },
	{ CFG_GLOBAL, "maxpipes", cfg_parse_global_limits },
	{ CFG_GLOBAL, "maxsessrate", cfg_parse_global_limits },
	{ CFG_GLOBAL, "maxsslrate", cfg_parse_global_limits },
	{ CFG_GLOBAL, "maxzlibmem", cfg_parse_global_comp_limits },
	{ CFG_GLOBAL, "nbproc", cfg_parse_global_unsupported_opts },
	{ CFG_GLOBAL, "nogetaddrinfo", cfg_parse_global_bool_opts },
	{ CFG_GLOBAL, "node", cfg_parse_global_node_desc },
	{ CFG_GLOBAL, "noepoll", cfg_parse_global_disable_poller, KWF_DISCOVERY },
	{ CFG_GLOBAL, "noevports", cfg_parse_global_disable_poller, KWF_DISCOVERY },
	{ CFG_GLOBAL, "nokqueue", cfg_parse_global_disable_poller, KWF_DISCOVERY },
	{ CFG_GLOBAL, "noktls", cfg_parse_global_disable_ktls, KWF_DISCOVERY },
	{ CFG_GLOBAL, "nopoll", cfg_parse_global_disable_poller, KWF_DISCOVERY },
	{ CFG_GLOBAL, "noreuseport", cfg_parse_global_bool_opts },
	{ CFG_GLOBAL, "nosplice", cfg_parse_global_bool_opts },
	{ CFG_GLOBAL, "numa-cpu-mapping", cfg_parse_global_bool_opts },
	{ CFG_GLOBAL, "pidfile", cfg_parse_global_pidfile, KWF_DISCOVERY },
	{ CFG_GLOBAL, "prealloc-fd", cfg_parse_prealloc_fd },
	{ CFG_GLOBAL, "presetenv", cfg_parse_global_env_opts, KWF_DISCOVERY },
	{ CFG_GLOBAL, "quick-exit", cfg_parse_global_bool_opts },
	{ CFG_GLOBAL, "quiet", cfg_parse_global_mode, KWF_DISCOVERY },
	{ CFG_GLOBAL, "resetenv", cfg_parse_global_env_opts, KWF_DISCOVERY },
	{ CFG_GLOBAL, "server-state-base", cfg_parse_global_state_files },
	{ CFG_GLOBAL, "server-state-file", cfg_parse_global_state_files },
	{ CFG_GLOBAL, "setenv", cfg_parse_global_env_opts, KWF_DISCOVERY },
	{ CFG_GLOBAL, "set-dumpable", cfg_parse_global_set_dumpable },
	{ CFG_GLOBAL, "shm-stats-file", cfg_parse_global_shm_stats_file },
	{ CFG_GLOBAL, "shm-stats-file-max-objects", cfg_parse_global_shm_stats_file_max_objects },
	{ CFG_GLOBAL, "spread-checks", cfg_parse_global_spread_checks },
	{ CFG_GLOBAL, "ssl-server-verify", cfg_parse_global_ssl_server_verify },
	{ CFG_GLOBAL, "stats-file", cfg_parse_global_state_files },
	{ CFG_GLOBAL, "stress-level", cfg_parse_global_stress_level },
	{ CFG_GLOBAL, "strict-limits", cfg_parse_global_bool_opts },
	{ CFG_GLOBAL, "tune.bufsize", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.chksize", cfg_parse_global_unsupported_opts },
	{ CFG_GLOBAL, "tune.comp.maxlevel", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.debug-file-directory", cfg_parse_global_tune_debug_opts },
	{ CFG_GLOBAL, "tune.defaults.purge", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.disable-elf-symbols", cfg_parse_global_tune_debug_opts },
	{ CFG_GLOBAL, "tune.disable-fast-forward", cfg_parse_global_tune_forward_opts },
	{ CFG_GLOBAL, "tune.disable-zero-copy-forwarding", cfg_parse_global_tune_forward_opts },
	{ CFG_GLOBAL, "tune.fd.tables", cfg_parse_global_tune_opts, KWF_EXPERIMENTAL },
	{ CFG_GLOBAL, "tune.glitches.kill.cpu-usage", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.http.cookielen", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.http.logurilen", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.http.maxhdr", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.idletimer", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.max-rules-at-once", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.maxaccept", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.maxpollevents", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.maxrewrite", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.notsent-lowat.client", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.notsent-lowat.server", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.pattern.cache-size", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.pipesize", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.rcvbuf.client", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.rcvbuf.server", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.recv_enough", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.renice.runtime", cfg_parse_tune_renice },
	{ CFG_GLOBAL, "tune.renice.startup", cfg_parse_tune_renice },
	{ CFG_GLOBAL, "tune.runqueue-depth", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.sndbuf.client", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.sndbuf.server", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.streams-elasticity", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "tune.takeover-other-tg-connections", cfg_parse_global_tune_opts },
	{ CFG_GLOBAL, "uid", cfg_parse_global_uid_gid },
	{ CFG_GLOBAL, "ulimit-n", cfg_parse_global_limits },
	{ CFG_GLOBAL, "unix-bind", cfg_parse_global_unix_bind },
	{ CFG_GLOBAL, "unsetenv", cfg_parse_global_env_opts, KWF_DISCOVERY },
	{ CFG_GLOBAL, "worker-id", cfg_parse_global_worker_id },
	{ CFG_GLOBAL, "user", cfg_parse_global_uid_gid },
	{ CFG_GLOBAL, "zero-warning", cfg_parse_global_mode, KWF_DISCOVERY },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
