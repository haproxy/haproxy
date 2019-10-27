#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <common/cfgparse.h>
#include <proto/compression.h>

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

	if (!strcmp(args[0], "global")) {  /* new section */
		/* no option, nothing special to do */
		alertif_too_many_args(0, file, linenum, args, &err_code);
		goto out;
	}
	else if (!strcmp(args[0], "daemon")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.mode |= MODE_DAEMON;
	}
	else if (!strcmp(args[0], "master-worker")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*args[1]) {
			if (!strcmp(args[1], "no-exit-on-failure")) {
				global.tune.options |= GTUNE_NOEXIT_ONFAILURE;
			} else {
				ha_alert("parsing [%s:%d] : '%s' only supports 'no-exit-on-failure' option.\n", file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
		global.mode |= MODE_MWORKER;
	}
	else if (!strcmp(args[0], "debug")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.mode |= MODE_DEBUG;
	}
	else if (!strcmp(args[0], "noepoll")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.tune.options &= ~GTUNE_USE_EPOLL;
	}
	else if (!strcmp(args[0], "nokqueue")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.tune.options &= ~GTUNE_USE_KQUEUE;
	}
	else if (!strcmp(args[0], "noevports")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.tune.options &= ~GTUNE_USE_EVPORTS;
	}
	else if (!strcmp(args[0], "nopoll")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.tune.options &= ~GTUNE_USE_POLL;
	}
	else if (!strcmp(args[0], "busy-polling")) { /* "no busy-polling" or "busy-polling" */
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		if (kwm == KWM_NO)
			global.tune.options &= ~GTUNE_BUSY_POLLING;
		else
			global.tune.options |=  GTUNE_BUSY_POLLING;
	}
	else if (!strcmp(args[0], "set-dumpable")) { /* "no set-dumpable" or "set-dumpable" */
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		if (kwm == KWM_NO)
			global.tune.options &= ~GTUNE_SET_DUMPABLE;
		else
			global.tune.options |=  GTUNE_SET_DUMPABLE;
	}
	else if (!strcmp(args[0], "nosplice")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.tune.options &= ~GTUNE_USE_SPLICE;
	}
	else if (!strcmp(args[0], "nogetaddrinfo")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.tune.options &= ~GTUNE_USE_GAI;
	}
	else if (!strcmp(args[0], "noreuseport")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.tune.options &= ~GTUNE_USE_REUSEPORT;
	}
	else if (!strcmp(args[0], "quiet")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.mode |= MODE_QUIET;
	}
	else if (!strcmp(args[0], "tune.runqueue-depth")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.tune.runqueue_depth != 0) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.runqueue_depth = atol(args[1]);

	}
	else if (!strcmp(args[0], "tune.maxpollevents")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.tune.maxpollevents != 0) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.maxpollevents = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.maxaccept")) {
		long max;

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.tune.maxaccept != 0) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		max = atol(args[1]);
		if (/*max < -1 || */max > INT_MAX) {
			ha_alert("parsing [%s:%d] : '%s' expects -1 or an integer from 0 to INT_MAX.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.maxaccept = max;
	}
	else if (!strcmp(args[0], "tune.chksize")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.chksize = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.recv_enough")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.recv_enough = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.buffers.limit")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.buf_limit = atol(args[1]);
		if (global.tune.buf_limit) {
			if (global.tune.buf_limit < 3)
				global.tune.buf_limit = 3;
			if (global.tune.buf_limit <= global.tune.reserved_bufs)
				global.tune.buf_limit = global.tune.reserved_bufs + 1;
		}
	}
	else if (!strcmp(args[0], "tune.buffers.reserve")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.reserved_bufs = atol(args[1]);
		if (global.tune.reserved_bufs < 2)
			global.tune.reserved_bufs = 2;
		if (global.tune.buf_limit && global.tune.buf_limit <= global.tune.reserved_bufs)
			global.tune.buf_limit = global.tune.reserved_bufs + 1;
	}
	else if (!strcmp(args[0], "tune.bufsize")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.bufsize = atol(args[1]);
		/* round it up to support a two-pointer alignment at the end */
		global.tune.bufsize = (global.tune.bufsize + 2 * sizeof(void *) - 1) & -(2 * sizeof(void *));
		if (global.tune.bufsize <= 0) {
			ha_alert("parsing [%s:%d] : '%s' expects a positive integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "tune.maxrewrite")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.maxrewrite = atol(args[1]);
		if (global.tune.maxrewrite < 0) {
			ha_alert("parsing [%s:%d] : '%s' expects a positive integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "tune.idletimer")) {
		unsigned int idle;
		const char *res;

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects a timer value between 0 and 65535 ms.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		res = parse_time_err(args[1], &idle, TIME_UNIT_MS);
		if (res == PARSE_TIME_OVER) {
			ha_alert("parsing [%s:%d]: timer overflow in argument <%s> to <%s>, maximum value is 65535 ms.\n",
			         file, linenum, args[1], args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (res == PARSE_TIME_UNDER) {
			ha_alert("parsing [%s:%d]: timer underflow in argument <%s> to <%s>, minimum non-null value is 1 ms.\n",
			         file, linenum, args[1], args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (res) {
			ha_alert("parsing [%s:%d]: unexpected character '%c' in argument to <%s>.\n",
			         file, linenum, *res, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (idle > 65535) {
			ha_alert("parsing [%s:%d] : '%s' expects a timer value between 0 and 65535 ms.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.idle_timer = idle;
	}
	else if (!strcmp(args[0], "tune.rcvbuf.client")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.tune.client_rcvbuf != 0) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.client_rcvbuf = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.rcvbuf.server")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.tune.server_rcvbuf != 0) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.server_rcvbuf = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.sndbuf.client")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.tune.client_sndbuf != 0) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.client_sndbuf = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.sndbuf.server")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.tune.server_sndbuf != 0) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.server_sndbuf = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.pipesize")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.pipesize = atol(args[1]);
	}
	else if (!strcmp(args[0], "tune.http.cookielen")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.cookie_len = atol(args[1]) + 1;
	}
	else if (!strcmp(args[0], "tune.http.logurilen")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.requri_len = atol(args[1]) + 1;
	}
	else if (!strcmp(args[0], "tune.http.maxhdr")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.tune.max_http_hdr = atoi(args[1]);
		if (global.tune.max_http_hdr < 1 || global.tune.max_http_hdr > 32767) {
			ha_alert("parsing [%s:%d] : '%s' expects a numeric value between 1 and 32767\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "tune.comp.maxlevel")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*args[1]) {
			global.tune.comp_maxlevel = atoi(args[1]);
			if (global.tune.comp_maxlevel < 1 || global.tune.comp_maxlevel > 9) {
				ha_alert("parsing [%s:%d] : '%s' expects a numeric value between 1 and 9\n",
					 file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		} else {
			ha_alert("parsing [%s:%d] : '%s' expects a numeric value between 1 and 9\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "tune.pattern.cache-size")) {
		if (*args[1]) {
			global.tune.pattern_cache = atoi(args[1]);
			if (global.tune.pattern_cache < 0) {
				ha_alert("parsing [%s:%d] : '%s' expects a positive numeric value\n",
					 file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		} else {
			ha_alert("parsing [%s:%d] : '%s' expects a positive numeric value\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "uid")) {
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
	else if (!strcmp(args[0], "gid")) {
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
	else if (!strcmp(args[0], "external-check")) {
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		global.external_check = 1;
	}
	/* user/group name handling */
	else if (!strcmp(args[0], "user")) {
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
	else if (!strcmp(args[0], "group")) {
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
	else if (!strcmp(args[0], "nbproc")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.nbproc = atol(args[1]);
		all_proc_mask = nbits(global.nbproc);
		if (global.nbproc < 1 || global.nbproc > MAX_PROCS) {
			ha_alert("parsing [%s:%d] : '%s' must be between 1 and %d (was %d).\n",
				 file, linenum, args[0], MAX_PROCS, global.nbproc);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "nbthread")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.nbthread = parse_nbthread(args[1], &errmsg);
		if (!global.nbthread) {
			ha_alert("parsing [%s:%d] : '%s' %s.\n",
				 file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "maxconn")) {
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
		global.maxconn = atol(args[1]);
#ifdef SYSTEM_MAXCONN
		if (global.maxconn > SYSTEM_MAXCONN && cfg_maxconn <= SYSTEM_MAXCONN) {
			ha_alert("parsing [%s:%d] : maxconn value %d too high for this system.\nLimiting to %d. Please use '-n' to force the value.\n", file, linenum, global.maxconn, SYSTEM_MAXCONN);
			global.maxconn = SYSTEM_MAXCONN;
			err_code |= ERR_ALERT;
		}
#endif /* SYSTEM_MAXCONN */
	}
	else if (!strcmp(args[0], "ssl-server-verify")) {
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
	else if (!strcmp(args[0], "maxconnrate")) {
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
	else if (!strcmp(args[0], "maxsessrate")) {
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
	else if (!strcmp(args[0], "maxsslrate")) {
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
	else if (!strcmp(args[0], "maxcomprate")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument in kb/s.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.comp_rate_lim = atoi(args[1]) * 1024;
	}
	else if (!strcmp(args[0], "maxpipes")) {
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
	else if (!strcmp(args[0], "maxzlibmem")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.maxzlibmem = atol(args[1]) * 1024L * 1024L;
	}
	else if (!strcmp(args[0], "maxcompcpuusage")) {
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

	else if (!strcmp(args[0], "ulimit-n")) {
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
	else if (!strcmp(args[0], "chroot")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.chroot != NULL) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects a directory as an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.chroot = strdup(args[1]);
	}
	else if (!strcmp(args[0], "description")) {
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
	else if (!strcmp(args[0], "node")) {
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
	else if (!strcmp(args[0], "pidfile")) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (global.pidfile != NULL) {
			ha_alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT;
			goto out;
		}
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects a file name as an argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		global.pidfile = strdup(args[1]);
	}
	else if (!strcmp(args[0], "unix-bind")) {
		int cur_arg = 1;
		while (*(args[cur_arg])) {
			if (!strcmp(args[cur_arg], "prefix")) {
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

			if (!strcmp(args[cur_arg], "mode")) {

				global.unix_bind.ux.mode = strtol(args[cur_arg + 1], NULL, 8);
                                cur_arg += 2;
				continue;
			}

			if (!strcmp(args[cur_arg], "uid")) {

				global.unix_bind.ux.uid = atol(args[cur_arg + 1 ]);
                                cur_arg += 2;
				continue;
                        }

			if (!strcmp(args[cur_arg], "gid")) {

				global.unix_bind.ux.gid = atol(args[cur_arg + 1 ]);
                                cur_arg += 2;
				continue;
                        }

			if (!strcmp(args[cur_arg], "user")) {
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

			if (!strcmp(args[cur_arg], "group")) {
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
	else if (!strcmp(args[0], "log")) { /* "no log" or "log ..." */
		if (!parse_logsrv(args, &global.logsrvs, (kwm == KWM_NO), &errmsg)) {
			ha_alert("parsing [%s:%d] : %s : %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "log-send-hostname")) { /* set the hostname in syslog header */
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
	else if (!strcmp(args[0], "server-state-base")) { /* path base where HAProxy can find server state files */
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
	else if (!strcmp(args[0], "server-state-file")) { /* path to the file where HAProxy can load the server states */
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
	else if (!strcmp(args[0], "log-tag")) {  /* tag to report to syslog */
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects a tag for use in syslog.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		chunk_destroy(&global.log_tag);
		chunk_initstr(&global.log_tag, strdup(args[1]));
	}
	else if (!strcmp(args[0], "spread-checks")) {  /* random time between checks (0-50) */
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
	else if (!strcmp(args[0], "max-spread-checks")) {  /* maximum time between first and last check */
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
		unsigned long proc = 0, thread = 0, cpus;
		int i, j, n, autoinc;

		if (!*args[1] || !*args[2]) {
			ha_alert("parsing [%s:%d] : %s expects a process number "
				 " ('all', 'odd', 'even', a number from 1 to %d or a range), "
				 " followed by a list of CPU ranges with numbers from 0 to %d.\n",
				 file, linenum, args[0], LONGBITS, LONGBITS - 1);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if ((slash = strchr(args[1], '/')) != NULL)
			*slash = 0;

		/* note: we silently ignore processes over MAX_PROCS and
		 * threads over MAX_THREADS so as not to make configurations a
		 * pain to maintain.
		 */
		if (parse_process_number(args[1], &proc, LONGBITS, &autoinc, &errmsg)) {
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

			if (autoinc && atleast2(proc) && atleast2(thread)) {
				ha_alert("parsing [%s:%d] : %s : '%s' : unable to automatically bind "
					 "a process range _AND_ a thread range\n",
					 file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}

		if (parse_cpu_set((const char **)args+2, &cpus, &errmsg)) {
			ha_alert("parsing [%s:%d] : %s : %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (autoinc &&
		    my_popcountl(proc)  != my_popcountl(cpus) &&
		    my_popcountl(thread) != my_popcountl(cpus)) {
			ha_alert("parsing [%s:%d] : %s : PROC/THREAD range and CPU sets "
				 "must have the same size to be automatically bound\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		/* we now have to deal with 3 real cases :
		 *    cpu-map P-Q    => mapping for whole processes, numbers P to Q
		 *    cpu-map P-Q/1  => mapping of first thread of processes P to Q
		 *    cpu-map 1/T-U  => mapping of threads T to U of process 1
		 * Otherwise other combinations are silently ignored since nbthread
		 * and nbproc cannot both be >1 :
		 *    cpu-map P-Q/T  => mapping for thread T for processes P to Q.
		 *                      Only one of T,Q may be > 1, others ignored.
		 *    cpu-map P/T-U  => mapping for threads T to U of process P. Only
		 *                      one of P,U may be > 1, others ignored.
		 */
		if (!thread) {
			/* mapping for whole processes. E.g. cpu-map 1-4 0-3 */
			for (i = n = 0; i < MAX_PROCS; i++) {
				/* No mapping for this process */
				if (!(proc & (1UL << i)))
					continue;

				if (!autoinc)
					global.cpu_map.proc[i] = cpus;
				else {
					n += my_ffsl(cpus >> n);
					global.cpu_map.proc[i] = (1UL << (n-1));
				}
			}
		} else {
			/* Mapping at the thread level. All threads are retained
			 * for process 1, and only thread 1 is retained for other
			 * processes.
			 */
			if (thread == 0x1) {
				/* first thread, iterate on processes. E.g. cpu-map 1-4/1 0-3 */
				for (i = n = 0; i < MAX_PROCS; i++) {
					/* No mapping for this process */
					if (!(proc & (1UL << i)))
						continue;
					if (!autoinc)
						global.cpu_map.proc_t1[i] = cpus;
					else {
						n += my_ffsl(cpus >> n);
						global.cpu_map.proc_t1[i] = (1UL << (n-1));
					}
				}
			}

			if (proc == 0x1) {
				/* first process, iterate on threads. E.g. cpu-map 1/1-4 0-3 */
				for (j = n = 0; j < MAX_THREADS; j++) {
					/* No mapping for this thread */
					if (!(thread & (1UL << j)))
						continue;

					if (!autoinc)
						global.cpu_map.thread[j] = cpus;
					else {
						n += my_ffsl(cpus >> n);
						global.cpu_map.thread[j] = (1UL << (n-1));
					}
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
	else if (strcmp(args[0], "setenv") == 0 || strcmp(args[0], "presetenv") == 0) {
		if (alertif_too_many_args(3, file, linenum, args, &err_code))
			goto out;

		if (*(args[2]) == 0) {
			ha_alert("parsing [%s:%d]: '%s' expects a name and a value.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		/* "setenv" overwrites, "presetenv" only sets if not yet set */
		if (setenv(args[1], args[2], (args[0][0] == 's')) != 0) {
			ha_alert("parsing [%s:%d]: '%s' failed on variable '%s' : %s.\n", file, linenum, args[0], args[1], strerror(errno));
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "unsetenv")) {
		int arg;

		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d]: '%s' expects at least one variable name.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		for (arg = 1; *args[arg]; arg++) {
			if (unsetenv(args[arg]) != 0) {
				ha_alert("parsing [%s:%d]: '%s' failed on variable '%s' : %s.\n", file, linenum, args[0], args[arg], strerror(errno));
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
	}
	else if (!strcmp(args[0], "resetenv")) {
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
					ha_alert("parsing [%s:%d]: '%s' failed to unset invalid variable '%s'.\n", file, linenum, args[0], *env);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				memcpy(trash.area, *env, delim - *env);
				trash.area[delim - *env] = 0;

				if (unsetenv(trash.area) != 0) {
					ha_alert("parsing [%s:%d]: '%s' failed to unset variable '%s' : %s.\n", file, linenum, args[0], *env, strerror(errno));
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			}
			else
				env++;
		}
	}
	else if (!strcmp(args[0], "strict-limits")) { /* "no strict-limits" or "strict-limits" */
		if (alertif_too_many_args(0, file, linenum, args, &err_code))
			goto out;
		if (kwm == KWM_NO)
			global.tune.options &= ~GTUNE_STRICT_LIMITS;
		else
			global.tune.options |= GTUNE_STRICT_LIMITS;
	}
	else {
		struct cfg_kw_list *kwl;
		int index;
		int rc;

		list_for_each_entry(kwl, &cfg_keywords.list, list) {
			for (index = 0; kwl->kw[index].kw != NULL; index++) {
				if (kwl->kw[index].section != CFG_GLOBAL)
					continue;
				if (strcmp(kwl->kw[index].kw, args[0]) == 0) {
					rc = kwl->kw[index].parse(args, CFG_GLOBAL, NULL, NULL, file, linenum, &errmsg);
					if (rc < 0) {
						ha_alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
						err_code |= ERR_ALERT | ERR_FATAL;
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
		
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], "global");
		err_code |= ERR_ALERT | ERR_FATAL;
	}

 out:
	free(errmsg);
	return err_code;
}

