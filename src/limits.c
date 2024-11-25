/*
 * Handlers for process resources limits.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later.
 *
 */

#include <haproxy/global.h>
#include <haproxy/limits.h>
#include <haproxy/log.h>
#include <haproxy/proxy.h>


unsigned int rlim_fd_cur_at_boot = 0;
unsigned int rlim_fd_max_at_boot = 0;

/* Sets the RLIMIT_NOFILE setting to <new_limit> and returns the previous one
 * in <old_limit> if the pointer is not NULL, even if set_rlimit() fails. The
 * two pointers may point to the same variable as the copy happens after
 * setting the new value. The value is only changed if at least one of the new
 * limits is strictly higher than the current one, otherwise returns 0 without
 * changing anything. The getrlimit() or setrlimit() syscall return value is
 * returned and errno is preserved.
 */
int raise_rlim_nofile(struct rlimit *old_limit, struct rlimit *new_limit)
{
	struct rlimit limit = { };
	int ret = 0;

	ret = getrlimit(RLIMIT_NOFILE, &limit);

	if (ret == 0 &&
	    (limit.rlim_max < new_limit->rlim_max ||
	     limit.rlim_cur < new_limit->rlim_cur)) {
		ret = setrlimit(RLIMIT_NOFILE, new_limit);
	}

	if (old_limit)
		*old_limit = limit;

	return ret;
}

/* Encapsulates the check of all supported for now process internal limits,
 * which could be provided via config or/and cmdline. Returns 1, if even only
 * one supported limit is set, otherwise 0.
 */
static int is_any_limit_configured()
{
       int ret = 0;

       if (global.maxconn || global.rlimit_nofile || global.rlimit_memmax ||
               global.fd_hard_limit)
               ret = 1;

       return ret;
}

/* considers splicing proxies' maxconn, computes the ideal global.maxpipes
 * setting, and returns it. It may return -1 meaning "unlimited" if some
 * unlimited proxies have been found and the global.maxconn value is not yet
 * set. It may also return a value greater than maxconn if it's not yet set.
 * Note that a value of zero means there is no need for pipes. -1 is never
 * returned if global.maxconn is valid.
 */
int compute_ideal_maxpipes()
{
	struct proxy *cur;
	int nbfe = 0, nbbe = 0;
	int unlimited = 0;
	int pipes;
	int max;

	for (cur = proxies_list; cur; cur = cur->next) {
		if (cur->options2 & (PR_O2_SPLIC_ANY)) {
			if (cur->cap & PR_CAP_FE) {
				max = cur->maxconn;
				nbfe += max;
				if (!max) {
					unlimited = 1;
					break;
				}
			}
			if (cur->cap & PR_CAP_BE) {
				max = cur->fullconn ? cur->fullconn : global.maxconn;
				nbbe += max;
				if (!max) {
					unlimited = 1;
					break;
				}
			}
		}
	}

	pipes = MAX(nbfe, nbbe);
	if (global.maxconn) {
		if (pipes > global.maxconn || unlimited)
			pipes = global.maxconn;
	} else if (unlimited) {
		pipes = -1;
	}

	return pipes >= 4 ? pipes / 4 : pipes;
}

/* considers global.maxsocks, global.maxpipes, async engines, SSL frontends and
 * rlimits and computes an ideal maxconn. It's meant to be called only when
 * maxsock contains the sum of listening FDs, before it is updated based on
 * maxconn and pipes. If there are not enough FDs left, DEFAULT_MAXCONN (by
 * default 100) is returned as it is expected that it will even run on tight
 * environments, and will maintain compatibility with previous packages that
 * used to rely on this value as the default one. The system will emit a
 * warning indicating how many FDs are missing anyway if needed.
 */
static int compute_ideal_maxconn()
{
	int ssl_sides = !!global.ssl_used_frontend + !!global.ssl_used_backend;
	int engine_fds = global.ssl_used_async_engines * ssl_sides;
	int pipes = compute_ideal_maxpipes();
	int remain = MAX(rlim_fd_cur_at_boot, rlim_fd_max_at_boot);
	int maxconn;

	/* we have to take into account these elements :
	 *   - number of engine_fds, which inflates the number of FD needed per
	 *     connection by this number.
	 *   - number of pipes per connection on average : for the unlimited
	 *     case, this is 0.5 pipe FDs per connection, otherwise it's a
	 *     fixed value of 2*pipes.
	 *   - two FDs per connection
	 */

	/* on some modern distros for archs like amd64 fs.nr_open (kernel max)
	 * could be in order of 1 billion. Systemd since the version 256~rc3-3
	 * bumped fs.nr_open as the hard RLIMIT_NOFILE (rlim_fd_max_at_boot).
	 * If we are started without any limits, we risk to finish with computed
	 * maxconn = ~500000000, maxsock = ~2*maxconn. So, fdtab will be
	 * extremely large and watchdog will kill the process, when it will try
	 * to loop over the fdtab (see fd_reregister_all). Please note, that
	 * fd_hard_limit is taken in account implicitly via 'ideal_maxconn'
	 * value in all global.maxconn adjustements, when global.rlimit_memmax
	 * is set:
	 *
	 *   MIN(global.maxconn, capped by global.rlimit_memmax, ideal_maxconn);
	 *
	 * It also caps global.rlimit_nofile, if it couldn't be set as rlim_cur
	 * and as rlim_max. So, fd_hard_limitit is a good parameter to serve as
	 * a safeguard, when no haproxy-specific limits are set, i.e.
	 * rlimit_memmax, maxconn, rlimit_nofile. But it must be kept as a zero,
	 * if only one of these ha-specific limits is presented in config or in
	 * the cmdline.
	 */
	if (!is_any_limit_configured())
		global.fd_hard_limit = DEFAULT_MAXFD;

	if (remain > global.fd_hard_limit)
		remain = global.fd_hard_limit;

	/* subtract listeners and checks */
	remain -= global.maxsock;

	/* one epoll_fd/kqueue_fd per thread */
	remain -= global.nbthread;

	/* one wake-up pipe (2 fd) per thread */
	remain -= 2 * global.nbthread;

	/* Fixed pipes values : we only subtract them if they're not larger
	 * than the remaining FDs because pipes are optional.
	 */
	if (pipes >= 0 && pipes * 2 < remain)
		remain -= pipes * 2;

	if (pipes < 0) {
		/* maxsock = maxconn * 2 + maxconn/4 * 2 + maxconn * engine_fds.
		 *         = maxconn * (2 + 0.5 + engine_fds)
		 *         = maxconn * (4 + 1 + 2*engine_fds) / 2
		 */
		maxconn = 2 * remain / (5 + 2 * engine_fds);
	} else {
		/* maxsock = maxconn * 2 + maxconn * engine_fds.
		 *         = maxconn * (2 + engine_fds)
		 */
		maxconn = remain / (2 + engine_fds);
	}

	return MAX(maxconn, DEFAULT_MAXCONN);
}

/* computes the estimated maxsock value for the given maxconn based on the
 * possibly set global.maxpipes and existing partial global.maxsock. It may
 * temporarily change global.maxconn for the time needed to propagate the
 * computations, and will reset it.
 */
int compute_ideal_maxsock(int maxconn)
{
	int maxpipes = global.maxpipes;
	int maxsock  = global.maxsock;


	if (!maxpipes) {
		int old_maxconn = global.maxconn;

		global.maxconn = maxconn;
		maxpipes = compute_ideal_maxpipes();
		global.maxconn = old_maxconn;
	}

	maxsock += maxconn * 2;         /* each connection needs two sockets */
	maxsock += maxpipes * 2;        /* each pipe needs two FDs */
	maxsock += global.nbthread;     /* one epoll_fd/kqueue_fd per thread */
	maxsock += 2 * global.nbthread; /* one wake-up pipe (2 fd) per thread */

	/* compute fd used by async engines */
	if (global.ssl_used_async_engines) {
		int sides = !!global.ssl_used_frontend + !!global.ssl_used_backend;

		maxsock += maxconn * sides * global.ssl_used_async_engines;
	}
	return maxsock;
}

/* Tests if it is possible to set the current process's RLIMIT_NOFILE to
 * <maxsock>, then sets it back to the previous value. Returns non-zero if the
 * value is accepted, non-zero otherwise. This is used to determine if an
 * automatic limit may be applied or not. When it is not, the caller knows that
 * the highest we can do is the rlim_max at boot. In case of error, we return
 * that the setting is possible, so that we defer the error processing to the
 * final stage in charge of enforcing this.
 */
int check_if_maxsock_permitted(int maxsock)
{
	struct rlimit orig_limit, test_limit;
	int ret;

	if (global.fd_hard_limit && maxsock > global.fd_hard_limit)
		return 0;

	if (getrlimit(RLIMIT_NOFILE, &orig_limit) != 0)
		return 1;

	/* don't go further if we can't even set to what we have */
	if (raise_rlim_nofile(NULL, &orig_limit) != 0)
		return 1;

	test_limit.rlim_max = MAX(maxsock, orig_limit.rlim_max);
	test_limit.rlim_cur = test_limit.rlim_max;
	ret = raise_rlim_nofile(NULL, &test_limit);

	if (raise_rlim_nofile(NULL, &orig_limit) != 0)
		return 1;

	return ret == 0;
}

/* Calculates and sets global.maxconn and if compiled with USE_OPENSSL,
 * global.maxsslconn.
 */
void set_global_maxconn(void)
{
	int ideal_maxconn = compute_ideal_maxconn();

	/* It's a bit tricky. Maxconn defaults to the pre-computed value based
	 * on rlim_fd_cur and the number of FDs in use due to the configuration,
	 * and maxsslconn defaults to DEFAULT_MAXSSLCONN. On top of that we can
	 * enforce a lower limit based on memmax.
	 *
	 * If memmax is set, then it depends on which values are set. If
	 * maxsslconn is set, we use memmax to determine how many cleartext
	 * connections may be added, and set maxconn to the sum of the two.
	 * If maxconn is set and not maxsslconn, maxsslconn is computed from
	 * the remaining amount of memory between memmax and the cleartext
	 * connections. If neither are set, then it is considered that all
	 * connections are SSL-capable, and maxconn is computed based on this,
	 * then maxsslconn accordingly. We need to know if SSL is used on the
	 * frontends, backends, or both, because when it's used on both sides,
	 * we need twice the value for maxsslconn, but we only count the
	 * handshake once since it is not performed on the two sides at the
	 * same time (frontend-side is terminated before backend-side begins).
	 * The SSL stack is supposed to have filled ssl_session_cost and
	 * ssl_handshake_cost during its initialization. In any case, if
	 * SYSTEM_MAXCONN is set, we still enforce it as an upper limit for
	 * maxconn in order to protect the system.
	 */

	if (!global.rlimit_memmax) {
		if (global.maxconn == 0) {
			global.maxconn = ideal_maxconn;
			if (global.mode & (MODE_VERBOSE|MODE_DEBUG))
				fprintf(stderr, "Note: setting global.maxconn to %d.\n", global.maxconn);
		}
	}
#ifdef USE_OPENSSL
	else if (!global.maxconn && !global.maxsslconn &&
		 (global.ssl_used_frontend || global.ssl_used_backend)) {
		/* memmax is set, compute everything automatically. Here we want
		 * to ensure that all SSL connections will be served. We take
		 * care of the number of sides where SSL is used, and consider
		 * the worst case : SSL used on both sides and doing a handshake
		 * simultaneously. Note that we can't have more than maxconn
		 * handshakes at a time by definition, so for the worst case of
		 * two SSL conns per connection, we count a single handshake.
		 */
		int sides = !!global.ssl_used_frontend + !!global.ssl_used_backend;
		int64_t mem = global.rlimit_memmax * 1048576ULL;
		int retried = 0;

		mem -= global.tune.sslcachesize * 200ULL; // about 200 bytes per SSL cache entry
		mem -= global.maxzlibmem;
		mem = mem * MEM_USABLE_RATIO;

		/* Principle: we test once to set maxconn according to the free
		 * memory. If it results in values the system rejects, we try a
		 * second time by respecting rlim_fd_max. If it fails again, we
		 * go back to the initial value and will let the final code
		 * dealing with rlimit report the error. That's up to 3 attempts.
		 */
		do {
			global.maxconn = mem /
				((STREAM_MAX_COST + 2 * global.tune.bufsize) +    // stream + 2 buffers per stream
				 sides * global.ssl_session_max_cost +            // SSL buffers, one per side
				 global.ssl_handshake_max_cost);                  // 1 handshake per connection max

			if (retried == 1)
				global.maxconn = MIN(global.maxconn, ideal_maxconn);
			global.maxconn = round_2dig(global.maxconn);
#ifdef SYSTEM_MAXCONN
			if (global.maxconn > SYSTEM_MAXCONN)
				global.maxconn = SYSTEM_MAXCONN;
#endif /* SYSTEM_MAXCONN */
			global.maxsslconn = sides * global.maxconn;

			if (check_if_maxsock_permitted(compute_ideal_maxsock(global.maxconn)))
				break;
		} while (retried++ < 2);

		if (global.mode & (MODE_VERBOSE|MODE_DEBUG))
			fprintf(stderr, "Note: setting global.maxconn to %d and global.maxsslconn to %d.\n",
			        global.maxconn, global.maxsslconn);
	}
	else if (!global.maxsslconn &&
		 (global.ssl_used_frontend || global.ssl_used_backend)) {
		/* memmax and maxconn are known, compute maxsslconn automatically.
		 * maxsslconn being forced, we don't know how many of it will be
		 * on each side if both sides are being used. The worst case is
		 * when all connections use only one SSL instance because
		 * handshakes may be on two sides at the same time.
		 */
		int sides = !!global.ssl_used_frontend + !!global.ssl_used_backend;
		int64_t mem = global.rlimit_memmax * 1048576ULL;
		int64_t sslmem;

		mem -= global.tune.sslcachesize * 200ULL; // about 200 bytes per SSL cache entry
		mem -= global.maxzlibmem;
		mem = mem * MEM_USABLE_RATIO;

		sslmem = mem - global.maxconn * (int64_t)(STREAM_MAX_COST + 2 * global.tune.bufsize);
		global.maxsslconn = sslmem / (global.ssl_session_max_cost + global.ssl_handshake_max_cost);
		global.maxsslconn = round_2dig(global.maxsslconn);

		if (sslmem <= 0 || global.maxsslconn < sides) {
			ha_alert("Cannot compute the automatic maxsslconn because global.maxconn is already too "
				 "high for the global.memmax value (%d MB). The absolute maximum possible value "
				 "without SSL is %d, but %d was found and SSL is in use.\n",
				 global.rlimit_memmax,
				 (int)(mem / (STREAM_MAX_COST + 2 * global.tune.bufsize)),
				 global.maxconn);
			exit(1);
		}

		if (global.maxsslconn > sides * global.maxconn)
			global.maxsslconn = sides * global.maxconn;

		if (global.mode & (MODE_VERBOSE|MODE_DEBUG))
			fprintf(stderr, "Note: setting global.maxsslconn to %d\n", global.maxsslconn);
	}
#endif
	else if (!global.maxconn) {
		/* memmax and maxsslconn are known/unused, compute maxconn automatically */
		int sides = !!global.ssl_used_frontend + !!global.ssl_used_backend;
		int64_t mem = global.rlimit_memmax * 1048576ULL;
		int64_t clearmem;
		int retried = 0;

		if (global.ssl_used_frontend || global.ssl_used_backend)
			mem -= global.tune.sslcachesize * 200ULL; // about 200 bytes per SSL cache entry

		mem -= global.maxzlibmem;
		mem = mem * MEM_USABLE_RATIO;

		clearmem = mem;
		if (sides)
			clearmem -= (global.ssl_session_max_cost + global.ssl_handshake_max_cost) * (int64_t)global.maxsslconn;

		/* Principle: we test once to set maxconn according to the free
		 * memory. If it results in values the system rejects, we try a
		 * second time by respecting rlim_fd_max. If it fails again, we
		 * go back to the initial value and will let the final code
		 * dealing with rlimit report the error. That's up to 3 attempts.
		 */
		do {
			global.maxconn = clearmem / (STREAM_MAX_COST + 2 * global.tune.bufsize);
			if (retried == 1)
				global.maxconn = MIN(global.maxconn, ideal_maxconn);
			global.maxconn = round_2dig(global.maxconn);
#ifdef SYSTEM_MAXCONN
			if (global.maxconn > SYSTEM_MAXCONN)
				global.maxconn = SYSTEM_MAXCONN;
#endif /* SYSTEM_MAXCONN */

			if (clearmem <= 0 || !global.maxconn) {
				ha_alert("Cannot compute the automatic maxconn because global.maxsslconn is already too "
					 "high for the global.memmax value (%d MB). The absolute maximum possible value "
					 "is %d, but %d was found.\n",
					 global.rlimit_memmax,
				 (int)(mem / (global.ssl_session_max_cost + global.ssl_handshake_max_cost)),
					 global.maxsslconn);
				exit(1);
			}

			if (check_if_maxsock_permitted(compute_ideal_maxsock(global.maxconn)))
				break;
		} while (retried++ < 2);

		if (global.mode & (MODE_VERBOSE|MODE_DEBUG)) {
			if (sides && global.maxsslconn > sides * global.maxconn) {
				fprintf(stderr, "Note: global.maxsslconn is forced to %d which causes global.maxconn "
				        "to be limited to %d. Better reduce global.maxsslconn to get more "
				        "room for extra connections.\n", global.maxsslconn, global.maxconn);
			}
			fprintf(stderr, "Note: setting global.maxconn to %d\n", global.maxconn);
		}
	}
}

/* Sets the current and max nofile limits for the process. It may terminate the
 * process, if it can't raise FD limit and there is no 'no strict-limits' in the
 * global section.
 */
void apply_nofile_limit(void)
{
	struct rlimit limit;

	if (!global.rlimit_nofile)
		global.rlimit_nofile = global.maxsock;

	if (global.rlimit_nofile) {
		limit.rlim_cur = global.rlimit_nofile;
		limit.rlim_max = MAX(rlim_fd_max_at_boot, limit.rlim_cur);

		if ((global.fd_hard_limit && limit.rlim_cur > global.fd_hard_limit) ||
		    raise_rlim_nofile(NULL, &limit) != 0) {
			getrlimit(RLIMIT_NOFILE, &limit);
			if (global.fd_hard_limit && limit.rlim_cur > global.fd_hard_limit)
				limit.rlim_cur = global.fd_hard_limit;

			if (global.tune.options & GTUNE_STRICT_LIMITS) {
				ha_alert("[%s.main()] Cannot raise FD limit to %d, limit is %d.\n",
					 progname, global.rlimit_nofile, (int)limit.rlim_cur);
				exit(1);
			}
			else {
				/* try to set it to the max possible at least */
				limit.rlim_cur = limit.rlim_max;
				if (global.fd_hard_limit && limit.rlim_cur > global.fd_hard_limit)
					limit.rlim_cur = global.fd_hard_limit;

				if (raise_rlim_nofile(&limit, &limit) == 0)
					getrlimit(RLIMIT_NOFILE, &limit);

				ha_warning("[%s.main()] Cannot raise FD limit to %d, limit is %d.\n",
					   progname, global.rlimit_nofile, (int)limit.rlim_cur);
				global.rlimit_nofile = limit.rlim_cur;
			}
		}
	}

}

/* Sets the current and max memory limits for the process. It may terminate the
 * process, if it can't raise RLIMIT_DATA limit and there is no
 * 'no strict-limits' in the global section.
 */
void apply_memory_limit(void)
{
	struct rlimit limit;

	if (global.rlimit_memmax) {
		limit.rlim_cur = limit.rlim_max =
			global.rlimit_memmax * 1048576ULL;
		if (setrlimit(RLIMIT_DATA, &limit) == -1) {
			if (global.tune.options & GTUNE_STRICT_LIMITS) {
				ha_alert("[%s.main()] Cannot fix MEM limit to %d megs.\n",
					 progname, global.rlimit_memmax);
				exit(1);
			}
			else
				ha_warning("[%s.main()] Cannot fix MEM limit to %d megs.\n",
					   progname, global.rlimit_memmax);
		}
	}

}

/* Checks the current nofile limit via getrlimit and preallocates the
 * (limit.rlim_cur - 1) of FDs. It may terminate the process, if its current
 * nofile limit is lower than global.maxsock and there is no 'no strict-limits'
 * in the global section.
 */
void check_nofile_lim_and_prealloc_fd(void)
{
	struct rlimit limit;

	limit.rlim_cur = limit.rlim_max = 0;
	getrlimit(RLIMIT_NOFILE, &limit);
	if (limit.rlim_cur < global.maxsock) {
		if (global.tune.options & GTUNE_STRICT_LIMITS) {
			ha_alert("[%s.main()] FD limit (%d) too low for maxconn=%d/maxsock=%d. "
				 "Please raise 'ulimit-n' to %d or more to avoid any trouble.\n",
			         progname, (int)limit.rlim_cur, global.maxconn, global.maxsock,
				 global.maxsock);
			exit(1);
		}
		else
			ha_alert("[%s.main()] FD limit (%d) too low for maxconn=%d/maxsock=%d. "
				 "Please raise 'ulimit-n' to %d or more to avoid any trouble.\n",
			         progname, (int)limit.rlim_cur, global.maxconn, global.maxsock,
				 global.maxsock);
	}

	if (global.prealloc_fd && fcntl((int)limit.rlim_cur - 1, F_GETFD) == -1) {
		if (dup2(0, (int)limit.rlim_cur - 1) == -1)
			ha_warning("[%s.main()] Unable to preallocate file descriptor %d : %s",
				progname, (int)limit.rlim_cur - 1, strerror(errno));
		else
			close((int)limit.rlim_cur - 1);
	}
}
